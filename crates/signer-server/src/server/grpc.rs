//! gRPC router construction for the signer server.
//!
//! Extracted from `server::run` so hardened-builder limits, the 1 MiB decode
//! cap, the H-9 insecure gate, and shared-gate injection are unit-testable
//! without binding the accept loop.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{error, info};

use crate::config::ResolvedConfig;
use crate::error::ServerError;
use crate::metrics::SignerMetrics;
use crate::service::SignerServiceImpl;
#[cfg(feature = "dvt")]
use crate::{dvt, PeerSignerServiceServerV2};
use crate::{grpc_tls, insecure_startup, SignerServiceServerV2};

/// Per-service max decoding message size (M-10). Signing a BeaconBlock is well
/// under 1 MiB after SSZ encoding; 1 MiB is a comfortable upper bound.
pub(crate) const MAX_DECODE_BYTES: usize = 1 << 20; // 1 MiB

/// Tower concurrency limit applied by [`grpc_tls::server_builder::hardened_server_builder`].
/// Kept here so unit tests can assert the composition root still pins this value.
pub(crate) const CONCURRENCY_LIMIT_PER_CONNECTION: usize = 32;

/// H2 `SETTINGS_MAX_CONCURRENT_STREAMS` applied by the hardened builder.
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 64;

/// Per-request timeout (seconds) applied by the hardened builder.
pub(crate) const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Inputs for [`build_grpc_router`].
///
/// `shared_gate` is the **one** composition-root gate (ADR-003 / FR-26); when
/// `Some`, it is injected into the gRPC service via `new_v2_with_gate`. HTTP
/// receives the same `Arc` through [`super::http::spawn_http_api`].
pub(crate) struct GrpcRouterDeps<'a> {
    pub resolved: &'a ResolvedConfig,
    pub tls_config: Option<&'a crate::grpc_tls::TlsConfig>,
    pub signing_backend: Arc<dyn crate::backend::SigningBackend>,
    pub shared_gate: Option<Arc<signer::SigningGate>>,
    pub client_cn_allow_list: Option<Arc<crate::audit::ClientCnAllowList>>,
    pub signer_metrics: Arc<SignerMetrics>,
    pub slashing_db: Option<Arc<::slashing::SlashingDb>>,
    #[cfg(feature = "dvt")]
    pub dvt_share_map: Option<super::backend::ShareMap>,
    #[cfg(feature = "dvt")]
    pub dvt_allow_list: Option<Arc<dvt::allow_list::AllowedPeers>>,
}

/// Output of [`build_grpc_router`]: a ready-to-serve Tonic router + bind address.
pub(crate) struct BuiltGrpcRouter {
    pub router: tonic::transport::server::Router,
    pub listen_addr: SocketAddr,
}

/// Build the v2 `SignerServiceImpl` with injected gate / metrics / CN list.
///
/// Exposed `pub(crate)` so FR-26 tests can assert `Arc::ptr_eq` against the
/// HTTP state built from the same gate without binding a listener.
pub(crate) fn build_v2_signer_service(deps: &GrpcRouterDeps<'_>) -> SignerServiceImpl {
    if let Some(ref shared_gate) = deps.shared_gate {
        SignerServiceImpl::new_v2_with_gate(
            Arc::clone(&deps.signing_backend),
            deps.resolved.backend.to_string(),
            Arc::clone(shared_gate),
        )
        .with_metrics(Arc::clone(&deps.signer_metrics))
        .with_client_cn_allow_list(deps.client_cn_allow_list.clone())
        .with_genesis_fork_version(deps.resolved.genesis_fork_version)
    } else {
        SignerServiceImpl::new(Arc::clone(&deps.signing_backend), deps.resolved.backend.to_string())
            .with_metrics(Arc::clone(&deps.signer_metrics))
            .with_client_cn_allow_list(deps.client_cn_allow_list.clone())
            .with_genesis_fork_version(deps.resolved.genesis_fork_version)
    }
}

/// Build the hardened gRPC router (TLS / H-9 insecure gate / services / decode cap).
///
/// Does **not** bind or serve — the composition root calls
/// `router.serve_with_shutdown`.
pub(crate) fn build_grpc_router(deps: GrpcRouterDeps<'_>) -> Result<BuiltGrpcRouter, ServerError> {
    let svc_v2 = build_v2_signer_service(&deps);

    // Build the PeerSignerService (DVT) now that we have the slashing DB.
    // The allow-list was already loaded and validated in build_backend
    // (hoisted to avoid a double file-read — ISSUE-4.1 / L-1 DRY fix).
    #[cfg(feature = "dvt")]
    let peer_signer_service: Option<dvt::peer_service::PeerSignerServiceImpl> = if let Some(
        share_map,
    ) =
        deps.dvt_share_map
    {
        let allow_list = deps.dvt_allow_list.ok_or_else(|| {
                ServerError::config(
                    "DVT is enabled but --dvt-allowed-peers was not provided. \
                     Create a dvt-allowed-peers.toml file and pass its path via --dvt-allowed-peers.",
                )
            })?;
        Some(
            dvt::peer_service::PeerSignerServiceImpl::new(
                share_map,
                allow_list,
                deps.slashing_db.clone(),
            )
            .with_genesis_fork_version(deps.resolved.genesis_fork_version),
        )
    } else {
        None
    };

    // Non-DVT builds still accept the slashing_db field (used only by DVT peer svc).
    #[cfg(not(feature = "dvt"))]
    let _ = &deps.slashing_db;

    let addr: SocketAddr = deps
        .resolved
        .listen_address
        .parse()
        .map_err(|e| ServerError::bind(format!("invalid listen address: {e}")))?;

    // ── M-10: hardened server builder (concurrency + timeout limits) ──────────
    //
    // `hardened_server_builder()` applies per research/05 §"Recommended values":
    //   - concurrency_limit_per_connection(32) — Tower-level cap per connection
    //   - max_concurrent_streams(Some(64))     — H2 SETTINGS frame to clients
    //   - timeout(Duration::from_secs(10))     — per-request timeout via Tower
    //
    // Per-service max_decoding_message_size(1 MiB) is set on each ServiceServer
    // below (Tonic exposes it only at the service level, not the builder level).
    //
    // The constants above must stay in lockstep with `grpc_tls::server_builder`.
    debug_assert_eq!(
        CONCURRENCY_LIMIT_PER_CONNECTION, 32,
        "keep in sync with grpc_tls::server_builder::hardened_server_builder"
    );
    debug_assert_eq!(MAX_CONCURRENT_STREAMS, 64);
    debug_assert_eq!(REQUEST_TIMEOUT_SECS, 10);

    let mut builder = grpc_tls::server_builder::hardened_server_builder();

    if let Some(tls_cfg) = deps.tls_config {
        let server_tls =
            tls_cfg.to_server_tls_config().map_err(|e| ServerError::tls(e.to_string()))?;
        builder = builder.tls_config(server_tls).map_err(|e| ServerError::tls(e.to_string()))?;
        info!("mTLS enabled");
    } else if deps.resolved.insecure {
        // ── H-9: env-var double-confirm + loopback gate ───────────────────
        //
        // `--insecure` requires BOTH `RVC_SIGNER_ALLOW_INSECURE=true` in the
        // environment AND a loopback bind address.  Per NFR-10 / ISSUE-3.13
        // (GA tag) the gate now runs in Refuse mode: startup hard-fails when
        // the opt-in conditions are not fully met.
        insecure_startup::check_insecure_startup(true, addr, crypto::InsecureMode::Refuse)
            .map_err(|e| {
                error!(error = %e, "insecure startup refused by gate");
                ServerError::config(e.to_string())
            })?;
        tracing::warn!("TLS disabled via --insecure flag. Do NOT use in production!");
    } else {
        return Err(ServerError::tls(
            "TLS is required. Provide --tls-cert, --tls-key, and --tls-ca-cert, \
             or use --insecure to disable (NOT recommended for production).",
        ));
    }

    // SS-1 (Issue 2.2): only the v2 typed-RPC service is registered.
    // The v1 raw-root service has been removed from the live listener.
    let router = builder.add_service(
        SignerServiceServerV2::new(svc_v2).max_decoding_message_size(MAX_DECODE_BYTES),
    );

    #[cfg(feature = "dvt")]
    let router = if let Some(peer_svc) = peer_signer_service {
        info!("PeerSignerService v2 registered for DVT");
        router.add_service(
            PeerSignerServiceServerV2::new(peer_svc).max_decoding_message_size(MAX_DECODE_BYTES),
        )
    } else {
        router
    };

    Ok(BuiltGrpcRouter { router, listen_addr: addr })
}

#[cfg(test)]
// RF1-12: unit tests may mutate env via unsafe set_var/remove_var.
// await_holding_lock: ENV_LOCK intentionally serializes process-global env.
#[allow(unsafe_code, clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::server::env_lock;
    use crate::service::SignerServiceImpl;
    use std::sync::Arc;

    /// Minimal empty backend for router-construction tests.
    struct EmptyBackend;

    #[async_trait::async_trait]
    impl crate::backend::SigningBackend for EmptyBackend {
        async fn sign(
            &self,
            _signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], crate::backend::SigningBackendError> {
            Err(crate::backend::SigningBackendError::KeyNotFound(*pubkey))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            vec![]
        }
    }

    fn base_resolved(listen: &str) -> ResolvedConfig {
        ResolvedConfig {
            listen_address: listen.to_string(),
            keystore_dir: std::path::PathBuf::from("/tmp/unused"),
            password_file: None,
            backend: Backend::Basic,
            dry_run: false,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            reload_interval_secs: 0,
            enable_hot_reload: false,
            dvt_peers: vec![],
            dvt_threshold: None,
            dvt_index: None,
            dvt_timeout_ms: 2000,
            http_enabled: false,
            http_listen_address: "127.0.0.1:9000".to_string(),
            http_tls_mode: HttpTlsMode::Mtls,
            http_tls_cert: None,
            http_tls_key: None,
            http_tls_ca_cert: None,
            genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
            insecure: true,
            data_dir: None,
            disable_slashing_protection: true,
            init_slashing_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            gloas_fork_epoch: u64::MAX,
            metrics_address: "127.0.0.1:0".to_string(),
            enable_log_reload: false,
            allowed_client_cns: None,
            #[cfg(feature = "dvt")]
            dvt_allowed_peers: None,
        }
    }

    fn deps_for(
        resolved: &ResolvedConfig,
        gate: Option<Arc<signer::SigningGate>>,
        metrics: Arc<SignerMetrics>,
    ) -> GrpcRouterDeps<'_> {
        GrpcRouterDeps {
            resolved,
            tls_config: None,
            signing_backend: Arc::new(EmptyBackend),
            shared_gate: gate,
            client_cn_allow_list: None,
            signer_metrics: metrics,
            slashing_db: None,
            #[cfg(feature = "dvt")]
            dvt_share_map: None,
            #[cfg(feature = "dvt")]
            dvt_allow_list: None,
        }
    }

    fn make_gate() -> Arc<signer::SigningGate> {
        let db = Arc::new(::slashing::SlashingDb::open_in_memory().unwrap());
        let backend: Arc<dyn crate::backend::SigningBackend> = Arc::new(EmptyBackend);
        Arc::new(SignerServiceImpl::build_gate(backend, db))
    }

    /// Hardened-builder limits and the 1 MiB decode cap stay pinned.
    #[test]
    fn test_grpc_router_applies_decode_cap_and_concurrency_limits() {
        assert_eq!(MAX_DECODE_BYTES, 1 << 20, "1 MiB decode cap must not change");
        assert_eq!(CONCURRENCY_LIMIT_PER_CONNECTION, 32);
        assert_eq!(MAX_CONCURRENT_STREAMS, 64);
        assert_eq!(REQUEST_TIMEOUT_SECS, 10);

        // Smoke: builder path succeeds with insecure + env + loopback.
        let _g = env_lock();
        let prev = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true") };

        let resolved = base_resolved("127.0.0.1:0");
        let metrics = Arc::new(SignerMetrics::new());
        let built = build_grpc_router(deps_for(&resolved, None, metrics))
            .expect("insecure loopback router builds");
        // Router is ready; address parsed from config.
        assert_eq!(built.listen_addr.ip().to_string(), "127.0.0.1");

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
    }

    /// H-9: `--insecure` requires env var **and** loopback; Refuse mode.
    #[test]
    fn test_insecure_flag_requires_env_and_loopback() {
        let _g = env_lock();
        let prev = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        let metrics = Arc::new(SignerMetrics::new());

        // Case 1: insecure + loopback but NO env → refuse.
        unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") };
        let resolved = base_resolved("127.0.0.1:0");
        let err = match build_grpc_router(deps_for(&resolved, None, Arc::clone(&metrics))) {
            Ok(_) => panic!("missing env must refuse"),
            Err(e) => e,
        };
        assert!(matches!(err, ServerError::Config(_)), "expected Config error, got {err:?}");

        // Case 2: insecure + env but NON-loopback → refuse.
        unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true") };
        let resolved = base_resolved("0.0.0.0:0");
        let err = match build_grpc_router(deps_for(&resolved, None, Arc::clone(&metrics))) {
            Ok(_) => panic!("non-loopback must refuse"),
            Err(e) => e,
        };
        assert!(matches!(err, ServerError::Config(_)), "expected Config error, got {err:?}");

        // Case 3: both conditions met → ok.
        let resolved = base_resolved("127.0.0.1:0");
        build_grpc_router(deps_for(&resolved, None, metrics)).expect("fully opted-in insecure");

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
    }

    /// Service construction injects the composition-root gate (FR-26).
    #[test]
    fn test_build_v2_service_injects_shared_gate() {
        let gate = make_gate();
        let resolved = base_resolved("127.0.0.1:0");
        let metrics = Arc::new(SignerMetrics::new());
        let deps = deps_for(&resolved, Some(Arc::clone(&gate)), Arc::clone(&metrics));
        let svc = build_v2_signer_service(&deps);
        let svc_gate = svc.shared_gate().expect("gate injected");
        assert!(
            Arc::ptr_eq(svc_gate, &gate),
            "gRPC service must hold the SAME Arc<SigningGate> as the composition root"
        );
        let svc_metrics = svc.shared_metrics().expect("metrics injected");
        assert!(
            Arc::ptr_eq(svc_metrics, &metrics),
            "gRPC service must hold the SAME Arc<SignerMetrics>"
        );
    }
}
