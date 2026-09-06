//! Web3Signer HTTP API spawn for the signer server.
//!
//! Extracted from `server::run` so the fail-closed gate requirement, shared
//! metrics registry, and CN allow-list parity are unit-testable without the
//! full composition root.

use std::sync::Arc;

use tracing::info;

use crate::config::ResolvedConfig;
use crate::error::ServerError;
use crate::http_api::{self, Web3SignerState};
use crate::metrics::SignerMetrics;

/// Inputs for [`spawn_http_api`] / [`build_http_state`].
///
/// `shared_gate` must be the **same** `Arc` injected into the gRPC service
/// (ADR-003 / FR-26). When HTTP is enabled and the gate is `None`, startup
/// fails closed.
pub(crate) struct HttpApiDeps<'a> {
    pub resolved: &'a ResolvedConfig,
    pub shared_gate: Option<Arc<signer::SigningGate>>,
    pub signing_backend: Arc<dyn crate::backend::SigningBackend>,
    pub signer_metrics: Arc<SignerMetrics>,
    pub client_cn_allow_list: Option<Arc<crate::audit::ClientCnAllowList>>,
}

/// Build [`Web3SignerState`] from shared composition-root deps.
///
/// Fail-closed when the HTTP API is enabled without a signing gate. When HTTP
/// is disabled this still builds a state if a gate is present (for tests);
/// callers that only care about spawn should use [`spawn_http_api`].
pub(crate) fn build_http_state(deps: &HttpApiDeps<'_>) -> Result<Web3SignerState, ServerError> {
    // Fail closed: the HTTP API requires the shared gate. Running a remote
    // signer's HTTP API without slashing protection is refused at startup
    // (stricter than the gRPC per-request `require_gate()` 500).
    let gate = deps.shared_gate.clone().ok_or_else(|| {
        ServerError::config(
            "[signer.http] is enabled but slashing protection is disabled. The HTTP \
             API requires the shared signing gate; enable slashing protection or \
             disable the HTTP API.",
        )
    })?;

    Ok(Web3SignerState {
        gate,
        backend: Arc::clone(&deps.signing_backend),
        // Record the active backend label ("basic"/"dvt") in HTTP audit lines
        // so they line up with the gRPC metrics `backend` label (Issue 4.4).
        audit: http_api::AuditCfg {
            backend_name: deps.resolved.backend.to_string(),
            ..http_api::AuditCfg::default()
        },
        // Share the one SignerMetrics registry so HTTP-path series land on the
        // same `:9101` scrape as the gRPC series (Issue 4.5).
        metrics: Arc::clone(&deps.signer_metrics),
        // SEC-4 residual F1: same primary client-CN allow-list as gRPC so
        // HTTP cannot bypass `--allowed-client-cns` as a parallel oracle.
        client_cn_allow_list: deps.client_cn_allow_list.clone(),
        // Same network genesis as gRPC for builder-registration equality.
        genesis_fork_version: deps.resolved.genesis_fork_version,
    })
}

/// Spawn the opt-in Web3Signer HTTPS listener, or return `Ok(None)` when disabled.
///
/// When enabled, requires the shared gate, HTTP TLS material, and binds the
/// configured listen address. Shutdown is driven by `shutdown` (the composition
/// root cancels after gRPC exit and awaits the returned handle).
pub(crate) async fn spawn_http_api(
    deps: HttpApiDeps<'_>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<Option<tokio::task::JoinHandle<()>>, ServerError> {
    if !deps.resolved.http_enabled {
        return Ok(None);
    }

    let state = build_http_state(&deps)?;

    let cert =
        deps.resolved.http_tls_cert.as_deref().ok_or_else(|| {
            ServerError::config("[signer.http] enabled but http.tls_cert is not set")
        })?;
    let key =
        deps.resolved.http_tls_key.as_deref().ok_or_else(|| {
            ServerError::config("[signer.http] enabled but http.tls_key is not set")
        })?;
    let ca = deps.resolved.http_tls_ca_cert.as_deref().ok_or_else(|| {
        ServerError::config("[signer.http] enabled but http.tls_ca_cert is not set")
    })?;

    let (bound, handle) = http_api::accept_loop::spawn_https_listener(
        &deps.resolved.http_listen_address,
        cert,
        key,
        ca,
        deps.resolved.http_tls_mode,
        state,
        shutdown,
    )
    .await
    .map_err(|e| ServerError::bind(e.to_string()))?;

    info!(
        address = %bound,
        tls_mode = ?deps.resolved.http_tls_mode,
        "Web3Signer HTTP API listening"
    );
    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::server::grpc::build_v2_signer_service;
    use crate::server::grpc::GrpcRouterDeps;
    use crate::service::SignerServiceImpl;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

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

    fn base_resolved(http_enabled: bool) -> ResolvedConfig {
        ResolvedConfig {
            listen_address: "127.0.0.1:0".to_string(),
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
            http_enabled,
            http_listen_address: "127.0.0.1:0".to_string(),
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

    fn make_gate(backend: Arc<dyn crate::backend::SigningBackend>) -> Arc<signer::SigningGate> {
        let db = Arc::new(::slashing::SlashingDb::open_in_memory().unwrap());
        Arc::new(SignerServiceImpl::build_gate(backend, db))
    }

    /// HTTP API without a gate refuses at startup (fail-closed).
    #[tokio::test]
    async fn test_http_api_refuses_startup_without_gate() {
        let resolved = base_resolved(true);
        let backend: Arc<dyn crate::backend::SigningBackend> = Arc::new(EmptyBackend);
        let metrics = Arc::new(SignerMetrics::new());

        let deps = HttpApiDeps {
            resolved: &resolved,
            shared_gate: None,
            signing_backend: Arc::clone(&backend),
            signer_metrics: metrics,
            client_cn_allow_list: None,
        };

        // State builder fails closed.
        let err = match build_http_state(&deps) {
            Ok(_) => panic!("HTTP without gate must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, ServerError::Config(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("shared signing gate") || msg.contains("slashing"),
            "message should mention gate/slashing: {msg}"
        );

        // Spawn path also fails closed (no bind attempted past the gate check).
        let err = match spawn_http_api(deps, CancellationToken::new()).await {
            Ok(_) => panic!("spawn without gate must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, ServerError::Config(_)), "got {err:?}");
    }

    /// One `SigningGate` instance is shared by gRPC and HTTP (permanent ptr_eq).
    #[test]
    fn test_grpc_and_http_share_one_signing_gate() {
        let backend: Arc<dyn crate::backend::SigningBackend> = Arc::new(EmptyBackend);
        let gate = make_gate(Arc::clone(&backend));
        let metrics = Arc::new(SignerMetrics::new());
        let resolved = base_resolved(true);

        let grpc_deps = GrpcRouterDeps {
            resolved: &resolved,
            tls_config: None,
            signing_backend: Arc::clone(&backend),
            shared_gate: Some(Arc::clone(&gate)),
            client_cn_allow_list: None,
            signer_metrics: Arc::clone(&metrics),
            slashing_db: None,
            #[cfg(feature = "dvt")]
            dvt_share_map: None,
            #[cfg(feature = "dvt")]
            dvt_allow_list: None,
        };
        let svc = build_v2_signer_service(&grpc_deps);
        let svc_gate = svc.shared_gate().expect("gRPC holds gate");

        let http_deps = HttpApiDeps {
            resolved: &resolved,
            shared_gate: Some(Arc::clone(&gate)),
            signing_backend: Arc::clone(&backend),
            signer_metrics: Arc::clone(&metrics),
            client_cn_allow_list: None,
        };
        let state = build_http_state(&http_deps).expect("HTTP state with gate");

        assert!(
            Arc::ptr_eq(svc_gate, &state.gate),
            "gRPC and HTTP must share one SigningGate Arc (FR-26 / ADR-003)"
        );
        assert!(
            Arc::ptr_eq(svc_gate, &gate),
            "both transports must hold the composition-root gate"
        );
    }

    /// One `SignerMetrics` registry serves both transports.
    #[test]
    fn test_both_transports_emit_to_one_metrics_registry() {
        let backend: Arc<dyn crate::backend::SigningBackend> = Arc::new(EmptyBackend);
        let gate = make_gate(Arc::clone(&backend));
        let metrics = Arc::new(SignerMetrics::new());
        let resolved = base_resolved(true);

        let grpc_deps = GrpcRouterDeps {
            resolved: &resolved,
            tls_config: None,
            signing_backend: Arc::clone(&backend),
            shared_gate: Some(Arc::clone(&gate)),
            client_cn_allow_list: None,
            signer_metrics: Arc::clone(&metrics),
            slashing_db: None,
            #[cfg(feature = "dvt")]
            dvt_share_map: None,
            #[cfg(feature = "dvt")]
            dvt_allow_list: None,
        };
        let svc = build_v2_signer_service(&grpc_deps);
        let svc_metrics = svc.shared_metrics().expect("gRPC holds metrics");

        let http_deps = HttpApiDeps {
            resolved: &resolved,
            shared_gate: Some(Arc::clone(&gate)),
            signing_backend: backend,
            signer_metrics: Arc::clone(&metrics),
            client_cn_allow_list: None,
        };
        let state = build_http_state(&http_deps).expect("HTTP state");

        assert!(
            Arc::ptr_eq(svc_metrics, &state.metrics),
            "gRPC and HTTP must share one SignerMetrics registry"
        );
        assert!(Arc::ptr_eq(svc_metrics, &metrics));
    }

    /// Disabled HTTP returns `Ok(None)` without requiring a gate.
    #[tokio::test]
    async fn test_spawn_http_api_disabled_returns_none() {
        let resolved = base_resolved(false);
        let backend: Arc<dyn crate::backend::SigningBackend> = Arc::new(EmptyBackend);
        let metrics = Arc::new(SignerMetrics::new());
        let deps = HttpApiDeps {
            resolved: &resolved,
            shared_gate: None,
            signing_backend: backend,
            signer_metrics: metrics,
            client_cn_allow_list: None,
        };
        let handle =
            spawn_http_api(deps, CancellationToken::new()).await.expect("disabled HTTP is ok");
        assert!(handle.is_none());
    }
}
