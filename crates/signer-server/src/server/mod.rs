//! Signer server composition root (`server::run`).
//!
//! RF5-19 moved the former `main::run_serve` body into the library target.
//! RF5-20 decomposes the first two phases into [`open_slashing_db`] and
//! [`build_backend`]; RF5-21 adds [`build_grpc_router`] and [`spawn_http_api`].

mod backend;
mod grpc;
mod http;
mod slashing;

pub(crate) use backend::build_backend;
pub(crate) use grpc::build_grpc_router;
pub(crate) use http::spawn_http_api;
pub(crate) use slashing::open_slashing_db;

/// Process-global env mutations in server unit tests must take this lock so
/// concurrent tests do not clobber each other's `RVC_*` variables.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|p| p.into_inner())
}

use std::sync::Arc;

use tracing::info;

use crate::error::ServerError;
use crate::{config, http_api, metrics, reload, service};

/// Run the signer server until `shutdown` is cancelled.
///
/// Composition root: crypto-provider install → password → TLS material →
/// [`build_backend`] → hot-reload / metrics → [`open_slashing_db`] → one shared
/// gate → [`spawn_http_api`] + [`build_grpc_router`] → serve until `shutdown`.
pub async fn run(
    resolved: crate::config::ResolvedConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), ServerError> {
    // Install the rustls crypto provider before any TLS work. Idempotent and
    // safe even with HTTP disabled. Forward-defense (ADR-006, R1): pins a single
    // explicit default so the Phase-3 `ServerConfig::builder()` path stays
    // deterministic and never hits rustls's automatic resolution, which panics
    // if the feature graph ever compiles in more than one provider. Not
    // load-bearing in today's ring-only build; see http_api::tls_config for details.
    http_api::tls_config::install_crypto_provider();

    info!(
        listen_address = %resolved.listen_address,
        keystore_dir = %resolved.keystore_dir.display(),
        backend = %resolved.backend,
        "Starting rvc-signer"
    );

    let password = config::load_serve_password(&resolved).map_err(ServerError::config)?;

    let tls_config = match (
        resolved.tls_cert.as_ref(),
        resolved.tls_key.as_ref(),
        resolved.tls_ca_cert.as_ref(),
    ) {
        (Some(cert), Some(key), Some(ca)) => {
            Some(crate::grpc_tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()))
        }
        _ => None,
    };

    // Set up Prometheus metrics early so DVT backend can use them
    let signer_metrics = Arc::new(metrics::SignerMetrics::new());

    // Build the signing backend and optional share-map for the PeerSignerService.
    // The PeerSignerService is constructed later (after the slashing DB is opened),
    // so build_backend returns the raw share_map / allow-list rather than a complete
    // service. Allow-list is loaded ONCE inside build_backend (ISSUE-4.1 / L-1).
    let built = build_backend(&resolved, &signer_metrics, &password, tls_config.as_ref()).await?;
    let signing_backend = built.signing_backend;
    let basic_signer_ref = built.basic_signer;
    #[cfg(feature = "dvt")]
    let dvt_share_map_opt = built.dvt_share_map;
    #[cfg(feature = "dvt")]
    let dvt_allow_list_opt = built.dvt_allow_list;

    // Validate TLS certificates if provided
    if let Some(ref tls) = tls_config {
        tls.to_server_tls_config().map_err(|e| ServerError::tls(e.to_string()))?;
    }

    if resolved.dry_run {
        println!("Configuration valid:");
        println!("  Backend: {}", resolved.backend);
        println!("  Keys loaded: {}", signing_backend.public_keys().len());
        if tls_config.is_some() {
            println!("  TLS: certificates valid");
        } else {
            println!("  TLS: disabled");
        }
        #[cfg(feature = "dvt")]
        if matches!(resolved.backend, config::Backend::Dvt) {
            println!("  DVT peers: {}", resolved.dvt_peers.len());
            if let Some(threshold) = resolved.dvt_threshold {
                println!("  DVT threshold: {}", threshold);
            }
            if let Some(index) = resolved.dvt_index {
                println!("  DVT index: {}", index);
            }
        }
        return Ok(());
    }

    // ISSUE-4.6 / L-6: keystore hot-reload is opt-in.  The reloader is only
    // spawned when `--enable-hot-reload` is set (or the equivalent TOML key
    // is true) AND `reload_interval_secs > 0`.  Each reload pass also
    // enforces a strict 0o700 / signer-UID-owned directory check before
    // touching keys (see `reload.rs::scan_and_reload`).
    if let Some(ref basic_signer) = basic_signer_ref {
        if resolved.enable_hot_reload && resolved.reload_interval_secs > 0 {
            let reloader = reload::KeystoreReloader::new(
                resolved.keystore_dir.clone(),
                password.clone(),
                std::time::Duration::from_secs(resolved.reload_interval_secs),
                Arc::clone(basic_signer),
            );

            let cancel = tokio_util::sync::CancellationToken::new();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                reloader.run(cancel_clone).await;
            });

            info!(
                interval_secs = resolved.reload_interval_secs,
                "Keystore hot-reload enabled (--enable-hot-reload)"
            );
        } else if resolved.reload_interval_secs > 0 {
            // Operators upgrading from a previous release where the reloader
            // ran by default with a 30s interval will see this notice once
            // at startup if they had a non-zero interval configured.
            info!(
                "Keystore hot-reload disabled (set --enable-hot-reload to opt in; \
                 ISSUE-4.6 / L-6)"
            );
        }
    }

    // Set up Prometheus metrics server
    let key_count = signing_backend.public_keys().len() as f64;
    let backend_label = resolved.backend.as_str();
    signer_metrics.keys_loaded.with_label_values(&[backend_label]).set(key_count);

    let metrics_addr: std::net::SocketAddr = resolved
        .metrics_address
        .parse()
        .map_err(|e| ServerError::bind(format!("invalid metrics address: {e}")))?;
    let (_metrics_handle, metrics_bound_addr) =
        metrics::serve_metrics(metrics_addr, Arc::clone(&signer_metrics))
            .await
            .map_err(|e| ServerError::bind(e.to_string()))?;
    info!(address = %metrics_bound_addr, "Prometheus metrics server listening");

    let slashing_db_opt = open_slashing_db(&resolved)?;

    // Build the v2 service implementation (RF2-17: v1 proto surface is gone).
    // Hoist (ADR-003, FR-26): build the ONE shared `SigningGate` at the
    // composition root, then inject the same `Arc` into BOTH the gRPC service and
    // the HTTP listener (Issue 3.5). `None` when slashing protection is disabled
    // (the gRPC `new()` path and the HTTP no-gate refusal below both handle it).
    let shared_gate: Option<Arc<signer::SigningGate>> = slashing_db_opt.as_ref().map(|db| {
        Arc::new(service::SignerServiceImpl::build_gate(
            Arc::clone(&signing_backend),
            Arc::clone(db),
        ))
    });

    // SEC-4: optional primary-path client-CN allow-list. When unset, warn and
    // accept any mTLS client (backward compatible). mTLS still mandatory.
    let client_cn_allow_list: Option<Arc<crate::audit::ClientCnAllowList>> =
        if let Some(path) = resolved.allowed_client_cns.as_deref() {
            let list = crate::audit::ClientCnAllowList::load_from_path(path).map_err(|e| {
                ServerError::config(format!("failed to load client-CN allow-list: {e}"))
            })?;
            info!(
                path = %path.display(),
                client_count = list.len(),
                "Loaded primary client-CN allow-list (SEC-4)"
            );
            Some(Arc::new(list))
        } else {
            crate::audit::log_missing_client_cn_allow_list_warning();
            None
        };

    // Build the gRPC router first (TLS / H-9 insecure gate / services) so a
    // transport-config failure never leaves an HTTP listener half-started.
    let built_grpc = build_grpc_router(grpc::GrpcRouterDeps {
        resolved: &resolved,
        tls_config: tls_config.as_ref(),
        signing_backend: Arc::clone(&signing_backend),
        shared_gate: shared_gate.clone(),
        client_cn_allow_list: client_cn_allow_list.clone(),
        signer_metrics: Arc::clone(&signer_metrics),
        slashing_db: slashing_db_opt,
        #[cfg(feature = "dvt")]
        dvt_share_map: dvt_share_map_opt,
        #[cfg(feature = "dvt")]
        dvt_allow_list: dvt_allow_list_opt,
    })?;

    // ── Web3Signer HTTP API listener (Issue 3.5, FR-25/26/27, ADR-001) ────────
    //
    // Opt-in via `[signer.http]`; gRPC stays default-on and unchanged. The HTTP
    // state carries the SAME `Arc<SigningGate>` injected into the gRPC service
    // (FR-26), so slashing protection + the in-memory `ValidatorLockMap` are
    // unified across both transports. A panic in an HTTP connection task is
    // isolated and never touches the gRPC accept loop (Issue 3.3).
    let http_shutdown = tokio_util::sync::CancellationToken::new();
    let http_handle = spawn_http_api(
        http::HttpApiDeps {
            resolved: &resolved,
            shared_gate,
            signing_backend: Arc::clone(&signing_backend),
            signer_metrics: Arc::clone(&signer_metrics),
            client_cn_allow_list,
        },
        http_shutdown.clone(),
    )
    .await?;

    info!(address = %built_grpc.listen_addr, "gRPC server listening");

    built_grpc
        .router
        .serve_with_shutdown(built_grpc.listen_addr, async move { shutdown.cancelled().await })
        .await
        .map_err(|e| ServerError::bind(e.to_string()))?;

    // gRPC has shut down (shutdown token cancelled). Stop the HTTP listener
    // accepting new connections and drain any in-flight `/sign` (bounded inside
    // serve_https). Log-reload SIGHUP task is owned by `main` (init_logging).
    http_shutdown.cancel();
    if let Some(handle) = http_handle {
        let _ = handle.await;
    }

    Ok(())
}

#[cfg(test)]
// RF1-12: unit tests may mutate env via unsafe set_var/remove_var.
// await_holding_lock: ENV_LOCK intentionally serializes process-global env
// mutations across async tests (same pattern as main.rs logging tests).
#[allow(unsafe_code, clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::error::ServerError;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        listener.local_addr().expect("local_addr").port()
    }

    fn create_keystore(dir: &std::path::Path, password: &str) {
        use crypto::{EncryptionKdf, Keystore, SecretKey};
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let ks = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let filename = format!("{}.json", hex::encode(pubkey));
        std::fs::write(dir.join(filename), ks.to_json().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// Build a minimal `ResolvedConfig` pointing at a temp keystore + password.
    fn base_resolved(tmp: &TempDir) -> ResolvedConfig {
        let keystore_dir = tmp.path().join("keystores");
        std::fs::create_dir(&keystore_dir).unwrap();
        let password = "test-password";
        create_keystore(&keystore_dir, password);
        let password_file = tmp.path().join("password.txt");
        std::fs::write(&password_file, password).unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();
        let listen = free_port();
        let metrics = free_port();

        ResolvedConfig {
            listen_address: format!("127.0.0.1:{listen}"),
            keystore_dir,
            password_file: Some(password_file),
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
            data_dir: Some(data_dir),
            disable_slashing_protection: false,
            init_slashing_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            gloas_fork_epoch: u64::MAX,
            metrics_address: format!("127.0.0.1:{metrics}"),
            enable_log_reload: false,
            allowed_client_cns: None,
            #[cfg(feature = "dvt")]
            dvt_allowed_peers: None,
        }
    }

    /// Missing slashing DB without `--init-slashing-db` → `ServerError::SlashingDb`.
    #[tokio::test]
    async fn test_server_run_returns_slashing_db_error_variant_on_missing_db() {
        let _g = env_lock();
        let prev = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true") };

        let tmp = TempDir::new().unwrap();
        let resolved = base_resolved(&tmp);
        // data_dir exists, but no signer-slashing.db and init_slashing_db=false.
        assert!(!resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        let shutdown = CancellationToken::new();
        let err = run(resolved, shutdown).await.expect_err("must refuse missing slashing DB");
        assert!(
            matches!(err, ServerError::SlashingDb(_)),
            "expected SlashingDb variant, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist") || msg.contains("slashing"),
            "message should mention missing DB: {msg}"
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
    }

    /// `server::run` is callable in-process (no subprocess) and returns Ok on cancel.
    #[tokio::test]
    async fn test_server_run_is_callable_in_process() {
        let _g = env_lock();
        let prev_signer = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        let prev_allow = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe {
            std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
            std::env::set_var("RVC_ALLOW_INSECURE", "true");
        }

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        // Disable slashing so we can start without a DB for a short-lived smoke.
        resolved.disable_slashing_protection = true;
        resolved.init_slashing_db = false;

        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let handle = tokio::spawn(async move { run(resolved, shutdown2).await });

        // Give the server a moment to bind, then cancel.
        tokio::time::sleep(Duration::from_millis(300)).await;
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("join timed out")
            .expect("task panicked");
        assert!(result.is_ok(), "in-process run should shut down cleanly: {result:?}");

        match prev_signer {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
        match prev_allow {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    /// Cancelling the token stops `server::run` without error.
    #[tokio::test]
    async fn test_server_run_shuts_down_on_cancellation_token() {
        let _g = env_lock();
        let prev_signer = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        let prev_allow = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe {
            std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
            std::env::set_var("RVC_ALLOW_INSECURE", "true");
        }

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.disable_slashing_protection = true;

        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let handle = tokio::spawn(async move { run(resolved, shutdown2).await });

        // Wait until metrics/gRPC ports are likely bound, then cancel.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Best-effort: cancel as soon as a little time has passed.
        }
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("join timed out")
            .expect("task panicked");
        assert!(result.is_ok(), "cancel should yield Ok: {result:?}");

        match prev_signer {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
        match prev_allow {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    /// Process exit code for every `ServerError` class remains `1`.
    #[test]
    fn test_exit_codes_unchanged_for_each_failure_class() {
        // Mirrors `main::classify_exit_code` — every class exits 1 today.
        fn exit_code(err: &ServerError) -> i32 {
            match err {
                ServerError::SlashingDb(_)
                | ServerError::Backend(_)
                | ServerError::Tls(_)
                | ServerError::Bind(_)
                | ServerError::Config(_)
                | ServerError::Io(_) => 1,
            }
        }

        let cases = [
            ServerError::slashing_db("missing db"),
            ServerError::backend("bad keystore"),
            ServerError::tls("bad cert"),
            ServerError::bind("addr in use"),
            ServerError::config("bad flag"),
            ServerError::Io(std::io::Error::other("io")),
        ];
        for err in cases {
            assert_eq!(exit_code(&err), 1, "exit code changed for {err:?}");
        }
    }

    /// Dry-run path: callable without binding listeners.
    #[tokio::test]
    async fn test_server_run_dry_run_ok() {
        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.dry_run = true;
        // dry_run returns before TLS/slashing gates; insecure still fine.
        let shutdown = CancellationToken::new();
        run(resolved, shutdown).await.expect("dry_run should succeed");
    }
}
