//! Bootstrap phase: metrics, monitoring, proposer-config, BN SSE, and sync-monitor tasks.
//!
//! Extracted from the former `run_validator` tail so the ISSUE-4.10 metrics bind
//! gate and task cancel/drain sequence can be unit-tested without the full
//! startup chain.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use bn_manager::BnManager;
use metrics::SharedHealthStatus;
use tokio::sync::watch;
use tracing::{error, info, warn};
use validator_store::ValidatorStore;

use super::executor::{ShutdownTier, TaskExecutor};
use super::BootstrapError;
use crate::config::{redact_url, Config};
use crate::orchestrator::head_events::HeadEventGate;
use crate::orchestrator::PubkeyMap;

/// Executor name for the BN SSE subscriber (ARCH-3l).
pub const SSE_TASK_NAME: &str = "bn.sse";

/// Cancel-forwarder that maps the process token onto `start_sse`'s `watch<bool>`.
pub const SSE_CANCEL_TASK_NAME: &str = "bn.sse.cancel";

/// Executor name for the BN sync monitor (DSR-2.1 / FR-P1-3).
pub const SYNC_MONITOR_TASK_NAME: &str = "bn.sync_monitor";

/// Cancel-forwarder that maps the process token onto `start_sync_monitor`'s `watch<bool>`.
pub const SYNC_MONITOR_CANCEL_TASK_NAME: &str = "bn.sync_monitor.cancel";

/// Env var that opts in to non-loopback metrics binds (ISSUE-4.10 / L-10).
pub const METRICS_ALLOW_NON_LOOPBACK_ENV: &str = "RVC_METRICS_ALLOW_NON_LOOPBACK";

/// Enforce the ISSUE-4.10 non-loopback metrics bind gate.
///
/// Loopback binds pass silently. Non-loopback binds require
/// `RVC_METRICS_ALLOW_NON_LOOPBACK=true`. Uses `InsecureGate::with_predicate`
/// with a constant-true predicate so the env var alone decides the outcome
/// (see comment preserved from the binary).
pub fn check_metrics_bind_gate(metrics_address: IpAddr) -> Result<(), BootstrapError> {
    if metrics_address.is_loopback() {
        return Ok(());
    }

    // The predicate is constant-true here: the bind is already known to
    // be non-loopback, so the env var alone determines the outcome (the
    // InsecureGate `new()` constructor would set predicate=is_loopback,
    // which is false at this point and would refuse even with the env
    // var set; with_predicate keeps the env-var-only contract).
    let metrics_gate = crypto::insecure::InsecureGate::with_predicate(
        METRICS_ALLOW_NON_LOOPBACK_ENV,
        crypto::insecure::InsecureMode::default(),
        || true,
    );
    if let Err(e) = metrics_gate.check() {
        error!(
            addr = %metrics_address,
            error = %e,
            "Refusing to start metrics server on non-loopback address (ISSUE-4.10 / L-10)"
        );
        return Err(BootstrapError::MetricsBind(e));
    }
    warn!(
        addr = %metrics_address,
        "Metrics server is bound to a non-loopback address (RVC_METRICS_ALLOW_NON_LOOPBACK=true); \
         this exposes metrics over the network"
    );
    Ok(())
}

/// Live validator counts for the monitoring push.
///
/// Returns `(total_loaded, active_enabled)`:
/// - element 0 = keys currently loaded in [`PubkeyMap`]
/// - element 1 = signing-enabled validators in [`ValidatorStore`]
///
/// Reads are sequential (map guard dropped before store access) so the two
/// locks are never held nested. The pair is a **best-effort, non-atomic
/// snapshot**: a monitoring tick can briefly observe `active > total` (e.g.
/// DELETE removes the map entry before the store entry). Operational
/// telemetry only — not a transactional inventory; accepted residual.
fn live_monitoring_counts(pubkey_map: &PubkeyMap, validator_store: &ValidatorStore) -> (u32, u32) {
    let total = pubkey_map.read().len() as u32;
    let active = validator_store.list_enabled_pubkeys().len() as u32;
    (total, active)
}

/// Spawn metrics on `metrics_listener`, plus optional monitoring and proposer refresh
/// through the process [`TaskExecutor`] (ARCH-2g).
///
/// Cooperative tasks take `executor.token()` and exit on cancel. The metrics
/// server has no token (abort-drain on Telemetry tier via `TaskExecutor::shutdown`).
///
/// `pubkey_map` and `validator_store` are captured by the monitoring push so
/// each interval reports live totals (not a boot-time constant).
pub fn spawn_background_tasks(
    config: &Config,
    metrics_listener: tokio::net::TcpListener,
    health_status: SharedHealthStatus,
    executor: &TaskExecutor,
    pubkey_map: PubkeyMap,
    validator_store: Arc<ValidatorStore>,
) -> Result<(), BootstrapError> {
    let metrics_address = config.metrics_address;
    let metrics_port = config.metrics_port;
    check_metrics_bind_gate(metrics_address)?;

    // Force-register families (including PTC zero-children) before the scrape listener.
    crate::metrics::init();

    info!(addr = %metrics_address, port = metrics_port, "Starting metrics server");
    // P1-2: Telemetry tier; no cooperative token (abort-drain).
    // detached: metrics server; serve loop is serve_metrics_on (no bind), out of P1-1 scope.
    executor.spawn("metrics_server", ShutdownTier::Telemetry, async move {
        if let Err(e) = metrics::server::serve_metrics_on(metrics_listener, health_status).await {
            error!(error = %e, "Metrics server exited with error");
        }
    });
    // Listener was bound by bind_required_listeners after check_metrics_bind_gate.
    // This spawn serves that socket and does not bind a second time.

    // P1-3: monitoring push (PB-B2) — Background tier.
    if let Some(ref monitoring_endpoint) = config.monitoring.endpoint {
        let monitoring_config = crate::background_tasks::monitoring::MonitoringConfig {
            endpoint: monitoring_endpoint.clone(),
            interval: Duration::from_secs(config.monitoring.interval),
            insecure: config.monitoring.endpoint_insecure,
        };
        let monitoring_shutdown = executor.token();
        let store_for_monitoring = Arc::clone(&validator_store);
        info!(
            endpoint = %redact_url(monitoring_endpoint),
            interval_secs = config.monitoring.interval,
            "Starting monitoring push task"
        );
        executor.spawn("monitoring_push", ShutdownTier::Background, async move {
            crate::background_tasks::monitoring::start_monitoring_push(
                monitoring_config,
                monitoring_shutdown,
                move || live_monitoring_counts(&pubkey_map, &store_for_monitoring),
            )
            .await;
        });
    }

    // P1-4: proposer config URL refresh (PB-B1) — Background tier.
    if let Some(ref proposer_config_url) = config.proposer_config.url {
        let settings = crate::background_tasks::config_url::ProposerConfigUrlSettings {
            url: proposer_config_url.clone(),
            refresh_interval: Duration::from_secs(config.proposer_config.refresh_interval),
            token: config.proposer_config.url_token.clone(),
            insecure: config.proposer_config.url_insecure,
        };
        let config_refresh_shutdown = executor.token();
        info!(
            url = %redact_url(proposer_config_url),
            refresh_interval_secs = config.proposer_config.refresh_interval,
            "Starting proposer config URL refresh task"
        );
        // The applier remembers seen pubkeys. `apply` takes the store locks.
        // The store does not call back into the applier. `parking_lot::Mutex`
        // does not poison.
        let proposer_config_applier =
            Arc::new(Mutex::new(crate::background_tasks::config_url::ProposerConfigApplier::new()));
        executor.spawn("proposer_config_refresh", ShutdownTier::Background, async move {
            crate::background_tasks::config_url::start_proposer_config_refresh(
                settings,
                config_refresh_shutdown,
                move |fetched| {
                    // `start_proposer_config_refresh` runs this closure in
                    // `spawn_blocking`. `apply` waits on `save_lock`, which
                    // durable writers hold across `write_toml_atomic` and
                    // `sync_parent_dir`.
                    let mut applier = proposer_config_applier.lock();
                    applier.apply(&validator_store, fetched.updates, fetched.default_update);
                },
            )
            .await;
        });
    }

    Ok(())
}

/// Register the BN SSE subscriber at tier [`ShutdownTier::Background`].
///
/// `None` / unconfigured uses [`TaskExecutor::register_opt`] so
/// `rvc_tasks_running{task="bn.sse"}` stays honest. `start_sse` is Infra and
/// cannot depend on the executor (DAG): its `JoinHandle` is passed to
/// [`TaskExecutor::register`]. A small [`SSE_CANCEL_TASK_NAME`] forwarder maps
/// the process token onto `start_sse`'s `watch<bool>` and then aborts the
/// Infra handle so drain does not wait on `sse.rs`'s uninterruptible reconnect
/// sleep. A panic in that handle is `ShutdownReason::Failure("bn.sse")`.
/// Framing failures are not panics: a leading BOM, an oversize line or
/// `data`/`event`/`id` field, or invalid UTF-8 closes the BN connection and
/// the subscriber reconnects or fails over. Timer-based duties keep running.
pub fn spawn_sse_subscriber(
    bn_manager: Option<Arc<BnManager>>,
    executor: &TaskExecutor,
) -> Option<HeadEventGate> {
    let Some(bn_manager) = bn_manager else {
        executor.register_opt::<()>(SSE_TASK_NAME, ShutdownTier::Background, None);
        return None;
    };

    let (bridge, gate) = HeadEventGate::pair();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    info!("Starting beacon-node SSE subscriber");
    let sse_handle = bn_manager.start_sse(bridge.into_callback(), shutdown_rx);
    let sse_abort = sse_handle.abort_handle();
    // detached: BN SSE subscriber; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope.
    executor.register(SSE_TASK_NAME, ShutdownTier::Background, sse_handle);

    let token = executor.token();
    // detached: cancel-forwarder for bn.sse; not an iteration loop.
    executor.spawn(SSE_CANCEL_TASK_NAME, ShutdownTier::Background, async move {
        token.cancelled().await;
        let _ = shutdown_tx.send(true);
        sse_abort.abort();
    });
    Some(gate)
}

/// Register the BN sync-status monitor at tier [`ShutdownTier::Background`].
///
/// `None` / unconfigured uses [`TaskExecutor::register_opt`] so
/// `rvc_tasks_running{task="bn.sync_monitor"}` stays honest. `start_sync_monitor`
/// is Infra and cannot depend on the executor (DAG): its `JoinHandle` is passed
/// to [`TaskExecutor::register`]. A small [`SYNC_MONITOR_CANCEL_TASK_NAME`]
/// forwarder maps the process token onto `start_sync_monitor`'s `watch<bool>`
/// and then aborts the Infra handle so drain does not wait on an in-flight poll.
/// A panic in that handle is `ShutdownReason::Failure("bn.sync_monitor")`.
///
/// `interval` is forwarded to [`BnManager::start_sync_monitor`]; `None` uses the
/// default one-epoch poll cadence.
pub fn spawn_sync_monitor(
    bn_manager: Option<Arc<BnManager>>,
    executor: &TaskExecutor,
    interval: Option<Duration>,
) {
    let Some(bn_manager) = bn_manager else {
        executor.register_opt::<()>(SYNC_MONITOR_TASK_NAME, ShutdownTier::Background, None);
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    info!("Starting beacon-node sync monitor");
    let sync_handle = bn_manager.start_sync_monitor(interval, shutdown_rx);
    let sync_abort = sync_handle.abort_handle();
    // detached: BN sync monitor; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope.
    executor.register(SYNC_MONITOR_TASK_NAME, ShutdownTier::Background, sync_handle);

    let token = executor.token();
    // detached: cancel-forwarder for bn.sync_monitor; not an iteration loop.
    executor.spawn(SYNC_MONITOR_CANCEL_TASK_NAME, ShutdownTier::Background, async move {
        token.cancelled().await;
        let _ = shutdown_tx.send(true);
        sync_abort.abort();
    });
}

/// Executor name for the proposer-pool sync monitor.
pub const PROPOSER_SYNC_MONITOR_TASK_NAME: &str = "bn.proposer_sync_monitor";

/// Cancel-forwarder for [`PROPOSER_SYNC_MONITOR_TASK_NAME`].
pub const PROPOSER_SYNC_MONITOR_CANCEL_TASK_NAME: &str = "bn.proposer_sync_monitor.cancel";

/// Register the proposer-pool sync monitor at [`ShutdownTier::Background`].
///
/// Same shape as [`spawn_sync_monitor`]. `None` uses
/// [`TaskExecutor::register_opt`] and is not a census site. The poll loop
/// lives in bn-manager. The caller passes the interval from
/// [`bn_manager::sync_check_interval_for`].
pub fn spawn_proposer_sync_monitor(
    bn_manager: Option<Arc<BnManager>>,
    executor: &TaskExecutor,
    interval: Option<Duration>,
) {
    let Some(bn_manager) = bn_manager else {
        executor.register_opt::<()>(
            PROPOSER_SYNC_MONITOR_TASK_NAME,
            ShutdownTier::Background,
            None,
        );
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    info!("Starting proposer beacon-node sync monitor");
    let sync_handle = bn_manager.start_sync_monitor(interval, shutdown_rx);
    let sync_abort = sync_handle.abort_handle();
    // detached: proposer BN sync monitor; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope.
    executor.register(PROPOSER_SYNC_MONITOR_TASK_NAME, ShutdownTier::Background, sync_handle);

    let token = executor.token();
    // detached: cancel-forwarder for bn.proposer_sync_monitor; not an iteration loop.
    executor.spawn(PROPOSER_SYNC_MONITOR_CANCEL_TASK_NAME, ShutdownTier::Background, async move {
        token.cancelled().await;
        let _ = shutdown_tx.send(true);
        sync_abort.abort();
    });
}

/// Listeners bound before keystore load so a port clash aborts startup.
///
/// `metrics` is always bound. `keymanager` is bound only when
/// `config.keymanager.enabled` is set.
#[derive(Debug)]
pub struct RequiredListeners {
    /// Metrics and health HTTP listener.
    pub metrics: tokio::net::TcpListener,
    /// Keymanager API listener. `None` when keymanager is disabled.
    pub keymanager: Option<tokio::net::TcpListener>,
}

/// Bind the metrics listener, then the keymanager listener when it is enabled.
///
/// [`check_metrics_bind_gate`] runs first, so a non-loopback metrics address
/// without `RVC_METRICS_ALLOW_NON_LOOPBACK=true` is [`BootstrapError::MetricsBind`]
/// (exit 1) and nothing is bound. A port clash is [`BootstrapError::ListenerBind`]
/// (exit 15) and names the listener and the address.
///
/// The keymanager address uses the loopback default `127.0.0.1:5062` when unset
/// ([`crate::keymanager_adapters::keymanager_bind_addr`]). Disabled keymanager
/// does not bind.
pub async fn bind_required_listeners(config: &Config) -> Result<RequiredListeners, BootstrapError> {
    check_metrics_bind_gate(config.metrics_address)?;

    let metrics_addr = SocketAddr::from((config.metrics_address, config.metrics_port));
    let metrics = match tokio::net::TcpListener::bind(metrics_addr).await {
        Ok(listener) => listener,
        Err(source) => {
            error!(
                listener = "metrics",
                addr = %metrics_addr,
                error = %source,
                "failed to bind required listener"
            );
            return Err(BootstrapError::ListenerBind {
                listener: "metrics",
                addr: metrics_addr,
                source,
            });
        }
    };

    let keymanager = if config.keymanager.enabled {
        let addr = crate::keymanager_adapters::keymanager_bind_addr(config)?;
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => Some(listener),
            Err(source) => {
                error!(
                    listener = "keymanager",
                    addr = %addr,
                    error = %source,
                    "failed to bind required listener"
                );
                return Err(BootstrapError::ListenerBind { listener: "keymanager", addr, source });
            }
        }
    } else {
        None
    };

    Ok(RequiredListeners { metrics, keymanager })
}

#[cfg(test)]
// RF5-10: env-var contract tests use set_var/remove_var under a lock.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use keymanager_api::traits::KeystoreManager;
    use tempfile::TempDir;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    use validator_store::ValidatorConfig;

    use super::super::executor::{ShutdownReason, TierBudget};
    use crate::keymanager_adapters::KeystoreManagerAdapter;

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env_var<F: FnOnce()>(value: Option<&str>, f: F) {
        let _guard = env_lock();
        let prev = std::env::var(METRICS_ALLOW_NON_LOOPBACK_ENV).ok();
        // SAFETY: env mutations serialized by ENV_LOCK.
        unsafe {
            match value {
                Some(v) => std::env::set_var(METRICS_ALLOW_NON_LOOPBACK_ENV, v),
                None => std::env::remove_var(METRICS_ALLOW_NON_LOOPBACK_ENV),
            }
        }
        f();
        unsafe {
            match prev {
                Some(p) => std::env::set_var(METRICS_ALLOW_NON_LOOPBACK_ENV, p),
                None => std::env::remove_var(METRICS_ALLOW_NON_LOOPBACK_ENV),
            }
        }
    }

    fn empty_pubkey_map() -> PubkeyMap {
        Arc::new(parking_lot::RwLock::new(HashMap::new()))
    }

    fn empty_validator_store() -> Arc<ValidatorStore> {
        Arc::new(ValidatorStore::new([0u8; 20], 30_000_000))
    }

    async fn prebound_metrics(config: &Config) -> tokio::net::TcpListener {
        tokio::net::TcpListener::bind((config.metrics_address, config.metrics_port))
            .await
            .expect("pre-bind metrics listener")
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(fut)
    }

    fn encrypt_test_keystore(sk: &SecretKey) -> String {
        let keystore = crypto::Keystore::encrypt(
            sk,
            b"testpass",
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        serde_json::to_string(&keystore).expect("serialize keystore")
    }

    /// RR1-08: an occupied metrics port aborts with `ListenerBind` naming the
    /// listener and the address, and the process exit code is 15.
    #[tokio::test]
    async fn bind_required_listeners_fails_with_listener_and_addr() {
        let held =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("hold port");
        let addr = held.local_addr().expect("held addr");
        let config =
            Config { metrics_address: addr.ip(), metrics_port: addr.port(), ..Config::default() };

        let err =
            bind_required_listeners(&config).await.expect_err("occupied metrics port must fail");
        match &err {
            BootstrapError::ListenerBind { listener, addr: got, .. } => {
                assert_eq!(*listener, "metrics");
                assert_eq!(*got, addr);
            }
            other => panic!("expected ListenerBind, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("metrics"), "message must name the listener, got: {msg}");
        assert!(msg.contains(&addr.to_string()), "message must name the address, got: {msg}");
        assert_eq!(err.exit_code(), 15);
        assert_eq!(err.exit_code(), crate::startup::EXIT_LISTENER_BIND);
        // Keep the port occupied until the assertion returns.
        drop(held);
    }

    /// RR1-08: an occupied keymanager port is the same `ListenerBind` (exit 15)
    /// when keymanager is enabled.
    #[tokio::test]
    async fn bind_required_listeners_keymanager_port_held_is_listener_bind() {
        let held =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("hold port");
        let addr = held.local_addr().expect("held addr");
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            keymanager: crate::config::KeymanagerConfig {
                enabled: true,
                address: Some(addr.to_string()),
                ..Default::default()
            },
            ..Config::default()
        };

        let err =
            bind_required_listeners(&config).await.expect_err("occupied keymanager port must fail");
        match &err {
            BootstrapError::ListenerBind { listener, addr: got, .. } => {
                assert_eq!(*listener, "keymanager");
                assert_eq!(*got, addr);
            }
            other => panic!("expected ListenerBind, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("keymanager"), "message must name the listener, got: {msg}");
        assert!(msg.contains(&addr.to_string()), "message must name the address, got: {msg}");
        assert_eq!(err.exit_code(), crate::startup::EXIT_LISTENER_BIND);
        drop(held);
    }

    /// RR1-08: keymanager disabled does not bind, even if its address is held.
    #[tokio::test]
    async fn bind_required_listeners_skips_keymanager_when_disabled() {
        let held =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("hold port");
        let addr = held.local_addr().expect("held addr");
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            keymanager: crate::config::KeymanagerConfig {
                enabled: false,
                address: Some(addr.to_string()),
                ..Default::default()
            },
            ..Config::default()
        };

        let listeners = bind_required_listeners(&config)
            .await
            .expect("disabled keymanager must not bind the held address");
        assert!(listeners.keymanager.is_none(), "disabled keymanager must not bind");
        assert!(listeners.metrics.local_addr().expect("metrics addr").ip().is_loopback());
        drop(held);
    }

    /// RR1-08: a non-loopback metrics address still fails the gate (exit 1) and
    /// is not `ListenerBind` (exit 15).
    #[test]
    fn bind_required_listeners_non_loopback_metrics_is_metrics_bind_exit_1() {
        with_env_var(None, || {
            let config = Config {
                metrics_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                metrics_port: 0,
                ..Config::default()
            };
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(bind_required_listeners(&config))
                .expect_err("non-loopback metrics without opt-in must fail the gate");
            assert!(
                matches!(err, BootstrapError::MetricsBind(_)),
                "gate refusal must stay MetricsBind, got {err:?}"
            );
            assert!(!matches!(err, BootstrapError::ListenerBind { .. }));
            assert_eq!(err.exit_code(), 1);
            assert_ne!(err.exit_code(), 15);
            let msg = err.to_string();
            assert!(
                msg.contains(METRICS_ALLOW_NON_LOOPBACK_ENV),
                "error must name the opt-in env var, got: {msg}"
            );
        });
    }

    #[test]
    fn test_spawn_background_tasks_refuses_non_loopback_metrics_bind_without_env_optin() {
        with_env_var(None, || {
            let err = check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                .expect_err("non-loopback without env must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains(METRICS_ALLOW_NON_LOOPBACK_ENV),
                "error must name the opt-in env var, got: {msg}"
            );
        });
    }

    #[test]
    fn test_metrics_bind_gate_allows_loopback_without_env() {
        with_env_var(None, || {
            check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .expect("loopback must pass without env opt-in");
        });
    }

    #[test]
    fn test_metrics_bind_gate_allows_non_loopback_with_env_optin() {
        with_env_var(Some("true"), || {
            check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                .expect("non-loopback with env must pass");
        });
    }

    #[tokio::test]
    async fn test_metrics_server_answers_health_and_readyz() {
        let health = metrics::new_health_status();
        {
            let mut status = health.write().await;
            status.beacon_connected = true;
            status.validators_loaded = 1;
            status.slashing_db_initialized = true;
            status.update_healthy();
        }
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            ..Config::default()
        };
        let listener = prebound_metrics(&config).await;
        let port = listener.local_addr().expect("local_addr").port();
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
            listener,
            health,
            &executor,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("loopback metrics spawn");

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("reqwest client");
        let health_url = format!("http://127.0.0.1:{port}/health");
        let readyz_url = format!("http://127.0.0.1:{port}/readyz");
        let livez_url = format!("http://127.0.0.1:{port}/livez");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut health_ok = false;
        let mut readyz_ok = false;
        let mut livez_ok = false;
        while std::time::Instant::now() < deadline {
            if let Ok(resp) = client.get(&health_url).send().await {
                health_ok = resp.status().is_success();
            }
            if let Ok(resp) = client.get(&readyz_url).send().await {
                readyz_ok = resp.status().is_success();
            }
            if let Ok(resp) = client.get(&livez_url).send().await {
                livez_ok = resp.status().is_success();
            }
            if health_ok && readyz_ok && livez_ok {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(health_ok, "/health must answer on the metrics server");
        assert!(readyz_ok, "/readyz must answer on the metrics server");
        assert!(livez_ok, "/livez must answer on the metrics server");

        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_spawn_background_tasks_all_tasks_cancel_on_shutdown() {
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0, // OS-assigned; caller pre-binds ephemeral
            // monitoring / proposer_config left at nested defaults (disabled)
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let listener = prebound_metrics(&config).await;
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        spawn_background_tasks(
            &config,
            listener,
            health,
            &executor,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("loopback metrics spawn");

        // Give the server a moment to start, then drain via the executor.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_shutdown_drains_metrics_server_before_returning() {
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let listener = prebound_metrics(&config).await;
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
            listener,
            health,
            &executor,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("spawn");

        let start = std::time::Instant::now();
        let outcome = executor.shutdown(TierBudget::default()).await;
        // Telemetry tier default is 0.5 s abort-drain; stay under a generous bound.
        assert!(start.elapsed() < Duration::from_secs(3), "metrics drain exceeded shutdown bound");
        assert!(
            outcome.joined.contains(&"metrics_server")
                || outcome.aborted.contains(&"metrics_server"),
            "metrics_server must be accounted for in ShutdownOutcome"
        );
    }

    #[tokio::test]
    async fn test_background_tasks_are_registered_by_name() {
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            monitoring: crate::config::MonitoringConfig {
                endpoint: Some("http://127.0.0.1:9/metrics".into()),
                interval: 60,
                endpoint_insecure: true,
            },
            proposer_config: crate::config::ProposerConfigSource {
                url: Some("http://127.0.0.1:9/proposer".into()),
                refresh_interval: 60,
                url_token: None,
                url_insecure: true,
                ..Default::default()
            },
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let listener = prebound_metrics(&config).await;
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
            listener,
            health,
            &executor,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("spawn");

        let names: Vec<_> = executor.registered_names();
        for expected in ["metrics_server", "monitoring_push", "proposer_config_refresh"] {
            assert!(names.contains(&expected), "missing registered task {expected}: {names:?}");
        }

        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[test]
    fn monitoring_count_reflects_a_keymanager_import() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();
        let count = || live_monitoring_counts(&pubkey_map, &validator_store);

        assert_eq!(count(), (0, 0));

        let dir = TempDir::new().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let (tx, _rx) = watch::channel(0u64);
        let adapter = KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            composite,
            pubkey_map.clone(),
            tx,
        );

        let sk = SecretKey::generate();
        let keystore_json = encrypt_test_keystore(&sk);
        block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();

        let (total, _active) = count();
        assert_eq!(total, 1, "keymanager import must bump live total loaded count");
    }

    #[test]
    fn monitoring_count_reflects_a_delete() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();
        let count = || live_monitoring_counts(&pubkey_map, &validator_store);

        let dir = TempDir::new().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let (tx, _rx) = watch::channel(0u64);
        let adapter = KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            composite,
            pubkey_map.clone(),
            tx,
        );

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let keystore_json = encrypt_test_keystore(&sk);
        block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();
        assert_eq!(count().0, 1);

        assert!(adapter.delete_keystore(&pk_bytes).unwrap());
        assert_eq!(count().0, 0, "keymanager delete must drop live total loaded count");
    }

    #[test]
    fn total_and_active_are_distinct_when_a_validator_is_disabled() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = sk1.public_key().to_bytes();
        let pk2 = sk2.public_key().to_bytes();

        pubkey_map.write().insert(pk1, sk1.public_key());
        pubkey_map.write().insert(pk2, sk2.public_key());
        validator_store.add_validator(ValidatorConfig::new(pk1)).unwrap();
        validator_store.add_validator(ValidatorConfig::new(pk2)).unwrap();

        assert_eq!(live_monitoring_counts(&pubkey_map, &validator_store), (2, 2));

        validator_store.set_enabled(&pk1, false);
        assert_eq!(
            live_monitoring_counts(&pubkey_map, &validator_store),
            (2, 1),
            "disabled validator must reduce active without changing total loaded"
        );
    }

    fn test_bn_manager() -> Arc<BnManager> {
        Arc::new(
            BnManager::new(bn_manager::BnManagerConfig::new(vec!["http://127.0.0.1:9".into()]))
                .expect("test BnManager"),
        )
    }

    #[tokio::test]
    async fn test_head_event_subscriber_is_started_at_bootstrap() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let gate = spawn_sse_subscriber(Some(test_bn_manager()), &executor);
        assert!(gate.is_some(), "configured SSE must return a HeadEventGate");
        let names = executor.registered_names();
        assert!(
            names.contains(&SSE_TASK_NAME),
            "missing registered task {SSE_TASK_NAME}: {names:?}"
        );
        assert!(
            names.contains(&SSE_CANCEL_TASK_NAME),
            "missing cancel-forwarder {SSE_CANCEL_TASK_NAME}: {names:?}"
        );
        let entries = executor.registry_entries();
        assert!(
            entries.contains(&(SSE_TASK_NAME, ShutdownTier::Background)),
            "bn.sse must be Background, got {entries:?}"
        );
        assert!(
            entries.contains(&(SSE_CANCEL_TASK_NAME, ShutdownTier::Background)),
            "bn.sse.cancel must be Background, got {entries:?}"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_sse_unconfigured_uses_register_opt() {
        use metrics::definitions::RVC_TASKS_RUNNING;

        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let before = RVC_TASKS_RUNNING.with_label_values(&[SSE_TASK_NAME]).get();
        let gate = spawn_sse_subscriber(None, &executor);
        assert!(gate.is_none());
        assert!(
            !executor.registered_names().contains(&SSE_TASK_NAME),
            "unconfigured SSE must not register {SSE_TASK_NAME}"
        );
        assert!(
            !executor.registered_names().contains(&SSE_CANCEL_TASK_NAME),
            "unconfigured SSE must not register {SSE_CANCEL_TASK_NAME}"
        );
        assert_eq!(
            RVC_TASKS_RUNNING.with_label_values(&[SSE_TASK_NAME]).get(),
            before,
            "register_opt(None) must not touch rvc_tasks_running{{task={SSE_TASK_NAME}}}"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_sse_task_stops_on_cancellation_within_its_tier_budget() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let _gate = spawn_sse_subscriber(Some(test_bn_manager()), &executor);

        let budget = TierBudget::new([
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(500),
            Duration::from_millis(50),
        ]);
        let start = std::time::Instant::now();
        let outcome = executor.shutdown(budget).await;
        let elapsed = start.elapsed();

        assert!(
            outcome.joined.contains(&SSE_TASK_NAME) || outcome.aborted.contains(&SSE_TASK_NAME),
            "bn.sse must finish within Background budget (abort-on-cancel; sse.rs reconnect sleep is uninterruptible), joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "SSE cancel took {elapsed:?}, expected inside Background budget"
        );
    }

    /// `BnManager::start_sse` cannot be forced to panic without editing bn-manager.
    /// The production path is `executor.register(SSE_TASK_NAME, …, start_sse_handle)`,
    /// so a panic in that handle is `ShutdownReason::Failure("bn.sse")`.
    #[tokio::test]
    async fn test_registered_sse_handle_panic_surfaces_failure_reason() {
        let (executor, mut rx) = TaskExecutor::new(CancellationToken::new());
        executor.register(
            SSE_TASK_NAME,
            ShutdownTier::Background,
            tokio::spawn(async { panic!("injected start_sse JoinHandle panic") }),
        );

        let reason = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");
        assert_eq!(reason, ShutdownReason::Failure(SSE_TASK_NAME));
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    /// A leading BOM used to panic inside `eventsource-stream` (`&str[1..]` on
    /// U+FEFF). That panic is `ShutdownReason::Failure("bn.sse")` and drains
    /// the process, which stops timer-driven duties. Framing errors must stay
    /// inside the subscriber.
    #[tokio::test]
    async fn test_malformed_sse_stream_does_not_fail_the_process() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio::sync::mpsc::error::TryRecvError;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    // U+FEFF (EF BB BF) then invalid UTF-8. The old parser panics
                    // on the BOM before it can report the bad bytes.
                    let body = b"\xEF\xBB\xBF\xFF\xFEnot-an-event\n";
                    let headers = "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Transfer-Encoding: chunked\r\n\
                         \r\n";
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let chunk = format!("{:x}\r\n", body.len());
                    let _ = stream.write_all(chunk.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    let _ = stream.write_all(b"\r\n").await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });

        let bn = Arc::new(
            BnManager::new(bn_manager::BnManagerConfig::new(vec![format!(
                "http://127.0.0.1:{port}"
            )]))
            .expect("test BnManager"),
        );
        let (executor, mut rx) = TaskExecutor::new(CancellationToken::new());
        let _gate = spawn_sse_subscriber(Some(bn), &executor);

        let ticks = Arc::new(AtomicUsize::new(0));
        let ticks_task = Arc::clone(&ticks);
        executor.spawn("slot.timer", ShutdownTier::Orchestrator, async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            loop {
                interval.tick().await;
                ticks_task.fetch_add(1, Ordering::Relaxed);
            }
        });

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let reason = rx.try_recv();
        assert!(
            matches!(reason, Err(TryRecvError::Empty)),
            "malformed SSE must not end in ShutdownReason::Failure(\"bn.sse\"), got {reason:?}"
        );
        assert!(
            ticks.load(Ordering::Relaxed) >= 5,
            "timer-based duties must keep running while SSE is down, ticks={}",
            ticks.load(Ordering::Relaxed)
        );

        let _ = executor.shutdown(TierBudget::default()).await;
        server.abort();
    }

    #[test]
    fn test_spawn_sse_subscriber_registers_the_start_sse_handle() {
        let src = include_str!("tasks.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body");
        assert!(
            body.contains("executor.register(SSE_TASK_NAME") && body.contains("sse_handle"),
            "ARCH-3l must register the start_sse JoinHandle as bn.sse"
        );
        assert!(
            body.contains("executor.spawn(SSE_CANCEL_TASK_NAME"),
            "token→watch mapping must be a named cancel-forwarder, not the bn.sse work"
        );
        assert!(
            !body.contains("executor.spawn(SSE_TASK_NAME"),
            "bn.sse must not be an adapter wrapper around start_sse"
        );
    }

    #[test]
    fn sync_monitor_interval_is_one_epoch_of_the_bn_slot_duration() {
        let interval = bn_manager::sync_check_interval_for(Duration::from_millis(6_000), 32);
        assert_eq!(interval, Duration::from_secs(192));
        let src = include_str!("run.rs");
        assert!(
            src.contains("sync_check_interval_for("),
            "the sync monitor must use one epoch of the beacon-node slot duration"
        );
    }

    // -- DSR-2.1: sync monitor bootstrap wiring --

    #[tokio::test]
    async fn test_sync_monitor_is_started_at_bootstrap() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_sync_monitor(Some(test_bn_manager()), &executor, Some(Duration::from_millis(50)));
        let names = executor.registered_names();
        assert!(
            names.contains(&SYNC_MONITOR_TASK_NAME),
            "missing registered task {SYNC_MONITOR_TASK_NAME}: {names:?}"
        );
        assert!(
            names.contains(&SYNC_MONITOR_CANCEL_TASK_NAME),
            "missing cancel-forwarder {SYNC_MONITOR_CANCEL_TASK_NAME}: {names:?}"
        );
        let entries = executor.registry_entries();
        assert!(
            entries.contains(&(SYNC_MONITOR_TASK_NAME, ShutdownTier::Background)),
            "bn.sync_monitor must be Background, got {entries:?}"
        );
        assert!(
            entries.contains(&(SYNC_MONITOR_CANCEL_TASK_NAME, ShutdownTier::Background)),
            "bn.sync_monitor.cancel must be Background, got {entries:?}"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_sync_monitor_unconfigured_uses_register_opt() {
        use metrics::definitions::RVC_TASKS_RUNNING;

        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let before = RVC_TASKS_RUNNING.with_label_values(&[SYNC_MONITOR_TASK_NAME]).get();
        spawn_sync_monitor(None, &executor, None);
        assert!(
            !executor.registered_names().contains(&SYNC_MONITOR_TASK_NAME),
            "unconfigured sync monitor must not register {SYNC_MONITOR_TASK_NAME}"
        );
        assert!(
            !executor.registered_names().contains(&SYNC_MONITOR_CANCEL_TASK_NAME),
            "unconfigured sync monitor must not register {SYNC_MONITOR_CANCEL_TASK_NAME}"
        );
        assert_eq!(
            RVC_TASKS_RUNNING.with_label_values(&[SYNC_MONITOR_TASK_NAME]).get(),
            before,
            "register_opt(None) must not touch rvc_tasks_running{{task={SYNC_MONITOR_TASK_NAME}}}"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_sync_monitor_alive_after_start() {
        use bn_manager::BnSyncStatus;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&server)
            .await;

        let bn_manager = Arc::new(
            BnManager::new(bn_manager::BnManagerConfig::new(vec![server.uri()]))
                .expect("test BnManager"),
        );
        {
            let guard = bn_manager.sync_statuses().read().await;
            assert_eq!(guard[0].status, BnSyncStatus::Unknown);
        }

        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_sync_monitor(
            Some(Arc::clone(&bn_manager)),
            &executor,
            Some(Duration::from_millis(50)),
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status = bn_manager.sync_statuses().read().await[0].status;
            if status == BnSyncStatus::Synced {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "sync monitor must poll and update status to Synced while registered"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            executor.registered_names().contains(&SYNC_MONITOR_TASK_NAME),
            "sync monitor task must still be registered after first poll"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_sync_monitor_task_stops_on_cancellation_within_its_tier_budget() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_sync_monitor(Some(test_bn_manager()), &executor, Some(Duration::from_millis(50)));

        let budget = TierBudget::new([
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(500),
            Duration::from_millis(50),
        ]);
        let start = std::time::Instant::now();
        let outcome = executor.shutdown(budget).await;
        let elapsed = start.elapsed();

        assert!(
            outcome.joined.contains(&SYNC_MONITOR_TASK_NAME)
                || outcome.aborted.contains(&SYNC_MONITOR_TASK_NAME),
            "bn.sync_monitor must finish within Background budget, joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "sync monitor cancel took {elapsed:?}, expected inside Background budget"
        );
    }

    #[tokio::test]
    async fn test_registered_sync_monitor_handle_panic_surfaces_failure_reason() {
        let (executor, mut rx) = TaskExecutor::new(CancellationToken::new());
        executor.register(
            SYNC_MONITOR_TASK_NAME,
            ShutdownTier::Background,
            tokio::spawn(async { panic!("injected start_sync_monitor JoinHandle panic") }),
        );

        let reason = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");
        assert_eq!(reason, ShutdownReason::Failure(SYNC_MONITOR_TASK_NAME));
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    #[test]
    fn test_spawn_sync_monitor_registers_the_start_sync_monitor_handle() {
        let src = include_str!("tasks.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body");
        assert!(
            body.contains("executor.register(SYNC_MONITOR_TASK_NAME")
                && body.contains("sync_handle"),
            "DSR-2.1 must register the start_sync_monitor JoinHandle as bn.sync_monitor"
        );
        assert!(
            body.contains("executor.spawn(SYNC_MONITOR_CANCEL_TASK_NAME"),
            "token→watch mapping must be a named cancel-forwarder, not the bn.sync_monitor work"
        );
        assert!(
            !body.contains("executor.spawn(SYNC_MONITOR_TASK_NAME"),
            "bn.sync_monitor must not be an adapter wrapper around start_sync_monitor"
        );
        assert!(
            body.contains("bn_manager.start_sync_monitor"),
            "bootstrap must call BnManager::start_sync_monitor"
        );
    }

    /// One monitor pass marks a matching proposer node Synced.
    ///
    /// The first poll runs before the interval sleep. The test waits on
    /// [`BnManager::testing_sync_polled`] and then shuts the executor down, so
    /// it does not sleep for the epoch. Pausing time here advances the client
    /// timeout before wiremock answers and records the node as unreachable.
    /// The fallback floor is the same predicate `fallback_unsynced` uses.
    #[tokio::test]
    async fn proposer_pool_sync_monitor_publishes_tiers() {
        use bn_manager::ChainIdentity;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"data":{{"SLOT_DURATION_MS":"12000","SLOTS_PER_EPOCH":"32",{}}}}}"#,
                bn_manager::MAINNET_FORK_SPEC_FIELDS
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&server)
            .await;

        let manager = Arc::new(
            BnManager::new(bn_manager::BnManagerConfig::new(vec![server.uri()]))
                .expect("proposer manager"),
        );
        let admitted = manager
            .admit_against_identity(ChainIdentity {
                slot_duration_ms: 12_000,
                slots_per_epoch: 32,
                genesis_time: 1_606_824_023,
                genesis_validators_root: "0xabc".to_string(),
                genesis_fork_version: "0x00000000".to_string(),
                fork_schedule: bn_manager::mainnet_fork_schedule(),
            })
            .await;
        assert_eq!(admitted, 1);
        assert!(
            !manager.testing_fallback_would_select(0).await,
            "an unknown tier is below the fallback floor"
        );
        // Identity is stored and the bit is set. Revoke before the monitor
        // starts so only `recheck` can admit the node again. Dropping
        // `notify_one` still hangs on `polled`; dropping `recheck` leaves
        // the bit clear and fails the fallback assertion below.
        manager.testing_revoke_admission(0);
        assert!(
            bn_manager::BeaconNodeClient::duty_fence(manager.as_ref()).is_err(),
            "the proposer node stays unadmitted until recheck"
        );

        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let polled = manager.testing_sync_polled();
        spawn_proposer_sync_monitor(
            Some(Arc::clone(&manager)),
            &executor,
            Some(Duration::from_secs(192)),
        );
        polled.notified().await;
        let status = manager.sync_statuses().read().await;
        assert_eq!(
            status.first().map(|detail| detail.status),
            Some(bn_manager::BnSyncStatus::Synced)
        );
        drop(status);
        assert!(
            manager.testing_fallback_would_select(0).await,
            "recheck must admit the matching proposer node again"
        );
        assert!(
            bn_manager::BeaconNodeClient::duty_fence(manager.as_ref()).is_ok(),
            "recheck must grant the matching proposer node again"
        );
        let entries = executor.registry_entries();
        assert!(
            entries.contains(&(PROPOSER_SYNC_MONITOR_TASK_NAME, ShutdownTier::Background)),
            "{entries:?}"
        );
        assert!(
            entries.contains(&(PROPOSER_SYNC_MONITOR_CANCEL_TASK_NAME, ShutdownTier::Background)),
            "{entries:?}"
        );
        let _ = executor.shutdown(TierBudget::default()).await;
    }

    /// Cancelling the process token must abort the registered proposer monitor.
    ///
    /// The first sync poll is held open, so closing the shutdown watch does
    /// not finish the task. `executor.shutdown` aborts registered work on its
    /// own, so this test only cancels the token. Removing the forwarder body
    /// leaves the registered work running.
    #[tokio::test]
    async fn proposer_sync_monitor_cancel_forwarder_stops_the_registered_task() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
            .mount(&server)
            .await;
        let manager = Arc::new(
            BnManager::new(bn_manager::BnManagerConfig::new(vec![server.uri()]))
                .expect("proposer manager"),
        );
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_proposer_sync_monitor(Some(manager), &executor, Some(Duration::from_secs(192)));
        assert!(
            executor.registered_names().contains(&PROPOSER_SYNC_MONITOR_TASK_NAME),
            "the proposer sync monitor must be registered before cancel"
        );
        executor.token().cancel();
        tokio::time::timeout(
            Duration::from_secs(5),
            executor.wait_until_work_finished(PROPOSER_SYNC_MONITOR_TASK_NAME),
        )
        .await
        .expect(
            "the cancel forwarder must abort bn.proposer_sync_monitor without executor.shutdown",
        );
        assert!(executor.work_finished(PROPOSER_SYNC_MONITOR_TASK_NAME));
    }
}
