//! Bootstrap phase: metrics, monitoring, proposer-config, and BN SSE tasks.
//!
//! Extracted from the former `run_validator` tail so the ISSUE-4.10 metrics bind
//! gate and task cancel/drain sequence can be unit-tested without the full
//! startup chain.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bn_manager::BnManager;
use metrics::{serve_metrics_with_health, SharedHealthStatus};
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

/// Spawn metrics server, optional monitoring push, and optional proposer-config
/// refresh through the process [`TaskExecutor`] (ARCH-2g).
///
/// Cooperative tasks take `executor.token()` and exit on cancel. The metrics
/// server has no token (abort-drain on Telemetry tier via `TaskExecutor::shutdown`).
///
/// `pubkey_map` and `validator_store` are captured by the monitoring push so
/// each interval reports live totals (not a boot-time constant).
pub fn spawn_background_tasks(
    config: &Config,
    health_status: SharedHealthStatus,
    executor: &TaskExecutor,
    pubkey_map: PubkeyMap,
    validator_store: Arc<ValidatorStore>,
) -> Result<(), BootstrapError> {
    let metrics_address = config.metrics_address;
    let metrics_port = config.metrics_port;

    check_metrics_bind_gate(metrics_address)?;

    info!(addr = %metrics_address, port = metrics_port, "Starting metrics server");
    // P1-2: Telemetry tier; no cooperative token (abort-drain).
    executor.spawn("metrics_server", ShutdownTier::Telemetry, async move {
        if let Err(e) =
            serve_metrics_with_health(metrics_address, metrics_port, health_status).await
        {
            error!(error = %e, "Metrics server exited with error");
        }
    });

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
        executor.spawn("proposer_config_refresh", ShutdownTier::Background, async move {
            crate::background_tasks::config_url::start_proposer_config_refresh(
                settings,
                config_refresh_shutdown,
                move |updates, default_update| {
                    crate::background_tasks::config_url::apply_proposer_config_updates(
                        &validator_store,
                        updates,
                        default_update,
                    );
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
    executor.register(SSE_TASK_NAME, ShutdownTier::Background, sse_handle);

    let token = executor.token();
    executor.spawn(SSE_CANCEL_TASK_NAME, ShutdownTier::Background, async move {
        token.cancelled().await;
        let _ = shutdown_tx.send(true);
        sse_abort.abort();
    });
    Some(gate)
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
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
            listener.local_addr().expect("local_addr").port()
        };
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
            metrics_port: port,
            ..Config::default()
        };
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
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
            metrics_port: 0, // OS-assigned; serve binds ephemeral
            // monitoring / proposer_config left at nested defaults (disabled)
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        spawn_background_tasks(
            &config,
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
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
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
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_background_tasks(
            &config,
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
        adapter.import_keystore(&keystore_json, "testpass").unwrap();

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
        adapter.import_keystore(&keystore_json, "testpass").unwrap();
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
}
