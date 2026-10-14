//! ARCH-2g: production background tasks route through [`TaskExecutor`].
//!
//! Pins the migration acceptance criteria that unit tests in individual modules
//! also cover: named registration, panic → reasoned shutdown, and disabled
//! slashing creating no series.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use rvc::bootstrap::{
    spawn_background_tasks, ShutdownReason, ShutdownTier, TaskExecutor, TierBudget,
};
use rvc::config::Config;
use rvc::slashing_monitor::{spawn as spawn_slashing_monitor, SlashedAction};
use tokio_util::sync::CancellationToken;
use validator_store::ValidatorStore;

fn empty_pubkey_map() -> rvc::orchestrator::PubkeyMap {
    Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
}

/// Every background helper that is exercised here registers under a known name.
#[tokio::test]
async fn test_every_background_task_is_registered_by_name() {
    let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

    let config = Config {
        metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        metrics_port: 0,
        monitoring: rvc::config::MonitoringConfig {
            endpoint: Some("http://127.0.0.1:9/push".into()),
            interval: 3600,
            endpoint_insecure: true,
        },
        proposer_config: rvc::config::ProposerConfigSource {
            url: Some("http://127.0.0.1:9/proposer".into()),
            refresh_interval: 3600,
            url_token: None,
            url_insecure: true,
            ..Default::default()
        },
        ..Config::default()
    };

    let metrics_listener =
        tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("pre-bind metrics");
    spawn_background_tasks(
        &config,
        metrics_listener,
        metrics::new_health_status(),
        &executor,
        empty_pubkey_map(),
        Arc::new(ValidatorStore::new([0u8; 20], 30_000_000)),
    )
    .expect("spawn background tasks");

    spawn_slashing_monitor(
        Arc::new(bn_manager::MockBeaconNodeClient::new()),
        Arc::new(ValidatorStore::new([0u8; 20], 100)),
        SlashedAction::DisableOnly,
        &executor,
    );

    let names = executor.registered_names();
    for expected in
        ["metrics_server", "monitoring_push", "proposer_config_refresh", "slashing_monitor"]
    {
        assert!(names.contains(&expected), "expected registered task {expected}, got {names:?}");
    }

    let _ = executor.shutdown(TierBudget::default()).await;
}

/// A panicking Background-tier task produces [`ShutdownReason::Failure`] (ARCH-P1-4).
#[tokio::test]
async fn test_panicking_background_task_triggers_reasoned_shutdown() {
    let (executor, mut rx) = TaskExecutor::new(CancellationToken::new());
    executor.spawn("panic_probe", ShutdownTier::Background, async {
        panic!("injected panic for ARCH-2g");
    });

    let reason = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for ShutdownReason")
        .expect("channel closed without reason");

    assert_eq!(reason, ShutdownReason::Failure("panic_probe"));
    let _ = executor.shutdown(TierBudget::default()).await;
}

/// `SlashedAction::None` registers nothing (P1-8). Gauge honesty is pinned in
/// `slashing_monitor` unit tests (process-global metrics are racy across parallel
/// integration tests that share the `slashing_monitor` label).
#[tokio::test]
async fn test_disabled_slashing_monitor_registers_no_task() {
    let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

    spawn_slashing_monitor(
        Arc::new(bn_manager::MockBeaconNodeClient::new()),
        Arc::new(ValidatorStore::new([0u8; 20], 100)),
        SlashedAction::None,
        &executor,
    );

    assert!(executor.registered_names().is_empty(), "disabled slashing must register no task");
}
