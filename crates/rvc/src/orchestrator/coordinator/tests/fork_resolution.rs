//! Coordinator tests: fork-resolution gauge lifecycle.
//!
//! The gauges are process-global. Each test removes every `ForkName` series
//! first, so a sequential `cargo test` of this module does not observe a
//! sibling label. Tests that overlap in one process still race on these
//! gauges; nextest's process-per-test isolation is what keeps them apart.

use super::*;

fn clear_next_activation_series() {
    for fork in ForkName::ALL {
        let _ =
            crate::metrics::RVC_FORK_NEXT_ACTIVATION_EPOCH.remove_label_values(&[fork.as_ref()]);
    }
}

#[tokio::test]
async fn current_fork_gauge_is_set_on_resolution() {
    clear_next_activation_series();
    let schedule = create_test_fork_schedule();
    let mut orchestrator = orchestrator_with(schedule.clone()).await;
    let epoch = 55;
    let fork = ForkName::from_epoch(epoch, &schedule);
    assert_eq!(fork, ForkName::Electra);

    orchestrator.record_fork_resolution(epoch, fork);

    assert_eq!(gathered_gauge("rvc_fork_current_id"), f64::from(fork.id()));
}

#[tokio::test]
async fn next_activation_label_is_set_from_the_schedule() {
    clear_next_activation_series();
    let schedule = create_test_fork_schedule();
    let mut orchestrator = orchestrator_with(schedule.clone()).await;
    let epoch = 55;
    let (name, activation) =
        schedule.next_activation(epoch).expect("electra epoch has a later fork");
    assert_eq!((name, activation), (ForkName::Fulu, 60));

    orchestrator.record_fork_resolution(epoch, ForkName::from_epoch(epoch, &schedule));

    assert_eq!(gathered_fork_series(), vec![("fulu".to_string(), activation as f64)]);
}

#[tokio::test]
async fn stale_next_activation_label_is_removed_not_overwritten() {
    clear_next_activation_series();
    let schedule = create_test_fork_schedule();
    let mut orchestrator = orchestrator_with(schedule.clone()).await;
    // Fork A then fork B: next activation moves altair → bellatrix.
    assert_eq!(schedule.next_activation(0), Some((ForkName::Altair, 10)));
    assert_eq!(schedule.next_activation(10), Some((ForkName::Bellatrix, 20)));

    orchestrator.record_fork_resolution(0, ForkName::from_epoch(0, &schedule));
    orchestrator.record_fork_resolution(10, ForkName::from_epoch(10, &schedule));

    let series = gathered_fork_series();
    assert!(
        !series.iter().any(|(fork, _)| fork == "altair"),
        "stale RVC_FORK_NEXT_ACTIVATION_EPOCH{{fork=altair}} must be absent, got {series:?}"
    );
    assert_eq!(
        series.iter().find(|(fork, _)| fork == "bellatrix").map(|(_, epoch)| *epoch),
        Some(20.0),
        "bellatrix activation missing, got {series:?}"
    );
}

#[tokio::test]
async fn label_is_cleared_when_no_activation_remains() {
    clear_next_activation_series();
    let schedule = create_test_fork_schedule();
    let mut orchestrator = orchestrator_with(schedule.clone()).await;
    assert_eq!(schedule.next_activation(69), Some((ForkName::Gloas, 70)));
    assert_eq!(schedule.next_activation(70), None);

    orchestrator.record_fork_resolution(69, ForkName::from_epoch(69, &schedule));
    assert_eq!(gathered_fork_series(), vec![("gloas".to_string(), 70.0)]);

    orchestrator.record_fork_resolution(70, ForkName::from_epoch(70, &schedule));

    let series = gathered_fork_series();
    assert!(
        !series.iter().any(|(fork, _)| fork == "gloas"),
        "next-activation label must be cleared when none remains, got {series:?}"
    );
    assert_eq!(gathered_gauge("rvc_fork_current_id"), f64::from(ForkName::Gloas.id()));
}

async fn orchestrator_with(
    schedule: Arc<ForkSchedule>,
) -> DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon> {
    // No beacon is contacted: the client is constructed and never requested.
    let (orchestrator, _handle, _pubkey, _pubkey_hex) =
        build_aggregation_orchestrator_with_schedule("http://127.0.0.1:1", schedule).await;
    orchestrator
}

fn gathered_gauge(name: &str) -> f64 {
    let gathered = metrics::REGISTRY.gather();
    let family = gathered.iter().find(|metric| metric.name() == name).unwrap_or_else(|| {
        panic!(
            "{name} missing from gathered families: {:?}",
            gathered.iter().map(|metric| metric.name()).collect::<Vec<_>>()
        )
    });
    let sample = family.get_metric().first().unwrap_or_else(|| panic!("{name} has no sample"));
    sample.get_gauge().get_value()
}

fn gathered_fork_series() -> Vec<(String, f64)> {
    let gathered = metrics::REGISTRY.gather();
    let Some(family) =
        gathered.iter().find(|metric| metric.name() == "rvc_fork_next_activation_epoch")
    else {
        return Vec::new();
    };
    family
        .get_metric()
        .iter()
        .map(|sample| {
            let fork = sample
                .get_label()
                .iter()
                .find(|label| label.name() == "fork")
                .map(|label| label.value().to_string())
                .unwrap_or_default();
            (fork, sample.get_gauge().get_value())
        })
        .collect()
}
