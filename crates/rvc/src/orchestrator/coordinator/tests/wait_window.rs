//! ARCH-3h: post-duty wait window can host work against a `&self` wait.

use super::*;
use parking_lot::Mutex;
use timing::{DeadlineBps, DeadlineSchedule};
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;

fn wait_window_orchestrator(
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

/// Hosted work must run (and may borrow `duty_management`) before the window
/// yields the next slot. Compiling this test is the VD-32 proof: the wait is
/// `&self`, so it can race an owned-field borrow.
#[tokio::test]
async fn test_post_duty_window_runs_hosted_work_before_the_next_slot() {
    let (orchestrator, _handle) = wait_window_orchestrator();
    let done = AtomicBool::new(false);

    let hosted = async {
        // Simultaneous `&self` use of the owned duty-management field.
        orchestrator.duty_management.epoch_boundary_summary_counts(0, 0).await;
        done.store(true, Ordering::SeqCst);
    };

    let outcome = orchestrator.run_post_duty_window(Duration::from_millis(200), hosted).await;

    assert_eq!(outcome, WaitOutcome::Continue);
    assert!(done.load(Ordering::SeqCst), "hosted work must complete before the next slot");
}

/// A hosted future that never completes must be abandoned when the next slot
/// arrives — the window cannot block the slot loop.
#[tokio::test]
async fn test_post_duty_window_abandons_hosted_work_when_the_slot_arrives_first() {
    let (orchestrator, _handle) = wait_window_orchestrator();

    let outcome = tokio::time::timeout(
        Duration::from_millis(200),
        orchestrator.run_post_duty_window(Duration::from_millis(20), std::future::pending()),
    )
    .await
    .expect("never-completing hosted work must not delay the next slot");

    assert_eq!(outcome, WaitOutcome::Continue);
}

/// Shutdown during the window must surface `WaitOutcome::Shutdown` promptly so
/// `run()` can return `Ok(())` without waiting out the slot.
#[tokio::test]
async fn test_shutdown_during_the_post_duty_window_still_returns() {
    let (orchestrator, handle) = wait_window_orchestrator();

    let outcome = tokio::time::timeout(Duration::from_millis(500), async {
        tokio::select! {
            biased;
            outcome = orchestrator.run_post_duty_window(
                Duration::from_secs(30),
                std::future::pending(),
            ) => outcome,
            () = async {
                handle.shutdown();
                std::future::pending::<()>().await;
            } => unreachable!("shutdown arm must stay pending so the window can return"),
        }
    })
    .await
    .expect("post-duty window must return promptly on shutdown");

    assert_eq!(outcome, WaitOutcome::Shutdown);
}

/// Permanent regression: pre-Gloas mainnet deadlines stay 3999 / 8000 ms.
#[test]
fn test_pre_gloas_mainnet_deadlines_are_3999_and_8000_ms() {
    let (orchestrator, _handle) = wait_window_orchestrator();
    let slot_duration_ms = orchestrator.clock.slot_duration().as_millis() as u64;
    assert_eq!(slot_duration_ms, 12_000);
    assert_eq!(
        due_ms(orchestrator.config.deadline_schedule.pre_gloas.attestation, slot_duration_ms),
        3999
    );
    assert_eq!(
        due_ms(orchestrator.config.deadline_schedule.pre_gloas.aggregate, slot_duration_ms),
        8000
    );
}

const PROCESS_SLOT: &str = "orchestrator.process_slot";
const PRODUCE_AGGREGATIONS: &str = "orchestrator.produce_aggregations";
const PRODUCE_SYNC_MESSAGES: &str = "orchestrator.produce_sync_messages";
const PRODUCE_SYNC_CONTRIBUTIONS: &str = "orchestrator.produce_sync_contributions";

fn gloas_at_epoch(epoch: u64) -> Arc<ForkSchedule> {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.gloas_fork_epoch = epoch;
    Arc::new(schedule)
}

fn spec_gloas_bps() -> DeadlineBps {
    DeadlineBps {
        attestation: 2500,
        aggregate: 5000,
        sync_message: 2500,
        contribution: 5000,
        payload: 5000,
        payload_attestation: 7500,
    }
}

fn observe_config(gloas: DeadlineBps) -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], gloas_at_epoch(1))
        .with_deadline_schedule(DeadlineSchedule { pre_gloas: DeadlineBps::default(), gloas })
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO)
}

fn observe_orchestrator(
    slot: Slot,
    config: OrchestratorConfig,
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);
    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
    DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

struct TimedSpans {
    start: tokio::time::Instant,
    times: Arc<Mutex<Vec<(String, u64)>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TimedSpans {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        self.times.lock().push((attrs.metadata().name().to_string(), elapsed));
    }
}

fn first_ms(times: &[(String, u64)], name: &str) -> u64 {
    times
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, ms)| *ms)
        .unwrap_or_else(|| panic!("missing span {name}, got {times:?}"))
}

async fn observe_duty_times(slot: Slot, config: OrchestratorConfig) -> Vec<(String, u64)> {
    let (mut orchestrator, handle) = observe_orchestrator(slot, config);
    let times = Arc::new(Mutex::new(Vec::new()));
    let layer = TimedSpans { start: tokio::time::Instant::now(), times: times.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(8500)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let recorded = times.lock().clone();
    recorded
}

/// Last pre-Gloas slot (epoch 0 with Gloas at epoch 1): attestation 3999 ms, aggregate 8000 ms.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_attestation_and_aggregate_times_at_last_pre_gloas_slot() {
    let times = observe_duty_times(31, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3999);
    assert_eq!(first_ms(&times, PRODUCE_AGGREGATIONS), 8000);
}

/// First Gloas slot: attestation 3000 ms (2500 bps), aggregate 6000 ms (5000 bps).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_attestation_and_aggregate_times_at_first_gloas_slot() {
    let times = observe_duty_times(32, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3000);
    assert_eq!(first_ms(&times, PRODUCE_AGGREGATIONS), 6000);
}

/// `aggregate_due_bps_gloas = 6667` and `contribution_due_bps_gloas = 5000` yield
/// two distinct observed times in the same slot.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_contributions_and_aggregates_use_distinct_offsets_when_bps_differ() {
    let gloas = DeadlineBps {
        attestation: 2500,
        aggregate: 6667,
        sync_message: 2500,
        contribution: 5000,
        payload: 5000,
        payload_attestation: 7500,
    };
    let times = observe_duty_times(32, observe_config(gloas)).await;
    assert_eq!(first_ms(&times, PRODUCE_SYNC_CONTRIBUTIONS), 6000);
    assert_eq!(first_ms(&times, PRODUCE_AGGREGATIONS), 8000);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_sync_messages_share_attestation_wait_when_bps_equal() {
    let times = observe_duty_times(32, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3000);
    assert_eq!(first_ms(&times, PRODUCE_SYNC_MESSAGES), 3000);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_sync_messages_fire_at_own_offset_when_bps_unequal() {
    let gloas = DeadlineBps {
        attestation: 2500,
        aggregate: 5000,
        sync_message: 5000,
        contribution: 5000,
        payload: 5000,
        payload_attestation: 7500,
    };
    let times = observe_duty_times(32, observe_config(gloas)).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3000);
    assert_eq!(first_ms(&times, PRODUCE_SYNC_MESSAGES), 6000);
}
