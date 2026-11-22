//! ARCH-3h: post-duty wait window can host work against a `&self` wait.

use super::*;
use parking_lot::Mutex;
use std::collections::HashSet;
use timing::{DeadlineBps, DeadlineSchedule, TimingError};
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
const PRODUCE_PAYLOAD_ATTESTATIONS: &str = "orchestrator.produce_payload_attestations";

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
    observe_duty_times_for(slot, config, 8500).await
}

async fn observe_duty_times_for(
    slot: Slot,
    config: OrchestratorConfig,
    wait_ms: u64,
) -> Vec<(String, u64)> {
    let (mut orchestrator, handle) = observe_orchestrator(slot, config);
    let times = Arc::new(Mutex::new(Vec::new()));
    let layer = TimedSpans { start: tokio::time::Instant::now(), times: times.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let recorded = times.lock().clone();
    recorded
}

fn production_src(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap()
}

/// Last pre-Gloas slot (epoch 0 with Gloas at epoch 1): attestation 3999 ms, aggregate 8000 ms.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_attestation_and_aggregate_times_at_last_pre_gloas_slot() {
    let _metrics = m2_metric_lock().await;
    let times = observe_duty_times(31, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3999);
    assert_eq!(first_ms(&times, PRODUCE_AGGREGATIONS), 8000);
}

/// First Gloas slot: attestation 3000 ms (2500 bps), aggregate 6000 ms (5000 bps).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_attestation_and_aggregate_times_at_first_gloas_slot() {
    let _metrics = m2_metric_lock().await;
    let times = observe_duty_times(32, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3000);
    assert_eq!(first_ms(&times, PRODUCE_AGGREGATIONS), 6000);
}

/// `aggregate_due_bps_gloas = 6667` and `contribution_due_bps_gloas = 5000` yield
/// two distinct observed times in the same slot.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_contributions_and_aggregates_use_distinct_offsets_when_bps_differ() {
    let _metrics = m2_metric_lock().await;
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
    let _metrics = m2_metric_lock().await;
    let times = observe_duty_times(32, observe_config(spec_gloas_bps())).await;
    assert_eq!(first_ms(&times, PROCESS_SLOT), 3000);
    assert_eq!(first_ms(&times, PRODUCE_SYNC_MESSAGES), 3000);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_sync_messages_fire_at_own_offset_when_bps_unequal() {
    let _metrics = m2_metric_lock().await;
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

/// PTC waits to the 4.19-resolved `payload_attestation` offset for the slot's
/// fork (8000 bps → 9600 ms), not pre-Gloas 3333/6667 or a hardcoded 7500.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_ptc_phase_fires_at_configured_bps() {
    let _metrics = m2_metric_lock().await;
    let gloas = DeadlineBps {
        attestation: 2500,
        aggregate: 5000,
        sync_message: 2500,
        contribution: 5000,
        payload: 5000,
        payload_attestation: 8000,
    };
    let times = observe_duty_times_for(32, observe_config(gloas), 11000).await;
    let ptc_ms = first_ms(&times, PRODUCE_PAYLOAD_ATTESTATIONS);
    assert_eq!(ptc_ms, 9600);
    assert_ne!(ptc_ms, 3999, "must not use attestation 3333 bps");
    assert_ne!(ptc_ms, 8000, "must not use aggregate 6667 bps");
    assert_ne!(ptc_ms, 9000, "must not hardcode 7500 bps");
}

#[test]
fn test_ptc_path_contains_no_payload_attestation_due_bps_read() {
    let ptc = production_src(include_str!("../../payload_attestation.rs"));
    let coord = production_src(include_str!("../mod.rs"));
    assert!(
        !ptc.contains("payload_attestation_due_bps"),
        "D9: payload_attestation.rs must not read TimingConfig::payload_attestation_due_bps"
    );
    assert!(
        !coord.contains("payload_attestation_due_bps"),
        "D9: coordinator must consume deadlines.payload_attestation, not payload_attestation_due_bps"
    );
}

/// Last pre-Gloas slot: the PTC phase does not run (no produce span).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_pre_gloas_epoch_does_not_run_ptc_phase() {
    let _metrics = m2_metric_lock().await;
    let times = observe_duty_times_for(31, observe_config(spec_gloas_bps()), 11000).await;
    assert!(
        times.iter().all(|(n, _)| n != PRODUCE_PAYLOAD_ATTESTATIONS),
        "pre-Gloas must not enter produce_payload_attestations, got {times:?}"
    );
}

/// Pre-Gloas with cached PTC duties still must not hit the PTC data endpoint.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_pre_gloas_epoch_does_not_call_ptc_endpoint() {
    let _metrics = m2_metric_lock().await;
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(
        bn_manager::MockBeaconNodeClient::new()
            .with_post_ptc_duties({
                let pk_hex = pk_hex.clone();
                move |_epoch, _indices| {
                    Ok(bn_manager::PtcDutiesResponse {
                        dependent_root: "0xdeproot".to_string(),
                        execution_optimistic: false,
                        data: vec![bn_manager::PtcDuty {
                            pubkey: pk_hex.clone(),
                            validator_index: "1".to_string(),
                            slot: "31".to_string(),
                        }],
                    })
                }
            })
            .with_get_payload_attestation_data({
                let fetch_count = fetch_count.clone();
                move |_slot| {
                    fetch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                }
            })
            .with_submit_payload_attestations(|_msgs| Ok(())),
    );
    let beacon: Arc<dyn bn_manager::BeaconNodeClient> = mock.clone();

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(31);
    let mut key_manager = KeyManager::new();
    key_manager.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let duty_tracker = Arc::new(DutyTracker::new(mock.clone(), vec!["1".to_string()]));
    duty_tracker.fetch_ptc_duties(0, &["1".to_string()]).await.unwrap();
    let mut map = HashMap::new();
    map.insert(pk.to_bytes(), pk.clone());
    let validator_store = create_mock_validator_store();
    validator_store.add_validator(validator_store::ValidatorConfig::new(pk.to_bytes())).unwrap();
    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store,
        observe_config(spec_gloas_bps()),
        Arc::new(parking_lot::RwLock::new(map)),
    ));

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(11000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    assert_eq!(
        fetch_count.load(Ordering::SeqCst),
        0,
        "pre-Gloas must not call get_payload_attestation_data"
    );
    assert!(mock.get_payload_attestation_data_calls().is_empty());
}

// ── W4-E2c: zero post-duty window over a cold duty cache ──────────────

const SLOT_MS: u64 = 12_000;
const LOCAL_INDEX: &str = "7";
const DUTY_ROOT: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FETCH_EPOCH_DUTIES: &str = "orchestrator.fetch_epoch_duties";

/// `now` is genesis, plus `start_slot` slots, plus the paused tokio time
/// since construction, so the inter-slot wait and the phase deadlines move
/// together.
struct PausedSlotClock {
    origin: tokio::time::Instant,
    start_slot: Slot,
}

impl SlotClock for PausedSlotClock {
    fn genesis_time(&self) -> u64 {
        TEST_GENESIS_TIME
    }

    fn slot_duration(&self) -> Duration {
        Duration::from_millis(SLOT_MS)
    }

    fn slots_per_epoch(&self) -> u64 {
        SLOTS_PER_EPOCH
    }

    fn now_since_epoch(&self) -> Duration {
        Duration::from_secs(TEST_GENESIS_TIME)
            + Duration::from_millis(self.start_slot * SLOT_MS)
            + self.origin.elapsed()
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let since_genesis =
            self.now_since_epoch().saturating_sub(Duration::from_secs(TEST_GENESIS_TIME));
        Ok(u64::try_from(since_genesis.as_millis()).unwrap_or(u64::MAX) / SLOT_MS)
    }
}

/// Aggregate and contribution at 10,000 bps: the last phase ends at the next
/// slot start, so every post-duty window is zero.
fn zero_window_config() -> OrchestratorConfig {
    create_test_config().with_deadline_schedule(DeadlineSchedule::uniform(DeadlineBps {
        aggregate: 10_000,
        contribution: 10_000,
        ..DeadlineBps::default()
    }))
}

/// Answers 503 to the first attester-duties request for each epoch, then one
/// duty for index 7 at slot 1 of that epoch.
fn first_request_503_attester_duties(pubkey_hex: String) -> bn_manager::MockBeaconNodeClient {
    let answered = Mutex::new(HashSet::new());
    bn_manager::MockBeaconNodeClient::new().with_get_attester_duties(move |epoch, _indices| {
        if answered.lock().insert(epoch) {
            return Err(beacon::BeaconError::ApiError {
                status: 503,
                message: "first request".to_string(),
            });
        }
        Ok(beacon::DependentRootResponse {
            dependent_root: DUTY_ROOT.to_string(),
            execution_optimistic: false,
            data: vec![AttesterDuty {
                pubkey: pubkey_hex.clone(),
                validator_index: LOCAL_INDEX.to_string(),
                committee_index: "1".to_string(),
                committee_length: "8".to_string(),
                committees_at_slot: "4".to_string(),
                validator_committee_index: "0".to_string(),
                slot: (epoch * SLOTS_PER_EPOCH + 1).to_string(),
            }],
        })
    })
}

/// Offset from `start_slot`'s start to `slot`'s start.
fn slot_offset(start_slot: Slot, slot: Slot) -> Duration {
    Duration::from_millis((slot - start_slot) * SLOT_MS)
}

fn duty_slots<const N: usize>(slots: [&str; N]) -> Vec<String> {
    slots.iter().map(|slot| slot.to_string()).collect()
}

struct ZeroWindowRun {
    mock: Arc<bn_manager::MockBeaconNodeClient>,
    /// Offset from boot and duty slots of each subscription POST.
    subscriptions: Vec<(Duration, Vec<String>)>,
    spans: Vec<(String, u64)>,
    boot: tokio::time::Instant,
}

impl ZeroWindowRun {
    /// Offset from boot of each prepare POST; every POST is for index 7 only.
    fn prepares(&self) -> Vec<Duration> {
        for posted in self.mock.prepare_beacon_proposer_calls() {
            let indices: Vec<&str> = posted.iter().map(|p| p.validator_index.as_str()).collect();
            assert_eq!(indices, [LOCAL_INDEX], "prepare for index 7");
        }
        self.mock
            .call_stamps()
            .iter()
            .filter(|stamp| stamp.method == bn_manager::MockMethod::PrepareBeaconProposer)
            .map(|stamp| stamp.at.duration_since(self.boot))
            .collect()
    }

    fn assert_no_warm_up(&self) {
        let warm_ups: Vec<u64> =
            self.spans.iter().filter(|(name, _)| name == FETCH_EPOCH_DUTIES).map(|s| s.1).collect();
        assert!(warm_ups.is_empty(), "a post-duty window was not zero: warm-up at {warm_ups:?} ms");
    }
}

/// Boots at the start of `start_slot` with an empty duty cache, index 7 in
/// the registry and every post-duty window zero. Runs `run()` and the runner
/// task side by side for `run_for` of virtual time, then shuts down.
async fn run_zero_window(start_slot: Slot, run_for: Duration) -> ZeroWindowRun {
    let boot = tokio::time::Instant::now();
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let pk_bytes = pubkey.to_bytes();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let subscriptions = Arc::clone(&recorded);
    let mock = Arc::new(
        first_request_503_attester_duties(format!("0x{}", hex::encode(pk_bytes)))
            .with_get_proposer_duties(|_epoch| {
                Ok(beacon::DependentRootResponse {
                    dependent_root: DUTY_ROOT.to_string(),
                    execution_optimistic: false,
                    data: Vec::new(),
                })
            })
            .with_prepare_beacon_proposer(|_preparations| Ok(()))
            .with_submit_beacon_committee_subscriptions(move |posted| {
                let slots = posted.into_iter().map(|s| s.slot).collect();
                subscriptions.lock().push((boot.elapsed(), slots));
                Ok(())
            }),
    );
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret);
    let signer = Arc::new(
        SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
            Arc::new(SlashingDb::open_in_memory().expect("slashing db")),
        )
        .with_enablement(always_enabled()),
    );
    let validator_store = create_mock_validator_store();
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pk_bytes))
        .expect("add validator");
    let pubkey_index = crate::pubkey_index::PubkeyIndexRegistry::shared();
    pubkey_index.write().insert(pk_bytes, LOCAL_INDEX.to_string());
    let deps = OrchestratorDeps::for_test(
        Arc::new(PausedSlotClock { origin: boot, start_slot }),
        Arc::new(DutyTracker::new(mock.clone(), vec![LOCAL_INDEX.to_string()])),
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        mock.clone(),
        create_mock_block_beacon(),
        None,
        validator_store,
        zero_window_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::from([(pk_bytes, pubkey)]))),
    );
    let (mut orchestrator, handle) =
        DutyOrchestrator::new(OrchestratorDeps { pubkey_index, ..deps });

    let times = Arc::new(Mutex::new(Vec::new()));
    let layer = TimedSpans { start: boot, times: times.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    let runner = tokio::spawn(orchestrator.take_epoch_boundary_runner().expect("runner").run());
    let run = tokio::spawn(async move { orchestrator.run().await });
    tokio::time::sleep_until(boot + run_for).await;
    handle.shutdown();
    let result = run.await.expect("run task");
    assert!(result.is_ok(), "shutdown ends the slot loop: {result:?}");
    runner.await.expect("runner task");

    let subscriptions = recorded.lock().clone();
    let spans = times.lock().clone();
    ZeroWindowRun { mock, subscriptions, spans, boot }
}

/// W4-E2c cold start: boot at slot 10 with an empty cache, every post-duty
/// window zero (the warm-up never runs) and the first attester request for
/// each epoch failing. The runner's epoch-0 pass, woken by processed slot
/// 10 at the end of slot 10, fetches epoch 1 itself and subscribes for both
/// epochs before slot 32.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_cold_start_with_zero_post_duty_window_subscribes_for_the_boot_epoch() {
    let _metrics = m2_metric_lock().await;
    let end_of_slot_31 = slot_offset(10, 32) - Duration::from_millis(1);
    let run = run_zero_window(10, end_of_slot_31).await;

    let end_of_slot_10 = slot_offset(10, 11);
    assert_eq!(
        run.subscriptions,
        [(end_of_slot_10, duty_slots(["1"])), (end_of_slot_10, duty_slots(["33"]))],
        "the epoch-0 and epoch-1 duties are subscribed in epoch 0"
    );
    assert_eq!(
        run.prepares(),
        [end_of_slot_10],
        "The runner's epoch-0 pass must send the only prepare."
    );
    run.assert_no_warm_up();
}

/// 652-AC2: boot at slot 31, then slot 32 with a zero window. The epoch-1
/// pass is woken by processed slot 32 when its last phase ends, at the end
/// of slot 32, before slot 33's first phase: it prepares and subscribes for
/// epochs 1 and 2 there although the warm-up never runs.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_zero_post_duty_window_at_slot_0_still_runs_boundary_steps() {
    let _metrics = m2_metric_lock().await;
    let run = run_zero_window(31, slot_offset(31, 33) + Duration::from_secs(1)).await;

    let end_of_slot_31 = slot_offset(31, 32);
    let end_of_slot_32 = slot_offset(31, 33);
    assert_eq!(
        run.subscriptions,
        [
            (end_of_slot_31, duty_slots(["1"])),
            (end_of_slot_31, duty_slots(["33"])),
            (end_of_slot_32, duty_slots(["33"])),
            (end_of_slot_32, duty_slots(["65"])),
        ],
        "epoch 0's pass subscribes for epochs 0 and 1, epoch 1's for epochs 1 and 2"
    );
    assert_eq!(
        run.prepares(),
        [end_of_slot_31, end_of_slot_32],
        "The epoch-0 pass and the epoch-1 pass must each send one prepare."
    );
    run.assert_no_warm_up();
}
