//! RR1-04: a backward clock step must not re-run a slot whose phases finished.
//!
//! The wall-based inter-slot wait is the primary protection. This guard is
//! defence-in-depth: `current_slot <= last_processed_slot` skips the slot,
//! counts it, and waits again instead of spinning.

use super::*;
use metrics::definitions::RVC_SLOT_REPLAY_SKIPPED_TOTAL;
use std::collections::HashMap as SpanMap;
use timing::DeadlineSchedule;
use tracing::field::{Field, Visit};
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;

const SLOT_S: Slot = 100;
const OFFSET_MS: u64 = 5_000;
const SLOT_MS: u64 = 12_000;
const PHASE_BLOCK: &str = "slot.phase.block";
const PROCESS: &str = "slot.process";
const EPOCH_BOUNDARY: &str = "epoch.boundary";
/// Virtual time after the skip, shorter than the remaining wait to slot S+1.
const BOUNDED_ADVANCE: Duration = Duration::from_millis(2_000);
const FORWARD_SLOTS: u64 = 32;
const FORWARD_START: Slot = 65;

fn zero_deadlines() -> timing::DeadlineBps {
    timing::DeadlineBps {
        attestation: 0,
        aggregate: 0,
        sync_message: 0,
        contribution: 0,
        payload: 0,
        payload_attestation: 0,
    }
}

fn replay_config() -> OrchestratorConfig {
    let deadlines = zero_deadlines();
    create_test_config()
        .with_deadline_schedule(DeadlineSchedule { pre_gloas: deadlines, gloas: deadlines })
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO)
        .with_timeouts(fast_timeouts())
}

fn replay_orchestrator(
    clock: Arc<MockSlotClock>,
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
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
        replay_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

fn slot_start_ms(slot: Slot) -> u64 {
    TEST_GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn replay_skipped() -> u64 {
    RVC_SLOT_REPLAY_SKIPPED_TOTAL.get()
}

#[derive(Clone, Debug)]
struct ReplayWarn {
    current_slot: Option<u64>,
    last_processed_slot: Option<u64>,
}

struct WarnVisit {
    current_slot: Option<u64>,
    last_processed_slot: Option<u64>,
}

impl Visit for WarnVisit {
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "current_slot" => self.current_slot = Some(value),
            "last_processed_slot" => self.last_processed_slot = Some(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        let text = rendered.trim_matches('"');
        let parsed = text.parse().ok();
        match field.name() {
            "current_slot" if self.current_slot.is_none() => self.current_slot = parsed,
            "last_processed_slot" if self.last_processed_slot.is_none() => {
                self.last_processed_slot = parsed;
            }
            _ => {}
        }
    }
}

struct SlotVisit {
    slot: Option<u64>,
}

impl Visit for SlotVisit {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "slot" {
            self.slot = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "slot" && self.slot.is_none() {
            let rendered = format!("{value:?}");
            self.slot = rendered.trim_matches('"').parse().ok();
        }
    }
}

#[derive(Debug)]
struct SpanEntry {
    name: String,
    parent_id: Option<u64>,
    slot: Option<u64>,
}

struct ReplayCapture {
    spans: Arc<parking_lot::Mutex<SpanMap<u64, SpanEntry>>>,
    warns: Arc<parking_lot::Mutex<Vec<ReplayWarn>>>,
}

impl<S> tracing_subscriber::Layer<S> for ReplayCapture
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut slot_visit = SlotVisit { slot: None };
        attrs.record(&mut slot_visit);
        let parent_id = attrs
            .parent()
            .map(|parent| parent.into_u64())
            .or_else(|| ctx.current_span().id().map(|parent| parent.into_u64()));
        self.spans.lock().insert(
            id.into_u64(),
            SpanEntry {
                name: attrs.metadata().name().to_string(),
                parent_id,
                slot: slot_visit.slot,
            },
        );
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visit = WarnVisit { current_slot: None, last_processed_slot: None };
        event.record(&mut visit);
        if visit.current_slot.is_some() || visit.last_processed_slot.is_some() {
            self.warns.lock().push(ReplayWarn {
                current_slot: visit.current_slot,
                last_processed_slot: visit.last_processed_slot,
            });
        }
    }
}

fn phase0_for_slot(spans: &SpanMap<u64, SpanEntry>, slot: Slot) -> usize {
    let parents: Vec<u64> = spans
        .values()
        .filter(|entry| entry.name == PHASE_BLOCK)
        .filter_map(|entry| entry.parent_id)
        .collect();
    parents
        .into_iter()
        .filter(|parent_id| {
            spans
                .get(parent_id)
                .is_some_and(|parent| parent.name == PROCESS && parent.slot == Some(slot))
        })
        .count()
}

fn epoch_boundary_count(spans: &SpanMap<u64, SpanEntry>) -> usize {
    spans.values().filter(|entry| entry.name == EPOCH_BOUNDARY).count()
}

struct BackwardObs {
    phase0_for_s: usize,
    skips_at_wake: u64,
    skips_after_bounded_advance: u64,
    warns: Vec<ReplayWarn>,
}

/// Process slot S, step the mock clock backwards inside S, then let the loop wake.
async fn drive_backward_clock_step() -> BackwardObs {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot_with_offset_ms(SLOT_S, OFFSET_MS);
    let (mut orchestrator, handle) = replay_orchestrator(clock.clone());

    let spans = Arc::new(parking_lot::Mutex::new(SpanMap::new()));
    let warns = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let layer = ReplayCapture { spans: spans.clone(), warns: warns.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let before = replay_skipped();
    let clock_step = clock.clone();
    let spans_step = spans.clone();
    let skips_at_wake = Arc::new(AtomicUsize::new(0));
    let phase_at_wake = Arc::new(AtomicUsize::new(0));
    let skips_snap = skips_at_wake.clone();
    let phase_snap = phase_at_wake.clone();

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            wait_for(|| phase0_for_slot(&spans_step.lock(), SLOT_S) >= 1).await;
            // Settle into the wall-based inter-slot wait before stepping the clock.
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert_eq!(
                phase0_for_slot(&spans_step.lock(), SLOT_S),
                1,
                "phase 0 for slot S runs once before the clock steps backwards"
            );

            let stepped = slot_start_ms(SLOT_S) + 1_000;
            assert!(stepped < slot_start_ms(SLOT_S) + OFFSET_MS);
            clock_step.set_current_time_ms(stepped);
            assert_eq!(clock_step.current_slot().expect("stepped time is after genesis"), SLOT_S);

            // Past the wait that was computed from the pre-step offset (7s).
            tokio::time::sleep(Duration::from_millis(SLOT_MS)).await;
            tokio::task::yield_now().await;
            skips_snap.store(
                usize::try_from(replay_skipped() - before).unwrap_or(usize::MAX),
                Ordering::SeqCst,
            );
            phase_snap.store(phase0_for_slot(&spans_step.lock(), SLOT_S), Ordering::SeqCst);
            tokio::time::sleep(BOUNDED_ADVANCE).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let recorded_warns = warns.lock().clone();
    BackwardObs {
        phase0_for_s: phase_at_wake.load(Ordering::SeqCst),
        skips_at_wake: skips_at_wake.load(Ordering::SeqCst) as u64,
        skips_after_bounded_advance: replay_skipped() - before,
        warns: recorded_warns,
    }
}

async fn wait_for(mut pred: impl FnMut() -> bool) {
    for _ in 0..100_000 {
        if pred() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("slot loop did not reach the expected state");
}

/// A backward mock-clock step between slots does not re-process slot S.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn backward_clock_step_between_slots_does_not_reprocess_slot_s() {
    let _guard = m2_metric_lock().await;
    let obs = drive_backward_clock_step().await;

    assert_eq!(
        obs.phase0_for_s, 1,
        "phase 0 for slot S must run once; a backward step re-processes the slot"
    );
    assert_eq!(
        obs.skips_at_wake, 1,
        "rvc_slot_replay_skipped_total must increment once for the skipped replay"
    );
    let replay_warns: Vec<_> =
        obs.warns.iter().filter(|warn| warn.last_processed_slot.is_some()).cloned().collect();
    assert_eq!(replay_warns.len(), 1, "one warn naming both slots, got {replay_warns:?}");
    assert_eq!(replay_warns[0].current_slot, Some(SLOT_S));
    assert_eq!(replay_warns[0].last_processed_slot, Some(SLOT_S));
}

/// After the skip, a bounded virtual-time advance stays inside the wait.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn skipped_slot_reenters_wait_without_spinning() {
    let _guard = m2_metric_lock().await;
    let obs = drive_backward_clock_step().await;

    assert_eq!(obs.phase0_for_s, 1, "a spinning skip path must not re-enter phase 0");
    assert_eq!(
        obs.skips_at_wake, 1,
        "the skip is one iteration, not a busy loop under paused time"
    );
    assert_eq!(
        obs.skips_after_bounded_advance, obs.skips_at_wake,
        "advancing {:?} after the skip must not increment the counter again",
        BOUNDED_ADVANCE
    );
}

/// Thirty-two forward slots leave the counter at zero. Slot 96 is the one
/// epoch boundary in the run, and its prep runs once.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn forward_32_slots_leave_slot_replay_skipped_at_zero() {
    let _guard = m2_metric_lock().await;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(FORWARD_START);
    let (mut orchestrator, handle) = replay_orchestrator(clock.clone());

    let spans = Arc::new(parking_lot::Mutex::new(SpanMap::new()));
    let warns = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let layer = ReplayCapture { spans: spans.clone(), warns };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard_sub = tracing::subscriber::set_default(subscriber);

    let before = replay_skipped();
    let clock_fwd = clock.clone();
    let spans_fwd = spans.clone();

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            for i in 0..FORWARD_SLOTS {
                let slot = FORWARD_START + i;
                wait_for(|| phase0_for_slot(&spans_fwd.lock(), slot) >= 1).await;
                tokio::time::sleep(Duration::from_millis(1)).await;
                assert_eq!(
                    phase0_for_slot(&spans_fwd.lock(), slot),
                    1,
                    "slot {slot} must be processed once before the clock moves forward"
                );
                if i + 1 == FORWARD_SLOTS {
                    assert_eq!(
                        epoch_boundary_count(&spans_fwd.lock()),
                        1,
                        "slot {} is the only epoch boundary in {}..={}",
                        FORWARD_START + FORWARD_SLOTS - 1,
                        FORWARD_START,
                        FORWARD_START + FORWARD_SLOTS - 1
                    );
                    handle.shutdown();
                    std::future::pending::<()>().await;
                }
                clock_fwd.set_slot(FORWARD_START + i + 1);
                tokio::time::sleep(Duration::from_millis(SLOT_MS)).await;
            }
            std::future::pending::<()>().await;
        } => {}
    }

    let mut phase0_slots = 0usize;
    {
        let spans = spans.lock();
        for slot in FORWARD_START..FORWARD_START + FORWARD_SLOTS {
            phase0_slots += phase0_for_slot(&spans, slot);
        }
        assert_eq!(epoch_boundary_count(&spans), 1);
    }
    assert_eq!(phase0_slots, FORWARD_SLOTS as usize, "each forward slot runs phase 0 once");
    assert_eq!(replay_skipped() - before, 0, "forward progress must not skip a replay");
}
