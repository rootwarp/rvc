//! RR1-03: absolute phase deadlines from one mid-slot wall-clock read.
//!
//! A 600 ms wake must not re-add the fraction `current_time_secs()` drops.
//! Phase deadlines are measured from the true slot start (600 ms before the
//! wake). Phase 0 has no bps wait, so a late wake fires it immediately.

use super::*;
use metrics::definitions::{slot_phase_late, RVC_SLOT_PHASE_LATE_TOTAL};
use timing::{due_ms, DeadlineBps, DeadlineSchedule};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::SubscriberExt;

const OFFSET_MS: u64 = 600;
const SLOT: Slot = 100;
const PHASE_BLOCK: &str = "slot.phase.block";
const PROCESS_SLOT: &str = "orchestrator.process_slot";
const PRODUCE_SYNC_MESSAGES: &str = "orchestrator.produce_sync_messages";
const PRODUCE_AGGREGATIONS: &str = "orchestrator.produce_aggregations";

/// Sync is already due (120 ms) at a 600 ms wake. Attestation and aggregate
/// stay on the pre-Gloas spec marks (3999 ms and 8000 ms).
fn mid_slot_deadlines() -> DeadlineBps {
    DeadlineBps {
        attestation: 3333,
        aggregate: 6667,
        sync_message: 100,
        contribution: 6667,
        payload: 6667,
        payload_attestation: 6667,
    }
}

fn mid_slot_config() -> OrchestratorConfig {
    let deadlines = mid_slot_deadlines();
    create_test_config()
        .with_deadline_schedule(DeadlineSchedule { pre_gloas: deadlines, gloas: deadlines })
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO)
}

fn mid_slot_orchestrator(
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot_with_offset_ms(SLOT, OFFSET_MS);
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
        mid_slot_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

#[derive(Clone, Debug)]
struct LateWarn {
    phase: Option<String>,
    overrun_ms: Option<u64>,
    message: String,
}

struct LateWarnVisitor {
    phase: Option<String>,
    overrun_ms: Option<u64>,
    message: String,
}

impl Visit for LateWarnVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "phase" => self.phase = Some(value.to_string()),
            "message" => self.message = value.to_string(),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "overrun_ms" {
            self.overrun_ms = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        let text = rendered.trim_matches('"');
        match field.name() {
            "phase" if self.phase.is_none() => self.phase = Some(text.to_string()),
            "message" if self.message.is_empty() => self.message = text.to_string(),
            "overrun_ms" if self.overrun_ms.is_none() => {
                if let Ok(parsed) = text.parse() {
                    self.overrun_ms = Some(parsed);
                }
            }
            _ => {}
        }
    }
}

struct FireCapture {
    true_slot_start: tokio::time::Instant,
    fires: Arc<parking_lot::Mutex<Vec<(String, u64)>>>,
    warns: Arc<parking_lot::Mutex<Vec<LateWarn>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FireCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = attrs.metadata().name();
        if !matches!(
            name,
            PHASE_BLOCK | PROCESS_SLOT | PRODUCE_SYNC_MESSAGES | PRODUCE_AGGREGATIONS
        ) {
            return;
        }
        let at_ms = u64::try_from(self.true_slot_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.fires.lock().push((name.to_string(), at_ms));
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visitor = LateWarnVisitor { phase: None, overrun_ms: None, message: String::new() };
        event.record(&mut visitor);
        if visitor.phase.is_some() {
            self.warns.lock().push(LateWarn {
                phase: visitor.phase,
                overrun_ms: visitor.overrun_ms,
                message: visitor.message,
            });
        }
    }
}

fn first_ms(fires: &[(String, u64)], name: &str) -> u64 {
    let hits: Vec<_> = fires.iter().filter(|(n, _)| n == name).map(|(_, ms)| *ms).collect();
    assert_eq!(hits.len(), 1, "{name} should fire once, got {fires:?}");
    hits[0]
}

fn late_total(phase: &str) -> u64 {
    RVC_SLOT_PHASE_LATE_TOTAL.with_label_values(&[phase]).get()
}

/// `DeadlineBps::default` stays the pre-Gloas 1/3 and 2/3 pair.
#[test]
fn deadline_bps_defaults_are_unchanged() {
    let deadlines = DeadlineBps::default();
    assert_eq!(deadlines.attestation, timing::ATTESTATION_DUE_BPS);
    assert_eq!(deadlines.attestation, 3333);
    assert_eq!(deadlines.aggregate, timing::AGGREGATE_DUE_BPS);
    assert_eq!(deadlines.aggregate, 6667);
    assert_eq!(deadlines.sync_message, deadlines.attestation);
    assert_eq!(deadlines.contribution, deadlines.aggregate);
    assert_eq!(deadlines.payload, deadlines.aggregate);
    assert_eq!(deadlines.payload_attestation, deadlines.aggregate);
    assert_eq!(due_ms(deadlines.attestation, 12_000), 3999);
    assert_eq!(due_ms(deadlines.aggregate, 12_000), 8000);
}

/// Mid-second start: phase 0 fires on the wake, attestation lands in
/// `[3999, 4049]` ms after the true slot start and never early. A phase whose
/// deadline has already passed fires immediately (warn + metric) and does not
/// move the aggregate phase.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn attestation_phase_fires_in_3999_4049_from_a_mid_second_start() {
    let _guard_metric = m2_metric_lock().await;
    let slot_ms = 12_000u64;
    let deadlines = mid_slot_deadlines();
    assert_eq!(due_ms(deadlines.attestation, slot_ms), 3999);
    assert_eq!(due_ms(deadlines.aggregate, slot_ms), 8000);
    assert_eq!(due_ms(deadlines.sync_message, slot_ms), 120);

    let before_sync = late_total(slot_phase_late::SYNC_MESSAGE);
    let before_att = late_total(slot_phase_late::ATTESTATION);
    let before_agg = late_total(slot_phase_late::AGGREGATE);

    let (mut orchestrator, handle) = mid_slot_orchestrator();
    let wake = tokio::time::Instant::now();
    let true_slot_start =
        wake.checked_sub(Duration::from_millis(OFFSET_MS)).expect("600ms fits in the paused clock");
    let fires = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let warns = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let layer = FireCapture { true_slot_start, fires: fires.clone(), warns: warns.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            // After the aggregate (8000ms from the true start = 7400ms from the
            // wake) and before the wall-based inter-slot wait elapses.
            tokio::time::sleep(Duration::from_millis(9_000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let fires = fires.lock().clone();
    let warns = warns.lock().clone();
    let phase0 = first_ms(&fires, PHASE_BLOCK);
    let attestation = first_ms(&fires, PROCESS_SLOT);
    let sync = first_ms(&fires, PRODUCE_SYNC_MESSAGES);
    let aggregate = first_ms(&fires, PRODUCE_AGGREGATIONS);

    // Phase 0 has no deadline wait. The wake is already 600ms into the slot, so
    // the earliest legal fire is that wake, within 50ms.
    assert!(
        (OFFSET_MS..=OFFSET_MS + 50).contains(&phase0),
        "phase 0 fires within 50ms of the 600ms-late wake, got {phase0}ms after true slot start"
    );
    assert!(
        (3999..=4049).contains(&attestation),
        "attestation fired at {attestation}ms after true slot start; expected [3999, 4049], never early \
         (a ~600ms miss means phase_deadline re-added the truncated fraction)"
    );
    assert!(
        (OFFSET_MS..=OFFSET_MS + 50).contains(&sync),
        "late sync phase must fire immediately, got {sync}ms after true slot start"
    );

    let late: Vec<_> = warns
        .iter()
        .filter(|warn| warn.phase.as_deref() == Some(slot_phase_late::SYNC_MESSAGE))
        .collect();
    assert_eq!(late.len(), 1, "one late-fire warn for sync_message, got {warns:?}");
    let overrun_ms = late[0].overrun_ms.expect("warn names overrun_ms");
    assert!((480..=530).contains(&overrun_ms), "overrun_ms {overrun_ms} should be about 600 - 120");
    assert!(
        late[0].phase.as_deref() == Some(slot_phase_late::SYNC_MESSAGE),
        "warn must name the phase, got {late:?}"
    );
    assert!(
        late[0].message.contains("firing immediately"),
        "warn message got {:?}",
        late[0].message
    );

    assert_eq!(
        late_total(slot_phase_late::SYNC_MESSAGE) - before_sync,
        1,
        "rvc_slot_phase_late_total{{phase}} increments once"
    );
    assert_eq!(
        late_total(slot_phase_late::ATTESTATION) - before_att,
        0,
        "on-time attestation must not count as late"
    );
    assert_eq!(
        late_total(slot_phase_late::AGGREGATE) - before_agg,
        0,
        "on-time aggregate must not count as late"
    );

    assert!(
        (8000..=8050).contains(&aggregate),
        "aggregate fired at {aggregate}ms; a late earlier phase must not shift it (expected [8000, 8050])"
    );
}
