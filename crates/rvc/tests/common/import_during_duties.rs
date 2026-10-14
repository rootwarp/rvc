//! Import-during-duties scenario (RR2-15 / #528).
//!
//! Composes the N-key [`pipeline_fixture`](crate::common::pipeline_fixture::pipeline_fixture)
//! with the on-disk [`SlashingDb`] it opens for `N > 1`, and runs one slot of
//! [`DutyOrchestrator::run`](rvc::orchestrator::DutyOrchestrator::run) while a
//! 10 MB interchange import takes the slashing connection.
//!
//! # Signature
//!
//! ```text
//! pub async fn run_import_during_duties(
//!     opts: ImportDuringDutiesOpts,
//!     admission: impl ImportAdmission,
//! ) -> Result<ImportDuringDutiesRecord, String>
//! ```
//!
//! [`ImportAdmission`] is the schedule hook. [`UnscheduledImport`] calls
//! [`SlashingProtection::import_interchange`](keymanager_api::traits::SlashingProtection::import_interchange)
//! as soon as [`ImportDuringDutiesOpts::fire_at`] is entered, with no RV-15b
//! window. RR3-07 (#536) passes a different [`ImportAdmission`] that waits on
//! RR3-02's free-window gate and then imports. The fixture, the payload, the
//! miss count, and the `rvc_slashing_import_conn_hold_ms` read stay here.
//!
//! [`ImportDuringDutiesOpts::n200_unscheduled_attestation`] leaves the block
//! beacon as [`NoopBlockBeacon`](super::pipeline_fixture::NoopBlockBeacon).
//! [`ImportDuringDutiesOpts::n200_scheduled_attestation`] turns on RR3-06's
//! proposer duty and Deneb production so a block reserve is observable.
//! `block_phase_overlapped` is phase-span overlap. `late_block_reserves`
//! counts block-reserve waits whose interval meets the import conn-hold (PQ-7).
//!
//! Those waits are the `(start, end)` instants around `reserve()` in
//! `SlashableSignSession::reserve_then_sign` (block kind only). The conn-hold
//! end is the `slashing DB import completed` event, which fires on the import
//! thread immediately after the hold histogram is sampled. The start is that
//! instant minus the sample. Neither interval is reconstructed from a poll.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bn_manager::{MockBeaconNodeClient, MockMethod, VersionedAttestation};
use keymanager_api::traits::SlashingProtection;
use slashing::metrics::{RVC_SLASHING_IMPORT_CONN_HOLD_MS, RVC_SLASHING_IMPORT_DEFERRED_MS};
use slashing::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata, SlashingDb,
    ValidatorRecord,
};
use timing::{due_ms, DeadlineBps};
use timing::{MockSlotClock, SlotClock};
use tokio::sync::oneshot;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

use super::pipeline_fixture::{
    create_test_config, make_beacon_attestation_data, pipeline_fixture, FixtureBlockProduction,
    PipelineFixtureOpts, SLOTS_PER_EPOCH,
};
use rvc::keymanager_adapters::SlashingProtectionAdapter;

/// RR2-13 compact JSON size for one attestation and one block per validator.
pub const TEN_MB_JSON_BYTES: usize = 10_026_526;
/// Validators in that interchange.
pub const TEN_MB_VALIDATORS: u64 = 26_737;
/// Attestation rows plus block rows (`TEN_MB_VALIDATORS * 2`).
pub const TEN_MB_HISTORY_ROWS: u64 = 53_474;

/// RR2-03 / RR2-16 publish slack after the attestation deadline.
///
/// A `SubmitAttestation` item whose estimated completion is later than
/// `attestation_deadline_ms + ATTESTATION_PUBLISH_BUDGET_MS` is one
/// attestation-deadline miss. The 0-miss gate is RR3-07, not this scenario.
pub const ATTESTATION_PUBLISH_BUDGET_MS: u64 = 1_000;

const SLOT_DURATION_MS: u64 = 12_000;
/// Hang guard for the ignored scenario. A finished N=200 slot is well under this.
const SLOT_WALL_BUDGET: Duration = Duration::from_secs(90);
const SIGNING_ROOT: &str = "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b";

const PHASE_ORDER: &[&str] =
    &["block", "attestation", "sync_message", "aggregate", "payload_attestation"];

/// Slot phase whose entry starts [`ImportAdmission::admit`].
///
/// Names match `rvc_slot_phase_offset_ms` labels. Contribution shares the
/// aggregate span when the two deadlines match, which is the default schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlapPhase {
    Block,
    Attestation,
    SyncMessage,
    Aggregate,
    PayloadAttestation,
}

impl OverlapPhase {
    /// Metric / record label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Attestation => "attestation",
            Self::SyncMessage => "sync_message",
            Self::Aggregate => "aggregate",
            Self::PayloadAttestation => "payload_attestation",
        }
    }

    fn span_name(self) -> &'static str {
        match self {
            Self::Block => "slot.phase.block",
            Self::Attestation => "slot.phase.attestation",
            Self::SyncMessage => "slot.phase.sync_message",
            Self::Aggregate => "slot.phase.aggregation",
            Self::PayloadAttestation => "slot.phase.payload_attestation",
        }
    }
}

/// Knobs for [`run_import_during_duties`].
///
/// RR2-15 uses [`Self::n200_unscheduled_attestation`]. RR3-07 keeps this
/// constructor and passes a scheduled [`ImportAdmission`].
#[derive(Clone, Debug)]
pub struct ImportDuringDutiesOpts {
    /// Local validators. The fixture opens an on-disk `SlashingDb` when this is greater than 1.
    pub validators: usize,
    /// Mock-BN delay charged before every role-trait call, including attestation publish.
    pub request_delay: Duration,
    /// Phase entry that calls [`ImportAdmission::admit`].
    pub fire_at: OverlapPhase,
    /// Put every validator in the sync committee.
    pub sync_committee: bool,
    /// Select every validator as an aggregator.
    pub aggregators: bool,
    /// Duty slot. Use the first slot of an epoch so the vote's target epoch is new.
    pub slot: u64,
    /// Serve a proposer duty and produce a Deneb block (RR3-06).
    ///
    /// RR2-15 leaves this false, so the block beacon stays the `Err` path.
    pub proposer: bool,
    /// Advance the fixture clock with wall time after the block phase so the
    /// import gate sees the same offset as the slot anchor.
    ///
    /// The orchestrator captures the anchor once and then waits on tokio time.
    /// [`MockSlotClock`] does not move on its own. Without this, a gate on the
    /// fixture clock still reads t=0 at attestation entry. RR2-15 leaves it
    /// false: [`UnscheduledImport`] uses its own clock.
    pub sync_slot_clock: bool,
    /// Wait this many milliseconds after the slot anchor before `admit`.
    ///
    /// `None` admits at [`Self::fire_at`] entry. The boundary cell sets this
    /// so the import starts late in slot N.
    pub fire_after_ms: Option<u64>,
    /// When true, clock sync may pass the slot end and `current_slot()` rolls.
    ///
    /// `false` clamps the offset at one millisecond before the slot end, which
    /// keeps `current_slot()` on `slot` and so never reaches a later reserve.
    pub roll_slot_clock: bool,
    /// Slots after [`Self::slot`] that also get a duty and attestation data.
    ///
    /// `0` is the one-slot scenario. `1` lets the orchestrator propose slot
    /// N+1 while an import started in slot N is still in flight.
    pub following_slots: u64,
}

impl ImportDuringDutiesOpts {
    /// N=200, 50 ms mock delay, sync and aggregators on, fire at attestation entry.
    ///
    /// This is A's slot loop (the N=200 `pipeline_fixture` duties) with B's
    /// import admitted on the unscheduled path.
    pub fn n200_unscheduled_attestation() -> Self {
        Self {
            validators: 200,
            request_delay: Duration::from_millis(50),
            fire_at: OverlapPhase::Attestation,
            sync_committee: true,
            aggregators: true,
            slot: SLOTS_PER_EPOCH,
            proposer: false,
            sync_slot_clock: false,
            fire_after_ms: None,
            roll_slot_clock: false,
            following_slots: 0,
        }
    }

    /// N=200 scheduled path. Same duty mix as [`Self::n200_unscheduled_attestation`].
    ///
    /// The slot is the first slot of the Deneb epoch (epoch 40). Slot 32 is
    /// epoch 1, and a Deneb body there fails the consensus-version check
    /// before `reserve_block`. Epoch 40 is Deneb and still pre-Electra
    /// (Electra is epoch 50), so the attestation target epoch is new and
    /// RR3-06's block production can record a reserve.
    pub fn n200_scheduled_attestation() -> Self {
        Self {
            validators: 200,
            request_delay: Duration::from_millis(50),
            fire_at: OverlapPhase::Attestation,
            sync_committee: true,
            aggregators: true,
            slot: 40 * SLOTS_PER_EPOCH,
            proposer: true,
            sync_slot_clock: true,
            fire_after_ms: None,
            roll_slot_clock: false,
            following_slots: 0,
        }
    }

    /// N=200 boundary cell. Import fires late in slot N and the clock may roll
    /// into slot N+1, which also has a proposer duty.
    ///
    /// `fire_after_ms` is 11_600. The free window closes at 11_800, so a
    /// scheduled admission cannot finish a ~700 ms hold in the remainder and
    /// defers to slot N+1's open at 4,499 ms. An unscheduled admission starts
    /// at 11_600 ms and can still be holding `conn` when slot N+1's t=0 block
    /// reserve begins. Slot 1280 is the first slot of Deneb epoch 40, so slot
    /// 1281 stays on that fork and in that epoch.
    pub fn n200_boundary_attestation() -> Self {
        Self {
            validators: 200,
            request_delay: Duration::from_millis(50),
            fire_at: OverlapPhase::Attestation,
            sync_committee: true,
            aggregators: true,
            slot: 40 * SLOTS_PER_EPOCH,
            proposer: true,
            sync_slot_clock: true,
            fire_after_ms: Some(11_600),
            roll_slot_clock: true,
            following_slots: 1,
        }
    }
}

/// Borrowed interchange the admission policy imports.
///
/// `history_rows` is the figure RR3-02 passes to `gate.admit`. The JSON is the
/// body of `import_interchange`.
pub struct ImportRequest<'a> {
    pub interchange_json: &'a str,
    pub history_rows: u64,
    pub slashing_db: &'a Arc<SlashingDb>,
    pub genesis_validators_root: eth_types::Root,
    /// Fixture clock. [`ScheduledImport`] builds its gate on this.
    /// [`UnscheduledImport`] does not read it.
    pub slot_clock: &'a Arc<MockSlotClock>,
}

/// Failure from [`ImportAdmission::admit`].
#[derive(Debug)]
pub struct AdmissionError {
    pub message: String,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// When the interchange may call `import_interchange`.
///
/// The harness awaits [`Self::admit`] at [`ImportDuringDutiesOpts::fire_at`]
/// and does not know whether the impl defers. [`UnscheduledImport`] does not.
pub trait ImportAdmission: Send {
    /// Record label. [`UnscheduledImport`] returns `"unscheduled"`.
    fn label(&self) -> &'static str;

    /// Import `request`, deferring first when this policy has a gate.
    fn admit(
        &mut self,
        request: ImportRequest<'_>,
    ) -> impl Future<Output = Result<(), AdmissionError>> + Send;
}

/// No orchestrator-slot window. The adapter's gate clock is already inside a
/// free window, so `import_interchange` starts at phase entry.
///
/// The adapter moves the SQLite transaction onto Tokio's blocking pool and
/// keeps the admission guard there. This harness awaits that future on the
/// runtime; nesting `block_on` inside another `spawn_blocking` would stall it.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnscheduledImport;

impl ImportAdmission for UnscheduledImport {
    fn label(&self) -> &'static str {
        "unscheduled"
    }

    async fn admit(&mut self, request: ImportRequest<'_>) -> Result<(), AdmissionError> {
        let slashing = SlashingProtectionAdapter::new_in_free_window(
            Arc::clone(request.slashing_db),
            request.genesis_validators_root,
        );
        slashing
            .import_interchange(request.interchange_json)
            .await
            .map_err(|err| AdmissionError { message: err.to_string() })
    }
}

/// Wait on the fixture clock's free window, then import.
///
/// [`SlashingProtectionAdapter::new_on_clock`] builds one import-window gate
/// for this call. `import_interchange` is what calls `admit`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScheduledImport;

impl ImportAdmission for ScheduledImport {
    fn label(&self) -> &'static str {
        "scheduled"
    }

    async fn admit(&mut self, request: ImportRequest<'_>) -> Result<(), AdmissionError> {
        let slashing = SlashingProtectionAdapter::new_on_clock(
            Arc::clone(request.slashing_db),
            request.genesis_validators_root,
            Arc::clone(request.slot_clock) as Arc<dyn SlotClock>,
        );
        slashing
            .import_interchange(request.interchange_json)
            .await
            .map_err(|err| AdmissionError { message: err.to_string() })
    }
}

/// One measured run. Misses are recorded; they are not a pass/fail gate.
#[derive(Clone, Debug)]
pub struct ImportDuringDutiesRecord {
    pub admission: &'static str,
    pub sha: String,
    pub host: String,
    pub toolchain: String,
    pub clock_mode: &'static str,
    pub n: usize,
    pub slot: u64,
    pub slot_duration_ms: u64,
    pub request_delay_ms: u64,
    pub payload_bytes: usize,
    pub payload_validators: u64,
    pub history_rows: u64,
    pub on_disk: bool,
    pub fire_at: &'static str,
    /// Milliseconds after the slot anchor before `admit`. `None` is phase entry.
    pub fire_after_ms: Option<u64>,
    /// Clock sync was allowed to roll `current_slot()` past [`Self::slot`].
    pub roll_slot_clock: bool,
    /// Extra duty slots after [`Self::slot`].
    pub following_slots: u64,
    pub attestation_deadline_ms: u64,
    pub attestation_publish_budget_ms: u64,
    /// Attestation items whose estimated publish completion is later than
    /// the deadline plus [`ATTESTATION_PUBLISH_BUDGET_MS`].
    pub attestation_deadline_misses: u64,
    /// Latest estimated publish completion minus the attestation deadline.
    /// Negative means the publish landed before the deadline.
    pub last_publish_ms_after_att_deadline: f64,
    pub attestation_items: u64,
    /// Delta of `rvc_slashing_import_conn_hold_ms` sample sum for this import.
    pub conn_hold_ms: f64,
    pub conn_hold_samples: u64,
    /// `conn.lock()` offset from the slot anchor, in milliseconds.
    pub conn_hold_start_ms: f64,
    /// `COMMIT` offset from the slot anchor, in milliseconds.
    pub conn_hold_end_ms: f64,
    /// Phases whose open interval intersected the conn-hold window, in slot order.
    pub overlapping_phase: String,
    /// `true` when the hold intersected the block phase. Phase-span overlap.
    pub block_phase_overlapped: bool,
    /// RR3-06 proposer duty was served.
    pub proposer: bool,
    /// Delta of `rvc_slashing_import_deferred_ms` for this import.
    pub import_deferred_ms: f64,
    pub import_deferred_samples: u64,
    /// Block-reserve waits observed on `rvc_slashing_reserve_tx_hold_duration_ms{kind="block"}`.
    pub block_reserves: u64,
    /// How many of those waits meet the import conn-hold interval (PQ-7).
    pub late_block_reserves: u64,
    pub block_reserve_intervals: Vec<BlockReserveWait>,
    pub phase_fires: Vec<PhaseFireRecord>,
}

/// One block reserve's wait: mutex acquire through COMMIT, placed on the slot clock.
#[derive(Clone, Debug)]
pub struct BlockReserveWait {
    /// Offset from the slot anchor, milliseconds.
    pub start_ms: f64,
    /// Offset from the slot anchor, milliseconds.
    pub end_ms: f64,
    pub duration_ms: f64,
}

fn round_ms(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// One phase entry observed from `time_into_slot` on the phase span.
#[derive(Clone, Debug)]
pub struct PhaseFireRecord {
    pub phase: &'static str,
    /// `time_into_slot` recorded by the coordinator, milliseconds.
    pub offset_ms: u64,
}

impl ImportDuringDutiesRecord {
    /// Pretty JSON for the measurement note. One object, trailing newline.
    pub fn to_json(&self) -> String {
        let fires: Vec<serde_json::Value> = self
            .phase_fires
            .iter()
            .map(|fire| serde_json::json!({ "phase": fire.phase, "offset_ms": fire.offset_ms }))
            .collect();
        let value = serde_json::json!({
            "issue": if self.admission == "scheduled" { "RR3-07" } else { "RR2-15" },
            "admission": self.admission,
            "sha": self.sha,
            "host": self.host,
            "toolchain": self.toolchain,
            "clock_mode": self.clock_mode,
            "n": self.n,
            "slot": self.slot,
            "slot_duration_ms": self.slot_duration_ms,
            "request_delay_ms": self.request_delay_ms,
            "payload_bytes": self.payload_bytes,
            "payload_validators": self.payload_validators,
            "history_rows": self.history_rows,
            "on_disk": self.on_disk,
            "fire_at": self.fire_at,
            "fire_after_ms": self.fire_after_ms,
            "roll_slot_clock": self.roll_slot_clock,
            "following_slots": self.following_slots,
            "attestation_deadline_ms": self.attestation_deadline_ms,
            "attestation_publish_budget_ms": self.attestation_publish_budget_ms,
            "attestation_deadline_misses": self.attestation_deadline_misses,
            "last_publish_ms_after_att_deadline": round_ms(self.last_publish_ms_after_att_deadline),
            "attestation_items": self.attestation_items,
            "conn_hold_ms": round_ms(self.conn_hold_ms),
            "conn_hold_samples": self.conn_hold_samples,
            "conn_hold_start_ms": round_ms(self.conn_hold_start_ms),
            "conn_hold_end_ms": round_ms(self.conn_hold_end_ms),
            "overlapping_phase": self.overlapping_phase,
            "block_phase_overlapped": self.block_phase_overlapped,
            "proposer": self.proposer,
            "import_deferred_ms": round_ms(self.import_deferred_ms),
            "import_deferred_samples": self.import_deferred_samples,
            "block_reserves": self.block_reserves,
            "late_block_reserves": self.late_block_reserves,
            "block_reserve_intervals": self.block_reserve_intervals.iter().map(|wait| {
                serde_json::json!({
                    "start_ms": round_ms(wait.start_ms),
                    "end_ms": round_ms(wait.end_ms),
                    "duration_ms": round_ms(wait.duration_ms),
                })
            }).collect::<Vec<_>>(),
            "phase_fires": fires,
        });
        format!("{}\n", serde_json::to_string_pretty(&value).expect("record json"))
    }
}

struct Payload {
    json: String,
    bytes: usize,
    validators: u64,
    history_rows: u64,
    gvr: eth_types::Root,
}

/// Same shape as the RR2-13 generator in `crates/slashing/tests/interchange.rs`:
/// compact JSON of at least 10_000_000 bytes, one attestation and one block
/// per validator, each with a 32-byte signing root. The metadata genesis root
/// is the pipeline fixture's root so `import_interchange` passes the GVR check
/// and takes `conn`. That root is the same hex length as the RR2-13 constant,
/// so the published byte count does not move.
fn ten_mb_payload() -> Result<Payload, String> {
    let gvr = create_test_config().genesis_validators_root;
    let gvr_hex = format!("0x{}", hex::encode(gvr));
    const TARGET_BYTES: usize = 10_000_000;

    let sample = ten_mb_validator(0, SIGNING_ROOT);
    let sample_len = serde_json::to_vec(&sample).map_err(|err| err.to_string())?.len();
    let empty = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: gvr_hex.clone(),
        },
        data: vec![],
    };
    let empty_len = serde_json::to_vec(&empty).map_err(|err| err.to_string())?.len();
    let estimated = TARGET_BYTES.saturating_sub(empty_len.saturating_sub(2)) / sample_len.max(1);
    let mut n = u32::try_from(estimated).unwrap_or(u32::MAX).max(1);
    loop {
        let data: Vec<ValidatorRecord> =
            (0..n).map(|index| ten_mb_validator(index, SIGNING_ROOT)).collect();
        let file = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: gvr_hex.clone(),
            },
            data,
        };
        let bytes = serde_json::to_vec(&file).map_err(|err| err.to_string())?;
        if bytes.len() >= TARGET_BYTES {
            let validators = u64::from(n);
            let json = String::from_utf8(bytes).map_err(|err| err.to_string())?;
            let payload_bytes = json.len();
            if payload_bytes != TEN_MB_JSON_BYTES || validators != TEN_MB_VALIDATORS {
                return Err(format!(
                    "10 MB payload drifted: {payload_bytes} bytes / {validators} validators \
                     (pinned {TEN_MB_JSON_BYTES} / {TEN_MB_VALIDATORS})"
                ));
            }
            let history_rows = validators * 2;
            if history_rows != TEN_MB_HISTORY_ROWS {
                return Err(format!(
                    "history rows drifted: {history_rows} (pinned {TEN_MB_HISTORY_ROWS})"
                ));
            }
            return Ok(Payload { json, bytes: payload_bytes, validators, history_rows, gvr });
        }
        n = n.checked_add(1).ok_or("10 MB interchange validator count overflowed u32")?;
    }
}

fn ten_mb_validator(index: u32, signing_root: &str) -> ValidatorRecord {
    let mut raw = [0x11u8; 48];
    raw[44..48].copy_from_slice(&index.to_be_bytes());
    ValidatorRecord {
        pubkey: format!("0x{}", hex::encode(raw)),
        signed_blocks: vec![InterchangeBlock {
            slot: "1".to_string(),
            signing_root: Some(signing_root.to_string()),
        }],
        signed_attestations: vec![InterchangeAttestation {
            source_epoch: "1".to_string(),
            target_epoch: "2".to_string(),
            signing_root: Some(signing_root.to_string()),
        }],
    }
}

struct PhaseFire {
    phase: &'static str,
    span_key: u64,
    /// `time_into_slot` record. The phase is open from here, not from span creation
    /// (the coordinator builds the span before the intra-slot wait).
    at: tokio::time::Instant,
    offset_ms: u64,
    /// Span drop. Attestation and sync message run concurrently, so the next
    /// phase's entry does not close this one.
    closed_at: Option<tokio::time::Instant>,
}

struct PhaseState {
    spans: HashMap<Id, &'static str>,
    slot_started: Option<tokio::time::Instant>,
    /// Same origin as `slot_started`, on `std::time::Instant`.
    ///
    /// Reserve instants and the import-completed event use that clock.
    /// Tokio's clock is only the phase spans.
    slot_started_std: Option<Instant>,
    /// `slashing DB import completed`, on the import thread.
    import_completed_at: Option<Instant>,
    fires: Vec<PhaseFire>,
}

struct PhaseLayer {
    state: Arc<Mutex<PhaseState>>,
    fire_tx: Mutex<Option<oneshot::Sender<()>>>,
    target_span: &'static str,
}

impl<S> Layer<S> for PhaseLayer
where
    S: tracing::Subscriber,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let Some(phase) = phase_from_span(attrs.metadata().name()) else {
            return;
        };
        self.state.lock().expect("phase log").spans.insert(id.clone(), phase);
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, _ctx: Context<'_, S>) {
        let mut visitor = TimeIntoSlotVisitor::default();
        values.record(&mut visitor);
        let Some(offset_ms) = visitor.offset_ms else {
            return;
        };
        let mut state = self.state.lock().expect("phase log");
        let Some(phase) = state.spans.get(id).copied() else {
            return;
        };
        let now = tokio::time::Instant::now();
        let now_std = Instant::now();
        if phase == "block" && state.slot_started.is_none() {
            state.slot_started =
                Some(now.checked_sub(Duration::from_millis(offset_ms)).unwrap_or(now));
            state.slot_started_std =
                Some(now_std.checked_sub(Duration::from_millis(offset_ms)).unwrap_or(now_std));
        }
        let span_key = id.into_u64();
        state.fires.push(PhaseFire { phase, span_key, at: now, offset_ms, closed_at: None });
        let is_target = phase_from_span(self.target_span) == Some(phase);
        drop(state);
        if is_target {
            let tx = self.fire_tx.lock().expect("fire channel").take();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
        }
    }

    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        let mut state = self.state.lock().expect("phase log");
        let span_key = id.into_u64();
        let now = tokio::time::Instant::now();
        for fire in &mut state.fires {
            if fire.span_key == span_key {
                fire.closed_at = Some(now);
            }
        }
        state.spans.remove(&id);
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // `metadata().name()` is the callsite (`event path:line`), not the
        // message. The message is a field on the event.
        let mut visitor = ImportCompletedVisitor { matched: false };
        event.record(&mut visitor);
        if !visitor.matched {
            return;
        }
        let mut state = self.state.lock().expect("phase log");
        if state.import_completed_at.is_none() {
            state.import_completed_at = Some(Instant::now());
        }
    }
}

/// Sees the static message on `tracing::info!(..., "slashing DB import completed")`.
struct ImportCompletedVisitor {
    matched: bool,
}

impl Visit for ImportCompletedVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message"
            && format!("{value:?}").contains("slashing DB import completed")
        {
            self.matched = true;
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" && value == "slashing DB import completed" {
            self.matched = true;
        }
    }
}

#[derive(Default)]
struct TimeIntoSlotVisitor {
    offset_ms: Option<u64>,
}

impl Visit for TimeIntoSlotVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "time_into_slot" {
            self.offset_ms = Some(value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "time_into_slot" && value >= 0 {
            self.offset_ms = Some(value as u64);
        }
    }
}

fn phase_from_span(name: &str) -> Option<&'static str> {
    match name {
        "slot.phase.block" => Some("block"),
        "slot.phase.attestation" => Some("attestation"),
        "slot.phase.sync_message" => Some("sync_message"),
        "slot.phase.aggregation" => Some("aggregate"),
        "slot.phase.payload_attestation" => Some("payload_attestation"),
        _ => None,
    }
}

fn command_stdout(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).unwrap_or_default().trim().to_string()
        }
        _ => String::new(),
    }
}

fn host_label() -> String {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".to_string());
    format!("{} {}/{}", hostname.trim(), std::env::consts::OS, std::env::consts::ARCH)
}

fn attestation_items(batch: &VersionedAttestation) -> usize {
    match batch {
        VersionedAttestation::PreElectra(v) => v.len(),
        VersionedAttestation::Electra(v)
        | VersionedAttestation::Fulu(v)
        | VersionedAttestation::Gloas(v) => v.len(),
    }
}

fn offset_ms(slot_started: tokio::time::Instant, at: tokio::time::Instant) -> f64 {
    at.saturating_duration_since(slot_started).as_secs_f64() * 1000.0
}

struct PublishTally {
    items: u64,
    misses: u64,
    last_publish_ms_after_att_deadline: f64,
}

fn tally_publishes(
    client: &MockBeaconNodeClient,
    slot_started: tokio::time::Instant,
    request_delay: Duration,
    deadline_ms: f64,
    miss_after_ms: f64,
    // Publishes later than this offset are a following slot, not slot N misses.
    count_through_ms: Option<f64>,
) -> PublishTally {
    let calls = client.submit_attestation_calls();
    let mut call_index = 0usize;
    let mut items = 0u64;
    let mut misses = 0u64;
    let mut last_completion_ms: Option<f64> = None;
    for stamp in client.call_stamps() {
        if stamp.method != MockMethod::SubmitAttestation {
            continue;
        }
        let batch_items = calls.get(call_index).map(attestation_items).unwrap_or(0) as u64;
        call_index += 1;
        let completion = stamp.at + request_delay;
        let offset = offset_ms(slot_started, completion);
        if count_through_ms.is_some_and(|limit| offset > limit) {
            continue;
        }
        items += batch_items;
        last_completion_ms = Some(last_completion_ms.map_or(offset, |prev| prev.max(offset)));
        if offset > miss_after_ms {
            misses += batch_items;
        }
    }
    let last_publish_ms_after_att_deadline =
        last_completion_ms.map(|ms| ms - deadline_ms).unwrap_or(0.0);
    PublishTally { items, misses, last_publish_ms_after_att_deadline }
}

/// Phases whose `[time_into_slot, span close]` window meets the conn-hold.
///
/// A phase that has not closed yet is treated as running through `hold_end`.
/// Attestation and sync message run together, so one entry does not close the other.
fn overlapping_phases(
    fires: &[PhaseFire],
    hold_start: tokio::time::Instant,
    hold_end: tokio::time::Instant,
) -> Vec<&'static str> {
    let mut names = Vec::new();
    for fire in fires {
        let end = fire.closed_at.unwrap_or(hold_end).max(fire.at);
        let overlaps = fire.at <= hold_end && hold_start <= end;
        if overlaps && !names.contains(&fire.phase) {
            names.push(fire.phase);
        }
    }
    names.sort_by_key(|name| {
        PHASE_ORDER.iter().position(|phase| phase == name).unwrap_or(PHASE_ORDER.len())
    });
    names
}

fn sync_slot_clock(state: &Mutex<PhaseState>, clock: &MockSlotClock, slot: u64, roll: bool) {
    let phase_state = state.lock().expect("phase log");
    let Some(block) = phase_state.fires.iter().find(|fire| fire.phase == "block") else {
        return;
    };
    let elapsed_ms = u64::try_from(block.at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut into_slot = block.offset_ms.saturating_add(elapsed_ms);
    if !roll {
        into_slot = into_slot.min(SLOT_DURATION_MS - 1);
    }
    drop(phase_state);
    clock.set_slot_with_offset_ms(slot, into_slot);
}

fn std_offset_ms(origin: Instant, at: Instant) -> f64 {
    at.saturating_duration_since(origin).as_secs_f64() * 1000.0
}

/// Closed intervals. An endpoint touch counts as overlap.
pub fn intervals_overlap(a_start: f64, a_end: f64, b_start: f64, b_end: f64) -> bool {
    a_start <= b_end && b_start <= a_end
}

/// How many reserve intervals `[start, end]` meet the hold.
///
/// The harness passes the instants recorded at reserve start/return and at
/// the import-completed event. It does not shift them by a poll lag.
pub fn late_reserve_count(hold_start: f64, hold_end: f64, reserves: &[(f64, f64)]) -> u64 {
    u64::try_from(
        reserves
            .iter()
            .filter(|(start, end)| intervals_overlap(hold_start, hold_end, *start, *end))
            .count(),
    )
    .unwrap_or(u64::MAX)
}

/// Interval the old 10 ms poll detector stored for one histogram sample.
///
/// `poll_at_ms` is the poll instant. The start is that instant minus the
/// sample, so a late poll slides the whole wait forward by the lag.
pub fn poll_reconstructed_interval(poll_at_ms: f64, duration_ms: f64) -> (f64, f64) {
    (poll_at_ms - duration_ms, poll_at_ms)
}

/// Drive `opts` against `admission` and return the measurement record.
///
/// Wall clock, not paused. The import is not a pass/fail latency gate.
/// Call this from a Tokio runtime; [`UnscheduledImport`] uses `spawn_blocking`.
///
/// RR3-07 calls this function with the same `opts` shape and a gate-backed
/// [`ImportAdmission`]. It does not reimplement the slot loop.
pub async fn run_import_during_duties(
    opts: ImportDuringDutiesOpts,
    mut admission: impl ImportAdmission,
) -> Result<ImportDuringDutiesRecord, String> {
    if opts.validators < 2 {
        return Err(format!(
            "validators must be > 1 so pipeline_fixture opens an on-disk SlashingDb, got {}",
            opts.validators
        ));
    }

    let (fire_tx, fire_rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(PhaseState {
        spans: HashMap::new(),
        slot_started: None,
        slot_started_std: None,
        import_completed_at: None,
        fires: Vec::new(),
    }));
    let layer = PhaseLayer {
        state: Arc::clone(&state),
        fire_tx: Mutex::new(Some(fire_tx)),
        target_span: opts.fire_at.span_name(),
    };
    // Install before the fixture. `spawn_blocking` threads cache the global
    // dispatcher on their first event, and the import completion is one of
    // those events. A subscriber installed after the pool has already logged
    // is invisible to it.
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|err| format!("installing the import-during-duties subscriber failed: {err}"))?;
    slashing::metrics::init();

    let payload = ten_mb_payload()?;
    let attestation_deadline_ms = due_ms(DeadlineBps::default().attestation, SLOT_DURATION_MS);
    if attestation_deadline_ms != 3999 {
        return Err(format!(
            "attestation deadline drifted from 3999 ms: {attestation_deadline_ms}"
        ));
    }
    let miss_after_ms = attestation_deadline_ms as f64 + ATTESTATION_PUBLISH_BUDGET_MS as f64;

    let mut duty_slots = vec![opts.slot];
    let mut attestation_data_by_slot = std::collections::HashMap::new();
    attestation_data_by_slot
        .insert(opts.slot, make_beacon_attestation_data(opts.slot, 0, 0x22, 0x33, 0x11));
    for extra in 1..=opts.following_slots {
        let slot = opts.slot + extra;
        duty_slots.push(slot);
        attestation_data_by_slot
            .insert(slot, make_beacon_attestation_data(slot, 0, 0x22, 0x33, 0x11));
    }
    let mut prepared = PipelineFixtureOpts {
        attestation_data_by_slot,
        duty_slots,
        initial_slot: opts.slot,
        ..Default::default()
    }
    .with_validators(opts.validators)
    .with_sync_committee(opts.sync_committee)
    .with_aggregators(opts.aggregators)
    .with_request_delay(opts.request_delay);
    if opts.proposer {
        prepared =
            prepared.with_proposer(true).with_block_production(FixtureBlockProduction::Deneb);
    }
    let mut fixture = pipeline_fixture(prepared);
    let db_path = fixture
        .slashing_db_path()
        .ok_or_else(|| "N-key pipeline_fixture did not open an on-disk SlashingDb".to_string())?;
    if !db_path.is_file() {
        return Err(format!("slashing db path is not a file: {}", db_path.display()));
    }

    let mut epochs = vec![opts.slot / SLOTS_PER_EPOCH];
    for extra in 1..=opts.following_slots {
        let epoch = (opts.slot + extra) / SLOTS_PER_EPOCH;
        if !epochs.contains(&epoch) {
            epochs.push(epoch);
        }
    }
    for epoch in epochs {
        fixture
            .duty_tracker
            .fetch_duties_for_epoch(epoch)
            .await
            .map_err(|err| format!("fetch attester duties: {err}"))?;
        if opts.sync_committee {
            fixture
                .duty_tracker
                .fetch_sync_committee_duties(epoch)
                .await
                .map_err(|err| format!("fetch sync duties: {err}"))?;
        }
    }
    fixture.set_slot(opts.slot);

    let db = Arc::clone(&fixture.slashing_db);
    let client = Arc::clone(&fixture.beacon_client);

    let hold_sum_before = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_sum();
    let hold_n_before = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count();
    let deferred_sum_before = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_sum();
    let deferred_n_before = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_count();
    let admission_label = admission.label();
    let history_rows = payload.history_rows;
    let gvr = payload.gvr;
    let json = payload.json;
    let slot_clock = Arc::clone(&fixture.clock);
    signer::clear_block_reserve_intervals();
    let fire_after_ms = opts.fire_after_ms;
    let roll_slot_clock = opts.roll_slot_clock;
    let sync_clock = opts.sync_slot_clock;
    let clock_slot = opts.slot;

    let import_fut = async {
        let _ = fire_rx.await;
        if let Some(after_ms) = fire_after_ms {
            let slot_started = loop {
                if let Some(started) = state.lock().expect("phase log").slot_started {
                    break started;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            tokio::time::sleep_until(slot_started + Duration::from_millis(after_ms)).await;
            if sync_clock {
                sync_slot_clock(&state, &slot_clock, clock_slot, roll_slot_clock);
            }
        }
        admission
            .admit(ImportRequest {
                interchange_json: &json,
                history_rows,
                slashing_db: &db,
                genesis_validators_root: gvr,
                slot_clock: &slot_clock,
            })
            .await
    };
    tokio::pin!(import_fut);

    let run_fut = fixture.orchestrator.run();
    tokio::pin!(run_fut);
    let handle = &fixture.handle;
    let wall_started = std::time::Instant::now();
    let mut shutdown_sent = false;
    let mut budget_exceeded = false;
    let mut import_done: Option<Result<(), AdmissionError>> = None;
    // Slot N's t=0 reserve, plus one t=0 reserve per following proposer slot.
    let needed_reserves = if opts.proposer { 1 + opts.following_slots } else { 0 };

    loop {
        tokio::select! {
            biased;
            result = &mut run_fut => {
                if let Err(err) = result {
                    return Err(format!("orchestrator run: {err}"));
                }
                break;
            }
            outcome = &mut import_fut, if import_done.is_none() => {
                import_done = Some(outcome);
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                if opts.sync_slot_clock {
                    sync_slot_clock(&state, &slot_clock, opts.slot, opts.roll_slot_clock);
                }
                if shutdown_sent {
                    continue;
                }
                let published = client
                    .submit_attestation_calls()
                    .iter()
                    .map(attestation_items)
                    .sum::<usize>();
                let import_finished = import_done.is_some();
                let reserves_done = signer::block_reserve_interval_count() >= needed_reserves as usize;
                // The one-slot path stops once slot N has published. The
                // boundary path must stay up through the later block reserve;
                // slot N's publishes finish before that reserve starts.
                let scenario_done = if opts.following_slots == 0 {
                    import_finished && published >= opts.validators
                } else {
                    import_finished && reserves_done
                };
                if scenario_done {
                    handle.shutdown();
                    shutdown_sent = true;
                } else if wall_started.elapsed() > SLOT_WALL_BUDGET {
                    budget_exceeded = true;
                    handle.shutdown();
                    shutdown_sent = true;
                }
            }
        }
    }

    if budget_exceeded {
        return Err(format!(
            "slot wall budget {SLOT_WALL_BUDGET:?} exceeded before {} attestation publishes and the import finished",
            opts.validators,
        ));
    }
    let import_result = import_done.ok_or("orchestrator stopped before the import finished")?;
    import_result.map_err(|err| format!("import_interchange: {err}"))?;

    let conn_hold_ms = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_sum() - hold_sum_before;
    let conn_hold_samples =
        RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count().saturating_sub(hold_n_before);
    let import_deferred_ms = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_sum() - deferred_sum_before;
    let import_deferred_samples =
        RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_count().saturating_sub(deferred_n_before);
    if conn_hold_samples != 1 {
        return Err(format!(
            "expected one rvc_slashing_import_conn_hold_ms sample, got {conn_hold_samples}"
        ));
    }

    let phase_state = state.lock().expect("phase log");
    let slot_started =
        phase_state.slot_started.ok_or("block phase did not record time_into_slot")?;
    let slot_started_std =
        phase_state.slot_started_std.ok_or("block phase did not record a std slot origin")?;
    let hold_end_std = phase_state
        .import_completed_at
        .ok_or("slashing DB import completed was not observed; the conn-hold end is that event")?;
    let hold_start_std = hold_end_std
        .checked_sub(Duration::from_secs_f64((conn_hold_ms / 1000.0).max(0.0)))
        .unwrap_or(hold_end_std);
    let hold_start = slot_started + hold_start_std.saturating_duration_since(slot_started_std);
    let hold_end = slot_started + hold_end_std.saturating_duration_since(slot_started_std);
    let phases = overlapping_phases(&phase_state.fires, hold_start, hold_end);
    // Recorded, not gated. A deferred admission may return after `fire_at` has
    // closed; the unscheduled test asserts attestation overlap itself.
    let overlapping_phase = phases.join("+");
    let block_phase_overlapped = phases.contains(&"block");
    let phase_fires = phase_state
        .fires
        .iter()
        .map(|fire| PhaseFireRecord { phase: fire.phase, offset_ms: fire.offset_ms })
        .collect();
    drop(phase_state);

    let count_through_ms =
        if opts.following_slots == 0 { None } else { Some(SLOT_DURATION_MS as f64) };
    let tally = tally_publishes(
        &client,
        slot_started,
        opts.request_delay,
        attestation_deadline_ms as f64,
        miss_after_ms,
        count_through_ms,
    );
    if opts.following_slots == 0 && tally.items != opts.validators as u64 {
        return Err(format!("expected {} attestation items, got {}", opts.validators, tally.items));
    }
    if opts.following_slots > 0 && tally.items < opts.validators as u64 {
        return Err(format!(
            "expected at least {} slot-{} attestation items, got {}",
            opts.validators, opts.slot, tally.items
        ));
    }

    let request_delay_ms =
        u64::try_from(opts.request_delay.as_millis()).map_err(|_| "request delay exceeds u64")?;

    let conn_hold_start_ms = std_offset_ms(slot_started_std, hold_start_std);
    let conn_hold_end_ms = std_offset_ms(slot_started_std, hold_end_std);
    let block_reserve_intervals: Vec<BlockReserveWait> = signer::take_block_reserve_intervals()
        .into_iter()
        .map(|(start, end)| BlockReserveWait {
            start_ms: std_offset_ms(slot_started_std, start),
            end_ms: std_offset_ms(slot_started_std, end),
            duration_ms: end.saturating_duration_since(start).as_secs_f64() * 1000.0,
        })
        .collect();
    let reserve_pairs: Vec<(f64, f64)> =
        block_reserve_intervals.iter().map(|wait| (wait.start_ms, wait.end_ms)).collect();
    let late_block_reserves =
        late_reserve_count(conn_hold_start_ms, conn_hold_end_ms, &reserve_pairs);
    let block_reserves = u64::try_from(block_reserve_intervals.len()).unwrap_or(u64::MAX);

    Ok(ImportDuringDutiesRecord {
        admission: admission_label,
        sha: command_stdout("git", &["rev-parse", "HEAD"]),
        host: host_label(),
        toolchain: command_stdout("rustc", &["--version"]),
        clock_mode: "wall",
        n: opts.validators,
        slot: opts.slot,
        slot_duration_ms: SLOT_DURATION_MS,
        request_delay_ms,
        payload_bytes: payload.bytes,
        payload_validators: payload.validators,
        history_rows: payload.history_rows,
        on_disk: true,
        fire_at: opts.fire_at.as_str(),
        fire_after_ms: opts.fire_after_ms,
        roll_slot_clock: opts.roll_slot_clock,
        following_slots: opts.following_slots,
        attestation_deadline_ms,
        attestation_publish_budget_ms: ATTESTATION_PUBLISH_BUDGET_MS,
        attestation_deadline_misses: tally.misses,
        last_publish_ms_after_att_deadline: tally.last_publish_ms_after_att_deadline,
        attestation_items: tally.items,
        conn_hold_ms,
        conn_hold_samples,
        conn_hold_start_ms,
        conn_hold_end_ms,
        overlapping_phase,
        block_phase_overlapped,
        proposer: opts.proposer,
        import_deferred_ms,
        import_deferred_samples,
        block_reserves,
        late_block_reserves,
        block_reserve_intervals,
        phase_fires,
    })
}
