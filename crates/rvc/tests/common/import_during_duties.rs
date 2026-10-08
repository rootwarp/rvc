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
//! The fixture block beacon stays [`NoopBlockBeacon`](super::pipeline_fixture::NoopBlockBeacon)
//! until RR3-06. `block_phase_overlapped` is the phase-span overlap PQ-7 can
//! read today; it is not yet a block-reserve interval.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bn_manager::{MockBeaconNodeClient, MockMethod, VersionedAttestation};
use keymanager_api::traits::SlashingProtection;
use slashing::metrics::RVC_SLASHING_IMPORT_CONN_HOLD_MS;
use slashing::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata, SlashingDb,
    ValidatorRecord,
};
use timing::{due_ms, DeadlineBps};
use tokio::sync::oneshot;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

use super::pipeline_fixture::{
    create_test_config, make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts,
    SLOTS_PER_EPOCH,
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
    /// `true` when the hold intersected the block phase. PQ-7 input.
    pub block_phase_overlapped: bool,
    pub phase_fires: Vec<PhaseFireRecord>,
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
            "issue": "RR2-15",
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
        if phase == "block" && state.slot_started.is_none() {
            state.slot_started =
                Some(now.checked_sub(Duration::from_millis(offset_ms)).unwrap_or(now));
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

    slashing::metrics::init();
    let payload = ten_mb_payload()?;
    let attestation_deadline_ms = due_ms(DeadlineBps::default().attestation, SLOT_DURATION_MS);
    if attestation_deadline_ms != 3999 {
        return Err(format!(
            "attestation deadline drifted from 3999 ms: {attestation_deadline_ms}"
        ));
    }
    let miss_after_ms = attestation_deadline_ms as f64 + ATTESTATION_PUBLISH_BUDGET_MS as f64;

    let mut attestation_data_by_slot = std::collections::HashMap::new();
    attestation_data_by_slot
        .insert(opts.slot, make_beacon_attestation_data(opts.slot, 0, 0x22, 0x33, 0x11));
    let mut fixture = pipeline_fixture(
        PipelineFixtureOpts {
            attestation_data_by_slot,
            duty_slots: vec![opts.slot],
            initial_slot: opts.slot,
            ..Default::default()
        }
        .with_validators(opts.validators)
        .with_sync_committee(opts.sync_committee)
        .with_aggregators(opts.aggregators)
        .with_request_delay(opts.request_delay),
    );
    let db_path = fixture
        .slashing_db_path()
        .ok_or_else(|| "N-key pipeline_fixture did not open an on-disk SlashingDb".to_string())?;
    if !db_path.is_file() {
        return Err(format!("slashing db path is not a file: {}", db_path.display()));
    }

    let epoch = opts.slot / SLOTS_PER_EPOCH;
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
    fixture.set_slot(opts.slot);

    let db = Arc::clone(&fixture.slashing_db);
    let client = Arc::clone(&fixture.beacon_client);
    let (fire_tx, fire_rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(PhaseState {
        spans: HashMap::new(),
        slot_started: None,
        fires: Vec::new(),
    }));
    let layer = PhaseLayer {
        state: Arc::clone(&state),
        fire_tx: Mutex::new(Some(fire_tx)),
        target_span: opts.fire_at.span_name(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let hold_sum_before = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_sum();
    let hold_n_before = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count();
    let admission_label = admission.label();
    let history_rows = payload.history_rows;
    let gvr = payload.gvr;
    let json = payload.json;

    let import_fut = async {
        let _ = fire_rx.await;
        let result = admission
            .admit(ImportRequest {
                interchange_json: &json,
                history_rows,
                slashing_db: &db,
                genesis_validators_root: gvr,
            })
            .await;
        (result, tokio::time::Instant::now())
    };
    tokio::pin!(import_fut);

    let run_fut = fixture.orchestrator.run();
    tokio::pin!(run_fut);
    let handle = &fixture.handle;
    let wall_started = std::time::Instant::now();
    let mut shutdown_sent = false;
    let mut budget_exceeded = false;
    let mut import_done: Option<(Result<(), AdmissionError>, tokio::time::Instant)> = None;

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
                if shutdown_sent {
                    continue;
                }
                let published = client
                    .submit_attestation_calls()
                    .iter()
                    .map(attestation_items)
                    .sum::<usize>();
                let import_finished = import_done.is_some();
                if import_finished && published >= opts.validators {
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
    let (import_result, import_finished_at) =
        import_done.ok_or("orchestrator stopped before the import finished")?;
    import_result.map_err(|err| format!("import_interchange: {err}"))?;

    let conn_hold_ms = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_sum() - hold_sum_before;
    let conn_hold_samples =
        RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count().saturating_sub(hold_n_before);
    if conn_hold_samples != 1 {
        return Err(format!(
            "expected one rvc_slashing_import_conn_hold_ms sample, got {conn_hold_samples}"
        ));
    }

    let phase_state = state.lock().expect("phase log");
    let slot_started =
        phase_state.slot_started.ok_or("block phase did not record time_into_slot")?;
    let hold_end = import_finished_at;
    let hold_start = hold_end
        .checked_sub(Duration::from_secs_f64((conn_hold_ms / 1000.0).max(0.0)))
        .unwrap_or(hold_end);
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

    let tally = tally_publishes(
        &client,
        slot_started,
        opts.request_delay,
        attestation_deadline_ms as f64,
        miss_after_ms,
    );
    if tally.items != opts.validators as u64 {
        return Err(format!("expected {} attestation items, got {}", opts.validators, tally.items));
    }

    let request_delay_ms =
        u64::try_from(opts.request_delay.as_millis()).map_err(|_| "request delay exceeds u64")?;

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
        attestation_deadline_ms,
        attestation_publish_budget_ms: ATTESTATION_PUBLISH_BUDGET_MS,
        attestation_deadline_misses: tally.misses,
        last_publish_ms_after_att_deadline: tally.last_publish_ms_after_att_deadline,
        attestation_items: tally.items,
        conn_hold_ms,
        conn_hold_samples,
        conn_hold_start_ms: offset_ms(slot_started, hold_start),
        conn_hold_end_ms: offset_ms(slot_started, hold_end),
        overlapping_phase,
        block_phase_overlapped,
        phase_fires,
    })
}
