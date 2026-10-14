//! Integration tests for ISSUE-2.7 (H-7): `sync_enabled` flag is independent
//! of `attesting_enabled`.
//!
//! These tests verify the full orchestrator workflow: the sync-committee
//! messages phase must obey `sync_enabled`, not `attesting_enabled`.  The
//! attestation phase continues to be gated by `attesting_enabled` only.
//!
//! Test strategy:
//! - Build a full `DutyOrchestrator` with a custom mock beacon (shared mock)
//!   that pre-seeds sync-committee duties and captures submitted sync messages.
//! - Set the mock slot clock to be past the 2/3-slot mark so all phase waits
//!   resolve immediately (zero wait for attestation window and 2/3 window).
//! - Run the orchestrator in a background task.
//! - For the "sync runs" test: wait on a oneshot channel that fires the moment
//!   the first sync-message batch is submitted.
//! - For the "sync disabled" test: sleep briefly, then assert no submissions.
//! - Signal shutdown to interrupt the "wait for next slot" sleep.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty, BeaconError,
    Checkpoint, ExecutionOptimisticResponse, SubmitAttestationResult, VersionedAttestation,
};
use block_service::{
    BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse as BlockProdResp,
};
use bn_manager::{
    AttestationSubmitter, BeaconNodeClient, MockBeaconNodeClient, MockMethod, Propagator,
};
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, Slot, SyncCommitteeDuty};
use rvc::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorDeps};
use signer::CircuitBreakerState;
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use tracing::field::{Field, Visit};
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;
use validator_store::{ValidatorConfig, ValidatorStore};

// ── constants ────────────────────────────────────────────────────────────────

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
/// Current slot for the integration clock. Slot 0's parent query is also
/// `"0"` (`saturating_sub`); a slot-aware stub with `head_slot = 0` 404s it.
const FIXTURE_SLOT: Slot = 1;

// ── test helpers ─────────────────────────────────────────────────────────────

fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 1],
        altair_fork_epoch: 10,
        altair_fork_version: [0, 0, 0, 2],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0, 0, 0, 3],
        capella_fork_epoch: 30,
        capella_fork_version: [0, 0, 0, 4],
        deneb_fork_epoch: 40,
        deneb_fork_version: [0, 0, 0, 5],
        electra_fork_epoch: 50,
        electra_fork_version: [0, 0, 0, 6],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0, 0, 0, 7],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0, 0, 0, 8],
    })
}

fn create_test_config() -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
}

// ── Sync test beacon (shared mock builder, RF4-24) ───────────────────────────
//
// A configurable MockBeaconNodeClient that:
//   - Serves a spec-honest block root: current slot 404s; parent and `"head"` resolve.
//   - Serves sync-committee duties for `duty_pubkey`.
//   - Captures any sync-committee message submissions via an AtomicUsize counter
//     and a oneshot channel (fires on the first submission).

fn sync_test_beacon(
    duty_pubkey: [u8; 48],
    submitted_count: Arc<AtomicUsize>,
    submitted_tx: tokio::sync::oneshot::Sender<()>,
    head_slot: Slot,
) -> MockBeaconNodeClient {
    let submitted_tx = Mutex::new(Some(submitted_tx));
    MockBeaconNodeClient::new()
        .with_slot_aware_block_root(head_slot, &[], |_queried| {
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
        })
        .with_post_sync_committee_duties(move |_epoch, _indices| {
            Ok(ExecutionOptimisticResponse {
                execution_optimistic: false,
                data: vec![SyncCommitteeDuty {
                    pubkey: duty_pubkey,
                    validator_index: 1,
                    validator_sync_committee_indices: vec![0],
                }],
            })
        })
        .with_submit_sync_committee_messages(move |messages| {
            submitted_count.fetch_add(messages.len(), Ordering::SeqCst);
            if let Some(tx) = submitted_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            Ok(())
        })
        .with_submit_contribution_and_proofs(|_proofs| Ok(()))
}

// ── NoopBlockBeacon ───────────────────────────────────────────────────────────

struct NoopBlockBeacon;

#[async_trait]
impl BeaconBlockClient for NoopBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<BlockProdResp, BlockServiceError> {
        Err(BlockServiceError::Beacon("noop".to_string()))
    }
    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<BlockProdResp, BlockServiceError> {
        Err(BlockServiceError::Beacon("noop".to_string()))
    }
    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }

    async fn publish_execution_payload_envelope(
        &self,
        _signed_envelope: &block_service::WireBody,
        _blobs: &block_service::WireBody,
        _kzg_proofs: &block_service::WireBody,
        _consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
}

// ── NoopSubmitter ─────────────────────────────────────────────────────────────

struct NoopSubmitter;

impl AttestationSubmitter for NoopSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<SubmitAttestationResult, BeaconError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── orchestrator factory ──────────────────────────────────────────────────────

async fn build_integration_orchestrator(
    beacon: Arc<dyn BeaconNodeClient>,
    _pk_hex: String,
    pk: crypto::PublicKey,
    sk: SecretKey,
    attesting_enabled: Arc<AtomicBool>,
) -> (
    DutyOrchestrator<MockSlotClock, NoopSubmitter, NoopBlockBeacon>,
    rvc::orchestrator::OrchestratorHandle,
) {
    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    // Upcast: wide object only.
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    // Pre-seed the sync-committee duty cache so the orchestrator doesn't need
    // to reach the BN for it inside run().
    duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

    let pk_bytes = pk.to_bytes();
    let mut map = HashMap::new();
    map.insert(pk_bytes, pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let propagator = Arc::new(Propagator::new(Arc::new(NoopSubmitter)));
    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed gate (Issue 2.11): the sync path skips any duty whose
    // validator is not signing-enabled in the store. The real VC registers loaded
    // validators at startup (ServiceBuilder::register_loaded_validators); this
    // harness bypasses that, so register the test validator (enabled) here —
    // otherwise the H-7 phase under test is suppressed before it can run.
    validator_store.add_validator(ValidatorConfig::new(pk_bytes)).unwrap();
    let config = create_test_config();

    // Set clock to 2/3 of FIXTURE_SLOT so all phase waits resolve immediately.
    // 12-second slot: slot 1 starts at genesis+12s, 2/3 at genesis+20s.
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_current_time(TEST_GENESIS_TIME + FIXTURE_SLOT * 12 + 8);

    let circuit_breaker = Arc::new(CircuitBreakerState::new(0, 0));

    DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker,
        attesting_enabled,
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon as Arc<dyn BeaconNodeClient>,
            Arc::new(NoopBlockBeacon),
            None,
            validator_store,
            config,
            pubkey_map,
        )
    })
}

// ── test cases ────────────────────────────────────────────────────────────────

/// H-7 integration test — `test_sync_runs_with_attesting_disabled`:
///
/// With `attesting_enabled = false` and `sync_enabled = true` (default),
/// the orchestrator must still produce sync-committee messages.
///
/// RED (before fix): sync messages skipped because they're inside the
///   `if attesting_enabled` guard → `submitted_tx` never fires → timeout.
/// GREEN (after fix): guard is split; `submitted_tx` fires promptly.
///
/// ADR-002 regression pin: bare `tokio::spawn` of `orchestrator.run()` proves
/// the future is `Send`. Do not reintroduce a thread-local task scaffold
/// (project-plan RP6).
#[tokio::test]
async fn test_sync_runs_with_attesting_disabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let submitted_count = Arc::new(AtomicUsize::new(0));
    let (submitted_tx, submitted_rx) = tokio::sync::oneshot::channel::<()>();

    let beacon = Arc::new(sync_test_beacon(
        pk.to_bytes(),
        submitted_count.clone(),
        submitted_tx,
        FIXTURE_SLOT,
    ));

    // attesting_enabled = false; sync_enabled = true (default)
    let attesting_enabled = Arc::new(AtomicBool::new(false));
    let (mut orchestrator, handle) =
        build_integration_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // sync_enabled defaults to true — no explicit call needed, but shown for clarity.

    // ADR-002 regression pin: bare tokio::spawn; do not reintroduce thread-local scaffold.
    let run_task = tokio::spawn(async move { orchestrator.run().await });

    // Wait for the sync submission notification, or bail after 5 s.
    // With the clock past 2/3 of FIXTURE_SLOT all phase waits are zero,
    // so this fires almost immediately after the task starts.
    let received = tokio::time::timeout(Duration::from_secs(5), submitted_rx).await;

    // Signal shutdown to interrupt the "wait for next slot" sleep.
    handle.shutdown();
    let _ = run_task.await;

    assert!(
        received.is_ok(),
        "H-7: sync messages must be produced even when attesting is disabled \
         (sync_enabled defaults to true)"
    );
    assert!(
        submitted_count.load(Ordering::SeqCst) > 0,
        "H-7: at least one sync message must have been submitted to the BN"
    );
}

/// H-7 integration test — `test_sync_disabled_attesting_enabled`:
///
/// With `attesting_enabled = true` and `sync_enabled = false` (explicit),
/// the orchestrator must NOT produce sync-committee messages.
///
/// RED (before fix): sync runs unconditionally → `submitted_count` > 0.
/// GREEN (after fix): `sync_enabled = false` guard prevents the call.
#[tokio::test]
async fn test_sync_disabled_attesting_enabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let submitted_count = Arc::new(AtomicUsize::new(0));
    // We don't use the rx side here; the sender is dropped with the beacon.
    let (submitted_tx, _submitted_rx) = tokio::sync::oneshot::channel::<()>();

    let beacon = Arc::new(sync_test_beacon(
        pk.to_bytes(),
        submitted_count.clone(),
        submitted_tx,
        FIXTURE_SLOT,
    ));

    // attesting_enabled = true; sync_enabled will be set to false below
    let attesting_enabled = Arc::new(AtomicBool::new(true));
    let (mut orchestrator, handle) =
        build_integration_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // Explicitly disable sync (the flag being tested).
    orchestrator.set_sync_enabled(false);

    // ADR-002 regression pin: bare tokio::spawn; do not reintroduce thread-local scaffold.
    let run_task = tokio::spawn(async move { orchestrator.run().await });

    // Give the orchestrator enough time to process the slot phases.
    // All waits are zero because the clock is past 2/3 of FIXTURE_SLOT, so
    // 300 ms is more than sufficient for the synchronous mock calls.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Snapshot the counter before shutdown to avoid a race.
    let count_after_phases = submitted_count.load(Ordering::SeqCst);

    // Shutdown interrupts the "wait for next slot" sleep.
    handle.shutdown();
    let _ = run_task.await;

    assert_eq!(
        count_after_phases, 0,
        "H-7: sync messages must NOT be produced when sync_enabled = false"
    );
}

// ── RR2-07: sync phase span opens with attestation ───────────────────────────

/// Longer than the 50 ms open bound, so a sync phase that still waits for the
/// last attestation is late under `tokio::time::pause`.
const ATTESTATION_FETCH_DELAY: Duration = Duration::from_millis(200);
const PHASE_ATTESTATION: &str = "slot.phase.attestation";
const PHASE_SYNC_MESSAGE: &str = "slot.phase.sync_message";

#[derive(Debug)]
struct OpenedSpan {
    name: String,
    parent_id: Option<Id>,
    /// `on_new_span` under the paused clock.
    opened_at: tokio::time::Instant,
    /// First `on_enter`. The phase is active here, which is when a span
    /// created in `run()` actually starts covering work.
    entered_at: Option<tokio::time::Instant>,
    time_into_slot: Option<u64>,
}

/// Span tree plus paused-clock open and enter instants.
struct HierarchyCapture {
    spans: Arc<Mutex<HashMap<u64, OpenedSpan>>>,
}

impl<S> Layer<S> for HierarchyCapture
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let parent_id = attrs.parent().cloned().or_else(|| ctx.current_span().id().cloned());
        self.spans.lock().expect("span map").insert(
            id.into_u64(),
            OpenedSpan {
                name: attrs.metadata().name().to_string(),
                parent_id,
                opened_at: tokio::time::Instant::now(),
                entered_at: None,
                time_into_slot: None,
            },
        );
    }

    fn on_enter(&self, id: &Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut spans = self.spans.lock().expect("span map");
        if let Some(span) = spans.get_mut(&id.into_u64()) {
            if span.entered_at.is_none() {
                span.entered_at = Some(tokio::time::Instant::now());
            }
        }
    }

    fn on_record(
        &self,
        id: &Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = TimeIntoSlotVisitor { value: None };
        values.record(&mut visitor);
        if let Some(value) = visitor.value {
            if let Some(span) = self.spans.lock().expect("span map").get_mut(&id.into_u64()) {
                span.time_into_slot = Some(value);
            }
        }
    }
}

struct TimeIntoSlotVisitor {
    value: Option<u64>,
}

impl Visit for TimeIntoSlotVisitor {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == observability::logging::fields::TIME_INTO_SLOT {
            self.value = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

fn only_span<'a>(spans: &'a HashMap<u64, OpenedSpan>, name: &str) -> &'a OpenedSpan {
    let hits: Vec<_> = spans.values().filter(|span| span.name == name).collect();
    assert_eq!(hits.len(), 1, "{name} must be created once, opened: {hits:?}");
    hits[0]
}

fn parent_name(spans: &HashMap<u64, OpenedSpan>, child: &OpenedSpan) -> Option<String> {
    let parent_id = child.parent_id.as_ref()?;
    spans.get(&parent_id.into_u64()).map(|parent| parent.name.clone())
}

fn attestation_data(slot: Slot) -> AttestationData {
    AttestationData {
        slot: slot.to_string(),
        index: "0".to_string(),
        beacon_block_root: format!("0x{}", "11".repeat(32)),
        source: Checkpoint { epoch: "0".to_string(), root: format!("0x{}", "22".repeat(32)) },
        target: Checkpoint { epoch: "0".to_string(), root: format!("0x{}", "33".repeat(32)) },
    }
}

fn attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "128".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: slot.to_string(),
    }
}

/// Same harness as the H-7 tests, with an attester duty whose
/// `get_attestation_data` sleeps [`ATTESTATION_FETCH_DELAY`] and the clock
/// already past the shared attestation/sync deadline.
async fn build_span_race_orchestrator(
    pk: crypto::PublicKey,
    sk: SecretKey,
) -> (
    DutyOrchestrator<MockSlotClock, NoopSubmitter, NoopBlockBeacon>,
    rvc::orchestrator::OrchestratorHandle,
) {
    let pubkey_hex = format!("0x{}", hex::encode(pk.to_bytes()));
    let duty_pk = pk.to_bytes();
    let slot = FIXTURE_SLOT;
    let data = attestation_data(slot);
    let duty = attester_duty(&pubkey_hex, slot);

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_slot_aware_block_root(slot, &[], |_queried| {
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            })
            .with_get_attester_duties(move |_epoch, _indices| {
                Ok(AttesterDutiesResponse {
                    dependent_root: format!("0x{}", "00".repeat(32)),
                    execution_optimistic: false,
                    data: vec![duty.clone()],
                })
            })
            .with_get_attestation_data(move |_slot, _committee| {
                Ok(AttestationDataResponse { data: data.clone() })
            })
            .with_method_delay(MockMethod::GetAttestationData, ATTESTATION_FETCH_DELAY)
            .with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: vec![SyncCommitteeDuty {
                        pubkey: duty_pk,
                        validator_index: 1,
                        validator_sync_committee_indices: vec![0],
                    }],
                })
            })
            .with_submit_sync_committee_messages(|_messages| Ok(()))
            .with_submit_contribution_and_proofs(|_proofs| Ok(())),
    );

    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    let epoch = slot / 32;
    duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    duty_tracker.fetch_sync_committee_duties(epoch).await.unwrap();

    let pk_bytes = pk.to_bytes();
    let mut map = HashMap::new();
    map.insert(pk_bytes, pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pk_bytes)).unwrap();

    // 4s into the 12s slot: past the 3,999 ms shared deadline, short of aggregate.
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot_with_offset_ms(slot, 4_000);

    let config = create_test_config()
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO);

    DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            Arc::new(Propagator::new(Arc::new(NoopSubmitter))),
            beacon,
            Arc::new(NoopBlockBeacon),
            None,
            validator_store,
            config,
            pubkey_map,
        )
    })
}

/// RR2-07: `slot.phase.sync_message` opens within 50 ms of
/// `slot.phase.attestation`.
///
/// The attestation data fetch sleeps 200 ms on the paused clock. A sync phase
/// that still runs after the last attestation, or that is only instrumented
/// with the attestation span, cannot satisfy the bound.
#[tokio::test(flavor = "current_thread")]
async fn sync_phase_span_opens_within_50ms_of_attestation_phase_span() {
    tokio::time::pause();

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (mut orchestrator, handle) = build_span_race_orchestrator(pk, sk).await;

    let spans = Arc::new(Mutex::new(HashMap::new()));
    let layer = HierarchyCapture { spans: spans.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let run_task = tokio::spawn(async move { orchestrator.run().await });

    let give_up = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let ready = {
            let map = spans.lock().expect("span map");
            let att = map.values().any(|span| span.name == PHASE_ATTESTATION);
            let sync = map
                .values()
                .any(|span| span.name == PHASE_SYNC_MESSAGE && span.entered_at.is_some());
            att && sync
        };
        if ready || tokio::time::Instant::now() >= give_up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    handle.shutdown();
    let _ = run_task.await;

    let map = spans.lock().expect("span map");
    let attestation = only_span(&map, PHASE_ATTESTATION);
    let sync = only_span(&map, PHASE_SYNC_MESSAGE);

    assert_eq!(
        parent_name(&map, sync).as_deref(),
        Some("slot.process"),
        "sync phase span is a child of slot.process, not the attestation span"
    );

    let open_gap = sync.opened_at.saturating_duration_since(attestation.opened_at);
    assert!(
        open_gap <= Duration::from_millis(50),
        "slot.phase.sync_message opened {open_gap:?} after slot.phase.attestation; bound is 50ms"
    );

    let att_entered = attestation.entered_at.expect("attestation phase span must be entered");
    let sync_entered = sync.entered_at.expect("sync phase span must be entered");
    let enter_gap = sync_entered.saturating_duration_since(att_entered);
    assert!(
        enter_gap <= Duration::from_millis(50),
        "slot.phase.sync_message entered {enter_gap:?} after slot.phase.attestation; \
         a sync phase that waits for the last attestation is later than 50ms \
         (attestation fetch delay is {ATTESTATION_FETCH_DELAY:?})"
    );

    let time_into_slot = sync
        .time_into_slot
        .expect("slot.phase.sync_message must record time_into_slot from the slot anchor");
    assert!(
        (4_000..=4_050).contains(&time_into_slot),
        "time_into_slot must be the anchor elapsed at the 4000ms wake, got {time_into_slot}"
    );
}
