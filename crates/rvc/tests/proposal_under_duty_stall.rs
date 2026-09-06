//! ARCH-7b / M1: missed-proposal rate under injected BN duty-fetch latency.
//!
//! Harness only — does **not** reorder the slot loop (ADR-004 / Phase 3 owns that).
//!
//! Strategy:
//! - BN mock with per-endpoint latency injection on **duty endpoints only**
//!   (`get_attester_duties`, `get_proposer_duties`, `post_sync_committee_duties`,
//!   `post_ptc_duties`).
//! - `get_block_root` and the separate block-production client stay fast so a
//!   miss is attributable to pre-proposal duty-fetch ordering.
//! - Deterministic [`MockSlotClock`] + `tokio` `start_paused` so multi-second
//!   stalls are virtual (not wall-clock flaky).
//! - Measure published proposals vs expected proposer-duty slots across
//!   [`MATRIX_SAMPLE_SLOTS`] (≥ plan “32 slots per condition”).
//!
//! # Two distinct “cache” axes (do not join casually)
//!
//! 1. **Duty-cache condition** (`warm_cache` / `cache_condition` on
//!    [`MissRateReport`]): whether `DutyTracker` attester/proposer/sync caches
//!    were pre-seeded before `run()`. This is the M1 axis — warm means the
//!    slot loop’s cache guards skip BN duty fetches, so duty-stall inject has
//!    no effect.
//! 2. **M2 offset label** (`cold_offset_samples` / `warm_offset_samples`):
//!    `rvc_slot_phase_block_start_offset_ms{cache=…}` from ARCH-7a. First slot
//!    after boot (and post-`key_gen`) is labelled `cold` even when the duty
//!    cache is pre-seeded. Multi-slot warm duty cells should show
//!    `warm_offset_samples >= n-1` once past the boot slot.
//!
//! Recording form of the RED finding: at 60 s duty stall with a cold duty
//! cache the miss rate is ~100 % (PB-A1). That number is handed to ARCH-7c;
//! this suite stays green by asserting only that a rate was measured (plus a
//! hard warm×stall contrast that the harness itself is sound).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    DependentRootResponse, ExecutionOptimisticResponse, PayloadAttestationDataResponse,
    ProduceBlockResponse as BnProduceBlockResponse, ProposerDutiesResponse, ProposerDuty,
    ProposerPreparation, PtcDutiesResponse, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
use block_service::{BeaconBlockClient, BlockServiceError, ProduceBlockResponse as BlockProdResp};
use bn_manager::{
    AttestationApi, AttestationSubmitter, BeaconNodeClient, BlockProducer, DutiesProvider,
    LivenessApi, MockBeaconNodeClient, NodeStatusApi, OperationTimeouts, PayloadAttestationApi,
    Propagator, SyncCommitteeApi,
};
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::{
    ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedValidatorRegistration, Slot,
};
use metrics::definitions::{slot_phase_cache, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS};
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle,
};
use signer::{always_enabled, CircuitBreakerState, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

// ── constants ────────────────────────────────────────────────────────────────

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const SLOT_DURATION: Duration = Duration::from_secs(12);
const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_INDEX: u64 = 1;
/// Plan ARCH-7b: ≥ 32 slots per matrix condition. Virtual under `start_paused`.
const MATRIX_SAMPLE_SLOTS: usize = 32;
/// First candidate slot (epoch 2, past the epoch-boundary slot 64).
const MATRIX_START_SLOT: Slot = 65;
/// Zero-root hex used for empty duty dependent roots (not a KAT / signing root).
const ZERO_DEPENDENT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// `n` proposal slots starting at [`MATRIX_START_SLOT`], **skipping epoch
/// boundaries** (`slot % 32 == 0`).
///
/// At epoch boundaries the orchestrator races builder registration against
/// `wait_for(next_slot)`. With `builder_service = None` the registration
/// future is immediately ready, so `select!` never sleeps and the slot loop
/// busy-spins — starving the harness driver under `current_thread`. Skipping
/// those slots keeps multi-slot runs deterministic without a full builder.
fn proposal_slots_sample(n: usize) -> Vec<Slot> {
    let mut slots = Vec::with_capacity(n);
    let mut slot = MATRIX_START_SLOT;
    while slots.len() < n {
        if !slot.is_multiple_of(SLOTS_PER_EPOCH) {
            slots.push(slot);
        }
        slot += 1;
    }
    slots
}

/// Global histogram counters are process-wide; serialize M1 cases so sample
/// deltas and publish counts are not raced by sibling tests.
async fn m1_harness_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

// ── miss-rate report ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct MissRateReport {
    #[allow(dead_code)] // retained for ARCH-7c baseline logging
    stall: Duration,
    /// Duty-cache condition (`"warm"` = pre-seeded, `"cold"` = empty at boot).
    /// Not the same as M2 `cache=` histogram labels — see module docs.
    cache_condition: &'static str,
    expected_proposals: usize,
    published: usize,
    /// M2 histogram deltas (boot/key_gen cold vs steady warm), not duty-cache.
    cold_offset_samples: u64,
    warm_offset_samples: u64,
}

impl MissRateReport {
    fn missed(&self) -> usize {
        self.expected_proposals.saturating_sub(self.published)
    }

    fn miss_rate(&self) -> f64 {
        if self.expected_proposals == 0 {
            return 0.0;
        }
        self.missed() as f64 / self.expected_proposals as f64
    }
}

// ── latency-injecting BN (duty endpoints only) ───────────────────────────────

/// Beacon mock that delays **only** the duty-fetch endpoints.
///
/// All other methods forward immediately so proposal submission and
/// `get_block_root` cannot inflate the measured miss rate.
struct DutyStallBeacon {
    inner: MockBeaconNodeClient,
    duty_stall: Duration,
}

impl DutyStallBeacon {
    async fn inject_duty_stall(&self) {
        if !self.duty_stall.is_zero() {
            tokio::time::sleep(self.duty_stall).await;
        }
    }
}

#[async_trait]
impl NodeStatusApi for DutyStallBeacon {
    async fn get_genesis(&self) -> Result<beacon::GenesisResponse, BeaconError> {
        self.inner.get_genesis().await
    }
    async fn get_config_spec(&self) -> Result<beacon::ConfigSpecResponse, BeaconError> {
        self.inner.get_config_spec().await
    }
    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.inner.get_fork_schedule().await
    }
    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.inner.get_fork(state_id).await
    }
    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.inner.get_validators(pubkeys).await
    }
    async fn get_block_root(
        &self,
        block_id: &str,
    ) -> Result<beacon::BlockRootResponse, BeaconError> {
        // Fast path: no stall. Fail so SlotContext.head_root is None and the
        // H-4 parent-root check stays inert (empty-slot 404 behaviour).
        self.inner.get_block_root(block_id).await
    }
    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.inner.get_node_syncing().await
    }
    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.inner.get_node_version().await
    }
}

#[async_trait]
impl DutiesProvider for DutyStallBeacon {
    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.inject_duty_stall().await;
        self.inner.get_attester_duties(epoch, validator_indices).await
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        self.inject_duty_stall().await;
        self.inner.get_proposer_duties(epoch, schedule).await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.inject_duty_stall().await;
        self.inner.post_sync_committee_duties(epoch, validator_indices).await
    }

    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError> {
        self.inject_duty_stall().await;
        self.inner.post_ptc_duties(epoch, validator_indices).await
    }
}

#[async_trait]
impl BlockProducer for DutyStallBeacon {
    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<BnProduceBlockResponse, BeaconError> {
        self.inner.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }
    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.inner.publish_block(signed_block, consensus_version).await
    }
    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.inner.publish_blinded_block(signed_blinded_block, consensus_version).await
    }
    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError> {
        self.inner.publish_block_ssz(ssz_bytes, consensus_version, is_blinded).await
    }
    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.inner.prepare_beacon_proposer(preparations).await
    }
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.inner.register_validators(registrations).await
    }
}

#[async_trait]
impl AttestationApi for DutyStallBeacon {
    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.inner.get_attestation_data(slot, committee_index).await
    }
    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        AttestationApi::submit_attestation(&self.inner, attestations).await
    }
    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.inner.get_aggregate_attestation(slot, attestation_data_root, committee_index).await
    }
    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        self.inner.submit_aggregate_and_proofs(proofs).await
    }
    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.inner.submit_beacon_committee_subscriptions(subscriptions).await
    }
}

#[async_trait]
impl PayloadAttestationApi for DutyStallBeacon {
    async fn get_payload_attestation_data(
        &self,
        slot: u64,
    ) -> Result<Option<PayloadAttestationDataResponse>, BeaconError> {
        self.inner.get_payload_attestation_data(slot).await
    }
    async fn submit_payload_attestations(
        &self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError> {
        self.inner.submit_payload_attestations(messages).await
    }
}

#[async_trait]
impl SyncCommitteeApi for DutyStallBeacon {
    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.inner.submit_sync_committee_messages(messages).await
    }
    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.inner
            .get_sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
            .await
    }
    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.inner.submit_contribution_and_proofs(proofs).await
    }
}

#[async_trait]
impl LivenessApi for DutyStallBeacon {
    async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        self.inner.post_validator_liveness(epoch, validator_indices).await
    }

    async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        self.inner.post_validator_liveness_merged(epoch, validator_indices).await
    }
}

impl BeaconNodeClient for DutyStallBeacon {}

// ── tracking block beacon (produce + publish) ────────────────────────────────

/// Returns a signable Deneb block for any slot and records successful publishes.
struct TrackingBlockBeacon {
    validator_index: u64,
    published_slots: Arc<Mutex<Vec<Slot>>>,
    produce_calls: Arc<AtomicUsize>,
}

impl TrackingBlockBeacon {
    fn new(validator_index: u64) -> Self {
        Self {
            validator_index,
            published_slots: Arc::new(Mutex::new(Vec::new())),
            produce_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn published_count(&self) -> usize {
        self.published_slots.lock().expect("published_slots lock").len()
    }

    fn published_slots(&self) -> Vec<Slot> {
        self.published_slots.lock().expect("published_slots lock").clone()
    }
}

#[async_trait]
impl BeaconBlockClient for TrackingBlockBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<BlockProdResp, BlockServiceError> {
        self.produce_calls.fetch_add(1, Ordering::SeqCst);
        let mut block = eth_types::external_vector_deneb_block();
        block.slot = slot;
        block.proposer_index = self.validator_index;
        // head_root is None in this harness (get_block_root fails fast), so
        // parent_root is not checked — leave fixture value.
        Ok(BlockProdResp {
            data: serde_json::to_value(&block)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("0".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        })
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.published_slots.lock().expect("published_slots lock").push(signed_block.message.slot);
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.published_slots.lock().expect("published_slots lock").push(signed_block.message.slot);
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        // Slot is little-endian u64 at offset 0 in BeaconBlock / BlockContents.
        let slot = if ssz_bytes.len() >= 8 {
            u64::from_le_bytes(ssz_bytes[0..8].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };
        self.published_slots.lock().expect("published_slots lock").push(slot);
        Ok(())
    }
}

// ── noop submitter ───────────────────────────────────────────────────────────

struct NoopSubmitter;

impl AttestationSubmitter for NoopSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── BN factory ───────────────────────────────────────────────────────────────

fn empty_attester_response() -> AttesterDutiesResponse {
    DependentRootResponse {
        dependent_root: ZERO_DEPENDENT.to_string(),
        execution_optimistic: false,
        data: vec![],
    }
}

fn empty_sync_response() -> SyncCommitteeDutiesResponse {
    ExecutionOptimisticResponse { execution_optimistic: false, data: vec![] }
}

fn proposer_response_for_slots(pubkey_hex: &str, slots: &[Slot]) -> ProposerDutiesResponse {
    DependentRootResponse {
        dependent_root: ZERO_DEPENDENT.to_string(),
        execution_optimistic: false,
        data: slots
            .iter()
            .map(|&slot| ProposerDuty {
                pubkey: pubkey_hex.to_string(),
                validator_index: VALIDATOR_INDEX.to_string(),
                slot: slot.to_string(),
            })
            .collect(),
    }
}

/// Build a duty-stall BN mock. Proposer duties cover every slot in each epoch
/// that overlaps `proposal_slots` so multi-slot runs stay assigned.
fn build_duty_stall_beacon(
    duty_stall: Duration,
    pubkey_hex: String,
    proposal_slots: Vec<Slot>,
) -> DutyStallBeacon {
    let proposal_slots = Arc::new(proposal_slots);
    let pk = pubkey_hex.clone();
    let slots_for_proposer = proposal_slots.clone();

    let inner = MockBeaconNodeClient::new()
        .with_get_block_root(|_block_id| {
            // Fail fast: SlotContext continues with head_root = None.
            Err(BeaconError::HttpError("harness: empty slot (no head)".to_string()))
        })
        .with_get_attester_duties(move |_epoch, _indices| Ok(empty_attester_response()))
        .with_get_proposer_duties(move |epoch| {
            let epoch_slots: Vec<Slot> = slots_for_proposer
                .iter()
                .copied()
                .filter(|s| s / SLOTS_PER_EPOCH == epoch)
                .collect();
            // Always return a cacheable response for the epoch (possibly empty).
            // When non-empty, duties are only for our proposal slots.
            if epoch_slots.is_empty() {
                // Still mark the epoch as having been fetched: empty data is fine
                // for non-proposal epochs (epoch+1 lookahead).
                Ok(proposer_response_for_slots(&pk, &[]))
            } else {
                Ok(proposer_response_for_slots(&pk, &epoch_slots))
            }
        })
        .with_post_sync_committee_duties(move |_epoch, _indices| Ok(empty_sync_response()))
        .with_prepare_beacon_proposer(|_p| Ok(()))
        .with_submit_beacon_committee_subscriptions(|_s| Ok(()));

    DutyStallBeacon { inner, duty_stall }
}

// ── orchestrator factory ─────────────────────────────────────────────────────

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

fn create_test_config(timeouts: OperationTimeouts) -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule()).with_timeouts(timeouts)
}

/// Default production-like duty_fetch (10 s). Other ops stay short for the harness.
fn harness_timeouts() -> OperationTimeouts {
    OperationTimeouts {
        duty_fetch: Duration::from_secs(10),
        block_production: Duration::from_secs(2),
        block_publication: Duration::from_secs(2),
        attestation_fetch: Duration::from_millis(50),
        attestation_submit: Duration::from_millis(50),
        aggregate_fetch: Duration::from_millis(50),
        aggregate_submit: Duration::from_millis(50),
        sync_message: Duration::from_millis(50),
        sync_contribution: Duration::from_millis(50),
        preparation: Duration::from_millis(50),
    }
}

struct HarnessParts {
    orchestrator: DutyOrchestrator<MockSlotClock, NoopSubmitter, TrackingBlockBeacon>,
    handle: OrchestratorHandle,
    clock: Arc<MockSlotClock>,
    block_beacon: Arc<TrackingBlockBeacon>,
    key_gen_tx: tokio::sync::watch::Sender<u64>,
}

async fn build_harness(
    duty_stall: Duration,
    proposal_slots: &[Slot],
    warm_cache: bool,
    pk: PublicKey,
    sk: SecretKey,
) -> HarnessParts {
    let pubkey_hex = format!("0x{}", hex::encode(pk.to_bytes()));
    let start_slot = proposal_slots[0];

    let beacon =
        Arc::new(build_duty_stall_beacon(duty_stall, pubkey_hex.clone(), proposal_slots.to_vec()));

    let duty_tracker = Arc::new(DutyTracker::new(
        beacon.clone() as Arc<dyn BeaconNodeClient>,
        vec!["1".to_string()],
    ));

    if warm_cache {
        // Duty-cache warm: pre-seed attester/proposer/sync so the slot loop's
        // cache guards skip BN duty fetches. Stall inject then has no effect
        // on those endpoints. (M2 offset label is still `cold` on the first
        // post-boot slot — that axis is independent; see module docs.)
        let mut epochs: Vec<u64> = proposal_slots.iter().map(|s| s / SLOTS_PER_EPOCH).collect();
        epochs.sort_unstable();
        epochs.dedup();
        // Lookahead epoch fetched every slot as well.
        if let Some(&last) = epochs.last() {
            epochs.push(last + 1);
        }
        for epoch in epochs {
            duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
            duty_tracker.fetch_proposer_duties(epoch).await.unwrap();
            let _ = duty_tracker.fetch_sync_committee_duties(epoch).await;
        }
    }

    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let block_beacon = Arc::new(TrackingBlockBeacon::new(VALIDATOR_INDEX));
    let propagator = Arc::new(Propagator::new(Arc::new(NoopSubmitter)));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pk.to_bytes()));
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let mut map = HashMap::new();
    map.insert(pk.to_bytes(), pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, SLOT_DURATION, SLOTS_PER_EPOCH));
    // Past 2/3 of the slot so attestation / aggregation waits are zero.
    clock.set_slot(start_slot);
    clock.advance_time(9);

    let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
        attesting_enabled: Arc::new(AtomicBool::new(false)),
        ..OrchestratorDeps::for_test(
            clock.clone(),
            duty_tracker,
            signer,
            propagator,
            beacon as Arc<dyn BeaconNodeClient>,
            block_beacon.clone(),
            None,
            validator_store,
            create_test_config(harness_timeouts()),
            pubkey_map,
        )
    });

    HarnessParts { orchestrator, handle, clock, block_beacon, key_gen_tx }
}

// ── drive_orchestrator ───────────────────────────────────────────────────────

/// Drive the orchestrator via bare `tokio::spawn` (ADR-002 regression pin).
/// Do not reintroduce a thread-local task scaffold (project-plan RP6).
async fn drive_orchestrator<C, S, B, F, Fut>(
    mut orchestrator: DutyOrchestrator<C, S, B>,
    handle: OrchestratorHandle,
    scenario: F,
) where
    C: timing::SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
    F: FnOnce(OrchestratorHandle) -> Fut,
    Fut: Future<Output = ()>,
{
    let run_task = tokio::spawn(async move {
        let _ = orchestrator.run().await;
    });
    scenario(handle).await;
    let _ = run_task.await;
}

fn histogram_count(cache: &str) -> u64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_count()
}

fn total_offset_samples() -> u64 {
    histogram_count(slot_phase_cache::COLD) + histogram_count(slot_phase_cache::WARM)
}

/// Wait until the M2 phase-block offset records `target` new samples (or budget).
///
/// Under `start_paused`, duty-fetch timeouts advance virtual time while both
/// the orchestrator and this waiter sleep — so a multi-second stall completes
/// without wall-clock delay. We shut down as soon as the sample lands so the
/// mock clock cannot re-enter the same slot after `wait_for(next)`.
async fn wait_for_offset_samples(before: u64, target_added: u64, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    while total_offset_samples() < before + target_added {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Allow produce→sign→publish to finish after the offset sample.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Drive `slots` one at a time: advance the mock clock, wait for one phase-0
/// offset sample, optionally fire `key_gen` before a slot.
async fn drive_proposal_slots(
    clock: Arc<MockSlotClock>,
    handle: OrchestratorHandle,
    slots: &[Slot],
    stall: Duration,
    mut before_slot: impl FnMut(usize, Slot),
) {
    // Worst case cold+stall: duty_fetch(10s) × 3 endpoints × 2 epochs + headroom.
    // Zero-stall budget must also cover `wait_for(next_slot)` (~3 s with
    // advance_time(9) on a 12 s slot) before the next mock-slot advance.
    let per_slot_budget =
        if stall.is_zero() { Duration::from_secs(10) } else { Duration::from_secs(90) };

    for (i, &slot) in slots.iter().enumerate() {
        before_slot(i, slot);
        if i > 0 {
            clock.set_slot(slot);
            clock.advance_time(9);
        }
        let samples_before = total_offset_samples();
        wait_for_offset_samples(samples_before, 1, per_slot_budget).await;
    }
    handle.shutdown();
    // Unblock orchestrator if it is in wait_for(next_slot).
    tokio::time::sleep(Duration::from_millis(20)).await;
}

async fn measure_miss_rate_under_stalled_duty_fetch(
    stall: Duration,
    warm_cache: bool,
    proposal_slots: &[Slot],
) -> MissRateReport {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let expected = proposal_slots.len();

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);

    let parts = build_harness(stall, proposal_slots, warm_cache, pk, sk).await;
    let clock = parts.clock.clone();
    let block_beacon = parts.block_beacon.clone();
    let slots = proposal_slots.to_vec();

    drive_orchestrator(parts.orchestrator, parts.handle, move |handle| {
        let clock = clock.clone();
        let slots = slots.clone();
        async move {
            drive_proposal_slots(clock, handle, &slots, stall, |_, _| {}).await;
        }
    })
    .await;

    let published = block_beacon.published_count();
    let cache_condition = if warm_cache { "warm" } else { "cold" };

    MissRateReport {
        stall,
        cache_condition,
        expected_proposals: expected,
        published,
        cold_offset_samples: histogram_count(slot_phase_cache::COLD) - cold_before,
        warm_offset_samples: histogram_count(slot_phase_cache::WARM) - warm_before,
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Recording form of the M1 RED baseline.
///
/// With a 60 s injected duty-fetch stall and a **cold duty cache**, the
/// pre-proposal `fetch_epoch_duties` path times out (10 s each) before
/// `maybe_propose_block`, so the proposer duty is never cached → **~100 %
/// miss** over [`MATRIX_SAMPLE_SLOTS`] slots. That failure is the finding
/// (PB-A1 / ADR-004 target); we record the rate rather than assert
/// `missed == 0` on the RED cell, so `develop` stays green (ADR-012).
///
/// Historical RED assertion (do not re-enable until Phase 3 lands):
/// `assert_eq!(red.missed(), 0)` — expected to fail with missed ≈ expected.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_records_missed_proposal_rate_under_stall() {
    let _guard = m1_harness_lock().await;

    // Matrix: stall ∈ {0s, 10s, 60s} × duty-cache ∈ {cold, warm}.
    // Plan: ≥ 32 slots per condition (MATRIX_SAMPLE_SLOTS).
    let proposal_slots = proposal_slots_sample(MATRIX_SAMPLE_SLOTS);
    let stalls = [Duration::ZERO, Duration::from_secs(10), Duration::from_secs(60)];
    let caches = [false, true]; // duty-cache cold, warm

    let mut reports = Vec::new();
    for &stall in &stalls {
        for &warm in &caches {
            let report =
                measure_miss_rate_under_stalled_duty_fetch(stall, warm, &proposal_slots).await;
            eprintln!(
                "ARCH-7b M1 cell (duty_cache={}, stall={}s, n={}): expected={} published={} \
                 missed={} miss_rate={:.1}% m2_offset_samples cold={} warm={}",
                report.cache_condition,
                report.stall.as_secs(),
                MATRIX_SAMPLE_SLOTS,
                report.expected_proposals,
                report.published,
                report.missed(),
                report.miss_rate() * 100.0,
                report.cold_offset_samples,
                report.warm_offset_samples,
            );
            assert_eq!(
                report.expected_proposals, MATRIX_SAMPLE_SLOTS,
                "each matrix cell must schedule MATRIX_SAMPLE_SLOTS proposal slots"
            );
            let rate = report.miss_rate();
            assert!((0.0..=1.0).contains(&rate), "miss rate must be in [0,1], got {rate}");
            reports.push(report);
        }
    }

    // RED baseline cell: cold duty-cache × 60 s — expected ~100 % miss pre-ADR-004.
    let red = reports
        .iter()
        .find(|r| r.cache_condition == "cold" && r.stall == Duration::from_secs(60))
        .expect("cold/60s cell");
    if red.missed() == red.expected_proposals {
        eprintln!(
            "ARCH-7b RED baseline: confirmed 100% miss under 60s duty stall \
             (cold duty-cache, n={}) — ADR-004 / Phase 3 target is 0%",
            MATRIX_SAMPLE_SLOTS
        );
    } else {
        eprintln!(
            "ARCH-7b RED baseline: miss_rate={:.1}% under 60s stall cold n={} \
             (not 100% — note for ARCH-7c)",
            red.miss_rate() * 100.0,
            MATRIX_SAMPLE_SLOTS
        );
    }

    // Contrast cell (F3): warm duty-cache × 60 s must fully publish — proves
    // the harness measures cache/ordering, not a broken produce path.
    let warm_stall = reports
        .iter()
        .find(|r| r.cache_condition == "warm" && r.stall == Duration::from_secs(60))
        .expect("warm/60s cell");
    assert_eq!(
        warm_stall.missed(),
        0,
        "warm duty-cache × 60s stall must publish all proposals (n={}); \
         published={} expected={}",
        MATRIX_SAMPLE_SLOTS,
        warm_stall.published,
        warm_stall.expected_proposals
    );
    // Multi-slot warm duty runs should also emit M2 warm offset samples after boot.
    assert!(
        warm_stall.warm_offset_samples >= 1,
        "n≥2 warm duty-cache run should record at least one M2 cache=warm offset sample; \
         cold={} warm={}",
        warm_stall.cold_offset_samples,
        warm_stall.warm_offset_samples
    );
}

/// Control: with 0 s injection the harness itself does not invent misses.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_no_missed_proposal_without_stall() {
    let _guard = m1_harness_lock().await;

    // Same sample size as the recording matrix so the control is a rate, not a coin-flip.
    let proposal_slots = proposal_slots_sample(MATRIX_SAMPLE_SLOTS);
    // Warm cache: propose from cache and fetch after. Cold 0s-stall slots
    // use the bounded pre-proposal fetch (ARCH-3j).
    let report =
        measure_miss_rate_under_stalled_duty_fetch(Duration::ZERO, true, &proposal_slots).await;

    eprintln!(
        "ARCH-7b M1 control (duty_cache=warm, stall=0s, n={}): expected={} published={} \
         missed={} miss_rate={:.1}%",
        MATRIX_SAMPLE_SLOTS,
        report.expected_proposals,
        report.published,
        report.missed(),
        report.miss_rate() * 100.0,
    );

    assert_eq!(
        report.missed(),
        0,
        "0s stall must yield zero missed proposals (harness measures ordering, not itself); \
         published={} expected={} report={:?}",
        report.published,
        report.expected_proposals,
        report
    );
    assert_eq!(report.published, report.expected_proposals);
    assert_eq!(report.expected_proposals, MATRIX_SAMPLE_SLOTS);
}

/// Cold-cache slots (post-boot and post-`key_gen`) are attributed separately
/// from warm steady-state slots (C6 / M2 `cache` label).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_cold_cache_slot_is_measured_separately() {
    let _guard = m1_harness_lock().await;

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    // Three consecutive mid-epoch slots: boot cold → warm → post-key_gen cold.
    let proposal_slots = [65u64, 66, 67];

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);

    let parts = build_harness(Duration::ZERO, &proposal_slots, false, pk, sk).await;
    let clock = parts.clock.clone();
    let key_gen_tx = parts.key_gen_tx.clone();
    let block_beacon = parts.block_beacon.clone();

    drive_orchestrator(parts.orchestrator, parts.handle, move |handle| {
        let clock = clock.clone();
        async move {
            drive_proposal_slots(clock, handle, &proposal_slots, Duration::ZERO, |i, _slot| {
                // Invalidate before slot 67 so that slot is labelled cache=cold.
                if i == 2 {
                    key_gen_tx.send_modify(|g| *g += 1);
                }
            })
            .await;
        }
    })
    .await;

    let cold_added = histogram_count(slot_phase_cache::COLD) - cold_before;
    let warm_added = histogram_count(slot_phase_cache::WARM) - warm_before;

    eprintln!(
        "ARCH-7b cold-vs-warm attribution: cold_offset_samples={} warm_offset_samples={} \
         published_slots={:?}",
        cold_added,
        warm_added,
        block_beacon.published_slots(),
    );

    assert!(
        warm_added >= 1,
        "steady-state slot after boot must be labelled cache=warm; warm_added={warm_added}"
    );
    assert!(
        cold_added >= 2,
        "post-boot and post-key_gen slots must both be cache=cold; cold_added={cold_added}"
    );

    // Cold-condition miss-rate sample is measured independently of warm.
    let cold_report = MissRateReport {
        stall: Duration::ZERO,
        cache_condition: "cold",
        expected_proposals: 2, // slots 65 and 67
        published: block_beacon.published_slots().iter().filter(|&&s| s == 65 || s == 67).count(),
        cold_offset_samples: cold_added,
        warm_offset_samples: warm_added,
    };
    let warm_report = MissRateReport {
        stall: Duration::ZERO,
        cache_condition: "warm",
        expected_proposals: 1, // slot 66
        published: block_beacon.published_slots().iter().filter(|&&s| s == 66).count(),
        cold_offset_samples: cold_added,
        warm_offset_samples: warm_added,
    };

    assert_eq!(
        cold_report.cache_condition, "cold",
        "cold condition label must be distinct from warm"
    );
    assert_ne!(cold_report.cache_condition, warm_report.cache_condition);
    assert_eq!(
        cold_report.published, 2,
        "cold boot and post-key_gen slots must still propose via the bounded fetch"
    );
    assert_eq!(warm_report.missed(), 0, "warm slot at 0s stall must not miss");
}
