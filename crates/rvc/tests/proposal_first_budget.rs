//! ARCH-3k: M1/M2 acceptance against the proposal-first slot loop.
//!
//! Does **not** reorder production code. Reuses the Phase-0 M1/M2 instrument
//! (`rvc_slot_phase_block_start_offset_ms` + duty-endpoint stall) and asserts
//! the ADR-004 / A-5 targets:
//!
//! - **M1** = 0 missed proposals with epoch duty fetches stalled 60 s (milestone)
//!   and 80 s (VD-35 envelope).
//! - **M2** p99 offset to `maybe_propose_block` ≤ 1_000 ms warm / ≤ 2_000 ms cold
//!   in three scenarios: warm, cold post-boot, cold after `key_gen`.
//!
//! Spec-honest [`MockBeaconNodeClient::with_slot_aware_block_root`] only (G-8).
//! Orchestrator is driven by a bare [`tokio::spawn`] (no `LocalSet`).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BuilderConfig, DependentRootResponse, ExecutionOptimisticResponse,
    PayloadAttestationDataResponse, ProduceBlockResponse as BnProduceBlockResponse,
    ProposerDutiesResponse, ProposerDuty, ProposerPreparation, PtcDutiesResponse,
    SignedContributionAndProof, StateForkResponse, SubmitAttestationResult,
    SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
    SyncingResponse, ValidatorLivenessResponse, ValidatorsResponse, VersionedAggregateAttestation,
    VersionedAttestation, VersionedSignedAggregateAndProof,
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
    SignedProposerPreferences, SignedValidatorRegistration, Slot,
};
use metrics::definitions::{slot_phase_cache, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS};
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle,
};
use signer::{always_enabled, CircuitBreakerState, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const SLOT_DURATION: Duration = Duration::from_secs(12);
const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_INDEX: u64 = 1;
const MATRIX_SAMPLE_SLOTS: usize = 32;
const MATRIX_START_SLOT: Slot = 65;
const ZERO_DEPENDENT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
/// Matches `eth_types::external_vector_deneb_block().parent_root` so H-4 accepts.
const PARENT_HEX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

const WARM_BUDGET_MS: f64 = 1_000.0;
const COLD_BUDGET_MS: f64 = 2_000.0;

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

async fn harness_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

#[derive(Debug, Clone, Copy)]
struct DutyStalls {
    attester: Duration,
    proposer: Duration,
    sync: Duration,
}

impl DutyStalls {
    fn all(stall: Duration) -> Self {
        Self { attester: stall, proposer: stall, sync: stall }
    }

    /// Epoch-fetch envelope (VD-35): attester + sync hang; proposer stays live
    /// so the ARCH-3j cold fetch can still learn a duty (C6).
    fn epoch_envelope(stall: Duration) -> Self {
        Self { attester: stall, proposer: Duration::ZERO, sync: stall }
    }

    fn none() -> Self {
        Self::all(Duration::ZERO)
    }

    fn max_secs(self) -> u64 {
        self.attester.max(self.proposer).max(self.sync).as_secs()
    }
}

#[derive(Debug, Clone)]
struct MissRateReport {
    stall_secs: u64,
    cache_condition: &'static str,
    expected_proposals: usize,
    published: usize,
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

struct DutyStallBeacon {
    inner: MockBeaconNodeClient,
    stalls: DutyStalls,
}

impl DutyStallBeacon {
    async fn inject(stall: Duration) {
        if !stall.is_zero() {
            tokio::time::sleep(stall).await;
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
        Self::inject(self.stalls.attester).await;
        self.inner.get_attester_duties(epoch, validator_indices).await
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        Self::inject(self.stalls.proposer).await;
        self.inner.get_proposer_duties(epoch, schedule).await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        Self::inject(self.stalls.sync).await;
        self.inner.post_sync_committee_duties(epoch, validator_indices).await
    }

    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError> {
        Self::inject(self.stalls.attester).await;
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
    async fn produce_block_v4(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<BnProduceBlockResponse, BeaconError> {
        self.inner.produce_block_v4(slot, randao_reveal, graffiti, builder_config).await
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
    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        self.inner.submit_proposer_preferences(preferences).await
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

struct TrackingBlockBeacon {
    validator_index: u64,
    published_slots: Arc<Mutex<Vec<Slot>>>,
}

impl TrackingBlockBeacon {
    fn new(validator_index: u64) -> Self {
        Self { validator_index, published_slots: Arc::new(Mutex::new(Vec::new())) }
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
        let mut block = eth_types::external_vector_deneb_block();
        block.slot = slot;
        block.proposer_index = self.validator_index;
        block.parent_root = [0x11; 32];
        Ok(BlockProdResp {
            data: serde_json::to_value(&block)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("0".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        })
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<BlockProdResp, BlockServiceError> {
        Err(BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
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
        let slot = if ssz_bytes.len() >= 8 {
            u64::from_le_bytes(ssz_bytes[0..8].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };
        self.published_slots.lock().expect("published_slots lock").push(slot);
        Ok(())
    }
}

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

fn build_duty_stall_beacon(
    stalls: DutyStalls,
    pubkey_hex: String,
    proposal_slots: Vec<Slot>,
) -> DutyStallBeacon {
    let proposal_slots = Arc::new(proposal_slots);
    let pk = pubkey_hex.clone();
    let slots_for_proposer = proposal_slots.clone();
    let head_slot = proposal_slots.first().copied().unwrap_or(MATRIX_START_SLOT);

    let inner = MockBeaconNodeClient::new()
        .with_slot_aware_block_root(head_slot, &[], |_queried| PARENT_HEX.to_string())
        .with_get_attester_duties(move |_epoch, _indices| Ok(empty_attester_response()))
        .with_get_proposer_duties(move |epoch| {
            let epoch_slots: Vec<Slot> = slots_for_proposer
                .iter()
                .copied()
                .filter(|s| s / SLOTS_PER_EPOCH == epoch)
                .collect();
            if epoch_slots.is_empty() {
                Ok(proposer_response_for_slots(&pk, &[]))
            } else {
                Ok(proposer_response_for_slots(&pk, &epoch_slots))
            }
        })
        .with_post_sync_committee_duties(move |_epoch, _indices| Ok(empty_sync_response()))
        .with_prepare_beacon_proposer(|_p| Ok(()))
        .with_submit_beacon_committee_subscriptions(|_s| Ok(()));

    DutyStallBeacon { inner, stalls }
}

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

struct BuildOpts<'a> {
    stalls: DutyStalls,
    proposal_slots: &'a [Slot],
    warm_cache: bool,
    at_slot_start: bool,
    pk: PublicKey,
    sk: SecretKey,
}

async fn build_harness(opts: BuildOpts<'_>) -> HarnessParts {
    let pubkey_hex = format!("0x{}", hex::encode(opts.pk.to_bytes()));
    let start_slot = opts.proposal_slots[0];

    let beacon = Arc::new(build_duty_stall_beacon(
        opts.stalls,
        pubkey_hex.clone(),
        opts.proposal_slots.to_vec(),
    ));

    let duty_tracker = Arc::new(DutyTracker::new(
        beacon.clone() as Arc<dyn BeaconNodeClient>,
        vec!["1".to_string()],
    ));

    if opts.warm_cache {
        let mut epochs: Vec<u64> =
            opts.proposal_slots.iter().map(|s| s / SLOTS_PER_EPOCH).collect();
        epochs.sort_unstable();
        epochs.dedup();
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
    km.insert(opts.sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let block_beacon = Arc::new(TrackingBlockBeacon::new(VALIDATOR_INDEX));
    let propagator = Arc::new(Propagator::new(Arc::new(NoopSubmitter)));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(opts.pk.to_bytes())).unwrap();
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let mut map = HashMap::new();
    map.insert(opts.pk.to_bytes(), opts.pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, SLOT_DURATION, SLOTS_PER_EPOCH));
    clock.set_slot(start_slot);
    if !opts.at_slot_start {
        clock.advance_time(9);
    }

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

async fn drive_orchestrator<C, S, B, F, Fut>(
    mut orchestrator: DutyOrchestrator<C, S, B>,
    handle: OrchestratorHandle,
    scenario: F,
) -> Fut::Output
where
    C: timing::SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
    F: FnOnce(OrchestratorHandle) -> Fut,
    Fut: Future,
{
    let run_task = tokio::spawn(async move {
        let _ = orchestrator.run().await;
    });
    let out = scenario(handle).await;
    let _ = run_task.await;
    out
}

fn histogram_count(cache: &str) -> u64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_count()
}

fn histogram_sum(cache: &str) -> f64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_sum()
}

fn total_offset_samples() -> u64 {
    histogram_count(slot_phase_cache::COLD) + histogram_count(slot_phase_cache::WARM)
}

async fn wait_for_offset_samples(before: u64, target_added: u64, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    while total_offset_samples() < before + target_added {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[derive(Debug, Clone)]
struct SlotOffset {
    cache: &'static str,
    offset_ms: f64,
}

async fn drive_proposal_slots(
    clock: Arc<MockSlotClock>,
    handle: OrchestratorHandle,
    slots: &[Slot],
    stall: DutyStalls,
    at_slot_start: bool,
    mut before_slot: impl FnMut(usize, Slot),
) -> Vec<SlotOffset> {
    let per_slot_budget =
        if stall.max_secs() == 0 { Duration::from_secs(20) } else { Duration::from_secs(90) };

    let mut offsets = Vec::with_capacity(slots.len());
    for (i, &slot) in slots.iter().enumerate() {
        before_slot(i, slot);
        if i > 0 {
            clock.set_slot(slot);
            if !at_slot_start {
                clock.advance_time(9);
            }
        }
        let cold_c = histogram_count(slot_phase_cache::COLD);
        let warm_c = histogram_count(slot_phase_cache::WARM);
        let cold_s = histogram_sum(slot_phase_cache::COLD);
        let warm_s = histogram_sum(slot_phase_cache::WARM);
        wait_for_offset_samples(cold_c + warm_c, 1, per_slot_budget).await;

        let cold_added = histogram_count(slot_phase_cache::COLD) - cold_c;
        let warm_added = histogram_count(slot_phase_cache::WARM) - warm_c;
        if cold_added > 0 {
            offsets.push(SlotOffset {
                cache: slot_phase_cache::COLD,
                offset_ms: (histogram_sum(slot_phase_cache::COLD) - cold_s) / cold_added as f64,
            });
        } else if warm_added > 0 {
            offsets.push(SlotOffset {
                cache: slot_phase_cache::WARM,
                offset_ms: (histogram_sum(slot_phase_cache::WARM) - warm_s) / warm_added as f64,
            });
        }
    }
    handle.shutdown();
    tokio::time::sleep(Duration::from_millis(20)).await;
    offsets
}

fn p99(values: &[f64]) -> f64 {
    assert!(!values.is_empty(), "p99 requires at least one offset sample");
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("offset is finite"));
    let rank = ((0.99 * sorted.len() as f64).ceil() as usize).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

fn summarize(values: &[f64]) -> (f64, f64, f64, f64) {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("offset is finite"));
    let min = sorted[0];
    let max = *sorted.last().expect("non-empty");
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    (min, mean, p99(&sorted), max)
}

async fn measure_miss_rate(
    stalls: DutyStalls,
    warm_cache: bool,
    proposal_slots: &[Slot],
) -> MissRateReport {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let expected = proposal_slots.len();

    let parts = build_harness(BuildOpts {
        stalls,
        proposal_slots,
        warm_cache,
        at_slot_start: false,
        pk,
        sk,
    })
    .await;
    let clock = parts.clock.clone();
    let block_beacon = parts.block_beacon.clone();
    let slots = proposal_slots.to_vec();

    drive_orchestrator(parts.orchestrator, parts.handle, move |handle| {
        let clock = clock.clone();
        let slots = slots.clone();
        async move {
            drive_proposal_slots(clock, handle, &slots, stalls, false, |_, _| {}).await;
        }
    })
    .await;

    MissRateReport {
        stall_secs: stalls.max_secs(),
        cache_condition: if warm_cache { "warm" } else { "cold" },
        expected_proposals: expected,
        published: block_beacon.published_count(),
    }
}

fn assert_zero_miss(report: &MissRateReport) {
    eprintln!(
        "ARCH-3k M1 cell (duty_cache={}, stall={}s, n={}): expected={} published={} \
         missed={} miss_rate={:.1}%",
        report.cache_condition,
        report.stall_secs,
        report.expected_proposals,
        report.expected_proposals,
        report.published,
        report.missed(),
        report.miss_rate() * 100.0,
    );
    assert_eq!(
        report.missed(),
        0,
        "M1 target is 0 missed proposals; duty_cache={} stall={}s published={} expected={}",
        report.cache_condition,
        report.stall_secs,
        report.published,
        report.expected_proposals
    );
}

/// All duty endpoints hang (warm cache) / epoch envelope hangs (cold); the
/// block is still proposed at 60 s and at the 80 s VD-35 envelope.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_proposal_survives_a_full_duty_fetch_stall() {
    let _guard = harness_lock().await;
    let proposal_slots = proposal_slots_sample(MATRIX_SAMPLE_SLOTS);
    let envelopes = [Duration::from_secs(60), Duration::from_secs(80)];

    for stall in envelopes {
        let warm = measure_miss_rate(DutyStalls::all(stall), true, &proposal_slots).await;
        assert_zero_miss(&warm);

        let cold =
            measure_miss_rate(DutyStalls::epoch_envelope(stall), false, &proposal_slots).await;
        assert_zero_miss(&cold);
        assert_eq!(
            cold.published, cold.expected_proposals,
            "cold cache must still propose when a duty exists (C6)"
        );
    }
}

/// Warm duty-cache, steady-state M2 `cache=warm` samples within 1_000 ms of
/// slot start (Phase-0 instrument, clock parked at slot start).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_phase_zero_offset_within_budget_warm() {
    let _guard = harness_lock().await;
    let proposal_slots = proposal_slots_sample(MATRIX_SAMPLE_SLOTS);
    let sk = SecretKey::generate();
    let pk = sk.public_key();

    let parts = build_harness(BuildOpts {
        stalls: DutyStalls::none(),
        proposal_slots: &proposal_slots,
        warm_cache: true,
        at_slot_start: true,
        pk,
        sk,
    })
    .await;
    let clock = parts.clock.clone();
    let block_beacon = parts.block_beacon.clone();
    let slots = proposal_slots.clone();

    let offsets = drive_orchestrator(parts.orchestrator, parts.handle, {
        let clock = clock.clone();
        let slots = slots.clone();
        move |handle| async move {
            drive_proposal_slots(clock, handle, &slots, DutyStalls::none(), true, |_, _| {}).await
        }
    })
    .await;

    let warm: Vec<f64> =
        offsets.iter().filter(|o| o.cache == slot_phase_cache::WARM).map(|o| o.offset_ms).collect();
    assert!(
        warm.len() >= MATRIX_SAMPLE_SLOTS - 1,
        "expected ≥{} warm M2 samples after the boot slot; got {} ({offsets:?})",
        MATRIX_SAMPLE_SLOTS - 1,
        warm.len()
    );
    let (min, mean, p99, max) = summarize(&warm);
    eprintln!(
        "ARCH-3k M2 warm (n={}, slot-start): min={min:.0} mean={mean:.0} p99={p99:.0} max={max:.0} \
         budget={WARM_BUDGET_MS:.0} published={}",
        warm.len(),
        block_beacon.published_count(),
    );
    assert!(
        p99 <= WARM_BUDGET_MS,
        "M2 warm p99 {p99} ms exceeds {WARM_BUDGET_MS} ms (min={min} mean={mean} max={max})"
    );
    assert_eq!(
        block_beacon.published_count(),
        MATRIX_SAMPLE_SLOTS,
        "warm scenario must publish every assigned slot; published_slots={:?}",
        block_beacon.published_slots()
    );
}

/// First slot after boot: M2 `cache=cold` p99 ≤ 2_000 ms, and a duty on the
/// BN is still proposed (C6).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_phase_zero_offset_within_budget_cold_after_boot() {
    let _guard = harness_lock().await;
    let mut offsets = Vec::with_capacity(MATRIX_SAMPLE_SLOTS);
    let mut published = 0usize;
    let mut slot = MATRIX_START_SLOT;

    while offsets.len() < MATRIX_SAMPLE_SLOTS {
        if slot.is_multiple_of(SLOTS_PER_EPOCH) {
            slot += 1;
            continue;
        }
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let slots = [slot];
        let parts = build_harness(BuildOpts {
            stalls: DutyStalls::none(),
            proposal_slots: &slots,
            warm_cache: false,
            at_slot_start: true,
            pk,
            sk,
        })
        .await;
        let clock = parts.clock.clone();
        let block_beacon = parts.block_beacon.clone();

        let run_offsets = drive_orchestrator(parts.orchestrator, parts.handle, {
            let clock = clock.clone();
            move |handle| async move {
                drive_proposal_slots(clock, handle, &slots, DutyStalls::none(), true, |_, _| {})
                    .await
            }
        })
        .await;

        published += block_beacon.published_count();
        offsets.extend(run_offsets.into_iter().filter(|o| o.cache == slot_phase_cache::COLD));
        slot += 1;
    }

    assert_eq!(
        offsets.len(),
        MATRIX_SAMPLE_SLOTS,
        "need {MATRIX_SAMPLE_SLOTS} cold-after-boot M2 samples"
    );
    let values: Vec<f64> = offsets.iter().map(|o| o.offset_ms).collect();
    let (min, mean, p99, max) = summarize(&values);
    eprintln!(
        "ARCH-3k M2 cold-after-boot (n={}, slot-start): min={min:.0} mean={mean:.0} p99={p99:.0} \
         max={max:.0} budget={COLD_BUDGET_MS:.0} published={published}",
        values.len(),
    );
    assert!(
        p99 <= COLD_BUDGET_MS,
        "M2 cold-after-boot p99 {p99} ms exceeds {COLD_BUDGET_MS} ms (min={min} mean={mean} max={max})"
    );
    assert_eq!(
        published, MATRIX_SAMPLE_SLOTS,
        "cold post-boot must propose when a duty exists (C6); published={published}"
    );
}

/// Slot after a `key_gen` cache clear: M2 `cache=cold` p99 ≤ 2_000 ms and
/// the duty is still proposed (C6).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_phase_zero_offset_within_budget_cold_after_key_gen() {
    let _guard = harness_lock().await;
    let proposal_slots = proposal_slots_sample(MATRIX_SAMPLE_SLOTS);
    let sk = SecretKey::generate();
    let pk = sk.public_key();

    let parts = build_harness(BuildOpts {
        stalls: DutyStalls::none(),
        proposal_slots: &proposal_slots,
        warm_cache: true,
        at_slot_start: true,
        pk,
        sk,
    })
    .await;
    let clock = parts.clock.clone();
    let key_gen_tx = parts.key_gen_tx.clone();
    let block_beacon = parts.block_beacon.clone();
    let slots = proposal_slots.clone();

    let offsets = drive_orchestrator(parts.orchestrator, parts.handle, {
        let clock = clock.clone();
        let slots = slots.clone();
        move |handle| async move {
            drive_proposal_slots(clock, handle, &slots, DutyStalls::none(), true, |i, _slot| {
                if i > 0 {
                    key_gen_tx.send_modify(|g| *g += 1);
                }
            })
            .await
        }
    })
    .await;

    let key_gen_cold: Vec<f64> = offsets
        .iter()
        .skip(1)
        .filter(|o| o.cache == slot_phase_cache::COLD)
        .map(|o| o.offset_ms)
        .collect();
    assert!(
        key_gen_cold.len() >= MATRIX_SAMPLE_SLOTS - 1,
        "expected ≥{} post-key_gen cold M2 samples; got {} ({offsets:?})",
        MATRIX_SAMPLE_SLOTS - 1,
        key_gen_cold.len()
    );
    let (min, mean, p99, max) = summarize(&key_gen_cold);
    eprintln!(
        "ARCH-3k M2 cold-after-key_gen (n={}, slot-start): min={min:.0} mean={mean:.0} p99={p99:.0} \
         max={max:.0} budget={COLD_BUDGET_MS:.0} published={}",
        key_gen_cold.len(),
        block_beacon.published_count(),
    );
    assert!(
        p99 <= COLD_BUDGET_MS,
        "M2 cold-after-key_gen p99 {p99} ms exceeds {COLD_BUDGET_MS} ms (min={min} mean={mean} max={max})"
    );
    assert_eq!(
        block_beacon.published_count(),
        MATRIX_SAMPLE_SLOTS,
        "post-key_gen slots must still propose when a duty exists (C6); published_slots={:?}",
        block_beacon.published_slots()
    );
}

/// Local G-8 pin: this harness must keep the slot-aware stub and must not
/// grow a dishonest block-root builder call (name ends in `_stub`, not `_root`).
#[test]
fn test_acceptance_harness_uses_a_slot_aware_block_root_stub() {
    let src = include_str!("proposal_first_budget.rs");
    assert!(
        src.contains("with_slot_aware_block_root("),
        "ARCH-3k acceptance harness must call with_slot_aware_block_root"
    );
    let needle = concat!("with_get_block", "_root(");
    let call_sites = src.matches(needle).count();
    assert_eq!(
        call_sites, 0,
        "ARCH-3k acceptance harness must not use the dishonest block-root builder"
    );
}
