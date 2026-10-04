//! Reusable pipeline harness for RF1-02 (slashing) and RF1-08 (key-import /
//! doppelganger gate).
//!
//! Wires: mock BN → duty tracker → SignerService → SlashingDb →
//! DutyOrchestrator, with knobs for attestation data, enablement, key-gen
//! watch channel, and whether a signing key is preloaded.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationData as BeaconAttestationData, AttesterDuty, BeaconError,
    Checkpoint as BeaconCheckpoint, DataResponse, ExecutionOptimisticResponse,
    SubmitAttestationResult, VersionedAggregateAttestation, VersionedAttestation,
};
use block_service::{
    BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse as BlockProdResp,
};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, MockBeaconNodeClient, Propagator};
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use duty_tracker::DutyTracker;
use eth_types::{
    Attestation as EthAttestation, AttestationData as EthAttestationData,
    Checkpoint as EthCheckpoint, ForkSchedule, Slot, SyncCommitteeDuty,
};
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle, PubkeyMap,
};
use signer::CircuitBreakerState;
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use tokio::sync::watch;
use validator_store::{ValidatorConfig, ValidatorStore};

// ── constants ────────────────────────────────────────────────────────────────

pub const TEST_GENESIS_TIME: u64 = 1_606_824_023;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const VALIDATOR_INDEX: &str = "1";
pub const COMMITTEE_INDEX: &str = "0";

/// Slot pair in the same epoch used for the double-vote / import scenarios.
pub const SLOT_A: Slot = 100; // epoch 3
pub const SLOT_B: Slot = 101; // epoch 3

// ── shared helpers ───────────────────────────────────────────────────────────

pub fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    // Electra at epoch 50 so slots 100/101 (epoch 3) stay on the pre-Electra
    // aggregation-bits path (matches other rvc integration tests).
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

pub fn create_test_config() -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
}

pub fn root_hex(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

/// Build beacon-API attestation data for `slot` with the given vote roots.
///
/// `target.epoch` is derived from `slot / 32` so M-2 validation passes.
pub fn make_beacon_attestation_data(
    slot: Slot,
    source_epoch: u64,
    source_root: u8,
    target_root: u8,
    head_root: u8,
) -> BeaconAttestationData {
    let target_epoch = slot / SLOTS_PER_EPOCH;
    BeaconAttestationData {
        slot: slot.to_string(),
        index: COMMITTEE_INDEX.to_string(),
        beacon_block_root: root_hex(head_root),
        source: BeaconCheckpoint { epoch: source_epoch.to_string(), root: root_hex(source_root) },
        target: BeaconCheckpoint { epoch: target_epoch.to_string(), root: root_hex(target_root) },
    }
}

pub fn make_attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: VALIDATOR_INDEX.to_string(),
        committee_index: COMMITTEE_INDEX.to_string(),
        committee_length: "4".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: slot.to_string(),
    }
}

// ── recording submitter (captures signatures) ────────────────────────────────

/// Counts submitted attestation batches and records how many signed objects
/// were included. Used to assert signature *absence* without relying on logs.
pub struct RecordingSubmitter {
    batch_count: AtomicUsize,
    signature_count: AtomicUsize,
}

impl RecordingSubmitter {
    pub fn new() -> Self {
        Self { batch_count: AtomicUsize::new(0), signature_count: AtomicUsize::new(0) }
    }

    pub fn batch_count(&self) -> usize {
        self.batch_count.load(Ordering::SeqCst)
    }

    pub fn signature_count(&self) -> usize {
        self.signature_count.load(Ordering::SeqCst)
    }
}

impl Default for RecordingSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationSubmitter for RecordingSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        let n = match attestations {
            VersionedAttestation::PreElectra(v) => v.len(),
            VersionedAttestation::Electra(v) => v.len(),
            VersionedAttestation::Fulu(v) => v.len(),
            VersionedAttestation::Gloas(v) => v.len(),
        };
        self.batch_count.fetch_add(1, Ordering::SeqCst);
        self.signature_count.fetch_add(n, Ordering::SeqCst);
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── mock block beacon ────────────────────────────────────────────────────────

pub struct NoopBlockBeacon;

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

// ── mock beacon with per-slot attestation data (shared mock, RF4-24) ─────────

/// One seeded validator registered when [`PipelineFixtureOpts::with_validators`]
/// requests more than one.
struct FixtureAttester {
    pubkey: PublicKey,
    pubkey_bytes: [u8; 48],
    pubkey_hex_0x: String,
    validator_index: String,
    committee_position: usize,
}

/// Duty identity captured by the N-validator mock. Strings only — the signing
/// key stays in the composite signer. `pubkey_bytes` is the sync-committee
/// duty key (`SyncCommitteeDuty::pubkey`).
struct BeaconAttester {
    pubkey_bytes: [u8; 48],
    pubkey_hex_0x: String,
    validator_index: String,
    committee_position: usize,
}

/// Control handle + shared state for the pipeline mock BN.
///
/// Mutable knobs (`set_duty_pubkey`, `set_attestation_data`) update Arc state
/// read by the [`MockBeaconNodeClient`] handlers built in [`Self::build_client`].
pub struct PipelineBeacon {
    duty_pubkey: Arc<Mutex<String>>,
    duty_slots: Arc<Vec<Slot>>,
    attestation_data_by_slot: Arc<Mutex<HashMap<Slot, BeaconAttestationData>>>,
    /// Empty for the single-validator fixture. Non-empty replaces the single
    /// `duty_pubkey` duty with one attester duty per identity per slot.
    attesters: Arc<Vec<BeaconAttester>>,
    /// Compressed pubkey of the single-validator fixture. Unused once
    /// `attesters` is non-empty.
    single_pubkey: [u8; 48],
    /// When set, `post_sync_committee_duties` returns one duty per validator.
    sync_committee: bool,
    /// When set, attester duties use a committee length that selects every
    /// validator as an aggregator, and the aggregate fetch/submit hooks are on.
    aggregators: bool,
}

impl PipelineBeacon {
    pub fn new(
        duty_pubkey: String,
        duty_slots: Vec<Slot>,
        attestation_data_by_slot: HashMap<Slot, BeaconAttestationData>,
    ) -> Self {
        Self {
            duty_pubkey: Arc::new(Mutex::new(duty_pubkey)),
            duty_slots: Arc::new(duty_slots),
            attestation_data_by_slot: Arc::new(Mutex::new(attestation_data_by_slot)),
            attesters: Arc::new(Vec::new()),
            single_pubkey: [0u8; 48],
            sync_committee: false,
            aggregators: false,
        }
    }

    fn with_attesters(mut self, attesters: Vec<BeaconAttester>) -> Self {
        self.attesters = Arc::new(attesters);
        self
    }

    fn with_duty_modes(
        mut self,
        single_pubkey: [u8; 48],
        sync_committee: bool,
        aggregators: bool,
    ) -> Self {
        self.single_pubkey = single_pubkey;
        self.sync_committee = sync_committee;
        self.aggregators = aggregators;
        self
    }

    /// Replace or insert attestation data for a slot (RF1-08 reuse knob).
    pub fn set_attestation_data(&self, slot: Slot, data: BeaconAttestationData) {
        self.attestation_data_by_slot.lock().unwrap().insert(slot, data);
    }

    /// Change the pubkey returned by subsequent `get_attester_duties` calls.
    ///
    /// Already-cached epoch entries in `DutyTracker` are **not** updated; a
    /// key-gen cache clear (or other invalidation) is required before the new
    /// identity appears in duty matching. Used by RF1-08 to model a stale
    /// pre-import duty set.
    pub fn set_duty_pubkey(&self, duty_pubkey: String) {
        *self.duty_pubkey.lock().unwrap() = duty_pubkey;
    }

    /// Build the shared configurable mock wired to this control state.
    pub fn build_client(&self) -> MockBeaconNodeClient {
        if !self.attesters.is_empty() {
            return self.build_n_client();
        }
        let duty_pubkey = Arc::clone(&self.duty_pubkey);
        let duty_slots = Arc::clone(&self.duty_slots);
        let att_map = Arc::clone(&self.attestation_data_by_slot);
        let head_slot = duty_slots.iter().copied().max().unwrap_or(0);
        let client = MockBeaconNodeClient::new()
            .with_slot_aware_block_root(head_slot, &[], |_queried| root_hex(0xbb))
            .with_get_attester_duties(move |epoch, _indices| {
                let duty_pubkey = duty_pubkey.lock().unwrap().clone();
                let data: Vec<AttesterDuty> = duty_slots
                    .iter()
                    .copied()
                    .filter(|s| s / SLOTS_PER_EPOCH == epoch)
                    .map(|s| make_attester_duty(&duty_pubkey, s))
                    .collect();
                Ok(beacon::DependentRootResponse {
                    dependent_root: root_hex(0xdd),
                    execution_optimistic: false,
                    data,
                })
            })
            .with_get_attestation_data(move |slot, _committee_index| {
                let map = att_map.lock().unwrap();
                let data = map.get(&slot).cloned().ok_or_else(|| {
                    BeaconError::HttpError(format!(
                        "no attestation data configured for slot {slot}"
                    ))
                })?;
                Ok(DataResponse { data })
            })
            .with_submit_sync_committee_messages(|_messages| Ok(()))
            .with_submit_contribution_and_proofs(|_proofs| Ok(()));
        self.finish_client(client)
    }

    /// N attester duties per duty slot. Committee length is N and each
    /// validator occupies a distinct in-range `validator_committee_index`,
    /// unless aggregators are on: then every validator is selected.
    fn build_n_client(&self) -> MockBeaconNodeClient {
        let attesters = Arc::clone(&self.attesters);
        let duty_slots = Arc::clone(&self.duty_slots);
        let att_map = Arc::clone(&self.attestation_data_by_slot);
        let head_slot = duty_slots.iter().copied().max().unwrap_or(0);
        // `committee_length / 16 == 0` makes `is_aggregator` true for every
        // selection proof. Length 1 also keeps `validator_committee_index` 0
        // inside the bitlist. The default (aggregators off) keeps length N.
        let force_aggregators = self.aggregators;
        let committee_length = if force_aggregators { 1 } else { attesters.len() };
        let client = MockBeaconNodeClient::new()
            .with_slot_aware_block_root(head_slot, &[], |_queried| root_hex(0xbb))
            .with_get_attester_duties(move |epoch, _indices| {
                let mut data = Vec::new();
                for &slot in duty_slots.iter() {
                    if slot / SLOTS_PER_EPOCH != epoch {
                        continue;
                    }
                    for attester in attesters.iter() {
                        data.push(AttesterDuty {
                            pubkey: attester.pubkey_hex_0x.clone(),
                            validator_index: attester.validator_index.clone(),
                            committee_index: COMMITTEE_INDEX.to_string(),
                            committee_length: committee_length.to_string(),
                            committees_at_slot: "1".to_string(),
                            validator_committee_index: if force_aggregators {
                                "0".to_string()
                            } else {
                                attester.committee_position.to_string()
                            },
                            slot: slot.to_string(),
                        });
                    }
                }
                Ok(beacon::DependentRootResponse {
                    dependent_root: root_hex(0xdd),
                    execution_optimistic: false,
                    data,
                })
            })
            .with_get_attestation_data(move |slot, _committee_index| {
                let map = att_map.lock().unwrap();
                let data = map.get(&slot).cloned().ok_or_else(|| {
                    BeaconError::HttpError(format!(
                        "no attestation data configured for slot {slot}"
                    ))
                })?;
                Ok(DataResponse { data })
            })
            .with_submit_sync_committee_messages(|_messages| Ok(()))
            .with_submit_contribution_and_proofs(|_proofs| Ok(()));
        self.finish_client(client)
    }

    /// Sync-committee duties and aggregator hooks. The sync *submit* handler
    /// above stays a submit hook; duties come from `post_sync_committee_duties`.
    fn finish_client(&self, mut client: MockBeaconNodeClient) -> MockBeaconNodeClient {
        if self.sync_committee {
            let duties = self.sync_committee_duties();
            client = client.with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: duties.clone(),
                })
            });
        }
        if self.aggregators {
            client = client
                .with_get_aggregate_attestation(|slot, _root, _committee_index, _fork| {
                    Ok(VersionedAggregateAttestation::PreElectra(pre_electra_aggregate(slot)))
                })
                .with_submit_aggregate_and_proofs(|_proofs| Ok(()));
        }
        client
    }

    fn sync_committee_duties(&self) -> Vec<SyncCommitteeDuty> {
        if self.attesters.is_empty() {
            return vec![SyncCommitteeDuty {
                pubkey: self.single_pubkey,
                validator_index: VALIDATOR_INDEX.parse().expect("validator index"),
                validator_sync_committee_indices: vec![0],
            }];
        }
        self.attesters
            .iter()
            .map(|attester| SyncCommitteeDuty {
                pubkey: attester.pubkey_bytes,
                validator_index: attester.committee_position as u64,
                validator_sync_committee_indices: vec![attester.committee_position as u64],
            })
            .collect()
    }
}

/// Pre-Electra aggregate returned when aggregators are on.
///
/// The fixture fork schedule puts Electra at epoch 50. Slots 100 and 101 are
/// epoch 3, so `AggregationService` expects this variant. The bitlist and
/// signature match the aggregation unit-test body that tree-hashes.
fn pre_electra_aggregate(slot: Slot) -> EthAttestation {
    EthAttestation {
        aggregation_bits: vec![0xff, 0x01],
        data: EthAttestationData {
            slot,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: EthCheckpoint { epoch: 0, root: [0u8; 32] },
            target: EthCheckpoint { epoch: 0, root: [0u8; 32] },
        },
        signature: vec![0xab; 96],
    }
}

// ── fixture options + fixture ────────────────────────────────────────────────

/// Knobs for [`pipeline_fixture`].
///
/// RF1-08 reuses these to inject a custom enablement gate, a real key-gen
/// watch channel, and an empty (import-ready) key set.
pub struct PipelineFixtureOpts {
    /// Attestation data the mock BN returns, keyed by duty slot.
    pub attestation_data_by_slot: HashMap<Slot, BeaconAttestationData>,
    /// Slots for which the mock BN returns attester duties.
    pub duty_slots: Vec<Slot>,
    /// Signing enablement (default: always enabled). RF1-08 plugs
    /// `ForwardWindowMachine` here.
    pub enablement: Arc<dyn SigningEnablement>,
    /// Optional pre-built slashing DB (e.g. a poisoned file-backed DB for the
    /// fail-closed DB-error test). When `None`, the single-validator fixture
    /// opens an in-memory DB. [`Self::with_validators`] with `n > 1` opens an
    /// on-disk DB with production PRAGMAs instead.
    pub slashing_db: Option<Arc<SlashingDb>>,
    /// Initial mock-clock slot. Updated by callers via [`PipelineFixture::set_slot`].
    pub initial_slot: Slot,
    /// When `Some`, the orchestrator uses this receiver instead of the discarded
    /// channel from [`OrchestratorDeps::for_test`]. Pair with a sender shared
    /// with `KeystoreManagerAdapter` (RF1-08).
    pub key_gen_rx: Option<watch::Receiver<u64>>,
    /// When `false`, start with an empty `CompositeSigner` + empty `PubkeyMap`
    /// and do not register the identity in `ValidatorStore`. The mock BN still
    /// serves duties for [`Self::duty_identity`]. Default `true` (RF1-02).
    pub preload_signing_key: bool,
    /// Public key identity for mock BN duties / hex fields. When `None`, a
    /// fresh key is generated. RF1-08 passes the key that will be imported.
    pub duty_identity: Option<PublicKey>,
}

impl Default for PipelineFixtureOpts {
    fn default() -> Self {
        Self {
            attestation_data_by_slot: HashMap::new(),
            duty_slots: vec![SLOT_A, SLOT_B],
            enablement: always_enabled(),
            slashing_db: None,
            initial_slot: SLOT_A,
            key_gen_rx: None,
            preload_signing_key: true,
            duty_identity: None,
        }
    }
}

/// [`PipelineFixtureOpts`] plus a validator count and optional duty modes.
///
/// The count is not a field of [`PipelineFixtureOpts`]: two existing literals
/// name every field, and a new field would stop those tests compiling.
/// [`PipelineFixtureOpts::with_validators`] sets it; passing opts alone is
/// one validator. Sync-committee and aggregator modes default to off and are
/// set with [`Self::with_sync_committee`] and [`Self::with_aggregators`].
pub struct PreparedPipelineFixture {
    opts: PipelineFixtureOpts,
    validator_count: usize,
    sync_committee: bool,
    aggregators: bool,
}

impl From<PipelineFixtureOpts> for PreparedPipelineFixture {
    fn from(opts: PipelineFixtureOpts) -> Self {
        Self { opts, validator_count: 1, sync_committee: false, aggregators: false }
    }
}

impl PipelineFixtureOpts {
    /// Register `n` local validators.
    ///
    /// `with_validators(1)` matches a plain [`PipelineFixtureOpts`] build.
    /// `n > 1` is seeded: two builds at the same `n` share one pubkey set.
    /// Sync-committee and aggregator modes stay off.
    pub fn with_validators(self, n: usize) -> PreparedPipelineFixture {
        PreparedPipelineFixture {
            opts: self,
            validator_count: n,
            sync_committee: false,
            aggregators: false,
        }
    }
}

impl PreparedPipelineFixture {
    /// Put every validator in the sync committee when `enabled`.
    ///
    /// Default is off. This does not change the sync-message submit hook.
    pub fn with_sync_committee(mut self, enabled: bool) -> Self {
        self.sync_committee = enabled;
        self
    }

    /// Make mock attester duties select every validator as an aggregator
    /// when `enabled`.
    ///
    /// Default is off. Selection is the committee length (`is_aggregator`
    /// modulo 1), not a second duty API.
    pub fn with_aggregators(mut self, enabled: bool) -> Self {
        self.aggregators = enabled;
        self
    }
}

/// Fully wired pipeline under test.
///
/// Holds the orchestrator plus the shared handles RF1-02/RF1-08 need to drive
/// slots and assert signatures / DB rows / duty-cache invalidation.
pub struct PipelineFixture {
    pub orchestrator: DutyOrchestrator<MockSlotClock, RecordingSubmitter, NoopBlockBeacon>,
    pub handle: OrchestratorHandle,
    pub clock: Arc<MockSlotClock>,
    pub slashing_db: Arc<SlashingDb>,
    pub submitter: Arc<RecordingSubmitter>,
    pub beacon: Arc<PipelineBeacon>,
    pub duty_tracker: Arc<DutyTracker>,
    pub pubkey_map: PubkeyMap,
    pub composite_signer: Arc<CompositeSigner>,
    pub validator_store: Arc<ValidatorStore>,
    pub pubkey: PublicKey,
    /// Lowercase hex **without** `0x` — matches `SlashingDb` / signer storage.
    pub pubkey_hex: String,
    /// `0x`-prefixed hex used in duty / pubkey_map keys.
    pub pubkey_hex_0x: String,
    /// Concrete mock behind [`Self::beacon`]. Submit counters live here.
    pub beacon_client: Arc<MockBeaconNodeClient>,
    /// Owns the on-disk slashing DB directory when more than one validator is
    /// requested and the caller did not pass [`PipelineFixtureOpts::slashing_db`].
    slashing_db_dir: Option<tempfile::TempDir>,
}

impl PipelineFixture {
    /// Path of the on-disk slashing database, when this fixture opened one.
    ///
    /// `None` for the single-validator in-memory database and when the caller
    /// supplied [`PipelineFixtureOpts::slashing_db`].
    pub fn slashing_db_path(&self) -> Option<std::path::PathBuf> {
        self.slashing_db_dir.as_ref().map(|dir| dir.path().join("slashing.sqlite"))
    }

    /// Advance the mock clock to `slot` (required before each `process_slot`).
    pub fn set_slot(&self, slot: Slot) {
        self.clock.set_slot(slot);
    }

    /// Convenience: set clock then call `process_slot`.
    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<rvc::orchestrator::AttestationResult>, rvc::orchestrator::OrchestratorError>
    {
        self.set_slot(slot);
        self.orchestrator.process_slot(slot).await
    }
}

/// Build a reusable pipeline harness: mock BN + duty tracker + signer with
/// slashing DB + `DutyOrchestrator`.
///
/// This is the RF1-02 / RF1-08 shared fixture contract — keep knobs on
/// [`PipelineFixtureOpts`], not inlined inside individual tests.
pub fn pipeline_fixture(opts: impl Into<PreparedPipelineFixture>) -> PipelineFixture {
    let PreparedPipelineFixture { opts, validator_count, sync_committee, aggregators } =
        opts.into();
    assert!(
        validator_count >= 1,
        "pipeline_fixture: validator_count must be >= 1, got {validator_count}"
    );
    if opts.preload_signing_key {
        // RF1-02 path: generate a local signing key and preload it into the
        // composite signer + pubkey_map + validator_store.
        assert!(
            opts.duty_identity.is_none(),
            "pipeline_fixture: preload_signing_key=true with duty_identity is unsupported \
             (PublicKey alone cannot load a signing key); use preload_signing_key=false \
             and import via KeystoreManagerAdapter"
        );
        if validator_count == 1 {
            let secret_key = SecretKey::generate();
            let pubkey = secret_key.public_key();
            let pubkey_hex = hex::encode(pubkey.to_bytes());
            let pubkey_hex_0x = format!("0x{pubkey_hex}");

            let mut key_manager = KeyManager::new();
            key_manager.insert(secret_key);
            let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

            finish_fixture(
                FixtureBuild { opts, sync_committee, aggregators },
                composite,
                pubkey,
                pubkey_hex,
                pubkey_hex_0x,
                true,
                Vec::new(),
            )
        } else {
            let seeded = seeded_attesters(validator_count);
            let first = &seeded[0];
            let pubkey = first.pubkey.clone();
            let pubkey_hex = hex::encode(first.pubkey_bytes);
            let pubkey_hex_0x = first.pubkey_hex_0x.clone();
            let mut key_manager = KeyManager::new();
            for bytes in seeded_secret_key_bytes(validator_count).iter() {
                let secret_key = SecretKey::from_bytes(bytes).expect("seeded BLS secret key");
                key_manager.insert(secret_key);
            }
            let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
            finish_fixture(
                FixtureBuild { opts, sync_committee, aggregators },
                composite,
                pubkey,
                pubkey_hex,
                pubkey_hex_0x,
                true,
                seeded,
            )
        }
    } else {
        // RF1-08 path: empty signer/map; mock BN serves duties for the
        // identity that the test will import.
        assert!(
            validator_count == 1,
            "pipeline_fixture: validator_count > 1 requires preload_signing_key=true"
        );
        let pubkey = opts
            .duty_identity
            .clone()
            .expect("pipeline_fixture: duty_identity is required when preload_signing_key=false");
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let pubkey_hex_0x = format!("0x{pubkey_hex}");
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));

        finish_fixture(
            FixtureBuild { opts, sync_committee, aggregators },
            composite,
            pubkey,
            pubkey_hex,
            pubkey_hex_0x,
            false,
            Vec::new(),
        )
    }
}

/// Opts plus the duty modes that must not be fields of [`PipelineFixtureOpts`].
struct FixtureBuild {
    opts: PipelineFixtureOpts,
    sync_committee: bool,
    aggregators: bool,
}

fn finish_fixture(
    build: FixtureBuild,
    composite: Arc<CompositeSigner>,
    pubkey: PublicKey,
    pubkey_hex: String,
    pubkey_hex_0x: String,
    preload: bool,
    seeded: Vec<FixtureAttester>,
) -> PipelineFixture {
    let FixtureBuild { opts, sync_committee, aggregators } = build;
    // An empty `seeded` vec is the single-validator constructor. N > 1 passes
    // one entry per validator, so the length is the count.
    let validator_count = if seeded.is_empty() { 1 } else { seeded.len() };
    let pubkey_bytes = pubkey.to_bytes();

    let (slashing_db, slashing_db_dir) = if let Some(db) = opts.slashing_db {
        (db, None)
    } else if validator_count > 1 {
        let (db, dir) = open_production_slashing_db();
        (db, Some(dir))
    } else {
        (Arc::new(SlashingDb::open_in_memory().expect("open in-memory slashing db")), None)
    };
    let signer = Arc::new(
        SignerService::new(Arc::clone(&composite), Arc::clone(&slashing_db))
            .with_enablement(opts.enablement),
    );

    let beacon_attesters: Vec<BeaconAttester> = seeded
        .iter()
        .map(|attester| BeaconAttester {
            pubkey_bytes: attester.pubkey_bytes,
            pubkey_hex_0x: attester.pubkey_hex_0x.clone(),
            validator_index: attester.validator_index.clone(),
            committee_position: attester.committee_position,
        })
        .collect();
    let mut beacon =
        PipelineBeacon::new(pubkey_hex_0x.clone(), opts.duty_slots, opts.attestation_data_by_slot)
            .with_duty_modes(pubkey_bytes, sync_committee, aggregators);
    if validator_count > 1 {
        beacon = beacon.with_attesters(beacon_attesters);
    }
    let beacon = Arc::new(beacon);
    let beacon_client = Arc::new(beacon.build_client());
    let beacon_node: Arc<dyn BeaconNodeClient> = beacon_client.clone();

    let indices = if validator_count == 1 {
        vec![VALIDATOR_INDEX.to_string()]
    } else {
        seeded.iter().map(|attester| attester.validator_index.clone()).collect()
    };
    let duty_tracker = Arc::new(DutyTracker::new(Arc::clone(&beacon_node), indices));

    let submitter = Arc::new(RecordingSubmitter::new());
    let propagator = Arc::new(Propagator::new(Arc::clone(&submitter) as Arc<RecordingSubmitter>));

    let mut map = HashMap::new();
    if preload && validator_count == 1 {
        map.insert(pubkey_bytes, pubkey.clone());
    } else if preload {
        for attester in &seeded {
            map.insert(attester.pubkey_bytes, attester.pubkey.clone());
        }
    }
    let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(map));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the validator as signing-enabled so duties
    // are not dropped by the post-import store gate (unless import path starts empty).
    if preload && validator_count == 1 {
        validator_store.add_validator(ValidatorConfig::new(pubkey_bytes)).unwrap();
    } else if preload {
        for attester in &seeded {
            validator_store.add_validator(ValidatorConfig::new(attester.pubkey_bytes)).unwrap();
        }
    }

    let clock =
        Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), SLOTS_PER_EPOCH));
    clock.set_slot(opts.initial_slot);

    let config = create_test_config();
    let circuit_breaker = Arc::new(CircuitBreakerState::new(0, 0));
    let attesting_enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let mut deps = OrchestratorDeps::for_test(
        Arc::clone(&clock),
        Arc::clone(&duty_tracker),
        signer,
        propagator,
        beacon_node,
        Arc::new(NoopBlockBeacon),
        None,
        Arc::clone(&validator_store),
        config,
        Arc::clone(&pubkey_map),
    );
    if let Some(key_gen_rx) = opts.key_gen_rx {
        deps.key_gen_rx = key_gen_rx;
    }
    deps.circuit_breaker = circuit_breaker;
    deps.attesting_enabled = attesting_enabled;

    let (orchestrator, handle) = DutyOrchestrator::new(deps);

    PipelineFixture {
        orchestrator,
        handle,
        clock,
        slashing_db,
        submitter,
        beacon,
        duty_tracker,
        pubkey_map,
        composite_signer: composite,
        validator_store,
        pubkey,
        pubkey_hex,
        pubkey_hex_0x,
        beacon_client,
        slashing_db_dir,
    }
}

/// Domain tag mixed into the per-validator seed (`b"RVC0"`).
const SEEDED_KEY_DOMAIN: &[u8; 4] = b"RVC0";

/// 32-byte seed for validator `index` in an N-key set.
///
/// Bytes 0..4 are [`SEEDED_KEY_DOMAIN`], 4..12 are `n` little-endian, and
/// 12..20 are `index` little-endian. The same `(n, index)` always yields the
/// same seed, so two builds at one N share a pubkey set.
fn seed_for_validator(n: usize, index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(SEEDED_KEY_DOMAIN);
    seed[4..12].copy_from_slice(&(n as u64).to_le_bytes());
    seed[12..20].copy_from_slice(&(index as u64).to_le_bytes());
    seed
}

type SeededKeyBytes = Arc<Vec<[u8; 32]>>;
type SeededKeyCache = HashMap<usize, SeededKeyBytes>;

fn seeded_secret_key_bytes(n: usize) -> SeededKeyBytes {
    static CACHE: OnceLock<Mutex<SeededKeyCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().expect("seeded key cache");
    if let Some(hit) = guard.get(&n) {
        return Arc::clone(hit);
    }
    let generated = Arc::new(generate_seeded_secret_bytes(n));
    guard.insert(n, Arc::clone(&generated));
    generated
}

#[allow(clippy::disallowed_methods)] // Gate 1: cache seeded fixture key bytes; never logged
fn generate_seeded_secret_bytes(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|index| {
            let secret = crypto::eip2333::derive_master_sk(&seed_for_validator(n, index))
                .expect("derive seeded BLS key");
            secret.to_bytes()
        })
        .collect()
}

fn seeded_attesters(n: usize) -> Vec<FixtureAttester> {
    seeded_secret_key_bytes(n)
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let secret_key = SecretKey::from_bytes(bytes).expect("seeded BLS secret key");
            let pubkey = secret_key.public_key();
            let pubkey_bytes = pubkey.to_bytes();
            let pubkey_hex_0x = format!("0x{}", hex::encode(pubkey_bytes));
            FixtureAttester {
                pubkey,
                pubkey_bytes,
                pubkey_hex_0x,
                validator_index: index.to_string(),
                committee_position: index,
            }
        })
        .collect()
}

fn open_production_slashing_db() -> (Arc<SlashingDb>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("slashing db tempdir");
    let path = dir.path().join("slashing.sqlite");
    let db = Arc::new(SlashingDb::open(&path).expect("open on-disk slashing db"));
    (db, dir)
}

/// Default double-vote attestation data: same target epoch, different roots.
pub fn double_vote_attestation_map() -> HashMap<Slot, BeaconAttestationData> {
    let mut map = HashMap::new();
    // First vote: source=2, target=3 (epoch of slot 100), roots A.
    map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    // Conflicting vote: same target epoch 3, different source + target root.
    map.insert(SLOT_B, make_beacon_attestation_data(SLOT_B, 1, 0x44, 0x55, 0x66));
    map
}

/// Open a file-backed `SlashingDb`, then drop the `attestations` table via a
/// second connection so subsequent stage queries fail with a database error.
pub fn open_poisoned_slashing_db(path: &std::path::Path) -> Arc<SlashingDb> {
    let db = Arc::new(SlashingDb::open(path).expect("open file-backed slashing db"));
    // Poison while the SlashingDb connection is idle (mutex free). The next
    // stage_* call's SELECT against `attestations`/`watermarks` fails closed.
    {
        let conn = rusqlite::Connection::open(path).expect("second connection for poison");
        conn.execute_batch(
            "DROP TABLE IF EXISTS attestations;
             DROP TABLE IF EXISTS watermarks;
             DROP TABLE IF EXISTS blocks;",
        )
        .expect("drop slashing tables");
    }
    db
}
