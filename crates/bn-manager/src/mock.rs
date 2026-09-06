//! Shared configurable mock for [`crate::BeaconNodeClient`].
//!
//! Gated by `cfg(any(test, feature = "test-utils"))`. Errors by default for
//! every method; override per method with the `with_*` builders. Call arguments
//! are captured for assertions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BlockRootData, BlockRootResponse, BuilderConfig, ConfigSpecResponse, GenesisResponse,
    PayloadAttestationDataResponse, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, PtcDutiesResponse, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
use eth_types::{
    ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedProposerPreferences, SignedValidatorRegistration, Slot,
};

use crate::traits::{
    AttestationApi, BeaconNodeClient, BlockProducer, DutiesProvider, LivenessApi, NodeStatusApi,
    PayloadAttestationApi, SyncCommitteeApi,
};

type Handler<A, R> = Arc<dyn Fn(A) -> Result<R, BeaconError> + Send + Sync>;

/// Same variant `BeaconClient` surfaces for HTTP 404 (`GET .../blocks/{block_id}/root`).
fn block_root_not_found() -> BeaconError {
    BeaconError::ApiError { status: 404, message: "Block not found".to_string() }
}

struct MethodHook<A, R> {
    handler: Mutex<Option<Handler<A, R>>>,
    calls: Mutex<Vec<A>>,
}

impl<A, R> Default for MethodHook<A, R> {
    fn default() -> Self {
        Self { handler: Mutex::new(None), calls: Mutex::new(Vec::new()) }
    }
}

impl<A: Clone, R> MethodHook<A, R> {
    fn invoke(&self, method: &'static str, args: A) -> Result<R, BeaconError> {
        self.calls.lock().expect("mock call log poisoned").push(args.clone());
        match self.handler.lock().expect("mock handler poisoned").as_ref() {
            Some(h) => h(args),
            None => Err(BeaconError::HttpError(format!(
                "MockBeaconNodeClient: {method} not configured"
            ))),
        }
    }

    fn set_handler(&self, f: Handler<A, R>) {
        *self.handler.lock().expect("mock handler poisoned") = Some(f);
    }

    fn calls(&self) -> Vec<A> {
        self.calls.lock().expect("mock call log poisoned").clone()
    }
}

/// Erroring-by-default mock implementing all role traits and [`BeaconNodeClient`].
///
/// Configure responses with `with_*` builders; inspect captured arguments with
/// `*_calls` accessors.
#[derive(Default)]
pub struct MockBeaconNodeClient {
    // NodeStatusApi
    get_genesis: MethodHook<(), GenesisResponse>,
    get_config_spec: MethodHook<(), ConfigSpecResponse>,
    get_fork_schedule: MethodHook<(), ForkSchedule>,
    get_fork: MethodHook<String, StateForkResponse>,
    get_validators: MethodHook<Vec<String>, ValidatorsResponse>,
    get_block_root: MethodHook<String, BlockRootResponse>,
    get_node_syncing: MethodHook<(), SyncingResponse>,
    get_node_version: MethodHook<(), String>,
    // DutiesProvider
    get_attester_duties: MethodHook<(u64, Vec<String>), AttesterDutiesResponse>,
    get_proposer_duties: MethodHook<u64, ProposerDutiesResponse>,
    post_sync_committee_duties: MethodHook<(u64, Vec<String>), SyncCommitteeDutiesResponse>,
    post_ptc_duties: MethodHook<(u64, Vec<String>), PtcDutiesResponse>,
    // BlockProducer
    produce_block_v3: MethodHook<(u64, String, Option<String>, Option<u64>), ProduceBlockResponse>,
    produce_block_v4:
        MethodHook<(u64, String, Option<String>, BuilderConfig), ProduceBlockResponse>,
    publish_block: MethodHook<(SignedBeaconBlock, String), ()>,
    publish_blinded_block: MethodHook<(SignedBlindedBeaconBlock, String), ()>,
    publish_block_ssz: MethodHook<(Vec<u8>, String, bool), ()>,
    prepare_beacon_proposer: MethodHook<Vec<ProposerPreparation>, ()>,
    register_validators: MethodHook<Vec<SignedValidatorRegistration>, ()>,
    submit_proposer_preferences: MethodHook<Vec<SignedProposerPreferences>, ()>,
    // AttestationApi
    get_attestation_data: MethodHook<(u64, u64), AttestationDataResponse>,
    submit_attestation: MethodHook<VersionedAttestation, SubmitAttestationResult>,
    get_aggregate_attestation:
        MethodHook<(u64, String, Option<u64>), VersionedAggregateAttestation>,
    submit_aggregate_and_proofs: MethodHook<VersionedSignedAggregateAndProof, ()>,
    submit_beacon_committee_subscriptions: MethodHook<Vec<BeaconCommitteeSubscription>, ()>,
    // PayloadAttestationApi
    get_payload_attestation_data: MethodHook<u64, Option<PayloadAttestationDataResponse>>,
    submit_payload_attestations: MethodHook<Vec<PayloadAttestationMessage>, ()>,
    // SyncCommitteeApi
    submit_sync_committee_messages: MethodHook<Vec<SyncCommitteeMessage>, ()>,
    get_sync_committee_contribution:
        MethodHook<(u64, u64, String), SyncCommitteeContributionResponse>,
    submit_contribution_and_proofs: MethodHook<Vec<SignedContributionAndProof>, ()>,
    // LivenessApi
    post_validator_liveness: MethodHook<(u64, Vec<String>), ValidatorLivenessResponse>,
}

impl MockBeaconNodeClient {
    pub fn new() -> Self {
        Self::default()
    }

    // -- NodeStatusApi builders --

    pub fn with_get_genesis(
        self,
        f: impl Fn() -> Result<GenesisResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_genesis.set_handler(Arc::new(move |()| f()));
        self
    }

    pub fn with_get_config_spec(
        self,
        f: impl Fn() -> Result<ConfigSpecResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_config_spec.set_handler(Arc::new(move |()| f()));
        self
    }

    pub fn with_get_fork_schedule(
        self,
        f: impl Fn() -> Result<ForkSchedule, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_fork_schedule.set_handler(Arc::new(move |()| f()));
        self
    }

    pub fn with_get_fork(
        self,
        f: impl Fn(String) -> Result<StateForkResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_fork.set_handler(Arc::new(f));
        self
    }

    pub fn with_get_validators(
        self,
        f: impl Fn(Vec<String>) -> Result<ValidatorsResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_validators.set_handler(Arc::new(f));
        self
    }

    pub fn with_get_block_root(
        self,
        f: impl Fn(String) -> Result<BlockRootResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_block_root.set_handler(Arc::new(f));
        self
    }

    /// Spec-honest block-root stub: `block_id` values that name a slot at or after
    /// `head_slot` answer `404` the way a conformant BN does (beacon-APIs
    /// `blocks/{block_id}/root`); `"head"`, `"finalized"` and slots <= head resolve
    /// to `root_for(slot)`. Skipped slots named in `skipped` also 404.
    pub fn with_slot_aware_block_root(
        self,
        head_slot: Slot,
        skipped: &[Slot],
        root_for: impl Fn(Option<Slot>) -> String + Send + Sync + 'static,
    ) -> Self {
        let skipped = skipped.to_vec();
        self.get_block_root.set_handler(Arc::new(move |block_id: String| {
            let slot = if block_id == "head" || block_id == "finalized" {
                None
            } else {
                let parsed = block_id.parse::<Slot>().map_err(|_| block_root_not_found())?;
                if parsed >= head_slot || skipped.contains(&parsed) {
                    return Err(block_root_not_found());
                }
                Some(parsed)
            };
            Ok(BlockRootResponse { data: BlockRootData { root: root_for(slot) } })
        }));
        self
    }

    pub fn with_get_node_syncing(
        self,
        f: impl Fn() -> Result<SyncingResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_node_syncing.set_handler(Arc::new(move |()| f()));
        self
    }

    pub fn with_get_node_version(
        self,
        f: impl Fn() -> Result<String, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_node_version.set_handler(Arc::new(move |()| f()));
        self
    }

    // -- DutiesProvider builders --

    pub fn with_get_attester_duties(
        self,
        f: impl Fn(u64, Vec<String>) -> Result<AttesterDutiesResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_attester_duties.set_handler(Arc::new(move |(epoch, indices)| f(epoch, indices)));
        self
    }

    pub fn with_get_proposer_duties(
        self,
        f: impl Fn(u64) -> Result<ProposerDutiesResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_proposer_duties.set_handler(Arc::new(f));
        self
    }

    pub fn with_post_sync_committee_duties(
        self,
        f: impl Fn(u64, Vec<String>) -> Result<SyncCommitteeDutiesResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.post_sync_committee_duties
            .set_handler(Arc::new(move |(epoch, indices)| f(epoch, indices)));
        self
    }

    pub fn with_post_ptc_duties(
        self,
        f: impl Fn(u64, Vec<String>) -> Result<PtcDutiesResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.post_ptc_duties.set_handler(Arc::new(move |(epoch, indices)| f(epoch, indices)));
        self
    }

    // -- BlockProducer builders --

    pub fn with_produce_block_v3(
        self,
        f: impl Fn(
                u64,
                String,
                Option<String>,
                Option<u64>,
            ) -> Result<ProduceBlockResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.produce_block_v3.set_handler(Arc::new(move |(slot, randao, graffiti, boost)| {
            f(slot, randao, graffiti, boost)
        }));
        self
    }

    pub fn with_produce_block_v4(
        self,
        f: impl Fn(
                u64,
                String,
                Option<String>,
                BuilderConfig,
            ) -> Result<ProduceBlockResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.produce_block_v4.set_handler(Arc::new(move |(slot, randao, graffiti, config)| {
            f(slot, randao, graffiti, config)
        }));
        self
    }

    pub fn with_publish_block(
        self,
        f: impl Fn(SignedBeaconBlock, String) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.publish_block.set_handler(Arc::new(move |(block, version)| f(block, version)));
        self
    }

    pub fn with_publish_blinded_block(
        self,
        f: impl Fn(SignedBlindedBeaconBlock, String) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.publish_blinded_block.set_handler(Arc::new(move |(block, version)| f(block, version)));
        self
    }

    pub fn with_publish_block_ssz(
        self,
        f: impl Fn(Vec<u8>, String, bool) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.publish_block_ssz
            .set_handler(Arc::new(move |(bytes, version, blinded)| f(bytes, version, blinded)));
        self
    }

    pub fn with_prepare_beacon_proposer(
        self,
        f: impl Fn(Vec<ProposerPreparation>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.prepare_beacon_proposer.set_handler(Arc::new(f));
        self
    }

    pub fn with_register_validators(
        self,
        f: impl Fn(Vec<SignedValidatorRegistration>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.register_validators.set_handler(Arc::new(f));
        self
    }

    pub fn with_submit_proposer_preferences(
        self,
        f: impl Fn(Vec<SignedProposerPreferences>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_proposer_preferences.set_handler(Arc::new(f));
        self
    }

    // -- AttestationApi builders --

    pub fn with_get_attestation_data(
        self,
        f: impl Fn(u64, u64) -> Result<AttestationDataResponse, BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_attestation_data
            .set_handler(Arc::new(move |(slot, committee_index)| f(slot, committee_index)));
        self
    }

    pub fn with_submit_attestation(
        self,
        f: impl Fn(VersionedAttestation) -> Result<SubmitAttestationResult, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.submit_attestation.set_handler(Arc::new(f));
        self
    }

    pub fn with_get_aggregate_attestation(
        self,
        f: impl Fn(u64, String, Option<u64>) -> Result<VersionedAggregateAttestation, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_aggregate_attestation
            .set_handler(Arc::new(move |(slot, root, idx)| f(slot, root, idx)));
        self
    }

    pub fn with_submit_aggregate_and_proofs(
        self,
        f: impl Fn(VersionedSignedAggregateAndProof) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_aggregate_and_proofs.set_handler(Arc::new(f));
        self
    }

    pub fn with_submit_beacon_committee_subscriptions(
        self,
        f: impl Fn(Vec<BeaconCommitteeSubscription>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_beacon_committee_subscriptions.set_handler(Arc::new(f));
        self
    }

    // -- PayloadAttestationApi builders --

    pub fn with_get_payload_attestation_data(
        self,
        f: impl Fn(u64) -> Result<Option<PayloadAttestationDataResponse>, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_payload_attestation_data.set_handler(Arc::new(f));
        self
    }

    pub fn with_submit_payload_attestations(
        self,
        f: impl Fn(Vec<PayloadAttestationMessage>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_payload_attestations.set_handler(Arc::new(f));
        self
    }

    // -- SyncCommitteeApi builders --

    pub fn with_submit_sync_committee_messages(
        self,
        f: impl Fn(Vec<SyncCommitteeMessage>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_sync_committee_messages.set_handler(Arc::new(f));
        self
    }

    pub fn with_get_sync_committee_contribution(
        self,
        f: impl Fn(u64, u64, String) -> Result<SyncCommitteeContributionResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_sync_committee_contribution
            .set_handler(Arc::new(move |(slot, sub, root)| f(slot, sub, root)));
        self
    }

    pub fn with_submit_contribution_and_proofs(
        self,
        f: impl Fn(Vec<SignedContributionAndProof>) -> Result<(), BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.submit_contribution_and_proofs.set_handler(Arc::new(f));
        self
    }

    // -- LivenessApi builders --

    pub fn with_post_validator_liveness(
        self,
        f: impl Fn(u64, Vec<String>) -> Result<ValidatorLivenessResponse, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.post_validator_liveness
            .set_handler(Arc::new(move |(epoch, indices)| f(epoch, indices)));
        self
    }

    // -- Call capture accessors --

    pub fn get_genesis_calls(&self) -> usize {
        self.get_genesis.calls().len()
    }

    pub fn get_attester_duties_calls(&self) -> Vec<(u64, Vec<String>)> {
        self.get_attester_duties.calls()
    }

    pub fn get_proposer_duties_calls(&self) -> Vec<u64> {
        self.get_proposer_duties.calls()
    }

    pub fn post_ptc_duties_calls(&self) -> Vec<(u64, Vec<String>)> {
        self.post_ptc_duties.calls()
    }

    pub fn post_validator_liveness_calls(&self) -> Vec<(u64, Vec<String>)> {
        self.post_validator_liveness.calls()
    }

    pub fn prepare_beacon_proposer_calls(&self) -> Vec<Vec<ProposerPreparation>> {
        self.prepare_beacon_proposer.calls()
    }

    pub fn register_validators_calls(&self) -> Vec<Vec<SignedValidatorRegistration>> {
        self.register_validators.calls()
    }

    pub fn submit_proposer_preferences_calls(&self) -> Vec<Vec<SignedProposerPreferences>> {
        self.submit_proposer_preferences.calls()
    }

    pub fn get_block_root_calls(&self) -> Vec<String> {
        self.get_block_root.calls()
    }

    pub fn get_fork_calls(&self) -> Vec<String> {
        self.get_fork.calls()
    }

    pub fn get_attestation_data_calls(&self) -> Vec<(u64, u64)> {
        self.get_attestation_data.calls()
    }

    pub fn get_payload_attestation_data_calls(&self) -> Vec<u64> {
        self.get_payload_attestation_data.calls()
    }

    pub fn submit_payload_attestations_calls(&self) -> Vec<Vec<PayloadAttestationMessage>> {
        self.submit_payload_attestations.calls()
    }

    pub fn produce_block_v3_calls(&self) -> Vec<(u64, String, Option<String>, Option<u64>)> {
        self.produce_block_v3.calls()
    }

    pub fn produce_block_v4_calls(&self) -> Vec<(u64, String, Option<String>, BuilderConfig)> {
        self.produce_block_v4.calls()
    }

    pub fn submit_sync_committee_messages_calls(&self) -> Vec<Vec<SyncCommitteeMessage>> {
        self.submit_sync_committee_messages.calls()
    }

    pub fn submit_attestation_calls(&self) -> Vec<VersionedAttestation> {
        self.submit_attestation.calls()
    }
}

// ---------------------------------------------------------------------------
// Role trait impls
// ---------------------------------------------------------------------------

#[async_trait]
impl NodeStatusApi for MockBeaconNodeClient {
    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.get_genesis.invoke("get_genesis", ())
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.get_config_spec.invoke("get_config_spec", ())
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.get_fork_schedule.invoke("get_fork_schedule", ())
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.get_fork.invoke("get_fork", state_id.to_string())
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.get_validators.invoke("get_validators", pubkeys.to_vec())
    }

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.get_block_root.invoke("get_block_root", block_id.to_string())
    }

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.get_node_syncing.invoke("get_node_syncing", ())
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.get_node_version.invoke("get_node_version", ())
    }
}

#[async_trait]
impl DutiesProvider for MockBeaconNodeClient {
    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.get_attester_duties.invoke("get_attester_duties", (epoch, validator_indices.to_vec()))
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        _schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        self.get_proposer_duties.invoke("get_proposer_duties", epoch)
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.post_sync_committee_duties
            .invoke("post_sync_committee_duties", (epoch, validator_indices.to_vec()))
    }

    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError> {
        self.post_ptc_duties.invoke("post_ptc_duties", (epoch, validator_indices.to_vec()))
    }
}

#[async_trait]
impl BlockProducer for MockBeaconNodeClient {
    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.produce_block_v3.invoke(
            "produce_block_v3",
            (slot, randao_reveal.to_string(), graffiti.map(str::to_string), builder_boost_factor),
        )
    }

    async fn produce_block_v4(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.produce_block_v4.invoke(
            "produce_block_v4",
            (slot, randao_reveal.to_string(), graffiti.map(str::to_string), builder_config.clone()),
        )
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.publish_block
            .invoke("publish_block", (signed_block.clone(), consensus_version.to_string()))
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.publish_blinded_block.invoke(
            "publish_blinded_block",
            (signed_blinded_block.clone(), consensus_version.to_string()),
        )
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError> {
        self.publish_block_ssz.invoke(
            "publish_block_ssz",
            (ssz_bytes.to_vec(), consensus_version.to_string(), is_blinded),
        )
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.prepare_beacon_proposer.invoke("prepare_beacon_proposer", preparations.to_vec())
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.register_validators.invoke("register_validators", registrations.to_vec())
    }

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        self.submit_proposer_preferences.invoke("submit_proposer_preferences", preferences.to_vec())
    }
}

#[async_trait]
impl AttestationApi for MockBeaconNodeClient {
    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.get_attestation_data.invoke("get_attestation_data", (slot, committee_index))
    }

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.submit_attestation.invoke("submit_attestation", attestations.clone())
    }

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.get_aggregate_attestation.invoke(
            "get_aggregate_attestation",
            (slot, attestation_data_root.to_string(), committee_index),
        )
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        self.submit_aggregate_and_proofs.invoke("submit_aggregate_and_proofs", proofs.clone())
    }

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.submit_beacon_committee_subscriptions
            .invoke("submit_beacon_committee_subscriptions", subscriptions.to_vec())
    }
}

#[async_trait]
impl PayloadAttestationApi for MockBeaconNodeClient {
    async fn get_payload_attestation_data(
        &self,
        slot: u64,
    ) -> Result<Option<PayloadAttestationDataResponse>, BeaconError> {
        self.get_payload_attestation_data.invoke("get_payload_attestation_data", slot)
    }

    async fn submit_payload_attestations(
        &self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError> {
        self.submit_payload_attestations.invoke("submit_payload_attestations", messages.to_vec())
    }
}

#[async_trait]
impl SyncCommitteeApi for MockBeaconNodeClient {
    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.submit_sync_committee_messages
            .invoke("submit_sync_committee_messages", messages.to_vec())
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.get_sync_committee_contribution.invoke(
            "get_sync_committee_contribution",
            (slot, subcommittee_index, beacon_block_root.to_string()),
        )
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.submit_contribution_and_proofs
            .invoke("submit_contribution_and_proofs", proofs.to_vec())
    }
}

#[async_trait]
impl LivenessApi for MockBeaconNodeClient {
    async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        self.post_validator_liveness
            .invoke("post_validator_liveness", (epoch, validator_indices.to_vec()))
    }

    async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        // Single-source mock: merge is a self-delegation so existing
        // `with_post_validator_liveness` fixtures keep working.
        self.post_validator_liveness(epoch, validator_indices).await
    }
}

impl BeaconNodeClient for MockBeaconNodeClient {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_mock_errors_by_default_for_unconfigured_methods() {
        let mock = MockBeaconNodeClient::new();
        let err = mock.get_genesis().await.unwrap_err();
        match err {
            BeaconError::HttpError(msg) => {
                assert!(msg.contains("get_genesis"), "unexpected message: {msg}");
                assert!(msg.contains("not configured"), "unexpected message: {msg}");
            }
            other => panic!("expected HttpError, got {other:?}"),
        }
        let err = mock.get_attester_duties(1, &["0".into()]).await.unwrap_err();
        assert!(matches!(err, BeaconError::HttpError(_)));
        let err = mock.post_validator_liveness(2, &["1".into()]).await.unwrap_err();
        assert!(matches!(err, BeaconError::HttpError(_)));
        let err = mock.submit_proposer_preferences(&[]).await.unwrap_err();
        match err {
            BeaconError::HttpError(msg) => {
                assert!(msg.contains("submit_proposer_preferences"), "unexpected message: {msg}");
            }
            other => panic!("expected HttpError, got {other:?}"),
        }
        let err = mock
            .produce_block_v4(1, "0xrandao", None, &BuilderConfig::default())
            .await
            .unwrap_err();
        match err {
            BeaconError::HttpError(msg) => {
                assert!(msg.contains("produce_block_v4"), "unexpected message: {msg}");
            }
            other => panic!("expected HttpError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_shared_mock_submit_proposer_preferences_captures() {
        let mock = MockBeaconNodeClient::new().with_submit_proposer_preferences(|_prefs| Ok(()));
        let prefs = vec![SignedProposerPreferences {
            message: eth_types::ProposerPreferences {
                dependent_root: [0x33; 32],
                proposal_slot: 32,
                validator_index: 3,
                fee_recipient: [0x44; 20],
                target_gas_limit: 36_000_000,
            },
            signature: vec![0xaa; 96],
        }];
        mock.submit_proposer_preferences(&prefs).await.unwrap();
        assert_eq!(mock.submit_proposer_preferences_calls(), vec![prefs]);
    }

    #[tokio::test]
    async fn test_shared_mock_produce_block_v4_captures() {
        let mock =
            MockBeaconNodeClient::new().with_produce_block_v4(|_slot, _randao, _graffiti, _cfg| {
                Ok(ProduceBlockResponse {
                    data: serde_json::Value::Null,
                    is_blinded: false,
                    consensus_version: "gloas".to_string(),
                    execution_payload_value: None,
                    is_ssz: false,
                    ssz_bytes: None,
                })
            });
        let cfg = BuilderConfig::default();
        mock.produce_block_v4(7, "0xrandao", Some("0xgraf"), &cfg).await.unwrap();
        assert_eq!(
            mock.produce_block_v4_calls(),
            vec![(7, "0xrandao".to_string(), Some("0xgraf".to_string()), cfg)]
        );
    }

    #[tokio::test]
    async fn test_shared_mock_captures_call_arguments() {
        let mock = MockBeaconNodeClient::new().with_get_attester_duties(|epoch, _indices| {
            Ok(AttesterDutiesResponse {
                dependent_root: format!("0x{epoch}"),
                execution_optimistic: false,
                data: vec![],
            })
        });

        let indices = vec!["42".into(), "7".into()];
        let resp = mock.get_attester_duties(99, &indices).await.unwrap();
        assert_eq!(resp.dependent_root, "0x99");

        let calls = mock.get_attester_duties_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 99);
        assert_eq!(calls[0].1, indices);

        // Unconfigured methods still error and capture
        let _ = mock.get_fork("head").await;
        assert_eq!(mock.get_fork_calls(), vec!["head".to_string()]);
    }

    #[tokio::test]
    async fn test_shared_mock_as_dyn_beacon_node_client() {
        let mock: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new().with_get_node_version(|| Ok("MockBeacon/v0.0.0".into())),
        );
        assert_eq!(mock.get_node_version().await.unwrap(), "MockBeacon/v0.0.0");
        let err = mock.get_genesis().await.unwrap_err();
        assert!(matches!(err, BeaconError::HttpError(_)));
    }

    fn slot_aware_mock(head_slot: Slot, skipped: &[Slot]) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_slot_aware_block_root(
            head_slot,
            skipped,
            |slot| match slot {
                Some(s) => format!("0xslot{s}"),
                None => "0xnamed".to_string(),
            },
        )
    }

    fn assert_block_not_found(err: BeaconError) {
        match err {
            BeaconError::ApiError { status: 404, .. } => {}
            other => panic!("expected ApiError 404, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_slot_aware_stub_404s_a_slot_at_head() {
        let mock = slot_aware_mock(100, &[]);
        assert_block_not_found(mock.get_block_root("100").await.unwrap_err());
    }

    #[tokio::test]
    async fn test_slot_aware_stub_resolves_a_past_slot() {
        let mock = slot_aware_mock(100, &[]);
        let resp = mock.get_block_root("99").await.expect("past slot must resolve");
        assert_eq!(resp.data.root, "0xslot99");
    }

    #[tokio::test]
    async fn test_slot_aware_stub_404s_a_skipped_slot() {
        let mock = slot_aware_mock(100, &[99]);
        assert_block_not_found(mock.get_block_root("99").await.unwrap_err());
        let resp = mock.get_block_root("98").await.expect("non-skipped past slot must resolve");
        assert_eq!(resp.data.root, "0xslot98");
    }

    #[tokio::test]
    async fn test_slot_aware_stub_resolves_head_literal() {
        let mock = slot_aware_mock(100, &[]);
        let head = mock.get_block_root("head").await.expect("head literal must resolve");
        let past = mock.get_block_root("99").await.expect("past slot must resolve");
        assert_ne!(head.data.root, past.data.root);
    }
}
