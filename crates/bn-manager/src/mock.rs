//! Shared configurable mock for [`crate::BeaconNodeClient`].
//!
//! Gated by `cfg(any(test, feature = "test-utils"))`. Errors by default for
//! every method; override per method with the `with_*` builders. Call arguments
//! are captured for assertions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BlockRootData, BlockRootResponse, BuilderConfig, BuilderPreferencesEntry, ConfigSpecResponse,
    GenesisResponse, PayloadAttestationDataResponse, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, PtcDutiesResponse, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SubmitBuilderPreferencesResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncingResponse, ValidatorLivenessResponse,
    ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
    VersionedSignedAggregateAndProof, WireBody,
};
use eth_types::{
    ForkName, ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedBlockContentsJson, SignedProposerPreferences, SignedValidatorRegistration, Slot,
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
    fn record(&self, args: A) {
        self.calls.lock().expect("mock call log poisoned").push(args);
    }

    fn invoke(&self, method: &'static str, args: A) -> Result<R, BeaconError> {
        self.record(args.clone());
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

/// Role-trait methods on [`MockBeaconNodeClient`].
///
/// Keys the per-method request-delay override. A present entry wins over the
/// global delay from [`MockBeaconNodeClient::with_request_delay`], including
/// an explicit zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MockMethod {
    GetGenesis,
    GetGenesisMatchingValidatorsRoot,
    GetConfigSpec,
    GetForkSchedule,
    GetFork,
    GetValidators,
    GetBlockRoot,
    GetNodeSyncing,
    GetNodeVersion,
    GetAttesterDuties,
    GetProposerDuties,
    PostSyncCommitteeDuties,
    PostPtcDuties,
    ProduceBlockV3,
    ProduceBlockV4,
    PublishBlock,
    PublishBlockContents,
    PublishBlindedBlock,
    PublishBlockSsz,
    PublishExecutionPayloadEnvelope,
    PrepareBeaconProposer,
    RegisterValidators,
    SubmitProposerPreferences,
    SubmitBuilderPreferences,
    GetAttestationData,
    SubmitAttestation,
    GetAggregateAttestation,
    SubmitAggregateAndProofs,
    SubmitBeaconCommitteeSubscriptions,
    GetPayloadAttestationData,
    SubmitPayloadAttestations,
    SubmitSyncCommitteeMessages,
    GetSyncCommitteeContribution,
    SubmitContributionAndProofs,
    PostValidatorLiveness,
    PostValidatorLivenessMerged,
}

#[cfg(test)]
impl MockMethod {
    /// Every role-trait method, discriminants `0..ALL.len()` with no gaps.
    const ALL: [Self; 36] = [
        Self::GetGenesis,
        Self::GetGenesisMatchingValidatorsRoot,
        Self::GetConfigSpec,
        Self::GetForkSchedule,
        Self::GetFork,
        Self::GetValidators,
        Self::GetBlockRoot,
        Self::GetNodeSyncing,
        Self::GetNodeVersion,
        Self::GetAttesterDuties,
        Self::GetProposerDuties,
        Self::PostSyncCommitteeDuties,
        Self::PostPtcDuties,
        Self::ProduceBlockV3,
        Self::ProduceBlockV4,
        Self::PublishBlock,
        Self::PublishBlockContents,
        Self::PublishBlindedBlock,
        Self::PublishBlockSsz,
        Self::PublishExecutionPayloadEnvelope,
        Self::PrepareBeaconProposer,
        Self::RegisterValidators,
        Self::SubmitProposerPreferences,
        Self::SubmitBuilderPreferences,
        Self::GetAttestationData,
        Self::SubmitAttestation,
        Self::GetAggregateAttestation,
        Self::SubmitAggregateAndProofs,
        Self::SubmitBeaconCommitteeSubscriptions,
        Self::GetPayloadAttestationData,
        Self::SubmitPayloadAttestations,
        Self::SubmitSyncCommitteeMessages,
        Self::GetSyncCommitteeContribution,
        Self::SubmitContributionAndProofs,
        Self::PostValidatorLiveness,
        Self::PostValidatorLivenessMerged,
    ];
}

type AttestationDataErrorInject = Arc<dyn Fn(u64, u64) -> Option<BeaconError> + Send + Sync>;

/// Erroring-by-default mock implementing all role traits and [`BeaconNodeClient`].
///
/// Configure responses with `with_*` builders; inspect captured arguments with
/// `*_calls` accessors. [`Self::with_request_delay`] sleeps before each async
/// role-trait method; the default delay is zero.
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
    publish_block: MethodHook<(SignedBeaconBlock, String, Option<String>), ()>,
    publish_block_contents: MethodHook<(SignedBlockContentsJson, String, Option<String>), ()>,
    publish_blinded_block: MethodHook<(SignedBlindedBeaconBlock, String), ()>,
    publish_block_ssz: MethodHook<(Vec<u8>, String, bool, Option<String>), ()>,
    publish_execution_payload_envelope:
        MethodHook<(WireBody, WireBody, WireBody, String, Option<String>), ()>,
    prepare_beacon_proposer: MethodHook<Vec<ProposerPreparation>, ()>,
    register_validators: MethodHook<Vec<SignedValidatorRegistration>, ()>,
    submit_proposer_preferences: MethodHook<Vec<SignedProposerPreferences>, ()>,
    submit_builder_preferences:
        MethodHook<Vec<BuilderPreferencesEntry>, SubmitBuilderPreferencesResult>,
    // AttestationApi
    get_attestation_data: MethodHook<(u64, u64), AttestationDataResponse>,
    submit_attestation: MethodHook<VersionedAttestation, SubmitAttestationResult>,
    get_aggregate_attestation:
        MethodHook<(u64, String, Option<u64>, ForkName), VersionedAggregateAttestation>,
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
    /// Global delay charged before every async role-trait method. Zero does not sleep.
    request_delay: Duration,
    /// Per-method override. A present key wins over `request_delay`, including zero.
    method_delays: HashMap<MockMethod, Duration>,
    /// One stamp per role-trait entry, taken before [`Self::charge`] sleeps.
    arrivals: Mutex<Vec<MockCallStamp>>,
    /// `submit_sync_committee_messages` futures that returned, after the delay
    /// and the handler. A call dropped during [`Self::charge`] is absent.
    sync_message_completions: Mutex<Vec<tokio::time::Instant>>,
    /// `submit_aggregate_and_proofs` futures that returned, after the delay
    /// and the handler. A call dropped during [`Self::charge`] is absent.
    aggregate_completions: Mutex<Vec<tokio::time::Instant>>,
    /// When this returns `Some`, `get_attestation_data` fails that call and skips the handler.
    get_attestation_data_error: Option<AttestationDataErrorInject>,
}

/// Arrival of one role-trait call, before the injected request delay.
///
/// [`tokio::time::Instant`] follows `pause` / `advance`, so a paused-clock
/// harness and a wall-clock harness share this stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockCallStamp {
    pub method: MockMethod,
    pub at: tokio::time::Instant,
}

impl MockBeaconNodeClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sleep `delay` before every async role-trait method.
    ///
    /// The default is [`Duration::ZERO`], which does not sleep, so existing
    /// callers keep their timing. [`Self::with_method_delay`] wins for one
    /// method, including an explicit zero. The wait is [`tokio::time::sleep`],
    /// so `tokio::time::pause` / `start_paused` drives it with no wall clock.
    pub fn with_request_delay(mut self, delay: Duration) -> Self {
        self.request_delay = delay;
        self
    }

    /// Override [`Self::with_request_delay`] for one role-trait method.
    pub fn with_method_delay(mut self, method: MockMethod, delay: Duration) -> Self {
        self.method_delays.insert(method, delay);
        self
    }

    fn effective_delay(&self, method: MockMethod) -> Duration {
        self.method_delays.get(&method).copied().unwrap_or(self.request_delay)
    }

    /// Stamps recorded since the client was built, in arrival order.
    ///
    /// Each stamp is taken before the request delay. Completed sync-message
    /// publishes are [`Self::submit_sync_committee_messages_completions`].
    /// Completed aggregate publishes are
    /// [`Self::submit_aggregate_and_proofs_completions`].
    pub fn call_stamps(&self) -> Vec<MockCallStamp> {
        self.arrivals.lock().expect("mock arrival log poisoned").clone()
    }

    /// Paused-clock instants when `submit_sync_committee_messages` returned.
    ///
    /// Recorded after [`Self::charge`] and the handler, so this is when the
    /// publish future finishes. [`Self::call_stamps`] is the pre-delay arrival.
    pub fn submit_sync_committee_messages_completions(&self) -> Vec<tokio::time::Instant> {
        self.sync_message_completions.lock().expect("mock completion log poisoned").clone()
    }

    /// Paused-clock instants when `submit_aggregate_and_proofs` returned.
    ///
    /// Recorded after [`Self::charge`] and the handler, so this is when the
    /// publish future finishes. [`Self::call_stamps`] is the pre-delay arrival.
    pub fn submit_aggregate_and_proofs_completions(&self) -> Vec<tokio::time::Instant> {
        self.aggregate_completions.lock().expect("mock completion log poisoned").clone()
    }

    fn stamp_sync_message_completion(&self) {
        self.sync_message_completions
            .lock()
            .expect("mock completion log poisoned")
            .push(tokio::time::Instant::now());
    }

    fn stamp_aggregate_completion(&self) {
        self.aggregate_completions
            .lock()
            .expect("mock completion log poisoned")
            .push(tokio::time::Instant::now());
    }

    async fn charge(&self, method: MockMethod) {
        self.arrivals
            .lock()
            .expect("mock arrival log poisoned")
            .push(MockCallStamp { method, at: tokio::time::Instant::now() });
        let delay = self.effective_delay(method);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
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
        f: impl Fn(SignedBeaconBlock, String, Option<String>) -> Result<(), BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.publish_block.set_handler(Arc::new(move |(block, version, builder_url)| {
            f(block, version, builder_url)
        }));
        self
    }

    pub fn with_publish_block_contents(
        self,
        f: impl Fn(SignedBlockContentsJson, String, Option<String>) -> Result<(), BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.publish_block_contents.set_handler(Arc::new(
            move |(contents, version, builder_url)| f(contents, version, builder_url),
        ));
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
        f: impl Fn(Vec<u8>, String, bool, Option<String>) -> Result<(), BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.publish_block_ssz.set_handler(Arc::new(
            move |(bytes, version, blinded, builder_url)| f(bytes, version, blinded, builder_url),
        ));
        self
    }

    pub fn with_publish_execution_payload_envelope(
        self,
        f: impl Fn(WireBody, WireBody, WireBody, String, Option<String>) -> Result<(), BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.publish_execution_payload_envelope.set_handler(Arc::new(
            move |(envelope, blobs, proofs, version, validation)| {
                f(envelope, blobs, proofs, version, validation)
            },
        ));
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

    pub fn with_submit_builder_preferences(
        self,
        f: impl Fn(Vec<BuilderPreferencesEntry>) -> Result<SubmitBuilderPreferencesResult, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.submit_builder_preferences.set_handler(Arc::new(f));
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

    /// Fail selected `get_attestation_data` calls without replacing the success handler.
    ///
    /// Return `Some(err)` to fail that `(slot, committee_index)`; `None` falls
    /// through to [`Self::with_get_attestation_data`]. The call is still recorded.
    /// RR2-06 uses this so committee 3 can fail while other committees succeed.
    pub fn with_get_attestation_data_error(
        mut self,
        f: impl Fn(u64, u64) -> Option<BeaconError> + Send + Sync + 'static,
    ) -> Self {
        self.get_attestation_data_error = Some(Arc::new(f));
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
        f: impl Fn(
                u64,
                String,
                Option<u64>,
                ForkName,
            ) -> Result<VersionedAggregateAttestation, BeaconError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_aggregate_attestation
            .set_handler(Arc::new(move |(slot, root, idx, fork)| f(slot, root, idx, fork)));
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

    pub fn submit_builder_preferences_calls(&self) -> Vec<Vec<BuilderPreferencesEntry>> {
        self.submit_builder_preferences.calls()
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

    pub fn publish_block_contents_calls(
        &self,
    ) -> Vec<(SignedBlockContentsJson, String, Option<String>)> {
        self.publish_block_contents.calls()
    }

    pub fn publish_execution_payload_envelope_calls(
        &self,
    ) -> Vec<(WireBody, WireBody, WireBody, String, Option<String>)> {
        self.publish_execution_payload_envelope.calls()
    }

    pub fn submit_sync_committee_messages_calls(&self) -> Vec<Vec<SyncCommitteeMessage>> {
        self.submit_sync_committee_messages.calls()
    }

    pub fn submit_aggregate_and_proofs_calls(&self) -> Vec<VersionedSignedAggregateAndProof> {
        self.submit_aggregate_and_proofs.calls()
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
        self.charge(MockMethod::GetGenesis).await;
        self.get_genesis.invoke("get_genesis", ())
    }

    async fn get_genesis_matching_validators_root(
        &self,
        expected_root_hex: &str,
    ) -> Result<GenesisResponse, BeaconError> {
        // One request: charge this method, then the genesis hook directly so
        // the inner `get_genesis` delay is not added on top.
        self.charge(MockMethod::GetGenesisMatchingValidatorsRoot).await;
        beacon::ensure_genesis_validators_root(
            self.get_genesis.invoke("get_genesis", ())?,
            expected_root_hex,
        )
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.charge(MockMethod::GetConfigSpec).await;
        self.get_config_spec.invoke("get_config_spec", ())
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.charge(MockMethod::GetForkSchedule).await;
        self.get_fork_schedule.invoke("get_fork_schedule", ())
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.charge(MockMethod::GetFork).await;
        self.get_fork.invoke("get_fork", state_id.to_string())
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.charge(MockMethod::GetValidators).await;
        self.get_validators.invoke("get_validators", pubkeys.to_vec())
    }

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.charge(MockMethod::GetBlockRoot).await;
        self.get_block_root.invoke("get_block_root", block_id.to_string())
    }

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.charge(MockMethod::GetNodeSyncing).await;
        self.get_node_syncing.invoke("get_node_syncing", ())
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.charge(MockMethod::GetNodeVersion).await;
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
        self.charge(MockMethod::GetAttesterDuties).await;
        self.get_attester_duties.invoke("get_attester_duties", (epoch, validator_indices.to_vec()))
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        _schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        self.charge(MockMethod::GetProposerDuties).await;
        self.get_proposer_duties.invoke("get_proposer_duties", epoch)
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.charge(MockMethod::PostSyncCommitteeDuties).await;
        self.post_sync_committee_duties
            .invoke("post_sync_committee_duties", (epoch, validator_indices.to_vec()))
    }

    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError> {
        self.charge(MockMethod::PostPtcDuties).await;
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
        self.charge(MockMethod::ProduceBlockV3).await;
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
        self.charge(MockMethod::ProduceBlockV4).await;
        self.produce_block_v4.invoke(
            "produce_block_v4",
            (slot, randao_reveal.to_string(), graffiti.map(str::to_string), builder_config.clone()),
        )
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PublishBlock).await;
        self.publish_block.invoke(
            "publish_block",
            (signed_block.clone(), consensus_version.to_string(), builder_url.map(str::to_string)),
        )
    }

    async fn publish_block_contents(
        &self,
        contents: &SignedBlockContentsJson,
        consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PublishBlockContents).await;
        self.publish_block_contents.invoke(
            "publish_block_contents",
            (contents.clone(), consensus_version.to_string(), builder_url.map(str::to_string)),
        )
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PublishBlindedBlock).await;
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
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PublishBlockSsz).await;
        self.publish_block_ssz.invoke(
            "publish_block_ssz",
            (
                ssz_bytes.to_vec(),
                consensus_version.to_string(),
                is_blinded,
                builder_url.map(str::to_string),
            ),
        )
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &WireBody,
        blobs: &WireBody,
        kzg_proofs: &WireBody,
        consensus_version: &str,
        broadcast_validation: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PublishExecutionPayloadEnvelope).await;
        self.publish_execution_payload_envelope.invoke(
            "publish_execution_payload_envelope",
            (
                signed_envelope.clone(),
                blobs.clone(),
                kzg_proofs.clone(),
                consensus_version.to_string(),
                broadcast_validation.map(str::to_string),
            ),
        )
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::PrepareBeaconProposer).await;
        self.prepare_beacon_proposer.invoke("prepare_beacon_proposer", preparations.to_vec())
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::RegisterValidators).await;
        self.register_validators.invoke("register_validators", registrations.to_vec())
    }

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitProposerPreferences).await;
        self.submit_proposer_preferences.invoke("submit_proposer_preferences", preferences.to_vec())
    }

    async fn submit_builder_preferences(
        &self,
        entries: &[BuilderPreferencesEntry],
    ) -> Result<SubmitBuilderPreferencesResult, BeaconError> {
        self.charge(MockMethod::SubmitBuilderPreferences).await;
        self.submit_builder_preferences.invoke("submit_builder_preferences", entries.to_vec())
    }
}

#[async_trait]
impl AttestationApi for MockBeaconNodeClient {
    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.charge(MockMethod::GetAttestationData).await;
        if let Some(err) = self
            .get_attestation_data_error
            .as_ref()
            .and_then(|inject| inject(slot, committee_index))
        {
            self.get_attestation_data.record((slot, committee_index));
            return Err(err);
        }
        self.get_attestation_data.invoke("get_attestation_data", (slot, committee_index))
    }

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.charge(MockMethod::SubmitAttestation).await;
        self.submit_attestation.invoke("submit_attestation", attestations.clone())
    }

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
        fork: ForkName,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.charge(MockMethod::GetAggregateAttestation).await;
        self.get_aggregate_attestation.invoke(
            "get_aggregate_attestation",
            (slot, attestation_data_root.to_string(), committee_index, fork),
        )
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitAggregateAndProofs).await;
        let result =
            self.submit_aggregate_and_proofs.invoke("submit_aggregate_and_proofs", proofs.clone());
        self.stamp_aggregate_completion();
        result
    }

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitBeaconCommitteeSubscriptions).await;
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
        self.charge(MockMethod::GetPayloadAttestationData).await;
        self.get_payload_attestation_data.invoke("get_payload_attestation_data", slot)
    }

    async fn submit_payload_attestations(
        &self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitPayloadAttestations).await;
        self.submit_payload_attestations.invoke("submit_payload_attestations", messages.to_vec())
    }
}

#[async_trait]
impl SyncCommitteeApi for MockBeaconNodeClient {
    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitSyncCommitteeMessages).await;
        let result = self
            .submit_sync_committee_messages
            .invoke("submit_sync_committee_messages", messages.to_vec());
        self.stamp_sync_message_completion();
        result
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.charge(MockMethod::GetSyncCommitteeContribution).await;
        self.get_sync_committee_contribution.invoke(
            "get_sync_committee_contribution",
            (slot, subcommittee_index, beacon_block_root.to_string()),
        )
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.charge(MockMethod::SubmitContributionAndProofs).await;
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
        self.charge(MockMethod::PostValidatorLiveness).await;
        self.post_validator_liveness
            .invoke("post_validator_liveness", (epoch, validator_indices.to_vec()))
    }

    async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        // Single-source mock: merge is a self-delegation so existing
        // `with_post_validator_liveness` fixtures keep working. Charge this
        // method once, then the liveness hook directly (no second delay).
        self.charge(MockMethod::PostValidatorLivenessMerged).await;
        self.post_validator_liveness
            .invoke("post_validator_liveness", (epoch, validator_indices.to_vec()))
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
        let err = mock.submit_builder_preferences(&[]).await.unwrap_err();
        match err {
            BeaconError::HttpError(msg) => {
                assert!(msg.contains("submit_builder_preferences"), "unexpected message: {msg}");
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
    async fn test_shared_mock_submit_builder_preferences_captures() {
        let mock = MockBeaconNodeClient::new()
            .with_submit_builder_preferences(|_e| Ok(SubmitBuilderPreferencesResult::Success));
        let entries = vec![BuilderPreferencesEntry {
            proposer_pubkey: format!("0x{}", "ab".repeat(48)),
            url: "https://builder.example.com".to_string(),
            auth: beacon::SignedBuilderRequestAuth {
                message: beacon::BuilderRequestAuth { data: "0x1234".to_string(), slot: 32 },
                signature: format!("0x{}", "cd".repeat(96)),
            },
            max_execution_payment: 0,
        }];
        mock.submit_builder_preferences(&entries).await.unwrap();
        assert_eq!(mock.submit_builder_preferences_calls(), vec![entries]);
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
                    payload_included: false,
                    builder_url: None,
                    consensus_block_value: None,
                })
            });
        let cfg = BuilderConfig::default();
        mock.produce_block_v4(7, "0xrandao", Some("0xgraf"), &cfg).await.unwrap();
        assert_eq!(
            mock.produce_block_v4_calls(),
            vec![(7, "0xrandao".to_string(), Some("0xgraf".to_string()), cfg)]
        );
    }

    fn sample_block_contents() -> SignedBlockContentsJson {
        SignedBlockContentsJson {
            signed_block: eth_types::signed_block_contents_json::SignedBeaconBlockJson {
                message: eth_types::signed_block_contents_json::BeaconBlockJson {
                    slot: 1,
                    proposer_index: 0,
                    parent_root: [1u8; 32],
                    state_root: [2u8; 32],
                    body: serde_json::json!({"randao_reveal": "0x01"}),
                },
                signature: vec![0xaa; 96],
            },
            kzg_proofs: vec![vec![0x11; 48]],
            blobs: vec![vec![0x22; 8]],
        }
    }

    #[tokio::test]
    async fn publish_block_contents_is_recorded() {
        let contents = sample_block_contents();
        let builder = "https://builder.example/echo";
        let mock = MockBeaconNodeClient::new().with_publish_block_contents(|_c, _v, _u| Ok(()));
        mock.publish_block_contents(&contents, "electra", Some(builder)).await.unwrap();
        assert_eq!(
            mock.publish_block_contents_calls(),
            vec![(contents, "electra".to_string(), Some(builder.to_string()))]
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

    /// Arrival is before the delay; completion is when the submit future returns.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn submit_sync_message_completion_is_after_the_request_delay() {
        use std::time::Duration;

        let delay = Duration::from_millis(50);
        let mock = MockBeaconNodeClient::new()
            .with_request_delay(delay)
            .with_submit_sync_committee_messages(|_| Ok(()));
        let start = tokio::time::Instant::now();
        mock.submit_sync_committee_messages(&[]).await.expect("submit");
        let arrivals = mock.call_stamps();
        assert_eq!(arrivals.len(), 1);
        assert_eq!(arrivals[0].method, MockMethod::SubmitSyncCommitteeMessages);
        assert_eq!(arrivals[0].at.saturating_duration_since(start), Duration::ZERO);
        assert_eq!(mock.submit_sync_committee_messages_completions(), vec![start + delay]);
        assert_eq!(start.elapsed(), delay);
    }

    /// Arrival is before the delay; completion is when the aggregate submit returns.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn submit_aggregate_completion_is_after_the_request_delay() {
        use std::time::Duration;

        let delay = Duration::from_millis(50);
        let mock = MockBeaconNodeClient::new()
            .with_request_delay(delay)
            .with_submit_aggregate_and_proofs(|_| Ok(()));
        let start = tokio::time::Instant::now();
        mock.submit_aggregate_and_proofs(&VersionedSignedAggregateAndProof::Electra(vec![]))
            .await
            .expect("submit");
        let arrivals = mock.call_stamps();
        assert_eq!(arrivals.len(), 1);
        assert_eq!(arrivals[0].method, MockMethod::SubmitAggregateAndProofs);
        assert_eq!(arrivals[0].at.saturating_duration_since(start), Duration::ZERO);
        assert_eq!(mock.submit_aggregate_and_proofs_completions(), vec![start + delay]);
        assert_eq!(start.elapsed(), delay);
    }

    /// Two sequential requests each pay the configured delay on a paused clock.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mock_request_delay_is_charged_per_request() {
        use std::time::Duration;

        let mock = MockBeaconNodeClient::new().with_request_delay(Duration::from_millis(50));
        let start = tokio::time::Instant::now();
        let _ = mock.get_attestation_data(1, 0).await;
        let _ = mock.get_attestation_data(1, 1).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "two sequential get_attestation_data calls with with_request_delay(50ms) \
             must advance virtual time by >= 100ms, got {elapsed:?}"
        );
        assert_eq!(
            elapsed,
            Duration::from_millis(100),
            "paused clock must charge exactly 50ms per request, got {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mock_method_delay_overrides_the_global_request_delay() {
        use std::time::Duration;

        let mock = MockBeaconNodeClient::new()
            .with_request_delay(Duration::from_millis(50))
            .with_method_delay(MockMethod::GetAttestationData, Duration::from_millis(10))
            .with_method_delay(MockMethod::GetGenesis, Duration::ZERO);
        let start = tokio::time::Instant::now();
        let _ = mock.get_attestation_data(1, 0).await;
        let _ = mock.get_attestation_data(1, 1).await;
        assert_eq!(start.elapsed(), Duration::from_millis(20));
        let _ = mock.get_genesis().await;
        assert_eq!(start.elapsed(), Duration::from_millis(20));
        let _ = mock.get_fork("head").await;
        assert_eq!(start.elapsed(), Duration::from_millis(70));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mock_default_request_delay_does_not_advance_virtual_time() {
        use std::time::Duration;

        let mock = MockBeaconNodeClient::new();
        let start = tokio::time::Instant::now();
        let _ = mock.get_attestation_data(1, 0).await;
        let _ = mock.get_genesis().await;
        let _ = mock.submit_attestation(&VersionedAttestation::Electra(vec![])).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[test]
    fn mock_method_all_covers_every_discriminant() {
        assert_eq!(
            MockMethod::ALL.len(),
            (MockMethod::PostValidatorLivenessMerged as usize) + 1,
            "MockMethod::ALL must list every variant"
        );
        let mut seen = vec![false; MockMethod::ALL.len()];
        for method in MockMethod::ALL {
            let index = method as usize;
            assert!(index < seen.len(), "{method:?} discriminant {index} is outside ALL");
            assert!(!seen[index], "duplicate {method:?}");
            seen[index] = true;
        }
        assert!(seen.iter().all(|hit| *hit));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mock_request_delay_covers_every_role_trait_method() {
        use std::time::Duration;

        let delay = Duration::from_millis(50);
        let mock = MockBeaconNodeClient::new().with_request_delay(delay);
        let start = tokio::time::Instant::now();
        for method in MockMethod::ALL {
            invoke_role_method(&mock, method).await;
        }
        assert_eq!(start.elapsed(), delay * u32::try_from(MockMethod::ALL.len()).unwrap());
    }

    async fn invoke_role_method(mock: &MockBeaconNodeClient, method: MockMethod) {
        let schedule = ForkSchedule::unscheduled_gloas();
        let contents = sample_block_contents();
        let block = SignedBeaconBlock {
            message: eth_types::BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [1u8; 32],
                state_root: [2u8; 32],
                body: vec![0xde, 0xad],
            },
            signature: vec![0xaa; 96],
        };
        let blinded = SignedBlindedBeaconBlock {
            message: eth_types::BlindedBeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [1u8; 32],
                state_root: [2u8; 32],
                body: vec![0xbe, 0xef],
            },
            signature: vec![0xbb; 96],
        };
        let wire = WireBody::Ssz(Vec::new());
        // Fork-name literals stay outside the match so the fork-hazard scanner
        // does not treat this MockMethod dispatch as a string-literal fork match.
        let deneb = "deneb";
        let electra = "electra";
        let gloas = "gloas";
        match method {
            MockMethod::GetGenesis => {
                let _ = mock.get_genesis().await;
            }
            MockMethod::GetGenesisMatchingValidatorsRoot => {
                let _ = mock.get_genesis_matching_validators_root("0x00").await;
            }
            MockMethod::GetConfigSpec => {
                let _ = mock.get_config_spec().await;
            }
            MockMethod::GetForkSchedule => {
                let _ = mock.get_fork_schedule().await;
            }
            MockMethod::GetFork => {
                let _ = mock.get_fork("head").await;
            }
            MockMethod::GetValidators => {
                let _ = mock.get_validators(&[]).await;
            }
            MockMethod::GetBlockRoot => {
                let _ = mock.get_block_root("head").await;
            }
            MockMethod::GetNodeSyncing => {
                let _ = mock.get_node_syncing().await;
            }
            MockMethod::GetNodeVersion => {
                let _ = mock.get_node_version().await;
            }
            MockMethod::GetAttesterDuties => {
                let _ = mock.get_attester_duties(0, &[]).await;
            }
            MockMethod::GetProposerDuties => {
                let _ = mock.get_proposer_duties(0, &schedule).await;
            }
            MockMethod::PostSyncCommitteeDuties => {
                let _ = mock.post_sync_committee_duties(0, &[]).await;
            }
            MockMethod::PostPtcDuties => {
                let _ = mock.post_ptc_duties(0, &[]).await;
            }
            MockMethod::ProduceBlockV3 => {
                let _ = mock.produce_block_v3(0, "0x", None, None).await;
            }
            MockMethod::ProduceBlockV4 => {
                let _ = mock.produce_block_v4(0, "0x", None, &BuilderConfig::default()).await;
            }
            MockMethod::PublishBlock => {
                let _ = mock.publish_block(&block, deneb, None).await;
            }
            MockMethod::PublishBlockContents => {
                let _ = mock.publish_block_contents(&contents, electra, None).await;
            }
            MockMethod::PublishBlindedBlock => {
                let _ = mock.publish_blinded_block(&blinded, deneb).await;
            }
            MockMethod::PublishBlockSsz => {
                let _ = mock.publish_block_ssz(&[], deneb, false, None).await;
            }
            MockMethod::PublishExecutionPayloadEnvelope => {
                let _ =
                    mock.publish_execution_payload_envelope(&wire, &wire, &wire, gloas, None).await;
            }
            MockMethod::PrepareBeaconProposer => {
                let _ = mock.prepare_beacon_proposer(&[]).await;
            }
            MockMethod::RegisterValidators => {
                let _ = mock.register_validators(&[]).await;
            }
            MockMethod::SubmitProposerPreferences => {
                let _ = mock.submit_proposer_preferences(&[]).await;
            }
            MockMethod::SubmitBuilderPreferences => {
                let _ = mock.submit_builder_preferences(&[]).await;
            }
            MockMethod::GetAttestationData => {
                let _ = mock.get_attestation_data(1, 0).await;
            }
            MockMethod::SubmitAttestation => {
                let _ = mock.submit_attestation(&VersionedAttestation::Electra(vec![])).await;
            }
            MockMethod::GetAggregateAttestation => {
                let _ = mock.get_aggregate_attestation(0, "0x00", None, ForkName::Phase0).await;
            }
            MockMethod::SubmitAggregateAndProofs => {
                let _ = mock
                    .submit_aggregate_and_proofs(&VersionedSignedAggregateAndProof::Electra(vec![]))
                    .await;
            }
            MockMethod::SubmitBeaconCommitteeSubscriptions => {
                let _ = mock.submit_beacon_committee_subscriptions(&[]).await;
            }
            MockMethod::GetPayloadAttestationData => {
                let _ = mock.get_payload_attestation_data(0).await;
            }
            MockMethod::SubmitPayloadAttestations => {
                let _ = mock.submit_payload_attestations(&[]).await;
            }
            MockMethod::SubmitSyncCommitteeMessages => {
                let _ = mock.submit_sync_committee_messages(&[]).await;
            }
            MockMethod::GetSyncCommitteeContribution => {
                let _ = mock.get_sync_committee_contribution(0, 0, "0x00").await;
            }
            MockMethod::SubmitContributionAndProofs => {
                let _ = mock.submit_contribution_and_proofs(&[]).await;
            }
            MockMethod::PostValidatorLiveness => {
                let _ = mock.post_validator_liveness(0, &[]).await;
            }
            MockMethod::PostValidatorLivenessMerged => {
                let _ = mock.post_validator_liveness_merged(0, &[]).await;
            }
        }
    }

    #[tokio::test]
    async fn get_attestation_data_error_fails_only_the_selected_committee() {
        let mock = MockBeaconNodeClient::new()
            .with_get_attestation_data(|_slot, committee| {
                Ok(AttestationDataResponse {
                    data: beacon::AttestationData {
                        slot: "1".to_string(),
                        index: committee.to_string(),
                        beacon_block_root: "0x00".to_string(),
                        source: beacon::Checkpoint {
                            epoch: "0".to_string(),
                            root: "0x01".to_string(),
                        },
                        target: beacon::Checkpoint {
                            epoch: "1".to_string(),
                            root: "0x02".to_string(),
                        },
                    },
                })
            })
            .with_get_attestation_data_error(|_slot, committee| {
                (committee == 3).then(|| BeaconError::HttpError("committee 3".to_string()))
            });

        let err = mock.get_attestation_data(1, 3).await.unwrap_err();
        assert!(matches!(err, BeaconError::HttpError(ref msg) if msg.contains("committee 3")));
        let ok = mock.get_attestation_data(1, 1).await.expect("other committees succeed");
        assert_eq!(ok.data.index, "1");
        assert_eq!(mock.get_attestation_data_calls(), vec![(1, 3), (1, 1)]);
    }
}
