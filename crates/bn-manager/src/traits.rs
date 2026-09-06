use std::time::Duration;

use async_trait::async_trait;

use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BlockRootResponse, BuilderConfig, ConfigSpecResponse, GenesisResponse,
    PayloadAttestationDataResponse, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, PtcDutiesResponse, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
use eth_types::{
    ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedProposerPreferences, SignedValidatorRegistration,
};

// ---------------------------------------------------------------------------
// Role traits (domain splits of the former monolithic BeaconNodeClient)
// ---------------------------------------------------------------------------

/// Duty discovery: attester, proposer, sync-committee, and PTC duty endpoints.
#[async_trait]
pub trait DutiesProvider: Send + Sync {
    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError>;

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError>;

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError>;

    /// Fetch PTC duties for the given epoch (`POST /eth/v1/validator/duties/ptc/{epoch}`).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError>;
}

/// Block production, publication, proposer preparation, and builder registration.
#[async_trait]
pub trait BlockProducer: Send + Sync {
    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError>;

    /// Produce a block via `POST /eth/v4/validator/blocks/{slot}`.
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn produce_block_v4(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BeaconError>;

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError>;

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError>;

    /// Publish a block as raw SSZ bytes (`Content-Type: application/octet-stream`).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure (same policy as [`LivenessApi::post_validator_liveness`]).
    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError>;

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError>;

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError>;

    /// Submit signed proposer preferences
    /// (`POST /eth/v1/validator/proposer_preferences`).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError>;
}

/// Attestation data, submission, aggregation, and committee subscriptions.
#[async_trait]
pub trait AttestationApi: Send + Sync {
    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError>;

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError>;

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError>;

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError>;

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError>;
}

/// Payload attestation data fetch and pool submission.
#[async_trait]
pub trait PayloadAttestationApi: Send + Sync {
    /// Fetch payload attestation data for `slot`
    /// (`GET /eth/v1/validator/payload_attestation_data?slot=`).
    ///
    /// HTTP 204 from the BN is `Ok(None)` (skip the duty).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn get_payload_attestation_data(
        &self,
        slot: u64,
    ) -> Result<Option<PayloadAttestationDataResponse>, BeaconError>;

    /// Submit payload attestation messages
    /// (`POST /eth/v1/beacon/pool/payload_attestations`).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn submit_payload_attestations(
        &self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError>;
}

/// Sync committee messages, contributions, and contribution-and-proofs.
#[async_trait]
pub trait SyncCommitteeApi: Send + Sync {
    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError>;

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError>;

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError>;
}

/// Doppelganger / validator liveness queries.
#[async_trait]
pub trait LivenessApi: Send + Sync {
    /// Query validator liveness for the given epoch
    /// (`POST /eth/v1/validator/liveness/{epoch}`).
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure.
    async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError>;

    /// Query liveness on every configured BN and OR-merge `is_live` per index.
    ///
    /// Any BN reporting live wins (fail-safe). Errors and non-responses
    /// contribute nothing — they are not treated as "not live". Returns `Err`
    /// only when every BN fails, so callers can stay fail-closed.
    ///
    /// No default body: an unimplemented method is a compile error, not a
    /// silent runtime failure. Single-BN clients (`BeaconClient`) self-delegate
    /// to [`Self::post_validator_liveness`].
    async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError>;
}

/// Chain state, config, block roots, and node health/version.
#[async_trait]
pub trait NodeStatusApi: Send + Sync {
    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError>;

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError>;

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError>;

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError>;

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError>;

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError>;

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError>;

    async fn get_node_version(&self) -> Result<String, BeaconError>;
}

/// Full beacon-node surface: composition of the seven role traits.
///
/// Supertrait composition (not a blanket impl) keeps `dyn BeaconNodeClient`
/// object-safe and lets callers that only need one role depend on that role
/// alone. Implementors provide the seven role traits, then an empty
/// `impl BeaconNodeClient for T {}`.
pub trait BeaconNodeClient:
    DutiesProvider
    + BlockProducer
    + AttestationApi
    + PayloadAttestationApi
    + SyncCommitteeApi
    + LivenessApi
    + NodeStatusApi
    + Send
    + Sync
{
}

/// Per-operation timeout configuration for beacon node API calls.
#[derive(Debug, Clone)]
pub struct OperationTimeouts {
    pub block_production: Duration,
    pub block_publication: Duration,
    pub attestation_fetch: Duration,
    pub attestation_submit: Duration,
    pub aggregate_fetch: Duration,
    pub aggregate_submit: Duration,
    pub sync_message: Duration,
    pub sync_contribution: Duration,
    pub duty_fetch: Duration,
    pub preparation: Duration,
}

impl Default for OperationTimeouts {
    fn default() -> Self {
        Self {
            block_production: Duration::from_secs(3),
            block_publication: Duration::from_secs(2),
            attestation_fetch: Duration::from_secs(4),
            attestation_submit: Duration::from_secs(2),
            aggregate_fetch: Duration::from_secs(2),
            aggregate_submit: Duration::from_secs(2),
            sync_message: Duration::from_secs(2),
            sync_contribution: Duration::from_secs(2),
            duty_fetch: Duration::from_secs(10),
            preparation: Duration::from_secs(3),
        }
    }
}

/// Controls which message types are broadcast to role-matching BNs vs sent to the first healthy BN.
///
/// When a topic is `true`, the corresponding submission is broadcast to BNs whose
/// `BnRole` matches the message (plus the `All`-role fallback). Health tier and
/// health-score are **not** applied. An empty role+All set is
/// [`crate::BeaconError::NoEligibleBn`] — never off-role fan-out. When `false`,
/// only the first healthy BN receives the message (query_first strategy).
/// Default: all topics enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastTopics {
    pub attestations: bool,
    pub blocks: bool,
    pub sync_committee: bool,
    pub subscriptions: bool,
}

impl Default for BroadcastTopics {
    fn default() -> Self {
        Self { attestations: true, blocks: true, sync_committee: true, subscriptions: true }
    }
}

/// Configuration for the beacon node manager.
///
/// BN selection is not configurable: strategy is fixed per operation on
/// [`crate::BnManager`] (query-first for reads, broadcast for submissions,
/// best-of for block production). See that type's docs.
#[derive(Debug, Clone)]
pub struct BnManagerConfig {
    /// Beacon node endpoint URLs.
    pub endpoints: Vec<String>,
    /// Per-BN request timeout.
    pub timeout: Duration,
    /// Which submission types are broadcast to role-matching BNs
    /// (fail-closed if none).
    pub broadcast_topics: BroadcastTopics,
    /// Per-BN role assignments (parallel to endpoints). Honoured by query and
    /// broadcast selection. Default: {All} for each.
    pub roles: Vec<std::collections::HashSet<crate::types::BnRole>>,
    /// Health tier thresholds for sync distance classification.
    pub tier_thresholds: crate::types::TierThresholds,
    /// Maximum bytes allowed in a JSON response body (H-12).
    ///
    /// Applied to every `BeaconClient` created by `BnManager::new`.
    /// Default: 32 MiB (`ResponseCaps::DEFAULT_MAX_BODY_BYTES`).
    pub max_body_bytes: usize,
}

impl BnManagerConfig {
    pub fn new(endpoints: Vec<String>) -> Self {
        let count = endpoints.len();
        Self {
            endpoints,
            timeout: Duration::from_secs(30),
            broadcast_topics: BroadcastTopics::default(),
            roles: vec![
                {
                    let mut s = std::collections::HashSet::new();
                    s.insert(crate::types::BnRole::All);
                    s
                };
                count
            ],
            tier_thresholds: crate::types::TierThresholds::default(),
            max_body_bytes: beacon::ResponseCaps::DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Set the maximum JSON response body size for all per-BN clients.
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// Health score for a beacon node, used for selection and failover decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct BnHealthScore {
    /// Endpoint URL of the beacon node.
    pub endpoint: String,
    /// Whether the node is currently reachable.
    pub is_reachable: bool,
    /// Whether the node is fully synced.
    pub is_synced: bool,
    /// Whether the node's execution layer is offline.
    pub is_el_offline: bool,
    /// Latest observed head slot from the node.
    pub head_slot: Option<u64>,
    /// Response latency for the most recent health check.
    pub latency: Option<Duration>,
    /// Exponential moving average latency in milliseconds.
    pub latency_ms: f64,
    /// Error rate as a fraction (0.0 = no errors, 1.0 = all errors).
    pub error_rate: f64,
    /// Composite health score (0.0 = worst, 1.0 = best).
    pub score: f64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // -- Trait object safety --

    #[test]
    fn test_trait_is_object_safe() {
        // This test verifies that BeaconNodeClient can be used as a trait object.
        // If the trait is not object-safe, this will fail to compile.
        fn _assert_object_safe(_: &dyn BeaconNodeClient) {}
    }

    #[test]
    fn test_dyn_beacon_node_client_still_object_safe() {
        fn _assert(_: &dyn BeaconNodeClient) {}
        fn _assert_role_duties(_: &dyn DutiesProvider) {}
        fn _assert_role_block(_: &dyn BlockProducer) {}
        fn _assert_role_attestation(_: &dyn AttestationApi) {}
        fn _assert_role_payload_attestation(_: &dyn PayloadAttestationApi) {}
        fn _assert_role_sync(_: &dyn SyncCommitteeApi) {}
        fn _assert_role_liveness(_: &dyn LivenessApi) {}
        fn _assert_role_status(_: &dyn NodeStatusApi) {}
    }

    #[test]
    fn test_trait_can_be_arc_wrapped() {
        // Verifies Arc<dyn BeaconNodeClient> compiles (Send + Sync required).
        fn _assert_arc_dyn(_: Arc<dyn BeaconNodeClient>) {}
    }

    // -- Narrow role: only DutiesProvider --

    struct OnlyDuties;

    #[async_trait]
    impl DutiesProvider for OnlyDuties {
        async fn get_attester_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError> {
            Ok(AttesterDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        }

        async fn get_proposer_duties(
            &self,
            _epoch: u64,
            _schedule: &ForkSchedule,
        ) -> Result<ProposerDutiesResponse, BeaconError> {
            Ok(ProposerDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        }

        async fn post_sync_committee_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
            Ok(SyncCommitteeDutiesResponse { execution_optimistic: false, data: vec![] })
        }

        async fn post_ptc_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
        ) -> Result<PtcDutiesResponse, BeaconError> {
            Ok(PtcDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        }
    }

    #[tokio::test]
    async fn test_mock_with_only_duties_role_compiles_and_serves_duties() {
        let only = OnlyDuties;
        let attester = only.get_attester_duties(1, &["0".into()]).await.unwrap();
        assert!(attester.data.is_empty());
        let proposer =
            only.get_proposer_duties(1, &ForkSchedule::unscheduled_gloas()).await.unwrap();
        assert!(proposer.data.is_empty());
        let sync = only.post_sync_committee_duties(1, &["0".into()]).await.unwrap();
        assert!(sync.data.is_empty());
        let ptc = only.post_ptc_duties(1, &["0".into()]).await.unwrap();
        assert!(ptc.data.is_empty());
        // OnlyDuties is *not* a BeaconNodeClient — that is the point of role traits.
        fn _takes_duties(_: &dyn DutiesProvider) {}
        _takes_duties(&only);
    }

    // -- BnManagerConfig --

    #[test]
    fn test_config_new_defaults() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.endpoints[0], "http://localhost:5052");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_multiple_endpoints() {
        let config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
            "http://bn3:5052".to_string(),
        ]);
        assert_eq!(config.endpoints.len(), 3);
    }

    #[test]
    fn test_config_empty_endpoints() {
        let config = BnManagerConfig::new(vec![]);
        assert!(config.endpoints.is_empty());
    }

    #[test]
    fn test_config_clone() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let cloned = config.clone();
        assert_eq!(cloned.endpoints, config.endpoints);
        assert_eq!(cloned.timeout, config.timeout);
    }

    #[test]
    fn test_config_debug() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let debug = format!("{:?}", config);
        assert!(debug.contains("BnManagerConfig"));
    }

    // -- BnHealthScore --

    #[test]
    fn test_health_score_fields() {
        let score = BnHealthScore {
            endpoint: "http://localhost:5052".to_string(),
            is_reachable: true,
            is_synced: true,
            is_el_offline: false,
            head_slot: Some(100),
            latency: Some(Duration::from_millis(50)),
            latency_ms: 50.0,
            error_rate: 0.0,
            score: 1.0,
        };
        assert_eq!(score.endpoint, "http://localhost:5052");
        assert!(score.is_reachable);
        assert!(score.is_synced);
        assert!(!score.is_el_offline);
        assert_eq!(score.head_slot, Some(100));
        assert_eq!(score.latency, Some(Duration::from_millis(50)));
        assert_eq!(score.score, 1.0);
    }

    #[test]
    fn test_health_score_clone() {
        let score = BnHealthScore {
            endpoint: "http://bn:5052".to_string(),
            is_reachable: false,
            is_synced: false,
            is_el_offline: true,
            head_slot: None,
            latency: None,
            latency_ms: 0.0,
            error_rate: 1.0,
            score: 0.0,
        };
        let cloned = score.clone();
        assert_eq!(cloned, score);
    }

    #[test]
    fn test_health_score_partial_eq() {
        let a = BnHealthScore {
            endpoint: "http://a".to_string(),
            is_reachable: true,
            is_synced: true,
            is_el_offline: false,
            head_slot: Some(1),
            latency: None,
            latency_ms: 10.0,
            error_rate: 0.0,
            score: 0.9,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let mut c = a.clone();
        c.score = 0.5;
        assert_ne!(a, c);
    }

    // -- OperationTimeouts --

    #[test]
    fn test_operation_timeouts_default_values() {
        let t = OperationTimeouts::default();
        assert_eq!(t.block_production, Duration::from_secs(3));
        assert_eq!(t.block_publication, Duration::from_secs(2));
        assert_eq!(t.attestation_fetch, Duration::from_secs(4));
        assert_eq!(t.attestation_submit, Duration::from_secs(2));
        assert_eq!(t.aggregate_fetch, Duration::from_secs(2));
        assert_eq!(t.aggregate_submit, Duration::from_secs(2));
        assert_eq!(t.sync_message, Duration::from_secs(2));
        assert_eq!(t.sync_contribution, Duration::from_secs(2));
        assert_eq!(t.duty_fetch, Duration::from_secs(10));
        assert_eq!(t.preparation, Duration::from_secs(3));
    }

    #[test]
    fn test_operation_timeouts_clone() {
        let t = OperationTimeouts::default();
        let cloned = t.clone();
        assert_eq!(t.block_production, cloned.block_production);
        assert_eq!(t.duty_fetch, cloned.duty_fetch);
    }

    #[test]
    fn test_operation_timeouts_debug() {
        let t = OperationTimeouts::default();
        let debug = format!("{:?}", t);
        assert!(debug.contains("OperationTimeouts"));
    }

    // -- BroadcastTopics --

    #[test]
    fn test_broadcast_topics_default_all_enabled() {
        let topics = BroadcastTopics::default();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_broadcast_topics_all_disabled() {
        let topics = BroadcastTopics {
            attestations: false,
            blocks: false,
            sync_committee: false,
            subscriptions: false,
        };
        assert!(!topics.attestations);
        assert!(!topics.blocks);
    }

    #[test]
    fn test_broadcast_topics_partial() {
        let topics = BroadcastTopics {
            attestations: false,
            blocks: true,
            sync_committee: false,
            subscriptions: true,
        };
        assert!(!topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_broadcast_topics_clone() {
        let topics = BroadcastTopics {
            attestations: true,
            blocks: false,
            sync_committee: true,
            subscriptions: false,
        };
        let cloned = topics.clone();
        assert_eq!(topics, cloned);
    }

    #[test]
    fn test_broadcast_topics_debug() {
        let topics = BroadcastTopics::default();
        let debug = format!("{:?}", topics);
        assert!(debug.contains("BroadcastTopics"));
    }

    #[test]
    fn test_bn_manager_config_includes_broadcast_topics() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert_eq!(config.broadcast_topics, BroadcastTopics::default());
    }
}
