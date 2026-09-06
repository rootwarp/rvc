//! Beacon node manager with multi-BN support, failover, and health tracking.

mod broadcast;
mod error;
mod health;
mod manager;
pub mod metrics;
#[cfg(any(test, feature = "test-utils"))]
mod mock;
pub mod sse;
mod submit;
mod sync_status;
mod traits;
pub mod types;

pub use error::BnManagerError;
pub use manager::BnManager;
#[cfg(any(test, feature = "test-utils"))]
pub use mock::MockBeaconNodeClient;
pub use sse::{
    parse_sse_event, BlockEvent, ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent, SseConfig,
    SseConnectionState, SseError, SseEvent, DEFAULT_SSE_TOPICS,
};
pub use submit::{AttestationSubmitter, PropagationResult, Propagator, PropagatorError};
pub use sync_status::{BnSyncDetail, BnSyncStatus, SharedSyncStatuses};
pub use traits::{
    AttestationApi, BeaconNodeClient, BlockProducer, BnHealthScore, BnManagerConfig,
    BroadcastTopics, DutiesProvider, LivenessApi, NodeStatusApi, OperationTimeouts,
    PayloadAttestationApi, SyncCommitteeApi,
};
pub use types::{BnRole, HealthTier, TierThresholds};

// Re-export types used in trait signatures so downstream crates
// don't need to depend on `beacon` directly.
pub use beacon::{
    AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty,
    BeaconCommitteeSubscription, BeaconError, BlockRootResponse, BuilderConfig, Checkpoint,
    ConfigSpecResponse, GenesisResponse, IndexedAttestationError, LegacyAttestation,
    PayloadAttestationDataResponse, ProduceBlockResponse, ProposerDutiesResponse, ProposerDuty,
    ProposerPreparation, PtcDutiesResponse, PtcDuty, SignedAggregateAndProof,
    SignedContributionAndProof, SingleAttestation, StateForkResponse, SubmitAttestationResult,
    SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
    SyncingData, SyncingResponse, ValidatorLiveness, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
pub use eth_types::{
    ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedProposerPreferences, SignedValidatorRegistration, ValidatorRegistrationV1,
};
