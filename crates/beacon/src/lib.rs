//! HTTP client for Ethereum Beacon Node API
//!
//! Provides async HTTP client with retry logic for beacon node communication.

mod client;
mod error;
pub(crate) mod http_caps;
mod retry;
pub mod ssz_deser;
mod types;

pub use client::{BeaconClient, BeaconClientConfig};
pub use error::BeaconError;
pub use http_caps::ResponseCaps;
pub use retry::RetryPolicy;
pub use types::{
    parse_fork_schedule, parse_slot_duration_ms, AttestationData, AttestationDataResponse,
    AttesterDutiesResponse, AttesterDuty, BeaconBlockHeader, BeaconCommitteeSubscription,
    BlockRootData, BlockRootResponse, Checkpoint, ClientVersionV1, ConfigSpecResponse,
    DataResponse, DependentRootResponse, ExecutionOptimisticResponse, GenesisData, GenesisResponse,
    IndexedAttestationError, LegacyAttestation, NodeVersionData, NodeVersionResponse,
    NodeVersionV2Data, NodeVersionV2Response, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerDuty, ProposerPreparation, SignedAggregateAndProof, SignedContributionAndProof,
    SingleAttestation, StateFork, StateForkResponse, StateResponse, SubmitAttestationResult,
    SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
    SyncingData, SyncingResponse, ValidatorData, ValidatorInfo, ValidatorLiveness,
    ValidatorLivenessResponse, ValidatorsResponse, VersionedAggregateAttestation,
    VersionedAttestation, VersionedSignedAggregateAndProof,
};
