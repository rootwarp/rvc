//! HTTP client for Ethereum Beacon Node API
//!
//! Provides async HTTP client with retry logic for beacon node communication.

mod client;
mod error;
pub(crate) mod http_caps;
mod retry;
pub mod ssz_deser;
mod types;
mod v4_wire;

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
    NodeVersionV2Data, NodeVersionV2Response, PayloadAttestationDataResponse, ProduceBlockResponse,
    ProposerDutiesResponse, ProposerDuty, ProposerPreparation, PtcDutiesResponse, PtcDuty,
    SignedAggregateAndProof, SignedContributionAndProof, SingleAttestation, StateFork,
    StateForkResponse, StateResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncingData, SyncingResponse, ValidatorData,
    ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
pub use v4_wire::{
    BuilderConfig, BuilderEntry, BuilderRequestAuth, SignedBuilderRequestAuth,
    FALLBACK_BUILDER_BOOST_FACTOR, FALLBACK_MIN_BID, HEADER_ETH_BUILDER_URL,
    HEADER_ETH_CONSENSUS_BLOCK_VALUE, HEADER_ETH_CONSENSUS_VERSION,
    HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, HEADER_ETH_EXECUTION_PAYLOAD_VALUE, MAX_BUILDER_ENTRIES,
    MAX_BUILDER_PUBKEYS, MAX_BUILDER_URL_SIZE, PRODUCE_BLOCK_V4_PATH_PREFIX, QUERY_GRAFFITI,
    QUERY_INCLUDE_PAYLOAD, QUERY_RANDAO_REVEAL, QUERY_SKIP_RANDAO_VERIFICATION, V4_WIRE_REVISION,
};
