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
    GloasBlockContents, IndexedAttestationError, IndexedErrorMessage, IndexedFailure,
    LegacyAttestation, NodeVersionData, NodeVersionResponse, NodeVersionV2Data,
    NodeVersionV2Response, PayloadAttestationDataResponse, ProduceBlockResponse,
    ProduceBlockV4Body, ProposerDutiesResponse, ProposerDuty, ProposerPreparation,
    PtcDutiesResponse, PtcDuty, SignedAggregateAndProof, SignedContributionAndProof,
    SingleAttestation, StateFork, StateForkResponse, StateResponse, SubmitAttestationResult,
    SubmitBuilderPreferencesResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingData, SyncingResponse, ValidatorData, ValidatorInfo,
    ValidatorLiveness, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
    WireBody,
};
pub use v4_wire::{
    BuilderConfig, BuilderEntry, BuilderPreferencesEntry, BuilderRequestAuth,
    SignedBuilderRequestAuth, BUILDER_PREFERENCES_PATH, FALLBACK_BUILDER_BOOST_FACTOR,
    FALLBACK_MAX_EXECUTION_PAYMENT, FALLBACK_MIN_BID, FIELD_BLOBS, FIELD_BLOCK,
    FIELD_EXECUTION_PAYLOAD_ENVELOPE, FIELD_KZG_PROOFS, FIELD_SIGNED_EXECUTION_PAYLOAD_ENVELOPE,
    HEADER_ETH_BLOB_DATA_INCLUDED, HEADER_ETH_BUILDER_URL, HEADER_ETH_CONSENSUS_BLOCK_VALUE,
    HEADER_ETH_CONSENSUS_VERSION, HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED,
    HEADER_ETH_EXECUTION_PAYLOAD_VALUE, MAX_BUILDER_ENTRIES, MAX_BUILDER_PUBKEYS,
    MAX_BUILDER_URL_SIZE, PRODUCE_BLOCK_V4_PATH_PREFIX, PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH,
    QUERY_BROADCAST_VALIDATION, QUERY_GRAFFITI, QUERY_INCLUDE_PAYLOAD, QUERY_RANDAO_REVEAL,
    QUERY_SKIP_RANDAO_VERIFICATION, V4_WIRE_REVISION,
};
