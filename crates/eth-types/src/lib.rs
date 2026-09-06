use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

mod aggregation;
mod aggregator;
mod attestation;
mod block;
/// Typed BeaconBlockBody containers + SSZ decode (SEC-6b; foundation for SEC-6c wire).
///
/// Path C (ARCH-7h): one struct per container. Crate-root types carry both
/// `ssz` 0.9 and `ssz08` 0.8 codecs; see `block_body` module docs.
pub mod block_body;
mod builder;
pub mod canonical;
mod deposit;
mod domains;
mod duties;
mod fork;
pub(crate) mod hex_fixed;
pub mod networks;
mod payload_attestation;
mod proposer_preferences;
pub(crate) mod serde_signature;
pub mod ssz_helpers;
mod sync_committee;
pub(crate) mod tree_hash_utils;
pub use aggregation::{
    AggregateAndProof, Attestation, ElectraAggregateAndProof, ElectraAttestation,
    SignedAggregateAndProof, SignedElectraAggregateAndProof,
};
pub use attestation::SingleAttestation;
pub use block::{
    body_fork_layout, kzg_commitment_list_root, BeaconBlock, BeaconBlockBody, BeaconBlockHeader,
    BlindedBeaconBlock, BlindedBeaconBlockBody, BlobSidecar, BlockContents, BodyForkLayout,
    ProducedBlock, SignedBeaconBlock, SignedBlindedBeaconBlock,
};
pub use block_body::{
    blinded_body_tree_hash_root, blinded_body_tree_hash_root_for_layout, body_tree_hash_root,
    body_tree_hash_root_for_layout, decode_beacon_block_body_deneb,
    decode_beacon_block_body_electra, decode_blinded_beacon_block_body_deneb,
    decode_blinded_beacon_block_body_electra, BeaconBlockBodyDeneb, BeaconBlockBodyElectra,
    BlindedBeaconBlockBodyDeneb, BlindedBeaconBlockBodyElectra, BodySszError, ExecutionPayload,
    ExecutionPayloadHeader, ExecutionRequests, SyncAggregate,
};

/// Deterministic SSZ/KAT bodies and known roots for tests (RF3-19 / G5).
///
/// Compiled only when the `test-fixtures` feature is enabled. Consumer crates
/// should pull it in via a dev-dependency:
/// `eth-types = { workspace = true, features = ["test-fixtures"] }`.
#[cfg(feature = "test-fixtures")]
pub mod fixtures {
    pub use crate::block::{
        external_vector_deneb_blinded_block, external_vector_deneb_block,
        external_vector_electra_blinded_block, external_vector_electra_block,
    };
    pub use crate::block_body::{
        external_vector_blinded_deneb_body, external_vector_blinded_electra_body,
        external_vector_deneb_body, external_vector_electra_body,
        external_vector_execution_payload_header, EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX,
        EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX, EXTERNAL_DENEB_BLOCK_ROOT_HEX,
        EXTERNAL_DENEB_BODY_ROOT_HEX, EXTERNAL_ELECTRA_BLOCK_ROOT_HEX,
        EXTERNAL_ELECTRA_BODY_ROOT_HEX,
    };
}

// Crate-root re-exports so existing `eth_types::external_vector_*` / `EXTERNAL_*`
// paths keep working when the feature is on (dev builds / tests).
pub use aggregator::is_aggregator;
pub use builder::{SignedValidatorRegistration, ValidatorRegistrationV1};
pub use deposit::{BLSToExecutionChange, DepositData, DepositMessage, SignedBLSToExecutionChange};
pub use domains::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_DEPOSIT, DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT,
};
pub use duties::{ProposerDuty, SignedVoluntaryExit, VoluntaryExit};
#[cfg(feature = "test-fixtures")]
pub use fixtures::*;
pub use fork::{ForkName, ForkSchedule, ParseForkNameError, UnknownForkIdError};
pub use networks::{from_name as network_from_name, NetworkPreset, ALL as NETWORK_PRESETS};
pub use payload_attestation::{PayloadAttestationData, PayloadAttestationMessage};
pub use proposer_preferences::{ProposerPreferences, SignedProposerPreferences};
pub use ssz_helpers::{
    decode_attestation_ssz, decode_beacon_block_ssz, decode_blinded_beacon_block_ssz,
    decode_sync_committee_contribution_ssz, encode_attestation_ssz, encode_beacon_block_ssz,
    encode_blinded_beacon_block_ssz, encode_sync_committee_contribution_ssz, SszDecodeError,
};
pub use sync_committee::{
    is_sync_committee_aggregator, subcommittee_index, ContributionAndProof,
    SignedContributionAndProof, SyncAggregatorSelectionData, SyncCommitteeContribution,
    SyncCommitteeDuty, SyncCommitteeMessage, SYNC_COMMITTEE_SIZE, SYNC_COMMITTEE_SUBNET_COUNT,
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
};
pub use tree_hash_utils::TreeHashError;

pub type Slot = u64;
pub type Epoch = u64;
pub type CommitteeIndex = u64;
pub type Version = [u8; 4];
pub type Root = [u8; 32];
pub type Domain = [u8; 32];
pub type DomainType = [u8; 4];
pub type Signature = Vec<u8>;

/// Expected length of a BLS signature in bytes.
pub const SIGNATURE_BYTES_LEN: usize = 96;

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SLOT_DURATION_MS: u64 = 12_000;
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

/// SSZ preset bound on a single committee's size. Sets the `Bitlist[N]` limit for a pre-Electra
/// `Attestation.aggregation_bits` (chunk_count = ceil(2048 / 256) = 8).
pub const MAX_VALIDATORS_PER_COMMITTEE: u64 = 2048;
/// EIP-7549 preset bound on committees aggregated into one Electra attestation. The Electra
/// `Attestation.aggregation_bits` is `Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]`.
pub const MAX_COMMITTEES_PER_SLOT: u64 = 64;

/// Consensus specification version this client implements.
pub const CONSENSUS_SPEC_VERSION: &str = "v1.5.0-alpha.12";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: CommitteeIndex,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Fork {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub previous_version: Version,
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: Version,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ForkData {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: Version,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub genesis_validators_root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SigningData {
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub object_root: Root,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub domain: Domain,
}

/// Fork context used for domain computation in signed duties.
/// Carries both the current fork version and the genesis validators root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkInfo {
    pub previous_version: Version,
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn test_checkpoint_ssz_encode() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let encoded = checkpoint.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 32);
    }

    #[test]
    fn test_attestation_data_ssz_encode() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let encoded = data.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 8 + 32 + 40 + 40);
    }

    #[test]
    fn test_fork_ssz_encode() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let encoded = fork.as_ssz_bytes();
        assert_eq!(encoded.len(), 4 + 4 + 8);
    }

    #[test]
    fn test_fork_data_ssz_encode() {
        let fork_data =
            ForkData { current_version: [1, 0, 0, 0], genesis_validators_root: [0u8; 32] };
        let encoded = fork_data.as_ssz_bytes();
        assert_eq!(encoded.len(), 4 + 32);
    }

    #[test]
    fn test_signing_data_ssz_encode() {
        let signing_data = SigningData { object_root: [0u8; 32], domain: [1u8; 32] };
        let encoded = signing_data.as_ssz_bytes();
        assert_eq!(encoded.len(), 32 + 32);
    }

    #[test]
    fn test_checkpoint_quoted_epoch_serialization() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let json = serde_json::to_string(&checkpoint).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_checkpoint_root_hex_serialization() {
        let checkpoint = Checkpoint { epoch: 100, root: [0xab; 32] };
        let json = serde_json::to_string(&checkpoint).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_hex = format!("0x{}", "ab".repeat(32));
        assert_eq!(parsed["root"], serde_json::Value::String(expected_hex));
    }

    #[test]
    fn test_checkpoint_root_hex_deserialization() {
        let hex_root = format!("0x{}", "ab".repeat(32));
        let json = format!(r#"{{"epoch":"100","root":"{}"}}"#, hex_root);
        let checkpoint: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint.epoch, 100);
        assert_eq!(checkpoint.root, [0xab; 32]);
    }

    #[test]
    fn test_checkpoint_json_roundtrip() {
        let original = Checkpoint { epoch: 42, root: [0xab; 32] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_attestation_data_quoted_integers_serialization() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let json = serde_json::to_string(&data).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("1000".to_string()));
        assert_eq!(parsed["index"], serde_json::Value::String("5".to_string()));
        assert_eq!(parsed["source"]["epoch"], serde_json::Value::String("99".to_string()));
        assert_eq!(parsed["target"]["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_attestation_data_json_roundtrip() {
        let original = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AttestationData = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_fork_quoted_epoch_serialization() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&fork).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_fork_json_roundtrip() {
        let original =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Fork = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_fork_version_hex_serialization() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&fork).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["previous_version"], serde_json::Value::String("0x00000000".to_string()));
        assert_eq!(parsed["current_version"], serde_json::Value::String("0x01000000".to_string()));
    }

    #[test]
    fn test_checkpoint_ssz_unaffected_by_serde() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let encoded = checkpoint.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 32);
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(checkpoint, decoded);
    }

    #[test]
    fn test_attestation_data_ssz_unaffected_by_serde() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let encoded = data.as_ssz_bytes();
        let decoded = AttestationData::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_fork_ssz_unaffected_by_serde() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let encoded = fork.as_ssz_bytes();
        let decoded = Fork::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(fork, decoded);
    }

    #[test]
    fn test_consensus_spec_version_exists_and_starts_with_v() {
        assert!(CONSENSUS_SPEC_VERSION.starts_with('v'));
    }
}
