use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

use crate::hex_fixed::{bytes_32_hex, bytes_48_hex};
use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root};
use crate::{Root, Signature, Slot};

/// Total validators in a sync committee (Altair+).
pub const SYNC_COMMITTEE_SIZE: u64 = 512;

/// Number of subnets the sync committee is split across.
pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

/// Target number of aggregators per sync subcommittee.
pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;

/// Map a validator's position in the full sync committee to its subcommittee index.
///
/// Spec: `subcommittee_index = position // (SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT)`.
#[inline]
pub fn subcommittee_index(pos: u64) -> u64 {
    pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT)
}

/// Returns `true` when `selection_proof` selects the validator as a sync
/// committee aggregator (`sha256(proof)[0..8] as u64 % modulo == 0`).
pub fn is_sync_committee_aggregator(selection_proof: &[u8]) -> bool {
    let modulo = (SYNC_COMMITTEE_SIZE
        / SYNC_COMMITTEE_SUBNET_COUNT
        / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
        .max(1);

    let hash = Sha256::digest(selection_proof);
    let value = u64::from_le_bytes(hash[0..8].try_into().expect("sha256 output is 32 bytes"));
    value % modulo == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "bytes_32_hex")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeDuty {
    #[serde(with = "bytes_48_hex")]
    pub pubkey: [u8; 48],
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validator_sync_committee_indices: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeContribution {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "bytes_32_hex")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: slot, beacon_block_root, subcommittee_index, aggregation_bits, signature
impl_container_tree_hash!(
    SyncCommitteeContribution,
    "valid SyncCommitteeContribution",
    [
        |s| Ok(s.slot.tree_hash_root()),
        |s| Ok(s.beacon_block_root.tree_hash_root()),
        |s| Ok(s.subcommittee_index.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.aggregation_bits)),
        |s| Ok(vec_u8_tree_hash_root(&s.signature)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregatorSelectionData {
    pub slot: Slot,
    pub subcommittee_index: u64,
}

// Leaf order: slot, subcommittee_index
impl_container_tree_hash!(
    SyncAggregatorSelectionData,
    "valid SyncAggregatorSelectionData",
    [|s| Ok(s.slot.tree_hash_root()), |s| Ok(s.subcommittee_index.tree_hash_root()),]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub contribution: SyncCommitteeContribution,
    #[serde(with = "crate::serde_signature")]
    pub selection_proof: Signature,
}

// Leaf order: aggregator_index, contribution, selection_proof
impl_container_tree_hash!(
    ContributionAndProof,
    "valid ContributionAndProof",
    [
        |s| Ok(s.aggregator_index.tree_hash_root()),
        |s| Ok(s.contribution.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.selection_proof)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContributionAndProof {
    pub message: ContributionAndProof,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::MerkleHasher;

    /// Pins `subcommittee_index` to the legacy expression that used to live in
    /// the orchestrator (F99 / RF3-20).
    #[test]
    fn test_subcommittee_index_matches_both_legacy_closures() {
        for pos in 0..SYNC_COMMITTEE_SIZE {
            let legacy = pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT);
            assert_eq!(
                subcommittee_index(pos),
                legacy,
                "pos={pos}: helper must match legacy closure"
            );
        }
        // Boundary checks matching the former drift-detection KAT.
        assert_eq!(subcommittee_index(0), 0);
        assert_eq!(subcommittee_index(127), 0);
        assert_eq!(subcommittee_index(128), 1);
        assert_eq!(subcommittee_index(255), 1);
        assert_eq!(subcommittee_index(256), 2);
        assert_eq!(subcommittee_index(383), 2);
        assert_eq!(subcommittee_index(384), 3);
        assert_eq!(subcommittee_index(511), 3);
    }

    fn find_aggregator_proof() -> Vec<u8> {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo == 0 {
                return proof;
            }
        }
        unreachable!()
    }

    fn find_non_aggregator_proof() -> Vec<u8> {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo != 0 {
                return proof;
            }
        }
        unreachable!()
    }

    #[test]
    fn test_is_sync_committee_aggregator_kat() {
        let proof = find_aggregator_proof();
        assert!(is_sync_committee_aggregator(&proof));

        let non = find_non_aggregator_proof();
        assert!(!is_sync_committee_aggregator(&non));

        // 512 / 4 / 16 = 8
        let modulo = SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE;
        assert_eq!(modulo, 8);

        // Empty proof: SHA256("") first 8 LE bytes % 8
        let result = is_sync_committee_aggregator(&[]);
        let hash = Sha256::digest([]);
        let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        assert_eq!(result, value % 8 == 0);
    }

    fn sample_sync_committee_message() -> SyncCommitteeMessage {
        SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [1u8; 32],
            validator_index: 42,
            signature: vec![0xaa; 96],
        }
    }

    fn sample_sync_committee_duty() -> SyncCommitteeDuty {
        SyncCommitteeDuty {
            pubkey: [0xab; 48],
            validator_index: 42,
            validator_sync_committee_indices: vec![0, 128, 256],
        }
    }

    fn sample_contribution() -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot: 100,
            beacon_block_root: [1u8; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        }
    }

    fn sample_contribution_and_proof() -> ContributionAndProof {
        ContributionAndProof {
            aggregator_index: 42,
            contribution: sample_contribution(),
            selection_proof: vec![0xcc; 96],
        }
    }

    #[test]
    fn test_sync_committee_message_serde_roundtrip() {
        let msg = sample_sync_committee_message();
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: SyncCommitteeMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_sync_committee_message_quoted_integers() {
        let msg = sample_sync_committee_message();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_sync_committee_duty_serde_roundtrip() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: SyncCommitteeDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    #[test]
    fn test_sync_committee_duty_quoted_validator_index() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_sync_committee_duty_quoted_indices() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let indices = parsed["validator_sync_committee_indices"].as_array().unwrap();
        assert_eq!(indices[0], serde_json::Value::String("0".to_string()));
        assert_eq!(indices[1], serde_json::Value::String("128".to_string()));
        assert_eq!(indices[2], serde_json::Value::String("256".to_string()));
    }

    #[test]
    fn test_sync_committee_duty_empty_indices() {
        let duty = SyncCommitteeDuty {
            pubkey: [0x12; 48],
            validator_index: 0,
            validator_sync_committee_indices: vec![],
        };
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: SyncCommitteeDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    /// RF3-16: malformed BN pubkey must fail serde, not land as a free-form String.
    #[test]
    fn test_sync_committee_duty_rejects_malformed_pubkey() {
        let invalid_hex = r#"{
            "pubkey": "0xzz",
            "validator_index": "42",
            "validator_sync_committee_indices": ["0"]
        }"#;
        assert!(
            serde_json::from_str::<SyncCommitteeDuty>(invalid_hex).is_err(),
            "non-hex pubkey must fail deserialize"
        );

        let wrong_len = format!(
            r#"{{
            "pubkey": "0x{}",
            "validator_index": "42",
            "validator_sync_committee_indices": ["0"]
        }}"#,
            "ab".repeat(32)
        );
        assert!(
            serde_json::from_str::<SyncCommitteeDuty>(&wrong_len).is_err(),
            "wrong-length pubkey must fail deserialize"
        );

        let bare = format!(
            r#"{{
            "pubkey": "{}",
            "validator_index": "42",
            "validator_sync_committee_indices": ["0"]
        }}"#,
            "ab".repeat(48)
        );
        assert!(
            serde_json::from_str::<SyncCommitteeDuty>(&bare).is_err(),
            "bare (no 0x) pubkey must fail deserialize — Beacon API requires 0x"
        );
    }

    /// RF3-16: JSON wire form stays `0x` + 96 hex chars (same as ProposerDuty).
    #[test]
    fn test_sync_committee_duty_json_wire_form_unchanged() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected = format!("0x{}", "ab".repeat(48));
        assert_eq!(parsed["pubkey"], serde_json::Value::String(expected));

        // Recorded BN-shaped body: re-encode must stay byte-identical on pubkey.
        let recorded = format!(
            r#"{{"pubkey":"0x{}","validator_index":"42","validator_sync_committee_indices":["0","128","256"]}}"#,
            "ab".repeat(48)
        );
        let decoded: SyncCommitteeDuty = serde_json::from_str(&recorded).unwrap();
        assert_eq!(decoded.pubkey, [0xab; 48]);
        let re_encoded = serde_json::to_string(&decoded).unwrap();
        let re_parsed: serde_json::Value = serde_json::from_str(&re_encoded).unwrap();
        let orig: serde_json::Value = serde_json::from_str(&recorded).unwrap();
        assert_eq!(re_parsed["pubkey"], orig["pubkey"]);
    }

    #[test]
    fn test_sync_committee_contribution_serde_roundtrip() {
        let contribution = sample_contribution();
        let json = serde_json::to_string(&contribution).unwrap();
        let deserialized: SyncCommitteeContribution = serde_json::from_str(&json).unwrap();
        assert_eq!(contribution, deserialized);
    }

    #[test]
    fn test_sync_committee_contribution_quoted_integers() {
        let contribution = sample_contribution();
        let json = serde_json::to_string(&contribution).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["subcommittee_index"], serde_json::Value::String("2".to_string()));
    }

    #[test]
    fn test_contribution_and_proof_serde_roundtrip() {
        let proof = sample_contribution_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ContributionAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_contribution_and_proof_quoted_aggregator_index() {
        let proof = sample_contribution_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["aggregator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_contribution_and_proof_serde_roundtrip() {
        let signed = SignedContributionAndProof {
            message: sample_contribution_and_proof(),
            signature: vec![0xdd; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedContributionAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    // -- TreeHash tests (Finding #20) --

    #[test]
    fn test_sync_committee_contribution_tree_hash_deterministic() {
        let contrib = sample_contribution();
        let hash1 = contrib.tree_hash_root();
        let hash2 = contrib.tree_hash_root();
        assert_eq!(hash1, hash2, "tree hash must be deterministic for identical input");
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_slot() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.slot += 1;
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different slot must produce different tree hash"
        );
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_subcommittee() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.subcommittee_index += 1;
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different subcommittee_index must produce different tree hash"
        );
    }

    #[test]
    // kat_exempt: field-sensitivity — different beacon_block_root must yield different roots; not a container-root KAT
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_block_root() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.beacon_block_root = [2u8; 32];
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different beacon_block_root must produce different tree hash"
        );
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_leaf_count() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let contrib = sample_contribution();
        let actual_hash = contrib.tree_hash_root();

        // Manually compute with 5 leaves to lock in the correct leaf count
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(contrib.slot.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.beacon_block_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.subcommittee_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.aggregation_bits).as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.signature).as_slice()).unwrap();
        let expected_hash = hasher.finish().unwrap();

        assert_eq!(
            actual_hash, expected_hash,
            "tree_hash_root must match manual computation with 5 leaves"
        );
    }

    #[test]
    fn test_sync_committee_contribution_wrong_leaf_count_differs() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let contrib = sample_contribution();
        let correct_hash = contrib.tree_hash_root();

        // Compute with wrong leaf count (4 instead of 5) — must produce a different hash.
        // with_leaves(4) only accepts 4 writes, so the 5th write will error.
        // This proves the leaf count matters: changing with_leaves(5) to with_leaves(4)
        // would break the implementation.
        let mut hasher = MerkleHasher::with_leaves(4);
        hasher.write(contrib.slot.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.beacon_block_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.subcommittee_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.aggregation_bits).as_slice()).unwrap();
        // 5th write would fail with 4 leaves — the hash from 4 leaves differs from 5
        let wrong_hash = hasher.finish().unwrap();

        assert_ne!(
            correct_hash, wrong_hash,
            "with_leaves(4) must produce different hash than with_leaves(5)"
        );
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_deterministic() {
        let proof = sample_contribution_and_proof();
        let hash1 = proof.tree_hash_root();
        let hash2 = proof.tree_hash_root();
        assert_eq!(hash1, hash2, "ContributionAndProof tree hash must be deterministic");
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_field_sensitivity() {
        let proof1 = sample_contribution_and_proof();
        let mut proof2 = proof1.clone();
        proof2.aggregator_index += 1;
        assert_ne!(
            proof1.tree_hash_root(),
            proof2.tree_hash_root(),
            "different aggregator_index must produce different tree hash"
        );
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_leaf_count() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let proof = sample_contribution_and_proof();
        let actual_hash = proof.tree_hash_root();

        // Manually compute with 3 leaves to lock in the correct leaf count
        let mut hasher = MerkleHasher::with_leaves(3);
        hasher.write(proof.aggregator_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(proof.contribution.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&proof.selection_proof).as_slice()).unwrap();
        let expected_hash = hasher.finish().unwrap();

        assert_eq!(
            actual_hash, expected_hash,
            "tree_hash_root must match manual computation with 3 leaves"
        );
    }

    #[test]
    fn test_contribution_and_proof_wrong_leaf_count_differs() {
        let proof = sample_contribution_and_proof();
        let correct_hash = proof.tree_hash_root();

        // Compute with wrong leaf count (2 instead of 3) — must produce different hash
        let mut hasher = MerkleHasher::with_leaves(2);
        hasher.write(proof.aggregator_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(proof.contribution.tree_hash_root().as_slice()).unwrap();
        let wrong_hash = hasher.finish().unwrap();

        assert_ne!(
            correct_hash, wrong_hash,
            "with_leaves(2) must produce different hash than with_leaves(3)"
        );
    }
}
