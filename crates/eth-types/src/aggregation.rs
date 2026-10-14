use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

use crate::tree_hash_utils::{
    bitlist_tree_hash_root, impl_container_tree_hash, vec_u8_tree_hash_root,
};
use crate::{AttestationData, Signature, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE};

/// `Bitlist[N]` limit for a pre-Electra `Attestation.aggregation_bits` (chunk_count = 8).
const PRE_ELECTRA_AGG_BITS_LIMIT: u64 = MAX_VALIDATORS_PER_COMMITTEE;
/// EIP-7549 `Bitlist[N]` limit for an Electra `Attestation.aggregation_bits`:
/// `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` = 131072 (chunk_count = 512).
const ELECTRA_AGG_BITS_LIMIT: u64 = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(with = "serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationData,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: aggregation_bits, data, signature
impl_container_tree_hash!(
    Attestation,
    "valid aggregation bits",
    [
        |s| bitlist_tree_hash_root(&s.aggregation_bits, PRE_ELECTRA_AGG_BITS_LIMIT),
        |s| Ok(s.data.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.signature)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: Attestation,
    #[serde(with = "crate::serde_signature")]
    pub selection_proof: Signature,
}

// Leaf order: aggregator_index, aggregate, selection_proof
impl_container_tree_hash!(
    AggregateAndProof,
    "valid aggregation bits",
    [
        |s| Ok(s.aggregator_index.tree_hash_root()),
        |s| s.aggregate.try_tree_hash_root(),
        |s| Ok(vec_u8_tree_hash_root(&s.selection_proof)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectraAttestation {
    #[serde(with = "serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationData,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
    #[serde(with = "serde_utils::hex_vec")]
    pub committee_bits: Vec<u8>,
}

// EIP-7549 container field order: aggregation_bits, data, signature, committee_bits
impl_container_tree_hash!(
    ElectraAttestation,
    "valid aggregation bits",
    [
        |s| bitlist_tree_hash_root(&s.aggregation_bits, ELECTRA_AGG_BITS_LIMIT),
        |s| Ok(s.data.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.signature)),
        |s| Ok(vec_u8_tree_hash_root(&s.committee_bits)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectraAggregateAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: ElectraAttestation,
    #[serde(with = "crate::serde_signature")]
    pub selection_proof: Signature,
}

// Leaf order: aggregator_index, aggregate, selection_proof
impl_container_tree_hash!(
    ElectraAggregateAndProof,
    "valid aggregation bits",
    [
        |s| Ok(s.aggregator_index.tree_hash_root()),
        |s| s.aggregate.try_tree_hash_root(),
        |s| Ok(vec_u8_tree_hash_root(&s.selection_proof)),
    ]
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedElectraAggregateAndProof {
    pub message: ElectraAggregateAndProof,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_hash_utils::bitlist_tree_hash_root;
    use crate::Checkpoint;
    use tree_hash::MerkleHasher;

    fn sample_attestation() -> Attestation {
        Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: 3, root: [2u8; 32] },
                target: Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        }
    }

    fn sample_aggregate_and_proof() -> AggregateAndProof {
        AggregateAndProof {
            aggregator_index: 42,
            aggregate: sample_attestation(),
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_attestation_serde_roundtrip() {
        let att = sample_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_aggregate_and_proof_serde_roundtrip() {
        let proof = sample_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: AggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_aggregate_and_proof_quoted_aggregator_index() {
        let proof = sample_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["aggregator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_aggregate_and_proof_serde_roundtrip() {
        let signed = SignedAggregateAndProof {
            message: sample_aggregate_and_proof(),
            signature: vec![0xcc; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedAggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_attestation_empty_aggregation_bits() {
        let att = Attestation {
            aggregation_bits: vec![],
            data: AttestationData {
                slot: 0,
                index: 0,
                beacon_block_root: [0u8; 32],
                source: Checkpoint { epoch: 0, root: [0u8; 32] },
                target: Checkpoint { epoch: 0, root: [0u8; 32] },
            },
            signature: vec![0; 96],
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_attestation_tree_hash_deterministic() {
        let att = sample_attestation();
        let root1 = att.tree_hash_root();
        let root2 = att.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    // kat_exempt: field-sensitivity — different data must yield different roots; not a container-root KAT
    fn test_attestation_tree_hash_different_data_different_root() {
        let att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att2.data.slot = 999;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_aggregate_and_proof_tree_hash_deterministic() {
        let proof = sample_aggregate_and_proof();
        let root1 = proof.tree_hash_root();
        let root2 = proof.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    // kat_exempt: field-sensitivity — different aggregator_index must yield different roots; not a container-root KAT
    fn test_aggregate_and_proof_tree_hash_different_index_different_root() {
        let proof1 = sample_aggregate_and_proof();
        let mut proof2 = sample_aggregate_and_proof();
        proof2.aggregator_index = 99;
        assert_ne!(proof1.tree_hash_root(), proof2.tree_hash_root());
    }

    #[test]
    fn test_attestation_try_tree_hash_root_invalid_bits() {
        let mut att = sample_attestation();
        att.aggregation_bits = vec![0x00];
        assert!(att.try_tree_hash_root().is_err());
    }

    #[test]
    fn test_aggregate_and_proof_try_tree_hash_root_invalid_bits() {
        let mut proof = sample_aggregate_and_proof();
        proof.aggregate.aggregation_bits = vec![0x00];
        assert!(proof.try_tree_hash_root().is_err());
    }

    fn sample_electra_attestation() -> ElectraAttestation {
        ElectraAttestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot: 100,
                // EIP-7549: index must be 0 for Electra attestations
                index: 0,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: 3, root: [2u8; 32] },
                target: Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01; 8],
        }
    }

    fn sample_electra_aggregate_and_proof() -> ElectraAggregateAndProof {
        ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: sample_electra_attestation(),
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_electra_attestation_serde_roundtrip() {
        let att = sample_electra_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: ElectraAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_electra_attestation_tree_hash_deterministic() {
        let att = sample_electra_attestation();
        let root1 = att.tree_hash_root();
        let root2 = att.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_electra_attestation_tree_hash_sensitive_to_aggregation_bits() {
        let att1 = sample_electra_attestation();
        let mut att2 = sample_electra_attestation();
        att2.aggregation_bits = vec![0x01; 4];
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_electra_attestation_tree_hash_sensitive_to_data() {
        let att1 = sample_electra_attestation();
        let mut att2 = sample_electra_attestation();
        att2.data.slot = 999;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_electra_attestation_tree_hash_sensitive_to_signature() {
        let att1 = sample_electra_attestation();
        let mut att2 = sample_electra_attestation();
        att2.signature = vec![0xbb; 96];
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_electra_attestation_tree_hash_sensitive_to_committee_bits() {
        let att1 = sample_electra_attestation();
        let mut att2 = sample_electra_attestation();
        att2.committee_bits = vec![0x02; 8];
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_electra_aggregate_and_proof_serde_roundtrip() {
        let proof = sample_electra_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ElectraAggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_electra_aggregate_and_proof_quoted_aggregator_index() {
        let proof = sample_electra_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["aggregator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_electra_aggregate_and_proof_tree_hash_deterministic() {
        let proof = sample_electra_aggregate_and_proof();
        let root1 = proof.tree_hash_root();
        let root2 = proof.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_electra_aggregate_and_proof_tree_hash_sensitive_to_index() {
        let proof1 = sample_electra_aggregate_and_proof();
        let mut proof2 = sample_electra_aggregate_and_proof();
        proof2.aggregator_index = 99;
        assert_ne!(proof1.tree_hash_root(), proof2.tree_hash_root());
    }

    #[test]
    fn test_electra_aggregate_and_proof_tree_hash_sensitive_to_aggregate() {
        let proof1 = sample_electra_aggregate_and_proof();
        let mut proof2 = sample_electra_aggregate_and_proof();
        proof2.aggregate.data.slot = 999;
        assert_ne!(proof1.tree_hash_root(), proof2.tree_hash_root());
    }

    #[test]
    fn test_electra_aggregate_and_proof_tree_hash_sensitive_to_selection_proof() {
        let proof1 = sample_electra_aggregate_and_proof();
        let mut proof2 = sample_electra_aggregate_and_proof();
        proof2.selection_proof = vec![0xcc; 96];
        assert_ne!(proof1.tree_hash_root(), proof2.tree_hash_root());
    }

    #[test]
    fn test_signed_electra_aggregate_and_proof_serde_roundtrip() {
        let signed = SignedElectraAggregateAndProof {
            message: sample_electra_aggregate_and_proof(),
            signature: vec![0xcc; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedElectraAggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_electra_attestation_tree_hash_spec_field_order() {
        let att = sample_electra_attestation();

        let mut hasher = MerkleHasher::with_leaves(4);
        hasher
            .write(
                bitlist_tree_hash_root(&att.aggregation_bits, ELECTRA_AGG_BITS_LIMIT)
                    .unwrap()
                    .as_slice(),
            )
            .expect("leaf");
        hasher.write(att.data.tree_hash_root().as_slice()).expect("leaf");
        hasher.write(vec_u8_tree_hash_root(&att.signature).as_slice()).expect("leaf");
        hasher.write(vec_u8_tree_hash_root(&att.committee_bits).as_slice()).expect("leaf");
        let expected = hasher.finish().expect("root");

        assert_eq!(att.tree_hash_root(), expected, "tree_hash_root must match spec field order");
    }

    #[test]
    fn test_electra_attestation_wrong_field_order_differs() {
        let att = sample_electra_attestation();

        let mut hasher = MerkleHasher::with_leaves(4);
        hasher
            .write(
                bitlist_tree_hash_root(&att.aggregation_bits, ELECTRA_AGG_BITS_LIMIT)
                    .unwrap()
                    .as_slice(),
            )
            .expect("leaf");
        hasher.write(att.data.tree_hash_root().as_slice()).expect("leaf");
        hasher.write(vec_u8_tree_hash_root(&att.committee_bits).as_slice()).expect("leaf");
        hasher.write(vec_u8_tree_hash_root(&att.signature).as_slice()).expect("leaf");
        let wrong_root = hasher.finish().expect("root");

        assert_ne!(
            att.tree_hash_root(),
            wrong_root,
            "tree_hash_root must differ from wrong field order"
        );
    }

    // Known-answer test pinning the Electra `Attestation` tree-hash root to the TRUE consensus-spec
    // root, so leaf order can no longer be silently re-swapped (report §4.1, Decision Log D3) AND
    // the `aggregation_bits` leaf is byte-equal to the SSZ spec (bitlist limit-padding fix).
    //
    // Provenance of the golden root (EXTERNAL oracle, not rvc's own helpers):
    //   Derived with `remerkleable` (the consensus-spec SSZ implementation) modelling the exact
    //   EIP-7549 Electra `Attestation` container:
    //     aggregation_bits : Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
    //                        = Bitlist[131072]  (chunk_count 512), value = SSZ [0xff;4] (31 bits set)
    //     data             : AttestationData{slot:100,index:0,bbr:[1;32],src{3,[2;32]},tgt{4,[3;32]}}
    //     signature        : Vector[byte, 96]  = [0xaa;96]
    //     committee_bits   : Bitvector[64]      = SSZ [0x01;8]  (bit 0 set)
    //   remerkleable per-leaf roots:
    //     leaf0 aggregation_bits = 0x0acb28fe2d45369378d2ec4fd21993e5bf593d2b62d1493da535c6c3978e37a3
    //     leaf1 data             = 0x3810cbc2daad89c727791c249ea17025b976d05c2fd41344285bc86ecd5105c6
    //     leaf2 signature        = 0x31e174b330d124df75b7fbe184191693a4c9820e5f82bcaa41f6f22bd3f2fb68
    //     leaf3 committee_bits   = 0x0101010101010101000000000000000000000000000000000000000000000000
    //     root = sha256( sha256(leaf0‖leaf1) ‖ sha256(leaf2‖leaf3) )
    //          = 0x26b23c318b00c7e774670fa8c54f3ba256018f798226d717df0d82c2e143914f
    //   Leaves 1/2/3 are byte-identical to the previous (self-consistent) literal; only leaf 0
    //   changed once bitlist_tree_hash_root pads the chunk tree to chunk_count(131072)=512. The old
    //   literal 0x452361d8…2128fe4 was spec-divergent and is intentionally replaced here.
    const ELECTRA_ATTESTATION_KNOWN_ROOT: [u8; 32] = [
        0x26, 0xb2, 0x3c, 0x31, 0x8b, 0x00, 0xc7, 0xe7, 0x74, 0x67, 0x0f, 0xa8, 0xc5, 0x4f, 0x3b,
        0xa2, 0x56, 0x01, 0x8f, 0x79, 0x82, 0x26, 0xd7, 0x17, 0xdf, 0x0d, 0x82, 0xc2, 0xe1, 0x43,
        0x91, 0x4f,
    ];

    #[test]
    fn test_electra_attestation_tree_hash_known_answer() {
        let att = sample_electra_attestation();
        assert_eq!(
            att.tree_hash_root().as_slice(),
            ELECTRA_ATTESTATION_KNOWN_ROOT.as_slice(),
            "tree_hash_root must equal the EIP-7549 per-leaf known-answer root"
        );
    }

    #[test]
    fn test_electra_attestation_try_tree_hash_root_invalid_bits() {
        let mut att = sample_electra_attestation();
        att.aggregation_bits = vec![0x00];
        assert!(att.try_tree_hash_root().is_err());
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        fn arb_attestation_data() -> impl Strategy<Value = AttestationData> {
            (
                any::<u64>(),
                any::<u64>(),
                any::<[u8; 32]>(),
                any::<u64>(),
                any::<[u8; 32]>(),
                any::<u64>(),
                any::<[u8; 32]>(),
            )
                .prop_map(
                    |(slot, index, bbr, src_epoch, src_root, tgt_epoch, tgt_root)| {
                        AttestationData {
                            slot,
                            index,
                            beacon_block_root: bbr,
                            source: Checkpoint { epoch: src_epoch, root: src_root },
                            target: Checkpoint { epoch: tgt_epoch, root: tgt_root },
                        }
                    },
                )
        }

        fn arb_attestation() -> impl Strategy<Value = Attestation> {
            (
                proptest::collection::vec(any::<u8>(), 0..128),
                arb_attestation_data(),
                proptest::collection::vec(any::<u8>(), 96..=96),
            )
                .prop_map(|(bits, data, sig)| Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: sig,
                })
        }

        fn arb_electra_attestation() -> impl Strategy<Value = ElectraAttestation> {
            (
                proptest::collection::vec(any::<u8>(), 0..128),
                arb_attestation_data(),
                proptest::collection::vec(any::<u8>(), 96..=96),
                proptest::collection::vec(any::<u8>(), 0..64),
            )
                .prop_map(|(bits, data, sig, committee)| ElectraAttestation {
                    aggregation_bits: bits,
                    data,
                    signature: sig,
                    committee_bits: committee,
                })
        }

        proptest! {
            #[test]
            fn fuzz_attestation_try_tree_hash_root_no_panic(att in arb_attestation()) {
                let _ = att.try_tree_hash_root();
            }

            #[test]
            fn fuzz_electra_attestation_try_tree_hash_root_no_panic(att in arb_electra_attestation()) {
                let _ = att.try_tree_hash_root();
            }

            #[test]
            fn fuzz_attestation_serde_roundtrip(att in arb_attestation()) {
                let json = serde_json::to_string(&att).unwrap();
                let deserialized: Attestation = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(att, deserialized);
            }

            #[test]
            fn fuzz_aggregate_and_proof_try_tree_hash_root_no_panic(
                att in arb_attestation(),
                idx in any::<u64>(),
                proof in proptest::collection::vec(any::<u8>(), 96..=96),
            ) {
                let agg = AggregateAndProof {
                    aggregator_index: idx,
                    aggregate: att,
                    selection_proof: proof,
                };
                let _ = agg.try_tree_hash_root();
            }

            #[test]
            fn fuzz_electra_aggregate_and_proof_try_tree_hash_root_no_panic(
                att in arb_electra_attestation(),
                idx in any::<u64>(),
                proof in proptest::collection::vec(any::<u8>(), 96..=96),
            ) {
                let agg = ElectraAggregateAndProof {
                    aggregator_index: idx,
                    aggregate: att,
                    selection_proof: proof,
                };
                let _ = agg.try_tree_hash_root();
            }
        }
    }

    #[test]
    fn test_electra_aggregate_and_proof_try_tree_hash_root_invalid_bits() {
        let mut proof = sample_electra_aggregate_and_proof();
        proof.aggregate.aggregation_bits = vec![0x00];
        assert!(proof.try_tree_hash_root().is_err());
    }
}
