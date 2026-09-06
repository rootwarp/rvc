//! Gloas attestation family: progressive `Attestation` / `IndexedAttestation`
//! and the plain closures that embed them.
//!
//! First production callers land in later island issues (5.9, 5.10).

#![allow(dead_code)]

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{ProgressiveBitlist, ProgressiveList, SszBitvector};

use super::leaves::AttestationData;

/// Gloas `Attestation` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class Attestation(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=4)`. `N` is `MAX_COMMITTEES_PER_SLOT`
/// (minimal 4, mainnet 64). `aggregation_bits` is `ProgressiveBitlist`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1])]
pub(crate) struct Attestation<const N: usize> {
    pub(crate) aggregation_bits: ProgressiveBitlist,
    pub(crate) data: AttestationData,
    pub(crate) signature: [u8; 96],
    pub(crate) committee_bits: SszBitvector<N>,
}

/// Gloas `IndexedAttestation` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class IndexedAttestation(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=3)`. `attesting_indices` is
/// `ProgressiveList[ValidatorIndex]`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1])]
pub(crate) struct IndexedAttestation {
    pub(crate) attesting_indices: ProgressiveList<u64>,
    pub(crate) data: AttestationData,
    pub(crate) signature: [u8; 96],
}

/// Plain container whose two children are progressive `IndexedAttestation`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct AttesterSlashing {
    pub(crate) attestation_1: IndexedAttestation,
    pub(crate) attestation_2: IndexedAttestation,
}

/// Plain container embedding progressive `Attestation`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct AggregateAndProof<const N: usize> {
    pub(crate) aggregator_index: u64,
    pub(crate) aggregate: Attestation<N>,
    pub(crate) selection_proof: [u8; 96],
}

/// Plain container embedding `AggregateAndProof`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedAggregateAndProof<const N: usize> {
    pub(crate) message: AggregateAndProof<N>,
    pub(crate) signature: [u8; 96],
}

#[cfg(test)]
mod tests {
    use super::{
        AggregateAndProof, Attestation, AttesterSlashing, IndexedAttestation,
        SignedAggregateAndProof,
    };
    use crate::containers::leaves::AttestationData;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::SszDecode;
    use libssz_derive::{HashTreeRoot, SszDecode};
    use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};
    use libssz_types::{ProgressiveBitlist, ProgressiveList, SszBitvector};

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        assert_eq!(hex.len() % 2, 0, "SPEC_* hex must have even length, got {}", hex.len());
        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let s = core::str::from_utf8(chunk).expect("hex digits are utf8");
                u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"))
            })
            .collect()
    }

    fn parse_root(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
        parse_hex(hex).try_into().expect("64 hex chars decode to 32 bytes")
    }

    fn assert_ssz_matches_spec_root<T>(ssz_hex: &str, root_hex: &str)
    where
        T: SszDecode + libssz_merkle::HashTreeRoot,
    {
        let bytes = parse_hex(ssz_hex);
        let decoded = T::from_ssz_bytes(&bytes).expect("SSZ decode");
        let got = decoded.hash_tree_root(&Sha2Hasher);
        assert_eq!(got, parse_root(root_hex));
    }

    #[test]
    fn test_attestation_hash_tree_root() {
        assert_ssz_matches_spec_root::<Attestation<4>>(
            minimal::SPEC_GLOAS_ATTESTATION_SSZ,
            minimal::SPEC_GLOAS_ATTESTATION_ROOT,
        );
        assert_ssz_matches_spec_root::<Attestation<64>>(
            mainnet::SPEC_GLOAS_ATTESTATION_SSZ,
            mainnet::SPEC_GLOAS_ATTESTATION_ROOT,
        );
        assert_ne!(minimal::SPEC_GLOAS_ATTESTATION_ROOT, mainnet::SPEC_GLOAS_ATTESTATION_ROOT);
    }

    #[test]
    fn test_indexed_attestation_hash_tree_root() {
        assert_ssz_matches_spec_root::<IndexedAttestation>(
            minimal::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ,
            minimal::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT,
        );
        assert_ssz_matches_spec_root::<IndexedAttestation>(
            mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ,
            mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT,
            mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT,
        );
    }

    #[test]
    fn test_attester_slashing_hash_tree_root() {
        assert_ssz_matches_spec_root::<AttesterSlashing>(
            minimal::SPEC_GLOAS_ATTESTER_SLASHING_SSZ,
            minimal::SPEC_GLOAS_ATTESTER_SLASHING_ROOT,
        );
        assert_ssz_matches_spec_root::<AttesterSlashing>(
            mainnet::SPEC_GLOAS_ATTESTER_SLASHING_SSZ,
            mainnet::SPEC_GLOAS_ATTESTER_SLASHING_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_ATTESTER_SLASHING_ROOT,
            mainnet::SPEC_GLOAS_ATTESTER_SLASHING_ROOT,
        );
    }

    #[test]
    fn test_aggregate_and_proof_hash_tree_root() {
        assert_ssz_matches_spec_root::<AggregateAndProof<4>>(
            minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ,
            minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT,
        );
        assert_ssz_matches_spec_root::<AggregateAndProof<64>>(
            mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ,
            mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT,
            mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT,
        );
    }

    #[test]
    fn test_signed_aggregate_and_proof_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedAggregateAndProof<4>>(
            minimal::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_SSZ,
            minimal::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedAggregateAndProof<64>>(
            mainnet::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT,
            mainnet::SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT,
        );
    }

    #[test]
    fn test_active_fields_attestation_width() {
        assert_eq!(crate::ACTIVE_FIELDS_ATTESTATION.len(), 4);
        assert!(
            crate::ACTIVE_FIELDS_ATTESTATION.iter().all(|bit| *bit),
            "v1.7.0-beta.0 Attestation ACTIVE_FIELDS is all-ones width 4"
        );
    }

    #[test]
    fn test_active_fields_indexed_attestation_width() {
        assert_eq!(crate::ACTIVE_FIELDS_INDEXED_ATTESTATION.len(), 3);
        assert!(
            crate::ACTIVE_FIELDS_INDEXED_ATTESTATION.iter().all(|bit| *bit),
            "v1.7.0-beta.0 IndexedAttestation ACTIVE_FIELDS is all-ones width 3"
        );
    }

    /// Width 5 with an inactive slot: same four fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 1, 0, 1])]
    struct AttestationWrongWidth<const N: usize> {
        aggregation_bits: ProgressiveBitlist,
        data: AttestationData,
        signature: [u8; 96],
        committee_bits: SszBitvector<N>,
    }

    /// Width 4 with an inactive slot: same three fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 0, 1])]
    struct IndexedAttestationWrongWidth {
        attesting_indices: ProgressiveList<u64>,
        data: AttestationData,
        signature: [u8; 96],
    }

    #[test]
    fn test_attestation_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_ATTESTATION_SSZ);
        let wrong = AttestationWrongWidth::<4>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_ATTESTATION_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_ATTESTATION_SSZ);
        let wrong = AttestationWrongWidth::<64>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_ATTESTATION_ROOT)
        );
    }

    #[test]
    fn test_indexed_attestation_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ);
        let wrong = IndexedAttestationWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ);
        let wrong = IndexedAttestationWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT)
        );
    }
}
