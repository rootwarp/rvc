//! Embed-only Gloas payload-attestation and execution-payload-bid containers.
//!
//! Merkleized inside the block body, never signed and never exported through the
//! island. `ExecutionPayload` itself is excluded from this module (P0-10): declare
//! the bid, never the payload.
//!
//! First production callers land in later island issues (5.9).

#![allow(dead_code)]

use eth_types::{Root, Slot};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{ProgressiveList, SszBitvector};

/// Island embed-only `PayloadAttestationData` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class PayloadAttestationData(Container)` — not a `ProgressiveContainer`.
///
/// A second declaration from `eth_types::PayloadAttestationData` by design: that twin
/// owns the PTC signing path on `tree_hash` 0.9 (ADR-006). This copy is merkleized
/// inside `PayloadAttestation` / the block body and is never signed or exported.
/// Do not de-duplicate into a `TreeHash` bridge — 5.12's differential does not cover
/// them (the island copy is progressive-adjacent and may diverge legitimately).
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct PayloadAttestationData {
    pub(crate) beacon_block_root: Root,
    pub(crate) slot: Slot,
    pub(crate) payload_present: bool,
    pub(crate) blob_data_available: bool,
}

/// Gloas `PayloadAttestation` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class PayloadAttestation(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=3)`. `N` is `PTC_SIZE`
/// (minimal 16, mainnet 512). `aggregation_bits` is
/// `PayloadTimelinessCommitteeBits` (`BitVector[PTC_SIZE]`).
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1])]
pub(crate) struct PayloadAttestation<const N: usize> {
    pub(crate) aggregation_bits: SszBitvector<N>,
    pub(crate) data: PayloadAttestationData,
    pub(crate) signature: [u8; 96],
}

/// Gloas `ExecutionPayloadBid` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class ExecutionPayloadBid(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=12)`. Embed-only: merkleized inside
/// the body, never signed and never exported. `blob_kzg_commitments` is
/// `ProgressiveList[KZGCommitment]` (`Bytes48`).
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
pub(crate) struct ExecutionPayloadBid {
    pub(crate) parent_block_hash: Root,
    pub(crate) parent_block_root: Root,
    pub(crate) block_hash: Root,
    pub(crate) prev_randao: Root,
    pub(crate) fee_recipient: [u8; 20],
    pub(crate) gas_limit: u64,
    pub(crate) builder_index: u64,
    pub(crate) slot: Slot,
    pub(crate) value: u64,
    pub(crate) execution_payment: u64,
    pub(crate) blob_kzg_commitments: ProgressiveList<[u8; 48]>,
    pub(crate) execution_requests_root: Root,
}

/// Gloas `SignedExecutionPayloadBid` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class SignedExecutionPayloadBid(Container)` — not a `ProgressiveContainer`.
/// Embed-only: merkleized inside the body, never signed by rs-vc and never exported.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedExecutionPayloadBid {
    pub(crate) message: ExecutionPayloadBid,
    pub(crate) signature: [u8; 96],
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutionPayloadBid, PayloadAttestation, PayloadAttestationData, SignedExecutionPayloadBid,
    };
    use crate::spec_kat::{mainnet, minimal};
    use eth_types::{Root, Slot};
    use libssz::SszDecode;
    use libssz_derive::{HashTreeRoot, SszDecode};
    use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};
    use libssz_types::{ProgressiveList, SszBitvector};

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
    fn test_payload_attestation_data_hash_tree_root() {
        assert_ssz_matches_spec_root::<PayloadAttestationData>(
            minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_SSZ,
            minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT,
        );
        assert_ssz_matches_spec_root::<PayloadAttestationData>(
            mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_SSZ,
            mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT,
        );
    }

    #[test]
    fn test_payload_attestation_hash_tree_root() {
        assert_ssz_matches_spec_root::<PayloadAttestation<16>>(
            minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ,
            minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT,
        );
        assert_ssz_matches_spec_root::<PayloadAttestation<512>>(
            mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ,
            mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT,
            mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT,
        );
    }

    #[test]
    fn test_execution_payload_bid_hash_tree_root() {
        assert_ssz_matches_spec_root::<ExecutionPayloadBid>(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ,
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT,
        );
        assert_ssz_matches_spec_root::<ExecutionPayloadBid>(
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT,
        );
    }

    #[test]
    fn test_signed_execution_payload_bid_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedExecutionPayloadBid>(
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_SSZ,
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedExecutionPayloadBid>(
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT,
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT,
        );
    }

    #[test]
    fn test_active_fields_payload_attestation_width() {
        assert_eq!(crate::ACTIVE_FIELDS_PAYLOAD_ATTESTATION.len(), 3);
        assert!(
            crate::ACTIVE_FIELDS_PAYLOAD_ATTESTATION.iter().all(|bit| *bit),
            "v1.7.0-beta.0 PayloadAttestation ACTIVE_FIELDS is all-ones width 3"
        );
    }

    /// Width 4 with an inactive slot: same three fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 0, 1])]
    struct PayloadAttestationWrongWidth<const N: usize> {
        aggregation_bits: SszBitvector<N>,
        data: PayloadAttestationData,
        signature: [u8; 96],
    }

    /// Width 13 with an inactive slot: same twelve fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1])]
    struct ExecutionPayloadBidWrongWidth {
        parent_block_hash: Root,
        parent_block_root: Root,
        block_hash: Root,
        prev_randao: Root,
        fee_recipient: [u8; 20],
        gas_limit: u64,
        builder_index: u64,
        slot: Slot,
        value: u64,
        execution_payment: u64,
        blob_kzg_commitments: ProgressiveList<[u8; 48]>,
        execution_requests_root: Root,
    }

    #[test]
    fn test_payload_attestation_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ);
        let wrong = PayloadAttestationWrongWidth::<16>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ);
        let wrong =
            PayloadAttestationWrongWidth::<512>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT)
        );
    }

    #[test]
    fn test_execution_payload_bid_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ);
        let wrong = ExecutionPayloadBidWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ);
        let wrong = ExecutionPayloadBidWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT)
        );
    }
}
