//! Gloas `ExecutionPayloadEnvelope` progressive container (EIP-7732 + EIP-7688).
//!
//! Self-build proposers sign `SignedExecutionPayloadEnvelope` under
//! `DOMAIN_BEACON_BUILDER` when `builder_index == BUILDER_INDEX_SELF_BUILD`
//! (D20, ADR-010). Types stay crate-private; the unsigned envelope root is
//! exported from [`crate::roots`].

#![allow(dead_code)]

use eth_types::Root;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use super::execution_payload::ExecutionPayload;
use super::requests::ExecutionRequests;

/// Gloas `ExecutionPayloadEnvelope` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class ExecutionPayloadEnvelope(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=5)`. `execution_requests` is the
/// island type from 5.7 — never `eth_types::`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1])]
pub(crate) struct ExecutionPayloadEnvelope {
    pub(crate) payload: ExecutionPayload,
    pub(crate) execution_requests: ExecutionRequests,
    pub(crate) builder_index: u64,
    pub(crate) beacon_block_root: Root,
    pub(crate) parent_beacon_block_root: Root,
}

/// Gloas `SignedExecutionPayloadEnvelope` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class SignedExecutionPayloadEnvelope(Container)` — not a
/// `ProgressiveContainer`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedExecutionPayloadEnvelope {
    pub(crate) message: ExecutionPayloadEnvelope,
    pub(crate) signature: [u8; 96],
}

#[cfg(test)]
mod tests {
    use super::{ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope};
    use crate::containers::execution_payload::ExecutionPayload;
    use crate::containers::requests::ExecutionRequests;
    use crate::spec_kat::{mainnet, minimal};
    use eth_types::Root;
    use libssz::{SszDecode, SszEncode};
    use libssz_derive::{HashTreeRoot, SszDecode};
    use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};

    const EXECUTION_PAYLOAD_ENVELOPE_FIELDS: &[&str] = &[
        "payload",
        "execution_requests",
        "builder_index",
        "beacon_block_root",
        "parent_beacon_block_root",
    ];

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

    fn assert_ssz_round_trip<T>(ssz_hex: &str)
    where
        T: SszDecode + SszEncode,
    {
        let bytes = parse_hex(ssz_hex);
        let decoded = T::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(decoded.to_ssz(), bytes);
    }

    #[test]
    fn test_execution_payload_envelope_hash_tree_root() {
        assert_ssz_matches_spec_root::<ExecutionPayloadEnvelope>(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
        assert_ssz_matches_spec_root::<ExecutionPayloadEnvelope>(
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
    }

    #[test]
    fn test_signed_execution_payload_envelope_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedExecutionPayloadEnvelope>(
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedExecutionPayloadEnvelope>(
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT,
        );
    }

    #[test]
    fn test_execution_payload_envelope_ssz_round_trip() {
        assert_ssz_round_trip::<ExecutionPayloadEnvelope>(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
        );
        assert_ssz_round_trip::<ExecutionPayloadEnvelope>(
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
        );
    }

    #[test]
    fn test_signed_execution_payload_envelope_ssz_round_trip() {
        assert_ssz_round_trip::<SignedExecutionPayloadEnvelope>(
            minimal::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
        );
        assert_ssz_round_trip::<SignedExecutionPayloadEnvelope>(
            mainnet::SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ,
        );
    }

    #[test]
    fn test_active_fields_execution_payload_envelope_width() {
        assert_eq!(crate::ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE.len(), 5);
        assert_eq!(
            EXECUTION_PAYLOAD_ENVELOPE_FIELDS.len(),
            crate::ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE.len()
        );
        assert!(
            crate::ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE.iter().all(|bit| *bit),
            "v1.7.0-beta.0 ExecutionPayloadEnvelope ACTIVE_FIELDS is all-ones width 5"
        );
    }

    /// Width 6 with an inactive slot: same five fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 1, 1, 0, 1])]
    struct ExecutionPayloadEnvelopeWrongWidth {
        payload: ExecutionPayload,
        execution_requests: ExecutionRequests,
        builder_index: u64,
        beacon_block_root: Root,
        parent_beacon_block_root: Root,
    }

    #[test]
    fn test_execution_payload_envelope_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let wrong = ExecutionPayloadEnvelopeWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let wrong = ExecutionPayloadEnvelopeWrongWidth::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT)
        );
    }
}
