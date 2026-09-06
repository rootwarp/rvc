//! Gloas `ExecutionPayload` progressive container (EIP-7688 + EIP-7928 + EIP-7843).
//!
//! The VC merkleizes `ExecutionPayload` only as an embed inside a self-build
//! `ExecutionPayloadEnvelope` (D20, ADR-010). No payload root is exported and
//! no type in this module is `pub`.

#![allow(dead_code)]

use eth_types::Root;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{ProgressiveList, SszList};

/// Bellatrix `MAX_EXTRA_DATA_BYTES`. Gloas did not re-wrap `ExtraData`.
const MAX_EXTRA_DATA_BYTES: usize = 32;

/// Gloas `Transaction` = `ProgressiveList[Byte]`.
type Transaction = ProgressiveList<u8>;

/// Capella `Withdrawal` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class Withdrawal(Container)` — not a `ProgressiveContainer`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct Withdrawal {
    pub(crate) index: u64,
    pub(crate) validator_index: u64,
    pub(crate) address: [u8; 20],
    pub(crate) amount: u64,
}

/// Gloas `ExecutionPayload` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class ExecutionPayload(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=19)`. Embed-only: merkleized inside
/// the envelope, never signed on its own, never exported.
///
/// ProgressiveList fields at the frozen tag: `transactions`
/// (`ProgressiveList[ProgressiveList[Byte]]`), `withdrawals`,
/// `block_access_list`. `extra_data` remains Bellatrix `ByteList[32]`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
])]
pub(crate) struct ExecutionPayload {
    pub(crate) parent_hash: Root,
    pub(crate) fee_recipient: [u8; 20],
    pub(crate) state_root: Root,
    pub(crate) receipts_root: Root,
    pub(crate) logs_bloom: [u8; 256],
    pub(crate) prev_randao: Root,
    pub(crate) block_number: u64,
    pub(crate) gas_limit: u64,
    pub(crate) gas_used: u64,
    pub(crate) timestamp: u64,
    pub(crate) extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    pub(crate) base_fee_per_gas: [u8; 32],
    pub(crate) block_hash: Root,
    pub(crate) transactions: ProgressiveList<Transaction>,
    pub(crate) withdrawals: ProgressiveList<Withdrawal>,
    pub(crate) blob_gas_used: u64,
    pub(crate) excess_blob_gas: u64,
    pub(crate) block_access_list: ProgressiveList<u8>,
    pub(crate) slot_number: u64,
}

#[cfg(test)]
mod tests {
    use super::ExecutionPayload;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::{SszDecode, SszEncode};
    use libssz_merkle::{HashTreeRoot, Sha2Hasher};

    const EXECUTION_PAYLOAD_FIELDS: &[&str] = &[
        "parent_hash",
        "fee_recipient",
        "state_root",
        "receipts_root",
        "logs_bloom",
        "prev_randao",
        "block_number",
        "gas_limit",
        "gas_used",
        "timestamp",
        "extra_data",
        "base_fee_per_gas",
        "block_hash",
        "transactions",
        "withdrawals",
        "blob_gas_used",
        "excess_blob_gas",
        "block_access_list",
        "slot_number",
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
        T: SszDecode + HashTreeRoot,
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
    fn test_execution_payload_hash_tree_root() {
        assert_ssz_matches_spec_root::<ExecutionPayload>(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ,
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT,
        );
        assert_ssz_matches_spec_root::<ExecutionPayload>(
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT,
            mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT,
        );
    }

    #[test]
    fn test_execution_payload_ssz_round_trip() {
        assert_ssz_round_trip::<ExecutionPayload>(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ);
        assert_ssz_round_trip::<ExecutionPayload>(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ);
    }

    #[test]
    fn test_execution_payload_field_width() {
        assert_eq!(EXECUTION_PAYLOAD_FIELDS.len(), 19);
    }
}
