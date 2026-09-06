//! Gloas `ExecutionRequests` progressive container (EIP-7688 + EIP-8282).
//!
//! First production callers land in later island issues (5.9, 5.16).

#![allow(dead_code)]

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::ProgressiveList;

use super::body_leaves::{ConsolidationRequest, DepositRequest, WithdrawalRequest};
use super::builder_requests::{BuilderDepositRequest, BuilderExitRequest};

/// Gloas `ExecutionRequests` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class ExecutionRequests(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=5)`: deposits, withdrawals,
/// consolidations, then EIP-8282 `builder_deposits` / `builder_exits`.
/// Element types are island re-declarations — never `eth_types::`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1])]
pub(crate) struct ExecutionRequests {
    pub(crate) deposits: ProgressiveList<DepositRequest>,
    pub(crate) withdrawals: ProgressiveList<WithdrawalRequest>,
    pub(crate) consolidations: ProgressiveList<ConsolidationRequest>,
    pub(crate) builder_deposits: ProgressiveList<BuilderDepositRequest>,
    pub(crate) builder_exits: ProgressiveList<BuilderExitRequest>,
}

#[cfg(test)]
mod tests {
    use super::ExecutionRequests;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::SszDecode;
    use libssz_merkle::{HashTreeRoot, Sha2Hasher};

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

    #[test]
    fn test_execution_requests_hash_tree_root() {
        assert_ssz_matches_spec_root::<ExecutionRequests>(
            minimal::SPEC_GLOAS_EXECUTION_REQUESTS_SSZ,
            minimal::SPEC_GLOAS_EXECUTION_REQUESTS_ROOT,
        );
        assert_ssz_matches_spec_root::<ExecutionRequests>(
            mainnet::SPEC_GLOAS_EXECUTION_REQUESTS_SSZ,
            mainnet::SPEC_GLOAS_EXECUTION_REQUESTS_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_EXECUTION_REQUESTS_ROOT,
            mainnet::SPEC_GLOAS_EXECUTION_REQUESTS_ROOT,
        );
    }

    #[test]
    fn test_active_fields_execution_requests_width() {
        assert_eq!(crate::ACTIVE_FIELDS_EXECUTION_REQUESTS.len(), 5);
        assert!(
            crate::ACTIVE_FIELDS_EXECUTION_REQUESTS.iter().all(|bit| *bit),
            "v1.7.0-beta.0 ExecutionRequests ACTIVE_FIELDS is all-ones width 5"
        );
    }
}
