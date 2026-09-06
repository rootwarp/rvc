//! EIP-8282 builder-request SSZ containers (plain libssz, no progressive_container).
//!
//! First production callers land in later island issues (5.7).

#![allow(dead_code)]

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

/// Gloas `BuilderDepositRequest` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class BuilderDepositRequest(Container)` — not a `ProgressiveContainer`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct BuilderDepositRequest {
    pub(crate) pubkey: [u8; 48],
    pub(crate) withdrawal_credentials: [u8; 32],
    pub(crate) amount: u64,
    pub(crate) signature: [u8; 96],
}

/// Gloas `BuilderExitRequest` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class BuilderExitRequest(Container)` — not a `ProgressiveContainer`.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct BuilderExitRequest {
    pub(crate) source_address: [u8; 20],
    pub(crate) pubkey: [u8; 48],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::{SszDecode, SszEncode};
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

    fn assert_ssz_round_trip<T>(ssz_hex: &str)
    where
        T: SszDecode + SszEncode + PartialEq + std::fmt::Debug,
    {
        let bytes = parse_hex(ssz_hex);
        let decoded = T::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(decoded.to_ssz(), bytes);
        let redecoded = T::from_ssz_bytes(&decoded.to_ssz()).expect("SSZ re-decode");
        assert_eq!(redecoded, decoded);
    }

    #[test]
    fn test_builder_deposit_request_hash_tree_root() {
        assert_ssz_matches_spec_root::<BuilderDepositRequest>(
            minimal::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ,
            minimal::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT,
        );
        assert_ssz_matches_spec_root::<BuilderDepositRequest>(
            mainnet::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ,
            mainnet::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT,
        );
    }

    #[test]
    fn test_builder_exit_request_hash_tree_root() {
        assert_ssz_matches_spec_root::<BuilderExitRequest>(
            minimal::SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ,
            minimal::SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT,
        );
        assert_ssz_matches_spec_root::<BuilderExitRequest>(
            mainnet::SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ,
            mainnet::SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT,
        );
    }

    #[test]
    fn test_builder_deposit_request_ssz_round_trip() {
        assert_ssz_round_trip::<BuilderDepositRequest>(
            minimal::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ,
        );
        assert_ssz_round_trip::<BuilderDepositRequest>(
            mainnet::SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ,
        );
    }

    #[test]
    fn test_builder_exit_request_ssz_round_trip() {
        assert_ssz_round_trip::<BuilderExitRequest>(minimal::SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ);
        assert_ssz_round_trip::<BuilderExitRequest>(mainnet::SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ);
    }
}
