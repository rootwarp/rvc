//! Unmodified body-closure SSZ containers (plain libssz, no progressive_container).
//!
//! First production callers land in later island issues.

#![allow(dead_code)]

use eth_types::Epoch;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszVector};

/// `DEPOSIT_CONTRACT_TREE_DEPTH + 1` (Merkle proof including the leaf).
const DEPOSIT_PROOF_LENGTH: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct DepositData {
    pub(crate) pubkey: [u8; 48],
    pub(crate) withdrawal_credentials: [u8; 32],
    pub(crate) amount: u64,
    pub(crate) signature: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct Deposit {
    pub(crate) proof: SszVector<[u8; 32], DEPOSIT_PROOF_LENGTH>,
    pub(crate) data: DepositData,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct VoluntaryExit {
    pub(crate) epoch: Epoch,
    pub(crate) validator_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedVoluntaryExit {
    pub(crate) message: VoluntaryExit,
    pub(crate) signature: [u8; 96],
}

/// Preset-sensitive: `N` is `SYNC_COMMITTEE_SIZE` (minimal 32, mainnet 512).
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SyncAggregate<const N: usize> {
    pub(crate) sync_committee_bits: SszBitvector<N>,
    pub(crate) sync_committee_signature: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct BlsToExecutionChange {
    pub(crate) validator_index: u64,
    pub(crate) from_bls_pubkey: [u8; 48],
    pub(crate) to_execution_address: [u8; 20],
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedBlsToExecutionChange {
    pub(crate) message: BlsToExecutionChange,
    pub(crate) signature: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct DepositRequest {
    pub(crate) pubkey: [u8; 48],
    pub(crate) withdrawal_credentials: [u8; 32],
    pub(crate) amount: u64,
    pub(crate) signature: [u8; 96],
    pub(crate) index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct WithdrawalRequest {
    pub(crate) source_address: [u8; 20],
    pub(crate) validator_pubkey: [u8; 48],
    pub(crate) amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct ConsolidationRequest {
    pub(crate) source_address: [u8; 20],
    pub(crate) source_pubkey: [u8; 48],
    pub(crate) target_pubkey: [u8; 48],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::{SszDecode, SszEncode};
    use libssz_merkle::{HashTreeRoot, Sha2Hasher};
    use ssz08::Decode;
    use tree_hash::TreeHash;

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

    fn tree_hash_root_bytes<T: TreeHash>(value: &T) -> [u8; 32] {
        value.tree_hash_root().as_slice().try_into().expect("Hash256 is 32 bytes")
    }

    fn assert_island_matches_tree_hash<I, E>(ssz_hex: &str)
    where
        I: SszDecode + HashTreeRoot,
        E: Decode + TreeHash,
    {
        assert_island_matches_tree_hash_bytes::<I, E>(&parse_hex(ssz_hex));
    }

    fn assert_island_matches_tree_hash_bytes<I, E>(bytes: &[u8])
    where
        I: SszDecode + HashTreeRoot,
        E: Decode + TreeHash,
    {
        let island = I::from_ssz_bytes(bytes).expect("island SSZ decode");
        let twin = E::from_ssz_bytes(bytes).expect("eth-types SSZ decode");
        assert_eq!(island.hash_tree_root(&Sha2Hasher), tree_hash_root_bytes(&twin));
    }

    #[test]
    fn test_deposit_data_hash_tree_root() {
        assert_ssz_matches_spec_root::<DepositData>(
            minimal::SPEC_GLOAS_DEPOSIT_DATA_SSZ,
            minimal::SPEC_GLOAS_DEPOSIT_DATA_ROOT,
        );
        assert_ssz_matches_spec_root::<DepositData>(
            mainnet::SPEC_GLOAS_DEPOSIT_DATA_SSZ,
            mainnet::SPEC_GLOAS_DEPOSIT_DATA_ROOT,
        );
    }

    #[test]
    fn test_deposit_hash_tree_root() {
        assert_ssz_matches_spec_root::<Deposit>(
            minimal::SPEC_GLOAS_DEPOSIT_SSZ,
            minimal::SPEC_GLOAS_DEPOSIT_ROOT,
        );
        assert_ssz_matches_spec_root::<Deposit>(
            mainnet::SPEC_GLOAS_DEPOSIT_SSZ,
            mainnet::SPEC_GLOAS_DEPOSIT_ROOT,
        );
    }

    #[test]
    fn test_voluntary_exit_hash_tree_root() {
        assert_ssz_matches_spec_root::<VoluntaryExit>(
            minimal::SPEC_GLOAS_VOLUNTARY_EXIT_SSZ,
            minimal::SPEC_GLOAS_VOLUNTARY_EXIT_ROOT,
        );
        assert_ssz_matches_spec_root::<VoluntaryExit>(
            mainnet::SPEC_GLOAS_VOLUNTARY_EXIT_SSZ,
            mainnet::SPEC_GLOAS_VOLUNTARY_EXIT_ROOT,
        );
    }

    #[test]
    fn test_signed_voluntary_exit_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedVoluntaryExit>(
            minimal::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ,
            minimal::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedVoluntaryExit>(
            mainnet::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT,
        );
    }

    #[test]
    fn test_sync_aggregate_hash_tree_root() {
        assert_ssz_matches_spec_root::<SyncAggregate<32>>(
            minimal::SPEC_GLOAS_SYNC_AGGREGATE_SSZ,
            minimal::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
        );
        assert_ssz_matches_spec_root::<SyncAggregate<512>>(
            mainnet::SPEC_GLOAS_SYNC_AGGREGATE_SSZ,
            mainnet::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
        );
    }

    #[test]
    fn test_bls_to_execution_change_hash_tree_root() {
        assert_ssz_matches_spec_root::<BlsToExecutionChange>(
            minimal::SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_SSZ,
            minimal::SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT,
        );
        assert_ssz_matches_spec_root::<BlsToExecutionChange>(
            mainnet::SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_SSZ,
            mainnet::SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT,
        );
    }

    #[test]
    fn test_signed_bls_to_execution_change_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedBlsToExecutionChange>(
            minimal::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ,
            minimal::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedBlsToExecutionChange>(
            mainnet::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT,
        );
    }

    #[test]
    fn test_deposit_request_hash_tree_root() {
        assert_ssz_matches_spec_root::<DepositRequest>(
            minimal::SPEC_GLOAS_DEPOSIT_REQUEST_SSZ,
            minimal::SPEC_GLOAS_DEPOSIT_REQUEST_ROOT,
        );
        assert_ssz_matches_spec_root::<DepositRequest>(
            mainnet::SPEC_GLOAS_DEPOSIT_REQUEST_SSZ,
            mainnet::SPEC_GLOAS_DEPOSIT_REQUEST_ROOT,
        );
    }

    #[test]
    fn test_withdrawal_request_hash_tree_root() {
        assert_ssz_matches_spec_root::<WithdrawalRequest>(
            minimal::SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ,
            minimal::SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT,
        );
        assert_ssz_matches_spec_root::<WithdrawalRequest>(
            mainnet::SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ,
            mainnet::SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT,
        );
    }

    #[test]
    fn test_consolidation_request_hash_tree_root() {
        assert_ssz_matches_spec_root::<ConsolidationRequest>(
            minimal::SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ,
            minimal::SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT,
        );
        assert_ssz_matches_spec_root::<ConsolidationRequest>(
            mainnet::SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ,
            mainnet::SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT,
        );
    }

    #[test]
    fn test_deposit_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<Deposit, eth_types::block_body::Deposit>(
            minimal::SPEC_GLOAS_DEPOSIT_SSZ,
        );
        assert_island_matches_tree_hash::<Deposit, eth_types::block_body::Deposit>(
            mainnet::SPEC_GLOAS_DEPOSIT_SSZ,
        );
    }

    #[test]
    fn test_signed_voluntary_exit_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<SignedVoluntaryExit, eth_types::SignedVoluntaryExit>(
            minimal::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ,
        );
        assert_island_matches_tree_hash::<SignedVoluntaryExit, eth_types::SignedVoluntaryExit>(
            mainnet::SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ,
        );
    }

    #[test]
    fn test_sync_aggregate_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        // eth-types twin is BitVector<U512> (mainnet); minimal Bitvector[32] has no twin.
        assert_island_matches_tree_hash::<SyncAggregate<512>, eth_types::SyncAggregate>(
            mainnet::SPEC_GLOAS_SYNC_AGGREGATE_SSZ,
        );
        let mut second = SyncAggregate::<512>::from_ssz_bytes(&parse_hex(
            mainnet::SPEC_GLOAS_SYNC_AGGREGATE_SSZ,
        ))
        .expect("island SSZ decode");
        second.sync_committee_signature[0] ^= 0xff;
        let second_ssz = second.to_ssz();
        assert_island_matches_tree_hash_bytes::<SyncAggregate<512>, eth_types::SyncAggregate>(
            &second_ssz,
        );
        let first = SyncAggregate::<512>::from_ssz_bytes(&parse_hex(
            mainnet::SPEC_GLOAS_SYNC_AGGREGATE_SSZ,
        ))
        .expect("island SSZ decode");
        assert_ne!(first.hash_tree_root(&Sha2Hasher), second.hash_tree_root(&Sha2Hasher));
    }

    #[test]
    fn test_signed_bls_to_execution_change_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<
            SignedBlsToExecutionChange,
            eth_types::block_body::SignedBlsToExecutionChange,
        >(minimal::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ);
        assert_island_matches_tree_hash::<
            SignedBlsToExecutionChange,
            eth_types::block_body::SignedBlsToExecutionChange,
        >(mainnet::SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ);
    }

    #[test]
    fn test_deposit_request_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<DepositRequest, eth_types::block_body::DepositRequest>(
            minimal::SPEC_GLOAS_DEPOSIT_REQUEST_SSZ,
        );
        assert_island_matches_tree_hash::<DepositRequest, eth_types::block_body::DepositRequest>(
            mainnet::SPEC_GLOAS_DEPOSIT_REQUEST_SSZ,
        );
    }

    #[test]
    fn test_withdrawal_request_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<
            WithdrawalRequest,
            eth_types::block_body::WithdrawalRequest,
        >(minimal::SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ);
        assert_island_matches_tree_hash::<
            WithdrawalRequest,
            eth_types::block_body::WithdrawalRequest,
        >(mainnet::SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ);
    }

    #[test]
    fn test_consolidation_request_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<
            ConsolidationRequest,
            eth_types::block_body::ConsolidationRequest,
        >(minimal::SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ);
        assert_island_matches_tree_hash::<
            ConsolidationRequest,
            eth_types::block_body::ConsolidationRequest,
        >(mainnet::SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ);
    }
}
