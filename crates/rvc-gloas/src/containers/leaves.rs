//! Unmodified attestation-side SSZ containers (plain libssz, no progressive_container).
//!
//! First production callers land in later island issues.

#![allow(dead_code)]

use eth_types::{Epoch, Root, Slot};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct Checkpoint {
    pub(crate) epoch: Epoch,
    pub(crate) root: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct AttestationData {
    pub(crate) slot: Slot,
    /// Gloas payload-status bit. Never normalized or zeroed.
    pub(crate) index: u64,
    pub(crate) beacon_block_root: Root,
    pub(crate) source: Checkpoint,
    pub(crate) target: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct Eth1Data {
    pub(crate) deposit_root: Root,
    pub(crate) deposit_count: u64,
    pub(crate) block_hash: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct BeaconBlockHeader {
    pub(crate) slot: Slot,
    pub(crate) proposer_index: u64,
    pub(crate) parent_root: Root,
    pub(crate) state_root: Root,
    pub(crate) body_root: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct SignedBeaconBlockHeader {
    pub(crate) message: BeaconBlockHeader,
    pub(crate) signature: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub(crate) struct ProposerSlashing {
    pub(crate) signed_header_1: SignedBeaconBlockHeader,
    pub(crate) signed_header_2: SignedBeaconBlockHeader,
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
        let bytes = parse_hex(ssz_hex);
        let island = I::from_ssz_bytes(&bytes).expect("island SSZ decode");
        let twin = E::from_ssz_bytes(&bytes).expect("eth-types SSZ decode");
        assert_eq!(island.hash_tree_root(&Sha2Hasher), tree_hash_root_bytes(&twin));
    }

    fn wire_attestation_data_index(ssz: &[u8]) -> u64 {
        u64::from_le_bytes(ssz[8..16].try_into().expect("AttestationData.index is 8 bytes"))
    }

    fn with_index(mut data: AttestationData, index: u64) -> AttestationData {
        data.index = index;
        data
    }

    #[test]
    fn test_checkpoint_hash_tree_root() {
        assert_ssz_matches_spec_root::<Checkpoint>(
            minimal::SPEC_GLOAS_CHECKPOINT_SSZ,
            minimal::SPEC_GLOAS_CHECKPOINT_ROOT,
        );
        assert_ssz_matches_spec_root::<Checkpoint>(
            mainnet::SPEC_GLOAS_CHECKPOINT_SSZ,
            mainnet::SPEC_GLOAS_CHECKPOINT_ROOT,
        );
    }

    #[test]
    fn test_attestation_data_hash_tree_root() {
        assert_ssz_matches_spec_root::<AttestationData>(
            minimal::SPEC_GLOAS_ATTESTATION_DATA_SSZ,
            minimal::SPEC_GLOAS_ATTESTATION_DATA_ROOT,
        );
        assert_ssz_matches_spec_root::<AttestationData>(
            mainnet::SPEC_GLOAS_ATTESTATION_DATA_SSZ,
            mainnet::SPEC_GLOAS_ATTESTATION_DATA_ROOT,
        );
    }

    #[test]
    fn test_eth1data_hash_tree_root() {
        assert_ssz_matches_spec_root::<Eth1Data>(
            minimal::SPEC_GLOAS_ETH1DATA_SSZ,
            minimal::SPEC_GLOAS_ETH1DATA_ROOT,
        );
        assert_ssz_matches_spec_root::<Eth1Data>(
            mainnet::SPEC_GLOAS_ETH1DATA_SSZ,
            mainnet::SPEC_GLOAS_ETH1DATA_ROOT,
        );
    }

    #[test]
    fn test_beacon_block_header_hash_tree_root() {
        assert_ssz_matches_spec_root::<BeaconBlockHeader>(
            minimal::SPEC_GLOAS_BEACON_BLOCK_HEADER_SSZ,
            minimal::SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT,
        );
        assert_ssz_matches_spec_root::<BeaconBlockHeader>(
            mainnet::SPEC_GLOAS_BEACON_BLOCK_HEADER_SSZ,
            mainnet::SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT,
        );
    }

    #[test]
    fn test_signed_beacon_block_header_hash_tree_root() {
        assert_ssz_matches_spec_root::<SignedBeaconBlockHeader>(
            minimal::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ,
            minimal::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT,
        );
        assert_ssz_matches_spec_root::<SignedBeaconBlockHeader>(
            mainnet::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ,
            mainnet::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT,
        );
    }

    #[test]
    fn test_proposer_slashing_hash_tree_root() {
        assert_ssz_matches_spec_root::<ProposerSlashing>(
            minimal::SPEC_GLOAS_PROPOSER_SLASHING_SSZ,
            minimal::SPEC_GLOAS_PROPOSER_SLASHING_ROOT,
        );
        assert_ssz_matches_spec_root::<ProposerSlashing>(
            mainnet::SPEC_GLOAS_PROPOSER_SLASHING_SSZ,
            mainnet::SPEC_GLOAS_PROPOSER_SLASHING_ROOT,
        );
    }

    #[test]
    fn test_attestation_data_index_is_not_normalized() {
        for ssz_hex in
            [minimal::SPEC_GLOAS_ATTESTATION_DATA_SSZ, mainnet::SPEC_GLOAS_ATTESTATION_DATA_SSZ]
        {
            let bytes = parse_hex(ssz_hex);
            let decoded = AttestationData::from_ssz_bytes(&bytes).expect("AttestationData SSZ");
            assert_eq!(
                decoded.index,
                wire_attestation_data_index(&bytes),
                "AttestationData.index must not be rewritten"
            );

            let index_one = with_index(decoded.clone(), 1);
            assert_eq!(index_one.index, 1);
            let roundtrip =
                AttestationData::from_ssz_bytes(&index_one.to_ssz()).expect("re-decode index=1");
            assert_eq!(roundtrip.index, 1);

            let index_zero = with_index(decoded, 0);
            assert_eq!(index_zero.index, 0);
            assert_ne!(
                index_one.hash_tree_root(&Sha2Hasher),
                index_zero.hash_tree_root(&Sha2Hasher)
            );
        }
    }

    #[test]
    fn test_checkpoint_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<Checkpoint, eth_types::Checkpoint>(
            minimal::SPEC_GLOAS_CHECKPOINT_SSZ,
        );
        assert_island_matches_tree_hash::<Checkpoint, eth_types::Checkpoint>(
            mainnet::SPEC_GLOAS_CHECKPOINT_SSZ,
        );
    }

    #[test]
    fn test_attestation_data_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<AttestationData, eth_types::AttestationData>(
            minimal::SPEC_GLOAS_ATTESTATION_DATA_SSZ,
        );
        assert_island_matches_tree_hash::<AttestationData, eth_types::AttestationData>(
            mainnet::SPEC_GLOAS_ATTESTATION_DATA_SSZ,
        );
    }

    #[test]
    fn test_eth1data_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<Eth1Data, eth_types::block_body::Eth1Data>(
            minimal::SPEC_GLOAS_ETH1DATA_SSZ,
        );
        assert_island_matches_tree_hash::<Eth1Data, eth_types::block_body::Eth1Data>(
            mainnet::SPEC_GLOAS_ETH1DATA_SSZ,
        );
    }

    #[test]
    fn test_proposer_slashing_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<ProposerSlashing, eth_types::block_body::ProposerSlashing>(
            minimal::SPEC_GLOAS_PROPOSER_SLASHING_SSZ,
        );
        assert_island_matches_tree_hash::<ProposerSlashing, eth_types::block_body::ProposerSlashing>(
            mainnet::SPEC_GLOAS_PROPOSER_SLASHING_SSZ,
        );
    }

    #[test]
    fn test_signed_beacon_block_header_matches_tree_hash_root() {
        // kat_exempt: cross-implementation differential, not a spec-root assertion
        assert_island_matches_tree_hash::<
            SignedBeaconBlockHeader,
            eth_types::block_body::SignedBeaconBlockHeader,
        >(minimal::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ);
        assert_island_matches_tree_hash::<
            SignedBeaconBlockHeader,
            eth_types::block_body::SignedBeaconBlockHeader,
        >(mainnet::SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ);
    }
}
