use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root};
use crate::{Root, Signature, Slot};

/// Gloas `ProposerPreferences` (`consensus-specs` `SPEC_TAG` v1.7.0-beta.0).
///
/// Field order: `dependent_root`, `proposal_slot`, `validator_index`,
/// `fee_recipient`, `target_gas_limit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProposerPreferences {
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub dependent_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposal_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "crate::hex_fixed::bytes_20_hex")]
    pub fee_recipient: [u8; 20],
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_gas_limit: u64,
}

/// Gloas `SignedProposerPreferences` (`consensus-specs` `SPEC_TAG` v1.7.0-beta.0).
///
/// Field order: `message`, `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: message, signature (Bytes96 / vec_u8 of length 96)
impl_container_tree_hash!(
    SignedProposerPreferences,
    "valid SignedProposerPreferences",
    [|s| Ok(s.message.tree_hash_root()), |s| Ok(vec_u8_tree_hash_root(&s.signature)),]
);

#[cfg(test)]
mod tests {
    use super::*;
    use rvc_spec_vectors::spec_kat::SPEC_GLOAS_PROPOSERPREFERENCES_ROOT;
    use tree_hash::Hash256;

    fn hex32(s: &str) -> Hash256 {
        Hash256::from_slice(&hex::decode(s.trim_start_matches("0x")).expect("hex"))
    }

    fn kat_prefs() -> ProposerPreferences {
        ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 3,
            fee_recipient: [0x44; 20],
            target_gas_limit: 36_000_000,
        }
    }

    #[test]
    fn test_proposer_preferences_tree_hash_root() {
        const SPEC_KAT: &str = include_str!("../../rvc-spec-vectors/src/spec_kat.rs");
        let header: String = SPEC_KAT.lines().take_while(|l| l.starts_with("//!")).collect();
        assert!(
            !header.to_ascii_lowercase().contains("remerkleable"),
            "SPEC_GLOAS_PROPOSERPREFERENCES_ROOT provenance must not be remerkleable (D15)"
        );
        assert_eq!(kat_prefs().tree_hash_root(), hex32(SPEC_GLOAS_PROPOSERPREFERENCES_ROOT));
    }
}
