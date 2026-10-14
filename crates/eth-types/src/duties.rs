use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root};
use crate::{Epoch, Signature, Slot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDuty {
    #[serde(with = "crate::hex_fixed::bytes_48_hex")]
    pub pubkey: [u8; 48],
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct VoluntaryExit {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: message, signature (Bytes96 / vec_u8 of length 96)
impl_container_tree_hash!(
    SignedVoluntaryExit,
    "valid 96-byte signature",
    [|s| Ok(s.message.tree_hash_root()), |s| Ok(vec_u8_tree_hash_root(&s.signature)),]
);

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proposer_duty() -> ProposerDuty {
        ProposerDuty { pubkey: [0xab; 48], validator_index: 42, slot: 1000 }
    }

    fn sample_voluntary_exit() -> VoluntaryExit {
        VoluntaryExit { epoch: 100, validator_index: 42 }
    }

    #[test]
    fn test_proposer_duty_serde_roundtrip() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: ProposerDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    #[test]
    fn test_proposer_duty_quoted_integers() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
        assert_eq!(parsed["slot"], serde_json::Value::String("1000".to_string()));
    }

    #[test]
    fn test_proposer_duty_pubkey_is_hex() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected = format!("0x{}", "ab".repeat(48));
        assert_eq!(parsed["pubkey"], serde_json::Value::String(expected));
    }

    #[test]
    fn test_voluntary_exit_serde_roundtrip() {
        let exit = sample_voluntary_exit();
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_voluntary_exit_quoted_integers() {
        let exit = sample_voluntary_exit();
        let json = serde_json::to_string(&exit).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_voluntary_exit_serde_roundtrip() {
        let signed =
            SignedVoluntaryExit { message: sample_voluntary_exit(), signature: vec![0xaa; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedVoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_voluntary_exit_zero_values() {
        let exit = VoluntaryExit { epoch: 0, validator_index: 0 };
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_voluntary_exit_max_values() {
        let exit = VoluntaryExit { epoch: u64::MAX, validator_index: u64::MAX };
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_signed_voluntary_exit_rejects_empty_signature() {
        let json =
            r#"{"message":{"epoch":"100","validator_index":"42"},"signature":"0x"}"#.to_string();
        assert!(serde_json::from_str::<SignedVoluntaryExit>(&json).is_err());
    }
}
