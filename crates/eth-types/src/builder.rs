use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::Signature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ValidatorRegistrationV1 {
    #[serde(with = "crate::hex_fixed::bytes_20_hex")]
    pub fee_recipient: [u8; 20],
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "crate::hex_fixed::bytes_48_hex")]
    pub pubkey: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedValidatorRegistration {
    pub message: ValidatorRegistrationV1,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registration() -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        }
    }

    fn sample_signed_registration() -> SignedValidatorRegistration {
        SignedValidatorRegistration { message: sample_registration(), signature: vec![0xee; 96] }
    }

    #[test]
    fn test_builder_registration_serde_roundtrip() {
        let original = sample_registration();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ValidatorRegistrationV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_builder_registration_fee_recipient_hex() {
        let reg = sample_registration();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected = format!("0x{}", "ab".repeat(20));
        assert_eq!(parsed["fee_recipient"], serde_json::Value::String(expected));
    }

    #[test]
    fn test_builder_registration_pubkey_hex() {
        let reg = sample_registration();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected = format!("0x{}", "cd".repeat(48));
        assert_eq!(parsed["pubkey"], serde_json::Value::String(expected));
    }

    #[test]
    fn test_builder_registration_quoted_integers() {
        let reg = sample_registration();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["gas_limit"], serde_json::Value::String("30000000".to_string()));
        assert_eq!(parsed["timestamp"], serde_json::Value::String("1700000000".to_string()));
    }

    #[test]
    fn test_builder_registration_zero_values() {
        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0u8; 20],
            gas_limit: 0,
            timestamp: 0,
            pubkey: [0u8; 48],
        };
        let json = serde_json::to_string(&reg).unwrap();
        let decoded: ValidatorRegistrationV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, decoded);
    }

    #[test]
    fn test_builder_registration_max_values() {
        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0xff; 20],
            gas_limit: u64::MAX,
            timestamp: u64::MAX,
            pubkey: [0xff; 48],
        };
        let json = serde_json::to_string(&reg).unwrap();
        let decoded: ValidatorRegistrationV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, decoded);
    }

    #[test]
    fn test_builder_signed_registration_serde_roundtrip() {
        let signed = sample_signed_registration();
        let json = serde_json::to_string(&signed).unwrap();
        let decoded: SignedValidatorRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, decoded);
    }

    #[test]
    fn test_builder_signed_registration_signature_hex() {
        let signed = sample_signed_registration();
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected = format!("0x{}", "ee".repeat(96));
        assert_eq!(parsed["signature"], serde_json::Value::String(expected));
    }

    #[test]
    fn test_builder_registration_ssz_roundtrip() {
        use ssz::{Decode, Encode};
        let original = sample_registration();
        let encoded = original.as_ssz_bytes();
        let decoded = ValidatorRegistrationV1::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_builder_registration_ssz_length() {
        use ssz::Encode;
        let reg = sample_registration();
        let encoded = reg.as_ssz_bytes();
        // 20 (fee_recipient) + 8 (gas_limit) + 8 (timestamp) + 48 (pubkey) = 84
        assert_eq!(encoded.len(), 84);
    }

    #[test]
    fn test_builder_registration_tree_hash_deterministic() {
        use tree_hash::TreeHash;
        let reg = sample_registration();
        let root1 = reg.tree_hash_root();
        let root2 = reg.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    // kat_exempt: field-sensitivity — different gas_limit must yield different roots; not a container-root KAT
    fn test_builder_registration_tree_hash_different_data_different_root() {
        use tree_hash::TreeHash;
        let reg1 = sample_registration();
        let mut reg2 = sample_registration();
        reg2.gas_limit = 999;
        assert_ne!(reg1.tree_hash_root(), reg2.tree_hash_root());
    }
}
