use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root};
use crate::{Root, Signature, Slot};

/// Gloas `PayloadAttestationData` (`consensus-specs` `SPEC_TAG` v1.7.0-beta.0).
///
/// Field order: `beacon_block_root`, `slot`, `payload_present`, `blob_data_available`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct PayloadAttestationData {
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

/// Gloas `PayloadAttestationMessage` (`consensus-specs` `SPEC_TAG` v1.7.0-beta.0).
///
/// Field order: `validator_index`, `data`, `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub data: PayloadAttestationData,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: validator_index, data, signature (Bytes96 / vec_u8 of length 96)
impl_container_tree_hash!(
    PayloadAttestationMessage,
    "valid PayloadAttestationMessage",
    [
        |s| Ok(s.validator_index.tree_hash_root()),
        |s| Ok(s.data.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.signature)),
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use rvc_spec_vectors::spec_kat::{
        SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT, SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT,
    };
    use tree_hash::Hash256;

    fn hex32(s: &str) -> Hash256 {
        Hash256::from_slice(&hex::decode(s.trim_start_matches("0x")).expect("hex"))
    }

    fn kat_data() -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        }
    }

    fn kat_message() -> PayloadAttestationMessage {
        PayloadAttestationMessage {
            validator_index: 7,
            data: kat_data(),
            signature: vec![0x22; 96],
        }
    }

    #[test]
    fn test_payload_attestation_data_tree_hash_root() {
        assert_eq!(kat_data().tree_hash_root(), hex32(SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT));
    }

    #[test]
    fn test_payload_attestation_message_tree_hash_root() {
        assert_eq!(
            kat_message().tree_hash_root(),
            hex32(SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT)
        );
    }

    #[test]
    fn test_payload_attestation_data_serde_roundtrip_bools() {
        for (payload_present, blob_data_available) in [(true, false), (false, true)] {
            let data = PayloadAttestationData {
                beacon_block_root: [0x11; 32],
                slot: 1,
                payload_present,
                blob_data_available,
            };
            let json = serde_json::to_string(&data).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed["payload_present"], serde_json::Value::Bool(payload_present));
            assert_eq!(parsed["blob_data_available"], serde_json::Value::Bool(blob_data_available));
            assert_eq!(parsed["slot"], serde_json::Value::String("1".to_string()));
            let decoded: PayloadAttestationData = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn test_payload_attestation_message_serde_roundtrip() {
        let message = kat_message();
        let json = serde_json::to_string(&message).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("7".to_string()));
        assert_eq!(parsed["data"]["payload_present"], serde_json::Value::Bool(true));
        assert_eq!(parsed["data"]["blob_data_available"], serde_json::Value::Bool(false));
        let decoded: PayloadAttestationMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_payload_attestation_message_rejects_non_96_byte_signature() {
        let root = format!("0x{}", "11".repeat(32));
        let data = format!(
            r#"{{"beacon_block_root":"{root}","slot":"1","payload_present":true,"blob_data_available":false}}"#
        );
        for sig_hex in ["0x", &format!("0x{}", "22".repeat(95)), &format!("0x{}", "22".repeat(97))]
        {
            let json =
                format!(r#"{{"validator_index":"7","data":{data},"signature":"{sig_hex}"}}"#);
            assert!(
                serde_json::from_str::<PayloadAttestationMessage>(&json).is_err(),
                "accepted signature {sig_hex}"
            );
        }
    }
}
