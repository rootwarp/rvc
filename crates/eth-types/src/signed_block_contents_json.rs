//! Beacon-API JSON for a signed block and a signed blinded block.
//!
//! `signed_block.message.body` is a JSON object from [`crate::block_body_json::encode`],
//! not the hex string [`crate::BeaconBlock`] emits. A blinded publish uses
//! [`SignedBlindedBeaconBlockJson`]: `message.body` is an object from
//! [`crate::block_body_json::encode_blinded`]. SSZ stays canonical on
//! [`crate::SignedBeaconBlock`] and [`crate::SignedBlindedBeaconBlock`].
//! [`crate::BodyForkLayout::Gloas`] fails closed. The JSON block publish path
//! sends the contents container, proofs and blobs included. Blinded JSON
//! publish sends `{message, signature}` to `/eth/v1/beacon/blinded_blocks`.

use serde::Serialize;

use crate::{
    BodyForkLayout, BodySszError, Root, Signature, SignedBeaconBlock, SignedBlindedBeaconBlock,
    Slot,
};

/// Signed block whose body is a Beacon-API JSON object, not hex SSZ.
///
/// Not [`crate::BeaconBlock`]: that type's `body` field is `hex_vec`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BeaconBlockJson {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub state_root: Root,
    /// Object produced by [`crate::block_body_json::encode`].
    pub body: serde_json::Value,
}

/// `signed_block` half of [`SignedBlockContentsJson`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignedBeaconBlockJson {
    pub message: BeaconBlockJson,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

/// Deneb+ publish body: signed block, KZG proofs, and blobs.
///
/// Proofs and blobs are `0x`-prefixed hex strings on the wire. The block body
/// is not [`crate::BeaconBlock`]; it is encoded through [`crate::block_body_json::encode`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignedBlockContentsJson {
    pub signed_block: SignedBeaconBlockJson,
    #[serde(with = "serde_utils::list_of_bytes_lists")]
    pub kzg_proofs: Vec<Vec<u8>>,
    #[serde(with = "serde_utils::list_of_bytes_lists")]
    pub blobs: Vec<Vec<u8>>,
}

impl SignedBeaconBlockJson {
    /// Build `{message, signature}` from a signed block whose body is canonical SSZ.
    ///
    /// Encodes that body with [`crate::block_body_json::encode`] for `layout`.
    /// [`BodyForkLayout::Gloas`] returns [`BodySszError::GloasUnsupported`].
    /// This is the bare Deneb+ publish body: the object that was hashed, not hex.
    pub fn from_signed(
        signed: &SignedBeaconBlock,
        layout: BodyForkLayout,
    ) -> Result<Self, BodySszError> {
        let body = crate::block_body_json::encode(&signed.message.body, layout)?;
        require_json_object(&body, "encode")?;
        Ok(Self {
            message: BeaconBlockJson {
                slot: signed.message.slot,
                proposer_index: signed.message.proposer_index,
                parent_root: signed.message.parent_root,
                state_root: signed.message.state_root,
                body,
            },
            signature: signed.signature.clone(),
        })
    }
}

impl SignedBlockContentsJson {
    /// Build contents from a signed block whose `message.body` is canonical SSZ.
    ///
    /// Encodes that body with [`crate::block_body_json::encode`] for `layout`.
    /// [`BodyForkLayout::Gloas`] returns [`BodySszError::GloasUnsupported`].
    pub fn from_signed_block(
        signed_block: &SignedBeaconBlock,
        kzg_proofs: Vec<Vec<u8>>,
        blobs: Vec<Vec<u8>>,
        layout: BodyForkLayout,
    ) -> Result<Self, BodySszError> {
        Ok(Self {
            signed_block: SignedBeaconBlockJson::from_signed(signed_block, layout)?,
            kzg_proofs,
            blobs,
        })
    }
}

/// Blinded block whose body is a Beacon-API JSON object, not hex SSZ.
///
/// Not [`crate::BlindedBeaconBlock`]: that type's `body` field is `hex_vec`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlindedBeaconBlockJson {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub state_root: Root,
    /// Object produced by [`crate::block_body_json::encode_blinded`].
    pub body: serde_json::Value,
}

/// `POST /eth/v1/beacon/blinded_blocks` JSON body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignedBlindedBeaconBlockJson {
    pub message: BlindedBeaconBlockJson,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

impl SignedBlindedBeaconBlockJson {
    /// Build a blinded publish body from a signed block whose body is canonical SSZ.
    ///
    /// Encodes that body with [`crate::block_body_json::encode_blinded`] for
    /// `layout`. [`BodyForkLayout::Gloas`] returns [`BodySszError::GloasUnsupported`]
    /// and does not read the SSZ. The input block is not modified.
    pub fn from_signed_blinded(
        signed: &SignedBlindedBeaconBlock,
        layout: BodyForkLayout,
    ) -> Result<Self, BodySszError> {
        let body = crate::block_body_json::encode_blinded(&signed.message.body, layout)?;
        require_json_object(&body, "encode_blinded")?;
        Ok(Self {
            message: BlindedBeaconBlockJson {
                slot: signed.message.slot,
                proposer_index: signed.message.proposer_index,
                parent_root: signed.message.parent_root,
                state_root: signed.message.state_root,
                body,
            },
            signature: signed.signature.clone(),
        })
    }
}

/// Publish bodies are JSON objects. A hex string or null must not be signed onto the wire.
fn require_json_object(body: &serde_json::Value, encoder: &str) -> Result<(), BodySszError> {
    if body.is_object() {
        Ok(())
    } else {
        Err(BodySszError::InvalidEncoding(format!(
            "block_body_json::{encoder} did not return a JSON object"
        )))
    }
}

#[cfg(test)]
mod types {
    use super::*;

    #[test]
    fn signed_block_contents_json_serializes_the_body_as_an_object() {
        let signed = SignedBeaconBlock {
            message: crate::block::external_vector_electra_block(),
            signature: vec![0xab; crate::SIGNATURE_BYTES_LEN],
        };
        let contents = SignedBlockContentsJson::from_signed_block(
            &signed,
            vec![vec![0x11; 48]],
            vec![vec![0x22; 8]],
            BodyForkLayout::Electra,
        )
        .expect("electra body encodes");

        let body = serde_json::to_value(&contents).expect("serialize contents");
        assert!(
            body["signed_block"]["message"]["body"].is_object(),
            "signed_block.message.body must be a JSON object, not a hex string: {body}"
        );
        assert!(body["signed_block"]["message"]["body"]["execution_payload"].is_object());
        assert!(body["signed_block"]["message"]["body"]["randao_reveal"].is_string());
        assert!(body["kzg_proofs"].is_array());
        assert!(body["blobs"].is_array());
        assert_eq!(body["kzg_proofs"].as_array().unwrap().len(), 1);
        assert!(body["kzg_proofs"][0].as_str().unwrap().starts_with("0x"));

        let hex_body = serde_json::to_value(&signed).expect("serialize SignedBeaconBlock");
        assert!(
            hex_body["message"]["body"].is_string(),
            "BeaconBlock body stays hex; contents must not reuse that serde"
        );
    }

    #[test]
    fn signed_blinded_block_json_serializes_the_body_as_an_object() {
        let signed = SignedBlindedBeaconBlock {
            message: crate::block::external_vector_electra_blinded_block(),
            signature: vec![0xab; crate::SIGNATURE_BYTES_LEN],
        };
        let before = signed.message.body.clone();
        let json =
            SignedBlindedBeaconBlockJson::from_signed_blinded(&signed, BodyForkLayout::Electra)
                .expect("electra blinded body encodes");
        assert_eq!(signed.message.body, before);

        let wire = serde_json::to_value(&json).expect("serialize blinded block");
        assert!(wire["message"]["body"].is_object(), "{wire}");
        assert!(wire["message"]["body"]["execution_payload_header"].is_object());
        assert!(wire["message"]["body"].get("execution_payload").is_none());
        assert!(wire.get("signed_block").is_none());
        let hex_body = serde_json::to_value(&signed).expect("serialize SignedBlindedBeaconBlock");
        assert!(hex_body["message"]["body"].is_string());

        assert_eq!(
            SignedBlindedBeaconBlockJson::from_signed_blinded(&signed, BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
        let garbage = SignedBlindedBeaconBlock {
            message: crate::BlindedBeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body: vec![0xbe, 0xef],
            },
            signature: vec![0xab; crate::SIGNATURE_BYTES_LEN],
        };
        assert!(matches!(
            SignedBlindedBeaconBlockJson::from_signed_blinded(&garbage, BodyForkLayout::Deneb),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert_eq!(garbage.message.body, vec![0xbe, 0xef]);
    }

    #[test]
    fn publish_body_must_be_a_json_object() {
        for body in [serde_json::Value::Null, serde_json::Value::String("0x00".into())] {
            let err = require_json_object(&body, "encode_blinded").expect_err("non-object");
            assert_eq!(
                err,
                BodySszError::InvalidEncoding(
                    "block_body_json::encode_blinded did not return a JSON object".into()
                )
            );
        }
        assert!(require_json_object(&serde_json::json!({}), "encode_blinded").is_ok());
    }

    #[test]
    fn published_json_matches_signed_body_leaf_with_a_withdrawal() {
        let mut body = crate::block_body::external_vector_blinded_electra_body();
        body.execution_requests.withdrawals =
            ssz_types::VariableList::from(vec![crate::block_body::WithdrawalRequest {
                source_address: [0xab; 20],
                validator_pubkey: [0xcd; 48],
                amount: 32_000_000_000,
            }]);
        assert_eq!(body.execution_requests.withdrawals.len(), 1);
        let ssz = body.as_ssz_bytes();
        let signed = SignedBlindedBeaconBlock {
            message: crate::BlindedBeaconBlock {
                slot: 3_000_000,
                proposer_index: 42,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body: ssz,
            },
            signature: vec![0xab; crate::SIGNATURE_BYTES_LEN],
        };
        let json =
            SignedBlindedBeaconBlockJson::from_signed_blinded(&signed, BodyForkLayout::Electra)
                .expect("encode");
        let decoded =
            crate::block_body_json::decode_blinded(&json.message.body, BodyForkLayout::Electra)
                .expect("decode published body");
        let published =
            crate::blinded_body_tree_hash_root_for_layout(&decoded, BodyForkLayout::Electra)
                .expect("published leaf");
        let signed_leaf = crate::blinded_body_tree_hash_root_for_layout(
            &signed.message.body,
            BodyForkLayout::Electra,
        )
        .expect("signed leaf");
        assert_eq!(published, signed_leaf);
        let typed = crate::decode_blinded_beacon_block_body_electra(&decoded).expect("typed");
        assert_eq!(typed.execution_requests.withdrawals.len(), 1);
    }
}
