//! Beacon-API JSON `SignedBlockContents`: `{signed_block, kzg_proofs, blobs}`.
//!
//! `signed_block.message.body` is a JSON object from [`crate::block_body_json::encode`],
//! not the hex string [`crate::BeaconBlock`] emits. SSZ stays canonical on
//! [`crate::SignedBeaconBlock`]. [`crate::BodyForkLayout::Gloas`] fails closed.
//! No production path publishes this yet.

use serde::Serialize;

use crate::{BodyForkLayout, BodySszError, Root, Signature, SignedBeaconBlock, Slot};

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
        let body = crate::block_body_json::encode(&signed_block.message.body, layout)?;
        if !body.is_object() {
            return Err(BodySszError::InvalidEncoding(
                "block_body_json::encode did not return a JSON object".into(),
            ));
        }
        Ok(Self {
            signed_block: SignedBeaconBlockJson {
                message: BeaconBlockJson {
                    slot: signed_block.message.slot,
                    proposer_index: signed_block.message.proposer_index,
                    parent_root: signed_block.message.parent_root,
                    state_root: signed_block.message.state_root,
                    body,
                },
                signature: signed_block.signature.clone(),
            },
            kzg_proofs,
            blobs,
        })
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
}
