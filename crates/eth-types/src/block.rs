use serde::{Deserialize, Serialize};
use tree_hash::{mix_in_length, MerkleHasher, TreeHash};

use crate::block_body::{
    blinded_body_tree_hash_root, blinded_body_tree_hash_root_for_layout, body_tree_hash_root,
    body_tree_hash_root_for_layout, decode_beacon_block_body_deneb,
    decode_beacon_block_body_electra, BodySszError,
};
use crate::hex_fixed::bytes_32_hex;
use crate::tree_hash_utils::{impl_container_tree_hash, TreeHashError};
use crate::{Root, Signature, Slot};

/// Fork variants relevant to `BeaconBlockBody` SSZ layout for KZG extraction.
///
/// Deneb has `blob_kzg_commitments` as the *last* variable field (field 12).
/// Electra adds `execution_requests` as field 13 *after* `blob_kzg_commitments`.
/// Gloas has no decoder yet; extraction and layout HTR fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyForkLayout {
    /// Deneb `BeaconBlockBody`: `blob_kzg_commitments` is the trailing variable field.
    Deneb,
    /// Electra+ `BeaconBlockBody`: `execution_requests` follows `blob_kzg_commitments`.
    Electra,
    /// Gloas `BeaconBlockBody`: no decoder; KZG extraction and layout HTR error.
    Gloas,
}

/// Map a `consensus_version` string from the BN response to a `BodyForkLayout`.
///
/// Returns `Some(Deneb)` for `"deneb"`, `Some(Electra)` for `"electra"` /
/// `"fulu"`, `Some(Gloas)` for `"gloas"`. Pre-Deneb forks have no blob
/// commitments and return `None`.
///
/// Exact, case-sensitive match via [`ForkName::from_str`] + [`ForkName::body_layout`].
/// Unrecognised strings (including wrong case) yield `None`.
pub fn body_fork_layout(consensus_version: &str) -> Option<BodyForkLayout> {
    use std::str::FromStr;

    use crate::fork::ForkName;

    ForkName::from_str(consensus_version).ok().and_then(ForkName::body_layout)
}

/// Extract blob KZG commitments from a raw SSZ-encoded `BeaconBlockBody`.
///
/// Dispatches on `layout` to the typed Deneb/Electra body decoder and returns
/// `body.blob_kzg_commitments`. A **genuinely empty** commitment list is
/// `Ok(vec![])`; a **malformed** body is `Err(BodySszError)` — the two must not
/// be conflated (a corrupt body must not fingerprint as the empty list).
/// [`BodyForkLayout::Gloas`] is always `Err` (no decoder; never `Ok(vec![])`).
///
/// # Spec reference
///
/// Deneb `BeaconBlockBody` (EIP-4844): `blob_kzg_commitments` is field 12.
/// Electra `BeaconBlockBody` (EIP-7685): `execution_requests` is field 13 after
/// the commitments; the typed decoder bounds the commitment list correctly.
pub(crate) fn extract_blob_kzg_commitments(
    body: &[u8],
    layout: BodyForkLayout,
) -> Result<Vec<[u8; 48]>, BodySszError> {
    match layout {
        BodyForkLayout::Deneb => {
            let decoded = decode_beacon_block_body_deneb(body)?;
            Ok(decoded.blob_kzg_commitments.into())
        }
        BodyForkLayout::Electra => {
            let decoded = decode_beacon_block_body_electra(body)?;
            Ok(decoded.blob_kzg_commitments.into())
        }
        // Empty Ok would silently disable the blob-binding control.
        BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

/// Compute an internal KZG-commitment binding fingerprint.
///
/// **NOT spec-aligned.** This is *not* the spec's
/// `hash_tree_root(List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK=4096])`
/// — the spec merkleizes per-element roots with `limit=4096` padding, which
/// produces different 32-byte values than this function. This function packs
/// commitments into raw 32-byte chunks (bytes 0–31 + bytes 32–47 zero-padded)
/// and merkleizes them with `mix_in_length`. The output is deterministic,
/// collision-resistant, and length-sensitive — sufficient for the
/// defense-in-depth goal of detecting commitment substitution by a compromised
/// BN — but it must not be cross-checked against a Lighthouse / Lodestar
/// `hash_tree_root` value.
///
/// This root is used as an **internal fingerprint** (ISSUE-4.3, L-3): it
/// makes `blob_kzg_commitments` deterministically addressable within rvc
/// without altering the BN-facing signing scope.
pub fn kzg_commitment_list_root(commitments: &[[u8; 48]]) -> [u8; 32] {
    // Each KZGCommitment (48 bytes) packs into two 32-byte chunks.
    let num_chunks = commitments.len().saturating_mul(2);
    let mut hasher = MerkleHasher::with_leaves(num_chunks.max(1));

    for commitment in commitments {
        // First chunk: bytes 0–31.
        hasher.write(&commitment[..32]).expect("valid first chunk");
        // Second chunk: bytes 32–47 zero-padded to 32 bytes.
        let mut second = [0u8; 32];
        second[..16].copy_from_slice(&commitment[32..]);
        hasher.write(&second).expect("valid second chunk");
    }

    let root = hasher.finish().expect("valid merkle root");
    // Mix in the element count for length-sensitivity (SSZ List semantics).
    mix_in_length(&root, commitments.len())
        .as_slice()
        .try_into()
        .expect("Hash256 is always 32 bytes")
}

pub type BeaconBlockBody = Vec<u8>;
pub type BlindedBeaconBlockBody = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BeaconBlockBody,
}

/// SSZ `BeaconBlockHeader` container (FR-31, ADR-009).
///
/// From Bellatrix onward, the Web3Signer `BLOCK_V2` request carries the block
/// **header** (`{slot, proposer_index, parent_root, state_root, body_root}`),
/// not the full block. The handler computes the block signing root by hashing
/// this header — reconstructing a full block is impossible (clients send only
/// the header) and a slashing-safety hazard.
///
/// The five fields are in **spec order**; SSZ Merkleization is order-sensitive,
/// so do not reorder. Field encodings mirror `AttestationData` (`quoted_u64`
/// integers, `0x`+lowercase 32-byte hex roots). `#[derive(TreeHash)]`
/// auto-generates the correct 5-leaf container `tree_hash_root` (no hand-written
/// `MerkleHasher` is needed — that is only for the `Vec<u8>`-body cases like
/// `BeaconBlock`).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    ssz_derive::Encode,
    ssz_derive::Decode,
    tree_hash_derive::TreeHash,
)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub body_root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedBeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BlindedBeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSidecar {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BlockContents {
    BlockAndBlobs { block: BeaconBlock, blob_sidecars: Vec<BlobSidecar> },
    Block(BeaconBlock),
}

impl<'de> serde::Deserialize<'de> for BlockContents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        // Try BlockAndBlobs first (has both "block" and "blob_sidecars" keys)
        if value.get("blob_sidecars").is_some() {
            #[derive(Deserialize)]
            struct BlockAndBlobsHelper {
                block: BeaconBlock,
                blob_sidecars: Vec<BlobSidecar>,
            }
            return serde_json::from_value::<BlockAndBlobsHelper>(value.clone())
                .map(|h| BlockContents::BlockAndBlobs {
                    block: h.block,
                    blob_sidecars: h.blob_sidecars,
                })
                .map_err(|e| {
                    serde::de::Error::custom(format!("invalid BlockAndBlobs variant: {e}"))
                });
        }

        // Fall back to Block (bare BeaconBlock)
        serde_json::from_value::<BeaconBlock>(value)
            .map(BlockContents::Block)
            .map_err(|e| serde::de::Error::custom(format!("invalid Block variant: {e}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProducedBlock {
    Full(BlockContents),
    Blinded(BlindedBeaconBlock),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

impl BlockContents {
    pub fn block(&self) -> &BeaconBlock {
        match self {
            Self::Block(block) => block,
            Self::BlockAndBlobs { block, .. } => block,
        }
    }

    /// Extract blob KZG commitments from the `BeaconBlockBody` SSZ bytes.
    ///
    /// Returns `Ok(vec![])` for the `Block` variant (no blob commitments on that
    /// wire shape). For `BlockAndBlobs`, decodes the body with the typed layout
    /// decoder: empty commitments are `Ok(vec![])`, malformed SSZ is `Err`.
    ///
    /// This is the ISSUE-4.3 (L-3) defense-in-depth accessor: blob commitments
    /// are already opaquely bound via the block body tree hash; exposing them
    /// canonically allows callers to verify counts and compute a structured root
    /// before signing without changing the BN-facing signing scope.
    pub fn blob_kzg_commitments(
        &self,
        layout: BodyForkLayout,
    ) -> Result<Vec<[u8; 48]>, BodySszError> {
        match self {
            Self::BlockAndBlobs { block, .. } => extract_blob_kzg_commitments(&block.body, layout),
            Self::Block(_) => Ok(vec![]),
        }
    }

    /// Compute the internal KZG commitment binding fingerprint (ISSUE-4.3, L-3).
    ///
    /// Each 48-byte commitment is packed into two 32-byte chunks, merkleized,
    /// and the element count is mixed in. Returns the empty-list fingerprint for
    /// `Block` or for `BlockAndBlobs` with no blobs. **NOT spec-aligned**; see
    /// [`kzg_commitment_list_root`] for the threat model and design rationale.
    ///
    /// `layout` selects the body SSZ schema (Deneb vs. Electra+). Propagates
    /// body-decode errors — a corrupt body is never fingerprinted as empty.
    ///
    /// This root is **separate from and does not change the block signing scope**.
    /// It is logged by the block service as a structured commitment binding.
    pub fn kzg_commitment_root(&self, layout: BodyForkLayout) -> Result<[u8; 32], BodySszError> {
        Ok(kzg_commitment_list_root(&self.blob_kzg_commitments(layout)?))
    }
}

/// Electra `BeaconBlock` for the SEC-6c external block-level vector.
///
/// Header: slot=3_000_000, proposer=42, parent=`0x11…`, state=`0x22…`;
/// body = [`crate::block_body::external_vector_electra_body`].
///
/// Gated behind `test-fixtures` (or crate-local `cfg(test)`); see RF3-19.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_electra_block() -> BeaconBlock {
    BeaconBlock {
        slot: 3_000_000,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: crate::block_body::external_vector_electra_body().as_ssz_bytes(),
    }
}

/// Electra blinded block for the SEC-6d external vector (distinct blinded
/// graffiti; same header fields as the full Electra block vector).
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_electra_blinded_block() -> BlindedBeaconBlock {
    BlindedBeaconBlock {
        slot: 3_000_000,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: crate::block_body::external_vector_blinded_electra_body().as_ssz_bytes(),
    }
}

/// Deneb `BeaconBlock` for the SEC-6d external block-level vector.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_deneb_block() -> BeaconBlock {
    BeaconBlock {
        slot: 3_000_000,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: crate::block_body::external_vector_deneb_body().as_ssz_bytes(),
    }
}

/// Deneb blinded block for the SEC-6d external vector.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_deneb_blinded_block() -> BlindedBeaconBlock {
    BlindedBeaconBlock {
        slot: 3_000_000,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: crate::block_body::external_vector_blinded_deneb_body().as_ssz_bytes(),
    }
}

impl BeaconBlock {
    /// Compute the internal KZG commitment binding fingerprint from this block's body SSZ.
    ///
    /// Equivalent to `BlockContents::kzg_commitment_root` for the SSZ signing
    /// path where a bare `BeaconBlock` is available instead of `BlockContents`.
    /// **NOT spec-aligned**; see [`kzg_commitment_list_root`] doc.
    ///
    /// `layout` selects the body SSZ schema (Deneb vs. Electra+). Propagates
    /// body-decode errors — a corrupt body is never fingerprinted as empty.
    pub fn kzg_commitment_root(&self, layout: BodyForkLayout) -> Result<[u8; 32], BodySszError> {
        Ok(kzg_commitment_list_root(&extract_blob_kzg_commitments(&self.body, layout)?))
    }

    /// Return the number of blob KZG commitments in this block's body SSZ.
    ///
    /// Propagates typed body-decode errors; does not treat malformed SSZ as
    /// zero commitments.
    pub fn blob_kzg_count(&self, layout: BodyForkLayout) -> Result<usize, BodySszError> {
        Ok(extract_blob_kzg_commitments(&self.body, layout)?.len())
    }
}

// Leaf order: slot, proposer_index, parent_root, state_root, body_root
// (body_root is the typed body HTR over raw SSZ bytes — not a ByteList leaf).
impl_container_tree_hash!(
    BeaconBlock,
    "valid Electra/Deneb BeaconBlockBody SSZ for tree_hash_root",
    body_auto = |s| {
        body_tree_hash_root(&s.body)
            .map_err(|e| TreeHashError::InvalidBody { reason: e.to_string() })
    },
    body_layout = |s, layout| {
        body_tree_hash_root_for_layout(&s.body, layout)
            .map_err(|e| TreeHashError::InvalidBody { reason: e.to_string() })
    },
    [
        |s| Ok(s.slot.tree_hash_root()),
        |s| Ok(s.proposer_index.tree_hash_root()),
        |s| Ok(s.parent_root.tree_hash_root()),
        |s| Ok(s.state_root.tree_hash_root()),
    ]
);

// Leaf order: slot, proposer_index, parent_root, state_root, body_root
// (body_root is the typed blinded body HTR over raw SSZ bytes).
impl_container_tree_hash!(
    BlindedBeaconBlock,
    "valid Electra/Deneb BlindedBeaconBlockBody SSZ for tree_hash_root",
    body_auto = |s| {
        blinded_body_tree_hash_root(&s.body)
            .map_err(|e| TreeHashError::InvalidBody { reason: e.to_string() })
    },
    body_layout = |s, layout| {
        blinded_body_tree_hash_root_for_layout(&s.body, layout)
            .map_err(|e| TreeHashError::InvalidBody { reason: e.to_string() })
    },
    [
        |s| Ok(s.slot.tree_hash_root()),
        |s| Ok(s.proposer_index.tree_hash_root()),
        |s| Ok(s.parent_root.tree_hash_root()),
        |s| Ok(s.state_root.tree_hash_root()),
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_body::{
        external_vector_blinded_electra_body, external_vector_deneb_body,
        external_vector_electra_body, EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX,
        EXTERNAL_DENEB_BLOCK_ROOT_HEX, EXTERNAL_DENEB_BODY_ROOT_HEX,
        EXTERNAL_ELECTRA_BLOCK_ROOT_HEX, EXTERNAL_ELECTRA_BODY_ROOT_HEX,
    };
    use tree_hash::TreeHash;

    fn sample_block() -> BeaconBlock {
        BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: external_vector_electra_body().as_ssz_bytes(),
        }
    }

    fn sample_blinded_block() -> BlindedBeaconBlock {
        // Distinct graffiti so body root differs from the full sample (empty-ops
        // full vs blinded bodies otherwise share the same body HTR).
        let mut body = external_vector_blinded_electra_body();
        body.graffiti = [0xbe; 32];
        BlindedBeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: body.as_ssz_bytes(),
        }
    }

    fn sample_blob_sidecar() -> BlobSidecar {
        BlobSidecar { index: 0, blob: vec![0xab; 8] }
    }

    /// Pin `body_fork_layout` behaviour: exact, case-sensitive fork names only.
    /// RF3-07 delegates onto `ForkName`; this table guards against accidental
    /// leniency (lowercase, trimming) and against layout drift.
    #[test]
    fn test_body_fork_layout_unchanged_for_all_known_and_unknown_versions() {
        let cases: &[(&str, Option<BodyForkLayout>)] = &[
            ("phase0", None),
            ("altair", None),
            ("bellatrix", None),
            ("capella", None),
            ("deneb", Some(BodyForkLayout::Deneb)),
            ("electra", Some(BodyForkLayout::Electra)),
            ("fulu", Some(BodyForkLayout::Electra)),
            ("gloas", Some(BodyForkLayout::Gloas)),
            // Exact-match only: trailing space / wrong case / empty / garbage → None
            ("electra ", None),
            ("Deneb", None),
            ("ELECTRA", None),
            ("", None),
            ("not-a-fork", None),
            ("deneb\n", None),
        ];
        for &(version, expected) in cases {
            assert_eq!(
                body_fork_layout(version),
                expected,
                "body_fork_layout({version:?}) mismatch"
            );
        }
    }

    #[test]
    fn test_beacon_block_serde_roundtrip() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_beacon_block_quoted_integers() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blinded_beacon_block_serde_roundtrip() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_blinded_beacon_block_quoted_integers() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blob_sidecar_serde_roundtrip() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let deserialized: BlobSidecar = serde_json::from_str(&json).unwrap();
        assert_eq!(sidecar, deserialized);
    }

    #[test]
    fn test_blob_sidecar_quoted_index() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["index"], serde_json::Value::String("0".to_string()));
    }

    #[test]
    fn test_block_contents_block_only_serde_roundtrip() {
        let contents = BlockContents::Block(sample_block());
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_with_blobs_serde_roundtrip() {
        let contents = BlockContents::BlockAndBlobs {
            block: sample_block(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_block_accessor() {
        let block = sample_block();
        let contents_block = BlockContents::Block(block.clone());
        assert_eq!(contents_block.block(), &block);

        let contents_blobs = BlockContents::BlockAndBlobs {
            block: block.clone(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        assert_eq!(contents_blobs.block(), &block);
    }

    #[test]
    fn test_block_contents_empty_blobs() {
        let contents =
            BlockContents::BlockAndBlobs { block: sample_block(), blob_sidecars: vec![] };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_signed_beacon_block_serde_roundtrip() {
        let signed = SignedBeaconBlock { message: sample_block(), signature: vec![0xaa; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_signed_blinded_beacon_block_serde_roundtrip() {
        let signed =
            SignedBlindedBeaconBlock { message: sample_blinded_block(), signature: vec![0xbb; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_produced_block_full_variant() {
        let produced = ProducedBlock::Full(BlockContents::Block(sample_block()));
        assert!(matches!(produced, ProducedBlock::Full(_)));
    }

    #[test]
    fn test_produced_block_blinded_variant() {
        let produced = ProducedBlock::Blinded(sample_blinded_block());
        assert!(matches!(produced, ProducedBlock::Blinded(_)));
    }

    #[test]
    fn test_beacon_block_fields() {
        let block = sample_block();
        assert_eq!(block.slot, 100);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.parent_root, [1u8; 32]);
        assert_eq!(block.state_root, [2u8; 32]);
    }

    #[test]
    fn test_beacon_block_tree_hash_root_deterministic() {
        let block = sample_block();
        let root1 = block.tree_hash_root();
        let root2 = block.tree_hash_root();
        assert_eq!(root1, root2);
        assert_ne!(root1.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_beacon_block_tree_hash_root_differs_for_different_blocks() {
        let block1 = sample_block();
        let mut block2 = sample_block();
        block2.slot = 200;
        assert_ne!(block1.tree_hash_root(), block2.tree_hash_root());
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_root_deterministic() {
        let block = sample_blinded_block();
        let root1 = block.tree_hash_root();
        let root2 = block.tree_hash_root();
        assert_eq!(root1, root2);
        assert_ne!(root1.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_root_differs_for_different_blocks() {
        let block1 = sample_blinded_block();
        let mut block2 = sample_blinded_block();
        block2.slot = 200;
        assert_ne!(block1.tree_hash_root(), block2.tree_hash_root());
    }

    #[test]
    fn test_block_contents_invalid_json_error_has_context() {
        let json = r#"{"blob_sidecars": "not-an-array"}"#;
        let err = serde_json::from_str::<BlockContents>(json).unwrap_err();
        assert!(
            err.to_string().contains("BlockAndBlobs"),
            "expected error to mention BlockAndBlobs variant, got: {}",
            err
        );
    }

    #[test]
    fn test_block_contents_completely_invalid_json_error() {
        let json = r#"{"random_field": 42}"#;
        let err = serde_json::from_str::<BlockContents>(json).unwrap_err();
        assert!(
            err.to_string().contains("Block variant"),
            "expected error to mention Block variant, got: {}",
            err
        );
    }

    #[test]
    fn test_beacon_block_and_blinded_differ() {
        let block = sample_block();
        let blinded = sample_blinded_block();
        assert_ne!(block.tree_hash_root(), blinded.tree_hash_root());
    }

    // ── SEC-6c: typed body leaf + external-vector block root ─────────────────

    #[test]
    fn test_beacon_block_body_leaf_is_typed_not_bytelist() {
        // Old non-spec leaf was vec_u8_tree_hash_root(body_ssz). Spec leaf is
        // hash_tree_root(typed body) == EXTERNAL_ELECTRA_BODY_ROOT.
        let block = external_vector_electra_block();
        let body_root = external_vector_electra_body().tree_hash_root();
        assert_eq!(body_root.as_slice(), &hex::decode(EXTERNAL_ELECTRA_BODY_ROOT_HEX).unwrap()[..]);
        // Reconstruct block root as independent 5-leaf container with body_root leaf.
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(block.slot.tree_hash_root().as_slice()).unwrap();
        hasher.write(block.proposer_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(block.parent_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(block.state_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(body_root.as_slice()).unwrap();
        let expected = hasher.finish().unwrap();
        assert_eq!(block.tree_hash_root(), expected);
        assert_eq!(
            block.tree_hash_root().as_slice(),
            &hex::decode(EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap()[..],
            "block HTR must match external remerkleable KAT"
        );
    }

    #[test]
    fn test_beacon_block_tree_hash_matches_external_electra_vector() {
        let block = external_vector_electra_block();
        let root = block.try_tree_hash_root().expect("valid external vector body");
        assert_eq!(
            root.as_slice(),
            &hex::decode(EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap()[..],
            "BeaconBlock hash_tree_root must match remerkleable external vector"
        );
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_matches_external_electra_vector() {
        // SEC-6d distinct-graffiti blinded Electra vector (not the full-body KAT).
        let block = external_vector_electra_blinded_block();
        let root = block.try_tree_hash_root().expect("valid external vector blinded body");
        assert_eq!(
            root.as_slice(),
            &hex::decode(EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX).unwrap()[..],
            "BlindedBeaconBlock hash_tree_root must match remerkleable external vector"
        );
        assert_ne!(root.as_slice(), &hex::decode(EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap()[..],);
    }

    #[test]
    fn test_beacon_block_tree_hash_matches_external_deneb_vector() {
        let block = external_vector_deneb_block();
        let root = block.try_tree_hash_root().expect("valid Deneb external vector body");
        assert_eq!(
            root.as_slice(),
            &hex::decode(EXTERNAL_DENEB_BLOCK_ROOT_HEX).unwrap()[..],
            "Deneb BeaconBlock hash_tree_root must match remerkleable external vector"
        );
        // Explicit layout path matches auto-detect.
        assert_eq!(block.try_tree_hash_root_for_layout(BodyForkLayout::Deneb).unwrap(), root);
        // Body leaf is the typed Deneb body root.
        assert_eq!(
            external_vector_deneb_body().tree_hash_root().as_slice(),
            &hex::decode(EXTERNAL_DENEB_BODY_ROOT_HEX).unwrap()[..],
        );
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_matches_external_deneb_vector() {
        let block = external_vector_deneb_blinded_block();
        let root = block.try_tree_hash_root().expect("valid Deneb blinded body");
        // Empty-ops full/blinded Deneb share body HTR → same block root KAT.
        assert_eq!(root.as_slice(), &hex::decode(EXTERNAL_DENEB_BLOCK_ROOT_HEX).unwrap()[..],);
        assert_eq!(block.try_tree_hash_root_for_layout(BodyForkLayout::Deneb).unwrap(), root);
    }

    #[test]
    fn test_malformed_body_returns_error_not_panic() {
        let block = BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: vec![0xde, 0xad], // not valid Electra/Deneb body SSZ
        };
        let err = block.try_tree_hash_root().expect_err("malformed body must error");
        assert!(
            matches!(err, TreeHashError::InvalidBody { .. }),
            "expected InvalidBody, got {err:?}"
        );

        let blinded = BlindedBeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: vec![0xbe, 0xef],
        };
        let err = blinded.try_tree_hash_root().expect_err("malformed blinded body must error");
        assert!(matches!(err, TreeHashError::InvalidBody { .. }));
    }

    #[test]
    fn test_beacon_block_gloas_layout_try_tree_hash_root() {
        // kat_exempt: Gloas layout is an error arm; no spec root exists to anchor
        let block = sample_block();
        let err = block
            .try_tree_hash_root_for_layout(BodyForkLayout::Gloas)
            .expect_err("Gloas layout must not produce a block root");
        assert!(
            matches!(err, TreeHashError::InvalidBody { .. }),
            "expected InvalidBody, got {err:?}"
        );
    }

    // ── ISSUE-4.3 (L-3): extract_blob_kzg_commitments unit tests ────────────
    //
    // Well-formed bodies use typed SSZ encode (external-vector fixtures + set
    // blob_kzg_commitments). Malformed cases use truncated/corrupted bytes and
    // must yield Err — never Ok(vec![]) (empty list is only for valid empty).

    /// Spec cap `MAX_BLOB_COMMITMENTS_PER_BLOCK` (typed containers own the limit).
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;

    /// Valid Deneb body SSZ with the given `blob_kzg_commitments`.
    fn body_with_kzg_commitments(commitments: &[[u8; 48]]) -> Vec<u8> {
        let mut body = crate::block_body::external_vector_deneb_body();
        body.blob_kzg_commitments = commitments.to_vec().into();
        body.as_ssz_bytes()
    }

    /// Valid Electra body SSZ with the given `blob_kzg_commitments`.
    fn electra_body_with_kzg_commitments(commitments: &[[u8; 48]]) -> Vec<u8> {
        let mut body = crate::block_body::external_vector_electra_body();
        body.blob_kzg_commitments = commitments.to_vec().into();
        body.as_ssz_bytes()
    }

    fn assert_body_ssz_err(result: Result<Vec<[u8; 48]>, BodySszError>) {
        match result {
            Err(BodySszError::InvalidEncoding(_)) => {}
            other => panic!("expected BodySszError::InvalidEncoding, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_kzg_commitments_two_blobs() {
        let c0 = [0x11; 48];
        let c1 = [0x22; 48];
        let body = body_with_kzg_commitments(&[c0, c1]);
        let parsed = extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb).unwrap();
        assert_eq!(parsed, vec![c0, c1]);
    }

    /// Genuinely empty commitment list on a well-formed body is Ok([]), not Err.
    #[test]
    fn test_extract_kzg_commitments_empty() {
        let body = body_with_kzg_commitments(&[]);
        let parsed = extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb).unwrap();
        assert_eq!(parsed, Vec::<[u8; 48]>::new());
    }

    /// Truncated body must be Err, not Ok([]) — empty list vs malformed distinction.
    #[test]
    fn test_extract_kzg_commitments_body_too_short() {
        let body = vec![0u8; 100];
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb));
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Electra));
    }

    /// Fixed-portion-only zeros (invalid offsets) must be Err, not Ok([]).
    #[test]
    fn test_extract_kzg_commitments_invalid_offset_zero() {
        // 392 zero bytes: not a valid Deneb container (variable offsets are 0).
        let body = vec![0u8; 392];
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb));

        let mut longer = vec![0u8; 392 + 48];
        // Offset pointing inside the fixed portion.
        let bad_offset = 391u32;
        longer[388..392].copy_from_slice(&bad_offset.to_le_bytes());
        assert_body_ssz_err(extract_blob_kzg_commitments(&longer, BodyForkLayout::Deneb));
    }

    /// Trailing bytes that break SSZ list alignment/length must be rejected.
    #[test]
    fn test_extract_kzg_commitments_misaligned_data_rejected() {
        let mut body = body_with_kzg_commitments(&[[0xaa; 48]]);
        body.push(0xff); // corrupt trailing length of last variable field
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb));
    }

    /// Well-formed body with empty KZG list: Ok([]) without panic.
    #[test]
    fn test_extract_kzg_commitments_offset_at_body_end() {
        let body = body_with_kzg_commitments(&[]);
        assert_eq!(
            extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb).unwrap(),
            Vec::<[u8; 48]>::new()
        );
    }

    /// Over `MAX_BLOB_COMMITMENTS_PER_BLOCK` entries: typed decode rejects.
    #[test]
    fn test_extract_kzg_commitments_over_max_rejected() {
        // Encode at the max, then append one extra commitment to the trailing list.
        let max_list = vec![[0u8; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        let mut body = body_with_kzg_commitments(&max_list);
        body.extend_from_slice(&[0u8; 48]);
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb));
    }

    /// Electra typed decoder returns only `blob_kzg_commitments` (not
    /// `execution_requests`). Wrong layout (Deneb decoder on Electra SSZ) fails
    /// closed rather than silently over-reading.
    #[test]
    fn test_extract_kzg_commitments_electra_bounds_at_next_offset() {
        let real = [[0x11u8; 48], [0x22u8; 48]];
        let body = electra_body_with_kzg_commitments(&real);

        assert_eq!(
            extract_blob_kzg_commitments(&body, BodyForkLayout::Electra).unwrap(),
            vec![[0x11u8; 48], [0x22u8; 48]],
        );
        // Deneb layout on an Electra body is a decode error (fail-closed).
        assert_body_ssz_err(extract_blob_kzg_commitments(&body, BodyForkLayout::Deneb));
    }

    /// Gloas is a typed error, never Ok([]) — empty would silently drop blob binding.
    #[test]
    fn test_extract_blob_kzg_commitments_gloas_returns_err() {
        let body = sample_block().body;
        let err = extract_blob_kzg_commitments(&body, BodyForkLayout::Gloas)
            .expect_err("Gloas layout must not extract commitments");
        let msg = err.to_string();
        assert!(msg.to_ascii_lowercase().contains("gloas"), "error must name Gloas, got: {msg}");
        assert!(sample_block().kzg_commitment_root(BodyForkLayout::Gloas).is_err());
        assert!(sample_block().blob_kzg_count(BodyForkLayout::Gloas).is_err());
    }

    /// Round-trip: Electra encode → extract matches hand-set commitments.
    #[test]
    fn test_extract_kzg_commitments_electra_round_trip() {
        let c0 = [0xab; 48];
        let c1 = [0xcd; 48];
        let body = electra_body_with_kzg_commitments(&[c0, c1]);
        assert_eq!(
            extract_blob_kzg_commitments(&body, BodyForkLayout::Electra).unwrap(),
            vec![c0, c1]
        );
    }

    /// Empty list vs truncated body: Ok([]) vs Err (contract pin).
    #[test]
    fn test_extract_empty_list_ok_truncated_err() {
        let empty_ok =
            extract_blob_kzg_commitments(&body_with_kzg_commitments(&[]), BodyForkLayout::Deneb)
                .unwrap();
        assert!(empty_ok.is_empty());

        let truncated_err = extract_blob_kzg_commitments(&[0u8; 50], BodyForkLayout::Deneb);
        assert_body_ssz_err(truncated_err);
    }

    // ── ISSUE-4.3 (L-3): kzg_commitment_list_root unit tests ────────────────

    #[test]
    fn test_kzg_commitment_list_root_deterministic() {
        let commitments = [[0xab; 48], [0xcd; 48]];
        assert_eq!(kzg_commitment_list_root(&commitments), kzg_commitment_list_root(&commitments));
    }

    #[test]
    fn test_kzg_commitment_list_root_nonzero_for_nonempty() {
        let root = kzg_commitment_list_root(&[[0x42; 48]]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_kzg_commitment_list_root_length_sensitive() {
        let c = [0xff; 48];
        let root_one = kzg_commitment_list_root(&[c]);
        let root_two = kzg_commitment_list_root(&[c, c]);
        assert_ne!(root_one, root_two, "root must be length-sensitive");
    }

    #[test]
    fn test_kzg_commitment_list_root_empty_deterministic() {
        let r1 = kzg_commitment_list_root(&[]);
        let r2 = kzg_commitment_list_root(&[]);
        assert_eq!(r1, r2, "empty root must be deterministic");
    }

    // ── ISSUE-4.3 (L-3): BlockContents methods ──────────────────────────────

    #[test]
    fn test_block_contents_blob_kzg_commitments_extracted() {
        let c = [0x77; 48];
        let body = body_with_kzg_commitments(&[c]);
        let contents = BlockContents::BlockAndBlobs {
            block: BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body,
            },
            blob_sidecars: vec![],
        };
        assert_eq!(contents.blob_kzg_commitments(BodyForkLayout::Deneb).unwrap(), vec![c]);
    }

    #[test]
    fn test_block_contents_kzg_root_changes_with_commitment_mutation() {
        let original = [0xde; 48];
        let body_orig = body_with_kzg_commitments(&[original]);
        let make_block = |body: Vec<u8>| BlockContents::BlockAndBlobs {
            block: BeaconBlock {
                slot: 10,
                proposer_index: 1,
                parent_root: [0; 32],
                state_root: [0; 32],
                body,
            },
            blob_sidecars: vec![],
        };

        let root_orig = make_block(body_orig).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();

        let mut mutated = original;
        mutated[0] ^= 0x01;
        let body_mut = body_with_kzg_commitments(&[mutated]);
        let root_mut = make_block(body_mut).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();

        assert_ne!(root_orig, root_mut, "mutated commitment must change root");
    }

    #[test]
    fn test_block_variant_has_no_blob_kzg_commitments() {
        let body = body_with_kzg_commitments(&[[0xff; 48]]);
        let contents = BlockContents::Block(BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body,
        });
        assert_eq!(
            contents.blob_kzg_commitments(BodyForkLayout::Deneb).unwrap(),
            Vec::<[u8; 48]>::new(),
            "Block variant must return empty commitments"
        );
    }

    #[test]
    fn test_block_contents_malformed_body_kzg_root_errors() {
        let contents = BlockContents::BlockAndBlobs {
            block: BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body: vec![0u8; 50],
            },
            blob_sidecars: vec![],
        };
        assert!(contents.kzg_commitment_root(BodyForkLayout::Deneb).is_err());
        assert!(contents.blob_kzg_commitments(BodyForkLayout::Deneb).is_err());
    }

    // ── FR-31 (Issue 1.4): BeaconBlockHeader SSZ + tree_hash_root KAT ────────

    use sha2::{Digest, Sha256};

    /// SSZ `uint64` leaf: little-endian 8 bytes, right-zero-padded to 32.
    fn u64_leaf(x: u64) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        leaf[..8].copy_from_slice(&x.to_le_bytes());
        leaf
    }

    fn sha256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }

    /// Independent SSZ Merkleization of the 5-field `BeaconBlockHeader` container
    /// (pad to 8 leaves), computed with raw `sha2` in spec field order —
    /// deliberately NOT using `tree_hash_derive`, so it is an external oracle
    /// that catches a field-order or leaf-count bug in the derived impl.
    fn independent_header_root(h: &BeaconBlockHeader) -> [u8; 32] {
        let zero = [0u8; 32];
        let leaves = [
            u64_leaf(h.slot),
            u64_leaf(h.proposer_index),
            h.parent_root,
            h.state_root,
            h.body_root,
            zero,
            zero,
            zero,
        ];
        let n0 = sha256_pair(&leaves[0], &leaves[1]);
        let n1 = sha256_pair(&leaves[2], &leaves[3]);
        let n2 = sha256_pair(&leaves[4], &leaves[5]);
        let n3 = sha256_pair(&leaves[6], &leaves[7]);
        let m0 = sha256_pair(&n0, &n1);
        let m1 = sha256_pair(&n2, &n3);
        sha256_pair(&m0, &m1)
    }

    fn sample_header() -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 3_000_000,
            proposer_index: 12_345,
            parent_root: [0x11u8; 32],
            state_root: [0x22u8; 32],
            body_root: [0x33u8; 32],
        }
    }

    fn header_root(h: &BeaconBlockHeader) -> [u8; 32] {
        h.tree_hash_root().as_slice().try_into().expect("Hash256 is 32 bytes")
    }

    /// An all-zero header hashes to the published SSZ zero-hash for a depth-3
    /// tree (5 fields → 8 leaves): `zero_hashes[3]`. This is an independent,
    /// published consensus-spec constant — it anchors the Merkleization
    /// structure + sha256 backend and cross-validates `independent_header_root`.
    #[test]
    fn test_beacon_block_header_all_zero_kat() {
        // zero_hashes[3] = sha256(z2 ‖ z2); z2 = sha256(z1 ‖ z1); z1 = sha256(0 ‖ 0).
        const ZERO_HASH_3: [u8; 32] = [
            0xc7, 0x80, 0x09, 0xfd, 0xf0, 0x7f, 0xc5, 0x6a, 0x11, 0xf1, 0x22, 0x37, 0x06, 0x58,
            0xa3, 0x53, 0xaa, 0xa5, 0x42, 0xed, 0x63, 0xe4, 0x4c, 0x4b, 0xc1, 0x5f, 0xf4, 0xcd,
            0x10, 0x5a, 0xb3, 0x3c,
        ];
        let zero = BeaconBlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
        };
        assert_eq!(
            header_root(&zero),
            ZERO_HASH_3,
            "all-zero BeaconBlockHeader must hash to zero_hashes[3]"
        );
        // The independent oracle must reproduce the published constant too.
        assert_eq!(independent_header_root(&zero), ZERO_HASH_3);
    }

    /// KAT: the derived `tree_hash_root` matches an independent raw-sha256
    /// Merkleization (spec field order) for a non-trivial header — the
    /// load-bearing field-order + per-leaf-encoding check.
    #[test]
    fn test_beacon_block_header_tree_hash_matches_independent_oracle() {
        let h = sample_header();
        assert_eq!(
            header_root(&h),
            independent_header_root(&h),
            "derived tree_hash_root must equal the independent sha256 oracle"
        );
    }

    #[test]
    fn test_beacon_block_header_serde_shape_roundtrip() {
        let h = sample_header();
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        // quoted_u64 integers serialize as strings.
        assert_eq!(v["slot"], serde_json::Value::String("3000000".to_string()));
        assert_eq!(v["proposer_index"], serde_json::Value::String("12345".to_string()));
        // 0x + lowercase hex roots.
        assert_eq!(v["parent_root"], serde_json::Value::String(format!("0x{}", "11".repeat(32))));
        // round-trip.
        let back: BeaconBlockHeader = serde_json::from_value(v).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn test_beacon_block_header_ssz_roundtrip_and_len() {
        use ssz::{Decode, Encode};
        let h = sample_header();
        let bytes = h.as_ssz_bytes();
        assert_eq!(bytes.len(), 8 + 8 + 32 + 32 + 32, "fixed SSZ length must be 112 bytes");
        let back = BeaconBlockHeader::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn test_beacon_block_header_root_is_field_sensitive() {
        let base = sample_header();
        let base_root = header_root(&base);

        let mut s = base.clone();
        s.slot += 1;
        let mut p = base.clone();
        p.proposer_index += 1;
        let mut pr = base.clone();
        pr.parent_root[0] ^= 1;
        let mut st = base.clone();
        st.state_root[0] ^= 1;
        let mut bo = base.clone();
        bo.body_root[0] ^= 1;

        for (label, v) in [
            ("slot", s),
            ("proposer_index", p),
            ("parent_root", pr),
            ("state_root", st),
            ("body_root", bo),
        ] {
            assert_ne!(header_root(&v), base_root, "root must change when {label} changes");
        }
    }
}
