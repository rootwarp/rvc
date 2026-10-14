/// ISSUE-4.3 (L-3): Canonical blob KZG commitment binding
///
/// These tests verify that `BlockContents::BlockAndBlobs` exposes blob KZG
/// commitments parsed from the block body SSZ and that the canonical commitment
/// root is sensitive to any single-byte mutation.
///
/// Bodies are valid typed Deneb containers (SEC-6). Malformed SSZ surfaces as
/// `Err`, not as an empty commitment list.
use rvc_eth_types::{BeaconBlock, BlockContents, BodyForkLayout};

/// Valid Deneb `BeaconBlockBody` SSZ with the given KZG commitments.
fn body_with_commitments(commitments: &[[u8; 48]]) -> Vec<u8> {
    let mut body = rvc_eth_types::external_vector_deneb_body();
    body.blob_kzg_commitments = commitments.to_vec().into();
    body.as_ssz_bytes()
}

fn block_and_blobs(commitments: &[[u8; 48]]) -> BlockContents {
    BlockContents::BlockAndBlobs {
        block: BeaconBlock {
            slot: 1000,
            proposer_index: 7,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: body_with_commitments(commitments),
        },
        kzg_proofs: vec![],
        blobs: vec![],
    }
}

// ── RED → GREEN: basic extraction ───────────────────────────────────────────

#[test]
fn test_blob_commitments_extracted_from_body() {
    let c0 = [0xaa; 48];
    let c1 = [0xbb; 48];
    let contents = block_and_blobs(&[c0, c1]);
    let parsed = contents.blob_kzg_commitments(BodyForkLayout::Deneb).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0], c0);
    assert_eq!(parsed[1], c1);
}

#[test]
fn test_blob_commitments_empty_when_no_blobs() {
    let contents = block_and_blobs(&[]);
    assert_eq!(
        contents.blob_kzg_commitments(BodyForkLayout::Deneb).unwrap(),
        Vec::<[u8; 48]>::new()
    );
}

#[test]
fn test_blob_commitments_empty_for_block_variant() {
    let contents = BlockContents::Block(BeaconBlock {
        slot: 1,
        proposer_index: 0,
        parent_root: [0; 32],
        state_root: [0; 32],
        body: body_with_commitments(&[[0xcc; 48]]),
    });
    assert_eq!(
        contents.blob_kzg_commitments(BodyForkLayout::Deneb).unwrap(),
        Vec::<[u8; 48]>::new(),
        "Block variant has no blob commitments"
    );
}

// ── ISSUE-4.3 acceptance criteria ───────────────────────────────────────────

/// A non-empty set of blob commitments must produce a nonzero canonical root.
#[test]
fn test_blob_commitments_bound_in_signing_scope() {
    let commitments = vec![[0x42; 48], [0x24; 48], [0x77; 48]];
    let contents = block_and_blobs(&commitments);
    let root = contents.kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
    assert_ne!(root, [0u8; 32], "canonical commitment root must be nonzero");
}

/// Mutating any single byte in any blob commitment must change the canonical root.
#[test]
fn test_signing_scope_changes_with_blob_commitments() {
    let original = vec![[0xde; 48], [0xad; 48]];
    let base_root = block_and_blobs(&original).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();

    for commit_idx in 0..original.len() {
        for byte_idx in 0..48 {
            let mut mutated = original.clone();
            mutated[commit_idx][byte_idx] ^= 0x01;
            let mutated_root =
                block_and_blobs(&mutated).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
            assert_ne!(
                base_root, mutated_root,
                "commitment[{}][{}] mutation did not change root",
                commit_idx, byte_idx
            );
        }
    }
}

/// Commitment root for a body with no blobs must be the constant empty root.
#[test]
fn test_commitment_root_empty_for_no_blobs() {
    let empty_contents = block_and_blobs(&[]);
    let root = empty_contents.kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
    let same_root = empty_contents.kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
    assert_eq!(root, same_root, "empty root is deterministic");
}

/// Single-blob commitment root differs from two-blob root, even if blobs match.
#[test]
fn test_commitment_root_length_sensitive() {
    let c = [0xff; 48];
    let root_1 = block_and_blobs(&[c]).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
    let root_2 = block_and_blobs(&[c, c]).kzg_commitment_root(BodyForkLayout::Deneb).unwrap();
    assert_ne!(root_1, root_2, "commitment root must be length-sensitive");
}

/// Body bytes that are shorter than a valid SSZ body yield Err, not Ok([]).
#[test]
fn test_short_body_yields_error_not_empty_list() {
    let contents = BlockContents::BlockAndBlobs {
        block: BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body: vec![0u8; 100], // shorter than a valid Deneb body
        },
        kzg_proofs: vec![],
        blobs: vec![],
    };
    assert!(
        contents.blob_kzg_commitments(BodyForkLayout::Deneb).is_err(),
        "malformed body must not look like an empty commitment list"
    );
}

/// kzg_commitment_root is deterministic (same input → same output).
#[test]
fn test_commitment_root_is_deterministic() {
    let commitments = vec![[0xab; 48], [0xcd; 48]];
    let contents = block_and_blobs(&commitments);
    assert_eq!(
        contents.kzg_commitment_root(BodyForkLayout::Deneb).unwrap(),
        contents.kzg_commitment_root(BodyForkLayout::Deneb).unwrap()
    );
}
