//! Pre-Gloas `BlockContents` split and 3-offset framing.
//!
//! Fixtures in `tests/fixtures/` are Deneb, Electra, and Fulu `BlockContents`
//! with two 48-byte proofs and two 64-byte blobs. The blob region is opaque and
//! smaller than a consensus blob; the decoder copies it byte-for-byte.

use beacon::ssz_deser::{
    deserialize_block_contents_ssz, deserialize_gloas_block_contents,
    encode_signed_envelope_contents, serialize_signed_beacon_block_ssz,
    serialize_signed_block_contents_ssz, SszBlockFormat,
};

const DENEB_BLOCK_CONTENTS: &[u8] = include_bytes!("fixtures/deneb_block_contents.ssz");
const ELECTRA_BLOCK_CONTENTS: &[u8] = include_bytes!("fixtures/electra_block_contents.ssz");
const FULU_BLOCK_CONTENTS: &[u8] = include_bytes!("fixtures/fulu_block_contents.ssz");

const DENEB_BODY: &[u8] = &[0xAB; 32];
const ELECTRA_BODY: &[u8] = &[0xEE; 32];
const FULU_BODY: &[u8] = &[0xCC; 32];

fn le_u32(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn beacon_block_ssz(
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&slot.to_le_bytes());
    buf.extend_from_slice(&proposer_index.to_le_bytes());
    buf.extend_from_slice(&parent_root);
    buf.extend_from_slice(&state_root);
    buf.extend_from_slice(&84u32.to_le_bytes());
    buf.extend_from_slice(body);
    buf
}

#[test]
fn block_contents_split_bounds_block_by_the_kzg_offset() {
    for (label, bytes, slot, body) in [
        ("deneb", DENEB_BLOCK_CONTENTS, 7_000_000_u64, DENEB_BODY),
        ("electra", ELECTRA_BLOCK_CONTENTS, 11_649_024, ELECTRA_BODY),
        ("fulu", FULU_BLOCK_CONTENTS, 15_000_000, FULU_BODY),
    ] {
        let block_off = le_u32(bytes, 0);
        let kzg_off = le_u32(bytes, 4);
        let blobs_off = le_u32(bytes, 8);
        let parsed = deserialize_block_contents_ssz(bytes, SszBlockFormat::BlockContents)
            .unwrap_or_else(|err| panic!("{label}: {err}"));

        assert!(!parsed.kzg_proofs.is_empty(), "{label} kzg_proofs empty");
        assert!(!parsed.blobs.is_empty(), "{label} blobs empty");
        // Two 48-byte proofs and two 64-byte blobs, not a parsed length bound.
        assert_eq!(parsed.kzg_proofs.len(), 48 * 2, "{label}");
        assert_eq!(parsed.blobs.len(), 64 * 2, "{label}");
        assert_eq!(parsed.block_ssz.len(), kzg_off - block_off, "{label}");
        assert_eq!(parsed.block_ssz, &bytes[block_off..kzg_off], "{label}");
        assert_eq!(parsed.kzg_proofs, &bytes[kzg_off..blobs_off], "{label}");
        assert_eq!(parsed.blobs, &bytes[blobs_off..], "{label}");
        assert!(
            parsed.kzg_proofs.iter().all(|byte| !parsed.block_ssz.contains(byte)),
            "{label}: proof byte inside block_ssz"
        );
        assert_eq!(parsed.block.slot, slot, "{label}");
        assert_eq!(parsed.block.body, body, "{label}");
    }
}

#[test]
fn serialize_signed_block_contents_round_trips() {
    for bytes in [DENEB_BLOCK_CONTENTS, ELECTRA_BLOCK_CONTENTS, FULU_BLOCK_CONTENTS] {
        let parsed = deserialize_block_contents_ssz(bytes, SszBlockFormat::BlockContents).unwrap();
        let framed =
            serialize_signed_block_contents_ssz(parsed.block_ssz, parsed.kzg_proofs, parsed.blobs);
        assert_eq!(
            framed.len(),
            12 + parsed.block_ssz.len() + parsed.kzg_proofs.len() + parsed.blobs.len()
        );
        assert_eq!(
            framed,
            encode_signed_envelope_contents(parsed.block_ssz, parsed.kzg_proofs, parsed.blobs)
        );
        let again = deserialize_block_contents_ssz(&framed, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(again.block_ssz, parsed.block_ssz);
        assert_eq!(again.kzg_proofs, parsed.kzg_proofs);
        assert_eq!(again.blobs, parsed.blobs);
        assert_eq!(again.block, parsed.block);

        let signed = serialize_signed_beacon_block_ssz(parsed.block_ssz, &[0x07; 96]).unwrap();
        let signed_framed =
            serialize_signed_block_contents_ssz(&signed, parsed.kzg_proofs, parsed.blobs);
        assert_eq!(
            signed_framed.len(),
            12 + signed.len() + parsed.kzg_proofs.len() + parsed.blobs.len()
        );
        let signed_off = le_u32(&signed_framed, 0);
        let proofs_off = le_u32(&signed_framed, 4);
        let blobs_off = le_u32(&signed_framed, 8);
        assert_eq!(&signed_framed[signed_off..proofs_off], signed.as_slice());
        assert_eq!(&signed_framed[proofs_off..blobs_off], parsed.kzg_proofs);
        assert_eq!(&signed_framed[blobs_off..], parsed.blobs);
    }
}

#[test]
fn block_contents_split_rejects_offsets_outside_the_buffer() {
    let mut precedes = vec![0u8; 32];
    precedes[0..4].copy_from_slice(&20u32.to_le_bytes());
    precedes[4..8].copy_from_slice(&16u32.to_le_bytes());
    precedes[8..12].copy_from_slice(&24u32.to_le_bytes());
    let err = deserialize_block_contents_ssz(&precedes, SszBlockFormat::BlockContents).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("kzg_proofs offset 16 precedes block offset 20"), "{msg}");

    let mut exceeds = vec![0u8; 12];
    exceeds[0..4].copy_from_slice(&12u32.to_le_bytes());
    exceeds[4..8].copy_from_slice(&100u32.to_le_bytes());
    exceeds[8..12].copy_from_slice(&100u32.to_le_bytes());
    let err = deserialize_block_contents_ssz(&exceeds, SszBlockFormat::BlockContents).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("kzg_proofs offset 100 exceeds buffer length 12"), "{msg}");

    let mut blobs_past = vec![0u8; 24];
    blobs_past[0..4].copy_from_slice(&12u32.to_le_bytes());
    blobs_past[4..8].copy_from_slice(&20u32.to_le_bytes());
    blobs_past[8..12].copy_from_slice(&1000u32.to_le_bytes());
    let err =
        deserialize_block_contents_ssz(&blobs_past, SszBlockFormat::BlockContents).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not monotonic or out of bounds"), "{msg}");
    assert!(msg.contains("blobs=1000"), "{msg}");

    let err = deserialize_block_contents_ssz(DENEB_BLOCK_CONTENTS, SszBlockFormat::BeaconBlock)
        .unwrap_err();
    assert!(err.to_string().contains("requires BlockContents format"), "{err}");
}

#[test]
fn gloas_path_is_unchanged() {
    let block = beacon_block_ssz(77, 3, [0x11; 32], [0x22; 32], &[0xde, 0xad]);
    let envelope = [0xe0u8, 0xe1, 0xe2];
    let kzg = [0xaau8; 8];
    let blobs = [0xbbu8; 4];
    let block_off = 16u32;
    let envelope_off = block_off + block.len() as u32;
    let kzg_off = envelope_off + envelope.len() as u32;
    let blobs_off = kzg_off + kzg.len() as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&block_off.to_le_bytes());
    bytes.extend_from_slice(&envelope_off.to_le_bytes());
    bytes.extend_from_slice(&kzg_off.to_le_bytes());
    bytes.extend_from_slice(&blobs_off.to_le_bytes());
    bytes.extend_from_slice(&block);
    bytes.extend_from_slice(&envelope);
    bytes.extend_from_slice(&kzg);
    bytes.extend_from_slice(&blobs);

    let parsed = deserialize_gloas_block_contents(&bytes).unwrap();
    assert_eq!(parsed.block_ssz, block);
    assert_eq!(parsed.envelope_ssz, envelope);
    assert_eq!(parsed.kzg_proofs, kzg);
    assert_eq!(parsed.blobs, blobs);
    assert_eq!(parsed.block.slot, 77);
    assert_eq!(parsed.block.proposer_index, 3);
    assert_eq!(parsed.block.parent_root, [0x11; 32]);
    assert_eq!(parsed.block.state_root, [0x22; 32]);
    assert_eq!(parsed.block.body, vec![0xde, 0xad]);
}

/// LH-style monotonicity check for a 3-offset `SignedBlockContents` / `BlockContents`
/// table. Returns `Err` with an `OffsetOutOfBounds`-class message when offsets are
/// not monotonic or exceed the buffer — the blake-manual / RR-P0-3 failure mode.
fn signed_block_contents_offsets_ok(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 12 {
        return Err(format!("OffsetOutOfBounds: buffer {} < 12", bytes.len()));
    }
    let o0 = le_u32(bytes, 0);
    let o1 = le_u32(bytes, 4);
    let o2 = le_u32(bytes, 8);
    if o0 < 12 {
        return Err(format!("OffsetOutOfBounds: signed_block offset {o0} < 12"));
    }
    if o1 < o0 || o1 > bytes.len() {
        return Err(format!(
            "OffsetOutOfBounds: kzg_proofs offset {o1} (signed_block={o0}, len={})",
            bytes.len()
        ));
    }
    if o2 < o1 || o2 > bytes.len() {
        return Err(format!(
            "OffsetOutOfBounds: blobs offset {o2} (kzg={o1}, len={})",
            bytes.len()
        ));
    }
    Ok(())
}

/// Pre-RR-1.2 Electra publish bug: frame a bare `SignedBeaconBlock` over the
/// unbounded `BlockContents` tail (`ssz_bytes[block_offset..]`), then hand that
/// buffer to a BN that expects `SignedBlockContents`. The first u32 is the
/// message offset `100`, so the second/third "offsets" are signature bytes and
/// fail the 3-offset table check (`OffsetOutOfBounds` / RR-P0-3).
#[test]
fn electra_legacy_unbounded_signed_framing_is_offset_out_of_bounds() {
    let parsed =
        deserialize_block_contents_ssz(ELECTRA_BLOCK_CONTENTS, SszBlockFormat::BlockContents)
            .expect("electra fixture");
    assert!(!parsed.kzg_proofs.is_empty());
    assert!(!parsed.blobs.is_empty());

    // Legacy: unbounded tail from the produce-block BlockContents offset.
    let block_off = le_u32(ELECTRA_BLOCK_CONTENTS, 0);
    let unbounded_tail = &ELECTRA_BLOCK_CONTENTS[block_off..];
    let legacy = serialize_signed_beacon_block_ssz(unbounded_tail, &[0x07; 96]).unwrap();
    let err = signed_block_contents_offsets_ok(&legacy).expect_err("legacy framing");
    assert!(
        err.contains("OffsetOutOfBounds"),
        "legacy Electra publish must be OffsetOutOfBounds-class: {err}"
    );

    // ADR-R01 / RR-1.1+1.2: bounded block + sidecars as SignedBlockContents.
    let signed_block = serialize_signed_beacon_block_ssz(parsed.block_ssz, &[0x07; 96]).unwrap();
    let framed =
        serialize_signed_block_contents_ssz(&signed_block, parsed.kzg_proofs, parsed.blobs);
    signed_block_contents_offsets_ok(&framed).expect("ADR-R01 framing");
    let signed_off = le_u32(&framed, 0);
    let proofs_off = le_u32(&framed, 4);
    let blobs_off = le_u32(&framed, 8);
    assert_eq!(&framed[signed_off..proofs_off], signed_block.as_slice());
    assert_eq!(&framed[proofs_off..blobs_off], parsed.kzg_proofs);
    assert_eq!(&framed[blobs_off..], parsed.blobs);
    assert_eq!(&framed[signed_off + 100..proofs_off], parsed.block_ssz);
}
