use eth_types::{BeaconBlock, BlindedBeaconBlock};

use crate::BeaconError;

/// Minimal block header extracted from raw SSZ-encoded `BeaconBlock` bytes.
///
/// The SSZ layout of `BeaconBlock` always starts with `slot` (8 bytes LE)
/// followed by `proposer_index` (8 bytes LE) at a fixed offset, across all
/// fork variants (Phase0 through Electra).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SszBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
}

/// SSZ wire format returned by the `/eth/v3/validator/blocks/{slot}` endpoint.
///
/// The SSZ layout differs between forks and block types:
/// - **`BeaconBlock`**: Pre-Deneb unblinded, Gloas unblinded (bare
///   `SignedBeaconBlock`), and all blinded blocks. `slot` is at byte offset 0.
/// - **`BlockContents`**: Deneb/Electra/Fulu unblinded blocks. The first 12
///   bytes are three 4-byte LE offsets (block, kzg_proofs, blobs). The
///   `BeaconBlock` data (and thus `slot`) lives at the offset given by the
///   first 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SszBlockFormat {
    /// Raw `BeaconBlock` — slot at byte 0 (pre-Deneb / Gloas unblinded, all blinded).
    BeaconBlock,
    /// `BlockContents` wrapper — first 4 bytes = LE offset to inner `BeaconBlock`.
    BlockContents,
}

/// Minimum number of bytes required to extract the block header from a `BeaconBlock`.
const MIN_BEACON_BLOCK_HEADER_LEN: usize = 16;

/// Minimum size of the `BlockContents` fixed portion (3 × 4-byte offsets).
const BLOCK_CONTENTS_FIXED_LEN: usize = 12;

/// Gloas `BlockContents` fixed portion (4 × 4-byte offsets).
const GLOAS_BLOCK_CONTENTS_FIXED_LEN: usize = 16;

/// SSZ `SignedBeaconBlock` / `SignedBlindedBeaconBlock` message offset (4 + 96).
pub const SIGNED_BEACON_BLOCK_MESSAGE_OFFSET: u32 = 100;

/// BLS signature size on the SSZ wire.
const SSZ_SIGNATURE_LEN: usize = 96;

/// Fixed portion of the SSZ `BeaconBlock` layout:
/// slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_offset(4) = 84.
const BEACON_BLOCK_FIXED_LEN: usize = 84;

/// Resolves the byte offset where the `BeaconBlock` data starts within `bytes`.
fn resolve_block_offset(bytes: &[u8], format: SszBlockFormat) -> Result<usize, BeaconError> {
    match format {
        SszBlockFormat::BeaconBlock => Ok(0),
        SszBlockFormat::BlockContents => {
            if bytes.len() < BLOCK_CONTENTS_FIXED_LEN {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents too short: {} bytes, need at least {}",
                    bytes.len(),
                    BLOCK_CONTENTS_FIXED_LEN,
                )));
            }
            let offset =
                u32::from_le_bytes(bytes[0..4].try_into().expect("slice length verified above"))
                    as usize;
            if offset < BLOCK_CONTENTS_FIXED_LEN {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents block offset {} is inside the fixed portion (< {})",
                    offset, BLOCK_CONTENTS_FIXED_LEN,
                )));
            }
            Ok(offset)
        }
    }
}

/// Resolves where the `BeaconBlock` region ends within `bytes`.
///
/// For `BeaconBlock` format the block fills the entire payload. For
/// `BlockContents` (Deneb+ unblinded path) the outer SSZ container holds three
/// variable-length fields — `(BeaconBlock, kzg_proofs, blobs)` — and the second
/// 4-byte offset (`bytes[4..8]`) marks the start of the `kzg_proofs` region,
/// which is the upper bound of the BeaconBlock body. Reading past that bound
/// pulls KZG-proof bytes into `body` and corrupts the recomputed root.
fn resolve_block_region_end(
    bytes: &[u8],
    format: SszBlockFormat,
    block_offset: usize,
) -> Result<usize, BeaconError> {
    match format {
        SszBlockFormat::BeaconBlock => Ok(bytes.len()),
        SszBlockFormat::BlockContents => {
            // BLOCK_CONTENTS_FIXED_LEN bytes already verified by resolve_block_offset.
            let kzg_offset =
                u32::from_le_bytes(bytes[4..8].try_into().expect("slice length verified above"))
                    as usize;
            if kzg_offset < block_offset {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents kzg_proofs offset {} precedes block offset {}",
                    kzg_offset, block_offset,
                )));
            }
            if kzg_offset > bytes.len() {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents kzg_proofs offset {} exceeds buffer length {}",
                    kzg_offset,
                    bytes.len(),
                )));
            }
            Ok(kzg_offset)
        }
    }
}

/// Extracts slot and proposer_index from raw SSZ bytes.
///
/// The `format` parameter determines how to locate the `BeaconBlock` within
/// the SSZ payload. See [`SszBlockFormat`] for details.
///
/// # Errors
///
/// Returns `BeaconError::ParseError` if the input is too short or the
/// offset within a `BlockContents` payload points outside the buffer.
pub fn extract_block_header_from_ssz(
    bytes: &[u8],
    format: SszBlockFormat,
) -> Result<SszBlockHeader, BeaconError> {
    let block_offset = resolve_block_offset(bytes, format)?;

    let end = block_offset
        .checked_add(MIN_BEACON_BLOCK_HEADER_LEN)
        .ok_or_else(|| BeaconError::ParseError("SSZ offset overflow".to_string()))?;

    if bytes.len() < end {
        return Err(BeaconError::ParseError(format!(
            "SSZ block too short: {} bytes, need at least {} (offset {} + header {})",
            bytes.len(),
            end,
            block_offset,
            MIN_BEACON_BLOCK_HEADER_LEN,
        )));
    }

    let slot = u64::from_le_bytes(
        bytes[block_offset..block_offset + 8].try_into().expect("slice length verified above"),
    );
    let proposer_index = u64::from_le_bytes(
        bytes[block_offset + 8..block_offset + 16].try_into().expect("slice length verified above"),
    );

    Ok(SszBlockHeader { slot, proposer_index })
}

/// Deserializes raw SSZ bytes into a `BeaconBlock`.
///
/// Returns the deserialized block and the byte offset within `bytes` where the
/// `BeaconBlock` data starts. The offset is needed by callers constructing
/// `SignedBeaconBlock` SSZ payloads.
///
/// # Errors
///
/// Returns `BeaconError::ParseError` if the input is too short, the body offset
/// is invalid, or the `BlockContents` wrapper offset is out of bounds.
pub fn deserialize_beacon_block_from_ssz(
    bytes: &[u8],
    format: SszBlockFormat,
) -> Result<(BeaconBlock, usize), BeaconError> {
    let block_offset = resolve_block_offset(bytes, format)?;
    let block_region_end = resolve_block_region_end(bytes, format, block_offset)?;
    let block = deserialize_block_fields(bytes, block_offset, block_region_end)?;
    Ok((block, block_offset))
}

/// Deserializes raw SSZ bytes into a `BlindedBeaconBlock`.
///
/// Identical SSZ layout to `BeaconBlock` (slot, proposer_index, parent_root,
/// state_root, body).
///
/// # Errors
///
/// Returns `BeaconError::ParseError` if the input is too short or malformed.
pub fn deserialize_blinded_beacon_block_from_ssz(
    bytes: &[u8],
    format: SszBlockFormat,
) -> Result<(BlindedBeaconBlock, usize), BeaconError> {
    let block_offset = resolve_block_offset(bytes, format)?;
    let block_region_end = resolve_block_region_end(bytes, format, block_offset)?;
    let block = deserialize_block_fields(bytes, block_offset, block_region_end)?;
    let blinded = BlindedBeaconBlock {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body: block.body,
    };
    Ok((blinded, block_offset))
}

/// Parses the fixed fields and body of a `BeaconBlock` starting at `block_offset`.
///
/// `block_region_end` is the upper bound of the block region within `bytes`
/// (computed by `resolve_block_region_end`); for `BlockContents` payloads it is
/// the kzg_proofs offset, for raw `BeaconBlock` it is `bytes.len()`. Reading
/// past this bound corrupts the body with kzg/blob bytes — see C-1 / ISSUE-1.1.
fn deserialize_block_fields(
    bytes: &[u8],
    block_offset: usize,
    block_region_end: usize,
) -> Result<BeaconBlock, BeaconError> {
    let fixed_end = block_offset
        .checked_add(BEACON_BLOCK_FIXED_LEN)
        .ok_or_else(|| BeaconError::ParseError("SSZ offset overflow".to_string()))?;

    if block_region_end < fixed_end {
        return Err(BeaconError::ParseError(format!(
            "SSZ BeaconBlock too short: region ends at {}, need at least {} (offset {} + fixed {})",
            block_region_end, fixed_end, block_offset, BEACON_BLOCK_FIXED_LEN,
        )));
    }

    let b = &bytes[block_offset..];

    let slot = u64::from_le_bytes(b[0..8].try_into().expect("length verified"));
    let proposer_index = u64::from_le_bytes(b[8..16].try_into().expect("length verified"));

    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(&b[16..48]);

    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&b[48..80]);

    let body_offset_rel =
        u32::from_le_bytes(b[80..84].try_into().expect("length verified")) as usize;

    if body_offset_rel < BEACON_BLOCK_FIXED_LEN {
        return Err(BeaconError::ParseError(format!(
            "SSZ BeaconBlock body offset {} is inside the fixed portion (< {})",
            body_offset_rel, BEACON_BLOCK_FIXED_LEN,
        )));
    }

    let body_start = block_offset + body_offset_rel;
    if body_start > block_region_end {
        return Err(BeaconError::ParseError(format!(
            "SSZ BeaconBlock body offset {} points past end of block region ({})",
            body_start, block_region_end,
        )));
    }

    let body = bytes[body_start..block_region_end].to_vec();

    Ok(BeaconBlock { slot, proposer_index, parent_root, state_root, body })
}

/// Parsed Gloas V4 `BlockContents` SSZ: bounded block plus opaque envelope/blob slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GloasBlockContentsSsz {
    pub block: BeaconBlock,
    /// Inner `BeaconBlock` SSZ (no envelope / proofs / blobs).
    pub block_ssz: Vec<u8>,
    pub envelope_ssz: Vec<u8>,
    pub kzg_proofs: Vec<u8>,
    pub blobs: Vec<u8>,
}

fn read_u32_le(bytes: &[u8], at: usize) -> Result<usize, BeaconError> {
    let slice = bytes.get(at..at + 4).ok_or_else(|| {
        BeaconError::ParseError("SSZ Gloas BlockContents too short for offset table".to_string())
    })?;
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| BeaconError::ParseError("SSZ offset slice must be 4 bytes".to_string()))?;
    Ok(u32::from_le_bytes(arr) as usize)
}

/// True when `bytes` is a 4-offset Gloas `BlockContents` container.
pub fn looks_like_gloas_block_contents(bytes: &[u8]) -> bool {
    if bytes.len() < GLOAS_BLOCK_CONTENTS_FIXED_LEN {
        return false;
    }
    let Ok(block_off) = read_u32_le(bytes, 0) else {
        return false;
    };
    let Ok(envelope_off) = read_u32_le(bytes, 4) else {
        return false;
    };
    let Ok(kzg_off) = read_u32_le(bytes, 8) else {
        return false;
    };
    let Ok(blobs_off) = read_u32_le(bytes, 12) else {
        return false;
    };
    block_off == GLOAS_BLOCK_CONTENTS_FIXED_LEN
        && block_off <= envelope_off
        && envelope_off <= kzg_off
        && kzg_off <= blobs_off
        && blobs_off <= bytes.len()
}

/// Deserialize Gloas `BlockContents` `{block, envelope, kzg_proofs, blobs}`.
pub fn deserialize_gloas_block_contents(
    bytes: &[u8],
) -> Result<GloasBlockContentsSsz, BeaconError> {
    if bytes.len() < GLOAS_BLOCK_CONTENTS_FIXED_LEN {
        return Err(BeaconError::ParseError(format!(
            "SSZ Gloas BlockContents too short: {} bytes, need at least {}",
            bytes.len(),
            GLOAS_BLOCK_CONTENTS_FIXED_LEN,
        )));
    }
    let block_off = read_u32_le(bytes, 0)?;
    let envelope_off = read_u32_le(bytes, 4)?;
    let kzg_off = read_u32_le(bytes, 8)?;
    let blobs_off = read_u32_le(bytes, 12)?;
    if block_off < GLOAS_BLOCK_CONTENTS_FIXED_LEN {
        return Err(BeaconError::ParseError(format!(
            "SSZ Gloas BlockContents block offset {block_off} is inside the fixed portion (< {GLOAS_BLOCK_CONTENTS_FIXED_LEN})"
        )));
    }
    if !(block_off <= envelope_off
        && envelope_off <= kzg_off
        && kzg_off <= blobs_off
        && blobs_off <= bytes.len())
    {
        return Err(BeaconError::ParseError(format!(
            "SSZ Gloas BlockContents offsets not monotonic or out of bounds: block={block_off} envelope={envelope_off} kzg={kzg_off} blobs={blobs_off} len={}",
            bytes.len()
        )));
    }
    let block = deserialize_block_fields(bytes, block_off, envelope_off)?;
    Ok(GloasBlockContentsSsz {
        block,
        block_ssz: bytes[block_off..envelope_off].to_vec(),
        envelope_ssz: bytes[envelope_off..kzg_off].to_vec(),
        kzg_proofs: bytes[kzg_off..blobs_off].to_vec(),
        blobs: bytes[blobs_off..].to_vec(),
    })
}

/// Frame a signed beacon block as `[offset=100][96-byte sig][block_ssz]`.
pub fn serialize_signed_beacon_block_ssz(
    block_ssz: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, BeaconError> {
    if signature.len() != SSZ_SIGNATURE_LEN {
        return Err(BeaconError::ParseError(format!(
            "signature must be {SSZ_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )));
    }
    let mut out = Vec::with_capacity(100 + block_ssz.len());
    out.extend_from_slice(&SIGNED_BEACON_BLOCK_MESSAGE_OFFSET.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(block_ssz);
    Ok(out)
}

/// SSZ `SignedExecutionPayloadEnvelopeContents`: three variable-length fields.
pub fn encode_signed_envelope_contents(
    signed_envelope: &[u8],
    kzg_proofs: &[u8],
    blobs: &[u8],
) -> Vec<u8> {
    const FIXED: u32 = 12;
    let signed_len = signed_envelope.len() as u32;
    let kzg_len = kzg_proofs.len() as u32;
    let o0 = FIXED;
    let o1 = FIXED + signed_len;
    let o2 = o1 + kzg_len;
    let mut out = Vec::with_capacity(12 + signed_envelope.len() + kzg_proofs.len() + blobs.len());
    out.extend_from_slice(&o0.to_le_bytes());
    out.extend_from_slice(&o1.to_le_bytes());
    out.extend_from_slice(&o2.to_le_bytes());
    out.extend_from_slice(signed_envelope);
    out.extend_from_slice(kzg_proofs);
    out.extend_from_slice(blobs);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BeaconBlock format tests ---

    #[test]
    fn test_beacon_block_empty_input_returns_error() {
        let result = extract_block_header_from_ssz(&[], SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_short_input_8_bytes_returns_error() {
        let bytes = vec![0u8; 8];
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_short_input_15_bytes_returns_error() {
        let bytes = vec![0u8; 15];
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_exactly_16_bytes_succeeds() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
        assert_eq!(bytes.len(), 16);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 100);
        assert_eq!(header.proposer_index, 42);
    }

    #[test]
    fn test_beacon_block_zero_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 0);
        assert_eq!(header.proposer_index, 0);
    }

    #[test]
    fn test_beacon_block_max_u64_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, u64::MAX);
        assert_eq!(header.proposer_index, u64::MAX);
    }

    #[test]
    fn test_beacon_block_typical_mainnet_values() {
        let slot: u64 = 9_000_000;
        let proposer_index: u64 = 500_000;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        bytes.extend_from_slice(&[0xab; 128]);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, slot);
        assert_eq!(header.proposer_index, proposer_index);
    }

    #[test]
    fn test_beacon_block_ignores_trailing_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&99u64.to_le_bytes());
        bytes.extend_from_slice(&[0xff; 1024]);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer_index, 99);
    }

    // --- BlockContents format tests ---

    /// Build a minimal BlockContents SSZ payload:
    /// [block_offset(4) | kzg_offset(4) | blobs_offset(4) | ... | BeaconBlock at block_offset]
    fn build_block_contents_ssz(slot: u64, proposer_index: u64) -> Vec<u8> {
        // 3 offsets × 4 bytes = 12 bytes fixed portion
        // BeaconBlock data starts immediately after at offset 12
        let block_offset: u32 = 12;
        let kzg_offset: u32 = 12 + 16 + 64; // block data + padding
        let blobs_offset: u32 = kzg_offset + 48; // kzg proof placeholder

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block_offset.to_le_bytes());
        bytes.extend_from_slice(&kzg_offset.to_le_bytes());
        bytes.extend_from_slice(&blobs_offset.to_le_bytes());

        // BeaconBlock data at offset 12
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        // Simulated remaining block fields (parent_root, state_root, body offset, body...)
        bytes.extend_from_slice(&[0xcc; 128]);

        bytes
    }

    #[test]
    fn test_block_contents_extracts_slot_and_proposer() {
        let bytes = build_block_contents_ssz(9_000_000, 500_000);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 9_000_000);
        assert_eq!(header.proposer_index, 500_000);
    }

    #[test]
    fn test_block_contents_zero_values() {
        let bytes = build_block_contents_ssz(0, 0);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 0);
        assert_eq!(header.proposer_index, 0);
    }

    #[test]
    fn test_block_contents_max_u64_values() {
        let bytes = build_block_contents_ssz(u64::MAX, u64::MAX);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, u64::MAX);
        assert_eq!(header.proposer_index, u64::MAX);
    }

    #[test]
    fn test_block_contents_empty_input_returns_error() {
        let result = extract_block_header_from_ssz(&[], SszBlockFormat::BlockContents);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BlockContents"), "error should mention BlockContents: {err}");
    }

    #[test]
    fn test_block_contents_short_input_returns_error() {
        let bytes = vec![0u8; 8]; // less than 12 bytes needed for offsets
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_offset_beyond_buffer_returns_error() {
        // Valid 12-byte fixed portion, but offset points past end of buffer
        let mut bytes = Vec::new();
        let huge_offset: u32 = 10_000;
        bytes.extend_from_slice(&huge_offset.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // Only 12 bytes total — block_offset 10000 is way out of bounds

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_offset_inside_fixed_portion_returns_error() {
        // Offset = 4, which points inside the fixed portion (< 12)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes()); // offset inside fixed portion
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]); // padding

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("fixed portion"), "error should mention fixed portion: {err}");
    }

    #[test]
    fn test_block_contents_buffer_too_short_for_header_at_offset() {
        // Offset = 12 but buffer only has 20 bytes total (need 12 + 16 = 28)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]); // only 8 bytes after offset, need 16

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_minimum_valid_payload() {
        // Exactly 12 (offsets) + 16 (slot + proposer_index) = 28 bytes
        let slot: u64 = 42;
        let proposer_index: u64 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u32.to_le_bytes()); // block at offset 12
        bytes.extend_from_slice(&28u32.to_le_bytes()); // kzg_proofs (end of block)
        bytes.extend_from_slice(&28u32.to_le_bytes()); // blobs (same, empty)
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        assert_eq!(bytes.len(), 28);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer_index, 99);
    }

    // --- deserialize_beacon_block_from_ssz tests ---

    /// Build a valid SSZ-encoded `BeaconBlock` from components.
    /// Layout: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_offset(4) + body
    fn build_beacon_block_ssz(
        slot: u64,
        proposer_index: u64,
        parent_root: [u8; 32],
        state_root: [u8; 32],
        body: &[u8],
    ) -> Vec<u8> {
        let body_offset: u32 = 84; // fixed portion size
        let mut buf = Vec::new();
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&proposer_index.to_le_bytes());
        buf.extend_from_slice(&parent_root);
        buf.extend_from_slice(&state_root);
        buf.extend_from_slice(&body_offset.to_le_bytes());
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn test_deserialize_beacon_block_from_ssz_roundtrip() {
        let parent_root = [1u8; 32];
        let state_root = [2u8; 32];
        let body = vec![0xde, 0xad, 0xbe, 0xef];

        let ssz = build_beacon_block_ssz(100, 42, parent_root, state_root, &body);
        let (block, offset) =
            deserialize_beacon_block_from_ssz(&ssz, SszBlockFormat::BeaconBlock).unwrap();

        assert_eq!(offset, 0);
        assert_eq!(block.slot, 100);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.parent_root, parent_root);
        assert_eq!(block.state_root, state_root);
        assert_eq!(block.body, body);
    }

    #[test]
    fn test_deserialize_beacon_block_from_block_contents_ssz() {
        let parent_root = [3u8; 32];
        let state_root = [4u8; 32];
        let body = vec![0xca, 0xfe];

        let block_ssz = build_beacon_block_ssz(200, 55, parent_root, state_root, &body);
        let block_len = block_ssz.len();

        // BlockContents: [block_offset(4) | kzg_offset(4) | blobs_offset(4) | BeaconBlock | kzg | blobs]
        let block_offset: u32 = 12;
        let kzg_offset: u32 = block_offset + block_len as u32;
        let blobs_offset: u32 = kzg_offset;

        let mut buf = Vec::new();
        buf.extend_from_slice(&block_offset.to_le_bytes());
        buf.extend_from_slice(&kzg_offset.to_le_bytes());
        buf.extend_from_slice(&blobs_offset.to_le_bytes());
        buf.extend_from_slice(&block_ssz);

        let (block, offset) =
            deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BlockContents).unwrap();

        assert_eq!(offset, 12);
        assert_eq!(block.slot, 200);
        assert_eq!(block.proposer_index, 55);
        assert_eq!(block.parent_root, parent_root);
        assert_eq!(block.state_root, state_root);
        // Body is bounded by kzg_offset (no kzg/blobs trailing data here).
        assert_eq!(block.body, body);
    }

    /// Regression for C-1 / ISSUE-1.1: when parsing a `BlockContents` payload that
    /// contains real kzg_proofs and blobs trailing data, the body region MUST be
    /// bounded by the kzg_proofs offset from the outer SSZ container — not the
    /// end of the buffer. Otherwise the recomputed `tree_hash_root` drifts from
    /// the BN-reported root because the body absorbs kzg/blob bytes.
    #[test]
    fn test_block_contents_kzg_offset_bounds_body_with_trailing_data() {
        use tree_hash::TreeHash;

        let parent_root = [0xa1; 32];
        let state_root = [0xa2; 32];
        // Valid Electra body so tree_hash_root (typed body leaf, SEC-6c) succeeds.
        let body = eth_types::external_vector_electra_body().as_ssz_bytes();

        let block_ssz = build_beacon_block_ssz(1234, 567, parent_root, state_root, &body);
        let block_len = block_ssz.len() as u32;

        // Two kzg "proofs" of 48 bytes each + one 131072-byte blob region marker.
        let kzg_data = vec![0xee; 48 * 2];
        let blobs_data = vec![0xdd; 256];

        let block_offset: u32 = 12;
        let kzg_offset: u32 = block_offset + block_len;
        let blobs_offset: u32 = kzg_offset + kzg_data.len() as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&block_offset.to_le_bytes());
        buf.extend_from_slice(&kzg_offset.to_le_bytes());
        buf.extend_from_slice(&blobs_offset.to_le_bytes());
        buf.extend_from_slice(&block_ssz);
        buf.extend_from_slice(&kzg_data);
        buf.extend_from_slice(&blobs_data);

        let (parsed, offset) =
            deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BlockContents).unwrap();

        assert_eq!(offset, 12);
        assert_eq!(parsed.slot, 1234);
        assert_eq!(parsed.proposer_index, 567);

        // Body must equal exactly the inner block body — no kzg/blob bleed-through.
        assert_eq!(parsed.body, body);
        assert!(!parsed.body.contains(&0xee), "body must not include kzg_proofs bytes");
        assert!(!parsed.body.contains(&0xdd), "body must not include blobs bytes");

        // Recomputed root matches the canonical root of the inner BeaconBlock.
        let canonical = BeaconBlock {
            slot: 1234,
            proposer_index: 567,
            parent_root,
            state_root,
            body: body.clone(),
        };
        assert_eq!(parsed.tree_hash_root(), canonical.tree_hash_root());
    }

    #[test]
    fn test_block_contents_kzg_offset_used_as_block_end_deneb() {
        // Deneb: 2 kzg proofs (96 bytes) + 1 blob (representative).
        // Verifies the offset-table parse picks kzg_offset (not bytes.len()).
        let block_ssz =
            build_beacon_block_ssz(7_000_000, 1234, [0x10; 32], [0x20; 32], &[0xab; 96]);
        let block_offset: u32 = 12;
        let kzg_offset: u32 = block_offset + block_ssz.len() as u32;
        let kzg = vec![0x77; 96];
        let blobs_offset: u32 = kzg_offset + kzg.len() as u32;
        let blobs = vec![0x88; 131072];

        let mut buf = Vec::new();
        buf.extend_from_slice(&block_offset.to_le_bytes());
        buf.extend_from_slice(&kzg_offset.to_le_bytes());
        buf.extend_from_slice(&blobs_offset.to_le_bytes());
        buf.extend_from_slice(&block_ssz);
        buf.extend_from_slice(&kzg);
        buf.extend_from_slice(&blobs);

        let (block, _) =
            deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(block.slot, 7_000_000);
        assert_eq!(block.body.len(), 96);
        assert!(block.body.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn test_block_contents_kzg_offset_used_as_block_end_electra() {
        // Electra slot range — same offset semantics, just a different fork epoch.
        let block_ssz = build_beacon_block_ssz(11_649_024, 99, [0xee; 32], [0xff; 32], &[0xbb; 64]);
        let block_offset: u32 = 12;
        let kzg_offset: u32 = block_offset + block_ssz.len() as u32;
        let blobs_offset: u32 = kzg_offset;

        let mut buf = Vec::new();
        buf.extend_from_slice(&block_offset.to_le_bytes());
        buf.extend_from_slice(&kzg_offset.to_le_bytes());
        buf.extend_from_slice(&blobs_offset.to_le_bytes());
        buf.extend_from_slice(&block_ssz);
        buf.extend_from_slice(&[0x99; 64]); // trailing data past kzg_offset

        let (block, _) =
            deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(block.slot, 11_649_024);
        assert_eq!(block.body, vec![0xbb; 64]);
    }

    #[test]
    fn test_block_contents_kzg_offset_used_as_block_end_fulu() {
        // Fulu slot range — same offset semantics.
        let block_ssz =
            build_beacon_block_ssz(15_000_000, 200, [0x55; 32], [0x66; 32], &[0xcc; 32]);
        let block_offset: u32 = 12;
        let kzg_offset: u32 = block_offset + block_ssz.len() as u32;
        let blobs_offset: u32 = kzg_offset;

        let mut buf = Vec::new();
        buf.extend_from_slice(&block_offset.to_le_bytes());
        buf.extend_from_slice(&kzg_offset.to_le_bytes());
        buf.extend_from_slice(&blobs_offset.to_le_bytes());
        buf.extend_from_slice(&block_ssz);
        buf.extend_from_slice(&[0x44; 128]); // trailing data past kzg_offset

        let (block, _) =
            deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(block.slot, 15_000_000);
        assert_eq!(block.body, vec![0xcc; 32]);
    }

    #[test]
    fn test_deserialize_beacon_block_ssz_too_short() {
        // Empty
        let result = deserialize_beacon_block_from_ssz(&[], SszBlockFormat::BeaconBlock);
        assert!(result.is_err());

        // 83 bytes — one short of fixed portion
        let bytes = vec![0u8; 83];
        let result = deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "error should mention too short: {err}");
    }

    #[test]
    fn test_deserialize_beacon_block_tree_hash_matches() {
        use tree_hash::TreeHash;

        let parent_root = [0xaa; 32];
        let state_root = [0xbb; 32];
        let body = eth_types::external_vector_electra_body().as_ssz_bytes();

        let expected = BeaconBlock {
            slot: 999,
            proposer_index: 77,
            parent_root,
            state_root,
            body: body.clone(),
        };
        let expected_root = expected.tree_hash_root();

        let ssz = build_beacon_block_ssz(999, 77, parent_root, state_root, &body);
        let (block, _) =
            deserialize_beacon_block_from_ssz(&ssz, SszBlockFormat::BeaconBlock).unwrap();

        assert_eq!(block.tree_hash_root(), expected_root);
    }

    #[test]
    fn test_deserialize_beacon_block_body_offset_too_small() {
        // Construct SSZ with body_offset < 84 (inside fixed portion)
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u64.to_le_bytes()); // slot
        buf.extend_from_slice(&42u64.to_le_bytes()); // proposer_index
        buf.extend_from_slice(&[0u8; 32]); // parent_root
        buf.extend_from_slice(&[0u8; 32]); // state_root
        buf.extend_from_slice(&10u32.to_le_bytes()); // body_offset = 10 (invalid)

        let result = deserialize_beacon_block_from_ssz(&buf, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("fixed portion"), "error: {err}");
    }

    #[test]
    fn test_deserialize_blinded_beacon_block_from_ssz_roundtrip() {
        let parent_root = [5u8; 32];
        let state_root = [6u8; 32];
        let body = vec![0xfe, 0xed];

        let ssz = build_beacon_block_ssz(300, 88, parent_root, state_root, &body);
        let (block, offset) =
            deserialize_blinded_beacon_block_from_ssz(&ssz, SszBlockFormat::BeaconBlock).unwrap();

        assert_eq!(offset, 0);
        assert_eq!(block.slot, 300);
        assert_eq!(block.proposer_index, 88);
        assert_eq!(block.parent_root, parent_root);
        assert_eq!(block.state_root, state_root);
        assert_eq!(block.body, body);
    }

    #[test]
    fn test_deserialize_beacon_block_empty_body() {
        let ssz = build_beacon_block_ssz(1, 1, [0u8; 32], [0u8; 32], &[]);
        let (block, _) =
            deserialize_beacon_block_from_ssz(&ssz, SszBlockFormat::BeaconBlock).unwrap();
        assert!(block.body.is_empty());
    }

    fn build_gloas_block_contents_ssz(
        slot: u64,
        proposer_index: u64,
        envelope: &[u8],
        kzg_proofs: &[u8],
        blobs: &[u8],
    ) -> Vec<u8> {
        let block_ssz =
            build_beacon_block_ssz(slot, proposer_index, [0x11; 32], [0x22; 32], &[0xde, 0xad]);
        let block_off: u32 = GLOAS_BLOCK_CONTENTS_FIXED_LEN as u32;
        let envelope_off = block_off + block_ssz.len() as u32;
        let kzg_off = envelope_off + envelope.len() as u32;
        let blobs_off = kzg_off + kzg_proofs.len() as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&block_off.to_le_bytes());
        buf.extend_from_slice(&envelope_off.to_le_bytes());
        buf.extend_from_slice(&kzg_off.to_le_bytes());
        buf.extend_from_slice(&blobs_off.to_le_bytes());
        buf.extend_from_slice(&block_ssz);
        buf.extend_from_slice(envelope);
        buf.extend_from_slice(kzg_proofs);
        buf.extend_from_slice(blobs);
        buf
    }

    #[test]
    fn test_gloas_block_contents_extracts_opaque_slices_and_bounded_block() {
        let envelope = vec![0xe0, 0xe1, 0xe2];
        let kzg = vec![0xaa; 8];
        let blobs = vec![0xbb; 16];
        let bytes = build_gloas_block_contents_ssz(77, 3, &envelope, &kzg, &blobs);
        assert!(looks_like_gloas_block_contents(&bytes));
        let parsed = deserialize_gloas_block_contents(&bytes).unwrap();
        assert_eq!(parsed.block.slot, 77);
        assert_eq!(parsed.block.proposer_index, 3);
        assert_eq!(parsed.envelope_ssz, envelope);
        assert_eq!(parsed.kzg_proofs, kzg);
        assert_eq!(parsed.blobs, blobs);
        assert!(!parsed.block_ssz.windows(envelope.len()).any(|w| w == envelope.as_slice()));
        assert!(!parsed.block_ssz.windows(kzg.len()).any(|w| w == kzg.as_slice()));
    }

    #[test]
    fn test_serialize_signed_beacon_block_ssz_offset_sig_block() {
        let block_ssz = vec![0x01, 0x02, 0x03, 0x04];
        let sig = vec![0xab; 96];
        let framed = serialize_signed_beacon_block_ssz(&block_ssz, &sig).unwrap();
        assert_eq!(&framed[0..4], &SIGNED_BEACON_BLOCK_MESSAGE_OFFSET.to_le_bytes());
        assert_eq!(&framed[4..100], sig.as_slice());
        assert_eq!(&framed[100..], block_ssz.as_slice());
    }

    #[test]
    fn test_looks_like_gloas_block_contents_rejects_bare_beacon_block() {
        let ssz = build_beacon_block_ssz(100, 42, [1u8; 32], [2u8; 32], &[0xde]);
        assert!(!looks_like_gloas_block_contents(&ssz));
    }

    #[test]
    fn test_gloas_block_contents_too_short_is_error() {
        let err = deserialize_gloas_block_contents(&[0u8; 8]).unwrap_err();
        match err {
            crate::BeaconError::ParseError(msg) => {
                assert!(msg.contains("Gloas BlockContents"), "{msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }
}
