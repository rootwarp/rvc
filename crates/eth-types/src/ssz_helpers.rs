//! SSZ encode/decode helpers for consensus objects.
//!
//! ## What `fork_id` means here
//!
//! Helpers take a numeric `fork_id` matching [`crate::ForkName::id`]
//! (PHASE0=0 … FULU=6). Unknown ids are rejected against
//! `DECODER_SUPPORTED_FORK_IDS` (`0..=6`), **not** [`crate::ForkName`]'s
//! `TryFrom<u32>` impl. **`fork_id` is not a layout dispatcher**: encoders
//! ignore it, and decoders use a single fixed layout per type. In particular
//! [`decode_attestation_ssz`] always expects the pre-Electra three-field
//! attestation shape (see below). A live mainnet Electra VC may still send
//! `fork_id = 5` with that pre-Electra-shaped buffer — that path must keep
//! working. Electra-shaped four-field buffers are rejected with
//! [`SszDecodeError::ElectraLayoutUnsupported`] rather than misparsed.
//! A real `ElectraAttestation` SSZ codec is out of scope for these helpers.
//!
//! The allowlist is independent of [`crate::ForkName`] so adding a variant
//! cannot silently admit new bytes to these fixed pre-Electra decoders. After
//! issue 2.5b, `ForkName::try_from(7) == Ok(Gloas)` while `validate_fork_id(7)`
//! stays `Err`. At this commit the two sets are bit-identical (`0..=6`); the
//! only later behavioural change is id 7 staying rejected. Do not treat
//! `DECODER_SUPPORTED_FORK_IDS` as a free-floating tuning knob, and do not
//! widen it to `ForkName::COUNT`.
//!
//! Encoded `fork_id` is ignored (`encode_beacon_block_ssz` takes `_fork_id`)
//! but every `decode_*_ssz` validates, so the gRPC path
//! `grpc-signer/src/client.rs` (`fork_id = ctx.fork_name.id()`) →
//! `signer-server/src/grpc_common.rs` fails every remote sign at Gloas with
//! `UnknownForkId(7)`. That fail-closed verdict is deliberate for Phase 2
//! (tested end-to-end in 2.5b) and is not the accepted end state for gRPC
//! duties: Phase 4 adds a Gloas-safe signing contract (precomputed object
//! root plus explicit fork-version/domain context). No Gloas SSZ bytes may
//! reach a decoder guarded by `0..=6`.
//!
//! ## BeaconBlock container
//!
//! The `BeaconBlock` and related types use a `body: Vec<u8>` representation
//! internally. Their SSZ layout is a simple 5-field container with one
//! variable-length field (`body`):
//!
//! | field          | type      | size                  |
//! |----------------|-----------|-----------------------|
//! | slot           | uint64    | 8 bytes (fixed)       |
//! | proposer_index | uint64    | 8 bytes (fixed)       |
//! | parent_root    | bytes32   | 32 bytes (fixed)      |
//! | state_root     | bytes32   | 32 bytes (fixed)      |
//! | body           | List[...]  | 4-byte offset + data  |
//!
//! The fixed part (including the 4-byte offset for `body`) is 84 bytes.

use std::ops::RangeInclusive;

use thiserror::Error;

use crate::{
    Attestation, AttestationData, BeaconBlock, BlindedBeaconBlock, SyncCommitteeContribution,
};

/// Errors that can occur when decoding SSZ bytes into a consensus type.
#[derive(Debug, Error)]
pub enum SszDecodeError {
    #[error("SSZ buffer too short: need at least {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("SSZ offset out of range: offset {offset} > buffer length {len}")]
    OffsetOutOfRange { offset: usize, len: usize },

    #[error("unknown fork_id: {0}")]
    UnknownForkId(u32),

    #[error("invalid SSZ encoding: {0}")]
    InvalidEncoding(String),

    /// Buffer looks like an Electra (or later) attestation layout with
    /// `committee_bits`, which these helpers do not decode. Prefer this over
    /// silently returning a garbage pre-Electra [`Attestation`].
    #[error(
        "Electra-shaped attestation SSZ is not supported by this decoder (fork_id={fork_id}); \
         send the pre-Electra three-field layout or use a codec that understands committee_bits"
    )]
    ElectraLayoutUnsupported { fork_id: u32 },
}

// ============================================================
// BeaconBlock
// ============================================================

/// SSZ-encode a [`BeaconBlock`] to bytes.
///
/// The layout mirrors the Ethereum consensus specification SSZ container
/// with one variable-length field (`body`).
pub fn encode_beacon_block_ssz(block: &BeaconBlock, _fork_id: u32) -> Vec<u8> {
    encode_beacon_block_inner(
        &block.slot,
        block.proposer_index,
        &block.parent_root,
        &block.state_root,
        &block.body,
    )
}

/// SSZ-decode bytes into a [`BeaconBlock`], dispatching by `fork_id`.
///
/// All forks share the same `BeaconBlock` SSZ container layout (the fork
/// is encoded in the body, not in the outer wrapper). The `fork_id` is
/// accepted for forward compatibility and validated to be a known value.
pub fn decode_beacon_block_ssz(bytes: &[u8], fork_id: u32) -> Result<BeaconBlock, SszDecodeError> {
    validate_fork_id(fork_id)?;
    let (slot, proposer_index, parent_root, state_root, body) = decode_block_container(bytes)?;
    Ok(BeaconBlock { slot, proposer_index, parent_root, state_root, body })
}

// ============================================================
// BlindedBeaconBlock
// ============================================================

/// SSZ-encode a [`BlindedBeaconBlock`] to bytes.
pub fn encode_blinded_beacon_block_ssz(block: &BlindedBeaconBlock, _fork_id: u32) -> Vec<u8> {
    encode_beacon_block_inner(
        &block.slot,
        block.proposer_index,
        &block.parent_root,
        &block.state_root,
        &block.body,
    )
}

/// SSZ-decode bytes into a [`BlindedBeaconBlock`], dispatching by `fork_id`.
pub fn decode_blinded_beacon_block_ssz(
    bytes: &[u8],
    fork_id: u32,
) -> Result<BlindedBeaconBlock, SszDecodeError> {
    validate_fork_id(fork_id)?;
    let (slot, proposer_index, parent_root, state_root, body) = decode_block_container(bytes)?;
    Ok(BlindedBeaconBlock { slot, proposer_index, parent_root, state_root, body })
}

// ============================================================
// Attestation
// ============================================================

/// Pre-Electra attestation fixed prefix length for the wire layout used here:
/// `offset_agg(4) | data(128) | offset_sig(4)`.
const ATTESTATION_FIXED_LEN: usize = 4 + 128 + 4;

/// SSZ-encode an [`Attestation`] to bytes.
///
/// Pre-Electra three-field layout (aggregation_bits and signature treated as
/// variable-length regions; data fixed at 128 bytes):
/// `offset_agg(4) + data(128) + offset_sig(4) + aggregation_bits + signature`.
///
/// `fork_id` is accepted for API symmetry and is not used for encoding.
pub fn encode_attestation_ssz(att: &Attestation, _fork_id: u32) -> Vec<u8> {
    // data is fixed-length (128 bytes: 8+8+32+40+40)
    use ssz::Encode;
    let data_bytes = att.data.as_ssz_bytes();

    let fixed_size = 4 + data_bytes.len() + 4; // offset1 + data + offset3
    let offset1: u32 = fixed_size as u32; // aggregation_bits starts here
    let offset3: u32 = offset1 + att.aggregation_bits.len() as u32; // signature starts here

    let mut out = Vec::with_capacity(fixed_size + att.aggregation_bits.len() + att.signature.len());
    out.extend_from_slice(&offset1.to_le_bytes());
    out.extend_from_slice(&data_bytes);
    out.extend_from_slice(&offset3.to_le_bytes());
    out.extend_from_slice(&att.aggregation_bits);
    out.extend_from_slice(&att.signature);
    out
}

/// SSZ-decode bytes into a pre-Electra [`Attestation`].
///
/// Always expects the three-field layout produced by [`encode_attestation_ssz`],
/// regardless of `fork_id` (including Electra/`5` and Fulu/`6`). Buffers whose
/// offsets or trailing sizes do not match that layout — typically Electra
/// attestations carrying `committee_bits` — return
/// [`SszDecodeError::ElectraLayoutUnsupported`] instead of a wrong
/// [`Attestation`].
pub fn decode_attestation_ssz(bytes: &[u8], fork_id: u32) -> Result<Attestation, SszDecodeError> {
    validate_fork_id(fork_id)?;

    use ssz::Decode;

    // Layout: offset_agg(4) + data(128) + offset_sig(4) + aggregation_bits + signature(96)
    const DATA_SSZ_LEN: usize = 128; // 8+8+32+40+40
    const FIXED_LEN: usize = ATTESTATION_FIXED_LEN;
    const BLS_SIG_LEN: usize = crate::SIGNATURE_BYTES_LEN;

    if bytes.len() < FIXED_LEN {
        return Err(SszDecodeError::TooShort { need: FIXED_LEN, got: bytes.len() });
    }

    let offset1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let data_bytes = &bytes[4..4 + DATA_SSZ_LEN];
    let offset3 =
        u32::from_le_bytes(bytes[4 + DATA_SSZ_LEN..FIXED_LEN].try_into().unwrap()) as usize;

    // Strict inverse of `encode_attestation_ssz`: the first variable region
    // must start immediately after the fixed prefix. A larger first offset is
    // what Electra four-field encodings produce (extra offset / fixed fields
    // in the prefix) and must not be misparsed as aggregation_bits.
    if offset1 != FIXED_LEN {
        if offset1 > FIXED_LEN && offset1 <= bytes.len() {
            return Err(SszDecodeError::ElectraLayoutUnsupported { fork_id });
        }
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset1, len: bytes.len() });
    }
    if offset3 < offset1 || offset3 > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset3, len: bytes.len() });
    }

    let sig_len = bytes.len() - offset3;
    // BLS signatures are fixed 96 bytes. Extra trailing bytes are the usual
    // signature of an Electra buffer that appended `committee_bits` after the
    // three-field body (or used a different trailing split).
    if sig_len != BLS_SIG_LEN {
        return Err(SszDecodeError::ElectraLayoutUnsupported { fork_id });
    }

    let aggregation_bits = bytes[offset1..offset3].to_vec();
    let signature = bytes[offset3..].to_vec();
    let data = AttestationData::from_ssz_bytes(data_bytes)
        .map_err(|e| SszDecodeError::InvalidEncoding(format!("AttestationData: {:?}", e)))?;

    Ok(Attestation { aggregation_bits, data, signature })
}

// ============================================================
// SyncCommitteeContribution
// ============================================================

/// SSZ-encode a [`SyncCommitteeContribution`] to bytes.
///
/// Layout: slot(8) + beacon_block_root(32) + subcommittee_index(8) + offset_aggbits(4) + offset_sig(4)
///         + aggregation_bits + signature
pub fn encode_sync_committee_contribution_ssz(
    contrib: &SyncCommitteeContribution,
    _fork_id: u32,
) -> Vec<u8> {
    // Fixed fields: slot(8) + beacon_block_root(32) + subcommittee_index(8) = 48 bytes
    // Two variable fields: aggregation_bits, signature → 2 × 4-byte offsets
    let fixed_size = 8 + 32 + 8 + 4 + 4; // 56
    let offset_aggbits: u32 = fixed_size as u32;
    let offset_sig: u32 = offset_aggbits + contrib.aggregation_bits.len() as u32;

    let mut out =
        Vec::with_capacity(fixed_size + contrib.aggregation_bits.len() + contrib.signature.len());
    out.extend_from_slice(&contrib.slot.to_le_bytes());
    out.extend_from_slice(&contrib.beacon_block_root);
    out.extend_from_slice(&contrib.subcommittee_index.to_le_bytes());
    out.extend_from_slice(&offset_aggbits.to_le_bytes());
    out.extend_from_slice(&offset_sig.to_le_bytes());
    out.extend_from_slice(&contrib.aggregation_bits);
    out.extend_from_slice(&contrib.signature);
    out
}

/// SSZ-decode bytes into a [`SyncCommitteeContribution`], dispatching by `fork_id`.
pub fn decode_sync_committee_contribution_ssz(
    bytes: &[u8],
    fork_id: u32,
) -> Result<SyncCommitteeContribution, SszDecodeError> {
    validate_fork_id(fork_id)?;

    // Fixed: slot(8) + beacon_block_root(32) + subcommittee_index(8) + offset_aggbits(4) + offset_sig(4) = 56
    const FIXED_LEN: usize = 56;
    if bytes.len() < FIXED_LEN {
        return Err(SszDecodeError::TooShort { need: FIXED_LEN, got: bytes.len() });
    }

    let slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let beacon_block_root: [u8; 32] = bytes[8..40].try_into().unwrap();
    let subcommittee_index = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let offset_aggbits = u32::from_le_bytes(bytes[48..52].try_into().unwrap()) as usize;
    let offset_sig = u32::from_le_bytes(bytes[52..56].try_into().unwrap()) as usize;

    if offset_aggbits < FIXED_LEN || offset_aggbits > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset_aggbits, len: bytes.len() });
    }
    if offset_sig < offset_aggbits || offset_sig > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset_sig, len: bytes.len() });
    }

    let aggregation_bits = bytes[offset_aggbits..offset_sig].to_vec();
    let signature = bytes[offset_sig..].to_vec();

    Ok(SyncCommitteeContribution {
        slot,
        beacon_block_root,
        subcommittee_index,
        aggregation_bits,
        signature,
    })
}

// ============================================================
// Internal helpers
// ============================================================

/// Decoded inner fields of a block container:
/// (slot, proposer_index, parent_root, state_root, body)
type BlockFields = (u64, u64, [u8; 32], [u8; 32], Vec<u8>);

/// Fork ids accepted by the four `decode_*_ssz` entry points (Phase0=0 … Fulu=6).
///
/// Not derived from [`crate::ForkName`]: after 2.5b, `ForkName::try_from(7)` is
/// `Ok(Gloas)` while id 7 stays rejected here so Gloas SSZ never reaches these
/// fixed pre-Electra layouts. Bit-identical to today's `ForkName` accept set;
/// do not widen when Gloas lands (and never to `ForkName::COUNT`).
const DECODER_SUPPORTED_FORK_IDS: RangeInclusive<u32> = 0..=6;

/// Reject `fork_id`s outside [`DECODER_SUPPORTED_FORK_IDS`].
///
/// Independent of [`crate::ForkName::try_from`].
fn validate_fork_id(fork_id: u32) -> Result<(), SszDecodeError> {
    if DECODER_SUPPORTED_FORK_IDS.contains(&fork_id) {
        Ok(())
    } else {
        Err(SszDecodeError::UnknownForkId(fork_id))
    }
}

/// SSZ encode the inner block fields (shared by BeaconBlock and BlindedBeaconBlock).
///
/// Layout: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_offset(4) + body
fn encode_beacon_block_inner(
    slot: &u64,
    proposer_index: u64,
    parent_root: &[u8; 32],
    state_root: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    // Fixed: 8 + 8 + 32 + 32 + 4 (offset for body) = 84
    const FIXED: u32 = 84;
    let mut out = Vec::with_capacity(84 + body.len());
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&proposer_index.to_le_bytes());
    out.extend_from_slice(parent_root.as_ref());
    out.extend_from_slice(state_root.as_ref());
    out.extend_from_slice(&FIXED.to_le_bytes()); // body offset = 84
    out.extend_from_slice(body);
    out
}

/// SSZ decode the inner block fields.
fn decode_block_container(bytes: &[u8]) -> Result<BlockFields, SszDecodeError> {
    const FIXED: usize = 84;
    if bytes.len() < FIXED {
        return Err(SszDecodeError::TooShort { need: FIXED, got: bytes.len() });
    }

    let slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let proposer_index = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let parent_root: [u8; 32] = bytes[16..48].try_into().unwrap();
    let state_root: [u8; 32] = bytes[48..80].try_into().unwrap();
    let body_offset = u32::from_le_bytes(bytes[80..84].try_into().unwrap()) as usize;

    if body_offset < FIXED || body_offset > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: body_offset, len: bytes.len() });
    }

    let body = bytes[body_offset..].to_vec();
    Ok((slot, proposer_index, parent_root, state_root, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationData, Checkpoint};

    fn sample_beacon_block() -> BeaconBlock {
        BeaconBlock {
            slot: 12345,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    fn sample_blinded_block() -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot: 12345,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xca, 0xfe],
        }
    }

    fn sample_attestation() -> Attestation {
        Attestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [0x33; 32],
                source: Checkpoint { epoch: 9, root: [0x44; 32] },
                target: Checkpoint { epoch: 10, root: [0x55; 32] },
            },
            signature: vec![0xaa; 96],
        }
    }

    fn sample_contribution() -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot: 200,
            beacon_block_root: [0x66; 32],
            subcommittee_index: 3,
            aggregation_bits: vec![0x0f; 16],
            signature: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_encode_decode_beacon_block_roundtrip_all_fork_ids() {
        let block = sample_beacon_block();
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let encoded = encode_beacon_block_ssz(&block, fork_id);
            let decoded = decode_beacon_block_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(block, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_blinded_beacon_block_roundtrip_all_fork_ids() {
        let block = sample_blinded_block();
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let encoded = encode_blinded_beacon_block_ssz(&block, fork_id);
            let decoded =
                decode_blinded_beacon_block_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(block, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_attestation_roundtrip_all_fork_ids() {
        let att = sample_attestation();
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let encoded = encode_attestation_ssz(&att, fork_id);
            let decoded = decode_attestation_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(att, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_sync_committee_contribution_roundtrip_all_fork_ids() {
        let contrib = sample_contribution();
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let encoded = encode_sync_committee_contribution_ssz(&contrib, fork_id);
            let decoded =
                decode_sync_committee_contribution_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(contrib, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    /// Gloas is fork id 7. These fixed-layout decoders must reject it even
    /// after `ForkName::try_from(7)` becomes `Ok(Gloas)` (issue 2.5b). The
    /// allowlist is independent of `ForkName`'s variant set.
    #[test]
    fn test_decode_beacon_block_unknown_fork_id_rejected() {
        let block = sample_beacon_block();
        let encoded = encode_beacon_block_ssz(&block, 0);
        let result = decode_beacon_block_ssz(&encoded, 7);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(7))));
    }

    /// `validate_fork_id` checks `DECODER_SUPPORTED_FORK_IDS` (`0..=6`), not
    /// `ForkName::try_from`. After 2.5b, `ForkName::try_from(7) == Ok(Gloas)`
    /// while this decoder path stays `Err(UnknownForkId(7))`.
    /// Accept 0..=6; reject 7 and `u32::MAX` with `UnknownForkId`.
    #[test]
    fn test_validate_fork_id_accepts_0_through_6_rejects_7_and_max() {
        let block = sample_beacon_block();
        let encoded = encode_beacon_block_ssz(&block, 0);
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            decode_beacon_block_ssz(&encoded, fork_id)
                .unwrap_or_else(|e| panic!("fork_id={fork_id} should be accepted: {e}"));
        }
        for fork_id in [7u32, u32::MAX] {
            let result = decode_beacon_block_ssz(&encoded, fork_id);
            assert!(
                matches!(result, Err(SszDecodeError::UnknownForkId(id)) if id == fork_id),
                "fork_id={fork_id} should be UnknownForkId, got {result:?}"
            );
        }
    }

    /// B4 (D18): pin allowlist membership as a set, independent of loops that
    /// iterate `DECODER_SUPPORTED_FORK_IDS`. Widening to include Gloas (7) or
    /// narrowing must fail even if those loops stay green.
    #[test]
    fn test_decoder_supported_fork_ids_membership_is_exactly_0_through_6() {
        let members: Vec<u32> = DECODER_SUPPORTED_FORK_IDS.collect();
        assert_eq!(members, vec![0, 1, 2, 3, 4, 5, 6]);

        let block_bytes = encode_beacon_block_ssz(&sample_beacon_block(), 0);
        let blinded_bytes = encode_blinded_beacon_block_ssz(&sample_blinded_block(), 0);
        let att_bytes = encode_attestation_ssz(&sample_attestation(), 0);
        let contrib_bytes = encode_sync_committee_contribution_ssz(&sample_contribution(), 0);

        for fork_id in [0u32, 1, 2, 3, 4, 5, 6] {
            decode_beacon_block_ssz(&block_bytes, fork_id).unwrap_or_else(|e| {
                panic!("beacon_block fork_id={fork_id} should be accepted: {e}")
            });
            decode_blinded_beacon_block_ssz(&blinded_bytes, fork_id).unwrap_or_else(|e| {
                panic!("blinded_beacon_block fork_id={fork_id} should be accepted: {e}")
            });
            decode_attestation_ssz(&att_bytes, fork_id).unwrap_or_else(|e| {
                panic!("attestation fork_id={fork_id} should be accepted: {e}")
            });
            decode_sync_committee_contribution_ssz(&contrib_bytes, fork_id).unwrap_or_else(|e| {
                panic!("sync_committee_contribution fork_id={fork_id} should be accepted: {e}")
            });
        }
        for fork_id in [7u32, 8, u32::MAX] {
            for (name, result) in [
                ("beacon_block", decode_beacon_block_ssz(&block_bytes, fork_id).map(|_| ())),
                (
                    "blinded_beacon_block",
                    decode_blinded_beacon_block_ssz(&blinded_bytes, fork_id).map(|_| ()),
                ),
                ("attestation", decode_attestation_ssz(&att_bytes, fork_id).map(|_| ())),
                (
                    "sync_committee_contribution",
                    decode_sync_committee_contribution_ssz(&contrib_bytes, fork_id).map(|_| ()),
                ),
            ] {
                assert!(
                    matches!(result, Err(SszDecodeError::UnknownForkId(id)) if id == fork_id),
                    "{name} fork_id={fork_id} should be UnknownForkId, got {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_decode_beacon_block_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_beacon_block_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_blinded_beacon_block_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_blinded_beacon_block_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_attestation_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_attestation_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_contribution_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_sync_committee_contribution_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_attestation_unknown_fork_id_rejected() {
        let att = sample_attestation();
        let encoded = encode_attestation_ssz(&att, 0);
        let result = decode_attestation_ssz(&encoded, 99);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(99))));
    }

    #[test]
    fn test_decode_contribution_unknown_fork_id_rejected() {
        let contrib = sample_contribution();
        let encoded = encode_sync_committee_contribution_ssz(&contrib, 0);
        let result = decode_sync_committee_contribution_ssz(&encoded, 99);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(99))));
    }

    #[test]
    fn test_beacon_block_encoded_length() {
        let block = sample_beacon_block();
        let encoded = encode_beacon_block_ssz(&block, 0);
        // 84 bytes fixed + body.len()
        assert_eq!(encoded.len(), 84 + block.body.len());
    }

    #[test]
    fn test_beacon_block_empty_body_roundtrip() {
        let block = BeaconBlock {
            slot: 0,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: vec![],
        };
        let encoded = encode_beacon_block_ssz(&block, 4); // Deneb
        let decoded = decode_beacon_block_ssz(&encoded, 4).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn test_attestation_empty_bits_roundtrip() {
        let att = Attestation {
            aggregation_bits: vec![],
            data: AttestationData {
                slot: 0,
                index: 0,
                beacon_block_root: [0u8; 32],
                source: Checkpoint { epoch: 0, root: [0u8; 32] },
                target: Checkpoint { epoch: 0, root: [0u8; 32] },
            },
            signature: vec![0u8; 96],
        };
        let encoded = encode_attestation_ssz(&att, 0);
        let decoded = decode_attestation_ssz(&encoded, 0).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn test_contribution_large_aggregation_bits_roundtrip() {
        let contrib = SyncCommitteeContribution {
            slot: 999,
            beacon_block_root: [0x77; 32],
            subcommittee_index: 7,
            aggregation_bits: vec![0xff; 64],
            signature: vec![0xcc; 96],
        };
        let encoded = encode_sync_committee_contribution_ssz(&contrib, 5); // Electra
        let decoded = decode_sync_committee_contribution_ssz(&encoded, 5).unwrap();
        assert_eq!(contrib, decoded);
    }

    /// Hand-encode an Electra four-field attestation in the same offset style as
    /// [`encode_attestation_ssz`], plus a third offset for `committee_bits`.
    ///
    /// Layout: `offset_agg(4) | data(128) | offset_sig(4) | offset_committee(4)
    /// | aggregation_bits | signature | committee_bits`.
    fn encode_electra_shaped_attestation_handrolled(
        aggregation_bits: &[u8],
        data: &AttestationData,
        signature: &[u8],
        committee_bits: &[u8],
    ) -> Vec<u8> {
        use ssz::Encode;
        let data_bytes = data.as_ssz_bytes();
        let fixed_size = 4 + data_bytes.len() + 4 + 4;
        let offset_agg = fixed_size as u32;
        let offset_sig = offset_agg + aggregation_bits.len() as u32;
        let offset_committee = offset_sig + signature.len() as u32;

        let mut out = Vec::with_capacity(
            fixed_size + aggregation_bits.len() + signature.len() + committee_bits.len(),
        );
        out.extend_from_slice(&offset_agg.to_le_bytes());
        out.extend_from_slice(&data_bytes);
        out.extend_from_slice(&offset_sig.to_le_bytes());
        out.extend_from_slice(&offset_committee.to_le_bytes());
        out.extend_from_slice(aggregation_bits);
        out.extend_from_slice(signature);
        out.extend_from_slice(committee_bits);
        out
    }

    /// RF3-09: Electra four-field buffers must not decode as a garbage
    /// pre-Electra `Attestation`.
    #[test]
    fn test_electra_shaped_aggregate_is_not_silently_misparsed() {
        let data = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0x33; 32],
            source: Checkpoint { epoch: 9, root: [0x44; 32] },
            target: Checkpoint { epoch: 10, root: [0x55; 32] },
        };
        let encoded = encode_electra_shaped_attestation_handrolled(
            &[0xff, 0x01],
            &data,
            &[0xaa; 96],
            &[0x01; 8], // committee_bits (Bitvector[64] = 8 bytes)
        );

        // First offset is 140, not 136 — without the structural check this used
        // to return Ok(Attestation) with a corrupted signature region.
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), 140);

        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let result = decode_attestation_ssz(&encoded, fork_id);
            assert!(
                matches!(
                    result,
                    Err(SszDecodeError::ElectraLayoutUnsupported { fork_id: id }) if id == fork_id
                ),
                "fork_id={fork_id}: expected ElectraLayoutUnsupported, got {result:?}"
            );
        }
    }

    /// RF3-09: mainnet Electra path tags `fork_id = 5` but still sends the
    /// pre-Electra-shaped buffer from [`encode_attestation_ssz`].
    #[test]
    fn test_legacy_attestation_at_fork_id_5_still_decodes() {
        let att = sample_attestation();
        let encoded = encode_attestation_ssz(&att, 5);
        let decoded = decode_attestation_ssz(&encoded, 5).expect("legacy @ fork_id=5");
        assert_eq!(att, decoded);
    }

    /// RF3-09: legacy round-trip remains green for every known fork id.
    #[test]
    fn test_legacy_attestation_roundtrip_all_fork_ids_0_to_6() {
        let att = sample_attestation();
        for fork_id in DECODER_SUPPORTED_FORK_IDS {
            let encoded = encode_attestation_ssz(&att, fork_id);
            let decoded = decode_attestation_ssz(&encoded, fork_id)
                .unwrap_or_else(|e| panic!("fork_id={fork_id}: {e}"));
            assert_eq!(att, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    /// RF3-09: Electra layout that reuses the 136-byte fixed prefix but appends
    /// `committee_bits` after a 96-byte signature (sig region longer than 96).
    #[test]
    fn test_electra_trailing_committee_bits_rejected() {
        let att = sample_attestation();
        let mut encoded = encode_attestation_ssz(&att, 5);
        encoded.extend_from_slice(&[0x01; 8]); // fake committee_bits trailer

        let result = decode_attestation_ssz(&encoded, 5);
        assert!(
            matches!(result, Err(SszDecodeError::ElectraLayoutUnsupported { fork_id: 5 })),
            "got {result:?}"
        );
    }
}
