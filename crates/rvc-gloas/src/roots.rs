//! Gloas container roots over SSZ bytes.
//!
//! [`gloas_attestation_root`], [`gloas_indexed_attestation_root`],
//! [`gloas_aggregate_and_proof_root`], [`gloas_block_root`], [`gloas_body_root`],
//! [`gloas_execution_payload_envelope_root`]. Island types stay crate-private.
//! `eth_types::Root` (`[u8; 32]`) is used, not re-exported.

use eth_types::Root;
use libssz::SszDecode;
#[cfg(any(test, feature = "test-fixtures"))]
use libssz::SszEncode;
use libssz_merkle::{HashTreeRoot, Sha2Hasher};

use crate::containers::attestation::{AggregateAndProof, Attestation, IndexedAttestation};
use crate::containers::block_body::from_ssz_bytes;
use crate::containers::envelope::ExecutionPayloadEnvelope;
use crate::containers::leaves::BeaconBlockHeader;
use crate::error::GloasError;

/// consensus-specs `BUILDER_INDEX_SELF_BUILD` (`ValidatorIndex(UINT64_MAX)`).
///
/// A Gloas bid with this `builder_index` is a self-build. Every other index is
/// an external bid. The produce container (`BlockContents` vs `BeaconBlock`)
/// does not decide that.
pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;

/// Official `MAX_COMMITTEES_PER_SLOT` values. `committee_bits` is `Bitvector[N]`;
/// SSZ `fixed_part_len` differs, so a payload decodes at exactly one N.
const MAX_COMMITTEES_PER_SLOT_MINIMAL: usize = 4;
const MAX_COMMITTEES_PER_SLOT_MAINNET: usize = 64;
const _: () =
    assert!(MAX_COMMITTEES_PER_SLOT_MAINNET == eth_types::MAX_COMMITTEES_PER_SLOT as usize);

/// Official `SYNC_COMMITTEE_SIZE` / `PTC_SIZE` (minimal vs mainnet). Body
/// `fixed_part_len` includes `SyncAggregate`, so a payload decodes at one preset.
const SYNC_COMMITTEE_SIZE_MINIMAL: usize = 32;
const SYNC_COMMITTEE_SIZE_MAINNET: usize = 512;
const PTC_SIZE_MINIMAL: usize = 16;
const PTC_SIZE_MAINNET: usize = 512;
const _: () = assert!(SYNC_COMMITTEE_SIZE_MAINNET == eth_types::SYNC_COMMITTEE_SIZE as usize);

/// Gloas `BeaconBlock` header leaves. Body is supplied separately as SSZ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderFields {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
}

fn decode_root<T: SszDecode + HashTreeRoot>(ssz: &[u8]) -> Result<Root, GloasError> {
    let decoded = T::from_ssz_bytes(ssz)
        .map_err(|err| GloasError::InvalidBody { reason: format!("{err:?}") })?;
    Ok(decoded.hash_tree_root(&Sha2Hasher))
}

fn decode_min_or_mainnet<TMin, TMain>(ssz: &[u8]) -> Result<Root, GloasError>
where
    TMin: SszDecode + HashTreeRoot,
    TMain: SszDecode + HashTreeRoot,
{
    // Wrong-N success would sign a root no peer accepts; libssz rejects a first
    // offset that is not `fixed_part_len`, so only one arm can succeed.
    decode_root::<TMin>(ssz).or_else(|_| decode_root::<TMain>(ssz))
}

/// Hash tree root of Gloas `Attestation` SSZ (`MAX_COMMITTEES_PER_SLOT` 4 or 64).
pub fn gloas_attestation_root(ssz: &[u8]) -> Result<Root, GloasError> {
    decode_min_or_mainnet::<
        Attestation<MAX_COMMITTEES_PER_SLOT_MINIMAL>,
        Attestation<MAX_COMMITTEES_PER_SLOT_MAINNET>,
    >(ssz)
}

/// Hash tree root of Gloas `IndexedAttestation` SSZ.
pub fn gloas_indexed_attestation_root(ssz: &[u8]) -> Result<Root, GloasError> {
    decode_root::<IndexedAttestation>(ssz)
}

/// Hash tree root of Gloas `AggregateAndProof` SSZ (`MAX_COMMITTEES_PER_SLOT` 4 or 64).
pub fn gloas_aggregate_and_proof_root(ssz: &[u8]) -> Result<Root, GloasError> {
    decode_min_or_mainnet::<
        AggregateAndProof<MAX_COMMITTEES_PER_SLOT_MINIMAL>,
        AggregateAndProof<MAX_COMMITTEES_PER_SLOT_MAINNET>,
    >(ssz)
}

/// Hash tree root of Gloas `BeaconBlockBody` SSZ (minimal or mainnet preset).
///
/// This is the `body_root` leaf for the gRPC header RPC. Decode failure is
/// [`GloasError::InvalidBody`] — never a fallback root.
pub fn gloas_body_root(body_ssz: &[u8]) -> Result<Root, GloasError> {
    gloas_body_root_at::<
        MAX_COMMITTEES_PER_SLOT_MINIMAL,
        SYNC_COMMITTEE_SIZE_MINIMAL,
        PTC_SIZE_MINIMAL,
    >(body_ssz)
    .or_else(|_| {
        gloas_body_root_at::<
            MAX_COMMITTEES_PER_SLOT_MAINNET,
            SYNC_COMMITTEE_SIZE_MAINNET,
            PTC_SIZE_MAINNET,
        >(body_ssz)
    })
}

fn gloas_body_root_at<const COMMITTEES: usize, const SYNC: usize, const PTC: usize>(
    body_ssz: &[u8],
) -> Result<Root, GloasError> {
    let body = from_ssz_bytes::<COMMITTEES, SYNC, PTC>(body_ssz)?;
    Ok(body.hash_tree_root(&Sha2Hasher))
}

/// Hash tree root of a Gloas `BeaconBlock`: header leaves plus typed body HTR.
///
/// Leaf order is `slot, proposer_index, parent_root, state_root, body_root`.
/// The body leaf is the decoded body's hash tree root, not a `ByteList` root.
pub fn gloas_block_root(header: &HeaderFields, body_ssz: &[u8]) -> Result<Root, GloasError> {
    let body_root = gloas_body_root(body_ssz)?;
    let block_header = BeaconBlockHeader {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root: header.parent_root,
        state_root: header.state_root,
        body_root,
    };
    Ok(block_header.hash_tree_root(&Sha2Hasher))
}

/// Slot, parent, and `builder_index` of the bid embedded in a Gloas body.
///
/// `parent_block_root` is the beacon parent. `parent_block_hash` is the
/// execution parent and is not part of this binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidBinding {
    pub builder_index: u64,
    pub slot: u64,
    pub parent_block_root: Root,
}

/// Bid fields that must match the block before it is signed.
///
/// Decode failure is [`GloasError::InvalidBody`]. A body that does not decode
/// is not treated as self-build or as an external bid.
pub fn gloas_bid_binding(body_ssz: &[u8]) -> Result<BidBinding, GloasError> {
    bid_binding_at::<MAX_COMMITTEES_PER_SLOT_MINIMAL, SYNC_COMMITTEE_SIZE_MINIMAL, PTC_SIZE_MINIMAL>(
        body_ssz,
    )
    .or_else(|_| {
        bid_binding_at::<
            MAX_COMMITTEES_PER_SLOT_MAINNET,
            SYNC_COMMITTEE_SIZE_MAINNET,
            PTC_SIZE_MAINNET,
        >(body_ssz)
    })
}

fn bid_binding_at<const COMMITTEES: usize, const SYNC: usize, const PTC: usize>(
    body_ssz: &[u8],
) -> Result<BidBinding, GloasError> {
    let body = from_ssz_bytes::<COMMITTEES, SYNC, PTC>(body_ssz)?;
    let bid = &body.signed_execution_payload_bid.message;
    Ok(BidBinding {
        builder_index: bid.builder_index,
        slot: bid.slot,
        parent_block_root: bid.parent_block_root,
    })
}

/// `builder_index` of the signed execution-payload bid embedded in a Gloas body.
///
/// Decode failure is [`GloasError::InvalidBody`]. A body that does not decode
/// is not treated as self-build or as an external bid.
pub fn gloas_bid_builder_index(body_ssz: &[u8]) -> Result<u64, GloasError> {
    Ok(gloas_bid_binding(body_ssz)?.builder_index)
}

/// Fields of an `ExecutionPayloadEnvelope` that must match the block being signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeBinding {
    pub builder_index: u64,
    pub beacon_block_root: Root,
    pub parent_beacon_block_root: Root,
}

/// Envelope fields that must match the block being signed.
///
/// Decode failure is [`GloasError::InvalidBody`].
pub fn gloas_envelope_binding(ssz: &[u8]) -> Result<EnvelopeBinding, GloasError> {
    let envelope = ExecutionPayloadEnvelope::from_ssz_bytes(ssz)
        .map_err(|err| GloasError::InvalidBody { reason: format!("{err:?}") })?;
    Ok(EnvelopeBinding {
        builder_index: envelope.builder_index,
        beacon_block_root: envelope.beacon_block_root,
        parent_beacon_block_root: envelope.parent_beacon_block_root,
    })
}

/// Copy `body_ssz` with the bid `builder_index` replaced. The rest of the body is unchanged.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn body_with_bid_builder_index(
    body_ssz: &[u8],
    builder_index: u64,
) -> Result<Vec<u8>, GloasError> {
    let binding = gloas_bid_binding(body_ssz)?;
    body_with_bid_binding(body_ssz, builder_index, binding.slot, binding.parent_block_root)
}

/// Copy `body_ssz` with the bid index, slot, and beacon parent replaced.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn body_with_bid_binding(
    body_ssz: &[u8],
    builder_index: u64,
    slot: u64,
    parent_block_root: Root,
) -> Result<Vec<u8>, GloasError> {
    fn rewrite<const COMMITTEES: usize, const SYNC: usize, const PTC: usize>(
        body_ssz: &[u8],
        builder_index: u64,
        slot: u64,
        parent_block_root: Root,
    ) -> Result<Vec<u8>, GloasError> {
        let mut body = from_ssz_bytes::<COMMITTEES, SYNC, PTC>(body_ssz)?;
        let bid = &mut body.signed_execution_payload_bid.message;
        bid.builder_index = builder_index;
        bid.slot = slot;
        bid.parent_block_root = parent_block_root;
        Ok(body.to_ssz())
    }
    rewrite::<MAX_COMMITTEES_PER_SLOT_MINIMAL, SYNC_COMMITTEE_SIZE_MINIMAL, PTC_SIZE_MINIMAL>(
        body_ssz,
        builder_index,
        slot,
        parent_block_root,
    )
    .or_else(|_| {
        rewrite::<MAX_COMMITTEES_PER_SLOT_MAINNET, SYNC_COMMITTEE_SIZE_MAINNET, PTC_SIZE_MAINNET>(
            body_ssz,
            builder_index,
            slot,
            parent_block_root,
        )
    })
}

/// Copy envelope SSZ with the three fields that bind it to the signed block.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn envelope_with_binding(
    ssz: &[u8],
    builder_index: u64,
    beacon_block_root: Root,
    parent_beacon_block_root: Root,
) -> Result<Vec<u8>, GloasError> {
    let mut envelope = ExecutionPayloadEnvelope::from_ssz_bytes(ssz)
        .map_err(|err| GloasError::InvalidBody { reason: format!("{err:?}") })?;
    envelope.builder_index = builder_index;
    envelope.beacon_block_root = beacon_block_root;
    envelope.parent_beacon_block_root = parent_beacon_block_root;
    Ok(envelope.to_ssz())
}

/// Hash tree root of unsigned Gloas `ExecutionPayloadEnvelope` SSZ.
///
/// This is the self-build signing object (D20). Decode failure is
/// [`GloasError::InvalidBody`] — never a fallback root.
pub fn gloas_execution_payload_envelope_root(ssz: &[u8]) -> Result<Root, GloasError> {
    decode_root::<ExecutionPayloadEnvelope>(ssz)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_root, gloas_aggregate_and_proof_root, gloas_attestation_root, gloas_block_root,
        gloas_body_root, gloas_body_root_at, gloas_execution_payload_envelope_root,
        gloas_indexed_attestation_root, AggregateAndProof, Attestation, HeaderFields,
        MAX_COMMITTEES_PER_SLOT_MAINNET, MAX_COMMITTEES_PER_SLOT_MINIMAL, PTC_SIZE_MAINNET,
        PTC_SIZE_MINIMAL, SYNC_COMMITTEE_SIZE_MAINNET, SYNC_COMMITTEE_SIZE_MINIMAL,
    };
    use crate::containers::leaves::BeaconBlockHeader;
    use crate::error::GloasError;
    use crate::spec_kat::{mainnet, minimal};
    use eth_types::Root;
    use libssz_merkle::{HashTreeRoot, Sha2Hasher};

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        assert_eq!(hex.len() % 2, 0, "SPEC_* hex must have even length, got {}", hex.len());
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| {
                let s = core::str::from_utf8(chunk).expect("hex digits are utf8");
                u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"))
            })
            .collect()
    }

    fn parse_root(hex: &str) -> Root {
        assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
        parse_hex(hex).try_into().expect("64 hex chars decode to 32 bytes")
    }

    fn truncated(bytes: &[u8]) -> &[u8] {
        assert!(bytes.len() > 1, "vector payload must be truncatable");
        &bytes[..bytes.len() / 2]
    }

    fn assert_invalid_body(result: Result<Root, GloasError>) {
        match result {
            Err(GloasError::InvalidBody { .. }) => {}
            other => panic!("expected InvalidBody, got {other:?}"),
        }
    }

    #[test]
    fn test_gloas_attestation_root() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_ATTESTATION_SSZ);
        let got = gloas_attestation_root(&ssz).expect("valid attestation SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_ATTESTATION_ROOT));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_ATTESTATION_SSZ);
        let got = gloas_attestation_root(&ssz).expect("valid attestation SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_ATTESTATION_ROOT));
    }

    #[test]
    fn test_gloas_indexed_attestation_root() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ);
        let got = gloas_indexed_attestation_root(&ssz).expect("valid indexed attestation SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ);
        let got = gloas_indexed_attestation_root(&ssz).expect("valid indexed attestation SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_INDEXED_ATTESTATION_ROOT));
    }

    #[test]
    fn test_gloas_aggregate_and_proof_root() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        let got = gloas_aggregate_and_proof_root(&ssz).expect("valid aggregate-and-proof SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        let got = gloas_aggregate_and_proof_root(&ssz).expect("valid aggregate-and-proof SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT));
    }

    #[test]
    fn test_gloas_attestation_rejects_truncated() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_ATTESTATION_SSZ);
        assert_invalid_body(gloas_attestation_root(truncated(&ssz)));
        assert_invalid_body(gloas_attestation_root(&[]));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_ATTESTATION_SSZ);
        assert_invalid_body(gloas_attestation_root(truncated(&ssz)));
    }

    #[test]
    fn test_gloas_indexed_attestation_rejects_truncated() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_INDEXED_ATTESTATION_SSZ);
        assert_invalid_body(gloas_indexed_attestation_root(truncated(&ssz)));
        assert_invalid_body(gloas_indexed_attestation_root(&[]));
    }

    #[test]
    fn test_gloas_aggregate_and_proof_rejects_truncated() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        assert_invalid_body(gloas_aggregate_and_proof_root(truncated(&ssz)));
        assert_invalid_body(gloas_aggregate_and_proof_root(&[]));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        assert_invalid_body(gloas_aggregate_and_proof_root(truncated(&ssz)));
    }

    #[test]
    fn test_gloas_execution_payload_envelope_root() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let got = gloas_execution_payload_envelope_root(&ssz).expect("valid envelope SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let got = gloas_execution_payload_envelope_root(&ssz).expect("valid envelope SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT));
    }

    #[test]
    fn test_gloas_execution_payload_envelope_rejects_truncated() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        assert_invalid_body(gloas_execution_payload_envelope_root(truncated(&ssz)));
        assert_invalid_body(gloas_execution_payload_envelope_root(&[]));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        assert_invalid_body(gloas_execution_payload_envelope_root(truncated(&ssz)));
    }

    #[test]
    fn test_attestation_decode_rejects_wrong_committee_width() {
        let minimal_att = parse_hex(minimal::SPEC_GLOAS_ATTESTATION_SSZ);
        let mainnet_att = parse_hex(mainnet::SPEC_GLOAS_ATTESTATION_SSZ);
        assert_invalid_body(decode_root::<Attestation<MAX_COMMITTEES_PER_SLOT_MINIMAL>>(
            &mainnet_att,
        ));
        assert_invalid_body(decode_root::<Attestation<MAX_COMMITTEES_PER_SLOT_MAINNET>>(
            &minimal_att,
        ));
        let minimal_agg = parse_hex(minimal::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        let mainnet_agg = parse_hex(mainnet::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        assert_invalid_body(decode_root::<AggregateAndProof<MAX_COMMITTEES_PER_SLOT_MINIMAL>>(
            &mainnet_agg,
        ));
        assert_invalid_body(decode_root::<AggregateAndProof<MAX_COMMITTEES_PER_SLOT_MAINNET>>(
            &minimal_agg,
        ));
    }

    fn require_active_fields_width(bits: &[bool], expected: usize) -> Result<(), GloasError> {
        let actual = bits.len();
        if actual != expected {
            return Err(GloasError::ActiveFieldsWidth { expected, actual });
        }
        Ok(())
    }

    #[test]
    fn test_active_fields_width_mismatch() {
        // Helper-only: public SSZ fns hash via derive mix-in; `ACTIVE_FIELDS_*`
        // lengths are const-asserted in `lib.rs` and cannot yield this error.
        let err = require_active_fields_width(&[true, true, true], 4)
            .expect_err("width-mismatched active_fields must not yield a root");
        assert_eq!(err, GloasError::ActiveFieldsWidth { expected: 4, actual: 3 });
        let msg = err.to_string();
        assert!(msg.contains("expected 4"), "{msg}");
        assert!(msg.contains("actual 3"), "{msg}");
    }

    /// `BeaconBlock` SSZ: slot, proposer_index, parent_root, state_root, body offset.
    const BEACON_BLOCK_BODY_OFFSET: usize = 8 + 8 + 32 + 32 + 4;

    fn header_and_body(block_ssz: &[u8]) -> (HeaderFields, &[u8]) {
        assert!(
            block_ssz.len() >= BEACON_BLOCK_BODY_OFFSET,
            "BeaconBlock SSZ shorter than fixed part"
        );
        let offset =
            u32::from_le_bytes(block_ssz[80..84].try_into().expect("body offset")) as usize;
        assert_eq!(offset, BEACON_BLOCK_BODY_OFFSET, "BeaconBlock body offset");
        let header = HeaderFields {
            slot: u64::from_le_bytes(block_ssz[0..8].try_into().expect("slot")),
            proposer_index: u64::from_le_bytes(block_ssz[8..16].try_into().expect("proposer")),
            parent_root: block_ssz[16..48].try_into().expect("parent_root"),
            state_root: block_ssz[48..80].try_into().expect("state_root"),
        };
        (header, &block_ssz[offset..])
    }

    fn header_root(header: &HeaderFields, body_root: Root) -> Root {
        BeaconBlockHeader {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body_root,
        }
        .hash_tree_root(&Sha2Hasher)
    }

    #[test]
    fn test_gloas_body_root() {
        // Standalone BeaconBlockBody vector (5.9), not the nested BeaconBlock body.
        let ssz = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let got = gloas_body_root(&ssz).expect("valid BeaconBlockBody SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let got = gloas_body_root(&ssz).expect("valid BeaconBlockBody SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT));
    }

    #[test]
    fn test_gloas_body_rejects_truncated() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        assert_invalid_body(gloas_body_root(truncated(&ssz)));
        assert_invalid_body(gloas_body_root(&[]));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        assert_invalid_body(gloas_body_root(truncated(&ssz)));
    }

    #[test]
    fn test_gloas_block_root() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (header, body) = header_and_body(&ssz);
        let got = gloas_block_root(&header, body).expect("valid BeaconBlock SSZ");
        assert_eq!(got, parse_root(minimal::SPEC_GLOAS_BEACON_BLOCK_ROOT));
        let body_leaf = gloas_body_root(body).expect("valid nested body SSZ");
        assert_eq!(got, header_root(&header, body_leaf));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (header, body) = header_and_body(&ssz);
        let got = gloas_block_root(&header, body).expect("valid BeaconBlock SSZ");
        assert_eq!(got, parse_root(mainnet::SPEC_GLOAS_BEACON_BLOCK_ROOT));
        let body_leaf = gloas_body_root(body).expect("valid nested body SSZ");
        assert_eq!(got, header_root(&header, body_leaf));
    }

    #[test]
    fn test_gloas_block_rejects_undecodable_body() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (header, body) = header_and_body(&ssz);
        assert_invalid_body(gloas_block_root(&header, truncated(body)));
        assert_invalid_body(gloas_block_root(&header, &[]));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (header, body) = header_and_body(&ssz);
        assert_invalid_body(gloas_block_root(&header, truncated(body)));
    }

    #[test]
    fn test_block_body_decode_rejects_wrong_preset() {
        let ssz = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (_, body) = header_and_body(&ssz);
        assert_invalid_body(gloas_body_root_at::<
            MAX_COMMITTEES_PER_SLOT_MAINNET,
            SYNC_COMMITTEE_SIZE_MAINNET,
            PTC_SIZE_MAINNET,
        >(body));
        let ssz = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_SSZ);
        let (_, body) = header_and_body(&ssz);
        assert_invalid_body(gloas_body_root_at::<
            MAX_COMMITTEES_PER_SLOT_MINIMAL,
            SYNC_COMMITTEE_SIZE_MINIMAL,
            PTC_SIZE_MINIMAL,
        >(body));
    }

    /// `BUILDER_INDEX_SELF_BUILD` is the spec `UINT64_MAX`. Rewriting the bid index
    /// round-trips, and the spec envelope binding is readable.
    #[test]
    fn test_bid_builder_index_and_envelope_binding_round_trip() {
        assert_eq!(super::BUILDER_INDEX_SELF_BUILD, 18_446_744_073_709_551_615);
        let body = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let index = super::gloas_bid_builder_index(&body).expect("spec body");
        let bid = super::gloas_bid_binding(&body).expect("spec bid");
        assert_eq!(bid.builder_index, index);
        let rewritten = super::body_with_bid_builder_index(&body, 1).expect("rewrite to 1");
        assert_eq!(super::gloas_bid_builder_index(&rewritten).expect("external"), 1);
        assert_ne!(rewritten, body);
        let restored =
            super::body_with_bid_builder_index(&rewritten, index).expect("restore spec index");
        assert_eq!(restored, body);
        let moved_bid =
            super::body_with_bid_binding(&body, 1, 2240, [0x11; 32]).expect("rewrite bid");
        let moved_binding = super::gloas_bid_binding(&moved_bid).expect("moved bid");
        assert_eq!(moved_binding.builder_index, 1);
        assert_eq!(moved_binding.slot, 2240);
        assert_eq!(moved_binding.parent_block_root, [0x11; 32]);
        let restored_bid = super::body_with_bid_binding(
            &moved_bid,
            bid.builder_index,
            bid.slot,
            bid.parent_block_root,
        )
        .expect("restore bid");
        assert_eq!(restored_bid, body);
        let self_build = super::body_with_bid_builder_index(&body, super::BUILDER_INDEX_SELF_BUILD)
            .expect("self-build index");
        assert_eq!(
            super::gloas_bid_builder_index(&self_build).expect("self-build"),
            18_446_744_073_709_551_615
        );

        let envelope = parse_hex(minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let binding = super::gloas_envelope_binding(&envelope).expect("spec envelope");
        let moved =
            super::envelope_with_binding(&envelope, 1, [0xee; 32], [0xab; 32]).expect("rewrite");
        let moved_binding = super::gloas_envelope_binding(&moved).expect("moved");
        assert_eq!(moved_binding.builder_index, 1);
        assert_eq!(moved_binding.beacon_block_root, [0xee; 32]);
        assert_eq!(moved_binding.parent_beacon_block_root, [0xab; 32]);
        assert_ne!(moved, envelope);
        let back = super::envelope_with_binding(
            &moved,
            binding.builder_index,
            binding.beacon_block_root,
            binding.parent_beacon_block_root,
        )
        .expect("restore");
        assert_eq!(back, envelope);
        assert_eq!(index, 3_618_015_003_522_193_470, "spec minimal bid is an external builder");
        assert_eq!(binding.builder_index, 3_344_796_263_416_987_794);
        assert_eq!(
            hex_root(&binding.beacon_block_root),
            "b737c1158f923acb223d148567091daf9bb38776404c4c95dadc269893b19ca3"
        );
        assert_ne!(index, super::BUILDER_INDEX_SELF_BUILD);
        assert_ne!(binding.builder_index, index);
    }

    fn hex_root(root: &eth_types::Root) -> String {
        root.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
