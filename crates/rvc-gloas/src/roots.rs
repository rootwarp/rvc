//! Attestation-side Gloas container roots over SSZ bytes.
//!
//! [`gloas_attestation_root`], [`gloas_indexed_attestation_root`],
//! [`gloas_aggregate_and_proof_root`]. Island types stay crate-private.
//! `eth_types::Root` (`[u8; 32]`) is used, not re-exported.

use eth_types::Root;
use libssz::SszDecode;
use libssz_merkle::{HashTreeRoot, Sha2Hasher};

use crate::containers::attestation::{AggregateAndProof, Attestation, IndexedAttestation};
use crate::error::GloasError;

/// Official `MAX_COMMITTEES_PER_SLOT` values. `committee_bits` is `Bitvector[N]`;
/// SSZ `fixed_part_len` differs, so a payload decodes at exactly one N.
const MAX_COMMITTEES_PER_SLOT_MINIMAL: usize = 4;
const MAX_COMMITTEES_PER_SLOT_MAINNET: usize = 64;
const _: () =
    assert!(MAX_COMMITTEES_PER_SLOT_MAINNET == eth_types::MAX_COMMITTEES_PER_SLOT as usize);

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

#[cfg(test)]
mod tests {
    use super::{
        decode_root, gloas_aggregate_and_proof_root, gloas_attestation_root,
        gloas_indexed_attestation_root, AggregateAndProof, Attestation,
        MAX_COMMITTEES_PER_SLOT_MAINNET, MAX_COMMITTEES_PER_SLOT_MINIMAL,
    };
    use crate::error::GloasError;
    use crate::spec_kat::{mainnet, minimal};
    use eth_types::Root;

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        assert_eq!(hex.len() % 2, 0, "SPEC_* hex must have even length, got {}", hex.len());
        hex.as_bytes()
            .chunks_exact(2)
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
}
