//! Progressive merkleization primitives (ADR-007).
//!
//! Sole island call site for `libssz-merkle`'s `merkleize_progressive` and
//! `mix_in_active_fields`.

use libssz::BYTES_PER_CHUNK;
use libssz_merkle::Sha2Hasher;

const _: () = assert!(BYTES_PER_CHUNK == 32);

/// Progressive merkleization of `chunks` (EIP-7916). Empty input is `[0u8; 32]`.
///
/// First production callers land in later island issues; tests in this module
/// are the current consumers.
#[allow(dead_code)]
pub(crate) fn merkleize_progressive(chunks: &[[u8; 32]]) -> [u8; 32] {
    libssz_merkle::merkleize_progressive(&Sha2Hasher, chunks)
}

/// Mix `active_fields` into `root` (EIP-7495).
///
/// Width validation belongs to the caller (`GloasError::ActiveFieldsWidth`, 5.10).
#[allow(dead_code)]
pub(crate) fn mix_in_active_fields(root: [u8; 32], bits: &[bool]) -> [u8; 32] {
    libssz_merkle::mix_in_active_fields(&Sha2Hasher, &root, bits)
}

#[cfg(test)]
mod tests {
    use super::{merkleize_progressive, mix_in_active_fields};
    use crate::spec_kat::{
        SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS, SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS,
        SPEC_PROGRESSIVE_CHUNKS_0, SPEC_PROGRESSIVE_CHUNK_COUNTS, SPEC_PROGRESSIVE_CHUNK_ROOTS,
    };
    use libssz_derive::HashTreeRoot;
    use libssz_merkle::HashTreeRoot as _;
    use libssz_types::ProgressiveList;

    /// First-use of `libssz-derive` / `libssz-types` in this crate (cargo machete).
    #[derive(HashTreeRoot)]
    struct LibsszFamilyTouch {
        n: u64,
        items: ProgressiveList<u64>,
    }

    #[test]
    fn test_libssz_family_is_linked() {
        let touch = LibsszFamilyTouch { n: 0, items: ProgressiveList::new() };
        let _ = touch.hash_tree_root(&libssz_merkle::Sha2Hasher);
    }

    const TWELVE: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
    const WIDTHS: &[u32] = &[3, 4, 5, 13];

    fn parse_root(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let s = core::str::from_utf8(chunk).expect("hex digits are utf8");
            out[i] = u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"));
        }
        out
    }

    /// `chunk_run(N)[i] == i.to_bytes(32, "little")` (issue 3.4a contract).
    fn chunk_run(n: u32) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut chunk = [0u8; 32];
                chunk[..4].copy_from_slice(&i.to_le_bytes());
                chunk
            })
            .collect()
    }

    /// Sample root from the 3.4a/3.4b contract: `(1).to_bytes(32, "little")`.
    fn sample_root() -> [u8; 32] {
        let mut root = [0u8; 32];
        root[0] = 1;
        root
    }

    fn bits_for(width: u32, pattern: &str) -> Vec<bool> {
        match pattern {
            "all_ones" => vec![true; width as usize],
            "sparse_bit0_clear" => {
                let mut bits = vec![true; width as usize];
                bits[0] = false;
                bits
            }
            other => panic!("unknown active-fields pattern {other}"),
        }
    }

    #[test]
    fn test_merkleize_progressive_empty_is_zero_root() {
        assert_eq!(parse_root(SPEC_PROGRESSIVE_CHUNKS_0), [0u8; 32]);
        assert_eq!(merkleize_progressive(&[]), [0u8; 32]);
        assert_eq!(merkleize_progressive(&chunk_run(0)), parse_root(SPEC_PROGRESSIVE_CHUNKS_0));
    }

    #[test]
    fn test_merkleize_progressive_twelve_counts_match_spec_root() {
        assert_eq!(SPEC_PROGRESSIVE_CHUNK_COUNTS, TWELVE);
        assert_eq!(SPEC_PROGRESSIVE_CHUNK_ROOTS.len(), TWELVE.len());
        let mut cases_run = 0usize;
        for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
            let spec = parse_root(hex);
            let got = merkleize_progressive(&chunk_run(*count));
            assert_eq!(
                got, spec,
                "merkleize_progressive(chunk_run({count})) vs SPEC_PROGRESSIVE_*"
            );
            if *count == 0 {
                assert_eq!(got, [0u8; 32], "empty uses SPEC_PROGRESSIVE_CHUNKS_0");
            }
            cases_run += 1;
        }
        assert_eq!(cases_run, 12);
    }

    #[test]
    fn test_mix_in_active_fields_matches_spec_root() {
        assert_eq!(SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS, WIDTHS);
        let mut cases_run = 0usize;
        let mut widths_seen = 0usize;
        for width in WIDTHS {
            let mut all_ones = None;
            let mut sparse = None;
            for (w, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
                if w != width {
                    continue;
                }
                let bits = bits_for(*w, pattern);
                assert_eq!(bits.len(), *width as usize, "width {width} bit count");
                let spec = parse_root(hex);
                let got = mix_in_active_fields(sample_root(), &bits);
                assert_eq!(
                    got, spec,
                    "mix_in_active_fields(sample_root, {width}/{pattern}) vs SPEC_PROGRESSIVE_*"
                );
                match *pattern {
                    "all_ones" => all_ones = Some(got),
                    "sparse_bit0_clear" => sparse = Some(got),
                    other => panic!("unknown active-fields pattern {other}"),
                }
                cases_run += 1;
            }
            let all_ones = all_ones.unwrap_or_else(|| panic!("missing width {width} all_ones"));
            let sparse =
                sparse.unwrap_or_else(|| panic!("missing width {width} sparse_bit0_clear"));
            assert_ne!(
                all_ones, sparse,
                "width {width}: sparse bit-0-clear (LSB) must differ from all-ones SPEC_PROGRESSIVE_*"
            );
            widths_seen += 1;
        }
        assert_eq!(widths_seen, WIDTHS.len());
        assert_eq!(cases_run, WIDTHS.len() * 2);
    }
}
