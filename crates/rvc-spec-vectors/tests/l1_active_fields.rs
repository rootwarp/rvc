//! L1 gate (b): `mix_in_active_fields` + LSB-first `pack_bits` (issue 3.8 / #236).
//!
//! `SPEC_PROGRESSIVE_*` assertions are implementation-agnostic and stay green.
//! The libssz comparison is the falsifiable ADR-001 half.

use libssz_merkle::{mix_in_active_fields, Sha2Hasher};
use rvc_spec_vectors::spec_kat::{
    SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES,
    SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR, SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES,
    SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR, SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES,
    SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR, SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS,
    SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS,
};
use sha2::{Digest, Sha256};

type Node = [u8; 32];

const WIDTHS: &[u32] = &[3, 4, 13];
const CASE_COUNT: usize = 6;

/// Sample root from the 3.4a/3.4b contract: `(1).to_bytes(32, "little")`.
fn sample_root() -> Node {
    let mut root = [0u8; 32];
    root[0] = 1;
    root
}

fn parse_root(hex: &str) -> Node {
    assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
    assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("hex digits are utf8");
        out[i] = u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"));
    }
    out
}

fn hash_nodes(a: &Node, b: &Node) -> Node {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    Sha256::digest(buf).into()
}

/// EIP-7495 / SSZ `pack_bits`: bit 0 is the LSB of byte 0, zero-padded to one 32-byte chunk.
fn pack_bits(bits: &[bool]) -> Node {
    let mut out = [0u8; 32];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Wrong packing: reverse bit order within the width (MSB-first).
fn pack_bits_msb(bits: &[bool]) -> Node {
    let n = bits.len();
    let mut out = [0u8; 32];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            let j = n - 1 - i;
            out[j / 8] |= 1 << (j % 8);
        }
    }
    out
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

/// `mix_in_active_fields(root, bits) = hash_nodes(root, pack_bits(bits))` (EIP-7495).
fn mix_in_eip(bits: &[bool]) -> Node {
    hash_nodes(&sample_root(), &pack_bits(bits))
}

fn assert_lsb_lead_bytes(width: u32, pattern: &str, packed: &Node) {
    let lead: &[u8] = match (width, pattern) {
        (3, "all_ones") => &[0x07],
        (3, "sparse_bit0_clear") => &[0x06],
        (4, "all_ones") => &[0x0F],
        (4, "sparse_bit0_clear") => &[0x0E],
        (13, "all_ones") => &[0xFF, 0x1F],
        (13, "sparse_bit0_clear") => &[0xFE, 0x1F],
        other => panic!("unpinned pack_bits case {other:?}"),
    };
    assert_eq!(&packed[..lead.len()], lead, "width {width} {pattern} LSB-first lead bytes");
    assert!(
        packed[lead.len()..].iter().all(|b| *b == 0),
        "width {width} {pattern} must be zero-padded"
    );
}

#[test]
fn test_active_field_case_count_is_nonzero() {
    assert_eq!(SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS, WIDTHS);
    assert_eq!(SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS.len(), CASE_COUNT);
    assert!(!SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS.is_empty());
}

#[test]
fn test_pack_bits_lsb_mixin_matches_spec_root() {
    let mut cases_run = 0usize;
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        let bits = bits_for(*width, pattern);
        assert_eq!(bits.len(), *width as usize, "width {width} bit count");
        let packed = pack_bits(&bits);
        assert_lsb_lead_bytes(*width, pattern, &packed);
        let spec = parse_root(hex);
        assert_eq!(
            hash_nodes(&sample_root(), &packed),
            spec,
            "hash_nodes(sample_root, pack_bits({width}/{pattern})) vs SPEC_PROGRESSIVE_*"
        );
        cases_run += 1;
    }
    assert_eq!(cases_run, CASE_COUNT);
}

#[test]
fn test_sparse_vs_all_ones_produce_different_spec_root() {
    let pairs = [
        (
            3,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR,
        ),
        (
            4,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR,
        ),
        (
            13,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES,
            SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR,
        ),
    ];
    let mut cases_run = 0usize;
    for (width, all_hex, sparse_hex) in pairs {
        let all_root = parse_root(all_hex);
        let sparse_root = parse_root(sparse_hex);
        assert_ne!(
            all_root, sparse_root,
            "width {width}: sparse bit-0-clear must differ from all-ones SPEC_PROGRESSIVE_*"
        );
        assert_eq!(mix_in_eip(&bits_for(width, "all_ones")), all_root);
        assert_eq!(mix_in_eip(&bits_for(width, "sparse_bit0_clear")), sparse_root);
        cases_run += 1;
    }
    assert_eq!(cases_run, WIDTHS.len());
}

#[test]
fn test_lsb_vs_msb_pack_bits_distinguishable_root() {
    let mut cases_run = 0usize;
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        if *pattern != "sparse_bit0_clear" {
            continue;
        }
        let bits = bits_for(*width, pattern);
        let spec = parse_root(hex);
        let lsb = pack_bits(&bits);
        let msb = pack_bits_msb(&bits);
        assert_ne!(
            lsb, msb,
            "width {width} bit-0-clear: LSB-first packing must differ from MSB-first"
        );
        assert_eq!(
            hash_nodes(&sample_root(), &lsb),
            spec,
            "width {width}: LSB-first mix-in vs SPEC_PROGRESSIVE_*"
        );
        assert_ne!(
            hash_nodes(&sample_root(), &msb),
            spec,
            "width {width}: MSB-first mix-in must not match SPEC_PROGRESSIVE_*"
        );
        cases_run += 1;
    }
    assert_eq!(cases_run, WIDTHS.len());
}

#[test]
fn test_mix_in_active_fields_equals_hash_nodes_pack_bits_root() {
    let mut cases_run = 0usize;
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        let bits = bits_for(*width, pattern);
        let spec = parse_root(hex);
        let via_hash = hash_nodes(&sample_root(), &pack_bits(&bits));
        assert_eq!(
            via_hash, spec,
            "hash_nodes(root, pack_bits({width}/{pattern})) vs SPEC_PROGRESSIVE_*"
        );
        assert_eq!(mix_in_eip(&bits), via_hash);
        cases_run += 1;
    }
    assert_eq!(cases_run, CASE_COUNT);
}

#[test]
fn test_libssz_mix_in_active_fields_matches_spec_root() {
    let mut cases_run = 0usize;
    let mut records = Vec::new();
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        let bits = bits_for(*width, pattern);
        let spec = parse_root(hex);
        let via_hash = hash_nodes(&sample_root(), &pack_bits(&bits));
        let got = mix_in_active_fields(&Sha2Hasher, &sample_root(), &bits);
        records.push((*width, *pattern, hex::encode(got), *hex, got == spec, got == via_hash));
        cases_run += 1;
    }
    assert_eq!(cases_run, CASE_COUNT);
    let diffs: Vec<String> = records
        .iter()
        .filter(|(_, _, _, _, vs_spec, vs_hash)| !(*vs_spec && *vs_hash))
        .map(|(width, pattern, got, spec, vs_spec, vs_hash)| {
            format!(
                "width={width} pattern={pattern} libssz={got} spec={spec} vs_spec={vs_spec} vs_hash_nodes_pack_bits={vs_hash}"
            )
        })
        .collect();
    assert!(
        diffs.is_empty(),
        "libssz-merkle 0.3.0 mix_in_active_fields vs hash_nodes(root, pack_bits) / SPEC_PROGRESSIVE_*:\n{}",
        diffs.join("\n")
    );
}
