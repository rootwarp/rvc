//! L1 gate (a): `merkleize_progressive` at the twelve chunk counts (issue 3.7 / #235).
//!
//! `SPEC_PROGRESSIVE_*` assertions are implementation-agnostic and stay green.
//! The libssz comparison is the falsifiable ADR-001 half.

use libssz_merkle::{merkleize_progressive, Sha2Hasher};
use rvc_spec_vectors::spec_kat::{
    SPEC_PROGRESSIVE_CHUNKS_0, SPEC_PROGRESSIVE_CHUNKS_2, SPEC_PROGRESSIVE_CHUNKS_22,
    SPEC_PROGRESSIVE_CHUNKS_6, SPEC_PROGRESSIVE_CHUNKS_86, SPEC_PROGRESSIVE_CHUNK_COUNTS,
    SPEC_PROGRESSIVE_CHUNK_ROOTS,
};
use sha2::{Digest, Sha256};

type Node = [u8; 32];

const TWELVE: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
const LEVEL_WIDTHS: &[usize] = &[1, 4, 16, 64];
const PADDING_CASES: &[(u32, &str)] = &[
    (2, SPEC_PROGRESSIVE_CHUNKS_2),
    (6, SPEC_PROGRESSIVE_CHUNKS_6),
    (22, SPEC_PROGRESSIVE_CHUNKS_22),
    (86, SPEC_PROGRESSIVE_CHUNKS_86),
];

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

/// `chunk_run(N)[i] == i.to_bytes(32, "little")` (issue 3.4a contract).
fn chunk_run(n: u32) -> Vec<Node> {
    (0..n)
        .map(|i| {
            let mut chunk = [0u8; 32];
            chunk[..4].copy_from_slice(&i.to_le_bytes());
            chunk
        })
        .collect()
}

fn hash_nodes(a: &Node, b: &Node) -> Node {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    Sha256::digest(buf).into()
}

/// EIP-7916 `merkleize(chunks, limit)` with fully materialized zero padding.
fn merkleize(chunks: &[Node], limit: usize) -> Node {
    assert!(chunks.len() <= limit, "chunk count {} exceeds limit {limit}", chunks.len());
    if limit == 0 {
        return [0u8; 32];
    }
    let size = limit.next_power_of_two();
    let mut layer = vec![[0u8; 32]; size];
    layer[..chunks.len()].copy_from_slice(chunks);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|pair| hash_nodes(&pair[0], &pair[1])).collect();
    }
    layer[0]
}

/// EIP-7916 `merkleize_progressive`: left subtree padded to `num_leaves`.
fn merkleize_progressive_eip(chunks: &[Node], num_leaves: usize) -> Node {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let take = num_leaves.min(chunks.len());
    let left = merkleize(&chunks[..take], num_leaves);
    let right = merkleize_progressive_eip(&chunks[take..], num_leaves * 4);
    hash_nodes(&left, &right)
}

/// Wrong padding: pad the partial left subtree to `next_pow2(len(remaining))`.
fn merkleize_progressive_next_pow2_remaining(chunks: &[Node], num_leaves: usize) -> Node {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let take = num_leaves.min(chunks.len());
    let remaining = &chunks[..take];
    let limit = remaining.len().next_power_of_two();
    let left = merkleize(remaining, limit);
    let right = merkleize_progressive_next_pow2_remaining(&chunks[take..], num_leaves * 4);
    hash_nodes(&left, &right)
}

#[test]
fn test_empty_input_is_zero_root() {
    assert_eq!(parse_root(SPEC_PROGRESSIVE_CHUNKS_0), [0u8; 32]);
    assert_eq!(merkleize_progressive_eip(&[], 1), [0u8; 32]);
}

#[test]
fn test_twelve_chunk_counts_match_spec_root() {
    assert_eq!(SPEC_PROGRESSIVE_CHUNK_COUNTS, TWELVE);
    let mut cases_run = 0usize;
    for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
        let spec = parse_root(hex);
        let eip = merkleize_progressive_eip(&chunk_run(*count), 1);
        assert_eq!(eip, spec, "EIP-7916 merkleize_progressive(chunk_run({count})) vs SPEC");
        cases_run += 1;
    }
    assert_eq!(cases_run, 12);
}

#[test]
fn test_left_subtree_padding_differs_from_next_pow2_root() {
    for (count, hex) in PADDING_CASES {
        let spec = parse_root(hex);
        let chunks = chunk_run(*count);
        let eip = merkleize_progressive_eip(&chunks, 1);
        let wrong = merkleize_progressive_next_pow2_remaining(&chunks, 1);
        assert_eq!(eip, spec, "count {count} EIP left-subtree padding vs SPEC_PROGRESSIVE_*");
        assert_ne!(
            wrong, spec,
            "count {count}: next_pow2(remaining) padding must differ from SPEC_PROGRESSIVE_*"
        );
    }
}

#[test]
fn test_x4_growth_subtree_is_left_child_root() {
    for pair in LEVEL_WIDTHS.windows(2) {
        assert_eq!(pair[1], pair[0] * 4, "level widths grow ×4");
    }
    let mut cases_run = 0usize;
    for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
        let spec = parse_root(hex);
        let chunks = chunk_run(*count);
        if chunks.is_empty() {
            assert_eq!(spec, [0u8; 32], "empty uses SPEC_PROGRESSIVE_CHUNKS_0");
        } else {
            let take = 1.min(chunks.len());
            let left = merkleize(&chunks[..take], 1);
            let right = merkleize_progressive_eip(&chunks[take..], 4);
            assert_eq!(
                hash_nodes(&left, &right),
                spec,
                "count {count}: subtree is the left child (SPEC_PROGRESSIVE_*)"
            );
        }
        cases_run += 1;
    }
    assert_eq!(cases_run, 12);
}

#[test]
fn test_libssz_merkleize_progressive_matches_spec_root() {
    let mut cases_run = 0usize;
    let mut records = Vec::new();
    for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
        let got = merkleize_progressive(&Sha2Hasher, &chunk_run(*count));
        let spec = parse_root(hex);
        records.push((*count, hex::encode(got), *hex, got == spec));
        cases_run += 1;
    }
    assert_eq!(cases_run, 12);
    let diffs: Vec<String> = records
        .iter()
        .filter(|(_, _, _, ok)| !*ok)
        .map(|(count, got, spec, _)| format!("count={count} libssz={got} spec={spec}"))
        .collect();
    assert!(
        diffs.is_empty(),
        "libssz-merkle 0.3.0 merkleize_progressive vs SPEC_PROGRESSIVE_*:\n{}",
        diffs.join("\n")
    );
}
