//! L3 signing-root KATs over `rvc_gloas::roots::*` (issue 5.13b).
//!
//! Official `ssz_static` minimal `ssz_random/case_0` bytes live in the island's
//! `spec_kat.rs` (`#[cfg(test)]` there, so this target cannot import them).
//! Reading that checked-in source keeps the test hermetic: no Python, no
//! network, no tarball.

use crypto::{compute_domain, compute_signing_root};
use rvc_gloas::roots::{
    gloas_aggregate_and_proof_root, gloas_block_root, gloas_execution_payload_envelope_root,
    HeaderFields,
};
use rvc_spec_vectors::gloas_signing_kat::{
    KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT, KAT_GLOAS_BLOCK_SIGNING_ROOT,
    KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT,
};

/// Same argv as 5.13a `gloas_signing_kat` provenance (`0x07000001`, zero GVR).
const GLOAS_FORK_VERSION: [u8; 4] = [0x07, 0x00, 0x00, 0x01];
const GVR: [u8; 32] = [0u8; 32];

/// Spec `DomainType` bytes (little-endian), matching `signing_roots.yaml`.
const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const DOMAIN_AGGREGATE_AND_PROOF: [u8; 4] = [0x06, 0x00, 0x00, 0x00];
const DOMAIN_BEACON_BUILDER: [u8; 4] = [0x0B, 0x00, 0x00, 0x00];

/// `BeaconBlock` SSZ: slot, proposer_index, parent_root, state_root, body offset.
const BEACON_BLOCK_BODY_OFFSET: usize = 8 + 8 + 32 + 32 + 4;

const ISLAND_SPEC_KAT: &str = include_str!("../../rvc-gloas/src/spec_kat.rs");

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

fn parse_root(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "KAT hex must be 64 chars, got {} ({hex:?})", hex.len());
    parse_hex(hex).try_into().expect("64 hex chars decode to 32 bytes")
}

fn header_and_body(block_ssz: &[u8]) -> (HeaderFields, &[u8]) {
    assert!(block_ssz.len() >= BEACON_BLOCK_BODY_OFFSET, "BeaconBlock SSZ shorter than fixed part");
    let offset = u32::from_le_bytes(block_ssz[80..84].try_into().expect("body offset")) as usize;
    assert_eq!(offset, BEACON_BLOCK_BODY_OFFSET, "BeaconBlock body offset");
    let header = HeaderFields {
        slot: u64::from_le_bytes(block_ssz[0..8].try_into().expect("slot")),
        proposer_index: u64::from_le_bytes(block_ssz[8..16].try_into().expect("proposer")),
        parent_root: block_ssz[16..48].try_into().expect("parent_root"),
        state_root: block_ssz[48..80].try_into().expect("state_root"),
    };
    (header, &block_ssz[offset..])
}

fn minimal_ssz(const_name: &str) -> Vec<u8> {
    let start = ISLAND_SPEC_KAT.find("pub mod minimal").expect("pub mod minimal");
    let rest = &ISLAND_SPEC_KAT[start..];
    let end = rest.find("pub mod mainnet").expect("pub mod mainnet");
    let minimal = &rest[..end];
    let needle = format!("pub const {const_name}");
    let at = minimal.find(&needle).unwrap_or_else(|| panic!("missing {const_name} in minimal"));
    let after = &minimal[at + needle.len()..];
    let concat_at = after.find("concat!(").unwrap_or_else(|| panic!("{const_name} is not concat!"));
    let body = &after[concat_at + "concat!(".len()..];
    let term = body.find(");").expect("concat terminator");
    let mut hex = String::new();
    for line in body[..term].lines() {
        let t = line.trim().trim_end_matches(',').trim();
        if let Some(s) = t.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            hex.push_str(s);
        }
    }
    assert!(!hex.is_empty(), "{const_name} concat yielded no hex");
    parse_hex(&hex)
}

fn signing_root_of(object_root: [u8; 32], domain_type: [u8; 4]) -> [u8; 32] {
    let domain = compute_domain(domain_type, GLOAS_FORK_VERSION, GVR);
    compute_signing_root(&object_root, domain)
}

#[test]
fn test_gloas_block_signing_root() {
    let ssz = minimal_ssz("SPEC_GLOAS_BEACON_BLOCK_SSZ");
    let (header, body) = header_and_body(&ssz);
    let object_root = gloas_block_root(&header, body).expect("valid BeaconBlock SSZ");
    assert_eq!(
        signing_root_of(object_root, DOMAIN_BEACON_PROPOSER),
        parse_root(KAT_GLOAS_BLOCK_SIGNING_ROOT)
    );
}

#[test]
fn test_gloas_aggregate_and_proof_signing_root() {
    let ssz = minimal_ssz("SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ");
    let object_root = gloas_aggregate_and_proof_root(&ssz).expect("valid AggregateAndProof SSZ");
    assert_eq!(
        signing_root_of(object_root, DOMAIN_AGGREGATE_AND_PROOF),
        parse_root(KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT)
    );
}

#[test]
fn test_gloas_execution_payload_envelope_signing_root() {
    let ssz = minimal_ssz("SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ");
    let object_root =
        gloas_execution_payload_envelope_root(&ssz).expect("valid ExecutionPayloadEnvelope SSZ");
    assert_eq!(
        signing_root_of(object_root, DOMAIN_BEACON_BUILDER),
        parse_root(KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT)
    );
}
