//! Compile-level public-surface lock.
//!
//! Implemented `roots::*`: `gloas_attestation_root`, `gloas_indexed_attestation_root`,
//! `gloas_aggregate_and_proof_root`, `gloas_block_root`, `gloas_body_root`, `HeaderFields`,
//! `gloas_execution_payload_envelope_root`.

#[test]
fn test_public_surface_implemented_root_fns() {
    // `eth_types::Root` is `[u8; 32]` and is used, not re-exported (`rvc_gloas::Root` does not exist).
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> = rvc_gloas::gloas_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::gloas_indexed_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::gloas_aggregate_and_proof_root;
    let _: fn(&rvc_gloas::HeaderFields, &[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::gloas_block_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> = rvc_gloas::gloas_body_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_indexed_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_aggregate_and_proof_root;
    let _: fn(&rvc_gloas::roots::HeaderFields, &[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_block_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> = rvc_gloas::roots::gloas_body_root;
    let _ = rvc_gloas::HeaderFields {
        slot: 0,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
    };
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::gloas_execution_payload_envelope_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_execution_payload_envelope_root;

    let _ = rvc_gloas::SPEC_TAG;
    let _ = rvc_gloas::ACTIVE_FIELDS_ATTESTATION;
    let _ = rvc_gloas::ACTIVE_FIELDS_INDEXED_ATTESTATION;
    let _ = rvc_gloas::ACTIVE_FIELDS_EXECUTION_REQUESTS;
    let _ = rvc_gloas::ACTIVE_FIELDS_PAYLOAD_ATTESTATION;
    let _ = rvc_gloas::ACTIVE_FIELDS_BEACON_BLOCK_BODY;
    let _ = rvc_gloas::ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE;
    let _ = rvc_gloas::GloasError::InvalidBody { reason: "surface".into() };
}

#[test]
fn test_kat_gloas_constants_are_feature_gated() {
    let src = include_str!("../src/lib.rs");
    let needle = "pub use test_fixtures::{";
    let at = src.find(needle).expect("crate-root re-export of test_fixtures");
    let prev = src[..at]
        .trim_end()
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("cfg attribute on crate-root re-export");
    assert_eq!(
        prev.trim(),
        "#[cfg(feature = \"test-fixtures\")]",
        "crate-root KAT re-export must be immediately cfg-gated, got {prev:?}"
    );
    assert!(
        src[at..].contains("KAT_GLOAS_BLOCK_SIGNING_ROOT"),
        "crate-root re-export must name KAT_GLOAS_BLOCK_SIGNING_ROOT"
    );
    assert!(
        !src.contains("\npub const KAT_GLOAS"),
        "ungated crate-root pub const KAT_GLOAS_* is forbidden"
    );
}

#[test]
fn test_crate_does_not_reexport_eth_types() {
    for src in [
        include_str!("../src/lib.rs"),
        include_str!("../src/roots.rs"),
        include_str!("../src/error.rs"),
    ] {
        assert!(!src.contains("pub use eth_types"), "do not re-export eth-types items");
        assert!(!src.contains("pub type Root"), "do not alias-export Root");
    }
}
