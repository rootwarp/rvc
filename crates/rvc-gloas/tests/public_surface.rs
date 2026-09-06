//! Compile-level public-surface lock.
//!
//! Implemented `roots::*`: `gloas_attestation_root`, `gloas_indexed_attestation_root`,
//! `gloas_aggregate_and_proof_root`, `gloas_block_root`, `HeaderFields`,
//! `gloas_execution_payload_envelope_root`.
//! Closed set also includes `gloas_body_root` (5.11b, not exported).

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
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_indexed_attestation_root;
    let _: fn(&[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_aggregate_and_proof_root;
    let _: fn(&rvc_gloas::roots::HeaderFields, &[u8]) -> Result<[u8; 32], rvc_gloas::GloasError> =
        rvc_gloas::roots::gloas_block_root;
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
