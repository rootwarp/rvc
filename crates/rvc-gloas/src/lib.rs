//! Gloas progressive SSZ merkleization island.
//!
//! Declares progressively-merkleized Gloas containers and exports roots only.
//! Production path dependency: `{rvc-eth-types}` (primitive aliases only).
//! `eth_types::Root` is used in [`roots`] and is not re-exported.
//!
//! ```compile_fail
//! let _: rvc_gloas::Root = [0u8; 32];
//! ```

/// Pinned `ethereum/consensus-specs` release this island is generated against.
pub const SPEC_TAG: &str = "v1.7.0-beta.0";

/// Gloas `Attestation` EIP-7495 `active_fields` at `SPEC_TAG` (width 4, all-ones).
pub const ACTIVE_FIELDS_ATTESTATION: &[bool] = &[true, true, true, true];

/// Gloas `IndexedAttestation` EIP-7495 `active_fields` at `SPEC_TAG` (width 3, all-ones).
pub const ACTIVE_FIELDS_INDEXED_ATTESTATION: &[bool] = &[true, true, true];

/// Gloas `ExecutionRequests` EIP-7495 `active_fields` at `SPEC_TAG` (width 5, all-ones).
pub const ACTIVE_FIELDS_EXECUTION_REQUESTS: &[bool] = &[true, true, true, true, true];

/// Gloas `PayloadAttestation` EIP-7495 `active_fields` at `SPEC_TAG` (width 3, all-ones).
pub const ACTIVE_FIELDS_PAYLOAD_ATTESTATION: &[bool] = &[true, true, true];

/// Gloas `BeaconBlockBody` EIP-7495 `active_fields` at `SPEC_TAG` (width 13, all-ones).
pub const ACTIVE_FIELDS_BEACON_BLOCK_BODY: &[bool] =
    &[true, true, true, true, true, true, true, true, true, true, true, true, true];

/// Gloas `ExecutionPayloadEnvelope` EIP-7495 `active_fields` at `SPEC_TAG` (width 5, all-ones).
pub const ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE: &[bool] = &[true, true, true, true, true];

const _: () = assert!(ACTIVE_FIELDS_ATTESTATION.len() == 4);
const _: () = assert!(ACTIVE_FIELDS_INDEXED_ATTESTATION.len() == 3);
const _: () = assert!(ACTIVE_FIELDS_EXECUTION_REQUESTS.len() == 5);
const _: () = assert!(ACTIVE_FIELDS_PAYLOAD_ATTESTATION.len() == 3);
const _: () = assert!(ACTIVE_FIELDS_BEACON_BLOCK_BODY.len() == 13);
const _: () = assert!(ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE.len() == 5);

mod containers;
mod error;
mod merkle;
pub mod roots;

pub use error::GloasError;
pub use roots::{
    gloas_aggregate_and_proof_root, gloas_attestation_root, gloas_block_root, gloas_body_root,
    gloas_execution_payload_envelope_root, gloas_indexed_attestation_root, HeaderFields,
};

#[cfg(test)]
mod public_surface_tests {
    #[test]
    fn test_public_api_uses_eth_types() {
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::gloas_attestation_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::gloas_indexed_attestation_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::gloas_aggregate_and_proof_root;
        let _: fn(&crate::HeaderFields, &[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::gloas_block_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> = crate::gloas_body_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::roots::gloas_attestation_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::roots::gloas_indexed_attestation_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::roots::gloas_aggregate_and_proof_root;
        let _: fn(
            &crate::roots::HeaderFields,
            &[u8],
        ) -> Result<eth_types::Root, crate::GloasError> = crate::roots::gloas_block_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::roots::gloas_body_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::gloas_execution_payload_envelope_root;
        let _: fn(&[u8]) -> Result<eth_types::Root, crate::GloasError> =
            crate::roots::gloas_execution_payload_envelope_root;
    }
}

#[cfg(test)]
mod spec_kat;

#[cfg(test)]
mod spec_kat_tests {
    #[test]
    fn test_spec_gloas_sync_aggregate_root() {
        assert_ne!(
            super::spec_kat::minimal::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
            super::spec_kat::mainnet::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
        );
        assert_eq!(super::spec_kat::minimal::SPEC_GLOAS_SYNC_AGGREGATE_ROOT.len(), 64);
        assert_eq!(super::spec_kat::mainnet::SPEC_GLOAS_SYNC_AGGREGATE_ROOT.len(), 64);
    }

    #[test]
    fn test_spec_kat_minimal_and_mainnet_constant_names_match() {
        assert_eq!(
            super::spec_kat::minimal::SPEC_GLOAS_ROOT_NAMES,
            super::spec_kat::mainnet::SPEC_GLOAS_ROOT_NAMES
        );
        assert!(!super::spec_kat::minimal::SPEC_GLOAS_ROOT_NAMES.is_empty());
    }

    #[test]
    fn test_spec_progressive_covers_twelve_counts_and_widths_3_4_5_13() {
        const COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
        const WIDTHS: &[u32] = &[3, 4, 5, 13];
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_CHUNK_COUNTS, COUNTS);
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS, WIDTHS);
        assert_eq!(
            super::spec_kat::minimal::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS,
            super::spec_kat::mainnet::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS
        );
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_CHUNK_ROOTS.len(), COUNTS.len());
        for width in WIDTHS {
            assert!(
                super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                    .iter()
                    .any(|(w, pattern, _)| w == width && *pattern == "all_ones"),
                "missing width {width} all_ones"
            );
            assert!(
                super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                    .iter()
                    .any(|(w, pattern, _)| w == width && *pattern == "sparse_bit0_clear"),
                "missing width {width} sparse_bit0_clear"
            );
        }
    }

    /// Frozen-tag `ACTIVE_FIELDS_*` widths (3/4/5/13 plus envelope 5). A wrong
    /// width or sparse bitvector must name the container and `SPEC_TAG`.
    #[test]
    fn test_active_fields_width_table_at_spec_tag() {
        const FROZEN_TAG: &str = "v1.7.0-beta.0";
        assert_eq!(
            crate::SPEC_TAG, FROZEN_TAG,
            "SPEC_TAG must stay the frozen consensus-specs tag {FROZEN_TAG}; do not invent a new tag"
        );
        assert_eq!(
            super::spec_kat::minimal::SPEC_TAG,
            crate::SPEC_TAG,
            "spec_kat::minimal header SPEC_TAG must equal crate SPEC_TAG {}",
            crate::SPEC_TAG
        );
        assert_eq!(
            super::spec_kat::mainnet::SPEC_TAG,
            crate::SPEC_TAG,
            "spec_kat::mainnet header SPEC_TAG must equal crate SPEC_TAG {}",
            crate::SPEC_TAG
        );

        const TABLE: &[(&str, &[bool], usize)] = &[
            ("Attestation", crate::ACTIVE_FIELDS_ATTESTATION, 4),
            ("IndexedAttestation", crate::ACTIVE_FIELDS_INDEXED_ATTESTATION, 3),
            ("ExecutionRequests", crate::ACTIVE_FIELDS_EXECUTION_REQUESTS, 5),
            ("PayloadAttestation", crate::ACTIVE_FIELDS_PAYLOAD_ATTESTATION, 3),
            ("BeaconBlockBody", crate::ACTIVE_FIELDS_BEACON_BLOCK_BODY, 13),
            ("ExecutionPayloadEnvelope", crate::ACTIVE_FIELDS_EXECUTION_PAYLOAD_ENVELOPE, 5),
        ];
        let prod = include_str!("lib.rs").split("#[cfg(test)]").next().expect("prod lib.rs");
        assert_eq!(
            TABLE.len(),
            prod.matches("pub const ACTIVE_FIELDS_").count(),
            "width table must list every ACTIVE_FIELDS_* const at SPEC_TAG {}",
            crate::SPEC_TAG
        );

        for &(container, bits, expected_width) in TABLE {
            let actual = bits.len();
            assert_eq!(
                actual, expected_width,
                "{container} active_fields width {actual} != {expected_width} at SPEC_TAG {}; \
                 a wrong width changes every root — re-read specs/gloas/beacon-chain.md at this tag, \
                 do not adapt silently",
                crate::SPEC_TAG
            );
            assert!(
                bits.iter().copied().all(|bit| bit),
                "{container} active_fields at SPEC_TAG {} is sparse (non all-ones); \
                 a sparse bitvector changes every root — re-read the frozen tag, do not adapt silently",
                crate::SPEC_TAG
            );
        }
    }
}
