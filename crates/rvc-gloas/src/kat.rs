//! P5 L3 signing-root KATs. Re-exported under `test-fixtures` (issue 6.8).
//!
//! Hex matches `rvc-spec-vectors` `gloas_signing_kat` at consensus-specs
//! `v1.7.0-beta.2` (`--fork-version 0x07000001`, zero GVR). Defined here so
//! `rvc-gloas` production out-edges stay `{rvc-eth-types}`.

/// BeaconBlock signing root under `DOMAIN_BEACON_PROPOSER`.
pub const KAT_GLOAS_BLOCK_SIGNING_ROOT: &str =
    "40f71e572549ec0853899d6d7ecd2b78384c24de492863f1af8f5cd523037d74";

/// AggregateAndProof signing root under `DOMAIN_AGGREGATE_AND_PROOF`.
pub const KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT: &str =
    "acf89a4bea5c3f4e5c7510f7511021a4f72f2bb42615b77c6824d058c9887d14";

/// ExecutionPayloadEnvelope signing root under `DOMAIN_BEACON_BUILDER`.
pub const KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT: &str =
    "b6969df7b86e2b5652a3dfc7f4eeeb4d73cf5bbbd484b819b8555735d83fc1f0";

/// AttestationData signing root (index = 1) under `DOMAIN_BEACON_ATTESTER`.
pub const KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT: &str =
    "e58076702842f323afe7a32e0bb5806bed43ec3de1b985c5e2f5b0bf6f60d849";

/// Self-build body root for the canonical fixture.
///
/// `scripts/gen_gloas_fixture_roots.py` (eth-ssz-specs==0.1.0, consensus-specs
/// `v1.7.0-beta.2`, minimal preset). Unmodified spec body matches
/// [`crate::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT`], then the bid is
/// rewritten: `builder_index = u64::MAX`, slot 2240, parent `0x01` × 32.
pub const KAT_GLOAS_SELF_BUILD_BODY_ROOT: &str =
    "e1b050b616d54250c5f77165bbef24fc7b45b8a912832458fc2cc7415fd97ab7";

/// BeaconBlock root of that self-build body.
///
/// Header: slot 2240, proposer 42, parent `0x01` × 32, state `0x02` × 32.
/// Same generator and spec pin as [`KAT_GLOAS_SELF_BUILD_BODY_ROOT`].
pub const KAT_GLOAS_SELF_BUILD_BLOCK_ROOT: &str =
    "e01735c32b603e2bf8a176368ffde9d573c84ee69e4e9539ccd8a6d054f2d5ae";

/// Execution-payload envelope bound to that block.
///
/// Spec envelope rewritten to `builder_index = u64::MAX`, `beacon_block_root` =
/// [`KAT_GLOAS_SELF_BUILD_BLOCK_ROOT`], `parent_beacon_block_root` = `0x01` × 32.
/// Same generator and spec pin as [`KAT_GLOAS_SELF_BUILD_BODY_ROOT`].
pub const KAT_GLOAS_BOUND_ENVELOPE_ROOT: &str =
    "da12da62506671f97eda440bff3dbc95bbc828d7789f381411e4a3b78d7f7257";

#[cfg(test)]
mod self_build_kat {
    use super::{
        KAT_GLOAS_BOUND_ENVELOPE_ROOT, KAT_GLOAS_SELF_BUILD_BLOCK_ROOT,
        KAT_GLOAS_SELF_BUILD_BODY_ROOT,
    };

    const SLOT: u64 = 2240;
    const PROPOSER: u64 = 42;

    fn decode_hex(hex_str: &str) -> Vec<u8> {
        assert_eq!(hex_str.len() % 2, 0, "hex length");
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn encode_root(root: eth_types::Root) -> String {
        root.iter().fold(String::with_capacity(64), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
    }

    fn self_build_body() -> Vec<u8> {
        let spec = decode_hex(crate::spec_kat::minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        crate::body_with_bid_binding(&spec, crate::BUILDER_INDEX_SELF_BUILD, SLOT, [0x01; 32])
            .expect("spec body accepts a self-build binding")
    }

    #[test]
    fn test_gloas_self_build_body_root() {
        let root = crate::gloas_body_root(&self_build_body()).expect("body root");
        assert_eq!(encode_root(root), KAT_GLOAS_SELF_BUILD_BODY_ROOT);
    }

    #[test]
    fn test_gloas_self_build_block_root() {
        let root = crate::gloas_block_root(
            &crate::HeaderFields {
                slot: SLOT,
                proposer_index: PROPOSER,
                parent_root: [0x01; 32],
                state_root: [0x02; 32],
            },
            &self_build_body(),
        )
        .expect("block root");
        assert_eq!(encode_root(root), KAT_GLOAS_SELF_BUILD_BLOCK_ROOT);
    }

    #[test]
    fn test_gloas_bound_envelope_root() {
        let block_root = decode_hex(KAT_GLOAS_SELF_BUILD_BLOCK_ROOT);
        let block_root: eth_types::Root = block_root.try_into().expect("32 bytes");
        let spec = decode_hex(crate::spec_kat::minimal::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
        let bound = crate::envelope_with_binding(
            &spec,
            crate::BUILDER_INDEX_SELF_BUILD,
            block_root,
            [0x01; 32],
        )
        .expect("spec envelope accepts a binding");
        let root = crate::gloas_execution_payload_envelope_root(&bound).expect("envelope root");
        assert_eq!(encode_root(root), KAT_GLOAS_BOUND_ENVELOPE_ROOT);
    }
}
