//! P5 L3 signing-root KATs. Re-exported under `test-fixtures` (issue 6.8).
//!
//! Hex matches `rvc-spec-vectors` `gloas_signing_kat` at consensus-specs
//! `v1.7.0-beta.0` (`--fork-version 0x07000001`, zero GVR). Defined here so
//! `rvc-gloas` production out-edges stay `{rvc-eth-types}`.

/// BeaconBlock signing root under `DOMAIN_BEACON_PROPOSER`.
pub const KAT_GLOAS_BLOCK_SIGNING_ROOT: &str =
    "cb806d0b3ff015d77bc5b320e8066894e37ec38be25f5acb178b65bad3250dc3";

/// AggregateAndProof signing root under `DOMAIN_AGGREGATE_AND_PROOF`.
pub const KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT: &str =
    "acf89a4bea5c3f4e5c7510f7511021a4f72f2bb42615b77c6824d058c9887d14";

/// ExecutionPayloadEnvelope signing root under `DOMAIN_BEACON_BUILDER`.
pub const KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT: &str =
    "b6969df7b86e2b5652a3dfc7f4eeeb4d73cf5bbbd484b819b8555735d83fc1f0";

/// AttestationData signing root (index = 1) under `DOMAIN_BEACON_ATTESTER`.
pub const KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT: &str =
    "e58076702842f323afe7a32e0bb5806bed43ec3de1b985c5e2f5b0bf6f60d849";
