//! Generated Gloas island L3 signing-root KATs. Do not edit by hand.
//!
//! Regenerate with `make spec-kat`.
//!
//! # Provenance
//!
//! provenance-source: ethereum/consensus-specs@v1.7.0-beta.2 ethereum/ssz-specs@v0.1.0
//! provenance-pyspec-revision: ethereum/consensus-specs@v1.7.0-beta.2
//! provenance-eth-ssz-specs: eth-ssz-specs==0.1.0
//! provenance-python: 3.13.7
//! provenance-argv: --out crates/rvc-spec-vectors/vectors-generated/gloas-signing-roots/signing_roots.yaml --gloas-out crates/rvc-spec-vectors/vectors-generated/gloas-signing-roots/signing_roots.yaml --fork-version 0x07000001 --genesis-validators-root 0x0000000000000000000000000000000000000000000000000000000000000000 --spec-tag v1.7.0-beta.2
//! provenance-generated: id=gloas-signing-roots sha256=4793b7ec18ad4040af55bb49a5f8929c1ea9aa3c8eb7f29065417eeb76567803
//! provenance-generator: gen-spec-kat 0.7.0
//! provenance-date: 2026-09-29
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/gloas-signing-roots/signing_roots.yaml sha256:4793b7ec18ad4040af55bb49a5f8929c1ea9aa3c8eb7f29065417eeb76567803
//! provenance-input-spec: phase0+gloas beacon-chain.md sha256:e70936c2b4b0ef8e1986ca7507d3ac13746d456f4cebe6aca4ed8a403ba134fe
//! provenance-fork-version: 0x07000001
//! provenance-genesis-validators-root: 0x0000000000000000000000000000000000000000000000000000000000000000

/// BeaconBlock signing root under DOMAIN_BEACON_PROPOSER, copied from the pyspec artifact.
pub const KAT_GLOAS_BLOCK_SIGNING_ROOT: &str =
    "40f71e572549ec0853899d6d7ecd2b78384c24de492863f1af8f5cd523037d74";

/// AggregateAndProof signing root under DOMAIN_AGGREGATE_AND_PROOF, copied from the pyspec artifact.
pub const KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT: &str =
    "acf89a4bea5c3f4e5c7510f7511021a4f72f2bb42615b77c6824d058c9887d14";

/// ExecutionPayloadEnvelope signing root under DOMAIN_BEACON_BUILDER, copied from the pyspec artifact.
pub const KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT: &str =
    "b6969df7b86e2b5652a3dfc7f4eeeb4d73cf5bbbd484b819b8555735d83fc1f0";

/// AttestationData signing root (index = 1) under DOMAIN_BEACON_ATTESTER, copied from the pyspec artifact.
pub const KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT: &str =
    "e58076702842f323afe7a32e0bb5806bed43ec3de1b985c5e2f5b0bf6f60d849";

/// BeaconBlock signing root with argv --fork-version last byte xor 1 (not a KAT).
pub const GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS: &str =
    "3566b3d65b8ebab4b6fa07d1754fb3fb09e8115c9170334aeeb96e63cb91f2cc";
