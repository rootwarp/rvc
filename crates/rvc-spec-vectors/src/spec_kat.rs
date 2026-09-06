//! Generated KAT constants. Do not edit by hand.
//!
//! Regenerate with `make spec-kat`.
//!
//! # Provenance
//!
//! provenance-source: ethereum/consensus-specs@v1.7.0-beta.0 ethereum/ssz-specs@v0.1.0
//! provenance-generated: id=progressive sha256=af96bc7dcab81b76427d50bec50944ec72eda3d33ce8426bf8569acebc6bd97f
//! provenance-generated: id=signing-roots sha256=864ff5176a0b83e9b3e12e2bc03688e32def59e39cbde8816be4a0b15d7962eb
//! provenance-generator: gen-spec-kat 0.7.0
//! provenance-date: 2026-09-06
//! provenance-input: crates/rvc-spec-vectors/tests/fixtures/tests/minimal/electra/ssz_static/AttestationData/ssz_random/case_0/roots.yaml sha256:4fd39bfafadb40d3fca6a6b77e712d1535a0df2fee7ed2d58607cb518a655c22
//! provenance-input: crates/rvc-spec-vectors/tests/fixtures/tests/minimal/electra/ssz_static/AttestationData/ssz_random/case_0/serialized.ssz_snappy sha256:cac01c86ff78e57ad395c9e3bf0d0dfbb3dd41640a009b2a0cb8dc95509b3b51
//! provenance-input: crates/rvc-spec-vectors/tests/fixtures/tests/minimal/electra/ssz_static/AttestationData/ssz_random/case_1/roots.yaml sha256:64150d0e41e95c1a47bf3e67cc36ff1cfb48077e05d6e3ed3e18f814d85a0a72
//! provenance-input: crates/rvc-spec-vectors/tests/fixtures/tests/minimal/electra/ssz_static/AttestationData/ssz_random/case_1/serialized.ssz_snappy sha256:b9db39ec6d2d1add2c11d9ee7c24e98fd88ee3db80c81a0b2417416fabb2f608
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/progressive/roots.yaml sha256:af96bc7dcab81b76427d50bec50944ec72eda3d33ce8426bf8569acebc6bd97f
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/signing-roots/signing_roots.yaml sha256:864ff5176a0b83e9b3e12e2bc03688e32def59e39cbde8816be4a0b15d7962eb

/// Chunk counts from eth-ssz-specs `PROGRESSIVE_CHUNK_COUNTS` (issue 3.4a).
pub const SPEC_PROGRESSIVE_CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];

/// Active-field widths 3 / 4 / 13 (`IndexedAttestation` / `Attestation` / `BeaconBlockBody`).
pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS: &[u32] = &[3, 4, 13];

/// `merkleize_progressive(chunk_run(0))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_0: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// `merkleize_progressive(chunk_run(1))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_1: &str =
    "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b";

/// `merkleize_progressive(chunk_run(2))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_2: &str =
    "cbd303e5b8ec95313f26a5908018b8114204aa35da3495cb5345a5d63fbcdc93";

/// `merkleize_progressive(chunk_run(4))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_4: &str =
    "b6cc9321ddadacebe6ea0232c10c68e00ed56b9032a06d80c22f3473833712e7";

/// `merkleize_progressive(chunk_run(5))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_5: &str =
    "49da5771be3bb66f84aeac2708de1d8667a4396362e080856faa1693f09b1d33";

/// `merkleize_progressive(chunk_run(6))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_6: &str =
    "d4e207b97c3a912b88df1466114d9a2f3b8d0c69c4ba683b07c3644b2cee10b2";

/// `merkleize_progressive(chunk_run(20))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_20: &str =
    "3af019339b7a3f665a096164a1c44c325fa272273c2a064e4b46678344bd96d1";

/// `merkleize_progressive(chunk_run(21))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_21: &str =
    "982138488f5a75df3bbd61397e08842bb8f915908551a3d30b2c25151122c1eb";

/// `merkleize_progressive(chunk_run(22))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_22: &str =
    "fd8939fecc677b5f76af2ff944e08f595ca98f8cfb53adaae45fe1eeab39de09";

/// `merkleize_progressive(chunk_run(84))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_84: &str =
    "29811ee7f965278e000724de2c913608d496ec681bfe021b33ab0e056dde5570";

/// `merkleize_progressive(chunk_run(85))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_85: &str =
    "b23cae180f07aa934431bebca266d3ba885c31f154c212ba6313b0f0df263a37";

/// `merkleize_progressive(chunk_run(86))` from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_CHUNKS_86: &str =
    "a04012b6cb7e2d2d523ed6cf04c6f3066787618f3ec605d6aea1818d1223c483";

/// `(chunk_count, root_hex)` pairs, same order as [`SPEC_PROGRESSIVE_CHUNK_COUNTS`].
pub const SPEC_PROGRESSIVE_CHUNK_ROOTS: &[(u32, &str)] = &[
    (0, SPEC_PROGRESSIVE_CHUNKS_0),
    (1, SPEC_PROGRESSIVE_CHUNKS_1),
    (2, SPEC_PROGRESSIVE_CHUNKS_2),
    (4, SPEC_PROGRESSIVE_CHUNKS_4),
    (5, SPEC_PROGRESSIVE_CHUNKS_5),
    (6, SPEC_PROGRESSIVE_CHUNKS_6),
    (20, SPEC_PROGRESSIVE_CHUNKS_20),
    (21, SPEC_PROGRESSIVE_CHUNKS_21),
    (22, SPEC_PROGRESSIVE_CHUNKS_22),
    (84, SPEC_PROGRESSIVE_CHUNKS_84),
    (85, SPEC_PROGRESSIVE_CHUNKS_85),
    (86, SPEC_PROGRESSIVE_CHUNKS_86),
];

/// `mix_in_active_fields(sample_root, all_ones)` at width 3 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES: &str =
    "e9a4dd72e27eca97b09690d892491e7cbbe3bd0fe3c3f130ac8b0789ae2c8d06";

/// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 3 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR: &str =
    "f8245c2557161e6000612609ef8e5c5d7c91b5d7b154a5248ddf0a5503b7f807";

/// `mix_in_active_fields(sample_root, all_ones)` at width 4 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES: &str =
    "979199afaecaba0a1c484ea3c04e69e791d21af4b5980103e6f48d2df65567c9";

/// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 4 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR: &str =
    "ad2a3dcb0c01109eb2ea9493f13f6bdfea5f2c58b07f7e8af959052ecdfac083";

/// `mix_in_active_fields(sample_root, all_ones)` at width 13 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES: &str =
    "e6abf04155618946e7c68b3ec7a30627a0a441405bdf7c2b683312c1be1a642f";

/// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 13 from the 3.4b pyspec artifact.
pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR: &str =
    "6a67e5570442f21c98371e8df23c484025d8a9d465c90b3e72209e7cc5fb89ce";

/// `(width, pattern, root_hex)` pairs for widths 3 / 4 / 13 (all-ones + bit-0-clear sparse).
pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS: &[(u32, &str, &str)] = &[
    (3, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES),
    (3, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR),
    (4, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES),
    (4, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR),
    (13, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES),
    (13, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR),
];

/// PayloadAttestationData hash tree root from 4.0 pyspec signing-roots artifact.
pub const SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT: &str =
    "e03211fd0eb67b3042c3a42bf70a92f8d782e27a913be1db6a50d9f7d74c4cab";

/// PayloadAttestationMessage hash tree root from 4.0 pyspec signing-roots artifact.
pub const SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT: &str =
    "91ff2e57c1d0f5c85614d8dc315a80f7620db016797576afd49e95f8ca98d7a4";

/// ProposerPreferences hash tree root from 4.0 pyspec signing-roots artifact.
pub const SPEC_GLOAS_PROPOSERPREFERENCES_ROOT: &str =
    "655562e907de72391c5313b1dc03490d47774d84655aae26de5929d0bd1fa1b9";

/// PayloadAttestationData signing root copied from the 4.0 pyspec artifact.
pub const KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT: &str =
    "fe0a6740a1b866580397fa5bb3467da40a74caf78a6c052ba1473054d2cb22b4";

/// ProposerPreferences signing root copied from the 4.0 pyspec artifact.
pub const KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT: &str =
    "850f7bd0d76cf6c1bdef307d46936af098ff2f94cb5dd163db2757c02bffa185";
