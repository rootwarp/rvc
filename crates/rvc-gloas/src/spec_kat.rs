//! Generated KAT constants. Do not edit by hand.
//!
//! Regenerate with `make spec-kat`.
//!
//! # Provenance
//!
//! provenance-source: ethereum/consensus-specs@v1.7.0-beta.2 ethereum/ssz-specs@v0.1.0
//! provenance-generated: id=gloas-signing-roots sha256=a76b893682635c1102290197ed36a67fd13a678aa21944a59e6be5c4f264c067
//! provenance-generated: id=progressive sha256=af96bc7dcab81b76427d50bec50944ec72eda3d33ce8426bf8569acebc6bd97f
//! provenance-generated: id=signing-roots sha256=ed6ddbabb85f37f3bb5d82ca44f3962aa9d75a4c3f6b1c84850478d38fabc135
//! provenance-generator: gen-spec-kat 0.7.0
//! provenance-date: 2026-09-29
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/gloas-signing-roots/signing_roots.yaml sha256:a76b893682635c1102290197ed36a67fd13a678aa21944a59e6be5c4f264c067
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/progressive/roots.yaml sha256:af96bc7dcab81b76427d50bec50944ec72eda3d33ce8426bf8569acebc6bd97f
//! provenance-input: crates/rvc-spec-vectors/vectors-generated/signing-roots/signing_roots.yaml sha256:ed6ddbabb85f37f3bb5d82ca44f3962aa9d75a4c3f6b1c84850478d38fabc135
//! provenance-input: crates/rvc-spec-vectors/vectors/v1.7.0-beta.2/mainnet.tar.gz sha256:0047b48f19fe6f74114291a46d0a16804871338ebec7166de6f3e4690da4313b
//! provenance-input: crates/rvc-spec-vectors/vectors/v1.7.0-beta.2/minimal.tar.gz sha256:86645aa51423de5dadcc279c785c1f0d03b0e07e054232c7f36ce0e3ec7ffa37
//!
//! # Residuals
//!
//! residual: none — every island container has an official ssz_static case

#![allow(dead_code)]

/// `minimal` Gloas island KATs at consensus-specs `v1.7.0-beta.2`.
pub mod minimal {
    /// Pinned `ethereum/consensus-specs` release this preset module is generated against.
    pub const SPEC_TAG: &str = "v1.7.0-beta.2";

    /// Chunk counts from eth-ssz-specs `PROGRESSIVE_CHUNK_COUNTS` (issue 3.4a).
    pub const SPEC_PROGRESSIVE_CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];

    /// Active-field widths 3 / 4 / 5 / 13 (`IndexedAttestation` / `Attestation` / `ExecutionRequests` / `BeaconBlockBody`).
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS: &[u32] = &[3, 4, 5, 13];

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

    /// `mix_in_active_fields(sample_root, all_ones)` at width 5 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_ALL_ONES: &str =
        "911c59673e029eac9c2cc499169aee5839df8b917c921207a71c1cf38ad96667";

    /// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 5 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_SPARSE_BIT0_CLEAR: &str =
        "a69ae34f32951bc3c9f0e0b50dd37e5577f2247bdfc70a11878c37995de5c3ca";

    /// `mix_in_active_fields(sample_root, all_ones)` at width 13 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES: &str =
        "e6abf04155618946e7c68b3ec7a30627a0a441405bdf7c2b683312c1be1a642f";

    /// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 13 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR: &str =
        "6a67e5570442f21c98371e8df23c484025d8a9d465c90b3e72209e7cc5fb89ce";

    /// `(width, pattern, root_hex)` pairs for widths 3 / 4 / 5 / 13 (all-ones + bit-0-clear sparse).
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS: &[(u32, &str, &str)] = &[
        (3, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES),
        (3, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR),
        (4, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES),
        (4, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR),
        (5, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_ALL_ONES),
        (5, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_SPARSE_BIT0_CLEAR),
        (13, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES),
        (13, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR),
    ];

    /// Official `ssz_static` suite selected for Gloas KATs.
    pub const SPEC_GLOAS_SUITE: &str = "ssz_random";

    /// Official `ssz_static` case selected for Gloas KATs.
    pub const SPEC_GLOAS_CASE: &str = "case_0";

    /// `SPEC_GLOAS_<TYPE>_ROOT` constant names in this module.
    pub const SPEC_GLOAS_ROOT_NAMES: &[&str] = &[
        "SPEC_GLOAS_CHECKPOINT_ROOT",
        "SPEC_GLOAS_ATTESTATION_DATA_ROOT",
        "SPEC_GLOAS_ETH1DATA_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT",
        "SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT",
        "SPEC_GLOAS_PROPOSER_SLASHING_ROOT",
        "SPEC_GLOAS_DEPOSIT_DATA_ROOT",
        "SPEC_GLOAS_DEPOSIT_ROOT",
        "SPEC_GLOAS_VOLUNTARY_EXIT_ROOT",
        "SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT",
        "SPEC_GLOAS_SYNC_AGGREGATE_ROOT",
        "SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT",
        "SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT",
        "SPEC_GLOAS_DEPOSIT_REQUEST_ROOT",
        "SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT",
        "SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT",
        "SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT",
        "SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT",
        "SPEC_GLOAS_ATTESTATION_ROOT",
        "SPEC_GLOAS_INDEXED_ATTESTATION_ROOT",
        "SPEC_GLOAS_ATTESTER_SLASHING_ROOT",
        "SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT",
        "SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT",
        "SPEC_GLOAS_EXECUTION_REQUESTS_ROOT",
        "SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT",
        "SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT",
        "SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT",
        "SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT",
    ];

    /// Official `ssz_static` `Checkpoint` root from `tests/minimal/gloas/ssz_static/Checkpoint/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_CHECKPOINT_ROOT: &str =
        "d8df90216b07c7c4fe15d1a416a23964caaebffe122c90738a9eb3bd75e701b5";

    /// Decoded `serialized.ssz_snappy` for `Checkpoint` from `tests/minimal/gloas/ssz_static/Checkpoint/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_CHECKPOINT_SSZ: &str = concat!(
        "a19507f80ddd89ce339b2260e5e353e66b475b98091758327e150c83ca25364c",
        "4f2d73e5fc3a12b2",
    );

    /// Official `ssz_static` `AttestationData` root from `tests/minimal/gloas/ssz_static/AttestationData/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_ATTESTATION_DATA_ROOT: &str =
        "895dc87887fda8265bcb7a6470bb64e4bd1629ed2e8246e00b83dc10acf15596";

    /// Decoded `serialized.ssz_snappy` for `AttestationData` from `tests/minimal/gloas/ssz_static/AttestationData/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_ATTESTATION_DATA_SSZ: &str = concat!(
        "322e86046b32ab87f72b3a376fbe55e356de6d617bd96b2546bdcc9de0792338",
        "789485c249e9247e0f7856d6b2acbdee7c56c495ae00c771961720bc3abe3512",
        "9c9c24f9b8e439c05e47b82d15a856d88be2ce31c21c28ef20c1c5cf8c8d4f8c",
        "2506efa6373e03f5ca749c0959ba6b5c50fa0fc59cbb14d6da732d0ac348dfa6",
    );

    /// Official `ssz_static` `Eth1Data` root from `tests/minimal/gloas/ssz_static/Eth1Data/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_ETH1DATA_ROOT: &str =
        "4ceaac5891d20515c7ecd85a7f84b8032bfd2987d9c615196e9335c7449af1f1";

    /// Decoded `serialized.ssz_snappy` for `Eth1Data` from `tests/minimal/gloas/ssz_static/Eth1Data/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_ETH1DATA_SSZ: &str = concat!(
        "aecbd9b9ea09f47815b67de9b19926cec996f9838d7464824766fe6f180d3971",
        "7d760731cecab31fe2b74537d649357a393a2a0960d60a7c240d6e1f04de6dd8",
        "a93503d8511595d7",
    );

    /// Official `ssz_static` `BeaconBlockHeader` root from `tests/minimal/gloas/ssz_static/BeaconBlockHeader/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT: &str =
        "5b18ad5300570f50558dece01042d7dcc597946fc4ba0598f2f9b3f30bc1f072";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlockHeader` from `tests/minimal/gloas/ssz_static/BeaconBlockHeader/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_HEADER_SSZ: &str = concat!(
        "dae48901d19e4ebdcf3f1d9d938d1352ae70c0ffe5f6258d04c55ea694c117da",
        "da19468c4821c40496efc662fd36de4c7e088265842a34eb2edad5e17d353b36",
        "5fe48afb51fb906e5c7d2e91681e56ffb2c3c345a8a774e83fe0298a24d84e05",
        "65509084256a9b3c9676048da1899bc1",
    );

    /// Official `ssz_static` `SignedBeaconBlockHeader` root from `tests/minimal/gloas/ssz_static/SignedBeaconBlockHeader/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT: &str =
        "b6fac72afc2168a6513a6508cdba50d1ee2ed1e7c89e562323c6eabbdce40d11";

    /// Decoded `serialized.ssz_snappy` for `SignedBeaconBlockHeader` from `tests/minimal/gloas/ssz_static/SignedBeaconBlockHeader/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ: &str = concat!(
        "67ff88156fcbec3b1749bcdd5e2f295b732dc8cd5fc86b6c5c98f2d6a2f837ef",
        "ddb057898608e5c5f6ddea503db12de5097f3190690d5cfc7eb86c6d1c3411fb",
        "f10ae17a8e86182077a6ab2a15a60a9a973937096eb62a7ee3756bb400691f68",
        "a29dca77a4f7d06c3a7a557d690e7b77043c5f03df801cd1c93b89bee1fb2e3b",
        "4b4049a4d796c2aa3cfd414393e31326361fce2d239a8b3186d5f4d749368fdd",
        "1b73d005048ea483e16bcc1a660fae9d3e5025d8ee8ca1af0b7afce9e7e6d648",
        "d7ecd89552fa794abceb6185ec8d6a71",
    );

    /// Official `ssz_static` `ProposerSlashing` root from `tests/minimal/gloas/ssz_static/ProposerSlashing/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_PROPOSER_SLASHING_ROOT: &str =
        "8521479d8a8b24cec5ddf63dd93c19f282fd34fa1159a18ac1c9aa376c698362";

    /// Decoded `serialized.ssz_snappy` for `ProposerSlashing` from `tests/minimal/gloas/ssz_static/ProposerSlashing/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_PROPOSER_SLASHING_SSZ: &str = concat!(
        "ef148b8bb57b439247a5777b1e3a55729c8b79ad8824c4dd45a488b4e02f3167",
        "8b47a897cc8a917c3a55cb0643a9a5f7757b9c478b71ae7fe6ae56fbce249d43",
        "2354aaae4b137a9c52da14b1f1d6b60107dfb983aa8654603c97548116c0d4d1",
        "f55d2ecf6331f4f256081a54d26efd83f4ce209fcae1056d0d800a7c29dd0a04",
        "6f9c04170ad88c69aa3699c40c95e832b0840f62b7bd28338b92c5a9cd3beff9",
        "c8e1e592b41801f428eb27427bb2abd6e8930f6423528a29ab0278fcd819ce2d",
        "194705acd0de74ac91c0b2ef7209bb1f569645b1a8fabe2a8cf359140dd84d80",
        "e3e83919b7dd31ad33f1a339c1dd80fec127c55ce4a4415e4aa872f2005a8456",
        "448dde2a8eb06e8820024f0d13b7e4533892f1e1f2b5d7ced65831eb838aa013",
        "982381e0c46d65d62e6b54ca668273e07e9a372c6e540fa5c3bc5114a16c89e3",
        "d56f377a1681a1cadeaf7d09bfd4c58490e569634a658b9787030eee7fb3e655",
        "6e82c357baa9bf55d8e13ed811417cc7cf44f479def0d1638c899956fd1e2798",
        "8ad4a94df8426e0a4dccb852b022f11d16d14bf4cbcc3e7e64b8b0bc9fb5b126",
    );

    /// Official `ssz_static` `DepositData` root from `tests/minimal/gloas/ssz_static/DepositData/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_DEPOSIT_DATA_ROOT: &str =
        "4722b1240a9722186c37f86e247b71b44af158195190e5ace819bb22d7ebeca9";

    /// Decoded `serialized.ssz_snappy` for `DepositData` from `tests/minimal/gloas/ssz_static/DepositData/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_DATA_SSZ: &str = concat!(
        "65a21e151cfe786a44326cefb3ed308bd11d083cc88f07c28abf4b5e6f0f62ce",
        "92e9bd74230ea1fed127dfda76ce6e17be836a64bebfae4283474fb54fad9228",
        "a9d52b0fcc0dd9b48e3cbb306cea29c8ed5c4a9a32a1f13d99fd2cb85d5c8b44",
        "0b8799734a8e308702e20c45077902e5c64c7f5bdc034588bfd6bf1b381686fa",
        "ca1f76bf4c5edc8955fad1720873d06decb4a527c288b059f72b2af1559ae0df",
        "61625a509994de8441e5b31eb9facf2dae7969d6cd52b471",
    );

    /// Official `ssz_static` `Deposit` root from `tests/minimal/gloas/ssz_static/Deposit/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_DEPOSIT_ROOT: &str =
        "89df7a35ef2edc63bd46d89217ea91e4fcc44481ede0c1e09f1f503cb295e77e";

    /// Decoded `serialized.ssz_snappy` for `Deposit` from `tests/minimal/gloas/ssz_static/Deposit/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_SSZ: &str = concat!(
        "fd9be9a75b2d664cd98332197a4be4396228388ac494e78cb506636ddbe4e131",
        "45d5173fde52b0e6cdbb7d39a1d439f6307755bc2434703bec0903e99a89f58a",
        "f06c5b57908c9e41535dff4d0d71427da494dec1643156f09b20969fee3bef43",
        "b05b2bc885d8677cffb1a24d74859b9e21f9b3477bc61e56af24a1d9bb518b01",
        "04b1f6fa3501915e88752306a8f3afe213a0f0adc92910a5c7469afa96a1559e",
        "04e821cdf0758a8ab3511b2a902a021d0453392d1dfb50f4630155fbd44dc790",
        "ce667900b19240ce3cc76c4b112cd33ab23043f92c178a7e4aad63f5cec0e8ba",
        "606068bf4e38d734e50c8d30be98bd48b581200c8a7fcb1155a798e11708bf11",
        "0511d2f3ebcc6c5eaf3d719c732e891c4538ae42b58352fcf7f5e73d9c98ea23",
        "7ee7803981c2657b24deca7e948e3bf4c4691f93e49b971d094b5fad0740acf2",
        "e5ba95d69262e4e4651c0474de2bd100128f786e930585bcb36f1806be711e67",
        "59c10d50f214d62c2f3bef72bdd6e75146521dc5ae76aa7c765ad34044f63287",
        "0301f3fbf10c5ae0e0c1b34436f1f89df5099190588a9fc473fee2df272d9c9c",
        "50ca7f1902f83366e46a2d14b82c6460985fe8f909eb3bd989592bfaa1ccea5a",
        "0a5d3c45d8827692ed2a205739c072bbd7f1deead4705761923fcd65c70d2850",
        "1e78db37e0e56037d95073eb59b4c02135b53bcdd50d8de18f3bce1d66adea51",
        "a5e32775ab9c85ae9f1a928e5edfff7ce267530b341924cd87671cdcbec20cc2",
        "7203c143f045ac66af742f93ced8596b84358213108bfb19afc6faa5d351c146",
        "cd7bdc269dc98cecd84c82bf43e663108d9ba61d306e40385e997dc57d0c53f5",
        "431ea5d118eadc0b89aa04be0fcd38e538462700ae3f1ed617696924c3ed8824",
        "1391134a0d85f187a979309466274471d89cd15da1055511dbf04c940278413f",
        "a628a3ab021c97179b3dfa5d79d1b4f4d92ff45f53b7beacea936eca95d11060",
        "9f95a0edce01a67b89f4e405545e6009d46bd88fa7213bf1af40430402cbf9c6",
        "09c37c4d9b80bb6c278cd3acbe333479c5da491205bc55d732ad61d77f1f9deb",
        "c845b4c09b0f99834099eec88d0693e057b292ddd1e56dd9cd1e93f98b73e000",
        "96f920b3227321a34d5e5afd0cf3a787d4dddb8fa637c82888725c689778be16",
        "0772a2f4d37f7abc9643a0728bafe45379c65a1814d3bd862c3fbeba6d715cb2",
        "cb694040d8d144724cd56e8d430b92255125b871f78b8d781a6dbf5813020aea",
        "defbf7f26a5419e0502c58e1fd955df76bdad766e72d6b17d30e58b573e73a7c",
        "7860c86dffcfaf29c3d624c311a6d79b73a81053b7f6d70982de386a3edab9a1",
        "5c5d6e81cccfe4709d6ea0a2f84b4f3ffafccf1faaed9eacb50149757e33ddf5",
        "c5cb5c3d0173f2540a0c5e141dc0f15b5cd79bde1c76098120e57cd61112da9a",
        "78b6cd1e46eee32bcf3e9c4276fe359490a2131a5e856b7b09214542b5077a98",
        "f8bffd791f9b04874c2469e86535e336e43b14b408dbfb32176cbb755f77c970",
        "efc8b4bda16622a99057035edbf6938ef43c5e0cc7221b85a4c683414009af51",
        "d6e5f024c68c9f44057ca3fdf955d19ac691b1c8f46451537a1f016619bd32a9",
        "2f66ca4a1bfc5703751206d6e9c59f83da830cbe6e7d26646dafeb1c1de008bd",
        "e4ce422085d01c92f7d179033e54cdd54b8a2c1f4f068a019cb87687b98db875",
        "8d96a58dac6162aa1370559bb7b9157d932df439e30043ec",
    );

    /// Official `ssz_static` `VoluntaryExit` root from `tests/minimal/gloas/ssz_static/VoluntaryExit/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_VOLUNTARY_EXIT_ROOT: &str =
        "b645fe52a58d86adcb7e5da057fa46b49fa2f6962e5a7f1473d19e5eac633370";

    /// Decoded `serialized.ssz_snappy` for `VoluntaryExit` from `tests/minimal/gloas/ssz_static/VoluntaryExit/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_VOLUNTARY_EXIT_SSZ: &str = "e985c5ff55c95d8d59866b34b9dc1986";

    /// Official `ssz_static` `SignedVoluntaryExit` root from `tests/minimal/gloas/ssz_static/SignedVoluntaryExit/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT: &str =
        "87c5ad0397dd4a74fcb52c0afd63667937c252fc2e8179d41f0378a0b942c405";

    /// Decoded `serialized.ssz_snappy` for `SignedVoluntaryExit` from `tests/minimal/gloas/ssz_static/SignedVoluntaryExit/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ: &str = concat!(
        "ebf2dbb128dcbfce153178bbc90f0bfeb151ad3f4776fec929f68ac288766bc3",
        "f7f1caf03a3a85660b6d058b9bc5c423d5ed7ab433afbfba27a998b0945c041d",
        "d35584fce8248a2a65bca234ad9a155485530066ca93a5554db597f81dc0c3c3",
        "74d2dfd01b03d428ad16e4afb76f0833",
    );

    /// Official `ssz_static` `SyncAggregate` root from `tests/minimal/gloas/ssz_static/SyncAggregate/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SYNC_AGGREGATE_ROOT: &str =
        "b1218583a28ed9d7cd1369e2d2440fc63022e397610d58ae7a16df017056c342";

    /// Decoded `serialized.ssz_snappy` for `SyncAggregate` from `tests/minimal/gloas/ssz_static/SyncAggregate/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SYNC_AGGREGATE_SSZ: &str = concat!(
        "fb6b779e84cc2deb07b0595a3ff74d94e621ae0813d8fef6f6969581f178b0fa",
        "81e33e0d7ec3ec7cf4fafab210f5ae6977081d2b18e7a5a78087bbcd90567fbb",
        "b92f7d63e9a7169331150725d2998f1378c34fb0571e08967e2334802f2cd0a7",
        "71b68733",
    );

    /// Official `ssz_static` `BLSToExecutionChange` root from `tests/minimal/gloas/ssz_static/BLSToExecutionChange/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT: &str =
        "3ebda9c03254054ab338d649c4bf1210391be20a81ddf023c334da51999a0343";

    /// Decoded `serialized.ssz_snappy` for `BLSToExecutionChange` from `tests/minimal/gloas/ssz_static/BLSToExecutionChange/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_SSZ: &str = concat!(
        "1add9c997f23db8a257770ca0cab66d34a53fc5bb7ffc45f5a2e25cb0dccf3a1",
        "4167cc54d694d5e4128ab90121b721d1cf0d49eaa7e834ce52fbdb7fc76b8b31",
        "95bce84df4ac10126ec91c14",
    );

    /// Official `ssz_static` `SignedBLSToExecutionChange` root from `tests/minimal/gloas/ssz_static/SignedBLSToExecutionChange/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT: &str =
        "274138c7e4c143b983ab76f6da2126e9756cbbd132542c145f48ca21ff270c31";

    /// Decoded `serialized.ssz_snappy` for `SignedBLSToExecutionChange` from `tests/minimal/gloas/ssz_static/SignedBLSToExecutionChange/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ: &str = concat!(
        "649871673e9b9386da23e29e254474999c5916c95e3a5eea26432f57653075da",
        "35786cab99eec3f8a861a129db6fdae98f1fcbbbf5c174eb881abd58cf7dc4f8",
        "de014d0837d4f5f72f0d321066be6b3a31c6f5752a52ff92d13334bbc6fc5d98",
        "f576389ac0819aad63931af01fd55a69b497b7ab490257290656e9326c2a7338",
        "bb0574c6f3331951b55beab3a2fb3453fce6101c3c30bd61d080c0d700a44cdc",
        "57c1e38cf55db5c0056b6324",
    );

    /// Official `ssz_static` `DepositRequest` root from `tests/minimal/gloas/ssz_static/DepositRequest/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_DEPOSIT_REQUEST_ROOT: &str =
        "73dddf502f0aa6e6449b3403b534af48bef77be332da8c64caeaf388b9bd2221";

    /// Decoded `serialized.ssz_snappy` for `DepositRequest` from `tests/minimal/gloas/ssz_static/DepositRequest/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_REQUEST_SSZ: &str = concat!(
        "e3cec553a741beb4d2aaa02a978ed08d95a479ebf3fb69e493d49bb8f4e3631e",
        "de739ee511528efcc802a5d2c1bb2df061a033eeb92650a7256a8f5fc9891c28",
        "9b358ceb39a4a881c432db275c31a7330bad78a8948726d5fee255d9e2882887",
        "d2dfc637b1cab803e79569ea14a35c148d00b1a3b34ece29a0a7bdd18a4341f4",
        "b4402d55bf267368d85f687ebbe1385308d82bd585722157ad9ee129daeccd2d",
        "86f061773a827d342e3379085595c60f6dd3502452bbf80d930fc5456f8bed4c",
    );

    /// Official `ssz_static` `WithdrawalRequest` root from `tests/minimal/gloas/ssz_static/WithdrawalRequest/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT: &str =
        "d3289d0657175a0684915f077325b8e99704f0aadd5f65047df3825bf459f1e8";

    /// Decoded `serialized.ssz_snappy` for `WithdrawalRequest` from `tests/minimal/gloas/ssz_static/WithdrawalRequest/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ: &str = concat!(
        "24701c461c1ab8c7c9eed153c0d3dd017bd61f7ff5f153b11ca61d0775a549f4",
        "99fc4453e92b1b60df3a29354f580f62e9e760e071a40c89577e273c05f479d5",
        "c0928e1e5bf1481e39721415",
    );

    /// Official `ssz_static` `ConsolidationRequest` root from `tests/minimal/gloas/ssz_static/ConsolidationRequest/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT: &str =
        "7137d280b8bd06ec6ab37f06dee9814943f31304b54be7f22122dfbe3a65d510";

    /// Decoded `serialized.ssz_snappy` for `ConsolidationRequest` from `tests/minimal/gloas/ssz_static/ConsolidationRequest/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ: &str = concat!(
        "caa937a1a7272ade779f0e7675578304506f3364806566f508b2adcf94c7c0a1",
        "f34cde509005578d3c0cefeb825f0b477b19bcbab8b9db1400c3d31777e340f8",
        "6c764820889b3eec066451ef91c1c49b1a1effaa28cf50430a892fc46451045e",
        "43143b18c44dd9b8ae2fab3242576729f91b32d2",
    );

    /// Official `ssz_static` `BuilderDepositRequest` root from `tests/minimal/gloas/ssz_static/BuilderDepositRequest/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT: &str =
        "b284ba2dd5a614c36b5b70f5944c8bfb10349d14bbff622c2b375bc7ce09ad56";

    /// Decoded `serialized.ssz_snappy` for `BuilderDepositRequest` from `tests/minimal/gloas/ssz_static/BuilderDepositRequest/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ: &str = concat!(
        "90ffcfe94557aaf6648ac34766693f8f5406a8e58587eca2cebed5c5eec7e3dd",
        "11102930f80d8f5576489bd34a7a0380995d8edb745bcbc999729a3267230fb3",
        "2c4f2bffd55fff6a2a4545ece5139301cb2a07084003154e03c422d84fe1e053",
        "48d38c6d837e272a2403e354ad97d6b0a42bb1c5f83a714c0a4124ef17ff5703",
        "bc9a554fef3cd1d72abb71e9435c760a3ed447751617e67c10290c851f87c4ee",
        "34fd555f811255f8de27704787a2f7bdee707caa69d4a4df",
    );

    /// Official `ssz_static` `BuilderExitRequest` root from `tests/minimal/gloas/ssz_static/BuilderExitRequest/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT: &str =
        "5fdde6594b06cfe71a41915462537d6db64af387803d3d848a1739ceb1f34991";

    /// Decoded `serialized.ssz_snappy` for `BuilderExitRequest` from `tests/minimal/gloas/ssz_static/BuilderExitRequest/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ: &str = concat!(
        "4a49feaf8256ecefd27f681ac16ee119d578aa0e780c243319b214cd87b8debf",
        "bc1d4d22c1fb94184f20dc76a7ae4dac4becfe0d613602e01407e453df19f546",
        "e1bc3de8",
    );

    /// Official `ssz_static` `Attestation` root from `tests/minimal/gloas/ssz_static/Attestation/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_ATTESTATION_ROOT: &str =
        "c04795f332bf5a374eae86a86b0908cd6c551337e5b50bff03fd228029a2bbc0";

    /// Decoded `serialized.ssz_snappy` for `Attestation` from `tests/minimal/gloas/ssz_static/Attestation/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_ATTESTATION_SSZ: &str = concat!(
        "e50000005b91506c8ac176643510375209fe2f53153203a25542deebf2dc40b4",
        "6ef3afd7d195cbd3a503c9a17131892069fee55775379faa1479386a4deae4ed",
        "dce46437ef6caeeb741cb5b78bbb06ac2397f15b3c97b666fc5e8e0aec4c8822",
        "bc520d6be3fdd98c10f0d24783ce66c56551497f3db245cbb77532e2be1b219f",
        "3c0f976cfffa60ff447189760f5240773fb230898fa0308bb876684e69ddd4b6",
        "18d8bed91ca491b97a1b0b72e53abf110eb855d3d51e1867c04d15b04ae86c13",
        "f25b29d93dc84d1092ffc5612d402f8583bf0e20869d5fba67693cd1c614a3d0",
        "e9faf43f0b05",
    );

    /// Official `ssz_static` `IndexedAttestation` root from `tests/minimal/gloas/ssz_static/IndexedAttestation/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_INDEXED_ATTESTATION_ROOT: &str =
        "3242ce43e60b34a105803e89a21962f760e1e7592bc7a90f399ea4cb85d56fe7";

    /// Decoded `serialized.ssz_snappy` for `IndexedAttestation` from `tests/minimal/gloas/ssz_static/IndexedAttestation/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_INDEXED_ATTESTATION_SSZ: &str = concat!(
        "e4000000e0cc690973c1ce6dd3a6ce5c77aecac03661bea920461be23c02026c",
        "0966a3ca6331e7a1873c7fb03cfa45e5746f564814725076afbb04bfdc7c48d0",
        "52a718cebc3b45a6e06a118581f7cdf0e89a4813025257e4d76fe3879ad1acb8",
        "c06d8f3939268dc45fd4c86727c227874d0fd449fc79306312d99418978b79c2",
        "7b5f9f1f518d53f21a4f56168cc26337aca5a7d74df39f47d17917fe36d9f084",
        "2cf7c676ac4a31a3f02ca48ab81950fbc2bd98f62a2bb7df872cd48c75e8ae84",
        "5b8f394dbd4d81e070c18072ec730b19647becf8babb79997951ef85e313eff3",
        "86580f5b6a0ee80a372f9405cc6a1a65827c7f5d7bfc1ef40019a65f34951a6d",
        "da5837f02a79bf8bad053126",
    );

    /// Official `ssz_static` `AttesterSlashing` root from `tests/minimal/gloas/ssz_static/AttesterSlashing/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_ATTESTER_SLASHING_ROOT: &str =
        "248e8c551e0e6960b1c84d273db447fe79144dead219770c7ad3c3332efc6914";

    /// Decoded `serialized.ssz_snappy` for `AttesterSlashing` from `tests/minimal/gloas/ssz_static/AttesterSlashing/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_ATTESTER_SLASHING_SSZ: &str = concat!(
        "0800000024010000e40000006183a7009d3f94b17cea5166db853c60c12bf89a",
        "0cc1c15584b175a62e316bffa3324f4407de8bd2cad71a886bde9336773499b4",
        "196c226ad95a6708eed2f2b20fd656290ca0320956514b72c8c8b337a21ba3d7",
        "1aeac6d9e6314c560dc1dda15e571a042fb2ea6d1c2fcfded23b0c40156f7978",
        "ae3cce68d7ab3deab589056c56f0d951f051f6468038b2ca6b6419416e8ef9de",
        "2b4e9d8abaf5e2b155311f4ac2777520cc312ae023a02c841f42ec94bf2fda67",
        "7aebddca94cf32ad3ae83482cda3cd1d1abb3fe446370ed3234f103c8399843f",
        "9f1f3682bd8afae622e80c60602e698c9d2fac76757142aedc963469314d580b",
        "2c0e26b4f1ec3b8748fd1762fd58b928cc9494715ac4451e676145c16636858e",
        "e5a8c1d3e40000002a31ee918f7521e8004b39e5292761bd917e43128ce305e1",
        "a33d07916d6b12978c5d7a9afe11923f928e425b9e898068bb0f86174907bc76",
        "35a91ae8b5bbeecd857a3393306c5ef27c9d682f2d650e0d7a8bd64df43fe463",
        "0744505959936da3d45fca985195e33de860caeddc135f87cdd792436a5b1254",
        "6b8cddf5f819ba4fb057a304f780ef1be7d25a0de8086358a8c853676be8cdfd",
        "6ce06090cfa27dd7fcf24736e784e81fd1b8c2c73790a846dc2eb2dd1132c503",
        "64f438293678428dede89bcea97609f66e20456043cb3e4e683caea7744ceacd",
        "c5005de86a69f7109d4d491e28e9c6235aa9a9a0f9bde22c6b935dc62f4ad936",
        "78f97548da4827eb904ce35d80c4f81b19edea5adcec09f4a561cdf918596c0e",
        "066b560c594f831a",
    );

    /// Official `ssz_static` `AggregateAndProof` root from `tests/minimal/gloas/ssz_static/AggregateAndProof/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT: &str =
        "8e20d3aab21ae5374ec249d072afa489e501d89e5c098f6792b2771cf5509bd1";

    /// Decoded `serialized.ssz_snappy` for `AggregateAndProof` from `tests/minimal/gloas/ssz_static/AggregateAndProof/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ: &str = concat!(
        "4ba7902c4d1c269f6c000000e88e6195cc4db2e06816cde6bbea338b88010629",
        "b0b9c041d50f47b276938f21201659abec0c6103c5cd90c5222046ff37370dc1",
        "4922cb5041198b141135c3d922c5a9314a57ed3b9bf9532f6c10a1d1bbae1459",
        "d676187b807b951689dc1bc7e5000000a790491376f37aee2147cf66e9714046",
        "ecbbec4c130e281e93c58058dd417a0e167154035486bb10087ad5d935e3993b",
        "0fe01548b9bdf0ebf283b42a0c649394dcdb85b311bac6f87fb7267dc63e8e24",
        "3e5e1e22afaf6064d971a570e883da585ed73c868af16a62e1125a70447b8c21",
        "b6d432448d83f60d029b391b07c4e773a5042bb3e19b623135daec3fb0c2d397",
        "325135268b4eb989e76459677c88181aa4d92ddbd7627340cd8fd06a04b60cbd",
        "936941549f4113342df98c0bba3fd4e3bde5a5423fbe30e9277c60cb5c983423",
        "496e87c2dddb143235036027ecc53d0406f402",
    );

    /// Official `ssz_static` `SignedAggregateAndProof` root from `tests/minimal/gloas/ssz_static/SignedAggregateAndProof/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT: &str =
        "cd1dd8a358d3ec417f23fd4b05799795b420928d9990f780cca04a59b2c01f49";

    /// Decoded `serialized.ssz_snappy` for `SignedAggregateAndProof` from `tests/minimal/gloas/ssz_static/SignedAggregateAndProof/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_SSZ: &str = concat!(
        "640000000e130cd5c951733ef0082c7ad47b67850d7ff3de90a5504a495c8683",
        "41dc54ee90c4b421f59468a04d14fc403738f7786261b2e6d93da890f9a6b96a",
        "369ddb3c6151d982dfcd9248838dac2e7c40604a01a030d655014f8f706e1bf6",
        "9d1aad67b2bf47d86f063b8f6c0000007ca9f862a9788882970b4aea5edb0665",
        "a767f82a0eff5398fe4c0de4cad2111b7df9e7d7aa30a07b16f6e3b25ce64ded",
        "077236435dd0e3ae1c1c2a16340e1f03d8337c0c84c5833c35f3bd8023ab5414",
        "b98bb0db0fa4395f99b281b3457209d2e50000007ca67a972f878897ae1121a4",
        "d3f2fdd1a98aa14f1d6a5d45049f11c8a9bcfcd9db212afb686718e7227e8984",
        "dd1b9031a663395a65b070c4f0ff3327268b6dac6d29a7b9d005b613780e7043",
        "19dd0055fde506f018a080d2ff0df38c81832b4d0c4dc4ca7bf804e6c303ea1b",
        "a07ec8e9990b96fd0b929a6494a8b432920f87b754697a430caa43da25a18632",
        "425eda9bcf89c16c04f4c32bed382a84707d4a6e5488438e45787bcd3db66327",
        "35d34c9be66cc0e353410b115a24f2728cec758a4419cc193d2132e2ab4fc289",
        "5c1c7602371332455c3ebd2ba3b5c525677ca0380d01",
    );

    /// Official `ssz_static` `ExecutionRequests` root from `tests/minimal/gloas/ssz_static/ExecutionRequests/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_EXECUTION_REQUESTS_ROOT: &str =
        "55007354a3ef0efc0fd662af250498a0ad167554303434ad2e5a000b26abf19d";

    /// Decoded `serialized.ssz_snappy` for `ExecutionRequests` from `tests/minimal/gloas/ssz_static/ExecutionRequests/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_REQUESTS_SSZ: &str = concat!(
        "1400000054050000ec05000060060000880800003a0b3c77ab4bf491f7759425",
        "ae8eca4e0c6ca8af5013281d5b2db0dcc6bf6eca0f01b57409184d8f182d8c14",
        "d0c223dd6a516ec5334ee9bdf372c72f0bef195c6eb75f486b369de64a8c3e27",
        "b8a575c78821080272bd74e1a26520642ec07f1e1d84f780cf1b6306cfb34f1b",
        "d089d6716d428c71f8af3474c330733fddf127cb5684284f7278abe4ed8e8850",
        "0c5e5484d17bbd8224124f770034119b63c9f1d1124b5c9f97643ee9ddf4e262",
        "b54a4b36e811f257df2deb76b55ff75bdef02e81afc521da9447531f1c3ccb62",
        "b6f27eb1db26d08113245a6986f0bd49520894eb5a43265116cb7e466757a8bf",
        "331220cfb9f077034153af469dd8bc6c83e77426a08995a5313df070df186f88",
        "099f26731c7b334213845dabb6a08e660a04d61a33ad26bfe9f773d3ebdba5e4",
        "a018fc840f5aa9ac5d66b5df6449b0fb0292fa9590c3fdb7d54c99202e80daa8",
        "324bfa220de1203e84fc4cb14ef4b1ee485b0b396d9c8ec45ec5d20b76c2a893",
        "2a4e9158565e874c7e3b54db95252c138293a161cd72a91b3d83c8afe3c424c9",
        "913ca1ad5084110d335ce4438aa3285372fb01dd10f159cc7ef080e9d782935d",
        "5b2c0e7528bd8e9b2dda596ba77d7424456bb92f67673c524b034b992c4f225c",
        "6d1fb2c437a3744f502843ac37dd02159edcd75ff6d919d9ae40c5c671ad57e4",
        "042543eab77dc137cc5c4290f0e973d6d4c09eb44f6a1aef746c5cac5ab68588",
        "9d30b4989e35a3fa212cf11ac7397647939a7d3328d746b8487c5856b3669933",
        "eca400ff2c3bc23e35e53787fdec14f7a18397a2a347adec900bf683a184488f",
        "c4ed5dbbd78a74d85b752dcad023d0f5d59b2eb1cde8352249d888eea32e7080",
        "f746cb4134acd9f8540233f6d04692c71f5813c39df4d03dc78c59bb00ab41af",
        "1b3877b93afe01815afd17e8ef94a8e9ed95602c89b0b70fc7b5cf6dce1d5e3a",
        "02e7ede72195de8de71ae0fa3281d464a911a7c509095181755b88617038d4aa",
        "d1f807fff47129b52ba464001240b508fb2f8283e4fb82cbefd5c7dba872462e",
        "506417d92c60af00eea5e8027e85b74fb0b2ef01817eb3ac063211721a4247f3",
        "579841c575794b94414f64a5a3519a66c4930d6f92d40b4a6787d8bd10b03805",
        "f3001bc844ed26c4f1feeb76b7a9513d0faefc8f64513d348a97476ec2a963aa",
        "186a4de04c199abc48be1dba48ef63fb908a49f291c26a8847e24486d43342c3",
        "89260cae9e8bf19a03bc20b5255f4553c3d67b0e61c0f20ffbd1e0159908c1cb",
        "8ab9064cdc2db97a854b91edc3b49c9664237190e47b1858d9afcf751769ee0c",
        "cbc6868bb68bdc5354c2688fa04a5a4c51583979b934aa4c2192a0807126f3db",
        "767a927cc69c92cf514ad09980a90565bbca19ea07401d22c03ef97921e6c221",
        "3a1099a1c66378c76fd1941deb4e2af72ce0f9e9096ef57213cdb4a88a1e72ef",
        "129880e284fa5bbb66a4b0525a394fef5b6f36bcdbdd6cc267d3980da7b5efd8",
        "f9612f84d11bbbb0072de5781d5311b73c536cfd0561f56fa6a531ceb5061afc",
        "64eb322416f79256cefc92ff67a7fe49cd708fe972ec43f3912706589f221998",
        "2f79aa156dbb5e79d20cdc0dea958b09e743dd2f6d8fa2bcd5c8cd3d0c45bf50",
        "cfef5298cbf008787e978ef1e6310b53a892e4d9a8d2cf4b062d352558fec5d3",
        "5b3ae9192abe11912cfc4230da5d23400fc93fb89eee41c631242b847e29e36f",
        "3f08a5482ccd35674d835ddd112ca7f52babea59cdd56e991b82d68ed7cd92f7",
        "7f782ac7fd96872f77d4785c5ff87b6f7893bb85a22200378e6391494816d1db",
        "f4e90c0db43132776b07600cc63d3cab4b65fde4b6cd3459cd0da5454d2f8306",
        "bdb43dc6e4ab0afab2268215a21cfe6972a0854cccffa3e877c012aeb92a3cf9",
        "b304f1dab55e997c718ac1902448e3d8aade1b942785983520e0533e18b8644b",
        "a9057af3a84211ed04150db58f9c260c0eb6b259e0221719431bf36f384cd3fe",
        "65b98b4a3d8cf194f57ea7259900c6e7f5105c9762b1b91993e27571f2e3fa56",
        "51e0b1603f742c062724785d5d4a5eda8acb881dd7d58ff2efa855acea8c9455",
        "62efd59a90561316857dbc66711a30c4c7db87b7e1383773b865454556f835e0",
        "47b5ae7c57ae70ef0da36fc72aefdd1d8911747b5440fdaf96ae90512125fcc4",
        "ad8f5a9edf53de326bdf317bc122dc9d2b6823ce0d55eb650b6e23afee37fb40",
        "d2a25d11e96270cbb396df07a4b0279f513a4cd9c4f61bb32bb31639fc38906d",
        "242e66040fbf505193c036d09c1c305d8128f64905b0273ae39db5b7e037fccd",
        "841e4b7322e11f63c5de26bede47842b51940df14c1f905d5504ef47e3fdde4f",
        "c88a585e7c9b097ece229207b26d8ff329d5f0b6d95cd6f35bcf1b00bce13b12",
        "0c865acf4032be6da45a4995c698412e261d65b432eb005d80178f6f768dc682",
        "a3a32590b0130c27b332aa67b254141639117c23f9c8c75d55f9127099d01546",
        "cd3167fd9fd4391508d8610ecb8c2e0f59f6c476a2237210d1d96f62ceee4c45",
        "59c98359dc6ce453aaa479285f9f4d4d5db49778cfe422ad850810a9a1190c8b",
        "2ad09c3c00b6ea10ecc0bf554697634caaa1479ae4fa597ddf79ce299fd2d000",
        "a9fdc67bbbec9b8ec3977cb8b7a90a56ab457e8b3d830096e793baf8010b9afb",
        "1b2189514a714f4ed8d6cf8a932bd71274c9cb234c1fd1fdf95ffb6fc8bc4270",
        "8df0df661e2bf0d6df3e01ec16434abbbf28ee08f63458065f5be2665c1b974c",
        "426eca6194cf7fcb3ea4bfd69c5b8580657101959e836e7e4415afd319ae9ca4",
        "eb11ca409c97dc3e0f8f9d9da5bfeee5296ee90fc29e3c39446c5cb00d77a424",
        "3705389b3d3aad5d61bcfdb5430ddbdaa664fbc2966bc95f4d71af049a0172f6",
        "fa9616e85f007275bc8656c8221342840f51488133ea60a779de131c04b39ad7",
        "a183ae7d7fc2723ff8fb399c2c8f61aa889a02e6e01248e5808cfaf474524f3d",
        "4b4c05d75a22bb10375ff35a46602ff311046efaf08943bc39e0e8b4039f9f03",
        "79f7075d560365703735849edd4b027acc866cab1149289232e05320f6cd9bb7",
        "61e05c4ffffc0f8b6fcb81b9de227c43d1641f4fbb4bb94cf042a62c4fee6207",
        "c4e66a5e7017f6efd4ce7d6172b0c39e6912f082d0822e68ecaa324892ab361b",
        "dadc4729f2fa7401c571ed69b1690ca71f753f0e5857bd24d569ebc569f4d78a",
        "4cbacffc03b348009e639c00929d36de03bf6d0500f7fa7d04435d85c1b4e605",
        "2118adefee377296a361dc5c9e65eda62c378cc83b4d297478d25bd0d6fcea8f",
        "b431c17ba466b393b340c15f57603392b37abbda44e722d8985cfc451d96dd7a",
        "84487d96ccfcd38a69c6b01bc908deb2db139e110331846d9fffad9a84f22f52",
        "af553431b2090d577cb365d2bccd2016e4556e13d0ce9f9d97169388b2031c80",
        "bb3e1a261bd85527c411539b7225b9b1aacee04efb764482351fb5be7a113cf2",
        "d9114fccce9a6f00510b379a8dd9bfb638422b5a8bfd897cb054533efcf78628",
        "d2725448222632526af6612a5e0b627243e7c4fcebcdbef235f4cbe739beb99f",
        "79612fc2fdfedd5c76732121c659f3a98fc03152f63fe8d1bf495c670c3f6dc4",
        "c6d82d98261608ca9726b929df5a1fa91494dbcdc6a0e6f60deb95094ebb09fa",
        "12ea1b5aa040c184019da82bd4f9663a64c356f0859972f5520bcaadc80e4cc7",
        "b3b08b107463cf7c6bfe721e55d35a02b8d90f43c6c8d05ee137ab886c2e394c",
        "6ec742eddc046a87548217598dcd99310e53ae19c69ce09d4a43e7f41b33259d",
        "86382c871bddb8d7",
    );

    /// Official `ssz_static` `PayloadAttestationData` root from `tests/minimal/gloas/ssz_static/PayloadAttestationData/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT: &str =
        "71262d0038a4a5f09c5389d11b2ad14795eebaa551fc458847623ee710742ef0";

    /// Decoded `serialized.ssz_snappy` for `PayloadAttestationData` from `tests/minimal/gloas/ssz_static/PayloadAttestationData/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_SSZ: &str = concat!(
        "fabc02064599c1f9dd0934d6c102bfab6e2ecafddd14ba4c3c374cd4847ba04f",
        "41b94498ff2ab0380000",
    );

    /// Official `ssz_static` `PayloadAttestation` root from `tests/minimal/gloas/ssz_static/PayloadAttestation/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT: &str =
        "f9cb70289a856c574ae6f0ef6cdd07cdf302567aac61183d99f9ba2289ec3504";

    /// Decoded `serialized.ssz_snappy` for `PayloadAttestation` from `tests/minimal/gloas/ssz_static/PayloadAttestation/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ: &str = concat!(
        "41eec92f72b79e44dcd7378a1d5a49546840fe9570eb728e9696d328d9654ee7",
        "59d172b4b4a897bf575d0001a4bd942f29ff97e7b74457292b832f29fb347cb1",
        "b8ac280b4554d63fe2ddb368dab466a0e8980a83bf2b1694949dd8028205c7be",
        "35cf393512d59af512d78c6bad6f8c3765f4873dbbaf31f6112f3f8ab98963e1",
        "1422748dfef017adc61db315",
    );

    /// Official `ssz_static` `ExecutionPayloadBid` root from `tests/minimal/gloas/ssz_static/ExecutionPayloadBid/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT: &str =
        "d12473439cb8bc233f4a594c02b90975d17c0feb582888cd60a3c9d462df5b9a";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayloadBid` from `tests/minimal/gloas/ssz_static/ExecutionPayloadBid/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ: &str = concat!(
        "e801b44352d2b7d530badf1691dcd14d891200352af24388bfbb7a54176035d7",
        "4df4cd31349ba1accce760fad621e410118d7c71abf76bdb50b315c3fe06d524",
        "862ef67e1243e57912b401a205a9ddf9c9a48e06092dc6ec39d606380f0e4c99",
        "07d0f30028f6f8608457ba1cf2928b847c1843d8d49a731c3a1e9044feb72090",
        "febf5fd098dbdd3f0748025a822370d681e80a15020c2a4412ae46c402156775",
        "6b2b27fd1aefc7bcb190ca7cfcf92b81676a2020fdcb8a4d759d44cde0000000",
        "c54c3572d6dce44c0dcb14dbd0b5bf951b36d9f633009da7ef0c0787eb76b3a5",
        "6dcd3a21c445b9e70258b4c5bbf2a37321be7d68efb3e201ffe96a7f5d093820",
        "1d7ef12f3bf762195b501862972b1b3e",
    );

    /// Official `ssz_static` `SignedExecutionPayloadBid` root from `tests/minimal/gloas/ssz_static/SignedExecutionPayloadBid/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT: &str =
        "f5774b9d3c00b023d6a46d17a2a9bd0ef210e1662fb5dba27816666bedcff706";

    /// Decoded `serialized.ssz_snappy` for `SignedExecutionPayloadBid` from `tests/minimal/gloas/ssz_static/SignedExecutionPayloadBid/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_SSZ: &str = concat!(
        "64000000b111300060d9c18172783306c3dddcd8831ea9e29ddb543b727faccd",
        "cfe1dc1e2b8b1d0a0d5a0cee4557ffe6bbbddb6315f1147de8b9ed3fa13806ad",
        "f573184f15237ba587c0d95ae313cbaed38e0ba1232455b2c5433e2582c225dc",
        "06241c1392fd94d2815dd795c34d3c1cac566fbdfb1291668347a9e5c1f2bee5",
        "01ec08412bdc481bb66a0c35273217d941f14cf983209445d8da86283eab0338",
        "a07fdc6639c47b25c73c9b2dc67f126f27bfaf33809c1d70ab4c1f479a19e406",
        "eeb0273909f908b299a55369e20c0d4772d4936ee60628e4b99ca61ffdb0100a",
        "f181238e4591beff76cb43b8a51c4f6f091eb861ea7c9b8ade4d95dca343e974",
        "16fa80b63ecc3a9682678695ef48d947e845dbc4440647d94b1b27ae28212ede",
        "e000000011c419faf0045a2058999706c82577bd5b51820637e13d0bedc6813a",
        "097f46993b053b1a25e12ab1f474ae7b03aac94bb7da22c83551c2609a87fd38",
        "22d494787ad372919a39290ac002f26774dd290a2be70a92adcaec176214478a",
        "117c497c1027ea0805cb12f4eb1af971269a396780add93398d1523e69315310",
        "cf796b48",
    );

    /// Official `ssz_static` `BeaconBlockBody` root from `tests/minimal/gloas/ssz_static/BeaconBlockBody/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT: &str =
        "af0e2c9f803d056b767619ba304a33f8d7ce7620e12edb8e3e5a1fba977fcfac";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlockBody` from `tests/minimal/gloas/ssz_static/BeaconBlockBody/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ: &str = concat!(
        "3de1ce97a3ee9e21a2d50852bf7302f5de618a7dae07d0e43fb3abdf2e629a34",
        "78265c3d1b22bffa64a43d850f72ab672edee466007a93173011f36d014c26c2",
        "1c975f08b72a5abfb586611720c2205be9aa2c1ffb4e7f02daf4b397dc3f1fa7",
        "220f0e84da24e4f47799e9febe551725673ab9d3558c4b62e02f2aefa09e289b",
        "8baf07195a2bdbd3924d159fa6f40a02f2c1d8ac36d9b91c60bec98268747ffb",
        "7b49753b33e240e54cd0823cc671d6453eddcf1be59a61bf588b663436930707",
        "4f8b4c905be360c25001000070090000740b0000061000000610000097e25f22",
        "a98094af599ac4fbae065133452ace1152379aeade7290f7a1c9219b5645c5a6",
        "f884eb8104c1a1668a2b18d3d70373bd9bb2f4f19fed56092878e903fd1bcf4f",
        "cd3dcbb7b84851f526db362c0dbf4db8e9bdc72f552692f118b45d021d2740b0",
        "a6120000ae160000a2190000ba1a0000f52f84ec135211189a070896ed88bcd2",
        "fb6dc2938e4760ca29f47225398df65e34ef8080bc4775bd13ef4475762e36c5",
        "e4dc1888a79d00d3ecd467833e2069d5bfd10c6563d6306c70d81af4987d607d",
        "3089e250cd759e9226646797b52f2afc02bb35ab319714eb538170ef226362d4",
        "2d94d4b86abc6ecf0c5d2390c928bc23456bc084ec1aa71ae7576429ed621358",
        "7a16492507394ce9d01e31a30f922eabc7e8c40769556210bcf50bdfd321e69e",
        "b5a7eb9f4308066426fc9c60d65e23ee55f21c08d81de859f98b66834b787df7",
        "117cb703d2b10e77492c92f129525137a2afea36fde5cf7ff9c7a17b7800acd3",
        "a88ecbc38d9b6953c969e5d5dc15e1034f2b2c3a4f4efac80648d683562ded6c",
        "4073b5630815cfe8be90033baa15845f9ab15e686071c3a31bbadf2d9e16ba97",
        "873047677b3f86fcfa92d46e7675926cff49bcbf5a211311c90f6126e43220d1",
        "4c6c043b679a13a7e92a123d25d032c024617256373bafa65a4f970656c28102",
        "e6bfcb266ee2fd9852fb3b75c6a59b259d6a5951cf309ab4f5aefbecd8627ef5",
        "9340b506804ad57255217f393b5fc599afdc34275275edce0bf11a02e076848d",
        "cce8672606399c6296813da0c0f91b40ae6742de55baa7c7a1416ea426ff5343",
        "d990623bb073d034b92fa96ac25cb1b4207e9387187e1c01dec0c6bbca36f404",
        "43ca4e02addb5533606c5670980e68d0cad2d7f884950b47c2a9e82ce140d81b",
        "f121ee4629e057a35ebe0b35baff8a1772efc5591d7175d5dcd3c62e6866959a",
        "46d0be8de7fec12f3691a3156f5d27b055887dddf824270108559dac9c0e637d",
        "823acbb52305f17ee0c85cd5e2281025358fa0d60829156219ed5d3deb575ed2",
        "3a482fe637179b24cdbffb852055eaa5e839490d27722cac226b2ec6e153488b",
        "0b0e5078eaa57c40864a7bbf2e4abc9326c315fdc6ed395dc7cba26c0ba072c8",
        "926f35aad23207aabe8e9b2d89765dbf4bcb8492834498930f5fc548859a3b46",
        "40e72f94959a6a6ed361c53f48a676b2d1e59f289455292bfb2c5366fd558a59",
        "76533d635ff4a15131142b253b0a90fcebf36990605bbd90285d7f8de238afb1",
        "b7fda36fd395ad76b74f9ac8b41856a39975a504603f7bc19369257c99555d39",
        "5a085747a768fe942303b3296c795ab57db17fccccbe814ba37c0b520cdfcfff",
        "2d81993b6f6627400a4723e2244459780a94936d919dbd2176bc43911e83b0aa",
        "8cdad351f3e5bbb3a71414f7d411b55d211813b7a0f5ed68844ceedab3db489a",
        "c5727c7a1322b63a1a9f0fa3f96afccd7ea5e3faf649da476c9bc02a56bc4a5c",
        "66d264e9b0ebc15465f7756e423ef7d7e6a946a840dd3d42f74e83ea6ac59d9f",
        "0554ecb644f0e9135800891940fc5d6c5ded7b17fdf2308158cbdca62de44479",
        "0e5c3435e71dc66751e2f57c2ebf550693f5f3aa1319f0def7b46456f7acb921",
        "6ce025a9e879f965cb94f1019f4bf6520d8bfae61c1b8cd36fe8937622efec94",
        "06a84c70f38c39c5850d538ffc42d5134652b077efea7d4f57b8b18ba9f6f9b4",
        "df0300e434cb87f429d298385cd7351b31638db4a72cd66b88b150383189a544",
        "daf9ee385545d1e1226ee5f98a1cfbff2030a13f17b97ae864b4e19302cb59c7",
        "47e74e3e4a10716ecbe7acca213e822065bd7febf5ad453c439c0f492e389ef2",
        "1ca8fb4cb44f4ab3c83377e6238a33c68076f484a5b8c48c6b799644de2d5d2f",
        "14126f3b2f9a5f9351025250e9f41bc79c49c0bdc40dee256ab2e7151c3a179f",
        "81de4908cc78d03e2706da723db8ca91cc5fbd3cb55b034f68d96e234184cc0c",
        "b21c006ca8d7575c5d4f10e69750db7ecc135dba937c84183a5a858ec564108d",
        "e06072b879ac79870724288d931e91184c62917acf6a6de33c886f576fbb02d9",
        "d73aae0ae32eb4e9d207298fa74eac5376553f77dde7401adebc8b6de7c81642",
        "3555d3f6ee82ceccd75d54017434d84b75973e3a1945a02b6fc344a640e34c68",
        "f46446998653742bc9c7669110feb8b47d1d3f01b31161be47c0f2ae0a97e3f0",
        "0579e9356e8246d339231eabaf48597d935f85e0fcc6f11ff10aaa9efc030b41",
        "3d224420a8ce7586d16b58faa7b0b83c14415bca882a3d19f139c0f124762469",
        "04bd6ce2b5a282c5470b86fa3aaf993c4d471256628211d40fcf7367e14c2436",
        "5fe261c4fb8cfa285205b600449063556855c17cae6161ab03b61ae41412eb4a",
        "56cd0730eed44290e0716f3e3cd03d0fd77cd116af28534bcbb5b875f8b19a3c",
        "0a314a8355e018bdfd5eca77e7ea76e6b2993677984af386698e6f36b4c784f0",
        "f63de6aa40c65e43493f92489940d60393e45682145b41fa86f25904079a1e42",
        "2a4c96222b4213b75a7ad7070ba4e62714b4798d8d5ee81cbb46153d2ee68f2a",
        "eb81d65b994a088196d55af5f6de918fad4a877a64399ee828b80f0d5c3b0769",
        "e66c6dac1fa19dcfd070c0af3278f4d27b434be7d4458658d8913b48977f7d53",
        "bc9870987fd0a8f34bd6ca9ea98e073b24d471d5f2d011b7bf12adbeb08ae7ab",
        "dc11e87ab39bae4563db46f5fa4190afe3310e96e4e8cc01b798390c284027fb",
        "0a980e70fc0e50e82a7635ed3dd11450b754df9c3a241f1d109b89194e29621b",
        "2d45e5264b4cec98dacdcad16c08f1cb391bb5f4a6f003b2519d8eac241d06dc",
        "33bd2e2183e7cbcc0aab777d73d9a60c45b2387a1e3ffd533adacb9579e69fbb",
        "dfbb3acff2a9a2c0e6d4afd4c48ed4f47f7eaf606e593a650097084d22fe60dc",
        "a29467dfb781d021a47dfe8db4fd9de0bf4c73c612cfed65abdfb69a78e08b5e",
        "c02d2e4375fb918639f970add5460144e518f8d67c7562eeafa3dcb26358ecbf",
        "c1d9bf3329620d3a30116e80fd3011d07cc9b66a71cf1b2fe73e577d5a70d318",
        "cadbfca402734d2964d05f0a4fc919fe04000000080000000c010000e4000000",
        "bf92b76d8455021c41018c3044ca9a196cea17485757c517ed4abf1498734580",
        "695f27dfe8a3fb18b3573ad0be5bddfadd7eecae5a010813fb87ed18d97c3eee",
        "e3aa266146fc3c34f7abd3735ff5cb52dcce619befb4a6c147e3beb86635d1de",
        "310292ff94febd860ce75abb262761eaa037f38caa0b90554e4e36b503b5ec99",
        "fb924357acf0c4b3eece4358a5347411489f7674fce6c3758ad3a56c1f2492cd",
        "ae340e712d236579ce3e407612b74921c138fbdce31a6d86e6418b3e4e77bd8f",
        "5fafdbccb5aa330ec4c003a3ae8a024f503a612ffd549e6328d643874c210528",
        "f9fe11adbeb4859e115a53034529b43b3989c522ba3f408729b96a3294350851",
        "e40000009d8af8da457819113e76ee771c00555ae4e844fdd47d06b467fb517d",
        "c97c4cc43b61d363afb4c12ecbf2c598e5a42d26fac1b965fa308e00d784e8bb",
        "2cf8da1fedce79970be45beb830f9bfbe8a0ff80d8b99dc85e3a4f10773ece2a",
        "4096543c9ef043559ee3ea8e3ee502c700e6a4e6176dff1224f93369f9149611",
        "64b5fda33ac281f35644211b21f85426e6ad26ec5e589c382a4ce76ad76ec426",
        "497e283fcf2d892a7544493d02b7ea3ba1428eba50f5571972798be0a7ec680d",
        "b4f7c5eb9df536124d12e0cf4caf5d1112ebae58b057b755b6e8e42be002f6a5",
        "23787f9d3d61031dfe432747602300779f84b82114000000fa000000e0010000",
        "c6020000ac030000e5000000f90663a8ccbc7147ef60b1d4a007ac9d44930686",
        "e39855fa7b58fb0e1cf1e559610ab81aa303540c8ed46fd5b12db917f2746bec",
        "ff0eaffa29ac5a27ab361ac1a8d7086c96102c28bf0dc89a2b2f907106a9da1a",
        "c09f1aa98d2e53db1bff9484f5e3050154f0eac6606786f1ca578d7a9c324ebb",
        "3910e642a6b530f958ed4241b400c2c8847c0abd43e4dd1c5bc1aea89f12da7a",
        "a1900e0bd2b7ad6f5394c435470fe5f6ae82f1b717e4b1414b1cabdf2a51cdd6",
        "2ba0fd4b418fc3e9ce5815148f72a9502f4a81486b554959171f514a43f52999",
        "36462e5377608418b33327fc0903e5000000a9cceaea624e96f9f56f38dcf6bd",
        "373a11560ca916d563ec68180fc68427972bb7f36f77a71c8bbe1fa959b74533",
        "219f8bb0162f59aa6a8c8fc829c94adbbc0337bd7ff702044a809b87683fa2a5",
        "44e4d5ad54122a5c43bb35c30d5b33141051fd2b1656bf640064df04d3b76f42",
        "5a157e8e5690c697c37d52f65d01ad12ffefe309def0c11a2cb931f6fc979809",
        "bbb90bdfc9ae1e6237ac9be6ecba2660e07f3ec01f2f941f8cdc6d29c6c418da",
        "ba727cb478927074117d878f76270aac0f5244795f58ed0733d403251b41509d",
        "dc089e8e9d8b130b828f249a48abcc088a480101e500000098030770a6cf86e1",
        "1f9b68c40fd6db66140455cb85e90e44052e163cdfa4be3692b374fe9f51a522",
        "14380f30b56845b756a04a107756d97cde45439438fdeb4a8b578b137d196307",
        "bbaca26862d5f43b2cf566b47a4867d563d412996c192a013739a75c7f95f552",
        "c8b65dc71dc3758ff64a8e55ac1485c98f8b4966594b5978eeccf2aae5ef2b03",
        "8dc93c5bcb6d56d51b932c622dfc9507a2bc582443ab9f46e03bdd9c3fc519d1",
        "581736ad6bc2ac5ba0617b723a1da777294aaa4cb15670160ed46e86fd4371b3",
        "ecf6d8f081515b3a556e31c1fd48b965239486520b12fe1d0d01e5000000604a",
        "3d8234ac932111e4f9d31d4afa1cf6de29380d435fbc14e6115d137b7a87b49e",
        "7cadf019dd4cb9b8a5aa2ba1ecd79c7b6284070dae213e28674d9176ff2bc266",
        "508a7ed5752f6cbd19fcd953e7038fe263bca48270a8535a34a1de1c3fea486c",
        "56f4b5ee902d8121df0691a5a4c703ec8729c45ca6ceaa04fda19de7bb91f1d5",
        "ac5fb00cb28efb412a496ff37b8828c9e48cb965f5db3b7b092f7e8c7802dad2",
        "b40bdd5ee2057afdfcb1025760d09934f5a34311d1e48eb5b8cbaef846e11d54",
        "766084ab97401cb9292b3e2cb6a9f56b0ad5d7bebe4e2f26c7e169b176ac001b",
        "e5000000cd37fc26e1428c313af123743427986f49b5cb980a6f434f05669f03",
        "468cfad5792a8f268cf423be5bf038fd6d48930133dfa607cbbe481cdcdf9bb6",
        "be0ab0c6e51e05b1262422383aa9bd03a89e5eebb9e6cd33e117917190f9b841",
        "ae110b2f3a01ea70d6c244bded5731be05d45613f6e16a49df510381f0628421",
        "292629d7ef5d131bce12b86a4ec02ac325ed0a324165610d4106390c2a1232d9",
        "ab31185a1862404856bc239a72ceb1844f931c2c99a891c4e5072b6f36246542",
        "969c60b04334d2d0662055c327c7729cd6c77ee87183d1babbacf820e7e37ff0",
        "5603101c05043abbba5c8c6025789a30d59cd5c2274eac0a2049a8c092d38c21",
        "0168fb524e31993249c9ee916d944fe42dc520797803fb1ac87f633b74541e11",
        "86cbcdf5152b15c9e49e251b094306fab467efe60ac0e888ca9546e5175f79e2",
        "437726a62d21fddea941319d8f59a38d21c9ab71b27b8ddfe00f009040732088",
        "d1e3d28b759bd28191d124f36f13a950ea5c83bbad5a33036d3303d8ae5727c7",
        "0288f73187f6292d440f141a51ff2a970e328d70b57b2f59b2052cdb3a8db6e9",
        "a2f28c7284ca47301c400cbfd01715714063a37fa4cd6e100a5ba5eebba2dda8",
        "5bb987965fd15e4375c5d0db7e59133efe49c34d0e140606ffe24bf38d0db27d",
        "ff474aa97121c63b7768e7113df550df6e3fd69084294cea7cfaa0863bf2eeff",
        "640d0c0788f679598baef62cdef3f17e0cf07758d44fbd569526822b7773670f",
        "108ca12a99ae96e168bb33b5ce5ebf47442aef39b70145edf972b6b163b36bc9",
        "fa3410436690e081eb4d5f743408f23d9dd198532ac4f2488b5f5c77d7ed00eb",
        "9bd772d4fe775c520f7bf51a8a8ed3193fbfff4a70135f13c7276758fb78fc81",
        "e557a1ea99c19c8aba87146ae0b0ffd19f732ef430b65f676b4ac4591f35b7b8",
        "5a4be7443e7ef3fe7be0f187a2ef3e443bac7538796fe49ea51b50e5cd6d67ed",
        "6b654b86bc82c80aaf80ebbfd21fc01b88c85f9ba392951ecdf14b0d26c9b55e",
        "95752b5a36e14d57e2d1086e87f3e2ddb5cd57535e70cf458e731a5a0b34502b",
        "8a151352d3070cb64e2500c359d047e7f093109eeca0767e33856a8376578ab1",
        "cef376a89cb5b1db625397d494c313b5cfd2de2dd648627014c090830318866d",
        "b40fb7efe3e6967228dac5a41256cc44429f0d2b4972398b9c4352ff2862dd1c",
        "60eff6b19f2924ce8228aab0327e18f61e294fbc66a50dc26f6a5c86130df6b2",
        "e7df8c1db8e43c288c35c81d3e42a03a9ffff8c68cdc7edd17ac25cf760bffc8",
        "0e632a1febcc95509eeee2c2d0ba1b66be0408b8731d40d4c0932b5733afb936",
        "7ce3bbc04911351df482354b8b828885a6091d6e6fc1b9a61ddf2ef0d2d8c000",
        "32b3abd230c5bf2b2e99c0fae8c757e3d3584243319b78f126f296f359b029f5",
        "62e620e7c555c59fac32ddcced22d78f3841ffac8b1b4141e0158fc72404d144",
        "b54a77ed16a67c3c95bb909d26a4c5a79b7fbbe9c1bbd500797a34d0a99c40ac",
        "2bda9eae23106db94a203ec9d7e174ab9137bd89afa79da559d66986780fc5ea",
        "268f97b7973005461b6c6a43abe14c39cce3056c4028c14f569626d11cd0f427",
        "f3558e583de01a24a27e642b9055f01cbe88d49b9f510ad0cfa8430637def869",
        "2b42e903da7aa9a7c520e008b4d98cd0f9adf3d4bf70820948349701da1c5ea2",
        "2db8160ee2684b3ed35c85584176be36dbe670fc43140d8266c9903b50b84cdc",
        "4fcd03d100ba7ae558f3e754fa6f0c393efdbedb3e59194f79fe91a1106914f3",
        "1a096a719d6fd339278e37ccdcfa318019e751a22ee29b381aceeb9176abfd3d",
        "0f10c65e8dd4d519cae13400493152fd6f65aedaf6f467833bc260eae9db68bf",
        "3624c369701986e964ef5a138c8067163180777b8152146fc2c84d4f2ccc6c38",
        "236e30d127b6dfb78ad3a23b3f68667c60beb069f92f3b0f1f74771f2ae932ae",
        "cbceba4b9994bd618855a61cf58a053706917491ddf0ffddda228424410de772",
        "6a243250c90585d59361fe3597c315c91d410b450033eb8c707c20fa7ced2ae0",
        "295645567b35c634c3bafc45b5747bac5166b1657bb8203b24c166fb610045c5",
        "92f3b2751e8c0c2d86ab9961a3896b7ef60714247c3d0a516323ef0b6c9f036c",
        "557da744a94923990e84de442dbac3048c1ac1b8cb5958033e12097692f32704",
        "61e4c4804e402e7c2038951e5e81d867bd9bdd0366179ebcf5c06d214f67b12a",
        "06224ff4c41e0c4bc2c390884a69e86d516bbdef12152a9a4873de0d24419abb",
        "0488075f83a4adfbd1eb7ecad6d1ac086ce06fc83848ebad84416f68166a4d9f",
        "a0ca5a0e2b61cb4eabc33de9b7d4f4ce89e7a58d4dbbfdaabd9033c57ddedd8c",
        "7c830968533a9371f834cfdf4a808b2ff66a88de4548ecd7d5ff0b0b932d27c2",
        "a6b7ab97ae62a5995c98bc821836d6643f91311441b83657b0e8c898d5e0f436",
        "d8ab7bc43217eb4239889bec3924a91c88346e225d5e5c8e741f0d44ec805c44",
        "71c0c29bc5606dd9b83e0ead84096117cddcdb235c1c5a564cfbe9c442c263cd",
        "b1a8621908dfc270baddb47480792182856228f2a86f018d7aaf47f4f41c4348",
        "71dc850299232c9fa3369f72e5d0c51366a2906df3ac697e305536b6d3379e65",
        "d4244a6e818450dec5555bec920db7aa078722f40c400078c313261fa9aa4d90",
        "6b0a7f099d235ef9e9e961dd062e6400000099d4a491417c520d24b2d2e4466e",
        "09bb34853a8acc581ab5742fd7c7a66162f1af60001415c8674ee1faf50536cd",
        "d3a7036b4c3ff9cdae94ade51162719243f57d99a6f1a3e6e85c666f8417d69c",
        "aa193ff3aec2bb4fee32f7edc9b6d601e9e53534082d5d5b6637f0b13fbdeeb7",
        "f66b4ab9d46b6ceb3e4dd968e3b7bd6ab64d3f5e8b6af7e364cdae0340289240",
        "3c705d1f3f835ccc12b07fa45f516e0a569f15ebbceb4c430c7ea0800beb5971",
        "bb3e84e9a7145d4d147161979302fadcc784898e1a86c5fbae9b39fe99feac50",
        "b754c96d0ab16cf4553e2d7f3da18ef9212f1f3bb0b23d4ecfd15dd9cbedbf8e",
        "bf75d20568494579c6c5c71168ea3e58f9047ac535325132342d37e0c42d4355",
        "e78c4d36d67167a598e29c11fa92e00000001c9a29bac98e3ca2cbd9237fccff",
        "292a48723803c1b5182ad1d9a386ae92c756423ad52c3b87e256368f173f09da",
        "18d40271a903c762a8384a5de5486c8704726db47f6a48c782ed8eda9a602fd0",
        "15bf6353b5018a562e53475a8a3e0d56555f96801138664969646867d22ea2e5",
        "f119ebf1db642a9974f45023e8a345ea93b13e2d53f04056a60790e2e1dcbdad",
        "d03e5aea63de0e7aba6eeb64b09f48868ee7fda1aee8990c120620ebe8653e66",
        "4090b6499bd3cf9945164a67678a1c9bdeeaf9bbb5b74391a31f4a8091247074",
        "925203688cc5a5f421851490005ce93e8f60b18667498384a9baf7f0c0c67817",
        "6010fd5922b94a5db960e628ea5807f7ef656ccf26765a0eb126c4c12e2d2f9d",
        "1a9f5df88f3825ff2331849fd42e9491b0031783f11349942077ab2006216be9",
        "875de44e78a8d0706abc09776f9582132b1e29badf651e1739c5dd440ba24671",
        "c02ea8f5e903a88a4cbf21b3fe45477484b2a6fc615a16f63b2d54c483551560",
        "16c4a61572151e9dafddd4326bd2f092bbcb876db1990c439ffb0712204d2abb",
        "23af9e78446f6bc362f2ee12bcf122186d1c3acfb4e3752219d7a9dadeaacadb",
        "6cbb9306d5120005f6885e1a31a5e274f9886615a954f5710574360735b55f35",
        "efe30d77acad1fc03e3ba3e90d837e293440e7557bf5a2b1513f9cb8205bd703",
        "f8283153fb2dbd75c4074a940100950abd8556f8722b0040bfb03d3427b6e0cd",
        "c3014fe9b86d172991f541f62cd0bb8a9c4a0e7d543fdb7fe3cdca19e00c5ec3",
        "3a84b601735046080122922b28903d201418f317d7825a8b1dac1ba626b3cf7c",
        "5a7f7f05996cf90793f199f68f11066d29c911d413241b9f7870b8964110472e",
        "12197c1e2127e3db245a285998591262e8b68c8251330fa600007bb2ff82691f",
        "21c635531dc7ba32145b9bbb42be6c108049e45cc938804f9fe081383c58e2a5",
        "b9f9351c0a38540fb75dec51cd1014e36c2cc638c4fe8007b47837912b81ce00",
        "e57b27f4319760734b6716aea4d207772e45d4a269200f7f199f140000001403",
        "0000440400002c050000ec0a0000b170511653146bdd5b9e9b221b75f9a6972d",
        "3981d66de31ff7131975147563db1cac7edfeb7a7da968fa2b68c7f064df93c6",
        "bb7470ee38281c880a2a92155adaa37ac22473956e00598ac66b1f2a7b47b17a",
        "3ab80e25fbabde0f4bcc6914041909242aa6ac410d09689b96a9c74242129319",
        "e569dca84564675fdfeab503a4fe18dd085afea2e736726d03938a970ea30720",
        "82d6ee0d0dfb3d7602d4c8e268e271c41af53e4097cada6cc11c92d2ca141430",
        "2570ee4c877ecf1f65910ada892ad0bdbb10187ae70c1ef3a4252f9a974085bf",
        "df01928aa4b2569c581c5793132090a6e26bf01984eb2680b31182b47d76acd5",
        "af741767e4c8b78488aa8c6c3a45537398bf880e560caaf275ab69c4048c9f3e",
        "8971a58229066ca8d459d7955a5a29fea8d057cd6f7cc048e619d889f40aad9f",
        "75eeb197e16d20104e04a0833a2bb6eb03d1f4badd108c41ff4f04c98c935399",
        "523371bd6f1b9d9233e69b844147c6a16cb655b592c4a46ef3fb6c6a5aba55cb",
        "6cbd9515e1817f9b8acbe3953cba38f5e77659c8e4e5e5d6a515508b4fc4a7d9",
        "e3d53a9917ffc6a09becc501224c6471a52078aaf382a4aef7f5c2bf163076b3",
        "d4a30ed67e6b2d4ee4726b788b18ffaee051bb2f95b5b376bb52173fab4c3af5",
        "42d45a54487e92cf8426f2197e47e8784cfc783f8d66e67a473ee0b29fba6444",
        "d49083b64c174d8914f70e0e1a539acf5a8141e2ee951637242c8be2ee4bb6a3",
        "46668635b5f34957ed4260a8978c27fd3371cc8ff721c3e6a60deee5218e26b1",
        "ccb3f85fc2f5ecacee58fda19e502c0d142fafbde5109fc00e3890dea9c01451",
        "1e80001711dbb1f75a24308695476b4ab65d2c32fcd6a63b80a08a5a67c6a727",
        "1c3a3a1c370f74f3f33dc2eba85ccd1618d268182e10366022b57996bc2e97ff",
        "b06fb7e84aa1cd29f461fb47a7a08c5b82793743a22d6b0ad6947ff87a912c7f",
        "ec42238093d02187d4387379546c6c1c49115f5a31c270b0f39e1b01293109da",
        "eb27208928341141cb17c63a9db19ba88ee809d8083700ae6871a919f2fe0a50",
        "822b559a3b88aedf3fa5aee7a3d61a8d4734990791265ef68ce27e916e53a9ab",
        "7640e8db91ea672cc915a121ec46d1a1bd7644732392d430cf85d8c0a657364b",
        "69fddce0d64b7277bab9f5717ceffb022cad10d3a47553bb5dead52aa02a8fb8",
        "0de33d94e88d8801b8dec4c4dc34788933dd2c9472a6c3bbe01aae7f0e0dd998",
        "9af3732cc256f712f1f75926c64066fb581da67e943d81eb0607b318044de33d",
        "b5fe0301f50a636561f8051eaa0d81fbe447c69d3096a79bb000e87928195e18",
        "b09e541e969acf468fc1a6cd6c7b8b9a18be1e526e6df686d8a8d20f4896b1fd",
        "9e68091f9274cff6b97c69b63dfc9e1a94416910aa76bfafbe7b50100db77dea",
        "b767e8abf0cda7ab2211a117e9e53f88bdce7e2f2006e7f39c04e69a3f6b642d",
        "10685502de40f9b46b5a944b0b8d5cc65c98c4b796c215fc33724390c3a03b1b",
        "ba98d4faf70450d22524e975f161a053e1588296788713e96a9dca884accd4c4",
        "5c069ffc0438433ae4c760c6c3b91fe82947c4a3e00cba105e050ada6fda62e3",
        "fa762f5958d57cbdfe0f165ca6df4d3a343f308880e0d8a4804b945116b18a4d",
        "60bc586873d0c62f85a4356d1c1795be11368f45b51e4b23850751c7dac8f7bb",
        "da47619eec5a0742adaf0b91c607532feab5eca92e2fa85321584c0f64819298",
        "5bbd4c7db982888b1cfa2a241c9dc9786d26a96b8f193f72b3aabb5912e13b45",
        "14c43ccb0d825e8cb0f3dde5f9b1b6641b08ab4377e0fb7d97b768b0f9aa1637",
        "00892eea16554e6eb3d3b5b22e0add3e5e6707b6fecf8c6e0f8efc11729bfe17",
        "26fa35f3813d983e0d49ef4160a3a48b93129cdf016ae55c0d83b5a173ffae4a",
        "0df781f531e2d1af322c5d3589c8950caf74510a6596984b0ffc64536c712549",
        "f4f6b37371c075052822116a69dca7e21b78c7553fef25dfa762c401aaebbbc9",
        "8aefd346dd5bfce46e88912929a065446abfacbd6e893fe82b68219a3803bb71",
        "c8e0971e2782b017be57c9953bb4bba079b3768cc33faf10225f2a9253d5c01b",
        "0204a47046b3d2136851a418b909c58f33d146e097a18dfad5ba3ca5d62cb453",
        "59e9496a160e03e4b5fe099db6bc3d191c94116094512ed12902f04ddf79190f",
        "e65ebad73bcbfbf4868295d725824319ca07a47074e10020f480fe92445a47bc",
        "ba521dd54241e85e1e2b62fc04bc86ee4ce1ddf76ace1c127ae704e6a5cf9164",
        "7659e4f112598ee0b06bfc21a1fd456a3f58b1c3af3267eb54a5f366c3527684",
        "7b817ca00410ca14e6e01969b4d0bec64df430ec5b47786ea77c33a66b0052a6",
        "fcd393d4b2429ead5676565e1a9861f4aefbb3e4e877a4a5cd6012e60b7fbfc7",
        "2423b727047b05637ae7acd6eaaca19f1bfa1a9ab14309d9fdaff6d9d6deccd9",
        "8912ece310de4e2d98befd70f0ea3e9381de1335df16b13ec5746230f7a62dd5",
        "4dc7bde7384202353b44b2b4d1df815805a324359f57c450b5d3773841828011",
        "27d00cca487987266edf41a80f930599c28a33c9551646f85878d5809d53c97e",
        "442226504ace69b6e4728b8bc0b0d76200bc5bc3647dce9d6e252fee5e8760c5",
        "d09ec755d8f1deee24e7e67c38fbc154d83be103a98bc5a29bc3a4a8360ebeea",
        "3f4761c8d908981b8c1b7d76e60a5414d31577a3452c9d458f22366bdb715942",
        "bdedffc8fb57609818f72374e3eb90763c078aeaf44f60c566b618d514dd914d",
        "14ffdd210aa246d3d085fcff489e5e6d76701ad8e4fc44b1ac8f20da0c373708",
        "fda152b9b0068432a33ad4115d48ef6fa0c3cc0bcb5d08ea9f6bea49f1e8ebe7",
        "920211b64a99aae03c188c68378a792ff8a4d08b82e8b874ad472ba398572f2e",
        "40ffba6329b32fd966beec0079335b915505dded87398b816c45dd55d5d3ca91",
        "dd229d2ba5904dcaacf4f10e4a067b37b3c9997d7c06c31d70e3ec3cbaac5fc3",
        "4ba7b706e08429b3524a31294de974a8f9a8e06a5d753bea6e85d5bb4ec52871",
        "af84821384a45313bf8ee536dea16ec37cd5a5036a0e15661f8e32dba68b0e46",
        "2b045af816e79a47d50b0dde09fe44198c92c24421c855dc4342b531e43e2da8",
        "424e78340bb0ff8f69d313a1ab101199da3b6ca3f94865d5a09004666a0b3ed1",
        "dda92e1385e6b5c59e1ab81fa7e996a9cc6e8ab371855ce6153ee3184fd02f27",
        "b703ac9052ca2802107c4a79618f0432d8329c4181a9dcefa1c2ce199bbbfcd1",
        "5bae443e9e68a310d1a0b84ae8fda1f6542ef665a526dc2e4617c9bdfa584bbd",
        "a55f2fbb00d5a1153c62d4063deb2912f207f840d9399355325be73d0099c363",
        "cdb1c2830c8a10719daae203c70b179439bb07bcb58ec98785ee24f1a6e08fc5",
        "63da496eec6f14de0b96101eb2770725577ab0d8376dd9cd3eae94a27b91551f",
        "528873a30d8d0fc07b156209db85afb471216ee062e2cad12fffa48516d35a6e",
        "b4417095398a7d432e35f9085ad33a07122748cdf1ddb94a0b3f8fb755b44373",
        "a2e2ff3616b4c320058bb61e3f8761ccf5496e23df49f51ddfd728d24c88c60e",
        "125dcb2da0725b54fe54ff677eb260d209bea09aa1e2595b3ed31070b5963632",
        "9223f965c9b0c1660a1e7a0f011f9a011684053ebaeed6ce25bfb63f08e1d2ce",
        "9805c19ee82c403d6177841b11f2f8d2ee4ec581e1695b223d135f6c24084ccb",
        "788a3a183dfcb188e8c0dd3b3ac64e548619a7535abfd038637a932abaf222aa",
        "0396996c4bf334d24b41a3dd1b7e1c517f43a370f767e6b85691e13e0e41517a",
        "e9e9fd583b069cbd4a6a74a11a016c5c93b2e3722dcf5d5af211af5cb433661b",
        "a01330eb694ac81f86e0af03a08b31091f5b792aa28f5e84e983fe2a5dbacb17",
        "3546f2d34dba",
    );

    /// Official `ssz_static` `BeaconBlock` root from `tests/minimal/gloas/ssz_static/BeaconBlock/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_BEACON_BLOCK_ROOT: &str =
        "797bb319a7a349213dcab18f6145424682894193e2fca77ba748b283e5353f52";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlock` from `tests/minimal/gloas/ssz_static/BeaconBlock/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_SSZ: &str = concat!(
        "e660b4fc61df435b09337c387df334a1e07720bb309a28e66a3955e9be54aa6c",
        "0885b6bf267215ac2a613a21df40c6253e1866119feab62b1d8acb7fa8de46e9",
        "6959e93deb8837aa109cdd419d3ee0cd540000004fdfae1538b0194c6cadc8e6",
        "ed5a2229842511087f6d34f88b9f099ac3bd510202253f08c75d9ba04064e712",
        "cd776cf2406253925d850beedfe2b907ef0abc623aba45e51edd48136d88df54",
        "4b6a27f72967d0ba826bd54a73255aeeb3e2ba71e48778f5bf442c89f8ae5ca3",
        "2e68ad1bd026f155fd3d9bbeaaf2ac1546ca5d00daece806285c9afeaa9675e7",
        "ec430611a52517b553179f56b3d73b619cf4f0a2bf3314f0c0b985f70bcac7ae",
        "052edbb28b845548358bf6cc43991933ffe64a7e5a6f332a383d698550010000",
        "500e0000500e0000b6140000b61400001a5db21f53f06e99d28bfa7565a41efe",
        "0dd8546e32a030b4c0d44d144c1bdff67d7835e70be98cb4535dfb1a5f987af3",
        "0d72a9872bbd361b92c70002a140848adea8d9c127552ff4f602e09819093c84",
        "35292c93e8484242da9ab4b2b0a339823598cd729615000096150000ca170000",
        "fa190000b1625b1f79c4e9ac1e17ae447eaa5e50228dc9320e522ae24d3b796c",
        "72a4131385080c44a7999dca2c9551f423854089bd294978062aee7d86dd40d1",
        "60abfc664f249cc71f9fdb42d5d3626fe67cdc0fc8e87cabef960da96a89a89b",
        "7be661b47f30613d9cea83b6ae64897b615e418b8a4a20015248524f29bf1f72",
        "d1ac25b970a48bbe1379dc19fdf65bad648b3b650bf475e38db82c2158bf14be",
        "8fc806b224a2e5395d7bb93d0b4d03637a8c6999d95a7af57332ddafae37db0c",
        "139c6553ff7eb6abd353b62bfc1aff0eac368c657b3a3b49b837449e1dfbd00f",
        "09343cbeded1130f6b6207535f8f344f47a1fa4e8a3ee22490f62e5a1d5841ab",
        "b1d8472d8ca6532627b594264f47492edbf590dc4cd027a2362a672f37b76cf4",
        "77e196b1248c8046b517024d65f70f241f741cd688161536a33d93174a709e4c",
        "3bb85cedeee99debab129dc7ecc4825ed223adaf97c33cedaa690fff4a65262a",
        "c562cdec0e1a785300bff0a3686a99e04b2bec4d3c04c638515dfd29bbb8ca77",
        "775d5aed74fad5da0b5c68d4f27c07e53bafc118bc85c2324c5797679868199d",
        "d064ecbabf89c427540d5c162979116b044475530472938431582907af94eeee",
        "f422e86c3d18f24355542b800e82811fb8e3ce96e321225939fe84564bcb80d1",
        "8c69f1b8229342b3faf2f7ad2cabf0ccfee2a37f2e823ec9a251d67eb1d7f9fc",
        "33543637afbe7f9bf48b2b8fc1cfbab90ce1f5278420d76d22336372b779840c",
        "778d30328306f14f50a4069a2b27faf34208472ebe487d0cfd06ec334430dfc5",
        "19e5084f65a5a16a094ebe96d83da37a0203c34d94bbcf11985e6f3dfe707f30",
        "d39cbc0b1dc0be69d3540c299baecd92e87f0a83fce6c6a24af024bcc377e6e7",
        "2000a9fa35a07292cb7f69c964563cc3d3954e32c1fc6baefd9acc331de15411",
        "70779ffd74c417759c37c00e707c2e07f10e7650691f328f23bb28a48857c073",
        "4a5f0be820feca4610e9676e5044e913b137c936d65a5ce8291a5dd15136706b",
        "10bc16731e332ff2c084be55c7fa2090ec048a7a4c5045267443e3c4867b75b1",
        "13021df354cd3991e50e8c4b9417f96d380ad582da76e5f2bbbca3a5239a433f",
        "562c003e214e6bf3aa612dee7020ef6091cfb3cbfa671037ccff20dc22a2a2c7",
        "a0f7a639056a1bb4b465ff0dc5db7fabeaf0914b01a75095a267753f9fd315ea",
        "c5772eea1afc67dca044142cc3972f93f80491d9ef654cfc8096f2949158187c",
        "70ff9e9ee644f0386313f24785ad7e50ba6f09b662c38563be85f48b8c8197bc",
        "8113b00acfab8dd22a4532478eee063946877495c310fb764ce2ba99ad5d59e1",
        "e37e5e822bf1d22f0193ca78e75eb38251524b813fd474d5af8b1365355208e0",
        "9700d92742c11e8b800d8f4dee9cbffc648b4c4d07f06a06fa6f052a5e71cc4a",
        "b25be4cadb013ab6f5845bf9a8e4a026c81a809fa118e7ff7e5e02d6eece3fae",
        "962006e025215f89867d7e01ca2d0e574007413a7e5db4f7ebbdd9d06439461f",
        "dac87558c737d03f23ddcec38859b47b317936eb9ec013521115e9deb8c4c7a7",
        "c6a8e29e3663ebffd68875aa2a1d7e04bebf0a45602ff5d0571a345b9c31c14d",
        "69bc3d6d89b44d9eda0e205f35a160b8f81aa7ce9ab6bca9d80f1a9784d25cf7",
        "798f74aac7fc5655dabefb011dc8fc3250d60cc7309845e855a40889acb99905",
        "a729d7baeae2fea355ded53aecb3347c48adbb7ea7501fa936c08f4b07b356e7",
        "7cce69f85db1857898c1f41056fe02fca6e1ae6ff92a3d36855f8d59028221ac",
        "e17a5cec4347b7ac7a27fae0f41257fb18724b87e7aa1adcf2f4fa11d5670cc3",
        "7fc1834ddaff3b8fd056c0b4512c7249858bb942310933e2d679450cc1240655",
        "d79d5fad96b2ae46c984ebd850bca4fb67994ad2702dab5544721d401d2bd205",
        "a9ed8088cfa80562a73824f9bab8678d89e61e774d22fc4ec53c73e7e9fd3b97",
        "0845b29219471455bce9899a50544b70f6e566f1ac376acf66d5034d1bc8a659",
        "148dd4fcc18da9acdeaaec50c00a6038a3f0489d9e4b2c054062a0d57f4c8d2a",
        "f6f7bd3da0e864fb29d827813d187b412af0c2b650c400052faab36b10932d65",
        "38756adf024bf825ac124db89b667f3c030fdd3b58b6324013a0683718144737",
        "8fb3ab4c9365df13d6fe719d4d22980efba5b36101e7aefdf796acdab1d3636d",
        "53d806891f3d81188723ffe9035072f4f8a3e3c5b08446bedc047ba133143f9e",
        "f46995180beae3f5c67fb0ca00805380cede320d23d5d68d731b5e949a0f6407",
        "0fbf19287cfc4f9a0e6273b4389075a5605106afdf1cd8ce5bfa2e9983306500",
        "56e199036a184971df225598da5d21224ad60a630b6678a6b100254c27160143",
        "d050695af61e09890044747f4d359536feb86c5f2542fa7cccd1ff528757603c",
        "17c0baf4dc9090f02a8ad2bb2cd65c7036e1d14c4154e6b033579075e28f18be",
        "3012b007febfaa61a6d155b117f5944dc64e1da82eaa419010bc55a1084d0041",
        "1e3d8a0ec41a27c54ce236b5c2590277a8cd897422efb27131917a42c56b7082",
        "01b44ea0f3823e5c10be19c66a3771ab864a4904a584f0647c83dd19b26433ed",
        "110a49daf3ea7db4229d84414f8491b11603a0cb5eb3f565065a7fbbe1abe62e",
        "a779770a563d5b18ddb5b1fbf22cbd38326cbc6b40d6dc7005246474368c411d",
        "067a244aa7c176940534c332d442a878d61a6a9ad2969165f8034f6b40be8d6d",
        "4312e07f39ccfd6581570eddc34f4f4d9b129b50b4448365c87bf8ddbdbe1d10",
        "e3cc55bafe4d8a4e4864fdb10fb2787ebf6f9b01f64ebf688fe2245c5981bb4c",
        "8b0da618fabaadb69492fe8892320693155d43fcb8a8c6f1a8a41e0909483f81",
        "f9606edf46838269cd7ae4f19d6e6b2522e9f01b66b16a9bae61b29f3dc068a6",
        "3ce4f059071a84515f50c5c0d164c9eb1195d426882ca56eacb4f76bb470e329",
        "bb589dfd01d03e669674ad5a9231f4ec7ebbf4aea42d50ea89b2244270c8b51e",
        "20cec4323089146a9e0cf4e725ce7f6fc89b9c09867dc63f902386211d171f0f",
        "93ac8c9043ad6d27329b8f069df2c5034cd39a440b9d9d09cece0d0a413f9b13",
        "5094d28f6e8ae0e8cd0724170c2a4ba53f835bd8ad90d5ec5762d9d2cb6cc95e",
        "f5e0724de36c77be95d8e7251de7879c28682d1c339c555a650eb78f129716f0",
        "2b03fc543372db2be1c7df3f8685233b368c8722a692d2e191c42ba2c2432608",
        "a672f0e6bd3f3315ddcaf9dd05557f76eabf7be624f07b71b207a6c9fda79a27",
        "084eba8d0cd659aa7a7279edd2348f43509174807da195b3e49834d5a49f5bbc",
        "8498cae52442a68002a5aef089d09dbe113e8066be51b8d2ceed4d6eb8395a24",
        "b52662cae45e3e2ddb21ca4f0f1a46bae5cf39d2be191e14f897a58b2ed6b9a0",
        "31650fb6ff18ed0019cad5daf228d6cf4b4a2187dac8ba5699254114af95adcf",
        "851fd35fcb7fd66401469801f01655b23cd2f81330f94e5bf4068a4041033efc",
        "d51e3cf7b0cc7aa86f4cfa3ea25f5e28f462555d76cd469f40edf3b2e1067037",
        "ad95a322df9dd161992c3d55b57a1f07634aebdffe184d7147114e2da6f4849a",
        "f0d89e7f57c13e6bd5e42be56517240f60143b42967e01ebf1ef75dfefaa72d3",
        "a519210be554806f6ea7a4b2d9a056a1e8f2a4224fd81c8608d81a076838030a",
        "70c61aab6bf5f9071ba751560e2e197144133a34d67529f24048faa441837ceb",
        "c42af441f23c5fb4e7cc7cb37a9d33f2858782304fea2841f444d4639418fcf9",
        "12bd3343e4bb06d59593430b5fe481e20461c1b48a7f5e96b9dbc7548e560c6a",
        "681699586c6dc2643dc8b12cbaa9637ac94119ec1c4b1cb73c4e4d571f2410ee",
        "f6505fec2a0eb7732d473bb15120a6552a319b713001e4268358a64f9c7b360f",
        "0ad43134a4d89dfaaf2d15b7f3e075720caccae3cedabcb573ab5cb883ba8d26",
        "91f31f8328e881526fc7be8da36da9b848781ddd6bf36a2a4741f1da7c3c9154",
        "07e018e1796cfb5fc8fbc3590a7f26b485293e7f8599198360fcf8e29398d023",
        "076583aca87602c0409b6d2a7323bb47895440cb58a3e8069efefac3b77616d1",
        "5b751a20349d7a2d61b42db5f8f7f7af6b6dc0c127e6882f88c91485f7862f62",
        "80ac8dfafa0eef982ccde20db40428218edd145eb288be764577bb43bf598610",
        "44ed7dc90180e324a1a1a8725c0aa4a4a8f0aa53eb0fc2bc02cab4cf1269d11e",
        "f2cb200f1ec11d3a09261b425960321acf2e3dbb82802f0b5a6f088237cc43b3",
        "2af7ecb3712688a5f3dc8a9408d186e8bd156bddc451c08b53137d971133e324",
        "3d69a192021d02e49e682bc889fcf40ab020975c88d576deb4f5fdadf7eb988c",
        "a07b0a14a4e405d5e823417f9a33f9ad28209b509a92614f270df41581de5fb8",
        "976549b2898c47c8dd2a31c648a5fa9c9a9f62851463e8018f22c0be9bf6aa37",
        "9e05c01fdbc234110d620e7b3816dbbe1683033ecb0d44df6c9f89cadb83264f",
        "26a223bf4934a7c4ae9d71c2d90fe6655c40b8b659ca251a289d5d699c21e789",
        "d937fe0f160a9dd1c4c144390852327040564d17430af41cc07038f4aa39f56b",
        "a8f35632ac07d97d721b9cfb266b53a1c23e660a1370c57a5108f4112ce46de5",
        "b183d6feeacc8dd25ac7f342e79c3b80470b071dcab5124491e2b8822ec94633",
        "462e4e981c00000002010000e8010000ce020000b40300009a04000080050000",
        "e500000087bb463b290a87ae63b459f7eda354c28c79acbdf60b52a9b6b810f2",
        "86e0209925f02a8e86211d26381f8696b1c460286c99bbc04e4550964cf15c4a",
        "e70b6c98bf401c1b407c4ff5185c8d8f826f9fef9e06b459da410405407d3c37",
        "65c8bb4a44972211d99fdc2427fe8daf06d53428847fbeb8f89cea403b5d6193",
        "4eff626fef6670bdabcdd677dc71890feacc6835fbde981028dac60f8de5d589",
        "b183538715407388975ce0a44fcd3c6f219edda9d311c5881d292e782d1275ba",
        "57c44063cb87d49c80baacf579940a17494035fd254f45a376a9440e5ddb4520",
        "7cb7e5f30602e5000000c5207cb6c0123b2b916d776f52285fd2324b188c5034",
        "768251f82d716f87a4daadb6ffa48a335d46c8c41d0b7a1941b814e9a3a0211f",
        "5400b3d0845f8437371b12a46fbd5599f31ecd5fa6d35acaebfbba7ff59258be",
        "032f2e5b6bdae8a819d62d5c1e86cd8e6975341d0a6a6e05545f05d3ec70ee69",
        "746d3394e55cf6360efc55ca775aec232f9900fefe951c8a1ddfe6f70d213bb0",
        "d9f2cb2d6f3fb5f9923488ca3ba5a277af76588e37ade720b25d287163417d42",
        "a7e432142233202bf5bc9ee2d46cec0997752d178d9b86df4e525f806f694618",
        "0cf8a140f341c47027060409e50000008447ec1704de16ebaed1c128c0081270",
        "5e1638f8a651d369588286eaaac093255238ee625345f4b619241a0a34b59344",
        "413ffb040e62e8cf92e5e5ab020d7e84ece273a813550cd64eef0cbbe5019a46",
        "efdfc4e58a382db30303a7d2c4f899d25ff74af56d310f0f27f243e9b0605f6a",
        "1d6cdb59413e5a5cde2fd7dc89b0dd2f02b7c44635bb7a60a013a2bf377472a7",
        "935e1d678761d7427f6be4708741795152617ba64e9deb5251db3d28ce66c88b",
        "a1bdb590ab3891072a754816f51a48aef7d26b1d3c5032bd3ae0cc1579a5ed17",
        "e4cd52a0e8f111b392e2433c1c9bf4b20703e500000046136d42d5cc149a0647",
        "8ce978ffb144d7f78d4864a1bc3ecf59e745d701d4de6fb5bbccde790a6bbbf3",
        "4f579a49535d22a3ff5bd69ff289590332d8fe29ee50b2e3c9209d2a5a611602",
        "225f45f0a9403c03f22d09eeb0b8a0648b9df53c1acd4edffeee27a92a8652de",
        "db3ffc35f86268b6582e146fad5bfeadce8a5e42cdc747f0a6aa6387b902ff4e",
        "ff7c4ae9a66a51ed12a41da15f0f6ae4c83d0de7557a377a14b77c2bd35e2b31",
        "cd82cc8e3e74cc18de8c82836daf8a791d51b66e79480c8b2978f70d0ce335eb",
        "8af9540b9af4dfd3846b9597e2c9b84ebf5c5c98b1510b05e5000000716b730a",
        "54d06006ddff1035d2b0ae517a4098aa3884d43f3e911685e4abed177686da52",
        "81d9dc7cd759869257cefbd6d3ece638a39951452bae022e95b1d42b8fdb9d3f",
        "fa9d4b7b6bffb731d54f639f02f995d0cb4c7021a6acf78de1050e8a959f8820",
        "c35241d99144b64376ddf1befab2a952cb2938ce983369177768322f24c98b06",
        "22cc2183053270d2b25ed6996a0524ce94389c04bb4ef8a944bdbe139786a4d3",
        "5e56b88d0a69109eea7e16eaa338f79ffc1293eeac8e7484508dc343e0879329",
        "fe63fbb90976c4f0888a891d9fdbb38c5dcfbb8c6cb936ae24db78490f0fe500",
        "0000187453db7b7a2ea19d26cb8f2d0b72dc4e6cc7e418af581cf01c06189fe8",
        "e379b77566c547cc00e5145dd3c740f5004d70230378736f4cb5668e21c20cfd",
        "0e5dd7d7d55cff258bd16668f824f6b594a92b23b668e2e4bf5525e5fb0a9c06",
        "aa0e0c4c9797063d866af550186f448846f3406f2e51759606d401557cf69bc1",
        "2ef5de7bb3479dfaaa2fa78ae031b1e1fc3240b0dd86de331e1d86de43a18214",
        "5c6f0f8f2382f14a4949e00fb449f06fad571db9d8e67b7e63a4af01aed33d92",
        "89abdd6bbd2043302b5be1646b56cb45168c70a9d9b88867357c3829d16effd8",
        "1bba0f11e5000000be11da9d85745ecae0a747bab150e8f653fe3f5bf94dfd66",
        "57757dc765c68e4c01708818393b3d09cea4b76547005a3c5a650d86b3214463",
        "e85ddc753c9649e71f90eab200da25c4bbac3a575efa8af536187f784e00dc7b",
        "7f289870ec59ed418c4b6e0b1f25bec7eaed8ea416f4c9fdc62359df106ed38b",
        "7f9b1c60bcd1c73884bc2621f22cecde692e81cfaeb3c2470d2359258147d5e9",
        "5a1b6ece26ee5fccfcda8c01322e316ce676dd7c74b4e01af894af3e6567a6cf",
        "6920986f37fe0cc6fa3ea2acd19052f4afe9aa9b0bf415fec0b30086515ef455",
        "d968a1ea090dacb509027de6c124f1089ea3e5fd6ba3e85e24fd06565100fd84",
        "2735618bc3a30132e73a4116f7644062b2fa6515994fdcf7c6dfc4a21bd50d0f",
        "b297c7747d8ddeb8028ab32abe2bbf2d013826d9ba0206efb3d6712f1ad7e421",
        "27cdef3d71a2e65b0cede573455d1ad315d4f0e4a4b871361f544dabd1cc5457",
        "5482d4b02dfa40af98732036ae5865c5e60a9c4e0e419287726a4b150bd6eeab",
        "a0bff5fd6687c3a08e2c1e2808867c3ca423aa82055f0d77aa7dd1e314422c49",
        "dc45795b11bc5b2bdcc7f7355507d84b41054344a5f74ddef670d3041e829c24",
        "4a512c5e9e748da8eefc64000000c8a6a2e2884e9ae75906ee4e7c158faf9d6c",
        "8782bdd40c5e88258d6da5c57461640ccd6f6018be7d6d334f84c979f955364a",
        "fb83051a298d7424774bc2f9f646de639d30fcf289086091e640a0d70ff370cd",
        "c7032a635cbdacc857236955c7f9ebbfa7e3cfd866abbd82dd7d9db8dd0e8942",
        "47d3d58481812352e17153307409f42866d10bf9cd38b9871075a15c586b4433",
        "ff73a030eb463595db724f995515d9ae99c38ddffd32e46755367699e010ebff",
        "301f23e5cdb06f8b8418350587a35f8a51f6da15043e51da6ff3166152a1becc",
        "f8362eb284c76cb9b25a5da241eb7f4a889733308c8c969533a72317a874c5e9",
        "61dc9169db0664121f3f0016e3eff6a7e95e5d200b766cdcdac4a2d46240b5c0",
        "642ef272abb70c00326ae000000056f14d1a37982f4dd25adc72597a3f968538",
        "c97c4391b517f6b1396d41cb63deef3780c8e117c92be65f7bd5bba0b98c6008",
        "760c0b27ec0bd14520dec8a8969fdb1b0a2e131d9ee987c892ca191777eb2b08",
        "fcb2dd5c334184eb87bcb8f35ca36a510674a753e5b73de449e3315ba005f466",
        "da15be40a385ba46ff737951c758036cc15518ee7073111d5b47611047ed64d0",
        "5180f67b3e32b7d1fd5324de951058908fa2af991074e6c06f8dc552dfaaa3c9",
        "2f23ac92039049aed0d9e0070a0444e82783ff2c7bf237f47b15f77e21e955f9",
        "2eb8efbc1ccbc6a18184a2016a7a36c041bce6c5e333a621bdec93cdbf23fec4",
        "5cf774e7f99a8aa9487294cbbbcf51f592792e30728b29249f0e32ede4904027",
        "51296b50b711bf1c1ca6438c6df08a18a95b41f669a9c8417f17d17c107a3539",
        "860521c2dd25eda10101579e324847befc427277fb7c70083afe00b26025d1bc",
        "1d601b16573f4dcc3479427b290595f4471a1e70b05a9f1b17e599055cb9b0f9",
        "c525f310139fc6f0a9a27950b5e6577afef224c754ae69211a5eb3cb38ed3cc0",
        "6fa969cdb1a33073a8ae4eae3f94b1df54c21771962ba546c9c584c7afb4e616",
        "0277afdc1e3410365ade9ca05bc142ea93d4943c01013f8d6bf4ff87f45f4bcd",
        "9f90718666ffe064aa995bc847d10b70091b373706c8e0e73018b744abfbd6da",
        "df54383b94dc16b18ef40ab8d14b5ea05663e4b08ed3e4871299d21c65728996",
        "2db32dac0ab596d0981661737aae1b80f9a3cd990eb220e590df50562e43f906",
        "8f447c7bbef5a8e4c24dd45e3de4212c9eb9ed1632d657e4bb48af98e136079e",
        "0101841bf06385220cbd016392a60bdaf447bec5966630cc4125fcfac320f253",
        "3f11b8dd36cd82b03fb2e32eb9ed51642cdafcc4b5aa2859ca4225898537475a",
        "37f55f236c08dee957a35cb404a8366b42876ce04f1779df3344357441e85d4d",
        "658c488efffee5d7a451db9ae49f7d1cd569f7def4b3fa15495cde0254d6a7ec",
        "fcd8cdacf26879cb3ed68cf50101d9669979a744107ac320df16cba3e5060b8b",
        "2dd5dc420eff2a96ad4c0e41f25ee5bdae4ebec4fc11f49752a713888bf49f68",
        "c718fcbc73111132a87e08ed6613b58a511a5494d8e2141906a4ce7b44809a49",
        "cde2dc1c6c647b79578d302652471400000054020000a0020000a00200008005",
        "0000fd5daa13ab4280538b155c3ada181f23d836255330dd088974e67f919b1e",
        "d9fbca0e2835432aaef1319fd6e51a74576b8c9621be74a886d471a92be66039",
        "41192fd670463424548ddf978ac627e5a63e9fdcec0cd890862d1b085783b86d",
        "5456e1f6aead7c30fdc6cbd4032230cc0ea56764be267f1fa016cc2d06b739d9",
        "5c11b93f4d3d56947257a5d7ff6f96d307f2ded9b216a1674e9ef0c8aa3b356f",
        "1f10fc14de1c438dc73209ce3a97649ab92e44f95c74e2bd0045ed0fe52acbe1",
        "4efe178d8c11f38e21ef43dc86f86b9bd541035f492e17f5bb7aba19f8c2649f",
        "3d98c90bba5523a1455fcd238614600b4d7d5c60b0919aa88a92807062a33b13",
        "62a8e826dd51f053e848ec5b98b9e41d573df939a62b0e706892e657ca995865",
        "6eee612de2b5ca8552a2c444ee24223d56b99e1b15350f2d736be875bd932763",
        "4c61dcfa01a7c95f9394cfeea225b2075d7add898ca677f733e20b18d272e52c",
        "5f190e0e14947b6a6387e6d9b95978fda0ae6fd3f9c9d24691d436879b833547",
        "83bc4d11e8ae3f2032aadb230ae13f2c5d8bd061d8bc6acb90571684bf5adf20",
        "9e1882d593f1b8579ce9de7c8d623066a39b55ca02595c33081439f8f85aff19",
        "89923c454def176cec62b8f7e5cf7d941215959b04b530e39eba3722095431b6",
        "831ace8d7b0e53fda89b79c7aeaf1f81ed68cb4bb3c7eb14fca89e38a25a701d",
        "712e90983c6cf4bd91e34f2aad718d3ebce61750296ec702f85a99b5f8e1e5e1",
        "eed6f837e0082af71a9d29aaa7b229232f0a631d8521a1fd8594fad56bc08f26",
        "102bd745c1c8cdf8bcc67a36c38ff2e9ff9e8817c51cbcf8b982e86589c49fe3",
        "d41e4a60c3f3000e4dedd069ea165202a446c42c0c510f412606f800c9afd575",
        "b70ec8df592ac585edc0ed5a08b160883d6f2f8d2c820c9b535cbb77c1483a35",
        "a64c943bdb9a025656663cbbd43e4e9cbf1770d617eb7fd7ffa05fde295ce4a2",
        "77e4aa31a6904adc34b794fe42d7e6f3ee0619de73197d53f9c50d7f20110494",
        "e4500cd5f771dc194d47c5c5441e07eaa026e081eae6b14a69f94f72a52c8433",
        "90ebaf8a592ee12cee76f3e4675ddea0fd753abc6a5d768bf7ab9f983f8f5bbe",
        "dcb4884a2f214c6d26a657aa0067daf8a2b8e3dfb43773fa5e7b30020069e9f2",
        "2a66dc8db865e724b96c1cdda5817f44d230fe285df3b877a9b182a8ffb6be7b",
        "c28965097f7f0cc099f2c73089c0b966cfca0e6de642f840fb38cb9721446ceb",
        "6a2183a8f93ada82ebb61db58173d2e51c10699144e9a9d342f3c7c33b4d3f44",
        "f90184e9ac03b7b9a1d14901871cf3dc2cb095f8d4d716cccdba6cd23c51ce1b",
        "63be929222da7f93626e764c26149da15e701973ebcef598a63968a3d717881e",
        "b87e064dd2a53197ee3e61e04c0751d680c7b91acb38c41a8b65fb252a2ee69a",
        "d90c82f4f7ee741ea13c84b47f43ada8692044a5da0ac44d31f7be6bc341574c",
        "5683f52ecdfef9fb1e91012dc9110c7532daa8cf19bdfd6363576890745c7659",
        "b32b39cfd4e07897f8ddf9f935bd5a68387e63a0810c507be38c75dccbd0b702",
        "99589d221f0b25e25308569e5afa4ab2f26b9e47f6ffdbd49c215d45cc9ea054",
        "0ee3497708bebd5d4cc6deda55b29cf58e4e9b34aab2f617cb109e28f0369eb1",
        "c600ce542fcf48c19c657610e538ad9feccb98e17067b683533a4926fc93aa32",
        "50944a671e5f0523f208de43efce79a66d94ec67cc78952cdd57864935274473",
        "7158465413709f3fdacc4391f55c8cd378cf78c89dd1fc5ac9ebf868a7cda7c6",
        "e21d3ce5c712060d1e333ff9009a2e1e38fd6a1b878d9413836d667e802a060c",
        "a69429c27a6e106e30a4a50195ab4e373e01c4b4618af23eea442d95bcd23865",
        "10c6b0a9a6e43fcacd323fac2a5be1a68f33bd67a7fc4fdbb494e6efd36863be",
        "6d920dedf0216cbb2df1f6b87888ad0da52d4a6d625231f6f28fa77dd41300c8",
        "f637d5b2480886a4f1cc754a59a16d214842a4f10ef5a7e16cc8954814736b34",
        "c4fe2b64fa978aaf149e400e02e842a118c4e9ea827627daf194cbd14b9fd18d",
        "f3fff7f4dd022e7286451892bb26013dca52aa27db2a2cbc50d470241ad0137e",
        "6af836561550f6ce0e5a48410fc37585c96721ef830dc66153c4b71885a59bbf",
        "b91f8531f3c0cdffd5557f0f3213f9ce62278c0120f27ab158ad2fe822d448eb",
        "13c2b1c9b5635dea7b73e944a81cd349aacbb6dc421004fadb31da9d7b4d0ae6",
        "d7f21b401f1b0d57eee2a06204c6519a587b868ebf9127e64d00ef042b8f7f0b",
        "107cc1cc8d331f81a6ffcab780d481ac6ff6b4035c6c920bd1ee346b16089a40",
        "bf6a4b73d8313a83929e2f861b2c7dd3b17cbd180c69b4ca1e9cbcd976a7fbb5",
        "d1301bbf869acf8ca243cea51dc48c3506ef804502c7d2a1eda8e690827437ec",
        "9d8b8c4d609d707e4dddae959df5a95083f6e551b2b362a72aa417c9d432c9df",
        "d53974155b4df83769a2bcbb508d647cdae1c8881f7d556f7f644421220c476d",
        "4153c8bc5d63b53a87f855b90cfc4cdc02bed40feb73a3156bc5a60940918e9f",
        "5622402d6d1d55c4a6fb59a382f3722dd630a559c1cbfa9a592a84a6b6e0e65a",
        "4fe2ecb273204b030dd4030718f70027744b978cdaccbb3d3c6417849139d2ab",
        "edf06d45c76519e08ac03c2a7f58efa096aa4254593f7e5de89bdd109de14acc",
        "f68c8dcf71bbf2726ecac7ebb880fba1bba96ba1ca6fc23ee8e4921d501f03ef",
        "b853e42dde9e5cc884c4f0dd3f633628e000b7d719578e9f217a16e62afc5cb7",
        "df15121fd05971b495cc750aedc438021ac25e9f71ede9d4f0e62613cb02df04",
        "afac73a78580e981d5ba50a5bb1296c113f463dcd686e168cb485fc4c8e9645d",
        "21754f44876711163704cd3bd7bf26b3587ed4c53f04",
    );

    /// Official `ssz_static` `ExecutionPayload` root from `tests/minimal/gloas/ssz_static/ExecutionPayload/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT: &str =
        "fa1898c570b21f8ae5e68a456f8a6ea37daeee4a078e5fa7b58493fe337174d5";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayload` from `tests/minimal/gloas/ssz_static/ExecutionPayload/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ: &str = concat!(
        "259f7c7de35439e6d6bc4c5c371d3af2ab50952d191ede6d7743a5a8766e4469",
        "a0cba22cacafc77ad349641da350d164c91a859da6133d5849bb3a42e1d59487",
        "47561903b175dae19f83fc326d9239e61c0ee54edc60e5194ae10ba04c1d34ea",
        "cbcd667290256254188b081338008aac6407edc73092f37d55c3ad88f673e27a",
        "3b39ec04d463fe585c86b4a62367e83916206a299a58f0a93d78664100415a24",
        "9a6ab197d5e3a57c9a83710dd5bb7471d33430018e78792b43255ace2f09f6f3",
        "bf7785e651107a41b0d115199c80fb414ceb97db7b39ba7c46c9bba26e6f7d9f",
        "b9a91e42e537227c0410c88641f4910cb100cd1ee784138fb30d750919a3ed18",
        "6998261978380961aa1d375ccb64ac977bc7c71cd0b01eb51ef5334725730173",
        "3f1f0a59733c14bfe0510bfe09f49702b0501e9a379f5921be013ee6e44320d2",
        "89677e9d6d4b118379f0b256ccd87d666242cdf20642f45be9b1b6b5112eda0a",
        "feeb2307efe390dabcf15fda4a7049e5aab2d8c57fbb83e5b1b5037526d3d62e",
        "283009ee91d007bc92020440c9fc4b09bcf833388e0554e66506345771f92226",
        "ea9ecb189e7a30a8971403e86209f3a19da1fbf51c020000811be6a796aa8228",
        "eeafd4c76a2b129ab6624d8de7ca4182b8786e59845540a0cc9ac630ef4c35ca",
        "0923e1a4465a5adb12cfc45cdc1625ff065486525d5ab4b22c02000044020000",
        "5ec5fcfb85e777a65f361bd8c1e0d0fb9c020000fd956b8480ddf323c2b682a5",
        "9068fc05ee3e477cd12ceb131000000010000000130000001500000074af2cfa",
        "20872e128236436f1239deb36644761c68d591a1a40c8404df3630aaf5beae0e",
        "12414c6a7aac63088911763e6b6dab48ad30d59cd7f11eb3b5b3509d1a54fa36",
        "5012d294c1cab90b093243a03c92d8914495ffa24e2d926664325637d25fece4",
        "0341",
    );

    /// Official `ssz_static` `ExecutionPayloadEnvelope` root from `tests/minimal/gloas/ssz_static/ExecutionPayloadEnvelope/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT: &str =
        "98f593cc36356b342abda8c5d87daa12afb5ea0595eeeb7393bf04d39acc381a";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayloadEnvelope` from `tests/minimal/gloas/ssz_static/ExecutionPayloadEnvelope/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ: &str = concat!(
        "50000000e8020000920006e77a1a6b2eb737c1158f923acb223d148567091daf",
        "9bb38776404c4c95dadc269893b19ca357448aa93f9d35aea97c307685415e2a",
        "5345e9586dfa6fad7052b1774baec04f55354b7b78287e27309b149dccea7503",
        "368458b584894cb07e5655eaedbe51e133f72b286ac7c5adf399a05cac7928c9",
        "a05a32508132a776f9220ad7f033fbd062b03501942a96a9a7f42711e9a9c7b0",
        "e2500e36324fae66375421081ca6eaab19317a7b51bdf907dfb30d44f5ac847f",
        "28c904e415e7212d81322548c5307dbf8489cacae76a6d26f050c8ebf42a1446",
        "88c10cf755220e2afbb3b7cef1401f03041d6cdf01045ed0b8f3fd9954c530e7",
        "259c2757525f1c1e6e53dc1384112f7835a351b919b8f3bbd021951d274fde80",
        "3931c72a78090e4ea4bb2f13eea7635fa894c1d7838e0bac9b827931282927ce",
        "5104ed5d91327b8e9f505f850c0a574d074c9dfc8d1ed0e8c67e5a29e141ad8b",
        "ab6ec34c44c6e1db001903d2e6bc5c5f56e601be51ae09ab2f919fada2693c81",
        "a1b9945afa67bb66bbf80fd66e037e97368e82b5bd37558070f35ed053741e29",
        "b550eea8a1afc0f567e83d3e5eda36a1c54811ca0af1295e04975b3321fa03ab",
        "f02ba34e91a6869d3d1c10e3335103ed82a875b04ab58d12afe135ca9a604a4a",
        "215b5e72819530bbb716931e8655cb14fcad4083610dd6f1c345994a78bb76aa",
        "eba494461c02000072f7df9082b06326f94f46a384e04fd92513459ebf0a519b",
        "098b059d7ea3024223aaf0d6efa9e203b20944b63115e583b321b488be41e1ac",
        "1be83e40ab4971fb230200003c0200005541beb72aae471d3e19882497566974",
        "94020000a2129b45a8c536262f70a394689b6410000000140000001400000017",
        "000000731d3fa6d61192e82706393f4e5b41408dd70a06044a9082af022c1f31",
        "8caf584ff1742cb4dda1ab5faadb5b9f715b44d4ef867a9b1f716d5a9354ef64",
        "9754e899a827483ccbe1ce023ac0862f9bd9fc7ff21217352fdc7f17f8982bad",
        "87848b566e9a05f714000000940700005c090000d0090000d80e000089075d9d",
        "4973166e3f8512f5ebe705fe24bbb1fb7b5c1401cd6122abd109ea09682f697d",
        "e91ec1b93bafd3ce4fbf5dfc3febcc6b7574371beea151e559dde634cad6a771",
        "1873439c990f29528dda722fb2aca284621a908085e3fd6f64c9f9379d6bbff6",
        "f3033885944ccc829f1de290da5c0fa900c1b7bbdd4fc6a16b8e11a17036b365",
        "dbce6900bc85b917d14c79358c7b72b3afe499a593e565eb8ee504cddc5bb207",
        "b9d7785f6dbf97aa92603f005db741ace6f0db9cc5e0b8ad020a48786cf24402",
        "101f294a15148e7dc047da85e3ab8157cca4ebbdf803a65f7ffac2a030bc7aee",
        "6436de7ad111859b0fcf74490925ff79a39c08ef44a67d1d211057477d731436",
        "b5addbbc18e8372550ef134d7113721e979830905bc8ffe2bc286ebdc584af5c",
        "f840487e2a5adda4790c1564b3a8e9a1f9593a990dc5b423ebe41b742121e196",
        "7d638be61308ef266b646684bc4117697a4f739ef010d8127bea8e5ecda93a91",
        "6c9d5581e6cce3f441c84f6fc50539621038821f3ade679d8b6949b4c2b681ff",
        "a27eed91036b001045005b5b2754e8c4c01bc79b6e63ed4c86f03c6165a450d3",
        "9e1d45decbae35cf7b01af17c078cfd8b45dd021489f5796e4c37b454070adf2",
        "b98db4b590bdea3e736ae0350e56988ed718dd51649bf8e78944d1fc845c4976",
        "5f80a438ea1eb2eae2d59c83b1e903d722ae1f4c64e617bcef121306b7813631",
        "4e5e3b70a7d1a1450f0d5beb3a307af9d410a7d24ac4351b5996fd66569ac4ed",
        "4242e09a95741a70ee438ac809a414214140291422cb225d3507747f4834db14",
        "97c7ed3ecb8ffd49485fa11db06a6173b17119c79c3de01ccff94aee4edfd3f1",
        "8b6ce51b92bccc07bc58a61c703342afe6e4f44c43d037fda1112a3590688192",
        "224686710e2cb743cf0952805d4a3aaf39f8f55c2623eead8c64dab7cb7fe980",
        "cef420fa7b238a8e0d8883196cf17822bad1b9f9589a33f34f35be016f824630",
        "1670cb8e6fb229f60bb4259d40a7023be3676048beb82d398f51b242e84393b9",
        "1039c10b4f990013048ccc36627ea181621eef2fb2655f26d085727c08aaeb13",
        "5f8bf07d05e06817de77d96afa906d959050a4cfa091360cdb9b9a9cca03dd99",
        "61890e4c61a7efa7ff1e833788a393c11a13e4d42d0924f07c43605a76cba946",
        "149a046738aa7dc72058820fb778286b76087a64dcd20d968880b5764039d2e6",
        "ee701442acba28e25d4070d36763ecb2f62097b26efed193a72728248271604f",
        "b53b8d0c5027e7fc0ad8785a0b2b1a571500b5e2c774b0e9005c5bbbe8c5b69d",
        "bbd82ee602cd3dadb731c5259b478edad020233797b06ca65eaf365e08de9808",
        "2feffcfdcff168783b821b9c5a719940a6c3da26cf58081757f5439dd449bf8d",
        "b931f469c261b92a95b08609dc576c0d4164ec5595e6dd12c8445383f262934a",
        "9f95ce1ab73d6dcbfebdb937c10e99947c80ed4cfbde38593dfd19975ae0072e",
        "85d617fa6535ad648f16bef38f6aab6b5cc2faccb48805a5e087c2bd1c501a30",
        "05f0a25caa19bb8299a05351b00cc9ad39085110fe4c6eb67ae4f95b4ad81b7d",
        "994aa90c43f8db72b89dd753406cfb71435a43cba46f893533b1f0465d063fc6",
        "488e6dcccb31f657757021c9e057e8513ab3f07e3aeae0f3fa0ed9bceb54b9c6",
        "c79e6f9749219981a71a9f0482580f205e282f4a5aecd0e28efe2c9ec46590aa",
        "805f54ceaaafe554f06dfa750b16c92f5f4315b76ded35b9acba327bd431a84e",
        "892a1c35dc70783e6bbeca3f75c1c06c2d8dba8bb291c61ddb43fce374c3e423",
        "5fac324c516e148053d32ed727ffa5f8fcfaf5073aedf9db8c89451b1001c36f",
        "2e86e421caee3b015e1f9953612ce2fa02e30a3b214b97f03ae0119d060d2fe7",
        "48e22ff80775c4883c0fce09d3b1e8734a942ac8c5813fb3c7b6c0bcaacac4a7",
        "84babf3f87e2e615fd97a2b90a6d0b59ffac2eac81a197f8b4bf2f493613aef0",
        "417fa50179120441af2d5ba3353435031344299d1b084a1c31ef5b06b5dbe5b3",
        "c445cd712659e33a1a682ffbb00f3cd73dcd8a7b9977df188510ff308ab53ea0",
        "60676e0427232eaa38708c8d3e195587f7733cd7dd287aa44af957185f2632ef",
        "8437404fe30b08dc91289ff2342b942d25fa9bb3ab9a80969a65439e7beded4d",
        "25371a6f76d880d8ed00047379bb822db262d795670c350ec3fdf2d5ae81983c",
        "ce3331e90c52cb0d4caca1ecc2d4edc1a38f53683a469a81a409d08546484661",
        "59766da8bcbfab34ddcb55a9ca1fbf47794c1a4675932f6f8881a839f605591a",
        "63c5fdf57a8f5f88b0ee03a2a6844d72152289d87197fda616d6f622f5af7f98",
        "61e29f016c36e69b852aff749342766295aab3a921db0496cc510704c52a1314",
        "04d5d4171772329ab793742882d12ae8cb5ce63f58a745c67d52a4a6cbcac687",
        "91880c188cc44ace0b9d5b0dd7c9ff67525eac4839ea20ba2dd57545da2f61d4",
        "34c0998c82f3fca545da28a0f86c2772604131d3b2386957de8d61f2b151580e",
        "b434a380d52151ac1e11411d983bf7bc7421e947d8a4a15826128865c762dd4c",
        "e0f1c69bca653857908a20ee3d17cde0d525d9ab5ab4dec41755c6da4d4e6772",
        "8b677672979fec993b9df6e3e2db3048c7c0c35f8a225bd351a7ea74483c4485",
        "07a291aa5538ff41ec9b7f5d1b82f7c508462663d2fefe725a1286bf9bbb8419",
        "016b51f374e1e2b859c55e0741604c00c5f9775d9d77762823700e47543f398a",
        "cfdfcae863195ad9e9fc2b6d3e9c3e8478616c19f76567d1be1c512a95b4da07",
        "b95153604ee6dbc04760403ad6aa0ea66dd9b9b96271208813fdb2c818886777",
        "ffae1193035f57dadb267751f58d451c0af7a58e12950eefc363c48c6ee3b04b",
        "9aacc31b91ca37d04207899a1dd0fd6e249f108c3104b200e247857017716247",
        "b67d589ec441f0a0d7984bc5138db54f076be0e72136d2e43e10cd8711df919b",
        "920ae17513df4cdcefb8a935d5c0930dbec1992b2b27ff59c1264126d55627bb",
        "1ab36d89f7cfd2c4fd0de17e549bfd3595f54e64d59dbcf8dea1181a2ee5da19",
        "66e3dec4703302c4416a7aed488c13f4fe4a891e5a3bc3eb80b06ec11779f558",
        "e69c7f021a70ee8b6b74fbfe1992403c0cf064b2655e80fbb2e6d2d6a0eb00af",
        "ee1295db60098ac057fbeec7eaf7c24b0c5b66efb5a4fdf722401e70f2a2e842",
        "4085b79716b352a9d3f9896fc2b40b9e410991c7038286619981e42c6549205a",
        "36fbf62f51df5bdd6142c2dc42e8e60eece3278bfbd620c0db8e07ed00003413",
        "6891183d2a36386e2d6d20c245798af600633dfe014f96850e51fc3c2c58a957",
        "d3c5002d102766724cbea9a7015f9645cbbde58da36629cdc37ca8b81e74fb85",
        "20daf49de3f5f2aa4fd99b0ba1d322f277764ca0a05c296acd77f1e5a79ed4b4",
        "646a34fc1d13f2d03645a7e6ec847a25310a5a2a17382be9c9c5d2cd8cb0fca1",
        "a0a17780003de8ba26fea3d6a6bab1f6fd69f686a4e924be212fe9d27681a011",
        "1041c75d2a737b81b63886c9c04c2cda43d2ef28d835b489cbe337665420d82b",
        "1e032985ac843b4c85d85c07825d8f1ceee7d9f232e8dc78b5ff703efc6666cb",
        "27b3f50c151c51abb3633309421db6281570f185e1764aa469f405a3748783fd",
        "07502ca2e9ddef3e4d41f0d0813d28d482a2d7dbf7b9fac9cd0dce0286c40e38",
        "b282e1e5fd50c09bdb34526ecfdc2a66620559e39ecb726b94b564b226b4fc3e",
        "d9651b6b327bf7ef9774c0d8f9502befcdab8479045361ddf7449b7ceb2a86a8",
        "7cb64c5f8ffb6300660fbc131feb56f86c5c63bd3aff1ddd76b33a1c84e01b43",
        "856a81695c8b1348638cc2ed410bc05386d40290a0ba4889b79159e8aed4c2a6",
        "1bd222b8d8a8bf01d5ddbca715db3074ab6a3a75a580945548327af20900ad81",
        "f5557aaa9866a6c3604113638307ef6a8144463549e46b7a902835899f4bfcc8",
        "8f8436fc57dae4e7f765915392fef064cc16ae49151556db8334fc7efdf12861",
        "9439a840431633936c145ec186cb53b9fb9fa506c5453c24352fc86a2f5b24cf",
        "f65cd90809fea254293f49138e9663b7c72eef7d50090254192f33b66bb8ad30",
        "5ecfd76e6258ea18171cb7a47ab368bd63f99ca6278f17198885b99edfcf82e4",
        "cf172efc1f084bc46ed57a9e4b473eed671c20c88647df5faf8b75905fc3385d",
        "d668684b67a9933bca27b5f1088588e0f588e3bdb2a2b637bd47105b4886d519",
        "efc0c447e604ce2f00c1465440df986fd8da2df68521ca06431e2a8a65c8aa98",
        "80b5f662b1a09cbcd65882f391bedd1e9ae90732933174655a1861bdb80a16f8",
        "3936ff2de1e06d52baa8300422b4742d7da87931f226ca0d981df743fb206cbf",
        "a4e74a80079a07b063cf9da0dd985032d30f9a9bb3be2c7b0619a93e8e71b631",
        "8a3dfdeedd3b3361deee030315d33036cbacf8d2818d6f44db085984faf22dcf",
        "7a1bfee47d14a96660d990b48acea6a413891ef64f01c4a7753e1ad78675f33e",
        "ed6d6f776fc2795f915eaa55f171fc90e0899ad591f9c45045a0d6e9c24d6adf",
        "c719433195fd6804e33b37d7f75968f0b808b99b2f9dd9d8ff91a642fa65921e",
        "93a59b427034946e570f499e44886cee3947b383eee81f09dab15490b82a5153",
        "9766cecf8d04e802ffd77b2a1db02cd932a526d60fc95993684b9b4f89f22507",
        "ebff38536abab2cc861e172ff8fd81770ebac2a311c3bea295a8ca4ade3e7f29",
        "21d67b9eb5e7e75d8a958ab6c2737ed00e8c51bec9b0cda8bf5188cf2a47e9a8",
        "76c6285ff74d5ddd081b44659e64cb1fcb2feca877c73f0ce5ad0851508d7902",
        "7aaf57bc18cc0dbf2999b1023fbf46dbb7bf8469f492887ece734715b9e84bd0",
        "7ae31d32da4a3f8a6e9ac01728c88d2b1243e746c5ab53f46682f35d67f7ee88",
        "7dfdcca3ce4fe0d2423363bedd6673af4b2e9560739d2a33b05a5835e957ddf7",
        "6ff8dbf5e12dd5b1238681fb4e036e64c2a98378ceeefafc7a3ef579405f6b61",
        "6f23a29293a1a6c3aab16769f9c760aad3f2b490b54d0fa6e7a6f91dd1ce15c6",
        "459fdb40cfa900a51572d18e3792ca5b0bf8c20f9393a21f4508064bab90204b",
        "f48ce1c376aa01d86b182e650126dac7910056e1fdae284db457867e71bb4c85",
        "184831d73f2871af39452fd37cf8b1c5e3195723ec3c5b45ec7a76f8bfddb2c1",
        "437a91e3eeccb0c97721f6b40c2d71613a8adf301045456b3e995ddff03fe1d6",
        "ab05c5db4140fdf5831db76aa4f6121b20fc784f9ff89578c296e05d96e76182",
        "53a84e8d2e2de8e8aedd4d9d1bcb6a3606df562c23794039f6cede7aa9932417",
        "d756b2db3c08eb2f3682de3928f00e71f9fc7f892f12db1237a12099e6bbda2d",
        "38b16bcea187209f60f5bcc89cbfd2cbf102cc6b2d7f4bda5baefa1d6006bbec",
        "c125f408da07e86a01c0a312b72eeeb6185e12c57217e91b09b58a1ddf4be2aa",
        "2a1090c91d90473a9bc1f72f16405af9401c55735ee629db4f5cfebe4c95aea9",
        "44cf900c8a1a4732c42d91ff0355762207c5e0377bb1e074e14236c2da40d235",
        "af20213b8ee1959127d9ca6fb3f18a183935d7fed705fe082d9fc5390541e165",
        "cc85538642b3e9e9a1345b645b77e5a91d1daad787c04dbea485d8c4e88bab0a",
        "898e2364c90ab52c26d82d9e087ae89a1e6515aac4f0236a5c09843942ad4ef2",
        "3a55678748159455aecb7145881193d0ab019e5f4037fef2f4942e25d8f6c167",
        "ad905a7de7eb0a34e48586a0c6281eef0335cac45e7f33cd11838a787a6f6e68",
        "0a077738dd871c52c02c10400a7cb27c6ff96c5b426192102e70547502f83917",
        "e1c37e64a89e3773191b03806de358ba23000d1502a43264b5ab8084ef9be37f",
        "3f9cf4df3b66a7f33777fb44e70ac11ca0a7a0359ce1e07e",
    );

    /// Official `ssz_static` `SignedExecutionPayloadEnvelope` root from `tests/minimal/gloas/ssz_static/SignedExecutionPayloadEnvelope/ssz_random/case_0` (preset minimal).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT: &str =
        "d54fa66dec5644ee2972ec2289a45f5a1b9831c666d7e6bf70c8cf297886bcf9";

    /// Decoded `serialized.ssz_snappy` for `SignedExecutionPayloadEnvelope` from `tests/minimal/gloas/ssz_static/SignedExecutionPayloadEnvelope/ssz_random/case_0` (preset minimal, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ: &str = concat!(
        "64000000623543417faea3939821fcb3ec4a2af6b6611279dabf405083414062",
        "e2ac4bf9e3bf883b587e8c4a05fab5e71a2d023e587a41294038886b7f95f96c",
        "4b4da587daff765aad462111d3b09dd05b18f3e0e0fd5d26f220686e6d496609",
        "57ae18f95000000014030000000182a521fbd25d9bfb674a3f697decb9e5e5e0",
        "e5b43a5e94ff9490c69fab85667850c6c3b8103ab53fdebe9b5247628234d792",
        "db30d9308beef6c1d5d5cd10342cb8d7ea19e4797ae58deb83566d36c6c2272b",
        "ca85dee9e4c27571c7c75a3770a5bb812d288b88616155823ac0c198f8424424",
        "f5ec16da8b1a198aca69c7fcaa4d9f70b7b4c692370b42a50b2b6581a5cb03cf",
        "96269998cfe56b6b0576ae564c75cf5d3a3631185517bd50224646623bddfa57",
        "66d060a2bffb20950cf212d3981e1654b65a6c253191d01f948acc995250c97d",
        "eb1ede12fa3c3fc630978ff3bbbea169815d3027092502fb946668357e0f4dd8",
        "7fbd100fe5b2ac5dbd1b12b8ec2ad22519f6e6d244b271f42b9656b9bda2a4ac",
        "924a54a3543c859c7ffca569bb664dd96e3055327fa48122e58a0fa9a816ad35",
        "7e8f19f39b8e6fcf06605ebe73227b578899bcc2fc06b9c6cb89361dbb7fcdc0",
        "67bf4c28a4a487c207787662a63a32471348b461969588a728c404cba092cd5a",
        "049c1f4fba630bc85529e9e0e2c1ea63a285b2ad4aec1ab946a220e5b1471dfe",
        "c7f28ef993eb421ea37cd75c5e54ffa8f38f993862f15e7f90334d6f7c616c96",
        "d147d391dd62f7bfdbcf5984507fa29503359377cb7c9519365c4d00c79157fa",
        "d1d7c07d561b994357f4223b1f4eaf0a438afd591919d0d8243ff17db96d62b2",
        "cdbb874dcb29fd741c0200000afb24badc13ce5abc5a9b314611a5dc3cb6a9ec",
        "f80dfc3b7c09d1e5c1dc153b523a9abb466fa4ccce5ac330c9694be64307a34b",
        "b769166c7af94666b6ec0a061d02000037020000562ee1436a83c38124c5868e",
        "88110543bb020000d7d9b1f6c4506b92f114000000160000001a0000001a0000",
        "001a000000c9f81ce2af818cada7aa5dbb32657145a1955e90b5c02880fa9bfc",
        "53478207dd6be04064498fdc02be3676bbf32d828ce52313464dd1a5ae4faa5b",
        "1956f39a558d0ec33694aa05b5c268b3bdc586e095e477ac0b765066124c82bc",
        "8cda9b079b5e2f1a730656f4c954c1ca7ad1f30d36046e78d365d52514506474",
        "8b523998a64b7f290e32b492a8d1823571976e67a4c587141400000014060000",
        "1406000088060000b0080000a7de2dfc5000f93cdc4b184fed678ea0b51acae9",
        "a7303e4a49f6ad2181594aca5c10c1aba19e2fadc9c853911e63d156361b468a",
        "bc137577a33b5afc4a460a2ebc2920f73f66ce5bafd068542a336d6e5df0c779",
        "7e8408be0639692161a54d1a0d2678339b3d90271e610a6609d1d58788d372f7",
        "52ed85a7c6fe1495921451ff888fe13462e5fba8ed53cd885da0e3d66b2ba241",
        "aabd8b37ee84a476da7e49074c219a583c3e2304dc3a2090bbb3dbf0c4775ec1",
        "efaf21c9b160c254e3e42482ca05b65b83ff6336e6eac1bb9ceb64ddf1e886b7",
        "c04cae7fed2967fc8243415e1db819d0e8bdd9310eaa007e6db00091a1ed1376",
        "a21e6f6801d02d07a6a2f64252010a998a88a713693be9aa60e4974103cee46d",
        "67897d09d545cc7a1500cab419c90ba4362ad62f4fc4021b5b73f73e1c7dcbef",
        "f46f26f489d42463cc8be67aa06c70fe06a4e01289d6d97cfafba437a7393d88",
        "8432685b8412e079928ad8314b77ecaea3bfd2cb33e1bf9694f9bf950eb7632b",
        "a98893625ed5d401e51c480b925ef5f44aefc07d8da5abd0b858d9a2d11a7b94",
        "97ccd86a0b2b9b61193c104addd8574824e39d9258b65eae3db4501bcd2e91b4",
        "3c1706266f9d25a09726a7d2466798a4b3416d65e1c5a3fe6cb1d4760467684f",
        "7ddf3179288bb36d926279357b54187fa18acea510fbe8a5da076c3255780a53",
        "c67fa76b7346e16901dbc3121b5fe31e6d8daa976f78ad94eba862a4c9688ce7",
        "fd30b14cff4788494a80a1244c21698fd493f2958824a5da0f6b81a628bd509c",
        "7c5a6c0e7953f752605ed33c4d5c2cf96990ea5ad54305249a4c798108a08e53",
        "31c7b8f5a7202e1ff33500c3aab444fbc3bab6a0212b94e66407ebc9c29fc6b5",
        "b1e70111ebf4ff2f89f5c356644f81033b2fc3ae6a5c4ae49ef70f82f09d81bb",
        "35efcfdc052d7b4eda7b3d9b9549db94a1bc5afd56c25112a11d9f980e71d570",
        "14d658a15fe604ab542ea4efca647d01259cf66ae8ea830552fdc5dfc53c258e",
        "01e70fcdcbb645abc532b1296a41d96f6abd5d38073c4c7d5a8d23ea9e1071d3",
        "649d2a0959bfab433e1648d034d5b58c2b609068cb366ca8eb204032a72b1869",
        "7b215c38b61f6af6b92d3c265c968f51fc2d4ad2725ec175fe4ce880b1d1c793",
        "4085cc6e4ad194ec07d331049b99587a680a26f94dcb2110c23c2bcf833d5d52",
        "543f6432c1d838d9259d3c6dc79ba63f00e169cc51f4a2edb9bbe29cd011f20b",
        "739cb6f79e64f82beff3f9e1fa7207970bc3fc673e415e4c2004522fb292fde8",
        "c873a88bea6353ad478a2843c35242c725e179ea2fd2b71bfba73f88b3a88289",
        "24e0289ba20fa8d55e08c47ce418cdc994c579a0afe20d3944006f6743d6d403",
        "5d23c79ae2a49ab160cc5c23ae10bf0ec6d969f7c4f39f02fd776778b1d13f5c",
        "1508c5e2764f3eb5a9dc17785e765fde46c6635d46c0353ced6258cb90ec5650",
        "db766da539a295048c5aa6da3c691f42add9ae1368fe96f9009ccead90f237dc",
        "05560fbf32888cf54e16031acbfae337e0dd10593d0fcda69c041484ac5d4bce",
        "8b0ca0ada82cda8a0e40c1929dde4add5d6ecd2d905010c62c089d3fe63c3e9a",
        "d167d9b57573e6e450034c880a4a2a0ab8f3701bccfbecd0d24ea86b22335258",
        "529625a5523bec5728a2d3c85b663cf43e11822e51f5c009bf3e58cb6cf3f5c9",
        "e50dafe942d314380de03065a54dd25389e18837fc4cbba695c541f75b448284",
        "7da6ec2788eb97f0abe92e1456cac4a39bf0db88f12597142cf0987dd415b220",
        "40c58acd800471b7eada5a2b698e6d88c08ce2c0977c6ee2a0ee5beb9f06aab1",
        "f2f0ccafb0a41de85e9965445db5ddc85deb3258958c2d50b0d31b32a18601c9",
        "e5f8ce77362d1995085901976fd6073486c659258fd42d3a9097b3a30720fc25",
        "6991784b9d82e071497a5adfe421cb1197e33170b5c84c058af9a74a644ac800",
        "9983a0328c79c0882432d16d931e30cd8df7543fb1a30933fa9263534ad585d3",
        "d7baf86e8fd4dd94f6483cd2d13126e5328b7e8a78e5c6c7d5a1907d57d31007",
        "ad639a8ab9b372fe91d1c697ba73dac08d866ecba62ace4d1a3f211133ebf523",
        "84a6631601cf3c0b772db43d3cab23c0f30bf0bd86f5f4080c8310126021e769",
        "d339a973e9f000c5f3b6695dad1111d53505d1ab984e111640fff826fbb49bce",
        "e707bde22e905ca7664c8d8b9d1a3fcf6120911630d104d3d559ae3e07305aba",
        "addac2c9e485461a4cfb74485ae7fe7c037833f291213858085d337671a56dff",
        "25ac8013629f8ff38eddfa87e59dc7b1f66fa5975c7288881ac58b74e9147f01",
        "c02bc64074c2ed92d486ec6ea77fe499c5d5277104534c969196c76f587e0986",
        "e2cb00fd3b188aadbdaa143e19aae164834af32690d3e3f0ba0baa5df3a475c5",
        "51b67baba0e7d5d59a8ec893c5e027350185edfa47648dcb9a5a4be9930b2d37",
        "81f190c7b51895d958da42dc16037b3494f12540b402c8f987614eddf3bd7b84",
        "bf670baa8fa8759166b70cfebbc4968e16d6cfb92e6c81ff08f5b2af25607a42",
        "e6e6a858700b61ef2f21324d33b46ebe858761d23825d40c000ff338030dbae2",
        "e22bf77895033bc7497a1b9afa627caa2c6fb4ed7058ab7b2c28f4af61abc557",
        "f6be4d93266aebdd5569e8c77a09049001bd3b7e00892e46d7fe98ff6bf966f4",
        "0d97c1739610e50c8d258b5f4437c135369427e865a915b748943742430d8c3a",
        "6a98eab89f2289a424747725a9279b014d021f5403bb9e930e4266a3cfe1b6f1",
        "ce72e4761d07549ece8f929c7643ffb9af9294624976a6cbc3cced2346fcf56d",
        "8608c34fbb7fdc282f42fa95be952c49d3394a1f4d92d0e7926c17dc453b792f",
        "d1b8646d1e16ef5a52f76a023d1bb750cef455fed1692bf24d89da6847b6af9d",
        "50e0fc93d9adf660a7a1720955ceed75157890d28828d8adaff6e5a686e67b5f",
        "27b0c0659e6b815495ac0b4755ccc8e752325c01bebbf9b83fd622dd5bcae38a",
        "b307f73bf566fef4ecb5d4df1a4b279cb2984921c4e487d1bfac665594a8adeb",
        "85d8d7540c3af864d434993e2758a49c8815af48e828cde1550659734ee78568",
        "caad54e47ef3173eb2b29ebd4416bc1a58d51f284ae663f1d86bb4d9889912cb",
        "9aff8a3440186ba8f363c6b9e6d7bbfe3be02fa3b014b34e42340220de3f7036",
        "5a3f1a33c771e796ae873922b1db62d98ce7df07b70cc8bd71f0691d75138d33",
        "6a7aa5230889a0ecb8990d251799354897baa4f70724415eb5c14caaf7c907db",
        "b2023dbca298631e6a7f5aa3d51a7bca64d80afcc5ae159b7c6284253d245483",
        "0b35e666dd67d223a09365a78e6724cc24d25cb863ccb6057857e85d4d926570",
        "8584ede7b004fdd3d0833cda15d274a371e6640b69a212820a0b40cec61f96eb",
        "72d80f9351af5c78b0baa9f228eee08303bccfdc24707264de7597167ec8ab75",
        "632a82671be0eaef0a09f2066d74d2a330bb04fffdce148963bba9b2a12b9699",
        "9a10fa6df24f9e635ad4fbb1d45c1f2d631a43fc52b47a2b28dfd3c6d4f8ded6",
        "29d36cac91e2450d6ab06c36cd684b65b6a2adb0b316d716d96d78e39a090582",
        "9f86a6ff517a67e71a3ca0f02736a470000775b28af167519501e98480f8f44f",
        "320cb8346dcd794c63d65583b594d556415201a0bff3d832ada82ae2403d6e81",
    );
}

/// `mainnet` Gloas island KATs at consensus-specs `v1.7.0-beta.2`.
pub mod mainnet {
    /// Pinned `ethereum/consensus-specs` release this preset module is generated against.
    pub const SPEC_TAG: &str = "v1.7.0-beta.2";

    /// Chunk counts from eth-ssz-specs `PROGRESSIVE_CHUNK_COUNTS` (issue 3.4a).
    pub const SPEC_PROGRESSIVE_CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];

    /// Active-field widths 3 / 4 / 5 / 13 (`IndexedAttestation` / `Attestation` / `ExecutionRequests` / `BeaconBlockBody`).
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS: &[u32] = &[3, 4, 5, 13];

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

    /// `mix_in_active_fields(sample_root, all_ones)` at width 5 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_ALL_ONES: &str =
        "911c59673e029eac9c2cc499169aee5839df8b917c921207a71c1cf38ad96667";

    /// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 5 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_SPARSE_BIT0_CLEAR: &str =
        "a69ae34f32951bc3c9f0e0b50dd37e5577f2247bdfc70a11878c37995de5c3ca";

    /// `mix_in_active_fields(sample_root, all_ones)` at width 13 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES: &str =
        "e6abf04155618946e7c68b3ec7a30627a0a441405bdf7c2b683312c1be1a642f";

    /// `mix_in_active_fields(sample_root, sparse_bit0_clear)` at width 13 from the 3.4b pyspec artifact.
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR: &str =
        "6a67e5570442f21c98371e8df23c484025d8a9d465c90b3e72209e7cc5fb89ce";

    /// `(width, pattern, root_hex)` pairs for widths 3 / 4 / 5 / 13 (all-ones + bit-0-clear sparse).
    pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS: &[(u32, &str, &str)] = &[
        (3, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_ALL_ONES),
        (3, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_3_SPARSE_BIT0_CLEAR),
        (4, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_ALL_ONES),
        (4, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_4_SPARSE_BIT0_CLEAR),
        (5, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_ALL_ONES),
        (5, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_SPARSE_BIT0_CLEAR),
        (13, "all_ones", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_ALL_ONES),
        (13, "sparse_bit0_clear", SPEC_PROGRESSIVE_ACTIVE_FIELDS_13_SPARSE_BIT0_CLEAR),
    ];

    /// Official `ssz_static` suite selected for Gloas KATs.
    pub const SPEC_GLOAS_SUITE: &str = "ssz_random";

    /// Official `ssz_static` case selected for Gloas KATs.
    pub const SPEC_GLOAS_CASE: &str = "case_0";

    /// `SPEC_GLOAS_<TYPE>_ROOT` constant names in this module.
    pub const SPEC_GLOAS_ROOT_NAMES: &[&str] = &[
        "SPEC_GLOAS_CHECKPOINT_ROOT",
        "SPEC_GLOAS_ATTESTATION_DATA_ROOT",
        "SPEC_GLOAS_ETH1DATA_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT",
        "SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT",
        "SPEC_GLOAS_PROPOSER_SLASHING_ROOT",
        "SPEC_GLOAS_DEPOSIT_DATA_ROOT",
        "SPEC_GLOAS_DEPOSIT_ROOT",
        "SPEC_GLOAS_VOLUNTARY_EXIT_ROOT",
        "SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT",
        "SPEC_GLOAS_SYNC_AGGREGATE_ROOT",
        "SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT",
        "SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT",
        "SPEC_GLOAS_DEPOSIT_REQUEST_ROOT",
        "SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT",
        "SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT",
        "SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT",
        "SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT",
        "SPEC_GLOAS_ATTESTATION_ROOT",
        "SPEC_GLOAS_INDEXED_ATTESTATION_ROOT",
        "SPEC_GLOAS_ATTESTER_SLASHING_ROOT",
        "SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT",
        "SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT",
        "SPEC_GLOAS_EXECUTION_REQUESTS_ROOT",
        "SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT",
        "SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT",
        "SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT",
        "SPEC_GLOAS_BEACON_BLOCK_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT",
        "SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT",
        "SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT",
    ];

    /// Official `ssz_static` `Checkpoint` root from `tests/mainnet/gloas/ssz_static/Checkpoint/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_CHECKPOINT_ROOT: &str =
        "6d753282f74b9157acbb414dbcc9361d2095b302ec9a2970b379e1478129a97c";

    /// Decoded `serialized.ssz_snappy` for `Checkpoint` from `tests/mainnet/gloas/ssz_static/Checkpoint/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_CHECKPOINT_SSZ: &str = concat!(
        "3676ff183db884fc990454785abe26a75557dcad2785f68e99a41f7a0becfef8",
        "08ee382dd6df9711",
    );

    /// Official `ssz_static` `AttestationData` root from `tests/mainnet/gloas/ssz_static/AttestationData/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_ATTESTATION_DATA_ROOT: &str =
        "32b90e17db088a6aa78afa8135d0279c7e720c59954b2ceae4c5d318489e39e5";

    /// Decoded `serialized.ssz_snappy` for `AttestationData` from `tests/mainnet/gloas/ssz_static/AttestationData/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_ATTESTATION_DATA_SSZ: &str = concat!(
        "c49c0c39c94e5475ed706571686586b13b19b9c8cf49bb19552a78e0b05d4660",
        "5462917e0e1108858d47ab56e40d4735bef6ad66209d25e028cf913490322e9b",
        "c16c3cd0f0db65b8894600b8995f2ebb285d8241a18116d2acaa773961611120",
        "50316301539549cb51f6982e2b43e4d5337308d39394fa863e9d2f667834a61a",
    );

    /// Official `ssz_static` `Eth1Data` root from `tests/mainnet/gloas/ssz_static/Eth1Data/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_ETH1DATA_ROOT: &str =
        "cb53901233f6a74469899d902b5bf9224633ff13cffcf6ba181eabaa6dd253bd";

    /// Decoded `serialized.ssz_snappy` for `Eth1Data` from `tests/mainnet/gloas/ssz_static/Eth1Data/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_ETH1DATA_SSZ: &str = concat!(
        "6f6a4b43f5009a6fa9ff583a11466f50f1bc3418ba9a1fd2d548a3ef52285da0",
        "4a514f692b03d3f551dc69a8f740e94564cd2e46d1a500adfc5ccec6722d2a40",
        "bc313f0ea15ed317",
    );

    /// Official `ssz_static` `BeaconBlockHeader` root from `tests/mainnet/gloas/ssz_static/BeaconBlockHeader/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BEACON_BLOCK_HEADER_ROOT: &str =
        "a2672769763d19c79dd7a584f37fd3391c0510c1fd6eba54ec0cd78748a84800";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlockHeader` from `tests/mainnet/gloas/ssz_static/BeaconBlockHeader/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_HEADER_SSZ: &str = concat!(
        "2eeb8a2314de74dfc9344be9d98b7ad4caf0db22470a8e987fef3d78ce7a14bb",
        "d7714570b78d5d5bc4421ea2b657f98677134de1d4dc7a8ffb098e305ae5ccfb",
        "7cb27cba5866712f95756ddbc044d328934af84956d1a252aa767406a8bae9e2",
        "6b083a81be4b1703f157a70abcfb6085",
    );

    /// Official `ssz_static` `SignedBeaconBlockHeader` root from `tests/mainnet/gloas/ssz_static/SignedBeaconBlockHeader/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_ROOT: &str =
        "068e91ae7d12b846acb2699e881c47ba01b81bd5a6d1644fbd404f80dc0c05c5";

    /// Decoded `serialized.ssz_snappy` for `SignedBeaconBlockHeader` from `tests/mainnet/gloas/ssz_static/SignedBeaconBlockHeader/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_BEACON_BLOCK_HEADER_SSZ: &str = concat!(
        "45bcd0c7218cdd076ae5050e8519a7f12a972a7bc142f8d2e6f36214791279f4",
        "8399355fbf596e50f8eb4103f9106aad8ecb8339515f181c9ff372147d6828c7",
        "bae5f6ae8a778747a9f3023268d20f58da12e689287ed37d62586e64a68bc06d",
        "93c1fa1c0abe7ece96d4ea1f7029823eb50059008249e227fbc38cd87663608a",
        "aefe45cb8a092d487c72643955939249f8d08d832b0c66d0c6bf5a11bb9d17f3",
        "c9a6033da5da696e962082470ffda3aca735c9c28ba23d1880f763e34e57e0fc",
        "f964ed3f26fc1cf060b1ad900326b627",
    );

    /// Official `ssz_static` `ProposerSlashing` root from `tests/mainnet/gloas/ssz_static/ProposerSlashing/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_PROPOSER_SLASHING_ROOT: &str =
        "07a2633957c0df517ea5d2c89982c720b1f295b84f6df8e3ee2ac612f6dff0f1";

    /// Decoded `serialized.ssz_snappy` for `ProposerSlashing` from `tests/mainnet/gloas/ssz_static/ProposerSlashing/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_PROPOSER_SLASHING_SSZ: &str = concat!(
        "25a44ccf1e1a0ad7c30114c36ffedb5994aeb8ef82e1d678372127e109dcba95",
        "4530dafe414154ea33bb901a0ca9fabf355bfb1f2aad5f4b1b312e9fe9396219",
        "0ea391d20879aeb7a25f113e858ad98392f14cff03facb6a10132e922e139eba",
        "6bf1fa3f04449a01498bb305d2f4b493738b9c9cbdbeb27eef02488e3988ba27",
        "52ff67be0f172a799f65bdb0f2ea30f74a308a9d564ea80dbc590aa804303bd6",
        "cd559055c81f19a056fad6e99530bc78018b882817670eccee35d91699d351fe",
        "cdc28a1c0e481ad7ddf2fcc795905e7760bc7c9c471ff4a61b384690b4eadc7c",
        "189e54884ec5fe6b682081d662ef2293f905e5f4bbed071a1cb8ab5f1d9d9fbd",
        "4e6db3ea5a15abc9ee676af213a3e5735c520bd641ba00242aec790d9d006c22",
        "2247898bf355b04f967ae31dc453d49b78e3ad8364414be4fdeaf380421214b1",
        "960eac7e2dd6ea4e9d80fb9da5fb5893f8286f727786f5d4d8f104ade064753b",
        "a28a59aceb60a1704ce1141722f85713976a3823f5d539d78b58217da5fd0881",
        "4bdf5004bba2ae846842f19ef64ab39dc313aa90f5cd40814000ed2c23421fc4",
    );

    /// Official `ssz_static` `DepositData` root from `tests/mainnet/gloas/ssz_static/DepositData/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_DEPOSIT_DATA_ROOT: &str =
        "6208b4944917072435e2742a3c7b94d28f9be222da3e609ff9e2747c30533865";

    /// Decoded `serialized.ssz_snappy` for `DepositData` from `tests/mainnet/gloas/ssz_static/DepositData/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_DATA_SSZ: &str = concat!(
        "0ec8317830ed1c1fc0e6285050c8b538e5c77d113e756d636308c845321c3ed1",
        "e241e1092b55804d548f97e886b765f533d1f8229d4d1749522659c7251dc677",
        "080ba2f9cee95ab9dac44bc80d825d3dda2ad70152dd4d1945b27300b8f18e64",
        "ba1bcad532d96a3bcf230485fe9d3b686189a0598dc2e25b4c957dfa6d235dd1",
        "c59c14f6beaa9783245d6caacdd0c93601683f6e87a8c7fe20e4c78ecd803495",
        "882fd63af7a05ca088ad7d55f92818598e9f2ddfa8f453a9",
    );

    /// Official `ssz_static` `Deposit` root from `tests/mainnet/gloas/ssz_static/Deposit/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_DEPOSIT_ROOT: &str =
        "ca5735a27105394c2ce6f09f5ccd6a0e5a7c63c427fd83c552a66475243e0c99";

    /// Decoded `serialized.ssz_snappy` for `Deposit` from `tests/mainnet/gloas/ssz_static/Deposit/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_SSZ: &str = concat!(
        "9db64d7797755f9297aa58731d5ed4a7d18e89db5ffaaa6fb1a2ac3ee0d91da4",
        "92096fa4102b2f743f99c4e119edd4bc9033ad155206b7c238013dd62b7afae1",
        "9efd908eb5bc244ac35117099e95bb92ffac6f7cf1a130b0127b86a69c2b7c91",
        "b9e42bbc233704a7b6a18bd542419c1e1e5ff8f9efb7d3e0e5d1778c49acf7e1",
        "9459dbfba46c8d3f1a90b7c4d61146d8e953f2286c33a3a52425038e51f4f5a3",
        "8ab8b985566b967afa0c6ebe2fa1f42d5ea168e25d38e46ef6b5320bf8c86ab8",
        "b9fc9bb7073c59ed467467354001fa7a4f3d2a74b57a4de74d8fd9d529ad72ae",
        "5468497a881105d1ef0c3827bfdac486d866c9170423619f7ad7cc6ab1575eac",
        "9a705aad8f6b10fee86c8eacbe29221965f44a1a148b3ef73a56b05116b445e8",
        "644a3138082f54d8e9af609ed4c50edb71f83b6f9acb44e57e515f1e8a50743b",
        "5853a5f5088a8ac2be20bd136bd48300871c437c359777e94f6bf69ed29232c7",
        "90094ae8ae07e07a54f7a0a02bc5b6f6df9bf075aa659f3a9e75476911f8741c",
        "0331d9ab0917dd418e0dacb15b8924af60b4c24afec36615c3bb12b516ff9061",
        "010563524cdd3b25e1ffb9200dfce3786c5949ef36f262b2ab032e39585b40cb",
        "e48c076ed521cd4e638ada76261a3f6de1418d975366229905dcfdcc3c7b0bae",
        "9fccf6c98f60a7edf375de5c20148069bddb5a040c7199cc9eba0f551553ec89",
        "d1818c4a4ee6792494cbbe47c934b07379f9b84fc5426a59cd8119e6f13f23c2",
        "f8a2c4ec312c9ab3c6b5361fa7300bdd4585fc052bb5ffe26d3c031152d391b5",
        "0fbc851ee120a9ba6a2d8643b916fc93cb43b57dd72fe982e7268441377624fd",
        "1bba930b3d33f73a724982558a7de5199027a2eaa4bfb1c73d72bfc0b6df056a",
        "354bb8a23485100e3911a04392c07c627811c01f9a669d5b02283591f0ee6062",
        "ee7a2dd777f1335bdf79243febc2fe782826d3f9b9076e7a2d7c0d7fa44dc050",
        "d4251a67251fe8d6fc7df1dceb94c7151b2b452d9c30ff55e58f19ba9dc10a12",
        "03dd89bd3cd355854b1f9425c212756459e812aa8ea5710747a4c39158b4935f",
        "63101f8ba9d2baf1570072281f37e4115aa5bb017f46c1006bb14fabe476536d",
        "1f248021f9e10a716d05bf7958c42c59cd0d06cdbb0d158c741fce327af1cb85",
        "72550a094d4f299ef6520f6062c9c910787f605fcfbd9c462dd859d56920ac9e",
        "f6d0e7da2b34b6cfbdeb9bc2ecdcc9292ad3f70358d7f19e0aab935eda51818a",
        "59f4fe394bd57b1d0166a83a590809a449e0f4679c84347d1de39f7cf6a54d23",
        "36e6907561530a2d429456e88924e483c40f93f76a4f07a581fc864ad212ebcb",
        "6dc423516a0a772d80e091316033158e5c91fd72563134475cbae480cdf9a1b1",
        "35b404316912d826b07a29f8379233944087263f1a38d46fb1003b490166aa87",
        "1f749a678042dd3b1ba9e4da9821a9edf04f85b30ccc0fe2df36becfef6217aa",
        "5fac0344aeb32fdcaa4de93a6c4dcbce423d045bf6ee6499d992167507586360",
        "c95b02b33dadce1ed92db418ee8adc1f7f9f7bb25159007367be5c289f00c3ad",
        "acc5d818bb7f7ae07301ababee7cd0303428ea61904ae56fdb7117ef79afc9d0",
        "b4362666a928204e4ea056c74d82222ffc56721e33a1a8b2cd38d8363220c3dc",
        "ebb6d8fb2dcd7dba08cc94445223aaa01f09e43a5e1b9baf3d97f28e45c6bea1",
        "1e123cab5b8214ef500185ad3edb8e2b7286bcf08089fa15",
    );

    /// Official `ssz_static` `VoluntaryExit` root from `tests/mainnet/gloas/ssz_static/VoluntaryExit/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_VOLUNTARY_EXIT_ROOT: &str =
        "26d13bef7c4f7ae1b28767afcc0ade5bf56efd495ed5a63a1e1ba035d59a5ef0";

    /// Decoded `serialized.ssz_snappy` for `VoluntaryExit` from `tests/mainnet/gloas/ssz_static/VoluntaryExit/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_VOLUNTARY_EXIT_SSZ: &str = "b7db3c9e2bd21426144bdc1d9119c5ca";

    /// Official `ssz_static` `SignedVoluntaryExit` root from `tests/mainnet/gloas/ssz_static/SignedVoluntaryExit/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_ROOT: &str =
        "41f269e84836014fad3bea9720042ca21b15ff3eae8489b5aae2ef0564187211";

    /// Decoded `serialized.ssz_snappy` for `SignedVoluntaryExit` from `tests/mainnet/gloas/ssz_static/SignedVoluntaryExit/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_VOLUNTARY_EXIT_SSZ: &str = concat!(
        "6913de847e52ceb479895a39d5a03cfeca275157d31d2408d15dc31d1e1c556c",
        "1d3fff1d6151df467b9339632dc2dc969345e69d20f55ad5ebae24b69933a52e",
        "712bcfe036285b9ed8d49bd52499496406d84dc4f713ca7e22d9bc545edca081",
        "2ace57fc649e572bf5f16ec01a5acf12",
    );

    /// Official `ssz_static` `SyncAggregate` root from `tests/mainnet/gloas/ssz_static/SyncAggregate/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SYNC_AGGREGATE_ROOT: &str =
        "a94d16491c1a75699d1bb7ed7e377968fd99d77c7713b2c1ae135f267b1070a6";

    /// Decoded `serialized.ssz_snappy` for `SyncAggregate` from `tests/mainnet/gloas/ssz_static/SyncAggregate/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SYNC_AGGREGATE_SSZ: &str = concat!(
        "1a3c069cd62b40607c5cffe6c1a4495e35a592a402c4487e7afc06a72a9452e1",
        "b995b16a15b8508ee356ecfacd08c1a06c7a03d619d55c9e453d14f3cf6f7e01",
        "f98cbd1e4957d4b2d7dd0f509e5ee1568591e56744fee31d2448c9cb81bec42d",
        "49c806d8b0ef8f1876b06cb0e1ddd9cf37823aeec155b051930b364950aba85c",
        "9d96512a7c4215118a5fba5f8e8049edb471a84ded72c265a77b082b35484024",
    );

    /// Official `ssz_static` `BLSToExecutionChange` root from `tests/mainnet/gloas/ssz_static/BLSToExecutionChange/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_ROOT: &str =
        "cee9f638d870c42c932165aed7630da579924fe755e3b841ccb0d3834b86ca92";

    /// Decoded `serialized.ssz_snappy` for `BLSToExecutionChange` from `tests/mainnet/gloas/ssz_static/BLSToExecutionChange/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BLS_TO_EXECUTION_CHANGE_SSZ: &str = concat!(
        "9495a74acf1ad2830d01674e7f20e0b3ee5fa2deb9de756cba08aa5b810e4bcf",
        "54b803b7c8610d0820247763f91e2cde1ac7665df2462b271289250f9ad93e1b",
        "6f201270de7317c483ccbf75",
    );

    /// Official `ssz_static` `SignedBLSToExecutionChange` root from `tests/mainnet/gloas/ssz_static/SignedBLSToExecutionChange/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_ROOT: &str =
        "a6e579609570a06c46111f0c3d0407a1cee12974e3a7ab8d5cb78e214db815ff";

    /// Decoded `serialized.ssz_snappy` for `SignedBLSToExecutionChange` from `tests/mainnet/gloas/ssz_static/SignedBLSToExecutionChange/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_BLS_TO_EXECUTION_CHANGE_SSZ: &str = concat!(
        "761188f401ce392ac977a24cbf26e33eb85c7782ae1a9e5356bc9f06f0992401",
        "33b387395a7a5f7ff80e4e09ecfc393f6a4246dadf24baa937ca78e069f4f1c7",
        "403bf414ffdfca08bece6d7547f465616704f3f2c8e210af37d559399033dbee",
        "6e82e46f37b441e4ddd87ddee7372249523c27e104b22ea117926f11b5760e74",
        "a293159ca6d9a69f9f8d785a423cd9119a47cc24c8e3f1c3ed3a62955f4b866b",
        "2768ba24daa523b82ba92a4a",
    );

    /// Official `ssz_static` `DepositRequest` root from `tests/mainnet/gloas/ssz_static/DepositRequest/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_DEPOSIT_REQUEST_ROOT: &str =
        "093f80385fe508aeb2f034ca209f6cef2b4f43f4738b2dcb090888d878e23e34";

    /// Decoded `serialized.ssz_snappy` for `DepositRequest` from `tests/mainnet/gloas/ssz_static/DepositRequest/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_DEPOSIT_REQUEST_SSZ: &str = concat!(
        "a29999ba4678842dde820a8935245ef95c66a478ca724c22856a9a5913aaa7af",
        "fb70900849dfc1a128500f61a047825e74eb9eb6d071b4dd34d4a81adc252816",
        "60da46331201dde313c7c74511dc408c2731cf0d31b4eea8d99ab01af4aaee12",
        "b631e7f54b1b4ac89e0dcd3bb59d5583b25e688dc6634ff49c33fe0aca4d957f",
        "6f7cd5652eea82d60e872205d75219ef931236a1e6832eb29d86ccfb14fe0031",
        "0b43920a00210cf74f6613a239d4ed2c12825f53d2dda65e57af6c6ba5f64115",
    );

    /// Official `ssz_static` `WithdrawalRequest` root from `tests/mainnet/gloas/ssz_static/WithdrawalRequest/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_WITHDRAWAL_REQUEST_ROOT: &str =
        "71b6dfd81b49e04aed0f6b42df7e28a9be09b7646a27546bb97fbfdc05f161a9";

    /// Decoded `serialized.ssz_snappy` for `WithdrawalRequest` from `tests/mainnet/gloas/ssz_static/WithdrawalRequest/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_WITHDRAWAL_REQUEST_SSZ: &str = concat!(
        "1d08850aba3446293b1523cad76d94bece25c6034c7ca442aa0e2ba00e035e2e",
        "fc0a230d2982b83aff22bd3eb64c4dc34d57264caad047f504e1a72b12446927",
        "ecb2f390d4c45e3599107ae8",
    );

    /// Official `ssz_static` `ConsolidationRequest` root from `tests/mainnet/gloas/ssz_static/ConsolidationRequest/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_CONSOLIDATION_REQUEST_ROOT: &str =
        "5b3a102baf5e2658189b8db69f57fdec65fca7713ec6689172fe1a305741a81e";

    /// Decoded `serialized.ssz_snappy` for `ConsolidationRequest` from `tests/mainnet/gloas/ssz_static/ConsolidationRequest/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_CONSOLIDATION_REQUEST_SSZ: &str = concat!(
        "8050d4cab659da67409ad993608c612f3737a5e03d3318a8103619051e658c0d",
        "7c8d40ed6ce2a9988cadbc91b5a6b0e124ffe749a301e70a7b2f7dd42d6b31f8",
        "eeeed8ff5b15f893f3fee660ca4ce470b08e0180ffd58d108080f03a03f79d03",
        "71fcc97c397e57969ae4ae9456afb00879d5b0f8",
    );

    /// Official `ssz_static` `BuilderDepositRequest` root from `tests/mainnet/gloas/ssz_static/BuilderDepositRequest/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_ROOT: &str =
        "f18cec0ee9d30e11b89192f30903cf37d5571d4fc012a680914ba0aa47eab06e";

    /// Decoded `serialized.ssz_snappy` for `BuilderDepositRequest` from `tests/mainnet/gloas/ssz_static/BuilderDepositRequest/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BUILDER_DEPOSIT_REQUEST_SSZ: &str = concat!(
        "56a6fb135c6ba4a386bb381dff7162b9865ee92e4f297f0b86edbf53e403b0fe",
        "fab90ab8b8771992259146814be0f87e8d7dcd49065bc850671d571cacdbe62d",
        "35cfef12f264cd952752b6e23e1804a4878c12aab137ac85313b0fc25c79d9e9",
        "d9b22838467e32cbbf30ec9907f38aa32cf57886e4d7d647a9250a04e0e8ef9b",
        "259f3dcaed222eb866fb6ddce4162e5d4432b2c8c059fb794f5a5ea4feb49fec",
        "3631489adbbaa59cb63ac496f4beb8111713cf2a09dfd496",
    );

    /// Official `ssz_static` `BuilderExitRequest` root from `tests/mainnet/gloas/ssz_static/BuilderExitRequest/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BUILDER_EXIT_REQUEST_ROOT: &str =
        "facc2584c82aff28f9933a1afeddeaab473e62a83154b6846e2d4a4762535a2b";

    /// Decoded `serialized.ssz_snappy` for `BuilderExitRequest` from `tests/mainnet/gloas/ssz_static/BuilderExitRequest/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BUILDER_EXIT_REQUEST_SSZ: &str = concat!(
        "6710925d0c798f659ba52dcf058567c76092b191d8e381c3c573de52a2052167",
        "9238f16a1cdf9bf45c14eacc85cb8af0794fc7c2ff68557f707faa302373714a",
        "bc1ec69d",
    );

    /// Official `ssz_static` `Attestation` root from `tests/mainnet/gloas/ssz_static/Attestation/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_ATTESTATION_ROOT: &str =
        "81bf881829df7ffc48c62a270a24af050c7347dd0c9ee7eb12722933fa5b7018";

    /// Decoded `serialized.ssz_snappy` for `Attestation` from `tests/mainnet/gloas/ssz_static/Attestation/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_ATTESTATION_SSZ: &str = concat!(
        "ec000000ad40204915078d130533954d6238aa199da5e81e889b1fac3142f4ab",
        "3af01e29f6f7cd43435071393c37ee5f3d0e18a063de83607df7903d17269c45",
        "333fa58afe9ab50a1e56e6721c6ac97c57d6d6951d38c131cd8640e7948547da",
        "9481c99059abfd546f66c23f5d4885a9a849596b44afc433a2049764547897ba",
        "3730e94b2efc330a60798cc8ec02bc1580b8ab05cca6de0b708a1201c3b22e27",
        "3d011a825e24f6098d9a6b4bc80520d6e3db2ddccec981c346e40f215274f8c1",
        "532ac0bfc99ceab37aa0287b9ed5239ea386cbca104704a361c7bc0eac1a836d",
        "d1815bdde14865b0955fc3d602",
    );

    /// Official `ssz_static` `IndexedAttestation` root from `tests/mainnet/gloas/ssz_static/IndexedAttestation/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_INDEXED_ATTESTATION_ROOT: &str =
        "87b2efcd66379b40b49e0ecf1cbda6a017f348b8706d014936b9786898032e82";

    /// Decoded `serialized.ssz_snappy` for `IndexedAttestation` from `tests/mainnet/gloas/ssz_static/IndexedAttestation/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_INDEXED_ATTESTATION_SSZ: &str = concat!(
        "e40000005b59e09d1286862056ddf7c562bcbf6ac003f34ad53284b932c8ab46",
        "abd61c19d7d34b040944b9cc7a65f3734b9e7bcd1f73a6c40b934e2dc3ba1800",
        "ebd09f601d82ca7ce905bb2cfbcec213c3ad1ffd3e014895393d69eb3a28410f",
        "ad4a79194846a6392c59ffaa53a846f7b4096934786f8ed3c32b1ad569612326",
        "c82a8a2b82516e4c6a5e88ccc60b47038a58a110d0c7cd5f5e99ffdcd770d375",
        "40c53e154bedd7cb88272e43db1031b2c83a79fbeee2926e65fecd3f9b1470f9",
        "f59e0b530c13f0b65fb04e816b779da566315cbd020d7475b27ce0eca34d6924",
        "2fde48e43e0618a7ea599ec48a583979e53a144abc2dd386e995bbe369cb1a36",
        "f8573847d62c2fe268d18a20f54062896f384af774c41d53af9a5902633488ee",
        "72eb743465f0e2550b62accf3a270e01d4eda59c",
    );

    /// Official `ssz_static` `AttesterSlashing` root from `tests/mainnet/gloas/ssz_static/AttesterSlashing/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_ATTESTER_SLASHING_ROOT: &str =
        "97cb159e9696851bd2373ef8c8cc61ce9982f055316aa4963d0d9fa269925611";

    /// Decoded `serialized.ssz_snappy` for `AttesterSlashing` from `tests/mainnet/gloas/ssz_static/AttesterSlashing/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_ATTESTER_SLASHING_SSZ: &str = concat!(
        "08000000fc000000e4000000e42ef67ae1d7ca444695e1a7d92cd60c026b59eb",
        "fbe6f350def501d158803643de472d6c21b6f34608092cf178e4a807c3a76d44",
        "8a27c525e539c053bee46e9b5c3060ab3f50a93c8d2e109c07645582c4f52517",
        "338e418dd42d9e865a99558303aa716ee9700a37be1e471ffc21f6065859dfa7",
        "37c413086af917cd747bba643468009dbdb1611cc05f7420e707e06defc81aea",
        "9c2f3b5f3a4a7e38e5bce6a3828e83db7e65842327c95e04fc8f235e1fa8e27f",
        "50bfb9112c249e46c6489112fa568a93d6fb49eacb34f2071042e281c29bb123",
        "c6fab58f397fc57b10893b1d038616a44702b8a9ebab2dd65f4012d1e4000000",
        "73a839e0bdd31d15f00d884ee075e8539c45a8ee2abb33e61b20ee22492ba998",
        "d8261c4fef27b84396f94a4e9e18b28b566aa9dc7b1664ad24a780b48f043c23",
        "8f40ffaf4359ca975befdce666e7d00e549736c624fb791911ecf929baa58458",
        "d79a2de40182257ecea0b8b4b94cd599c4abb39db3c20f9a25084e98b1da3e0b",
        "19b53ab984541a49ca31c6ef8337ed35e07e20798b24ffe5bfdd541715483b54",
        "32af832eb870ef9f512295c764cd4f81f011de025a7e9155dcfa7eaf74a0c79c",
        "d21d218e7f0700e7761096c8f0b33450b04fe627a8959f80eae9421576aa7f63",
        "c436d4c170d5f71c8c3ed78090e12a546210c2924817a076094470eaf7aef558",
        "f546175c2de8b4c5a71ab552adcd6998bed9dd80e7661b746aea467526ec6ac3",
    );

    /// Official `ssz_static` `AggregateAndProof` root from `tests/mainnet/gloas/ssz_static/AggregateAndProof/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT: &str =
        "680cbbd426d774ca9cc5a1b2a9df6000db5f0ba3de2180260715b31c181e66a5";

    /// Decoded `serialized.ssz_snappy` for `AggregateAndProof` from `tests/mainnet/gloas/ssz_static/AggregateAndProof/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ: &str = concat!(
        "a30e79816f72e8866c000000a3d2f79ee3a2be6166a79f69dc58e62f3605960a",
        "15857b8102bd37bcb9a602a0f609ab7dba8cdb94c00a3b608388bc175876141f",
        "e7b292f58cfb43926560987c64c9dfa51c0547e41b428e1dabe5874dfd868206",
        "16df26dacb90539c7dbee0ceec000000112ae89268fca3d43e43b375e55412e1",
        "d0110f43aeacf5158cc6eeecc9aae20e37b6d47463e1bcd76354e10138719962",
        "a8bfefb6e7f5afa32c3edf8913ab5dd3465c224c36b6fd46d47e6a31b01e15b8",
        "e4202eab9929cd8d0ceab6bfb6cef67d1376e864a6753643d8274ba619213b0a",
        "a1299c4cacca06b66f9db91697df4527c3a412f323bfe301b1a5dd55223fd873",
        "bb2cd1d79e2794b8cadeffa8b992b7d3fee8e5c82320c4b8333e10a6cf2ae2d2",
        "12731c1648833cfd458217fb8bd7183ab6509eefecdfcd5b6c5ca7745b50a31c",
        "e0584762bd20a9bbfd61c07b23d5272a45a45cac69c4be7f7a",
    );

    /// Official `ssz_static` `SignedAggregateAndProof` root from `tests/mainnet/gloas/ssz_static/SignedAggregateAndProof/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_ROOT: &str =
        "33deb395304be5142f59b8aef865ba6017727fcc12f9cbee85a847d520ec2324";

    /// Decoded `serialized.ssz_snappy` for `SignedAggregateAndProof` from `tests/mainnet/gloas/ssz_static/SignedAggregateAndProof/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_AGGREGATE_AND_PROOF_SSZ: &str = concat!(
        "6400000067c95320b8c5dae14126d77aca4b8b9ab961f42b9c1adca8e1a489e0",
        "b3e8d7523774ff5080ca48b901c2dce8f7ddea754dc38a3f6c4205af80e4a221",
        "efc95da48e0d79d6e7bb082cfb7dcfeb9defae010abc9b6d8387785e7abc27b5",
        "d948bc62b1ef63f2af72490f6c000000662d982fc6009019a9abaa5aa2e20b43",
        "efd63cfa92e5c06eadcbea57df7ffcbc7b3cd4c99b983beb6c81519508d08138",
        "beb4df8ad8ea2fc9f1dfd9dbb21a5f504c50d54ce19b7f9d46fd67f3405f755a",
        "3004785ac4e91e59223d8e20aaefe3d8ec0000001c369f0ded0897f02fe78298",
        "4724b20c55abe012ef7064d03b2bd4c4e69dab2b13ba906dc67fee11d39740f4",
        "c1e3da3514d45befbf7b261dfcc23161abaa6351c3c4b663328af2fe801278a5",
        "829ddd47e3f63fd5d75da54722093c79753039728e47125ab17fb509cf01b36a",
        "35700f4e2387932b1e7ed8fc8e6a96e653fb51b78a760612f02b2ce32d1f4879",
        "99176540ea749d1eb52cd3043bef4c2137d20af16135a3761842213cecf4ce23",
        "c79c9acaa3676e364cd697c971c7eba00f59259e942b915ab07c9ad056f2e57f",
        "9a34775605859288dcbbcacb071570abaaf1d324c5d4c6da973b141430",
    );

    /// Official `ssz_static` `ExecutionRequests` root from `tests/mainnet/gloas/ssz_static/ExecutionRequests/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_EXECUTION_REQUESTS_ROOT: &str =
        "68435dba46dea342c790e5a55c9279c2d490f4aef04866c1f713f3608fb444a1";

    /// Decoded `serialized.ssz_snappy` for `ExecutionRequests` from `tests/mainnet/gloas/ssz_static/ExecutionRequests/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_REQUESTS_SSZ: &str = concat!(
        "1400000054050000ec05000060060000400900005734257b170cd7af054e2438",
        "921d621f84c67a86d68ce5d9dd6cf23578e19fd14a39f7244c795b7ebc7dc5a2",
        "cee84293d15a7f6b7ae33d52058cfdfb4df78bf31693b5f56c94093c95d60d78",
        "9163de5f25494091c0c494f3281db55d66f16d2d320f60c39e79b78ba99adcb6",
        "b9074130481378645c5347f88e6b9a0563d662ba2cdf0f434aed0bf54e7c7fec",
        "1446987f63f10257241a88d936cb4b0a16555229d05727a6b9c59fc861da6cd9",
        "c2721b5fc76b6b792012061939c29291a19e4dcd3a69a9fe677fb258215383a9",
        "1a718906d90423f2a51d1a135135bf89cf5aa5aa2a7b3bbafb954e321e5aa64a",
        "f4af238739e4c9e72ac56c0b6bd09c98560dabf97239497c89900a3024496d6c",
        "82d1b3879623edaebcec5a487245e3e4684d5e7dc359ca0d4a9133285b18dd90",
        "b54fa87c438b003f0dadea5034d640fd6cdab2f235998a5266f3bbfed73fe70d",
        "a6a54fb41dab893f6a86dd8997a0e1873888966edc9df0862f0bbecd3352e07a",
        "3c5acd48277fbad07db9caad05c1e9b835c143a374a012c6e41936c377eec0bc",
        "bc33dcfa3e6d173be3721a95a30ed12ee942bdac00cec0e2bb7f9d2bfd9f719f",
        "606d90fa9288e2fbd89361a0b2d4852a9138eb7567c73748dddbea55f72f9ae2",
        "07156b84ca5863fa6eae12665fbbfd9b76354eee905c08b4f2229da2f1209c69",
        "b6a5957fe24ae62fbe239f83517b940accd673f177fb30a59bbf836790d0fa5a",
        "9a36ea3be342ed51cd5680c884c086ffe8d97286413713b0a49a7da1c0e7be86",
        "947fe47dbfcf42abb228a756a966f5ea24c15a776a682c4cf3cfd38e0cb2e4fb",
        "d075e55954d56d63eccce0ff99fc092708e51c15838a663d3d31f71b3347c4db",
        "ec62b3e2f144e46ac445b4b1f01771f0f0add982b909d5c1233d6a2997a1be1e",
        "5d04d1d962b7eac5323f219281f5958adacac61ca12dba2e5ae453831865fba1",
        "a1fabde771ca47366fcca81685f2a4fe9b20bf70f435976547d7259c834f7b11",
        "fe1249e705f8294ac71ed3cc8b1fb7a5a2e9680798089d8391ba932248d3e69f",
        "d392b3c9ca2b2fd3deab0d2f0830e5b9de75dcab212a8be611b79c826984db5d",
        "d5b5f3e23048a7ba90ce9e38b6860032663fa0568e82ab198d77da02b332af5d",
        "af29e5dfd6e7a555af77b738510d6684279be4246b6ff27b298ade1153a925fa",
        "724e53291af7352070aa9fd3b59a76c3ece9ac971d975f3619bd53816bdd165d",
        "f69ccd5d28babb143a7b6fcfa3bd883eee06a37ed53af369b944da2f24258924",
        "b2af032baf9fc8b50e281a0bfa08e9ebaa31a20ef743061887b65cfa58882f71",
        "90d9c661a0b501748ad61d78be27fad66b486a93d4a6b9f326593720dcec2688",
        "5e24b8091888a3feb5e77aaa64c01ae4548393209b727c41f696f35406c44557",
        "135565cc6f3f0173f24e46053b90b91c2c47a40689ff69482771abe011acdbba",
        "d8312d47f1ec806e92c21046964a32e505d1ac8fb6749e909862db21c303ba08",
        "785ecb88372000f453c533bbd4df88f7d54f883501e7f3467059d2388c51cda0",
        "862983d103f698f09ac2a982f53fefe25c504102458fc6963e4eaeec7695922c",
        "aaac67fce5c4aebf05eb62fa48f4d88e8cbbdee83bccda44f44a2d083274fc55",
        "66b39164c5d711a92e6b6e4a5db048a1c7f00150b67c3fd9ce45db48c4520033",
        "0e6aa63255d47f2f94631a09e4b594dd3d245b78b21d598eacddb7ca4d64b965",
        "3b68afcbc6e861c5687bad94deac7414dfd6cbac6007e7d1586c4411ed85b7d4",
        "c4ed1d99c22927972eb545e61ee05d7a05dbfaa62d55b9414188e91d6c61fe7b",
        "3c1fef2d517c3fde057701cca77213b32b9e241525e10b568aaf26b5e2d92156",
        "43d26ed32e0defa478bd983fa394ff7be699315acc52dc791fd729f3c9133e78",
        "ae0e3a3aa1c2612c135a6fbb12f05407a1d64667e39d62d01c01f3e317738311",
        "1a14e11c917cab7ffade5a34d9afd954aae2e57d1dd4ae23b040ef7eebd1da69",
        "59f306a656ac60415a0f04dfdc2b55131e92ba8929fe4f5fa0774bb8c3b7ee80",
        "1eb1d11f732affd3be5e5c5102005701f152da6a299f81a486f630cd3a07b16a",
        "4f9f92ad2a06694d883969f5508956020b4665868899057b1f38c64de3832fff",
        "d137ccb4b9534bcad36d4246a7c2f07756e34c34c32f361ef29c8bf3601d42d8",
        "8b8926ebeda9b927a70a1cddc01e57dc193625a5c8675be0dbfdb00ef7f953ae",
        "291cc4e41db4638cccbe02d2a0fadeeb6ba3119928424b30e549ef02c4cfeda7",
        "ddada30e836d458aeba26d4a69fd02c64312336a603f1bb0003cfbce6c9f680e",
        "46c1bd417812aec9d34c9a5445d454f95515bcd29d4a874b15bb1fcf7e3b4594",
        "e411ba1b043183accadbbc3a8dfd84513baa0833d85a39202b806c2744c96294",
        "6eb47dba02637518fcd4f161eabe20c1ff974dc39e2f78eaec8bfcb630410fad",
        "17cf7e6ee6502e334169f3f2fe8fcfb19e5023af7e2f94d8ebbc6655db7264f4",
        "20c4614dd5c95916e9ef1c1d1791fe41ad75417c722ec7424736fbe33c01af1a",
        "8c1fb89fc80f943729e7cde95a30c6d1f89a91d3e9ae781d96ce30d84f776b2f",
        "88176c148c935505e91825994e1fbbe7e9301ea238ed4bc2e133c6c42cec779c",
        "d6721a14204554a0b546ebfc16c5ad4270bd17b3ba32ffd350081972b6967121",
        "750e1f5e4f9cb7c0c4ce497837b74773a1bb41728952c791422a0ccfb3053abc",
        "a75e865873df3a7bcbb1b48c1bea2de1e7a98bf947b4c5608e74609c5d8f30cb",
        "db91079a4deef39c58aefe9444c14379e61b383b27c4611a4bf5f60471937ad2",
        "ea2cd86b1025568dd053ab23944732c45bc2324a3a04257c54b183170e82f8f4",
        "7726c41a33cf6b2a05613cd9b914e6a9936805a691d8da1ae4042b962cd5e3c5",
        "783b2b3c4789211422c35d567eef942c1bbaf79973f1c6c316b1625f2840d7d2",
        "169e3320f1f2d5e7d013aaa877ac188b6f0572bddb1cb71cb52035b4dfcf9379",
        "84e2d6e59e0c556d79b171c91b7e7c845cb951d6887520094344e97a159195e1",
        "829ffe8231f9a1dc33ef4657a1eddad3b182008b45e6b7572efc9090d2558b31",
        "19a8a35fd891fdc3c0804b9a4057036312a223d5ea950b86bcc1708eb214ec56",
        "9457b428bd38fae3227317c3ac34a2ff0c83073c9622943d0f78d27f05f42849",
        "46f9f089deed6d22bc5e6f5a6cd255a8168e8c0e15eba3e3231b2e4ebb3dad13",
        "f130418a7176ee9afadcf3188b86fa4985dea1d7f01f367913f58cf1fef922c4",
        "520c7ccdb8f517f9d2ae34cd260b39a2e449c19d476b5977e4ad39557dc46fcb",
        "7eb1d6722a05a73b3e3c7ed3fa1d9288951ba6cf51f0c1232c8c758b903390fd",
        "b03be54fdb36cfbe0df4a0e2b593ffd28d55ee0c5381a5ecdc0ad8c27b8ab25a",
        "5d29b820a07f09c722e685bcec549339f7463c3dc4fe809d636ba196153d4092",
        "b35509ddd90d9fa18c1dbd01a57a6798a1d372c06d4dc97be21fdb7a5829fa0f",
        "272b4f52c4cf360a63cb67642d76df2075c959de5f716d13e1e689ee19fbdcf2",
        "a0e5657b25552cb06bd2a9409e57066c696794d14cf9d41c9e9ab66eb117dae9",
        "47b3cc2997a958875f77752f2b54ded27c043ba52380289ce3c2edcc463c0b15",
        "34c39da8812bcfd157d57148d00abd8ba9a457d822d73875bc6a7771189644c1",
        "44592512019b8a5d71145f4a2cc23e19053fc0597f831444c9de92dc648c387e",
        "bb608172f676b18aded6045a1a4454f55db577e3a4f3f0d0e0e5b10c2164243b",
        "c76bb59643fe0d16268646a9420d1fe7f0e0664752cdd5d515fb89d22a41f7de",
        "b5a9041505962039734237e2842cd913fe6c1ac779be22efc765ee79b15ab166",
        "5c455a5a3718e876baf05edfbac8ac4ef00166b1f52549938b95d77dd136a04d",
        "e1cdd7dd46830f99c7e5dabdb17f82ba4c0212f423d75250cf4ab14cbedb25df",
        "12e893b7913dd7c175f2cce9c718f33b8d1b4fe44d4b61456936c88249ae87cc",
        "b1c789a6f56d129f585eb6ccd9528d06855aa9b6751a86311827ef22e137ed9d",
        "7ea59c4af39d4e345da7fa57a1b3bebec4884d715f6c544e1ac427417719d800",
        "0578d544144271d30c08ca3b456b7ad6d78834b8177fa4f698c5b299474b0b2e",
        "034cca4787a32a1d56a56ca6f7ab08c32a0b713b2cb6383cda76223c6aa9d360",
        "c97b6cf757abbe1d9ffdd5e932eb794f7ea096cefef2e836dee9a870a60ba949",
        "fd85e4f9073981c7e958b6ef9de5ecda686e28cacca6bdf42624915eff3b9c66",
        "2a31000e85238148",
    );

    /// Official `ssz_static` `PayloadAttestationData` root from `tests/mainnet/gloas/ssz_static/PayloadAttestationData/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_ROOT: &str =
        "c61864e2d30219f219bf7353024ec37f31b46ea4f5c7468bc1fd886a4c6ab046";

    /// Decoded `serialized.ssz_snappy` for `PayloadAttestationData` from `tests/mainnet/gloas/ssz_static/PayloadAttestationData/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_DATA_SSZ: &str = concat!(
        "f331c5d5b48f4d644077ce99eb7fc8c0f8112900343af2c5eca9891bb3773ccb",
        "ca4ddcd69f8920cf0100",
    );

    /// Official `ssz_static` `PayloadAttestation` root from `tests/mainnet/gloas/ssz_static/PayloadAttestation/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_ROOT: &str =
        "ad208bb58e9b84924abc1742d25058a08bba11b5e9a3032a26a3c3cced958d85";

    /// Decoded `serialized.ssz_snappy` for `PayloadAttestation` from `tests/mainnet/gloas/ssz_static/PayloadAttestation/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_PAYLOAD_ATTESTATION_SSZ: &str = concat!(
        "3058ebd7d8f545c9e194eda284a95861d7501dc11eab5785febdeb4b4e616f5d",
        "4b881d000ffd9a4a634558214fb477b1dae30f63db128b3d28b14006c268b5d7",
        "972229b21d1339ecf520b9ce03e2a9a2b6ff517408ea447afbcf42adad1dbe94",
        "58407b40466d77f501007bb8e65799f38680e2cf06212e1a074110e299e0799d",
        "5d3078b8b00514f0b282aa1cad66d6a0d06f4a91e4e3c19ae21a823fd917d280",
        "6644d6e7ac4cd937f2625b6381c63a5f92acf019aeacaa0e760fd1718661d1c7",
        "486bafe6f18b02ac4f91",
    );

    /// Official `ssz_static` `ExecutionPayloadBid` root from `tests/mainnet/gloas/ssz_static/ExecutionPayloadBid/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_BID_ROOT: &str =
        "11471715ef9ec41be53dc849256284d6d0e57c9e252623968a56483bf25cc983";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayloadBid` from `tests/mainnet/gloas/ssz_static/ExecutionPayloadBid/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_BID_SSZ: &str = concat!(
        "0978b048461bf112185e3fb78b17a0a4f6ee84a85869192a1cb0e2d44a220b89",
        "f6cdbd0e17deab4adf9a3847ae15192ae9ec6c2f39dc248d8c949418822005bc",
        "848701a0c29540e54242174efa52b675b1c318be8878f50cc55ed7007e32cc02",
        "76d5afe9d44b367784367b5b5a9a14aa94d7dc720d44cf8cf3a31472b07bdbe7",
        "59de57014fd8c27a3163ecab3bbd37890c8c2eb29d797074e952d42693d15586",
        "8d6789868ccbc79dc645f07b17d468b37253ecab7a45aec83bd92b80e0000000",
        "024c32fbea6f7b2e1b7cc01a30e67ff8200b2064dd810465c0260e0ea2e664f5",
        "025827d111156bee4a9331d2ccb7626d1861d260439010d0133b9d1b9a551414",
        "bebf6b7926008c95a884d2e75df166a0285dbeeecd3f7bf955ac3aed01ddd105",
        "23e7ab7e0dac986f3635069c3d3d13ff1068002628eeb031885aa019b7596d69",
        "d48791370c052400379f9573a0a8e15354a684f09bf889ad2741b45da786c9d8",
        "af2d7dbfd4502e065158defe7e9b9021",
    );

    /// Official `ssz_static` `SignedExecutionPayloadBid` root from `tests/mainnet/gloas/ssz_static/SignedExecutionPayloadBid/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_ROOT: &str =
        "fc7f8966e063b02df38781901bb9433193b0ed1b6bd226a47b2f76ca1a96f78f";

    /// Decoded `serialized.ssz_snappy` for `SignedExecutionPayloadBid` from `tests/mainnet/gloas/ssz_static/SignedExecutionPayloadBid/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_BID_SSZ: &str = concat!(
        "64000000fc02124558081ebffdedc0178cee0de08d0a6a56c0ecb40bca978517",
        "ff29354eddf68254628416fdbc54e72a194e9a609ae6c6ddca91886f8dde6136",
        "fbc10c8be88eea9012ac7295473295aeb3183274534f0ac69c41715a89ea6ff7",
        "87748376f54668a49d4689f27325d8630e33c699edb0d44d26589a435c140676",
        "80c6452d0cfd1076e5039d6b0090141fae99526a9b7e6d4c3db43f10a7455217",
        "97252e22560d93ba2d9d0a6cfab8c794b8cbe34c697f0aa4a14cf4637625f3f2",
        "484c474c6e806339f1167d2149d8dd50b83876fc464e5632a6c400ed71219def",
        "7d26567e062c1661e2c7fe4ec42929641e837a7aa2178ec8eb5a25dd77b79961",
        "49acb4138b23361024b7875a4385b7394f037efee4af08d05dc5adc635031ea9",
        "e00000009da3d4e4bab74bb5abd0ef30c1b3c676dbb85f465e94dc3edd967973",
        "942860ece3984ae59e7ae2adb508fffee02c31cecbb2c0c0e2c12a4dffa0c5dd",
        "01bf97f2db142b5e78a11e2109ac71dc0b6ab4d2e92a2c4b4d7d4ce30ad6296c",
        "6a40b7f290309c213c965a7ec5fb60d953a6694eafe5bac8f7bf1800e567d8f7",
        "fe46becbbf1a4ef8712d93e57f8816d4b1cc68b1aebfd7c8feafe2d4a26e0d7e",
        "7a589f10377db377e2731ef292d3e6baeae78584",
    );

    /// Official `ssz_static` `BeaconBlockBody` root from `tests/mainnet/gloas/ssz_static/BeaconBlockBody/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT: &str =
        "bcc9c7282c844a9ce1894ca1d345f6670ddab8e4804dbcbf6c9994f84a120158";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlockBody` from `tests/mainnet/gloas/ssz_static/BeaconBlockBody/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ: &str = concat!(
        "b9822778c7283d035d00fbc139652f8d571e2dfb8f03be27e47c514173eed7ec",
        "a576bf7aba895047bac6e25136685b4b2b2353ff404dfb28dfe51c6f5c355460",
        "141a4c67b8f010d516daa8c72cbb74f1f55889a899592ccc70761de80680c288",
        "8b20b8a988f8125b960347db91caab335811c9e9c89d13480bb2d8cf8e9b8a08",
        "2288f4adbc00de90c7e8871e95dd4955dd8c327a6186ee930621c4ff2275c5bd",
        "49c26465870f691fa32d45592cccb4a415c8d9d26dd81c0bd2eb923ded147acd",
        "2df14d414e6ca75d8c0100002c0300002c030000f0060000f0060000e9ef16e0",
        "5c77c3639d7968b97e453b6c76b0685afe517054e13b6f11c67b396d9730c7bb",
        "779283d20de12ef0f7f302e1354b53ea25171bd74c103a0c721073a5310ded9d",
        "7abc4f252c76500630daed89790fbee98359d8e09986f11ee51b3ba33d5e1705",
        "c62660c38e2a9a98d77c2f4b0a12c12f7cbf7e147d69ebf2007083415498901b",
        "d88247c002ba461c1ba7a36d3e68d0e76268fe3f1324ed2e66f55e1860070000",
        "680b00000c0d00000c0d0000aea1fa3cdfdb2e26c5ed9b72eebfde11c4631c08",
        "92cd7098abe6858825ab840a58a241e97f6a5ed24be9ce2420d820db792573df",
        "0eec485f224cb7e2edb6872d319c555f48ac5454d04322ebc93ead3d8f1b454c",
        "ea93bb78131dc81372989be8a30c1228d8e5b58ab5677e880f97b970b9ad091f",
        "88ba0a8e72f873f4c3115873a17019190436ed8b4ffc99eb4304c7a54efff4e7",
        "16eccb467e98c42d37fdff723ddecbd0f692e5be49861a6d7ab510d626f7fd70",
        "88759957edd0b5ae67e96762d934fda816d004ab5cb8d1be25d416c515e4b1b8",
        "dd0a1b85125072db913cf18259f5c035cb7e5a374b86cabec5f249560f2cb26c",
        "9baf26d729769b3dec97d3fdc0a83784b08b5fc6134107c485b7762a883f4f41",
        "918eae0bbe1db8d6b9d289a421b2a0fa10f6a40eb5ab2eea6abf167c81fce10c",
        "cc27287bea5296f9757c065b49cd0771c4df5fab084c2b5362f38ffb12058fae",
        "0d244066fc02325e72f1950259711022ec29ddb83eba570814e81deec1a5f98e",
        "e8ebb709cc811d39c338753236fcd7c73284aaf77fd1db9172f829ddd0fc2a32",
        "ca92e0f044657d89948033f210000000fd000000ea010000d7020000ec000000",
        "43d634a77a15bb885b99543cdbfc97c7ffeccda665ab600ed61ebb0446b84ae8",
        "a8d7e05633359b104f37f091ff0a72246099ea34b432b48cab6480a471052ac1",
        "1d87848ef52c15305c9a0f763e5c101967a11e12264af196d2949864804d213c",
        "bf4093770ff37c59072ac8a844ff761d896e9eefdabdb9c79ed9d638f8cb302f",
        "c4688e21d71a6020f0944f32e5a732b29194ce79795773989e1cb4cea290a452",
        "12a6a353067f1e639fbc506fc9ea3966d76ea0aca0a62cf1eba33244be7e8263",
        "8d68c04ea4f2dabee2f4af9e8cd822817e57538feb5d4ee5598734a4231efccc",
        "15606d1169009a2b03ec000000bea9d296f268bdf3cef7e7096374651d9b3ed2",
        "a24ecc6fbf998f1a38994b57dd9206012c0d4934bee25f0813a57d7df8484cf2",
        "87f45d086fa886002ed144c4f760bc1fc09e7f7296c8371aea1818baecd5a826",
        "54df9a92314c7b48fec4921633df313361467f8de5c322d460708b6420dc98c3",
        "dc9a677ba8a0c871ef66db3db849d7515b5ffe77da304a32fef8d3120fee3f11",
        "655246c1a7e09edb2f5b04700d8b1535bb4933e88f04ed201ebd0182cff2424a",
        "6b15a5a299aea151e4c9cb6f1805d89f677445b9e4fcbc0fc335ffe3a10a080d",
        "0be06bbf7d4af526200add2b94f115608b10a6d7e409ec0000009b4b0a61a393",
        "08be29821e562aa5d2624fb4035f9c6d042b11befd4d81440f9cf8f09310da28",
        "93c8920d241db455d2484d34f6f195b288941939b8d1e0cc978cd56f21abc767",
        "3b2073231f9444e2c91c1f3f83a94e80b8b60e39f5bbd1306d94eee739ddc933",
        "8d2d8290709bdce120ee4cc4fcc41c673181a54150a872f29f41048674291ce7",
        "7c06293d6c8609eb5c4dafcea17430961dea61d5ed6ae99621c6558ac761e738",
        "39835a5651621eae11b60dbcca36acf2586288da3950276c44da01aca599a5f4",
        "7c1fddda56d0bbf02abc3522b44eaabd1dcbb5863aa3022cbfc58800731e5139",
        "60cb0cec000000e50e2dda06e94aceb22f54cf5a0d5c699912d6399e45089da5",
        "2e87afd256aced830965fa392de6d579f39f70f59b1f3385c6de5c9ed3e08aed",
        "0970ce2bfb39455948f7463f297c7f9cee02198869083853b178efae21cbde93",
        "8c3664326ae6919767111033ae5f2bd934fe06624af16a5ecec5f1351a16b88b",
        "5a10da4508796b7aaaf97973b713741c8c47b5d64c9b85a1fbc4f547f41ed5ac",
        "199d22b76236594e3222738652b5feb055b61661772669e2e3160e17432c3749",
        "6e4283b70b22affd352933ffb6321ede22c44d584c02bdf2feb686c3d893e369",
        "46ef28890e41606a88e6d0a08b91a109d4d1ccf4577179ab32bb8f8cae6dcd64",
        "839b0510ebe0c7202f52f516b3b8185c8f267e02a290c06d1fb5d515b952eaa9",
        "035d9e14cb5d3f807a14fdc1e22fbd0f0b6c40ac04ff45a345e48851e12173fd",
        "b68fecd19516ff9a081d87cde75d9b394140d2ac2aabbf5638456dc8a3c1e01e",
        "6661c455c1ff997a6729b9e931f9d2af75f26968f23f6f90322ec0ba1b6eeef9",
        "2d9fb7f9c476bd71626a8a60d66024f3c219ab3343e62a8d2d7bfb0ff944b281",
        "285514011a525ac771e6281ba844b69453a85e26b17cfa8454b1cbada36c0d8e",
        "36adebd7fb002daf9f9aa05cbf18d32c15e81c984e6a386d649a3ace75a4fb28",
        "ec429c4f15f2a9b963e5a0eaf11592bfc387ee858124e2c64d25f6115d5283ab",
        "39b7f6a1e3c7817f4e9294baf029119cd5fe8c1a4ed9e4ff6ffe1bff4439951a",
        "c52cf1b516c16142fc2d550a8110a1ea78b67178e51b0dc569b5068ff02e495c",
        "bcfe609f463eb7caf70dc2cbf9fb994abdb73aea5b5592a181fbe0a279eb7367",
        "c579b039f6401b0811ebbd823509e0ebe671edffe04d571444e81d35d92506ee",
        "adf68fb750457ebc9ba39bb7cf36f74be7ab8ac773a4193334fbedb994c764ff",
        "6e5fd874bb9ecaff15ca23d5410f3f37eaffa61a79c60b0499590c42dbe06440",
        "76a24be737b7751a11ecacbf2dda206916acac6b84a4c85a6ce295caa18fcae1",
        "f45c841c6eca9ea8d657db80e6f989098968bd2d3d5d8ba613984f76f6a4925d",
        "91a0a48978e403fe62168b084433a5e38d6b596ca328301d3806f12f55a867e4",
        "113ca0427a1d4cf9aa39d3dc3fe82c3f068a423386da6c987d654f6c75576579",
        "62266c1dcc8d0c9b8e3067941410b3ce35cf6850a66c05abdf6a204178c42a4e",
        "25ef86ee6373679fecc1f23a2e253ea8e5dbf1c3188cdd5abe17950972fa63b4",
        "54e0f8630004caea9d659c713a79d54514208af44c091588ad11b1974e7de987",
        "d2f92b6306b64d35b3294fff12e6d431f09439d63be78fe12c56c644ad4b5a40",
        "52ab501722d98188aca5ebd44e89fb340283c29e4d7aedaba0f9ef6f317e3ce4",
        "816b2a8e8d59e2eb8aa847535f4efd72986adcbe48d0594ebc1069f801b604f9",
        "885ddcf6d932dfd340d275bfeb2341a73724e1ca456f03d49bf4eb1e0d223903",
        "12b4dc4a1cdd19293fc99e266af24178d9e6d16ae1147922747d08b485c05688",
        "6ff6475670b79d982c2c97e5b68e4d90cdeea8e48a66b1a88196ffac8fc904c4",
        "b36c8ad3ce394d939022067b41e0849ec4590a27fdbc885bd7a4b53bcb7b2766",
        "6237684f4fc8aac8a5721dd4e44d4b74a51e3af945e003d58538d27e3ea94ad2",
        "050c7661ac3720b3f0e2f896baa939ab1f6c853f74ca5c42fddf4e32a7484783",
        "4e8fb10259661c7c2c437af798834ba3f64b9499a48e3392cc89e96f3348d605",
        "32cf1e402140522fb82436903441c3fe78c17211e9126cc20c4a164fe7e6548c",
        "cfa46f35dbc737cdbb35288443478853108cab10815e78554b1f9d7797880c3b",
        "a6555d9fafe8cd45ac5597c31f4dfe86c5caceac90a0d44ca3dd135a3764206d",
        "1ee8d95c28574019007dfc86f1b6634b93f63219a9184d995f50c99a02912a98",
        "503f167c7b998e88640000002516726bb335ea5c86824829574f4170185a9a9a",
        "bb43b184a6fc1d8b33a6e0dcc87c79036bc84105f0b597ea3404e23752362f54",
        "c3eff87140ddae4024f8171643d013785ebacddc9b6b5ba9383616a599dc69f9",
        "8272f8708f1dafaabb779f5108da36b76cd2f938b8d9528ab76afdb96263b1e2",
        "848138dd614eaa2165712382128cbb1441ecf0205c3713fdbdf9bc35b021e477",
        "3e1a95e732aa0a736784d16c83bec5414ef65a796ed9fd6f539e74b9b76d19ed",
        "319d60714045ca692f7119d2f6d612fdb3775d3564fe19b55ca6448deb8370db",
        "5409bb3e50441ad0748bcf351804adbc5b90997f96ad021555c7bf309139b016",
        "e2060fac7b15a2b29026e92d9fcd836ae6b9de79dfa7fc6628121b19e32f6386",
        "0f637f0432c8dac9e000000003407dcfc6701eddd5662512d2e4c48d1977279e",
        "3f2806c617d87bacfa3e2fa2dc970864ba463daa04e5143893dd1284dfbd6b04",
        "9a559a77d138b3dda896c147b5269f8c132e3ce67a9b1825965cd26e53a39d15",
        "deb6d5ab16b305555551a0650b3d57bfc6291fa3a1435e9b17fb979e7216d580",
        "88eec8c4d1e5ff2ba34a80e014000000940100005c0300004404000094080000",
        "51c581a65bc0df981edddc1bf9954c06045d07e40b3f8cee18180afe64b307da",
        "b7bf0585bcb9be5ee64d7cfce2e265f8188e0490e43e2de08e5124b5e88c49fb",
        "487a566dd4894474955b7b0537e12a0459156373279edeb977d6014a9205b0d2",
        "f5512c0f466aec4d9db6161053e8bebdadd698525af3afeaa3cc51ba0af640a4",
        "8288ce077a29ca0a37a2901a4d55551b59b6e6fac38099e4e89c755a5f33e625",
        "715509f286c8f98526ade50bbe5a9981b064e5c2d2de7c7cb27beeb3e7917cd4",
        "67c624e5cf7eea3fd17c45ac0c80959053018b3c2d068b3a1e63346b34f33c5b",
        "ea56b328f39a91baf3ea1eca2633d1177d72fb918eb6e417d27e1079f2084707",
        "78ba9adb4ee8904c70e115a4f111a60b28dcbb578d099b5aa48d45cf1254a6b9",
        "2805215a4dcaf0736515514d61bfce013b3fc95fc68663531a9680798905e373",
        "57e413d223bb3756e268adae0aac61226b71aeb38bbafd24cc2098f8215db79a",
        "628a5817d9bc8c348c3673f03c8af05915b4fc75a4d5dc5fd6e66b58dfc2a42c",
        "a0f10fca1449cad319bd9ce95d51c966e1eeb4f26c11d24b7ccac6ccfb7b34e6",
        "35ab96d00472c17664f7a44b376dd3fee74e393242653faec40c3afd077b60bf",
        "1658440f377b385bc2964d5040e812cd77a708679ac83a2fbac4c2dfb17e627c",
        "fd5873229ae0fbf040e572b3d2ac5cf2e7d376131ba51102c32ec7840f0e334d",
        "e09b7bf9a2b1a7b3c6c1e4730402978ddbe97350102b3bec227d6a23b2c6998f",
        "ebd82bdd29fdae72adf8e041c6c2b98f02a10e7bfcb5982e2ddfc942a35e4f4d",
        "9da292411d8cc75f0b04fd71ae7b25e8a414588d3c6a1e0eb72a028accc39dbc",
        "1995b484f96e2d00142e67784eeefe1b53258a7c6778ca8ba7a5f23857d2b5d1",
        "079c145b73713c92c817982176ff1caa6b3a34b64dc3d2caed26bbc04414c790",
        "c9f974458bb7f7825aa84ab7bec439bc7d50f1ee8b41c7ecfc7a4b827cb461ff",
        "80be3d8b3fc022ada7c57cc7bfba94e1d78d89fc83a9e871084002dd244447aa",
        "5f051802ef2e190358d66d2df1f7587f9e3146f1430ee3e54b95ab175700842d",
        "aa3e7923950730262d0281696fd6d429fa0c8ff4645840f5551b8dfdc3ee47c8",
        "e404bf5ba594c7c465d6696001300e6eb361dac6423e440f2ccd51113e068603",
        "2f7c9a1dc048b1e92842972be9553cc9e5a0fe1260f35d01a996ba88c27e6d9b",
        "54a559dd47be8509712862a110bb32a78dc42204981fa5d8760ff0e8493a219b",
        "0bb22008cbe1905c489f0390b34d6a82dad0d3ed1ba35d93067870c118d13d9f",
        "dfd27d6c91a5eca0077496458604f7b09f4740d3c7533fab7f3ee60032685098",
        "d97a2ff6b91777dfebaa93ac182e5d584f4c229783f9f911bdea3335ae58b715",
        "b204725725f1526ad2054853a41444590e161b2acf224575a6dc439f393a3712",
        "2ad1acf297bdba313e53f62b8a03b8253eba72261d6018fb1f039f76ba1d4aba",
        "1faffb8d0eda2e6a760041ec6e3c74043c02afeef62f95ecf8891321549239db",
        "f6553d92c6d8a59b89bfd77ad28d0bec13df7dc4a26dfba96840dd2706f62aab",
        "b2ca6a73dc6fe079fee3c68b821d555d694db8e25f1cc940a468df50c0fd8ce7",
        "aa78ea80e893ae72f1621768aa98710be52e9b86b7834a0d0ef603da3f2af2f9",
        "6b580664d33dff7a75999e3dcb5ceb2300aff91877244d0b275314947de68a24",
        "9eb6a3f554753bcbd36099776e190505202f2888a1a691ba343f4b512ba19870",
        "7df790625f5dbef9d4f1b68f5ef7dac59e87973624443ad14cd8fb5bbc12c0a7",
        "f34fbff4517e07ff3b25b4ba3ddbf23da7efa4d357956fdee36889c8a62467c7",
        "2612d56f7d25db4fa546db13a6796622aa7bb0f4c795ff01da0f5a4cb47eb56d",
        "4db59bbfbddec58daffa4190f39ccfb42cabb687434207fa6a502c5be248f5e3",
        "8e4c01ecd6e86a1fa3167de5f8b17490eb015596fefc1808bdfec8c32f2b7e05",
        "3f2a805d8dd4c287c9827749f6836a44df49d6913ccf03b5e111f5bdaf9a4428",
        "e05bcbcc31df4155eb258449c61a9ede253803def3a4a155150f1ba66477cd95",
        "4d75794be8b48f9a7a1a2fbca58897b17994e5b8a75530dee7fa545fb948f4fe",
        "154bdca0b7e6e1fca51e02877b8700d047fcc09a7942ce6c0a40a4e409cad1c3",
        "eaf6aad5487df9e8714d3ecb25bfb2cf82681a7d6493c42c30e61150bacd6071",
        "cebd9010fa2318aba318a1501fac5c82784e3691471bd0b627619f5fa3d70237",
        "92074890f32ecadb2a5d875da66cac370a331722f1b108dc8760ffc0594d9847",
        "1daa516b06f2fc97f60a52febea751161db3c483a89e9e59ab18c600712a7fff",
        "a0bb88ec9fae420d179bdd0a2f9e4fc744d6be5c4ef737c2dc5353ff43e809da",
        "668a3f875e4fd1ef495b7dc1ba1bed1870ed0973ac62276c8f739c53c0cb5d85",
        "865d85a7b4d4cd123b538ad67bcb1c08bc4ea9a9489ff545bb73b7b784c4eb1d",
        "579df4e421480a5eac7e03da171ed10ac8292c70450358ffd6ef5d7570f3129b",
        "043bd7394219b7291a8c57efb731e0b4837ec44d853775526aaaee2ee7d754b0",
        "49ffec897224f136475f7c0f0362f99adeb9492e05075a70cbdda5773b2284c2",
        "a117f4c91847802ccc062634e08145483561337a19c8d7305712ce8af454190f",
        "1b470cf991ac66f5da0863da4b2bb6f48bf0216f5acabfed770fbb49c33ef0e1",
        "ebe41bcd85a6ab5d10b3f8e4e13740b92006298fda47665023ad4311b66f6947",
        "003f0f8d305ea70eae7ebd3d2667849bc8f1eb84c34df8fb75ab18faa291e24e",
        "95686d788053c1b45509a6d5891d342a046284273ded8a47793977cdfb5cbbaa",
        "af04fff15f983594fb86f18c39cea6f3329cd12332d1a843c039a92c27af3a3c",
        "eb11566e7ef9b03bd144a6ef2c5b60a45c067c6080128d11f1d773af490e42cf",
        "0d1407e8c7a2482bd999638d5aabc5372275ac394b4bfa4cf37e8c5a10dec6cb",
        "946fc2f93524e7bf6080f5d24f5d8a96a74aa731e2b89accb205630e919932da",
        "f876e9bace25b8f734abd4334e40c9a53bb0c3426c1a9fda89281c0e538d7afe",
        "10fe39b7cd2df8113734f74b2e93f6352b9585483d69007fa2b450f2bcbe0ec9",
        "a1a5cc496de90e1088efee70130b4d5baa0ceda69c692f47dbc3852edd663042",
        "020bdcb9a8b426d37d53badad175b8d70fb5182a2e7677b854fe4d942c54d111",
        "06943235b32b2c2c597ddf9650dbdb16105bf20df7eec7c1448869c59f6649e7",
        "676b72b19008af5e3dc6a4aecc33fbda315c6148931a6851bbda119c002b2b56",
        "6a8d56bc9f720309d98928211137daa1dcb4fd5373bd32e62e72fa65ba44c2b3",
        "5289d09cd9533d0ed19f9b0c7a79f3ff26b743b67d659930442b9d403cb1a9b3",
        "95b871b85e28402a1fbf5b46255b5864b928714fe7afd32a56e86d3d60849822",
        "3b2913c092c25cf355fa4f114679e5f613624859db1bea7989778730979c293c",
        "6ec69a4291cf2a924eb4e74d13b4618e66d2e22e4a3651f9e35fc6a6e7490209",
        "68b77c6207ce30fbad9d1b70cd430396ce8d9ec225fcd0601f538966206abd95",
        "01222e1be31f89fbe0566ae75217ccce90c1831f83e7257130e2d800ed8c6f64",
        "767dc25f570e1ed0d106ff8c4cb84abd7081ca0d3bb9f952",
    );

    /// Official `ssz_static` `BeaconBlock` root from `tests/mainnet/gloas/ssz_static/BeaconBlock/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_BEACON_BLOCK_ROOT: &str =
        "8e007c75b39a8449f16120e7b2ba0836f9e0621fcd19f7eb235461d978854d38";

    /// Decoded `serialized.ssz_snappy` for `BeaconBlock` from `tests/mainnet/gloas/ssz_static/BeaconBlock/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_BEACON_BLOCK_SSZ: &str = concat!(
        "916c4f4e07351f8c7a9769e4a215f5129e2b3d5c4bf2bb6bdeb95477fd8e3a5f",
        "c24c92ce46f5679b9b8b31d106ed23fea5bd8fd5ce34ebc02c2874a0fd996683",
        "ddbdbd11e1330b4f0f6feaed1e19db4b540000000d7e6b1e68793054282284fc",
        "e3d74ea3088a30159f3ee014f1b09f88c52dd7154c34cc84961aa5d226de5ed1",
        "0778183424bad2b8c8fa0e50d5d6a9859c50f8b1fea50373ce44842ef43291c9",
        "7b339d7317c4966de2d856daa34f4cadd9e5afc16e7ba38e202f78ba025bfea7",
        "d9a0dd394c9df4239a68b6dcb8a35673cd60284112f9a013dc391494740e8065",
        "7c17bc5ad5d82dd74fbede251079b88382f552af0e42d7fcef0ab1ed189bed48",
        "7b6a74177f8915a4668b98a22ab13b65adf7cb06c9e0d2fcd00a83f18c010000",
        "8c010000600300005104000051040000e037fd6bddfa829e29fd2cb19e12f1aa",
        "1b08d637ca5e99217f4301abc7b2c362f6c46f243cc1dd90f5d429c987fae2ab",
        "fc573b3892139f56cead738d1bee2227b59e0d73ec32e290cf061485b3e44dd6",
        "484a78f2db75774ce8e5112210bba3994b15a4b184a74a9171ab8cd9007d469d",
        "c018db3dd1f2daf6d4c0b4121ce17069d8c209f258433ae12327043c5d45af78",
        "e5c2f4770e65ed4fbeb27106a0488e9bd1070000850c0000790f0000d7110000",
        "0400000008000000ec000000e40000009f831316b6077272e380bcd5e0b669dd",
        "0a5f0c491dcbe5d2b33192b893d7cb518e416972538eec307262ebdcc8256c61",
        "7d4c25695a1a54bc0a5edccdfef29dda86f64f655fcdb7e5c77351bb7c2ae5a2",
        "a6f7b5eaf8c42bcd7bf4d2b8e64b74589ce49427bcd22980195ef034a9bf8108",
        "537fd8c1baaa666b1a5df50f252fd44cb5fcfe1e4c10516a37ef40c29080ce5d",
        "96504f5f01482084997d4b25e795ff47cb8d4ee10c401da87fd0bc6e76335d34",
        "f67c4f4128516cdaff17cccea09af0fc45af8607582207776074cba83172d250",
        "49e7d6c00ecbe10990ac26c2e8a02ed6e40000004491e4663273232c0c721c69",
        "9945e11b3b776d5a782e2e6557f5c360bbef7e033ba9a4dcf99925dcf9f11f39",
        "721b8381ded361ef0d1279c5fbd887403188d2d4594f3088f0a77e60e474c48c",
        "3916e2d77794ac75a958e121c2936a7d2c0a99672700acd0d3623b4eacb03d18",
        "684e97d46c4a3c29e247ee79fcfd2e8f3cb3309b7bc36d5c550cf6bc21845c13",
        "374fec0294cc827f5f09fc97176043aa37bd54fe194042debc6dff2c1df49288",
        "5c37a7cf329f3e4384368218ee3ce36bc6a909f70a7fa12f1eebfec248289d99",
        "b598f6feef4dc106dc02ae60ba9cdaf06438976e04000000ec0000003a5b476c",
        "649fb98b67cb578227b0dcc2ad4bbb6e811fdafb772d11b5cf15dc0ac767834f",
        "ee78eb92763ededef26991213caa6651c208ea50018f13a3487b874737bebf3d",
        "819ef1464312f15c8c50c95d1408d422d04fee342203cd38fee4aa2b576e6b00",
        "6390ffb82f31e13e4477d2cabf5257059fc5a81a52bb50849d7c562a1c317e4f",
        "5f65af54132c70a0f456819fc96a6101121565624b66e2764c941f7ede61fd3b",
        "5d0f5bf231321a95c5350bafa9845f817dd2a5e7df43c452013f2915a23c506c",
        "bef189f0660475f9c631ad173c96f4a196d075a92ceaaabf664344ad988e4909",
        "147fef82099412e51b48bf3700aa7d09d08aabf81004e4d9b59e0abb7554c1da",
        "f4b120b31fd7fbdbeefd91d4760258a0f730af6a61a502b1008c82595e7ca362",
        "8782bd28aa50fecb35afa5d77739ad4238c083f497c5398ce7ea9a43319d616d",
        "86fb0838847eadeb4b1f97a24b452d6a4543b1bbef47b292008b7dc705ae00f7",
        "6f2e34e27be2587608c4460c14cd4ee125f31400955b3de2db2084db689d0108",
        "b676274e2a4b5eba062b8fed969fee9e2fb847ce12ecc6a6b58b526c1be6ddfa",
        "226276a4d4811a037b308ab9f24a1244fc0760a4ac699e4b727253c6388a8b07",
        "d5e839d55073256c16d28a7d8da1e2e04b355972941f429587062938636b055f",
        "f45b13d374ea3fe454d78df728afa81d62cd6b1f270166ed5026a63c7df87176",
        "20c1085dc016df1ad6cbd9ef1bbccb948d3ab2b5ddd23a5911aea8b2097a439e",
        "92969f0d15966c82bf66d0635b008ef21268925aab4efb6236e279deff80109e",
        "4342db549d3340e68b0788866ea5bb581b06bf30ade15bdb04bee0652f88d582",
        "d4c128dd67f46dae466dbd7c0e38fd3e1c00c325cdc70cad34951267f52433cf",
        "e9a29f01b3f18c557d65b48f222a223a5876444f90d786e6d58cf00ecf0e3027",
        "162e24fb3f54ecb36f0414db6575d75792dac47d510060cacab1a8844bc419ff",
        "a9dc2afcd6d250c5fb95717d6fd84b14af869855897c57d76ab7bd5a5d2d26b7",
        "9d8d23d1daf3b99c10addb15649abbbf5bf2ea6e6f56ba2b80e8de817164455e",
        "2e5e1faea86527a8104b188b7a20e194e5926a1ec9ea582f22e4ddce3026dc93",
        "6c8b3ffc930de8a6d1d5c3e2c8769782e5d6345fbd0b07453b60549bc0c66ac6",
        "116b6d696cd1349cad500728425ed5c63d9bb480376d5dbaa164a621f5cf2b43",
        "0d5b282a4b49f5c699a2692e63fcac8a392112e83dc656fe22fbe7511078020b",
        "812fb9e57cc7d227069e11bc5fd224260be9ee43f81f6ea03f0f403e0c76cced",
        "943c581950968bfebbf32e050fd5ac1de51e8f749069093c77855af59399b2b0",
        "5816870a1516e6c178664b8af01ed45e950231fd3e0ba8a14670794c54a5e23d",
        "9f67fd6e9215f9f92d81b66fc1db37504c3f76f46f9836947351d3b0dd54850b",
        "2a8a8c80f4537fe8d35ddad8a2d0e9c8c55a5ea84802c09152a1e38f84c199f2",
        "407f9cf4b11d2a19333548500ded9b7bdedd1f5f9879376ae845b6441ac768ef",
        "fd02af93fe23967dd5bbf322d748dba8db5ecdec86497444c9925940b0ab65d2",
        "02aeba31f90ad7ba647c08416019262fd37cdbd0dcddeb2bfb4f2ccc139f38b4",
        "e149da3f13386440ab2a9075ffc117e98abd1ea49adf91a08a5494e14203bca8",
        "f87966ba4e6726f2bb3f0c93689da6cd495097d6e13a5461b9afb43cc767f951",
        "a2b66c8cfa5eae6f1b59b8f25cc648653b770bae11b5b0f94639bf29dc99f725",
        "60165b52ddf30f45419ba9434a9f480a7a05fcb43fa573c824b1814677bd8872",
        "eff38670da154344f89b321cc1dfd11c2cd59c2f82265e9fb43e69b9844c9961",
        "21578e4624ef2d3725e8ffab539b6bdc4e3d7d219ab23174311d695433ab1cd4",
        "0249763fbb9027b67936fd627adafc2098ef58202c7a7a29a989a8364cc4327e",
        "707e150b3e25c49df26d2186dbf58f04fdd4b21394b11230ab313e744214b350",
        "3ff1bc1de516a34a9cf7c21d851c0a2d534c9e834b1a39620810926864b66120",
        "75ce6599ecdb8b35747cc837325fb1d7066048cb980d1a69431695701e23c584",
        "528197c5b09beb82215e4c626586013201878221cd895b0c1cc1f2e628e65a87",
        "34514663534f9ecea4f864db2a1044c3165158fb904003bca240f5a85727edec",
        "c72df0b1d95f7698ed2d22405bc928b76eaf3238f3f04b236a692eac8962ffee",
        "0ad86daa945da15c0e48a2f6ab1f36a3873badc6049e674e237dc9f8002ae5f2",
        "189b3c9c9933ac929541e29d9ed6be60364e0dfb235c4135d4a42c2920751c93",
        "0bfce9fb219c01507afe779682e01a84b9842abc9815e9bafe3c33460ee196b6",
        "154110bc6f557ecf15c26ebce198b39f6edbae3c562c0e18ca76986eb3b71747",
        "e767c5a94ce63bd2c1b0a494624591356ee362ebb707142187db0185eb8d6c6a",
        "5332e160020ec2cdf2e062b4227fc0b6bfcfdc36da7c462c7acd178c8861464b",
        "533273d0335e88b5e355a0292b7e00f2772d5d1dc6107e7d17fb6f189caef00f",
        "621d2eff8ff4937b24d1f1f0e5c207e6f79e6d6afdfedcaca345f0943f7a0451",
        "fd70040ebad730ef47c86b37d570a8f55a95d44dba1bea2bfb475f87ca333283",
        "f2fc0ddb5d79a4709ebfa75e43149e5845e773c109fbfa99e19d86bbbb661654",
        "df079b57fbdc39b6f8f669a3b6cdfd34a6ca9b6a67768c63ad4ad86a6cd9fca0",
        "a6b0139aaa1f7a0a0e87caaa5ff337684566ef344d65c0b4fb0607dfa262342d",
        "26f5d41b932570c96a7e8cbc3afbed817c3c786b854c4df74cfc61fb131bea44",
        "2d48b7b16d8bf14482f7f1976bb7510abfff09182b7fbe9c45f853f3aa1b38aa",
        "0b6c066a75ad838d8be6ec69517943c6a7aba1c033b86ba3ecf91199d28877ea",
        "068d7982292b7cdcdaf264595a94041e248363ac4bfe95fe0e91c32a2a42384c",
        "76e035c727cb646afa8e709e0a8131a0fc6b8591ccb6734c7e68434d85632c6a",
        "0622e25a220d9479e85185cf1531f8b34db888e61073be53ef377574c2d18797",
        "cc5d1ca7a069ec293a8b9590467360b91c5da89bbece928a42a7de3fca87fee8",
        "1dcf5d167a53cd1147b0986cc544a8e200d261133bf6adf3119c174a19f4316c",
        "4338d87647835cb37cda07b41798b49b57c84cb6e54c30a7074749b578aa5207",
        "20df0269231996a38b70c046d69c97d2853d675bb9a4741432d1262142275d03",
        "7721a51297c26273538abaebbda8b8b499902d2de84fd8e3c5430ca89fce7a95",
        "224603d3a8eb7134322019a86504b8082b55b655e4b4695d6e64000000685419",
        "57dea18d295981b75ea90ab774602d56d5377a9541e6b431514e206c4c0655f2",
        "3ded582eb0829d43f11a1eb6b74480aef09b82c970d0918c415b220a7bb6a8b0",
        "f0ad7653a1071753b25e49cd2da442b792522599cd8a24a540f4206771c85674",
        "0d71e303257fb201097c7d1d54ea1c56c45b809b44a2ed7c677e434fac2b29f2",
        "6167708128754c59473bd0a7212ca7c375c9f726b63ab0f54a94c424153299ab",
        "3c46c15c0538508888a6507bdfc0bc418d87c2644fbab54a1baaec8eb7fe6cbd",
        "f91aee956044c42c970ff4ed44f2f2215db69e4701046327bf9cb516c30fa490",
        "a310053cf113e58518def056c83619bd2a2678768688ee600ccb87a5752425d9",
        "7cfab2110f0548a34b3b15feef5033f7cf09ddb7cb8bea6f8ce0000000a44cae",
        "c0eb6f982c699a2ea87338a5697c10dc4fbed3a08df36bf6ba10385100e79b85",
        "e09e0ccaa7c5a82516dc49d22b73a166dfb4ebe5b7d28e2bc709e69b2298f02d",
        "e658f8b103496365bf5776a3626f796628defa1706df0239ee8ad75c472fd106",
        "5f7fac43a58e28a1bb7df2c54783cfb39f478a21a17fdf1f188902921bc26fa2",
        "e9143e9463d8076f568fc22856a4456973e30a0e9a7184b72591f915c4729fa4",
        "469c21522337455dd486196b2454e2633729e857d8b47950c9b4ed4c518edf76",
        "ae218d952221256b0cdf4cfccf0a2e196412728af34ba52242e47b932bc6f3d2",
        "b44f879dda53a46487cb2fcb155f77dcc8bea921592b07db75a1ebf0931867e2",
        "65573cd7714068eef7f7b782a0c056140391abf3d2cd3e0323c9c7c017cac211",
        "f5dee89382e46a7955f12b431f64b3cb06438065751b8d731ea6de0765397bd2",
        "44df13bd05747db35a1f7cbb30f29c3a56d8923363d1be38216301f65c65cb68",
        "de15c55a68b9bb9befcfc20a7dccddc624ac6f89f80513c39488bd8020c25c3d",
        "ff7f324466d55348f0e8a2b012a3180b1307a5002fcaf0e53d3578c2e6b43356",
        "e66309fc3b4766312ce00925bf5dc8db517b706c736d719812b29785871f8a73",
        "fa4469d2a608b1635e5d7ad05ffa9b2cab4a889e894df189af2d81feb7a53cd6",
        "0e144c99c3228edf83629a7208ca54fd35f07c6a2782029a14a2cf069110898a",
        "a9b076c4efb0d1d884d0f6d73ebfc1e8299cdf490df93823c178a299c604cd67",
        "5a158278f9df6a0aaa5c52da36f21ceff5614479170101ef8d810eb674492ced",
        "0880cf946edf88c18b1c76bb38908269c738119410ae1fc6eb50cae28137adba",
        "5af9a587909a0d256fdedac6d2c2c7247c2ef4d80e6dc931faee8b9708d8fa8d",
        "914e27985ec7a78a7be36c0734ed375766886cd17f93f70261256bd98f671850",
        "569a0be460ece427610b5f01cafcf7537bdea59245ac05a40914b047d391e3f6",
        "569b5474d530a1b1b6409abf9926cd88462c31a6ea4d9c5eb3f3514baf480903",
        "1622802715ef3a3fa9bd21b5166e0b3f0d51c1df26463a92b88dcabd55e67500",
        "01301fb79f1a9812ac5b06e1f559437991e290ca938104582239efc9d1855468",
        "f8fa54dddb639841da34313642b0216d2264a07365b2c3b44bce9ca4a5a9e1d4",
        "25230c00609d5a33b88fbca51f087aa4ce05b189d4cb9c7d580d3dab55d82bb4",
        "7aca3463db556b832c64bf68a310d53284cd2a8cbfabfedcbb8f5d484bc9752c",
        "5304956dc4e93ca4150ab6118035151a1371a366f946ca04358818b2ed9fdc74",
        "83a66faafe41227a89466848ace224abe48906c9d01a1e415e348f7edf0b3cff",
        "f50bf3676d551cf0a70100c53bc0004a11b8c391f21042c605b872e4756a9181",
        "d678c8f493ee09923f5eb9c30e4855c597a1df82953b8b143c9cb1c3042019e8",
        "1efc8cff6b4ac22421f6c4f24459a7e8da6d072cda210b0bca2d1bb5ba43aa0d",
        "3b52156686c2e62da5a4e114000000d40300005005000050050000a009000061",
        "66bdebae893079b021dbbef0e703ec2601825369242e7dbe27b48df3e97840dd",
        "53341c5f638281fe97132f8a96d90ca461081d3973089bbd35c3f40f72c1f115",
        "050230d82b661224506a00090a8f9f5d8c99dc411de9907ea2fa896b94ad082d",
        "67ffe7df448b7a3019baa83e04d2243524ae4dd7a4cd622a368be468abe4ac34",
        "fb5e143dfdb647a4c0eb2138d068075d524188028947ebfeb1655038c3e079f3",
        "53a28c23f8ef0b53994b5715df5e04aea9399af732e1723853e97db870d45d43",
        "3c324ba7b64d4a056cd9d4417e3b1f4b2688e536bc6c1cfb8d8e250005a9150a",
        "3aa20d4e8d799effabcbee4c9625e5b14936db1c9c1e984a6ae264a471136e65",
        "dd01bc0e6337e6de40cad51603d90534c99dc10c4999a3dbca33c4acbb6a0360",
        "70253baf6f385e3b39a46ef0fb746bf27749e9276b367d0acea164b7abc1c2e7",
        "aeb7869a4a11a452302e00c5d5a0a6ef73c53e22b5b45f87beb651fb50d13d3a",
        "c153e69502698e475354f8d35231d8ad0cdfedf5198b11ccc47b2160c302c7b1",
        "101265485630b51f2fb5407bd156baead6aeaeea7f693095c37a9a6614d04c60",
        "a7a4be55405a346f78b2dc88cb53cb743805db0db8f3bb4426daaa5a6777d097",
        "2365db11404d5f1cb013515951961f8cde19488028368a920048903bb82c8082",
        "3305c5026611053f23103442da545a948833ec60fffab4188fbfa565c0935b52",
        "7753a30a88e6b3c5221d8988fea3c3cd216d8c7deb95fdbcaa2be9acbe6392ee",
        "10e7633277c67e3a97d5c2974cafc2b4a09c6c2aff0e223b84e0b191d4ec0a21",
        "086eca6a803fab31527614622728844f098bf523b3eefe297a88074c0f194d0d",
        "414fe9e0ce4c23f7946c756b2db149c7b6c186bd61a4b6d1e58117d05f5cd66f",
        "a181ad9ec8f0cfab901c260d7d573268f2938c4917d7060da04946d54f900778",
        "e3a058b98f9b4a8650eaa396af500764d6b37f6d9b60ae2aa457544a54be0266",
        "4336014b9da9be6311abb811cfc49afde0e95db53c2517aa16a17387d0cceee4",
        "0362b7ba32c412b2c2f775cbbb744ec12afe5ac6d7fa01b02e4cfacc0a946c46",
        "4d6cc0cf2e069cbb20405dcc91d1691efe2415be56711ffd4e5ba5b3d3e19448",
        "d13ca320c52ad1ad79d165d768a370f75852ea67ca0e07996038e60ad2f46df2",
        "5a9ee2179934014e86c52da65293976b7ad0c12e76241ba5a1754376f307f18f",
        "4b2044b658ce30309dc4e555e19eb03de84560a67dbb339584268f0802d33eed",
        "f4a6a54af3df2eafff48e6b488e4f7ea9989265b9c0f41cff860e1fafdab01f7",
        "72d7326d81c0bcc9d0a18cb233dca134ddae9e32ca3a26ccdb5fc8faa1bc5dbc",
        "6c5495f89f926981cccdf29b0fbdd2551c52aa8fcfaef50def8d1903c3207c24",
        "b62efc029639668a3040b515897bfa6c4698055f00e2259551855c67b3ca021d",
        "52461ced39aed36746470be36cf945e2dda367045d425dd72eaecc7eb3c713da",
        "e261ca2af1bc310b7a8290c48cd924649cebec11799c57db2ca09f6b68f0b2d7",
        "9111b611fae2438c34c466cd9acf7509a7f0dcfe522dcd7341e9843937078031",
        "3c72537ac4779b4a51762db9684813b2617338ef1c9488f68dea60fe761fad74",
        "9b0e8508087a54d4334adea4d712ac3ddad9f7b55e8ecf6316610455aac7914a",
        "3f54d0251d65320d63dfad7de10efef0bec1d90c17cf3eef8af398ac23b1d0cb",
        "41206e34351edd477ada4779150fa61daf7af7a49f020b5cd201c7b9be827191",
        "2e8a986b3087e1b566207dea88c2cb6c19f711e733b628e5663e0b1288d993fb",
        "821a4976ddf5446c109f8012434d7aa49e05c0d41a033ffeeda6bc246dfcc63a",
        "f17576edbffe25d83efef36b44bb55916d7375d0c279d8809fa97564f8b51a54",
        "d9ca5219168bc47d6551966e4f026d34fd12b2cea025d9c02e34ac022ff101ec",
        "73da547639d9c68ab0266567a9bb6f24e915e8d325c7bc869e524e40494a234a",
        "fa7bdcc15161a216ac989dbe694caf9dd820b962dcbb0938063091185160a47d",
        "d14d599ea56c631144e0bb2d5e797532b6cc078f6cdbbc64e77ca586bbf8aa66",
        "f53e824c8b89565ed520ac6999d85ee65cd7c86346309e4045d346ee3a874a38",
        "bc2200ac55b8189b466a3f4377ae37dcfd2b82560a3830ccff4a65d89a3a4ab0",
        "a332c65e967a8c47bfe5db4a1c880ce6eb7605b5e137ea4cbd55f8feff9e720b",
        "da51e06941dfb60b4b148f427dd994ff1ba91896f82036e6c0f063bb28d7f4ec",
        "97d10a0005c052e0160c6217ceaeaa5e00c6d405ca78c5c5fbd40730002b718a",
        "7cdaa5c799fa61f161566edf76d658fd8fe2e173d18b34df14491dbca8684a48",
        "a7b344c43338dda671b5c8d445aceefeb1b0e91f1d4a0b55c156a13c0638f098",
        "4bb12fb7dff5bb75e975948e28f78eea519ed1a737de7011bcdd351ca091e5f8",
        "cf417cfa453117516659d812901da7813abe7a15c14bea203436576e64935e51",
        "3dd0ae99185c3539800bc99c98618b7aea14b6084c4139ecabb0d21eef2d1633",
        "bd37b6f92d85122bd7a2d46a796fac8fd4f11df76be18d9bff79f1b4a320b664",
        "4a5c09d845463eb2d733b06b974117039f6d52cced1092738353e9df6ab6f7cf",
        "140e7d13f497e53e00896a00616216a534818c58fcaf8fed1ae08491d365f277",
        "ebcc750cbcd743a2f7640ac4cc2cc38978ac64c5729f619b194498de8e3e3bb0",
        "872d6901cecd15fec248ba868c98bd2553dba1525d1f8c02a26b608c9d5dafad",
        "c446c57e3de0c651126ef4b91c479fd6ea8d7ac516760ee167702f593258039d",
        "364fb82159014c99a6a5c42c63c1a48c8146292bd3bb5b4cfd2c114dd665e0ab",
        "431f0a653a760c811dd012ab824696e9048b1b81a24d7d8cd2ea01814ba334d1",
        "40c9be7fdcf3bfd814fea651297b4542a1b23666bdaa1f2d469348d2a6e5fae1",
        "92a8b4f1ad7cd40c0cae2f856e51c575ff7de0439d4da1ec463546a52aa86625",
        "4260a95a289ca19272b54403ca9975dc3050eab867c87ae169d5cd2c1638ccc6",
        "5866ca82856d36374bd0fcfca12c3b95bb1a353eadc806ec49e7dfda3979d4c2",
        "049f206cb73aa355cdf0e6f7a425ab84fceb908d66af7573ce1fbbf13743a82a",
        "fd7805bbcc4909b448f67c499d990e297350516d9c6e3b9b68e8110180059705",
        "d1ef61c50250989039e900ef7a9d5538c1d99a7412ae12be0cc33450e590fadc",
        "9f6cd609855de882f7f76412c99b2c73c4bd6889472a3df03427b4df242d8659",
        "e20a373b882941c7ab508cea7ce57a865b44af779fb98fa0743db1b7a75790de",
        "ffcabae41b5121de34c6a8616e11748c0f965f1ee217deb3fff12f149ddfa9fc",
        "e8750838fbc9cd9f9a72b4ce21d6010e1859fd5d8f63c5a418d940a7516a9678",
        "839af4e2f483866f0b8403044a4d31c4485a15613ddf3edad81f3e2852167e9f",
        "6a1f86165afaac56a20d5a",
    );

    /// Official `ssz_static` `ExecutionPayload` root from `tests/mainnet/gloas/ssz_static/ExecutionPayload/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ROOT: &str =
        "fc03d9891dc3a7382568b0bbb81c2565729986ee4f24b0a37ada04d8efc4c27c";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayload` from `tests/mainnet/gloas/ssz_static/ExecutionPayload/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_SSZ: &str = concat!(
        "1a96d6a866d5a79fc25d1d67abed34db3b53a96604ad535c5a796f4a8da3b2ab",
        "568a5969f04a5e9432afd278eb13b54841772fee8f0ab5302192fd73728d450f",
        "083ea1d3dd72afce417b5ce6ae2162aa64cfe202a4c35f97f686c30eb6b52a41",
        "90851eace34ca0504389509ac00f4098001e89e127c7761dc7338ad98c096943",
        "45eba497e93db6c2676cf1a44b07da22c0847d616eddbf0e86ddc771ad34b5b6",
        "2c5444cc29195e738dfc8c1a12151fbd9ed6c17ad0dfcb39177dcf7ab32be9f7",
        "c709ec0b9ed7c82f0aa13dc0b4df0e5d04ce58df00292bdd8be9bfdc8d8d4484",
        "925c0ce3d0905530205a523e127ecf21642ec16ab6f897ce6c51dff0cf66095c",
        "92f85e312e82c11606f9f00a6d6e5da460feeb289fdac7560c268518c84d2438",
        "9f5fc231583accae463e1edcef4b3f1b724afb8b24587da46c33119700557db6",
        "ed13c7c0d308a7628caf2b0a6d57a44ada110208b9d0f8035edc5b7832bd0e42",
        "9f1f55ff3ab12ba4f43c92a148e5d9991f23525ca43eb21e43e1efbf167b2721",
        "8b980416ecf7e0865bce0abb86128a50408aa04da54ae3f2b399b5fa52f0808a",
        "4ddce455a5305fdf47e0da4d72f634eaa5e295931c02000041d0ce4a3e473532",
        "d87e444b89c57ce071ac6b9ce54ad44cd834526c8f5e11a29959784e894aba44",
        "59eccbde48e04c991d6d08031d56776bb7a3c4017416128d230200003e020000",
        "810e8ac177317dff17f5d0107484e7db9e030000bddbe34cb20971f3b15ccc23",
        "3b882b100000001100000014000000180000007228206c6dc3d860782610f0c7",
        "5969bc9bd9bcd62a91423331c4f9433f9b79ee2d19d1834117516290324fc277",
        "6dec8d278d8325f672e361645c72f469408e3617cd0b3e8f179ff861b3999b5a",
        "7bc8a790348b2303d2884ab74999bc318f5d3f29669b35be3bfef0ae188e5aa7",
        "ca96901292ef62390b92e788aa66124d6ae0c76aa24788da5e0ab5a562813ad5",
        "9d0ad7513e32df7282719d375656e9a44c4eec5663dbf1a03ce362615bfbab6b",
        "2344b28c70f7d3219e3b500701259c45db057dfa647938bce6e2656a514f91e7",
        "22bdaad03668d9ee996fdc0865bb18b80e9c27b48aff36b5067aba6048856078",
        "426287366b62912b49289e57e1c145723cdc16caf11e64e782248ddea596269e",
        "25b76829c53f1101645ed39575da7bc7b33917767c4f450617ef41474ad7ca51",
        "8b0127f5aa8c6a47bc2fe167464b96556053200c55c1faca8f713bc14948453a",
        "29f643e97e94cc65fdabb8782ef6b366c33fbdfdbf540f3dce06a4544f27",
    );

    /// Official `ssz_static` `ExecutionPayloadEnvelope` root from `tests/mainnet/gloas/ssz_static/ExecutionPayloadEnvelope/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT: &str =
        "5859e52bdb11a5b0e76d1289ff7e88ae190c826a4850a42066a6adde026fa90e";

    /// Decoded `serialized.ssz_snappy` for `ExecutionPayloadEnvelope` from `tests/mainnet/gloas/ssz_static/ExecutionPayloadEnvelope/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ: &str = concat!(
        "500000001b030000877b6704589bc5e7a08e290421fe9a67cda8509eea324b0c",
        "a440bcbd67989ca7fa0c22ad8532224c04d4083393ef5a49cf3b143c59f3409f",
        "9513a6302f5d51c30a1c67f4b27fb26466e6d831c84f898b174991515b7d2c3c",
        "c96d28a957e1955c800d1722247ba8677a635df9612d87850fac67b1e902875e",
        "6bc75c07a279eb0c414417d5b38dcda8863230ca7531ff4d63dbadfe0e21b5c6",
        "9c91312ee4fd4e6c397abbe3a00c34de7c9b3b108f99019e22f772cd0153f547",
        "08c8fc4f15c6a471df104cf3410d5297ae41f5301031d17407d754c5d09633fc",
        "a814286e1d24029a7a95aa4dc97d314e7d53b5ceaf9f8f6fa2e1ed94a76d26e9",
        "6db3fd948811467dde696f31ab1a73a4be4934d29f702a645aca7529a6f7569e",
        "f0157f05b47de5b88fd51d5e08646118bea03c2e1a7f0a2334e7eb3c3c4314fc",
        "7277504e03167f79497c47bdf367f1da5d3868cc9b4b7321cfef9aba8a10de47",
        "de28d78e0cb05ff52a60ce40baaaff3622388c1993e12ed0f43033d2970e76c2",
        "c9323059fb59cfb40a8ae928b57dd30e9cb51d62425120af0069bb54a411ba7b",
        "3f9c1a4ba8d0c35bef59a3d0ef6b6ba6de56d90a46968e4fb21a922777e4225f",
        "7c47e101efa8b46d7db4f37df60beec20725b888bcef05a8fb90aee43e08ef29",
        "08ace8b849f44945fc19d3d15fc19ae18371d035f68dbe15120e78671f9a7105",
        "ed6dc03e1c020000cdaedf4e2bd6ff8a3e78ace40414149c1b8edf014bf955c1",
        "925033dba154604ab88e036b3c0bce2d4599d90d7c6e6f9e6e980e0c8d20ff50",
        "5940af16669987bc330200003f020000a170396bc396936b11dd01fb3b0de147",
        "c3020000ce2ebd13bfd9e4c4df317c5c605c82b9b2441e390e604e11e8c514a9",
        "76de6b080000000900000016cfa0500d133f2b3588d2f5174ca3f2038bbc2cc1",
        "7d612494aa4a37ea9ff82222c63d24f303cd89d03beb8a5f318f1b8a7295a518",
        "5d2bb15bc43eb84d4c4cf6c13728985e53f65c144b3e5d78e7011b397b7cff5e",
        "feed8203b9f6c0cbe426daf7217bbfd8af597d1baab5e3196b8db9750a7cc27d",
        "f1411e4a2d149b52c17d36e023709700799b3a535d1cd111bd789f1400000094",
        "040000a8060000a806000060070000748c8db7961daa235e8b90aa524d3ee911",
        "bf15ce6b65fc007f6a0d25a55bf38692e1a37e21997780802193870610dfa68a",
        "2b133949b59dd90c90d440a812f2f775d3309f651cb3d42f159a2a06579d80fc",
        "7ef90e62c5c355e32b9be60948ea923c5f0eb6ce05118d5929d29a0d06b106a5",
        "5bf1fb0c719f71f52720968acf3e29c997fffbd2c34b451d511d7f487a31f769",
        "9467f9879e0c2abed3393be8b867e1a8da0c794dd2aabc3e6f5c15341034e681",
        "e197a2aa9cefc371cc388bfca85750a50a7dd15a1e75b114674188c1efb23bc9",
        "c64fccedef480a265f34704ff5686bb3dac2140a6f17123155634f7e5a8e6335",
        "502b0469d04e13d65bd4dd63bc6cb0e8577df2e36951a72c15e6efe1fec31334",
        "d3f41f18009c6a29df2cc08dbfdfdefdff6f324e9e01591f339e2a44d693d27f",
        "ecc5a72bbade757e7a54a8f9beacd68c413464a0245df8fc22e3da1fe6527152",
        "9d61531e5b0f8a941d2c1039679386ff71f9df004976aaa399e6fed3fc554b9e",
        "f2c9cbdea5fa76a4495a63bb76f9a674198d26ae26f00f8ee67accdff838fed0",
        "3cf253a74131193cf862d32c0337cc18f0505edb62c0af590819ccfa02409b58",
        "614af6448f1211904289fe105c54105971141e56445cd39d8b5f530805107796",
        "262df2d7512bab1477c673c3c6cd5d3bcfac8d8a98c1fc67162cd681c312e67a",
        "06ed8700513e2c9cc50c245ec4061667b65110032dd7ba3c023d6b4c0cbdabda",
        "22cc8c4e74a29aca4919653c96e0acdb0a3b4de71e21ee9e2584a858248e8900",
        "11047a3a1294af78c4f8668f8336b9369a8cbf867376f16d0dff57a89946d69b",
        "04312eec4545587da9f2edf034abe591acddd36f39386d75022aa4dc5400a593",
        "aa4b88e3717e4fe33a943d2c52c2ce9f432f7a3e9f5e70ee6c7e88e01b778a0e",
        "fa9d81992f4beaabbaf5dc91b3f67be677a68c312e9ddf160d655dda7425bbac",
        "c418ac4eeca1afc8f96a865009a3a83709aa3c7d015b720eea083b249fd99a14",
        "8ef29869b7c8b9df71d0ca5dcd9f19b98ec2729ffcce58150417cd6e5174c240",
        "aafbc1cf927fa085e03e7ef39928ff7a364375a2191a2a2d25d8e766363bc52c",
        "6df09950638b50d4ddddffbac96fc15612976d74b5061be82dab0476ebbc2d42",
        "ccb0421052120f962c256cd44759db6d3c8236e503f5d124ea735b188f37f116",
        "38aaf87c9681a9eab052f890a1e8d0841cb539a9093472754a8b0ccc68faa33f",
        "15b67b11a0f6ab3948c85484b45e466cd54c7eed1ba32343f1af1f42e203d8be",
        "86b264dd215d7f6352240cc5e1f44c144da3ba4cd233aff5471a44ab4fa1de11",
        "0b5cc43f52b1155eb08ad39fd068777069f8cebed67ec6b3a4f0532e141614bc",
        "6a2fa73c1af24b1a7cccea04b76331d960866e1f7bd3e6a144720125c8ef81f3",
        "aed939bbca41daaa34ec54dd8d6f6a2cb8705e69192809d9b9e5a90bc2f1500c",
        "b6f3b694ce22fff7e5b322ca297dae186f80c8938569a3e9cd31426b547eba3e",
        "e9e2959551a3633064f76e5baed2ed3e31050dfb1be34d62d38c124516909ace",
        "1055036b1f25240344cf2d956e742b9b715d913cb51f55f73f2dfdceea27240e",
        "ee63d32455aa5792287d66b64d02be831cdbd34cb4143c5000692bec7e124c2a",
        "547df3c5d95be0a8b9263ba7e4f469b2c3f6aa270cd29d5111987ddcf893c830",
        "6bfe6b70d81a43bd96d05d0e8965501d1cab0e86bc6a1469a69c577a22dbdc69",
        "076e3ef5c07bdecca09cde3714778e8658dab05c0c412622f38e224c78837cfe",
        "93eafcd39fa2d060f25df4b26691dc454d72fad6a20d151329a007d4819b09e6",
        "2e61334c60fb679eb8d5767c20c5e60945ed89e35b9995b8ae3e3500cdbc735b",
        "b819c6b4d667aecd4b3e2ad8d76491d0468c15b7cb759eb9965e8b93211a103b",
        "25ba55d91cc94c69813ca0e215adbf2ef64ac0edf0e27bb6799d23804d99db96",
        "c1e721caaa88bff3afb3c4e0b147bf456222ffa191b08ca3c04a6712a63080f1",
        "a7ca06304783f8c05d01e68684d28ef19850546d91672eaeb65b642094a8fd6b",
        "ccdaeadd04574e1bc297996b1ffb19e9a3963eeebb3809ec7a747c04e2ff90a0",
        "8cb262ccf3b3ff2df788f68721e45329cf3784fb6f492a9f94683cff5f90affc",
        "8b4e5289c4878b7a1dd1083cdb55b38e96416f94ba7d27da6b2020f8f754b2f1",
        "94bfb46677033225b7b1ca7d87332d5dbe6fa957d3f1d56b749d817f3607e4fb",
        "d2c6e75ff84c60cf8c8f77e0a1d11b443a3d846299dbf8e13e3bde7b815e3b24",
        "d0a47291e5b50871ae6653710d2d439c63abdad790f7ba7b5261510f22ac41a0",
        "294afaeb7dbffaee913bacd7fdf3fe94dd864949158d6438635680bdf914a8b8",
        "5983a964b1c6fdbd92e939ea0f075b007f9e6c1332bdbd307d76e7a32baeb5a2",
        "abf848b5ce083da2642f398834e8ff41286d9ea30a2645bfff1a6dd7318fffcb",
        "0e19c3d1366bc247832964c466bfdbddf0cb1aa0add1a520c5b2ab74fb729d36",
        "61dfec33841f81e8f2ecf40c8988b0a64672fccc79c0dc65362ea510a7ec3505",
        "5e9d0ae73cccbb5bea20890ab811bf9e6b67e9a3829f8cd02832650acfb26b6e",
        "54a807c1a3584354f724008087cad0248dfa094c3a7fcbe67e30ea706a9ccfa6",
        "2177672e7cd7558db3f0b105c0f92867c6b4b529c5907c18a31d85c1de012789",
        "1c3abc5e1f9a1872aa57177ed748af410bd197577e3941888b6c06eb674415c7",
        "c2f723c56c961bf19dbae3a51745a2d9c8d180d2a3f8d28e03601b220dc1889b",
        "d1dac2ea2d7933185afab215f60d0c1e6365d6cbf9e6171edd702127d8f70b13",
        "fdf7624ebd83524609ca2c4c24e5f860574d013604816cf62e69c747b4d00755",
        "bcd12aeaf7ddc6fd371c600f9f565f0af3b0fd25f5c315a4c680f72b640e17d2",
        "828e7e8cf9dc1a7622beec7c7b62258adddf3dd96558025cc0615273fed72a0d",
        "f4f6d4c2ababb3c8e51692a5052cbc7533de68c56c6e8e7813241f438719bf4d",
        "7c6a5639279ec97b6d162312bd5c665a8f8b87d406a9db45e16065714c7e367b",
        "df28171f9fc38c4684e4529faa1740e7c8f4ea106c141d2f1f000133c39f0475",
        "54f7b26b656701d268ea523cd369eb8668b00baba6fc715ae57512b2028cc5b9",
        "8409a16996b0b5612ff9b8884d390eba5986ed473398f3622693d9e1b310a049",
        "8399929bb7d10f4d66bdf7e460c52d970920f2",
    );

    /// Official `ssz_static` `SignedExecutionPayloadEnvelope` root from `tests/mainnet/gloas/ssz_static/SignedExecutionPayloadEnvelope/ssz_random/case_0` (preset mainnet).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_ROOT: &str =
        "fcf9e14ad81160e55e02678ac019225e7ab9a572928a0d3127160794205e6381";

    /// Decoded `serialized.ssz_snappy` for `SignedExecutionPayloadEnvelope` from `tests/mainnet/gloas/ssz_static/SignedExecutionPayloadEnvelope/ssz_random/case_0` (preset mainnet, lowercase hex).
    pub const SPEC_GLOAS_SIGNED_EXECUTION_PAYLOAD_ENVELOPE_SSZ: &str = concat!(
        "6400000037cf6aeae0879227d186696291b902febcc7a29e0ce2c7eff8399b62",
        "4fc3c899e0d3889785ebc89b9b637c89f4316a0ac7c7d1d81a05884e379349ac",
        "195f95fe8d6263e36622f891554f518b3798e533e760d16da5a02d5056d593ef",
        "ca6f7a41500000000f03000096b2671cd4f48dbc1b06f138193c61c771d1ff02",
        "aa6825599c7e9d5fcc790c3304c4a549e2ef4e2e58bb9ca039ed8c2e5b006fe4",
        "bc54d4c9598df8afabb7d4e8de7e48c42e4ee8fc8b63c65002013e8194e36f78",
        "359370173e6f1e602a6a006067480573e7507dbc248b86a31fd18555be850025",
        "e42ebf1e34d7901428a34d63462c2b1ce89022a9b0299f2b11bdaf258dbe640b",
        "c58d90c7253eb6b86e541ce00a291cf95c052a9ead05b2b41a6d917eb86e6717",
        "6991b5b87b9bcae7b505c965969c09e7bfd60cd491b624a76d277d9db4c5b318",
        "b91aa8a2e691cf4cbc87359456f47f088b952605ad3a3f34876c59b95730fd69",
        "c51fa9621c49762ed181cffb9a63d552e95d1e4e1d2b34cfec70e4f664660541",
        "4738970ebb9d1d3da0c15a6f390690ae06e81dcc921bfc345175822d794347ad",
        "3ffb3a227c70456a267e5a16373bb08e26fc514d852895c38eb4d3210ff99135",
        "989c9f342b4d67425424caf4bab47dc619c85d5b3f818ca56ab73c0d42b64fb6",
        "176f7d46d719a1c592853b3d9e230cf1c5b805490ede2cc3e109a4450f327dcd",
        "06bf5cc8ae7b36bb50af30e972cf9dbeb532e48bf5e577b3947bf5ca78a05a7b",
        "88aa0ee02629fbdb2c2c85f8858c3560ca21061bcee312c5376b925bb382db57",
        "c4cdbe12afcbef08ae1cde70085280af35becfca29574414f5bc98d021f6d51a",
        "b01682a19cfd5b4d1c0200007fe9417174a4b05f4be0e5f1d99ccab33c68a265",
        "869fcc4750e4769ee7a45118f4cc20f8edea719d04c3a43fd64a9021acdfef48",
        "0ed56dd10cfd1cf3722aaede2902000031020000ef68a3e7dcdc30e862a6a5d9",
        "a2e3acc0b5020000d5b1616c5036642666f66d4d6bb0dbf47585eb63bc040000",
        "0061e75af6fed32054bfdc2cfb18e0a3aefdb8581f7792038dc7a5e818f4fe09",
        "220e50e6e2e735ecfa2656cf33b48c06d92393fe79852565af509789486d8256",
        "60718cfb04b0552917d55edeb897b245e1b0c2ac55c04960aad6a367c6bf0fe4",
        "c8454af226120231957aec97b5e6c5b0571139dffa89104d6380dcd7b120e89c",
        "555d092b57677bdd8cb30f50bbba41eeaf13b21400000054050000d0060000b8",
        "070000780d0000ff2d3e2cc00cb91cef5d319bb96297e029855e26a344805468",
        "e0d0ba818ae2bc3034a7be9500dedcb4daad760d417fbdeb434bcdd31957b8f1",
        "f6aad41823e15d4a6c3ba94d6a078f54e6988bbbe54e0d1737f14a36e839675b",
        "c715e8bd1e73b9964ea0e50cf6981e7255a586c5e6f273c08d85ff889f9b736b",
        "bb11d206f7e90bc32ad7091cdea65fba9fc518b8a2b9c991d6e47a9a0119c58d",
        "1fdc69b197cc68801fa5d153802408173c0b812882a24bafdecadef600429ed1",
        "a968a29f8a0565cf38c565b69331255230d231bc6c344b8ec7620b6bd67b9eb8",
        "86cc7a285ba6fca74e23a5eb1bc95aa62584a8d3ade9b7bd29e314f9a3c4b875",
        "1278621c947b3895c02b15dc1f614e7ce2e0db806acc51a8761b9c4ad1677865",
        "acdba1083b8fcd0aeb10264fafce39feb908f4ae798822963f42ae314696c862",
        "15e4db028cbfaa9dfcecbbbe5cb03cf99a2f31681a2e746657e1f5e86c85e4bd",
        "d10d93bdd5eea1c43a633381dd77a465a83fa942c32f1c78ef5a11350d6b6ae6",
        "5a49c82a89ea447b5732924ae82c43bdfa1bbd911ccea8f0cbe624b0424193d4",
        "924f1c0835f3758a4e66045f11d44485db88f449264be4a7ed6e08f1ee3dd3ba",
        "6cf0d636483f6bc3bd426cd5c86d16c68ca3d1511e746b98c55c43afbdb4ee84",
        "7b5189f8b9116b24fd53a52868931693f5cbe15bca29f323c44572e274d91ae3",
        "6873678264a284f28fdc055181b9f246ea28fd65b6d455603661913e899061c0",
        "a3ee6497e1aa9808bc46f3d0304bda122062c533c5bf529bbc4b604a4f038eba",
        "b426cb7be1b0f8c377ce178571bead303e4b96eb78b31e8cfc4ac455989c6ca2",
        "90299a33a60f4ed1ce0a5ae2b78f0f022d5b43cc51cdd4b9ef12b842455dc989",
        "29ece39d7b2ae9b297c82bb9bb401248065c03ac9bf5af9d036b90990841409e",
        "0f47bfc6f4838af9b9a02b87af4aab251f2ba73545dd7c59a8bfce40a455d40d",
        "1967a82aea9a369adf83fb52a370de676b39f92477e317e6e5ab67bb64e1d426",
        "b5553e7dd59f192e340ac20cedef3e5f3d221235892a8343520969248a2daf72",
        "3aed73aa5b282effd91ff2b7e6deaa3ae5b1b2355ccd57aa2bb6f7e118c418a7",
        "fc8bb5b81d7bf1c690c6d2eb002af96f41bcd478bb6c38d18c41ba11542e3a7d",
        "7c983750ac3fa7d9b56b25e63d3ac2eb3e19d83a578895d7173d82384710c334",
        "8fdeb8aef18b49c6da3bfde5bb7823e639e3099fa2af5c4330386273b608daa1",
        "afabb208aff7673bff03f61df29385634282317d2cf97b941fce9812c54bed4f",
        "ed397e00e73dab132f3c6d0bfc2e2546c9c8f5d590e0ab84fa3984cb875906f3",
        "70ce8c86b708072387bab5d2c74df65f016e50cdfbfb1070ae8765768b2f5498",
        "e9697bc56f0521601f6d3e11522d137d5f942509fb71f6a3fb5e0c40a0ea7688",
        "9250071178e3f2da708a124cfd10852c44a1eb2a7326a5fcec6c86ea47b5371c",
        "e94f0c9efe170ebe2390c26fd80000a80d099379ab28a27efe1c60c71c6a72da",
        "dc6d0859ba7cc43c2faa3f0bec7f53bd4fd22d78ea837c597a0b0959e3ac8de9",
        "289d6ac8eddc71b40b9a0fb06363bfd2a2f100ac989426b9330cef80c0087090",
        "de93aac3e815ebf0f376b9b5b41d0a8c6cb21436176f2c0f350c9de9b31405ef",
        "8b7b701e0c7a5590e977b478bde3b1e3ce887e8176e3d54c4a189f3b92988c39",
        "a7647e9639517a6e62bde2404637d85c9b40987c48e2f11828c5044dd021ef0b",
        "f1f302e2704fca2412c3775866e97733373a8c34cc63558117b6cba497f438b9",
        "9a7512036478275005c7494fbb7863f08bc7ef086e608753ccf9512bf4cbdc53",
        "5fa5ea5cd49fa96a15f5f83b8b9c1f0362e1e2a38aa10127ee083dab6adba0ea",
        "2dc11a657a360fa2e888712fc86b25a0607e72ca809072ff8b2cc698fcaa8cee",
        "4ef86d313509a13a713064601addbec86ac9f8c9cbf51ca566747d6db0556c62",
        "3b59d5d845ab17d5b5a5dd80bfa014c8f303e3fcb72ef9ec7d742e9f56136ec9",
        "9b6cace6ecbeee0d0620b73ddf79ed6747ee48ee266bcc0be694c5f1d0b61fe7",
        "183d49a8dfbfee3eaa6a1406a21f1fe37fe39d5449ebafbe235c5d015656ffe6",
        "d898e86b67a0e89f4b16756d7852931176156661b9077f3edc7ae1fd22f57eff",
        "877ec8f1506e9894cdc83072a017182fdf31d0251c022aa72b865db432dba048",
        "a71c3144e27a63a490d011aad85580082a4d5de9deb4dbe6f91f8445600a3018",
        "9e63a1ff5b01cae6d5d22d2587ab63a99c2678c7a2394544c0680a248440a834",
        "2485b148c6625bc14808230bb5f9d47b016c24dc0868ecdd4c9eefb2c5a23074",
        "3d311c83d83e0ba2e2bea4c15548487728bf23ea49131073fb463a2821c7ae63",
        "6677ed1ac7844bcd947e2a1af3aa81a374892e4934b2fc525a523191a045e148",
        "790628ebdf99574d13f83744ae25b6914453136fec6d466f17942094852d9465",
        "28a4bed6e6bda1770b6ed2069b3ceba5b1bcacf416139aead06ec70bc7d50b6d",
        "40f07ab2a9717866598fe35df07ab7abf0a8a0e13bebb6740ee8f290c1fcc5cc",
        "671228ddc77abb446cbd72418a39b25490f529930e7680e983585847fe2f6081",
        "830ad5d26a023c58f3336df595e2dd3a252fb29bf18fc314c75d446d213f7be2",
        "e69c34f62ed3143ccbc89b866b1a64caf75eda1962829617c5be662ecd3a5bec",
        "e64827c1bebb9acfd95c3fb1161404ca1de08f6a5b86b614a4b09378d65ac84c",
        "3de85cefc6bf9660a0089d073908984a459ffcf9cc83706e9c539842b0ae48f0",
        "1360330cab766ed0dd8821ee9caa645981a1a7f14938826575f5f4b32f2fe2d2",
        "42133653646c5713dc53a10f35a5edddf5084682c8a6d10408c5ef1befab598a",
        "ef6698fad1252863efb9fe91acb93ac8df7a45026fa064107ce32e15f8599797",
        "66f70b7acf8e1124d7da28f343b7efb37a27e93fae3779a6d1d0058ab6bae8f1",
        "5b5273427b4f118e9f102148f72bad279f5af2f4b302720bf5b880206715a383",
        "4eceb22aa0ed69d96ad49102b0acdd840da5b44136a53207133a13e134c7cb89",
        "2efb18dd6813436900ccd1a63103f4f1735675b569db5a895f436740050ab666",
        "eb616e1b55beb14cd4f01ee0d57dc40d478a013c35c33cc647066344d6aea8e4",
        "5bad60968ea5faa4e3a27a7ecce759a3c62602d3ade9f78aa5dc72d92dd0207d",
        "312bbacc94bf13ef538589ad12076d9632c2a03c56ab5dc83bd8a6a37fd2483c",
        "d112e17bbece0701bdb8338b00b0a6fa89e23ae9738a27e3b98a940c4a0d78a7",
        "33f9274ffd4c3578773708e2bd230f89987d6c6441bf85138b5c9818e725e502",
        "c0f371c14811d61422dfff5863919cbf2d136aec5d134d33dc0f380a853bc127",
        "cecfdf1ec945b19eba4bc36d964072f3ee3e6fb0c41ae69fa46daff32c5066c0",
        "fc5eacf9764707f29591e93443b49973df93eb3530339ee47f9fed874c7fcf65",
        "c42fbab87e72c2e650703fe68056b13b2e94c81ffe42d7a444fca973fc7877df",
        "d565d1070be8558ce84a38741ad81a38a1ff0bad6b2addd2570d3a4dfd6684e6",
        "b94c359e7bf78c9957563a74b1777bea11730f0ecaca16b7dfb12a7741ff7f36",
        "19d95b53137ecf6982b574d71f2095f7b4aa10e25724bba59ada59f1d603e5f7",
        "77ab11ccda7525d2a632c2c2e388a8150438d96b49f446cd28ff078660dc1b22",
        "20847371a62f143965fb8ac4e6fce8a8f110cf88b14814039621cf187022a366",
        "3cbdedf1084d9dc247de56b6073ef970ce9277bb6ed9281512baee13cd5d26b0",
        "d08b744e509bb114a9893c8c8b8fa1e49117fa34516ef094e55f90b45d69be3b",
        "8f372242a47b9d48ab5998f0166f5c1dc820dc0150dbddfec7b57b11000eb856",
        "b78d5f19861a8e4846355f2c0bad4b3b1c2ff6feef4d3daa5a7d866e3f26998a",
        "410be36a48dee5a7a375aaa5a3b62c5cd1e9c8e62f8aba09a73fc2eb3abcb7e8",
        "9ddf93e15678e41183f0de46c4ca5333fe0455ab532a79300fa65d264c782a3d",
        "878359be5931ea6c2000b9bad7bb43cc80e53ed98735017c798e243314ba0ffa",
        "b25f37d4371ee2f132305f2ccb1986fb54d0eb6a09467689d8c8ee9a66368e9a",
        "0212fff3c4d00c70255c46047574987cdcf7602217d6c430c16f0abf9036f51d",
        "ecd69fe00dd5328bc5c7bf301a4a3b076034c2d0325e04a9545ffedd0f1f9fc1",
        "a66a515d0d70773bd1211afdfd004ff6c3caaae5c3f10609b45aeee5fc621fd0",
        "c0e5e3ad502c9240a4bb0fd3b17f6e5acae2edb83f63320368973039dc5ad5ce",
        "c5b67b94a664fc5da8d0d082cd471909908235cf6e968bf3d76149b19f7d7520",
        "617c9adfaeb873663b0d07ad5636d32c88f886423b5af4a3d8c77ce262b557de",
        "f5ef7ec72a26bb756a682d3424ae2cdf73ed9d4ba8faf174939799a636fa025b",
        "e0dfbb4949abbe86b413f1eb85e081907de6daaf346418b5c1a5616e60e4a91d",
        "0812cee49aaaa0dd0496d3e24778487129ee02e91e9d7229b0903a611e24f91f",
        "2a59493ba699408f6f247252d4244ae12f83b6af4283531160bd3890ca203670",
        "2facdcf161834152326883a83af9dfabc2d887bd214a23678ac4a1aac8034f45",
        "f8ae018571cdbfb166c872f1fa772aa5906f51b2d9ebeabea71f616b1d635e39",
        "65dac14321f534ff2bbc0dd338ab40635ef6d689336bae209efb75afefa7c661",
        "d7106ed4a9afa9066693aa43009f8d2ce2131a2ffe20d629f8a4615b8ba4d0ef",
        "efedbf05d8e30d193b6d7539fd2f565e05bd3be1df8b6cbf5df77e388191b4d7",
        "f1e1ccd8a67a51e55fe29b1db4512d11e964b0892150f7c3973587241bea2e94",
        "9ca682dc4cd96db2b00d05e322da14d36992f66f7078d01f7409b343582e84fb",
        "54f86ae8f6375c547868cc65696395c3d4e54b1a1c4f1597d0f032747e07d483",
        "48bf5df32238dc29d9923c4a07ff85e8ed1008454cbc25fc8e564808e00eb915",
        "b7a2a08c91c7a652f6a4d403db341041128fb9266dd877e9b500336f6f3bbe21",
        "e87574bfd6b27d5d39bd92a80e715a32552a7a",
    );
}

pub use minimal::*;
