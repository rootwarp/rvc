//! Gloas progressive SSZ merkleization island.
//!
//! Declares progressively-merkleized Gloas containers and exports roots only.
//! This crate currently has no path dependencies. The only path dependency it
//! may ever gain is `{rvc-eth-types}`.

/// Pinned `ethereum/consensus-specs` release this island is generated against.
pub const SPEC_TAG: &str = "v1.7.0-beta.0";
