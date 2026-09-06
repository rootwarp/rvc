//! In-source tests for [`crate::service`].
//!
//! Split by topic (RF6-10). Shared mocks live in [`mocks`]; topic suites are
//! sibling modules. Exactly one `BeaconBlockClient` mock is defined.

// Re-exports for topic submodules (`use super::*`).
pub(super) use super::{
    compute_blinded_block_root, compute_block_root, ssz_block_format, BlockService,
};
pub(super) use crate::traits::{BeaconBlockClient, BuilderConfig, ProduceBlockResponse};
pub(super) use crate::types::BlockSelectionMode;
pub(super) use crate::BlockServiceError;
pub(super) use crypto::PublicKey;
pub(super) use eth_types::{ForkSchedule, Root, Slot, SLOTS_PER_EPOCH};
pub(super) use signer::CircuitBreakerState;
pub(super) use signer::ValidatorSigner;

mod mocks;
pub(crate) use mocks::*;

mod boost;
mod propose;
mod ssz;
