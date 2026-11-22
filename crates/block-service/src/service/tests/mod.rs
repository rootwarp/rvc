//! In-source tests for [`crate::service`].
//!
//! Split by topic (RF6-10). Shared mocks live in [`mocks`]; topic suites are
//! sibling modules. Exactly one `BeaconBlockClient` mock is defined.

// Re-exports for topic submodules (`use super::*`).
pub(super) use super::{
    compute_blinded_block_root, compute_blinded_block_root_for_layout, compute_block_root,
    compute_block_root_for_layout, demote_post_sign, gloas_header_and_root, header_from_blinded,
    header_from_full, note_signed_fee_penalty, ssz_block_format, with_shape_rejection_lock,
    with_signed_fee_penalty_lock, BlockProposalResult, BlockService, PayloadDeadline,
};
pub(super) use crate::traits::{
    BeaconBlockClient, BuilderConfig, BuilderConfigProvider, ProduceBlockResponse, RankedBlock,
};
pub(super) use crate::types::BlockSelectionMode;
pub(super) use crate::validation::ExpectedParents;
pub(super) use crate::BlockServiceError;
pub(super) use crypto::PublicKey;
pub(super) use eth_types::{ForkSchedule, Root, Slot, SLOTS_PER_EPOCH};
pub(super) use signer::CircuitBreakerState;
pub(super) use signer::ValidatorSigner;

mod mocks;
pub(crate) use mocks::*;

mod boost;
mod deadline;
mod envelope;
mod json;
mod mode;
mod prepare_check;
mod propose;
mod ssz;
mod v4;
