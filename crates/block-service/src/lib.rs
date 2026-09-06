//! rvc-block-service - Block proposal lifecycle orchestration.
//!
//! Orchestrates RANDAO reveal signing, block production, block signing,
//! and block publication through the beacon node API.

mod error;
mod service;
mod traits;
mod types;
mod validation;

pub use beacon::{BuilderConfig, ProduceBlockResponse};
pub use error::BlockServiceError;
pub use service::{BlockProposalResult, BlockService};
pub use traits::BeaconBlockClient;
pub use types::BlockSelectionMode;
