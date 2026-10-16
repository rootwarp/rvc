//! rvc-block-service - Block proposal lifecycle orchestration.
//!
//! Orchestrates RANDAO reveal signing, block production, block signing,
//! and block publication through the beacon node API.

mod error;
pub mod metrics;
mod service;
mod traits;
mod types;
mod validation;

pub use beacon::{BuilderConfig, ProduceBlockResponse, RankedBlock, WireBody};
pub use error::BlockServiceError;
pub use service::{BlockProposalResult, BlockService};
pub use traits::{BeaconBlockClient, BuilderConfigProvider, ProduceDuty};
pub use types::BlockSelectionMode;
pub use validation::ExpectedParents;
