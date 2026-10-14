//! Slashing protection module for validator client.
//!
//! This module provides types and functionality for slashing protection
//! as specified in EIP-3076.

mod audit;
mod db;
mod error;
mod group_commit;
mod history;
pub mod metrics;
mod reader;
mod rules;
mod scoped;
mod stage;
mod types;

pub use audit::audit_log;
pub use db::watermarks::{raise_watermark, read_watermark, WatermarkKind};
pub use db::SlashingDb;
pub use error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
pub use group_commit::{GroupCommitConfig, GroupCommitConfigError};
pub use reader::{SlashingDbReader, TargetEpoch};
pub use scoped::{PendingAudit, PubkeyScopedDb};
pub use stage::{
    CommittedReservation, ReconcileOutcome, ReservationKind, StagedAttestation, StagedBlock,
};
pub use types::{
    CanonicalPubkey, InterchangeAttestation, InterchangeBlock, InterchangeFormat,
    InterchangeMetadata, PruneStats, SignedAttestation, SignedBlock, SigningRoot, ValidatorRecord,
};

/// Production `rules.rs` engine as a history-validity oracle (ARCH-5h).
///
/// Integration tests cannot see `pub(crate)` `check_*`; this re-export is
/// gated so production dependents never take it (they do not enable
/// `test-utils`).
#[cfg(any(test, feature = "test-utils"))]
pub use group_commit::CancellableReserve;
#[cfg(any(test, feature = "test-utils"))]
pub use rules::{
    eip3076_allows_attestation, eip3076_allows_block, first_eip3076_history_violation,
};
