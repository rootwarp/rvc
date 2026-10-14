//! Slashing protection error types.

use thiserror::Error;

use eth_types::{Epoch, Root, Slot};

/// Errors that can occur during slashing protection operations.
#[derive(Debug, Error)]
pub enum SlashingError {
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("schema migration failed: {0}")]
    MigrationFailed(String),

    #[error("attestation slashable: {0}")]
    SlashableAttestation(#[from] AttestationSlashingViolation),

    #[error("block slashable: {0}")]
    SlashableBlock(#[from] BlockSlashingViolation),

    #[error("genesis validators root mismatch: expected {expected}, got {actual}")]
    GenesisValidatorsRootMismatch { expected: String, actual: String },

    /// Per-call genesis validators root check failed (M-6 / ISSUE-3.5).
    ///
    /// Returned when the caller-supplied `gvr` does not match the value pinned
    /// in `metadata.genesis_validators_root`.  A mismatch indicates that the
    /// validator client is pointing at a different chain's beacon node than the
    /// one it was originally configured for (i.e. a chain swap).
    #[error(
        "genesis root mismatch: expected 0x{}, got 0x{}",
        hex::encode(expected),
        hex::encode(got)
    )]
    GenesisRootMismatch { expected: Root, got: Root },

    #[error("invalid interchange format: {0}")]
    InvalidInterchangeFormat(String),

    /// Attestation floor cannot be encoded as one interchange record.
    ///
    /// The derived bounds have `source_bound > target_bound`, or only one of
    /// the source and target watermarks is set (the missing side is `0`).
    /// The whole export fails; no partial interchange is returned.
    #[error(
        "attestation floor for {pubkey} cannot be represented \
         (source_bound={source_bound}, target_bound={target_bound})"
    )]
    UnrepresentableFloor { pubkey: String, source_bound: Epoch, target_bound: Epoch },

    /// Pubkey rejected at internal-record construction ([`crate::SignedBlock::new`] /
    /// [`crate::SignedAttestation::new`]).
    #[error("invalid slashing-record pubkey ({0})")]
    InvalidPubkey(&'static str),

    /// A staging-path invariant that used to be `.expect` (ARCH-5o).
    #[error("internal slashing invariant violated: {0}")]
    InternalInvariant(&'static str),

    #[error("database integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error(
        "watermark can only be raised: attempted to lower {watermark_type} for {pubkey} \
         (current={current}, attempted={attempted})"
    )]
    WatermarkLowered { pubkey: String, watermark_type: String, current: u64, attempted: u64 },

    #[error(
        "no watermarks set — import an EIP-3076 interchange (or set watermarks) before pruning; \
         pruning without watermarks would delete all records"
    )]
    NoWatermarksSet,

    #[error(
        "block at slot {slot} is at or below watermark slot {watermark_slot} for pubkey {pubkey}"
    )]
    BelowBlockWatermark { pubkey: String, slot: Slot, watermark_slot: Slot },

    #[error(
        "attestation with target epoch {target_epoch} is at or below watermark target epoch \
         {watermark_target} for pubkey {pubkey}"
    )]
    BelowAttestationWatermark { pubkey: String, target_epoch: Epoch, watermark_target: Epoch },

    #[error(
        "attestation with source epoch {source_epoch} is below watermark source epoch \
         {watermark_source} for pubkey {pubkey}"
    )]
    BelowAttestationSourceWatermark { pubkey: String, source_epoch: Epoch, watermark_source: Epoch },

    #[error("unsafe file permissions on {path} (mode {mode}): group or world accessible")]
    UnsafePermissions { path: String, mode: String },

    #[error("Slashing DB refused to open with non-WAL journal mode: actual={actual}. {hint}")]
    JournalMode { actual: String, hint: String },

    /// Empty (0-byte) or non-SQLite header at the configured path.
    ///
    /// SEC-3: a truncated/partial-write file is corruption, never a legitimate
    /// fresh init. Operators must restore from backup; opt-in flags cannot
    /// override this.
    #[error(
        "slashing protection database at {path} is empty or has a corrupt SQLite header \
         (size={size} bytes). This is corruption, not a fresh init — restore from backup. \
         Opt-in flags (--init-slashing-db / allow_fresh_db) cannot override this."
    )]
    CorruptOrEmpty { path: String, size: u64 },

    /// File inspection failed before open (permissions, I/O).
    #[error("failed to inspect slashing protection database at {path}: {message}")]
    InspectFailed { path: String, message: String },

    /// INSERT+COMMIT inside [`crate::SlashingDb::reserve_block`] /
    /// [`crate::SlashingDb::reserve_attestation`] failed. The transaction was
    /// rolled back; no new history row exists.
    ///
    /// Distinguished from a rule violation (`SlashableBlock` /
    /// `SlashableAttestation` / watermark floors) so the signer can map this
    /// to `CommitFailed` (same-root retry safe), never `SlashingBlocked`.
    /// Classification of this variant is ARCH-5i; the inject is ARCH-5e/5g.
    #[error("slashing-protection reserve commit failed (no row written): {0}")]
    ReserveCommitFailed(String),

    /// Compensating delete inside [`crate::SlashingDb::reconcile_unsigned`]
    /// failed. The reserved history row is **retained** (C1 fail-safe).
    ///
    /// Never returned as `Err` from `reconcile_unsigned` — that method returns
    /// [`crate::ReconcileOutcome::Failed`] so a caller cannot `?` a compensation
    /// failure off a signing path.
    #[error("slashing-protection compensating delete failed (row retained): {0}")]
    ReconcileFailed(String),
}

impl SlashingError {
    /// True when a `reserve_*` persist (INSERT/COMMIT, including the test inject)
    /// failed. Not a slashing-rule verdict.
    pub fn is_reserve_commit_failure(&self) -> bool {
        matches!(self, Self::ReserveCommitFailed(_))
    }

    /// Rule / watermark / GVR rejections that apply to one group-commit member
    /// without aborting the rest of the batch.
    pub(crate) fn is_group_member_rejection(&self) -> bool {
        matches!(
            self,
            Self::SlashableBlock(_)
                | Self::SlashableAttestation(_)
                | Self::GenesisRootMismatch { .. }
                | Self::BelowBlockWatermark { .. }
                | Self::BelowAttestationWatermark { .. }
                | Self::BelowAttestationSourceWatermark { .. }
        )
    }
}

/// Specific types of attestation slashing violations per EIP-3076.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationSlashingViolation {
    #[error("double vote: already signed attestation for target epoch {target_epoch}")]
    DoubleVote { target_epoch: Epoch },

    #[error(
        "surrounding vote: new attestation ({new_source}, {new_target}) surrounds existing ({existing_source}, {existing_target})"
    )]
    SurroundingVote {
        new_source: Epoch,
        new_target: Epoch,
        existing_source: Epoch,
        existing_target: Epoch,
    },

    #[error(
        "surrounded vote: new attestation ({new_source}, {new_target}) is surrounded by existing ({existing_source}, {existing_target})"
    )]
    SurroundedVote {
        new_source: Epoch,
        new_target: Epoch,
        existing_source: Epoch,
        existing_target: Epoch,
    },

    #[error("target epoch {target_epoch} is below minimum existing target epoch {min_target}")]
    TargetEpochBelowMinimum { target_epoch: Epoch, min_target: Epoch },
}

/// Specific types of block slashing violations per EIP-3076.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockSlashingViolation {
    #[error("double block proposal: already signed a different block for slot {slot}")]
    DoubleBlockProposal { slot: Slot },

    #[error("slot {slot} is below minimum existing slot {min_slot}")]
    SlotBelowMinimum { slot: Slot, min_slot: Slot },
}
