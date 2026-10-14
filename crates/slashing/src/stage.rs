//! RAII guard types for the "stage / commit on success" ordering API.
//!
//! # Design rationale
//!
//! The [`StagedBlock`] and [`StagedAttestation`] guards implement the A15
//! architecture pattern: *check first, commit only on signer success*.  This
//! eliminates phantom rows — rows that were committed before the sign call
//! and then left in the database when the sign call fails.
//!
//! ## Lock-holding strategy
//!
//! `rusqlite::Transaction<'conn>` holds `&'conn Connection`.  Because
//! `Connection: !Sync`, the borrow prevents `Transaction` from being `Send`.
//! Storing both `MutexGuard<Connection>` and `Transaction` in the same struct
//! would require a self-referential layout (`Transaction` borrowing from data
//! owned by `MutexGuard`), which is unsound in safe Rust without a crate like
//! `ouroboros`.
//!
//! We therefore avoid holding a `Transaction` object in the guard struct at
//! all.  Instead, the guard holds just the `parking_lot::MutexGuard<'db,
//! Connection>` and manages the SQLite transaction explicitly via raw
//! `execute_batch` calls:
//!
//! - `stage_*` issues `BEGIN IMMEDIATE`, runs the violation check, and on
//!   success returns a guard that owns the mutex lock (keeping all other
//!   writers out) and the planned INSERT parameters.
//! - `commit` issues the `INSERT` then `COMMIT`, then drops the guard (releases
//!   the lock).
//! - `discard` issues `ROLLBACK` then drops the guard.
//! - `Drop` (without an explicit commit/discard) issues `ROLLBACK` then drops.
//!
//! ## Trade-off: holding the mutex across the signer call
//!
//! The mutex is held for the entire stage → (signer call) → commit window.
//! This means concurrent sign requests for *different* (pubkey, slot) pairs
//! from the same client are serialised behind this lock.  In practice this is
//! acceptable because:
//!
//! 1. The existing per-validator mutex in `crates/signer/src/lib.rs` already
//!    serialises signs for the same validator.
//! 2. The SQLite WAL writer lock is coarse-grained anyway; there is at most
//!    one writer at a time regardless.
//! 3. Signer calls are fast (sub-millisecond BLS on a local key, or bounded
//!    by the network timeout for a remote signer).
//!
//! Callers **should** bound the signer call's wall-clock budget (e.g. a
//! `tokio::time::timeout`) so a stalled signer does not hold the lock
//! indefinitely.
//!
//! ## Test inject (`test-utils`)
//!
//! With the `test-utils` feature, [`SlashingDb::fail_next_commits`] forces the
//! next N commits on **that** DB instance to fail before INSERT/`COMMIT`
//! (snapshotted onto the staged guard at `stage_*`). Drop still rolls back.
//! Used by RF4-03 path-level `CommitFailed` tests in `rvc-signer`.
//!
//! ## `!Send` guarantee
//!
//! `parking_lot::MutexGuard<'_, Connection>` is `!Send` (it must be released
//! on the same thread that acquired it).  Therefore `StagedBlock<'_>` and
//! `StagedAttestation<'_>` are also `!Send`.  Do **not** hold a staged guard
//! across an `.await` point unless the entire future is pinned to a single
//! thread (e.g. via `spawn_blocking`).
//!
//! ## Additive `reserve_*` (ARCH-5e / ADR-005)
//!
//! [`SlashingDb::reserve_block`] / [`SlashingDb::reserve_attestation`] sit
//! **alongside** `stage_*` (A-5.2). They run rule check + INSERT + COMMIT in
//! one short write transaction and return a [`CommittedReservation`] that is
//! `Send` — no `MutexGuard` escapes. Concurrent reserves share one transaction
//! (group commit) so N members pay one fsync; commit-before-sign is
//! unchanged. `stage_*`, `commit()`, `discard()`, and `Drop` are unchanged.
//!
//! **M-1 prior-art warning** (`crates/signer/tests/phantom_row_m1.rs:1-10`):
//! this repo already shipped commit-before-sign and reverted it as a bug.
//! *Before the fix, `sign_attestation` / `sign_block` called
//! `check_and_record_*` (which committed the row immediately) and only then
//! called `signer.sign`. A signing failure left a committed row in the DB,
//! causing the next legitimate sign attempt to look like a DoubleVote.*
//! M-1's failure mode was **liveness, not safety** (a phantom row refuses a
//! legitimate sign; it never permits a double-sign).
//!
//! [`SlashingDb::reconcile_unsigned`] is the compensating delete that makes
//! this ordering admissible (ARCH-5f / M-1). It returns
//! [`ReconcileOutcome`], never `Result`, so a caller cannot `?` a failed
//! delete off a signing path. A failed delete **retains** the row (C1).
//!
//! **Liveness trade (A-5.5).** `SigningGate` is `Fixed(DiscardStagedRow)`.
//! Under that policy a failed compensating delete leaves a phantom row —
//! M-1's liveness mode (a phantom refuses a legitimate later sign; it never
//! permits a double-sign). Accepted because the alternative direction
//! permits a signature on the wire with no slashing record. Failures are
//! metered (`rvc_slashing_reconcile_total{outcome="failed"}`) and logged at
//! `error!`, never silent.
//!
//! Reconcile never touches watermark tables (VD-S6): the signing path does
//! not raise watermarks — they are raised only by interchange import — so a
//! history-row delete cannot lower a floor or re-open a minified-import slot.
//!
//! **C1 (binding):** stage → release → sign → re-check-and-commit is rejected
//! by name. It cannot retain a released row, so an ambiguous remote sign
//! silently becomes a rolled-back row — a signature that may exist on the
//! wire with **no** slashing record. Tentative-commit makes retention the
//! default (the row is already committed). C9's cancellation-proof
//! `stage → sign → commit` core is not weakened: `stage_*` stays.

use parking_lot::MutexGuard;
use rusqlite::Connection;

use crate::db::watermarks::{read_watermark, WatermarkKind};
use crate::error::SlashingError;
use crate::history::{TargetedSqlAttestationHistory, TargetedSqlBlockHistory};
use crate::metrics;
use crate::rules::{
    check_attestation, check_block, AttestationCandidate, AttestationVerdict,
    AttestationWatermarks, BlockCandidate, BlockVerdict, BlockWatermarks,
};
use crate::SlashingDb;
use eth_types::{Epoch, Root, Slot, SLOTS_PER_EPOCH};
use observability::logging::TruncatedPubkey;

/// Fixed audit origin written to the `client_cn` column on INSERT.
///
/// Per-CN audit visibility now flows through [`crate::audit_log`] instead.
/// `pub(crate)` so `db.rs` can use the same constant for `check_and_record_*`.
pub(crate) const AUDIT_ORIGIN: &str = "local-vc";

// ── BlockRow ──────────────────────────────────────────────────────────────────

/// Parameters for the staged block INSERT — stored in the guard so `commit` can
/// execute the INSERT without re-running any business logic.
///
/// The `client_cn` column in the INSERT is always written as [`AUDIT_ORIGIN`].
/// Per-CN audit visibility flows through [`crate::audit_log`].
struct BlockRow {
    pubkey: String,
    slot: Slot,
    signing_root: Option<String>,
    /// Hex-encoded genesis validators root to write into the per-row column.
    gvr_hex: String,
    /// When `true` the row already exists in the DB (idempotent re-sign).
    /// `commit()` skips the INSERT and issues `COMMIT` to close the transaction.
    is_resign: bool,
}

// ── AttestationRow ────────────────────────────────────────────────────────────

/// Parameters for the staged attestation INSERT.
///
/// The `client_cn` column in the INSERT is always written as [`AUDIT_ORIGIN`].
/// Per-CN audit visibility flows through [`crate::audit_log`].
struct AttestationRow {
    pubkey: String,
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: Option<String>,
    /// Hex-encoded genesis validators root to write into the per-row column.
    gvr_hex: String,
    is_duplicate: bool,
}

// ── CommittedReservation (ARCH-5e) ────────────────────────────────────────────

/// Proof that a history row is COMMITTED and the DB lock is released.
///
/// Carries what a compensating delete needs. `Send` — the mutex is gone.
///
/// C1 retain-on-ambiguity is the reason the row is committed *before* the
/// sign: an ambiguous signer error needs no action to retain it.
/// [`SlashingDb::reconcile_unsigned`] is the only safe way to remove a
/// reservation that was never signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedReservation {
    pub pubkey_hex: String,
    pub kind: ReservationKind,
    pub signing_root_hex: Option<String>,
    /// Distinguishes a fresh INSERT (reconcilable) from an idempotent re-sign
    /// or duplicate, where NOTHING may be deleted.
    pub inserted: bool,
}

/// Discriminant stored on [`CommittedReservation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationKind {
    Block { slot: Slot },
    Attestation { source: Epoch, target: Epoch },
}

impl ReservationKind {
    fn metric_kind(self) -> &'static str {
        match self {
            Self::Block { .. } => metrics::tx_hold_kind::BLOCK,
            Self::Attestation { .. } => metrics::tx_hold_kind::ATTESTATION,
        }
    }
}

/// Outcome of [`SlashingDb::reconcile_unsigned`].
///
/// **Not a `Result`.** A compensation failure must not abort a signing path
/// via `?` — failing safe means continuing with the row retained.
#[must_use = "a Failed reconcile retains the reserved row (C1); do not discard silently"]
#[derive(Debug)]
pub enum ReconcileOutcome {
    /// Targeted DELETE removed exactly one reserved history row.
    Deleted,
    /// No-op: `inserted == false` (an earlier legitimate sign owns the row),
    /// or the targeted `(pubkey, kind, signing_root)` matched zero rows.
    NotApplicable,
    /// DELETE/COMMIT failed. The reserved row is still present.
    Failed(SlashingError),
}

// ── StagedBlock ───────────────────────────────────────────────────────────────

/// RAII guard returned by [`SlashingDb::stage_block`].
///
/// The guard holds the database mutex for the lifetime of the staged operation.
/// Call [`commit`](StagedBlock::commit) after a successful sign to persist the
/// row, or [`discard`](StagedBlock::discard) (or just drop the guard) to roll
/// back.
///
/// # Drop behaviour
///
/// Dropping this guard without calling `commit()` issues a `ROLLBACK` and
/// releases the mutex.  An error during `ROLLBACK` at drop time is logged but
/// not propagated (panicking in `Drop` is unsound).
///
/// # `!Send`
///
/// This type is `!Send` because `parking_lot::MutexGuard` must be released on
/// the same thread.  Do **not** hold it across an `.await` unless you are on a
/// single-threaded runtime or inside `spawn_blocking`.
pub struct StagedBlock<'db> {
    guard: Option<MutexGuard<'db, Connection>>,
    row: BlockRow,
    committed: bool,
    /// Snapshotted from [`SlashingDb::take_injected_commit_failure`] at stage time.
    inject_fail_commit: bool,
}

impl std::fmt::Debug for StagedBlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedBlock")
            .field("pubkey", &self.row.pubkey)
            .field("slot", &self.row.slot)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl<'db> StagedBlock<'db> {
    /// Execute the staged INSERT and commit the transaction.
    ///
    /// For idempotent re-signs (the row already exists with the same signing
    /// root) the INSERT is skipped and only `COMMIT` is issued.
    ///
    /// Consumes the guard and releases the database mutex.
    pub fn commit(mut self) -> Result<(), SlashingError> {
        if self.inject_fail_commit {
            return Err(SlashingError::MigrationFailed(
                "injected commit failure (test-utils)".into(),
            ));
        }

        let Some(guard) = self.guard.as_mut() else {
            return Err(SlashingError::InternalInvariant("staged block guard missing at commit"));
        };

        if !self.row.is_resign {
            guard.execute(
                "INSERT INTO blocks
                 (client_cn, pubkey, slot, signing_root, genesis_validators_root)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    AUDIT_ORIGIN,
                    &self.row.pubkey,
                    self.row.slot as i64,
                    &self.row.signing_root,
                    &self.row.gvr_hex,
                ),
            )?;
        }

        guard.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    /// Roll back the staged transaction without committing.
    ///
    /// Equivalent to dropping the guard.  Prefer calling this explicitly so
    /// the intent is visible at the call site.
    pub fn discard(self) {
        // Drop fires the ROLLBACK.
    }
}

impl Drop for StagedBlock<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(guard) = self.guard.as_mut() {
                if let Err(e) = guard.execute_batch("ROLLBACK") {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&self.row.pubkey),
                        slot = self.row.slot,
                        error = %e,
                        "StagedBlock::drop: ROLLBACK failed (transaction may already be finished)"
                    );
                }
            }
        }
    }
}

// ── StagedAttestation ─────────────────────────────────────────────────────────

/// RAII guard returned by [`SlashingDb::stage_attestation`].
///
/// See [`StagedBlock`] for full documentation of the semantics.
pub struct StagedAttestation<'db> {
    guard: Option<MutexGuard<'db, Connection>>,
    row: AttestationRow,
    committed: bool,
    /// Snapshotted from [`SlashingDb::take_injected_commit_failure`] at stage time.
    inject_fail_commit: bool,
}

impl std::fmt::Debug for StagedAttestation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedAttestation")
            .field("pubkey", &self.row.pubkey)
            .field("source_epoch", &self.row.source_epoch)
            .field("target_epoch", &self.row.target_epoch)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl<'db> StagedAttestation<'db> {
    /// Execute the staged INSERT (if not a duplicate re-sign) and commit the
    /// transaction.
    pub fn commit(mut self) -> Result<(), SlashingError> {
        if self.inject_fail_commit {
            return Err(SlashingError::MigrationFailed(
                "injected commit failure (test-utils)".into(),
            ));
        }

        let Some(guard) = self.guard.as_mut() else {
            return Err(SlashingError::InternalInvariant(
                "staged attestation guard missing at commit",
            ));
        };

        if !self.row.is_duplicate {
            guard.execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    AUDIT_ORIGIN,
                    &self.row.pubkey,
                    self.row.source_epoch as i64,
                    self.row.target_epoch as i64,
                    &self.row.signing_root,
                    &self.row.gvr_hex,
                ),
            )?;
        }

        guard.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    /// Roll back the staged transaction without committing.
    pub fn discard(self) {
        // Drop fires the ROLLBACK.
    }
}

impl Drop for StagedAttestation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(guard) = self.guard.as_mut() {
                if let Err(e) = guard.execute_batch("ROLLBACK") {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&self.row.pubkey),
                        source_epoch = self.row.source_epoch,
                        target_epoch = self.row.target_epoch,
                        error = %e,
                        "StagedAttestation::drop: ROLLBACK failed"
                    );
                }
            }
        }
    }
}

// ── SlashingDb staging methods ────────────────────────────────────────────────

impl SlashingDb {
    /// Begin an immediate transaction, run the EIP-3076 violation check for a
    /// block proposal, and return a [`StagedBlock`] guard.
    ///
    /// The guard holds the database mutex until it is consumed by
    /// [`commit`](StagedBlock::commit) or dropped (which rolls back).
    ///
    /// # Arguments
    /// - `pubkey_hex`: Validator public key as a hex string.
    /// - `slot`: Beacon chain slot being proposed.
    /// - `signing_root_hex`: Optional signing root.
    /// - `gvr`: Genesis validators root.  Compared against
    ///   `metadata.genesis_validators_root` (M-6 / ISSUE-3.5).  On mismatch,
    ///   returns `Err(SlashingError::GenesisRootMismatch)` before acquiring the lock.
    ///
    /// The `client_cn` column in the committed row is always written as `"local-vc"`.
    /// Per-CN audit visibility is emitted via [`crate::audit_log`] by callers
    /// (e.g. [`crate::PubkeyScopedDb`]) that know the CN.
    ///
    /// # Errors
    /// Returns `SlashingError::GenesisRootMismatch` if `gvr` does not match the
    /// pinned metadata value.  Returns `SlashingError::SlashableBlock` (specifically
    /// `BlockSlashingViolation::DoubleBlockProposal`) if a different signing
    /// root has already been committed for `(pubkey, slot)`.
    ///
    /// # Trade-off: mutex held across signer call
    ///
    /// The returned guard holds the internal `Connection` mutex for its entire
    /// lifetime.  See the [module-level documentation](crate::stage) for a
    /// full analysis.  Callers should bound the signer call's wall-clock budget.
    pub fn stage_block<'db>(
        &'db self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<StagedBlock<'db>, SlashingError> {
        // M-6: GVR check before acquiring the main mutex to avoid nested-lock deadlock.
        // pinned_gvr() may itself briefly acquire the mutex on a cold cache, then release it.
        if let Some(pinned) = self.pinned_gvr()? {
            if pinned != *gvr {
                tracing::error!(
                    rejection_reason = "genesis_root_mismatch",
                    "stage_block rejected: genesis root mismatch"
                );
                return Err(SlashingError::GenesisRootMismatch { expected: pinned, got: *gvr });
            }
        }

        let gvr_hex = crate::db::SlashingDb::root_to_hex(gvr);
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let guard = self.conn.lock();

        guard.execute_batch("BEGIN IMMEDIATE")?;

        let strict = self.fork_aware_strict(slot / SLOTS_PER_EPOCH);
        // Run violation checks inside a closure so any error — whether a SQL
        // I/O error from `?`-propagation or an EIP-3076 violation — funnels
        // through a single ROLLBACK before we return. Without this wrapper a
        // SQL error between `BEGIN IMMEDIATE` and the guard transfer would
        // drop the MutexGuard with the transaction still open, leaving the
        // connection in a broken "transaction within transaction" state.
        let outcome = (|| -> Result<BlockVerdict, SlashingError> {
            let watermark = read_watermark(&guard, pubkey.as_ref(), WatermarkKind::Block)?;

            let history = TargetedSqlBlockHistory::new(&guard, pubkey.as_ref());
            let watermarks = BlockWatermarks { block: watermark.map(|w| w as Slot) };
            let candidate = BlockCandidate { slot, signing_root: signing_root_hex.clone() };
            check_block(pubkey.as_ref(), &history, &watermarks, &candidate, strict)
        })();

        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                return Err(e);
            }
        };

        // Same signing root on a Resign — keep the transaction open and let
        // `commit()` skip the INSERT but still close the transaction. A
        // `discard()` or bare drop issues `ROLLBACK`, which is harmless on
        // a read-only transaction.
        let inject_fail_commit = self.take_injected_commit_failure();
        Ok(StagedBlock {
            guard: Some(guard),
            row: BlockRow {
                pubkey: pubkey.to_string(),
                slot,
                signing_root: signing_root_hex,
                gvr_hex,
                is_resign: matches!(outcome, BlockVerdict::Resign),
            },
            committed: false,
            inject_fail_commit,
        })
    }

    /// Begin an immediate transaction, run the EIP-3076 violation check for an
    /// attestation, and return a [`StagedAttestation`] guard.
    ///
    /// See [`stage_block`](SlashingDb::stage_block) for the general contract.
    ///
    /// The `client_cn` column in the committed row is always written as `"local-vc"`.
    /// Per-CN audit visibility is emitted via [`crate::audit_log`] by callers.
    ///
    /// # Errors
    /// Returns `SlashingError::GenesisRootMismatch` if `gvr` does not match the
    /// pinned metadata value.  Returns `SlashingError::SlashableAttestation` (double
    /// vote, surrounding, or surrounded) if the new `(source, target)` pair conflicts
    /// with any existing attestation for `pubkey` (pubkey-scoped).
    pub fn stage_attestation<'db>(
        &'db self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<StagedAttestation<'db>, SlashingError> {
        // M-6: GVR check before acquiring the main mutex.
        if let Some(pinned) = self.pinned_gvr()? {
            if pinned != *gvr {
                tracing::error!(
                    rejection_reason = "genesis_root_mismatch",
                    "stage_attestation rejected: genesis root mismatch"
                );
                return Err(SlashingError::GenesisRootMismatch { expected: pinned, got: *gvr });
            }
        }

        let gvr_hex = crate::db::SlashingDb::root_to_hex(gvr);
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let guard = self.conn.lock();

        guard.execute_batch("BEGIN IMMEDIATE")?;

        let strict = self.fork_aware_strict(target_epoch);
        // Wrap the violation-check phase so any error — SQL I/O or EIP-3076 —
        // funnels through a single ROLLBACK before we return.  See the
        // matching note in `stage_block`.
        let outcome = (|| -> Result<AttestationVerdict, SlashingError> {
            let wm_source =
                read_watermark(&guard, pubkey.as_ref(), WatermarkKind::AttestationSource)?;
            let wm_target =
                read_watermark(&guard, pubkey.as_ref(), WatermarkKind::AttestationTarget)?;

            let history = TargetedSqlAttestationHistory::new(&guard, pubkey.as_ref());
            let watermarks = AttestationWatermarks {
                source: wm_source.map(|w| w as Epoch),
                target: wm_target.map(|w| w as Epoch),
            };
            let candidate = AttestationCandidate {
                source_epoch,
                target_epoch,
                signing_root: signing_root_hex.clone(),
            };
            check_attestation(pubkey.as_ref(), &history, &watermarks, &candidate, strict)
        })();

        let verdict = match outcome {
            Ok(v) => v,
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                return Err(e);
            }
        };

        let inject_fail_commit = self.take_injected_commit_failure();
        Ok(StagedAttestation {
            guard: Some(guard),
            row: AttestationRow {
                pubkey: pubkey.to_string(),
                source_epoch,
                target_epoch,
                signing_root: signing_root_hex,
                gvr_hex,
                is_duplicate: matches!(verdict, AttestationVerdict::Duplicate),
            },
            committed: false,
            inject_fail_commit,
        })
    }

    /// Rule check + INSERT + COMMIT in one short write transaction.
    ///
    /// The connection mutex is acquired and released **inside** this call; no
    /// guard escapes, so the returned [`CommittedReservation`] is `Send`.
    ///
    /// GVR is still checked **before** the mutex, preserving the nested-lock
    /// avoidance already at [`Self::stage_block`].
    ///
    /// # C1 / M-1
    ///
    /// This commits the row *before* any sign. That is what makes retain-on-
    /// ambiguity the default (C1). It is **not** the rejected
    /// stage→release→sign→re-check design. Call [`Self::reconcile_unsigned`]
    /// on the unambiguous-no-signature class (and, under `DiscardStagedRow`,
    /// on timeout/ambiguous too — §5.3). A failed delete retains.
    ///
    /// # Errors
    ///
    /// - [`SlashingError::GenesisRootMismatch`] — before the mutex.
    /// - [`SlashingError::SlashableBlock`] / watermark floors — rule check;
    ///   transaction rolled back, no row.
    /// - [`SlashingError::ReserveCommitFailed`] — INSERT/COMMIT (or the test
    ///   inject) failed; transaction rolled back, no new row. Distinguishable
    ///   from a rule violation.
    pub fn reserve_block(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<CommittedReservation, SlashingError> {
        self.reserve_block_grouped(pubkey_hex, slot, signing_root_hex, gvr)
    }

    /// Attestation counterpart of [`Self::reserve_block`].
    ///
    /// Same contract: one short write transaction, `Send` token, GVR check
    /// before the mutex, errors between `BEGIN IMMEDIATE` and return funnel
    /// through exactly one `ROLLBACK`. Pair with [`Self::reconcile_unsigned`].
    pub fn reserve_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<CommittedReservation, SlashingError> {
        self.reserve_attestation_grouped(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root_hex,
            gvr,
        )
    }

    /// Best-effort compensating delete of a reserved history row.
    ///
    /// Returns [`ReconcileOutcome`], never `Result` — a failed delete must not
    /// be `?`-propagated off a signing path. Failing safe means continuing
    /// with the row retained (C1).
    ///
    /// - `inserted == false` → [`ReconcileOutcome::NotApplicable`]. Deleting a
    ///   row an earlier legitimate sign owns would be a **safety** regression.
    /// - Targeted `DELETE` on `(pubkey, kind-discriminant, signing_root)` in
    ///   its own short `BEGIN IMMEDIATE` transaction. `changes() == 1` →
    ///   [`ReconcileOutcome::Deleted`]; `changes() == 0` →
    ///   [`ReconcileOutcome::NotApplicable`] (never reported as Deleted).
    ///   `changes() > 1` rolls back.
    ///
    /// Watermark tables are never written. Metric emission and the `error!` on
    /// [`ReconcileOutcome::Failed`] happen **after** the connection mutex is
    /// released (C2 / G-7).
    pub fn reconcile_unsigned(&self, reservation: &CommittedReservation) -> ReconcileOutcome {
        let kind = reservation.kind;
        if !reservation.inserted {
            record_reconcile(kind, metrics::reconcile_outcome::NOT_APPLICABLE);
            return ReconcileOutcome::NotApplicable;
        }

        let result = {
            let guard = self.conn.lock();
            with_immediate_txn(&guard, |conn| reconcile_delete_txn(self, conn, reservation))
        };

        match result {
            Ok(true) => {
                record_reconcile(kind, metrics::reconcile_outcome::DELETED);
                ReconcileOutcome::Deleted
            }
            Ok(false) => {
                record_reconcile(kind, metrics::reconcile_outcome::NOT_APPLICABLE);
                ReconcileOutcome::NotApplicable
            }
            Err(err) => {
                record_reconcile(kind, metrics::reconcile_outcome::FAILED);
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&reservation.pubkey_hex),
                    ?kind,
                    error = %err,
                    "reconcile_unsigned failed; retaining reserved slashing row \
                     (C1 fail-safe; M-1 liveness)"
                );
                ReconcileOutcome::Failed(err)
            }
        }
    }
}

/// DELETE + COMMIT for one reserved row. `Ok(true)` = one row deleted;
/// `Ok(false)` = targeted identity matched nothing. Any `Err` is rolled back
/// by [`with_immediate_txn`] so the row is retained.
fn reconcile_delete_txn(
    db: &SlashingDb,
    conn: &Connection,
    reservation: &CommittedReservation,
) -> Result<bool, SlashingError> {
    if db.take_injected_commit_failure() {
        return Err(SlashingError::ReconcileFailed(
            "injected reconcile failure (test-utils)".into(),
        ));
    }

    let before = if cfg!(debug_assertions) { Some(snapshot_watermarks(conn)?) } else { None };

    let pubkey = crate::db::normalize_pubkey(&reservation.pubkey_hex)?;
    let changes = delete_reserved_row(conn, pubkey.as_ref(), reservation)
        .map_err(|e| SlashingError::ReconcileFailed(e.to_string()))?;
    if changes > 1 {
        return Err(SlashingError::ReconcileFailed(format!(
            "targeted delete affected {changes} rows (cap is 1)"
        )));
    }

    if let Some(before) = before {
        let after = snapshot_watermarks(conn)?;
        debug_assert_eq!(
            before, after,
            "reconcile_unsigned must not touch watermark tables (VD-S6)"
        );
    }

    conn.execute_batch("COMMIT").map_err(|e| SlashingError::ReconcileFailed(e.to_string()))?;
    Ok(changes == 1)
}

/// Targeted DELETE: `(pubkey, kind-discriminant, signing_root)`.
/// `signing_root IS ?` is NULL-safe so a `None` reservation cannot match a
/// different row that happens to have a non-NULL root.
fn delete_reserved_row(
    conn: &Connection,
    pubkey: &str,
    reservation: &CommittedReservation,
) -> rusqlite::Result<usize> {
    match reservation.kind {
        ReservationKind::Block { slot } => conn.execute(
            "DELETE FROM blocks
             WHERE pubkey = ?1 AND slot = ?2 AND signing_root IS ?3",
            (pubkey, slot as i64, &reservation.signing_root_hex),
        ),
        ReservationKind::Attestation { source, target } => conn.execute(
            "DELETE FROM attestations
             WHERE pubkey = ?1 AND source_epoch = ?2 AND target_epoch = ?3
               AND signing_root IS ?4",
            (pubkey, source as i64, target as i64, &reservation.signing_root_hex),
        ),
    }
}

fn snapshot_watermarks(conn: &Connection) -> Result<Vec<(String, String, i64)>, SlashingError> {
    let mut stmt = conn.prepare(
        "SELECT pubkey, watermark_type, value FROM watermarks ORDER BY pubkey, watermark_type",
    )?;
    let mapped = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    let mut rows = Vec::new();
    for row in mapped {
        rows.push(row?);
    }
    Ok(rows)
}

fn record_reconcile(kind: ReservationKind, outcome: &str) {
    metrics::RVC_SLASHING_RECONCILE_TOTAL.with_label_values(&[kind.metric_kind(), outcome]).inc();
}

/// `BEGIN IMMEDIATE` then `body`. Any `Err` from `body` is followed by exactly
/// one `ROLLBACK` so the connection is never left mid-transaction. A successful
/// `body` has already `COMMIT`ted or `ROLLBACK`ed (the all-rejected path).
pub(crate) fn with_immediate_txn<T, F>(conn: &Connection, body: F) -> Result<T, SlashingError>
where
    F: FnOnce(&Connection) -> Result<T, SlashingError>,
{
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match body(conn) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Consume the commit inject (if armed), run `insert`, then `COMMIT`.
/// INSERT/COMMIT failures become [`SlashingError::ReserveCommitFailed`].
pub(crate) fn persist_reserved_row(
    db: &SlashingDb,
    conn: &Connection,
    insert: impl FnOnce() -> Result<(), SlashingError>,
) -> Result<(), SlashingError> {
    if db.take_injected_commit_failure() {
        return Err(SlashingError::ReserveCommitFailed(
            "injected commit failure (test-utils)".into(),
        ));
    }
    insert()?;
    conn.execute_batch("COMMIT").map_err(|e| SlashingError::ReserveCommitFailed(e.to_string()))
}
