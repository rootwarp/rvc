//! Pubkey-scoped view over the shared `SlashingDb` (Issue 2.4 / 2.5).
//!
//! `PubkeyScopedDb` binds a fixed `genesis_validators_root` and records a
//! `client_cn` for audit-log purposes only.  It exposes no API that lets the
//! caller key the slashing check by CN — all checks are purely pubkey+gvr scoped.
//!
//! This replaces `bin/rvc-signer::ScopedSlashingDb` as the canonical high-level
//! entry point (Issue 2.5 migration).

use std::sync::Arc;

use eth_types::{Epoch, Root, Slot};

use crate::audit::audit_log;
use crate::error::SlashingError;
use crate::stage::{CommittedReservation, ReconcileOutcome, StagedAttestation, StagedBlock};
use crate::SlashingDb;

/// Captured audit outcome whose emission is deferred until the staged guard is gone.
///
/// `#[must_use]` is the enforcement: a caller that forgets to emit gets a warning,
/// and `-D warnings` in CI turns that into a failure.
///
/// # Ordering guarantee (ADR-006)
///
/// - `"rejected"` is emitted synchronously on the `Err` path of
///   [`PubkeyScopedDb::stage_block`] / [`PubkeyScopedDb::stage_attestation`]
///   (no guard exists at that point).
/// - `"staged"` is returned here and must be emitted by the caller **after**
///   `commit()` / `discard()` releases the connection mutex. A `"staged"` event
///   therefore correlates with commit/discard rather than preceding it — an
///   accepted consequence of ADR-006, not a defect.
#[must_use = "the slashing audit record must be emitted after the staged guard is released"]
#[derive(Debug)]
pub struct PendingAudit {
    client_cn: String,
    pubkey_hex: String,
    outcome: &'static str,
}

impl PendingAudit {
    /// Emit the record. Call ONLY after `commit()` / `discard()` has released the mutex.
    pub fn emit(self) {
        audit_log(&self.client_cn, &self.pubkey_hex, self.outcome);
    }
}

/// A pubkey-scoped view over the shared `SlashingDb` bound to a specific
/// `genesis_validators_root`.
///
/// Stores `client_cn` for audit-log emission only; it is never used as a
/// slashing-check discriminator.  pubkey+gvr is the sole uniqueness scope.
///
/// # Example
/// ```ignore
/// use std::sync::Arc;
/// use rvc_slashing::{SlashingDb, PubkeyScopedDb};
///
/// let db = Arc::new(SlashingDb::open_in_memory().unwrap());
/// let gvr: [u8; 32] = [1u8; 32];
/// let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), gvr);
/// ```
pub struct PubkeyScopedDb {
    db: Arc<SlashingDb>,
    /// Audit CN — recorded in `audit_log` calls; never used in slashing checks.
    client_cn: String,
    gvr: Root,
}

impl PubkeyScopedDb {
    /// Create a new pubkey-scoped view.
    ///
    /// - `db`: Shared database instance.
    /// - `client_cn`: The client CN to record in audit-log entries.  Has no
    ///   effect on the slashing check — the check is pubkey+gvr scoped only.
    /// - `gvr`: Genesis validators root for this chain.  Every signing call will
    ///   be validated against the metadata-pinned value via the M-6 GVR check.
    pub fn new(db: Arc<SlashingDb>, client_cn: String, gvr: Root) -> Self {
        Self { db, client_cn, gvr }
    }

    /// Begin an immediate transaction and run the EIP-3076 block-proposal check.
    ///
    /// Delegates to [`SlashingDb::stage_block`].
    ///
    /// # Audit ordering (ADR-006)
    ///
    /// - On `Err`: emits `"rejected"` immediately (no staged guard exists).
    /// - On `Ok`: returns [`PendingAudit`] with outcome `"staged"`. The caller
    ///   **must** call [`PendingAudit::emit`] only after `commit()` / `discard()`
    ///   releases the connection mutex. A `"staged"` event therefore correlates
    ///   with commit/discard rather than preceding it — accepted ADR-006
    ///   consequence, not a defect.
    ///
    /// # Errors
    ///
    /// Returns `SlashingError::SlashableBlock` if a different signing root has
    /// already been committed for `(pubkey, slot)` across any CN.
    pub fn stage_block<'db>(
        &'db self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
    ) -> Result<(StagedBlock<'db>, PendingAudit), SlashingError> {
        match self.db.stage_block(pubkey_hex, slot, signing_root_hex, &self.gvr) {
            Ok(staged) => {
                let audit = PendingAudit {
                    client_cn: self.client_cn.clone(),
                    pubkey_hex: pubkey_hex.to_string(),
                    outcome: "staged",
                };
                Ok((staged, audit))
            }
            Err(e) => {
                // No guard was ever created — safe to emit under no lock.
                audit_log(&self.client_cn, pubkey_hex, "rejected");
                Err(e)
            }
        }
    }

    /// Begin an immediate transaction and run the EIP-3076 attestation check.
    ///
    /// Delegates to [`SlashingDb::stage_attestation`].
    ///
    /// # Audit ordering (ADR-006)
    ///
    /// Same contract as [`Self::stage_block`]: `"rejected"` is emitted
    /// synchronously; `"staged"` is handed off via [`PendingAudit`] and must be
    /// emitted after the caller releases the guard.
    ///
    /// # Errors
    ///
    /// Returns `SlashingError::SlashableAttestation` if the new `(source, target)` pair
    /// conflicts with any existing attestation for `pubkey` across any CN.
    pub fn stage_attestation<'db>(
        &'db self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
    ) -> Result<(StagedAttestation<'db>, PendingAudit), SlashingError> {
        match self.db.stage_attestation(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root_hex,
            &self.gvr,
        ) {
            Ok(staged) => {
                let audit = PendingAudit {
                    client_cn: self.client_cn.clone(),
                    pubkey_hex: pubkey_hex.to_string(),
                    outcome: "staged",
                };
                Ok((staged, audit))
            }
            Err(e) => {
                audit_log(&self.client_cn, pubkey_hex, "rejected");
                Err(e)
            }
        }
    }

    /// Rule check + INSERT + COMMIT, then emit the slashing audit record.
    ///
    /// Delegates to [`SlashingDb::reserve_block`]. The connection mutex is
    /// released before this method returns, so audit emission is **outside**
    /// the lock by construction (C2 / ADR-006).
    ///
    /// # Audit ordering (ADR-006)
    ///
    /// `"staged"` is emitted after the reserve transaction commits. It
    /// correlates with **"a row exists"** — not with "a row will exist if the
    /// sign succeeds" (that was the `stage_*` / [`PendingAudit`] meaning).
    /// `"rejected"` is emitted on `Err` (rule violation, GVR mismatch, or
    /// reserve-time commit failure). No [`PendingAudit`] is returned: there
    /// is no guard for the caller to release.
    ///
    /// `fail_next_commits` is consumed by the inner `reserve_*` immediately
    /// before INSERT: the inject fails **this** call, not a later commit or
    /// reconcile.
    ///
    /// # Errors
    ///
    /// Same surface as [`SlashingDb::reserve_block`].
    pub fn reserve_block(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
    ) -> Result<CommittedReservation, SlashingError> {
        match self.db.reserve_block(pubkey_hex, slot, signing_root_hex, &self.gvr) {
            Ok(reservation) => {
                audit_log(&self.client_cn, pubkey_hex, "staged");
                Ok(reservation)
            }
            Err(e) => {
                audit_log(&self.client_cn, pubkey_hex, "rejected");
                Err(e)
            }
        }
    }

    /// Attestation counterpart of [`Self::reserve_block`].
    ///
    /// Same audit contract: `"staged"` means a row exists; `"rejected"` is
    /// emitted on `Err`. Emission is after the inner reserve returns, so it
    /// is outside the connection mutex (C2 / ADR-006).
    ///
    /// # Errors
    ///
    /// Same surface as [`SlashingDb::reserve_attestation`].
    pub fn reserve_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
    ) -> Result<CommittedReservation, SlashingError> {
        match self.db.reserve_attestation(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root_hex,
            &self.gvr,
        ) {
            Ok(reservation) => {
                audit_log(&self.client_cn, pubkey_hex, "staged");
                Ok(reservation)
            }
            Err(e) => {
                audit_log(&self.client_cn, pubkey_hex, "rejected");
                Err(e)
            }
        }
    }

    /// Compensating delete of a reserved row, then emit an audit record.
    ///
    /// Delegates to [`SlashingDb::reconcile_unsigned`]. That method releases
    /// the mutex before returning, so emission is outside the lock (C2 / G-7).
    ///
    /// `outcome` is `"reconciled"` on [`ReconcileOutcome::Deleted`] /
    /// [`ReconcileOutcome::NotApplicable`], and `"reconcile_failed"` on
    /// [`ReconcileOutcome::Failed`].
    pub fn reconcile_unsigned(&self, reservation: &CommittedReservation) -> ReconcileOutcome {
        let outcome = self.db.reconcile_unsigned(reservation);
        let audit_outcome = match &outcome {
            ReconcileOutcome::Failed(_) => "reconcile_failed",
            ReconcileOutcome::Deleted | ReconcileOutcome::NotApplicable => "reconciled",
        };
        audit_log(&self.client_cn, &reservation.pubkey_hex, audit_outcome);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation};

    const PUBKEY: &str =
        "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";
    const GVR: Root = [1u8; 32];

    fn open_scoped() -> (Arc<SlashingDb>, PubkeyScopedDb) {
        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), GVR);
        (db, scoped)
    }

    #[test]
    fn test_stage_block_commit_succeeds() {
        let (_db, scoped) = open_scoped();
        let (staged, audit) = scoped
            .stage_block(PUBKEY, 100, Some("0xroot_ok".into()))
            .expect("stage_block must succeed");
        staged.commit().expect("commit must succeed");
        audit.emit();
    }

    #[test]
    fn test_stage_block_double_proposal_rejected() {
        let (_db, scoped) = open_scoped();

        let (staged, audit) =
            scoped.stage_block(PUBKEY, 200, Some("0xroot_1".into())).expect("first stage");
        staged.commit().expect("first commit");
        audit.emit();

        let err = scoped
            .stage_block(PUBKEY, 200, Some("0xroot_2".into()))
            .expect_err("double proposal must be rejected");

        assert!(
            matches!(
                err,
                SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                    slot: 200
                })
            ),
            "expected DoubleBlockProposal at slot 200, got: {err:?}"
        );
    }

    #[test]
    fn test_stage_block_discard_leaves_no_row() {
        let (db, scoped) = open_scoped();
        let (staged, audit) =
            scoped.stage_block(PUBKEY, 300, Some("0xroot".into())).expect("stage");
        staged.discard();
        audit.emit();
        assert!(db.get_blocks(PUBKEY).expect("get_blocks").is_empty());
    }

    #[test]
    fn test_stage_attestation_commit_succeeds() {
        let (_db, scoped) = open_scoped();
        let (staged, audit) = scoped
            .stage_attestation(PUBKEY, 5, 10, Some("0xatt_root".into()))
            .expect("stage_attestation must succeed");
        staged.commit().expect("commit must succeed");
        audit.emit();
    }

    #[test]
    fn test_stage_attestation_double_vote_rejected() {
        let (_db, scoped) = open_scoped();

        let (staged, audit) =
            scoped.stage_attestation(PUBKEY, 1, 5, Some("0xatt_1".into())).expect("first stage");
        staged.commit().expect("first commit");
        audit.emit();

        let err = scoped
            .stage_attestation(PUBKEY, 1, 5, Some("0xatt_2".into()))
            .expect_err("double vote must be rejected");

        assert!(
            matches!(
                err,
                SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                    target_epoch: 5
                })
            ),
            "expected DoubleVote at target_epoch 5, got: {err:?}"
        );
    }

    #[test]
    fn test_stage_attestation_discard_leaves_no_row() {
        let (db, scoped) = open_scoped();
        let (staged, audit) =
            scoped.stage_attestation(PUBKEY, 10, 20, Some("0xatt_root".into())).expect("stage");
        staged.discard();
        audit.emit();
        assert!(db.get_attestations(PUBKEY).expect("get_attestations").is_empty());
    }

    /// PubkeyScopedDb records rows with audit CN = "local-vc".
    #[test]
    fn test_audit_cn_is_local_vc() {
        use rusqlite::Connection;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit_cn.db");
        let db = Arc::new(SlashingDb::open(&path).expect("open file db"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), GVR);

        let (staged, audit) =
            scoped.stage_block(PUBKEY, 400, Some("0xaudit_root".into())).expect("stage");
        staged.commit().expect("commit");
        audit.emit();

        drop(scoped);
        drop(db);

        let conn = Connection::open(&path).expect("direct open");
        let cn: String = conn
            .query_row(
                "SELECT client_cn FROM blocks WHERE pubkey = ?1 AND slot = 400",
                [PUBKEY],
                |row| row.get(0),
            )
            .expect("block row must exist");

        assert_eq!(cn, "local-vc", "audit CN must be 'local-vc'");
    }

    /// PubkeyScopedDb with a non-local-vc CN emits audit_log with that CN.
    /// The row in the DB still gets AUDIT_ORIGIN ("local-vc") — the per-CN audit
    /// is in the tracing event only.
    #[test]
    fn test_audit_log_fires_on_stage_block() {
        // Install a no-op subscriber so the audit_log tracing call does not panic.
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "peer-dvt-1".to_string(), GVR);

        // Happy-path stage: PendingAudit must be emitted after commit (no panic).
        let (staged, audit) = scoped
            .stage_block(PUBKEY, 500, Some("0xaudit_fire_root".into()))
            .expect("stage must succeed");
        staged.commit().expect("commit must succeed");
        audit.emit();

        // Rejection path: audit_log must fire with outcome "rejected" (no panic).
        let _err = scoped
            .stage_block(PUBKEY, 500, Some("0xaudit_conflict_root".into()))
            .expect_err("double proposal must be rejected");
    }

    /// Same audit_log coverage for stage_attestation paths.
    #[test]
    fn test_audit_log_fires_on_stage_attestation() {
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "peer-dvt-2".to_string(), GVR);

        // Happy-path: emit "staged" after commit.
        let (staged, audit) = scoped
            .stage_attestation(PUBKEY, 3, 8, Some("0xatt_fire".into()))
            .expect("stage must succeed");
        staged.commit().expect("commit must succeed");
        audit.emit();

        // Rejection path: audit_log fires with "rejected".
        let _err = scoped
            .stage_attestation(PUBKEY, 3, 8, Some("0xatt_conflict".into()))
            .expect_err("double vote must be rejected");
    }

    /// GREEN: double proposal rejects and `"rejected"` is emitted with no guard held.
    ///
    /// Mirrors `audit_log_truncates_pubkey` (`audit.rs`) for capture style. Proves
    /// the Err path is fixed in-file: no staged guard exists when `audit_log` runs.
    #[tracing_test::traced_test]
    #[test]
    fn stage_block_rejection_emits_audit_without_holding_the_guard() {
        let (_db, scoped) = open_scoped();

        let (staged, audit) =
            scoped.stage_block(PUBKEY, 600, Some("0xfirst".into())).expect("first stage");
        staged.commit().expect("first commit");
        audit.emit();

        let err = scoped
            .stage_block(PUBKEY, 600, Some("0xsecond".into()))
            .expect_err("double proposal must be rejected");
        assert!(
            matches!(
                err,
                SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                    slot: 600
                })
            ),
            "expected DoubleBlockProposal, got {err:?}"
        );

        assert!(logs_contain("slashing audit"), "rejected audit event did not fire");
        assert!(logs_contain("rejected"), "outcome must be rejected");
    }
}
