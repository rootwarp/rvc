//! SQLite database layer for slashing protection.
//!
//! # Schema versions
//!
//! ## v1 (legacy)
//! Tables: `attestations`, `blocks`, `metadata`, `watermarks`.
//! Uniqueness: `(pubkey, target_epoch)` / `(pubkey, slot)`.
//!
//! ## v2 (current — ISSUE-1.2)
//! Added columns on `attestations` and `blocks`:
//! - `client_cn TEXT NOT NULL DEFAULT '__legacy__'` — per-client-CN namespace.
//!   Sentinel values: `'__legacy__'` for pre-migration rows; `'local-vc'` for VC-side
//!   runtime writes (`crates/signer`). DVT peers use their mTLS CN (ISSUE-1.7).
//! - `genesis_validators_root TEXT` — nullable; legacy rows = NULL.
//!
//! New uniqueness indexes: `(client_cn, pubkey, target_epoch)` / `(client_cn, pubkey, slot)`.
//! `metadata.schema_version = '2'` is set on every v2 open.
//!
//! Migration runs eagerly on `SlashingDb::open` and is idempotent.
//! A backup `<path>.bak.<UNIX_TS>` is written before any ALTER fires.
//!
//! # Module layout (E2)
//!
//! - [`open`] — connection open, preflight, pragmas, permissions
//! - [`migrations`] — schema v1→v2→v3
//! - [`records`] — attestation/block row CRUD and liveness queries
//! - [`interchange`] — EIP-3076 import/export and GVR metadata
//! - [`watermarks`] — `WatermarkKind` helpers plus set/get/prune API
//!
//! This file retains [`SlashingDb`], accessors, strict-semantics, Gloas
//! leniency gate, GVR cache, integrity check, and `check_and_record_*` rules
//! delegation.

mod interchange;
mod migrations;
mod open;
mod records;
pub mod watermarks;

use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

use rusqlite::Connection;

use crate::error::SlashingError;
use eth_types::{Epoch, Root, Slot};

/// Normalize a pubkey to lowercase with 0x prefix for consistent DB storage/lookup.
///
/// Delegates to [`observability::pubkey::CanonicalPubkey`] — the single source of
/// truth for pubkey normalisation across all crates (CQ-2.4 / C1).
///
/// `CanonicalPubkey::from_str` is [`Infallible`](std::convert::Infallible) by
/// design (normalisation, not validation). `Result` replaces `.expect`; hex
/// policy lives only on `SignedBlock::new` / `SignedAttestation::new`.
pub(crate) fn normalize_pubkey(
    pubkey: &str,
) -> Result<observability::pubkey::CanonicalPubkey, SlashingError> {
    match pubkey.parse::<observability::pubkey::CanonicalPubkey>() {
        Ok(pk) => Ok(pk),
        Err(never) => match never {},
    }
}

/// SQLite-backed database for storing slashing protection data.
pub struct SlashingDb {
    pub(crate) conn: Mutex<Connection>,
    path: Option<PathBuf>,
    pub(crate) strict_semantics: AtomicBool,
    /// Epoch at which FU-33 `None==None` leniency is disabled.
    ///
    /// `u64::MAX` is the far-future unscheduled sentinel (same value as
    /// [`eth_types::ForkSchedule::unscheduled_gloas`]): existing tests and
    /// pre-Gloas networks stay on `strict_semantics` alone.
    pub(crate) gloas_fork_epoch: AtomicU64,
    /// One-time cache for `metadata.genesis_validators_root`.
    ///
    /// `None` means "no GVR pinned in metadata" (backward-compat: skip the per-call check).
    /// `Some(root)` means the pinned value has been loaded and every caller-supplied `gvr`
    /// will be compared against it.
    ///
    /// Populated only once a real `Root` is read from the metadata row.  Absence (no row
    /// pinned yet) is **not** cached — otherwise an early signing call could permanently
    /// disable the chain-swap check for a process whose GVR is pinned later (e.g. when
    /// `import()` opens the DB before startup pins the GVR).  Reset never happens within a
    /// process lifetime
    /// because the metadata GVR is immutable once set.  A race between two threads both
    /// writing to the `OnceLock` is harmless: both writers compute the same value (they both
    /// read the same DB row), and `OnceLock::set` silently discards the losing write.
    gvr_cache: OnceLock<Root>,
    /// Logged-once flag: emit an `error!` warning the first time a signing-path entry
    /// observes "no GVR pinned in metadata" so operators can detect a degraded
    /// chain-swap-protection state.
    gvr_skip_warned: OnceLock<()>,
    /// Per-instance countdown of forced persist failures (`test-utils` only arms it).
    ///
    /// Scoped to this `SlashingDb` so parallel tests with separate in-memory DBs
    /// cannot steal each other's inject. Snapshotted into `Staged*` at `stage_*`;
    /// consumed inside `Staged*::commit` (snapshotted at `stage_*`), inside
    /// group-commit immediately before `COMMIT`, and inside
    /// `reconcile_unsigned` immediately before the compensating DELETE.
    pub(crate) fail_next_commits: AtomicU32,
    /// Group-commit knobs. Replaced at startup from operator config.
    pub(crate) group_commit: Mutex<crate::group_commit::GroupCommitConfig>,
    pub(crate) pending: Mutex<VecDeque<crate::group_commit::QueuedReserve>>,
    pub(crate) pending_cv: Condvar,
    /// Serialises the flusher so wait-to-fill does not hold `conn`.
    pub(crate) flush_lock: Mutex<()>,
    /// True while a flusher is responsible for the queue. Enqueue claims it;
    /// the flusher clears it under `pending` when the queue is empty.
    pub(crate) leader_active: AtomicBool,
    /// Test-only: block the next in-txn eval until the release sender fires.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) eval_gate:
        Mutex<Option<(std::sync::mpsc::SyncSender<()>, std::sync::mpsc::Receiver<()>)>>,
    /// Skip this many in-txn eval stalls before honouring `eval_gate`.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) eval_skip: AtomicU32,
}

impl SlashingDb {
    pub(crate) fn from_connection(conn: Connection, path: Option<PathBuf>) -> Self {
        Self {
            conn: Mutex::new(conn),
            path,
            strict_semantics: AtomicBool::new(false),
            gloas_fork_epoch: AtomicU64::new(u64::MAX),
            gvr_cache: OnceLock::new(),
            gvr_skip_warned: OnceLock::new(),
            fail_next_commits: AtomicU32::new(0),
            group_commit: Mutex::new(crate::group_commit::GroupCommitConfig::default()),
            pending: Mutex::new(VecDeque::new()),
            pending_cv: Condvar::new(),
            flush_lock: Mutex::new(()),
            leader_active: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-utils"))]
            eval_gate: Mutex::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            eval_skip: AtomicU32::new(0),
        }
    }
}

impl SlashingDb {
    /// Force the next `n` persist operations on **this** DB to fail:
    /// `Staged*::commit` (snapshotted at `stage_*`), group-commit `COMMIT`
    /// (consumed immediately before `COMMIT`), and `reconcile_unsigned`
    /// (consumed immediately before DELETE). Drop of a staged guard still rolls back.
    /// Per-instance — safe under parallel tests with separate
    /// `open_in_memory()` DBs.
    ///
    /// Arm this **after** a successful `reserve_*` to fail the compensating
    /// delete; otherwise `reserve_*` consumes the inject first.
    ///
    /// # Test-only
    ///
    /// Not on the production API. Gated by `cfg(test)` (this crate's unit
    /// tests) or the `test-utils` feature (other crates' `[dev-dependencies]`,
    /// and this crate's integration tests via the self-path `test-utils`
    /// dev-dep). Production binaries cannot arm the inject.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fail_next_commits(&self, n: u32) {
        self.fail_next_commits.store(n, Ordering::SeqCst);
    }

    /// Whether the connection mutex is free right now (`try_lock` succeeds).
    ///
    /// # Test-only
    ///
    /// Lets a tracing subscriber prove an audit event was emitted after the
    /// staged guard released the connection (ADR-006 / G-7 behavioural proof).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn try_lock_free(&self) -> bool {
        self.conn.try_lock().is_some()
    }

    /// Take one injected commit failure for this DB (used when building a staged guard).
    pub(crate) fn take_injected_commit_failure(&self) -> bool {
        loop {
            let cur = self.fail_next_commits.load(Ordering::SeqCst);
            if cur == 0 {
                return false;
            }
            if self
                .fail_next_commits
                .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }
}

impl SlashingDb {
    /// Enable or disable strict slashing semantics.
    ///
    /// When enabled, `None == None` signing roots at the same target epoch
    /// (or slot for blocks) are rejected as potential double votes/proposals.
    /// Default is `false` (lenient: treats `None == None` as a re-sign).
    ///
    /// Gloas epochs are strict regardless of this flag — see
    /// [`Self::set_gloas_fork_epoch`].
    pub fn set_strict_semantics(&self, strict: bool) {
        self.strict_semantics.store(strict, Ordering::Relaxed);
    }

    /// Set the Gloas fork epoch used by the FU-33 `None==None` leniency gate.
    ///
    /// `u64::MAX` is the unscheduled sentinel: every practical epoch stays
    /// on the operator [`Self::set_strict_semantics`] flag alone. At
    /// `target_epoch >= gloas_fork_epoch` (and the matching block-slot epoch)
    /// the lenient `(None, None)` arm is disabled even when `strict_semantics`
    /// is off.
    pub fn set_gloas_fork_epoch(&self, epoch: Epoch) {
        self.gloas_fork_epoch.store(epoch, Ordering::Relaxed);
    }

    /// Operator-strict **or** the candidate epoch is at/after Gloas.
    ///
    /// Two Gloas attestations for one slot share source/target and differ
    /// only in signing root (payload-status `data.index`). The lenient
    /// `(None, None)` arm would treat those as a re-sign.
    pub(crate) fn fork_aware_strict(&self, epoch: Epoch) -> bool {
        self.strict_semantics.load(Ordering::Relaxed)
            || epoch >= self.gloas_fork_epoch.load(Ordering::Relaxed)
    }

    // ── GVR per-call re-check helpers (M-6 / ISSUE-3.5) ─────────────────────

    /// Encode a `Root` ([u8; 32]) as a lowercase `0x`-prefixed hex string for DB storage.
    ///
    /// Uses [`eth_types::canonical::gvr_hex::GvrHex`] so metadata and row writes
    /// share one normalised representation (RF3-17).
    pub(crate) fn root_to_hex(root: &Root) -> String {
        eth_types::canonical::gvr_hex::GvrHex::from_root(*root).as_normalised_hex().to_string()
    }

    /// Return the metadata-pinned GVR, using the cache to avoid repeated DB reads.
    ///
    /// On the first call, reads from `metadata.genesis_validators_root` and populates
    /// the `gvr_cache`.  Subsequent calls return the cached value directly.
    ///
    /// Returns `Ok(None)` if no GVR is set in metadata (backward compat: the per-call
    /// check is skipped).  Returns `Ok(Some(root))` once GVR is pinned.
    ///
    /// Race safety: if two threads call this simultaneously on a cold cache, both read
    /// the same DB row and compute the same value.  `OnceLock::set` silently discards
    /// the losing write — both outcomes are identical.
    pub(crate) fn pinned_gvr(&self) -> Result<Option<Root>, SlashingError> {
        if let Some(cached) = self.gvr_cache.get() {
            return Ok(Some(*cached));
        }
        match self.read_metadata_gvr()? {
            Some(root) => {
                // Race-OK: if another thread wins the set, both wrote the same value.
                let _ = self.gvr_cache.set(root);
                Ok(Some(root))
            }
            None => {
                // Do NOT cache absence — the GVR may be pinned later (e.g. by
                // startup after an import() flow opened the DB).  Caching None
                // would permanently disable the chain-swap check.
                if self.gvr_skip_warned.set(()).is_ok() {
                    tracing::error!(
                        "genesis_validators_root not pinned in metadata; per-call \
                         chain-swap protection is disabled until set_genesis_validators_root \
                         is called.  This warning is emitted once per SlashingDb instance."
                    );
                }
                Ok(None)
            }
        }
    }

    /// Atomically check and record a block proposal.
    ///
    /// Thin convenience wrapper around [`Self::stage_block`] +
    /// [`crate::stage::StagedBlock::commit`]. All EIP-3076 rule evaluation lives
    /// in the stage path; this helper exists so test call sites can still
    /// express check-and-write as a single call.
    ///
    /// Transaction atomicity is identical to the production path: `stage_block`
    /// opens `BEGIN IMMEDIATE` and holds the connection mutex until `commit`
    /// (or `discard` / drop).
    ///
    /// # Arguments
    /// - `gvr`: Genesis validators root for this signing operation.  Compared
    ///   against `metadata.genesis_validators_root` (M-6 / ISSUE-3.5).
    ///   On mismatch, `Err(SlashingError::GenesisRootMismatch)` is returned.
    ///
    /// All rows carry [`crate::stage::AUDIT_ORIGIN`] (`"local-vc"`) in the
    /// `client_cn` column. Per-CN audit visibility is via [`crate::audit_log`]
    /// in [`crate::PubkeyScopedDb`].
    #[tracing::instrument(name = "slashing.db.block", skip_all, fields(slashing_result))]
    pub fn check_and_record_block(
        &self,
        pubkey: &str,
        slot: Slot,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        self.stage_block(pubkey, slot, signing_root, gvr)?.commit()
    }

    /// Atomically check and record an attestation.
    ///
    /// Thin convenience wrapper around [`Self::stage_attestation`] +
    /// [`crate::stage::StagedAttestation::commit`]. All EIP-3076 rule evaluation
    /// lives in the stage path; this helper exists so test call sites can still
    /// express check-and-write as a single call.
    ///
    /// Transaction atomicity is identical to the production path: `stage_attestation`
    /// opens `BEGIN IMMEDIATE` and holds the connection mutex until `commit`
    /// (or `discard` / drop).
    ///
    /// # Arguments
    /// - `gvr`: Genesis validators root for this signing operation.  Compared
    ///   against `metadata.genesis_validators_root` (M-6 / ISSUE-3.5).
    ///   On mismatch, `Err(SlashingError::GenesisRootMismatch)` is returned.
    ///
    /// All rows carry [`crate::stage::AUDIT_ORIGIN`] (`"local-vc"`) in the
    /// `client_cn` column. Per-CN audit visibility is via [`crate::audit_log`]
    /// in [`crate::PubkeyScopedDb`].
    ///
    /// ## Edge Case Decisions (FU-32, FU-33)
    ///
    /// **FU-32 (same root, different source):**
    /// Per EIP-3076, `signing_root` = `hash_tree_root(AttestationData)`. Since
    /// `AttestationData` includes `source_epoch`, identical roots imply identical
    /// source epochs. If source differs with same root, we log a warning
    /// (signing pipeline bug indicator) but allow the attestation. This is
    /// defense-in-depth only — the invariant violation is physically impossible
    /// under correct SSZ serialization. See EIP-3076 Condition 5.
    ///
    /// **FU-33 (None==None signing root):**
    /// EIP-3076 recommends treating null roots as "unknown" and assigning a
    /// suitable dummy root internally. With `strict_semantics = false`
    /// (default): `None==None` is treated as a re-sign for backward
    /// compatibility with pre-existing records that lack roots. With
    /// `strict_semantics = true`: `None==None` is rejected as a potential
    /// double vote, matching Lighthouse/Prysm/Teku conservative behavior.
    /// Gloas epochs (`target_epoch >= gloas_fork_epoch`) are always strict:
    /// payload-status `data.index` 0 vs 1 share source/target and would
    /// otherwise be deduplicated. See EIP-3076 §Conditions, note on
    /// `signing_root` handling.
    #[tracing::instrument(name = "slashing.db.attestation", skip_all, fields(slashing_result))]
    pub fn check_and_record_attestation(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        self.stage_attestation(pubkey, source_epoch, target_epoch, signing_root, gvr)?.commit()
    }

    /// Run SQLite `PRAGMA integrity_check` and return an error if the database is corrupt.
    pub fn check_integrity(&self) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(SlashingError::IntegrityCheckFailed(result));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation};
    use tempfile::tempdir;

    /// Zero GVR used as a test sentinel.  No GVR is pinned in metadata for these
    /// unit tests, so the M-6 per-call GVR check is skipped and this value is
    /// only written into the row's `genesis_validators_root` column.
    const TEST_GVR: Root = [0u8; 32];

    /// The `slashing.db.block`/`slashing.db.attestation` spans declare
    /// `slashing_result = field::Empty` and late-bind it via Span::record. This proves the
    /// renamed key lands (the declared field name MUST match the record key, or it vanishes).
    #[test]
    fn slashing_result_field_late_binds() {
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};
        use tracing::span::Record;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Default)]
        struct Cap(Arc<Mutex<Vec<String>>>);
        struct V<'a>(&'a mut Vec<String>);
        impl Visit for V<'_> {
            fn record_debug(&mut self, f: &Field, _v: &dyn std::fmt::Debug) {
                self.0.push(f.name().to_string());
            }
        }
        impl<S> Layer<S> for Cap
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_record(&self, _id: &tracing::Id, values: &Record<'_>, _ctx: Context<'_, S>) {
                if let Ok(mut keys) = self.0.lock() {
                    values.record(&mut V(&mut keys));
                }
            }
        }

        let cap = Cap::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span =
                tracing::info_span!("slashing.db.block", slashing_result = tracing::field::Empty);
            let _e = span.enter();
            tracing::Span::current().record("slashing_result", "blocked");
        });

        let recorded = cap.0.lock().unwrap();
        assert!(
            recorded.iter().any(|k| k == "slashing_result"),
            "late-bound slashing_result did not land: {recorded:?}"
        );
    }

    #[test]
    fn test_check_and_record_block_safe() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let result =
            db.check_and_record_block("0x1234", 1000, Some("0xroot1".to_string()), &[0u8; 32]);
        assert!(result.is_ok());

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xroot1"));
    }

    #[test]
    fn test_check_and_record_block_double_proposal_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block("0x1234", 1000, Some("0xroot1".to_string()), &[0u8; 32])
            .expect("first should succeed");

        let result =
            db.check_and_record_block("0x1234", 1000, Some("0xroot2".to_string()), &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
                assert_eq!(slot, 1000);
            }
            other => panic!("expected DoubleBlockProposal, got: {other:?}"),
        }

        // Verify no second record was inserted
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_check_and_record_block_idempotent_resign() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block("0x1234", 1000, Some("0xroot1".to_string()), &[0u8; 32])
            .expect("first should succeed");

        let result =
            db.check_and_record_block("0x1234", 1000, Some("0xroot1".to_string()), &[0u8; 32]);
        assert!(result.is_ok());

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_safe() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let result = db.check_and_record_attestation(
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
    }

    #[test]
    fn test_check_and_record_attestation_double_vote_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        let result = db.check_and_record_attestation(
            "0x1234",
            99,
            101,
            Some("0xroot2".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch,
            }) => {
                assert_eq!(target_epoch, 101);
            }
            other => panic!("expected DoubleVote, got: {other:?}"),
        }

        // Verify no second record was inserted
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_surrounding_vote_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("0x1234", 5, 10, None, &[0u8; 32])
            .expect("first should succeed");

        let result = db.check_and_record_attestation("0x1234", 4, 11, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(
                AttestationSlashingViolation::SurroundingVote { .. },
            ) => {}
            other => panic!("expected SurroundingVote, got: {other:?}"),
        }

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_idempotent_resign() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        // Same signing root for same epoch should pass (idempotent)
        let result = db.check_and_record_attestation(
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_same_root_same_source_no_warning() {
        // Same signing_root + same source_epoch + same target_epoch → no warning, no error
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("0x1234", 3, 5, Some("0xABC".to_string()), &[0u8; 32])
            .expect("first should succeed");

        // Re-sign with identical source, target, root → should succeed silently
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xABC".to_string()), &[0u8; 32]);
        assert!(result.is_ok());

        // Should not have inserted a duplicate
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_same_root_different_source_warns_but_allows() {
        // Same signing_root + same target_epoch but different source_epoch
        // → should log warning but still allow (defense-in-depth, not a rejection)
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("0x1234", 3, 5, Some("0xABC".to_string()), &[0u8; 32])
            .expect("first should succeed");

        // Same root but different source → indicates possible signing pipeline bug
        // Should still succeed (is_duplicate = true) but log a warning
        let result =
            db.check_and_record_attestation("0x1234", 4, 5, Some("0xABC".to_string()), &[0u8; 32]);
        assert!(result.is_ok(), "same root with different source must still be allowed");

        // Should not have inserted a duplicate
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_double_vote_rejection_unchanged() {
        // Different root + same target → must still be rejected as DoubleVote
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("0x1234", 3, 5, Some("0xABC".to_string()), &[0u8; 32])
            .expect("first should succeed");

        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xDEF".to_string()), &[0u8; 32]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("double vote"), "expected double vote error, got: {err}");
    }

    // ── FU-33 strict slashing semantics test matrix ──────────────────
    // 6 root combinations × 2 modes (lenient/strict) = 12 tests
    // Attestation tests:

    #[test]
    fn test_strict_att_some_same_lenient_allows() {
        // Some("0xA") vs Some("0xA"), lenient → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_some_same_strict_allows() {
        // Some("0xA") vs Some("0xA"), strict → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_some_diff_lenient_rejects() {
        // Some("0xA") vs Some("0xB"), lenient → reject (double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xB".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_diff_strict_rejects() {
        // Some("0xA") vs Some("0xB"), strict → reject (double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xB".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_none_lenient_rejects() {
        // Some("0xA") vs None, lenient → reject (different roots)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_none_strict_rejects() {
        // Some("0xA") vs None, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_some_lenient_rejects() {
        // None vs Some("0xA"), lenient → reject (different roots)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]).expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_some_strict_rejects() {
        // None vs Some("0xA"), strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]).expect("first");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_none_lenient_allows() {
        // None vs None, lenient (default) → allow (treat as re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_none_none_strict_rejects() {
        // None vs None, strict → reject (unknown root = potential double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_attestation("0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err(), "strict mode should reject None==None as potential double vote");
    }

    #[test]
    fn test_strict_att_no_existing_lenient_inserts() {
        // No existing record, lenient → insert
        let db = SlashingDb::open_in_memory().expect("open");
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    #[test]
    fn test_strict_att_no_existing_strict_inserts() {
        // No existing record, strict → insert
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        let result =
            db.check_and_record_attestation("0x1234", 3, 5, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    // Block proposal strict semantics tests (None==None case)

    #[test]
    fn test_strict_block_none_none_lenient_allows() {
        // None vs None block, lenient → allow
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_block("0x1234", 100, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("0x1234", 100, None, &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_block_none_none_strict_rejects() {
        // None vs None block, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("0x1234", 100, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("0x1234", 100, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode should reject None==None block as potential double proposal"
        );
    }

    #[test]
    fn test_strict_block_some_same_strict_allows() {
        // Some("0xA") vs Some("0xA") block, strict → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("0x1234", 100, Some("0xA".into()), &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("0x1234", 100, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_block_none_some_strict_rejects() {
        // None vs Some("0xA") block, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("0x1234", 100, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("0x1234", 100, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_and_record_block_concurrent_double_proposal() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("concurrent_block.db");
        let db = Arc::new(SlashingDb::open(&path).expect("failed to open db"));

        let db1 = Arc::clone(&db);
        let db2 = Arc::clone(&db);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);

        let handle1 = thread::spawn(move || {
            b1.wait();
            db1.check_and_record_block("0x1234", 1000, Some("0xroot1".to_string()), &[0u8; 32])
        });

        let handle2 = thread::spawn(move || {
            b2.wait();
            db2.check_and_record_block("0x1234", 1000, Some("0xroot2".to_string()), &[0u8; 32])
        });

        let r1 = handle1.join().expect("thread panicked");
        let r2 = handle2.join().expect("thread panicked");

        // Exactly one should succeed, one should fail
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one concurrent block proposal should succeed");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_concurrent_double_vote() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("concurrent_attestation.db");
        let db = Arc::new(SlashingDb::open(&path).expect("failed to open db"));

        let db1 = Arc::clone(&db);
        let db2 = Arc::clone(&db);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);

        let handle1 = thread::spawn(move || {
            b1.wait();
            db1.check_and_record_attestation(
                "0x1234",
                100,
                101,
                Some("0xroot1".to_string()),
                &[0u8; 32],
            )
        });

        let handle2 = thread::spawn(move || {
            b2.wait();
            db2.check_and_record_attestation(
                "0x1234",
                99,
                101,
                Some("0xroot2".to_string()),
                &[0u8; 32],
            )
        });

        let r1 = handle1.join().expect("thread panicked");
        let r2 = handle2.join().expect("thread panicked");

        // Exactly one should succeed, one should fail
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one concurrent attestation should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    // --- Startup integrity check tests ---

    #[test]
    fn test_integrity_check_clean_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.check_integrity();
        assert!(result.is_ok());
    }

    #[test]
    fn test_integrity_check_clean_file_db() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("integrity.db");
        let db = SlashingDb::open(&path).expect("failed to open db");
        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        let result = db.check_integrity();
        assert!(result.is_ok());
    }

    #[test]
    fn test_integrity_check_returns_error_variant() {
        let err = SlashingError::IntegrityCheckFailed("test failure".to_string());
        match err {
            SlashingError::IntegrityCheckFailed(msg) => assert_eq!(msg, "test failure"),
            _ => panic!("expected IntegrityCheckFailed"),
        }
    }
}

/// Living documentation tests for EIP-3076 edge case decisions.
///
/// These tests codify the rationale behind FU-32 and FU-33 slashing
/// protection decisions. Each test documents a specific edge case with
/// references to the relevant EIP-3076 section. Future developers
/// should read these tests to understand *why* the code behaves this way.
#[cfg(test)]
mod edge_case_tests {
    use super::*;
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation};
    use crate::types::{InterchangeFormat, InterchangeMetadata};

    const TEST_GVR: Root = [0u8; 32];

    // ── FU-32: Same signing_root but different source_epoch ──────────
    //
    // EIP-3076 defines signing_root as hash_tree_root(AttestationData).
    // AttestationData includes both source and target. Therefore, if two
    // attestations share the same signing_root, they MUST have identical
    // source_epoch, target_epoch, and beacon_block_root.
    //
    // If we ever see same root + different source, it indicates a bug in
    // the signing pipeline (e.g., incorrect root computation). We log a
    // warning but still allow the attestation because:
    //   1. The signing_root match means it's the same logical message.
    //   2. Rejecting would be overly strict — the validator already signed
    //      this exact data.
    //   3. The mismatch is physically impossible under correct SSZ, so
    //      rejection would only punish buggy-but-non-slashable clients.

    #[test]
    fn test_fu32_same_root_same_source_silent_pass() {
        // EIP-3076 Condition 5: re-signing the same attestation is safe.
        // When signing_root matches AND source matches, this is a genuine
        // idempotent re-sign. No warning, no rejection.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation("0xval", 10, 20, Some("0xdeadbeef".into()), &[0u8; 32])
            .expect("initial attestation");

        // Identical re-sign: same source, same target, same root
        let result =
            db.check_and_record_attestation("0xval", 10, 20, Some("0xdeadbeef".into()), &[0u8; 32]);
        assert!(result.is_ok(), "identical re-sign must be allowed silently");

        // Should not create a duplicate record
        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_fu32_same_root_different_source_warns_but_allows() {
        // EIP-3076 Condition 5 + FU-32 defense-in-depth:
        //
        // This scenario is physically impossible under correct SSZ because
        // signing_root = hash_tree_root(AttestationData) which includes
        // source_epoch. If it occurs, something is wrong in the signing
        // pipeline (e.g., root was copied from a different attestation).
        //
        // Decision: LOG WARNING but ALLOW the attestation.
        // Rationale: the root match proves it's the same data, so rejecting
        // would only hurt a client with a minor bookkeeping bug.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation("0xval", 10, 20, Some("0xdeadbeef".into()), &[0u8; 32])
            .expect("initial attestation");

        // Same root but source_epoch differs (10 → 15): warns internally
        let result =
            db.check_and_record_attestation("0xval", 15, 20, Some("0xdeadbeef".into()), &[0u8; 32]);
        assert!(
            result.is_ok(),
            "same root with different source must still be allowed (defense-in-depth warning only)"
        );

        // No duplicate inserted
        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    // ── FU-33: None==None signing root semantics ─────────────────────
    //
    // EIP-3076 notes that signing_root "can be missing for legacy records."
    // The spec recommends assigning a dummy root internally.
    //
    // Problem: if both the existing record and the new attestation have
    // None as signing_root, are they the same attestation (re-sign) or
    // different attestations (double vote)?
    //
    // We cannot know — hence the choice is a policy decision:
    //
    // - Lenient (default, strict_semantics=false): treat None==None as
    //   re-sign. This is safer for operators with legacy records that
    //   pre-date root recording. Avoids false-positive rejections.
    //
    // - Strict (strict_semantics=true): treat None==None as a potential
    //   double vote. This matches the conservative behavior of Lighthouse,
    //   Prysm, and Teku. Recommended for new deployments where all records
    //   should have roots.
    //
    // - Gloas (target_epoch >= gloas_fork_epoch): always strict, even when
    //   strict_semantics is off. Payload-status index 0 vs 1 share source/
    //   target; the lenient arm would treat missing roots as a re-sign.

    #[test]
    fn test_fu33_none_none_lenient_allows() {
        // Default (lenient) mode: None==None at same target is treated as
        // an idempotent re-sign. This preserves backward compatibility with
        // legacy slashing protection records that lack signing_root.
        //
        // EIP-3076 §Conditions: "If signing_root is not provided, the
        // implementation should treat it as 'unknown'."
        // Our lenient interpretation: unknown == unknown → same message.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation("0xval", 10, 20, None, &[0u8; 32])
            .expect("initial attestation without root");

        let result = db.check_and_record_attestation("0xval", 10, 20, None, &[0u8; 32]);
        assert!(result.is_ok(), "lenient mode: None==None must be allowed as re-sign");
    }

    #[test]
    fn test_fu33_none_none_strict_rejects() {
        // Strict mode: None==None at same target is rejected as a potential
        // double vote. Without a signing_root, we cannot prove the two
        // attestations contain the same data.
        //
        // EIP-3076 §Conditions: "If signing_root is not provided, the
        // implementation should treat it as 'unknown'."
        // Our strict interpretation: unknown == unknown → could be different
        // messages → reject to be safe.
        //
        // This matches Lighthouse/Prysm/Teku conservative behavior and is
        // recommended for new deployments where all attestations should
        // have signing_root populated.
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);

        db.check_and_record_attestation("0xval", 10, 20, None, &[0u8; 32])
            .expect("initial attestation without root");

        let result = db.check_and_record_attestation("0xval", 10, 20, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode: None==None must be rejected as potential double vote"
        );
    }

    #[test]
    fn test_fu33_none_vs_some_always_rejects() {
        // Regardless of strict/lenient mode, None vs Some (or Some vs None)
        // at the same target epoch is ALWAYS rejected as a double vote.
        //
        // Rationale: if one attestation has a known root and the other doesn't,
        // we cannot prove they are the same message. The safe choice is to
        // reject. This is unambiguous in EIP-3076 — different roots (including
        // the absence of one) at the same target = double vote.
        let db = SlashingDb::open_in_memory().expect("open");

        // Case 1: existing=Some, new=None
        db.check_and_record_attestation("0xval_a", 10, 20, Some("0xroot".into()), &[0u8; 32])
            .expect("initial with root");
        let result = db.check_and_record_attestation("0xval_a", 10, 20, None, &[0u8; 32]);
        assert!(result.is_err(), "Some vs None must always reject");

        // Case 2: existing=None, new=Some
        db.check_and_record_attestation("0xval_b", 10, 20, None, &[0u8; 32])
            .expect("initial without root");
        let result =
            db.check_and_record_attestation("0xval_b", 10, 20, Some("0xroot".into()), &[0u8; 32]);
        assert!(result.is_err(), "None vs Some must always reject");
    }

    #[test]
    fn test_fu33_strict_block_none_none_rejects() {
        // FU-33 strict semantics also applies to block proposals.
        //
        // EIP-3076 block signing_root = hash_tree_root(BeaconBlock).
        // Same policy: in strict mode, None==None at the same slot is
        // rejected because we cannot confirm it's the same block.
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);

        db.check_and_record_block("0xval", 500, None, &[0u8; 32])
            .expect("initial block without root");

        let result = db.check_and_record_block("0xval", 500, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode: None==None block must be rejected as potential double proposal"
        );
    }

    #[test]
    fn test_fu33_gloas_none_none_rejected_on_all_entry_points() {
        const GLOAS: Epoch = 100;
        const PRE: Epoch = 99;
        const GVR: Root = [0u8; 32];
        let slot = GLOAS * eth_types::SLOTS_PER_EPOCH;

        {
            let db = SlashingDb::open_in_memory().expect("open");
            db.set_gloas_fork_epoch(GLOAS);
            db.stage_attestation("0xstage_att", PRE, GLOAS, None, &GVR)
                .expect("first")
                .commit()
                .expect("commit");
            let err = db
                .stage_attestation("0xstage_att", PRE, GLOAS, None, &GVR)
                .expect_err("Gloas None==None must double-vote via stage_attestation");
            assert!(matches!(
                err,
                SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                    target_epoch: GLOAS
                })
            ));
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            db.set_gloas_fork_epoch(GLOAS);
            db.reserve_attestation("0xres_att", PRE, GLOAS, None, &GVR).expect("first");
            let err = db
                .reserve_attestation("0xres_att", PRE, GLOAS, None, &GVR)
                .expect_err("Gloas None==None must double-vote via reserve_attestation");
            assert!(matches!(
                err,
                SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                    target_epoch: GLOAS
                })
            ));
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            db.set_gloas_fork_epoch(GLOAS);
            db.stage_block("0xstage_blk", slot, None, &GVR)
                .expect("first")
                .commit()
                .expect("commit");
            let err = db
                .stage_block("0xstage_blk", slot, None, &GVR)
                .expect_err("Gloas None==None must double-propose via stage_block");
            assert!(matches!(
                err,
                SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { .. })
            ));
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            db.set_gloas_fork_epoch(GLOAS);
            db.reserve_block("0xres_blk", slot, None, &GVR).expect("first");
            let err = db
                .reserve_block("0xres_blk", slot, None, &GVR)
                .expect_err("Gloas None==None must double-propose via reserve_block");
            assert!(matches!(
                err,
                SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { .. })
            ));
        }
    }

    #[test]
    fn test_fu33_pre_gloas_none_none_still_lenient() {
        const GLOAS: Epoch = 100;
        const GVR: Root = [0u8; 32];
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_gloas_fork_epoch(GLOAS);
        db.check_and_record_attestation("0xpre", 1, 5, None, &GVR).expect("first");
        db.check_and_record_attestation("0xpre", 1, 5, None, &GVR)
            .expect("pre-Gloas None==None stays a re-sign");
        let pre_slot = 5 * eth_types::SLOTS_PER_EPOCH;
        db.check_and_record_block("0xpreb", pre_slot, None, &GVR).expect("first block");
        db.check_and_record_block("0xpreb", pre_slot, None, &GVR)
            .expect("pre-Gloas None==None block stays a re-sign");
    }

    #[test]
    fn test_fu33_sentinel_gloas_keeps_lenient_none_none() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("0xsent", 1, 5, None, &[0u8; 32]).expect("first");
        db.check_and_record_attestation("0xsent", 1, 5, None, &[0u8; 32])
            .expect("sentinel Gloas: None==None is still a re-sign");
        {
            let conn = db.conn.lock();
            assert_eq!(
                super::migrations::read_schema_version(&conn).unwrap(),
                Some(3),
                "FU-33 gate must not add a schema migration"
            );
        }
    }

    // LOW-13: Validate interchange_format_version on import
    #[test]
    fn test_import_rejects_wrong_interchange_version() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr = [0xabu8; 32];
        let gvr_hex = format!("0x{}", hex::encode(gvr));
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "4".to_string(),
                genesis_validators_root: gvr_hex,
            },
            data: vec![],
        };
        let err = db.import(&interchange, &gvr).unwrap_err();
        assert!(err.to_string().contains("unsupported interchange_format_version"));
        assert!(err.to_string().contains("\"4\""));
    }

    #[test]
    fn test_import_accepts_version_5() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr = [0xabu8; 32];
        let gvr_hex = format!("0x{}", hex::encode(gvr));
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: gvr_hex,
            },
            data: vec![],
        };
        assert!(db.import(&interchange, &gvr).is_ok());
    }

    // LOW-14: Normalize pubkeys
    #[test]
    fn test_pubkey_normalization_case_insensitive() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.seed_attestation("0xABCD", 1, 2, None, &TEST_GVR).expect("insert");
        let results = db.get_attestations("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_pubkey_normalization_adds_prefix() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.seed_block("ABCD", 100, None, &TEST_GVR).expect("insert");
        let results = db.get_blocks("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_pubkey_normalization_already_normalized() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.seed_block("0xabcd", 100, None, &TEST_GVR).expect("insert");
        let results = db.get_blocks("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    // LOW-15: Transactional set_block_watermark
    #[test]
    fn test_set_block_watermark_is_transactional() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_block_watermark("0xval", 100).expect("set");
        assert_eq!(db.get_block_watermark("0xval").expect("get"), Some(100));
        db.set_block_watermark("0xval", 200).expect("raise");
        assert_eq!(db.get_block_watermark("0xval").expect("get"), Some(200));
    }

    // Finding #16: Epoch 0 / Slot 0 slashing protection boundary tests

    #[test]
    fn test_attestation_at_epoch_zero() {
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation("0xval", 0, 0, Some("0xroot_a".into()), &[0u8; 32])
            .expect("first attestation at epoch 0");

        let result =
            db.check_and_record_attestation("0xval", 0, 0, Some("0xroot_b".into()), &[0u8; 32]);
        assert!(result.is_err(), "double vote at target epoch 0 must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch,
            }) => {
                assert_eq!(target_epoch, 0);
            }
            other => panic!("expected DoubleVote at epoch 0, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_surround_vote_at_epoch_zero_boundary() {
        let db = SlashingDb::open_in_memory().expect("open");

        // Wide attestation: source=0, target=2
        db.check_and_record_attestation("0xval", 0, 2, Some("0xroot_wide".into()), &[0u8; 32])
            .expect("wide attestation at epoch 0 boundary");

        // Narrow attestation: source=1, target=1 — surrounded by (0,2)
        // existing_source(0) < new_source(1) AND existing_target(2) > new_target(1)
        let result = db.check_and_record_attestation(
            "0xval",
            1,
            1,
            Some("0xroot_narrow".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "surrounded vote at epoch 0 boundary must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundedVote {
                ..
            }) => {}
            other => panic!("expected SurroundedVote, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_block_proposal_at_slot_zero() {
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_block("0xval", 0, Some("0xblock_a".into()), &[0u8; 32])
            .expect("first block at slot 0");

        let result = db.check_and_record_block("0xval", 0, Some("0xblock_b".into()), &[0u8; 32]);
        assert!(result.is_err(), "double proposal at slot 0 must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
                assert_eq!(slot, 0);
            }
            other => panic!("expected DoubleBlockProposal at slot 0, got: {other:?}"),
        }

        assert_eq!(db.get_blocks("0xval").unwrap().len(), 1);
    }

    // Finding #30: Surrounded vote test at check_and_record level

    #[test]
    fn test_surrounded_vote_at_check_and_record_level() {
        let db = SlashingDb::open_in_memory().expect("open");

        // Wide attestation: source=2, target=10
        db.check_and_record_attestation("0xval", 2, 10, Some("0xroot_wide".into()), &[0u8; 32])
            .expect("wide attestation");

        // Narrow attestation: source=5, target=7 — surrounded by (2,10)
        // existing_source(2) < new_source(5) AND existing_target(10) > new_target(7)
        let result = db.check_and_record_attestation(
            "0xval",
            5,
            7,
            Some("0xroot_narrow".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "surrounded vote must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundedVote {
                ..
            }) => {}
            other => panic!("expected SurroundedVote, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    /// Post-2.5 invariant: every new row written by `check_and_record_block`,
    /// `check_and_record_attestation`, AND the `PubkeyScopedDb`/`stage_*` path
    /// carries `AUDIT_ORIGIN` (`"local-vc"`) in the `client_cn` column.
    ///
    /// This pins the guarantee that the DB column is always canonical, so a future
    /// reader querying `SELECT client_cn …` sees a predictable value.
    #[test]
    fn test_new_rows_store_audit_origin() {
        use rusqlite::Connection;
        use tempfile::tempdir;

        const PUBKEY_BLOCK: &str =
            "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";
        const PUBKEY_ATT: &str =
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        const GVR: [u8; 32] = [0u8; 32];

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit_origin.db");
        let db = SlashingDb::open(&path).expect("open file db");

        // check_and_record_block: row must carry AUDIT_ORIGIN.
        db.check_and_record_block(PUBKEY_BLOCK, 500, Some("0xblockroot".to_string()), &GVR)
            .expect("check_and_record_block must succeed");

        // check_and_record_attestation: same invariant.
        db.check_and_record_attestation(PUBKEY_ATT, 10, 20, Some("0xattroot".to_string()), &GVR)
            .expect("check_and_record_attestation must succeed");

        // stage_block via PubkeyScopedDb (the RAII path).
        {
            use crate::PubkeyScopedDb;
            use std::sync::Arc;
            let db_arc = Arc::new(SlashingDb::open(&path).expect("open for scoped"));
            let scoped = PubkeyScopedDb::new(Arc::clone(&db_arc), "peer-dvt-x".to_string(), GVR);
            let (staged, audit) = scoped
                .stage_block(PUBKEY_BLOCK, 501, Some("0xscopedroot".to_string()))
                .expect("scoped stage_block must succeed");
            staged.commit().expect("commit");
            audit.emit();
        }

        drop(db);

        // Inspect the rows directly to confirm all client_cn values = AUDIT_ORIGIN.
        let conn = Connection::open(&path).expect("direct open");

        let block_cns: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT client_cn FROM blocks ORDER BY slot").expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect")
        };

        assert!(
            block_cns.iter().all(|cn| cn == crate::stage::AUDIT_ORIGIN),
            "all block rows must carry AUDIT_ORIGIN; got: {block_cns:?}"
        );

        let att_cns: Vec<String> = {
            let mut stmt = conn.prepare("SELECT client_cn FROM attestations").expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect")
        };

        assert!(
            att_cns.iter().all(|cn| cn == crate::stage::AUDIT_ORIGIN),
            "all attestation rows must carry AUDIT_ORIGIN; got: {att_cns:?}"
        );
    }

    // ── RF2-10: check_and_record_* is a thin stage+commit wrapper ────────────

    /// Equivalence matrix: `check_and_record_*` and `stage_* → commit` must
    /// produce the same accept/reject decision and the same final rows on a
    /// representative set of EIP-3076 cases.
    #[test]
    fn test_check_and_record_matches_stage_commit_matrix() {
        let gvr = [0u8; 32];
        let pk = "0xrf210_eq";

        // Case: first block accepted via both paths on independent DBs.
        {
            let via_wrapper = open_in_memory();
            let via_stage = open_in_memory();
            via_wrapper
                .check_and_record_block(pk, 10, Some("0xroot_a".into()), &gvr)
                .expect("wrapper accept");
            via_stage
                .stage_block(pk, 10, Some("0xroot_a".into()), &gvr)
                .expect("stage accept")
                .commit()
                .expect("commit");
            assert_eq!(via_wrapper.get_blocks(pk).unwrap(), via_stage.get_blocks(pk).unwrap());
        }

        // Case: double proposal rejected with the same error variant.
        {
            let via_wrapper = open_in_memory();
            let via_stage = open_in_memory();
            via_wrapper
                .check_and_record_block(pk, 20, Some("0xroot_a".into()), &gvr)
                .expect("seed");
            via_stage
                .stage_block(pk, 20, Some("0xroot_a".into()), &gvr)
                .expect("seed stage")
                .commit()
                .expect("seed commit");

            let w_err = via_wrapper
                .check_and_record_block(pk, 20, Some("0xroot_b".into()), &gvr)
                .expect_err("wrapper reject");
            let s_err = via_stage
                .stage_block(pk, 20, Some("0xroot_b".into()), &gvr)
                .expect_err("stage reject");
            assert!(matches!(
                (&w_err, &s_err),
                (
                    crate::error::SlashingError::SlashableBlock(
                        BlockSlashingViolation::DoubleBlockProposal { slot: 20 }
                    ),
                    crate::error::SlashingError::SlashableBlock(
                        BlockSlashingViolation::DoubleBlockProposal { slot: 20 }
                    )
                )
            ));
        }

        // Case: first attestation accepted; surrounding vote rejected.
        {
            let via_wrapper = open_in_memory();
            let via_stage = open_in_memory();
            via_wrapper
                .check_and_record_attestation(pk, 5, 10, Some("0xatt_a".into()), &gvr)
                .expect("wrapper att");
            via_stage
                .stage_attestation(pk, 5, 10, Some("0xatt_a".into()), &gvr)
                .expect("stage att")
                .commit()
                .expect("commit");
            assert_eq!(
                via_wrapper.get_attestations(pk).unwrap(),
                via_stage.get_attestations(pk).unwrap()
            );

            let w_err = via_wrapper
                .check_and_record_attestation(pk, 4, 11, Some("0xatt_surr".into()), &gvr)
                .expect_err("wrapper surround reject");
            let s_err = via_stage
                .stage_attestation(pk, 4, 11, Some("0xatt_surr".into()), &gvr)
                .expect_err("stage surround reject");
            assert!(matches!(
                (&w_err, &s_err),
                (
                    crate::error::SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::SurroundingVote { .. }
                    ),
                    crate::error::SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::SurroundingVote { .. }
                    )
                )
            ));
        }

        // Case: idempotent re-sign accepted on both paths (no second row).
        {
            let via_wrapper = open_in_memory();
            let via_stage = open_in_memory();
            let root = Some("0xsame".into());
            via_wrapper.check_and_record_block(pk, 30, root.clone(), &gvr).expect("first");
            via_wrapper.check_and_record_block(pk, 30, root.clone(), &gvr).expect("resign wrapper");
            via_stage
                .stage_block(pk, 30, root.clone(), &gvr)
                .expect("first stage")
                .commit()
                .expect("c1");
            via_stage.stage_block(pk, 30, root, &gvr).expect("resign stage").commit().expect("c2");
            assert_eq!(via_wrapper.get_blocks(pk).unwrap().len(), 1);
            assert_eq!(via_stage.get_blocks(pk).unwrap().len(), 1);
        }
    }

    /// RF2-10 atomicity: concurrent conflicting `check_and_record_block` calls
    /// still serialise under a single `BEGIN IMMEDIATE` window — exactly one
    /// succeeds, one row is written. (Production stage path inherits the same
    /// lock; this pins the wrapper still exercises that guarantee.)
    #[test]
    fn test_check_and_record_block_wrapper_atomicity_under_concurrency() {
        use std::sync::Arc;
        use std::thread;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rf2_10_atomic.db");
        let db = Arc::new(SlashingDb::open(&path).expect("open"));

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [Some("0xroot1".to_string()), Some("0xroot2".to_string())]
            .into_iter()
            .map(|root| {
                let db = Arc::clone(&db);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    db.check_and_record_block("0xrf210_atomic", 777, root, &[0u8; 32])
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().expect("join")).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "exactly one concurrent wrapper write must succeed");
        assert_eq!(db.get_blocks("0xrf210_atomic").unwrap().len(), 1);
    }

    fn open_in_memory() -> SlashingDb {
        SlashingDb::open_in_memory().expect("open in-memory")
    }
}
