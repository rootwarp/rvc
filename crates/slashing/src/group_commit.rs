//! Group commit for `reserve_*`.
//!
//! One `BEGIN IMMEDIATE` → per-member rule check + INSERT → one `COMMIT`
//! (one fsync), then every member is released to sign. Commit-before-sign is
//! unchanged: a signature is never returned until its row is durably
//! committed.
//!
//! A slashable rule-check rejects only that member. A failed `COMMIT` rejects
//! members that would have been inserted; a member already rejected as
//! slashable keeps that error. A waiter that drops before insert is skipped
//! so it cannot stall the others.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension};

use crate::db::watermarks::{read_watermark, WatermarkKind};
use crate::error::SlashingError;
use crate::history::{TargetedSqlAttestationHistory, TargetedSqlBlockHistory};
use crate::rules::{
    check_attestation, check_block, AttestationCandidate, AttestationVerdict,
    AttestationWatermarks, BlockCandidate, BlockVerdict, BlockWatermarks,
};
use crate::stage::{
    persist_reserved_row, with_immediate_txn, CommittedReservation, ReservationKind, AUDIT_ORIGIN,
};
use crate::SlashingDb;
use eth_types::{Epoch, Root, Slot, SLOTS_PER_EPOCH};

/// Operator knobs for slashing-DB group commit.
///
/// Defaults are sized from the measured fsync quantum (~4.5 ms): a batch of 50
/// puts queued reserve-tx p99 near `200 / 50 × 4.5 ≈ 18 ms` at 200 keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCommitConfig {
    /// Max members in one `BEGIN IMMEDIATE … COMMIT`. Values below 1 are
    /// treated as 1 (no grouping).
    pub batch_size: usize,
    /// Wait for a partial batch to fill before committing. Zero disables the
    /// wait and drains whatever is already queued.
    pub wait_to_fill: Duration,
}

/// Invalid operator knobs for [`GroupCommitConfig::try_from_knobs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCommitConfigError {
    message: &'static str,
}

impl GroupCommitConfigError {
    /// Operator-facing reason.
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for GroupCommitConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for GroupCommitConfigError {}

impl GroupCommitConfig {
    /// Measured-quantum default.
    pub const DEFAULT_BATCH_SIZE: usize = 50;
    /// Milliseconds matching [`Self::DEFAULT_WAIT_TO_FILL`].
    pub const DEFAULT_WAIT_TO_FILL_MS: u64 = 1;
    /// Cap on wait-to-fill (one attestation window).
    pub const MAX_WAIT_TO_FILL_MS: u64 = 3999;

    /// Default wait-to-fill. Concurrent waves fill the batch before this
    /// elapses; sparse traffic pays one extra millisecond per commit.
    pub const DEFAULT_WAIT_TO_FILL: Duration = Duration::from_millis(Self::DEFAULT_WAIT_TO_FILL_MS);

    /// Overlay optional operator knobs onto the measured defaults.
    ///
    /// Rejects `batch_size == 0` and `wait_to_fill_ms > 3999`. Both binaries
    /// apply this gate at DB open.
    pub fn try_from_knobs(
        batch_size: Option<usize>,
        wait_to_fill_ms: Option<u64>,
    ) -> Result<Self, GroupCommitConfigError> {
        if matches!(batch_size, Some(0)) {
            return Err(GroupCommitConfigError {
                message: "group-commit batch_size must be greater than 0",
            });
        }
        if wait_to_fill_ms.is_some_and(|ms| ms > Self::MAX_WAIT_TO_FILL_MS) {
            return Err(GroupCommitConfigError {
                message: "group-commit wait_to_fill_ms must be at most 3999 (attestation window)",
            });
        }
        Ok(Self {
            batch_size: batch_size.unwrap_or(Self::DEFAULT_BATCH_SIZE),
            wait_to_fill: Duration::from_millis(
                wait_to_fill_ms.unwrap_or(Self::DEFAULT_WAIT_TO_FILL_MS),
            ),
        }
        .sanitized())
    }

    /// Overlay knobs, clamping illegal values. Prefer [`Self::try_from_knobs`]
    /// at process startup so operators see a hard error.
    pub fn from_knobs(batch_size: Option<usize>, wait_to_fill_ms: Option<u64>) -> Self {
        Self::try_from_knobs(batch_size, wait_to_fill_ms).unwrap_or_else(|_| Self {
            batch_size: batch_size.unwrap_or(Self::DEFAULT_BATCH_SIZE).max(1),
            wait_to_fill: Duration::from_millis(
                wait_to_fill_ms
                    .unwrap_or(Self::DEFAULT_WAIT_TO_FILL_MS)
                    .min(Self::MAX_WAIT_TO_FILL_MS),
            ),
        })
    }

    fn sanitized(self) -> Self {
        Self {
            batch_size: self.batch_size.max(1),
            wait_to_fill: self.wait_to_fill.min(Duration::from_millis(Self::MAX_WAIT_TO_FILL_MS)),
        }
    }
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self { batch_size: Self::DEFAULT_BATCH_SIZE, wait_to_fill: Self::DEFAULT_WAIT_TO_FILL }
    }
}

pub(crate) enum ReserveSpec {
    Block {
        pubkey: String,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: Root,
        gvr_hex: String,
    },
    Attestation {
        pubkey: String,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
        gvr: Root,
        gvr_hex: String,
    },
}

impl ReserveSpec {
    fn gvr(&self) -> Root {
        match self {
            Self::Block { gvr, .. } | Self::Attestation { gvr, .. } => *gvr,
        }
    }

    fn gvr_hex(&self) -> &str {
        match self {
            Self::Block { gvr_hex, .. } | Self::Attestation { gvr_hex, .. } => gvr_hex,
        }
    }
}

pub(crate) struct QueuedReserve {
    spec: ReserveSpec,
    tx: SyncSender<Result<CommittedReservation, SlashingError>>,
    cancelled: Arc<AtomicBool>,
}

struct ReserveWait {
    rx: Receiver<Result<CommittedReservation, SlashingError>>,
    cancelled: Arc<AtomicBool>,
}

impl ReserveWait {
    fn arm(
        rx: Receiver<Result<CommittedReservation, SlashingError>>,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        // Live waiter: INSERT is allowed until Drop.
        cancelled.store(false, Ordering::SeqCst);
        Self { rx, cancelled }
    }

    fn recv(self) -> Result<CommittedReservation, SlashingError> {
        match self.rx.recv() {
            Ok(r) => r,
            Err(_) => Err(SlashingError::ReserveCommitFailed(
                "group-commit worker disconnected before commit".into(),
            )),
        }
    }
}

impl Drop for ReserveWait {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

/// Droppable waiter used to prove cancel-during-eval skips INSERT.
#[cfg(any(test, feature = "test-utils"))]
pub struct CancellableReserve {
    rx: Option<Receiver<Result<CommittedReservation, SlashingError>>>,
    cancelled: Arc<AtomicBool>,
}

#[cfg(any(test, feature = "test-utils"))]
impl CancellableReserve {
    /// Allow INSERT until this handle is dropped.
    pub fn arm(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    /// Wait for this member's group-commit result.
    pub fn recv(mut self) -> Result<CommittedReservation, SlashingError> {
        self.arm();
        let rx = self.rx.take().ok_or_else(|| {
            SlashingError::ReserveCommitFailed("cancellable reserve already taken".into())
        })?;
        match rx.recv() {
            Ok(r) => r,
            Err(_) => Err(SlashingError::ReserveCommitFailed(
                "group-commit worker disconnected before commit".into(),
            )),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Drop for CancellableReserve {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.rx.take();
    }
}

impl SlashingDb {
    /// Replace the group-commit knobs. Intended for startup overlay and tests.
    pub fn set_group_commit(&self, config: GroupCommitConfig) {
        *self.group_commit.lock() = config.sanitized();
    }

    /// Snapshot of the knobs currently in force.
    pub fn group_commit_config(&self) -> GroupCommitConfig {
        *self.group_commit.lock()
    }

    pub(crate) fn reserve_block_grouped(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<CommittedReservation, SlashingError> {
        self.check_gvr_before_lock(gvr, "reserve_block")?;
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let spec = ReserveSpec::Block {
            pubkey: pubkey.to_string(),
            slot,
            signing_root_hex,
            gvr: *gvr,
            gvr_hex: crate::db::SlashingDb::root_to_hex(gvr),
        };
        self.enqueue_and_wait(spec)
    }

    pub(crate) fn reserve_attestation_grouped(
        &self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<CommittedReservation, SlashingError> {
        self.check_gvr_before_lock(gvr, "reserve_attestation")?;
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let spec = ReserveSpec::Attestation {
            pubkey: pubkey.to_string(),
            source_epoch,
            target_epoch,
            signing_root_hex,
            gvr: *gvr,
            gvr_hex: crate::db::SlashingDb::root_to_hex(gvr),
        };
        self.enqueue_and_wait(spec)
    }

    /// Enqueue a block reserve whose waiter is already gone. Used to prove a
    /// cancelled member cannot stall the rest of the batch.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn enqueue_and_abandon_block(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        self.check_gvr_before_lock(gvr, "reserve_block")?;
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let (tx, rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(true));
        self.push_pending(
            QueuedReserve {
                spec: ReserveSpec::Block {
                    pubkey: pubkey.to_string(),
                    slot,
                    signing_root_hex,
                    gvr: *gvr,
                    gvr_hex: crate::db::SlashingDb::root_to_hex(gvr),
                },
                tx,
                cancelled,
            },
            false,
        );
        drop(rx);
        Ok(())
    }

    /// Enqueue a live-cancellable block reserve. Starts cancelled; call
    /// [`CancellableReserve::arm`] to allow INSERT, then drop to cancel.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn enqueue_block_cancellable(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        gvr: &Root,
    ) -> Result<CancellableReserve, SlashingError> {
        self.check_gvr_before_lock(gvr, "reserve_block")?;
        let pubkey = crate::db::normalize_pubkey(pubkey_hex)?;
        let (tx, rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(true));
        self.push_pending(
            QueuedReserve {
                spec: ReserveSpec::Block {
                    pubkey: pubkey.to_string(),
                    slot,
                    signing_root_hex,
                    gvr: *gvr,
                    gvr_hex: crate::db::SlashingDb::root_to_hex(gvr),
                },
                tx,
                cancelled: Arc::clone(&cancelled),
            },
            false,
        );
        Ok(CancellableReserve { rx: Some(rx), cancelled })
    }

    /// Stall the next in-txn eval until the returned sender is dropped/sent.
    /// The receiver fires once eval has entered the stall.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn block_next_eval(&self) -> (Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        *self.eval_gate.lock() = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    /// Honour [`Self::block_next_eval`] only after `n` in-txn evals have passed.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn skip_eval_gates(&self, n: u32) {
        self.eval_skip.store(n, Ordering::SeqCst);
    }

    fn check_gvr_before_lock(&self, gvr: &Root, op: &str) -> Result<(), SlashingError> {
        // Must not wait on the connection mutex (nested-lock / GVR test).
        if let Some(pinned) = self.pinned_gvr()? {
            if pinned != *gvr {
                tracing::error!(
                    rejection_reason = "genesis_root_mismatch",
                    op,
                    "reserve rejected: genesis root mismatch"
                );
                return Err(SlashingError::GenesisRootMismatch { expected: pinned, got: *gvr });
            }
        }
        Ok(())
    }

    fn push_pending(&self, item: QueuedReserve, claim_leader: bool) -> bool {
        let mut q = self.pending.lock();
        q.push_back(item);
        self.pending_cv.notify_one();
        if claim_leader {
            !self.leader_active.swap(true, Ordering::SeqCst)
        } else {
            false
        }
    }

    fn enqueue_and_wait(&self, spec: ReserveSpec) -> Result<CommittedReservation, SlashingError> {
        let (tx, rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(true));
        let become_leader =
            self.push_pending(QueuedReserve { spec, tx, cancelled: Arc::clone(&cancelled) }, true);
        let wait = ReserveWait::arm(rx, cancelled);
        if become_leader {
            self.lead_flush();
        }
        wait.recv()
    }

    fn lead_flush(&self) {
        let _guard = self.flush_lock.lock();
        loop {
            let batch = self.drain_batch();
            if !batch.is_empty() {
                self.commit_batch(batch);
                continue;
            }
            let q = self.pending.lock();
            if q.is_empty() {
                self.leader_active.store(false, Ordering::SeqCst);
                return;
            }
        }
    }

    fn drain_batch(&self) -> Vec<QueuedReserve> {
        let cfg = *self.group_commit.lock();
        let mut q = self.pending.lock();
        if q.is_empty() {
            return Vec::new();
        }
        let batch_size = cfg.batch_size.max(1);
        if q.len() < batch_size && !cfg.wait_to_fill.is_zero() {
            let deadline = Instant::now() + cfg.wait_to_fill;
            while q.len() < batch_size {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                if self.pending_cv.wait_for(&mut q, remaining).timed_out() {
                    break;
                }
            }
        }
        let n = q.len().min(batch_size);
        q.drain(..n).collect()
    }

    fn commit_batch(&self, batch: Vec<QueuedReserve>) {
        if batch.is_empty() {
            return;
        }

        let txn_result = {
            let conn = self.conn.lock();
            with_immediate_txn(&conn, |conn| {
                let mut outcomes: Vec<Option<Result<CommittedReservation, SlashingError>>> =
                    Vec::with_capacity(batch.len());
                let mut persist_err: Option<SlashingError> = None;
                for item in &batch {
                    if persist_err.is_some() {
                        outcomes.push(None);
                        continue;
                    }
                    if item.cancelled.load(Ordering::SeqCst) {
                        outcomes.push(None);
                        continue;
                    }
                    match check_spec_in_txn(self, conn, &item.spec) {
                        Ok(res) => {
                            // Claim immediately before INSERT so a drop during
                            // the rule-check skips the write.
                            if item.cancelled.swap(true, Ordering::SeqCst) {
                                outcomes.push(None);
                                continue;
                            }
                            match gvr_mismatch_on_conn(conn, &item.spec) {
                                Err(e) if e.is_group_member_rejection() => {
                                    outcomes.push(Some(Err(e)));
                                    continue;
                                }
                                Err(e) => {
                                    persist_err = Some(e);
                                    outcomes.push(None);
                                    continue;
                                }
                                Ok(()) => {}
                            }
                            if let Err(e) = insert_spec(conn, &item.spec, &res) {
                                persist_err = Some(e);
                                outcomes.push(None);
                                continue;
                            }
                            outcomes.push(Some(Ok(res)));
                        }
                        Err(e) if e.is_group_member_rejection() => {
                            outcomes.push(Some(Err(e)));
                        }
                        Err(e) => {
                            persist_err = Some(e);
                            outcomes.push(None);
                        }
                    }
                }

                let any_ok = outcomes.iter().any(|o| matches!(o, Some(Ok(_))));
                if persist_err.is_none() && any_ok {
                    if let Err(e) = persist_reserved_row(self, conn, || Ok(())) {
                        persist_err = Some(e);
                        let _ = conn.execute_batch("ROLLBACK");
                    }
                } else {
                    conn.execute_batch("ROLLBACK")?;
                }
                Ok((outcomes, persist_err))
            })
        };

        match txn_result {
            Ok((outcomes, persist_err)) => {
                dispatch_outcomes(batch, outcomes, persist_err);
            }
            Err(e) => {
                dispatch_outcomes(batch, Vec::new(), Some(e));
            }
        }
    }
}

fn commit_failed_err(err: &SlashingError) -> SlashingError {
    match err {
        SlashingError::ReserveCommitFailed(msg) => SlashingError::ReserveCommitFailed(msg.clone()),
        other => SlashingError::ReserveCommitFailed(other.to_string()),
    }
}

fn dispatch_outcomes(
    batch: Vec<QueuedReserve>,
    mut outcomes: Vec<Option<Result<CommittedReservation, SlashingError>>>,
    persist_err: Option<SlashingError>,
) {
    while outcomes.len() < batch.len() {
        outcomes.push(None);
    }
    for (item, outcome) in batch.into_iter().zip(outcomes) {
        match (outcome, persist_err.as_ref()) {
            (Some(Err(e)), _) => {
                let _ = item.tx.send(Err(e));
            }
            (Some(Ok(res)), None) => {
                let _ = item.tx.send(Ok(res));
            }
            (Some(Ok(_)), Some(err)) | (None, Some(err)) => {
                let _ = item.tx.send(Err(commit_failed_err(err)));
            }
            (None, None) => {}
        }
    }
}

fn wait_eval_gate(_db: &SlashingDb) {
    #[cfg(any(test, feature = "test-utils"))]
    {
        loop {
            let n = _db.eval_skip.load(Ordering::SeqCst);
            if n == 0 {
                break;
            }
            if _db.eval_skip.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok()
            {
                return;
            }
        }
        if let Some((entered, release)) = _db.eval_gate.lock().take() {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }
}

fn gvr_mismatch_on_conn(conn: &Connection, spec: &ReserveSpec) -> Result<(), SlashingError> {
    let pinned_hex: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key = 'genesis_validators_root'", [], |row| {
            row.get(0)
        })
        .optional()?;
    let Some(pinned_hex) = pinned_hex else {
        return Ok(());
    };
    if pinned_hex == spec.gvr_hex() {
        return Ok(());
    }
    let expected = SlashingDb::parse_gvr_hex(&pinned_hex)?;
    Err(SlashingError::GenesisRootMismatch { expected, got: spec.gvr() })
}

fn check_spec_in_txn(
    db: &SlashingDb,
    conn: &Connection,
    spec: &ReserveSpec,
) -> Result<CommittedReservation, SlashingError> {
    wait_eval_gate(db);
    match spec {
        ReserveSpec::Block { pubkey, slot, signing_root_hex, .. } => {
            let strict = db.fork_aware_strict(*slot / SLOTS_PER_EPOCH);
            let watermark = read_watermark(conn, pubkey, WatermarkKind::Block)?;
            let history = TargetedSqlBlockHistory::new(conn, pubkey);
            let watermarks = BlockWatermarks { block: watermark.map(|w| w as Slot) };
            let candidate = BlockCandidate { slot: *slot, signing_root: signing_root_hex.clone() };
            let outcome = check_block(pubkey, &history, &watermarks, &candidate, strict)?;
            let inserted = !matches!(outcome, BlockVerdict::Resign);
            Ok(CommittedReservation {
                pubkey_hex: pubkey.clone(),
                kind: ReservationKind::Block { slot: *slot },
                signing_root_hex: signing_root_hex.clone(),
                inserted,
            })
        }
        ReserveSpec::Attestation {
            pubkey, source_epoch, target_epoch, signing_root_hex, ..
        } => {
            let strict = db.fork_aware_strict(*target_epoch);
            let wm_source = read_watermark(conn, pubkey, WatermarkKind::AttestationSource)?;
            let wm_target = read_watermark(conn, pubkey, WatermarkKind::AttestationTarget)?;
            let history = TargetedSqlAttestationHistory::new(conn, pubkey);
            let watermarks = AttestationWatermarks {
                source: wm_source.map(|w| w as Epoch),
                target: wm_target.map(|w| w as Epoch),
            };
            let candidate = AttestationCandidate {
                source_epoch: *source_epoch,
                target_epoch: *target_epoch,
                signing_root: signing_root_hex.clone(),
            };
            let verdict = check_attestation(pubkey, &history, &watermarks, &candidate, strict)?;
            let inserted = !matches!(verdict, AttestationVerdict::Duplicate);
            Ok(CommittedReservation {
                pubkey_hex: pubkey.clone(),
                kind: ReservationKind::Attestation { source: *source_epoch, target: *target_epoch },
                signing_root_hex: signing_root_hex.clone(),
                inserted,
            })
        }
    }
}

fn insert_spec(
    conn: &Connection,
    spec: &ReserveSpec,
    reservation: &CommittedReservation,
) -> Result<(), SlashingError> {
    if !reservation.inserted {
        return Ok(());
    }
    match spec {
        ReserveSpec::Block { pubkey, slot, signing_root_hex, gvr_hex, .. } => {
            conn.execute(
                "INSERT INTO blocks
                 (client_cn, pubkey, slot, signing_root, genesis_validators_root)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (AUDIT_ORIGIN, pubkey.as_str(), *slot as i64, signing_root_hex, gvr_hex),
            )
            .map_err(|e| SlashingError::ReserveCommitFailed(e.to_string()))?;
        }
        ReserveSpec::Attestation {
            pubkey,
            source_epoch,
            target_epoch,
            signing_root_hex,
            gvr_hex,
            ..
        } => {
            conn.execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    AUDIT_ORIGIN,
                    pubkey.as_str(),
                    *source_epoch as i64,
                    *target_epoch as i64,
                    signing_root_hex,
                    gvr_hex,
                ),
            )
            .map_err(|e| SlashingError::ReserveCommitFailed(e.to_string()))?;
        }
    }
    Ok(())
}
