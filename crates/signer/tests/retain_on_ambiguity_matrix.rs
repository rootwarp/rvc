//! ARCH-5j: 14-cell error-class × policy matrix (`reserve_then_sign`).
//!
//! One `#[test]` per cell so a failing cell names itself. Each cell asserts
//! (a) `SigningGateError`, (b) DB row presence and signing-root hex, (c)
//! `rvc_slashing_reconcile_total` **deltas** (process-global).
//!
//! `test_today_*` runs the same classes through `stage_then_sign`. The two
//! designs agree where architecture §5.3 says identical and differ only on
//! the stricter unambiguous + Retain + failed-delete cell.
//!
//! No test name matches `.*(tree_hash|signing_root|_root)$` (A-5.10).
#![allow(deprecated)]

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use crypto::{PublicKey, SecretKey, Signature, Signer, SigningError};
use eth_types::Root;
use rvc_signer::{NoopSignHooks, SigningGateError, SlashableSignSession, TimeoutPolicy};
use slashing::metrics::{reconcile_outcome, tx_hold_kind, RVC_SLASHING_RECONCILE_TOTAL};
use slashing::{
    BlockSlashingViolation, CommittedReservation, GroupCommitConfig, SlashingDb, SlashingError,
};

use common::{
    AmbiguousErrorSigner, HangingSigner, KeyNotFoundSigner, LocalRejectedSigner, PanickingSigner,
    SucceedingSigner, UnsupportedSigningTypeSigner,
};

const GVR: Root = [0xc5; 32];
const SLOT: u64 = 17;
const SIGNING_ROOT: Root = [0x51; 32];
const OTHER_ROOT: Root = [0xee; 32];
const HANG_TIMEOUT: Duration = Duration::from_millis(50);
const SIGN_TIMEOUT: Duration = Duration::from_secs(4);

// ── Metric / DB helpers ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct ReconcileSnap {
    deleted: u64,
    not_applicable: u64,
    failed: u64,
}

fn snap_reconcile() -> ReconcileSnap {
    let kind = tx_hold_kind::BLOCK;
    ReconcileSnap {
        deleted: RVC_SLASHING_RECONCILE_TOTAL
            .with_label_values(&[kind, reconcile_outcome::DELETED])
            .get(),
        not_applicable: RVC_SLASHING_RECONCILE_TOTAL
            .with_label_values(&[kind, reconcile_outcome::NOT_APPLICABLE])
            .get(),
        failed: RVC_SLASHING_RECONCILE_TOTAL
            .with_label_values(&[kind, reconcile_outcome::FAILED])
            .get(),
    }
}

fn assert_reconcile_delta(before: ReconcileSnap, deleted: u64, not_applicable: u64, failed: u64) {
    let after = snap_reconcile();
    assert_eq!(
        after.deleted - before.deleted,
        deleted,
        "rvc_slashing_reconcile_total{{kind=block,outcome=deleted}} delta"
    );
    assert_eq!(
        after.not_applicable - before.not_applicable,
        not_applicable,
        "rvc_slashing_reconcile_total{{kind=block,outcome=not_applicable}} delta"
    );
    assert_eq!(
        after.failed - before.failed,
        failed,
        "rvc_slashing_reconcile_total{{kind=block,outcome=failed}} delta"
    );
}

fn root_hex(root: Root) -> String {
    hex::encode(root)
}

fn assert_no_row(db: &SlashingDb, pubkey_hex: &str) {
    let blocks = db.get_blocks(pubkey_hex).expect("get_blocks");
    assert!(blocks.is_empty(), "expected no block row, found {blocks:?}");
}

fn assert_one_row(db: &SlashingDb, pubkey_hex: &str, expected: Root) {
    let blocks = db.get_blocks(pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "expected exactly one block row, found {blocks:?}");
    assert_eq!(blocks[0].slot, SLOT);
    assert_eq!(
        blocks[0].signing_root.as_deref(),
        Some(root_hex(expected).as_str()),
        "row signing-root hex must match the cell's root"
    );
}

// ── Session / inject ──────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Inject {
    None,
    /// `fail_next_commits(1)` **before** reserve/stage (consumed by reserve_* / stage snapshot).
    FailPersist,
    /// `fail_next_commits(1)` **after** reserve/stage (reconcile leftover; stage discard ignores it).
    FailReconcile,
}

struct RecordingSigner {
    inner: Arc<dyn Signer>,
    attempts: Arc<AtomicU64>,
}

#[async_trait]
impl Signer for RecordingSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

fn wrap_recorded(inner: Arc<dyn Signer>) -> (Arc<dyn Signer>, Arc<AtomicU64>) {
    let attempts = Arc::new(AtomicU64::new(0));
    let signer: Arc<dyn Signer> =
        Arc::new(RecordingSigner { inner, attempts: Arc::clone(&attempts) });
    (signer, attempts)
}

fn succeeding_pair() -> (PublicKey, Arc<dyn Signer>) {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    (pubkey, Arc::new(SucceedingSigner::new(sk)))
}

fn fresh_pubkey() -> PublicKey {
    SecretKey::generate().public_key()
}

fn make_session(
    signer: Arc<dyn Signer>,
    pubkey: &PublicKey,
    policy: TimeoutPolicy,
    timeout: Duration,
    db: Arc<SlashingDb>,
    op_name: &'static str,
) -> SlashableSignSession {
    SlashableSignSession::for_tests(
        tokio::runtime::Handle::current(),
        signer,
        pubkey,
        SIGNING_ROOT,
        timeout,
        policy,
        None,
        db,
        Arc::new(NoopSignHooks),
        op_name,
    )
}

async fn run_reserve(
    session: SlashableSignSession,
    db: Arc<SlashingDb>,
    pubkey_hex: String,
    inject: Inject,
) -> Result<Vec<u8>, SigningGateError> {
    tokio::task::spawn_blocking(move || {
        session.reserve_then_sign(move || -> Result<CommittedReservation, SlashingError> {
            if matches!(inject, Inject::FailPersist) {
                db.fail_next_commits(1);
            }
            let reserved =
                db.reserve_block(&pubkey_hex, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)?;
            if matches!(inject, Inject::FailReconcile) {
                db.fail_next_commits(1);
            }
            Ok(reserved)
        })
    })
    .await
    .map_err(|e| SigningGateError::SigningFailed(format!("retain_matrix task panicked: {e}")))?
}

async fn run_stage(
    session: SlashableSignSession,
    db: Arc<SlashingDb>,
    pubkey_hex: String,
    inject: Inject,
) -> Result<Vec<u8>, SigningGateError> {
    tokio::task::spawn_blocking(move || {
        // Borrow `db` so `StagedBlock` can live in `stage_then_sign` (it is !Send).
        session.stage_then_sign(|| {
            if matches!(inject, Inject::FailPersist) {
                db.fail_next_commits(1);
            }
            let staged = db.stage_block(&pubkey_hex, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)?;
            if matches!(inject, Inject::FailReconcile) {
                db.fail_next_commits(1);
            }
            Ok(staged)
        })
    })
    .await
    .map_err(|e| SigningGateError::SigningFailed(format!("retain_matrix task panicked: {e}")))?
}

fn seed_conflicting_row(db: &SlashingDb, pubkey_hex: &str) {
    db.reserve_block(pubkey_hex, SLOT, Some(root_hex(OTHER_ROOT)), &GVR)
        .expect("seed conflicting history row");
}

fn assert_slashing_blocked(err: &SigningGateError) {
    match err {
        SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
            BlockSlashingViolation::DoubleBlockProposal { slot },
        )) => {
            assert_eq!(*slot, SLOT);
        }
        other => panic!("expected SlashingBlocked(DoubleBlockProposal), got {other:?}"),
    }
}

fn assert_commit_failed(err: &SigningGateError) {
    match err {
        SigningGateError::CommitFailed { signing_root, .. } => {
            assert_eq!(*signing_root, SIGNING_ROOT);
        }
        other => panic!("expected CommitFailed, got {other:?}"),
    }
}

fn assert_timed_out(err: &SigningGateError) {
    match err {
        SigningGateError::SigningFailed(msg) if msg.contains("timed out") => {}
        other => panic!("expected SigningFailed timed out, got {other:?}"),
    }
}

fn assert_signing_failed(err: &SigningGateError) {
    match err {
        SigningGateError::SigningFailed(_) => {}
        other => panic!("expected SigningFailed, got {other:?}"),
    }
}

fn assert_key_not_found(err: &SigningGateError) {
    match err {
        SigningGateError::KeyNotFound => {}
        other => panic!("expected KeyNotFound, got {other:?}"),
    }
}

fn assert_task_panicked(err: &SigningGateError) {
    match err {
        SigningGateError::SigningFailed(msg) if msg.contains("panicked") => {}
        other => panic!("expected SigningFailed task panicked, got {other:?}"),
    }
}

// ── Classifier pin (VD-5.3) ───────────────────────────────────────────────────

#[test]
fn test_matrix_unambiguous_backends_follow_signing_error_classifier() {
    assert!(
        KeyNotFoundSigner::classified_error().is_unambiguous_no_signature(),
        "KeyNotFoundSigner must follow crypto::SigningError::is_unambiguous_no_signature"
    );
    assert!(
        LocalRejectedSigner::classified_error().is_unambiguous_no_signature(),
        "LocalRejectedSigner must follow crypto::SigningError::is_unambiguous_no_signature"
    );
    assert!(
        UnsupportedSigningTypeSigner::classified_error().is_unambiguous_no_signature(),
        "UnsupportedSigningTypeSigner must follow crypto::SigningError::is_unambiguous_no_signature"
    );
    assert!(
        !AmbiguousErrorSigner::classified_error().is_unambiguous_no_signature(),
        "AmbiguousErrorSigner must not be classified as unambiguous"
    );
    assert!(
        !SigningError::InvalidRemoteSignature.is_unambiguous_no_signature(),
        "InvalidRemoteSignature is ambiguous (remote may have signed)"
    );
    assert!(
        !SigningError::RemoteSignerError("http 502 after possible sign".into())
            .is_unambiguous_no_signature(),
        "RemoteSignerError is ambiguous (remote may have signed)"
    );
}

// ── reserve_then_sign matrix (14 cells + stricter failed-delete) ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_reserve_rule_violation_discard() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    seed_conflicting_row(&db, &pubkey_hex);
    let session = make_session(
        Arc::new(SucceedingSigner::new(SecretKey::generate())),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_rule_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("rule violation must fail");
    assert_slashing_blocked(&err);
    assert_one_row(&db, &pubkey_hex, OTHER_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_reserve_rule_violation_retain() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    seed_conflicting_row(&db, &pubkey_hex);
    let session = make_session(
        Arc::new(SucceedingSigner::new(SecretKey::generate())),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_rule_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("rule violation must fail");
    assert_slashing_blocked(&err);
    assert_one_row(&db, &pubkey_hex, OTHER_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_sign_success_discard() {
    let db = common::open_db();
    let (pubkey, signer) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_ok_discard",
    );
    let before = snap_reconcile();
    let sig = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect("sign must succeed");
    assert_eq!(sig.len(), 96);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_sign_success_retain() {
    let db = common::open_db();
    let (pubkey, signer) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_ok_retain",
    );
    let before = snap_reconcile();
    let sig = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect("sign must succeed");
    assert_eq!(sig.len(), 96);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_timeout_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(HangingSigner::exceeding(HANG_TIMEOUT)),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        HANG_TIMEOUT,
        Arc::clone(&db),
        "matrix_timeout_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("timeout must fail");
    assert_timed_out(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 1, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_timeout_retain_keeps_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(HangingSigner::exceeding(HANG_TIMEOUT)),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        HANG_TIMEOUT,
        Arc::clone(&db),
        "matrix_timeout_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("timeout must fail");
    assert_timed_out(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

/// RED-named cell: Retain + ambiguous must keep the row (C1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_retain_matrix_ambiguous_error_retain_policy_keeps_the_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(AmbiguousErrorSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_ambiguous_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("ambiguous error must surface");
    assert_signing_failed(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_ambiguous_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(AmbiguousErrorSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_ambiguous_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("ambiguous error must surface");
    assert_signing_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 1, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_unambiguous_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(KeyNotFoundSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_unamb_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("unambiguous no-signature must fail");
    assert_key_not_found(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 1, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_unambiguous_retain_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(LocalRejectedSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_unamb_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("unambiguous no-signature must fail");
    assert_signing_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 1, 0, 0);
}

/// Stricter-than-today: failed compensating delete retains under Retain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_unambiguous_retain_failed_delete_keeps_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(KeyNotFoundSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_unamb_retain_fail_del",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailReconcile)
        .await
        .expect_err("original KeyNotFound must surface");
    assert_key_not_found(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_reserve_commit_failed_discard() {
    let db = common::open_db();
    let (pubkey, inner) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let (signer, attempts) = wrap_recorded(inner);
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_commit_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailPersist)
        .await
        .expect_err("reserve inject must fail");
    assert_commit_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_eq!(attempts.load(Ordering::SeqCst), 0, "reserve commit failure must not sign");
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_reserve_commit_failed_retain() {
    let db = common::open_db();
    let (pubkey, inner) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let (signer, attempts) = wrap_recorded(inner);
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_commit_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailPersist)
        .await
        .expect_err("reserve inject must fail");
    assert_commit_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_eq!(attempts.load(Ordering::SeqCst), 0, "reserve commit failure must not sign");
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_panic_discard_keeps_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(PanickingSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_panic_discard",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("panic must surface as SigningFailed");
    assert_task_panicked(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_matrix_panic_retain_keeps_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(PanickingSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "matrix_panic_retain",
    );
    let before = snap_reconcile();
    let err = run_reserve(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("panic must surface as SigningFailed");
    assert_task_panicked(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

// ── today: stage_then_sign comparison table ───────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_reserve_rule_violation_discard() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    seed_conflicting_row(&db, &pubkey_hex);
    let session = make_session(
        Arc::new(SucceedingSigner::new(SecretKey::generate())),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_rule_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("rule violation must fail");
    assert_slashing_blocked(&err);
    assert_one_row(&db, &pubkey_hex, OTHER_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_reserve_rule_violation_retain() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    seed_conflicting_row(&db, &pubkey_hex);
    let session = make_session(
        Arc::new(SucceedingSigner::new(SecretKey::generate())),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_rule_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("rule violation must fail");
    assert_slashing_blocked(&err);
    assert_one_row(&db, &pubkey_hex, OTHER_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_sign_success_discard() {
    let db = common::open_db();
    let (pubkey, signer) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_ok_discard",
    );
    let before = snap_reconcile();
    let sig = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect("sign must succeed");
    assert_eq!(sig.len(), 96);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_sign_success_retain() {
    let db = common::open_db();
    let (pubkey, signer) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_ok_retain",
    );
    let before = snap_reconcile();
    let sig = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect("sign must succeed");
    assert_eq!(sig.len(), 96);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_timeout_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(HangingSigner::exceeding(HANG_TIMEOUT)),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        HANG_TIMEOUT,
        Arc::clone(&db),
        "today_timeout_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("timeout must fail");
    assert_timed_out(&err);
    assert_no_row(&db, &pubkey_hex);
    // Today ROLLBACKs; it does not increment reconcile.
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_timeout_retain_keeps_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(HangingSigner::exceeding(HANG_TIMEOUT)),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        HANG_TIMEOUT,
        Arc::clone(&db),
        "today_timeout_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("timeout must fail");
    assert_timed_out(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_ambiguous_error_retain_policy_keeps_the_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(AmbiguousErrorSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_ambiguous_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("ambiguous error must surface");
    assert_signing_failed(&err);
    assert_one_row(&db, &pubkey_hex, SIGNING_ROOT);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_ambiguous_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(AmbiguousErrorSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_ambiguous_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("ambiguous error must surface");
    assert_signing_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_unambiguous_discard_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(KeyNotFoundSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_unamb_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("unambiguous no-signature must fail");
    assert_key_not_found(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_unambiguous_retain_reconciles() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(LocalRejectedSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_unamb_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("unambiguous no-signature must fail");
    assert_signing_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

/// Today always `discard_row()` on unambiguous — row gone even under Retain + leftover inject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_unambiguous_retain_failed_delete_drops_row() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(KeyNotFoundSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_unamb_retain_fail_del",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailReconcile)
        .await
        .expect_err("unambiguous no-signature must fail");
    assert_key_not_found(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_reserve_commit_failed_discard() {
    let db = common::open_db();
    let (pubkey, inner) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let (signer, attempts) = wrap_recorded(inner);
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_commit_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailPersist)
        .await
        .expect_err("commit inject must fail");
    assert_commit_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "today commit inject is consumed after a successful sign"
    );
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_reserve_commit_failed_retain() {
    let db = common::open_db();
    let (pubkey, inner) = succeeding_pair();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let (signer, attempts) = wrap_recorded(inner);
    let session = make_session(
        signer,
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_commit_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::FailPersist)
        .await
        .expect_err("commit inject must fail");
    assert_commit_failed(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "today commit inject is consumed after a successful sign"
    );
    assert_reconcile_delta(before, 0, 0, 0);
}

/// Today: guard `Drop` rolls back; new design keeps the already-committed row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_panic_discard_rolls_back() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(PanickingSigner),
        &pubkey,
        TimeoutPolicy::DiscardStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_panic_discard",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("panic must surface as SigningFailed");
    assert_task_panicked(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_today_panic_retain_rolls_back() {
    let db = common::open_db();
    let pubkey = fresh_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let session = make_session(
        Arc::new(PanickingSigner),
        &pubkey,
        TimeoutPolicy::RetainStagedRow,
        SIGN_TIMEOUT,
        Arc::clone(&db),
        "today_panic_retain",
    );
    let before = snap_reconcile();
    let err = run_stage(session, Arc::clone(&db), pubkey_hex.clone(), Inject::None)
        .await
        .expect_err("panic must surface as SigningFailed");
    assert_task_panicked(&err);
    assert_no_row(&db, &pubkey_hex);
    assert_reconcile_delta(before, 0, 0, 0);
}

/// Batch-boundary (#205): a failed group COMMIT rejects every member before
/// any backend sign. Same-root retry stays mapped to `CommitFailed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_batch_commit_failure_rejects_every_member_without_signing() {
    let db = common::open_db();
    db.set_group_commit(GroupCommitConfig {
        batch_size: 3,
        wait_to_fill: Duration::from_millis(80),
    });
    db.fail_next_commits(1);

    let mut joins = Vec::new();
    let mut pubkeys = Vec::new();
    let mut attempts = Vec::new();
    for _ in 0..3 {
        let (pubkey, signer) = succeeding_pair();
        let (signer, counted) = wrap_recorded(signer);
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        pubkeys.push(pubkey_hex.clone());
        attempts.push(Arc::clone(&counted));
        let session = make_session(
            signer,
            &pubkey,
            TimeoutPolicy::RetainStagedRow,
            SIGN_TIMEOUT,
            Arc::clone(&db),
            "batch_commit_fail",
        );
        joins.push(tokio::spawn(run_reserve(session, Arc::clone(&db), pubkey_hex, Inject::None)));
    }

    for ((join, pk), counted) in joins.into_iter().zip(pubkeys.iter()).zip(attempts.iter()) {
        let err = join.await.expect("join").expect_err("batch COMMIT fail must reject");
        assert_commit_failed(&err);
        assert_eq!(counted.load(Ordering::SeqCst), 0, "no member may sign before COMMIT");
        assert_no_row(&db, pk);
    }
}
