//! ARCH-5e / ARCH-5f / ARCH-5g: `reserve_*` + `reconcile_unsigned` + scoped wrappers.
//!
//! Additive sibling of `stage_*`. `reconcile_unsigned` is the compensating
//! delete that makes reserve-before-sign admissible (M-1). C1: a failed
//! delete retains. `PubkeyScopedDb::reserve_*` emits audit after the mutex
//! is gone (C2 / ADR-006). No production caller switch (ARCH-5l).
//!
//! M-1 (`crates/signer/tests/phantom_row_m1.rs:1-10`):
//! Before the fix, `SignerService::sign_attestation` and `sign_block` called
//! `check_and_record_*` (which committed the row immediately) and only then
//! called `signer.sign`. A signing failure left a committed row in the DB,
//! causing the next legitimate sign attempt to look like a DoubleVote.
//!
//! C1: stage → release → sign → re-check-and-commit is rejected by name.
//! No test in this file is named `*_root` (KAT-first name scanner).

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rvc_slashing::metrics::{reconcile_outcome, tx_hold_kind, RVC_SLASHING_RECONCILE_TOTAL};
use rvc_slashing::{
    BlockSlashingViolation, CommittedReservation, InterchangeAttestation, InterchangeBlock,
    InterchangeFormat, InterchangeMetadata, PubkeyScopedDb, ReconcileOutcome, ReservationKind,
    SlashingDb, SlashingError, ValidatorRecord,
};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const PUBKEY: &str = "0xdeadbeef01";
const PUBKEY2: &str = "0xdeadbeef02";
const GVR: &[u8; 32] = &[0u8; 32];
const R1: &[u8; 32] = &[0x01u8; 32];
const R2: &[u8; 32] = &[0x02u8; 32];
const CHAIN_GVR_HEX: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
const CHAIN_GVR: [u8; 32] = [
    0x04, 0x70, 0x00, 0x07, 0xfa, 0xbc, 0x82, 0x82, 0x64, 0x4a, 0xed, 0x6d, 0x1c, 0x7c, 0x9e, 0x21,
    0xd3, 0x8a, 0x03, 0xa0, 0xc4, 0xba, 0x19, 0x3f, 0x3a, 0xfe, 0x42, 0x88, 0x24, 0xb3, 0xa6, 0x73,
];

fn assert_send<T: Send>() {}

/// Compile-time pin: a leaked `MutexGuard` would make this fail to compile.
#[test]
fn test_committed_reservation_is_send() {
    assert_send::<CommittedReservation>();
}

/// RED for the phase: reserve on thread A, then a second thread must complete
/// `reserve_block` for a **different** pubkey while A still holds its token.
/// Under `stage_block` this deadlocks/blocks. Timeout, not a bare join.
#[test]
fn test_reserve_block_releases_the_connection_mutex_before_returning() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let db_a = Arc::clone(&db);
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let thread_a = thread::spawn(move || {
        let reservation =
            db_a.reserve_block(PUBKEY, 1, Some("0xroot_a".into()), GVR).expect("reserve A");
        held_tx.send(()).expect("signal held");
        let _ = release_rx.recv_timeout(Duration::from_secs(2));
        reservation
    });

    held_rx.recv_timeout(Duration::from_secs(1)).expect("thread A must reserve");

    let db_b = Arc::clone(&db);
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let started = Instant::now();
        let result = db_b.reserve_block(PUBKEY2, 1, Some("0xroot_b".into()), GVR);
        let _ = done_tx.send((result, started.elapsed()));
    });

    let (result, elapsed) = done_rx
        .recv_timeout(Duration::from_millis(50))
        .expect("second reserve must complete while the first CommittedReservation is still held");
    let reservation_b = result.expect("reserve B");
    assert!(
        elapsed < Duration::from_millis(50),
        "second reserve took {elapsed:?}; mutex must not be held by CommittedReservation"
    );
    assert!(reservation_b.inserted);
    assert_eq!(reservation_b.kind, ReservationKind::Block { slot: 1 });

    let _ = release_tx.send(());
    let reservation_a = thread_a.join().expect("thread A");
    assert!(reservation_a.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get A").len(), 1);
    assert_eq!(db.get_blocks(PUBKEY2).expect("get B").len(), 1);
}

#[test]
fn test_reserve_block_rule_violation_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first = db.reserve_block(PUBKEY, 100, Some("0xroot_1".into()), GVR).expect("first reserve");
    assert!(first.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    let err = db
        .reserve_block(PUBKEY, 100, Some("0xroot_2".into()), GVR)
        .expect_err("double proposal must fail");
    match err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 100);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
    assert!(
        !err.is_reserve_commit_failure(),
        "a rule violation must not be classified as reserve-commit failure"
    );
    assert_eq!(
        db.get_blocks(PUBKEY).expect("get").len(),
        1,
        "rollback must leave history unchanged"
    );

    // Connection must not be left mid-transaction (exactly one ROLLBACK).
    db.reserve_block(PUBKEY, 101, Some("0xroot_3".into()), GVR)
        .expect("subsequent reserve after a rolled-back violation must succeed");
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 2);
}

#[test]
fn test_reserve_block_resign_reports_not_inserted() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("first");
    assert!(first.inserted);

    let second = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("resign");
    assert!(!second.inserted, "idempotent re-sign must report inserted == false");
    assert_eq!(second.kind, ReservationKind::Block { slot: 42 });
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);
}

/// M-6: mismatch is rejected before the connection mutex. Proven by holding
/// that mutex via a live `stage_block` guard (which would deadlock a
/// post-mutex check). Suffixed `_mutex` so the name does not match `.*_root$`.
#[test]
fn test_reserve_rejects_genesis_root_mismatch_without_touching_the_mutex() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.set_genesis_validators_root(R1).expect("pin R1");

    // Warms the GVR cache, then holds the connection mutex for the rest of
    // this scope. `pinned_gvr()` after this is a cache hit and must not lock.
    let _held = db.stage_block(PUBKEY, 1, Some("0xhold".into()), R1).expect("hold mutex");

    let db_b = Arc::clone(&db);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(db_b.reserve_block(PUBKEY2, 2, Some("0xother".into()), R2));
    });

    let err = rx
        .recv_timeout(Duration::from_millis(200))
        .expect("GVR mismatch must not wait on the connection mutex")
        .expect_err("mismatch must be rejected");
    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
    // parking_lot::Mutex is not reentrant — release the staged guard before
    // any API that locks the connection again.
    drop(_held);
    assert!(db.get_blocks(PUBKEY2).expect("get").is_empty());
}

#[test]
fn test_reserve_commit_failure_is_distinguishable_from_a_rule_violation() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.fail_next_commits(1);

    let err = db
        .reserve_block(PUBKEY, 7, Some("0xinject".into()), GVR)
        .expect_err("injected persist failure");
    assert!(err.is_reserve_commit_failure(), "inject must be ReserveCommitFailed, got: {err:?}");
    match err {
        SlashingError::ReserveCommitFailed(msg) => {
            assert!(msg.contains("injected commit failure"), "got: {msg}");
        }
        other => panic!("expected ReserveCommitFailed, got: {other:?}"),
    }
    assert!(
        db.get_blocks(PUBKEY).expect("get").is_empty(),
        "failed reserve must leave no block row"
    );

    let rule_err = {
        db.reserve_block(PUBKEY, 7, Some("0xok".into()), GVR).expect("row after inject exhausted");
        db.reserve_block(PUBKEY, 7, Some("0xother".into()), GVR).expect_err("double proposal")
    };
    assert!(
        !rule_err.is_reserve_commit_failure(),
        "DoubleBlockProposal must not collapse into ReserveCommitFailed"
    );
    match rule_err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 7);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
}

#[test]
fn test_reserve_attestation_commits_and_duplicate_reports_not_inserted() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first =
        db.reserve_attestation(PUBKEY, 3, 10, Some("0xatt".into()), GVR).expect("first att");
    assert!(first.inserted);
    assert_eq!(first.kind, ReservationKind::Attestation { source: 3, target: 10 });
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);

    let dup = db.reserve_attestation(PUBKEY, 3, 10, Some("0xatt".into()), GVR).expect("duplicate");
    assert!(!dup.inserted);
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);
}

#[test]
fn test_reserve_attestation_double_vote_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.reserve_attestation(PUBKEY, 1, 5, Some("0xatt_1".into()), GVR).expect("first");
    let err =
        db.reserve_attestation(PUBKEY, 1, 5, Some("0xatt_2".into()), GVR).expect_err("double vote");
    assert!(!err.is_reserve_commit_failure());
    assert!(matches!(err, SlashingError::SlashableAttestation(_)));
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);
}

#[test]
fn test_reserve_attestation_commit_failure_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.fail_next_commits(1);
    let err =
        db.reserve_attestation(PUBKEY, 2, 8, Some("0xatt_inj".into()), GVR).expect_err("inject");
    assert!(err.is_reserve_commit_failure());
    assert!(db.get_attestations(PUBKEY).expect("get").is_empty());
}

// ── ARCH-5f: reconcile_unsigned ───────────────────────────────────────────────

/// RED for 5f: two reserved slots, reconcile one, the other must survive.
/// A naive `DELETE … WHERE pubkey = ?` fails this.
#[test]
fn test_reconcile_deletes_exactly_the_reserved_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    let keep = db.reserve_block(PUBKEY, 10, Some("0xkeep".into()), GVR).expect("reserve keep");
    let drop = db.reserve_block(PUBKEY, 20, Some("0xdrop".into()), GVR).expect("reserve drop");
    assert!(keep.inserted && drop.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 2);

    let outcome = db.reconcile_unsigned(&drop);
    assert!(matches!(outcome, ReconcileOutcome::Deleted));

    let remaining = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(remaining.len(), 1, "exactly the reserved row must be deleted");
    assert_eq!(remaining[0].slot, 10);
    assert_eq!(remaining[0].signing_root.as_deref(), Some("0xkeep"));
}

#[test]
fn test_reconcile_deletes_exactly_the_reserved_attestation() {
    let db = SlashingDb::open_in_memory().expect("open");
    let keep = db.reserve_attestation(PUBKEY, 1, 5, Some("0xatt_keep".into()), GVR).expect("keep");
    let drop = db.reserve_attestation(PUBKEY, 5, 9, Some("0xatt_drop".into()), GVR).expect("drop");
    assert!(keep.inserted && drop.inserted);

    let outcome = db.reconcile_unsigned(&drop);
    assert!(matches!(outcome, ReconcileOutcome::Deleted));

    let remaining = db.get_attestations(PUBKEY).expect("get");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].target_epoch, 5);
    assert_eq!(remaining[0].signing_root.as_deref(), Some("0xatt_keep"));
}

#[test]
fn test_reconcile_is_a_noop_for_a_resign_reservation() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("first");
    assert!(first.inserted);
    let resign = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("resign");
    assert!(!resign.inserted);

    let outcome = db.reconcile_unsigned(&resign);
    assert!(matches!(outcome, ReconcileOutcome::NotApplicable));
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    // The original inserted reservation is still reconcilable.
    let deleted = db.reconcile_unsigned(&first);
    assert!(matches!(deleted, ReconcileOutcome::Deleted));
    assert!(db.get_blocks(PUBKEY).expect("get").is_empty());
}

/// Targeting includes signing_root: a fabricated reservation for the same
/// slot/kind with a different root must not remove the real row.
#[test]
fn test_reconcile_does_not_delete_a_mismatched_signing_root_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    let reserved = db.reserve_block(PUBKEY, 7, Some("0xreal".into()), GVR).expect("reserve");
    assert!(reserved.inserted);

    let forged = CommittedReservation {
        pubkey_hex: reserved.pubkey_hex.clone(),
        kind: reserved.kind,
        signing_root_hex: Some("0xother".into()),
        inserted: true,
    };
    let outcome = db.reconcile_unsigned(&forged);
    assert!(
        matches!(outcome, ReconcileOutcome::NotApplicable),
        "0-row targeted DELETE must not report Deleted, got: {outcome:?}"
    );
    let remaining = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(remaining.len(), 1, "mismatched signing_root must not delete the row");
    assert_eq!(remaining[0].signing_root.as_deref(), Some("0xreal"));
}

#[test]
fn test_reconcile_never_changes_watermarks() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_block_watermark(PUBKEY, 50).expect("block wm");
    db.set_attestation_watermark(PUBKEY, 3, 4).expect("att wm");
    db.set_block_watermark(PUBKEY2, 999).expect("other wm");

    let before_block = db.get_block_watermark(PUBKEY).expect("get");
    let before_att = db.get_attestation_watermark(PUBKEY).expect("get");
    let before_other = db.get_block_watermark(PUBKEY2).expect("get");

    let reservation =
        db.reserve_block(PUBKEY, 80, Some("0xabove".into()), GVR).expect("reserve above floor");
    assert!(reservation.inserted);
    let outcome = db.reconcile_unsigned(&reservation);
    assert!(matches!(outcome, ReconcileOutcome::Deleted));

    assert_eq!(db.get_block_watermark(PUBKEY).expect("get"), before_block);
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("get"), before_att);
    assert_eq!(db.get_block_watermark(PUBKEY2).expect("get"), before_other);
}

/// Minified interchange: watermark floor + dummy history at the floor.
/// Reconciling a later reservation must not re-open a slot at or below that floor.
#[test]
fn test_reconcile_after_a_minified_import_cannot_reopen_a_closed_slot() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_genesis_validators_root(&CHAIN_GVR).expect("pin");

    let interchange = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".into(),
            genesis_validators_root: CHAIN_GVR_HEX.into(),
        },
        data: vec![ValidatorRecord {
            pubkey: PUBKEY.into(),
            signed_blocks: vec![InterchangeBlock { slot: "100".into(), signing_root: None }],
            signed_attestations: vec![InterchangeAttestation {
                source_epoch: "10".into(),
                target_epoch: "20".into(),
                signing_root: None,
            }],
        }],
    };
    db.import(&interchange, &CHAIN_GVR).expect("minified import");
    assert_eq!(db.get_block_watermark(PUBKEY).expect("wm"), Some(100));
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("wm"), Some((10, 20)));

    let reservation = db
        .reserve_block(PUBKEY, 200, Some("0xabove_floor".into()), &CHAIN_GVR)
        .expect("reserve above imported floor");
    assert!(reservation.inserted);
    let outcome = db.reconcile_unsigned(&reservation);
    assert!(matches!(outcome, ReconcileOutcome::Deleted));

    assert_eq!(
        db.get_block_watermark(PUBKEY).expect("wm"),
        Some(100),
        "reconcile must not lower the imported floor"
    );
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("wm"), Some((10, 20)));

    let below = db.reserve_block(PUBKEY, 50, Some("0xreopen".into()), &CHAIN_GVR);
    assert!(
        matches!(below, Err(SlashingError::BelowBlockWatermark { .. })),
        "slot at or below the minified floor must stay refused, got: {below:?}"
    );

    let at_floor = db.reserve_block(PUBKEY, 100, Some("0xat_floor".into()), &CHAIN_GVR);
    assert!(at_floor.is_err(), "the imported floor slot must stay closed, got: {at_floor:?}");

    // Watermark-only isolation: no history at the floor, only the raised watermark.
    db.set_block_watermark(PUBKEY2, 75).expect("watermark-only floor");
    let above = db
        .reserve_block(PUBKEY2, 200, Some("0xpk2".into()), &CHAIN_GVR)
        .expect("reserve above watermark-only floor");
    assert!(matches!(db.reconcile_unsigned(&above), ReconcileOutcome::Deleted));
    let reopen = db.reserve_block(PUBKEY2, 75, Some("0xreopen_wm".into()), &CHAIN_GVR);
    assert!(
        matches!(reopen, Err(SlashingError::BelowBlockWatermark { .. })),
        "watermark-only floor must survive reconcile, got: {reopen:?}"
    );
}

/// 48-byte compressed BLS key so `TruncatedPubkey` actually truncates.
/// A raw-pubkey log regression would fail `!logs_contain(FULL_PUBKEY)`.
const FULL_PUBKEY: &str = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
const FULL_PUBKEY_TRUNCATED: &str = "0x93247f2209...611df74a";

#[tracing_test::traced_test]
#[test]
fn test_reconcile_failure_reports_failed_and_retains_the_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    let reservation =
        db.reserve_block(FULL_PUBKEY, 3, Some("0xphantom".into()), GVR).expect("reserve");
    assert!(reservation.inserted);

    let failed_before = RVC_SLASHING_RECONCILE_TOTAL
        .with_label_values(&[tx_hold_kind::BLOCK, reconcile_outcome::FAILED])
        .get();

    // Consumed by reconcile, not reserve — armed after the INSERT committed.
    db.fail_next_commits(1);
    let outcome = db.reconcile_unsigned(&reservation);
    match outcome {
        ReconcileOutcome::Failed(SlashingError::ReconcileFailed(msg)) => {
            assert!(msg.contains("injected reconcile failure"), "got: {msg}");
        }
        other => panic!("expected Failed(ReconcileFailed), got: {other:?}"),
    }

    let remaining = db.get_blocks(FULL_PUBKEY).expect("get");
    assert_eq!(remaining.len(), 1, "failed delete must retain the row (C1)");
    assert_eq!(remaining[0].signing_root.as_deref(), Some("0xphantom"));

    let failed_after = RVC_SLASHING_RECONCILE_TOTAL
        .with_label_values(&[tx_hold_kind::BLOCK, reconcile_outcome::FAILED])
        .get();
    assert!(
        failed_after > failed_before,
        "rvc_slashing_reconcile_total{{outcome=failed}} must increment: before={failed_before} after={failed_after}"
    );
    assert!(logs_contain("reconcile_unsigned failed"));
    assert!(logs_contain("retaining reserved slashing row"));
    assert!(
        logs_contain(FULL_PUBKEY_TRUNCATED),
        "Failed path must log TruncatedPubkey, expected {FULL_PUBKEY_TRUNCATED}"
    );
    assert!(
        !logs_contain(FULL_PUBKEY),
        "raw 48-byte pubkey must not appear in the reconcile error log"
    );
}

// ── ARCH-5g: PubkeyScopedDb::reserve_* + reconcile_unsigned ───────────────────

const R1_HEX: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";
const SCOPED_CN: &str = "peer-dvt-5g";

/// Subscriber that acquires the slashing DB mutex on every tracing event.
///
/// Reproduces C2: if `"staged"` / `"reconciled"` fire while `reserve_*` still
/// holds `conn`, `get_blocks` deadlocks. Timeout is thread-based
/// (`recv_timeout`), never `tokio::time::timeout`: a `parking_lot` lock is
/// not an await point, so an async timeout cannot cancel it and would hang
/// nextest instead of failing.
struct DbReadingLayer {
    db: Arc<SlashingDb>,
}

impl<S: tracing::Subscriber> Layer<S> for DbReadingLayer {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let _ = self.db.get_blocks("0xdead");
    }
}

/// RED for 5g: a DB-reading subscriber must complete a scoped reserve →
/// (simulated sign) → reconcile cycle. Failure mode is deadlock, not an
/// assertion. Timeout, not a bare join.
#[test]
fn test_scoped_reserve_emits_audit_outside_the_connection_mutex() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let db_worker = Arc::clone(&db);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let subscriber =
            tracing_subscriber::registry().with(DbReadingLayer { db: Arc::clone(&db_worker) });
        let _guard = tracing::subscriber::set_default(subscriber);

        let scoped = PubkeyScopedDb::new(db_worker, SCOPED_CN.to_string(), *GVR);
        let result = (|| {
            let reservation = scoped.reserve_block(PUBKEY, 1, Some("0xscoped".into()))?;
            // Simulated sign while the reservation token is still held.
            // The mutex must already be free — the subscriber re-entered on
            // the `"staged"` event above.
            assert!(reservation.inserted, "fresh reserve must insert");
            let outcome = scoped.reconcile_unsigned(&reservation);
            Ok::<_, SlashingError>(outcome)
        })();
        let _ = tx.send(result);
    });

    let outcome = rx
        .recv_timeout(Duration::from_secs(2))
        .expect(
            "scoped reserve→reconcile must complete; deadlock means audit still holds the mutex \
             (C2 / ADR-006)",
        )
        .expect("reserve must succeed");
    assert!(
        matches!(outcome, ReconcileOutcome::Deleted),
        "reconcile after a successful reserve must delete, got: {outcome:?}"
    );
    assert!(db.get_blocks(PUBKEY).expect("get").is_empty());
}

/// Inject must fail `reserve_*` itself (INSERT+COMMIT is inside the call).
/// A leftover snapshot consumed by a later commit/reconcile would be a 5g miss.
#[test]
fn test_fail_next_commits_fails_the_reserve_not_a_later_call() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let scoped = PubkeyScopedDb::new(Arc::clone(&db), SCOPED_CN.to_string(), *GVR);

    db.fail_next_commits(1);
    let err = scoped
        .reserve_block(PUBKEY, 9, Some("0xinject".into()))
        .expect_err("inject must fail the reserve");
    assert!(err.is_reserve_commit_failure(), "got: {err:?}");
    match &err {
        SlashingError::ReserveCommitFailed(msg) => {
            assert!(msg.contains("injected commit failure"), "got: {msg}");
        }
        other => panic!("expected ReserveCommitFailed, got: {other:?}"),
    }
    assert!(db.get_blocks(PUBKEY).expect("get").is_empty(), "failed reserve must leave no row");

    // Inject exhausted by reserve — a later call must succeed without re-arming.
    let reservation = scoped
        .reserve_block(PUBKEY, 9, Some("0xinject".into()))
        .expect("second reserve after inject exhausted must succeed");
    assert!(reservation.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    let att_err = {
        db.fail_next_commits(1);
        scoped
            .reserve_attestation(PUBKEY, 1, 4, Some("0xatt_inj".into()))
            .expect_err("inject must fail reserve_attestation")
    };
    assert!(att_err.is_reserve_commit_failure(), "got: {att_err:?}");
    assert!(db.get_attestations(PUBKEY).expect("get").is_empty());
}

/// Captures `(client_cn, outcome)` from `slashing.audit` events.
struct AuditCapture {
    events: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

struct AuditVisitor {
    client_cn: Option<String>,
    outcome: Option<String>,
}

impl Visit for AuditVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "client_cn" => self.client_cn = Some(value.to_string()),
            "outcome" => self.outcome = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "client_cn" if self.client_cn.is_none() => {
                self.client_cn = Some(format!("{value:?}").trim_matches('"').to_string());
            }
            "outcome" if self.outcome.is_none() => {
                self.outcome = Some(format!("{value:?}").trim_matches('"').to_string());
            }
            _ => {}
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for AuditCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "slashing.audit" {
            return;
        }
        let mut visitor = AuditVisitor { client_cn: None, outcome: None };
        event.record(&mut visitor);
        if let (Some(cn), Some(outcome)) = (visitor.client_cn, visitor.outcome) {
            self.events.lock().expect("capture").push((cn, outcome));
        }
    }
}

#[test]
fn test_scoped_reserve_pins_client_cn_and_gvr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("scoped_reserve.db");
    let db = Arc::new(SlashingDb::open(&path).expect("open file db"));
    db.set_genesis_validators_root(R1).expect("pin R1");

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber =
        tracing_subscriber::registry().with(AuditCapture { events: Arc::clone(&events) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let scoped = PubkeyScopedDb::new(Arc::clone(&db), SCOPED_CN.to_string(), *R1);
    let reservation =
        scoped.reserve_block(PUBKEY, 11, Some("0xcn".into())).expect("matching GVR must reserve");
    assert!(reservation.inserted);

    let wrong = PubkeyScopedDb::new(Arc::clone(&db), SCOPED_CN.to_string(), *R2);
    let err = wrong
        .reserve_block(PUBKEY2, 12, Some("0xwrong_gvr".into()))
        .expect_err("wrong GVR must be rejected");
    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }

    let captured = events.lock().expect("capture");
    assert!(
        captured.iter().any(|(cn, outcome)| cn == SCOPED_CN && outcome == "staged"),
        "successful reserve must audit with the scoped CN, got: {captured:?}"
    );
    assert!(
        captured.iter().any(|(cn, outcome)| cn == SCOPED_CN && outcome == "rejected"),
        "GVR mismatch must audit rejected with the scoped CN, got: {captured:?}"
    );
    drop(captured);

    drop(scoped);
    drop(wrong);
    drop(db);

    let conn = rusqlite::Connection::open(&path).expect("direct open");
    let (cn, gvr_hex): (String, String) = conn
        .query_row(
            "SELECT client_cn, genesis_validators_root FROM blocks WHERE pubkey = ?1 AND slot = 11",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("reserved row must exist");
    assert_eq!(cn, "local-vc", "history row CN is AUDIT_ORIGIN; per-CN audit is the event");
    assert_eq!(gvr_hex, R1_HEX, "row must carry the scoped GVR");

    let leftover: i64 = conn
        .query_row("SELECT COUNT(*) FROM blocks WHERE pubkey = ?1", [PUBKEY2], |row| row.get(0))
        .expect("count");
    assert_eq!(leftover, 0, "GVR-rejected reserve must write no row");
}
