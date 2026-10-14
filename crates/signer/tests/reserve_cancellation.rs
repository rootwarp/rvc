//! ARCH-5k: crash / cancellation injection at every await point of `reserve_then_sign`.
//!
//! After abandonment the reserved row is present and a conflicting sign is refused.
//! Cancellation before reserve leaves no row. Same-root re-sign remains allowed.
//! Test names avoid the `*_root` KAT scanner (A-5.10).
#![allow(deprecated)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer, SigningError};
use eth_types::Root;
use rvc_signer::{NoopSignHooks, SlashableSignSession, TimeoutPolicy, ValidatorLockMap};
use slashing::{BlockSlashingViolation, GroupCommitConfig, SlashingDb, SlashingError};
use tokio::sync::{oneshot, Notify};

const GVR: Root = [0xc0; 32];
const SLOT: u64 = 17;
const SIGNING_ROOT: Root = [0xaa; 32];
const CONFLICT_ROOT: Root = [0xbb; 32];
/// Longer than the test body so a mid-sign drop is not a timeout-policy path.
const HANG_SIGN_TIMEOUT: Duration = Duration::from_secs(30);

struct ReopenableDb {
    _dir: tempfile::TempDir,
    path: PathBuf,
    db: Option<Arc<SlashingDb>>,
}

impl ReopenableDb {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("slashing.sqlite");
        let db = Arc::new(SlashingDb::open(&path).expect("open file-backed slashing DB"));
        Self { _dir: dir, path, db: Some(db) }
    }

    fn db(&self) -> Arc<SlashingDb> {
        Arc::clone(self.db.as_ref().expect("writer handle still held"))
    }

    fn drop_writer(&mut self) {
        self.db = None;
    }

    fn reopen(&self) -> SlashingDb {
        SlashingDb::open(&self.path).expect("reopen slashing DB from the same path")
    }
}

struct HangingSigner {
    inner: LocalSigner,
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    release_rx: Mutex<Option<oneshot::Receiver<()>>>,
}

#[async_trait]
impl Signer for HangingSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        let rx = self.release_rx.lock().expect("release_rx").take();
        if let Some(rx) = rx {
            let _ = rx.await;
        }
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

struct PanicSigner;

#[async_trait]
impl Signer for PanicSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        panic!("ARCH-5k injected panic in sign backend");
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        Vec::new()
    }
}

fn make_local(sk: SecretKey) -> (PublicKey, Arc<dyn Signer>) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    (pubkey, Arc::new(LocalSigner::new(km)) as Arc<dyn Signer>)
}

struct HangHandle {
    pubkey: PublicKey,
    signer: Arc<dyn Signer>,
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    release_tx: oneshot::Sender<()>,
}

fn hanging_pair(sk: SecretKey) -> HangHandle {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let entered = Arc::new(AtomicBool::new(false));
    let entered_notify = Arc::new(Notify::new());
    let (release_tx, release_rx) = oneshot::channel();
    let signer: Arc<dyn Signer> = Arc::new(HangingSigner {
        inner: LocalSigner::new(km),
        entered: Arc::clone(&entered),
        entered_notify: Arc::clone(&entered_notify),
        release_rx: Mutex::new(Some(release_rx)),
    });
    HangHandle { pubkey, signer, entered, entered_notify, release_tx }
}

fn session(
    signer: Arc<dyn Signer>,
    pubkey: &PublicKey,
    slashing_db: Arc<SlashingDb>,
    sign_timeout: Duration,
    policy: TimeoutPolicy,
    op_name: &'static str,
) -> SlashableSignSession {
    SlashableSignSession::for_tests(
        tokio::runtime::Handle::current(),
        signer,
        pubkey,
        SIGNING_ROOT,
        sign_timeout,
        policy,
        None,
        slashing_db,
        Arc::new(NoopSignHooks),
        op_name,
    )
}

fn root_hex(root: Root) -> String {
    hex::encode(root)
}

fn assert_conflict_refused(err: SlashingError, slot: u64) {
    match err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot: s }) => {
            assert_eq!(s, slot);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
}

async fn wait_until_sign_entered(entered: &AtomicBool, notify: &Notify) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = notify.notified();
            if entered.load(Ordering::SeqCst) {
                break;
            }
            notified.await;
        }
    })
    .await
    .expect("backend must enter sign() after reserve has committed");
}

#[derive(Clone, Copy)]
enum MidSignPath {
    Reserve,
    Stage,
}

struct MidSignDropOutcome {
    row_count: usize,
    conflict_refused: bool,
}

/// After `sign()` is entered, drop the test's extra DB handle, reopen, assert
/// durable state, then release the hang and join so Runtime drop cannot stall.
async fn mid_sign_drop_and_reopen(path: MidSignPath) -> MidSignDropOutcome {
    let mut fixture = ReopenableDb::new();
    let hang = hanging_pair(SecretKey::generate());
    let pubkey_hex = hex::encode(hang.pubkey.to_bytes());
    let sess = session(
        hang.signer,
        &hang.pubkey,
        fixture.db(),
        HANG_SIGN_TIMEOUT,
        TimeoutPolicy::RetainStagedRow,
        "test_mid_sign_drop",
    );
    let db_blocking = fixture.db();
    let pk = pubkey_hex.clone();

    let join = tokio::task::spawn_blocking(move || match path {
        MidSignPath::Reserve => sess.reserve_then_sign(|| {
            db_blocking.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
        }),
        MidSignPath::Stage => sess.stage_then_sign(|| {
            db_blocking.stage_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
        }),
    });

    wait_until_sign_entered(&hang.entered, &hang.entered_notify).await;
    fixture.drop_writer();

    let reopened = fixture.reopen();
    let blocks = reopened.get_blocks(&pubkey_hex).expect("get_blocks after reopen");
    let row_count = blocks.len();

    let conflict_refused = match path {
        MidSignPath::Reserve => {
            let err = reopened
                .reserve_block(&pubkey_hex, SLOT, Some(root_hex(CONFLICT_ROOT)), &GVR)
                .expect_err(
                    "conflicting slot/root must be refused while the reserved row is present",
                );
            assert_conflict_refused(err, SLOT);
            true
        }
        // The staged guard still holds BEGIN IMMEDIATE; a second writer would block.
        MidSignPath::Stage => false,
    };

    let _ = hang.release_tx.send(());
    let _ = join.await;
    MidSignDropOutcome { row_count, conflict_refused }
}

/// RED first: drop mid-sign, reopen, reserved row exists and a conflict is refused.
/// The same drop against `stage_then_sign` leaves the row absent (guard ROLLBACK).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dropped_future_mid_sign_leaves_the_reserved_row_present() {
    let stage = mid_sign_drop_and_reopen(MidSignPath::Stage).await;
    eprintln!("RED stage_then_sign mid-sign drop: reserved_rows={}", stage.row_count);
    assert_eq!(
        stage.row_count, 0,
        "stage_then_sign mid-sign drop must leave the row absent (uncommitted / ROLLBACK)"
    );

    let reserve = mid_sign_drop_and_reopen(MidSignPath::Reserve).await;
    eprintln!(
        "reserve_then_sign mid-sign drop: reserved_rows={} conflict_refused={}",
        reserve.row_count, reserve.conflict_refused
    );
    assert_eq!(
        reserve.row_count, 1,
        "reserve_then_sign mid-sign drop must leave the reserved row present; found {}",
        reserve.row_count
    );
    assert!(reserve.conflict_refused, "conflicting reserve must be refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_panic_in_the_sign_backend_leaves_the_reserved_row_present() {
    let mut fixture = ReopenableDb::new();
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let sess = session(
        Arc::new(PanicSigner),
        &pubkey,
        fixture.db(),
        Duration::from_secs(4),
        TimeoutPolicy::RetainStagedRow,
        "test_panic_backend",
    );
    let db_blocking = fixture.db();
    let pk = pubkey_hex.clone();

    let join = tokio::task::spawn_blocking(move || {
        sess.reserve_then_sign(|| {
            db_blocking.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
        })
    });
    let join_result = join.await;
    assert!(
        join_result.as_ref().is_err_and(|e| e.is_panic()),
        "blocking task must surface the backend panic, got: {join_result:?}"
    );

    fixture.drop_writer();
    let reopened = fixture.reopen();
    let blocks = reopened.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "panic after reserve must leave the row present; found {blocks:?}");
    let err = reopened
        .reserve_block(&pubkey_hex, SLOT, Some(root_hex(CONFLICT_ROOT)), &GVR)
        .expect_err("conflicting reserve must be refused");
    assert_conflict_refused(err, SLOT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cancellation_before_the_blocking_task_starts_leaves_no_row() {
    let mut fixture = ReopenableDb::new();
    let (pubkey, signer) = make_local(SecretKey::generate());
    let pubkey_bytes = pubkey.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let locks = Arc::new(ValidatorLockMap::new());
    let held = locks.lock(&pubkey_bytes).await;

    let sess = session(
        signer,
        &pubkey,
        fixture.db(),
        Duration::from_secs(4),
        TimeoutPolicy::RetainStagedRow,
        "test_cancel_before_blocking",
    );
    let locks_c = Arc::clone(&locks);
    let db_c = fixture.db();
    let pk = pubkey_hex.clone();
    let wrapper = async move {
        let _guard = locks_c.lock(&pubkey_bytes).await;
        tokio::task::spawn_blocking(move || {
            sess.reserve_then_sign(|| {
                db_c.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
            })
        })
        .await
    };

    let join = tokio::spawn(wrapper);
    tokio::time::sleep(Duration::from_millis(30)).await;
    join.abort();
    let aborted = join.await;
    assert!(aborted.is_err(), "wrapper must be cancelled while waiting on the pubkey lock");

    drop(held);
    fixture.drop_writer();
    let reopened = fixture.reopen();
    let blocks = reopened.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(blocks.is_empty(), "cancellation before reserve must leave no row; found {blocks:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_abandoned_reservation_still_permits_an_identical_resign() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("slashing.sqlite");
    let pubkey_hex = {
        let sk = SecretKey::generate();
        hex::encode(sk.public_key().to_bytes())
    };

    {
        let db = SlashingDb::open(&path).expect("open");
        let reservation = db
            .reserve_block(&pubkey_hex, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
            .expect("reserve");
        assert!(reservation.inserted);
        drop(reservation);
        drop(db);
    }

    let reopened = SlashingDb::open(&path).expect("reopen after process-kill simulation");
    let blocks = reopened.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "abandoned reservation must survive reopen; found {blocks:?}");

    let conflict = reopened
        .reserve_block(&pubkey_hex, SLOT, Some(root_hex(CONFLICT_ROOT)), &GVR)
        .expect_err("conflicting reserve must be refused");
    assert_conflict_refused(conflict, SLOT);

    let resign = reopened
        .reserve_block(&pubkey_hex, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
        .expect("identical re-sign must remain allowed");
    assert!(!resign.inserted, "EIP-3076 Resign must report inserted == false");
    assert_eq!(
        reopened.get_blocks(&pubkey_hex).expect("get_blocks after resign").len(),
        1,
        "resign must not insert a second row"
    );
}

/// Production shape after the lock-lifetime fix: Discard + drop the outer
/// future must not free the pubkey lock while `reserve_then_sign` is still in
/// `sign()`. A same-root retry must wait; first times out and reconciles
/// (unsigned row gone). That is Discard, not a double-sign window.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_discard_mid_sign_drop_does_not_free_a_slot_another_request_signed() {
    const DISCARD_TIMEOUT: Duration = Duration::from_millis(200);

    let mut fixture = ReopenableDb::new();
    let hang = hanging_pair(SecretKey::generate());
    let pubkey_bytes = hang.pubkey.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let locks = Arc::new(ValidatorLockMap::new());
    // Dropping this sender would unblock `sign()` onto success; keep it live.
    let _hold_release = hang.release_tx;
    let sess = session(
        hang.signer,
        &hang.pubkey,
        fixture.db(),
        DISCARD_TIMEOUT,
        TimeoutPolicy::DiscardStagedRow,
        "test_discard_mid_sign_drop",
    );

    let (done_tx, done_rx) = oneshot::channel();
    let db_blocking = fixture.db();
    let pk = pubkey_hex.clone();
    let guard = locks.lock(&pubkey_bytes).await;
    let blocking = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let result = sess.reserve_then_sign(|| {
            db_blocking.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
        });
        let _ = done_tx.send(());
        result
    });

    let outer = tokio::spawn(blocking);
    wait_until_sign_entered(&hang.entered, &hang.entered_notify).await;
    fixture.drop_writer();
    outer.abort();
    let _ = outer.await;

    assert!(
        locks.get(&pubkey_bytes).try_lock().is_err(),
        "dropping the outer future must not release the lock while sign() is in flight"
    );

    let retry_db = fixture.reopen();
    let retry_locks = Arc::clone(&locks);
    let retry_pk = pubkey_hex.clone();
    let retry_got_lock = Arc::new(AtomicBool::new(false));
    let empty_when_acquired = Arc::new(AtomicBool::new(false));
    let got_c = Arc::clone(&retry_got_lock);
    let empty_c = Arc::clone(&empty_when_acquired);
    let retry = tokio::spawn(async move {
        let _g = retry_locks.lock(&pubkey_bytes).await;
        got_c.store(true, Ordering::SeqCst);
        let n = retry_db.get_blocks(&retry_pk).expect("get_blocks under retry lock").len();
        empty_c.store(n == 0, Ordering::SeqCst);
        retry_db.reserve_block(&retry_pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !retry.is_finished(),
        "same-root retry must not finish while the first blocking task is still in sign()"
    );
    assert!(
        !retry_got_lock.load(Ordering::SeqCst),
        "same-root retry must not acquire the lock before the first task completes"
    );
    assert!(locks.get(&pubkey_bytes).try_lock().is_err());

    tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("first task must finish via sign timeout, not a released success")
        .expect("done signal");

    let retry_res = tokio::time::timeout(Duration::from_secs(2), retry)
        .await
        .expect("retry must complete after the first task releases the lock")
        .expect("retry join");
    assert!(retry_got_lock.load(Ordering::SeqCst));
    assert!(
        empty_when_acquired.load(Ordering::SeqCst),
        "Discard timeout must delete the unsigned row before the retry reserves"
    );
    let reservation = retry_res.expect("same-root retry after Discard reconcile must reserve");
    assert!(reservation.inserted);

    let reopened = fixture.reopen();
    let err = reopened
        .reserve_block(&pubkey_hex, SLOT, Some(root_hex(CONFLICT_ROOT)), &GVR)
        .expect_err("after the retry inserted, a different root must be refused");
    assert_conflict_refused(err, SLOT);
}

fn assert_send<T: Send>(_: &T) {}

/// Compile-time Send proof for the lock → `spawn_blocking(reserve_then_sign)` future.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reserve_then_sign_future_is_send() {
    let fixture = ReopenableDb::new();
    let (pubkey, signer) = make_local(SecretKey::generate());
    let pubkey_bytes = pubkey.to_bytes();
    let locks = Arc::new(ValidatorLockMap::new());
    let sess = session(
        signer,
        &pubkey,
        fixture.db(),
        Duration::from_secs(4),
        TimeoutPolicy::RetainStagedRow,
        "test_send",
    );
    let locks_c = Arc::clone(&locks);
    let db_c = fixture.db();
    let pk = hex::encode(pubkey_bytes);

    let fut = async move {
        let guard = locks_c.lock(&pubkey_bytes).await;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            sess.reserve_then_sign(|| {
                db_c.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
            })
        })
        .await
    };
    assert_send(&fut);
    // Mirror core.rs's tokio::spawn of the slashable future.
    tokio::spawn(fut).await.expect("join").expect("blocking").expect("reserve_then_sign");
}

/// Batch-boundary (#205): dropping one waiter must not stall the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_cancelled_batch_member_does_not_block_the_others() {
    let mut fixture = ReopenableDb::new();
    fixture.db().set_group_commit(GroupCommitConfig {
        batch_size: 3,
        wait_to_fill: Duration::from_millis(80),
    });
    let abandoned = hex::encode(SecretKey::generate().public_key().to_bytes());
    fixture
        .db()
        .enqueue_and_abandon_block(&abandoned, SLOT, Some(root_hex(CONFLICT_ROOT)), &GVR)
        .expect("abandon");

    let mut joins = Vec::new();
    let mut pubkeys = Vec::new();
    for _ in 0..2 {
        let (pubkey, signer) = make_local(SecretKey::generate());
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        pubkeys.push(pubkey_hex.clone());
        let sess = session(
            signer,
            &pubkey,
            fixture.db(),
            Duration::from_secs(4),
            TimeoutPolicy::RetainStagedRow,
            "test_cancel_batch_member",
        );
        let db_blocking = fixture.db();
        let pk = pubkey_hex;
        joins.push(tokio::task::spawn_blocking(move || {
            sess.reserve_then_sign(|| {
                db_blocking.reserve_block(&pk, SLOT, Some(root_hex(SIGNING_ROOT)), &GVR)
            })
        }));
    }

    for join in joins {
        join.await.expect("join").expect("other members must still sign");
    }
    fixture.drop_writer();
    let reopened = fixture.reopen();
    assert!(
        reopened.get_blocks(&abandoned).expect("abandoned").is_empty(),
        "cancelled member must not insert"
    );
    for pk in &pubkeys {
        assert_eq!(
            reopened.get_blocks(pk).expect("get").len(),
            1,
            "surviving member {pk} must have a reserved row"
        );
    }
}
