//! Issue #205: group-commit batch boundary.
//!
//! A failed COMMIT rejects every member. A slashable rule-check rejects only
//! that member. A cancelled waiter must not stall the others. No test is named
//! `*_root` (KAT-first name scanner, A-5.10).

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, GroupCommitConfig, SlashingDb,
    SlashingError,
};

const GVR: [u8; 32] = [0u8; 32];

fn pk(i: u8) -> String {
    format!("0xgc{i:02x}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

fn root(i: u8) -> String {
    format!("0xgcroot{i:02x}")
}

fn batching_db(batch_size: usize) -> Arc<SlashingDb> {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.set_group_commit(GroupCommitConfig { batch_size, wait_to_fill: Duration::from_millis(80) });
    db
}

#[test]
fn test_commit_failure_rejects_every_member_of_the_batch() {
    let db = batching_db(3);
    db.fail_next_commits(1);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for i in 0..3 {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let pk = pk(i);
        handles.push(thread::spawn(move || {
            barrier.wait();
            db.reserve_block(&pk, 1, Some(root(i)), &GVR)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().expect("join")).collect();
    assert_eq!(results.len(), 3);
    for r in &results {
        let err = r.as_ref().expect_err("every member must be rejected when COMMIT fails");
        assert!(err.is_reserve_commit_failure(), "expected ReserveCommitFailed, got: {err:?}");
    }
    for i in 0..3 {
        assert!(
            db.get_blocks(&pk(i)).expect("get").is_empty(),
            "rolled-back batch must leave no row for {}",
            pk(i)
        );
    }
}

#[test]
fn test_slashable_member_does_not_reject_the_rest_of_the_batch() {
    let db = batching_db(3);
    let barrier = Arc::new(Barrier::new(3));

    let db_ok = Arc::clone(&db);
    let b_ok = Arc::clone(&barrier);
    let pk_a = pk(0);
    let t_ok = thread::spawn(move || {
        b_ok.wait();
        db_ok.reserve_block(&pk_a, 10, Some(root(1)), &GVR)
    });

    let db_bad = Arc::clone(&db);
    let b_bad = Arc::clone(&barrier);
    let pk_a_conflict = pk(0);
    let t_bad = thread::spawn(move || {
        b_bad.wait();
        db_bad.reserve_block(&pk_a_conflict, 10, Some(root(2)), &GVR)
    });

    let db_other = Arc::clone(&db);
    let b_other = Arc::clone(&barrier);
    let pk_b = pk(1);
    let t_other = thread::spawn(move || {
        b_other.wait();
        db_other.reserve_block(&pk_b, 11, Some(root(3)), &GVR)
    });

    let r_ok = t_ok.join().expect("join ok");
    let r_bad = t_bad.join().expect("join bad");
    let r_other = t_other.join().expect("join other");

    let ok_count = usize::from(r_ok.is_ok()) + usize::from(r_bad.is_ok());
    assert_eq!(ok_count, 1, "exactly one of the conflicting slot-10 reserves must succeed");
    let slashable = if r_ok.is_err() { &r_ok } else { &r_bad };
    match slashable.as_ref().expect_err("slashable") {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(*slot, 10);
        }
        other => panic!("expected DoubleBlockProposal, got {other:?}"),
    }
    assert!(
        !slashable.as_ref().expect_err("slashable").is_reserve_commit_failure(),
        "a rule-check must not collapse into ReserveCommitFailed"
    );
    assert!(r_other.is_ok(), "unrelated member must still commit; got {r_other:?}");
    assert_eq!(db.get_blocks(&pk(0)).expect("get A").len(), 1);
    assert_eq!(db.get_blocks(&pk(1)).expect("get B").len(), 1);
}

#[test]
fn test_cancelled_member_does_not_block_the_others() {
    let db = batching_db(3);
    db.enqueue_and_abandon_block(&pk(9), 99, Some(root(9)), &GVR).expect("abandon");

    let barrier = Arc::new(Barrier::new(2));
    let db_a = Arc::clone(&db);
    let b_a = Arc::clone(&barrier);
    let pk_a = pk(0);
    let t_a = thread::spawn(move || {
        b_a.wait();
        db_a.reserve_block(&pk_a, 1, Some(root(1)), &GVR)
    });
    let db_b = Arc::clone(&db);
    let b_b = Arc::clone(&barrier);
    let pk_b = pk(1);
    let t_b = thread::spawn(move || {
        b_b.wait();
        db_b.reserve_block(&pk_b, 2, Some(root(2)), &GVR)
    });

    let a = t_a.join().expect("join A").expect("A must reserve");
    let b = t_b.join().expect("join B").expect("B must reserve");
    assert!(a.inserted && b.inserted);
    assert!(
        db.get_blocks(&pk(9)).expect("abandoned").is_empty(),
        "cancelled member must not insert"
    );
    assert_eq!(db.get_blocks(&pk(0)).expect("A").len(), 1);
    assert_eq!(db.get_blocks(&pk(1)).expect("B").len(), 1);
}

#[test]
fn test_group_commit_defaults_are_the_measured_quantum() {
    let cfg = GroupCommitConfig::default();
    assert_eq!(cfg.batch_size, 50);
    assert_eq!(cfg.wait_to_fill, Duration::from_millis(1));
}

#[test]
fn test_try_from_knobs_rejects_zero_batch_and_oversized_wait() {
    assert!(GroupCommitConfig::try_from_knobs(Some(0), None).is_err());
    assert!(GroupCommitConfig::try_from_knobs(None, Some(4000)).is_err());
    let ok = GroupCommitConfig::try_from_knobs(Some(50), Some(1)).expect("defaults");
    assert_eq!(ok.batch_size, 50);
}

#[test]
fn test_attestation_commit_failure_rejects_every_member_of_the_batch() {
    let db = batching_db(3);
    db.fail_next_commits(1);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for i in 0..3 {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let pk = pk(i);
        handles.push(thread::spawn(move || {
            barrier.wait();
            db.reserve_attestation(&pk, 1, 2, Some(root(i)), &GVR)
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        let err = h.join().expect("join").expect_err("COMMIT fail must reject");
        assert!(err.is_reserve_commit_failure(), "member {i}: {err:?}");
        assert!(db.get_attestations(&pk(i as u8)).expect("get").is_empty());
    }
}

#[test]
fn test_slashable_attestation_does_not_reject_a_block_sibling() {
    let db = batching_db(3);
    db.reserve_attestation(&pk(0), 1, 5, Some(root(1)), &GVR).expect("seed att");
    let barrier = Arc::new(Barrier::new(2));

    let db_bad = Arc::clone(&db);
    let b_bad = Arc::clone(&barrier);
    let pk_a = pk(0);
    let t_bad = thread::spawn(move || {
        b_bad.wait();
        db_bad.reserve_attestation(&pk_a, 1, 5, Some(root(2)), &GVR)
    });

    let db_ok = Arc::clone(&db);
    let b_ok = Arc::clone(&barrier);
    let pk_b = pk(1);
    let t_ok = thread::spawn(move || {
        b_ok.wait();
        db_ok.reserve_block(&pk_b, 11, Some(root(3)), &GVR)
    });

    let r_bad = t_bad.join().expect("join bad");
    let r_ok = t_ok.join().expect("join ok");
    match r_bad.expect_err("double vote") {
        SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
            target_epoch,
        }) => {
            assert_eq!(target_epoch, 5);
        }
        other => panic!("expected DoubleVote, got {other:?}"),
    }
    assert!(r_ok.is_ok(), "block sibling must commit; {r_ok:?}");
    assert_eq!(db.get_attestations(&pk(0)).expect("att").len(), 1);
    assert_eq!(db.get_blocks(&pk(1)).expect("block").len(), 1);
}

#[test]
fn test_commit_failure_keeps_slashable_error_for_that_member() {
    let db = batching_db(2);
    db.reserve_block(&pk(0), 10, Some(root(1)), &GVR).expect("seed");
    db.fail_next_commits(1);
    let barrier = Arc::new(Barrier::new(2));

    let db_bad = Arc::clone(&db);
    let b_bad = Arc::clone(&barrier);
    let pk_a = pk(0);
    let t_bad = thread::spawn(move || {
        b_bad.wait();
        db_bad.reserve_block(&pk_a, 10, Some(root(2)), &GVR)
    });
    let db_ok = Arc::clone(&db);
    let b_ok = Arc::clone(&barrier);
    let pk_b = pk(1);
    let t_ok = thread::spawn(move || {
        b_ok.wait();
        db_ok.reserve_block(&pk_b, 11, Some(root(3)), &GVR)
    });

    let r_bad = t_bad.join().expect("join bad");
    let r_ok = t_ok.join().expect("join ok");
    match r_bad.expect_err("slashable") {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 10);
        }
        other => panic!("slashable member must keep DoubleBlockProposal, got {other:?}"),
    }
    assert!(
        r_ok.expect_err("ok member rolled back").is_reserve_commit_failure(),
        "would-be insert must become ReserveCommitFailed"
    );
    assert_eq!(db.get_blocks(&pk(0)).expect("seed").len(), 1);
    assert!(db.get_blocks(&pk(1)).expect("rolled back").is_empty());
}

#[test]
fn test_in_txn_gvr_recheck_rejects_after_pin() {
    let db = batching_db(2);
    let r1: [u8; 32] = [0x11; 32];
    let r2: [u8; 32] = [0x22; 32];
    let db_a = Arc::clone(&db);
    let pk_a = pk(0);
    let t_a = thread::spawn(move || db_a.reserve_block(&pk_a, 1, Some(root(1)), &r1));
    // Wait-to-fill does not hold `conn`, so a pin here is visible at INSERT.
    thread::sleep(Duration::from_millis(20));
    db.set_genesis_validators_root(&r2).expect("pin r2 during wait-to-fill");
    let err = t_a.join().expect("join").expect_err("must reject after pin");
    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, r2);
            assert_eq!(got, r1);
        }
        other => panic!("expected GenesisRootMismatch, got {other:?}"),
    }
    assert!(db.get_blocks(&pk(0)).expect("get").is_empty());
}

#[test]
fn test_drop_during_eval_skips_insert() {
    let db = batching_db(2);
    let (entered, release) = db.block_next_eval();
    let db_a = Arc::clone(&db);
    let pk_a = pk(0);
    let t_a = thread::spawn(move || db_a.reserve_block(&pk_a, 1, Some(root(1)), &GVR));
    thread::sleep(Duration::from_millis(20));
    let handle = db.enqueue_block_cancellable(&pk(1), 2, Some(root(2)), &GVR).expect("enqueue B");
    handle.arm();
    entered.recv_timeout(Duration::from_secs(2)).expect("eval entered");
    drop(handle);
    drop(release);
    t_a.join().expect("join A").expect("A must reserve");
    assert_eq!(db.get_blocks(&pk(0)).expect("A").len(), 1);
    assert!(db.get_blocks(&pk(1)).expect("B").is_empty(), "cancelled member must not insert");
}

#[test]
fn test_committed_member_returns_while_later_batch_is_stalled() {
    let db = batching_db(2);
    db.skip_eval_gates(2);
    let (entered, release) = db.block_next_eval();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let barrier = Arc::new(Barrier::new(3));
    let mut joins = Vec::new();
    for i in 0..3u8 {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let done_tx = done_tx.clone();
        let pk = pk(i);
        joins.push(thread::spawn(move || {
            barrier.wait();
            let r = db.reserve_block(&pk, u64::from(i) + 1, Some(root(i)), &GVR);
            let _ = done_tx.send(i);
            r
        }));
    }
    drop(done_tx);
    entered.recv_timeout(Duration::from_secs(2)).expect("later batch entered eval");
    let finished = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("a member of the first durable batch must return before a later COMMIT");
    assert!(finished < 3, "got {finished}");
    drop(release);
    for h in joins {
        h.join().expect("join").expect("all must finish");
    }
}

/// Reserves that arrive together must each get a commit result.
///
/// The waiter is armed before the item is queued. A leader that drains during
/// enqueue must not drop a live member as "worker disconnected".
#[test]
fn concurrent_reserves_all_receive_a_commit_result() {
    let db = batching_db(8);
    let n = 64;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let i = u8::try_from(i).expect("index");
            db.reserve_block(&pk(i), u64::from(i) + 1, Some(root(i)), &GVR)
        }));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.join().expect("join");
        assert!(result.is_ok(), "reserve {i} must commit, got {result:?}");
    }
}
