//! Regression tests for M-1: phantom slashing-DB records on signer failure.
//!
//! Before the fix, `SignerService::sign_attestation` and `sign_block` called
//! `check_and_record_*` (which committed the row immediately) and only then
//! called `signer.sign`.  A signing failure left a committed row in the DB,
//! causing the next legitimate sign attempt to look like a DoubleVote.
//!
//! After the fix, these methods use the stage + commit-on-success pattern:
//! the row is only committed if `signer.sign` succeeds; on signer failure
//! `discard()` rolls the transaction back, leaving the DB pristine.

#![allow(deprecated)]

mod common;

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, SecretKey};
use eth_types::{AttestationData, Checkpoint, ForkSchedule, Root};
use rvc_signer::{SignerService, ValidatorSigner};
use slashing::SlashingDb;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_fork_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
        altair_fork_epoch: 50,
        altair_fork_version: [0x00, 0x00, 0x00, 0x02],
        bellatrix_fork_epoch: u64::MAX,
        bellatrix_fork_version: [0x00, 0x00, 0x00, 0x03],
        capella_fork_epoch: u64::MAX,
        capella_fork_version: [0x00, 0x00, 0x00, 0x04],
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [0x00, 0x00, 0x00, 0x05],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [0x00, 0x00, 0x00, 0x06],
        fulu_fork_epoch: u64::MAX,
        fulu_fork_version: [0x00, 0x00, 0x00, 0x07],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0x00, 0x00, 0x00, 0x08],
    }
}

fn make_attestation_data(source_epoch: u64, target_epoch: u64) -> AttestationData {
    AttestationData {
        slot: target_epoch * 8,
        index: 0,
        beacon_block_root: [0xbb; 32],
        source: Checkpoint { epoch: source_epoch, root: [0x11; 32] },
        target: Checkpoint { epoch: target_epoch, root: [0x22; 32] },
    }
}

const GVR: Root = [0xaa; 32];

// ── Test: signer failure must not commit any row (attestation) ────────────────

/// M-1 regression: when the signer has no key for the requested pubkey, the
/// signing call fails.  After the fix, the slashing-DB must remain empty.
///
/// Before the fix this test fails because the phantom row IS committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signer_failure_does_not_commit_row_attestation() {
    // Signer with no keys — signing will fail with KeyNotFound.
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(Arc::clone(&empty_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let data = make_attestation_data(10, 11);
    let fs = make_fork_schedule();

    let result = service.sign_attestation(&data, &pubkey, &fs, &GVR).await;

    // Signing must fail.
    assert!(result.is_err(), "expected signing failure when key is absent");

    // M-1 fix: NO row must be committed after signer failure.
    let attestations = db.get_attestations(&pubkey_hex).expect("DB query");
    assert!(
        attestations.is_empty(),
        "M-1 fix: signer failure must not commit a phantom row; found: {attestations:?}"
    );
}

/// M-1 regression: same for `sign_block`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signer_failure_does_not_commit_row_block() {
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(Arc::clone(&empty_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let block_root: Root = [0xde; 32];
    let slot = 100u64;
    let fs = make_fork_schedule();

    let result = service.sign_block(&block_root, slot, &pubkey, &fs, &GVR).await;

    assert!(result.is_err(), "expected signing failure when key is absent");

    let blocks = db.get_blocks(&pubkey_hex).expect("DB query");
    assert!(
        blocks.is_empty(),
        "M-1 fix: signer failure must not commit a phantom block row; found: {blocks:?}"
    );
}

// ── Test: retry with different root succeeds after a signer failure ───────────

/// M-1 regression (phantom-row scenario):
/// 1. First sign call fails (signer error) — must NOT commit a row.
/// 2. Second sign call with a different signing root must succeed (not be
///    rejected as DoubleVote due to a phantom row from step 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_retry_after_signer_failure_succeeds() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    // First call: signer with no key.
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service_fail = SignerService::new(Arc::clone(&empty_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let data_first = make_attestation_data(10, 11);
    let fs = make_fork_schedule();

    let fail_result = service_fail.sign_attestation(&data_first, &pubkey, &fs, &GVR).await;
    assert!(fail_result.is_err(), "first call must fail (no key in signer)");

    // After failure, DB must still be empty.
    let after_fail = db.get_attestations(&pubkey_hex).expect("DB query");
    assert!(after_fail.is_empty(), "no phantom row after signer failure; found: {after_fail:?}");

    // Second call: same data, now with the real key — must succeed.
    let mut manager = KeyManager::new();
    manager.insert(sk);
    let real_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let service_ok = SignerService::new(Arc::clone(&real_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let data_retry = make_attestation_data(10, 11);
    let ok_result = service_ok.sign_attestation(&data_retry, &pubkey, &fs, &GVR).await;
    assert!(
        ok_result.is_ok(),
        "retry with real key must succeed (no phantom DoubleVote row blocking it); err: {:?}",
        ok_result.err()
    );

    // Row must now be present after the successful sign.
    let after_ok = db.get_attestations(&pubkey_hex).expect("DB query");
    assert_eq!(after_ok.len(), 1, "exactly one row must be committed after success");
    assert_eq!(after_ok[0].source_epoch, 10);
    assert_eq!(after_ok[0].target_epoch, 11);
}

// ── Test: successful sign commits the row ─────────────────────────────────────

/// Happy path: a successful sign must persist the row so a subsequent
/// conflicting sign is rejected as DoubleVote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_successful_sign_commits_row_and_double_vote_rejected() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let mut manager = KeyManager::new();
    manager.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(Arc::clone(&signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let data_first = make_attestation_data(20, 30);
    let fs = make_fork_schedule();

    // First sign: must succeed.
    let ok = service.sign_attestation(&data_first, &pubkey, &fs, &GVR).await;
    assert!(ok.is_ok(), "first sign must succeed; err: {:?}", ok.err());

    // Row must be committed.
    let rows = db.get_attestations(&pubkey_hex).expect("DB query");
    assert_eq!(rows.len(), 1, "one row committed after success");
    assert_eq!(rows[0].target_epoch, 30);

    // Second sign with same target but different beacon_block_root (different signing root)
    // must be rejected as DoubleVote.
    let data_conflict = AttestationData {
        slot: data_first.slot,
        index: data_first.index,
        beacon_block_root: [0xff; 32], // changed — produces a different signing root
        source: data_first.source,
        target: data_first.target,
    };
    let conflict = service.sign_attestation(&data_conflict, &pubkey, &fs, &GVR).await;
    assert!(conflict.is_err(), "conflicting sign must be rejected as DoubleVote after commit");
    match conflict.err().unwrap() {
        rvc_signer::SignerError::SlashingBlocked(_) => {}
        other => panic!("expected SlashingBlocked, got: {other}"),
    }
}

/// Same happy-path test for `sign_block`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_successful_sign_block_commits_row_and_double_proposal_rejected() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let mut manager = KeyManager::new();
    manager.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(Arc::clone(&signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let block_root_a: Root = [0xaa; 32];
    let slot = 200u64;
    let fs = make_fork_schedule();

    // First sign: must succeed and commit a row.
    let ok = service.sign_block(&block_root_a, slot, &pubkey, &fs, &GVR).await;
    assert!(ok.is_ok(), "first block sign must succeed; err: {:?}", ok.err());

    let rows = db.get_blocks(&pubkey_hex).expect("DB query");
    assert_eq!(rows.len(), 1, "one block row committed after success");
    assert_eq!(rows[0].slot, slot);

    // Second sign at the same slot with a different root must be rejected.
    let block_root_b: Root = [0xbb; 32];
    let conflict = service.sign_block(&block_root_b, slot, &pubkey, &fs, &GVR).await;
    assert!(conflict.is_err(), "double block proposal must be rejected");
    match conflict.err().unwrap() {
        rvc_signer::SignerError::SlashingBlocked(_) => {}
        other => panic!("expected SlashingBlocked, got: {other}"),
    }
}
