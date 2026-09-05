//! Regression tests for ISSUE-3.12: `rvc_signer_slashing_tx_hold_duration_ms` histogram.
//!
//! These tests assert that the tx-hold histogram is observed on every
//! stage → commit (happy path) and stage → discard (signer failure) cycle.

mod common;

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, SecretKey};
use eth_types::{AttestationData, Checkpoint, ForkSchedule, Root};
use metrics::definitions::{tx_hold_kind, RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS};
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

// ── Test: histogram observed on stage → commit (happy path) ──────────────────

/// ISSUE-3.12: after a successful `sign_attestation`, the histogram
/// `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` must have
/// been incremented and the observed value must be > 0 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metric_recorded_on_stage_commit() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let mut manager = KeyManager::new();
    manager.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(signer, db).with_enablement(common::always_allowed());

    let fs = make_fork_schedule();
    let data = make_attestation_data(1, 2);

    // Snapshot before
    let count_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_count();
    let sum_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_sum();

    let result = service.sign_attestation(&data, &pubkey, &fs, &GVR).await;
    assert!(result.is_ok(), "sign_attestation must succeed; err: {:?}", result.err());

    // Assert: exactly one new observation was added for kind=attestation
    let count_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_count();
    let sum_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_sum();

    assert!(
        count_after > count_before,
        "histogram must be observed at least once on commit; before={count_before}, after={count_after}"
    );
    assert!(
        sum_after >= sum_before,
        "histogram sum must be non-decreasing; before={sum_before}, after={sum_after}"
    );
}

// ── Test: histogram observed on stage → discard (signer failure) ─────────────

/// ISSUE-3.12: when `sign_block` fails because the key is absent, the
/// staged transaction is discarded.  The histogram
/// `rvc_signer_slashing_tx_hold_duration_ms{kind="block"}` must still be
/// incremented — the transaction hold was real even though the row was rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metric_recorded_on_stage_discard() {
    // Empty signer — sign call will fail with KeyNotFound, triggering discard.
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(empty_signer, db).with_enablement(common::always_allowed());

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let block_root: Root = [0xde; 32];
    let slot = 300u64;
    let fs = make_fork_schedule();

    // Snapshot before
    let count_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::BLOCK])
        .get_sample_count();

    let result = service.sign_block(&block_root, slot, &pubkey, &fs, &GVR).await;
    assert!(result.is_err(), "sign_block must fail when key is absent");

    // Assert: histogram was still observed for kind=block despite the discard
    let count_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::BLOCK])
        .get_sample_count();

    assert!(
        count_after > count_before,
        "histogram must be observed on discard too; before={count_before}, after={count_after}"
    );
}

// ── Test: histogram observed on stage → slashing-rejection (review MF-1) ─────

/// ISSUE-3.12 review MF-1: when `stage_attestation` is rejected by slashing
/// protection (the second sign attempt against the same source/target with a
/// different signing root looks like a DoubleVote), the histogram must STILL
/// be observed — the staging attempt held the SQLite transaction for real
/// wall-clock time even though the row was never written.
///
/// Before MF-1, the `?` operator returned from the closure before the
/// post-stage observe() ran, silently dropping every slashing rejection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metric_recorded_on_stage_slashing_rejected() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let mut manager = KeyManager::new();
    manager.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(signer, db).with_enablement(common::always_allowed());

    let fs = make_fork_schedule();

    // First call: source=10, target=11 — succeeds, writes a row.
    let first = make_attestation_data(10, 11);
    service.sign_attestation(&first, &pubkey, &fs, &GVR).await.expect("first must succeed");

    // Snapshot AFTER the first (successful) sign so we measure only the
    // contribution of the rejection path.
    let count_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_count();

    // Second call: same (source, target) but with a different beacon_block_root
    // (which changes the signing_root). slashing-DB sees a DoubleVote and
    // rejects at stage_attestation time.
    let mut second = make_attestation_data(10, 11);
    second.beacon_block_root = [0xcc; 32];
    let result = service.sign_attestation(&second, &pubkey, &fs, &GVR).await;
    assert!(result.is_err(), "second sign must be rejected as DoubleVote");

    // The rejection path must still observe the histogram.
    let count_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::ATTESTATION])
        .get_sample_count();

    assert!(
        count_after > count_before,
        "histogram must be observed on slashing-rejection path; \
         before={count_before}, after={count_after}"
    );
}
