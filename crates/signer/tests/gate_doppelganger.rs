//! Doppelganger-blocked gate paths: enablement=false → BlockedByDoppelganger,
//! no slashing-DB row on slashable methods.
//!
//! Consolidates the former single-test binaries:
//! - `gate_block_doppelganger_blocked.rs`
//! - `gate_attestation_doppelganger_blocked.rs`
//! - `gate_sync_doppelganger_blocked.rs` (non-slashable methods)

mod common;

use std::sync::Arc;

use crypto::SecretKey;
use eth_types::Root;
use rvc_signer::SigningGateError;

const GVR: Root = [0xd3; 32];

// ── Slashable: block ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_block_blocked_by_doppelganger_no_row_committed() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signing_root: Root = [0xbe; 32];
    let slot = 42u64;

    let result = gate.sign_block(&pubkey, slot, signing_root, GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );

    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks must not fail");
    assert!(
        blocks.is_empty(),
        "doppelganger block must not commit any slashing-DB row; found: {blocks:?}"
    );
}

// ── Slashable: attestation ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_attestation_blocked_by_doppelganger_no_row_committed() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signing_root: Root = [0xbe; 32];
    let source_epoch = 10u64;
    let target_epoch = 11u64;

    let result =
        gate.sign_attestation(&pubkey, source_epoch, target_epoch, signing_root, GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );

    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations must not fail");
    assert!(
        attestations.is_empty(),
        "doppelganger block must not commit any slashing-DB row; found: {attestations:?}"
    );
}

// ── Non-slashable methods (former gate_sync_doppelganger_blocked) ────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_sync_committee_message_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x11; 32];
    let result = gate.sign_sync_committee_message(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_contribution_and_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x22; 32];
    let result = gate.sign_contribution_and_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_aggregate_and_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x33; 32];
    let result = gate.sign_aggregate_and_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_selection_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x44; 32];
    let result = gate.sign_selection_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_randao_reveal_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x55; 32];
    let result = gate.sign_randao_reveal(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_voluntary_exit_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x66; 32];
    let result = gate.sign_voluntary_exit(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_builder_registration_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x77; 32];
    let result = gate.sign_builder_registration(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_payload_attestation_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x88; 32];
    let result = gate.sign_payload_attestation(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_proposer_preferences_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let signing_root: Root = [0x99; 32];
    let result = gate.sign_proposer_preferences(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}
