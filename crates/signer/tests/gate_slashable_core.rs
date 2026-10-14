//! RF4-05: SigningGate delegates to `sign_slashable` — metrics + enablement recheck.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::metrics::{
    slashing_result, tx_hold_kind, RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS,
    RVC_SIGNING_DURATION_SECONDS, RVC_SLASHING_PROTECTION_CHECKS_TOTAL,
};
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};

const GVR: Root = [0xa5; 32];

struct FlipEnablement {
    enabled: AtomicBool,
}
impl SigningEnablement for FlipEnablement {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
}

/// Gate records the same metric families as SignerService on success and on block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gate_metrics_recorded_on_success_and_on_block() {
    let db = common::open_db();
    let (pubkey, gate) = common::gate_allowed(SecretKey::generate(), Arc::clone(&db));

    let safe_before =
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).get();
    let blocked_before =
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::BLOCKED]).get();
    let hold_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::BLOCK])
        .get_sample_count();
    let dur_before =
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).get_sample_count();

    // Success path.
    let ok = gate.sign_block(&pubkey, 100, [0x01; 32], GVR, "test").await;
    assert!(ok.is_ok(), "first sign_block must succeed: {ok:?}");

    let safe_after =
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).get();
    let hold_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&[tx_hold_kind::BLOCK])
        .get_sample_count();
    let dur_after =
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).get_sample_count();

    assert!(safe_after > safe_before, "safe check metric must increment on success");
    assert!(hold_after > hold_before, "tx-hold metric must increment on success");
    assert!(dur_after > dur_before, "signing duration metric must increment on success");

    // Blocked path (double proposal, different root).
    let blocked = gate.sign_block(&pubkey, 100, [0x02; 32], GVR, "test").await;
    assert!(
        matches!(blocked, Err(SigningGateError::SlashingBlocked(_))),
        "conflicting block must be SlashingBlocked: {blocked:?}"
    );

    let blocked_after =
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::BLOCKED]).get();
    assert!(
        blocked_after > blocked_before,
        "blocked check metric must increment on slashing rejection"
    );
}

/// Gate re-checks enablement under the per-validator lock (Safe→Detected TOCTOU).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gate_reenables_check_under_lock() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let mut km = KeyManager::new();
    km.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)));
    let db = common::open_db();
    let locks = Arc::new(ValidatorLockMap::new());
    let enablement = Arc::new(FlipEnablement { enabled: AtomicBool::new(true) });
    let gate = SigningGate::new(
        Arc::clone(&db),
        Arc::clone(&enablement) as Arc<dyn SigningEnablement>,
        signer,
        Arc::clone(&locks),
    );

    // Hold the lock so sign_block waits after its outer enablement check.
    let held = locks.lock(&pubkey_bytes).await;

    let pk = pubkey.clone();
    let join = tokio::spawn(async move { gate.sign_block(&pk, 55, [0xab; 32], GVR, "test").await });

    tokio::time::sleep(Duration::from_millis(20)).await;
    enablement.enabled.store(false, Ordering::SeqCst);
    drop(held);

    let result = join.await.expect("join");
    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "under-lock recheck must refuse after flip; got {result:?}"
    );

    // No phantom row.
    let pubkey_hex = hex::encode(pubkey_bytes);
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(blocks.is_empty(), "blocked recheck must not write a row: {blocks:?}");
}
