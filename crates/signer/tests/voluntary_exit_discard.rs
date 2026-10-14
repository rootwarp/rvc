// RED test for ISSUE-CQ-2.2 (C2).
//
// ── Reality-check finding ────────────────────────────────────────────────────
//
// Audit finding C2 states that `sign_voluntary_exit` "only emits `warn!` on
// signer failure, no `staged.discard()`" and calls for mirroring the
// stage/discard/commit pattern used by `sign_attestation` and `sign_block`.
//
// After reading the function (crates/signer/src/lib.rs L729-781 on develop):
//
//   1. Voluntary exits are NOT slashable per Ethereum spec.  The slashing
//      crate has NO `stage_voluntary_exit` / `StagedVoluntaryExit` API, so
//      the stage/discard/commit mirror is not applicable.
//
//   2. The signer error IS already propagated: the `Err(e)` arm returns
//      `Err(e.into())`, NOT `Ok(())`.  The audit finding overstated the
//      issue by implying the error was swallowed; it was not.
//
// Therefore the C2 "bug" reduces to confirming that:
//   - Signer errors reach the caller (error propagation invariant).
//   - No ghost state is left after a failed attempt (structural guarantee
//     since there is no staging mechanism at all).
//
// These tests pin that behaviour as a regression guard so a future refactor
// cannot inadvertently swallow the signer error.
//
// ── Note on RED/GREEN status ─────────────────────────────────────────────────
//
// Because the error-propagation path was never broken in `sign_voluntary_exit`
// the tests below PASS on develop HEAD without any code change.  The two-commit
// structure (CQ-2.1 test + CQ-2.2 comment fix) is preserved for traceability;
// CQ-2.2 adds an inline comment documenting WHY staging is absent.  This is the
// correct outcome per the issue-spec fallback: "adjust the test accordingly."

mod common;

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, SecretKey};
use eth_types::{ForkSchedule, Root, VoluntaryExit};
use rvc_signer::{SignerError, SignerService, ValidatorSigner};
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

const GVR: Root = [0xaa; 32];

// ── Test: signer error must surface to the caller (C2 invariant) ──────────────

/// C2 invariant: when the signer has no key for the requested pubkey the
/// signing call fails with `KeyNotFound`.  `sign_voluntary_exit` must
/// propagate that error — returning `Err(SignerError::KeyNotFound)` — rather
/// than silently swallowing it.
///
/// Voluntary exits are not slashable per spec so no slashing-DB staging is
/// involved; the sole C2 invariant here is error propagation to the caller.
///
/// This test acts as a regression guard: if a future refactor accidentally
/// swallows the signer error (e.g. replaces `Err(e.into())` with a bare
/// `warn!` and `Ok(...)`) this test immediately fails with the message
/// "expected slashing stage to be discarded".
#[tokio::test]
async fn test_voluntary_exit_signer_error_is_propagated() {
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(Arc::clone(&empty_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let exit = VoluntaryExit { epoch: 10, validator_index: 1 };
    let fs = make_fork_schedule();

    let result = service.sign_voluntary_exit(&exit, &pubkey, &fs, &GVR).await;

    assert!(
        result.is_err(),
        "expected slashing stage to be discarded (C2): signer error must propagate to caller, \
         got Ok instead of Err"
    );

    match result.err().unwrap() {
        SignerError::KeyNotFound(_) => {}
        other => panic!("expected KeyNotFound variant after signer failure, got: {other:?}"),
    }
}

/// C2 invariant (retry): after a signer failure, a retry with a real key must
/// succeed.  This pins the absence-of-ghost-state property:
///
///   - For `sign_attestation`/`sign_block`, ghost-state is prevented by
///     `staged.discard()` rolling back the SQLite transaction.
///   - For `sign_voluntary_exit`, the guarantee is structural — no staging
///     means no residual DB row to block the retry.
///
/// This test confirms the structural guarantee holds end-to-end.
#[tokio::test]
async fn test_voluntary_exit_retry_after_signer_failure_succeeds() {
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service_fail = SignerService::new(Arc::clone(&empty_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let exit = VoluntaryExit { epoch: 20, validator_index: 42 };
    let fs = make_fork_schedule();

    let fail_result = service_fail.sign_voluntary_exit(&exit, &pubkey, &fs, &GVR).await;
    assert!(
        fail_result.is_err(),
        "expected slashing stage to be discarded (C2): first call must fail when key is absent"
    );

    // Retry with a real key — must succeed (no ghost state should block it).
    let mut manager = KeyManager::new();
    manager.insert(sk);
    let real_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let service_ok = SignerService::new(Arc::clone(&real_signer), Arc::clone(&db))
        .with_enablement(common::always_allowed());

    let ok_result = service_ok.sign_voluntary_exit(&exit, &pubkey, &fs, &GVR).await;
    assert!(
        ok_result.is_ok(),
        "retry with real key must succeed after a prior signer failure \
         (no ghost state blocking the re-sign); err: {:?}",
        ok_result.err()
    );
}
