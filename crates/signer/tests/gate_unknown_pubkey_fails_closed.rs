//! RED test: unknown pubkey fails closed on both slashable and non-slashable paths.
//!
//! The fail-closed default is codified via `<bool as FailClosedDefault>::default_when_unknown()`
//! = `false` in the gate's `gate_decision` helper.  Any pubkey that the
//! `SigningEnablement` implementation does not know about returns `false`, which
//! causes the gate to refuse signing (BlockedByDoppelganger).
//!
//! This test is intentionally reused by Issue 2.11; keep its assertions about
//! the fail-closed semantic stable.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use crypto::{PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::SigningGateError;

/// A `SigningEnablement` mock that only allows a pre-registered set of pubkeys.
/// Any unknown pubkey returns `false` — the fail-closed default.
struct KnownOnlyEnablement {
    known: HashSet<Vec<u8>>,
}

impl KnownOnlyEnablement {
    fn new(pubkeys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self { known: pubkeys.into_iter().map(|pk| pk.to_bytes().to_vec()).collect() }
    }
}

impl SigningEnablement for KnownOnlyEnablement {
    fn is_signing_enabled(&self, pubkey: &PublicKey) -> bool {
        // Unknown pubkey → false (fail-closed per FailClosedDefault::default_when_unknown).
        self.known.contains(pubkey.to_bytes().as_slice())
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }
}

const GVR: Root = [0xd3; 32];

/// Slashable path (sign_block): an unregistered pubkey must be refused
/// with `BlockedByDoppelganger` — the fail-closed default applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_pubkey_slashable_path_fails_closed() {
    // Gate knows only the "known" key.
    let known_sk = SecretKey::generate();
    let known_pubkey = known_sk.public_key();

    // Unregistered key — the gate doesn't know about it.
    let unknown_sk = SecretKey::generate();
    let unknown_pubkey = unknown_sk.public_key();

    let db = common::open_db();
    let enablement = Arc::new(KnownOnlyEnablement::new([known_pubkey]));

    // Signer only has the "known" key, but we sign for the unknown pubkey.
    let (_, gate) = common::gate_fixture(known_sk, Arc::clone(&db), enablement);

    let result = gate.sign_block(&unknown_pubkey, 42, [0xfe; 32], GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "unknown pubkey on slashable path must be refused (BlockedByDoppelganger); got: {result:?}"
    );

    // No slashing row must have been written.
    let pubkey_hex = hex::encode(unknown_pubkey.to_bytes());
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(
        blocks.is_empty(),
        "fail-closed gate must not write any slashing row for unknown pubkey; found: {blocks:?}"
    );
}

/// Non-slashable path (sign_randao_reveal): an unregistered pubkey must also
/// be refused — the same gate_decision helper covers both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_pubkey_nonslashable_path_fails_closed() {
    let known_sk = SecretKey::generate();
    let known_pubkey = known_sk.public_key();

    let unknown_sk = SecretKey::generate();
    let unknown_pubkey = unknown_sk.public_key();

    let db = common::open_db();
    let enablement = Arc::new(KnownOnlyEnablement::new([known_pubkey]));

    let (_, gate) = common::gate_fixture(known_sk, Arc::clone(&db), enablement);

    let signing_root: Root = [0xef; 32];
    let result = gate.sign_randao_reveal(&unknown_pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "unknown pubkey on non-slashable path must be refused (BlockedByDoppelganger); \
         got: {result:?}"
    );
}
