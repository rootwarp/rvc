//! Smoke tests for the `SigningEnablement` and `FailClosedDefault` trait seams
//! (Issue 1.3).  These tests verify the trait contracts without exercising any
//! production consumer or implementor.

use crypto::SecretKey;
use rvc_signer::{FailClosedDefault, SigningEnablement};

/// A minimal deny-all implementation used only in these smoke tests.
struct DenyAll;

impl SigningEnablement for DenyAll {
    fn is_signing_enabled(&self, _pubkey: &crypto::PublicKey) -> bool {
        false
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }

    fn blocked_by_doppelganger(&self, _pubkey: &crypto::PublicKey) -> bool {
        false
    }
}

#[test]
fn deny_all_returns_false_for_any_pubkey() {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let gate = DenyAll;
    assert!(!gate.is_signing_enabled(&pubkey));
}

#[test]
fn signing_enablement_is_object_safe() {
    let _: &dyn SigningEnablement = &DenyAll;
}

#[test]
fn bool_fail_closed_default_is_false() {
    assert!(!<bool as FailClosedDefault>::default_when_unknown());
}
