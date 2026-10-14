//! Shared gate / enablement fixtures for `rvc-signer` integration tests.
//!
//! Each top-level `tests/*.rs` binary is a separate crate; this module is the
//! single home for `AlwaysAllowed` / `AlwaysDenied` and the
//! `KeyManager → LocalSigner → CompositeSigner → SigningGate` builder so gate
//! suites stop re-implementing the same mocks.
//!
//! `dead_code` is allowed: each binary only exercises a subset of the helpers.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use crypto::{
    CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer, SigningError,
};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, ValidatorLockMap};
use slashing::SlashingDb;

// ── Enablement mocks (sole definitions in crates/signer) ─────────────────────

/// Permits every pubkey. Integration-test twin of [`rvc_signer::AlwaysEnabled`]
/// (that helper stays behind `test-utils` / unit-test `cfg(test)` for cross-crate
/// use; unit tests and `rvc` already consume it).
pub struct AlwaysAllowed;

impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

/// Denies every pubkey (active doppelganger window or fail-closed unknown key).
pub struct AlwaysDenied;

impl SigningEnablement for AlwaysDenied {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

#[must_use]
pub fn always_allowed() -> Arc<dyn SigningEnablement> {
    Arc::new(AlwaysAllowed)
}

#[must_use]
pub fn always_denied() -> Arc<dyn SigningEnablement> {
    Arc::new(AlwaysDenied)
}

// ── Composite signer builders ────────────────────────────────────────────────

/// Insert `sk` into a fresh [`KeyManager`] and wrap as [`CompositeSigner`].
#[must_use]
pub fn composite_with_key(sk: SecretKey) -> (PublicKey, Arc<CompositeSigner>) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    (pubkey, Arc::new(CompositeSigner::new(LocalSigner::new(km))))
}

/// Empty key manager — every sign fails with key-not-found.
#[must_use]
pub fn empty_composite() -> Arc<CompositeSigner> {
    Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
}

// ── Gate fixture ─────────────────────────────────────────────────────────────

/// Build `KeyManager → LocalSigner → CompositeSigner → SigningGate` for `sk`.
#[must_use]
pub fn gate_fixture(
    sk: SecretKey,
    db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
) -> (PublicKey, SigningGate) {
    let (pubkey, signer) = composite_with_key(sk);
    let gate = SigningGate::new(db, enablement, signer, Arc::new(ValidatorLockMap::new()));
    (pubkey, gate)
}

/// Gate with [`AlwaysAllowed`] enablement and a real local key.
#[must_use]
pub fn gate_allowed(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    gate_fixture(sk, db, always_allowed())
}

/// Gate with [`AlwaysDenied`] enablement and a real local key.
#[must_use]
pub fn gate_denied(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    gate_fixture(sk, db, always_denied())
}

/// Gate whose BLS backend holds no keys (enablement still open).
#[must_use]
pub fn gate_empty_signer(db: Arc<SlashingDb>) -> SigningGate {
    SigningGate::new(db, always_allowed(), empty_composite(), Arc::new(ValidatorLockMap::new()))
}

/// Gate with a custom raw [`Signer`] backend (timeout / fault injection).
#[must_use]
pub fn gate_with_raw_signer(
    db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
    signer: Arc<dyn Signer>,
    sign_timeout: std::time::Duration,
) -> SigningGate {
    SigningGate::new_with_raw_signer(
        db,
        enablement,
        signer,
        Arc::new(ValidatorLockMap::new()),
        sign_timeout,
    )
}

/// In-memory slashing DB for a single test.
#[must_use]
pub fn open_db() -> Arc<SlashingDb> {
    Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"))
}

/// Valid-curve mock BLS signature (bytes not stable across calls).
#[must_use]
pub fn mock_sig(tag: &[u8]) -> Signature {
    SecretKey::generate().sign(tag)
}

// ── Fault signers (ARCH-5j matrix) ───────────────────────────────────────────
// Classification is asserted against `SigningError::is_unambiguous_no_signature`
// (VD-5.3) so the backends cannot drift from the production classifier.

/// Local BLS success.
pub struct SucceedingSigner {
    inner: LocalSigner,
}

impl SucceedingSigner {
    #[must_use]
    pub fn new(sk: SecretKey) -> Self {
        let mut km = KeyManager::new();
        km.insert(sk);
        Self { inner: LocalSigner::new(km) }
    }
}

#[async_trait]
impl Signer for SucceedingSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

/// Sleeps longer than the session `sign_timeout`.
pub struct HangingSigner {
    sleep: Duration,
}

impl HangingSigner {
    #[must_use]
    pub fn exceeding(timeout: Duration) -> Self {
        Self { sleep: timeout.saturating_add(Duration::from_millis(350)) }
    }
}

#[async_trait]
impl Signer for HangingSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        tokio::time::sleep(self.sleep).await;
        Err(SigningError::RemoteSignerError("hang completed after timeout".into()))
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// Remote verify-fail: ambiguous (signature bytes may already exist on the wire).
pub struct AmbiguousErrorSigner;

impl AmbiguousErrorSigner {
    #[must_use]
    pub fn classified_error() -> SigningError {
        let err = SigningError::InvalidRemoteSignature;
        assert!(
            !err.is_unambiguous_no_signature(),
            "AmbiguousErrorSigner must stay outside is_unambiguous_no_signature (VD-5.3)"
        );
        err
    }
}

#[async_trait]
impl Signer for AmbiguousErrorSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        Err(Self::classified_error())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// `SigningError::KeyNotFound` — unambiguous no-signature.
pub struct KeyNotFoundSigner;

impl KeyNotFoundSigner {
    #[must_use]
    pub fn classified_error() -> SigningError {
        let err = SigningError::KeyNotFound("retain-matrix".into());
        assert!(
            err.is_unambiguous_no_signature(),
            "KeyNotFound must stay is_unambiguous_no_signature (VD-5.3)"
        );
        err
    }
}

#[async_trait]
impl Signer for KeyNotFoundSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        Err(Self::classified_error())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// `SigningError::LocalRejected` — unambiguous no-signature.
pub struct LocalRejectedSigner;

impl LocalRejectedSigner {
    #[must_use]
    pub fn classified_error() -> SigningError {
        let err = SigningError::LocalRejected("gRPC raw-root; no remote I/O".into());
        assert!(
            err.is_unambiguous_no_signature(),
            "LocalRejected must stay is_unambiguous_no_signature (VD-5.3)"
        );
        err
    }
}

#[async_trait]
impl Signer for LocalRejectedSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        Err(Self::classified_error())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// `SigningError::UnsupportedSigningType` — unambiguous no-signature.
pub struct UnsupportedSigningTypeSigner;

impl UnsupportedSigningTypeSigner {
    #[must_use]
    pub fn classified_error() -> SigningError {
        let err = SigningError::UnsupportedSigningType("matrix-duty".into());
        assert!(
            err.is_unambiguous_no_signature(),
            "UnsupportedSigningType must stay is_unambiguous_no_signature (VD-5.3)"
        );
        err
    }
}

#[async_trait]
impl Signer for UnsupportedSigningTypeSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        Err(Self::classified_error())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// `panic!` inside `Signer::sign`; `spawn_blocking` join maps to `SigningFailed`.
pub struct PanickingSigner;

#[async_trait]
impl Signer for PanickingSigner {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        panic!("matrix signer panic");
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}
