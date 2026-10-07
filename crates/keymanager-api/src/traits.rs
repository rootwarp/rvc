use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

use crate::error::ApiError;

pub type Pubkey = [u8; 48];

#[derive(Debug, Error)]
pub enum ImportKeystoreError {
    #[error("duplicate key")]
    Duplicate,
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid keystore: {0}")]
    InvalidKeystore(String),
    #[error("I/O error: {0}")]
    Io(String),
    /// A DELETE has snapshotted this pubkey and has not finished yet.
    ///
    /// The key is not present. This is not [`Self::Duplicate`].
    #[error("delete in progress")]
    DeleteInProgress,
}

#[derive(Debug, Error)]
pub enum DeleteKeystoreError {
    #[error("I/O error: {0}")]
    Io(String),
}

/// Manages BLS keystores: decryption, import, removal, and file operations.
#[async_trait]
pub trait KeystoreManager: Send + Sync {
    fn list_keys(&self) -> Vec<Pubkey>;
    fn has_key(&self, pubkey: &Pubkey) -> bool;
    async fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError>;
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError>;

    /// Which of `candidates` are members, decided under the same lock as
    /// [`Self::import_keystore`] and [`Self::delete_keystore`] when the
    /// implementor has one.
    ///
    /// The VC adapter also records the in-flight DELETE count for that
    /// snapshot before releasing the lock. [`Self::begin_delete_export`] must
    /// not count those pubkeys again. [`Self::end_delete_export`] drops the
    /// count. The default is a `has_key` filter with no count. A key that
    /// appears after this snapshot must not be removed by a DELETE whose
    /// export omitted it.
    fn membership_for_delete(&self, candidates: &[Pubkey]) -> Vec<Pubkey> {
        let mut members = Vec::new();
        for pubkey in candidates {
            if self.has_key(pubkey) && !members.contains(pubkey) {
                members.push(*pubkey);
            }
        }
        members
    }

    /// Mark the start of a DELETE whose membership snapshot is already counted.
    ///
    /// Must not increment the in-flight count. That count is taken in
    /// [`Self::membership_for_delete`] under the same lock as the scan.
    /// Paired with [`Self::end_delete_export`] for the same pubkeys, which
    /// stays up through export, deletion, drain timeout, and every other
    /// return. Default is a no-op.
    fn begin_delete_export(&self, _members: &[Pubkey]) {}

    /// Drop the in-flight count installed by [`Self::membership_for_delete`]
    /// for `members`.
    fn end_delete_export(&self, _members: &[Pubkey]) {}
}

/// Errors from [`SlashingProtection`] trait methods.
///
/// Client exposure is decided by the central mapper in [`crate::error`]:
/// * [`Self::NotFound`] / [`Self::InvalidInterchange`] — safe to surface
/// * [`Self::Backend`] — logged server-side only; clients get a generic message
#[derive(Debug, Error)]
pub enum SlashingProtectionError {
    #[error("not found")]
    NotFound,
    #[error("invalid interchange: {0}")]
    InvalidInterchange(String),
    /// Internal/backend failure. Detail is never echoed to HTTP clients.
    #[error("{0}")]
    Backend(String),
}

/// Manages EIP-3076 slashing protection interchange data.
#[async_trait]
pub trait SlashingProtection: Send + Sync {
    async fn import_interchange(
        &self,
        interchange_json: &str,
    ) -> Result<(), SlashingProtectionError>;
    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError>;
}

/// Manages validator configurations (enable/disable).
pub trait ValidatorManager: Send + Sync {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool);
    fn remove_validator(&self, pubkey: &Pubkey) -> bool;
    /// Flip the attesting-enabled state of an existing validator.
    ///
    /// No-op if `pubkey` is not tracked (e.g. already deleted).
    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool);
}

/// Triggers doppelganger detection for newly imported keys.
pub trait DoppelgangerMonitor: Send + Sync {
    fn start_monitoring(&self, pubkey: Pubkey);
    /// Signal that the wall-clock M-12 import window has elapsed (or prune a
    /// time-based pending entry).
    ///
    /// **Must not** tear down forward-window enablement state that still needs
    /// network liveness satisfaction (SEC-2b/2c). Production
    /// `ForwardWindowMachine` adapters treat this as a no-op for machine state;
    /// only [`Self::cancel_monitoring`] (DELETE) removes machine registration.
    fn stop_monitoring(&self, pubkey: &Pubkey);
    /// DELETE / hard-remove path: drop all monitoring state so a re-import starts
    /// a fresh window (`ForwardWindowMachine::cancel`).
    ///
    /// Default: same as [`Self::stop_monitoring`] (log-only / pending-set
    /// implementors where both mean "prune pending").
    fn cancel_monitoring(&self, pubkey: &Pubkey) {
        self.stop_monitoring(pubkey);
    }
    /// Returns `true` if the doppelganger window for this key has elapsed.
    ///
    /// Keys that are not under active monitoring (e.g. existing keys loaded at
    /// startup) are considered safe and return `true` by default.
    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool;
}

/// Errors from remote-key import.
///
/// Client exposure is decided by the central mapper in [`crate::error`]:
/// * [`Self::Duplicate`], [`Self::InvalidUrl`], [`Self::HostNotAllowed`] — safe
/// * [`Self::Backend`] — logged server-side only
#[derive(Debug, Error)]
pub enum ImportRemoteKeyError {
    #[error("duplicate key")]
    Duplicate,
    #[error("invalid remote signer URL: {0}")]
    InvalidUrl(String),
    #[error("remote signer host '{0}' is not in the allowed hosts list")]
    HostNotAllowed(String),
    /// Internal/backend failure. Detail is never echoed to HTTP clients.
    #[error("{0}")]
    Backend(String),
}

/// Errors from remote-key delete.
#[derive(Debug, Error)]
pub enum DeleteRemoteKeyError {
    #[error("not found")]
    NotFound,
    /// Internal/backend failure. Detail is never echoed to HTTP clients.
    #[error("{0}")]
    Backend(String),
}

/// Manages remote signing keys (Web3Signer).
pub trait RemoteKeyManager: Send + Sync {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)>;
    fn has_remote_key(&self, pubkey: &Pubkey) -> bool;
    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError>;
    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError>;
}

/// Manages per-validator configuration: fee recipient, gas limit, and graffiti.
pub trait ValidatorConfigManager: Send + Sync {
    fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError>;
    fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError>;
    fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
    fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError>;
    fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError>;
    fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
    fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError>;
    fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError>;
    fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
}

/// Manages voluntary exit **signing** for validators.
///
/// # Submit semantics
///
/// `sign_voluntary_exit` only constructs and signs a [`eth_types::SignedVoluntaryExit`].
/// It does **not** broadcast or submit the exit to the beacon chain. Both
/// Keymanager routes that use this trait
/// (`POST /eth/v1/validator/:pubkey/voluntary_exit` and
/// `POST /rvc/v1/validator/:pubkey/prepare_exit`) therefore return the signed
/// message for the operator to submit separately; they differ only in log
/// framing, not in submit behavior.
#[async_trait]
pub trait VoluntaryExitManager: Send + Sync {
    /// Sign a voluntary exit for `pubkey` at `epoch` (or current epoch when `None`).
    ///
    /// Returns the signed message only; does not submit it to the beacon chain.
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<eth_types::SignedVoluntaryExit, ApiError>;
}

/// A drain that did not see the per-pubkey signing lock become free.
///
/// Not a success variant. The pubkey stays quiesced; callers must not export
/// or delete it.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuiesceError {
    /// `waited` is how long the drain blocked before giving up.
    #[error("signing drain timed out after {waited:?}")]
    DrainTimedOut { waited: Duration },
}

/// Close the under-lock signing gate for one pubkey and drain the slashable lock.
///
/// This trait lives in `rvc-keymanager-api` because that crate is Infra and
/// must not depend on `rvc-signer` (Domain). A direct dependency would fail
/// the G-5b `layer_edges` gate. The VC (`rvc`) implements the trait and calls
/// the signer's per-pubkey drain; keymanager handlers depend only on this trait.
///
/// `Ok` means the pubkey is quiesced, so the enablement gate re-checked under
/// the slashable per-pubkey lock is closed, and that lock was acquired and
/// dropped. It does **not** mean every in-flight non-slashable signature has
/// finished: randao, sync committee, aggregate, and voluntary exit check
/// enablement and then sign without taking that lock. A later DELETE must not
/// treat `Ok` as "all duties are idle".
///
/// [`QuiesceError::DrainTimedOut`] is an error. A timed-out drain leaves the
/// pubkey quiesced and must not be ignored.
#[async_trait]
pub trait SigningQuiesce: Send + Sync {
    /// Quiesce `pubkey` and wait up to `timeout` for the slashable per-pubkey lock.
    ///
    /// `Ok` — the under-lock gate is closed and that lock was acquired and
    /// dropped. Non-slashable duties do not hold the lock, so `Ok` does not
    /// mean they are idle. DELETE must not treat `Ok` as "all duties are idle".
    ///
    /// The pubkey remains quiesced on both `Ok` and [`QuiesceError::DrainTimedOut`].
    async fn quiesce(&self, pubkey: &Pubkey, timeout: Duration) -> Result<(), QuiesceError>;
}
