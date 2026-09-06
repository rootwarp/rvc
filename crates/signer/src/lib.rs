//! rvc-signer - Validator signing with slashing protection.
//!
//! This module provides a signing service that ensures all validator
//! signatures are checked against slashing protection rules before signing.
//!
//! See the signer hierarchy doc on the `rvc-crypto` crate root for how
//! [`crypto::Signer`] / [`crypto::TypedSigner`] / [`crypto::CompositeSigner`]
//! relate to [`SignerService`] and [`SigningGate`].

#![deny(rustdoc::broken_intra_doc_links)]

mod core;
mod error;
mod fail_closed;
mod gate;
mod locks;
pub mod metrics;
mod service_util;
mod traits;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub use eth_types::is_aggregator;
// SigningEnablement was relocated from rvc-signer to rvc-doppelganger (Issue 2.6)
// to allow ForwardWindowMachine to implement it without a doppelganger→signer cycle.
#[allow(deprecated)]
pub use core::StagedRow;
pub use core::{
    sign_nonslashable_core, sign_slashable, NonSlashableFailure, NoopSignHooks, SignHooks,
    SignSlashableRequest, SlashableKind, SlashableSignSession, StandardSlashableHooks,
    TimeoutPolicy, TimeoutPolicySource, DEFAULT_SIGN_TIMEOUT,
};
pub use doppelganger::SigningEnablement;
pub use error::{classify, GateErrClass, SigningGateError};
pub use fail_closed::FailClosedDefault;
pub use gate::{SigningGate, AUDIT_CN_DEFAULT};
pub use locks::ValidatorLockMap;
/// Shared duty-crate helpers (circuit breaker, …). Home for types that must not
/// create peer domain edges (block-service must not depend on builder for this).
pub use service_util::CircuitBreakerState;
pub use traits::{BeaconBlockHeaderFields, ValidatorSigner};

/// Test-only stubs (`StubValidatorSigner`, `mock_sig`). Enable via `test-utils`.
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::{mock_sig, StubValidatorSigner};

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;
use tracing::{debug, error, warn};

use crypto::{
    capella_capped_fork_version, signing_root_for, signing_root_with_fork_version, CompositeSigner,
    DutyRef, PublicKey, SignContext, Signature, Signer, SigningCtx, SigningError, TypedSigner,
};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlock, BlindedBeaconBlock,
    ContributionAndProof, ElectraAggregateAndProof, Epoch, ForkInfo, ForkName, ForkSchedule,
    PayloadAttestationData, Root, Slot, ValidatorRegistrationV1, VoluntaryExit, SLOTS_PER_EPOCH,
};
use observability::logging::fields::Duty;
use observability::logging::{TruncatedPubkey, TruncatedRoot};
use slashing::{SlashingDb, SlashingError};

/// Errors that can occur during signing operations (VC / `SignerService` path).
///
/// Slashing-related variants share the D3 taxonomy documented on
/// [`error`](crate::error): **`SlashingBlocked`** (never retry different root)
/// vs **`CommitFailed`** (same-root retry safe; carries `signing_root`).
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("key not found for pubkey: {0}")]
    KeyNotFound(String),

    /// Stage rejected the sign (double-vote / double-proposal / etc.).
    ///
    /// See [`error`](crate::error) module docs — **SlashingBlocked** retry contract.
    ///
    /// Display intentionally omits the raw `SlashingError` (which may contain
    /// SQLite paths or lock messages on non-slashable variants). Use `source()`
    /// for the full error; slashable variants carry safe slot/epoch detail there.
    #[error("signing blocked by slashing protection")]
    SlashingBlocked(#[source] SlashingError),

    /// Sign succeeded but the slashing-DB commit failed (nothing written).
    ///
    /// See [`error`](crate::error) module docs — **CommitFailed** retry contract.
    /// `signing_root` is the only root a VC caller may retry with.
    #[error("slashing-protection commit failed (no row written; same-root retry is safe)")]
    CommitFailed {
        /// Signing root that was staged (and must be used for any retry).
        signing_root: Root,
        /// Underlying slashing-DB I/O error (available via `source()`).
        #[source]
        source: SlashingError,
    },

    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The doppelganger enablement gate denied signing for this pubkey.
    ///
    /// Either the validator is not yet cleared through the monitoring window, or
    /// the pubkey is unknown to the enablement implementation (fail-closed).
    /// No slashing-DB row was staged or committed.
    #[error("signing blocked by doppelganger gate")]
    BlockedByDoppelganger,

    /// This signer cannot produce a signature for the named duty.
    ///
    /// The duty is dropped; implementations must not sign under a fallback
    /// domain. No slashing-DB row is written.
    #[error("unsupported duty: {duty}")]
    UnsupportedDuty { duty: &'static str },
}

impl SignerError {
    /// Taxonomy-level check for **commit-failure same-root retry** only.
    ///
    /// - `CommitFailed` → `true` only when `proposed_root` equals the carried root.
    /// - `SlashingBlocked` → always `false` here (conservative; does not encode
    ///   EIP-3076 same-root re-sign after a prior successful commit — that is a
    ///   separate stage check on retry).
    /// - Other variants → `false`.
    ///
    /// Not a general oracle for stage I/O recoverability: non-slashable stage
    /// errors also map to `SlashingBlocked` and refuse via this helper.
    pub fn permits_retry_with_root(&self, proposed_root: &Root) -> bool {
        match self {
            Self::CommitFailed { signing_root, .. } => signing_root == proposed_root,
            Self::SlashingBlocked(_) => false,
            _ => false,
        }
    }
}

/// Truncates an error message body to at most `max` bytes, appending
/// "... (truncated)" if the message exceeds the limit.
///
/// The cut point is adjusted to the highest valid UTF-8 character boundary
/// that is ≤ `max` bytes, so the result is always a valid `String` even when
/// `msg` contains multi-byte Unicode sequences.
fn truncate_error_body(msg: &str, max: usize) -> String {
    if msg.len() <= max {
        msg.to_string()
    } else {
        // Walk back from `max` to find a valid char boundary.
        let safe = (0..=max).rev().find(|&i| msg.is_char_boundary(i)).unwrap_or(0);
        format!("{}... (truncated)", &msg[..safe])
    }
}

impl From<SigningError> for SignerError {
    fn from(e: SigningError) -> Self {
        match e {
            SigningError::KeyNotFound(pk) => SignerError::KeyNotFound(pk),
            SigningError::LocalRejected(msg) => {
                SignerError::SigningFailed(truncate_error_body(&msg, 200))
            }
            SigningError::RemoteSignerError(msg) => {
                SignerError::SigningFailed(truncate_error_body(&msg, 200))
            }
            SigningError::InvalidRemoteSignature => {
                SignerError::SigningFailed("remote signer returned invalid signature".to_string())
            }
            SigningError::UnsupportedSigningType(msg) => {
                SignerError::SigningFailed(format!("unsupported remote signing type: {msg}"))
            }
            SigningError::UnsupportedDuty { duty } => SignerError::UnsupportedDuty { duty },
        }
    }
}

/// Audit CN recorded by [`slashing::PubkeyScopedDb`] on the VC slashable path.
const AUDIT_CN_VC: &str = "local-vc";

/// How the composite routes a pubkey — drives fail-closed [`TimeoutPolicy`].
///
/// Only a **proven in-process local** key (and not also remote) may discard a
/// staged row on timeout. Remote, dual-routed, or unresolvable keys retain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Local keystore / dynamic local only — discard staged row on timeout.
    InProcess,
    /// HTTP Web3Signer or gRPC remote — retain staged row on timeout / ambiguous errors.
    Remote,
    /// Neither local-only nor clearly remote (missing or dual-registered) — fail closed.
    Unknown,
}

/// Service that combines signing through CompositeSigner with slashing protection.
///
/// Record-then-sign order is mandated by Ethereum consensus spec (phase0/validator.md):
/// "Save a record to hard disk ... Generate and broadcast."
/// The per-validator mutex prevents TOCTOU between concurrent signing requests.
///
/// # Gate integration (SEC-2a)
///
/// Every duty-signing method consults [`SigningEnablement::is_signing_enabled`]
/// **before** the slashing stage (or, for non-slashable duties, before the BLS
/// sign).  A closed gate returns [`SignerError::BlockedByDoppelganger`] with no
/// slashing-DB row written.  The default enablement is fail-closed (unknown /
/// un-wired keys are refused).  Wire a real implementation (e.g.
/// `ForwardWindowMachine` in SEC-2b) via [`SignerService::with_enablement`].
///
/// Slashable paths (`sign_block` / `sign_attestation`) delegate to
/// [`sign_slashable`]: outer enablement → per-validator lock → enablement
/// re-check under lock → [`slashing::PubkeyScopedDb`] stage → timed sign → commit/discard
/// per per-pubkey [`TimeoutPolicy`] (fail-closed retain for remote/unknown).
/// Metrics use [`StandardSlashableHooks`] (same families as the gate).
///
/// Non-slashable paths: `ensure_signing_enabled` then
/// [`sign_nonslashable_core`] (timeout + uniform classification). They take
/// no per-validator lock and write no slashing-DB row. VC-specific `debug!`
/// timing stays in the wrapper.
pub struct SignerService {
    signer: Arc<CompositeSigner>,
    /// BLS backend used by slashable and non-slashable sign paths.
    ///
    /// Defaults to the same [`CompositeSigner`] as [`Self::signer`]. Tests may
    /// inject a slow/failing backend via [`Self::with_sign_backend`] without
    /// replacing key-management APIs on the composite.
    sign_backend: Arc<dyn Signer>,
    slashing_db: Arc<SlashingDb>,
    validator_locks: ValidatorLockMap,
    enablement: Arc<dyn SigningEnablement>,
    /// Maximum wall-clock duration allowed for a single BLS sign (slashable + non-slashable).
    ///
    /// Expiry returns `Err(SigningFailed("signer timed out"))`. Defaults to 4s.
    /// On retain policies the staged slashing row is **committed**, not discarded.
    sign_timeout: Duration,
}

/// Fail-closed enablement used when no `with_enablement` was provided.
///
/// Denies every pubkey, matching
/// `<bool as FailClosedDefault>::default_when_unknown() == false` (PRD §6.3).
struct FailClosedEnablement;

impl SigningEnablement for FailClosedEnablement {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        <bool as FailClosedDefault>::default_when_unknown()
    }
}

/// Enablement that permits every pubkey.
///
/// **Test / test-utils only.** Gated by `cfg(any(test, feature = "test-utils"))`
/// so production dependency lines cannot import it without an explicit feature.
/// Do **not** wire this into production `build_signer` / `main.rs`. SEC-2b
/// operator opt-out must use a distinctly named type (e.g.
/// `DoppelgangerDisabledByOperator`), not this helper.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub struct AlwaysEnabled;

#[cfg(any(test, feature = "test-utils"))]
impl SigningEnablement for AlwaysEnabled {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

/// Convenience constructor for [`AlwaysEnabled`].
///
/// Available only under `cfg(test)` or the `test-utils` feature.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
#[must_use]
pub fn always_enabled() -> Arc<dyn SigningEnablement> {
    Arc::new(AlwaysEnabled)
}

/// One-shot factory invoked inside the existing timeout envelope.
type TypedSignFut = Pin<Box<dyn Future<Output = Result<Signature, SigningError>> + Send>>;
type TypedSignFactory = Box<dyn FnOnce() -> TypedSignFut + Send>;

/// Adapts a typed gRPC sign into [`Signer::sign`] so slashable/non-slashable
/// cores keep their lock / stage / timeout path. Verifies the signature against
/// the staged `signing_root` before returning (HTTP remote already does this).
struct TypedSignAdapter {
    factory: parking_lot::Mutex<Option<TypedSignFactory>>,
    expected_root: Root,
    pubkey: PublicKey,
}

#[async_trait]
impl Signer for TypedSignAdapter {
    async fn sign(
        &self,
        signing_root: &Root,
        _pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        if signing_root != &self.expected_root {
            return Err(SigningError::LocalRejected(
                "typed sign adapter: signing_root mismatch".to_string(),
            ));
        }
        let factory = self.factory.lock().take().ok_or_else(|| {
            SigningError::LocalRejected("typed sign adapter: already consumed".to_string())
        })?;
        let sig = factory().await?;
        if sig.verify(&self.pubkey, signing_root).is_err() {
            return Err(SigningError::InvalidRemoteSignature);
        }
        Ok(sig)
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![self.pubkey.to_bytes()]
    }
}

fn grpc_raw_root_rejected() -> TypedSignFactory {
    Box::new(|| {
        Box::pin(async {
            Err(SigningError::LocalRejected(
                "raw-root signing is not supported for gRPC remote signers; \
                 use TypedSigner::sign_block / sign_attestation / etc."
                    .to_string(),
            ))
        })
    })
}

fn sign_context_at_epoch(
    pubkey: PublicKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
    epoch: Epoch,
) -> SignContext {
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let current_version = fork_name.fork_version(fork_schedule);
    let previous_version = fork_name.previous_fork(fork_schedule).fork_version(fork_schedule);
    SignContext::new(
        pubkey,
        ForkInfo { previous_version, current_version, genesis_validators_root },
        fork_name,
    )
}

fn electra_aggregate_as_legacy(e: &ElectraAggregateAndProof) -> AggregateAndProof {
    AggregateAndProof {
        aggregator_index: e.aggregator_index,
        aggregate: Attestation {
            aggregation_bits: e.aggregate.aggregation_bits.clone(),
            data: e.aggregate.data.clone(),
            signature: e.aggregate.signature.clone(),
        },
        selection_proof: e.selection_proof.clone(),
    }
}

fn sign_context_for_exit(
    pubkey: PublicKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
    epoch: Epoch,
) -> SignContext {
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let current_version = capella_capped_fork_version(epoch, fork_schedule);
    let previous_version = fork_name.previous_fork(fork_schedule).fork_version(fork_schedule);
    SignContext::new(
        pubkey,
        ForkInfo { previous_version, current_version, genesis_validators_root },
        fork_name,
    )
}

impl SignerService {
    /// Creates a new SignerService with the provided composite signer and slashing database.
    ///
    /// The enablement gate defaults to **fail-closed**: every pubkey is refused
    /// until [`with_enablement`](Self::with_enablement) installs a real
    /// [`SigningEnablement`] (e.g. `ForwardWindowMachine` in SEC-2b).
    ///
    /// Signs use a **4-second** default timeout (matching `SigningGate`).
    /// Override with [`with_sign_timeout`](Self::with_sign_timeout).
    pub fn new(signer: Arc<CompositeSigner>, slashing_db: Arc<SlashingDb>) -> Self {
        // Coerce CompositeSigner → dyn Signer for the shared sign backend.
        let sign_backend: Arc<dyn Signer> = signer.clone();
        Self {
            signer,
            sign_backend,
            slashing_db,
            validator_locks: ValidatorLockMap::new(),
            enablement: Arc::new(FailClosedEnablement),
            sign_timeout: DEFAULT_SIGN_TIMEOUT,
        }
    }

    /// Replace the signing enablement gate (builder style).
    ///
    /// Production paths wire `ForwardWindowMachine` (SEC-2b).  Tests that need
    /// unrestricted signing use `always_enabled()` (requires `test-utils`
    /// feature or `cfg(test)`).
    #[must_use]
    pub fn with_enablement(mut self, enablement: Arc<dyn SigningEnablement>) -> Self {
        self.enablement = enablement;
        self
    }

    /// Override the per-sign timeout for slashable and non-slashable BLS calls.
    ///
    /// Default is 4 seconds.
    #[must_use]
    pub fn with_sign_timeout(mut self, timeout: Duration) -> Self {
        self.sign_timeout = timeout;
        self
    }

    /// Replace the BLS sign backend used by slashable and non-slashable paths.
    ///
    /// Production uses the [`CompositeSigner`] from [`Self::new`]. Available under
    /// `cfg(test)` / `test-utils` so tests can inject a slow or failing backend
    /// (timeout / error-mapping coverage) without changing key-management APIs.
    /// [`BackendKind`] / timeout policy still resolve from the composite registry.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_sign_backend(mut self, backend: Arc<dyn Signer>) -> Self {
        self.sign_backend = backend;
        self
    }

    /// Resolve how the composite routes `pubkey` (local vs remote vs unknown).
    ///
    /// **Fail-closed:** only a local-only key is [`BackendKind::InProcess`].
    /// Dual registration (local + remote) or missing registration is
    /// [`BackendKind::Unknown`].
    pub fn backend_kind(&self, pubkey: &PublicKey) -> BackendKind {
        let pk = pubkey.to_bytes();
        let local = self.signer.has_local_key(&pk);
        let remote = self.signer.has_grpc_remote(&pk) || self.signer.has_remote_key(&pk);
        match (local, remote) {
            (true, false) => BackendKind::InProcess,
            (false, true) => BackendKind::Remote,
            // Dual-registered or unregistered: cannot prove in-process drop is safe.
            _ => BackendKind::Unknown,
        }
    }

    /// Map [`BackendKind`] → [`TimeoutPolicy`]. **Default is fail-closed retain.**
    ///
    /// Only [`BackendKind::InProcess`] discards on timeout; `Remote` and
    /// `Unknown` retain so late remote completion cannot double-sign.
    ///
    /// Production paths use [`Self::timeout_policy_source`] (resolve under lock).
    /// This helper is retained for tests that assert the kind→policy mapping.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn timeout_policy_for(&self, pubkey: &PublicKey) -> TimeoutPolicy {
        Self::timeout_policy_for_kind(self.backend_kind(pubkey))
    }

    fn timeout_policy_for_kind(kind: BackendKind) -> TimeoutPolicy {
        match kind {
            BackendKind::InProcess => TimeoutPolicy::DiscardStagedRow,
            BackendKind::Remote | BackendKind::Unknown => TimeoutPolicy::RetainStagedRow,
        }
    }

    /// Policy source that re-resolves [`BackendKind`] under the validator lock
    /// and again immediately before BLS sign (SEC-1).
    fn timeout_policy_source(&self, pubkey: &PublicKey) -> TimeoutPolicySource {
        let composite = Arc::clone(&self.signer);
        let pk_bytes = pubkey.to_bytes();
        TimeoutPolicySource::ResolveUnderLock(Arc::new(move || {
            let local = composite.has_local_key(&pk_bytes);
            let remote =
                composite.has_grpc_remote(&pk_bytes) || composite.has_remote_key(&pk_bytes);
            let kind = match (local, remote) {
                (true, false) => BackendKind::InProcess,
                (false, true) => BackendKind::Remote,
                _ => BackendKind::Unknown,
            };
            Self::timeout_policy_for_kind(kind)
        }))
    }

    /// Refuse signing when the doppelganger enablement gate is closed.
    ///
    /// Called **before** any slashing stage or BLS sign so a closed gate never
    /// stages a row or produces a signature.  On slashable paths the shared
    /// core re-checks enablement **under** the per-validator lock (closes
    /// Safe→Detected TOCTOU vs concurrent liveness).
    fn ensure_signing_enabled(&self, pubkey: &PublicKey) -> Result<(), SignerError> {
        if self.enablement.is_signing_enabled(pubkey) {
            return Ok(());
        }
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        warn!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            "SignerService: signing blocked by doppelganger enablement gate"
        );
        Err(SignerError::BlockedByDoppelganger)
    }

    /// Raw-root [`Self::sign_backend`] for local/HTTP keys; typed adapter for gRPC.
    fn bls_backend_for_duty(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
        typed: Option<TypedSignFactory>,
    ) -> Arc<dyn Signer> {
        if self.signer.has_grpc_remote(&pubkey.to_bytes()) {
            Arc::new(TypedSignAdapter {
                factory: parking_lot::Mutex::new(Some(
                    typed.unwrap_or_else(grpc_raw_root_rejected),
                )),
                expected_root: signing_root,
                pubkey: pubkey.clone(),
            })
        } else {
            Arc::clone(&self.sign_backend)
        }
    }

    fn grpc_typed_factory<F, Fut>(&self, pubkey: &PublicKey, f: F) -> Option<TypedSignFactory>
    where
        F: FnOnce(Arc<dyn TypedSigner + Send + Sync>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Signature, SigningError>> + Send + 'static,
    {
        let grpc = self.signer.get_grpc_remote(&pubkey.to_bytes())?;
        Some(Box::new(move || Box::pin(f(grpc))))
    }

    /// Map shared-core [`SigningGateError`] into the VC [`SignerError`] surface.
    fn map_gate_error(err: SigningGateError, pubkey_hex: &str) -> SignerError {
        match err {
            SigningGateError::BlockedByDoppelganger => SignerError::BlockedByDoppelganger,
            SigningGateError::SlashingBlocked(e) => SignerError::SlashingBlocked(e),
            SigningGateError::CommitFailed { signing_root, source } => {
                SignerError::CommitFailed { signing_root, source }
            }
            SigningGateError::SigningFailed(msg) => SignerError::SigningFailed(msg),
            SigningGateError::KeyNotFound => SignerError::KeyNotFound(pubkey_hex.to_string()),
            SigningGateError::UnknownPubkey => SignerError::BlockedByDoppelganger,
        }
    }

    /// Decode signature bytes from the shared core into [`Signature`].
    fn signature_from_bytes(bytes: Vec<u8>) -> Result<Signature, SignerError> {
        Signature::from_bytes(&bytes).map_err(|e| {
            SignerError::SigningFailed(format!("invalid signature bytes from sign core: {e}"))
        })
    }

    // -------------------------------------------------------------------------
    // Non-slashable paths — all route through `sign_nonslashable`
    // -------------------------------------------------------------------------
    //
    // Pattern (mirrors SigningGate):
    //   1. Root derivation in the public wrapper
    //   2. `ensure_signing_enabled` (Result) then `sign_nonslashable_core`
    // No per-validator lock, no slashing-DB staging. VC `debug!`/timing stay here.

    /// Facade wrapper: `ensure_signing_enabled` then [`sign_nonslashable_core`].
    ///
    /// VC-specific `debug!` / elapsed timing stay here (operator output, not
    /// core behaviour). `KeyNotFound` and other backend errors fold through
    /// [`SignerError`]'s `From<SigningError>`.
    async fn sign_nonslashable(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
        op_name: &str,
        backend: Arc<dyn Signer>,
    ) -> Result<Signature, SignerError> {
        // Same gate point as slashable early check (Result, not a bool).
        self.ensure_signing_enabled(pubkey)?;

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let start = Instant::now();

        debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            signing_type = op_name,
            "Signing non-slashable duty"
        );

        match sign_nonslashable_core(
            self.enablement.as_ref(),
            backend.as_ref(),
            pubkey,
            signing_root,
            self.sign_timeout,
        )
        .await
        {
            Ok(sig) => {
                debug!(
                    duration_ms = start.elapsed().as_millis() as u64,
                    signing_type = op_name,
                    "Signing completed"
                );
                Ok(sig)
            }
            Err(NonSlashableFailure::Blocked) => Err(SignerError::BlockedByDoppelganger),
            Err(NonSlashableFailure::TimedOut { after }) => {
                error!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    timeout_secs = after.as_secs_f64(),
                    "SignerService: non-slashable signer timed out"
                );
                Err(SignerError::SigningFailed("signer timed out".to_string()))
            }
            Err(NonSlashableFailure::KeyNotFound) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    signing_type = op_name,
                    "Signing failed"
                );
                Err(SigningError::KeyNotFound(pubkey_hex).into())
            }
            Err(NonSlashableFailure::Backend(e)) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    error = %e,
                    signing_type = op_name,
                    "Signing failed"
                );
                Err(e.into())
            }
        }
    }

    /// Returns a reference to the underlying composite signer.
    pub fn signer(&self) -> &CompositeSigner {
        &self.signer
    }

    /// Returns a reference to the underlying slashing database.
    pub fn slashing_db(&self) -> &SlashingDb {
        &self.slashing_db
    }
}

// Single surface: sign methods live only on [`ValidatorSigner`] (RF4-12 / F44).
// No parallel inherent methods and no pure-forward delegation. Callers of a
// concrete [`SignerService`] need `ValidatorSigner` in scope (crate re-exports it).
// Wire conversion via [`Signature::to_bytes`] remains at beacon/gRPC/HTTP boundaries.
//
// `Send` futures — see docs on [`ValidatorSigner`].
#[async_trait]
impl ValidatorSigner for SignerService {
    /// Signs an attestation after checking slashing protection.
    ///
    /// Delegates to [`sign_slashable`] with per-pubkey [`TimeoutPolicy`]:
    /// in-process local keys discard on timeout; remote/unknown retain
    /// (fail-closed). Metrics via [`StandardSlashableHooks::attestation`].
    #[tracing::instrument(name = "sign.attestation", skip_all, fields(slot = data.slot, duty = %Duty::Attestation.as_str(), slashing_result = tracing::field::Empty))]
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        // Cheap outer enablement check (core re-checks under the lock).
        self.ensure_signing_enabled(pubkey)?;

        let start = Instant::now();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            slot = data.slot,
            source_epoch = data.source.epoch,
            target_epoch = data.target.epoch,
            signing_type = "attestation",
            "Signing attestation"
        );

        let source_epoch = data.source.epoch;
        let target_epoch = data.target.epoch;

        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::Attestation(data), &ctx);

        debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            signing_root = %TruncatedRoot::new(&signing_root),
            genesis_validators_root = %TruncatedRoot::new(genesis_validators_root),
            slot = data.slot,
            index = data.index,
            source_epoch = data.source.epoch,
            target_epoch = data.target.epoch,
            "Computed attestation signing root"
        );

        // Emit `slashing.check` on the async task so subscribers can observe it
        // before the core moves stage work onto a blocking thread.
        let _slashing_span = tracing::info_span!("slashing.check").entered();
        drop(_slashing_span);

        let gvr = *genesis_validators_root;
        // SEC-1: resolve policy under the per-validator lock (and recheck pre-sign).
        let policy = self.timeout_policy_source(pubkey);

        let data_owned = data.clone();
        let sign_ctx = sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, data.target.epoch);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_attestation(&data_owned, &sign_ctx).await
        });
        let signer = self.bls_backend_for_duty(pubkey, signing_root, typed);

        let result = sign_slashable(SignSlashableRequest {
            locks: &self.validator_locks,
            pubkey,
            enablement: self.enablement.as_ref(),
            signer,
            signing_root,
            sign_timeout: self.sign_timeout,
            policy,
            hooks: Arc::new(StandardSlashableHooks::attestation()),
            op_name: "sign_attestation",
            slashing_db: Arc::clone(&self.slashing_db),
            client_cn: AUDIT_CN_VC.to_string(),
            gvr,
            kind: SlashableKind::Attestation { source_epoch, target_epoch },
        })
        .await;

        match result {
            Ok(bytes) => {
                observability::logging::record_display(
                    &tracing::Span::current(),
                    "slashing_result",
                    "safe",
                );
                debug!(
                    duration_ms = start.elapsed().as_millis() as u64,
                    signing_type = "attestation",
                    "Signing completed"
                );
                Self::signature_from_bytes(bytes)
            }
            Err(e) => {
                if matches!(e, SigningGateError::SlashingBlocked(_)) {
                    observability::logging::record_display(
                        &tracing::Span::current(),
                        "slashing_result",
                        "blocked",
                    );
                }
                Err(Self::map_gate_error(e, &pubkey_hex))
            }
        }
    }

    /// Signs a block after checking slashing protection.
    ///
    /// Same shared-core path as [`Self::sign_attestation`] with
    /// [`StandardSlashableHooks::block`] and per-pubkey [`TimeoutPolicy`].
    #[tracing::instrument(name = "sign.block", skip_all, fields(slot = slot, duty = %Duty::Block.as_str(), slashing_result = tracing::field::Empty))]
    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.ensure_signing_enabled(pubkey)?;

        let start = Instant::now();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            slot = slot,
            signing_type = "block",
            "Signing block"
        );

        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::BlockRoot { root: block_root, slot }, &ctx);

        let gvr = *genesis_validators_root;
        // SEC-1: resolve policy under the per-validator lock (and recheck pre-sign).
        let policy = self.timeout_policy_source(pubkey);
        let signer = self.bls_backend_for_duty(pubkey, signing_root, None);

        let result = sign_slashable(SignSlashableRequest {
            locks: &self.validator_locks,
            pubkey,
            enablement: self.enablement.as_ref(),
            signer,
            signing_root,
            sign_timeout: self.sign_timeout,
            policy,
            hooks: Arc::new(StandardSlashableHooks::block()),
            op_name: "sign_block",
            slashing_db: Arc::clone(&self.slashing_db),
            client_cn: AUDIT_CN_VC.to_string(),
            gvr,
            kind: SlashableKind::Block { slot },
        })
        .await;

        match result {
            Ok(bytes) => {
                observability::logging::record_display(
                    &tracing::Span::current(),
                    "slashing_result",
                    "safe",
                );
                debug!(
                    duration_ms = start.elapsed().as_millis() as u64,
                    signing_type = "block",
                    "Signing completed"
                );
                Self::signature_from_bytes(bytes)
            }
            Err(e) => {
                if matches!(e, SigningGateError::SlashingBlocked(_)) {
                    observability::logging::record_display(
                        &tracing::Span::current(),
                        "slashing_result",
                        "blocked",
                    );
                }
                Err(Self::map_gate_error(e, &pubkey_hex))
            }
        }
    }

    /// Signs a block from five header leaves after slashing protection.
    ///
    /// Raw-root keys hash the header into [`DutyRef::BlockRoot`] (byte-identical
    /// to [`Self::sign_block`] for the same object root). gRPC keys call
    /// [`TypedSigner::sign_block_header`].
    #[tracing::instrument(name = "sign.block", skip_all, fields(slot = header.slot, duty = %Duty::Block.as_str(), slashing_result = tracing::field::Empty))]
    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeaderFields,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.ensure_signing_enabled(pubkey)?;

        let start = Instant::now();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let slot = header.slot;

        debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            slot = slot,
            signing_type = "block",
            "Signing block header"
        );

        let block_root: Root = header.object_root();
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::BlockRoot { root: &block_root, slot }, &ctx);

        let gvr = *genesis_validators_root;
        let policy = self.timeout_policy_source(pubkey);

        let header_owned = header.clone();
        let sign_ctx =
            sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, slot / SLOTS_PER_EPOCH);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            // Pre-Gloas: legacy SignBeaconBlock / SignBlindedBeaconBlock when
            // the caller still has body bytes. 4.20c selects SignBlockHeader at Gloas.
            if header_owned.body_ssz.is_empty() {
                grpc.sign_block_header(&header_owned.spec_header(), &sign_ctx).await
            } else if header_owned.is_blinded {
                let blinded = BlindedBeaconBlock {
                    slot: header_owned.slot,
                    proposer_index: header_owned.proposer_index,
                    parent_root: header_owned.parent_root,
                    state_root: header_owned.state_root,
                    body: header_owned.body_ssz,
                };
                grpc.sign_blinded_block(&blinded, &sign_ctx).await
            } else {
                let block = BeaconBlock {
                    slot: header_owned.slot,
                    proposer_index: header_owned.proposer_index,
                    parent_root: header_owned.parent_root,
                    state_root: header_owned.state_root,
                    body: header_owned.body_ssz,
                };
                grpc.sign_block(&block, &sign_ctx).await
            }
        });
        let signer = self.bls_backend_for_duty(pubkey, signing_root, typed);

        let result = sign_slashable(SignSlashableRequest {
            locks: &self.validator_locks,
            pubkey,
            enablement: self.enablement.as_ref(),
            signer,
            signing_root,
            sign_timeout: self.sign_timeout,
            policy,
            hooks: Arc::new(StandardSlashableHooks::block()),
            op_name: "sign_block_header",
            slashing_db: Arc::clone(&self.slashing_db),
            client_cn: AUDIT_CN_VC.to_string(),
            gvr,
            kind: SlashableKind::Block { slot },
        })
        .await;

        match result {
            Ok(bytes) => {
                observability::logging::record_display(
                    &tracing::Span::current(),
                    "slashing_result",
                    "safe",
                );
                debug!(
                    duration_ms = start.elapsed().as_millis() as u64,
                    signing_type = "block",
                    "Signing completed"
                );
                Self::signature_from_bytes(bytes)
            }
            Err(e) => {
                if matches!(e, SigningGateError::SlashingBlocked(_)) {
                    observability::logging::record_display(
                        &tracing::Span::current(),
                        "slashing_result",
                        "blocked",
                    );
                }
                Err(Self::map_gate_error(e, &pubkey_hex))
            }
        }
    }

    /// Signs a RANDAO reveal for the given epoch.
    #[tracing::instrument(name = "sign.randao", skip_all, fields(duty = %Duty::Block.as_str()))]
    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::Randao(epoch), &ctx);
        let gvr = *genesis_validators_root;
        let epoch_c = epoch;
        let sign_ctx = sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, epoch);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_randao_reveal(epoch_c, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "randao", backend).await
    }

    /// Signs a sync committee message for the given beacon block root and slot.
    #[tracing::instrument(name = "sign.sync_committee_message", skip_all, fields(duty = %Duty::SyncCommittee.as_str()))]
    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root =
            signing_root_for(&DutyRef::SyncMessage { beacon_block_root, slot }, &ctx);
        let gvr = *genesis_validators_root;
        let root = *beacon_block_root;
        let sign_ctx =
            sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, slot / SLOTS_PER_EPOCH);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_sync_committee_message(slot, root, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "sync_committee_message", backend).await
    }

    /// Signs payload attestation data with `DOMAIN_PTC_ATTESTER`.
    ///
    /// Non-slashable: routes through [`Self::sign_nonslashable`], not
    /// [`sign_slashable`].
    #[tracing::instrument(name = "sign.payload_attestation", skip_all, fields(slot = data.slot))]
    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::PtcAttestation(data), &ctx);
        let gvr = *genesis_validators_root;
        let data_owned = data.clone();
        let sign_ctx =
            sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, data.slot / SLOTS_PER_EPOCH);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_payload_attestation(&data_owned, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "payload_attestation", backend).await
    }

    /// Signs a slot with DOMAIN_SELECTION_PROOF to produce a selection proof.
    #[tracing::instrument(name = "sign.selection_proof", skip_all, fields(duty = %Duty::Aggregate.as_str()))]
    async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::SelectionProof(slot), &ctx);
        let backend = self.bls_backend_for_duty(pubkey, signing_root, None);
        self.sign_nonslashable(pubkey, signing_root, "selection_proof", backend).await
    }

    /// Signs an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    ///
    /// Non-slashable: the inner attestation must already have been committed by
    /// [`Self::sign_attestation`]. This method does not touch the slashing DB.
    #[tracing::instrument(name = "sign.aggregate_and_proof", skip_all, fields(duty = %Duty::Aggregate.as_str()))]
    async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::AggregateAndProof(aggregate_and_proof), &ctx);
        let gvr = *genesis_validators_root;
        let agg = aggregate_and_proof.clone();
        let epoch = aggregate_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
        let sign_ctx = sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, epoch);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_aggregate_and_proof(&agg, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "aggregate_and_proof", backend).await
    }

    /// Signs an ElectraAggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    ///
    /// Non-slashable: same chain-of-custody rule as [`Self::sign_aggregate_and_proof`].
    #[tracing::instrument(name = "sign.electra_aggregate_and_proof", skip_all, fields(duty = %Duty::Aggregate.as_str()))]
    async fn sign_electra_aggregate_and_proof(
        &self,
        aggregate_and_proof: &ElectraAggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let gvr = *genesis_validators_root;
        let epoch = aggregate_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
        let sign_ctx = sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, epoch);
        let pk = pubkey.to_bytes();
        if self.signer.has_grpc_remote(&pk) {
            // Existing SignAggregateAndProof RPC is pre-Electra attestation SSZ.
            let legacy = electra_aggregate_as_legacy(aggregate_and_proof);
            let signing_root = signing_root_for(&DutyRef::AggregateAndProof(&legacy), &ctx);
            let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
                grpc.sign_aggregate_and_proof(&legacy, &sign_ctx).await
            });
            let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
            self.sign_nonslashable(pubkey, signing_root, "electra_aggregate_and_proof", backend)
                .await
        } else {
            let signing_root =
                signing_root_for(&DutyRef::ElectraAggregateAndProof(aggregate_and_proof), &ctx);
            let backend = self.bls_backend_for_duty(pubkey, signing_root, None);
            self.sign_nonslashable(pubkey, signing_root, "electra_aggregate_and_proof", backend)
                .await
        }
    }

    /// Signs a voluntary exit with DOMAIN_VOLUNTARY_EXIT.
    ///
    /// # Slashing-protection note (C2 invariant)
    ///
    /// Voluntary exits are **not slashable** per the Ethereum consensus spec, so
    /// this function intentionally omits the stage → commit / discard pattern used
    /// by [`Self::sign_attestation`] and [`Self::sign_block`].  There is no
    /// `stage_voluntary_exit` API in the slashing crate.
    ///
    /// The C2 error-handling invariant is still satisfied here: every signer
    /// failure is propagated directly to the caller via `Err` — no error is
    /// swallowed or silently converted to `Ok`.
    #[tracing::instrument(name = "sign.voluntary_exit", skip_all, fields(duty = %Duty::VoluntaryExit.as_str()))]
    async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        // EIP-7044 Capella cap is applied inside signing_root_for.
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root = signing_root_for(&DutyRef::VoluntaryExit(voluntary_exit), &ctx);
        let gvr = *genesis_validators_root;
        let exit = voluntary_exit.clone();
        let sign_ctx =
            sign_context_for_exit(pubkey.clone(), fork_schedule, gvr, voluntary_exit.epoch);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_voluntary_exit(&exit, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "voluntary_exit", backend).await
    }

    /// Signs a builder registration with DOMAIN_APPLICATION_BUILDER.
    ///
    /// No slashing check is needed — builder registrations are not slashable.
    #[tracing::instrument(name = "sign.builder_registration", skip_all, fields(duty = %Duty::ValidatorRegistration.as_str()))]
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        // Per-transport fork version preserved (RF4-10 unifies deliberately).
        // Builder domain uses zero GVR per MEV-Boost / builder-specs.
        let signing_root = signing_root_with_fork_version(
            registration,
            eth_types::DOMAIN_APPLICATION_BUILDER,
            fork_version,
            [0u8; 32],
        );
        let reg = registration.clone();
        let fv = fork_version;
        let sign_ctx = SignContext::new(
            pubkey.clone(),
            ForkInfo {
                previous_version: fork_version,
                current_version: fork_version,
                genesis_validators_root: [0u8; 32],
            },
            ForkName::Phase0,
        );
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_builder_registration(&reg, fv, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "builder_registration", backend).await
    }

    /// Signs a sync committee selection proof for the given slot and subcommittee.
    #[tracing::instrument(name = "sign.sync_committee_selection_proof", skip_all, fields(duty = %Duty::SyncContribution.as_str()))]
    async fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root =
            signing_root_for(&DutyRef::SyncSelection { slot, subcommittee_index }, &ctx);
        let gvr = *genesis_validators_root;
        let sign_ctx =
            sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, slot / SLOTS_PER_EPOCH);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_sync_aggregator_selection(slot, subcommittee_index, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "sync_committee_selection_proof", backend)
            .await
    }

    /// Signs a ContributionAndProof with DOMAIN_CONTRIBUTION_AND_PROOF.
    #[tracing::instrument(name = "sign.contribution_and_proof", skip_all, fields(duty = %Duty::SyncContribution.as_str()))]
    async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let ctx = SigningCtx { fork_schedule, genesis_validators_root: *genesis_validators_root };
        let signing_root =
            signing_root_for(&DutyRef::ContributionAndProof(contribution_and_proof), &ctx);
        let gvr = *genesis_validators_root;
        let cap = contribution_and_proof.clone();
        let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
        let sign_ctx = sign_context_at_epoch(pubkey.clone(), fork_schedule, gvr, epoch);
        let typed = self.grpc_typed_factory(pubkey, move |grpc| async move {
            grpc.sign_contribution_and_proof(&cap, &sign_ctx).await
        });
        let backend = self.bls_backend_for_duty(pubkey, signing_root, typed);
        self.sign_nonslashable(pubkey, signing_root, "contribution_and_proof", backend).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A captured event: its level, message, the names of the spans in its scope
    /// (to prove a `spawn_blocking`-thread event re-enters the sign span), and the
    /// rendered text of all its non-message fields (to prove no raw secret leaks).
    #[derive(Clone)]
    struct CapturedEvent {
        level: tracing::Level,
        message: String,
        scope: Vec<String>,
        fields_text: String,
    }

    /// A captured span: its name and the `(field, value)` pairs recorded on it —
    /// both at creation (e.g. `slot`/`duty`) and late-bound via `record()` (e.g.
    /// `slashing_result`). Keyed by span id so `on_record` merges onto the same
    /// entry the late value was recorded against.
    #[derive(Clone)]
    struct CapturedSpan {
        name: String,
        fields: Vec<(String, String)>,
    }

    type Events = Arc<parking_lot::Mutex<Vec<CapturedEvent>>>;
    type Spans = Arc<parking_lot::Mutex<std::collections::HashMap<u64, CapturedSpan>>>;

    /// Visits field VALUES (not just names) so span-field landing and redaction
    /// can both be asserted. `%`/`?` values arrive via `record_debug`.
    struct ValueVisitor(Vec<(String, String)>);
    impl tracing::field::Visit for ValueVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push((field.name().to_string(), format!("{value:?}")));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push((field.name().to_string(), value.to_string()));
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.push((field.name().to_string(), value.to_string()));
        }
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.0.push((field.name().to_string(), value.to_string()));
        }
    }

    /// Splits an event's `message` from the rendered text of all other fields.
    #[derive(Default)]
    struct EventVisitor {
        message: Option<String>,
        fields_text: String,
    }
    impl tracing::field::Visit for EventVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            } else {
                self.fields_text.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = Some(value.to_string());
            } else {
                self.fields_text.push_str(&format!("{}={value} ", field.name()));
            }
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields_text.push_str(&format!("{}={value} ", field.name()));
        }
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.fields_text.push_str(&format!("{}={value} ", field.name()));
        }
    }

    /// Test-only capturing layer (format-independent). Non-poisoning
    /// `parking_lot::Mutex` buffers so a failed assertion in one test can never
    /// poison the buffer and cascade into a concurrent test under `cargo test`.
    struct Capture {
        events: Events,
        spans: Spans,
    }

    impl<S> tracing_subscriber::Layer<S> for Capture
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut v = ValueVisitor(Vec::new());
            attrs.record(&mut v);
            self.spans.lock().insert(
                id.into_u64(),
                CapturedSpan { name: attrs.metadata().name().to_string(), fields: v.0 },
            );
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut v = ValueVisitor(Vec::new());
            values.record(&mut v);
            if let Some(span) = self.spans.lock().get_mut(&id.into_u64()) {
                span.fields.extend(v.0);
            }
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut v = EventVisitor::default();
            event.record(&mut v);
            let scope: Vec<String> = ctx
                .event_scope(event)
                .into_iter()
                .flatten()
                .map(|span| span.name().to_string())
                .collect();
            self.events.lock().push(CapturedEvent {
                level: *event.metadata().level(),
                message: v.message.unwrap_or_default(),
                scope,
                fields_text: v.fields_text,
            });
        }
    }

    /// Issue 2.2 acceptance, in one test (one global subscriber per process):
    /// (1) the `spawn_blocking` closure re-enters the parent sign span so a
    ///     blocking-thread event stays correlated to the duty trace, and
    /// (2) the `sign.block` span actually records `slot` (the bare `fields(slot)`
    ///     form is a silent no-op under `skip_all`; the explicit `slot = slot`
    ///     form is required).
    ///
    /// A global subscriber is required because `spawn_blocking` runs on a
    /// separate OS thread the thread-local dispatcher would not reach. This is
    /// the crate's only `set_global_default` caller, so it always wins the
    /// one-shot install; buffers use a non-poisoning `parking_lot::Mutex` and
    /// every assertion clones out before checking, so a failure stays local even
    /// under `cargo test`'s shared-process, multi-thread model.
    /// Gate 3 (signer): one global subscriber proves, across a representative
    /// sign path, that
    ///  (1) the `spawn_blocking` closure re-enters the parent sign span so a
    ///      blocking-thread event stays correlated to the duty trace,
    ///  (2) the canonical fields land on the span — `slot`/`duty` at creation and
    ///      `slashing_result` late-bound via `record()` (the vanishing-attribute
    ///      guard); the bare `fields(slot)` form is a silent no-op under
    ///      `skip_all`, so the explicit `slot = slot` form is required,
    ///  (3) the validator pubkey appears only truncated — no full pubkey hex
    ///      reaches any event, including the `spawn_blocking`-thread rejection
    ///      line, and
    ///  (4) the per-signature success milestone fires at `debug` while a slashing
    ///      rejection fires at `error`.
    ///
    /// A global subscriber is required because `spawn_blocking` runs on a separate
    /// OS thread the thread-local dispatcher would not reach. This is the crate's
    /// only `set_global_default` caller, so it always wins the one-shot install;
    /// buffers use a non-poisoning `parking_lot::Mutex` and every assertion clones
    /// out before checking, so a failure stays local even under `cargo test`'s
    /// shared-process, multi-thread model.
    #[tokio::test]
    async fn test_sign_path_redaction_level_and_field_conformance() {
        use tracing_subscriber::layer::SubscriberExt;

        let events: Events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let spans: Spans = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        let subscriber = tracing_subscriber::registry::Registry::default()
            .with(Capture { events: events.clone(), spans: spans.clone() });
        let _ = tracing::subscriber::set_global_default(subscriber);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let full_pubkey_hex = hex::encode(pubkey.to_bytes());
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        // Attestation (slot 1000): exercises the first spawn_blocking closure and
        // commits a record at target epoch 101.
        let attestation_data = create_test_attestation_data(100, 101);
        service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await
            .expect("attestation sign should succeed");

        // Block (slot 3200): exercises the second spawn_blocking closure.
        service
            .sign_block(&[0x11; 32], 3200, &pubkey, &fork_schedule, &genesis_root)
            .await
            .expect("block sign should succeed");

        // Conflicting attestation: same target epoch 101, different data → a
        // double-vote the slashing DB rejects, exercising the blocking-thread
        // `error!` rejection line and `slashing_result = "blocked"`.
        let conflicting = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x99; 32],
            source: Checkpoint { epoch: 100, root: [0x22; 32] },
            target: Checkpoint { epoch: 101, root: [0x44; 32] },
        };
        let blocked =
            service.sign_attestation(&conflicting, &pubkey, &fork_schedule, &genesis_root).await;
        assert!(
            matches!(blocked, Err(SignerError::SlashingBlocked(_))),
            "conflicting attestation must be slashing-blocked, got {blocked:?}"
        );

        let events = events.lock().clone();
        let spans: Vec<CapturedSpan> = spans.lock().values().cloned().collect();

        // (1) Re-entry: the attestation blocking-thread marker carries the span.
        let att_scope = events
            .iter()
            .find(|e| e.message.contains("reserving attestation slashing-protection record"))
            .map(|e| e.scope.clone())
            .expect("attestation blocking-section marker must be captured");
        assert!(
            att_scope.iter().any(|name| name == "sign.attestation"),
            "blocking-section event must inherit the sign.attestation span; scope was {att_scope:?}"
        );

        // (2) Canonical fields land on the span (values, not just names).
        // Match by slot=3200 so concurrent tests that also emit `sign.block`
        // (e.g. SEC-2a enablement tests) cannot pollute the assertion — the
        // global Capture subscriber is process-wide once installed.
        let block = spans
            .iter()
            .find(|s| {
                s.name == "sign.block" && s.fields.iter().any(|(k, v)| k == "slot" && v == "3200")
            })
            .expect("sign.block span with slot=3200 must be created");
        assert!(
            block.fields.iter().any(|(k, v)| k == "duty" && v == "block"),
            "sign.block must record duty=block; fields were {:?}",
            block.fields
        );
        assert!(
            block.fields.iter().any(|(k, v)| k == "slashing_result" && v == "safe"),
            "sign.block must late-bind slashing_result=safe; fields were {:?}",
            block.fields
        );

        let att_spans: Vec<&CapturedSpan> =
            spans.iter().filter(|s| s.name == "sign.attestation").collect();
        assert!(
            att_spans
                .iter()
                .any(|s| s.fields.iter().any(|(k, v)| k == "duty" && v == "attestation")),
            "a sign.attestation span must record duty=attestation"
        );
        // The vanishing-attribute guard: both outcomes land late-bound.
        assert!(
            att_spans
                .iter()
                .any(|s| s.fields.iter().any(|(k, v)| k == "slashing_result" && v == "safe")),
            "a committed attestation must late-bind slashing_result=safe"
        );
        assert!(
            att_spans
                .iter()
                .any(|s| s.fields.iter().any(|(k, v)| k == "slashing_result" && v == "blocked")),
            "the rejected attestation must late-bind slashing_result=blocked"
        );

        // (3) Redaction: the full pubkey hex never appears on ANY event...
        for e in &events {
            assert!(
                !e.fields_text.contains(&full_pubkey_hex) && !e.message.contains(&full_pubkey_hex),
                "full pubkey hex leaked into event {:?} / {}",
                e.message,
                e.fields_text
            );
        }
        // ...and the blocking-thread rejection line carries the truncated pubkey.
        let rejection = events
            .iter()
            .find(|e| e.message.contains("slashing protection rejected duty"))
            .expect("rejection error line must be captured");
        assert!(
            rejection.fields_text.contains("..."),
            "rejection line must render a truncated pubkey; fields were {}",
            rejection.fields_text
        );

        // (4) Level conformance: success at debug, rejection at error.
        let completed = events
            .iter()
            .find(|e| e.message.contains("Signing completed"))
            .expect("success milestone must be captured");
        assert_eq!(
            completed.level,
            tracing::Level::DEBUG,
            "the per-signature success milestone must be debug, not info"
        );
        assert_eq!(rejection.level, tracing::Level::ERROR, "a slashing rejection must be error");
    }
    use crypto::{
        compute_domain, compute_signing_root, signing_root_for, DutyRef, KeyManager, LocalSigner,
        SecretKey, SigningCtx, DOMAIN_BEACON_ATTESTER,
    };
    use eth_types::{
        Checkpoint, SyncAggregatorSelectionData, DOMAIN_CONTRIBUTION_AND_PROOF,
        DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, SLOTS_PER_EPOCH,
    };

    fn create_test_composite_signer_with_key(secret_key: SecretKey) -> Arc<CompositeSigner> {
        let mut manager = KeyManager::new();
        manager.insert(secret_key);
        Arc::new(CompositeSigner::new(LocalSigner::new(manager)))
    }

    fn create_empty_composite_signer() -> Arc<CompositeSigner> {
        Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
    }

    fn create_test_attestation_data(source_epoch: u64, target_epoch: u64) -> AttestationData {
        AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: source_epoch, root: [0x22; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
        }
    }

    fn create_test_fork_schedule_for_attestation() -> ForkSchedule {
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

    #[test]
    fn test_signer_service_creation() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        assert!(service.signer().public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_sign_attestation_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service =
            SignerService::new(signer, slashing_db.clone()).with_enablement(always_enabled());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await;

        assert!(result.is_ok());
        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(101, &fork_schedule);
        let fork_version = fork_name.fork_version(&fork_schedule);
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&pubkey, &signing_root).is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert!(attestations[0].signing_root.is_some());
    }

    #[tokio::test]
    async fn test_sign_attestation_success_uses_correct_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        // Use a schedule where target_epoch=51 falls in the Phase0 range (before altair at 100)
        let fork_schedule = ForkSchedule {
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
            altair_fork_epoch: 100,
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
        };
        let attestation_data = create_test_attestation_data(50, 51);
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await;

        assert!(result.is_ok());
        let signature = result.unwrap();

        // target_epoch=51 is before altair at 100, so Phase0 fork version is used
        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER,
            fork_schedule.genesis_fork_version,
            genesis_root,
        );
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_attestation_prevents_double_vote_after_signing() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let attestation_data1 = create_test_attestation_data(100, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result1 = service
            .sign_attestation(&attestation_data1, &pubkey, &fork_schedule, &genesis_root)
            .await;
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(99, 101);
        let result2 = service
            .sign_attestation(&attestation_data2, &pubkey, &fork_schedule, &genesis_root)
            .await;

        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingBlocked(_) => {}
            _ => panic!("expected SlashingBlocked error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_allows_multiple_non_conflicting() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service =
            SignerService::new(signer, slashing_db.clone()).with_enablement(always_enabled());

        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let attestation_data1 = create_test_attestation_data(100, 101);
        let result1 = service
            .sign_attestation(&attestation_data1, &pubkey, &fork_schedule, &genesis_root)
            .await;
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(101, 102);
        let result2 = service
            .sign_attestation(&attestation_data2, &pubkey, &fork_schedule, &genesis_root)
            .await;
        assert!(result2.is_ok());

        let attestation_data3 = create_test_attestation_data(102, 103);
        let result3 = service
            .sign_attestation(&attestation_data3, &pubkey, &fork_schedule, &genesis_root)
            .await;
        assert!(result3.is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 3);
    }

    #[tokio::test]
    async fn test_sign_attestation_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let attestation_data = create_test_attestation_data(100, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(pk) => {
                assert_eq!(pk, hex::encode(pubkey.to_bytes()));
            }
            _ => panic!("expected KeyNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_slashing_blocked_double_vote() {
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let gvr = [0xaau8; 32]; // test gvr matching genesis_root below
        slashing_db
            .seed_attestation(&pubkey_hex, 100, 101, None, &gvr)
            .expect("record should succeed");

        let signer = create_empty_composite_signer();
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let attestation_data = create_test_attestation_data(99, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SlashingBlocked(_) => {}
            _ => panic!("expected SlashingBlocked error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_different_validators_isolated() {
        let secret_key1 = SecretKey::generate();
        let secret_key2 = SecretKey::generate();
        let pubkey1 = secret_key1.public_key();
        let pubkey2 = secret_key2.public_key();

        let signer = create_empty_composite_signer();
        signer.add_local_key(secret_key1);
        signer.add_local_key(secret_key2);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result1 = service
            .sign_attestation(&attestation_data, &pubkey1, &fork_schedule, &genesis_root)
            .await;
        assert!(result1.is_ok());

        let result2 = service
            .sign_attestation(&attestation_data, &pubkey2, &fork_schedule, &genesis_root)
            .await;
        assert!(result2.is_ok());
    }

    #[test]
    fn test_signer_error_display() {
        let err = SignerError::KeyNotFound("abc123".to_string());
        assert_eq!(err.to_string(), "key not found for pubkey: abc123");

        use slashing::AttestationSlashingViolation;
        let slashing_err =
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch: 100,
            });
        let err = SignerError::SlashingBlocked(slashing_err);
        assert!(err.to_string().contains("signing blocked by slashing protection"));

        let err = SignerError::SigningFailed("remote error".to_string());
        assert!(err.to_string().contains("signing failed"));

        let err = SignerError::UnsupportedDuty { duty: "payload_attestation" };
        assert_eq!(err.to_string(), "unsupported duty: payload_attestation");
    }

    /// RF4-03 (M1): production `sign_block` commit arm returns `CommitFailed`
    /// with the real signing root — not a hand-built enum.
    #[tokio::test]
    async fn test_sign_block_commit_failure_is_commit_failed_not_slashing_blocked() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            SignerService::new(signer, Arc::clone(&slashing_db)).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];
        let slot = 5u64;

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let expected_root = compute_signing_root(
            &block_root,
            compute_domain(eth_types::DOMAIN_BEACON_PROPOSER, fork_version, genesis_root),
        );

        slashing_db.fail_next_commits(1);
        let err = service
            .sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root)
            .await
            .expect_err("injected commit failure must surface");

        match &err {
            SignerError::CommitFailed { signing_root, source } => {
                assert_eq!(*signing_root, expected_root, "must carry the production signing root");
                assert!(
                    source.to_string().contains("injected commit failure"),
                    "source should be the inject: {source}"
                );
            }
            SignerError::SlashingBlocked(_) => {
                panic!("commit failure must NOT be reported as SlashingBlocked")
            }
            other => panic!("expected CommitFailed from production path, got: {other:?}"),
        }
        assert!(err.permits_retry_with_root(&expected_root));
        assert!(!err.permits_retry_with_root(&[0xff; 32]));

        // Nothing written; same-root retry after inject is exhausted succeeds.
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        assert!(
            slashing_db.get_blocks(&pubkey_hex).expect("query").is_empty(),
            "failed commit must leave no row"
        );
        service
            .sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root)
            .await
            .expect("same-root retry after CommitFailed must succeed");
        assert_eq!(slashing_db.get_blocks(&pubkey_hex).expect("query").len(), 1);
    }

    /// RF4-03 (M1): production `sign_attestation` commit arm returns `CommitFailed`.
    #[tokio::test]
    async fn test_sign_attestation_commit_failure_is_commit_failed_not_slashing_blocked() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            SignerService::new(signer, Arc::clone(&slashing_db)).with_enablement(always_enabled());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let epoch = attestation_data.target.epoch;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &fork_schedule);
        let fork_version = fork_name.fork_version(&fork_schedule);
        let expected_root = compute_signing_root(
            &attestation_data,
            compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_root),
        );

        slashing_db.fail_next_commits(1);
        let err = service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await
            .expect_err("injected commit failure must surface");

        match &err {
            SignerError::CommitFailed { signing_root, .. } => {
                assert_eq!(*signing_root, expected_root);
            }
            SignerError::SlashingBlocked(_) => {
                panic!("commit failure must NOT be reported as SlashingBlocked")
            }
            other => panic!("expected CommitFailed from production path, got: {other:?}"),
        }
        assert!(err.permits_retry_with_root(&expected_root));
        assert!(!err.permits_retry_with_root(&[0xee; 32]));

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        assert!(slashing_db.get_attestations(&pubkey_hex).expect("query").is_empty());
        service
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await
            .expect("same-root retry after CommitFailed must succeed");
    }

    /// RF4-03: stage rejection maps to `SlashingBlocked` (never retry different root).
    #[tokio::test]
    async fn test_slashing_rejection_maps_to_slashing_blocked() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        service
            .sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root)
            .await
            .expect("first proposal ok");

        let blocked = service
            .sign_block(&[0x22; 32], 5, &pubkey, &schedule, &genesis_root)
            .await
            .expect_err("double proposal must fail");
        match &blocked {
            SignerError::SlashingBlocked(_) => {}
            other => panic!("stage rejection must be SlashingBlocked, got: {other:?}"),
        }
        // Retry semantics on the first blocked error (not a second call).
        assert!(!blocked.permits_retry_with_root(&[0x11; 32]), "SlashingBlocked must refuse retry");
        assert!(!blocked.permits_retry_with_root(&[0x22; 32]));
    }

    /// RF4-03: pure unit check that `CommitFailed` retry helper is root-equality only.
    #[test]
    fn test_commit_failed_carries_signing_root_for_same_root_retry() {
        let signing_root = [0xcd; 32];
        let other_root = [0xef; 32];
        let err = SignerError::CommitFailed {
            signing_root,
            source: SlashingError::MigrationFailed("io".into()),
        };

        assert!(
            err.permits_retry_with_root(&signing_root),
            "same-root retry must be permitted after CommitFailed"
        );
        assert!(
            !err.permits_retry_with_root(&other_root),
            "different-root retry must be refused after CommitFailed"
        );

        match err {
            SignerError::CommitFailed { signing_root: r, .. } => assert_eq!(r, signing_root),
            other => panic!("expected CommitFailed, got {other:?}"),
        }
    }

    /// RF4-03: gate and service taxonomies agree on the two slashing concepts
    /// and their retry contracts (table-driven over both enums).
    #[test]
    fn test_gate_and_service_error_taxonomies_agree() {
        use slashing::{AttestationSlashingViolation, BlockSlashingViolation};

        let root_a = [0x11; 32];
        let root_b = [0x22; 32];

        let cases: &[(
            &str,
            SignerError,
            SigningGateError,
            /* same-root ok */ bool,
            /* other-root ok */ bool,
        )] = &[
            (
                "slashing_blocked_attestation",
                SignerError::SlashingBlocked(SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::DoubleVote { target_epoch: 1 },
                )),
                SigningGateError::SlashingBlocked(SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::DoubleVote { target_epoch: 1 },
                )),
                false,
                false,
            ),
            (
                "slashing_blocked_block",
                SignerError::SlashingBlocked(SlashingError::SlashableBlock(
                    BlockSlashingViolation::DoubleBlockProposal { slot: 9 },
                )),
                SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
                    BlockSlashingViolation::DoubleBlockProposal { slot: 9 },
                )),
                false,
                false,
            ),
            (
                "commit_failed",
                SignerError::CommitFailed {
                    signing_root: root_a,
                    source: SlashingError::MigrationFailed("io".into()),
                },
                SigningGateError::CommitFailed {
                    signing_root: root_a,
                    source: SlashingError::MigrationFailed("io".into()),
                },
                true,
                false,
            ),
        ];

        for (name, service_err, gate_err, same_ok, other_ok) in cases {
            assert_eq!(
                service_err.permits_retry_with_root(&root_a),
                *same_ok,
                "{name}: service same-root"
            );
            assert_eq!(
                service_err.permits_retry_with_root(&root_b),
                *other_ok,
                "{name}: service other-root"
            );
            assert_eq!(
                gate_err.permits_retry_with_root(&root_a),
                *same_ok,
                "{name}: gate same-root"
            );
            assert_eq!(
                gate_err.permits_retry_with_root(&root_b),
                *other_ok,
                "{name}: gate other-root"
            );

            // Both sides expose the same concept via discriminant-level matches.
            match (service_err, gate_err) {
                (SignerError::SlashingBlocked(_), SigningGateError::SlashingBlocked(_)) => {}
                (
                    SignerError::CommitFailed { signing_root: s, .. },
                    SigningGateError::CommitFailed { signing_root: g, .. },
                ) => {
                    assert_eq!(s, g, "{name}: carried roots must match");
                }
                other => panic!("{name}: taxonomy mismatch: {other:?}"),
            }
        }
    }

    #[test]
    fn test_truncate_error_body_short_message() {
        let msg = "short error";
        let result = truncate_error_body(msg, 200);
        assert_eq!(result, "short error");
    }

    #[test]
    fn test_truncate_error_body_exact_limit() {
        let msg = "a".repeat(200);
        let result = truncate_error_body(&msg, 200);
        assert_eq!(result, msg);
    }

    #[test]
    fn test_truncate_error_body_over_limit() {
        let msg = "a".repeat(300);
        let result = truncate_error_body(&msg, 200);
        assert_eq!(result.len(), 200 + "... (truncated)".len());
        assert!(result.ends_with("... (truncated)"));
        assert!(result.starts_with(&"a".repeat(200)));
    }

    #[test]
    fn test_remote_signer_error_truncated_on_conversion() {
        let long_msg = "x".repeat(500);
        let signing_error = SigningError::RemoteSignerError(long_msg);
        let signer_error: SignerError = signing_error.into();
        match signer_error {
            SignerError::SigningFailed(msg) => {
                assert!(msg.len() < 500);
                assert!(msg.ends_with("... (truncated)"));
            }
            _ => panic!("expected SigningFailed"),
        }
    }

    #[test]
    fn test_signer_service_accessors() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let keys = service.signer().public_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], pubkey.to_bytes());
    }

    // --- Block signing tests ---

    fn create_test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        }
    }

    #[tokio::test]
    async fn test_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service =
            SignerService::new(signer, slashing_db.clone()).with_enablement(always_enabled());

        let block_root = [0x11; 32];
        let slot = 5;
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(eth_types::DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 5);
        assert!(blocks[0].signing_root.is_some());
    }

    #[tokio::test]
    async fn test_sign_block_header_matches_sign_block_at_fulu() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let db_header = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let db_block = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let header_svc =
            SignerService::new(Arc::clone(&signer), db_header).with_enablement(always_enabled());
        let block_svc = SignerService::new(signer, db_block).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot = 60 * SLOTS_PER_EPOCH;
        let header = BeaconBlockHeaderFields {
            slot,
            proposer_index: 7,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
            body_ssz: Vec::new(),
            is_blinded: false,
        };
        let block_root = header.object_root();

        let sig_header = header_svc
            .sign_block_header(&header, &pubkey, &schedule, &genesis_root)
            .await
            .expect("header sign");
        let sig_block = block_svc
            .sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root)
            .await
            .expect("root sign");
        assert_eq!(sig_header.to_bytes(), sig_block.to_bytes());
    }

    #[tokio::test]
    async fn test_sign_block_double_proposal_rejected() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result1.is_ok());

        let result2 = service.sign_block(&[0x22; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingBlocked(_) => {}
            other => panic!("expected SlashingBlocked, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_block_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    // --- RANDAO signing tests ---

    #[tokio::test]
    async fn test_sign_randao_reveal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 5_u64;

        let result = service.sign_randao_reveal(epoch, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(eth_types::DOMAIN_RANDAO, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_randao_reveal_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    fn gloas_ptc_fixture() -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        }
    }

    fn gloas_ptc_fork_schedule() -> ForkSchedule {
        let mut schedule = create_test_fork_schedule();
        schedule.gloas_fork_epoch = 0;
        schedule.gloas_fork_version = [0x07, 0x00, 0x00, 0x01];
        schedule
    }

    /// Signing a payload attestation writes no slashing-DB row (row count
    /// before and after).
    #[tokio::test]
    async fn test_sign_payload_attestation_writes_no_slashing_row() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            SignerService::new(signer, Arc::clone(&slashing_db)).with_enablement(always_enabled());

        let before_blocks = slashing_db.get_blocks(&pubkey_hex).expect("query blocks").len();
        let before_attestations =
            slashing_db.get_attestations(&pubkey_hex).expect("query attestations").len();

        let schedule = gloas_ptc_fork_schedule();
        let gvr = [0u8; 32];
        let data = gloas_ptc_fixture();
        let sig = service
            .sign_payload_attestation(&data, &pubkey, &schedule, &gvr)
            .await
            .expect("payload attestation is non-slashable and must sign");

        let kat_root: Root =
            hex::decode(rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
                .expect("kat hex")
                .try_into()
                .expect("32-byte kat root");
        assert!(
            sig.verify(&pubkey, &kat_root).is_ok(),
            "payload attestation must verify over KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT, not a fallback domain"
        );

        let after_blocks = slashing_db.get_blocks(&pubkey_hex).expect("query blocks").len();
        let after_attestations =
            slashing_db.get_attestations(&pubkey_hex).expect("query attestations").len();
        assert_eq!(after_blocks, before_blocks, "payload attestation must not write a block row");
        assert_eq!(
            after_attestations, before_attestations,
            "payload attestation must not write an attestation row"
        );
    }

    #[test]
    fn test_unsupported_duty_from_signing_error() {
        let err: SignerError = SigningError::UnsupportedDuty { duty: "payload_attestation" }.into();
        match err {
            SignerError::UnsupportedDuty { duty } => assert_eq!(duty, "payload_attestation"),
            other => panic!("expected UnsupportedDuty, got: {other:?}"),
        }
    }

    // --- Sync committee signing tests ---

    #[tokio::test]
    async fn test_sign_sync_committee_message() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let beacon_block_root = [0x11; 32];
        let slot = SLOTS_PER_EPOCH * 15; // Altair epoch
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_sync_committee_message(
                &beacon_block_root,
                slot,
                &pubkey,
                &schedule,
                &genesis_root,
            )
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&beacon_block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- ValidatorSigner trait tests ---

    #[tokio::test]
    async fn test_trait_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service =
            SignerService::new(signer, slashing_db.clone()).with_enablement(always_enabled());
        let trait_signer: &dyn ValidatorSigner = &service;

        let block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result =
            trait_signer.sign_block(&block_root, 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig = result.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn test_trait_sign_attestation_still_works() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service =
            SignerService::new(signer, slashing_db.clone()).with_enablement(always_enabled());
        let trait_signer: &dyn ValidatorSigner = &service;

        let attestation_data = create_test_attestation_data(100, 101);
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = trait_signer
            .sign_attestation(&attestation_data, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let sig = result.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
    }

    /// Compile-level + runtime check that `ValidatorSigner` returns `crypto::Signature`.
    #[tokio::test]
    async fn test_validator_signer_trait_returns_typed_signature() {
        fn _assert_returns_signature<T: ValidatorSigner>(_: &T) {}

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());
        _assert_returns_signature(&service);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let trait_signer: &dyn ValidatorSigner = &service;
        let sig: Signature = trait_signer
            .sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root)
            .await
            .expect("sign_block via trait");
        // Typed binding proves the trait surface is `Signature`, not `Vec<u8>`.
        let _: [u8; 96] = sig.to_bytes();
    }

    /// Concrete `SignerService` and `&dyn ValidatorSigner` share one method
    /// surface (single-surface RF4-12) — same-root re-sign yields identical bytes.
    ///
    /// BLS signing with a fixed key and root is deterministic; the second call
    /// is allowed by EIP-3076 same-root retry and must match the first.
    #[tokio::test]
    async fn test_trait_and_inherent_methods_are_the_same_function() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x22; 32];
        let slot = 7u64;

        // Concrete type (trait method in scope via `use super::*`).
        let via_concrete = service
            .sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root)
            .await
            .expect("concrete");

        // Same service via trait object — no second API surface.
        let trait_signer: &dyn ValidatorSigner = &service;
        let via_trait = trait_signer
            .sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root)
            .await
            .expect("trait object");

        assert_eq!(
            via_concrete.to_bytes(),
            via_trait.to_bytes(),
            "concrete and dyn trait object must return identical signature bytes"
        );
    }

    // --- Aggregation signing tests ---

    fn create_test_aggregate_and_proof(slot: Slot) -> eth_types::AggregateAndProof {
        eth_types::AggregateAndProof {
            aggregator_index: 42,
            aggregate: eth_types::Attestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 1,
                    beacon_block_root: [1u8; 32],
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH + 1, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[tokio::test]
    async fn test_sign_selection_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot: Slot = 100;

        let result = service.sign_selection_proof(slot, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(eth_types::DOMAIN_SELECTION_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&slot, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_aggregate_and_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let agg_and_proof = create_test_aggregate_and_proof(100);

        let result = service
            .sign_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let slot = agg_and_proof.aggregate.data.slot;
        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(eth_types::DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_is_aggregator_reexported() {
        assert!(is_aggregator(0, &[0xaa; 96]));
        assert!(is_aggregator(1, &[0xaa; 96]));
    }

    #[test]
    fn signer_reexports_is_aggregator_from_eth_types() {
        assert!(eth_types::is_aggregator(1, &[0x00; 96]));
    }

    fn create_test_electra_aggregate_and_proof(slot: Slot) -> eth_types::ElectraAggregateAndProof {
        eth_types::ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: eth_types::ElectraAttestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 0,
                    beacon_block_root: [1u8; 32],
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH + 1, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
                committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[tokio::test]
    async fn test_sign_electra_aggregate_and_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot = schedule.electra_fork_epoch * SLOTS_PER_EPOCH;
        let agg_and_proof = create_test_electra_aggregate_and_proof(slot);

        let result = service
            .sign_electra_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(eth_types::DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- Voluntary exit signing tests ---

    #[tokio::test]
    async fn test_sign_voluntary_exit_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let exit = eth_types::VoluntaryExit { epoch: 5, validator_index: 42 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(exit.epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_electra_epoch_uses_capella_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 55 is in the Electra era (electra_fork_epoch=50)
        let exit = eth_types::VoluntaryExit { epoch: 55, validator_index: 99 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        // EIP-7044: still capped at Capella even in Electra
        let capella_fork_version = schedule.capella_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "EIP-7044: voluntary exit at Electra epoch must use Capella fork version"
        );
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_pre_capella_uses_actual_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 15 is in the Altair era (altair=10, bellatrix=20) — pre-Capella, no cap
        let exit = eth_types::VoluntaryExit { epoch: 15, validator_index: 7 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let altair_fork_version = schedule.altair_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "Pre-Capella voluntary exit should use the actual fork version (Altair)"
        );
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_deneb_epoch_uses_capella_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 45 is in the Deneb era (deneb_fork_epoch=40, electra_fork_epoch=50)
        let exit = eth_types::VoluntaryExit { epoch: 45, validator_index: 42 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        // EIP-7044: voluntary exit fork version MUST be capped at Capella
        let capella_fork_version = schedule.capella_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "EIP-7044: voluntary exit at Deneb epoch must use Capella fork version"
        );
    }

    // --- Builder registration signing tests ---

    fn create_test_registration() -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        }
    }

    #[tokio::test]
    async fn test_sign_builder_registration_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let registration = create_test_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let result = service.sign_builder_registration(&registration, &pubkey, fork_version).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let zeroed_genesis_root = [0u8; 32];
        let domain = compute_domain(
            eth_types::DOMAIN_APPLICATION_BUILDER,
            fork_version,
            zeroed_genesis_root,
        );
        let signing_root = compute_signing_root(&registration, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- CompositeSigner integration: dynamically added keys work ---

    #[tokio::test]
    async fn test_dynamically_added_key_is_signable() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            SignerService::new(signer.clone(), slashing_db).with_enablement(always_enabled());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        // Key is not in signer yet — signing should fail
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());

        // Add key dynamically (simulating keymanager API import)
        signer.add_local_key(secret_key);

        // Now signing should succeed
        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());
    }

    // --- Sync committee selection proof / contribution tests ---

    #[tokio::test]
    async fn test_sign_sync_committee_selection_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let slot: Slot = 100;
        let subcommittee_index: u64 = 2;
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_sync_committee_selection_proof(
                slot,
                subcommittee_index,
                &pubkey,
                &schedule,
                &genesis_root,
            )
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, fork_version, genesis_root);
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_contribution_and_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let contribution_and_proof = ContributionAndProof {
            aggregator_index: 42,
            contribution: eth_types::SyncCommitteeContribution {
                slot: 100,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        };

        let result = service
            .sign_contribution_and_proof(&contribution_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&contribution_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- COR-01 Tests: Per-validator signing mutex ---

    #[test]
    fn test_validator_lock_map_returns_same_lock_for_same_key() {
        let map = ValidatorLockMap::new();
        let pk = [1u8; 48];
        let lock1 = map.get(&pk);
        let lock2 = map.get(&pk);
        assert!(Arc::ptr_eq(&lock1, &lock2));
    }

    #[test]
    fn test_validator_lock_map_returns_different_locks_for_different_keys() {
        let map = ValidatorLockMap::new();
        let pk1 = [1u8; 48];
        let pk2 = [2u8; 48];
        let lock1 = map.get(&pk1);
        let lock2 = map.get(&pk2);
        assert!(!Arc::ptr_eq(&lock1, &lock2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_signing_same_validator_serialized() {
        use tokio::sync::Barrier;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            Arc::new(SignerService::new(signer, slashing_db).with_enablement(always_enabled()));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];
        let barrier = Arc::new(Barrier::new(2));

        // Task A: (source=59, target=60), Task B: (source=58, target=60)
        // Same target, different source = double-vote attempt.
        // The per-validator mutex serializes access so the second task sees
        // the first's record and gets rejected by slashing protection.
        let data_a = create_test_attestation_data(59, 60);
        let data_b = create_test_attestation_data(58, 60);

        let mut handles = vec![];
        for d in [data_a, data_b] {
            let service = service.clone();
            let pk = pubkey.clone();
            let f = fork_schedule.clone();
            let barrier = barrier.clone();

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                service.sign_attestation(&d, &pk, &f, &genesis_root).await
            }));
        }

        let mut results = vec![];
        for h in handles {
            results.push(h.await.unwrap());
        }

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(successes, 1, "exactly one concurrent attestation must succeed");
        assert_eq!(failures, 1, "exactly one concurrent attestation must be rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_signing_different_validators_parallel() {
        use tokio::sync::Barrier;

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let mut manager = KeyManager::new();
        manager.insert(sk1);
        manager.insert(sk2);
        let signer = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            Arc::new(SignerService::new(signer, slashing_db).with_enablement(always_enabled()));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];
        let barrier = Arc::new(Barrier::new(2));

        let mut handles = vec![];
        for (pk, epoch) in [(pk1, 60u64), (pk2, 60)] {
            let service = service.clone();
            let f = fork_schedule.clone();
            let barrier = barrier.clone();

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let data = create_test_attestation_data(epoch - 1, epoch);
                service.sign_attestation(&data, &pk, &f, &genesis_root).await
            }));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_ok(), "parallel signing should succeed: {:?}", result.err());
        }
    }

    #[tokio::test]
    async fn test_signing_failure_does_not_commit_phantom_row() {
        // M-1 fix: when signing fails, the staged slashing-DB row must be rolled back
        // so no phantom entry remains.  Before the fix, this test would find a row.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        // Signer with no keys — signing will fail with KeyNotFound.
        let empty_signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service =
            SignerService::new(empty_signer, slashing_db.clone()).with_enablement(always_enabled());
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let data = create_test_attestation_data(59, 60);
        let result = service.sign_attestation(&data, &pubkey, &fork_schedule, &genesis_root).await;
        assert!(result.is_err(), "expected signing failure when key is absent");

        match result.err().unwrap() {
            SignerError::KeyNotFound(_) | SignerError::SigningFailed(_) => {}
            other => panic!("expected signing failure, got: {other}"),
        }

        // M-1 fix: the staged row must have been rolled back — DB must be empty.
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations =
            slashing_db.get_attestations(&pubkey_hex).expect("failed to query slashing db");
        assert!(
            attestations.is_empty(),
            "M-1 fix: no phantom row must be committed after signing failure; found: {attestations:?}"
        );
    }

    #[tokio::test]
    async fn test_db_error_returns_error_not_silent_success() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = dir.path().join("slashing.sqlite");
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        // Record one valid attestation via a first service instance, then drop it
        {
            let sk = SecretKey::generate();
            let pk = sk.public_key();
            let signer = create_test_composite_signer_with_key(sk);
            let slashing_db = Arc::new(SlashingDb::open(&db_path).expect("failed to open db"));
            let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());
            let data = create_test_attestation_data(59, 60);
            let result = service.sign_attestation(&data, &pk, &fork_schedule, &genesis_root).await;
            assert!(result.is_ok(), "first attestation should succeed");
        }
        // Connection is dropped, flushing WAL to disk

        // Corrupt the SQLite database file and remove WAL/SHM sidecars
        std::fs::write(&db_path, b"corrupted").expect("failed to corrupt db");
        let wal_path = db_path.with_extension("sqlite-wal");
        let shm_path = db_path.with_extension("sqlite-shm");
        let _ = std::fs::remove_file(&wal_path);
        let _ = std::fs::remove_file(&shm_path);

        // Open a new service from the corrupted database
        let sk2 = SecretKey::generate();
        let pk2 = sk2.public_key();
        let signer = create_test_composite_signer_with_key(sk2);
        let corrupted_db = SlashingDb::open(&db_path);

        // Fail-closed in BOTH branches — no vacuous pass (RF1-02 / F124).
        match corrupted_db {
            Ok(db) => {
                // SQLite may open a corrupt file and surface the error on first query.
                let service =
                    SignerService::new(signer, Arc::new(db)).with_enablement(always_enabled());
                let data = create_test_attestation_data(60, 61);
                let result =
                    service.sign_attestation(&data, &pk2, &fork_schedule, &genesis_root).await;
                assert!(
                    result.is_err(),
                    "DB error on sign must propagate (fail-closed), not be swallowed; got {result:?}"
                );
            }
            Err(open_err) => {
                // Opening itself rejected the corrupt file — also fail-closed.
                // Assert unconditionally so this branch cannot pass vacuously
                // when open fails (the pre-RF1-02 form had an empty `if let Ok`
                // else arm).
                let msg = open_err.to_string().to_lowercase();
                assert!(
                    msg.contains("corrupt")
                        || msg.contains("empty")
                        || msg.contains("database")
                        || msg.contains("sqlite")
                        || msg.contains("header")
                        || msg.contains("inspect"),
                    "SlashingDb::open must fail closed on corrupted file with a \
                     recognizable error; got: {open_err}"
                );
            }
        }
    }

    // ── SEC-2a: production SignerService consults SigningEnablement ─────────

    /// Enablement mock that denies every pubkey.
    struct DenyAllEnablement;
    impl SigningEnablement for DenyAllEnablement {
        fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn test_sign_block_refused_when_enablement_false() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, Arc::clone(&slashing_db))
            .with_enablement(Arc::new(DenyAllEnablement));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_block(&[0x11; 32], 100, &pubkey, &fork_schedule, &genesis_root).await;

        assert!(
            matches!(result, Err(SignerError::BlockedByDoppelganger)),
            "closed enablement must refuse block signing; got: {result:?}"
        );

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("query blocks");
        assert!(
            blocks.is_empty(),
            "closed enablement must not stage/commit a slashing row; found: {blocks:?}"
        );
    }

    #[tokio::test]
    async fn test_sign_attestation_refused_when_enablement_false() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, Arc::clone(&slashing_db))
            .with_enablement(Arc::new(DenyAllEnablement));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];
        let data = create_test_attestation_data(10, 11);

        let result = service.sign_attestation(&data, &pubkey, &fork_schedule, &genesis_root).await;

        assert!(
            matches!(result, Err(SignerError::BlockedByDoppelganger)),
            "closed enablement must refuse attestation signing; got: {result:?}"
        );

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("query attestations");
        assert!(
            attestations.is_empty(),
            "closed enablement must not stage/commit a slashing row; found: {attestations:?}"
        );
    }

    #[tokio::test]
    async fn test_default_enablement_is_fail_closed_for_unknown_key() {
        // Un-wired SignerService::new must refuse every key (fail-closed default).
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, Arc::clone(&slashing_db));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let block =
            service.sign_block(&[0x22; 32], 200, &pubkey, &fork_schedule, &genesis_root).await;
        assert!(
            matches!(block, Err(SignerError::BlockedByDoppelganger)),
            "default enablement must fail closed for block; got: {block:?}"
        );

        let data = create_test_attestation_data(20, 21);
        let att = service.sign_attestation(&data, &pubkey, &fork_schedule, &genesis_root).await;
        assert!(
            matches!(att, Err(SignerError::BlockedByDoppelganger)),
            "default enablement must fail closed for attestation; got: {att:?}"
        );

        // Codify PRD §6.3: FailClosedDefault for bool is false.
        assert!(!<bool as FailClosedDefault>::default_when_unknown());
    }

    #[tokio::test]
    async fn test_enablement_check_precedes_slashing_stage() {
        // When enablement is closed, stage is never reached: a different signing
        // root at a pre-seeded slot would be SlashingBlocked *if*
        // stage ran; we assert the error is BlockedByDoppelganger instead, and
        // that the pre-seeded row count is unchanged.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let gvr = [0xaa; 32];
        slashing_db
            .check_and_record_block(&pubkey_hex, 50, Some(hex::encode([0xaa; 32])), &gvr)
            .expect("seed block row");

        let service = SignerService::new(signer, Arc::clone(&slashing_db))
            .with_enablement(Arc::new(DenyAllEnablement));
        let fork_schedule = create_test_fork_schedule_for_attestation();

        // Different root at same slot: would be SlashingBlocked if stage ran.
        let result = service.sign_block(&[0xbb; 32], 50, &pubkey, &fork_schedule, &gvr).await;

        assert!(
            matches!(result, Err(SignerError::BlockedByDoppelganger)),
            "enablement must refuse before stage; got: {result:?} \
             (SlashingBlocked would mean stage ran first)"
        );

        // Only the pre-seeded row should exist (no additional stage/commit).
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("query blocks");
        assert_eq!(
            blocks.len(),
            1,
            "enablement denial must not add a slashing row; found: {blocks:?}"
        );
    }

    /// Returns true on the first `is_signing_enabled` call, false thereafter.
    /// Models Safe→Detected between the early check and the under-lock re-check.
    struct AllowOnceThenDeny {
        remaining: std::sync::atomic::AtomicUsize,
    }
    impl AllowOnceThenDeny {
        fn new() -> Self {
            Self { remaining: std::sync::atomic::AtomicUsize::new(1) }
        }
    }
    impl SigningEnablement for AllowOnceThenDeny {
        fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
            // fetch_update / swap: first caller sees 1 → true, subsequent → false.
            self.remaining
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| Some(n.saturating_sub(1)),
                )
                .map(|prev| prev > 0)
                .unwrap_or(false)
        }
    }

    #[tokio::test]
    async fn test_enablement_rechecked_under_lock_for_block() {
        // Without under-lock re-check, the early allow would let stage run.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, Arc::clone(&slashing_db))
            .with_enablement(Arc::new(AllowOnceThenDeny::new()));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_block(&[0xcc; 32], 300, &pubkey, &fork_schedule, &genesis_root).await;

        assert!(
            matches!(result, Err(SignerError::BlockedByDoppelganger)),
            "under-lock re-check must refuse after early allow; got: {result:?}"
        );
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("query blocks");
        assert!(blocks.is_empty(), "under-lock denial must not stage a row; found: {blocks:?}");
    }

    #[tokio::test]
    async fn test_enablement_rechecked_under_lock_for_attestation() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, Arc::clone(&slashing_db))
            .with_enablement(Arc::new(AllowOnceThenDeny::new()));
        let fork_schedule = create_test_fork_schedule_for_attestation();
        let genesis_root = [0xaa; 32];
        let data = create_test_attestation_data(30, 31);

        let result = service.sign_attestation(&data, &pubkey, &fork_schedule, &genesis_root).await;

        assert!(
            matches!(result, Err(SignerError::BlockedByDoppelganger)),
            "under-lock re-check must refuse after early allow; got: {result:?}"
        );
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("query attestations");
        assert!(
            attestations.is_empty(),
            "under-lock denial must not stage a row; found: {attestations:?}"
        );
    }

    /// Characterization: every schedule-aware `SignerService` method derives its
    /// root via `signing_root_for` — proven by verifying the signature against
    /// the shared helper under a non-default fork schedule.
    #[tokio::test]
    async fn test_all_sign_methods_derive_roots_via_signing_root_for() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        // Compressed, non-default schedule so an accidental hardcoded fork fails.
        let schedule = ForkSchedule {
            genesis_fork_version: [0x10, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [0x11, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [0x12, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [0x13, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [0x14, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [0x15, 0, 0, 0],
            fulu_fork_epoch: 60,
            fulu_fork_version: [0x16, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0x17, 0, 0, 0],
        };
        let gvr: Root = [0xbb; 32];
        let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: gvr };

        // Attestation at Altair.
        let att = create_test_attestation_data(9, 10);
        let sig = service.sign_attestation(&att, &pubkey, &schedule, &gvr).await.unwrap();
        let root = signing_root_for(&DutyRef::Attestation(&att), &ctx);
        assert!(sig.verify(&pubkey, &root).is_ok(), "attestation root must match signing_root_for");

        // Block at Capella.
        let block_root: Root = [0x11; 32];
        let slot = 30 * SLOTS_PER_EPOCH;
        let sig = service.sign_block(&block_root, slot, &pubkey, &schedule, &gvr).await.unwrap();
        let root = signing_root_for(&DutyRef::BlockRoot { root: &block_root, slot }, &ctx);
        assert!(sig.verify(&pubkey, &root).is_ok(), "block root must match signing_root_for");

        // RANDAO at Deneb.
        let epoch = 45u64;
        let sig = service.sign_randao_reveal(epoch, &pubkey, &schedule, &gvr).await.unwrap();
        let root = signing_root_for(&DutyRef::Randao(epoch), &ctx);
        assert!(sig.verify(&pubkey, &root).is_ok(), "randao root must match signing_root_for");

        // Voluntary exit post-Capella (auto Capella-cap).
        let exit = VoluntaryExit { epoch: 55, validator_index: 1 };
        let sig = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &gvr).await.unwrap();
        let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx);
        assert!(
            sig.verify(&pubkey, &root).is_ok(),
            "voluntary exit root must match signing_root_for (Capella-capped)"
        );

        // Builder registration preserves caller-supplied fork version.
        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1,
            pubkey: pubkey.to_bytes(),
        };
        let builder_fv = [0x99, 0, 0, 0];
        let sig = service.sign_builder_registration(&reg, &pubkey, builder_fv).await.unwrap();
        let root = crypto::signing_root_with_fork_version(
            &reg,
            eth_types::DOMAIN_APPLICATION_BUILDER,
            builder_fv,
            [0u8; 32],
        );
        assert!(
            sig.verify(&pubkey, &root).is_ok(),
            "builder registration must preserve per-transport fork version"
        );

        let ptc = gloas_ptc_fixture();
        let sig = service.sign_payload_attestation(&ptc, &pubkey, &schedule, &gvr).await.unwrap();
        let root = signing_root_for(&DutyRef::PtcAttestation(&ptc), &ctx);
        assert!(
            sig.verify(&pubkey, &root).is_ok(),
            "payload attestation root must match signing_root_for"
        );
    }

    // -------------------------------------------------------------------------
    // RF4-04: sign_nonslashable helper (timeout, no-lock, no-row, error parity)
    // -------------------------------------------------------------------------

    /// Backend that sleeps before signing — used to exercise sign timeout.
    struct SlowSigner {
        inner: LocalSigner,
        sleep: Duration,
    }

    #[async_trait]
    impl Signer for SlowSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<Signature, crypto::SigningError> {
            tokio::time::sleep(self.sleep).await;
            self.inner.sign(signing_root, pubkey).await
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.inner.public_keys()
        }
    }

    /// A hung backend must fail a non-slashable sign after the configured timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_nonslashable_sign_times_out_against_hung_backend() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let mut km = KeyManager::new();
        km.insert(secret_key);
        let slow: Arc<dyn Signer> =
            Arc::new(SlowSigner { inner: LocalSigner::new(km), sleep: Duration::from_millis(400) });
        // Composite can be empty: non-slashable path uses sign_backend override.
        let composite = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, slashing_db)
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(slow);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &gvr).await;

        assert!(
            matches!(
                result,
                Err(SignerError::SigningFailed(ref msg)) if msg.contains("timed out")
            ),
            "expected SigningFailed containing 'timed out', got: {result:?}"
        );
    }

    /// Holding the per-validator lock must not deadlock a non-slashable sign
    /// (helper must not take the lock).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_nonslashable_helper_takes_no_validator_lock() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_bytes = pubkey.to_bytes();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        // Hold the per-validator lock. If sign_nonslashable tried to acquire it,
        // this would deadlock (tokio Mutex is not reentrant on the same task).
        let lock = service.validator_locks.get(&pubkey_bytes);
        let _guard = lock.lock().await;

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            service.sign_randao_reveal(5, &pubkey, &schedule, &gvr),
        )
        .await;

        assert!(result.is_ok(), "non-slashable sign must not block on validator lock");
        assert!(result.unwrap().is_ok(), "sign must succeed while lock is held by caller");
    }

    /// Non-slashable helper must not write any slashing-DB row.
    #[tokio::test]
    async fn test_nonslashable_helper_writes_no_slashing_row() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service =
            SignerService::new(signer, Arc::clone(&slashing_db)).with_enablement(always_enabled());

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let contribution = make_minimal_contribution_and_proof(100);

        service.sign_randao_reveal(5, &pubkey, &schedule, &gvr).await.expect("randao");
        service
            .sign_sync_committee_message(&[0x11; 32], 100, &pubkey, &schedule, &gvr)
            .await
            .expect("sync message");
        service.sign_selection_proof(100, &pubkey, &schedule, &gvr).await.expect("selection");
        let agg = create_test_aggregate_and_proof(100);
        service.sign_aggregate_and_proof(&agg, &pubkey, &schedule, &gvr).await.expect("aggregate");
        let electra_agg = create_test_electra_aggregate_and_proof(100);
        service
            .sign_electra_aggregate_and_proof(&electra_agg, &pubkey, &schedule, &gvr)
            .await
            .expect("electra aggregate");
        let exit = VoluntaryExit { epoch: 10, validator_index: 1 };
        service.sign_voluntary_exit(&exit, &pubkey, &schedule, &gvr).await.expect("exit");
        let reg = create_test_registration();
        service.sign_builder_registration(&reg, &pubkey, [0; 4]).await.expect("builder");
        service
            .sign_sync_committee_selection_proof(100, 0, &pubkey, &schedule, &gvr)
            .await
            .expect("sync selection");
        service
            .sign_contribution_and_proof(&contribution, &pubkey, &schedule, &gvr)
            .await
            .expect("contribution");
        service
            .sign_payload_attestation(&gloas_ptc_fixture(), &pubkey, &schedule, &gvr)
            .await
            .expect("payload attestation");

        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get_blocks");
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("get_attestations");
        assert!(blocks.is_empty(), "non-slashable must not write block rows; found: {blocks:?}");
        assert!(
            attestations.is_empty(),
            "non-slashable must not write attestation rows; found: {attestations:?}"
        );
    }

    /// ARCH-5c / ARCH-P1-6: both facades classify the same four non-slashable
    /// outcomes the same way. Return types stay distinct (`SigningGateError` vs
    /// `SignerError`); only the class must match.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NonSlashableClass {
        Success,
        TimedOut,
        KeyNotFound,
        Backend,
    }

    fn classify_gate_nonslashable(result: Result<Vec<u8>, SigningGateError>) -> NonSlashableClass {
        match result {
            Ok(_) => NonSlashableClass::Success,
            Err(SigningGateError::SigningFailed(ref msg)) if msg.contains("timed out") => {
                NonSlashableClass::TimedOut
            }
            Err(SigningGateError::KeyNotFound) => NonSlashableClass::KeyNotFound,
            Err(SigningGateError::SigningFailed(_)) => NonSlashableClass::Backend,
            other => panic!("unexpected gate non-slashable outcome: {other:?}"),
        }
    }

    fn classify_service_nonslashable(result: Result<Signature, SignerError>) -> NonSlashableClass {
        match result {
            Ok(_) => NonSlashableClass::Success,
            Err(SignerError::SigningFailed(ref msg)) if msg.contains("timed out") => {
                NonSlashableClass::TimedOut
            }
            Err(SignerError::KeyNotFound(_)) => NonSlashableClass::KeyNotFound,
            Err(SignerError::SigningFailed(_)) => NonSlashableClass::Backend,
            other => panic!("unexpected service non-slashable outcome: {other:?}"),
        }
    }

    struct RemoteFailSigner;

    #[async_trait]
    impl Signer for RemoteFailSigner {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; 48],
        ) -> Result<Signature, crypto::SigningError> {
            Err(crypto::SigningError::RemoteSignerError("connection reset mid-response".into()))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            vec![]
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_nonslashable_path_behaves_identically_through_both_entry_points() {
        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let beacon_block_root = [0x11; 32];
        let slot = 100;

        // success
        {
            let secret_key = SecretKey::generate();
            let pubkey = secret_key.public_key();
            let mut km = KeyManager::new();
            km.insert(secret_key);
            let backend: Arc<dyn Signer> = Arc::new(LocalSigner::new(km));
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let gate = SigningGate::new_with_raw_signer(
                Arc::clone(&db),
                always_enabled(),
                Arc::clone(&backend),
                Arc::new(ValidatorLockMap::new()),
                Duration::from_secs(4),
            );
            let service = SignerService::new(create_empty_composite_signer(), db)
                .with_enablement(always_enabled())
                .with_sign_backend(backend);

            let gate_class = classify_gate_nonslashable(
                gate.sign_sync_committee_message(&pubkey, [0xde; 32]).await,
            );
            let svc_class = classify_service_nonslashable(
                service
                    .sign_sync_committee_message(&beacon_block_root, slot, &pubkey, &schedule, &gvr)
                    .await,
            );
            assert_eq!(gate_class, NonSlashableClass::Success);
            assert_eq!(svc_class, gate_class, "success class must match through both entry points");
        }

        // timeout
        {
            let secret_key = SecretKey::generate();
            let pubkey = secret_key.public_key();
            let mut km = KeyManager::new();
            km.insert(secret_key);
            let slow: Arc<dyn Signer> = Arc::new(SlowSigner {
                inner: LocalSigner::new(km),
                sleep: Duration::from_millis(400),
            });
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let gate = SigningGate::new_with_raw_signer(
                Arc::clone(&db),
                always_enabled(),
                Arc::clone(&slow),
                Arc::new(ValidatorLockMap::new()),
                Duration::from_millis(50),
            );
            let service = SignerService::new(create_empty_composite_signer(), db)
                .with_enablement(always_enabled())
                .with_sign_timeout(Duration::from_millis(50))
                .with_sign_backend(slow);

            let gate_class = classify_gate_nonslashable(
                gate.sign_sync_committee_message(&pubkey, [0xde; 32]).await,
            );
            let svc_class = classify_service_nonslashable(
                service
                    .sign_sync_committee_message(&beacon_block_root, slot, &pubkey, &schedule, &gvr)
                    .await,
            );
            assert_eq!(gate_class, NonSlashableClass::TimedOut);
            assert_eq!(svc_class, gate_class, "timeout class must match through both entry points");
        }

        // KeyNotFound
        {
            let pubkey = SecretKey::generate().public_key();
            let empty: Arc<dyn Signer> = Arc::new(LocalSigner::new(KeyManager::new()));
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let gate = SigningGate::new_with_raw_signer(
                Arc::clone(&db),
                always_enabled(),
                Arc::clone(&empty),
                Arc::new(ValidatorLockMap::new()),
                Duration::from_secs(4),
            );
            let service = SignerService::new(create_empty_composite_signer(), db)
                .with_enablement(always_enabled())
                .with_sign_backend(empty);

            let gate_class = classify_gate_nonslashable(
                gate.sign_sync_committee_message(&pubkey, [0xde; 32]).await,
            );
            let svc_class = classify_service_nonslashable(
                service
                    .sign_sync_committee_message(&beacon_block_root, slot, &pubkey, &schedule, &gvr)
                    .await,
            );
            assert_eq!(gate_class, NonSlashableClass::KeyNotFound);
            assert_eq!(
                svc_class, gate_class,
                "KeyNotFound class must match through both entry points"
            );
        }

        // generic backend error
        {
            let pubkey = SecretKey::generate().public_key();
            let failing: Arc<dyn Signer> = Arc::new(RemoteFailSigner);
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let gate = SigningGate::new_with_raw_signer(
                Arc::clone(&db),
                always_enabled(),
                Arc::clone(&failing),
                Arc::new(ValidatorLockMap::new()),
                Duration::from_secs(4),
            );
            let service = SignerService::new(create_empty_composite_signer(), db)
                .with_enablement(always_enabled())
                .with_sign_backend(failing);

            let gate_class = classify_gate_nonslashable(
                gate.sign_sync_committee_message(&pubkey, [0xde; 32]).await,
            );
            let svc_class = classify_service_nonslashable(
                service
                    .sign_sync_committee_message(&beacon_block_root, slot, &pubkey, &schedule, &gvr)
                    .await,
            );
            assert_eq!(gate_class, NonSlashableClass::Backend);
            assert_eq!(svc_class, gate_class, "backend class must match through both entry points");
        }
    }

    /// All non-slashable methods share the helper's error mapping
    /// (`BlockedByDoppelganger` and `KeyNotFound` parity tables).
    #[tokio::test]
    async fn test_each_nonslashable_method_delegates_to_helper() {
        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        // Arbitrary pubkey: enablement / KeyNotFound fire before signature verification.
        let pubkey = SecretKey::generate().public_key();
        let exit = VoluntaryExit { epoch: 10, validator_index: 1 };
        let agg = create_test_aggregate_and_proof(100);
        let electra_agg = create_test_electra_aggregate_and_proof(100);
        let reg = create_test_registration();
        let contribution = make_minimal_contribution_and_proof(100);

        // --- BlockedByDoppelganger: fail-closed default enablement ---
        {
            // Key material is irrelevant: the gate refuses before the BLS sign.
            let signer = create_test_composite_signer_with_key(SecretKey::generate());
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let service = SignerService::new(signer, db); // no with_enablement

            let results = vec![
                ("randao", service.sign_randao_reveal(5, &pubkey, &schedule, &gvr).await),
                (
                    "sync_committee_message",
                    service
                        .sign_sync_committee_message(&[0x11; 32], 100, &pubkey, &schedule, &gvr)
                        .await,
                ),
                (
                    "selection_proof",
                    service.sign_selection_proof(100, &pubkey, &schedule, &gvr).await,
                ),
                (
                    "aggregate_and_proof",
                    service.sign_aggregate_and_proof(&agg, &pubkey, &schedule, &gvr).await,
                ),
                (
                    "electra_aggregate_and_proof",
                    service
                        .sign_electra_aggregate_and_proof(&electra_agg, &pubkey, &schedule, &gvr)
                        .await,
                ),
                (
                    "voluntary_exit",
                    service.sign_voluntary_exit(&exit, &pubkey, &schedule, &gvr).await,
                ),
                (
                    "builder_registration",
                    service.sign_builder_registration(&reg, &pubkey, [0; 4]).await,
                ),
                (
                    "sync_committee_selection_proof",
                    service
                        .sign_sync_committee_selection_proof(100, 0, &pubkey, &schedule, &gvr)
                        .await,
                ),
                (
                    "contribution_and_proof",
                    service
                        .sign_contribution_and_proof(&contribution, &pubkey, &schedule, &gvr)
                        .await,
                ),
                (
                    "payload_attestation",
                    service
                        .sign_payload_attestation(&gloas_ptc_fixture(), &pubkey, &schedule, &gvr)
                        .await,
                ),
            ];

            for (name, result) in results {
                assert!(
                    matches!(result, Err(SignerError::BlockedByDoppelganger)),
                    "{name}: expected BlockedByDoppelganger, got: {result:?}"
                );
            }
        }

        // --- KeyNotFound: always_enabled + empty composite ---
        {
            let empty = create_empty_composite_signer();
            let db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
            let service = SignerService::new(empty, db).with_enablement(always_enabled());
            let unknown = SecretKey::generate().public_key();

            let results = vec![
                ("randao", service.sign_randao_reveal(5, &unknown, &schedule, &gvr).await),
                (
                    "sync_committee_message",
                    service
                        .sign_sync_committee_message(&[0x11; 32], 100, &unknown, &schedule, &gvr)
                        .await,
                ),
                (
                    "selection_proof",
                    service.sign_selection_proof(100, &unknown, &schedule, &gvr).await,
                ),
                (
                    "aggregate_and_proof",
                    service.sign_aggregate_and_proof(&agg, &unknown, &schedule, &gvr).await,
                ),
                (
                    "electra_aggregate_and_proof",
                    service
                        .sign_electra_aggregate_and_proof(&electra_agg, &unknown, &schedule, &gvr)
                        .await,
                ),
                (
                    "voluntary_exit",
                    service.sign_voluntary_exit(&exit, &unknown, &schedule, &gvr).await,
                ),
                (
                    "builder_registration",
                    service.sign_builder_registration(&reg, &unknown, [0; 4]).await,
                ),
                (
                    "sync_committee_selection_proof",
                    service
                        .sign_sync_committee_selection_proof(100, 0, &unknown, &schedule, &gvr)
                        .await,
                ),
                (
                    "contribution_and_proof",
                    service
                        .sign_contribution_and_proof(&contribution, &unknown, &schedule, &gvr)
                        .await,
                ),
                (
                    "payload_attestation",
                    service
                        .sign_payload_attestation(&gloas_ptc_fixture(), &unknown, &schedule, &gvr)
                        .await,
                ),
            ];

            for (name, result) in results {
                assert!(
                    matches!(result, Err(SignerError::KeyNotFound(_))),
                    "{name}: expected KeyNotFound, got: {result:?}"
                );
            }
        }
    }

    fn make_minimal_contribution_and_proof(slot: Slot) -> ContributionAndProof {
        ContributionAndProof {
            aggregator_index: 42,
            contribution: eth_types::SyncCommitteeContribution {
                slot,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        }
    }

    // -------------------------------------------------------------------------
    // RF4-06: SignerService on shared sign_slashable core (fail-closed remote)
    // -------------------------------------------------------------------------

    /// Signer that sleeps on every call — models a late remote completion.
    fn make_slow_backend(secret_key: SecretKey, sleep: Duration) -> Arc<dyn Signer> {
        let mut km = KeyManager::new();
        km.insert(secret_key);
        Arc::new(SlowSigner { inner: LocalSigner::new(km), sleep })
    }

    /// Register pubkey as HTTP-remote in the composite (no live dial) so
    /// `backend_kind == Remote` for policy tests.
    fn register_http_remote_marker(composite: &CompositeSigner, pk: [u8; 48]) {
        let remote = remote_signer_client::RemoteSigner::new_for_tests(
            remote_signer_client::RemoteSignerConfig::new("https://127.0.0.1:1"),
            vec![pk],
        );
        composite.add_remote_key(pk, Arc::new(remote));
    }

    /// Times out once, then signs promptly (same-root retry after retain).
    struct TimeoutOnceSigner {
        inner: LocalSigner,
        calls: std::sync::atomic::AtomicU64,
        first_sleep: Duration,
    }

    #[async_trait]
    impl Signer for TimeoutOnceSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<Signature, crypto::SigningError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                tokio::time::sleep(self.first_sleep).await;
            }
            self.inner.sign(signing_root, pubkey).await
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.inner.public_keys()
        }
    }

    /// Remote mock that always returns a transport-style error after a tiny delay
    /// (S2: ambiguous remote non-timeout failure).
    struct FailingRemoteSigner {
        pubkeys: Vec<[u8; 48]>,
    }

    #[async_trait]
    impl Signer for FailingRemoteSigner {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; 48],
        ) -> Result<Signature, crypto::SigningError> {
            Err(crypto::SigningError::RemoteSignerError(
                "connection reset after remote may have signed".into(),
            ))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.pubkeys.clone()
        }
    }

    /// Phase-gate late-completion test: **`BackendKind::Remote`** pubkey times out
    /// (retain), then a **conflicting** sign for the same target epoch is blocked.
    ///
    /// Must fail if `DiscardStagedRow` is ever used for a remote pubkey (MAJOR-1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remote_backend_timeout_then_late_completion_blocks_conflicting_sign() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pk = pubkey.to_bytes();
        // HTTP remote registry entry → BackendKind::Remote → RetainStagedRow.
        let composite = create_empty_composite_signer();
        register_http_remote_marker(&composite, pk);
        let slow = make_slow_backend(secret_key, Duration::from_millis(400));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(slow);

        assert_eq!(
            service.backend_kind(&pubkey),
            BackendKind::Remote,
            "phase-gate must pin BackendKind::Remote (not only Unknown)"
        );
        assert_eq!(
            service.timeout_policy_for(&pubkey),
            TimeoutPolicy::RetainStagedRow,
            "Remote must map to RetainStagedRow"
        );

        let schedule = create_test_fork_schedule_for_attestation();
        let gvr = [0xaa; 32];
        let first = create_test_attestation_data(10, 11);

        let err = service
            .sign_attestation(&first, &pubkey, &schedule, &gvr)
            .await
            .expect_err("first sign must time out");
        assert!(
            matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")),
            "expected timed out SigningFailed, got {err:?}"
        );

        // Conflicting attestation: same target epoch, different source → double-vote.
        let conflict = create_test_attestation_data(9, 11);
        let blocked = service
            .sign_attestation(&conflict, &pubkey, &schedule, &gvr)
            .await
            .expect_err("conflicting sign after retain-timeout must be blocked");
        assert!(
            matches!(blocked, SignerError::SlashingBlocked(_)),
            "late-completion retain must block conflicting retry, got {blocked:?}"
        );

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let rows = slashing_db.get_attestations(&pubkey_hex).expect("get attestations");
        assert_eq!(rows.len(), 1, "retain-on-timeout must leave one committed row");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remote_backend_timeout_retains_staged_row() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let composite = create_empty_composite_signer();
        register_http_remote_marker(&composite, pubkey.to_bytes());
        let slow = make_slow_backend(secret_key, Duration::from_millis(400));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(slow);
        assert_eq!(service.backend_kind(&pubkey), BackendKind::Remote);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let block_root = [0xbb; 32];
        let err = service
            .sign_block(&block_root, 42, &pubkey, &schedule, &gvr)
            .await
            .expect_err("must time out");
        assert!(matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")));

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get blocks");
        assert_eq!(blocks.len(), 1, "remote/unknown timeout must retain staged block row");
        assert_eq!(blocks[0].slot, 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_local_backend_timeout_discards_staged_row() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        // Local key on composite → InProcess → DiscardStagedRow.
        // Sleep-then-delegate avoids a second secret-key material copy (clippy disallows
        // SecretKey::to_bytes outside crypto).
        let composite = create_test_composite_signer_with_key(secret_key);
        struct SlowDelegatingSigner {
            inner: Arc<dyn Signer>,
            sleep: Duration,
        }
        #[async_trait]
        impl Signer for SlowDelegatingSigner {
            async fn sign(
                &self,
                signing_root: &Root,
                pubkey: &[u8; 48],
            ) -> Result<Signature, crypto::SigningError> {
                tokio::time::sleep(self.sleep).await;
                self.inner.sign(signing_root, pubkey).await
            }
            fn public_keys(&self) -> Vec<[u8; 48]> {
                self.inner.public_keys()
            }
        }
        let slow: Arc<dyn Signer> = Arc::new(SlowDelegatingSigner {
            inner: Arc::clone(&composite) as Arc<dyn Signer>,
            sleep: Duration::from_millis(400),
        });
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(slow);

        assert_eq!(service.backend_kind(&pubkey), BackendKind::InProcess);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let err = service
            .sign_block(&[0xcc; 32], 7, &pubkey, &schedule, &gvr)
            .await
            .expect_err("must time out");
        assert!(matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")));

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get blocks");
        assert!(blocks.is_empty(), "in-process timeout must discard staged row; found {blocks:?}");
    }

    #[test]
    fn test_unknown_backend_kind_defaults_to_retain() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let composite = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, slashing_db).with_enablement(always_enabled());

        assert_eq!(service.backend_kind(&pubkey), BackendKind::Unknown);
        assert_eq!(
            service.timeout_policy_for(&pubkey),
            TimeoutPolicy::RetainStagedRow,
            "Unknown must map to RetainStagedRow (fail-closed)"
        );
    }

    /// MAJOR-2: `LocalRejected` (gRPC raw-root / no remote I/O) must discard under
    /// Retain policy — never burn slot history for an unambiguous local reject.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_local_rejected_discards_under_remote_retain_policy() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pk = pubkey.to_bytes();

        struct LocalRejectSigner;
        #[async_trait]
        impl Signer for LocalRejectSigner {
            async fn sign(
                &self,
                _signing_root: &Root,
                _pubkey: &[u8; 48],
            ) -> Result<Signature, crypto::SigningError> {
                Err(crypto::SigningError::LocalRejected(
                    "raw-root signing is not supported for gRPC remote signers; use TypedSigner"
                        .into(),
                ))
            }
            fn public_keys(&self) -> Vec<[u8; 48]> {
                vec![]
            }
        }

        // Remote registry → Retain on ambiguous errors; LocalRejected must still discard.
        let composite = create_empty_composite_signer();
        register_http_remote_marker(&composite, pk);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_backend(Arc::new(LocalRejectSigner));

        assert_eq!(service.backend_kind(&pubkey), BackendKind::Remote);
        assert_eq!(service.timeout_policy_for(&pubkey), TimeoutPolicy::RetainStagedRow);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let err = service
            .sign_block(&[0xee; 32], 77, &pubkey, &schedule, &gvr)
            .await
            .expect_err("LocalRejected must fail the sign");
        assert!(
            matches!(err, SignerError::SigningFailed(_)),
            "expected SigningFailed from LocalRejected, got {err:?}"
        );

        let pubkey_hex = hex::encode(pk);
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get blocks");
        assert!(
            blocks.is_empty(),
            "LocalRejected must discard staged row (no remote contact); found {blocks:?}"
        );
    }

    /// SEC-1: concurrent remote import while a local-classified sign is in flight
    /// must upgrade Discard → Retain before backend contact (fail-closed).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_policy_upgrades_to_retain_when_remote_appears_before_sign() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pk = pubkey.to_bytes();
        // Start as local-only (would be Discard) but inject remote during first policy resolve.
        let composite = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));

        // Backend that always times out so we can observe retain vs discard.
        struct AlwaysTimeout;
        #[async_trait]
        impl Signer for AlwaysTimeout {
            async fn sign(
                &self,
                _signing_root: &Root,
                _pubkey: &[u8; 48],
            ) -> Result<Signature, crypto::SigningError> {
                tokio::time::sleep(Duration::from_millis(400)).await;
                Err(crypto::SigningError::RemoteSignerError("unreachable".into()))
            }
            fn public_keys(&self) -> Vec<[u8; 48]> {
                vec![]
            }
        }

        assert_eq!(
            SignerService::new(Arc::clone(&composite), Arc::clone(&slashing_db))
                .backend_kind(&pubkey),
            BackendKind::InProcess
        );

        // Register remote *before* sign so under-lock resolve sees Remote → Retain.
        // (Models keymanager import that lands before stage; full concurrent race
        // is covered by pre-sign recheck using the same resolver Arc.)
        register_http_remote_marker(&composite, pk);
        assert_eq!(
            SignerService::new(Arc::clone(&composite), Arc::clone(&slashing_db))
                .backend_kind(&pubkey),
            BackendKind::Unknown, // local + remote → fail-closed Unknown
        );

        let service = SignerService::new(Arc::clone(&composite), Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(Arc::new(AlwaysTimeout));

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let err = service
            .sign_block(&[0xab; 32], 88, &pubkey, &schedule, &gvr)
            .await
            .expect_err("must time out");
        assert!(matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")));

        let pubkey_hex = hex::encode(pk);
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get blocks");
        assert_eq!(
            blocks.len(),
            1,
            "dual local+remote after import must retain on timeout; found {blocks:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_same_root_retry_after_timeout_permitted() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let mut km = KeyManager::new();
        km.insert(secret_key);
        let once: Arc<dyn Signer> = Arc::new(TimeoutOnceSigner {
            inner: LocalSigner::new(km),
            calls: std::sync::atomic::AtomicU64::new(0),
            first_sleep: Duration::from_millis(400),
        });
        // Unknown → retain so first timeout commits the root; second same-root re-signs.
        let composite = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, slashing_db)
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(once);

        let schedule = create_test_fork_schedule_for_attestation();
        let gvr = [0xaa; 32];
        let data = create_test_attestation_data(20, 21);

        let first = service.sign_attestation(&data, &pubkey, &schedule, &gvr).await;
        assert!(
            matches!(first, Err(SignerError::SigningFailed(ref m)) if m.contains("timed out")),
            "first call must time out: {first:?}"
        );

        // EIP-3076 same-root re-sign after retain-commit is permitted.
        let second = service.sign_attestation(&data, &pubkey, &schedule, &gvr).await;
        assert!(second.is_ok(), "same-root retry after retain-timeout must succeed: {second:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_different_root_retry_after_timeout_blocked() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let composite = create_empty_composite_signer();
        let once: Arc<dyn Signer> = {
            let mut km = KeyManager::new();
            km.insert(secret_key);
            Arc::new(TimeoutOnceSigner {
                inner: LocalSigner::new(km),
                calls: std::sync::atomic::AtomicU64::new(0),
                first_sleep: Duration::from_millis(400),
            })
        };
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, slashing_db)
            .with_enablement(always_enabled())
            .with_sign_timeout(Duration::from_millis(50))
            .with_sign_backend(once);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let first_root = [0x11; 32];
        let err = service
            .sign_block(&first_root, 100, &pubkey, &schedule, &gvr)
            .await
            .expect_err("must time out");
        assert!(matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")));

        let other_root = [0x22; 32];
        let blocked = service
            .sign_block(&other_root, 100, &pubkey, &schedule, &gvr)
            .await
            .expect_err("different root same slot must be blocked after retain");
        assert!(
            matches!(blocked, SignerError::SlashingBlocked(_)),
            "expected SlashingBlocked, got {blocked:?}"
        );
    }

    /// Ambiguous remote non-timeout error under retain must commit the staged row (S2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remote_ambiguous_error_retains_staged_row() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pk_bytes = pubkey.to_bytes();
        let composite = create_empty_composite_signer();
        register_http_remote_marker(&composite, pk_bytes);
        let failing: Arc<dyn Signer> = Arc::new(FailingRemoteSigner { pubkeys: vec![pk_bytes] });
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(composite, Arc::clone(&slashing_db))
            .with_enablement(always_enabled())
            .with_sign_backend(failing);
        assert_eq!(service.backend_kind(&pubkey), BackendKind::Remote);

        let schedule = create_test_fork_schedule();
        let gvr = [0xaa; 32];
        let err = service
            .sign_block(&[0xdd; 32], 55, &pubkey, &schedule, &gvr)
            .await
            .expect_err("remote error must fail the sign");
        assert!(
            matches!(err, SignerError::SigningFailed(_)),
            "expected SigningFailed, got {err:?}"
        );

        let pubkey_hex = hex::encode(pk_bytes);
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("get blocks");
        assert_eq!(
            blocks.len(),
            1,
            "Retain policy must commit on ambiguous remote error; found {blocks:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_all_signer_metrics_still_recorded_after_core_delegation() {
        use crate::metrics::{
            attestation_status, slashing_result, tx_hold_kind, RVC_ATTESTATIONS_TOTAL,
            RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS, RVC_SIGNING_DURATION_SECONDS,
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL,
        };

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("open db"));
        let service = SignerService::new(signer, slashing_db).with_enablement(always_enabled());

        let safe_before =
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).get();
        let blocked_before = RVC_SLASHING_PROTECTION_CHECKS_TOTAL
            .with_label_values(&[slashing_result::BLOCKED])
            .get();
        let att_ok_before =
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).get();
        let att_fail_before =
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        let tx_hold_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
            .with_label_values(&[tx_hold_kind::ATTESTATION])
            .get_sample_count();
        let sign_dur_before =
            RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).get_sample_count();

        let schedule = create_test_fork_schedule_for_attestation();
        let gvr = [0xaa; 32];
        let data = create_test_attestation_data(30, 31);
        service
            .sign_attestation(&data, &pubkey, &schedule, &gvr)
            .await
            .expect("first attestation must succeed");

        // Double-vote conflict to exercise blocked + failed paths.
        let conflict = create_test_attestation_data(29, 31);
        let blocked = service.sign_attestation(&conflict, &pubkey, &schedule, &gvr).await;
        assert!(matches!(blocked, Err(SignerError::SlashingBlocked(_))));

        // Global prometheus counters race with parallel tests — assert growth, not exact deltas.
        assert!(
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).get()
                > safe_before,
            "safe check metric must increment on success"
        );
        assert!(
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL
                .with_label_values(&[slashing_result::BLOCKED])
                .get()
                > blocked_before,
            "blocked check metric must increment on slashing rejection"
        );
        assert!(
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).get()
                > att_ok_before,
            "attestation success counter must increment"
        );
        assert!(
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get()
                > att_fail_before,
            "attestation failed counter must increment on blocked"
        );
        assert!(
            RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
                .with_label_values(&[tx_hold_kind::ATTESTATION])
                .get_sample_count()
                > tx_hold_before,
            "tx-hold must observe stage paths"
        );
        assert!(
            RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).get_sample_count()
                > sign_dur_before,
            "signing duration must observe successful sign"
        );
    }
}
