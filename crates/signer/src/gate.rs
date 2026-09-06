//! `SigningGate` — the central signing seam for validator operations.
//!
//! Composes slashing protection, doppelganger detection, BLS signing, and
//! per-validator serialization into a single, defense-in-depth gate.
//!
//! # Slashable-signing flow
//!
//! For each slashable operation (`sign_block`, `sign_attestation`):
//!
//! 1. Cheap outer `gate_decision` — if false, return
//!    `Err(SigningGateError::BlockedByDoppelganger)` immediately (no lock).
//! 2. Delegate to [`crate::core::sign_slashable`] with
//!    [`TimeoutPolicy::DiscardStagedRow`] (in-process / gate backends):
//!    - acquire the per-pubkey async lock;
//!    - **re-check** enablement under the lock (Safe→Detected TOCTOU);
//!    - `spawn_blocking` reserve → sign (with timeout) → reconcile;
//!    - record the standard RVC slashable metric families via
//!      [`crate::core::StandardSlashableHooks`].
//!
//! The gate's timeout policy is always discard-on-timeout, which is sound for the
//! **in-process** BLS backends production `rvc-signer` wires today. Dropping the
//! timed-out client future does **not** prove “no signature” for an arbitrary
//! remote-capable `dyn Signer` — do not place remote backends behind
//! `DiscardStagedRow`. Remote fail-closed retain is RF4-06
//! (`SignerService` + `RetainStagedRow` / backend-kind mapping).
//!
//! # Non-slashable signing flow
//!
//! For each non-slashable operation (`sign_sync_committee_message`,
//! `sign_aggregate_and_proof`, `sign_payload_attestation`,
//! `sign_proposer_preferences`, `sign_contribution_and_proof`,
//! `sign_selection_proof`, `sign_randao_reveal`, `sign_voluntary_exit`,
//! `sign_builder_registration`):
//!
//! 1. Check `gate_decision` — if false, return
//!    `Err(SigningGateError::BlockedByDoppelganger)` immediately.
//! 2. Delegate to [`crate::sign_nonslashable_core`] (same duration as slashable).
//!    No slashing-DB staging or committing occurs — these operations are not
//!    slashable by the Ethereum consensus spec.
//!
//! Because non-slashable signs carry no `!Send` staging guard, they are plain
//! `async` with a direct `.await` on the signer — no `spawn_blocking` needed.
//!
//! **SS-2 / SS-3 (aggregate-and-proof):** `sign_aggregate_and_proof` is
//! deliberately non-slashable. The inner attestation is slashable and must
//! already have been committed via `sign_attestation`; re-staging the aggregate
//! would double-stage and mis-attribute epochs/roots. See the method docs.
//!
//! # Gate decision and fail-closed default
//!
//! The single `gate_decision` helper centralises the doppelganger check for
//! all paths (slashable and non-slashable).  It calls `is_signing_enabled` and
//! returns the result.  For unknown pubkeys the `SigningEnablement`
//! implementation (e.g. `ForwardWindowMachine`) returns `false`, matching the
//! fail-closed default `<bool as FailClosedDefault>::default_when_unknown()` = `false`.
//!
//! # Cancellation safety and the true double-sign authoritative lock
//!
//! The per-pubkey `OwnedMutexGuard` (tokio async lock) is held on the *async*
//! task until `spawn_blocking(...).await` completes.  **If the caller drops the
//! future mid-flight at that `.await` point, the tokio lock is released while
//! the blocking task continues to run.**
//!
//! This is safe because the AUTHORITATIVE double-sign serializer is the
//! `parking_lot::MutexGuard<Connection>` held inside the `StagedBlock` /
//! `StagedAttestation` guard: it owns a `BEGIN IMMEDIATE` SQLite transaction that
//! keeps all other writers out of the database until `commit()` or `discard()` is
//! called.  The blocked task therefore still has exclusive DB access; it will
//! complete (commit or rollback) atomically regardless of the caller's state.
//! The per-pubkey tokio lock provides an *additional* latency benefit — it avoids
//! queuing multiple blocking tasks for the same pubkey — but the no-double-sign
//! invariant is upheld by SQLite even if that outer lock is lost to cancellation.
//!
//! # Signer timeout (BUG-003)
//!
//! The staging guard holds the SQLite single-writer `parking_lot::MutexGuard`
//! across the stage→sign→commit window.  A wedged signer would hold this write
//! lock indefinitely, causing a signing blackout for ALL validators (they queue
//! behind the same lock).  The gate therefore wraps the sign call in a
//! `tokio::time::timeout`; on expiry with the gate's `DiscardStagedRow` policy
//! the staged guard is discarded (ROLLBACK) and
//! `Err(SigningFailed("signer timed out"))` is returned.  The default is 4 seconds
//! (well under a 12-second Ethereum slot).  Configure with `with_sign_timeout`.

use std::sync::Arc;
use std::time::Duration;

use crypto::{CompositeSigner, PublicKey, Signer};
use doppelganger::SigningEnablement;
use eth_types::Root;
use observability::logging::TruncatedPubkey;
use slashing::SlashingDb;
use tracing::{error, warn};

use crate::core::{
    sign_nonslashable_core, sign_slashable, NonSlashableFailure, SignSlashableRequest,
    SlashableKind, StandardSlashableHooks, TimeoutPolicy, TimeoutPolicySource,
    DEFAULT_SIGN_TIMEOUT,
};
use crate::error::SigningGateError;
use crate::fail_closed::FailClosedDefault;
use crate::locks::ValidatorLockMap;

/// Audit CN used in `PubkeyScopedDb` when no caller-supplied CN is available.
///
/// Slashable handlers pass the real mTLS client CN via the `client_cn` parameter
/// of `sign_block` / `sign_attestation`; this constant is the fallback for any
/// call site that does not have an mTLS context (e.g. crate-internal callers and
/// integration tests).
pub const AUDIT_CN_DEFAULT: &str = "signing-gate";

/// Central signing gate with slashing protection and doppelganger detection.
///
/// # Signature contract
///
/// `sign_block` / `sign_attestation` receive a **pre-computed** `signing_root`
/// and `gvr` from the caller (the v2 handler computes domain + signing root
/// before calling the gate).  The gate stages `pubkey / slot|epochs /
/// signing_root_hex` in the slashing DB, then signs `signing_root` via the
/// BLS backend.
///
/// Non-slashable methods receive a **pre-computed** `signing_root`; they
/// gate-check the pubkey and call the BLS backend directly — no slashing DB.
pub struct SigningGate {
    slashing_db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
    /// BLS signing backend.  Stored as `Arc<dyn Signer>` so tests can inject
    /// a slow/failing backend without changing production APIs.
    signer: Arc<dyn Signer>,
    locks: Arc<ValidatorLockMap>,
    /// Maximum wall-clock duration allowed for a single BLS sign call.
    ///
    /// Expiry is handled by the slashable core's [`TimeoutPolicy`] (gate uses
    /// discard-on-timeout → ROLLBACK) and returns
    /// `Err(SigningFailed("signer timed out"))`.  Defaults to 4 seconds.
    sign_timeout: Duration,
}

impl SigningGate {
    /// Construct a new `SigningGate` with the default 4-second sign timeout.
    pub fn new(
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
        signer: Arc<CompositeSigner>,
        locks: Arc<ValidatorLockMap>,
    ) -> Self {
        Self {
            slashing_db,
            enablement,
            signer: signer as Arc<dyn Signer>,
            locks,
            sign_timeout: DEFAULT_SIGN_TIMEOUT,
        }
    }

    /// Override the per-sign timeout (builder style).
    ///
    /// Issue 2.10 wiring uses this to pass the operator-configured timeout.
    pub fn with_sign_timeout(mut self, timeout: Duration) -> Self {
        self.sign_timeout = timeout;
        self
    }

    /// Constructor accepting any `Signer` implementation.
    ///
    /// Intended primarily for integration tests that need to inject slow or
    /// failing backends (e.g. to exercise the sign timeout).  Production code
    /// should use `new()` which constrains the signer to `CompositeSigner`.
    pub fn new_with_raw_signer(
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
        signer: Arc<dyn Signer>,
        locks: Arc<ValidatorLockMap>,
        sign_timeout: Duration,
    ) -> Self {
        Self { slashing_db, enablement, signer, locks, sign_timeout }
    }

    /// Evaluate the doppelganger gate for `pubkey`.
    ///
    /// Returns `true` when signing is permitted, `false` when it is denied.
    ///
    /// # Fail-closed default (PRD §6.3 — unknown → denied)
    ///
    /// For any pubkey that the `SigningEnablement` implementation does not
    /// recognise (e.g. an unregistered validator in `ForwardWindowMachine`),
    /// `is_signing_enabled` returns `false`.  This matches the explicit
    /// fail-closed default `<bool as FailClosedDefault>::default_when_unknown()` = `false`.
    ///
    /// The `debug_assert_eq!` below makes this codification executable: in debug
    /// and test builds it fires if the `FailClosedDefault` contract is ever
    /// changed to a non-false value without updating the gate logic.
    ///
    /// This helper is the single gate-decision point for BOTH slashable and
    /// non-slashable signing paths, ensuring the fail-closed semantics are
    /// applied uniformly.
    fn gate_decision(&self, pubkey: &PublicKey) -> bool {
        let enabled = self.enablement.is_signing_enabled(pubkey);
        // Codify PRD §6.3: when the enablement returns false (unknown or blocked),
        // the gate decision must equal the fail-closed default.  This assert fires
        // in debug/test builds if `FailClosedDefault::default_when_unknown()` is
        // ever changed to a non-false value without a corresponding gate update.
        debug_assert!(
            !<bool as FailClosedDefault>::default_when_unknown(),
            "FailClosedDefault::default_when_unknown() must remain false (PRD §6.3)"
        );
        enabled
    }

    /// Sign a beacon block proposal.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `slot`: The slot being proposed.
    /// - `signing_root`: The pre-computed signing root (caller applies domain).
    /// - `gvr`: Genesis validators root — passed to `PubkeyScopedDb` for the
    ///   M-6 GVR pinning check.
    /// - `client_cn`: mTLS client CN for the audit-log origin field.  Pass the CN
    ///   extracted by the gRPC handler, or `AUDIT_CN_DEFAULT` when no mTLS context
    ///   is available.
    ///
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// 1. Outer `gate_decision` — fails closed on false (unknown pubkey → denied).
    /// 2. [`sign_slashable`] with [`TimeoutPolicy::DiscardStagedRow`]: lock →
    ///    re-check enablement under lock → reserve → sign (timeout) → reconcile.
    ///    On reserve error → `SlashingBlocked`. On reserve-time persist failure →
    ///    `CommitFailed` (nothing written; same-root retry safe). On timeout /
    ///    unambiguous no-signature with Discard → `reconcile_unsigned` (a failed
    ///    delete retains). See [`SigningGateError::SigningFailed`].
    ///    Records standard RVC slashable metrics.
    pub async fn sign_block(
        &self,
        pubkey: &PublicKey,
        slot: u64,
        signing_root: Root,
        gvr: Root,
        client_cn: &str,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        // Cheap outer enablement check (no lock). Core re-checks under the lock.
        if !self.gate_decision(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                slot,
                "SigningGate: sign_block blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Explicit policy: gate backends are in-process — discard on timeout.
        sign_slashable(SignSlashableRequest {
            locks: self.locks.as_ref(),
            pubkey,
            enablement: self.enablement.as_ref(),
            signer: Arc::clone(&self.signer),
            signing_root,
            sign_timeout: self.sign_timeout,
            policy: TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow),
            hooks: Arc::new(StandardSlashableHooks::block()),
            op_name: "sign_block",
            slashing_db: Arc::clone(&self.slashing_db),
            client_cn: client_cn.to_string(),
            gvr,
            kind: SlashableKind::Block { slot },
        })
        .await
    }

    /// Sign an attestation.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `source_epoch`: The attestation source epoch (for slashing check).
    /// - `target_epoch`: The attestation target epoch (for slashing check).
    /// - `signing_root`: The pre-computed signing root (caller applies domain).
    /// - `gvr`: Genesis validators root — passed to `PubkeyScopedDb` for the
    ///   M-6 GVR pinning check.
    /// - `client_cn`: mTLS client CN for the audit-log origin field.  Pass the CN
    ///   extracted by the gRPC handler, or `AUDIT_CN_DEFAULT` when no mTLS context
    ///   is available.
    ///
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// Identical flow to `sign_block`: outer `gate_decision` →
    /// [`sign_slashable`] with [`TimeoutPolicy::DiscardStagedRow`].
    /// On reserve error → `SlashingBlocked` (epoch consumed).
    /// On reserve-time persist failure → `CommitFailed` (nothing written;
    /// same-root retry safe). On timeout or ambiguous sign errors with Discard →
    /// `reconcile_unsigned` (a failed delete retains). See
    /// [`SigningGateError::SigningFailed`]. Discard applies to the full
    /// [`crate::TimeoutPolicy`] scope on the gate path (in-process backends).
    pub async fn sign_attestation(
        &self,
        pubkey: &PublicKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Root,
        gvr: Root,
        client_cn: &str,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        // Cheap outer enablement check (no lock). Core re-checks under the lock.
        if !self.gate_decision(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                source_epoch,
                target_epoch,
                "SigningGate: sign_attestation blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Explicit policy: gate backends are in-process — discard on timeout.
        sign_slashable(SignSlashableRequest {
            locks: self.locks.as_ref(),
            pubkey,
            enablement: self.enablement.as_ref(),
            signer: Arc::clone(&self.signer),
            signing_root,
            sign_timeout: self.sign_timeout,
            policy: TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow),
            hooks: Arc::new(StandardSlashableHooks::attestation()),
            op_name: "sign_attestation",
            slashing_db: Arc::clone(&self.slashing_db),
            client_cn: client_cn.to_string(),
            gvr,
            kind: SlashableKind::Attestation { source_epoch, target_epoch },
        })
        .await
    }

    // ── Non-slashable signing methods ─────────────────────────────────────────
    //
    // Non-slashable methods: `gate_decision` (bool, fail-closed) then
    // [`sign_nonslashable_core`]. No slashing DB, no spawn_blocking.
    //
    // Error mapping is uniform: timeout/generic → SigningFailed,
    // KeyNotFound → KeyNotFound (explicit, not folded into Display).

    /// Facade wrapper: `gate_decision` then [`sign_nonslashable_core`].
    ///
    /// Maps the core's neutral [`NonSlashableFailure`] onto [`SigningGateError`].
    /// The no-lock invariant lives on the core helper.
    async fn sign_nonslashable(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
        op_name: &str,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        // Same gate_decision point as slashable paths (bool, fail-closed).
        if !self.gate_decision(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                op = op_name,
                "SigningGate: non-slashable sign blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        match sign_nonslashable_core(
            self.enablement.as_ref(),
            self.signer.as_ref(),
            pubkey,
            signing_root,
            self.sign_timeout,
        )
        .await
        {
            Ok(sig) => Ok(sig.to_bytes().to_vec()),
            Err(NonSlashableFailure::Blocked) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    "SigningGate: non-slashable sign blocked by doppelganger gate"
                );
                Err(SigningGateError::BlockedByDoppelganger)
            }
            Err(NonSlashableFailure::TimedOut { after }) => {
                error!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    timeout_secs = after.as_secs_f64(),
                    "SigningGate: non-slashable signer timed out"
                );
                Err(SigningGateError::SigningFailed("signer timed out".to_string()))
            }
            Err(NonSlashableFailure::KeyNotFound) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    "SigningGate: non-slashable key not found"
                );
                Err(SigningGateError::KeyNotFound)
            }
            Err(NonSlashableFailure::Backend(e)) => {
                error!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    error = %e,
                    "SigningGate: non-slashable signer error"
                );
                Err(SigningGateError::SigningFailed(e.to_string()))
            }
        }
    }

    /// Sign a sync committee message.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_SYNC_COMMITTEE` domain).
    pub async fn sign_sync_committee_message(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_sync_committee_message").await
    }

    /// Sign an aggregate-and-proof.
    ///
    /// # Chain-of-custody invariant (SS-2 / SS-3)
    ///
    /// An `AggregateAndProof` is **NOT** itself slashable; its inner
    /// `Attestation` is, and the caller MUST have already signed that inner
    /// attestation via `sign_attestation` (which staged the slashing watermark).
    ///
    /// This method therefore does **NOT** touch the slashing DB.  Running
    /// attestation-slashing staging here would be wrong on two counts:
    ///   a) it would double-stage the attestation rows (the inner attestation
    ///      was already committed by `sign_attestation`), breaking the
    ///      EIP-3076 replay-detection logic; and
    ///   b) it would re-interpret the outer `AggregateAndProof` as an
    ///      independent attestation, mis-attributing epochs/roots.
    ///
    /// The SS-2/SS-3 core fix — removing the erroneous attestation-staging from
    /// `bin/rvc-signer/src/service.rs` — landed in Issue 2.10a by routing every
    /// aggregate handler through this method.  Phase 4 Issue 4.9 covers the
    /// end-to-end aggregator flow + orchestrator side.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_AGGREGATE_AND_PROOF` domain).
    pub async fn sign_aggregate_and_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_aggregate_and_proof").await
    }

    /// Sign a payload attestation (PTC).
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_PTC_ATTESTER` domain over the `PayloadAttestationData` HTR).
    pub async fn sign_payload_attestation(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_payload_attestation").await
    }

    /// Sign proposer preferences.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_PROPOSER_PREFERENCES` over the `ProposerPreferences` HTR).
    pub async fn sign_proposer_preferences(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_proposer_preferences").await
    }

    /// Sign a contribution-and-proof.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_CONTRIBUTION_AND_PROOF` domain).
    pub async fn sign_contribution_and_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_contribution_and_proof").await
    }

    /// Sign a sync committee selection proof.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` domain).
    pub async fn sign_selection_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_selection_proof").await
    }

    /// Sign a RANDAO reveal.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_RANDAO` domain over the epoch SSZ-encoded as `Epoch`).
    pub async fn sign_randao_reveal(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_randao_reveal").await
    }

    /// Sign a voluntary exit.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_VOLUNTARY_EXIT` domain, capped at Capella per EIP-7044).
    pub async fn sign_voluntary_exit(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_voluntary_exit").await
    }

    /// Sign a builder registration.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_APPLICATION_BUILDER` domain with zeroed genesis root).
    pub async fn sign_builder_registration(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_builder_registration").await
    }
}
