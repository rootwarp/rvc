/// Controls whether a validator is permitted to sign.
///
/// Implementations perform an in-memory lookup and return `false` for any
/// pubkey that is not explicitly enabled.  The fail-closed contract means that
/// an unknown pubkey **always** returns `false` — signing is never allowed by
/// default.
///
/// # Location note
///
/// This trait was relocated from `rvc-signer` to `rvc-doppelganger` (Issue 2.6)
/// so that `ForwardWindowMachine` can implement it without creating a
/// `doppelganger → signer` dependency cycle.  `rvc-signer` re-exports it as
/// `pub use doppelganger::SigningEnablement`.
pub trait SigningEnablement: Send + Sync {
    /// Returns whether signing is currently enabled for this validator.
    ///
    /// Fail-closed default: an unknown pubkey returns `false`.
    ///
    /// A `true` result unlocks every duty unless [`voluntary_exit_only`]
    /// narrows it. Callers must use [`signing_allowed`], not this method alone.
    ///
    /// [`voluntary_exit_only`]: SigningEnablement::voluntary_exit_only
    #[must_use = "is_signing_enabled gates signing; the returned bool must be checked before proceeding"]
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool;

    /// When `true`, [`is_signing_enabled`] unlocks only [`SigningDuty::VoluntaryExit`].
    ///
    /// There is no default. A wrapper that only implements [`is_signing_enabled`]
    /// does not compile, so it cannot silently open every other duty. `false`
    /// means every duty that [`is_signing_enabled`] already allows. A wrapper
    /// forwards the inner value.
    ///
    /// [`is_signing_enabled`]: SigningEnablement::is_signing_enabled
    #[must_use]
    fn voluntary_exit_only(&self) -> bool;

    /// `true` only when doppelganger detection has closed signing for `pubkey`.
    ///
    /// There is no default. A wrapper that omits this method does not compile,
    /// so it cannot silently skip the post-reserve check. Wrappers forward the
    /// inner value. Delete quiesce is not detection: a wrapper that closes
    /// signing for another reason still returns the inner value, which is
    /// `false` unless detection itself closed signing.
    ///
    /// The slashable path calls this after the slashing reservation and before
    /// BLS. That call is the admission boundary for a sign that has not yet
    /// contacted the backend. It is not atomic with the BLS call. Detection can
    /// land after this returns `false`, and a BLS call that has already started,
    /// including a request already sent to a remote signer, still finishes
    /// inside the sign timeout.
    #[must_use]
    fn blocked_by_doppelganger(&self, pubkey: &crypto::PublicKey) -> bool;
}

/// Duty presented to [`signing_allowed`].
///
/// One variant per `ValidatorSigner` method and per `SigningGate` method that
/// reaches the enablement check. [`signing_allowed`] matches every variant.
/// Only [`Self::VoluntaryExit`] unlocks an enablement that returns
/// [`SigningEnablement::voluntary_exit_only`]. A new duty is a compile error
/// in that match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningDuty {
    Attestation,
    Block,
    RandaoReveal,
    SyncCommitteeMessage,
    SelectionProof,
    AggregateAndProof,
    ElectraAggregateAndProof,
    AggregateAndProofRoot,
    SyncCommitteeSelectionProof,
    ContributionAndProof,
    PayloadAttestation,
    ProposerPreferences,
    BuilderRegistration,
    BuilderRequestAuth,
    ExecutionPayloadEnvelope,
    VoluntaryExit,
}

/// `true` except [`SigningDuty::VoluntaryExit`].
///
/// The signed exit is the epoch and the validator index, so that duty does not
/// require a beacon admission scope. The keymanager may still read the index
/// from a beacon node. That read is not an admission fence.
#[must_use]
pub fn duty_requires_beacon_admission(duty: SigningDuty) -> bool {
    match duty {
        SigningDuty::VoluntaryExit => false,
        SigningDuty::Attestation
        | SigningDuty::Block
        | SigningDuty::RandaoReveal
        | SigningDuty::SyncCommitteeMessage
        | SigningDuty::SelectionProof
        | SigningDuty::AggregateAndProof
        | SigningDuty::ElectraAggregateAndProof
        | SigningDuty::AggregateAndProofRoot
        | SigningDuty::SyncCommitteeSelectionProof
        | SigningDuty::ContributionAndProof
        | SigningDuty::PayloadAttestation
        | SigningDuty::ProposerPreferences
        | SigningDuty::BuilderRegistration
        | SigningDuty::BuilderRequestAuth
        | SigningDuty::ExecutionPayloadEnvelope => true,
    }
}

/// Whether `enablement` permits `pubkey` for `duty`.
///
/// The match is exhaustive and has no wildcard. Only a voluntary exit stays
/// open when [`SigningEnablement::voluntary_exit_only`] is true.
#[must_use]
pub fn signing_allowed(
    enablement: &dyn SigningEnablement,
    pubkey: &crypto::PublicKey,
    duty: SigningDuty,
) -> bool {
    if !enablement.is_signing_enabled(pubkey) {
        return false;
    }
    match duty {
        SigningDuty::VoluntaryExit => true,
        SigningDuty::Attestation
        | SigningDuty::Block
        | SigningDuty::RandaoReveal
        | SigningDuty::SyncCommitteeMessage
        | SigningDuty::SelectionProof
        | SigningDuty::AggregateAndProof
        | SigningDuty::ElectraAggregateAndProof
        | SigningDuty::AggregateAndProofRoot
        | SigningDuty::SyncCommitteeSelectionProof
        | SigningDuty::ContributionAndProof
        | SigningDuty::PayloadAttestation
        | SigningDuty::ProposerPreferences
        | SigningDuty::BuilderRegistration
        | SigningDuty::BuilderRequestAuth
        | SigningDuty::ExecutionPayloadEnvelope => !enablement.voluntary_exit_only(),
    }
}

/// Production opt-out of doppelganger protection (`--no-doppelganger-detection`).
///
/// Enables signing for every pubkey. This forgoes the forward window.
/// With the default [`crate::DEFAULT_MONITORING_EPOCHS`] of 2, a key stays
/// closed until 3 closed not-live epochs are counted. On mainnet (12 s slots,
/// 32 slots per epoch) that is 19.2 minutes when every one of those epochs is
/// closed on time. A gap delays `Safe`; two epochs are not enough. Prefer
/// leaving doppelganger on (the default).
///
/// Distinct from the test-only `AlwaysEnabled` helper in `rvc-signer`: this type
/// is the **documented operator opt-out** and is safe to wire on the production
/// path when the operator has explicitly disabled doppelganger detection.
pub struct DoppelgangerDisabledByOperator;

impl SigningEnablement for DoppelgangerDisabledByOperator {
    fn is_signing_enabled(&self, _pubkey: &crypto::PublicKey) -> bool {
        true
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }

    fn blocked_by_doppelganger(&self, _pubkey: &crypto::PublicKey) -> bool {
        false
    }
}
