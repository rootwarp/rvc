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
/// Enables signing for every pubkey. This deliberately forgoes the forward-window
/// safety cost of roughly **2–3 epochs** of monitoring (~12.8–19.2 minutes on
/// mainnet with 12 s slots). Prefer leaving doppelganger on (the default).
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
}
