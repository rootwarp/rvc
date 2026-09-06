//! Narrow traits for the builder registration / prepare-proposer path.
//!
//! `BuilderService` depends only on these surfaces so unit tests can stub the
//! beacon methods and sign methods instead of the full BN / signer traits.

use std::sync::Arc;

use async_trait::async_trait;
use bn_manager::{BeaconError, BeaconNodeClient, ProposerPreparation, SignedValidatorRegistration};
use crypto::{PublicKey, Signature};
use eth_types::{
    ForkSchedule, ProposerPreferences, Root, SignedProposerPreferences, ValidatorRegistrationV1,
};
use signer::{SignerError, ValidatorSigner};

/// Beacon methods used by [`crate::BuilderService`].
#[async_trait]
pub trait BuilderBeaconClient: Send + Sync {
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError>;

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError>;

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError>;
}

/// Production bridge: full BN trait object satisfies the narrow builder surface.
///
/// Targets the narrow trait only (no other impls), so this is coherence-safe.
#[async_trait]
impl BuilderBeaconClient for Arc<dyn BeaconNodeClient> {
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        (**self).register_validators(registrations).await
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        (**self).prepare_beacon_proposer(preparations).await
    }

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        (**self).submit_proposer_preferences(preferences).await
    }
}

/// Signer methods used by [`crate::BuilderService`] for builder registrations
/// and Gloas proposer-preferences broadcasts.
///
/// Returns [`crypto::Signature`]; convert with [`Signature::to_bytes`] at the
/// eth_types / beacon wire boundary only (RF4-12).
///
/// `Send + Sync` so `Arc<dyn RegistrationSigner>` / production bridges work
/// with Send futures (matches [`ValidatorSigner`]).
#[async_trait]
pub trait RegistrationSigner: Send + Sync {
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError>;

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;
}

/// Production bridge: full signer trait object satisfies the registration surface.
#[async_trait]
impl RegistrationSigner for Arc<dyn ValidatorSigner> {
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        (**self).sign_builder_registration(registration, pubkey, fork_version).await
    }

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        (**self)
            .sign_proposer_preferences(prefs, pubkey, fork_schedule, genesis_validators_root)
            .await
    }
}
