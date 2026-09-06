use async_trait::async_trait;

use crypto::{PublicKey, Signature};
use eth_types::{
    AggregateAndProof, AttestationData, ContributionAndProof, ElectraAggregateAndProof, Epoch,
    ForkSchedule, PayloadAttestationData, Root, Slot, ValidatorRegistrationV1, VoluntaryExit,
};

use crate::SignerError;

/// Trait for signing validator duties with slashing protection.
///
/// Implementations must ensure that slashing-protected operations
/// (attestation signing, block signing) perform the appropriate
/// checks before producing a signature.
///
/// Returns [`crypto::Signature`] (not raw bytes). Callers convert with
/// [`Signature::to_bytes`] only at wire boundaries (beacon HTTP/SSZ,
/// gRPC/HTTP responses, JSON hex encoding).
///
/// # `Send` + `Sync` decision (RF4-12)
///
/// Uses `#[async_trait]` (**Send** futures) and requires `Send + Sync` on the
/// trait object. After RF4-06 the slashable path keeps `!Send` staged-row
/// guards inside `spawn_blocking`, so the async sign methods never hold
/// `!Send` state across `.await`. Sign methods live only on this trait (no
/// parallel inherent methods on [`crate::SignerService`]); `Send` futures are
/// required so callers can `tokio::spawn` duty work, and `Send + Sync` is
/// required so `Arc<dyn ValidatorSigner>` is usable from Send async contexts.
/// Consumer mocks must use `#[async_trait]` (not `?Send`) and be `Send + Sync`.
#[async_trait]
pub trait ValidatorSigner: Send + Sync {
    /// Sign an attestation after checking slashing protection.
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a block after checking slashing protection.
    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a RANDAO reveal for the given epoch.
    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a sync committee message for the given beacon block root and slot.
    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a slot with DOMAIN_SELECTION_PROOF to produce a selection proof.
    async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign an ElectraAggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    async fn sign_electra_aggregate_and_proof(
        &self,
        aggregate_and_proof: &ElectraAggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a voluntary exit with DOMAIN_VOLUNTARY_EXIT.
    async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a builder registration with DOMAIN_APPLICATION_BUILDER.
    ///
    /// No slashing check is needed — builder registrations are not slashable.
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError>;

    /// Sign a sync committee selection proof for aggregator selection.
    async fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a ContributionAndProof with DOMAIN_CONTRIBUTION_AND_PROOF.
    async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign payload attestation data (`DOMAIN_PTC_ATTESTER`).
    ///
    /// Non-slashable: must not stage or commit a slashing-DB row.
    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;
}
