use async_trait::async_trait;

use crypto::{PublicKey, Signature};
use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlockHeader, ContributionAndProof,
    ElectraAggregateAndProof, Epoch, ForkSchedule, PayloadAttestationData, ProposerPreferences,
    Root, Slot, ValidatorRegistrationV1, VoluntaryExit,
};
use tree_hash::TreeHash;

use crate::SignerError;

/// Five spec header leaves plus pre-Gloas body bytes for the gRPC legacy RPC.
///
/// Spec field order (`slot`, `proposer_index`, `parent_root`, `state_root`,
/// `body_root`) is hashed with `tree_hash` 0.9. `body_ssz` is **not** a spec
/// leaf: production fills it so a gRPC key can speak `SignBeaconBlock` /
/// `SignBlindedBeaconBlock` pre-Gloas. At Gloas, 4.20c selects `SignBlockHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconBlockHeaderFields {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
    /// Original body SSZ (full or blinded). Empty when the caller only has leaves.
    pub body_ssz: Vec<u8>,
    pub is_blinded: bool,
}

impl BeaconBlockHeaderFields {
    /// Spec `BeaconBlockHeader` (five leaves only).
    #[must_use]
    pub fn spec_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body_root,
        }
    }

    /// `tree_hash` 0.9 of the five spec leaves.
    #[must_use]
    pub fn object_root(&self) -> Root {
        self.spec_header().tree_hash_root().0
    }
}

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

    /// Sign a block from its five header leaves after slashing protection.
    ///
    /// Local and HTTP keys hash the five spec leaves (`tree_hash` 0.9) into the
    /// same root [`Self::sign_block`] would take. gRPC keys use the legacy
    /// `SignBeaconBlock` / `SignBlindedBeaconBlock` RPCs when `body_ssz` is
    /// present and the fork is pre-Gloas; at Gloas they select `SignBlockHeader`.
    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeaderFields,
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

    /// Sign proposer preferences (`DOMAIN_PROPOSER_PREFERENCES`).
    ///
    /// Default: unsupported. Local and HTTP remotes that can sign this duty
    /// must override. Non-slashable: must not stage or commit a slashing-DB row.
    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let _ = (prefs, pubkey, fork_schedule, genesis_validators_root);
        Err(SignerError::UnsupportedDuty { duty: "proposer_preferences" })
    }
}
