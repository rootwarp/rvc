//! Test-only helpers for cross-crate consumers (`block-service`, `builder`, …).
//!
//! Gated by `cfg(any(test, feature = "test-utils"))`. Enable only from
//! `[dev-dependencies]`:
//!
//! ```toml
//! [dev-dependencies]
//! signer = { workspace = true, features = ["test-utils"] }
//! ```

use async_trait::async_trait;
use crypto::{PublicKey, SecretKey, Signature};
use eth_types::{
    AggregateAndProof, AttestationData, ContributionAndProof, ElectraAggregateAndProof, Epoch,
    ForkSchedule, PayloadAttestationData, Root, Slot, ValidatorRegistrationV1, VoluntaryExit,
};

use crate::{BeaconBlockHeaderFields, SignerError, ValidatorSigner};

fn stub_block_sig() -> Signature {
    thread_local! {
        static SIG: Signature = SecretKey::generate().sign(b"block");
    }
    SIG.with(Clone::clone)
}

/// Valid-curve mock BLS signature (fresh key each call).
#[must_use]
pub fn mock_sig(tag: &[u8]) -> Signature {
    SecretKey::generate().sign(tag)
}

/// Minimal [`ValidatorSigner`] that succeeds every method with a mock signature.
///
/// Intended for unit tests that only need a trait object, not call capture.
/// Consumers that need failure injection or argument recording should wrap or
/// extend this type rather than re-stubbing all 12 methods.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubValidatorSigner;

impl StubValidatorSigner {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ValidatorSigner for StubValidatorSigner {
    async fn sign_attestation(
        &self,
        _data: &AttestationData,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"attestation"))
    }

    async fn sign_block(
        &self,
        _block_root: &Root,
        _slot: Slot,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(stub_block_sig())
    }

    async fn sign_block_header(
        &self,
        _header: &BeaconBlockHeaderFields,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(stub_block_sig())
    }

    async fn sign_randao_reveal(
        &self,
        _epoch: Epoch,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"randao"))
    }

    async fn sign_sync_committee_message(
        &self,
        _beacon_block_root: &Root,
        _slot: Slot,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"sync-msg"))
    }

    async fn sign_selection_proof(
        &self,
        _slot: Slot,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"selection"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _aggregate_and_proof: &AggregateAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"aggregate"))
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        _aggregate_and_proof: &ElectraAggregateAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"electra-aggregate"))
    }

    async fn sign_voluntary_exit(
        &self,
        _voluntary_exit: &VoluntaryExit,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"voluntary-exit"))
    }

    async fn sign_builder_registration(
        &self,
        _registration: &ValidatorRegistrationV1,
        _pubkey: &PublicKey,
        _fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"builder-reg"))
    }

    async fn sign_sync_committee_selection_proof(
        &self,
        _slot: Slot,
        _subcommittee_index: u64,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"sync-selection"))
    }

    async fn sign_contribution_and_proof(
        &self,
        _contribution_and_proof: &ContributionAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"contribution"))
    }

    async fn sign_payload_attestation(
        &self,
        _data: &PayloadAttestationData,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        Ok(mock_sig(b"payload-attestation"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Checkpoint, ValidatorRegistrationV1};

    fn fs() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0; 4],
            altair_fork_epoch: u64::MAX,
            altair_fork_version: [0; 4],
            bellatrix_fork_epoch: u64::MAX,
            bellatrix_fork_version: [0; 4],
            capella_fork_epoch: u64::MAX,
            capella_fork_version: [0; 4],
            deneb_fork_epoch: u64::MAX,
            deneb_fork_version: [0; 4],
            electra_fork_epoch: u64::MAX,
            electra_fork_version: [0; 4],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0; 4],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0; 4],
        }
    }

    #[tokio::test]
    async fn stub_validator_signer_succeeds_on_all_methods() {
        let stub = StubValidatorSigner::new();
        let pk = SecretKey::generate().public_key();
        let gvr = [0u8; 32];
        let fork = fs();

        let data = AttestationData {
            slot: 1,
            index: 0,
            beacon_block_root: [1; 32],
            source: Checkpoint { epoch: 0, root: [2; 32] },
            target: Checkpoint { epoch: 1, root: [3; 32] },
        };
        assert!(stub.sign_attestation(&data, &pk, &fork, &gvr).await.is_ok());
        assert!(stub.sign_block(&[4; 32], 1, &pk, &fork, &gvr).await.is_ok());
        let header = BeaconBlockHeaderFields {
            slot: 1920,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
            body_ssz: Vec::new(),
            is_blinded: false,
        };
        // Stub returns a dummy constant (not a BLS signature over the root).
        // Compare the same dummy from both methods using the spec-header HTR.
        let object = header.object_root();
        let sig_header = stub.sign_block_header(&header, &pk, &fork, &gvr).await.unwrap();
        let sig_block = stub.sign_block(&object, header.slot, &pk, &fork, &gvr).await.unwrap();
        assert_eq!(
            sig_header.to_bytes(),
            sig_block.to_bytes(),
            "stub sign_block_header must match sign_block of the header object"
        );
        assert!(stub.sign_randao_reveal(1, &pk, &fork, &gvr).await.is_ok());
        assert!(stub.sign_sync_committee_message(&[5; 32], 1, &pk, &fork, &gvr).await.is_ok());
        assert!(stub.sign_selection_proof(1, &pk, &fork, &gvr).await.is_ok());

        // AggregateAndProof / ElectraAggregateAndProof / ContributionAndProof are large
        // SSZ types; smoke the remaining methods with minimal values where available.
        let exit = VoluntaryExit { epoch: 1, validator_index: 0 };
        assert!(stub.sign_voluntary_exit(&exit, &pk, &fork, &gvr).await.is_ok());

        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0; 20],
            gas_limit: 0,
            timestamp: 0,
            pubkey: pk.to_bytes(),
        };
        assert!(stub.sign_builder_registration(&reg, &pk, [0; 4]).await.is_ok());
        assert!(stub.sign_sync_committee_selection_proof(1, 0, &pk, &fork, &gvr).await.is_ok());

        let ptc = PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        assert!(stub.sign_payload_attestation(&ptc, &pk, &fork, &gvr).await.is_ok());
    }
}
