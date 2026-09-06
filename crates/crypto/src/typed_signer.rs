//! Typed signing trait and [`SignContext`].
//!
//! [`TypedSigner`] exposes one method per Ethereum consensus duty type.
//! [`LocalSigner`] implements it by computing the signing root and delegating
//! to [`Signer::sign`].

use async_trait::async_trait;

use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlock, BlindedBeaconBlock, ContributionAndProof,
    Epoch, ForkInfo, PayloadAttestationData, Root, Slot, ValidatorRegistrationV1, VoluntaryExit,
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
    DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};

use crate::bls::{PublicKey, Signature};
use crate::signer_trait::{LocalSigner, Signer, SigningError};
use crate::signing_root::signing_root_with_fork_version;
use eth_types::{ForkName, ForkSchedule, SyncAggregatorSelectionData};

// ============================================================
// SignContext
// ============================================================

/// Signing context passed to every [`TypedSigner`] method.
///
/// Carries the signer's public key, the fork versions used for domain
/// computation, and the resolved [`ForkName`] used for SSZ fork-id tagging
/// (gRPC remote path). Callers that already know the active fork from a
/// [`ForkSchedule`] should set [`Self::fork_name`] directly; use
/// [`Self::resolve`] when only version bytes are available.
pub struct SignContext {
    pub pubkey: PublicKey,
    pub fork_info: ForkInfo,
    /// Resolved consensus fork for SSZ / wire `fork_id` (never inferred from
    /// mainnet-only version bytes).
    pub fork_name: ForkName,
}

impl SignContext {
    /// Build a context with an already-resolved fork name.
    pub fn new(pubkey: PublicKey, fork_info: ForkInfo, fork_name: ForkName) -> Self {
        Self { pubkey, fork_info, fork_name }
    }

    /// Resolve [`Self::fork_name`] by matching `fork_info.current_version`
    /// against `schedule.entries()`.
    ///
    /// Returns a typed error (and emits a `warn!`) when the version is not in
    /// the schedule — never silently defaults to Deneb.
    pub fn resolve(
        pubkey: PublicKey,
        fork_info: ForkInfo,
        schedule: &ForkSchedule,
    ) -> Result<Self, SigningError> {
        match schedule
            .entries()
            .into_iter()
            .find(|(_, _, version)| *version == fork_info.current_version)
            .map(|(name, _, _)| name)
        {
            Some(fork_name) => Ok(Self { pubkey, fork_info, fork_name }),
            None => {
                tracing::warn!(
                    current_version = %hex::encode(fork_info.current_version),
                    "unresolvable fork version for SignContext; refusing silent Deneb default"
                );
                Err(SigningError::RemoteSignerError(format!(
                    "unresolvable fork version 0x{}",
                    hex::encode(fork_info.current_version)
                )))
            }
        }
    }
}

// ============================================================
// TypedSigner
// ============================================================

/// High-level signing trait: one method per consensus duty type.
///
/// Implementations compute the signing root from the consensus object and
/// the fork context, then call the underlying key.
#[async_trait]
pub trait TypedSigner: Send + Sync {
    /// Sign a full beacon block (DOMAIN_BEACON_PROPOSER).
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a blinded beacon block (DOMAIN_BEACON_PROPOSER).
    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign attestation data (DOMAIN_BEACON_ATTESTER).
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign an aggregate-and-proof (DOMAIN_AGGREGATE_AND_PROOF).
    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a sync committee message (DOMAIN_SYNC_COMMITTEE).
    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign sync aggregator selection data (DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF).
    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a contribution-and-proof (DOMAIN_CONTRIBUTION_AND_PROOF).
    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a builder registration (DOMAIN_APPLICATION_BUILDER, zero gvr).
    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a RANDAO reveal (DOMAIN_RANDAO).
    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign a voluntary exit (DOMAIN_VOLUNTARY_EXIT).
    ///
    /// # EIP-7044
    ///
    /// This trait method uses `ctx.fork_info.current_version` as-is (no
    /// schedule). Callers that hold a [`ForkSchedule`] should prefer
    /// [`crate::sign_voluntary_exit`] or [`crate::signing_root_for`] with
    /// [`crate::DutyRef::VoluntaryExit`], which apply the Capella cap
    /// automatically. When building a [`SignContext`] for this path, set
    /// `current_version` via [`crate::capella_capped_fork_version`].
    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError>;

    /// Sign payload attestation data (`DOMAIN_PTC_ATTESTER`).
    ///
    /// Default: the duty is dropped and no signature is produced. Signers that
    /// support this duty must override.
    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let _ = (data, ctx);
        Err(SigningError::UnsupportedDuty { duty: "payload_attestation" })
    }
}

// ============================================================
// TypedSigner impl for LocalSigner
// ============================================================

#[async_trait]
impl TypedSigner for LocalSigner {
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            block,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            block,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            data,
            DOMAIN_BEACON_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            agg,
            DOMAIN_AGGREGATE_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_sync_committee_message(
        &self,
        _slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            &beacon_block_root,
            DOMAIN_SYNC_COMMITTEE,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = signing_root_with_fork_version(
            &selection_data,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            c,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        // Per MEV-Boost spec: DOMAIN_APPLICATION_BUILDER + GENESIS_FORK_VERSION + zero gvr
        let signing_root = signing_root_with_fork_version(
            reg,
            DOMAIN_APPLICATION_BUILDER,
            genesis_fork_version,
            [0u8; 32],
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            &epoch,
            DOMAIN_RANDAO,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        // Pre-resolved fork version path: Capella cap is the caller's duty
        // (or use free `sign_voluntary_exit` / `signing_root_for` with schedule).
        let signing_root = signing_root_with_fork_version(
            exit,
            DOMAIN_VOLUNTARY_EXIT,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }

    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let signing_root = signing_root_with_fork_version(
            data,
            DOMAIN_PTC_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let pk = ctx.pubkey.to_bytes();
        Signer::sign(self, &signing_root, &pk).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::SecretKey;
    use crate::capella_capped_fork_version;
    use crate::key_manager::KeyManager;
    use crate::signing::{compute_domain, compute_signing_root};

    fn make_local_signer(sk: SecretKey) -> LocalSigner {
        let mut km = KeyManager::new();
        km.insert(sk);
        LocalSigner::new(km)
    }

    fn test_fork_info() -> ForkInfo {
        ForkInfo {
            previous_version: [0x00, 0x00, 0x00, 0x00],
            current_version: [0x04, 0x00, 0x00, 0x00], // Deneb
            genesis_validators_root: [0xaa; 32],
        }
    }

    fn test_ctx(sk: &SecretKey) -> SignContext {
        SignContext {
            pubkey: sk.public_key(),
            fork_info: test_fork_info(),
            fork_name: ForkName::Deneb,
        }
    }

    // ---- TypedSigner::sign_block ----

    #[tokio::test]
    async fn test_typed_signer_sign_block_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let block = BeaconBlock {
            slot: 100,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_block(&signer, &block, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&block, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_blinded_block ----

    #[tokio::test]
    async fn test_typed_signer_sign_blinded_block_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let block = BlindedBeaconBlock {
            slot: 200,
            proposer_index: 2,
            parent_root: [0x33; 32],
            state_root: [0x44; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_blinded_block(&signer, &block, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&block, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_attestation ----

    #[tokio::test]
    async fn test_typed_signer_sign_attestation_verifies() {
        use eth_types::Checkpoint;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let data = AttestationData {
            slot: 100,
            index: 1,
            beacon_block_root: [0x55; 32],
            source: Checkpoint { epoch: 9, root: [0x66; 32] },
            target: Checkpoint { epoch: 10, root: [0x77; 32] },
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&data, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_aggregate_and_proof ----

    #[tokio::test]
    async fn test_typed_signer_sign_aggregate_verifies() {
        use eth_types::{Attestation, Checkpoint};
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let agg = AggregateAndProof {
            aggregator_index: 42,
            aggregate: Attestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot: 100,
                    index: 1,
                    beacon_block_root: [0x11; 32],
                    source: Checkpoint { epoch: 9, root: [0x22; 32] },
                    target: Checkpoint { epoch: 10, root: [0x33; 32] },
                },
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_aggregate_and_proof(&signer, &agg, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_AGGREGATE_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&agg, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_sync_committee_message ----

    #[tokio::test]
    async fn test_typed_signer_sign_sync_committee_message_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let slot = 500u64;
        let beacon_block_root = [0x88; 32];
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_sync_committee_message(&signer, slot, beacon_block_root, &ctx)
            .await
            .unwrap();

        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&beacon_block_root, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_sync_aggregator_selection ----

    #[tokio::test]
    async fn test_typed_signer_sign_sync_aggregator_selection_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let slot = 600u64;
        let subcommittee_index = 3u64;
        let signer = make_local_signer(sk);

        let sig =
            TypedSigner::sign_sync_aggregator_selection(&signer, slot, subcommittee_index, &ctx)
                .await
                .unwrap();

        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_contribution_and_proof ----

    #[tokio::test]
    async fn test_typed_signer_sign_contribution_and_proof_verifies() {
        use eth_types::SyncCommitteeContribution;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let c = ContributionAndProof {
            aggregator_index: 7,
            contribution: SyncCommitteeContribution {
                slot: 400,
                beacon_block_root: [0x99; 32],
                subcommittee_index: 1,
                aggregation_bits: vec![0x03; 16],
                signature: vec![0xcc; 96],
            },
            selection_proof: vec![0xdd; 96],
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_contribution_and_proof(&signer, &c, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_CONTRIBUTION_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&c, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_builder_registration ----

    #[tokio::test]
    async fn test_typed_signer_sign_builder_registration_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let genesis_fork_version = [0x00, 0x00, 0x00, 0x00];
        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: pk.to_bytes(),
        };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_builder_registration(&signer, &reg, genesis_fork_version, &ctx)
            .await
            .unwrap();

        let zero_gvr = [0u8; 32];
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
        let signing_root = compute_signing_root(&reg, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_randao_reveal ----

    #[tokio::test]
    async fn test_typed_signer_sign_randao_reveal_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = test_ctx(&sk);
        let epoch = 42u64;
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_randao_reveal(&signer, epoch, &ctx).await.unwrap();

        let domain = compute_domain(
            DOMAIN_RANDAO,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_voluntary_exit ----

    #[tokio::test]
    async fn test_typed_signer_sign_voluntary_exit_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        // Capella fork version (EIP-7044 cap)
        let fork_info = ForkInfo {
            previous_version: [0x02, 0x00, 0x00, 0x00],
            current_version: [0x03, 0x00, 0x00, 0x00], // Capella
            genesis_validators_root: [0xaa; 32],
        };
        let ctx = SignContext { pubkey: sk.public_key(), fork_info, fork_name: ForkName::Capella };
        let exit = VoluntaryExit { epoch: 200, validator_index: 99 };
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_voluntary_exit(&signer, &exit, &ctx).await.unwrap();

        let capella_version = [0x03, 0x00, 0x00, 0x00];
        let genesis_root = [0xaa; 32];
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, capella_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    // ---- TypedSigner::sign_payload_attestation ----

    fn parse_kat_root(hex_str: &str) -> Root {
        hex::decode(hex_str).expect("kat hex").try_into().expect("32-byte kat root")
    }

    fn gloas_ptc_fixture() -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        }
    }

    fn gloas_kat_ctx(sk: &SecretKey) -> SignContext {
        SignContext {
            pubkey: sk.public_key(),
            fork_info: ForkInfo {
                previous_version: [0x06, 0x00, 0x00, 0x01],
                current_version: [0x07, 0x00, 0x00, 0x01],
                genesis_validators_root: [0u8; 32],
            },
            fork_name: ForkName::Gloas,
        }
    }

    /// L3: signature verifies over `KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT`
    /// (4.2 fixture: block root `[0x11; 32]`, slot 1, payload present, no blob
    /// data, fork `0x07000001`, GVR zeros).
    #[tokio::test]
    async fn test_local_signer_payload_attestation_signature_verifies() {
        use rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT;

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let ctx = gloas_kat_ctx(&sk);
        let data = gloas_ptc_fixture();
        let signer = make_local_signer(sk);

        let sig = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await.unwrap();

        let kat_root = parse_kat_root(KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT);
        assert!(
            sig.verify(&pk, &kat_root).is_ok(),
            "payload attestation signature must verify over the KAT signing root"
        );
    }

    struct CapabilityMissingSigner;

    #[async_trait]
    impl TypedSigner for CapabilityMissingSigner {
        async fn sign_block(
            &self,
            _block: &BeaconBlock,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_blinded_block(
            &self,
            _block: &BlindedBeaconBlock,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_attestation(
            &self,
            _data: &AttestationData,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_aggregate_and_proof(
            &self,
            _agg: &AggregateAndProof,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_sync_committee_message(
            &self,
            _slot: Slot,
            _beacon_block_root: Root,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_sync_aggregator_selection(
            &self,
            _slot: Slot,
            _subcommittee_index: u64,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_contribution_and_proof(
            &self,
            _c: &ContributionAndProof,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_builder_registration(
            &self,
            _reg: &ValidatorRegistrationV1,
            _genesis_fork_version: [u8; 4],
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_randao_reveal(
            &self,
            _epoch: Epoch,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
        async fn sign_voluntary_exit(
            &self,
            _exit: &VoluntaryExit,
            _ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            unreachable!("not under test")
        }
    }

    #[tokio::test]
    async fn test_typed_signer_payload_attestation_unsupported_duty() {
        let sk = SecretKey::generate();
        let ctx = gloas_kat_ctx(&sk);
        let data = gloas_ptc_fixture();
        let signer = CapabilityMissingSigner;

        let result = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await;
        match result {
            Err(SigningError::UnsupportedDuty { duty }) => {
                assert_eq!(duty, "payload_attestation");
            }
            Ok(_) => panic!("unsupported signer must not produce a signature"),
            other => panic!("expected UnsupportedDuty, got: {other:?}"),
        }
    }

    // ---- capella_capped_fork_version ----

    #[test]
    fn test_capella_capped_fork_version_pre_capella_returns_original() {
        let schedule = ForkSchedule {
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
        };
        // Altair epoch — no cap, returns Altair version
        assert_eq!(capella_capped_fork_version(15, &schedule), [1, 0, 0, 0]);
    }

    #[test]
    fn test_capella_capped_fork_version_post_capella_returns_capella() {
        let schedule = ForkSchedule {
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
        };
        // Electra epoch — cap at Capella
        assert_eq!(capella_capped_fork_version(55, &schedule), [3, 0, 0, 0]);
    }

    fn dummy_pubkey() -> PublicKey {
        SecretKey::generate().public_key()
    }

    #[test]
    fn test_resolve_gloas_version_returns_gloas() {
        let schedule = ForkSchedule {
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
            gloas_fork_epoch: 70,
            gloas_fork_version: [0x07, 0, 0, 0],
        };
        let fork_info = ForkInfo {
            previous_version: [6, 0, 0, 0],
            current_version: [0x07, 0, 0, 0],
            genesis_validators_root: [0xaa; 32],
        };
        let ctx = SignContext::resolve(dummy_pubkey(), fork_info, &schedule).unwrap();
        assert_eq!(ctx.fork_name, ForkName::Gloas);
    }

    #[test]
    fn test_resolve_sentinel_collision_first_matches_fulu() {
        // When the BN omits both FULU_* and GLOAS_*, two entries() rows carry
        // [0xFF; 4] and resolve first-matches Fulu — documented, not incidental.
        // Issue 2.10's conditional fail-closed rule confines this to the
        // fully-unscheduled case: a scheduled Gloas requires a real version
        // from both sources.
        let schedule = ForkSchedule {
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
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0xFF; 4],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0xFF; 4],
        };
        let fork_info = ForkInfo {
            previous_version: [0xFF; 4],
            current_version: [0xFF; 4],
            genesis_validators_root: [0xaa; 32],
        };
        let ctx = SignContext::resolve(dummy_pubkey(), fork_info, &schedule).unwrap();
        assert_eq!(ctx.fork_name, ForkName::Fulu);
    }
}
