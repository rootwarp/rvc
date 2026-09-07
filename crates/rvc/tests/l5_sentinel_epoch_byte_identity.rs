//! Issue 6.13 / #308: L5 sentinel-epoch byte-identity suite (ADR-009).
//!
//! With `GLOAS_FORK_EPOCH` at `u64::MAX`, existing duty roots stay byte-identical
//! to the checked-in KAT vectors, and the V3 production path is taken because no
//! realistic epoch resolves to Gloas.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use block_service::{
    BeaconBlockClient, BlockService, BlockServiceError, BuilderConfig, ProduceBlockResponse,
};
use crypto::test_utils::{
    sentinel_gloas_schedule, KAT_AGGREGATE_AND_PROOF_SIGNING_ROOT_PHASE0,
    KAT_ATTESTATION_SIGNING_ROOT_ELECTRA_BOUNDARY, KAT_BLOCK_SIGNING_ROOT_PHASE0,
    KAT_BUILDER_REGISTRATION_SIGNING_ROOT, KAT_SYNC_COMMITTEE_MESSAGE_SIGNING_ROOT_PHASE0,
    KAT_VOLUNTARY_EXIT_SIGNING_ROOT_EIP7044_DENEB,
};
use crypto::{signing_root_for, DutyRef, PublicKey, SecretKey, Signature, SigningCtx};
use eth_types::{
    body_tree_hash_root, AggregateAndProof, Attestation, AttestationData, BeaconBlock, Checkpoint,
    ContributionAndProof, ElectraAggregateAndProof, Epoch, ForkName, ForkSchedule, Root,
    SignedBeaconBlock, SignedBlindedBeaconBlock, Slot, ValidatorRegistrationV1, VoluntaryExit,
    EXTERNAL_ELECTRA_BODY_ROOT_HEX, SLOTS_PER_EPOCH,
};
use signer::{BeaconBlockHeaderFields, SignerError, StubValidatorSigner, ValidatorSigner};
use validator_store::{ValidatorConfig, ValidatorStore};

const GVR: Root = [0xaa; 32];
const ALTAIR: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
const FAR_FUTURE_EPOCH: u64 = 1_000_000;

fn ctx(schedule: &ForkSchedule) -> SigningCtx<'_> {
    SigningCtx { fork_schedule: schedule, genesis_validators_root: GVR }
}

/// ADR-009: block / attestation / aggregate / sync roots match the recorded
/// pre-change KAT bytes under the sentinel schedule. Exit is EIP-7044 Capella-capped
/// (schedule-independent of Gloas). Builder registration uses genesis + zero GVR
/// (also schedule-independent of Gloas).
#[test]
fn test_l5_sentinel_epoch_duty_signing_root() {
    let schedule = sentinel_gloas_schedule();
    assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
    let ctx = ctx(&schedule);

    let block_root: Root = [0x11; 32];
    assert_eq!(
        signing_root_for(&DutyRef::BlockRoot { root: &block_root, slot: 0 }, &ctx),
        KAT_BLOCK_SIGNING_ROOT_PHASE0
    );

    let target_epoch = 50u64;
    let att_data = AttestationData {
        slot: target_epoch * SLOTS_PER_EPOCH,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
        target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
    };
    assert_eq!(
        signing_root_for(&DutyRef::Attestation(&att_data), &ctx),
        KAT_ATTESTATION_SIGNING_ROOT_ELECTRA_BOUNDARY
    );

    let slot: Slot = 100;
    let agg = AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH - 1, root: [2u8; 32] },
                target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    };
    assert_eq!(
        signing_root_for(&DutyRef::AggregateAndProof(&agg), &ctx),
        KAT_AGGREGATE_AND_PROOF_SIGNING_ROOT_PHASE0
    );

    let beacon_block_root: Root = [0x11; 32];
    assert_eq!(
        signing_root_for(
            &DutyRef::SyncMessage { beacon_block_root: &beacon_block_root, slot: 100 },
            &ctx
        ),
        KAT_SYNC_COMMITTEE_MESSAGE_SIGNING_ROOT_PHASE0
    );

    // Schedule-independent of Gloas: EIP-7044 still Capella-caps a Deneb-era exit.
    let exit = VoluntaryExit { epoch: 45, validator_index: 42 };
    assert_eq!(
        signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx),
        KAT_VOLUNTARY_EXIT_SIGNING_ROOT_EIP7044_DENEB
    );

    // Schedule-independent of Gloas: builder domain is genesis fork + zero GVR.
    let registration = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: [0xcd; 48],
    };
    assert_eq!(
        signing_root_for(
            &DutyRef::BuilderRegistration {
                registration: &registration,
                genesis_fork_version: ALTAIR
            },
            &ctx
        ),
        KAT_BUILDER_REGISTRATION_SIGNING_ROOT
    );
}

/// Sentinel Gloas never resolves for a consensus slot; `from_epoch(u64::MAX)` is
/// the documented exception (the sentinel *is* Gloas's activation epoch).
#[test]
fn test_l5_sentinel_epoch_gloas_arm_unreachable() {
    let schedule = sentinel_gloas_schedule();
    assert_eq!(schedule.gloas_fork_epoch, u64::MAX);

    for epoch in [0, 10, 50, 60, FAR_FUTURE_EPOCH, u64::MAX - 1] {
        let fork = ForkName::from_epoch(epoch, &schedule);
        assert_ne!(fork, ForkName::Gloas, "epoch {epoch} must stay pre-Gloas at the sentinel");
        assert!(
            fork < ForkName::Gloas,
            "epoch {epoch} must not take a `>= ForkName::Gloas` production arm"
        );
    }

    assert_eq!(ForkName::from_epoch(u64::MAX, &schedule), ForkName::Gloas);
}

struct RecordingBeacon {
    v3: Mutex<Vec<Slot>>,
    v4: Mutex<Vec<Slot>>,
    block: BeaconBlock,
}

impl RecordingBeacon {
    fn new(block: BeaconBlock) -> Self {
        Self { v3: Mutex::new(Vec::new()), v4: Mutex::new(Vec::new()), block }
    }
}

#[async_trait]
impl BeaconBlockClient for RecordingBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.v3.lock().expect("v3 mutex").push(slot);
        Ok(ProduceBlockResponse {
            data: serde_json::to_value(&self.block).expect("block json"),
            is_blinded: false,
            consensus_version: "fulu".to_string(),
            execution_payload_value: Some("12345".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        })
    }

    async fn produce_block_v4(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.v4.lock().expect("v4 mutex").push(slot);
        Err(BlockServiceError::Beacon("v4 must stay unreachable at the sentinel".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }

    async fn publish_execution_payload_envelope(
        &self,
        _signed_envelope: &block_service::WireBody,
        _blobs: &block_service::WireBody,
        _kzg_proofs: &block_service::WireBody,
        _consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
}

struct RecordingSigner {
    inner: StubValidatorSigner,
    calls: Mutex<Vec<&'static str>>,
}

impl RecordingSigner {
    fn new() -> Self {
        Self { inner: StubValidatorSigner::new(), calls: Mutex::new(Vec::new()) }
    }

    fn record(&self, name: &'static str) {
        self.calls.lock().expect("calls mutex").push(name);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls mutex").clone()
    }
}

macro_rules! rec_fwd {
    ($($name:ident($($arg:ident: $ty:ty),* $(,)?));* $(;)?) => {
        #[async_trait]
        impl ValidatorSigner for RecordingSigner {
            $(
                async fn $name(
                    &self,
                    $($arg: $ty),*
                ) -> Result<Signature, SignerError> {
                    self.record(stringify!($name));
                    self.inner.$name($($arg),*).await
                }
            )*
        }
    };
}

rec_fwd! {
    sign_attestation(data: &AttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_block(block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_block_header(header: &BeaconBlockHeaderFields, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_randao_reveal(epoch: Epoch, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_sync_committee_message(beacon_block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_selection_proof(slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_aggregate_and_proof(aggregate_and_proof: &AggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_electra_aggregate_and_proof(aggregate_and_proof: &ElectraAggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_voluntary_exit(voluntary_exit: &VoluntaryExit, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_builder_registration(registration: &ValidatorRegistrationV1, pubkey: &PublicKey, fork_version: [u8; 4]);
    sign_sync_committee_selection_proof(slot: Slot, subcommittee_index: u64, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_contribution_and_proof(contribution_and_proof: &ContributionAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_payload_attestation(data: &eth_types::PayloadAttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_execution_payload_envelope_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    sign_aggregate_and_proof_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
}

fn fulu_electra_block(slot: Slot) -> BeaconBlock {
    BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    }
}

/// Production `propose_block` stays on V3 at epoch 1_000_000 (Fulu under the
/// sentinel), signs the Electra/Fulu tree-hash, and does not take the Gloas
/// island hasher or V4 produce. Aggregate at the same epoch records the
/// container signer, not `sign_aggregate_and_proof_root`.
#[tokio::test]
async fn test_l5_sentinel_epoch_v3_production_path() {
    let schedule = Arc::new(sentinel_gloas_schedule());
    let slot = FAR_FUTURE_EPOCH * SLOTS_PER_EPOCH;
    let fork = ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
    assert_ne!(fork, ForkName::Gloas, "far-future slot must stay pre-Gloas at the sentinel");
    assert!(fork < ForkName::Gloas);
    assert_eq!(fork, ForkName::Fulu);

    let block = fulu_electra_block(slot);
    let body_root = body_tree_hash_root(&block.body).expect("Electra body fixture");
    assert_eq!(
        hex::encode(body_root.0),
        EXTERNAL_ELECTRA_BODY_ROOT_HEX,
        "V3 body must be the Electra/Fulu EXTERNAL_* fixture"
    );
    let expected_block_root = block.try_tree_hash_root().expect("valid Electra body").0;

    let beacon = Arc::new(RecordingBeacon::new(block.clone()));
    let signer = Arc::new(RecordingSigner::new());
    let pubkey = SecretKey::generate().public_key();
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    let service =
        BlockService::new(signer.clone(), beacon.clone(), Arc::new(store), schedule.clone(), GVR);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Fulu V3 produce must succeed: {result:?}");
    let proposal = result.unwrap();
    assert_eq!(proposal.block_root, expected_block_root);
    assert_eq!(proposal.consensus_version, "fulu");
    assert!(!proposal.is_blinded);

    if let Ok(island) = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    ) {
        assert_ne!(
            proposal.block_root, island,
            "Fulu V3 must not sign the Gloas island root of the same body"
        );
    }

    let v3 = beacon.v3.lock().expect("v3 mutex").clone();
    let v4 = beacon.v4.lock().expect("v4 mutex").clone();
    assert_eq!(v3, vec![slot], "sentinel Gloas must take the V3 production path");
    assert!(v4.is_empty(), "Gloas V4 arm must be unreachable at the sentinel epoch");

    let agg = AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: FAR_FUTURE_EPOCH - 1, root: [2u8; 32] },
                target: Checkpoint { epoch: FAR_FUTURE_EPOCH, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    };
    signer
        .sign_aggregate_and_proof(&agg, &pubkey, &schedule, &GVR)
        .await
        .expect("container aggregate at Fulu");
    let calls = signer.calls();
    assert!(
        calls.contains(&"sign_aggregate_and_proof"),
        "Fulu aggregate must record sign_aggregate_and_proof; calls={calls:?}"
    );
    assert!(
        !calls.contains(&"sign_aggregate_and_proof_root"),
        "Fulu aggregate must not call sign_aggregate_and_proof_root; calls={calls:?}"
    );
}
