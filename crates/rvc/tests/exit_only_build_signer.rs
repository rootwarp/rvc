//! `ServiceBuilder::build_signer` always wraps the enablement in `QuiescingEnablement`.
//! An exit-only inner must still refuse every non-exit duty after that wrap.
//!
//! The control uses the same builder with `DoppelgangerDisabledByOperator`, so a
//! refusal is the forwarded exit-only flag and not a duty the fixture cannot sign.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use crypto::{
    CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer,
    SigningError, PUBLIC_KEY_BYTES_LEN,
};
use doppelganger::{DoppelgangerDisabledByOperator, SigningEnablement};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BuilderRequestAuth, Checkpoint,
    ContributionAndProof, ElectraAggregateAndProof, ElectraAttestation, ForkSchedule,
    PayloadAttestationData, ProposerPreferences, Root, SyncCommitteeContribution,
    ValidatorRegistrationV1, VoluntaryExit, SLOTS_PER_EPOCH,
};
use rvc::config::{Config, ServiceBuilder};
use signer::{
    BeaconBlockHeaderFields, OfflineExitEnablement, SignerError, SignerService, ValidatorSigner,
};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

fn schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x10, 0, 0, 0],
        altair_fork_epoch: 1,
        altair_fork_version: [0x11, 0, 0, 0],
        bellatrix_fork_epoch: 2,
        bellatrix_fork_version: [0x12, 0, 0, 0],
        capella_fork_epoch: 3,
        capella_fork_version: [0x13, 0, 0, 0],
        deneb_fork_epoch: 4,
        deneb_fork_version: [0x14, 0, 0, 0],
        electra_fork_epoch: 10,
        electra_fork_version: [0x15, 0, 0, 0],
        fulu_fork_epoch: 20,
        fulu_fork_version: [0x16, 0, 0, 0],
        gloas_fork_epoch: 30,
        gloas_fork_version: [0x17, 0, 0, 0],
    }
}

fn att(slot: u64, source: u64, target: u64) -> AttestationData {
    AttestationData {
        slot,
        index: 0,
        beacon_block_root: [0x55; 32],
        source: Checkpoint { epoch: source, root: [0x66; 32] },
        target: Checkpoint { epoch: target, root: [0x77; 32] },
    }
}

fn composite(keys: impl IntoIterator<Item = SecretKey>) -> Arc<CompositeSigner> {
    let mut manager = KeyManager::new();
    for key in keys {
        manager.insert(key);
    }
    Arc::new(CompositeSigner::new(LocalSigner::new(manager)))
}

struct CallCounter {
    inner: Arc<dyn Signer>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Signer for CallCounter {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.inner.public_keys()
    }
}

struct Wired {
    service: SignerService,
    db: Arc<SlashingDb>,
    calls: Arc<AtomicUsize>,
}

fn built(signer: Arc<CompositeSigner>, enablement: Arc<dyn SigningEnablement>) -> Wired {
    let db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
    db.set_genesis_validators_root(&GVR).expect("pin gvr");
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(CallCounter { inner: signer.clone(), calls: Arc::clone(&calls) });
    let (service, _registry) =
        ServiceBuilder::new(Config::default()).build_signer(signer, Arc::clone(&db), enablement);
    let service = match Arc::try_unwrap(service) {
        Ok(service) => service,
        Err(_shared) => panic!("builder returns a unique signer"),
    };
    let service = service.with_sign_backend(counter);
    Wired { service, db, calls }
}

fn slash_rows(db: &SlashingDb, pk: &PublicKey) -> (usize, usize) {
    let id = hex::encode(pk.to_bytes());
    (
        db.get_blocks(&id).expect("blocks").len(),
        db.get_attestations(&id).expect("attestations").len(),
    )
}

async fn duties(
    svc: &SignerService,
    pk: &PublicKey,
    other: &PublicKey,
) -> Vec<(&'static str, Result<Signature, SignerError>)> {
    let fs = schedule();
    let gvr = &GVR;
    let deneb_slot = 5 * SLOTS_PER_EPOCH;
    let electra_slot = 12 * SLOTS_PER_EPOCH;
    let gloas_slot = 35 * SLOTS_PER_EPOCH;
    let agg = AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: att(deneb_slot, 4, 5),
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    };
    let electra = ElectraAggregateAndProof {
        aggregator_index: 42,
        aggregate: ElectraAttestation {
            aggregation_bits: vec![0xff; 4],
            data: att(electra_slot, 11, 12),
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
        },
        selection_proof: vec![0xbb; 96],
    };
    let contrib = ContributionAndProof {
        aggregator_index: 7,
        contribution: SyncCommitteeContribution {
            slot: electra_slot,
            beacon_block_root: [0x99; 32],
            subcommittee_index: 1,
            aggregation_bits: vec![0x03; 16],
            signature: vec![0xcc; 96],
        },
        selection_proof: vec![0xdd; 96],
    };
    let header = BeaconBlockHeaderFields {
        slot: electra_slot + 1,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
        body_ssz: Vec::new(),
        is_blinded: false,
    };
    let ptc = PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot: gloas_slot,
        payload_present: true,
        blob_data_available: false,
    };
    let prefs = ProposerPreferences {
        dependent_root: [0x33; 32],
        proposal_slot: gloas_slot,
        validator_index: 3,
        fee_recipient: [0x44; 20],
        target_gas_limit: 36_000_000,
    };
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0x44; 20],
        gas_limit: 30_000_000,
        timestamp: 1,
        pubkey: pk.to_bytes(),
    };
    let auth = BuilderRequestAuth::new(hex::decode("1234567890abcdef").expect("auth bytes"), 1)
        .expect("builder request auth");
    let exit = VoluntaryExit { epoch: 12, validator_index: 1 };
    vec![
        ("attestation", svc.sign_attestation(&att(electra_slot, 11, 12), pk, &fs, gvr).await),
        ("block", svc.sign_block(&[0x01; 32], electra_slot, pk, &fs, gvr).await),
        ("block_header", svc.sign_block_header(&header, pk, &fs, gvr).await),
        ("randao", svc.sign_randao_reveal(12, pk, &fs, gvr).await),
        (
            "sync_msg",
            svc.sign_sync_committee_message(&[0x02; 32], electra_slot, pk, &fs, gvr).await,
        ),
        ("selection_proof", svc.sign_selection_proof(electra_slot, pk, &fs, gvr).await),
        ("aggregate", svc.sign_aggregate_and_proof(&agg, pk, &fs, gvr).await),
        ("electra_aggregate", svc.sign_electra_aggregate_and_proof(&electra, pk, &fs, gvr).await),
        ("builder_registration", svc.sign_builder_registration(&reg, pk, [0x10, 0, 0, 0]).await),
        (
            "sync_selection_proof",
            svc.sign_sync_committee_selection_proof(electra_slot, 1, pk, &fs, gvr).await,
        ),
        ("contribution", svc.sign_contribution_and_proof(&contrib, pk, &fs, gvr).await),
        ("payload_attestation", svc.sign_payload_attestation(&ptc, pk, &fs, gvr).await),
        ("proposer_preferences", svc.sign_proposer_preferences(&prefs, pk, &fs, gvr).await),
        ("builder_request_auth", svc.sign_builder_request_auth(&auth, pk, [0x10, 0, 0, 0]).await),
        (
            "envelope_root",
            svc.sign_execution_payload_envelope_root(&[0x03; 32], gloas_slot, pk, &fs, gvr).await,
        ),
        (
            "aggregate_root",
            svc.sign_aggregate_and_proof_root(&[0x04; 32], deneb_slot, pk, &fs, gvr).await,
        ),
        ("exit_other_pk", svc.sign_voluntary_exit(&exit, other, &fs, gvr).await),
        ("exit", svc.sign_voluntary_exit(&exit, pk, &fs, gvr).await),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_build_signer_exit_only_refuses_every_non_exit_duty() {
    let allowed_key = SecretKey::generate();
    let other_key = SecretKey::generate();
    let allowed = allowed_key.public_key();
    let other = other_key.public_key();
    let keys = composite([allowed_key, other_key]);

    let control_wired = built(Arc::clone(&keys), Arc::new(DoppelgangerDisabledByOperator));
    let control = duties(&control_wired.service, &allowed, &other).await;
    let gated_wired = built(keys, Arc::new(OfflineExitEnablement::new(&allowed)));
    let gated = duties(&gated_wired.service, &allowed, &other).await;

    assert_eq!(control.len(), 18, "16 non-exit duties, the other pubkey's exit, and the exit");
    for ((name, control_result), (gated_name, gated_result)) in control.iter().zip(gated.iter()) {
        assert_eq!(*name, *gated_name);
        if *name == "exit" {
            assert!(control_result.is_ok(), "{name} control must sign: {control_result:?}");
            assert!(
                gated_result.is_ok(),
                "{name} must sign for the exited pubkey: {gated_result:?}"
            );
            continue;
        }
        assert!(
            control_result.is_ok(),
            "{name} control must sign, so a refusal is the gate: {control_result:?}"
        );
        assert!(
            matches!(gated_result, Err(SignerError::BlockedByDoppelganger)),
            "{name} must be refused by the wrapped exit-only gate, got {gated_result:?}"
        );
    }

    assert_eq!(control_wired.calls.load(Ordering::SeqCst), 18, "control must reach the signer");
    let (control_blocks, control_atts) = slash_rows(&control_wired.db, &allowed);
    assert!(control_blocks > 0 && control_atts > 0, "control must record slashable rows");
    assert_eq!(
        gated_wired.calls.load(Ordering::SeqCst),
        1,
        "only the voluntary exit may reach the signer"
    );
    assert_eq!(slash_rows(&gated_wired.db, &allowed), (0, 0));
    assert_eq!(slash_rows(&gated_wired.db, &other), (0, 0));
}
