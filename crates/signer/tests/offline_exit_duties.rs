//! Exit-only enablement refuses every non-exit duty on `SignerService` and `SigningGate`.
//!
//! The control is `DoppelgangerDisabledByOperator` with the same keys loaded, so a
//! refusal under `OfflineExitEnablement` is the gate and not a fixture that cannot sign.
//! The selection-proof tests pin each surface's rejection label for the two selection duties.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use crypto::{
    CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer,
    SigningError, PUBLIC_KEY_BYTES_LEN,
};
use doppelganger::{DoppelgangerDisabledByOperator, SigningEnablement};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BuilderRequestAuth, Checkpoint,
    ContributionAndProof, ElectraAggregateAndProof, ElectraAttestation, ForkName, ForkSchedule,
    PayloadAttestationData, ProposerPreferences, Root, SyncCommitteeContribution,
    ValidatorRegistrationV1, VoluntaryExit, SLOTS_PER_EPOCH,
};
use rvc_signer::metrics::{
    rejection_reason, rejection_sign_type, version_label, RVC_SIGNER_REJECTIONS_TOTAL,
};
use rvc_signer::{
    BeaconBlockHeaderFields, OfflineExitEnablement, SignerError, SignerService, SigningGate,
    SigningGateError, ValidatorLockMap, ValidatorSigner,
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

fn open_pinned_db() -> Arc<SlashingDb> {
    let db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
    db.set_genesis_validators_root(&GVR).expect("pin gvr");
    db
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

fn service(signer: Arc<CompositeSigner>, enablement: Arc<dyn SigningEnablement>) -> Wired {
    let db = open_pinned_db();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(CallCounter { inner: signer.clone(), calls: Arc::clone(&calls) });
    let service = SignerService::new(signer, Arc::clone(&db))
        .with_enablement(enablement)
        .with_sign_backend(counter);
    Wired { service, db, calls }
}

fn slash_rows(db: &SlashingDb, pk: &PublicKey) -> (usize, usize) {
    let id = hex::encode(pk.to_bytes());
    (
        db.get_blocks(&id).expect("blocks").len(),
        db.get_attestations(&id).expect("attestations").len(),
    )
}

async fn signer_duties(
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

fn assert_signer_pair(
    name: &str,
    control: &Result<Signature, SignerError>,
    gated: &Result<Signature, SignerError>,
) {
    if name == "exit" {
        assert!(control.is_ok(), "{name} control must sign: {control:?}");
        assert!(gated.is_ok(), "{name} must sign for the exited pubkey: {gated:?}");
        return;
    }
    assert!(control.is_ok(), "{name} control must sign, so a refusal is the gate: {control:?}");
    assert!(
        matches!(gated, Err(SignerError::BlockedByDoppelganger)),
        "{name} must be refused by the exit-only gate, got {gated:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_offline_exit_enablement_refuses_every_non_exit_validator_duty() {
    let allowed_key = SecretKey::generate();
    let other_key = SecretKey::generate();
    let allowed = allowed_key.public_key();
    let other = other_key.public_key();
    let keys = composite([allowed_key, other_key]);

    let control_wired = service(Arc::clone(&keys), Arc::new(DoppelgangerDisabledByOperator));
    let control = signer_duties(&control_wired.service, &allowed, &other).await;
    let gated_wired = service(keys, Arc::new(OfflineExitEnablement::new(&allowed)));
    let gated = signer_duties(&gated_wired.service, &allowed, &other).await;

    assert_eq!(control.len(), 18, "16 non-exit duties, the other pubkey's exit, and the exit");
    for ((name, control_result), (gated_name, gated_result)) in control.iter().zip(gated.iter()) {
        assert_eq!(*name, *gated_name);
        assert_signer_pair(name, control_result, gated_result);
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

struct WiredGate {
    gate: SigningGate,
    db: Arc<SlashingDb>,
    calls: Arc<AtomicUsize>,
}

fn gate_for(signer: Arc<CompositeSigner>, enablement: Arc<dyn SigningEnablement>) -> WiredGate {
    let db = open_pinned_db();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(CallCounter { inner: signer, calls: Arc::clone(&calls) });
    let gate = SigningGate::new_with_raw_signer(
        Arc::clone(&db),
        enablement,
        counter,
        Arc::new(ValidatorLockMap::new()),
        Duration::from_secs(4),
    );
    WiredGate { gate, db, calls }
}

async fn gate_duties(
    gate: &SigningGate,
    pk: &PublicKey,
    other: &PublicKey,
) -> Vec<(&'static str, Result<Vec<u8>, SigningGateError>)> {
    let root = [0x42; 32];
    vec![
        ("block", gate.sign_block(pk, 1, root, GVR, "t").await),
        ("attestation", gate.sign_attestation(pk, 1, 2, root, GVR, "t").await),
        ("sync", gate.sign_sync_committee_message(pk, root).await),
        ("aggregate", gate.sign_aggregate_and_proof(pk, root).await),
        ("payload_attestation", gate.sign_payload_attestation(pk, root).await),
        ("proposer_preferences", gate.sign_proposer_preferences(pk, root).await),
        ("contribution", gate.sign_contribution_and_proof(pk, root).await),
        ("selection_proof", gate.sign_selection_proof(pk, root).await),
        ("sync_selection_proof", gate.sign_sync_committee_selection_proof(pk, root).await),
        ("randao", gate.sign_randao_reveal(pk, root).await),
        ("builder_registration", gate.sign_builder_registration(pk, root).await),
        ("builder_request_auth", gate.sign_builder_request_auth(pk, root).await),
        ("envelope", gate.sign_execution_payload_envelope(pk, root).await),
        ("exit_other_pk", gate.sign_voluntary_exit(other, root).await),
        ("exit", gate.sign_voluntary_exit(pk, root).await),
    ]
}

fn assert_gate_pair(
    name: &str,
    control: &Result<Vec<u8>, SigningGateError>,
    gated: &Result<Vec<u8>, SigningGateError>,
) {
    if name == "exit" {
        assert!(control.is_ok(), "{name} control must sign: {control:?}");
        assert!(gated.is_ok(), "{name} must sign for the exited pubkey: {gated:?}");
        return;
    }
    assert!(control.is_ok(), "{name} control must sign, so a refusal is the gate: {control:?}");
    assert!(
        matches!(gated, Err(SigningGateError::BlockedByDoppelganger)),
        "{name} must be refused by the exit-only gate, got {gated:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signing_gate_exit_only_refuses_every_non_exit_duty() {
    let allowed_key = SecretKey::generate();
    let other_key = SecretKey::generate();
    let allowed = allowed_key.public_key();
    let other = other_key.public_key();
    let keys = composite([allowed_key, other_key]);

    let control_wired = gate_for(Arc::clone(&keys), Arc::new(DoppelgangerDisabledByOperator));
    let control = gate_duties(&control_wired.gate, &allowed, &other).await;
    let gated_wired = gate_for(keys, Arc::new(OfflineExitEnablement::new(&allowed)));
    let gated = gate_duties(&gated_wired.gate, &allowed, &other).await;

    assert_eq!(control.len(), 15, "13 non-exit duties, the other pubkey's exit, and the exit");
    for ((name, control_result), (gated_name, gated_result)) in control.iter().zip(gated.iter()) {
        assert_eq!(*name, *gated_name);
        assert_gate_pair(name, control_result, gated_result);
    }

    assert_eq!(control_wired.calls.load(Ordering::SeqCst), 15, "control must reach the signer");
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

/// Refuses every root as an unsupported signing type, a classified rejection.
struct UnsupportedType;

#[async_trait]
impl Signer for UnsupportedType {
    async fn sign(
        &self,
        _signing_root: &Root,
        _pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        Err(SigningError::UnsupportedSigningType("selection proof".to_string()))
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        Vec::new()
    }
}

/// The counter only grows, so callers compare with `>`. Each surface uses its
/// own `version` label, and no other test in this binary records a rejection.
fn unsupported_type_rejections(sign_type: &str, version: &str) -> u64 {
    RVC_SIGNER_REJECTIONS_TOTAL
        .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
        .get()
}

#[tokio::test]
async fn test_signer_service_selection_proof_rejection_is_labelled_aggregation_slot() {
    let key = SecretKey::generate();
    let pk = key.public_key();
    let svc = SignerService::new(composite([key]), open_pinned_db())
        .with_enablement(Arc::new(DoppelgangerDisabledByOperator))
        .with_sign_backend(Arc::new(UnsupportedType));
    let fs = schedule();
    let slot = 12 * SLOTS_PER_EPOCH;
    let version = version_label(Some(ForkName::Electra));

    let attester = unsupported_type_rejections(rejection_sign_type::AGGREGATION_SLOT, version);
    let result = svc.sign_selection_proof(slot, &pk, &fs, &GVR).await;
    assert!(result.is_err(), "the backend refuses: {result:?}");
    assert!(
        unsupported_type_rejections(rejection_sign_type::AGGREGATION_SLOT, version) > attester,
        "SignerService::sign_selection_proof must count under aggregation_slot"
    );

    let sync_label = rejection_sign_type::SYNC_AGGREGATOR_SELECTION_DATA;
    let sync = unsupported_type_rejections(sync_label, version);
    let result = svc.sign_sync_committee_selection_proof(slot, 1, &pk, &fs, &GVR).await;
    assert!(result.is_err(), "the backend refuses: {result:?}");
    assert!(
        unsupported_type_rejections(sync_label, version) > sync,
        "SignerService::sign_sync_committee_selection_proof must count under {sync_label}"
    );
}

#[tokio::test]
async fn test_signing_gate_selection_proof_rejection_is_labelled_aggregation_slot() {
    let pk = SecretKey::generate().public_key();
    let gate = SigningGate::new_with_raw_signer(
        open_pinned_db(),
        Arc::new(DoppelgangerDisabledByOperator),
        Arc::new(UnsupportedType),
        Arc::new(ValidatorLockMap::new()),
        Duration::from_secs(4),
    );
    let version = rejection_reason::UNKNOWN;

    let attester = unsupported_type_rejections(rejection_sign_type::AGGREGATION_SLOT, version);
    let result = gate.sign_selection_proof(&pk, [0x42; 32]).await;
    assert!(result.is_err(), "the backend refuses: {result:?}");
    assert!(
        unsupported_type_rejections(rejection_sign_type::AGGREGATION_SLOT, version) > attester,
        "SigningGate::sign_selection_proof must count under aggregation_slot"
    );

    let sync_label = rejection_sign_type::SYNC_AGGREGATOR_SELECTION_DATA;
    let sync = unsupported_type_rejections(sync_label, version);
    let result = gate.sign_sync_committee_selection_proof(&pk, [0x42; 32]).await;
    assert!(result.is_err(), "the backend refuses: {result:?}");
    assert!(
        unsupported_type_rejections(sync_label, version) > sync,
        "SigningGate::sign_sync_committee_selection_proof must count under {sync_label}"
    );
}

fn arm_between<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let at = src.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &src[at + start.len()..];
    let stop = rest.find(end).unwrap_or_else(|| panic!("missing {end} after {start}"));
    &rest[..stop]
}

/// The signer-server keeps sync-committee selection apart from the attester
/// selection proof, in dispatch and in the gate docs.
#[test]
fn test_selection_dispatch_and_docs_stay_split() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let gate = std::fs::read_to_string(root.join("src/gate.rs")).expect("gate.rs");
    let plan =
        std::fs::read_to_string(root.join("../signer-server/src/sign_plan.rs")).expect("sign_plan");
    let service =
        std::fs::read_to_string(root.join("../signer-server/src/service.rs")).expect("service");

    let sync_arm =
        arm_between(&plan, "PlanInput::SyncCommitteeSelection", "PlanInput::ContributionAndProof");
    assert!(sync_arm.contains("NonSlashableOp::SyncCommitteeSelectionProof"), "{sync_arm}");
    assert!(!sync_arm.contains("NonSlashableOp::SelectionProof"), "{sync_arm}");
    let slot_arm = arm_between(&plan, "PlanInput::AggregationSlot", "PlanInput::AggregateAndProof");
    assert!(slot_arm.contains("NonSlashableOp::SelectionProof"), "{slot_arm}");
    assert!(!slot_arm.contains("SyncCommitteeSelectionProof"), "{slot_arm}");
    let dispatch = arm_between(
        &plan,
        "NonSlashableOp::SyncCommitteeSelectionProof =>",
        "NonSlashableOp::AggregateAndProof",
    );
    assert!(dispatch.contains("sign_sync_committee_selection_proof"), "{dispatch}");
    assert!(!dispatch.contains("sign_selection_proof"), "{dispatch}");

    let handler = arm_between(
        &service,
        "fn sign_sync_aggregator_selection_data",
        "fn sign_contribution_and_proof",
    );
    assert!(handler.contains("NonSlashableOp::SyncCommitteeSelectionProof"), "{handler}");
    assert!(!handler.contains("NonSlashableOp::SelectionProof"), "{handler}");

    let selection_doc = preceding(&gate, "pub async fn sign_selection_proof");
    assert!(selection_doc.contains("DOMAIN_SELECTION_PROOF"), "{selection_doc}");
    assert!(!selection_doc.contains("DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"), "{selection_doc}");
    assert!(!selection_doc.contains("DOMAIN_RANDAO"), "{selection_doc}");
    let sync_doc = preceding(&gate, "pub async fn sign_sync_committee_selection_proof");
    assert!(sync_doc.contains("DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"), "{sync_doc}");
    let randao_doc = preceding(&gate, "pub async fn sign_randao_reveal");
    assert!(randao_doc.contains("DOMAIN_RANDAO"), "{randao_doc}");
}

fn preceding<'a>(src: &'a str, marker: &str) -> &'a str {
    let at = src.find(marker).unwrap_or_else(|| panic!("missing {marker}"));
    let start = at.saturating_sub(500);
    &src[start..at]
}
