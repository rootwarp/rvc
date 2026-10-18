//! Exit-only enablement refuses every non-exit duty on `SignerService` and `SigningGate`.
//!
//! The control is `DoppelgangerDisabledByOperator` with the same keys loaded, so a
//! refusal under `OfflineExitEnablement` is the gate and not a fixture that cannot sign.

use std::collections::{BTreeMap, BTreeSet};
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
    ContributionAndProof, ElectraAggregateAndProof, ElectraAttestation, ForkSchedule,
    PayloadAttestationData, ProposerPreferences, Root, SyncCommitteeContribution,
    ValidatorRegistrationV1, VoluntaryExit, SLOTS_PER_EPOCH,
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

fn function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name = rest.split(['(', '<']).next()?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

fn duty_on_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return None;
    }
    let idx = line.find("SigningDuty::")?;
    let rest = &line[idx + "SigningDuty::".len()..];
    let duty: String =
        rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if duty.is_empty() {
        None
    } else {
        Some(duty)
    }
}

fn duty_map(src: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut current = String::new();
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in src.lines() {
        if let Some(name) = function_name(line) {
            current = name;
        }
        if current.starts_with("test_") {
            continue;
        }
        if let Some(duty) = duty_on_line(line) {
            map.entry(current.clone()).or_default().insert(duty);
        }
    }
    map
}

fn expect_duties(pairs: &[(&str, &str)]) -> BTreeMap<String, BTreeSet<String>> {
    let mut map = BTreeMap::new();
    for (function, duty) in pairs {
        map.entry((*function).to_string())
            .or_insert_with(BTreeSet::new)
            .insert((*duty).to_string());
    }
    map
}

fn arm_between<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let at = src.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &src[at + start.len()..];
    let stop = rest.find(end).unwrap_or_else(|| panic!("missing {end} after {start}"));
    &rest[..stop]
}

/// Every production `SigningDuty::` site names its method. Only `sign_voluntary_exit`
/// uses `VoluntaryExit`. Sync-committee selection is not the attester selection proof.
#[test]
fn test_method_to_duty_mapping_reserves_voluntary_exit() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let signer = std::fs::read_to_string(root.join("src/lib.rs")).expect("lib.rs");
    let gate = std::fs::read_to_string(root.join("src/gate.rs")).expect("gate.rs");
    let plan =
        std::fs::read_to_string(root.join("../signer-server/src/sign_plan.rs")).expect("sign_plan");
    let service =
        std::fs::read_to_string(root.join("../signer-server/src/service.rs")).expect("service");

    let signer_expected = expect_duties(&[
        ("sign_attestation", "Attestation"),
        ("sign_block", "Block"),
        ("sign_block_header", "Block"),
        ("sign_randao_reveal", "RandaoReveal"),
        ("sign_sync_committee_message", "SyncCommitteeMessage"),
        ("sign_payload_attestation", "PayloadAttestation"),
        ("sign_proposer_preferences", "ProposerPreferences"),
        ("sign_builder_request_auth", "BuilderRequestAuth"),
        ("sign_execution_payload_envelope_root", "ExecutionPayloadEnvelope"),
        ("sign_selection_proof", "SelectionProof"),
        ("sign_aggregate_and_proof", "AggregateAndProof"),
        ("sign_aggregate_and_proof_root", "AggregateAndProofRoot"),
        ("sign_electra_aggregate_and_proof", "ElectraAggregateAndProof"),
        ("sign_voluntary_exit", "VoluntaryExit"),
        ("sign_builder_registration", "BuilderRegistration"),
        ("sign_sync_committee_selection_proof", "SyncCommitteeSelectionProof"),
        ("sign_contribution_and_proof", "ContributionAndProof"),
    ]);
    assert_eq!(duty_map(&signer), signer_expected, "SignerService method-to-duty map");

    let gate_expected = expect_duties(&[
        ("sign_block", "Block"),
        ("sign_attestation", "Attestation"),
        ("sign_sync_committee_message", "SyncCommitteeMessage"),
        ("sign_aggregate_and_proof", "AggregateAndProof"),
        ("sign_payload_attestation", "PayloadAttestation"),
        ("sign_proposer_preferences", "ProposerPreferences"),
        ("sign_contribution_and_proof", "ContributionAndProof"),
        ("sign_selection_proof", "SelectionProof"),
        ("sign_sync_committee_selection_proof", "SyncCommitteeSelectionProof"),
        ("sign_randao_reveal", "RandaoReveal"),
        ("sign_voluntary_exit", "VoluntaryExit"),
        ("sign_builder_registration", "BuilderRegistration"),
        ("sign_builder_request_auth", "BuilderRequestAuth"),
        ("sign_execution_payload_envelope", "ExecutionPayloadEnvelope"),
    ]);
    assert_eq!(duty_map(&gate), gate_expected, "SigningGate method-to-duty map");

    for (label, map) in [("signer", duty_map(&signer)), ("gate", duty_map(&gate))] {
        for (function, duties) in &map {
            if duties.contains("VoluntaryExit") {
                assert_eq!(
                    function, "sign_voluntary_exit",
                    "{label} {function} must not use VoluntaryExit"
                );
            }
        }
    }

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
