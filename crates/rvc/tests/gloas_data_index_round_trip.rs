//! Issue 6.12: L4 behavioural `data.index` 0/1 round-trip.
//!
//! Fixture BN → recording signer → submitted `SingleAttestation`. At a Gloas
//! epoch the payload-status bit survives BN → signature → submission for both
//! `index` values. Electra and Fulu still zero. Submission uses the Gloas wire
//! version (`Eth-Consensus-Version: gloas`), not `fulu`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationData as BeaconAttestationData, AttesterDuty, BeaconClient, BeaconClientConfig,
    Checkpoint as BeaconCheckpoint, DataResponse, DependentRootResponse, SingleAttestation,
    HEADER_ETH_CONSENSUS_VERSION,
};
use bn_manager::{BeaconNodeClient, MockBeaconNodeClient, Propagator};
use common::pipeline_fixture::NoopBlockBeacon;
use crypto::{
    signing_root_for, CompositeSigner, DutyRef, KeyManager, LocalSigner, SecretKey, Signature,
    Signer, SigningCtx, SigningError,
};
use duty_tracker::DutyTracker;
use eth_types::{AttestationData, Checkpoint, ForkName, ForkSchedule, Root, Slot, SLOTS_PER_EPOCH};
use rvc::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorDeps};
use rvc_gloas::KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT;
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use ssz08::Encode;
use timing::MockSlotClock;
use validator_store::{ValidatorConfig, ValidatorStore};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const VALIDATOR_INDEX: &str = "1";
const COMMITTEE_INDEX: &str = "3";
const TEST_ELECTRA_EPOCH: u64 = 50;
const TEST_FULU_EPOCH: u64 = 60;
/// Test-only near Gloas epoch — never a network value.
const TEST_GLOAS_EPOCH: u64 = 70;
const GVR: Root = [0xaa; 32];

/// pyspec argv `--fork-version 0x07000001` (issue 5.13b / 6.8 KAT provenance).
const KAT_GLOAS_FORK_VERSION: [u8; 4] = [0x07, 0x00, 0x00, 0x01];

fn near_gloas_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 10,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 30,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 40,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: TEST_ELECTRA_EPOCH,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: TEST_FULU_EPOCH,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: TEST_GLOAS_EPOCH,
        gloas_fork_version: [7, 0, 0, 0],
    })
}

fn kat_gloas_schedule() -> ForkSchedule {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.gloas_fork_epoch = 0;
    schedule.gloas_fork_version = KAT_GLOAS_FORK_VERSION;
    schedule
}

fn epoch_for(fork: ForkName) -> u64 {
    match fork {
        ForkName::Electra => TEST_ELECTRA_EPOCH,
        ForkName::Fulu => TEST_FULU_EPOCH,
        ForkName::Gloas => TEST_GLOAS_EPOCH,
        other => panic!("issue 6.12 covers Electra/Fulu/Gloas, got {other:?}"),
    }
}

fn root_hex(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn parse_root(hex_str: &str) -> Root {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).expect("root hex");
    bytes.try_into().expect("32-byte root")
}

fn crypto_from_beacon(data: &BeaconAttestationData) -> AttestationData {
    AttestationData {
        slot: data.slot.parse().expect("slot"),
        index: data.index.parse().expect("index"),
        beacon_block_root: parse_root(&data.beacon_block_root),
        source: Checkpoint {
            epoch: data.source.epoch.parse().expect("source epoch"),
            root: parse_root(&data.source.root),
        },
        target: Checkpoint {
            epoch: data.target.epoch.parse().expect("target epoch"),
            root: parse_root(&data.target.root),
        },
    }
}

fn make_bn_attestation_data(slot: Slot, epoch: u64, index: &str) -> BeaconAttestationData {
    BeaconAttestationData {
        slot: slot.to_string(),
        index: index.to_string(),
        beacon_block_root: root_hex(0x11),
        source: BeaconCheckpoint {
            epoch: epoch.saturating_sub(1).to_string(),
            root: root_hex(0x22),
        },
        target: BeaconCheckpoint { epoch: epoch.to_string(), root: root_hex(0x33) },
    }
}

fn make_attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: VALIDATOR_INDEX.to_string(),
        committee_index: COMMITTEE_INDEX.to_string(),
        committee_length: "8".to_string(),
        committees_at_slot: "4".to_string(),
        validator_committee_index: "2".to_string(),
        slot: slot.to_string(),
    }
}

struct RecordingSigner {
    inner: Arc<CompositeSigner>,
    roots: Mutex<Vec<Root>>,
}

impl RecordingSigner {
    fn new(inner: Arc<CompositeSigner>) -> Self {
        Self { inner, roots: Mutex::new(Vec::new()) }
    }

    fn roots(&self) -> Vec<Root> {
        self.roots.lock().expect("recording signer").clone()
    }
}

#[async_trait]
impl Signer for RecordingSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        self.roots.lock().expect("recording signer").push(*signing_root);
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

struct RoundTrip {
    bn_data: BeaconAttestationData,
    submitted: SingleAttestation,
    wire_version: String,
    signed_root: Root,
    /// Reconstructed from the submitted `SingleAttestation`, not from `sign_attestation`.
    submitted_crypto: AttestationData,
    schedule: Arc<ForkSchedule>,
}

async fn run_round_trip(fork: ForkName, bn_index: &str) -> RoundTrip {
    let schedule = near_gloas_schedule();
    let epoch = epoch_for(fork);
    let slot = epoch * SLOTS_PER_EPOCH;
    assert_eq!(ForkName::from_epoch(epoch, &schedule), fork);
    let expected_version = fork.as_ref();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let bn_data = make_bn_attestation_data(slot, epoch, bn_index);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(header(HEADER_ETH_CONSENSUS_VERSION, expected_version))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let submit_client =
        BeaconClient::new(BeaconClientConfig::new(mock_server.uri()).with_max_retries(0))
            .expect("BeaconClient");

    let duty = make_attester_duty(&pubkey_hex, slot);
    let bn_for_duty = bn_data.clone();
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(move |_epoch, _indices| {
                Ok(DependentRootResponse {
                    dependent_root: root_hex(0xdd),
                    execution_optimistic: false,
                    data: vec![duty.clone()],
                })
            })
            .with_get_attestation_data(move |_slot, _committee_index| {
                Ok(DataResponse { data: bn_for_duty.clone() })
            }),
    );
    let beacon: Arc<dyn BeaconNodeClient> = mock;

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let recording = Arc::new(RecordingSigner::new(Arc::clone(&composite)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let signer = Arc::new(
        SignerService::new(Arc::clone(&composite), slashing_db)
            .with_enablement(always_enabled())
            .with_sign_backend(recording.clone()),
    );

    let duty_tracker =
        Arc::new(DutyTracker::new(beacon.clone(), vec![VALIDATOR_INDEX.to_string()]));

    let mut map = HashMap::new();
    map.insert(pubkey.to_bytes(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();

    let clock =
        Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), SLOTS_PER_EPOCH));
    clock.set_slot(slot);

    let config = OrchestratorConfig::new(GVR, schedule.clone());
    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(submit_client))),
        beacon,
        Arc::new(NoopBlockBeacon),
        None,
        validator_store,
        config,
        pubkey_map,
    );
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    let results = orchestrator.process_slot(slot).await.expect("process_slot");
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "attestation must succeed: {:?}", results[0].error);

    let requests = mock_server.received_requests().await.expect("wiremock requests");
    let submit = requests
        .iter()
        .find(|r| r.url.path() == "/eth/v2/beacon/pool/attestations")
        .expect("POST /eth/v2/beacon/pool/attestations");
    let wire_version = submit
        .headers
        .get(HEADER_ETH_CONSENSUS_VERSION)
        .expect("Eth-Consensus-Version")
        .to_str()
        .expect("header utf8")
        .to_string();
    let submitted: Vec<SingleAttestation> =
        serde_json::from_slice(&submit.body).expect("SingleAttestation JSON");
    assert_eq!(submitted.len(), 1);
    let submitted = submitted.into_iter().next().unwrap();

    let roots = recording.roots();
    assert_eq!(roots.len(), 1, "exactly one BLS sign for the attestation");
    let signed_root = roots[0];
    let submitted_crypto = crypto_from_beacon(&submitted.data);

    let ctx = SigningCtx { fork_schedule: schedule.as_ref(), genesis_validators_root: GVR };
    assert_eq!(
        signed_root,
        signing_root_for(&DutyRef::Attestation(&submitted_crypto), &ctx),
        "recorded signing root must equal the submitted AttestationData"
    );
    let sig_bytes = hex::decode(submitted.signature.trim_start_matches("0x")).expect("sig hex");
    let sig = Signature::from_bytes(&sig_bytes).expect("signature");
    sig.verify(&pubkey, &signed_root).expect("signature must verify over the recorded root");

    RoundTrip { bn_data, submitted, wire_version, signed_root, submitted_crypto, schedule }
}

fn assert_bytes_equal(left: &AttestationData, right: &AttestationData, label: &str) {
    assert_eq!(left, right, "{label}: AttestationData must match");
    assert_eq!(
        Encode::as_ssz_bytes(left),
        Encode::as_ssz_bytes(right),
        "{label}: SSZ bytes must match"
    );
}

fn ctx_for(schedule: &ForkSchedule) -> SigningCtx<'_> {
    SigningCtx { fork_schedule: schedule, genesis_validators_root: GVR }
}

/// `index = 1` KAT from P5 5.13b / 6.8 `test-fixtures` (do not mint a new hex).
#[test]
fn test_gloas_attestation_data_index_1_signing_root() {
    let data = AttestationData {
        slot: 1,
        index: 1,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 0, root: [0; 32] },
        target: Checkpoint { epoch: 0, root: [0; 32] },
    };
    let schedule = kat_gloas_schedule();
    let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0; 32] };
    let got = signing_root_for(&DutyRef::Attestation(&data), &ctx);
    assert_eq!(
        hex::encode(got),
        KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT,
        "Gloas AttestationData index=1 signing root"
    );
}

#[tokio::test]
async fn test_gloas_data_index_0_and_1_round_trip() {
    for bn_index in ["0", "1"] {
        let rt = run_round_trip(ForkName::Gloas, bn_index).await;
        let bn_crypto = crypto_from_beacon(&rt.bn_data);
        let ctx = ctx_for(&rt.schedule);

        assert_eq!(rt.wire_version, "gloas", "Eth-Consensus-Version must be gloas, not fulu");
        assert_eq!(rt.submitted.data.index, bn_index);
        assert_eq!(
            serde_json::to_vec(&rt.submitted.data).expect("submitted json"),
            serde_json::to_vec(&rt.bn_data).expect("bn json"),
            "Gloas submitted SingleAttestation.data must be byte-identical to the BN value"
        );
        assert_bytes_equal(
            &rt.submitted_crypto,
            &bn_crypto,
            &format!("Gloas index={bn_index} submitted == BN"),
        );
        assert_eq!(
            rt.signed_root,
            signing_root_for(&DutyRef::Attestation(&bn_crypto), &ctx),
            "Gloas index={bn_index}: recorded signer root must equal BN data"
        );

        if bn_index == "1" {
            let mut zeroed = bn_crypto.clone();
            zeroed.index = 0;
            assert_ne!(
                rt.signed_root,
                signing_root_for(&DutyRef::Attestation(&zeroed), &ctx),
                "Gloas index=1 must fail if the signing path zeroed the payload-status bit"
            );
        }
    }
}

#[tokio::test]
async fn test_electra_and_fulu_still_zero_index_on_signing_and_submission() {
    for (fork, version) in [(ForkName::Electra, "electra"), (ForkName::Fulu, "fulu")] {
        let rt = run_round_trip(fork, "1").await;
        let bn_crypto = crypto_from_beacon(&rt.bn_data);
        let ctx = ctx_for(&rt.schedule);
        assert_eq!(rt.bn_data.index, "1", "{fork:?}: BN supplied a non-zero index");
        assert_eq!(rt.wire_version, version, "{fork:?}: Eth-Consensus-Version");
        assert_eq!(
            rt.submitted.data.index, "0",
            "{fork:?}: submission-path SingleAttestation.data.index must be zeroed"
        );
        assert_eq!(
            rt.submitted_crypto.index, 0,
            "{fork:?}: submitted AttestationData.index must be zeroed"
        );
        let mut expected = bn_crypto.clone();
        expected.index = 0;
        assert_bytes_equal(
            &rt.submitted_crypto,
            &expected,
            &format!("{fork:?} submitted == zeroed BN"),
        );
        assert_ne!(
            rt.signed_root,
            signing_root_for(&DutyRef::Attestation(&bn_crypto), &ctx),
            "{fork:?}: recorded root must not match BN index=1"
        );
        assert_ne!(
            serde_json::to_vec(&rt.submitted.data).expect("submitted json"),
            serde_json::to_vec(&rt.bn_data).expect("bn json"),
            "{fork:?}: submitted data must not leak the BN's non-zero index"
        );
    }
}
