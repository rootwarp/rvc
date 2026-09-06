//! Issue 4.18: PTC fetch → deadline fire → `DOMAIN_PTC_ATTESTER` sign → POST
//! against a fixture BN. The slashing DB must not grow a row.
//!
//! Cache-cold `DutyOrchestrator::run()` must POST `duties/ptc` itself (no
//! harness pre-fetch). The fixture serves `duties/ptc`,
//! `payload_attestation_data`, and `pool/payload_attestations`. Deadline
//! observation uses paused time, which cannot share a runtime with wiremock HTTP.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    BeaconError, PayloadAttestationDataResponse, PtcDutiesResponse, PtcDuty,
    SubmitAttestationResult, VersionedAttestation,
};
use block_service::{BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, MockBeaconNodeClient, Propagator};
use crypto::{
    compute_domain, compute_signing_root, signing_root_for, CompositeSigner, DutyRef, KeyManager,
    LocalSigner, SecretKey, Signature, SigningCtx,
};
use duty_tracker::DutyTracker;
use eth_types::{
    ForkSchedule, PayloadAttestationData, SignedBeaconBlock, SignedBlindedBeaconBlock, Slot,
    DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER,
};
use parking_lot::Mutex as ParkingMutex;
use rvc::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorDeps};
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::{due_ms, DeadlineBps, DeadlineSchedule, MockSlotClock};
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;
use validator_store::{ValidatorConfig, ValidatorStore};

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const SLOTS_PER_EPOCH: u64 = 32;
/// First Gloas slot when `gloas_fork_epoch = 1`.
const SLOT: Slot = 32;
const EPOCH: u64 = 1;
const VALIDATOR_INDEX: u64 = 1;
const GVR: [u8; 32] = [0xaa; 32];
const BLOCK_ROOT: [u8; 32] = [0x11; 32];
/// Deliberately not spec 7500 — fire time must come from the resolved set.
const PTC_BPS: u64 = 8000;
const PRODUCE_PAYLOAD_ATTESTATIONS: &str = "orchestrator.produce_payload_attestations";

fn gloas_schedule() -> Arc<ForkSchedule> {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.gloas_fork_epoch = EPOCH;
    Arc::new(schedule)
}

fn ptc_deadline_bps() -> DeadlineBps {
    DeadlineBps {
        attestation: 2500,
        aggregate: 5000,
        sync_message: 2500,
        contribution: 5000,
        payload: 5000,
        payload_attestation: PTC_BPS,
    }
}

fn expected_data() -> PayloadAttestationData {
    PayloadAttestationData {
        beacon_block_root: BLOCK_ROOT,
        slot: SLOT,
        payload_present: true,
        blob_data_available: false,
    }
}

fn slashing_row_count(db: &SlashingDb, pubkey_hex: &str) -> usize {
    db.get_attestations(pubkey_hex).expect("attestations").len()
        + db.get_blocks(pubkey_hex).expect("blocks").len()
}

struct NoopSubmitter;

impl AttestationSubmitter for NoopSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

struct NoopBlockBeacon;

#[async_trait]
impl BeaconBlockClient for NoopBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        Err(BlockServiceError::Beacon("noop".to_string()))
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        Err(BlockServiceError::Beacon("noop".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &SignedBeaconBlock,
        _consensus_version: &str,
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
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
}

struct TimedSpans {
    start: tokio::time::Instant,
    times: Arc<ParkingMutex<Vec<(String, u64)>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TimedSpans {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        self.times.lock().push((attrs.metadata().name().to_string(), elapsed));
    }
}

fn first_ms(times: &[(String, u64)], name: &str) -> u64 {
    times
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, ms)| *ms)
        .unwrap_or_else(|| panic!("missing span {name}, got {times:?}"))
}

/// Cache-cold `run()`: orchestrator POSTs duties/ptc, waits to the resolved
/// payload-attestation offset, signs under `DOMAIN_PTC_ATTESTER`, and POSTs a
/// message that matches the signed data.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_ptc_duty_round_trip() {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let pubkey_hex_plain = hex::encode(pubkey.to_bytes());
    let expected = expected_data();

    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_post_ptc_duties({
                let duty = PtcDuty {
                    pubkey: pubkey_hex.clone(),
                    validator_index: VALIDATOR_INDEX.to_string(),
                    slot: SLOT.to_string(),
                };
                move |_epoch, _indices| {
                    Ok(PtcDutiesResponse {
                        dependent_root: "0xdeproot".to_string(),
                        execution_optimistic: false,
                        data: vec![duty.clone()],
                    })
                }
            })
            .with_get_payload_attestation_data({
                let expected = expected.clone();
                move |_slot| Ok(Some(PayloadAttestationDataResponse { data: expected.clone() }))
            })
            .with_submit_payload_attestations(|_msgs| Ok(())),
    );
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();

    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
    let rows_before = slashing_row_count(&slashing_db, &pubkey_hex_plain);

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let signer = Arc::new(
        SignerService::new(composite, Arc::clone(&slashing_db)).with_enablement(always_enabled()),
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
    clock.set_slot(SLOT);

    let config = OrchestratorConfig::new(GVR, gloas_schedule())
        .with_deadline_schedule(DeadlineSchedule {
            pre_gloas: DeadlineBps::default(),
            gloas: ptc_deadline_bps(),
        })
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO);

    let mut deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(NoopSubmitter))),
        beacon,
        Arc::new(NoopBlockBeacon),
        None,
        validator_store,
        config,
        pubkey_map,
    );
    deps.attesting_enabled = Arc::new(AtomicBool::new(false));
    let (mut orchestrator, handle) = DutyOrchestrator::new(deps);
    orchestrator.set_sync_enabled(false);

    let times = Arc::new(ParkingMutex::new(Vec::new()));
    let layer = TimedSpans { start: tokio::time::Instant::now(), times: times.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(11_000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let recorded = times.lock().clone();
    let slot_duration_ms = 12_000;
    let expected_ms = due_ms(PTC_BPS, slot_duration_ms);
    let ptc_ms = first_ms(&recorded, PRODUCE_PAYLOAD_ATTESTATIONS);
    assert_eq!(ptc_ms, expected_ms, "PTC must fire at resolved payload_attestation bps");
    assert_ne!(ptc_ms, due_ms(7500, slot_duration_ms), "must not hardcode 7500 bps");

    let ptc_duty_calls = mock.post_ptc_duties_calls();
    assert!(
        ptc_duty_calls.iter().any(|(epoch, indices)| {
            *epoch == EPOCH && indices.as_slice() == [VALIDATOR_INDEX.to_string()]
        }),
        "cache-cold run() must POST duties/ptc, got {ptc_duty_calls:?}"
    );

    assert_eq!(mock.get_payload_attestation_data_calls(), vec![SLOT]);
    let calls = mock.submit_payload_attestations_calls();
    assert_eq!(calls.len(), 1, "fixture BN must accept pool/payload_attestations");
    let messages = calls.into_iter().next().expect("one submit batch");
    assert_eq!(messages.len(), 1);
    let message = &messages[0];
    assert_eq!(message.validator_index, VALIDATOR_INDEX);
    assert_eq!(
        message.data, expected,
        "submitted data must equal the signed data field-for-field, including both bools"
    );
    assert_eq!(
        serde_json::to_vec(&message.data).expect("data json"),
        serde_json::to_vec(&expected).expect("expected json"),
        "submitted data must be byte-identical to the signed PayloadAttestationData"
    );
    assert!(message.data.payload_present);
    assert!(!message.data.blob_data_available);

    let sig = Signature::from_bytes(&message.signature).expect("96-byte BLS signature");
    let schedule = gloas_schedule();
    let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: GVR };
    let ptc_root = signing_root_for(&DutyRef::PtcAttestation(&message.data), &ctx);
    assert!(
        sig.verify(&pubkey, &ptc_root).is_ok(),
        "payload attestation must verify under DOMAIN_PTC_ATTESTER"
    );
    let attester_domain = compute_domain(DOMAIN_BEACON_ATTESTER, schedule.gloas_fork_version, GVR);
    let attester_root = compute_signing_root(&message.data, attester_domain);
    assert!(
        sig.verify(&pubkey, &attester_root).is_err(),
        "must not have signed under DOMAIN_BEACON_ATTESTER"
    );
    assert_eq!(DOMAIN_PTC_ATTESTER, [0x0C, 0x00, 0x00, 0x00]);

    let rows_after = slashing_row_count(&slashing_db, &pubkey_hex_plain);
    assert_eq!(rows_after, rows_before, "PTC must not write a slashing DB row");
}
