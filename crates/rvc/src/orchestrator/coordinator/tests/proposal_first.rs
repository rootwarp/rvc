//! ARCH-3i: proposal-first slot ordering.

use super::*;
use beacon::{
    AttestationData, AttesterDuty, Checkpoint, DependentRootResponse, ExecutionOptimisticResponse,
    ProposerDuty,
};
use block_service::{BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse};
use bn_manager::MockBeaconNodeClient;
use eth_types::{SignedBeaconBlock, SignedBlindedBeaconBlock, SyncCommitteeDuty};
use parking_lot::Mutex as ParkingMutex;
use timing::SLOTS_PER_EPOCH;
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;
use validator_store::{BlockSelectionMode, ValidatorConfig};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ZERO_DEPENDENT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const PARENT_HEX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// BN / produce call names recorded for ordering assertions.
const PRODUCE_BLOCK: &str = "produceBlock";
const GET_ATTESTER_DUTIES: &str = "get_attester_duties";

type CallLog = Arc<ParkingMutex<Vec<&'static str>>>;

struct RecordingBlockBeacon {
    validator_index: u64,
    log: CallLog,
    produce_calls: Arc<AtomicUsize>,
    published: Arc<AtomicUsize>,
}

impl RecordingBlockBeacon {
    fn new(validator_index: u64, log: CallLog) -> Self {
        Self {
            validator_index,
            log,
            produce_calls: Arc::new(AtomicUsize::new(0)),
            published: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl BeaconBlockClient for RecordingBlockBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.log.lock().push(PRODUCE_BLOCK);
        self.produce_calls.fetch_add(1, Ordering::SeqCst);
        let mut block = eth_types::external_vector_deneb_block();
        block.slot = slot;
        block.proposer_index = self.validator_index;
        Ok(ProduceBlockResponse {
            data: serde_json::to_value(&block)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("0".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        })
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        Err(BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &SignedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn empty_proposer() -> DependentRootResponse<Vec<ProposerDuty>> {
    DependentRootResponse {
        dependent_root: ZERO_DEPENDENT.to_string(),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

struct ProposalFirstParts {
    orchestrator: DutyOrchestrator<MockSlotClock, MockSubmitter, RecordingBlockBeacon>,
    handle: OrchestratorHandle,
    beacon: Arc<MockBeaconNodeClient>,
    block_beacon: Arc<RecordingBlockBeacon>,
    log: CallLog,
}

struct ProposalFirstOpts {
    slot: Slot,
    seed_proposer: bool,
    seed_attester: bool,
    seed_sync: bool,
}

fn hex_root(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "128".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: slot.to_string(),
    }
}

async fn build_proposal_first(opts: ProposalFirstOpts) -> ProposalFirstParts {
    let slot = opts.slot;
    let epoch = slot / SLOTS_PER_EPOCH;
    let seed_attester = opts.seed_attester;

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let log: CallLog = Arc::new(ParkingMutex::new(Vec::new()));

    let attester_log = log.clone();
    let attester_body = attester_duty(&pubkey_hex, slot);
    let proposer_hex = pubkey_hex.clone();
    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_slot_aware_block_root(slot, &[], |_| PARENT_HEX.to_string())
            .with_get_attester_duties(move |_epoch, _indices| {
                attester_log.lock().push(GET_ATTESTER_DUTIES);
                Ok(DependentRootResponse {
                    dependent_root: ZERO_DEPENDENT.to_string(),
                    execution_optimistic: false,
                    data: if seed_attester { vec![attester_body.clone()] } else { Vec::new() },
                })
            })
            .with_get_proposer_duties(move |e| {
                if e == epoch {
                    Ok(DependentRootResponse {
                        dependent_root: ZERO_DEPENDENT.to_string(),
                        execution_optimistic: false,
                        data: vec![ProposerDuty {
                            pubkey: proposer_hex.clone(),
                            validator_index: "1".to_string(),
                            slot: slot.to_string(),
                        }],
                    })
                } else {
                    Ok(empty_proposer())
                }
            })
            .with_post_sync_committee_duties({
                let duty_pk = pubkey.to_bytes();
                move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                }
            })
            .with_get_attestation_data(move |_, _| {
                Ok(beacon::DataResponse {
                    data: AttestationData {
                        slot: slot.to_string(),
                        index: "0".to_string(),
                        beacon_block_root: hex_root(0x11),
                        source: Checkpoint { epoch: "1".to_string(), root: hex_root(0x22) },
                        target: Checkpoint { epoch: "2".to_string(), root: hex_root(0x33) },
                    },
                })
            })
            .with_prepare_beacon_proposer(|_p| Ok(()))
            .with_submit_beacon_committee_subscriptions(|_s| Ok(()))
            .with_submit_sync_committee_messages(|_m| Ok(()))
            .with_submit_contribution_and_proofs(|_p| Ok(())),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));

    if opts.seed_proposer {
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();
    }
    if seed_attester {
        duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    }
    if opts.seed_sync {
        duty_tracker.fetch_sync_committee_duties(epoch).await.unwrap();
    }

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let block_beacon = Arc::new(RecordingBlockBeacon::new(1, log.clone()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);
    clock.advance_time(9);

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon.clone(),
        block_beacon.clone(),
        None,
        validator_store,
        create_test_config().with_timeouts(fast_timeouts()),
        pubkey_map,
    ));

    ProposalFirstParts { orchestrator, handle, beacon, block_beacon, log }
}

fn first_index(log: &[&'static str], name: &str) -> Option<usize> {
    log.iter().position(|n| *n == name)
}

/// Span names in creation order.
struct SpanNames {
    names: Arc<ParkingMutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanNames {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.names.lock().push(attrs.metadata().name().to_string());
    }
}

/// `produceBlock` must be entered before the first `get_attester_duties`.
///
/// RED at HEAD: `fetch_epoch_duties` runs unconditionally before
/// `maybe_propose_block`.
#[tokio::test(flavor = "current_thread")]
async fn test_proposal_is_attempted_before_any_epoch_duty_fetch() {
    let parts = build_proposal_first(ProposalFirstOpts {
        slot: 65,
        seed_proposer: true,
        seed_attester: false,
        seed_sync: true,
    })
    .await;
    let log = parts.log.clone();
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        handle.shutdown();
    });
    let _ = orchestrator.run().await;

    let recorded = log.lock().clone();
    let produce_at = first_index(&recorded, PRODUCE_BLOCK)
        .expect("produceBlock-path must be entered when a proposer duty is cached");
    let attester_at = first_index(&recorded, GET_ATTESTER_DUTIES)
        .expect("get_attester_duties must still run (moved to the post-duty window)");
    assert!(
        produce_at < attester_at,
        "produceBlock must precede the first get_attester_duties; order={recorded:?}"
    );
}

/// A stalled epoch duty fetch must not block proposal (single-fetch proof).
///
/// RED at HEAD: the first `fetch_epoch_duties` waits out the stall before
/// `maybe_propose_block`.
#[tokio::test(flavor = "current_thread")]
async fn test_proposal_still_happens_when_duty_fetches_stall() {
    use wiremock::matchers::path;

    let slot = 65u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    let mock_server = MockServer::start().await;

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let log: CallLog = Arc::new(ParkingMutex::new(Vec::new()));

    let empty_duties = serde_json::json!({
        "dependent_root": ZERO_DEPENDENT,
        "execution_optimistic": false,
        "data": []
    });
    let proposer_body = serde_json::json!({
        "dependent_root": ZERO_DEPENDENT,
        "execution_optimistic": false,
        "data": [{
            "pubkey": pubkey_hex,
            "validator_index": "1",
            "slot": slot.to_string()
        }]
    });

    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{epoch}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&proposer_body))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&empty_duties)
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/sync/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&empty_duties))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/beacon/blocks/.*/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "data": { "root": PARENT_HEX }
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(60))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let block_beacon = Arc::new(RecordingBlockBeacon::new(1, log));
    let produce_calls = block_beacon.produce_calls.clone();
    let published = block_beacon.published.clone();
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);
    clock.advance_time(9);

    let timeouts = OperationTimeouts { duty_fetch: Duration::from_secs(10), ..fast_timeouts() };
    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        validator_store,
        create_test_config().with_timeouts(timeouts),
        pubkey_map,
    ));

    let run = tokio::spawn(async move { orchestrator.run().await });
    let produced = tokio::time::timeout(Duration::from_millis(400), async {
        loop {
            if produce_calls.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(200), run).await;

    assert!(produced.is_ok(), "maybe_propose_block must be entered while duty fetches are stalled");
    assert!(
        published.load(Ordering::SeqCst) > 0,
        "a block must be produced (produce+publish) despite stalled duty fetches"
    );
}

/// Epoch-boundary prep runs after phase 3, only on boundary slots.
///
/// RED at HEAD: `on_epoch_boundary` (span `epoch.boundary`) is entered before
/// `slot.phase.block` / `slot.phase.aggregation`.
#[tokio::test(flavor = "current_thread")]
async fn test_epoch_boundary_prep_runs_in_the_post_duty_window() {
    async fn drive(slot: Slot) -> Vec<String> {
        let parts = build_proposal_first(ProposalFirstOpts {
            slot,
            seed_proposer: true,
            seed_attester: false,
            seed_sync: true,
        })
        .await;
        let handle = parts.handle;
        let mut orchestrator = parts.orchestrator;

        let captured = Arc::new(ParkingMutex::new(Vec::new()));
        let layer = SpanNames { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(800)).await;
            handle.shutdown();
        });
        let _ = orchestrator.run().await;
        let names = captured.lock().clone();
        names
    }

    let boundary = drive(64).await;
    let aggregation_at = boundary
        .iter()
        .position(|n| n == "slot.phase.aggregation")
        .expect("phase 3 span must exist");
    let epoch_at = boundary
        .iter()
        .position(|n| n == "epoch.boundary")
        .expect("epoch-boundary prep must still run on a boundary slot");
    assert!(
        epoch_at > aggregation_at,
        "on_epoch_boundary must run after phase 3; spans={boundary:?}"
    );

    let mid_epoch = drive(65).await;
    assert!(
        !mid_epoch.iter().any(|n| n == "epoch.boundary"),
        "epoch-boundary prep must not run on a non-boundary slot; spans={mid_epoch:?}"
    );
}

/// Which duties run is unchanged by the reorder — only when they run.
#[tokio::test(flavor = "current_thread")]
async fn test_duties_performed_are_unchanged_by_the_reorder() {
    let parts = build_proposal_first(ProposalFirstOpts {
        slot: 65,
        seed_proposer: true,
        seed_attester: true,
        seed_sync: true,
    })
    .await;
    let produce_calls = parts.block_beacon.produce_calls.clone();
    let beacon = parts.beacon.clone();
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        handle.shutdown();
    });
    let _ = orchestrator.run().await;

    let mut performed = std::collections::BTreeSet::new();
    if produce_calls.load(Ordering::SeqCst) > 0 {
        performed.insert("proposal");
    }
    if !beacon.get_attestation_data_calls().is_empty() {
        performed.insert("attestation");
    }
    if !beacon.submit_sync_committee_messages_calls().is_empty() {
        performed.insert("sync_message");
    }

    assert_eq!(
        performed,
        ["attestation", "proposal", "sync_message"].into_iter().collect(),
        "the reorder must not change which duties are performed"
    );
}
