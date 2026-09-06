//! ARCH-3j: bounded cold-cache pre-proposal proposer fetch (C6).

use super::*;
use crate::metrics::{
    pre_proposal_cold_fetch, RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS,
    RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL,
};
use beacon::{DependentRootResponse, ExecutionOptimisticResponse, ProposerDuty};
use block_service::{BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse};
use bn_manager::MockBeaconNodeClient;
use eth_types::{SignedBeaconBlock, SignedBlindedBeaconBlock};
use parking_lot::Mutex as ParkingMutex;
use std::time::Instant;
use timing::SLOTS_PER_EPOCH;
use tokio::sync::watch;
use tracing_test::traced_test;
use validator_store::{BlockSelectionMode, ValidatorConfig};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ZERO_DEPENDENT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const PARENT_HEX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const GET_PROPOSER_DUTIES: &str = "get_proposer_duties";
const PRODUCE_BLOCK: &str = "produceBlock";

type CallLog = Arc<ParkingMutex<Vec<&'static str>>>;

fn cold_fetch_count(outcome: &str) -> u64 {
    RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL.with_label_values(&[outcome]).get()
}

fn cold_fetch_duration_count(outcome: &str) -> u64 {
    RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS.with_label_values(&[outcome]).get_sample_count()
}

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
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
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

struct ColdParts {
    orchestrator: DutyOrchestrator<MockSlotClock, MockSubmitter, RecordingBlockBeacon>,
    handle: OrchestratorHandle,
    clock: Arc<MockSlotClock>,
    block_beacon: Arc<RecordingBlockBeacon>,
    log: CallLog,
    key_gen_tx: watch::Sender<u64>,
}

struct MockBuildOpts {
    slot: Slot,
    extra_slots: Vec<Slot>,
    seed_proposer: bool,
}

fn empty_proposer() -> DependentRootResponse<Vec<ProposerDuty>> {
    DependentRootResponse {
        dependent_root: ZERO_DEPENDENT.to_string(),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

async fn build_mock_parts(opts: MockBuildOpts) -> ColdParts {
    let slot = opts.slot;
    let epoch = slot / SLOTS_PER_EPOCH;
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let log: CallLog = Arc::new(ParkingMutex::new(Vec::new()));

    let mut duty_slots = vec![slot];
    duty_slots.extend(opts.extra_slots.iter().copied());
    let proposer_hex = pubkey_hex.clone();
    let proposer_log = log.clone();
    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_slot_aware_block_root(slot, &[], |_| PARENT_HEX.to_string())
            .with_get_proposer_duties(move |e| {
                proposer_log.lock().push(GET_PROPOSER_DUTIES);
                if e == epoch {
                    Ok(DependentRootResponse {
                        dependent_root: ZERO_DEPENDENT.to_string(),
                        execution_optimistic: false,
                        data: duty_slots
                            .iter()
                            .map(|s| ProposerDuty {
                                pubkey: proposer_hex.clone(),
                                validator_index: "1".to_string(),
                                slot: s.to_string(),
                            })
                            .collect(),
                    })
                } else {
                    Ok(empty_proposer())
                }
            })
            .with_get_attester_duties(|_e, _i| {
                Ok(DependentRootResponse {
                    dependent_root: ZERO_DEPENDENT.to_string(),
                    execution_optimistic: false,
                    data: Vec::new(),
                })
            })
            .with_post_sync_committee_duties(|_e, _i| {
                Ok(ExecutionOptimisticResponse { execution_optimistic: false, data: Vec::new() })
            })
            .with_prepare_beacon_proposer(|_p| Ok(()))
            .with_submit_beacon_committee_subscriptions(|_s| Ok(())),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    if opts.seed_proposer {
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();
    }

    finish_parts(slot, secret_key, pubkey, log, beacon, duty_tracker).await
}

async fn finish_parts<B>(
    slot: Slot,
    secret_key: SecretKey,
    pubkey: PublicKey,
    log: CallLog,
    beacon: Arc<B>,
    duty_tracker: Arc<DutyTracker>,
) -> ColdParts
where
    B: BeaconNodeClient + 'static,
{
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
    // Past 2/3; 1 s remains until the next slot so multi-slot drives stay short.
    clock.advance_time(11);

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        attesting_enabled: Arc::new(AtomicBool::new(false)),
        ..OrchestratorDeps::for_test(
            clock.clone(),
            duty_tracker,
            signer,
            propagator,
            beacon.clone(),
            block_beacon.clone(),
            None,
            validator_store,
            create_test_config().with_timeouts(fast_timeouts()),
            pubkey_map,
        )
    });

    ColdParts { orchestrator, handle, clock, block_beacon, log, key_gen_tx }
}

async fn wait_until(cond: impl Fn() -> bool, budget: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while !cond() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

async fn mount_http_proposal_path(
    mock_server: &MockServer,
    epoch: u64,
    slot: Slot,
    pubkey_hex: &str,
    proposer_delay: Duration,
) {
    let empty = serde_json::json!({
        "dependent_root": ZERO_DEPENDENT,
        "execution_optimistic": false,
        "data": []
    });
    let proposer = serde_json::json!({
        "dependent_root": ZERO_DEPENDENT,
        "execution_optimistic": false,
        "data": [{
            "pubkey": pubkey_hex,
            "validator_index": "1",
            "slot": slot.to_string()
        }]
    });

    let mut proposer_tmpl = ResponseTemplate::new(200).set_body_json(&proposer);
    if !proposer_delay.is_zero() {
        proposer_tmpl = proposer_tmpl.set_delay(proposer_delay);
    }
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{epoch}")))
        .respond_with(proposer_tmpl)
        .mount(mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch + 1)))
        .respond_with(ResponseTemplate::new(200).set_body_json(&empty))
        .mount(mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&empty))
        .mount(mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/sync/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&empty))
        .mount(mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/beacon/blocks/.*/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "data": { "root": PARENT_HEX }
        })))
        .mount(mock_server)
        .await;
}

async fn build_http_parts(
    mock_server: &MockServer,
    slot: Slot,
    proposer_delay: Duration,
) -> ColdParts {
    let epoch = slot / SLOTS_PER_EPOCH;
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    mount_http_proposal_path(mock_server, epoch, slot, &pubkey_hex, proposer_delay).await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(30))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    let log: CallLog = Arc::new(ParkingMutex::new(Vec::new()));
    finish_parts(slot, secret_key, pubkey, log, beacon, duty_tracker).await
}

/// Empty duty cache, BN serving proposer duties with 100 ms latency; the
/// block must still be proposed (C6 — never silently skip).
#[tokio::test(flavor = "current_thread")]
#[traced_test]
async fn test_cold_cache_slot_still_proposes_when_a_duty_exists() {
    let _guard = m2_metric_lock().await;
    let mock_server = MockServer::start().await;
    let parts = build_http_parts(&mock_server, 65, Duration::from_millis(100)).await;
    let published = parts.block_beacon.published.clone();
    let hit_before = cold_fetch_count(pre_proposal_cold_fetch::HIT);
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    let run = tokio::spawn(async move { orchestrator.run().await });
    // Test-local publish, not the process-wide M2 histogram (F1).
    let proposed =
        wait_until(|| published.load(Ordering::SeqCst) > 0, Duration::from_millis(800)).await;
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(200), run).await;

    assert!(proposed, "cold cache must fetch proposer duties and propose on the first slot pass");
    assert!(
        cold_fetch_count(pre_proposal_cold_fetch::HIT) > hit_before,
        "successful cold fetch that finds a duty must count outcome=hit"
    );
    assert!(
        logs_contain("Pre-proposal cold-cache proposer fetch"),
        "cold fetch must emit its own log line"
    );
}

/// A `key_gen` bump is not a boot flag: the very next slot must still propose.
#[tokio::test(flavor = "current_thread")]
async fn test_slot_after_key_gen_bump_still_proposes() {
    let _guard = m2_metric_lock().await;
    let parts =
        build_mock_parts(MockBuildOpts { slot: 65, extra_slots: vec![66], seed_proposer: true })
            .await;
    let published = parts.block_beacon.published.clone();
    let clock = parts.clock.clone();
    let key_gen_tx = parts.key_gen_tx;
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    orchestrator.apply_key_gen_cache_invalidation().await;
    let hit_before = cold_fetch_count(pre_proposal_cold_fetch::HIT);

    let run = tokio::spawn(async move { orchestrator.run().await });
    assert!(
        wait_until(|| published.load(Ordering::SeqCst) >= 1, Duration::from_secs(2)).await,
        "warm first slot must propose from the seeded cache"
    );
    assert_eq!(
        cold_fetch_count(pre_proposal_cold_fetch::HIT),
        hit_before,
        "warm first slot must not take the cold-fetch path"
    );

    key_gen_tx.send_modify(|g| *g += 1);
    clock.set_slot(66);
    clock.advance_time(11);

    let second = wait_until(
        || {
            published.load(Ordering::SeqCst) >= 2
                && cold_fetch_count(pre_proposal_cold_fetch::HIT) > hit_before
        },
        Duration::from_secs(3),
    )
    .await;
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(200), run).await;

    assert!(
        second,
        "the slot after a key_gen cache clear must cold-fetch and propose on that slot's first pass"
    );
    assert!(
        cold_fetch_count(pre_proposal_cold_fetch::HIT) > hit_before,
        "post-key_gen slot must count outcome=hit"
    );
}

/// BN latency 5 s: give up at the named 500 ms deadline, count timeout, and
/// still reach `maybe_propose_block`.
#[tokio::test(flavor = "current_thread")]
#[traced_test]
async fn test_cold_fetch_gives_up_at_the_bounded_deadline() {
    let _guard = m2_metric_lock().await;
    let mock_server = MockServer::start().await;
    let parts = build_http_parts(&mock_server, 65, Duration::from_secs(5)).await;
    let produce_calls = parts.block_beacon.produce_calls.clone();
    let timeout_before = cold_fetch_count(pre_proposal_cold_fetch::TIMEOUT);
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    let started = Instant::now();
    let run = tokio::spawn(async move { orchestrator.run().await });
    // Timeout counter is C6-only; do not wait on the process-wide M2 histogram.
    let reached = wait_until(
        || cold_fetch_count(pre_proposal_cold_fetch::TIMEOUT) > timeout_before,
        COLD_PROPOSER_FETCH_DEADLINE + Duration::from_millis(400),
    )
    .await;
    let elapsed = started.elapsed();
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(200), run).await;

    assert!(reached, "pre-proposal path must give up at the cold-fetch deadline and still proceed");
    assert!(
        elapsed < COLD_PROPOSER_FETCH_DEADLINE + Duration::from_millis(400),
        "cold fetch must give up at ~{}ms, took {elapsed:?}",
        COLD_PROPOSER_FETCH_DEADLINE.as_millis()
    );
    assert!(
        elapsed < DEFAULT_PRE_PROPOSAL_DEADLINE,
        "cold fetch must stay inside the aggregate pre-proposal budget"
    );
    assert!(
        cold_fetch_count(pre_proposal_cold_fetch::TIMEOUT) > timeout_before,
        "timeout counter must increment when the 500 ms deadline fires"
    );
    assert_eq!(
        produce_calls.load(Ordering::SeqCst),
        0,
        "a timed-out fetch leaves no duty, so produce is not entered"
    );
    assert!(
        logs_contain("Pre-proposal cold-cache proposer fetch timed out"),
        "timeout must emit the distinct cold-fetch log line"
    );
}

/// Warm cache: zero BN proposer-duty calls before produce (A-3.10).
#[tokio::test(flavor = "current_thread")]
async fn test_warm_cache_slot_issues_no_pre_proposal_duty_fetch() {
    let _guard = m2_metric_lock().await;
    let parts =
        build_mock_parts(MockBuildOpts { slot: 65, extra_slots: Vec::new(), seed_proposer: true })
            .await;
    let log = parts.log.clone();
    let published = parts.block_beacon.published.clone();
    let duration_before = cold_fetch_duration_count(pre_proposal_cold_fetch::HIT)
        + cold_fetch_duration_count(pre_proposal_cold_fetch::MISS)
        + cold_fetch_duration_count(pre_proposal_cold_fetch::TIMEOUT);
    let handle = parts.handle;
    let mut orchestrator = parts.orchestrator;

    log.lock().clear();

    let run = tokio::spawn(async move { orchestrator.run().await });
    let proposed =
        wait_until(|| published.load(Ordering::SeqCst) > 0, Duration::from_secs(2)).await;
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(200), run).await;

    assert!(proposed, "warm cache must still propose");
    let recorded = log.lock().clone();
    let produce_at = recorded
        .iter()
        .position(|n| *n == PRODUCE_BLOCK)
        .expect("produceBlock must run on a warm proposer duty");
    let proposer_before_produce =
        recorded[..produce_at].iter().filter(|n| **n == GET_PROPOSER_DUTIES).count();
    assert_eq!(
        proposer_before_produce, 0,
        "warm slot must issue no pre-proposal proposer-duty fetch; order={recorded:?}"
    );
    let duration_after = cold_fetch_duration_count(pre_proposal_cold_fetch::HIT)
        + cold_fetch_duration_count(pre_proposal_cold_fetch::MISS)
        + cold_fetch_duration_count(pre_proposal_cold_fetch::TIMEOUT);
    assert_eq!(
        duration_after, duration_before,
        "warm slot must not record a cold-fetch duration sample"
    );
}
