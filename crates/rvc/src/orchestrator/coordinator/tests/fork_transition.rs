//! Coordinator tests: fork transition.

use super::*;

#[test]
fn test_fork_name_electra_detection() {
    let schedule = create_test_fork_schedule();
    // electra_fork_epoch = 50

    // Pre-Electra (Deneb)
    let fork_name = ForkName::from_epoch(49, &schedule);
    assert!(!utils::zeroes_committee_index(fork_name));

    // Electra boundary
    let fork_name = ForkName::from_epoch(50, &schedule);
    assert!(utils::zeroes_committee_index(fork_name));

    // Post-Electra: 69 is last Fulu / last EIP-7549 zeroing epoch (Gloas at 70).
    let fork_name = ForkName::from_epoch(69, &schedule);
    assert!(utils::zeroes_committee_index(fork_name));
}

#[test]
fn test_fork_name_gloas_detection() {
    let schedule = create_test_fork_schedule();
    assert_eq!(ForkName::from_epoch(69, &schedule), ForkName::Fulu);
    assert_eq!(ForkName::from_epoch(70, &schedule), ForkName::Gloas);
}

/// Builds an orchestrator with a CapturingSubmitter for fork transition tests.
/// Returns the orchestrator, handle, pubkey hex, and a reference to the capturing submitter.
async fn build_fork_transition_orchestrator(
    mock_server_uri: &str,
    slot: u64,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    String,
    Arc<CapturingSubmitter>,
) {
    build_fork_transition_orchestrator_with_schedule(
        mock_server_uri,
        slot,
        create_test_fork_schedule(),
    )
    .await
}

async fn build_fork_transition_orchestrator_with_schedule(
    mock_server_uri: &str,
    slot: u64,
    schedule: Arc<ForkSchedule>,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    String,
    Arc<CapturingSubmitter>,
) {
    // Existing 7.1–7.4 callers keep `builder_service: None`.
    build_fork_transition_orchestrator_with(mock_server_uri, slot, schedule, false).await
}

async fn build_fork_transition_orchestrator_with_builder(
    mock_server_uri: &str,
    slot: u64,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    String,
    Arc<CapturingSubmitter>,
) {
    build_fork_transition_orchestrator_with(
        mock_server_uri,
        slot,
        create_test_fork_schedule(),
        true,
    )
    .await
}

async fn build_fork_transition_orchestrator_with(
    mock_server_uri: &str,
    slot: u64,
    schedule: Arc<ForkSchedule>,
    attach_builder: bool,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    String,
    Arc<CapturingSubmitter>,
) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let beacon_config = BeaconClientConfig::new(mock_server_uri);
    let beacon: Arc<dyn BeaconNodeClient> = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let secret_key = SecretKey::generate();
    let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

    let duty_tracker = {
        let tracker = DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]);
        // Production pins the reconciled schedule (v1 pre-Gloas, v2 at Gloas).
        Arc::new(if attach_builder {
            tracker.with_fork_schedule((*schedule).clone())
        } else {
            tracker
        })
    };

    let pubkey = secret_key.public_key();
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let capturing_submitter = Arc::new(CapturingSubmitter::new());
    let propagator = Arc::new(Propagator::new(capturing_submitter.clone()));

    let config = OrchestratorConfig::new([0xaa; 32], schedule.clone());
    let pubkey_bytes = pubkey.to_bytes();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits its duties (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    let mut validator_cfg = validator_store::ValidatorConfig::new(pubkey_bytes);
    if attach_builder {
        validator_cfg.builder_proposals = true;
    }
    validator_store.add_validator(validator_cfg).unwrap();

    let builder_service: Option<Arc<BuilderService>> = attach_builder.then(|| {
        let vs: Arc<dyn ValidatorSigner> = signer.clone();
        Arc::new(BuilderService::new(
            Arc::new(vs),
            Arc::new(beacon.clone()),
            validator_store.clone(),
            schedule.genesis_fork_version,
            schedule,
        ))
    });

    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        builder_service,
        validator_store,
        config,
        pubkey_map,
    );
    if attach_builder {
        deps.pubkey_index.write().insert(pubkey_bytes, PROPOSER_INDEX.to_string());
    }
    let (orchestrator, handle) = DutyOrchestrator::new(deps);

    (orchestrator, handle, pubkey_hex, capturing_submitter)
}

/// Mounts attestation data and attester duties on the mock server for a given slot.
async fn mount_attestation_mocks(mock_server: &wiremock::MockServer, slot: u64, pubkey_hex: &str) {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, ResponseTemplate};

    let epoch = slot / SLOTS_PER_EPOCH;

    // Mock attester duties — small committee (always aggregator)
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "3",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "2",
                "slot": slot.to_string()
            }]
        })))
        .mount(mock_server)
        .await;

    // Mock attestation data
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "3",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch.saturating_sub(1)).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(mock_server)
        .await;
}

/// Mounts Gloas PTC HTTP endpoints on the mock server for a given slot.
async fn mount_gloas_mocks(mock_server: &wiremock::MockServer, slot: u64, pubkey_hex: &str) {
    mount_gloas_mocks_with_payload_data(mock_server, slot, pubkey_hex, true).await;
}

/// Same as [`mount_gloas_mocks`], optionally serving HTTP 204 for payload data.
async fn mount_gloas_mocks_with_payload_data(
    mock_server: &wiremock::MockServer,
    slot: u64,
    pubkey_hex: &str,
    payload_data_available: bool,
) {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};

    let epoch = slot / SLOTS_PER_EPOCH;

    Mock::given(method("POST"))
        .and(path(format!("/eth/v1/validator/duties/ptc/{epoch}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "slot": slot.to_string()
            }]
        })))
        .mount(mock_server)
        .await;

    let data_response = if payload_data_available {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "slot": slot.to_string(),
                "payload_present": true,
                "blob_data_available": false
            }
        }))
    } else {
        ResponseTemplate::new(204)
    };
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(data_response)
        .mount(mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock_server)
        .await;
}

fn request_paths(requests: &[wiremock::Request]) -> Vec<String> {
    requests.iter().map(|r| format!("{} {}", r.method, r.url.path())).collect()
}

fn hit_ptc_duty(requests: &[wiremock::Request], epoch: u64) -> bool {
    requests.iter().any(|r| {
        r.method == wiremock::http::Method::POST
            && r.url.path() == format!("/eth/v1/validator/duties/ptc/{epoch}")
    })
}

fn hit_payload_attestation_data(requests: &[wiremock::Request]) -> bool {
    requests.iter().any(|r| {
        r.method == wiremock::http::Method::GET
            && r.url.path() == "/eth/v1/validator/payload_attestation_data"
    })
}

fn hit_payload_attestation_pool(requests: &[wiremock::Request]) -> bool {
    requests.iter().any(|r| {
        r.method == wiremock::http::Method::POST
            && r.url.path() == "/eth/v1/beacon/pool/payload_attestations"
    })
}

fn ptc_duty_request_count(requests: &[wiremock::Request], epoch: u64) -> usize {
    requests
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path() == format!("/eth/v1/validator/duties/ptc/{epoch}")
        })
        .count()
}

fn payload_attestation_pool_messages(requests: &[wiremock::Request]) -> Vec<serde_json::Value> {
    requests
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path() == "/eth/v1/beacon/pool/payload_attestations"
        })
        .flat_map(|r| {
            serde_json::from_slice::<Vec<serde_json::Value>>(&r.body).unwrap_or_else(|e| {
                panic!("pool/payload_attestations body must be a JSON array: {e}")
            })
        })
        .collect()
}

fn slashing_row_count(db: &SlashingDb, pubkey_hex: &str) -> usize {
    let pubkey = pubkey_hex.trim_start_matches("0x");
    db.get_attestations(pubkey).expect("attestations").len()
        + db.get_blocks(pubkey).expect("blocks").len()
}

type ForkTransitionOrchestrator =
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>;

fn payload_attestation_due_bps(orchestrator: &ForkTransitionOrchestrator, slot: Slot) -> u64 {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork = ForkName::from_epoch(epoch, &orchestrator.config.fork_schedule);
    orchestrator.config.deadline_schedule.for_fork(fork).payload_attestation
}

fn park_at_due_bps(orchestrator: &ForkTransitionOrchestrator, slot: Slot, bps: u64) {
    use timing::{due_ms, SlotClock};

    let slot_duration_ms = orchestrator.clock.slot_duration().as_millis() as u64;
    let wait = orchestrator.clock.time_until_due(slot, bps).expect("due");
    assert_eq!(
        wait,
        Duration::from_millis(due_ms(bps, slot_duration_ms)),
        "MockSlotClock wait must come from the given bps via due_ms"
    );
    orchestrator.clock.advance_time(wait.as_secs());
    assert!(
        orchestrator.clock.time_until_due(slot, bps).expect("due after park").is_zero(),
        "MockSlotClock must sit at the configured bps deadline"
    );
}

fn park_at_payload_attestation_deadline(orchestrator: &ForkTransitionOrchestrator, slot: Slot) {
    park_at_due_bps(orchestrator, slot, payload_attestation_due_bps(orchestrator, slot));
}

async fn run_until_shutdown(
    orchestrator: &mut ForkTransitionOrchestrator,
    handle: &OrchestratorHandle,
) {
    tokio::select! {
        biased;
        result = orchestrator.run() => {
            result.expect("run() must not error");
        }
        () = async {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }
}

#[tokio::test]
async fn test_run_at_gloas_hits_payload_attestation_endpoints() {
    let mock_server = wiremock::MockServer::start().await;

    // Slot 2240 = epoch 70 = gloas_fork_epoch
    let slot = 2240u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 70, "Slot 2240 should be epoch 70");

    let (mut orchestrator, handle, pubkey_hex, _capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;
    mount_gloas_mocks(&mock_server, slot, &pubkey_hex).await;

    // Park at the Gloas payload-attestation offset so `run()` does not sleep.
    orchestrator.clock.advance_time(9);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let requests = mock_server.received_requests().await.unwrap();
    let paths = request_paths(&requests);

    assert!(
        hit_ptc_duty(&requests, epoch),
        "expected POST /eth/v1/validator/duties/ptc/{epoch} from run(), got {paths:?}"
    );
    assert!(
        hit_payload_attestation_data(&requests),
        "expected GET /eth/v1/validator/payload_attestation_data from run(), got {paths:?}"
    );
    assert!(
        hit_payload_attestation_pool(&requests),
        "expected POST /eth/v1/beacon/pool/payload_attestations from run(), got {paths:?}"
    );
}

/// PTC phase is skipped at epoch 69 (no data GET / pool POST) even though
/// ungated post-duty fetch POSTs duties/ptc/69. At Gloas, PTC waits for the
/// configured bps deadline then submits one pool message per validator
/// without writing a slashing row.
#[tokio::test]
async fn test_ptc_duties_absent_before_gloas_fire_at_configured_bps() {
    use timing::{due_ms, SlotClock};

    // Park at the pre-Gloas aggregate offset so att/agg remaining are zero and
    // post-duty `fetch_epoch_duties` runs. Fetch is ungated; the phase is not.
    let pre_slot = 2208u64;
    let pre_epoch = pre_slot / SLOTS_PER_EPOCH;
    assert_eq!(pre_epoch, 69, "Slot 2208 should be epoch 69");

    let pre_server = wiremock::MockServer::start().await;
    let (mut pre_orch, pre_handle, pre_pubkey, _capturing) =
        build_fork_transition_orchestrator(&pre_server.uri(), pre_slot).await;
    mount_attestation_mocks(&pre_server, pre_slot, &pre_pubkey).await;
    mount_gloas_mocks(&pre_server, pre_slot, &pre_pubkey).await;

    let pre_fork = ForkName::from_epoch(pre_epoch, &pre_orch.config.fork_schedule);
    assert_eq!(pre_fork, ForkName::Fulu);
    let pre_agg_bps = pre_orch.config.deadline_schedule.for_fork(pre_fork).aggregate;
    park_at_due_bps(&pre_orch, pre_slot, pre_agg_bps);

    run_until_shutdown(&mut pre_orch, &pre_handle).await;

    let pre_requests = pre_server.received_requests().await.unwrap();
    let pre_paths = request_paths(&pre_requests);
    assert!(
        ptc_duty_request_count(&pre_requests, pre_epoch) >= 1,
        "ungated fetch_epoch_duties must POST /eth/v1/validator/duties/ptc/{pre_epoch}, got {pre_paths:?}"
    );
    assert!(
        !hit_payload_attestation_data(&pre_requests),
        "pre-Gloas PTC phase skip: no GET payload_attestation_data, got {pre_paths:?}"
    );
    assert!(
        !hit_payload_attestation_pool(&pre_requests),
        "pre-Gloas PTC phase skip: no POST pool/payload_attestations, got {pre_paths:?}"
    );

    // Gloas slot start: MockSlotClock has not reached the configured bps, so
    // the 1s shutdown must interrupt the wait and skip produce.
    let slot = 2240u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 70, "Slot 2240 should be epoch 70");

    let early_server = wiremock::MockServer::start().await;
    let (mut early_orch, early_handle, early_pubkey, _early_capturing) =
        build_fork_transition_orchestrator(&early_server.uri(), slot).await;
    mount_attestation_mocks(&early_server, slot, &early_pubkey).await;
    mount_gloas_mocks(&early_server, slot, &early_pubkey).await;

    let early_bps = payload_attestation_due_bps(&early_orch, slot);
    let slot_duration_ms = early_orch.clock.slot_duration().as_millis() as u64;
    let early_wait = early_orch.clock.time_until_due(slot, early_bps).expect("gloas due");
    assert_eq!(
        early_wait,
        Duration::from_millis(due_ms(early_bps, slot_duration_ms)),
        "Gloas slot-start wait must equal config payload_attestation bps via due_ms"
    );
    assert!(
        !early_wait.is_zero(),
        "Gloas slot start must be before payload_attestation bps={early_bps}"
    );

    run_until_shutdown(&mut early_orch, &early_handle).await;

    let early_requests = early_server.received_requests().await.unwrap();
    let early_paths = request_paths(&early_requests);
    assert!(
        payload_attestation_pool_messages(&early_requests).is_empty(),
        "PTC must not submit before the configured bps deadline, got {early_paths:?}"
    );

    // Park MockSlotClock at the config/bps deadline, then run().
    let mock_server = wiremock::MockServer::start().await;
    let (mut orchestrator, handle, pubkey_hex, _capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;
    mount_gloas_mocks(&mock_server, slot, &pubkey_hex).await;

    // Attesting off so the slashing snapshot is PTC-only; coexistence with
    // attestation is the 204 test.
    orchestrator.attesting_enabled.store(false, Ordering::Relaxed);
    orchestrator.set_sync_enabled(false);

    let rows_before =
        slashing_row_count(orchestrator.payload_attestation_service.slashing_db(), &pubkey_hex);
    park_at_payload_attestation_deadline(&orchestrator, slot);
    run_until_shutdown(&mut orchestrator, &handle).await;
    let rows_after =
        slashing_row_count(orchestrator.payload_attestation_service.slashing_db(), &pubkey_hex);

    let requests = mock_server.received_requests().await.unwrap();
    let paths = request_paths(&requests);
    assert!(
        ptc_duty_request_count(&requests, epoch) >= 1,
        "expected ≥ 1 POST /eth/v1/validator/duties/ptc/{epoch} at Gloas, got {paths:?}"
    );
    let messages = payload_attestation_pool_messages(&requests);
    assert_eq!(
        messages.len(),
        1,
        "exactly one pool/payload_attestations message per assigned validator, got {messages:?}"
    );
    assert_eq!(
        rows_after, rows_before,
        "PTC must not write a slashing DB row (before={rows_before} after={rows_after})"
    );
}

/// HTTP 204 from payload_attestation_data skips PTC with no fallback; the
/// attestation duty for the same Gloas slot still succeeds.
#[tokio::test]
async fn test_payload_attestation_204_skips_submission_attestation_still_succeeds() {
    let slot = 2240u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 70, "Slot 2240 should be epoch 70");

    let mock_server = wiremock::MockServer::start().await;
    let (mut orchestrator, handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;
    mount_gloas_mocks_with_payload_data(&mock_server, slot, &pubkey_hex, false).await;

    park_at_payload_attestation_deadline(&orchestrator, slot);
    run_until_shutdown(&mut orchestrator, &handle).await;

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1, "attestation duty must still submit on PTC 204");
    match &captured[0] {
        VersionedAttestation::Gloas(atts) => {
            assert_eq!(atts.len(), 1, "one Gloas attestation");
        }
        other => panic!(
            "expected Gloas attestation after PTC 204, got {:?}",
            std::mem::discriminant(other)
        ),
    }

    let requests = mock_server.received_requests().await.unwrap();
    let paths = request_paths(&requests);
    assert!(
        hit_payload_attestation_data(&requests),
        "204 path must still GET payload_attestation_data, got {paths:?}"
    );
    assert!(
        payload_attestation_pool_messages(&requests).is_empty(),
        "204 must not POST pool/payload_attestations (no fallback), got {paths:?}"
    );
}

#[tokio::test]
async fn test_pre_electra_attestation_produces_legacy_format() {
    let mock_server = wiremock::MockServer::start().await;

    // Slot 96 = epoch 3, well before electra_fork_epoch=50
    let slot = 96u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    // Fetch duties so they're cached
    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // Process the slot
    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    // Verify the captured attestation is PreElectra
    let captured = capturing.captured();
    assert_eq!(captured.len(), 1, "Expected exactly one submission");

    match &captured[0] {
        VersionedAttestation::PreElectra(attestations) => {
            assert_eq!(attestations.len(), 1);
            let att = &attestations[0];
            // aggregation_bits should be set (not empty)
            assert!(!att.aggregation_bits.is_empty());
            // data.index should be the committee index from the duty ("3")
            assert_eq!(att.data.index, "3");
        }
        VersionedAttestation::Electra(_)
        | VersionedAttestation::Fulu(_)
        | VersionedAttestation::Gloas(_) => {
            panic!("Expected PreElectra attestation for slot in epoch 3 (< electra_fork_epoch=50)");
        }
    }
}

#[tokio::test]
async fn test_electra_attestation_produces_single_attestation_format() {
    let mock_server = wiremock::MockServer::start().await;

    // Slot 1600 = epoch 50 = electra_fork_epoch, first Electra slot
    let slot = 1600u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 50, "Slot 1600 should be epoch 50");

    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::Electra(attestations) => {
            assert_eq!(attestations.len(), 1);
            let att = &attestations[0];
            // EIP-7549: data.index must be "0" in Electra
            assert_eq!(att.data.index, "0", "Electra attestation data.index must be 0 (EIP-7549)");
            // committee_index carries the original committee index
            assert_eq!(
                att.committee_index, 3,
                "committee_index should be the duty committee index"
            );
            // attester_index should be the validator index
            assert_eq!(att.attester_index, 42);
        }
        VersionedAttestation::PreElectra(_)
        | VersionedAttestation::Fulu(_)
        | VersionedAttestation::Gloas(_) => {
            panic!("Expected Electra attestation for slot in epoch 50 (= electra_fork_epoch)");
        }
    }
}

#[tokio::test]
async fn test_fork_boundary_last_pre_electra_slot() {
    let mock_server = wiremock::MockServer::start().await;

    // Slot 1599 = last slot of epoch 49 (pre-Electra)
    let slot = 1599u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 49, "Slot 1599 should be epoch 49");

    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::PreElectra(attestations) => {
            assert_eq!(attestations.len(), 1);
            // Last pre-Electra slot should still use legacy format
            assert!(!attestations[0].aggregation_bits.is_empty());
            assert_eq!(attestations[0].data.index, "3");
        }
        VersionedAttestation::Electra(_)
        | VersionedAttestation::Fulu(_)
        | VersionedAttestation::Gloas(_) => {
            panic!("Expected PreElectra attestation for slot 1599 (epoch 49, last pre-Electra)");
        }
    }
}

#[tokio::test]
async fn test_electra_aggregation_passes_committee_index() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // Slot 1600 = epoch 50 = electra_fork_epoch, small committee → always aggregator
    let slot = 1600u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    let (orchestrator, _handle, pubkey_hex, _capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    // Mock aggregate attestation endpoint — expect committee_index query param for Electra
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .and(query_param("committee_index", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "0",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "committee_bits": "0x0800000000000000"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock aggregate submission (Electra uses v2 endpoint)
    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

    // wiremock expect(1) on aggregate_attestation with committee_index=3
    // confirms Electra path passes the committee_index query parameter
}

#[tokio::test]
async fn test_pre_electra_aggregation_no_committee_index() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // Slot 96 = epoch 3, pre-Electra
    let slot = 96u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    let (orchestrator, _handle, pubkey_hex, _capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    // Pre-Electra: aggregate_attestation WITHOUT committee_index param
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "3",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch.saturating_sub(1)).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

    // Verify pre-Electra requests do NOT contain committee_index query param
    let requests = mock_server.received_requests().await.unwrap();
    let aggregate_requests: Vec<_> = requests
        .iter()
        .filter(|r| {
            r.url.path() == "/eth/v1/validator/aggregate_attestation"
                && r.method == wiremock::http::Method::GET
        })
        .collect();
    assert!(!aggregate_requests.is_empty(), "expected at least one aggregate_attestation request");
    for req in &aggregate_requests {
        let query = req.url.query().unwrap_or("");
        assert!(
            !query.contains("committee_index"),
            "pre-Electra aggregate_attestation must not include committee_index, but got: {query}"
        );
    }
}

#[tokio::test]
async fn test_electra_attestation_data_index_zero_before_signing() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // Post-Electra: epoch 51
    let slot = 1632u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 51);

    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    // BN returns attestation data with index "7" — different from 0
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "99",
                "committee_index": "7",
                "committee_length": "16",
                "committees_at_slot": "8",
                "validator_committee_index": "5",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "7",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::Electra(atts) => {
            // EIP-7549: data.index must be "0" even though BN returned "7"
            assert_eq!(
                atts[0].data.index, "0",
                "EIP-7549: data.index must be zeroed before signing"
            );
            // committee_index preserves the original value
            assert_eq!(atts[0].committee_index, 7);
            assert_eq!(atts[0].attester_index, 99);
        }
        VersionedAttestation::PreElectra(_)
        | VersionedAttestation::Fulu(_)
        | VersionedAttestation::Gloas(_) => {
            panic!("Expected Electra attestation for epoch 51");
        }
    }
}

// --- AT-07: Electra data.index invariant tests ---

#[test]
fn test_electra_crypto_attestation_data_index_zeroed() {
    // Verify that for Electra attestations, crypto_attestation_data.index == 0
    // after applying the EIP-7549 zeroing logic.
    let beacon_data = beacon::AttestationData {
        slot: "1600".to_string(),
        index: "7".to_string(),
        beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        source: beacon::Checkpoint {
            epoch: "49".to_string(),
            root: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        },
        target: beacon::Checkpoint {
            epoch: "50".to_string(),
            root: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        },
    };

    let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();

    // Before EIP-7549, index matches BN response
    assert_eq!(crypto_data.index, 7, "index should initially match BN response");

    // Apply EIP-7549: target epoch 50 >= electra_fork_epoch 50
    let schedule = create_test_fork_schedule();
    let target_epoch = crypto_data.target.epoch;
    let fork_name = ForkName::from_epoch(target_epoch, &schedule);
    let is_electra = utils::zeroes_committee_index(fork_name);
    assert!(is_electra, "epoch 50 should be Electra");

    if is_electra {
        crypto_data.index = 0;
    }

    assert_eq!(
        crypto_data.index, 0,
        "EIP-7549: crypto_attestation_data.index must be 0 for Electra"
    );
}

#[tokio::test]
async fn test_electra_submitted_single_attestation_data_index_zero() {
    // Verify that the submitted SingleAttestation has data.index == "0" for Electra,
    // even when the BN returns a non-zero index.
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // Epoch 52 (well into Electra), BN returns index "9"
    let slot = 1664u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    assert_eq!(epoch, 52);

    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "77",
                "committee_index": "9",
                "committee_length": "32",
                "committees_at_slot": "16",
                "validator_committee_index": "4",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "9",
                "beacon_block_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x5555555555555555555555555555555555555555555555555555555555555555"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::Electra(atts) => {
            assert_eq!(atts.len(), 1);
            let att = &atts[0];
            assert_eq!(
                att.data.index, "0",
                "EIP-7549: submitted SingleAttestation data.index must be \"0\""
            );
            assert_eq!(
                att.committee_index, 9,
                "committee_index should carry the original committee index"
            );
            assert_eq!(att.attester_index, 77);
        }
        VersionedAttestation::PreElectra(_)
        | VersionedAttestation::Fulu(_)
        | VersionedAttestation::Gloas(_) => {
            panic!("Expected Electra attestation for epoch 52");
        }
    }
}

#[test]
fn test_pre_electra_data_index_preserved() {
    // Verify that for pre-Electra attestations, data.index is preserved (not zeroed).
    let beacon_data = beacon::AttestationData {
        slot: "96".to_string(),
        index: "5".to_string(),
        beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        source: beacon::Checkpoint {
            epoch: "2".to_string(),
            root: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        },
        target: beacon::Checkpoint {
            epoch: "3".to_string(),
            root: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        },
    };

    let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();

    assert_eq!(crypto_data.index, 5, "index should match BN response");

    // Pre-Electra: epoch 3 < electra_fork_epoch 50
    let schedule = create_test_fork_schedule();
    let target_epoch = crypto_data.target.epoch;
    let fork_name = ForkName::from_epoch(target_epoch, &schedule);
    let is_electra = utils::zeroes_committee_index(fork_name);
    assert!(!is_electra, "epoch 3 should be pre-Electra");

    // Apply the same logic as process_attestation_duty
    if is_electra {
        crypto_data.index = 0;
    }

    assert_eq!(crypto_data.index, 5, "Pre-Electra: data.index must be preserved, not zeroed");
}

#[test]
fn test_electra_signing_root_matches_submitted_data() {
    // Verify that the signing root computed with index=0 matches the tree hash
    // of the data reconstructed from what would be in the submitted SingleAttestation.
    // This ensures: what's signed == what's submitted, field by field.
    let beacon_data = beacon::AttestationData {
        slot: "1600".to_string(),
        index: "7".to_string(),
        beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        source: beacon::Checkpoint {
            epoch: "49".to_string(),
            root: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        },
        target: beacon::Checkpoint {
            epoch: "50".to_string(),
            root: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        },
    };

    // Step 1: Convert and apply EIP-7549 zeroing (what gets signed)
    let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();
    assert_eq!(crypto_data.index, 7);
    crypto_data.index = 0; // EIP-7549
    let signed_root = crypto_data.tree_hash_root();

    // Step 2: Reconstruct from submitted SingleAttestation data
    // In process_attestation_duty, the submitted data is:
    //   electra_data = beacon_attestation_data.clone(); electra_data.index = "0";
    // We reconstruct that and convert back to crypto types.
    let mut submitted_beacon_data = beacon_data;
    submitted_beacon_data.index = "0".to_string();
    let submitted_crypto_data = utils::convert_attestation_data(&submitted_beacon_data).unwrap();
    let submitted_root = submitted_crypto_data.tree_hash_root();

    assert_eq!(
        signed_root, submitted_root,
        "Signing root (index=0) must match tree hash of submitted SingleAttestation data"
    );

    // Also verify the submitted data has index 0
    assert_eq!(submitted_crypto_data.index, 0);
    // And all other fields are preserved
    assert_eq!(crypto_data.slot, submitted_crypto_data.slot);
    assert_eq!(crypto_data.beacon_block_root, submitted_crypto_data.beacon_block_root);
    assert_eq!(crypto_data.source, submitted_crypto_data.source);
    assert_eq!(crypto_data.target, submitted_crypto_data.target);
}

// --- H-05: derive_fork_for_epoch refactor and Fulu attestation versioning tests ---

/// Helper: derives a Fork from ForkSchedule using the same logic as the refactored
/// derive_fork_for_epoch (activation_epoch + previous_fork helpers).
fn derive_fork_for_epoch_standalone(epoch: u64, schedule: &ForkSchedule) -> eth_types::Fork {
    let current = ForkName::from_epoch(epoch, schedule);
    let previous = current.previous_fork(schedule);
    eth_types::Fork {
        previous_version: previous.fork_version(schedule),
        current_version: current.fork_version(schedule),
        epoch: current.activation_epoch(schedule),
    }
}

#[test]
fn test_derive_fork_for_epoch_fulu() {
    let schedule = create_test_fork_schedule();
    // fulu_fork_epoch = 60 in test schedule
    let fork = derive_fork_for_epoch_standalone(60, &schedule);
    // At fulu epoch: current = fulu version, previous = electra version
    assert_eq!(fork.current_version, [0, 0, 0, 7]); // fulu_fork_version
    assert_eq!(fork.previous_version, [0, 0, 0, 6]); // electra_fork_version
    assert_eq!(fork.epoch, 60); // fulu activation epoch
}

#[test]
fn test_derive_fork_for_epoch_at_boundary() {
    let schedule = create_test_fork_schedule();
    // epoch 59 = Electra, epoch 60 = Fulu
    let fork_before = derive_fork_for_epoch_standalone(59, &schedule);
    assert_eq!(fork_before.current_version, [0, 0, 0, 6]); // electra
    let fork_at = derive_fork_for_epoch_standalone(60, &schedule);
    assert_eq!(fork_at.current_version, [0, 0, 0, 7]); // fulu
}

#[tokio::test]
async fn test_fulu_attestation_versioning() {
    let mock_server = wiremock::MockServer::start().await;
    // Fulu epoch = 60, slot = 60*32 = 1920
    let slot = 1920;
    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::Fulu(atts) => {
            assert_eq!(atts.len(), 1);
            let att = &atts[0];
            // EIP-7549: data.index must be "0" for Fulu (since Fulu >= Electra)
            assert_eq!(att.data.index, "0", "Fulu attestation data.index must be 0 (EIP-7549)");
        }
        other => {
            panic!(
                "Expected Fulu attestation for slot in epoch 60 (= fulu_fork_epoch), got {:?}",
                std::mem::discriminant(other)
            );
        }
    }
}

#[tokio::test]
async fn test_fulu_eip7549_index_zeroing() {
    let mock_server = wiremock::MockServer::start().await;
    // Fulu epoch = 60, slot = 60*32 = 1920
    let slot = 1920;
    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert!(results[0].success);

    let captured = capturing.captured();
    match &captured[0] {
        VersionedAttestation::Fulu(atts) => {
            assert_eq!(
                atts[0].data.index, "0",
                "EIP-7549: data.index must be zeroed for Fulu attestations"
            );
            // committee_index should carry the original committee index from duty
            assert_eq!(atts[0].committee_index, 3);
        }
        other => {
            panic!("Expected Fulu attestation, got {:?}", std::mem::discriminant(other));
        }
    }
}

#[tokio::test]
async fn test_electra_attestation_unchanged() {
    let mock_server = wiremock::MockServer::start().await;
    // Electra epoch = 50, slot = 50*32 = 1600 (same as existing test, just verify it's still Electra, not Fulu)
    let slot = 1600;
    let (orchestrator, _handle, pubkey_hex, capturing) =
        build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
    mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

    let results = orchestrator.process_slot(slot).await.unwrap();
    assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

    let captured = capturing.captured();
    assert_eq!(captured.len(), 1);

    match &captured[0] {
        VersionedAttestation::Electra(atts) => {
            assert_eq!(atts.len(), 1);
            assert_eq!(atts[0].data.index, "0", "Electra attestation data.index must be 0");
        }
        other => {
            panic!(
                "Expected Electra attestation for epoch 50, got {:?}",
                std::mem::discriminant(other)
            );
        }
    }
}

/// `eth-types` `fork.rs` `test_schedule()`: Electra 364544, Fulu 500000 (finite).
/// The builder fixture pins Fulu at `u64::MAX` and cannot drive a Fulu epoch.
fn mainnet_shaped_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 74240,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 144896,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 194048,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 269568,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: 364544,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: 500000,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [7, 0, 0, 0],
    })
}

const B1_DENEB_EPOCH: u64 = 269568;
const B1_ELECTRA_EPOCH: u64 = 364544;
const B1_FULU_EPOCH: u64 = 500000;
const B1_GLOAS_EPOCH: u64 = 600000;
const B1_GVR: Root = [0xaa; 32];

fn gloas_capable_fork_schedule() -> Arc<ForkSchedule> {
    let mut schedule = (*mainnet_shaped_fork_schedule()).clone();
    schedule.gloas_fork_epoch = B1_GLOAS_EPOCH;
    Arc::new(schedule)
}

/// B1 (D18): Electra and Fulu still zero `data.index` through the attestation
/// call sites (`from_epoch` → signing via `convert_and_normalize` and
/// submission `SingleAttestation.data.index`), not by calling the helper.
#[tokio::test]
async fn test_attestation_still_zeroes_index_at_electra_and_fulu() {
    use crypto::{signing_root_for, DutyRef, Signature, SigningCtx};

    let schedule = mainnet_shaped_fork_schedule();
    for (label, epoch, expected_fork) in
        [("electra", B1_ELECTRA_EPOCH, ForkName::Electra), ("fulu", B1_FULU_EPOCH, ForkName::Fulu)]
    {
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        assert_eq!(fork_name, expected_fork, "{label}: from_epoch on mainnet-shaped schedule");

        let slot = epoch * SLOTS_PER_EPOCH;
        let mock_server = wiremock::MockServer::start().await;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator_with_schedule(
                &mock_server.uri(),
                slot,
                schedule.clone(),
            )
            .await;
        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "{label} attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1, "{label}: one submission");
        let att = match &captured[0] {
            VersionedAttestation::Electra(atts) => {
                assert_eq!(expected_fork, ForkName::Electra, "{label}: Electra wrapper");
                assert_eq!(atts.len(), 1);
                &atts[0]
            }
            VersionedAttestation::Fulu(atts) => {
                assert_eq!(expected_fork, ForkName::Fulu, "{label}: Fulu wrapper");
                assert_eq!(atts.len(), 1);
                &atts[0]
            }
            other => panic!(
                "{label}: expected {expected_fork:?} wrapper, got {:?}",
                std::mem::discriminant(other)
            ),
        };
        assert_eq!(
            att.data.index, "0",
            "{label}: submission-path SingleAttestation.data.index must be \"0\" \
             (BN data.index was non-zero)"
        );
        assert_ne!(att.data.index, "3", "{label}: BN mock index must not leak onto the wire");

        let signed = utils::convert_attestation_data(&att.data).unwrap();
        assert_eq!(signed.index, 0, "{label}: signed AttestationData.index must be 0");

        let pk_bytes = hex::decode(pubkey_hex.trim_start_matches("0x")).expect("pubkey hex");
        let pk = PublicKey::from_bytes(&pk_bytes).expect("pubkey");
        let sig_bytes = hex::decode(att.signature.trim_start_matches("0x")).expect("sig hex");
        let sig = Signature::from_bytes(&sig_bytes).expect("signature");
        let ctx = SigningCtx { fork_schedule: schedule.as_ref(), genesis_validators_root: B1_GVR };
        let root = signing_root_for(&DutyRef::Attestation(&signed), &ctx);
        sig.verify(&pk, &root).unwrap_or_else(|e| {
            panic!("{label}: signature must verify over index=0 signing path: {e}")
        });

        let mut bn_index = signed.clone();
        bn_index.index = 3;
        let bn_root = signing_root_for(&DutyRef::Attestation(&bn_index), &ctx);
        assert!(
            sig.verify(&pk, &bn_root).is_err(),
            "{label}: signature must not verify over the BN's non-zero index"
        );
    }
}

/// B1 (D18): aggregation call sites (`aggregation.rs` `is_electra` +
/// `convert_and_normalize`) still zero the aggregate-query root at Electra
/// and Fulu on a mainnet-shaped schedule.
#[tokio::test]
async fn test_aggregation_still_zeroes_index_at_electra_and_fulu() {
    use eth_types::{AttestationData, Checkpoint};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let schedule = mainnet_shaped_fork_schedule();
    for (label, epoch, expected_fork) in
        [("electra", B1_ELECTRA_EPOCH, ForkName::Electra), ("fulu", B1_FULU_EPOCH, ForkName::Fulu)]
    {
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        assert_eq!(fork_name, expected_fork, "{label}: from_epoch on mainnet-shaped schedule");

        let slot = epoch * SLOTS_PER_EPOCH;
        let expected = AttestationData {
            slot,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: epoch.saturating_sub(1), root: [0x22; 32] },
            target: Checkpoint { epoch, root: [0x33; 32] },
        };
        let expected_root = format!("0x{}", hex::encode(expected.tree_hash_root().0));

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, pubkey_hex, _capturing) =
            build_fork_transition_orchestrator_with_schedule(
                &mock_server.uri(),
                slot,
                schedule.clone(),
            )
            .await;
        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .and(query_param("committee_index", "3"))
            .and(query_param("attestation_data_root", expected_root.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xff01",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "0",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": epoch.saturating_sub(1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "committee_bits": "0x0800000000000000"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }
}

async fn mount_attestation_mocks_with_bn_index(
    mock_server: &wiremock::MockServer,
    slot: u64,
    pubkey_hex: &str,
    bn_index: &str,
) {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};

    let epoch = slot / SLOTS_PER_EPOCH;

    // Exact epoch path: a regex `attester/.*` would match first and steal the
    // epoch-70 fetch when 69 and 70 are mounted on one server.
    Mock::given(method("POST"))
        .and(path(format!("/eth/v1/validator/duties/attester/{epoch}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "3",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "2",
                "slot": slot.to_string()
            }]
        })))
        .mount(mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": bn_index,
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch.saturating_sub(1)).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(mock_server)
        .await;
}

fn expected_attestation_data(slot: u64, epoch: u64, index: u64) -> eth_types::AttestationData {
    eth_types::AttestationData {
        slot,
        index,
        beacon_block_root: [0x11; 32],
        source: eth_types::Checkpoint { epoch: epoch.saturating_sub(1), root: [0x22; 32] },
        target: eth_types::Checkpoint { epoch, root: [0x33; 32] },
    }
}

/// Submission path: BN `data.index` is preserved at Gloas (EMPTY=0 and FULL=1)
/// and zeroed at Electra and Fulu. Forks are resolved via `from_epoch`.
#[tokio::test]
async fn test_submission_preserves_index_at_gloas_zeroes_at_electra_and_fulu() {
    use crypto::{signing_root_for, DutyRef, Signature, SigningCtx};

    let schedule = gloas_capable_fork_schedule();
    let cases = [
        ("electra", B1_ELECTRA_EPOCH, ForkName::Electra, "1", "0"),
        ("fulu", B1_FULU_EPOCH, ForkName::Fulu, "1", "0"),
        ("gloas-empty", B1_GLOAS_EPOCH, ForkName::Gloas, "0", "0"),
        ("gloas-full", B1_GLOAS_EPOCH, ForkName::Gloas, "1", "1"),
    ];

    for (label, epoch, expected_fork, bn_index, submitted_index) in cases {
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        assert_eq!(fork_name, expected_fork, "{label}: from_epoch on finite schedule");

        let slot = epoch * SLOTS_PER_EPOCH;
        let mock_server = wiremock::MockServer::start().await;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator_with_schedule(
                &mock_server.uri(),
                slot,
                schedule.clone(),
            )
            .await;
        mount_attestation_mocks_with_bn_index(&mock_server, slot, &pubkey_hex, bn_index).await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "{label} attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1, "{label}: one submission");
        let att = match &captured[0] {
            VersionedAttestation::Electra(atts) => {
                assert_eq!(expected_fork, ForkName::Electra, "{label}: Electra wrapper");
                assert_eq!(atts.len(), 1);
                &atts[0]
            }
            VersionedAttestation::Fulu(atts) => {
                assert_eq!(expected_fork, ForkName::Fulu, "{label}: Fulu wrapper");
                assert_eq!(atts.len(), 1);
                &atts[0]
            }
            VersionedAttestation::Gloas(atts) => {
                assert_eq!(expected_fork, ForkName::Gloas, "{label}: Gloas wrapper");
                assert_eq!(atts.len(), 1);
                &atts[0]
            }
            other => panic!(
                "{label}: expected Electra+ SingleAttestation, got {:?}",
                std::mem::discriminant(other)
            ),
        };
        assert_eq!(
            att.data.index, submitted_index,
            "{label}: submission-path SingleAttestation.data.index must equal \
             {submitted_index} (BN data.index was {bn_index})"
        );

        let signed = utils::convert_attestation_data(&att.data).unwrap();
        assert_eq!(
            signed.index,
            submitted_index.parse::<u64>().unwrap(),
            "{label}: signed AttestationData.index must match the submitted value"
        );

        let pk_bytes = hex::decode(pubkey_hex.trim_start_matches("0x")).expect("pubkey hex");
        let pk = PublicKey::from_bytes(&pk_bytes).expect("pubkey");
        let sig_bytes = hex::decode(att.signature.trim_start_matches("0x")).expect("sig hex");
        let sig = Signature::from_bytes(&sig_bytes).expect("signature");
        let ctx = SigningCtx { fork_schedule: schedule.as_ref(), genesis_validators_root: B1_GVR };
        let root = signing_root_for(&DutyRef::Attestation(&signed), &ctx);
        sig.verify(&pk, &root).unwrap_or_else(|e| {
            panic!("{label}: signature must verify over submitted index={submitted_index}: {e}")
        });

        if submitted_index != "0" {
            let zeroed = eth_types::AttestationData { index: 0, ..signed.clone() };
            let zeroed_signing = signing_root_for(&DutyRef::Attestation(&zeroed), &ctx);
            assert!(
                sig.verify(&pk, &zeroed_signing).is_err(),
                "{label}: signature must not verify over a zeroed index"
            );
        }
    }
}

/// Table over Deneb/Electra/Fulu/Gloas: Electra+ wrapper + `committee_index`
/// query (aggregate `:297` / `:334`) at Electra onward, pre-Electra at Deneb.
#[tokio::test]
async fn test_electra_attestation_wire_taken_at_gloas_electra_fulu_not_deneb() {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let schedule = gloas_capable_fork_schedule();
    // (label, epoch, fork, bn_index, submitted_index, query_index, electra_wire)
    let cases = [
        ("deneb", B1_DENEB_EPOCH, ForkName::Deneb, "3", "3", 3u64, false),
        ("electra", B1_ELECTRA_EPOCH, ForkName::Electra, "3", "0", 0, true),
        ("fulu", B1_FULU_EPOCH, ForkName::Fulu, "3", "0", 0, true),
        ("gloas-empty", B1_GLOAS_EPOCH, ForkName::Gloas, "0", "0", 0, true),
        ("gloas-full", B1_GLOAS_EPOCH, ForkName::Gloas, "1", "1", 1, true),
    ];

    for (label, epoch, expected_fork, bn_index, submitted_index, query_index, electra_wire) in cases
    {
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        assert_eq!(fork_name, expected_fork, "{label}: from_epoch on finite schedule");
        assert_eq!(
            utils::uses_electra_attestation_wire(fork_name),
            electra_wire,
            "{label}: Electra+ wire predicate"
        );

        let slot = epoch * SLOTS_PER_EPOCH;
        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator_with_schedule(
                &mock_server.uri(),
                slot,
                schedule.clone(),
            )
            .await;
        mount_attestation_mocks_with_bn_index(&mock_server, slot, &pubkey_hex, bn_index).await;

        let expected_root = format!(
            "0x{}",
            hex::encode(expected_attestation_data(slot, epoch, query_index).tree_hash_root().0)
        );

        let mut aggregate_mock = Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .and(query_param("attestation_data_root", expected_root.as_str()));
        if electra_wire {
            aggregate_mock = aggregate_mock.and(query_param("committee_index", "3"));
        }
        let aggregate_body = if electra_wire {
            serde_json::json!({
                "data": {
                    "aggregation_bits": "0xff01",
                    "data": {
                        "slot": slot.to_string(),
                        "index": query_index.to_string(),
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": epoch.saturating_sub(1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "committee_bits": "0x0800000000000000"
                }
            })
        } else {
            serde_json::json!({
                "data": {
                    "aggregation_bits": "0xff01",
                    "data": {
                        "slot": slot.to_string(),
                        "index": query_index.to_string(),
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": epoch.saturating_sub(1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })
        };
        aggregate_mock
            .respond_with(ResponseTemplate::new(200).set_body_json(aggregate_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let submit_v1 = if electra_wire {
            Mock::given(method("POST"))
                .and(path("/eth/v1/validator/aggregate_and_proofs"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
        } else {
            Mock::given(method("POST"))
                .and(path("/eth/v1/validator/aggregate_and_proofs"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
        };
        submit_v1.mount(&mock_server).await;

        let submit_v2 = if electra_wire {
            Mock::given(method("POST"))
                .and(path("/eth/v2/validator/aggregate_and_proofs"))
                .and(header("Eth-Consensus-Version", expected_fork.as_ref()))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
        } else {
            Mock::given(method("POST"))
                .and(path("/eth/v2/validator/aggregate_and_proofs"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
        };
        submit_v2.mount(&mock_server).await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "{label} attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1, "{label}: one attestation submission");
        match &captured[0] {
            VersionedAttestation::PreElectra(atts) => {
                assert!(!electra_wire, "{label}: pre-Electra wrapper only at Deneb");
                assert_eq!(atts.len(), 1);
                assert_eq!(atts[0].data.index, submitted_index, "{label}: pre-Electra data.index");
            }
            VersionedAttestation::Electra(atts) => {
                assert!(electra_wire, "{label}: Electra SingleAttestation");
                assert_eq!(expected_fork, ForkName::Electra, "{label}: Electra wrapper");
                assert_eq!(atts.len(), 1);
                assert_eq!(atts[0].data.index, submitted_index);
            }
            VersionedAttestation::Fulu(atts) => {
                assert!(electra_wire, "{label}: Fulu SingleAttestation is Electra+ wire");
                assert_eq!(expected_fork, ForkName::Fulu, "{label}: Fulu wrapper");
                assert_eq!(atts.len(), 1);
                assert_eq!(atts[0].data.index, submitted_index);
            }
            VersionedAttestation::Gloas(atts) => {
                assert!(electra_wire, "{label}: Gloas SingleAttestation is Electra+ wire");
                assert_eq!(expected_fork, ForkName::Gloas, "{label}: Gloas wrapper");
                assert_eq!(atts.len(), 1);
                assert_eq!(atts[0].data.index, submitted_index);
            }
        }

        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        let requests = mock_server.received_requests().await.unwrap();
        let aggregate_requests: Vec<_> = requests
            .iter()
            .filter(|r| {
                r.url.path() == "/eth/v1/validator/aggregate_attestation"
                    && r.method == wiremock::http::Method::GET
            })
            .collect();
        assert!(!aggregate_requests.is_empty(), "{label}: expected aggregate_attestation request");
        for req in &aggregate_requests {
            let query = req.url.query().unwrap_or("");
            if electra_wire {
                assert!(
                    query.contains("committee_index=3"),
                    "{label}: Electra+ aggregate branch must pass committee_index, got: {query}"
                );
            } else {
                assert!(
                    !query.contains("committee_index"),
                    "{label}: Deneb aggregate must not include committee_index, got: {query}"
                );
            }
        }
    }
}

fn electra_aggregate_response(slot: u64, epoch: u64, index: &str) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "aggregation_bits": "0xff01",
            "data": {
                "slot": slot.to_string(),
                "index": index,
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": epoch.saturating_sub(1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "committee_bits": "0x0800000000000000"
        }
    })
}

async fn mount_electra_plus_aggregate_mocks(
    mock_server: &wiremock::MockServer,
    slot: u64,
    epoch: u64,
    query_index: u64,
    consensus_version: &str,
) {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};

    let expected_root = format!(
        "0x{}",
        hex::encode(expected_attestation_data(slot, epoch, query_index).tree_hash_root().0)
    );

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .and(query_param("committee_index", "3"))
        .and(query_param("attestation_data_root", expected_root.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(electra_aggregate_response(
            slot,
            epoch,
            &query_index.to_string(),
        )))
        .expect(1)
        .mount(mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(header("Eth-Consensus-Version", consensus_version))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(mock_server)
        .await;
}

fn submitted_index(att: &VersionedAttestation, expected_fork: ForkName) -> &str {
    match att {
        VersionedAttestation::Fulu(atts) => {
            assert_eq!(expected_fork, ForkName::Fulu, "Fulu wrapper");
            assert_eq!(atts.len(), 1);
            atts[0].data.index.as_str()
        }
        VersionedAttestation::Gloas(atts) => {
            assert_eq!(expected_fork, ForkName::Gloas, "Gloas wrapper");
            assert_eq!(atts.len(), 1);
            atts[0].data.index.as_str()
        }
        VersionedAttestation::Electra(atts) => {
            assert_eq!(expected_fork, ForkName::Electra, "Electra wrapper");
            assert_eq!(atts.len(), 1);
            atts[0].data.index.as_str()
        }
        VersionedAttestation::PreElectra(atts) => {
            assert_eq!(expected_fork, ForkName::Deneb, "pre-Electra wrapper");
            assert_eq!(atts.len(), 1);
            atts[0].data.index.as_str()
        }
    }
}

fn submitted_attestation_data(att: &VersionedAttestation) -> &beacon::AttestationData {
    match att {
        VersionedAttestation::Electra(atts)
        | VersionedAttestation::Fulu(atts)
        | VersionedAttestation::Gloas(atts) => &atts[0].data,
        VersionedAttestation::PreElectra(atts) => &atts[0].data,
    }
}

fn submitted_signature_hex(att: &VersionedAttestation) -> &str {
    match att {
        VersionedAttestation::Electra(atts)
        | VersionedAttestation::Fulu(atts)
        | VersionedAttestation::Gloas(atts) => atts[0].signature.as_str(),
        VersionedAttestation::PreElectra(atts) => atts[0].signature.as_str(),
    }
}

/// One orchestrator instance crossing Fulu slot 2208 → Gloas slot 2240 without
/// restart. EIP-7549 still zeros `data.index` at Fulu; Gloas preserves the BN
/// payload-status bit on both signing and submission. Aggregate submit after
/// the boundary uses the Gloas arm.
#[tokio::test]
async fn test_boundary_attestation_and_aggregate_continuity() {
    use crypto::{signing_root_for, DutyRef, Signature, SigningCtx};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let schedule = create_test_fork_schedule();
    let fulu_slot = 2208u64;
    let gloas_slot = 2240u64;
    let fulu_epoch = fulu_slot / SLOTS_PER_EPOCH;
    let gloas_epoch = gloas_slot / SLOTS_PER_EPOCH;
    assert_eq!(fulu_epoch, 69, "slot 2208 is epoch 69");
    assert_eq!(gloas_epoch, 70, "slot 2240 is epoch 70");

    let fulu_fork = ForkName::from_epoch(fulu_epoch, &schedule);
    let gloas_fork = ForkName::from_epoch(gloas_epoch, &schedule);
    assert_eq!(fulu_fork, ForkName::Fulu);
    assert_eq!(gloas_fork, ForkName::Gloas);
    assert_eq!(
        fulu_fork.fork_version(&schedule),
        schedule.fulu_fork_version,
        "slot 2208 must resolve via from_epoch → fulu_fork_version"
    );
    assert_eq!(
        gloas_fork.fork_version(&schedule),
        schedule.gloas_fork_version,
        "slot 2240 must resolve via from_epoch → gloas_fork_version"
    );

    // Two crossings: one instance cannot submit two 2240 attestations
    // (EIP-3076 double vote on the same target epoch).
    for (gloas_bn_index, expected_gloas_index) in [("1", "1"), ("0", "0")] {
        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator_with_schedule(
                &mock_server.uri(),
                fulu_slot,
                schedule.clone(),
            )
            .await;

        mount_attestation_mocks_with_bn_index(&mock_server, fulu_slot, &pubkey_hex, "3").await;
        mount_attestation_mocks_with_bn_index(
            &mock_server,
            gloas_slot,
            &pubkey_hex,
            gloas_bn_index,
        )
        .await;

        mount_electra_plus_aggregate_mocks(
            &mock_server,
            fulu_slot,
            fulu_epoch,
            0,
            fulu_fork.as_ref(),
        )
        .await;
        let gloas_query_index: u64 = gloas_bn_index.parse().unwrap();
        mount_electra_plus_aggregate_mocks(
            &mock_server,
            gloas_slot,
            gloas_epoch,
            gloas_query_index,
            gloas_fork.as_ref(),
        )
        .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(fulu_epoch).await.unwrap();
        let fulu_results = orchestrator.process_slot(fulu_slot).await.unwrap();
        assert_eq!(fulu_results.len(), 1);
        assert!(
            fulu_results[0].success,
            "Fulu slot 2208 attestation should succeed: {:?}",
            fulu_results[0].error
        );
        orchestrator.aggregation_service.maybe_produce_aggregations(fulu_slot, fulu_epoch).await;

        orchestrator.clock.set_slot(gloas_slot);
        orchestrator.duty_tracker.fetch_duties_for_epoch(gloas_epoch).await.unwrap();
        let gloas_results = orchestrator.process_slot(gloas_slot).await.unwrap();
        assert_eq!(gloas_results.len(), 1);
        assert!(
            gloas_results[0].success,
            "Gloas slot 2240 attestation should succeed: {:?}",
            gloas_results[0].error
        );
        orchestrator.aggregation_service.maybe_produce_aggregations(gloas_slot, gloas_epoch).await;

        let captured = capturing.captured();
        assert_eq!(
            captured.len(),
            2,
            "one orchestrator must submit at 2208 and 2240 without restart"
        );

        assert_eq!(
            submitted_index(&captured[0], ForkName::Fulu),
            "0",
            "slot 2208: EIP-7549 still zeros data.index at Fulu (BN index was 3)"
        );
        assert_eq!(
            submitted_index(&captured[1], ForkName::Gloas),
            expected_gloas_index,
            "slot 2240: submitted data.index must equal BN index {gloas_bn_index}"
        );
        assert_eq!(
            submitted_attestation_data(&captured[0]).target.epoch,
            fulu_epoch.to_string(),
            "captured Fulu target.epoch must match slot/32"
        );
        assert_eq!(
            submitted_attestation_data(&captured[1]).target.epoch,
            gloas_epoch.to_string(),
            "captured Gloas target.epoch must match slot/32"
        );

        let ctx =
            SigningCtx { fork_schedule: schedule.as_ref(), genesis_validators_root: [0xaa; 32] };
        let pk_bytes = hex::decode(pubkey_hex.trim_start_matches("0x")).expect("pubkey hex");
        let pk = PublicKey::from_bytes(&pk_bytes).expect("pubkey");

        for (label, att, fork_name, bn_index, expected_index) in [
            ("fulu-2208", &captured[0], fulu_fork, "3", "0"),
            ("gloas-2240", &captured[1], gloas_fork, gloas_bn_index, expected_gloas_index),
        ] {
            let mut bn_data = submitted_attestation_data(att).clone();
            bn_data.index = bn_index.to_string();
            let signed = utils::convert_and_normalize_attestation_data(&bn_data, fork_name)
                .unwrap_or_else(|e| panic!("{label}: convert_and_normalize: {e}"));
            assert_eq!(
                signed.index.to_string(),
                expected_index,
                "{label}: signing-path index must be {expected_index}"
            );
            assert_eq!(
                submitted_attestation_data(att).index,
                expected_index,
                "{label}: submission-path index must be {expected_index}"
            );

            let sig_bytes = hex::decode(submitted_signature_hex(att).trim_start_matches("0x"))
                .expect("sig hex");
            let sig = Signature::from_bytes(&sig_bytes).expect("signature");
            let root = signing_root_for(&DutyRef::Attestation(&signed), &ctx);
            sig.verify(&pk, &root).unwrap_or_else(|e| {
                panic!("{label}: signature must verify over signed index={expected_index}: {e}")
            });
        }
    }
}

// --- Issue 7.4: Boundary proposal v3 → v4 dispatch + slashing record ---

const PRE_GLOAS_SLOT: Slot = 2208;
const GLOAS_SLOT: Slot = 2240;
const PROPOSER_INDEX: u64 = 42;

async fn build_proposal_boundary_orchestrator(
    mock_server_uri: &str,
    slot: u64,
    block_beacon: Arc<MockBlockBeacon>,
    slashing_db: Arc<SlashingDb>,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    PublicKey,
    String,
    Arc<MockSlotClock>,
) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let beacon_config = BeaconClientConfig::new(mock_server_uri);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let capturing_submitter = Arc::new(CapturingSubmitter::new());
    let propagator = Arc::new(Propagator::new(capturing_submitter));

    let config = create_test_config();
    let pubkey_bytes = pubkey.to_bytes();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey_bytes, pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let validator_store = create_mock_validator_store();
    validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey_bytes)).unwrap();

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock.clone(),
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        validator_store,
        config,
        pubkey_map,
    ));

    (orchestrator, handle, pubkey, pubkey_hex, clock)
}

fn proposal_ctx(slot: Slot) -> SlotContext {
    SlotContext { slot, epoch: slot / SLOTS_PER_EPOCH, parent_root: None, head_root: None }
}

fn gloas_beacon_block(slot: Slot) -> eth_types::BeaconBlock {
    gloas_beacon_block_with_state(slot, [2u8; 32])
}

fn gloas_beacon_block_with_state(slot: Slot, state_root: Root) -> eth_types::BeaconBlock {
    eth_types::BeaconBlock {
        slot,
        proposer_index: PROPOSER_INDEX,
        parent_root: [1u8; 32],
        state_root,
        body: hex::decode(rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ).unwrap(),
    }
}

fn gloas_envelope_hex() -> String {
    format!("0x{}", rvc_gloas::test_fixtures::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ)
}

fn gloas_block_contents_response(slot: Slot) -> ProduceBlockResponse {
    gloas_block_contents_response_for(gloas_beacon_block(slot))
}

fn gloas_block_contents_response_for(block: eth_types::BeaconBlock) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data: serde_json::json!({
            "block": block,
            "execution_payload_envelope": gloas_envelope_hex(),
            "kzg_proofs": ["0xaa"],
            "blobs": ["0xbb"],
        }),
        is_blinded: false,
        // Shared canned body: 2208 is dispatch-only and fail-closes on this
        // version (`ConsensusVersionMismatch`), not a JSON parse error.
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: true,
        builder_url: None,
        consensus_block_value: None,
    }
}

fn gloas_builder_win_response(slot: Slot, builder_url: &str) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data: serde_json::to_value(gloas_beacon_block(slot)).unwrap(),
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: Some(builder_url.to_string()),
        consensus_block_value: None,
    }
}

fn island_block_signing_root(block: &eth_types::BeaconBlock, schedule: &ForkSchedule) -> Root {
    use crypto::{signing_root_for, DutyRef, SigningCtx};

    let island_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("Gloas island block root");
    let ctx = SigningCtx { fork_schedule: schedule, genesis_validators_root: [0xaa; 32] };
    signing_root_for(&DutyRef::BlockRoot { root: &island_root, slot: block.slot }, &ctx)
}

fn block_records_for_slot(db: &SlashingDb, pubkey_hex: &str, slot: Slot) -> Vec<Option<String>> {
    db.get_blocks(pubkey_hex)
        .expect("slashing block query")
        .into_iter()
        .filter(|block| block.slot == slot)
        .map(|block| block.signing_root.map(|root| root.as_hex().to_string()))
        .collect()
}

/// Slot 2208 stays on v3; first Gloas slot uses v4, records slashing, and
/// publishes the self-build envelope after the block (D20).
#[tokio::test]
async fn test_gloas_slot_dispatches_produce_block_v4() {
    use crypto::{signing_root_for, DutyRef, Signature, SigningCtx};

    let mock_server = wiremock::MockServer::start().await;
    // One canned Gloas BlockContents for both slots. 2208 only records v3 then
    // fail-closes on consensus_version (successful Fulu propose is covered in
    // block-service); 2240 is the success path.
    let block_beacon =
        Arc::new(MockBlockBeacon::with_response(gloas_block_contents_response(GLOAS_SLOT)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());

    let (orchestrator, _handle, pubkey, pubkey_hex, clock) = build_proposal_boundary_orchestrator(
        &mock_server.uri(),
        PRE_GLOAS_SLOT,
        block_beacon.clone(),
        slashing_db.clone(),
    )
    .await;

    setup_proposer_duty(
        &mock_server,
        PRE_GLOAS_SLOT / SLOTS_PER_EPOCH,
        PRE_GLOAS_SLOT,
        &pubkey_hex,
        PROPOSER_INDEX,
    )
    .await;
    setup_proposer_duty(
        &mock_server,
        GLOAS_SLOT / SLOTS_PER_EPOCH,
        GLOAS_SLOT,
        &pubkey_hex,
        PROPOSER_INDEX,
    )
    .await;
    orchestrator
        .duty_tracker
        .fetch_proposer_duties(PRE_GLOAS_SLOT / SLOTS_PER_EPOCH)
        .await
        .unwrap();
    orchestrator.duty_tracker.fetch_proposer_duties(GLOAS_SLOT / SLOTS_PER_EPOCH).await.unwrap();

    // Dispatch-only: v3 is recorded, then ConsensusVersionMismatch on the
    // canned Gloas version. No publish / slashing row at 2208.
    orchestrator
        .maybe_propose_block(
            PRE_GLOAS_SLOT,
            PRE_GLOAS_SLOT / SLOTS_PER_EPOCH,
            &proposal_ctx(PRE_GLOAS_SLOT),
        )
        .await;

    assert_eq!(
        block_beacon.produce_v3_slots(),
        vec![PRE_GLOAS_SLOT],
        "pre-Gloas slot must call produce_block_v3 exactly once"
    );
    assert!(
        block_beacon.produce_v4_calls().is_empty(),
        "pre-Gloas slot must not call produce_block_v4"
    );

    clock.set_slot(GLOAS_SLOT);
    orchestrator
        .maybe_propose_block(GLOAS_SLOT, GLOAS_SLOT / SLOTS_PER_EPOCH, &proposal_ctx(GLOAS_SLOT))
        .await;

    assert_eq!(
        block_beacon.produce_v3_slots(),
        vec![PRE_GLOAS_SLOT],
        "Gloas slot must not add a produce_block_v3 call"
    );
    let v4 = block_beacon.produce_v4_calls();
    assert_eq!(v4.len(), 1, "Gloas slot must call produce_block_v4 exactly once");
    assert_eq!(v4[0].0, GLOAS_SLOT);
    let builder_config = &v4[0].1;
    assert_eq!(builder_config.builder_boost_factor, 100);
    assert_eq!(builder_config.min_bid, 0);

    assert_eq!(
        block_beacon.publish_blinded_count(),
        0,
        "Gloas slot must not publish a blinded block"
    );

    let publish = block_beacon.publish_block_calls();
    assert_eq!(publish.len(), 1, "self-build must publish the unblinded block once");
    assert_eq!(publish[0].0, GLOAS_SLOT);
    assert!(publish[0].1.is_none(), "self-build must not echo Eth-Builder-Url");

    let envelopes = block_beacon.envelope_publish_calls();
    assert_eq!(envelopes.len(), 1, "BlockContents self-build must publish one envelope");
    let publish_idx = block_beacon
        .recorded_calls()
        .iter()
        .position(|call| matches!(call, BlockBeaconCall::PublishBlock { .. }))
        .expect("block publish recorded");
    let envelope_idx = block_beacon
        .recorded_calls()
        .iter()
        .position(|call| matches!(call, BlockBeaconCall::PublishExecutionPayloadEnvelope { .. }))
        .expect("envelope publish recorded");
    assert!(envelope_idx > publish_idx, "envelope publish must follow the block publish");

    match &envelopes[0] {
        BlockBeaconCall::PublishExecutionPayloadEnvelope {
            signed_envelope,
            blobs,
            kzg_proofs,
            consensus_version,
        } => {
            assert_eq!(blobs, &WireBody::Json(serde_json::json!(["0xbb"])));
            assert_eq!(kzg_proofs, &WireBody::Json(serde_json::json!(["0xaa"])));
            assert_eq!(consensus_version, "gloas");
            let WireBody::Json(value) = signed_envelope else {
                panic!("expected JSON signed envelope, got {signed_envelope:?}");
            };
            assert_eq!(value["message"], serde_json::json!(gloas_envelope_hex()));
            let sig_hex = value["signature"].as_str().expect("envelope signature hex");
            let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x")).expect("sig hex");
            let sig = Signature::from_bytes(&sig_bytes).expect("envelope signature");
            let envelope_ssz =
                hex::decode(rvc_gloas::test_fixtures::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ)
                    .unwrap();
            let envelope_root =
                rvc_gloas::gloas_execution_payload_envelope_root(&envelope_ssz).unwrap();
            let schedule = create_test_fork_schedule();
            let ctx = SigningCtx {
                fork_schedule: schedule.as_ref(),
                genesis_validators_root: [0xaa; 32],
            };
            let builder_signing = signing_root_for(
                &DutyRef::ExecutionPayloadEnvelopeRoot { root: &envelope_root, slot: GLOAS_SLOT },
                &ctx,
            );
            sig.verify(&pubkey, &builder_signing)
                .expect("envelope must verify under DOMAIN_BEACON_BUILDER");
            let proposer_signing = signing_root_for(
                &DutyRef::BlockRoot { root: &envelope_root, slot: GLOAS_SLOT },
                &ctx,
            );
            assert!(
                sig.verify(&pubkey, &proposer_signing).is_err(),
                "envelope must not verify under DOMAIN_BEACON_PROPOSER"
            );
        }
        other => panic!("expected envelope publish, got {other:?}"),
    }

    let block = gloas_beacon_block(GLOAS_SLOT);
    assert!(
        block.try_tree_hash_root().is_err(),
        "Gloas body must not merkleize through the Electra/Deneb tree_hash bridge"
    );
    let expected_signing = island_block_signing_root(&block, create_test_fork_schedule().as_ref());
    let block_sig = Signature::from_bytes(&publish[0].2).expect("block signature");
    block_sig
        .verify(&pubkey, &expected_signing)
        .expect("block signature must verify over DutyRef::BlockRoot island output");

    let slot_blocks = block_records_for_slot(&slashing_db, &pubkey_hex, GLOAS_SLOT);
    assert_eq!(slot_blocks.len(), 1, "slashing DB must hold exactly one block record for 2240");
    assert_eq!(
        slot_blocks[0].as_deref(),
        Some(hex::encode(expected_signing).as_str()),
        "slashing row must store the DutyRef::BlockRoot signing root"
    );

    let publish_before = block_beacon.publish_block_calls().len();
    let envelopes_before = block_beacon.envelope_publish_calls().len();
    // Same slot, different signing root — EIP-3076 double proposal, not a re-sign.
    block_beacon.set_response(gloas_block_contents_response_for(gloas_beacon_block_with_state(
        GLOAS_SLOT, [3u8; 32],
    )));
    orchestrator
        .maybe_propose_block(GLOAS_SLOT, GLOAS_SLOT / SLOTS_PER_EPOCH, &proposal_ctx(GLOAS_SLOT))
        .await;
    assert_eq!(
        block_beacon.publish_block_calls().len(),
        publish_before,
        "replay must not publish a second block"
    );
    assert_eq!(
        block_beacon.envelope_publish_calls().len(),
        envelopes_before,
        "replay must not publish a second envelope"
    );
    let after_replay = block_records_for_slot(&slashing_db, &pubkey_hex, GLOAS_SLOT);
    assert_eq!(after_replay.len(), 1, "replay of slot 2240 must be refused");
    assert_eq!(
        after_replay[0].as_deref(),
        Some(hex::encode(expected_signing).as_str()),
        "remaining slashing row must still be the original DutyRef::BlockRoot hex"
    );
}

/// Bare-block (builder-win) Gloas produce: no envelope, Eth-Builder-Url echoed.
#[tokio::test]
async fn test_gloas_builder_win_skips_envelope_and_echoes_builder_url() {
    let mock_server = wiremock::MockServer::start().await;
    let builder_url = "https://relay.example/v1";
    let block_beacon = Arc::new(MockBlockBeacon::with_response(gloas_builder_win_response(
        GLOAS_SLOT,
        builder_url,
    )));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());

    let (orchestrator, _handle, _pubkey, pubkey_hex, _clock) =
        build_proposal_boundary_orchestrator(
            &mock_server.uri(),
            GLOAS_SLOT,
            block_beacon.clone(),
            slashing_db,
        )
        .await;

    setup_proposer_duty(
        &mock_server,
        GLOAS_SLOT / SLOTS_PER_EPOCH,
        GLOAS_SLOT,
        &pubkey_hex,
        PROPOSER_INDEX,
    )
    .await;
    orchestrator.duty_tracker.fetch_proposer_duties(GLOAS_SLOT / SLOTS_PER_EPOCH).await.unwrap();

    orchestrator
        .maybe_propose_block(GLOAS_SLOT, GLOAS_SLOT / SLOTS_PER_EPOCH, &proposal_ctx(GLOAS_SLOT))
        .await;

    assert!(block_beacon.produce_v3_slots().is_empty());
    let v4 = block_beacon.produce_v4_calls();
    assert_eq!(v4.len(), 1);
    assert_eq!(v4[0].0, GLOAS_SLOT);

    assert_eq!(block_beacon.publish_blinded_count(), 0);
    assert!(
        block_beacon.envelope_publish_calls().is_empty(),
        "builder-win must not publish an execution payload envelope"
    );
    let publish = block_beacon.publish_block_calls();
    assert_eq!(publish.len(), 1);
    assert_eq!(publish[0].1.as_deref(), Some(builder_url));
}

// --- Issue 7.4b: Preferences broadcast across the Gloas boundary ---

fn post_hits(requests: &[wiremock::Request], path: &str) -> usize {
    requests
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == path)
        .count()
}

fn signed_proposer_preferences(
    requests: &[wiremock::Request],
) -> Vec<eth_types::SignedProposerPreferences> {
    requests
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path() == "/eth/v1/validator/proposer_preferences"
        })
        .flat_map(|r| {
            serde_json::from_slice::<Vec<eth_types::SignedProposerPreferences>>(&r.body)
                .unwrap_or_else(|e| panic!("proposer_preferences body must be a JSON array: {e}"))
        })
        .collect()
}

async fn setup_proposer_duty_http(
    mock_server: &wiremock::MockServer,
    epoch: u64,
    slot: u64,
    pubkey_hex: &str,
    validator_index: u64,
    version: &str,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    Mock::given(method("GET"))
        .and(path(format!("/eth/{version}/validator/duties/proposer/{epoch}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": validator_index.to_string(),
                "slot": slot.to_string()
            }]
        })))
        .mount(mock_server)
        .await;
}

/// `SignedProposerPreferences` is advertised one epoch ahead of a Gloas
/// proposal (slot 2240 during epoch 69) and supersedes
/// `prepare_beacon_proposer` / `register_validator` at epoch 70.
///
/// RED: with `builder_service: None` the slot-2240 preferences assertion fails.
#[tokio::test]
async fn test_gloas_preferences_broadcast_one_epoch_ahead() {
    use crypto::{signing_root_for, DutyRef, Signature, SigningCtx};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let mock_server = wiremock::MockServer::start().await;
    let fulu_slot = PRE_GLOAS_SLOT;
    let gloas_slot = GLOAS_SLOT;
    let fulu_epoch = fulu_slot / SLOTS_PER_EPOCH;
    let gloas_epoch = gloas_slot / SLOTS_PER_EPOCH;
    assert_eq!(fulu_epoch, 69, "slot 2208 is epoch 69");
    assert_eq!(gloas_epoch, 70, "slot 2240 is epoch 70");

    let (orchestrator, _handle, pubkey_hex, _capturing) =
        build_fork_transition_orchestrator_with_builder(&mock_server.uri(), fulu_slot).await;

    // Pinned test schedule routes Gloas proposer duties to v2.
    setup_proposer_duty_http(
        &mock_server,
        gloas_epoch,
        gloas_slot,
        &pubkey_hex,
        PROPOSER_INDEX,
        "v2",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/register_validator"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_proposer_duties(gloas_epoch).await.unwrap();

    orchestrator.duty_management.on_epoch_boundary(fulu_epoch, fulu_slot).await;
    orchestrator.run_builder_epoch_boundary(fulu_epoch).await;

    let after_69 = mock_server.received_requests().await.unwrap();
    let prefs_69 = signed_proposer_preferences(&after_69);
    let slots_69: Vec<u64> = prefs_69.iter().map(|p| p.message.proposal_slot).collect();
    assert_eq!(
        slots_69.iter().filter(|slot| **slot == gloas_slot).count(),
        1,
        "SignedProposerPreferences for slot 2240 must be observed exactly once during epoch 69, got {slots_69:?}"
    );
    assert_eq!(prefs_69.len(), 1, "epoch 69 must broadcast only the upcoming Gloas slot");
    assert_eq!(prefs_69[0].message.proposal_slot, gloas_slot);
    assert_eq!(prefs_69[0].message.validator_index, PROPOSER_INDEX);
    assert_eq!(prefs_69[0].message.fee_recipient, [0u8; 20]);
    assert_eq!(prefs_69[0].message.target_gas_limit, 100);

    let pubkey_bytes: [u8; 48] = hex::decode(pubkey_hex.trim_start_matches("0x"))
        .expect("pubkey hex")
        .try_into()
        .expect("compressed pubkey is 48 bytes");
    let pubkey = PublicKey::from_bytes(&pubkey_bytes).expect("pubkey");
    let sig = Signature::from_bytes(&prefs_69[0].signature).expect("preferences signature");
    let schedule = create_test_fork_schedule();
    let ctx = SigningCtx { fork_schedule: schedule.as_ref(), genesis_validators_root: [0xaa; 32] };
    let prefs_signing = signing_root_for(&DutyRef::ProposerPreferences(&prefs_69[0].message), &ctx);
    sig.verify(&pubkey, &prefs_signing).expect(
        "preferences must verify under DOMAIN_PROPOSER_PREFERENCES at the proposal-slot fork",
    );
    let proposer_signing =
        signing_root_for(&DutyRef::BlockRoot { root: &[0u8; 32], slot: gloas_slot }, &ctx);
    assert!(
        sig.verify(&pubkey, &proposer_signing).is_err(),
        "preferences must not verify under DOMAIN_BEACON_PROPOSER"
    );

    assert_eq!(
        post_hits(&after_69, "/eth/v1/validator/prepare_beacon_proposer"),
        1,
        "pre-Gloas epoch 69 must issue prepare_beacon_proposer once"
    );
    assert_eq!(
        post_hits(&after_69, "/eth/v1/validator/register_validator"),
        1,
        "pre-Gloas epoch 69 must issue register_validator once"
    );

    // Cold registration cache: a missing Gloas gate would POST register again.
    orchestrator
        .builder_service
        .as_ref()
        .expect("builder attached")
        .clear_cached_registrations()
        .await;

    orchestrator.clock.set_slot(gloas_slot);
    orchestrator.duty_management.on_epoch_boundary(gloas_epoch, gloas_slot).await;
    orchestrator.run_builder_epoch_boundary(gloas_epoch).await;

    let after_70 = mock_server.received_requests().await.unwrap();
    let epoch_70 = &after_70[after_69.len()..];
    let prefs_70_slots: Vec<u64> =
        signed_proposer_preferences(epoch_70).iter().map(|p| p.message.proposal_slot).collect();
    assert!(
        !prefs_70_slots.contains(&gloas_slot),
        "slot 2240 must not be re-broadcast at epoch 70, got {prefs_70_slots:?}"
    );
    assert_eq!(
        signed_proposer_preferences(&after_70)
            .iter()
            .filter(|p| p.message.proposal_slot == gloas_slot)
            .count(),
        1,
        "slot 2240 preferences must remain exactly once after epoch 70"
    );
    assert_eq!(
        post_hits(epoch_70, "/eth/v1/validator/prepare_beacon_proposer"),
        0,
        "epoch 70 must not call prepare_beacon_proposer"
    );
    assert_eq!(
        post_hits(epoch_70, "/eth/v1/validator/register_validator"),
        0,
        "epoch 70 must not call register_validator"
    );
}
