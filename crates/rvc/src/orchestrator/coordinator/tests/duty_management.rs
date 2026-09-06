//! Coordinator tests: proposer preparation, committee subscriptions, epoch reorg.

use super::*;

// --- B-05: Proposer preparation tests ---

#[tokio::test]
async fn test_prepare_proposers_sends_preparations() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Mock attester duties endpoint to seed the duty tracker cache
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "4",
                "validator_committee_index": "10",
                "slot": "96"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Mock proposer preparation endpoint
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Slot 96 = epoch 3, slot 0 of epoch
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
    clock.set_slot(96);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));

    // Fetch duties to populate the cache
    duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    // O(1) prepare_proposers path uses the shared registry, not duty scans.
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store,
        config,
        pubkey_map,
    );
    deps.pubkey_index.write().insert(pubkey.to_bytes(), "42".to_string());
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    orchestrator.duty_management.prepare_proposers().await;
    // wiremock will verify expect(1) on drop
}

#[tokio::test]
async fn test_prepare_proposers_no_validators_no_call() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Mock should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 0));
    clock.set_slot(0);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    orchestrator.duty_management.prepare_proposers().await;
}

#[tokio::test]
async fn test_prepare_proposers_failure_is_non_fatal() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Mock attester duties to seed cache
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "validator_index": "99",
                "committee_index": "0",
                "committee_length": "64",
                "committees_at_slot": "2",
                "validator_committee_index": "5",
                "slot": "96"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Return error for prepare_beacon_proposer
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
    clock.set_slot(96);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["99".to_string()]));

    duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store,
        config,
        pubkey_map,
    );
    deps.pubkey_index.write().insert(pubkey.to_bytes(), "99".to_string());
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    // Should not panic - failure is non-fatal
    orchestrator.duty_management.prepare_proposers().await;
}

// --- B-05: Committee subscription tests ---

#[tokio::test]
async fn test_submit_committee_subscriptions_sends_subscriptions() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Mock attester duties
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "validator_index": "10",
                "committee_index": "2",
                "committee_length": "128",
                "committees_at_slot": "4",
                "validator_committee_index": "7",
                "slot": "100"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Mock committee subscription endpoint
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
    clock.set_slot(96);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["10".to_string()]));
    duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    // Mock duty pubkey is 0xcc… with 98 hex digits (49 bytes) historically —
    // parse fails. Use a valid 48-byte 0xcc key that matches a re-parsed duty,
    // and keep the mock duty string at exactly 96 hex digits.
    let duty_pk_bytes = [0xccu8; 48];
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(duty_pk_bytes, pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    orchestrator.duty_management.submit_committee_subscriptions(3).await;
    // wiremock will verify expect(1) on drop
}

#[tokio::test]
async fn test_submit_committee_subscriptions_no_duties_no_call() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Mock should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 0));
    clock.set_slot(0);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    orchestrator.duty_management.submit_committee_subscriptions(0).await;
}

#[tokio::test]
async fn test_submit_committee_subscriptions_failure_is_non_fatal() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "validator_index": "55",
                "committee_index": "0",
                "committee_length": "64",
                "committees_at_slot": "2",
                "validator_committee_index": "3",
                "slot": "97"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Return error for subscriptions
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
    clock.set_slot(96);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["55".to_string()]));
    duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let duty_pk_bytes = [0xddu8; 48];
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(duty_pk_bytes, pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // Should not panic
    orchestrator.duty_management.submit_committee_subscriptions(3).await;
}

// NOTE: Tests for builder registration behavior (called_at_epoch_boundary,
// nonfatal_on_failure, skipped_when_no_builder_service,
// skips_non_builder_validators) were removed after CON-01 refactored
// register_builders() into the main loop via tokio::select!.
// Builder registration is now tested implicitly through the main loop tests.

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_no_change() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let attester_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xstable_root",
        "execution_optimistic": false
    });

    let proposer_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xstable_root",
        "execution_optimistic": false
    });

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&attester_response))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&proposer_response))
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(5))
        .with_max_retries(1);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    // Pre-populate caches
    duty_tracker.fetch_duties_for_epoch(10).await.unwrap();
    duty_tracker.fetch_duties_for_epoch(11).await.unwrap();
    duty_tracker.fetch_proposer_duties(10).await.unwrap();
    duty_tracker.fetch_proposer_duties(11).await.unwrap();

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(320);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // Should not panic, should complete successfully
    orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_uncached_fetches() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let attester_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xnew_root",
        "execution_optimistic": false
    });

    let proposer_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xnew_root",
        "execution_optimistic": false
    });

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&attester_response))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&proposer_response))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/ptc/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&attester_response))
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(5))
        .with_max_retries(1);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(320);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker.clone(),
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // No caches populated — should fetch and not panic
    orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;

    // Caches should now be populated
    assert!(duty_tracker.is_epoch_cached(10).await);
    assert!(duty_tracker.is_epoch_cached(11).await);
    assert!(duty_tracker.is_proposer_epoch_cached(10).await);
    assert!(duty_tracker.is_proposer_epoch_cached(11).await);
    assert!(duty_tracker.is_ptc_epoch_cached(10).await);
    assert!(duty_tracker.is_ptc_epoch_cached(11).await);
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_timeout_bounds_slow_beacon() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slow_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xslow_root",
        "execution_optimistic": false
    });

    let timeouts = fast_timeouts();

    // Respond slower than duty_fetch timeout (200ms)
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&slow_response)
                .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&slow_response)
                .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
        )
        .mount(&mock_server)
        .await;

    // HTTP timeout must exceed duty_fetch timeout so the tokio timeout fires first
    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(30))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(320);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = create_test_config().with_timeouts(timeouts.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    let start = std::time::Instant::now();
    orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
    let elapsed = start.elapsed();

    // 4 calls each bounded by duty_fetch timeout (200ms).
    // Without timeout wrapping this would take 4 * 700ms ≈ 2.8s.
    // With timeouts: 4 * 200ms = 800ms + margin.
    assert!(
        elapsed < timeouts.duty_fetch * 5,
        "Reorg check took {:?}, expected < {:?} (4 timeouts + margin)",
        elapsed,
        timeouts.duty_fetch * 5
    );
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_survives_error() {
    // Use a broken beacon endpoint to verify errors are logged not propagated
    let beacon_config = beacon::BeaconClientConfig::new("http://127.0.0.1:1")
        .with_timeout(Duration::from_millis(100))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(320);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // Should not panic even with broken beacon
    orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
}

// --- RF6-31: prepare_proposers complexity (count-based, not wall-clock) ---

/// Pre-fix, `prepare_proposers` scanned `validators × 64 slots × duties` via
/// `get_duties_for_slot`. With N=8 validators and a fully seeded duty cache that
/// would be on the order of 8 × 64 × 2 epochs × (duties/slot) lookups.
///
/// Post-fix the path uses the shared pubkey→index registry only: **zero**
/// duty-cache lookups. Assert on the access counter, not wall-clock.
#[tokio::test]
async fn test_prepare_proposers_index_lookups_are_linear_in_validators() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const N: usize = 8;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Seed a dense attester duty cache so a naive O(v×64×d) scan would thrash it.
    let duties: Vec<serde_json::Value> = (0..N)
        .map(|i| {
            serde_json::json!({
                "pubkey": format!("0x{}", hex::encode([i as u8 + 1; 48])),
                "validator_index": format!("{}", 1000 + i),
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "1",
                "validator_committee_index": "0",
                "slot": "96"
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": duties
        })))
        .mount(&mock_server)
        .await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
    clock.set_slot(96);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(
        beacon.clone(),
        (0..N).map(|i| format!("{}", 1000 + i)).collect(),
    ));
    duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

    // Build N local validators + seed the shared registry with their indices.
    let mut key_manager = KeyManager::new();
    let mut pubkey_map_inner = HashMap::new();
    let mut secrets = Vec::new();
    for _ in 0..N {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        pubkey_map_inner.insert(pk.to_bytes(), pk);
        secrets.push(sk);
    }
    for sk in secrets {
        key_manager.insert(sk);
    }
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

    let deps = OrchestratorDeps::for_test(
        clock,
        Arc::clone(&duty_tracker),
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store,
        config,
        pubkey_map.clone(),
    );
    for (i, bytes) in pubkey_map.read().keys().enumerate() {
        deps.pubkey_index.write().insert(*bytes, format!("{}", 1000 + i));
    }
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    let before = duty_tracker.slot_duty_lookup_count();
    orchestrator.duty_management.prepare_proposers().await;
    let after = duty_tracker.slot_duty_lookup_count();
    let lookups = after - before;

    // Registry path: no duty-cache scans. Old path was ~N×64×2 epoch slots.
    assert_eq!(
        lookups, 0,
        "prepare_proposers must not scan the duty cache (observed {lookups} get_duties_for_slot \
         calls; pre-fix O(v×64×d) for N={N} was typically hundreds)"
    );
}
