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

    orchestrator.duty_management.prepare_proposers(3).await;
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

    orchestrator.duty_management.prepare_proposers(0).await;
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
    orchestrator.duty_management.prepare_proposers(3).await;
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
    pubkey_map_inner.insert(duty_pk_bytes, pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the mapped local pubkey so the per-validator
    // signing gate permits committee subscription (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
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

    // Attester/proposer caches populated; PTC skipped (epochs 10/11 are pre-Gloas).
    assert!(duty_tracker.is_epoch_cached(10).await);
    assert!(duty_tracker.is_epoch_cached(11).await);
    assert!(duty_tracker.is_proposer_epoch_cached(10).await);
    assert!(duty_tracker.is_proposer_epoch_cached(11).await);
    assert!(!duty_tracker.is_ptc_epoch_cached(10).await);
    assert!(!duty_tracker.is_ptc_epoch_cached(11).await);
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_uncached_fetches_ptc_when_gloas_active() {
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

    // create_test_config schedules Gloas at epoch 70.
    let gloas_epoch = 70u64;
    let slot = gloas_epoch * ::timing::SLOTS_PER_EPOCH;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

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

    orchestrator.duty_management.check_reorg_at_epoch_boundary(gloas_epoch).await;

    assert!(duty_tracker.is_epoch_cached(gloas_epoch).await);
    assert!(duty_tracker.is_epoch_cached(gloas_epoch + 1).await);
    assert!(duty_tracker.is_proposer_epoch_cached(gloas_epoch).await);
    assert!(duty_tracker.is_proposer_epoch_cached(gloas_epoch + 1).await);
    assert!(duty_tracker.is_ptc_epoch_cached(gloas_epoch).await);
    assert!(duty_tracker.is_ptc_epoch_cached(gloas_epoch + 1).await);
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

    // Pre-Gloas: 4 calls (attester+proposer × current/next), each bounded by
    // duty_fetch (200ms). PTC is gated out. Without timeout wrapping this would
    // take 4 * 700ms ≈ 2.8s. With timeouts: 4 * 200ms = 800ms + margin.
    assert!(
        elapsed < timeouts.duty_fetch * 5,
        "Reorg check took {:?}, expected < {:?} (4 timeouts + margin)",
        elapsed,
        timeouts.duty_fetch * 5
    );
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_timeout_bounds_slow_beacon_when_gloas_active() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slow_response = serde_json::json!({
        "data": [],
        "dependent_root": "0xslow_root",
        "execution_optimistic": false
    });

    let timeouts = fast_timeouts();

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

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/ptc/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&slow_response)
                .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
        )
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(30))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let gloas_epoch = 70u64;
    let slot = gloas_epoch * ::timing::SLOTS_PER_EPOCH;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

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
    orchestrator.duty_management.check_reorg_at_epoch_boundary(gloas_epoch).await;
    let elapsed = start.elapsed();

    // Gloas+: 6 calls (attester+proposer+ptc × current/next), each bounded by
    // duty_fetch (200ms). With timeouts: 6 * 200ms = 1.2s + margin.
    assert!(
        elapsed < timeouts.duty_fetch * 7,
        "Gloas reorg check took {:?}, expected < {:?} (6 timeouts + margin)",
        elapsed,
        timeouts.duty_fetch * 7
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

    // Should not panic even with broken beacon (pre-Gloas: PTC path not entered)
    orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
}

#[tokio::test]
async fn test_check_reorg_at_epoch_boundary_survives_error_when_gloas_active() {
    // Broken beacon must not panic once the PTC reorg arm is entered at Gloas+.
    let beacon_config = beacon::BeaconClientConfig::new("http://127.0.0.1:1")
        .with_timeout(Duration::from_millis(100))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let gloas_epoch = 70u64;
    let slot = gloas_epoch * ::timing::SLOTS_PER_EPOCH;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

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

    orchestrator.duty_management.check_reorg_at_epoch_boundary(gloas_epoch).await;
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
    orchestrator.duty_management.prepare_proposers(3).await;
    let after = duty_tracker.slot_duty_lookup_count();
    let lookups = after - before;

    // Registry path: no duty-cache scans. Old path was ~N×64×2 epoch slots.
    assert_eq!(
        lookups, 0,
        "prepare_proposers must not scan the duty cache (observed {lookups} get_duties_for_slot \
         calls; pre-fix O(v×64×d) for N={N} was typically hundreds)"
    );
}

// --- Gloas retirement of prepare_beacon_proposer / register_validators ---

const ZERO_DEPENDENT_ROOT: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

fn near_gloas_schedule(gloas_epoch: u64) -> Arc<ForkSchedule> {
    let mut schedule = (*create_test_fork_schedule()).clone();
    schedule.gloas_fork_epoch = gloas_epoch;
    Arc::new(schedule)
}

fn empty_dependent<T>() -> beacon::DependentRootResponse<Vec<T>> {
    beacon::DependentRootResponse {
        dependent_root: ZERO_DEPENDENT_ROOT.to_string(),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

fn pubkey_hex(pk: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pk))
}

fn proposer_duty(pubkey_hex: &str, index: &str, slot: u64) -> beacon::ProposerDuty {
    beacon::ProposerDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: index.to_string(),
        slot: slot.to_string(),
    }
}

fn retirement_beacon_base() -> bn_manager::MockBeaconNodeClient {
    bn_manager::MockBeaconNodeClient::new()
        .with_get_attester_duties(|_e, _i| Ok(empty_dependent()))
        .with_post_ptc_duties(|_e, _i| Ok(empty_dependent()))
        .with_post_sync_committee_duties(|_e, _i| {
            Ok(beacon::ExecutionOptimisticResponse {
                execution_optimistic: false,
                data: Vec::new(),
            })
        })
        .with_prepare_beacon_proposer(|_p| Ok(()))
        .with_register_validators(|_r| Ok(()))
        .with_submit_proposer_preferences(|_p| Ok(()))
        .with_submit_builder_preferences(|_e| Ok(beacon::SubmitBuilderPreferencesResult::Success))
        .with_submit_beacon_committee_subscriptions(|_s| Ok(()))
}

fn retirement_beacon() -> bn_manager::MockBeaconNodeClient {
    retirement_beacon_base().with_get_proposer_duties(|_e| Ok(empty_dependent()))
}

fn retirement_beacon_with_mixed_duties(
    local_hex: String,
    disabled_hex: String,
    foreign_hex: String,
) -> bn_manager::MockBeaconNodeClient {
    retirement_beacon_base().with_get_proposer_duties(move |epoch| {
        let slots = ::timing::SLOTS_PER_EPOCH;
        Ok(beacon::DependentRootResponse {
            dependent_root: ZERO_DEPENDENT_ROOT.to_string(),
            execution_optimistic: false,
            data: vec![
                proposer_duty(&local_hex, "42", epoch * slots + 5),
                proposer_duty(&disabled_hex, "43", epoch * slots + 6),
                proposer_duty(&foreign_hex, "99", epoch * slots + 7),
            ],
        })
    })
}

fn retirement_beacon_legacy_errors() -> bn_manager::MockBeaconNodeClient {
    use beacon::BeaconError;
    retirement_beacon()
        .with_prepare_beacon_proposer(|_p| {
            Err(BeaconError::ApiError { status: 404, message: "not found".into() })
        })
        .with_register_validators(|_r| {
            Err(BeaconError::ApiError { status: 501, message: "not implemented".into() })
        })
}

struct RetirementDrive {
    mock: Arc<bn_manager::MockBeaconNodeClient>,
}

async fn drive_prepare_and_register(
    epoch: u64,
    schedule: Arc<ForkSchedule>,
    mock: bn_manager::MockBeaconNodeClient,
    local: (SecretKey, bool),
    extra_locals: Vec<(SecretKey, bool)>,
    foreign_keys: Vec<SecretKey>,
) -> RetirementDrive {
    use signer::ValidatorSigner;
    use validator_store::ValidatorConfig;

    let mock = Arc::new(mock);
    mock.track_admission();
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
    let slot = epoch * ::timing::SLOTS_PER_EPOCH;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), slot));
    clock.set_slot(slot);

    let local_pk = local.0.public_key().to_bytes();
    let mut key_manager = KeyManager::new();
    let mut pubkey_map_inner = HashMap::new();
    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

    let mut keys = vec![local];
    keys.extend(extra_locals);
    for (sk, signing_enabled) in keys {
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let mut cfg = ValidatorConfig::new(pk_bytes);
        cfg.builder_proposals = true;
        cfg.enabled = signing_enabled;
        if signing_enabled {
            cfg.builders = Some(vec!["https://builder.example.com".to_string()]);
        }
        validator_store.add_validator(cfg).unwrap();
        pubkey_map_inner.insert(pk_bytes, pk);
        key_manager.insert(sk);
    }
    // Signable but not in pubkey_map: a missing find_pubkey gate would submit these.
    for sk in foreign_keys {
        key_manager.insert(sk);
    }

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let vs: Arc<dyn ValidatorSigner> = signer.clone();
    let builder_service = Some(Arc::new(BuilderService::new(
        Arc::new(vs),
        Arc::new(beacon.clone()),
        validator_store.clone(),
        schedule.genesis_fork_version,
        schedule.clone(),
    )));

    let duty_tracker = Arc::new(
        DutyTracker::new(mock.clone(), vec!["42".to_string(), "43".to_string()])
            .with_fork_schedule((*schedule).clone()),
    );

    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = OrchestratorConfig::new([0xaau8; 32], schedule);

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
    deps.pubkey_index.write().insert(local_pk, "42".to_string());
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    orchestrator.duty_management.on_epoch_boundary(epoch, slot).await;
    orchestrator.run_builder_epoch_boundary(epoch).await;
    RetirementDrive { mock }
}

#[tokio::test]
async fn test_prepare_and_register_retired_only_at_gloas() {
    let gloas_epoch = 100u64;
    let schedule = near_gloas_schedule(gloas_epoch);
    assert_eq!(ForkName::from_epoch(gloas_epoch - 1, &schedule), ForkName::Fulu);
    assert_eq!(ForkName::from_epoch(gloas_epoch, &schedule), ForkName::Gloas);

    let expected_fee = format!("0x{}", hex::encode([0xffu8; 20]));
    let slots = ::timing::SLOTS_PER_EPOCH;

    for (epoch, retired) in [(gloas_epoch - 1, false), (gloas_epoch, true)] {
        let local = SecretKey::generate();
        let disabled = SecretKey::generate();
        let foreign = SecretKey::generate();
        let local_hex = pubkey_hex(&local.public_key().to_bytes());
        let disabled_hex = pubkey_hex(&disabled.public_key().to_bytes());
        let foreign_hex = pubkey_hex(&foreign.public_key().to_bytes());
        let mock = retirement_beacon_with_mixed_duties(local_hex, disabled_hex, foreign_hex);
        let driven = drive_prepare_and_register(
            epoch,
            schedule.clone(),
            mock,
            (local, true),
            vec![(disabled, false)],
            vec![foreign],
        )
        .await;

        let prepare = driven.mock.prepare_beacon_proposer_calls();
        let register = driven.mock.register_validators_calls();
        let prefs = driven.mock.submit_proposer_preferences_calls();
        let builder_prefs = driven.mock.submit_builder_preferences_calls();
        if retired {
            assert!(
                prepare.is_empty(),
                "Gloas epoch {epoch}: prepare_beacon_proposer must not be called"
            );
            assert!(
                register.is_empty(),
                "Gloas epoch {epoch}: register_validators must not be called"
            );
            assert_eq!(prefs.len(), 1, "Gloas epoch {epoch}: one preferences POST");
            assert_eq!(prefs[0].len(), 2, "Gloas arm: current + next epoch local slots only");
            let current_slot = gloas_epoch * slots + 5;
            let next_slot = (gloas_epoch + 1) * slots + 5;
            let slots_sent: Vec<u64> =
                prefs.iter().flatten().map(|p| p.message.proposal_slot).collect();
            assert!(
                slots_sent.contains(&current_slot),
                "Gloas arm must advertise remaining current-epoch Gloas slot {current_slot}, got {slots_sent:?}"
            );
            assert!(
                slots_sent.contains(&next_slot),
                "Gloas arm must advertise Gloas+1 slot {next_slot}, got {slots_sent:?}"
            );
            assert_eq!(builder_prefs.len(), 1, "Gloas epoch {epoch}: one builder_preferences POST");
            assert_eq!(builder_prefs[0].len(), 2, "Gloas arm: one entry per Gloas slot × builder");
            let builder_slots: Vec<u64> =
                builder_prefs.iter().flatten().map(|e| e.auth.message.slot).collect();
            assert!(builder_slots.contains(&current_slot), "got {builder_slots:?}");
            assert!(builder_slots.contains(&next_slot), "got {builder_slots:?}");
            for entry in builder_prefs.iter().flatten() {
                assert_eq!(entry.url, "https://builder.example.com");
            }
        } else {
            assert_eq!(prepare.len(), 1, "pre-Gloas prepare call count");
            assert_eq!(prepare[0].len(), 1);
            assert_eq!(prepare[0][0].validator_index, "42");
            assert_eq!(prepare[0][0].fee_recipient, expected_fee);
            assert_eq!(register.len(), 1, "pre-Gloas register call count");
            assert_eq!(register[0].len(), 1);
            assert_eq!(register[0][0].message.fee_recipient, [0xffu8; 20]);
            assert_eq!(register[0][0].message.gas_limit, 30_000_000);
            assert_eq!(prefs.len(), 1, "Gloas-1 must submit preferences for Gloas slots");
            assert_eq!(prefs[0].len(), 1);
            assert_eq!(prefs[0][0].message.proposal_slot, gloas_epoch * slots + 5);
            assert_eq!(prefs[0][0].message.validator_index, 42);
            assert_eq!(prefs[0][0].message.fee_recipient, [0xffu8; 20]);
            assert_eq!(
                builder_prefs.len(),
                1,
                "Gloas-1 must submit builder_preferences for Gloas slots"
            );
            assert_eq!(builder_prefs[0].len(), 1);
            assert_eq!(builder_prefs[0][0].auth.message.slot, gloas_epoch * slots + 5);
            assert_eq!(builder_prefs[0][0].url, "https://builder.example.com");
        }

        for signed in prefs.iter().flatten() {
            assert_eq!(
                signed.message.fee_recipient, [0xffu8; 20],
                "only the local validator's fee recipient"
            );
            assert_ne!(signed.message.validator_index, 99, "foreign duty must not be signed");
            assert_ne!(signed.message.validator_index, 43, "disabled local must not be signed");
        }
    }
}

#[tokio::test]
async fn test_legacy_404_or_501_does_not_retire_prepare_or_register() {
    let gloas_epoch = 100u64;
    let schedule = near_gloas_schedule(gloas_epoch);
    let epoch = gloas_epoch - 1;
    assert_ne!(ForkName::from_epoch(epoch, &schedule), ForkName::Gloas);

    let local = SecretKey::generate();
    let driven = drive_prepare_and_register(
        epoch,
        schedule,
        retirement_beacon_legacy_errors(),
        (local, true),
        vec![],
        vec![],
    )
    .await;
    assert_eq!(
        driven.mock.prepare_beacon_proposer_calls().len(),
        1,
        "BN 404 must not skip prepare_beacon_proposer"
    );
    assert_eq!(
        driven.mock.register_validators_calls().len(),
        1,
        "BN 501 must not skip register_validators"
    );
}

#[test]
fn test_retirement_gate_reads_only_fork_name_from_epoch() {
    let gloas_epoch = 100u64;
    let schedule = near_gloas_schedule(gloas_epoch);
    assert!(!::builder::legacy_proposer_ops_retired(ForkName::from_epoch(
        gloas_epoch - 1,
        &schedule
    )));
    assert!(::builder::legacy_proposer_ops_retired(ForkName::from_epoch(gloas_epoch, &schedule)));
}

#[tokio::test]
async fn test_proposer_root_change_rebroadcasts_preferences() {
    use signer::ValidatorSigner;
    use validator_store::ValidatorConfig;

    const ROOT_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let gloas_epoch = 100u64;
    let schedule = near_gloas_schedule(gloas_epoch);
    let local = SecretKey::generate();
    let local_pk = local.public_key().to_bytes();
    let local_hex = pubkey_hex(&local_pk);
    let mock = Arc::new(retirement_beacon());
    mock.track_admission();
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
    let slot = gloas_epoch * ::timing::SLOTS_PER_EPOCH;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), slot));
    clock.set_slot(slot);

    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
    let mut cfg = ValidatorConfig::new(local_pk);
    cfg.builder_proposals = true;
    cfg.builders = Some(vec!["https://builder.example.com".to_string()]);
    validator_store.add_validator(cfg).unwrap();

    let mut key_manager = KeyManager::new();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(local_pk, local.public_key());
    key_manager.insert(local);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let vs: Arc<dyn ValidatorSigner> = signer.clone();
    let builder_service = Some(Arc::new(BuilderService::new(
        Arc::new(vs),
        Arc::new(beacon.clone()),
        validator_store.clone(),
        schedule.genesis_fork_version,
        schedule.clone(),
    )));
    let duty_tracker = Arc::new(
        DutyTracker::new(mock.clone(), vec!["42".to_string()])
            .with_fork_schedule((*schedule).clone()),
    );
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let config = OrchestratorConfig::new([0xaau8; 32], schedule);
    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker.clone(),
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        builder_service,
        validator_store,
        config,
        pubkey_map,
    );
    deps.pubkey_index.write().insert(local_pk, "42".to_string());
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);

    let proposal_slot = gloas_epoch * ::timing::SLOTS_PER_EPOCH + 5;
    let duties = vec![proposer_duty(&local_hex, "42", proposal_slot)];

    assert!(!duty_tracker.cache_proposer_duties(gloas_epoch, ROOT_A.into(), &duties).await);
    orchestrator.run_builder_epoch_boundary(gloas_epoch).await;
    {
        let calls = mock.submit_proposer_preferences_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert_eq!(
            calls[0][0].message.dependent_root,
            eth_types::canonical::gvr_hex::parse_gvr_hex(ROOT_A).unwrap()
        );
    }

    assert!(duty_tracker.cache_proposer_duties(gloas_epoch, ROOT_B.into(), &duties).await);
    orchestrator.on_proposer_dependent_root_changed(gloas_epoch).await;
    {
        let calls = mock.submit_proposer_preferences_calls();
        assert_eq!(calls.len(), 2, "root change must invoke one more preferences POST");
        assert_eq!(calls[1].len(), 1);
        assert_eq!(
            calls[1][0].message.dependent_root,
            eth_types::canonical::gvr_hex::parse_gvr_hex(ROOT_B).unwrap()
        );
    }
}

/// Records `produce` so a startup test can see the first proposer duty.
///
/// Slot 2 is not an epoch boundary, so the post-duty epoch-boundary path does
/// not send `prepare_beacon_proposer` before that proposal. Startup
/// preparation runs on its own task and can overlap the proposal.
struct StartupOrderBlockBeacon {
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl BeaconBlockClient for StartupOrderBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        self.log.lock().expect("order log").push("produce");
        Ok(ProduceBlockResponse {
            data: serde_json::json!({
                "slot": "2",
                "proposer_index": "7",
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body": {}
            }),
            is_blinded: false,
            consensus_version: "phase0".to_string(),
            execution_payload_value: Some("1".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
            candidate_memo: beacon::CandidateMemo::arc(),
        })
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        Err(block_service::BlockServiceError::Beacon("produce_block_v4 not configured".into()))
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }

    async fn publish_execution_payload_envelope(
        &self,
        _signed_envelope: &WireBody,
        _blobs: &WireBody,
        _kzg_proofs: &WireBody,
        _consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }
}

struct StartupFeeRun {
    mock: Arc<bn_manager::MockBeaconNodeClient>,
    clock: Arc<MockSlotClock>,
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    handle: OrchestratorHandle,
    run: tokio::task::JoinHandle<Result<(), super::super::OrchestratorError>>,
}

fn fee_hex(fee: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(fee))
}

/// Local validator index 7, default fee `0xff`, slot 2 (not an epoch boundary).
async fn spawn_startup_fee_run(
    mock: bn_manager::MockBeaconNodeClient,
    clock: Arc<MockSlotClock>,
    timeouts: OperationTimeouts,
    seed_duty: bool,
) -> StartupFeeRun {
    use signer::ValidatorSigner;
    use validator_store::{BlockSelectionMode, ValidatorConfig};

    let log = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
    let local = SecretKey::generate();
    let local_pk = local.public_key().to_bytes();
    let local_hex = pubkey_hex(&local_pk);
    let slot: Slot = 2;
    let epoch = slot / ::timing::SLOTS_PER_EPOCH;

    let mock = mock.with_get_proposer_duties(move |e| {
        if e == epoch && seed_duty {
            Ok(beacon::DependentRootResponse {
                dependent_root: ZERO_DEPENDENT_ROOT.to_string(),
                execution_optimistic: false,
                data: vec![proposer_duty(&local_hex, "7", slot)],
            })
        } else {
            Ok(empty_dependent())
        }
    });
    let mock = Arc::new(mock);
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();

    let mut key_manager = KeyManager::new();
    key_manager.insert(local);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
    let mut cfg = ValidatorConfig::new(local_pk);
    cfg.builder_proposals = true;
    validator_store.add_validator(cfg).unwrap();
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let schedule = create_test_fork_schedule();
    let vs: Arc<dyn ValidatorSigner> = signer.clone();
    let builder_service = Some(Arc::new(BuilderService::new(
        Arc::new(vs),
        Arc::new(beacon.clone()),
        validator_store.clone(),
        schedule.genesis_fork_version,
        schedule.clone(),
    )));

    let duty_tracker = Arc::new(DutyTracker::new(mock.clone(), vec!["7".to_string()]));
    if seed_duty {
        duty_tracker.fetch_proposer_duties(epoch).await.expect("seed proposer duty");
    }

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(local_pk, local_pk_public(&local_pk));
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
    let config = OrchestratorConfig::new([0xaau8; 32], schedule).with_timeouts(timeouts);
    let deps = OrchestratorDeps::for_test(
        Arc::clone(&clock),
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon,
        Arc::new(StartupOrderBlockBeacon { log: Arc::clone(&log) }),
        builder_service,
        validator_store,
        config,
        pubkey_map,
    );
    deps.pubkey_index.write().insert(local_pk, "7".to_string());
    let (mut orchestrator, handle) = DutyOrchestrator::new(deps);
    let run = tokio::spawn(async move { orchestrator.run().await });
    StartupFeeRun { mock, clock, log, handle, run }
}

async fn shutdown_startup_fee_run(started: StartupFeeRun) {
    started.handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(500), started.run).await;
}

#[tokio::test]
async fn test_prepare_and_register_payloads_at_startup() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(2);
    clock.advance_time(9);
    let started =
        spawn_startup_fee_run(retirement_beacon_base(), Arc::clone(&clock), fast_timeouts(), true)
            .await;

    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let produced = started.log.lock().expect("order log").contains(&"produce");
            let prepared = !started.mock.prepare_beacon_proposer_calls().is_empty();
            let registered = !started.mock.register_validators_calls().is_empty();
            if produced && prepared && registered {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let prepares = started.mock.prepare_beacon_proposer_calls();
    let registers = started.mock.register_validators_calls();
    shutdown_startup_fee_run(started).await;

    assert!(ready.is_ok(), "startup prepare, register, and the proposer duty must run");
    let fee = fee_hex(&[0xff; 20]);
    assert_eq!(prepares[0].len(), 1);
    assert_eq!(prepares[0][0].validator_index, "7");
    assert_eq!(prepares[0][0].fee_recipient, fee);
    assert_eq!(registers[0][0].message.fee_recipient, [0xff; 20]);
}

#[tokio::test]
async fn test_startup_preparation_retries_a_failed_prepare_next_slot() {
    use beacon::BeaconError;

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_hook = Arc::clone(&attempts);
    let mock = retirement_beacon_base().with_prepare_beacon_proposer(move |_preparations| {
        if attempts_hook.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(BeaconError::ApiError { status: 500, message: "unavailable".into() })
        } else {
            Ok(())
        }
    });
    // 100 ms left in slot 2, so the per-slot retry is short.
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot_with_offset_ms(2, 11_900);
    let started = spawn_startup_fee_run(mock, Arc::clone(&clock), fast_timeouts(), false).await;

    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if started.mock.prepare_beacon_proposer_calls().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let calls = started.mock.prepare_beacon_proposer_calls().len();
    shutdown_startup_fee_run(started).await;

    assert!(ready.is_ok(), "a failed prepare must be retried within 2s; calls={calls}");
    assert!(calls >= 2, "startup must POST prepare again after the first failure; calls={calls}");
    assert!(attempts.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn test_startup_preparation_uses_epoch_zero_before_genesis() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let genesis_ms = TEST_GENESIS_TIME.saturating_mul(1000);
    clock.set_current_time_ms(genesis_ms - 50);
    assert!(
        matches!(clock.current_slot(), Err(::timing::TimingError::BeforeGenesis { .. })),
        "fixture must still be before genesis"
    );
    let started =
        spawn_startup_fee_run(retirement_beacon_base(), Arc::clone(&clock), fast_timeouts(), false)
            .await;

    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !started.mock.prepare_beacon_proposer_calls().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let prepares = started.mock.prepare_beacon_proposer_calls();
    let still_before =
        matches!(started.clock.current_slot(), Err(::timing::TimingError::BeforeGenesis { .. }));
    shutdown_startup_fee_run(started).await;

    assert!(ready.is_ok(), "prepare_beacon_proposer must run before genesis");
    assert!(still_before, "the clock must still be before genesis when prepare is sent");
    assert_eq!(prepares[0][0].validator_index, "7");
    assert_eq!(prepares[0][0].fee_recipient, fee_hex(&[0xff; 20]));
}

#[tokio::test]
async fn test_startup_preparation_does_not_block_the_proposer_duty() {
    use bn_manager::MockMethod;

    let mock = retirement_beacon_base()
        .with_method_delay(MockMethod::PrepareBeaconProposer, Duration::from_secs(5));
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(2);
    clock.advance_time(9);
    let mut timeouts = fast_timeouts();
    // Longer than the wait below, so the timed wrapper does not cancel the
    // in-flight prepare and hide a blocked slot loop.
    timeouts.preparation = Duration::from_secs(5);
    let started = spawn_startup_fee_run(mock, clock, timeouts, true).await;

    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let produced = started.log.lock().expect("order log").contains(&"produce");
            let arrived = started
                .mock
                .call_stamps()
                .iter()
                .any(|stamp| stamp.method == MockMethod::PrepareBeaconProposer);
            if produced && arrived {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let prepare_finished = !started.mock.prepare_beacon_proposer_calls().is_empty();
    shutdown_startup_fee_run(started).await;

    assert!(
        ready.is_ok(),
        "the proposer duty must run while prepare_beacon_proposer is still in flight"
    );
    assert!(
        !prepare_finished,
        "prepare must still be sleeping when the proposer duty has already run"
    );
}

fn local_pk_public(bytes: &[u8; 48]) -> PublicKey {
    PublicKey::from_bytes(bytes).expect("pubkey bytes")
}
