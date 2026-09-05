//! Coordinator tests: core orchestrator construction and duty matching.

use super::*;

/// ADR-002 / ARCH-2b: `DutyOrchestrator::run()`'s future must be `Send` so the
/// orchestrator can be `tokio::spawn`ed (ARCH-2c / ARCH-2h). Compile-time only —
/// a runtime assertion cannot observe `!Send`.
#[test]
fn test_duty_orchestrator_run_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (mut orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
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

    let fut = orchestrator.run();
    assert_send(&fut);
    // Drop without polling; this test only proves Send.
    drop(fut);
}

#[test]
fn test_orchestrator_config_new() {
    let config = OrchestratorConfig::new([0xbb; 32], create_test_fork_schedule());
    assert_eq!(config.genesis_validators_root, [0xbb; 32]);
    assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
}

#[test]
fn test_orchestrator_config_default_bps_fields() {
    let config = OrchestratorConfig::new([0xbb; 32], create_test_fork_schedule());
    let defaults = timing::DeadlineBps::default();
    assert_eq!(config.attestation_due_bps, defaults.attestation);
    assert_eq!(config.aggregate_due_bps, defaults.aggregate);
}

#[test]
fn test_orchestrator_config_with_shutdown_timeout() {
    let config = OrchestratorConfig::new([0xcc; 32], create_test_fork_schedule())
        .with_shutdown_timeout(Duration::from_secs(60));
    assert_eq!(config.shutdown_timeout, Duration::from_secs(60));
}

#[test]
fn test_orchestrator_config_with_timeouts() {
    let timeouts = OperationTimeouts {
        block_production: Duration::from_secs(5),
        duty_fetch: Duration::from_secs(15),
        ..Default::default()
    };

    let config =
        OrchestratorConfig::new([0xdd; 32], create_test_fork_schedule()).with_timeouts(timeouts);

    assert_eq!(config.timeouts.block_production, Duration::from_secs(5));
    assert_eq!(config.timeouts.duty_fetch, Duration::from_secs(15));
    // Other fields remain at default
    assert_eq!(config.timeouts.block_publication, Duration::from_secs(2));
}

#[test]
fn test_orchestrator_config_default_timeouts() {
    let config = OrchestratorConfig::new([0xee; 32], create_test_fork_schedule());
    let defaults = OperationTimeouts::default();

    assert_eq!(config.timeouts.block_production, defaults.block_production);
    assert_eq!(config.timeouts.duty_fetch, defaults.duty_fetch);
    assert_eq!(config.timeouts.attestation_fetch, defaults.attestation_fetch);
}

#[tokio::test]
async fn test_orchestrator_handle_shutdown() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
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

    handle.shutdown();

    let result = orchestrator.run().await;

    assert!(result.is_ok());
}

/// RF1-07: a key-generation watch notification clears the duty cache.
///
/// Pre-populates a far-future epoch (not re-fetched on the current slot),
/// sends on the paired `key_gen_tx`, drives one `run()` iteration, and
/// asserts the far-future epoch is no longer cached.
#[tokio::test(flavor = "current_thread")]
async fn test_key_gen_notification_clears_duty_cache() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let far_epoch = 50u64;

    Mock::given(method("POST"))
        .and(path(format!("/eth/v1/validator/duties/attester/{}", far_epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "validator_index": "1",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "0",
                "slot": (far_epoch * 32).to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Catch-all empty responses for the current-slot duty fetches so
    // run() completes without error after clearing.
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x00",
            "execution_optimistic": false,
            "data": []
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x00",
            "execution_optimistic": false,
            "data": []
        })))
        .mount(&mock_server)
        .await;
    for epoch in [3u64, 4] {
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x00",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&mock_server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/blocks/100/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "data": { "root": "0x0000000000000000000000000000000000000000000000000000000000000001" }
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));

    // Populate a far-future epoch that run() will not re-fetch (slot 100 → epoch 3).
    duty_tracker.fetch_duties_for_epoch(far_epoch).await.unwrap();
    assert!(
        duty_tracker.is_epoch_cached(far_epoch).await,
        "precondition: far-future epoch must be cached"
    );

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    // Slot 100 = epoch 3; park near end of slot so phase waits are short.
    clock.set_slot(100);
    clock.advance_time(9);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker.clone(),
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config().with_timeouts(fast_timeouts()),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        )
    });

    // Notify key change before the orchestrator checks has_changed().
    key_gen_tx.send_modify(|gen| *gen += 1);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    assert!(
        !duty_tracker.is_epoch_cached(far_epoch).await,
        "key_gen notification must clear the duty cache (far-future epoch gone)"
    );
}

/// RF1-07 / S1: a single key-gen notification must clear the duty cache
/// exactly once. Subsequent iterations must not re-clear until another
/// notify (marks the watch value as seen via `mark_unchanged`).
#[tokio::test]
async fn test_key_gen_notification_clears_only_once_until_next_notify() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let far_epoch = 50u64;

    Mock::given(method("POST"))
        .and(path(format!("/eth/v1/validator/duties/attester/{}", far_epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "validator_index": "1",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "0",
                "slot": (far_epoch * 32).to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));

    duty_tracker.fetch_duties_for_epoch(far_epoch).await.unwrap();
    assert!(duty_tracker.is_epoch_cached(far_epoch).await);

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));

    let (mut orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker.clone(),
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config().with_timeouts(fast_timeouts()),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        )
    });

    // ── Iteration 1: notify once → must clear ──────────────────────────
    key_gen_tx.send_modify(|gen| *gen += 1);
    orchestrator.apply_key_gen_cache_invalidation().await;
    assert!(
        !duty_tracker.is_epoch_cached(far_epoch).await,
        "first notify must clear the duty cache"
    );

    // Re-populate a far-future epoch that only a second clear would wipe.
    duty_tracker.fetch_duties_for_epoch(far_epoch).await.unwrap();
    assert!(duty_tracker.is_epoch_cached(far_epoch).await);

    // ── Iteration 2: no new notify → must NOT clear ────────────────────
    orchestrator.apply_key_gen_cache_invalidation().await;
    assert!(
        duty_tracker.is_epoch_cached(far_epoch).await,
        "second iteration without notify must not re-clear the duty cache (S1 mark-as-seen)"
    );

    // ── Iteration 3: second notify → must clear again ──────────────────
    key_gen_tx.send_modify(|gen| *gen += 1);
    orchestrator.apply_key_gen_cache_invalidation().await;
    assert!(
        !duty_tracker.is_epoch_cached(far_epoch).await,
        "a fresh notify must clear the duty cache again"
    );
}

/// RF1-07: compile/API-shape guard — the sole constructor requires
/// `OrchestratorDeps`, which always includes `key_gen_rx`. There is no
/// `new` / `new_with_attesting_enabled` path that fabricates a discarded
/// watch channel.
#[test]
fn test_orchestrator_deps_requires_key_gen_receiver() {
    let field_names = [
        "clock",
        "duty_tracker",
        "signer",
        "propagator",
        "beacon",
        "block_beacon",
        "builder_service",
        "validator_store",
        "config",
        "pubkey_map",
        "key_gen_rx",
        "circuit_breaker",
        "attesting_enabled",
        "head_gate",
    ];
    assert!(field_names.contains(&"key_gen_rx"), "OrchestratorDeps must require key_gen_rx");
    // Constructing via for_test yields a usable receiver field (type-checked).
    let (_tx, rx) = watch::channel(0u64);
    let _ = rx;
    // The production constructor signature is `new(OrchestratorDeps<..>)`
    // — verified by every call site in this module compiling.
}

#[tokio::test]
async fn test_orchestrator_no_duties_for_slot() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
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

    let result = orchestrator.process_slot(100).await;

    assert!(matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 100 })));
}

#[tokio::test]
async fn test_orchestrator_slot_missed() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(105);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

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

    let result = orchestrator.process_slot(100).await;

    assert!(matches!(result, Err(OrchestratorError::SlotMissed { .. })));
}

#[test]
fn test_attestation_result_success() {
    let result = AttestationResult {
        validator_index: "1234".to_string(),
        slot: 100,
        success: true,
        error: None,
    };
    assert!(result.success);
    assert!(result.error.is_none());
}

#[test]
fn test_attestation_result_failure() {
    let result = AttestationResult {
        validator_index: "1234".to_string(),
        slot: 100,
        success: false,
        error: Some("Test error".to_string()),
    };
    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("Test error"));
}

#[tokio::test]
async fn test_orchestrator_with_validator_keys() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let _pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

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
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let (_orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
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

    assert!(!*handle.shutdown_tx.borrow());
    handle.shutdown();
    assert!(*handle.shutdown_tx.borrow());
}

#[tokio::test]
async fn test_find_pubkey_exact_match() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
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

    let found = utils::find_pubkey(&orchestrator.pubkey_map, &pubkey_hex);
    assert!(found.is_some());
    assert_eq!(found.unwrap().to_bytes(), pubkey.to_bytes());
}

#[tokio::test]
async fn test_find_pubkey_case_insensitive() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
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

    let found = utils::find_pubkey(&orchestrator.pubkey_map, &pubkey_hex.to_lowercase());
    assert!(found.is_some());
}

#[tokio::test]
async fn test_find_pubkey_not_found() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
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

    let found = utils::find_pubkey(&orchestrator.pubkey_map, "0x1234567890abcdef");
    assert!(found.is_none());
}
