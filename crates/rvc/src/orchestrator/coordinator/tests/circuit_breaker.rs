//! Coordinator tests: circuit breaker.

use super::*;

/// H-3: A BN error on the **non-builder** path (ExecutionOnly mode →
/// `builder_boost_factor = 0`) must NOT trip the circuit breaker.
///
/// RED before fix: the coordinator calls `record_miss()` unconditionally
/// on every `Ok(Err(e))` arm, so `consecutive_misses` becomes 1.
///
/// GREEN after fix: only `BuilderFailure` / `BuilderOnly` errors call
/// `record_miss()`; a plain `Beacon` error leaves the counter at 0.
#[tokio::test]
async fn test_non_builder_timeout_does_not_trip_breaker() {
    use wiremock::MockServer;

    let mock_server = MockServer::start().await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 1u64;

    // Real key so RANDAO signing succeeds and we reach the BN call.
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    // Serve proposer duties so the cache is warm.
    setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    // ExecutionOnly → builder_boost_factor = 0 → not a builder attempt.
    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits this proposal (mirrors startup registration).
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();
    validator_store
        .set_global_block_selection_mode(validator_store::BlockSelectionMode::ExecutionOnly);

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    // Shared circuit breaker with realistic limits so we can observe misses.
    let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: circuit_breaker.clone(),
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            // MockBlockBeacon always returns Beacon("mock") error.
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        )
    });

    let ctx = SlotContext { slot, epoch, parent_root: None, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // Non-builder BN error must NOT record a miss.
    assert_eq!(
        circuit_breaker.consecutive_misses(),
        0,
        "BN error on non-builder path must not trip the circuit breaker (H-3)"
    );
}

/// H-3: A BN error on the **builder** path (BuilderAlways mode →
/// `builder_boost_factor = u64::MAX`) MUST trip the circuit breaker.
///
/// This test is GREEN with the current code and remains GREEN after the
/// fix — it guards against regressing builder-failure detection.
#[tokio::test]
async fn test_builder_timeout_trips_breaker() {
    use wiremock::MockServer;

    let mock_server = MockServer::start().await;

    let slot = 200u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 2u64;

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    // BuilderAlways → builder_boost_factor = u64::MAX → builder attempt.
    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits this proposal (mirrors startup registration).
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();
    validator_store
        .set_global_block_selection_mode(validator_store::BlockSelectionMode::BuilderAlways);

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: circuit_breaker.clone(),
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        ..OrchestratorDeps::for_test(
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
        )
    });

    let ctx = SlotContext { slot, epoch, parent_root: None, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // Builder BN error MUST record a miss.
    assert_eq!(
        circuit_breaker.consecutive_misses(),
        1,
        "BN error on builder path must trip the circuit breaker (H-3)"
    );
}

/// H-3: A local signer error must NOT trip the circuit breaker.
///
/// RED before fix: `record_miss()` is called unconditionally, so the
/// signer error (RANDAO signing fails because the key is absent from the
/// KeyManager) increments `consecutive_misses` to 1.
///
/// GREEN after fix: only `BuilderFailure` / `BuilderOnly` call
/// `record_miss()`.  `Signer` errors are ignored by the breaker.
#[tokio::test]
async fn test_signer_error_does_not_trip_breaker() {
    use wiremock::MockServer;

    let mock_server = MockServer::start().await;

    let slot = 300u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 3u64;

    // Generate a keypair but intentionally do NOT insert the secret key
    // into the KeyManager so RANDAO signing will fail.
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    // secret_key is dropped here — not in KeyManager.

    setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    // Empty KeyManager → sign_randao_reveal will return SignerError.
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the loaded validator so the signing gate is
    // passed and the RANDAO signing failure (empty KeyManager) is the path
    // under test (mirrors startup registration).
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    // pubkey is in the map so find_pubkey succeeds, but the secret key is absent.
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: circuit_breaker.clone(),
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        ..OrchestratorDeps::for_test(
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
        )
    });

    let ctx = SlotContext { slot, epoch, parent_root: None, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // Signer error must NOT record a miss.
    assert_eq!(
        circuit_breaker.consecutive_misses(),
        0,
        "Local signer error must not trip the circuit breaker (H-3)"
    );
}
