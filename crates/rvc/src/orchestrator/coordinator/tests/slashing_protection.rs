//! Coordinator tests: slashing.

use super::*;

// --- Issue 1.3: Slashing protection integration test ---

/// Builds an orchestrator with a shared SlashingDb for slashing integration tests.
/// Returns the orchestrator, handle, pubkey hex, capturing submitter, and clock.
async fn build_slashing_integration_orchestrator(
    mock_server_uri: &str,
    initial_slot: u64,
    slashing_db: Arc<SlashingDb>,
) -> (
    DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    String,
    Arc<CapturingSubmitter>,
    Arc<MockSlotClock>,
) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(initial_slot);

    let beacon_config = BeaconClientConfig::new(mock_server_uri);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let secret_key = SecretKey::generate();
    let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

    let pubkey = secret_key.public_key();
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let capturing_submitter = Arc::new(CapturingSubmitter::new());
    let propagator = Arc::new(Propagator::new(capturing_submitter.clone()));

    let config = create_test_config();
    let pubkey_bytes = pubkey.to_bytes();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits its duties (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey_bytes)).unwrap();

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock.clone(),
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

    (orchestrator, handle, pubkey_hex, capturing_submitter, clock)
}

/// Mounts attester duties for multiple slots in a single response.
async fn mount_multi_slot_duties(
    mock_server: &wiremock::MockServer,
    slots: &[u64],
    pubkey_hex: &str,
) {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    let duties: Vec<serde_json::Value> = slots
        .iter()
        .map(|slot| {
            serde_json::json!({
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "3",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "2",
                "slot": slot.to_string()
            })
        })
        .collect();

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": duties
        })))
        .mount(mock_server)
        .await;
}

/// Mounts attestation data with explicit source/target epochs, keyed by slot.
async fn mount_attestation_data_with_epochs(
    mock_server: &wiremock::MockServer,
    slot: u64,
    source_epoch: u64,
    target_epoch: u64,
) {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "3",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": source_epoch.to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": target_epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn test_double_vote_rejected_through_full_pipeline() {
    let mock_server = wiremock::MockServer::start().await;

    // Shared SlashingDb — this is the key: both slots share the same DB
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());

    // Slot 192 = epoch 6 (pre-Electra), slot 193 = same epoch
    let slot_1 = 192u64;
    let slot_2 = 193u64;
    let epoch = slot_1 / SLOTS_PER_EPOCH;

    let (orchestrator, _handle, pubkey_hex, capturing, clock) =
        build_slashing_integration_orchestrator(&mock_server.uri(), slot_1, slashing_db).await;

    // Mount duties for both slots in a single response
    mount_multi_slot_duties(&mock_server, &[slot_1, slot_2], &pubkey_hex).await;

    // Mount attestation data per slot with different source epochs but same target
    // Slot 1: source=5, target=6
    mount_attestation_data_with_epochs(&mock_server, slot_1, 5, 6).await;
    // Slot 2: source=4, target=6 — same target epoch, different source → double vote
    mount_attestation_data_with_epochs(&mock_server, slot_2, 4, 6).await;

    // Fetch duties for epoch 6 (caches duties for both slots)
    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // --- Slot 1: First attestation should succeed ---
    let results_1 = orchestrator.process_slot(slot_1).await.unwrap();
    assert_eq!(results_1.len(), 1, "Expected one attestation result for slot 1");
    assert!(results_1[0].success, "First attestation should succeed: {:?}", results_1[0].error);
    assert_eq!(
        capturing.captured().len(),
        1,
        "Exactly one attestation should be submitted after slot 1"
    );

    // --- Slot 2: Double vote should be REJECTED by slashing protection ---
    clock.set_slot(slot_2);
    let results_2 = orchestrator.process_slot(slot_2).await.unwrap();
    assert_eq!(results_2.len(), 1, "Expected one attestation result for slot 2");
    assert!(!results_2[0].success, "Second attestation (double vote) must be rejected");

    // Verify the rejection is specifically from slashing protection, not a generic error
    let error_msg = results_2[0].error.as_deref().expect("rejected attestation must have error");
    assert!(
        error_msg.contains("slashing protection") || error_msg.contains("SlashingBlocked"),
        "Error must indicate slashing protection blocked signing, got: {error_msg}"
    );

    // Verify only the first attestation was submitted — the double vote was never propagated
    assert_eq!(
        capturing.captured().len(),
        1,
        "Only the first attestation should be submitted; double vote must not be propagated"
    );
}
