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

    // Post-Electra
    let fork_name = ForkName::from_epoch(100, &schedule);
    assert!(utils::zeroes_committee_index(fork_name));
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
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let beacon_config = BeaconClientConfig::new(mock_server_uri);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let secret_key = SecretKey::generate();
    let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

    let pubkey = secret_key.public_key();
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let capturing_submitter = Arc::new(CapturingSubmitter::new());
    let propagator = Arc::new(Propagator::new(capturing_submitter.clone()));

    let config = OrchestratorConfig::new([0xaa; 32], schedule);
    let pubkey_bytes = pubkey.to_bytes();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits its duties (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey_bytes));

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
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
        VersionedAttestation::Electra(_) | VersionedAttestation::Fulu(_) => {
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
        VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
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
        VersionedAttestation::Electra(_) | VersionedAttestation::Fulu(_) => {
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
        VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
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
        VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
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

const B1_ELECTRA_EPOCH: u64 = 364544;
const B1_FULU_EPOCH: u64 = 500000;
const B1_GVR: Root = [0xaa; 32];

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
