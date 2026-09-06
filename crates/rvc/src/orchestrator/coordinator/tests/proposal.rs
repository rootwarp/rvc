//! Coordinator tests: attestation doppelganger gate (shared harness location).
//!
//! Block-proposal method tests live in
//! `orchestrator::block_proposal::tests` (RF6-28).

use super::*;

/// When a validator's `enabled` flag is `false` in `ValidatorStore` (i.e.
/// it is still inside the post-import doppelganger window), the attestation
/// service must skip the duty and return `NoDutiesForSlot` rather than
/// attempting to sign.
///
/// Verifies the fix for ISSUE-3.11 Critical #1: "gate is never consulted
/// by the attestation path".
#[tokio::test]
async fn test_orchestrator_skips_duty_during_doppelganger_window() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // 0x + 96 hex chars = 48 bytes (one 'd' nibble-pair per byte × 48)
    let duty_pubkey_hex =
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    // Slot 64 is in epoch 2 (64 / 32 = 2); mock duties endpoint for epoch 2.
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": duty_pubkey_hex,
                "validator_index": "42",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "1",
                "validator_committee_index": "5",
                "slot": "64"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Signer call count — must be zero while validator is disabled.
    let submitter = Arc::new(MockSubmitter::new());
    let submit_count = submitter.call_count.load(Ordering::SeqCst);

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 64));
    clock.set_slot(64);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));

    // Pre-populate the duty cache so process_slot can find the duty.
    duty_tracker.fetch_duties_for_epoch(2).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let propagator = Arc::new(Propagator::new(submitter.clone()));
    let config = create_test_config();

    // Map key is the duty's compressed bytes (0xdd…); value is a real BLS key.
    // get_duties_for_slot matches on the key; the gate uses PublicKey::to_bytes().
    let duty_map_key: [u8; 48] = [0xdd; 48];
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(duty_map_key, pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // --- Critical: add the RESOLVED pubkey as DISABLED (inside doppelganger window).
    // D-3 (FUP-6): the gate resolves the duty pubkey via `find_pubkey` and gates
    // on the resolved typed pubkey's `to_bytes()` (real BLS bytes), not the
    // literal `0xdddd...` map key.
    let duty_pk_bytes: [u8; 48] = pubkey.to_bytes();
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    {
        let mut config = validator_store::ValidatorConfig::new(duty_pk_bytes);
        config.enabled = false;
        validator_store.add_validator(config).unwrap();
    }

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store.clone(),
        config,
        pubkey_map,
    ));

    // Phase 1 (RED → GREEN): process_slot must return NoDutiesForSlot
    // because the validator is inside the doppelganger window (enabled=false).
    let result = orchestrator.attestation_service.process_slot(64).await;
    assert!(
        matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 64 })),
        "duty must be filtered out while validator is in doppelganger window; got: {result:?}"
    );
    assert_eq!(
        submitter.call_count.load(Ordering::SeqCst),
        submit_count,
        "signer must NOT be called while validator is in doppelganger window"
    );

    // Phase 2: enable the validator (simulates window elapsed).
    validator_store.set_enabled(&duty_pk_bytes, true);

    // Now process_slot should proceed past the gate (will fail further on
    // because no beacon attestation-data mock is set up, but the important
    // thing is the duty is NOT filtered by the doppelganger check).
    let result2 = orchestrator.attestation_service.process_slot(64).await;
    assert!(
        !matches!(result2, Err(OrchestratorError::NoDutiesForSlot { .. })),
        "after enabling the validator, duty must NOT be filtered by doppelganger gate; \
         got: {result2:?}"
    );
}
