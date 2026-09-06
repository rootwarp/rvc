//! Coordinator tests: sync gating.

use super::*;

// ── H-7: sync_enabled flag tests ────────────────────────────────────────

/// Minimal helper: build an orchestrator with a `SyncGuardBeacon` mock.
/// Used to avoid repetition in the H-7 guard tests.
async fn build_sync_test_orchestrator(
    beacon: Arc<dyn bn_manager::BeaconNodeClient>,
    _pk_hex: String,
    pk: crypto::PublicKey,
    sk: crypto::SecretKey,
    attesting_enabled: Arc<AtomicBool>,
) -> DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon> {
    let mut key_manager = KeyManager::new();
    key_manager.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    // Pre-populate sync committee duties for period 0 (epoch 0).
    duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

    let pk_bytes = pk.to_bytes();
    let mut map = HashMap::new();
    map.insert(pk.to_bytes(), pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits sync duties (mirrors startup registration). The
    // sync_enabled=false test short-circuits before this gate, so it stays
    // correct regardless.
    validator_store.add_validator(validator_store::ValidatorConfig::new(pk_bytes)).unwrap();
    let config = create_test_config();
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(0);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
        attesting_enabled,
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
    orchestrator
}

/// H-7: `sync_enabled` defaults to `true` on a freshly-constructed orchestrator.
///
/// RED: fails to compile before the `sync_enabled` field is added.
/// GREEN: field exists and is initialized to `true`.
#[test]
fn test_sync_enabled_defaults_to_true() {
    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config(),
        pubkey_map,
    ));

    assert!(
        orchestrator.sync_enabled.load(Ordering::Acquire),
        "sync_enabled must default to true (H-7)"
    );
}

/// H-7: `set_sync_enabled` writes with `Release` ordering and the new
/// value is immediately visible via `Acquire` load.
///
/// RED: fails to compile before `set_sync_enabled` is added.
/// GREEN: method exists and correctly toggles the flag.
#[test]
fn test_set_sync_enabled_toggles_flag() {
    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));
    let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config(),
        pubkey_map,
    ));

    assert!(orchestrator.sync_enabled.load(Ordering::Acquire), "default must be true");

    orchestrator.set_sync_enabled(false);
    assert!(
        !orchestrator.sync_enabled.load(Ordering::Acquire),
        "set_sync_enabled(false) must disable the flag"
    );

    orchestrator.set_sync_enabled(true);
    assert!(
        orchestrator.sync_enabled.load(Ordering::Acquire),
        "set_sync_enabled(true) must re-enable the flag"
    );
}

/// H-7 / ISSUE-2.7: when `attesting_enabled = false` and `sync_enabled = true`
/// (the default), sync-committee messages are still produced.
///
/// Before the fix the two services shared the `attesting_enabled` guard, so
/// disabling attestations would silently skip sync duties. After the fix the
/// guard is split: sync is gated only by `sync_enabled`.
///
/// RED: test fails (no sync messages) because sync is inside the attesting block.
/// GREEN: test passes after the guard is split.
#[tokio::test]
async fn test_sync_runs_with_attesting_disabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let r_captured: Root = [0xAA; 32];
    let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

    let beacon: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(sync_guard_beacon(pk.to_bytes(), submitted_roots.clone()));

    // attesting_enabled = false; sync_enabled = true (default)
    let attesting_enabled = Arc::new(AtomicBool::new(false));
    let orchestrator =
        build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // Confirm default: sync is enabled
    assert!(orchestrator.sync_enabled.load(Ordering::Acquire));

    let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some(r_captured) };

    // Exercise the guarded sync-messages phase directly.
    orchestrator.run_sync_messages_phase(0, 0, &ctx).await;

    let roots = submitted_roots.lock().unwrap();
    assert!(
        !roots.is_empty(),
        "H-7: sync messages must be produced even when attesting is disabled \
         (sync_enabled=true overrides attesting_enabled=false)"
    );
    for root in roots.iter() {
        assert_eq!(*root, r_captured, "submitted root must match SlotContext.head_root");
    }
}

/// H-7 / ISSUE-2.7: inverse — when `sync_enabled = false` and `attesting_enabled = true`,
/// no sync-committee messages are produced, but attestations would still run.
///
/// RED: fails (sync runs unconditionally) before the separate guard is added.
/// GREEN: `run_sync_messages_phase` short-circuits on `sync_enabled = false`.
#[tokio::test]
async fn test_sync_messages_skipped_when_sync_disabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let r_captured: Root = [0xAA; 32];
    let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

    let beacon: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(sync_guard_beacon(pk.to_bytes(), submitted_roots.clone()));

    // attesting_enabled = true; sync_enabled = false (explicit)
    let attesting_enabled = Arc::new(AtomicBool::new(true));
    let orchestrator =
        build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    orchestrator.set_sync_enabled(false);
    assert!(!orchestrator.sync_enabled.load(Ordering::Acquire));

    let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some(r_captured) };

    orchestrator.run_sync_messages_phase(0, 0, &ctx).await;

    assert!(
        submitted_roots.lock().unwrap().is_empty(),
        "H-7: sync messages must NOT be produced when sync_enabled = false"
    );
}

/// H-7: same guard split applies to contributions phase — skipped when sync disabled.
#[tokio::test]
async fn test_sync_contributions_skipped_when_sync_disabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let r_captured: Root = [0xAA; 32];
    let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

    let beacon: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(sync_guard_beacon(pk.to_bytes(), submitted_roots.clone()));

    let attesting_enabled = Arc::new(AtomicBool::new(false));
    let orchestrator =
        build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // Disable sync: contributions must not call the signer.
    orchestrator.set_sync_enabled(false);

    let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some(r_captured) };
    // With sync_enabled=false the phase guard returns early before any
    // signer or BN call. The test just verifies no panic and no submission.
    orchestrator.run_sync_contributions_phase(0, 0, &ctx).await;

    // No sync messages or contributions were submitted.
    assert!(
        submitted_roots.lock().unwrap().is_empty(),
        "H-7: sync contributions must NOT run when sync_enabled = false"
    );
}
