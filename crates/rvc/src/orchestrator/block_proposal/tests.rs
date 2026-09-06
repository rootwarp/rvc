//! Block-proposal method tests (relocated from `coordinator/tests/proposal.rs`).

use crate::orchestrator::coordinator::{
    tests::{
        always_enabled, create_mock_validator_store, create_test_config, BadProposerBlockBeacon,
        MockSubmitter, TEST_GENESIS_TIME,
    },
    DutyOrchestrator, OrchestratorDeps,
};
use crate::orchestrator::slot_context::SlotContext;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig};
use bn_manager::Propagator;
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::Slot;
use signer::SignerService;
use slashing::SlashingDb;
use timing::{MockSlotClock, SLOTS_PER_EPOCH};
use validator_store::ValidatorStore;

/// H-4 coordinator integration test: when the BN returns a block whose
/// `proposer_index` does not match the duty's `validator_index`, the duty
/// must be silently dropped — no signer call and no publish call.
///
/// RED against d490044: `propose_block` (unvalidated) ignores the
/// `proposer_index` and proceeds to sign + publish, so `publish_called`
/// becomes `true` → assertion fails.
///
/// GREEN after CQ-3.2: the validated `propose_block` is the only entry point;
/// the mismatch is caught before signing, `publish_called` stays `false`.
#[tokio::test]
async fn test_maybe_propose_block_bad_proposer_index_drops_duty() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    // The duty says this validator should propose at slot 100.
    let expected_validator_index = 42u64;
    // The BN returns a block with a different (forged) proposer_index.
    let bad_proposer_index = 99u64;

    // Generate a real key so RANDAO signing succeeds and we reach the
    // proposer_index validation step.
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    // Beacon client for duty fetching (backed by wiremock).
    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    // Serve proposer duties for the epoch.
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": expected_validator_index.to_string(),
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    // Pre-populate the proposer duty cache before calling maybe_propose_block.
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    // Block beacon: returns a block with wrong proposer_index; tracks publish.
    let publish_called = Arc::new(AtomicBool::new(false));
    let block_beacon = Arc::new(BadProposerBlockBeacon {
        slot,
        bad_proposer_index,
        publish_called: publish_called.clone(),
    });

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

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // Invoke the proposer path directly.
    let ctx = SlotContext { slot, epoch, parent_root: None, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // H-4: a forged proposer_index must drop the duty before any
    // signing or publishing occurs.
    assert!(
        !publish_called.load(Ordering::SeqCst),
        "publish_block must NOT be called when proposer_index mismatches the duty"
    );
}

// ── D-3: block proposal gate ─────────────────────────────────────────────

/// D-3: a validator whose `is_signing_enabled = false` must NOT propose a block.
///
/// The test uses wiremock to serve a proposer duty, then checks that
/// `publish_block` is never called when the validator is disabled.
///
/// RED: `maybe_propose_block` does not check `is_signing_enabled` →
///      the block_service is called (RANDAO sign, produce, publish).
///      The `BadProposerBlockBeacon` sets `publish_called = true` via
///      `produce_block_v3` returning a block with `proposer_index="1"`.
///      Actually `BadProposerBlockBeacon` calls `produce_block_v3` which
///      would attempt RANDAO sign first — the D-3 gate must fire before any
///      signer call, so the RANDAO sign never happens if the gate is correct.
///
/// GREEN: D-3 gate in `maybe_propose_block` returns early before
///        `block_service.propose_block`, so `publish_called` stays `false`.
#[tokio::test]
async fn test_block_proposal_skipped_when_validator_disabled() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slot: Slot = 10;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 1u64;

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let pk_bytes: [u8; 48] = pubkey.to_bytes();

    // Serve proposer duties from wiremock.
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": validator_index.to_string(),
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    // BadProposerBlockBeacon returns a block with configurable proposer_index.
    // Use a matching proposer_index (validator_index) so the only gate is D-3.
    let publish_called = Arc::new(AtomicBool::new(false));
    let block_beacon = Arc::new(BadProposerBlockBeacon {
        slot,
        bad_proposer_index: validator_index, // matching index → no H-4 drop
        publish_called: publish_called.clone(),
    });

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    // Validator store with this validator DISABLED (doppelganger window).
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 0));
    {
        let mut config = validator_store::ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        validator_store.add_validator(config).unwrap();
    }

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        validator_store,
        create_test_config(),
        pubkey_map,
    ));

    let ctx = SlotContext { slot, epoch, parent_root: None, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // D-3: the block must NOT be proposed when is_signing_enabled=false.
    // publish_called stays false because the gate returns early before
    // block_service.propose_block (which would call produce_block_v3).
    assert!(
        !publish_called.load(Ordering::SeqCst),
        "D-3: block must NOT be proposed when is_signing_enabled=false"
    );
}

/// ARCH-3c: `propose_block`'s 4th argument must be the slot N-1 root
/// (`parent_root`), not slot N (`head_root`). Passing the current slot's
/// root would arm ParentRootMismatch on a valid block.
#[tokio::test]
async fn test_proposal_passes_previous_slot_as_expected_parent() {
    use async_trait::async_trait;
    use beacon::{BlockRootData, DataResponse, DependentRootResponse, ProposerDuty};
    use block_service::{BeaconBlockClient, BlockServiceError, ProduceBlockResponse};
    use bn_manager::MockBeaconNodeClient;
    use eth_types::{Root, SignedBeaconBlock, SignedBlindedBeaconBlock};

    struct ParentAwareBlockBeacon {
        slot: Slot,
        proposer_index: u64,
        parent: Root,
        publish_called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl BeaconBlockClient for ParentAwareBlockBeacon {
        async fn produce_block_v3(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            let mut block = eth_types::external_vector_deneb_block();
            block.slot = self.slot;
            block.proposer_index = self.proposer_index;
            block.parent_root = self.parent;
            Ok(ProduceBlockResponse {
                data: serde_json::to_value(&block)
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
                is_blinded: false,
                consensus_version: "deneb".to_string(),
                execution_payload_value: Some("0".to_string()),
                is_ssz: false,
                ssz_bytes: None,
            })
        }

        async fn publish_block(
            &self,
            _signed_block: &SignedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            _signed_block: &SignedBlindedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_block_ssz(
            &self,
            _ssz_bytes: &[u8],
            _consensus_version: &str,
            _is_blinded: bool,
        ) -> Result<(), BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let slot: Slot = 100;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 42u64;
    let r_prev: Root = [0x11; 32];
    let r_curr: Root = [0x22; 32];
    let r_prev_hex = format!("0x{}", hex::encode(r_prev));
    let r_curr_hex = format!("0x{}", hex::encode(r_curr));

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_block_root({
                let r_prev_hex = r_prev_hex.clone();
                let r_curr_hex = r_curr_hex.clone();
                move |block_id| {
                    let root = if block_id == slot.to_string() {
                        r_curr_hex.clone()
                    } else if block_id == (slot - 1).to_string() {
                        r_prev_hex.clone()
                    } else {
                        return Err(beacon::BeaconError::HttpError(format!(
                            "unexpected block_id {block_id}"
                        )));
                    };
                    Ok(DataResponse { data: BlockRootData { root } })
                }
            })
            .with_get_proposer_duties({
                let pubkey_hex = pubkey_hex.clone();
                move |_epoch| {
                    Ok(DependentRootResponse {
                        dependent_root:
                            "0x0000000000000000000000000000000000000000000000000000000000000000"
                                .to_string(),
                        execution_optimistic: false,
                        data: vec![ProposerDuty {
                            pubkey: pubkey_hex.clone(),
                            validator_index: validator_index.to_string(),
                            slot: slot.to_string(),
                        }],
                    })
                }
            }),
    );

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    let publish_called = Arc::new(AtomicBool::new(false));
    let block_beacon = Arc::new(ParentAwareBlockBeacon {
        slot,
        proposer_index: validator_index,
        parent: r_prev,
        publish_called: publish_called.clone(),
    });

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();
    validator_store
        .set_global_block_selection_mode(validator_store::BlockSelectionMode::ExecutionOnly);

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon.clone(),
        block_beacon,
        None,
        validator_store,
        create_test_config(),
        pubkey_map,
    ));

    let mut ctx = SlotContext::capture_parent(beacon.as_ref(), slot, epoch).await;
    ctx.capture_head(beacon.as_ref()).await;
    assert_eq!(ctx.parent_root, Some(r_prev), "t=0 parent must be slot N-1");
    assert_eq!(ctx.head_root, Some(r_curr), "phase-2 head must be slot N");

    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    assert!(
        publish_called.load(Ordering::SeqCst),
        "propose_block 4th arg must be slot N-1 (parent_root); passing head_root \
         rejects a valid previous-slot parent with ParentRootMismatch"
    );
}
