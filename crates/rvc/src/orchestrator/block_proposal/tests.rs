//! Block-proposal method tests (relocated from `coordinator/tests/proposal.rs`).

use crate::orchestrator::coordinator::{
    tests::{
        always_enabled, create_mock_block_beacon, create_mock_validator_store, create_test_config,
        BadProposerBlockBeacon, MockSubmitter, TEST_GENESIS_TIME,
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
    let ctx = SlotContext::bare(slot, epoch);
    orchestrator.maybe_propose_block(slot, epoch, &ctx, None).await;

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

    let ctx = SlotContext::bare(slot, epoch);
    orchestrator.maybe_propose_block(slot, epoch, &ctx, None).await;

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
    use block_service::{
        BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse,
    };
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
                payload_included: false,
                builder_url: None,
                consensus_block_value: None,
            })
        }

        async fn produce_block_v4(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_config: &BuilderConfig,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            Err(BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
        }

        async fn publish_block(
            &self,
            _signed_block: &SignedBeaconBlock,
            _consensus_version: &str,
            _builder_url: Option<&str>,
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
            _builder_url: Option<&str>,
        ) -> Result<(), BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_execution_payload_envelope(
            &self,
            _signed_envelope: &block_service::WireBody,
            _blobs: &block_service::WireBody,
            _kzg_proofs: &block_service::WireBody,
            _consensus_version: &str,
            _broadcast_validation: Option<&str>,
        ) -> Result<(), BlockServiceError> {
            Ok(())
        }
    }

    let slot: Slot = 100;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 42u64;
    let r_prev: Root = [0x11; 32];
    let r_curr: Root = [0x22; 32];
    let r_curr_hex = format!("0x{}", hex::encode(r_curr));

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let reorg_parent: Root = [0x33; 32];
    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_block_header({
                move |block_id| {
                    if block_id != (slot - 1).to_string() {
                        return Err(beacon::BeaconError::HttpError(format!(
                            "unexpected block_id {block_id}"
                        )));
                    }
                    Ok(beacon::BlockHeaderSummary {
                        root: r_prev,
                        slot: slot - 1,
                        proposer_index: 1,
                        parent_root: reorg_parent,
                    })
                }
            })
            .with_get_block_root({
                let r_curr_hex = r_curr_hex.clone();
                move |block_id| {
                    let root = if block_id == slot.to_string() {
                        r_curr_hex.clone()
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
    ctx.apply_phase2_head(beacon.as_ref()).await;
    assert_eq!(ctx.parent_root, Some(r_prev), "t=0 parent must be slot N-1");
    assert_eq!(
        ctx.expected_parents,
        Some(block_service::ExpectedParents {
            root: r_prev,
            parent: Some(reorg_parent),
            closed: false
        }),
        "a header at N-1 keeps its parent for a single-slot re-org"
    );
    assert_eq!(ctx.head_root, Some(r_curr), "phase-2 head must be slot N");

    orchestrator.maybe_propose_block(slot, epoch, &ctx, None).await;

    assert!(
        publish_called.load(Ordering::SeqCst),
        "propose_block 4th arg must be slot N-1 (parent_root); passing head_root \
         rejects a valid previous-slot parent with ParentRootMismatch"
    );
}

// ── DSR-1.2: proposal outcome metrics ─────────────────────────────────────

fn proposal_outcome_count(outcome: &str) -> u64 {
    block_service::metrics::RVC_PROPOSALS_TOTAL.with_label_values(&[outcome]).get()
}

/// Successful propose+publish must increment `rvc_proposals_total{outcome=success}`.
#[tokio::test]
async fn test_successful_proposal_increments_success_outcome() {
    use async_trait::async_trait;
    use block_service::{
        BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse,
    };
    use bn_manager::MockBeaconNodeClient;
    use eth_types::SignedBeaconBlock;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct OkBlockBeacon {
        validator_index: u64,
        published: Arc<AtomicBool>,
    }

    #[async_trait]
    impl BeaconBlockClient for OkBlockBeacon {
        async fn produce_block_v3(
            &self,
            slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            let mut block = eth_types::external_vector_deneb_block();
            block.slot = slot;
            block.proposer_index = self.validator_index;
            Ok(ProduceBlockResponse {
                data: serde_json::to_value(&block)
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
                is_blinded: false,
                consensus_version: "deneb".to_string(),
                execution_payload_value: Some("0".to_string()),
                is_ssz: false,
                ssz_bytes: None,
                payload_included: false,
                builder_url: None,
                consensus_block_value: None,
            })
        }

        async fn produce_block_v4(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_config: &BuilderConfig,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            Err(BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
        }

        async fn publish_block(
            &self,
            _signed_block: &SignedBeaconBlock,
            _consensus_version: &str,
            _builder_url: Option<&str>,
        ) -> Result<(), BlockServiceError> {
            self.published.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            _signed_block: &eth_types::SignedBlindedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.published.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_block_ssz(
            &self,
            _ssz_bytes: &[u8],
            _consensus_version: &str,
            _is_blinded: bool,
            _builder_url: Option<&str>,
        ) -> Result<(), BlockServiceError> {
            self.published.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_execution_payload_envelope(
            &self,
            _signed_envelope: &block_service::WireBody,
            _blobs: &block_service::WireBody,
            _kzg_proofs: &block_service::WireBody,
            _consensus_version: &str,
            _broadcast_validation: Option<&str>,
        ) -> Result<(), BlockServiceError> {
            Ok(())
        }
    }

    super::proposal_counter_lock::with_held(async {
        let mock_server = MockServer::start().await;
        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 1u64;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{epoch}")))
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
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        let published = Arc::new(AtomicBool::new(false));
        let block_beacon = Arc::new(OkBlockBeacon {
            validator_index,
            published: published.clone(),
        });

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

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
            Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
            Arc::new(MockBeaconNodeClient::new()),
            block_beacon,
            None,
            validator_store,
            create_test_config(),
            pubkey_map,
        ));

        let before_success =
            proposal_outcome_count(block_service::metrics::proposal_outcome::SUCCESS);
        let before_failed = proposal_outcome_count(block_service::metrics::proposal_outcome::FAILED);

        let ctx = SlotContext::bare(slot, epoch);
        orchestrator.maybe_propose_block(slot, epoch, &ctx, None).await;

        assert!(published.load(Ordering::SeqCst), "success path must publish");
        assert_eq!(
            proposal_outcome_count(block_service::metrics::proposal_outcome::SUCCESS),
            before_success + 1,
            "rvc_proposals_total{{outcome=success}} must increment after a successful proposal"
        );
        assert_eq!(
            proposal_outcome_count(block_service::metrics::proposal_outcome::FAILED),
            before_failed,
            "successful proposal must not increment failed"
        );
    })
    .await;
}

/// A BN produce error on the publish path must increment `outcome=failed`.
#[tokio::test]
async fn test_failed_proposal_increments_failed_outcome() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    super::proposal_counter_lock::with_held(async {
        let mock_server = MockServer::start().await;
        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 1u64;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{epoch}")))
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
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

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
            Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            create_test_config(),
            pubkey_map,
        ));

        let before_success =
            proposal_outcome_count(block_service::metrics::proposal_outcome::SUCCESS);
        let before_failed = proposal_outcome_count(block_service::metrics::proposal_outcome::FAILED);

        let ctx = SlotContext::bare(slot, epoch);
        orchestrator.maybe_propose_block(slot, epoch, &ctx, None).await;

        assert_eq!(
            proposal_outcome_count(block_service::metrics::proposal_outcome::FAILED),
            before_failed + 1,
            "rvc_proposals_total{{outcome=failed}} must increment after a failed proposal attempt"
        );
        assert_eq!(
            proposal_outcome_count(block_service::metrics::proposal_outcome::SUCCESS),
            before_success,
            "failed proposal must not increment success"
        );
    })
    .await;
}

/// One produce step, then the publish outcome for that step.
#[derive(Clone, Copy)]
enum PublishStep {
    BlindedFail,
    BlindedOk,
    LocalOk,
    LocalFail,
    BlindedHang,
}

struct ScriptedBeacon {
    steps: std::sync::Mutex<std::collections::VecDeque<PublishStep>>,
    current: std::sync::Mutex<Option<PublishStep>>,
    index: u64,
    /// Deadline of each `produce_block_v3_ranked_by` call, in order.
    recorded_deadline: std::sync::Mutex<Vec<Option<tokio::time::Instant>>>,
}

impl ScriptedBeacon {
    fn new(index: u64, steps: Vec<PublishStep>) -> Self {
        Self {
            steps: std::sync::Mutex::new(steps.into()),
            current: std::sync::Mutex::new(None),
            index,
            recorded_deadline: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn recorded_deadline(&self) -> Vec<Option<tokio::time::Instant>> {
        self.recorded_deadline.lock().expect("deadline").clone()
    }

    fn take(&self) -> PublishStep {
        let step = self.steps.lock().expect("steps").pop_front().expect("a step");
        *self.current.lock().expect("current") = Some(step);
        step
    }

    fn block(
        &self,
        slot: Slot,
        blinded: bool,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        let data = if blinded {
            let mut block = eth_types::external_vector_deneb_blinded_block();
            block.slot = slot;
            block.proposer_index = self.index;
            serde_json::to_value(&block)
        } else {
            let mut block = eth_types::external_vector_deneb_block();
            block.slot = slot;
            block.proposer_index = self.index;
            serde_json::to_value(&block)
        }
        .map_err(|err| block_service::BlockServiceError::Parse(err.to_string()))?;
        Ok(block_service::ProduceBlockResponse {
            data,
            is_blinded: blinded,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        })
    }

    async fn finish(&self) -> Result<(), block_service::BlockServiceError> {
        let step = *self.current.lock().expect("current");
        match step {
            Some(PublishStep::BlindedOk | PublishStep::LocalOk) => Ok(()),
            Some(PublishStep::BlindedHang) => std::future::pending().await,
            Some(PublishStep::BlindedFail | PublishStep::LocalFail) | None => {
                Err(block_service::BlockServiceError::Beacon("publish failed".to_string()))
            }
        }
    }
}

#[async_trait::async_trait]
impl block_service::BeaconBlockClient for ScriptedBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        let blinded = matches!(
            self.take(),
            PublishStep::BlindedFail | PublishStep::BlindedOk | PublishStep::BlindedHang
        );
        self.block(slot, blinded)
    }

    async fn produce_block_v3_ranked_by(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        _duty: Option<block_service::ProduceDuty>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<block_service::RankedBlock>, block_service::BlockServiceError> {
        self.recorded_deadline.lock().expect("deadline").push(deadline);
        let response =
            self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await?;
        Ok(vec![block_service::RankedBlock { bn_index: 0, response }])
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &block_service::BuilderConfig,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        Err(block_service::BlockServiceError::Beacon("v4 unused".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.finish().await
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), block_service::BlockServiceError> {
        self.finish().await
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.finish().await
    }

    async fn publish_block_contents(
        &self,
        _contents: &eth_types::SignedBlockContentsJson,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.finish().await
    }

    async fn publish_execution_payload_envelope(
        &self,
        _signed_envelope: &block_service::WireBody,
        _blobs: &block_service::WireBody,
        _kzg_proofs: &block_service::WireBody,
        _consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.finish().await
    }
}

struct ProposalRig {
    orchestrator: DutyOrchestrator<MockSlotClock, MockSubmitter, ScriptedBeacon>,
    breaker: Arc<signer::CircuitBreakerState>,
    clock: Arc<MockSlotClock>,
    epoch: u64,
    beacon: Arc<ScriptedBeacon>,
}

async fn proposal_rig(limit: u32, steps: Vec<PublishStep>, slots: &[u64]) -> ProposalRig {
    use bn_manager::MockBeaconNodeClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let index = 1u64;
    let epoch = slots[0] / SLOTS_PER_EPOCH;
    let data = slots
        .iter()
        .map(|slot| {
            serde_json::json!({
                "pubkey": pubkey_hex,
                "validator_index": index.to_string(),
                "slot": slot.to_string(),
            })
        })
        .collect::<Vec<_>>();
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{epoch}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": data,
        })))
        .mount(&server)
        .await;

    let beacon = Arc::new(BeaconClient::new(BeaconClientConfig::new(server.uri())).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    let mut keys = KeyManager::new();
    keys.insert(secret);
    let signer = Arc::new(
        SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(keys))),
            Arc::new(SlashingDb::open_in_memory().unwrap()),
        )
        .with_enablement(always_enabled()),
    );
    let store = Arc::new(ValidatorStore::new([0xaa; 20], 30_000_000));
    store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    store.set_global_block_selection_mode(validator_store::BlockSelectionMode::MaxProfit);
    let mut map = HashMap::new();
    map.insert(pubkey.to_bytes(), pubkey);
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let breaker = Arc::new(signer::CircuitBreakerState::new(limit, 0));
    let beacon = Arc::new(ScriptedBeacon::new(index, steps));
    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps {
        circuit_breaker: Arc::clone(&breaker),
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        ..OrchestratorDeps::for_test(
            Arc::clone(&clock),
            duty_tracker,
            signer,
            Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
            Arc::new(MockBeaconNodeClient::new()),
            Arc::clone(&beacon),
            None,
            store,
            create_test_config(),
            Arc::new(parking_lot::RwLock::new(map)),
        )
    });
    ProposalRig { orchestrator, breaker, clock, epoch, beacon }
}

async fn propose_at(rig: &ProposalRig, slot: u64) {
    rig.clock.set_slot(slot);
    let ctx = SlotContext::bare(slot, rig.epoch);
    rig.orchestrator.maybe_propose_block(slot, rig.epoch, &ctx, None).await;
}

/// N consecutive blinded publish failures trip the breaker.
#[tokio::test]
async fn test_blinded_publish_failure_trips_breaker() {
    let slots = [100u64, 101, 102];
    let rig = proposal_rig(
        3,
        vec![PublishStep::BlindedFail, PublishStep::BlindedFail, PublishStep::BlindedFail],
        &slots,
    )
    .await;
    for slot in slots {
        propose_at(&rig, slot).await;
    }
    assert_eq!(rig.breaker.consecutive_misses(), 3);
    assert_eq!(rig.breaker.epoch_misses(), 3);
    assert!(rig.breaker.is_tripped());
}

/// A local block after a blinded failure does not reset the miss count.
///
/// Blinded failure, local success, repeated. The breaker trips on the blinded
/// failures alone.
#[tokio::test]
async fn test_local_fallback_after_blinded_failure_does_not_reset_the_breaker() {
    let slots = [100u64, 101, 102, 103, 104];
    let rig = proposal_rig(
        3,
        vec![
            PublishStep::BlindedFail,
            PublishStep::LocalOk,
            PublishStep::BlindedFail,
            PublishStep::LocalOk,
            PublishStep::BlindedFail,
        ],
        &slots,
    )
    .await;
    for slot in slots {
        propose_at(&rig, slot).await;
    }
    assert_eq!(rig.breaker.consecutive_misses(), 3);
    assert!(rig.breaker.is_tripped());
}

/// A blinded publish the beacon node accepted clears the consecutive count
/// and leaves the epoch count.
#[tokio::test]
async fn test_successful_blinded_publish_resets_the_miss_count() {
    let slots = [110u64, 111, 112];
    let rig = proposal_rig(
        3,
        vec![PublishStep::BlindedFail, PublishStep::BlindedFail, PublishStep::BlindedOk],
        &slots,
    )
    .await;
    for slot in slots {
        propose_at(&rig, slot).await;
    }
    assert_eq!(rig.breaker.consecutive_misses(), 0);
    assert_eq!(rig.breaker.epoch_misses(), 2);
    assert!(!rig.breaker.is_tripped());
}

/// A local publish failure is not a builder miss.
#[tokio::test]
async fn test_local_publish_failure_does_not_move_the_breaker() {
    let rig = proposal_rig(3, vec![PublishStep::LocalFail], &[120]).await;
    propose_at(&rig, 120).await;
    assert_eq!(rig.breaker.consecutive_misses(), 0);
    assert_eq!(rig.breaker.epoch_misses(), 0);
    assert!(!rig.breaker.is_tripped());
}

/// The outer proposal timeout cannot classify the publish, so it records nothing.
#[tokio::test(flavor = "current_thread")]
async fn test_proposal_timeout_does_not_record_a_miss() {
    let rig = proposal_rig(3, vec![PublishStep::BlindedHang], &[121]).await;
    tokio::time::pause();
    rig.clock.set_slot(121);
    let allowance = super::block_proposal_allowance(&rig.orchestrator.config.timeouts);
    let epoch = rig.epoch;
    let orch = rig.orchestrator;
    let task = tokio::spawn(async move {
        let ctx = SlotContext::bare(121, epoch);
        orch.maybe_propose_block(121, epoch, &ctx, None).await;
    });
    tokio::time::sleep(allowance).await;
    tokio::time::timeout(Duration::from_millis(1), task)
        .await
        .expect("the outer timeout ends the proposal")
        .expect("proposal task");
    assert_eq!(rig.breaker.consecutive_misses(), 0);
    assert!(!rig.breaker.is_tripped());
}

/// The outer allowance is `min(block proposal allowance, time left in the slot)`.
///
/// A hang returns at the shorter of those two. Tokio's timer wheel rounds a
/// deadline up by at most one millisecond, so under pause the measured elapsed
/// is that shorter duration or one millisecond more. A slot that is already
/// over does not wait out the allowance.
#[tokio::test(flavor = "current_thread")]
async fn test_proposal_outer_timeout_is_clamped_to_slot_end() {
    let rig = proposal_rig(
        3,
        vec![PublishStep::BlindedHang, PublishStep::BlindedHang, PublishStep::BlindedHang],
        &[121, 122, 123],
    )
    .await;
    tokio::time::pause();
    let allowance = super::block_proposal_allowance(&rig.orchestrator.config.timeouts);
    let slot_ms = 12_000u64;
    assert!(Duration::from_millis(slot_ms) > allowance);
    let epoch = rig.epoch;
    // `deadline_to_tick` adds 999_999 ns. Elapsed is the armed duration, or
    // one millisecond more when the paused instant is not on a millisecond.
    let within_one_tick = |actual: Duration, armed: Duration| {
        let tick = Duration::from_millis(1);
        assert!(
            actual == armed || actual == armed.saturating_add(tick),
            "elapsed {actual:?}, armed {armed:?}"
        );
    };

    // Slot already over: remaining is zero, shorter than the allowance.
    rig.clock.set_slot_with_offset_ms(121, slot_ms);
    let start = tokio::time::Instant::now();
    let ctx = SlotContext::bare(121, epoch);
    rig.orchestrator.maybe_propose_block(121, epoch, &ctx, None).await;
    within_one_tick(start.elapsed(), Duration::ZERO);

    // 40 ms left in the slot, shorter than the allowance.
    rig.clock.set_slot_with_offset_ms(122, slot_ms - 40);
    let start = tokio::time::Instant::now();
    let ctx = SlotContext::bare(122, epoch);
    rig.orchestrator.maybe_propose_block(122, epoch, &ctx, None).await;
    within_one_tick(start.elapsed(), Duration::from_millis(40));

    // A full slot remains, longer than the allowance. The allowance wins.
    rig.clock.set_slot(123);
    let start = tokio::time::Instant::now();
    let ctx = SlotContext::bare(123, epoch);
    rig.orchestrator.maybe_propose_block(123, epoch, &ctx, None).await;
    within_one_tick(start.elapsed(), allowance);
}

/// `maybe_propose_block` passes the slot-end deadline into block production.
/// Each call stores its own instant. `None` stays `None` on the next call.
#[tokio::test(flavor = "current_thread")]
async fn test_maybe_propose_block_forwards_the_slot_end_deadline() {
    let rig = proposal_rig(
        3,
        vec![PublishStep::LocalOk, PublishStep::LocalOk, PublishStep::LocalOk],
        &[130, 131, 132],
    )
    .await;
    tokio::time::pause();
    let epoch = rig.epoch;

    rig.clock.set_slot(130);
    let first = tokio::time::Instant::now() + Duration::from_millis(800);
    let ctx = SlotContext::bare(130, epoch);
    rig.orchestrator.maybe_propose_block(130, epoch, &ctx, Some(first)).await;

    rig.clock.set_slot(131);
    let second = tokio::time::Instant::now() + Duration::from_secs(2);
    let ctx = SlotContext::bare(131, epoch);
    rig.orchestrator.maybe_propose_block(131, epoch, &ctx, Some(second)).await;

    rig.clock.set_slot(132);
    let ctx = SlotContext::bare(132, epoch);
    rig.orchestrator.maybe_propose_block(132, epoch, &ctx, None).await;

    assert_eq!(rig.beacon.recorded_deadline(), vec![Some(first), Some(second), None]);
}
