//! In-source tests for [`crate::orchestrator::coordinator`].
//!
//! Split by topic (RF6-09 / F5). Shared mock scaffolding lives here;
//! topic suites are sibling modules.

#![allow(unused_imports)] // re-exports for topic submodules

// Re-exports for topic submodules (`use super::*`) and sibling modules
// (e.g. `block_proposal::tests`) that share this harness.
// External crates use `::crate_name` so submodule names cannot shadow them.
pub(crate) use super::*;
pub(crate) use crate::orchestrator::utils;
pub(crate) use ::async_trait::async_trait;
pub(crate) use ::beacon::{AttesterDuty, BeaconClient, BeaconClientConfig, VersionedAttestation};
pub(crate) use ::block_service::BeaconBlockClient;
pub(crate) use ::block_service::BuilderConfig;
pub(crate) use ::block_service::ProduceBlockResponse;
pub(crate) use ::block_service::WireBody;
pub(crate) use ::bn_manager::{
    AttestationSubmitter, BeaconNodeClient, OperationTimeouts, Propagator,
};
pub(crate) use ::builder::BuilderService;
pub(crate) use ::crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
pub(crate) use ::duty_tracker::DutyTracker;
pub(crate) use ::eth_types::{ForkName, ForkSchedule, Root, Slot};
pub(crate) use ::signer::{always_enabled, CircuitBreakerState, SignerService, ValidatorSigner};
pub(crate) use ::slashing::SlashingDb;
pub(crate) use ::timing::MockSlotClock;
pub(crate) use ::tree_hash::TreeHash;
pub(crate) use ::validator_store::ValidatorStore;
pub(crate) use std::collections::HashMap;
pub(crate) use std::future::Future;
pub(crate) use std::pin::Pin;
pub(crate) use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
pub(crate) use std::sync::{Arc, OnceLock};
pub(crate) use std::time::Duration;
pub(crate) use tokio::sync::{Mutex, MutexGuard};

/// Process-wide M2 / slot-loop histogram counters; serialize tests that
/// wait on or delta those samples (ARCH-7a + ARCH-3j C6). Slot loops also
/// write the fork gauges and the attestation-trigger counter, so the
/// `fork_resolution` and `head_events` readers take it too.
pub(crate) async fn m2_metric_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

// ── Shared helpers / mocks ─────────────────────────────────────────────

pub(crate) const TEST_GENESIS_TIME: u64 = 1606824023;

pub(crate) fn fast_timeouts() -> OperationTimeouts {
    OperationTimeouts {
        duty_fetch: Duration::from_millis(200),
        block_production: Duration::from_millis(200),
        block_publication: Duration::from_millis(200),
        attestation_fetch: Duration::from_millis(200),
        attestation_submit: Duration::from_millis(200),
        aggregate_fetch: Duration::from_millis(200),
        aggregate_submit: Duration::from_millis(200),
        sync_message: Duration::from_millis(200),
        sync_contribution: Duration::from_millis(200),
        preparation: Duration::from_millis(200),
    }
}

pub(crate) fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 1],
        altair_fork_epoch: 10,
        altair_fork_version: [0, 0, 0, 2],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0, 0, 0, 3],
        capella_fork_epoch: 30,
        capella_fork_version: [0, 0, 0, 4],
        // Block produces advertise "deneb". The V3 path requires that header
        // to match the slot fork, so Deneb starts at genesis in this fixture.
        deneb_fork_epoch: 0,
        deneb_fork_version: [0, 0, 0, 5],
        electra_fork_epoch: 50,
        electra_fork_version: [0, 0, 0, 6],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0, 0, 0, 7],
        gloas_fork_epoch: 70,
        gloas_fork_version: [0, 0, 0, 8],
    })
}

pub(crate) fn create_test_config() -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
}

pub(crate) struct MockSubmitter {
    pub(crate) call_count: AtomicUsize,
    should_succeed: std::sync::atomic::AtomicBool,
}

impl MockSubmitter {
    pub(crate) fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
            should_succeed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    #[allow(dead_code)]
    pub(super) fn set_should_succeed(&self, value: bool) {
        self.should_succeed.store(value, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    pub(super) fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl AttestationSubmitter for MockSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                + Send
                + 'a,
        >,
    > {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let should_succeed = self.should_succeed.load(Ordering::SeqCst);
        Box::pin(async move {
            if should_succeed {
                Ok(beacon::SubmitAttestationResult::Success)
            } else {
                Err(beacon::BeaconError::Timeout)
            }
        })
    }
}

/// Recorded `BeaconBlockClient` call. Dispatch tests assert on this seam,
/// not on wiremock — production never reaches `MockServer` for block produce.
#[derive(Debug, Clone)]
#[allow(dead_code)] // SSZ / blinded fields are recorded for dispatch assertions.
pub(crate) enum BlockBeaconCall {
    ProduceV3 {
        slot: Slot,
    },
    ProduceV4 {
        slot: Slot,
        builder_config: BuilderConfig,
    },
    PublishBlock {
        slot: Slot,
        builder_url: Option<String>,
        signature_bytes: Vec<u8>,
    },
    PublishBlindedBlock {
        slot: Slot,
    },
    PublishBlockSsz {
        is_blinded: bool,
        builder_url: Option<String>,
    },
    PublishExecutionPayloadEnvelope {
        signed_envelope: WireBody,
        blobs: WireBody,
        kzg_proofs: WireBody,
        consensus_version: String,
    },
}

/// Call-recording `BeaconBlockClient`.
///
/// Default produce still returns `Err("mock")` so existing tests keep their
/// assertions. `with_response` supplies a canned `ProduceBlockResponse`.
pub(crate) struct MockBlockBeacon {
    calls: std::sync::Mutex<Vec<BlockBeaconCall>>,
    produce_response: std::sync::Mutex<Option<ProduceBlockResponse>>,
}

impl MockBlockBeacon {
    pub(crate) fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            produce_response: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn with_response(response: ProduceBlockResponse) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            produce_response: std::sync::Mutex::new(Some(response)),
        }
    }

    pub(crate) fn set_response(&self, response: ProduceBlockResponse) {
        *self.produce_response.lock().unwrap() = Some(response);
    }

    fn record(&self, call: BlockBeaconCall) {
        self.calls.lock().unwrap().push(call);
    }

    fn produce_answer(&self) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        self.produce_response
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| block_service::BlockServiceError::Beacon("mock".to_string()))
    }

    pub(crate) fn recorded_calls(&self) -> Vec<BlockBeaconCall> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn produce_v3_slots(&self) -> Vec<Slot> {
        self.recorded_calls()
            .into_iter()
            .filter_map(|call| match call {
                BlockBeaconCall::ProduceV3 { slot } => Some(slot),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn produce_v4_calls(&self) -> Vec<(Slot, BuilderConfig)> {
        self.recorded_calls()
            .into_iter()
            .filter_map(|call| match call {
                BlockBeaconCall::ProduceV4 { slot, builder_config } => Some((slot, builder_config)),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn publish_block_calls(&self) -> Vec<(Slot, Option<String>, Vec<u8>)> {
        self.recorded_calls()
            .into_iter()
            .filter_map(|call| match call {
                BlockBeaconCall::PublishBlock { slot, builder_url, signature_bytes } => {
                    Some((slot, builder_url, signature_bytes))
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn publish_blinded_count(&self) -> usize {
        self.recorded_calls()
            .iter()
            .filter(|call| matches!(call, BlockBeaconCall::PublishBlindedBlock { .. }))
            .count()
    }

    pub(crate) fn envelope_publish_calls(&self) -> Vec<BlockBeaconCall> {
        self.recorded_calls()
            .into_iter()
            .filter(|call| matches!(call, BlockBeaconCall::PublishExecutionPayloadEnvelope { .. }))
            .collect()
    }
}

#[async_trait]
impl BeaconBlockClient for MockBlockBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        self.record(BlockBeaconCall::ProduceV3 { slot });
        self.produce_answer()
    }

    async fn produce_block_v4(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        self.record(BlockBeaconCall::ProduceV4 { slot, builder_config: builder_config.clone() });
        self.produce_answer()
    }

    async fn publish_block(
        &self,
        signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.record(BlockBeaconCall::PublishBlock {
            slot: signed_block.message.slot,
            builder_url: builder_url.map(str::to_string),
            signature_bytes: signed_block.signature.clone(),
        });
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), block_service::BlockServiceError> {
        self.record(BlockBeaconCall::PublishBlindedBlock { slot: signed_block.message.slot });
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        is_blinded: bool,
        builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.record(BlockBeaconCall::PublishBlockSsz {
            is_blinded,
            builder_url: builder_url.map(str::to_string),
        });
        Ok(())
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &WireBody,
        blobs: &WireBody,
        kzg_proofs: &WireBody,
        consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.record(BlockBeaconCall::PublishExecutionPayloadEnvelope {
            signed_envelope: signed_envelope.clone(),
            blobs: blobs.clone(),
            kzg_proofs: kzg_proofs.clone(),
            consensus_version: consensus_version.to_string(),
        });
        Ok(())
    }

    async fn produce_block_v3_for_duty(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        _duty: block_service::ProduceDuty,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }

    async fn produce_block_v3_ranked(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        _duty: Option<block_service::ProduceDuty>,
    ) -> Result<Vec<block_service::RankedBlock>, block_service::BlockServiceError> {
        let response =
            self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await?;
        Ok(vec![block_service::RankedBlock { bn_index: 0, response }])
    }

    async fn produce_block_v3_ranked_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<block_service::ProduceDuty>,
        _deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<block_service::RankedBlock>, block_service::BlockServiceError> {
        self.produce_block_v3_ranked(slot, randao_reveal, graffiti, builder_boost_factor, duty)
            .await
    }

    async fn produce_block_v4_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &block_service::BuilderConfig,
        _deadline: Option<tokio::time::Instant>,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        self.produce_block_v4(slot, randao_reveal, graffiti, builder_config).await
    }
}

pub(crate) fn create_mock_block_beacon() -> Arc<MockBlockBeacon> {
    Arc::new(MockBlockBeacon::new())
}

/// Block beacon that returns a block with a configurable `proposer_index`
/// and tracks whether `publish_block` / `publish_blinded_block` /
/// `publish_block_ssz` is called.  Used by the H-4 block-proposal integration
/// test to verify that a wrong `proposer_index` causes the duty to be
/// dropped before any publish attempt.
pub(crate) struct BadProposerBlockBeacon {
    pub(crate) slot: Slot,
    pub(crate) bad_proposer_index: u64,
    pub(crate) publish_called: Arc<AtomicBool>,
}

#[async_trait]
impl BeaconBlockClient for BadProposerBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        Ok(ProduceBlockResponse {
            data: serde_json::json!({
                "slot": self.slot.to_string(),
                "proposer_index": self.bad_proposer_index.to_string(),
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body": "0x"
            }),
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
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
        Err(block_service::BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
        self.publish_called.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), block_service::BlockServiceError> {
        self.publish_called.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), block_service::BlockServiceError> {
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
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }

    async fn produce_block_v3_for_duty(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        _duty: block_service::ProduceDuty,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }

    async fn produce_block_v3_ranked(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        _duty: Option<block_service::ProduceDuty>,
    ) -> Result<Vec<block_service::RankedBlock>, block_service::BlockServiceError> {
        let response =
            self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await?;
        Ok(vec![block_service::RankedBlock { bn_index: 0, response }])
    }

    async fn produce_block_v3_ranked_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<block_service::ProduceDuty>,
        _deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<block_service::RankedBlock>, block_service::BlockServiceError> {
        self.produce_block_v3_ranked(slot, randao_reveal, graffiti, builder_boost_factor, duty)
            .await
    }

    async fn produce_block_v4_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &block_service::BuilderConfig,
        _deadline: Option<tokio::time::Instant>,
    ) -> Result<block_service::ProduceBlockResponse, block_service::BlockServiceError> {
        self.produce_block_v4(slot, randao_reveal, graffiti, builder_config).await
    }
}

pub(crate) fn create_mock_validator_store() -> Arc<ValidatorStore> {
    Arc::new(ValidatorStore::new([0u8; 20], 100))
}

// ── H-7 mock: captures sync committee message submissions (shared mock, RF4-24)
//
// Configurable MockBeaconNodeClient with:
//   - `post_sync_committee_duties` → returns a duty for `duty_pubkey`
//   - `submit_sync_committee_messages` → records beacon_block_root values
//   - All other methods → error by default (orchestrator handles gracefully)
//
// Used to test the `sync_enabled` guard without a real beacon node.
pub(super) fn sync_guard_beacon(
    duty_pubkey: [u8; 48],
    submitted_roots: Arc<std::sync::Mutex<Vec<Root>>>,
) -> bn_manager::MockBeaconNodeClient {
    use beacon::ExecutionOptimisticResponse;
    use eth_types::SyncCommitteeDuty;
    bn_manager::MockBeaconNodeClient::new()
        .with_slot_aware_block_root(0, &[], |_queried| {
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
        })
        .with_post_sync_committee_duties(move |_epoch, _indices| {
            Ok(ExecutionOptimisticResponse {
                execution_optimistic: false,
                data: vec![SyncCommitteeDuty {
                    pubkey: duty_pubkey,
                    validator_index: 1,
                    validator_sync_committee_indices: vec![0],
                }],
            })
        })
        .with_submit_sync_committee_messages(move |messages| {
            let mut roots = submitted_roots.lock().unwrap();
            for msg in messages {
                roots.push(msg.beacon_block_root);
            }
            Ok(())
        })
        .with_submit_contribution_and_proofs(|_proofs| Ok(()))
}

/// Helper to build an orchestrator wired to a wiremock mock_server for aggregation tests.
pub(super) async fn build_aggregation_orchestrator(
    mock_server_uri: &str,
) -> (
    DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    PublicKey,
    String,
) {
    build_aggregation_orchestrator_with_schedule(mock_server_uri, create_test_fork_schedule()).await
}

pub(super) async fn build_aggregation_orchestrator_with_schedule(
    mock_server_uri: &str,
    schedule: Arc<ForkSchedule>,
) -> (
    DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>,
    OrchestratorHandle,
    PublicKey,
    String,
) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

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

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = OrchestratorConfig::new([0xaa; 32], schedule);
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits its duties (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .unwrap();

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

    (orchestrator, handle, pubkey, pubkey_hex)
}

// --- G-1-06: Electra fork transition integration tests ---

/// A submitter that captures the submitted VersionedAttestation for assertion.
pub(super) struct CapturingSubmitter {
    captured: parking_lot::Mutex<Vec<VersionedAttestation>>,
}

impl CapturingSubmitter {
    pub(super) fn new() -> Self {
        Self { captured: parking_lot::Mutex::new(Vec::new()) }
    }

    pub(super) fn captured(&self) -> Vec<VersionedAttestation> {
        self.captured.lock().clone()
    }
}

impl AttestationSubmitter for CapturingSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                + Send
                + 'a,
        >,
    > {
        self.captured.lock().push(attestations.clone());
        Box::pin(async move { Ok(beacon::SubmitAttestationResult::Success) })
    }
}

// ── H-3: circuit-breaker scoping helpers ────────────────────────────────

/// Wire up a proposer duty in a wiremock mock server so that
/// `duty_tracker.fetch_proposer_duties(epoch)` succeeds and the duty is
/// cached for `slot`.
pub(super) async fn setup_proposer_duty(
    mock_server: &wiremock::MockServer,
    epoch: u64,
    slot: u64,
    pubkey_hex: &str,
    validator_index: u64,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

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
        .mount(mock_server)
        .await;
}

/// Deleting the body of `arm_operation_deadline` (returning "now") or
/// ignoring the clock makes this fail. The slot loop passes the returned
/// instant only into block proposal.
#[tokio::test]
async fn arm_operation_deadline_is_the_time_left_in_the_slot() {
    let beacon = Arc::new(
        BeaconClient::new(BeaconClientConfig::new("http://127.0.0.1:1".to_string())).unwrap(),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let signer = Arc::new(
        SignerService::new(composite, Arc::new(SlashingDb::open_in_memory().unwrap()))
            .with_enablement(always_enabled()),
    );
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
    let clock = Arc::new(MockSlotClock::new(0, Duration::from_secs(12), 32));
    let slot = 5u64;
    clock.set_slot_with_offset_ms(slot, 11_800);
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
        create_test_config(),
        pubkey_map,
    ));

    let before = tokio::time::Instant::now();
    let deadline = orchestrator.arm_operation_deadline(slot);
    let left = deadline.saturating_duration_since(before);
    assert!(left > Duration::from_millis(100) && left < Duration::from_millis(400), "{left:?}");

    let src = include_str!("../mod.rs");
    assert!(src.contains("let proposal_deadline = self.arm_operation_deadline(current_slot);"));
    assert!(src.contains("Some(proposal_deadline)"));
    assert!(!src.contains("set_operation_deadline"));
}

// ── Slot-loop writers hold the M2 metric lock ──────────────────────────

/// Result of [`slot_loop_lock_scan`]. Entries are `<file>::<fn>`.
#[derive(Debug, Default)]
struct LockScan {
    unlocked: Vec<String>,
    exempt: Vec<String>,
    /// `include!` and `path` attributes: they pull in code the scan never reads.
    escapes: Vec<String>,
    run_sites: usize,
}

struct ScannedFn {
    name: String,
    is_test: bool,
    item: std::ops::Range<usize>,
    body: std::ops::Range<usize>,
}

struct ScannedFile<'a> {
    name: &'a str,
    src: &'a str,
    code: Vec<u8>,
    fns: Vec<ScannedFn>,
}

/// Fns in a set of coordinator test files that drive a slot loop without
/// holding [`m2_metric_lock`].
///
/// A fn drives the loop when its body has `.run()` or `::run(`, or calls a
/// fn that drives it without holding the lock. Calls are matched by name in
/// every file of the set, so a helper reached from a child module or a
/// sibling file counts. The lock is held at a call when the body's top level
/// binds `let <name> = m2_metric_lock().await;` before it, `<name>` is not
/// `_`, and no `drop(<name>)` comes in between. Comments and literals are
/// blanked first. A run site outside every fn body, and a lockless helper
/// that no fn calls, are reported. A test whose body has a
/// `// m2_lock_exempt: <reason>` comment is listed in `exempt` instead.
/// `include!` and `path` attributes (also inside `cfg_attr`) are listed in
/// `escapes`.
fn slot_loop_lock_scan(files: &[(&str, &str)]) -> LockScan {
    let files: Vec<_> = files
        .iter()
        .map(|&(name, src)| {
            let code = code_only(src);
            let fns = fn_items(&code);
            ScannedFile { name, src, code, fns }
        })
        .collect();
    let fns: Vec<(usize, &ScannedFn)> = files
        .iter()
        .enumerate()
        .flat_map(|(file, scanned)| scanned.fns.iter().map(move |f| (file, f)))
        .collect();
    let owner = |file: usize, at: usize| {
        fns.iter()
            .enumerate()
            .filter(|(_, (in_file, f))| *in_file == file && f.body.contains(&at))
            .min_by_key(|(_, (_, f))| f.body.len())
            .map(|(index, _)| index)
    };
    let mut scan = LockScan::default();
    let mut triggers = vec![Vec::new(); fns.len()];
    let mut outside = Vec::new();
    for (file, scanned) in files.iter().enumerate() {
        let code = &scanned.code;
        for at in find_all(code, b".run()").into_iter().chain(find_all(code, b"::run(")) {
            scan.run_sites += 1;
            match owner(file, at) {
                Some(index) => triggers[index].push(at),
                None => outside.push((file, at)),
            }
        }
        for (at, what) in escape_sites(code) {
            scan.escapes.push(format!(
                "{}::{what} at line {}",
                scanned.name,
                line_of(scanned.src, at)
            ));
        }
    }
    let mut needs = vec![false; fns.len()];
    let mut uncalled = vec![false; fns.len()];
    loop {
        let mut changed = false;
        for index in 0..fns.len() {
            let (file, f) = fns[index];
            if needs[index] || triggers[index].iter().all(|&at| lock_held(&files[file].code, f, at))
            {
                continue;
            }
            needs[index] = true;
            changed = true;
            if f.is_test {
                continue;
            }
            let mut called = false;
            for (caller_file, scanned) in files.iter().enumerate() {
                for at in call_sites(&scanned.code, &f.name) {
                    called = true;
                    match owner(caller_file, at) {
                        Some(caller) => triggers[caller].push(at),
                        None => outside.push((caller_file, at)),
                    }
                }
            }
            uncalled[index] = !called;
        }
        if !changed {
            break;
        }
    }
    for (index, &(file, f)) in fns.iter().enumerate().filter(|(index, _)| needs[*index]) {
        let name = format!("{}::{}", files[file].name, f.name);
        if f.is_test && has_exempt_reason(&files[file].src[f.item.clone()]) {
            scan.exempt.push(name);
        } else if f.is_test {
            scan.unlocked.push(name);
        } else if uncalled[index] {
            scan.unlocked.push(format!("{name} (no caller)"));
        }
    }
    outside.sort_unstable();
    for (file, at) in outside {
        let scanned = &files[file];
        scan.unlocked.push(format!(
            "{}::outside a fn at line {}",
            scanned.name,
            line_of(scanned.src, at)
        ));
    }
    scan
}

/// `include!` calls and attributes with a `path = ` item (`#[path = ..]`,
/// `#[cfg_attr(.., path = ..)]`).
fn escape_sites(code: &[u8]) -> Vec<(usize, &'static str)> {
    let mut sites: Vec<_> = find_words(code, b"include")
        .into_iter()
        .filter(|&at| code.get(skip_ws(code, at + 7)) == Some(&b'!'))
        .map(|at| (at, "include!"))
        .collect();
    for at in find_all(code, b"#") {
        let mut open = skip_ws(code, at + 1);
        if code.get(open) == Some(&b'!') {
            open = skip_ws(code, open + 1);
        }
        if code.get(open) != Some(&b'[') {
            continue;
        }
        let mut depth = 0usize;
        let Some(len) = code[open..].iter().position(|&byte| {
            match byte {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            depth == 0
        }) else {
            continue;
        };
        let attr = &code[open..open + len];
        let sets_path = find_words(attr, b"path").into_iter().any(|word| {
            let eq = skip_ws(attr, word + 4);
            attr.get(eq) == Some(&b'=') && attr.get(eq + 1) != Some(&b'=')
        });
        if sets_path {
            sites.push((at, "#[path]"));
        }
    }
    sites.sort_unstable();
    sites
}

fn line_of(src: &str, at: usize) -> usize {
    src[..at].matches('\n').count() + 1
}

/// Every `.rs` file under `dir`, subdirectories included, as
/// (`/`-joined path relative to `dir`, source), sorted by path.
fn rs_files_under(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(next) = dirs.pop() {
        for entry in std::fs::read_dir(&next).expect("read test dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path
                    .strip_prefix(dir)
                    .expect("a path under dir")
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push((name, std::fs::read_to_string(&path).expect("read test file")));
            }
        }
    }
    files.sort();
    files
}

/// `src` with comments and the contents of string and char literals blanked.
fn code_only(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to.min(b.len())] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let ident = |at: usize| at < b.len() && (b[at].is_ascii_alphanumeric() || b[at] == b'_');
    let mut i = 0;
    while i < b.len() {
        let raw_hashes = (b[i] == b'r'
            && (i == 0 || !ident(i - 1) || (b[i - 1] == b'b' && (i < 2 || !ident(i - 2)))))
        .then(|| b[i + 1..].iter().take_while(|&&c| c == b'#').count())
        .filter(|&n| b.get(i + 1 + n) == Some(&b'"'));
        if let Some(n) = raw_hashes {
            let open = i + 2 + n;
            let mut close = b"\"".to_vec();
            close.extend(std::iter::repeat_n(b'#', n));
            let end = find_from(b, &close, open).unwrap_or(b.len());
            blank(&mut out, open, end);
            i = end + close.len();
        } else if b[i..].starts_with(b"//") {
            let end = find_from(b, b"\n", i).unwrap_or(b.len());
            blank(&mut out, i, end);
            i = end;
        } else if b[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if b[i] == b'\'' {
            let width = src[i + 1..].chars().next().map_or(1, char::len_utf8);
            let end = if b.get(i + 1) == Some(&b'\\') {
                find_from(b, b"'", i + 3)
            } else {
                (b.get(i + 1 + width) == Some(&b'\'')).then_some(i + 1 + width)
            };
            match end {
                Some(end) => {
                    blank(&mut out, i + 1, end);
                    i = end + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    out
}

fn fn_items(code: &[u8]) -> Vec<ScannedFn> {
    let mut fns = Vec::new();
    for at in find_words(code, b"fn") {
        let name_at = skip_ws(code, at + 2);
        let name_end = ident_end(code, name_at);
        if name_end == name_at {
            continue;
        }
        let mut depth = 0i32;
        let mut open = None;
        for (offset, &byte) in code[name_end..].iter().enumerate() {
            match byte {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b'{' if depth == 0 => {
                    open = Some(name_end + offset);
                    break;
                }
                b';' if depth == 0 => break,
                _ => {}
            }
        }
        let Some((open, close)) = open.and_then(|open| Some((open, matching_brace(code, open)?)))
        else {
            continue;
        };
        let item_at = code[..at].iter().rposition(|c| b"{};".contains(c)).map_or(0, |p| p + 1);
        let head = &code[item_at..at];
        fns.push(ScannedFn {
            name: String::from_utf8_lossy(&code[name_at..name_end]).into_owned(),
            is_test: find_from(head, b"#[test]", 0).is_some()
                || find_from(head, b"#[tokio::test", 0).is_some(),
            item: item_at..close + 1,
            body: open..close + 1,
        });
    }
    fns
}

/// `true` when a top-level `let <name> = m2_metric_lock().await;` of `f`
/// comes before `at` and no `drop(<name>)` sits between them.
fn lock_held(code: &[u8], f: &ScannedFn, at: usize) -> bool {
    let mut depth = 0usize;
    let mut i = f.body.start;
    while i < at {
        match code[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        if depth == 1 && is_word_at(code, i, b"let") {
            if let Some(name) = lock_binding(code, i + 3) {
                let dropped = find_all(&code[i..at], b"drop(").into_iter().any(|offset| {
                    let arg = skip_ws(code, i + offset + 5);
                    let arg_end = ident_end(code, arg);
                    code[arg..arg_end] == *name.as_bytes() && code[skip_ws(code, arg_end)] == b')'
                });
                if !dropped {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// The `<name>` of `let [mut] <name> = m2_metric_lock().await;` at `at`.
fn lock_binding(code: &[u8], at: usize) -> Option<String> {
    let mut i = skip_ws(code, at);
    if is_word_at(code, i, b"mut") {
        i = skip_ws(code, i + 3);
    }
    let name_end = ident_end(code, i);
    let name = std::str::from_utf8(&code[i..name_end]).ok()?.to_string();
    if name.is_empty() || name == "_" {
        return None;
    }
    let mut i = name_end;
    for token in [&b"="[..], b"m2_metric_lock", b"(", b")", b".", b"await", b";"] {
        i = skip_ws(code, i);
        if !code[i..].starts_with(token) || (token == b"await" && ident_end(code, i) != i + 5) {
            return None;
        }
        i += token.len();
    }
    Some(name)
}

/// Calls of the plain fn `name(` (not `fn name`, not a `.name(` method).
fn call_sites(code: &[u8], name: &str) -> Vec<usize> {
    find_words(code, name.as_bytes())
        .into_iter()
        .filter(|&at| code[skip_ws(code, at + name.len())] == b'(')
        .filter(|&at| {
            let before = &code[..at];
            let prev = before.iter().rposition(|c| !c.is_ascii_whitespace());
            let after_fn = prev.is_some_and(|p| p >= 1 && is_word_at(code, p - 1, b"fn"));
            !after_fn && prev.is_none_or(|p| code[p] != b'.')
        })
        .collect()
}

fn has_exempt_reason(item: &str) -> bool {
    item.lines().any(|line| {
        line.trim_start()
            .strip_prefix("// m2_lock_exempt:")
            .is_some_and(|reason| !reason.trim().is_empty())
    })
}

fn matching_brace(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, &byte) in code[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|p| from + p)
}

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut from = 0;
    while let Some(at) = find_from(hay, needle, from) {
        hits.push(at);
        from = at + 1;
    }
    hits
}

fn find_words(code: &[u8], word: &[u8]) -> Vec<usize> {
    find_all(code, word).into_iter().filter(|&at| is_word_at(code, at, word)).collect()
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_word_at(code: &[u8], at: usize, word: &[u8]) -> bool {
    code[at..].starts_with(word)
        && (at == 0 || !is_ident_byte(code[at - 1]))
        && code.get(at + word.len()).is_none_or(|&c| !is_ident_byte(c))
}

fn ident_end(code: &[u8], at: usize) -> usize {
    at + code[at..].iter().take_while(|&&c| is_ident_byte(c)).count()
}

fn skip_ws(code: &[u8], at: usize) -> usize {
    at + code[at..].iter().take_while(|c| c.is_ascii_whitespace()).count()
}

/// One row per rule of [`slot_loop_lock_scan`].
const LOCK_SCAN_FIXTURE: &str = r####"
#[tokio::test]
async fn locked() {
    let _guard = m2_metric_lock().await;
    orchestrator.run().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unlocked() {
    orchestrator.run().await;
}

#[tokio::test]
async fn underscore_binding() {
    let _ = m2_metric_lock().await;
    orchestrator.run().await;
}

#[tokio::test]
async fn locked_after_run() {
    orchestrator.run().await;
    let _guard = m2_metric_lock().await;
}

#[tokio::test]
async fn locked_in_inner_block() {
    {
        let _guard = m2_metric_lock().await;
    }
    orchestrator.run().await;
}

#[tokio::test]
async fn not_awaited() {
    let _guard = m2_metric_lock();
    orchestrator.run().await;
}

#[tokio::test]
async fn dropped_before_run() {
    let guard = m2_metric_lock().await;
    drop(guard);
    orchestrator.run().await;
}

#[tokio::test]
async fn lock_only_in_a_comment() {
    // let _guard = m2_metric_lock().await;
    /* let _guard = m2_metric_lock().await; */
    orchestrator.run().await;
}

#[tokio::test]
async fn run_only_in_text() {
    // orchestrator.run().await;
    let _ = (".run()", r#"::run("#, '"');
}

#[tokio::test]
async fn path_call() {
    let _: &'static str = "";
    DutyOrchestrator::run(&mut orchestrator).await;
}

async fn helper_without_lock(expect: [u8; 32]) -> [u8; 32] {
    orchestrator.run().await;
    expect
}

#[tokio::test]
async fn calls_helper_locked() {
    let mut metrics = m2_metric_lock().await;
    helper_without_lock([0; 32]).await;
}

#[tokio::test]
async fn calls_helper_unlocked() {
    tokio::select! { _ = helper_without_lock([0; 32]) => {} }
}

async fn helper_with_lock() {
    let _metrics = m2_metric_lock().await;
    orchestrator.run().await;
}

#[tokio::test]
async fn calls_locking_helper() {
    helper_with_lock().await;
}

async fn orphan_helper() {
    let run = tokio::spawn(async move { orchestrator.run().await });
}

#[test]
fn exempt_never_polled() {
    // m2_lock_exempt: builds the future to check Send and never polls it
    let fut = orchestrator.run();
}

#[test]
fn exempt_without_reason() {
    // m2_lock_exempt:
    let fut = orchestrator.run();
}

#[tokio::test]
async fn lock_in_a_nested_fn() {
    async fn inner() {
        let _guard = m2_metric_lock().await;
    }
    inner().await;
    orchestrator.run().await;
}

macro_rules! generated {
    () => {
        orchestrator.run().await;
    };
}
"####;

#[test]
fn slot_loop_lock_scan_reports_each_unlocked_shape() {
    let scan = slot_loop_lock_scan(&[("fixture.rs", LOCK_SCAN_FIXTURE)]);
    let unlocked = [
        "unlocked",
        "underscore_binding",
        "locked_after_run",
        "locked_in_inner_block",
        "not_awaited",
        "dropped_before_run",
        "lock_only_in_a_comment",
        "path_call",
        "calls_helper_unlocked",
        "orphan_helper (no caller)",
        "exempt_without_reason",
        "lock_in_a_nested_fn",
        "outside a fn at line 118",
    ];
    assert_eq!(scan.unlocked, unlocked.map(|name| format!("fixture.rs::{name}")));
    assert_eq!(scan.exempt, ["fixture.rs::exempt_never_polled"]);
    assert!(scan.escapes.is_empty(), "{:?}", scan.escapes);
    assert_eq!(scan.run_sites, 16);
}

/// One row per cross-file rule of [`slot_loop_lock_scan`]: `parent.rs` and its
/// child module share helpers, and `escapes.rs` pulls in code from elsewhere.
const LOCK_SCAN_TREE: [(&str, &str); 3] = [
    (
        "parent.rs",
        r#"
async fn drive() {
    orchestrator.run().await;
}

async fn drive_for_the_child() {
    orchestrator.run().await;
}

#[tokio::test]
async fn parent_locked() {
    let _guard = m2_metric_lock().await;
    drive().await;
}

mod child;
"#,
    ),
    (
        "parent/child.rs",
        r#"
use super::*;

#[tokio::test]
async fn child_unlocked() {
    super::drive().await;
}

#[tokio::test]
async fn child_locked() {
    let _guard = m2_metric_lock().await;
    drive_for_the_child().await;
}
"#,
    ),
    (
        "escapes.rs",
        r#"
include!("extra/unlocked.rs");
std::include! { "more.rs" }
#[path = "../outside.rs"]
mod outside;
#[cfg_attr(test, path = "other.rs")]
mod other;
#[cfg(my_path = "x")]
mod plain;

fn neither() {
    let include = include_str!("data.txt");
    let path = include.len();
}
"#,
    ),
];

#[test]
fn slot_loop_lock_scan_follows_calls_across_files_and_reports_escapes() {
    let scan = slot_loop_lock_scan(&LOCK_SCAN_TREE);
    assert_eq!(scan.unlocked, ["parent/child.rs::child_unlocked"]);
    assert_eq!(
        scan.escapes,
        [
            "escapes.rs::include! at line 2",
            "escapes.rs::include! at line 3",
            "escapes.rs::#[path] at line 4",
            "escapes.rs::#[path] at line 6",
        ]
    );
    assert!(scan.exempt.is_empty(), "{:?}", scan.exempt);
    assert_eq!(scan.run_sites, 2);
}

#[test]
fn rs_files_under_reads_every_subdirectory() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (file, text) in
        [("top.rs", "a"), ("child/mod.rs", "b"), ("child/deeper/leaf.rs", "c"), ("notes.txt", "d")]
    {
        let path = dir.path().join(file);
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("create dir");
        std::fs::write(path, text).expect("write file");
    }
    let expected = [("child/deeper/leaf.rs", "c"), ("child/mod.rs", "b"), ("top.rs", "a")];
    assert_eq!(rs_files_under(dir.path()), expected.map(|(n, s)| (n.to_owned(), s.to_owned())));
}

/// Every coordinator test that drives `DutyOrchestrator::run` holds
/// [`m2_metric_lock`] first, so the exact-delta readers in `cold_cache.rs`
/// and `phase_block_offset.rs` never see a concurrent slot loop's sample.
/// It reads every `.rs` file under `coordinator/tests`, subdirectories
/// included, and fails on `include!` or a `path` attribute.
#[test]
fn every_slot_loop_test_holds_the_m2_metric_lock() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/coordinator/tests");
    let files = rs_files_under(std::path::Path::new(dir));
    let files: Vec<_> = files.iter().map(|(name, src)| (name.as_str(), src.as_str())).collect();
    let scan = slot_loop_lock_scan(&files);
    assert!(scan.escapes.is_empty(), "code the scan cannot read: {:#?}", scan.escapes);
    assert!(
        scan.unlocked.is_empty(),
        "take m2_metric_lock().await before .run(): {:#?}",
        scan.unlocked
    );
    assert_eq!(scan.exempt, ["core.rs::test_duty_orchestrator_run_future_is_send"]);
    let run_sites = scan.run_sites;
    assert!(run_sites >= 35, "the scan must see every slot-loop call site, saw {run_sites}");
}

// ── Topic modules ─────────────────────────────────────────────────────

mod aggregation;
mod circuit_breaker;
mod cold_cache;
mod core;
mod duty_management;
mod fork_resolution;
mod fork_transition;
mod head_capture;
mod phase2_signer;
mod phase_block_offset;
mod proposal;
mod proposal_first;
mod slashing_protection;
mod slot_anchor;
mod slot_replay;
mod spans;
mod sync_gating;
mod timeouts;
mod wait_window;
