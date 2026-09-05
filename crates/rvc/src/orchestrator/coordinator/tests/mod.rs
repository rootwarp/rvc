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
pub(crate) use ::block_service::ProduceBlockResponse;
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
/// wait on or delta those samples (ARCH-7a + ARCH-3j C6).
pub(super) async fn m2_metric_lock() -> MutexGuard<'static, ()> {
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
        deneb_fork_epoch: 40,
        deneb_fork_version: [0, 0, 0, 5],
        electra_fork_epoch: 50,
        electra_fork_version: [0, 0, 0, 6],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0, 0, 0, 7],
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

pub(crate) struct MockBlockBeacon;

#[async_trait]
impl BeaconBlockClient for MockBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
        Err(block_service::BlockServiceError::Beacon("mock".to_string()))
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
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
    ) -> Result<(), block_service::BlockServiceError> {
        Ok(())
    }
}

pub(crate) fn create_mock_block_beacon() -> Arc<MockBlockBeacon> {
    Arc::new(MockBlockBeacon)
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
        })
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
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
    ) -> Result<(), block_service::BlockServiceError> {
        self.publish_called.store(true, Ordering::SeqCst);
        Ok(())
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

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey.to_bytes(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // D-3 fail-closed: register the loaded validator so the per-validator
    // signing gate permits its duties (mirrors startup registration).
    let validator_store = create_mock_validator_store();
    validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()));

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

// ── Topic modules ─────────────────────────────────────────────────────

mod aggregation;
mod bps_fields;
mod circuit_breaker;
mod cold_cache;
mod core;
mod duty_management;
mod fork_transition;
mod phase_block_offset;
mod proposal;
mod proposal_first;
mod slashing_protection;
mod spans;
mod sync_gating;
mod timeouts;
mod wait_window;
