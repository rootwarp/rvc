//! ARCH-2h / M10: in-flight block publish completes when shutdown is signalled.
//!
//! Pre-fix: the composition root polled `orchestrator.run()` inside a three-arm
//! `select!` with `shutdown_signal()`. When the signal fired, `select!` dropped the
//! orchestrator future mid-phase — including an in-flight `publish_block` — and the
//! subsequent `handle.shutdown()` targeted a future that no longer existed.
//!
//! Post-fix: the orchestrator is `TaskExecutor::spawn`ed; signal handling only
//! requests cooperative stop + tiered join. A publish that has already entered the
//! BN mock must complete before the join returns.
//!
//! Every body is wrapped in `tokio::time::timeout` so a hang (pre-fix interleaving)
//! fails loudly rather than wedging CI.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    BeaconError, DependentRootResponse, ExecutionOptimisticResponse, ProposerDuty,
    SubmitAttestationResult, VersionedAttestation,
};
use block_service::{
    BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse as BlockProdResp,
};
use bn_manager::{
    AttestationSubmitter, BeaconNodeClient, BlockProducer, MockBeaconNodeClient, OperationTimeouts,
    Propagator,
};
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, Slot};
use rvc::bootstrap::executor::{ShutdownTier, TaskExecutor, TierBudget};
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle,
};
use signer::{always_enabled, CircuitBreakerState, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const SLOT_DURATION: Duration = Duration::from_secs(12);
const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_INDEX: u64 = 1;
const PROPOSAL_SLOT: Slot = 65;
const ZERO_DEPENDENT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ── blocking publish mock ────────────────────────────────────────────────────

/// Records publishes and can hold `publish_block` until a barrier is released.
struct BarrierBlockBeacon {
    validator_index: u64,
    /// Set when `publish_block` is entered (before waiting).
    entered: Arc<AtomicBool>,
    /// Waiters blocked in `publish_block` until this is notified.
    release: Arc<Notify>,
    /// Number of successful publishes observed by the mock.
    published: Arc<AtomicUsize>,
    /// When true, `publish_block` waits on `release` before completing.
    hold: AtomicBool,
}

impl BarrierBlockBeacon {
    fn new(validator_index: u64) -> Self {
        Self {
            validator_index,
            entered: Arc::new(AtomicBool::new(false)),
            release: Arc::new(Notify::new()),
            published: Arc::new(AtomicUsize::new(0)),
            hold: AtomicBool::new(true),
        }
    }
}

#[async_trait]
impl BeaconBlockClient for BarrierBlockBeacon {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<BlockProdResp, BlockServiceError> {
        let mut block = eth_types::external_vector_deneb_block();
        block.slot = slot;
        block.proposer_index = self.validator_index;
        Ok(BlockProdResp {
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
            candidate_memo: beacon::CandidateMemo::arc(),
        })
    }

    async fn produce_block_v4(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<BlockProdResp, BlockServiceError> {
        Err(BlockServiceError::Beacon("produce_block_v4 not configured".to_string()))
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        let _ = signed_block;
        self.entered.store(true, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            // Hold ~1 s of wall time or until released — models a slow BN publish.
            tokio::select! {
                _ = self.release.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        let _ = signed_block;
        self.entered.store(true, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            tokio::select! {
                _ = self.release.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        self.entered.store(true, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            tokio::select! {
                _ = self.release.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
        self.published.fetch_add(1, Ordering::SeqCst);
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

// ── noop submitter ───────────────────────────────────────────────────────────

struct NoopSubmitter;

impl AttestationSubmitter for NoopSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── BN factory ───────────────────────────────────────────────────────────────

fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 1],
        altair_fork_epoch: 10,
        altair_fork_version: [0, 0, 0, 2],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0, 0, 0, 3],
        capella_fork_epoch: 30,
        capella_fork_version: [0, 0, 0, 4],
        deneb_fork_epoch: 0,
        deneb_fork_version: [0, 0, 0, 5],
        electra_fork_epoch: 50,
        electra_fork_version: [0, 0, 0, 6],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0, 0, 0, 7],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0, 0, 0, 8],
    })
}

fn harness_timeouts() -> OperationTimeouts {
    // Publish barrier is up to 2 s; production+publication must cover it.
    OperationTimeouts {
        duty_fetch: Duration::from_secs(2),
        block_production: Duration::from_secs(2),
        block_publication: Duration::from_secs(3),
        attestation_fetch: Duration::from_millis(50),
        attestation_submit: Duration::from_millis(50),
        aggregate_fetch: Duration::from_millis(50),
        aggregate_submit: Duration::from_millis(50),
        sync_message: Duration::from_millis(50),
        sync_contribution: Duration::from_millis(50),
        preparation: Duration::from_millis(50),
    }
}

fn build_proposer_beacon(pubkey_hex: String, proposal_slot: Slot) -> MockBeaconNodeClient {
    let pk = pubkey_hex.clone();
    MockBeaconNodeClient::new()
        .with_get_block_root(|_block_id| {
            Err(BeaconError::HttpError("harness: empty slot (no head)".to_string()))
        })
        .with_get_attester_duties(move |_epoch, _indices| {
            Ok(DependentRootResponse {
                dependent_root: ZERO_DEPENDENT.to_string(),
                execution_optimistic: false,
                data: vec![],
            })
        })
        .with_get_proposer_duties(move |epoch| {
            let slot_epoch = proposal_slot / SLOTS_PER_EPOCH;
            let data = if epoch == slot_epoch {
                vec![ProposerDuty {
                    pubkey: pk.clone(),
                    validator_index: VALIDATOR_INDEX.to_string(),
                    slot: proposal_slot.to_string(),
                }]
            } else {
                vec![]
            };
            Ok(DependentRootResponse {
                dependent_root: ZERO_DEPENDENT.to_string(),
                execution_optimistic: false,
                data,
            })
        })
        .with_post_sync_committee_duties(move |_epoch, _indices| {
            Ok(ExecutionOptimisticResponse { execution_optimistic: false, data: vec![] })
        })
        .with_prepare_beacon_proposer(|_p| Ok(()))
        .with_submit_beacon_committee_subscriptions(|_s| Ok(()))
}

struct Harness {
    orchestrator: DutyOrchestrator<MockSlotClock, NoopSubmitter, BarrierBlockBeacon>,
    handle: OrchestratorHandle,
    block_beacon: Arc<BarrierBlockBeacon>,
}

async fn build_harness(pk: PublicKey, sk: SecretKey) -> Harness {
    let pubkey_hex = format!("0x{}", hex::encode(pk.to_bytes()));
    let beacon = Arc::new(build_proposer_beacon(pubkey_hex, PROPOSAL_SLOT));

    let duty_tracker =
        Arc::new(DutyTracker::new(beacon.clone(), vec![VALIDATOR_INDEX.to_string()]));
    // Warm duty cache so the slot loop does not stall on BN fetches.
    let epoch = PROPOSAL_SLOT / SLOTS_PER_EPOCH;
    duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();
    let _ = duty_tracker.fetch_sync_committee_duties(epoch).await;
    duty_tracker.fetch_duties_for_epoch(epoch + 1).await.unwrap();
    duty_tracker.fetch_proposer_duties(epoch + 1).await.unwrap();
    let _ = duty_tracker.fetch_sync_committee_duties(epoch + 1).await;

    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let block_beacon = Arc::new(BarrierBlockBeacon::new(VALIDATOR_INDEX));
    let propagator = Arc::new(Propagator::new(Arc::new(NoopSubmitter)));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    validator_store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
    validator_store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

    let mut map = HashMap::new();
    map.insert(pk.to_bytes(), pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, SLOT_DURATION, SLOTS_PER_EPOCH));
    clock.set_slot(PROPOSAL_SLOT);
    // Past 2/3 so att/agg waits are zero after proposal phase.
    clock.advance_time(9);

    let (_key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);
    let config = OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
        .with_timeouts(harness_timeouts());

    let (orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
        attesting_enabled: Arc::new(AtomicBool::new(false)),
        ..OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon as Arc<dyn BeaconNodeClient>,
            block_beacon.clone(),
            None,
            validator_store,
            config,
            pubkey_map,
        )
    });

    Harness { orchestrator, handle, block_beacon }
}

/// Production-shaped lifecycle: spawn orchestrator on executor, wait for signal
/// arm (simulated by cancel token / handle), drain with TierBudget.
async fn run_executor_lifecycle(
    mut orchestrator: DutyOrchestrator<MockSlotClock, NoopSubmitter, BarrierBlockBeacon>,
    handle: OrchestratorHandle,
    on_entered_publish: impl FnOnce() + Send + 'static,
    entered: Arc<AtomicBool>,
    release: Arc<Notify>,
) -> rvc::bootstrap::executor::ShutdownOutcome {
    let token = CancellationToken::new();
    let (executor, mut shutdown_rx) = TaskExecutor::new(token.clone());

    executor.spawn("duty_orchestrator", ShutdownTier::Orchestrator, async move {
        let _ = orchestrator.run().await;
    });

    // Poll until publish is entered, then request shutdown the same way run.rs does.
    let wait_entered = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::SeqCst) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        on_entered_publish();
        // Simulate operator signal: request orchestrator stop (watch), then drain.
        // Do NOT drop the orchestrator task — that is the pre-fix bug.
        handle.shutdown();
        // Brief pause so the in-flight publish is still blocked when drain starts.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Release the BN barrier so publish can complete under the join budget.
        release.notify_waiters();
        // Drain (cancels token + joins duty_orchestrator).
        executor.shutdown(TierBudget::default()).await
    };

    // Also race shutdown_rx so a panic would take the same path as production.
    tokio::select! {
        outcome = wait_entered => outcome,
        reason = shutdown_rx.recv() => {
            panic!("unexpected ShutdownReason during M10 harness: {reason:?}");
        }
    }
}

/// M10: publish in flight at shutdown signal time must complete (timeout-wrapped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_in_flight_publish_completes_on_shutdown_signal() {
    let body = async {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let parts = build_harness(pk, sk).await;
        let entered = Arc::clone(&parts.block_beacon.entered);
        let release = Arc::clone(&parts.block_beacon.release);
        let published = Arc::clone(&parts.block_beacon.published);

        let outcome =
            run_executor_lifecycle(parts.orchestrator, parts.handle, || {}, entered, release).await;

        assert!(
            published.load(Ordering::SeqCst) >= 1,
            "publish must complete after shutdown signal (M10); pre-fix select! dropped it"
        );
        assert!(
            outcome.joined.contains(&"duty_orchestrator"),
            "duty_orchestrator must be joined, not aborted: joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted
        );
    };

    tokio::time::timeout(Duration::from_secs(10), body)
        .await
        .expect("M10 harness timed out — pre-fix hang interleaving would wedge here");
}

/// ARCH-2h: handle.shutdown() → loop returns Ok(()) → join inside Orchestrator budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_orchestrator_handle_shutdown_is_joined_within_budget() {
    let body = async {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let parts = build_harness(pk, sk).await;
        // Do not hold publish — we only care about cooperative stop + join.
        parts.block_beacon.hold.store(false, Ordering::SeqCst);

        let token = CancellationToken::new();
        let (executor, _rx) = TaskExecutor::new(token);
        let mut orchestrator = parts.orchestrator;
        let handle = parts.handle;

        executor.spawn("duty_orchestrator", ShutdownTier::Orchestrator, async move {
            match orchestrator.run().await {
                Ok(()) => {}
                Err(e) => panic!("orchestrator error: {e}"),
            }
        });

        // Let the first slot progress past proposal.
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.shutdown();
        let outcome = executor.shutdown(TierBudget::default()).await;

        assert!(
            outcome.joined.contains(&"duty_orchestrator"),
            "assert on join membership, not elapsed sleep: joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted
        );
        assert!(
            !outcome.aborted.contains(&"duty_orchestrator"),
            "duty_orchestrator must not be aborted when handle.shutdown was called"
        );
    };

    tokio::time::timeout(Duration::from_secs(10), body)
        .await
        .expect("orchestrator join test timed out");
}

/// ARCH-2h: second cancel during drain still yields Ingress→Orchestrator→Background→Telemetry.
///
/// Drain order is a property of `TaskExecutor::shutdown`; registering one task per
/// tier and cancelling the token twice must not reorder tiers.
#[tokio::test]
async fn test_second_sigint_during_drain_does_not_bypass_tier_order() {
    let body = async {
        let token = CancellationToken::new();
        let (executor, _rx) = TaskExecutor::new(token.clone());
        let order = Arc::new(Mutex::new(Vec::new()));

        for (name, tier) in [
            ("ingress_task", ShutdownTier::Ingress),
            ("orch_task", ShutdownTier::Orchestrator),
            ("bg_task", ShutdownTier::Background),
            ("telem_task", ShutdownTier::Telemetry),
        ] {
            let order = Arc::clone(&order);
            let t = token.clone();
            executor.spawn(name, tier, async move {
                t.cancelled().await;
                order.lock().expect("order").push(name);
            });
        }

        // First signal: cancel token (what drain also does). Second cancel is a no-op.
        token.cancel();
        token.cancel();

        let outcome = executor.shutdown(TierBudget::default()).await;
        let recorded = order.lock().expect("order").clone();
        assert_eq!(
            recorded,
            vec!["ingress_task", "orch_task", "bg_task", "telem_task"],
            "drain order must stay Ingress→Orchestrator→Background→Telemetry"
        );
        assert_eq!(outcome.joined.len(), 4);
        assert!(outcome.aborted.is_empty());
    };

    tokio::time::timeout(Duration::from_secs(5), body).await.expect("tier-order test timed out");
}

/// Read one HTTP/1.1 request, including a Content-Length body.
async fn read_http_request(sock: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            if buf.len() > 65_536 {
                break;
            }
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let mut len = 0usize;
        for line in headers.lines() {
            let Some((name, value)) = line.split_once(':') else { continue };
            if name.eq_ignore_ascii_case("content-length") {
                len = value.trim().parse().unwrap_or(0);
            }
        }
        let need = header_end + 4 + len;
        while buf.len() < need {
            let n = sock.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        break;
    }
    Ok(())
}

/// One-shot HTTP server. `hold` waits after the request is read and before 200.
async fn serve_once(
    hold: Option<Arc<Notify>>,
    release: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        if read_http_request(&mut sock).await.is_err() {
            return;
        }
        entered.store(true, Ordering::SeqCst);
        if let Some(hold) = hold {
            loop {
                let notified = hold.notified();
                tokio::pin!(notified);
                if release.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
        }
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if tokio::io::AsyncWriteExt::write_all(&mut sock, response).await.is_ok() {
            finished.store(true, Ordering::SeqCst);
        }
    });
    format!("http://{addr}")
}

/// A detached publish to a slow beacon node finishes before shutdown returns.
///
/// The fast node returns first-OK. The slow node is still in the detached
/// drain. The waiter registered after the orchestrator tier joins that drain,
/// bounded by `block_publication`.
#[tokio::test]
async fn test_detached_broadcast_to_slow_bn_finishes_before_shutdown() {
    let body = async {
        let release = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let fast_entered = Arc::new(AtomicBool::new(false));
        let fast_finished = Arc::new(AtomicBool::new(false));
        let slow_entered = Arc::new(AtomicBool::new(false));
        let slow_finished = Arc::new(AtomicBool::new(false));
        let fast = serve_once(
            None,
            Arc::clone(&release),
            Arc::clone(&fast_entered),
            Arc::clone(&fast_finished),
        )
        .await;
        let slow = serve_once(
            Some(Arc::clone(&wake)),
            Arc::clone(&release),
            Arc::clone(&slow_entered),
            Arc::clone(&slow_finished),
        )
        .await;

        let timeouts = OperationTimeouts {
            preparation: Duration::from_secs(8),
            ..OperationTimeouts::default()
        };
        let manager = Arc::new(
            bn_manager::BnManager::new(bn_manager::BnManagerConfig::new(vec![fast, slow]))
                .expect("manager")
                .with_operation_timeouts(timeouts),
        );

        let block_publication = Duration::from_secs(3);
        let token = CancellationToken::new();
        let (executor, _rx) = TaskExecutor::new(token);
        let drains = Arc::clone(&manager);
        executor.set_after_orchestrator_waiter(async move {
            drains.wait_for_broadcast_drains(block_publication).await;
        });

        BlockProducer::prepare_beacon_proposer(manager.as_ref(), &[])
            .await
            .expect("fast beacon node accepts the broadcast");
        let wall = std::time::Instant::now() + Duration::from_secs(5);
        while !slow_entered.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < wall, "the slow beacon node never saw the publish");
            tokio::task::yield_now().await;
        }
        assert!(fast_finished.load(Ordering::SeqCst), "the fast beacon node returned 200");
        assert!(!slow_finished.load(Ordering::SeqCst), "the slow publish is still detached");

        let shutdown = tokio::spawn(async move {
            executor
                .shutdown(TierBudget::new([
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                ]))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!shutdown.is_finished(), "shutdown must wait for the detached publish");
        assert!(!slow_finished.load(Ordering::SeqCst));

        release.store(true, Ordering::SeqCst);
        wake.notify_waiters();
        let outcome = tokio::time::timeout(Duration::from_secs(3), shutdown)
            .await
            .expect("shutdown exceeded block_publication")
            .expect("shutdown task");
        assert!(
            slow_finished.load(Ordering::SeqCst),
            "the slow publish must finish before shutdown returns"
        );
        assert!(outcome.aborted.is_empty(), "no tier task was aborted: {:?}", outcome.aborted);
    };

    tokio::time::timeout(Duration::from_secs(10), body)
        .await
        .expect("detached broadcast shutdown test timed out");
}
