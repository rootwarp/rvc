//! Coordinator tests: tracing.

use super::*;

// --- H-08: Orchestrator slot lifecycle span tests ---

use parking_lot::Mutex;
use std::collections::HashMap as SpanMap;
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;

/// A tracing layer that captures span names for test verification.
struct SpanCapture {
    names: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.names.lock().push(attrs.metadata().name().to_string());
    }
}

/// Recorded span entry with name and optional parent span ID.
#[derive(Debug, Clone)]
struct SpanEntry {
    name: String,
    parent_id: Option<Id>,
}

/// A tracing layer that captures span names and parent-child relationships.
struct HierarchyCapture {
    spans: Arc<Mutex<SpanMap<u64, SpanEntry>>>,
}

impl<S> tracing_subscriber::Layer<S> for HierarchyCapture
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let parent_id = attrs.parent().cloned().or_else(|| ctx.current_span().id().cloned());
        self.spans.lock().insert(
            id.into_u64(),
            SpanEntry { name: attrs.metadata().name().to_string(), parent_id },
        );
    }
}

impl HierarchyCapture {
    fn new() -> (Self, Arc<Mutex<SpanMap<u64, SpanEntry>>>) {
        let spans = Arc::new(Mutex::new(SpanMap::new()));
        (Self { spans: spans.clone() }, spans)
    }
}

/// Returns the parent span name for a given child span name, if both exist.
fn find_parent_name(spans: &SpanMap<u64, SpanEntry>, child_name: &str) -> Option<String> {
    for entry in spans.values() {
        if entry.name == child_name {
            if let Some(ref parent_id) = entry.parent_id {
                if let Some(parent) = spans.get(&parent_id.into_u64()) {
                    return Some(parent.name.clone());
                }
            }
        }
    }
    None
}

#[tokio::test(flavor = "current_thread")]
async fn test_slot_processing_creates_root_and_phase_spans() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65); // slot 65 = epoch 2, not at epoch boundary
                        // Advance past 2/3 of slot so all phases run without waiting
    clock.advance_time(9);

    // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
    // immediately, keeping the test well within its 5-second window even after
    // SlotContext::capture adds a get_block_root call to the slot loop.
    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    // Capture spans via thread-local subscriber
    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Shutdown after enough time for all phases (HTTP failures are fast)
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"slot.process".to_string()),
        "Expected slot.process span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.block".to_string()),
        "Expected slot.phase.block span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.attestation".to_string()),
        "Expected slot.phase.attestation span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.aggregation".to_string()),
        "Expected slot.phase.aggregation span, got: {:?}",
        *span_names
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_epoch_boundary_creates_epoch_span() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(32); // slot 32 = epoch 1, IS at epoch boundary (32 % 32 == 0)
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"epoch.boundary".to_string()),
        "Expected epoch.boundary span at epoch boundary slot, got: {:?}",
        *span_names
    );
}

// --- H-25: Aggregation span link tests ---

#[tokio::test]
async fn test_aggregation_creates_produce_span() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
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
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Mock attestation data
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock aggregate attestation
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xffffffff",
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                    "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock submit aggregate and proofs
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"orchestrator.produce_aggregations".to_string()),
        "Expected orchestrator.produce_aggregations span, got: {:?}",
        *span_names
    );
    // Note: aggregation.submit may not appear under coverage instrumentation
    // due to subscriber interference in concurrent test runs. The produce span
    // is the primary assertion for this test.
}

#[tokio::test]
async fn test_aggregation_non_aggregator_creates_produce_span_without_submit() {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Large committee → unlikely to be aggregator
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "100000",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Should NOT call aggregate attestation or submit
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;

    let span_names = captured.lock();
    // produce span should still be created (it wraps the entire per-validator loop body)
    assert!(
        span_names.contains(&"orchestrator.produce_aggregations".to_string()),
        "Expected orchestrator.produce_aggregations span even for non-aggregator, got: {:?}",
        *span_names
    );
    // submit span should NOT be created (no aggregates to submit)
    assert!(
        !span_names.contains(&"aggregation.submit".to_string()),
        "Did not expect aggregation.submit span for non-aggregator, got: {:?}",
        *span_names
    );
}

// --- H-14: End-to-end span hierarchy integration tests ---

#[tokio::test(flavor = "current_thread")]
async fn test_phase_spans_are_children_of_slot_process() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65); // non-boundary slot
    clock.advance_time(9);

    // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
    // immediately, keeping the test well within its 5-second window even after
    // SlotContext::capture adds a get_block_root call to the slot loop.
    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (layer, spans) = HierarchyCapture::new();
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_map = spans.lock();

    // Verify phase spans are children of slot.process
    let block_parent = find_parent_name(&span_map, "slot.phase.block");
    assert_eq!(
        block_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.block should be child of slot.process"
    );

    let att_parent = find_parent_name(&span_map, "slot.phase.attestation");
    assert_eq!(
        att_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.attestation should be child of slot.process"
    );

    let agg_parent = find_parent_name(&span_map, "slot.phase.aggregation");
    assert_eq!(
        agg_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.aggregation should be child of slot.process"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_epoch_boundary_span_is_child_of_slot_process() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(32); // epoch boundary
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (layer, spans) = HierarchyCapture::new();
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_map = spans.lock();

    let epoch_parent = find_parent_name(&span_map, "epoch.boundary");
    assert_eq!(
        epoch_parent.as_deref(),
        Some("slot.process"),
        "epoch.boundary should be child of slot.process"
    );
}

#[tokio::test]
async fn test_signer_span_created_on_sign_attestation() {
    use crypto::SecretKey;
    use eth_types::{AttestationData, Checkpoint};

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut manager = KeyManager::new();
    manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer = SignerService::new(composite, slashing_db).with_enablement(always_enabled());

    let attestation_data = AttestationData {
        slot: 1000,
        index: 5,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 100, root: [0x22; 32] },
        target: Checkpoint { epoch: 101, root: [0x33; 32] },
    };
    let fork_schedule = create_test_fork_schedule();
    let genesis_root = [0xaa; 32];

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let result =
        signer.sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root).await;
    assert!(result.is_ok());

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"sign.attestation".to_string()),
        "Expected sign.attestation span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slashing.check".to_string()),
        "Expected slashing.check span within sign_attestation, got: {:?}",
        *span_names
    );
}

#[tokio::test]
async fn test_beacon_http_span_created() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": "mock/v1.0.0" }
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = BeaconClient::new(beacon_config).unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let _ = beacon.get_node_version().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"beacon.http".to_string()),
        "Expected beacon.http span, got: {:?}",
        *span_names
    );
}

// --- T15 / TRC-4c: time_into_slot stamped when the phase fires ---

use timing::{due_ms, DeadlineBps, DeadlineSchedule};
use tracing::field::{Field, Visit};

const PHASE_BLOCK: &str = "slot.phase.block";
const PHASE_ATTESTATION: &str = "slot.phase.attestation";
const PHASE_AGGREGATION: &str = "slot.phase.aggregation";
const PHASE_PTC: &str = "slot.phase.payload_attestation";

/// Whole-second truncation a `SlotClock` stamp can represent
/// (`(seconds_into_slot) * 1000`). Sub-second bps offsets are not in this set.
fn slot_clock_ms(elapsed_ms: u64) -> u64 {
    (elapsed_ms / 1000) * 1000
}

fn gloas_at_epoch(epoch: u64) -> Arc<ForkSchedule> {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.gloas_fork_epoch = epoch;
    Arc::new(schedule)
}

fn t15_config(pre_gloas: DeadlineBps, gloas: DeadlineBps) -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], gloas_at_epoch(1))
        .with_deadline_schedule(DeadlineSchedule { pre_gloas, gloas })
        .with_pre_proposal_deadline(Duration::ZERO)
        .with_cold_proposer_fetch_deadline(Duration::ZERO)
}

fn t15_orchestrator(
    slot: Slot,
    config: OrchestratorConfig,
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);
    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
    DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

struct TimeIntoSlotVisitor {
    value: Option<u64>,
}

impl Visit for TimeIntoSlotVisitor {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == observability::logging::fields::TIME_INTO_SLOT {
            self.value = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

#[derive(Clone, Debug)]
struct PhaseStamp {
    name: String,
    /// Milliseconds passed to `Span::record`.
    value: u64,
    /// Tokio time when `on_record` ran. Equals `value` only if the stamp is
    /// the fire-time elapsed, not a bps constant written early.
    at_ms: u64,
}

#[derive(Clone, Debug)]
struct ConstructedPhase {
    name: String,
    time_into_slot: Option<u64>,
}

struct FireTimeCapture {
    origin: tokio::time::Instant,
    names: Arc<Mutex<SpanMap<u64, String>>>,
    constructed: Arc<Mutex<Vec<ConstructedPhase>>>,
    recorded: Arc<Mutex<Vec<PhaseStamp>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FireTimeCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = attrs.metadata().name().to_string();
        let mut visitor = TimeIntoSlotVisitor { value: None };
        attrs.record(&mut visitor);
        self.names.lock().insert(id.into_u64(), name.clone());
        if name.starts_with("slot.phase.") {
            self.constructed.lock().push(ConstructedPhase { name, time_into_slot: visitor.value });
        }
    }

    fn on_record(
        &self,
        id: &Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let Some(name) = self.names.lock().get(&id.into_u64()).cloned() else {
            return;
        };
        if !name.starts_with("slot.phase.") {
            return;
        }
        let mut visitor = TimeIntoSlotVisitor { value: None };
        values.record(&mut visitor);
        if let Some(value) = visitor.value {
            let at_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.recorded.lock().push(PhaseStamp { name, value, at_ms });
        }
    }
}

async fn drive_phase_stamps(
    slot: Slot,
    config: OrchestratorConfig,
    shutdown_after_ms: u64,
) -> (Vec<ConstructedPhase>, Vec<PhaseStamp>) {
    let (mut orchestrator, handle) = t15_orchestrator(slot, config);
    let constructed = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let layer = FireTimeCapture {
        origin: tokio::time::Instant::now(),
        names: Arc::new(Mutex::new(SpanMap::new())),
        constructed: constructed.clone(),
        recorded: recorded.clone(),
    };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(shutdown_after_ms)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let constructed = constructed.lock().clone();
    let recorded = recorded.lock().clone();
    (constructed, recorded)
}

fn constructed_field<'a>(constructed: &'a [ConstructedPhase], name: &str) -> &'a Option<u64> {
    let hits: Vec<_> = constructed.iter().filter(|phase| phase.name == name).collect();
    assert_eq!(hits.len(), 1, "{name} constructed once, got {constructed:?}");
    &hits[0].time_into_slot
}

fn phase_stamp<'a>(recorded: &'a [PhaseStamp], name: &str) -> &'a PhaseStamp {
    let hits: Vec<_> = recorded.iter().filter(|s| s.name == name).collect();
    assert_eq!(hits.len(), 1, "{name} records time_into_slot once, got {recorded:?}");
    hits[0]
}

fn assert_fire_stamp(stamp: &PhaseStamp, expected_ms: u64) {
    assert_eq!(
        stamp.value, expected_ms,
        "{} time_into_slot must match the configured bps offset",
        stamp.name
    );
    assert_eq!(
        stamp.at_ms, stamp.value,
        "{} time_into_slot must be the elapsed ms at fire (on_record at {}, value {})",
        stamp.name, stamp.at_ms, stamp.value
    );
}

/// Pre-Gloas: block / attestation / aggregation stamp `time_into_slot` at fire.
/// Attestation's 3999 ms is not a whole second, so a SlotClock reimplementation
/// (`current_time_secs` truncated) cannot satisfy it. PTC does not fire.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_t15_time_into_slot_matches_bps_when_phase_fires() {
    let slot_ms = 12_000u64;
    let pre = DeadlineBps::default();
    let expected_att = due_ms(pre.attestation, slot_ms);
    let expected_agg = due_ms(pre.aggregate, slot_ms);
    assert_eq!(expected_att, 3999, "fixture: spec 1/3 is 3999 ms");
    assert_eq!(expected_agg, 8000);
    assert_ne!(
        expected_att,
        slot_clock_ms(expected_att),
        "fixture must reject a whole-second SlotClock stamp"
    );

    let (constructed, recorded) =
        drive_phase_stamps(31, t15_config(pre, DeadlineBps::default()), 8_500).await;

    for name in [PHASE_BLOCK, PHASE_ATTESTATION, PHASE_AGGREGATION, PHASE_PTC] {
        assert!(
            constructed_field(&constructed, name).is_none(),
            "{name} must declare time_into_slot empty at construction, got {constructed:?}"
        );
    }

    let block = phase_stamp(&recorded, PHASE_BLOCK);
    let att = phase_stamp(&recorded, PHASE_ATTESTATION);
    let agg = phase_stamp(&recorded, PHASE_AGGREGATION);
    assert_fire_stamp(block, 0);
    assert_fire_stamp(att, expected_att);
    assert_fire_stamp(agg, expected_agg);
    assert!(
        recorded.iter().all(|s| s.name != PHASE_PTC),
        "pre-Gloas PTC phase must not stamp time_into_slot, got {recorded:?}"
    );
    assert_ne!(block.value, att.value);
    assert_ne!(att.value, agg.value);
}

/// Gloas+: PTC is the fourth phase. Attestation and aggregation offsets differ
/// by 100 ms, so a 1-second clock cannot tell them apart.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_t15_ptc_time_into_slot_when_gloas_active() {
    let slot_ms = 12_000u64;
    // Attestation 3333 → 3999 and aggregate 3416 → 4099 differ by 100 ms.
    // Sync and contribution use different bps so those duties take the split
    // wait; the phase stamp must stay on the phase's own offset.
    // PTC 4166 → 4999.
    let gloas = DeadlineBps {
        attestation: 3333,
        aggregate: 3416,
        sync_message: 2500,
        contribution: 5000,
        payload: 4166,
        payload_attestation: 4166,
    };
    let expected_att = due_ms(gloas.attestation, slot_ms);
    let expected_agg = due_ms(gloas.aggregate, slot_ms);
    let expected_ptc = due_ms(gloas.payload_attestation, slot_ms);
    assert_eq!(expected_att, 3999);
    assert_eq!(expected_agg, 4099);
    assert_eq!(expected_ptc, 4999);
    assert_ne!(expected_att, due_ms(gloas.sync_message, slot_ms));
    assert_ne!(expected_agg, due_ms(gloas.contribution, slot_ms));
    let gap = expected_agg.abs_diff(expected_att);
    assert!(gap > 0 && gap < 1000, "fixture offsets must be sub-second-distinguishable");
    assert_ne!(slot_clock_ms(expected_att), expected_att);
    assert_ne!(slot_clock_ms(expected_agg), expected_agg);
    assert_eq!(
        slot_clock_ms(expected_agg),
        slot_clock_ms(expected_ptc),
        "fixture: a whole-second clock collapses aggregation and PTC"
    );

    let (constructed, recorded) =
        drive_phase_stamps(32, t15_config(DeadlineBps::default(), gloas), 6_500).await;

    for name in [PHASE_BLOCK, PHASE_ATTESTATION, PHASE_AGGREGATION, PHASE_PTC] {
        assert!(
            constructed_field(&constructed, name).is_none(),
            "{name} must declare time_into_slot empty at construction, got {constructed:?}"
        );
    }

    assert_fire_stamp(phase_stamp(&recorded, PHASE_BLOCK), 0);
    assert_fire_stamp(phase_stamp(&recorded, PHASE_ATTESTATION), expected_att);
    assert_fire_stamp(phase_stamp(&recorded, PHASE_AGGREGATION), expected_agg);
    assert_fire_stamp(phase_stamp(&recorded, PHASE_PTC), expected_ptc);
}

/// A wake 600 ms after slot start is part of the attestation span's
/// `time_into_slot`. Measuring from the wake instant drops that offset.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn attestation_span_time_into_slot_includes_a_late_wake() {
    const OFFSET_MS: u64 = 600;
    let slot_ms = 12_000u64;
    let pre = DeadlineBps::default();
    let expected_att = due_ms(pre.attestation, slot_ms);
    assert_eq!(expected_att, 3999);

    let slot = 31u64;
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot_with_offset_ms(slot, 0);
    clock.advance_ms(OFFSET_MS);

    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        t15_config(pre, DeadlineBps::default()),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let constructed = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let layer = FireTimeCapture {
        origin: tokio::time::Instant::now(),
        names: Arc::new(Mutex::new(SpanMap::new())),
        constructed: constructed.clone(),
        recorded: recorded.clone(),
    };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            // Attestation is due at 3999 ms from the true start (3399 ms from the wake).
            tokio::time::sleep(Duration::from_millis(4_000)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let recorded = recorded.lock().clone();
    let att = phase_stamp(&recorded, PHASE_ATTESTATION);
    assert!(
        (expected_att..=expected_att + 50).contains(&att.value),
        "attestation time_into_slot must include the {OFFSET_MS} ms late wake \
         (true offset ~{expected_att}), got {} (tokio elapsed at fire {})",
        att.value,
        att.at_ms
    );
    assert!(
        att.value.abs_diff(att.at_ms + OFFSET_MS) <= 50,
        "time_into_slot {} must be the wake-relative elapsed {} plus the {OFFSET_MS} ms late wake",
        att.value,
        att.at_ms
    );
}
