//! Real-time hanging beacon nodes for per-attempt budget tests.
//!
//! Each row in [`BUDGETED_OPERATIONS`] is one converted query-first site.
//! Broadcast topics are off so topic-gated submissions take the query_first arm.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use beacon::{BeaconClient, BeaconClientConfig};
use eth_types::{ForkName, ForkSchedule};
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use rvc_bn_manager::{
    AttestationApi, BeaconError, BlockProducer, BnManager, BnManagerConfig, BroadcastTopics,
    DutiesProvider, OperationTimeouts, PayloadAttestationApi, SignedBeaconBlock, SyncCommitteeApi,
    VersionedAttestation, ATTEMPT_TIMEOUT_FLOOR,
};

/// How long each fixture BN waits before responding. Longer than any row budget.
const HANG: Duration = Duration::from_millis(400);

/// Operation budget installed on the non-vacuity fixture. Shorter than [`HANG`].
const BUDGET: Duration = Duration::from_millis(80);

/// Row budget. Tens of ms and well below [`ATTEMPT_TIMEOUT_FLOOR`].
const ROW_BUDGET: Duration = Duration::from_millis(40);

/// Scheduling slack. Several times smaller than `FLOOR - ROW_BUDGET`.
const ROW_EPSILON: Duration = Duration::from_millis(50);

/// Elapsed ceiling for one budgeted row.
///
/// llvm-cov stretched a 40 ms budget to 111 ms, past the 90 ms ceiling.
/// Coverage keeps a wider ceiling that is still below the attempt floor and
/// the hang, so a missing inner deadline still fails.
fn row_elapsed_limit() -> Duration {
    let slack = if std::env::var_os("CARGO_LLVM_COV").is_some()
        || std::env::var_os("LLVM_PROFILE_FILE").is_some()
    {
        Duration::from_millis(200)
    } else {
        ROW_EPSILON
    };
    ROW_BUDGET + slack
}

type OpFut<'a> = Pin<Box<dyn Future<Output = Result<(), BeaconError>> + Send + 'a>>;

/// One budgeted operation. One row per converted site.
struct BudgetedOperation {
    op_name: &'static str,
    invoke: for<'a> fn(&'a BnManager) -> OpFut<'a>,
}

fn op_get_attester_duties(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        let indices = vec!["1".to_string()];
        manager.get_attester_duties(1, &indices).await.map(|_| ())
    })
}

fn op_get_proposer_duties(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        let schedule = ForkSchedule::unscheduled_gloas();
        manager.get_proposer_duties(1, &schedule).await.map(|_| ())
    })
}

fn op_post_sync_committee_duties(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        let indices = vec!["1".to_string()];
        manager.post_sync_committee_duties(1, &indices).await.map(|_| ())
    })
}

fn op_post_ptc_duties(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        let indices = vec!["1".to_string()];
        manager.post_ptc_duties(1, &indices).await.map(|_| ())
    })
}

fn op_publish_block_ssz(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async { manager.publish_block_ssz(&[], "deneb", false, None).await })
}

fn op_get_attestation_data(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async { manager.get_attestation_data(1, 0).await.map(|_| ()) })
}

fn op_submit_attestation(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        let attestations = VersionedAttestation::Electra(vec![]);
        manager.submit_attestation(&attestations).await.map(|_| ())
    })
}

fn op_get_aggregate_attestation(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async {
        manager.get_aggregate_attestation(1, "0x11", Some(0), ForkName::Electra).await.map(|_| ())
    })
}

fn op_get_payload_attestation_data(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async { manager.get_payload_attestation_data(1).await.map(|_| ()) })
}

fn op_submit_payload_attestations(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async { manager.submit_payload_attestations(&[]).await })
}

fn op_get_sync_committee_contribution(manager: &BnManager) -> OpFut<'_> {
    Box::pin(async { manager.get_sync_committee_contribution(1, 0, "0x11").await.map(|_| ()) })
}

fn op_publish_block(manager: &BnManager) -> OpFut<'_> {
    // `submit()`'s query_first arm. The other submit() callers share this arm.
    Box::pin(async {
        let signed = sample_signed_block();
        manager.publish_block(&signed, "deneb", None).await
    })
}

fn sample_signed_block() -> SignedBeaconBlock {
    SignedBeaconBlock {
        message: eth_types::BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        },
        signature: vec![0xaa; 96],
    }
}

/// Twelve converted operations, named. `publish_block` is the generic `submit`
/// helper's query_first arm (broadcast off).
static BUDGETED_OPERATIONS: &[BudgetedOperation] = &[
    BudgetedOperation { op_name: "get_attester_duties", invoke: op_get_attester_duties },
    BudgetedOperation { op_name: "get_proposer_duties", invoke: op_get_proposer_duties },
    BudgetedOperation {
        op_name: "post_sync_committee_duties",
        invoke: op_post_sync_committee_duties,
    },
    BudgetedOperation { op_name: "post_ptc_duties", invoke: op_post_ptc_duties },
    BudgetedOperation { op_name: "publish_block_ssz", invoke: op_publish_block_ssz },
    BudgetedOperation { op_name: "get_attestation_data", invoke: op_get_attestation_data },
    BudgetedOperation { op_name: "submit_attestation", invoke: op_submit_attestation },
    BudgetedOperation {
        op_name: "get_aggregate_attestation",
        invoke: op_get_aggregate_attestation,
    },
    BudgetedOperation {
        op_name: "get_payload_attestation_data",
        invoke: op_get_payload_attestation_data,
    },
    BudgetedOperation {
        op_name: "submit_payload_attestations",
        invoke: op_submit_payload_attestations,
    },
    BudgetedOperation {
        op_name: "get_sync_committee_contribution",
        invoke: op_get_sync_committee_contribution,
    },
    BudgetedOperation { op_name: "publish_block", invoke: op_publish_block },
];

struct HangingFleet {
    servers: Vec<MockServer>,
    manager: BnManager,
    budget: Duration,
    hang: Duration,
}

impl HangingFleet {
    async fn start(n: usize, budget: Duration, hang: Duration, broadcast: bool) -> Self {
        assert!(n > 0, "fleet needs at least one BN");
        assert!(hang > budget, "hang must outlast the operation budget");
        let mut servers = Vec::with_capacity(n);
        for _ in 0..n {
            let server = MockServer::start().await;
            Mock::given(any())
                .respond_with(ResponseTemplate::new(200).set_body_string("{}").set_delay(hang))
                .mount(&server)
                .await;
            servers.push(server);
        }
        let endpoints = servers.iter().map(|server| server.uri()).collect();
        let timeouts = OperationTimeouts {
            block_production: budget,
            block_publication: budget,
            attestation_fetch: budget,
            attestation_submit: budget,
            aggregate_fetch: budget,
            aggregate_submit: budget,
            sync_message: budget,
            sync_contribution: budget,
            duty_fetch: budget,
            preparation: budget,
        };
        let mut config = BnManagerConfig::new(endpoints);
        config.broadcast_topics = if broadcast {
            BroadcastTopics::default()
        } else {
            BroadcastTopics {
                attestations: false,
                blocks: false,
                sync_committee: false,
                subscriptions: false,
            }
        };
        let manager = BnManager::new(config).unwrap().with_operation_timeouts(timeouts);
        Self { servers, manager, budget, hang }
    }

    /// Wall time until the delayed BN actually responds.
    async fn probe_hang(&self) -> Duration {
        let client = BeaconClient::new(
            BeaconClientConfig::new(self.servers[0].uri())
                .with_timeout(self.hang + Duration::from_secs(2)),
        )
        .unwrap();
        let started = Instant::now();
        let _ = client.get_genesis().await;
        started.elapsed()
    }
}

#[tokio::test]
async fn harness_actually_hangs_past_the_budget() {
    for op in BUDGETED_OPERATIONS {
        let _ = (op.op_name, op.invoke);
    }

    let fleet = HangingFleet::start(2, BUDGET, HANG, false).await;
    assert!(fleet.hang > fleet.budget);
    assert_eq!(fleet.servers.len(), 2);
    // The manager is part of the fixture the rows drive. Touch it so the field
    // stays live without running the operation table.
    let _ = fleet.manager.health_scores().await;

    let elapsed = fleet.probe_hang().await;
    assert!(
        elapsed > fleet.budget,
        "measured hang {elapsed:?} did not exceed the operation budget {:?}; rows would pass for free",
        fleet.budget
    );
    assert!(
        elapsed + Duration::from_millis(30) >= fleet.hang,
        "wiremock responded in {elapsed:?}, configured hang is {:?}",
        fleet.hang
    );
}

#[tokio::test]
async fn every_converted_site_still_returns_operation_timeout() {
    assert_eq!(BUDGETED_OPERATIONS.len(), 12, "one row per converted operation");
    let names: Vec<&str> = BUDGETED_OPERATIONS.iter().map(|op| op.op_name).collect();
    assert_eq!(
        names,
        [
            "get_attester_duties",
            "get_proposer_duties",
            "post_sync_committee_duties",
            "post_ptc_duties",
            "publish_block_ssz",
            "get_attestation_data",
            "submit_attestation",
            "get_aggregate_attestation",
            "get_payload_attestation_data",
            "submit_payload_attestations",
            "get_sync_committee_contribution",
            "publish_block",
        ]
    );
    assert!(
        ATTEMPT_TIMEOUT_FLOOR.saturating_sub(ROW_BUDGET) > ROW_EPSILON * 3,
        "FLOOR ({ATTEMPT_TIMEOUT_FLOOR:?}) - budget ({ROW_BUDGET:?}) must be several times ε ({ROW_EPSILON:?})"
    );
    assert!(ROW_BUDGET < ATTEMPT_TIMEOUT_FLOOR);
    assert!(HANG > ATTEMPT_TIMEOUT_FLOOR, "a missing deadline must outlast the floor");

    let fleet = HangingFleet::start(1, ROW_BUDGET, HANG, false).await;
    for op in BUDGETED_OPERATIONS {
        let started = Instant::now();
        let err = (op.invoke)(&fleet.manager).await.expect_err(op.op_name);
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == op.op_name),
            "{} returned {err:?}",
            op.op_name
        );
        let limit = row_elapsed_limit();
        assert!(
            limit < HANG && limit < ATTEMPT_TIMEOUT_FLOOR,
            "the elapsed limit {limit:?} must stay under the hang ({HANG:?}) and the floor ({ATTEMPT_TIMEOUT_FLOOR:?})"
        );
        assert!(
            elapsed <= limit,
            "{} elapsed {elapsed:?} exceeded {limit:?} (floor {:?}); a site with no inner deadline would wait for the hang",
            op.op_name,
            ATTEMPT_TIMEOUT_FLOOR
        );
    }
}

/// B-001: one stalled BN must not turn another BN's 200 into `OperationTimeout`.
///
/// BN-A answers `POST /eth/v2/beacon/pool/attestations` immediately. BN-B delays
/// that publish past the attestation budget. The call returns `Ok` before the
/// budget, and the drain records BN-A's success and BN-B's timeout.
#[tokio::test]
async fn submit_attestation_returns_ok_before_budget_when_peer_hangs() {
    /// Fast enough to stay under a loaded CI run, long enough that `join_all`
    /// plus one outer timeout cannot return `Ok`.
    const BUDGET_MS: u64 = 200;
    let budget = Duration::from_millis(BUDGET_MS);
    let hang = Duration::from_millis(800);
    assert!(hang > budget);

    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&bn_a)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]").set_delay(hang))
        .mount(&bn_b)
        .await;

    let mut config = BnManagerConfig::new(vec![bn_a.uri(), bn_b.uri()]);
    config.broadcast_topics.attestations = true;
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        attestation_submit: budget,
        ..OperationTimeouts::default()
    });

    let started = Instant::now();
    let result = manager.submit_attestation(&VersionedAttestation::Electra(vec![])).await;
    let elapsed = started.elapsed();
    assert!(result.is_ok(), "BN-A's 200 must win while BN-B is still hanging, got {result:?}");
    assert!(
        elapsed < budget,
        "submit_attestation returned in {elapsed:?}, which is not before the {budget:?} budget"
    );

    let deadline = Instant::now() + hang + Duration::from_millis(500);
    loop {
        let scores = manager.health_scores().await;
        let bn_a_success = scores[0].latency_ms > 0.0 && scores[0].error_rate == 0.0;
        let bn_b_error = scores[1].error_rate == 1.0;
        if bn_a_success && bn_b_error {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "drain did not record BN-A success and BN-B error: {scores:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let trackers = manager.health_trackers().read().await;
    assert!(
        trackers[0].latency_ema_ms().is_some() && trackers[0].error_rate() == 0.0,
        "BN-A must hold a success"
    );
    assert!(trackers[1].error_rate() > 0.0, "BN-B's timeout must count as an error");
}

/// Broadcast topics on: every budgeted operation still returns by the backstop
/// (budget + 250 ms), not when the hanging BN finally answers.
#[tokio::test]
async fn every_operation_with_broadcast_on_returns_within_backstop() {
    let budget = Duration::from_millis(200);
    let hang = Duration::from_millis(800);
    let backstop = Duration::from_millis(250);
    assert!(hang > budget + backstop, "a missing per-BN bound must be able to fail this test");
    assert_eq!(BUDGETED_OPERATIONS.len(), 12);

    let fleet = HangingFleet::start(2, budget, hang, true).await;
    for op in BUDGETED_OPERATIONS {
        let started = Instant::now();
        let result = (op.invoke)(&fleet.manager).await;
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{} must fail while every BN hangs, got {result:?}", op.op_name);
        assert!(
            elapsed <= budget + backstop,
            "{} elapsed {elapsed:?} exceeded budget + 250 ms ({:?})",
            op.op_name,
            budget + backstop
        );
    }
}
