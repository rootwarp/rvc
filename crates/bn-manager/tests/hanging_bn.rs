//! Real-time hanging beacon nodes for per-attempt budget tests.
//!
//! RR-1.4 appends rows to [`BUDGETED_OPERATIONS`]. This file does not convert
//! call sites.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use beacon::{BeaconClient, BeaconClientConfig};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

use rvc_bn_manager::{BeaconError, BnManager, BnManagerConfig, OperationTimeouts};

/// How long each fixture BN waits before responding. Longer than [`BUDGET`].
const HANG: Duration = Duration::from_millis(400);

/// Operation budget installed on the fixture. Shorter than [`HANG`].
const BUDGET: Duration = Duration::from_millis(80);

type OpFut<'a> = Pin<Box<dyn Future<Output = Result<(), BeaconError>> + Send + 'a>>;

/// One budgeted operation. RR-1.4 pushes `(op_name, invocation)` rows.
struct BudgetedOperation {
    op_name: &'static str,
    invoke: for<'a> fn(&'a BnManager) -> OpFut<'a>,
}

/// Empty until RR-1.4 adds the twelve budgeted sites.
static BUDGETED_OPERATIONS: &[BudgetedOperation] = &[];

struct HangingFleet {
    servers: Vec<MockServer>,
    manager: BnManager,
    budget: Duration,
    hang: Duration,
}

impl HangingFleet {
    async fn start(n: usize, budget: Duration, hang: Duration) -> Self {
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
        let manager = BnManager::new(BnManagerConfig::new(endpoints))
            .unwrap()
            .with_operation_timeouts(timeouts);
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
    // Keep the row shape compiled. RR-1.4 fills the table; this test does not
    // invoke rows (an empty drive would not prove the delay).
    for op in BUDGETED_OPERATIONS {
        let _ = (op.op_name, op.invoke);
    }

    let fleet = HangingFleet::start(2, BUDGET, HANG).await;
    assert!(fleet.hang > fleet.budget);
    assert_eq!(fleet.servers.len(), 2);
    // The manager is part of the fixture RR-1.4 drives. Touch it so the field
    // stays live without running the empty operation table.
    let _ = fleet.manager.health_scores().await;

    let elapsed = fleet.probe_hang().await;
    assert!(
        elapsed > fleet.budget,
        "measured hang {elapsed:?} did not exceed the operation budget {:?}; RR-1.4 rows would pass for free",
        fleet.budget
    );
    assert!(
        elapsed + Duration::from_millis(30) >= fleet.hang,
        "wiremock responded in {elapsed:?}, configured hang is {:?}",
        fleet.hang
    );
}
