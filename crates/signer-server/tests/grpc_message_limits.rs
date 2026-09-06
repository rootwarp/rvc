//! Regression tests for M-10: Tonic server concurrency/size/timeout limits.
//!
//! Formerly `tonic_limits_m10.rs` (audit issue M-10).
//!
//! These tests verify that `hardened_server_builder()` enforces:
//! - `concurrency_limit_per_connection(32)` — Tower-level handler concurrency cap
//! - `max_concurrent_streams(Some(64))` — H2-level stream cap (sent to client)
//! - `timeout(Duration::from_secs(10))` — per-request timeout via Tower
//!
//! And that per-service `max_decoding_message_size(1 MiB)` blocks oversized requests.
//!
//! RF2-15: ported from v1 raw-root `Sign` onto v2 `SignBeaconBlock` so this suite
//! does not depend on the retiring v1 SignerService surface.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;
use tonic::{Code, Request, Response, Status};

// V2 service types from rvc-grpc-signer (external dep name `grpc-signer` → `grpc_signer`).
// Using the client crate's v2 types keeps this test free of rvc-signer-bin's v1 surface
// so RF2-17 can delete that surface without revisiting these assertions.
use grpc_signer::proto::signer_v2::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    SignAggregateAndProofRequest, SignAttestationDataRequest, SignBeaconBlockRequest,
    SignBlindedBeaconBlockRequest, SignBlockHeaderRequest, SignBuilderRegistrationRequest,
    SignContributionAndProofRequest, SignRandaoRevealRequest, SignResponse, SignRootRequest,
    SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
    SignVoluntaryExitRequest,
};
use grpc_signer::{SignerServiceClientV2, SignerServiceServerV2, SignerServiceV2};

use signer_server::grpc_tls::server_builder::hardened_server_builder;

// ── TestService ────────────────────────────────────────────────────────────────

/// Minimal gRPC v2 service for testing server-level limits.
///
/// The `sign_beacon_block` handler:
/// - increments `concurrent`, updates `peak_concurrent`
/// - notifies `handler_started` (so the timeout test can synchronize)
/// - sleeps for `handler_sleep` before returning
/// - decrements `concurrent`
///
/// Other RPCs are stubs (unused by the limit assertions).
struct TestService {
    handler_sleep: Duration,
    concurrent: Arc<AtomicI32>,
    peak_concurrent: Arc<AtomicI32>,
    handler_started: Arc<tokio::sync::Notify>,
}

impl TestService {
    fn new(sleep: Duration) -> Self {
        Self {
            handler_sleep: sleep,
            concurrent: Arc::new(AtomicI32::new(0)),
            peak_concurrent: Arc::new(AtomicI32::new(0)),
            handler_started: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn handler_started_notifier(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.handler_started)
    }

    async fn run_instrumented_handler(&self) -> Result<Response<SignResponse>, Status> {
        let prev = self.concurrent.fetch_add(1, Ordering::SeqCst);
        let cur = prev + 1;

        // Update peak concurrency (compare-and-swap loop).
        let mut peak = self.peak_concurrent.load(Ordering::SeqCst);
        while cur > peak {
            match self.peak_concurrent.compare_exchange(
                peak,
                cur,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(new_peak) => peak = new_peak,
            }
        }

        self.handler_started.notify_one();

        if !self.handler_sleep.is_zero() {
            tokio::time::sleep(self.handler_sleep).await;
        }

        self.concurrent.fetch_sub(1, Ordering::SeqCst);
        Ok(Response::new(SignResponse { signature: vec![0u8; 96] }))
    }
}

#[tonic::async_trait]
impl SignerServiceV2 for TestService {
    async fn sign_beacon_block(
        &self,
        _request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        self.run_instrumented_handler().await
    }

    async fn sign_blinded_beacon_block(
        &self,
        _request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_attestation_data(
        &self,
        _request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_sync_committee_message(
        &self,
        _request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        _request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_contribution_and_proof(
        &self,
        _request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_builder_registration(
        &self,
        _request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_randao_reveal(
        &self,
        _request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_voluntary_exit(
        &self,
        _request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_block_header(
        &self,
        _request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn sign_root(
        &self,
        _request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("test mock"))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        Ok(Response::new(ListPublicKeysResponse { pubkeys: vec![] }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(GetStatusResponse {
            ready: true,
            backend: "test".to_string(),
            key_count: 0,
        }))
    }
}

// ── Server helper ──────────────────────────────────────────────────────────────

/// Spawn a hardened test server.  Returns the bound address and a JoinHandle.
///
/// Uses `hardened_server_builder()` + `max_decoding_message_size(1 MiB)` on the
/// service — exactly what `main.rs` uses in production.
async fn spawn_test_server(svc: TestService) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        hardened_server_builder()
            .add_service(
                SignerServiceServerV2::new(svc).max_decoding_message_size(1 << 20), // 1 MiB
            )
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Let the server start accepting connections before returning.
    tokio::time::sleep(Duration::from_millis(20)).await;

    (addr, handle)
}

// ── Client helper ──────────────────────────────────────────────────────────────

fn make_channel(addr: SocketAddr) -> Channel {
    Channel::from_shared(format!("http://{addr}")).unwrap().connect_lazy()
}

fn small_sign_beacon_block_request() -> SignBeaconBlockRequest {
    SignBeaconBlockRequest {
        pubkey: vec![0u8; 48],
        fork_info: None,
        block_ssz: vec![0u8; 84],
        fork_id: 4, // Deneb
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// Sending a message larger than `max_decoding_message_size` (1 MiB) must be
/// rejected by the server.  Tonic 0.12 returns `OutOfRange` (gRPC status 11)
/// for codec-level size violations (see `tonic::codec::decode`).
///
/// Oversized payload is carried in `SignBeaconBlockRequest.block_ssz` (raw
/// `bytes`) so the rejection still happens at the decode layer, matching the
/// former v1 `signing_root` oversized case.
#[tokio::test]
async fn test_oversized_message_refused() {
    let svc = TestService::new(Duration::ZERO);
    let (addr, _handle) = spawn_test_server(svc).await;

    // Client must be able to SEND a 2 MiB message (raise client encoding cap).
    let mut client =
        SignerServiceClientV2::new(make_channel(addr)).max_encoding_message_size(8 * 1024 * 1024); // 8 MiB — well above 2 MiB

    // SignBeaconBlockRequest with a 2 MiB block_ssz (exceeds server's 1 MiB decode limit).
    let req = SignBeaconBlockRequest {
        pubkey: vec![0u8; 48],
        fork_info: None,
        block_ssz: vec![0xAB; 2 * 1024 * 1024],
        fork_id: 4,
    };

    let result = client.sign_beacon_block(req).await;
    let err = result.expect_err("server must reject 2 MiB message");

    // Tonic 0.12 maps decode-size violations to OutOfRange (code 11); the
    // important invariant is that the server REJECTED the oversized message
    // before calling the handler — not the specific error code.
    assert!(
        err.code() == Code::OutOfRange || err.code() == Code::ResourceExhausted,
        "expected OutOfRange or ResourceExhausted for oversized message (got {:?}): {err}",
        err.code()
    );
    assert!(
        err.message().contains("too large") || err.message().contains("exceeded"),
        "error message should mention size limit: {err}"
    );
}

/// A request whose handler sleeps 30 s must be cut off by the 10 s server
/// timeout and return `DeadlineExceeded` (or `Cancelled`).
///
/// Uses `tokio::time::pause()` + `advance()` to avoid a real 10-second wait.
#[tokio::test]
async fn test_request_timeout() {
    // Handler sleeps 30 s — far beyond the 10 s server timeout.
    let svc = TestService::new(Duration::from_secs(30));
    let notifier = svc.handler_started_notifier();
    let (addr, _handle) = spawn_test_server(svc).await;

    let mut client = SignerServiceClientV2::new(make_channel(addr));

    // Spawn the request so we can interleave time advancement.
    let req_task =
        tokio::spawn(
            async move { client.sign_beacon_block(small_sign_beacon_block_request()).await },
        );

    // Wait until the server handler has started (its sleep timer is running).
    notifier.notified().await;

    // Yield once so the handler future actually progresses past notify_one() and
    // registers its `tokio::time::sleep(30s)` with the runtime's time driver
    // BEFORE we freeze the virtual clock.  Without this yield the test has a
    // scheduling race: pause() can fire before the timer is registered, and on
    // a loaded CI runner the timer ends up scheduled at virtual t=11s instead
    // of t=0s — leading to nondeterministic outcomes (review M-10 MF-2).
    tokio::task::yield_now().await;

    // Freeze the tokio clock and jump forward 11 s — past the 10 s server timeout.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;

    let result = req_task.await.expect("task did not panic");
    let err = result.expect_err("request should have been cut off by the 10 s server timeout");

    let code = err.code();
    assert!(
        code == Code::DeadlineExceeded || code == Code::Cancelled,
        "expected DeadlineExceeded or Cancelled when server timeout fires, got: {code:?} — {err}"
    );
}

/// Sending 100 concurrent requests through a single channel must not saturate
/// the server handler beyond the limits set by `hardened_server_builder()`:
/// - `concurrency_limit_per_connection(32)` (Tower) caps handler concurrency
/// - `max_concurrent_streams(Some(64))` (H2 SETTINGS) caps open streams
///
/// Observed peak concurrent handler invocations must be ≤ 32 — the Tower
/// `concurrency_limit_per_connection` is the binding cap because it queues
/// requests beyond the 32-handler ceiling, while `max_concurrent_streams=64`
/// only bounds H2 streams (Tonic admits streams 1–64 and Tower then queues
/// requests 33–64 inside the call queue).  Asserting ≤ 32 means a regression
/// that silently removes the Tower cap fails the test (review M-10 MF-1).
///
/// Excess streams beyond `max_concurrent_streams=64` are **refused** by the
/// server with `RST_STREAM(REFUSED_STREAM)` — per RFC 7540 §8.1.4 such
/// streams are safe to retry.  Tonic surfaces these as `Unavailable`.  The test
/// therefore accepts `Unavailable` for some requests and verifies:
/// 1. No error other than `Unavailable` is seen (no data-loss errors).
/// 2. Peak concurrent handler invocations ≤ 32.
#[tokio::test]
async fn test_concurrent_stream_surge_bounded() {
    const NUM_REQUESTS: usize = 100;
    // Handler sleeps 50 ms to keep streams open long enough to observe overlap.
    let svc = TestService::new(Duration::from_millis(50));

    // Keep a reference to the peak counter BEFORE moving `svc` into the server.
    let peak = Arc::clone(&svc.peak_concurrent);

    let (addr, _handle) = spawn_test_server(svc).await;

    // One channel → one H2 connection pool →
    // server's max_concurrent_streams and concurrency_limit_per_connection apply.
    let base_channel = make_channel(addr);

    // Fan out NUM_REQUESTS concurrent requests, all through the same channel.
    let mut handles = Vec::with_capacity(NUM_REQUESTS);
    for _ in 0..NUM_REQUESTS {
        let ch = base_channel.clone();
        handles.push(tokio::spawn(async move {
            let mut client = SignerServiceClientV2::new(ch);
            client.sign_beacon_block(small_sign_beacon_block_request()).await
        }));
    }

    // Collect outcomes.  Streams beyond max_concurrent_streams(64) are refused
    // with RST_STREAM(REFUSED_STREAM), which Tonic maps to Unavailable.
    // Any other error code would indicate an unexpected problem.
    let mut succeeded = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        match handle.await.expect("spawned task did not panic") {
            Ok(_) => succeeded += 1,
            Err(status) if status.code() == Code::Unavailable => refused += 1,
            Err(other) => panic!("unexpected error (not Unavailable): {other}"),
        }
    }

    assert!(
        succeeded > 0,
        "at least some requests must succeed; succeeded={succeeded} refused={refused}"
    );

    let peak_value = peak.load(Ordering::SeqCst);
    assert!(
        peak_value <= 32,
        "peak concurrent handler invocations was {peak_value}, expected ≤ 32 \
         (concurrency_limit_per_connection=32 is the Tower-level binding cap); \
         succeeded={succeeded} refused={refused}"
    );
}
