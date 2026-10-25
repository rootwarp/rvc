use std::net::SocketAddr;
use std::time::Instant;

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use tokio::task::JoinHandle;
use tracing::info;

/// Bounded, code-derived gRPC sign `type` label values (RF1-09).
///
/// Never request-derived — keeps Prometheus series cardinality low (same
/// reasoning as the HTTP path at `http_api/routes.rs`).
pub mod grpc_sign_type {
    pub const BEACON_BLOCK: &str = "beacon_block";
    pub const BLINDED_BEACON_BLOCK: &str = "blinded_beacon_block";
    pub const RANDAO_REVEAL: &str = "randao_reveal";
    pub const ATTESTATION_DATA: &str = "attestation_data";
    pub const AGGREGATE_AND_PROOF: &str = "aggregate_and_proof";
    pub const SYNC_COMMITTEE_MESSAGE: &str = "sync_committee_message";
    pub const SYNC_AGGREGATOR_SELECTION_DATA: &str = "sync_aggregator_selection_data";
    pub const CONTRIBUTION_AND_PROOF: &str = "contribution_and_proof";
    pub const BUILDER_REGISTRATION: &str = "builder_registration";
    pub const VOLUNTARY_EXIT: &str = "voluntary_exit";
    /// Web3Signer `AGGREGATION_SLOT` (HTTP-only; domain 0x05 selection proof).
    /// Not a v2 gRPC RPC, but shares the A7 `sign_*` series when HTTP dispatches.
    pub const AGGREGATION_SLOT: &str = "aggregation_slot";
    /// Web3Signer `PAYLOAD_ATTESTATION` and gRPC `SignRoot` (domain 0x0C PTC attester).
    pub const PAYLOAD_ATTESTATION: &str = "payload_attestation";
    /// Web3Signer `PROPOSER_PREFERENCES` and gRPC `SignRoot` (domain 0x0D).
    pub const PROPOSER_PREFERENCES: &str = "proposer_preferences";
    /// Web3Signer `BUILDER_REQUEST_AUTH` and gRPC `SignRoot` (domain 0x0B000001).
    pub const BUILDER_REQUEST_AUTH: &str = "builder_request_auth";
    /// gRPC `SignRoot` self-build envelope (domain 0x0B000000). HTTP wire is D19.
    pub const EXECUTION_PAYLOAD_ENVELOPE: &str = "execution_payload_envelope";

    /// All dispatched v2 RPC type labels — used by the table-driven recording test.
    pub const ALL: &[&str] = &[
        BEACON_BLOCK,
        BLINDED_BEACON_BLOCK,
        RANDAO_REVEAL,
        ATTESTATION_DATA,
        AGGREGATE_AND_PROOF,
        SYNC_COMMITTEE_MESSAGE,
        SYNC_AGGREGATOR_SELECTION_DATA,
        CONTRIBUTION_AND_PROOF,
        BUILDER_REGISTRATION,
        VOLUNTARY_EXIT,
        PAYLOAD_ATTESTATION,
        PROPOSER_PREFERENCES,
        BUILDER_REQUEST_AUTH,
        EXECUTION_PAYLOAD_ENVELOPE,
    ];
}

#[cfg(feature = "dvt")]
pub use crate::dvt::peer_ready::RVC_DVT_PEER_READY;

#[cfg(feature = "dvt")]
#[derive(Clone)]
pub struct DvtMetrics {
    pub coordination_duration_seconds: HistogramVec,
    pub peers_responded: HistogramVec,
    pub threshold_failures_total: IntCounterVec,
    pub partial_sign_duration_seconds: HistogramVec,
}

pub struct SignerMetrics {
    pub registry: Registry,
    pub sign_total: IntCounterVec,
    pub sign_duration_seconds: HistogramVec,
    pub sign_errors_total: IntCounterVec,
    pub keys_loaded: GaugeVec,
    /// HTTP (Web3Signer) sign requests, labeled by Web3Signer `type` and outcome
    /// (Issue 4.5). A DISTINCT name from the gRPC `sign_total` so the two
    /// transports' series never collide on label arity; both are scraped on the
    /// single `:9101` listener.
    pub http_sign_total: IntCounterVec,
    /// HTTP (Web3Signer) sign latency in seconds (Issue 4.5), separate from the
    /// gRPC `sign_duration_seconds` histogram.
    pub http_sign_duration_seconds: HistogramVec,
    /// Fail-closed type/version rejections (issue 8.4). Same family name as
    /// `signer::metrics::RVC_SIGNER_REJECTIONS_TOTAL`; this handle is registered
    /// on the process-local `:9101` registry (not the VC global `REGISTRY`).
    pub rejections_total: IntCounterVec,
    #[cfg(feature = "dvt")]
    pub dvt: DvtMetrics,
}

impl Default for SignerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SignerMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // gRPC collectors (RF1-09): type × outcome, plus backend dimension.
        // Series were never emitted in production before RF1-09, so the arity
        // change from {backend,result} / {backend} is dashboard-safe.
        let sign_total = IntCounterVec::new(
            Opts::new("rvc_signer_sign_total", "Total number of signing requests"),
            &["backend", "type", "result"],
        )
        .expect("failed to create rvc_signer_sign_total");
        registry
            .register(Box::new(sign_total.clone()))
            .expect("failed to register rvc_signer_sign_total");

        let sign_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "rvc_signer_sign_duration_seconds",
                "Duration of signing operations in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["backend", "type"],
        )
        .expect("failed to create rvc_signer_sign_duration_seconds");
        registry
            .register(Box::new(sign_duration_seconds.clone()))
            .expect("failed to register rvc_signer_sign_duration_seconds");

        let sign_errors_total = IntCounterVec::new(
            Opts::new("rvc_signer_sign_errors_total", "Total number of signing errors"),
            &["backend", "error_type"],
        )
        .expect("failed to create rvc_signer_sign_errors_total");
        registry
            .register(Box::new(sign_errors_total.clone()))
            .expect("failed to register rvc_signer_sign_errors_total");

        let keys_loaded = GaugeVec::new(
            Opts::new("rvc_signer_keys_loaded", "Number of keys currently loaded"),
            &["backend"],
        )
        .expect("failed to create rvc_signer_keys_loaded");
        registry
            .register(Box::new(keys_loaded.clone()))
            .expect("failed to register rvc_signer_keys_loaded");

        // HTTP (Web3Signer) path series (Issue 4.5) — DISTINCT names from the
        // gRPC vecs above so a single `:9101` scrape spans both transports.
        let http_sign_total = IntCounterVec::new(
            Opts::new("rvc_signer_http_sign_total", "Total number of HTTP sign requests"),
            &["type", "result"],
        )
        .expect("failed to create rvc_signer_http_sign_total");
        registry
            .register(Box::new(http_sign_total.clone()))
            .expect("failed to register rvc_signer_http_sign_total");

        let http_sign_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "rvc_signer_http_sign_duration_seconds",
                "Duration of HTTP sign requests in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &[],
        )
        .expect("failed to create rvc_signer_http_sign_duration_seconds");
        registry
            .register(Box::new(http_sign_duration_seconds.clone()))
            .expect("failed to register rvc_signer_http_sign_duration_seconds");

        let rejections_total = IntCounterVec::new(
            Opts::new(
                "rvc_signer_rejections_total",
                "Fail-closed signer rejections by reason, sign type, and consensus version",
            ),
            &["reason", "sign_type", "version"],
        )
        .expect("failed to create rvc_signer_rejections_total");
        registry
            .register(Box::new(rejections_total.clone()))
            .expect("failed to register rvc_signer_rejections_total");

        #[cfg(feature = "dvt")]
        let dvt = {
            let coordination_duration_seconds = HistogramVec::new(
                HistogramOpts::new(
                    "rvc_signer_dvt_coordination_duration_seconds",
                    "Total time for DVT peer coordination in seconds",
                )
                .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
                &[],
            )
            .expect("failed to create rvc_signer_dvt_coordination_duration_seconds");
            registry
                .register(Box::new(coordination_duration_seconds.clone()))
                .expect("failed to register rvc_signer_dvt_coordination_duration_seconds");

            let peers_responded = HistogramVec::new(
                HistogramOpts::new(
                    "rvc_signer_dvt_peers_responded",
                    "Number of peers that responded per DVT sign operation",
                )
                .buckets(vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0]),
                &[],
            )
            .expect("failed to create rvc_signer_dvt_peers_responded");
            registry
                .register(Box::new(peers_responded.clone()))
                .expect("failed to register rvc_signer_dvt_peers_responded");

            let threshold_failures_total = IntCounterVec::new(
                Opts::new(
                    "rvc_signer_dvt_threshold_failures_total",
                    "Total times DVT threshold was not met",
                ),
                &[],
            )
            .expect("failed to create rvc_signer_dvt_threshold_failures_total");
            registry
                .register(Box::new(threshold_failures_total.clone()))
                .expect("failed to register rvc_signer_dvt_threshold_failures_total");

            let partial_sign_duration_seconds = HistogramVec::new(
                HistogramOpts::new(
                    "rvc_signer_dvt_partial_sign_duration_seconds",
                    "Per-peer partial signature latency in seconds",
                )
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
                &["peer"],
            )
            .expect("failed to create rvc_signer_dvt_partial_sign_duration_seconds");
            registry
                .register(Box::new(partial_sign_duration_seconds.clone()))
                .expect("failed to register rvc_signer_dvt_partial_sign_duration_seconds");

            crate::dvt::peer_ready::init();
            registry
                .register(Box::new(crate::dvt::peer_ready::RVC_DVT_PEER_READY.clone()))
                .expect("failed to register rvc_dvt_peer_ready");

            DvtMetrics {
                coordination_duration_seconds,
                peers_responded,
                threshold_failures_total,
                partial_sign_duration_seconds,
            }
        };

        Self {
            registry,
            sign_total,
            sign_duration_seconds,
            sign_errors_total,
            keys_loaded,
            http_sign_total,
            http_sign_duration_seconds,
            rejections_total,
            #[cfg(feature = "dvt")]
            dvt,
        }
    }

    /// Increment the `:9101` twin of `rvc_signer_rejections_total`.
    pub fn record_rejection(&self, reason: &str, sign_type: &str, version: &str) {
        self.rejections_total.with_label_values(&[reason, sign_type, version]).inc();
    }

    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }
}

/// Map a backend error to a bounded `error_type` label for `sign_errors_total`.
pub fn classify_error(err: &crate::backend::SigningBackendError) -> &'static str {
    match err {
        crate::backend::SigningBackendError::KeyNotFound(_) => "key_not_found",
        crate::backend::SigningBackendError::SigningFailed(_) => "internal",
        crate::backend::SigningBackendError::KeystoreLoadFailed(_) => "internal",
    }
}

/// Map a gate error to a bounded `error_type` label for `sign_errors_total`.
///
/// Label vocabulary aligns with the HTTP audit labels
/// (`http_api/response.rs::audit_label`) so operators can correlate transports:
/// - `key_not_found` — unknown pubkey
/// - `doppelganger` — signing enablement / doppelganger gate blocked
/// - `slashing` — slashable conflict (double vote / double proposal / surround)
/// - `slashing_db_error` — non-slashable slashing-DB staging failure (I/O, etc.)
/// - `internal` — backend sign failure or post-sign commit failure
///
/// All values are code-derived constants (never request-derived); cardinality
/// stays fixed regardless of error message content.
pub fn classify_gate_error(err: &signer::SigningGateError) -> &'static str {
    // Shared library classifier — same labels as HTTP audit via GateErrClass.
    signer::classify(err).metrics_label()
}

/// Record one gRPC sign attempt on the shared collectors (RF1-09).
///
/// Free-standing (not a method on `SignerServiceImpl`) so Phase 4's D4
/// `SignPlan` dispatcher can absorb it unchanged.
///
/// - No-ops when `metrics` is `None`.
/// - Always increments `sign_total{backend,type,result}` and observes
///   `sign_duration_seconds{backend,type}`.
/// - On `Err(error_type)`, increments `sign_errors_total{backend,error_type}`.
///   Callers must pass a **bounded** label from [`classify_error`] (backend) or
///   [`classify_gate_error`] (gate) — never request-derived text.
///
/// # Timer semantics
///
/// `started` is expected to be captured at the **gate/backend sign boundary**
/// (after CN auth, SSZ decode, and signing-root computation). Duration therefore
/// reflects pure sign latency, not full RPC wall time. Pre-sign validation
/// failures do not call this helper at all (no series increment).
///
/// `rpc_type` must be one of the bounded [`grpc_sign_type`] constants — never
/// request-derived.
pub fn record_sign(
    metrics: Option<&SignerMetrics>,
    backend: &str,
    rpc_type: &str,
    started: Instant,
    outcome: Result<(), &'static str>,
) {
    let Some(m) = metrics else {
        return;
    };
    let elapsed = started.elapsed().as_secs_f64();
    let result = if outcome.is_ok() { "success" } else { "error" };
    m.sign_total.with_label_values(&[backend, rpc_type, result]).inc();
    m.sign_duration_seconds.with_label_values(&[backend, rpc_type]).observe(elapsed);
    if let Err(error_type) = outcome {
        m.sign_errors_total.with_label_values(&[backend, error_type]).inc();
    }
}

/// Binds `addr` and serves the Prometheus text on `GET /metrics`.
///
/// `HEAD /metrics` gets the headers only. Another path gets `404`, another
/// method on `/metrics` gets `405` with `Allow: GET, HEAD`, and a malformed or
/// oversized request head gets `400`. The listener reads the request head
/// before it answers. Each connection runs in its own task, at most 16 at a
/// time. When 16 are open, a new connection evicts the oldest one that has no
/// complete request head. A 2 s limit covers the head read and the response
/// write together.
///
/// # Errors
/// Returns an error if the bind fails.
pub async fn serve_metrics(
    addr: SocketAddr,
    metrics: std::sync::Arc<SignerMetrics>,
) -> Result<(JoinHandle<()>, SocketAddr), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    info!(address = %local_addr, "Metrics server listening");

    let handle = tokio::spawn(async move {
        serve_metrics_loop(listener, metrics, ConnectionLimits::default()).await;
    });

    Ok((handle, local_addr))
}

/// Largest request head that the metrics listener reads.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;

/// Most connections that the metrics listener serves at the same time.
const MAX_METRICS_CONNECTIONS: usize = 16;

/// Time limit for one connection: the request head read and the response write.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Limits of the metrics listener. Tests use smaller values.
struct ConnectionLimits {
    max_connections: usize,
    connection_timeout: std::time::Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self { max_connections: MAX_METRICS_CONNECTIONS, connection_timeout: CONNECTION_TIMEOUT }
    }
}

/// One open connection, in accept order.
struct OpenConnection {
    abort: tokio::task::AbortHandle,
    /// Set when the connection sent a complete request head.
    head_complete: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The open connections of the metrics listener, oldest first.
struct OpenConnections {
    max: usize,
    queue: std::collections::VecDeque<OpenConnection>,
}

impl OpenConnections {
    fn new(max: usize) -> Self {
        Self { max, queue: std::collections::VecDeque::with_capacity(max) }
    }

    /// Makes room for one more connection.
    ///
    /// When the listener is full, aborts the oldest connection that has no
    /// complete request head. Returns `false` when each open connection has a
    /// complete head, because those connections are writing a response.
    fn make_room(&mut self) -> bool {
        self.queue.retain(|conn| !conn.abort.is_finished());
        if self.queue.len() < self.max {
            return true;
        }
        let silent = self
            .queue
            .iter()
            .position(|conn| !conn.head_complete.load(std::sync::atomic::Ordering::Acquire));
        match silent.and_then(|at| self.queue.remove(at)) {
            Some(oldest) => {
                oldest.abort.abort();
                true
            }
            None => false,
        }
    }

    fn push(&mut self, conn: OpenConnection) {
        self.queue.push_back(conn);
    }
}

/// Accepts connections and serves each one in its own task.
///
/// When the listener is full, a new connection evicts the oldest connection
/// that has no complete request head. Thus silent clients cannot lock out a
/// scrape or the health probe. If each open connection has a complete head,
/// the new connection is closed at once. Aborting this task drops the
/// `JoinSet`, which aborts each open connection.
async fn serve_metrics_loop(
    listener: tokio::net::TcpListener,
    metrics: std::sync::Arc<SignerMetrics>,
    limits: ConnectionLimits,
) {
    let mut connections = tokio::task::JoinSet::new();
    let mut open = OpenConnections::new(limits.max_connections);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept metrics connection");
                continue;
            }
        };
        while connections.try_join_next().is_some() {}

        if !open.make_room() {
            drop(stream);
            continue;
        }
        let head_complete = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&head_complete);
        let metrics = std::sync::Arc::clone(&metrics);
        let timeout = limits.connection_timeout;
        let abort = connections.spawn(async move {
            let _ = tokio::time::timeout(timeout, serve_connection(stream, &metrics, &flag)).await;
        });
        open.push(OpenConnection { abort, head_complete });
    }
}

/// Reads one request head and writes one response.
async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    metrics: &SignerMetrics,
    head_complete: &std::sync::atomic::AtomicBool,
) {
    use tokio::io::AsyncWriteExt;

    let Ok(head) = read_request_head(&mut stream).await else {
        return;
    };
    head_complete.store(true, std::sync::atomic::Ordering::Release);
    let response = match route_request(&head) {
        route @ (MetricsRoute::Metrics | MetricsRoute::MetricsHead) => match metrics.encode() {
            Ok(body) => {
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                if route == MetricsRoute::Metrics {
                    response.extend_from_slice(&body);
                }
                response
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode metrics");
                empty_response("500 Internal Server Error", "")
            }
        },
        MetricsRoute::NotFound => empty_response("404 Not Found", ""),
        MetricsRoute::MethodNotAllowed => {
            empty_response("405 Method Not Allowed", "Allow: GET, HEAD\r\n")
        }
        MetricsRoute::BadRequest => empty_response("400 Bad Request", ""),
    };
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

/// What the metrics listener does with one request head.
#[derive(Debug, PartialEq, Eq)]
enum MetricsRoute {
    Metrics,
    MetricsHead,
    NotFound,
    MethodNotAllowed,
    BadRequest,
}

/// Reads up to the blank line (`CRLF CRLF` or bare `LF LF`) that ends the head.
///
/// An oversized head gives an empty head, which [`route_request`] rejects.
async fn read_request_head(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n") {
            return Ok(head);
        }
        if head.len() >= MAX_REQUEST_HEAD_BYTES {
            return Ok(Vec::new());
        }
    }
}

/// Only `GET` or `HEAD` on `/metrics` (with or without a query string) gives
/// the metrics. An absolute-form target (`http://host/metrics`) gives the same.
fn route_request(head: &[u8]) -> MetricsRoute {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return MetricsRoute::BadRequest;
    };
    let mut parts = line.trim_end_matches('\r').split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return MetricsRoute::BadRequest;
    };
    if !version.starts_with("HTTP/1.") {
        return MetricsRoute::BadRequest;
    }
    let origin_form = match target.split_once("://") {
        Some((_, rest)) if !target.starts_with('/') => rest.find('/').map_or("/", |at| &rest[at..]),
        _ => target,
    };
    let path = origin_form.split('?').next().unwrap_or(origin_form);
    match (method, path) {
        ("GET", "/metrics") => MetricsRoute::Metrics,
        ("HEAD", "/metrics") => MetricsRoute::MetricsHead,
        (_, "/metrics") => MetricsRoute::MethodNotAllowed,
        _ => MetricsRoute::NotFound,
    }
}

fn empty_response(status: &str, extra_headers: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n{extra_headers}Connection: close\r\n\r\n")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new_creates_all_metrics() {
        let m = SignerMetrics::new();
        // Touch each metric so gather() returns them
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
        m.sign_duration_seconds.with_label_values(&["basic", "beacon_block"]).observe(0.0);
        m.sign_errors_total.with_label_values(&["basic", "internal"]).inc();
        m.keys_loaded.with_label_values(&["basic"]).set(0.0);
        // HTTP-path series (Issue 4.5) — registered in the same registry.
        m.http_sign_total.with_label_values(&["ATTESTATION", "success"]).inc();
        m.http_sign_duration_seconds.with_label_values(&[] as &[&str]).observe(0.0);
        m.record_rejection("unsupported_version", "beacon_block", "unknown");

        let gathered = m.registry.gather();
        let names: Vec<&str> = gathered.iter().map(|mf| mf.name()).collect();
        assert!(names.contains(&"rvc_signer_sign_total"));
        assert!(names.contains(&"rvc_signer_sign_duration_seconds"));
        assert!(names.contains(&"rvc_signer_sign_errors_total"));
        assert!(names.contains(&"rvc_signer_keys_loaded"));
        assert!(names.contains(&"rvc_signer_http_sign_total"));
        assert!(names.contains(&"rvc_signer_http_sign_duration_seconds"));
        assert!(names.contains(&"rvc_signer_rejections_total"));
    }

    #[test]
    fn test_sign_total_counter_increments() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
        assert_eq!(m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).get(), 1);
    }

    #[test]
    fn test_sign_duration_histogram_records() {
        let m = SignerMetrics::new();
        m.sign_duration_seconds.with_label_values(&["basic", "beacon_block"]).observe(0.05);
        assert_eq!(
            m.sign_duration_seconds
                .with_label_values(&["basic", "beacon_block"])
                .get_sample_count(),
            1
        );
        assert!(
            (m.sign_duration_seconds
                .with_label_values(&["basic", "beacon_block"])
                .get_sample_sum()
                - 0.05)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn test_sign_errors_total_increments() {
        let m = SignerMetrics::new();
        m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).inc();
        assert_eq!(m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(), 1);
    }

    #[test]
    fn test_keys_loaded_gauge_sets() {
        let m = SignerMetrics::new();
        m.keys_loaded.with_label_values(&["basic"]).set(5.0);
        assert_eq!(m.keys_loaded.with_label_values(&["basic"]).get(), 5.0);
    }

    #[test]
    fn test_encode_returns_prometheus_text() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
        let output = m.encode().unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("rvc_signer_sign_total"));
        assert!(text.contains("basic"));
        assert!(text.contains("success"));
        assert!(text.contains("beacon_block"));
    }

    #[test]
    fn test_classify_error_key_not_found() {
        let err = crate::backend::SigningBackendError::KeyNotFound([0u8; 48]);
        assert_eq!(classify_error(&err), "key_not_found");
    }

    #[test]
    fn test_classify_error_signing_failed() {
        let err = crate::backend::SigningBackendError::SigningFailed("test".to_string());
        assert_eq!(classify_error(&err), "internal");
    }

    #[test]
    fn test_classify_error_keystore_load_failed() {
        let err = crate::backend::SigningBackendError::KeystoreLoadFailed("test".to_string());
        assert_eq!(classify_error(&err), "internal");
    }

    #[test]
    fn test_different_backends_independent() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
        m.sign_total.with_label_values(&["dvt", "beacon_block", "success"]).inc();
        m.sign_total.with_label_values(&["dvt", "beacon_block", "success"]).inc();
        assert_eq!(m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).get(), 1);
        assert_eq!(m.sign_total.with_label_values(&["dvt", "beacon_block", "success"]).get(), 2);
    }

    #[test]
    fn test_record_sign_success_increments_total_and_duration() {
        let m = SignerMetrics::new();
        let started = Instant::now();
        record_sign(Some(&m), "basic", grpc_sign_type::BEACON_BLOCK, started, Ok(()));
        assert_eq!(
            m.sign_total
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK, "success"])
                .get(),
            1
        );
        assert_eq!(
            m.sign_duration_seconds
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK])
                .get_sample_count(),
            1
        );
        assert_eq!(m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(), 0);
    }

    #[test]
    fn test_record_sign_error_routes_through_classify_error() {
        let m = SignerMetrics::new();
        let err = crate::backend::SigningBackendError::KeyNotFound([0u8; 48]);
        let started = Instant::now();
        record_sign(
            Some(&m),
            "basic",
            grpc_sign_type::ATTESTATION_DATA,
            started,
            Err(classify_error(&err)),
        );
        assert_eq!(
            m.sign_total
                .with_label_values(&["basic", grpc_sign_type::ATTESTATION_DATA, "error"])
                .get(),
            1
        );
        assert_eq!(m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(), 1);
    }

    #[test]
    fn test_classify_gate_error_bounded_taxonomy() {
        use signer::SigningGateError;
        use slashing::{BlockSlashingViolation, SlashingError};

        assert_eq!(classify_gate_error(&SigningGateError::BlockedByDoppelganger), "doppelganger");
        assert_eq!(
            classify_gate_error(&SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
                BlockSlashingViolation::DoubleBlockProposal { slot: 1 }
            ))),
            "slashing"
        );
        assert_eq!(
            classify_gate_error(&SigningGateError::SlashingBlocked(
                SlashingError::MigrationFailed("io".into())
            )),
            "slashing_db_error"
        );
        assert_eq!(
            classify_gate_error(&SigningGateError::CommitFailed {
                signing_root: [0u8; 32],
                source: SlashingError::MigrationFailed("io".into()),
            }),
            "internal"
        );
        assert_eq!(classify_gate_error(&SigningGateError::KeyNotFound), "key_not_found");
        assert_eq!(classify_gate_error(&SigningGateError::UnknownPubkey), "key_not_found");
        assert_eq!(classify_gate_error(&SigningGateError::SigningFailed("x".into())), "internal");
    }

    #[test]
    fn test_sign_recording_helper_no_ops_without_metrics() {
        // Must not panic when metrics is None (RF1-09 acceptance).
        record_sign(None, "basic", grpc_sign_type::RANDAO_REVEAL, Instant::now(), Ok(()));
        record_sign(None, "basic", grpc_sign_type::RANDAO_REVEAL, Instant::now(), Err("internal"));
    }

    #[test]
    fn test_grpc_sign_type_all_lists_dispatched_handlers() {
        assert_eq!(grpc_sign_type::ALL.len(), 14);
        assert_eq!(grpc_sign_type::ALL[0], grpc_sign_type::BEACON_BLOCK);
        assert_eq!(grpc_sign_type::ALL[9], grpc_sign_type::VOLUNTARY_EXIT);
        assert_eq!(grpc_sign_type::ALL[10], grpc_sign_type::PAYLOAD_ATTESTATION);
        assert_eq!(grpc_sign_type::ALL[11], grpc_sign_type::PROPOSER_PREFERENCES);
        assert_eq!(grpc_sign_type::ALL[12], grpc_sign_type::BUILDER_REQUEST_AUTH);
        assert_eq!(grpc_sign_type::ALL[13], grpc_sign_type::EXECUTION_PAYLOAD_ENVELOPE);
    }

    #[tokio::test]
    async fn test_serve_metrics_responds_to_http() {
        let m = std::sync::Arc::new(SignerMetrics::new());
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (handle, bound_addr) = serve_metrics(addr, std::sync::Arc::clone(&m)).await.unwrap();

        let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        // Wait for full response
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200 OK"), "response: {response}");
        assert!(response.contains("rvc_signer_sign_total"), "response: {response}");

        handle.abort();
    }

    async fn spawn_test_listener() -> (JoinHandle<()>, SocketAddr) {
        let m = std::sync::Arc::new(SignerMetrics::new());
        m.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
        serve_metrics("127.0.0.1:0".parse().expect("addr"), m).await.expect("serve")
    }

    async fn spawn_test_listener_with(
        max_connections: usize,
        connection_timeout: std::time::Duration,
    ) -> (JoinHandle<()>, SocketAddr) {
        let m = std::sync::Arc::new(SignerMetrics::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let limits = ConnectionLimits { max_connections, connection_timeout };
        (tokio::spawn(serve_metrics_loop(listener, m, limits)), addr)
    }

    /// An HTTP client sends the request first. A reply before the request is
    /// an error for hyper ("received unexpected message from connection").
    #[tokio::test]
    async fn test_serve_metrics_answers_an_http_client_on_the_metrics_route() {
        let (handle, addr) = spawn_test_listener().await;
        for _ in 0..20 {
            let response =
                reqwest::get(format!("http://{addr}/metrics")).await.expect("GET /metrics");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let body = response.text().await.expect("body");
            assert!(body.contains("rvc_signer_sign_total"), "body: {body}");
        }
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_answers_404_on_an_unknown_path() {
        let (handle, addr) = spawn_test_listener().await;
        for path in ["/healthz", "/", "/metricsx"] {
            let response = reqwest::get(format!("http://{addr}{path}")).await.expect("GET");
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
            assert!(!response.text().await.expect("body").contains("rvc_signer_"), "{path}");
        }
        let query = reqwest::get(format!("http://{addr}/metrics?x=1")).await.expect("GET");
        assert_eq!(query.status(), reqwest::StatusCode::OK);
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_answers_405_on_a_method_other_than_get() {
        let (handle, addr) = spawn_test_listener().await;
        let response = reqwest::Client::new()
            .post(format!("http://{addr}/metrics"))
            .send()
            .await
            .expect("POST");
        assert_eq!(response.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(reqwest::header::ALLOW).and_then(|v| v.to_str().ok()),
            Some("GET, HEAD")
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_answers_400_on_a_malformed_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (handle, addr) = spawn_test_listener().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.write_all(b"garbage\r\n\r\n").await.expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).await.expect("read");
        assert!(response.starts_with("HTTP/1.1 400 "), "response: {response}");
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_answers_400_on_an_oversized_request_head() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (handle, addr) = spawn_test_listener().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut request = b"GET /metrics HTTP/1.1\r\nX-Pad: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEAD_BYTES));
        let _ = stream.write_all(&request).await;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400 "), "response: {response}");
        handle.abort();
    }

    #[test]
    fn test_route_request_accepts_only_get_metrics() {
        for (head, route) in [
            (&b"GET /metrics HTTP/1.1\r\n\r\n"[..], MetricsRoute::Metrics),
            (b"GET /metrics?name=x HTTP/1.0\r\n\r\n", MetricsRoute::Metrics),
            (b"GET /healthz HTTP/1.1\r\n\r\n", MetricsRoute::NotFound),
            (b"HEAD /metrics HTTP/1.1\r\n\r\n", MetricsRoute::MetricsHead),
            (b"POST /metrics HTTP/1.1\r\n\r\n", MetricsRoute::MethodNotAllowed),
            (b"GET /metrics HTTP/1.1\n\n", MetricsRoute::Metrics),
            (b"GET http://127.0.0.1:9101/metrics HTTP/1.1\r\n\r\n", MetricsRoute::Metrics),
            (b"GET https://signer/metrics?x=1 HTTP/1.1\r\n\r\n", MetricsRoute::Metrics),
            (b"GET http://127.0.0.1:9101/healthz HTTP/1.1\r\n\r\n", MetricsRoute::NotFound),
            (b"GET http://127.0.0.1:9101 HTTP/1.1\r\n\r\n", MetricsRoute::NotFound),
            (b"GET /metrics?next=http://a/b HTTP/1.1\r\n\r\n", MetricsRoute::Metrics),
            (b"GET /metrics HTTP/2\r\n\r\n", MetricsRoute::BadRequest),
            (b"GET /metrics\r\n\r\n", MetricsRoute::BadRequest),
            (b"GET  /metrics HTTP/1.1\r\n\r\n", MetricsRoute::BadRequest),
            (b"GET /\xff HTTP/1.1\r\n\r\n", MetricsRoute::BadRequest),
            (b"", MetricsRoute::BadRequest),
        ] {
            assert_eq!(route_request(head), route, "{}", String::from_utf8_lossy(head));
        }
    }

    /// A client that closes before the request head ends gets no answer, and
    /// the listener still serves the next client.
    #[tokio::test]
    async fn test_serve_metrics_survives_a_client_that_closes_early() {
        use tokio::io::AsyncWriteExt;

        let (handle, addr) = spawn_test_listener().await;
        let mut early = tokio::net::TcpStream::connect(addr).await.expect("connect");
        early.write_all(b"GET /metr").await.expect("write");
        drop(early);
        let response = reqwest::get(format!("http://{addr}/metrics")).await.expect("GET");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        handle.abort();
    }

    /// Idle clients do not delay a scrape. The old serial loop held each idle
    /// client for the full head timeout, so three of them delayed a scrape by 6 s.
    #[tokio::test]
    async fn test_serve_metrics_serves_a_scrape_while_idle_clients_wait() {
        let (handle, addr) = spawn_test_listener().await;
        let mut idle = Vec::new();
        for _ in 0..3 {
            idle.push(tokio::net::TcpStream::connect(addr).await.expect("connect idle"));
        }
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let response =
            client.get(format!("http://{addr}/metrics")).send().await.expect("GET with idle");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(4),
            "scrape waited {:?}",
            started.elapsed()
        );
        drop(idle);
        handle.abort();
    }

    /// The listener closes a client that sends no complete request, but only
    /// when the connection timeout ends.
    #[tokio::test]
    async fn test_serve_metrics_closes_a_silent_connection_after_the_timeout() {
        use tokio::io::AsyncReadExt;

        let limit = std::time::Duration::from_millis(500);
        let (handle, addr) = spawn_test_listener_with(4, limit).await;
        let mut silent = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let started = std::time::Instant::now();
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(5), silent.read_to_end(&mut buf))
                .await
                .expect("listener must close the silent connection");
        let closed_after = started.elapsed();
        assert!(read.is_err() || buf.is_empty(), "no response to a silent client: {buf:?}");
        assert!(
            closed_after >= limit - std::time::Duration::from_millis(100),
            "closed before the timeout: {closed_after:?}"
        );
        handle.abort();
    }

    /// Sixteen silent clients do not lock out the health probe. The listener
    /// evicts the oldest connection that has no complete request head.
    #[tokio::test]
    async fn test_serve_metrics_evicts_the_oldest_silent_connection_when_full() {
        use tokio::io::AsyncReadExt;

        let (handle, addr) = spawn_test_listener().await;
        let mut silent = Vec::new();
        for _ in 0..MAX_METRICS_CONNECTIONS {
            silent.push(tokio::net::TcpStream::connect(addr).await.expect("connect silent"));
        }
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let response =
            client.get(format!("http://{addr}/metrics")).send().await.expect("GET when full");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1500),
            "scrape waited {:?}",
            started.elapsed()
        );

        let mut buf = Vec::new();
        let oldest = tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            silent[0].read_to_end(&mut buf),
        )
        .await
        .expect("the oldest silent connection is evicted before its timeout");
        assert!(oldest.is_err() || buf.is_empty(), "evicted client got bytes: {buf:?}");
        handle.abort();
    }

    /// Eviction takes the oldest connection that has no complete head. A
    /// connection with a complete head is never evicted.
    #[tokio::test]
    async fn test_open_connections_never_evict_a_connection_with_a_complete_head() {
        use std::sync::atomic::AtomicBool;

        let mut tasks = tokio::task::JoinSet::new();
        let mut open = OpenConnections::new(3);
        let mut ids = Vec::new();
        for complete in [true, false, false] {
            let abort = tasks.spawn(std::future::pending::<()>());
            ids.push(abort.id());
            open.push(OpenConnection {
                abort,
                head_complete: std::sync::Arc::new(AtomicBool::new(complete)),
            });
        }

        assert!(open.make_room(), "a silent connection can make room");
        let evicted = tasks.join_next_with_id().await.expect("one task ends");
        let err = evicted.expect_err("the evicted task is cancelled");
        assert!(err.is_cancelled());
        assert_eq!(err.id(), ids[1], "the oldest silent connection is evicted");
        assert_eq!(tasks.len(), 2);

        let mut full = OpenConnections::new(2);
        for _ in 0..2 {
            let abort = tasks.spawn(std::future::pending::<()>());
            full.push(OpenConnection {
                abort,
                head_complete: std::sync::Arc::new(AtomicBool::new(true)),
            });
        }
        assert!(!full.make_room(), "connections with a complete head stay");
        assert!(tasks.try_join_next().is_none(), "no task was cancelled");
        tasks.abort_all();
    }

    #[tokio::test]
    async fn test_serve_metrics_answers_a_head_that_ends_with_bare_lf() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (handle, addr) = spawn_test_listener().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.write_all(b"GET /metrics HTTP/1.1\n\n").await.expect("write");
        let mut response = String::new();
        tokio::time::timeout(
            CONNECTION_TIMEOUT - std::time::Duration::from_millis(200),
            stream.read_to_string(&mut response),
        )
        .await
        .expect("answer must not wait for the head timeout")
        .expect("read");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "response: {response}");
        handle.abort();
    }

    /// Raw bytes, because hyper drops any body on a HEAD response.
    #[tokio::test]
    async fn test_serve_metrics_answers_head_without_a_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (handle, addr) = spawn_test_listener().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.write_all(b"HEAD /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read to EOF");
        let response = String::from_utf8(raw).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "response: {response}");
        let head_end = response.find("\r\n\r\n").expect("head end") + 4;
        assert_eq!(head_end, response.len(), "HEAD must not send a body: {response}");
        let length: usize = response
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("content-length")
            .parse()
            .expect("number");
        assert!(length > 0, "HEAD gives the GET length");
        handle.abort();
    }

    #[cfg(feature = "dvt")]
    mod dvt_metrics_tests {
        use super::*;

        #[test]
        fn test_dvt_metrics_registered_in_signer_metrics() {
            let m = SignerMetrics::new();
            m.dvt.coordination_duration_seconds.with_label_values(&[] as &[&str]).observe(0.1);
            m.dvt.peers_responded.with_label_values(&[] as &[&str]).observe(2.0);
            m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).inc();
            m.dvt.partial_sign_duration_seconds.with_label_values(&["peer1:5000"]).observe(0.05);

            let gathered = m.registry.gather();
            let names: Vec<&str> = gathered.iter().map(|mf| mf.name()).collect();
            assert!(names.contains(&"rvc_signer_dvt_coordination_duration_seconds"));
            assert!(names.contains(&"rvc_signer_dvt_peers_responded"));
            assert!(names.contains(&"rvc_signer_dvt_threshold_failures_total"));
            assert!(names.contains(&"rvc_signer_dvt_partial_sign_duration_seconds"));
        }

        /// 4.11c / D4: reuse `threshold_failures_total`; do not register a new family.
        /// Pins DVT family *identity*, not an absolute family count.
        #[test]
        fn test_signer_server_dvt_metric_families_unchanged() {
            let m = SignerMetrics::new();
            // Touch each existing family so gather() emits them.
            m.dvt.coordination_duration_seconds.with_label_values(&[] as &[&str]).observe(0.0);
            m.dvt.peers_responded.with_label_values(&[] as &[&str]).observe(0.0);
            m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).inc();
            m.dvt.partial_sign_duration_seconds.with_label_values(&["peer"]).observe(0.0);

            let gathered = m.registry.gather();
            let names: Vec<&str> = gathered.iter().map(|mf| mf.name()).collect();
            assert!(
                !names.iter().any(|n| n.contains("disagreement") || n.contains("ptc_session")),
                "4.11c must not register a disagreement/session family: {names:?}"
            );
            let mut dvt: Vec<&str> =
                names.iter().copied().filter(|n| n.starts_with("rvc_signer_dvt_")).collect();
            dvt.sort_unstable();
            assert_eq!(
                dvt,
                [
                    "rvc_signer_dvt_coordination_duration_seconds",
                    "rvc_signer_dvt_partial_sign_duration_seconds",
                    "rvc_signer_dvt_peers_responded",
                    "rvc_signer_dvt_threshold_failures_total",
                ]
            );
        }

        #[test]
        fn test_dvt_coordination_duration_records() {
            let m = SignerMetrics::new();
            m.dvt.coordination_duration_seconds.with_label_values(&[] as &[&str]).observe(0.25);
            assert_eq!(
                m.dvt
                    .coordination_duration_seconds
                    .with_label_values(&[] as &[&str])
                    .get_sample_count(),
                1
            );
        }

        #[test]
        fn test_dvt_peers_responded_records() {
            let m = SignerMetrics::new();
            m.dvt.peers_responded.with_label_values(&[] as &[&str]).observe(3.0);
            assert_eq!(
                m.dvt.peers_responded.with_label_values(&[] as &[&str]).get_sample_count(),
                1
            );
            assert!(
                (m.dvt.peers_responded.with_label_values(&[] as &[&str]).get_sample_sum() - 3.0)
                    .abs()
                    < 1e-9
            );
        }

        #[test]
        fn test_dvt_threshold_failures_increments() {
            let m = SignerMetrics::new();
            m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).inc();
            m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).inc();
            assert_eq!(m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).get(), 2);
        }

        #[test]
        fn test_dvt_partial_sign_duration_per_peer() {
            let m = SignerMetrics::new();
            m.dvt.partial_sign_duration_seconds.with_label_values(&["peer1:5000"]).observe(0.05);
            m.dvt.partial_sign_duration_seconds.with_label_values(&["peer2:5000"]).observe(0.10);
            assert_eq!(
                m.dvt
                    .partial_sign_duration_seconds
                    .with_label_values(&["peer1:5000"])
                    .get_sample_count(),
                1
            );
            assert_eq!(
                m.dvt
                    .partial_sign_duration_seconds
                    .with_label_values(&["peer2:5000"])
                    .get_sample_count(),
                1
            );
        }

        #[test]
        fn test_dvt_metrics_in_encode_output() {
            let m = SignerMetrics::new();
            m.dvt.coordination_duration_seconds.with_label_values(&[] as &[&str]).observe(0.1);
            m.dvt.threshold_failures_total.with_label_values(&[] as &[&str]).inc();

            let output = m.encode().unwrap();
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("rvc_signer_dvt_coordination_duration_seconds"));
            assert!(text.contains("rvc_signer_dvt_threshold_failures_total"));
        }
    }
}
