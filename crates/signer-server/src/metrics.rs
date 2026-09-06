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
    /// Web3Signer `PAYLOAD_ATTESTATION` (HTTP-only; domain 0x0C PTC attester).
    /// Not a v2 gRPC RPC, but shares the A7 `sign_*` series when HTTP dispatches.
    pub const PAYLOAD_ATTESTATION: &str = "payload_attestation";

    /// All ten v2 RPC type labels — used by the table-driven recording test.
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
    ];
}

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
            #[cfg(feature = "dvt")]
            dvt,
        }
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

pub async fn serve_metrics(
    addr: SocketAddr,
    metrics: std::sync::Arc<SignerMetrics>,
) -> Result<(JoinHandle<()>, SocketAddr), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    info!(address = %local_addr, "Metrics server listening");

    let handle = tokio::spawn(async move {
        serve_metrics_loop(listener, metrics).await;
    });

    Ok((handle, local_addr))
}

async fn serve_metrics_loop(
    listener: tokio::net::TcpListener,
    metrics: std::sync::Arc<SignerMetrics>,
) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept metrics connection");
                continue;
            }
        };

        let body = match metrics.encode() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode metrics");
                continue;
            }
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
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

        let gathered = m.registry.gather();
        let names: Vec<&str> = gathered.iter().map(|mf| mf.name()).collect();
        assert!(names.contains(&"rvc_signer_sign_total"));
        assert!(names.contains(&"rvc_signer_sign_duration_seconds"));
        assert!(names.contains(&"rvc_signer_sign_errors_total"));
        assert!(names.contains(&"rvc_signer_keys_loaded"));
        assert!(names.contains(&"rvc_signer_http_sign_total"));
        assert!(names.contains(&"rvc_signer_http_sign_duration_seconds"));
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
    fn test_grpc_sign_type_all_has_ten_handlers() {
        assert_eq!(grpc_sign_type::ALL.len(), 10);
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
