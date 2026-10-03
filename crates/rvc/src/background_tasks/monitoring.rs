use std::time::Duration;

use beacon::RetryPolicy;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn, Instrument};

/// beaconcha.in monitoring API v1 payload for the validator process.
#[derive(Debug, Clone, Serialize)]
pub struct MonitoringPayload {
    pub version: u32,
    pub timestamp: u64,
    pub process: String,
    pub cpu_process_seconds_total: u64,
    pub memory_process_bytes: u64,
    pub client_name: String,
    pub client_version: String,
    pub client_build: u32,
    pub sync_eth2_fallback_configured: bool,
    pub sync_eth2_fallback_connected: bool,
    pub validator_total: u32,
    pub validator_active: u32,
}

/// Collects current process metrics into a `MonitoringPayload`.
///
/// `validator_total` and `validator_active` are provided by the caller
/// (typically live `PubkeyMap` size and enabled `ValidatorStore` count).
/// CPU and memory are read from the current process.
pub fn collect_metrics(validator_total: u32, validator_active: u32) -> MonitoringPayload {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let (cpu_seconds, memory_bytes) = read_process_metrics();

    MonitoringPayload {
        version: 1,
        timestamp,
        process: "validator".to_string(),
        cpu_process_seconds_total: cpu_seconds,
        memory_process_bytes: memory_bytes,
        client_name: "rvc".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        client_build: 0,
        sync_eth2_fallback_configured: false,
        sync_eth2_fallback_connected: false,
        validator_total,
        validator_active,
    }
}

/// Reads CPU seconds and RSS memory from the current process.
///
/// On macOS, uses `proc_pidinfo`. On Linux, reads `/proc/self/stat`.
/// Returns (0, 0) if metrics cannot be read.
fn read_process_metrics() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        read_process_metrics_linux()
    }
    #[cfg(target_os = "macos")]
    {
        read_process_metrics_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

// RF1-12: pre-existing production libc (sysconf). Function-scoped allow — not crate-level.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn read_process_metrics_linux() -> (u64, u64) {
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 24 {
        return (0, 0);
    }
    // Field 13 = utime (user ticks), Field 14 = stime (kernel ticks)
    let utime: u64 = fields[13].parse().unwrap_or(0);
    let stime: u64 = fields[14].parse().unwrap_or(0);
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    let cpu_seconds = (utime + stime).checked_div(ticks_per_sec).unwrap_or(0);

    // Field 23 = rss (pages)
    let rss_pages: u64 = fields[23].parse().unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let memory_bytes = rss_pages * page_size;

    (cpu_seconds, memory_bytes)
}

// RF1-12: pre-existing production libc (getrusage/zeroed). Function-scoped allow — not crate-level.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn read_process_metrics_macos() -> (u64, u64) {
    use std::mem;

    let pid = std::process::id() as i32;

    // Get rusage for CPU time
    let mut usage: libc::rusage = unsafe { mem::zeroed() };
    let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let cpu_seconds =
        if ret == 0 { (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as u64 } else { 0 };

    // Get memory via task_info or rusage maxrss
    // On macOS, ru_maxrss is in bytes
    let memory_bytes = if ret == 0 { usage.ru_maxrss as u64 } else { 0 };
    let _ = pid; // suppress unused warning

    (cpu_seconds, memory_bytes)
}

/// Configuration for the monitoring push task.
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub endpoint: String,
    pub interval: Duration,
    pub insecure: bool,
}

/// Starts the background monitoring push task.
///
/// POSTs `MonitoringPayload` to the configured endpoint at the given interval.
/// Retries up to 3 times with exponential backoff on transient failures.
/// Failures are logged at WARN level and do not affect validator operation.
pub async fn start_monitoring_push(
    config: MonitoringConfig,
    shutdown: CancellationToken,
    validator_count_fn: impl Fn() -> (u32, u32) + Send + 'static,
) {
    if !config.insecure && !config.endpoint.starts_with("https://") {
        warn!(
            endpoint = %config.endpoint,
            "Monitoring endpoint requires HTTPS. Use --monitoring-endpoint-insecure to allow HTTP."
        );
        return;
    }

    let client = match reqwest::Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create HTTP client for monitoring");
            return;
        }
    };

    let mut interval = tokio::time::interval(config.interval);
    // Skip the immediate first tick
    interval.tick().await;

    // detached: process-lifetime loop root; the tick is the exported span.
    let loop_span = tracing::info_span!(parent: None, "monitoring_push");
    loop {
        let tick = tracing::info_span!(parent: None, "monitoring_push.tick");
        tick.follows_from(&loop_span);
        let stop = async {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("Monitoring push task shutting down");
                    true
                }
                _ = interval.tick() => {
                    let (total, active) = validator_count_fn();
                    let payload = collect_metrics(total, active);
                    push_with_retry(&client, &config.endpoint, &payload).await;
                    false
                }
            }
        }
        .instrument(tick)
        .await;
        if stop {
            return;
        }
    }
}

/// Total push attempts (first try + retries). Preserves the historical 3-attempt budget.
const MAX_ATTEMPTS: u32 = 3;

async fn push_with_retry(client: &reqwest::Client, endpoint: &str, payload: &MonitoringPayload) {
    // Share beacon's backoff / Retry-After policy (F108). Attempt budget stays at
    // MAX_ATTEMPTS total (not `0..=max_retries`) so existing 4xx/5xx expectations hold.
    let policy = RetryPolicy::default();

    for attempt in 0..MAX_ATTEMPTS {
        match client.post(endpoint).json(payload).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("Monitoring metrics pushed successfully");
                    metrics::definitions::RVC_MONITORING_PUSH_SUCCESS_TOTAL.inc();
                    return;
                }

                let status = response.status();

                // 429: honour Retry-After via the shared policy, then retry.
                if status.as_u16() == 429 {
                    warn!(
                        status = %status,
                        attempt = attempt + 1,
                        "Monitoring push rate-limited (429), retrying"
                    );
                    if attempt < MAX_ATTEMPTS - 1 {
                        let delay = RetryPolicy::retry_after_delay(
                            &response,
                            policy.calculate_backoff(attempt),
                        );
                        tokio::time::sleep(delay).await;
                    }
                    continue;
                }

                if status.is_client_error() {
                    // Other 4xx — not transient, don't retry
                    warn!(status = %status, "Monitoring push rejected (client error), not retrying");
                    metrics::definitions::RVC_MONITORING_PUSH_FAILURES_TOTAL.inc();
                    return;
                }

                // 5xx — transient, retry with shared exponential backoff
                warn!(
                    status = %status,
                    attempt = attempt + 1,
                    "Monitoring push failed (server error), retrying"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    attempt = attempt + 1,
                    "Monitoring push request failed, retrying"
                );
            }
        }

        if attempt < MAX_ATTEMPTS - 1 {
            tokio::time::sleep(policy.calculate_backoff(attempt)).await;
        }
    }

    warn!("Monitoring push failed after {MAX_ATTEMPTS} attempts");
    metrics::definitions::RVC_MONITORING_PUSH_FAILURES_TOTAL.inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_payload_serialization() {
        let payload = MonitoringPayload {
            version: 1,
            timestamp: 1704067200000,
            process: "validator".to_string(),
            cpu_process_seconds_total: 1234,
            memory_process_bytes: 654321,
            client_name: "rvc".to_string(),
            client_version: "0.1.0".to_string(),
            client_build: 0,
            sync_eth2_fallback_configured: false,
            sync_eth2_fallback_connected: false,
            validator_total: 3,
            validator_active: 2,
        };

        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["process"], "validator");
        assert_eq!(json["client_name"], "rvc");
        assert_eq!(json["validator_total"], 3);
        assert_eq!(json["validator_active"], 2);
        assert_eq!(json["timestamp"], 1704067200000u64);
        assert_eq!(json["cpu_process_seconds_total"], 1234);
        assert_eq!(json["memory_process_bytes"], 654321);
        assert_eq!(json["sync_eth2_fallback_configured"], false);
        assert_eq!(json["sync_eth2_fallback_connected"], false);
    }

    #[test]
    fn test_collect_metrics_returns_valid_payload() {
        let payload = collect_metrics(10, 8);

        assert_eq!(payload.version, 1);
        assert_eq!(payload.process, "validator");
        assert_eq!(payload.client_name, "rvc");
        assert_eq!(payload.validator_total, 10);
        assert_eq!(payload.validator_active, 8);
        assert!(payload.timestamp > 0);
    }

    #[test]
    fn test_collect_metrics_zero_validators() {
        let payload = collect_metrics(0, 0);

        assert_eq!(payload.validator_total, 0);
        assert_eq!(payload.validator_active, 0);
    }

    #[test]
    fn test_read_process_metrics_does_not_panic() {
        let (cpu, mem) = read_process_metrics();
        // Just ensure no panics; values are platform-dependent
        let _ = (cpu, mem);
    }

    #[tokio::test]
    async fn test_monitoring_push_rejects_http_without_insecure() {
        let config = MonitoringConfig {
            endpoint: "http://example.com/api/v1/metrics".to_string(),
            interval: Duration::from_secs(1),
            insecure: false,
        };
        let shutdown = CancellationToken::new();
        shutdown.cancel(); // immediate shutdown

        // Should return immediately because HTTP is rejected without insecure
        start_monitoring_push(config, shutdown, || (0, 0)).await;
    }

    #[tokio::test]
    async fn test_push_with_retry_4xx_no_retry() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1) // Should only be called once (no retry for 4xx)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let payload = collect_metrics(1, 1);

        push_with_retry(&client, &mock_server.uri(), &payload).await;
    }

    #[tokio::test]
    async fn test_push_with_retry_success() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let payload = collect_metrics(5, 3);

        push_with_retry(&client, &mock_server.uri(), &payload).await;
    }

    #[tokio::test]
    async fn test_push_with_retry_5xx_retries() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Return 500 three times → all retries exhausted
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(3)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let payload = collect_metrics(1, 1);

        push_with_retry(&client, &mock_server.uri(), &payload).await;
    }

    #[test]
    fn test_monitoring_push_uses_shared_backoff_policy() {
        // Monitoring shares beacon::RetryPolicy for delay calculation (F108).
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.initial_backoff, Duration::from_millis(100));

        let b0 = policy.calculate_backoff(0).as_millis() as u64;
        assert!((75..=125).contains(&b0), "shared policy attempt-0 backoff {b0}ms not in [75,125]");
        let b1 = policy.calculate_backoff(1).as_millis() as u64;
        assert!(
            (150..=250).contains(&b1),
            "shared policy attempt-1 backoff {b1}ms not in [150,250]"
        );

        // 4xx (other than 429) remains non-retryable via is_retryable_status.
        assert!(!RetryPolicy::is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(RetryPolicy::is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(RetryPolicy::is_retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[tokio::test]
    async fn test_push_with_retry_429_uses_shared_retry_after() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // First call 429 with Retry-After: 0 (no real wait), then success.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let payload = collect_metrics(1, 1);
        push_with_retry(&client, &mock_server.uri(), &payload).await;
    }

    #[tokio::test]
    async fn test_start_monitoring_push_clean_shutdown() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            start_monitoring_push(config, shutdown_clone, || (2, 1)).await;
        });

        // Let it run a couple of ticks
        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }
}
