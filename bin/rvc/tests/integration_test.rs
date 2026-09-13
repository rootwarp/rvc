//! Integration tests for the validator client startup and shutdown.
//!
//! CLI startup smoke tests run against a local wiremock beacon node (RF5-01)
//! so they are hermetic and do not require network access.
//!
//! Readiness means `/health` returns **HTTP 200** with `healthy: true`
//! (beacon connected + slashing DB + at least one loaded key). A permanent
//! 503 (e.g. empty keystore) is **not** treated as ready.

// RF5-01 / RF1-12: Tests send SIGTERM to child processes via unsafe libc::kill (Unix).
#![allow(unsafe_code)]

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::MockBn;
use crypto::{EncryptionKdf, Keystore, SecretKey};
use eth_types::ForkName;
use tempfile::{NamedTempFile, TempDir};

/// Ordered log markers that define a successful ready path with a loaded key.
///
/// Later bootstrap extractions (RF5-03+) must update this constant deliberately
/// when startup log text changes — do not edit it as incidental cleanup.
///
/// Smoke harness installs a single cheap-scrypt keystore so key load succeeds
/// and `"Loaded validator keys"` is emitted (required for `/health` 200).
const STARTUP_SEQUENCE: &[&str] = &[
    "Starting validator client",
    "Slashing DB integrity check passed",
    "Genesis validators root validated successfully",
    "Loaded validator keys",
    "Starting duty orchestrator",
];

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(35);
const TEST_KEYSTORE_PASSWORD: &str = "rf5-01-smoke-password";

fn get_binary_path() -> std::path::PathBuf {
    // Cargo builds the `rvc` binary as a prerequisite of these integration tests and
    // exposes its path via CARGO_BIN_EXE_<name>, with the same profile/features as the
    // test build. This avoids shelling out to `cargo build` from inside each test, which
    // serialized on cargo's build lock and thrashed the build cache under parallel runners.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rvc"))
}

/// Bind `:0` then release so the OS assigns a free port (parallel-safe).
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

struct TestPorts {
    metrics: u16,
}

impl TestPorts {
    fn allocate() -> Self {
        Self { metrics: free_port() }
    }
}

/// Non-zero fee recipient required by startup validation (zero address is refused).
const TEST_FEE_RECIPIENT: &str = "0x1111111111111111111111111111111111111111";

/// Write a validators TOML with a non-zero default fee recipient.
fn create_validators_config(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("validators.toml");
    std::fs::write(&path, format!("[defaults]\nfee_recipient = \"{TEST_FEE_RECIPIENT}\"\n"))
        .expect("write validators config");
    path
}

/// Install one cheap-scrypt EIP-2335 keystore + wildcard password file.
///
/// Required so `/health` can report `healthy: true` (`validators_loaded > 0`).
fn install_smoke_keystore(keystore_dir: &TempDir) -> PathBuf {
    let sk = SecretKey::generate();
    let path = "m/12381/3600/0/0/0";
    let keystore = Keystore::encrypt(
        &sk,
        TEST_KEYSTORE_PASSWORD.as_bytes(),
        path,
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt smoke keystore");
    keystore.to_file(keystore_dir.path().join("keystore-0.json")).expect("write smoke keystore");

    let password_file = keystore_dir.path().join("passwords.txt");
    std::fs::write(&password_file, format!("*={TEST_KEYSTORE_PASSWORD}\n"))
        .expect("write password file");
    password_file
}

/// Write a minimal config pointing at `beacon_url` with per-test ports.
fn create_test_config(
    keystore_dir: &TempDir,
    slashing_db_path: &Path,
    validators_config: &Path,
    password_file: &Path,
    beacon_url: &str,
    ports: &TestPorts,
) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp config file");
    writeln!(
        file,
        r#"
beacon_url = "{beacon_url}"
keystore_path = "{keystore}"
slashing_db_path = "{slashing}"
validators_config = "{validators}"
password_file = "{password_file}"
metrics_address = "127.0.0.1"
metrics_port = {metrics}
network = "mainnet"
log_level = "info"
keymanager_enabled = false
"#,
        beacon_url = beacon_url,
        keystore = keystore_dir.path().display(),
        slashing = slashing_db_path.display(),
        validators = validators_config.display(),
        password_file = password_file.display(),
        metrics = ports.metrics,
    )
    .unwrap();
    file
}

/// Spawn `rvc start` with `--init-slashing-db` for the fresh-DB SEC-3 path.
///
/// Ports are still passed on the CLI so parallel tests do not collide.
/// After ARCH-4i / ADR-009 a TOML `metrics_port` survives when the flag is
/// absent. Clear `OTEL_*` so ambient collector env stays offline.
fn spawn_validator(config_path: &std::path::Path, ports: &TestPorts) -> Child {
    let binary_path = get_binary_path();

    Command::new(binary_path)
        .args([
            "start",
            "--config",
            config_path.to_str().unwrap(),
            "--init-slashing-db",
            "--metrics-port",
            &ports.metrics.to_string(),
            "--metrics-address",
            "127.0.0.1",
        ])
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_PROTOCOL")
        .env_remove("OTEL_METRICS_EXPORTER")
        .env_remove("OTEL_TRACES_EXPORTER")
        .env_remove("OTEL_TRACES_SAMPLER_ARG")
        // Console fmt layer writes to stdout (see `console_fmt_layer(..., stdout)`).
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn validator process")
}

/// Drain child stdout on a background thread so the process cannot block on a full pipe.
///
/// Console logs go to stdout; stderr is only used for a few `eprintln!` warnings.
struct LogCapture {
    buffer: Arc<Mutex<String>>,
    handle: Option<JoinHandle<()>>,
}

impl LogCapture {
    fn start(stdout: ChildStdout) -> Self {
        let buffer = Arc::new(Mutex::new(String::new()));
        let buf = Arc::clone(&buffer);
        let handle = thread::spawn(move || {
            let mut reader = stdout;
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&chunk[..n]);
                        if let Ok(mut guard) = buf.lock() {
                            guard.push_str(&text);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Self { buffer, handle: Some(handle) }
    }

    fn snapshot(&self) -> String {
        self.buffer.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn finish(&mut self) -> String {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.snapshot()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Poll until `url` returns HTTP 200 (503 / connection errors are not ready).
async fn wait_for_http_ok(url: &str, timeout: Duration) -> bool {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(1)).build().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Assert `/health` body reports fully healthy (production readiness predicate).
async fn assert_health_json_healthy(health_url: &str) {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
    let resp = client.get(health_url).send().await.expect("health request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "ready path must expose /health 200 (not 503); got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("health json");
    assert_eq!(body["healthy"], true, "health.healthy; body={body}");
    assert_eq!(body["beacon_connected"], true, "health.beacon_connected; body={body}");
    assert_eq!(
        body["slashing_db_initialized"], true,
        "health.slashing_db_initialized; body={body}"
    );
    let loaded = body["validators_loaded"].as_u64().unwrap_or(0);
    assert!(loaded >= 1, "health.validators_loaded >= 1; body={body}");
}

fn assert_startup_sequence(logs: &str) {
    let mut search_from = 0usize;
    for (i, marker) in STARTUP_SEQUENCE.iter().enumerate() {
        match logs[search_from..].find(marker) {
            Some(rel) => {
                search_from += rel + marker.len();
            }
            None => {
                panic!(
                    "startup marker[{i}] {marker:?} not found in order after prior markers.\n\
                     searched from offset {search_from}.\n--- stdout ---\n{logs}"
                );
            }
        }
    }
}

#[cfg(unix)]
fn send_sigterm(child: &Child) {
    // SAFETY: child was spawned by this process; pid is live until wait/kill.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("process did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for process: {e}"),
        }
    }
}

/// Shared harness: mock BN + temp dirs + spawned `rvc start`.
struct SmokeHarness {
    _mock_bn: MockBn,
    _keystore_dir: TempDir,
    _slashing_db_dir: TempDir,
    _config_file: NamedTempFile,
    ports: TestPorts,
    child: Child,
    logs: LogCapture,
}

impl SmokeHarness {
    async fn start() -> Self {
        Self::start_with_bn(MockBn::start().await).await
    }

    async fn start_with_bn(mock_bn: MockBn) -> Self {
        let keystore_dir = TempDir::new().expect("keystore dir");
        let password_file = install_smoke_keystore(&keystore_dir);
        let slashing_db_dir = TempDir::new().expect("slashing db dir");
        let slashing_db_path = slashing_db_dir.path().join("slashing.db");
        let validators_config = create_validators_config(&keystore_dir);
        let ports = TestPorts::allocate();
        let config_file = create_test_config(
            &keystore_dir,
            &slashing_db_path,
            &validators_config,
            &password_file,
            &mock_bn.uri(),
            &ports,
        );

        let mut child = spawn_validator(config_file.path(), &ports);
        let stdout = child.stdout.take().expect("stdout piped");
        let logs = LogCapture::start(stdout);

        Self {
            _mock_bn: mock_bn,
            _keystore_dir: keystore_dir,
            _slashing_db_dir: slashing_db_dir,
            _config_file: config_file,
            ports,
            child,
            logs,
        }
    }

    fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.ports.metrics)
    }

    fn metrics_url(&self) -> String {
        format!("http://127.0.0.1:{}/metrics", self.ports.metrics)
    }

    fn readyz_url(&self) -> String {
        format!("http://127.0.0.1:{}/readyz", self.ports.metrics)
    }

    fn livez_url(&self) -> String {
        format!("http://127.0.0.1:{}/livez", self.ports.metrics)
    }

    /// Wait until `/health` is HTTP 200 (healthy=true). 503 is not ready.
    async fn wait_until_ready(&self) {
        let health = self.health_url();
        assert!(
            wait_for_http_ok(&health, READY_TIMEOUT).await,
            "health endpoint not HTTP 200 within {:?}.\n--- stdout ---\n{}",
            READY_TIMEOUT,
            self.logs.snapshot()
        );
        assert_health_json_healthy(&health).await;
    }

    #[cfg(unix)]
    async fn shutdown_cleanly(&mut self) -> (std::process::ExitStatus, String) {
        self.wait_until_ready().await;
        send_sigterm(&self.child);
        let status = wait_for_exit(&mut self.child, SHUTDOWN_TIMEOUT);
        let logs = self.logs.finish();
        (status, logs)
    }

    #[cfg(not(unix))]
    async fn shutdown_cleanly(&mut self) -> (std::process::ExitStatus, String) {
        self.wait_until_ready().await;
        let _ = self.child.kill();
        let status = self.child.wait().expect("wait after kill");
        let logs = self.logs.finish();
        (status, logs)
    }
}

impl Drop for SmokeHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Flag / exit-code CLI cases live in `cli.rs` (RF6-20). This file keeps the
// F1 startup-ready + SIGTERM smoke path against a mock BN.

#[tokio::test(flavor = "multi_thread")]
async fn test_startup_reaches_ready_against_mock_bn() {
    let mut harness = SmokeHarness::start().await;
    harness.wait_until_ready().await;

    // Explicit healthy pin (wait_until_ready already checked; re-assert after).
    assert_health_json_healthy(&harness.health_url()).await;
    assert!(
        wait_for_http_ok(&harness.readyz_url(), Duration::from_secs(2)).await,
        "/readyz must be 200 when healthy"
    );

    let (status, _logs) = harness.shutdown_cleanly().await;
    #[cfg(unix)]
    assert!(status.success(), "expected exit 0 on SIGTERM, got {status}");
    let _ = status;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_startup_reaches_ready_against_gloas_mock_bn() {
    let mock_bn = MockBn::with_fork(ForkName::Gloas).start().await;
    let mut harness = SmokeHarness::start_with_bn(mock_bn).await;
    harness.wait_until_ready().await;
    assert_health_json_healthy(&harness.health_url()).await;

    let (status, logs) = harness.shutdown_cleanly().await;
    assert_startup_sequence(&logs);
    #[cfg(unix)]
    assert!(status.success(), "expected exit 0 on SIGTERM, got {status}\n--- stdout ---\n{logs}");
    let _ = status;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_startup_sequence_markers_in_order() {
    let mut harness = SmokeHarness::start().await;
    let (_status, logs) = harness.shutdown_cleanly().await;
    assert_startup_sequence(&logs);
    // Key-load marker is part of STARTUP_SEQUENCE; pin the loaded count wording too.
    assert!(
        logs.contains("Loaded validator keys") && logs.contains("count=1"),
        "expected one keystore-loaded validator in logs.\n--- stdout ---\n{logs}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_graceful_shutdown_sigterm_exit_code_zero() {
    let mut harness = SmokeHarness::start().await;
    let (status, logs) = harness.shutdown_cleanly().await;

    #[cfg(unix)]
    {
        assert!(
            status.success() || status.code() == Some(0),
            "process should exit cleanly on SIGTERM, got {status}\n--- stdout ---\n{logs}"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (status, logs);
    }
}

/// ARCH-7e: healthz gRPC is gone; leftover bind knobs are rejected, so this
/// only asserts the process never logs a gRPC listener start.
#[tokio::test(flavor = "multi_thread")]
async fn test_no_grpc_listener_on_startup() {
    let mut harness = SmokeHarness::start().await;
    harness.wait_until_ready().await;

    let logs = harness.logs.snapshot();
    assert!(
        !logs.contains("Starting gRPC server"),
        "startup must not bind a gRPC listener.\n--- stdout ---\n{logs}"
    );

    let (status, _logs) = harness.shutdown_cleanly().await;
    #[cfg(unix)]
    assert!(status.success(), "expected exit 0 on SIGTERM, got {status}");
    let _ = status;
}

/// ARCH-7d: metrics `/health` and `/readyz` are the live replacement probes.
#[tokio::test(flavor = "multi_thread")]
async fn test_metrics_server_answers_health_and_readyz() {
    let mut harness = SmokeHarness::start().await;
    harness.wait_until_ready().await;

    assert_health_json_healthy(&harness.health_url()).await;
    assert!(
        wait_for_http_ok(&harness.readyz_url(), Duration::from_secs(2)).await,
        "/readyz must answer HTTP 200 when the process is ready.\n--- stdout ---\n{}",
        harness.logs.snapshot()
    );
    assert!(
        wait_for_http_ok(&harness.livez_url(), Duration::from_secs(2)).await,
        "/livez must answer HTTP 200 (process-up).\n--- stdout ---\n{}",
        harness.logs.snapshot()
    );

    let (status, _logs) = harness.shutdown_cleanly().await;
    #[cfg(unix)]
    assert!(status.success(), "expected exit 0 on SIGTERM, got {status}");
    let _ = status;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_metrics_and_health_endpoints_served() {
    let mut harness = SmokeHarness::start().await;
    harness.wait_until_ready().await;

    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();

    assert_health_json_healthy(&harness.health_url()).await;

    assert!(
        wait_for_http_ok(&harness.metrics_url(), Duration::from_secs(5)).await,
        "metrics not reachable.\n--- stdout ---\n{}",
        harness.logs.snapshot()
    );
    let metrics = client.get(harness.metrics_url()).send().await.expect("metrics");
    assert!(metrics.status().is_success(), "metrics: {}", metrics.status());
    let body = metrics.text().await.unwrap_or_default();
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "metrics body should expose prometheus series, got empty/unexpected"
    );

    let (status, _logs) = harness.shutdown_cleanly().await;
    #[cfg(unix)]
    assert!(status.success(), "expected exit 0, got {status}");
    let _ = status;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_startup_fails_closed_on_genesis_root_mismatch() {
    // Config uses mainnet GVR; mock advertises a different root → fail closed.
    let mock_bn = MockBn::builder()
        .with_genesis_validators_root(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .start()
        .await;

    let keystore_dir = TempDir::new().expect("keystore dir");
    let password_file = install_smoke_keystore(&keystore_dir);
    let slashing_db_dir = TempDir::new().expect("slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");
    let validators_config = create_validators_config(&keystore_dir);
    let ports = TestPorts::allocate();
    let config_file = create_test_config(
        &keystore_dir,
        &slashing_db_path,
        &validators_config,
        &password_file,
        &mock_bn.uri(),
        &ports,
    );

    let mut child = spawn_validator(config_file.path(), &ports);
    let stdout = child.stdout.take().expect("stdout piped");
    let mut capture = LogCapture::start(stdout);

    let status = wait_for_exit(&mut child, READY_TIMEOUT);
    let logs = capture.finish();

    assert!(
        !status.success(),
        "genesis-root mismatch must exit non-zero, got {status}\n--- stdout ---\n{logs}"
    );
    assert!(
        logs.contains("Genesis") || logs.contains("genesis"),
        "expected genesis mismatch diagnostics in logs.\n--- stdout ---\n{logs}"
    );

    // Keep mock alive until child has exited.
    drop(mock_bn);
}

/// SEC-9 / RF5-07: unknown head fork version is fatal by default (MockBn fork APIs).
#[tokio::test(flavor = "multi_thread")]
async fn test_startup_fails_closed_on_unsupported_fork() {
    let mock_bn = MockBn::builder().with_head_fork_version("0xdeadbeef").start().await;

    let keystore_dir = TempDir::new().expect("keystore dir");
    let password_file = install_smoke_keystore(&keystore_dir);
    let slashing_db_dir = TempDir::new().expect("slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");
    let validators_config = create_validators_config(&keystore_dir);
    let ports = TestPorts::allocate();
    let config_file = create_test_config(
        &keystore_dir,
        &slashing_db_path,
        &validators_config,
        &password_file,
        &mock_bn.uri(),
        &ports,
    );

    let mut child = spawn_validator(config_file.path(), &ports);
    let stdout = child.stdout.take().expect("stdout piped");
    let mut capture = LogCapture::start(stdout);

    let status = wait_for_exit(&mut child, READY_TIMEOUT);
    let logs = capture.finish();

    assert!(
        !status.success(),
        "unsupported fork must exit non-zero, got {status}\n--- stdout ---\n{logs}"
    );
    assert_eq!(
        status.code(),
        Some(13),
        "unsupported fork must exit 13, got {status}\n--- stdout ---\n{logs}"
    );
    assert!(
        logs.contains("Fork compatibility")
            || logs.contains("unsupported")
            || logs.contains("fork"),
        "expected fork-compat diagnostics in logs.\n--- stdout ---\n{logs}"
    );

    drop(mock_bn);
}
