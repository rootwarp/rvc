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
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
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
/// First process plus respawns. The last attempt is not respawned.
const READY_ATTEMPTS: u32 = 5;

/// Exit 15 before the orchestrator log is the only startup failure that is retried.
fn is_port_bind_race(code: Option<i32>, saw_orchestrator: bool) -> bool {
    !saw_orchestrator && code == Some(rvc::startup::EXIT_LISTENER_BIND)
}

fn child_status(child: &mut Child) -> Option<ExitStatus> {
    match child.try_wait() {
        Ok(status) => status,
        Err(err) => panic!("error waiting for process: {err}"),
    }
}

#[test]
fn non_bind_exit_is_not_retried() {
    let exit = |code: i32| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("exit {code}"))
            .status()
            .expect("spawn sh")
            .code()
    };
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    assert!(is_port_bind_race(exit(bind), false), "exit {bind} before the log is a port race");
    assert!(!is_port_bind_race(exit(bind), true), "exit {bind} after the log is not retried");
    assert!(!is_port_bind_race(exit(1), false), "exit 1 is not retried");
    assert!(!is_port_bind_race(exit(0), false), "exit 0 is not retried");
    let signal =
        std::process::Command::new("sh").arg("-c").arg("kill -TERM $$").status().expect("spawn sh");
    assert!(signal.code().is_none(), "signal death has no code, got {signal}");
    assert!(!is_port_bind_race(signal.code(), false), "signal death is not retried");
}

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
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn validator process")
}

/// Drain child stdout and stderr so the process cannot block on a full pipe.
///
/// The orchestrator flag is set only from stdout. Stderr is appended so a
/// failed attempt's panic includes both streams.
struct LogCapture {
    buffer: Arc<Mutex<String>>,
    handles: Vec<JoinHandle<()>>,
    orchestrator: Arc<(Mutex<bool>, Condvar)>,
}

fn spawn_log_reader(
    mut reader: impl Read + Send + 'static,
    buf: Arc<Mutex<String>>,
    orchestrator: Option<Arc<(Mutex<bool>, Condvar)>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk[..n]);
                    let mut saw = false;
                    if let Ok(mut guard) = buf.lock() {
                        guard.push_str(&text);
                        saw =
                            orchestrator.is_some() && guard.contains("Starting duty orchestrator");
                    }
                    if let Some(ready) = orchestrator.as_ref().filter(|_| saw) {
                        let (lock, cv) = &**ready;
                        if let Ok(mut flag) = lock.lock() {
                            *flag = true;
                            cv.notify_all();
                        }
                    }
                }
                Err(_) => break,
            }
        }
    })
}

impl LogCapture {
    fn start(stdout: ChildStdout, stderr: ChildStderr) -> Self {
        let buffer = Arc::new(Mutex::new(String::new()));
        let orchestrator = Arc::new((Mutex::new(false), Condvar::new()));
        let handles = vec![
            spawn_log_reader(stdout, Arc::clone(&buffer), Some(Arc::clone(&orchestrator))),
            spawn_log_reader(stderr, Arc::clone(&buffer), None),
        ];
        Self { buffer, handles, orchestrator }
    }

    fn saw_orchestrator(&self) -> bool {
        let (lock, _) = &*self.orchestrator;
        *lock.lock().expect("orchestrator log")
    }

    fn wait_for_orchestrator(&self, timeout: Duration) -> bool {
        let (lock, cv) = &*self.orchestrator;
        let guard = lock.lock().expect("orchestrator log");
        let (guard, _) =
            cv.wait_timeout_while(guard, timeout, |flag| !*flag).expect("orchestrator log");
        *guard
    }

    fn snapshot(&self) -> String {
        self.buffer.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn finish(&mut self) -> String {
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
        self.snapshot()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
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
    beacon_url: String,
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
        let stderr = child.stderr.take().expect("stderr piped");
        let logs = LogCapture::start(stdout, stderr);

        Self {
            beacon_url: mock_bn.uri(),
            _mock_bn: mock_bn,
            _keystore_dir: keystore_dir,
            _slashing_db_dir: slashing_db_dir,
            _config_file: config_file,
            ports,
            child,
            logs,
        }
    }

    fn respawn(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.logs.finish();
        self.ports = TestPorts::allocate();
        let slashing = self._slashing_db_dir.path().join("slashing.db");
        let _ = std::fs::remove_file(&slashing);
        let _ = std::fs::remove_file(self._slashing_db_dir.path().join("slashing.db-wal"));
        let _ = std::fs::remove_file(self._slashing_db_dir.path().join("slashing.db-shm"));
        let config_file = create_test_config(
            &self._keystore_dir,
            &slashing,
            &self._keystore_dir.path().join("validators.toml"),
            &self._keystore_dir.path().join("passwords.txt"),
            &self.beacon_url,
            &self.ports,
        );
        let mut child = spawn_validator(config_file.path(), &self.ports);
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");
        self.logs = LogCapture::start(stdout, stderr);
        self._config_file = config_file;
        self.child = child;
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

    /// Wait until `/health` is HTTP 200 on this child, after the orchestrator starts.
    ///
    /// A 200 from a process that already exited is another test's listener
    /// (`free_port` releases the port before the child binds). Respawn only
    /// when this child exited [`rvc::startup::EXIT_LISTENER_BIND`] before the
    /// orchestrator log. Any other exit panics with the status and the log.
    async fn wait_until_ready(&mut self) {
        for attempt in 1..=READY_ATTEMPTS {
            if self.retry_port_bind_race(attempt) {
                continue;
            }
            let health = self.health_url();
            let healthy = wait_for_http_ok(&health, READY_TIMEOUT).await;
            if self.retry_port_bind_race(attempt) {
                continue;
            }
            assert!(
                healthy,
                "health endpoint not HTTP 200 within {:?}.\n--- log ---\n{}",
                READY_TIMEOUT,
                self.logs.snapshot()
            );
            let saw = self.logs.wait_for_orchestrator(READY_TIMEOUT);
            if self.retry_port_bind_race(attempt) {
                continue;
            }
            if saw {
                assert_health_json_healthy(&self.health_url()).await;
                return;
            }
        }
        panic!(
            "duty orchestrator did not start within {READY_ATTEMPTS} attempts.\n--- log ---\n{}",
            self.logs.snapshot()
        );
    }

    /// Respawn after exit 15 before the orchestrator log. Every other exit panics.
    fn retry_port_bind_race(&mut self, attempt: u32) -> bool {
        let Some(status) = child_status(&mut self.child) else {
            return false;
        };
        let saw = self.logs.saw_orchestrator();
        let logs = self.logs.snapshot();
        if is_port_bind_race(status.code(), saw) && attempt < READY_ATTEMPTS {
            self.respawn();
            return true;
        }
        panic!(
            "startup exited {status} on attempt {attempt}/{READY_ATTEMPTS} \
             (orchestrator log seen: {saw}); respawn is only for exit {} before that log\n\
             --- log ---\n{logs}",
            rvc::startup::EXIT_LISTENER_BIND,
        );
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
    let stderr = child.stderr.take().expect("stderr piped");
    let mut capture = LogCapture::start(stdout, stderr);

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
    let stderr = child.stderr.take().expect("stderr piped");
    let mut capture = LogCapture::start(stdout, stderr);

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
