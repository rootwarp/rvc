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
use std::sync::{Arc, Barrier, Condvar, Mutex};
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
    ORCHESTRATOR_MARKER,
];

/// Startup log line that ends the ready path. Matched on stdout only.
const ORCHESTRATOR_MARKER: &str = "Starting duty orchestrator";

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

#[derive(Debug, PartialEq, Eq)]
enum ExitAction {
    Respawn,
    Fail,
}

/// Classify an exited child once its log readers have drained.
///
/// The readers are joined first, so the marker check sees every byte the
/// child wrote before it exited.
fn classify_exit(code: Option<i32>, logs: &mut LogCapture) -> ExitAction {
    logs.drain();
    if is_port_bind_race(code, logs.saw_orchestrator()) {
        ExitAction::Respawn
    } else {
        ExitAction::Fail
    }
}

/// Return only when `status` is a port-bind race and `attempt` is not the
/// last one. Every other exit panics with the drained log.
fn expect_respawn(status: ExitStatus, attempt: u32, logs: &mut LogCapture) {
    match classify_exit(status.code(), logs) {
        ExitAction::Respawn if attempt < READY_ATTEMPTS => {}
        action => panic!(
            "startup exited {status} on attempt {attempt}/{READY_ATTEMPTS} ({action:?}, \
             orchestrator log seen: {}); respawn is only for exit {} before that log\n\
             --- log ---\n{}",
            logs.saw_orchestrator(),
            rvc::startup::EXIT_LISTENER_BIND,
            logs.snapshot(),
        ),
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
/// The orchestrator flag is set only from stdout: the stdout reader matches
/// the marker on its own text. Both streams append to `buffer`, so a failed
/// attempt's panic includes both.
struct LogCapture {
    buffer: Arc<Mutex<String>>,
    handles: Vec<JoinHandle<()>>,
    readers: Arc<(Mutex<ReaderState>, Condvar)>,
    /// Held by the stdout reader until [`Self::drain`] waits on it too.
    gate: Option<Arc<Barrier>>,
}

struct ReaderState {
    orchestrator: bool,
    open_streams: usize,
    /// Times a [`LogCapture::wait_for_orchestrator`] caller went to sleep. It
    /// rises under the lock just before the caller sleeps, so a test that
    /// reads a non-zero count knows only a notify can wake that caller.
    parked: usize,
}

/// How [`LogCapture::wait_for_orchestrator`] ended.
#[derive(Debug, PartialEq, Eq)]
enum ReadyWait {
    Ready,
    /// Every stream reached EOF without the marker: the child is exiting.
    StreamsClosed,
    TimedOut,
}

fn spawn_log_reader(
    mut reader: impl Read + Send + 'static,
    buffer: Arc<Mutex<String>>,
    readers: Arc<(Mutex<ReaderState>, Condvar)>,
    match_marker: bool,
    gate: Option<Arc<Barrier>>,
) -> JoinHandle<()> {
    let update = move |change: fn(&mut ReaderState)| {
        let (lock, cv) = &*readers;
        if let Ok(mut state) = lock.lock() {
            change(&mut state);
            cv.notify_all();
        }
    };
    thread::spawn(move || {
        if let Some(gate) = gate {
            gate.wait();
        }
        let mut own = String::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk[..n]);
                    if let Ok(mut all) = buffer.lock() {
                        all.push_str(&text);
                    }
                    if match_marker {
                        own.push_str(&text);
                        if own.contains(ORCHESTRATOR_MARKER) {
                            update(|state| state.orchestrator = true);
                        }
                    }
                }
            }
        }
        update(|state| state.open_streams -= 1);
    })
}

impl LogCapture {
    fn start(stdout: ChildStdout, stderr: ChildStderr) -> Self {
        Self::start_from(stdout, stderr, None)
    }

    /// `gate` holds the stdout reader before its first read until this
    /// capture drains, so a test can observe an exit before the marker.
    fn start_from(
        stdout: impl Read + Send + 'static,
        stderr: impl Read + Send + 'static,
        gate: Option<Arc<Barrier>>,
    ) -> Self {
        let buffer = Arc::new(Mutex::new(String::new()));
        let readers = Arc::new((
            Mutex::new(ReaderState { orchestrator: false, open_streams: 2, parked: 0 }),
            Condvar::new(),
        ));
        let handles = vec![
            spawn_log_reader(stdout, Arc::clone(&buffer), Arc::clone(&readers), true, gate.clone()),
            spawn_log_reader(stderr, Arc::clone(&buffer), Arc::clone(&readers), false, None),
        ];
        Self { buffer, handles, readers, gate }
    }

    fn saw_orchestrator(&self) -> bool {
        let (lock, _) = &*self.readers;
        lock.lock().expect("log readers").orchestrator
    }

    /// Wait for the marker. Returns at once when every stream closes first.
    fn wait_for_orchestrator(&self, timeout: Duration) -> ReadyWait {
        let (lock, cv) = &*self.readers;
        let guard = lock.lock().expect("log readers");
        let (state, _) = cv
            .wait_timeout_while(guard, timeout, |state| {
                let sleeps = !state.orchestrator && state.open_streams > 0;
                state.parked += usize::from(sleeps);
                sleeps
            })
            .expect("log readers");
        if state.orchestrator {
            ReadyWait::Ready
        } else if state.open_streams == 0 {
            ReadyWait::StreamsClosed
        } else {
            ReadyWait::TimedOut
        }
    }

    fn snapshot(&self) -> String {
        self.buffer.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Release a gated reader, then join every reader.
    fn drain(&mut self) {
        if let Some(gate) = self.gate.take() {
            gate.wait();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }

    fn finish(&mut self) -> String {
        self.drain();
        self.snapshot()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        self.drain();
    }
}

// ── Harness tests on fake children ──────────────────────────────────────
// The child's stdin pipe and the gate order each step. The hang guards only
// turn a hang into a failure; no test asserts on elapsed time.

#[cfg(unix)]
const HANG_GUARD: Duration = Duration::from_secs(60);

#[cfg(unix)]
fn fake_child(script: &str) -> Child {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh")
}

#[cfg(unix)]
fn capture(child: &mut Child, gate: Option<Arc<Barrier>>) -> LogCapture {
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    LogCapture::start_from(stdout, stderr, gate)
}

/// Take stdin after the capture: a failed assertion then drops (closes) it
/// first, so the child exits and the capture's join does not hang.
#[cfg(unix)]
fn stdin_of(child: &mut Child) -> std::process::ChildStdin {
    child.stdin.take().expect("stdin piped")
}

#[cfg(unix)]
fn release(stdin: &mut std::process::ChildStdin) {
    stdin.write_all(b"go\n").expect("release the child");
}

#[cfg(unix)]
fn poll_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + HANG_GUARD;
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "{what} not seen within {HANG_GUARD:?}");
        thread::yield_now();
    }
}

#[cfg(unix)]
fn on_thread<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> std::sync::mpsc::Receiver<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx
}

#[cfg(unix)]
fn hang_guarded<T>(what: &str, result: std::sync::mpsc::Receiver<T>) -> T {
    match result.recv_timeout(HANG_GUARD) {
        Ok(value) => value,
        Err(err) => panic!("{what} did not return: {err}"),
    }
}

#[cfg(unix)]
fn within_hang_guard<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    hang_guarded(what, on_thread(f))
}

/// See [`ReaderState::parked`].
#[cfg(unix)]
fn parked(readers: &(Mutex<ReaderState>, Condvar)) -> usize {
    readers.0.lock().expect("log readers").parked
}

#[cfg(unix)]
#[test]
fn log_capture_ignores_the_marker_on_stderr() {
    let mut child = fake_child(&format!("echo '{ORCHESTRATOR_MARKER}' >&2; read line; echo x"));
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut logs = LogCapture::start(stdout, stderr);
    let mut stdin = stdin_of(&mut child);
    poll_until("the stderr marker", || logs.snapshot().contains(ORCHESTRATOR_MARKER));
    release(&mut stdin);
    assert!(child.wait().expect("wait").success());
    let log = logs.finish();
    assert!(
        log.lines().any(|line| line == "x"),
        "stdout must be read after the marker; log:\n{log}"
    );
    assert!(!logs.saw_orchestrator(), "a marker on stderr must not set the flag; log:\n{log}");
}

#[cfg(unix)]
#[test]
fn log_capture_sees_a_marker_split_across_reads() {
    let (head, tail) = ORCHESTRATOR_MARKER.split_at(8);
    let mut child = fake_child(&format!("printf '%s' '{head}'; read line; echo '{tail}'"));
    let mut logs = capture(&mut child, None);
    let mut stdin = stdin_of(&mut child);
    poll_until("the first half of the marker", || logs.snapshot().contains(head));
    assert_eq!(logs.wait_for_orchestrator(Duration::ZERO), ReadyWait::TimedOut);
    release(&mut stdin);
    assert_eq!(logs.wait_for_orchestrator(HANG_GUARD), ReadyWait::Ready);
    assert!(child.wait().expect("wait").success());
    assert!(logs.saw_orchestrator(), "log:\n{}", logs.finish());
}

#[cfg(unix)]
#[test]
fn wait_for_orchestrator_returns_when_the_child_exits_before_the_marker() {
    let mut child = fake_child("read line; exit 0");
    let logs = capture(&mut child, None);
    let readers = Arc::clone(&logs.readers);
    let stdin = stdin_of(&mut child);
    let wait = on_thread(move || logs.wait_for_orchestrator(Duration::from_secs(3600)));
    // The child holds both pipes open until its stdin closes, so the EOFs
    // arrive while the waiter sleeps and only their notify can wake it.
    poll_until("wait_for_orchestrator to park", || parked(&readers) > 0);
    drop(stdin);
    assert_eq!(
        hang_guarded("wait_for_orchestrator after the child exited", wait),
        ReadyWait::StreamsClosed
    );
    assert!(child.wait().expect("wait").success());
}

#[cfg(unix)]
#[test]
fn retry_classifies_after_the_log_readers_drain() {
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    let mut child = fake_child(&format!("echo '{ORCHESTRATOR_MARKER}'; exit {bind}"));
    let mut logs = capture(&mut child, Some(Arc::new(Barrier::new(2))));
    let status = child.wait().expect("wait");
    assert_eq!(child_status(&mut child), Some(status));
    assert_eq!(status.code(), Some(bind));
    assert!(!logs.saw_orchestrator(), "the gate holds the stdout reader past the exit");
    let (action, saw) = within_hang_guard("classify_exit", move || {
        let action = classify_exit(status.code(), &mut logs);
        (action, logs.saw_orchestrator())
    });
    assert!(saw, "the drain must read the marker written before exit {bind}");
    assert_eq!(action, ExitAction::Fail, "exit {bind} after the marker is not a bind race");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exit_1_is_not_respawned() {
    let mut child = fake_child("exit 1");
    let mut logs = capture(&mut child, None);
    let status = child.wait().expect("wait");
    assert_eq!(classify_exit(status.code(), &mut logs), ExitAction::Fail);

    let mut harness =
        SmokeHarness::start_with(MockBn::start().await, None, |_, _| fake_child("exit 1"));
    let fake = harness.child.id();
    assert_eq!(harness.child.wait().expect("wait").code(), Some(1));
    let attempt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.retry_port_bind_race(1)));
    assert!(attempt.is_err(), "exit 1 must fail the attempt");
    assert_eq!(harness.child.id(), fake, "exit 1 must not respawn the child");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exit_15_before_the_marker_respawns_the_child() {
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    let mut harness = SmokeHarness::start_with(MockBn::start().await, None, move |_, _| {
        fake_child(&format!("echo 'Binding listeners'; exit {bind}"))
    });
    let fake = harness.child.id();
    assert_eq!(harness.child.wait().expect("wait").code(), Some(bind));
    assert!(harness.retry_port_bind_race(1), "exit {bind} before the marker is retried");
    assert_ne!(harness.child.id(), fake, "the bind race must respawn the child");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn retry_port_bind_race_drains_before_it_classifies() {
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    let gate = Some(Arc::new(Barrier::new(2)));
    let mut harness = SmokeHarness::start_with(MockBn::start().await, gate, move |_, _| {
        fake_child(&format!("echo '{ORCHESTRATOR_MARKER}'; exit {bind}"))
    });
    let fake = harness.child.id();
    assert_eq!(harness.child.wait().expect("wait").code(), Some(bind));
    assert!(!harness.logs.saw_orchestrator(), "the gate holds the stdout reader past the exit");
    let attempt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.retry_port_bind_race(1)));
    assert!(attempt.is_err(), "exit {bind} after the marker must fail the attempt");
    assert!(harness.logs.saw_orchestrator(), "the drain must read the marker");
    assert_eq!(harness.child.id(), fake, "exit {bind} after the marker must not respawn");
}

#[cfg(unix)]
#[test]
fn classify_exit_retries_exit_15_before_the_marker() {
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    let mut child = fake_child(&format!("echo 'Binding listeners'; exit {bind}"));
    let mut logs = capture(&mut child, None);
    let status = child.wait().expect("wait");
    assert_eq!(classify_exit(status.code(), &mut logs), ExitAction::Respawn);
    expect_respawn(status, 1, &mut logs);
    let last = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        expect_respawn(status, READY_ATTEMPTS, &mut logs)
    }));
    assert!(last.is_err(), "the last attempt is not respawned");
}

// ── `wait_until_ready` when the streams close before the marker ─────────
// A stand-in answers `/health` 200, so attempt 1 reaches the orchestrator wait
// while the fake child still runs.

#[cfg(unix)]
async fn fake_start(script: &str) -> (SmokeHarness, wiremock::MockServer) {
    let health = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::path("/health"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&health)
        .await;
    let script = script.to_owned();
    let mut harness =
        SmokeHarness::start_with(MockBn::start().await, None, move |_, _| fake_child(&script));
    harness.ports = TestPorts { metrics: health.address().port() };
    (harness, health)
}

/// Close the first child's stdin once `wait_until_ready` sleeps in the
/// orchestrator wait, which comes after both of attempt 1's exit checks.
#[cfg(unix)]
fn release_when_parked(harness: &mut SmokeHarness) -> JoinHandle<()> {
    let stdin = stdin_of(&mut harness.child);
    let readers = Arc::clone(&harness.logs.readers);
    thread::spawn(move || {
        poll_until("wait_for_orchestrator to park", || parked(&readers) > 0);
        drop(stdin);
    })
}

/// `wait_until_ready` to its end; `Err` carries its panic message.
#[cfg(unix)]
fn ready_or_panic(harness: &mut SmokeHarness) -> Result<(), String> {
    tokio::task::block_in_place(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::runtime::Handle::current().block_on(harness.wait_until_ready())
        }))
    })
    .map_err(|panic| match panic.downcast::<String>() {
        Ok(message) => *message,
        Err(panic) => panic.downcast_ref::<&str>().map(|s| s.to_string()).unwrap_or_default(),
    })
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn streams_closed_then_exit_15_respawns_the_child() {
    let bind = rvc::startup::EXIT_LISTENER_BIND;
    let (mut harness, _health) = fake_start(&format!("read line; exit {bind}")).await;
    let fake = harness.child.id();
    let release = release_when_parked(&mut harness);
    let ready = ready_or_panic(&mut harness);
    release.join().expect("the child is released from the orchestrator wait");
    if let Err(panic) = ready {
        panic!("exit {bind} after the streams closed must respawn: {panic}");
    }
    assert_ne!(harness.child.id(), fake, "the bind race must respawn the child");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn streams_closed_then_exit_1_fails_without_a_respawn() {
    let (mut harness, _health) = fake_start("read line; exit 1").await;
    let fake = harness.child.id();
    let release = release_when_parked(&mut harness);
    let ready = ready_or_panic(&mut harness);
    release.join().expect("the child is released from the orchestrator wait");
    let panic = ready.expect_err("exit 1 after the streams closed must fail the attempt");
    assert!(panic.contains("startup exited exit status: 1 on attempt 1/"), "{panic}");
    assert_eq!(harness.child.id(), fake, "exit 1 must not respawn the child");
}

/// The child closes its streams and never exits, so only the reap bound ends
/// the attempt (about `SHUTDOWN_TIMEOUT`).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn streams_closed_waits_for_the_exit_before_another_attempt() {
    use std::os::unix::process::ExitStatusExt;
    let (mut harness, _health) = fake_start("exec >&- 2>&-; read line").await;
    let fake = harness.child.id();
    let panic = ready_or_panic(&mut harness).expect_err("a child that never exits fails");
    assert!(
        panic.contains(&format!("process did not exit within {SHUTDOWN_TIMEOUT:?}")),
        "closed streams must be followed by a wait for the exit: {panic}"
    );
    assert_eq!(harness.child.id(), fake, "no respawn without an exit status");
    let status = harness.child.try_wait().expect("try_wait").expect("reaped after the kill");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the reap bound kills the child");
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
        Self::start_with(mock_bn, None, spawn_validator)
    }

    /// `spawn` starts the first child; respawns always run `rvc start`.
    /// `gate` holds the first child's stdout reader until its log drains.
    fn start_with(
        mock_bn: MockBn,
        gate: Option<Arc<Barrier>>,
        spawn: impl FnOnce(&Path, &TestPorts) -> Child,
    ) -> Self {
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

        let mut child = spawn(config_file.path(), &ports);
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");
        let logs = LogCapture::start_from(stdout, stderr, gate);

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
            let wait = self.logs.wait_for_orchestrator(READY_TIMEOUT);
            if wait == ReadyWait::StreamsClosed {
                // Both pipes closed before the marker, so the child is exiting.
                let status = wait_for_exit(&mut self.child, SHUTDOWN_TIMEOUT);
                self.respawn_after(status, attempt);
                continue;
            }
            if self.retry_port_bind_race(attempt) {
                continue;
            }
            if wait == ReadyWait::Ready {
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
        self.respawn_after(status, attempt);
        true
    }

    fn respawn_after(&mut self, status: ExitStatus, attempt: u32) {
        expect_respawn(status, attempt, &mut self.logs);
        self.respawn();
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
