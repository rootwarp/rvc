//! Shared spawn / PKI / fixture helpers for rvc-signer integration tests.
//!
//! Binary-level suites must use [`bin_path`] (`env!("CARGO_BIN_EXE_rvc-signer")`)
//! rather than nesting a cargo invocation inside the test runner, which
//! serializes on the target-dir lock and breaks under `--locked` / offline CI.

#![allow(dead_code)]

use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Path to the `rvc-signer` binary built as a test prerequisite.
///
/// Cargo exposes `CARGO_BIN_EXE_<name>` with the same profile/features as the
/// test build. Prefer this over a nested cargo invocation (target-dir lock thrash).
pub fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rvc-signer"))
}

/// Reserve an ephemeral loopback port (best-effort; small TOCTOU window).
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Poll until `host:port` accepts TCP connections or `timeout` elapses.
pub fn wait_for_port(host: &str, port: u16, timeout: Duration) -> bool {
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(&addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Minimal on-disk fixture for binary serve/dry-run tests.
pub struct ServeFixture {
    pub dir: TempDir,
    pub keystore_dir: PathBuf,
    pub password_file: PathBuf,
    pub password: String,
}

impl ServeFixture {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let keystore_dir = dir.path().join("keystores");
        std::fs::create_dir(&keystore_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keystore_dir, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let password = "test-password".to_string();
        let password_file = dir.path().join("password.txt");
        std::fs::write(&password_file, &password).unwrap();
        Self { dir, keystore_dir, password_file, password }
    }

    pub fn with_keystore(self) -> Self {
        let _ = crypto::test_utils::create_test_keystore(&self.keystore_dir, &self.password, None);
        self
    }

    pub fn write_config(&self, body: &str) -> PathBuf {
        let path = self.dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }
}

/// Run `rvc-signer` to completion and capture output.
pub fn run_bin(args: &[&str]) -> Output {
    Command::new(bin_path())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute rvc-signer")
}

/// Long-running serve child with background pipe drains (avoids pipe-buffer deadlock).
///
/// Both stdout and stderr are piped and continuously read into buffers so the
/// child never blocks on a full OS pipe. Captured bytes are available after
/// [`SpawnedServe::terminate_and_wait`] / [`SpawnedServe::kill_and_collect`].
pub struct SpawnedServe {
    child: Child,
    stdout_buf: Arc<Mutex<Vec<u8>>>,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    drain_threads: Vec<JoinHandle<()>>,
}

/// Outcome of reaping a [`SpawnedServe`] child after signal/kill.
pub struct TerminateOutcome {
    pub status: ExitStatus,
    /// True when the wait timeout elapsed and the child was force-killed.
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl TerminateOutcome {
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Format status + captured logs for assertion / panic messages.
    pub fn diagnostic(&self) -> String {
        format!(
            "status={:?}, timed_out={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status,
            self.timed_out,
            self.stdout_lossy(),
            self.stderr_lossy()
        )
    }
}

fn drain_pipe_thread(
    mut pipe: impl Read + Send + 'static,
    buf: Arc<Mutex<Vec<u8>>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut guard) = buf.lock() {
                        guard.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(_) => break,
            }
        }
    })
}

/// Spawn `rvc-signer serve` with piped stdio drained on background threads.
///
/// Sets `RUST_LOG=warn` unless the caller already provided `RUST_LOG` in
/// `extra_env`, keeping startup noise small while still capturing failures.
pub fn spawn_serve(args: &[&str], extra_env: &[(&str, &str)]) -> SpawnedServe {
    spawn_serve_clearing(args, extra_env, &[])
}

/// [`spawn_serve`] that also drops `remove_env` keys from the child.
///
/// `Command` inherits the runner environment. T9's negative half must not see
/// a parent `OTEL_EXPORTER_OTLP_ENDPOINT`, or tracing turns on without a flag.
pub fn spawn_serve_clearing(
    args: &[&str],
    extra_env: &[(&str, &str)],
    remove_env: &[&str],
) -> SpawnedServe {
    let mut cmd = Command::new(bin_path());
    cmd.arg("serve").args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    for key in remove_env {
        cmd.env_remove(key);
    }

    let mut has_rust_log = false;
    for (k, v) in extra_env {
        if *k == "RUST_LOG" {
            has_rust_log = true;
        }
        cmd.env(k, v);
    }
    if !has_rust_log {
        cmd.env("RUST_LOG", "warn");
    }

    let mut child = cmd.spawn().expect("failed to spawn rvc-signer");

    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let mut drain_threads = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        drain_threads.push(drain_pipe_thread(stdout, Arc::clone(&stdout_buf)));
    }
    if let Some(stderr) = child.stderr.take() {
        drain_threads.push(drain_pipe_thread(stderr, Arc::clone(&stderr_buf)));
    }

    SpawnedServe { child, stdout_buf, stderr_buf, drain_threads }
}

impl SpawnedServe {
    fn join_drains_and_collect(mut self) -> (Vec<u8>, Vec<u8>) {
        for t in self.drain_threads.drain(..) {
            let _ = t.join();
        }
        let stdout = self.stdout_buf.lock().map(|g| g.clone()).unwrap_or_default();
        let stderr = self.stderr_buf.lock().map(|g| g.clone()).unwrap_or_default();
        (stdout, stderr)
    }

    /// Force-kill and collect all captured output (e.g. readiness failure).
    pub fn kill_and_collect(mut self) -> TerminateOutcome {
        let _ = self.child.kill();
        let status = self.child.wait().expect("wait after kill");
        let (stdout, stderr) = self.join_drains_and_collect();
        TerminateOutcome { status, timed_out: false, stdout, stderr }
    }

    /// Send SIGTERM (Unix) or kill (elsewhere) and wait for exit, always draining pipes.
    pub fn terminate_and_wait(mut self, timeout: Duration) -> TerminateOutcome {
        #[cfg(unix)]
        {
            // RF1-12: send SIGTERM via libc so the binary's graceful shutdown path runs.
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }

        let start = Instant::now();
        let (status, timed_out) = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break (status, false),
                Ok(None) if start.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let status = self.child.wait().expect("wait after force-kill");
                    break (status, true);
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        };

        let (stdout, stderr) = self.join_drains_and_collect();
        TerminateOutcome { status, timed_out, stdout, stderr }
    }
}

/// mTLS fixture: CA + server cert/key written under `dir`.
pub struct PkiFixture {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
}

impl PkiFixture {
    pub fn generate(dir: &Path) -> Self {
        use rvc_test_support::{TestPki, TestPkiParams};

        let pki = TestPki::generate(TestPkiParams {
            ca_name: "test-ca".to_string(),
            server_sans: vec!["localhost".to_string()],
            client_name: "rvc-signer.test".to_string(),
        });
        // Server CN is the first SAN (`localhost`); rewrite PEMs with the
        // shared helper's layout (ca.pem / server.pem / server.key).
        let paths = pki.write_server_pem(dir);
        Self { ca_cert: paths.ca_cert, server_cert: paths.cert, server_key: paths.key }
    }
}
