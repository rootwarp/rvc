//! Real CLI-level tests for the `rvc` binary (RF6-20 / H3 / F17).
//!
//! Every case spawns the Cargo-built binary via `env!("CARGO_BIN_EXE_rvc")` —
//! none shells out to `cargo build`. Assertions are on exit status plus a
//! stable substring (never full stderr dumps).
//!
//! ## Case inventory (vs Phase 5 F1 smoke in `integration_test.rs`)
//!
//! | Case | Source |
//! |------|--------|
//! | `--help` / `--version` / `start --help` exit 0 | Moved from `integration_test` (flag surface) |
//! | Unknown flag → non-zero + usage on stderr | **New** |
//! | Missing config path → non-zero | Moved from `integration_test` |
//! | Missing slashing DB refuses start (SEC-3) | **New** |
//! | `--tracing-sample-rate 0.01` survives `OTEL_TRACES_SAMPLER_ARG` | **New** (e2e of RF5-15 / F20) |
//!
//! Startup-ready + SIGTERM clean exit remain in `integration_test.rs` (F1 smoke);
//! this file deliberately does not re-run the full mock-BN ready path.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::{NamedTempFile, TempDir};

/// Absolute path to the `rvc` binary built as a test prerequisite.
fn rvc_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rvc"))
}

/// Spawn with an explicit wall-clock timeout so a hung child cannot stall CI.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn rvc");
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().expect("collect output");
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("rvc did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local_addr").port()
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// Flag parsing + exit codes (fast)
// ---------------------------------------------------------------------------

#[test]
fn help_exits_zero() {
    let output = run_with_timeout(Command::new(rvc_bin()).arg("--help"), Duration::from_secs(10));
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Rust Validator Client"), "stdout={stdout}");
    assert!(stdout.contains("start"), "stdout={stdout}");
}

#[test]
fn version_exits_zero() {
    let output =
        run_with_timeout(Command::new(rvc_bin()).arg("--version"), Duration::from_secs(10));
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rvc"), "stdout={stdout}");
}

#[test]
fn start_help_exits_zero_and_lists_flags() {
    let output = run_with_timeout(
        Command::new(rvc_bin()).args(["start", "--help"]),
        Duration::from_secs(10),
    );
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Core surface + RF5-14 complete flag set (dropped clap flatten field fails loudly).
    for flag in [
        "--config",
        "--beacon-url",
        "--beacon-nodes",
        "--beacon-max-body-bytes",
        "--keystore-path",
        "--slashing-db-path",
        "--init-slashing-db",
        "--allow-unsupported-fork",
        "--metrics-address",
        "--metrics-port",
        "--network",
        "--genesis-time",
        "--genesis-validators-root",
        "--graffiti",
        "--no-doppelganger-detection",
        "--log-level",
        "--log-format",
        "--enable-log-reload",
        "--keymanager-enabled",
        "--no-keymanager",
        "--keymanager-address",
        "--keymanager-token-file",
        "--remote-signer-url",
        "--remote-signer-allowed-hosts",
        "--strict-permissions",
        "--strict-slashing-semantics",
        "--block-production-timeout",
        "--attestation-timeout",
        "--aggregate-timeout",
        "--duty-fetch-timeout",
        "--duty-dispatch-concurrency",
        "--duty-publish-concurrency",
        "--key-decrypt-threads",
        "--tracing-endpoint",
        "--tracing-exporter",
        "--tracing-sample-rate",
        "--tracing-max-queue-size",
        "--tracing-max-export-batch-size",
        "--secret-provider",
        "--gcp-project-id",
        "--gcp-secret-prefix",
        "--secret-refresh-interval",
        "--secret-provider-strict",
        "--allow-insecure-remote-signer",
        "--keymanager-cors-origins",
        "--keymanager-body-limit",
        "--grpc-signer-url",
        "--grpc-signer-tls-cert",
        "--grpc-signer-tls-key",
        "--grpc-signer-tls-ca-cert",
        "--disable-attesting",
        "--slashed-validators-action",
        "--builder-circuit-breaker-consecutive-limit",
        "--builder-circuit-breaker-epoch-limit",
        "--disable-keystore-locking",
        "--proposer-nodes",
        "--broadcast",
        "--proposer-config-url",
        "--proposer-config-file",
        "--proposer-config-refresh-interval",
        "--proposer-config-url-token",
        "--proposer-config-url-insecure",
        "--monitoring-endpoint",
        "--monitoring-interval",
        "--monitoring-endpoint-insecure",
        "--logfile",
        "--logfile-max-size",
        "--logfile-max-number",
        "--logfile-compress",
        "--logfile-level",
        "--block-selection-mode",
        "--validator-registration-batch-size",
        "--validator-registration-batch-delay",
        "--validators-config",
        "--password-file",
    ] {
        assert!(stdout.contains(flag), "start --help missing {flag}\n{stdout}");
    }
}

#[test]
fn unknown_flag_exits_nonzero_with_usage() {
    let output = run_with_timeout(
        Command::new(rvc_bin()).args(["--not-a-real-flag"]),
        Duration::from_secs(10),
    );
    assert!(!output.status.success(), "unknown flag must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap prints usage / unexpected argument on stderr
    assert!(
        stderr.contains("unexpected")
            || stderr.contains("Usage")
            || stderr.contains("usage")
            || stderr.contains("error"),
        "expected clap usage/error on stderr, got: {stderr}"
    );
}

#[test]
fn test_unknown_grpc_cli_flag_is_rejected() {
    for args in [
        ["start", "--grpc-port", "1"].as_slice(),
        ["start", "--grpc-address", "127.0.0.1"].as_slice(),
    ] {
        let output = run_with_timeout(Command::new(rvc_bin()).args(args), Duration::from_secs(10));
        assert!(
            !output.status.success(),
            "{args:?} must exit non-zero after the flags were removed; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected")
                || stderr.contains("Usage")
                || stderr.contains("usage")
                || stderr.contains("error"),
            "expected clap rejection for {args:?}, got: {stderr}"
        );
    }
}

#[test]
fn start_unknown_flag_exits_nonzero_with_usage() {
    let output = run_with_timeout(
        Command::new(rvc_bin()).args(["start", "--definitely-not-a-flag"]),
        Duration::from_secs(10),
    );
    assert!(!output.status.success(), "unknown start flag must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected")
            || stderr.contains("Usage")
            || stderr.contains("usage")
            || stderr.contains("error"),
        "expected clap usage/error on stderr, got: {stderr}"
    );
}

#[test]
fn missing_config_exits_nonzero() {
    let output = run_with_timeout(
        Command::new(rvc_bin()).args(["start", "--config", "/nonexistent/config.toml"]),
        Duration::from_secs(15),
    );
    assert!(!output.status.success(), "missing config must exit non-zero");
    let text = combined(&output);
    assert!(
        text.contains("not found") || text.contains("No such file") || text.contains("config"),
        "expected config-not-found diagnostics, got: {text}"
    );
}

// ---------------------------------------------------------------------------
// Startup fail-closed paths (no full ready-path; exits before duty loop)
// ---------------------------------------------------------------------------

/// Minimal config that passes `Config::validate` and reaches slashing-DB open.
fn write_start_config(
    dir: &TempDir,
    slashing_db_path: &Path,
    beacon_url: &str,
    metrics_port: u16,
    extra_toml: &str,
) -> NamedTempFile {
    let keystore = dir.path().join("keystores");
    std::fs::create_dir_all(&keystore).expect("keystore dir");
    let mut file = NamedTempFile::new().expect("temp config");
    writeln!(
        file,
        r#"
beacon_url = "{beacon_url}"
keystore_path = "{keystore}"
slashing_db_path = "{slashing}"
metrics_address = "127.0.0.1"
metrics_port = {metrics_port}
network = "mainnet"
log_level = "info"
keymanager_enabled = false
{extra}
"#,
        beacon_url = beacon_url,
        keystore = keystore.display(),
        slashing = slashing_db_path.display(),
        metrics_port = metrics_port,
        extra = extra_toml,
    )
    .expect("write config");
    file
}

/// SEC-3: missing slashing DB without `--init-slashing-db` must refuse to start
/// and must not leave a fresh DB (or SQLite sidecars) behind.
#[test]
fn missing_slashing_db_refuses_start() {
    let dir = TempDir::new().expect("temp dir");
    let slashing_path = dir.path().join("missing-slashing.db");
    assert!(!slashing_path.exists());

    let metrics = free_port();
    let config = write_start_config(
        &dir,
        &slashing_path,
        "http://127.0.0.1:9", // unreachable; open fails before BN connect
        metrics,
        "",
    );

    let output = run_with_timeout(
        Command::new(rvc_bin())
            .args([
                "start",
                "--config",
                config.path().to_str().unwrap(),
                // deliberately NO --init-slashing-db
                "--metrics-port",
                &metrics.to_string(),
            ])
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
            .env_remove("OTEL_TRACES_SAMPLER_ARG"),
        Duration::from_secs(20),
    );

    assert!(
        !output.status.success(),
        "missing slashing DB must exit non-zero, got {}\n--- output ---\n{}",
        output.status,
        combined(&output)
    );
    let text = combined(&output);
    assert!(
        text.contains("slashing protection database does not exist")
            || text.contains("Refusing to create a fresh empty DB")
            || text.contains("--init-slashing-db"),
        "expected SEC-3 refuse message, got: {text}"
    );
    assert!(!slashing_path.exists(), "must not create a fresh slashing DB");
    assert!(!dir.path().join("missing-slashing.db-wal").exists(), "must not leave -wal sidecar");
    assert!(!dir.path().join("missing-slashing.db-shm").exists(), "must not leave -shm sidecar");
}

/// RF5-15 / F20 e2e: explicit `--tracing-sample-rate 0.01` must win over
/// `OTEL_TRACES_SAMPLER_ARG`. Observed via the OTEL enable line on stderr
/// (printed after precedence resolution, before duty loop).
///
/// The process is expected to fail later (missing slashing DB / no BN) — we
/// only care that logging init printed the resolved sample_rate.
#[test]
fn tracing_sample_rate_cli_survives_otel_env() {
    let dir = TempDir::new().expect("temp dir");
    let slashing_path = dir.path().join("missing-slashing.db");
    let metrics = free_port();
    // Point OTLP at a closed local port so exporter construction is cheap and
    // does not require a real collector. init_tracing typically succeeds; if it
    // fails we still assert the sample_rate appeared in the enable line or the
    // failure path still exercised merge (test will fail loudly either way).
    let otlp = format!("http://127.0.0.1:{}", free_port());
    let config = write_start_config(&dir, &slashing_path, "http://127.0.0.1:9", metrics, "");

    let output = run_with_timeout(
        Command::new(rvc_bin())
            .args([
                "start",
                "--config",
                config.path().to_str().unwrap(),
                "--tracing-endpoint",
                &otlp,
                "--tracing-sample-rate",
                "0.01",
                "--metrics-port",
                &metrics.to_string(),
            ])
            // Env would win under the pre-F20 bug when the explicit value was 0.01.
            .env("OTEL_TRACES_SAMPLER_ARG", "0.5")
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT"),
        Duration::from_secs(25),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let text = format!("{stdout}{stderr}");

    assert!(
        text.contains("sample_rate: 0.01") || text.contains("sample_rate: 0.01,"),
        "CLI --tracing-sample-rate 0.01 must survive OTEL_TRACES_SAMPLER_ARG=0.5.\n\
         expected sample_rate: 0.01 in process output.\n--- combined ---\n{text}"
    );
    assert!(
        !text.contains("sample_rate: 0.5"),
        "env sample rate must not override explicit CLI 0.01.\n--- combined ---\n{text}"
    );
}

/// TRC-1a / ADR-005: resolved sample_rate < 1.0 emits a startup `warn!`
/// **after** subscriber init (CD-12). Rate `1.0` stays silent; `0.0` names
/// exporter-receives-nothing.
fn run_start_with_tracing_sample_rate(rate: &str) -> String {
    let dir = TempDir::new().expect("temp dir");
    let slashing_path = dir.path().join("missing-slashing.db");
    let metrics = free_port();
    let otlp = format!("http://127.0.0.1:{}", free_port());
    let config = write_start_config(&dir, &slashing_path, "http://127.0.0.1:9", metrics, "");

    let output = run_with_timeout(
        Command::new(rvc_bin())
            .args([
                "start",
                "--config",
                config.path().to_str().unwrap(),
                "--tracing-endpoint",
                &otlp,
                "--tracing-sample-rate",
                rate,
                "--metrics-port",
                &metrics.to_string(),
            ])
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
            .env_remove("OTEL_TRACES_SAMPLER_ARG"),
        Duration::from_secs(25),
    );

    combined(&output)
}

#[test]
fn tracing_sample_rate_below_one_warns_after_subscriber_init() {
    // Case 1: 0.9 → warn after init (visible on the subscriber).
    let text_09 = run_start_with_tracing_sample_rate("0.9");
    assert!(
        text_09.contains("tracing sample_rate is below 1.0"),
        "resolved 0.9 must warn after subscriber init.\n--- combined ---\n{text_09}"
    );

    // Case 2: 0.0 → warn naming exporter-receives-nothing.
    let text_00 = run_start_with_tracing_sample_rate("0.0");
    assert!(
        text_00.contains("exporter receives nothing"),
        "resolved 0.0 must warn that exporter receives nothing.\n--- combined ---\n{text_00}"
    );

    // Case 3: 1.0 → silent (no below-1.0 / exporter-nothing warn).
    let text_10 = run_start_with_tracing_sample_rate("1.0");
    assert!(
        !text_10.contains("tracing sample_rate is below 1.0")
            && !text_10.contains("exporter receives nothing"),
        "resolved 1.0 must not emit the sample-rate warn.\n--- combined ---\n{text_10}"
    );
}

/// TRC-1b: path-less OTLP endpoint is rewritten to `…/v1/traces` in the enable
/// line, and the non-localhost `http://` warn fires only for dotted remotes
/// (Compose host `jaeger` and loopback stay silent).
fn run_start_with_tracing_endpoint(endpoint: &str) -> String {
    let dir = TempDir::new().expect("temp dir");
    let slashing_path = dir.path().join("missing-slashing.db");
    let metrics = free_port();
    let config = write_start_config(&dir, &slashing_path, "http://127.0.0.1:9", metrics, "");

    let output = run_with_timeout(
        Command::new(rvc_bin())
            .args([
                "start",
                "--config",
                config.path().to_str().unwrap(),
                "--tracing-endpoint",
                endpoint,
                "--tracing-sample-rate",
                "1.0",
                "--metrics-port",
                &metrics.to_string(),
            ])
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
            .env_remove("OTEL_TRACES_SAMPLER_ARG"),
        Duration::from_secs(25),
    );

    combined(&output)
}

#[test]
fn tracing_otlp_path_append_and_compose_host_http_warn() {
    const HTTP_WARN: &str = "tracing endpoint uses http:// with non-localhost host";

    // Path-less Compose host → `/v1/traces` appended; no http warn.
    let jaeger = run_start_with_tracing_endpoint("http://jaeger:4318");
    assert!(
        jaeger.contains("http://jaeger:4318/v1/traces"),
        "path-less jaeger endpoint must append /v1/traces.\n--- combined ---\n{jaeger}"
    );
    assert!(
        !jaeger.contains(HTTP_WARN),
        "dot-less compose host must not emit non-localhost http warn.\n--- combined ---\n{jaeger}"
    );

    // Loopback → path append; no http warn.
    let loopback = format!("http://127.0.0.1:{}", free_port());
    let local = run_start_with_tracing_endpoint(&loopback);
    assert!(
        local.contains(&format!("{loopback}/v1/traces")),
        "path-less loopback must append /v1/traces.\n--- combined ---\n{local}"
    );
    assert!(
        !local.contains(HTTP_WARN),
        "localhost must not emit non-localhost http warn.\n--- combined ---\n{local}"
    );

    // Dotted remote → warn after subscriber init.
    let remote = run_start_with_tracing_endpoint("http://collector.example.invalid:9");
    assert!(
        remote.contains("http://collector.example.invalid:9/v1/traces"),
        "path-less remote must append /v1/traces.\n--- combined ---\n{remote}"
    );
    assert!(
        remote.contains(HTTP_WARN),
        "dotted remote http:// must warn after subscriber init.\n--- combined ---\n{remote}"
    );
}
