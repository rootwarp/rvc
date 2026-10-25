//! Binary-level startup / dry-run / shutdown tests for `rvc-signer`.
//!
//! Formerly `server_startup.rs` (binary-spawning cases from the opaque
//! `integration_polish.rs` suite; see RF5-18 / H1).
//!
//! Uses `env!("CARGO_BIN_EXE_rvc-signer")` (via [`common::bin_path`]) so tests
//! never nest a cargo invocation. Runs under default features and `--features dvt`.

// RF1-12: SIGTERM via libc::kill in the common harness.
#![allow(unsafe_code)]

mod common;

use std::time::Duration;

use common::{bin_path, free_port, run_bin, spawn_serve, wait_for_port, ServeFixture};

/// Guard: binary path must come from Cargo's CARGO_BIN_EXE, not a nested build.
#[test]
fn test_binary_path_comes_from_cargo_bin_exe() {
    let path = bin_path();
    assert!(path.is_absolute(), "CARGO_BIN_EXE path should be absolute: {}", path.display());
    assert!(
        path.file_name().and_then(|s| s.to_str()).is_some_and(|n| n.starts_with("rvc-signer")),
        "unexpected binary name: {}",
        path.display()
    );
    assert!(
        path.exists(),
        "CARGO_BIN_EXE_rvc-signer does not exist: {} (cargo should build it as a test prereq)",
        path.display()
    );
    // Hard guard against reintroducing a nested cargo invocation in the harness.
    let src = include_str!("common/mod.rs");
    assert!(
        !src.contains("Command::new(\"cargo\")") && !src.contains("args([\"build\""),
        "tests/common must not nest a cargo invocation to produce the binary"
    );
}

#[test]
fn test_dry_run_prints_resolved_config_and_exits_zero() {
    let fx = ServeFixture::new().with_keystore();
    let output = run_bin(&[
        "serve",
        "--dry-run",
        "--keystore-dir",
        &fx.keystore_dir.to_string_lossy(),
        "--password-file",
        &fx.password_file.to_string_lossy(),
    ]);

    assert!(
        output.status.success(),
        "dry-run with valid config should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration valid"), "should print validation summary: {stdout}");
    assert!(stdout.contains("Keys loaded: 1"), "should report loaded keys: {stdout}");
    assert!(stdout.contains("Backend: basic"), "should report backend: {stdout}");
}

#[test]
fn test_dry_run_binary_exit_code_valid() {
    let fx = ServeFixture::new();
    let output = run_bin(&[
        "serve",
        "--dry-run",
        "--keystore-dir",
        &fx.keystore_dir.to_string_lossy(),
        "--password-file",
        &fx.password_file.to_string_lossy(),
    ]);

    assert!(
        output.status.success(),
        "dry-run with valid config should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration valid"), "should print validation summary");
}

#[test]
fn test_dry_run_binary_exit_code_invalid_tls() {
    let fx = ServeFixture::new();
    let output = run_bin(&[
        "serve",
        "--dry-run",
        "--keystore-dir",
        &fx.keystore_dir.to_string_lossy(),
        "--password-file",
        &fx.password_file.to_string_lossy(),
        "--tls-cert",
        "/nonexistent/cert.pem",
        "--tls-key",
        "/nonexistent/key.pem",
        "--tls-ca-cert",
        "/nonexistent/ca.pem",
    ]);

    assert!(!output.status.success(), "dry-run with invalid TLS certs should exit non-zero");
}

#[test]
fn test_dry_run_binary_with_config_toml() {
    let fx = ServeFixture::new().with_keystore();
    let config_path = fx.write_config(&format!(
        r#"
[signer]
keystore_dir = "{ks}"
password_file = "{pw}"
backend = "basic"
"#,
        ks = fx.keystore_dir.display(),
        pw = fx.password_file.display(),
    ));

    let output = run_bin(&["serve", "--dry-run", "--config", &config_path.to_string_lossy()]);

    assert!(
        output.status.success(),
        "dry-run with config.toml should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration valid"));
    assert!(stdout.contains("Keys loaded: 1"));
    assert!(stdout.contains("Backend: basic"));
}

/// Clean start under `--insecure` + init slashing DB, then SIGTERM → exit 0.
///
/// Child stdout/stderr are drained on background threads (see [`common::SpawnedServe`])
/// so a full pipe buffer cannot stall shutdown; failure paths dump captured logs.
#[test]
fn test_server_starts_and_shuts_down_cleanly() {
    let fx = ServeFixture::new().with_keystore();
    let listen_port = free_port();
    let metrics_port = free_port();
    let listen = format!("127.0.0.1:{listen_port}");
    let metrics = format!("127.0.0.1:{metrics_port}");
    let data_dir = fx.dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let child = spawn_serve(
        &[
            "--insecure",
            "--init-slashing-db",
            "--keystore-dir",
            &fx.keystore_dir.to_string_lossy(),
            "--password-file",
            &fx.password_file.to_string_lossy(),
            "--listen-address",
            &listen,
            "--metrics-address",
            &metrics,
            "--data-dir",
            &data_dir.to_string_lossy(),
        ],
        &[("RVC_SIGNER_ALLOW_INSECURE", "true")],
    );

    let ready = wait_for_port("127.0.0.1", listen_port, Duration::from_secs(15));
    if !ready {
        let outcome = child.kill_and_collect();
        panic!("server did not become ready on {listen}\n{}", outcome.diagnostic());
    }

    let outcome = child.terminate_and_wait(Duration::from_secs(10));
    assert!(
        outcome.status.success() && !outcome.timed_out,
        "SIGTERM should yield exit code 0 without force-kill; {}",
        outcome.diagnostic()
    );
}

// ---------------------------------------------------------------------------
// `rvc-signer health`: the image HEALTHCHECK probe
// ---------------------------------------------------------------------------

/// Serves the production signer metrics listener on an ephemeral loopback port.
fn spawn_signer_metrics() -> std::net::SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        runtime.block_on(async move {
            let metrics = std::sync::Arc::new(signer_server::metrics::SignerMetrics::new());
            let (handle, addr) = signer_server::metrics::serve_metrics(
                "127.0.0.1:0".parse().expect("addr"),
                metrics,
            )
            .await
            .expect("serve metrics");
            tx.send(addr).expect("send addr");
            let _ = handle.await;
        });
    });
    rx.recv_timeout(Duration::from_secs(5)).expect("signer metrics address")
}

/// Answers each connection with a 404, like a server without the probed route.
fn spawn_not_found() -> std::net::SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    addr
}

#[test]
fn test_health_exits_zero_on_the_signer_metrics_route() {
    let addr = spawn_signer_metrics();
    for _ in 0..20 {
        let out = run_bin(&["health", "--url", &format!("http://{addr}/metrics")]);
        assert!(
            out.status.success(),
            "health on /metrics must pass: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn test_health_exits_nonzero_on_a_404() {
    let addr = spawn_not_found();
    let out = run_bin(&["health", "--url", &format!("http://{addr}/metrics")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "health on a 404 must fail: {stderr}");
    assert!(stderr.contains("404"), "stderr must name the status: {stderr}");
}

#[test]
fn test_health_exits_nonzero_when_nothing_listens() {
    let out = run_bin(&["health", "--url", &format!("http://127.0.0.1:{}/metrics", free_port())]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "health with no listener must fail: {stderr}");
    assert!(stderr.contains("health probe"), "stderr: {stderr}");
}
