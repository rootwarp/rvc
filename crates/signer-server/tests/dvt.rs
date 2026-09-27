//! DVT startup: reachability is lazy; allow-list and empty SNI stay fatal.

#![cfg(feature = "dvt")]
// Startup opt-in gates read process env. Nextest runs each test in its own process.
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use crypto::{EncryptionKdf, Keystore, SecretKey};
use signer_server::backend::dvt::{PartialSignDuty, PeerRequestError, PeerRequester};
use signer_server::config::{Backend, HttpTlsMode, ResolvedConfig};
use signer_server::dvt::peer_client::{GrpcPeerRequester, PeerConnectInfo};
use signer_server::proto::signer_v2::ForkInfo;
use signer_server::server::run;
use signer_server::ServerError;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Test deadline only. Startup reaches the listener because dials are lazy,
/// not because `connect_timeout` is set — nothing in startup issues a peer RPC.
const CONNECT_TIMEOUT_MS: u64 = 200;
const STARTUP_BOUND: Duration = Duration::from_secs(5);

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    listener.local_addr().expect("local_addr").port()
}

fn closed_peer() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("closed-peer bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    drop(listener);
    addr
}

/// Accepts TCP and never speaks. Startup must still serve; this does not
/// exercise `connect_timeout` (the handshake already finished at `accept`).
fn black_hole_peer() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("black-hole bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept() {
            held.push(sock);
        }
    });
    addr
}

fn write_share(dir: &Path, password: &str) {
    let sk = SecretKey::generate();
    let mut keystore =
        Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::scrypt_cheap_for_tests())
            .expect("encrypt share");
    keystore.description = Some("shamir-share".to_string());
    keystore.pubkey = Some(hex::encode(sk.public_key().to_bytes()));
    std::fs::write(dir.join("share-1.json"), keystore.to_json().expect("share json"))
        .expect("write share");
    std::fs::write(dir.join("share-meta.json"), r#"{"threshold":2,"total":3,"index":1}"#)
        .expect("write share meta");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("keystore mode");
    }
}

fn allow_list(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("dvt-allowed-peers.toml");
    std::fs::write(&path, body).expect("write allow-list");
    path
}

fn resolved(
    tmp: &TempDir,
    peers: Vec<String>,
    allow: Option<std::path::PathBuf>,
) -> ResolvedConfig {
    let keystore_dir = tmp.path().join("keystores");
    std::fs::create_dir(&keystore_dir).expect("keystore dir");
    let password = "test-password";
    write_share(&keystore_dir, password);
    let password_file = tmp.path().join("password.txt");
    std::fs::write(&password_file, password).expect("password");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).expect("data dir");

    ResolvedConfig {
        listen_address: format!("127.0.0.1:{}", free_port()),
        keystore_dir,
        password_file: Some(password_file),
        backend: Backend::Dvt,
        dry_run: false,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        reload_interval_secs: 0,
        enable_hot_reload: false,
        dvt_peers: peers,
        dvt_threshold: Some(2),
        dvt_index: Some(1),
        dvt_timeout_ms: CONNECT_TIMEOUT_MS,
        http_enabled: false,
        http_listen_address: format!("127.0.0.1:{}", free_port()),
        http_tls_mode: HttpTlsMode::Mtls,
        http_tls_cert: None,
        http_tls_key: None,
        http_tls_ca_cert: None,
        genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
        insecure: true,
        data_dir: Some(data_dir),
        disable_slashing_protection: true,
        init_slashing_db: false,
        group_commit_batch_size: None,
        group_commit_wait_to_fill_ms: None,
        gloas_fork_epoch: u64::MAX,
        metrics_address: format!("127.0.0.1:{}", free_port()),
        enable_log_reload: false,
        allowed_client_cns: None,
        dvt_allowed_peers: allow,
    }
}

fn allow_insecure() {
    unsafe {
        std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
        std::env::set_var("RVC_ALLOW_INSECURE", "true");
    }
}

async fn wait_accept(sock: SocketAddr) {
    loop {
        if tokio::net::TcpStream::connect(sock).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn run_until_serving(resolved: ResolvedConfig) {
    let listen: SocketAddr = resolved.listen_address.parse().expect("listen addr");
    let shutdown = CancellationToken::new();
    let shutdown_task = shutdown.clone();
    let mut handle = tokio::spawn(async move { run(resolved, shutdown_task).await });
    tokio::select! {
        joined = &mut handle => {
            let result = joined.expect("run task panicked");
            panic!("startup exited before the gRPC listener served: {result:?}");
        }
        () = wait_accept(listen) => {}
        () = tokio::time::sleep(STARTUP_BOUND) => {
            panic!("gRPC listener {listen} was not accepting within {STARTUP_BOUND:?}");
        }
    };
    shutdown.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("shutdown hung")
        .expect("run task panicked");
    assert!(result.is_ok(), "server failed after the listener was up: {result:?}");
}

async fn startup_error(resolved: ResolvedConfig) -> ServerError {
    let shutdown = CancellationToken::new();
    tokio::time::timeout(Duration::from_secs(5), run(resolved, shutdown))
        .await
        .expect("startup hung")
        .expect_err("startup must fail")
}

fn with_tls(mut resolved: ResolvedConfig, dir: &Path) -> ResolvedConfig {
    let pki = rvc_test_support::TestPki::generate(rvc_test_support::TestPkiParams {
        ca_name: "test-ca.internal".to_string(),
        server_sans: vec!["127.0.0.1".to_string()],
        client_name: "test-client.internal".to_string(),
    });
    let paths = pki.write_client_pem(dir);
    resolved.tls_cert = Some(paths.cert);
    resolved.tls_key = Some(paths.key);
    resolved.tls_ca_cert = Some(paths.ca_cert);
    resolved.insecure = false;
    resolved
}

#[tokio::test]
async fn unreachable_peer_does_not_block_serving() {
    allow_insecure();
    let tmp = TempDir::new().unwrap();
    let peers = vec![closed_peer(), closed_peer()];
    let allow = allow_list(
        tmp.path(),
        r#"
[[peer]]
peer_cn = "peer-a.local"
share_index = 1
addr = "127.0.0.1:1"
"#,
    );
    run_until_serving(resolved(&tmp, peers, Some(allow))).await;
}

/// Listener is up while a peer has accepted TCP and stays silent.
/// Laziness is what makes this true; deleting `connect_timeout` must not fail it.
#[tokio::test]
async fn black_holed_peer_does_not_stall_startup() {
    allow_insecure();
    let tmp = TempDir::new().unwrap();
    let peers = vec![black_hole_peer()];
    let allow = allow_list(
        tmp.path(),
        r#"
[[peer]]
peer_cn = "peer-a.local"
share_index = 1
addr = "127.0.0.1:1"
"#,
    );
    run_until_serving(resolved(&tmp, peers, Some(allow))).await;
}

#[tokio::test]
async fn missing_allow_list_entry_still_fails_startup() {
    let tmp = TempDir::new().unwrap();
    let missing = "127.0.0.1:9".to_string();
    let allow = allow_list(
        tmp.path(),
        r#"
[[peer]]
peer_cn = "peer-a.local"
share_index = 1
addr = "127.0.0.1:1"
"#,
    );
    let resolved = with_tls(resolved(&tmp, vec![missing.clone()], Some(allow)), tmp.path());
    let err = startup_error(resolved).await;
    assert!(matches!(err, ServerError::Config(_)), "expected Config, got {err:?}");
    let msg = err.to_string();
    assert!(
        msg.contains("has no matching") && msg.contains(&missing) && msg.contains("ISSUE-4.1"),
        "allow-list miss must keep its startup message, got {msg}"
    );
}

#[tokio::test]
async fn empty_sni_cn_under_tls_still_fails_startup() {
    let tmp = TempDir::new().unwrap();
    let peer = "127.0.0.1:9".to_string();
    let allow = allow_list(
        tmp.path(),
        &format!(
            r#"
[[peer]]
peer_cn = ""
share_index = 1
addr = "{peer}"
"#
        ),
    );
    let resolved = with_tls(resolved(&tmp, vec![peer], Some(allow)), tmp.path());
    let err = startup_error(resolved).await;
    assert!(matches!(err, ServerError::Backend(_)), "expected Backend, got {err:?}");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to connect to DVT peers")
            && msg.contains("has no SNI hostname")
            && msg.contains("ISSUE-4.1"),
        "empty SNI must stay fatal with its existing message, got {msg}"
    );
}

/// Nothing answers SYNs, so `TcpSocket::connect` cannot succeed.
///
/// macOS completes loopback TCP only for 127.0.0.1; other 127/8 addresses leave
/// the handshake unfinished. Other OS answer the whole 127/8 with RST, so use
/// RFC 5737 TEST-NET-1, which is not assigned and is not accepted.
fn handshake_never_finishes() -> &'static str {
    if cfg!(target_os = "macos") {
        "127.0.0.2:9"
    } else {
        "192.0.2.1:9"
    }
}

/// `connect_timeout` must win over the RPC deadline when TCP cannot finish.
/// An accept-and-stall peer is the wrong fixture: `accept` completes the
/// handshake, and `connect_timeout` no longer applies.
#[tokio::test]
async fn connect_timeout_bounds_unfinished_tcp_handshake() {
    let connect_timeout = Duration::from_millis(200);
    let rpc_timeout = Duration::from_secs(5);
    let addr = handshake_never_finishes();
    let requester = GrpcPeerRequester::connect(
        &[PeerConnectInfo { addr: addr.to_string(), sni_cn: String::new() }],
        None,
        rpc_timeout,
        connect_timeout,
    )
    .await
    .expect("lazy connect does not dial");

    let started = Instant::now();
    let err = requester
        .request_partial(
            addr,
            &PartialSignDuty::BeaconBlock {
                fork_info: ForkInfo {
                    previous_version: vec![0, 0, 0, 0],
                    current_version: vec![1, 0, 0, 0],
                    epoch: 0,
                    genesis_validators_root: vec![0u8; 32],
                },
                block_ssz: vec![0u8; 8],
                fork_id: 4,
            },
            &[0u8; 48],
            1,
        )
        .await
        .expect_err("unfinished handshake must fail the RPC");
    let elapsed = started.elapsed();

    assert!(
        !matches!(err, PeerRequestError::Timeout),
        "outer RPC deadline must not be what fires; got {err} after {elapsed:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("tcp connect error"),
        "expected the connector TCP timeout, got {msg} after {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(2),
        "dial took {elapsed:?}; connect_timeout is {connect_timeout:?}, RPC deadline is {rpc_timeout:?}"
    );
}
