use super::super::tls_config::{build_server_config, install_crypto_provider};
use super::*;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Extension;
use axum::Router;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::ClientConfig;
use rustls::RootCertStore;
use rvc_test_support::{TestPki, TestPkiParams};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use crate::config::HttpTlsMode;

struct Pki {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: Vec<u8>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: Vec<u8>,
}

fn test_pki() -> Pki {
    let pki = TestPki::generate(TestPkiParams {
        ca_name: "test-ca".to_string(),
        server_sans: vec!["localhost".to_string()],
        client_name: "client".to_string(),
    });
    Pki {
        ca: CertificateDer::from(pki.ca_cert_der),
        server_chain: vec![CertificateDer::from(pki.server_cert_der)],
        server_key: pki.server_key_der,
        client_chain: vec![CertificateDer::from(pki.client_cert_der)],
        client_key: pki.client_key_der,
    }
}

fn key_of(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(der.to_vec()).into()
}

fn server_cfg(pki: &Pki, mode: HttpTlsMode) -> Arc<ServerConfig> {
    build_server_config(
        pki.server_chain.clone(),
        key_of(&pki.server_key),
        vec![pki.ca.clone()],
        mode,
    )
    .expect("server config builds")
}

fn client_cfg(pki: &Pki, client: Option<(&[CertificateDer<'static>], &[u8])>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let b = ClientConfig::builder().with_root_certificates(roots);
    let cfg = match client {
        Some((chain, key)) => b.with_client_auth_cert(chain.to_vec(), key_of(key)).unwrap(),
        None => b.with_no_client_auth(),
    };
    Arc::new(cfg)
}

use std::io::Write;

fn write_pem(dir: &TempDir, name: &str, pem: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(pem).unwrap();
    path
}

fn server_pems() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let pki = TestPki::generate(TestPkiParams {
        ca_name: "test-ca".to_string(),
        server_sans: vec!["localhost".to_string()],
        client_name: "client".to_string(),
    });
    (pki.server_cert_pem, pki.server_key_pem, pki.ca_cert_pem)
}

async fn peer_handler(Extension(PeerCert(leaf)): Extension<PeerCert>) -> &'static str {
    if leaf.is_some() {
        "some"
    } else {
        "none"
    }
}

async fn panic_handler() -> &'static str {
    panic!("intentional handler panic")
}

/// Reflects the audit CN derived from the connection's `PeerCert` (Issue 3.4).
async fn cn_handler(Extension(peer): Extension<PeerCert>) -> String {
    crate::audit::cn::audit_cn(peer.leaf_der(), signer::AUDIT_CN_DEFAULT)
}

/// An OPAQUE test router (no gate/state) with a route that reflects the
/// injected `PeerCert`, the derived audit CN, a panicking route, and a
/// liveness route.
fn serve_test_router() -> Router {
    Router::new()
        .route("/peer", get(peer_handler))
        .route("/cn", get(cn_handler))
        .route("/ok", get(|| async { "ok" }))
        .route("/panic", get(panic_handler))
        // Stand-in for Web3Signer `/sign`: keep-alive shutdown must refuse this.
        .route(
            "/api/v1/eth2/sign/:identifier",
            axum::routing::post(|| async { (axum::http::StatusCode::OK, "signed") }),
        )
}

/// Spawn `serve_https` on an ephemeral loopback port; return its address.
async fn start_server(mode: HttpTlsMode, pki: &Pki) -> std::net::SocketAddr {
    start_server_with_shutdown(mode, pki, CancellationToken::new()).await
}

/// Like [`start_server`], but returns the shutdown token so tests can cancel it.
async fn start_server_with_shutdown(
    mode: HttpTlsMode,
    pki: &Pki,
    shutdown: CancellationToken,
) -> std::net::SocketAddr {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_https(listener, server_cfg(pki, mode), serve_test_router(), shutdown));
    addr
}

/// One real HTTPS GET over a fresh TLS connection (raw hyper client), using
/// `client` (with or without a client identity). `Err` if the TLS handshake
/// or the request fails.
async fn https_get(
    addr: std::net::SocketAddr,
    client: Arc<ClientConfig>,
    path: &str,
) -> Result<(axum::http::StatusCode, String), String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(client);
    let name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(name, tcp).await.map_err(|e| e.to_string())?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri(path)
        .header("host", "localhost")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let bytes = axum::body::to_bytes(axum::body::Body::new(resp.into_body()), usize::MAX)
        .await
        .map_err(|e| e.to_string())?;
    Ok((status, String::from_utf8(bytes.to_vec()).unwrap()))
}

#[tokio::test]
async fn mtls_client_cert_is_injected_as_peer_cert_some() {
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::Mtls, &pki).await;
    let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
    let (status, body) = https_get(addr, client, "/peer").await.expect("mTLS request succeeds");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "some", "the leaf client cert must reach the handler as PeerCert(Some)");
}

#[tokio::test]
async fn server_tls_only_no_cert_is_peer_cert_none() {
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
    let client = client_cfg(&pki, None);
    let (status, body) = https_get(addr, client, "/peer").await.expect("no-cert request ok");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "none", "a no-cert connection must yield PeerCert(None)");
}

#[tokio::test]
async fn handshake_failure_does_not_wedge_the_loop() {
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::Mtls, &pki).await;
    // A no-cert client against mTLS fails the handshake — its connection dies.
    let bad = https_get(addr, client_cfg(&pki, None), "/ok").await;
    assert!(bad.is_err(), "no-cert client must be rejected at handshake");
    // The loop must still serve a subsequent good client.
    let good = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
    let (status, body) = https_get(addr, good, "/ok").await.expect("loop still serves");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn handler_panic_does_not_take_down_the_listener() {
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
    // Trigger a handler panic on one connection (the request errors as the
    // connection task aborts) — the spawned-task panic is isolated by tokio.
    let _ = https_get(addr, client_cfg(&pki, None), "/panic").await;
    // A new connection must still be served.
    let (status, body) =
        https_get(addr, client_cfg(&pki, None), "/ok").await.expect("listener survived");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "ok");
}

// ── audit CN via accept loop (Issue 3.4) ──────────────────────────────

#[tokio::test]
async fn server_tls_only_cert_bearing_client_yields_its_real_cn() {
    // AC: a client that DOES present a cert on a server-TLS-only listener
    // still has its CN extracted (allow_unauthenticated relaxes "required",
    // not the cert's CA-validation or its CN).
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
    let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
    let (status, body) = https_get(addr, client, "/cn").await.expect("request ok");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "client", "the leaf CN must reach the audit layer");
}

#[tokio::test]
async fn server_tls_only_no_cert_yields_default_cn() {
    let pki = test_pki();
    let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
    let (status, body) =
        https_get(addr, client_cfg(&pki, None), "/cn").await.expect("no-cert request ok");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, signer::AUDIT_CN_DEFAULT, "no client cert → default audit CN");
}

// ── run_serve wiring: spawn_https_listener + graceful shutdown (Issue 3.5) ─

/// A client config trusting `ca_pem` (to validate the server cert), no client cert.
fn client_trusting(ca_pem: &[u8]) -> Arc<ClientConfig> {
    let ca = rustls_pemfile::certs(&mut &ca_pem[..]).next().unwrap().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

#[tokio::test]
async fn spawn_https_listener_serves_upcheck_over_tls() {
    install_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert, key, ca) = server_pems();
    let cert_p = write_pem(&dir, "c.pem", &cert);
    let key_p = write_pem(&dir, "k.pem", &key);
    let ca_p = write_pem(&dir, "ca.pem", &ca);

    // The state carries a real shared SigningGate — the exact wiring
    // `run_serve` performs (the gate is cloned from the gRPC service's gate).
    let state = crate::http_api::test_support::test_state(Arc::new(
        crate::http_api::test_support::MockBackend::empty(),
    ));
    let (addr, _handle) = spawn_https_listener(
        "127.0.0.1:0",
        &cert_p,
        &key_p,
        &ca_p,
        HttpTlsMode::ServerTlsOnly,
        state,
        CancellationToken::new(),
    )
    .await
    .expect("HTTP listener spawns");

    let (status, body) =
        https_get(addr, client_trusting(&ca), "/upcheck").await.expect("upcheck over TLS");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "OK", "the full 3.1–3.4 path serves /upcheck over TLS");
}

/// An already-open keep-alive connection must not accept a new `/sign` after
/// shutdown begins: the connection is closed or the request is refused.
#[tokio::test]
async fn keep_alive_sign_after_shutdown_is_refused_or_closed() {
    install_crypto_provider();
    let pki = test_pki();
    let shutdown = CancellationToken::new();
    let addr = start_server_with_shutdown(HttpTlsMode::ServerTlsOnly, &pki, shutdown.clone()).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_cfg(&pki, None));
    let tls = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Establish keep-alive with a successful request on this connection.
    let warm = Request::builder()
        .uri("/ok")
        .header("host", "localhost")
        .body(axum::body::Body::empty())
        .unwrap();
    let warm_resp = sender.send_request(warm).await.expect("warm-up request");
    assert_eq!(warm_resp.status(), axum::http::StatusCode::OK);
    let _ = axum::body::to_bytes(axum::body::Body::new(warm_resp.into_body()), usize::MAX)
        .await
        .expect("warm-up body");

    shutdown.cancel();
    // Give the accept loop and per-connection graceful_shutdown a moment.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sign = Request::builder()
        .method("POST")
        .uri("/api/v1/eth2/sign/0xabc")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap();
    match sender.send_request(sign).await {
        Ok(resp) => {
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "keep-alive /sign after shutdown must be refused with 503"
            );
        }
        Err(_) => {
            // Connection closed by per-connection graceful_shutdown — also success.
        }
    }
}

#[tokio::test]
async fn serve_https_exits_promptly_on_shutdown() {
    install_crypto_provider();
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token = CancellationToken::new();
    let handle = tokio::spawn(serve_https(
        listener,
        server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
        serve_test_router(),
        token.clone(),
    ));
    token.cancel();
    // The loop must break on cancellation and the drain must complete.
    let exited = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(exited.is_ok(), "serve_https must exit promptly after cancellation");
}

/// The carry-forward #3 proof (3.5 review): shutdown must be prompt even when
/// the connection cap is SATURATED. Pre-fix, the loop parked on the permit
/// acquire (outside the select) and ignored cancellation until an in-flight
/// connection freed a permit (~HEADER_READ_TIMEOUT). This holds the only
/// permit and asserts exit well under that stall.
#[tokio::test]
async fn shutdown_is_prompt_even_when_connection_cap_is_saturated() {
    install_crypto_provider();
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    // cap = 1 so a single held connection saturates the loop's permit;
    // a short drain timeout keeps the test fast.
    let handle = tokio::spawn(serve_https_inner(
        listener,
        server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
        serve_test_router(),
        token.clone(),
        1,
        Duration::from_millis(200),
    ));

    // Finish the TLS handshake but send NO request: this connection's
    // serve_one task holds the only permit (parked in header-read), so the
    // accept loop is parked acquiring the next permit.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_cfg(&pki, None));
    let _held = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    token.cancel();
    // With the acquire raced against shutdown the loop breaks promptly and
    // the bounded drain finishes — far under HEADER_READ_TIMEOUT (30s), the
    // pre-fix stall point.
    let exited = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(exited.is_ok(), "shutdown must be prompt even when the connection cap is saturated");
}

#[test]
fn test_accept_loop_hardening_constants() {
    assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    assert_eq!(HEADER_READ_TIMEOUT, Duration::from_secs(30));
    assert_eq!(MAX_CONCURRENT_CONNECTIONS, 1024);
    assert_eq!(DRAIN_TIMEOUT, Duration::from_secs(10));
    assert_eq!(ACCEPT_ERROR_BACKOFF, Duration::from_millis(50));
}

/// With cap = 1, a second concurrent request cannot complete until the first
/// connection releases its semaphore permit (backpressure, not hard reject).
#[tokio::test]
async fn test_accept_loop_rejects_beyond_semaphore_limit() {
    install_crypto_provider();
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let handle = tokio::spawn(serve_https_inner(
        listener,
        server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
        serve_test_router(),
        token.clone(),
        1,
        Duration::from_secs(2),
    ));

    // Hold the only permit with a finished TLS handshake that never sends a request.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_cfg(&pki, None));
    let _held = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A second client should not complete while the cap is saturated.
    let pending = tokio::spawn({
        let pki_ca = pki.ca.clone();
        let client = client_cfg(&pki, None);
        async move {
            let _ = pki_ca;
            https_get(addr, client, "/ok").await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!pending.is_finished(), "second connection must wait while the semaphore is saturated");

    drop(_held);
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("join timeout")
        .expect("task join")
        .expect("second request after release");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, "ok");

    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

/// A client that opens TCP but never completes the TLS handshake is closed
/// after the handshake timeout (injected short value for the test).
#[tokio::test]
async fn test_handshake_timeout_closes_connection() {
    install_crypto_provider();
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Manually accept + serve_one_with_timeout with a short handshake budget.
    let acceptor = TlsAcceptor::from(server_cfg(&pki, HttpTlsMode::ServerTlsOnly));
    let router = serve_test_router();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        serve_one_with_timeout(
            acceptor,
            tcp,
            router,
            Duration::from_millis(200),
            CancellationToken::new(),
        )
        .await;
    });

    // Open TCP but do not speak TLS.
    let _raw = TcpStream::connect(addr).await.unwrap();
    let finished = tokio::time::timeout(Duration::from_secs(3), server).await;
    assert!(finished.is_ok(), "handshake timeout must close the connection task");
    finished.unwrap().unwrap();
}
