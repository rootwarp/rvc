//! Hardened HTTPS accept loop for the Web3Signer HTTP API.
//!
//! Split from the former grab-bag `http_api::tls` (RF5-22 / F34). TLS material
//! loading and rustls `ServerConfig` construction live in
//! [`super::tls_config`]; audit CN derivation lives in
//! [`crate::audit::cn::audit_cn`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::rustls::{pki_types::CertificateDer, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::tls_config::load_server_config;
use crate::config::HttpTlsMode;

/// The leaf client certificate from the TLS handshake, injected as a request
/// extension so the audit layer (Issue 3.4) can derive the client CN. `None` on
/// a server-TLS-only / no-cert connection (→ `AUDIT_CN_DEFAULT`).
#[derive(Clone, Debug)]
pub struct PeerCert(pub Option<CertificateDer<'static>>);

impl PeerCert {
    /// Borrow the leaf DER when a client certificate was presented.
    pub fn leaf_der(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|c| c.as_ref())
    }
}

/// Per-connection handshake timeout: a stalled client cannot hold a task open.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Slow-header (slowloris) bound on each accepted connection (SEC-2.11-01, the
/// Phase-2 request-hardening carry-forward).
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Max concurrently-served connections. Bounds per-connection-task fan-out so a
/// connection flood cannot exhaust memory/fds (3.3 review). Sensible default;
/// promoting it to a `[signer.http]` knob is a follow-up.
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 1024;
/// Backoff after an `accept()` error. EMFILE/ENFILE (fd exhaustion) leaves the
/// listener readable, so a bare `continue` busy-spins at 100% CPU; this yields
/// the task and bounds the spin (3.3 review).
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
/// Upper bound on draining in-flight connections at shutdown, so SIGTERM cannot
/// hang on an idle keep-alive client that ignores per-connection graceful
/// shutdown.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve the Web3Signer HTTP API over TLS on `listener` (ADR-005, R7).
///
/// Per accepted connection: complete the rustls handshake (bounded by
/// [`HANDSHAKE_TIMEOUT`]), extract the leaf client cert into a [`PeerCert`]
/// request extension, and serve the **opaque** `router` over HTTP/1.1 via hyper
/// `serve_connection` (no upgrades — research R6). Each connection runs in its
/// own task, so one bad client (handshake failure or a panicking handler) never
/// wedges the accept loop or the process. A `header_read_timeout` bounds
/// slow-header (slowloris) connections.
///
/// Hardening (3.3 review):
/// - a [`Semaphore`] caps concurrency at [`MAX_CONCURRENT_CONNECTIONS`] —
///   acquired before each accept, so a flood applies backpressure rather than
///   spawning unbounded tasks;
/// - an `accept()` error backs off [`ACCEPT_ERROR_BACKOFF`] so EMFILE/ENFILE
///   cannot busy-spin the loop;
/// - on `shutdown`, the loop stops accepting and each open connection's hyper
///   [`Connection::graceful_shutdown`](http1::Connection::graceful_shutdown) is
///   wired to the same token, so an idle keep-alive client cannot keep serving
///   new `/sign` requests during the drain; an in-progress request still finishes,
///   then the connection closes (bounded by [`DRAIN_TIMEOUT`]).
///
/// `router` is taken as an opaque [`axum::Router`]; this module stays ignorant
/// of `/sign` and the gate (extraction-readiness).
pub async fn serve_https(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
    shutdown: CancellationToken,
) {
    serve_https_inner(listener, tls, router, shutdown, MAX_CONCURRENT_CONNECTIONS, DRAIN_TIMEOUT)
        .await
}

/// [`serve_https`] with the connection cap and drain timeout injected, so tests
/// can saturate the cap and assert prompt shutdown.
async fn serve_https_inner(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
    shutdown: CancellationToken,
    max_connections: usize,
    drain_timeout: Duration,
) {
    let acceptor = TlsAcceptor::from(tls);
    let limit = Arc::new(Semaphore::new(max_connections));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        // Backpressure: do not accept a new connection until a serving slot is
        // free. The acquire is RACED against `shutdown` — when the cap is
        // saturated the loop must still observe cancellation promptly rather than
        // park on the permit until an in-flight connection frees one (3.5 review).
        // `acquire_owned`'s future is cancel-safe (dropping it just deregisters
        // the waiter), so losing the race leaks no permit.
        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            permit = Arc::clone(&limit).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };

        let (tcp, _peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "HTTP listener: accept failed");
                    drop(permit);
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        let conn_shutdown = shutdown.clone();
        conns.spawn(async move {
            serve_one(acceptor, tcp, router, conn_shutdown).await;
            drop(permit); // release the serving slot when the connection ends
        });

        // Reap finished connection tasks so the JoinSet does not grow unbounded.
        while conns.try_join_next().is_some() {}
    }

    // Accept loop stopped: listener is dropped below. Open connections already
    // observe `shutdown` via per-connection graceful_shutdown; drain them here
    // so an in-progress request can finish, bounded by `drain_timeout`.
    tracing::info!("HTTP listener stopped accepting");
    drop(listener);
    let _ =
        tokio::time::timeout(drain_timeout, async { while conns.join_next().await.is_some() {} })
            .await;
}

/// Build the HTTP listener's TLS config + router from already-loaded paths and
/// the shared application state, bind `listen_address`, and spawn
/// [`serve_https`] (Issue 3.5). Returns the bound address + the listener task.
///
/// `run_serve` calls this when `[signer.http].enabled`; the `state` carries the
/// SAME `Arc<SigningGate>` injected into the gRPC service (FR-26).
#[allow(clippy::too_many_arguments)]
pub async fn spawn_https_listener(
    listen_address: &str,
    tls_cert: &Path,
    tls_key: &Path,
    tls_ca_cert: &Path,
    tls_mode: HttpTlsMode,
    state: super::Web3SignerState,
    shutdown: CancellationToken,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let tls = load_server_config(tls_cert, tls_key, tls_ca_cert, tls_mode)?;
    let router = super::router(state);
    let listener = TcpListener::bind(listen_address).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(serve_https(listener, tls, router, shutdown));
    Ok((addr, handle))
}

/// Handshake one connection, inject [`PeerCert`], and serve `router` over it.
///
/// `shutdown` drives hyper [`Connection::graceful_shutdown`]: after the token
/// fires, the current request (if any) finishes and keep-alive is disabled so
/// no further `/sign` (or other) requests are accepted on this connection.
async fn serve_one(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    router: Router,
    shutdown: CancellationToken,
) {
    serve_one_with_timeout(acceptor, tcp, router, HANDSHAKE_TIMEOUT, shutdown).await
}

/// [`serve_one`] with an injectable handshake timeout for unit tests.
async fn serve_one_with_timeout(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    router: Router,
    handshake_timeout: Duration,
    shutdown: CancellationToken,
) {
    let tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            // Handshake failure (e.g. an mTLS client with no/invalid cert) drops
            // this connection only; the accept loop keeps serving others.
            tracing::debug!(error = %e, "TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!("TLS handshake timed out");
            return;
        }
    };

    // Leaf client cert (owned so it outlives the borrow); `None` in
    // server-TLS-only / no-cert connections.
    let leaf = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.clone().into_owned());
    let peer = PeerCert(leaf);

    // Inject the per-connection PeerCert into every request, then serve the
    // opaque Router (tower) via hyper. `oneshot` drives poll_ready + call.
    let service = service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(peer.clone());
        router.clone().oneshot(req)
    });

    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    let conn = builder.serve_connection(TokioIo::new(tls_stream), service);
    tokio::pin!(conn);

    // Already shutting down (e.g. accepted just as the token fired): disable
    // keep-alive before the first request on this connection.
    if shutdown.is_cancelled() {
        conn.as_mut().graceful_shutdown();
    }

    tokio::select! {
        biased;
        result = conn.as_mut() => {
            if let Err(e) = result {
                tracing::debug!(error = %e, "HTTP connection closed with error");
            }
        }
        _ = shutdown.cancelled() => {
            // Finish the in-flight request (if any), then close — do not accept
            // further keep-alive requests such as a late `/sign`.
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.as_mut().await {
                tracing::debug!(error = %e, "HTTP connection closed with error");
            }
        }
    }
}

#[cfg(test)]
mod tests;
