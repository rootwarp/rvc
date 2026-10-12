//! Signer server composition root (`server::run`).
//!
//! RF5-19 moved the former `main::run_serve` body into the library target.
//! RF5-20 decomposes the first two phases into [`open_slashing_db`] and
//! [`build_backend`]; RF5-21 adds [`build_grpc_router`] and [`spawn_http_api`].

mod backend;
mod grpc;
mod http;
mod slashing;

pub(crate) use backend::build_backend;
pub(crate) use grpc::build_grpc_router;
pub(crate) use http::spawn_http_api;
pub(crate) use slashing::open_slashing_db;

/// Process-global env mutations in server unit tests must take this lock so
/// concurrent tests do not clobber each other's `RVC_*` variables.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|p| p.into_inner())
}

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tracing::{error, info, warn};

use crate::error::ServerError;
use crate::{config, http_api, metrics, reload, service};

/// Upper bound for shutdown after cancel **or** after `run_inner` returns an
/// error that still has children to join.
///
/// Covers the gRPC graceful drain (on the cancel path) and the reloader,
/// metrics, and HTTP joins. Longer than the HTTP in-flight drain
/// ([`crate::http_api::accept_loop::DRAIN_TIMEOUT`], 10s) so a healthy drain is
/// not aborted. On expiry remaining owned children are aborted and a warning is
/// logged. Dropping the gRPC `serve` future stops waiting on the drain; tonic's
/// per-connection tasks are not individually tracked here.
pub(crate) const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);

/// Child tasks spawned by [`run_inner`].
///
/// [`Self::shutdown`] cancels cooperative tokens, aborts the metrics task (it
/// has no stop token), then joins every handle. A child panic is logged and
/// returned as [`ServerError::Runtime`]. Dropping a `JoinHandle` would detach
/// the task, so [`Drop`] cancels every token and aborts every handle still
/// owned here when [`run`] is dropped or panics.
#[derive(Default)]
struct Children {
    reloader: Option<tokio::task::JoinHandle<()>>,
    metrics: Option<tokio::task::JoinHandle<()>>,
    http: Option<tokio::task::JoinHandle<()>>,
    reloader_cancel: Option<tokio_util::sync::CancellationToken>,
    http_shutdown: Option<tokio_util::sync::CancellationToken>,
}

impl Children {
    fn cancel_tokens(&mut self) {
        if let Some(token) = self.reloader_cancel.take() {
            token.cancel();
        }
        if let Some(token) = self.http_shutdown.take() {
            token.cancel();
        }
    }

    /// Cancel, abort metrics, then join. Metrics has no stop token and is
    /// stopped before waiting on the reloader so a wedged reloader cannot keep
    /// the metrics listener open for the full join wait.
    async fn shutdown(&mut self) -> Result<(), ServerError> {
        #[cfg(test)]
        tests::note_shutdown();

        self.cancel_tokens();
        // Abort metrics before any cooperative join so a hung reloader does not
        // leave the scrape port bound while we wait.
        if let Some(handle) = &self.metrics {
            if !handle.is_finished() {
                handle.abort();
            }
        }
        let mut failure = None;
        // Metrics first (already aborted), then reloader/http. A panic that
        // already completed is still reported (`join_named` checks that).
        for (name, aborted) in [("metrics", true), ("reloader", false), ("http", false)] {
            if let Err(err) = self.join_named(name, aborted).await {
                if failure.is_none() {
                    failure = Some(err);
                }
            }
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn join_named(&mut self, name: &'static str, aborted: bool) -> Result<(), ServerError> {
        let handle = match name {
            "reloader" => self.reloader.take(),
            "metrics" => self.metrics.take(),
            "http" => self.http.take(),
            _ => None,
        };
        let Some(handle) = handle else {
            return Ok(());
        };
        // Abort only a still-running metrics task. A child that already
        // panicked must surface as `JoinError::is_panic`, not as a cancel.
        if aborted && !handle.is_finished() {
            handle.abort();
        }
        let result = AbortOnDropJoin::new(handle).await;
        #[cfg(test)]
        tests::note_joined(name);
        match result {
            Ok(()) => Ok(()),
            Err(err) if err.is_panic() => {
                error!(child = name, error = %err, "signer child task panicked");
                Err(ServerError::runtime(format!("{name} task panicked")))
            }
            Err(_) if aborted => Ok(()),
            Err(err) if err.is_cancelled() => {
                warn!(child = name, "signer child task cancelled");
                Ok(())
            }
            Err(err) => {
                error!(child = name, error = %err, "signer child task failed");
                Err(ServerError::runtime(format!("{name} task failed: {err}")))
            }
        }
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.cancel_tokens();
        if let Some(handle) = self.reloader.take() {
            handle.abort();
        }
        if let Some(handle) = self.metrics.take() {
            handle.abort();
        }
        if let Some(handle) = self.http.take() {
            handle.abort();
        }
        #[cfg(test)]
        tests::note_drop_guard();
    }
}

/// Aborts the task if this join is dropped before it completes.
///
/// `JoinHandle`'s own `Drop` detaches. Shutdown awaits through this wrapper so
/// a dropped or panicked [`run`] still aborts a child that is mid-join.
struct AbortOnDropJoin {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AbortOnDropJoin {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self { handle: Some(handle) }
    }
}

impl Drop for AbortOnDropJoin {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Future for AbortOnDropJoin {
    type Output = Result<(), tokio::task::JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(handle) = this.handle.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(handle).poll(cx) {
            Poll::Ready(result) => {
                this.handle.take();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Run the signer server until `shutdown` is cancelled.
///
/// Composition root: crypto-provider install → password → TLS material →
/// [`build_backend`] → hot-reload / metrics → [`open_slashing_db`] → one shared
/// gate → [`spawn_http_api`] + [`build_grpc_router`] → serve until `shutdown`.
///
/// When `shutdown` fires, HTTP stops accepting (and open keep-alive connections
/// stop taking new requests) before the gRPC drain starts. The reloader,
/// metrics server, and HTTP listener are then joined. That whole shutdown is
/// bounded by [`SHUTDOWN_DEADLINE`] (20s). The same deadline also bounds child
/// joins when `run_inner` fails without a cancel (startup / transport errors),
/// so a wedged reloader cannot hang `run` forever. If the reloader join or the
/// gRPC drain is still running at the deadline, owned children are aborted, a
/// warning is logged, and this returns [`ServerError::Runtime`]. Dropping the
/// gRPC serve future ends the drain wait; per-connection gRPC tasks are not
/// individually aborted here.
///
/// A panicking child is logged and returned as [`ServerError::Runtime`], which
/// the process maps to a non-zero exit. Dropping this future, or panicking
/// inside it, cancels and aborts every child.
pub async fn run(
    resolved: crate::config::ResolvedConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), ServerError> {
    let deadline = active_shutdown_deadline();
    let mut children = Children::default();
    let parent = shutdown.clone();
    let mut work = Box::pin(async {
        let result = run_inner(&mut children, resolved, shutdown).await;
        // Bound joins on every exit path (cancel, success, and run_inner Err).
        let joined = match tokio::time::timeout(deadline, children.shutdown()).await {
            Ok(joined) => joined,
            Err(_elapsed) => {
                warn!(
                    deadline_ms = deadline.as_millis() as u64,
                    "signer shutdown deadline exceeded; aborting remaining signer child tasks"
                );
                Err(ServerError::runtime(
                    "shutdown deadline exceeded; aborted remaining signer tasks",
                ))
            }
        };
        combine_shutdown(result, joined)
    });

    tokio::select! {
        biased;
        result = &mut work => result,
        _ = parent.cancelled() => {
            match tokio::time::timeout(deadline, &mut work).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    warn!(
                        deadline_ms = deadline.as_millis() as u64,
                        "signer shutdown deadline exceeded; dropping gRPC serve and aborting owned children"
                    );
                    // Dropping `work` aborts a child mid-join. `children` then
                    // drops and aborts anything shutdown had not taken yet.
                    drop(work);
                    Err(ServerError::runtime(
                        "shutdown deadline exceeded; aborted remaining signer tasks",
                    ))
                }
            }
        }
    }
}

fn active_shutdown_deadline() -> Duration {
    #[cfg(test)]
    if let Some(deadline) = tests::deadline_override() {
        return deadline;
    }
    SHUTDOWN_DEADLINE
}

fn combine_shutdown(
    result: Result<(), ServerError>,
    joined: Result<(), ServerError>,
) -> Result<(), ServerError> {
    match (result, joined) {
        (Ok(()), joined) => joined,
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(child)) => {
            error!(
                error = %child,
                "signer child failed while the server was already returning an error"
            );
            Err(err)
        }
    }
}

async fn run_inner(
    children: &mut Children,
    resolved: crate::config::ResolvedConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), ServerError> {
    // Install the rustls crypto provider before any TLS work. Idempotent and
    // safe even with HTTP disabled. Forward-defense (ADR-006, R1): pins a single
    // explicit default so the Phase-3 `ServerConfig::builder()` path stays
    // deterministic and never hits rustls's automatic resolution, which panics
    // if the feature graph ever compiles in more than one provider. Not
    // load-bearing in today's ring-only build; see http_api::tls_config for details.
    http_api::tls_config::install_crypto_provider();

    info!(
        listen_address = %resolved.listen_address,
        keystore_dir = %resolved.keystore_dir.display(),
        backend = %resolved.backend,
        "Starting rvc-signer"
    );

    let password = config::load_serve_password(&resolved).map_err(ServerError::config)?;

    let tls_config = match (
        resolved.tls_cert.as_ref(),
        resolved.tls_key.as_ref(),
        resolved.tls_ca_cert.as_ref(),
    ) {
        (Some(cert), Some(key), Some(ca)) => {
            Some(crate::grpc_tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()))
        }
        _ => None,
    };

    // Set up Prometheus metrics early so DVT backend can use them
    let signer_metrics = Arc::new(metrics::SignerMetrics::new());

    // Build the signing backend and optional share-map for the PeerSignerService.
    // The PeerSignerService is constructed later (after the slashing DB is opened),
    // so build_backend returns the raw share_map / allow-list rather than a complete
    // service. Allow-list is loaded ONCE inside build_backend (ISSUE-4.1 / L-1).
    let built = build_backend(&resolved, &signer_metrics, &password, tls_config.as_ref()).await?;
    let signing_backend = built.signing_backend;
    let basic_signer_ref = built.basic_signer;
    #[cfg(feature = "dvt")]
    let dvt_share_map_opt = built.dvt_share_map;
    #[cfg(feature = "dvt")]
    let dvt_allow_list_opt = built.dvt_allow_list;

    // Validate TLS certificates if provided
    if let Some(ref tls) = tls_config {
        tls.to_server_tls_config().map_err(|e| ServerError::tls(e.to_string()))?;
    }

    if resolved.dry_run {
        println!("Configuration valid:");
        println!("  Backend: {}", resolved.backend);
        println!("  Keys loaded: {}", signing_backend.public_keys().len());
        if tls_config.is_some() {
            println!("  TLS: certificates valid");
        } else {
            println!("  TLS: disabled");
        }
        #[cfg(feature = "dvt")]
        if matches!(resolved.backend, config::Backend::Dvt) {
            println!("  DVT peers: {}", resolved.dvt_peers.len());
            if let Some(threshold) = resolved.dvt_threshold {
                println!("  DVT threshold: {}", threshold);
            }
            if let Some(index) = resolved.dvt_index {
                println!("  DVT index: {}", index);
            }
        }
        return Ok(());
    }

    // ISSUE-4.6 / L-6: keystore hot-reload is opt-in.  The reloader is only
    // spawned when `--enable-hot-reload` is set (or the equivalent TOML key
    // is true) AND `reload_interval_secs > 0`.  Each reload pass also
    // enforces a strict 0o700 / signer-UID-owned directory check before
    // touching keys (see `reload.rs::scan_and_reload`).
    if let Some(ref basic_signer) = basic_signer_ref {
        if resolved.enable_hot_reload && resolved.reload_interval_secs > 0 {
            let reloader = reload::KeystoreReloader::new(
                resolved.keystore_dir.clone(),
                password.clone(),
                std::time::Duration::from_secs(resolved.reload_interval_secs),
                Arc::clone(basic_signer),
            );

            // Parent cancel propagates through `child_token`. Shutdown cancels
            // the same token so a startup or transport error stops the reloader too.
            let reloader_cancel = shutdown.child_token();
            let cancel_for_task = reloader_cancel.clone();
            let reloader_handle = tokio::spawn(async move {
                reloader.run(cancel_for_task).await;
            });
            // A scan that blocks in synchronous keystore I/O never observes
            // cancel. The test task stands in for that hang.
            #[cfg(test)]
            let reloader_handle = if tests::wedge_reloader() {
                reloader_handle.abort();
                tokio::spawn(async {
                    std::future::pending::<()>().await;
                })
            } else {
                reloader_handle
            };
            #[cfg(test)]
            tests::note_reloader(&reloader_handle, &reloader_cancel);
            children.reloader = Some(reloader_handle);
            children.reloader_cancel = Some(reloader_cancel);

            info!(
                interval_secs = resolved.reload_interval_secs,
                "Keystore hot-reload enabled (--enable-hot-reload)"
            );
        } else if resolved.reload_interval_secs > 0 {
            // Operators upgrading from a previous release where the reloader
            // ran by default with a 30s interval will see this notice once
            // at startup if they had a non-zero interval configured.
            info!(
                "Keystore hot-reload disabled (set --enable-hot-reload to opt in; \
                 ISSUE-4.6 / L-6)"
            );
        }
    }

    // Set up Prometheus metrics server
    let key_count = signing_backend.public_keys().len() as f64;
    let backend_label = resolved.backend.as_str();
    signer_metrics.keys_loaded.with_label_values(&[backend_label]).set(key_count);

    let metrics_addr: std::net::SocketAddr = resolved
        .metrics_address
        .parse()
        .map_err(|e| ServerError::bind(format!("invalid metrics address: {e}")))?;
    let (metrics_handle, metrics_bound_addr) =
        metrics::serve_metrics(metrics_addr, Arc::clone(&signer_metrics))
            .await
            .map_err(|e| ServerError::bind(e.to_string()))?;
    #[cfg(test)]
    tests::note_metrics(&metrics_handle, metrics_bound_addr);
    children.metrics = Some(metrics_handle);
    info!(address = %metrics_bound_addr, "Prometheus metrics server listening");

    let slashing_db_opt = open_slashing_db(&resolved)?;

    // Build the v2 service implementation (RF2-17: v1 proto surface is gone).
    // Hoist (ADR-003, FR-26): build the ONE shared `SigningGate` at the
    // composition root, then inject the same `Arc` into BOTH the gRPC service and
    // the HTTP listener (Issue 3.5). `None` when slashing protection is disabled
    // (the gRPC `new()` path and the HTTP no-gate refusal below both handle it).
    let shared_gate: Option<Arc<signer::SigningGate>> = slashing_db_opt.as_ref().map(|db| {
        Arc::new(service::SignerServiceImpl::build_gate(
            Arc::clone(&signing_backend),
            Arc::clone(db),
        ))
    });

    // SEC-4: optional primary-path client-CN allow-list. When unset, warn and
    // accept any mTLS client (backward compatible). mTLS still mandatory.
    let client_cn_allow_list: Option<Arc<crate::audit::ClientCnAllowList>> =
        if let Some(path) = resolved.allowed_client_cns.as_deref() {
            let list = crate::audit::ClientCnAllowList::load_from_path(path).map_err(|e| {
                ServerError::config(format!("failed to load client-CN allow-list: {e}"))
            })?;
            info!(
                path = %path.display(),
                client_count = list.len(),
                "Loaded primary client-CN allow-list (SEC-4)"
            );
            Some(Arc::new(list))
        } else {
            crate::audit::log_missing_client_cn_allow_list_warning();
            None
        };

    // Build the gRPC router first (TLS / H-9 insecure gate / services) so a
    // transport-config failure never leaves an HTTP listener half-started.
    let built_grpc = build_grpc_router(grpc::GrpcRouterDeps {
        resolved: &resolved,
        tls_config: tls_config.as_ref(),
        signing_backend: Arc::clone(&signing_backend),
        shared_gate: shared_gate.clone(),
        client_cn_allow_list: client_cn_allow_list.clone(),
        signer_metrics: Arc::clone(&signer_metrics),
        slashing_db: slashing_db_opt,
        #[cfg(feature = "dvt")]
        dvt_share_map: dvt_share_map_opt,
        #[cfg(feature = "dvt")]
        dvt_allow_list: dvt_allow_list_opt,
    })?;

    // ── Web3Signer HTTP API listener (Issue 3.5, FR-25/26/27, ADR-001) ────────
    //
    // Opt-in via `[signer.http]`; gRPC stays default-on and unchanged. The HTTP
    // state carries the SAME `Arc<SigningGate>` injected into the gRPC service
    // (FR-26), so slashing protection + the in-memory `ValidatorLockMap` are
    // unified across both transports. A panic in an HTTP connection task is
    // isolated and never touches the gRPC accept loop (Issue 3.3).
    //
    // The listening line is emitted by `http::log_http_listening` on the
    // `signer_server::server::http` target. This token is not a child of
    // `shutdown`: `serve_until_shutdown` cancels it only after the parent
    // fires and before the gRPC drain signal, so HTTP stops accepting first.
    let http_shutdown = tokio_util::sync::CancellationToken::new();
    let spawned_http = spawn_http_api(
        http::HttpApiDeps {
            resolved: &resolved,
            shared_gate,
            signing_backend: Arc::clone(&signing_backend),
            signer_metrics: Arc::clone(&signer_metrics),
            client_cn_allow_list,
        },
        http_shutdown.clone(),
    )
    .await?;
    if let Some(spawned) = spawned_http {
        // Target stays `signer_server::server::http` (the pre-move module path).
        http::log_http_listening(spawned.bound, resolved.http_tls_mode);
        #[cfg(test)]
        tests::note_http(&spawned.handle, spawned.bound, &http_shutdown);
        children.http = Some(spawned.handle);
        children.http_shutdown = Some(http_shutdown);
    }

    #[cfg(test)]
    tests::inject_panicking_child(children);
    #[cfg(test)]
    tests::maybe_panic_after_spawn();

    info!(address = %built_grpc.listen_addr, "gRPC server listening");

    // HTTP / reloader / metrics are joined by `Children::shutdown` after this
    // returns, including when `serve_with_shutdown` fails. Log-reload SIGHUP
    // stays owned by `main` (`init_logging`).
    serve_until_shutdown(
        built_grpc.router,
        built_grpc.listen_addr,
        shutdown,
        children.http_shutdown.clone(),
    )
    .await?;

    Ok(())
}

/// Stop HTTP accepts, then drain gRPC.
///
/// `http_shutdown` is cancelled when `shutdown` fires, and only then is the
/// gRPC drain signal cancelled. The HTTP accept loop stops new TCP accepts and
/// each open connection's hyper graceful shutdown disables keep-alive, so a
/// late `/sign` on an already-open connection is refused (connection closed).
/// In-flight HTTP requests still finish inside the HTTP task, bounded by
/// `DRAIN_TIMEOUT` and by [`SHUTDOWN_DEADLINE`].
async fn serve_until_shutdown(
    router: tonic::transport::server::Router,
    listen_addr: std::net::SocketAddr,
    shutdown: tokio_util::sync::CancellationToken,
    http_shutdown: Option<tokio_util::sync::CancellationToken>,
) -> Result<(), ServerError> {
    let grpc_shutdown = tokio_util::sync::CancellationToken::new();
    let grpc_stop = grpc_shutdown.clone();
    let mut serve = Box::pin(router.serve_with_shutdown(listen_addr, async move {
        grpc_shutdown.cancelled().await;
    }));

    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            if let Some(token) = &http_shutdown {
                token.cancel();
            }
            #[cfg(test)]
            tests::note_http_accepts_stopped();
            grpc_stop.cancel();
            #[cfg(test)]
            if tests::wedge_grpc_drain() {
                // Reach serve.await so the real drain path runs, then hang as if
                // a connection ignored the shutdown signal.
                let _ = serve.as_mut().await;
                std::future::pending::<()>().await;
            }
            serve.await.map_err(|e| ServerError::bind(e.to_string()))
        }
        result = &mut serve => result.map_err(|e| ServerError::bind(e.to_string())),
    }
}

#[cfg(test)]
// RF1-12: unit tests may mutate env via unsafe set_var/remove_var.
// await_holding_lock: ENV_LOCK intentionally serializes process-global env
// mutations across async tests (same pattern as main.rs logging tests).
#[allow(unsafe_code, clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::error::ServerError;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    /// Test-only view of child-task handles owned by `run`.
    ///
    /// Shutdown consumes each `JoinHandle`. These abort handles name the same
    /// tasks, so tests can call `is_finished` after `run` returns.
    #[derive(Clone, Default)]
    struct ChildProbe {
        reloader: Option<tokio::task::AbortHandle>,
        metrics: Option<tokio::task::AbortHandle>,
        http: Option<tokio::task::AbortHandle>,
        reloader_cancel: Option<CancellationToken>,
        http_shutdown: Option<CancellationToken>,
        http_addr: Option<std::net::SocketAddr>,
        metrics_addr: Option<std::net::SocketAddr>,
        shutdown_ran: bool,
        joined_reloader: bool,
        joined_metrics: bool,
        joined_http: bool,
        drop_guard_ran: bool,
        http_accepts_stopped: bool,
        wedge_reloader: bool,
        wedge_grpc_drain: bool,
        panic_child: Option<&'static str>,
        panic_after_spawn: bool,
        deadline: Option<Duration>,
    }

    tokio::task_local! {
        static CHILD_PROBE: Arc<Mutex<ChildProbe>>;
    }

    fn probe_snapshot(probe: &Arc<Mutex<ChildProbe>>) -> ChildProbe {
        probe.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(super) fn note_shutdown() {
        let _ = CHILD_PROBE.try_with(|probe| {
            probe.lock().unwrap_or_else(|e| e.into_inner()).shutdown_ran = true;
        });
    }

    pub(super) fn note_metrics(handle: &tokio::task::JoinHandle<()>, addr: std::net::SocketAddr) {
        let _ = CHILD_PROBE.try_with(|probe| {
            let mut slot = probe.lock().unwrap_or_else(|e| e.into_inner());
            slot.metrics = Some(handle.abort_handle());
            slot.metrics_addr = Some(addr);
        });
    }

    pub(super) fn note_http(
        handle: &tokio::task::JoinHandle<()>,
        addr: std::net::SocketAddr,
        shutdown: &CancellationToken,
    ) {
        let _ = CHILD_PROBE.try_with(|probe| {
            let mut slot = probe.lock().unwrap_or_else(|e| e.into_inner());
            slot.http = Some(handle.abort_handle());
            slot.http_addr = Some(addr);
            slot.http_shutdown = Some(shutdown.clone());
        });
    }

    pub(super) fn note_joined(name: &'static str) {
        let _ = CHILD_PROBE.try_with(|probe| {
            let mut slot = probe.lock().unwrap_or_else(|e| e.into_inner());
            match name {
                "reloader" => slot.joined_reloader = true,
                "metrics" => slot.joined_metrics = true,
                "http" => slot.joined_http = true,
                _ => {}
            }
        });
    }

    pub(super) fn note_drop_guard() {
        let _ = CHILD_PROBE.try_with(|probe| {
            probe.lock().unwrap_or_else(|e| e.into_inner()).drop_guard_ran = true;
        });
    }

    pub(super) fn note_http_accepts_stopped() {
        let _ = CHILD_PROBE.try_with(|probe| {
            probe.lock().unwrap_or_else(|e| e.into_inner()).http_accepts_stopped = true;
        });
    }

    pub(super) fn deadline_override() -> Option<Duration> {
        CHILD_PROBE
            .try_with(|probe| probe.lock().unwrap_or_else(|e| e.into_inner()).deadline)
            .ok()
            .flatten()
    }

    pub(super) fn wedge_reloader() -> bool {
        CHILD_PROBE
            .try_with(|probe| probe.lock().unwrap_or_else(|e| e.into_inner()).wedge_reloader)
            .unwrap_or(false)
    }

    pub(super) fn wedge_grpc_drain() -> bool {
        CHILD_PROBE
            .try_with(|probe| probe.lock().unwrap_or_else(|e| e.into_inner()).wedge_grpc_drain)
            .unwrap_or(false)
    }

    pub(super) fn maybe_panic_after_spawn() {
        let panic_now = CHILD_PROBE
            .try_with(|probe| probe.lock().unwrap_or_else(|e| e.into_inner()).panic_after_spawn)
            .unwrap_or(false);
        if panic_now {
            panic!("injected panic inside run");
        }
    }

    pub(super) fn inject_panicking_child(children: &mut Children) {
        let kind = CHILD_PROBE
            .try_with(|probe| probe.lock().unwrap_or_else(|e| e.into_inner()).panic_child)
            .ok()
            .flatten();
        let Some(kind) = kind else {
            return;
        };
        let handle = tokio::spawn(async move {
            panic!("injected {kind} child panic");
        });
        let previous = match kind {
            "reloader" => children.reloader.replace(handle),
            "metrics" => children.metrics.replace(handle),
            "http" => children.http.replace(handle),
            _ => {
                handle.abort();
                None
            }
        };
        if let Some(previous) = previous {
            previous.abort();
        }
    }

    pub(super) fn note_reloader(handle: &tokio::task::JoinHandle<()>, cancel: &CancellationToken) {
        let _ = CHILD_PROBE.try_with(|probe| {
            let mut slot = probe.lock().unwrap_or_else(|e| e.into_inner());
            slot.reloader = Some(handle.abort_handle());
            slot.reloader_cancel = Some(cancel.clone());
        });
    }

    fn assert_finished(handle: &Option<tokio::task::AbortHandle>, name: &str) {
        assert!(
            handle.as_ref().is_some_and(|h| h.is_finished()),
            "{name} child handle must be finished when run returns (present={}, finished={})",
            handle.is_some(),
            handle.as_ref().is_some_and(|h| h.is_finished()),
        );
    }

    fn assert_rebindable(addr: std::net::SocketAddr) {
        std::net::TcpListener::bind(addr).unwrap_or_else(|e| {
            panic!("listener {addr} must be rebindable after run returns: {e}")
        });
    }

    struct InsecureEnv {
        prev_signer: Option<String>,
        prev_allow: Option<String>,
    }

    impl InsecureEnv {
        fn enable() -> Self {
            let prev_signer = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
            let prev_allow = std::env::var("RVC_ALLOW_INSECURE").ok();
            unsafe {
                std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
                std::env::set_var("RVC_ALLOW_INSECURE", "true");
            }
            Self { prev_signer, prev_allow }
        }
    }

    impl Drop for InsecureEnv {
        fn drop(&mut self) {
            restore_env("RVC_SIGNER_ALLOW_INSECURE", self.prev_signer.as_deref());
            restore_env("RVC_ALLOW_INSECURE", self.prev_allow.as_deref());
        }
    }

    fn restore_env(key: &str, prev: Option<&str>) {
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    fn use_ephemeral_listeners(resolved: &mut ResolvedConfig) {
        resolved.metrics_address = "127.0.0.1:0".to_string();
        resolved.http_listen_address = "127.0.0.1:0".to_string();
    }

    fn enable_http(resolved: &mut ResolvedConfig, tmp: &TempDir) {
        let pki = rvc_test_support::TestPki::generate(rvc_test_support::TestPkiParams {
            ca_name: "rvc-signer-ca".to_string(),
            server_sans: vec!["localhost".to_string()],
            client_name: "rvc-client".to_string(),
        });
        let paths = pki.write_server_pem(tmp.path());
        resolved.http_enabled = true;
        resolved.http_tls_mode = HttpTlsMode::Mtls;
        resolved.http_tls_cert = Some(paths.cert);
        resolved.http_tls_key = Some(paths.key);
        resolved.http_tls_ca_cert = Some(paths.ca_cert);
        resolved.init_slashing_db = true;
        resolved.disable_slashing_protection = false;
    }

    /// Slashing off, metrics and gRPC on port 0, HTTP left disabled.
    fn live_resolved(tmp: &TempDir) -> ResolvedConfig {
        let mut resolved = base_resolved(tmp);
        resolved.listen_address = "127.0.0.1:0".to_string();
        resolved.metrics_address = "127.0.0.1:0".to_string();
        resolved.disable_slashing_protection = true;
        resolved.init_slashing_db = false;
        resolved
    }

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        listener.local_addr().expect("local_addr").port()
    }

    fn create_keystore(dir: &std::path::Path, password: &str) {
        use crypto::{EncryptionKdf, Keystore, SecretKey};
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let ks = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let filename = format!("{}.json", hex::encode(pubkey));
        std::fs::write(dir.join(filename), ks.to_json().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// Build a minimal `ResolvedConfig` pointing at a temp keystore + password.
    fn base_resolved(tmp: &TempDir) -> ResolvedConfig {
        let keystore_dir = tmp.path().join("keystores");
        std::fs::create_dir(&keystore_dir).unwrap();
        let password = "test-password";
        create_keystore(&keystore_dir, password);
        let password_file = tmp.path().join("password.txt");
        std::fs::write(&password_file, password).unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();
        let listen = free_port();
        let metrics = free_port();

        ResolvedConfig {
            listen_address: format!("127.0.0.1:{listen}"),
            keystore_dir,
            password_file: Some(password_file),
            backend: Backend::Basic,
            dry_run: false,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            reload_interval_secs: 0,
            enable_hot_reload: false,
            dvt_peers: vec![],
            dvt_threshold: None,
            dvt_index: None,
            dvt_timeout_ms: 2000,
            http_enabled: false,
            http_listen_address: "127.0.0.1:9000".to_string(),
            http_tls_mode: HttpTlsMode::Mtls,
            http_tls_cert: None,
            http_tls_key: None,
            http_tls_ca_cert: None,
            genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
            insecure: true,
            data_dir: Some(data_dir),
            disable_slashing_protection: false,
            init_slashing_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            gloas_fork_epoch: u64::MAX,
            metrics_address: format!("127.0.0.1:{metrics}"),
            enable_log_reload: false,
            allowed_client_cns: None,
            #[cfg(feature = "dvt")]
            dvt_allowed_peers: None,
        }
    }

    /// Missing slashing DB without `--init-slashing-db` → `ServerError::SlashingDb`.
    #[tokio::test]
    async fn test_server_run_returns_slashing_db_error_variant_on_missing_db() {
        let _g = env_lock();
        let prev = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true") };

        let tmp = TempDir::new().unwrap();
        let resolved = base_resolved(&tmp);
        // data_dir exists, but no signer-slashing.db and init_slashing_db=false.
        assert!(!resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        let shutdown = CancellationToken::new();
        let err = run(resolved, shutdown).await.expect_err("must refuse missing slashing DB");
        assert!(
            matches!(err, ServerError::SlashingDb(_)),
            "expected SlashingDb variant, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist") || msg.contains("slashing"),
            "message should mention missing DB: {msg}"
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
    }

    /// `server::run` is callable in-process (no subprocess) and returns Ok on cancel.
    #[tokio::test]
    async fn test_server_run_is_callable_in_process() {
        let _g = env_lock();
        let prev_signer = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        let prev_allow = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe {
            std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
            std::env::set_var("RVC_ALLOW_INSECURE", "true");
        }

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        // Disable slashing so we can start without a DB for a short-lived smoke.
        resolved.disable_slashing_protection = true;
        resolved.init_slashing_db = false;

        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let handle = tokio::spawn(async move { run(resolved, shutdown2).await });

        // Give the server a moment to bind, then cancel.
        tokio::time::sleep(Duration::from_millis(300)).await;
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("join timed out")
            .expect("task panicked");
        assert!(result.is_ok(), "in-process run should shut down cleanly: {result:?}");

        match prev_signer {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
        match prev_allow {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    /// Cancelling the token stops `server::run` without error.
    #[tokio::test]
    async fn test_server_run_shuts_down_on_cancellation_token() {
        let _g = env_lock();
        let prev_signer = std::env::var("RVC_SIGNER_ALLOW_INSECURE").ok();
        let prev_allow = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe {
            std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
            std::env::set_var("RVC_ALLOW_INSECURE", "true");
        }

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.disable_slashing_protection = true;

        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let handle = tokio::spawn(async move { run(resolved, shutdown2).await });

        // Wait until metrics/gRPC ports are likely bound, then cancel.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Best-effort: cancel as soon as a little time has passed.
        }
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("join timed out")
            .expect("task panicked");
        assert!(result.is_ok(), "cancel should yield Ok: {result:?}");

        match prev_signer {
            Some(v) => unsafe { std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_SIGNER_ALLOW_INSECURE") },
        }
        match prev_allow {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    /// Process exit code for every `ServerError` class remains `1`.
    #[test]
    fn test_exit_codes_unchanged_for_each_failure_class() {
        // Mirrors `main::classify_exit_code` — every class exits 1 today.
        fn exit_code(err: &ServerError) -> i32 {
            match err {
                ServerError::SlashingDb(_)
                | ServerError::Backend(_)
                | ServerError::Tls(_)
                | ServerError::Bind(_)
                | ServerError::Config(_)
                | ServerError::Io(_)
                | ServerError::Runtime(_) => 1,
            }
        }

        let cases = [
            ServerError::slashing_db("missing db"),
            ServerError::backend("bad keystore"),
            ServerError::tls("bad cert"),
            ServerError::bind("addr in use"),
            ServerError::config("bad flag"),
            ServerError::Io(std::io::Error::other("io")),
            ServerError::runtime("child panicked"),
        ];
        for err in cases {
            assert_eq!(exit_code(&err), 1, "exit code changed for {err:?}");
        }
    }

    /// Dry-run path: callable without binding listeners.
    #[tokio::test]
    async fn test_server_run_dry_run_ok() {
        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.dry_run = true;
        // dry_run returns before TLS/slashing gates; insecure still fine.
        let shutdown = CancellationToken::new();
        run(resolved, shutdown).await.expect("dry_run should succeed");
    }

    /// gRPC transport error after both listeners are up: HTTP port is rebindable
    /// and both child handles are finished. Awaited on this test's runtime.
    #[tokio::test]
    async fn run_joins_both_children_on_the_grpc_error_path() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        use_ephemeral_listeners(&mut resolved);
        enable_http(&mut resolved, &tmp);
        // Invalid transport: the address parses, but the port is already bound,
        // so `serve_with_shutdown` fails after metrics and HTTP are spawned.
        let grpc_in_use = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy grpc port");
        let grpc_port = grpc_in_use.local_addr().expect("grpc local_addr").port();
        resolved.listen_address = format!("127.0.0.1:{grpc_port}");

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let shutdown = CancellationToken::new();
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                tokio::time::timeout(Duration::from_secs(10), run(resolved, shutdown)).await
            })
            .await;

        let result = outcome.expect("run must return on the gRPC transport error path");
        let err = result.expect_err("gRPC transport bind must fail");
        assert!(matches!(err, ServerError::Bind(_)), "expected Bind, got {err:?}");

        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "children.shutdown must run on the gRPC error path");
        assert_finished(&snap.metrics, "metrics");
        assert_finished(&snap.http, "http");
        let http_addr = snap.http_addr.expect("HTTP listener address");
        assert_rebindable(http_addr);
        drop(grpc_in_use);
    }

    /// Success path: cancel the parent, `run` returns `Ok`, shutdown joined metrics.
    #[tokio::test]
    async fn run_shutdown_joins_children_on_the_success_path() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = live_resolved(&tmp);

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let probe_for_wait = Arc::clone(&probe);
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown.clone());
                tokio::pin!(run_fut);
                let started = Instant::now();
                loop {
                    tokio::select! {
                        result = &mut run_fut => {
                            panic!("run returned before the metrics child was observed: {result:?}");
                        }
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {
                            if probe_snapshot(&probe_for_wait).metrics.is_some() {
                                break;
                            }
                            if started.elapsed() >= Duration::from_secs(10) {
                                panic!("timed out waiting for the metrics child to be owned");
                            }
                        }
                    }
                }
                shutdown.cancel();
                tokio::time::timeout(Duration::from_secs(10), run_fut).await
            })
            .await;

        let result = outcome.expect("run must return after parent cancel");
        assert!(result.is_ok(), "success path should shut down cleanly: {result:?}");
        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "children.shutdown must run on the success path");
        assert_finished(&snap.metrics, "metrics");
        assert_rebindable(snap.metrics_addr.expect("metrics listener address"));
    }

    /// `run_inner` failing after a wedged reloader is still bounded by the deadline.
    ///
    /// The deadline must cover the error/startup-failure join path, not only the
    /// cancel path: a reloader stuck in sync I/O ignores cancel, and without a
    /// bound `run` would never return.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn run_returns_err_within_deadline_when_run_inner_fails_with_wedged_reloader() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.metrics_address = "127.0.0.1:0".to_string();
        resolved.enable_hot_reload = true;
        resolved.reload_interval_secs = 30;
        // Fail after the reloader (and metrics) are spawned.
        resolved.disable_slashing_protection = false;
        resolved.init_slashing_db = false;
        assert!(!resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        let probe = Arc::new(Mutex::new(ChildProbe {
            wedge_reloader: true,
            deadline: Some(Duration::from_millis(200)),
            ..ChildProbe::default()
        }));
        let shutdown = CancellationToken::new();
        // Do NOT cancel: this is the error path, not the signal path.
        let started = Instant::now();
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                tokio::time::timeout(Duration::from_secs(2), run(resolved, shutdown)).await
            })
            .await;

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "wedged reloader on the error path must not stall run: {elapsed:?}"
        );
        let result = outcome.expect("run must return within the outer test timeout");
        let err = result.expect_err("run_inner failure with a wedged reloader must surface");
        // combine_shutdown prefers the run_inner error when both fail.
        assert!(
            matches!(err, ServerError::SlashingDb(_)),
            "expected the run_inner SlashingDb error, got {err:?}"
        );
        assert!(
            logs_contain("shutdown deadline exceeded"),
            "deadline expiry must be logged on the error-path join"
        );
        let snap = probe_snapshot(&probe);
        expect_abort_finished("reloader", &snap.reloader).await;
        expect_abort_finished("metrics", &snap.metrics).await;
    }

    /// A `?` inside `run_inner` (missing slashing DB, after metrics is spawned)
    /// still runs shutdown and joins that child.
    #[tokio::test]
    async fn run_shutdown_joins_children_on_run_inner_error_path() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.metrics_address = "127.0.0.1:0".to_string();
        resolved.disable_slashing_protection = false;
        resolved.init_slashing_db = false;
        assert!(!resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let shutdown = CancellationToken::new();
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                tokio::time::timeout(Duration::from_secs(10), run(resolved, shutdown)).await
            })
            .await;

        let result = outcome.expect("run must return when run_inner hits ?");
        let err = result.expect_err("missing slashing DB");
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");

        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "children.shutdown must run on a ? inside run_inner");
        assert_finished(&snap.metrics, "metrics");
        assert_rebindable(snap.metrics_addr.expect("metrics listener address"));
    }

    /// `reloader_cancel` is a `child_token()` of `shutdown`: cancelling the
    /// parent stops the reloader before `Children::shutdown` runs.
    #[tokio::test]
    async fn cancelling_the_parent_shutdown_token_stops_the_reloader() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let mut resolved = live_resolved(&tmp);
        resolved.enable_hot_reload = true;
        // Longer than this test's wait, so the reloader sits in `select` until cancelled.
        resolved.reload_interval_secs = 30;

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let probe_for_wait = Arc::clone(&probe);
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown.clone());
                tokio::pin!(run_fut);
                let started = Instant::now();
                let token = loop {
                    tokio::select! {
                        result = &mut run_fut => {
                            panic!("run returned before the reloader token was observed: {result:?}");
                        }
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {
                            if let Some(token) = probe_snapshot(&probe_for_wait).reloader_cancel.clone()
                            {
                                break token;
                            }
                            if started.elapsed() >= Duration::from_secs(10) {
                                panic!("timed out waiting for the reloader cancellation token");
                            }
                        }
                    }
                };
                assert!(!token.is_cancelled(), "reloader must still be running");
                // No await between cancel and the assert: shutdown has not run yet,
                // so only a child token of `shutdown` is cancelled here.
                shutdown.cancel();
                assert!(
                    token.is_cancelled(),
                    "cancelling the parent shutdown token must stop the reloader"
                );
                tokio::time::timeout(Duration::from_secs(10), run_fut).await
            })
            .await;

        let result = outcome.expect("run must return after the reloader is cancelled");
        assert!(result.is_ok(), "parent cancel should yield Ok: {result:?}");
        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "children.shutdown must run after the reloader stops");
        assert_finished(&snap.reloader, "reloader");
    }

    /// Metrics has no cooperative stop. Abort bounds the join so `run` returns
    /// while that child is wedged in `accept`.
    #[tokio::test]
    async fn wedged_metrics_child_is_bounded_by_abort() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = live_resolved(&tmp);
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                tokio::time::timeout(Duration::from_secs(10), run(resolved, shutdown)).await
            })
            .await;

        let result = outcome
            .expect("wedged metrics child must not hang run; abort then join bounds shutdown");
        assert!(result.is_ok(), "aborting the wedged metrics task still returns Ok: {result:?}");
        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "children.shutdown must abort the wedged metrics child");
        assert_finished(&snap.metrics, "metrics");
        assert_rebindable(snap.metrics_addr.expect("metrics listener address"));
    }

    async fn wait_for_probe(
        probe: &Arc<Mutex<ChildProbe>>,
        run_fut: &mut std::pin::Pin<&mut impl Future<Output = Result<(), ServerError>>>,
        ready: impl Fn(&ChildProbe) -> bool,
        what: &str,
    ) {
        let started = Instant::now();
        loop {
            tokio::select! {
                result = run_fut.as_mut() => {
                    panic!("{what}: run returned early: {result:?}");
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    if ready(&probe_snapshot(probe)) {
                        return;
                    }
                    if started.elapsed() >= Duration::from_secs(10) {
                        panic!("timed out waiting for {what}");
                    }
                }
            }
        }
    }

    async fn expect_abort_finished(name: &str, handle: &Option<tokio::task::AbortHandle>) {
        let started = Instant::now();
        loop {
            if handle.as_ref().is_some_and(|h| h.is_finished()) {
                return;
            }
            if started.elapsed() >= Duration::from_secs(2) {
                assert_finished(handle, name);
            }
            tokio::task::yield_now().await;
        }
    }

    fn http_and_reloader(tmp: &TempDir) -> ResolvedConfig {
        let mut resolved = base_resolved(tmp);
        resolved.listen_address = "127.0.0.1:0".to_string();
        use_ephemeral_listeners(&mut resolved);
        enable_http(&mut resolved, tmp);
        resolved.enable_hot_reload = true;
        resolved.reload_interval_secs = 30;
        resolved
    }

    /// Shutdown returns within the deadline when the reloader never observes cancel.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn shutdown_finishes_when_the_reloader_hangs() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let mut resolved = live_resolved(&tmp);
        resolved.enable_hot_reload = true;
        resolved.reload_interval_secs = 30;

        let probe = Arc::new(Mutex::new(ChildProbe {
            wedge_reloader: true,
            deadline: Some(Duration::from_millis(200)),
            ..ChildProbe::default()
        }));
        let probe_for_wait = Arc::clone(&probe);
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown.clone());
                tokio::pin!(run_fut);
                wait_for_probe(
                    &probe_for_wait,
                    &mut run_fut,
                    |snap| snap.reloader.is_some(),
                    "reloader",
                )
                .await;
                let started = Instant::now();
                shutdown.cancel();
                let result = tokio::time::timeout(Duration::from_secs(2), run_fut).await;
                (result, started.elapsed())
            })
            .await;

        let (result, elapsed) = outcome;
        assert!(
            elapsed < Duration::from_secs(2),
            "hung reloader must not stall shutdown: {elapsed:?}"
        );
        let result = result.expect("shutdown deadline must bound a hung reloader");
        let err = result.expect_err("aborting a hung reloader is a runtime error");
        assert!(matches!(err, ServerError::Runtime(_)), "expected Runtime, got {err:?}");
        assert!(
            err.to_string().contains("shutdown deadline"),
            "deadline must be named in the error: {err}"
        );
        assert!(logs_contain("shutdown deadline exceeded"), "deadline expiry must be logged");
        let snap = probe_snapshot(&probe);
        expect_abort_finished("reloader", &snap.reloader).await;
    }

    /// gRPC drain is inside the same deadline, and HTTP accepts stop first.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn shutdown_finishes_when_the_grpc_drain_hangs() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = http_and_reloader(&tmp);

        let probe = Arc::new(Mutex::new(ChildProbe {
            wedge_grpc_drain: true,
            deadline: Some(Duration::from_millis(200)),
            ..ChildProbe::default()
        }));
        let probe_for_wait = Arc::clone(&probe);
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown.clone());
                tokio::pin!(run_fut);
                wait_for_probe(
                    &probe_for_wait,
                    &mut run_fut,
                    |snap| snap.http_shutdown.is_some() && snap.reloader.is_some(),
                    "http and reloader",
                )
                .await;
                shutdown.cancel();
                let started = Instant::now();
                loop {
                    let snap = probe_snapshot(&probe_for_wait);
                    let http_stopped = snap.http_accepts_stopped
                        && snap.http_shutdown.as_ref().is_some_and(|token| token.is_cancelled());
                    if http_stopped {
                        break;
                    }
                    if started.elapsed() > Duration::from_millis(150) {
                        panic!(
                            "HTTP accepts must stop before a hung gRPC drain hits the deadline \
                             (stopped={}, cancelled={})",
                            snap.http_accepts_stopped,
                            snap.http_shutdown.as_ref().is_some_and(|token| token.is_cancelled()),
                        );
                    }
                    tokio::select! {
                        result = &mut run_fut => {
                            panic!("run returned before HTTP accepts stopped: {result:?}");
                        }
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                    }
                }
                let result = tokio::time::timeout(Duration::from_secs(2), run_fut).await;
                (result, started.elapsed())
            })
            .await;

        let (result, elapsed) = outcome;
        assert!(elapsed < Duration::from_secs(2), "hung gRPC drain stalled shutdown: {elapsed:?}");
        let result = result.expect("shutdown deadline must bound a hung gRPC drain");
        let err = result.expect_err("aborting a hung gRPC drain is a runtime error");
        assert!(
            err.to_string().contains("shutdown deadline"),
            "deadline must be named in the error: {err}"
        );
        assert!(logs_contain("shutdown deadline exceeded"));
        let snap = probe_snapshot(&probe);
        expect_abort_finished("reloader", &snap.reloader).await;
        expect_abort_finished("metrics", &snap.metrics).await;
        expect_abort_finished("http", &snap.http).await;
    }

    /// The deadline constant outlasts a healthy HTTP drain.
    #[test]
    fn shutdown_deadline_outlasts_the_http_drain() {
        assert!(
            SHUTDOWN_DEADLINE > crate::http_api::accept_loop::DRAIN_TIMEOUT,
            "shutdown deadline {:?} must exceed HTTP drain {:?}",
            SHUTDOWN_DEADLINE,
            crate::http_api::accept_loop::DRAIN_TIMEOUT,
        );
    }

    /// Each supervised child is joined on its own. Dropping one handle without
    /// awaiting it leaves that child's joined flag unset.
    #[tokio::test]
    async fn shutdown_joins_each_child_individually() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = http_and_reloader(&tmp);

        let probe = Arc::new(Mutex::new(ChildProbe::default()));
        let probe_for_wait = Arc::clone(&probe);
        let outcome = CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown.clone());
                tokio::pin!(run_fut);
                wait_for_probe(
                    &probe_for_wait,
                    &mut run_fut,
                    |snap| snap.reloader.is_some() && snap.metrics.is_some() && snap.http.is_some(),
                    "all children",
                )
                .await;
                shutdown.cancel();
                tokio::time::timeout(Duration::from_secs(10), run_fut).await
            })
            .await;

        let result = outcome.expect("run must return after joining each child");
        assert!(result.is_ok(), "clean shutdown should be Ok: {result:?}");
        let snap = probe_snapshot(&probe);
        assert!(snap.shutdown_ran, "shutdown must run");
        assert!(snap.joined_reloader, "reloader join was not observed");
        assert!(snap.joined_metrics, "metrics join was not observed");
        assert!(snap.joined_http, "http join was not observed");
        assert_finished(&snap.reloader, "reloader");
        assert_finished(&snap.metrics, "metrics");
        assert_finished(&snap.http, "http");
    }

    /// A panic in any child is an error from `run`, not a clean exit.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn panicking_child_makes_run_return_an_error() {
        for child in ["reloader", "metrics", "http"] {
            let _g = env_lock();
            let _env = InsecureEnv::enable();
            let tmp = TempDir::new().unwrap();
            let resolved = live_resolved(&tmp);
            let probe = Arc::new(Mutex::new(ChildProbe {
                panic_child: Some(child),
                ..ChildProbe::default()
            }));
            let probe_for_wait = Arc::clone(&probe);
            let outcome = CHILD_PROBE
                .scope(Arc::clone(&probe), async move {
                    let shutdown = CancellationToken::new();
                    let run_fut = run(resolved, shutdown.clone());
                    tokio::pin!(run_fut);
                    wait_for_probe(
                        &probe_for_wait,
                        &mut run_fut,
                        |snap| snap.metrics.is_some(),
                        "metrics",
                    )
                    .await;
                    shutdown.cancel();
                    tokio::time::timeout(Duration::from_secs(10), run_fut).await
                })
                .await;

            let result = outcome.expect("run must return after a child panic");
            let err = match result {
                Ok(value) => {
                    panic!("panicking {child} must make run return an error, got Ok({value:?})")
                }
                Err(err) => err,
            };
            assert!(matches!(err, ServerError::Runtime(_)), "{child}: {err:?}");
            let msg = err.to_string();
            assert!(msg.contains("panicked"), "{child} error should name the panic: {msg}");
            assert!(msg.contains(child), "{child} error should name that child: {msg}");
            assert!(logs_contain("signer child task panicked"), "{child} panic must be logged");
            assert!(logs_contain(child), "{child} panic log must name that child");
        }
    }

    /// Dropping `run` cancels and aborts every child without the async join.
    #[tokio::test]
    async fn dropping_run_cancels_every_child() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = http_and_reloader(&tmp);
        let probe =
            Arc::new(Mutex::new(ChildProbe { wedge_reloader: true, ..ChildProbe::default() }));
        let probe_for_wait = Arc::clone(&probe);
        CHILD_PROBE
            .scope(Arc::clone(&probe), async move {
                // The block owns `run`. Leaving it drops the future, which is
                // the Drop-guard path (no async shutdown join).
                let shutdown = CancellationToken::new();
                let run_fut = run(resolved, shutdown);
                tokio::pin!(run_fut);
                wait_for_probe(
                    &probe_for_wait,
                    &mut run_fut,
                    |snap| snap.reloader.is_some() && snap.metrics.is_some() && snap.http.is_some(),
                    "all children",
                )
                .await;
            })
            .await;

        let snap = probe_snapshot(&probe);
        assert!(snap.drop_guard_ran, "Drop guard must run when run is dropped");
        assert!(!snap.shutdown_ran, "Drop must not depend on the async shutdown join");
        assert!(
            snap.reloader_cancel.as_ref().is_some_and(|token| token.is_cancelled()),
            "Drop must cancel the reloader"
        );
        assert!(
            snap.http_shutdown.as_ref().is_some_and(|token| token.is_cancelled()),
            "Drop must cancel HTTP accepts"
        );
        expect_abort_finished("reloader", &snap.reloader).await;
        expect_abort_finished("metrics", &snap.metrics).await;
        expect_abort_finished("http", &snap.http).await;
    }

    /// A panic inside `run` takes the same Drop guard as dropping the future.
    #[tokio::test]
    async fn panicking_run_cancels_every_child() {
        let _g = env_lock();
        let _env = InsecureEnv::enable();
        let tmp = TempDir::new().unwrap();
        let resolved = http_and_reloader(&tmp);
        let probe = Arc::new(Mutex::new(ChildProbe {
            wedge_reloader: true,
            panic_after_spawn: true,
            ..ChildProbe::default()
        }));
        let task = CHILD_PROBE.scope(Arc::clone(&probe), async move {
            let shutdown = CancellationToken::new();
            run(resolved, shutdown).await
        });
        let joined = tokio::spawn(task).await.expect_err("run must panic");
        assert!(joined.is_panic(), "run must panic");

        let snap = probe_snapshot(&probe);
        assert!(snap.drop_guard_ran, "Drop guard must run when run panics");
        assert!(!snap.shutdown_ran, "panic must not reach the async shutdown join");
        assert!(
            snap.reloader_cancel.as_ref().is_some_and(|token| token.is_cancelled()),
            "panic Drop must cancel the reloader"
        );
        assert!(
            snap.http_shutdown.as_ref().is_some_and(|token| token.is_cancelled()),
            "panic Drop must cancel HTTP accepts"
        );
        expect_abort_finished("reloader", &snap.reloader).await;
        expect_abort_finished("metrics", &snap.metrics).await;
        expect_abort_finished("http", &snap.http).await;
    }
}
