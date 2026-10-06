//! Full validator-client bootstrap composition.
//!
//! [`run`] is the library entry point for the production Start path: it chains
//! every bootstrap phase, spawns the duty orchestrator on [`TaskExecutor`], and
//! drains registered tasks tier-by-tier on SIGTERM or task panic (ARCH-2h).

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use bn_manager::{BeaconNodeClient, OperationTimeouts};
use metrics::{new_health_status, SharedHealthStatus};
use secret_provider::SecretProvider;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::executor::{ShutdownOutcome, ShutdownReason, ShutdownTier, TaskExecutor, TierBudget};
use super::tasks::{
    bind_required_listeners, spawn_background_tasks, spawn_sse_subscriber, spawn_sync_monitor,
};
use super::{
    build_services, connect_beacon, load_signing_keys, open_slashing_db, wire_signing_enablement,
    BeaconHandles, BootstrapError, EnablementHandles, LoadedKeys, ServiceHandles,
};
use crate::config::{redact_url, Config};
use crate::deletion_denylist::DeletionDenylist;
use crate::index_resolver::{spawn_index_resolver, IndexResolverDeps};
use crate::key_admission::{AdmissionSource, KeyAdmissionService};
use crate::keymanager_adapters::{spawn_keymanager_api, KeymanagerApiDeps};
use crate::orchestrator::OrchestratorHandle;
use crate::startup;

/// Binary-owned flags that are not part of [`Config`].
pub struct RunOptions {
    /// Fail startup on world-readable keystore/password files.
    pub strict_permissions: bool,
    /// Strict slashing-interchange import semantics.
    pub strict_slashing_semantics: bool,
    /// Per-operation BN HTTP timeouts (CLI overrides applied by the binary).
    pub timeouts: OperationTimeouts,
}

/// Compose all bootstrap phases and run until shutdown.
///
/// `executor` is the process [`TaskExecutor`] (shared with the binary for the
/// SIGHUP log-reload task). Cancel propagates via `executor.token()` to every
/// cooperative background task. `shutdown_rx` is the single `ShutdownReason`
/// receiver from [`TaskExecutor::new`]; a panicking registered task and an
/// operator SIGTERM/SIGINT enter the same drain path (ARCH-2h).
/// Logging guards stay owned by `main` and drop after this future resolves,
/// flushing pending records last.
///
/// # Errors
///
/// Returns [`BootstrapError`] for phase failures and for a panicking registered
/// task ([`BootstrapError::CriticalTaskFailed`], exit 16). Named `EXIT_*` codes
/// (10, 11, 13 unsupported-fork, 14 keystore-lock, 15 listener-bind,
/// 16 critical-task) are mapped by the synchronous binary `main` after the
/// Tokio runtime is dropped (ARCH-2i / NFR-3). `run` itself never calls
/// `process::exit`.
pub async fn run(
    config: Config,
    options: RunOptions,
    executor: TaskExecutor,
    shutdown_rx: mpsc::Receiver<ShutdownReason>,
) -> Result<(), BootstrapError> {
    let startup_time = std::time::Instant::now();
    let shutdown_token = executor.token();

    let redacted_nodes: Vec<String> =
        config.effective_beacon_nodes().iter().map(|u| redact_url(u)).collect();
    info!(
        beacon_url = %redact_url(&config.beacon_url),
        beacon_nodes = ?redacted_nodes,
        network = %config.network,
        metrics_address = %config.metrics_address,
        metrics_port = config.metrics_port,
        doppelganger_detection = config.doppelganger_detection,
        spec_version = eth_types::CONSENSUS_SPEC_VERSION,
        "Starting validator client"
    );

    let health_status = new_health_status();

    // Steps 1–2d: open slashing DB, integrity, permissions, keystore lock, denylist.
    let slashing_handles = match open_slashing_db(
        &config,
        options.strict_permissions,
        options.strict_slashing_semantics,
    ) {
        Ok(handles) => {
            update_health_slashing_db(&health_status, true).await;
            handles
        }
        Err(e) if e.is_keystore_locked() => {
            // No drain is required: this is steps 1–2d, before any task is spawned.
            // Synchronous main maps named BootstrapError codes (14 here) after
            // the runtime is dropped (ARCH-2i / NFR-3).
            return Err(e);
        }
        Err(e) => {
            if matches!(e, BootstrapError::Config(_)) {
                update_health_error(&health_status, format!("Slashing DB error: {}", e)).await;
            }
            return Err(e);
        }
    };
    let slashing_db = slashing_handles.db;
    let _keystore_lock_guard = slashing_handles.keystore_lock;
    let deletion_denylist = slashing_handles.denylist;

    // Steps 3–5: beacon client, BnManager, GVR, genesis gate, reachability.
    let beacon_handles =
        match connect_beacon(&config, options.timeouts.clone(), slashing_db.as_ref()).await {
            Ok(handles) => {
                update_health_beacon_connected(&health_status, true).await;
                handles
            }
            Err(e) => {
                if matches!(e, BootstrapError::Config(_)) {
                    update_health_error(&health_status, format!("Beacon client error: {}", e))
                        .await;
                }
                return Err(e);
            }
        };

    // RR1-08: bind metrics and, when enabled, keymanager before keystore
    // decryption. A port clash is ListenerBind (exit 15) and returns here,
    // before load_signing_keys and before the duty orchestrator is spawned.
    let listeners = bind_required_listeners(&config).await?;

    // Keystore-dir + secret providers + CompositeSigner + optional gRPC remote.
    let loaded_keys = match load_signing_keys(&config, &deletion_denylist).await {
        Ok(keys) => {
            update_health_validators(&health_status, keys.validator_count).await;
            keys
        }
        Err(e) => {
            if matches!(e, BootstrapError::Config(_)) {
                update_health_error(&health_status, format!("Key load error: {}", e)).await;
            }
            return Err(e);
        }
    };

    // Step 6: SEC-2b/2c enablement + liveness loop (P1-7 registered on executor).
    let enablement = wire_signing_enablement(
        &config,
        &loaded_keys,
        &beacon_handles,
        Arc::clone(&slashing_db),
        &executor,
    )
    .await?;

    // Step 7: remaining services (signer, D-3, fork gate, proposer, toggle).
    let services = build_services(
        &config,
        &loaded_keys,
        &enablement,
        &beacon_handles,
        Arc::clone(&slashing_db),
        options.timeouts,
    )
    .await?;

    let BeaconHandles {
        beacon_client: _,
        bn_manager,
        genesis_validators_root,
        genesis_validators_root_hex: _,
        genesis_time: _,
    } = beacon_handles;

    let LoadedKeys {
        composite_signer,
        validator_count: _,
        local_pubkeys,
        pubkey_map,
        secret_providers,
        grpc_signer: _grpc_remote_signer,
    } = loaded_keys;

    let EnablementHandles {
        signing_enablement: _,
        forward_window_machine,
        epoch_clock,
        pubkey_map: _,
        liveness_task: _,
        pubkey_index,
    } = enablement;

    let ServiceHandles {
        signer,
        quiesce_registry,
        validator_store,
        propagator,
        beacon,
        duty_tracker,
        slot_clock,
        orchestrator_config,
        proposer_bn_manager: _,
        block_beacon,
        builder_service,
        attesting_enabled,
    } = services;

    // RF1-06/07: single key-generation watch channel shared by keymanager
    // adapters (tx), the index resolver, and DutyOrchestrator (rx).
    let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);

    // ADR-R05: one index writer, including when doppelganger detection is off.
    spawn_index_resolver(
        IndexResolverDeps {
            registry: Arc::clone(&pubkey_index),
            pubkey_map: Arc::clone(&pubkey_map),
            beacon: Arc::clone(&bn_manager) as Arc<dyn BeaconNodeClient>,
            key_gen_tx: key_gen_tx.clone(),
            key_gen_rx: key_gen_rx.clone(),
            epoch_clock: Arc::clone(&epoch_clock),
        },
        &executor,
    );

    // ARCH-2c: single admission choke point for provider refresh + keymanager import.
    let admissions = Arc::new(KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        key_gen_tx.clone(),
        Arc::clone(&composite_signer),
        Arc::clone(&validator_store),
        Arc::clone(&deletion_denylist),
        forward_window_machine.clone(),
        Arc::clone(&epoch_clock),
    ));

    // ARCH-2a / VD-E1: refresh after key_gen_tx + validator_store are in scope
    // (RefreshService sleeps `interval` before first fetch — no startup timing change).
    // P1-5: secret-provider refresh on executor (Background).
    spawn_secret_provider_refresh(
        &config,
        secret_providers,
        local_pubkeys,
        Arc::clone(&deletion_denylist),
        Arc::clone(&admissions),
        &executor,
    );

    // Step 7c: optionally start Keymanager API (Ingress; ARCH-2g P1-6).
    let _keymanager_started = spawn_keymanager_api(
        &config,
        KeymanagerApiDeps {
            composite_signer: composite_signer.clone(),
            slashing_db: slashing_db.clone(),
            genesis_validators_root,
            validator_store: validator_store.clone(),
            // Pool, not the single-endpoint client: exit must fail over with the rest of the VC.
            beacon_client: bn_manager.clone(),
            signer: signer.clone(),
            fork_schedule: orchestrator_config.fork_schedule.clone(),
            deletion_denylist: Arc::clone(&deletion_denylist),
            attesting_enabled: attesting_enabled.clone(),
            forward_window_machine: forward_window_machine.clone(),
            epoch_clock: Arc::clone(&epoch_clock),
            pubkey_map: pubkey_map.clone(),
            key_gen_tx,
            admissions,
            quiesce_registry,
        },
        listeners.keymanager,
        &executor,
    )?;

    // Step 8: duty orchestrator.
    let circuit_breaker = std::sync::Arc::new(signer::CircuitBreakerState::new(
        config.builder_limits.circuit_breaker_consecutive_limit,
        config.builder_limits.circuit_breaker_epoch_limit,
    ));
    info!(
        consecutive_limit = config.builder_limits.circuit_breaker_consecutive_limit,
        epoch_limit = config.builder_limits.circuit_breaker_epoch_limit,
        "Builder circuit breaker configured"
    );

    let validator_count = pubkey_map.read().len();
    let bn_count = config.effective_beacon_nodes().len();
    // ARCH-3l/3i: register bn.sse (Background) and hand the gate to the slot loop.
    let head_gate = spawn_sse_subscriber(Some(Arc::clone(&bn_manager)), &executor)
        .unwrap_or_else(|| crate::orchestrator::HeadEventGate::pair().1);
    // DSR-2.1 / FR-P1-3: register bn.sync_monitor (Background).
    spawn_sync_monitor(Some(Arc::clone(&bn_manager)), &executor, None);
    let (mut orchestrator, orchestrator_handle) =
        crate::orchestrator::DutyOrchestrator::new(crate::orchestrator::OrchestratorDeps {
            clock: slot_clock,
            duty_tracker,
            signer,
            propagator,
            beacon: beacon.clone(),
            block_beacon,
            builder_service,
            validator_store: validator_store.clone(),
            config: orchestrator_config,
            pubkey_map: pubkey_map.clone(),
            pubkey_index,
            key_gen_rx,
            circuit_breaker,
            attesting_enabled: attesting_enabled.clone(),
            head_gate,
        });

    // Step 8b: slashing monitor (P1-8/P1-9 via register_opt / spawn).
    {
        let slashed_action = config.slashed_validators_action;
        crate::slashing_monitor::spawn(
            beacon.clone(),
            validator_store.clone(),
            slashed_action,
            &executor,
        );
        if slashed_action != crate::slashing_monitor::SlashedAction::None {
            info!(action = %slashed_action, "Slashing monitor started");
        }
    }

    finalize_health_status(&health_status).await;

    // P1-2/P1-3/P1-4: metrics + monitoring + proposer-config on executor.
    spawn_background_tasks(
        &config,
        listeners.metrics,
        health_status,
        &executor,
        pubkey_map.clone(),
        validator_store.clone(),
    )?;

    // Log broadcast topics if non-default (T3.4)
    {
        let topics = config.effective_broadcast_topics();
        info!(
            attestations = topics.attestations,
            blocks = topics.blocks,
            sync_committee = topics.sync_committee,
            subscriptions = topics.subscriptions,
            "Active broadcast topics"
        );
    }

    startup::log_orchestrator_started(validator_count, bn_count);
    info!("Starting duty orchestrator");

    // Spawn (not poll inline): in-flight publish survives the shutdown signal (M10).
    // detached: already a per-slot root inside the task (slot.process, crates/rvc/src/orchestrator/coordinator/mod.rs:490); not shape B.
    executor.spawn_result("duty_orchestrator", ShutdownTier::Orchestrator, async move {
        orchestrator.run().await
    });

    // Operator signal, panicking registered tasks, and internal token cancel
    // (e.g. slashing-monitor ShutdownRequested) converge on one drain path.
    let (outcome, res) = await_shutdown_and_drain(ShutdownInputs {
        executor,
        orchestrator_handle,
        shutdown_rx,
        shutdown_token,
        budget: TierBudget::default(),
    })
    .await;
    info!(
        joined = ?outcome.joined,
        aborted = ?outcome.aborted,
        "TaskExecutor drain complete"
    );

    info!(uptime_secs = startup_time.elapsed().as_secs(), "Validator client shut down complete");
    res?;
    Ok(())
}

/// Pieces the composition root hands to [`await_shutdown_and_drain`].
pub(crate) struct ShutdownInputs {
    /// Registered tasks, consumed by the tier drain.
    pub(crate) executor: TaskExecutor,
    /// Cooperative stop for the duty loop (watch channel, not the cancel token).
    pub(crate) orchestrator_handle: OrchestratorHandle,
    /// Panic and intentional-stop reasons from [`TaskExecutor`].
    pub(crate) shutdown_rx: mpsc::Receiver<ShutdownReason>,
    /// Process cancellation token (internal shutdown, e.g. slashing monitor).
    pub(crate) shutdown_token: CancellationToken,
    /// Per-tier join budgets for the drain.
    pub(crate) budget: TierBudget,
}

/// Wait until an operator signal, a [`ShutdownReason`], or token cancel, then
/// stop the duty loop and drain every registered task.
///
/// The drain finishes before this returns, on every arm.
/// [`ShutdownReason::Failure`] becomes [`BootstrapError::CriticalTaskFailed`]
/// (exit 16). Signal, token, and [`ShutdownReason::Success`] return `Ok`.
pub(crate) async fn await_shutdown_and_drain(
    inputs: ShutdownInputs,
) -> (ShutdownOutcome, Result<(), BootstrapError>) {
    await_shutdown_and_drain_with_signal(inputs, shutdown_signal()).await
}

/// Same as [`await_shutdown_and_drain`], with the operator-signal arm replaced.
///
/// Production passes [`shutdown_signal`]. Tests pass a ready or pending future
/// so the signal arm does not install a process-wide SIGINT handler.
async fn await_shutdown_and_drain_with_signal(
    inputs: ShutdownInputs,
    signal: impl Future<Output = ()>,
) -> (ShutdownOutcome, Result<(), BootstrapError>) {
    let ShutdownInputs { executor, orchestrator_handle, mut shutdown_rx, shutdown_token, budget } =
        inputs;

    let failed_task = tokio::select! {
        _ = signal => {
            info!("Shutdown signal received");
            startup::log_shutdown_initiated("signal received");
            None
        }
        reason = shutdown_rx.recv() => {
            match reason {
                Some(ShutdownReason::Failure(task)) => {
                    error!(task, "Registered task panicked; initiating process drain");
                    startup::log_shutdown_initiated("task failure");
                    Some(task)
                }
                Some(ShutdownReason::Success(msg)) => {
                    info!(reason = msg, "Shutdown reason received");
                    startup::log_shutdown_initiated(msg);
                    None
                }
                None => {
                    warn!("Shutdown reason channel closed");
                    startup::log_shutdown_initiated("shutdown channel closed");
                    None
                }
            }
        }
        _ = shutdown_token.cancelled() => {
            info!("Process cancellation token cancelled");
            startup::log_shutdown_initiated("token cancelled");
            None
        }
    };

    // Cooperative stop for the duty loop (watch channel, not the cancel token).
    orchestrator_handle.shutdown();
    // Cancels the process token once, then joins each tier under TierBudget.
    // No sleep-as-join: duty_orchestrator is in the registry and is joined here.
    let outcome = executor.shutdown(budget).await;
    let res = match failed_task {
        Some(task) => Err(BootstrapError::CriticalTaskFailed { task }),
        None => Ok(()),
    };
    (outcome, res)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C)");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
    }
}

// Health status update helpers (formerly binary-local). Safe RMW during sequential startup.
async fn update_health_beacon_connected(health_status: &SharedHealthStatus, connected: bool) {
    let mut status = health_status.write().await;
    status.beacon_connected = connected;
    status.update_healthy();
}

async fn update_health_validators(health_status: &SharedHealthStatus, count: usize) {
    let mut status = health_status.write().await;
    status.validators_loaded = count;
    status.update_healthy();
}

async fn update_health_slashing_db(health_status: &SharedHealthStatus, initialized: bool) {
    let mut status = health_status.write().await;
    status.slashing_db_initialized = initialized;
    status.update_healthy();
}

async fn update_health_error(health_status: &SharedHealthStatus, error: String) {
    let mut status = health_status.write().await;
    status.error = Some(error);
    status.healthy = false;
}

async fn finalize_health_status(health_status: &SharedHealthStatus) {
    let mut status = health_status.write().await;
    status.update_healthy();
    info!(healthy = status.healthy, "Health status finalized");
}

/// Spawn secret-provider refresh when configured and providers are present.
///
/// Relocated from `wire_signing_enablement` so `validator_store` and `key_gen_tx`
/// are in scope (ARCH-2a / VD-E1). ARCH-2c: callback is a single
/// [`KeyAdmissionService::admit`] with [`AdmissionSource::RawSecret`].
/// Denylist re-check lives inside `admit` (not duplicated here).
///
/// Returns whether a task was registered (ARCH-2g P1-5).
fn spawn_secret_provider_refresh(
    config: &Config,
    secret_providers: Vec<Arc<dyn SecretProvider>>,
    local_pubkeys: HashSet<[u8; 48]>,
    denylist: Arc<DeletionDenylist>,
    admissions: Arc<KeyAdmissionService>,
    executor: &TaskExecutor,
) -> bool {
    let refresh_interval = config.secret_provider.refresh_interval.unwrap_or(0);
    if refresh_interval > 0 && !secret_providers.is_empty() {
        let denylist_for_refresh = Arc::clone(&denylist);
        let is_denied: secret_provider::DenylistCheck =
            Arc::new(move |pk: &[u8; 48]| denylist_for_refresh.contains(pk));
        let refresh_service = secret_provider::RefreshService::with_denylist(
            secret_providers,
            local_pubkeys,
            Some(is_denied),
            std::time::Duration::from_secs(refresh_interval),
            executor.token(),
        );
        // detached: secret_provider::RefreshService::run; loop body is crates/secret-provider/src/refresh.rs:179, out of scope.
        executor.spawn("secret_provider_refresh", ShutdownTier::Background, async move {
            refresh_service
                .run(move |sk| {
                    // Denylist DELETE-races-refresh guard is inside admit.
                    let _ = admissions.admit(sk, AdmissionSource::RawSecret);
                })
                .await;
        });
        info!(interval_secs = refresh_interval, "Secret provider refresh task started");
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::{
        acquire_keystore_lock, EXIT_CRITICAL_TASK_FAILED, EXIT_GENESIS_ROOT_MISMATCH,
        EXIT_INTEGRITY_CHECK_FAILED, EXIT_KEYSTORE_LOCKED, EXIT_LISTENER_BIND,
        EXIT_UNSUPPORTED_FORK_VERSION,
    };
    use ::slashing::SlashingDb;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn short_budget() -> TierBudget {
        TierBudget::new([
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_millis(200),
        ])
    }

    /// RR1-06: a panicking registered task must surface as exit 16 after the drain.
    ///
    /// No beacon node, slashing database, or keys — only a registered task and the
    /// extracted shutdown tail.
    #[tokio::test]
    async fn await_shutdown_and_drain_returns_err_on_task_failure() {
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        executor.spawn("boom_task", ShutdownTier::Background, async {
            panic!("registered task failed");
        });

        let (outcome, res) = await_shutdown_and_drain(ShutdownInputs {
            executor,
            orchestrator_handle: OrchestratorHandle::for_drain_test(),
            shutdown_rx,
            shutdown_token: token,
            budget: short_budget(),
        })
        .await;

        assert!(
            matches!(res, Err(BootstrapError::CriticalTaskFailed { task: "boom_task" })),
            "expected CriticalTaskFailed(boom_task) with exit {EXIT_CRITICAL_TASK_FAILED}, got {res:?}; joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted,
        );
        let err = res.expect_err("task failure must not return Ok");
        assert_eq!(err.exit_code(), EXIT_CRITICAL_TASK_FAILED);
        assert_eq!(err.exit_code(), 16);
        assert!(
            outcome.joined.contains(&"boom_task") || outcome.aborted.contains(&"boom_task"),
            "drain must report boom_task in joined ({:?}) or aborted ({:?})",
            outcome.joined,
            outcome.aborted,
        );
    }

    /// RR1-09: `spawn_result` returning `Err` is exit 16 after the same drain.
    #[tokio::test]
    async fn await_shutdown_and_drain_returns_exit_16_on_spawn_result_error() {
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        executor.spawn_result("duty_orchestrator", ShutdownTier::Orchestrator, async {
            Err::<(), _>("orchestrator failed")
        });

        let (outcome, res) = await_shutdown_and_drain(ShutdownInputs {
            executor,
            orchestrator_handle: OrchestratorHandle::for_drain_test(),
            shutdown_rx,
            shutdown_token: token,
            budget: short_budget(),
        })
        .await;

        assert!(
            matches!(res, Err(BootstrapError::CriticalTaskFailed { task: "duty_orchestrator" })),
            "expected CriticalTaskFailed(duty_orchestrator) with exit {EXIT_CRITICAL_TASK_FAILED}, got {res:?}; joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted,
        );
        let err = res.expect_err("Ok(Err) must not return Ok");
        assert_eq!(err.exit_code(), EXIT_CRITICAL_TASK_FAILED);
        assert_eq!(err.exit_code(), 16);
        assert!(
            outcome.joined.contains(&"duty_orchestrator")
                || outcome.aborted.contains(&"duty_orchestrator"),
            "drain must report duty_orchestrator in joined ({:?}) or aborted ({:?})",
            outcome.joined,
            outcome.aborted,
        );
    }

    fn assert_ok_with_drain(outcome: &ShutdownOutcome, res: &Result<(), BootstrapError>) {
        assert!(res.is_ok(), "non-failure shutdown must stay Ok, got {res:?}");
        assert!(
            outcome.joined.contains(&"drain_probe") || outcome.aborted.contains(&"drain_probe"),
            "drain must report drain_probe in joined ({:?}) or aborted ({:?})",
            outcome.joined,
            outcome.aborted,
        );
    }

    fn probe_inputs(
        executor: TaskExecutor,
        shutdown_rx: mpsc::Receiver<ShutdownReason>,
        shutdown_token: CancellationToken,
    ) -> ShutdownInputs {
        ShutdownInputs {
            executor,
            orchestrator_handle: OrchestratorHandle::for_drain_test(),
            shutdown_rx,
            shutdown_token,
            budget: short_budget(),
        }
    }

    /// Signal shutdown still returns Ok, and the drain still runs.
    #[tokio::test]
    async fn await_shutdown_and_drain_returns_ok_on_signal() {
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        executor.spawn("drain_probe", ShutdownTier::Background, async {});
        let (outcome, res) = await_shutdown_and_drain_with_signal(
            probe_inputs(executor, shutdown_rx, token),
            std::future::ready(()),
        )
        .await;
        assert_ok_with_drain(&outcome, &res);
    }

    /// [`ShutdownReason::Success`] still returns Ok, and the drain still runs.
    #[tokio::test]
    async fn await_shutdown_and_drain_returns_ok_on_success_reason() {
        let token = CancellationToken::new();
        let (executor, _executor_rx) = TaskExecutor::new(token.clone());
        executor.spawn("drain_probe", ShutdownTier::Background, async {});
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(ShutdownReason::Success("operator stop")).expect("send success");
        let (outcome, res) = await_shutdown_and_drain_with_signal(
            probe_inputs(executor, rx, token),
            std::future::pending::<()>(),
        )
        .await;
        assert_ok_with_drain(&outcome, &res);
    }

    /// Token cancel still returns Ok, and the drain still runs.
    #[tokio::test]
    async fn await_shutdown_and_drain_returns_ok_on_token_cancel() {
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        executor.spawn("drain_probe", ShutdownTier::Background, async {});
        token.cancel();
        let (outcome, res) = await_shutdown_and_drain_with_signal(
            probe_inputs(executor, shutdown_rx, token),
            std::future::pending::<()>(),
        )
        .await;
        assert_ok_with_drain(&outcome, &res);
    }

    /// ARCH-2i / NFR-3: pin EXIT_* numeric values so a silent renumber fails CI.
    #[test]
    fn test_exit_codes_are_unchanged() {
        assert_eq!(EXIT_INTEGRITY_CHECK_FAILED, 10);
        assert_eq!(EXIT_GENESIS_ROOT_MISMATCH, 11);
        assert_eq!(EXIT_UNSUPPORTED_FORK_VERSION, 13);
        assert_eq!(EXIT_KEYSTORE_LOCKED, 14);
        assert_eq!(EXIT_LISTENER_BIND, 15);
        assert_eq!(EXIT_CRITICAL_TASK_FAILED, 16);
        // Reserved historically (one-shot doppelganger); must not be reused.
        assert_ne!(EXIT_INTEGRITY_CHECK_FAILED, 12);
        assert_ne!(EXIT_GENESIS_ROOT_MISMATCH, 12);
        assert_ne!(EXIT_UNSUPPORTED_FORK_VERSION, 12);
        assert_ne!(EXIT_KEYSTORE_LOCKED, 12);
        assert_ne!(EXIT_LISTENER_BIND, 12);
        assert_ne!(EXIT_CRITICAL_TASK_FAILED, 12);
        let startup_src = include_str!("../startup.rs");
        assert!(
            startup_src
                .contains("EXIT 12 reserved historically for one-shot doppelganger detection"),
            "exit 12 must stay documented as reserved"
        );
        assert!(
            !startup_src.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("pub const EXIT_") && trimmed.contains("= 12")
            }),
            "exit 12 must stay unused"
        );
    }

    /// ARCH-2i: keystore-lock contention returns `Err` with EXIT_KEYSTORE_LOCKED
    /// rather than hard-exiting mid-async (which would kill the test binary).
    /// No tasks are spawned yet, so no drain is required.
    #[tokio::test]
    async fn test_keystore_lock_contention_returns_exit_code_not_process_exit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).expect("keystore dir");
        let db_path = dir.path().join("slashing.db");
        try_seed_slashing_db(&db_path);

        let _held = acquire_keystore_lock(&keystore).expect("hold keystore lock");

        let config = Config {
            beacon_url: "http://127.0.0.1:1".to_string(),
            keystore_path: keystore,
            slashing_db_path: db_path,
            allow_fresh_db: false,
            disable_keystore_locking: false,
            ..Default::default()
        };
        let options = RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: OperationTimeouts::default(),
        };

        let (executor, rx) = TaskExecutor::new(CancellationToken::new());
        let err = run(config, options, executor, rx)
            .await
            .expect_err("lock contention must return Err, not hard-exit the process");
        assert!(err.is_keystore_locked(), "expected keystore-locked BootstrapError, got: {err}");
        assert_eq!(
            err.exit_code(),
            EXIT_KEYSTORE_LOCKED,
            "operator tooling still sees exit code 14 (NFR-3)"
        );
    }

    fn try_seed_slashing_db(path: &std::path::Path) {
        SlashingDb::open(path).expect("seed slashing db");
    }

    /// ARCH-7d: bootstrap must not start a tonic server on the configured gRPC port.
    #[test]
    fn test_run_rs_does_not_start_a_grpc_server() {
        let src = include_str!("run.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body before tests");
        assert!(
            !body.contains("Starting gRPC server"),
            "bootstrap/run.rs must not start a tonic server (ARCH-7d)"
        );
        assert!(
            !body.contains("serve_with_shutdown"),
            "bootstrap/run.rs must not call tonic serve_with_shutdown (ARCH-7d)"
        );
    }

    /// RR1-08: required listeners bind after beacon connect and before keystore
    /// load, which is itself before the duty orchestrator spawn. A bind failure
    /// therefore returns from `run` before any orchestrator task exists.
    #[test]
    fn bind_required_listeners_precedes_keystore_load_and_orchestrator_spawn() {
        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production body before tests");
        let start = prod.find("pub async fn run(").expect("fn run");
        let rest = &prod[start..];
        let end = rest.find("pub(crate) struct ShutdownInputs").expect("end of run");
        let run_fn = &rest[..end];

        let connect_at = run_fn.find("connect_beacon(").expect("connect_beacon call");
        let bind_at =
            run_fn.find("bind_required_listeners(").expect("bind_required_listeners call");
        let keys_at = run_fn.find("load_signing_keys(").expect("load_signing_keys call");
        // Production spawn is `executor.spawn_result("duty_orchestrator"`.
        let orch_at = run_fn.find("\"duty_orchestrator\"").expect("duty_orchestrator spawn");

        assert!(connect_at < bind_at, "bind_required_listeners must follow connect_beacon");
        assert!(bind_at < keys_at, "bind_required_listeners must precede load_signing_keys");
        assert!(keys_at < orch_at, "load_signing_keys must precede the duty_orchestrator spawn");
    }

    /// ARCH-2i: production body of run.rs must not hard-exit the process.
    #[test]
    fn test_run_rs_has_no_process_exit_call() {
        let src = include_str!("run.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body before tests");
        // Match the call form only; prose may mention the historical bug.
        assert!(
            !body.contains("std::process::exit") && !body.contains("::exit("),
            "bootstrap/run.rs production body must not hard-exit the process (ARCH-2i)"
        );
    }

    /// ARCH-2h: no `sleep` may stand in for a join in the production body.
    #[test]
    fn test_run_rs_has_no_sleep_as_join_substitute() {
        let src = include_str!("run.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body before tests");
        assert!(
            !body.contains("tokio::time::sleep"),
            "bootstrap/run.rs must not use sleep as a join substitute (ARCH-2h / M10)"
        );
        assert!(
            body.contains("executor.shutdown"),
            "production shutdown must drain via TaskExecutor::shutdown"
        );
        assert!(
            body.contains("duty_orchestrator"),
            "orchestrator must be registered as duty_orchestrator"
        );
        assert!(
            body.contains("spawn_sse_subscriber"),
            "ARCH-3l must start the SSE subscriber from production run()"
        );
        assert!(body.contains("bn.sse"), "ARCH-3l must name the registered SSE task bn.sse");
        assert!(
            body.contains("spawn_sync_monitor"),
            "DSR-2.1 must start the sync monitor from production run()"
        );
        assert!(
            body.contains("bn.sync_monitor"),
            "DSR-2.1 must name the registered sync-monitor task bn.sync_monitor"
        );
    }

    fn test_admissions(
        dir: &tempfile::TempDir,
    ) -> (Arc<KeyAdmissionService>, Arc<DeletionDenylist>, crate::orchestrator::PubkeyMap) {
        use std::collections::HashMap;

        use crypto::CompositeSigner;
        use doppelganger::MonotonicEpochClock;
        use validator_store::ValidatorStore;

        let denylist = Arc::new(DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: crate::orchestrator::PubkeyMap =
            Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, _) = tokio::sync::watch::channel(0u64);
        let composite =
            Arc::new(CompositeSigner::new(crypto::LocalSigner::new(crypto::KeyManager::new())));
        let admissions = Arc::new(KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            composite,
            Arc::new(ValidatorStore::new([0u8; 20], 30_000_000)),
            Arc::clone(&denylist),
            None,
            Arc::new(MonotonicEpochClock::new(0)),
        ));
        (admissions, denylist, pubkey_map)
    }

    /// ARCH-2a: pin that refresh spawn accepts a fully-wired `KeyAdmissionService`
    /// (VD-E1 ordering — validator_store + key_gen must be constructible at the call site).
    #[tokio::test]
    async fn secret_provider_refresh_is_spawned_after_key_gen_channel_exists() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let config = Config {
            secret_provider: crate::config::SecretProviderConfig {
                refresh_interval: Some(60),
                ..Default::default()
            },
            ..Default::default()
        };
        let provider: Arc<dyn SecretProvider> = Arc::new(DummySecretProvider);
        let dir = tempfile::tempdir().unwrap();
        let (admissions, denylist, _) = test_admissions(&dir);

        let started = spawn_secret_provider_refresh(
            &config,
            vec![provider],
            HashSet::new(),
            denylist,
            admissions,
            &executor,
        );
        assert!(started, "refresh must spawn when interval > 0 and providers present");
        assert!(executor.registered_names().contains(&"secret_provider_refresh"));
        let _ =
            tokio::time::timeout(Duration::from_secs(2), executor.shutdown(TierBudget::default()))
                .await;
        // Keep TempDir alive for full test body (F1).
        drop(dir);
    }

    #[tokio::test]
    async fn secret_provider_refresh_not_spawned_when_interval_is_zero() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let config = Config {
            secret_provider: crate::config::SecretProviderConfig {
                refresh_interval: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let provider: Arc<dyn SecretProvider> = Arc::new(DummySecretProvider);
        let dir = tempfile::tempdir().unwrap();
        let (admissions, denylist, _) = test_admissions(&dir);
        let started = spawn_secret_provider_refresh(
            &config,
            vec![provider],
            HashSet::new(),
            denylist,
            admissions,
            &executor,
        );
        assert!(!started, "refresh_interval = 0 must not spawn");
        assert!(executor.registered_names().is_empty());
        drop(dir);
    }

    #[tokio::test]
    async fn secret_provider_refresh_not_spawned_when_no_providers() {
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let config = Config {
            secret_provider: crate::config::SecretProviderConfig {
                refresh_interval: Some(60),
                ..Default::default()
            },
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let (admissions, denylist, _) = test_admissions(&dir);
        let started = spawn_secret_provider_refresh(
            &config,
            vec![],
            HashSet::new(),
            denylist,
            admissions,
            &executor,
        );
        assert!(!started, "empty providers must not spawn");
        assert!(executor.registered_names().is_empty());
        drop(dir);
    }

    /// ARCH-2c: refresh callback admits through the service only (denylist in admit).
    #[test]
    fn refresh_admits_through_the_service_only() {
        // Source-shape guard: the refresh closure must be a single admit call.
        let src = include_str!("run.rs");
        let spawn_fn = src
            .split("fn spawn_secret_provider_refresh")
            .nth(1)
            .expect("spawn_secret_provider_refresh present");
        let body = spawn_fn.split("#[cfg(test)]").next().expect("fn body before tests");
        assert!(
            body.contains("admissions.admit(sk, AdmissionSource::RawSecret)"),
            "refresh callback must call admit(RawSecret)"
        );
        assert!(!body.contains("add_local_key"), "refresh must not call add_local_key directly");
        assert!(
            !body.contains("register_for_import"),
            "refresh must not register doppelganger outside admit"
        );
        assert!(
            !body.contains("denylist_for_callback"),
            "denylist guard must live inside admit, not at the call site"
        );
    }

    /// ARCH-2c: DELETE then refresh skips the denylisted key via admit.
    #[test]
    fn delete_then_refresh_race_skips_the_denylisted_key() {
        use crypto::SecretKey;

        let dir = tempfile::tempdir().unwrap();
        let (admissions, denylist, pubkey_map) = test_admissions(&dir);
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        denylist.insert(&pk).expect("denylist insert");

        // Simulate the refresh callback body.
        let outcome = admissions.admit(sk, AdmissionSource::RawSecret).expect("admit ok");
        assert!(
            matches!(outcome, crate::key_admission::AdmissionOutcome::SkippedDenylisted { pubkey } if pubkey == pk),
            "denylisted key must be skipped, got {outcome:?}"
        );
        assert!(!pubkey_map.read().contains_key(&pk), "skipped key must not enter PubkeyMap");
        drop(dir);
    }

    /// Minimal provider so tests can build a non-empty `Vec<Arc<dyn SecretProvider>>`.
    struct DummySecretProvider;

    #[async_trait::async_trait]
    impl SecretProvider for DummySecretProvider {
        fn name(&self) -> &str {
            "dummy"
        }

        async fn list_keys(
            &self,
        ) -> Result<Vec<secret_provider::SecretKeyEntry>, secret_provider::SecretProviderError>
        {
            Ok(vec![])
        }

        async fn fetch_key(
            &self,
            _id: &str,
        ) -> Result<secret_provider::KeyMaterial, secret_provider::SecretProviderError> {
            Err(secret_provider::SecretProviderError::NotFound("dummy".into()))
        }
    }
}
