//! Full validator-client bootstrap composition.
//!
//! [`run`] is the library entry point for the production Start path: it chains
//! every bootstrap phase, spawns the duty orchestrator on [`TaskExecutor`], and
//! drains registered tasks tier-by-tier on SIGTERM or task panic (ARCH-2h).

use std::collections::HashSet;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bn_manager::{BeaconNodeClient, OperationTimeouts};
use metrics::{new_health_status, SharedHealthStatus};
use observability::logging::TruncatedPubkey;
use secret_provider::SecretProvider;
use timing::SlotClock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::executor::{ShutdownOutcome, ShutdownReason, ShutdownTier, TaskExecutor, TierBudget};
use super::tasks::{
    bind_required_listeners, spawn_background_tasks, spawn_proposer_sync_monitor,
    spawn_sse_subscriber, spawn_sync_monitor,
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
use crate::liveness_loop::spawn_liveness_loop;
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
    run_with_clock(config, options, executor, shutdown_rx, |system| system).await
}

/// [`run`] with `clock` in place of the system slot clock.
///
/// Only the slot clock changes. `run` still builds everything else,
/// including every beacon-node client.
///
/// # Errors
///
/// The same as [`run`].
#[cfg(any(test, feature = "test-utils"))]
pub async fn run_with_slot_clock<C: SlotClock + 'static>(
    config: Config,
    options: RunOptions,
    executor: TaskExecutor,
    shutdown_rx: mpsc::Receiver<ShutdownReason>,
    clock: Arc<C>,
) -> Result<(), BootstrapError> {
    run_with_clock(config, options, executor, shutdown_rx, |_system| clock).await
}

/// The body of [`run`]. `pick_clock` maps the system slot clock from
/// `build_services` to the clock that every later reader gets.
async fn run_with_clock<C: SlotClock + 'static>(
    config: Config,
    options: RunOptions,
    executor: TaskExecutor,
    shutdown_rx: mpsc::Receiver<ShutdownReason>,
    pick_clock: impl FnOnce(Arc<timing::SystemSlotClock>) -> Arc<C>,
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

    if let Err(err) = crate::detection_marker::check_slashing_db_name(
        &config.keystore_path,
        &config.slashing_db_path,
    ) {
        error!(
            path = %config.slashing_db_path.display(),
            error = %err,
            "the slashing database path gives no clear detection marker name; refusing to start"
        );
        return Err(BootstrapError::InvalidConfig(err.to_string()));
    }
    refuse_if_detection_records(&config.keystore_path, &config.slashing_db_path)?;
    if config.doppelganger_detection {
        ensure_marker_dir_writable(&config.keystore_path)?;
        if let Some(fallback) = crate::detection_marker::FallbackMarkerPath::for_config(
            &config.keystore_path,
            &config.slashing_db_path,
        ) {
            ensure_fallback_dir_writable(&fallback.dir)?;
        }
        ensure_detection_record(&config.keystore_path, &config.slashing_db_path)?;
    }

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
    if config.doppelganger_detection {
        // This process holds the keystore lock when locking is enabled. A
        // concurrent create can still fail closed.
        if let Err(err) = crate::detection_marker::sweep_stale_record_temps(&config.keystore_path) {
            warn!(
                path = %config.keystore_path.display(),
                error = %err,
                "cannot remove the stale doppelganger detection record temp files"
            );
        }
    }

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

    // Step 6: SEC-2b/2c enablement. The liveness loop is built here and
    // spawned after the last fallible step (P1-7 registered on executor).
    let enablement = wire_signing_enablement(
        &config,
        &loaded_keys,
        &beacon_handles,
        Arc::clone(&slashing_db),
        &executor,
    )
    .await?;

    // Step 7: remaining services (signer, D-3, fork gate, proposer, toggle).
    let block_publication = options.timeouts.block_publication;
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
        slot_duration_ms: _,
        genesis_confirmed: _,
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
        liveness_task,
        pubkey_index,
        tracked_keys,
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
        proposer_bn_manager,
        block_beacon,
        builder_service,
        attesting_enabled,
    } = services;
    let slot_clock = pick_clock(slot_clock);

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
    // A refresh admit takes the keymanager adapters' key-set lock.
    let admissions = Arc::new(
        KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx.clone(),
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            Arc::clone(&deletion_denylist),
            forward_window_machine.clone(),
            Arc::clone(&epoch_clock),
        )
        .with_tracked_keys(Arc::clone(&tracked_keys)),
    );

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
    // From the first task spawn on, each boot error stops the tasks first.
    let keymanager_started = spawn_keymanager_api(
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
            slot_clock: Arc::clone(&slot_clock) as Arc<dyn timing::SlotClock>,
            tracked_keys,
        },
        listeners.keymanager,
        &executor,
    );
    if let Err(err) = keymanager_started {
        return Err(stop_boot_tasks(executor, err.into()).await);
    }

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
    let sync_check = bn_manager::sync_check_interval_for(
        slot_clock.slot_duration(),
        slot_clock.slots_per_epoch(),
    );
    spawn_sync_monitor(Some(Arc::clone(&bn_manager)), &executor, Some(sync_check));
    spawn_proposer_sync_monitor(proposer_bn_manager, &executor, Some(sync_check));
    let slot_duration_ms = slot_clock.slot_duration().as_millis() as u64;
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
            slot_duration_ms,
        );
        if slashed_action != crate::slashing_monitor::SlashedAction::None {
            info!(action = %slashed_action, "Slashing monitor started");
        }
    }

    finalize_health_status(&health_status).await;

    // P1-2/P1-3/P1-4: metrics + monitoring + proposer-config on executor.
    let background_started = spawn_background_tasks(
        &config,
        listeners.metrics,
        health_status,
        &executor,
        pubkey_map.clone(),
        validator_store.clone(),
    );
    if let Err(err) = background_started {
        return Err(stop_boot_tasks(executor, err).await);
    }

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

    // After the orchestrator tier, join detached broadcast drains for up to
    // the block-publication budget. Zero is no budget: the wait ends when
    // the drains do. The future starts only then, so drains spawned while
    // duties are stopping are included. One runtime tracker covers the main
    // pool and the proposer pool. The waiter is not an executor spawn.
    let broadcast_drains = Arc::clone(&bn_manager);
    executor.set_after_orchestrator_waiter(async move {
        broadcast_drains.wait_for_broadcast_drains(block_publication).await;
    });

    // Its own task, so the slot loop's post-duty window cannot drop a pass.
    // Shape B: `EpochBoundaryTask::run` roots each pass span.
    let Some(boundary) = orchestrator.take_epoch_boundary_runner() else {
        return Err(stop_boot_tasks(executor, BootstrapError::EpochBoundaryRunnerMissing).await);
    };
    executor.spawn("epoch.boundary.runner", ShutdownTier::Orchestrator, boundary.run());

    // The last fallible boot step. From the loop start on, the only way out
    // of `run` is the drain, so a latch reaches `persist_latched_detection`.
    // SIGINT and SIGTERM have a handler before the loop can latch.
    let signal = match ShutdownSignal::install() {
        Ok(signal) => signal,
        Err(err) => return Err(stop_boot_tasks(executor, err).await),
    };
    if let Some(task) = liveness_task {
        spawn_liveness_loop(task, &executor);
    }

    // Spawn (not poll inline): in-flight publish survives the shutdown signal (M10).
    // detached: already a per-slot root inside the task (`DutyOrchestrator::run`, span `slot.process`); not shape B.
    executor.spawn_result("duty_orchestrator", ShutdownTier::Orchestrator, async move {
        orchestrator.run().await
    });

    // Operator signal, panicking registered tasks, and internal token cancel
    // (e.g. slashing-monitor ShutdownRequested) converge on one drain path.
    let detection = forward_window_machine.map(|machine| DetectionShutdown {
        machine,
        keystore_dir: config.keystore_path.clone(),
        fallback: crate::detection_marker::FallbackMarkerPath::for_config(
            &config.keystore_path,
            &config.slashing_db_path,
        ),
        epoch_clock: Arc::clone(&epoch_clock),
    });
    let (outcome, res) = await_shutdown_and_drain(
        ShutdownInputs {
            executor,
            orchestrator_handle,
            shutdown_rx,
            shutdown_token,
            budget: TierBudget::default(),
            detection,
        },
        signal,
    )
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
    /// Set when doppelganger detection is on. The drain writes a marker if
    /// the latch is set, including when shutdown won the race with the retry.
    pub(crate) detection: Option<DetectionShutdown>,
}

/// Machine and directories the drain uses to leave a durable detection record.
pub(crate) struct DetectionShutdown {
    /// Process latch and the detected pubkey hexes.
    pub(crate) machine: Arc<doppelganger::ForwardWindowMachine>,
    /// Keystore directory. The primary marker is written here.
    pub(crate) keystore_dir: std::path::PathBuf,
    /// Fallback marker of the slashing database when its directory is not
    /// the keystore.
    pub(crate) fallback: Option<crate::detection_marker::FallbackMarkerPath>,
    /// Epoch recorded in the marker.
    pub(crate) epoch_clock: Arc<doppelganger::MonotonicEpochClock>,
}

/// Wait until an operator signal, a [`ShutdownReason`], or token cancel, then
/// stop the duty loop and drain every registered task.
///
/// The drain finishes before this returns, on every arm.
/// [`ShutdownReason::Failure`] becomes [`BootstrapError::CriticalTaskFailed`]
/// (exit 16). A doppelganger exit flag or a set detection latch becomes
/// [`BootstrapError::DoppelgangerDetected`] (exit 12) and outranks a panic, a
/// signal, or token cancel. Exit 12 follows only after a write and its fsync
/// returned `Ok` in this process (a rename also needs the directory fsync).
/// The record is overwritten in place first; the keystore marker and the
/// slashing-database parent are additional paths. A later rewrite failure
/// does not retry once that acknowledgement is set. A read-back, including an
/// unreadable file, is not durability. When the acknowledgement is still
/// clear, this keeps retrying and does not return `Ok` or exit 16. `SIGKILL`
/// before the first successful fsync loses the latch. Signal, token, and
/// [`ShutdownReason::Success`] return `Ok` when the latch is clear.
///
/// `signal` is the operator-signal arm. [`run`] installs it before the
/// liveness loop starts, so its handlers already catch SIGINT and SIGTERM.
pub(crate) async fn await_shutdown_and_drain<S: SignalStream>(
    inputs: ShutdownInputs,
    mut signal: ShutdownSignal<S>,
) -> (ShutdownOutcome, Result<(), BootstrapError>) {
    await_shutdown_and_drain_with_signal(inputs, async move {
        let name = signal.recv().await;
        info!("Received {name}");
    })
    .await
}

/// Same as [`await_shutdown_and_drain`], with the operator-signal arm replaced.
///
/// Production passes the future of a [`ShutdownSignal`]. Tests pass a ready
/// or pending future so the signal arm does not install a process-wide
/// SIGINT handler.
pub(crate) async fn await_shutdown_and_drain_with_signal(
    inputs: ShutdownInputs,
    signal: impl Future<Output = ()>,
) -> (ShutdownOutcome, Result<(), BootstrapError>) {
    let ShutdownInputs {
        executor,
        orchestrator_handle,
        mut shutdown_rx,
        shutdown_token,
        budget,
        detection,
    } = inputs;

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
                Some(ShutdownReason::DoppelgangerDetected) => {
                    error!("doppelganger detected; initiating process drain");
                    startup::log_shutdown_initiated("doppelganger detected");
                    None
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
    // The marker retry below sleeps only after this drain returns.
    // The flag outlives `shutdown`, which consumes the executor. Load it
    // after the drain so a detection that lands while a tier is still
    // joining exits 12, not the reason that woke the select.
    let doppelganger_exit = executor.doppelganger_exit_flag();
    let outcome = executor.shutdown(budget).await;
    // The latch lives on the machine, which this drain holds. A signal, a
    // token cancel, or a task panic can arrive while the keystore write is
    // still failing and before the exit flag is stored. Leaving here with
    // `Ok` or exit 16 would restart the detected key with a fresh window.
    if let Some(detection) = detection.as_ref() {
        if persist_latched_detection(detection).await {
            doppelganger_exit.store(true, Ordering::SeqCst);
        }
    }
    let doppelganger_exit = doppelganger_exit.load(Ordering::SeqCst);
    let res = if doppelganger_exit {
        Err(BootstrapError::DoppelgangerDetected)
    } else {
        match failed_task {
            Some(task) => Err(BootstrapError::CriticalTaskFailed { task }),
            None => Ok(()),
        }
    };
    (outcome, res)
}

/// Cancel and join the tasks that boot has spawned, then return `err`.
///
/// Each boot error after the first task spawn returns through this function,
/// so `run` does not return while a spawned task still runs. The liveness
/// loop has not started at that point, so no detection latch can be set.
async fn stop_boot_tasks(executor: TaskExecutor, err: BootstrapError) -> BootstrapError {
    let outcome = executor.shutdown(TierBudget::default()).await;
    warn!(
        joined = ?outcome.joined,
        aborted = ?outcome.aborted,
        "a boot step failed after the first task spawn; the boot tasks are stopped"
    );
    err
}

/// How long the drain waits between attempts when nothing durable exists yet.
const MARKER_SHUTDOWN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// Operator hint included in a refuse-to-start log: the `clear-detection`
/// command for the keystore `keystore_dir` and the slashing database
/// `slashing_db_path`. The fallback marker, when one was written, sits beside
/// the slashing database.
///
/// Each path is the [`crate::detection_marker::absolute_path`] of the
/// configured path, so the command works from any working directory, and its
/// `--datadir` is the owner that a fallback marker of this process records.
/// A path without an absolute form is printed as configured. Each path is
/// one shell word ([`shell_word`]). When a path cannot be one, the hint
/// prints no command and asks the operator to type each path. The text goes
/// only to the log: no selection, read, write or clear uses it.
fn detection_clear_hint(
    keystore_dir: &std::path::Path,
    slashing_db_path: &std::path::Path,
) -> String {
    let shown = |path: &std::path::Path| {
        shell_word(
            &crate::detection_marker::absolute_path(path).unwrap_or_else(|_| path.to_path_buf()),
        )
    };
    match (shown(keystore_dir), shown(slashing_db_path)) {
        (Some(keystore), Some(db)) => format!(
            "Clear it with `rvc doppelganger clear-detection --datadir {keystore} \
             --slashing-db-path {db} --confirm` after the other instance is gone"
        ),
        _ => "Clear it after the other instance is gone: run `rvc doppelganger clear-detection` \
              with `--datadir` set to the keystore directory, `--slashing-db-path` set to the \
              slashing database, and `--confirm`. This log cannot show these paths as exact \
              shell text, so type each path yourself"
            .to_string(),
    }
}

/// `path` as one POSIX shell word: the path text in single quotes, with
/// each `'` written as `'\''`. `None` when the path is not UTF-8 or has a
/// control character, because a log line cannot show such a path exactly.
fn shell_word(path: &std::path::Path) -> Option<String> {
    let text = path.to_str().filter(|text| !text.contains(char::is_control))?;
    Some(format!("'{}'", text.replace('\'', r"'\''")))
}

/// Write a durable detection record once the latch is set.
///
/// The pre-allocated keystore record is overwritten in place first. The
/// keystore marker and [`DetectionShutdown::fallback`] are additional
/// paths. `true` only when this process has seen a write and its fsync return
/// `Ok` (a rename also needs the directory fsync). A later rewrite failure
/// does not retry. A read of the record or a marker is not durability, and
/// neither is an unreadable file. Only a latch whose flag is still clear
/// sleeps and retries. Exit 12 without a completed fsync is not safe: Compose
/// `restart: unless-stopped` starts the process again, and the detected key
/// would get a fresh window.
async fn persist_latched_detection(detection: &DetectionShutdown) -> bool {
    if !detection.machine.detected_latch() {
        return false;
    }
    loop {
        if detection.machine.detection_persisted() {
            return true;
        }
        let epoch = detection.epoch_clock.current_epoch();
        let unix_secs = crate::detection_marker::unix_secs_now();
        let marker = crate::detection_marker::DetectionMarker {
            epoch,
            unix_secs,
            pubkeys: detection.machine.detected_hexes(),
        };
        if crate::detection_marker::commit_detection_record(
            &detection.keystore_dir,
            epoch,
            unix_secs,
        )
        .is_ok()
        {
            detection.machine.mark_detection_persisted();
            if let Err(err) =
                crate::detection_marker::write_marker(&detection.keystore_dir, &marker)
            {
                crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                error!(
                    error = %err,
                    path = %crate::detection_marker::marker_path(&detection.keystore_dir).display(),
                    "in-place detection record is durable; the marker write failed"
                );
                if let Some(fallback) = &detection.fallback {
                    if let Err(fallback_err) = crate::detection_marker::write_fallback_marker(
                        fallback,
                        &detection.keystore_dir,
                        &marker,
                    ) {
                        crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                        error!(
                            error = %fallback_err,
                            path = %fallback.owned_path().display(),
                            "in-place detection record is durable; the fallback marker write failed"
                        );
                    }
                }
            }
        } else if crate::detection_marker::write_marker(&detection.keystore_dir, &marker).is_ok() {
            detection.machine.mark_detection_persisted();
        } else {
            crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
            error!(
                path = %crate::detection_marker::marker_path(&detection.keystore_dir).display(),
                "failed to persist doppelganger detection marker during shutdown"
            );
            if let Some(fallback) = &detection.fallback {
                if crate::detection_marker::write_fallback_marker(
                    fallback,
                    &detection.keystore_dir,
                    &marker,
                )
                .is_ok()
                {
                    detection.machine.mark_detection_persisted();
                    error!(
                        path = %fallback.owned_path().display(),
                        "persisted doppelganger detection marker beside the slashing database"
                    );
                } else {
                    crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                    error!(
                        path = %fallback.owned_path().display(),
                        "failed to persist the fallback doppelganger detection marker"
                    );
                }
            }
        }
        if detection.machine.detection_persisted() {
            return true;
        }
        tokio::time::sleep(MARKER_SHUTDOWN_RETRY).await;
    }
}

/// Exit 12 before a signer or the keymanager API is built when a detection
/// marker or a detected record is present in the keystore directory or, when
/// that directory is different, the owned fallback marker of this database or
/// a legacy fallback marker is beside the slashing database. Each refusal log
/// gives the `clear-detection` command of the two paths.
pub(crate) fn refuse_if_detection_records(
    keystore_dir: &std::path::Path,
    slashing_db_path: &std::path::Path,
) -> Result<(), BootstrapError> {
    let hint = detection_clear_hint(keystore_dir, slashing_db_path);
    refuse_if_detection_record(keystore_dir, &hint)?;
    refuse_if_detection_marker(
        &crate::detection_marker::marker_path(keystore_dir),
        crate::detection_marker::inspect(keystore_dir),
        &hint,
    )?;
    if let Some(fallback) =
        crate::detection_marker::FallbackMarkerPath::for_config(keystore_dir, slashing_db_path)
    {
        let found = crate::detection_marker::inspect_fallback(&fallback);
        refuse_if_detection_marker(&fallback.owned_path(), found.owned, &hint)?;
        refuse_if_detection_marker(
            &crate::detection_marker::marker_path(&fallback.dir),
            found.legacy,
            &hint,
        )?;
    }
    Ok(())
}

/// Exit 12 when the pre-allocated record is `detected` or cannot be trusted.
///
/// Each refusal log gives `hint`, the `clear-detection` command. That command
/// replaces a record that does not parse when it is a regular file.
fn refuse_if_detection_record(
    data_dir: &std::path::Path,
    hint: &str,
) -> Result<(), BootstrapError> {
    match crate::detection_marker::inspect_record(data_dir) {
        crate::detection_marker::RecordInspect::Absent
        | crate::detection_marker::RecordInspect::Clear => Ok(()),
        crate::detection_marker::RecordInspect::Detected { epoch, unix_secs } => {
            error!(
                epoch,
                unix_secs,
                path = %crate::detection_marker::record_path(data_dir).display(),
                "doppelganger detection record is in the detected state; refusing to start. {}",
                hint
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::RecordInspect::Unreadable { path, reason } => {
            error!(
                path = %path.display(),
                reason,
                "doppelganger detection record cannot be read or does not parse; refusing to \
                 start. A symlink, directory or FIFO at that path must be removed first. {}",
                hint
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
    }
}

/// Exit 12 before a signer or the keymanager API is built when the detection
/// marker that `found` describes at `path` is present, unreadable, or not a
/// valid marker. Each refusal log gives `hint`, the `clear-detection` command.
fn refuse_if_detection_marker(
    path: &std::path::Path,
    found: crate::detection_marker::MarkerInspect,
    hint: &str,
) -> Result<(), BootstrapError> {
    match found {
        crate::detection_marker::MarkerInspect::Absent => Ok(()),
        crate::detection_marker::MarkerInspect::Present(marker) => {
            for pubkey in &marker.pubkeys {
                error!(
                    pubkey = %TruncatedPubkey::new(pubkey),
                    epoch = marker.epoch,
                    unix_secs = marker.unix_secs,
                    path = %path.display(),
                    "doppelganger detection marker is present; refusing to start. {}",
                    hint
                );
            }
            if marker.pubkeys.is_empty() {
                error!(
                    epoch = marker.epoch,
                    path = %path.display(),
                    "doppelganger detection marker listed no keys; refusing to start. {}",
                    hint
                );
            }
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::MarkerInspect::Corrupt { path, reason } => {
            error!(
                path = %path.display(),
                reason,
                "doppelganger detection marker is corrupt; refusing to start. {}",
                hint
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::MarkerInspect::Unreadable { path, source } => {
            error!(
                path = %path.display(),
                error = %source,
                "doppelganger detection marker is unreadable; refusing to start. {}",
                hint
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
    }
}

/// Detection stays on only when the fixed-size record can be pre-allocated.
///
/// A failure here is exit 1. The process cannot promise to latch a later
/// detection if that overwrite has nowhere to land. A record that is
/// `detected` by then is exit 12, and the log gives the `clear-detection`
/// command for the keystore `data_dir` and the database `slashing_db_path`.
fn ensure_detection_record(
    data_dir: &std::path::Path,
    slashing_db_path: &std::path::Path,
) -> Result<(), BootstrapError> {
    if let Err(err) = crate::detection_marker::preallocate_detection_record(data_dir) {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            error!(
                path = %crate::detection_marker::record_path(data_dir).display(),
                "doppelganger detection record is already in the detected state; refusing to start. {}",
                detection_clear_hint(data_dir, slashing_db_path)
            );
            return Err(BootstrapError::DoppelgangerDetected);
        }
        error!(
            path = %data_dir.display(),
            error = %err,
            "cannot preallocate the doppelganger detection record; the latch cannot be guaranteed"
        );
        return Err(BootstrapError::InvalidConfig(format!(
            "cannot preallocate the doppelganger detection record in {}: {err}. \
             The process cannot guarantee the detection latch",
            data_dir.display()
        )));
    }
    Ok(())
}

/// Detection stays on only when the marker directory can take a durable write.
fn ensure_marker_dir_writable(data_dir: &std::path::Path) -> Result<(), BootstrapError> {
    if let Err(err) = crate::detection_marker::probe_marker_dir_writable(data_dir) {
        error!(
            path = %data_dir.display(),
            error = %err,
            "doppelganger detection is enabled but the keystore directory is not writable"
        );
        return Err(BootstrapError::InvalidConfig(format!(
            "keystore_path {} must be a persistent, writable directory while doppelganger \
             detection is enabled: {err}",
            data_dir.display()
        )));
    }
    Ok(())
}

/// Detection stays on only when the slashing database directory `dir` can
/// take a durable write. Boot calls this only when that directory is not the
/// keystore directory: the drain writes the fallback marker there when the
/// keystore write fails. A failure here is exit 1.
fn ensure_fallback_dir_writable(dir: &std::path::Path) -> Result<(), BootstrapError> {
    crate::detection_marker::probe_fallback_dir_writable(dir).map_err(|err| {
        error!(
            path = %dir.display(),
            error = %err,
            "doppelganger detection is enabled but the slashing database directory cannot hold \
             the fallback detection marker"
        );
        BootstrapError::InvalidConfig(format!(
            "the slashing database directory {} must be writable while doppelganger detection \
             is enabled, because the fallback detection marker is written there: {err}",
            dir.display()
        ))
    })
}

/// The SIGINT and SIGTERM handlers of the drain.
///
/// [`Self::install`] registers both handlers before it returns. A signal
/// that comes later waits for [`Self::recv`] and does not stop the process
/// by the default action. [`run`] installs the handlers just before the
/// liveness loop starts. Earlier boot steps keep the default action, so
/// Ctrl+C still stops a boot that has latched nothing.
///
/// `S` is the signal stream. Production uses [`OsSignal`]. A test stream
/// lets a test drive each arm of [`Self::recv`] without a signal.
pub(crate) struct ShutdownSignal<S = OsSignal> {
    interrupt: S,
    #[cfg(unix)]
    terminate: S,
}

/// One kind of operator signal that [`ShutdownSignal::recv`] waits for.
pub(crate) trait SignalStream {
    /// Wait for the next delivery of the signal.
    fn recv(&mut self) -> impl Future<Output = Option<()>> + Send;
}

/// The signal stream of the platform.
#[cfg(unix)]
pub(crate) type OsSignal = tokio::signal::unix::Signal;
/// The signal stream of the platform.
#[cfg(not(unix))]
pub(crate) type OsSignal = tokio::signal::windows::CtrlC;

impl SignalStream for OsSignal {
    fn recv(&mut self) -> impl Future<Output = Option<()>> + Send {
        OsSignal::recv(self)
    }
}

impl ShutdownSignal {
    /// Register the SIGINT and SIGTERM handlers now (Ctrl+C when the target
    /// is not Unix).
    ///
    /// # Errors
    ///
    /// [`BootstrapError::InvalidConfig`] (exit 1) when a handler cannot be
    /// registered. Boot then stops before the liveness loop starts.
    pub(crate) fn install() -> Result<Self, BootstrapError> {
        let failed = |err: std::io::Error| {
            BootstrapError::InvalidConfig(format!(
                "cannot install the SIGINT and SIGTERM handlers: {err}"
            ))
        };
        #[cfg(unix)]
        let installed = {
            use tokio::signal::unix::{signal, SignalKind};
            Self {
                interrupt: signal(SignalKind::interrupt()).map_err(failed)?,
                terminate: signal(SignalKind::terminate()).map_err(failed)?,
            }
        };
        #[cfg(not(unix))]
        let installed = Self { interrupt: tokio::signal::windows::ctrl_c().map_err(failed)? };
        Ok(installed)
    }
}

impl<S: SignalStream> ShutdownSignal<S> {
    /// Wait for the next SIGINT or SIGTERM and return its name.
    pub(crate) async fn recv(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => "SIGINT",
                _ = self.terminate.recv() => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            self.interrupt.recv().await;
            "SIGINT"
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
        // detached: secret_provider::RefreshService::run; loop body is crates/secret-provider/src/refresh.rs:185, out of scope.
        executor.spawn("secret_provider_refresh", ShutdownTier::Background, async move {
            refresh_service
                .run(move |sk| {
                    // Denylist DELETE-races-refresh guard is inside admit.
                    // A rejected key is forgotten so the next refresh retries it.
                    let pubkey = sk.public_key().to_bytes();
                    match admissions.admit(sk, AdmissionSource::RawSecret) {
                        Ok(_) => true,
                        Err(e) => {
                            warn!(
                                pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
                                error = %e,
                                "secret-provider key was not admitted; it will be retried"
                            );
                            false
                        }
                    }
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
        acquire_keystore_lock, EXIT_CRITICAL_TASK_FAILED, EXIT_DOPPELGANGER_DETECTED,
        EXIT_GENESIS_ROOT_MISMATCH, EXIT_INTEGRITY_CHECK_FAILED, EXIT_KEYSTORE_LOCKED,
        EXIT_LISTENER_BIND, EXIT_UNSUPPORTED_FORK_VERSION,
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

        let (outcome, res) = await_shutdown_and_drain(
            ShutdownInputs {
                executor,
                orchestrator_handle: OrchestratorHandle::for_drain_test(),
                shutdown_rx,
                shutdown_token: token,
                budget: short_budget(),
                detection: None,
            },
            ShutdownSignal::install()
                .expect("`ShutdownSignal::install` must register both signal handlers."),
        )
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

        let (outcome, res) = await_shutdown_and_drain(
            ShutdownInputs {
                executor,
                orchestrator_handle: OrchestratorHandle::for_drain_test(),
                shutdown_rx,
                shutdown_token: token,
                budget: short_budget(),
                detection: None,
            },
            ShutdownSignal::install()
                .expect("`ShutdownSignal::install` must register both signal handlers."),
        )
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
            detection: None,
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

    /// W4-D2c: `ShutdownSignal::install` registers the SIGINT and the SIGTERM
    /// handler before it returns. The test reads the caught-signal mask
    /// (`SigCgt`) of this process and sends no signal. Nextest runs each test
    /// in its own process, so no other test sets these bits.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shutdown_signal_install_registers_both_handlers() {
        use tokio::signal::unix::SignalKind;

        let _signal = ShutdownSignal::install()
            .expect("`ShutdownSignal::install` must register both signal handlers.");
        let status = std::fs::read_to_string("/proc/self/status")
            .expect("The test must read /proc/self/status.");
        let caught = status
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:"))
            .map(|mask| u64::from_str_radix(mask.trim(), 16))
            .expect("The status must have a SigCgt line.")
            .expect("The SigCgt mask must be a hexadecimal number.");
        for (name, kind) in
            [("SIGINT", SignalKind::interrupt()), ("SIGTERM", SignalKind::terminate())]
        {
            let bit = 1u64 << (kind.as_raw_value() - 1);
            assert_ne!(
                caught & bit,
                0,
                "{name} must have a handler when install returns. SigCgt is {caught:#018x}."
            );
        }
    }

    /// A signal stream for a test. The stream gives a delivery at once, or
    /// it never gives a delivery.
    #[cfg(unix)]
    struct TestSignal {
        delivered: bool,
    }

    #[cfg(unix)]
    impl SignalStream for TestSignal {
        fn recv(&mut self) -> impl Future<Output = Option<()>> + Send {
            let delivered = self.delivered;
            async move {
                if delivered {
                    Some(())
                } else {
                    std::future::pending().await
                }
            }
        }
    }

    /// Poll `future` one time with a waker that does nothing.
    #[cfg(unix)]
    fn poll_once<F: Future>(future: F) -> std::task::Poll<F::Output> {
        let mut future = std::pin::pin!(future);
        future.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    }

    /// W4-D2c fix1: give a delivery only to the `delivered` stream of a
    /// `ShutdownSignal` with test streams. Then do these steps:
    ///
    /// 1. Poll `recv` one time. It must return the name of `delivered`.
    /// 2. Give a new signal of the same kind to `await_shutdown_and_drain`.
    ///    The drain must start and join `drain_probe`.
    ///
    /// A spawned task cancels the token after the first poll of the drain. If
    /// the signal arm does not start the drain, the token arm starts it, and
    /// the log assertions of the caller fail. Thus the test cannot hang.
    #[cfg(unix)]
    async fn drain_with_one_signal(delivered: &'static str) {
        let signal = || ShutdownSignal {
            interrupt: TestSignal { delivered: delivered == "SIGINT" },
            terminate: TestSignal { delivered: delivered == "SIGTERM" },
        };
        assert_eq!(
            poll_once(signal().recv()),
            std::task::Poll::Ready(delivered),
            "ShutdownSignal::recv must return {delivered} at the first poll when only \
             {delivered} has a delivery."
        );

        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let probe_token = token.clone();
        executor.spawn("drain_probe", ShutdownTier::Background, async move {
            probe_token.cancelled().await;
        });
        let fallback = token.clone();
        tokio::spawn(async move { fallback.cancel() });
        let (outcome, res) =
            await_shutdown_and_drain(probe_inputs(executor, shutdown_rx, token), signal()).await;
        assert!(res.is_ok(), "The drain after {delivered} must return Ok. The result is {res:?}.");
        assert!(
            outcome.joined.contains(&"drain_probe"),
            "The drain must join drain_probe. The drain joined {:?} and aborted {:?}.",
            outcome.joined,
            outcome.aborted
        );
    }

    /// W4-D2c fix1: SIGINT alone must start the drain. See
    /// [`drain_with_one_signal`].
    #[cfg(unix)]
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn sigint_alone_starts_the_drain() {
        drain_with_one_signal("SIGINT").await;
        assert!(logs_contain("Received SIGINT"), "The SIGINT arm must start the drain.");
        assert!(!logs_contain("Received SIGTERM"), "The SIGTERM arm must not start the drain.");
        assert!(
            !logs_contain("Process cancellation token cancelled"),
            "The token arm must not start the drain when SIGINT has a delivery."
        );
    }

    /// W4-D2c fix1: SIGTERM alone must start the drain. See
    /// [`drain_with_one_signal`].
    #[cfg(unix)]
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn sigterm_alone_starts_the_drain() {
        drain_with_one_signal("SIGTERM").await;
        assert!(logs_contain("Received SIGTERM"), "The SIGTERM arm must start the drain.");
        assert!(!logs_contain("Received SIGINT"), "The SIGINT arm must not start the drain.");
        assert!(
            !logs_contain("Process cancellation token cancelled"),
            "The token arm must not start the drain when SIGTERM has a delivery."
        );
    }

    /// Shutdown while the runner's prepare POST is held: the drain joins
    /// both Orchestrator-tier tasks inside the tier budget and aborts none.
    /// The hold, and the preparation and duty-fetch bounds, outlast that
    /// budget, so only shutdown can end the held pass in time.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn drain_joins_the_boundary_work_with_a_step_in_flight() {
        use bn_manager::{MockBeaconNodeClient, MockMethod, Propagator};
        use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};

        use crate::beacon_adapter::BeaconBlockAdapter;
        use crate::orchestrator::{
            epoch_boundary, DutyOrchestrator, OrchestratorConfig, OrchestratorDeps,
        };

        const HOLD: Duration = Duration::from_secs(3_600);
        let mock = Arc::new(
            MockBeaconNodeClient::new()
                .with_prepare_beacon_proposer(|_| Ok(()))
                .with_method_delay(MockMethod::PrepareBeaconProposer, HOLD),
        );
        let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
        let local = SecretKey::generate().public_key();
        let local_bytes = local.to_bytes();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::from([(
            local_bytes,
            local,
        )])));
        let clock =
            Arc::new(timing::MockSlotClock::new(1_606_824_023, Duration::from_secs(12), 32));
        clock.set_slot(32);
        // Past every duty deadline, so slot 32 is processed at once.
        clock.advance_time(9);
        let timeouts = OperationTimeouts {
            preparation: 2 * HOLD,
            duty_fetch: 2 * HOLD,
            ..OperationTimeouts::default()
        };
        let schedule = Arc::new(eth_types::ForkSchedule::unscheduled_gloas());
        let config = OrchestratorConfig::new([0xaa; 32], schedule).with_timeouts(timeouts);
        let keys = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
        let signer = Arc::new(
            ::signer::SignerService::new(keys, slashing_db)
                .with_enablement(::signer::always_enabled()),
        );
        let deps = OrchestratorDeps::for_test(
            clock,
            Arc::new(duty_tracker::DutyTracker::new(mock.clone(), vec!["7".to_string()])),
            signer,
            Arc::new(Propagator::new(Arc::clone(&mock))),
            Arc::clone(&beacon),
            Arc::new(BeaconBlockAdapter::new(beacon)),
            None,
            Arc::new(validator_store::ValidatorStore::new([0; 20], 100)),
            config,
            pubkey_map,
        );
        deps.pubkey_index.write().insert(local_bytes, "7".to_string());
        let (mut orchestrator, orchestrator_handle) = DutyOrchestrator::new(deps);

        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let boundary = orchestrator.take_epoch_boundary_runner().expect("runner");
        executor.spawn("epoch.boundary.runner", ShutdownTier::Orchestrator, boundary.run());
        executor.spawn_result("duty_orchestrator", ShutdownTier::Orchestrator, async move {
            orchestrator.run().await
        });

        // The mock holds the runner's prepare.
        let prepares = || {
            let stamps = mock.call_stamps();
            stamps.iter().filter(|stamp| stamp.method == MockMethod::PrepareBeaconProposer).count()
        };
        let mut waited_ms = 0u64;
        while prepares() < 1 {
            waited_ms += 1;
            assert!(waited_ms <= 5_000, "the runner's prepare did not start: {}", prepares());
            tokio::time::advance(Duration::from_millis(1)).await;
        }

        token.cancel();
        let inputs = ShutdownInputs {
            executor,
            orchestrator_handle,
            shutdown_rx,
            shutdown_token: token,
            budget: TierBudget::default(),
            detection: None,
        };
        let (outcome, res) =
            await_shutdown_and_drain_with_signal(inputs, std::future::pending::<()>()).await;

        assert!(res.is_ok(), "token cancel drains to Ok: {res:?}");
        assert!(outcome.aborted.is_empty(), "nothing outlives the budget: {:?}", outcome.aborted);
        for task in ["duty_orchestrator", epoch_boundary::TASK_NAME] {
            assert!(outcome.joined.contains(&task), "{task} joins: {:?}", outcome.joined);
        }
        assert!(mock.prepare_beacon_proposer_calls().is_empty(), "the held prepares were dropped");
    }

    /// ARCH-2i / NFR-3: pin EXIT_* numeric values so a silent renumber fails CI.
    #[test]
    fn test_exit_codes_are_unchanged() {
        assert_eq!(EXIT_INTEGRITY_CHECK_FAILED, 10);
        assert_eq!(EXIT_GENESIS_ROOT_MISMATCH, 11);
        assert_eq!(EXIT_DOPPELGANGER_DETECTED, 12);
        assert_eq!(EXIT_UNSUPPORTED_FORK_VERSION, 13);
        assert_eq!(EXIT_KEYSTORE_LOCKED, 14);
        assert_eq!(EXIT_LISTENER_BIND, 15);
        assert_eq!(EXIT_CRITICAL_TASK_FAILED, 16);
        assert_ne!(EXIT_INTEGRITY_CHECK_FAILED, 12);
        assert_ne!(EXIT_GENESIS_ROOT_MISMATCH, 12);
        assert_ne!(EXIT_UNSUPPORTED_FORK_VERSION, 12);
        assert_ne!(EXIT_KEYSTORE_LOCKED, 12);
        assert_ne!(EXIT_LISTENER_BIND, 12);
        assert_ne!(EXIT_CRITICAL_TASK_FAILED, 12);
        let startup_src = include_str!("../startup.rs");
        assert!(
            startup_src.contains("pub const EXIT_DOPPELGANGER_DETECTED: i32 = 12;"),
            "exit 12 is the doppelganger detection code"
        );
        let loop_src = include_str!("../liveness_loop.rs");
        assert!(
            loop_src.contains("EXIT_DOPPELGANGER_DETECTED"),
            "the liveness loop must request exit 12"
        );
        assert!(
            loop_src.contains("detected_latch"),
            "the liveness loop must exit from the latch transition"
        );
    }

    #[tokio::test]
    async fn boot_refuses_when_detection_marker_is_present_or_corrupt() {
        let dir = tempfile::tempdir().expect("temp");
        crate::detection_marker::write_marker(
            dir.path(),
            &crate::detection_marker::DetectionMarker {
                epoch: 9,
                unix_secs: 10,
                pubkeys: vec!["0x".to_string() + &"cd".repeat(48)],
            },
        )
        .expect("marker");
        let err = boot_with_keystore(dir.path()).await;
        assert_eq!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);

        let dir = tempfile::tempdir().expect("temp");
        crate::detection_marker::write_marker(
            dir.path(),
            &crate::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] },
        )
        .expect("empty");
        let err = boot_with_keystore(dir.path()).await;
        assert_eq!(err.exit_code(), 12);

        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(crate::detection_marker::marker_path(dir.path()), b"{").expect("corrupt");
        let err = boot_with_keystore(dir.path()).await;
        assert_eq!(err.exit_code(), 12);

        let dir = tempfile::tempdir().expect("temp");
        std::fs::create_dir(crate::detection_marker::marker_path(dir.path())).expect("unreadable");
        let err = boot_with_keystore(dir.path()).await;
        assert_eq!(err.exit_code(), 12);
    }

    /// Boot reads the record also when detection is off. A record that the
    /// parser cannot trust must stop boot with exit 12.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_unparseable_detection_records() {
        use crate::detection_marker::{record_path, RECORD_LEN};
        let padded = |header: &[u8]| {
            let mut bytes = header.to_vec();
            bytes.resize(RECORD_LEN, 0);
            bytes
        };
        let mut tail = padded(b"version=1\nstate=not-detected\nepoch=0\nunix_secs=0\n");
        tail[4000] = b'x';
        let records = [
            ("state=maybe", padded(b"version=1\nstate=maybe\nepoch=0\nunix_secs=0\n")),
            ("a non-zero byte at offset 4000", tail),
            ("version=2", padded(b"version=2\nstate=not-detected\nepoch=0\nunix_secs=0\n")),
        ];
        for (case, bytes) in records {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            std::fs::write(record_path(dir.path()), bytes)
                .expect("The test must write the record file.");
            let err = boot_with_keystore(dir.path()).await;
            assert_eq!(
                err.exit_code(),
                EXIT_DOPPELGANGER_DETECTED,
                "Boot must exit 12 for a record with {case}. The error is: {err}"
            );
        }
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        std::fs::create_dir(record_path(dir.path()))
            .expect("The test must create a directory at the record path.");
        let err = boot_with_keystore(dir.path()).await;
        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Boot must exit 12 when the record path is a directory. The error is: {err}"
        );
    }

    /// Boot refuses a zero-filled record with exit 12. The refusal log gives
    /// the `clear-detection` command.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn boot_refusal_of_an_unparseable_record_prints_the_clear_hint() {
        use crate::detection_marker::{record_path, RECORD_LEN};
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        std::fs::write(record_path(dir.path()), vec![0u8; RECORD_LEN])
            .expect("The test must write the zero-filled record.");

        let err = boot_with_keystore(dir.path()).await;

        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Boot must exit 12 for a zero-filled record. The error is: {err}"
        );
        assert!(
            logs_contain("rvc doppelganger clear-detection"),
            "The refusal log must give the clear-detection command."
        );
        assert!(
            logs_contain("symlink, directory or FIFO"),
            "The refusal log must name the three entry types that require removal."
        );
    }

    /// Boot returns exit code 12 if the owned fallback marker exists. The
    /// test writes the marker directly as JSON.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_an_owned_fallback_marker() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let slash = tempfile::tempdir().expect("The test must create the database directory.");
        let owned = slash.path().join(".rvc.doppelganger_detected.a.sqlite");
        let body = serde_json::json!({
            "version": 1,
            "epoch": 3,
            "unix_secs": 4,
            "pubkeys": [],
            "keystore_dir": keys.path().to_string_lossy(),
        });
        std::fs::write(&owned, body.to_string())
            .expect("The test must write the owned fallback marker.");
        let config = crate::config::Config {
            keystore_path: keys.path().to_path_buf(),
            slashing_db_path: slash.path().join("a.sqlite"),
            doppelganger_detection: false,
            ..Default::default()
        };
        let (executor, rx) = TaskExecutor::new(CancellationToken::new());

        let err = run(
            config,
            RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            executor,
            rx,
        )
        .await
        .expect_err("Boot must return an error for this fixture.");

        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Boot must return exit code 12 when it finds the marker at {}. The error is {err}.",
            owned.display()
        );
    }

    /// Run boot with the keystore `keys` and the slashing database `db`.
    /// Detection is off. Return the boot error.
    async fn boot_with_db(
        keys: &std::path::Path,
        db: &std::path::Path,
        allow_fresh_db: bool,
    ) -> BootstrapError {
        let config = crate::config::Config {
            keystore_path: keys.to_path_buf(),
            slashing_db_path: db.to_path_buf(),
            allow_fresh_db,
            doppelganger_detection: false,
            ..Default::default()
        };
        let (executor, rx) = TaskExecutor::new(CancellationToken::new());
        let options = RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: bn_manager::OperationTimeouts::default(),
        };
        run(config, options, executor, rx).await.expect_err("Boot must return an error.")
    }

    /// A directory is at the owned fallback path of `a.sqlite`, so the
    /// marker cannot be read. The database does not exist. Boot must return
    /// exit code 12 before it opens the database.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_an_unreadable_owned_fallback_marker() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let slash = tempfile::tempdir().expect("The test must create the database directory.");
        let owned = slash.path().join(".rvc.doppelganger_detected.a.sqlite");
        std::fs::create_dir(&owned).expect("The test must create a directory at the owned path.");

        let err = boot_with_db(keys.path(), &slash.path().join("a.sqlite"), false).await;

        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Boot must return exit code 12 for the unreadable entry {}. The error is: {err}",
            owned.display()
        );
    }

    /// Boot checks the file name of the slashing database before SQLite
    /// opens it. A new database is allowed. Each row requires these results:
    ///
    /// - Boot returns exit code 1 with an error that gives the reason.
    /// - No file is at the database path after boot.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_a_db_name_that_cannot_get_a_fallback_marker() {
        let rows = [
            (
                "a name in the reserved name space",
                ".rvc.doppelganger_detected.other.sqlite".to_string(),
                "name space",
            ),
            ("a name of 229 bytes", format!("{}.sqlite", "x".repeat(222)), "at most 255 bytes"),
        ];
        for (case, name, reason) in rows {
            let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
            let slash = tempfile::tempdir().expect("The test must create the database directory.");
            let db = slash.path().join(&name);

            let err = boot_with_db(keys.path(), &db, true).await;

            assert_eq!(
                err.exit_code(),
                1,
                "Boot must return exit code 1 for {case}. The error is: {err}"
            );
            assert!(
                err.to_string().contains(reason),
                "The error must give the reason \"{reason}\" for {case}. The error is: {err}"
            );
            assert!(
                std::fs::symlink_metadata(&db).is_err(),
                "Boot must not create a file at the database path for {case}."
            );
        }
    }

    /// The databases `<slash>/a.sqlite` and `<slash>/h.sqlite` have owned
    /// fallback markers. `<other>/h.sqlite` is a hard link of `h.sqlite`.
    /// Each row boots with a second name of a database and gives the exit
    /// code and a text of the error. A name with a `.` component selects the
    /// same fallback marker, so boot returns exit code 12. Boot refuses each
    /// other name with exit code 1. This includes a database directory that
    /// is a symlink to the keystore directory: boot does not skip the
    /// fallback check for it.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_a_second_name_of_a_database_with_a_fallback_marker() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let [keys, slash, other] = ["keys", "slash", "other"].map(|name| root.path().join(name));
        for dir in [&keys, &slash, &other] {
            std::fs::create_dir(dir).expect("The test must create a directory.");
        }
        let body = serde_json::json!({
            "version": 1,
            "epoch": 3,
            "unix_secs": 4,
            "pubkeys": [],
            "keystore_dir": keys.to_string_lossy(),
        });
        for name in ["a.sqlite", "h.sqlite"] {
            std::fs::write(slash.join(name), b"db").expect("The test must write a database.");
            let owned = slash.join(format!(".rvc.doppelganger_detected.{name}"));
            std::fs::write(owned, body.to_string()).expect("The test must write the marker.");
        }
        std::os::unix::fs::symlink(slash.join("a.sqlite"), other.join("a.sqlite"))
            .expect("The test must create a symlink to the database file.");
        std::fs::hard_link(slash.join("h.sqlite"), other.join("h.sqlite"))
            .expect("The test must create a hard link of the database file.");
        std::os::unix::fs::symlink(&slash, root.path().join("link"))
            .expect("The test must create a symlink to the database directory.");
        std::os::unix::fs::symlink(&keys, root.path().join("keys-link"))
            .expect("The test must create a symlink to the keystore directory.");
        let detected = EXIT_DOPPELGANGER_DETECTED;
        let rows = [
            (
                "a symlink to the keystore directory",
                root.path().join("keys-link/a.sqlite"),
                1,
                "no symlink",
            ),
            ("a symlink to the database file", other.join("a.sqlite"), 1, "one link"),
            ("a hard link of the database file", other.join("h.sqlite"), 1, "one link"),
            ("the first name of a file with two links", slash.join("h.sqlite"), 1, "one link"),
            ("a symlink in the directory path", root.path().join("link/a.sqlite"), 1, "no symlink"),
            ("a `..` in the directory path", other.join("../slash/a.sqlite"), 1, "no symlink"),
            ("a missing database directory", root.path().join("no/a.sqlite"), 1, "no symlink"),
            ("a `.` in the directory path", slash.join("./a.sqlite"), detected, "detected"),
        ];
        for (case, db, code, text) in rows {
            let err = boot_with_db(&keys, &db, false).await;

            assert!(
                err.exit_code() == code && err.to_string().contains(text),
                "Boot must return exit code {code} and an error with the text \"{text}\" for \
                 {case}. The error is: {err}"
            );
        }
    }

    /// The owned fallback marker of `slashing.sqlite` is in the directory
    /// `slash`. `arm_walk_start` makes `slash` the working directory of each
    /// walk, so the test does not change the working directory of the
    /// process. For the names `./slashing.sqlite` and `slashing.sqlite`, boot
    /// must return exit code 12.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_an_owned_fallback_marker_of_a_bare_db_name() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let slash = tempfile::tempdir().expect("The test must create the database directory.");
        let body = serde_json::json!({ "version": 1, "epoch": 3, "unix_secs": 4, "pubkeys": [] });
        std::fs::write(
            slash.path().join(".rvc.doppelganger_detected.slashing.sqlite"),
            body.to_string(),
        )
        .expect("The test must write the owned fallback marker.");
        let _start = crate::detection_marker::arm_walk_start(slash.path());

        for name in ["./slashing.sqlite", "slashing.sqlite"] {
            let err = boot_with_db(keys.path(), std::path::Path::new(name), false).await;

            assert_eq!(
                err.exit_code(),
                EXIT_DOPPELGANGER_DETECTED,
                "Boot must return exit code 12 for the database name {name}. The error is: {err}"
            );
        }
    }

    #[tokio::test]
    async fn detection_enabled_refuses_a_keystore_dir_that_cannot_hold_the_marker() {
        let missing = std::env::temp_dir().join(format!(
            "rvc-dg-unwritable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let config = crate::config::Config {
            keystore_path: missing,
            doppelganger_detection: true,
            ..Default::default()
        };
        let token = CancellationToken::new();
        let (executor, rx) = TaskExecutor::new(token);
        let err = run(
            config,
            RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            executor,
            rx,
        )
        .await
        .expect_err("an unwritable keystore must not start with detection on");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn detection_enabled_refuses_when_the_record_cannot_be_preallocated() {
        let _guard = crate::detection_marker::arm_preallocate_failure();
        let dir = tempfile::tempdir().expect("temp");
        let config = crate::config::Config {
            keystore_path: dir.path().to_path_buf(),
            doppelganger_detection: true,
            ..Default::default()
        };
        let token = CancellationToken::new();
        let (executor, rx) = TaskExecutor::new(token);
        let err = run(
            config,
            RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            executor,
            rx,
        )
        .await
        .expect_err("a record that cannot be preallocated must not start");
        assert_eq!(err.exit_code(), 1);
        let text = err.to_string();
        assert!(text.contains("detection record"), "{text}");
        assert!(text.contains("latch"), "{text}");
    }

    #[tokio::test]
    async fn detection_disabled_does_not_probe_marker_writability() {
        let missing = std::env::temp_dir().join(format!(
            "rvc-dg-noprobe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let config = crate::config::Config {
            keystore_path: missing,
            doppelganger_detection: false,
            ..Default::default()
        };
        let token = CancellationToken::new();
        let (executor, rx) = TaskExecutor::new(token);
        let err = run(
            config,
            RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            executor,
            rx,
        )
        .await
        .expect_err("startup still fails later without a slashing db");
        assert_ne!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);
        assert!(!err.to_string().contains("writable"), "{err}");
    }

    /// Run boot with `config` and the default run options. Return the boot
    /// error.
    async fn boot_error(config: Config) -> BootstrapError {
        let (executor, rx) = TaskExecutor::new(CancellationToken::new());
        let options = RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: OperationTimeouts::default(),
        };
        run(config, options, executor, rx).await.expect_err("Boot must return an error.")
    }

    /// Return a record of `RECORD_LEN` bytes with the state `detected`.
    fn detected_record() -> Vec<u8> {
        let mut bytes = b"version=1\nstate=detected\nepoch=5\nunix_secs=6\n".to_vec();
        bytes.resize(crate::detection_marker::RECORD_LEN, 0);
        bytes
    }

    /// Split `command` into words by the POSIX shell rules for single quotes
    /// and a backslash. Outside quotes, a space ends a word. The function
    /// returns an error for these items:
    ///
    /// - A single quote that does not end.
    /// - A backslash at the end of the command.
    /// - An unquoted character that is not a letter, a digit, `-`, `_`, `.`
    ///   or `/`. The shell can give such a character a special meaning.
    fn shell_words(command: &str) -> Result<Vec<String>, String> {
        let mut words = Vec::new();
        let mut word: Option<String> = None;
        let mut chars = command.chars();
        while let Some(c) = chars.next() {
            if c == ' ' {
                words.extend(word.take());
                continue;
            }
            let text = word.get_or_insert_with(String::new);
            if c == '\'' {
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(quoted) => text.push(quoted),
                        None => {
                            return Err(format!(
                                "The command has a single quote that does not end: {command}"
                            ));
                        }
                    }
                }
            } else if c == '\\' {
                let escaped = chars
                    .next()
                    .ok_or_else(|| format!("The command ends with a backslash: {command}"))?;
                text.push(escaped);
            } else if c.is_ascii_alphanumeric() || "-_./".contains(c) {
                text.push(c);
            } else {
                return Err(format!(
                    "The command has the unquoted character {c:?}, and the shell can give it a \
                     special meaning: {command}"
                ));
            }
        }
        words.extend(word);
        Ok(words)
    }

    /// Return the `clear-detection` command of each refusal hint in `lines`,
    /// split into shell words.
    fn printed_commands(lines: &[&str]) -> Vec<Result<Vec<String>, String>> {
        lines
            .iter()
            .filter_map(|line| {
                let (_, rest) = line.split_once("Clear it with `")?;
                let (command, _) = rest.split_once("` after the other instance is gone")?;
                Some(shell_words(command))
            })
            .collect()
    }

    /// Return the arguments of the clear command for the keystore `keys` and
    /// the database `db`.
    fn clear_command(keys: &std::path::Path, db: &std::path::Path) -> Vec<String> {
        let [keys, db] = [keys, db]
            .map(|path| path.to_str().expect("The test paths must be UTF-8.").to_string());
        ["rvc", "doppelganger", "clear-detection", "--datadir", &keys]
            .into_iter()
            .chain(["--slashing-db-path", &db, "--confirm"])
            .map(String::from)
            .collect()
    }

    /// The start of the name of each temporary directory of the hint tests:
    /// a space, a single quote and the characters `$`, `;`, `` ` `` and `&`.
    const SHELL_CHARACTERS: &str = "dir '$;`&";

    /// Return a new temporary directory. Its name starts with
    /// [`SHELL_CHARACTERS`].
    fn shell_char_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(SHELL_CHARACTERS)
            .tempdir()
            .expect("The test must create a temporary directory.")
    }

    /// The hint gives each path as one shell word. The hint gives no command
    /// when it cannot show a path exactly. The test requires these results:
    ///
    /// - The test parser splits a known command into the known words. The
    ///   parser rejects an unquoted `;` and a single quote that does not end.
    /// - For paths with a space, a single quote and the characters `$`, `;`,
    ///   `` ` `` and `&`, the shell words of the command are the expected
    ///   arguments.
    /// - For a keystore path or a database path that is not UTF-8 or that has
    ///   a line feed, the hint has no command. The hint tells the operator to
    ///   type each path.
    #[cfg(unix)]
    #[test]
    fn clear_hint_gives_each_path_as_one_shell_word() {
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;
        assert_eq!(
            shell_words(r"a 'b c' d\ e'' 'f'\''g'"),
            Ok(["a", "b c", "d e", "f'g"].map(String::from).to_vec()),
            "The test parser must split the known command into the known words."
        );
        assert!(
            shell_words("a;b").is_err() && shell_words("'a").is_err(),
            "The test parser must reject an unquoted `;` and a single quote that does not end."
        );

        let keys = Path::new("/srv/my keys/it's $HOME;`id`&x");
        let db = Path::new("/srv/'db'/a'b.sqlite");
        let hint = detection_clear_hint(keys, db);
        assert_eq!(
            printed_commands(&[hint.as_str()]),
            vec![Ok(clear_command(keys, db))],
            "The shell words of the command must be the expected arguments. The hint is: {hint}"
        );

        let not_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"/srv/keys-\xff"));
        let line_feed = Path::new("/srv/keys\nx");
        for (keys, db) in [(not_utf8, db), (line_feed, db), (keys, not_utf8), (keys, line_feed)] {
            let hint = detection_clear_hint(keys, db);
            assert!(
                printed_commands(&[hint.as_str()]).is_empty() && hint.contains("type each path"),
                "The hint must have no command and must tell the operator to type each path. \
                 The hint is: {hint}"
            );
        }
    }

    /// Each row writes one item of detection evidence for the keystore `keys`
    /// and the database `<slash>/slashing.sqlite`. Then boot runs with
    /// detection off. The name of each temporary directory starts with
    /// [`SHELL_CHARACTERS`]. Three more boots use these fixtures:
    ///
    /// - Detection is on. A hook writes a detected record after boot checks
    ///   the record. The hook runs before boot links the new record.
    /// - The database path is the bare name `slashing.sqlite`, and the record
    ///   is `detected`.
    /// - The keystore path has a symlink, and a marker of that keystore is at
    ///   the owned fallback path.
    ///
    /// For each boot, the test requires these results:
    ///
    /// - Boot returns exit code 12.
    /// - A refusal log gives a command with these shell words: `rvc
    ///   doppelganger clear-detection --datadir <keys> --slashing-db-path
    ///   <db> --confirm`. Each path is absolute. For the bare name, `<db>` is
    ///   the name in the working directory of the process. For the symlink,
    ///   `<keys>` is the keystore that the marker records.
    ///
    /// The test records each boot that fails a check. The assertion lists
    /// these boots.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn boot_refusal_prints_the_resolved_clear_command() {
        use crate::detection_marker::{
            arm_before_record_link, marker_path, record_path, write_fallback_marker, write_marker,
            DetectionMarker, FallbackMarkerPath, MARKER_FILENAME, RECORD_LEN,
        };
        use std::path::Path;
        const NO_KEYS: &str = r#"{"version":1,"epoch":3,"unix_secs":4,"pubkeys":[]}"#;
        type Setup = fn(&Path, &Path);
        let rows: [(&str, Setup); 8] = [
            ("a keystore marker with a key", |keys, _| {
                let pubkeys = vec![format!("0x{}", "cd".repeat(48))];
                write_marker(keys, &DetectionMarker { epoch: 1, unix_secs: 2, pubkeys })
                    .expect("The test must write the keystore marker.");
            }),
            ("a keystore marker with no key", |keys, _| {
                std::fs::write(marker_path(keys), NO_KEYS)
                    .expect("The test must write the keystore marker.");
            }),
            ("a corrupt keystore marker", |keys, _| {
                std::fs::write(marker_path(keys), b"{")
                    .expect("The test must write the corrupt marker.");
            }),
            ("an unreadable keystore marker", |keys, _| {
                std::fs::create_dir(marker_path(keys))
                    .expect("The test must create a directory at the marker path.");
            }),
            ("a detected record", |keys, _| {
                std::fs::write(record_path(keys), detected_record())
                    .expect("The test must write the detected record.");
            }),
            ("a record that does not parse", |keys, _| {
                std::fs::write(record_path(keys), vec![0u8; RECORD_LEN])
                    .expect("The test must write the zero-filled record.");
            }),
            ("a marker at the owned fallback path", |_, slash| {
                std::fs::write(slash.join(".rvc.doppelganger_detected.slashing.sqlite"), NO_KEYS)
                    .expect("The test must write a marker at the owned fallback path.");
            }),
            ("a legacy fallback marker", |_, slash| {
                std::fs::write(slash.join(MARKER_FILENAME), NO_KEYS)
                    .expect("The test must write the legacy fallback marker.");
            }),
        ];
        let mut failed = Vec::new();
        let mut check = |case: &str, err: BootstrapError, keys: &Path, db: &Path| {
            let expected = Ok(clear_command(keys, db));
            let printed = std::cell::Cell::new(false);
            logs_assert(|lines| {
                printed.set(printed_commands(lines).contains(&expected));
                Ok(())
            });
            if err.exit_code() != EXIT_DOPPELGANGER_DETECTED || !printed.get() {
                failed.push(format!("{case}: exit code {}, error \"{err}\"", err.exit_code()));
            }
        };
        let config = |keys: &Path, db: &Path, detection: bool| Config {
            keystore_path: keys.to_path_buf(),
            slashing_db_path: db.to_path_buf(),
            doppelganger_detection: detection,
            ..Default::default()
        };

        for (case, setup) in rows {
            let keys = shell_char_tempdir();
            let slash = shell_char_tempdir();
            let db = slash.path().join("slashing.sqlite");
            setup(keys.path(), slash.path());
            let err = boot_error(config(keys.path(), &db, false)).await;
            check(case, err, keys.path(), &db);
        }

        let keys = shell_char_tempdir();
        let slash = shell_char_tempdir();
        let db = slash.path().join("slashing.sqlite");
        let record = record_path(keys.path());
        let link = arm_before_record_link(move || {
            std::fs::write(&record, detected_record())
                .expect("The hook must write the detected record.");
        });
        let err = boot_error(config(keys.path(), &db, true)).await;
        drop(link);
        check("a record that is detected before the link", err, keys.path(), &db);

        let keys = shell_char_tempdir();
        std::fs::write(record_path(keys.path()), detected_record())
            .expect("The test must write the detected record.");
        let bare = Path::new("slashing.sqlite");
        let err = boot_error(config(keys.path(), bare, false)).await;
        let cwd = std::env::current_dir().expect("The test must read the working directory.");
        check("a bare database name", err, keys.path(), &cwd.join(bare));

        let root = shell_char_tempdir();
        let keys = root.path().join("keys-link");
        std::fs::create_dir(root.path().join("keys"))
            .expect("The test must create the keystore directory.");
        std::os::unix::fs::symlink("keys", &keys)
            .expect("The test must create the keystore symlink.");
        let slash = shell_char_tempdir();
        let db = slash.path().join("slashing.sqlite");
        let fallback = FallbackMarkerPath::for_config(&keys, &db)
            .expect("The database directory must get a fallback marker.");
        let marker = DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: Vec::new() };
        write_fallback_marker(&fallback, &keys, &marker)
            .expect("The test must write a marker at the owned fallback path.");
        let bytes = std::fs::read(fallback.owned_path()).expect("The test must read the marker.");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("The marker must be a JSON document.");
        let owner = body["keystore_dir"].as_str().expect("The marker must record its keystore.");
        let err = boot_error(config(&keys, &db, false)).await;
        check("a keystore path with a symlink", err, Path::new(owner), &db);

        assert!(
            failed.is_empty(),
            "Each refusal must exit 12 and log the complete clear-detection command. Each \
             absolute path must be one shell word. These boots do not: {failed:#?}"
        );
    }

    /// Return a keystore directory, a database directory with a valid
    /// database, and a boot config for the two. The genesis validators root
    /// `0xzz` stops boot after the slashing database step and before a
    /// network call.
    fn fallback_probe_fixture(detection: bool) -> (tempfile::TempDir, tempfile::TempDir, Config) {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let slash = tempfile::tempdir().expect("The test must create the database directory.");
        let db = slash.path().join("slashing.sqlite");
        try_seed_slashing_db(&db);
        let config = Config {
            keystore_path: keys.path().to_path_buf(),
            slashing_db_path: db,
            genesis_validators_root: Some("0xzz".to_string()),
            doppelganger_detection: detection,
            ..Default::default()
        };
        (keys, slash, config)
    }

    /// Detection is on. The keystore directory takes the probe, and the hook
    /// fails the probe of the database directory. The test requires these
    /// results:
    ///
    /// - Boot returns exit code 1.
    /// - The error names the slashing database directory and contains
    ///   "writable".
    /// - No probe file stays in the database directory.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_when_the_fallback_dir_cannot_hold_a_marker() {
        let (_keys, slash, config) = fallback_probe_fixture(true);
        let _probe = crate::detection_marker::arm_probe_failure(slash.path());

        let err = boot_error(config).await;

        let text = err.to_string();
        let dir = format!("slashing database directory {}", slash.path().display());
        assert!(
            err.exit_code() == 1 && text.contains(&dir) && text.contains("writable"),
            "Boot must return exit code 1 with an error that contains \"{dir}\" and \
             \"writable\". The exit code is {}. The error is: {text}",
            err.exit_code()
        );
        let probes: Vec<String> = sorted_names(slash.path())
            .into_iter()
            .filter(|name| name.ends_with(".probe"))
            .collect();
        assert!(
            probes.is_empty(),
            "The failed probe must leave no probe file in the database directory: {probes:?}"
        );
    }

    /// Detection is on. The database path is relative, and each walk starts
    /// in a temporary directory that is not the working directory of the
    /// process. Thus a probe that opens the database directory again by its
    /// path does not find it. The keystore path is absolute. The hook fails
    /// the record step. On Linux, the test injects `EOPNOTSUPP` into the
    /// `O_TMPFILE` open, so the probe uses the private subdirectory. The test
    /// requires these results:
    ///
    /// - Boot passes the probe of the database directory and returns the
    ///   error of the record step.
    /// - No probe entry stays in the database directory.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_probes_the_fallback_dir_through_the_handle_of_the_walk() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let root = tempfile::tempdir().expect("The test must create the start directory.");
        let slash = tempfile::tempdir_in(root.path())
            .expect("The test must create the database directory.");
        let name = slash.path().file_name().expect("The database directory must have a name.");
        let _start = crate::detection_marker::arm_walk_start(root.path());
        let _record = crate::detection_marker::arm_preallocate_failure();
        #[cfg(target_os = "linux")]
        let _unnamed = crate::detection_marker::arm_unnamed_probe_error(libc::EOPNOTSUPP);
        let config = Config {
            keystore_path: keys.path().to_path_buf(),
            slashing_db_path: std::path::Path::new(name).join("slashing.sqlite"),
            doppelganger_detection: true,
            ..Default::default()
        };

        let err = boot_error(config).await;

        let text = err.to_string();
        assert!(
            err.exit_code() == 1 && text.contains("cannot preallocate"),
            "Boot must probe the database directory through the handle of the walk. Then boot \
             must return the error of the record step. The exit code is {}. The error is: {text}",
            err.exit_code()
        );
        let probes: Vec<String> = sorted_names(slash.path())
            .into_iter()
            .filter(|name| name.ends_with(".probe"))
            .collect();
        assert!(
            probes.is_empty(),
            "The probe must remove its entry from the database directory: {probes:?}"
        );
    }

    /// Detection is on. At one step of the probe of the database directory, a
    /// hook moves the probe entry to a different name. Then the hook puts a
    /// different entry at the name of the probe entry. The rows are:
    ///
    /// - Before the create, an empty directory with mode 0700 gets the name.
    ///   The hook moves no entry.
    /// - Before the open, an empty directory with mode 0755 gets the name.
    /// - Before the identity check, an empty directory with mode 0700 gets
    ///   the name.
    /// - After the identity check and before the removal, a file gets the
    ///   name.
    /// - After the identity check and before the removal, a directory with a
    ///   file gets the name.
    ///
    /// On Linux, the test injects `EOPNOTSUPP` into the `O_TMPFILE` open, so
    /// the probe uses the private subdirectory. For each row, the test
    /// requires these results:
    ///
    /// - Boot returns exit code 1, and the error names the database
    ///   directory.
    /// - The different entry stays at the name of the probe entry.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_keeps_an_entry_that_replaces_the_probe_entry() {
        use crate::detection_marker::{arm_probe_step, ProbeStep};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        #[derive(Clone, Copy)]
        enum Other {
            Dir(u32),
            File,
            DirWithFile,
        }
        fn entry_id(path: &std::path::Path) -> Option<(u64, u64)> {
            std::fs::symlink_metadata(path).ok().map(|meta| (meta.dev(), meta.ino()))
        }
        let rows = [
            (
                "an empty directory with mode 0700 before the create",
                ProbeStep::Create,
                Other::Dir(0o700),
            ),
            (
                "an empty directory with mode 0755 before the open",
                ProbeStep::Open,
                Other::Dir(0o755),
            ),
            (
                "an empty directory with mode 0700 before the identity check",
                ProbeStep::Check,
                Other::Dir(0o700),
            ),
            ("a file after the identity check", ProbeStep::Remove, Other::File),
            (
                "a directory with a file after the identity check",
                ProbeStep::Remove,
                Other::DirWithFile,
            ),
        ];
        let mut failed = Vec::new();
        for (row, step, other) in rows {
            let (_keys, slash, config) = fallback_probe_fixture(true);
            let made = std::rc::Rc::new(std::cell::RefCell::new(None));
            let record = std::rc::Rc::clone(&made);
            #[cfg(target_os = "linux")]
            let _unnamed = crate::detection_marker::arm_unnamed_probe_error(libc::EOPNOTSUPP);
            let _hook = arm_probe_step(slash.path(), step, move |entry| {
                if step != ProbeStep::Create {
                    std::fs::rename(entry, entry.with_extension("moved"))
                        .expect("The hook must move the probe entry.");
                }
                let put = match other {
                    Other::File => std::fs::write(entry, b"other"),
                    Other::Dir(mode) => std::fs::create_dir(entry).and_then(|()| {
                        std::fs::set_permissions(entry, std::fs::Permissions::from_mode(mode))
                    }),
                    Other::DirWithFile => std::fs::create_dir(entry)
                        .and_then(|()| std::fs::write(entry.join("other"), b"other")),
                };
                put.expect("The hook must put the different entry at the name of the probe entry.");
                *record.borrow_mut() = Some((entry.to_path_buf(), entry_id(entry)));
            });

            let err = boot_error(config).await;

            let text = err.to_string();
            let dir = format!("slashing database directory {}", slash.path().display());
            let kept = made
                .borrow()
                .as_ref()
                .is_some_and(|(entry, id)| id.is_some() && entry_id(entry) == *id);
            if err.exit_code() != 1 || !text.contains(&dir) || !kept {
                failed.push(format!(
                    "{row}: exit code {}, different entry kept {kept}, error {text}",
                    err.exit_code()
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "Each boot must return exit code 1 with an error that names the database directory. \
             Each boot must keep the different entry at the name of the probe entry. These boots \
             do not: {failed:#?}"
        );
    }

    /// Detection is on. A hook reads the probe entry of the database directory
    /// after the identity check and before the removal. On Linux, the test
    /// injects `EISDIR` into the `O_TMPFILE` open, so the probe uses the
    /// private subdirectory. The test requires these results:
    ///
    /// - The probe entry is a directory with mode 0700 that holds one file.
    /// - Boot passes the probe and stops when it checks the genesis validators
    ///   root.
    /// - No probe entry stays in the database directory.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_probes_with_a_file_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let (_keys, slash, config) = fallback_probe_fixture(true);
        #[cfg(target_os = "linux")]
        let _unnamed = crate::detection_marker::arm_unnamed_probe_error(libc::EISDIR);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let record = std::rc::Rc::clone(&seen);
        let step = crate::detection_marker::ProbeStep::Remove;
        let _hook = crate::detection_marker::arm_probe_step(slash.path(), step, move |entry| {
            let meta = std::fs::symlink_metadata(entry).ok().filter(std::fs::Metadata::is_dir);
            let mode = meta.map(|meta| meta.permissions().mode() & 0o777);
            let files = std::fs::read_dir(entry).ok().map(|names| {
                names
                    .map(|name| {
                        name.and_then(|name| name.file_type()).is_ok_and(|kind| kind.is_file())
                    })
                    .collect::<Vec<bool>>()
            });
            *record.borrow_mut() = Some((mode, files));
        });

        let err = boot_error(config).await;

        assert_eq!(
            *seen.borrow(),
            Some((Some(0o700), Some(vec![true]))),
            "Before the removal, the probe entry must be a directory with mode 0700 that holds \
             one file."
        );
        let text = err.to_string();
        assert!(
            text.contains("genesis validators root"),
            "Boot must pass the probe and stop when it checks the genesis validators root. The \
             error is: {text}"
        );
        let probes: Vec<String> = sorted_names(slash.path())
            .into_iter()
            .filter(|name| name.ends_with(".probe"))
            .collect();
        assert!(
            probes.is_empty(),
            "The probe must remove its entry from the database directory: {probes:?}"
        );
    }

    /// Detection is on, and the probe of the database directory opens a file
    /// with no name (`O_TMPFILE`). The database path is relative, and each
    /// walk starts in a temporary directory that is not the working
    /// directory. The hook fails the record step after the probe. At one step
    /// of the probe, a hook adds an empty directory with mode 0700 and a file
    /// to the database directory. For each step, the test requires these
    /// results:
    ///
    /// - At the step, the database directory holds no entry.
    /// - Boot passes the probe with no fallback and returns the error of the
    ///   record step.
    /// - After boot, the database directory holds only the two entries of the
    ///   hook, with the device and inode numbers from the hook.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_probes_the_fallback_dir_with_a_file_that_has_no_name() {
        use crate::detection_marker::{arm_probe_step, fallback_probes, ProbeStep};
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        fn ids(paths: &[std::path::PathBuf]) -> Vec<Option<(u64, u64)>> {
            let id = |path: &std::path::PathBuf| std::fs::symlink_metadata(path).ok();
            paths.iter().map(|path| id(path).map(|meta| (meta.dev(), meta.ino()))).collect()
        }
        let mut failed = Vec::new();
        for step in [ProbeStep::Unnamed, ProbeStep::SyncDir] {
            let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
            let root = tempfile::tempdir().expect("The test must create the start directory.");
            let slash = tempfile::tempdir_in(root.path())
                .expect("The test must create the database directory.");
            let name = slash.path().file_name().expect("The database directory must have a name.");
            let _start = crate::detection_marker::arm_walk_start(root.path());
            let _record = crate::detection_marker::arm_preallocate_failure();
            let added = vec![slash.path().join("added-dir"), slash.path().join("added-file")];
            let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
            let (record, dir, paths) =
                (std::rc::Rc::clone(&seen), slash.path().to_path_buf(), added.clone());
            let _hook = arm_probe_step(std::path::Path::new(name), step, move |_| {
                let names = sorted_names(&dir);
                let made = std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&paths[0])
                    .and_then(|()| std::fs::write(&paths[1], b"added"));
                *record.borrow_mut() = Some((names, made.is_ok(), ids(&paths)));
            });
            let config = Config {
                keystore_path: keys.path().to_path_buf(),
                slashing_db_path: std::path::Path::new(name).join("slashing.sqlite"),
                doppelganger_detection: true,
                ..Default::default()
            };
            let fallbacks = fallback_probes();

            let err = boot_error(config).await;

            let fallbacks = fallback_probes() - fallbacks;
            let after = sorted_names(slash.path());
            let text = err.to_string();
            let hook = seen.borrow().clone();
            let kept = hook.as_ref().is_some_and(|(names, made, made_ids)| {
                names.is_empty() && *made && *made_ids == ids(&added)
            });
            let stopped = err.exit_code() == 1 && text.contains("cannot preallocate");
            if !kept || after != ["added-dir", "added-file"] || fallbacks != 0 || !stopped {
                failed.push(format!(
                    "{step:?}: hook {hook:?}, entries after boot {after:?}, fallback probes \
                     {fallbacks}, exit code {}, error {text}",
                    err.exit_code()
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "At each step, the probe must add no entry to the database directory and must remove \
             no entry. Boot must pass the probe with no fallback and stop at the record step. \
             These steps do not: {failed:#?}"
        );
    }

    /// Detection is on, and one step of the probe with no name fails. The
    /// rows are:
    ///
    /// - The `O_TMPFILE` open fails with `EACCES`.
    /// - The `O_TMPFILE` open fails with `EIO`.
    /// - The write of the file with no name fails with `ENOSPC`.
    /// - The fsync of the file with no name fails with `EIO`.
    /// - The fsync of the database directory fails with `EIO`.
    ///
    /// For each row, the test requires these results:
    ///
    /// - Boot returns exit code 1, and the error names the database directory.
    /// - The probe does not use the private subdirectory.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_stops_at_each_error_of_the_unnamed_probe() {
        use crate::detection_marker::{
            arm_fsync_failures_after, arm_unnamed_probe_error, arm_unnamed_probe_write_error,
            fallback_probes,
        };
        // The probe of the keystore directory does two fsyncs before this probe.
        let rows = [
            ("an EACCES open", Some(libc::EACCES), None, None),
            ("an EIO open", Some(libc::EIO), None, None),
            ("an ENOSPC write of the file", None, Some(libc::ENOSPC), None),
            ("an EIO fsync of the file", None, None, Some(2)),
            ("an EIO fsync of the directory", None, None, Some(3)),
        ];
        let mut failed = Vec::new();
        for (row, open, write, skip) in rows {
            let (_keys, slash, config) = fallback_probe_fixture(true);
            let _open = open.map(arm_unnamed_probe_error);
            let _write = write.map(arm_unnamed_probe_write_error);
            let _sync = skip.map(|skip| arm_fsync_failures_after(skip, 1));
            let fallbacks = fallback_probes();

            let err = boot_error(config).await;

            let fallbacks = fallback_probes() - fallbacks;
            let text = err.to_string();
            let dir = format!("slashing database directory {}", slash.path().display());
            if err.exit_code() != 1 || !text.contains(&dir) || fallbacks != 0 {
                failed.push(format!(
                    "{row}: exit code {}, fallback probes {fallbacks}, error {text}",
                    err.exit_code()
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "For each error of the probe with no name, boot must return exit code 1 with an error \
             that names the database directory. The probe must not use the private \
             subdirectory. These boots do not: {failed:#?}"
        );
    }

    /// Detection is off, and the hook fails the probe of the database
    /// directory. The test requires these results:
    ///
    /// - The probe count of this thread does not change.
    /// - Boot stops when it checks the genesis validators root.
    /// - The error omits the database directory and the word "writable".
    #[tokio::test(flavor = "current_thread")]
    async fn detection_off_does_not_probe_the_fallback_dir() {
        let (_keys, slash, config) = fallback_probe_fixture(false);
        let _probe = crate::detection_marker::arm_probe_failure(slash.path());
        let before = crate::detection_marker::probe_attempts();

        let err = boot_error(config).await;

        let after = crate::detection_marker::probe_attempts();
        assert_eq!(
            after, before,
            "With detection off, boot must not probe a directory. The probe count must stay \
             at {before}."
        );
        let text = err.to_string();
        let dir = slash.path().display().to_string();
        assert!(
            text.contains("genesis validators root")
                && !text.contains(&dir)
                && !text.contains("writable"),
            "With detection off, boot must stop when it checks the genesis validators root. The \
             error must omit {dir} and the word \"writable\". The error is: {text}"
        );
    }

    async fn boot_with_keystore(dir: &std::path::Path) -> BootstrapError {
        let config = crate::config::Config {
            keystore_path: dir.to_path_buf(),
            // The marker refuses start even when detection is switched off.
            doppelganger_detection: false,
            ..Default::default()
        };
        let token = CancellationToken::new();
        let (executor, rx) = TaskExecutor::new(token);
        run(
            config,
            RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            executor,
            rx,
        )
        .await
        .expect_err("marker must refuse start")
    }

    /// A detection that arrives after shutdown has started still exits 12.
    #[tokio::test]
    async fn detection_during_drain_still_exits_12() {
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let task_token = executor.token();
        let entered_task = std::sync::Arc::clone(&entered);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        executor.spawn("drain_probe", ShutdownTier::Background, async move {
            task_token.cancelled().await;
            entered_task.notify_one();
            let _ = release_rx.await;
        });
        let handle = executor.shutdown_handle();
        let budget = TierBudget::new([
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        ]);
        let drain = tokio::spawn(async move {
            await_shutdown_and_drain_with_signal(
                ShutdownInputs {
                    executor,
                    orchestrator_handle: crate::orchestrator::OrchestratorHandle::for_drain_test(),
                    shutdown_rx,
                    shutdown_token: token,
                    budget,
                    detection: None,
                },
                std::future::ready(()),
            )
            .await
        });
        entered.notified().await;
        handle.request_exit(EXIT_DOPPELGANGER_DETECTED);
        let _ = release_tx.send(());
        let (_outcome, res) = drain.await.expect("drain task");
        assert!(
            matches!(res, Err(BootstrapError::DoppelgangerDetected)),
            "detection during the drain must exit 12, got {res:?}"
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

    /// W4-E2b: the epoch boundary runner is its own Orchestrator-tier executor
    /// task, spawned before the slot loop. A missing runner fails boot with
    /// [`BootstrapError::EpochBoundaryRunnerMissing`].
    ///
    /// The spawn passes the task name as a literal: the census scan rejects a
    /// path argument such as `epoch_boundary::TASK_NAME`.
    #[test]
    fn runner_is_spawned_on_the_orchestrator_tier() {
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production body before tests");
        let start =
            prod.find("async fn run_with_clock<").expect("run.rs must define run_with_clock.");
        let rest = &prod[start..];
        let end = rest.find("pub(crate) struct ShutdownInputs").expect("end of run");
        let run_fn = squash(&rest[..end]);

        let take = squash(
            "let Some(boundary) = orchestrator.take_epoch_boundary_runner() else {
                return Err(stop_boot_tasks(executor, BootstrapError::EpochBoundaryRunnerMissing).await);
            };",
        );
        let spawn = format!(
            "executor.spawn(\"{}\", ShutdownTier::Orchestrator, boundary.run());",
            crate::orchestrator::epoch_boundary::TASK_NAME
        );
        let orchestrator =
            "executor.spawn_result(\"duty_orchestrator\", ShutdownTier::Orchestrator,";

        let take_at =
            run_fn.find(&take).expect("a missing runner returns EpochBoundaryRunnerMissing");
        let spawn_at = run_fn.find(&spawn).expect("the runner is spawned on the Orchestrator tier");
        let orch_at = run_fn.find(orchestrator).expect("duty_orchestrator spawn");
        assert_eq!(run_fn.matches("take_epoch_boundary_runner").count(), 1, "one take");
        assert_eq!(run_fn.matches("boundary.run()").count(), 1, "one runner spawn");
        assert!(take_at < spawn_at, "take the runner before spawning it");
        assert!(spawn_at < orch_at, "spawn the runner before the duty_orchestrator task");
    }

    /// The kind of a token from [`rust_tokens`].
    #[derive(PartialEq, Eq)]
    enum TokenKind {
        /// A line comment or a block comment.
        Comment,
        /// A string literal or a character literal. This includes byte
        /// strings, C strings and raw strings.
        Literal,
        /// A word or one punctuation character. A word is an identifier, a
        /// keyword, a number or a lifetime.
        Code,
    }

    /// Split the Rust source `src` into tokens. Return the kind and the byte
    /// range of each token. Whitespace is not a token. A comment or a literal
    /// with no end stops at the end of `src`.
    fn rust_tokens(src: &str) -> Vec<(TokenKind, std::ops::Range<usize>)> {
        let word = |c: char| c.is_alphanumeric() || c == '_';
        let mut tokens = Vec::new();
        let mut at = 0;
        while let Some(c) = src[at..].chars().next() {
            let rest = &src[at..];
            let (kind, len) = if rest.starts_with("//") {
                (TokenKind::Comment, rest.find('\n').unwrap_or(rest.len()))
            } else if rest.starts_with("/*") {
                (TokenKind::Comment, block_comment_len(rest))
            } else if let Some(len) = literal_len(rest) {
                (TokenKind::Literal, len)
            } else if word(c) || c == '\'' {
                (TokenKind::Code, rest.len() - rest[c.len_utf8()..].trim_start_matches(word).len())
            } else {
                (TokenKind::Code, c.len_utf8())
            };
            if !c.is_whitespace() {
                tokens.push((kind, at..at + len));
            }
            at += len;
        }
        tokens
    }

    /// Return the byte length of the block comment at the start of `text`.
    /// A block comment can contain block comments.
    fn block_comment_len(text: &str) -> usize {
        let mut depth = 0usize;
        let mut at = 0;
        while let Some(c) = text[at..].chars().next() {
            if text[at..].starts_with("/*") {
                depth += 1;
                at += 2;
            } else if text[at..].starts_with("*/") {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return at;
                }
            } else {
                at += c.len_utf8();
            }
        }
        text.len()
    }

    /// Return the byte length of the string or character literal at the
    /// start of `text`. Return `None` if no literal starts there. A raw
    /// string can have `#` delimiters. A literal with no end stops at the end
    /// of `text`.
    fn literal_len(text: &str) -> Option<usize> {
        let rest = text.trim_start_matches(|c: char| c.is_ascii_alphabetic());
        let prefix = &text[..text.len() - rest.len()];
        if matches!(prefix, "r" | "br" | "cr") {
            let quoted = rest.trim_start_matches('#');
            let body = quoted.strip_prefix('"')?;
            let end = format!("\"{}", &rest[..rest.len() - quoted.len()]);
            let len = body.find(&end).map_or(body.len(), |at| at + end.len());
            return Some(text.len() - body.len() + len);
        }
        let quote = rest.chars().next().filter(|&q| q == '"' || q == '\'')?;
        if !matches!((prefix, quote), ("" | "b" | "c", '"') | ("" | "b", '\'')) {
            return None;
        }
        if quote == '\'' {
            let first = rest[1..].chars().next()?;
            if first != '\\' && !rest[1 + first.len_utf8()..].starts_with('\'') {
                return None;
            }
        }
        let mut chars = rest.char_indices().skip(1);
        while let Some((at, c)) = chars.next() {
            if c == '\\' {
                chars.next();
            } else if c == quote {
                return Some(prefix.len() + at + 1);
            }
        }
        Some(text.len())
    }

    /// Return `src` without its comments. A block comment changes to one
    /// space. The `\n` after a line comment stays.
    fn without_comments(src: &str) -> String {
        let mut code = String::with_capacity(src.len());
        let mut at = 0;
        for (kind, range) in rust_tokens(src) {
            if kind == TokenKind::Comment {
                code.push_str(&src[at..range.start]);
                if src[range.clone()].starts_with("/*") {
                    code.push(' ');
                }
                at = range.end;
            }
        }
        code.push_str(&src[at..]);
        code
    }

    /// Return the byte index and the text of each `Code` token in `code`.
    fn code_tokens(code: &str) -> Vec<(usize, &str)> {
        rust_tokens(code)
            .into_iter()
            .filter(|(kind, _)| *kind == TokenKind::Code)
            .map(|(_, range)| (range.start, &code[range]))
            .collect()
    }

    /// Return the byte index of the first run of `Code` tokens in `code`
    /// that is equal to `pattern`.
    fn find_tokens(code: &str, pattern: &[&str]) -> Option<usize> {
        code_tokens(code)
            .windows(pattern.len())
            .find(|run| run.iter().map(|&(_, token)| token).eq(pattern.iter().copied()))
            .map(|run| run[0].0)
    }

    /// Return the index of the bracket that closes the `open_char` at the
    /// byte index `open` in `code`. The scan counts only `Code` tokens, thus
    /// it skips comments and literals. Return `None` if the closing bracket
    /// is missing.
    fn closing_bracket(
        code: &str,
        open: usize,
        (open_char, close_char): (char, char),
    ) -> Option<usize> {
        let mut depth = 0usize;
        code_tokens(&code[open..]).into_iter().find_map(|(at, token)| {
            if token.starts_with(open_char) {
                depth += 1;
            } else if token.starts_with(close_char) {
                depth -= 1;
                return (depth == 0).then_some(open + at);
            }
            None
        })
    }

    /// Return the text between the outer braces of `async fn run_with_clock<`
    /// in `src`, with no comments. The scans use `Code` tokens, thus a
    /// comment or a literal cannot give the function or a brace. Return
    /// `None` if the function or its closing brace is missing.
    fn boot_body(src: &str) -> Option<String> {
        let code = without_comments(src);
        let start = find_tokens(&code, &["async", "fn", "run_with_clock", "<"])?;
        let open = start + find_tokens(&code[start..], &["{"])?;
        let close = closing_bracket(&code, open, ('{', '}'))?;
        Some(code[open + 1..close].to_string())
    }

    /// Return the byte index of each `return` keyword in `text`.
    fn return_keywords(text: &str) -> Vec<usize> {
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        text.match_indices("return")
            .map(|(at, _)| at)
            .filter(|&at| {
                !ident(text[..at].chars().next_back())
                    && !ident(text[at + "return".len()..].chars().next())
            })
            .collect()
    }

    /// Return the first token in `text` that can leave the boot function
    /// before the drain ends: `return`, `?`, `.unwrap(`, `.expect(` or
    /// `panic!(`.
    fn early_exit(text: &str) -> Option<&'static str> {
        if !return_keywords(text).is_empty() {
            return Some("return");
        }
        ["?", ".unwrap(", ".expect(", "panic!("].into_iter().find(|token| text.contains(token))
    }

    /// Return the line of `text` at the byte index `at`, after the line
    /// before it.
    fn lines_at(text: &str, at: usize) -> String {
        let line = text[..at].matches('\n').count();
        text.lines()
            .skip(line.saturating_sub(1))
            .take(2)
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Check the start rule of the liveness loop in the boot `body`. Return
    /// the first rule that `body` breaks:
    ///
    /// 1. `body` calls `spawn_liveness_loop(` one time.
    /// 2. That call comes after each `spawn_background_tasks(`,
    ///    `ShutdownSignal::install(` and `take_epoch_boundary_runner(`.
    /// 3. That call comes before `"duty_orchestrator"`, and
    ///    `"duty_orchestrator"` comes before `await_shutdown_and_drain(`.
    /// 4. The text from that call to the closing parenthesis of the drain
    ///    call has no early exit (see [`early_exit`]). This text includes
    ///    the drain arguments.
    fn liveness_start_rule(body: &str) -> Result<(), String> {
        let spawns = body.matches("spawn_liveness_loop(").count();
        if spawns != 1 {
            return Err(format!(
                "The boot function must call `spawn_liveness_loop` one time. The scan found \
                 {spawns} calls."
            ));
        }
        let spawn_at = body.find("spawn_liveness_loop(").unwrap_or_default();
        for step in
            ["spawn_background_tasks(", "ShutdownSignal::install(", "take_epoch_boundary_runner("]
        {
            match body.rfind(step) {
                Some(step_at) if step_at < spawn_at => {}
                Some(_) => return Err(format!("spawn_liveness_loop( must come after {step}.")),
                None => return Err(format!("The boot body must call {step}.")),
            }
        }
        let Some(orchestrator_at) = body.find("\"duty_orchestrator\"") else {
            return Err("The boot body must spawn \"duty_orchestrator\".".to_string());
        };
        if orchestrator_at < spawn_at {
            return Err("spawn_liveness_loop( must come before the \"duty_orchestrator\" spawn."
                .to_string());
        }
        let Some(drain_at) = body.find("await_shutdown_and_drain(") else {
            return Err("The boot body must call await_shutdown_and_drain(.".to_string());
        };
        if drain_at < orchestrator_at {
            return Err(
                "await_shutdown_and_drain( must come after the \"duty_orchestrator\" spawn."
                    .to_string(),
            );
        }
        let open = drain_at + "await_shutdown_and_drain".len();
        let Some(drain_end) = closing_bracket(body, open, ('(', ')')) else {
            return Err("The drain call must have a closing parenthesis.".to_string());
        };
        let window = &body[spawn_at..=drain_end];
        if let Some(exit) = early_exit(window) {
            return Err(format!(
                "From spawn_liveness_loop( to the end of the drain call, the boot function must \
                 not return early or panic. The text has `{exit}`: {window}"
            ));
        }
        Ok(())
    }

    /// Check the error exits of the boot `body` after the first task spawn.
    /// Return the first rule that `body` breaks:
    ///
    /// 1. `body` calls `spawn_index_resolver(`, the first task spawn.
    /// 2. `body` calls `spawn_liveness_loop(` after the first task spawn.
    /// 3. The text from the first task spawn to the loop start has no `?`.
    /// 4. Each `return` in that text returns
    ///    `Err(stop_boot_tasks(executor, ..))`.
    fn boot_error_rule(body: &str) -> Result<(), String> {
        let Some(first_spawn_at) = body.find("spawn_index_resolver(") else {
            return Err("The boot function must call spawn_index_resolver(.".to_string());
        };
        let Some(loop_at) = body.find("spawn_liveness_loop(") else {
            return Err("The boot function must call spawn_liveness_loop(.".to_string());
        };
        if loop_at < first_spawn_at {
            return Err("spawn_liveness_loop( must come after spawn_index_resolver(.".to_string());
        }
        let window = &body[first_spawn_at..loop_at];
        if let Some(at) = window.find('?') {
            return Err(format!(
                "After the first task spawn, a boot error must not return with `?`. The text \
                 is: {}",
                lines_at(window, at)
            ));
        }
        for at in return_keywords(window) {
            let exit: String = window[at..].chars().filter(|c| !c.is_whitespace()).collect();
            if !exit.starts_with("returnErr(stop_boot_tasks(executor,") {
                return Err(format!(
                    "After the first task spawn, each boot error must return through \
                     stop_boot_tasks. The text is: {}",
                    lines_at(window, at)
                ));
            }
        }
        Ok(())
    }

    /// W4-D2c fix1: after the first task spawn, each boot error stops the
    /// spawned tasks before the boot function returns. The fixtures make sure
    /// that the rule check rejects each early exit that skips the task stop.
    #[test]
    fn boot_errors_after_the_first_task_spawn_stop_the_tasks() {
        for (case, fixture) in [
            (
                "a `?` before the first spawn",
                "a()?; spawn_index_resolver(); spawn_liveness_loop(t);",
            ),
            (
                "an error that stops the tasks",
                "spawn_index_resolver(); match f() { Ok(v) => v, Err(err) => return \
                 Err(stop_boot_tasks(executor, err).await), }; spawn_liveness_loop(t);",
            ),
            (
                "a stop on more than one line",
                "spawn_index_resolver(); return Err(\n stop_boot_tasks(executor, e).await\n); \
                 spawn_liveness_loop(t);",
            ),
        ] {
            assert_eq!(boot_error_rule(fixture), Ok(()), "The rule check must accept {case}.");
        }
        for (case, fixture, reason) in [
            (
                "a body with no first spawn",
                "f()?; spawn_liveness_loop(t);",
                "spawn_index_resolver(",
            ),
            ("a body with no loop start", "spawn_index_resolver(); f()?;", "spawn_liveness_loop(."),
            (
                "a loop start before the first spawn",
                "spawn_liveness_loop(t); spawn_index_resolver();",
                "must come after",
            ),
            (
                "a `?` after the first spawn",
                "spawn_index_resolver(); f()?; spawn_liveness_loop(t);",
                "`?`",
            ),
            (
                "a `return Err` that skips the task stop",
                "spawn_index_resolver(); if e { return Err(e); } spawn_liveness_loop(t);",
                "stop_boot_tasks",
            ),
            (
                "a `return` of a local `Result`",
                "spawn_index_resolver(); if r.is_err() { return r; } spawn_liveness_loop(t);",
                "stop_boot_tasks",
            ),
        ] {
            let found = boot_error_rule(fixture);
            assert!(
                found.as_ref().is_err_and(|err| err.contains(reason)),
                "The rule check must reject {case}. The result is {found:?}."
            );
        }

        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().expect("The production code must come first.");
        let body = boot_body(prod).expect("The brace scan must find the body of run_with_clock.");
        assert_eq!(
            boot_error_rule(&body),
            Ok(()),
            "Each boot error after the first task spawn must stop the spawned tasks before the \
             boot function returns."
        );
    }

    /// W4-D2c: the boot function starts the loop after the last step that can
    /// fail. It installs both signal handlers before it starts the loop.
    /// From the loop start to the end of the drain call, the boot function
    /// does not return early or panic. The fixtures make sure that the brace
    /// scan finds a body and that the rule check rejects each wrong order.
    #[test]
    fn liveness_loop_starts_after_the_last_fallible_boot_step() {
        assert_eq!(
            boot_body(
                "async fn run_with_clock<C>() -> R {\n a({ b }, \"}\"); // }\n}\nfn next() {}"
            )
            .map(|body| body.split_whitespace().collect::<Vec<_>>().join(" ")),
            Some("a({ b }, \"}\");".to_string()),
            "The body text must have no comments, and it must stop at the outer brace."
        );
        for (case, fixture) in [
            ("a source without run_with_clock", "fn run() {}"),
            ("a body with no closing brace", "async fn run_with_clock<C>() { a {"),
        ] {
            assert_eq!(boot_body(fixture), None, "The brace scan must reject {case}.");
        }

        let pre = "spawn_background_tasks(); take_epoch_boundary_runner(); \
                   ShutdownSignal::install();";
        let good = format!(
            "{pre} spawn_liveness_loop(task); spawn_result(\"duty_orchestrator\"); \
             await_shutdown_and_drain(inputs, signal);"
        );
        assert_eq!(
            liveness_start_rule(&format!("a()?; {good} res?;")),
            Ok(()),
            "The rule check must accept the loop start after the last fallible step."
        );
        let after = "spawn_result(\"duty_orchestrator\"); await_shutdown_and_drain(inputs);";
        for (case, fixture) in [
            ("an empty body", String::new()),
            ("a body with no loop start", format!("{pre} {after}")),
            (
                "a second loop start",
                format!("{pre} spawn_liveness_loop(a); spawn_liveness_loop(b); {after}"),
            ),
            (
                "a loop start before spawn_background_tasks",
                "take_epoch_boundary_runner(); ShutdownSignal::install(); spawn_liveness_loop(t); \
                 spawn_background_tasks(); spawn_result(\"duty_orchestrator\"); \
                 await_shutdown_and_drain(inputs);"
                    .to_string(),
            ),
            (
                "a loop start before the handler install",
                "spawn_background_tasks(); take_epoch_boundary_runner(); spawn_liveness_loop(t); \
                 ShutdownSignal::install(); spawn_result(\"duty_orchestrator\"); \
                 await_shutdown_and_drain(inputs);"
                    .to_string(),
            ),
            (
                "a body with no handler install",
                format!(
                    "spawn_background_tasks(); take_epoch_boundary_runner(); \
                     spawn_liveness_loop(t); {after}"
                ),
            ),
            (
                "a loop start before the runner take",
                "spawn_background_tasks(); ShutdownSignal::install(); spawn_liveness_loop(t); \
                 take_epoch_boundary_runner(); spawn_result(\"duty_orchestrator\"); \
                 await_shutdown_and_drain(inputs);"
                    .to_string(),
            ),
            (
                "a loop start after the duty_orchestrator spawn",
                format!(
                    "{pre} spawn_result(\"duty_orchestrator\"); spawn_liveness_loop(t); \
                     await_shutdown_and_drain(inputs);"
                ),
            ),
            (
                "a body with no drain",
                format!("{pre} spawn_liveness_loop(t); spawn_result(\"duty_orchestrator\");"),
            ),
            (
                "a drain before the duty_orchestrator spawn",
                format!(
                    "{pre} spawn_liveness_loop(t); await_shutdown_and_drain(inputs); \
                     spawn_result(\"duty_orchestrator\");"
                ),
            ),
            ("a `?` after the loop start", format!("{pre} spawn_liveness_loop(t); b()?; {after}")),
            (
                "a `return Err` after the loop start",
                format!("{pre} spawn_liveness_loop(t); if x {{ return Err(e); }} {after}"),
            ),
            (
                "a `?` between the duty_orchestrator spawn and the drain",
                format!(
                    "{pre} spawn_liveness_loop(t); spawn_result(\"duty_orchestrator\"); b()?; \
                     await_shutdown_and_drain(inputs);"
                ),
            ),
        ] {
            assert!(liveness_start_rule(&fixture).is_err(), "The rule check must reject {case}.");
        }

        let orchestrator = "spawn_result(\"duty_orchestrator\");";
        assert_eq!(
            liveness_start_rule(&format!(
                "{pre} spawn_liveness_loop(t); {orchestrator} \
                 await_shutdown_and_drain(Inputs {{ a: f(x), b: \")\" }}, signal).await; res?;"
            )),
            Ok(()),
            "The scan must end at the parenthesis that closes the drain call."
        );
        for (case, fixture, exit) in [
            (
                "a `?` in a drain argument",
                format!(
                    "{pre} spawn_liveness_loop(t); {orchestrator} \
                     await_shutdown_and_drain(Inputs {{ budget: {{ check()?; b }} }}, signal);"
                ),
                "`?`",
            ),
            (
                "a `return` of a local `Result` after the loop start",
                format!("{pre} spawn_liveness_loop(t); let r = f(); if r.is_err() {{ return r; }} {after}"),
                "`return`",
            ),
            (
                "an `expect` after the loop start",
                format!("{pre} spawn_liveness_loop(t); a.expect(\"x\"); {after}"),
                "`.expect(`",
            ),
            (
                "a drain call with no closing parenthesis",
                format!("{pre} spawn_liveness_loop(t); {orchestrator} await_shutdown_and_drain(a"),
                "closing parenthesis",
            ),
        ] {
            let found = liveness_start_rule(&fixture);
            assert!(
                found.as_ref().is_err_and(|err| err.contains(exit)),
                "The rule check must reject {case}. The result is {found:?}."
            );
        }

        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().expect("The production code must come first.");
        let body = boot_body(prod).expect("The brace scan must find the body of run_with_clock.");
        assert!(
            body.contains("wire_signing_enablement(") && body.contains("build_services("),
            "The brace scan must find the boot body. The body is: {body}"
        );
        assert_eq!(
            liveness_start_rule(&body),
            Ok(()),
            "run_with_clock must start the liveness loop after its last fallible step."
        );
    }

    /// W4-E4d: `run` is one call to the shared body with the identity clock
    /// picker. The build compiles the test entry point only for tests and
    /// `test-utils`, so the test path cannot drift from production.
    #[test]
    fn run_delegates_to_the_shared_body() {
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().expect("The production code must come first.");
        let rest = &prod[prod.find("pub async fn run(").expect("run.rs must define run.")..];
        let open = rest.find('{').expect("run must have a body.");
        let close = rest.find("\n}\n").expect("run must end with a closing brace line.");
        assert_eq!(
            squash(&rest[open + 1..close]),
            "run_with_clock(config, options, executor, shutdown_rx, |system| system).await",
            "The body of run must be one run_with_clock call with the identity clock picker."
        );
        let entry = prod
            .find("pub async fn run_with_slot_clock<")
            .expect("run.rs must define run_with_slot_clock.");
        assert_eq!(
            prod[..entry].trim_end().lines().last().map(str::trim),
            Some("#[cfg(any(test, feature = \"test-utils\"))]"),
            "The build must compile run_with_slot_clock only for tests and the test-utils feature."
        );
    }

    /// Return `true` when `body` has these calls in this order:
    ///
    /// 1. `open_slashing_db(`
    /// 2. `sweep_stale_record_temps(`
    /// 3. `wire_signing_enablement(`
    ///
    /// The scan uses the first instance of each call.
    fn sweep_runs_under_the_lock(body: &str) -> bool {
        let [lock, sweep, wire] =
            ["open_slashing_db(", "sweep_stale_record_temps(", "wire_signing_enablement("]
                .map(|call| body.find(call));
        matches!((lock, sweep, wire), (Some(lock), Some(sweep), Some(wire)) if lock < sweep && sweep < wire)
    }

    /// The boot body must remove stale record temp files only after
    /// `open_slashing_db` takes the keystore lock, and before
    /// `wire_signing_enablement`. The fixtures make sure that the scan rejects
    /// each wrong order and a body without the sweep.
    #[test]
    fn record_temp_sweep_runs_under_the_keystore_lock() {
        assert!(
            sweep_runs_under_the_lock(
                "open_slashing_db(); sweep_stale_record_temps(); wire_signing_enablement();"
            ),
            "The scan must accept the sweep between the lock and the enablement."
        );
        for (case, fixture) in [
            (
                "a sweep before the lock",
                "sweep_stale_record_temps(); open_slashing_db(); wire_signing_enablement();",
            ),
            (
                "a sweep after the enablement",
                "open_slashing_db(); wire_signing_enablement(); sweep_stale_record_temps();",
            ),
            ("a body without the sweep", "open_slashing_db(); wire_signing_enablement();"),
        ] {
            assert!(!sweep_runs_under_the_lock(fixture), "The scan must reject {case}.");
        }

        let src = include_str!("run.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or_default();
        let start = prod.find("async fn run_with_clock<").unwrap_or(prod.len());
        let rest = &prod[start..];
        let body = &rest[..rest.find("pub(crate) struct ShutdownInputs").unwrap_or(0)];
        assert!(
            body.contains("let _keystore_lock_guard = slashing_handles.keystore_lock;"),
            "The scan must find the boot body that holds the keystore lock."
        );
        assert!(
            sweep_runs_under_the_lock(body),
            "run_with_clock must call sweep_stale_record_temps after open_slashing_db and \
             before wire_signing_enablement."
        );
    }

    /// Return the boot error for the keystore `dir` with detection on. The
    /// config has no slashing database.
    async fn boot_with_detection_on(dir: &std::path::Path) -> BootstrapError {
        let config = Config {
            keystore_path: dir.to_path_buf(),
            doppelganger_detection: true,
            ..Default::default()
        };
        let (executor, rx) = TaskExecutor::new(CancellationToken::new());
        let options = RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: OperationTimeouts::default(),
        };
        run(config, options, executor, rx)
            .await
            .expect_err("The boot must stop, because the test has no slashing database.")
    }

    /// Return the sorted names in `dir`.
    fn sorted_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("The test must read the directory.")
            .map(|entry| {
                let entry = entry.expect("The test must read a directory entry.");
                entry.file_name().to_string_lossy().into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// The keystore holds a stale record temp file, and the slashing database
    /// is valid. The invalid genesis validators root stops the boot after the
    /// sweep step. The test requires these results:
    ///
    /// - Each boot stops at the genesis validators root.
    /// - With detection on, the sweep removes the temp file, and the record
    ///   is `Clear`.
    /// - With detection off, the temp file stays, and no record exists.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_removes_a_stale_record_temp_only_with_detection_on() {
        use crate::detection_marker::{inspect_record, RecordInspect, RECORD_FILENAME};
        let stale = format!(".{RECORD_FILENAME}.1.2.tmp");
        let rows = [
            ("on", true, vec![RECORD_FILENAME.to_string()], RecordInspect::Clear),
            ("off", false, vec![stale.clone()], RecordInspect::Absent),
        ];
        for (state, detection, kept, record) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let keystore = dir.path().join("keys");
            std::fs::create_dir_all(&keystore).expect("The test must create the keystore.");
            let db_path = dir.path().join("slashing.db");
            try_seed_slashing_db(&db_path);
            std::fs::write(keystore.join(&stale), b"partial")
                .expect("The test must write the stale temp file.");
            let config = Config {
                keystore_path: keystore.clone(),
                slashing_db_path: db_path,
                genesis_validators_root: Some("0xzz".to_string()),
                doppelganger_detection: detection,
                ..Default::default()
            };
            let (executor, rx) = TaskExecutor::new(CancellationToken::new());
            let options = RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: OperationTimeouts::default(),
            };
            let err = run(config, options, executor, rx)
                .await
                .expect_err("The invalid genesis validators root must stop the boot.");
            assert!(
                err.to_string().contains("genesis validators root"),
                "With detection {state}, the boot must stop at the genesis validators root. \
                 The error is: {err}"
            );
            let names: Vec<String> = sorted_names(&keystore)
                .into_iter()
                .filter(|name| name.contains(RECORD_FILENAME))
                .collect();
            assert_eq!(
                names, kept,
                "With detection {state}, the keystore must hold only these record names."
            );
            assert_eq!(
                inspect_record(&keystore),
                record,
                "With detection {state}, the record must have this state."
            );
        }
    }

    /// The create fails with `AlreadyExists` at the link, and a hook removes
    /// the record before the second read. The test requires exit 1 and the
    /// preallocation error text.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_exits_1_when_the_record_is_absent_after_a_link_collision() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let final_path = crate::detection_marker::record_path(dir.path());
        let link_guard = crate::detection_marker::arm_before_record_link(move || {
            std::fs::write(&final_path, b"appeared").expect("The hook must write the record.");
        });
        let read_guard = crate::detection_marker::arm_before_second_record_read(|data_dir| {
            std::fs::remove_file(crate::detection_marker::record_path(data_dir))
                .expect("The hook must remove the record.");
        });
        let err = boot_with_detection_on(dir.path()).await;
        drop(read_guard);
        drop(link_guard);
        assert_eq!(err.exit_code(), 1, "The boot must exit 1. The error is: {err}");
        assert!(
            err.to_string().contains("cannot preallocate the doppelganger detection record"),
            "The boot must stop at the record preallocation. The error is: {err}"
        );
    }

    /// A filesystem without hard links fails the record link with
    /// `PermissionDenied` or `Unsupported`. For each kind, the test requires
    /// these results:
    ///
    /// - The boot with detection on exits 1.
    /// - The error text names the missing hard-link support.
    /// - No record and no temp file stay in the keystore.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_names_the_missing_hard_link_support() {
        for kind in [std::io::ErrorKind::PermissionDenied, std::io::ErrorKind::Unsupported] {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let guard = crate::detection_marker::arm_record_link_failure(kind);
            let err = boot_with_detection_on(dir.path()).await;
            drop(guard);
            assert_eq!(
                err.exit_code(),
                1,
                "The boot must exit 1 for the {kind:?} link error. The error is: {err}"
            );
            assert!(
                err.to_string().contains("does not support hard links"),
                "The {kind:?} boot error must name the missing hard-link support. The error \
                 is: {err}"
            );
            assert_eq!(
                sorted_names(dir.path()),
                Vec::<String>::new(),
                "The failed {kind:?} create must leave no record and no temp file."
            );
        }
    }

    /// The keystore holds a `Clear` record with mode `0o644`. The test
    /// requires these results:
    ///
    /// - The boot with detection on exits 1.
    /// - The error text names the detection record and the mode `0o644`.
    /// - The boot does not change the mode of the record.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_refuses_a_reused_record_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        crate::detection_marker::preallocate_detection_record(dir.path())
            .expect("The test must preallocate the record.");
        let path = crate::detection_marker::record_path(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("The test must set mode 0o644 on the record.");
        let err = boot_with_detection_on(dir.path()).await;
        assert_eq!(err.exit_code(), 1, "The boot must exit 1. The error is: {err}");
        let text = err.to_string();
        assert!(
            text.contains("detection record"),
            "The boot error must name the detection record. The error is: {text}"
        );
        assert!(
            text.contains("mode 0o644"),
            "The boot error must name the mode 0o644. The error is: {text}"
        );
        let mode = std::fs::metadata(&path)
            .expect("The test must read the record metadata.")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "The boot must not change the mode of the record. The mode is 0o{mode:o}."
        );
    }

    /// The keystore holds a `Clear` record, and each case makes the check of
    /// that record fail. The test runs each case at two entries:
    ///
    /// - The first entry: the boot reads the record before the create.
    /// - The collision entry: a hook moves the record to the final name after
    ///   the fsync of the new record and before the link.
    ///
    /// For each case and each entry, the test requires these results:
    ///
    /// - The boot with detection on exits 1 at the record step.
    /// - The boot error names the cause of the case.
    /// - The bytes and the mode of the record do not change.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn boot_stops_at_the_record_step_for_each_failed_reuse_check() {
        use crate::detection_marker::{
            arm_before_record_link, arm_fsync_failure_for, arm_owner_uid_override,
            preallocate_detection_record, record_path,
        };
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        #[derive(Clone, Copy, PartialEq)]
        enum Fault {
            Mode,
            Owner,
            RecordFsync,
            DirFsync,
        }
        let cases = [
            ("group write", 0o620, Fault::Mode),
            ("other write", 0o602, Fault::Mode),
            ("another owner", 0o600, Fault::Owner),
            ("record fsync error", 0o600, Fault::RecordFsync),
            ("directory fsync error", 0o600, Fault::DirFsync),
        ];
        for (case, mode, fault) in cases {
            for entry in ["first", "collision"] {
                let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
                preallocate_detection_record(dir.path())
                    .expect("The test must preallocate the record.");
                let path = record_path(dir.path());
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .expect("The test must set the mode of the record.");
                let bytes = std::fs::read(&path).expect("The test must read the record.");
                let uid = std::fs::metadata(&path).expect("The test must read the metadata.").uid();
                let fsync_guard = match fault {
                    Fault::RecordFsync => Some(arm_fsync_failure_for(&path, 0)),
                    // The marker probe fsyncs the directory one time before the record step.
                    Fault::DirFsync => Some(arm_fsync_failure_for(dir.path(), 1)),
                    Fault::Mode | Fault::Owner => None,
                };
                let owner_guard = (fault == Fault::Owner).then(|| arm_owner_uid_override(uid + 1));
                let link_guard = (entry == "collision").then(|| {
                    let moved = dir.path().join("moved-record");
                    std::fs::rename(&path, &moved).expect("The test must move the record.");
                    let final_path = path.clone();
                    arm_before_record_link(move || {
                        std::fs::rename(&moved, &final_path)
                            .expect("The hook must move the record to the final name.");
                    })
                });
                let err = boot_with_detection_on(dir.path()).await;
                drop(link_guard);
                drop(owner_guard);
                drop(fsync_guard);
                let text = err.to_string();
                assert_eq!(
                    err.exit_code(),
                    1,
                    "In the {case} case at the {entry} entry, the boot must exit 1. The error is: \
                     {text}"
                );
                assert!(
                    text.contains("cannot preallocate the doppelganger detection record"),
                    "In the {case} case at the {entry} entry, the boot must stop at the record \
                     step. The error is: {text}"
                );
                let cause = match fault {
                    Fault::Mode => format!("mode 0o{mode:o}"),
                    Fault::Owner => format!("uid {uid}"),
                    Fault::RecordFsync | Fault::DirFsync => "os error 5".to_string(),
                };
                assert!(
                    text.contains(&cause),
                    "In the {case} case at the {entry} entry, the boot error must name {cause}. \
                     The error is: {text}"
                );
                assert!(
                    std::fs::read(&path).ok() == Some(bytes),
                    "In the {case} case at the {entry} entry, the boot must keep the bytes of \
                     the record."
                );
                let after = std::fs::metadata(&path).ok().map(|meta| meta.mode() & 0o7777);
                assert_eq!(
                    after,
                    Some(mode),
                    "In the {case} case at the {entry} entry, the boot must not change the mode \
                     of the record."
                );
            }
        }
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

    /// Return the name of the innermost `fn` whose body holds the byte index
    /// `at` in `code`. The brace scan skips string literals. Return `None`
    /// if no `fn` body holds `at`.
    fn enclosing_fn(code: &str, at: usize) -> Option<&str> {
        code[..at].rmatch_indices("fn ").find_map(|(start, _)| {
            let open = start + code[start..].find('{')?;
            let close = closing_bracket(code, open, ('{', '}'))?;
            let name = code[start + "fn ".len()..]
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()?;
            (open < at && at < close).then_some(name)
        })
    }

    /// Check the ARCH-2h sleep rule in the Rust source `src`. Return an
    /// error if `src` breaks one of these rules:
    ///
    /// 1. `src` has one `sleep` call. A `sleep` call in macro input counts.
    /// 2. That call is a call expression in `persist_latched_detection`.
    fn sleep_rule(src: &str) -> Result<(), String> {
        let code = without_comments(src);
        let sleeps: Vec<usize> = code.match_indices("sleep(").map(|(at, _)| at).collect();
        match sleeps[..] {
            [at] if enclosing_fn(&code, at) == Some("persist_latched_detection") => Ok(()),
            _ => Err(format!("The scan found these `sleep` calls: {sleeps:?}")),
        }
    }

    /// Check the drain order in the Rust source `src`. In
    /// `await_shutdown_and_drain_with_signal`, the first
    /// `persist_latched_detection` call must be a call expression after the
    /// first `executor.shutdown` call expression.
    fn drain_rule(src: &str) -> Result<(), String> {
        let code = without_comments(src);
        let at = code.find("fn await_shutdown_and_drain_with_signal(").ok_or("No drain.")?;
        let open = at + code[at..].find('{').ok_or("No body.")?;
        let drain = &code[open..closing_bracket(&code, open, ('{', '}')).ok_or("No end.")?];
        match (drain.find("executor.shutdown("), drain.find("persist_latched_detection(")) {
            (Some(shutdown), Some(persist)) if shutdown < persist => Ok(()),
            _ => Err(format!("The calls in the drain are wrong: {drain}")),
        }
    }

    /// Return `true` if `run_with_clock` in the Rust source `src` has a call
    /// expression to `name`. If `first_arg` is `Some`, the first argument of
    /// the call must be that identifier. A call in a comment, in a literal or
    /// in macro input does not count.
    fn boot_calls(src: &str, name: &str, first_arg: Option<&str>) -> bool {
        match first_arg {
            Some(arg) => {
                boot_body(src).is_some_and(|body| find_tokens(&body, &[name, "(", arg]).is_some())
            }
            None => src.contains(name),
        }
    }

    /// Return `true` if the body of `run_with_clock` in `src` calls
    /// `spawn_proposer_sync_monitor` with `proposer_bn_manager` as its first
    /// argument.
    fn boot_calls_proposer_sync_monitor(src: &str) -> bool {
        boot_calls(src, "spawn_proposer_sync_monitor", Some("proposer_bn_manager"))
    }

    /// ARCH-2h: the production body joins tasks. It does not sleep in place
    /// of a join. The checks read calls, not text. The test requires these
    /// results:
    ///
    /// - The production body has one `sleep(` call. That call is the retry
    ///   wait in `persist_latched_detection`.
    /// - In `await_shutdown_and_drain_with_signal`, `executor.shutdown(`
    ///   comes before `persist_latched_detection(`.
    /// - `run_with_clock` calls `spawn_proposer_sync_monitor(` with
    ///   `proposer_bn_manager` as its first argument. It also calls the
    ///   broadcast drain waiter, the SSE subscriber and the sync monitor.
    ///
    /// The fixtures make sure that a comment or a literal does not give a
    /// call. A literal is a character, byte, or string literal. String
    /// literals include byte and C strings. A call in macro input counts only
    /// for the sleep check.
    #[test]
    fn test_run_rs_has_no_sleep_as_join_substitute() {
        let call = "spawn_proposer_sync_monitor(proposer_bn_manager, &executor, Some(s));";
        let boot = |line: String| format!("async fn run_with_clock<C>() {{\n a();\n {line}\n}}");
        for (case, line) in [
            ("a call in run_with_clock", call.to_string()),
            ("a call after a raw string with `//`", format!(r##"let p = r#"a"//"#; {call}"##)),
            ("a call after a character literal with a quote", format!("let q = '\"'; {call}")),
        ] {
            assert!(
                boot_calls_proposer_sync_monitor(&boot(line)),
                "The call check must accept {case}."
            );
        }
        for (case, fixture) in [
            ("a call only in a comment", boot(format!("// {call}"))),
            (
                "a call outside run_with_clock",
                format!("fn other() {{ {call} }}\nasync fn run_with_clock<C>() {{ a(); }}"),
            ),
            ("a call only in a string", boot(format!("let s = \"{call}\";"))),
            ("a call only in a block comment", boot(format!("/* {call} */"))),
            ("a call only in a nested block comment", boot(format!("/* /* */ {call} */"))),
            ("a call only in a raw string with quotes", boot(format!(r##"r#"" {call} ""#;"##))),
            ("a call only in a string with escaped quotes", boot(format!(r#""\" {call} \"";"#))),
        ] {
            assert!(
                !boot_calls_proposer_sync_monitor(&fixture),
                "The call check must reject {case}."
            );
        }

        let mut wrong = Vec::new();
        for (case, valid, body, rest) in [
            ("a sleep after a nested fn", true, "if f(\"}\") { fn i() {} } sleep(T)", ""),
            ("an extra `sleep(` literal", true, "sleep(T);", "fn b() { \"sleep(\"; }"),
            ("a sleep only in a string", false, r#""sleep(T)";"#, ""),
            ("a sleep only in a string with escaped quotes", false, r#""\" sleep(T) \"";"#, ""),
            ("a sleep only in a raw string", false, r#"r"sleep(T)";"#, ""),
            ("a sleep only in a raw string with `##`", false, r###"r##""# sleep(T) ""##;"###, ""),
            ("a sleep in `stringify!`", false, "stringify!(sleep(T));", ""),
            ("a sleep in another fn", false, "", "fn o() { sleep(T); }"),
            ("a second sleep in macro input", false, "sleep(T);", "fn o() { m!(sleep(T)); }"),
            ("a sleep outside a fn", false, "", "static S: () = sleep(T);"),
        ] {
            let src = format!("async fn persist_latched_detection() {{ {body} }}\n{rest}");
            if sleep_rule(&src).is_ok() != valid {
                wrong.push(case);
            }
        }
        let (stop, save) = ("executor.shutdown(b);", "persist_latched_detection(d);");
        for (case, valid, body) in [
            ("the real call order", true, format!("h.shutdown(); {stop} {save}")),
            ("a persist literal first", true, format!("{save:?}; {stop} {save}")),
            ("a reversed call order", false, format!("{save} {stop}")),
            ("a persist call only in a comment", false, format!("{stop} // {save}\n")),
            ("a persist call only in a string", false, format!("{stop} {save:?};")),
            ("a persist call in `stringify!`", false, format!("{stop} stringify!({save});")),
            ("a persist call in macro input first", false, format!("m!({save}); {stop} {save}")),
            ("a shutdown in a raw string", false, format!(r###"r##""# {stop} ""##; {save}"###)),
            ("a shutdown call on another receiver", false, format!("h.shutdown(b); {save}")),
            ("the calls in a nested fn", false, format!("fn o() {{ {stop} {save} }}")),
        ] {
            let src = format!("fn await_shutdown_and_drain_with_signal() {{ {body} }}");
            if drain_rule(&src).is_ok() != valid {
                wrong.push(case);
            }
        }
        let bound = "async fn run_with_clock<C>() where [(); { 1 }]: Sized,";
        let (name, arg) = ("spawn_proposer_sync_monitor", "proposer_bn_manager");
        for (case, valid, src) in [
            ("a call after a brace in the signature", true, format!("{bound} {{ {call} }}")),
            ("a call in a method", true, format!("impl B {{ {} }}", boot(call.to_string()))),
            ("a call only in a byte string", false, boot(format!("b{call:?};"))),
            ("a call only in a C string", false, boot(format!("c{call:?};"))),
            ("a call in `stringify!`", false, boot(format!("stringify!({call});"))),
            ("a literal in `stringify!`", false, boot(format!("stringify!({name}(\"x\" {arg}));"))),
            ("a literal after the name", false, boot(format!("stringify!({name} \"x\" ({arg}));"))),
            ("a call to a longer identifier", false, boot(format!("x\u{301}{call}"))),
            ("a call with another first argument", false, boot(format!("{name}(bn_manager);"))),
        ] {
            if boot_calls_proposer_sync_monitor(&src) != valid {
                wrong.push(case);
            }
        }
        let waiter =
            "e.set_after_orchestrator_waiter(async { d.wait_for_broadcast_drains(b).await });";
        for (case, valid, line) in [
            ("the drain waiter in run_with_clock", true, waiter.to_string()),
            ("the drain waiter only in a comment", false, format!("// {waiter}")),
            ("the drain waiter only in a string", false, format!("{waiter:?};")),
        ] {
            let src = boot(line);
            let found = boot_calls(&src, "set_after_orchestrator_waiter", None)
                && boot_calls(&src, "wait_for_broadcast_drains", None);
            if found != valid {
                wrong.push(case);
            }
        }
        assert!(
            wrong.is_empty(),
            "Each call check must accept each valid case and reject each other case. These \
             cases give the wrong result: {wrong:?}"
        );

        let src = include_str!("run.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body before tests");
        assert_eq!(
            sleep_rule(body),
            Ok(()),
            "ARCH-2h: the production body must have one `sleep` call. That call must be the \
             retry wait in persist_latched_detection."
        );
        assert_eq!(
            drain_rule(body),
            Ok(()),
            "In await_shutdown_and_drain_with_signal, executor.shutdown must come before \
             persist_latched_detection."
        );
        for name in [
            "set_after_orchestrator_waiter",
            "wait_for_broadcast_drains",
            "spawn_sse_subscriber",
            "spawn_sync_monitor",
        ] {
            assert!(boot_calls(body, name, None), "run_with_clock must call {name}.");
        }
        assert!(
            body.contains("duty_orchestrator"),
            "orchestrator must be registered as duty_orchestrator"
        );
        assert!(body.contains("bn.sse"), "ARCH-3l must name the registered SSE task bn.sse");
        assert!(
            body.contains("bn.sync_monitor"),
            "DSR-2.1 must name the registered sync-monitor task bn.sync_monitor"
        );
        assert!(
            boot_calls_proposer_sync_monitor(body),
            "FU-A6. `run_with_clock` must call `spawn_proposer_sync_monitor` with \
             `proposer_bn_manager` as its first argument."
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
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
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

    /// The refresh admits through the service the keymanager adapters get,
    /// serialised on the `TrackedKeys` they share.
    #[test]
    fn refresh_admissions_take_the_keymanager_tracked_keys() {
        let src = include_str!("run.rs");
        let after = src.split("let admissions = Arc::new(").nth(1).expect("admissions in run");
        let built = after.split("spawn_secret_provider_refresh(").next().expect("built first");
        assert!(
            built.contains(".with_tracked_keys(Arc::clone(&tracked_keys))"),
            "the refresh admissions must take the keymanager TrackedKeys"
        );
        let deps = after.split("KeymanagerApiDeps {").nth(1).expect("keymanager deps");
        let deps = deps.split("listeners.keymanager").next().expect("deps literal");
        assert!(deps.contains("admissions,"), "the keymanager must get the same admissions");
        assert!(deps.contains("tracked_keys,"), "and the same TrackedKeys");
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
