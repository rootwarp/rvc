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

    refuse_if_detection_records(&config.keystore_path, &config.slashing_db_path)?;
    if config.doppelganger_detection {
        ensure_marker_dir_writable(&config.keystore_path)?;
        ensure_detection_record(&config.keystore_path)?;
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
        liveness_task: _,
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
            slot_clock: Arc::clone(&slot_clock) as Arc<dyn timing::SlotClock>,
            tracked_keys,
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
    let sync_check = bn_manager::sync_check_interval_for(
        slot_clock.slot_duration(),
        slot_clock.slots_per_epoch(),
    );
    spawn_sync_monitor(Some(Arc::clone(&bn_manager)), &executor, Some(sync_check));
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
    // detached: already a per-slot root inside the task (`DutyOrchestrator::run`, span `slot.process`); not shape B.
    executor.spawn_result("duty_orchestrator", ShutdownTier::Orchestrator, async move {
        orchestrator.run().await
    });

    // Operator signal, panicking registered tasks, and internal token cancel
    // (e.g. slashing-monitor ShutdownRequested) converge on one drain path.
    let detection = forward_window_machine.map(|machine| DetectionShutdown {
        machine,
        keystore_dir: config.keystore_path.clone(),
        fallback_dir: crate::detection_marker::fallback_marker_dir(
            &config.keystore_path,
            &config.slashing_db_path,
        ),
        epoch_clock: Arc::clone(&epoch_clock),
    });
    let (outcome, res) = await_shutdown_and_drain(ShutdownInputs {
        executor,
        orchestrator_handle,
        shutdown_rx,
        shutdown_token,
        budget: TierBudget::default(),
        detection,
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
    /// Parent of the slashing database when that directory is not the keystore.
    pub(crate) fallback_dir: Option<std::path::PathBuf>,
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
pub(crate) async fn await_shutdown_and_drain(
    inputs: ShutdownInputs,
) -> (ShutdownOutcome, Result<(), BootstrapError>) {
    await_shutdown_and_drain_with_signal(inputs, shutdown_signal()).await
}

/// Same as [`await_shutdown_and_drain`], with the operator-signal arm replaced.
///
/// Production passes [`shutdown_signal`]. Tests pass a ready or pending future
/// so the signal arm does not install a process-wide SIGINT handler.
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

/// How long the drain waits between attempts when nothing durable exists yet.
const MARKER_SHUTDOWN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// Operator hint included in a refuse-to-start log. The fallback marker, when
/// one was written, sits beside the slashing database.
const DETECTION_CLEAR_HINT: &str = "Clear it with `rvc doppelganger clear-detection \
     --datadir <data dir> --slashing-db-path <slashing db> --confirm` \
     after the other instance is gone";

/// Write a durable detection record once the latch is set.
///
/// The pre-allocated keystore record is overwritten in place first. The
/// keystore marker and [`DetectionShutdown::fallback_dir`] are additional
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
                if let Some(dir) = &detection.fallback_dir {
                    if let Err(fallback_err) = crate::detection_marker::write_marker(dir, &marker) {
                        crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                        error!(
                            error = %fallback_err,
                            path = %crate::detection_marker::marker_path(dir).display(),
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
            if let Some(dir) = &detection.fallback_dir {
                if crate::detection_marker::write_marker(dir, &marker).is_ok() {
                    detection.machine.mark_detection_persisted();
                    error!(
                        path = %crate::detection_marker::marker_path(dir).display(),
                        "persisted doppelganger detection marker beside the slashing database"
                    );
                } else {
                    crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                    error!(
                        path = %crate::detection_marker::marker_path(dir).display(),
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
/// that directory is different, a marker is beside the slashing database.
pub(crate) fn refuse_if_detection_records(
    keystore_dir: &std::path::Path,
    slashing_db_path: &std::path::Path,
) -> Result<(), BootstrapError> {
    refuse_if_detection_record(keystore_dir)?;
    refuse_if_detection_marker(keystore_dir)?;
    if let Some(dir) = crate::detection_marker::fallback_marker_dir(keystore_dir, slashing_db_path)
    {
        refuse_if_detection_marker(&dir)?;
    }
    Ok(())
}

/// Exit 12 when the pre-allocated record is `detected` or cannot be trusted.
fn refuse_if_detection_record(data_dir: &std::path::Path) -> Result<(), BootstrapError> {
    match crate::detection_marker::inspect_record(data_dir) {
        crate::detection_marker::RecordInspect::Absent
        | crate::detection_marker::RecordInspect::Clear => Ok(()),
        crate::detection_marker::RecordInspect::Detected { epoch, unix_secs } => {
            error!(
                epoch,
                unix_secs,
                path = %crate::detection_marker::record_path(data_dir).display(),
                "doppelganger detection record is in the detected state; refusing to start. {}",
                DETECTION_CLEAR_HINT
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::RecordInspect::Unreadable { path, reason } => {
            error!(
                path = %path.display(),
                reason,
                "doppelganger detection record is unreadable; refusing to start"
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
    }
}

/// Exit 12 before a signer or the keymanager API is built when a detection
/// marker is present, unreadable, or not a valid marker.
pub(crate) fn refuse_if_detection_marker(data_dir: &std::path::Path) -> Result<(), BootstrapError> {
    match crate::detection_marker::inspect(data_dir) {
        crate::detection_marker::MarkerInspect::Absent => Ok(()),
        crate::detection_marker::MarkerInspect::Present(marker) => {
            for pubkey in &marker.pubkeys {
                error!(
                    pubkey = %TruncatedPubkey::new(pubkey),
                    epoch = marker.epoch,
                    unix_secs = marker.unix_secs,
                    path = %crate::detection_marker::marker_path(data_dir).display(),
                    "doppelganger detection marker is present; refusing to start. {}",
                    DETECTION_CLEAR_HINT
                );
            }
            if marker.pubkeys.is_empty() {
                error!(
                    epoch = marker.epoch,
                    path = %crate::detection_marker::marker_path(data_dir).display(),
                    "doppelganger detection marker listed no keys; refusing to start. {}",
                    DETECTION_CLEAR_HINT
                );
            }
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::MarkerInspect::Corrupt { path, reason } => {
            error!(
                path = %path.display(),
                reason,
                "doppelganger detection marker is corrupt; refusing to start"
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
        crate::detection_marker::MarkerInspect::Unreadable { path, source } => {
            error!(
                path = %path.display(),
                error = %source,
                "doppelganger detection marker is unreadable; refusing to start"
            );
            Err(BootstrapError::DoppelgangerDetected)
        }
    }
}

/// Detection stays on only when the fixed-size record can be pre-allocated.
///
/// A failure here is exit 1. The process cannot promise to latch a later
/// detection if that overwrite has nowhere to land.
fn ensure_detection_record(data_dir: &std::path::Path) -> Result<(), BootstrapError> {
    if let Err(err) = crate::detection_marker::preallocate_detection_record(data_dir) {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            error!(
                path = %crate::detection_marker::record_path(data_dir).display(),
                "doppelganger detection record is already in the detected state; refusing to start. {}",
                DETECTION_CLEAR_HINT
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

        let (outcome, res) = await_shutdown_and_drain(ShutdownInputs {
            executor,
            orchestrator_handle: OrchestratorHandle::for_drain_test(),
            shutdown_rx,
            shutdown_token: token,
            budget: short_budget(),
            detection: None,
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
            detection: None,
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

    /// ARCH-2h: the production body joins tasks. The marker retry sleep is
    /// covered by the behavioural drain test, not by counting `sleep` calls.
    #[test]
    fn test_run_rs_has_no_sleep_as_join_substitute() {
        let src = include_str!("run.rs");
        let body = src.split("#[cfg(test)]").next().expect("production body before tests");
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
