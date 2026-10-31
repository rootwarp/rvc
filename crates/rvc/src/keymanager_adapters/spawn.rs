//! Assemble and spawn the Keymanager HTTP API.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bn_manager::BeaconNodeClient;
use crypto::CompositeSigner;
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock};
use eth_types::{Epoch, ForkSchedule, Root};
use keymanager_api::traits::{DoppelgangerMonitor, SigningQuiesce, VoluntaryExitManager};
use signer::SignerService;
use slashing::SlashingDb;
use tokio::sync::watch;
use tracing::{error, info, warn};
use validator_store::ValidatorStore;

use crate::bootstrap::executor::{ShutdownTier, TaskExecutor};
use crate::config::Config;
use crate::deletion_denylist::DeletionDenylist;
use crate::key_admission::KeyAdmissionService;
use crate::orchestrator::PubkeyMap;
use crate::quiesce::{QuiesceRegistry, SigningQuiesceAdapter};

use timing::SlotClock;

use super::config::ValidatorConfigManagerAdapter;
use super::doppelganger::{scan_and_rearm_gate, DoppelgangerDisabledMonitor, ForwardWindowMonitor};
use super::import_window::ImportWindowGate;
use super::kdf_budget::{KdfBudget, KdfBudgetConfig};
use super::keystore::KeystoreManagerAdapter;
use super::remote_keys::RemoteKeyManagerAdapter;
use super::slashing::SlashingProtectionAdapter;
use super::validator::ValidatorManagerAdapter;
use super::voluntary_exit::VoluntaryExitManagerAdapter;

/// Runtime dependencies for [`spawn_keymanager_api`] / [`build_keymanager_api`].
///
/// Parameter object for one call site — not a shared god-object for other phases.
pub struct KeymanagerApiDeps {
    pub composite_signer: Arc<CompositeSigner>,
    pub slashing_db: Arc<SlashingDb>,
    pub genesis_validators_root: Root,
    pub validator_store: Arc<ValidatorStore>,
    /// Beacon-node pool. Voluntary exit reads fail over across `beacon_nodes`.
    pub beacon_client: Arc<dyn BeaconNodeClient>,
    pub signer: Arc<SignerService>,
    pub fork_schedule: Arc<ForkSchedule>,
    pub deletion_denylist: Arc<DeletionDenylist>,
    pub attesting_enabled: Arc<AtomicBool>,
    pub forward_window_machine: Option<Arc<ForwardWindowMachine>>,
    pub epoch_clock: Arc<MonotonicEpochClock>,
    pub pubkey_map: PubkeyMap,
    pub key_gen_tx: watch::Sender<u64>,
    /// Shared admission choke point (ARCH-2c); keymanager import calls `admit`.
    pub admissions: Arc<KeyAdmissionService>,
    /// Registry the signer's [`crate::quiesce::QuiescingEnablement`] reads.
    /// DELETE inserts here before draining `signer`.
    pub quiesce_registry: Arc<QuiesceRegistry>,
    /// Process slot clock. [`build_keymanager_api`] builds one
    /// [`ImportWindowGate`] from it for the single slashing adapter.
    /// A second gate would not share the import mutex.
    pub slot_clock: Arc<dyn SlotClock>,
    /// Same lock the liveness loop uses for Safe sidecar cleanup.
    pub tracked_keys: Arc<crate::quiesce::TrackedKeys>,
}

/// Which doppelganger monitor was selected when assembling the keymanager API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoppelgangerMonitorKind {
    /// SEC-2b: imports register on the shared [`ForwardWindowMachine`].
    ForwardWindow,
    /// Always-safe [`DoppelgangerDisabledMonitor`] (doppelganger opt-out path).
    Disabled,
}

/// Assembled keymanager server + monitor (no bind yet).
///
/// Produced by [`build_keymanager_api`] so unit tests can assert re-arm and
/// monitor selection without spawning the HTTP listener.
pub struct BuiltKeymanagerApi {
    pub server: keymanager_api::KeymanagerServer,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub monitor_kind: DoppelgangerMonitorKind,
    pub doppelganger_window: Duration,
    pub addr: std::net::SocketAddr,
    pub token_path: PathBuf,
    /// The single import gate wired into [`SlashingProtectionAdapter`].
    ///
    /// Test-only: pins that [`build_keymanager_api`] forwards the DB's
    /// [`slashing::GroupCommitConfig`] into the gate.
    #[cfg(test)]
    pub(crate) import_window_gate: Arc<ImportWindowGate>,
    /// Test-only: pins that every key-set writer holds `deps.tracked_keys`.
    #[cfg(test)]
    pub(crate) adapter_tracked_keys: AdapterTrackedKeys,
    /// Test-only: pins that the remote DELETE cancels through `deps.admissions`.
    #[cfg(test)]
    pub(crate) remote_window_cancel: Option<Arc<KeyAdmissionService>>,
}

/// The [`crate::quiesce::TrackedKeys`] each keymanager adapter holds.
#[cfg(test)]
pub(crate) struct AdapterTrackedKeys {
    pub(crate) keystore: Arc<crate::quiesce::TrackedKeys>,
    pub(crate) remote: Arc<crate::quiesce::TrackedKeys>,
    pub(crate) signing_quiesce: Arc<crate::quiesce::TrackedKeys>,
}

/// Errors from assembling or spawning the Keymanager API.
#[derive(Debug, thiserror::Error)]
pub enum SpawnKeymanagerApiError {
    #[error("keymanager token error: {0}")]
    Token(String),
    #[error("invalid keymanager address: {0}")]
    InvalidAddress(String),
}

/// Select the doppelganger monitor and re-arm recently imported keys **once**.
///
/// Hoists the previously duplicated `scan_and_rearm_gate` calls that lived in
/// both branches of the forward-window vs opt-out monitor selection.
///
/// The forward-window monitor skips a DELETE's cancel while `composite` still
/// holds the key in any backend.
fn select_and_rearm_doppelganger_monitor(
    keystore_path: &Path,
    doppelganger_window: Duration,
    forward_window_machine: Option<Arc<ForwardWindowMachine>>,
    epoch_clock: Arc<MonotonicEpochClock>,
    composite: Arc<CompositeSigner>,
) -> (Arc<dyn DoppelgangerMonitor>, DoppelgangerMonitorKind) {
    let (monitor, kind): (Arc<dyn DoppelgangerMonitor>, DoppelgangerMonitorKind) =
        if let Some(machine) = forward_window_machine {
            let clock = epoch_clock;
            let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> =
                Arc::new(move || clock.current_epoch());
            let mon = Arc::new(
                ForwardWindowMonitor::new(machine, epoch_provider)
                    .with_backing(Arc::new(move |pk| composite.has_any_backend(pk))),
            );
            (mon, DoppelgangerMonitorKind::ForwardWindow)
        } else {
            let mon = Arc::new(DoppelgangerDisabledMonitor::new());
            (mon, DoppelgangerMonitorKind::Disabled)
        };

    // Single re-arm after the branch (both monitor variants).
    if !doppelganger_window.is_zero() {
        scan_and_rearm_gate(keystore_path, monitor.as_ref(), doppelganger_window.as_secs());
    }

    (monitor, kind)
}

/// Keymanager listen address.
///
/// An unset address defaults to loopback `127.0.0.1:5062`. A missing setting
/// does not widen the bind to an unspecified address.
pub fn keymanager_bind_addr(
    config: &Config,
) -> Result<std::net::SocketAddr, SpawnKeymanagerApiError> {
    config.keymanager.address.as_deref().unwrap_or("127.0.0.1:5062").parse().map_err(
        |e: std::net::AddrParseError| SpawnKeymanagerApiError::InvalidAddress(e.to_string()),
    )
}

/// Assemble Keymanager adapters, settings, and server without spawning the bind loop.
///
/// Returns `Ok(None)` when `config.keymanager.enabled` is false — nothing is
/// constructed (no token file, no adapters, no re-arm).
pub fn build_keymanager_api(
    config: &Config,
    deps: KeymanagerApiDeps,
) -> Result<Option<BuiltKeymanagerApi>, SpawnKeymanagerApiError> {
    if !config.keymanager.enabled {
        return Ok(None);
    }

    let token_path = config
        .keymanager
        .token_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("./keymanager-api-token.txt"));
    let token = match keymanager_api::auth::ensure_token(&token_path) {
        Ok(t) => {
            keymanager_api::auth::warn_if_insecure_permissions(&token_path);
            t
        }
        Err(e) => return Err(SpawnKeymanagerApiError::Token(e.to_string())),
    };

    let km_addr = keymanager_bind_addr(config)?;

    if !km_addr.ip().is_loopback() {
        warn!(
            addr = %km_addr,
            "Keymanager API is bound to a non-loopback address; this exposes key management over the network"
        );
    }

    let km_composite = deps.composite_signer;
    // The remote DELETE cancels a key's window through the same admissions.
    let window_cancel = Arc::clone(&deps.admissions);
    let kdf_budget = Arc::new(KdfBudget::new(KdfBudgetConfig::from_keymanager(&config.keymanager)));
    let keystore_mgr = Arc::new(
        KeystoreManagerAdapter::new(
            config.keystore_path.clone(),
            Arc::clone(&km_composite),
            deps.pubkey_map.clone(),
            deps.key_gen_tx.clone(),
        )
        .with_tracked_keys(Arc::clone(&deps.tracked_keys))
        .with_denylist(Arc::clone(&deps.deletion_denylist))
        .with_admission_service(deps.admissions)
        .with_quiesce_registry(Arc::clone(&deps.quiesce_registry))
        .with_kdf_budget(kdf_budget),
    );
    let tracked_keys = Arc::clone(&keystore_mgr.tracked_keys);
    let membership = Arc::clone(&km_composite);
    // One gate per `SlashingDb`, built here at bootstrap and stored in the
    // only adapter that imports interchange. The gate must see the DB's
    // effective group-commit knobs (not `GroupCommitConfig::default`).
    let slot_duration_ms = deps.slot_clock.slot_duration().as_millis() as u64;
    let genesis_time = deps.slot_clock.genesis_time();
    let import_gate = Arc::new(
        ImportWindowGate::new(deps.slot_clock)
            .with_group_commit(deps.slashing_db.group_commit_config()),
    );
    let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
        deps.slashing_db,
        deps.genesis_validators_root,
        Arc::clone(&import_gate),
    ));
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let open_holds = deps.validator_store.reconcile_doppelganger_holds_at_boot(now_unix);
    let validator_mgr = Arc::new(ValidatorManagerAdapter::new(deps.validator_store.clone()));

    // M-12: time-based window for the delayed set_enabled task. When
    // doppelganger is disabled the window is Duration::ZERO so keys are
    // immediately enabled. When on, the hold is two epochs at the beacon
    // node's slot duration (768 s when that duration is 12 s).
    let doppelganger_window = if config.doppelganger_detection {
        crate::config::doppelganger_import_window(slot_duration_ms)
    } else {
        Duration::ZERO
    };
    keystore_mgr.set_doppelganger_window(doppelganger_window);

    // SEC-2b: when a ForwardWindowMachine is wired, keymanager imports
    // register with it (signing gate). Same monotonic epoch_clock as boot.
    // Fall back to the always-safe Disabled monitor when doppelganger is opted out.
    let (doppelganger_mon, monitor_kind) = select_and_rearm_doppelganger_monitor(
        &config.keystore_path,
        doppelganger_window,
        deps.forward_window_machine,
        deps.epoch_clock,
        Arc::clone(&km_composite),
    );

    let remote_key_mgr = Arc::new(
        RemoteKeyManagerAdapter::new(
            km_composite,
            config.keymanager.remote_signer_allowed_hosts.clone(),
            deps.pubkey_map,
            deps.key_gen_tx,
        )
        .with_tracked_keys(Arc::clone(&deps.tracked_keys))
        .with_window_cancel(window_cancel),
    );

    let config_mgr =
        Arc::new(ValidatorConfigManagerAdapter::new(Arc::clone(&deps.validator_store)));

    let exit_mgr: Option<Arc<dyn VoluntaryExitManager>> =
        Some(Arc::new(VoluntaryExitManagerAdapter::new(
            deps.beacon_client,
            Arc::clone(&deps.signer),
            deps.fork_schedule,
            deps.genesis_validators_root,
            genesis_time,
            slot_duration_ms,
        )));

    let signing_quiesce = Arc::new(
        SigningQuiesceAdapter::new(Arc::clone(&deps.quiesce_registry), deps.signer)
            .with_keystore_membership(tracked_keys, membership),
    );
    #[cfg(test)]
    let adapter_tracked_keys = AdapterTrackedKeys {
        keystore: Arc::clone(&keystore_mgr.tracked_keys),
        remote: Arc::clone(remote_key_mgr.tracked_keys()),
        signing_quiesce: Arc::clone(signing_quiesce.tracked_keys()),
    };
    #[cfg(test)]
    let remote_window_cancel = remote_key_mgr.window_cancel().cloned();
    let signing_quiesce: Arc<dyn SigningQuiesce> = signing_quiesce;

    let server = keymanager_api::KeymanagerServer::new(
        keymanager_api::KeymanagerDeps {
            keystore_manager: keystore_mgr,
            slashing_protection: slashing_prot,
            validator_manager: validator_mgr,
            doppelganger_monitor: Arc::clone(&doppelganger_mon),
            remote_key_manager: remote_key_mgr,
            config_manager: config_mgr,
            exit_manager: exit_mgr,
            signing_quiesce: Some(signing_quiesce),
        },
        keymanager_api::KeymanagerSettings {
            token: token.to_string(),
            addr: km_addr,
            cors_origins: config.keymanager.cors_origins.clone(),
            body_limit: config.keymanager.body_limit,
            allow_insecure_remote_signer: config.keymanager.allow_insecure_remote_signer,
            attesting_enabled: deps.attesting_enabled,
            doppelganger_window,
        },
    );
    let lifecycle = Arc::downgrade(&server.doppelganger_lifecycle());
    deps.validator_store.set_disable_listener(Arc::new(move |pubkey| {
        if let Some(life) = lifecycle.upgrade() {
            life.cancel_enable_on_disable(pubkey);
        }
    }));
    server.rearm_persisted_doppelganger_holds(open_holds);

    Ok(Some(BuiltKeymanagerApi {
        server,
        doppelganger_monitor: doppelganger_mon,
        monitor_kind,
        doppelganger_window,
        addr: km_addr,
        token_path,
        #[cfg(test)]
        import_window_gate: import_gate,
        #[cfg(test)]
        adapter_tracked_keys,
        #[cfg(test)]
        remote_window_cancel,
    }))
}

/// Bootstrap phase: optionally assemble and spawn the Keymanager API server.
///
/// When `config.keymanager.enabled` is false, returns `Ok(false)` without
/// constructing adapters or touching the token file.
///
/// When enabled, registers the server on `executor` at Ingress tier (ARCH-2g
/// P1-6). `listener` is the socket from
/// [`crate::bootstrap::bind_required_listeners`]; this function does not bind.
/// Cancellation is driven by the executor token via
/// [`keymanager_api::KeymanagerServer::serve_on`].
pub fn spawn_keymanager_api(
    config: &Config,
    deps: KeymanagerApiDeps,
    listener: Option<tokio::net::TcpListener>,
    executor: &TaskExecutor,
) -> Result<bool, SpawnKeymanagerApiError> {
    let Some(built) = build_keymanager_api(config, deps)? else {
        return Ok(false);
    };

    let Some(listener) = listener else {
        return Err(SpawnKeymanagerApiError::InvalidAddress(
            "keymanager listener was not pre-bound".into(),
        ));
    };

    info!(
        addr = %built.addr,
        token_path = %built.token_path.display(),
        "Keymanager API enabled"
    );

    let token = executor.token();
    // detached: keymanager API server; serve loop is KeymanagerServer::serve_on, out of scope.
    executor.spawn("keymanager_api", ShutdownTier::Ingress, async move {
        if let Err(e) = built.server.serve_on(listener, token).await {
            error!("Keymanager API server error: {}", e);
        }
    });

    Ok(true)
}
