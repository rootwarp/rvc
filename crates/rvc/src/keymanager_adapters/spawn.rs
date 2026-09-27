//! Assemble and spawn the Keymanager HTTP API.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bn_manager::BeaconNodeClient;
use crypto::CompositeSigner;
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock};
use eth_types::{Epoch, ForkSchedule, Root, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
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

use super::config::ValidatorConfigManagerAdapter;
use super::doppelganger::{scan_and_rearm_gate, DoppelgangerDisabledMonitor, ForwardWindowMonitor};
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
fn select_and_rearm_doppelganger_monitor(
    keystore_path: &Path,
    doppelganger_window: Duration,
    forward_window_machine: Option<Arc<ForwardWindowMachine>>,
    epoch_clock: Arc<MonotonicEpochClock>,
) -> (Arc<dyn DoppelgangerMonitor>, DoppelgangerMonitorKind) {
    let (monitor, kind): (Arc<dyn DoppelgangerMonitor>, DoppelgangerMonitorKind) =
        if let Some(machine) = forward_window_machine {
            let clock = epoch_clock;
            let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> =
                Arc::new(move || clock.current_epoch());
            let mon = Arc::new(ForwardWindowMonitor::new(machine, epoch_provider));
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

    let km_addr: std::net::SocketAddr =
        config.keymanager.address.as_deref().unwrap_or("127.0.0.1:5062").parse().map_err(
            |e: std::net::AddrParseError| SpawnKeymanagerApiError::InvalidAddress(e.to_string()),
        )?;

    if !km_addr.ip().is_loopback() {
        warn!(
            addr = %km_addr,
            "Keymanager API is bound to a non-loopback address; this exposes key management over the network"
        );
    }

    let km_composite = deps.composite_signer;
    let keystore_mgr = Arc::new(
        KeystoreManagerAdapter::new(
            config.keystore_path.clone(),
            Arc::clone(&km_composite),
            deps.pubkey_map.clone(),
            deps.key_gen_tx.clone(),
        )
        .with_denylist(Arc::clone(&deps.deletion_denylist))
        .with_admission_service(deps.admissions)
        .with_quiesce_registry(Arc::clone(&deps.quiesce_registry)),
    );
    let tracked_keys = Arc::clone(&keystore_mgr.tracked_keys);
    let membership = Arc::clone(&km_composite);
    let slashing_prot =
        Arc::new(SlashingProtectionAdapter::new(deps.slashing_db, deps.genesis_validators_root));
    let validator_mgr = Arc::new(ValidatorManagerAdapter::new(deps.validator_store.clone()));

    // M-12: time-based window for the delayed set_enabled task. When
    // doppelganger is disabled the window is Duration::ZERO so keys are
    // immediately enabled. When on: 2 epochs × 32 slots × 12_000 ms = 768 s.
    let doppelganger_window = if config.doppelganger_detection {
        Duration::from_millis(2 * SLOTS_PER_EPOCH * SLOT_DURATION_MS)
    } else {
        Duration::ZERO
    };

    // SEC-2b: when a ForwardWindowMachine is wired, keymanager imports
    // register with it (signing gate). Same monotonic epoch_clock as boot.
    // Fall back to the always-safe Disabled monitor when doppelganger is opted out.
    let (doppelganger_mon, monitor_kind) = select_and_rearm_doppelganger_monitor(
        &config.keystore_path,
        doppelganger_window,
        deps.forward_window_machine,
        deps.epoch_clock,
    );

    let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(
        km_composite,
        config.keymanager.remote_signer_allowed_hosts.clone(),
        deps.pubkey_map,
        deps.key_gen_tx,
    ));

    let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(deps.validator_store));

    let exit_mgr: Option<Arc<dyn VoluntaryExitManager>> =
        Some(Arc::new(VoluntaryExitManagerAdapter::new(
            deps.beacon_client,
            Arc::clone(&deps.signer),
            deps.fork_schedule,
            deps.genesis_validators_root,
        )));

    let signing_quiesce: Arc<dyn SigningQuiesce> = Arc::new(
        SigningQuiesceAdapter::new(Arc::clone(&deps.quiesce_registry), deps.signer)
            .with_keystore_membership(tracked_keys, membership),
    );

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

    Ok(Some(BuiltKeymanagerApi {
        server,
        doppelganger_monitor: doppelganger_mon,
        monitor_kind,
        doppelganger_window,
        addr: km_addr,
        token_path,
    }))
}

/// Bootstrap phase: optionally assemble and spawn the Keymanager API server.
///
/// When `config.keymanager.enabled` is false, returns `Ok(false)` without
/// constructing adapters or touching the token file.
///
/// When enabled, registers the server on `executor` at Ingress tier (ARCH-2g
/// P1-6). Cancellation is driven by the executor token via
/// [`keymanager_api::KeymanagerServer::run_with_shutdown`].
pub fn spawn_keymanager_api(
    config: &Config,
    deps: KeymanagerApiDeps,
    executor: &TaskExecutor,
) -> Result<bool, SpawnKeymanagerApiError> {
    let Some(built) = build_keymanager_api(config, deps)? else {
        return Ok(false);
    };

    info!(
        addr = %built.addr,
        token_path = %built.token_path.display(),
        "Keymanager API enabled"
    );

    let token = executor.token();
    executor.spawn("keymanager_api", ShutdownTier::Ingress, async move {
        if let Err(e) = built.server.run_with_shutdown(token).await {
            error!("Keymanager API server error: {}", e);
        }
    });

    Ok(true)
}
