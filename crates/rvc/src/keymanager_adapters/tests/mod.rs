use super::keystore::import_meta_path;
use super::notifier::pubkey_hex;
use super::{
    build_keymanager_api, scan_and_rearm_gate, spawn_keymanager_api, DoppelgangerDisabledMonitor,
    DoppelgangerMonitorKind, ForwardWindowMonitor, KeymanagerApiDeps, KeystoreManagerAdapter,
    RemoteKeyManagerAdapter, SlashingProtectionAdapter, ValidatorConfigManagerAdapter,
    ValidatorManagerAdapter, VoluntaryExitManagerAdapter,
};

use beacon::BeaconClient;
use crypto::{CompositeSigner, KeyManager, Keystore, LocalSigner, SecretKey, Signer};
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock, SigningEnablement};
use eth_types::{Epoch, ForkSchedule, Root};
use keymanager_api::error::ApiError;
use keymanager_api::traits::{
    DoppelgangerMonitor, ImportKeystoreError, ImportRemoteKeyError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, ValidatorConfigManager, ValidatorManager,
    VoluntaryExitManager,
};
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use validator_store::ValidatorStore;

use crate::bootstrap::executor::TaskExecutor;
use crate::orchestrator::PubkeyMap;

fn test_pubkey(id: u8) -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = id;
    pk
}

fn create_empty_composite_signer() -> Arc<CompositeSigner> {
    Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
}

fn create_pubkey_map() -> PubkeyMap {
    Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
}

/// Shared test helper: build a KeystoreManagerAdapter with required map + channel.
fn test_keystore_adapter(
    dir: PathBuf,
    signer: Arc<CompositeSigner>,
) -> (KeystoreManagerAdapter, PubkeyMap, watch::Receiver<u64>) {
    let (tx, rx) = watch::channel(0u64);
    let pubkey_map = create_pubkey_map();
    let adapter = KeystoreManagerAdapter::new(dir, signer, pubkey_map.clone(), tx);
    (adapter, pubkey_map, rx)
}

/// Shared test helper: build a RemoteKeyManagerAdapter with required map + channel.
fn test_remote_adapter(
    signer: Arc<CompositeSigner>,
    allowed_hosts: Option<Vec<String>>,
) -> (RemoteKeyManagerAdapter, PubkeyMap, watch::Receiver<u64>) {
    let (tx, rx) = watch::channel(0u64);
    let pubkey_map = create_pubkey_map();
    let adapter = RemoteKeyManagerAdapter::new(signer, allowed_hosts, pubkey_map.clone(), tx);
    (adapter, pubkey_map, rx)
}

mod config;
mod delete_quiesce;
mod denylist;
mod exit;
mod export_floor;
mod keystore;
mod misc_adapters;
mod pubkey_map;
mod quiesce;
mod remote;
mod server;
mod spawn;
