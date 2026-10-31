use super::keystore::import_meta_path;
use super::notifier::pubkey_hex;
use super::{
    build_keymanager_api, keymanager_bind_addr, scan_and_rearm_gate, spawn_keymanager_api,
    DoppelgangerDisabledMonitor, DoppelgangerMonitorKind, ForwardWindowMonitor, KeymanagerApiDeps,
    KeystoreManagerAdapter, RemoteKeyManagerAdapter, SlashingProtectionAdapter,
    ValidatorConfigManagerAdapter, ValidatorManagerAdapter, VoluntaryExitManagerAdapter,
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
use crate::quiesce::TrackedKeys;

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

/// Remote adapter on a caller's `PubkeyMap` and `TrackedKeys`, as
/// `build_keymanager_api` wires it next to the keystore adapter.
fn shared_remote_adapter(
    signer: Arc<CompositeSigner>,
    pubkey_map: PubkeyMap,
    tracked_keys: Arc<TrackedKeys>,
) -> (RemoteKeyManagerAdapter, watch::Receiver<u64>) {
    let (tx, rx) = watch::channel(0u64);
    let adapter =
        RemoteKeyManagerAdapter::new(signer, None, pubkey_map, tx).with_tracked_keys(tracked_keys);
    (adapter, rx)
}

/// Registers a new key K only as a gRPC remote signer, as boot does for the
/// keys of a configured gRPC signer, and returns K's secret. An empty
/// `LocalSigner` stands in for the gRPC client: the duplicate checks never
/// sign, only the map K lands in matters.
fn add_grpc_remote_key(composite: &CompositeSigner) -> SecretKey {
    let secret = SecretKey::generate();
    composite.add_grpc_remote_signer(
        vec![secret.public_key().to_bytes()],
        Arc::new(LocalSigner::new(KeyManager::new())),
    );
    secret
}

/// The keystore and remote adapters on one `CompositeSigner`, one `PubkeyMap`
/// and one `TrackedKeys`, as `build_keymanager_api` wires them, with a real
/// forward-window machine behind both the keystore admissions and the
/// lifecycle's `ForwardWindowMonitor`.
struct RemoteAndKeystore {
    composite: Arc<CompositeSigner>,
    tracked_keys: Arc<TrackedKeys>,
    machine: Arc<ForwardWindowMachine>,
    keystore: KeystoreManagerAdapter,
    remote: Arc<RemoteKeyManagerAdapter>,
    lifecycle: Arc<keymanager_api::DoppelgangerLifecycle>,
    pubkey_map: PubkeyMap,
    keystore_dir: TempDir,
    _validators_dir: TempDir,
}

fn remote_and_keystore_fixture() -> RemoteAndKeystore {
    let composite = create_empty_composite_signer();
    let pubkey_map = create_pubkey_map();
    let (key_gen_tx, _) = watch::channel(0u64);
    let tracked_keys = Arc::new(TrackedKeys::new());
    let reader: Arc<dyn slashing::SlashingDbReader> =
        Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    // Two closed not-live epochs take an imported key to `Safe`.
    let machine = Arc::new(ForwardWindowMachine::new(reader, 1, [0x11; 32]));

    let keystore_dir = TempDir::new().unwrap();
    let validators_dir = TempDir::new().unwrap();
    let validators_path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &validators_path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&validators_path).expect("validators"));
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map.clone(),
        key_gen_tx.clone(),
        Arc::clone(&composite),
        Arc::clone(&store),
        Arc::clone(&denylist),
        Some(Arc::clone(&machine)),
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let keystore = KeystoreManagerAdapter::new(
        keystore_dir.path().to_path_buf(),
        Arc::clone(&composite),
        pubkey_map.clone(),
        key_gen_tx.clone(),
    )
    .with_tracked_keys(Arc::clone(&tracked_keys))
    .with_denylist(denylist)
    .with_admission_service(Arc::clone(&admissions));
    let remote = Arc::new(
        RemoteKeyManagerAdapter::new(Arc::clone(&composite), None, pubkey_map.clone(), key_gen_tx)
            .with_tracked_keys(Arc::clone(&tracked_keys))
            .with_window_cancel(admissions),
    );

    let epoch: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 5);
    let backing = Arc::clone(&composite);
    let monitor = Arc::new(
        ForwardWindowMonitor::new(Arc::clone(&machine), epoch)
            .with_backing(Arc::new(move |pk| backing.has_any_backend(pk))),
    );
    let lifecycle = Arc::new(keymanager_api::DoppelgangerLifecycle::new(
        std::time::Duration::from_secs(768),
        monitor,
        Arc::new(ValidatorManagerAdapter::new(store)),
    ));

    RemoteAndKeystore {
        composite,
        tracked_keys,
        machine,
        keystore,
        remote,
        lifecycle,
        pubkey_map,
        keystore_dir,
        _validators_dir: validators_dir,
    }
}

/// Drive a future that needs a Tokio runtime (`KdfBudget::admit`, `spawn_blocking`).
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut)
}

mod config;
mod delete_quiesce;
mod denylist;
mod exit;
mod export_floor;
mod import_budget;
mod import_window;
mod keystore;
mod misc_adapters;
mod pubkey_map;
mod quiesce;
mod remote;
mod server;
mod spawn;
