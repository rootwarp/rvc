//! Re-admission clears quiescence only after a successful keystore import.
//! DELETE's quiesce insert shares the adapter's `tracked_keys` lock.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::extract::{Json, State};
use axum::http::HeaderMap;
use crypto::{
    CompositeSigner, EncryptionKdf, KeyManager, Keystore, LocalSigner, PublicKey, SecretKey,
};
use doppelganger::{
    DoppelgangerDisabledByOperator, ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock,
    SigningEnablement, ValidatorLivenessData,
};
use eth_types::{Epoch, ForkSchedule, Root, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
use keymanager_api::error::ApiError;
use keymanager_api::handlers::{delete_keystores, import_keystores, AppState};
use keymanager_api::traits::{
    DeleteRemoteKeyError, DoppelgangerMonitor, ImportRemoteKeyError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, SlashingProtectionError, ValidatorConfigManager,
    ValidatorManager,
};
use keymanager_api::types::{
    DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteStatus, ImportKeystoresRequest,
    ImportKeystoresResponse, ImportStatus,
};
use keymanager_api::DoppelgangerLifecycle;
use signer::{PreReserveBarrier, SignerError, SignerService, ValidatorSigner};
use slashing::SlashingDb;
use tempfile::TempDir;
use tokio::sync::{watch, Notify};
use validator_store::ValidatorStore;

use super::pubkey_hex;
use super::{
    DoppelgangerDisabledMonitor, ForwardWindowMonitor, KeystoreManagerAdapter,
    SlashingProtectionAdapter, ValidatorManagerAdapter,
};
use crate::deletion_denylist::DeletionDenylist;
use crate::key_admission::KeyAdmissionService;
use crate::orchestrator::PubkeyMap;
use crate::quiesce::{QuiesceRegistry, QuiescingEnablement, SigningQuiesceAdapter};

const GVR: Root = [0x11; 32];
const PASSWORD: &str = "testpass";
const ITERATIONS: usize = 50;

struct Park {
    holding: std::sync::atomic::AtomicBool,
    release_flag: std::sync::atomic::AtomicBool,
    entered: Notify,
    release: Notify,
}

impl Park {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            holding: std::sync::atomic::AtomicBool::new(false),
            release_flag: std::sync::atomic::AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }

    async fn wait_until_holding(&self) {
        loop {
            if self.holding.load(Ordering::Acquire) {
                return;
            }
            let notified = self.entered.notified();
            if self.holding.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.release_flag.store(true, Ordering::Release);
        self.release.notify_waiters();
    }
}

#[async_trait]
impl PreReserveBarrier for Park {
    async fn wait(&self) {
        self.holding.store(true, Ordering::Release);
        self.entered.notify_waiters();
        loop {
            if self.release_flag.load(Ordering::Acquire) {
                return;
            }
            let notified = self.release.notified();
            if self.release_flag.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct NoopRemote;
impl RemoteKeyManager for NoopRemote {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        vec![]
    }
    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }
    fn import_remote_key(&self, _: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        Ok(())
    }
    fn delete_remote_key(&self, _: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        Ok(false)
    }
}

struct NoopConfig;
impl ValidatorConfigManager for NoopConfig {
    fn get_fee_recipient(&self, _: &Pubkey) -> Result<[u8; 20], ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_fee_recipient(&self, _: &Pubkey, _: [u8; 20]) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_fee_recipient(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_gas_limit(&self, _: &Pubkey) -> Result<u64, ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_gas_limit(&self, _: &Pubkey, _: u64) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_gas_limit(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_graffiti(&self, _: &Pubkey) -> Result<String, ApiError> {
        Ok(String::new())
    }
    fn set_graffiti(&self, _: &Pubkey, _: &str) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_graffiti(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
}

struct Harness {
    pk: Pubkey,
    public: PublicKey,
    json: String,
    adapter: Arc<KeystoreManagerAdapter>,
    registry: Arc<QuiesceRegistry>,
    quiesce: Arc<SigningQuiesceAdapter>,
    signer: Arc<SignerService>,
    gate: Arc<QuiescingEnablement>,
    store: Arc<ValidatorStore>,
    state: Arc<AppState>,
    machine: Option<Arc<ForwardWindowMachine>>,
    clock: Option<Arc<MonotonicEpochClock>>,
    denylist: Arc<DeletionDenylist>,
    fork: ForkSchedule,
    park: Option<Arc<Park>>,
    export_stall: Option<Arc<SecondExportStall>>,
    export_entered: Option<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
    export_release: Option<std::sync::mpsc::Sender<()>>,
    _dir: TempDir,
}

/// Blocks inside the second `export_interchange` until the test sends on the release channel.
struct SecondExportStall {
    inner: SlashingProtectionAdapter,
    calls: AtomicU32,
    entered_tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release_rx: Mutex<std::sync::mpsc::Receiver<()>>,
    captured: Mutex<Option<String>>,
}

impl SecondExportStall {
    fn new(
        inner: SlashingProtectionAdapter,
    ) -> (Arc<Self>, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stall = Arc::new(Self {
            inner,
            calls: AtomicU32::new(0),
            entered_tx: Mutex::new(Some(entered_tx)),
            release_rx: Mutex::new(release_rx),
            captured: Mutex::new(None),
        });
        (stall, entered_rx, release_tx)
    }
}

impl SlashingProtection for SecondExportStall {
    fn import_interchange(&self, json: &str) -> Result<(), SlashingProtectionError> {
        self.inner.import_interchange(json)
    }

    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 1 {
            if let Some(tx) = self.entered_tx.lock().expect("entered").take() {
                let _ = tx.send(());
            }
            let _ = self.release_rx.lock().expect("release").recv_timeout(Duration::from_secs(15));
        }
        let exported = self.inner.export_interchange(pubkeys)?;
        if n == 1 {
            *self.captured.lock().expect("captured") = Some(exported.clone());
        }
        Ok(exported)
    }
}

struct Build {
    doppelganger: bool,
    drain: Duration,
    park: bool,
    stall_second_export: bool,
}

fn clock_at(epoch: u64) -> Arc<MonotonicEpochClock> {
    let genesis = 1_700_000_000u64;
    let secs = epoch * SLOTS_PER_EPOCH * SLOT_DURATION_MS / 1000;
    Arc::new(MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis + secs))
}

fn build(opts: Build) -> Harness {
    let secret = SecretKey::generate();
    let public = secret.public_key();
    let pk = public.to_bytes();
    let keystore = Keystore::encrypt(
        &secret,
        PASSWORD.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = serde_json::to_string(&keystore).expect("keystore json");

    let dir = TempDir::new().expect("tempdir");
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
    db.set_genesis_validators_root(&GVR).expect("gvr");
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).expect("denylist"));
    let pubkey_map: PubkeyMap =
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    let (key_gen_tx, _rx) = watch::channel(0u64);
    let store = Arc::new(ValidatorStore::new([1u8; 20], 30_000_000));
    let registry = Arc::new(QuiesceRegistry::new());

    let machine;
    let clock;
    let inner: Arc<dyn SigningEnablement>;
    if opts.doppelganger {
        let epoch_clock = clock_at(5);
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::clone(&db) as _;
        let window = Arc::new(ForwardWindowMachine::new(reader, 1, GVR));
        inner = Arc::clone(&window) as _;
        machine = Some(window);
        clock = Some(epoch_clock);
    } else {
        machine = None;
        clock = None;
        inner = Arc::new(DoppelgangerDisabledByOperator);
    };

    let admissions = Arc::new(KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        key_gen_tx.clone(),
        Arc::clone(&composite),
        Arc::clone(&store),
        Arc::clone(&denylist),
        machine.clone(),
        clock.clone().unwrap_or_else(|| Arc::new(MonotonicEpochClock::new(0))),
    ));
    let adapter = Arc::new(
        KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            Arc::clone(&composite),
            pubkey_map,
            key_gen_tx,
        )
        .with_denylist(Arc::clone(&denylist))
        .with_admission_service(admissions)
        .with_quiesce_registry(Arc::clone(&registry)),
    );

    let gate = Arc::new(QuiescingEnablement::new(inner, Arc::clone(&registry)));
    let enablement: Arc<dyn SigningEnablement> = Arc::clone(&gate) as _;
    let signer = Arc::new(
        SignerService::new(Arc::clone(&composite), Arc::clone(&db)).with_enablement(enablement),
    );
    let park = if opts.park {
        let park = Park::new();
        signer.set_pre_reserve_barrier(Some(Arc::clone(&park) as Arc<dyn PreReserveBarrier>));
        Some(park)
    } else {
        None
    };

    let quiesce = Arc::new(
        SigningQuiesceAdapter::new(Arc::clone(&registry), Arc::clone(&signer))
            .with_keystore_membership(Arc::clone(&adapter.tracked_keys), composite),
    );

    let monitor: Arc<dyn DoppelgangerMonitor> = if let Some(machine) = &machine {
        let clock = Arc::clone(clock.as_ref().expect("clock"));
        let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> =
            Arc::new(move || clock.current_epoch());
        Arc::new(ForwardWindowMonitor::new(Arc::clone(machine), epoch_provider))
    } else {
        Arc::new(DoppelgangerDisabledMonitor::new())
    };
    let vm = Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let window = if opts.doppelganger { Duration::from_secs(3_600) } else { Duration::ZERO };
    let slashing = SlashingProtectionAdapter::new(Arc::clone(&db), GVR);
    let export_stall;
    let export_entered;
    let export_release;
    let slashing_protection: Arc<dyn SlashingProtection>;
    if opts.stall_second_export {
        let (stall, entered_rx, release_tx) = SecondExportStall::new(slashing);
        slashing_protection = Arc::clone(&stall) as _;
        export_entered = Some(Mutex::new(Some(entered_rx)));
        export_release = Some(release_tx);
        export_stall = Some(stall);
    } else {
        slashing_protection = Arc::new(slashing);
        export_stall = None;
        export_entered = None;
        export_release = None;
    }
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&adapter) as Arc<dyn KeystoreManager>,
        slashing_protection,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(window, monitor, Arc::clone(&vm_dyn))
                .with_signing_quiesce(Arc::clone(&quiesce) as _, opts.drain),
        ),
        validator_manager: vm_dyn,
        remote_key_manager: Arc::new(NoopRemote),
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    });

    Harness {
        pk,
        public,
        json,
        adapter,
        registry,
        quiesce,
        signer,
        gate,
        store,
        state,
        machine,
        clock,
        denylist,
        fork: ForkSchedule::unscheduled_gloas(),
        park,
        export_stall,
        export_entered,
        export_release,
        _dir: dir,
    }
}

async fn import_one(
    state: &Arc<AppState>,
    json: &str,
    slashing: Option<String>,
) -> ImportKeystoresResponse {
    let Json(resp) = import_keystores(
        State(Arc::clone(state)),
        HeaderMap::new(),
        Json(ImportKeystoresRequest {
            keystores: vec![json.to_string()],
            passwords: vec![PASSWORD.to_string()],
            slashing_protection: slashing,
        }),
    )
    .await
    .expect("import request");
    resp
}

async fn delete_one(
    state: &Arc<AppState>,
    pk: &Pubkey,
) -> Result<DeleteKeystoresResponse, ApiError> {
    delete_keystores(
        State(Arc::clone(state)),
        Json(DeleteKeystoresRequest { pubkeys: vec![pubkey_hex(*pk)] }),
    )
    .await
    .map(|Json(resp)| resp)
}

async fn sign(h: &Harness, slot: u64) -> Result<crypto::Signature, SignerError> {
    h.signer.sign_block(&[0xab; 32], slot, &h.public, &h.fork, &GVR).await
}

async fn assert_refused(h: &Harness, slot: u64) {
    let result = sign(h, slot).await;
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "signing must be refused, got {result:?}"
    );
}

fn assert_disabled(store: &ValidatorStore, pk: &Pubkey) {
    let config = store.get_config(pk).expect("validator remains after a failed delete");
    assert!(!config.enabled, "failed delete must leave the validator disabled");
}

fn satisfy_window(machine: &ForwardWindowMachine, clock: &MonotonicEpochClock, pk: &PublicKey) {
    let now = clock.current_epoch();
    let index = hex::encode(pk.to_bytes());
    for epoch in now.saturating_sub(1)..=now.saturating_add(2) {
        machine
            .observe_liveness(
                epoch,
                &[ValidatorLivenessData { index: index.clone(), is_live: false }],
            )
            .unwrap_or_else(|err| panic!("observe epoch {epoch}: {err}"));
    }
    let _ = machine.tick(now.saturating_add(4), 0);
    assert_eq!(machine.status(pk), ForwardWindowStatus::Safe, "doppelganger window must open");
}

fn hook_pair(
) -> (Arc<dyn Fn() + Send + Sync>, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = Arc::new(parking_lot::Mutex::new(release_rx));
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        entered_tx.send(()).expect("observer alive");
        release_rx.lock().recv_timeout(Duration::from_secs(15)).expect("hook released");
    });
    (hook, entered_rx, release_tx)
}

async fn wait_entered(rx: std::sync::mpsc::Receiver<()>, what: &str) {
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(8)))
        .await
        .unwrap_or_else(|_| panic!("{what} wait task"))
        .unwrap_or_else(|_| panic!("{what} was not reached"));
}

async fn wait_contended(keys: &crate::quiesce::TrackedKeys, before: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if keys.contended() > before {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("DELETE did not block on tracked_keys");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_then_reimport_signs_again_without_restart() {
    let h = build(Build {
        doppelganger: true,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);
    assert!(!h.registry.contains(&h.pk), "a fresh import is not quiesced");

    let deleted = delete_one(&h.state, &h.pk).await.expect("delete");
    assert_eq!(deleted.data[0].status, DeleteStatus::Deleted);
    assert!(!h.adapter.has_key(&h.pk));
    assert!(h.registry.contains(&h.pk), "successful delete leaves the key quiesced");

    let again = import_one(&h.state, &h.json, Some(deleted.slashing_protection)).await;
    assert_eq!(again.data[0].status, ImportStatus::Imported, "re-import after delete: {again:?}");
    assert!(h.adapter.has_key(&h.pk));
    assert!(!h.registry.contains(&h.pk), "successful re-import clears quiescence");
    let machine = h.machine.as_ref().expect("doppelganger on");
    assert_eq!(machine.status(&h.public), ForwardWindowStatus::Pending);
    assert_refused(&h, 3).await;

    satisfy_window(machine, h.clock.as_ref().expect("clock"), &h.public);
    sign(&h, 4).await.expect("signing succeeds after the doppelganger window, without a restart");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reimport_is_still_subject_to_doppelganger() {
    let h = build(Build {
        doppelganger: true,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);
    let deleted = delete_one(&h.state, &h.pk).await.expect("delete");
    assert_eq!(deleted.data[0].status, DeleteStatus::Deleted);

    let again = import_one(&h.state, &h.json, Some(deleted.slashing_protection)).await;
    assert_eq!(again.data[0].status, ImportStatus::Imported);
    assert!(!h.registry.contains(&h.pk), "quiescence cleared");
    let machine = h.machine.as_ref().expect("doppelganger on");
    assert_eq!(
        machine.status(&h.public),
        ForwardWindowStatus::Pending,
        "re-import must enter a fresh doppelganger window"
    );
    assert!(!h.gate.is_signing_enabled(&h.public), "inner gate stays closed during the window");
    assert_refused(&h, 5).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_quiesce_between_admit_and_readmit_is_not_erased() {
    let h = build(Build {
        doppelganger: false,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    h.registry.insert(&h.pk);

    let (admit_hook, admit_rx, admit_release) = hook_pair();
    let (readmit_hook, readmit_rx, readmit_release) = hook_pair();
    let (insert_hook, insert_rx, insert_release) = hook_pair();
    h.adapter.set_after_admit_hook(admit_hook);
    h.adapter.set_after_readmit_hook(readmit_hook);
    h.quiesce.set_after_insert_hook(insert_hook);

    let state = Arc::clone(&h.state);
    let json = h.json.clone();
    let import_task = tokio::spawn(async move { import_one(&state, &json, None).await });
    wait_entered(admit_rx, "after admit").await;
    assert!(h.adapter.has_key(&h.pk), "admit has installed the key");
    assert!(h.registry.contains(&h.pk), "readmit has not run yet");
    assert_eq!(h.quiesce.quiesce_inserts(), 0);

    let before = h.adapter.tracked_keys.contended();
    let state = Arc::clone(&h.state);
    let pk = h.pk;
    let delete_task = tokio::spawn(async move { delete_one(&state, &pk).await });
    wait_contended(&h.adapter.tracked_keys, before).await;
    assert_eq!(h.quiesce.quiesce_inserts(), 0, "quiesce insert must wait for tracked_keys");

    admit_release.send(()).expect("release admit hook");
    wait_entered(readmit_rx, "after readmit").await;
    assert!(
        !h.registry.contains(&h.pk),
        "readmit cleared the quiescence inserted before this import"
    );
    assert_eq!(h.quiesce.quiesce_inserts(), 0, "DELETE still has not inserted");
    assert!(h.adapter.has_key(&h.pk));

    readmit_release.send(()).expect("release readmit hook");
    wait_entered(insert_rx, "quiesce insert").await;
    assert_eq!(h.quiesce.quiesce_inserts(), 1);
    assert!(h.registry.contains(&h.pk), "DELETE's insert survived readmit");
    assert!(h.adapter.has_key(&h.pk), "delete_keystore has not run yet");
    assert_refused(&h, 8).await;

    insert_release.send(()).expect("release insert hook");
    let imported = import_task.await.expect("import join");
    assert_eq!(imported.data[0].status, ImportStatus::Imported, "{imported:?}");
    let deleted = delete_task.await.expect("delete join").expect("delete");
    assert_eq!(deleted.data[0].status, DeleteStatus::Deleted, "{deleted:?}");
    assert!(!h.adapter.has_key(&h.pk));
    assert!(h.registry.contains(&h.pk), "nothing erased the quiescence DELETE inserted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_reimport_leaves_the_key_quiesced() {
    let h = build(Build {
        doppelganger: false,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);
    let deleted = delete_one(&h.state, &h.pk).await.expect("delete");
    assert_eq!(deleted.data[0].status, DeleteStatus::Deleted);
    assert!(!h.adapter.has_key(&h.pk));
    assert!(h.registry.contains(&h.pk));
    assert!(h.denylist.contains(&h.pk));

    // SEC-1b persistence: `remove` rewrites the denylist file. A directory at
    // that path makes the rewrite fail after admission.
    let path = h.denylist.path().to_path_buf();
    std::fs::remove_file(&path).expect("denylist file");
    std::fs::create_dir(&path).expect("denylist path is not a file");

    let again = import_one(&h.state, &h.json, None).await;
    assert_eq!(again.data[0].status, ImportStatus::Error, "persistence failure: {again:?}");
    assert!(h.registry.contains(&h.pk), "failed re-import must not readmit");
    assert!(h.denylist.contains(&h.pk), "failed clear rolls the denylist entry back");
    assert!(h.adapter.has_key(&h.pk), "admission happened before the denylist write failed");
    assert_refused(&h, 6).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_import_after_failed_delete_does_not_readmit() {
    let h = build(Build {
        doppelganger: false,
        drain: Duration::from_millis(200),
        park: true,
        stall_second_export: false,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);

    let park = h.park.as_ref().expect("park").clone();
    let signer = Arc::clone(&h.signer);
    let public = h.public.clone();
    let fork = h.fork.clone();
    let parked =
        tokio::spawn(async move { signer.sign_block(&[0xcd; 32], 42, &public, &fork, &GVR).await });
    tokio::time::timeout(Duration::from_secs(2), park.wait_until_holding())
        .await
        .expect("sign reached the pre-reserve barrier");

    let err = delete_one(&h.state, &h.pk).await.expect_err("drain timeout fails DELETE");
    assert!(err.to_string().contains("signing drain timed out"), "{err}");
    assert!(h.adapter.has_key(&h.pk));
    assert!(h.registry.contains(&h.pk));
    assert_disabled(&h.store, &h.pk);

    let again = import_one(&h.state, &h.json, None).await;
    assert_eq!(again.data[0].status, ImportStatus::Duplicate, "{again:?}");
    assert!(h.adapter.has_key(&h.pk));
    assert!(h.registry.contains(&h.pk), "duplicate import must not readmit");
    assert_disabled(&h.store, &h.pk);

    park.release();
    parked.await.expect("parked sign").expect("in-flight sign already passed the gate");
    assert_refused(&h, 43).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_delete_and_import_never_reopen_a_quiesced_present_key() {
    let h = build(Build {
        doppelganger: false,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    let mut overlaps = 0u64;

    for i in 0..ITERATIONS {
        if !h.adapter.has_key(&h.pk) {
            let imported = import_one(&h.state, &h.json, None).await;
            assert_eq!(
                imported.data[0].status,
                ImportStatus::Imported,
                "iteration {i}: {imported:?}"
            );
        }
        assert!(h.adapter.has_key(&h.pk), "iteration {i}: key missing before the race");
        assert!(!h.registry.contains(&h.pk), "iteration {i}: key still quiesced before the race");

        let slot = 1_000 + i as u64;
        sign(&h, slot).await.unwrap_or_else(|err| panic!("iteration {i}: sign before race: {err}"));
        let slot_pat = format!("\"slot\":\"{slot}\"");

        let before = h.adapter.tracked_keys.contended();
        h.adapter.tracked_keys.set_stall_ms(30);
        let state_d = Arc::clone(&h.state);
        let state_i = Arc::clone(&h.state);
        let json = h.json.clone();
        let pk = h.pk;
        let delete_task = tokio::spawn(async move { delete_one(&state_d, &pk).await });
        let import_task = tokio::spawn(async move { import_one(&state_i, &json, None).await });
        let (deleted, imported) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(delete_task, import_task)
        })
        .await
        .unwrap_or_else(|_| panic!("iteration {i}: race hung"));
        h.adapter.tracked_keys.set_stall_ms(0);
        if h.adapter.tracked_keys.contended() > before {
            overlaps += 1;
        }

        let deleted =
            deleted.expect("delete join").unwrap_or_else(|err| panic!("iteration {i}: {err}"));
        assert_eq!(deleted.data[0].status, DeleteStatus::Deleted, "iteration {i}: {deleted:?}");
        assert!(
            deleted.slashing_protection.contains(&slot_pat),
            "iteration {i}: export omitted the signature: {}",
            deleted.slashing_protection
        );
        let imported = imported.expect("import join");
        assert!(
            matches!(imported.data[0].status, ImportStatus::Imported | ImportStatus::Duplicate),
            "iteration {i}: {imported:?}"
        );

        let present = h.adapter.has_key(&h.pk);
        let quiesced = h.registry.contains(&h.pk);
        let signing = h.gate.is_signing_enabled(&h.public);
        match (present, quiesced, signing) {
            (false, true, false) => {}
            (true, false, true) => {}
            other => {
                panic!("iteration {i}: inadmissible end state present/quiesced/signing = {other:?}")
            }
        }
    }

    assert!(
        overlaps >= 1,
        "instrumented counter saw no overlapping tracked_keys critical sections in {ITERATIONS} iterations"
    );
}

/// Two DELETEs snapshot the same key. The import runs while the second export
/// is in progress, after the first DELETE has already removed the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_deletes_reject_import_during_the_second_export() {
    let h = build(Build {
        doppelganger: false,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: true,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);
    let slot = 77u64;
    sign(&h, slot).await.expect("sign before the deletes");
    let slot_pat = format!("\"slot\":\"{slot}\"");

    let arrived = Arc::new(AtomicU32::new(0));
    let arrived_hook = Arc::clone(&arrived);
    h.quiesce.set_after_insert_hook(Arc::new(move || {
        let n = arrived_hook.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let start = std::time::Instant::now();
            while arrived_hook.load(Ordering::SeqCst) < 2 {
                assert!(start.elapsed() < Duration::from_secs(8), "second DELETE did not quiesce");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }));

    let state_a = Arc::clone(&h.state);
    let state_b = Arc::clone(&h.state);
    let pk = h.pk;
    let delete_a = tokio::spawn(async move { delete_one(&state_a, &pk).await });
    let delete_b = tokio::spawn(async move { delete_one(&state_b, &pk).await });

    let entered = h
        .export_entered
        .as_ref()
        .expect("stall")
        .lock()
        .expect("entered")
        .take()
        .expect("entered once");
    wait_entered(entered, "second export").await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !h.adapter.has_key(&h.pk) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the DELETE that was not stalled did not remove the key");

    let during = import_one(&h.state, &h.json, None).await;
    assert_eq!(during.data[0].status, ImportStatus::Error, "{during:?}");
    assert!(during.data[0].message.contains("delete in progress"), "{during:?}");
    assert!(!h.adapter.has_key(&h.pk), "in-flight DELETE must not admit");
    assert!(h.registry.contains(&h.pk), "readmit must not run");
    assert!(!h.gate.is_signing_enabled(&h.public));
    assert_refused(&h, 78).await;

    h.export_release.as_ref().expect("release").send(()).expect("second export waiting");
    let first = delete_a.await.expect("delete a join").expect("delete a");
    let second = delete_b.await.expect("delete b join").expect("delete b");
    let captured = h
        .export_stall
        .as_ref()
        .expect("stall")
        .captured
        .lock()
        .expect("captured")
        .clone()
        .expect("second export");
    assert!(
        captured.contains(&slot_pat),
        "signature missing from the export that raced the import: {captured}"
    );
    assert!(
        first.slashing_protection.contains(&slot_pat)
            || second.slashing_protection.contains(&slot_pat),
        "neither DELETE exported slot {slot}"
    );

    let again = import_one(&h.state, &h.json, None).await;
    assert_eq!(
        again.data[0].status,
        ImportStatus::Imported,
        "count must drop when both DELETEs return: {again:?}"
    );
    assert!(h.gate.is_signing_enabled(&h.public));
}

/// After the keystore removal drops `tracked_keys`, and before `on_delete`
/// calls `cancel_monitoring`, the forward window is already `Unmonitored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_cancels_doppelganger_before_unlocking_tracked_keys() {
    let h = build(Build {
        doppelganger: true,
        drain: Duration::from_secs(2),
        park: false,
        stall_second_export: false,
    });
    let imported = import_one(&h.state, &h.json, None).await;
    assert_eq!(imported.data[0].status, ImportStatus::Imported);
    let machine = h.machine.as_ref().expect("doppelganger on");
    satisfy_window(machine, h.clock.as_ref().expect("clock"), &h.public);
    assert_eq!(machine.status(&h.public), ForwardWindowStatus::Safe);

    let (hook, entered, release) = hook_pair();
    h.adapter.set_after_delete_unlock_hook(hook);
    let state = Arc::clone(&h.state);
    let pk = h.pk;
    let delete_task = tokio::spawn(async move { delete_one(&state, &pk).await });
    wait_entered(entered, "after delete unlock").await;

    assert_eq!(
        machine.status(&h.public),
        ForwardWindowStatus::Unmonitored,
        "cancel must run before tracked_keys is released"
    );
    let during = import_one(&h.state, &h.json, None).await;
    assert_eq!(during.data[0].status, ImportStatus::Error, "{during:?}");
    assert!(!h.adapter.has_key(&h.pk));
    assert!(!h.gate.is_signing_enabled(&h.public), "import must not open signing");
    assert_refused(&h, 90).await;

    release.send(()).expect("release delete hook");
    let deleted = delete_task.await.expect("delete join").expect("delete");
    assert_eq!(deleted.data[0].status, DeleteStatus::Deleted, "{deleted:?}");
}
