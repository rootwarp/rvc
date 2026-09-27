//! A slashable sign racing DELETE is refused or present in the export.
//! Never signed and then absent from the migration file.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::{DoppelgangerDisabledByOperator, SigningEnablement};
use eth_types::{ForkSchedule, Root};
use keymanager_api::error::ApiError;
use keymanager_api::handlers::{delete_keystores, AppState};
use keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
    KeystoreManager, Pubkey, QuiesceError, RemoteKeyManager, SigningQuiesce, SlashingProtection,
    ValidatorConfigManager, ValidatorManager,
};
use keymanager_api::types::DeleteKeystoresRequest;
use keymanager_api::DoppelgangerLifecycle;
use rvc::keymanager_adapters::{
    DoppelgangerDisabledMonitor, SlashingProtectionAdapter, ValidatorManagerAdapter,
};
use rvc::quiesce::{QuiesceRegistry, QuiescingEnablement, SigningQuiesceAdapter};
use signer::{PreReserveBarrier, SignerService, ValidatorSigner};
use slashing::SlashingDb;
use tokio::sync::Notify;
use validator_store::ValidatorStore;

const GVR: Root = [0x11; 32];
const ITERATIONS: usize = 50;
const DRAIN: Duration = Duration::from_secs(2);

struct Park {
    holding: AtomicBool,
    release_flag: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl Park {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            holding: AtomicBool::new(false),
            release_flag: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }

    async fn wait_holding(&self) {
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

struct ObservingQuiesce {
    inner: SigningQuiesceAdapter,
    park: Arc<Park>,
    raced: Arc<AtomicUsize>,
    entered: AtomicBool,
    entered_notify: Notify,
}

#[async_trait]
impl SigningQuiesce for ObservingQuiesce {
    async fn quiesce(&self, pubkey: &Pubkey, timeout: Duration) -> Result<(), QuiesceError> {
        if self.park.holding.load(Ordering::Acquire)
            && !self.park.release_flag.load(Ordering::Acquire)
        {
            self.raced.fetch_add(1, Ordering::SeqCst);
        }
        self.entered.store(true, Ordering::Release);
        self.entered_notify.notify_waiters();
        self.inner.quiesce(pubkey, timeout).await
    }
}

impl ObservingQuiesce {
    async fn wait_entered(&self) {
        loop {
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            let notified = self.entered_notify.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct MemoryKeys {
    keys: Mutex<Vec<Pubkey>>,
}

impl MemoryKeys {
    fn ensure(&self, pk: Pubkey) {
        let mut keys = self.keys.lock().expect("keys");
        if !keys.contains(&pk) {
            keys.push(pk);
        }
    }
}

impl KeystoreManager for MemoryKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().expect("keys").clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().expect("keys").contains(pubkey)
    }
    fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::InvalidKeystore("unused".into()))
    }
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.keys.lock().expect("keys");
        if let Some(i) = keys.iter().position(|k| k == pubkey) {
            keys.remove(i);
            Ok(true)
        } else {
            Ok(false)
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

struct World {
    pk: Pubkey,
    public: PublicKey,
    composite: Arc<CompositeSigner>,
    db: Arc<SlashingDb>,
    store: Arc<ValidatorStore>,
    vm: Arc<ValidatorManagerAdapter>,
    keys: Arc<MemoryKeys>,
    slashing: Arc<SlashingProtectionAdapter>,
    fork: ForkSchedule,
    raced: Arc<AtomicUsize>,
}

fn world() -> World {
    let secret = SecretKey::generate();
    let public = secret.public_key();
    let pk = public.to_bytes();
    let mut km = KeyManager::new();
    km.insert(secret);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
    db.set_genesis_validators_root(&GVR).expect("gvr");
    let store = Arc::new(ValidatorStore::new([1u8; 20], 30_000_000));
    let vm = Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    World {
        pk,
        public,
        composite,
        db: Arc::clone(&db),
        store,
        vm,
        keys: Arc::new(MemoryKeys { keys: Mutex::new(vec![pk]) }),
        slashing: Arc::new(SlashingProtectionAdapter::new(db, GVR)),
        fork: ForkSchedule::unscheduled_gloas(),
        raced: Arc::new(AtomicUsize::new(0)),
    }
}

async fn one_iteration(world: &World, n: u64) {
    if world.store.get_config(&world.pk).is_none() {
        world.vm.add_validator(world.pk, true);
    } else {
        world.vm.set_validator_enabled(&world.pk, true);
    }
    world.keys.ensure(world.pk);

    let park = Park::new();
    let registry = Arc::new(QuiesceRegistry::new());
    let inner: Arc<dyn SigningEnablement> = Arc::new(DoppelgangerDisabledByOperator);
    let enablement: Arc<dyn SigningEnablement> =
        Arc::new(QuiescingEnablement::new(inner, Arc::clone(&registry)));
    let signer = Arc::new(
        SignerService::new(Arc::clone(&world.composite), Arc::clone(&world.db))
            .with_enablement(enablement),
    );
    signer.set_pre_reserve_barrier(Some(Arc::clone(&park) as Arc<dyn PreReserveBarrier>));
    let observing = Arc::new(ObservingQuiesce {
        inner: SigningQuiesceAdapter::new(registry, Arc::clone(&signer)),
        park: Arc::clone(&park),
        raced: Arc::clone(&world.raced),
        entered: AtomicBool::new(false),
        entered_notify: Notify::new(),
    });
    let vm: Arc<dyn ValidatorManager> = Arc::clone(&world.vm) as _;
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&world.keys) as Arc<dyn KeystoreManager>,
        slashing_protection: Arc::clone(&world.slashing) as Arc<dyn SlashingProtection>,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::ZERO,
                Arc::new(DoppelgangerDisabledMonitor::new()),
                Arc::clone(&vm),
            )
            .with_signing_quiesce(Arc::clone(&observing) as _, DRAIN),
        ),
        validator_manager: vm,
        remote_key_manager: Arc::new(NoopRemote),
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    });

    let slot = 1_000 + n;
    let root = [(n as u8).wrapping_add(1); 32];
    let signer_task = Arc::clone(&signer);
    let public = world.public.clone();
    let fork = world.fork.clone();
    let sign =
        tokio::spawn(
            async move { signer_task.sign_block(&root, slot, &public, &fork, &GVR).await },
        );
    tokio::time::timeout(Duration::from_secs(2), park.wait_holding())
        .await
        .unwrap_or_else(|_| panic!("iteration {n}: sign never reached the pre-reserve barrier"));

    let pubkey_hex = format!("0x{}", hex::encode(world.pk));
    let delete_state = Arc::clone(&state);
    let delete = tokio::spawn(async move {
        delete_keystores(
            State(delete_state),
            Json(DeleteKeystoresRequest { pubkeys: vec![pubkey_hex] }),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), observing.wait_entered())
        .await
        .unwrap_or_else(|_| panic!("iteration {n}: DELETE never entered quiesce"));
    assert!(
        park.holding.load(Ordering::Acquire) && !park.release_flag.load(Ordering::Acquire),
        "iteration {n}: sign was not inside the DELETE window"
    );
    park.release();

    let signed = sign.await.expect("sign join").expect("in-flight sign completes");
    assert_eq!(signed.to_bytes().len(), 96);
    let stored = world.db.get_blocks(&hex::encode(world.pk)).expect("blocks");
    let row = stored.iter().find(|block| block.slot == slot).expect("reserved row");
    let signing_root = row.signing_root.as_ref().expect("signing root").as_hex().to_string();
    let Json(resp) = delete.await.expect("delete join").expect("DELETE after a finished drain");
    assert!(
        resp.slashing_protection.contains(&signing_root),
        "iteration {n}: signed and absent from the export: {}",
        resp.slashing_protection
    );
    assert!(
        resp.slashing_protection.contains(&format!("\"slot\":\"{slot}\"")),
        "iteration {n}: export missing slot {slot}: {}",
        resp.slashing_protection
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signature_concurrent_with_delete_is_refused_or_present_in_the_export() {
    let world = world();
    for n in 0..ITERATIONS {
        one_iteration(&world, n as u64).await;
    }
    let raced = world.raced.load(Ordering::SeqCst);
    assert!(
        raced >= 1,
        "no iteration observed the sign inside the DELETE window; the test is vacuous"
    );
    assert_eq!(raced, ITERATIONS, "every iteration must actually race");
}
