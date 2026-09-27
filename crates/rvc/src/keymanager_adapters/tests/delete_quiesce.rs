//! DELETE drain-timeout behaviour, driven through the real `delete_keystores`
//! handler. The sign is parked after the under-lock enablement check and
//! before reserve, so the outcome does not depend on repetition.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::{DoppelgangerDisabledByOperator, SigningEnablement};
use eth_types::{ForkSchedule, Root};
use http_body_util::BodyExt;
use keymanager_api::error::ApiError;
use keymanager_api::handlers::{delete_keystores, AppState};
use keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
    KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection, SlashingProtectionError,
    ValidatorConfigManager, ValidatorManager,
};
use keymanager_api::types::DeleteKeystoresRequest;
use keymanager_api::DoppelgangerLifecycle;
use observability::logging::TruncatedPubkey;
use signer::{PreReserveBarrier, SignerService, ValidatorSigner};
use slashing::SlashingDb;
use tokio::sync::Notify;
use validator_store::ValidatorStore;

use super::{
    pubkey_hex, DoppelgangerDisabledMonitor, SlashingProtectionAdapter, ValidatorManagerAdapter,
};
use crate::quiesce::{QuiesceRegistry, QuiescingEnablement, SigningQuiesceAdapter};

const GVR: Root = [0x11; 32];
const SLOT: u64 = 42;
const ROOT: Root = [0xab; 32];
const DRAIN: Duration = Duration::from_millis(200);

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

struct MemoryKeys {
    keys: Mutex<Vec<Pubkey>>,
    deletes: AtomicU32,
}

impl MemoryKeys {
    fn with(keys: Vec<Pubkey>) -> Arc<Self> {
        Arc::new(Self { keys: Mutex::new(keys), deletes: AtomicU32::new(0) })
    }

    fn has(&self, pk: &Pubkey) -> bool {
        self.keys.lock().expect("keys").contains(pk)
    }
}

impl KeystoreManager for MemoryKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().expect("keys").clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.has(pubkey)
    }

    fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::InvalidKeystore("unused".into()))
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.keys.lock().expect("keys");
        if let Some(i) = keys.iter().position(|k| k == pubkey) {
            keys.remove(i);
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct ExportSpy {
    inner: SlashingProtectionAdapter,
    calls: Arc<AtomicU32>,
}

impl SlashingProtection for ExportSpy {
    fn import_interchange(&self, json: &str) -> Result<(), SlashingProtectionError> {
        self.inner.import_interchange(json)
    }

    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.export_interchange(pubkeys)
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

struct Rig {
    pk: Pubkey,
    public: PublicKey,
    signer: Arc<SignerService>,
    db: Arc<SlashingDb>,
    registry: Arc<QuiesceRegistry>,
    store: Arc<ValidatorStore>,
    keys: Arc<MemoryKeys>,
    exports: Arc<AtomicU32>,
    state: Arc<AppState>,
    park: Arc<Park>,
    fork: ForkSchedule,
}

fn rig(extra: &[Pubkey]) -> Rig {
    let secret = SecretKey::generate();
    let public = secret.public_key();
    let pk = public.to_bytes();
    let mut km = KeyManager::new();
    km.insert(secret);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
    db.set_genesis_validators_root(&GVR).expect("gvr");

    let park = Park::new();
    let registry = Arc::new(QuiesceRegistry::new());
    let inner: Arc<dyn SigningEnablement> = Arc::new(DoppelgangerDisabledByOperator);
    let enablement: Arc<dyn SigningEnablement> =
        Arc::new(QuiescingEnablement::new(inner, Arc::clone(&registry)));
    let signer =
        Arc::new(SignerService::new(composite, Arc::clone(&db)).with_enablement(enablement));
    signer.set_pre_reserve_barrier(Some(Arc::clone(&park) as Arc<dyn PreReserveBarrier>));

    let store = Arc::new(ValidatorStore::new([1u8; 20], 30_000_000));
    let vm = Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    vm.add_validator(pk, true);
    for extra_pk in extra {
        vm.add_validator(*extra_pk, true);
    }

    let mut known = vec![pk];
    known.extend_from_slice(extra);
    let keys = MemoryKeys::with(known);
    let exports = Arc::new(AtomicU32::new(0));
    let slashing = Arc::new(ExportSpy {
        inner: SlashingProtectionAdapter::new(Arc::clone(&db), GVR),
        calls: Arc::clone(&exports),
    });
    let quiesce = Arc::new(SigningQuiesceAdapter::new(Arc::clone(&registry), Arc::clone(&signer)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&keys) as Arc<dyn KeystoreManager>,
        slashing_protection: slashing,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::ZERO,
                Arc::new(DoppelgangerDisabledMonitor::new()),
                Arc::clone(&vm_dyn),
            )
            .with_signing_quiesce(quiesce, DRAIN),
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

    Rig {
        pk,
        public,
        signer,
        db,
        registry,
        store,
        keys,
        exports,
        state,
        park,
        fork: ForkSchedule::unscheduled_gloas(),
    }
}

fn truncated(pk: &Pubkey) -> String {
    TruncatedPubkey::new(&pubkey_hex(*pk)).to_string()
}

fn block_slots(db: &SlashingDb, pk: &Pubkey) -> Vec<u64> {
    db.get_blocks(&hex::encode(pk)).expect("blocks").into_iter().map(|block| block.slot).collect()
}

async fn delete(
    state: Arc<AppState>,
    pubkeys: Vec<String>,
) -> Result<Json<keymanager_api::types::DeleteKeystoresResponse>, ApiError> {
    delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys })).await
}

async fn assert_http_500(err: ApiError, needle: &str) {
    let text = err.to_string();
    assert!(text.contains("signing drain timed out"), "{text}");
    assert!(text.contains("no keystores exported or deleted"), "{text}");
    assert!(text.contains(needle), "{text}");
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    let body = std::str::from_utf8(&bytes).expect("utf8");
    assert!(!body.contains("slashing_protection"), "{body}");
    assert!(body.contains(needle), "{body}");
}

fn assert_disabled(store: &ValidatorStore, pk: &Pubkey) {
    let config = store.get_config(pk).expect("validator stays in the store");
    assert!(!config.enabled, "key stays disabled");
}

fn park_sign(rig: &Rig) -> tokio::task::JoinHandle<Result<crypto::Signature, signer::SignerError>> {
    let signer = Arc::clone(&rig.signer);
    let public = rig.public.clone();
    let fork = rig.fork.clone();
    tokio::spawn(async move { signer.sign_block(&ROOT, SLOT, &public, &fork, &GVR).await })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_timeout_fails_delete_with_no_migration_export() {
    let rig = rig(&[]);
    let sign = park_sign(&rig);
    tokio::time::timeout(Duration::from_secs(2), rig.park.wait_until_holding())
        .await
        .expect("sign must reach the pre-reserve barrier");

    let err = delete(Arc::clone(&rig.state), vec![pubkey_hex(rig.pk)])
        .await
        .expect_err("drain timeout fails the DELETE");
    assert_http_500(err, &truncated(&rig.pk)).await;
    assert_eq!(rig.exports.load(Ordering::SeqCst), 0, "no slashing_protection export");
    assert_eq!(rig.keys.deletes.load(Ordering::SeqCst), 0, "keystore delete must not run");
    assert!(rig.keys.has(&rig.pk), "keystore still present");
    assert_disabled(&rig.store, &rig.pk);
    assert!(rig.registry.contains(&rig.pk), "key stays quiesced");
    assert!(block_slots(&rig.db, &rig.pk).is_empty(), "parked request must not have reserved yet");

    rig.park.release();
    sign.await.expect("sign task").expect("parked request signs after release");
    let stored = rig.db.get_blocks(&hex::encode(rig.pk)).expect("blocks");
    assert_eq!(stored.len(), 1, "the released request reserved a block");
    assert_eq!(stored[0].slot, SLOT);
    let signing_root = stored[0].signing_root.as_ref().expect("signing root").as_hex().to_string();

    let Json(resp) = delete(Arc::clone(&rig.state), vec![pubkey_hex(rig.pk)])
        .await
        .expect("retry drains and exports");
    assert_eq!(rig.exports.load(Ordering::SeqCst), 1, "retry is the first export");
    assert!(!rig.keys.has(&rig.pk), "retry deletes the keystore");
    assert!(
        resp.slashing_protection.contains(&signing_root),
        "retry export must contain the parked signature: {}",
        resp.slashing_protection
    );
    assert!(
        resp.slashing_protection.contains(&format!("\"slot\":\"{SLOT}\"")),
        "retry export must contain the parked block: {}",
        resp.slashing_protection
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_timeout_on_one_key_aborts_the_whole_request() {
    let idle = [0x22u8; 48];
    let rig = rig(&[idle]);
    let sign = park_sign(&rig);
    tokio::time::timeout(Duration::from_secs(2), rig.park.wait_until_holding())
        .await
        .expect("sign must reach the pre-reserve barrier");

    let err = delete(Arc::clone(&rig.state), vec![pubkey_hex(idle), pubkey_hex(rig.pk)])
        .await
        .expect_err("one timed-out key aborts the request");
    assert_http_500(err, &truncated(&rig.pk)).await;
    assert_eq!(rig.exports.load(Ordering::SeqCst), 0, "no partial migration export");
    assert_eq!(rig.keys.deletes.load(Ordering::SeqCst), 0, "neither key is deleted");
    assert!(rig.keys.has(&rig.pk) && rig.keys.has(&idle));
    assert_disabled(&rig.store, &rig.pk);
    assert_disabled(&rig.store, &idle);
    assert!(rig.registry.contains(&rig.pk) && rig.registry.contains(&idle));

    rig.park.release();
    sign.await.expect("sign task").expect("parked request still signs");
}
