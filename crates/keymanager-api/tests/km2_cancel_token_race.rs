//! KM-2 — doppelganger cancel-token race regression tests.
//!
//! RF5-26: the KM-2 invariant lives in [`DoppelgangerLifecycle`].  Most cases
//! drive the component directly (no HTTP stack).  One end-to-end HTTP test
//! remains so wiring through `import_keystores` / `delete_keystores` stays
//! covered.
//!
//! Criteria:
//!   (a) every import insert cancels the displaced token;
//!   (b) delete's remove_op AND token-removal/cancel are one critical section;
//!   (c) the window-elapsed branch prunes its OWN cancel-token entry;
//!   (d) concurrent delete+re-import leaves no stale enable task (HTTP e2e).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{delete_keystores, import_keystores, AppState};
use rvc_keymanager_api::lifecycle::{DoppelgangerLifecycle, ImportKind};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    SlashingProtectionError, ValidatorConfigManager, ValidatorManager,
};

// ── Mocks ─────────────────────────────────────────────────────────────────────

struct SpyValidatorManager {
    state: Mutex<HashMap<Pubkey, bool>>,
}

impl SpyValidatorManager {
    fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }

    fn is_enabled(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().get(pubkey).copied().unwrap_or(false)
    }

    fn is_tracked(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().contains_key(pubkey)
    }
}

impl ValidatorManager for SpyValidatorManager {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        self.state.lock().unwrap().insert(pubkey, enabled);
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().remove(pubkey).is_some()
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        if let Some(v) = self.state.lock().unwrap().get_mut(pubkey) {
            *v = enabled;
        }
    }
}

/// Doppelganger monitor that can park delete at `cancel_monitoring` /
/// `stop_monitoring` so HTTP race tests can interleave re-import.
struct GatedDoppelgangerMonitor {
    inner: common::PendingSetMonitor,
    start_signaled: Mutex<Option<mpsc::Sender<()>>>,
    stop_arrived: Mutex<Option<mpsc::Sender<()>>>,
    stop_release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl GatedDoppelgangerMonitor {
    fn new(_window: Duration) -> Self {
        Self {
            inner: common::PendingSetMonitor::new(),
            start_signaled: Mutex::new(None),
            stop_arrived: Mutex::new(None),
            stop_release: Mutex::new(None),
        }
    }

    fn ungated(window: Duration) -> Self {
        Self::new(window)
    }
}

impl DoppelgangerMonitor for GatedDoppelgangerMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        self.inner.start_monitoring(pubkey);
        if let Some(tx) = self.start_signaled.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        if let Some(tx) = self.stop_arrived.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.stop_release.lock().unwrap().take() {
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
        self.inner.stop_monitoring(pubkey);
    }

    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        self.inner.is_doppelganger_safe(pubkey)
    }
}

struct GatedKeystoreManager {
    keys: Mutex<Vec<Pubkey>>,
    keystore_removed: Mutex<Option<mpsc::Sender<()>>>,
    import_waits_for_delete: bool,
}

#[async_trait]
impl KeystoreManager for GatedKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().unwrap().clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().unwrap().contains(pubkey)
    }

    async fn import_keystore(
        &self,
        keystore_json: &str,
        _password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let v: serde_json::Value = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        let hex = v["pubkey"]
            .as_str()
            .ok_or_else(|| ImportKeystoreError::InvalidKeystore("missing pubkey".into()))?;
        let bytes =
            hex::decode(hex).map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        if bytes.len() != 48 {
            return Err(ImportKeystoreError::InvalidKeystore("pubkey must be 48 bytes".into()));
        }
        let mut pk = [0u8; 48];
        pk.copy_from_slice(&bytes);

        if self.import_waits_for_delete {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while self.keys.lock().unwrap().contains(&pk) {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let mut keys = self.keys.lock().unwrap();
        if keys.contains(&pk) {
            return Err(ImportKeystoreError::Duplicate);
        }
        keys.push(pk);
        Ok(pk)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let removed = {
            let mut keys = self.keys.lock().unwrap();
            if let Some(pos) = keys.iter().position(|k| k == pubkey) {
                keys.remove(pos);
                true
            } else {
                false
            }
        };
        if removed {
            if let Some(tx) = self.keystore_removed.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
        Ok(removed)
    }
}

struct NoopSlashingProtection;
#[async_trait]
impl SlashingProtection for NoopSlashingProtection {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Ok(String::new())
    }
}

struct NoopRemoteKeyManager;
impl RemoteKeyManager for NoopRemoteKeyManager {
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

struct NoopConfigManager;
impl ValidatorConfigManager for NoopConfigManager {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_pubkey() -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = 0x42;
    pk
}

fn keystore_json_for(pubkey: &Pubkey) -> String {
    serde_json::json!({ "pubkey": hex::encode(pubkey) }).to_string()
}

fn import_body(pubkey: &Pubkey) -> rvc_keymanager_api::types::ImportKeystoresRequest {
    serde_json::from_value(serde_json::json!({
        "keystores": [keystore_json_for(pubkey)],
        "passwords": ["test_password"],
    }))
    .unwrap()
}

fn delete_body(pubkey: &Pubkey) -> rvc_keymanager_api::types::DeleteKeystoresRequest {
    serde_json::from_value(serde_json::json!({
        "pubkeys": [format!("0x{}", hex::encode(pubkey))],
    }))
    .unwrap()
}

fn make_lifecycle(
    window: Duration,
    vm: Arc<SpyValidatorManager>,
    monitor: Arc<dyn DoppelgangerMonitor>,
) -> Arc<DoppelgangerLifecycle> {
    Arc::new(DoppelgangerLifecycle::new(window, monitor, vm as Arc<dyn ValidatorManager>))
}

fn make_state(
    keystore_manager: Arc<dyn KeystoreManager>,
    validator_manager: Arc<dyn ValidatorManager>,
    monitor: Arc<dyn DoppelgangerMonitor>,
    window: Duration,
) -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager,
        slashing_protection: Arc::new(NoopSlashingProtection),
        validator_manager: Arc::clone(&validator_manager),
        doppelganger: Arc::new(DoppelgangerLifecycle::new(
            window,
            monitor,
            Arc::clone(&validator_manager),
        )),
        remote_key_manager: Arc::new(NoopRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

// ── Component-level KM-2 tests ────────────────────────────────────────────────

/// PRD §KM-2 (a): re-import cancels the displaced cancel token.
#[tokio::test]
async fn km2_insert_cancels_displaced_token() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(3600);
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let life = make_lifecycle(window, vm, monitor);

    life.on_import(pubkey, ImportKind::Local);
    let t1 = life.current_cancel_token(&pubkey).expect("T1 registered after import #1");
    assert!(!t1.is_cancelled());

    life.on_import(pubkey, ImportKind::Local);
    let t2 = life.current_cancel_token(&pubkey).expect("T2 registered after re-import");
    assert!(!t2.is_cancelled());
    assert!(t1.is_cancelled(), "PRD §KM-2 (a): inserting T2 must cancel the displaced token T1",);
}

/// PRD §KM-2 (c): window-elapsed branch prunes its own cancel-token entry.
#[tokio::test(start_paused = true)]
async fn km2_window_elapsed_prunes_own_cancel_token() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(60);
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let life = make_lifecycle(window, vm.clone(), monitor);

    life.on_import(pubkey, ImportKind::Local);
    assert!(life.current_cancel_token(&pubkey).is_some());
    assert!(!vm.is_enabled(&pubkey));

    tokio::time::advance(window + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    assert!(vm.is_enabled(&pubkey), "validator enabled after window elapses");
    assert!(
        life.current_cancel_token(&pubkey).is_none(),
        "PRD §KM-2 (c): enable task must prune its own cancel-token entry",
    );
}

/// Finding 4: stale timer must not enable a displaced key (component-level).
#[tokio::test(start_paused = true)]
async fn km2_stale_timer_cannot_enable_after_displacement() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(60);
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let life = make_lifecycle(window, vm.clone(), monitor.clone());

    life.on_import(pubkey, ImportKind::Local);
    assert!(!vm.is_enabled(&pubkey));
    assert!(!monitor.is_doppelganger_safe(&pubkey));

    tokio::time::advance(window + Duration::from_secs(1)).await;

    life.on_delete(&pubkey, ImportKind::Local, || (true, ()));
    life.on_import(pubkey, ImportKind::Local);
    assert!(!vm.is_enabled(&pubkey));
    assert!(!monitor.is_doppelganger_safe(&pubkey));

    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    assert!(!vm.is_enabled(&pubkey), "Finding 1: stale task must not enable a displaced key",);
    assert!(
        !monitor.is_doppelganger_safe(&pubkey),
        "Finding 2: stale task must not stop_monitoring a fresh window",
    );
}

/// Remote import shares the lifecycle path (cancel token + monitoring).
#[tokio::test]
async fn km2_remote_import_registers_lifecycle_like_local() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(3600);
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let life = make_lifecycle(window, vm.clone(), monitor.clone());

    life.on_import(pubkey, ImportKind::Remote);

    assert!(!vm.is_tracked(&pubkey), "remote import does not touch ValidatorManager");
    assert!(!monitor.is_doppelganger_safe(&pubkey));
    assert!(
        life.current_cancel_token(&pubkey).is_some(),
        "remote import must register a cancel token",
    );

    let t1 = life.current_cancel_token(&pubkey).unwrap();
    life.on_import(pubkey, ImportKind::Remote);
    assert!(t1.is_cancelled(), "remote re-import displaces like local");
}

// ── HTTP end-to-end wiring test ───────────────────────────────────────────────

/// PRD §KM-2 (b)+(d): concurrent delete + re-import via HTTP handlers.
///
/// Keeps one full-stack test so handler → lifecycle wiring stays covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn km2_http_concurrent_delete_reimport_no_stale_enable() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(3600);

    let keystore = Arc::new(GatedKeystoreManager {
        keys: Mutex::new(vec![]),
        keystore_removed: Mutex::new(None),
        import_waits_for_delete: true,
    });
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::new(window));

    let state = make_state(
        keystore.clone(),
        vm.clone() as Arc<dyn ValidatorManager>,
        monitor.clone(),
        window,
    );

    let _ = import_keystores(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        axum::Json(import_body(&pubkey)),
    )
    .await
    .expect("import #1");
    let t1 =
        state.doppelganger.current_cancel_token(&pubkey).expect("T1 registered after import #1");
    assert!(!t1.is_cancelled());

    let (removed_tx, removed_rx) = mpsc::channel::<()>();
    *keystore.keystore_removed.lock().unwrap() = Some(removed_tx);
    let (arrived_tx, arrived_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    *monitor.stop_arrived.lock().unwrap() = Some(arrived_tx);
    *monitor.stop_release.lock().unwrap() = Some(release_rx);
    *monitor.start_signaled.lock().unwrap() = Some(started_tx);

    let state_del = state.clone();
    let delete_task = tokio::spawn(async move {
        delete_keystores(axum::extract::State(state_del), axum::Json(delete_body(&pubkey)))
            .await
            .map(|_| ())
    });

    let gate = tokio::task::spawn_blocking(move || {
        let removed = removed_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let arrived = arrived_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        (removed, arrived)
    })
    .await
    .unwrap();
    assert!(gate.0, "delete removed the keystore entry");
    assert!(gate.1, "delete parked at cancel_monitoring under the lifecycle lock");

    let state_imp = state.clone();
    let reimport_task = tokio::spawn(async move {
        import_keystores(
            axum::extract::State(state_imp),
            axum::http::HeaderMap::new(),
            axum::Json(import_body(&pubkey)),
        )
        .await
        .map(|_| ())
    });

    tokio::task::spawn_blocking(move || {
        let _ = started_rx.recv_timeout(Duration::from_secs(1));
    })
    .await
    .unwrap();
    let _ = release_tx.send(());

    let _ = delete_task.await.unwrap();
    let _ = reimport_task.await.unwrap();

    assert!(keystore.has_key(&pubkey), "key present after re-import");
    assert!(vm.is_tracked(&pubkey), "re-imported validator is tracked");

    assert!(
        t1.is_cancelled(),
        "PRD §KM-2 (i): token displaced during concurrent delete+re-import must be cancelled",
    );

    let surviving =
        state.doppelganger.current_cancel_token(&pubkey).expect("a fresh token survives the race");
    assert!(
        !surviving.is_cancelled(),
        "PRD §KM-2 (ii): the surviving enable task must be the NEW one",
    );

    assert!(
        !vm.is_enabled(&pubkey),
        "PRD §KM-2 (iii): re-imported key must remain disabled inside the fresh window",
    );
}
