//! Handler-level DELETE ordering: disable and quiesce only keys that exist,
//! and a failed delete does not turn the key back on.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use common::MockDoppelgangerMonitor;
use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{delete_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
    KeystoreManager, Pubkey, QuiesceError, RemoteKeyManager, SigningQuiesce, SlashingProtection,
    SlashingProtectionError, ValidatorConfigManager, ValidatorManager,
};
use rvc_keymanager_api::types::{DeleteKeystoresRequest, DeleteStatus};
use rvc_keymanager_api::DoppelgangerLifecycle;

fn pk(id: u8) -> Pubkey {
    let mut bytes = [0u8; 48];
    bytes[0] = id;
    bytes
}

fn hex_pk(id: u8) -> String {
    format!("0x{}", hex::encode(pk(id)))
}

struct Keys {
    present: Vec<Pubkey>,
    fail: Option<Pubkey>,
}

impl KeystoreManager for Keys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.present.clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.present.contains(pubkey)
    }
    fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::InvalidKeystore("unused".into()))
    }
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        if self.fail.as_ref() == Some(pubkey) {
            return Err(DeleteKeystoreError::Io("disk full".into()));
        }
        if self.present.contains(pubkey) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct SpyVm {
    enabled: Mutex<HashMap<Pubkey, bool>>,
    sets: Mutex<Vec<(Pubkey, bool)>>,
}

impl SpyVm {
    fn new() -> Self {
        Self { enabled: Mutex::new(HashMap::new()), sets: Mutex::new(Vec::new()) }
    }
}

impl ValidatorManager for SpyVm {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        self.enabled.lock().expect("vm").insert(pubkey, enabled);
    }
    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        self.enabled.lock().expect("vm").remove(pubkey).is_some()
    }
    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        self.sets.lock().expect("sets").push((*pubkey, enabled));
        if let Some(slot) = self.enabled.lock().expect("vm").get_mut(pubkey) {
            *slot = enabled;
        }
    }
}

struct SpyQuiesce {
    calls: Mutex<Vec<Pubkey>>,
}

impl SpyQuiesce {
    fn new() -> Self {
        Self { calls: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl SigningQuiesce for SpyQuiesce {
    async fn quiesce(&self, pubkey: &Pubkey, _: Duration) -> Result<(), QuiesceError> {
        self.calls.lock().expect("quiesce").push(*pubkey);
        Ok(())
    }
}

struct OkSlash {
    exported: Mutex<Vec<Vec<Pubkey>>>,
}

impl SlashingProtection for OkSlash {
    fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        self.exported.lock().expect("export").push(pubkeys.to_vec());
        Ok("{}".into())
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

fn state_for(
    keys: Arc<Keys>,
    vm: Arc<SpyVm>,
    quiesce: Arc<SpyQuiesce>,
    slash: Arc<OkSlash>,
) -> Arc<AppState> {
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    Arc::new(AppState {
        keystore_manager: keys,
        slashing_protection: slash,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::from_secs(3600),
                Arc::new(MockDoppelgangerMonitor::new()),
                Arc::clone(&vm_dyn),
            )
            .with_signing_quiesce(quiesce, Duration::from_secs(1)),
        ),
        validator_manager: vm_dyn,
        remote_key_manager: Arc::new(NoopRemote),
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    })
}

#[tokio::test]
async fn a_failed_delete_leaves_the_key_disabled_and_quiesced() {
    let key = pk(7);
    let vm = Arc::new(SpyVm::new());
    vm.add_validator(key, true);
    let quiesce = Arc::new(SpyQuiesce::new());
    let keys = Arc::new(Keys { present: vec![key], fail: Some(key) });
    let slash = Arc::new(OkSlash { exported: Mutex::new(Vec::new()) });
    let state = state_for(keys, Arc::clone(&vm), Arc::clone(&quiesce), slash);

    let Json(resp) =
        delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(7)] }))
            .await
            .expect("item error stays inside the response");

    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::Error);
    assert!(!resp.data[0].message.is_empty(), "the response reports the failed delete");
    assert!(vm.enabled.lock().expect("vm").get(&key) == Some(&false), "stays disabled");
    assert!(vm.enabled.lock().expect("vm").contains_key(&key), "not removed");
    assert!(
        vm.sets.lock().expect("sets").iter().all(|(_, on)| !*on),
        "never auto re-enable: {:?}",
        vm.sets.lock().expect("sets")
    );
    assert_eq!(quiesce.calls.lock().expect("quiesce").as_slice(), &[key]);
}

#[tokio::test]
async fn delete_quiesces_only_the_keys_that_exist() {
    let existing = pk(3);
    let unknown = pk(9);
    let vm = Arc::new(SpyVm::new());
    vm.add_validator(existing, true);
    let quiesce = Arc::new(SpyQuiesce::new());
    let keys = Arc::new(Keys { present: vec![existing], fail: None });
    let slash = Arc::new(OkSlash { exported: Mutex::new(Vec::new()) });
    let state =
        state_for(Arc::clone(&keys), Arc::clone(&vm), Arc::clone(&quiesce), Arc::clone(&slash));

    let Json(resp) = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(3), hex_pk(9), "not-a-pubkey".into()] }),
    )
    .await
    .expect("mixed delete succeeds");

    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert_eq!(resp.data[1].status, DeleteStatus::NotFound);
    assert_eq!(resp.data[2].status, DeleteStatus::Error);
    assert_eq!(quiesce.calls.lock().expect("quiesce").as_slice(), &[existing]);
    assert_eq!(vm.sets.lock().expect("sets").as_slice(), &[(existing, false)]);
    assert!(!quiesce.calls.lock().expect("quiesce").contains(&unknown));
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![existing]]);
}

struct LiveKeys {
    present: Mutex<Vec<Pubkey>>,
    deleted: Mutex<Vec<Pubkey>>,
}

impl KeystoreManager for LiveKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.present.lock().expect("present").clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.present.lock().expect("present").contains(pubkey)
    }
    fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::InvalidKeystore("unused".into()))
    }
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut present = self.present.lock().expect("present");
        if let Some(i) = present.iter().position(|pk| pk == pubkey) {
            present.remove(i);
            self.deleted.lock().expect("deleted").push(*pubkey);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Admits `late` the first time a drain runs, after membership was snapshotted.
struct AdmitDuringDrain {
    keys: Arc<LiveKeys>,
    late: Pubkey,
    calls: Mutex<Vec<Pubkey>>,
}

#[async_trait]
impl SigningQuiesce for AdmitDuringDrain {
    async fn quiesce(&self, pubkey: &Pubkey, _: Duration) -> Result<(), QuiesceError> {
        self.calls.lock().expect("calls").push(*pubkey);
        let mut present = self.keys.present.lock().expect("present");
        if !present.contains(&self.late) {
            present.push(self.late);
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_key_admitted_during_drain_is_not_deleted_or_exported() {
    let existing = pk(4);
    let late = pk(5);
    let keys =
        Arc::new(LiveKeys { present: Mutex::new(vec![existing]), deleted: Mutex::new(Vec::new()) });
    let quiesce =
        Arc::new(AdmitDuringDrain { keys: Arc::clone(&keys), late, calls: Mutex::new(Vec::new()) });
    let vm = Arc::new(SpyVm::new());
    vm.add_validator(existing, true);
    let slash = Arc::new(OkSlash { exported: Mutex::new(Vec::new()) });
    let vm_owned = Arc::clone(&vm);
    let vm_dyn: Arc<dyn ValidatorManager> = vm_owned;
    let quiesce_owned = Arc::clone(&quiesce);
    let quiesce_dyn: Arc<dyn SigningQuiesce> = quiesce_owned;
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&keys) as Arc<dyn KeystoreManager>,
        slashing_protection: Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::from_secs(3600),
                Arc::new(MockDoppelgangerMonitor::new()),
                Arc::clone(&vm_dyn),
            )
            .with_signing_quiesce(quiesce_dyn, Duration::from_secs(1)),
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

    let Json(resp) = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(4), hex_pk(5)] }),
    )
    .await
    .expect("late member is an item error, not a failed request");

    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert_eq!(resp.data[1].status, DeleteStatus::Error);
    assert!(
        resp.data[1].message.contains("not deleted"),
        "response must say the late key was not deleted: {}",
        resp.data[1].message
    );
    assert_eq!(keys.deleted.lock().expect("deleted").as_slice(), &[existing]);
    assert!(keys.has_key(&late), "late key stays in the keystore");
    assert!(!keys.has_key(&existing));
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![existing]]);
    assert!(
        !resp.slashing_protection.contains(&hex_pk(5)),
        "export must omit the key admitted during the drain: {}",
        resp.slashing_protection
    );
    assert_eq!(quiesce.calls.lock().expect("calls").as_slice(), &[existing]);
}
