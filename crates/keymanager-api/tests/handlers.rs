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
    DeleteKeystoreError, DeleteRemoteKeyError, ExportedInterchange, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, QuiesceError, RemoteKeyManager, SigningQuiesce,
    SlashingProtection, SlashingProtectionError, ValidatorConfigManager, ValidatorManager,
};
use rvc_keymanager_api::types::{DeleteKeystoresRequest, DeleteStatus};
use rvc_keymanager_api::DoppelgangerLifecycle;
use rvc_keymanager_api::ImportKind;

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

#[async_trait]
impl KeystoreManager for Keys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.present.clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.present.contains(pubkey)
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
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
    removes: Mutex<Vec<Pubkey>>,
}

impl SpyVm {
    fn new() -> Self {
        Self {
            enabled: Mutex::new(HashMap::new()),
            sets: Mutex::new(Vec::new()),
            removes: Mutex::new(Vec::new()),
        }
    }
}

impl ValidatorManager for SpyVm {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
        self.enabled.lock().expect("vm").insert(pubkey, enabled);
        Ok(())
    }
    fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
        self.removes.lock().expect("removes").push(*pubkey);
        Ok(self.enabled.lock().expect("vm").remove(pubkey).is_some())
    }
    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
        self.sets.lock().expect("sets").push((*pubkey, enabled));
        if let Some(slot) = self.enabled.lock().expect("vm").get_mut(pubkey) {
            *slot = enabled;
        }
        Ok(())
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

#[async_trait]
impl SlashingProtection for OkSlash {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    async fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<ExportedInterchange, SlashingProtectionError> {
        self.exported.lock().expect("export").push(pubkeys.to_vec());
        Ok(ExportedInterchange { json: "{}".into(), with_history: Vec::new() })
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
    vm.add_validator(key, true).unwrap();
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
    vm.add_validator(existing, true).unwrap();
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
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![existing, unknown]]);
}

struct LiveKeys {
    present: Mutex<Vec<Pubkey>>,
    deleted: Mutex<Vec<Pubkey>>,
}

#[async_trait]
impl KeystoreManager for LiveKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.present.lock().expect("present").clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.present.lock().expect("present").contains(pubkey)
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
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
    vm.add_validator(existing, true).unwrap();
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

const CONFIGURED_GVR: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

struct ConfiguredSlash {
    exported: Mutex<Vec<Vec<Pubkey>>>,
}

#[async_trait]
impl SlashingProtection for ConfiguredSlash {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }

    async fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<ExportedInterchange, SlashingProtectionError> {
        self.exported.lock().expect("export").push(pubkeys.to_vec());
        let data: Vec<serde_json::Value> = pubkeys
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": []
                })
            })
            .collect();
        Ok(ExportedInterchange {
            json: serde_json::json!({
                "metadata": {
                    "interchange_format_version": "5",
                    "genesis_validators_root": CONFIGURED_GVR
                },
                "data": data
            })
            .to_string(),
            with_history: Vec::new(),
        })
    }
}

fn state_with_slash(
    keys: Arc<Keys>,
    vm: Arc<SpyVm>,
    quiesce: Arc<SpyQuiesce>,
    slash: Arc<dyn SlashingProtection>,
    remote: Arc<dyn RemoteKeyManager>,
) -> Arc<AppState> {
    let vm_dyn: Arc<dyn ValidatorManager> = Arc::clone(&vm) as _;
    let quiesce_dyn: Arc<dyn SigningQuiesce> = Arc::clone(&quiesce) as _;
    Arc::new(AppState {
        keystore_manager: keys,
        slashing_protection: slash,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::from_secs(3600),
                Arc::new(MockDoppelgangerMonitor::new()),
                Arc::clone(&vm_dyn),
            )
            .with_signing_quiesce(quiesce_dyn, Duration::from_secs(1)),
        ),
        validator_manager: vm_dyn,
        remote_key_manager: remote,
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    })
}

#[tokio::test]
async fn delete_unknown_key_is_not_found_with_an_empty_record_under_the_real_gvr() {
    let first = pk(11);
    let second = pk(12);
    let vm = Arc::new(SpyVm::new());
    let quiesce = Arc::new(SpyQuiesce::new());
    let keys = Arc::new(Keys { present: Vec::new(), fail: None });
    let slash = Arc::new(ConfiguredSlash { exported: Mutex::new(Vec::new()) });
    let state = state_with_slash(
        keys,
        vm,
        Arc::clone(&quiesce),
        Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        Arc::new(NoopRemote),
    );

    let Json(resp) = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(11), hex_pk(12)] }),
    )
    .await
    .expect("unknown keys stay inside the response");

    assert_eq!(resp.data[0].status, DeleteStatus::NotFound);
    assert_eq!(resp.data[1].status, DeleteStatus::NotFound);
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![first, second]]);
    let json: serde_json::Value = serde_json::from_str(&resp.slashing_protection).expect("json");
    assert_eq!(json["metadata"]["genesis_validators_root"], CONFIGURED_GVR);
    let data = json["data"].as_array().expect("data");
    assert_eq!(data.len(), 2);
    assert!(data.iter().all(|row| {
        row["signed_attestations"].as_array().expect("atts").is_empty()
            && row["signed_blocks"].as_array().expect("blocks").is_empty()
    }));
    assert!(quiesce.calls.lock().expect("quiesce").is_empty());
}

struct RemoteSet {
    keys: Mutex<Vec<Pubkey>>,
}

impl RemoteKeyManager for RemoteSet {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.keys
            .lock()
            .expect("remote")
            .iter()
            .map(|pk| (*pk, "https://signer.example".into()))
            .collect()
    }
    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().expect("remote").contains(pubkey)
    }
    fn import_remote_key(&self, pubkey: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        self.keys.lock().expect("remote").push(pubkey);
        Ok(())
    }
    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.keys.lock().expect("remote");
        if let Some(index) = keys.iter().position(|pk| pk == pubkey) {
            keys.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct DiskKeys {
    present: Mutex<Vec<Pubkey>>,
    deletes: Mutex<Vec<Pubkey>>,
    denylist: Mutex<Vec<Pubkey>>,
    dir: std::path::PathBuf,
}

impl DiskKeys {
    fn bundle_names(pubkey: &Pubkey) -> (String, String) {
        let hex_key = hex::encode(pubkey);
        (format!("0x{hex_key}.json"), format!("0x{hex_key}.secret"))
    }

    fn write_bundle(&self, pubkey: &Pubkey) {
        let (keystore, secret) = Self::bundle_names(pubkey);
        std::fs::write(self.dir.join(keystore), b"{}").expect("keystore");
        std::fs::write(self.dir.join(secret), b"secret-material").expect("secret");
    }
}

#[async_trait]
impl KeystoreManager for DiskKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.present.lock().expect("present").clone()
    }
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.present.lock().expect("present").contains(pubkey)
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::InvalidKeystore("unused".into()))
    }
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        self.deletes.lock().expect("deletes").push(*pubkey);
        self.denylist.lock().expect("denylist").push(*pubkey);
        let (keystore, secret) = Self::bundle_names(pubkey);
        let _ = std::fs::remove_file(self.dir.join(keystore));
        let _ = std::fs::remove_file(self.dir.join(secret));
        let mut present = self.present.lock().expect("present");
        if let Some(index) = present.iter().position(|pk| pk == pubkey) {
            present.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn listed_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn delete_of_a_remote_only_key_is_an_error_and_touches_nothing() {
    let remote_pk = pk(21);
    let dir = tempfile::tempdir().expect("dir");
    let disk = Arc::new(DiskKeys {
        present: Mutex::new(Vec::new()),
        deletes: Mutex::new(Vec::new()),
        denylist: Mutex::new(Vec::new()),
        dir: dir.path().to_path_buf(),
    });
    disk.write_bundle(&remote_pk);
    let before = listed_names(dir.path());
    let remote = Arc::new(RemoteSet { keys: Mutex::new(vec![remote_pk]) });
    let vm = Arc::new(SpyVm::new());
    let quiesce = Arc::new(SpyQuiesce::new());
    let monitor = Arc::new(MockDoppelgangerMonitor::new());
    let slash = Arc::new(ConfiguredSlash { exported: Mutex::new(Vec::new()) });
    let vm_dyn: Arc<dyn ValidatorManager> = Arc::clone(&vm) as _;
    let quiesce_dyn: Arc<dyn SigningQuiesce> = Arc::clone(&quiesce) as _;
    let doppelganger = Arc::new(
        DoppelgangerLifecycle::new(
            Duration::from_secs(3600),
            Arc::clone(&monitor) as _,
            Arc::clone(&vm_dyn),
        )
        .with_signing_quiesce(quiesce_dyn, Duration::from_secs(1)),
    );
    doppelganger.on_import(remote_pk, ImportKind::Remote).expect("remote import");
    let token = doppelganger.current_cancel_token(&remote_pk).expect("enable token");
    assert!(!token.is_cancelled());
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&disk) as Arc<dyn KeystoreManager>,
        slashing_protection: Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        doppelganger: Arc::clone(&doppelganger),
        validator_manager: vm_dyn,
        remote_key_manager: Arc::clone(&remote) as Arc<dyn RemoteKeyManager>,
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    });

    let Json(resp) =
        delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(21)] }))
            .await
            .expect("remote-only refusal is an item error");

    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::Error);
    assert_eq!(
        resp.data[0].message,
        "registered as a remote key; delete it through /eth/v1/remotekeys"
    );
    assert!(disk.deletes.lock().expect("deletes").is_empty(), "delete_keystore is not called");
    assert!(disk.denylist.lock().expect("denylist").is_empty(), "no denylist write");
    assert_eq!(listed_names(dir.path()), before, "files are unchanged");
    let still = doppelganger.current_cancel_token(&remote_pk).expect("token stays");
    assert!(!still.is_cancelled());
    assert!(monitor.monitored.lock().contains(&remote_pk), "cancel_monitoring is not called");
    assert!(vm.removes.lock().expect("removes").is_empty(), "on_delete is not called");
    assert!(quiesce.calls.lock().expect("quiesce").is_empty());
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[Vec::<Pubkey>::new()]);
    assert!(
        !resp.slashing_protection.contains(&hex_pk(21)),
        "the export omits the remote key: {}",
        resp.slashing_protection
    );
    assert!(remote.has_remote_key(&remote_pk));
    let json: serde_json::Value = serde_json::from_str(&resp.slashing_protection).expect("json");
    assert_eq!(json["metadata"]["genesis_validators_root"], CONFIGURED_GVR);
}

#[tokio::test]
async fn delete_of_a_key_loaded_locally_and_remotely_is_deleted() {
    let both = pk(22);
    let vm = Arc::new(SpyVm::new());
    vm.add_validator(both, true).unwrap();
    let quiesce = Arc::new(SpyQuiesce::new());
    let keys = Arc::new(Keys { present: vec![both], fail: None });
    let remote = Arc::new(RemoteSet { keys: Mutex::new(vec![both]) });
    let slash = Arc::new(ConfiguredSlash { exported: Mutex::new(Vec::new()) });
    let state = state_with_slash(
        keys,
        Arc::clone(&vm),
        Arc::clone(&quiesce),
        Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        Arc::clone(&remote) as Arc<dyn RemoteKeyManager>,
    );

    let Json(resp) =
        delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(22)] }))
            .await
            .expect("local half deletes");

    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![both]]);
    assert!(remote.has_remote_key(&both), "the remote registration is not this endpoint's job");
    assert_eq!(vm.removes.lock().expect("removes").as_slice(), &[both]);
    assert_eq!(quiesce.calls.lock().expect("quiesce").as_slice(), &[both]);
}

/// Export double that drops a remote registration while the interchange is built.
struct ExportDropsRemote {
    exported: Mutex<Vec<Vec<Pubkey>>>,
    remote: Arc<RemoteSet>,
    key: Pubkey,
}

#[async_trait]
impl SlashingProtection for ExportDropsRemote {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }

    async fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<ExportedInterchange, SlashingProtectionError> {
        self.exported.lock().expect("export").push(pubkeys.to_vec());
        let _ = self.remote.delete_remote_key(&self.key);
        let data: Vec<serde_json::Value> = pubkeys
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": []
                })
            })
            .collect();
        Ok(ExportedInterchange {
            json: serde_json::json!({
                "metadata": {
                    "interchange_format_version": "5",
                    "genesis_validators_root": CONFIGURED_GVR
                },
                "data": data
            })
            .to_string(),
            with_history: Vec::new(),
        })
    }
}

fn disk_state(
    disk: Arc<DiskKeys>,
    vm: Arc<SpyVm>,
    quiesce: Arc<SpyQuiesce>,
    slash: Arc<dyn SlashingProtection>,
    remote: Arc<dyn RemoteKeyManager>,
) -> Arc<AppState> {
    let vm_dyn: Arc<dyn ValidatorManager> = Arc::clone(&vm) as _;
    let quiesce_dyn: Arc<dyn SigningQuiesce> = Arc::clone(&quiesce) as _;
    Arc::new(AppState {
        keystore_manager: disk,
        slashing_protection: slash,
        doppelganger: Arc::new(
            DoppelgangerLifecycle::new(
                Duration::from_secs(3600),
                Arc::new(MockDoppelgangerMonitor::new()),
                Arc::clone(&vm_dyn),
            )
            .with_signing_quiesce(quiesce_dyn, Duration::from_secs(1)),
        ),
        validator_manager: vm_dyn,
        remote_key_manager: remote,
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    })
}

#[tokio::test]
async fn harper_probe_c1_key_excluded_from_export_is_not_deleted() {
    let key = pk(31);
    let dir = tempfile::tempdir().expect("dir");
    let disk = Arc::new(DiskKeys {
        present: Mutex::new(Vec::new()),
        deletes: Mutex::new(Vec::new()),
        denylist: Mutex::new(Vec::new()),
        dir: dir.path().to_path_buf(),
    });
    disk.write_bundle(&key);
    let before = listed_names(dir.path());
    let remote = Arc::new(RemoteSet { keys: Mutex::new(vec![key]) });
    let slash = Arc::new(ExportDropsRemote {
        exported: Mutex::new(Vec::new()),
        remote: Arc::clone(&remote),
        key,
    });
    let vm = Arc::new(SpyVm::new());
    let quiesce = Arc::new(SpyQuiesce::new());
    let state = disk_state(
        Arc::clone(&disk),
        Arc::clone(&vm),
        quiesce,
        Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        Arc::clone(&remote) as Arc<dyn RemoteKeyManager>,
    );

    let Json(resp) =
        delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(31)] }))
            .await
            .expect("an unexported key is an item error");

    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[Vec::<Pubkey>::new()]);
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::Error);
    assert_eq!(resp.data[0].message, "not in the slashing-protection export; not deleted");
    assert!(disk.deletes.lock().expect("deletes").is_empty(), "delete_keystore is not called");
    assert!(disk.denylist.lock().expect("denylist").is_empty(), "no denylist write");
    assert_eq!(listed_names(dir.path()), before, "files stay in place");
    assert!(vm.removes.lock().expect("removes").is_empty(), "on_delete is not called");
    assert!(!remote.has_remote_key(&key), "the concurrent remote delete already dropped it");
    assert!(
        !resp.slashing_protection.contains(&hex_pk(31)),
        "the export has no record for the key: {}",
        resp.slashing_protection
    );
}

struct HistorySlash {
    exported: Mutex<Vec<Vec<Pubkey>>>,
    history: Vec<Pubkey>,
}

#[async_trait]
impl SlashingProtection for HistorySlash {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }

    async fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<ExportedInterchange, SlashingProtectionError> {
        self.exported.lock().expect("export").push(pubkeys.to_vec());
        let data: Vec<serde_json::Value> = pubkeys
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": []
                })
            })
            .collect();
        Ok(ExportedInterchange {
            json: serde_json::json!({
                "metadata": {
                    "interchange_format_version": "5",
                    "genesis_validators_root": CONFIGURED_GVR
                },
                "data": data
            })
            .to_string(),
            with_history: self.history.clone(),
        })
    }
}

#[tokio::test]
async fn delete_of_a_duplicated_local_and_remote_key_refuses_the_second_entry() {
    let both = pk(32);
    let dir = tempfile::tempdir().expect("dir");
    let disk = Arc::new(DiskKeys {
        present: Mutex::new(vec![both]),
        deletes: Mutex::new(Vec::new()),
        denylist: Mutex::new(Vec::new()),
        dir: dir.path().to_path_buf(),
    });
    let remote = Arc::new(RemoteSet { keys: Mutex::new(vec![both]) });
    let vm = Arc::new(SpyVm::new());
    vm.add_validator(both, true).unwrap();
    let quiesce = Arc::new(SpyQuiesce::new());
    let slash = Arc::new(HistorySlash { exported: Mutex::new(Vec::new()), history: vec![both] });
    let state = disk_state(
        Arc::clone(&disk),
        Arc::clone(&vm),
        Arc::clone(&quiesce),
        Arc::clone(&slash) as Arc<dyn SlashingProtection>,
        Arc::clone(&remote) as Arc<dyn RemoteKeyManager>,
    );

    let Json(resp) = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![hex_pk(32), hex_pk(32)] }),
    )
    .await
    .expect("duplicate local-and-remote delete");

    assert_eq!(resp.data.len(), 2);
    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert_eq!(resp.data[0].message, "");
    assert_eq!(resp.data[1].status, DeleteStatus::Error);
    assert_eq!(
        resp.data[1].message,
        "registered as a remote key; delete it through /eth/v1/remotekeys"
    );
    assert_eq!(disk.deletes.lock().expect("deletes").as_slice(), &[both]);
    assert_eq!(disk.denylist.lock().expect("denylist").as_slice(), &[both]);
    assert_eq!(vm.removes.lock().expect("removes").as_slice(), &[both]);
    assert!(remote.has_remote_key(&both), "the remote registration stays");
    assert!(!disk.has_key(&both));
    assert_eq!(slash.exported.lock().expect("export").as_slice(), &[vec![both]]);
    assert_eq!(quiesce.calls.lock().expect("quiesce").as_slice(), &[both]);
}
