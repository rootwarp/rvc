//! DELETE-path coverage for synthetic interchange floors (RR-4.3).
//!
//! `delete_keystores` calls [`SlashingProtectionAdapter::export_interchange`]
//! before it touches a keystore. These tests drive that function, and the
//! handler, with a real slashing DB.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use keymanager_api::error::ApiError;
use keymanager_api::handlers::{delete_keystores, AppState};
use keymanager_api::traits::{
    DeleteKeystoreError, DoppelgangerMonitor, ImportKeystoreError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, ValidatorConfigManager, ValidatorManager,
};
use keymanager_api::types::DeleteKeystoresRequest;
use keymanager_api::DoppelgangerLifecycle;
use slashing::SlashingDb;
use validator_store::ValidatorStore;

use super::{pubkey_hex, test_pubkey, SlashingProtectionAdapter, ValidatorManagerAdapter};

const CHAIN_GVR_HEX: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

fn chain_gvr() -> [u8; 32] {
    let bytes = hex::decode(CHAIN_GVR_HEX.strip_prefix("0x").expect("prefix")).expect("hex");
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

struct CountingKeys {
    keys: Mutex<Vec<Pubkey>>,
    deletes: AtomicU32,
}

impl CountingKeys {
    fn with_keys(keys: Vec<Pubkey>) -> Self {
        Self { keys: Mutex::new(keys), deletes: AtomicU32::new(0) }
    }

    fn deletes(&self) -> u32 {
        self.deletes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeystoreManager for CountingKeys {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().expect("keys").clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().expect("keys").contains(pubkey)
    }

    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::Io("unused".into()))
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        let mut keys = self.keys.lock().expect("keys");
        if let Some(index) = keys.iter().position(|key| key == pubkey) {
            keys.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct NoopMonitor;

impl DoppelgangerMonitor for NoopMonitor {
    fn start_monitoring(&self, _: Pubkey) {}
    fn stop_monitoring(&self, _: &Pubkey) {}
    fn is_doppelganger_safe(&self, _: &Pubkey) -> bool {
        true
    }
}

struct NoopRemote;

impl RemoteKeyManager for NoopRemote {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        Vec::new()
    }

    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }

    fn import_remote_key(
        &self,
        _: Pubkey,
        _: String,
    ) -> Result<(), keymanager_api::traits::ImportRemoteKeyError> {
        Ok(())
    }

    fn delete_remote_key(
        &self,
        _: &Pubkey,
    ) -> Result<bool, keymanager_api::traits::DeleteRemoteKeyError> {
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

fn app_state(
    keys: Arc<CountingKeys>,
    slashing: Arc<dyn SlashingProtection>,
    validator_manager: Arc<dyn ValidatorManager>,
) -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager: keys,
        slashing_protection: slashing,
        doppelganger: Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            Arc::new(NoopMonitor),
            Arc::clone(&validator_manager),
        )),
        validator_manager,
        remote_key_manager: Arc::new(NoopRemote),
        config_manager: Arc::new(NoopConfig),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    })
}

#[test]
fn a_pruned_key_delete_exports_a_floor_not_an_empty_record() {
    let pruned = test_pubkey(1);
    let unknown = test_pubkey(2);
    let pruned_hex = pubkey_hex(pruned);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&pruned_hex, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(&pruned_hex, 1, 11).expect("watermark");
    db.prune_below_watermarks().expect("prune");
    assert_eq!(db.get_attestation_watermark(&pruned_hex).expect("wm"), Some((5, 11)));

    let adapter = SlashingProtectionAdapter::new(db, gvr);
    let export = adapter.export_interchange(&[pruned, unknown]).expect("DELETE export");
    let json: serde_json::Value = serde_json::from_str(&export).expect("json");
    let data = json["data"].as_array().expect("data");
    assert_eq!(data.len(), 2, "requested keys are both represented");

    let pruned_record =
        data.iter().find(|record| record["pubkey"] == pruned_hex).expect("pruned key");
    let atts = pruned_record["signed_attestations"].as_array().expect("atts");
    assert_eq!(atts.len(), 1, "watermark-only key is a floor, not an empty record");
    assert_eq!(atts[0]["source_epoch"], "5");
    assert_eq!(atts[0]["target_epoch"], "11");
    assert!(atts[0].get("signing_root").is_none() || atts[0]["signing_root"].is_null());
    assert!(pruned_record["signed_blocks"].as_array().expect("blocks").is_empty());

    let unknown_hex = pubkey_hex(unknown);
    let unknown_record =
        data.iter().find(|record| record["pubkey"] == unknown_hex).expect("unknown key");
    assert!(unknown_record["signed_attestations"].as_array().expect("atts").is_empty());
    assert!(unknown_record["signed_blocks"].as_array().expect("blocks").is_empty());
}

#[tokio::test]
async fn export_fails_closed_delete_aborts_and_key_stays_disabled() {
    let bad = test_pubkey(7);
    let good = test_pubkey(8);
    let bad_hex = pubkey_hex(bad);
    let good_hex = pubkey_hex(good);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&bad_hex, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(&bad_hex, 20, 11).expect("unrepresentable");
    db.seed_attestation(&good_hex, 1, 2, Some("0xok".into()), &gvr).expect("other");
    db.set_attestation_watermark(&good_hex, 1, 3).expect("other watermark");

    let adapter = Arc::new(SlashingProtectionAdapter::new(Arc::clone(&db), gvr));
    assert!(adapter.export_interchange(&[bad]).is_err(), "no file for the unrepresentable key");
    assert!(
        adapter.export_interchange(&[good]).is_err(),
        "the whole export fails, so the representable key gets no file either"
    );

    let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let manager = ValidatorManagerAdapter::new(Arc::clone(&store));
    manager.add_validator(bad, false);
    assert!(!store.is_signing_enabled(&bad));
    let validator_manager: Arc<dyn ValidatorManager> = Arc::new(manager);

    let keys = Arc::new(CountingKeys::with_keys(vec![bad]));
    let state = app_state(Arc::clone(&keys), adapter, validator_manager);
    let result = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![bad_hex.clone()] }),
    )
    .await;

    match result {
        Err(ApiError::Internal(_)) => {}
        other => panic!("DELETE must abort before removing the key, got {other:?}"),
    }
    assert_eq!(keys.deletes(), 0, "keystore delete must not run");
    assert!(keys.has_key(&bad), "key stays in the keystore");
    let config = store.get_config(&bad).expect("validator stays in the store");
    assert!(!config.enabled, "key stays disabled");
}
