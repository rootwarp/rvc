//! DELETE-path coverage for synthetic interchange floors (RR-4.3).
//!
//! `delete_keystores` calls [`SlashingProtectionAdapter::export_interchange`]
//! before it touches a keystore. These tests drive that function, and the
//! handler, with a real slashing DB.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use keymanager_api::error::ApiError;
use keymanager_api::handlers::{delete_keystores, AppState};
use keymanager_api::traits::{
    DeleteKeystoreError, DoppelgangerMonitor, ImportKeystoreError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, SlashingProtectionError, ValidatorConfigManager,
    ValidatorManager,
};
use keymanager_api::types::{DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteStatus};
use keymanager_api::DoppelgangerLifecycle;
use slashing::{raise_watermark, SlashingDb, WatermarkKind};
use validator_store::ValidatorStore;

use super::{pubkey_hex, test_pubkey, SlashingProtectionAdapter, ValidatorManagerAdapter};
use crate::config::Config;

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
    /// When set, `delete_keystore` unlinks the keystore file, sidecar, and secret.
    keystore_dir: Option<PathBuf>,
}

impl CountingKeys {
    fn with_keys(keys: Vec<Pubkey>) -> Self {
        Self { keys: Mutex::new(keys), deletes: AtomicU32::new(0), keystore_dir: None }
    }

    fn with_keystore_dir(keys: Vec<Pubkey>, dir: PathBuf) -> Self {
        Self { keys: Mutex::new(keys), deletes: AtomicU32::new(0), keystore_dir: Some(dir) }
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
        if let Some(dir) = &self.keystore_dir {
            let hex_key = pubkey_hex(*pubkey);
            let _ = std::fs::remove_file(dir.join(format!("{hex_key}.json")));
            let _ = std::fs::remove_file(dir.join(format!("{hex_key}.import_meta.json")));
            let _ = std::fs::remove_file(dir.join(Config::IMPORT_SECRETS_DIR).join(&hex_key));
        }
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
    keys: Arc<dyn KeystoreManager>,
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

#[tokio::test]
async fn a_pruned_key_delete_exports_a_floor_not_an_empty_record() {
    let pruned = test_pubkey(1);
    let unknown = test_pubkey(2);
    let pruned_hex = pubkey_hex(pruned);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&pruned_hex, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(&pruned_hex, 1, 11).expect("watermark");
    db.prune_below_watermarks().expect("prune");
    assert_eq!(db.get_attestation_watermark(&pruned_hex).expect("wm"), Some((5, 11)));

    let adapter = SlashingProtectionAdapter::new_in_free_window(db, gvr);
    let export = adapter.export_interchange(&[pruned, unknown]).await.expect("DELETE export");
    assert_eq!(export.with_history, vec![pruned], "a watermark-only key is history");
    let json: serde_json::Value = serde_json::from_str(&export.json).expect("json");
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
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("km1.db");
    drop(SlashingDb::open(&path).expect("schema"));
    {
        let conn = rusqlite::Connection::open(&path).expect("second connection");
        raise_watermark(&conn, &bad_hex, WatermarkKind::AttestationSource, 20)
            .expect("one-sided source watermark");
    }
    let db = Arc::new(SlashingDb::open(&path).expect("reopen"));
    db.seed_attestation(&bad_hex, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.seed_attestation(&good_hex, 1, 2, Some("0xok".into()), &gvr).expect("other");
    db.set_attestation_watermark(&good_hex, 1, 3).expect("other watermark");

    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let bad_export = adapter.export_interchange(&[bad]).await;
    assert!(
        matches!(bad_export, Err(SlashingProtectionError::Backend(_))),
        "no file for the unrepresentable key, got {bad_export:?}"
    );
    let good_export = adapter.export_interchange(&[good]).await.expect("good is exportable");
    assert_eq!(good_export.with_history, vec![good]);
    let good_json: serde_json::Value = serde_json::from_str(&good_export.json).expect("json");
    let good_data = good_json["data"].as_array().expect("data");
    assert_eq!(good_data.len(), 1);
    assert_eq!(good_data[0]["pubkey"], good_hex);
    assert!(!recorded_pubkeys(&good_json).contains(&bad_hex.as_str()));

    let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let manager = ValidatorManagerAdapter::new(Arc::clone(&store));
    manager.add_validator(bad, false).unwrap();
    assert!(!store.is_signing_enabled(&bad));
    let validator_manager: Arc<dyn ValidatorManager> = Arc::new(manager);

    let keystore_dir = tempfile::tempdir().expect("keystore dir");
    write_keystore_bundle(keystore_dir.path(), &bad_hex);
    let keystore_file = keystore_dir.path().join(format!("{bad_hex}.json"));
    let sidecar = keystore_dir.path().join(format!("{bad_hex}.import_meta.json"));
    let secret = keystore_dir.path().join(Config::IMPORT_SECRETS_DIR).join(&bad_hex);
    let keys =
        Arc::new(CountingKeys::with_keystore_dir(vec![bad], keystore_dir.path().to_path_buf()));
    let state =
        app_state(Arc::clone(&keys) as Arc<dyn KeystoreManager>, adapter, validator_manager);
    let result = delete_keystores(
        State(state),
        Json(DeleteKeystoresRequest { pubkeys: vec![bad_hex.clone()] }),
    )
    .await;

    match result {
        Err(ApiError::Internal(message)) => {
            assert_eq!(message, "slashing protection export failed; no keystores deleted");
        }
        other => panic!("DELETE must abort before removing the key, got {other:?}"),
    }
    assert_eq!(keys.deletes(), 0, "keystore delete must not run");
    assert!(keys.has_key(&bad), "key stays in the keystore");
    let config = store.get_config(&bad).expect("validator stays in the store");
    assert!(!config.enabled, "key stays disabled");
    assert_eq!(db.get_attestations(&bad_hex).expect("bad rows").len(), 1, "DB rows remain");
    assert_eq!(db.get_attestations(&good_hex).expect("good rows").len(), 1, "DB rows remain");
    assert!(
        db.get_attestation_watermark(&bad_hex).expect("bad wm").is_none(),
        "the one-sided watermark is unchanged"
    );
    assert_eq!(db.get_attestation_watermark(&good_hex).expect("good wm"), Some((1, 3)));
    assert!(keystore_file.exists(), "keystore file remains");
    assert!(sidecar.exists(), "sidecar remains");
    assert!(secret.exists(), "import secret remains");
}

fn recorded_pubkeys(json: &serde_json::Value) -> Vec<&str> {
    json["data"].as_array().expect("data").iter().filter_map(|row| row["pubkey"].as_str()).collect()
}

fn write_keystore_bundle(dir: &std::path::Path, hex_key: &str) {
    std::fs::write(dir.join(format!("{hex_key}.json")), b"{}").expect("keystore");
    std::fs::write(dir.join(format!("{hex_key}.import_meta.json")), b"{}").expect("sidecar");
    let secrets = dir.join(Config::IMPORT_SECRETS_DIR);
    std::fs::create_dir_all(&secrets).expect("secrets dir");
    std::fs::write(secrets.join(hex_key), b"secret-material").expect("secret");
}

fn loaded_state(
    keys: Vec<Pubkey>,
    slashing: Arc<dyn SlashingProtection>,
) -> (Arc<CountingKeys>, Arc<ValidatorStore>, Arc<AppState>) {
    let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let manager = ValidatorManagerAdapter::new(Arc::clone(&store));
    for pubkey in &keys {
        manager.add_validator(*pubkey, true).expect("add");
    }
    let validator_manager: Arc<dyn ValidatorManager> = Arc::new(manager);
    let counting = Arc::new(CountingKeys::with_keys(keys));
    let state =
        app_state(Arc::clone(&counting) as Arc<dyn KeystoreManager>, slashing, validator_manager);
    (counting, store, state)
}

async fn delete(
    state: Arc<AppState>,
    pubkeys: Vec<String>,
) -> Result<DeleteKeystoresResponse, ApiError> {
    delete_keystores(State(state), Json(DeleteKeystoresRequest { pubkeys }))
        .await
        .map(|Json(body)| body)
}

#[tokio::test]
async fn delete_of_a_healthy_key_succeeds_when_an_unrelated_key_cannot_be_exported() {
    let good = test_pubkey(3);
    let bad = test_pubkey(4);
    let good_hex = pubkey_hex(good);
    let bad_hex = pubkey_hex(bad);
    let gvr = chain_gvr();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("km1.db");
    drop(SlashingDb::open(&path).expect("schema"));
    {
        let conn = rusqlite::Connection::open(&path).expect("second connection");
        raise_watermark(&conn, &bad_hex, WatermarkKind::AttestationSource, 20)
            .expect("one-sided source watermark");
    }
    let db = Arc::new(SlashingDb::open(&path).expect("reopen"));
    db.seed_attestation(&bad_hex, 5, 10, Some("0xbad".into()), &gvr).expect("bad row");
    db.seed_attestation(&good_hex, 1, 2, Some("0xlow".into()), &gvr).expect("low row");
    db.seed_attestation(&good_hex, 4, 10, Some("0xhigh".into()), &gvr).expect("high row");
    db.set_attestation_watermark(&good_hex, 1, 3).expect("good watermark");

    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let (keys, _store, state) = loaded_state(vec![good], adapter);
    let body = delete(state, vec![good_hex.clone()]).await.expect("DELETE of the healthy key");
    assert_eq!(body.data.len(), 1);
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    assert_eq!(keys.deletes(), 1);
    assert!(!keys.has_key(&good));

    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    let data = json["data"].as_array().expect("data");
    assert_eq!(recorded_pubkeys(&json), vec![good_hex.as_str()]);
    let atts = data[0]["signed_attestations"].as_array().expect("atts");
    assert!(atts.iter().any(|att| att["source_epoch"] == "1" && att["target_epoch"] == "3"));
    assert!(atts.iter().any(|att| att["source_epoch"] == "4" && att["target_epoch"] == "10"));
    assert!(!body.slashing_protection.contains(&bad_hex));
    assert_eq!(db.get_attestations(&good_hex).expect("good rows").len(), 2);
    assert_eq!(db.get_attestations(&bad_hex).expect("bad rows").len(), 1);
    assert!(db.get_attestation_watermark(&bad_hex).expect("bad wm").is_none());
}

#[tokio::test]
async fn a_delete_export_leaves_the_slashing_db_unchanged() {
    let good = test_pubkey(5);
    let other = test_pubkey(6);
    let good_hex = pubkey_hex(good);
    let other_hex = pubkey_hex(other);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&good_hex, 2, 4, Some("0xa".into()), &gvr).expect("good");
    db.set_attestation_watermark(&good_hex, 2, 5).expect("good wm");
    db.seed_attestation(&other_hex, 8, 9, Some("0xb".into()), &gvr).expect("other");
    db.set_attestation_watermark(&other_hex, 3, 9).expect("other wm");
    let before = serde_json::to_string(&db.export(&gvr).expect("before")).expect("before json");

    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let (keys, _store, state) = loaded_state(vec![good], adapter);
    let body = delete(Arc::clone(&state), vec![good_hex.clone()]).await.expect("delete");
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    assert_eq!(keys.deletes(), 1);
    let after = serde_json::to_string(&db.export(&gvr).expect("after")).expect("after json");
    assert_eq!(before, after, "DELETE export must not write rows or watermarks");

    let again = delete(state, vec![good_hex]).await.expect("already deleted");
    assert_eq!(again.data.len(), 1);
    assert_eq!(again.data[0].status, DeleteStatus::NotFound);
    assert!(!keys.has_key(&good), "an already-deleted key stays gone");
    let again_json: serde_json::Value =
        serde_json::from_str(&again.slashing_protection).expect("json");
    assert!(again_json["data"].as_array().expect("data").is_empty());
    let still = serde_json::to_string(&db.export(&gvr).expect("still")).expect("still json");
    assert_eq!(before, still);
}

#[tokio::test]
async fn delete_uppercase_request_exports_the_canonical_history() {
    let first = test_pubkey(9);
    let second = test_pubkey(10);
    let first_hex = pubkey_hex(first);
    let second_hex = pubkey_hex(second);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&first_hex, 10, 11, None, &gvr).expect("first");
    db.seed_attestation(&second_hex, 12, 13, None, &gvr).expect("second");
    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let (keys, _store, state) = loaded_state(vec![first, second], adapter);

    let upper = first_hex.to_uppercase();
    let bare_upper = second_hex.trim_start_matches("0x").to_uppercase();
    let body = delete(state, vec![upper, first_hex.clone(), bare_upper]).await.expect("delete");
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    assert_eq!(body.data[1].status, DeleteStatus::NotFound, "the same key was already removed");
    assert_eq!(body.data[2].status, DeleteStatus::Deleted);
    assert!(!keys.has_key(&first));
    assert!(!keys.has_key(&second));

    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    let records = json["data"].as_array().expect("data");
    assert_eq!(records.len(), 2, "case variants of one key are one record");
    let first_record = records.iter().find(|row| row["pubkey"] == first_hex).expect("first");
    let second_record = records.iter().find(|row| row["pubkey"] == second_hex).expect("second");
    assert_eq!(first_record["signed_attestations"][0]["source_epoch"], "10");
    assert_eq!(first_record["signed_attestations"][0]["target_epoch"], "11");
    assert_eq!(second_record["signed_attestations"][0]["source_epoch"], "12");
    assert_eq!(second_record["signed_attestations"][0]["target_epoch"], "13");
}

#[tokio::test]
async fn delete_edge_requests_export_only_member_history() {
    let known = test_pubkey(11);
    let quiet = test_pubkey(12);
    let stranger = test_pubkey(13);
    let known_hex = pubkey_hex(known);
    let quiet_hex = pubkey_hex(quiet);
    let stranger_hex = pubkey_hex(stranger);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.seed_attestation(&known_hex, 1, 2, Some("0xknown".into()), &gvr).expect("known");
    db.seed_attestation(&stranger_hex, 7, 8, Some("0xstranger".into()), &gvr).expect("stranger");
    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let (_keys, _store, state) = loaded_state(vec![known, quiet], Arc::clone(&adapter) as _);

    let empty = delete(Arc::clone(&state), Vec::new()).await.expect("empty request");
    assert!(empty.data.is_empty());
    let empty_json: serde_json::Value =
        serde_json::from_str(&empty.slashing_protection).expect("json");
    assert!(empty_json["data"].as_array().expect("data").is_empty());
    assert_eq!(
        empty_json["metadata"]["genesis_validators_root"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

    let mixed = delete(
        Arc::clone(&state),
        vec![known_hex.clone(), quiet_hex.clone(), stranger_hex.clone()],
    )
    .await
    .expect("mixed");
    assert_eq!(mixed.data[0].status, DeleteStatus::Deleted);
    assert_eq!(mixed.data[1].status, DeleteStatus::Deleted);
    assert_eq!(mixed.data[2].status, DeleteStatus::NotFound);
    let mixed_json: serde_json::Value =
        serde_json::from_str(&mixed.slashing_protection).expect("json");
    assert_eq!(recorded_pubkeys(&mixed_json), vec![known_hex.as_str(), quiet_hex.as_str()]);
    let known_row = mixed_json["data"]
        .as_array()
        .expect("data")
        .iter()
        .find(|row| row["pubkey"] == known_hex)
        .expect("known");
    assert_eq!(known_row["signed_attestations"][0]["target_epoch"], "2");
    let quiet_row = mixed_json["data"]
        .as_array()
        .expect("data")
        .iter()
        .find(|row| row["pubkey"] == quiet_hex)
        .expect("quiet");
    assert!(quiet_row["signed_attestations"].as_array().expect("atts").is_empty());
    assert!(quiet_row["signed_blocks"].as_array().expect("blocks").is_empty());
    assert!(!mixed.slashing_protection.contains(&stranger_hex));
    assert_eq!(db.get_attestations(&stranger_hex).expect("stranger rows").len(), 1);

    let unknown_only = delete(state, vec![stranger_hex.clone()]).await.expect("unknown");
    assert_eq!(unknown_only.data[0].status, DeleteStatus::NotFound);
    let unknown_json: serde_json::Value =
        serde_json::from_str(&unknown_only.slashing_protection).expect("json");
    assert!(unknown_json["data"].as_array().expect("data").is_empty());
    assert!(!unknown_only.slashing_protection.contains(&known_hex));
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_delete_and_import_exports_the_precommit_snapshot() {
    let key = test_pubkey(14);
    let key_hex = pubkey_hex(key);
    let gvr = chain_gvr();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let adapter = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let entered_tx = Mutex::new(Some(entered_tx));
    let release_rx = Mutex::new(release_rx);
    adapter.set_during_import(Some(Arc::new(move || {
        if let Some(tx) = entered_tx.lock().expect("entered").take() {
            let _ = tx.send(());
            let _ = release_rx.lock().expect("release").recv();
        }
    })));

    let import_json = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": CHAIN_GVR_HEX
        },
        "data": [{
            "pubkey": key_hex,
            "signed_blocks": [],
            "signed_attestations": [{
                "source_epoch": "3",
                "target_epoch": "4",
                "signing_root": null
            }]
        }]
    })
    .to_string();
    let import_adapter = Arc::clone(&adapter);
    let import_task =
        tokio::spawn(async move { import_adapter.import_interchange(&import_json).await });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("import entered")
        .expect("entered");

    let (_keys, _store, state) =
        loaded_state(vec![key], Arc::clone(&adapter) as Arc<dyn SlashingProtection>);
    let body = delete(state, vec![key_hex.clone()]).await.expect("delete during import");
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    assert_eq!(recorded_pubkeys(&json), vec![key_hex.as_str()]);
    assert!(json["data"][0]["signed_attestations"].as_array().expect("atts").is_empty());
    assert!(db.get_attestations(&key_hex).expect("rows").is_empty(), "import has not committed");

    release_tx.send(()).expect("release");
    tokio::time::timeout(Duration::from_secs(5), import_task)
        .await
        .expect("import finished")
        .expect("import task")
        .expect("import");
    let rows = db.get_attestations(&key_hex).expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source_epoch, 3);
    assert_eq!(rows[0].target_epoch, 4);
    assert!(json["data"][0]["signed_attestations"].as_array().expect("atts").is_empty());
}

#[tokio::test]
async fn export_error_leaves_the_real_keystore_file_secret_and_sidecar() {
    let secret_key = SecretKey::generate();
    let bad = secret_key.public_key().to_bytes();
    let mut manager = KeyManager::new();
    manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
    let keystore_dir = tempfile::tempdir().expect("keystore");
    let bad_hex = pubkey_hex(bad);
    write_keystore_bundle(keystore_dir.path(), &bad_hex);
    let (keystore, _, _) =
        super::test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));

    let gvr = chain_gvr();
    let dir = tempfile::tempdir().expect("db");
    let path = dir.path().join("km1.db");
    drop(SlashingDb::open(&path).expect("schema"));
    {
        let conn = rusqlite::Connection::open(&path).expect("second connection");
        raise_watermark(&conn, &bad_hex, WatermarkKind::AttestationSource, 20).expect("one-sided");
    }
    let db = Arc::new(SlashingDb::open(&path).expect("reopen"));
    db.seed_attestation(&bad_hex, 5, 10, Some("0xrow".into()), &gvr).expect("row");

    let slashing = Arc::new(SlashingProtectionAdapter::new_in_free_window(Arc::clone(&db), gvr));
    let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let validators = ValidatorManagerAdapter::new(Arc::clone(&store));
    validators.add_validator(bad, true).expect("add");
    let state =
        app_state(Arc::new(keystore), slashing, Arc::new(validators) as Arc<dyn ValidatorManager>);
    let err = delete(state, vec![bad_hex.clone()]).await.expect_err("export fails closed");
    match err {
        ApiError::Internal(message) => {
            assert_eq!(message, "slashing protection export failed; no keystores deleted");
        }
        other => panic!("expected Internal, got {other:?}"),
    }
    assert!(keystore_dir.path().join(format!("{bad_hex}.json")).exists());
    assert!(keystore_dir.path().join(format!("{bad_hex}.import_meta.json")).exists());
    assert!(keystore_dir.path().join(Config::IMPORT_SECRETS_DIR).join(&bad_hex).exists());
    assert!(composite.has_local_key(&bad), "the signing secret stays loaded");
    assert!(!store.is_signing_enabled(&bad), "the key stays disabled");
    assert_eq!(db.get_attestations(&bad_hex).expect("rows").len(), 1);
}
