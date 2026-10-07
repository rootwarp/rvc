use super::*;

// ── M-12 Critical #2: import_meta sidecar persistence ────────────────

/// Importing a keystore must write a `0x<pubkey>.import_meta.json` sidecar
/// with the current Unix timestamp.
#[test]
fn test_import_keystore_writes_import_meta_sidecar() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    let before =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();

    let after =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    // The sidecar must exist
    let meta_path = import_meta_path(dir.path(), &pk_bytes);
    assert!(meta_path.exists(), "import_meta sidecar must be written on import");

    // The sidecar must contain a valid timestamp
    let content = std::fs::read_to_string(&meta_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    let ts = v["imported_unix_seconds"].as_u64().expect("timestamp missing");
    assert!(
        ts >= before && ts <= after,
        "sidecar timestamp must be within the import window: before={before} ts={ts} after={after}"
    );
}

/// Deleting a keystore must remove the corresponding sidecar.
#[test]
fn test_delete_keystore_removes_import_meta_sidecar() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();
    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();

    let meta_path = import_meta_path(dir.path(), &pk_bytes);
    assert!(meta_path.exists(), "sidecar should exist after import");

    adapter.delete_keystore(&pk_bytes).unwrap();
    assert!(!meta_path.exists(), "sidecar must be removed after delete");
}

/// `scan_and_rearm_gate` must call `start_monitoring` for any key whose
/// sidecar shows an import timestamp within the configured window.
#[test]
#[tracing_test::traced_test]
fn test_scan_and_rearm_gate_rearms_recent_keys() {
    use keymanager_api::traits::DoppelgangerMonitor;
    let dir = TempDir::new().unwrap();
    let pk: Pubkey = [0xABu8; 48];

    // Write a sidecar with import time = now (very recent → still in window)
    let now_unix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let meta_path = import_meta_path(dir.path(), &pk);
    std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", now_unix)).unwrap();

    let window_secs = 768u64; // 2 epochs on mainnet
    let monitor = DoppelgangerDisabledMonitor::new();

    // Opt-out monitor is always safe; re-arm is observed via the scan log.
    assert!(monitor.is_doppelganger_safe(&pk), "key must be safe before monitoring starts");

    scan_and_rearm_gate(dir.path(), &monitor, window_secs);

    assert!(logs_contain("re-arming"), "recent import must be re-armed");
    assert!(monitor.is_doppelganger_safe(&pk), "Disabled monitor stays safe after re-arm");
}

/// `scan_and_rearm_gate` must NOT re-arm keys whose window has already elapsed.
#[test]
#[tracing_test::traced_test]
fn test_scan_and_rearm_gate_skips_expired_keys() {
    let dir = TempDir::new().unwrap();
    let pk: Pubkey = [0xCDu8; 48];
    let window_secs = 768u64;

    // Write a sidecar with import time = now - window - 100s (already expired)
    let old_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(window_secs + 100);
    let meta_path = import_meta_path(dir.path(), &pk);
    std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", old_unix)).unwrap();

    let monitor = DoppelgangerDisabledMonitor::new();
    scan_and_rearm_gate(dir.path(), &monitor, window_secs);

    assert!(!logs_contain("re-arming"), "expired key must not be re-armed");
    assert!(monitor.is_doppelganger_safe(&pk), "expired key must remain safe (not re-armed)");
}

// ── SEC-1a: real signing registry for list/has/delete ─────────────────

/// Simulate a boot-loaded keystore-dir key: present in `LocalSigner` /
/// `KeyManager`, never registered via `import_keystore` / `tracked_keys`.
fn boot_load_keystore_dir_key() -> (TempDir, Arc<CompositeSigner>, Pubkey) {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let dir = TempDir::new().unwrap();
    // Optional on-disk keystore file (as `--keystore-path` would leave behind)
    let filename = format!("{}.json", pubkey_hex(pk_bytes));
    std::fs::write(dir.path().join(&filename), "{}").unwrap();
    (dir, composite, pk_bytes)
}

#[test]
fn test_list_keys_includes_boot_loaded_keystore_dir_key() {
    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

    let keys = adapter.list_keys();
    assert!(
        keys.contains(&pk),
        "boot-loaded keystore-dir key must appear in list_keys (real registry)"
    );
}

#[test]
fn test_has_key_true_for_boot_loaded_key() {
    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

    assert!(
        adapter.has_key(&pk),
        "has_key must be true for a boot-loaded key even without import_keystore"
    );
}

#[tokio::test]
async fn test_delete_boot_loaded_key_returns_ok_true_and_stops_signing() {
    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let signing_root: eth_types::Root = [0x11; 32];

    assert!(composite.sign(&signing_root, &pk).await.is_ok(), "precondition: key can sign");

    let deleted = adapter.delete_keystore(&pk).expect("delete must not IO-error");
    assert!(deleted, "delete_keystore must return Ok(true) for boot-loaded keys");
    assert!(!adapter.has_key(&pk));
    assert!(!composite.has_local_key(&pk));
    assert!(
        matches!(
            composite.sign(&signing_root, &pk).await,
            Err(crypto::SigningError::KeyNotFound(_))
        ),
        "signing must fail after delete (key removed from real registry)"
    );

    // Keystore-dir file removed
    let filename = format!("{}.json", pubkey_hex(pk));
    assert!(!dir.path().join(&filename).exists());
}

#[test]
fn test_delete_returns_real_eip3076_interchange_for_key_with_history() {
    // Mirrors the DELETE handler: has_key gates export of existing keys, so a
    // boot-loaded key with real slashing rows must yield a non-empty history
    // in the interchange (not the empty interchange used for never-known keys).
    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

    let gvr_root = [0u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let pk_hex = pubkey_hex(pk);
    db.seed_attestation(&pk_hex, 10, 11, None, &gvr_root).expect("seed history");
    db.seed_block(&pk_hex, 42, None, &gvr_root).expect("seed block history");

    let slashing = SlashingProtectionAdapter::new(db, gvr_root);

    assert!(
        adapter.has_key(&pk),
        "handler only exports interchange for keys where has_key is true"
    );

    let export = slashing.export_interchange(&[pk]).expect("export");
    let v: serde_json::Value = serde_json::from_str(&export).unwrap();
    let data = v["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["pubkey"], pk_hex);
    assert!(
        !data[0]["signed_attestations"].as_array().unwrap().is_empty(),
        "interchange must carry the key's real attestation history"
    );
    assert!(
        !data[0]["signed_blocks"].as_array().unwrap().is_empty(),
        "interchange must carry the key's real block history"
    );

    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(!adapter.has_key(&pk));
}

#[test]
fn test_delete_never_known_pubkey_returns_not_found_no_side_effects() {
    let (dir, composite, boot_pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let unknown = test_pubkey(0xEE);
    let before_keys = adapter.list_keys();
    let before_signable = composite.local_public_keys();

    let result = adapter.delete_keystore(&unknown).expect("never-known must not IO-error");
    assert!(!result, "never-known pubkey must return Ok(false) → handler not_found");

    assert_eq!(adapter.list_keys(), before_keys);
    assert_eq!(composite.local_public_keys(), before_signable);
    assert!(adapter.has_key(&boot_pk), "unrelated boot-loaded key must remain");
    assert!(composite.has_local_key(&boot_pk));
}

/// Secret-provider-style keys land in the same LocalSigner / KeyManager set
/// (or later via `add_local_key` on refresh). Confirm list/has/delete cover them.
#[test]
fn test_list_has_delete_secret_provider_style_local_key() {
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // Refresh path uses add_local_key; initial load uses KeyManager — both are local.
    let composite = create_empty_composite_signer();
    composite.add_local_key(sk);
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    assert!(adapter.has_key(&pk));
    assert!(adapter.list_keys().contains(&pk));
    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(!adapter.has_key(&pk));
    assert!(!composite.has_local_key(&pk));
}

/// Boot-loaded keystore under a non-canonical name (`validator1.json`).
/// DELETE must unlink that file and stop signing (review Finding 1).
#[tokio::test]
async fn test_delete_removes_non_canonical_boot_loaded_keystore_file() {
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();

    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));

    let dir = TempDir::new().unwrap();
    // Deposit-cli / operator style name — not `0x{pubkey}.json`.
    // Delete matches on the EIP-2335 `pubkey` JSON field (no secret material needed).
    let file_path = dir.path().join("validator1.json");
    let keystore_json = serde_json::json!({
        "crypto": {
            "kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 2, "p": 1, "r": 8, "salt": "aa"}, "message": ""},
            "checksum": {"function": "sha256", "params": {}, "message": "00"},
            "cipher": {"function": "aes-128-ctr", "params": {"iv": "00"}, "message": "00"}
        },
        "pubkey": hex::encode(pk),
        "path": "m/12381/3600/0/0/0",
        "uuid": "00000000-0000-0000-0000-000000000001",
        "version": 4
    });
    std::fs::write(&file_path, keystore_json.to_string()).unwrap();
    assert!(file_path.exists());

    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let signing_root: eth_types::Root = [0x22; 32];
    assert!(composite.sign(&signing_root, &pk).await.is_ok());

    let deleted = adapter.delete_keystore(&pk).expect("delete");
    assert!(deleted);
    assert!(!file_path.exists(), "non-canonical keystore file must be unlinked");
    assert!(!adapter.has_key(&pk));
    assert!(matches!(
        composite.sign(&signing_root, &pk).await,
        Err(crypto::SigningError::KeyNotFound(_))
    ));
    // Canonical name must not have been created as a side effect
    assert!(!dir.path().join(format!("{}.json", pubkey_hex(pk))).exists());
}

// ── SEC-1b: persistent deletion denylist ──────────────────────────────

#[test]
fn test_delete_writes_denylist_entry() {
    use crate::deletion_denylist::{deleted_keys_path, DeletionDenylist};

    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);
    let adapter = adapter.with_denylist(Arc::clone(&denylist));

    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(denylist.contains(&pk));
    assert!(deleted_keys_path(dir.path()).exists());
}

#[tokio::test]
async fn test_deleted_keystore_dir_key_not_resurrected_on_restart() {
    use std::collections::HashMap;

    use crate::deletion_denylist::DeletionDenylist;
    use crypto::EncryptionKdf;
    use secrecy::SecretString;

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");

    let dir = TempDir::new().unwrap();
    let filename = format!("{}.json", pubkey_hex(pk));
    std::fs::write(dir.path().join(&filename), serde_json::to_string(&keystore).unwrap()).unwrap();

    // Boot load into composite + KeyManager
    let mut passwords = HashMap::new();
    passwords.insert("*".to_string(), SecretString::from("testpass".to_string()));
    let km = KeyManager::load_from_directory(dir.path(), &passwords).unwrap();
    assert!(km.contains(&pk));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));

    let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let adapter = adapter.with_denylist(Arc::clone(&denylist));

    // DELETE via API — file gone, denylist written, signing stopped
    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(!composite.has_local_key(&pk));
    assert!(denylist.contains(&pk));

    // Operator (or residual file) puts the keystore back — RockLogic pattern
    std::fs::write(dir.path().join(&filename), serde_json::to_string(&keystore).unwrap()).unwrap();

    // Simulated restart: load_from_directory with denylist must skip the key
    let deny_set = denylist.snapshot();
    let km2 = KeyManager::load_from_directory_with_threads_filtered(
        dir.path(),
        &passwords,
        Some(1),
        Some(&deny_set),
    )
    .unwrap();
    assert!(!km2.contains(&pk), "denylisted keystore-dir key must not resurrect on restart");
    assert_eq!(km2.len(), 0);
}

#[test]
fn test_reimport_clears_denylist_and_allows_key_again() {
    use crate::deletion_denylist::DeletionDenylist;
    use crypto::EncryptionKdf;

    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let adapter = adapter.with_denylist(Arc::clone(&denylist));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();
    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(denylist.contains(&pk), "delete must denylist");

    // Intentional re-import clears denylist so the key is allowed again
    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();
    assert!(!denylist.contains(&pk), "re-import must clear denylist entry");
    assert!(adapter.has_key(&pk));
    assert!(composite.has_local_key(&pk));

    // Persist across reload
    let reloaded = DeletionDenylist::load(dir.path()).unwrap();
    assert!(!reloaded.contains(&pk));
}

#[test]
fn test_delete_without_denylist_still_stops_signing() {
    // SEC-1a preserved when denylist is not wired (unit tests / no data dir).
    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(!composite.has_local_key(&pk));
    assert!(!crate::deletion_denylist::deleted_keys_path(dir.path()).exists());
}

/// Denylist is written *before* registry removal: a failed insert leaves the
/// key still local so DELETE is retryable (Finding 1).
#[test]
fn test_delete_denylist_before_registry_removal_order() {
    use crate::deletion_denylist::DeletionDenylist;

    let (dir, composite, pk) = boot_load_keystore_dir_key();
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let adapter = adapter.with_denylist(Arc::clone(&denylist));

    assert!(adapter.delete_keystore(&pk).unwrap());
    // After success both hold: denylist has key and registry does not.
    assert!(denylist.contains(&pk));
    assert!(!composite.has_local_key(&pk));

    // Retry DELETE of non-local key still force-inserts denylist (idempotent)
    // and returns Ok(false) → handler not_found.
    assert!(!adapter.delete_keystore(&pk).unwrap());
    assert!(denylist.contains(&pk));
}

/// Failed re-import must not clear the denylist (Finding 2).
#[test]
fn test_failed_reimport_leaves_denylist_intact() {
    use crate::deletion_denylist::DeletionDenylist;

    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);
    let adapter = adapter.with_denylist(Arc::clone(&denylist));

    let pk = test_pubkey(0xF1);
    denylist.insert(&pk).unwrap();
    assert!(denylist.contains(&pk));

    // Invalid keystore JSON fails before any denylist mutation.
    let err = futures::executor::block_on(adapter.import_keystore("not-valid-json", "password"));
    assert!(matches!(err, Err(ImportKeystoreError::InvalidKeystore(_))));

    assert!(denylist.contains(&pk), "failed import must not clear denylist");
    let reloaded = DeletionDenylist::load(dir.path()).unwrap();
    assert!(reloaded.contains(&pk), "denylist on disk must still contain key after failed import");
}

/// SEC-5 / H-5: correctly-passworded keystore with a truncated IV must
/// surface as a per-item import error (`DecryptionFailed`), not panic.
/// The adapter stays usable afterward (service keeps running).
#[test]
fn test_keymanager_import_iv_corrupted_keystore_returns_item_error() {
    use crypto::EncryptionKdf;

    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());

    let sk = SecretKey::generate();
    let password = "sec5-import-password";
    let mut keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    // Corrupt IV to 8 bytes (16 hex chars). Checksum still matches so
    // decrypt reaches the former panic site in decrypt_ciphertext.
    keystore.crypto.cipher.params.iv = hex::encode([0u8; 8]);
    let json = keystore.to_json().expect("serialize");

    let err = futures::executor::block_on(adapter.import_keystore(&json, password));
    match err {
        Err(ImportKeystoreError::DecryptionFailed(msg)) => {
            assert!(
                msg.contains("invalid cipher IV length") || msg.contains("IV length"),
                "expected InvalidIvLength surfaced as DecryptionFailed, got: {msg}"
            );
        }
        other => panic!("expected DecryptionFailed item error, got: {other:?}"),
    }

    // Service/adapter still responsive after the failed item.
    assert!(adapter.list_keys().is_empty());
    assert!(!adapter.has_key(&sk.public_key().to_bytes()));
}
