use super::*;

// --- KeystoreManagerAdapter tests ---

#[test]
fn test_keystore_manager_adapter_empty_list() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(adapter.list_keys().is_empty());
}

#[test]
fn test_keystore_manager_adapter_has_key_false() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(!adapter.has_key(&test_pubkey(1)));
}

#[test]
fn test_keystore_manager_adapter_delete_nonexistent() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(!adapter.delete_keystore(&test_pubkey(1)).unwrap());
}

#[test]
fn delete_refuses_a_local_key_absent_from_the_armed_export() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), Arc::clone(&composite));
    let secret = SecretKey::generate();
    let pk = secret.public_key().to_bytes();
    let members = adapter.membership_for_delete(&[]);
    adapter.begin_delete_export(&members);
    composite.add_local_key(secret);
    let err = adapter.delete_keystore(&pk).expect_err("outside the export");
    assert!(matches!(err, keymanager_api::traits::DeleteKeystoreError::Io(_)));
    assert!(adapter.has_key(&pk), "admitted key is not removed");
    adapter.end_delete_export(&members);
    assert!(adapter.delete_keystore(&pk).unwrap(), "unarmed delete still removes");
    assert!(!adapter.has_key(&pk));
}

#[test]
fn test_keystore_manager_adapter_import_invalid_json() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    let result = block_on(adapter.import_keystore("not valid json", "password"));
    assert!(matches!(result, Err(ImportKeystoreError::InvalidKeystore(_))));
}

// --- Keystore import with real secret key ---

#[test]
fn test_keystore_manager_tracks_imported_key_in_composite_signer() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();

    // Manually add key (simulating what would happen with a real keystore)
    composite.add_local_key(sk);
    adapter.tracked_keys.lock().push(pk_bytes);

    assert!(adapter.has_key(&pk_bytes));
    assert!(composite.public_keys().contains(&pk_bytes));

    // Delete
    let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
    assert!(deleted);
    assert!(!adapter.has_key(&pk_bytes));
    assert!(!composite.public_keys().contains(&pk_bytes));
}
