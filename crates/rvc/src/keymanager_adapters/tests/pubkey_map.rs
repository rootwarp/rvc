use super::*;

// --- CON-03 / RF1-06: Dynamic pubkey_map + generation counter tests ---

#[test]
fn test_import_updates_shared_pubkey_map_and_notifies() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, mut rx) =
        test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();
    let pk_bytes = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk_bytes);

    // Mark changed so the next has_changed() reflects only this import.
    rx.borrow_and_update();
    assert!(!rx.has_changed().unwrap());

    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();

    assert!(pubkey_map.read().contains_key(&pk_bytes), "import must update the shared PubkeyMap");
    assert!(rx.has_changed().unwrap(), "import must notify via key_gen_tx");
    assert_eq!(*rx.borrow(), 1);
}

#[test]
fn test_delete_removes_from_shared_pubkey_map_and_notifies() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, mut rx) =
        test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();
    let pk_bytes = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk_bytes);

    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();
    assert!(pubkey_map.read().contains_key(&pk_bytes));
    rx.borrow_and_update();
    assert!(!rx.has_changed().unwrap());

    let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
    assert!(deleted);
    assert!(
        !pubkey_map.read().contains_key(&pk_bytes),
        "delete must remove the key from the shared PubkeyMap"
    );
    assert!(rx.has_changed().unwrap(), "delete must notify via key_gen_tx");
    assert_eq!(*rx.borrow(), 2);
}

#[test]
fn test_remote_adapter_import_notifies_key_change() {
    let composite = create_empty_composite_signer();
    let (adapter, pubkey_map, mut rx) = test_remote_adapter(composite, None);

    // Valid BLS pubkey so map insert and notify are both exercised.
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk);

    rx.borrow_and_update();
    assert!(!rx.has_changed().unwrap());
    assert_eq!(*rx.borrow(), 0);

    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();

    assert!(
        pubkey_map.read().contains_key(&pk),
        "remote import of a valid BLS key must update the shared PubkeyMap"
    );
    assert!(rx.has_changed().unwrap(), "remote import must notify via key_gen_tx");
    assert_eq!(*rx.borrow(), 1);
    assert!(adapter.has_remote_key(&pk));
}

#[test]
fn test_keystore_adapter_delete_removes_from_pubkey_map() {
    // Regression: delete of a boot/manual-loaded local key clears the map entry.
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, mut rx) =
        test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk_bytes);
    let pk = crypto::PublicKey::from_bytes(&pk_bytes).unwrap();

    composite.add_local_key(sk);
    adapter.tracked_keys.lock().push(pk_bytes);
    pubkey_map.write().insert(pk_bytes, pk);

    rx.borrow_and_update();
    let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
    assert!(deleted);
    assert!(!pubkey_map.read().contains_key(&pk_bytes));
    assert!(rx.has_changed().unwrap());
}

#[test]
fn test_remote_key_adapter_delete_removes_from_pubkey_map() {
    let composite = create_empty_composite_signer();
    let (adapter, pubkey_map, mut rx) = test_remote_adapter(composite, None);

    // Use a real BLS pubkey so the map entry is written on import.
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk);

    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
    assert!(pubkey_map.read().contains_key(&pk));
    rx.borrow_and_update();

    let deleted = adapter.delete_remote_key(&pk).unwrap();
    assert!(deleted);
    assert!(!adapter.has_remote_key(&pk));
    assert!(!pubkey_map.read().contains_key(&pk));
    assert!(rx.has_changed().unwrap());
}

#[test]
fn test_generation_counter_increments_on_keystore_delete() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _map, rx) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    composite.add_local_key(sk);
    adapter.tracked_keys.lock().push(pk_bytes);

    assert_eq!(*rx.borrow(), 0);
    adapter.delete_keystore(&pk_bytes).unwrap();
    assert_eq!(*rx.borrow(), 1);
}

#[test]
fn test_generation_counter_increments_on_remote_key_import() {
    let composite = create_empty_composite_signer();
    let (adapter, _map, rx) = test_remote_adapter(composite, None);

    assert_eq!(*rx.borrow(), 0);
    adapter.import_remote_key(test_pubkey(1), "https://signer.example.com".to_string()).unwrap();
    assert_eq!(*rx.borrow(), 1);
}

// --- TOCTOU fix tests ---

fn setup_adapter_with_key(
    dir: &std::path::Path,
) -> (Arc<KeystoreManagerAdapter>, Pubkey, Arc<CompositeSigner>) {
    let composite = create_empty_composite_signer();
    let adapter = Arc::new(test_keystore_adapter(dir.to_path_buf(), composite.clone()).0);

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();

    // Write a dummy keystore file
    let filename = format!("{}.json", pubkey_hex(pk_bytes));
    let file_path = dir.join(&filename);
    std::fs::write(&file_path, "{}").unwrap();

    // Register in tracked_keys and composite signer
    composite.add_local_key(sk);
    adapter.tracked_keys.lock().push(pk_bytes);

    (adapter, pk_bytes, composite)
}

#[test]
fn test_delete_missing_file_succeeds() {
    let dir = TempDir::new().unwrap();
    let (adapter, pk_bytes, _composite) = setup_adapter_with_key(dir.path());

    // Manually remove the file to simulate external deletion
    let filename = format!("{}.json", pubkey_hex(pk_bytes));
    let file_path = dir.path().join(&filename);
    std::fs::remove_file(&file_path).unwrap();
    assert!(!file_path.exists());

    // delete_keystore should succeed (not error) even though file is gone
    let result = adapter.delete_keystore(&pk_bytes);
    assert!(result.is_ok());
    assert!(result.unwrap());
    assert!(!adapter.has_key(&pk_bytes));
}

#[test]
fn test_concurrent_delete_same_key() {
    use std::thread;

    let dir = TempDir::new().unwrap();
    let composite = create_empty_composite_signer();
    let adapter = Arc::new(test_keystore_adapter(dir.path().to_path_buf(), composite.clone()).0);

    // Set up N keys, each will be deleted by two threads simultaneously
    let n = 10;
    let mut keys = Vec::new();
    for _ in 0..n {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let filename = format!("{}.json", pubkey_hex(pk_bytes));
        std::fs::write(dir.path().join(&filename), "{}").unwrap();
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);
        keys.push(pk_bytes);
    }

    let mut handles = Vec::new();
    for key in &keys {
        let key = *key;
        // Two threads race to delete the same key
        for _ in 0..2 {
            let adapter = adapter.clone();
            handles.push(thread::spawn(move || adapter.delete_keystore(&key)));
        }
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All calls should succeed (no panic, no error)
    for result in &results {
        assert!(result.is_ok());
    }
    // For each key, exactly one thread should return true, the other false
    for key in &keys {
        let key_results: Vec<bool> = results
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let key_idx = keys.iter().position(|k| k == key).unwrap();
                *i / 2 == key_idx
            })
            .map(|(_, r)| *r.as_ref().unwrap())
            .collect();
        assert_eq!(
            key_results.iter().filter(|&&v| v).count(),
            1,
            "exactly one delete should return true for each key"
        );
    }
    assert!(adapter.list_keys().is_empty());
}

#[test]
fn test_concurrent_import_same_key() {
    use std::thread;

    let dir = TempDir::new().unwrap();
    let composite = create_empty_composite_signer();
    let adapter = Arc::new(test_keystore_adapter(dir.path().to_path_buf(), composite.clone()).0);

    let sk = SecretKey::generate();
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    let n = 10;
    let mut handles = Vec::new();
    for _ in 0..n {
        let adapter = adapter.clone();
        let json = keystore_json.clone();
        handles.push(thread::spawn(move || {
            futures::executor::block_on(adapter.import_keystore(&json, "testpass"))
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let duplicates =
        results.iter().filter(|r| matches!(r, Err(ImportKeystoreError::Duplicate))).count();
    assert_eq!(successes, 1, "exactly one import should succeed");
    assert_eq!(duplicates, n - 1, "all others should be Duplicate");
    assert_eq!(adapter.list_keys().len(), 1);
}

#[test]
fn test_concurrent_import_delete_same_key() {
    use std::sync::Barrier;
    use std::thread;

    let dir = TempDir::new().unwrap();
    let composite = create_empty_composite_signer();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
    let adapter = Arc::new(adapter);

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let _pubkey_hex = pubkey_hex(pk_bytes);
    let password = b"testpass";
    let keystore = crypto::Keystore::encrypt(
        &sk,
        password,
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    // Import the key first
    futures::executor::block_on(adapter.import_keystore(&keystore_json, "testpass")).unwrap();
    assert!(adapter.has_key(&pk_bytes));

    // Now race: half delete, half try to re-import
    let n = 10;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for i in 0..n {
        let adapter = adapter.clone();
        let json = keystore_json.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            if i % 2 == 0 {
                let _ = adapter.delete_keystore(&pk_bytes);
            } else {
                let _ = futures::executor::block_on(adapter.import_keystore(&json, "testpass"));
            }
        }));
    }

    // No thread should panic
    for h in handles {
        h.join().expect("thread should not panic");
    }

    // Final state should be consistent: list_keys and has_key agree on
    // registry membership (CompositeSigner local set, not tracked_keys).
    let keys = adapter.list_keys();
    let has_key = adapter.has_key(&pk_bytes);
    assert_eq!(keys.contains(&pk_bytes), has_key);

    // S1: PubkeyMap must stay in sync with the signing registry after concurrent
    // delete vs re-import (map remove runs under the same lock as registry ops).
    let in_map = pubkey_map.read().contains_key(&pk_bytes);
    assert_eq!(
        in_map, has_key,
        "PubkeyMap membership must match CompositeSigner after concurrent delete/import"
    );
}
