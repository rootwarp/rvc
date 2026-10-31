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

/// A failed admission must not leave a boot-loadable keystore or sidecar.
#[test]
fn failed_admit_leaves_no_keystore_json() {
    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));

    let validators_dir = TempDir::new().unwrap();
    let parent = validators_dir.path().join("gone");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    std::fs::remove_dir_all(&parent).unwrap();

    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password));
    assert!(err.is_err(), "import must fail when the validators file cannot be written");

    let names: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") || n.contains("import_meta"))
        .collect();
    assert!(
        names.is_empty(),
        "failed import must not leave a keystore or sidecar, found {names:?}"
    );

    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a key whose import failed"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// A duplicate import must not leave a boot-loadable `0x<pk>.json`.
#[test]
fn duplicate_import_leaves_no_boot_loadable_keystore() {
    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // In the map, but not a local signer key. The pre-rename map check reports
    // duplicate before the staged partials are published.
    pubkey_map.write().insert(pk, sk.public_key().clone());

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "duplicate import must be reported as duplicate, got {err:?}"
    );

    let live_json: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") && !n.ends_with(".partial") && !n.contains("import_meta"))
        .collect();
    assert!(
        live_json.is_empty(),
        "a duplicate import must not leave a live keystore json, found {live_json:?}"
    );

    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a duplicate import"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// The final `*.json` is durable before admit publishes the signer.
#[test]
fn keystore_files_are_durable_before_the_signer_is_live() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let final_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let saw_file = Arc::new(AtomicBool::new(false));
    let saw_signer = Arc::new(AtomicBool::new(false));
    let flag_file = Arc::clone(&saw_file);
    let flag_signer = Arc::clone(&saw_signer);
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_admit_hook(Arc::new(move || {
        flag_file.store(final_json.exists(), std::sync::atomic::Ordering::SeqCst);
        flag_signer.store(composite_hook.has_local_key(&pk), std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(
        saw_file.load(std::sync::atomic::Ordering::SeqCst),
        "the keystore json must be durable before admit publishes the signer"
    );
    assert!(
        !saw_signer.load(std::sync::atomic::Ordering::SeqCst),
        "the signer must not hold the key before the keystore commit"
    );
}

/// A crash at `before_admit` must not leave a boot-visible keystore over an enabled row.
#[test]
fn windowed_import_keeps_the_keystore_partial_until_the_hold_is_durable() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let pk_hex = pubkey_hex(pk);
    std::fs::write(
        &path,
        format!(
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"{pk_hex}\"\nenabled = true\n"
        ),
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let final_json = keystore_dir.path().join(format!("{pk_hex}.json"));
    let partial = keystore_dir.path().join(format!("{pk_hex}.json.partial"));
    let path_hook = path.clone();
    let saw = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_hook = std::sync::Arc::clone(&saw);
    adapter.set_before_admit_hook(std::sync::Arc::new(move || {
        let json_live = final_json.exists();
        let partial_live = partial.exists();
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let held = !disk.is_signing_enabled(&pk)
            && disk.get_config(&pk).and_then(|cfg| cfg.doppelganger_hold_until).is_some();
        saw_hook.store(!json_live && partial_live && held, std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(
        saw.load(std::sync::atomic::Ordering::SeqCst),
        "the keystore must stay .partial until the disabled hold is durable"
    );
    assert!(
        keystore_dir.path().join(format!("{pk_hex}.json")).exists(),
        "a finished import publishes the keystore json"
    );
    assert!(!store.is_signing_enabled(&pk));
}

/// The persisted hold deadline is sampled after the staged keystore bytes are written.
#[test]
fn hold_deadline_is_sampled_after_keystore_io() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let seen_hook = std::sync::Arc::clone(&seen);
    adapter.set_during_blocking_hook(std::sync::Arc::new(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        seen_hook.store(now, std::sync::atomic::Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    let disk = ValidatorStore::load_from_config(&path).expect("reload");
    let deadline =
        disk.get_config(&pk).and_then(|cfg| cfg.doppelganger_hold_until).expect("hold written");
    let seen_at = seen.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        deadline >= seen_at.saturating_add(31),
        "the hold deadline must be taken after keystore io, deadline {deadline} seen {seen_at}"
    );
}

/// A failed import unpublishes the key before it deletes the keystore files.
#[test]
fn rollback_revokes_before_discarding_keystore_files() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let signer_at_discard = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&signer_at_discard);
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_discard_hook(Arc::new(move || {
        flag.store(composite_hook.has_local_key(&pk), std::sync::atomic::Ordering::SeqCst);
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password));
    assert!(err.is_err(), "directory sync fault must fail the import");
    assert!(
        !signer_at_discard.load(std::sync::atomic::Ordering::SeqCst),
        "revoke must drop the signer before the keystore files are discarded"
    );
}

/// A crash while `*.json` is still boot-visible must not find the hold row already gone.
///
/// `register_loaded_validators` enables a loaded key that has no row.
#[test]
fn failed_import_keeps_the_hold_row_until_the_keystore_json_is_unlinked() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let crash_safe = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&crash_safe);
    let path_hook = path.clone();
    let json_hook = json_path.clone();
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_discard_hook(Arc::new(move || {
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let disabled_row = disk.has_validator(&pk) && !disk.is_signing_enabled(&pk);
        flag.store(
            json_hook.exists() && disabled_row && !composite_hook.has_local_key(&pk),
            std::sync::atomic::Ordering::SeqCst,
        );
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());
    assert!(
        crash_safe.load(std::sync::atomic::Ordering::SeqCst),
        "a crash before unlink must keep a disabled row while the keystore json is boot-visible"
    );
    assert!(!json_path.exists(), "a finished rollback unlinks the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(
        !disk.has_validator(&pk),
        "the hold row is removed only after the keystore json is gone"
    );
}

/// An unlink that does not stick leaves a plain disabled row, not a hold.
#[test]
fn failed_unlink_keeps_a_disabled_tombstone() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let locked_dir = keystore_dir.path().to_path_buf();
    adapter.set_before_discard_hook(Arc::new(move || {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&locked_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_dir, perms).unwrap();
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());

    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(keystore_dir.path()).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(keystore_dir.path(), perms).unwrap();

    assert!(json_path.exists(), "a failed unlink must leave the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(disk.has_validator(&pk), "a failed unlink must keep a validators row");
    assert!(!disk.is_signing_enabled(&pk), "the tombstone row must be disabled");
    assert!(
        disk.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
        "the tombstone must not be a hold boot can re-enable"
    );
}

/// Metadata or directory sync failing after the `*.json` rename must not drop the hold first.
#[test]
fn publish_failure_after_rename_keeps_the_hold_until_the_json_is_unlinked() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));
    adapter.fail_after_keystore_rename();

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let crash_safe = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&crash_safe);
    let path_hook = path.clone();
    let json_hook = json_path.clone();
    adapter.set_before_discard_hook(Arc::new(move || {
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let disabled_row = disk.has_validator(&pk) && !disk.is_signing_enabled(&pk);
        flag.store(json_hook.exists() && disabled_row, std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());
    assert!(
        crash_safe.load(std::sync::atomic::Ordering::SeqCst),
        "a crash after the json rename must keep the disabled hold while the keystore is boot-visible"
    );
    assert!(!json_path.exists(), "a finished publish rollback unlinks the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(
        !disk.has_validator(&pk),
        "the hold row is removed only after the keystore json is gone"
    );
}

/// A refresh that wins the same pubkey must keep its signer after this import's AlreadyPresent.
#[test]
fn already_present_import_does_not_unpublish_a_concurrent_refresh() {
    use doppelganger::ForwardWindowStatus;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let db: Arc<dyn slashing::SlashingDbReader> =
        Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let machine = Arc::new(ForwardWindowMachine::new(db, 2, [0xabu8; 32]));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        Some(Arc::clone(&machine)),
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let public = sk.public_key();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();
    let refresh = Arc::clone(&admissions);
    adapter.set_before_admit_hook(Arc::new(move || {
        let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
        refresh
            .admit(secret, crate::key_admission::AdmissionSource::RawSecret)
            .expect("refresh admit");
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race must be a duplicate, got {err:?}"
    );
    assert!(composite.has_local_key(&pk), "the refresh admission must still be signing");
    assert!(pubkey_map.read().contains_key(&pk), "the refresh map entry must stay");
    assert!(
        store.has_validator(&pk),
        "the rollback must not remove the row the refresh admitted over"
    );
    assert_ne!(
        machine.status(&public),
        ForwardWindowStatus::Unmonitored,
        "the refresh forward window must stay"
    );
    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "this import must not leave a live keystore json");
    let secret = keystore_dir.path().join(".rvc.keymanager-secrets").join(pubkey_hex(pk));
    assert!(!secret.exists(), "a lost race must not leave this import's password secret");
}

/// A refresh paused after its map insert, before `notify`, still owns the signer and the hold.
#[test]
fn already_present_import_leaves_a_midflight_refresh_hold() {
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));
    let window_secs = 30u64;
    adapter.set_doppelganger_window(Duration::from_secs(window_secs));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let release_on_drop = ReleaseOnDrop(Arc::new(std::sync::Mutex::new(Some(release_tx.clone()))));
    admissions.pause_once_after_map_insert(move || {
        if let Some(tx) = entered_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
        if let Some(rx) = release_rx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = rx.recv();
        }
    });

    let refresh = Arc::clone(&admissions);
    let entered_rx = Arc::new(std::sync::Mutex::new(Some(entered_rx)));
    let refresh_thread = Arc::new(std::sync::Mutex::new(None));
    let thread_slot = Arc::clone(&refresh_thread);
    adapter.set_before_admit_hook(Arc::new(move || {
        let refresh = Arc::clone(&refresh);
        let handle = std::thread::spawn(move || {
            let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
            refresh
                .admit(secret, crate::key_admission::AdmissionSource::RawSecret)
                .expect("refresh admit");
        });
        *thread_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        let rx = entered_rx.lock().unwrap_or_else(|p| p.into_inner()).take();
        rx.expect("pause channel")
            .recv_timeout(Duration::from_secs(10))
            .expect("refresh paused after the map insert");
    }));

    let started = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race must be a duplicate, got {err:?}"
    );

    let paused =
        store.get_config(&pk).expect("the hold row must survive while the refresh is paused");
    let hold = paused.doppelganger_hold_until.expect("the import hold must still be stored");
    assert!(!paused.enabled, "the held row must stay disabled while the refresh is paused");
    assert!(
        composite.has_local_key(&pk),
        "the refresh signer must already be installed before its generation bump"
    );

    release_on_drop.0.lock().unwrap_or_else(|p| p.into_inner()).take();
    release_tx.send(()).expect("release the refresh");
    let handle =
        refresh_thread.lock().unwrap_or_else(|p| p.into_inner()).take().expect("refresh thread");
    handle.join().expect("refresh admit finishes");

    let finished = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    assert!(composite.has_local_key(&pk), "the refresh signer must stay enabled");
    assert!(pubkey_map.read().contains_key(&pk), "the refresh map entry must stay");
    let cfg = store.get_config(&pk).expect("the refresh must end with a row");
    assert_eq!(cfg.doppelganger_hold_until, Some(hold), "the refresh must keep the import hold");
    assert!(!cfg.enabled, "a correct hold leaves the row disabled");
    assert!(hold >= started.saturating_add(window_secs));
    assert!(hold <= finished.saturating_add(window_secs));
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    let disk_cfg = disk.get_config(&pk).expect("the hold must be durable");
    assert_eq!(disk_cfg.doppelganger_hold_until, Some(hold));
    assert!(!disk_cfg.enabled);
    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "AlreadyPresent must not publish this import's keystore");
}

/// A zero-window import that loses the race after rename must not leave a boot-loadable keystore.
///
/// The refresh inserts its signer and map, then its validators-row write fails and
/// it rolls that signer back. Both admissions failed, so boot must not load the key.
#[test]
fn late_already_present_with_a_failed_refresh_row_is_not_boot_loadable() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::time::Duration;

    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let release_on_drop = ReleaseOnDrop(Arc::new(std::sync::Mutex::new(Some(release_tx.clone()))));
    let locked_validators = validators_dir.path().to_path_buf();
    let _restore_validators = RestoreDirPerms(locked_validators.clone());
    admissions.pause_once_after_map_insert(move || {
        let mut perms = std::fs::metadata(&locked_validators).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_validators, perms).unwrap();
        if let Some(tx) = entered_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
        if let Some(rx) = release_rx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = rx.recv();
        }
    });

    let refresh = Arc::clone(&admissions);
    let entered_rx = Arc::new(std::sync::Mutex::new(Some(entered_rx)));
    let refresh_thread = Arc::new(std::sync::Mutex::new(None));
    let thread_slot = Arc::clone(&refresh_thread);
    adapter.set_before_admit_hook(Arc::new(move || {
        let refresh = Arc::clone(&refresh);
        let handle = std::thread::spawn(move || {
            let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
            refresh.admit(secret, crate::key_admission::AdmissionSource::RawSecret)
        });
        *thread_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        let rx = entered_rx.lock().unwrap_or_else(|p| p.into_inner()).take();
        rx.expect("pause channel")
            .recv_timeout(Duration::from_secs(10))
            .expect("refresh paused after the map insert");
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race after rename must be a duplicate, got {err:?}"
    );

    release_on_drop.0.lock().unwrap_or_else(|p| p.into_inner()).take();
    release_tx.send(()).expect("release the refresh");
    let handle =
        refresh_thread.lock().unwrap_or_else(|p| p.into_inner()).take().expect("refresh thread");
    let refresh_result = handle.join().expect("refresh thread");
    assert!(refresh_result.is_err(), "the refresh row write must fail, got {refresh_result:?}");
    assert!(!composite.has_local_key(&pk), "a failed refresh must roll its signer back");
    assert!(!pubkey_map.read().contains_key(&pk), "a failed refresh must roll its map entry back");

    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "this import's renamed keystore must not stay boot-visible");
    let secret = keystore_dir.path().join(".rvc.keymanager-secrets").join(pubkey_hex(pk));
    assert!(!secret.exists(), "AlreadyPresent must remove the import password secret");
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a key both admissions failed"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// Sends the refresh-release token if the test fails while the admit is paused.
struct ReleaseOnDrop(Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

/// The tombstone disable listener must not take `state_lock` while import holds `tracked_keys`.
///
/// DELETE takes `state_lock` and then `tracked_keys`. A listener that runs under
/// `tracked_keys` deadlocks with that DELETE. The timeout is the failure mode.
#[test]
fn tombstone_disable_does_not_deadlock_with_delete() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::time::Instant;

    use keymanager_api::lifecycle::ConfigTouch;
    use keymanager_api::traits::ValidatorManager;
    use keymanager_api::{DoppelgangerLifecycle, ImportKind};

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = Arc::new(adapter.with_admission_service(admissions));
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));
    adapter.fail_after_admit();

    let vm = Arc::new(super::ValidatorManagerAdapter::new(Arc::clone(&store)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let life = Arc::new(DoppelgangerLifecycle::new(
        std::time::Duration::from_secs(30),
        Arc::new(super::DoppelgangerDisabledMonitor::new()),
        vm_dyn,
    ));
    let listener_ran = Arc::new(AtomicBool::new(false));
    let ran = Arc::clone(&listener_ran);
    let life_listener = Arc::clone(&life);
    store.set_disable_listener(Arc::new(move |pubkey| {
        ran.store(true, std::sync::atomic::Ordering::SeqCst);
        life_listener.cancel_enable_on_disable(pubkey);
    }));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(async {
        life.rearm_persisted_hold(pk, std::time::Duration::from_secs(60)).expect("arm enable task");
    });
    assert!(life.current_cancel_token(&pk).is_some(), "the real enable token must be armed");

    let (import_at_rollback_tx, import_at_rollback_rx) = mpsc::channel::<()>();
    let (delete_holds_state_lock_tx, delete_holds_state_lock_rx) = mpsc::channel::<()>();
    let delete_holds_state_lock_rx =
        Arc::new(std::sync::Mutex::new(Some(delete_holds_state_lock_rx)));
    let locked_dir = keystore_dir.path().to_path_buf();
    adapter.set_before_discard_hook(Arc::new(move || {
        let mut perms = std::fs::metadata(&locked_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_dir, perms).unwrap();
        import_at_rollback_tx.send(()).expect("import reached rollback");
        delete_holds_state_lock_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("delete signal")
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("DELETE did not take state_lock");
    }));
    let _restore_perms = RestoreDirPerms(keystore_dir.path().to_path_buf());

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");

    let (import_done_tx, import_done_rx) = mpsc::channel();
    let import_adapter = Arc::clone(&adapter);
    std::thread::spawn(move || {
        let result = block_on(import_adapter.import_keystore(&json, password));
        let _ = import_done_tx.send(result);
    });

    let (delete_done_tx, delete_done_rx) = mpsc::channel::<Result<(), String>>();
    let delete_adapter = Arc::clone(&adapter);
    let delete_life = Arc::clone(&life);
    std::thread::spawn(move || {
        if import_at_rollback_rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
            let _ = delete_done_tx.send(Err("import never reached the tombstone rollback".into()));
            return;
        }
        let _ = delete_life.on_delete(&pk, ImportKind::Local, || {
            delete_holds_state_lock_tx.send(()).expect("signal state_lock");
            match delete_adapter.delete_keystore(&pk) {
                Ok(present) => (ConfigTouch::Apply { keystore_present: present }, Ok(())),
                Err(e) => (ConfigTouch::Skip, Err(e.to_string())),
            }
        });
        let _ = delete_done_tx.send(Ok(()));
    });

    let budget = std::time::Duration::from_secs(5);
    let started = Instant::now();
    let import_result = import_done_rx.recv_timeout(budget).unwrap_or_else(|_| {
        panic!("deadlock: tombstone import held tracked_keys while DELETE held state_lock")
    });
    let delete_result =
        delete_done_rx.recv_timeout(budget.saturating_sub(started.elapsed())).unwrap_or_else(
            |_| panic!("deadlock: DELETE held state_lock while the import held tracked_keys"),
        );

    assert!(import_result.is_err(), "the unlink failure must still fail the import");
    delete_result.expect("DELETE finishes once tracked_keys is free");
    assert!(
        listener_ran.load(std::sync::atomic::Ordering::SeqCst),
        "the real disable listener must still run after tracked_keys is released"
    );
    assert!(life.current_cancel_token(&pk).is_none(), "the enable token must be cancelled");
}

/// A dropped keymanager handler never calls `DoppelgangerLifecycle::on_import`.
///
/// The blocking import still admits the key. While Pending, `SignerService`
/// refuses signing. Reloading the validators file must still show
/// `enabled = false` with the hold (admit's write, not only the adapter
/// pre-hold).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_import_withholds_signing_without_on_import() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use axum::extract::{Json, State};
    use axum::http::HeaderMap;
    use doppelganger::{ForwardWindowStatus, SigningEnablement};
    use eth_types::{ForkSchedule, Root};
    use keymanager_api::handlers::{import_keystores, AppState};
    use keymanager_api::types::ImportKeystoresRequest;
    use keymanager_api::DoppelgangerLifecycle;
    use parking_lot::{Condvar, Mutex as ParkMutex};
    use signer::{SignerError, SignerService, ValidatorSigner};

    const PASSWORD: &str = "testpass";
    const GVR: Root = [0xabu8; 32];

    struct Gate {
        entered: AtomicBool,
        release: AtomicBool,
        lock: ParkMutex<()>,
        cv: Condvar,
    }

    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                release: AtomicBool::new(false),
                lock: ParkMutex::new(()),
                cv: Condvar::new(),
            })
        }

        fn hook(self: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
            let gate = Arc::clone(self);
            Arc::new(move || {
                let mut guard = gate.lock.lock();
                gate.entered.store(true, Ordering::SeqCst);
                while !gate.release.load(Ordering::SeqCst) {
                    gate.cv.wait(&mut guard);
                }
            })
        }

        fn release(&self) {
            let _guard = self.lock.lock();
            self.release.store(true, Ordering::SeqCst);
            self.cv.notify_all();
        }
    }

    /// Releases the blocking import if a later assert panics.
    struct ReleaseOnDrop(Arc<Gate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    db.set_genesis_validators_root(&GVR).expect("gvr");
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::clone(&db) as _;
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, GVR));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        Some(Arc::clone(&machine)),
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = Arc::new(adapter.with_admission_service(admissions));
    adapter.set_doppelganger_window(Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let public = sk.public_key();

    // Drop the adapter pre-hold so reload asserts admit's own persist
    // (`enabled=false` / hold). Otherwise those writes are masked.
    let wipe_store = Arc::clone(&store);
    let wipe_pk = pk;
    let wiped = Arc::new(AtomicBool::new(false));
    let wiped_flag = Arc::clone(&wiped);
    adapter.set_before_admit_hook(Arc::new(move || {
        if let Ok(Some(_)) = wipe_store.remove_validator_durable(&wipe_pk) {
            wiped_flag.store(true, Ordering::SeqCst);
        }
    }));

    let admitted = Arc::new(AtomicBool::new(false));
    let admitted_flag = Arc::clone(&admitted);
    adapter.set_after_admit_hook(Arc::new(move || {
        admitted_flag.store(true, Ordering::SeqCst);
    }));

    let gate = Gate::new();
    let _release_on_drop = ReleaseOnDrop(Arc::clone(&gate));
    adapter.set_during_blocking_hook(gate.hook());

    let keystore = Keystore::encrypt(
        &sk,
        PASSWORD.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");

    let vm = Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let epoch_provider: Arc<dyn Fn() -> eth_types::Epoch + Send + Sync> = Arc::new(|| 0);
    let monitor = Arc::new(ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider));
    let life =
        Arc::new(DoppelgangerLifecycle::new(Duration::from_secs(30), monitor, Arc::clone(&vm_dyn)));
    let (remote, _, _) = test_remote_adapter(Arc::clone(&composite), None);
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&adapter) as Arc<dyn KeystoreManager>,
        slashing_protection: Arc::new(SlashingProtectionAdapter::new_in_free_window(
            Arc::clone(&db),
            GVR,
        )),
        validator_manager: Arc::clone(&vm_dyn),
        doppelganger: Arc::clone(&life),
        remote_key_manager: Arc::new(remote),
        config_manager: Arc::new(ValidatorConfigManagerAdapter::new(Arc::clone(&store))),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let handle = tokio::spawn({
        let state = Arc::clone(&state);
        let json = json.clone();
        async move {
            import_keystores(
                State(state),
                HeaderMap::new(),
                Json(ImportKeystoresRequest {
                    keystores: vec![json],
                    passwords: vec![PASSWORD.to_string()],
                    slashing_protection: None,
                }),
            )
            .await
        }
    });

    let started = std::time::Instant::now();
    while !gate.entered.load(Ordering::SeqCst) {
        assert!(started.elapsed() < Duration::from_secs(10), "blocking import never entered");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    handle.abort();
    let aborted = handle.await;
    assert!(aborted.is_err(), "dropping the handler future cancels the await");

    gate.release();
    let started = std::time::Instant::now();
    while !admitted.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "dropped handler must still finish admit"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert!(wiped.load(Ordering::SeqCst), "before_admit must remove the adapter pre-hold row");
    assert!(
        life.current_cancel_token(&pk).is_none(),
        "disconnect skips on_import, so no enable task is armed"
    );
    assert_eq!(
        machine.status(&public),
        ForwardWindowStatus::Pending,
        "admit registers the import without on_import"
    );

    let enablement: Arc<dyn SigningEnablement> = Arc::clone(&machine) as _;
    let signer =
        SignerService::new(Arc::clone(&composite), Arc::clone(&db)).with_enablement(enablement);
    let sign_result =
        signer.sign_block(&[0xcd; 32], 1, &public, &ForkSchedule::unscheduled_gloas(), &GVR).await;
    assert!(
        matches!(sign_result, Err(SignerError::BlockedByDoppelganger)),
        "SignerService must refuse while Pending, got {sign_result:?}"
    );

    let disk = ValidatorStore::load_from_config(&path).expect("reload validators file");
    assert!(
        !disk.is_signing_enabled(&pk),
        "admit must persist enabled=false (not only the adapter pre-hold)"
    );
    assert!(
        disk.get_config(&pk).and_then(|cfg| cfg.doppelganger_hold_until).is_some(),
        "admit must persist the doppelganger hold"
    );
}

fn validators_backed_adapter(
    dir: &std::path::Path,
) -> (KeystoreManagerAdapter, Arc<CompositeSigner>, TempDir) {
    let composite = create_empty_composite_signer();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(dir.to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        dir.join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        Arc::clone(&denylist),
        None,
        Arc::new(MonotonicEpochClock::new(0, 12_000)),
    ));
    let adapter = adapter.with_admission_service(admissions).with_denylist(denylist);
    (adapter, composite, validators_dir)
}

fn encrypt_json(sk: &SecretKey, password: &str) -> String {
    let keystore = Keystore::encrypt(
        sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    keystore.to_json().expect("json")
}

fn secret_file(dir: &std::path::Path, pk: &[u8; 48]) -> std::path::PathBuf {
    dir.join(".rvc.keymanager-secrets").join(pubkey_hex(pk))
}

/// Import a key whose password is absent from `--password-file`, then boot.
#[tokio::test]
async fn imported_keystore_loads_on_boot_and_is_listed() {
    use std::sync::atomic::AtomicBool;

    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json = encrypt_json(&sk, password);
    adapter.import_keystore(&json, password).await.expect("import");

    let password_file = keystore_dir.path().join("passwords.txt");
    std::fs::write(&password_file, "cafebabe=not-the-import-password\n").unwrap();
    let file_text = std::fs::read_to_string(&password_file).unwrap();
    assert!(!file_text.contains(password), "the password file must not hold the import password");

    let config = crate::config::Config {
        keystore_path: keystore_dir.path().to_path_buf(),
        password_file: Some(password_file),
        ..Default::default()
    };
    let loaded = crate::config::ServiceBuilder::new(config)
        .build_key_manager_owned_filtered(None)
        .expect("boot loads the persisted import password");
    assert!(loaded.contains(&pk), "boot must load the imported key");

    let booted = Arc::new(CompositeSigner::new(LocalSigner::new(loaded)));
    let (booted_adapter, _, _) = test_keystore_adapter(keystore_dir.path().to_path_buf(), booted);
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let validator_store = Arc::new(ValidatorStore::new([1u8; 20], 30_000_000));
    let token = "deadbeef".repeat(8);
    let server = keymanager_api::KeymanagerServer::new(
        keymanager_api::KeymanagerDeps {
            keystore_manager: Arc::new(booted_adapter),
            slashing_protection: Arc::new(SlashingProtectionAdapter::new_in_free_window(
                slashing_db,
                [0u8; 32],
            )),
            validator_manager: Arc::new(ValidatorManagerAdapter::new(Arc::clone(&validator_store))),
            doppelganger_monitor: Arc::new(DoppelgangerDisabledMonitor::new()),
            remote_key_manager: Arc::new(
                test_remote_adapter(create_empty_composite_signer(), None).0,
            ),
            config_manager: Arc::new(ValidatorConfigManagerAdapter::new(validator_store)),
            exit_manager: None,
            signing_quiesce: None,
        },
        keymanager_api::KeymanagerSettings {
            token: token.clone(),
            addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            body_limit: keymanager_api::DEFAULT_BODY_LIMIT,
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
            doppelganger_window: std::time::Duration::ZERO,
        },
    );
    let response = server
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let listed: keymanager_api::types::ListKeystoresResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(listed.data.len(), 1);
    assert_eq!(listed.data[0].validating_pubkey, pubkey_hex(pk));
}

#[test]
fn import_rejects_a_bad_pubkey_field_and_writes_nothing() {
    use axum::extract::{Json, State};
    use keymanager_api::handlers::{import_keystores, AppState};
    use keymanager_api::types::ImportKeystoresRequest;
    use keymanager_api::types::ImportStatus;
    use keymanager_api::DoppelgangerLifecycle;
    use std::sync::atomic::AtomicBool;

    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let derived = hex::encode(sk.public_key().to_bytes());
    let json = encrypt_json(&sk, password);
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let missing = {
        let mut v = value.clone();
        v.as_object_mut().unwrap().remove("pubkey");
        v.to_string()
    };
    value["pubkey"] = serde_json::Value::String(format!("0x{derived}"));
    let prefixed = value.to_string();
    value["pubkey"] = serde_json::Value::String("0X".to_string() + &derived);
    let prefixed_upper = value.to_string();
    value["pubkey"] = serde_json::Value::String("ab".repeat(48));
    let mismatched = value.to_string();
    value["pubkey"] = serde_json::Value::String("zz".to_string());
    let not_hex = value.to_string();
    value["pubkey"] = serde_json::Value::String(derived.to_ascii_uppercase());
    let uppercase = value.to_string();

    let store = Arc::new(ValidatorStore::new([1u8; 20], 30_000_000));
    let vm: Arc<dyn keymanager_api::traits::ValidatorManager> =
        Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    let monitor: Arc<dyn keymanager_api::traits::DoppelgangerMonitor> =
        Arc::new(DoppelgangerDisabledMonitor::new());
    let state = Arc::new(AppState {
        keystore_manager: Arc::new(adapter),
        slashing_protection: Arc::new(SlashingProtectionAdapter::new_in_free_window(
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            [0u8; 32],
        )),
        validator_manager: Arc::clone(&vm),
        doppelganger: Arc::new(DoppelgangerLifecycle::new(std::time::Duration::ZERO, monitor, vm)),
        remote_key_manager: Arc::new(test_remote_adapter(create_empty_composite_signer(), None).0),
        config_manager: Arc::new(ValidatorConfigManagerAdapter::new(store)),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let response = block_on(import_keystores(
        State(state),
        axum::http::HeaderMap::new(),
        Json(ImportKeystoresRequest {
            keystores: vec![missing, prefixed, prefixed_upper, mismatched, not_hex, uppercase],
            passwords: vec![password.to_string(); 6],
            slashing_protection: None,
        }),
    ))
    .expect("batch import response");
    let Json(body) = response;
    assert_eq!(body.data.len(), 6);
    for item in &body.data {
        assert_eq!(item.status, ImportStatus::Error);
        assert!(item.message.contains("pubkey"), "{}", item.message);
        assert!(!item.message.contains(password), "{}", item.message);
        assert!(!item.message.contains("request_id"), "{}", item.message);
    }
    let names: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".rvc.deleted_keys")
        .collect();
    assert!(names.is_empty(), "a rejected pubkey must write nothing, found {names:?}");
}

#[test]
fn import_keeps_a_multibyte_newline_password() {
    let password = "café\nsecond line\n";
    assert!(password.len() != password.chars().count());
    assert!(password.contains('\n'));
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    assert_eq!(std::fs::read(secret_file(keystore_dir.path(), &pk)).unwrap(), password.as_bytes());
}

#[test]
fn delete_retry_removes_a_leftover_secret() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    assert!(composite.remove_local_key(&pk));
    let secret = secret_file(keystore_dir.path(), &pk);
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    std::fs::remove_file(&json_path).unwrap();
    assert!(secret.exists());
    assert!(
        !adapter.delete_keystore(&pk).unwrap(),
        "a retry of an absent key is not a fresh delete"
    );
    assert!(!secret.exists(), "the retry removes the leftover plaintext");
    assert!(!adapter.has_key(&pk));
    let denylist = crate::deletion_denylist::DeletionDenylist::load(keystore_dir.path())
        .expect("denylist reloads");
    assert!(denylist.contains(&pk), "a successful retry of an absent key is denylisted");
}

#[test]
fn import_accepts_a_password_at_the_boot_limit() {
    let password = "x".repeat(4096);
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, &password), &password)).expect("import");
    assert!(adapter.has_key(&pk));
    assert_eq!(std::fs::read(secret_file(keystore_dir.path(), &pk)).unwrap(), password.as_bytes());
}

#[test]
fn import_rejects_a_password_over_the_boot_limit() {
    let password = "x".repeat(4097);
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json = encrypt_json(&sk, "short-password");
    let err = block_on(adapter.import_keystore(&json, &password))
        .expect_err("a password over 4096 bytes is rejected");
    let msg = err.to_string();
    assert!(msg.contains("exceeds 4096 bytes"), "{msg}");
    assert!(!msg.contains(&password), "{msg}");
    assert!(!secret_file(keystore_dir.path(), &pk).exists());
    let names: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".rvc.deleted_keys")
        .collect();
    assert!(names.is_empty(), "an oversized password must write nothing, found {names:?}");
}

struct ClearRemoveFail;
impl Drop for ClearRemoveFail {
    fn drop(&mut self) {
        super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(false));
    }
}

fn arm_remove_fail() -> ClearRemoveFail {
    super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(true));
    ClearRemoveFail
}

#[test]
fn delete_reports_a_secret_removal_failure_and_keeps_the_key() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let secret = secret_file(keystore_dir.path(), &pk);
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let _guard = arm_remove_fail();
    let err = adapter.delete_keystore(&pk).expect_err("secret removal must be reported");
    let msg = err.to_string();
    assert!(msg.contains("import password secret"), "{msg}");
    assert!(msg.contains("permission denied"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(
        !msg.contains(keystore_dir.path().to_str().expect("utf8 dir")),
        "a secret-removal error must not carry the directory path: {msg}"
    );
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
    assert!(secret.exists(), "the plaintext remains when removal fails");
    assert!(!json_path.exists(), "the keystore was already removed");
}

#[cfg(unix)]
#[test]
fn delete_reports_a_staged_secret_removal_failure_and_keeps_the_key() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let partial = secret_file(keystore_dir.path(), &pk)
        .parent()
        .unwrap()
        .join(format!(".{}.1.2.keymanager-secret.partial", pubkey_hex(pk)));
    std::fs::create_dir(&partial).unwrap();
    std::fs::write(partial.join("body"), b"leftover-plaintext").unwrap();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let err = adapter.delete_keystore(&pk).expect_err("staged secret removal must be reported");
    let msg = err.to_string();
    assert!(msg.contains("staged import secret"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
    assert!(partial.is_dir(), "the staged secret remains when removal fails");
    assert!(!json_path.exists(), "the keystore was already removed");
}

#[test]
fn delete_reports_a_secret_removal_failure_when_the_key_is_not_registered() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    assert!(composite.remove_local_key(&pk));
    let secret = secret_file(keystore_dir.path(), &pk);
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    std::fs::remove_file(&json_path).unwrap();
    let _guard = arm_remove_fail();
    let err = adapter.delete_keystore(&pk).expect_err("secret removal must be reported");
    let msg = err.to_string();
    assert!(msg.contains("import password secret"), "{msg}");
    assert!(msg.contains("permission denied"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(!adapter.has_key(&pk), "an unregistered key is not added back");
    assert!(secret.exists(), "the plaintext remains when removal fails");
}

#[test]
fn delete_fsyncs_the_secret_dir_when_a_staged_partial_cannot_be_removed() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let secret = secret_file(keystore_dir.path(), &pk);
    let partial =
        secret.parent().unwrap().join(format!(".{}.1.2.keymanager-secret.partial", pubkey_hex(pk)));
    std::fs::create_dir(&partial).unwrap();
    struct ClearSyncFail;
    impl Drop for ClearSyncFail {
        fn drop(&mut self) {
            super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(false));
        }
    }
    let _guard = ClearSyncFail;
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(true));
    let err = adapter.delete_keystore(&pk).expect_err("partial removal and fsync must be reported");
    let msg = err.to_string();
    assert!(msg.contains("staged import secret"), "{msg}");
    assert!(msg.contains("sync import secret directory"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
    assert!(!secret.exists(), "the final secret is unlinked before the directory fsync");
    assert!(partial.is_dir(), "the staged partial remains");
}

#[test]
fn delete_denylists_even_when_secret_removal_fails() {
    let password = "import-only-testpass";
    // Loaded key, final unlink fails. Not-registered key, final unlink fails.
    // Loaded key, staged partial cannot be removed. Loaded key, directory
    // fsync fails after the secret is unlinked. Final unlink fails and the
    // partial cleanup's fsync also fails. Denylist IO fails alone, and
    // together with the unlink.
    for case in [
        "loaded-unlink",
        "absent-unlink",
        "loaded-partial",
        "loaded-sync",
        "loaded-unlink-sync",
        "denylist-io",
        "both-io",
    ] {
        let keystore_dir = TempDir::new().unwrap();
        let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
        let loaded = !case.starts_with("absent");
        if !loaded {
            assert!(composite.remove_local_key(&pk));
            let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
            std::fs::remove_file(&json_path).unwrap();
        }
        let secret = secret_file(keystore_dir.path(), &pk);
        struct ClearHooks;
        impl Drop for ClearHooks {
            fn drop(&mut self) {
                super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(false));
                super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(false));
            }
        }
        let _guard = ClearHooks;
        let deny_path = keystore_dir.path().join(".rvc.deleted_keys");
        if case == "loaded-partial" {
            let partial = secret
                .parent()
                .unwrap()
                .join(format!(".{}.1.2.keymanager-secret.partial", pubkey_hex(pk)));
            std::fs::create_dir(&partial).unwrap();
        } else if case == "loaded-sync" {
            super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(true));
        } else if case == "loaded-unlink-sync" {
            std::fs::write(
                secret
                    .parent()
                    .unwrap()
                    .join(format!(".{}.1.2.keymanager-secret.partial", pubkey_hex(pk))),
                b"leftover",
            )
            .unwrap();
            super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(true));
            super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(true));
        } else if case == "denylist-io" || case == "both-io" {
            std::fs::create_dir(&deny_path).unwrap();
            if case == "both-io" {
                super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(true));
            }
        } else {
            super::super::keystore::IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.set(true));
        }
        let err = adapter.delete_keystore(&pk).expect_err(case);
        let msg = err.to_string();
        assert!(!msg.contains(password), "{case}: {msg}");
        assert_eq!(adapter.has_key(&pk), loaded, "{case}");
        if case == "denylist-io" || case == "both-io" {
            assert!(msg.contains("deletion denylist"), "{case}: {msg}");
            assert_eq!(secret.exists(), case == "both-io", "{case}");
            if case == "both-io" {
                assert!(msg.contains("import password secret"), "{case}: {msg}");
            }
            continue;
        }
        let denylist = crate::deletion_denylist::DeletionDenylist::load(keystore_dir.path())
            .unwrap_or_else(|e| panic!("{case}: denylist reload: {e}"));
        assert!(denylist.contains(&pk), "{case}: denylist missing");
        if case == "loaded-unlink-sync" {
            assert!(msg.contains("permission denied"), "{case}: {msg}");
            assert!(msg.contains("sync import secret directory"), "{case}: {msg}");
            assert!(secret.exists(), "{case}");
            let partial = secret
                .parent()
                .unwrap()
                .join(format!(".{}.1.2.keymanager-secret.partial", pubkey_hex(pk)));
            assert!(!partial.exists(), "{case}: the partial was removed before the fsync");
        }
        if case == "loaded-unlink" {
            assert!(secret.exists(), "{case}");
            std::fs::write(keystore_dir.path().join("notes.json"), b"{}").unwrap();
            let config = crate::config::Config {
                keystore_path: keystore_dir.path().to_path_buf(),
                ..Default::default()
            };
            let booted = crate::config::ServiceBuilder::new(config)
                .build_key_manager_owned_filtered(Some(&denylist.snapshot()))
                .unwrap_or_else(|e| panic!("{case}: boot: {e}"));
            assert!(!booted.contains(&pk), "{case}: restart must skip the denylisted secret");
        }
    }
}

#[test]
fn import_reports_a_secret_dir_sync_failure_after_abandoning_the_staged_secret() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let secrets = keystore_dir.path().join(".rvc.keymanager-secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::create_dir(secrets.join(pubkey_hex(pk))).unwrap();
    // Import runs on the blocking pool, so the counter has to be armed there.
    // No partial exists yet, so this path's first directory sync is
    // `abandon_staged` after the rename onto the occupied final path fails.
    adapter.set_during_blocking_hook(Arc::new(|| {
        super::super::keystore::IMPORT_SECRET_DIR_SYNC_CALLS.with(|slot| slot.set(0));
        super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.set(1));
    }));
    let err = block_on(adapter.import_keystore(&encrypt_json(&sk, password), password))
        .expect_err("rename and directory sync fail");
    let msg = err.to_string();
    assert!(msg.contains("rename import secret"), "{msg}");
    assert!(msg.contains("sync import secret directory"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    let staged: Vec<_> = std::fs::read_dir(&secrets)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("keymanager-secret.partial"))
        .collect();
    assert!(staged.is_empty(), "abandon removes the staged secret before the fsync: {staged:?}");
    assert!(secrets.join(pubkey_hex(pk)).is_dir());
    assert!(!adapter.has_key(&pk));
}

#[test]
fn boot_during_import_sees_the_secret_before_the_keystore() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json = encrypt_json(&sk, password);
    std::fs::write(keystore_dir.path().join("notes.json"), b"{}").unwrap();
    let secret = secret_file(keystore_dir.path(), &pk);
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let (boot_go_tx, boot_go_rx) = std::sync::mpsc::channel::<()>();
    let (boot_done_tx, boot_done_rx) = std::sync::mpsc::channel::<()>();
    let boot_go_tx = Arc::new(std::sync::Mutex::new(Some(boot_go_tx)));
    let boot_done_rx = Arc::new(std::sync::Mutex::new(boot_done_rx));
    let secret_hook = secret.clone();
    let json_hook = json_path.clone();
    adapter.set_after_secret_before_keystore_hook(Arc::new(move || {
        assert!(secret_hook.is_file(), "the secret is durable before the keystore");
        assert!(!json_hook.exists(), "the keystore is not renamed yet");
        let tx = boot_go_tx.lock().expect("boot gate").take().expect("boot gate once");
        tx.send(()).expect("boot thread is waiting");
        boot_done_rx.lock().expect("boot gate").recv().expect("boot finished");
    }));
    let boot_dir = keystore_dir.path().to_path_buf();
    let booted = std::thread::spawn(move || {
        boot_go_rx.recv().expect("import reached the secret");
        let config = crate::config::Config { keystore_path: boot_dir, ..Default::default() };
        let loaded = crate::config::ServiceBuilder::new(config)
            .build_key_manager()
            .expect("boot during import");
        boot_done_tx.send(()).expect("import is waiting");
        loaded
    });
    block_on(adapter.import_keystore(&json, password)).expect("import");
    let during = booted.join().expect("boot thread");
    assert!(
        !during.contains(&pk),
        "boot in the secret-before-keystore window does not load the key"
    );
    assert!(adapter.has_key(&pk));
    let config = crate::config::Config {
        keystore_path: keystore_dir.path().to_path_buf(),
        ..Default::default()
    };
    let after =
        crate::config::ServiceBuilder::new(config).build_key_manager().expect("boot after import");
    assert!(after.contains(&pk));
}

#[test]
fn delete_reports_a_secret_directory_sync_failure_and_keeps_the_key() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    struct ClearSyncFail;
    impl Drop for ClearSyncFail {
        fn drop(&mut self) {
            super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(false));
        }
    }
    let _guard = ClearSyncFail;
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(true));
    let err = adapter.delete_keystore(&pk).expect_err("directory sync must be reported");
    let msg = err.to_string();
    assert!(msg.contains("sync import secret directory"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
}

#[test]
fn import_rejects_a_keystore_that_fails_validate() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let mut value: serde_json::Value = serde_json::from_str(&encrypt_json(&sk, password)).unwrap();
    value["version"] = serde_json::json!(3);
    let err = block_on(adapter.import_keystore(&value.to_string(), password))
        .expect_err("version 3 is not a keystore this client can decrypt");
    let msg = err.to_string();
    assert!(msg.contains("invalid keystore"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(!secret_file(keystore_dir.path(), &pk).exists());
}

#[cfg(unix)]
#[test]
fn import_secret_is_private_and_lands_before_the_keystore() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let partial = keystore_dir.path().join(format!("{}.json.partial", pubkey_hex(pk)));
    let secret = secret_file(keystore_dir.path(), &pk);
    let saw = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&saw);
    let secret_hook = secret.clone();
    let json_hook = json_path.clone();
    let partial_hook = partial.clone();
    let keystore_hook = keystore_dir.path().to_path_buf();
    adapter.set_after_secret_before_keystore_hook(Arc::new(move || {
        let file_mode =
            std::fs::symlink_metadata(&secret_hook).unwrap().permissions().mode() & 0o777;
        let dir_mode =
            std::fs::symlink_metadata(secret_hook.parent().unwrap()).unwrap().permissions().mode()
                & 0o777;
        let staged_outside = std::fs::read_dir(&keystore_hook).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().ends_with(".keymanager-secret.partial")
        });
        flag.store(
            secret_hook.is_file()
                && file_mode == 0o600
                && dir_mode == 0o700
                && !json_hook.exists()
                && !partial_hook.exists()
                && !staged_outside,
            Ordering::SeqCst,
        );
    }));
    let json = encrypt_json(&sk, password);
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(saw.load(Ordering::SeqCst), "the secret must be durable before the keystore is staged");
    assert_eq!(std::fs::read(&secret).unwrap(), password.as_bytes());
    assert_eq!(std::fs::symlink_metadata(&secret).unwrap().permissions().mode() & 0o777, 0o600);
}

#[tracing_test::traced_test]
#[test]
fn failed_import_reports_a_secret_directory_sync_failure() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    adapter.fail_after_keystore_rename();
    adapter.set_before_discard_hook(Arc::new(|| {
        super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.set(true));
    }));
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let err = block_on(adapter.import_keystore(&encrypt_json(&sk, password), password))
        .expect_err("injected failure");
    assert!(err.to_string().contains("injected publish failure"), "{err}");
    assert!(!err.to_string().contains(password), "{err}");
    assert!(logs_contain("sync import secret directory"));
    assert!(logs_contain("failed to remove an import password secret after a failed import"));
    assert!(!logs_contain(password));
    assert!(!keystore_dir.path().join(format!("{}.json", pubkey_hex(pk))).exists());
    assert!(!secret_file(keystore_dir.path(), &pk).exists());
}

#[test]
fn fail_after_keystore_rename_removes_the_secret() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    adapter.fail_after_keystore_rename();
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json = encrypt_json(&sk, password);
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("injected failure");
    assert!(err.to_string().contains("injected publish failure"), "{err}");
    assert!(!keystore_dir.path().join(format!("{}.json", pubkey_hex(pk))).exists());
    assert!(!secret_file(keystore_dir.path(), &pk).exists());
}

#[test]
fn delete_removes_the_secret_and_reimport_writes_a_fresh_one() {
    let first = "import-only-testpass";
    let second = "reimport-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, first), first)).expect("import");
    let secret = secret_file(keystore_dir.path(), &pk);
    assert_eq!(std::fs::read(&secret).unwrap(), first.as_bytes());
    assert!(adapter.delete_keystore(&pk).unwrap());
    assert!(!secret.exists(), "DELETE removes the secret before the denylist");
    block_on(adapter.import_keystore(&encrypt_json(&sk, second), second)).expect("reimport");
    assert_eq!(std::fs::read(&secret).unwrap(), second.as_bytes());
}

#[test]
fn duplicate_import_keeps_the_original_secret() {
    let first = "import-only-testpass";
    let second = "reimport-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, first), first)).expect("import");
    let err = block_on(adapter.import_keystore(&encrypt_json(&sk, second), second))
        .expect_err("duplicate");
    assert!(matches!(err, ImportKeystoreError::Duplicate), "{err}");
    assert_eq!(std::fs::read(secret_file(keystore_dir.path(), &pk)).unwrap(), first.as_bytes());
}

#[cfg(unix)]
#[test]
fn import_refuses_a_secret_directory_symlink() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), keystore_dir.path().join(".rvc.keymanager-secrets"))
        .unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let err = block_on(adapter.import_keystore(&encrypt_json(&sk, password), password))
        .expect_err("symlink secrets dir");
    let message = err.to_string();
    assert!(message.contains("escapes"), "{message}");
    assert!(!message.contains(password), "{message}");
    let outside_names: Vec<_> = std::fs::read_dir(outside.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(outside_names.is_empty(), "the secret must not be written outside: {outside_names:?}");
}

#[cfg(unix)]
#[test]
fn import_forces_0700_on_an_existing_secrets_directory() {
    use std::os::unix::fs::PermissionsExt;

    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let secrets = keystore_dir.path().join(".rvc.keymanager-secrets");
    std::fs::create_dir(&secrets).unwrap();
    let mut perms = std::fs::metadata(&secrets).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&secrets, perms).unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let mode = std::fs::symlink_metadata(&secrets).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "an existing secrets directory is tightened to 0700");
}

fn keystore_document(pubkey: &Pubkey, uppercase: bool) -> String {
    let mut hex_key = hex::encode(pubkey);
    if uppercase {
        hex_key.make_ascii_uppercase();
    }
    format!(r#"{{"pubkey":"{hex_key}"}}"#)
}

fn neighbour_pubkey(pubkey: &Pubkey, index: usize) -> Pubkey {
    let mut bytes = *pubkey;
    bytes[index] ^= 0xff;
    bytes
}

fn write_named_keystore(dir: &std::path::Path, name: &str, pubkey: &Pubkey, uppercase: bool) {
    std::fs::write(dir.join(name), keystore_document(pubkey, uppercase)).unwrap();
}

fn write_secret_bytes(dir: &std::path::Path, pubkey: &Pubkey, bytes: &[u8]) {
    let secrets = dir.join(".rvc.keymanager-secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join(pubkey_hex(pubkey)), bytes).unwrap();
}

fn write_sidecars(dir: &std::path::Path, pubkey: &Pubkey) {
    let hex_key = pubkey_hex(pubkey);
    std::fs::write(import_meta_path(dir, pubkey), b"{}").unwrap();
    std::fs::write(dir.join(format!("{hex_key}.import_meta.json.partial")), b"{}").unwrap();
    std::fs::write(dir.join(format!("{hex_key}.import_meta.json.removing.1")), b"{}").unwrap();
}

fn sidecar_paths(dir: &std::path::Path, pubkey: &Pubkey) -> [std::path::PathBuf; 3] {
    let hex_key = pubkey_hex(pubkey);
    [
        import_meta_path(dir, pubkey),
        dir.join(format!("{hex_key}.import_meta.json.partial")),
        dir.join(format!("{hex_key}.import_meta.json.removing.1")),
    ]
}

fn reloaded_denylist(dir: &std::path::Path) -> crate::deletion_denylist::DeletionDenylist {
    crate::deletion_denylist::DeletionDenylist::load(dir).expect("denylist reloads")
}

struct ClearKeystoreUnlinkFail;
impl Drop for ClearKeystoreUnlinkFail {
    fn drop(&mut self) {
        super::super::keystore::KEYSTORE_UNLINK_FAILS.with(|flag| flag.set(false));
    }
}

fn arm_keystore_unlink_fail() -> ClearKeystoreUnlinkFail {
    super::super::keystore::KEYSTORE_UNLINK_FAILS.with(|flag| flag.set(true));
    ClearKeystoreUnlinkFail
}

#[test]
fn delete_not_loaded_key_removes_its_keystore_and_reports_deleted() {
    let cases = [("canonical", false), ("validator1.json", true), ("decoy-name", false)];
    for (case, uppercase) in cases {
        let keystore_dir = TempDir::new().unwrap();
        let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let other = test_pubkey(0xAB);
        assert!(!composite.has_local_key(&pk));
        let target_name = match case {
            "canonical" => format!("{}.json", pubkey_hex(pk)),
            "validator1.json" | "decoy-name" => "validator1.json".to_string(),
            other => panic!("unknown case {other}"),
        };
        if case == "decoy-name" {
            // The canonical filename belongs to a different key. Matching is
            // the pubkey inside the JSON, not the file name.
            write_named_keystore(
                keystore_dir.path(),
                &format!("{}.json", pubkey_hex(pk)),
                &other,
                false,
            );
        }
        write_named_keystore(keystore_dir.path(), &target_name, &pk, uppercase);
        let neighbor_name = format!("neighbor-{}-extra.json", hex::encode(pk));
        write_named_keystore(keystore_dir.path(), &neighbor_name, &other, false);
        write_secret_bytes(keystore_dir.path(), &pk, b"secret-material");
        write_secret_bytes(keystore_dir.path(), &other, b"other-secret");
        write_sidecars(keystore_dir.path(), &pk);
        write_sidecars(keystore_dir.path(), &other);

        let removed = adapter.delete_keystore(&pk).expect(case);
        assert!(removed, "{case}");
        assert!(!keystore_dir.path().join(&target_name).exists(), "{case}");
        assert!(!secret_file(keystore_dir.path(), &pk).exists(), "{case}");
        for path in sidecar_paths(keystore_dir.path(), &pk) {
            assert!(!path.exists(), "{case}: {}", path.display());
        }
        assert!(keystore_dir.path().join(&neighbor_name).exists(), "{case}");
        assert!(secret_file(keystore_dir.path(), &other).exists(), "{case}");
        for path in sidecar_paths(keystore_dir.path(), &other) {
            assert!(path.exists(), "{case}: {}", path.display());
        }
        if case == "decoy-name" {
            assert!(
                keystore_dir.path().join(format!("{}.json", pubkey_hex(pk))).exists(),
                "a canonical name whose JSON pubkey is a different key survives"
            );
        }
        let denylist = reloaded_denylist(keystore_dir.path());
        assert!(denylist.contains(&pk), "{case}");
        assert!(!denylist.contains(&other), "{case}");
        assert!(!adapter.has_key(&pk));
    }
}

#[test]
fn delete_not_loaded_key_leaves_last_byte_first_byte_and_description_neighbours() {
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    assert!(!composite.has_local_key(&pk));
    let last = neighbour_pubkey(&pk, 47);
    let first = neighbour_pubkey(&pk, 0);
    let described = test_pubkey(0xCD);
    assert_ne!(last[47], pk[47]);
    assert_eq!(&last[..47], &pk[..47]);
    assert_ne!(first[0], pk[0]);
    assert_eq!(&first[1..], &pk[1..]);
    assert_ne!(described, pk);
    assert_ne!(last, first);

    let target_name = format!("{}.json", pubkey_hex(pk));
    write_named_keystore(keystore_dir.path(), &target_name, &pk, false);
    write_named_keystore(keystore_dir.path(), "last-byte.json", &last, false);
    write_named_keystore(keystore_dir.path(), "first-byte.json", &first, false);
    let target_hex = hex::encode(pk);
    let described_body =
        format!(r#"{{"pubkey":"{}","description":"backup {target_hex}"}}"#, hex::encode(described));
    assert!(described_body.contains(&target_hex));
    std::fs::write(keystore_dir.path().join("described.json"), &described_body).unwrap();
    for key in [&pk, &last, &first, &described] {
        write_secret_bytes(keystore_dir.path(), key, b"secret-material");
        write_sidecars(keystore_dir.path(), key);
    }

    let removed = adapter.delete_keystore(&pk).expect("delete");
    assert!(removed);
    assert!(!keystore_dir.path().join(&target_name).exists());
    assert!(!secret_file(keystore_dir.path(), &pk).exists());
    for path in sidecar_paths(keystore_dir.path(), &pk) {
        assert!(!path.exists(), "{}", path.display());
    }
    for name in ["last-byte.json", "first-byte.json", "described.json"] {
        assert!(keystore_dir.path().join(name).exists(), "{name} must survive");
    }
    for key in [&last, &first, &described] {
        assert!(secret_file(keystore_dir.path(), key).exists());
        for path in sidecar_paths(keystore_dir.path(), key) {
            assert!(path.exists(), "{}", path.display());
        }
    }
    let denylist = reloaded_denylist(keystore_dir.path());
    assert!(denylist.contains(&pk));
    assert!(!denylist.contains(&last));
    assert!(!denylist.contains(&first));
    assert!(!denylist.contains(&described));
}

#[test]
fn delete_not_loaded_key_writes_denylist_when_secret_removal_fails() {
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    assert!(!composite.has_local_key(&pk));
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    write_named_keystore(
        keystore_dir.path(),
        json_path.file_name().unwrap().to_str().unwrap(),
        &pk,
        false,
    );
    write_secret_bytes(keystore_dir.path(), &pk, b"secret-material");
    write_sidecars(keystore_dir.path(), &pk);
    let secret = secret_file(keystore_dir.path(), &pk);

    let _guard = arm_remove_fail();
    let err = adapter.delete_keystore(&pk).expect_err("secret removal must be reported");
    assert!(matches!(err, keymanager_api::traits::DeleteKeystoreError::Io(_)), "{err}");
    assert!(!err.to_string().contains("secret-material"), "{err}");
    assert!(!json_path.exists(), "the keystore is unlinked before the secret step");
    assert!(secret.exists(), "the secret remains when removal fails");
    for path in sidecar_paths(keystore_dir.path(), &pk) {
        assert!(path.exists(), "sidecars wait for a successful secret removal: {}", path.display());
    }
    assert!(reloaded_denylist(keystore_dir.path()).contains(&pk));
    drop(_guard);

    let retry = adapter.delete_keystore(&pk).expect("retry");
    assert!(!retry, "a retry that only removes a leftover secret is not a fresh delete");
    assert!(!secret.exists());
    for path in sidecar_paths(keystore_dir.path(), &pk) {
        assert!(!path.exists(), "{}", path.display());
    }
    assert!(reloaded_denylist(keystore_dir.path()).contains(&pk));
}

#[test]
fn delete_not_loaded_key_unlink_failure_returns_before_the_denylist() {
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    write_named_keystore(
        keystore_dir.path(),
        json_path.file_name().unwrap().to_str().unwrap(),
        &pk,
        false,
    );
    write_secret_bytes(keystore_dir.path(), &pk, b"secret-material");
    write_sidecars(keystore_dir.path(), &pk);
    let _guard = arm_keystore_unlink_fail();
    let err = adapter.delete_keystore(&pk).expect_err("unlink failure");
    assert!(matches!(err, keymanager_api::traits::DeleteKeystoreError::Io(_)), "{err}");
    let message = err.to_string();
    assert!(!message.contains(keystore_dir.path().to_str().unwrap()), "{message}");
    assert!(!message.contains("secret-material"), "{message}");
    assert!(json_path.exists(), "the keystore file remains");
    assert!(secret_file(keystore_dir.path(), &pk).exists());
    for path in sidecar_paths(keystore_dir.path(), &pk) {
        assert!(path.exists(), "{}", path.display());
    }
    assert!(!reloaded_denylist(keystore_dir.path()).contains(&pk));
}

#[cfg(unix)]
#[test]
fn delete_skips_a_keystore_symlink_that_resolves_outside_the_directory() {
    let keystore_dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let outside_file = outside.path().join("outside.json");
    std::fs::write(&outside_file, keystore_document(&pk, false)).unwrap();
    let link = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    std::os::unix::fs::symlink(&outside_file, &link).unwrap();
    let removed = adapter.delete_keystore(&pk).expect("symlink is skipped");
    assert!(!removed, "a symlink outside keystore_path is not a removed keystore");
    assert!(link.exists(), "the symlink stays");
    assert!(outside_file.exists(), "the outside file stays");
    assert_eq!(std::fs::read(&outside_file).unwrap(), keystore_document(&pk, false).as_bytes());
}

struct RestoreDirPerms(std::path::PathBuf);

impl Drop for RestoreDirPerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&self.0) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&self.0, perms);
        }
    }
}

fn reset_dir_sync_calls() {
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_CALLS.with(|slot| slot.set(0));
}

fn dir_sync_calls() -> u32 {
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_CALLS.with(|slot| slot.get())
}

struct ClearSyncFailOnCall;
impl Drop for ClearSyncFailOnCall {
    fn drop(&mut self) {
        super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.set(0));
    }
}

#[test]
fn delete_fsyncs_the_keystore_directory() {
    let password = "import-only-testpass";
    // Secrets-dir sync when a secret is removed, then the keystore-dir sync on
    // every DELETE, including one that has nothing left to unlink.
    for (case, expected) in
        [("imported", 2), ("keystore-only", 1), ("not-loaded", 2), ("nothing-left", 1)]
    {
        let keystore_dir = TempDir::new().unwrap();
        let (adapter, composite, _validators) = validators_backed_adapter(keystore_dir.path());
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
        let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
        let secret = secret_file(keystore_dir.path(), &pk);
        match case {
            "keystore-only" => std::fs::remove_file(&secret).unwrap(),
            "not-loaded" => assert!(composite.remove_local_key(&pk)),
            "nothing-left" => {
                std::fs::remove_file(&secret).unwrap();
                std::fs::remove_file(&json_path).unwrap();
            }
            _ => {}
        }
        reset_dir_sync_calls();
        assert!(adapter.delete_keystore(&pk).expect(case), "{case}");
        assert_eq!(dir_sync_calls(), expected, "{case}");
        assert!(!json_path.exists(), "{case}");
        assert!(!secret.exists(), "{case}");
        assert!(reloaded_denylist(keystore_dir.path()).contains(&pk), "{case}");
        assert!(!adapter.has_key(&pk), "{case}");
    }
}

#[test]
fn delete_reports_a_keystore_dir_sync_failure_and_keeps_the_key() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let _guard = ClearSyncFailOnCall;
    reset_dir_sync_calls();
    // Call 1 is the secrets directory, call 2 the keystore directory.
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.set(2));
    let err = adapter.delete_keystore(&pk).expect_err("the keystore directory sync is reported");
    let msg = err.to_string();
    assert!(msg.contains("sync keystore directory"), "{msg}");
    let synced = format!("sync import secret directory {} failed", keystore_dir.path().display());
    assert!(msg.contains(&synced), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(
        reloaded_denylist(keystore_dir.path()).contains(&pk),
        "a failed keystore-dir sync still writes the denylist"
    );
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
    assert!(!json_path.exists());
    assert!(!secret_file(keystore_dir.path(), &pk).exists());

    assert!(adapter.delete_keystore(&pk).expect("retry"));
    assert_eq!(dir_sync_calls(), 3, "the retry fsyncs the keystore directory again");
    assert!(!adapter.has_key(&pk));
}

#[test]
fn delete_reports_both_a_secret_removal_and_a_keystore_dir_sync_failure() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let _remove = arm_remove_fail();
    let _sync = ClearSyncFailOnCall;
    reset_dir_sync_calls();
    // The secret is not removed, so the only directory sync is the keystore's.
    super::super::keystore::IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.set(1));
    let err = adapter.delete_keystore(&pk).expect_err("both failures are reported");
    let msg = err.to_string();
    assert!(msg.contains("remove import password secret"), "{msg}");
    assert!(msg.contains("sync keystore directory"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert_eq!(dir_sync_calls(), 1);
    assert!(reloaded_denylist(keystore_dir.path()).contains(&pk));
    assert!(adapter.has_key(&pk));
    assert!(secret_file(keystore_dir.path(), &pk).exists());
}

#[test]
fn delete_skips_the_keystore_dir_sync_when_the_directory_is_missing() {
    let root = TempDir::new().unwrap();
    let missing = root.path().join("missing");
    let (adapter, _composite, _validators) = validators_backed_adapter(&missing);
    let pk = test_pubkey(0x5A);
    reset_dir_sync_calls();
    let removed = adapter.delete_keystore(&pk).expect("a missing keystore directory is skipped");
    assert!(!removed);
    assert_eq!(dir_sync_calls(), 0);
    assert!(reloaded_denylist(&missing).contains(&pk));
}

/// With keystore locking off, boot continues when `keystore_path` is absent
/// and keys come from a secret provider. DELETE then creates `keystore_path`
/// through the denylist insert, and every directory that gains an entry is
/// fsynced before `deleted`.
#[test]
fn delete_with_an_absent_keystore_path_fsyncs_every_directory_the_denylist_creates() {
    use crate::deletion_denylist::{take_syncs, Synced};

    let root = TempDir::new().unwrap();
    let absent = root.path().join("absent");
    let keystore_path = absent.join("keystore");
    let slashing_db_path = root.path().join("slashing.db");
    SlashingDb::open(&slashing_db_path).unwrap();
    let config = crate::config::Config {
        keystore_path: keystore_path.clone(),
        slashing_db_path,
        disable_keystore_locking: true,
        ..Default::default()
    };
    let handles = crate::bootstrap::open_slashing_db(&config, false, false)
        .expect("boot continues without a keystore directory");
    assert!(!absent.exists());

    let composite = create_empty_composite_signer();
    let (adapter, _, _) = test_keystore_adapter(keystore_path.clone(), Arc::clone(&composite));
    let adapter = adapter.with_denylist(Arc::clone(&handles.denylist));
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    composite.add_local_key(sk);

    reset_dir_sync_calls();
    take_syncs();
    assert!(adapter.delete_keystore(&pk).expect("deleted"));
    assert_eq!(dir_sync_calls(), 0, "no keystore directory existed to fsync");
    assert_eq!(
        take_syncs(),
        [
            Synced::File(keystore_path.join(".rvc.deleted_keys")),
            Synced::Dir(root.path().to_path_buf()),
            Synced::Dir(absent),
            Synced::Dir(keystore_path.clone()),
        ]
    );
    assert!(!adapter.has_key(&pk));
    assert!(reloaded_denylist(&keystore_path).contains(&pk));
}

#[test]
fn delete_with_an_unremovable_secret_still_denylists() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    // `remove_file` on a non-empty directory fails in the kernel for every
    // euid (EISDIR on Linux, EPERM on macOS). No hook, no chmod.
    let secret = secret_file(keystore_dir.path(), &pk);
    std::fs::remove_file(&secret).unwrap();
    std::fs::create_dir(&secret).unwrap();
    std::fs::write(secret.join("pinned"), b"pinned").unwrap();
    let err = adapter.delete_keystore(&pk).expect_err("a real unlink failure is reported");
    let msg = err.to_string();
    assert!(msg.contains("remove import password secret"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(reloaded_denylist(keystore_dir.path()).contains(&pk));
    assert!(adapter.has_key(&pk), "the key stays registered so DELETE can be retried");
    assert!(secret.join("pinned").exists());
    assert!(!keystore_dir.path().join(format!("{}.json", pubkey_hex(pk))).exists());
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
        std::fs::set_permissions(&target, entry.metadata().unwrap().permissions()).unwrap();
    }
}

#[test]
fn reimport_after_a_crash_between_secret_and_keystore_succeeds() {
    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let crash = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json = encrypt_json(&sk, password);
    let (source, image) = (keystore_dir.path().to_path_buf(), crash.path().to_path_buf());
    adapter.set_after_secret_before_keystore_hook(Arc::new(move || copy_dir(&source, &image)));
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(secret_file(crash.path(), &pk).is_file(), "the crash image has the secret");
    let canonical = crash.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!canonical.exists(), "the crash image has no keystore");

    std::fs::write(crash.path().join("notes.json"), b"{}").unwrap();
    let boot = || {
        let config = crate::config::Config {
            keystore_path: crash.path().to_path_buf(),
            ..Default::default()
        };
        crate::config::ServiceBuilder::new(config).build_key_manager()
    };
    let booted = boot().expect("a secret with no keystore warns");
    assert!(!booted.contains(&pk));

    let (reimport, _composite, _validators) = validators_backed_adapter(crash.path());
    block_on(reimport.import_keystore(&json, password)).expect("re-import over the crash image");
    assert!(canonical.is_file());
    assert!(boot().expect("boot after the re-import").contains(&pk));
}

/// Regular files under `dir`, relative and sorted.
fn files_under(dir: &std::path::Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path.strip_prefix(dir).unwrap().display().to_string());
            }
        }
    }
    files.sort();
    files
}

/// What a keystore import of a remote pubkey leaves behind.
#[derive(Debug, PartialEq)]
struct AfterLocalImport {
    is_duplicate: bool,
    local: bool,
    remote: bool,
    secret_written: bool,
    files: Vec<String>,
}

/// 749-1, reverse direction. With its own `PubkeyMap` the keystore adapter's
/// later map check cannot see K, so only the backend check refuses it. Wired
/// as `build_keymanager_api` does (one map, one `TrackedKeys`), the refusal
/// comes before the import secret is written.
#[test]
fn local_import_of_a_remote_pubkey_is_a_duplicate() {
    for shared in [false, true] {
        let composite = create_empty_composite_signer();
        let keystore_dir = TempDir::new().unwrap();
        let (adapter, pubkey_map, _rx) =
            test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
        let (remote, _remote_rx) = if shared {
            shared_remote_adapter(
                Arc::clone(&composite),
                pubkey_map,
                Arc::clone(&adapter.tracked_keys),
            )
        } else {
            let (remote, _, rx) = test_remote_adapter(Arc::clone(&composite), None);
            (remote, rx)
        };
        let secret_written = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&secret_written);
        adapter.set_after_secret_before_keystore_hook(Arc::new(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        remote
            .import_remote_key(pk, "https://signer.example.com".to_string())
            .expect("remote import");

        let result = block_on(adapter.import_keystore(&encrypt_json(&sk, "testpass"), "testpass"));

        assert_eq!(
            AfterLocalImport {
                is_duplicate: matches!(result, Err(ImportKeystoreError::Duplicate)),
                local: composite.has_local_key(&pk),
                remote: composite.has_remote_key(&pk),
                secret_written: secret_written.load(std::sync::atomic::Ordering::SeqCst),
                files: files_under(keystore_dir.path()),
            },
            AfterLocalImport {
                is_duplicate: true,
                local: false,
                remote: true,
                secret_written: false,
                files: Vec::new(),
            },
            "shared map and lock: {shared}; import {result:?}"
        );
    }
}

/// What a keystore import of a gRPC remote pubkey leaves behind.
#[derive(Debug, PartialEq)]
struct AfterGrpcKeyImport {
    is_duplicate: bool,
    local: bool,
    remote: bool,
    grpc: bool,
    secret_written: bool,
    files: Vec<String>,
    pubkey_map: Vec<Pubkey>,
    key_gen: u64,
}

/// K is only in `grpc_remote`. The keystore import call site refuses K before
/// the import secret is written, both with K in the `PubkeyMap` as boot leaves
/// it and without, where the later map check cannot see K.
#[test]
fn local_import_of_a_grpc_pubkey_is_a_duplicate() {
    for in_pubkey_map in [false, true] {
        let composite = create_empty_composite_signer();
        let keystore_dir = TempDir::new().unwrap();
        let (adapter, pubkey_map, key_gen) =
            test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
        let sk = add_grpc_remote_key(&composite);
        let public = sk.public_key();
        let pk = public.to_bytes();
        if in_pubkey_map {
            pubkey_map.write().insert(pk, public);
        }
        let map_before: Vec<Pubkey> = pubkey_map.read().keys().copied().collect();
        let secret_written = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&secret_written);
        adapter.set_after_secret_before_keystore_hook(Arc::new(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let result = block_on(adapter.import_keystore(&encrypt_json(&sk, "testpass"), "testpass"));

        assert_eq!(
            AfterGrpcKeyImport {
                is_duplicate: matches!(result, Err(ImportKeystoreError::Duplicate)),
                local: composite.has_local_key(&pk),
                remote: composite.has_remote_key(&pk),
                grpc: composite.has_grpc_remote(&pk),
                secret_written: secret_written.load(std::sync::atomic::Ordering::SeqCst),
                files: files_under(keystore_dir.path()),
                pubkey_map: pubkey_map.read().keys().copied().collect(),
                key_gen: *key_gen.borrow(),
            },
            AfterGrpcKeyImport {
                is_duplicate: true,
                local: false,
                remote: false,
                grpc: true,
                secret_written: false,
                files: Vec::new(),
                pubkey_map: map_before,
                key_gen: 0,
            },
            "K in the PubkeyMap: {in_pubkey_map}; import {result:?}"
        );
    }
}

/// Spins until `done()`. The deadline is a hang guard only.
fn spin_until(what: &str, done: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "hang guard: {what}");
        std::thread::yield_now();
    }
}

/// The points inside a remote import or delete where its section hook runs.
const SECTION_POINTS: [&str; 2] = ["before_change", "after_change"];

/// A keystore import started from inside a remote adapter section.
struct ImportInSection {
    /// The import blocked on `TrackedKeys` before it could end.
    waited: bool,
    thread: std::thread::JoinHandle<Result<Pubkey, ImportKeystoreError>>,
}

type ImportInSectionSlot = Arc<parking_lot::Mutex<Option<ImportInSection>>>;

/// Arms `remote` so that its next import or delete, at `point` with both
/// locks held, starts a keystore import of `sk` on another thread. The section
/// goes on only once that import has either blocked on `TrackedKeys` or ended.
fn import_inside_the_next_remote_section(
    remote: &RemoteKeyManagerAdapter,
    point: &'static str,
    keystore: &Arc<KeystoreManagerAdapter>,
    sk: &SecretKey,
) -> ImportInSectionSlot {
    let slot = ImportInSectionSlot::default();
    let filled = Arc::clone(&slot);
    let pending =
        parking_lot::Mutex::new(Some((Arc::clone(keystore), encrypt_json(sk, "testpass"))));
    remote.set_section_hook(Arc::new(move |at| {
        if at != point {
            return;
        }
        let Some((keystore, json)) = pending.lock().take() else {
            return;
        };
        let tracked_keys = Arc::clone(&keystore.tracked_keys);
        let before = tracked_keys.contended();
        let thread =
            std::thread::spawn(move || block_on(keystore.import_keystore(&json, "testpass")));
        spin_until("the keystore import neither blocked nor ended", || {
            tracked_keys.contended() > before || thread.is_finished()
        });
        let waited = tracked_keys.contended() > before;
        *filled.lock() = Some(ImportInSection { waited, thread });
    }));
    slot
}

/// Joins the import once the remote section has returned.
fn finish_import_in_section(slot: &ImportInSectionSlot) -> (bool, String) {
    let ImportInSection { waited, thread } =
        slot.lock().take().expect("the remote section ran the hook");
    spin_until("the keystore import did not end after the section", || thread.is_finished());
    let result = thread.join().expect("keystore import thread");
    (waited, format!("{:?}", result.map(|_| ())))
}

/// What a keystore import of K, started inside a remote section on K, leaves.
#[derive(Debug, PartialEq)]
struct AfterImportInSection {
    remote_op: String,
    local_import_waited: bool,
    local_import: String,
    local: bool,
    remote: bool,
    in_pubkey_map: bool,
    keystore_dir_empty: bool,
}

/// A remote import holds `TrackedKeys` from its duplicate check to its end. A
/// keystore import of K started just before or just after the remote insert
/// waits for that section, then finds the remote K and returns `duplicate`.
#[test]
fn keystore_import_inside_a_remote_import_waits_then_is_a_duplicate() {
    for point in SECTION_POINTS {
        let composite = create_empty_composite_signer();
        let keystore_dir = TempDir::new().unwrap();
        let (keystore, pubkey_map, _rx) =
            test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
        let keystore = Arc::new(keystore);
        let (remote, _remote_rx) = shared_remote_adapter(
            Arc::clone(&composite),
            pubkey_map.clone(),
            Arc::clone(&keystore.tracked_keys),
        );
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let local = import_inside_the_next_remote_section(&remote, point, &keystore, &sk);

        let imported = remote.import_remote_key(pk, "https://signer.example.com".to_string());
        let (local_import_waited, local_import) = finish_import_in_section(&local);

        assert_eq!(
            AfterImportInSection {
                remote_op: format!("{imported:?}"),
                local_import_waited,
                local_import,
                local: composite.has_local_key(&pk),
                remote: composite.has_remote_key(&pk),
                in_pubkey_map: pubkey_map.read().contains_key(&pk),
                keystore_dir_empty: files_under(keystore_dir.path()).is_empty(),
            },
            AfterImportInSection {
                remote_op: "Ok(())".to_string(),
                local_import_waited: true,
                local_import: "Err(Duplicate)".to_string(),
                local: false,
                remote: true,
                in_pubkey_map: true,
                keystore_dir_empty: true,
            },
            "keystore import started at {point}"
        );
    }
}

/// A remote DELETE holds `TrackedKeys` from its lookup to its end. A keystore
/// import of K started just before or just after the removal waits for that
/// section, then imports K.
#[test]
fn keystore_import_inside_a_remote_delete_waits_then_imports() {
    for point in SECTION_POINTS {
        let composite = create_empty_composite_signer();
        let keystore_dir = TempDir::new().unwrap();
        let (keystore, pubkey_map, _rx) =
            test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
        let keystore = Arc::new(keystore);
        let (remote, _remote_rx) = shared_remote_adapter(
            Arc::clone(&composite),
            pubkey_map.clone(),
            Arc::clone(&keystore.tracked_keys),
        );
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        remote.import_remote_key(pk, "https://signer.example.com".to_string()).expect("remote");
        let local = import_inside_the_next_remote_section(&remote, point, &keystore, &sk);

        let deleted = remote.delete_remote_key(&pk);
        let (local_import_waited, local_import) = finish_import_in_section(&local);

        assert_eq!(
            AfterImportInSection {
                remote_op: format!("{deleted:?}"),
                local_import_waited,
                local_import,
                local: composite.has_local_key(&pk),
                remote: composite.has_remote_key(&pk),
                in_pubkey_map: pubkey_map.read().contains_key(&pk),
                keystore_dir_empty: files_under(keystore_dir.path()).is_empty(),
            },
            AfterImportInSection {
                remote_op: "Ok(true)".to_string(),
                local_import_waited: true,
                local_import: "Ok(())".to_string(),
                local: true,
                remote: false,
                in_pubkey_map: true,
                keystore_dir_empty: false,
            },
            "keystore import started at {point}"
        );
    }
}
