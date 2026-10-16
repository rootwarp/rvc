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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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
        Arc::new(MonotonicEpochClock::new(0)),
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

/// Root can unlink a file in a mode `0500` directory, so a DAC denial is not
/// observable and must not be asserted.
#[cfg(unix)]
#[allow(unsafe_code)]
fn root_ignores_directory_mode() -> bool {
    // SAFETY: geteuid only reads this process's effective user id.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
#[test]
fn delete_reports_a_secret_removal_failure_and_keeps_the_key() {
    use std::os::unix::fs::PermissionsExt;

    if root_ignores_directory_mode() {
        return;
    }

    let password = "import-only-testpass";
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, _composite, _validators) = validators_backed_adapter(keystore_dir.path());
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(adapter.import_keystore(&encrypt_json(&sk, password), password)).expect("import");
    let secret = secret_file(keystore_dir.path(), &pk);
    let secrets_dir = secret.parent().unwrap().to_path_buf();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    struct RestoreMode(std::path::PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let Ok(meta) = std::fs::metadata(&self.0) else {
                return;
            };
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&self.0, perms);
        }
    }
    let _restore = RestoreMode(secrets_dir.clone());
    let mut perms = std::fs::metadata(&secrets_dir).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&secrets_dir, perms).unwrap();
    let err = adapter.delete_keystore(&pk).expect_err("secret removal must be reported");
    let msg = err.to_string();
    assert!(msg.contains("import password secret"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
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

#[cfg(unix)]
#[test]
fn delete_reports_a_secret_removal_failure_when_the_key_is_not_registered() {
    use std::os::unix::fs::PermissionsExt;

    if root_ignores_directory_mode() {
        return;
    }

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
    let secrets_dir = secret.parent().unwrap().to_path_buf();
    struct RestoreMode(std::path::PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let Ok(meta) = std::fs::metadata(&self.0) else {
                return;
            };
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&self.0, perms);
        }
    }
    let _restore = RestoreMode(secrets_dir.clone());
    let mut perms = std::fs::metadata(&secrets_dir).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&secrets_dir, perms).unwrap();
    let err = adapter.delete_keystore(&pk).expect_err("secret removal must be reported");
    let msg = err.to_string();
    assert!(msg.contains("import password secret"), "{msg}");
    assert!(!msg.contains(password), "{msg}");
    assert!(!adapter.has_key(&pk), "an unregistered key is not added back");
    assert!(secret.exists(), "the plaintext remains when removal fails");
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
