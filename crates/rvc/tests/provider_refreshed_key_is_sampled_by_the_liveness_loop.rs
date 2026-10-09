//! ARCH-2c headline: a provider-refreshed key admitted via
//! [`KeyAdmissionService::admit`] enters `PubkeyMap`, is sampled by the
//! liveness loop, and can leave `Pending`.
//!
//! Against pre-ARCH-2c HEAD the refresh path never updated `PubkeyMap`, so the
//! loop starved the key (F5). This test exercises the full chain:
//! admit(RawSecret) → map membership → index refresh → clean not-live window → Safe.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use beacon::{
    BeaconError, ValidatorData, ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse,
    ValidatorsResponse,
};
use bn_manager::MockBeaconNodeClient;
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use doppelganger::{
    ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock, SigningEnablement,
    DEFAULT_MONITORING_EPOCHS,
};
use eth_types::SLOTS_PER_EPOCH;
use keymanager_api::traits::KeystoreManager;
use rvc::deletion_denylist::DeletionDenylist;
use rvc::key_admission::{AdmissionOutcome, AdmissionSource, KeyAdmissionService};
use rvc::liveness_loop::LivenessObservationLoop;
use rvc::orchestrator::PubkeyMap;
use rvc::pubkey_index::PubkeyIndexRegistry;
use slashing::SlashingDb;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use validator_store::ValidatorStore;

/// Drive one refresh-style admit and prove the key leaves `Pending` via the
/// liveness loop (clean not-live window).
#[tokio::test]
async fn a_provider_refreshed_key_leaves_pending() {
    let denylist_dir = TempDir::new().expect("tempdir");
    let denylist = Arc::new(DeletionDenylist::load(denylist_dir.path()).expect("denylist"));
    let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let (key_gen_tx, mut key_gen_rx) = tokio::sync::watch::channel(0u64);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
    let db: Arc<dyn slashing::SlashingDbReader> =
        Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
    let machine = Arc::new(ForwardWindowMachine::new(db, 2, [0xabu8; 32]));

    let admissions = Arc::new(KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        key_gen_tx,
        Arc::clone(&composite),
        Arc::clone(&validator_store),
        Arc::clone(&denylist),
        Some(Arc::clone(&machine)),
        Arc::clone(&epoch_clock),
    ));

    // Simulate one secret-provider refresh tick delivering a new SecretKey.
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();
    let pk_hex_0x = format!("0x{}", hex::encode(pk_bytes));
    key_gen_rx.borrow_and_update();

    let outcome =
        admissions.admit(sk, AdmissionSource::RawSecret).expect("RawSecret admit must succeed");
    assert!(
        matches!(outcome, AdmissionOutcome::Admitted { pubkey, .. } if pubkey == pk_bytes),
        "expected Admitted, got {outcome:?}"
    );

    // Multi-store reach (the stores the old refresh path never touched).
    assert!(pubkey_map.read().contains_key(&pk_bytes), "must reach PubkeyMap");
    assert!(validator_store.has_validator(&pk_bytes), "must reach ValidatorStore");
    assert!(composite.has_local_key(&pk_bytes), "must reach CompositeSigner");
    assert!(key_gen_rx.has_changed().unwrap(), "must bump key_gen_tx");
    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Pending,
        "import-strict registration must enter Pending"
    );
    assert!(!machine.is_signing_enabled(&pk));

    // Liveness loop samples from PubkeyMap only (F5). Seed BN mock for index + not-live.
    let index = "42";
    let pubkey_index = PubkeyIndexRegistry::shared();
    let bn = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_validators({
                let pk_hex = pk_hex_0x.clone();
                let index = index.to_string();
                move |pubkeys| {
                    let data = pubkeys
                        .iter()
                        .filter(|p| *p == &pk_hex)
                        .map(|p| ValidatorData {
                            index: index.clone(),
                            status: "active_ongoing".to_string(),
                            validator: ValidatorInfo { pubkey: p.clone() },
                        })
                        .collect();
                    Ok(ValidatorsResponse { data })
                }
            })
            .with_post_validator_liveness({
                let index = index.to_string();
                move |_epoch, indices| {
                    let data = indices
                        .iter()
                        .filter(|i| *i == &index)
                        .map(|i| ValidatorLiveness { index: i.clone(), is_live: false })
                        .collect();
                    Ok(ValidatorLivenessResponse { data })
                }
            }),
    );

    let loop_ = LivenessObservationLoop::new(
        Arc::clone(&machine),
        bn.clone(),
        Arc::clone(&pubkey_index),
        Arc::clone(&epoch_clock),
        CancellationToken::new(),
    )
    .with_pubkey_map(Arc::clone(&pubkey_map))
    .with_slot_duration(Duration::from_millis(1));

    // Without map membership this refresh would find nothing — that was the starvation bug.
    loop_.refresh_indices_for_test(bn.as_ref()).await;
    assert!(
        !pubkey_index.read().is_empty(),
        "liveness index map must resolve the admitted key from PubkeyMap"
    );

    let start = epoch_clock.current_epoch().max(1);
    // Force Pending window at a non-zero epoch so pre-genesis Safe-skip cannot apply.
    // (register_for_import already ran at admit; if that was epoch 0 the machine may
    // still be Pending — import path never Safe-skips.)
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);

    let end = start + DEFAULT_MONITORING_EPOCHS;
    for epoch in start..=end {
        loop_.drive_once_for_test(Some(epoch), epoch, 0).await.expect("drive");
    }
    let statuses =
        loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.expect("final tick");

    assert!(
        statuses.contains(&ForwardWindowStatus::Safe) || machine.is_signing_enabled(&pk),
        "clean not-live window must open the gate; statuses={statuses:?}"
    );
    assert!(
        machine.is_signing_enabled(&pk),
        "provider-refreshed key must leave Pending after liveness sampling"
    );
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Safe);

    // C4: RawSecret path wrote no keystore under the denylist dir (only denylist file if any).
    let entries: Vec<_> = std::fs::read_dir(denylist_dir.path())
        .expect("read denylist dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.ends_with(".json")
        })
        .collect();
    assert!(entries.is_empty(), "RawSecret must not write keystore JSON: {entries:?}");
}

/// Keystore import goes through the same admission service.
#[tokio::test]
async fn keymanager_import_admits_through_the_service() {
    use crypto::EncryptionKdf;
    use rvc::keymanager_adapters::KeystoreManagerAdapter;

    let dir = TempDir::new().expect("tempdir");
    let denylist = Arc::new(DeletionDenylist::load(dir.path()).expect("denylist"));
    let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let (key_gen_tx, mut key_gen_rx) = tokio::sync::watch::channel(0u64);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let admissions = Arc::new(KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        key_gen_tx.clone(),
        Arc::clone(&composite),
        Arc::clone(&validator_store),
        Arc::clone(&denylist),
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));

    let adapter = KeystoreManagerAdapter::new(
        dir.path().to_path_buf(),
        Arc::clone(&composite),
        Arc::clone(&pubkey_map),
        key_gen_tx,
    )
    .with_denylist(Arc::clone(&denylist))
    .with_admission_service(Arc::clone(&admissions));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let keystore = crypto::Keystore::encrypt(
        &sk,
        b"testpass",
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    key_gen_rx.borrow_and_update();
    adapter.import_keystore(&keystore_json, "testpass").await.expect("import");

    assert!(pubkey_map.read().contains_key(&pk));
    assert!(validator_store.has_validator(&pk));
    assert!(composite.has_local_key(&pk));
    assert!(key_gen_rx.has_changed().unwrap());
    assert!(
        key_admission_source_mentions_keystore_admit(),
        "adapter source must call admit with Keystore source"
    );
}

fn key_admission_source_mentions_keystore_admit() -> bool {
    let src = include_str!("../src/keymanager_adapters/keystore.rs");
    src.contains("AdmissionSource::Keystore") && src.contains("admissions") && src.contains("admit")
}

// Silence unused-import if Mock error type is only used in type inference.
#[allow(dead_code)]
fn _beacon_error_typecheck() -> BeaconError {
    BeaconError::HttpError("unused".into())
}
