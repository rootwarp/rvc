use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey, Signer as _};
use rvc_secret_provider::{
    KeyMaterial, KeySourceManager, MockSecretProvider, RefreshService, SecretKeyEntry,
    SecretProviderError,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn make_raw_key_entry(
    id: &str,
    sk: &SecretKey,
) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
    #[allow(clippy::disallowed_methods)] // test-only comparison of key material already in scope
    let bytes: [u8; 32] = sk.to_bytes();
    (
        SecretKeyEntry { id: id.to_string(), pubkey_hex: None },
        Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
    )
}

#[tokio::test]
async fn test_mock_provider_keys_visible_in_key_manager_and_signable() {
    let sk = SecretKey::generate();
    let pubkey_bytes = sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "mock-cloud".to_string(),
        keys: vec![make_raw_key_entry("cloud-key-1", &sk)],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();
    let summary = ksm.load_all(&mut km).await.expect("load_all should succeed");

    assert_eq!(summary.per_provider.len(), 1);
    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(km.len(), 1);

    let signer = LocalSigner::new(km);
    let signing_root = [0xABu8; 32];
    let signature = signer.sign(&signing_root, &pubkey_bytes).await;
    assert!(signature.is_ok(), "should be able to sign with cloud-loaded key");
}

#[tokio::test]
async fn test_mixed_filesystem_and_cloud_keys_coexist() {
    let fs_sk = SecretKey::generate();
    let fs_pubkey_bytes = fs_sk.public_key().to_bytes();
    let mut km = KeyManager::new();
    km.insert(fs_sk);
    assert_eq!(km.len(), 1);

    let cloud_sk = SecretKey::generate();
    let cloud_pubkey_bytes = cloud_sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "mock-cloud".to_string(),
        keys: vec![make_raw_key_entry("cloud-key-1", &cloud_sk)],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let summary = ksm.load_all(&mut km).await.expect("load_all should succeed");

    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(km.len(), 2);

    let signer = LocalSigner::new(km);
    let signing_root = [0xCDu8; 32];

    let fs_sig = signer.sign(&signing_root, &fs_pubkey_bytes).await;
    assert!(fs_sig.is_ok(), "filesystem key should be signable");

    let cloud_sig = signer.sign(&signing_root, &cloud_pubkey_bytes).await;
    assert!(cloud_sig.is_ok(), "cloud key should be signable");
}

#[tokio::test]
async fn test_partial_failures_load_successful_keys_skip_failed() {
    let good_sk = SecretKey::generate();
    let good_pubkey_bytes = good_sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "partial-fail".to_string(),
        keys: vec![
            make_raw_key_entry("good-key", &good_sk),
            (
                SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                Err(SecretProviderError::Provider("network timeout".into())),
            ),
        ],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();
    let summary =
        ksm.load_all(&mut km).await.expect("load_all should succeed despite partial failure");

    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(summary.per_provider[0].skipped, 1);
    assert_eq!(summary.per_provider[0].errors.len(), 1);
    assert_eq!(km.len(), 1);

    let signer = LocalSigner::new(km);
    let signing_root = [0xEFu8; 32];
    let sig = signer.sign(&signing_root, &good_pubkey_bytes).await;
    assert!(sig.is_ok(), "good key should be signable after partial failure");
}

// --- Phase 2 integration tests (SM-13) ---

#[tokio::test]
async fn test_refresh_discovers_new_key_available_via_composite_signer() {
    let initial_sk = SecretKey::generate();
    let initial_pubkey = initial_sk.public_key().to_bytes();

    let new_sk = SecretKey::generate();
    let new_pubkey = new_sk.public_key().to_bytes();

    // Provider has both keys, but only initial_sk is "known"
    let provider = Arc::new(MockSecretProvider {
        name: "refresh-test".to_string(),
        keys: vec![
            make_raw_key_entry("initial-key", &initial_sk),
            make_raw_key_entry("new-key", &new_sk),
        ],
        list_error: None,
    });

    // Set up CompositeSigner with only the initial key
    let mut km = KeyManager::new();
    km.insert(initial_sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));

    // RefreshService knows about initial key only
    let mut known = HashSet::new();
    known.insert(initial_pubkey);

    let cancel = CancellationToken::new();
    let mut service = RefreshService::new(vec![provider], known, Duration::from_secs(60), cancel);

    // Run one refresh cycle
    let new_keys = service.refresh().await;
    assert_eq!(new_keys.len(), 1, "should discover exactly one new key");
    assert_eq!(new_keys[0].public_key().to_bytes(), new_pubkey);

    // Add discovered key to composite signer (mimics the on_new_key callback)
    for sk in new_keys {
        composite.add_local_key(sk);
    }

    // Verify both keys are now signable via CompositeSigner
    let signing_root = [0x42u8; 32];
    let sig1 = composite.sign(&signing_root, &initial_pubkey).await;
    assert!(sig1.is_ok(), "initial key should be signable");

    let sig2 = composite.sign(&signing_root, &new_pubkey).await;
    assert!(sig2.is_ok(), "newly discovered key should be signable via CompositeSigner");
}

#[tokio::test]
async fn test_metrics_populated_after_load_all() {
    use rvc_secret_provider::metrics::{
        RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_KEYS_LOADED,
        RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
    };

    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();

    let provider = MockSecretProvider {
        name: "integ-metrics".to_string(),
        keys: vec![
            make_raw_key_entry("k1", &sk1),
            make_raw_key_entry("k2", &sk2),
            (
                SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                Err(SecretProviderError::Provider("simulated failure".into())),
            ),
        ],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();
    ksm.load_all(&mut km).await.unwrap();

    // Gauge: 2 keys loaded for "integ-metrics" source
    let keys_loaded = RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["integ-metrics"]).get();
    assert_eq!(keys_loaded, 2.0, "Expected 2 keys loaded");

    // Counter: 1 error for "integ-metrics" source, type "provider"
    let errors =
        RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&["integ-metrics", "provider"]).get();
    assert!(errors >= 1, "Expected at least 1 error, got {}", errors);

    // Histogram: at least 1 observation for "integ-metrics" source
    let duration_count = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
        .with_label_values(&["integ-metrics"])
        .get_sample_count();
    assert!(
        duration_count >= 1,
        "Expected at least 1 duration observation, got {}",
        duration_count
    );
}
