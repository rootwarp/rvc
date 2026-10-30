use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use observability::logging::TruncatedPubkey;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::key_source_manager::{
    fetch_provider_keys, record_list_keys_failure, KeysLoadedUpdate, DEFAULT_FETCH_CONCURRENCY,
    DEFAULT_KEY_FETCH_TIMEOUT,
};
use crate::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED;
use crate::SecretKeyEntry;
use crate::SecretProvider;
use crypto::SecretKey;

/// Predicate: return `true` if a pubkey must not be loaded (Keymanager DELETE denylist).
pub type DenylistCheck = Arc<dyn Fn(&[u8; 48]) -> bool + Send + Sync>;

pub struct RefreshService {
    providers: Vec<Arc<dyn SecretProvider>>,
    known_pubkeys: HashSet<[u8; 48]>,
    /// `(provider slot, secret id) → pubkey` for ids this process has already resolved.
    ///
    /// The slot is the provider's index in [`Self::providers`]. That vec is fixed by
    /// [`Self::new`] / [`Self::with_denylist`]; nothing adds, removes, or reorders it,
    /// so the slot stays stable for the life of the service. [`SecretProvider::name`]
    /// is a log label, not an identity: two providers may share a name, and the same
    /// opaque id under two slots is two keys.
    ///
    /// An entry is inserted only after a fetch returns that pubkey (admitted, already
    /// known, or skipped by the post-fetch denylist). A fetch error, timeout, or
    /// decrypt failure is not inserted. [`Self::run`] drops every entry whose pubkey
    /// `on_new_key` rejects. The map holds pubkey bytes only: no [`SecretKey`],
    /// keystore JSON, or password.
    known_ids: HashMap<(usize, String), [u8; 48]>,
    /// Live denylist check (SEC-1b). Consulted every refresh so a key deleted
    /// mid-process is not re-added from the secret provider.
    is_denied: Option<DenylistCheck>,
    interval: Duration,
    fetch_timeout: Duration,
    fetch_concurrency: usize,
    cancel_token: CancellationToken,
}

impl RefreshService {
    pub fn new(
        providers: Vec<Arc<dyn SecretProvider>>,
        known_pubkeys: HashSet<[u8; 48]>,
        interval: Duration,
        cancel_token: CancellationToken,
    ) -> Self {
        Self::with_denylist(providers, known_pubkeys, None, interval, cancel_token)
    }

    /// Like [`new`], but never re-discovers pubkeys for which `is_denied` returns true.
    pub fn with_denylist(
        providers: Vec<Arc<dyn SecretProvider>>,
        known_pubkeys: HashSet<[u8; 48]>,
        is_denied: Option<DenylistCheck>,
        interval: Duration,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            providers,
            known_pubkeys,
            known_ids: HashMap::new(),
            is_denied,
            interval,
            fetch_timeout: DEFAULT_KEY_FETCH_TIMEOUT,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
            cancel_token,
        }
    }

    /// Override the per-key fetch timeout (shared pipeline default is 30s).
    pub fn with_fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// Override max concurrent `fetch_key` calls per provider.
    pub fn with_fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetch_concurrency = concurrency.max(1);
        self
    }

    pub async fn refresh(&mut self) -> Vec<SecretKey> {
        let start = Instant::now();
        let mut new_keys = Vec::new();

        for (slot, provider) in self.providers.iter().enumerate() {
            info!(
                source = %provider.name(),
                interval_secs = self.interval.as_secs(),
                "Refresh cycle start"
            );
            let provider_name = provider.name().to_string();
            let timer = Instant::now();

            let entries = match provider.list_keys().await {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        provider = %provider_name,
                        error = %e,
                        "Failed to list keys during refresh"
                    );
                    record_list_keys_failure(&provider_name, &e, timer);
                    continue;
                }
            };

            // known_pubkeys / known_ids bookkeeping stays outside the shared pipeline.
            // Skip a fetch when list metadata already names a known pubkey, or when this
            // slot has resolved the id to a pubkey that is known or denylisted *now*.
            // `is_denied` is read every cycle, so a pubkey that leaves the denylist is
            // fetched again. The denylist check itself stays inside fetch_provider_keys
            // (hex precheck + post-fetch public_key check) for anything we do fetch.
            let to_fetch: Vec<_> =
                entries.into_iter().filter(|entry| self.should_fetch(slot, entry)).collect();

            // Idle cycle: nothing to fetch — do not wipe KEYS_LOADED or observe a
            // no-op load duration sample (RF4-14 Findings 1 + 3).
            if to_fetch.is_empty() {
                continue;
            }

            let fetch = fetch_provider_keys(
                Arc::clone(provider),
                &to_fetch,
                self.is_denied.clone(),
                self.fetch_timeout,
                self.fetch_concurrency,
                timer,
                // Never .set the source-level gauge from a refresh delta.
                KeysLoadedUpdate::LeaveUnchanged,
            )
            .await;

            let mut admitted_this_provider = 0usize;
            for (id, sk) in fetch.keys {
                let pubkey = sk.public_key().to_bytes();
                // Cache before the known-pubkey drop so an opaque id whose key is
                // already loaded is not fetched again. `sk` still drops (and zeroizes)
                // on the continue below. Denylist was applied inside fetch_provider_keys.
                self.known_ids.insert((slot, id), pubkey);
                if self.known_pubkeys.contains(&pubkey) {
                    continue;
                }

                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    source = %provider_name,
                    "Discovered new key during refresh"
                );

                self.known_pubkeys.insert(pubkey);
                new_keys.push(sk);
                admitted_this_provider += 1;
            }
            for (id, pubkey) in fetch.denied {
                self.known_ids.insert((slot, id), pubkey);
            }

            // Increment (never overwrite) the boot-set source total by newly admitted keys.
            if admitted_this_provider > 0 {
                RVC_SECRET_PROVIDER_KEYS_LOADED
                    .with_label_values(&[provider_name.as_str()])
                    .add(admitted_this_provider as f64);
            }
        }

        let total = self.known_pubkeys.len();
        let new_count = new_keys.len();
        let duration_ms = start.elapsed().as_millis();
        info!(
            keys_refreshed_count = new_count,
            total = total,
            duration_ms = duration_ms,
            "Refresh cycle completed"
        );

        new_keys
    }

    /// Skip this id without calling `fetch_key`.
    ///
    /// A cached id is skipped only when its pubkey is already loaded or is
    /// denylisted on this call. A cache hit whose pubkey is neither is fetched
    /// again, which is how a cleared denylist entry is loaded. A rejected key
    /// is removed from the map, so the next cycle is a cache miss.
    fn should_fetch(&self, slot: usize, entry: &SecretKeyEntry) -> bool {
        if let Some(pubkey) = self.cached_pubkey(slot, &entry.id) {
            if self.known_pubkeys.contains(&pubkey)
                || self.is_denied.as_ref().is_some_and(|deny| deny(&pubkey))
            {
                return false;
            }
        }
        if let Some(ref hex_str) = entry.pubkey_hex {
            if let Ok(pk) = eth_types::canonical::pubkey_hex::parse_pubkey_hex(hex_str) {
                if self.known_pubkeys.contains(pk.as_bytes()) {
                    return false;
                }
            }
        }
        true
    }

    fn cached_pubkey(&self, slot: usize, id: &str) -> Option<[u8; 48]> {
        self.known_ids.get(&(slot, id.to_owned())).copied()
    }

    /// Drop a rejected key from both sets so the next cycle offers it again.
    fn forget_rejected_pubkey(&mut self, pubkey: &[u8; 48]) {
        self.known_pubkeys.remove(pubkey);
        self.known_ids.retain(|_, cached| cached != pubkey);
    }

    /// `on_new_key` returns `true` when the key was kept. `false` drops it from
    /// `known_pubkeys` and from every `known_ids` entry that maps to it, so the
    /// next refresh offers it again.
    ///
    /// Returns the service after `cancel_token` fires.
    pub async fn run<F>(mut self, mut on_new_key: F) -> Self
    where
        F: FnMut(SecretKey) -> bool,
    {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {
                    let new_keys = self.refresh().await;
                    for sk in new_keys {
                        let pubkey = sk.public_key().to_bytes();
                        if !on_new_key(sk) {
                            self.forget_rejected_pubkey(&pubkey);
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => break,
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use parking_lot::Mutex;

    use async_trait::async_trait;
    use tracing::field::Visit;
    use tracing_subscriber::layer::SubscriberExt;
    use zeroize::Zeroizing;

    use super::*;
    use crate::key_source_manager::mock::MockSecretProvider;
    use crate::{KeyMaterial, SecretKeyEntry, SecretProvider, SecretProviderError};

    fn make_raw_key_entry(
        id: &str,
        sk: &SecretKey,
    ) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
        let bytes: [u8; 32] = sk.to_bytes();
        (
            SecretKeyEntry { id: id.to_string(), pubkey_hex: None },
            Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
        )
    }

    fn make_raw_key_entry_with_pubkey(
        id: &str,
        sk: &SecretKey,
    ) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
        let bytes: [u8; 32] = sk.to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(sk.public_key().to_bytes()));
        (
            SecretKeyEntry { id: id.to_string(), pubkey_hex: Some(pubkey_hex) },
            Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
        )
    }

    #[tokio::test]
    async fn test_refresh_detects_new_key() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1), make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        // Only key-1 is known; key-2 should be detected as new
        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1);
        assert_eq!(new_keys[0].public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[tokio::test]
    async fn test_refresh_same_keys_returns_empty() {
        let sk1 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1)],
            list_error: None,
        };

        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }

    /// RF3-15: early-skip path accepts uppercase `0X` pubkey_hex via canonical.
    #[tokio::test]
    async fn test_refresh_skips_known_key_with_uppercase_0x_pubkey_hex() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let bytes: [u8; 32] = sk.to_bytes();
        let pubkey_hex = format!("0X{}", hex::encode(pk).to_uppercase());
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![(
                SecretKeyEntry { id: "key-1".to_string(), pubkey_hex: Some(pubkey_hex) },
                Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
            )],
            list_error: None,
        };

        let mut known = HashSet::new();
        known.insert(pk);

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert!(
            new_keys.is_empty(),
            "0X-prefixed known pubkey_hex must early-skip without re-fetch"
        );
    }

    #[tokio::test]
    async fn test_refresh_updates_known_set() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1), make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        );

        // First refresh: both keys are new
        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 2);

        // Second refresh: no new keys
        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_cancellation_stops_refresh_loop() {
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(3600), // very long interval
            cancel,
        );

        let call_count = Arc::new(Mutex::new(0u32));
        let call_count_clone = call_count.clone();

        let handle = tokio::spawn(async move {
            service
                .run(move |_| {
                    *call_count_clone.lock() += 1;
                    true
                })
                .await;
        });

        // Cancel immediately
        cancel_clone.cancel();

        // The task should complete quickly
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "refresh loop should have stopped on cancellation");

        assert_eq!(*call_count.lock(), 0);
    }

    #[tokio::test]
    async fn test_refresh_with_no_providers() {
        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![], HashSet::new(), Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert!(new_keys.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_provider_list_error_continues() {
        let sk = SecretKey::generate();

        let failing_provider = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let good_provider = MockSecretProvider {
            name: "good".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(failing_provider), Arc::new(good_provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        );

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_run_calls_callback_for_new_keys() {
        let sk = SecretKey::generate();
        let expected_pubkey = sk.public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_millis(10), // very short interval for test
            cancel,
        );

        let captured_keys = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured_keys.clone();

        let handle = tokio::spawn(async move {
            service
                .run(move |sk| {
                    captured_clone.lock().push(sk.public_key().to_bytes());
                    true
                })
                .await;
        });

        // Wait for at least one refresh cycle
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel_clone.cancel();

        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let keys = captured_keys.lock();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], expected_pubkey);
    }

    /// A callback that rejects the key must not keep it in `known_pubkeys`.
    #[tokio::test]
    async fn test_rejected_callback_is_offered_again() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry_with_pubkey("key-1", &sk)],
            list_error: None,
        };
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_millis(20),
            cancel,
        );
        let seen = Arc::new(Mutex::new(0u32));
        let seen_clone = Arc::clone(&seen);
        let handle = tokio::spawn(async move {
            service
                .run(move |_sk| -> bool {
                    let mut n = seen_clone.lock();
                    *n += 1;
                    false
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        cancel_clone.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            *seen.lock() >= 2,
            "a callback that returns false must see the key on a later refresh, saw {}",
            *seen.lock()
        );
    }

    #[tokio::test]
    async fn test_refresh_skips_known_pubkey_hex_early() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        // sk1 has pubkey_hex set and is already known — should be skipped without fetch
        // sk2 has no pubkey_hex — will be fetched but is also known, skipped after fetch
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![
                make_raw_key_entry_with_pubkey("key-1", &sk1),
                make_raw_key_entry("key-2", &sk2),
            ],
            list_error: None,
        };

        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());
        known.insert(sk2.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }

    /// A mock provider whose `fetch_key` sleeps for a configurable duration,
    /// used to test timeout behavior.
    struct SlowSecretProvider {
        name: String,
        entry_ids: Vec<String>,
        fetch_delay: Duration,
    }

    #[async_trait]
    impl SecretProvider for SlowSecretProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(self
                .entry_ids
                .iter()
                .map(|id| SecretKeyEntry { id: id.clone(), pubkey_hex: None })
                .collect())
        }

        async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
            tokio::time::sleep(self.fetch_delay).await;
            // Return a dummy key (won't be reached if timeout fires)
            let sk = crypto::SecretKey::generate();
            let bytes: [u8; 32] = sk.to_bytes();
            Ok(KeyMaterial::RawKey(Zeroizing::new(bytes)))
        }
    }

    #[tokio::test]
    async fn test_refresh_fetch_timeout() {
        tokio::time::pause();

        let slow_provider = SlowSecretProvider {
            name: "slow".to_string(),
            entry_ids: vec!["slow-key-1".to_string()],
            fetch_delay: Duration::from_secs(60), // well over 30s timeout
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(slow_provider)],
            HashSet::new(),
            Duration::from_secs(300),
            cancel,
        );

        let new_keys = service.refresh().await;
        // The fetch should have timed out, so no keys are returned
        assert_eq!(new_keys.len(), 0);
    }

    // ── RF4-14: refresh metrics + post-fetch denylist ─────────────────────

    /// Refresh must emit the three RVC_SECRET_PROVIDER_* metric families.
    /// KEYS_LOADED is incremented by newly admitted keys (never overwritten with a cycle delta).
    #[tokio::test]
    async fn test_refresh_emits_secret_provider_metrics() {
        use crate::metrics::{
            RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_KEYS_LOADED,
            RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
        };

        let sk_ok = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "refresh-metrics".to_string(),
            keys: vec![
                make_raw_key_entry("ok", &sk_ok),
                (
                    SecretKeyEntry { id: "bad".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::Provider("fail".into())),
                ),
            ],
            list_error: None,
        };

        // Simulate boot having already set the source total.
        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["refresh-metrics"]).set(5.0);
        let before_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["refresh-metrics", "provider"])
            .get();
        let before_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["refresh-metrics"])
            .get_sample_count();

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        );
        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1);

        let loaded = RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["refresh-metrics"]).get();
        assert_eq!(
            loaded, 6.0,
            "KEYS_LOADED must add newly admitted keys onto the boot total, not replace it"
        );

        let after_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["refresh-metrics", "provider"])
            .get();
        assert_eq!(after_err, before_err + 1, "ERRORS_TOTAL must move on fetch failure");

        let after_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["refresh-metrics"])
            .get_sample_count();
        assert_eq!(
            after_dur,
            before_dur + 1,
            "LOAD_DURATION_SECONDS must observe once per provider with work"
        );
    }

    /// Idle refresh (all keys known via pubkey_hex) must not wipe boot KEYS_LOADED.
    #[tokio::test]
    async fn test_refresh_idle_does_not_wipe_keys_loaded_gauge() {
        use crate::metrics::{
            RVC_SECRET_PROVIDER_KEYS_LOADED, RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
        };

        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let provider = MockSecretProvider {
            name: "refresh-gauge-preserve".to_string(),
            keys: vec![make_raw_key_entry_with_pubkey("known", &sk)],
            list_error: None,
        };

        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["refresh-gauge-preserve"]).set(3.0);
        let before_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["refresh-gauge-preserve"])
            .get_sample_count();

        let mut known = HashSet::new();
        known.insert(pk);
        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);
        let new_keys = service.refresh().await;
        assert!(new_keys.is_empty());

        let loaded =
            RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["refresh-gauge-preserve"]).get();
        assert_eq!(loaded, 3.0, "idle refresh must leave boot KEYS_LOADED untouched");

        let after_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["refresh-gauge-preserve"])
            .get_sample_count();
        assert_eq!(
            after_dur, before_dur,
            "idle refresh with empty to_fetch must not observe load duration"
        );
    }

    /// Post-fetch denylist: listed pubkey_hex absent, but fetched material is denylisted.
    #[tokio::test]
    async fn test_refresh_applies_post_fetch_denylist_check() {
        let sk_denied = SecretKey::generate();
        let sk_ok = SecretKey::generate();
        let pk_denied = sk_denied.public_key().to_bytes();

        // No pubkey_hex → early skip cannot see the denylist; post-fetch must catch it.
        let provider = MockSecretProvider {
            name: "refresh-post-deny".to_string(),
            keys: vec![make_raw_key_entry("denied", &sk_denied), make_raw_key_entry("ok", &sk_ok)],
            list_error: None,
        };

        let deny: DenylistCheck = Arc::new(move |pk: &[u8; 48]| *pk == pk_denied);
        let cancel = CancellationToken::new();
        let mut service = RefreshService::with_denylist(
            vec![Arc::new(provider)],
            HashSet::new(),
            Some(deny),
            Duration::from_secs(60),
            cancel,
        );

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1, "only non-denylisted key returned");
        assert_eq!(new_keys[0].public_key().to_bytes(), sk_ok.public_key().to_bytes());
        assert_ne!(new_keys[0].public_key().to_bytes(), pk_denied);
    }

    /// Concurrency cap: with limit 1, peak in-flight fetches never exceeds 1.
    #[tokio::test]
    async fn test_refresh_fetch_concurrency_is_bounded() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct PeakTrackingProvider {
            name: String,
            entry_ids: Vec<String>,
            in_flight: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl SecretProvider for PeakTrackingProvider {
            fn name(&self) -> &str {
                &self.name
            }

            async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
                Ok(self
                    .entry_ids
                    .iter()
                    .map(|id| SecretKeyEntry { id: id.clone(), pubkey_hex: None })
                    .collect())
            }

            async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
                let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                let sk = SecretKey::generate();
                let bytes: [u8; 32] = sk.to_bytes();
                Ok(KeyMaterial::RawKey(Zeroizing::new(bytes)))
            }
        }

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let provider = PeakTrackingProvider {
            name: "peak-track".to_string(),
            entry_ids: (0..6).map(|i| format!("k{i}")).collect(),
            in_flight: in_flight.clone(),
            peak: peak.clone(),
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        )
        .with_fetch_concurrency(2);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 6);
        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= 2,
            "in-flight fetches must respect concurrency cap, peak={observed_peak}"
        );
        assert!(observed_peak >= 1, "at least one fetch must have run");
    }

    // ── W4-K3b: (provider slot, id) → pubkey cache ────────────────────────

    struct CountingProvider<P> {
        inner: P,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl<P: SecretProvider> SecretProvider for CountingProvider<P> {
        fn name(&self) -> &str {
            self.inner.name()
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            self.inner.list_keys().await
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.inner.fetch_key(id).await
        }
    }

    fn counting_raw(
        name: &str,
        id: &str,
        sk: &SecretKey,
        fetches: Arc<AtomicUsize>,
    ) -> CountingProvider<MockSecretProvider> {
        let (entry, material) = make_raw_key_entry(id, sk);
        assert!(entry.pubkey_hex.is_none(), "{id} must be an opaque id");
        CountingProvider {
            inner: MockSecretProvider {
                name: name.to_string(),
                keys: vec![(entry, material)],
                list_error: None,
            },
            fetches,
        }
    }

    fn pubkey_of(sk: &SecretKey) -> [u8; 48] {
        sk.public_key().to_bytes()
    }

    fn fresh_service(
        providers: Vec<Arc<dyn SecretProvider>>,
        known: HashSet<[u8; 48]>,
        deny: Option<DenylistCheck>,
    ) -> RefreshService {
        RefreshService::with_denylist(
            providers,
            known,
            deny,
            Duration::from_secs(60),
            CancellationToken::new(),
        )
    }

    /// One paused-time step of `RefreshService::run`. Returns the offered pubkey.
    async fn offered_pubkey(
        rx: &mut tokio::sync::mpsc::Receiver<[u8; 48]>,
        interval: Duration,
    ) -> [u8; 48] {
        if let Ok(pk) = rx.try_recv() {
            return pk;
        }
        tokio::time::timeout(interval.saturating_mul(3), rx.recv())
            .await
            .expect("paused clock reached an offer")
            .expect("offer channel stays open")
    }

    /// AC: a known opaque id is fetched once across two cycles and never returned.
    #[tokio::test]
    async fn an_opaque_known_id_is_fetched_once_across_two_cycles() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = counting_raw("opaque-known", "validator-7", &sk, Arc::clone(&fetches));
        let mut known = HashSet::new();
        known.insert(pk);
        let mut service = fresh_service(vec![Arc::new(provider)], known, None);

        let first = service.refresh().await;
        let second = service.refresh().await;

        assert!(first.is_empty(), "a known pubkey is not returned as new");
        assert!(second.is_empty(), "the second cycle still returns nothing");
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "cache hit must not fetch or decrypt");
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk));
    }

    /// A new opaque id is fetched and returned once, then served from the cache.
    #[tokio::test]
    async fn a_new_opaque_id_is_fetched_once_then_cached() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = counting_raw("opaque-new", "validator-7", &sk, Arc::clone(&fetches));
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1);
        assert_eq!(pubkey_of(&first[0]), pk);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let second = service.refresh().await;
        assert!(second.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "the second cycle is a cache hit");
        assert!(service.known_pubkeys.contains(&pk));
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk));
    }

    /// AC / NM-6: the same opaque id under two providers is cached per slot, not by name.
    #[tokio::test]
    async fn the_same_opaque_id_in_two_providers_is_cached_per_provider() {
        let sk_a = SecretKey::generate();
        let sk_b = SecretKey::generate();
        let pk_a = pubkey_of(&sk_a);
        let pk_b = pubkey_of(&sk_b);
        let fetches_a = Arc::new(AtomicUsize::new(0));
        let fetches_b = Arc::new(AtomicUsize::new(0));
        // Same log name on purpose: `name()` must not be the cache key.
        let provider_a = counting_raw("mock", "validator-7", &sk_a, Arc::clone(&fetches_a));
        let provider_b = counting_raw("mock", "validator-7", &sk_b, Arc::clone(&fetches_b));
        let mut known = HashSet::new();
        known.insert(pk_a);
        let mut service =
            fresh_service(vec![Arc::new(provider_a), Arc::new(provider_b)], known, None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1, "only provider B's key is new");
        assert_eq!(pubkey_of(&first[0]), pk_b);
        assert_eq!(fetches_a.load(Ordering::SeqCst), 1);
        assert_eq!(fetches_b.load(Ordering::SeqCst), 1);
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk_a));
        assert_eq!(service.cached_pubkey(1, "validator-7"), Some(pk_b));

        let second = service.refresh().await;
        assert!(second.is_empty());
        assert_eq!(fetches_a.load(Ordering::SeqCst), 1, "slot 0 cache hit");
        assert_eq!(fetches_b.load(Ordering::SeqCst), 1, "slot 1 cache hit");
    }

    /// AC: a denylisted opaque id is fetched once, hidden, and fetched again after the denylist clears.
    #[tokio::test]
    async fn a_denylisted_opaque_id_is_not_fetched_again() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = counting_raw("opaque-deny", "validator-9", &sk, Arc::clone(&fetches));
        let denied_now = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&denied_now);
        let is_denied: DenylistCheck =
            Arc::new(move |got| flag.load(Ordering::SeqCst) && *got == pk);
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), Some(is_denied));

        let first = service.refresh().await;
        assert!(first.is_empty(), "a denylisted key is not returned");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(service.cached_pubkey(0, "validator-9"), Some(pk));
        assert!(!service.known_pubkeys.contains(&pk));

        let second = service.refresh().await;
        assert!(second.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "still denylisted: cache hit, no fetch");

        denied_now.store(false, Ordering::SeqCst);
        let third = service.refresh().await;
        assert_eq!(third.len(), 1, "clearing the denylist fetches and returns the key");
        assert_eq!(pubkey_of(&third[0]), pk);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert!(service.known_pubkeys.contains(&pk));
    }

    /// AC: `on_new_key` returning false evicts the id, so the next cycle fetches it again.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_rejected_key_evicts_its_id_and_is_fetched_again() {
        let interval = Duration::from_secs(30);
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = counting_raw("opaque-reject", "validator-7", &sk, Arc::clone(&fetches));
        let cancel = CancellationToken::new();
        let cancel_task = cancel.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let service =
            RefreshService::new(vec![Arc::new(provider)], HashSet::new(), interval, cancel);

        let handle = tokio::spawn(async move {
            service
                .run(move |got| {
                    tx.try_send(pubkey_of(&got)).expect("offer channel accepts the key");
                    false
                })
                .await
        });

        tokio::time::advance(interval).await;
        let first = offered_pubkey(&mut rx, interval).await;
        assert_eq!(first, pk);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        tokio::time::advance(interval).await;
        let second = offered_pubkey(&mut rx, interval).await;
        assert_eq!(second, pk, "a rejected key is offered on the next cycle");
        assert_eq!(fetches.load(Ordering::SeqCst), 2);

        cancel_task.cancel();
        let service = handle.await.expect("run returns after cancel");
        assert!(!service.known_pubkeys.contains(&pk));
        assert!(
            service.known_ids.values().all(|cached| cached != &pk),
            "rejection removes every known_ids entry for that pubkey"
        );
    }

    struct LogEvent {
        level: tracing::Level,
        fields: Vec<(String, String)>,
    }

    struct LogCapture {
        events: Arc<Mutex<Vec<LogEvent>>>,
    }

    struct LogVisitor {
        fields: Vec<(String, String)>,
    }

    impl Visit for LogVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields.push((field.name().to_string(), format!("{value:?}")));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields.push((field.name().to_string(), value.to_string()));
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = LogVisitor { fields: Vec::new() };
            event.record(&mut visitor);
            self.events
                .lock()
                .push(LogEvent { level: *event.metadata().level(), fields: visitor.fields });
        }
    }

    fn field_value<'a>(event: &'a LogEvent, name: &str) -> Option<&'a str> {
        event.fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.trim_matches('"'))
    }

    /// AC: a decrypt failure is a warn, is not cached, and is fetched again.
    #[tokio::test(flavor = "current_thread")]
    async fn a_decrypt_failure_is_skipped_and_retried_next_cycle() {
        let password = Zeroizing::new("not-logged-keystore-password".to_string());
        let broken =
            KeyMaterial::Keystore { keystore_json: "{".to_string(), password: password.clone() };
        let err = crate::key_source_manager::convert_key_material("validator-7", broken)
            .expect_err("malformed keystore JSON");
        assert!(
            matches!(err, SecretProviderError::DecryptionFailed { ref id, .. } if id == "validator-7"),
            "decrypt failure is DecryptionFailed, got {err:?}"
        );

        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider {
            inner: MockSecretProvider {
                name: "opaque-decrypt".to_string(),
                keys: vec![(
                    SecretKeyEntry { id: "validator-7".to_string(), pubkey_hex: None },
                    Ok(KeyMaterial::Keystore {
                        keystore_json: "{".to_string(),
                        password: password.clone(),
                    }),
                )],
                list_error: None,
            },
            fetches: Arc::clone(&fetches),
        };
        let events = Arc::new(Mutex::new(Vec::new()));
        let layer = LogCapture { events: Arc::clone(&events) };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);
        let first = service.refresh().await;
        let second = service.refresh().await;

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 2, "a decrypt failure is not cached");
        assert!(service.known_ids.is_empty());
        let captured = events.lock();
        let warn_count = captured
            .iter()
            .filter(|event| {
                event.level == tracing::Level::WARN
                    && field_value(event, "message") == Some("Key fetch failure")
            })
            .count();
        assert_eq!(warn_count, 2, "each failed decrypt warns once");
        let secret = password.as_str();
        assert!(
            captured
                .iter()
                .all(|event| { event.fields.iter().all(|(_, value)| !value.contains(secret)) }),
            "decrypt warn must not contain the keystore password"
        );
    }

    struct FailThenServe {
        bytes: Zeroizing<[u8; 32]>,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SecretProvider for FailThenServe {
        fn name(&self) -> &str {
            "opaque-fetch-error"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(vec![SecretKeyEntry { id: "validator-7".to_string(), pubkey_hex: None }])
        }

        async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
            let n = self.fetches.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Err(SecretProviderError::Provider("provider down".into()));
            }
            Ok(KeyMaterial::RawKey(self.bytes.clone()))
        }
    }

    /// A fetch error is not cached, so the next cycle loads the key.
    #[tokio::test]
    async fn a_fetch_error_is_not_cached_and_is_retried_next_cycle() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider =
            FailThenServe { bytes: Zeroizing::new(sk.to_bytes()), fetches: Arc::clone(&fetches) };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert!(first.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(service.known_ids.is_empty(), "fetch error must not become a cache entry");

        let second = service.refresh().await;
        assert_eq!(second.len(), 1);
        assert_eq!(pubkey_of(&second[0]), pk);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk));
    }

    struct TimeoutThenServe {
        bytes: Zeroizing<[u8; 32]>,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SecretProvider for TimeoutThenServe {
        fn name(&self) -> &str {
            "opaque-timeout"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(vec![SecretKeyEntry { id: "validator-7".to_string(), pubkey_hex: None }])
        }

        async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
            let n = self.fetches.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(KeyMaterial::RawKey(self.bytes.clone()))
        }
    }

    /// A fetch timeout is not cached. The next cycle fetches again. Paused clock only.
    #[tokio::test(start_paused = true)]
    async fn a_fetch_timeout_is_not_cached_and_is_retried_next_cycle() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = TimeoutThenServe {
            bytes: Zeroizing::new(sk.to_bytes()),
            fetches: Arc::clone(&fetches),
        };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None)
            .with_fetch_timeout(Duration::from_secs(5));

        let first = service.refresh().await;
        assert!(first.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(service.known_ids.is_empty(), "timeout must not become a cache entry");

        let second = service.refresh().await;
        assert_eq!(second.len(), 1);
        assert_eq!(pubkey_of(&second[0]), pk);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    struct RotatingId {
        bytes: Arc<Mutex<Zeroizing<[u8; 32]>>>,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SecretProvider for RotatingId {
        fn name(&self) -> &str {
            "opaque-rotate"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(vec![SecretKeyEntry { id: "validator-7".to_string(), pubkey_hex: None }])
        }

        async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let bytes = self.bytes.lock().clone();
            Ok(KeyMaterial::RawKey(bytes))
        }
    }

    /// A new key under an already cached id is not fetched. Rotation waits for restart.
    #[tokio::test]
    async fn a_changed_secret_version_under_the_same_id_is_not_refetched() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = pubkey_of(&sk1);
        let pk2 = pubkey_of(&sk2);
        let bytes = Arc::new(Mutex::new(Zeroizing::new(sk1.to_bytes())));
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = RotatingId { bytes: Arc::clone(&bytes), fetches: Arc::clone(&fetches) };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1);
        assert_eq!(pubkey_of(&first[0]), pk1);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        *bytes.lock() = Zeroizing::new(sk2.to_bytes());
        let second = service.refresh().await;
        assert!(second.is_empty(), "refresh does not detect a same-id rotation");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk1));
        assert!(!service.known_pubkeys.contains(&pk2));
    }

    struct ListToggle {
        bytes: Zeroizing<[u8; 32]>,
        fail_list: Arc<AtomicBool>,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SecretProvider for ListToggle {
        fn name(&self) -> &str {
            "opaque-list-fail"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            if self.fail_list.load(Ordering::SeqCst) {
                return Err(SecretProviderError::Provider("list failed".into()));
            }
            Ok(vec![SecretKeyEntry { id: "validator-7".to_string(), pubkey_hex: None }])
        }

        async fn fetch_key(&self, _id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Ok(KeyMaterial::RawKey(self.bytes.clone()))
        }
    }

    /// `list_keys` failing does not insert and does not evict. The id stays cached.
    #[tokio::test]
    async fn a_list_keys_failure_does_not_drop_a_cached_id() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let fail_list = Arc::new(AtomicBool::new(false));
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = ListToggle {
            bytes: Zeroizing::new(sk.to_bytes()),
            fail_list: Arc::clone(&fail_list),
            fetches: Arc::clone(&fetches),
        };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        fail_list.store(true, Ordering::SeqCst);
        let during_outage = service.refresh().await;
        assert!(during_outage.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk));

        fail_list.store(false, Ordering::SeqCst);
        let after = service.refresh().await;
        assert!(after.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "list failure must not evict the id");
    }

    struct OverlappingFetches {
        keys: Vec<ListedRaw>,
        fetches: Arc<AtomicUsize>,
        started: Arc<AtomicUsize>,
        gate: Arc<tokio::sync::watch::Sender<bool>>,
    }

    #[async_trait]
    impl SecretProvider for OverlappingFetches {
        fn name(&self) -> &str {
            "opaque-concurrent"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(self
                .keys
                .iter()
                .map(|entry| SecretKeyEntry { id: entry.id.clone(), pubkey_hex: None })
                .collect())
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let mut rx = self.gate.subscribe();
            let n = self.started.fetch_add(1, Ordering::SeqCst) + 1;
            if n == self.keys.len() {
                self.gate.send(true).expect("watch channel is open");
            }
            while !*rx.borrow() {
                rx.changed().await.expect("watch channel stays open");
            }
            let bytes = self
                .keys
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| entry.bytes.clone())
                .expect("listed id is fetchable");
            Ok(KeyMaterial::RawKey(bytes))
        }
    }

    /// One cycle's fetch fan-out is concurrent. Every success is cached for the next cycle.
    ///
    /// `RefreshService::refresh` takes `&mut self`, so two cycles cannot overlap.
    /// The concurrent path is the bounded `fetch_key` fan-out inside one cycle.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_fetches_in_one_cycle_are_all_cached() {
        let mut expected = HashSet::new();
        let mut keys = Vec::new();
        for i in 0..4 {
            let sk = SecretKey::generate();
            expected.insert(pubkey_of(&sk));
            keys.push(ListedRaw { id: format!("id-{i}"), bytes: Zeroizing::new(sk.to_bytes()) });
        }
        let fetches = Arc::new(AtomicUsize::new(0));
        let (gate, _rx) = tokio::sync::watch::channel(false);
        let provider = OverlappingFetches {
            keys,
            fetches: Arc::clone(&fetches),
            started: Arc::new(AtomicUsize::new(0)),
            gate: Arc::new(gate),
        };
        let mut service =
            fresh_service(vec![Arc::new(provider)], HashSet::new(), None).with_fetch_concurrency(4);

        let first = service.refresh().await;
        let got: HashSet<_> = first.iter().map(pubkey_of).collect();
        assert_eq!(got, expected);
        assert_eq!(fetches.load(Ordering::SeqCst), 4);
        assert_eq!(service.known_ids.len(), 4);

        let second = service.refresh().await;
        assert!(second.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 4, "every concurrent id is cached");
    }

    struct ListedRaw {
        id: String,
        bytes: Zeroizing<[u8; 32]>,
    }

    struct MutableOpaqueList {
        entries: Arc<Mutex<Vec<ListedRaw>>>,
        fetches: Arc<AtomicUsize>,
        fetched_ids: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl SecretProvider for MutableOpaqueList {
        fn name(&self) -> &str {
            "opaque-mutable"
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(self
                .entries
                .lock()
                .iter()
                .map(|entry| SecretKeyEntry { id: entry.id.clone(), pubkey_hex: None })
                .collect())
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.fetched_ids.lock().push(id.to_string());
            let bytes = self
                .entries
                .lock()
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| entry.bytes.clone())
                .expect("listed id is fetchable");
            Ok(KeyMaterial::RawKey(bytes))
        }
    }

    /// A newly listed opaque id is fetched even when a sibling id is already cached.
    #[tokio::test]
    async fn a_new_sibling_id_is_fetched_while_the_cached_id_is_not() {
        let sk_old = SecretKey::generate();
        let sk_new = SecretKey::generate();
        let pk_new = pubkey_of(&sk_new);
        let entries = Arc::new(Mutex::new(vec![ListedRaw {
            id: "validator-7".to_string(),
            bytes: Zeroizing::new(sk_old.to_bytes()),
        }]));
        let fetches = Arc::new(AtomicUsize::new(0));
        let fetched_ids = Arc::new(Mutex::new(Vec::new()));
        let provider = MutableOpaqueList {
            entries: Arc::clone(&entries),
            fetches: Arc::clone(&fetches),
            fetched_ids: Arc::clone(&fetched_ids),
        };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1);
        assert_eq!(pubkey_of(&first[0]), pubkey_of(&sk_old));

        entries.lock().push(ListedRaw {
            id: "validator-8".to_string(),
            bytes: Zeroizing::new(sk_new.to_bytes()),
        });
        fetched_ids.lock().clear();
        let second = service.refresh().await;
        assert_eq!(second.len(), 1);
        assert_eq!(pubkey_of(&second[0]), pk_new);
        assert_eq!(fetched_ids.lock().as_slice(), ["validator-8"]);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    /// Dropping an id from the listing does not evict it. Putting that id back is a cache hit.
    ///
    /// Eviction is the rejected-callback path. A same-id rotation, including delete-and-recreate,
    /// is picked up at the next restart.
    #[tokio::test]
    async fn an_id_omitted_from_a_later_listing_is_not_evicted() {
        let sk = SecretKey::generate();
        let pk = pubkey_of(&sk);
        let entries = Arc::new(Mutex::new(vec![ListedRaw {
            id: "validator-7".to_string(),
            bytes: Zeroizing::new(sk.to_bytes()),
        }]));
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = MutableOpaqueList {
            entries: Arc::clone(&entries),
            fetches: Arc::clone(&fetches),
            fetched_ids: Arc::new(Mutex::new(Vec::new())),
        };
        let mut service = fresh_service(vec![Arc::new(provider)], HashSet::new(), None);

        let first = service.refresh().await;
        assert_eq!(first.len(), 1);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        entries.lock().clear();
        let while_absent = service.refresh().await;
        assert!(while_absent.is_empty());
        assert_eq!(service.cached_pubkey(0, "validator-7"), Some(pk));

        entries.lock().push(ListedRaw {
            id: "validator-7".to_string(),
            bytes: Zeroizing::new(sk.to_bytes()),
        });
        let relisted = service.refresh().await;
        assert!(relisted.is_empty(), "re-listing a cached id does not fetch");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }
}
