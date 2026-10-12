use std::collections::HashSet;
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
use crate::SecretProvider;
use crypto::SecretKey;

/// Predicate: return `true` if a pubkey must not be loaded (Keymanager DELETE denylist).
pub type DenylistCheck = Arc<dyn Fn(&[u8; 48]) -> bool + Send + Sync>;

pub struct RefreshService {
    providers: Vec<Arc<dyn SecretProvider>>,
    known_pubkeys: HashSet<[u8; 48]>,
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

        for provider in &self.providers {
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

            // known_pubkeys bookkeeping stays outside the shared pipeline: early-skip
            // already-known entries (when list metadata has pubkey_hex) so we do not
            // re-fetch them. Denylist is applied by fetch_provider_keys (hex precheck
            // + post-fetch public_key check).
            let to_fetch: Vec<_> = entries
                .into_iter()
                .filter(|entry| {
                    if let Some(ref hex_str) = entry.pubkey_hex {
                        if let Ok(pk) = eth_types::canonical::pubkey_hex::parse_pubkey_hex(hex_str)
                        {
                            if self.known_pubkeys.contains(pk.as_bytes()) {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect();

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
            for sk in fetch.keys {
                let pubkey = sk.public_key().to_bytes();
                // known_pubkeys bookkeeping: drop already-loaded keys (e.g. list had no
                // pubkey_hex so early skip could not run). Denylist was applied inside
                // fetch_provider_keys.
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

    /// `on_new_key` returns `true` when the key was kept. `false` drops it from
    /// `known_pubkeys` so the next refresh offers it again.
    pub async fn run<F>(mut self, mut on_new_key: F)
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
                            self.known_pubkeys.remove(&pubkey);
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use parking_lot::Mutex;

    use async_trait::async_trait;
    use zeroize::Zeroizing;

    use super::*;
    use crate::key_source_manager::mock::MockSecretProvider;
    use crate::{KeyMaterial, SecretKeyEntry, SecretProviderError};

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
}
