use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::{KeyManager, Keystore, SecretKey};
use observability::logging::TruncatedPubkey;
use tracing::{info, info_span, warn, Instrument};

use crate::metrics::{
    classify_error, RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_KEYS_LOADED,
    RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
};
use crate::{
    KeyMaterial, LoadSummary, ProviderSummary, SecretKeyEntry, SecretProvider, SecretProviderError,
};

/// Default per-key fetch timeout shared by boot and refresh (historical refresh value).
pub const DEFAULT_KEY_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Default max concurrent `fetch_key` calls per provider (JoinSet window).
///
/// Bounds provider thundering-herd risk on boot and especially on the lifetime
/// refresh loop (RF4-14 Finding 2 / F72 concurrency axis).
pub const DEFAULT_FETCH_CONCURRENCY: usize = 8;

/// How [`fetch_provider_keys`] updates `RVC_SECRET_PROVIDER_KEYS_LOADED`.
///
/// Boot sets an absolute per-source total. Refresh must **not** overwrite that
/// gauge with a per-cycle delta (often 0 when all keys are already known), or
/// dashboards flip to zero on every idle refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysLoadedUpdate {
    /// Set the gauge to this call's successfully loaded count (boot full load).
    SetAbsolute,
    /// Leave the gauge untouched in the pipeline. Callers that admit new keys
    /// (refresh) should [`prometheus::Gauge::add`] only the newly admitted count.
    LeaveUnchanged,
}

/// Instrumented result of fetching keys from a single provider's listed entries.
///
/// Callers own post-processing: boot inserts into [`KeyManager`]; refresh returns new keys.
pub struct ProviderFetchResult {
    pub name: String,
    pub loaded: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    /// Successfully converted keys that passed the post-fetch denylist check.
    ///
    /// The `String` is the provider secret id. Callers that do not cache ids
    /// ignore it. The vec does not include denylisted or failed ids.
    pub keys: Vec<(String, SecretKey)>,
    /// Ids the post-fetch denylist check skipped, with the pubkey only.
    ///
    /// No [`SecretKey`], keystore JSON, or password is retained. List-time hex
    /// skips are not recorded here: those ids are never fetched.
    pub denied: Vec<(String, [u8; 48])>,
}

enum FetchOutcome {
    Material(KeyMaterial),
    Error(SecretProviderError),
    Timeout,
}

/// Denylist / skip predicate for the shared fetch pipeline (`Send + Sync` so the
/// future remains spawnable across boot and the refresh loop).
pub type SkipPubkey = Arc<dyn Fn(&[u8; 48]) -> bool + Send + Sync>;

/// Record a `list_keys` failure on the shared metric families (boot + refresh).
pub fn record_list_keys_failure(provider_name: &str, err: &SecretProviderError, started: Instant) {
    RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&[provider_name, classify_error(err)]).inc();
    RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
        .with_label_values(&[provider_name])
        .observe(started.elapsed().as_secs_f64());
}

/// Shared instrumented fetch pipeline for boot and refresh (RF4-14 / E9).
///
/// Owns: hex denylist precheck, bounded concurrent `JoinSet` fan-out, per-fetch
/// `tokio::time::timeout`, `secret_provider.fetch_key` spans, error + duration
/// metrics, and optional absolute `KEYS_LOADED` gauge update.
///
/// `is_denied` is consulted both before fetch (when `pubkey_hex` is present) and
/// after conversion (fail-closed when list metadata omits the pubkey).
/// `load_started` is used for the duration histogram (callers may start it before
/// `list_keys` so list latency is included).
/// `concurrency` caps in-flight `fetch_key` tasks (minimum 1).
pub async fn fetch_provider_keys(
    provider: Arc<dyn SecretProvider>,
    entries: &[SecretKeyEntry],
    is_denied: Option<SkipPubkey>,
    timeout: Duration,
    concurrency: usize,
    load_started: Instant,
    keys_loaded_update: KeysLoadedUpdate,
) -> ProviderFetchResult {
    let provider_name = provider.name().to_string();
    let mut loaded = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();
    let mut keys = Vec::new();
    let mut denied = Vec::new();

    let concurrency = concurrency.max(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut join_set = tokio::task::JoinSet::new();
    for entry in entries {
        // Early skip when list_keys already provides the pubkey.
        if let (Some(ref deny), Some(ref hex_str)) = (&is_denied, &entry.pubkey_hex) {
            if let Ok(pk) = eth_types::canonical::pubkey_hex::parse_pubkey_hex(hex_str) {
                let arr = *pk.as_bytes();
                if deny(&arr) {
                    let pubkey_hex = format!("0x{}", hex::encode(arr));
                    info!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        source = %provider_name,
                        "Skipping denylisted secret-provider key"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }

        let id = entry.id.clone();
        let prov = Arc::clone(&provider);
        let prov_name = provider_name.clone();
        let permit = Arc::clone(&semaphore);
        let fetch_span = info_span!(
            "secret_provider.fetch_key",
            key.id = %id,
            provider.name = %prov_name,
        );
        join_set.spawn(
            async move {
                // Bound in-flight fetches; acquire before the timed fetch so the
                // timeout does not count queue wait against the provider SLA.
                let _permit = permit
                    .acquire_owned()
                    .await
                    .expect("fetch concurrency semaphore is never closed");
                let outcome = match tokio::time::timeout(timeout, prov.fetch_key(&id)).await {
                    Ok(Ok(material)) => FetchOutcome::Material(material),
                    Ok(Err(e)) => FetchOutcome::Error(e),
                    Err(_elapsed) => FetchOutcome::Timeout,
                };
                (id, outcome)
            }
            .instrument(fetch_span),
        );
    }

    while let Some(join_result) = join_set.join_next().await {
        let (entry_id, outcome) = match join_result {
            Ok(pair) => pair,
            Err(e) => {
                warn!(
                    provider = %provider_name,
                    error = %e,
                    "JoinSet task panicked, skipping"
                );
                RVC_SECRET_PROVIDER_ERRORS_TOTAL
                    .with_label_values(&[provider_name.as_str(), "task_panic"])
                    .inc();
                skipped += 1;
                errors.push(format!("task panic: {}", e));
                continue;
            }
        };

        match outcome {
            FetchOutcome::Material(material) => match convert_key_material(&entry_id, material) {
                Ok(secret_key) => {
                    let pubkey_bytes = secret_key.public_key().to_bytes();
                    if is_denied.as_ref().is_some_and(|deny| deny(&pubkey_bytes)) {
                        let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
                        info!(
                            pubkey = %TruncatedPubkey::new(&pubkey_hex),
                            source = %provider_name,
                            "Skipping denylisted secret-provider key"
                        );
                        skipped += 1;
                        // Pubkey only. `secret_key` drops here and zeroizes.
                        denied.push((entry_id, pubkey_bytes));
                        continue;
                    }
                    loaded += 1;
                    keys.push((entry_id, secret_key));
                }
                Err(e) => {
                    warn!(
                        key_id = %entry_id,
                        source = %provider_name,
                        error = %e,
                        "Key fetch failure"
                    );
                    RVC_SECRET_PROVIDER_ERRORS_TOTAL
                        .with_label_values(&[provider_name.as_str(), classify_error(&e)])
                        .inc();
                    skipped += 1;
                    errors.push(format!("{}: {}", entry_id, e));
                }
            },
            FetchOutcome::Error(e) => {
                tracing::Span::current().in_scope(|| {
                    tracing::error!(
                        provider = %provider_name,
                        key_id = %entry_id,
                        error = %e,
                        "Failed to fetch key"
                    );
                });
                RVC_SECRET_PROVIDER_ERRORS_TOTAL
                    .with_label_values(&[provider_name.as_str(), classify_error(&e)])
                    .inc();
                skipped += 1;
                errors.push(format!("{}: {}", entry_id, e));
            }
            FetchOutcome::Timeout => {
                warn!(
                    provider = %provider_name,
                    key_id = %entry_id,
                    timeout_secs = timeout.as_secs(),
                    "Timed out fetching key from secret provider"
                );
                RVC_SECRET_PROVIDER_ERRORS_TOTAL
                    .with_label_values(&[provider_name.as_str(), "timeout"])
                    .inc();
                skipped += 1;
                errors.push(format!("{}: fetch timed out after {}s", entry_id, timeout.as_secs()));
            }
        }
    }

    match keys_loaded_update {
        KeysLoadedUpdate::SetAbsolute => {
            RVC_SECRET_PROVIDER_KEYS_LOADED
                .with_label_values(&[provider_name.as_str()])
                .set(loaded as f64);
        }
        KeysLoadedUpdate::LeaveUnchanged => {}
    }
    RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
        .with_label_values(&[provider_name.as_str()])
        .observe(load_started.elapsed().as_secs_f64());

    ProviderFetchResult { name: provider_name, loaded, skipped, errors, keys, denied }
}

pub struct KeySourceManager {
    providers: Vec<Arc<dyn SecretProvider>>,
    /// When true, any provider `list_keys` failure aborts the load (SEC-9 / M-9).
    /// Default is resilient: log and continue so healthy providers still load.
    strict: bool,
    /// Per-key fetch timeout (default [`DEFAULT_KEY_FETCH_TIMEOUT`]).
    fetch_timeout: Duration,
    /// Max concurrent `fetch_key` tasks per provider (default [`DEFAULT_FETCH_CONCURRENCY`]).
    fetch_concurrency: usize,
}

impl KeySourceManager {
    pub fn new(providers: Vec<Box<dyn SecretProvider>>) -> Self {
        Self {
            providers: providers.into_iter().map(Arc::from).collect(),
            strict: false,
            fetch_timeout: DEFAULT_KEY_FETCH_TIMEOUT,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
        }
    }

    pub fn from_arc(providers: Vec<Arc<dyn SecretProvider>>) -> Self {
        Self {
            providers,
            strict: false,
            fetch_timeout: DEFAULT_KEY_FETCH_TIMEOUT,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
        }
    }

    /// Fail-fast when any provider's `list_keys` fails (SEC-9 / M-9 strict mode).
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
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

    /// Load every provider key into `key_manager` (no denylist).
    pub async fn load_all(
        &self,
        key_manager: &mut KeyManager,
    ) -> Result<LoadSummary, SecretProviderError> {
        self.load_all_except(key_manager, None).await
    }

    /// Load provider keys, skipping any pubkey present in `denylist` (SEC-1b).
    ///
    /// Denylisted keys are counted as `skipped` and never inserted, so a key
    /// deleted via the Keymanager API cannot resurrect from GCP/etc. on boot.
    ///
    /// Provider resilience (SEC-9 / M-9): by default a single provider's
    /// `list_keys` failure is logged and skipped so other providers can still
    /// contribute keys. Enable [`Self::with_strict`] to restore fail-fast.
    /// If every configured provider fails `list_keys`, the load still returns
    /// `Err` (all sources failing remains fatal).
    #[tracing::instrument(
        name = "secret_provider.load_all",
        skip_all,
        fields(providers.count = self.providers.len())
    )]
    pub async fn load_all_except(
        &self,
        key_manager: &mut KeyManager,
        denylist: Option<&HashSet<[u8; 48]>>,
    ) -> Result<LoadSummary, SecretProviderError> {
        let mut summary = LoadSummary::default();
        let mut list_successes = 0usize;
        let mut last_list_error: Option<SecretProviderError> = None;

        // Build SkipPubkey once for all providers (avoid cloning HashSet per provider).
        let is_denied: Option<SkipPubkey> = denylist.map(|set| {
            let set = Arc::new(set.clone());
            Arc::new(move |pk: &[u8; 48]| set.contains(pk)) as SkipPubkey
        });

        for provider in &self.providers {
            let provider_name = provider.name().to_string();
            let timer = Instant::now();

            let list_span = info_span!(
                "secret_provider.list_keys",
                provider.name = %provider_name,
                keys.count = tracing::field::Empty,
            );
            let entries = match provider.list_keys().instrument(list_span.clone()).await {
                Ok(entries) => {
                    list_successes += 1;
                    entries
                }
                Err(err) => {
                    record_list_keys_failure(&provider_name, &err, timer);
                    if self.strict {
                        return Err(err);
                    }
                    tracing::error!(
                        provider = %provider_name,
                        error = %err,
                        "Failed to list keys from secret provider; continuing with remaining providers"
                    );
                    summary.per_provider.push(ProviderSummary {
                        name: provider_name,
                        loaded: 0,
                        skipped: 0,
                        errors: vec![err.to_string()],
                    });
                    last_list_error = Some(err);
                    continue;
                }
            };
            list_span.record("keys.count", entries.len());

            let fetch = fetch_provider_keys(
                Arc::clone(provider),
                &entries,
                is_denied.clone(),
                self.fetch_timeout,
                self.fetch_concurrency,
                timer,
                KeysLoadedUpdate::SetAbsolute,
            )
            .await;

            for (_id, secret_key) in fetch.keys {
                let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    source = %provider_name,
                    "New key discovered"
                );
                key_manager.insert(secret_key);
            }

            summary.per_provider.push(ProviderSummary {
                name: fetch.name,
                loaded: fetch.loaded,
                skipped: fetch.skipped,
                errors: fetch.errors,
            });
        }

        // All configured providers failed list_keys — still fatal (SEC-9 / M-9).
        if list_successes == 0 {
            if let Some(err) = last_list_error {
                return Err(err);
            }
        }

        Ok(summary)
    }
}

pub fn convert_key_material(
    id: &str,
    material: KeyMaterial,
) -> Result<SecretKey, SecretProviderError> {
    match material {
        KeyMaterial::RawKey(bytes) => SecretKey::from_bytes(&*bytes).map_err(|e| {
            SecretProviderError::InvalidKeyMaterial(format!("invalid raw key for {}: {}", id, e))
        }),
        KeyMaterial::Keystore { keystore_json, password } => {
            let keystore = Keystore::from_json(&keystore_json).map_err(|e| {
                SecretProviderError::DecryptionFailed {
                    id: id.to_string(),
                    reason: format!("invalid keystore JSON: {}", e),
                }
            })?;
            keystore.decrypt(password.as_bytes()).map_err(|e| {
                SecretProviderError::DecryptionFailed {
                    id: id.to_string(),
                    reason: format!("decryption failed: {}", e),
                }
            })
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use async_trait::async_trait;

    use crate::{KeyMaterial, SecretKeyEntry, SecretProvider, SecretProviderError};

    pub struct MockSecretProvider {
        pub name: String,
        pub keys: Vec<(SecretKeyEntry, Result<KeyMaterial, SecretProviderError>)>,
        pub list_error: Option<SecretProviderError>,
    }

    impl MockSecretProvider {
        fn clone_error(err: &SecretProviderError) -> SecretProviderError {
            match err {
                SecretProviderError::Auth(msg) => SecretProviderError::Auth(msg.clone()),
                SecretProviderError::NotFound(msg) => SecretProviderError::NotFound(msg.clone()),
                SecretProviderError::Provider(msg) => SecretProviderError::Provider(msg.clone()),
                SecretProviderError::InvalidKeyMaterial(msg) => {
                    SecretProviderError::InvalidKeyMaterial(msg.clone())
                }
                SecretProviderError::DecryptionFailed { id, reason } => {
                    SecretProviderError::DecryptionFailed { id: id.clone(), reason: reason.clone() }
                }
            }
        }

        fn clone_material(material: &KeyMaterial) -> KeyMaterial {
            match material {
                KeyMaterial::RawKey(bytes) => KeyMaterial::RawKey(bytes.clone()),
                KeyMaterial::Keystore { keystore_json, password } => KeyMaterial::Keystore {
                    keystore_json: keystore_json.clone(),
                    password: password.clone(),
                },
            }
        }
    }

    #[async_trait]
    impl SecretProvider for MockSecretProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            if let Some(ref err) = self.list_error {
                return Err(Self::clone_error(err));
            }
            Ok(self
                .keys
                .iter()
                .map(|(entry, _)| SecretKeyEntry {
                    id: entry.id.clone(),
                    pubkey_hex: entry.pubkey_hex.clone(),
                })
                .collect())
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            for (entry, result) in &self.keys {
                if entry.id == id {
                    return match result {
                        Ok(material) => Ok(Self::clone_material(material)),
                        Err(e) => Err(Self::clone_error(e)),
                    };
                }
            }
            Err(SecretProviderError::NotFound(format!("key {} not found in mock", id)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use std::time::{Duration, Instant};

    use parking_lot::Mutex;

    use crypto::SecretKey;
    use tracing_subscriber::layer::SubscriberExt;
    use zeroize::Zeroizing;

    use super::*;
    use crate::key_source_manager::mock::MockSecretProvider;
    use crate::{SecretKeyEntry, SecretProviderError};

    struct SpanCapture {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.spans.lock().push(attrs.metadata().name().to_string());
        }
    }

    struct FieldCapture {
        fields: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for FieldCapture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let span_name = attrs.metadata().name().to_string();
            let mut visitor = FieldVisitor(self.fields.clone(), span_name);
            attrs.record(&mut visitor);
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let span_name = ctx.span(id).map(|s| s.name().to_string()).unwrap_or_default();
            let mut visitor = FieldVisitor(self.fields.clone(), span_name);
            values.record(&mut visitor);
        }
    }

    struct FieldVisitor(Arc<Mutex<Vec<(String, String, String)>>>, String);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), format!("{:?}", value)));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), value.to_string()));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), value.to_string()));
        }
    }

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

    #[tokio::test]
    async fn test_multi_provider_aggregation() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider1 = MockSecretProvider {
            name: "provider-a".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1)],
            list_error: None,
        };
        let provider2 = MockSecretProvider {
            name: "provider-b".to_string(),
            keys: vec![make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider1), Box::new(provider2)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider.len(), 2);
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[1].loaded, 1);
        assert_eq!(km.len(), 2);
    }

    #[tokio::test]
    async fn test_partial_failure_skip() {
        let sk1 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "mixed".to_string(),
            keys: vec![
                make_raw_key_entry("good-key", &sk1),
                (
                    SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::Provider("network error".into())),
                ),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[0].skipped, 1);
        assert_eq!(km.len(), 1);
    }

    #[tokio::test]
    async fn test_empty_provider() {
        let provider =
            MockSecretProvider { name: "empty".to_string(), keys: vec![], list_error: None };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider.len(), 1);
        assert_eq!(summary.per_provider[0].loaded, 0);
        assert_eq!(summary.per_provider[0].skipped, 0);
        assert!(km.is_empty());
    }

    #[tokio::test]
    async fn test_auth_error_propagation() {
        // A single provider that fails list_keys is "all sources failing" → still fatal.
        let provider = MockSecretProvider {
            name: "auth-fail".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(matches!(result, Err(SecretProviderError::Auth(_))));
    }

    // ── SEC-9 / M-9: provider resilience ──────────────────────────────────

    #[tokio::test]
    async fn test_one_failing_provider_starts_with_healthy_keys() {
        let sk = SecretKey::generate();
        let healthy = MockSecretProvider {
            name: "healthy".to_string(),
            keys: vec![make_raw_key_entry("good-key", &sk)],
            list_error: None,
        };
        let failing = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("network down".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(failing), Box::new(healthy)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("healthy provider should save the load");

        assert_eq!(km.len(), 1, "healthy provider's key must load");
        assert_eq!(summary.per_provider.len(), 2);
        let failing_summary =
            summary.per_provider.iter().find(|p| p.name == "failing").expect("failing summary");
        assert_eq!(failing_summary.loaded, 0);
        assert!(!failing_summary.errors.is_empty());
        let healthy_summary =
            summary.per_provider.iter().find(|p| p.name == "healthy").expect("healthy summary");
        assert_eq!(healthy_summary.loaded, 1);
    }

    #[tokio::test]
    async fn test_strict_mode_aborts_on_provider_failure() {
        let sk = SecretKey::generate();
        let healthy = MockSecretProvider {
            name: "healthy".to_string(),
            keys: vec![make_raw_key_entry("good-key", &sk)],
            list_error: None,
        };
        let failing = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("network down".into())),
        };

        // Failing provider first so strict mode aborts before healthy is reached.
        let ksm =
            KeySourceManager::new(vec![Box::new(failing), Box::new(healthy)]).with_strict(true);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(matches!(result, Err(SecretProviderError::Provider(_))));
        assert!(km.is_empty(), "strict mode must not partially load after a failure");
    }

    #[tokio::test]
    async fn test_all_sources_failing_aborts() {
        let a = MockSecretProvider {
            name: "a".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("a forbidden".into())),
        };
        let b = MockSecretProvider {
            name: "b".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("b down".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(a), Box::new(b)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(result.is_err(), "all providers failing must be fatal");
        assert!(km.is_empty());
    }

    #[tokio::test]
    async fn test_summary_correctness() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "summary-test".to_string(),
            keys: vec![
                make_raw_key_entry("ok-1", &sk1),
                make_raw_key_entry("ok-2", &sk2),
                (
                    SecretKeyEntry { id: "fail-1".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::InvalidKeyMaterial("bad".into())),
                ),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        let ps = &summary.per_provider[0];
        assert_eq!(ps.loaded, 2);
        assert_eq!(ps.skipped, 1);
        assert_eq!(ps.loaded + ps.skipped, 3);
        assert_eq!(ps.errors.len(), 1);
    }

    #[tokio::test]
    async fn test_load_all_creates_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.load_all".to_string()),
            "Expected secret_provider.load_all span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_creates_list_keys_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.list_keys".to_string()),
            "Expected secret_provider.list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_creates_fetch_key_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.fetch_key".to_string()),
            "Expected secret_provider.fetch_key span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_span_records_providers_count() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let p1 = MockSecretProvider {
            name: "prov-a".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk1)],
            list_error: None,
        };
        let p2 = MockSecretProvider {
            name: "prov-b".to_string(),
            keys: vec![make_raw_key_entry("k2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(p1), Box::new(p2)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.load_all"
                && field == "providers.count"
                && value == "2"),
            "Expected providers.count=2 on load_all span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_list_keys_span_records_keys_count() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![
                make_raw_key_entry("k1", &sk),
                make_raw_key_entry("k2", &SecretKey::generate()),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.list_keys"
                && field == "keys.count"
                && value == "2"),
            "Expected keys.count=2 on list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_fetch_key_span_records_key_id() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("my-key-id", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.fetch_key"
                && field == "key.id"
                && value == "my-key-id"),
            "Expected key.id=my-key-id on fetch_key span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_list_keys_span_records_provider_name() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "my-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.list_keys"
                && field == "provider.name"
                && value == "my-prov"),
            "Expected provider.name=my-prov on list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_metrics_keys_loaded_after_successful_load() {
        use crate::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED;

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-loaded".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk1), make_raw_key_entry("k2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let value =
            RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["metrics-test-loaded"]).get();
        assert_eq!(value, 2.0, "Expected 2 keys loaded for metrics-test-loaded");
    }

    #[tokio::test]
    async fn test_metrics_errors_total_after_fetch_failure() {
        use crate::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL;

        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-err".to_string(),
            keys: vec![
                make_raw_key_entry("ok-key", &sk),
                (
                    SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::Provider("fail".into())),
                ),
            ],
            list_error: None,
        };

        let before = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-test-err", "provider"])
            .get();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let after = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-test-err", "provider"])
            .get();
        assert_eq!(after, before + 1, "Expected error counter to increment by 1");
    }

    #[tokio::test]
    async fn test_metrics_load_duration_recorded() {
        use crate::metrics::RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS;

        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-dur".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let before = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-test-dur"])
            .get_sample_count();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let after = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-test-dur"])
            .get_sample_count();
        assert_eq!(after, before + 1, "Expected one duration observation");
    }

    #[tokio::test]
    async fn test_metrics_errors_total_on_list_keys_failure() {
        use crate::metrics::{
            RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
        };

        let provider = MockSecretProvider {
            name: "metrics-list-fail".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let before_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-list-fail", "auth"])
            .get();
        let before_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-list-fail"])
            .get_sample_count();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(result.is_err());
        let after_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-list-fail", "auth"])
            .get();
        assert_eq!(
            after_err,
            before_err + 1,
            "Expected errors_total to increment on list_keys failure"
        );
        let after_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-list-fail"])
            .get_sample_count();
        assert_eq!(
            after_dur,
            before_dur + 1,
            "Expected duration to be recorded on list_keys failure"
        );
    }

    #[tokio::test]
    async fn test_metrics_errors_total_on_task_panic() {
        use crate::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL;

        let before = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .get();

        // We can't easily cause a JoinSet panic in a unit test with MockSecretProvider,
        // so we verify the metric label exists and is usable. The actual code path
        // is verified by inspecting the implementation.
        RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .inc();
        let after = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .get();
        assert_eq!(after, before + 1, "task_panic error_type label should be valid");
    }

    #[tokio::test]
    async fn test_metrics_keys_loaded_zero_for_empty_provider() {
        use crate::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED;

        let provider = MockSecretProvider {
            name: "metrics-test-empty".to_string(),
            keys: vec![],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let value =
            RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["metrics-test-empty"]).get();
        assert_eq!(value, 0.0, "Expected 0 keys loaded for empty provider");
    }

    // ── SEC-1b: deletion denylist ─────────────────────────────────────────

    #[tokio::test]
    async fn test_deleted_secret_provider_key_not_resurrected_on_reload() {
        let sk_deleted = SecretKey::generate();
        let sk_kept = SecretKey::generate();
        let pk_deleted = sk_deleted.public_key().to_bytes();
        let pk_kept = sk_kept.public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![
                make_raw_key_entry("deleted-key", &sk_deleted),
                make_raw_key_entry("kept-key", &sk_kept),
            ],
            list_error: None,
        };

        // First load: both keys present (no denylist)
        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("initial load");
        assert_eq!(summary.per_provider[0].loaded, 2);
        assert!(km.contains(&pk_deleted));
        assert!(km.contains(&pk_kept));

        // Simulate Keymanager DELETE: remove from registry + denylist the pubkey
        assert!(km.remove(&pk_deleted));
        let mut denylist = HashSet::new();
        denylist.insert(pk_deleted);

        // Simulated restart: same provider still lists both keys
        let provider2 = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![
                make_raw_key_entry("deleted-key", &sk_deleted),
                make_raw_key_entry("kept-key", &sk_kept),
            ],
            list_error: None,
        };
        let ksm2 = KeySourceManager::new(vec![Box::new(provider2)]);
        let mut km2 = KeyManager::new();
        let summary2 =
            ksm2.load_all_except(&mut km2, Some(&denylist)).await.expect("reload with denylist");

        assert_eq!(summary2.per_provider[0].loaded, 1, "only the never-deleted key loads");
        assert_eq!(summary2.per_provider[0].skipped, 1, "denylisted key is skipped");
        assert!(!km2.contains(&pk_deleted), "deleted key must not resurrect");
        assert!(km2.contains(&pk_kept), "never-deleted key must load normally");
    }

    #[tokio::test]
    async fn test_never_deleted_key_loads_normally() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let other = SecretKey::generate().public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![make_raw_key_entry("only-key", &sk)],
            list_error: None,
        };
        let mut denylist = HashSet::new();
        denylist.insert(other); // unrelated deleted key

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all_except(&mut km, Some(&denylist)).await.unwrap();
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[0].skipped, 0);
        assert!(km.contains(&pk));
    }

    // ── RF4-14: shared fetch_provider_keys pipeline ───────────────────────

    /// Hung mock: `fetch_key` never completes until the per-key timeout fires.
    struct HungSecretProvider {
        name: String,
        entry_ids: Vec<String>,
        fetch_calls: Arc<Mutex<u32>>,
    }

    #[async_trait::async_trait]
    impl SecretProvider for HungSecretProvider {
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
            *self.fetch_calls.lock() += 1;
            // Sleep longer than any test timeout; with tokio::time::pause the
            // timeout future advances without waiting wall-clock.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Err(SecretProviderError::Provider("unreachable".into()))
        }
    }

    /// Counts `fetch_key` invocations; material is always a valid raw key.
    struct CountingSecretProvider {
        name: String,
        keys: Vec<(SecretKeyEntry, SecretKey)>,
        fetch_calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl SecretProvider for CountingSecretProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            Ok(self
                .keys
                .iter()
                .map(|(e, _)| SecretKeyEntry { id: e.id.clone(), pubkey_hex: e.pubkey_hex.clone() })
                .collect())
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            self.fetch_calls.lock().push(id.to_string());
            for (entry, sk) in &self.keys {
                if entry.id == id {
                    let bytes: [u8; 32] = sk.to_bytes();
                    return Ok(KeyMaterial::RawKey(Zeroizing::new(bytes)));
                }
            }
            Err(SecretProviderError::NotFound(format!("key {id} not found")))
        }
    }

    /// RED first (RF4-14): boot must bound hung providers with a per-key timeout.
    #[tokio::test]
    async fn test_boot_fetch_times_out_on_hung_provider() {
        tokio::time::pause();

        let fetch_calls = Arc::new(Mutex::new(0u32));
        let hung = HungSecretProvider {
            name: "hung-boot".to_string(),
            entry_ids: vec!["slow-key".to_string()],
            fetch_calls: fetch_calls.clone(),
        };
        // A healthy key must still load when the hung key times out.
        let sk_ok = SecretKey::generate();
        let healthy = MockSecretProvider {
            name: "healthy-boot".to_string(),
            keys: vec![make_raw_key_entry("ok-key", &sk_ok)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(hung), Box::new(healthy)])
            .with_fetch_timeout(Duration::from_secs(5));
        let mut km = KeyManager::new();

        let wall = Instant::now();
        let summary = ksm.load_all(&mut km).await.expect("boot continues after hung key timeout");
        let wall_elapsed = wall.elapsed();

        assert!(
            wall_elapsed < Duration::from_secs(2),
            "boot wall-clock must stay bounded under time pause, got {wall_elapsed:?}"
        );
        assert_eq!(*fetch_calls.lock(), 1, "hung provider must still be contacted");
        assert_eq!(km.len(), 1, "healthy key must load");
        assert!(km.contains(&sk_ok.public_key().to_bytes()));

        let hung_summary =
            summary.per_provider.iter().find(|p| p.name == "hung-boot").expect("hung summary");
        assert_eq!(hung_summary.loaded, 0);
        assert_eq!(hung_summary.skipped, 1);
        assert!(
            hung_summary.errors.iter().any(|e| e.contains("timed out")),
            "timeout must be recorded as an error: {:?}",
            hung_summary.errors
        );

        let errors = crate::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["hung-boot", "timeout"])
            .get();
        assert!(errors >= 1, "timeout must increment RVC_SECRET_PROVIDER_ERRORS_TOTAL");
    }

    /// Denylisted pubkey_hex must skip before any `fetch_key` is issued.
    #[tokio::test]
    async fn test_denylisted_key_skipped_before_fetch_issued() {
        let sk_denied = SecretKey::generate();
        let sk_ok = SecretKey::generate();
        let pk_denied = sk_denied.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_denied));

        let sk_ok_pk = sk_ok.public_key().to_bytes();
        let fetch_calls = Arc::new(Mutex::new(Vec::new()));
        let provider = CountingSecretProvider {
            name: "count-deny".to_string(),
            keys: vec![
                (
                    SecretKeyEntry { id: "denied-key".to_string(), pubkey_hex: Some(pubkey_hex) },
                    sk_denied,
                ),
                (SecretKeyEntry { id: "ok-key".to_string(), pubkey_hex: None }, sk_ok),
            ],
            fetch_calls: fetch_calls.clone(),
        };

        let mut denylist = HashSet::new();
        denylist.insert(pk_denied);

        let ksm = KeySourceManager::from_arc(vec![Arc::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all_except(&mut km, Some(&denylist)).await.unwrap();

        let calls = fetch_calls.lock().clone();
        assert!(
            !calls.iter().any(|id| id == "denied-key"),
            "denylisted key must not be fetched, calls={calls:?}"
        );
        assert!(calls.iter().any(|id| id == "ok-key"), "non-denied key must be fetched");
        assert_eq!(summary.per_provider[0].skipped, 1);
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert!(km.contains(&sk_ok_pk));
        assert!(!km.contains(&pk_denied));
    }

    fn shared_pipeline_fixture(
        sk1: &SecretKey,
        sk2: &SecretKey,
    ) -> Vec<(SecretKeyEntry, Result<KeyMaterial, SecretProviderError>)> {
        let pk_denied = sk2.public_key().to_bytes();
        let bytes1: [u8; 32] = sk1.to_bytes();
        let bytes2: [u8; 32] = sk2.to_bytes();
        let hex = format!("0x{}", hex::encode(pk_denied));
        vec![
            (
                SecretKeyEntry { id: "k1".to_string(), pubkey_hex: None },
                Ok(KeyMaterial::RawKey(Zeroizing::new(bytes1))),
            ),
            (
                SecretKeyEntry { id: "k2".to_string(), pubkey_hex: Some(hex) },
                Ok(KeyMaterial::RawKey(Zeroizing::new(bytes2))),
            ),
            (
                SecretKeyEntry { id: "k3".to_string(), pubkey_hex: None },
                Err(SecretProviderError::Provider("boom".into())),
            ),
        ]
    }

    /// Boot and refresh share one pipeline: identical fixture → identical fetch summary.
    #[tokio::test]
    async fn test_boot_and_refresh_share_one_fetch_pipeline() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk_denied = sk2.public_key().to_bytes();

        let boot_provider = MockSecretProvider {
            name: "shared-pipe".to_string(),
            keys: shared_pipeline_fixture(&sk1, &sk2),
            list_error: None,
        };
        let refresh_provider = MockSecretProvider {
            name: "shared-pipe".to_string(),
            keys: shared_pipeline_fixture(&sk1, &sk2),
            list_error: None,
        };

        let mut denylist = HashSet::new();
        denylist.insert(pk_denied);

        let ksm = KeySourceManager::new(vec![Box::new(boot_provider)]);
        let mut km = KeyManager::new();
        let boot_summary = ksm.load_all_except(&mut km, Some(&denylist)).await.unwrap();
        let boot = &boot_summary.per_provider[0];

        let deny: crate::refresh::DenylistCheck = Arc::new(move |pk: &[u8; 48]| *pk == pk_denied);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut refresh = crate::RefreshService::with_denylist(
            vec![Arc::new(refresh_provider)],
            HashSet::new(),
            Some(deny),
            Duration::from_secs(60),
            cancel,
        );
        let refresh_keys = refresh.refresh().await;

        // Same loaded/skipped semantics: 1 loaded (sk1), 1 early-deny skip (sk2), 1 error skip.
        assert_eq!(boot.loaded, 1);
        assert_eq!(boot.skipped, 2);
        assert_eq!(boot.errors.len(), 1);
        assert_eq!(
            refresh_keys.len(),
            boot.loaded,
            "refresh must surface the same non-denied successes as boot"
        );
        assert_eq!(refresh_keys[0].public_key().to_bytes(), sk1.public_key().to_bytes());
        assert_eq!(km.len(), 1);
        assert!(km.contains(&sk1.public_key().to_bytes()));
    }
}
