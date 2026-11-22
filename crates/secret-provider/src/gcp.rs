use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use eth_types::canonical::pubkey_hex::parse_pubkey_hex;
use google_cloud_gax::error::rpc::Code;
use google_cloud_gax::paginator::ItemPaginator as _;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use tracing::{debug, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::{KeyMaterial, SecretKeyEntry, SecretProvider, SecretProviderError};

pub struct GcpSecretProviderConfig {
    pub project_id: String,
    pub prefix: String,
}

impl Default for GcpSecretProviderConfig {
    fn default() -> Self {
        Self { project_id: String::new(), prefix: "validator-key-".to_string() }
    }
}

pub struct GcpSecretProvider {
    client: SecretManagerService,
    project_id: String,
    prefix: String,
    /// Secret ids already warned because the suffix is not a pubkey.
    ///
    /// This lock guards only that set. It is never held across an await. A
    /// poisoned lock is recovered with `into_inner` so a panicked holder cannot
    /// take down listing.
    opaque_warned: Mutex<HashSet<String>>,
}

impl GcpSecretProvider {
    pub async fn new(config: GcpSecretProviderConfig) -> Result<Self, SecretProviderError> {
        let client = SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| SecretProviderError::Auth(format!("failed to create GCP client: {e}")))?;

        Ok(Self {
            client,
            project_id: config.project_id,
            prefix: config.prefix,
            opaque_warned: Mutex::new(HashSet::new()),
        })
    }

    fn parent(&self) -> String {
        format!("projects/{}", self.project_id)
    }

    fn secret_version_name(&self, secret_id: &str) -> String {
        format!("projects/{}/secrets/{}/versions/latest", self.project_id, secret_id)
    }

    async fn access_secret_payload(
        &self,
        secret_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecretProviderError> {
        let name = self.secret_version_name(secret_id);
        let response = self
            .client
            .access_secret_version()
            .set_name(&name)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, &name))?;

        let payload = response
            .payload
            .ok_or_else(|| SecretProviderError::Provider("empty payload".into()))?;

        Ok(Zeroizing::new(payload.data.to_vec()))
    }

    async fn fetch_companion_password(
        &self,
        secret_id: &str,
    ) -> Result<Zeroizing<String>, SecretProviderError> {
        let password_id = format!("{secret_id}-password");
        let data = self.access_secret_payload(&password_id).await?;
        let raw_bytes = data.to_vec();
        let password = match String::from_utf8(raw_bytes) {
            Ok(s) => s,
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                return Err(SecretProviderError::InvalidKeyMaterial(format!(
                    "password secret {password_id} is not valid UTF-8"
                )));
            }
        };
        let result = Zeroizing::new(password.trim().to_string());
        let mut password = password;
        password.zeroize();
        Ok(result)
    }

    /// Warn once per id whose suffix is not a pubkey. The lock is dropped before
    /// logging so a subscriber cannot deadlock on it.
    fn note_opaque_ids(&self, entries: &[SecretKeyEntry]) {
        let mut fresh = Vec::new();
        {
            let mut seen =
                self.opaque_warned.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            for entry in entries {
                if entry.pubkey_hex.is_none() && first_sighting(&mut seen, &entry.id) {
                    fresh.push(entry.id.clone());
                }
            }
        }
        for id in fresh {
            warn!(
                secret_id = %id,
                prefix = %self.prefix,
                "GCP secret id suffix is not a pubkey; the secret still loads"
            );
        }
    }
}

fn extract_secret_id(full_name: &str) -> &str {
    full_name.rsplit('/').next().unwrap_or(full_name)
}

/// Quoted server pre-filter. `"` and `\` inside the prefix are escaped so the
/// filter stays one string literal. The client prefix check does not use this
/// string.
fn list_filter(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if c == '\\' || c == '"' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    format!("name:\"{escaped}\"")
}

/// Keep ids that start with `prefix` (case-sensitive). Companion `-password`
/// ids are dropped after that check. `pubkey_hex` is set only when the suffix
/// parses as a pubkey.
///
/// An empty prefix matches every id. That is intentional: `starts_with("")` is
/// true, so an operator who sets the prefix empty loads every non-password
/// secret in the project.
fn select_entries<'a>(ids: impl IntoIterator<Item = &'a str>, prefix: &str) -> Vec<SecretKeyEntry> {
    let mut entries = Vec::new();
    for id in ids {
        if !id.starts_with(prefix) {
            continue;
        }
        if id.ends_with("-password") {
            debug!(secret_id = id, "skipping companion password secret");
            continue;
        }
        entries.push(SecretKeyEntry {
            id: id.to_string(),
            pubkey_hex: extract_pubkey_from_name(id, prefix),
        });
    }
    entries
}

fn extract_pubkey_from_name(secret_id: &str, prefix: &str) -> Option<String> {
    let suffix = secret_id.strip_prefix(prefix)?;
    parse_pubkey_hex(suffix).ok()?;
    Some(suffix.to_string())
}

/// True the first time `id` is inserted into `seen`.
fn first_sighting(seen: &mut HashSet<String>, id: &str) -> bool {
    seen.insert(id.to_string())
}

fn map_sdk_error(err: google_cloud_secretmanager_v1::Error, context: &str) -> SecretProviderError {
    if let Some(status) = err.status() {
        match status.code {
            Code::Unauthenticated => {
                return SecretProviderError::Auth(format!("unauthenticated: {err}"));
            }
            Code::PermissionDenied => {
                return SecretProviderError::Auth(format!("permission denied: {err}"));
            }
            Code::NotFound => {
                return SecretProviderError::NotFound(context.to_string());
            }
            _ => {}
        }
    }

    if let Some(code) = err.http_status_code() {
        match code {
            401 | 403 => return SecretProviderError::Auth(format!("{err}")),
            404 => return SecretProviderError::NotFound(context.to_string()),
            _ => {}
        }
    }

    SecretProviderError::Provider(format!("{err}"))
}

#[async_trait]
impl SecretProvider for GcpSecretProvider {
    fn name(&self) -> &str {
        "gcp"
    }

    #[tracing::instrument(name = "secret_provider.gcp.list", skip_all, fields(keys.count = tracing::field::Empty))]
    async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
        let filter = list_filter(&self.prefix);
        let parent = self.parent();

        let mut items = self
            .client
            .list_secrets()
            .set_parent(&parent)
            .set_filter(&filter)
            .set_page_size(100)
            .by_item();

        let mut ids = Vec::new();
        while let Some(item) = items.next().await {
            let secret = item.map_err(|e| map_sdk_error(e, &parent))?;
            ids.push(extract_secret_id(&secret.name).to_string());
        }

        let entries = select_entries(ids.iter().map(String::as_str), &self.prefix);
        self.note_opaque_ids(&entries);

        tracing::Span::current().record("keys.count", entries.len());
        debug!(count = entries.len(), "listed GCP secrets");
        Ok(entries)
    }

    #[tracing::instrument(name = "secret_provider.gcp.fetch", skip_all, fields(key.id = %id))]
    async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
        let data = self.access_secret_payload(id).await?;

        let result = match crate::format::parse_secret_data(&data)? {
            crate::format::SecretDataFormat::KeystoreJson(json) => {
                let password = self.fetch_companion_password(id).await.map_err(|e| {
                    warn!(secret_id = id, error = %e, "failed to fetch companion password");
                    e
                })?;
                Ok(KeyMaterial::Keystore { keystore_json: json, password })
            }
            crate::format::SecretDataFormat::RawHex(key) => Ok(KeyMaterial::RawKey(key)),
        };

        if result.is_ok() {
            debug!(key_id = id, "GCP fetch completed");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use crypto::{KeyManager, SecretKey};
    use google_cloud_gax::error::rpc::{Code, Status};
    use google_cloud_gax::error::Error as GaxError;
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_secretmanager_v1::model::{
        AccessSecretVersionRequest, AccessSecretVersionResponse, ListSecretsRequest,
        ListSecretsResponse, Secret, SecretPayload,
    };
    use google_cloud_secretmanager_v1::stub::SecretManagerService as SecretManagerStub;
    use tracing::field::Visit;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;
    use crate::{KeySourceManager, SecretProvider};

    #[test]
    fn test_extract_secret_id_full_path() {
        let name = "projects/my-project/secrets/validator-key-abc123";
        assert_eq!(extract_secret_id(name), "validator-key-abc123");
    }

    #[test]
    fn test_extract_secret_id_bare_name() {
        assert_eq!(extract_secret_id("validator-key-abc"), "validator-key-abc");
    }

    #[test]
    fn test_extract_pubkey_with_prefix() {
        let suffix = format!("0x{}", "ab".repeat(48));
        let id = format!("validator-key-{suffix}");
        let pubkey = extract_pubkey_from_name(&id, "validator-key-");
        assert_eq!(pubkey.as_deref(), Some(suffix.as_str()));
    }

    #[test]
    fn test_extract_pubkey_rejects_non_pubkey_suffix() {
        assert_eq!(extract_pubkey_from_name("validator-key-0xabc123", "validator-key-"), None);
    }

    #[test]
    fn test_extract_pubkey_no_prefix() {
        let id = "other-secret";
        let pubkey = extract_pubkey_from_name(id, "validator-key-");
        assert_eq!(pubkey, None);
    }

    #[test]
    fn test_format_detection_delegates_to_format_module() {
        use crate::format::{parse_secret_data, SecretDataFormat};

        // JSON detection
        let data = br#"{"version":4,"crypto":{}}"#;
        assert!(matches!(parse_secret_data(data), Ok(SecretDataFormat::KeystoreJson(_))));

        // Hex detection
        let hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(matches!(parse_secret_data(hex.as_bytes()), Ok(SecretDataFormat::RawHex(_))));

        // Non-UTF-8 returns error
        let data = [0xFF, 0xFE, 0x00, 0x01];
        assert!(parse_secret_data(&data).is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = GcpSecretProviderConfig::default();
        assert_eq!(config.prefix, "validator-key-");
        assert!(config.project_id.is_empty());
    }

    #[test]
    fn test_config_custom() {
        let config =
            GcpSecretProviderConfig { project_id: "my-project".into(), prefix: "bls-key-".into() };
        assert_eq!(config.project_id, "my-project");
        assert_eq!(config.prefix, "bls-key-");
    }

    #[test]
    fn test_secret_version_name_format() {
        // We can't construct GcpSecretProvider without a real client,
        // but we can test the format helper logic directly.
        let project_id = "my-project";
        let secret_id = "validator-key-abc";
        let expected = "projects/my-project/secrets/validator-key-abc/versions/latest";
        let result = format!("projects/{project_id}/secrets/{secret_id}/versions/latest");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parent_format() {
        let project_id = "my-project";
        let result = format!("projects/{project_id}");
        assert_eq!(result, "projects/my-project");
    }

    #[test]
    fn test_password_secret_skipped_in_name_check() {
        let id = "validator-key-abc-password";
        assert!(id.ends_with("-password"));
    }

    #[test]
    fn test_non_password_secret_not_skipped() {
        let id = "validator-key-abc";
        assert!(!id.ends_with("-password"));
    }

    /// One listed page: secrets, then the `next_page_token` returned with that page.
    type ScriptedPage = (Vec<(String, Vec<u8>)>, String);

    /// Server-side stand-in. Ignores `filter` and returns every configured id, so a
    /// contains-style or wider server result cannot be mistaken for the client check.
    #[derive(Debug)]
    struct FakeGcp {
        inner: Arc<FakeState>,
    }

    struct Page {
        request_token: String,
        ids: Vec<String>,
        next_page_token: String,
    }

    struct FakeState {
        project_id: String,
        pages: Vec<Page>,
        payloads: HashMap<String, Vec<u8>>,
        filters: Mutex<Vec<String>>,
        page_tokens: Mutex<Vec<String>>,
        accessed: Mutex<Vec<String>>,
        /// When the request `page_token` equals this, `list_secrets` fails.
        fail_list_on_token: Option<String>,
    }

    impl std::fmt::Debug for FakeState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeState")
                .field("project_id", &self.project_id)
                .field("page_count", &self.pages.len())
                .field("payload_ids", &self.payloads.keys().collect::<Vec<_>>())
                .finish()
        }
    }

    impl FakeGcp {
        fn single_page(
            project_id: &str,
            secrets: Vec<(String, Vec<u8>)>,
        ) -> (Self, Arc<FakeState>) {
            Self::with_pages(project_id, vec![(secrets, String::new())], None)
        }

        fn with_pages(
            project_id: &str,
            pages: Vec<ScriptedPage>,
            fail_list_on_token: Option<String>,
        ) -> (Self, Arc<FakeState>) {
            let mut payloads = HashMap::new();
            let mut scripted = Vec::new();
            let mut request_token = String::new();
            for (secrets, next_page_token) in pages {
                let mut ids = Vec::new();
                for (id, payload) in secrets {
                    ids.push(id.clone());
                    payloads.insert(id, payload);
                }
                scripted.push(Page {
                    request_token: request_token.clone(),
                    ids,
                    next_page_token: next_page_token.clone(),
                });
                request_token = next_page_token;
            }
            let inner = Arc::new(FakeState {
                project_id: project_id.to_string(),
                pages: scripted,
                payloads,
                filters: Mutex::new(Vec::new()),
                page_tokens: Mutex::new(Vec::new()),
                accessed: Mutex::new(Vec::new()),
                fail_list_on_token,
            });
            (Self { inner: Arc::clone(&inner) }, inner)
        }
    }

    fn secret_id_from_version_name(name: &str) -> &str {
        let mut parts = name.split('/');
        while let Some(part) = parts.next() {
            if part == "secrets" {
                return parts.next().unwrap_or("");
            }
        }
        name
    }

    impl SecretManagerStub for FakeGcp {
        fn list_secrets(
            &self,
            req: ListSecretsRequest,
            _options: RequestOptions,
        ) -> impl std::future::Future<
            Output = google_cloud_secretmanager_v1::Result<Response<ListSecretsResponse>>,
        > + Send {
            self.inner.filters.lock().expect("filter log").push(req.filter.clone());
            self.inner.page_tokens.lock().expect("page-token log").push(req.page_token.clone());
            let result =
                if self.inner.fail_list_on_token.as_deref() == Some(req.page_token.as_str()) {
                    Err(GaxError::service(
                        Status::default().set_code(Code::NotFound).set_message("list failed"),
                    ))
                } else {
                    let page =
                        self.inner.pages.iter().find(|page| page.request_token == req.page_token);
                    let (ids, next) = match page {
                        Some(page) => (page.ids.clone(), page.next_page_token.clone()),
                        None => (Vec::new(), String::new()),
                    };
                    let project_id = self.inner.project_id.clone();
                    let body = ListSecretsResponse::new()
                        .set_secrets(ids.into_iter().map(|id| {
                            Secret::new().set_name(format!("projects/{project_id}/secrets/{id}"))
                        }))
                        .set_next_page_token(next);
                    Ok(Response::from(body))
                };
            std::future::ready(result)
        }

        fn access_secret_version(
            &self,
            req: AccessSecretVersionRequest,
            _options: RequestOptions,
        ) -> impl std::future::Future<
            Output = google_cloud_secretmanager_v1::Result<Response<AccessSecretVersionResponse>>,
        > + Send {
            self.inner.accessed.lock().expect("access log").push(req.name.clone());
            let id = secret_id_from_version_name(&req.name).to_string();
            let result = match self.inner.payloads.get(&id) {
                Some(data) => Ok(Response::from(
                    AccessSecretVersionResponse::new()
                        .set_name(req.name)
                        .set_payload(SecretPayload::new().set_data(data.clone())),
                )),
                None => Err(GaxError::service(
                    Status::default().set_code(Code::NotFound).set_message("missing secret"),
                )),
            };
            std::future::ready(result)
        }
    }

    fn fake_gcp_provider(stub: FakeGcp, project_id: &str, prefix: &str) -> GcpSecretProvider {
        GcpSecretProvider {
            client: SecretManagerService::from_stub(stub),
            project_id: project_id.to_string(),
            prefix: prefix.to_string(),
            opaque_warned: Mutex::new(HashSet::new()),
        }
    }

    #[allow(clippy::disallowed_methods)] // test payload is the key's own bytes; never logged
    fn raw_hex_payload(sk: &SecretKey) -> Vec<u8> {
        hex::encode(sk.to_bytes()).into_bytes()
    }

    fn pubkey_hex_of(sk: &SecretKey) -> String {
        format!("0x{}", hex::encode(sk.public_key().to_bytes()))
    }

    fn version_name(project_id: &str, id: &str) -> String {
        format!("projects/{project_id}/secrets/{id}/versions/latest")
    }

    const PREFIX: &str = "validator-key-";
    const PROJECT: &str = "shared-project";

    #[derive(Debug)]
    struct WarnEvent {
        fields: Vec<(String, String)>,
    }

    struct WarnCapture {
        events: Arc<Mutex<Vec<WarnEvent>>>,
    }

    struct WarnVisitor {
        fields: Vec<(String, String)>,
    }

    impl Visit for WarnVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields.push((field.name().to_string(), format!("{value:?}")));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields.push((field.name().to_string(), value.to_string()));
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = WarnVisitor { fields: Vec::new() };
            event.record(&mut visitor);
            self.events.lock().expect("warn log").push(WarnEvent { fields: visitor.fields });
        }
    }

    fn field_value<'a>(event: &'a WarnEvent, name: &str) -> Option<&'a str> {
        event.fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.trim_matches('"'))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn key_source_manager_loads_only_strict_prefix_secrets_from_gcp() {
        let sk_a = SecretKey::generate();
        let sk_b = SecretKey::generate();
        let sk_c = SecretKey::generate();
        let sk_d = SecretKey::generate();
        let pk_a = sk_a.public_key().to_bytes();
        let pk_b = sk_b.public_key().to_bytes();
        let pk_c = sk_c.public_key().to_bytes();
        let pk_d = sk_d.public_key().to_bytes();

        let id_a = format!("{PREFIX}{}", pubkey_hex_of(&sk_a));
        let id_old = format!("old-validator-key-{}", pubkey_hex_of(&sk_b));
        let id_b = format!("b-validator-key-{}", pubkey_hex_of(&sk_c));
        let id_case = format!("Validator-Key-{}", pubkey_hex_of(&sk_d));
        let id_password = format!("{id_a}-password");

        let (stub, state) = FakeGcp::single_page(
            PROJECT,
            vec![
                (id_a.clone(), raw_hex_payload(&sk_a)),
                (id_old.clone(), raw_hex_payload(&sk_b)),
                (id_b.clone(), raw_hex_payload(&sk_c)),
                (id_case.clone(), raw_hex_payload(&sk_d)),
                (id_password.clone(), b"not-a-key".to_vec()),
            ],
        );
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.expect("load");

        assert!(km.contains(&pk_a), "strict prefix key loads");
        assert!(!km.contains(&pk_b), "old-validator-key neighbour must not load");
        assert!(!km.contains(&pk_c), "b-validator-key neighbour must not load");
        assert!(!km.contains(&pk_d), "case variant must not load");
        assert_eq!(km.len(), 1);

        let accessed: HashSet<_> =
            state.accessed.lock().expect("access log").iter().cloned().collect();
        assert_eq!(
            accessed,
            HashSet::from([version_name(PROJECT, &id_a)]),
            "non-matching ids must not be fetched, accessed={accessed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_keys_sends_a_quoted_prefix_filter() {
        let (stub, state) = FakeGcp::single_page(PROJECT, Vec::new());
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        provider.list_keys().await.expect("list");
        let filters = state.filters.lock().expect("filter log").clone();
        assert_eq!(filters, vec!["name:\"validator-key-\"".to_string()]);

        let quoted = "pre\"fix\\";
        let match_id = format!("{quoted}kept");
        let neighbour = format!("x{quoted}kept");
        let (stub, state) = FakeGcp::single_page(
            PROJECT,
            vec![(match_id.clone(), b"aa".to_vec()), (neighbour, b"bb".to_vec())],
        );
        let provider = fake_gcp_provider(stub, PROJECT, quoted);
        let entries = provider.list_keys().await.expect("list quoted");
        let filters = state.filters.lock().expect("filter log").clone();
        assert_eq!(filters, vec!["name:\"pre\\\"fix\\\\\"".to_string()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, match_id);
        assert!(entries[0].pubkey_hex.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_keys_with_an_empty_prefix_keeps_non_password_ids() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let id_other = "other-fleet-secret";
        let id_password = "other-fleet-secret-password";
        let (stub, state) = FakeGcp::single_page(
            PROJECT,
            vec![
                (id_other.to_string(), raw_hex_payload(&sk)),
                (id_password.to_string(), b"secret-password".to_vec()),
            ],
        );
        let provider = fake_gcp_provider(stub, PROJECT, "");
        let entries = provider.list_keys().await.expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id_other);
        assert!(entries[0].pubkey_hex.is_none());
        assert_eq!(state.filters.lock().expect("filter log").as_slice(), ["name:\"\""]);

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.expect("empty prefix still loads");
        assert!(km.contains(&pk));
        assert_eq!(km.len(), 1);
        let accessed: HashSet<_> =
            state.accessed.lock().expect("access log").iter().cloned().collect();
        assert_eq!(accessed, HashSet::from([version_name(PROJECT, id_other)]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_non_pubkey_suffix_loads_without_a_pubkey_and_warns_once() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let id = format!("{PREFIX}7");
        let (stub, _state) =
            FakeGcp::single_page(PROJECT, vec![(id.clone(), raw_hex_payload(&sk))]);
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);

        let events = Arc::new(Mutex::new(Vec::new()));
        let layer = WarnCapture { events: Arc::clone(&events) };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let first = provider.list_keys().await.expect("first list");
        let second = provider.list_keys().await.expect("second list");
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].id, id);
        assert_eq!(second[0].id, id);
        assert!(first[0].pubkey_hex.is_none());
        assert!(second[0].pubkey_hex.is_none());

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.expect("opaque id still loads");
        assert!(km.contains(&pk));
        assert_eq!(km.len(), 1);

        let captured = events.lock().expect("warn log");
        let naming_id: Vec<_> = captured
            .iter()
            .filter(|event| field_value(event, "secret_id") == Some(id.as_str()))
            .collect();
        assert_eq!(naming_id.len(), 1, "warn once, got {captured:?}");
        assert_eq!(field_value(naming_id[0], "prefix"), Some(PREFIX));
        assert_eq!(
            field_value(naming_id[0], "message"),
            Some("GCP secret id suffix is not a pubkey; the secret still loads")
        );
        let payload = String::from_utf8(raw_hex_payload(&sk)).expect("hex is utf-8");
        assert!(
            naming_id[0].fields.iter().all(|(_, value)| !value.contains(&payload)),
            "warn must not include key material"
        );
        let names: HashSet<_> = naming_id[0].fields.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(names, HashSet::from(["secret_id", "prefix", "message"]));
    }

    #[test]
    fn select_entries_keeps_only_case_sensitive_prefix_matches() {
        let lower = format!("0x{}", "ab".repeat(48));
        let upper = format!("0X{}", "CD".repeat(48));
        assert!(parse_pubkey_hex(&lower).is_ok());
        assert!(parse_pubkey_hex(&upper).is_ok());

        struct Kept {
            prefix: String,
            id: String,
            pubkey_hex: Option<String>,
        }
        let kept = vec![
            Kept {
                prefix: PREFIX.to_string(),
                id: format!("{PREFIX}{lower}"),
                pubkey_hex: Some(lower.clone()),
            },
            Kept {
                prefix: PREFIX.to_string(),
                id: format!("{PREFIX}{upper}"),
                pubkey_hex: Some(upper.clone()),
            },
            Kept { prefix: PREFIX.to_string(), id: PREFIX.to_string(), pubkey_hex: None },
            Kept { prefix: PREFIX.to_string(), id: format!("{PREFIX}7"), pubkey_hex: None },
            Kept {
                prefix: String::new(),
                id: format!("old-validator-key-{lower}"),
                pubkey_hex: None,
            },
            Kept { prefix: String::new(), id: lower.clone(), pubkey_hex: Some(lower.clone()) },
            Kept {
                prefix: "pre\"fix-".to_string(),
                id: format!("pre\"fix-{lower}"),
                pubkey_hex: Some(lower.clone()),
            },
            Kept {
                prefix: "a:b *".to_string(),
                id: format!("a:b *{lower}"),
                pubkey_hex: Some(lower.clone()),
            },
        ];
        for row in &kept {
            let entries = select_entries([row.id.as_str()], &row.prefix);
            assert_eq!(entries.len(), 1, "kept {}", row.id);
            assert_eq!(entries[0].id, row.id);
            assert_eq!(entries[0].pubkey_hex, row.pubkey_hex);
        }

        let dropped = [
            (PREFIX, format!("old-validator-key-{lower}")),
            (PREFIX, format!("b-validator-key-{lower}")),
            (PREFIX, format!("Validator-Key-{lower}")),
            (PREFIX, format!("{PREFIX}{lower}-password")),
            (PREFIX, format!("x{PREFIX}{lower}")),
            ("", "companion-password".to_string()),
            ("pre\"fix-", format!("prefix-{lower}")),
            ("a:b *", format!("xa:b *{lower}")),
        ];
        for (prefix, id) in &dropped {
            let entries = select_entries([id.as_str()], prefix);
            assert!(entries.is_empty(), "{id} must be dropped for prefix {prefix:?}");
        }

        let filters = [
            ("validator-key-", "name:\"validator-key-\""),
            ("", "name:\"\""),
            ("pre\"fix-", "name:\"pre\\\"fix-\""),
            ("pre\\fix-", "name:\"pre\\\\fix-\""),
            ("a:b *", "name:\"a:b *\""),
        ];
        for (prefix, expected) in filters {
            assert_eq!(list_filter(prefix), expected, "filter for {prefix:?}");
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let layer = WarnCapture { events: Arc::clone(&events) };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let _ = select_entries(
            ["old-validator-key-abc-password", "validator-key-abc-password"],
            PREFIX,
        );
        let captured = events.lock().expect("debug log");
        let skips: Vec<_> = captured
            .iter()
            .filter(|event| {
                field_value(event, "message") == Some("skipping companion password secret")
            })
            .collect();
        assert_eq!(skips.len(), 1, "password skip is logged only after the prefix matches");
        assert_eq!(field_value(skips[0], "secret_id"), Some("validator-key-abc-password"));
    }

    #[test]
    fn first_sighting_is_true_only_for_a_new_id() {
        let mut seen = HashSet::new();
        assert!(first_sighting(&mut seen, "validator-key-7"));
        assert!(!first_sighting(&mut seen, "validator-key-7"));
        assert!(first_sighting(&mut seen, "validator-key-"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_keys_reads_every_page_before_the_prefix_check() {
        let sk_a = SecretKey::generate();
        let sk_b = SecretKey::generate();
        let sk_c = SecretKey::generate();
        let sk_d = SecretKey::generate();
        let pk_a = sk_a.public_key().to_bytes();
        let pk_b = sk_b.public_key().to_bytes();
        let pk_c = sk_c.public_key().to_bytes();
        let pk_d = sk_d.public_key().to_bytes();
        let id_a = format!("{PREFIX}{}", pubkey_hex_of(&sk_a));
        let id_old = format!("old-validator-key-{}", pubkey_hex_of(&sk_b));
        let id_b = format!("b-validator-key-{}", pubkey_hex_of(&sk_c));
        let id_d = format!("{PREFIX}{}", pubkey_hex_of(&sk_d));

        let (stub, state) = FakeGcp::with_pages(
            PROJECT,
            vec![
                (
                    vec![(id_a.clone(), raw_hex_payload(&sk_a)), (id_old, raw_hex_payload(&sk_b))],
                    "more".to_string(),
                ),
                (
                    vec![(id_b, raw_hex_payload(&sk_c)), (id_d.clone(), raw_hex_payload(&sk_d))],
                    String::new(),
                ),
            ],
            None,
        );
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        let entries = provider.list_keys().await.expect("list pages");
        let ids: Vec<_> = entries.iter().map(|entry| entry.id.as_str()).collect();
        assert_eq!(ids, vec![id_a.as_str(), id_d.as_str()]);
        assert_eq!(state.page_tokens.lock().expect("page tokens").as_slice(), ["", "more"]);

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.expect("load pages");
        assert!(km.contains(&pk_a));
        assert!(km.contains(&pk_d));
        assert!(!km.contains(&pk_b));
        assert!(!km.contains(&pk_c));
        assert_eq!(km.len(), 2);
        let accessed: HashSet<_> =
            state.accessed.lock().expect("access log").iter().cloned().collect();
        assert_eq!(
            accessed,
            HashSet::from([version_name(PROJECT, &id_a), version_name(PROJECT, &id_d)])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_keys_keeps_an_id_equal_to_the_prefix() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let id = PREFIX.to_string();
        let (stub, state) = FakeGcp::single_page(PROJECT, vec![(id.clone(), raw_hex_payload(&sk))]);
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        let entries = provider.list_keys().await.expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert!(entries[0].pubkey_hex.is_none());

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.expect("load exact prefix id");
        assert!(km.contains(&pk));
        assert_eq!(km.len(), 1);
        let accessed: HashSet<_> =
            state.accessed.lock().expect("access log").iter().cloned().collect();
        assert_eq!(accessed, HashSet::from([version_name(PROJECT, &id)]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_suffix_cannot_bypass_post_fetch_denylist() {
        let sk_denied = SecretKey::generate();
        let sk_decoy = SecretKey::generate();
        let sk_ok = SecretKey::generate();
        let pk_denied = sk_denied.public_key().to_bytes();
        let pk_decoy = sk_decoy.public_key().to_bytes();
        let pk_ok = sk_ok.public_key().to_bytes();
        let decoy_hex = pubkey_hex_of(&sk_decoy);
        let id_mismatch = format!("{PREFIX}{decoy_hex}");
        let id_ok = format!("{PREFIX}{}", pubkey_hex_of(&sk_ok));

        let (stub, state) = FakeGcp::single_page(
            PROJECT,
            vec![
                (id_mismatch.clone(), raw_hex_payload(&sk_denied)),
                (id_ok.clone(), raw_hex_payload(&sk_ok)),
            ],
        );
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        let entries = provider.list_keys().await.expect("list");
        let mismatch = entries.iter().find(|entry| entry.id == id_mismatch).expect("mismatch id");
        assert_eq!(mismatch.pubkey_hex.as_deref(), Some(decoy_hex.as_str()));

        let mut denylist = HashSet::new();
        denylist.insert(pk_denied);
        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all_except(&mut km, Some(&denylist)).await.expect("load");
        assert!(!km.contains(&pk_denied), "denylisted key material must not load");
        assert!(!km.contains(&pk_decoy), "the suffix pubkey is not the loaded key");
        assert!(km.contains(&pk_ok));
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[0].skipped, 1);
        let accessed: HashSet<_> =
            state.accessed.lock().expect("access log").iter().cloned().collect();
        assert_eq!(
            accessed,
            HashSet::from([version_name(PROJECT, &id_mismatch), version_name(PROJECT, &id_ok)])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_keys_returns_not_found_when_a_later_page_fails() {
        let sk = SecretKey::generate();
        let id = format!("{PREFIX}{}", pubkey_hex_of(&sk));
        let (stub, state) = FakeGcp::with_pages(
            PROJECT,
            vec![(vec![(id, raw_hex_payload(&sk))], "more".to_string())],
            Some("more".to_string()),
        );
        let provider = fake_gcp_provider(stub, PROJECT, PREFIX);
        let err = match provider.list_keys().await {
            Err(err) => err,
            Ok(_) => panic!("second page failure must not return a partial list"),
        };
        match err {
            SecretProviderError::NotFound(ctx) => {
                assert_eq!(ctx, format!("projects/{PROJECT}"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        assert!(state.accessed.lock().expect("access log").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn opaque_warn_recovers_a_poisoned_mutex() {
        let id = format!("{PREFIX}7");
        let (stub, _state) = FakeGcp::single_page(PROJECT, vec![(id.clone(), b"00".to_vec())]);
        let provider = Arc::new(fake_gcp_provider(stub, PROJECT, PREFIX));
        let poisoner = Arc::clone(&provider);
        let joined = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = poisoner.opaque_warned.lock().expect("lock before poison");
                panic!("poison opaque_warned");
            }));
        })
        .join();
        assert!(joined.is_ok());
        assert!(provider.opaque_warned.lock().is_err(), "mutex is poisoned");

        let events = Arc::new(Mutex::new(Vec::new()));
        let layer = WarnCapture { events: Arc::clone(&events) };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let entries = provider.list_keys().await.expect("list after poison");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].pubkey_hex.is_none());
        let captured = events.lock().expect("warn log");
        let naming_id = captured
            .iter()
            .filter(|event| field_value(event, "secret_id") == Some(id.as_str()))
            .count();
        assert_eq!(naming_id, 1);
    }
}
