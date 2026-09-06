use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use eth_types::{
    AttestationData, Checkpoint, ForkInfo, ForkName, PayloadAttestationData, ProposerPreferences,
};
use observability::logging::RedactedUrl;
use tracing_subscriber::layer::SubscriberExt;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::wire::{
    build_attestation_request, build_payload_attestation_request,
    build_proposer_preferences_request,
};
use crypto::{SecretKey, Signer, SigningError, TypedSigner, PUBLIC_KEY_BYTES_LEN};

/// Serialise tests in this module that read or mutate
/// `RVC_REMOTE_SIGNER_ALLOW_INSECURE`.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn test_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: [0x03, 0x00, 0x00, 0x00],
        current_version: [0x04, 0x00, 0x00, 0x00], // DENEB
        genesis_validators_root: [0xaa; 32],
    }
}

fn test_ctx(sk: &SecretKey) -> SignContext {
    SignContext {
        pubkey: sk.public_key(),
        fork_info: test_fork_info(),
        fork_name: eth_types::ForkName::Deneb,
    }
}

fn sample_attestation() -> AttestationData {
    AttestationData {
        slot: 5,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 1, root: [0x22; 32] },
        target: Checkpoint { epoch: 2, root: [0x33; 32] },
    }
}

/// Mock Web3Signer that returns a valid BLS sig for the attestation root.
async fn mock_attestation_signer(
    sk: &SecretKey,
) -> (MockServer, RemoteSigner, AttestationData, SignContext, Root) {
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(sk);
    let data = sample_attestation();
    let (req, signing_root) = build_attestation_request(&data, &ctx);
    let _ = req;
    let expected_sig = sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .mount(&mock_server)
        .await;

    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    (mock_server, signer, data, ctx, signing_root)
}

#[tokio::test]
async fn test_remote_signer_public_keys_returns_configured_keys() {
    let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
    let config = RemoteSignerConfig::new("http://localhost:9000");
    let signer = RemoteSigner::new_unchecked(config, vec![pk]);

    let keys = signer.public_keys();

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], pk);
}

#[tokio::test]
async fn test_remote_signer_sign_success() {
    let sk = SecretKey::generate();
    let (_mock, signer, data, ctx, signing_root) = mock_attestation_signer(&sk).await;
    let expected_sig = sk.sign(&signing_root);

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_bytes(), expected_sig.to_bytes());
}

#[tokio::test]
async fn test_remote_signer_sign_server_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
        )
        .mount(&mock_server)
        .await;

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::RemoteSignerError(msg) => {
            assert!(msg.contains("500"));
        }
        other => panic!("expected RemoteSignerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_key_not_found() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"error": "Key not found"})),
        )
        .mount(&mock_server)
        .await;

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::RemoteSignerError(msg) => {
            assert!(msg.contains("404"));
        }
        other => panic!("expected RemoteSignerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_invalid_signature_response() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": "0xinvalid"})),
        )
        .mount(&mock_server)
        .await;

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::RemoteSignerError(msg) => {
            assert!(msg.contains("invalid signature hex"));
        }
        other => panic!("expected RemoteSignerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_connection_refused() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let config = RemoteSignerConfig::new("http://127.0.0.1:1");
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::RemoteSignerError(msg) => {
            assert!(msg.contains("HTTP request failed"));
        }
        other => panic!("expected RemoteSignerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_unknown_pubkey_returns_key_not_found() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let unknown_sk = SecretKey::generate();
    let config = RemoteSignerConfig::new("http://localhost:9000");
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = SignContext {
        pubkey: unknown_sk.public_key(),
        fork_info: test_fork_info(),
        fork_name: eth_types::ForkName::Deneb,
    };
    let data = sample_attestation();

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::KeyNotFound(pk_hex) => {
            assert_eq!(pk_hex, hex::encode(unknown_sk.public_key().to_bytes()));
        }
        other => panic!("expected KeyNotFound, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_object_safety() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;
    let config = RemoteSignerConfig::new(signer.url());
    let typed: Box<dyn TypedSigner> = Box::new(RemoteSigner::new_unchecked(config, vec![pk_bytes]));

    let sig = TypedSigner::sign_attestation(typed.as_ref(), &data, &ctx).await.unwrap();
    assert_eq!(sig.to_bytes().len(), 96);
}

#[tokio::test]
async fn test_remote_signer_raw_sign_returns_unsupported() {
    let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
    let config = RemoteSignerConfig::new("http://localhost:9000");
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

    let result = Signer::sign(&signer, &[0xab; 32], &pk_bytes).await;
    match result.unwrap_err() {
        SigningError::UnsupportedSigningType(msg) => {
            assert!(msg.contains("TypedSigner"), "msg={msg}");
        }
        other => panic!("expected UnsupportedSigningType, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_strips_trailing_slash_from_url() {
    let config = RemoteSignerConfig::new("http://localhost:9000/");
    let signer = RemoteSigner::new_unchecked(config, vec![]);
    assert_eq!(signer.url(), "http://localhost:9000");
}

#[tokio::test]
async fn test_remote_signer_empty_public_keys() {
    let config = RemoteSignerConfig::new("http://localhost:9000");
    let signer = RemoteSigner::new_unchecked(config, vec![]);
    assert!(signer.public_keys().is_empty());
}

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
        self.spans.lock().unwrap().push(attrs.metadata().name().to_string());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_sign_creates_remote_span() {
    let sk = SecretKey::generate();
    let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

    let spans = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { spans: spans.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);
    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());

    let captured = spans.lock().unwrap();
    assert!(
        captured.contains(&"sign.remote".to_string()),
        "Expected sign.remote span, got: {:?}",
        *captured
    );
}

struct FieldCapture {
    fields: Arc<Mutex<Vec<(String, String)>>>,
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
        let mut visitor = FieldVisitor(self.fields.clone());
        attrs.record(&mut visitor);
    }

    fn on_record(
        &self,
        _id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor(self.fields.clone());
        values.record(&mut visitor);
    }
}

struct FieldVisitor(Arc<Mutex<Vec<(String, String)>>>);

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.lock().unwrap().push((field.name().to_string(), format!("{:?}", value)));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_sign_span_records_status_code() {
    let sk = SecretKey::generate();
    let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

    let fields = Arc::new(Mutex::new(Vec::new()));
    let layer = FieldCapture { fields: fields.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);
    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());

    let captured = fields.lock().unwrap();
    assert!(
        captured.iter().any(|(k, v)| k == "http.method" && v == "POST"),
        "Expected http.method=POST, got: {:?}",
        *captured
    );
    assert!(
        captured.iter().any(|(k, v)| k == "signer_type" && v == "remote"),
        "Expected signer_type=remote, got: {:?}",
        *captured
    );
    assert!(
        captured.iter().any(|(k, v)| k == "http.status_code" && v == "200"),
        "Expected http.status_code=200, got: {:?}",
        *captured
    );
}

/// Gate 3: the `rvc.sign.remote` span carries the validator pubkey only in
/// its truncated form.
#[tokio::test(flavor = "current_thread")]
async fn test_sign_span_url_truncates_pubkey() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let full_pubkey_hex = hex::encode(pk_bytes);
    let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

    let fields = Arc::new(Mutex::new(Vec::new()));
    let layer = FieldCapture { fields: fields.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);
    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());

    let captured = fields.lock().unwrap();
    let http_url = captured.iter().find(|(k, _)| k == "http.url");
    assert!(http_url.is_some(), "Expected http.url span field, got: {:?}", *captured);
    let (_, url_value) = http_url.unwrap();
    assert!(url_value.contains("..."), "pubkey in URL must be truncated: {url_value}");
    assert!(
        !url_value.contains(&full_pubkey_hex),
        "full pubkey hex must never appear in http.url: {url_value}"
    );
    assert!(
        !captured.iter().any(|(_, v)| v.contains(&full_pubkey_hex)),
        "full pubkey hex leaked into a span field: {:?}",
        *captured
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_sign_span_records_error_status_code() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
        )
        .mount(&mock_server)
        .await;

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let fields = Arc::new(Mutex::new(Vec::new()));
    let layer = FieldCapture { fields: fields.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);
    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());

    let captured = fields.lock().unwrap();
    assert!(
        captured.iter().any(|(k, v)| k == "http.status_code" && v == "500"),
        "Expected http.status_code=500, got: {:?}",
        *captured
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_sign_span_redacts_url_credentials() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let url_with_creds = "http://user:secret@signer.example.com:9000";
    let config = RemoteSignerConfig::new(url_with_creds);
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

    let fields = Arc::new(Mutex::new(Vec::new()));
    let layer = FieldCapture { fields: fields.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);
    let _ = TypedSigner::sign_attestation(&signer, &data, &ctx).await;

    let captured = fields.lock().unwrap();
    let http_url = captured.iter().find(|(k, _)| k == "http.url");
    assert!(http_url.is_some(), "Expected http.url field, got: {:?}", *captured);
    let (_, url_value) = http_url.unwrap();
    assert!(!url_value.contains("user"), "URL should not contain username: {url_value}");
    assert!(!url_value.contains("secret"), "URL should not contain password: {url_value}");
    assert!(url_value.contains("***"), "URL should contain redacted marker: {url_value}");
}

#[test]
fn test_redacted_url_hides_credentials() {
    let url = "http://user:pass@example.com:9000/api";
    let redacted = RedactedUrl(url).to_string();
    assert!(!redacted.contains("user"));
    assert!(!redacted.contains("pass"));
    assert!(redacted.contains("***"));
    assert!(redacted.contains("example.com"));
}

#[test]
fn test_redacted_url_preserves_url_without_credentials() {
    let url = "http://example.com:9000/api";
    let redacted = RedactedUrl(url).to_string();
    assert_eq!(redacted, "http://example.com:9000/api");
}

#[test]
fn test_redacted_url_handles_invalid_url() {
    let url = "not-a-url";
    let redacted = RedactedUrl(url).to_string();
    assert_eq!(redacted, "not-a-url");
}

/// GA regression: `http://` without env var must be refused (ISSUE-3.13 / NFR-10).
#[test]
fn test_remote_signer_refuses_http_url_without_env_var() {
    let _lock = env_lock();
    unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
    let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
    let config = RemoteSignerConfig::new("http://signer.example.com:9000");
    let result = RemoteSigner::new(config, vec![pk]);
    assert!(result.is_err(), "http:// without env var must fail in GA (Refuse mode)");
}

#[test]
fn test_remote_signer_no_warn_on_https_url() {
    let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
    let config = RemoteSignerConfig::new("https://signer.example.com:9000");
    let signer = RemoteSigner::new(config, vec![pk]);
    assert!(signer.is_ok());
}

#[tokio::test]
async fn test_remote_signer_sign_sends_correct_request() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(&sk);
    let data = sample_attestation();
    let (_req, signing_root) = build_attestation_request(&data, &ctx);
    let expected_sig = sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

    let mock_server = MockServer::start().await;
    let expected_path = format!("/api/v1/eth2/sign/0x{}", hex::encode(pk_bytes));
    Mock::given(method("POST"))
        .and(wiremock::matchers::path(expected_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_remote_signer_rejects_wrong_key_signature() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(&sk);
    let data = sample_attestation();
    let (_req, signing_root) = build_attestation_request(&data, &ctx);

    let wrong_sk = SecretKey::generate();
    let wrong_sig = wrong_sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(wrong_sig.to_bytes()));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .mount(&mock_server)
        .await;

    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SigningError::InvalidRemoteSignature => {}
        other => panic!("expected InvalidRemoteSignature, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_accepts_correct_signature() {
    let sk = SecretKey::generate();
    let (_mock, signer, data, ctx, signing_root) = mock_attestation_signer(&sk).await;
    let correct_sig = sk.sign(&signing_root);

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_bytes(), correct_sig.to_bytes());
}

#[tokio::test]
async fn test_remote_signer_rejects_garbage_signature_bytes() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(&sk);
    let data = sample_attestation();

    let garbage_bytes = [0xffu8; 96];
    let sig_hex = format!("0x{}", hex::encode(garbage_bytes));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .mount(&mock_server)
        .await;

    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

    let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
    assert!(result.is_err());
}

#[test]
fn test_web3signer_client_unsupported_type_returns_error_not_malformed_body() {
    let pk = [0xcc; PUBLIC_KEY_BYTES_LEN];
    let config = RemoteSignerConfig::new("http://localhost:9000");
    let signer = RemoteSigner::new_unchecked(config, vec![pk]);

    let err = futures_executor_block_on(Signer::sign(&signer, &[0xde; 32], &pk)).unwrap_err();
    match err {
        SigningError::UnsupportedSigningType(msg) => {
            assert!(
                msg.contains("TypedSigner") || msg.contains("raw-root"),
                "typed error must name the supported path, got: {msg}"
            );
        }
        other => {
            panic!("expected UnsupportedSigningType (not a malformed body), got: {other:?}")
        }
    }
}

fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
}

#[tokio::test]
// kat_exempt: name-pattern false positive — asserts a typed HTTP body, not a spec root
async fn test_web3signer_client_posts_typed_body_not_bare_root() {
    use wiremock::matchers::body_partial_json;

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = test_ctx(&sk);
    let data = sample_attestation();
    let (req, signing_root) = build_attestation_request(&data, &ctx);
    let expected_sig = sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));
    let signing_root_hex = format!("0x{}", hex::encode(signing_root));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .and(body_partial_json(serde_json::json!({
            "type": "ATTESTATION",
            "signingRoot": signing_root_hex,
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = RemoteSignerConfig::new(mock_server.uri());
    let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
    let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    // RF3-10-M1: request builder set signing_root.
    assert_eq!(req.signing_root, Some(signing_root));
}

fn gloas_ptc_data() -> PayloadAttestationData {
    PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot: 1,
        payload_present: true,
        blob_data_available: false,
    }
}

fn gloas_kat_ctx(sk: &SecretKey) -> SignContext {
    SignContext {
        pubkey: sk.public_key(),
        fork_info: ForkInfo {
            previous_version: [0x06, 0x00, 0x00, 0x01],
            current_version: [0x07, 0x00, 0x00, 0x01],
            genesis_validators_root: [0u8; 32],
        },
        fork_name: ForkName::Gloas,
    }
}

async fn mock_ptc_status(
    status: u16,
    body: serde_json::Value,
) -> (MockServer, RemoteSigner, PayloadAttestationData, SignContext) {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = gloas_kat_ctx(&sk);
    let data = gloas_ptc_data();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&mock_server)
        .await;
    let signer =
        RemoteSigner::new_unchecked(RemoteSignerConfig::new(mock_server.uri()), vec![pk_bytes]);
    (mock_server, signer, data, ctx)
}

#[test]
fn test_classify_payload_attestation_400_is_transient_not_unsupported() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::BAD_REQUEST,
        "bad request",
        Some("payload_attestation"),
    );
    match &err {
        SigningError::RemoteSignerError(msg) => assert!(msg.contains("400")),
        other => panic!("400 must stay RemoteSignerError, got: {other:?}"),
    }
    assert!(
        !err.is_unambiguous_no_signature(),
        "400 is transient (retryable), never a permanent unsupported-type"
    );
}

#[test]
fn test_classify_payload_attestation_404_is_unsupported_duty() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::NOT_FOUND,
        "not found",
        Some("payload_attestation"),
    );
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "payload_attestation"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[test]
fn test_classify_payload_attestation_501_is_unsupported_duty() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::NOT_IMPLEMENTED,
        "not implemented",
        Some("payload_attestation"),
    );
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "payload_attestation"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[test]
fn test_classify_404_without_duty_stays_remote_error() {
    let err = classify_web3signer_http_error(reqwest::StatusCode::NOT_FOUND, "key missing", None);
    match err {
        SigningError::RemoteSignerError(msg) => assert!(msg.contains("404")),
        other => {
            panic!("existing mapping: 404 without a duty stays RemoteSignerError, got: {other:?}")
        }
    }
}

#[tokio::test]
async fn test_payload_attestation_http_400_is_transient_not_unsupported() {
    let (_mock, signer, data, ctx) =
        mock_ptc_status(400, serde_json::json!({"error": "bad request"})).await;
    let err = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await.unwrap_err();
    match &err {
        SigningError::RemoteSignerError(msg) => assert!(msg.contains("400"), "msg={msg}"),
        other => panic!("400 must stay transient RemoteSignerError, got: {other:?}"),
    }
    assert!(!matches!(err, SigningError::UnsupportedDuty { .. }));
    assert!(!matches!(err, SigningError::UnsupportedSigningType(_)));
    assert!(!err.is_unambiguous_no_signature());
}

#[tokio::test]
async fn test_payload_attestation_http_404_is_unsupported_duty() {
    let (_mock, signer, data, ctx) =
        mock_ptc_status(404, serde_json::json!({"error": "not found"})).await;
    let err = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await.unwrap_err();
    assert!(err.is_unambiguous_no_signature(), "duty is dropped; no signature");
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "payload_attestation"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_payload_attestation_http_501_is_unsupported_duty() {
    let (_mock, signer, data, ctx) =
        mock_ptc_status(501, serde_json::json!({"error": "not implemented"})).await;
    let err = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await.unwrap_err();
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "payload_attestation"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_payload_attestation_success() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = gloas_kat_ctx(&sk);
    let data = gloas_ptc_data();
    let (_req, signing_root) = build_payload_attestation_request(&data, &ctx);
    let expected_sig = sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .mount(&mock_server)
        .await;

    let signer =
        RemoteSigner::new_unchecked(RemoteSignerConfig::new(mock_server.uri()), vec![pk_bytes]);
    let sig = TypedSigner::sign_payload_attestation(&signer, &data, &ctx).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
}

fn gloas_prefs_data() -> ProposerPreferences {
    ProposerPreferences {
        dependent_root: [0x33; 32],
        proposal_slot: 32,
        validator_index: 3,
        fee_recipient: [0x44; 20],
        target_gas_limit: 36_000_000,
    }
}

async fn mock_prefs_status(
    status: u16,
    body: serde_json::Value,
) -> (MockServer, RemoteSigner, ProposerPreferences, SignContext) {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = gloas_kat_ctx(&sk);
    let data = gloas_prefs_data();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&mock_server)
        .await;
    let signer =
        RemoteSigner::new_unchecked(RemoteSignerConfig::new(mock_server.uri()), vec![pk_bytes]);
    (mock_server, signer, data, ctx)
}

#[test]
fn test_classify_proposer_preferences_400_is_transient_not_unsupported() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::BAD_REQUEST,
        "bad request",
        Some("proposer_preferences"),
    );
    match &err {
        SigningError::RemoteSignerError(msg) => assert!(msg.contains("400")),
        other => panic!("400 must stay RemoteSignerError, got: {other:?}"),
    }
    assert!(
        !err.is_unambiguous_no_signature(),
        "400 is transient (retryable), never a permanent unsupported-type"
    );
}

#[test]
fn test_classify_proposer_preferences_404_is_unsupported_duty() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::NOT_FOUND,
        "not found",
        Some("proposer_preferences"),
    );
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "proposer_preferences"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[test]
fn test_classify_proposer_preferences_501_is_unsupported_duty() {
    let err = classify_web3signer_http_error(
        reqwest::StatusCode::NOT_IMPLEMENTED,
        "not implemented",
        Some("proposer_preferences"),
    );
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "proposer_preferences"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_proposer_preferences_http_400_is_transient_not_unsupported() {
    let (_mock, signer, data, ctx) =
        mock_prefs_status(400, serde_json::json!({"error": "bad request"})).await;
    let err = TypedSigner::sign_proposer_preferences(&signer, &data, &ctx).await.unwrap_err();
    match &err {
        SigningError::RemoteSignerError(msg) => assert!(msg.contains("400"), "msg={msg}"),
        other => panic!("400 must stay transient RemoteSignerError, got: {other:?}"),
    }
    assert!(!matches!(err, SigningError::UnsupportedDuty { .. }));
    assert!(!matches!(err, SigningError::UnsupportedSigningType(_)));
    assert!(!err.is_unambiguous_no_signature());
}

#[tokio::test]
async fn test_proposer_preferences_http_404_is_unsupported_duty() {
    let (_mock, signer, data, ctx) =
        mock_prefs_status(404, serde_json::json!({"error": "not found"})).await;
    let err = TypedSigner::sign_proposer_preferences(&signer, &data, &ctx).await.unwrap_err();
    assert!(err.is_unambiguous_no_signature(), "duty is dropped; no signature");
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "proposer_preferences"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_proposer_preferences_http_501_is_unsupported_duty() {
    let (_mock, signer, data, ctx) =
        mock_prefs_status(501, serde_json::json!({"error": "not implemented"})).await;
    let err = TypedSigner::sign_proposer_preferences(&signer, &data, &ctx).await.unwrap_err();
    match err {
        SigningError::UnsupportedDuty { duty } => assert_eq!(duty, "proposer_preferences"),
        other => panic!("expected UnsupportedDuty, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_remote_signer_sign_proposer_preferences_success() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();
    let ctx = gloas_kat_ctx(&sk);
    let data = gloas_prefs_data();
    let (_req, signing_root) = build_proposer_preferences_request(&data, &ctx);
    let expected_sig = sk.sign(&signing_root);
    let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/api/v1/eth2/sign/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
        )
        .mount(&mock_server)
        .await;

    let signer =
        RemoteSigner::new_unchecked(RemoteSignerConfig::new(mock_server.uri()), vec![pk_bytes]);
    let sig = TypedSigner::sign_proposer_preferences(&signer, &data, &ctx).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
}
