use std::sync::{Arc, Mutex};

use crypto::{KeyManager, SecretKey};
use rvc_secret_provider::{KeyMaterial, KeySourceManager, MockSecretProvider, SecretKeyEntry};
use tracing_subscriber::layer::SubscriberExt;
use zeroize::Zeroizing;

fn make_raw_key_entry(
    id: &str,
    sk: &SecretKey,
) -> (SecretKeyEntry, Result<KeyMaterial, rvc_secret_provider::SecretProviderError>) {
    #[allow(clippy::disallowed_methods)] // test-only comparison of key material already in scope
    let bytes: [u8; 32] = sk.to_bytes();
    (
        SecretKeyEntry { id: id.to_string(), pubkey_hex: None },
        Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
    )
}

type CapturedSpan = (String, Option<String>);

struct HierarchyCapture {
    spans: Arc<Mutex<Vec<CapturedSpan>>>,
}

impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
    tracing_subscriber::Layer<S> for HierarchyCapture
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = attrs.metadata().name().to_string();
        let parent = if let Some(parent_id) = attrs.parent() {
            ctx.span(parent_id).map(|s| s.name().to_string())
        } else if attrs.is_contextual() {
            ctx.current_span().id().and_then(|id| ctx.span(id).map(|s| s.name().to_string()))
        } else {
            None
        };
        self.spans.lock().unwrap().push((name, parent));
    }
}

#[tokio::test]
async fn test_tracing_span_hierarchy_load_all_list_keys_fetch_key() {
    let sk = SecretKey::generate();
    let provider = MockSecretProvider {
        name: "span-test".to_string(),
        keys: vec![make_raw_key_entry("key-1", &sk)],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();

    let spans = Arc::new(Mutex::new(Vec::new()));
    let layer = HierarchyCapture { spans: spans.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    ksm.load_all(&mut km).await.unwrap();

    let captured = spans.lock().unwrap();

    let names: Vec<&str> = captured.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"secret_provider.load_all"), "Missing load_all span, got: {:?}", names);
    assert!(
        names.contains(&"secret_provider.list_keys"),
        "Missing list_keys span, got: {:?}",
        names
    );
    assert!(
        names.contains(&"secret_provider.fetch_key"),
        "Missing fetch_key span, got: {:?}",
        names
    );

    // Verify hierarchy: list_keys is child of load_all
    let list_keys_entry = captured
        .iter()
        .find(|(n, _)| n == "secret_provider.list_keys")
        .expect("list_keys span should exist");
    assert_eq!(
        list_keys_entry.1.as_deref(),
        Some("secret_provider.load_all"),
        "list_keys should be child of load_all"
    );

    // Verify hierarchy: fetch_key is child of load_all
    let fetch_key_entry = captured
        .iter()
        .find(|(n, _)| n == "secret_provider.fetch_key")
        .expect("fetch_key span should exist");
    assert_eq!(
        fetch_key_entry.1.as_deref(),
        Some("secret_provider.load_all"),
        "fetch_key should be child of load_all"
    );
}
