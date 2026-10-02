use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Adapter that implements [`Injector`] for [`reqwest::header::HeaderMap`].
struct HeaderInjector<'a>(&'a mut reqwest::header::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

/// Adapter that implements [`Injector`] for [`tonic::metadata::MetadataMap`].
///
/// Structurally the same as [`HeaderInjector`]: invalid keys and values are dropped
/// rather than panicking, so a propagator cannot fail an RPC by writing metadata.
#[cfg(feature = "grpc")]
struct MetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);

#[cfg(feature = "grpc")]
impl Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = tonic::metadata::MetadataValue::try_from(value.as_str()) {
                self.0.insert(name, val);
            }
        }
    }
}

/// Inject the current trace context as W3C `traceparent` / `tracestate`
/// headers into an HTTP header map.
///
/// This is used to propagate trace context across service boundaries,
/// for example when calling a remote signer or beacon node.
///
/// If no OTel layer is active, this is a no-op — no headers are added.
pub fn inject_trace_context(headers: &mut reqwest::header::HeaderMap) {
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(headers));
    });
}

/// Inject the current span's W3C trace context into outbound gRPC request metadata.
///
/// This is the [`MetadataMap`](tonic::metadata::MetadataMap) sibling of
/// [`inject_trace_context`]. It writes `traceparent` / `tracestate` into outbound
/// gRPC metadata so a duty trace continues across a tonic client call.
///
/// If no OTel layer is active, this is a no-op — no metadata entries are added.
/// Uses the globally installed text-map propagator (`global::get_text_map_propagator`);
/// it does not construct a second propagator.
#[cfg(feature = "grpc")]
pub fn inject_trace_context_metadata(metadata: &mut tonic::metadata::MetadataMap) {
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut MetadataInjector(metadata));
    });
}

/// Adapter that implements [`Extractor`] for an inbound [`reqwest::header::HeaderMap`].
///
/// `reqwest::header::HeaderMap` is a re-export of `http::HeaderMap` — the same type the
/// inbound :9000 axum handler holds (`axum::http::HeaderMap`) — so this single extractor
/// serves the server side without pulling in a new `http`/`axum` dependency (Open Q1
/// resolved via the reqwest re-export; the sibling [`HeaderInjector`] uses the same type).
struct HeaderExtractor<'a>(&'a reqwest::header::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Adapter that implements [`Extractor`] for an inbound [`tonic::metadata::MetadataMap`].
///
/// Sibling of [`HeaderExtractor`]. ASCII metadata is exposed as `&str`; binary
/// (`*-bin`) keys are listed but not readable via [`Extractor::get`] (trace context
/// is ASCII `traceparent` / `tracestate`).
#[cfg(feature = "grpc")]
struct MetadataExtractor<'a>(&'a tonic::metadata::MetadataMap);

#[cfg(feature = "grpc")]
impl Extractor for MetadataExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|key| match key {
                tonic::metadata::KeyRef::Ascii(k) => k.as_str(),
                tonic::metadata::KeyRef::Binary(k) => k.as_str(),
            })
            .collect()
    }
}

/// Set a span's OpenTelemetry parent from inbound W3C `traceparent` / `tracestate` headers.
///
/// The exact inverse of [`inject_trace_context`]: it reads the inbound trace context from
/// `headers` and makes `span` a child of the caller's trace, so a duty trace continues
/// across a service boundary (e.g. the :9000 Web3Signer path) under the existing
/// `ParentBased` sampler.
///
/// **Precondition — call before the span is entered/started.** `set_parent` attaches a
/// parent only while the span is still being built; once the span has been entered
/// (started), it returns `Err(AlreadyStarted)` and the parent is silently *not* attached
/// (the span stays its own root). Wire this as the first action in the handler span, before
/// any `.enter()`/`.in_scope()`.
///
/// Failure is graceful: an absent or malformed `traceparent` yields an empty context, so
/// the span stays a root — no panic and no signing-behavior change, mirroring
/// [`inject_trace_context`]'s no-op-without-context behavior.
pub fn set_parent_from_headers(span: &tracing::Span, headers: &reqwest::header::HeaderMap) {
    let parent_cx =
        global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)));
    // Graceful: a failure here (e.g. no active OTel layer — `SetParentError::LayerNotFound`)
    // leaves the span a root. Never panic; mirror inject_trace_context's no-op-without-layer
    // behavior, and surface the (non-secret) reason at trace for diagnosability.
    if let Err(err) = span.set_parent(parent_cx) {
        tracing::trace!(?err, "could not attach inbound OTel parent; span stays a root");
    }
}

/// Set a span's OpenTelemetry parent from inbound W3C `traceparent` / `tracestate`
/// gRPC metadata.
///
/// The exact inverse of [`inject_trace_context_metadata`]: it reads the inbound trace
/// context from `metadata` and makes `span` a child of the caller's trace, so a duty
/// trace continues across a tonic service boundary under the existing `ParentBased`
/// sampler.
///
/// **Precondition — call before the span is entered/started.** `set_parent` attaches a
/// parent only while the span is still being built; once the span has been entered
/// (started), it returns `Err(AlreadyStarted)` and the parent is silently *not* attached
/// (the span stays its own root). Wire this as the first action in the handler span, before
/// any `.enter()`/`.in_scope()`.
///
/// Failure is graceful: an absent or malformed `traceparent` yields an empty context, so
/// the span stays a root — no panic and no signing-behavior change, mirroring
/// [`inject_trace_context_metadata`]'s no-op-without-context behavior.
/// Uses the globally installed text-map propagator (`global::get_text_map_propagator`);
/// it does not construct a second propagator.
#[cfg(feature = "grpc")]
pub fn set_parent_from_metadata(span: &tracing::Span, metadata: &tonic::metadata::MetadataMap) {
    let parent_cx = global::get_text_map_propagator(|propagator| {
        propagator.extract(&MetadataExtractor(metadata))
    });
    // Graceful: a failure here (e.g. no active OTel layer — `SetParentError::LayerNotFound`)
    // leaves the span a root. Never panic; mirror inject_trace_context_metadata's
    // no-op-without-layer behavior, and surface the (non-secret) reason at trace.
    if let Err(err) = span.set_parent(parent_cx) {
        tracing::trace!(?err, "could not attach inbound OTel parent; span stays a root");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;
    use crate::init::init_tracing;

    #[test]
    fn test_inject_without_otel_layer_is_noop() {
        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        // Without an active OTel layer, no traceparent header should be
        // injected (the default NoopTextMapPropagator injects nothing, or
        // the propagator injects a root with all-zero trace ID which is
        // considered invalid).
        let has_valid_trace = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.contains("00000000000000000000000000000000"))
            .unwrap_or(false);
        assert!(!has_valid_trace);
    }

    #[test]
    fn test_inject_with_otel_layer() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;

        let config = TelemetryConfig::default();
        let (layer, guard) = init_tracing(&config).expect("init should succeed");

        let subscriber = Registry::default().with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("test_span");
        let _enter = span.enter();

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);

        let traceparent = headers.get("traceparent").expect("traceparent should be present");
        let value = traceparent.to_str().expect("should be valid string");
        assert!(value.starts_with("00-"), "traceparent should start with version 00");
        assert!(!value.contains("00000000000000000000000000000000"), "trace ID should not be zero");

        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_header_injector_invalid_name() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        // Header names with spaces are invalid
        injector.set("invalid header", "value".to_string());
        assert!(headers.is_empty());
    }

    #[test]
    fn test_header_injector_invalid_value() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        // Header values with newlines are invalid
        injector.set("valid-name", "invalid\nvalue".to_string());
        assert!(headers.is_empty());
    }

    #[test]
    fn test_header_injector_valid() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        injector.set("traceparent", "00-abc-def-01".to_string());
        assert_eq!(headers.get("traceparent").unwrap(), "00-abc-def-01");
    }

    // --- set_parent_from_headers / HeaderExtractor tests ---

    fn setup_otel() -> (tracing::subscriber::DefaultGuard, crate::TracingGuard) {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;
        let config = TelemetryConfig::default();
        let (layer, guard) = init_tracing(&config).expect("init should succeed");
        let subscriber = Registry::default().with(layer);
        let default = tracing::subscriber::set_default(subscriber);
        (default, guard)
    }

    /// A synthetic inbound `traceparent` makes the span a child of the caller's trace:
    /// re-injecting from the now-parented span yields the SAME trace id (continuity), not a
    /// fresh root. Reuses the proven `inject_trace_context` path as the oracle.
    #[test]
    fn test_set_parent_continues_trace() {
        let (_default, guard) = setup_otel();

        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let mut inbound = reqwest::header::HeaderMap::new();
        inbound
            .insert("traceparent", format!("00-{trace_id}-b7ad6b7169203331-01").parse().unwrap());

        let span = tracing::info_span!("server_span");
        set_parent_from_headers(&span, &inbound);

        let _enter = span.enter();
        let mut outbound = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut outbound);
        let tp = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be present");
        assert!(tp.contains(trace_id), "trace must continue (got {tp})");
        assert!(!tp.contains("00000000000000000000000000000000"));

        guard.provider.shutdown().ok();
    }

    /// An absent `traceparent` leaves the span a root and does not panic.
    #[test]
    fn test_set_parent_absent_header_is_root_no_panic() {
        let (_default, guard) = setup_otel();
        let empty = reqwest::header::HeaderMap::new();
        let span = tracing::info_span!("server_span");
        set_parent_from_headers(&span, &empty); // must not panic
        let _enter = span.enter();
        let mut outbound = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut outbound);
        // A fresh root: if a traceparent is present it must be valid (non-zero); never a panic.
        if let Some(tp) = outbound.get("traceparent").and_then(|v| v.to_str().ok()) {
            assert!(!tp.contains("00000000000000000000000000000000"));
        }
        guard.provider.shutdown().ok();
    }

    /// A malformed `traceparent` yields a root span, no panic — and, crucially, the ghost
    /// trace id embedded in the malformed value must NOT leak into the outbound trace (a
    /// regression that partially-parsed-and-continued would fail this).
    #[test]
    fn test_set_parent_garbled_header_is_root_no_panic() {
        let (_default, guard) = setup_otel();
        // Structurally invalid (bad flags "zz") but embeds a recognizable trace id; a correct
        // parser rejects the whole value, so the ghost id must not be continued.
        let ghost = "11111111111111111111111111111111";
        let mut garbled = reqwest::header::HeaderMap::new();
        garbled.insert("traceparent", format!("00-{ghost}-2222222222222222-zz").parse().unwrap());
        let span = tracing::info_span!("server_span");
        set_parent_from_headers(&span, &garbled); // must not panic on malformed input
        let _enter = span.enter();
        let mut outbound = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut outbound);
        let tp = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be present");
        assert!(!tp.contains(ghost), "garbled inbound trace id must NOT continue (got {tp})");
        assert!(!tp.contains("00000000000000000000000000000000"), "fresh valid root");
        guard.provider.shutdown().ok();
    }

    /// PRECONDITION GUARD: `set_parent_from_headers` must be called BEFORE the span is
    /// entered/started. Once the span has started, `set_parent` returns `Err(AlreadyStarted)`
    /// and the parent is NOT attached (the span stays its own root). Guards the ordering trap
    /// for the upcoming :9000 caller.
    #[test]
    fn test_set_parent_after_enter_is_noop_root() {
        let (_default, guard) = setup_otel();
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let mut inbound = reqwest::header::HeaderMap::new();
        inbound
            .insert("traceparent", format!("00-{trace_id}-b7ad6b7169203331-01").parse().unwrap());

        let span = tracing::info_span!("server_span");
        let _enter = span.enter(); // span starts HERE — now too late to set a parent
        set_parent_from_headers(&span, &inbound); // no-op (AlreadyStarted), must not panic

        let mut outbound = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut outbound);
        let tp = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be present");
        assert!(
            !tp.contains(trace_id),
            "a parent set after enter() must NOT continue the inbound trace (got {tp})"
        );
        assert!(!tp.contains("00000000000000000000000000000000"), "still a valid root");
        guard.provider.shutdown().ok();
    }

    /// With NO active OTel layer (telemetry disabled), `set_parent` returns
    /// `Err(LayerNotFound)`, which is handled gracefully: the call does not panic and the
    /// span stays a root. This is the production path when telemetry is off.
    #[test]
    fn test_set_parent_without_layer_is_graceful() {
        let mut inbound = reqwest::header::HeaderMap::new();
        inbound.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".parse().unwrap(),
        );
        let span = tracing::info_span!("server_span");
        // No subscriber/layer installed in this process → must not panic.
        set_parent_from_headers(&span, &inbound);
    }

    #[test]
    fn test_header_extractor_get_and_keys() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("traceparent", "00-abc-def-01".parse().unwrap());
        let ex = HeaderExtractor(&headers);
        assert_eq!(ex.get("traceparent"), Some("00-abc-def-01"));
        assert_eq!(ex.get("missing"), None);
        assert!(ex.keys().contains(&"traceparent"));
    }

    // --- MetadataMap inject/extract (feature = "grpc", T10/T11) ---

    /// T10: a synthetic inbound `traceparent` makes the span a child of the caller's trace.
    /// Re-injecting from the now-parented span yields the SAME trace id. MetadataMap mirror of
    /// [`test_set_parent_continues_trace`].
    #[cfg(feature = "grpc")]
    #[test]
    fn test_set_parent_metadata_continues_trace() {
        let (_default, guard) = setup_otel();

        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let mut inbound = tonic::metadata::MetadataMap::new();
        inbound
            .insert("traceparent", format!("00-{trace_id}-b7ad6b7169203331-01").parse().unwrap());

        let span = tracing::info_span!("server_span");
        set_parent_from_metadata(&span, &inbound);

        let _enter = span.enter();
        let mut outbound = tonic::metadata::MetadataMap::new();
        inject_trace_context_metadata(&mut outbound);
        let tp = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be present");
        assert!(tp.contains(trace_id), "trace must continue (got {tp})");
        assert!(!tp.contains("00000000000000000000000000000000"));

        guard.provider.shutdown().ok();
    }

    /// T11: no `traceparent` leaves the span a valid fresh root and does not panic.
    /// MetadataMap mirror of [`test_set_parent_absent_header_is_root_no_panic`].
    #[cfg(feature = "grpc")]
    #[test]
    fn test_set_parent_metadata_absent_is_root_no_panic() {
        let (_default, guard) = setup_otel();
        let empty = tonic::metadata::MetadataMap::new();
        let span = tracing::info_span!("server_span");
        set_parent_from_metadata(&span, &empty); // must not panic
        let _enter = span.enter();
        let mut outbound = tonic::metadata::MetadataMap::new();
        inject_trace_context_metadata(&mut outbound);
        if let Some(tp) = outbound.get("traceparent").and_then(|v| v.to_str().ok()) {
            assert!(!tp.contains("00000000000000000000000000000000"));
        }
        guard.provider.shutdown().ok();
    }

    /// A malformed `traceparent` yields a root span, no panic, and the ghost trace id must NOT
    /// continue. Same contract as [`test_set_parent_garbled_header_is_root_no_panic`].
    #[cfg(feature = "grpc")]
    #[test]
    fn test_set_parent_metadata_garbled_is_root_no_panic() {
        let (_default, guard) = setup_otel();
        let ghost = "11111111111111111111111111111111";
        let mut garbled = tonic::metadata::MetadataMap::new();
        garbled.insert("traceparent", format!("00-{ghost}-2222222222222222-zz").parse().unwrap());
        let span = tracing::info_span!("server_span");
        set_parent_from_metadata(&span, &garbled); // must not panic on malformed input
        let _enter = span.enter();
        let mut outbound = tonic::metadata::MetadataMap::new();
        inject_trace_context_metadata(&mut outbound);
        let tp = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be present");
        assert!(!tp.contains(ghost), "garbled inbound trace id must NOT continue (got {tp})");
        assert!(!tp.contains("00000000000000000000000000000000"), "fresh valid root");
        guard.provider.shutdown().ok();
    }

    /// Without an active OTel layer, metadata inject adds no valid `traceparent`.
    #[cfg(feature = "grpc")]
    #[test]
    fn test_inject_metadata_without_otel_layer_is_noop() {
        let mut metadata = tonic::metadata::MetadataMap::new();
        inject_trace_context_metadata(&mut metadata);
        let has_valid_trace = metadata
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.contains("00000000000000000000000000000000"))
            .unwrap_or(false);
        assert!(!has_valid_trace);
    }

    /// With no OTel layer, `set_parent_from_metadata` returns `LayerNotFound` and must not panic.
    #[cfg(feature = "grpc")]
    #[test]
    fn test_set_parent_metadata_without_layer_is_graceful() {
        let mut inbound = tonic::metadata::MetadataMap::new();
        inbound.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".parse().unwrap(),
        );
        let span = tracing::info_span!("server_span");
        set_parent_from_metadata(&span, &inbound);
    }
}
