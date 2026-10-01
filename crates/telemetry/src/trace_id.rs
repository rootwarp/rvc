//! Lazy per-span OpenTelemetry trace/span id cache for log correlation (TRC-2b).
//!
//! [`TraceIdLayer`] resolves OTel ids on the **first event** inside a span
//! (`on_event` only — ADR-001 option D). Ids are cached as [`Copy`] values on
//! the span's extensions so a later formatter (TRC-2c) can render them without
//! re-entering the OTel layer. Unsampled / invalid / missing OTel contexts are
//! never cached (including never as zeroed placeholders).
//!
//! Trace/span ids are **correlators**, not authentication material. Only a
//! validated (`is_valid`) and sampled (`is_sampled`) OTel `SpanContext` is
//! cached; this layer does not record same-name fields onto events (avoids
//! dual `trace_id`/`span_id` keys — rendering is TRC-2c's job).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use opentelemetry::trace::{SpanId, TraceContextExt, TraceId};
use tracing::dispatcher::WeakDispatch;
use tracing::{Event, Subscriber};
use tracing_opentelemetry::get_otel_context;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Canonical log-field key for the OpenTelemetry trace id.
///
/// Kept equal to `observability::logging::fields::TRACE_ID` by
/// `telemetry_field_keys_match_registry` (ADR-002 pin / TRC-2e).
pub const TRACE_ID_KEY: &str = "trace_id";

/// Canonical log-field key for the OpenTelemetry span id.
///
/// Kept equal to `observability::logging::fields::SPAN_ID` by
/// `telemetry_field_keys_match_registry` (ADR-002 pin / TRC-2e).
pub const SPAN_ID_KEY: &str = "span_id";

/// Cached OpenTelemetry trace and span ids for one tracing span.
///
/// Stored in span extensions by [`TraceIdLayer`]. Both fields are [`Copy`]
/// newtypes (24 bytes total); their [`Display`] impls write hex digits
/// straight into a formatter without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceIds {
    /// W3C / OTel 128-bit trace id.
    pub trace_id: TraceId,
    /// W3C / OTel 64-bit span id.
    pub span_id: SpanId,
}

/// Subscriber layer that lazily caches [`TraceIds`] on sampled spans.
///
/// Does **not** implement `on_new_span` (ADR-001 option B is forbidden).
#[derive(Debug, Clone, Default)]
pub struct TraceIdLayer {
    /// Weak handle to the installed `Dispatch`, needed by `get_otel_context`.
    dispatch: Arc<OnceLock<WeakDispatch>>,
    /// Count of `get_otel_context` invocations (cache misses only).
    otel_lookups: Arc<AtomicUsize>,
}

impl TraceIdLayer {
    /// Create a new [`TraceIdLayer`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of times this layer called `get_otel_context` (cache misses).
    #[cfg(test)]
    pub(crate) fn otel_lookup_count(&self) -> usize {
        self.otel_lookups.load(Ordering::Relaxed)
    }
}

impl<S> Layer<S> for TraceIdLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_register_dispatch(&self, subscriber: &tracing::Dispatch) {
        let _ = self.dispatch.set(subscriber.downgrade());
    }

    // Intentionally no `on_new_span` — ADR-001 option B is forbidden (lazy
    // on_event only; see architecture ADR-001 option D).

    fn on_event(&self, _event: &Event<'_>, ctx: Context<'_, S>) {
        // L2: event outside any span — return before touching extensions.
        let Some(span) = ctx.lookup_current() else {
            return;
        };

        // Cached-extension early return: subsequent events skip OTel lookup.
        if span.extensions().get::<TraceIds>().is_some() {
            return;
        }

        let Some(weak) = self.dispatch.get() else {
            return;
        };
        let Some(dispatch) = weak.upgrade() else {
            return;
        };

        let mut extensions = span.extensions_mut();
        // Re-check under exclusive access (concurrent first-event race).
        if extensions.get_mut::<TraceIds>().is_some() {
            return;
        }

        self.otel_lookups.fetch_add(1, Ordering::Relaxed);

        // L4: no OTel / WithContext → None; never insert zeroed TraceIds.
        let Some(otel_cx) = get_otel_context(&mut extensions, &dispatch) else {
            return;
        };

        // Soft P2: validated OTel SpanContext only (correlators, not auth).
        let otel_span = otel_cx.span();
        let span_context = otel_span.span_context();
        // L3: unsampled (sample_rate 0.0) → is_sampled == false → no cache.
        if !(span_context.is_valid() && span_context.is_sampled()) {
            return;
        }

        // Cache Copy ids — not Strings. Format injection is TRC-2c.
        extensions.insert(TraceIds {
            trace_id: span_context.trace_id(),
            span_id: span_context.span_id(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;
    use crate::init::init_tracing;
    use crate::propagation::inject_trace_context;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry::Registry;

    /// Read [`TraceIds`] from a live span's registry extensions.
    fn extension_trace_ids(span: &tracing::Span) -> Option<TraceIds> {
        span.with_subscriber(|(id, dispatch)| {
            dispatch.downcast_ref::<Registry>().and_then(|registry| {
                registry
                    .span(id)
                    .and_then(|span_ref| span_ref.extensions().get::<TraceIds>().copied())
            })
        })
        .flatten()
    }

    /// Trace-id hex from a W3C `traceparent` header value.
    fn trace_id_from_traceparent(tp: &str) -> &str {
        tp.split('-').nth(1).expect("traceparent must have a trace-id field")
    }

    #[test]
    fn l1_caches_trace_ids_matching_inject_trace_context() {
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let layer = TraceIdLayer::new();
        let subscriber = Registry::default().with(otel).with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("l1_sampled");
        let _enter = span.enter();
        tracing::info!("l1 event");

        let ids = extension_trace_ids(&span).expect("L1: TraceIds must be cached after an event");

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        let tp = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("inject_trace_context must yield traceparent under a sampled span");
        let injected = trace_id_from_traceparent(tp);
        assert_eq!(
            ids.trace_id.to_string(),
            injected,
            "cached trace_id must equal inject_trace_context's id (got cached={}, injected={tp})",
            ids.trace_id
        );
        assert_ne!(ids.trace_id, TraceId::INVALID);
        assert_ne!(ids.span_id, SpanId::INVALID);

        guard.provider.shutdown().ok();
    }

    #[test]
    fn l2_event_outside_span_caches_nothing() {
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let layer = TraceIdLayer::new();
        let subscriber = Registry::default().with(otel).with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        // A span that exists but is never entered must not be touched.
        let unused = tracing::info_span!("l2_unused");
        // Event outside any entered span → on_event returns before extensions.
        tracing::info!("l2 root event");

        assert!(
            extension_trace_ids(&unused).is_none(),
            "L2: unused span must not receive TraceIds from a root event"
        );

        guard.provider.shutdown().ok();
    }

    #[test]
    fn l3_unsampled_span_extension_is_none() {
        let config = TelemetryConfig { sample_rate: 0.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let layer = TraceIdLayer::new();
        let subscriber = Registry::default().with(otel).with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("l3_unsampled");
        let _enter = span.enter();
        tracing::info!("l3 event");

        assert!(
            extension_trace_ids(&span).is_none(),
            "L3: sample_rate 0.0 must leave TraceIds extension unset"
        );

        guard.provider.shutdown().ok();
    }

    #[test]
    fn l4_without_otel_layer_extension_is_none_no_zeros() {
        let layer = TraceIdLayer::new();
        let subscriber = Registry::default().with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("l4_no_otel");
        let _enter = span.enter();
        tracing::info!("l4 event");

        assert!(
            extension_trace_ids(&span).is_none(),
            "L4: without OTel layer, TraceIds must stay unset (no zeroed placeholder)"
        );
    }

    #[test]
    fn cached_extension_means_one_get_otel_context_per_span() {
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let layer = TraceIdLayer::new();
        let probe = layer.clone();
        let subscriber = Registry::default().with(otel).with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("cache_once");
        let _enter = span.enter();
        tracing::info!("event one");
        tracing::info!("event two");
        tracing::info!("event three");

        let ids = extension_trace_ids(&span).expect("cached after first event");
        assert_eq!(probe.otel_lookup_count(), 1, "exactly one get_otel_context per span");
        assert_eq!(extension_trace_ids(&span), Some(ids));

        guard.provider.shutdown().ok();
    }

    #[test]
    fn on_new_span_is_not_implemented() {
        // Static AC check: source must not define on_new_span (ADR-001 option B).
        let src = include_str!("trace_id.rs");
        let impl_region = src
            .split("impl<S> Layer<S> for TraceIdLayer")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("Layer impl present");
        assert!(
            !impl_region.contains("fn on_new_span"),
            "TraceIdLayer must not implement on_new_span (ADR-001 option B forbidden)"
        );
    }
}
