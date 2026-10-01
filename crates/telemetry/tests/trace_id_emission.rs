//! T13 / TRC-2e — `set_parent_from_headers` continues inbound traces under TraceIdLayer.
//!
//! ADR-001 option D (lazy `on_event`) is load-bearing: `get_otel_context` activates the
//! OTel span builder into a started `Context`. Resolving in `on_new_span` (option B)
//! would therefore consume the builder before `set_parent_from_headers` can attach the
//! inbound parent (`SetParentError::AlreadyStarted`), silently forking the duty trace.
//!
//! Name must NOT end in `_root` (kat_policy shrink-only).

use rvc_telemetry::{
    init_tracing, inject_trace_context, set_parent_from_headers, shutdown_tracing, TelemetryConfig,
    TraceIdLayer,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// T13: with TraceIdLayer installed, `set_parent_from_headers` still continues the inbound trace.
///
/// Must NOT be named `*_root` — kat_policy shrink-only.
#[tokio::test]
async fn set_parent_continues_inbound_with_trace_id_layer() {
    let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
    let (otel, guard) = init_tracing(&config).expect("init_tracing");
    let layer = TraceIdLayer::new();
    let subscriber = Registry::default().with(otel).with(layer);
    let _default = tracing::subscriber::set_default(subscriber);

    let trace_id = "0af7651916cd43dd8448eb211c80319c";
    let mut inbound = reqwest::header::HeaderMap::new();
    inbound.insert("traceparent", format!("00-{trace_id}-b7ad6b7169203331-01").parse().unwrap());

    // Unentered span — set_parent requires Builder state (before activation).
    let span = tracing::info_span!("t13_server_span");
    set_parent_from_headers(&span, &inbound);

    let _enter = span.enter();
    let mut outbound = reqwest::header::HeaderMap::new();
    inject_trace_context(&mut outbound);
    let tp = outbound
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .expect("traceparent should be present after enter");
    assert!(
        tp.contains(trace_id),
        "T13: TraceIdLayer must not prevent inbound continue (got {tp})"
    );
    assert!(
        !tp.contains("00000000000000000000000000000000"),
        "T13: continued trace must be non-zero (got {tp})"
    );

    // Emit an event so TraceIdLayer's on_event path also runs (lazy option D).
    tracing::info!("t13 event after set_parent");

    drop(_enter);
    drop(_default);
    shutdown_tracing(guard).await;
}
