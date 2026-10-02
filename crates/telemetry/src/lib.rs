//! Telemetry subsystem for the validator client.
//!
//! Provides OpenTelemetry-based distributed tracing with OTLP/HTTP
//! export and optional GCP Cloud Trace support.
//!
//! The normative logging & observability contract for the whole workspace —
//! level taxonomy, the canonical structured-field registry, the secret-redaction
//! policy, and the `#[instrument]` idioms every crate codes against — is defined in
//! [`plan/logging/STANDARD.md`](https://github.com/dsrvlabs/rvc/blob/develop/plan/logging/STANDARD.md)
//! (also available in-tree at `plan/logging/STANDARD.md`).

pub mod config;
pub mod file_appender;
pub mod format;
pub mod init;
pub mod propagation;
pub mod shutdown;
pub mod trace_id;

pub use config::{ExporterKind, TelemetryConfig};
pub use file_appender::{create_file_layer, FileAppenderConfig};
pub use format::{console_fmt_layer, LogFormat, TraceIdFormat, LOG_FORMAT_ENV};
pub use init::{env_filter_or, init_tracing, reloadable_env_filter, LogReloadHandle};
pub use propagation::{inject_trace_context, set_parent_from_headers};
#[cfg(feature = "grpc")]
pub use propagation::{inject_trace_context_metadata, set_parent_from_metadata};
pub use shutdown::shutdown_tracing;
pub use trace_id::{TraceIdLayer, TraceIds, SPAN_ID_KEY, TRACE_ID_KEY};

/// Guard that keeps the tracing pipeline alive.
///
/// Hold it for process lifetime, then pass it to [`shutdown_tracing`].
/// Dropping the guard does **not** shut the provider down or flush pending
/// spans: the OpenTelemetry layer keeps its own provider clone, so the batch
/// processor's worker keeps running until [`shutdown_tracing`] is awaited.
#[must_use = "pass TracingGuard to shutdown_tracing; dropping it does not flush spans"]
pub struct TracingGuard {
    /// The SDK tracer provider backing the pipeline.
    pub(crate) provider: opentelemetry_sdk::trace::SdkTracerProvider,
}
