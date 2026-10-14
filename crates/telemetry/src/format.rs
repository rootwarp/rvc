//! Console log-output format selector (issue 5.5 / P2-3).
//!
//! Both binaries render their **console** log stream through a single
//! `tracing_subscriber::fmt` layer. By default that layer emits the
//! human-readable *pretty* format (colorized, span-scoped lines) — the right
//! choice for interactive debugging and `grep`. An operator shipping logs to an
//! aggregation backend (Loki / Elasticsearch / a SIEM) can opt into a structured
//! **JSON** profile instead, where each event is one JSON object whose keys are
//! the canonical correlation fields (`request_id`, `slot`, …) so they are
//! machine-filterable.
//!
//! The selector is **opt-in and identical across both binaries** (consistent with
//! the Phase-3 [`env_filter_or`](crate::env_filter_or) /
//! [`reloadable_env_filter`](crate::reloadable_env_filter) shared-helper approach),
//! so an operator learns one knob, not two.
//!
//! ## Scope
//! This selector governs the **console** `fmt` layer only. It does **not** touch
//! the OTLP trace layer, the trace sampler, or the file appender's own format —
//! the on-disk file keeps its independent (pretty) rendering.
//!
//! ## Redaction is unaffected
//! Secret redaction happens at the **value** level: a `pubkey` is recorded as an
//! already-truncated `0x{first10}...{last8}` string (via
//! `observability::logging::TruncatedPubkey`) and a URL via `RedactedUrl` *before* it is
//! handed to any layer. JSON serialization of an already-redacted value stays
//! redacted — selecting JSON is **not** a redaction bypass (proven by a captured
//! subscriber test, see this module's tests).

use std::fmt;

use opentelemetry::trace::{SpanId, TraceId};
use tracing::Event;
use tracing_subscriber::fmt::format::{DefaultFields, Format, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, MakeWriter};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::trace_id::{TraceIds, SPAN_ID_KEY, TRACE_ID_KEY};

/// [`FormatEvent`] wrapper that renders cached [`TraceIds`] onto every log line.
///
/// Reads ids from the event's parent span extensions (`FmtContext::parent_span`,
/// which is `Context::event_span` — not bare `lookup_current`) so formatting
/// aligns with the event parent. When the extension is missing, emits nothing
/// (keys absent, not empty). Never emits zeroed / invalid ids.
///
/// Trace/span ids are **correlators**, not authentication material — do not key
/// ACL or audit decisions on their presence or the sampled flag.
///
/// Applied at all three build sites (pretty console, JSON console, file
/// appender). Does not record same-name fields onto the event (avoids dual
/// `trace_id` / `span_id` keys); rendering is this formatter's job alone.
pub struct TraceIdFormat<F>(pub F);

impl<S, N, F> FormatEvent<S, N> for TraceIdFormat<F>
where
    F: FormatEvent<S, N>,
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Soft P2: event parent via parent_span (== event_span), not lookup_current.
        let ids = ctx
            .parent_span()
            .and_then(|span| span.extensions().get::<TraceIds>().copied())
            .filter(|ids| ids.trace_id != TraceId::INVALID && ids.span_id != SpanId::INVALID);

        match ids {
            None => self.0.format_event(ctx, writer, event),
            Some(ids) => {
                // Preserve the caller's Writer by wrapping writes; Format may
                // still override ANSI via Format::with_ansi (same-crate).
                let mut inject = TraceIdInject { inner: writer, ids, state: InjectState::Pending };
                self.0.format_event(ctx, Writer::new(&mut inject), event)
            }
        }
    }
}

/// Injection state for [`TraceIdInject`].
#[derive(Debug, Clone, Copy)]
enum InjectState {
    /// Waiting for the first write from the inner formatter.
    Pending,
    /// JSON `{` + keys written; next content may need a separating comma.
    NeedComma,
    /// Keys already injected.
    Done,
}

/// Writer adapter that injects `trace_id` / `span_id` using each profile's field
/// syntax (pretty `key=value`, JSON `"key":"value"`) without `format!` /
/// `to_string()` on the render path.
struct TraceIdInject<'a> {
    inner: Writer<'a>,
    ids: TraceIds,
    state: InjectState,
}

impl fmt::Write for TraceIdInject<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self.state {
            InjectState::Pending => {
                if let Some(rest) = s.strip_prefix('{') {
                    // JSON profile: inject top-level keys immediately after `{`.
                    self.inner.write_char('{')?;
                    write_json_id_fields(&mut self.inner, &self.ids)?;
                    if rest.is_empty() {
                        self.state = InjectState::NeedComma;
                    } else {
                        if rest.starts_with('"') {
                            self.inner.write_char(',')?;
                        }
                        self.state = InjectState::Done;
                        self.inner.write_str(rest)?;
                    }
                } else {
                    // Pretty / full profile: emit key=value before the line body.
                    write_pretty_id_fields(&mut self.inner, &self.ids)?;
                    self.state = InjectState::Done;
                    self.inner.write_str(s)?;
                }
            }
            InjectState::NeedComma => {
                if s.starts_with('"') {
                    self.inner.write_char(',')?;
                }
                self.state = InjectState::Done;
                self.inner.write_str(s)?;
            }
            InjectState::Done => self.inner.write_str(s)?,
        }
        Ok(())
    }
}

/// Write `trace_id` / `span_id` as pretty `key=value` fields (no allocation).
fn write_pretty_id_fields(writer: &mut Writer<'_>, ids: &TraceIds) -> fmt::Result {
    writer.write_str(TRACE_ID_KEY)?;
    writer.write_str("=")?;
    write!(writer, "{}", ids.trace_id)?;
    writer.write_str(" ")?;
    writer.write_str(SPAN_ID_KEY)?;
    writer.write_str("=")?;
    write!(writer, "{}", ids.span_id)?;
    writer.write_str(" ")
}

/// Write `trace_id` / `span_id` as JSON object entries (no allocation).
fn write_json_id_fields(writer: &mut Writer<'_>, ids: &TraceIds) -> fmt::Result {
    writer.write_char('"')?;
    writer.write_str(TRACE_ID_KEY)?;
    writer.write_str("\":\"")?;
    write!(writer, "{}", ids.trace_id)?;
    writer.write_str("\",\"")?;
    writer.write_str(SPAN_ID_KEY)?;
    writer.write_str("\":\"")?;
    write!(writer, "{}", ids.span_id)?;
    writer.write_char('"')
}

/// Selects how the **console** log stream is rendered (issue 5.5).
///
/// `Pretty` is the default and reproduces today's exact human-readable output;
/// `Json` emits one structured JSON object per event for log-aggregation
/// backends. Parsed from the `--log-format` CLI flag and/or the
/// `RVC_LOG_FORMAT` environment variable via [`LogFormat::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable, colorized, span-scoped lines (the default).
    #[default]
    Pretty,
    /// One JSON object per event, canonical fields flattened to top-level keys.
    Json,
}

/// The environment variable an operator may set to choose the console format,
/// mirroring how `RUST_LOG` selects the level. An explicit `--log-format` CLI
/// flag takes precedence over this (see [`LogFormat::resolve`]).
pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";

impl LogFormat {
    /// Parse a single textual token (`"pretty"` / `"json"`, case-insensitive,
    /// surrounding whitespace tolerated) into a [`LogFormat`].
    ///
    /// Returns `None` for anything unrecognized so a caller can decide whether an
    /// unknown value is a hard error (CLI, via `clap`'s `ValueEnum`) or a soft
    /// fall-back-to-default (the `RVC_LOG_FORMAT` env path — an accidental typo in
    /// a k8s manifest must never silence or crash logging).
    pub fn parse_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "pretty" => Some(Self::Pretty),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Reconcile the console format from the optional CLI value and the
    /// `RVC_LOG_FORMAT` environment variable, with **pretty as the default**.
    ///
    /// Precedence (highest first), parallel to ADR-003's `RUST_LOG` precedence so
    /// the two knobs behave consistently:
    /// 1. an explicit, recognized `--log-format` CLI value wins entirely;
    /// 2. else a recognized `RVC_LOG_FORMAT` env value;
    /// 3. else (unset / empty / unrecognized) → [`LogFormat::Pretty`].
    ///
    /// Unrecognized values fall back rather than panicking, so a typo never takes
    /// logging dark — exactly the posture [`env_filter_or`](crate::env_filter_or)
    /// takes for the level.
    pub fn resolve(cli_value: Option<&str>) -> Self {
        if let Some(v) = cli_value {
            if let Some(fmt) = Self::parse_token(v) {
                return fmt;
            }
        }
        if let Ok(env) = std::env::var(LOG_FORMAT_ENV) {
            if let Some(fmt) = Self::parse_token(&env) {
                return fmt;
            }
        }
        Self::Pretty
    }

    /// The canonical lowercase token for this format (`"pretty"` / `"json"`),
    /// for echoing the resolved choice back to logs/help text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the **console** `fmt` layer for the selected [`LogFormat`], type-erased to
/// `Box<dyn Layer<S>>` so a single variable holds either arm.
///
/// `fmt::layer()` (pretty) and `fmt::layer().json()` are **different types**, so
/// they cannot be assigned to one variable directly; boxing both behind
/// `dyn Layer<S>` lets each binary compose ONE console layer into its subscriber
/// stack identically, regardless of the format. This keeps the 5.4 reload
/// composition and the empty-`Vec` `Identity` padding byte-identical across both
/// arms — only the leaf console layer's *format* differs.
///
/// For `Json`, `flatten_event(true)` lifts the event's own fields to the top level
/// (no nested `fields` object) and `with_current_span(true)` attaches the current
/// span's fields, so the canonical correlation keys (`request_id`, `slot`, …) land
/// as top-level JSON keys that an aggregation backend can index directly.
///
/// The `make_writer` parameter is the destination (production passes
/// `std::io::stdout`); it is generic so tests can capture output into a buffer.
pub fn console_fmt_layer<S, W>(format: LogFormat, make_writer: W) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Pretty => fmt_layer_pretty(make_writer).boxed(),
        LogFormat::Json => json_layer::json_console_layer(make_writer).boxed(),
    }
}

/// The pretty (default) console layer — the `fmt::layer()` both binaries
/// built before issue 5.5, parameterized only by its writer.
///
/// ANSI styling is enabled only when the process stdout is a terminal, so
/// piped/redirected console output (journald, docker, test harnesses) stays
/// free of escape sequences — matching the file appender's `with_ansi(false)`.
///
/// Wrapped in [`TraceIdFormat`] so sampled spans carry `trace_id` / `span_id`
/// (TRC-2c). `Format::with_ansi` mirrors the layer flag so color survives the
/// writer-adapter wrap inside [`TraceIdFormat`].
fn fmt_layer_pretty<S, W>(
    make_writer: W,
) -> tracing_subscriber::fmt::Layer<S, DefaultFields, TraceIdFormat<Format>, W>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    use std::io::IsTerminal;
    let ansi = std::io::stdout().is_terminal();
    tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .event_format(TraceIdFormat(Format::default().with_ansi(ansi)))
        .with_writer(make_writer)
}

/// Local sub-module so the JSON-layer type (`Format<Json>`) need not be named at
/// the call site — `.boxed()` erases it immediately in [`console_fmt_layer`].
mod json_layer {
    use super::*;

    /// The JSON console layer with canonical fields flattened to top-level keys.
    ///
    /// [`TraceIdFormat`] wraps the JSON event formatter so `trace_id` /
    /// `span_id` land as top-level keys (T6) when the span extension is set.
    pub(super) fn json_console_layer<S, W>(make_writer: W) -> impl Layer<S> + Send + Sync
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .map_event_format(TraceIdFormat)
            .with_writer(make_writer)
    }
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::prelude::*;

    // Serializes the `RVC_LOG_FORMAT`-mutating `resolve` tests (process-global env).
    // nextest forks a process per test, but guard anyway so the suite is correct
    // under any runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_log_format_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(LOG_FORMAT_ENV).ok();
        match value {
            Some(v) => unsafe { std::env::set_var(LOG_FORMAT_ENV, v) },
            None => unsafe { std::env::remove_var(LOG_FORMAT_ENV) },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var(LOG_FORMAT_ENV, p) },
            None => unsafe { std::env::remove_var(LOG_FORMAT_ENV) },
        }
        out
    }

    /// A `MakeWriter` that captures everything written into a shared buffer, so a
    /// captured-subscriber test can inspect the rendered bytes.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    impl SharedBuf {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    // ── LogFormat::parse_token ────────────────────────────────────────────────

    #[test]
    fn parse_token_accepts_canonical_tokens_case_and_space_insensitively() {
        assert_eq!(LogFormat::parse_token("pretty"), Some(LogFormat::Pretty));
        assert_eq!(LogFormat::parse_token("json"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse_token("  JSON  "), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse_token("Pretty"), Some(LogFormat::Pretty));
    }

    #[test]
    fn parse_token_rejects_unknown() {
        assert_eq!(LogFormat::parse_token("logfmt"), None);
        assert_eq!(LogFormat::parse_token(""), None);
    }

    #[test]
    fn default_is_pretty() {
        assert_eq!(LogFormat::default(), LogFormat::Pretty);
    }

    // ── LogFormat::resolve precedence ────────────────────────────────────────

    /// With no CLI value and no env, the format defaults to pretty — the
    /// constraint that an unset selector reproduces today's exact output.
    #[test]
    fn resolve_unset_defaults_to_pretty() {
        let got = with_log_format_env(None, || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Pretty);
    }

    /// An explicit CLI value wins over both the env and the default.
    #[test]
    fn resolve_cli_value_wins_over_env() {
        let got = with_log_format_env(Some("pretty"), || LogFormat::resolve(Some("json")));
        assert_eq!(got, LogFormat::Json, "CLI --log-format must outrank RVC_LOG_FORMAT");
    }

    /// With no CLI value, a recognized env value selects the format.
    #[test]
    fn resolve_env_selects_when_no_cli() {
        let got = with_log_format_env(Some("json"), || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Json);
    }

    /// An unrecognized value (CLI or env) never panics and never silences logging:
    /// it falls back to pretty, exactly as `env_filter_or` falls back for the level.
    #[test]
    fn resolve_unrecognized_falls_back_to_pretty() {
        let got = with_log_format_env(Some("garbage"), || LogFormat::resolve(Some("nonsense")));
        assert_eq!(got, LogFormat::Pretty);
        // A bad env with no CLI value also falls back.
        let got = with_log_format_env(Some("xml"), || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Pretty);
    }

    // ── JSON profile: parses + canonical fields are top-level keys ────────────

    /// With the JSON profile selected, a representative event carrying canonical
    /// correlation fields serializes to ONE valid JSON object per line in which
    /// `slot`, `request_id`, and a (truncated) `pubkey` appear as TOP-LEVEL keys
    /// (thanks to `flatten_event`) — i.e. machine-filterable, not nested.
    #[test]
    fn json_profile_emits_parseable_object_with_canonical_top_level_keys() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                slot = 7u64,
                request_id = "11111111-2222-3333-4444-555555555555",
                pubkey = "0x93247f2209...611df74a",
                "duty signed"
            );
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("duty signed")).expect("event line present");
        let v: serde_json::Value = serde_json::from_str(line).expect("each JSON line must parse");

        assert_eq!(
            v["fields"],
            serde_json::Value::Null,
            "flatten_event must hoist fields to top level"
        );
        assert_eq!(v["slot"], 7, "slot must be a top-level JSON key");
        assert_eq!(v["request_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(v["pubkey"], "0x93247f2209...611df74a");
        assert_eq!(v["message"], "duty signed");
        assert_eq!(v["level"], "INFO");
    }

    /// The current span's fields surface as top-level JSON keys too
    /// (`with_current_span(true)`), so a `request_id` set on the enclosing span is
    /// machine-filterable on every event emitted within it.
    #[test]
    fn json_profile_includes_current_span_fields() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", request_id = "abc-123");
            let _e = span.enter();
            tracing::info!("inside span");
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("inside span")).expect("event line present");
        let v: serde_json::Value = serde_json::from_str(line).expect("parses");
        // `with_current_span` records the span under `span` with its fields.
        assert_eq!(v["span"]["request_id"], "abc-123", "current span field must be present");
    }

    // ── Default (pretty) profile: NOT JSON, unchanged shape ───────────────────

    /// With the pretty profile (the default), output is the human-readable line
    /// format — it is NOT a parseable JSON object, and it contains the message and
    /// fields rendered the classic way. This pins that selecting nothing keeps
    /// today's behavior.
    #[test]
    fn pretty_profile_is_not_json() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Pretty, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(slot = 7u64, "duty signed");
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("duty signed")).expect("event line present");
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_err(),
            "pretty output must NOT be a JSON object; got: {line:?}"
        );
        // Strip ANSI styling so the pretty `key=value` rendering is greppable
        // (the colorized output interleaves escape sequences around the `=`).
        let plain = strip_ansi(line);
        assert!(plain.contains("INFO"), "pretty renders the level; got: {plain:?}");
        assert!(plain.contains("slot"), "pretty renders the field name; got: {plain:?}");
        assert!(plain.contains("slot=7"), "pretty renders fields key=value; got: {plain:?}");
    }

    /// Strip ANSI SGR escape sequences (`\x1b[...m`) so a pretty line's text can be
    /// asserted without the interleaved color codes.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // Consume up to and including the terminating 'm' of an SGR sequence.
                for n in chars.by_ref() {
                    if n == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    // ── TraceIdFormat (TRC-2c): T1–T4, T6 ─────────────────────────────────────

    use crate::config::TelemetryConfig;
    use crate::init::init_tracing;
    use crate::propagation::inject_trace_context;
    use crate::trace_id::{TraceIdLayer, SPAN_ID_KEY, TRACE_ID_KEY};

    /// Trace-id hex from a W3C `traceparent` header value.
    fn trace_id_from_traceparent(tp: &str) -> &str {
        tp.split('-').nth(1).expect("traceparent must have a trace-id field")
    }

    /// Extract `key=value` field text from a pretty line (ANSI-stripped).
    fn pretty_field_value<'a>(plain: &'a str, key: &str) -> Option<&'a str> {
        let marker = format!("{key}=");
        let start = plain.find(&marker)? + marker.len();
        let rest = &plain[start..];
        Some(rest.split_whitespace().next().unwrap_or(rest))
    }

    /// Shared stack: OTel → TraceIdLayer → console fmt (Layered, not Vec — so
    /// `on_register_dispatch` reaches TraceIdLayer).
    fn with_trace_id_console(
        otel: Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
        format: LogFormat,
        buf: SharedBuf,
    ) -> impl tracing::Subscriber + Send + Sync {
        let fmt_layer = console_fmt_layer(format, buf);
        tracing_subscriber::registry().with(otel).with(TraceIdLayer::new()).with(fmt_layer)
    }

    /// T1: line inside a sampled span carries both keys; rendered `trace_id`
    /// equals `inject_trace_context` re-inject for that span.
    #[test]
    fn t1_sampled_span_line_carries_keys_matching_inject() {
        let buf = SharedBuf::default();
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let subscriber = with_trace_id_console(otel, LogFormat::Pretty, buf.clone());
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("t1_sampled");
        let _enter = span.enter();
        tracing::info!("t1 correlated event");

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        let tp = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("inject_trace_context must yield traceparent under a sampled span");
        let injected = trace_id_from_traceparent(tp);

        let out = buf.contents();
        let line =
            out.lines().find(|l| l.contains("t1 correlated event")).expect("event line present");
        let plain = strip_ansi(line);

        assert!(
            plain.contains(TRACE_ID_KEY),
            "T1: pretty line must carry {TRACE_ID_KEY}; got: {plain:?}"
        );
        assert!(
            plain.contains(SPAN_ID_KEY),
            "T1: pretty line must carry {SPAN_ID_KEY}; got: {plain:?}"
        );
        let rendered =
            pretty_field_value(&plain, TRACE_ID_KEY).expect("T1: trace_id= value must be present");
        assert_eq!(
            rendered, injected,
            "T1: rendered trace_id must equal inject_trace_context (got {rendered}, injected={tp})"
        );

        guard.provider.shutdown().ok();
    }

    /// T2: line outside any span carries neither key — absent, not empty.
    #[test]
    fn t2_outside_span_keys_absent() {
        let buf = SharedBuf::default();
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let subscriber = with_trace_id_console(otel, LogFormat::Pretty, buf.clone());
        let _default = tracing::subscriber::set_default(subscriber);

        tracing::info!("t2 root event");

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("t2 root event")).expect("event line present");
        let plain = strip_ansi(line);
        assert!(
            !plain.contains(TRACE_ID_KEY),
            "T2: {TRACE_ID_KEY} must be absent outside a span; got: {plain:?}"
        );
        assert!(
            !plain.contains(SPAN_ID_KEY),
            "T2: {SPAN_ID_KEY} must be absent outside a span; got: {plain:?}"
        );

        guard.provider.shutdown().ok();
    }

    /// T3: `sample_rate: 0.0` → both keys absent (dominant production case).
    #[test]
    fn t3_unsampled_keys_absent() {
        let buf = SharedBuf::default();
        let config = TelemetryConfig { sample_rate: 0.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let subscriber = with_trace_id_console(otel, LogFormat::Pretty, buf.clone());
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("t3_unsampled");
        let _enter = span.enter();
        tracing::info!("t3 unsampled event");

        let out = buf.contents();
        let line =
            out.lines().find(|l| l.contains("t3 unsampled event")).expect("event line present");
        let plain = strip_ansi(line);
        assert!(
            !plain.contains(TRACE_ID_KEY),
            "T3: {TRACE_ID_KEY} must be absent at sample_rate 0.0; got: {plain:?}"
        );
        assert!(
            !plain.contains(SPAN_ID_KEY),
            "T3: {SPAN_ID_KEY} must be absent at sample_rate 0.0; got: {plain:?}"
        );

        guard.provider.shutdown().ok();
    }

    /// T4: subscriber without `init_tracing` → substring `00000000` never appears.
    #[test]
    fn t4_without_otel_never_emits_zeroed_ids() {
        let buf = SharedBuf::default();
        // without_time on the inner Format avoids timestamp false-positives on
        // the literal `00000000` scan (e.g. `00.00000000` in fractional seconds).
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .event_format(TraceIdFormat(
                tracing_subscriber::fmt::format().without_time().with_ansi(false),
            ))
            .with_writer(buf.clone());
        let subscriber = tracing_subscriber::registry().with(TraceIdLayer::new()).with(fmt_layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("t4_no_otel");
        let _enter = span.enter();
        tracing::info!("t4 no otel event");

        let out = buf.contents();
        let line =
            out.lines().find(|l| l.contains("t4 no otel event")).expect("event line present");
        assert!(
            !line.contains(TRACE_ID_KEY) && !line.contains(SPAN_ID_KEY),
            "T4: keys must be absent without OTel; got: {line:?}"
        );
        assert!(
            !line.contains("00000000"),
            "T4: zeroed-id substring must never appear; got: {line:?}"
        );
    }

    /// T6: JSON profile yields `v["trace_id"]` and `v["span_id"]` at top level.
    #[test]
    fn t6_json_profile_top_level_trace_and_span_id() {
        let buf = SharedBuf::default();
        let config = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, guard) = init_tracing(&config).expect("init_tracing");
        let subscriber = with_trace_id_console(otel, LogFormat::Json, buf.clone());
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("t6_json");
        let _enter = span.enter();
        tracing::info!("t6 json event");

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        let tp = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("inject_trace_context must yield traceparent");
        let injected = trace_id_from_traceparent(tp);

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("t6 json event")).expect("event line present");
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON line must parse");

        let tid = v[TRACE_ID_KEY].as_str().expect("T6: top-level trace_id string");
        let sid = v[SPAN_ID_KEY].as_str().expect("T6: top-level span_id string");
        assert_eq!(tid, injected, "T6: JSON trace_id must equal inject_trace_context");
        assert!(!tid.is_empty() && tid != "00000000000000000000000000000000");
        assert!(!sid.is_empty() && sid != "0000000000000000");

        guard.provider.shutdown().ok();
    }

    /// REFACTOR: TraceIdFormat render path must not call `format!` / `to_string()`.
    #[test]
    fn trace_id_format_render_path_has_no_format_or_to_string() {
        let src = include_str!("format.rs");
        let hot = src
            .split("impl fmt::Write for TraceIdInject")
            .nth(1)
            .and_then(|s| s.split("/// Selects how the **console** log stream is rendered").next())
            .expect("TraceIdInject Write impl + id-field helpers present");
        assert!(
            !hot.contains("format!(") && !hot.contains(".to_string()"),
            "REFACTOR: no format!/to_string() on TraceIdFormat render hot path"
        );
    }

    /// JSON serialization must NOT undo value-level redaction. Redaction happens
    /// BEFORE recording: a `pubkey` is recorded as the already-truncated
    /// `0x{first10}...{last8}` string and a URL via `RedactedUrl`, so the layer
    /// only ever sees redacted strings. This proves the JSON profile serializes
    /// those redacted values verbatim — the full 96-char pubkey and the URL
    /// credentials never appear in the JSON.
    #[test]
    fn json_profile_does_not_bypass_value_level_redaction() {
        // The full secret material an upstream call site would have held.
        let full_pubkey =
            "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        // The already-redacted values that actually get recorded (this is exactly
        // what `observability::logging::TruncatedPubkey` / `RedactedUrl` produce at the
        // VALUE level before the field is handed to any layer).
        let redacted_pubkey = "0x93247f2209...611df74a";
        let redacted_url = "http://***:***@beacon.internal:5052/";

        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                pubkey = redacted_pubkey,
                bn_url = redacted_url,
                "high-risk signing event"
            );
        });

        let out = buf.contents();
        let line =
            out.lines().find(|l| l.contains("high-risk signing event")).expect("event present");
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON parses");

        // The redacted values appear verbatim as JSON values…
        assert_eq!(v["pubkey"], redacted_pubkey, "pubkey must be the truncated form");
        assert_eq!(v["bn_url"], redacted_url, "bn_url must be the credential-stripped form");

        // …and the secrets NEVER appear anywhere in the serialized JSON.
        assert!(
            !line.contains(full_pubkey),
            "the full 96-char pubkey must NOT appear in JSON output; line: {line:?}"
        );
        assert!(
            !line.contains("hunter2") && !line.contains(":pass@"),
            "URL credentials must NOT appear in JSON output; line: {line:?}"
        );
        // The middle of the full pubkey (absent from the truncated form) must be gone.
        assert!(
            !line.contains("abcacf57b75a51"),
            "middle of the full pubkey must be truncated away; line: {line:?}"
        );
    }
}
