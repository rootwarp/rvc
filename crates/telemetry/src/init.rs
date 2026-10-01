use anyhow::Result;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider,
};
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::Registry;

use crate::config::{ExporterKind, TelemetryConfig};
use crate::TracingGuard;

const SERVICE_NAME: &str = "rvc";

/// Initialize the tracing pipeline with the given configuration.
///
/// Returns a tuple of:
/// - An [`OpenTelemetryLayer`] to be composed into a `tracing_subscriber`
/// - A [`TracingGuard`] that must be held for the lifetime of the application
///
/// The caller is responsible for composing the layer into their subscriber.
pub fn init_tracing(
    config: &TelemetryConfig,
) -> Result<(Box<dyn Layer<Registry> + Send + Sync>, TracingGuard)> {
    config.validate()?;

    global::set_text_map_propagator(TraceContextPropagator::new());

    let version =
        config.service_version.clone().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    // Resolve once for both resource and tracer (ADR-007 / TRC-1c).
    let service_name = config.service_name.as_deref().unwrap_or(SERVICE_NAME).to_string();

    let resource = Resource::builder()
        .with_service_name(service_name.clone())
        .with_attributes([
            KeyValue::new("service.version", version),
            KeyValue::new("network.name", config.network.clone()),
        ])
        .build();

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));

    let provider = build_provider(config, resource, sampler)?;

    let tracer = provider.tracer(service_name);
    let layer = OpenTelemetryLayer::new(tracer).boxed();

    Ok((layer, TracingGuard { provider }))
}

fn build_provider(
    config: &TelemetryConfig,
    resource: Resource,
    sampler: Sampler,
) -> Result<SdkTracerProvider> {
    match config.exporter {
        ExporterKind::Otlp => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(&config.endpoint)
                .build()?;

            let mut batch_config = BatchConfigBuilder::default();
            if let Some(queue_size) = config.max_queue_size {
                batch_config = batch_config.with_max_queue_size(queue_size);
            }
            if let Some(batch_size) = config.max_export_batch_size {
                batch_config = batch_config.with_max_export_batch_size(batch_size);
            }
            let processor = BatchSpanProcessor::builder(exporter)
                .with_batch_config(batch_config.build())
                .build();

            Ok(SdkTracerProvider::builder()
                .with_sampler(sampler)
                .with_resource(resource)
                .with_span_processor(processor)
                .build())
        }
        #[cfg(feature = "gcp-trace")]
        ExporterKind::Gcp => build_gcp_provider(resource, sampler),
    }
}

#[cfg(feature = "gcp-trace")]
fn build_gcp_provider(resource: Resource, sampler: Sampler) -> Result<SdkTracerProvider> {
    let handle = tokio::runtime::Handle::current();

    tokio::task::block_in_place(|| {
        let gcp_builder = handle
            .block_on(
                opentelemetry_gcloud_trace::GcpCloudTraceExporterBuilder::for_default_project_id(),
            )
            .map_err(|e| anyhow::anyhow!("GCP project ID detection failed: {e}"))?;

        let provider_builder =
            SdkTracerProvider::builder().with_sampler(sampler).with_resource(resource.clone());

        let provider = handle
            .block_on(
                gcp_builder.with_resource(resource).create_provider_from_builder(provider_builder),
            )
            .map_err(|e| anyhow::anyhow!("GCP Cloud Trace exporter initialization failed: {e}"))?;

        Ok(provider)
    })
}

/// Build an [`EnvFilter`](tracing_subscriber::EnvFilter) honoring the rs-vc
/// logging precedence (ADR-003): if `RUST_LOG` is set to one or more valid
/// directives, it wins entirely; otherwise the filter falls back to
/// `default_level`.
///
/// The env value is normalized before parsing: each comma-separated directive
/// is trimmed and empty ones are dropped, so human-written whitespace
/// (`"warn, rvc=trace"`) is honored rather than discarded.
///
/// The fallback deliberately covers every case that would otherwise leave the
/// process with no logging, so an *accidental* "verbose off" never means
/// "silent":
/// - `RUST_LOG` unset (or non-UTF-8),
/// - a malformed directive (e.g. an invalid level like `rvc=notalevel`), and
/// - a set-but-empty value (`""`, `","`, whitespace) — which `tracing-subscriber`
///   would otherwise parse into an all-`OFF` filter (a real `RUST_LOG=` /
///   `value: ""` misconfig in a Dockerfile or k8s manifest).
///
/// An *explicit* `RUST_LOG=off` is still honored (the operator asked for
/// silence); only the accidental-empty cases fall back to `default_level`.
///
/// This never panics: `default_level` is fed through the lossy
/// [`EnvFilter::new`], which *ignores* an invalid directive (printing a warning)
/// rather than panicking. Callers pass a static `"info"`. This is the single
/// shared implementation both `bin/rvc` and `bin/rvc-signer` route their
/// subscriber init through, so the two binaries cannot drift on default level
/// or precedence.
///
/// # Example
/// ```
/// use rvc_telemetry::env_filter_or;
/// // With `RUST_LOG` unset, empty, or malformed, the filter defaults to `info`.
/// let _filter = env_filter_or("info");
/// ```
pub fn env_filter_or(default_level: &str) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    // Normalize: split on ',', trim each directive, drop empties. This honors
    // human-written whitespace ("warn, rvc=trace") and collapses a set-but-empty
    // value ("", ",", "   ") to the unset case rather than an all-`OFF` filter.
    let normalized = std::env::var("RUST_LOG").ok().map(|v| {
        v.split(',').map(str::trim).filter(|d| !d.is_empty()).collect::<Vec<_>>().join(",")
    });
    match normalized {
        // At least one directive survived normalization: it wins, falling back
        // only if the directives fail to parse (e.g. an invalid level).
        Some(dirs) if !dirs.is_empty() => {
            EnvFilter::try_new(&dirs).unwrap_or_else(|_| EnvFilter::new(default_level))
        }
        // Unset, non-UTF-8, or set-but-effectively-empty.
        _ => EnvFilter::new(default_level),
    }
}

/// Wrap the reconciled [`EnvFilter`](tracing_subscriber::EnvFilter) in a
/// [`reload::Layer`](tracing_subscriber::reload::Layer) so the active log filter
/// can be swapped at runtime without restarting the process (issue 5.4 / P2-2).
///
/// The layer's **initial value is exactly `env_filter_or(default_level)`** — the
/// same filter both binaries' init reconciles to (ADR-003 precedence) — so wiring
/// this in place of a bare `env_filter_or(level)` changes nothing about the
/// startup behavior: unset/empty/malformed `RUST_LOG` still yields
/// `default_level`, and a valid `RUST_LOG` still wins. The only difference is that
/// the returned [`reload::Handle`](tracing_subscriber::reload::Handle) can later
/// call [`reload`](tracing_subscriber::reload::Handle::reload) to install a fresh
/// filter; `reload` rebuilds tracing's callsite-interest cache, so a previously
/// disabled `debug!`/`trace!` callsite is re-evaluated and begins emitting.
///
/// # Cost (P0-6 / Gate 4)
/// The reload layer adds an `RwLock` read **only** when a callsite's interest is
/// (re)computed or an enabled event dispatches. A callsite the inner `EnvFilter`
/// reports as `Interest::never()` (e.g. a disabled `debug!` at the default `info`
/// level) short-circuits in the `tracing` macro *before* dispatch, so it never
/// enters this layer — the disabled hot path stays zero-allocation. Operators who
/// want the absolute-minimum default build can leave the runtime trigger that
/// drives the handle opt-in (it is); the layer itself is always-on but free on the
/// disabled path.
///
/// Generic over the subscriber `S` so each binary can compose it as the outer
/// filter layer over its own `Registry` stack, identically.
///
/// # Example
/// ```
/// use rvc_telemetry::reloadable_env_filter;
/// use tracing_subscriber::Registry;
/// let (_layer, handle) = reloadable_env_filter::<Registry>("info");
/// // Later, raise a specific target at runtime:
/// let _ = handle.reload(rvc_telemetry::env_filter_or("info"));
/// ```
pub fn reloadable_env_filter<S>(
    default_level: &str,
) -> (
    tracing_subscriber::reload::Layer<tracing_subscriber::EnvFilter, S>,
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, S>,
) {
    tracing_subscriber::reload::Layer::new(env_filter_or(default_level))
}

/// A type-erased handle to the runtime-reloadable log filter (issue 5.4).
///
/// The underlying [`reload::Handle`](tracing_subscriber::reload::Handle) is
/// generic over the (unspellable) layered subscriber type each binary composes,
/// so the bins store this erased wrapper instead. [`reload_from_env`] re-reads
/// `RUST_LOG` through the same [`env_filter_or`] precedence used at startup and
/// swaps the active filter in place — exactly what an operator's runtime trigger
/// (e.g. a `SIGHUP` handler) calls. Cloning is cheap (the inner handle holds a
/// `Weak`), so the handle can be moved into a signal-handler task.
#[derive(Clone)]
pub struct LogReloadHandle {
    default_level: std::sync::Arc<str>,
    reload: std::sync::Arc<
        dyn Fn(tracing_subscriber::EnvFilter) -> Result<(), tracing_subscriber::reload::Error>
            + Send
            + Sync,
    >,
}

impl LogReloadHandle {
    /// Erase a concrete [`reload::Handle`](tracing_subscriber::reload::Handle)
    /// into a transport-agnostic handle, remembering the `default_level` so
    /// [`reload_from_env`](Self::reload_from_env) reproduces the startup
    /// precedence (unset/empty/malformed `RUST_LOG` → `default_level`).
    pub fn new<S>(
        default_level: &str,
        handle: tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, S>,
    ) -> Self
    where
        S: 'static,
    {
        Self {
            default_level: std::sync::Arc::from(default_level),
            reload: std::sync::Arc::new(move |filter| handle.reload(filter)),
        }
    }

    /// Re-read `RUST_LOG` via [`env_filter_or`] and install the resulting filter,
    /// rebuilding tracing's callsite-interest cache so newly enabled
    /// `debug!`/`trace!` callsites begin emitting. Returns an error only if the
    /// subscriber has already been torn down (the layer was dropped).
    pub fn reload_from_env(&self) -> Result<(), tracing_subscriber::reload::Error> {
        (self.reload)(env_filter_or(&self.default_level))
    }
}

impl std::fmt::Debug for LogReloadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogReloadHandle")
            .field("default_level", &self.default_level)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes the `RUST_LOG`-mutating `env_filter_or` tests. `nextest` runs
    // each test in its own process, but guard anyway so the suite stays correct
    // under any runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_rust_log<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        match value {
            Some(v) => unsafe { std::env::set_var("RUST_LOG", v) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        out
    }

    #[test]
    fn env_filter_or_unset_defaults_to_info() {
        let rendered = with_rust_log(None, || format!("{}", env_filter_or("info")));
        assert_eq!(rendered, "info", "expected info default, got: {rendered}");
    }

    #[test]
    fn env_filter_or_set_but_empty_falls_back_to_default() {
        // A present-but-empty RUST_LOG ("", ",", whitespace) would otherwise
        // parse to an all-OFF filter and silence the process; treat it as unset
        // so logging never goes dark on a `RUST_LOG=` style misconfig.
        for v in ["", ",", ",,,", "   "] {
            let rendered = with_rust_log(Some(v), || format!("{}", env_filter_or("info")));
            assert_eq!(
                rendered, "info",
                "RUST_LOG={v:?} should fall back to info, got: {rendered}"
            );
        }
    }

    #[test]
    fn env_filter_or_respects_rust_log() {
        let rendered = with_rust_log(Some("debug"), || format!("{}", env_filter_or("info")));
        assert!(rendered.contains("debug"), "env RUST_LOG=debug should win, got: {rendered}");
    }

    #[test]
    fn env_filter_or_trims_whitespace_around_directives() {
        // Human-written RUST_LOG with spaces after commas must be honored, not
        // silently discarded to the default (the way an SRE hand-types it).
        let rendered =
            with_rust_log(Some("warn, rvc=trace"), || format!("{}", env_filter_or("info")));
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(rendered.contains("rvc=trace"), "trimmed per-module directive missing: {rendered}");
        // A whitespace-padded single directive is also tolerated.
        let single = with_rust_log(Some("  debug "), || format!("{}", env_filter_or("info")));
        assert_eq!(single, "debug", "padded single directive should render debug, got: {single}");
    }

    #[test]
    fn env_filter_or_malformed_falls_back_to_default() {
        // A *syntactically invalid* directive — here an unknown level after `=`
        // (a realistic operator typo) — fails to parse, so the helper falls back
        // to the default rather than panicking or going silent. (A bare junk
        // token like "garbage" would instead parse as a valid *target* directive,
        // not an error, so it is not the malformed case this guards.)
        let rendered =
            with_rust_log(Some("rvc=invalidlevel"), || format!("{}", env_filter_or("info")));
        assert_eq!(
            rendered, "info",
            "malformed RUST_LOG should fall back to info, got: {rendered}"
        );
    }

    #[test]
    fn env_filter_or_preserves_per_module_directive() {
        let rendered = with_rust_log(Some("warn,signer_server::http_api=trace"), || {
            format!("{}", env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(
            rendered.contains("signer_server::http_api"),
            "per-module target missing: {rendered}"
        );
        assert!(rendered.contains("trace"), "per-module level missing: {rendered}");
    }

    // ── Issue 5.4: runtime log-level reload via `reload::Layer` ───────────────

    /// `reloadable_env_filter` must seed the layer with EXACTLY the value
    /// `env_filter_or` would return — so wiring it in place of a bare
    /// `env_filter_or(level)` is invisible at startup (the Phase-3 init
    /// reconciliation / cross-binary parity contract is preserved).
    #[test]
    fn reloadable_env_filter_initial_value_matches_env_filter_or() {
        use tracing_subscriber::Registry;
        for env in [None, Some("debug"), Some("warn,rvc=trace"), Some(""), Some("rvc=invalidlevel")]
        {
            let (reload_rendered, plain_rendered) = with_rust_log(env, || {
                let (layer, handle) = reloadable_env_filter::<Registry>("info");
                let reloaded = handle
                    .with_current(|f| format!("{f}"))
                    .expect("handle live while layer in scope");
                drop(layer);
                (reloaded, format!("{}", env_filter_or("info")))
            });
            assert_eq!(
                reload_rendered, plain_rendered,
                "reloadable layer initial value must match env_filter_or for RUST_LOG={env:?}"
            );
        }
    }

    /// The core mechanism: a subscriber initialized at effective `info` via the
    /// reloadable layer suppresses `debug!` on every target; after the handle
    /// reloads a filter that raises ONE target to `debug`, a `debug!` on THAT
    /// target emits while an unrelated target's `debug!` still does not. This is
    /// the runtime "raise verbosity without a restart" guarantee (issue 5.4),
    /// proven by a direct `handle.reload(...)` (no live signal needed).
    #[test]
    fn reload_raises_one_target_without_restart() {
        use std::io;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;

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

        // Force the default-`info` startup path regardless of the runner's env.
        with_rust_log(None, || {
            let buf = SharedBuf::default();
            // Compose exactly as the binaries do — the reload filter is the OUTER
            // layer over the fmt stack, so `S` is inferred as the layered type and
            // the filter governs the whole subscriber globally.
            let (reload_layer, handle) = reloadable_env_filter("info");
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()))
                .with(reload_layer);
            let _: &tracing_subscriber::reload::Handle<EnvFilter, _> = &handle;

            tracing::subscriber::with_default(subscriber, || {
                // Before reload: both targets' `debug!` are below the `info` floor.
                tracing::debug!(target: "reload_raise_me", "pre-reload debug on raise target");
                tracing::debug!(target: "reload_leave_me", "pre-reload debug on other target");
                let pre = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
                assert!(
                    !pre.contains("pre-reload debug on raise target"),
                    "debug must be suppressed at the info default; captured: {pre:?}"
                );

                // Raise ONLY `reload_raise_me` to debug, keep the global floor at info.
                handle
                    .reload(EnvFilter::new("info,reload_raise_me=debug"))
                    .expect("reload must succeed while the subscriber is live");

                tracing::debug!(target: "reload_raise_me", "post-reload debug on raise target");
                tracing::debug!(target: "reload_leave_me", "post-reload debug on other target");

                let post = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
                assert!(
                    post.contains("post-reload debug on raise target"),
                    "the reloaded target's debug! must now emit; captured: {post:?}"
                );
                assert!(
                    !post.contains("post-reload debug on other target"),
                    "an unrelated target's debug! must stay suppressed; captured: {post:?}"
                );
            });
            // Outlive the closure so the `Weak` upgrade in `reload` stays valid.
            let _ = &handle;
        });
    }

    /// The type-erased [`LogReloadHandle`] that the binaries store must drive the
    /// same effect from a runtime trigger: with the layer seeded at `info`,
    /// setting `RUST_LOG=info,reload_via_env=debug` and calling
    /// `reload_from_env()` (what a `SIGHUP` handler does) makes that target's
    /// `debug!` start emitting — re-reading `RUST_LOG` through `env_filter_or`.
    #[test]
    fn erased_handle_reload_from_env_raises_target() {
        use std::io;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::prelude::*;

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

        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        unsafe { std::env::remove_var("RUST_LOG") };

        let buf = SharedBuf::default();
        let (reload_layer, handle) = reloadable_env_filter("info");
        let erased = LogReloadHandle::new("info", handle);
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()))
            .with(reload_layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "reload_via_env", "pre debug via env");
            assert!(
                !String::from_utf8(buf.0.lock().unwrap().clone())
                    .unwrap()
                    .contains("pre debug via env"),
                "debug suppressed at info default"
            );

            unsafe { std::env::set_var("RUST_LOG", "info,reload_via_env=debug") };
            erased.reload_from_env().expect("reload while subscriber live");

            tracing::debug!(target: "reload_via_env", "post debug via env");
        });

        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }

        assert!(
            captured.contains("post debug via env"),
            "reload_from_env must re-read RUST_LOG and enable the raised target; captured: {captured:?}"
        );
    }

    #[test]
    fn test_init_tracing_valid_config() {
        let config = TelemetryConfig::default();
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_custom_endpoint() {
        let config = TelemetryConfig {
            endpoint: "http://otel-collector:4318".to_string(),
            sample_rate: 0.5,
            network: "hoodi".to_string(),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_sample_rate_nan() {
        let config = TelemetryConfig { sample_rate: f64::NAN, ..Default::default() };
        let err = init_tracing(&config).err().expect("should fail");
        assert!(err.to_string().contains("sample_rate"));
    }

    #[test]
    fn test_init_tracing_sample_rate_negative() {
        let config = TelemetryConfig { sample_rate: -0.5, ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_sample_rate_too_high() {
        let config = TelemetryConfig { sample_rate: 2.0, ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_invalid_endpoint() {
        let config = TelemetryConfig { endpoint: "ftp://bad:21".to_string(), ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_endpoint_no_scheme() {
        let config =
            TelemetryConfig { endpoint: "localhost:4318".to_string(), ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_https_endpoint() {
        let config = TelemetryConfig {
            endpoint: "https://collector.example.com:4318".to_string(),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_zero_sample_rate() {
        let config = TelemetryConfig { sample_rate: 0.0, ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_build_provider_otlp() {
        let config = TelemetryConfig::default();
        let resource = Resource::builder().with_service_name("test").build();
        let sampler =
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));
        let result = build_provider(&config, resource, sampler);
        assert!(result.is_ok());
        result.unwrap().shutdown().ok();
    }

    #[test]
    fn test_init_tracing_with_service_version() {
        let config =
            TelemetryConfig { service_version: Some("0.99.0".to_string()), ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    /// TRC-1c / ADR-007: `service_name` resolves once and feeds both the
    /// resource `service.name` attribute and the tracer instrumentation name.
    #[test]
    fn test_init_tracing_service_name_applies_to_resource_and_tracer() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry::Key;

        let src = include_str!("init.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production section");
        assert_eq!(
            prod.matches("unwrap_or(SERVICE_NAME)").count(),
            1,
            "service_name must resolve once via unwrap_or(SERVICE_NAME)"
        );
        assert!(
            prod.contains(".with_service_name(service_name.clone())"),
            "resource must use the resolved service_name"
        );
        assert!(
            prod.contains("provider.tracer(service_name)"),
            "tracer must use the resolved service_name"
        );

        let cases: [(Option<&str>, &str); 2] = [(None, "rvc"), (Some("rvc-signer"), "rvc-signer")];

        for (configured, expected) in cases {
            let config = TelemetryConfig {
                service_name: configured.map(str::to_string),
                ..Default::default()
            };
            let resolved = config.service_name.as_deref().unwrap_or(SERVICE_NAME).to_string();
            assert_eq!(resolved, expected, "resolve None→rvc / Some→configured");

            // Resource attribute (same builder path as init_tracing).
            let resource = Resource::builder().with_service_name(resolved.clone()).build();
            let resource_name = resource
                .get(&Key::from_static_str("service.name"))
                .map(|v: opentelemetry::Value| v.as_str().into_owned());
            assert_eq!(
                resource_name.as_deref(),
                Some(expected),
                "resource service.name must be {expected}"
            );

            // Tracer instrumentation name (Debug exposes scope.name).
            let (_layer, guard) = init_tracing(&config).expect("init_tracing");
            let tracer = guard.provider.tracer(resolved);
            let tracer_debug = format!("{tracer:?}");
            assert!(
                tracer_debug.contains(expected),
                "tracer Debug must include service name {expected}: {tracer_debug}"
            );
            guard.provider.shutdown().ok();
        }
    }

    #[test]
    fn test_init_tracing_with_custom_batch_config() {
        let config = TelemetryConfig {
            max_queue_size: Some(4096),
            max_export_batch_size: Some(1024),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_with_partial_batch_config() {
        let config = TelemetryConfig { max_queue_size: Some(8192), ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_batch_size_one() {
        let config = TelemetryConfig {
            max_queue_size: Some(1),
            max_export_batch_size: Some(1),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_does_not_panic() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            ..Default::default()
        };
        match init_tracing(&config) {
            Ok((_layer, guard)) => {
                guard.provider.shutdown().ok();
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("GCP") || msg.contains("project") || msg.contains("gcloud"),
                    "GCP error should reference GCP/project: {msg}"
                );
            }
        }
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_respects_sample_rate_validation() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            sample_rate: f64::NAN,
            ..Default::default()
        };
        let err = init_tracing(&config).err().expect("NaN sample_rate should fail");
        assert!(err.to_string().contains("sample_rate"));
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_custom_network() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            sample_rate: 0.5,
            network: "hoodi".to_string(),
            ..Default::default()
        };
        match init_tracing(&config) {
            Ok((_layer, guard)) => {
                guard.provider.shutdown().ok();
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.contains("sample_rate"), "Should not fail on sample_rate: {msg}");
                assert!(!msg.contains("network"), "Should not fail on network: {msg}");
            }
        }
    }
}
