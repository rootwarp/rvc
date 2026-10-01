//! Logging init helpers for the `rvc` binary.

use rvc::config::Config;
use tracing::{error, info, warn};

/// Guards returned from init_logging that must be held for application lifetime.
pub struct LoggingGuards {
    _tracing_guard: Option<telemetry::TracingGuard>,
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    /// Type-erased handle to the runtime-reloadable log filter (issue 5.4). The
    /// opt-in `SIGHUP` trigger (gated behind `--enable-log-reload`) calls
    /// `reload_from_env()` to re-read `RUST_LOG` without a restart.
    pub reload_handle: telemetry::LogReloadHandle,
}

pub fn init_logging(
    level: &str,
    log_format: telemetry::LogFormat,
    tracing_config: Option<&telemetry::TelemetryConfig>,
    file_config: Option<&telemetry::FileAppenderConfig>,
) -> LoggingGuards {
    use tracing_subscriber::layer::Layer;
    use tracing_subscriber::prelude::*;

    // The reconciled filter is wrapped in a `reload::Layer` so verbosity can be
    // changed at runtime (issue 5.4). The layer's INITIAL value is exactly
    // `env_filter_or(level)` — identical to the bare filter this replaced — so
    // the Phase-3 init reconciliation (unset/empty/malformed RUST_LOG → `level`)
    // is unchanged. A disabled `debug!`/`trace!` callsite still short-circuits in
    // the macro before reaching this layer, so the disabled hot path stays
    // zero-allocation (Gate 4 / P0-6) whether or not the trigger is enabled.
    let (filter, reload_filter_handle) = telemetry::reloadable_env_filter(level);

    let (file_layer, file_guard): (
        Option<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>>,
        Option<tracing_appender::non_blocking::WorkerGuard>,
    ) = match file_config {
        Some(config) => match telemetry::create_file_layer(config) {
            Ok((layer, guard)) => {
                eprintln!("File logging enabled: {}/{}", config.directory, config.filename);
                (Some(layer), Some(guard))
            }
            Err(e) => {
                eprintln!("WARNING: Failed to initialize file logging: {e}");
                (None, None)
            }
        },
        None => (None, None),
    };

    // Collect all boxed layers to apply to Registry in a single .with() call.
    // This avoids type issues when mixing Box<dyn Layer<Registry>> with generic layers.
    let mut boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
        Vec::new();

    let tracing_guard = match tracing_config {
        Some(config) => {
            // Log resolved sample_rate before init so operators (and CLI e2e
            // tests) can confirm CLI/file/OTEL precedence even if exporter
            // construction fails (RF5-15 / F20 / RF6-20).
            eprintln!(
                "OpenTelemetry tracing config (endpoint: {}, sample_rate: {})",
                config.endpoint, config.sample_rate
            );
            match telemetry::init_tracing(config) {
                Ok((otel_layer, guard)) => {
                    boxed_layers.push(otel_layer);
                    eprintln!("OpenTelemetry tracing enabled (endpoint: {})", config.endpoint);
                    Some(guard)
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: Failed to initialize OpenTelemetry tracing: {e}. \
                         Falling back to fmt-only logging."
                    );
                    None
                }
            }
        }
        None => None,
    };

    if let Some(fl) = file_layer {
        boxed_layers.push(fl);
    }

    // tracing-subscriber 0.3 `Vec<L: Layer<S>>::register_callsite()` returns
    // `Interest::never()` when empty. As the outer layer in a `Layered` stack
    // that short-circuits every callsite via `Layered::pick_interest`, so no
    // events ever reach `fmt::layer` underneath. Pad with `Identity` (a no-op
    // that returns `Interest::always()`) when no optional layers are present.
    if boxed_layers.is_empty() {
        boxed_layers.push(Box::new(tracing_subscriber::layer::Identity::new()));
    }

    // The CONSOLE fmt layer is built for the selected format (issue 5.5): `pretty`
    // (default — byte-identical to the previous `fmt::layer()`) or `json`. Both
    // arms return one boxed `dyn Layer<Registry>`, so the surrounding composition —
    // the `boxed_layers` (OTLP/file, Identity-padded when empty) and the 5.4
    // reload-wrapped `filter` as the outer global layer — is unchanged either way.
    // The selector governs only this console leaf; the file appender keeps its own
    // format.
    let console_layer = telemetry::console_fmt_layer(log_format, std::io::stdout);

    tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter).init();

    // Erase the concrete reload handle (its subscriber type is the unspellable
    // layered stack above) so it can be stored and moved into the SIGHUP task.
    let reload_handle = telemetry::LogReloadHandle::new(level, reload_filter_handle);

    LoggingGuards { _tracing_guard: tracing_guard, _file_guard: file_guard, reload_handle }
}

/// Startup-only warn when the resolved head sample rate is below 1.0 (TRC-1a /
/// ADR-005 / CD-12).
///
/// Must run **after** [`init_logging`]: a `warn!` emitted while building the
/// tracing config (before the subscriber is installed) is silently dropped.
/// Call once per process start — never on a per-slot path.
pub fn warn_if_sample_rate_below_one(sample_rate: f64) {
    if sample_rate < 1.0 {
        if sample_rate == 0.0 {
            warn!(sample_rate, "tracing sample_rate is 0.0; exporter receives nothing");
        } else {
            warn!(sample_rate, "tracing sample_rate is below 1.0; most traces will be dropped");
        }
    }
}

/// Startup-only warn when the tracing endpoint uses `http://` to a real remote
/// host (TRC-1b / CD-12).
///
/// Must run **after** [`init_logging`]: a `warn!` emitted while building the
/// tracing config (before the subscriber is installed) is silently dropped.
/// Call once per process start — never on a per-slot path.
///
/// Skips localhost (`localhost` / `127.0.0.1` / `::1`) and Docker Compose
/// service names (hosts without a `.`, e.g. `jaeger`). Real remotes with a
/// dotted hostname still warn.
///
/// The logged `endpoint` field is [`redact_tracing_endpoint_for_log`] — never the
/// raw URL — so userinfo credentials cannot reach post-init sinks.
pub fn warn_if_insecure_remote_tracing_endpoint(endpoint: &str) {
    if should_warn_insecure_remote_http(endpoint) {
        warn!(
            endpoint = %redact_tracing_endpoint_for_log(endpoint),
            "tracing endpoint uses http:// with non-localhost host; consider using https://"
        );
    }
}

/// Log-safe view of an OTLP endpoint: `scheme://host:port` only.
///
/// Strips userinfo, path, query, and fragment so credentials never reach sinks.
/// Unparseable input is replaced (never echoed raw).
fn redact_tracing_endpoint_for_log(endpoint: &str) -> String {
    let Ok(mut url) = url::Url::parse(endpoint) else {
        return "<unparseable>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    url.to_string().trim_end_matches('/').to_string()
}

/// Append `/v1/traces` when the OTLP HTTP endpoint path is empty or `/` (TRC-1b).
///
/// Path-less collector URLs (e.g. Compose `http://jaeger:4318` /
/// `OTEL_EXPORTER_OTLP_ENDPOINT`) otherwise miss the OTLP HTTP traces route.
/// Already-pathful endpoints (`/v1/traces`, gateway prefixes like
/// `/otlp/v1/traces`) are left unchanged.
fn ensure_otlp_http_traces_path(endpoint: String) -> String {
    let Ok(mut url) = url::Url::parse(&endpoint) else {
        return endpoint;
    };
    let path = url.path();
    if path.is_empty() || path == "/" {
        url.set_path("/v1/traces");
        url.into()
    } else {
        endpoint
    }
}

/// Whether `endpoint` should emit the insecure-remote `http://` startup warn.
///
/// Returns `false` for non-`http://`, localhost, and dot-less Compose hosts.
fn should_warn_insecure_remote_http(endpoint: &str) -> bool {
    if !endpoint.starts_with("http://") {
        return false;
    }
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return false;
    }
    // Compose DNS names like `jaeger` have no `.` — treat as local stack.
    if !host.contains('.') {
        return false;
    }
    true
}

pub fn build_tracing_config(config: &Config) -> Option<telemetry::TelemetryConfig> {
    // OTEL env precedence lives on TracingConfig (RF5-15); the binary only maps.
    let endpoint = config.tracing.resolve_endpoint()?;
    let endpoint = ensure_otlp_http_traces_path(endpoint);
    let sample_rate = config.tracing.resolve_sample_rate();

    let exporter = match config.tracing.exporter {
        rvc::config::TracingExporter::Otlp => telemetry::ExporterKind::Otlp,
        #[cfg(feature = "gcp-trace")]
        rvc::config::TracingExporter::Gcp => telemetry::ExporterKind::Gcp,
        #[cfg(not(feature = "gcp-trace"))]
        rvc::config::TracingExporter::Gcp => {
            eprintln!(
                "ERROR: --tracing-exporter=gcp requires the `gcp-trace` feature. \
                 Rebuild with: cargo build --features gcp-trace"
            );
            return None;
        }
    };

    Some(telemetry::TelemetryConfig {
        endpoint,
        exporter,
        sample_rate,
        network: config.network.to_string(),
        service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        max_queue_size: config.tracing.max_queue_size,
        max_export_batch_size: config.tracing.max_export_batch_size,
    })
}

pub fn build_file_layer_config(config: &Config) -> Option<telemetry::FileAppenderConfig> {
    let logfile = config.logfile.path.as_ref()?;

    let directory = logfile
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let filename = logfile
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "rvc.log".to_string());

    let level = config.logfile.level.clone().unwrap_or_else(|| config.log_level.clone());

    Some(telemetry::FileAppenderConfig {
        directory,
        filename,
        max_size_mb: config.logfile.max_size,
        max_files: config.logfile.max_number,
        compress: config.logfile.compress,
        level,
    })
}

/// Spawn the opt-in `SIGHUP` log-reload handler (issue 5.4 / P2-2 / ARCH-2g P1-1).
///
/// No-op unless `enabled` (the `--enable-log-reload` opt-in). When enabled on a
/// Unix host, each `SIGHUP` re-reads `RUST_LOG` through the same
/// [`telemetry::env_filter_or`] precedence used at startup and swaps the active
/// filter, raising/lowering verbosity without a restart. The task is registered
/// on `executor` at Telemetry tier and exits when the process token is cancelled.
/// On non-Unix targets there is no `SIGHUP`; the flag is accepted but inert
/// (logged once).
pub fn spawn_log_reload_handler(
    enabled: bool,
    reload_handle: telemetry::LogReloadHandle,
    executor: &rvc::bootstrap::TaskExecutor,
) {
    if !enabled {
        return;
    }

    #[cfg(unix)]
    {
        use rvc::bootstrap::ShutdownTier;

        let shutdown_token = executor.token();
        executor.spawn("log_reload", ShutdownTier::Telemetry, async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "failed to install SIGHUP handler; log reload disabled");
                        return;
                    }
                };
            info!("Runtime log-level reload enabled (send SIGHUP to re-read RUST_LOG)");
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => break,
                    sig = sighup.recv() => {
                        if sig.is_none() {
                            // Signal stream closed; stop listening.
                            break;
                        }
                        match reload_handle.reload_from_env() {
                            Ok(()) => info!("Reloaded log filter from RUST_LOG (SIGHUP)"),
                            Err(e) => {
                                warn!(error = %e, "log-filter reload failed (subscriber gone?)")
                            }
                        }
                    }
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = (reload_handle, executor);
        warn!("--enable-log-reload set, but SIGHUP-based reload is only supported on Unix");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvc::config::TracingConfig;
    use std::io;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

    use clap::Parser;
    use rvc::config::StartArgs;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::cli::Cli;

    /// Serialize all tests in this module that read or write OTEL env vars.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Shared capture writer for subscriber composition tests (defined once).
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

    #[test]
    fn test_build_tracing_config_no_endpoint_returns_none() {
        let _guard = env_lock();
        // Clear env vars that could interfere
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default();
        assert!(build_tracing_config(&config).is_none());
    }

    #[test]
    fn test_ensure_otlp_http_traces_path_table() {
        let cases = [
            ("http://jaeger:4318", "http://jaeger:4318/v1/traces"),
            ("http://jaeger:4318/", "http://jaeger:4318/v1/traces"),
            ("http://jaeger:4318/v1/traces", "http://jaeger:4318/v1/traces"),
            ("http://gateway:4318/otlp/v1/traces", "http://gateway:4318/otlp/v1/traces"),
            ("http://localhost:4318", "http://localhost:4318/v1/traces"),
            ("https://collector.example.com:4318", "https://collector.example.com:4318/v1/traces"),
        ];
        for (input, expected) in cases {
            assert_eq!(ensure_otlp_http_traces_path(input.to_string()), expected, "input={input}");
        }
    }

    #[test]
    fn test_should_warn_insecure_remote_http_table() {
        let cases = [
            ("http://jaeger:4318", false),
            ("http://jaeger:4318/v1/traces", false),
            ("http://otel-collector:4318", false),
            ("http://localhost:4318", false),
            ("http://localhost:4318/v1/traces", false),
            ("http://127.0.0.1:4318", false),
            ("http://[::1]:4318", false),
            ("https://collector.example.com:4318", false),
            ("http://collector.example.com:4318", true),
            ("http://collector.example.com:4318/v1/traces", true),
            ("http://192.168.1.10:4318", true),
            ("http://user:s3cret@collector.example.com:4318/v1/traces", true),
        ];
        for (input, expected) in cases {
            assert_eq!(should_warn_insecure_remote_http(input), expected, "input={input}");
        }
    }

    #[test]
    fn test_redact_tracing_endpoint_for_log_strips_userinfo_and_path() {
        let cases = [
            (
                "http://user:s3cret@collector.example.com:4318/v1/traces",
                "http://collector.example.com:4318",
            ),
            ("http://user@collector.example.com:4318", "http://collector.example.com:4318"),
            ("http://collector.example.com:4318/v1/traces", "http://collector.example.com:4318"),
            ("http://127.0.0.1:4318", "http://127.0.0.1:4318"),
            ("not a url", "<unparseable>"),
        ];
        for (input, expected) in cases {
            let redacted = redact_tracing_endpoint_for_log(input);
            assert_eq!(redacted, expected, "input={input}");
            assert!(!redacted.contains("s3cret"), "must not leak password: {redacted}");
            assert!(!redacted.contains("user:"), "must not leak userinfo: {redacted}");
        }
    }

    /// Warn path must log the redacted form — capture proves userinfo never reaches the sink.
    #[test]
    fn test_warn_if_insecure_remote_tracing_endpoint_redacts_userinfo() {
        use tracing_subscriber::prelude::*;

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("warn");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()).with_ansi(false))
            .with(filter);

        tracing::subscriber::with_default(subscriber, || {
            warn_if_insecure_remote_tracing_endpoint(
                "http://user:s3cret@collector.example.com:4318/v1/traces",
            );
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("tracing endpoint uses http:// with non-localhost host"),
            "warn must fire for dotted remote.\n--- captured ---\n{out}"
        );
        assert!(
            out.contains("collector.example.com:4318"),
            "redacted host:port must appear.\n--- captured ---\n{out}"
        );
        assert!(!out.contains("s3cret"), "password must not reach sink.\n--- captured ---\n{out}");
        assert!(!out.contains("user:"), "userinfo must not reach sink.\n--- captured ---\n{out}");
        assert!(!out.contains("/v1/traces"), "path must be stripped.\n--- captured ---\n{out}");
    }

    #[test]
    fn test_build_tracing_config_with_endpoint_returns_some() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.endpoint, "http://localhost:4318/v1/traces");
        assert_eq!(tc.exporter, telemetry::ExporterKind::Otlp);
        assert!((tc.sample_rate - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_pathful_endpoint_unchanged() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://gateway:4318/otlp/v1/traces".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.endpoint, "http://gateway:4318/otlp/v1/traces");
    }

    #[test]
    fn test_build_tracing_config_jaeger_compose_appends_traces_path() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://jaeger:4318".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.endpoint, "http://jaeger:4318/v1/traces");
        assert!(!should_warn_insecure_remote_http(&tc.endpoint));
    }

    #[test]
    fn test_build_tracing_config_env_var_fallback() {
        let _guard = env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default(); // no tracing_endpoint set
        let tc = build_tracing_config(&config).expect("should fall back to env var");
        assert_eq!(tc.endpoint, "http://env-collector:4318/v1/traces");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_build_tracing_config_cli_overrides_env() {
        let _guard = env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://cli-collector:4318".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should use config value");
        assert_eq!(tc.endpoint, "http://cli-collector:4318/v1/traces");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_build_tracing_config_sample_rate_env_fallback() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                // sample_rate unset → env applies
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 0.5).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_build_tracing_config_explicit_sample_rate_overrides_env() {
        let _guard = env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                sample_rate: Some(0.75),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 0.75).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_build_tracing_config_explicit_default_sample_rate_survives_env() {
        let _guard = env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");

        // F20: explicit 0.01 must not be treated as "unset".
        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                sample_rate: Some(0.01),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 0.01).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_build_tracing_config_sample_rate_clamped() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                sample_rate: Some(2.0),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_negative_sample_rate_clamped() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                sample_rate: Some(-0.5),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!(tc.sample_rate.abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_network_propagated() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                ..Default::default()
            },
            network: rvc::config::Network::Hoodi,
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.network, "hoodi");
    }

    #[test]
    fn test_build_tracing_config_otlp_exporter() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                exporter: rvc::config::TracingExporter::Otlp,
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.exporter, telemetry::ExporterKind::Otlp);
    }

    #[test]
    fn test_build_tracing_config_batch_fields_passthrough() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                max_queue_size: Some(4096),
                max_export_batch_size: Some(1024),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.max_queue_size, Some(4096));
        assert_eq!(tc.max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_build_tracing_config_batch_fields_none_by_default() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!(tc.max_queue_size.is_none());
        assert!(tc.max_export_batch_size.is_none());
    }

    // H-07: binary-local mapping — `build_tracing_config` produces a config
    // that `telemetry::init_tracing` accepts. Pure `init_tracing` behaviour
    // lives in `crates/telemetry` (RF6-19).

    #[test]
    fn test_build_tracing_config_creates_valid_telemetry_config() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing: TracingConfig {
                endpoint: Some("http://localhost:4318".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");

        // The config should be valid for init_tracing
        let result = telemetry::init_tracing(&tc);
        assert!(result.is_ok(), "init_tracing should succeed with valid config");
        let (_layer, guard) = result.unwrap();
        // Clean up the provider
        drop(guard);
    }

    #[test]
    fn test_grpc_signer_cli_flags_parse_all() {
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--grpc-signer-url",
            "https://signer.example.com:50051",
            "--grpc-signer-tls-cert",
            "/tmp/cert.pem",
            "--grpc-signer-tls-key",
            "/tmp/key.pem",
            "--grpc-signer-tls-ca-cert",
            "/tmp/ca.pem",
        ])
        .expect("should parse");

        match cli.command {
            crate::cli::Commands::Start(args) => {
                assert_eq!(
                    args.grpc_signer.url.as_deref(),
                    Some("https://signer.example.com:50051")
                );
                assert_eq!(args.grpc_signer.tls_cert, Some(PathBuf::from("/tmp/cert.pem")));
                assert_eq!(args.grpc_signer.tls_key, Some(PathBuf::from("/tmp/key.pem")));
                assert_eq!(args.grpc_signer.tls_ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_grpc_signer_cli_flags_optional() {
        let cli = Cli::try_parse_from(["rvc", "start"]).expect("should parse without grpc flags");

        match cli.command {
            crate::cli::Commands::Start(args) => {
                assert!(args.grpc_signer.url.is_none());
                assert!(args.grpc_signer.tls_cert.is_none());
                assert!(args.grpc_signer.tls_key.is_none());
                assert!(args.grpc_signer.tls_ca_cert.is_none());
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_grpc_signer_config_defaults_none() {
        let config = Config::default();
        assert!(config.grpc_signer.url.is_none());
        assert!(config.grpc_signer.tls_cert.is_none());
        assert!(config.grpc_signer.tls_key.is_none());
        assert!(config.grpc_signer.tls_ca_cert.is_none());
    }

    #[test]
    fn test_grpc_signer_config_merge_with_cli() {
        let mut args = StartArgs::default();
        args.grpc_signer.url = Some("https://signer:50051".to_string());
        args.grpc_signer.tls_cert = Some(PathBuf::from("/cert.pem"));
        args.grpc_signer.tls_key = Some(PathBuf::from("/key.pem"));
        args.grpc_signer.tls_ca_cert = Some(PathBuf::from("/ca.pem"));
        let config = Config::load(None, args).expect("load");

        assert_eq!(config.grpc_signer.url.as_deref(), Some("https://signer:50051"));
        assert_eq!(config.grpc_signer.tls_cert, Some(PathBuf::from("/cert.pem")));
        assert_eq!(config.grpc_signer.tls_key, Some(PathBuf::from("/key.pem")));
        assert_eq!(config.grpc_signer.tls_ca_cert, Some(PathBuf::from("/ca.pem")));
    }

    #[test]
    fn test_grpc_signer_config_merge_preserves_none() {
        let config = Config::load(None, StartArgs::default()).expect("load");

        assert!(config.grpc_signer.url.is_none());
        assert!(config.grpc_signer.tls_cert.is_none());
    }

    // ── SEC-9 / M-15: allow_unsupported_fork CLI merge ────────────────────

    #[test]
    fn test_allow_unsupported_fork_cli_merge() {
        let config = Config::default();
        assert!(!config.allow_unsupported_fork);

        let mut args = StartArgs::default();
        args.safety.allow_unsupported_fork = true;
        let config = Config::load(None, args).expect("load");
        assert!(config.allow_unsupported_fork);
    }

    #[test]
    fn test_secret_provider_strict_cli_merge() {
        let config = Config::default();
        assert!(!config.secret_provider.strict);

        let mut args = StartArgs::default();
        args.keys.secret_provider.strict = Some(true);
        let config = Config::load(None, args).expect("load");
        assert!(config.secret_provider.strict);
    }

    /// Regression guard for the v0.4.0 logging silence bug.
    ///
    /// `Vec<L: Layer<S>>::register_callsite()` returns `Interest::never()`
    /// for an empty Vec (tracing-subscriber 0.3 `layer/mod.rs:1788`). When
    /// that empty Vec is the outer layer in a `Layered` stack, the
    /// short-circuit in `Layered::pick_interest` disables every callsite,
    /// so no events ever reach `fmt::layer` underneath.
    ///
    /// This test mirrors `init_logging`'s subscriber composition for the
    /// no-extras case (no `--tracing-endpoint`, no `--logfile`) and asserts
    /// that a basic `info!` event reaches the writer.
    #[test]
    fn test_init_logging_no_extras_emits_events() {
        use tracing_subscriber::layer::Layer;
        use tracing_subscriber::prelude::*;

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("info");

        // Match the exact shape `init_logging` builds when both
        // `tracing_config` and `file_config` are None: a Vec that would have
        // been empty, padded with `Identity` to avoid the never-Interest poison.
        let boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
            vec![Box::new(tracing_subscriber::layer::Identity::new())];

        let subscriber = tracing_subscriber::registry()
            .with(boxed_layers)
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()))
            .with(filter);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("init_logging regression marker");
        });

        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("init_logging regression marker"),
            "init_logging composition silently drops events; captured: {captured:?}"
        );
    }

    // ── Issue 5.5: opt-in JSON console log output profile ─────────────────────

    /// `--log-format json` parses on `start` and resolves to `LogFormat::Json`;
    /// the default (flag omitted) stays `Pretty` — the constraint that an unset
    /// selector keeps today's behavior.
    #[test]
    fn test_log_format_flag_parses_and_defaults_to_pretty() {
        let cli = Cli::try_parse_from(["rvc", "start", "--log-format", "json"])
            .expect("--log-format json should parse");
        match cli.command {
            crate::cli::Commands::Start(args) => {
                assert_eq!(
                    telemetry::LogFormat::resolve(Some(&args.logging.log_format)),
                    telemetry::LogFormat::Json
                );
            }
            _ => panic!("expected Start command"),
        }

        let cli = Cli::try_parse_from(["rvc", "start"]).expect("default should parse");
        match cli.command {
            crate::cli::Commands::Start(args) => {
                assert_eq!(
                    args.logging.log_format, "pretty",
                    "default --log-format must be pretty"
                );
                assert_eq!(
                    telemetry::LogFormat::resolve(Some(&args.logging.log_format)),
                    telemetry::LogFormat::Pretty
                );
            }
            _ => panic!("expected Start command"),
        }
    }

    /// The JSON arm of `init_logging`'s composition — `Identity`-padded
    /// `boxed_layers` + `console_fmt_layer(Json, …)` + the reconciled filter —
    /// emits one parseable JSON object per event with canonical fields as
    /// top-level keys. Mirrors `init_logging`'s shape exactly so this guards the
    /// shipped JSON path (not just the telemetry helper in isolation).
    #[test]
    fn test_init_logging_json_arm_emits_parseable_json() {
        use tracing_subscriber::layer::Layer;
        use tracing_subscriber::prelude::*;

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("info");
        // Same Identity-padded `boxed_layers` as the no-extras `init_logging` path.
        let boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
            vec![Box::new(tracing_subscriber::layer::Identity::new())];
        let console_layer = telemetry::console_fmt_layer(telemetry::LogFormat::Json, buf.clone());

        let subscriber =
            tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(slot = 42u64, "json arm marker");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = out.lines().find(|l| l.contains("json arm marker")).expect("event present");
        let v: serde_json::Value =
            serde_json::from_str(line).expect("JSON arm must emit parseable JSON");
        assert_eq!(v["slot"], 42, "canonical field must be a top-level JSON key");
        assert_eq!(v["message"], "json arm marker");
    }
}
