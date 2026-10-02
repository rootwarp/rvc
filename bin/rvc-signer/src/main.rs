//! rvc-signer binary entry point.
//!
//! Thin CLI shim: parse args, init logging, call [`signer_server::server::run`].
//! Server assembly lives in the `signer_server` crate.

use signer_server::config::ServeArgs;
use signer_server::{config, server, ServerError};

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "rvc-signer")]
#[command(version)]
#[command(about = "Remote BLS signer for rvc validator client", long_about = None)]
struct Cli {
    /// OTLP HTTP endpoint (for example `http://jaeger:4318`). Enables tracing when set.
    ///
    /// Explicit flag wins over `OTEL_EXPORTER_OTLP_ENDPOINT`. A path-less URL gets
    /// `/v1/traces` appended.
    #[arg(long, global = true)]
    tracing_endpoint: Option<String>,

    /// Head-based sample rate in `0.0..=1.0`.
    ///
    /// Explicit flag wins over `OTEL_TRACES_SAMPLER_ARG`, which wins over the
    /// built-in default `0.01`. A resolved rate below `1.0` warns at startup.
    #[arg(long, global = true)]
    tracing_sample_rate: Option<f64>,

    /// OpenTelemetry `service.name`. Unset defaults to `rvc-signer`.
    #[arg(long, global = true)]
    tracing_service_name: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// `Serve` carries the full server-config arg set and is necessarily larger than
// `SplitKey`. This enum is parsed exactly once at startup and immediately
// matched/consumed, so the variant-size disparity costs nothing — boxing the
// variant is not an option because clap's `Subcommand` derive requires the field
// to implement `Args`, which `Box<ServeArgs>` does not.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Start the gRPC signing server
    Serve(ServeArgs),

    /// Split a BLS secret key into Shamir shares stored as EIP-2335 keystores
    #[cfg(feature = "dvt")]
    SplitKey(SplitKeyCliArgs),
}

#[cfg(feature = "dvt")]
#[derive(Parser)]
struct SplitKeyCliArgs {
    /// Path to the source EIP-2335 keystore
    #[arg(long)]
    keystore: std::path::PathBuf,

    /// Password for the source keystore
    #[arg(long, group = "src_password")]
    password: Option<String>,

    /// Path to a file containing the source keystore password
    #[arg(long, group = "src_password")]
    password_file: Option<std::path::PathBuf>,

    /// Threshold (t) for Shamir secret sharing
    #[arg(long)]
    threshold: u64,

    /// Total number of shares (n) to generate
    #[arg(long)]
    shares: u64,

    /// Output directory for share keystores
    #[arg(long)]
    output_dir: std::path::PathBuf,

    /// Password for the output share keystores
    #[arg(long, group = "out_password")]
    output_password: Option<String>,

    /// Path to a file containing the password for output share keystores
    #[arg(long, group = "out_password")]
    output_password_file: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() {
    // Logging output is console-only (stdout/stderr); operators collect rvc-signer
    // logs from the process's standard streams. Unlike `bin/rvc`, rvc-signer does
    // NOT wire the telemetry file appender, so there is no independent file level:
    // file == console (ADR-004 "file more verbose than console" does not apply here).
    //
    // Phase-3 issue 3.5 spike conclusion: the appender itself *is* capable of an
    // independent file level — `telemetry::create_file_layer` filters each file
    // layer with its own `EnvFilter::new(config.level)` (see
    // `crates/telemetry/src/file_appender.rs`), exactly as `bin/rvc` uses it.
    // Delivering it for rvc-signer would require a new `--logfile`/`logfile_level`
    // CLI + `ResolvedConfig` surface (it has none today); per 3.5's bounded scope
    // it is deferred as a documented fallback rather than a rushed file path in a
    // security-sensitive signer; the console-only status is stated in the Phase-5
    // OPERATOR_GUIDE.
    // Parse the CLI BEFORE initializing logging so the `Serve` subcommand's
    // `--log-format` flag can select the console format (issue 5.5). Nothing logs
    // between parse and init, so the Phase-3 init parity (the reconciled filter is
    // still the first subscriber installed) is preserved. One-shot subcommands
    // without the flag (e.g. `split-key`) resolve the format from `RVC_LOG_FORMAT`
    // env only (default pretty) via `resolve(None)`.
    let cli = Cli::parse();

    let log_format = match &cli.command {
        Command::Serve(args) => telemetry::LogFormat::resolve(args.log_format.as_deref()),
        #[cfg(feature = "dvt")]
        Command::SplitKey(_) => telemetry::LogFormat::resolve(None),
    };

    // Flag → `OTEL_*` env → default (ADR-006 duplicate of `TracingConfig::resolve_*`).
    // The guard is a named binding (not `_`) held until `shutdown_tracing_guard`.
    // Drop does not flush: `TracingGuard` has no `Drop` shutdown, and the OTel
    // layer keeps its own provider clone.
    let tracing_config = build_signer_tracing_config(&SignerTracingFlags::from_cli(&cli));
    // Sample-rate warn is after subscriber init (TRC-1a / CD-12). A `warn!`
    // emitted while resolving, before `init_logging`, would be dropped.
    let sample_rate = tracing_config.as_ref().map(|config| config.sample_rate);
    let (reload_handle, mut tracing_guard) = init_logging(log_format, tracing_config);
    if let Some(sample_rate) = sample_rate {
        warn_if_sample_rate_below_one(sample_rate);
    }

    match cli.command {
        Command::Serve(args) => {
            let enable_log_reload = args.enable_log_reload;
            let resolved = match config::resolve_config(&args) {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "rvc-signer failed");
                    // `process::exit` skips the final await. Drop would not
                    // flush either — shut the processor down explicitly.
                    shutdown_tracing_guard(tracing_guard.take()).await;
                    std::process::exit(1);
                }
            };

            // Runtime log-level reload (issue 5.4): owned by main because the
            // reload handle is created by `init_logging`. Cancelled after serve.
            let log_reload_shutdown = CancellationToken::new();
            spawn_log_reload_handler(enable_log_reload, reload_handle, log_reload_shutdown.clone());

            let shutdown = CancellationToken::new();
            let shutdown_for_signal = shutdown.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_for_signal.cancel();
            });

            let result = server::run(resolved, shutdown).await;
            log_reload_shutdown.cancel();

            if let Err(e) = result {
                error!(error = %e, "rvc-signer failed");
                // Exit code unchanged: every ServerError class maps to 1.
                let _ = classify_exit_code(&e);
                shutdown_tracing_guard(tracing_guard.take()).await;
                std::process::exit(1);
            }

            info!("Shutting down rvc-signer");
        }
        #[cfg(feature = "dvt")]
        Command::SplitKey(args) => {
            if let Err(e) = run_split_key(args) {
                error!(error = %e, "split-key failed");
                shutdown_tracing_guard(tracing_guard.take()).await;
                std::process::exit(1);
            }
        }
    }

    // After the subcommand returns. `None` is a no-op; `Some` awaits
    // `telemetry::shutdown_tracing` so BatchSpanProcessor flushes.
    shutdown_tracing_guard(tracing_guard).await;
}

/// Flush and stop the OTel pipeline, if `init_logging` returned a guard.
///
/// [`telemetry::TracingGuard`] has no `Drop` impl that calls `shutdown`. The
/// subscriber's OpenTelemetry layer retains its own provider clone, so
/// dropping the guard leaves `BatchSpanProcessor`'s worker running and drops
/// queued spans on the floor. Every completion path and every `process::exit`
/// path must await this instead.
async fn shutdown_tracing_guard(guard: Option<telemetry::TracingGuard>) {
    if let Some(guard) = guard {
        telemetry::shutdown_tracing(guard).await;
    }
}

/// Built-in head-based sample rate when neither the flag nor
/// `OTEL_TRACES_SAMPLER_ARG` sets one (ADR-005 / TRC-1a).
///
/// Same value as `rvc_config::DEFAULT_TRACING_SAMPLE_RATE`. The parity test
/// locks the two together.
const DEFAULT_TRACING_SAMPLE_RATE: f64 = 0.01;

/// Default OTel `service.name` for this process (TRC-2h / ADR-007).
///
/// Distinct from the validator client's `rvc` so a shared collector lists two
/// services. Overridden by `--tracing-service-name`. Not read from
/// `OTEL_SERVICE_NAME` (G-3 does not allow-list that variable).
const DEFAULT_SIGNER_SERVICE_NAME: &str = "rvc-signer";

fn default_tracing_sample_rate() -> f64 {
    DEFAULT_TRACING_SAMPLE_RATE
}

/// Signer-local tracing inputs (ADR-006).
///
/// Deliberate duplicate of the sibling resolver, not a shared helper.
/// Sibling: `TracingConfig::resolve_endpoint` / `resolve_sample_rate`, cited by
/// #417 at `crates/rvc/src/config/types.rs:437-458`. Those methods now live in
/// `crates/rvc-config/src/sections/tracing.rs` (re-exported through `rvc::config`).
/// `test_signer_tracing_flag_env_default_parity_table` is the lock that keeps
/// this copy equal to `rvc_config::TracingConfig::resolve_*`.
///
/// Precedence is explicit flag → `OTEL_*` env → built-in default. The env names
/// are string literals so G-3 classifies them as ecosystem config-else-env reads.
///
/// `service_name` is explicit flag → `None`. G-3 allow-lists only
/// `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_TRACES_SAMPLER_ARG`, and the sibling
/// stores `service_name` as the explicit value with no env read. The signer
/// default `"rvc-signer"` is applied in [`build_signer_tracing_config`]
/// (TRC-2h / #418), not here, so an omitted flag does not fall through to
/// telemetry's `"rvc"` name.
struct SignerTracingFlags {
    endpoint: Option<String>,
    sample_rate: Option<f64>,
    service_name: Option<String>,
}

impl SignerTracingFlags {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            endpoint: cli.tracing_endpoint.clone(),
            sample_rate: cli.tracing_sample_rate,
            service_name: cli.tracing_service_name.clone(),
        }
    }

    /// Resolve the OTLP endpoint: explicit flag > `OTEL_EXPORTER_OTLP_ENDPOINT`.
    ///
    /// Returns `None` when neither source provides a value (tracing stays disabled).
    /// Does not append `/v1/traces`; [`ensure_otlp_http_traces_path`] does that,
    /// matching `bin/rvc`'s split between `resolve_endpoint` and path rewrite.
    fn resolve_endpoint(&self) -> Option<String> {
        self.endpoint.clone().or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
    }

    /// Resolve the sample rate: explicit flag > `OTEL_TRACES_SAMPLER_ARG` >
    /// [`DEFAULT_TRACING_SAMPLE_RATE`].
    ///
    /// Values outside `0.0..=1.0` are clamped with a warning.
    fn resolve_sample_rate(&self) -> f64 {
        let mut rate = match self.sample_rate {
            Some(rate) => rate,
            None => match std::env::var("OTEL_TRACES_SAMPLER_ARG") {
                Ok(env_rate) => {
                    env_rate.parse::<f64>().unwrap_or_else(|_| default_tracing_sample_rate())
                }
                Err(_) => default_tracing_sample_rate(),
            },
        };

        if !(0.0..=1.0).contains(&rate) {
            warn!(sample_rate = rate, "tracing_sample_rate out of range 0.0..=1.0, clamping");
            rate = rate.clamp(0.0, 1.0);
        }
        rate
    }

    /// Explicit `--tracing-service-name`, or `None` when the flag was omitted.
    fn resolve_service_name(&self) -> Option<String> {
        self.service_name.clone()
    }
}

/// Append `/v1/traces` when the OTLP HTTP endpoint path is empty or `/` (TRC-1b).
///
/// Path-less collector URLs (for example Compose `http://jaeger:4318` /
/// `OTEL_EXPORTER_OTLP_ENDPOINT`) otherwise miss the OTLP HTTP traces route.
/// Already-pathful endpoints (`/v1/traces`, gateway prefixes like
/// `/otlp/v1/traces`) are left unchanged. Structural parallel of
/// `bin/rvc`'s `ensure_otlp_http_traces_path`.
fn ensure_otlp_http_traces_path(endpoint: String) -> String {
    let Ok(mut url) = url::Url::parse(&endpoint) else {
        return endpoint;
    };
    let path = url.path();
    if path.is_empty() || path == "/" {
        url.set_path("/v1/traces");
        url.into()
    } else {
        // Pathful input is the exporter URL and is returned unchanged, userinfo
        // included. Print it only through `redact_endpoint_userinfo_for_log`.
        endpoint
    }
}

/// Map resolved flags into the telemetry config `init_logging` consumes.
///
/// `None` when no endpoint is configured (tracing stays off), same as
/// `bin/rvc`'s `build_tracing_config`.
fn build_signer_tracing_config(flags: &SignerTracingFlags) -> Option<telemetry::TelemetryConfig> {
    let endpoint = flags.resolve_endpoint()?;
    let endpoint = ensure_otlp_http_traces_path(endpoint);
    let sample_rate = flags.resolve_sample_rate();
    Some(telemetry::TelemetryConfig {
        endpoint,
        sample_rate,
        service_name: flags
            .resolve_service_name()
            .or_else(|| Some(DEFAULT_SIGNER_SERVICE_NAME.to_string())),
        service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        ..Default::default()
    })
}

/// Startup-only warn when the resolved head sample rate is below 1.0 (TRC-1a).
///
/// Must run **after** [`init_logging`]: a `warn!` emitted while building the
/// tracing config (before the subscriber is installed) is silently dropped.
/// Call once per process start. `1.0` is silent; `0.0` names that the exporter
/// receives nothing. Structural parallel of `bin/rvc`'s
/// `warn_if_sample_rate_below_one`.
fn warn_if_sample_rate_below_one(sample_rate: f64) {
    if sample_rate < 1.0 {
        if sample_rate == 0.0 {
            warn!(sample_rate, "tracing sample_rate is 0.0; exporter receives nothing");
        } else {
            warn!(sample_rate, "tracing sample_rate is below 1.0; most traces will be dropped");
        }
    }
}

/// Log-only view of an OTLP endpoint.
///
/// Parses a separate [`url::Url`], clears the entire username and password
/// (the parser's userinfo, which ends at the last `@` in the authority), then
/// serializes. Scheme, host, port, path, query, and fragment stay, so
/// `/v1/traces` remains visible. This value is never written back to
/// [`telemetry::TelemetryConfig::endpoint`].
///
/// Input [`url::Url::parse`] rejects, and that still contains `@`, becomes the
/// literal `<unparseable>` — the raw string is not echoed.
fn redact_endpoint_userinfo_for_log(endpoint: &str) -> String {
    let Ok(mut url) = url::Url::parse(endpoint) else {
        return unparseable_or_raw(endpoint);
    };
    // OTLP endpoints are http(s). Any other scheme that still carries `@`
    // (`user:s3cret@host` parses as scheme `user`) is not a loggable URL.
    if url.scheme() != "http" && url.scheme() != "https" {
        return unparseable_or_raw(endpoint);
    }
    if url.username().is_empty() && url.password().is_none() {
        // No authority userinfo. Keep the caller's string so a path `@` and
        // other credential-free forms are not rewritten.
        return endpoint.to_string();
    }
    // Drop password before username. An empty username removes userinfo.
    let _ = url.set_password(None);
    if url.set_username("").is_err() {
        return "<unparseable>".to_string();
    }
    url.into()
}

/// `<unparseable>` when `raw` might still hold userinfo; otherwise `raw`.
fn unparseable_or_raw(raw: &str) -> String {
    if raw.contains('@') {
        "<unparseable>".to_string()
    } else {
        raw.to_string()
    }
}

/// Initialize the console-only tracing subscriber.
///
/// Returns the type-erased runtime-reloadable log-filter handle (issue 5.4 /
/// P2-2) and, when `tracing_config` is `Some` and [`telemetry::init_tracing`]
/// succeeds, the [`telemetry::TracingGuard`] `main` holds for process lifetime.
/// Flush is **not** `Drop`: `main` must await [`shutdown_tracing_guard`], which
/// calls [`telemetry::shutdown_tracing`], or `BatchSpanProcessor` never shuts
/// down (the OTel layer keeps the provider alive).
///
/// The reconciled `EnvFilter` (unset/empty/malformed `RUST_LOG` → `info`, env
/// otherwise wins — ADR-003) is wrapped in a `reload::Layer` so its value can be
/// swapped at runtime. The **initial value is exactly `env_filter_or("info")`**,
/// so a `None` tracing config produces byte-for-byte identical *user-visible*
/// output to the previous bare console filter — the Phase-3 cross-binary init
/// parity is preserved. No OpenTelemetry layer and no [`telemetry::TraceIdLayer`]
/// are installed on that path, so lines carry no `trace_id` and no zeroed ids.
///
/// Subscriber shape, matching `bin/rvc`:
/// `registry().with(boxed_layers).with(console_layer).with(filter).init()`.
/// On the success arm the OTel layer and `TraceIdLayer` are pushed adjacently
/// into `boxed_layers` (OTel, then `TraceIdLayer`) before the console layer.
/// An empty `boxed_layers` is padded with
/// [`Identity`](tracing_subscriber::layer::Identity) so the empty-`Vec`
/// `Interest::never()` short-circuit cannot silence the console.
///
/// `log_format` selects the CONSOLE rendering (issue 5.5): `Pretty` (default)
/// or `Json`. The reload-wrapped filter stays the outer global layer either way.
/// A disabled `debug!`/`trace!` callsite short-circuits in the macro before
/// reaching it (Gate 4 / P0-6 unaffected). The opt-in `SIGHUP` trigger (gated by
/// `--enable-log-reload`) is wired from `main` after `init_logging`.
///
/// rvc-signer does not wire the telemetry file appender (console-only). Soft P2
/// residuals stay deferred: negative-cache, `OnceLock` priming
/// (`TraceIdLayer::register_dispatch` after `.init()` — `Vec` does not forward
/// `on_register_dispatch`; the global default falls back to
/// `dispatcher::get_default`), and Format heuristics.
fn init_logging(
    log_format: telemetry::LogFormat,
    tracing_config: Option<telemetry::TelemetryConfig>,
) -> (telemetry::LogReloadHandle, Option<telemetry::TracingGuard>) {
    use tracing_subscriber::layer::Layer;
    use tracing_subscriber::prelude::*;

    let (filter, handle) = telemetry::reloadable_env_filter("info");

    // Collect boxed layers for a single `.with()` on the registry. Mixing
    // `Box<dyn Layer<Registry>>` with generic layers in separate `.with()` calls
    // does not type-check; `bin/rvc` uses the same vector.
    let mut boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
        Vec::new();

    let tracing_guard = match tracing_config.as_ref() {
        Some(config) => {
            // Log resolved sample_rate before init so operators can confirm the
            // config even if exporter construction fails (same as bin/rvc).
            eprintln!(
                "OpenTelemetry tracing config (endpoint: {}, sample_rate: {})",
                redact_endpoint_userinfo_for_log(&config.endpoint),
                config.sample_rate
            );
            match telemetry::init_tracing(config) {
                Ok((otel_layer, guard)) => {
                    boxed_layers.push(otel_layer);
                    // Ordering (T5): OpenTelemetryLayer then TraceIdLayer, both
                    // inside boxed_layers and before console_layer.
                    // `Layered::on_event` runs inner before the outer layer, so
                    // TraceIdLayer must sit here to cache ids before the console
                    // formatter reads them. Do not reorder these two pushes.
                    //
                    // Soft P2 deferred: bin/rvc clones TraceIdLayer and primes
                    // `register_dispatch` after `.init()`. Not done here.
                    let trace_id_layer = telemetry::TraceIdLayer::new();
                    boxed_layers.push(Box::new(trace_id_layer));
                    eprintln!(
                        "OpenTelemetry tracing enabled (endpoint: {})",
                        redact_endpoint_userinfo_for_log(&config.endpoint)
                    );
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

    // tracing-subscriber 0.3 `Vec<L: Layer<S>>::register_callsite()` returns
    // `Interest::never()` when empty. As the outer layer in a `Layered` stack
    // that short-circuits every callsite via `Layered::pick_interest`, so no
    // events ever reach the console layer underneath. Pad with `Identity` (a
    // no-op that returns `Interest::always()`) when no optional layers are
    // present. Mirrors `bin/rvc`.
    if boxed_layers.is_empty() {
        boxed_layers.push(Box::new(tracing_subscriber::layer::Identity::new()));
    }

    let console_layer = telemetry::console_fmt_layer(log_format, std::io::stdout);

    tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter).init();

    let reload_handle = telemetry::LogReloadHandle::new("info", handle);
    (reload_handle, tracing_guard)
}

/// Spawn the opt-in `SIGHUP` log-reload handler (issue 5.4 / P2-2).
///
/// No-op unless `enabled` (the `--enable-log-reload` opt-in). When enabled on a
/// Unix host, each `SIGHUP` re-reads `RUST_LOG` through the same
/// [`telemetry::env_filter_or`] precedence used at startup and swaps the active
/// filter, raising/lowering verbosity without a restart. The task is scoped to
/// `shutdown_token` so it exits cleanly when the server stops. On non-Unix
/// targets there is no `SIGHUP`; the flag is accepted but inert (logged once).
fn spawn_log_reload_handler(
    enabled: bool,
    reload_handle: telemetry::LogReloadHandle,
    shutdown_token: tokio_util::sync::CancellationToken,
) {
    if !enabled {
        return;
    }

    #[cfg(unix)]
    {
        tokio::spawn(async move {
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
                            break;
                        }
                        match reload_handle.reload_from_env() {
                            Ok(()) => info!("Reloaded log filter from RUST_LOG (SIGHUP)"),
                            Err(e) => {
                                tracing::warn!(error = %e, "log-filter reload failed (subscriber gone?)")
                            }
                        }
                    }
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = (reload_handle, shutdown_token);
        tracing::warn!(
            "--enable-log-reload set, but SIGHUP-based reload is only supported on Unix"
        );
    }
}

/// Map each `ServerError` class to a process exit code.
///
/// Today every class is `1` (identical to the pre-extraction `Box<dyn Error>`
/// path). Kept as an explicit function so RF5 tests can lock the mapping.
fn classify_exit_code(err: &ServerError) -> i32 {
    match err {
        ServerError::SlashingDb(_)
        | ServerError::Backend(_)
        | ServerError::Tls(_)
        | ServerError::Bind(_)
        | ServerError::Config(_)
        | ServerError::Io(_) => 1,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    info!("Shutdown signal received");
}

/// Run the split-key subcommand.
#[cfg(feature = "dvt")]
fn run_split_key(args: SplitKeyCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    use signer_server::commands::split_key::{execute, SplitKeyArgs};
    use zeroize::Zeroizing;

    let password = if let Some(ref pw) = args.password {
        Zeroizing::new(pw.clone())
    } else if let Some(ref file) = args.password_file {
        let content = std::fs::read_to_string(file)?;
        Zeroizing::new(content.trim_end_matches('\n').to_string())
    } else {
        Zeroizing::new(String::new())
    };

    let output_password = if let Some(ref pw) = args.output_password {
        Zeroizing::new(pw.clone())
    } else if let Some(ref file) = args.output_password_file {
        let content = std::fs::read_to_string(file)?;
        Zeroizing::new(content.trim_end_matches('\n').to_string())
    } else {
        Zeroizing::new(String::new())
    };

    execute(SplitKeyArgs {
        keystore: args.keystore,
        password,
        threshold: args.threshold,
        shares: args.shares,
        output_dir: args.output_dir,
        output_password,
    })?;
    info!("Split key successfully");
    Ok(())
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

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

    // Serialize RUST_LOG mutation (process-global). nextest runs each test in
    // its own process, but guard anyway so the suite stays correct under any
    // runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// With `RUST_LOG` unset, rvc-signer's reconciled init must default to
    /// `info` and emit `info!` events — the P0-5 cross-binary parity fix. Before
    /// the reconciliation it used `EnvFilter::from_default_env()`, which drops
    /// `info` to `ERROR` when `RUST_LOG` is unset (the silent-by-default footgun
    /// this issue closes). Mirrors `bin/rvc`'s `test_init_logging_no_extras_emits_events`.
    ///
    /// This builds the ACTUAL shipped composition that `init_logging(format, None)`
    /// uses: `registry().with(boxed_layers).with(console_layer).with(filter)`,
    /// with `boxed_layers` Identity-padded (no OTel layer, no `TraceIdLayer`).
    /// Output is captured through `.with_writer()` and `with_default` instead of
    /// `.init()`. `without_time` avoids a wall-clock timestamp false-positive on
    /// the literal `00000000` scan (same rationale as bin/rvc T4).
    #[test]
    fn test_init_logging_emits_info_by_default() {
        use tracing_subscriber::layer::Layer;
        use tracing_subscriber::prelude::*;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        unsafe { std::env::remove_var("RUST_LOG") };

        let buf = SharedBuf::default();
        let (filter, _handle) = telemetry::reloadable_env_filter("info");
        // No tracing config: Identity only. TraceIdLayer must not be pushed.
        let boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
            vec![Box::new(tracing_subscriber::layer::Identity::new())];
        let console_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .event_format(telemetry::TraceIdFormat(
                tracing_subscriber::fmt::format().without_time().with_ansi(false),
            ))
            .with_writer(buf.clone());
        let subscriber =
            tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("signer_no_otel");
            let _enter = span.enter();
            tracing::info!("rvc-signer init regression marker");
        });

        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }

        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = captured
            .lines()
            .find(|l| l.contains("rvc-signer init regression marker"))
            .unwrap_or("");
        assert!(
            !line.is_empty(),
            "reconciled init dropped an info event with RUST_LOG unset; captured: {captured:?}"
        );
        assert!(
            !line.contains(telemetry::TRACE_ID_KEY) && !line.contains(telemetry::SPAN_ID_KEY),
            "no-config composition must not emit trace ids; got: {line:?}"
        );
        assert!(
            !line.contains("00000000"),
            "no-config composition must not emit a zeroed id; got: {line:?}"
        );
    }

    /// TRC-2f startup: with a tracing config, `init_logging` installs a subscriber
    /// whose `boxed_layers` contain the OpenTelemetry layer and `TraceIdLayer`
    /// adjacently, and returns the `TracingGuard` for process lifetime.
    ///
    /// Calls the real `init_logging` (`.init()`), so this must stay the only test
    /// that installs the global subscriber. nextest isolates processes; the
    /// `ENV_LOCK` still serializes `RUST_LOG` if a runner threads tests.
    #[test]
    fn test_init_logging_with_tracing_config_installs_otel_and_trace_id_layers() {
        use tracing_subscriber::registry::LookupSpan;

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        unsafe { std::env::remove_var("RUST_LOG") };

        let config = telemetry::TelemetryConfig {
            sample_rate: 1.0,
            service_name: Some("rvc-signer".to_string()),
            ..telemetry::TelemetryConfig::default()
        };

        // Named binding, not `_`: the guard must outlive the event so
        // BatchSpanProcessor is still up while the cache is observed.
        let (reload_handle, tracing_guard) =
            super::init_logging(telemetry::LogFormat::Pretty, Some(config));
        assert!(
            tracing_guard.is_some(),
            "a tracing config must return a TracingGuard held for process lifetime"
        );
        reload_handle.reload_from_env().expect("reload handle still works after tracing init");

        let span = tracing::info_span!("trc2f_signer_startup");
        let _enter = span.enter();
        tracing::info!("trc2f signer startup event");

        let ids = span
            .with_subscriber(|(id, dispatch)| {
                dispatch.downcast_ref::<tracing_subscriber::Registry>().and_then(|registry| {
                    registry.span(id).and_then(|span_ref| {
                        span_ref.extensions().get::<telemetry::TraceIds>().copied()
                    })
                })
            })
            .flatten();

        let ids = ids.expect(
            "subscriber stack must contain OpenTelemetryLayer and TraceIdLayer in boxed_layers",
        );
        let trace_hex = ids.trace_id.to_string();
        let span_hex = ids.span_id.to_string();
        assert_eq!(trace_hex.len(), 32, "trace id must be 32 hex chars, got {trace_hex}");
        assert!(
            trace_hex.chars().any(|c| c != '0'),
            "trace id must not be zeroed, got {trace_hex}"
        );
        assert!(span_hex.chars().any(|c| c != '0'), "span id must not be zeroed, got {span_hex}");

        // Drop does not stop BatchSpanProcessor. Same helper `main` awaits.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("shutdown runtime")
            .block_on(super::shutdown_tracing_guard(tracing_guard));

        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
    }

    /// Lifecycle: `BatchSpanProcessor`'s worker stays up until
    /// [`super::shutdown_tracing_guard`] awaits [`telemetry::shutdown_tracing`].
    /// `provider.shutdown() == Ok` joins that worker and is logged as
    /// "OpenTelemetry traces flushed". Dropping the guard does not emit that
    /// line — the OTel layer still holds the provider.
    ///
    /// The span is unsampled (`sample_rate` 0.0) so shutdown does not export.
    /// A sampled batch is posted from the processor thread by the blocking
    /// OTLP client (workspace `reqwest-blocking-client`). This test only locks
    /// the shutdown log line, so it does not stand up a collector.
    ///
    /// Also locks `main`: every pre-exit path and the success path await the
    /// helper, and `main` does not `drop` the guard.
    #[tokio::test(flavor = "current_thread")]
    async fn test_shutdown_tracing_guard_shuts_down_batch_processor() {
        use tracing_subscriber::prelude::*;

        let src = include_str!("main.rs");
        let main_start = src.find("async fn main()").expect("main");
        let main_end = src.find("async fn shutdown_tracing_guard").expect("helper");
        let main_body = &src[main_start..main_end];
        assert!(
            !main_body.contains("drop(tracing_guard"),
            "main must not drop the guard; drop does not flush BatchSpanProcessor"
        );
        assert_eq!(
            main_body.matches("shutdown_tracing_guard(tracing_guard.take()).await").count(),
            3,
            "config error, serve error, and split-key error must await shutdown before process::exit"
        );
        assert!(
            main_body.contains("shutdown_tracing_guard(tracing_guard).await"),
            "the success path must await shutdown after the subcommand returns"
        );
        let helper_end = src[main_end..].find("\nfn init_logging").expect("init_logging");
        let helper = &src[main_end..main_end + helper_end];
        assert!(
            helper.contains("telemetry::shutdown_tracing(guard).await"),
            "shutdown_tracing_guard must await telemetry::shutdown_tracing"
        );

        // Production `None` config: nothing to shut down.
        super::shutdown_tracing_guard(None).await;

        // Unsampled so the processor worker can shut down without exporting.
        let config = telemetry::TelemetryConfig {
            endpoint: "http://127.0.0.1:1/v1/traces".to_string(),
            sample_rate: 0.0,
            service_name: Some("rvc-signer".to_string()),
            ..telemetry::TelemetryConfig::default()
        };
        let (otel, guard) = telemetry::init_tracing(&config).expect("init_tracing");
        {
            let subscriber = tracing_subscriber::registry().with(otel);
            tracing::subscriber::with_default(subscriber, || {
                let span = tracing::info_span!("signer_processor_lifecycle");
                let _enter = span.enter();
                tracing::info!("queued before processor shutdown");
            });
        }

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("info");
        let capture = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_ansi(false).with_writer(buf.clone()))
            .with(filter);
        // Thread-local default covers the await on this current-thread runtime.
        let _default = tracing::subscriber::set_default(capture);
        super::shutdown_tracing_guard(Some(guard)).await;
        drop(_default);

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("OpenTelemetry traces flushed"),
            "shutdown_tracing must shut down BatchSpanProcessor; captured: {out}"
        );
        assert!(
            !out.contains("OpenTelemetry shutdown error")
                && !out.contains("OpenTelemetry shutdown timed out"),
            "processor shutdown failed; captured: {out}"
        );
    }

    // ── Issue 5.5: opt-in JSON console log output profile ─────────────────────

    /// `serve --log-format json` parses and resolves to `LogFormat::Json`; the
    /// default (flag omitted) stays `Pretty`. Same flag/semantics as `bin/rvc`.
    /// Pull the `ServeArgs` out of a parsed `Cli`, panicking on any other
    /// subcommand. Written as a `match` (not `let…else`) so it is warning-free
    /// whether or not the `dvt` feature adds a second `Command` variant.
    fn serve_args(cli: super::Cli) -> super::ServeArgs {
        match cli.command {
            super::Command::Serve(args) => args,
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_serve_log_format_flag_parses_and_defaults_to_pretty() {
        use clap::Parser;

        let cli = super::Cli::try_parse_from(["rvc-signer", "serve", "--log-format", "json"])
            .expect("serve --log-format json should parse");
        let args = serve_args(cli);
        assert_eq!(
            telemetry::LogFormat::resolve(args.log_format.as_deref()),
            telemetry::LogFormat::Json
        );

        let cli = super::Cli::try_parse_from(["rvc-signer", "serve"])
            .expect("serve default should parse");
        let args = serve_args(cli);
        assert!(
            args.log_format.is_none(),
            "omitted --log-format must be None (resolved later to pretty)"
        );
        assert_eq!(
            telemetry::LogFormat::resolve(args.log_format.as_deref()),
            telemetry::LogFormat::Pretty
        );
    }

    /// The JSON arm of `init_logging`'s no-config composition — Identity-padded
    /// `boxed_layers` + `console_fmt_layer(Json, …)` + the reload-wrapped filter —
    /// emits one parseable JSON object per event. No OTel layer, so `trace_id`
    /// stays absent.
    #[test]
    fn test_init_logging_json_arm_emits_parseable_json() {
        use tracing_subscriber::layer::Layer;
        use tracing_subscriber::prelude::*;

        // Hold ENV_LOCK + clear RUST_LOG so a parallel filter test cannot drop info.
        let out = with_rust_log(None, || {
            let buf = SharedBuf::default();
            let (filter, _handle) = telemetry::reloadable_env_filter("info");
            let boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
                vec![Box::new(tracing_subscriber::layer::Identity::new())];
            let console_layer =
                telemetry::console_fmt_layer(telemetry::LogFormat::Json, buf.clone());
            let subscriber =
                tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter);

            tracing::subscriber::with_default(subscriber, || {
                let span = tracing::info_span!("signer_json_no_otel");
                let _enter = span.enter();
                tracing::info!(request_id = "abc-123", "rvc-signer json arm marker");
            });

            let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
            captured
        });
        let line = out.lines().find(|l| l.contains("rvc-signer json arm marker")).expect("present");
        let v: serde_json::Value =
            serde_json::from_str(line).expect("JSON arm must emit parseable JSON");
        assert_eq!(v["request_id"], "abc-123", "canonical field must be a top-level JSON key");
        assert_eq!(v["message"], "rvc-signer json arm marker");
        assert!(
            v.get(telemetry::TRACE_ID_KEY).is_none() && v.get(telemetry::SPAN_ID_KEY).is_none(),
            "no-config JSON must not carry trace ids; got: {line}"
        );
    }

    /// Locks the production compose against `bin/rvc`: OTel then `TraceIdLayer`
    /// pushed with nothing between them, then
    /// `registry().with(boxed_layers).with(console_layer).with(filter).init()`.
    #[test]
    fn test_init_logging_subscriber_composition_matches_bin_rvc() {
        let src = include_str!("main.rs");
        let start = src.find("fn init_logging(").expect("init_logging");
        let body = &src[start..];
        let end = body.find("\nfn spawn_log_reload_handler").expect("following fn");
        let body = &body[..end];

        assert!(
            body.contains(
                "tracing_subscriber::registry().with(boxed_layers).with(console_layer).with(filter).init()"
            ),
            "subscriber must be registry().with(boxed_layers).with(console_layer).with(filter)"
        );
        let otel = body.find("boxed_layers.push(otel_layer)").expect("OTel push");
        let trace =
            body.find("boxed_layers.push(Box::new(trace_id_layer))").expect("TraceIdLayer push");
        assert!(otel < trace, "OTel layer must be pushed before TraceIdLayer");
        assert!(
            !body[otel + "boxed_layers.push(otel_layer)".len()..trace]
                .contains("boxed_layers.push"),
            "OTel and TraceIdLayer pushes must be adjacent"
        );
        let console = body.find("let console_layer").expect("console_layer");
        assert!(trace < console, "both pushes must precede console_layer");
        let init_at = body
            .find("registry().with(boxed_layers).with(console_layer).with(filter).init()")
            .expect("init");
        assert!(console < init_at, "console_layer must be built before .init()");
    }

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

    // Cross-binary init parity (P0-5 / M3): rvc-signer must exhibit the SAME
    // default level (`info`) and RUST_LOG precedence as bin/rvc — both route
    // their filter through `telemetry::env_filter_or("info")`. These mirror the
    // bin/rvc parity tests so an operator learns one behavior, not two.
    #[test]
    fn test_rvc_signer_unset_rust_log_defaults_to_info() {
        let rendered = with_rust_log(None, || format!("{}", telemetry::env_filter_or("info")));
        assert_eq!(rendered, "info", "unset RUST_LOG must default to info, got: {rendered}");
    }

    #[test]
    fn test_rvc_signer_rust_log_overrides_default() {
        let rendered =
            with_rust_log(Some("debug"), || format!("{}", telemetry::env_filter_or("info")));
        assert!(rendered.contains("debug"), "RUST_LOG=debug must override the default: {rendered}");
    }

    #[test]
    fn test_rvc_signer_per_module_directive_preserved() {
        let rendered = with_rust_log(Some("warn,signer_server::http_api=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        // Assert the joined target=level token, not three independent substrings:
        // the latter green-lights a filter where the target binds to a *different*
        // level (e.g. http_api=info,foo=trace).
        assert!(
            rendered.contains("signer_server::http_api=trace"),
            "per-module directive not preserved verbatim (target must bind to trace): {rendered}"
        );
    }

    #[test]
    fn test_rvc_signer_malformed_rust_log_falls_back_to_info() {
        let rendered = with_rust_log(Some("rvc=invalidlevel"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert_eq!(
            rendered, "info",
            "malformed RUST_LOG must fall back to info (no panic, no silence): {rendered}"
        );
    }

    #[test]
    fn test_rvc_signer_whitespace_padded_rust_log_honored() {
        let rendered = with_rust_log(Some("warn, signer_server::http_api=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(
            rendered.contains("signer_server::http_api=trace"),
            "padded per-module directive not preserved verbatim (target must bind to trace): {rendered}"
        );
    }

    struct EnvSlot {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvSlot {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let prev = std::env::var(key).ok();
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvSlot {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn capture_sample_rate_warn(sample_rate: f64) -> String {
        use tracing_subscriber::prelude::*;

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("warn");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()).with_ansi(false))
            .with(filter);
        tracing::subscriber::with_default(subscriber, || {
            super::warn_if_sample_rate_below_one(sample_rate);
        });
        let captured = buf.0.lock().unwrap().clone();
        String::from_utf8(captured).unwrap()
    }

    struct ParityRow {
        label: &'static str,
        flag_endpoint: Option<&'static str>,
        env_endpoint: Option<&'static str>,
        flag_sample_rate: Option<f64>,
        env_sample_rate: Option<&'static str>,
        flag_service_name: Option<&'static str>,
        /// Composed endpoint after `/v1/traces` append. `None` = tracing stays off.
        expect_endpoint: Option<&'static str>,
        expect_sample_rate: f64,
        /// Substring the post-init sample-rate warn must contain.
        /// `None` means that warn must not fire.
        expect_warn: Option<&'static str>,
    }

    /// TRC-2g shared-behavior lock.
    ///
    /// Every row is flag → `OTEL_*` env → default, checked against
    /// `rvc_config::TracingConfig::resolve_*` (the sibling at
    /// `crates/rvc/src/config/types.rs:437-458`, now
    /// `crates/rvc-config/src/sections/tracing.rs`). The composed endpoint
    /// covers TRC-1b path append. The captured `warn!` covers TRC-1a
    /// (`< 1.0` including `0.0` warns; `1.0` does not) and only runs when an
    /// endpoint resolved, matching `main`.
    #[test]
    fn test_signer_tracing_flag_env_default_parity_table() {
        use clap::Parser;

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        assert_eq!(super::DEFAULT_TRACING_SAMPLE_RATE, rvc_config::DEFAULT_TRACING_SAMPLE_RATE);

        let src = include_str!("main.rs");
        let resolver_at = src.find("fn resolve_endpoint(&self)").expect("resolve_endpoint");
        let resolver_end = src[resolver_at..]
            .find("fn ensure_otlp_http_traces_path")
            .expect("path append follows the resolver");
        let resolver = &src[resolver_at..resolver_at + resolver_end];
        assert!(
            resolver.contains("std::env::var(\"OTEL_EXPORTER_OTLP_ENDPOINT\")"),
            "endpoint env read must be the G-3 literal"
        );
        assert!(
            resolver.contains("std::env::var(\"OTEL_TRACES_SAMPLER_ARG\")"),
            "sample-rate env read must be the G-3 literal"
        );
        assert!(
            !resolver.contains("OTEL_SERVICE_NAME"),
            "service name has no sanctioned OTEL env; #418 owns the signer default"
        );

        let main_start = src.find("async fn main()").expect("main");
        let main_end = src.find("async fn shutdown_tracing_guard").expect("helper");
        let main_body = &src[main_start..main_end];
        let init_at = main_body.find("init_logging(").expect("init_logging call");
        let warn_at = main_body.find("warn_if_sample_rate_below_one(").expect("startup warn");
        assert!(init_at < warn_at, "TRC-1a warn must run after the subscriber is installed");

        let init_fn = src.find("fn init_logging(").expect("init_logging");
        let init_fn_end = src[init_fn..].find("\nfn spawn_log_reload_handler").expect("next fn");
        let init_body = &src[init_fn..init_fn + init_fn_end];
        assert_eq!(
            init_body.matches("redact_endpoint_userinfo_for_log(&config.endpoint)").count(),
            2,
            "pre-init and enabled eprintln lines must redact endpoint userinfo"
        );

        let parsed = super::Cli::try_parse_from([
            "rvc-signer",
            "serve",
            "--log-format",
            "json",
            "--tracing-endpoint",
            "http://jaeger:4318",
            "--tracing-sample-rate",
            "0.0",
            "--tracing-service-name",
            "custom-signer",
        ])
        .expect("serve accepts the three tracing flags next to --log-format");
        let parsed_flags = super::SignerTracingFlags::from_cli(&parsed);
        assert_eq!(parsed_flags.endpoint.as_deref(), Some("http://jaeger:4318"));
        assert_eq!(parsed_flags.sample_rate, Some(0.0));
        assert_eq!(parsed_flags.service_name.as_deref(), Some("custom-signer"));

        let omitted = super::Cli::try_parse_from(["rvc-signer", "serve"]).expect("serve");
        let omitted_flags = super::SignerTracingFlags::from_cli(&omitted);
        assert!(omitted_flags.endpoint.is_none());
        assert!(omitted_flags.sample_rate.is_none());
        assert!(omitted_flags.service_name.is_none());

        let rows = [
            ParityRow {
                label: "unset flag and env disables tracing; rate stays the built-in default",
                flag_endpoint: None,
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: None,
                expect_sample_rate: 0.01,
                expect_warn: None,
            },
            ParityRow {
                label: "path-less jaeger endpoint appends /v1/traces",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "path-less endpoint with a trailing slash appends /v1/traces",
                flag_endpoint: Some("http://jaeger:4318/"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "pathful /v1/traces endpoint is untouched",
                flag_endpoint: Some("http://jaeger:4318/v1/traces"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "pathful gateway prefix is untouched",
                flag_endpoint: Some("http://gateway:4318/otlp/v1/traces"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://gateway:4318/otlp/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "explicit endpoint wins over OTEL_EXPORTER_OTLP_ENDPOINT",
                flag_endpoint: Some("http://cli:4318"),
                env_endpoint: Some("http://env:4318"),
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://cli:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "env endpoint is used when the flag is omitted",
                flag_endpoint: None,
                env_endpoint: Some("http://jaeger:4318"),
                flag_sample_rate: None,
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "sample rate 0.0 warns that the exporter receives nothing",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(0.0),
                env_sample_rate: Some("0.5"),
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.0,
                expect_warn: Some("exporter receives nothing"),
            },
            ParityRow {
                label: "sample rate 1.0 does not warn and wins over env",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: Some("0.5"),
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "explicit 0.01 survives OTEL_TRACES_SAMPLER_ARG",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(0.01),
                env_sample_rate: Some("0.5"),
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "env sample rate applies when the flag is omitted",
                flag_endpoint: Some("http://localhost:4318"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: Some("0.5"),
                flag_service_name: None,
                expect_endpoint: Some("http://localhost:4318/v1/traces"),
                expect_sample_rate: 0.5,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "malformed env sample rate falls back to the built-in default",
                flag_endpoint: Some("http://localhost:4318"),
                env_endpoint: None,
                flag_sample_rate: None,
                env_sample_rate: Some("nope"),
                flag_service_name: None,
                expect_endpoint: Some("http://localhost:4318/v1/traces"),
                expect_sample_rate: 0.01,
                expect_warn: Some("tracing sample_rate is below 1.0"),
            },
            ParityRow {
                label: "sample rate above 1 is clamped to 1.0 and does not warn",
                flag_endpoint: Some("http://localhost:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(2.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://localhost:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "negative sample rate clamps to 0.0 and warns",
                flag_endpoint: Some("http://localhost:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(-0.5),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://localhost:4318/v1/traces"),
                expect_sample_rate: 0.0,
                expect_warn: Some("exporter receives nothing"),
            },
            ParityRow {
                label: "explicit service name is passed through",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: Some("custom-signer"),
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "omitted service name defaults TelemetryConfig to rvc-signer",
                flag_endpoint: Some("http://jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://jaeger:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "credentialed path-less endpoint keeps userinfo and appends /v1/traces",
                flag_endpoint: Some("http://user:s3cret@jaeger:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://user:s3cret@jaeger:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "pathful endpoint is the original exporter URL, userinfo included",
                flag_endpoint: Some("http://user:s3cret@gateway:4318/otlp/v1/traces"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://user:s3cret@gateway:4318/otlp/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "pathful multi-@ userinfo stays on the exporter URL",
                flag_endpoint: Some("http://user:s3cret@pass@gateway:4318/otlp/v1/traces"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("http://user:s3cret@pass@gateway:4318/otlp/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
            ParityRow {
                label: "https path-less endpoint appends /v1/traces",
                flag_endpoint: Some("https://collector.example.com:4318"),
                env_endpoint: None,
                flag_sample_rate: Some(1.0),
                env_sample_rate: None,
                flag_service_name: None,
                expect_endpoint: Some("https://collector.example.com:4318/v1/traces"),
                expect_sample_rate: 1.0,
                expect_warn: None,
            },
        ];

        for row in rows {
            let _endpoint_env = EnvSlot::set("OTEL_EXPORTER_OTLP_ENDPOINT", row.env_endpoint);
            let _rate_env = EnvSlot::set("OTEL_TRACES_SAMPLER_ARG", row.env_sample_rate);
            let flags = super::SignerTracingFlags {
                endpoint: row.flag_endpoint.map(str::to_string),
                sample_rate: row.flag_sample_rate,
                service_name: row.flag_service_name.map(str::to_string),
            };
            let sibling = rvc_config::TracingConfig {
                endpoint: flags.endpoint.clone(),
                sample_rate: flags.sample_rate,
                service_name: flags.service_name.clone(),
                ..Default::default()
            };
            assert_eq!(
                flags.resolve_endpoint(),
                sibling.resolve_endpoint(),
                "{}: resolve_endpoint drifted from TracingConfig",
                row.label
            );
            let ours = flags.resolve_sample_rate();
            let theirs = sibling.resolve_sample_rate();
            assert!(
                (ours - theirs).abs() < f64::EPSILON,
                "{}: resolve_sample_rate drifted ({ours} vs {theirs})",
                row.label
            );

            let built = super::build_signer_tracing_config(&flags);
            assert_eq!(
                built.as_ref().map(|config| config.endpoint.as_str()),
                row.expect_endpoint,
                "{}: composed endpoint",
                row.label
            );
            assert!(
                (ours - row.expect_sample_rate).abs() < f64::EPSILON,
                "{}: sample rate {} != {}",
                row.label,
                ours,
                row.expect_sample_rate
            );
            assert_eq!(
                flags.resolve_service_name().as_deref(),
                row.flag_service_name,
                "{}: resolve_service_name stays the explicit flag",
                row.label
            );
            if let Some(config) = &built {
                assert!(
                    (config.sample_rate - row.expect_sample_rate).abs() < f64::EPSILON,
                    "{}: TelemetryConfig sample rate",
                    row.label
                );
                // TRC-2h: omitted flag defaults the constructed config to
                // `rvc-signer`. An explicit `--tracing-service-name` wins.
                // `resolve_service_name` itself stays flag-only (no OTEL env).
                let expect_config_service = row.flag_service_name.or(Some("rvc-signer"));
                assert_eq!(
                    config.service_name.as_deref(),
                    expect_config_service,
                    "{}: TelemetryConfig service name",
                    row.label
                );
                let logged = super::redact_endpoint_userinfo_for_log(&config.endpoint);
                assert!(
                    !logged.contains("s3cret")
                        && !logged.contains("user")
                        && !logged.contains("pass"),
                    "{}: eprintln leaked userinfo: {logged}",
                    row.label
                );
                if config.endpoint.contains('@') {
                    let authority = logged
                        .split_once("://")
                        .map(|(_, rest)| rest)
                        .unwrap_or(logged.as_str())
                        .split(['/', '?', '#'])
                        .next()
                        .unwrap_or("");
                    assert!(
                        !authority.contains('@') && logged.contains("/v1/traces"),
                        "{}: log URL must drop authority userinfo and keep the traces path: {logged}",
                        row.label
                    );
                } else {
                    assert_eq!(logged, config.endpoint, "{}: credential-free endpoint", row.label);
                }
                let warned = capture_sample_rate_warn(config.sample_rate);
                match row.expect_warn {
                    Some(needle) => {
                        assert!(
                            warned.contains(needle),
                            "{}: startup warn missing {needle:?}.\n--- captured ---\n{warned}",
                            row.label
                        );
                        if needle.contains("exporter receives nothing") {
                            assert!(
                                !warned.contains("below 1.0"),
                                "{}: 0.0 must use the exporter-receives-nothing warn.\n{warned}",
                                row.label
                            );
                        }
                    }
                    None => assert!(
                        !warned.contains("tracing sample_rate is below 1.0")
                            && !warned.contains("exporter receives nothing"),
                        "{}: rate 1.0 must not warn.\n--- captured ---\n{warned}",
                        row.label
                    ),
                }
            } else {
                assert!(
                    row.expect_warn.is_none(),
                    "{}: tracing-off must not expect a startup warn",
                    row.label
                );
            }
        }

        assert_eq!(
            super::redact_endpoint_userinfo_for_log("http://user:s3cret@jaeger:4318/v1/traces"),
            "http://jaeger:4318/v1/traces"
        );
        assert_eq!(
            super::redact_endpoint_userinfo_for_log("http://jaeger:4318/v1/traces"),
            "http://jaeger:4318/v1/traces"
        );
        assert_eq!(super::redact_endpoint_userinfo_for_log("user:s3cret@host"), "<unparseable>");
        let unparseable = super::redact_endpoint_userinfo_for_log("user:pass@s3cret");
        assert_eq!(unparseable, "<unparseable>");
        assert!(
            !unparseable.contains("user")
                && !unparseable.contains("pass")
                && !unparseable.contains("s3cret")
                && !unparseable.contains('@')
        );
        assert_eq!(
            super::redact_endpoint_userinfo_for_log("http://jaeger:4318/path@not-userinfo"),
            "http://jaeger:4318/path@not-userinfo"
        );

        // Pathful branch returns the original string (exporter contract). The
        // log URL is a second parse that drops userinfo at the last authority `@`.
        let pathful = "http://user:s3cret@gateway:4318/otlp/v1/traces?q=1#frag";
        assert_eq!(super::ensure_otlp_http_traces_path(pathful.to_string()), pathful);
        assert_eq!(
            super::redact_endpoint_userinfo_for_log(pathful),
            "http://gateway:4318/otlp/v1/traces?q=1#frag"
        );
        let multi_at = "http://user:s3cret@pass@gateway:4318/otlp/v1/traces";
        assert_eq!(super::ensure_otlp_http_traces_path(multi_at.to_string()), multi_at);
        let multi_logged = super::redact_endpoint_userinfo_for_log(multi_at);
        assert_eq!(multi_logged, "http://gateway:4318/otlp/v1/traces");
        assert!(
            !multi_logged.contains("user")
                && !multi_logged.contains("pass")
                && !multi_logged.contains("s3cret")
        );
    }
}
