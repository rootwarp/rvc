//! Tracing / OpenTelemetry section (ARCH-4f).
//!
//! Clap group, TOML `[tracing]` table, and `Config.tracing` share this module.
//! Valued knobs are `Option<T>` with no clap `default_value` (ADR-009).
//! `OTEL_*` reads stay config-else-env (A-4.8 / C3) — not an env layer.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Built-in head-based sample rate when neither config/CLI nor
/// `OTEL_TRACES_SAMPLER_ARG` sets one (ADR-005 / TRC-1a).
///
/// Names the production default — does not change it.
pub const DEFAULT_TRACING_SAMPLE_RATE: f64 = 0.01;

/// OpenTelemetry exporter backend selected in config / CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TracingExporter {
    /// OTLP over HTTP (default).
    #[default]
    Otlp,
    /// Google Cloud Trace (requires the `gcp-trace` feature on the binary).
    Gcp,
}

impl fmt::Display for TracingExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otlp => write!(f, "otlp"),
            Self::Gcp => write!(f, "gcp"),
        }
    }
}

impl FromStr for TracingExporter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "otlp" => Ok(Self::Otlp),
            "gcp" => Ok(Self::Gcp),
            other => Err(format!("invalid tracing_exporter '{other}': must be one of otlp, gcp")),
        }
    }
}

fn default_tracing_sample_rate() -> f64 {
    DEFAULT_TRACING_SAMPLE_RATE
}

/// Clap + serde declaration for the tracing knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TracingArgs {
    /// OTLP exporter endpoint (e.g., http://localhost:4318). Enables tracing when set.
    #[arg(id = "tracing_endpoint", long = "tracing-endpoint")]
    #[serde(alias = "tracing_endpoint", skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Exporter backend: "otlp" (default) or "gcp"
    #[arg(id = "tracing_exporter", long = "tracing-exporter")]
    #[serde(alias = "tracing_exporter", skip_serializing_if = "Option::is_none")]
    pub exporter: Option<TracingExporter>,

    /// Head-based sampling ratio 0.0–1.0 (default: [`DEFAULT_TRACING_SAMPLE_RATE`] when unset;
    /// see `OTEL_TRACES_SAMPLER_ARG`)
    #[arg(id = "tracing_sample_rate", long = "tracing-sample-rate")]
    #[serde(alias = "tracing_sample_rate", skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<f64>,

    /// Maximum number of spans queued for export (OTel SDK default: 2048)
    #[arg(id = "tracing_max_queue_size", long = "tracing-max-queue-size")]
    #[serde(alias = "tracing_max_queue_size", skip_serializing_if = "Option::is_none")]
    pub max_queue_size: Option<usize>,

    /// Maximum number of spans per export batch (OTel SDK default: 512)
    #[arg(id = "tracing_max_export_batch_size", long = "tracing-max-export-batch-size")]
    #[serde(alias = "tracing_max_export_batch_size", skip_serializing_if = "Option::is_none")]
    pub max_export_batch_size: Option<usize>,

    /// OpenTelemetry `service.name` (default: `"rvc"` when unset). Distinguishes
    /// VC vs signer in Jaeger/OTLP (ADR-007 / TRC-1c).
    #[arg(id = "tracing_service_name", long = "tracing-service-name")]
    #[serde(alias = "tracing_service_name", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

impl TracingArgs {
    /// Fold this declaration into a [`TracingConfig`].
    ///
    /// Defaults live on `TracingConfig`; load overlays Option fields.
    /// `sample_rate` stays `None` so [`TracingConfig::resolve_sample_rate`] can
    /// apply `OTEL_TRACES_SAMPLER_ARG` (config-else-env).
    pub fn resolved(&self) -> TracingConfig {
        TracingConfig {
            endpoint: self.endpoint.clone(),
            exporter: self.exporter.unwrap_or_default(),
            sample_rate: self.sample_rate,
            max_queue_size: self.max_queue_size,
            max_export_batch_size: self.max_export_batch_size,
            service_name: self.service_name.clone(),
        }
    }
}

/// Distributed tracing / OpenTelemetry settings (resolved / `Config` field).
///
/// `sample_rate` is `Option` end-to-end so an explicit
/// [`DEFAULT_TRACING_SAMPLE_RATE`] is distinguishable from "unset" (RF5-15 / F20).
/// Resolve with [`TracingConfig::resolve_sample_rate`] /
/// [`TracingConfig::resolve_endpoint`] — precedence is CLI > file > `OTEL_*` env >
/// built-in default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TracingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub exporter: TracingExporter,
    /// Head-based sampling ratio when set. `None` means "not configured" so
    /// `OTEL_TRACES_SAMPLER_ARG` and [`DEFAULT_TRACING_SAMPLE_RATE`] can apply at
    /// resolution time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_export_batch_size: Option<usize>,
    /// OpenTelemetry `service.name`. `None` means use the built-in `"rvc"`
    /// fallback in `telemetry::init_tracing` (ADR-007 / TRC-1c).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

impl TracingConfig {
    /// Resolve the OTLP endpoint: explicit config/CLI > `OTEL_EXPORTER_OTLP_ENDPOINT`.
    ///
    /// Returns `None` when neither source provides a value (tracing stays disabled).
    pub fn resolve_endpoint(&self) -> Option<String> {
        self.endpoint.clone().or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
    }

    /// Resolve the sample rate: explicit config/CLI > `OTEL_TRACES_SAMPLER_ARG` >
    /// [`DEFAULT_TRACING_SAMPLE_RATE`].
    ///
    /// Values outside `0.0..=1.0` are clamped with a warning.
    pub fn resolve_sample_rate(&self) -> f64 {
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
}
