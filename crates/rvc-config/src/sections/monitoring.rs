//! Monitoring push-endpoint section (ARCH-4f).
//!
//! Clap group, TOML `[monitoring]` table, and `Config.monitoring` share this module.
//! Valued knobs are `Option<T>` with no clap `default_value` (ADR-009).

use serde::{Deserialize, Serialize};

fn default_monitoring_interval() -> u64 {
    384
}

/// Clap + serde declaration for the monitoring knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitoringArgs {
    /// Remote monitoring endpoint URL (e.g., https://beaconcha.in/api/v1/client/metrics?apikey=...)
    #[arg(id = "monitoring_endpoint", long = "monitoring-endpoint")]
    #[serde(alias = "monitoring_endpoint", skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Monitoring push interval in seconds (default: 384, i.e., one epoch)
    #[arg(id = "monitoring_interval", long = "monitoring-interval")]
    #[serde(alias = "monitoring_interval", skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,

    /// Allow HTTP (non-HTTPS) monitoring endpoint
    #[arg(
        id = "monitoring_endpoint_insecure",
        long = "monitoring-endpoint-insecure",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(alias = "monitoring_endpoint_insecure", skip_serializing_if = "Option::is_none")]
    pub endpoint_insecure: Option<bool>,
}

impl MonitoringArgs {
    /// Fold this declaration into a [`MonitoringConfig`].
    ///
    /// Defaults live on `MonitoringConfig`; load overlays Option fields.
    pub fn resolved(&self) -> MonitoringConfig {
        MonitoringConfig {
            endpoint: self.endpoint.clone(),
            interval: self.interval.unwrap_or_else(default_monitoring_interval),
            endpoint_insecure: self.endpoint_insecure.unwrap_or(false),
        }
    }
}

/// Monitoring push-endpoint settings (resolved / `Config` field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_monitoring_interval")]
    pub interval: u64,
    #[serde(default)]
    pub endpoint_insecure: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self { endpoint: None, interval: default_monitoring_interval(), endpoint_insecure: false }
    }
}
