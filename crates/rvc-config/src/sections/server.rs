//! Metrics HTTP bind section (ARCH-4h).
//!
//! Invented `[server]` table. ADR-009 fields live here (`metrics_address`,
//! `metrics_port`) and must not regain clap `default_value`. Nested tables
//! accept section-relative names only (4f SEC). Flat top-level keys stay on
//! `ConfigWire`. Leftover healthz bind knobs are rejected at load.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Clap + serde declaration for the `[server]` knobs (ADR-008 / ADR-009).
///
/// Field names match the operator-visible keys. `--flag` strings stay the
/// pre-move longs. No flat-legacy `#[serde(alias)]` here.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerArgs {
    /// Bind address for the metrics HTTP server (default: 127.0.0.1)
    #[arg(long = "metrics-address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_address: Option<IpAddr>,

    /// Port for the metrics HTTP server (default: 8080)
    #[arg(long = "metrics-port")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_port: Option<u16>,
}

impl ServerArgs {
    /// Fold this declaration into a [`ServerConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> ServerConfig {
        ServerConfig { metrics_address: self.metrics_address, metrics_port: self.metrics_port }
    }
}

/// `[server]` table (section-relative names only; no flat aliases).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_port: Option<u16>,
}
