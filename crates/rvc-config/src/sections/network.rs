//! Network preset and genesis-override section (ARCH-4h).
//!
//! Invented `[network]` table. The TOML key `network` is dual-shape: a flat
//! string preset *or* a table (same class as `logfile`). The string-or-table
//! split lives in rvc `Config`'s custom `Deserialize`; this `*Config` is the
//! table half. Nested tables accept section-relative names only (4f SEC).
//!
//! KAT-first: do not name tests `…_genesis_validators_root` (A-4.9).

use serde::{Deserialize, Serialize};

use crate::Network;

/// Clap + serde declaration for the `[network]` knobs (ADR-008).
///
/// `--flag` strings stay the pre-move longs. No flat-legacy `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkArgs {
    /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
    #[arg(long = "network")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    /// Genesis time override (Unix timestamp)
    #[arg(long = "genesis-time")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,

    /// Genesis validators root override (hex string with 0x prefix)
    #[arg(long = "genesis-validators-root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,

    /// Graffiti string for blocks
    #[arg(long = "graffiti")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<String>,
}

impl NetworkArgs {
    /// Fold this declaration into a [`NetworkConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> NetworkConfig {
        NetworkConfig {
            network: self.network,
            genesis_time: self.genesis_time,
            genesis_validators_root: self.genesis_validators_root.clone(),
            graffiti: self.graffiti.clone(),
        }
    }
}

/// `[network]` table (section-relative names only; no flat aliases).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<String>,
}
