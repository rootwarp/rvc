//! Secret-provider section (ARCH-4g).
//!
//! **A-4.4:** the existing TOML `[secret_provider]` table wins; there is no
//! clap group of that name today (the five knobs sat on `KeysArgs`). This is
//! a deliberate refinement of ADR-008's "the clap group *is* the section" —
//! inventing a `[keys]` table for these knobs would rename the operator-visible
//! wire.
//!
//! **A-4.5:** [`SecretProviderArgs`] is its own clap/serde struct;
//! [`super::keys::KeysArgs`] flattens it (`#[command(flatten)]`). Nested
//! flatten is a clap-supported shape; a sibling-group fallback is not taken.
//!
//! Flat/top-level spellings (`--gcp-project-id`, `--secret-provider`, …) stay
//! as clap `--flag` strings. Nested `[secret_provider.gcp]` accepts
//! section-relative names only (4f SEC: no prefixed aliases on `*Config`).

use serde::{Deserialize, Serialize};

fn default_gcp_secret_prefix() -> String {
    "validator-key-".to_string()
}

/// Clap + serde declaration for the `[secret_provider]` knobs (A-4.5).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// [`GcpSecretArgs`] is clap-flattened so `--gcp-project-id` stays top-level
/// on the CLI, and serde-nested so `[secret_provider.gcp]` stays a table.
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretProviderArgs {
    /// Secret provider(s) to use for loading validator keys (e.g., "gcp")
    #[arg(id = "secret_provider", long = "secret-provider")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<String>,

    /// Interval in seconds to refresh keys from secret providers (0 = disabled)
    #[arg(id = "secret_refresh_interval", long = "secret-refresh-interval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<u64>,

    /// Fail startup if any secret provider fails to list keys (SEC-9 / M-9).
    /// Default is resilient: one flaky provider is skipped; all providers
    /// failing remains fatal regardless of this flag.
    #[arg(
        id = "secret_provider_strict",
        long = "secret-provider-strict",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,

    /// Nested `[secret_provider.gcp]` knobs; clap-flattened to keep `--gcp-*` flags.
    #[command(flatten)]
    #[serde(default)]
    pub gcp: GcpSecretArgs,
}

impl SecretProviderArgs {
    /// Fold this declaration into a [`SecretProviderConfig`].
    ///
    /// Defaults live on `SecretProviderConfig`; load overlays Option fields.
    pub fn resolved(&self) -> SecretProviderConfig {
        SecretProviderConfig {
            providers: self
                .providers
                .as_ref()
                .map(|csv| {
                    csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
                })
                .unwrap_or_default(),
            refresh_interval: self.refresh_interval,
            strict: self.strict.unwrap_or(false),
            gcp: self.gcp.resolved(),
        }
    }
}

/// GCP secret-manager knobs (clap-flat / serde-nested under `[secret_provider.gcp]`).
///
/// No `gcp_*` serde aliases: those would bind inside the nested table (4f SEC).
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GcpSecretArgs {
    /// GCP project ID (required when --secret-provider includes "gcp")
    #[arg(id = "gcp_project_id", long = "gcp-project-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Prefix for GCP secret names (default: "validator-key-")
    #[arg(id = "gcp_secret_prefix", long = "gcp-secret-prefix")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_prefix: Option<String>,
}

impl GcpSecretArgs {
    /// Fold into [`GcpSecretConfig`]. Unused on today's merge path (ARCH-4i).
    pub fn resolved(&self) -> GcpSecretConfig {
        GcpSecretConfig {
            project_id: self.project_id.clone(),
            secret_prefix: self.secret_prefix.clone().unwrap_or_else(default_gcp_secret_prefix),
        }
    }
}

/// Secret-provider settings (resolved / `Config` field).
///
/// No flat-legacy `#[serde(alias)]` here: those bind inside `[secret_provider]`
/// (4f SEC).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretProviderConfig {
    #[serde(default)]
    pub providers: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<u64>,

    /// When true, any secret-provider `list_keys` failure aborts startup (SEC-9 / M-9).
    ///
    /// Default `false`: a single flaky provider is logged and skipped so healthy
    /// providers can still load keys. A failure of **all** configured providers
    /// remains fatal regardless of this flag.
    #[serde(default)]
    pub strict: bool,

    #[serde(default)]
    pub gcp: GcpSecretConfig,
}

/// GCP project / prefix (resolved / `SecretProviderConfig.gcp` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GcpSecretConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    #[serde(default = "default_gcp_secret_prefix")]
    pub secret_prefix: String,
}

impl Default for GcpSecretConfig {
    fn default() -> Self {
        Self { project_id: None, secret_prefix: default_gcp_secret_prefix() }
    }
}
