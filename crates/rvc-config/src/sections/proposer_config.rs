//! Proposer-config source section (ARCH-4g).
//!
//! **A-4.4:** the existing TOML `[proposer_config]` table wins; the clap group
//! is reshaped to match it. This is a deliberate refinement of ADR-008's
//! "the clap group *is* the section" — renaming the operator-visible table is
//! out of scope. `proposer_nodes` and `broadcast` stay top-level TOML knobs
//! (aliased on the CLI wrapper, not on this `*Config`).
//!
//! Flat `proposer_config_*` keys stay on `ConfigWire`. This `*Config` accepts
//! section-relative names only (4f SEC).

use serde::{Deserialize, Serialize};

fn default_proposer_config_refresh_interval() -> u64 {
    384
}

/// Clap + serde declaration for the `[proposer_config]` knobs (ADR-008 / A-4.4).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]` on this `*Args`
/// type only — not on [`ProposerConfigSource`].
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProposerConfigArgs {
    /// Remote URL for proposer configuration (mutually exclusive with --proposer-config-file)
    #[arg(
        id = "proposer_config_url",
        long = "proposer-config-url",
        conflicts_with = "proposer_config_file"
    )]
    #[serde(alias = "proposer_config_url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Local file path for proposer configuration (mutually exclusive with --proposer-config-url)
    #[arg(
        id = "proposer_config_file",
        long = "proposer-config-file",
        conflicts_with = "proposer_config_url"
    )]
    #[serde(alias = "proposer_config_file", skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    /// Refresh interval in seconds for proposer config URL (default: 384, i.e., one epoch)
    #[arg(id = "proposer_config_refresh_interval", long = "proposer-config-refresh-interval")]
    #[serde(alias = "proposer_config_refresh_interval", skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<u64>,

    /// Bearer token for proposer config URL authentication
    #[arg(id = "proposer_config_url_token", long = "proposer-config-url-token")]
    #[serde(alias = "proposer_config_url_token", skip_serializing_if = "Option::is_none")]
    pub url_token: Option<String>,

    /// Allow HTTP (non-HTTPS) proposer config URL
    #[arg(
        id = "proposer_config_url_insecure",
        long = "proposer-config-url-insecure",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(alias = "proposer_config_url_insecure", skip_serializing_if = "Option::is_none")]
    pub url_insecure: Option<bool>,
}

impl ProposerConfigArgs {
    /// Fold this declaration into a [`ProposerConfigSource`].
    ///
    /// Defaults live on `ProposerConfigSource`; load overlays Option fields.
    pub fn resolved(&self) -> ProposerConfigSource {
        ProposerConfigSource {
            url: self.url.clone(),
            file: self.file.clone(),
            refresh_interval: self
                .refresh_interval
                .unwrap_or_else(default_proposer_config_refresh_interval),
            url_token: self.url_token.clone(),
            url_insecure: self.url_insecure.unwrap_or(false),
        }
    }
}

/// Proposer-config URL / file source settings (resolved / `Config` field).
///
/// No flat-legacy `#[serde(alias)]` here: those bind inside `[proposer_config]`
/// (4f SEC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProposerConfigSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default = "default_proposer_config_refresh_interval")]
    pub refresh_interval: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_token: Option<String>,
    #[serde(default)]
    pub url_insecure: bool,
}

impl Default for ProposerConfigSource {
    fn default() -> Self {
        Self {
            url: None,
            file: None,
            refresh_interval: default_proposer_config_refresh_interval(),
            url_token: None,
            url_insecure: false,
        }
    }
}
