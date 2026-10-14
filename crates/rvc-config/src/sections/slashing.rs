//! Slashing-protection database section (ARCH-4h).
//!
//! Invented `[slashing]` table. CLI `--init-slashing-db` maps to TOML
//! `allow_fresh_db`. `strict_permissions` / `strict_slashing_semantics` stay
//! CLI-only (G-2 `BYPASS`). Nested tables accept section-relative names only
//! (4f SEC). Flat top-level keys stay on `ConfigWire`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Clap + serde declaration for the `[slashing]` knobs (ADR-008).
///
/// `--flag` strings stay the pre-move longs. `init_slashing_db` is CLI-only;
/// the TOML key is [`SlashingConfig::allow_fresh_db`].
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SlashingArgs {
    /// Path to the slashing protection database
    #[arg(long = "slashing-db-path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slashing_db_path: Option<PathBuf>,

    /// Allow creating a fresh empty slashing-protection DB when the path is
    /// missing (SEC-3). DANGEROUS on a previously-active validator: the new
    /// DB has zero signing history and can enable double-signing / slashing.
    /// Use only for genuine first-time deployments. A 0-byte or corrupt DB
    /// is always a hard error regardless of this flag.
    #[arg(long = "init-slashing-db", default_value_t = false)]
    #[serde(skip)]
    pub init_slashing_db: bool,

    /// Exit on unsafe slashing DB file permissions (world-readable/writable)
    #[arg(long = "strict-permissions")]
    #[serde(skip)]
    pub strict_permissions: bool,

    /// Reject null-root re-signs as potential double votes (strict EIP-3076 semantics)
    #[arg(long = "strict-slashing-semantics")]
    #[serde(skip)]
    pub strict_slashing_semantics: bool,

    /// Max slashing-DB reserve checks per COMMIT (group commit). Default 50.
    #[arg(id = "group_commit_batch_size", long = "slashing-group-commit-batch-size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_commit_batch_size: Option<usize>,

    /// Milliseconds to wait for a group-commit batch to fill. Default 1. 0 = no wait.
    #[arg(id = "group_commit_wait_to_fill_ms", long = "slashing-group-commit-wait-to-fill-ms")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_commit_wait_to_fill_ms: Option<u64>,
}

impl SlashingArgs {
    /// Fold this declaration into a [`SlashingConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> SlashingConfig {
        SlashingConfig {
            slashing_db_path: self.slashing_db_path.clone(),
            allow_fresh_db: if self.init_slashing_db { Some(true) } else { None },
            group_commit_batch_size: self.group_commit_batch_size,
            group_commit_wait_to_fill_ms: self.group_commit_wait_to_fill_ms,
        }
    }
}

/// `[slashing]` table (section-relative names only; no flat aliases).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SlashingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slashing_db_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_fresh_db: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_commit_batch_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_commit_wait_to_fill_ms: Option<u64>,
}
