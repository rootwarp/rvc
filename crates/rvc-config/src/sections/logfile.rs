//! Logfile rotation section (ARCH-4g).
//!
//! **A-4.4:** the existing TOML `[logfile]` table wins; the clap group is reshaped
//! to match it. This is a deliberate refinement of ADR-008's "the clap group
//! *is* the section" — renaming the operator-visible table is out of scope.
//! `log_level` stays a bare top-level knob (ARCH-4h). `log_format` /
//! `enable_log_reload` stay CLI-only (G-2 `BYPASS`).
//!
//! Flat `logfile_max_*` keys stay on `ConfigWire`. This `*Config` accepts
//! section-relative names only (4f SEC: prefixed aliases must not bind inside
//! the nested table). The string-or-table `logfile` wire stays in `rvc`
//! (`types.rs` custom `Deserialize`) and must not move.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_logfile_max_size() -> u64 {
    200
}

fn default_logfile_max_number() -> usize {
    5
}

/// Clap + serde declaration for the `[logfile]` knobs (ADR-008 / A-4.4).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]` on this `*Args`
/// type only — not on [`LogfileConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogfileArgs {
    /// Path to the log file (enables file logging alongside stdout)
    #[arg(id = "logfile", long = "logfile")]
    #[serde(alias = "logfile", skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Maximum log file size in MB before rotation (default: 200)
    #[arg(id = "logfile_max_size", long = "logfile-max-size")]
    #[serde(alias = "logfile_max_size", skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,

    /// Maximum number of rotated log files to keep (default: 5)
    #[arg(id = "logfile_max_number", long = "logfile-max-number")]
    #[serde(alias = "logfile_max_number", skip_serializing_if = "Option::is_none")]
    pub max_number: Option<usize>,

    /// Enable gzip compression of rotated log files
    #[arg(
        id = "logfile_compress",
        long = "logfile-compress",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(alias = "logfile_compress", skip_serializing_if = "Option::is_none")]
    pub compress: Option<bool>,

    /// Log level for file logging (default: same as --log-level)
    #[arg(id = "logfile_level", long = "logfile-level")]
    #[serde(alias = "logfile_level", skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

impl LogfileArgs {
    /// Fold this declaration into a [`LogfileConfig`].
    ///
    /// Defaults live on `LogfileConfig` / `rvc::config::Config`; load overlays Options.
    pub fn resolved(&self) -> LogfileConfig {
        LogfileConfig {
            path: self.path.clone(),
            max_size: self.max_size.unwrap_or_else(default_logfile_max_size),
            max_number: self.max_number.unwrap_or_else(default_logfile_max_number),
            compress: self.compress.unwrap_or(false),
            level: self.level.clone(),
        }
    }
}

/// Log-file rotation settings (resolved / `Config` field).
///
/// No flat-legacy `#[serde(alias)]` here: those bind inside `[logfile]` (4f SEC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogfileConfig {
    /// Path to the log file (`logfile` flat key, lifted by `Config`'s custom Deserialize).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Max size in MB before rotation.
    #[serde(default = "default_logfile_max_size")]
    pub max_size: u64,
    /// Max number of rotated files to keep.
    #[serde(default = "default_logfile_max_number")]
    pub max_number: usize,
    /// Compress rotated files.
    #[serde(default)]
    pub compress: bool,
    /// Optional override log level for the file sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

impl Default for LogfileConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_size: default_logfile_max_size(),
            max_number: default_logfile_max_number(),
            compress: false,
            level: None,
        }
    }
}
