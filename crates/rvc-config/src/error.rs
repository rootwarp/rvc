//! Config errors with provenance and no figment dependency.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

/// Layer that produced a config value (`defaults < file < CLI`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Built-in default.
    Default,
    /// TOML file at this path.
    File(PathBuf),
    /// Command-line flag.
    Cli,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::File(path) => write!(f, "file {}", path.display()),
            Self::Cli => write!(f, "cli"),
        }
    }
}

/// Configuration error that names the field and its provenance layer.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A field failed validation or parsing.
    #[error("{field}: {message} (from {source_layer})")]
    Invalid {
        /// Dotted field path (e.g. `metrics.port`).
        field: &'static str,
        /// Human-readable reason.
        message: String,
        /// Layer that supplied the bad value.
        source_layer: ConfigSource,
    },
}
