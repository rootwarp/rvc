//! Configuration error types.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Field-level error that names the provenance layer (`defaults < file < CLI`).
    #[error("{field}: {message} (from {source_layer})")]
    Invalid {
        /// Dotted field path (e.g. `config`).
        field: &'static str,
        /// Human-readable reason.
        message: String,
        /// Layer that supplied the bad value.
        source_layer: rvc_config::ConfigSource,
    },

    #[error("invalid beacon URL: {0}")]
    InvalidBeaconUrl(String),

    #[error("keystore path does not exist: {0}")]
    KeystorePathNotFound(PathBuf),

    #[error("slashing db path parent directory does not exist: {0}")]
    SlashingDbPathInvalid(PathBuf),

    /// Missing slashing DB without an explicit operator opt-in (SEC-3).
    ///
    /// Creating a fresh empty DB would let the process sign with **zero history**.
    /// For a genuine new deployment, pass `--init-slashing-db` or set
    /// `allow_fresh_db = true` in the config file.
    #[error(
        "slashing protection database does not exist at {0}. \
         Refusing to create a fresh empty DB (would sign with zero history). \
         For a genuine new deployment, pass --init-slashing-db or set \
         allow_fresh_db = true in config. If this path should hold existing \
         history, restore the DB from backup."
    )]
    SlashingDbMissing(PathBuf),

    /// 0-byte or corrupt-header slashing DB (SEC-3). Always a hard error.
    #[error(
        "slashing protection database at {0} is empty or corrupt \
         (0-byte or invalid SQLite header). This indicates truncation or \
         corruption — never treated as a fresh init. Restore from backup; \
         --init-slashing-db / allow_fresh_db cannot override this."
    )]
    SlashingDbCorrupt(PathBuf),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid port number: {0}")]
    InvalidPort(u16),

    /// Leftover `grpc_port` / `grpc_address` after the healthz listener was
    /// removed. Presence must fail startup; otherwise leftover TOML is ignored.
    #[error(
        "`{key}` was removed in this release (gRPC healthz listener is gone). \
         Use {replacement} instead"
    )]
    RemovedKey {
        /// Operator-facing key (`grpc_port` or `grpc_address`).
        key: &'static str,
        /// Probe that replaces the removed listener.
        replacement: &'static str,
    },

    #[error("invalid graffiti: {0}")]
    InvalidGraffiti(String),

    #[error("password file not found: {0}")]
    PasswordFileNotFound(PathBuf),

    #[error("failed to read password file: {0}")]
    PasswordReadError(String),

    #[error("key manager error: {0}")]
    KeyManagerError(#[from] crypto::KeyManagerError),

    #[error("slashing db error: {0}")]
    SlashingDbError(#[from] slashing::SlashingError),

    #[error("beacon client error: {0}")]
    BeaconClientError(#[from] beacon::BeaconError),

    #[error("feature not enabled: {0}")]
    FeatureNotEnabled(String),

    #[error("secret provider error: {0}")]
    SecretProviderError(String),

    #[error(
        "--allow-insecure-remote-signer requires RVC_ALLOW_INSECURE=true environment variable"
    )]
    InsecureFlagRequiresEnvVar,

    /// Returned when the effective default fee recipient is the zero address.
    ///
    /// All EL fees and MEV rewards would be silently routed to the burn
    /// address.  Operators must set a non-zero address in their validators
    /// config file:
    ///
    /// ```toml
    /// [defaults]
    /// fee_recipient = "0x<your-fee-address>"
    /// ```
    #[error(
        "default_fee_recipient is the zero address \
         (0x0000000000000000000000000000000000000000), which routes all EL \
         fees and MEV rewards to the burn address.\n\
         Set a non-zero fee_recipient in your validators config file:\n\
         \n\
         [defaults]\n\
         fee_recipient = \"0x<your-fee-address>\"\n\
         \n\
         Pass the file with --validators-config <path>."
    )]
    ZeroFeeRecipient,

    /// Wraps a `ValidatorStoreError` that occurs during validator store construction.
    #[error("validator store error: {0}")]
    ValidatorStoreError(String),
}

impl From<rvc_config::ConfigError> for ConfigError {
    fn from(err: rvc_config::ConfigError) -> Self {
        match err {
            rvc_config::ConfigError::Invalid { field, message, source_layer } => {
                Self::Invalid { field, message, source_layer }
            }
        }
    }
}
