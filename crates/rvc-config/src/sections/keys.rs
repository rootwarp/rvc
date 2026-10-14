//! Keys clap group and `[keys]` table (ARCH-4g / ARCH-4h).
//!
//! Created in 4g so [`KeysArgs`] can flatten [`SecretProviderArgs`] (A-4.5).
//! Nested flatten is clap-supported; the sibling-group fallback is not taken.
//!
//! ARCH-4h adds the `[keys]` TOML table for the five remaining bare knobs.
//! `[keys]` deserializes through [`KeysConfig`], not [`KeysArgs`], so
//! `secret_provider` stays its own table (A-4.5). `disable_keystore_locking`
//! is `Option<bool>` (no `#[serde(skip)]`) so `disable_keystore_locking = true`
//! is not dropped.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::secret_provider::SecretProviderArgs;

/// Clap group for keystore paths plus flattened [`SecretProviderArgs`] (A-4.5).
///
/// `[secret_provider]` stays its own table. `[keys]` deserializes through
/// [`KeysConfig`] (no `secret_provider` field).
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysArgs {
    /// Path to the keystore directory
    #[arg(long = "keystore-path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_path: Option<PathBuf>,

    /// Path to the password file for keystore decryption
    #[arg(long = "password-file")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,

    /// Number of threads for parallel keystore decryption (default: auto-detect)
    #[arg(long = "key-decrypt-threads")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,

    /// Disable keystore file locking (for DVT setups with shared key material)
    #[arg(
        long = "disable-keystore-locking",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_keystore_locking: Option<bool>,

    /// Path to a TOML file containing per-validator fee_recipient and gas_limit overrides.
    /// rvc refuses to start if default_fee_recipient is the zero address (0x000…000).
    ///
    /// Example file:
    ///   [defaults]
    ///   fee_recipient = "0xYourAddress"
    ///   gas_limit = 30000000
    #[arg(long = "validators-config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators_config: Option<PathBuf>,

    /// `[secret_provider]` knobs (A-4.5). Clap-flattened so `--gcp-project-id`
    /// stays a top-level flag. Not part of the `[keys]` TOML table.
    #[command(flatten)]
    #[serde(skip)]
    pub secret_provider: SecretProviderArgs,
}

impl KeysArgs {
    /// Fold the five `[keys]` knobs into a [`KeysConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> KeysConfig {
        KeysConfig {
            keystore_path: self.keystore_path.clone(),
            password_file: self.password_file.clone(),
            key_decrypt_threads: self.key_decrypt_threads,
            disable_keystore_locking: self.disable_keystore_locking,
            validators_config: self.validators_config.clone(),
        }
    }
}

/// `[keys]` table (section-relative names only; no flat aliases).
///
/// Does not include `secret_provider` — that stays `[secret_provider]` (A-4.5).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KeysConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keystore_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_keystore_locking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validators_config: Option<PathBuf>,
}
