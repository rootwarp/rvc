//! Keymanager API section (ARCH-4f).
//!
//! Clap group, TOML `[keymanager]` table, and `Config.keymanager` share this module.
//! Valued knobs are `Option<T>` with no clap `default_value` (ADR-009).
//! `--no-keymanager` is CLI-only and is skipped on the serde wire.
//!
//! The three import-KDF knobs (RR2-10) default to the same numbers as
//! `KdfBudgetConfig` in `rvc`. This crate cannot name that type (`rvc` depends
//! on `rvc-config`); a const assert next to `KdfBudgetConfig::default` keeps
//! them locked. They are not `key_decrypt_threads` (startup keystore load).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_keymanager_body_limit() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// Concurrent import KDF derivations when the knob is unset.
///
/// Lock-step with `KdfBudgetConfig::default().concurrency`.
pub const DEFAULT_IMPORT_KDF_CONCURRENCY: u32 = 2;

/// Accounted import KDF working-set budget, in MiB, when the knob is unset.
///
/// Lock-step with `KdfBudgetConfig::default().total_bytes` (512 MiB).
pub const DEFAULT_IMPORT_KDF_TOTAL_MIB: u32 = 512;

/// Per-keystore import KDF cap, in MiB, when the knob is unset.
///
/// Lock-step with `MAX_KDF_WORKING_SET_BYTES / 1 MiB` (8192). The operator
/// knob is tighten-only: `Config::validate` rejects any larger value.
pub const DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB: u32 = 8192;

/// Inclusive upper bound for [`KeymanagerArgs::keymanager_import_kdf_concurrency`].
pub const MAX_IMPORT_KDF_CONCURRENCY: u32 = 32;

fn default_import_kdf_concurrency() -> u32 {
    DEFAULT_IMPORT_KDF_CONCURRENCY
}

fn default_import_kdf_total_mib() -> u32 {
    DEFAULT_IMPORT_KDF_TOTAL_MIB
}

fn default_import_kdf_max_keystore_mib() -> u32 {
    DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB
}

fn skip_default_import_kdf_concurrency(value: &u32) -> bool {
    *value == DEFAULT_IMPORT_KDF_CONCURRENCY
}

fn skip_default_import_kdf_total_mib(value: &u32) -> bool {
    *value == DEFAULT_IMPORT_KDF_TOTAL_MIB
}

fn skip_default_import_kdf_max_keystore_mib(value: &u32) -> bool {
    *value == DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB
}

/// Clap + serde declaration for the keymanager knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeymanagerArgs {
    /// Enable the Keymanager API server
    #[arg(
        id = "keymanager_enabled",
        long = "keymanager-enabled",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(alias = "keymanager_enabled", skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Disable the Keymanager API server (overrides config file)
    #[arg(long = "no-keymanager", conflicts_with = "keymanager_enabled")]
    #[serde(skip)]
    pub no_keymanager: bool,

    /// Bind address for the Keymanager API server (default: 127.0.0.1:5062)
    #[arg(id = "keymanager_address", long = "keymanager-address")]
    #[serde(alias = "keymanager_address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// Path to the Keymanager API bearer token file
    #[arg(id = "keymanager_token_file", long = "keymanager-token-file")]
    #[serde(alias = "keymanager_token_file", skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,

    /// Remote signer (Web3Signer) URL
    #[arg(long = "remote-signer-url")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,

    /// Comma-separated list of allowed remote signer hostnames
    #[arg(long = "remote-signer-allowed-hosts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<String>,

    /// Allow HTTP (non-TLS) URLs for remote signer imports
    #[arg(
        long = "allow-insecure-remote-signer",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure_remote_signer: Option<bool>,

    /// Comma-separated list of allowed CORS origins for the Keymanager API
    #[arg(id = "keymanager_cors_origins", long = "keymanager-cors-origins", value_delimiter = ',')]
    #[serde(alias = "keymanager_cors_origins", skip_serializing_if = "Option::is_none")]
    pub cors_origins: Option<Vec<String>>,

    /// Maximum request body size in bytes for the Keymanager API (default: 10 MB)
    #[arg(id = "keymanager_body_limit", long = "keymanager-body-limit")]
    #[serde(alias = "keymanager_body_limit", skip_serializing_if = "Option::is_none")]
    pub body_limit: Option<usize>,

    /// Concurrent KDF derivations during keystore import (default when unset: 2).
    ///
    /// Not `--key-decrypt-threads` (startup keystore load). Valid range is `1..=32`.
    #[arg(id = "keymanager_import_kdf_concurrency", long = "keymanager-import-kdf-concurrency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_import_kdf_concurrency: Option<u32>,

    /// Accounted KDF working-set budget for keystore import, in MiB (default when unset: 512).
    ///
    /// Not `--key-decrypt-threads`. Must be at least 1.
    #[arg(id = "keymanager_import_kdf_total_mib", long = "keymanager-import-kdf-total-mib")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_import_kdf_total_mib: Option<u32>,

    /// Per-keystore KDF working-set cap, in MiB (default when unset: 8192).
    ///
    /// Tighten-only: a value above the decrypt working-set ceiling is rejected.
    /// Not `--key-decrypt-threads`.
    #[arg(
        id = "keymanager_import_kdf_max_keystore_mib",
        long = "keymanager-import-kdf-max-keystore-mib"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_import_kdf_max_keystore_mib: Option<u32>,
}

impl KeymanagerArgs {
    /// Fold this declaration into a [`KeymanagerConfig`].
    ///
    /// Defaults live on `KeymanagerConfig`; load overlays Option fields.
    /// There is no clap `default_value`: an absent flag stays `None`.
    pub fn resolved(&self) -> KeymanagerConfig {
        let enabled = if self.no_keymanager { false } else { self.enabled.unwrap_or(false) };
        KeymanagerConfig {
            enabled,
            address: self.address.clone(),
            token_file: self.token_file.clone(),
            remote_signer_url: self.remote_signer_url.clone(),
            remote_signer_allowed_hosts: self.remote_signer_allowed_hosts.as_ref().map(|csv| {
                csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
            }),
            allow_insecure_remote_signer: self.allow_insecure_remote_signer.unwrap_or(false),
            cors_origins: self.cors_origins.clone().unwrap_or_default(),
            body_limit: self.body_limit.unwrap_or_else(default_keymanager_body_limit),
            keymanager_import_kdf_concurrency: self
                .keymanager_import_kdf_concurrency
                .unwrap_or(DEFAULT_IMPORT_KDF_CONCURRENCY),
            keymanager_import_kdf_total_mib: self
                .keymanager_import_kdf_total_mib
                .unwrap_or(DEFAULT_IMPORT_KDF_TOTAL_MIB),
            keymanager_import_kdf_max_keystore_mib: self
                .keymanager_import_kdf_max_keystore_mib
                .unwrap_or(DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB),
        }
    }
}

/// Keymanager API and remote-signer settings (resolved / `Config` field).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeymanagerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure_remote_signer: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_origins: Vec<String>,
    #[serde(default = "default_keymanager_body_limit")]
    pub body_limit: usize,
    /// Concurrent import KDF derivations. `Config::validate` requires `1..=32`.
    #[serde(
        default = "default_import_kdf_concurrency",
        skip_serializing_if = "skip_default_import_kdf_concurrency"
    )]
    pub keymanager_import_kdf_concurrency: u32,
    /// Accounted import KDF budget, in MiB. `Config::validate` requires `>= 1`.
    #[serde(
        default = "default_import_kdf_total_mib",
        skip_serializing_if = "skip_default_import_kdf_total_mib"
    )]
    pub keymanager_import_kdf_total_mib: u32,
    /// Per-keystore import KDF cap, in MiB. Tighten-only against the decrypt ceiling.
    #[serde(
        default = "default_import_kdf_max_keystore_mib",
        skip_serializing_if = "skip_default_import_kdf_max_keystore_mib"
    )]
    pub keymanager_import_kdf_max_keystore_mib: u32,
}

impl Default for KeymanagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: None,
            token_file: None,
            remote_signer_url: None,
            remote_signer_allowed_hosts: None,
            allow_insecure_remote_signer: false,
            cors_origins: Vec::new(),
            body_limit: default_keymanager_body_limit(),
            keymanager_import_kdf_concurrency: DEFAULT_IMPORT_KDF_CONCURRENCY,
            keymanager_import_kdf_total_mib: DEFAULT_IMPORT_KDF_TOTAL_MIB,
            keymanager_import_kdf_max_keystore_mib: DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser, Debug)]
    #[command(name = "keymanager-probe", no_binary_name = true)]
    struct Probe {
        #[command(flatten)]
        keymanager: KeymanagerArgs,
    }

    #[test]
    fn resolved_kdf_fold_uses_constants_not_clap_defaults() {
        let absent = Probe::try_parse_from(std::iter::empty::<&str>()).expect("empty argv");
        assert!(absent.keymanager.keymanager_import_kdf_concurrency.is_none());
        assert!(absent.keymanager.keymanager_import_kdf_total_mib.is_none());
        assert!(absent.keymanager.keymanager_import_kdf_max_keystore_mib.is_none());
        let folded = absent.keymanager.resolved();
        assert_eq!(folded.keymanager_import_kdf_concurrency, DEFAULT_IMPORT_KDF_CONCURRENCY);
        assert_eq!(folded.keymanager_import_kdf_total_mib, DEFAULT_IMPORT_KDF_TOTAL_MIB);
        assert_eq!(
            folded.keymanager_import_kdf_max_keystore_mib,
            DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB
        );
        assert_eq!(DEFAULT_IMPORT_KDF_CONCURRENCY, 2);
        assert_eq!(DEFAULT_IMPORT_KDF_TOTAL_MIB, 512);
        assert_eq!(DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB, 8192);
        assert_eq!(MAX_IMPORT_KDF_CONCURRENCY, 32);
    }

    #[test]
    fn kdf_flags_parse_without_a_clap_default_value() {
        let src = include_str!("keymanager.rs");
        for line in src.lines() {
            if !line.contains("keymanager_import_kdf_") && !line.contains("keymanager-import-kdf-")
            {
                continue;
            }
            assert!(
                !line.contains("default_value"),
                "import KDF knob must not set a clap default_value: {line}"
            );
        }
        let parsed = Probe::try_parse_from([
            "--keymanager-import-kdf-concurrency",
            "4",
            "--keymanager-import-kdf-total-mib",
            "256",
            "--keymanager-import-kdf-max-keystore-mib",
            "1024",
        ])
        .expect("flags");
        assert_eq!(parsed.keymanager.keymanager_import_kdf_concurrency, Some(4));
        assert_eq!(parsed.keymanager.keymanager_import_kdf_total_mib, Some(256));
        assert_eq!(parsed.keymanager.keymanager_import_kdf_max_keystore_mib, Some(1024));
        let folded = parsed.keymanager.resolved();
        assert_eq!(folded.keymanager_import_kdf_concurrency, 4);
        assert_eq!(folded.keymanager_import_kdf_total_mib, 256);
        assert_eq!(folded.keymanager_import_kdf_max_keystore_mib, 1024);
    }

    #[test]
    fn empty_keymanager_table_uses_kdf_defaults() {
        let cfg: KeymanagerConfig = toml::from_str("").expect("empty");
        assert_eq!(cfg.keymanager_import_kdf_concurrency, DEFAULT_IMPORT_KDF_CONCURRENCY);
        assert_eq!(cfg.keymanager_import_kdf_total_mib, DEFAULT_IMPORT_KDF_TOTAL_MIB);
        assert_eq!(cfg.keymanager_import_kdf_max_keystore_mib, DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB);
    }

    #[test]
    fn keymanager_table_parses_import_kdf_knobs() {
        let cfg: KeymanagerConfig = toml::from_str(
            "keymanager_import_kdf_concurrency = 8\n\
             keymanager_import_kdf_total_mib = 128\n\
             keymanager_import_kdf_max_keystore_mib = 64\n",
        )
        .expect("section fields");
        assert_eq!(cfg.keymanager_import_kdf_concurrency, 8);
        assert_eq!(cfg.keymanager_import_kdf_total_mib, 128);
        assert_eq!(cfg.keymanager_import_kdf_max_keystore_mib, 64);
    }
}
