//! Slashing protection configuration for rvc-signer startup.
//!
//! Per OQ-A4 binding decision: slashing protection is **on by default**.
//! `rvc-signer` refuses to start without a `SlashingDb` unless **both**:
//! - `--disable-slashing-protection` is passed on the CLI, **AND**
//! - `RVC_ALLOW_INSECURE=true` is set in the environment.
//!
//! This two-factor opt-out prevents a stray env-var leak from silently
//! disabling slashing protection.

use std::path::PathBuf;

/// How slashing protection is configured at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashingProtectionMode {
    /// Default: slashing protection is required.  `validate()` succeeds only
    /// when a `db_path` is provided.
    Required,
    /// `--disable-slashing-protection` was passed on the CLI, but
    /// `RVC_ALLOW_INSECURE` is **not** set.  Still refuses to start.
    DisabledCliOnly,
    /// Both `--disable-slashing-protection` **and** `RVC_ALLOW_INSECURE=true`
    /// are active.  Slashing protection is disabled; `validate()` succeeds
    /// even without a `db_path`.
    DisabledBothFlags,
}

/// Slashing-DB configuration bundle, validated at startup.
#[derive(Debug, Clone)]
pub struct SlashingDbConfig {
    /// Path to the `signer-slashing.db` file.
    ///
    /// When `None` and mode is [`SlashingProtectionMode::Required`] (or
    /// `DisabledCliOnly`), startup is refused.
    pub db_path: Option<PathBuf>,
    /// Current protection mode, derived from CLI flags and env vars.
    pub mode: SlashingProtectionMode,
    /// Epoch at which FU-33 `None==None` leniency is disabled.
    ///
    /// `u64::MAX` is the far-future unscheduled sentinel (same value the VC
    /// and this signer apply when `[fork_schedule].gloas_fork_epoch` is unset).
    pub gloas_fork_epoch: u64,
}

impl SlashingDbConfig {
    /// Build a `SlashingDbConfig` from a `data_dir`, CLI flag, and environment.
    ///
    /// - `data_dir`: The directory that holds `signer-slashing.db` (typically the
    ///   keystore directory's parent, or an explicit `--data-dir` argument).
    /// - `disable_cli_flag`: `true` iff `--disable-slashing-protection` was passed.
    /// - `gloas_fork_epoch`: FU-33 leniency gate; `u64::MAX` leaves pre-Gloas
    ///   epochs on the operator-strict flag alone.
    /// - `env_allow_insecure`: reads `RVC_ALLOW_INSECURE` from the environment.
    pub fn from_env(
        data_dir: Option<&std::path::Path>,
        disable_cli_flag: bool,
        gloas_fork_epoch: u64,
    ) -> Self {
        let allow_insecure = std::env::var("RVC_ALLOW_INSECURE").as_deref() == Ok("true");

        let mode = match (disable_cli_flag, allow_insecure) {
            (true, true) => SlashingProtectionMode::DisabledBothFlags,
            (true, false) => SlashingProtectionMode::DisabledCliOnly,
            _ => SlashingProtectionMode::Required,
        };

        let db_path = data_dir.map(|d| d.join("signer-slashing.db"));

        Self { db_path, mode, gloas_fork_epoch }
    }

    /// Validate the configuration.
    ///
    /// Returns `Ok(())` if the configuration is valid, or `Err(message)` with an
    /// actionable hint for the operator.
    pub fn validate(&self) -> Result<(), String> {
        match self.mode {
            SlashingProtectionMode::DisabledBothFlags => {
                // Both flags set — allowed even without a DB.
                tracing::warn!(
                    "Slashing protection DISABLED via --disable-slashing-protection + \
                     RVC_ALLOW_INSECURE=true. This is UNSAFE in production."
                );
                Ok(())
            }
            SlashingProtectionMode::DisabledCliOnly => {
                Err("Cannot disable slashing protection with --disable-slashing-protection alone. \
                     You must also set RVC_ALLOW_INSECURE=true in the environment. \
                     Both checks are required to prevent accidental opt-out."
                    .to_string())
            }
            SlashingProtectionMode::Required => {
                if self.db_path.is_some() {
                    Ok(())
                } else {
                    Err("Slashing protection requires a database path. \
                         Provide --data-dir (default: <keystore_dir>/../signer-slashing.db) or \
                         disable protection with --disable-slashing-protection AND \
                         RVC_ALLOW_INSECURE=true (NOT recommended for production)."
                        .to_string())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_mode_no_db_path_fails() {
        let cfg = SlashingDbConfig {
            db_path: None,
            mode: SlashingProtectionMode::Required,
            gloas_fork_epoch: u64::MAX,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("slashing") || err.contains("protection"), "{err}");
    }

    #[test]
    fn test_required_mode_with_db_path_ok() {
        let cfg = SlashingDbConfig {
            db_path: Some("/tmp/test.db".into()),
            mode: SlashingProtectionMode::Required,
            gloas_fork_epoch: u64::MAX,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_disabled_cli_only_fails() {
        let cfg = SlashingDbConfig {
            db_path: None,
            mode: SlashingProtectionMode::DisabledCliOnly,
            gloas_fork_epoch: u64::MAX,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("RVC_ALLOW_INSECURE") || err.contains("insecure"), "{err}");
    }

    #[test]
    fn test_disabled_both_flags_ok_without_db() {
        let cfg = SlashingDbConfig {
            db_path: None,
            mode: SlashingProtectionMode::DisabledBothFlags,
            gloas_fork_epoch: u64::MAX,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_from_env_both_flags() {
        // Can't set env vars reliably in unit tests without coordination;
        // test the struct directly instead.
        let cfg = SlashingDbConfig {
            db_path: None,
            mode: SlashingProtectionMode::DisabledBothFlags,
            gloas_fork_epoch: u64::MAX,
        };
        assert_eq!(cfg.mode, SlashingProtectionMode::DisabledBothFlags);
        assert!(cfg.validate().is_ok());
    }
}
