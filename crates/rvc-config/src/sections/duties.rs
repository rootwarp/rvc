//! Concurrent duty dispatch (`[duties]`).
//!
//! Clap fields are `Option` with **no** `default_value` (ADR-009 / clause iv).
//! [`DutiesArgs::resolved`] folds an unset flag to
//! [`DEFAULT_DUTY_DISPATCH_CONCURRENCY`] (32) or
//! [`DEFAULT_DUTY_PUBLISH_CONCURRENCY`] (2). Those are the same numbers as
//! `DispatchLimits::DEFAULT_CONCURRENCY` / `DEFAULT_PUBLISH_CONCURRENCY` in
//! `rvc` — this crate cannot name that type (`rvc` depends on `rvc-config`).
//! A compile-time assert in `orchestrator/dispatch.rs` keeps them locked.

use clap::Args;
use serde::{Deserialize, Serialize};

/// Sign-request concurrency used when `--duty-dispatch-concurrency` is absent.
///
/// Lock-step with `DispatchLimits::DEFAULT_CONCURRENCY`.
pub const DEFAULT_DUTY_DISPATCH_CONCURRENCY: u32 = 32;

/// Publish-wave concurrency used when `--duty-publish-concurrency` is absent.
///
/// Lock-step with `DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY`.
pub const DEFAULT_DUTY_PUBLISH_CONCURRENCY: u32 = 2;

/// Clap declaration for the `[duties]` knobs.
///
/// Field names match the operator knob ids. There is no `default_value`: an
/// absent flag stays `None` so it cannot clobber TOML.
#[derive(Debug, Clone, PartialEq, Eq, Default, Args)]
pub struct DutiesArgs {
    /// In-flight attestation sign requests per wave (default when unset: 32).
    #[arg(id = "duty_dispatch_concurrency", long = "duty-dispatch-concurrency")]
    pub duty_dispatch_concurrency: Option<u32>,

    /// In-flight publish waves (default when unset: 2).
    #[arg(id = "duty_publish_concurrency", long = "duty-publish-concurrency")]
    pub duty_publish_concurrency: Option<u32>,
}

impl DutiesArgs {
    /// Fold unset flags onto the `[duties]` defaults.
    ///
    /// `Config::load` does not call this. It overlays present flags onto a
    /// `DutiesConfig` that already carries the defaults.
    pub fn resolved(&self) -> DutiesConfig {
        DutiesConfig {
            duty_dispatch_concurrency: self
                .duty_dispatch_concurrency
                .unwrap_or(DEFAULT_DUTY_DISPATCH_CONCURRENCY),
            duty_publish_concurrency: self
                .duty_publish_concurrency
                .unwrap_or(DEFAULT_DUTY_PUBLISH_CONCURRENCY),
        }
    }
}

/// Resolved `[duties]` table.
///
/// Unknown keys fail deserialize so a typo cannot sit inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DutiesConfig {
    /// Sign requests per wave. `Config::validate` requires `1..=512`.
    pub duty_dispatch_concurrency: u32,
    /// Publish waves in flight. `Config::validate` requires `1..=16`.
    pub duty_publish_concurrency: u32,
}

impl Default for DutiesConfig {
    fn default() -> Self {
        Self {
            duty_dispatch_concurrency: DEFAULT_DUTY_DISPATCH_CONCURRENCY,
            duty_publish_concurrency: DEFAULT_DUTY_PUBLISH_CONCURRENCY,
        }
    }
}

impl DutiesConfig {
    /// `true` when both knobs are at the built-in defaults (omit from snapshots).
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser, Debug)]
    #[command(name = "duties-probe", no_binary_name = true)]
    struct Probe {
        #[command(flatten)]
        duties: DutiesArgs,
    }

    #[test]
    fn resolved_fold_uses_constants_not_clap_defaults() {
        let absent = Probe::try_parse_from(std::iter::empty::<&str>()).expect("empty argv");
        assert!(absent.duties.duty_dispatch_concurrency.is_none());
        assert!(absent.duties.duty_publish_concurrency.is_none());
        let folded = absent.duties.resolved();
        assert_eq!(folded.duty_dispatch_concurrency, DEFAULT_DUTY_DISPATCH_CONCURRENCY);
        assert_eq!(folded.duty_publish_concurrency, DEFAULT_DUTY_PUBLISH_CONCURRENCY);
        assert_eq!(DEFAULT_DUTY_DISPATCH_CONCURRENCY, 32);
        assert_eq!(DEFAULT_DUTY_PUBLISH_CONCURRENCY, 2);
    }

    #[test]
    fn flags_parse_and_override_the_fold() {
        let parsed = Probe::try_parse_from([
            "--duty-dispatch-concurrency",
            "64",
            "--duty-publish-concurrency",
            "4",
        ])
        .expect("flags");
        assert_eq!(parsed.duties.duty_dispatch_concurrency, Some(64));
        assert_eq!(parsed.duties.duty_publish_concurrency, Some(4));
        let folded = parsed.duties.resolved();
        assert_eq!(folded.duty_dispatch_concurrency, 64);
        assert_eq!(folded.duty_publish_concurrency, 4);
    }

    #[test]
    fn empty_table_uses_defaults() {
        let cfg: DutiesConfig = toml::from_str("").expect("empty");
        assert!(cfg.is_default());
        assert_eq!(cfg.duty_dispatch_concurrency, 32);
        assert_eq!(cfg.duty_publish_concurrency, 2);
    }

    #[test]
    fn unknown_duties_key_fails_naming_the_key() {
        let err = toml::from_str::<DutiesConfig>("not_a_duties_key = 1")
            .expect_err("unknown duties key must fail");
        let msg = err.to_string();
        assert!(msg.contains("not_a_duties_key"), "{msg}");
    }
}
