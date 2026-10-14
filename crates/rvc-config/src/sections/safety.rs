//! Startup safety toggles (ARCH-4h).
//!
//! Invented `[safety]` table. CLI polarity `--no-doppelganger-detection` stays
//! on the clap group; the TOML key is `doppelganger_detection`. Nested tables
//! accept section-relative names only (4f SEC). Flat top-level keys stay on
//! `ConfigWire`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Action taken when a managed validator is detected as slashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlashedAction {
    /// Disable the validator in the store and keep running.
    #[default]
    DisableOnly,
    /// Request process shutdown.
    Shutdown,
    /// Do not monitor / take no action.
    None,
}

impl fmt::Display for SlashedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisableOnly => write!(f, "disable-only"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::None => write!(f, "none"),
        }
    }
}

impl FromStr for SlashedAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable-only" => Ok(Self::DisableOnly),
            "shutdown" => Ok(Self::Shutdown),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid slashed-validators-action '{other}': must be one of disable-only, shutdown, none"
            )),
        }
    }
}

/// Clap + serde declaration for the `[safety]` knobs (ADR-008).
///
/// `--flag` strings stay the pre-move longs. `no_doppelganger_detection` is
/// CLI-only polarity; the TOML key is [`SafetyConfig::doppelganger_detection`].
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyArgs {
    /// Disable doppelganger / forward-window protection (enabled by default).
    ///
    /// When enabled (default), newly loaded and imported keys are withheld from
    /// signing for ~2 epochs (~12.8 min on mainnet) while network liveness is
    /// observed, mitigating double-signing if another live instance holds the
    /// same keys. Opting out removes that safety cost but exposes the process
    /// to the Staked 2021 / SSV-Ankr class of mass-slashing incidents.
    #[arg(long = "no-doppelganger-detection")]
    #[serde(skip)]
    pub no_doppelganger_detection: bool,

    /// Disable attestation duties at startup (emergency use only)
    #[arg(long = "disable-attesting")]
    #[serde(skip)]
    pub disable_attesting: bool,

    /// Action when a slashed validator is detected: disable-only (default), shutdown, none
    #[arg(long = "slashed-validators-action")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slashed_validators_action: Option<SlashedAction>,

    /// Allow startup when the beacon node's current fork version is not in
    /// the client's schedule (SEC-9 / M-15). For testnets / experimental
    /// forks only; default is fatal on unknown fork.
    #[arg(long = "allow-unsupported-fork", default_value_t = false)]
    #[serde(skip)]
    pub allow_unsupported_fork: bool,
}

impl SafetyArgs {
    /// Fold this declaration into a [`SafetyConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> SafetyConfig {
        SafetyConfig {
            allow_unsupported_fork: if self.allow_unsupported_fork { Some(true) } else { None },
            doppelganger_detection: if self.no_doppelganger_detection { Some(false) } else { None },
            disable_attesting: if self.disable_attesting { Some(true) } else { None },
            slashed_validators_action: self.slashed_validators_action,
        }
    }
}

/// `[safety]` table (section-relative names only; no flat aliases).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SafetyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_unsupported_fork: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doppelganger_detection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_attesting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slashed_validators_action: Option<SlashedAction>,
}
