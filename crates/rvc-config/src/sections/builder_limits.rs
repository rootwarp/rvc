//! Builder circuit-breaker section (ARCH-4g).
//!
//! **A-4.4:** the existing TOML `[builder_limits]` table wins; the clap group
//! is reshaped to match it. This is a deliberate refinement of ADR-008's
//! "the clap group *is* the section" — renaming the operator-visible table is
//! out of scope. `block_selection_mode`, `validator_registration_batch_size`,
//! and `validator_registration_batch_delay` stay top-level TOML knobs
//! (ARCH-4h will section them; 4g must not invent `[builder]`).
//!
//! Flat `builder_circuit_breaker_*` keys stay on `ConfigWire`. This `*Config`
//! accepts section-relative names only (4f SEC).

use serde::{Deserialize, Serialize};

fn default_circuit_breaker_consecutive_limit() -> u32 {
    3
}

fn default_circuit_breaker_epoch_limit() -> u32 {
    5
}

/// Clap + serde declaration for the `[builder_limits]` knobs (ADR-008 / A-4.4).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]` on this `*Args`
/// type only — not on [`BuilderLimits`].
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuilderLimitsArgs {
    /// Builder circuit breaker: consecutive missed slots before fallback to local block (default: 3, 0 to disable)
    #[arg(
        id = "builder_circuit_breaker_consecutive_limit",
        long = "builder-circuit-breaker-consecutive-limit"
    )]
    #[serde(
        alias = "builder_circuit_breaker_consecutive_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub circuit_breaker_consecutive_limit: Option<u32>,

    /// Builder circuit breaker: total epoch missed slots before fallback to local block (default: 5, 0 to disable)
    #[arg(
        id = "builder_circuit_breaker_epoch_limit",
        long = "builder-circuit-breaker-epoch-limit"
    )]
    #[serde(
        alias = "builder_circuit_breaker_epoch_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub circuit_breaker_epoch_limit: Option<u32>,
}

impl BuilderLimitsArgs {
    /// Fold this declaration into a [`BuilderLimits`].
    ///
    /// Defaults live on `BuilderLimits`; load overlays Option fields.
    pub fn resolved(&self) -> BuilderLimits {
        BuilderLimits {
            circuit_breaker_consecutive_limit: self
                .circuit_breaker_consecutive_limit
                .unwrap_or_else(default_circuit_breaker_consecutive_limit),
            circuit_breaker_epoch_limit: self
                .circuit_breaker_epoch_limit
                .unwrap_or_else(default_circuit_breaker_epoch_limit),
        }
    }
}

/// Builder circuit-breaker limits (resolved / `Config` field).
///
/// No flat-legacy `#[serde(alias)]` here: those bind inside `[builder_limits]`
/// (4f SEC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuilderLimits {
    #[serde(default = "default_circuit_breaker_consecutive_limit")]
    pub circuit_breaker_consecutive_limit: u32,
    #[serde(default = "default_circuit_breaker_epoch_limit")]
    pub circuit_breaker_epoch_limit: u32,
}

impl Default for BuilderLimits {
    fn default() -> Self {
        Self {
            circuit_breaker_consecutive_limit: default_circuit_breaker_consecutive_limit(),
            circuit_breaker_epoch_limit: default_circuit_breaker_epoch_limit(),
        }
    }
}
