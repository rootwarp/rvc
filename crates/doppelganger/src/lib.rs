//! Doppelganger detection for Ethereum validator clients.
//!
//! Detects if another instance is running with the same validator keys.
//! Implements restart-awareness (Lodestar pattern) to avoid false positives
//! when a validator client restarts after recently signing attestations.

mod enablement;
mod epoch_clock;
mod error;
mod forward_window;
mod restart_skip;
mod state;
mod traits;

pub use enablement::{DoppelgangerDisabledByOperator, SigningEnablement};
pub use epoch_clock::MonotonicEpochClock;
pub use error::DoppelgangerError;
pub use forward_window::ForwardWindowMachine;
pub use restart_skip::should_skip_restart_monitoring;
pub use state::{ForwardWindowStatus, ValidatorState};
pub use traits::{LivenessChecker, ValidatorLivenessData};

/// Default forward-window length in epochs (≈ 2 epochs / ~12.8 min on mainnet).
///
/// Shared by [`crate::ForwardWindowMachine`] production wiring (SEC-2b).
pub const DEFAULT_MONITORING_EPOCHS: u64 = 2;

/// Status of doppelganger detection for a validator.
///
/// Distinct from [`ForwardWindowStatus`], which is the 4-variant status for
/// [`ForwardWindowMachine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoppelgangerStatus {
    /// Validator is safe to sign (restart-aware skip or monitoring complete).
    Safe,
    /// Detection is still in progress.
    DetectionInProgress,
    /// A doppelganger was detected for this validator.
    DoppelgangerDetected,
}

/// Result of a doppelganger check for a set of validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoppelgangerResult {
    /// Validators that are safe to sign.
    pub safe_validators: Vec<String>,
    /// Validators for which a doppelganger was detected.
    pub detected: Vec<String>,
}
