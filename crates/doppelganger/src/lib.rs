//! Doppelganger detection for Ethereum validator clients.
//!
//! Detects if another instance is running with the same validator keys.
//! Implements restart-awareness (Lodestar pattern) to avoid false positives
//! when a validator client restarts after recently signing attestations.

mod enablement;
mod epoch_clock;
mod forward_window;
mod restart_skip;
mod state;
mod traits;

pub use enablement::{
    signing_allowed, DoppelgangerDisabledByOperator, SigningDuty, SigningEnablement,
};
pub use epoch_clock::MonotonicEpochClock;
pub use forward_window::{EpochLiveness, ForwardWindowMachine};
pub use restart_skip::should_skip_restart_monitoring;
pub use state::{ForwardWindowStatus, PendingKey, ValidatorState};
pub use traits::ValidatorLivenessData;

/// Default forward-window length in epochs.
///
/// The remaining-epoch counter starts at this value plus one
/// ([`CLOSED_EPOCH_SLOT`] answers). Shared by [`crate::ForwardWindowMachine`]
/// production wiring (SEC-2b).
pub const DEFAULT_MONITORING_EPOCHS: u64 = 2;

/// Slot of epoch `e + 1` at which an answer for epoch `e` counts as closed.
///
/// Three quarters of [`eth_types::SLOTS_PER_EPOCH`]. An answer taken earlier
/// can still detect a live validator. It does not decrement the
/// remaining-epoch counter.
pub const CLOSED_EPOCH_SLOT: u64 = eth_types::SLOTS_PER_EPOCH * 3 / 4;
