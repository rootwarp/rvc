//! Validator state for the forward-window doppelganger state machine.

use std::collections::BTreeSet;

use eth_types::Epoch;

/// Per-validator state in the forward-window doppelganger machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorState {
    /// Pubkey has never been registered with this machine.
    Unmonitored,
    /// Validator is in the monitoring window.
    ///
    /// When `observe_liveness` receives `is_live == true` for this validator
    /// within the window, the whole variant is REPLACED by `Detected` — so
    /// there is no `detected_live: bool` field.  The `Detected` state is
    /// terminal and permanently denies signing.
    ///
    /// `observed_epochs` records which epochs in the monitoring window
    /// `[start_epoch, end_epoch]` have received a COMPLETE liveness response
    /// (i.e. the validator's pubkey-hex index was present in the beacon-node
    /// reply).  A `Safe` transition at the satisfaction boundary requires this
    /// set to contain every epoch in the inclusive window (D-2, Issue 2.7).
    Pending { start_epoch: Epoch, end_epoch: Epoch, observed_epochs: BTreeSet<Epoch> },
    /// Monitoring window completed with no unexplained liveness → safe to sign.
    Safe,
    /// An unexplained `is_live` was observed during the monitoring window.
    /// This state is TERMINAL: `tick` never transitions out of `Detected`.
    Detected,
}

/// Observable status returned by [`ForwardWindowMachine::tick`] and
/// [`ForwardWindowMachine::status`].
///
/// Named `ForwardWindowStatus` (not `DoppelgangerStatus`) to avoid confusion
/// with the 3-variant crate-level [`crate::DoppelgangerStatus`].
///
/// `Copy` so callers can cheaply pass it around without cloning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardWindowStatus {
    /// Pubkey is unknown to this machine.
    Unmonitored,
    /// Monitoring window is active.
    Pending,
    /// Monitoring complete; signing allowed.
    Safe,
    /// Doppelganger detected; signing denied.
    Detected,
}
