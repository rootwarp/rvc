//! Validator state for the forward-window doppelganger state machine.

use eth_types::Epoch;

/// Per-validator state in the forward-window doppelganger machine.
///
/// `Pending` counts closed not-live epochs down from
/// `monitoring_epochs + 1`. There is no end epoch: a gap does not open the
/// gate, and a live answer at any epoch `>= next_check_epoch` replaces the
/// variant with [`Detected`](ValidatorState::Detected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorState {
    /// Pubkey has never been registered with this machine.
    Unmonitored,
    /// Still waiting for `remaining` closed not-live epochs.
    ///
    /// `next_check_epoch` is the first epoch that may decrement or detect.
    /// `remaining` starts at `monitoring_epochs + 1` and hits `Safe` at 0.
    Pending { next_check_epoch: Epoch, remaining: u64 },
    /// `remaining` reached 0 with no live answer → safe to sign.
    Safe,
    /// An unexplained `is_live` was observed at an epoch `>= next_check_epoch`.
    ///
    /// `Detected` is terminal in the machine. `cancel`, `register`,
    /// `register_for_import`, `start_monitoring`, and `cancel_monitoring` do not
    /// remove or replace it, so a DELETE then re-import in this process stays
    /// `Detected`. The first transition also sets the process-wide detection
    /// latch under the same states lock. While that latch is set,
    /// [`crate::SigningEnablement::is_signing_enabled`] is false for every key.
    /// The latch is not cleared in this process. The durable marker in the
    /// validator data directory is what makes the next start exit 12.
    Detected,
}

/// Observable status returned by [`crate::ForwardWindowMachine::tick`] and
/// [`crate::ForwardWindowMachine::status`].
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

/// A validator the liveness loop still has to observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKey {
    /// Lowercase bare pubkey hex, the machine's state-map key.
    pub pubkey_hex: String,
    /// First epoch that may decrement this key or move it to `Detected`.
    pub next_check_epoch: Epoch,
}
