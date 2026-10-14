//! Shared restart-aware safe-skip predicate for doppelganger detection.
//!
//! [`crate::ForwardWindowMachine::register`] uses this predicate so the
//! pre-genesis guard and recency window cannot drift.

use eth_types::Epoch;

/// Whether a validator may skip monitoring because local slashing history
/// shows a recent attestation (VC restart, not a second concurrent instance).
///
/// Returns `true` only when all of the following hold:
/// 1. `last_signed_epoch` is `Some`,
/// 2. `last_signed_epoch <= current_epoch` — future history is never treated as
///    a recent restart (would collapse to distance 0 under saturating sub and
///    open the enablement gate without a liveness window),
/// 3. `current_epoch > monitoring_epochs` (blocks pre-genesis / low-epoch bypass
///    where any history would look recent),
/// 4. `current_epoch - last_signed_epoch <= monitoring_epochs`
///    (attestation is still within the monitoring window).
///
/// Used by the forward-window machine.
#[must_use]
pub fn should_skip_restart_monitoring(
    current_epoch: Epoch,
    last_signed_epoch: Option<Epoch>,
    monitoring_epochs: u64,
) -> bool {
    let Some(epoch) = last_signed_epoch else {
        return false;
    };
    // Future targets (interchange import, clock lag) must force monitoring.
    if epoch > current_epoch {
        return false;
    }
    current_epoch > monitoring_epochs && current_epoch - epoch <= monitoring_epochs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_skip_predicate_skips_only_restarted_keys() {
        // Recent attestation within window → skip (restart).
        assert!(should_skip_restart_monitoring(100, Some(99), 2));
        assert!(should_skip_restart_monitoring(100, Some(100), 2));
        // Edge of window (distance == monitoring_epochs) → skip.
        assert!(should_skip_restart_monitoring(100, Some(98), 2));

        // Just outside window → no skip.
        assert!(!should_skip_restart_monitoring(100, Some(97), 2));
        // No prior attestation → no skip.
        assert!(!should_skip_restart_monitoring(100, None, 2));
        // Stale history far in the past → no skip.
        assert!(!should_skip_restart_monitoring(10_000, Some(0), 2));

        // Pre-genesis / low-epoch guard: current_epoch <= monitoring_epochs.
        assert!(!should_skip_restart_monitoring(0, Some(0), 2));
        assert!(!should_skip_restart_monitoring(1, Some(1), 2));
        assert!(!should_skip_restart_monitoring(2, Some(2), 2)); // 2 > 2 is false
                                                                 // Just above the guard with recent history → skip.
        assert!(should_skip_restart_monitoring(3, Some(2), 2));
    }

    #[test]
    fn test_restart_skip_predicate_custom_window() {
        // monitoring_epochs = 5: distance 5 is in, 6 is out.
        assert!(should_skip_restart_monitoring(100, Some(95), 5));
        assert!(!should_skip_restart_monitoring(100, Some(94), 5));
    }

    /// Future last_signed must NOT Safe-skip (saturating_sub would yield 0).
    #[test]
    fn test_restart_skip_predicate_rejects_future_last_signed() {
        // Classic case from the security audit: current=100, last=200 → distance
        // would be 0 under saturating_sub and incorrectly pass the window check.
        assert!(!should_skip_restart_monitoring(100, Some(200), 2));
        assert!(!should_skip_restart_monitoring(100, Some(101), 2));
        // Far-future plant under same GVR (interchange / clock lag).
        assert!(!should_skip_restart_monitoring(10_000, Some(u64::MAX), 2));
        // Same-epoch remains a valid recent restart.
        assert!(should_skip_restart_monitoring(100, Some(100), 2));
    }
}
