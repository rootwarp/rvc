//! Doppelganger detection for Ethereum validator clients.
//!
//! Detects if another instance is running with the same validator keys.
//! Implements restart-awareness (Lodestar pattern) to avoid false positives
//! when a validator client restarts after recently signing attestations.

mod enablement;
mod epoch_clock;
mod forward_window;
pub mod marker_file;
mod restart_skip;
mod state;
mod traits;

pub use enablement::{
    duty_requires_beacon_admission, signing_allowed, DoppelgangerDisabledByOperator, SigningDuty,
    SigningEnablement,
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

#[cfg(test)]
mod closed_epoch_slot_tests {
    use std::sync::Arc;

    use crypto::SecretKey;
    use eth_types::Root;

    use super::{
        EpochLiveness, ForwardWindowMachine, ForwardWindowStatus, ValidatorLivenessData,
        CLOSED_EPOCH_SLOT,
    };

    struct NoPrior;

    impl slashing::SlashingDbReader for NoPrior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &Root,
        ) -> Option<slashing::TargetEpoch> {
            None
        }
    }

    fn drive(slot: u64) -> ForwardWindowStatus {
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
        let machine = ForwardWindowMachine::new(reader, 1, [0xcd; 32]);
        let pubkey = SecretKey::generate().public_key();
        let hex = hex::encode(pubkey.to_bytes());
        let start = 10u64;
        machine.register(&pubkey, start);
        let not_live = |epoch: u64| EpochLiveness {
            epoch,
            samples: Some(vec![ValidatorLivenessData { index: hex.clone(), is_live: false }]),
        };
        for epoch in start..start + 2 {
            let current = epoch + 1;
            let _ =
                machine.apply_liveness_tick(&[not_live(epoch), not_live(current)], current, slot);
            if epoch == start {
                assert_eq!(
                    machine.status(&pubkey),
                    ForwardWindowStatus::Pending,
                    "one closed epoch leaves the key Pending at slot {slot}"
                );
            }
        }
        machine.status(&pubkey)
    }

    #[test]
    fn closed_epoch_slot_is_24() {
        assert_eq!(CLOSED_EPOCH_SLOT, 24);
    }

    /// Slot 23 does not decrement. Slot 24 does, and the second closed epoch
    /// reaches Safe when `monitoring_epochs` is 1.
    #[test]
    fn test_literal_slot_23_does_not_decrement() {
        assert_eq!(drive(23), ForwardWindowStatus::Pending);
        assert_eq!(drive(24), ForwardWindowStatus::Safe);
    }
}
