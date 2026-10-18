//! Remaining-epoch doppelganger state machine.
//!
//! A validator stays withheld until `monitoring_epochs + 1` closed, fully
//! observed not-live epochs have been counted. A closed epoch is the previous
//! one, and only an answer taken at slot >= [`CLOSED_EPOCH_SLOT`] of the
//! following epoch decrements. A live answer at any epoch at or after
//! `next_check_epoch` moves the validator to `Detected`, which permanently
//! denies signing. Time passing without those answers does not open the gate.
//!
//! [`ForwardWindowMachine::apply_liveness_tick`] takes every epoch fetched for
//! one slot and applies them under one lock. Any live answer at or after
//! `next_check_epoch` is `Detected` before a decrement. The decrement that
//! would reach zero does not run when the current epoch failed or omitted the
//! key.

use std::collections::HashMap;
use std::sync::Arc;

use eth_types::{Epoch, Root};

use crate::enablement::SigningEnablement;
use crate::restart_skip::should_skip_restart_monitoring;
use crate::state::{ForwardWindowStatus, PendingKey, ValidatorState};
use crate::traits::ValidatorLivenessData;
use crate::CLOSED_EPOCH_SLOT;

/// One epoch's liveness answer, collected before the machine changes state.
///
/// `samples == None` is a failed query. `Some` is the translated pubkey-hex
/// samples from a successful query. An empty vec named no validator.
#[derive(Debug, Clone)]
pub struct EpochLiveness {
    pub epoch: Epoch,
    pub samples: Option<Vec<ValidatorLivenessData>>,
}

/// Any `is_live = true` for a pubkey wins. Order does not matter.
fn or_fold_samples(samples: &[ValidatorLivenessData]) -> HashMap<&str, bool> {
    let mut response: HashMap<&str, bool> = HashMap::with_capacity(samples.len());
    for sample in samples {
        response
            .entry(sample.index.as_str())
            .and_modify(|live| *live |= sample.is_live)
            .or_insert(sample.is_live);
    }
    response
}

/// Forward-window doppelganger state machine.
///
/// Thread-safe via an internal `parking_lot::Mutex`.
pub struct ForwardWindowMachine {
    states: parking_lot::Mutex<HashMap<String, ValidatorState>>,
    monitoring_epochs: u64,
    slashing_reader: Arc<dyn slashing::SlashingDbReader>,
    gvr: Root,
    /// Epoch 0 marks keys Safe only after genesis times agreed across BNs.
    genesis_confirmed: bool,
}

impl ForwardWindowMachine {
    /// Create a new machine.
    ///
    /// # Panics
    ///
    /// Panics if `monitoring_epochs` is zero.
    pub fn new(
        slashing_reader: Arc<dyn slashing::SlashingDbReader>,
        monitoring_epochs: u64,
        gvr: Root,
    ) -> Self {
        assert!(monitoring_epochs >= 1, "monitoring_epochs must be >= 1");
        Self {
            states: parking_lot::Mutex::new(HashMap::new()),
            monitoring_epochs,
            slashing_reader,
            gvr,
            genesis_confirmed: false,
        }
    }

    /// Allow the epoch-0 Safe bypass. Production sets this only for a named
    /// network whose responding beacon nodes matched the preset genesis.
    /// Custom stays closed: those nodes also choose the slot duration.
    pub fn with_confirmed_genesis(mut self) -> Self {
        self.genesis_confirmed = true;
        self
    }

    fn initial_remaining(&self) -> u64 {
        self.monitoring_epochs.saturating_add(1)
    }

    /// Register a validator for monitoring, starting at `current_epoch`.
    ///
    /// IDEMPOTENT: calling twice for the same pubkey does NOT reset state.  A
    /// validator that is already `Pending`, `Safe`, or `Detected` is left
    /// unchanged.
    ///
    /// `next_check_epoch` is `current_epoch`, so the registration epoch itself
    /// counts once it is closed. `remaining` starts at `monitoring_epochs + 1`.
    ///
    /// Restart-aware safe-skip (Layer 4): if `last_signed_attestation` returns a
    /// target epoch that is RECENT (within the monitoring window), the validator
    /// transitions straight to `Safe` without waiting for the full window.
    /// A stale attestation (outside the window) does NOT trigger the skip.
    /// Uses the shared [`crate::should_skip_restart_monitoring`] predicate
    /// (same rule as the legacy service).
    pub fn register(&self, pubkey: &crypto::PublicKey, current_epoch: Epoch) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let mut states = self.states.lock();

        // Idempotency guard: any state other than Unmonitored stays as-is.
        if let Some(state) = states.get(&pubkey_hex) {
            if !matches!(state, ValidatorState::Unmonitored) {
                return;
            }
        }

        // Epoch 0 after genesis is the Safe bypass: no slots of this chain have
        // been missed yet. A clock still before genesis also saturates to epoch
        // 0, and that is not a counted epoch — callers must leave
        // `genesis_confirmed` false until [`crate::MonotonicEpochClock::allow_epoch0_bypass`]
        // is true. An inflated slot duration must not set the flag either.
        // This branch stays after the idempotency guard, so a second register
        // does not rewrite Pending, Safe, or Detected.
        if current_epoch == 0 && self.genesis_confirmed {
            tracing::info!(
                pubkey = %observability::logging::TruncatedPubkey::new(&pubkey_hex),
                "doppelganger: pre-genesis (epoch 0) bypass — validator marked Safe without a monitoring window"
            );
            states.insert(pubkey_hex, ValidatorState::Safe);
            return;
        }

        // Restart-aware safe-skip: only skip if the prior attestation is RECENT.
        let prior = self.slashing_reader.last_signed_attestation(&pubkey_hex, &self.gvr);
        if should_skip_restart_monitoring(current_epoch, prior, self.monitoring_epochs) {
            states.insert(pubkey_hex, ValidatorState::Safe);
            return;
        }

        states.insert(
            pubkey_hex,
            ValidatorState::Pending {
                next_check_epoch: current_epoch,
                remaining: self.initial_remaining(),
            },
        );
    }

    /// Register a **keymanager-imported** (or dynamically discovered) key.
    ///
    /// Unlike [`Self::register`], this path **never** applies:
    /// - epoch-0 pre-genesis Safe bypass
    /// - restart-aware Safe-skip from slashing-DB history
    ///
    /// Both bypasses are unsafe on the import path: a future/`mis-set`
    /// genesis can yield epoch 0, and interchange import can plant recent
    /// attestation history that would Safe-skip before any network liveness
    /// is observed (SEC-2b review Finding 1 / 2). Imported keys always enter
    /// `Pending` until observation counts `monitoring_epochs + 1` closed
    /// not-live epochs (or operator opt-out).
    ///
    /// `next_check_epoch` is `current_epoch + 1`: the import epoch itself
    /// does not count and does not detect.
    ///
    /// Idempotent: existing non-`Unmonitored` state is left unchanged.
    pub fn register_for_import(&self, pubkey: &crypto::PublicKey, current_epoch: Epoch) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let mut states = self.states.lock();

        if let Some(state) = states.get(&pubkey_hex) {
            if !matches!(state, ValidatorState::Unmonitored) {
                return;
            }
        }

        let next_check_epoch = current_epoch.saturating_add(1);
        tracing::info!(
            pubkey = %observability::logging::TruncatedPubkey::new(&pubkey_hex),
            current_epoch,
            next_check_epoch,
            "doppelganger: import/register_for_import — forced Pending (no epoch-0 / restart safe-skip)"
        );
        states.insert(
            pubkey_hex,
            ValidatorState::Pending { next_check_epoch, remaining: self.initial_remaining() },
        );
    }

    /// Report status. Does not open the gate.
    ///
    /// Safe happens only inside [`Self::observe_liveness`] or
    /// [`Self::apply_liveness_tick`] when `remaining` hits 0. A tick past any
    /// epoch, including one far ahead, leaves `Pending` keys `Pending`.
    pub fn tick(&self, _current_epoch: Epoch, _slot_in_epoch: u64) -> Vec<ForwardWindowStatus> {
        let states = self.states.lock();
        let mut statuses = Vec::with_capacity(states.len());
        for state in states.values() {
            statuses.push(Self::status_of(state));
        }
        statuses
    }

    /// Pubkeys still `Pending`, including those with no validator index yet.
    pub fn pending_keys(&self) -> Vec<PendingKey> {
        let states = self.states.lock();
        let mut keys = Vec::new();
        for (pubkey_hex, state) in states.iter() {
            if let ValidatorState::Pending { next_check_epoch, .. } = state {
                keys.push(PendingKey {
                    pubkey_hex: pubkey_hex.clone(),
                    next_check_epoch: *next_check_epoch,
                });
            }
        }
        keys.sort_by(|a, b| a.pubkey_hex.cmp(&b.pubkey_hex));
        keys
    }

    /// Apply one epoch's liveness answer, taken at `(current_epoch, slot_in_epoch)`.
    ///
    /// # Pubkey-hex key contract (SEC-001)
    ///
    /// Each `ValidatorLivenessData.index` MUST be the lowercase
    /// `hex::encode(pubkey.to_bytes())` for that validator. The caller
    /// translates beacon-node numeric indices first and omits any index it
    /// cannot translate.
    ///
    /// # What counts
    ///
    /// For each `Pending` key with `epoch >= next_check_epoch`:
    ///
    /// - Index present and any sample `is_live` (OR-fold over duplicates) →
    ///   `Detected`.
    /// - Index present, not live, `epoch == current_epoch - 1`, and
    ///   `slot_in_epoch >= CLOSED_EPOCH_SLOT` → decrement `remaining` and set
    ///   `next_check_epoch = epoch + 1`. `remaining == 0` → `Safe`.
    /// - Index absent → the key is returned and is not decremented.
    ///
    /// Epochs before `next_check_epoch`, and not-live answers that are not a
    /// closed previous epoch, do not change state and are not returned.
    ///
    /// The returned pubkey-hex list is sorted. Callers must log or retry it:
    /// a missing answer never opens the gate.
    ///
    /// One epoch on its own may open the gate. The production loop fetches the
    /// previous epoch and the current epoch first and applies both through
    /// [`Self::apply_liveness_tick`], so a live current epoch is not dropped
    /// on the tick that would otherwise reach `Safe`.
    #[must_use = "unobserved keys stay Pending; log or retry them"]
    pub fn observe_liveness(
        &self,
        epoch: Epoch,
        samples: &[ValidatorLivenessData],
        current_epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Vec<String> {
        // OR-fold duplicates (SEC-008): any is_live=true wins. A first-wins
        // fold drops a later true. A last-wins fold drops an earlier true.
        let response = or_fold_samples(samples);

        let closed =
            current_epoch > 0 && epoch == current_epoch - 1 && slot_in_epoch >= CLOSED_EPOCH_SLOT;

        let mut states = self.states.lock();
        let keys: Vec<String> = states.keys().cloned().collect();
        let mut unobserved = Vec::new();
        for key in keys {
            let Some(state) = states.get_mut(&key) else { continue };
            let ValidatorState::Pending { next_check_epoch, remaining } = *state else {
                continue;
            };
            if epoch < next_check_epoch {
                continue;
            }
            match response.get(key.as_str()).copied() {
                Some(true) => {
                    *state = ValidatorState::Detected;
                }
                Some(false) if closed => {
                    let Some(next_check) = epoch.checked_add(1) else {
                        continue;
                    };
                    let next_remaining = remaining.saturating_sub(1);
                    if next_remaining == 0 {
                        *state = ValidatorState::Safe;
                    } else {
                        *state = ValidatorState::Pending {
                            next_check_epoch: next_check,
                            remaining: next_remaining,
                        };
                    }
                }
                Some(false) => {}
                None => unobserved.push(key),
            }
        }
        unobserved.sort();
        unobserved
    }

    /// Apply every answer fetched for one slot, under one lock.
    ///
    /// Live is decided first: any sample with `is_live` at an epoch at or
    /// after `next_check_epoch` moves that key to `Detected`, and no decrement
    /// runs for it. Otherwise a closed not-live previous epoch decrements.
    /// When `remaining` is 1, that decrement runs only if the current epoch's
    /// answer includes the key as not live. A failed query, a response that
    /// omits the key, or a missing current-epoch answer leaves the key
    /// `Pending`.
    ///
    /// Returned pairs are `(epoch, pubkey-hex)` for a due key with no sample,
    /// sorted by epoch then pubkey. Signing stays at its previous value until
    /// this function returns.
    #[must_use = "unobserved keys stay Pending; log or retry them"]
    pub fn apply_liveness_tick(
        &self,
        answers: &[EpochLiveness],
        current_epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Vec<(Epoch, String)> {
        let folded: Vec<(Epoch, Option<HashMap<&str, bool>>)> = answers
            .iter()
            .map(|answer| (answer.epoch, answer.samples.as_deref().map(or_fold_samples)))
            .collect();
        let closed_slot = slot_in_epoch >= CLOSED_EPOCH_SLOT;

        let mut states = self.states.lock();
        let keys: Vec<String> = states.keys().cloned().collect();
        let mut unobserved = Vec::new();
        for key in keys {
            let Some(state) = states.get_mut(&key) else { continue };
            let ValidatorState::Pending { next_check_epoch, remaining } = *state else {
                continue;
            };

            let mut saw_live = false;
            let mut closed_not_live_epoch: Option<Epoch> = None;
            let mut current_not_live = false;
            for (epoch, response) in &folded {
                if *epoch < next_check_epoch {
                    continue;
                }
                match response {
                    None => unobserved.push((*epoch, key.clone())),
                    Some(samples) => match samples.get(key.as_str()).copied() {
                        Some(true) => saw_live = true,
                        Some(false) => {
                            let previous =
                                current_epoch > 0 && *epoch == current_epoch - 1 && closed_slot;
                            if previous {
                                closed_not_live_epoch = Some(*epoch);
                            }
                            if *epoch == current_epoch {
                                current_not_live = true;
                            }
                        }
                        None => unobserved.push((*epoch, key.clone())),
                    },
                }
            }

            if saw_live {
                *state = ValidatorState::Detected;
                continue;
            }
            let Some(epoch) = closed_not_live_epoch else { continue };
            // The last count would open the gate. It needs a successful
            // not-live answer for the epoch being entered.
            if remaining == 1 && !current_not_live {
                continue;
            }
            let Some(next_check) = epoch.checked_add(1) else { continue };
            let next_remaining = remaining.saturating_sub(1);
            if next_remaining == 0 {
                *state = ValidatorState::Safe;
            } else {
                *state = ValidatorState::Pending {
                    next_check_epoch: next_check,
                    remaining: next_remaining,
                };
            }
        }
        unobserved.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        unobserved
    }

    /// Remove the validator from the state map.
    ///
    /// The next `register` call will start fresh (KM-2 / Issue 2.12).
    pub fn cancel(&self, pubkey: &crypto::PublicKey) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        self.states.lock().remove(&pubkey_hex);
    }

    /// Read-only status inspection for a single validator.
    pub fn status(&self, pubkey: &crypto::PublicKey) -> ForwardWindowStatus {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        match states.get(&pubkey_hex) {
            None => ForwardWindowStatus::Unmonitored,
            Some(state) => Self::status_of(state),
        }
    }

    fn status_of(state: &ValidatorState) -> ForwardWindowStatus {
        match state {
            ValidatorState::Unmonitored => ForwardWindowStatus::Unmonitored,
            ValidatorState::Pending { .. } => ForwardWindowStatus::Pending,
            ValidatorState::Safe => ForwardWindowStatus::Safe,
            ValidatorState::Detected => ForwardWindowStatus::Detected,
        }
    }
}

impl SigningEnablement for ForwardWindowMachine {
    /// Returns `true` ONLY when the validator state is `Safe`.
    ///
    /// All other states (`Pending`, `Detected`, `Unmonitored`) return `false`
    /// (fail-closed by construction, per PRD §6.3).
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool {
        matches!(self.status(pubkey), ForwardWindowStatus::Safe)
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }
}
