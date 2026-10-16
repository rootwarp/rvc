//! Forward-window doppelganger state machine (D-1/D-2, Issues 2.6/2.7).
//!
//! Implements the Lighthouse v5.3.0 forward-window pattern: a validator is
//! withheld from signing for `monitoring_epochs` epochs after registration.
//! The monitoring window closes — and signing is permitted — only at or after
//! the LAST slot of `start_epoch + monitoring_epochs`.  Any unexplained
//! `is_live` observation during the window transitions the validator to
//! `Detected`, which permanently denies signing (fail-closed).
//!
//! # D-2: Fail-closed on incomplete liveness (Issue 2.7)
//!
//! A validator reaches `Safe` ONLY if EVERY epoch in its monitoring window
//! `[start_epoch, end_epoch]` (INCLUSIVE — `end_epoch = start_epoch +
//! monitoring_epochs`) had a COMPLETE liveness observation: the validator's
//! pubkey-hex index was present in the beacon-node response for that epoch.
//! An epoch whose response omits the validator's index is NOT recorded as
//! observed; the validator remains `Pending` through the satisfaction boundary.
//! This is "fail-closed": missing data never grants signing permission.
//!
//! # Caller polling contract
//!
//! Each slot cycle, the orchestrator SHOULD call these methods in order:
//!
//! 1. `observe_liveness(epoch, samples)` — record the beacon-node liveness
//!    response for `epoch`.  The registration epoch (`start_epoch`) must be
//!    observed just like any other window epoch; it is NOT exempted.  If the
//!    method returns `Err(IncompleteLiveness)`, the caller MUST retry the
//!    liveness check for that epoch rather than suppressing the error.
//! 2. `tick(current_epoch, slot_in_epoch)` — advance the state machine.
//!
//! Calling `tick` before `observe_liveness` at the satisfaction boundary is
//! safe but will leave the validator `Pending` for one more cycle: the
//! `past_boundary` arm (`current_epoch > end_epoch`) will catch it on the next
//! tick once observation is complete.
//!
//! # Pubkey-hex key contract (SEC-001)
//!
//! The machine keys its internal state by `hex::encode(pubkey.to_bytes())`
//! (lowercase hex).  `ValidatorLivenessData.index` values in the `samples`
//! slice passed to `observe_liveness` MUST use the same encoding.  Beacon
//! nodes return NUMERIC validator indices; the orchestrator/adapter is
//! responsible for translating numeric index → pubkey-hex BEFORE calling
//! `observe_liveness`.  An index that cannot be translated MUST be treated as
//! a missing entry (fail-closed).  The production wiring and translation land
//! in Issue 2.10.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};
use parking_lot::Mutex;

use crate::enablement::SigningEnablement;
use crate::error::DoppelgangerError;
use crate::restart_skip::should_skip_restart_monitoring;
use crate::state::{ForwardWindowStatus, ValidatorState};
use crate::traits::ValidatorLivenessData;

/// Forward-window doppelganger state machine.
///
/// Thread-safe via an internal `parking_lot::Mutex`.
pub struct ForwardWindowMachine {
    states: Mutex<HashMap<String, ValidatorState>>,
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
            states: Mutex::new(HashMap::new()),
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

    /// Register a validator for monitoring, starting at `current_epoch`.
    ///
    /// IDEMPOTENT: calling twice for the same pubkey does NOT reset state.  A
    /// validator that is already `Pending`, `Safe`, or `Detected` is left
    /// unchanged.
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

        // Pre-genesis bypass (S-3, Issue 2.8): at epoch 0 no slots have occurred,
        // so liveness-based detection is not meaningful.  Mirror the documented
        // Lighthouse behaviour (remaining_epochs = 0) by marking the validator
        // `Safe` immediately and emitting an explicit log so operators see the
        // deliberate decision in the startup logs rather than a silent skip.
        //
        // Rationale: placing this branch AFTER the idempotency guard ensures that
        // a validator already in Pending/Safe/Detected keeps its existing state
        // even if `register` is called again at epoch 0 (idempotency wins).
        // Epoch 0 is also what an inflated slot duration produces. That must
        // not open signing. The bypass runs only when genesis was confirmed
        // from the named-network preset, not from the beacon-reported duration.
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

        let end_epoch = current_epoch.saturating_add(self.monitoring_epochs);
        states.insert(
            pubkey_hex,
            ValidatorState::Pending {
                start_epoch: current_epoch,
                end_epoch,
                observed_epochs: BTreeSet::new(),
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
    /// `Pending` until SEC-2c observation + tick (or operator opt-out).
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

        let end_epoch = current_epoch.saturating_add(self.monitoring_epochs);
        tracing::info!(
            pubkey = %observability::logging::TruncatedPubkey::new(&pubkey_hex),
            current_epoch,
            end_epoch,
            "doppelganger: import/register_for_import — forced Pending (no epoch-0 / restart safe-skip)"
        );
        states.insert(
            pubkey_hex,
            ValidatorState::Pending {
                start_epoch: current_epoch,
                end_epoch,
                observed_epochs: BTreeSet::new(),
            },
        );
    }

    /// Advance the state machine by one slot tick.
    ///
    /// A `Pending` validator transitions to `Safe` when ALL of the following hold:
    ///
    /// - The satisfaction boundary has been reached: `current_epoch > end_epoch`,
    ///   OR `current_epoch == end_epoch && slot_in_epoch >= SLOTS_PER_EPOCH - 1`.
    ///   This "at-or-after" semantics means a missed tick (e.g. after a restart)
    ///   does not leave the validator stuck `Pending` forever.
    /// - Every epoch in the monitoring window `[start_epoch, end_epoch]`
    ///   (INCLUSIVE) has a COMPLETE liveness observation recorded in
    ///   `observed_epochs` (D-2, Issue 2.7).  A missing-entry epoch prevents the
    ///   `Safe` transition (fail-closed).
    ///
    /// `Detected` is TERMINAL: a validator in the `Detected` state is never
    /// transitioned to `Safe` by `tick`, regardless of how much time has passed.
    ///
    /// Returns the current status of every registered validator.
    pub fn tick(&self, current_epoch: Epoch, slot_in_epoch: u64) -> Vec<ForwardWindowStatus> {
        let mut states = self.states.lock();
        let mut statuses = Vec::with_capacity(states.len());

        for state in states.values_mut() {
            if let ValidatorState::Pending { start_epoch, end_epoch, observed_epochs } = state {
                let at_boundary =
                    current_epoch == *end_epoch && slot_in_epoch >= SLOTS_PER_EPOCH - 1;
                let past_boundary = current_epoch > *end_epoch;

                if at_boundary || past_boundary {
                    // D-2: Safe requires complete observation of every window epoch.
                    let window_fully_observed =
                        (*start_epoch..=*end_epoch).all(|e| observed_epochs.contains(&e));
                    if window_fully_observed {
                        *state = ValidatorState::Safe;
                    }
                }
            }

            statuses.push(Self::status_of(state));
        }

        statuses
    }

    /// Record liveness observations for a given epoch.
    ///
    /// # Pubkey-hex key contract (SEC-001)
    ///
    /// Each `ValidatorLivenessData.index` in `samples` MUST be the lowercase
    /// `hex::encode(pubkey.to_bytes())` for the corresponding validator — the
    /// same encoding used as the state-map key in [`Self::register`].  Beacon
    /// nodes return NUMERIC validator indices; the orchestrator/adapter MUST
    /// translate numeric index → pubkey-hex before calling this method, and
    /// MUST treat any untranslatable index as a missing entry (fail-closed).
    /// See the module-level doc and Issue 2.10 for production wiring details.
    ///
    /// # Behaviour for each `Pending` in-window validator
    ///
    /// For each `Pending` validator whose monitoring window `[start_epoch,
    /// end_epoch]` includes `epoch`:
    ///
    /// - If the validator's index **is present** in `samples`:
    ///   - `epoch` is recorded as completely observed in `observed_epochs`.
    ///   - If ANY sample for that index has `is_live == true` (OR-fold over
    ///     duplicate entries), the validator transitions to `Detected`.
    /// - If the validator's index **is absent** from `samples`:
    ///   - `epoch` is NOT recorded (incomplete response — fail-closed per D-2).
    ///   - The validator stays `Pending` and cannot satisfy the window.
    ///
    /// After processing all in-window validators, the method returns
    /// `Err(DoppelgangerError::IncompleteLiveness { epoch, missing_count })`
    /// if ANY expected validator was absent from the response.  Callers MUST
    /// log this error and retry the liveness check for the same epoch; they
    /// MUST NOT suppress it.
    ///
    /// # Out-of-window and non-Pending behaviour
    ///
    /// Out-of-window epochs (before `start_epoch` or after `end_epoch` for a
    /// specific validator) are ignored for that validator.  If no `Pending`
    /// in-window validator is expected for `epoch` at all (because all
    /// validators are `Safe`, `Detected`, or out-of-window), the method
    /// returns `Ok(())` regardless of what `samples` contains.
    pub fn observe_liveness(
        &self,
        epoch: Epoch,
        samples: &[ValidatorLivenessData],
    ) -> Result<(), DoppelgangerError> {
        // Build a lookup map of index → is_live using OR-fold over duplicates
        // (SEC-008): if a pubkey appears more than once, ANY is_live=true wins.
        // A naive HashMap::collect keeps the LAST entry, which could allow a
        // malicious/buggy BN to append (pk, false) after (pk, true) and
        // silently suppress a detection.
        let mut response: HashMap<&str, bool> = HashMap::with_capacity(samples.len());
        for s in samples {
            response.entry(s.index.as_str()).and_modify(|v| *v |= s.is_live).or_insert(s.is_live);
        }

        let mut states = self.states.lock();

        // Phase 1: collect keys of Pending validators whose window includes epoch.
        // Gathered first so Phase 2 can use get_mut without borrow conflicts.
        let pending_in_window_keys: Vec<String> = states
            .iter()
            .filter_map(|(key, state)| {
                if let ValidatorState::Pending { start_epoch, end_epoch, .. } = state {
                    if epoch >= *start_epoch && epoch <= *end_epoch {
                        return Some(key.clone());
                    }
                }
                None
            })
            .collect();

        // Phase 2: process each in-window Pending validator.
        let mut missing_count: usize = 0;
        for key in &pending_in_window_keys {
            let Some(state) = states.get_mut(key) else { continue };

            match response.get(key.as_str()) {
                Some(&is_live) => {
                    // Index is present → record the epoch as completely observed.
                    if let ValidatorState::Pending { observed_epochs, .. } = state {
                        observed_epochs.insert(epoch);
                    }
                    // Transition to Detected if the validator is live (OR-folded above).
                    if is_live {
                        *state = ValidatorState::Detected;
                    }
                }
                None => {
                    // Index is absent from the response → incomplete (fail-closed D-2).
                    missing_count += 1;
                }
            }
        }

        if missing_count > 0 {
            Err(DoppelgangerError::IncompleteLiveness { epoch, missing_count })
        } else {
            Ok(())
        }
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
}
