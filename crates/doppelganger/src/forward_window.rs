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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eth_types::{Epoch, Root};

use crate::enablement::SigningEnablement;
use crate::marker_file::{self, MarkerFile};
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

fn path_blocks_skip(path: &std::path::Path) -> bool {
    !matches!(marker_file::read_marker_file(path), MarkerFile::Absent)
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

/// Invoked under the states lock when the latch is first stored.
type LatchHook = Arc<dyn Fn() + Send + Sync>;

/// Invoked under the states lock with the `is_signing_enabled` decision.
type AdmissionHook = Arc<dyn Fn(bool) + Send + Sync>;

/// Per-key status and the process-wide detection latch.
///
/// Both live under [`ForwardWindowMachine`]'s states mutex. The latch is set in
/// the same critical section as the first [`ValidatorState::Detected`] write
/// and is never cleared.
struct MachineStates {
    by_pubkey: HashMap<String, ValidatorState>,
    detected_latch: bool,
    /// Set with the latch. `register` does not Safe-skip while this is set.
    window_skip_blocked: bool,
    /// Pubkeys registered while the force-window file was present.
    ///
    /// The file is one record for that whole set. It is removed only after
    /// every one of them has reached `Safe` or been dropped.
    force_window_keys: HashSet<String>,
    /// `true` after at least one key was charged to the force-window file.
    force_window_owed: bool,
}

impl MachineStates {
    fn new() -> Self {
        Self {
            by_pubkey: HashMap::new(),
            detected_latch: false,
            window_skip_blocked: false,
            force_window_keys: HashSet::new(),
            force_window_owed: false,
        }
    }
}

/// Forward-window doppelganger state machine.
///
/// Thread-safe via an internal `parking_lot::Mutex`.
pub struct ForwardWindowMachine {
    states: parking_lot::Mutex<MachineStates>,
    monitoring_epochs: u64,
    slashing_reader: Arc<dyn slashing::SlashingDbReader>,
    gvr: Root,
    /// Epoch 0 marks keys Safe only after genesis times agreed across BNs.
    genesis_confirmed: bool,
    /// Detection-marker path. Absent is the only status that allows a skip.
    /// A symlink, a directory, or an unreadable path blocks the skip.
    marker_path: Option<PathBuf>,
    /// One-shot file from `clear-detection`. Blocks skip until a key finishes
    /// a full window, then this process deletes it.
    force_window_path: Option<PathBuf>,
    /// Set only after a detection write and its fsync returned `Ok` in this
    /// process. A rename also requires the directory fsync. Never inferred
    /// from a later read. The next process still reads the files at boot.
    detection_persisted: AtomicBool,
    /// Called under the states lock when the latch is stored. Must not re-enter
    /// the machine or block. Test builds only.
    #[cfg(any(test, feature = "test-utils"))]
    latch_hook: parking_lot::Mutex<Option<LatchHook>>,
    /// Called under the states lock at the end of `is_signing_enabled`, with the
    /// decision. Must not re-enter the machine or block. Test builds only.
    #[cfg(any(test, feature = "test-utils"))]
    admission_hook: parking_lot::Mutex<Option<AdmissionHook>>,
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
            states: parking_lot::Mutex::new(MachineStates::new()),
            monitoring_epochs,
            slashing_reader,
            gvr,
            genesis_confirmed: false,
            marker_path: None,
            force_window_path: None,
            detection_persisted: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-utils"))]
            latch_hook: parking_lot::Mutex::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            admission_hook: parking_lot::Mutex::new(None),
        }
    }

    /// Record that a detection write, its file fsync, and any directory fsync returned `Ok`.
    pub fn mark_detection_persisted(&self) {
        self.detection_persisted.store(true, Ordering::SeqCst);
    }

    /// `true` only after [`Self::mark_detection_persisted`].
    pub fn detection_persisted(&self) -> bool {
        self.detection_persisted.load(Ordering::SeqCst)
    }

    /// Install the hook invoked under the states lock when the latch is first stored.
    ///
    /// The hook must not call back into this machine and must not block: it runs
    /// while the states mutex is held. `None` clears it.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_detected_latch_hook(&self, hook: Option<LatchHook>) {
        *self.latch_hook.lock() = hook;
    }

    /// Install the hook invoked under the states lock after each signing decision.
    ///
    /// The argument is the value `is_signing_enabled` is about to return. The
    /// hook must not call back into this machine and must not block.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_admission_hook(&self, hook: Option<AdmissionHook>) {
        *self.admission_hook.lock() = hook;
    }

    fn latch_hook_snapshot(&self) -> Option<LatchHook> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            self.latch_hook.lock().clone()
        }
        #[cfg(not(any(test, feature = "test-utils")))]
        {
            None
        }
    }

    fn admission_hook_snapshot(&self) -> Option<AdmissionHook> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            self.admission_hook.lock().clone()
        }
        #[cfg(not(any(test, feature = "test-utils")))]
        {
            None
        }
    }

    fn fire_latch_hook(hook: &Option<LatchHook>) {
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Whether the process-wide detection latch is set.
    pub fn detected_latch(&self) -> bool {
        self.states.lock().detected_latch
    }

    /// Pubkey hexes currently `Detected`, sorted.
    pub fn detected_hexes(&self) -> Vec<String> {
        let states = self.states.lock();
        let mut hexes: Vec<String> = states
            .by_pubkey
            .iter()
            .filter(|(_, state)| matches!(state, ValidatorState::Detected))
            .map(|(hex, _)| hex.clone())
            .collect();
        hexes.sort();
        hexes
    }

    /// `true` when `pubkey` is `Detected` or the process latch is set.
    ///
    /// Distinct from [`SigningEnablement::is_signing_enabled`]: a `Pending` key
    /// is also unable to sign, and that is not detection.
    pub fn signing_closed_by_detection(&self, pubkey: &crypto::PublicKey) -> bool {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        states.detected_latch
            || matches!(states.by_pubkey.get(&pubkey_hex), Some(ValidatorState::Detected))
    }

    /// Remember where the detection marker lives. `register` will not skip the
    /// window unless that path is absent. A symlink is not absent.
    pub fn with_detection_marker_path(mut self, path: PathBuf) -> Self {
        self.marker_path = Some(path);
        self
    }

    /// Remember the one-shot force-window file. `register` will not skip while
    /// it is present. The file is deleted only after every key registered
    /// while it was present has finished a full window.
    pub fn with_force_window_path(mut self, path: PathBuf) -> Self {
        self.force_window_path = Some(path);
        self
    }

    /// `true` when this pubkey's own status is [`ValidatorState::Detected`].
    ///
    /// The process latch is not included. Signing refusal uses
    /// [`Self::signing_closed_by_detection`].
    pub fn is_detected(&self, pubkey: &crypto::PublicKey) -> bool {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        matches!(states.by_pubkey.get(&pubkey_hex), Some(ValidatorState::Detected))
    }

    fn marker_blocks_skip(&self) -> bool {
        self.marker_path.as_deref().is_some_and(path_blocks_skip)
            || self.force_window_path.as_deref().is_some_and(path_blocks_skip)
    }

    /// Delete the force-window file after every key that was registered while
    /// it was present has finished, or been dropped.
    ///
    /// A failed delete leaves the file, so the next boot still withholds skip.
    fn consume_force_window(&self) {
        let Some(path) = &self.force_window_path else {
            return;
        };
        match std::fs::remove_file(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    if let Ok(dir) = std::fs::File::open(parent) {
                        let _ = dir.sync_all();
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::error!(
                    error = %err,
                    path = %path.display(),
                    "failed to remove the doppelganger force-window file"
                );
            }
        }
    }

    fn insert_pending(
        states: &mut MachineStates,
        pubkey_hex: String,
        current_epoch: Epoch,
        remaining: u64,
    ) {
        states.by_pubkey.insert(
            pubkey_hex,
            ValidatorState::Pending { next_check_epoch: current_epoch, remaining },
        );
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
        let force_blocks = self.force_window_path.as_deref().is_some_and(path_blocks_skip);
        let marker_blocks = self.marker_blocks_skip();
        let mut states = self.states.lock();

        // Idempotency guard: any state other than Unmonitored stays as-is.
        if let Some(state) = states.by_pubkey.get(&pubkey_hex) {
            if !matches!(state, ValidatorState::Unmonitored) {
                return;
            }
        }

        // A detection marker, or the in-process latch, closes both the epoch-0
        // bypass and the restart skip. The key stays Pending for a full window.
        if states.window_skip_blocked || marker_blocks {
            states.window_skip_blocked = true;
            if force_blocks {
                states.force_window_keys.insert(pubkey_hex.clone());
                states.force_window_owed = true;
            }
            let remaining = self.initial_remaining();
            Self::insert_pending(&mut states, pubkey_hex, current_epoch, remaining);
            return;
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
            states.by_pubkey.insert(pubkey_hex, ValidatorState::Safe);
            return;
        }

        // Restart-aware safe-skip: only skip if the prior attestation is RECENT.
        let prior = self.slashing_reader.last_signed_attestation(&pubkey_hex, &self.gvr);
        if should_skip_restart_monitoring(current_epoch, prior, self.monitoring_epochs) {
            states.by_pubkey.insert(pubkey_hex, ValidatorState::Safe);
            return;
        }

        states.by_pubkey.insert(
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

        if let Some(state) = states.by_pubkey.get(&pubkey_hex) {
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
        states.by_pubkey.insert(
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
        let mut statuses = Vec::with_capacity(states.by_pubkey.len());
        for state in states.by_pubkey.values() {
            statuses.push(Self::status_of(state));
        }
        statuses
    }

    /// Pubkeys still `Pending`, including those with no validator index yet.
    pub fn pending_keys(&self) -> Vec<PendingKey> {
        let states = self.states.lock();
        let mut keys = Vec::new();
        for (pubkey_hex, state) in states.by_pubkey.iter() {
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

        let latch_hook = self.latch_hook_snapshot();
        let mut states = self.states.lock();
        let keys: Vec<String> = states.by_pubkey.keys().cloned().collect();
        let mut unobserved = Vec::new();
        let mut arm_latch = false;
        let mut window_completed = false;
        let mut finished = Vec::new();
        for key in keys {
            let Some(state) = states.by_pubkey.get_mut(&key) else { continue };
            let ValidatorState::Pending { next_check_epoch, remaining } = *state else {
                continue;
            };
            if epoch < next_check_epoch {
                continue;
            }
            match response.get(key.as_str()).copied() {
                Some(true) => {
                    *state = ValidatorState::Detected;
                    arm_latch = true;
                }
                Some(false) if closed => {
                    let Some(next_check) = epoch.checked_add(1) else {
                        continue;
                    };
                    let next_remaining = remaining.saturating_sub(1);
                    if next_remaining == 0 {
                        *state = ValidatorState::Safe;
                        window_completed = true;
                        finished.push(key.clone());
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
        if arm_latch && !states.detected_latch {
            states.detected_latch = true;
            states.window_skip_blocked = true;
            Self::fire_latch_hook(&latch_hook);
        }
        let clear_force =
            Self::release_finished_force_keys(&mut states, &finished, window_completed);
        drop(states);
        if clear_force {
            self.consume_force_window();
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

        let latch_hook = self.latch_hook_snapshot();
        let mut states = self.states.lock();
        let keys: Vec<String> = states.by_pubkey.keys().cloned().collect();
        let mut unobserved = Vec::new();
        let mut arm_latch = false;
        let mut window_completed = false;
        let mut finished = Vec::new();
        for key in keys {
            let Some(state) = states.by_pubkey.get_mut(&key) else { continue };
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
                arm_latch = true;
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
                window_completed = true;
                finished.push(key.clone());
            } else {
                *state = ValidatorState::Pending {
                    next_check_epoch: next_check,
                    remaining: next_remaining,
                };
            }
        }
        if arm_latch && !states.detected_latch {
            states.detected_latch = true;
            states.window_skip_blocked = true;
            Self::fire_latch_hook(&latch_hook);
        }
        let clear_force =
            Self::release_finished_force_keys(&mut states, &finished, window_completed);
        drop(states);
        if clear_force {
            self.consume_force_window();
        }
        unobserved.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        unobserved
    }

    /// Drop `Pending`, `Safe`, or `Unmonitored` state so the next register starts fresh.
    ///
    /// [`ValidatorState::Detected`] stays. A DELETE then re-import in this process
    /// does not open a new window (FU-A2a).
    pub fn cancel(&self, pubkey: &crypto::PublicKey) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let clear = {
            let mut states = self.states.lock();
            if matches!(states.by_pubkey.get(&pubkey_hex), Some(ValidatorState::Detected)) {
                return;
            }
            states.by_pubkey.remove(&pubkey_hex);
            states.force_window_keys.remove(&pubkey_hex);
            states.force_window_owed
                && states.force_window_keys.is_empty()
                && !states.detected_latch
        };
        if clear {
            self.consume_force_window();
        }
    }

    /// Drop finished keys from the force-window set. `true` when that set is
    /// now empty and the file may be removed.
    fn release_finished_force_keys(
        states: &mut MachineStates,
        finished: &[String],
        window_completed: bool,
    ) -> bool {
        for key in finished {
            states.force_window_keys.remove(key);
        }
        window_completed
            && states.force_window_owed
            && states.force_window_keys.is_empty()
            && !states.detected_latch
    }

    /// Read-only status inspection for a single validator.
    pub fn status(&self, pubkey: &crypto::PublicKey) -> ForwardWindowStatus {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        match states.by_pubkey.get(&pubkey_hex) {
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
    /// Returns `true` only when this key is `Safe` and the detection latch is clear.
    ///
    /// The latch is read first, under the same states lock as the per-key status.
    /// While it is set, every key returns `false`, including keys that are still
    /// `Safe`. `Pending`, `Detected`, and `Unmonitored` also return `false`.
    ///
    /// A check that runs after the latch was stored is refused. A non-slashable
    /// sign whose check already returned `true` may finish. A slashable sign
    /// is checked again via [`Self::blocked_by_doppelganger`] after reserve.
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let admission = self.admission_hook_snapshot();
        let states = self.states.lock();
        let enabled = !states.detected_latch
            && matches!(states.by_pubkey.get(&pubkey_hex), Some(ValidatorState::Safe));
        if let Some(hook) = admission {
            hook(enabled);
        }
        enabled
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }

    fn blocked_by_doppelganger(&self, pubkey: &crypto::PublicKey) -> bool {
        self.signing_closed_by_detection(pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> ForwardWindowMachine {
        let db: Arc<dyn slashing::SlashingDbReader> =
            Arc::new(slashing::SlashingDb::open_in_memory().expect("memory db"));
        ForwardWindowMachine::new(db, 1, [0x11; 32]).with_confirmed_genesis()
    }

    fn pubkey() -> crypto::PublicKey {
        crypto::SecretKey::generate().public_key()
    }

    fn detect(machine: &ForwardWindowMachine, pubkey: &crypto::PublicKey, epoch: Epoch) {
        let samples =
            vec![ValidatorLivenessData { index: hex::encode(pubkey.to_bytes()), is_live: true }];
        let _ = machine.apply_liveness_tick(
            &[EpochLiveness { epoch, samples: Some(samples) }],
            epoch,
            0,
        );
    }

    #[test]
    fn detection_latch_blocks_signing_for_every_key() {
        let machine = machine();
        let safe = pubkey();
        let pending = pubkey();
        machine.register(&safe, 0);
        machine.register(&pending, 5);
        assert!(machine.is_signing_enabled(&safe), "epoch-0 register is Safe before detection");
        detect(&machine, &pending, 5);
        assert_eq!(machine.status(&pending), ForwardWindowStatus::Detected);
        assert_eq!(machine.status(&safe), ForwardWindowStatus::Safe);
        assert!(
            !machine.is_signing_enabled(&safe),
            "a Safe key must not sign after another key is Detected"
        );
        assert!(!machine.is_signing_enabled(&pending));
    }

    #[test]
    fn delete_then_reimport_of_a_detected_key_stays_detected() {
        let machine = machine();
        let key = pubkey();
        machine.register(&key, 5);
        detect(&machine, &key, 5);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Detected);
        machine.cancel(&key);
        machine.register_for_import(&key, 6);
        assert_eq!(
            machine.status(&key),
            ForwardWindowStatus::Detected,
            "DELETE then re-import must not open a fresh window"
        );
    }

    /// `register_for_import` concurrent with the detecting tick leaves Detected.
    ///
    /// The states lock already serializes the two writers, and register is
    /// idempotent for a non-`Unmonitored` key. This pins that guard: dropping
    /// it would let the import open a fresh `Pending` window.
    #[test]
    fn import_racing_detection_cannot_reset_detected() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let machine = Arc::new(machine());
        let key = pubkey();
        machine.register(&key, 5);
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let machine = Arc::clone(&machine);
            let key = key.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    machine.register_for_import(&key, 0);
                }
                machine.register_for_import(&key, 9);
            })
        };
        detect(&machine, &key, 5);
        stop.store(true, Ordering::SeqCst);
        worker.join().expect("import racer");
        assert_eq!(machine.status(&key), ForwardWindowStatus::Detected);
        assert!(machine.detected_latch(), "the detecting tick must store the latch");
        assert!(!machine.is_signing_enabled(&key));
    }

    struct Prior(u64);

    impl slashing::SlashingDbReader for Prior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &eth_types::Root,
        ) -> Option<slashing::TargetEpoch> {
            Some(self.0)
        }
    }

    fn machine_with_recent_history() -> ForwardWindowMachine {
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        ForwardWindowMachine::new(reader, 2, [0x11; 32]).with_confirmed_genesis()
    }

    #[test]
    fn marker_file_disables_restart_skip_and_import_stays_pending() {
        let bare = machine_with_recent_history();
        let skipped = pubkey();
        bare.register(&skipped, 100);
        assert!(bare.is_signing_enabled(&skipped), "fixture must skip without a marker");

        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("marker");
        std::fs::write(&path, b"marker").expect("marker");
        let machine = machine_with_recent_history().with_detection_marker_path(path);
        let booted = pubkey();
        let imported = pubkey();
        machine.register(&booted, 100);
        machine.register_for_import(&imported, 100);
        assert_eq!(machine.status(&booted), ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&booted));
        assert_eq!(machine.status(&imported), ForwardWindowStatus::Pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_marker_path_disables_restart_skip() {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-unreadable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let not_a_dir = dir.join("file");
        std::fs::write(&not_a_dir, b"x").expect("file");
        let machine =
            machine_with_recent_history().with_detection_marker_path(not_a_dir.join("marker"));
        let key = pubkey();
        machine.register(&key, 100);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_marker_disables_restart_skip() {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("marker");
        std::os::unix::fs::symlink("missing-target", &path).expect("symlink");
        let machine = machine_with_recent_history().with_detection_marker_path(path);
        let key = pubkey();
        machine.register(&key, 100);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn force_window_file_blocks_skip_until_a_window_completes() {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-force-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("force");
        std::fs::write(&path, b"1\n").expect("force");
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let machine = ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path.clone());
        let key = pubkey();
        machine.register(&key, 100);
        assert_eq!(
            machine.status(&key),
            ForwardWindowStatus::Pending,
            "the force file must withhold a restart skip"
        );
        let not_live = |pk: &crypto::PublicKey| ValidatorLivenessData {
            index: hex::encode(pk.to_bytes()),
            is_live: false,
        };
        let _ = machine.observe_liveness(100, &[not_live(&key)], 101, crate::CLOSED_EPOCH_SLOT);
        assert_eq!(
            machine.status(&key),
            ForwardWindowStatus::Pending,
            "one epoch is not the window"
        );
        assert!(path.exists(), "the force file stays until the window finishes");
        let control: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let without = ForwardWindowMachine::new(control, 1, [0x11; 32]).with_confirmed_genesis();
        let skipped = pubkey();
        without.register(&skipped, 100);
        assert!(
            without.is_signing_enabled(&skipped),
            "this history skips when the force file is absent"
        );
        let _ = machine.observe_liveness(101, &[not_live(&key)], 102, crate::CLOSED_EPOCH_SLOT);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Safe);
        assert!(!path.exists(), "a finished window removes the force file");

        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let later = ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path);
        let again = pubkey();
        later.register(&again, 100);
        assert!(later.is_signing_enabled(&again), "the next boot may restart-skip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The force file is one record for every key loaded while it was present.
    /// The first key to finish its window must not delete it.
    #[test]
    fn force_window_file_stays_until_every_loaded_key_finishes() {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-force-many-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("force");
        std::fs::write(&path, b"1\n").expect("force");
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let machine = ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path.clone());
        let first = pubkey();
        let second = pubkey();
        machine.register(&first, 100);
        machine.register(&second, 100);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Pending);
        assert_eq!(machine.status(&second), ForwardWindowStatus::Pending);
        let not_live = |pk: &crypto::PublicKey| ValidatorLivenessData {
            index: hex::encode(pk.to_bytes()),
            is_live: false,
        };
        let _ = machine.observe_liveness(100, &[not_live(&first)], 101, crate::CLOSED_EPOCH_SLOT);
        let _ = machine.observe_liveness(101, &[not_live(&first)], 102, crate::CLOSED_EPOCH_SLOT);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Safe);
        assert_eq!(
            machine.status(&second),
            ForwardWindowStatus::Pending,
            "the key that has not finished stays withheld"
        );
        assert!(path.exists(), "the first finished key must not delete the force file");

        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let restarted = ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path.clone());
        let late = pubkey();
        restarted.register(&late, 100);
        assert_eq!(
            restarted.status(&late),
            ForwardWindowStatus::Pending,
            "a restart before the other key finishes must still withhold skip"
        );

        let _ = machine.observe_liveness(100, &[not_live(&second)], 101, crate::CLOSED_EPOCH_SLOT);
        let _ = machine.observe_liveness(101, &[not_live(&second)], 102, crate::CLOSED_EPOCH_SLOT);
        assert_eq!(machine.status(&second), ForwardWindowStatus::Safe);
        assert!(
            !path.exists(),
            "the force file goes away only after every loaded key has finished"
        );
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        let after = ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path);
        let again = pubkey();
        after.register(&again, 100);
        assert!(after.is_signing_enabled(&again), "the next boot may restart-skip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn force_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("force");
        std::fs::write(&path, b"1\n").expect("force");
        (dir, path)
    }

    fn force_machine(path: std::path::PathBuf) -> ForwardWindowMachine {
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Prior(99));
        ForwardWindowMachine::new(reader, 1, [0x11; 32])
            .with_confirmed_genesis()
            .with_force_window_path(path)
    }

    fn not_live(pk: &crypto::PublicKey) -> ValidatorLivenessData {
        ValidatorLivenessData { index: hex::encode(pk.to_bytes()), is_live: false }
    }

    /// F5: dropping one mid-window key leaves the force file for the other.
    #[test]
    fn cancel_one_forced_key_mid_window_keeps_the_file() {
        let (dir, path) = force_paths();
        let machine = force_machine(path.clone());
        let first = pubkey();
        let second = pubkey();
        machine.register(&first, 100);
        machine.register(&second, 100);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Pending);
        machine.cancel(&first);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Unmonitored);
        assert_eq!(machine.status(&second), ForwardWindowStatus::Pending);
        assert!(path.exists(), "the remaining mid-window key keeps the force file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F6: dropping the only mid-window key removes the file, so a later boot may skip.
    #[test]
    fn cancel_the_only_forced_key_mid_window_removes_the_file() {
        let (dir, path) = force_paths();
        let machine = force_machine(path.clone());
        let key = pubkey();
        machine.register(&key, 100);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Pending);
        machine.cancel(&key);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Unmonitored);
        assert!(!path.exists(), "no remaining forced key means the file is gone");

        let later = force_machine(path);
        let again = pubkey();
        later.register(&again, 100);
        assert!(
            later.is_signing_enabled(&again),
            "epoch 100 with Prior(99) skips once the force file is gone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F7: a finished key can be removed while a sibling is still in the window.
    #[test]
    fn cancel_a_safe_forced_key_keeps_the_file_while_a_sibling_is_pending() {
        let (dir, path) = force_paths();
        let machine = force_machine(path.clone());
        let first = pubkey();
        let second = pubkey();
        machine.register(&first, 100);
        machine.register(&second, 100);
        let _ = machine.observe_liveness(100, &[not_live(&first)], 101, crate::CLOSED_EPOCH_SLOT);
        let _ = machine.observe_liveness(101, &[not_live(&first)], 102, crate::CLOSED_EPOCH_SLOT);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Safe);
        assert_eq!(machine.status(&second), ForwardWindowStatus::Pending);
        assert!(path.exists());
        machine.cancel(&first);
        assert_eq!(machine.status(&first), ForwardWindowStatus::Unmonitored);
        assert_eq!(machine.status(&second), ForwardWindowStatus::Pending);
        assert!(path.exists(), "the pending sibling keeps the force file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F8: a detected key is not cancelled, and the latch keeps the force file.
    #[test]
    fn cancel_a_detected_forced_key_stays_detected_and_keeps_the_file() {
        let (dir, path) = force_paths();
        let machine = force_machine(path.clone());
        let key = pubkey();
        machine.register(&key, 100);
        detect(&machine, &key, 100);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Detected);
        assert!(machine.detected_latch());
        machine.cancel(&key);
        assert_eq!(machine.status(&key), ForwardWindowStatus::Detected);
        assert!(path.exists(), "a detected key does not consume the force file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn latch_blocks_epoch0_skip_for_a_key_registered_later() {
        let machine = machine();
        let detected = pubkey();
        machine.register(&detected, 5);
        detect(&machine, &detected, 5);
        let late = pubkey();
        machine.register(&late, 0);
        assert_eq!(machine.status(&late), ForwardWindowStatus::Pending);
        assert!(machine.is_detected(&detected));
        assert!(!machine.is_detected(&late));
    }
}
