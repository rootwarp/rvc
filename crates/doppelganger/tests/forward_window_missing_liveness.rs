//! Tests for D-2: `ForwardWindowMachine` fails CLOSED on missing/incomplete liveness data.
//!
//! A validator must be marked `Safe` ONLY after EVERY epoch in its monitoring
//! window has a COMPLETE liveness observation (i.e. the validator's pubkey-hex
//! index is present in the beacon-node response for that epoch).  An epoch
//! whose response omits a requested validator does NOT count as "observed" —
//! the validator stays `Pending` through the satisfaction boundary.

use std::sync::Arc;

use rvc_doppelganger::{
    EpochLiveness, ForwardWindowMachine, ForwardWindowStatus, SigningEnablement,
    ValidatorLivenessData, CLOSED_EPOCH_SLOT,
};

use crypto::SecretKey;
use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct NoPriorAttestation;

impl slashing::SlashingDbReader for NoPriorAttestation {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        None
    }
}

fn gvr() -> Root {
    [0xbb; 32]
}

fn new_pubkey() -> crypto::PublicKey {
    SecretKey::generate().public_key()
}

fn machine() -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, 1, gvr())
}

fn machine_n(monitoring_epochs: u64) -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, monitoring_epochs, gvr())
}

/// Observe EVERY epoch in `[start_epoch, end_epoch]` as complete and not-live.
///
/// Panics if any call returns an error (which would indicate the response is
/// missing the validator's index — a test-setup bug).
fn observe_complete_window(
    machine: &ForwardWindowMachine,
    pubkey: &crypto::PublicKey,
    start_epoch: Epoch,
    end_epoch: Epoch,
) {
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        assert!(
            machine.observe_liveness(epoch, &samples, epoch + 1, CLOSED_EPOCH_SLOT).is_empty(),
            "complete observation must succeed"
        );
    }
}

// ---------------------------------------------------------------------------
// D-2: missing entry in response → that pubkey is returned, not decremented
// ---------------------------------------------------------------------------

/// When `observe_liveness` is called for an epoch with an empty sample slice,
/// any due Pending validator is absent and is returned.
#[test]
fn test_observe_liveness_empty_samples_returns_incomplete_liveness_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let start_epoch: Epoch = 10;
    machine.register(&pubkey, start_epoch);

    // Empty slice — validator is absent.
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let result = machine.observe_liveness(start_epoch, &[], start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(
        result,
        vec![pubkey_hex],
        "empty samples for a due Pending validator must return that key"
    );
}

/// When the response contains an entry for a DIFFERENT validator but not for
/// our validator, that pubkey is returned and is not decremented.
#[test]
fn test_observe_liveness_missing_validator_in_partial_response_returns_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 20;
    machine.register(&pubkey, start_epoch);

    // Response contains a *different* index — our validator is missing.
    let other_index = "deadbeef".to_string();
    assert_ne!(other_index, pubkey_hex, "test setup: indices must differ");
    let samples = vec![ValidatorLivenessData { index: other_index, is_live: false }];
    let result =
        machine.observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(
        result,
        vec![pubkey_hex],
        "response missing our validator's index must return that key"
    );
}

/// Every absent due validator is returned, sorted by pubkey hex.
#[test]
fn test_incomplete_liveness_error_carries_epoch_and_count() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 77;

    let machine = machine_n(monitoring_epochs);
    let _pk_a = new_pubkey();
    let _pk_b = new_pubkey();

    // Register two validators.
    machine.register(&_pk_a, start_epoch);
    machine.register(&_pk_b, start_epoch);

    // Respond with empty samples — both validators are absent.
    let result = machine.observe_liveness(start_epoch, &[], start_epoch + 1, CLOSED_EPOCH_SLOT);
    let mut expected = vec![hex::encode(_pk_a.to_bytes()), hex::encode(_pk_b.to_bytes())];
    expected.sort();
    assert_eq!(result, expected, "both absent validators are unobserved");
}

// ---------------------------------------------------------------------------
// D-2: missing-entry epoch → validator stays Pending through boundary (fail-closed)
// ---------------------------------------------------------------------------

/// Negative path: a validator with a missing-entry epoch CANNOT transition to
/// Safe at the satisfaction boundary — it must remain Pending (fail-closed).
#[test]
fn test_missing_entry_epoch_keeps_validator_pending_through_boundary() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 30;
    let end_epoch = start_epoch + monitoring_epochs; // 31

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Call observe_liveness with empty samples for start_epoch.
    // This is an incomplete response — the validator is absent.
    // We assert the error is returned (must_use: errors must not be silently dropped).
    let missing = machine.observe_liveness(start_epoch, &[], start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(missing, vec![hex::encode(pubkey.to_bytes())], "empty samples return the key");

    // Tick to the satisfaction boundary.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "validator with incomplete liveness observation must NOT become Safe at the boundary \
         (fail-closed D-2)"
    );
}

/// A key with no index until E+5 stays Pending across a far tick, then reaches
/// Safe after three later closed not-live epochs. No re-register.
#[test]
fn test_missing_entry_keeps_pending_even_far_past_boundary() {
    let monitoring_epochs: u64 = rvc_doppelganger::DEFAULT_MONITORING_EPOCHS;
    let start_epoch: Epoch = 40;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    for epoch in start_epoch..start_epoch + 5 {
        let missing = machine.observe_liveness(epoch, &[], epoch + 1, CLOSED_EPOCH_SLOT);
        assert_eq!(missing, vec![pubkey_hex.clone()], "epoch {epoch} has no index");
        machine.tick(epoch + 50, 0);
        assert!(
            !machine.is_signing_enabled(&pubkey),
            "no index and a far tick must not open the gate at epoch {epoch}"
        );
    }

    let not_live = vec![ValidatorLivenessData { index: pubkey_hex, is_live: false }];
    for epoch in (start_epoch + 5)..(start_epoch + 8) {
        assert!(
            machine.observe_liveness(epoch, &not_live, epoch + 1, CLOSED_EPOCH_SLOT).is_empty(),
            "epoch {epoch} is answered"
        );
        assert!(
            !machine.is_signing_enabled(&pubkey) || epoch == start_epoch + 7,
            "Safe only on the third closed not-live epoch"
        );
    }
    assert!(
        machine.is_signing_enabled(&pubkey),
        "three closed not-live epochs after the index appears must reach Safe"
    );
}

/// Start_epoch absent + end_epoch present: the most realistic transient-BN-omission case.
/// The BN happened to include the validator for end_epoch but omitted it for start_epoch.
/// The window is not complete → validator must stay Pending.
#[test]
fn test_start_epoch_absent_end_epoch_present_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 55;
    let end_epoch = start_epoch + monitoring_epochs; // 56

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // start_epoch: missing (BN transient omission).
    let missing = machine.observe_liveness(start_epoch, &[], start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(missing, vec![pubkey_hex.clone()], "missing start_epoch returns the key");

    // end_epoch: present, not-live.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    assert!(
        machine.observe_liveness(end_epoch, &samples, end_epoch + 1, CLOSED_EPOCH_SLOT).is_empty(),
        "end_epoch observation must succeed"
    );

    // Tick to boundary — start_epoch was never recorded → window incomplete → stays Pending.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "start_epoch absent + end_epoch present must NOT satisfy the window (fail-closed)"
    );
}

// ---------------------------------------------------------------------------
// D-2: complete observation → Safe at boundary (positive path unchanged)
// ---------------------------------------------------------------------------

/// Positive path: a validator with COMPLETE (present, not-live) observations for
/// EVERY epoch in the window transitions to Safe at the satisfaction boundary.
#[test]
fn test_complete_observation_yields_safe_at_boundary() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 50;
    let end_epoch = start_epoch + monitoring_epochs; // 51

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    assert!(
        machine.is_signing_enabled(&pubkey),
        "validator with complete not-live observation across the window must be Safe at boundary"
    );
}

/// Complete observation for monitoring_epochs = 2 (window is [start, start+2]).
#[test]
fn test_complete_observation_monitoring_epochs_2_yields_safe() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 100;
    let end_epoch = start_epoch + monitoring_epochs; // 102

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "monitoring_epochs=2: all 3 epochs observed completely → Safe at boundary"
    );
}

/// Partial observation (only start_epoch, missing middle and end_epoch) → stays Pending.
#[test]
fn test_partial_observation_only_start_epoch_stays_pending() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 200;
    let end_epoch = start_epoch + monitoring_epochs; // 202

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Observe ONLY start_epoch — middle and end_epoch are missing.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "start_epoch must succeed"
    );

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "only start_epoch observed (missing middle and end_epoch) → must stay Pending"
    );
}

// ---------------------------------------------------------------------------
// D-2: is_live in any observed epoch → Detected (unchanged from D-1)
// ---------------------------------------------------------------------------

/// An is_live=true in a complete response still transitions to Detected (D-1 preserved).
#[test]
fn test_complete_observation_with_live_transitions_to_detected() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 70;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Present AND is_live=true → must Detect.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "a present index is observed"
    );

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "is_live=true in complete response → Detected; signing denied"
    );
}

/// Detected is TERMINAL: tick past end_epoch must NOT resurrect to Safe.
#[test]
fn test_detected_is_terminal_tick_past_boundary_still_denied() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 71;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Detect the validator.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "must not fail"
    );
    assert!(!machine.is_signing_enabled(&pubkey), "Detected → signing denied");

    // Tick far past end_epoch.
    machine.tick(end_epoch + 10, 0);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "Detected is terminal: tick past end_epoch must NOT resurrect to Safe"
    );
}

/// Present + is_live=true does NOT return Err (the index is present; the error is about absence).
#[test]
fn test_live_validator_present_does_not_return_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 80;
    machine.register(&pubkey, start_epoch);

    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    let result =
        machine.observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert!(
        result.is_empty(),
        "is_live=true with the index present is observed, not reported missing"
    );
}

// ---------------------------------------------------------------------------
// SEC-008: duplicate-sample OR semantics
// ---------------------------------------------------------------------------

/// If a pubkey appears twice in samples with is_live=false then is_live=true,
/// the OR-fold must detect it (true wins over false).
#[test]
fn test_duplicate_sample_or_semantics_true_wins() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 85;
    machine.register(&pubkey, start_epoch);

    // (false, true): a first-wins fold keeps false and misses the detection.
    let samples = vec![
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true },
    ];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "must succeed (index present)"
    );

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "OR-fold: (false, true) → is_live=true must win → Detected"
    );
}

/// (true, false): a last-wins fold keeps false and misses the detection.
#[test]
fn test_duplicate_sample_reverse_order_true_then_false_detects() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 85;
    machine.register(&pubkey, start_epoch);

    let samples = vec![
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true },
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
    ];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "must succeed (index present)"
    );
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Detected);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "OR-fold: (true, false) → is_live=true must win → Detected"
    );
}

/// If a pubkey appears twice both not-live, OR-fold keeps false → stays Pending.
#[test]
fn test_duplicate_sample_or_semantics_both_false_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 86;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Both not-live — OR-fold keeps false.
    let samples = vec![
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
    ];
    assert!(
        machine
            .observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "must succeed (index present)"
    );

    // Observe end_epoch too, then tick.
    let samples2 = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    assert!(
        machine.observe_liveness(end_epoch, &samples2, end_epoch + 1, CLOSED_EPOCH_SLOT).is_empty(),
        "end_epoch must succeed"
    );

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "OR-fold: (false, false) → is_live=false → Safe after complete window"
    );
}

// ---------------------------------------------------------------------------
// D-2: out-of-window observations still ignored (D-1 preserved)
// ---------------------------------------------------------------------------

/// An is_live observation before `next_check_epoch` is ignored: not counted,
/// not detected, and not reported as unobserved.
#[test]
fn test_out_of_window_before_start_ignored_completely() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 90;
    let end_epoch = start_epoch + monitoring_epochs; // 91

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Call observe_liveness for an epoch BEFORE the window.
    // The validator IS in the response, but the epoch is out-of-window.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    let result =
        machine.observe_liveness(start_epoch - 1, &samples, start_epoch - 1 + 1, CLOSED_EPOCH_SLOT);
    // No due Pending validator for this epoch, so the key is not reported.
    assert!(result.is_empty(), "epoch before next_check is not an unobserved failure");

    // Confirm the validator is still Pending (not Detected) — out-of-window is_live ignored.
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "out-of-window is_live must not Detect the validator"
    );

    // Now provide complete observation for in-window epochs and confirm Safe.
    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "complete in-window observation after out-of-window ignore → Safe"
    );
}

/// observe_liveness returns no keys when none are still Pending
/// (every registered validator is already Safe or Detected).
#[test]
fn test_observe_liveness_returns_ok_when_no_pending_in_window_validators() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 5;
    let end_epoch = start_epoch + monitoring_epochs; // 6

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Observe completely to reach Safe.
    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey), "must be Safe");

    // Now call observe_liveness for another epoch with empty samples.
    // The only validator is Safe (not Pending) — no expected in-window validator → Ok.
    let result = machine.observe_liveness(end_epoch + 1, &[], end_epoch + 1 + 1, CLOSED_EPOCH_SLOT);
    assert!(result.is_empty(), "a Safe validator is not reported unobserved");
}

// ---------------------------------------------------------------------------
// Multi-validator partial response (new — review item 6a)
// ---------------------------------------------------------------------------

/// Multi-validator: A present, B absent in the same epoch.
/// - only B is returned
/// - A's epoch counts; B's does not
/// - After a complete retry for B, both reach Safe.
#[test]
fn test_multi_validator_partial_response_a_present_b_absent() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 300;
    let end_epoch = start_epoch + monitoring_epochs; // 301

    let machine = machine_n(monitoring_epochs);
    let pk_a = new_pubkey();
    let pk_b = new_pubkey();
    let hex_a = hex::encode(pk_a.to_bytes());
    let hex_b = hex::encode(pk_b.to_bytes());

    machine.register(&pk_a, start_epoch);
    machine.register(&pk_b, start_epoch);

    // start_epoch: A is present, B is absent.
    let samples = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let result =
        machine.observe_liveness(start_epoch, &samples, start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(
        result,
        vec![hex_b.clone()],
        "A present, B absent → only B is unobserved, got {result:?}"
    );

    // Both are still Pending; A has start_epoch recorded, B does not.
    assert!(!machine.is_signing_enabled(&pk_a), "A must still be Pending");
    assert!(!machine.is_signing_enabled(&pk_b), "B must still be Pending");

    // Retry B for start_epoch with a complete response (A already recorded, B missing).
    // Both are present so neither key is reported unobserved.
    let retry = vec![
        ValidatorLivenessData { index: hex_a.clone(), is_live: false },
        ValidatorLivenessData { index: hex_b.clone(), is_live: false },
    ];
    assert!(
        machine
            .observe_liveness(start_epoch, &retry, start_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "retry must succeed"
    );

    // Observe end_epoch for both.
    let end_samples = vec![
        ValidatorLivenessData { index: hex_a.clone(), is_live: false },
        ValidatorLivenessData { index: hex_b.clone(), is_live: false },
    ];
    assert!(
        machine
            .observe_liveness(end_epoch, &end_samples, end_epoch + 1, CLOSED_EPOCH_SLOT)
            .is_empty(),
        "end_epoch must succeed"
    );

    // Tick to boundary — both should now be Safe.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pk_a), "A must be Safe after complete observation");
    assert!(machine.is_signing_enabled(&pk_b), "B must be Safe after retry + complete observation");
}

/// Multi-validator: A present, B absent — B is NEVER retried.
/// After ticking to boundary: A is Safe, B stays Pending (fail-closed).
#[test]
fn test_multi_validator_b_never_retried_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 310;
    let end_epoch = start_epoch + monitoring_epochs; // 311

    let machine = machine_n(monitoring_epochs);
    let pk_a = new_pubkey();
    let pk_b = new_pubkey();
    let hex_a = hex::encode(pk_a.to_bytes());
    // hex_b deliberately not used: B is never included in any response.
    let _ = hex::encode(pk_b.to_bytes());

    machine.register(&pk_a, start_epoch);
    machine.register(&pk_b, start_epoch);

    // start_epoch: A present, B absent (never retried).
    let samples_start = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let missing =
        machine.observe_liveness(start_epoch, &samples_start, start_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(missing, vec![hex::encode(pk_b.to_bytes())]);

    // end_epoch: A present (complete), B still absent.
    let samples_end = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let missing_end =
        machine.observe_liveness(end_epoch, &samples_end, end_epoch + 1, CLOSED_EPOCH_SLOT);
    assert_eq!(missing_end, vec![hex::encode(pk_b.to_bytes())]);

    // Tick to boundary.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    // A has both start_epoch and end_epoch recorded → Safe.
    assert!(machine.is_signing_enabled(&pk_a), "A (fully observed) must be Safe");
    // B has neither epoch recorded → window incomplete → stays Pending.
    assert!(
        !machine.is_signing_enabled(&pk_b),
        "B (never retried) must stay Pending (fail-closed)"
    );
}

fn not_live(hex: &str) -> Option<Vec<ValidatorLivenessData>> {
    Some(vec![ValidatorLivenessData { index: hex.to_string(), is_live: false }])
}

fn live(hex: &str) -> Option<Vec<ValidatorLivenessData>> {
    Some(vec![ValidatorLivenessData { index: hex.to_string(), is_live: true }])
}

/// `monitoring_epochs = 1` starts `remaining` at 2. One closed tick leaves it at 1.
fn close_once(machine: &ForwardWindowMachine, hex: &str, start: Epoch) {
    let current = start + 1;
    let answers = [
        EpochLiveness { epoch: start, samples: not_live(hex) },
        EpochLiveness { epoch: current, samples: not_live(hex) },
    ];
    assert!(machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT).is_empty());
}

#[test]
fn test_opening_tick_live_current_epoch_is_detected() {
    let machine = machine_n(1);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 10u64;
    machine.register(&pubkey, start);
    close_once(&machine, &hex, start);
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending);

    let current = start + 2;
    let answers = [
        EpochLiveness { epoch: start + 1, samples: not_live(&hex) },
        EpochLiveness { epoch: current, samples: live(&hex) },
    ];
    let _ = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Detected);
    assert!(!machine.is_signing_enabled(&pubkey));
}

#[test]
fn test_opening_tick_live_current_epoch_wins_in_reverse_answer_order() {
    let machine = machine_n(1);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 20u64;
    machine.register(&pubkey, start);
    close_once(&machine, &hex, start);

    let current = start + 2;
    let answers = [
        EpochLiveness { epoch: current, samples: live(&hex) },
        EpochLiveness { epoch: start + 1, samples: not_live(&hex) },
    ];
    let _ = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Detected);
    assert!(!machine.is_signing_enabled(&pubkey));
}

/// A failed or omitted duplicate cancels that epoch's not-live, for the
/// previous epoch and for the current epoch. A live duplicate still detects.
#[test]
fn test_duplicate_failed_and_not_live_does_not_decrement() {
    let omitted = Some(vec![ValidatorLivenessData { index: "other".to_string(), is_live: false }]);
    let cases = [
        "previous-failed-after",
        "previous-failed-before",
        "previous-omitted",
        "current-failed",
        "current-omitted",
    ];
    for label in cases {
        let machine = machine_n(1);
        let pubkey = new_pubkey();
        let hex = hex::encode(pubkey.to_bytes());
        let start = 50u64;
        machine.register(&pubkey, start);
        close_once(&machine, &hex, start);
        assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending, "{label}");

        let current = start + 2;
        let previous = start + 1;
        let answers = match label {
            "previous-failed-after" => vec![
                EpochLiveness { epoch: previous, samples: not_live(&hex) },
                EpochLiveness { epoch: previous, samples: None },
                EpochLiveness { epoch: current, samples: not_live(&hex) },
            ],
            "previous-failed-before" => vec![
                EpochLiveness { epoch: previous, samples: None },
                EpochLiveness { epoch: previous, samples: not_live(&hex) },
                EpochLiveness { epoch: current, samples: not_live(&hex) },
            ],
            "previous-omitted" => vec![
                EpochLiveness { epoch: previous, samples: not_live(&hex) },
                EpochLiveness { epoch: previous, samples: omitted.clone() },
                EpochLiveness { epoch: current, samples: not_live(&hex) },
            ],
            "current-failed" => vec![
                EpochLiveness { epoch: previous, samples: not_live(&hex) },
                EpochLiveness { epoch: current, samples: not_live(&hex) },
                EpochLiveness { epoch: current, samples: None },
            ],
            "current-omitted" => vec![
                EpochLiveness { epoch: previous, samples: not_live(&hex) },
                EpochLiveness { epoch: current, samples: not_live(&hex) },
                EpochLiveness { epoch: current, samples: omitted.clone() },
            ],
            _ => unreachable!(),
        };
        let _ = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
        assert_eq!(
            machine.status(&pubkey),
            ForwardWindowStatus::Pending,
            "{label}: a failed or omitted duplicate must not decrement"
        );
        assert!(!machine.is_signing_enabled(&pubkey), "{label}");
    }

    let machine = machine_n(1);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 80u64;
    machine.register(&pubkey, start);
    let current = start + 1;
    let answers = [
        EpochLiveness { epoch: current, samples: live(&hex) },
        EpochLiveness { epoch: current, samples: None },
    ];
    let missing = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
    assert!(missing.is_empty(), "a live answer is not an unobserved epoch");
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Detected);
    assert!(!machine.is_signing_enabled(&pubkey), "a live answer still closes signing");
}

#[test]
fn test_opening_tick_failed_current_epoch_stays_pending() {
    let machine = machine_n(1);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 30u64;
    machine.register(&pubkey, start);
    close_once(&machine, &hex, start);

    let current = start + 2;
    let answers = [
        EpochLiveness { epoch: start + 1, samples: not_live(&hex) },
        EpochLiveness { epoch: current, samples: None },
    ];
    let missing = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
    assert_eq!(missing, vec![(current, hex)]);
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending);
    assert!(!machine.is_signing_enabled(&pubkey));
}

#[test]
fn test_opening_tick_partial_current_epoch_stays_pending() {
    let machine = machine_n(1);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 40u64;
    machine.register(&pubkey, start);
    close_once(&machine, &hex, start);

    let current = start + 2;
    let answers = [
        EpochLiveness { epoch: start + 1, samples: not_live(&hex) },
        EpochLiveness {
            epoch: current,
            samples: Some(vec![ValidatorLivenessData {
                index: "other".to_string(),
                is_live: false,
            }]),
        },
    ];
    let missing = machine.apply_liveness_tick(&answers, current, CLOSED_EPOCH_SLOT);
    assert_eq!(missing, vec![(current, hex.clone())]);
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending);
    assert!(!machine.is_signing_enabled(&pubkey));
}

#[test]
fn test_import_starts_counting_in_the_next_epoch() {
    let monitoring_epochs = 2u64;
    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let hex = hex::encode(pubkey.to_bytes());
    let start = 10u64;
    machine.register_for_import(&pubkey, start);

    let live_import = vec![ValidatorLivenessData { index: hex.clone(), is_live: true }];
    assert!(
        machine.observe_liveness(start, &live_import, start + 1, CLOSED_EPOCH_SLOT).is_empty(),
        "the import epoch is before next_check"
    );
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending);
    assert!(!machine.is_signing_enabled(&pubkey));

    for epoch in (start + 1)..=(start + monitoring_epochs) {
        let samples = vec![ValidatorLivenessData { index: hex.clone(), is_live: false }];
        assert!(machine.observe_liveness(epoch, &samples, epoch + 1, CLOSED_EPOCH_SLOT).is_empty());
        assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Pending);
    }
    let last = start + 1 + monitoring_epochs;
    let samples = vec![ValidatorLivenessData { index: hex, is_live: false }];
    assert!(machine.observe_liveness(last, &samples, last + 1, CLOSED_EPOCH_SLOT).is_empty());
    assert_eq!(machine.status(&pubkey), ForwardWindowStatus::Safe);
    assert!(machine.is_signing_enabled(&pubkey));
}
