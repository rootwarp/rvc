//! History oracle for the forward-window machine.
//!
//! A `Safe` key must be explained by one permitted boot bypass, or by
//! `monitoring_epochs + 1` distinct closed not-live epochs. The oracle does
//! not track `remaining` or rewrite `next_check`. The generator only moves
//! the epoch forward, so an answer is for an epoch that has not already been
//! passed.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use crypto::SecretKey;
use eth_types::Root;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{RngSeed, TestRunner};
use rvc_doppelganger::{
    should_skip_restart_monitoring, DoppelgangerDisabledByOperator, EpochLiveness,
    ForwardWindowMachine, ForwardWindowStatus, SigningEnablement, ValidatorLivenessData,
};

/// Literal closed-epoch cut-off. Not [`rvc_doppelganger::CLOSED_EPOCH_SLOT`].
const CUTOFF_SLOT: u64 = 24;

const PROPTEST_CASES: u32 = 64;
const COVERAGE_CASES: u32 = 120;
const COVERAGE_SEED: u64 = 0x00D5_0729;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    Boot,
    Import,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sample {
    NotLive,
    Live,
    Missing,
}

#[derive(Clone, Debug)]
struct KeyPlan {
    path: Reg,
    last_signed: Option<u64>,
}

#[derive(Clone, Debug)]
struct Tick {
    current_epoch: u64,
    slot: u64,
    current_first: bool,
    prev_failed: bool,
    curr_failed: bool,
    prev: Vec<Sample>,
    curr: Vec<Sample>,
}

#[derive(Clone, Debug)]
struct Case {
    opt_out: bool,
    monitoring_epochs: u64,
    genesis_confirmed: bool,
    start_epoch: u64,
    keys: Vec<KeyPlan>,
    ticks: Vec<Tick>,
}

struct Planted(HashMap<String, u64>);

impl slashing::SlashingDbReader for Planted {
    fn last_signed_attestation(&self, pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        self.0.get(pubkey).copied()
    }
}

fn pubkeys() -> &'static [crypto::PublicKey; 3] {
    static KEYS: OnceLock<[crypto::PublicKey; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            SecretKey::generate().public_key(),
            SecretKey::generate().public_key(),
            SecretKey::generate().public_key(),
        ]
    })
}

fn hex_of(index: usize) -> String {
    hex::encode(pubkeys()[index].to_bytes())
}

fn boot() -> KeyPlan {
    KeyPlan { path: Reg::Boot, last_signed: None }
}

fn import() -> KeyPlan {
    KeyPlan { path: Reg::Import, last_signed: None }
}

fn next_check_epoch(path: Reg, start: u64) -> u64 {
    match path {
        Reg::Boot => start,
        Reg::Import => start.saturating_add(1),
    }
}

fn permitted_bypass(key: &KeyPlan, start: u64, genesis_confirmed: bool, monitoring: u64) -> bool {
    match key.path {
        Reg::Import => false,
        Reg::Boot => {
            let epoch0 = start == 0 && genesis_confirmed;
            let restart = should_skip_restart_monitoring(start, key.last_signed, monitoring);
            epoch0 || restart
        }
    }
}

fn clean_tick(current: u64, slot: u64, n_keys: usize, current_first: bool) -> Tick {
    Tick {
        current_epoch: current,
        slot,
        current_first,
        prev_failed: false,
        curr_failed: false,
        prev: vec![Sample::NotLive; n_keys],
        curr: vec![Sample::NotLive; n_keys],
    }
}

fn sample_strategy() -> impl Strategy<Value = Sample> {
    prop_oneof![6 => Just(Sample::NotLive), 1 => Just(Sample::Live), 1 => Just(Sample::Missing),]
}

fn case_strategy() -> impl Strategy<Value = Case> {
    prop_oneof![
        8 => progress_case(),
        2 => blocked_close_case(),
        1 => epoch0_boot_case(),
        1 => epoch0_monitored_case(),
        1 => epoch0_import_case(),
        1 => restart_boot_case(),
        1 => restart_import_case(),
        1 => future_history_case(),
        1 => slot_below_cutoff_case(),
        1 => Just(opt_out_case()),
        2 => noisy_case(),
    ]
}

fn progress_case() -> impl Strategy<Value = Case> {
    (1u64..=3, any::<bool>(), any::<bool>()).prop_map(|(monitoring_epochs, with_import, swap)| {
        let start_epoch = 40u64;
        let keys = if with_import { vec![boot(), import()] } else { vec![boot()] };
        let extra = u64::from(with_import);
        let ticks = (0..monitoring_epochs.saturating_add(1).saturating_add(extra))
            .map(|i| {
                let slot = CUTOFF_SLOT + (i % 8);
                clean_tick(start_epoch + i + 1, slot, keys.len(), swap ^ (i % 2 == 1))
            })
            .collect();
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: false,
            start_epoch,
            keys,
            ticks,
        }
    })
}

fn blocked_close_case() -> impl Strategy<Value = Case> {
    (1u64..=3, any::<bool>()).prop_map(|(monitoring_epochs, current_first)| {
        let start_epoch = 50u64;
        let keys = vec![boot()];
        let needed = monitoring_epochs.saturating_add(1);
        let mut ticks = Vec::new();
        for i in 0..needed.saturating_sub(1) {
            ticks.push(clean_tick(start_epoch + i + 1, CUTOFF_SLOT, 1, false));
        }
        ticks.push(Tick {
            current_epoch: start_epoch + needed,
            slot: CUTOFF_SLOT,
            current_first,
            prev_failed: false,
            curr_failed: true,
            prev: vec![Sample::NotLive],
            curr: vec![Sample::NotLive],
        });
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: false,
            start_epoch,
            keys,
            ticks,
        }
    })
}

fn epoch0_boot_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| Case {
        opt_out: false,
        monitoring_epochs,
        genesis_confirmed: true,
        start_epoch: 0,
        keys: vec![boot()],
        ticks: vec![clean_tick(1, CUTOFF_SLOT, 1, false)],
    })
}

fn epoch0_monitored_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| {
        let keys = vec![boot()];
        let ticks = (0..monitoring_epochs.saturating_add(1))
            .map(|i| clean_tick(i + 1, CUTOFF_SLOT, 1, false))
            .collect();
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: false,
            start_epoch: 0,
            keys,
            ticks,
        }
    })
}

fn epoch0_import_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| Case {
        opt_out: false,
        monitoring_epochs,
        genesis_confirmed: true,
        start_epoch: 0,
        keys: vec![import()],
        ticks: vec![],
    })
}

fn restart_boot_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| {
        let start_epoch = 30u64;
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: false,
            start_epoch,
            keys: vec![KeyPlan { path: Reg::Boot, last_signed: Some(start_epoch) }],
            ticks: vec![],
        }
    })
}

fn restart_import_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| {
        let start_epoch = 30u64;
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: true,
            start_epoch,
            keys: vec![KeyPlan { path: Reg::Import, last_signed: Some(start_epoch) }],
            ticks: vec![],
        }
    })
}

fn future_history_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| {
        let start_epoch = 80u64;
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: true,
            start_epoch,
            keys: vec![KeyPlan {
                path: Reg::Boot,
                last_signed: Some(start_epoch.saturating_add(5)),
            }],
            ticks: vec![],
        }
    })
}

fn slot_below_cutoff_case() -> impl Strategy<Value = Case> {
    (1u64..=3).prop_map(|monitoring_epochs| {
        let start_epoch = 70u64;
        let keys = vec![boot()];
        let ticks = (0..monitoring_epochs.saturating_add(1))
            .map(|i| clean_tick(start_epoch + i + 1, CUTOFF_SLOT - 1, 1, true))
            .collect();
        Case {
            opt_out: false,
            monitoring_epochs,
            genesis_confirmed: false,
            start_epoch,
            keys,
            ticks,
        }
    })
}

fn opt_out_case() -> Case {
    Case {
        opt_out: true,
        monitoring_epochs: 1,
        genesis_confirmed: false,
        start_epoch: 10,
        keys: vec![],
        ticks: vec![],
    }
}

#[derive(Clone, Debug)]
struct NoisyStep {
    delta: u64,
    slot: u64,
    current_first: bool,
    prev_failed: bool,
    curr_failed: bool,
    prev: Sample,
    curr: Sample,
}

fn noisy_case() -> impl Strategy<Value = Case> {
    let step = (
        prop_oneof![4 => Just(1u64), 1 => Just(2u64)],
        prop_oneof![5 => CUTOFF_SLOT..32u64, 1 => 0u64..CUTOFF_SLOT],
        any::<bool>(),
        prop_oneof![8 => Just(false), 1 => Just(true)],
        prop_oneof![8 => Just(false), 1 => Just(true)],
        sample_strategy(),
        sample_strategy(),
    )
        .prop_map(|(delta, slot, current_first, prev_failed, curr_failed, prev, curr)| NoisyStep {
            delta,
            slot,
            current_first,
            prev_failed,
            curr_failed,
            prev,
            curr,
        });
    (1u64..=3, any::<bool>(), proptest::collection::vec(step, 1..12)).prop_map(
        |(monitoring_epochs, with_import, steps)| {
            let start_epoch = 90u64;
            let keys = if with_import { vec![boot(), import()] } else { vec![boot()] };
            let mut current = start_epoch;
            let ticks = steps
                .into_iter()
                .map(|step| {
                    current = current.saturating_add(step.delta);
                    Tick {
                        current_epoch: current,
                        slot: step.slot,
                        current_first: step.current_first,
                        prev_failed: step.prev_failed,
                        curr_failed: step.curr_failed,
                        prev: vec![step.prev; keys.len()],
                        curr: vec![step.curr; keys.len()],
                    }
                })
                .collect();
            Case {
                opt_out: false,
                monitoring_epochs,
                genesis_confirmed: false,
                start_epoch,
                keys,
                ticks,
            }
        },
    )
}

fn epoch_answer(epoch: u64, failed: bool, samples: &[Sample]) -> EpochLiveness {
    if failed {
        return EpochLiveness { epoch, samples: None };
    }
    let mut data = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        match sample {
            Sample::NotLive => {
                data.push(ValidatorLivenessData { index: hex_of(index), is_live: false })
            }
            Sample::Live => {
                data.push(ValidatorLivenessData { index: hex_of(index), is_live: true })
            }
            Sample::Missing => {}
        }
    }
    EpochLiveness { epoch, samples: Some(data) }
}

fn apply_tick(machine: &ForwardWindowMachine, tick: &Tick) {
    let mut answers = Vec::with_capacity(2);
    if tick.current_epoch > 0 {
        answers.push(epoch_answer(tick.current_epoch - 1, tick.prev_failed, &tick.prev));
    }
    answers.push(epoch_answer(tick.current_epoch, tick.curr_failed, &tick.curr));
    if tick.current_first && answers.len() == 2 {
        answers.swap(0, 1);
    }
    let _ = machine.apply_liveness_tick(&answers, tick.current_epoch, tick.slot);
}

/// `true` when this prefix has a live sample at an epoch `>= next_check`.
fn saw_blocking_live(ticks: &[Tick], key_idx: usize, next_check: u64) -> bool {
    ticks.iter().any(|tick| {
        let prev_live = tick.current_epoch > 0
            && !tick.prev_failed
            && tick.prev.get(key_idx) == Some(&Sample::Live)
            && tick.current_epoch > next_check;
        let curr_live = !tick.curr_failed
            && tick.curr.get(key_idx) == Some(&Sample::Live)
            && tick.current_epoch >= next_check;
        prev_live || curr_live
    })
}

/// Monitored Safe: at least `monitoring_epochs + 1` distinct closed not-live
/// epochs, the last tick's current answer present and not live, and no live
/// answer at or after `next_check`.
fn explains_monitored(
    ticks: &[Tick],
    key_idx: usize,
    next_check: u64,
    monitoring_epochs: u64,
) -> bool {
    if ticks.is_empty() || saw_blocking_live(ticks, key_idx, next_check) {
        return false;
    }
    let needed = monitoring_epochs.saturating_add(1);
    let mut closed = BTreeSet::new();
    for tick in ticks {
        let Some(prev_epoch) = tick.current_epoch.checked_sub(1) else { continue };
        if prev_epoch >= next_check
            && tick.slot >= CUTOFF_SLOT
            && !tick.prev_failed
            && tick.prev.get(key_idx) == Some(&Sample::NotLive)
        {
            closed.insert(prev_epoch);
        }
    }
    let Some(last) = ticks.last() else { return false };
    let current_not_live = !last.curr_failed && last.curr.get(key_idx) == Some(&Sample::NotLive);
    u64::try_from(closed.len()).unwrap_or(u64::MAX) >= needed && current_not_live
}

fn trace_reaches_closing_tick(case: &Case) -> bool {
    if case.opt_out {
        return false;
    }
    let needed = case.monitoring_epochs.saturating_add(1);
    case.keys.iter().enumerate().any(|(idx, key)| {
        if permitted_bypass(key, case.start_epoch, case.genesis_confirmed, case.monitoring_epochs) {
            return false;
        }
        let next_check = next_check_epoch(key.path, case.start_epoch);
        let mut closed = BTreeSet::new();
        for tick in &case.ticks {
            let Some(prev_epoch) = tick.current_epoch.checked_sub(1) else { continue };
            if prev_epoch >= next_check
                && tick.slot >= CUTOFF_SLOT
                && !tick.prev_failed
                && tick.prev.get(idx) == Some(&Sample::NotLive)
            {
                closed.insert(prev_epoch);
            }
        }
        u64::try_from(closed.len()).unwrap_or(u64::MAX) >= needed
    })
}

struct Outcome {
    monitored_safe: bool,
    epoch0_bypass: bool,
    restart_bypass: bool,
}

fn execute(case: &Case) -> Result<Outcome, TestCaseError> {
    if case.opt_out {
        let gate = DoppelgangerDisabledByOperator;
        for pubkey in pubkeys() {
            prop_assert!(gate.is_signing_enabled(pubkey));
        }
        return Ok(Outcome { monitored_safe: false, epoch0_bypass: false, restart_bypass: false });
    }

    let mut planted = HashMap::new();
    for (index, key) in case.keys.iter().enumerate() {
        if let Some(epoch) = key.last_signed {
            planted.insert(hex_of(index), epoch);
        }
    }
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(Planted(planted));
    let mut machine = ForwardWindowMachine::new(reader, case.monitoring_epochs, [0xab; 32]);
    if case.genesis_confirmed {
        machine = machine.with_confirmed_genesis();
    }

    let mut safe_from_bypass = Vec::with_capacity(case.keys.len());
    for (index, key) in case.keys.iter().enumerate() {
        let pubkey = &pubkeys()[index];
        match key.path {
            Reg::Boot => machine.register(pubkey, case.start_epoch),
            Reg::Import => machine.register_for_import(pubkey, case.start_epoch),
        }
        let bypass =
            permitted_bypass(key, case.start_epoch, case.genesis_confirmed, case.monitoring_epochs);
        let status = machine.status(pubkey);
        if bypass {
            prop_assert_eq!(status, ForwardWindowStatus::Safe);
        } else {
            prop_assert_eq!(status, ForwardWindowStatus::Pending);
        }
        prop_assert!(!machine.detected_latch());
        safe_from_bypass.push(bypass && status == ForwardWindowStatus::Safe);
    }

    let mut became_safe = vec![false; case.keys.len()];
    let mut seen_detected = vec![false; case.keys.len()];
    for (tick_index, tick) in case.ticks.iter().enumerate() {
        apply_tick(&machine, tick);
        let latch = machine.detected_latch();
        for (index, key) in case.keys.iter().enumerate() {
            let pubkey = &pubkeys()[index];
            let status = machine.status(pubkey);
            if seen_detected[index] {
                prop_assert_eq!(status, ForwardWindowStatus::Detected);
            }
            if safe_from_bypass[index] || became_safe[index] {
                prop_assert_eq!(status, ForwardWindowStatus::Safe);
            }
            let next_check = next_check_epoch(key.path, case.start_epoch);
            let prefix = &case.ticks[..=tick_index];
            if status == ForwardWindowStatus::Detected {
                prop_assert!(saw_blocking_live(prefix, index, next_check));
                seen_detected[index] = true;
            }
            if status == ForwardWindowStatus::Safe
                && !safe_from_bypass[index]
                && !became_safe[index]
            {
                let bypass = permitted_bypass(
                    key,
                    case.start_epoch,
                    case.genesis_confirmed,
                    case.monitoring_epochs,
                );
                prop_assert!(!bypass);
                prop_assert!(explains_monitored(prefix, index, next_check, case.monitoring_epochs));
                became_safe[index] = true;
            }
            if latch || status != ForwardWindowStatus::Safe {
                prop_assert!(!machine.is_signing_enabled(pubkey));
            } else {
                prop_assert!(machine.is_signing_enabled(pubkey));
            }
        }
    }

    let mut monitored_safe = false;
    let mut epoch0_bypass = false;
    let mut restart_bypass = false;
    for (index, key) in case.keys.iter().enumerate() {
        let status = machine.status(&pubkeys()[index]);
        let bypass =
            permitted_bypass(key, case.start_epoch, case.genesis_confirmed, case.monitoring_epochs);
        if status == ForwardWindowStatus::Safe && !bypass {
            monitored_safe = true;
        }
        if status == ForwardWindowStatus::Safe
            && key.path == Reg::Boot
            && case.start_epoch == 0
            && case.genesis_confirmed
        {
            epoch0_bypass = true;
        }
        if status == ForwardWindowStatus::Safe
            && key.path == Reg::Boot
            && should_skip_restart_monitoring(
                case.start_epoch,
                key.last_signed,
                case.monitoring_epochs,
            )
        {
            restart_bypass = true;
        }
    }
    Ok(Outcome { monitored_safe, epoch0_bypass, restart_bypass })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(0xD5D5_0001),
        ..ProptestConfig::default()
    })]

    #[test]
    fn safe_is_monitored_or_a_permitted_bypass(case in case_strategy()) {
        let _ = execute(&case)?;
    }
}

#[test]
fn generator_reaches_closing_tick() {
    let mut runner = TestRunner::new(ProptestConfig {
        rng_seed: RngSeed::Fixed(COVERAGE_SEED),
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let strategy = case_strategy();
    let mut closing = 0u32;
    let mut monitored_safe = 0u32;
    let mut epoch0_bypass = 0u32;
    let mut restart_bypass = 0u32;
    let mut opt_out = 0u32;
    for _ in 0..COVERAGE_CASES {
        let case = strategy.new_tree(&mut runner).expect("case strategy").current();
        if case.opt_out {
            opt_out += 1;
        }
        if trace_reaches_closing_tick(&case) {
            closing += 1;
        }
        let outcome =
            execute(&case).unwrap_or_else(|err| panic!("oracle rejected a generated case: {err}"));
        if outcome.monitored_safe {
            monitored_safe += 1;
        }
        if outcome.epoch0_bypass {
            epoch0_bypass += 1;
        }
        if outcome.restart_bypass {
            restart_bypass += 1;
        }
    }
    assert!(
        closing.saturating_mul(10) >= COVERAGE_CASES,
        "closing tick in {closing} of {COVERAGE_CASES}"
    );
    assert!(monitored_safe >= 1, "monitored Safe count {monitored_safe}");
    assert!(epoch0_bypass >= 1, "epoch-0 bypass count {epoch0_bypass}");
    assert!(restart_bypass >= 1, "restart bypass count {restart_bypass}");
    assert!(opt_out >= 1, "operator opt-out count {opt_out}");
}
