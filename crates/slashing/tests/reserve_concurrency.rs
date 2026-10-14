//! ARCH-5h — Proof surface 3: concurrency proptest over interleaved reservations.
//!
//! The EIP-3076 conformance vectors are necessary and insufficient (VD-S3): they
//! are single-threaded rule-engine fixtures. This file re-establishes the
//! double-sign property at the DB layer now that `reserve_*` releases the
//! connection mutex before the sign (the `BEGIN IMMEDIATE` guard no longer
//! spans it).
//!
//! **VD-5.7 hazard (do not walk into this when deleting `stage_*`):**
//! `crates/slashing/tests/conformance.rs:17-19` documents that the
//! `minimal_conservative` runner raises a watermark **after a successful
//! stage commit**. It reaches the staging API only through
//! `stage_and_commit_block` (`tests/common/mod.rs:17-24`) and
//! `stage_and_commit_attestation` (`:32-40`) — `conformance.rs` itself has
//! **zero** `stage_*` call sites. This file does **not** touch
//! `conformance.rs` or those helpers (A-5.2). If `stage_*` is ever deleted,
//! those two helpers must be re-pointed at `reserve_*` **and** taught that a
//! reconciled reservation must not leave a raised watermark behind.
//!
//! Oracle: production `crates/slashing/src/rules.rs` via
//! [`rvc_slashing::first_eip3076_history_violation`],
//! [`rvc_slashing::eip3076_allows_block`], and
//! [`rvc_slashing::eip3076_allows_attestation`] (`test-utils`).
//!
//! Bounds: 64 cases (override with `PROPTEST_CASES`), 8 worker threads,
//! shrinking on. Deterministic seed `0xA5C5000500000008` (`RngSeed::Fixed`).
//! Not `#[ignore]` — a switchover gate that CI does not run is not a gate.
//! Target wall: ≲ 30 s for `cargo nextest run -p rvc-slashing reserve_concurrency`.
//!
//! No test in this file is named `*_root` (KAT-first name scanner, A-5.10).

use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngSeed};
use rvc_slashing::{
    eip3076_allows_attestation, eip3076_allows_block, first_eip3076_history_violation,
    CanonicalPubkey, CommittedReservation, GroupCommitConfig, SignedAttestation, SignedBlock,
    SigningRoot, SlashingDb,
};

/// Documented default; `PROPTEST_CASES` wins when set.
const DEFAULT_CASES: u32 = 64;
/// Worker threads per property case (ARCH-5h bound).
const THREADS: usize = 8;
/// Pinned seed so a failure is reproducible without a regressions file.
const RNG_SEED: u64 = 0xA5C5_0005_0000_0008;
const K_PUBKEYS: u8 = 3;
const N_SLOTS: u64 = 8;
const GVR: [u8; 32] = [0u8; 32];

fn config() -> ProptestConfig {
    let cases =
        env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_CASES);
    ProptestConfig {
        cases,
        rng_seed: RngSeed::Fixed(RNG_SEED),
        // Shrinking stays on (`0` would disable it). Default `u32::MAX` is
        // "four times the case count"; keep that so RED can shrink to two ops.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn pk_hex(i: u8) -> String {
    format!("0xarch5h{i:02x}")
}

fn root_hex(i: u8) -> String {
    format!("0x5hroot{i:02x}")
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Duty {
    Block { pk: u8, slot: u64, root: u8 },
    Att { pk: u8, source: u64, target: u64, root: u8 },
}

impl Duty {
    fn pubkey(&self) -> String {
        match self {
            Self::Block { pk, .. } | Self::Att { pk, .. } => pk_hex(*pk),
        }
    }

    fn identity(&self) -> Identity {
        match *self {
            Self::Block { pk, slot, root } => {
                Identity::Block { pk: pk_hex(pk), slot, root: Some(root_hex(root)) }
            }
            Self::Att { pk, source, target, root } => {
                Identity::Att { pk: pk_hex(pk), source, target, root: Some(root_hex(root)) }
            }
        }
    }
}

/// Identity of a successful reserve / remaining history row.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Identity {
    Block { pk: String, slot: u64, root: Option<String> },
    Att { pk: String, source: u64, target: u64, root: Option<String> },
}

impl Identity {
    fn from_block(row: &SignedBlock) -> Self {
        Self::Block {
            pk: row.pubkey.to_string(),
            slot: row.slot,
            root: row.signing_root.as_ref().map(|r| r.as_hex().to_string()),
        }
    }

    fn from_att(row: &SignedAttestation) -> Self {
        Self::Att {
            pk: row.pubkey.to_string(),
            source: row.source_epoch,
            target: row.target_epoch,
            root: row.signing_root.as_ref().map(|r| r.as_hex().to_string()),
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Reserve(Duty),
    /// Reconcile the `k`-th `Reserve` in the script (0-based among Reserve ops).
    Reconcile(u8),
}

fn duty_strategy() -> impl Strategy<Value = Duty> {
    prop_oneof![
        (0u8..K_PUBKEYS, 0u64..N_SLOTS, 1u8..=4).prop_map(|(pk, slot, root)| Duty::Block {
            pk,
            slot,
            root
        }),
        // Small epoch space so surround / surrounded pairs are common (RED
        // shrinks a broken reserve to two such ops).
        (0u8..K_PUBKEYS, 0u64..6, 1u64..6, 1u8..=4).prop_map(|(pk, source, offset, root)| {
            Duty::Att { pk, source, target: source + offset, root }
        }),
    ]
}

/// Sequence of `Reserve` ops, each optionally followed by a `Reconcile` of
/// that same reservation. Shrinks toward a short reserve-only prefix.
fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec((duty_strategy(), any::<bool>()), 1..12).prop_map(|pairs| {
        let mut ops = Vec::with_capacity(pairs.len() * 2);
        for (i, (duty, reconcile)) in pairs.into_iter().enumerate() {
            ops.push(Op::Reserve(duty));
            if reconcile {
                ops.push(Op::Reconcile(i as u8));
            }
        }
        ops
    })
}

struct ReserveCell {
    duty: Duty,
    claimed: AtomicBool,
    result: Mutex<Option<Result<CommittedReservation, ()>>>,
}

fn reserve_duty(db: &SlashingDb, duty: &Duty) -> Result<CommittedReservation, ()> {
    match duty {
        Duty::Block { pk, slot, root } => {
            db.reserve_block(&pk_hex(*pk), *slot, Some(root_hex(*root)), &GVR).map_err(|_| ())
        }
        Duty::Att { pk, source, target, root } => db
            .reserve_attestation(&pk_hex(*pk), *source, *target, Some(root_hex(*root)), &GVR)
            .map_err(|_| ()),
    }
}

#[derive(Clone, Debug)]
enum Event {
    /// Linearized `reserve_*` of script-reserve `k`.
    Reserve { k: usize, duty: Duty },
    /// Linearized `reconcile_unsigned` of script-reserve `k`.
    Reconcile { k: usize },
}

fn ensure_reserved(db: &SlashingDb, k: usize, cell: &ReserveCell, log: &Mutex<Vec<Event>>) {
    if cell.claimed.swap(true, Ordering::SeqCst) {
        while cell.result.lock().expect("cell mutex").is_none() {
            thread::yield_now();
        }
        return;
    }
    let outcome = {
        // Hold the log lock across the DB call so the event order matches
        // the `BEGIN IMMEDIATE` linearization.
        let mut events = log.lock().expect("event log");
        let outcome = reserve_duty(db, &cell.duty);
        events.push(Event::Reserve { k, duty: cell.duty.clone() });
        outcome
    };
    *cell.result.lock().expect("cell mutex") = Some(outcome);
}

fn script_pubkeys(ops: &[Op]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for op in ops {
        if let Op::Reserve(d) = op {
            let pk = d.pubkey();
            if seen.insert(pk.clone()) {
                out.push(pk);
            }
        }
    }
    out
}

fn remaining_of(db: &SlashingDb, pubkeys: &[String]) -> (Vec<SignedBlock>, Vec<SignedAttestation>) {
    let mut blocks = Vec::new();
    let mut atts = Vec::new();
    for pk in pubkeys {
        blocks.extend(db.get_blocks(pk).expect("get_blocks"));
        atts.extend(db.get_attestations(pk).expect("get_attestations"));
    }
    (blocks, atts)
}

fn assert_oracle(pubkeys: &[String], blocks: &[SignedBlock], atts: &[SignedAttestation]) {
    let mut by_pk_blocks: HashMap<&str, Vec<SignedBlock>> = HashMap::new();
    let mut by_pk_atts: HashMap<&str, Vec<SignedAttestation>> = HashMap::new();
    for b in blocks {
        by_pk_blocks.entry(b.pubkey.as_ref()).or_default().push(b.clone());
    }
    for a in atts {
        by_pk_atts.entry(a.pubkey.as_ref()).or_default().push(a.clone());
    }
    for pk in pubkeys {
        let b = by_pk_blocks.get(pk.as_str()).cloned().unwrap_or_default();
        let a = by_pk_atts.get(pk.as_str()).cloned().unwrap_or_default();
        if let Some(v) = first_eip3076_history_violation(pk, &b, &a) {
            panic!("eip-3076 history violation for {pk}: {v}");
        }
    }
}

struct ConcurrentRun {
    accepted: HashSet<Identity>,
    remaining_blocks: Vec<SignedBlock>,
    remaining_atts: Vec<SignedAttestation>,
    events: Vec<Event>,
}

fn run_concurrent(ops: &[Op]) -> ConcurrentRun {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let duties: Vec<Duty> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Reserve(d) => Some(d.clone()),
            Op::Reconcile(_) => None,
        })
        .collect();
    let cells: Arc<Vec<ReserveCell>> = Arc::new(
        duties
            .into_iter()
            .map(|duty| ReserveCell {
                duty,
                claimed: AtomicBool::new(false),
                result: Mutex::new(None),
            })
            .collect(),
    );
    let cursor = AtomicUsize::new(0);
    let log = Mutex::new(Vec::new());
    let n = ops.len();
    let workers = THREADS.min(n.max(1));

    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    match &ops[i] {
                        Op::Reserve(_) => {
                            // The k-th Reserve in the script is cells[k]; count
                            // Reserve ops up to and including this index.
                            let k = ops[..i].iter().filter(|o| matches!(o, Op::Reserve(_))).count();
                            ensure_reserved(&db, k, &cells[k], &log);
                        }
                        Op::Reconcile(k) => {
                            let k = *k as usize;
                            if let Some(cell) = cells.get(k) {
                                ensure_reserved(&db, k, cell, &log);
                                if let Some(Ok(res)) = cell.result.lock().expect("cell").clone() {
                                    let mut events = log.lock().expect("event log");
                                    let _ = db.reconcile_unsigned(&res);
                                    events.push(Event::Reconcile { k });
                                }
                            }
                        }
                    }
                }
            });
        }
    });

    let mut accepted = HashSet::new();
    for cell in cells.iter() {
        if matches!(cell.result.lock().expect("cell").as_ref(), Some(Ok(_))) {
            accepted.insert(cell.duty.identity());
        }
    }
    let pubkeys = script_pubkeys(ops);
    let (remaining_blocks, remaining_atts) = remaining_of(&db, &pubkeys);
    let events = log.into_inner().expect("event log");
    ConcurrentRun { accepted, remaining_blocks, remaining_atts, events }
}

fn parse_pk(s: &str) -> CanonicalPubkey {
    match s.parse() {
        Ok(pk) => pk,
        Err(never) => match never {},
    }
}

fn signed_block(duty: &Duty) -> Option<SignedBlock> {
    match *duty {
        Duty::Block { pk, slot, root } => Some(SignedBlock {
            pubkey: parse_pk(&pk_hex(pk)),
            slot,
            signing_root: Some(SigningRoot::from_hex(root_hex(root))),
        }),
        Duty::Att { .. } => None,
    }
}

fn signed_att(duty: &Duty) -> Option<SignedAttestation> {
    match *duty {
        Duty::Att { pk, source, target, root } => Some(SignedAttestation {
            pubkey: parse_pk(&pk_hex(pk)),
            source_epoch: source,
            target_epoch: target,
            signing_root: Some(SigningRoot::from_hex(root_hex(root))),
        }),
        Duty::Block { .. } => None,
    }
}

/// Sequential `rules.rs` replay of a linearized reserve/reconcile schedule.
///
/// Reconcile of a resign (`inserted == false`) is a no-op, matching
/// production. The accepted set is every reserve the oracle allows given
/// history-so-far; remaining is what is still present after deletes.
fn simulate(events: &[Event]) -> (HashSet<Identity>, HashSet<Identity>) {
    let n = events
        .iter()
        .map(|e| match e {
            Event::Reserve { k, .. } | Event::Reconcile { k } => *k,
        })
        .max()
        .map(|k| k + 1)
        .unwrap_or(0);
    let mut inserted = vec![false; n];
    let mut present = vec![false; n];
    let mut duties: Vec<Option<Duty>> = vec![None; n];
    let mut blocks: HashMap<String, Vec<SignedBlock>> = HashMap::new();
    let mut atts: HashMap<String, Vec<SignedAttestation>> = HashMap::new();
    let mut accepted = HashSet::new();

    for ev in events {
        match ev {
            Event::Reserve { k, duty } => {
                if *k >= duties.len() {
                    continue;
                }
                duties[*k] = Some(duty.clone());
                let pk = duty.pubkey();
                let allow = match duty {
                    Duty::Block { slot, root, .. } => {
                        let hist = blocks.get(&pk).cloned().unwrap_or_default();
                        eip3076_allows_block(&pk, &hist, *slot, Some(root_hex(*root)), false)
                    }
                    Duty::Att { source, target, root, .. } => {
                        let hist = atts.get(&pk).cloned().unwrap_or_default();
                        eip3076_allows_attestation(
                            &pk,
                            &hist,
                            *source,
                            *target,
                            Some(root_hex(*root)),
                            false,
                        )
                    }
                };
                if !allow {
                    continue;
                }
                accepted.insert(duty.identity());
                let is_new = match duty {
                    Duty::Block { slot, .. } => {
                        !blocks.get(&pk).is_some_and(|h| h.iter().any(|b| b.slot == *slot))
                    }
                    Duty::Att { target, .. } => {
                        !atts.get(&pk).is_some_and(|h| h.iter().any(|a| a.target_epoch == *target))
                    }
                };
                if is_new {
                    inserted[*k] = true;
                    present[*k] = true;
                    match duty {
                        Duty::Block { .. } => {
                            blocks.entry(pk).or_default().push(signed_block(duty).expect("block"));
                        }
                        Duty::Att { .. } => {
                            atts.entry(pk).or_default().push(signed_att(duty).expect("att"));
                        }
                    }
                }
            }
            Event::Reconcile { k } => {
                if !inserted.get(*k).copied().unwrap_or(false)
                    || !present.get(*k).copied().unwrap_or(false)
                {
                    continue;
                }
                let Some(duty) = duties[*k].as_ref() else { continue };
                let id = duty.identity();
                match duty {
                    Duty::Block { .. } => {
                        if let Some(h) = blocks.get_mut(&duty.pubkey()) {
                            h.retain(|b| Identity::from_block(b) != id);
                        }
                    }
                    Duty::Att { .. } => {
                        if let Some(h) = atts.get_mut(&duty.pubkey()) {
                            h.retain(|a| Identity::from_att(a) != id);
                        }
                    }
                }
                present[*k] = false;
            }
        }
    }

    let mut remaining = HashSet::new();
    for (k, p) in present.iter().enumerate() {
        if *p {
            if let Some(d) = duties[k].as_ref() {
                remaining.insert(d.identity());
            }
        }
    }
    (accepted, remaining)
}

fn remaining_identities(blocks: &[SignedBlock], atts: &[SignedAttestation]) -> HashSet<Identity> {
    blocks.iter().map(Identity::from_block).chain(atts.iter().map(Identity::from_att)).collect()
}

// =========================================================================
// Property 1: interleaved reservations preserve EIP-3076 history
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn prop_interleaved_reservations_preserve_eip3076_history(ops in ops_strategy()) {
        let run = run_concurrent(&ops);
        let pubkeys = script_pubkeys(&ops);
        assert_oracle(&pubkeys, &run.remaining_blocks, &run.remaining_atts);
    }
}

// =========================================================================
// Property 2: reconcile never widens the accepted set
// =========================================================================

proptest! {
    #![proptest_config(config())]

    /// Reconcile must not accept anything a sequential `rules.rs` replay of
    /// the same linearized schedule would refuse, and must not invent a
    /// remaining row. (A two-world "no-reconcile accepts ⊆ reconciled"
    /// comparison is *not* the property: deleting A can admit B, and B can
    /// then refuse C, so the during-run accept sets are incomparable.)
    ///
    /// The observed DB accept/remaining sets must equal the oracle replay —
    /// a concurrent run that skipped the in-txn check would keep a surround
    /// pair the sequential engine rejects.
    #[test]
    fn prop_reconcile_never_widens_the_accepted_set(ops in ops_strategy()) {
        let conc = run_concurrent(&ops);
        let pubkeys = script_pubkeys(&ops);
        assert_oracle(&pubkeys, &conc.remaining_blocks, &conc.remaining_atts);

        let (oracle_accepted, oracle_remaining) = simulate(&conc.events);
        prop_assert!(
            conc.accepted.is_subset(&oracle_accepted),
            "concurrent accepts {:?} exceed sequential rules.rs {:?}",
            conc.accepted.difference(&oracle_accepted).collect::<Vec<_>>(),
            oracle_accepted,
        );
        let remaining = remaining_identities(&conc.remaining_blocks, &conc.remaining_atts);
        prop_assert_eq!(
            &remaining,
            &oracle_remaining,
            "remaining {:?} != sequential-oracle remaining {:?}",
            remaining,
            oracle_remaining,
        );
        prop_assert!(
            remaining.is_subset(&conc.accepted),
            "remaining row was never a successful reserve: {:?}",
            remaining.difference(&conc.accepted).collect::<Vec<_>>(),
        );
    }
}

// =========================================================================
// Deterministic companion — distinguish a proptest flake from a regression
// =========================================================================

#[test]
fn test_two_threads_reserving_the_same_slot_produce_exactly_one_row() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let pk = pk_hex(0);
    let db_a = Arc::clone(&db);
    let db_b = Arc::clone(&db);
    let pk_a = pk.clone();
    let pk_b = pk.clone();

    let t_a = thread::spawn(move || db_a.reserve_block(&pk_a, 42, Some(root_hex(1)), &GVR));
    let t_b = thread::spawn(move || db_b.reserve_block(&pk_b, 42, Some(root_hex(2)), &GVR));

    let r_a = t_a.join().expect("thread A");
    let r_b = t_b.join().expect("thread B");
    let ok_count = usize::from(r_a.is_ok()) + usize::from(r_b.is_ok());
    assert_eq!(
        ok_count, 1,
        "exactly one of the two same-slot reserves must succeed; A={r_a:?} B={r_b:?}"
    );
    let rows = db.get_blocks(&pk).expect("get_blocks");
    assert_eq!(rows.len(), 1, "history must contain exactly one row for the slot");
    assert_eq!(rows[0].slot, 42);
}

/// Batch-boundary (#205): one slashable member must not fail the COMMIT.
#[test]
fn test_slashable_member_does_not_fail_the_rest_of_a_group_commit() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.set_group_commit(GroupCommitConfig {
        batch_size: 3,
        wait_to_fill: std::time::Duration::from_millis(80),
    });
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let pk_a = pk_hex(0);
    let pk_b = pk_hex(1);

    let db_ok = Arc::clone(&db);
    let b_ok = Arc::clone(&barrier);
    let pk = pk_a.clone();
    let t_ok = thread::spawn(move || {
        b_ok.wait();
        db_ok.reserve_block(&pk, 10, Some(root_hex(1)), &GVR)
    });

    let db_bad = Arc::clone(&db);
    let b_bad = Arc::clone(&barrier);
    let pk = pk_a.clone();
    let t_bad = thread::spawn(move || {
        b_bad.wait();
        db_bad.reserve_block(&pk, 10, Some(root_hex(2)), &GVR)
    });

    let db_other = Arc::clone(&db);
    let b_other = Arc::clone(&barrier);
    let pk = pk_b.clone();
    let t_other = thread::spawn(move || {
        b_other.wait();
        db_other.reserve_block(&pk, 11, Some(root_hex(3)), &GVR)
    });

    let r_ok = t_ok.join().expect("join");
    let r_bad = t_bad.join().expect("join");
    let r_other = t_other.join().expect("join");
    let ok_count = usize::from(r_ok.is_ok()) + usize::from(r_bad.is_ok());
    assert_eq!(ok_count, 1, "exactly one of the conflicting reserves must succeed");
    assert!(r_other.is_ok(), "unrelated member must commit; {r_other:?}");
    assert_eq!(db.get_blocks(&pk_a).expect("A").len(), 1);
    assert_eq!(db.get_blocks(&pk_b).expect("B").len(), 1);
}

/// Batch-boundary (#205): COMMIT failure rejects every member, no leftover rows.
#[test]
fn test_group_commit_failure_rejects_every_member() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.set_group_commit(GroupCommitConfig {
        batch_size: 3,
        wait_to_fill: std::time::Duration::from_millis(80),
    });
    db.fail_next_commits(1);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for i in 0..3u8 {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let pk = pk_hex(i);
        handles.push(thread::spawn(move || {
            barrier.wait();
            db.reserve_block(&pk, u64::from(i) + 1, Some(root_hex(i + 1)), &GVR)
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        let err = h.join().expect("join").expect_err("COMMIT fail must reject");
        assert!(err.is_reserve_commit_failure(), "member {i}: {err:?}");
        assert!(db.get_blocks(&pk_hex(i as u8)).expect("get").is_empty());
    }
}
