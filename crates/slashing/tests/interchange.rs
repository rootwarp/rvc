//! Import-conflict observability and watermark floors (RR-4.2), and
//! drop-and-synthesise export (RR-4.3).

mod support;

use std::sync::Mutex;
use std::time::Duration;

use proptest::prelude::*;
use rvc_slashing::metrics::{
    RVC_SLASHING_EXPORT_SYNTHETIC_RECORDS_TOTAL, RVC_SLASHING_IMPORT_CONFLICTS_TOTAL,
    RVC_SLASHING_IMPORT_CONN_HOLD_MS, RVC_SLASHING_IMPORT_DURATION_MS,
};
use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, InterchangeAttestation, InterchangeBlock,
    InterchangeFormat, InterchangeMetadata, SlashingDb, SlashingError, ValidatorRecord,
};
use support::{refuses, same_slot_is_double_proposal, slashable_attestation_pair, Candidate};

/// The conflict counter is process-global. Hold this across a delta assertion
/// so a parallel import cannot land between the snapshots.
static CONFLICT_METRIC: Mutex<()> = Mutex::new(());

/// Same for synthetic-export increments. Proptest and the fixture tests share
/// the process counter.
static EXPORT_METRIC: Mutex<()> = Mutex::new(());

/// Import timing histograms are process-global. Hold this across a delta so
/// another import in this process cannot land between the snapshots.
static IMPORT_TIMING_METRIC: Mutex<()> = Mutex::new(());

const IMPORT_MS_BUCKETS: [f64; 10] =
    [10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0];

const OTHER_PUBKEY: &str = "0xaaaa";
/// Row and watermark domain for the export proptest, and the candidate grid.
const EXPORT_DOMAIN: u64 = 8;
const EXPORT_PROPTEST_CASES: u32 = 128;

const CHAIN_GVR_HEX: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
/// 48-byte key so [`observability::logging::TruncatedPubkey`] actually truncates.
const PUBKEY: &str = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
const PUBKEY_TRUNCATED: &str = "0x93247f2209...611df74a";

fn chain_gvr() -> [u8; 32] {
    let bytes = hex::decode(CHAIN_GVR_HEX.strip_prefix("0x").expect("prefix")).expect("hex");
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

fn att(source: &str, target: &str, signing_root: Option<String>) -> InterchangeAttestation {
    InterchangeAttestation {
        source_epoch: source.to_string(),
        target_epoch: target.to_string(),
        signing_root,
    }
}

fn interchange(
    signed_attestations: Vec<InterchangeAttestation>,
    signed_blocks: Vec<InterchangeBlock>,
) -> InterchangeFormat {
    InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: CHAIN_GVR_HEX.to_string(),
        },
        data: vec![ValidatorRecord {
            pubkey: PUBKEY.to_string(),
            signed_blocks,
            signed_attestations,
        }],
    }
}

fn conflicts() -> u64 {
    RVC_SLASHING_IMPORT_CONFLICTS_TOTAL.get()
}

fn hold_samples() -> u64 {
    RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count()
}

fn duration_samples() -> u64 {
    RVC_SLASHING_IMPORT_DURATION_MS.get_sample_count()
}

fn hold_sum_ms() -> f64 {
    RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_sum()
}

fn duration_sum_ms() -> f64 {
    RVC_SLASHING_IMPORT_DURATION_MS.get_sample_sum()
}

#[tracing_test::traced_test]
#[test]
fn a_dropped_conflicting_attestation_is_logged_and_counted() {
    let _guard = CONFLICT_METRIC.lock().expect("conflict metric lock");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    let before = conflicts();

    db.import(&interchange(vec![att("1", "10", Some("0xexisting".into()))], vec![]), &gvr)
        .expect("first import lands");
    assert_eq!(conflicts(), before, "a landed attestation is not a conflict");

    db.import(&interchange(vec![att("5", "10", Some("0xother".into()))], vec![]), &gvr)
        .expect("conflicting import");
    assert_eq!(conflicts(), before + 1, "one dropped attestation increments once");

    let rows = db.get_attestations(PUBKEY).expect("rows");
    assert_eq!(rows.len(), 1, "the conflicting row must not land");
    assert_eq!(rows[0].source_epoch, 1);
    assert_eq!(rows[0].target_epoch, 10);

    assert!(
        logs_contain("dropped conflicting interchange attestation (source, target)=(5, 10)"),
        "log must name the dropped (source, target)"
    );
    assert!(logs_contain(PUBKEY_TRUNCATED), "log must name the truncated pubkey");
    assert!(!logs_contain(PUBKEY), "raw pubkey must not appear in the import conflict log");
}

#[tracing_test::traced_test]
#[test]
fn a_dropped_conflicting_block_is_logged_and_counted() {
    let _guard = CONFLICT_METRIC.lock().expect("conflict metric lock");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    let before = conflicts();

    db.import(
        &interchange(
            vec![],
            vec![InterchangeBlock {
                slot: "100".to_string(),
                signing_root: Some("0xblock".into()),
            }],
        ),
        &gvr,
    )
    .expect("first block import lands");
    assert_eq!(conflicts(), before, "a landed block is not a conflict");

    db.import(
        &interchange(
            vec![],
            vec![InterchangeBlock {
                slot: "100".to_string(),
                signing_root: Some("0xotherblock".into()),
            }],
        ),
        &gvr,
    )
    .expect("conflicting block import");
    assert_eq!(conflicts(), before + 1, "one dropped block increments once");

    let blocks = db.get_blocks(PUBKEY).expect("blocks");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].slot, 100);
    assert_eq!(blocks[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xblock"));

    assert!(
        logs_contain("dropped conflicting interchange block slot=100"),
        "log must name the dropped slot"
    );
    assert!(logs_contain(PUBKEY_TRUNCATED), "log must name the truncated pubkey");
    assert!(!logs_contain(PUBKEY), "raw pubkey must not appear in the import conflict log");
}

/// R01/R02: import raises the source watermark above rows already in the DB.
#[test]
fn import_raises_the_source_watermark_above_existing_rows() {
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    db.seed_attestation(PUBKEY, 1, 2, Some("0xstart".into()), &gvr).expect("seed (1, 2)");
    assert!(db.get_attestation_watermark(PUBKEY).expect("wm").is_none());

    db.import(&interchange(vec![att("5", "10", None)], vec![]), &gvr).expect("import (5, 10)");
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("wm"), Some((5, 10)));

    let err = db
        .stage_attestation(PUBKEY, 2, 4, Some("0xrequest".into()), &gvr)
        .expect_err("request (2, 4) must be below the imported source watermark");
    match err {
        SlashingError::BelowAttestationSourceWatermark {
            source_epoch, watermark_source, ..
        } => {
            assert_eq!(source_epoch, 2);
            assert_eq!(watermark_source, 5);
        }
        other => panic!("expected BelowAttestationSourceWatermark, got {other:?}"),
    }
}

/// R02 / PB-A1 path 2: a row `WHERE NOT EXISTS` drops still raises the watermark.
#[test]
fn a_dropped_conflicting_row_still_raises_the_watermark() {
    let _guard = CONFLICT_METRIC.lock().expect("conflict metric lock");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    db.seed_attestation(PUBKEY, 1, 10, Some("0xrow".into()), &gvr).expect("seed (1, 10)");

    db.import(&interchange(vec![att("5", "10", Some("0xconflict".into()))], vec![]), &gvr)
        .expect("conflicting import");

    let rows = db.get_attestations(PUBKEY).expect("rows");
    assert_eq!(rows.len(), 1, "conflicting row must not land");
    assert_eq!(rows[0].source_epoch, 1);
    assert_eq!(rows[0].target_epoch, 10);
    assert_eq!(
        db.get_attestation_watermark(PUBKEY).expect("wm"),
        Some((5, 10)),
        "dropped (5, 10) still raises the watermark"
    );

    // (2, 11) is not a double vote or surround against the stored (1, 10).
    // Only the source watermark raised by the dropped row refuses it.
    let err = db
        .stage_attestation(PUBKEY, 2, 11, Some("0xabove".into()), &gvr)
        .expect_err("source watermark from the dropped row must refuse (2, 11)");
    match err {
        SlashingError::BelowAttestationSourceWatermark {
            source_epoch, watermark_source, ..
        } => {
            assert_eq!(source_epoch, 2);
            assert_eq!(watermark_source, 5);
        }
        other => panic!("expected BelowAttestationSourceWatermark, got {other:?}"),
    }
}

/// Q2: a re-imported null signing-root synthetic does not mask a double vote.
///
/// Same scenario as the 2026-09-27 probe: import `{5, 10, signing_root: null}`,
/// then a different source at target 10 is refused by the target watermark
/// before `(None, None) if !strict => is_duplicate`.
#[test]
fn a_reimported_null_signing_root_synthetic_does_not_mask_a_double_vote() {
    let gvr = chain_gvr();
    let json = format!(
        r#"{{
  "metadata": {{
    "interchange_format_version": "5",
    "genesis_validators_root": "{CHAIN_GVR_HEX}"
  }},
  "data": [{{
    "pubkey": "{PUBKEY}",
    "signed_blocks": [],
    "signed_attestations": [{{
      "source_epoch": "5",
      "target_epoch": "10",
      "signing_root": null
    }}]
  }}]
}}"#
    );
    let interchange: InterchangeFormat = serde_json::from_str(&json).expect("parse synthetic");
    assert!(interchange.data[0].signed_attestations[0].signing_root.is_none());

    let db = SlashingDb::open_in_memory().expect("scratch db");
    db.import(&interchange, &gvr).expect("import synthetic");
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("wm"), Some((5, 10)));
    let rows = db.get_attestations(PUBKEY).expect("rows");
    assert_eq!(rows.len(), 1);
    assert!(rows[0].signing_root.is_none());

    // Source 7 is not below the source watermark, so the target check is the one
    // that returns before the duplicate arm.
    let real = db
        .stage_attestation(PUBKEY, 7, 10, Some("0xreal_double_vote".into()), &gvr)
        .expect_err("real double vote must be refused");
    match real {
        SlashingError::BelowAttestationWatermark { target_epoch, watermark_target, .. } => {
            assert_eq!(target_epoch, 10);
            assert_eq!(watermark_target, 10);
        }
        other => panic!("expected target watermark refusal, got {other:?}"),
    }

    let null_vote = db
        .stage_attestation(PUBKEY, 7, 10, None, &gvr)
        .expect_err("(None, None) candidate must not be accepted as a duplicate");
    match null_vote {
        SlashingError::BelowAttestationWatermark { target_epoch, watermark_target, .. } => {
            assert_eq!(target_epoch, 10);
            assert_eq!(watermark_target, 10);
        }
        other => panic!("(None, None) candidate passed the watermark check: {other:?}"),
    }
    assert_eq!(db.get_attestations(PUBKEY).expect("rows").len(), 1);

    // The arm would allow this candidate if import had not raised the watermark.
    let bare = SlashingDb::open_in_memory().expect("control db");
    bare.seed_attestation(PUBKEY, 5, 10, None, &gvr).expect("seed");
    assert!(bare.get_attestation_watermark(PUBKEY).expect("wm").is_none());
    let masked = bare
        .stage_attestation(PUBKEY, 7, 10, None, &gvr)
        .expect("without a watermark the (None, None) arm allows the different-source vote");
    drop(masked);
}

fn export_metric_lock() -> std::sync::MutexGuard<'static, ()> {
    EXPORT_METRIC.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn synthetic_count() -> u64 {
    RVC_SLASHING_EXPORT_SYNTHETIC_RECORDS_TOTAL.get()
}

fn only_validator<'a>(file: &'a InterchangeFormat, pubkey: &str) -> &'a ValidatorRecord {
    let matches: Vec<_> = file.data.iter().filter(|record| record.pubkey == pubkey).collect();
    assert_eq!(matches.len(), 1, "validator {pubkey} missing or duplicated in export");
    matches[0]
}

fn attestation_triples(record: &ValidatorRecord) -> Vec<(u64, u64, Option<String>)> {
    record
        .signed_attestations
        .iter()
        .map(|att| {
            (
                att.source_epoch.parse().expect("source"),
                att.target_epoch.parse().expect("target"),
                att.signing_root.clone(),
            )
        })
        .collect()
}

/// Independent fixed point. Not the production function.
fn reference_floor(
    rows: &[(u64, u64)],
    source_wm: u64,
    target_wm: u64,
) -> Result<(u64, u64), (u64, u64)> {
    let mut target_bound = target_wm;
    let mut source_bound;
    loop {
        source_bound = source_wm;
        for &(source, target) in rows {
            if target <= target_bound {
                source_bound = source_bound.max(source);
            }
        }
        let mut raised: Option<u64> = None;
        for &(source, target) in rows {
            if target > target_bound && source < source_bound {
                raised = Some(raised.map_or(target, |current| current.max(target)));
            }
        }
        match raised {
            Some(next) => target_bound = next,
            None => break,
        }
    }
    if source_bound > target_bound {
        Err((source_bound, target_bound))
    } else {
        Ok((source_bound, target_bound))
    }
}

/// Watermark floors plus double-vote/surround. Min-target and min-slot are
/// not part of the antecedent: `stage_*` reports those gap rules separately
/// from the watermark checks.
fn db_refuses_attestation(
    db: &SlashingDb,
    pubkey: &str,
    source: u64,
    target: u64,
    gvr: &[u8; 32],
) -> bool {
    let root = Some(format!("0xfresh-a-{source}-{target}"));
    match db.stage_attestation(pubkey, source, target, root, gvr) {
        Ok(staged) => {
            staged.discard();
            false
        }
        Err(SlashingError::BelowAttestationWatermark { .. })
        | Err(SlashingError::BelowAttestationSourceWatermark { .. })
        | Err(SlashingError::SlashableAttestation(
            AttestationSlashingViolation::DoubleVote { .. }
            | AttestationSlashingViolation::SurroundingVote { .. }
            | AttestationSlashingViolation::SurroundedVote { .. },
        )) => true,
        Err(SlashingError::SlashableAttestation(
            AttestationSlashingViolation::TargetEpochBelowMinimum { .. },
        )) => false,
        Err(other) => panic!("unexpected stage_attestation error: {other:?}"),
    }
}

fn db_refuses_block(db: &SlashingDb, pubkey: &str, slot: u64, gvr: &[u8; 32]) -> bool {
    let root = Some(format!("0xfresh-b-{slot}"));
    match db.stage_block(pubkey, slot, root, gvr) {
        Ok(staged) => {
            staged.discard();
            false
        }
        Err(SlashingError::BelowBlockWatermark { .. })
        | Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
            ..
        })) => true,
        Err(SlashingError::SlashableBlock(BlockSlashingViolation::SlotBelowMinimum { .. })) => {
            false
        }
        Err(other) => panic!("unexpected stage_block error: {other:?}"),
    }
}

fn assert_no_synthetic_slashable_pair(file: &InterchangeFormat) {
    for record in &file.data {
        for (i, left) in record.signed_attestations.iter().enumerate() {
            if left.signing_root.is_some() {
                continue;
            }
            for (j, right) in record.signed_attestations.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !slashable_attestation_pair(left, right),
                    "synthetic attestation forms a slashable pair: {left:?} vs {right:?}"
                );
            }
        }
        for (i, left) in record.signed_blocks.iter().enumerate() {
            if left.signing_root.is_some() {
                continue;
            }
            for (j, right) in record.signed_blocks.iter().enumerate() {
                if i != j {
                    assert!(
                        !same_slot_is_double_proposal(left, right),
                        "synthetic block shares slot {} with another record",
                        left.slot
                    );
                }
            }
        }
    }
}

fn assert_non_weakening(
    db: &SlashingDb,
    file: &InterchangeFormat,
    pubkeys: &[&str],
    gvr: &[u8; 32],
    domain: u64,
) {
    assert_no_synthetic_slashable_pair(file);
    for pubkey in pubkeys {
        for source in 0..domain {
            for target in source..domain {
                if !db_refuses_attestation(db, pubkey, source, target, gvr) {
                    continue;
                }
                let candidate = Candidate::Attestation {
                    source_epoch: source,
                    target_epoch: target,
                    signing_root: Some(format!("0xfresh-a-{source}-{target}")),
                };
                assert!(
                    refuses(file, pubkey, &candidate),
                    "export weakened attestation ({source}, {target}) for {pubkey}"
                );
            }
        }
        for slot in 0..domain {
            if !db_refuses_block(db, pubkey, slot, gvr) {
                continue;
            }
            let candidate =
                Candidate::Block { slot, signing_root: Some(format!("0xfresh-b-{slot}")) };
            assert!(
                refuses(file, pubkey, &candidate),
                "export weakened block slot {slot} for {pubkey}"
            );
        }
    }
}

fn model_refuses_grid(
    first: &InterchangeFormat,
    second: &InterchangeFormat,
    pubkey: &str,
    domain: u64,
) {
    for source in 0..domain {
        for target in source..domain {
            let candidate = Candidate::Attestation {
                source_epoch: source,
                target_epoch: target,
                signing_root: Some(format!("0xfresh-a-{source}-{target}")),
            };
            if refuses(first, pubkey, &candidate) {
                assert!(
                    refuses(second, pubkey, &candidate),
                    "second file allowed attestation ({source}, {target}) the first refuses"
                );
            }
        }
    }
    for slot in 0..domain {
        let candidate = Candidate::Block { slot, signing_root: Some(format!("0xfresh-b-{slot}")) };
        if refuses(first, pubkey, &candidate) {
            assert!(
                refuses(second, pubkey, &candidate),
                "second file allowed block slot {slot} the first refuses"
            );
        }
    }
}

fn floors_bounded_by_surviving_maxima(
    first: &InterchangeFormat,
    second: &InterchangeFormat,
    pubkey: &str,
) {
    let first_atts = &only_validator(first, pubkey).signed_attestations;
    let second_atts = &only_validator(second, pubkey).signed_attestations;
    if !first_atts.is_empty() && !second_atts.is_empty() {
        let max_source =
            first_atts.iter().map(|att| att.source_epoch.parse::<u64>().unwrap()).max().unwrap();
        let max_target =
            first_atts.iter().map(|att| att.target_epoch.parse::<u64>().unwrap()).max().unwrap();
        let min_source =
            second_atts.iter().map(|att| att.source_epoch.parse::<u64>().unwrap()).min().unwrap();
        let min_target =
            second_atts.iter().map(|att| att.target_epoch.parse::<u64>().unwrap()).min().unwrap();
        assert!(
            min_source <= max_source,
            "second source floor {min_source} exceeds surviving max {max_source}"
        );
        assert!(
            min_target <= max_target,
            "second target floor {min_target} exceeds surviving max {max_target}"
        );
    }
    let first_blocks = &only_validator(first, pubkey).signed_blocks;
    let second_blocks = &only_validator(second, pubkey).signed_blocks;
    if !first_blocks.is_empty() && !second_blocks.is_empty() {
        let max_slot =
            first_blocks.iter().map(|block| block.slot.parse::<u64>().unwrap()).max().unwrap();
        let min_slot =
            second_blocks.iter().map(|block| block.slot.parse::<u64>().unwrap()).min().unwrap();
        assert!(
            min_slot <= max_slot,
            "second slot floor {min_slot} exceeds surviving max {max_slot}"
        );
    }
}

#[derive(Debug, Clone)]
struct ValSpec {
    atts: Vec<(u64, u64)>,
    blocks: Vec<u64>,
    att_wm: Option<(u64, u64)>,
    block_wm: Option<u64>,
}

fn val_strategy() -> impl Strategy<Value = ValSpec> {
    (
        prop::collection::vec((0u64..EXPORT_DOMAIN, 0u64..EXPORT_DOMAIN), 0..5),
        prop::collection::vec(0u64..EXPORT_DOMAIN, 0..4),
        prop::option::of((0u64..EXPORT_DOMAIN, 0u64..EXPORT_DOMAIN)),
        prop::option::of(0u64..EXPORT_DOMAIN),
    )
        .prop_map(|(atts, blocks, att_wm, block_wm)| {
            let mut seen_targets = std::collections::HashSet::new();
            let atts =
                atts.into_iter().filter(|(_, target)| seen_targets.insert(*target)).collect();
            let mut seen_slots = std::collections::HashSet::new();
            let blocks = blocks.into_iter().filter(|slot| seen_slots.insert(*slot)).collect();
            ValSpec { atts, blocks, att_wm, block_wm }
        })
}

fn load_spec(db: &SlashingDb, pubkey: &str, spec: &ValSpec, gvr: &[u8; 32]) {
    for &(source, target) in &spec.atts {
        db.seed_attestation(pubkey, source, target, Some(format!("0xrow-{target}")), gvr)
            .expect("seed attestation");
    }
    for &slot in &spec.blocks {
        db.seed_block(pubkey, slot, Some(format!("0xblk-{slot}")), gvr).expect("seed block");
    }
    if let Some((source, target)) = spec.att_wm {
        db.set_attestation_watermark(pubkey, source, target).expect("set attestation watermark");
    }
    if let Some(slot) = spec.block_wm {
        db.set_block_watermark(pubkey, slot).expect("set block watermark");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EXPORT_PROPTEST_CASES))]

    #[test]
    fn export_is_non_weakening_against_the_eip3076_model(
        left in val_strategy(),
        right in val_strategy(),
    ) {
        let _guard = export_metric_lock();
        let gvr = chain_gvr();
        let db = SlashingDb::open_in_memory().expect("open");
        let specs = [left, right];
        let pubkeys = [PUBKEY, OTHER_PUBKEY];
        for (pubkey, spec) in pubkeys.iter().zip(specs.iter()) {
            load_spec(&db, pubkey, spec, &gvr);
        }

        match db.export(&gvr) {
            Err(SlashingError::UnrepresentableFloor { pubkey, source_bound, target_bound }) => {
                let spec = specs
                    .iter()
                    .zip(pubkeys)
                    .find(|(_, pk)| *pk == pubkey)
                    .map(|(spec, _)| spec)
                    .expect("error names a loaded pubkey");
                let (source_wm, target_wm) = spec.att_wm.expect("floor error requires attestation watermarks");
                let Err((s_star, t_star)) = reference_floor(&spec.atts, source_wm, target_wm) else {
                    panic!("export failed closed but the reference floor is representable");
                };
                prop_assert!(s_star > t_star, "S* = {s_star}, T* = {t_star}");
                prop_assert_eq!(source_bound, s_star);
                prop_assert_eq!(target_bound, t_star);
            }
            Err(other) => panic!("unexpected export error: {other:?}"),
            Ok(file) => {
                for (pubkey, spec) in pubkeys.iter().zip(specs.iter()) {
                    if let Some((source_wm, target_wm)) = spec.att_wm {
                        prop_assert!(
                            reference_floor(&spec.atts, source_wm, target_wm).is_ok(),
                            "export succeeded but S* > T* for {pubkey}"
                        );
                    }
                }
                assert_non_weakening(&db, &file, &pubkeys, &gvr, EXPORT_DOMAIN);
            }
        }
    }
}

#[test]
fn export_fixture_rows_5_10_wm_1_11_is_exactly_synthetic_5_11() {
    let _guard = export_metric_lock();
    let before = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 1, 11).expect("watermark");

    let file = db.export(&gvr).expect("export");
    assert_eq!(synthetic_count(), before + 1, "one synthetic attestation");
    let record = only_validator(&file, PUBKEY);
    // min(source) = 5, not S_wm = 1. That is the fixed point, not a miss.
    assert_eq!(attestation_triples(record), vec![(5, 11, None)]);
    assert!(record.signed_blocks.is_empty());
    assert_non_weakening(&db, &file, &[PUBKEY], &gvr, 16);
}

#[test]
fn export_fixture_rows_2_30_wm_7_20_is_exactly_synthetic_7_30() {
    let _guard = export_metric_lock();
    let before = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 2, 30, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 7, 20).expect("watermark");

    let file = db.export(&gvr).expect("export");
    assert_eq!(synthetic_count(), before + 1);
    let triples = attestation_triples(only_validator(&file, PUBKEY));
    let surrounded = vec![(2, 30, Some("0xrow".into())), (7, 20, None)];
    assert_ne!(triples, surrounded, "keeping (2, 30) beside (7, 20) is a surround pair");
    assert_eq!(triples, vec![(7, 30, None)]);
    assert_non_weakening(&db, &file, &[PUBKEY], &gvr, 36);
}

#[test]
fn a_watermark_only_validator_exports_a_floor_not_an_empty_record() {
    let _guard = export_metric_lock();
    let before = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 1, 11).expect("watermark");
    db.prune_below_watermarks().expect("prune");

    assert!(db.get_attestations(PUBKEY).expect("rows").is_empty(), "prune deletes the row");
    assert_eq!(
        db.get_attestation_watermark(PUBKEY).expect("wm"),
        Some((5, 11)),
        "prune raises S_wm to the deleted row's source"
    );
    let file = db.export(&gvr).expect("export");
    assert_eq!(synthetic_count(), before + 1);
    let record = only_validator(&file, PUBKEY);
    assert_eq!(attestation_triples(record), vec![(5, 11, None)]);
    assert!(record.signed_blocks.is_empty());
}

#[test]
fn a_pruned_key_delete_exports_a_floor_not_an_empty_record() {
    // The keymanager DELETE path keeps whatever `SlashingDb::export` emitted
    // for the pubkey and only invents an empty record for a pubkey the export
    // omitted. After prune the pubkey must already be present, with a floor.
    let _guard = export_metric_lock();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 1, 11).expect("watermark");
    db.prune_below_watermarks().expect("prune");

    let file = db.export(&gvr).expect("export");
    let record = only_validator(&file, PUBKEY);
    assert_eq!(attestation_triples(record), vec![(5, 11, None)]);
    assert!(
        !record.signed_attestations.is_empty(),
        "DELETE must not be handed an empty attestation list"
    );
}

#[test]
fn a_destination_refuses_2_12_after_importing_the_synthetic() {
    let _guard = export_metric_lock();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 1, 11).expect("watermark");
    let file = db.export(&gvr).expect("export");
    assert_eq!(attestation_triples(only_validator(&file, PUBKEY)), vec![(5, 11, None)]);

    let destination = SlashingDb::open_in_memory().expect("destination");
    destination.import(&file, &gvr).expect("import synthetic");
    let err = destination
        .stage_attestation(PUBKEY, 2, 12, Some("0xfresh-2-12".into()), &gvr)
        .expect_err("destination must refuse (2, 12)");
    match err {
        SlashingError::BelowAttestationSourceWatermark {
            source_epoch, watermark_source, ..
        } => {
            assert_eq!(source_epoch, 2);
            assert_eq!(watermark_source, 5);
        }
        other => panic!("expected source-watermark refusal, got {other:?}"),
    }
}

#[test]
fn export_fails_closed_when_the_floor_cannot_be_represented() {
    let _guard = export_metric_lock();
    let before = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xrow".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 20, 11).expect("unrepresentable watermark");
    db.seed_attestation(OTHER_PUBKEY, 1, 2, Some("0xok".into()), &gvr).expect("other seed");
    db.set_attestation_watermark(OTHER_PUBKEY, 1, 3).expect("other watermark");

    let err = db.export(&gvr).expect_err("whole export fails");
    assert_eq!(synthetic_count(), before, "no synthetic is counted when no file is produced");
    match err {
        SlashingError::UnrepresentableFloor { pubkey, source_bound, target_bound } => {
            assert_eq!(pubkey, PUBKEY);
            assert_eq!(source_bound, 20);
            assert_eq!(target_bound, 11);
            assert!(source_bound > target_bound);
        }
        other => panic!("expected UnrepresentableFloor, got {other:?}"),
    }
    assert_eq!(db.get_attestations(PUBKEY).expect("rows").len(), 1);
    assert_eq!(db.get_attestations(OTHER_PUBKEY).expect("rows").len(), 1);
    assert_eq!(db.get_attestation_watermark(PUBKEY).expect("wm"), Some((20, 11)));
    assert_eq!(db.get_attestation_watermark(OTHER_PUBKEY).expect("wm"), Some((1, 3)));
}

#[test]
fn exports_get_smaller() {
    let _guard = export_metric_lock();
    let before_metric = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 1, 2, Some("0xa".into()), &gvr).expect("seed");
    db.seed_attestation(PUBKEY, 3, 4, Some("0xb".into()), &gvr).expect("seed");
    db.seed_attestation(PUBKEY, 5, 6, Some("0xc".into()), &gvr).expect("seed");
    let before_rows = db.get_attestations(PUBKEY).expect("rows").len();
    assert_eq!(before_rows, 3);
    db.set_attestation_watermark(PUBKEY, 1, 10).expect("watermark");
    db.prune_below_watermarks().expect("prune");

    let file = db.export(&gvr).expect("export");
    let triples = attestation_triples(only_validator(&file, PUBKEY));
    assert!(triples.len() < before_rows, "pruned export must be smaller than the pre-prune rows");
    assert_eq!(triples, vec![(5, 10, None)]);
    assert_eq!(synthetic_count(), before_metric + 1);
}

#[test]
fn export_import_export_is_non_weakening_and_bounded_by_the_surviving_maxima() {
    let _guard = export_metric_lock();
    let before = synthetic_count();
    let gvr = chain_gvr();
    let db = SlashingDb::open_in_memory().expect("open");
    db.seed_attestation(PUBKEY, 5, 10, Some("0xlow".into()), &gvr).expect("seed");
    db.seed_attestation(PUBKEY, 8, 20, Some("0xhigh".into()), &gvr).expect("seed");
    db.set_attestation_watermark(PUBKEY, 1, 11).expect("att watermark");
    db.seed_block(PUBKEY, 3, Some("0xoldblk".into()), &gvr).expect("block");
    db.seed_block(PUBKEY, 9, Some("0xnewblk".into()), &gvr).expect("block");
    db.set_block_watermark(PUBKEY, 4).expect("block watermark");

    let first = db.export(&gvr).expect("first export");
    let record = only_validator(&first, PUBKEY);
    assert_eq!(attestation_triples(record), vec![(5, 11, None), (8, 20, Some("0xhigh".into()))]);
    assert_eq!(record.signed_blocks.len(), 2);
    assert_eq!(record.signed_blocks[0].slot, "4");
    assert!(record.signed_blocks[0].signing_root.is_none());
    assert_eq!(record.signed_blocks[1].slot, "9");
    assert_eq!(record.signed_blocks[1].signing_root.as_deref(), Some("0xnewblk"));

    let destination = SlashingDb::open_in_memory().expect("destination");
    destination.import(&first, &gvr).expect("import");
    let second = destination.export(&gvr).expect("second export");
    // Each export writes one attestation floor and one block floor.
    assert_eq!(synthetic_count(), before + 4, "one increment per synthesised record");

    model_refuses_grid(&first, &second, PUBKEY, 24);
    floors_bounded_by_surviving_maxima(&first, &second, PUBKEY);

    // Not equivalence. Import ratchets to the file maxima, so the second file
    // refuses candidates the first still allows.
    let attestation = Candidate::Attestation {
        source_epoch: 6,
        target_epoch: 12,
        signing_root: Some("0xfresh-witness".into()),
    };
    assert!(!refuses(&first, PUBKEY, &attestation), "first file allows (6, 12)");
    assert!(refuses(&second, PUBKEY, &attestation), "second file refuses (6, 12)");
    let block = Candidate::Block { slot: 5, signing_root: Some("0xfresh-slot".into()) };
    assert!(!refuses(&first, PUBKEY, &block), "first file allows slot 5");
    assert!(refuses(&second, PUBKEY, &block), "second file refuses slot 5");
}

/// RR2-12: both import histograms exist at init, with the stated buckets, and
/// a scrape before any import sees zero samples.
#[test]
fn import_histograms_are_registered_at_init_with_stated_buckets() {
    rvc_slashing::metrics::init();
    let gathered = metrics::REGISTRY.gather();
    for name in ["rvc_slashing_import_duration_ms", "rvc_slashing_import_conn_hold_ms"] {
        let family = gathered.iter().find(|metric| metric.name() == name).unwrap_or_else(|| {
            panic!("{name} must be registered at init");
        });
        assert_eq!(family.get_metric().len(), 1, "{name} has no labels");
        let histogram = family.get_metric()[0].get_histogram();
        assert_eq!(histogram.get_sample_count(), 0, "{name} scrape sees zero before any import");
        let bounds: Vec<f64> = histogram
            .get_bucket()
            .iter()
            .map(|bucket| bucket.upper_bound())
            .filter(|bound| bound.is_finite())
            .collect();
        assert_eq!(bounds, IMPORT_MS_BUCKETS, "{name} buckets");
    }
}

/// RR2-12: one small valid import records exactly one hold sample and one
/// duration sample.
#[test]
fn import_records_one_conn_hold_sample() {
    let _guard = IMPORT_TIMING_METRIC.lock().expect("import timing metric");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    let hold_before = hold_samples();
    let duration_before = duration_samples();

    db.import(&interchange(vec![att("1", "2", None)], vec![]), &gvr).expect("small import");

    assert_eq!(hold_samples(), hold_before + 1, "one import records one conn-hold sample");
    assert_eq!(duration_samples(), duration_before + 1, "one import records one duration sample");
}

/// RR2-12: `conn_hold_ms` is `conn.lock()` → `COMMIT` only.
///
/// A format-version rejection and a genesis-validators-root rejection happen
/// before the lock, so they record a duration sample and no hold sample.
/// A successful import whose pre-lock work is paused records a hold sample
/// much smaller than the whole call: the pause stands in for a payload that
/// parses slowly and then commits quickly. Numeric field parsing runs before
/// the lock (RR2-13).
#[test]
fn import_conn_hold_covers_lock_to_commit_not_pre_lock_parse() {
    let _guard = IMPORT_TIMING_METRIC.lock().expect("import timing metric");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();

    let hold_before = hold_samples();
    let duration_before = duration_samples();
    let bad_version = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "4".to_string(),
            genesis_validators_root: CHAIN_GVR_HEX.to_string(),
        },
        data: vec![],
    };
    let err = db.import(&bad_version, &gvr).expect_err("unsupported version");
    assert!(matches!(err, SlashingError::InvalidInterchangeFormat(_)));
    assert_eq!(hold_samples(), hold_before, "format-version check must not take conn");
    assert_eq!(duration_samples(), duration_before + 1, "the whole call is still timed");

    let hold_before = hold_samples();
    let duration_before = duration_samples();
    let bad_gvr = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: "0xnot-a-root".to_string(),
        },
        data: vec![],
    };
    let err = db.import(&bad_gvr, &gvr).expect_err("gvr mismatch");
    assert!(matches!(err, SlashingError::GenesisValidatorsRootMismatch { .. }));
    assert_eq!(hold_samples(), hold_before, "GVR check must not take conn");
    assert_eq!(duration_samples(), duration_before + 1);

    let pause = Duration::from_millis(80);
    SlashingDb::set_import_pre_lock_pause_for_test(Some(pause));
    struct ClearPause;
    impl Drop for ClearPause {
        fn drop(&mut self) {
            SlashingDb::set_import_pre_lock_pause_for_test(None);
        }
    }
    let _clear = ClearPause;

    let hold_before = hold_samples();
    let duration_before = duration_samples();
    let hold_sum_before = hold_sum_ms();
    let duration_sum_before = duration_sum_ms();
    db.import(&interchange(vec![att("3", "4", None)], vec![]), &gvr)
        .expect("slow parse, quick commit");
    assert_eq!(hold_samples(), hold_before + 1);
    assert_eq!(duration_samples(), duration_before + 1);
    let hold_ms = hold_sum_ms() - hold_sum_before;
    let duration_ms = duration_sum_ms() - duration_sum_before;
    let pause_ms = pause.as_secs_f64() * 1000.0;
    assert!(
        duration_ms + 5.0 >= pause_ms,
        "duration {duration_ms} ms must include the {pause_ms} ms pre-lock pause"
    );
    assert!(
        hold_ms < duration_ms - pause_ms / 2.0,
        "conn_hold {hold_ms} ms is lock→COMMIT; duration {duration_ms} ms includes the pre-lock pause"
    );
}

/// RR2-13: the #525 fixture (a valid row, then a malformed epoch) no longer
/// takes `conn`. `parse_interchange` rejects the file first, so there is no
/// hold sample and the valid prefix does not land (SC-02).
#[test]
fn malformed_epoch_after_a_valid_row_does_not_take_conn() {
    let _guard = IMPORT_TIMING_METRIC.lock().expect("import timing metric");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();
    let hold_before = hold_samples();
    let duration_before = duration_samples();

    let file = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: CHAIN_GVR_HEX.to_string(),
        },
        data: vec![
            ValidatorRecord {
                pubkey: PUBKEY.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![att("1", "2", None)],
            },
            ValidatorRecord {
                pubkey: OTHER_PUBKEY.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![att("not_a_number", "3", None)],
            },
        ],
    };
    let err = db.import(&file, &gvr).expect_err("malformed epoch is rejected before the lock");
    assert!(matches!(err, SlashingError::InvalidInterchangeFormat(_)));
    assert_eq!(hold_samples(), hold_before, "a malformed numeric field must not take conn");
    assert_eq!(duration_samples(), duration_before + 1, "the whole call is still timed");
    assert!(
        db.get_attestations(PUBKEY).expect("rows").is_empty(),
        "a malformed numeric field must not keep the valid prefix"
    );
    assert!(db.get_attestations(OTHER_PUBKEY).expect("rows").is_empty());
}

/// RR2-13: a malformed numeric field returns `Err` without taking `conn`.
///
/// Invalid JSON, a bad format version, and a genesis-validators-root mismatch
/// are already rejected outside the mutex. This targets numeric fields only
/// (`source_epoch`, `target_epoch`, `slot`). A valid prefix in the same file
/// must not land.
#[test]
fn malformed_numeric_field_errors_without_taking_the_conn_mutex() {
    let _guard = IMPORT_TIMING_METRIC.lock().expect("import timing metric");
    let db = SlashingDb::open_in_memory().expect("open");
    let gvr = chain_gvr();

    let cases = [
        ("source_epoch", interchange(vec![att("not_a_number", "2", None)], vec![])),
        ("target_epoch", interchange(vec![att("1", "not_a_number", None)], vec![])),
        (
            "slot",
            interchange(
                vec![],
                vec![InterchangeBlock { slot: "not_a_number".to_string(), signing_root: None }],
            ),
        ),
    ];

    for (field, file) in cases {
        let hold_before = hold_samples();
        let duration_before = duration_samples();
        let err = db.import(&file, &gvr).unwrap_err();
        assert!(
            matches!(err, SlashingError::InvalidInterchangeFormat(ref msg) if msg.contains(field)),
            "{field} must be InvalidInterchangeFormat naming the field, got {err:?}"
        );
        assert_eq!(
            hold_samples(),
            hold_before,
            "{field} must not take the conn mutex (conn_hold_ms sample count unchanged)"
        );
        assert_eq!(duration_samples(), duration_before + 1, "{field} still times the whole call");
        assert!(db.get_attestations(PUBKEY).expect("rows").is_empty());
        assert!(db.get_blocks(PUBKEY).expect("blocks").is_empty());
    }

    let hold_before = hold_samples();
    let prefixed = InterchangeFormat {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: CHAIN_GVR_HEX.to_string(),
        },
        data: vec![
            ValidatorRecord {
                pubkey: PUBKEY.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![att("1", "2", None)],
            },
            ValidatorRecord {
                pubkey: OTHER_PUBKEY.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![att("3", "not_a_number", None)],
            },
        ],
    };
    let err = db.import(&prefixed, &gvr).expect_err("malformed target_epoch");
    assert!(matches!(err, SlashingError::InvalidInterchangeFormat(_)));
    assert_eq!(hold_samples(), hold_before, "prefixed malformed numeric field must not take conn");
    assert!(
        db.get_attestations(PUBKEY).expect("rows").is_empty(),
        "a malformed numeric field must not keep the valid prefix"
    );
    assert!(db.get_attestations(OTHER_PUBKEY).expect("rows").is_empty());
}
