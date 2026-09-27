//! Import-conflict observability and watermark floors (RR-4.2 / RR-P2-1 / RR-P2-3).

use std::sync::Mutex;

use rvc_slashing::metrics::RVC_SLASHING_IMPORT_CONFLICTS_TOTAL;
use rvc_slashing::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata, SlashingDb,
    SlashingError, ValidatorRecord,
};

/// The conflict counter is process-global. Hold this across a delta assertion
/// so a parallel import cannot land between the snapshots.
static CONFLICT_METRIC: Mutex<()> = Mutex::new(());

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
