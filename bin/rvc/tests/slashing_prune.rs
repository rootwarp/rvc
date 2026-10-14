//! CLI integration tests for `rvc slashing prune` (RF2-13 / B5).

use std::process::Command;

use eth_types::Root;
use slashing::{SlashingDb, SlashingError};
use tempfile::TempDir;

const TEST_GVR: Root = [0u8; 32];

fn rvc_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rvc"))
}

fn seed_prunable_db(path: &std::path::Path) {
    let db = SlashingDb::open(path).expect("open seed db");
    for slot in [100u64, 200, 300, 400, 500] {
        db.seed_block("0x1234", slot, None, &TEST_GVR).expect("seed block");
    }
    for (src, tgt) in [(5u64, 10), (10, 20), (20, 30), (30, 40), (40, 50)] {
        db.seed_attestation("0x1234", src, tgt, None, &TEST_GVR).expect("seed att");
    }
    db.set_block_watermark("0x1234", 300).expect("wm block");
    db.set_attestation_watermark("0x1234", 20, 30).expect("wm att");
}

#[test]
fn prune_missing_path_exits_nonzero_and_creates_no_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("does-not-exist.db");
    assert!(!path.exists());

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap(), "--yes"])
        .output()
        .expect("run rvc");

    assert!(!output.status.success(), "missing path must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("refuse") || combined.contains("not found") || combined.contains("fresh"),
        "expected refuse-fresh message, got: {combined}"
    );
    assert!(!path.exists(), "must not leave a fresh DB behind");
    assert!(!dir.path().join("does-not-exist.db-wal").exists());
    assert!(!dir.path().join("does-not-exist.db-shm").exists());
}

#[test]
fn prune_dry_run_reports_counts_and_deletes_nothing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    seed_prunable_db(&path);

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("run rvc");

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would delete"), "stdout={stdout}");
    assert!(stdout.contains("2 block"), "stdout={stdout}");
    assert!(stdout.contains("2 attestation"), "stdout={stdout}");

    let db = SlashingDb::open(&path).unwrap();
    assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
    assert_eq!(db.get_attestations("0x1234").unwrap().len(), 5);
}

#[test]
fn prune_yes_deletes_expected_rows() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    seed_prunable_db(&path);

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap(), "--yes"])
        .output()
        .expect("run rvc");

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("deleted"), "stdout={stdout}");
    assert!(stdout.contains("2 block"), "stdout={stdout}");
    assert!(stdout.contains("2 attestation"), "stdout={stdout}");

    let db = SlashingDb::open(&path).unwrap();
    assert_eq!(db.get_blocks("0x1234").unwrap().len(), 3);
    assert_eq!(db.get_attestations("0x1234").unwrap().len(), 3);
}

#[test]
fn prune_without_yes_or_dry_run_refuses() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    seed_prunable_db(&path);

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap()])
        .output()
        .expect("run rvc");

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--yes")
            || combined.contains("confirmation")
            || combined.contains("dry-run"),
        "expected confirmation prompt, got: {combined}"
    );

    let db = SlashingDb::open(&path).unwrap();
    assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
}

#[test]
fn prune_no_watermarks_is_actionable() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    {
        let db = SlashingDb::open(&path).unwrap();
        db.seed_block("0x1234", 100, None, &TEST_GVR).unwrap();
    }

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("run rvc");

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("no watermarks") || combined.contains("import"),
        "expected NoWatermarksSet operator message, got: {combined}"
    );
}

#[test]
fn prune_then_surround_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    {
        let db = SlashingDb::open(&path).unwrap();
        db.seed_attestation("0x1234", 5, 10, None, &TEST_GVR).unwrap();
        db.set_attestation_watermark("0x1234", 1, 11).unwrap();
    }

    let output = Command::new(rvc_bin())
        .args(["slashing", "prune", "--slashing-db-path", path.to_str().unwrap(), "--yes"])
        .output()
        .expect("run rvc");

    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let db = SlashingDb::open(&path).unwrap();
    assert!(db.get_attestations("0x1234").unwrap().is_empty(), "pruned row must be gone");
    let err = db
        .check_and_record_attestation("0x1234", 2, 12, None, &TEST_GVR)
        .expect_err("surround of a pruned row must be refused");
    assert!(
        matches!(err, SlashingError::BelowAttestationSourceWatermark { source_epoch: 2, .. }),
        "expected source-watermark refusal of (2, 12), got {err:?}"
    );
    assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((5, 11)));
}

#[test]
fn slashing_prune_help_lists_flags() {
    let output =
        Command::new(rvc_bin()).args(["slashing", "prune", "--help"]).output().expect("run rvc");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--slashing-db-path"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--yes"));
}
