//! Operator-facing slashing-protection maintenance commands (RF2-13 / B5).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use slashing::{PruneStats, SlashingDb, SlashingError};

/// Arguments for `rvc slashing prune`.
pub struct PruneArgs {
    pub slashing_db_path: PathBuf,
    pub dry_run: bool,
    /// Required for a real (non-dry-run) prune; pruning is irreversible.
    pub yes: bool,
}

/// Open an existing slashing DB for maintenance, refusing accidental fresh create.
///
/// Mirrors `reject_accidental_fresh_create` / `remove_accidental_fresh_db` in
/// `crates/rvc/src/config/builder.rs`: a prune (or any maintenance command) that
/// silently creates an empty DB on a typo'd path is a slashing footgun of the
/// same class as `--init-slashing-db` without opt-in.
fn open_existing_slashing_db(path: &Path) -> anyhow::Result<SlashingDb> {
    let (db, created_fresh) = SlashingDb::open_with_create_info(path).with_context(|| {
        format!("failed to open slashing protection database at {}", path.display())
    })?;

    if created_fresh {
        // Drop the connection so the accidental file can be unlinked (builder SEC-3).
        // Unlinking while SQLite still holds the handle can leave residual -wal/-shm on some platforms.
        drop(db);
        remove_accidental_fresh_db(path);
        bail!(
            "slashing protection database not found at {} — refuse to create a fresh empty DB \
             for prune (would have zero history). Restore from backup or pass an existing path.",
            path.display()
        );
    }

    Ok(db)
}

/// Best-effort cleanup of a DB file created without opt-in (and SQLite sidecars).
///
/// SQLite WAL filenames use `-wal` / `-shm` suffixes (no separator dot).
fn remove_accidental_fresh_db(path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let candidates = [
        path.to_path_buf(),
        parent.join(format!("{stem}-wal")),
        parent.join(format!("{stem}-shm")),
    ];
    for p in &candidates {
        if !p.exists() {
            continue;
        }
        if let Err(e) = std::fs::remove_file(p) {
            eprintln!(
                "warning: failed to remove accidental fresh slashing DB artifact at {}: {}; \
                 delete it manually before retrying",
                p.display(),
                e
            );
        }
    }
}

fn format_prune_stats(stats: &PruneStats, dry_run: bool) -> String {
    let verb = if dry_run { "would delete" } else { "deleted" };
    format!(
        "slashing prune {}: {} block row(s), {} attestation row(s)",
        verb, stats.blocks_deleted, stats.attestations_deleted
    )
}

fn map_prune_error(err: SlashingError) -> anyhow::Error {
    match err {
        // Surface the actionable operator message from the error Display.
        SlashingError::NoWatermarksSet => anyhow::Error::new(err),
        other => anyhow::Error::new(other).context("slashing DB prune failed"),
    }
}

/// Run `rvc slashing prune`.
pub fn execute_prune(args: PruneArgs) -> anyhow::Result<()> {
    if !args.dry_run && !args.yes {
        bail!(
            "refusing to prune without confirmation: re-run with --yes to delete rows below \
             watermarks, or --dry-run to report counts without deleting"
        );
    }

    let db = open_existing_slashing_db(&args.slashing_db_path)?;

    if args.dry_run {
        let stats = db.count_below_watermarks().map_err(map_prune_error)?;
        println!("{}", format_prune_stats(&stats, true));
        return Ok(());
    }

    let stats = db.prune_below_watermarks().map_err(map_prune_error)?;
    println!("{}", format_prune_stats(&stats, false));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::Root;
    use tempfile::TempDir;

    const TEST_GVR: Root = [0u8; 32];

    fn seeded_db_with_prunable_rows(path: &Path) {
        let db = SlashingDb::open(path).expect("open");
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
    fn open_existing_refuses_missing_path_and_leaves_no_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.db");
        assert!(!path.exists());

        let err = match open_existing_slashing_db(&path) {
            Ok(_) => panic!("expected error for missing path"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refuse to create") || msg.contains("not found"),
            "unexpected error: {msg}"
        );
        assert!(!path.exists(), "must not leave a fresh DB on a typo'd path");
        assert!(!path.with_extension("db-wal").exists());
        // SQLite sidecars use -wal / -shm (no extra dot)
        let wal = dir.path().join("missing.db-wal");
        let shm = dir.path().join("missing.db-shm");
        assert!(!wal.exists(), "must not leave -wal sidecar");
        assert!(!shm.exists(), "must not leave -shm sidecar");
    }

    #[test]
    fn dry_run_reports_counts_without_deleting() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing.db");
        seeded_db_with_prunable_rows(&path);

        let db = open_existing_slashing_db(&path).expect("open existing");
        let stats = db.count_below_watermarks().expect("count");
        assert_eq!(stats.blocks_deleted, 2);
        assert_eq!(stats.attestations_deleted, 2);

        // Rows still present
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 5);
    }

    #[test]
    fn execute_prune_requires_yes_without_dry_run() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing.db");
        seeded_db_with_prunable_rows(&path);

        let err =
            execute_prune(PruneArgs { slashing_db_path: path.clone(), dry_run: false, yes: false })
                .unwrap_err();
        assert!(err.to_string().contains("--yes") || err.to_string().contains("confirmation"));

        // Unchanged
        let db = SlashingDb::open(&path).unwrap();
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
    }

    #[test]
    fn execute_prune_yes_deletes_and_increments_metric() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing.db");
        seeded_db_with_prunable_rows(&path);

        let before_blocks = slashing::metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[slashing::metrics::prune_type::BLOCK])
            .get();
        let before_atts = slashing::metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[slashing::metrics::prune_type::ATTESTATION])
            .get();

        execute_prune(PruneArgs { slashing_db_path: path.clone(), dry_run: false, yes: true })
            .expect("prune");

        let db = SlashingDb::open(&path).unwrap();
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 3);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 3);

        let after_blocks = slashing::metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[slashing::metrics::prune_type::BLOCK])
            .get();
        let after_atts = slashing::metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[slashing::metrics::prune_type::ATTESTATION])
            .get();
        assert!(
            after_blocks >= before_blocks.saturating_add(2),
            "block prune metric should increase: before={before_blocks} after={after_blocks}"
        );
        assert!(
            after_atts >= before_atts.saturating_add(2),
            "attestation prune metric should increase: before={before_atts} after={after_atts}"
        );
    }

    #[test]
    fn execute_prune_no_watermarks_is_actionable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing.db");
        {
            let db = SlashingDb::open(&path).unwrap();
            db.seed_block("0x1234", 100, None, &TEST_GVR).unwrap();
        }

        let err = execute_prune(PruneArgs { slashing_db_path: path, dry_run: true, yes: false })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no watermarks") || msg.contains("import"),
            "expected actionable NoWatermarksSet message, got: {msg}"
        );
    }

    #[test]
    fn execute_prune_dry_run_end_to_end() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing.db");
        seeded_db_with_prunable_rows(&path);

        execute_prune(PruneArgs { slashing_db_path: path.clone(), dry_run: true, yes: false })
            .expect("dry-run");

        let db = open_existing_slashing_db(&path).unwrap();
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 5);
    }
}
