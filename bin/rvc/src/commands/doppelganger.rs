//! Operator commands for doppelganger detection.

use std::path::Path;

use anyhow::bail;
use rvc::detection_marker::{self, ClearOutcome};
use rvc::startup;

/// Remove `.rvc.doppelganger_detected` from the validator data directory.
///
/// `--confirm` is required. The command takes `.rvc.lock` and refuses while
/// another process holds it. A process started with `--disable-keystore-locking`
/// holds no lock, so this command cannot see it. It then writes
/// `.rvc.doppelganger_force_window` so the next start runs a full forward
/// window for every key loaded on that boot. It then resets
/// `.rvc.doppelganger_record` in place to `not-detected`. When
/// `slashing_db_path` is set and its directory is not `datadir`, the fallback
/// marker in that directory is removed too. The keystore marker is unlinked
/// last. Deleting only that marker by hand does not write the force-window
/// file, does not clear a detected record, and does not force the window.
pub fn execute_clear_detection(
    datadir: &Path,
    slashing_db_path: Option<&Path>,
    confirm: bool,
) -> anyhow::Result<()> {
    if !confirm {
        bail!(
            "refusing to clear the doppelganger detection marker without --confirm. \
             Deleting {} removes the refuse-to-start marker and does not force a fresh window",
            detection_marker::marker_path(datadir).display()
        );
    }
    let _lock = startup::acquire_keystore_lock(datadir).map_err(|err| {
        anyhow::anyhow!(
            "refusing to clear the doppelganger detection marker while the keystore lock is held: {err}"
        )
    })?;
    // The force-window file lands first. A crash before the unlink leaves the
    // detection marker in place, so the next start still exits 12.
    detection_marker::write_force_window(datadir)?;
    detection_marker::reset_detection_record(datadir).map_err(|err| {
        anyhow::anyhow!(
            "refusing to remove the detection marker because the in-place record could not be reset: {err}"
        )
    })?;
    if let Some(db_path) = slashing_db_path {
        if let Some(dir) = detection_marker::fallback_marker_dir(datadir, db_path) {
            detection_marker::clear_marker(&dir)?;
        }
    }
    match detection_marker::clear_marker(datadir)? {
        ClearOutcome::Removed => {
            println!(
                "removed doppelganger detection marker at {}. The next start runs a full forward window.",
                detection_marker::marker_path(datadir).display()
            );
        }
        ClearOutcome::Absent => {
            println!(
                "no doppelganger detection marker at {}. The next start runs a full forward window.",
                detection_marker::marker_path(datadir).display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_requires_confirm_and_then_removes_the_marker() {
        let dir = tempfile::tempdir().expect("temp");
        let err = execute_clear_detection(dir.path(), None, false).expect_err("confirm");
        assert!(err.to_string().contains("--confirm"));

        rvc::detection_marker::write_marker(
            dir.path(),
            &rvc::detection_marker::DetectionMarker {
                epoch: 1,
                unix_secs: 2,
                pubkeys: vec!["0x".to_string() + &"11".repeat(48)],
            },
        )
        .expect("write");
        execute_clear_detection(dir.path(), None, true).expect("clear");
        assert!(matches!(
            rvc::detection_marker::inspect(dir.path()),
            rvc::detection_marker::MarkerInspect::Absent
        ));
        assert!(rvc::detection_marker::force_window_path(dir.path()).is_file());
    }

    #[test]
    fn clear_refuses_while_the_keystore_lock_is_held() {
        let dir = tempfile::tempdir().expect("temp");
        rvc::detection_marker::write_marker(
            dir.path(),
            &rvc::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] },
        )
        .expect("write");
        let _held = rvc::startup::acquire_keystore_lock(dir.path()).expect("hold lock");
        let err = execute_clear_detection(dir.path(), None, true).expect_err("locked");
        assert!(err.to_string().contains("lock"), "{err}");
        assert!(matches!(
            rvc::detection_marker::inspect(dir.path()),
            rvc::detection_marker::MarkerInspect::Present(_)
        ));
        assert!(!rvc::detection_marker::force_window_path(dir.path()).exists());
    }

    #[test]
    fn clear_removes_a_fallback_marker_beside_the_slashing_db() {
        let keys = tempfile::tempdir().expect("keys");
        let slash = tempfile::tempdir().expect("slash");
        let marker =
            rvc::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] };
        rvc::detection_marker::write_marker(keys.path(), &marker).expect("keystore marker");
        rvc::detection_marker::write_marker(slash.path(), &marker).expect("fallback marker");
        let db = slash.path().join("slashing.sqlite");
        execute_clear_detection(keys.path(), Some(&db), true).expect("clear");
        assert!(matches!(
            rvc::detection_marker::inspect(keys.path()),
            rvc::detection_marker::MarkerInspect::Absent
        ));
        assert!(matches!(
            rvc::detection_marker::inspect(slash.path()),
            rvc::detection_marker::MarkerInspect::Absent
        ));
        assert!(rvc::detection_marker::force_window_path(keys.path()).is_file());
    }

    #[test]
    fn clear_resets_an_in_place_detection_record() {
        let dir = tempfile::tempdir().expect("temp");
        rvc::detection_marker::preallocate_detection_record(dir.path()).expect("record");
        rvc::detection_marker::commit_detection_record(dir.path(), 4, 5).expect("detected");
        execute_clear_detection(dir.path(), None, true).expect("clear");
        assert!(matches!(
            rvc::detection_marker::inspect_record(dir.path()),
            rvc::detection_marker::RecordInspect::Clear
        ));
        assert!(matches!(
            rvc::detection_marker::inspect(dir.path()),
            rvc::detection_marker::MarkerInspect::Absent
        ));
        assert!(rvc::detection_marker::force_window_path(dir.path()).is_file());
    }

    #[test]
    fn clear_leaves_the_marker_when_the_record_cannot_be_reset() {
        let dir = tempfile::tempdir().expect("temp");
        rvc::detection_marker::write_marker(
            dir.path(),
            &rvc::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] },
        )
        .expect("marker");
        std::fs::write(rvc::detection_marker::record_path(dir.path()), b"short").expect("short");
        let err = execute_clear_detection(dir.path(), None, true).expect_err("bad record");
        assert!(err.to_string().contains("in-place record"), "{err}");
        assert!(matches!(
            rvc::detection_marker::inspect(dir.path()),
            rvc::detection_marker::MarkerInspect::Present(_)
        ));
        assert_eq!(
            std::fs::read(rvc::detection_marker::record_path(dir.path())).expect("untouched"),
            b"short"
        );
    }
}
