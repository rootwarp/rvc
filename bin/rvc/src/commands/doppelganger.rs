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
        let record = rvc::detection_marker::record_path(dir.path());
        #[cfg(unix)]
        let detected_id = entry_id(&record);
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
        #[cfg(unix)]
        assert_eq!(
            entry_id(&record),
            detected_id,
            "The command must keep the device number and the inode number of a detected record."
        );
        assert_eq!(
            std::fs::metadata(&record).map(|meta| meta.len()).map_err(|err| err.to_string()),
            Ok(rvc::detection_marker::RECORD_LEN as u64),
            "The reset record must have RECORD_LEN bytes."
        );
        assert_eq!(
            temp_file_names(dir.path()),
            Vec::<String>::new(),
            "The command must not leave a temp file after the reset of a detected record."
        );
    }

    /// Return the device number and the inode number of the entry at
    /// `path`. The function does not follow a symlink.
    #[cfg(unix)]
    fn entry_id(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let meta =
            std::fs::symlink_metadata(path).expect("The test must read the metadata of the entry.");
        (meta.dev(), meta.ino())
    }

    /// Return the names of the temp files in `dir`.
    fn temp_file_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("The test must read the directory.")
            .map(|entry| {
                entry
                    .expect("The test must read a directory entry.")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    /// Write a detection marker with no keys in `dir`.
    fn write_marker_without_keys(dir: &Path) {
        rvc::detection_marker::write_marker(
            dir,
            &rvc::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] },
        )
        .expect("The test must write the detection marker.");
    }

    /// The command replaces a record that does not parse when the record is
    /// a regular file. Then it removes the marker.
    #[test]
    fn clear_detection_replaces_an_unreadable_regular_record() {
        use rvc::detection_marker::{
            force_window_path, inspect, inspect_record, record_path, MarkerInspect, RecordInspect,
            RECORD_LEN,
        };
        let rows: [(&str, Vec<u8>); 2] = [
            ("4096 zero bytes", vec![0; RECORD_LEN]),
            ("a 5-byte regular file", b"short".to_vec()),
        ];
        for (case, bytes) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            write_marker_without_keys(dir.path());
            let record = record_path(dir.path());
            std::fs::write(&record, &bytes).expect("The test must write the record file.");

            let result =
                execute_clear_detection(dir.path(), None, true).map_err(|err| err.to_string());

            assert_eq!(
                result,
                Ok(()),
                "The command must replace the record. The input case is {case}."
            );
            assert_eq!(
                inspect_record(dir.path()),
                RecordInspect::Clear,
                "The record must be clear after the command. The input case is {case}."
            );
            let meta = std::fs::symlink_metadata(&record)
                .expect("The test must read the metadata of the record.");
            assert!(
                meta.is_file(),
                "The new record must be a regular file. The input case is {case}."
            );
            assert_eq!(
                meta.len(),
                RECORD_LEN as u64,
                "The new record must have RECORD_LEN bytes. The input case is {case}."
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "The new record must have mode 0600. The input case is {case}."
                );
            }
            assert!(
                matches!(inspect(dir.path()), MarkerInspect::Absent),
                "The command must remove the marker. The input case is {case}."
            );
            assert!(
                force_window_path(dir.path()).is_file(),
                "The force-window file must exist. The input case is {case}."
            );
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The command must not leave a temp file. The input case is {case}."
            );
        }
    }

    /// The command must not change a record that does not parse before it
    /// holds the keystore lock and has written the force-window file.
    #[test]
    fn clear_changes_no_record_before_the_lock_and_the_force_window_file() {
        use rvc::detection_marker::{force_window_path, inspect, record_path, MarkerInspect};
        for case in ["the keystore lock is held", "the force-window file cannot be written"] {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            write_marker_without_keys(dir.path());
            let record = record_path(dir.path());
            std::fs::write(&record, b"short").expect("The test must write the record file.");
            let _held = if case == "the keystore lock is held" {
                Some(
                    rvc::startup::acquire_keystore_lock(dir.path())
                        .expect("The test must hold the keystore lock."),
                )
            } else {
                std::fs::create_dir(force_window_path(dir.path()))
                    .expect("The test must create a directory at the force-window path.");
                None
            };

            let result = execute_clear_detection(dir.path(), None, true);

            assert!(result.is_err(), "The command must fail when {case}.");
            assert_eq!(
                std::fs::read(&record).map_err(|err| err.to_string()),
                Ok(b"short".to_vec()),
                "The record must not change when {case}."
            );
            assert!(
                matches!(inspect(dir.path()), MarkerInspect::Present(_)),
                "The marker must stay when {case}."
            );
        }
    }

    /// The command handles a symlink, a directory or a FIFO at the record
    /// path. Each row requires these results:
    ///
    /// - The marker stays.
    /// - The entry keeps its type and its inode.
    /// - The symlink keeps its target, and the target keeps its bytes.
    /// - The directory stays empty.
    /// - No temp file stays.
    /// - The error names the record path and says that it is not a regular
    ///   file.
    #[cfg(unix)]
    #[test]
    fn clear_leaves_the_marker_when_the_record_is_not_a_regular_file() {
        use std::os::unix::fs::FileTypeExt;

        use rvc::detection_marker::{inspect, record_path, MarkerInspect};
        for case in ["a symlink", "a directory", "a FIFO"] {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            write_marker_without_keys(dir.path());
            let record = record_path(dir.path());
            let target = dir.path().join("symlink-target");
            if case == "a symlink" {
                std::fs::write(&target, b"short").expect("The test must write the link target.");
                std::os::unix::fs::symlink(&target, &record)
                    .expect("The test must create a symlink at the record path.");
            } else if case == "a directory" {
                std::fs::create_dir(&record)
                    .expect("The test must create a directory at the record path.");
            } else {
                let status = std::process::Command::new("mkfifo")
                    .arg(&record)
                    .status()
                    .expect("The test must start mkfifo.");
                assert!(
                    status.success(),
                    "The mkfifo command must succeed. The status is {status}."
                );
            }
            let before = entry_id(&record);

            let result =
                execute_clear_detection(dir.path(), None, true).map_err(|err| err.to_string());

            assert!(
                matches!(inspect(dir.path()), MarkerInspect::Present(_)),
                "The marker must stay when the record path is {case}."
            );
            assert_eq!(
                entry_id(&record),
                before,
                "The entry must keep its inode. The input case is {case}."
            );
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The command must not leave a temp file. The input case is {case}."
            );
            let file_type = std::fs::symlink_metadata(&record)
                .map(|meta| meta.file_type())
                .map_err(|err| err.to_string());
            if case == "a FIFO" {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_fifo()),
                    "The FIFO must stay a FIFO. The file type is {file_type:?}."
                );
            } else if case == "a symlink" {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_symlink()),
                    "The symlink must stay a symlink. The file type is {file_type:?}."
                );
                assert_eq!(
                    std::fs::read_link(&record).map_err(|err| err.to_string()),
                    Ok(target.clone()),
                    "The symlink must point to the same target."
                );
                assert_eq!(
                    std::fs::read(&target).map_err(|err| err.to_string()),
                    Ok(b"short".to_vec()),
                    "The command must not write through the symlink."
                );
            } else {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_dir()),
                    "The directory must stay a directory. The file type is {file_type:?}."
                );
                assert_eq!(
                    std::fs::read_dir(&record)
                        .map(|entries| entries.count())
                        .map_err(|err| err.to_string()),
                    Ok(0),
                    "The directory must stay empty."
                );
            }
            let err = result.err().unwrap_or_default();
            assert!(
                err.contains("is not a regular file"),
                "The error must say that the record path is not a regular file. The input case \
                 is {case}. The error is: {err:?}"
            );
            assert!(
                err.contains(&record.display().to_string()),
                "The command must fail with an error that names the record path {} when the \
                 record path is {case}. The error is: {err:?}",
                record.display()
            );
        }
    }
}
