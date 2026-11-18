//! Size-based rolling file writer for the file log layer.
//!
//! RED stub: the writer does not exist yet. The tests below define it.
#![allow(dead_code, unused_imports, unused_variables)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use crate::file_appender::FileAppenderConfig;

#[derive(Debug, Clone)]
struct Layout {
    dir: PathBuf,
    name: String,
    max_files: usize,
    compress: bool,
}

impl Layout {
    fn index_of(&self, file_name: &str) -> Option<usize> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct RollingWriter {
    cleanup: Option<JoinHandle<()>>,
}

impl RollingWriter {
    pub(crate) fn open(config: &FileAppenderConfig) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

impl Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;
    use std::sync::Mutex;

    /// While a test holds this lock, the background cleanup cannot start.
    pub(crate) static CLEANUP_GATE: Mutex<()> = Mutex::new(());

    const MIB: usize = 1024 * 1024;

    impl RollingWriter {
        fn join_cleanup(&mut self) {
            if let Some(cleanup) = self.cleanup.take() {
                cleanup.join().expect("The cleanup thread must not panic.");
            }
        }
    }

    fn config(dir: &Path, max_files: usize, compress: bool) -> FileAppenderConfig {
        FileAppenderConfig {
            directory: dir.to_string_lossy().into_owned(),
            filename: "app.log".to_string(),
            max_size_mb: 1,
            max_files,
            compress,
            level: "info".to_string(),
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn first_byte(path: &Path) -> u8 {
        let mut byte = [0u8; 1];
        File::open(path).unwrap().read_exact(&mut byte).unwrap();
        byte[0]
    }

    /// Writes one full MiB of `fill` and waits for the cleanup thread.
    fn roll(writer: &mut RollingWriter, fill: u8) {
        writer.write_all(&vec![fill; MIB]).unwrap();
        writer.join_cleanup();
    }

    #[test]
    fn rotates_when_the_active_file_reaches_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 5, false)).unwrap();

        writer.write_all(&vec![b'a'; MIB - 1]).unwrap();
        assert_eq!(names(dir.path()), ["app.log"], "1 byte below the limit must not rotate.");

        writer.write_all(b"a").unwrap();
        writer.join_cleanup();
        assert_eq!(names(dir.path()), ["app.log", "app.log.1"]);
        assert_eq!(fs::metadata(dir.path().join("app.log.1")).unwrap().len(), MIB as u64);
        assert_eq!(fs::metadata(dir.path().join("app.log")).unwrap().len(), 0);

        writer.write_all(&vec![b'b'; MIB - 5]).unwrap();
        writer.write_all(&[b'b'; 10]).unwrap();
        writer.join_cleanup();
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1", "app.log.2"],
            "A write that crosses the limit must rotate."
        );
        assert_eq!(fs::metadata(dir.path().join("app.log.1")).unwrap().len(), MIB as u64 + 5);
    }

    #[test]
    fn rotated_files_move_up_one_index_and_retention_keeps_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 3, false)).unwrap();

        roll(&mut writer, b'a');
        roll(&mut writer, b'b');
        assert_eq!(names(dir.path()), ["app.log", "app.log.1", "app.log.2"]);
        assert_eq!(first_byte(&dir.path().join("app.log.1")), b'b');
        assert_eq!(first_byte(&dir.path().join("app.log.2")), b'a');

        roll(&mut writer, b'c');
        roll(&mut writer, b'd');
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1", "app.log.2"],
            "max_files = 3 must keep the active file and two rotated files."
        );
        assert_eq!(first_byte(&dir.path().join("app.log.1")), b'd');
        assert_eq!(first_byte(&dir.path().join("app.log.2")), b'c');
    }

    #[test]
    fn compression_runs_on_a_background_thread_and_blocks_the_next_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 5, true)).unwrap();
        let gate = CLEANUP_GATE.lock().unwrap();

        writer.write_all(&vec![b'a'; MIB]).unwrap();
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1"],
            "The write must return before the compression starts."
        );

        writer.write_all(&vec![b'b'; MIB]).unwrap();
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1"],
            "The writer must not rotate while the cleanup thread runs."
        );

        drop(gate);
        writer.join_cleanup();
        assert_eq!(names(dir.path()), ["app.log", "app.log.1.gz"]);
        let mut text = Vec::new();
        GzDecoder::new(File::open(dir.path().join("app.log.1.gz")).unwrap())
            .read_to_end(&mut text)
            .unwrap();
        assert_eq!(text, vec![b'a'; MIB], "The archive must hold the rotated bytes.");

        writer.write_all(b"b").unwrap();
        writer.join_cleanup();
        assert_eq!(names(dir.path()), ["app.log", "app.log.1.gz", "app.log.2.gz"]);
    }

    #[test]
    fn open_appends_to_the_existing_files_and_removes_files_above_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        fs::write(path("app.log"), vec![b'a'; MIB - 1]).unwrap();
        fs::write(path("app.log.1"), "b").unwrap();
        fs::write(path("app.log.2.gz"), "c").unwrap();
        fs::write(path("app.log.7"), "d").unwrap();
        fs::write(path("other.log.1"), "e").unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 4, false)).unwrap();

        writer.write_all(b"a").unwrap();
        writer.join_cleanup();
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1", "app.log.2", "app.log.3.gz", "other.log.1"],
            "Index 7 is at or above max_files = 4, thus the cleanup must remove it."
        );
        assert_eq!(fs::read(path("app.log.1")).unwrap(), vec![b'a'; MIB]);
        assert_eq!(fs::read(path("app.log.2")).unwrap(), b"b");
        assert_eq!(fs::read(path("app.log.3.gz")).unwrap(), b"c");
    }

    #[test]
    fn a_failed_rename_stops_the_rotation_and_keeps_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.log.1"), "old").unwrap();
        fs::create_dir(dir.path().join("app.log.2")).unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 2, false)).unwrap();

        let error =
            writer.write_all(&vec![b'a'; MIB]).expect_err("A rename onto a directory fails.");
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(dir.path().join("app.log.1")).unwrap(), b"old");
    }

    #[test]
    fn index_of_reads_only_rotated_names() {
        let layout = Layout {
            dir: PathBuf::new(),
            name: "app.log".to_string(),
            max_files: 5,
            compress: false,
        };
        assert_eq!(layout.index_of("app.log.3"), Some(3));
        assert_eq!(layout.index_of("app.log.12.gz"), Some(12));
        for other in ["app.log", "app.log.gz", "app.logx.1", "app.log.1.tmp", "a.app.log.1"] {
            assert_eq!(layout.index_of(other), None, "{other} is not a rotated file name.");
        }
    }
}
