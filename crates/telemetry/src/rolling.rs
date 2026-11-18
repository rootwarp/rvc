//! Size-based rolling file writer for the file log layer.
//!
//! The writer keeps the file names and the retention rule of `logroller` 0.1:
//!
//! - The active file is `<name>`. A rotation renames it to `<name>.1` and
//!   moves each older `<name>.N` and `<name>.N.gz` to index `N + 1`.
//! - A rotation occurs after a write that makes the active file
//!   `max_size_mb` MiB or larger.
//! - After a rotation, a background thread compresses `<name>.1` to
//!   `<name>.1.gz` (when compression is on). Then it removes each rotated
//!   file with an index of `max_files` or more.
//! - While that thread runs, the writer does not rotate again.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::file_appender::FileAppenderConfig;

/// The names and the retention limit of one rolling log file.
#[derive(Debug, Clone)]
struct Layout {
    dir: PathBuf,
    name: String,
    max_files: usize,
    compress: bool,
}

impl Layout {
    fn active(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    fn rotated(&self, index: usize, gz: bool) -> PathBuf {
        let suffix = if gz { ".gz" } else { "" };
        self.dir.join(format!("{}.{index}{suffix}", self.name))
    }

    /// Returns `N` for `<name>.N` and `<name>.N.gz`.
    fn index_of(&self, file_name: &str) -> Option<usize> {
        let rest = file_name.strip_prefix(self.name.as_str())?.strip_prefix('.')?;
        rest.strip_suffix(".gz").unwrap_or(rest).parse().ok()
    }

    fn rotated_files(&self) -> io::Result<Vec<(usize, PathBuf)>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(index) = entry.file_name().to_str().and_then(|n| self.index_of(n)) {
                files.push((index, entry.path()));
            }
        }
        Ok(files)
    }

    /// Compresses `<name>.1` and removes the files above the retention limit.
    fn clean_up(&self) -> io::Result<()> {
        #[cfg(test)]
        let _gate = tests::CLEANUP_GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.compress {
            gzip(&self.rotated(1, false), &self.rotated(1, true))?;
        }
        for (index, path) in self.rotated_files()? {
            if index >= self.max_files {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

fn gzip(source: &Path, target: &Path) -> io::Result<()> {
    let mut encoder = GzEncoder::new(BufWriter::new(File::create(target)?), Compression::default());
    io::copy(&mut File::open(source)?, &mut encoder)?;
    encoder.finish()?.flush()?;
    fs::remove_file(source)
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn rename_if_present(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// A writer that rotates `<directory>/<filename>` by size. See the module docs.
#[derive(Debug)]
pub(crate) struct RollingWriter {
    layout: Layout,
    max_bytes: u64,
    file: File,
    size: u64,
    next_index: usize,
    cleanup: Option<JoinHandle<()>>,
}

impl RollingWriter {
    /// Opens the active file in append mode. Creates the directory if necessary.
    pub(crate) fn open(config: &FileAppenderConfig) -> io::Result<Self> {
        let layout = Layout {
            dir: PathBuf::from(&config.directory),
            name: config.filename.clone(),
            max_files: config.max_files,
            compress: config.compress,
        };
        fs::create_dir_all(&layout.dir)?;
        let file = open_append(&layout.active())?;
        let highest = layout.rotated_files()?.into_iter().map(|(i, _)| i).max().unwrap_or(0);
        Ok(Self {
            max_bytes: config.max_size_mb.saturating_mul(1024 * 1024),
            size: file.metadata()?.len(),
            next_index: (highest + 1).min(layout.max_files),
            file,
            layout,
            cleanup: None,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        for index in (1..self.next_index).rev() {
            for gz in [false, true] {
                let to = self.layout.rotated(index + 1, gz);
                rename_if_present(&self.layout.rotated(index, gz), &to)?;
            }
        }
        fs::rename(self.layout.active(), self.layout.rotated(1, false))?;
        self.file = open_append(&self.layout.active())?;
        self.size = 0;
        self.next_index = (self.next_index + 1).min(self.layout.max_files);
        let layout = self.layout.clone();
        let cleanup = thread::Builder::new().name("rvc-log-cleanup".into()).spawn(move || {
            if let Err(e) = layout.clean_up() {
                eprintln!("log cleanup failed for {}: {e}", layout.active().display());
            }
        })?;
        self.cleanup = Some(cleanup);
        Ok(())
    }
}

impl Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.file.write(buf)?;
        self.size += written as u64;
        let busy = self.cleanup.as_ref().is_some_and(|c| !c.is_finished());
        if !busy && self.size >= self.max_bytes {
            self.rotate()?;
        }
        Ok(written)
    }

    /// `File` has no buffer, thus there is nothing to flush.
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
