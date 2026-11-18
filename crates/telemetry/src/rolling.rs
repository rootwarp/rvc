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
//!
//! The writer opens the log directory one time. Each later file operation uses
//! that handle and does not follow a symlink. Each file that the writer opens
//! must be a regular file of the process user, and it gets mode 0600.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use flate2::write::GzEncoder;
use flate2::Compression;
use rustix::fs::{AtFlags, Dir, Mode, OFlags};

use crate::file_appender::FileAppenderConfig;

/// The directory handle, the names and the retention limit of one rolling log file.
#[derive(Debug, Clone)]
struct Layout {
    dir: Arc<OwnedFd>,
    name: String,
    max_files: usize,
    compress: bool,
}

impl Layout {
    fn rotated(&self, index: usize, gz: bool) -> String {
        let suffix = if gz { ".gz" } else { "" };
        format!("{}.{index}{suffix}", self.name)
    }

    /// Returns `N` for `<name>.N` and `<name>.N.gz`.
    fn index_of(&self, file_name: &str) -> Option<usize> {
        let rest = file_name.strip_prefix(self.name.as_str())?.strip_prefix('.')?;
        rest.strip_suffix(".gz").unwrap_or(rest).parse().ok()
    }

    fn rotated_files(&self) -> io::Result<Vec<(usize, String)>> {
        let mut files = Vec::new();
        for entry in Dir::read_from(&*self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(index) = self.index_of(&name) {
                files.push((index, name));
            }
        }
        Ok(files)
    }

    /// Opens `name` in the log directory. Rejects a symlink, a file that is not
    /// a regular file, and a file of a different user. `NONBLOCK` stops a FIFO
    /// from blocking the open.
    fn open(&self, name: &str, flags: OFlags) -> io::Result<File> {
        let flags = OFlags::from_iter([flags, OFlags::NOFOLLOW, OFlags::NONBLOCK, OFlags::CLOEXEC]);
        let mode = Mode::from_raw_mode(0o600);
        let file = File::from(rustix::fs::openat(&*self.dir, name, flags, mode)?);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != owner_uid() {
            let message = format!("log file {name} is not a regular file of this user");
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    fn open_active(&self) -> io::Result<File> {
        self.open(&self.name, OFlags::from_iter([OFlags::WRONLY, OFlags::APPEND, OFlags::CREATE]))
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        Ok(rustix::fs::renameat(&*self.dir, from, &*self.dir, to)?)
    }

    fn rename_if_present(&self, from: &str, to: &str) -> io::Result<()> {
        match self.rename(from, to) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&*self.dir, name, AtFlags::empty())?)
    }

    /// Compresses `<name>.1` and removes the files above the retention limit.
    fn clean_up(&self) -> io::Result<()> {
        #[cfg(test)]
        let _gate = tests::CLEANUP_GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.compress {
            self.gzip(&self.rotated(1, false), &self.rotated(1, true))?;
        }
        for (index, name) in self.rotated_files()? {
            if index >= self.max_files {
                self.remove(&name)?;
            }
        }
        Ok(())
    }

    fn gzip(&self, source: &str, target: &str) -> io::Result<()> {
        let mut input = self.open(source, OFlags::RDONLY)?;
        let output = self.open(target, OFlags::from_iter([OFlags::WRONLY, OFlags::CREATE]))?;
        output.set_len(0)?;
        let mut encoder = GzEncoder::new(BufWriter::new(output), Compression::default());
        io::copy(&mut input, &mut encoder)?;
        encoder.finish()?.flush()?;
        self.remove(source)
    }
}

/// Each log file must have this owner: the effective UID of the process.
fn owner_uid() -> u32 {
    #[cfg(test)]
    if let Some(uid) = tests::OWNER_UID.with(std::cell::Cell::get) {
        return uid;
    }
    rustix::process::geteuid().as_raw()
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
    /// The file name must be one path component.
    pub(crate) fn open(config: &FileAppenderConfig) -> io::Result<Self> {
        let name = config.filename.as_str();
        if Path::new(name).file_name() != Some(OsStr::new(name)) {
            let message = format!("log file name {name:?} must be one path component");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        }
        fs::create_dir_all(&config.directory)?;
        let dir_flags = OFlags::from_iter([OFlags::RDONLY, OFlags::DIRECTORY, OFlags::CLOEXEC]);
        let layout = Layout {
            dir: Arc::new(rustix::fs::open(config.directory.as_str(), dir_flags, Mode::empty())?),
            name: name.to_owned(),
            max_files: config.max_files,
            compress: config.compress,
        };
        let file = layout.open_active()?;
        let highest = layout.rotated_files()?.into_iter().map(|(i, _)| i).max().unwrap_or(0);
        Ok(Self {
            max_bytes: config.max_size_mb.saturating_mul(1024 * 1024),
            size: file.metadata()?.len(),
            next_index: highest.saturating_add(1).min(layout.max_files),
            file,
            layout,
            cleanup: None,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        for index in (1..self.next_index).rev() {
            for gz in [false, true] {
                let to = self.layout.rotated(index + 1, gz);
                self.layout.rename_if_present(&self.layout.rotated(index, gz), &to)?;
            }
        }
        self.layout.rename(&self.layout.name, &self.layout.rotated(1, false))?;
        self.file = self.layout.open_active()?;
        self.size = 0;
        self.next_index = self.next_index.saturating_add(1).min(self.layout.max_files);
        let layout = self.layout.clone();
        let cleanup = thread::Builder::new().name("rvc-log-cleanup".into()).spawn(move || {
            if let Err(e) = layout.clean_up() {
                eprintln!("log cleanup failed for {}: {e}", layout.name);
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
    use std::cell::Cell;
    use std::io::Read;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::Mutex;
    use std::time::Duration;

    /// While a test holds this lock, the background cleanup cannot start.
    pub(crate) static CLEANUP_GATE: Mutex<()> = Mutex::new(());

    thread_local! {
        /// When set, the writer on this thread uses this owner UID instead of the process UID.
        pub(crate) static OWNER_UID: Cell<Option<u32>> = const { Cell::new(None) };
    }

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

    fn layout(dir: &Path) -> Layout {
        let dir = Arc::new(rustix::fs::open(dir, OFlags::RDONLY, Mode::empty()).unwrap());
        Layout { dir, name: "app.log".to_string(), max_files: 5, compress: false }
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

    fn gunzip(path: &Path) -> Vec<u8> {
        let mut text = Vec::new();
        GzDecoder::new(File::open(path).unwrap()).read_to_end(&mut text).unwrap();
        text
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
        assert_eq!(
            names(dir.path()),
            ["app.log"],
            "The writer must not rotate when the file size is one byte below the limit."
        );

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
        let archive = |index: usize| gunzip(&dir.path().join(format!("app.log.{index}.gz")));
        assert_eq!(archive(1), vec![b'a'; MIB], "The archive must hold the rotated bytes.");

        writer.write_all(b"b").unwrap();
        writer.join_cleanup();
        assert_eq!(names(dir.path()), ["app.log", "app.log.1.gz", "app.log.2.gz"]);
        assert_eq!(
            archive(1),
            vec![b'b'; MIB + 1],
            "The writer must keep the bytes that it wrote while the cleanup ran."
        );
        assert_eq!(archive(2), vec![b'a'; MIB], "The older archive must move to index 2.");
    }

    #[test]
    fn open_appends_to_the_existing_files_and_removes_files_above_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        fs::write(path("app.log"), vec![b'a'; MIB - 1]).unwrap();
        fs::write(path("app.log.1"), "b").unwrap();
        fs::write(path("app.log.2.gz"), "c").unwrap();
        fs::write(path("other.log.1"), "e").unwrap();
        symlink(path("other.log.1"), path("app.log.7")).unwrap();
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
        assert_eq!(fs::read(path("other.log.1")).unwrap(), b"e", "The target must not change.");
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
        assert_eq!(
            fs::read(dir.path().join("app.log")).unwrap(),
            vec![b'a'; MIB],
            "A failed rename must keep the bytes of the active file."
        );
    }

    #[test]
    fn new_and_existing_log_files_are_private_under_a_permissive_umask() {
        let dir = tempfile::tempdir().unwrap();
        let mode = |name: &str| fs::metadata(dir.path().join(name)).unwrap().permissions().mode();
        fs::write(dir.path().join("app.log"), "old").unwrap();
        fs::set_permissions(dir.path().join("app.log"), fs::Permissions::from_mode(0o644)).unwrap();
        let umask = rustix::process::umask(rustix::fs::Mode::empty());
        let mut writer = RollingWriter::open(&config(dir.path(), 5, true)).unwrap();
        let existing = mode("app.log") & 0o777;
        roll(&mut writer, b'a');
        rustix::process::umask(umask);
        assert_eq!(existing, 0o600, "The writer must make the existing active file private.");
        for name in ["app.log", "app.log.1.gz"] {
            assert_eq!(mode(name) & 0o777, 0o600, "The writer must create {name} with mode 0600.");
        }
    }

    #[test]
    fn open_rejects_a_file_name_that_is_not_one_component() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("logs");
        fs::create_dir(&dir).unwrap();
        let outside = root.path().join("outside.log").to_string_lossy().into_owned();
        for name in ["", ".", "..", "a/app.log", "../app.log", "app.log/", &outside] {
            let config = FileAppenderConfig { filename: name.into(), ..config(&dir, 5, false) };
            let error = RollingWriter::open(&config).expect_err("The writer must reject the name.");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?} is not one component.");
        }
        assert_eq!(names(root.path()), ["logs"], "The writer must not create a file outside logs.");
    }

    #[test]
    fn open_and_compression_do_not_follow_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("logs");
        let secret = root.path().join("secret");
        fs::write(&secret, "secret").unwrap();
        let mut writer = RollingWriter::open(&config(&dir, 5, true)).unwrap();
        fs::remove_file(dir.join("app.log")).unwrap();
        symlink(&secret, dir.join("app.log")).unwrap();

        RollingWriter::open(&config(&dir, 5, true)).expect_err("The open must not follow a link.");
        roll(&mut writer, b'a');
        assert_eq!(names(&dir), ["app.log", "app.log.1"], "The cleanup must not gzip a link.");
        assert_eq!(fs::read(&secret).unwrap(), b"secret", "The symlink target must not change.");
    }

    #[test]
    fn open_rejects_a_file_of_another_user_and_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("app.log");
        fs::write(&active, "old").unwrap();
        OWNER_UID.with(|uid| uid.set(Some(rustix::process::geteuid().as_raw() + 1)));
        let result = RollingWriter::open(&config(dir.path(), 5, false));
        OWNER_UID.with(|uid| uid.set(None));
        let error = result.expect_err("The writer must reject a file of another user.");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        fs::remove_file(&active).unwrap();
        assert!(std::process::Command::new("mkfifo").arg(&active).status().unwrap().success());
        let layout = layout(dir.path());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || tx.send(layout.open("app.log", OFlags::RDONLY).map(drop)));
        let opened = rx.recv_timeout(Duration::from_secs(10)).expect("The open must not block.");
        let error = opened.expect_err("The writer must reject a FIFO.");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "A FIFO is not a regular file.");
    }

    #[test]
    fn open_accepts_the_largest_rotation_index() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.log.1"), "b").unwrap();
        fs::write(dir.path().join(format!("app.log.{}", usize::MAX)), "c").unwrap();
        let mut writer = RollingWriter::open(&config(dir.path(), 4, false)).unwrap();

        roll(&mut writer, b'a');
        assert_eq!(
            names(dir.path()),
            ["app.log", "app.log.1", "app.log.2"],
            "The cleanup must remove the file with the largest index."
        );
        assert_eq!(fs::read(dir.path().join("app.log.2")).unwrap(), b"b");
    }

    #[test]
    fn index_of_reads_only_rotated_names() {
        let layout = layout(Path::new("."));
        assert_eq!(layout.index_of("app.log.3"), Some(3));
        assert_eq!(layout.index_of("app.log.12.gz"), Some(12));
        for other in ["app.log", "app.log.gz", "app.logx.1", "app.log.1.tmp", "a.app.log.1"] {
            assert_eq!(layout.index_of(other), None, "{other} is not a rotated file name.");
        }
    }
}
