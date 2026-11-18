//! One rule for reading a doppelganger marker path.
//!
//! A missing path is absent. Anything else — a symlink (dangling or not), a
//! directory, a FIFO, an unreadable file, or a file past the size cap — is
//! unreadable. The open uses `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and then
//! `fstat` on that fd. A FIFO or symlink swapped in after the type check cannot
//! block the open or be followed. The read is bounded.

#[cfg(test)]
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

/// A larger payload is not a marker this process wrote.
pub const MAX_MARKER_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
type AfterLstatHook = Box<dyn Fn(&Path)>;

#[cfg(test)]
thread_local! {
    /// The hook runs between `symlink_metadata` and the open in [`read_marker_file`].
    static AFTER_LSTAT: RefCell<Option<AfterLstatHook>> = const { RefCell::new(None) };
}

/// Result of reading one marker path.
#[derive(Debug)]
pub enum MarkerFile {
    /// `symlink_metadata` reported not found. A dangling symlink is not this.
    Absent,
    /// A regular file, at most [`MAX_MARKER_BYTES`].
    Bytes(Vec<u8>),
    /// Present, or the read could not be trusted. Not absent.
    Unreadable(io::Error),
}

/// Read `path` without following a symlink and without reading past the cap.
pub fn read_marker_file(path: &Path) -> MarkerFile {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => return MarkerFile::Absent,
        Err(source) => return MarkerFile::Unreadable(source),
        // A symlink is unreadable without being opened, so it is never followed.
        // Every other type falls through to the non-blocking open: a FIFO that
        // replaces a regular file after this check must not block in `open`.
        Ok(meta) if meta.file_type().is_symlink() => {
            return MarkerFile::Unreadable(io::Error::new(
                io::ErrorKind::InvalidData,
                "detection marker is not a regular file",
            ));
        }
        Ok(_) => {}
    }
    #[cfg(test)]
    AFTER_LSTAT.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(path);
        }
    });

    match open_nofollow(path) {
        Ok(file) => read_open_marker(file),
        Err(source) if source.kind() == io::ErrorKind::NotFound => MarkerFile::Absent,
        Err(source) => MarkerFile::Unreadable(source),
    }
}

/// Read a marker through `file`, which the caller opened with `O_NOFOLLOW`
/// and `O_NONBLOCK`. Anything but a regular file within the size cap is
/// unreadable.
pub fn read_open_marker(file: File) -> MarkerFile {
    // `File::metadata` is `fstat` of this fd, not another lookup of the path.
    match file.metadata() {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => {
            return MarkerFile::Unreadable(io::Error::new(
                io::ErrorKind::InvalidData,
                "detection marker is not a regular file",
            ));
        }
        Err(source) => return MarkerFile::Unreadable(source),
    }
    let mut buf = Vec::new();
    if let Err(source) = file.take(MAX_MARKER_BYTES + 1).read_to_end(&mut buf) {
        return MarkerFile::Unreadable(source);
    }
    if buf.len() as u64 > MAX_MARKER_BYTES {
        return MarkerFile::Unreadable(io::Error::new(
            io::ErrorKind::InvalidData,
            "detection marker is not a regular file within the size cap",
        ));
    }
    MarkerFile::Bytes(buf)
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    opts.open(path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn fifo_marker_is_unreadable_without_blocking() {
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-fifo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("marker");
        let status = std::process::Command::new("mkfifo").arg(&path).status().expect("mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");

        let path_for_read = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_marker_file(&path_for_read));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("reading a FIFO marker blocked");
        assert!(matches!(result, MarkerFile::Unreadable(_)), "{result:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Return the file status flags of `file` from `fcntl(F_GETFL)`.
    /// A failed call returns -1.
    // The libc fcntl call is unsafe. This allow applies to this test helper only.
    #[allow(unsafe_code)]
    fn status_flags(file: &File) -> libc::c_int {
        use std::os::fd::AsRawFd;
        // SAFETY: `file` keeps the descriptor open during the call. F_GETFL takes
        // no third argument.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) }
    }

    /// The guard clears this thread's [`AFTER_LSTAT`] hook when it drops.
    struct AfterLstatGuard;

    impl Drop for AfterLstatGuard {
        fn drop(&mut self) {
            AFTER_LSTAT.with(|hook| *hook.borrow_mut() = None);
        }
    }

    /// Set the [`AFTER_LSTAT`] hook of this thread until the guard drops.
    fn arm_after_lstat(hook: impl Fn(&Path) + 'static) -> AfterLstatGuard {
        AFTER_LSTAT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        AfterLstatGuard
    }

    /// The hook replaces the regular marker with a FIFO after `lstat`.
    /// The test requires these results:
    ///
    /// - `open_nofollow` must set `O_NONBLOCK` on the regular marker before the swap.
    /// - The open must not block.
    /// - The read must return `Unreadable` for the FIFO.
    /// - The same thread must read a regular marker as bytes after the guard drops.
    #[test]
    fn marker_swapped_to_fifo_after_lstat_is_unreadable() {
        use std::os::unix::fs::FileTypeExt;
        let dir = std::env::temp_dir().join(format!(
            "rvc-dg-swap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("The system clock must be after the UNIX epoch.")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("The test must create the temporary directory.");
        let path = dir.join("marker");
        std::fs::write(&path, b"{}").expect("The test must write a regular marker file.");

        // The marker is a regular file before the swap, so this open cannot block.
        let opened = open_nofollow(&path).expect("open_nofollow must open the regular marker.");
        let flags = status_flags(&opened);
        assert_ne!(
            flags,
            -1,
            "The fcntl F_GETFL call must succeed. The error is {}.",
            io::Error::last_os_error()
        );
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "open_nofollow must set O_NONBLOCK. The status flags are {flags:#o}."
        );
        drop(opened);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // The hook is thread-local, so arm it on the reader thread.
            let hook = arm_after_lstat(|path| {
                std::fs::remove_file(path).expect("The hook must remove the regular marker file.");
                let status = std::process::Command::new("mkfifo")
                    .arg(path)
                    .status()
                    .expect("The hook must start mkfifo.");
                assert!(
                    status.success(),
                    "The mkfifo command must succeed. The status is {status}."
                );
            });
            let swapped = read_marker_file(&path);
            drop(hook);
            let fifo =
                std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_fifo());
            std::fs::remove_file(&path).expect("The test must remove the FIFO.");
            std::fs::write(&path, b"{}").expect("The test must write a regular marker file.");
            let _ = tx.send((swapped, fifo, read_marker_file(&path)));
        });
        // The timeout gives protection from a hang only.
        let (swapped, fifo, after_drop) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("The marker reads must return before the 10-second timeout.");
        assert!(
            matches!(swapped, MarkerFile::Unreadable(_)),
            "A FIFO in place of the marker after lstat must be Unreadable. The result is {swapped:?}."
        );
        assert!(fifo, "The hook must replace the marker with a FIFO.");
        assert!(
            matches!(after_drop, MarkerFile::Bytes(_)),
            "The hook must not run after its guard drops. The result is {after_drop:?}."
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
