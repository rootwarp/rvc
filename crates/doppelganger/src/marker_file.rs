//! One rule for reading a doppelganger marker path.
//!
//! A missing path is absent. Anything else — a symlink (dangling or not), a
//! directory, a FIFO, an unreadable file, or a file past the size cap — is
//! unreadable. The open uses `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and then
//! `fstat` on that fd. A FIFO or symlink swapped in after the type check cannot
//! block the open or be followed. The read is bounded.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

/// A larger payload is not a marker this process wrote.
pub const MAX_MARKER_BYTES: u64 = 1024 * 1024;

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

    let file = match open_nofollow(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return MarkerFile::Absent,
        Err(source) => return MarkerFile::Unreadable(source),
    };
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
}
