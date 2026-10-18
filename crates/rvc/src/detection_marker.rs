//! Durable doppelganger detection marker and the pre-allocated record.
//!
//! At boot the process creates a fixed-size `.rvc.doppelganger_record` in the
//! keystore directory and fills it with a `not-detected` header. Detection
//! overwrites that file in place (`pwrite`, then `fsync`). An in-place
//! overwrite does not allocate a new directory entry. On copy-on-write or
//! thin storage (btrfs, ZFS, thin LVM) it can still allocate a new block.
//! The keystore marker and, when that directory is different, the same marker
//! beside the slashing database are additional paths. A write is durable only
//! after its `fsync` returns `Ok`, and a rename also needs the directory
//! `fsync`. A later read is not a substitute. Exit 12 follows that
//! acknowledgement. A `SIGKILL` before the first of them is durable loses
//! the latch. The next start refuses to run while a marker is present or the
//! record is `detected`, including when a file cannot be read, is a symlink,
//! or is not valid. Clearing it is `rvc doppelganger clear-detection
//! --datadir … --slashing-db-path … --confirm`, which also forces a full
//! forward window on the next boot. Deleting only the keystore marker by
//! hand does not force that window and does not clear a detected record. A
//! record that is not a regular 4096-byte file cannot be reset in place:
//! stop the process, remove `.rvc.doppelganger_record`, and run
//! `clear-detection` again. Do not remove a valid `detected` record by hand;
//! that skips the force-window file.

#[cfg(test)]
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// File name under the validator data directory.
pub const MARKER_FILENAME: &str = ".rvc.doppelganger_detected";

/// One-shot file written by `clear-detection`. The next boot does not
/// restart-skip while it is present. The machine deletes it only after every
/// key registered while it was present has finished a full forward window.
pub const FORCE_WINDOW_FILENAME: &str = ".rvc.doppelganger_force_window";

const MARKER_VERSION: u32 = 1;

/// A larger file is not a marker this process wrote.
#[cfg(test)]
const MAX_MARKER_BYTES: u64 = doppelganger::marker_file::MAX_MARKER_BYTES;

/// What a start-up read of the marker found.
#[derive(Debug)]
pub enum MarkerInspect {
    /// No marker file.
    Absent,
    /// A marker this process can describe.
    Present(DetectionMarker),
    /// The file exists but is not a version-1 marker.
    Corrupt { path: PathBuf, reason: String },
    /// The path could not be read. This is not "absent".
    Unreadable { path: PathBuf, source: io::Error },
}

/// Detected keys, the epoch of the detection, and the wall time it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionMarker {
    pub epoch: u64,
    pub unix_secs: u64,
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerDocument {
    version: u32,
    epoch: u64,
    unix_secs: u64,
    pubkeys: Vec<String>,
}

/// `Removed` when a marker file was unlinked. `Absent` when there was none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    Removed,
    Absent,
}

/// Path of the marker in `data_dir`.
pub fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MARKER_FILENAME)
}

/// Parent of `slashing_db_path` when that directory is not `keystore_dir`.
///
/// The fallback marker uses [`MARKER_FILENAME`] in this directory. The same
/// directory as the keystore is not a second disk, so the caller keeps
/// retrying the keystore write instead.
pub fn fallback_marker_dir(keystore_dir: &Path, slashing_db_path: &Path) -> Option<PathBuf> {
    let parent = slashing_db_path.parent().filter(|parent| !parent.as_os_str().is_empty())?;
    if same_dir(parent, keystore_dir) {
        None
    } else {
        Some(parent.to_path_buf())
    }
}

fn same_dir(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Read the marker. A missing file is [`MarkerInspect::Absent`].
///
/// A symlink, including a dangling one, is [`MarkerInspect::Unreadable`].
pub fn inspect(data_dir: &Path) -> MarkerInspect {
    let path = marker_path(data_dir);
    match doppelganger::marker_file::read_marker_file(&path) {
        doppelganger::marker_file::MarkerFile::Absent => MarkerInspect::Absent,
        doppelganger::marker_file::MarkerFile::Unreadable(source) => {
            MarkerInspect::Unreadable { path, source }
        }
        doppelganger::marker_file::MarkerFile::Bytes(bytes) => match parse_marker(&bytes) {
            Ok(marker) => MarkerInspect::Present(marker),
            Err(reason) => MarkerInspect::Corrupt { path, reason },
        },
    }
}

/// Path of the one-shot force-window file in `data_dir`.
pub fn force_window_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FORCE_WINDOW_FILENAME)
}

/// Prove `data_dir` can hold a marker: create a temp file, fsync, and remove it.
pub fn probe_marker_dir_writable(data_dir: &Path) -> io::Result<()> {
    if !data_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "marker directory is missing or not a directory",
        ));
    }
    let tmp_path = data_dir.join(format!(
        ".{MARKER_FILENAME}.{}.{}.probe",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        file.write_all(b"ok")?;
        sync_file(&file)?;
        drop(file);
        fs::remove_file(&tmp_path)?;
        sync_dir(data_dir)?;
        Ok(())
    })();
    if write_result.is_err() && tmp_path.exists() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

/// Write the one-shot force-window file. The next boot does not restart-skip
/// while it remains.
pub fn write_force_window(data_dir: &Path) -> io::Result<()> {
    atomic_write(data_dir, FORCE_WINDOW_FILENAME, b"1\n")
}

/// `true` when restart-skip and import history must not skip the window.
///
/// A missing file is `false`. Any other outcome, including an unreadable or
/// corrupt file, is `true`.
pub fn blocks_window_skip(data_dir: &Path) -> bool {
    !matches!(inspect(data_dir), MarkerInspect::Absent)
}

/// Write the marker: temp file, fsync, rename, fsync the directory.
///
/// Pubkeys are stored as `0x` plus 96 lowercase hex digits. An empty list is
/// still written so a detection with no parsed key refuses the next start.
pub fn write_marker(data_dir: &Path, marker: &DetectionMarker) -> io::Result<()> {
    #[cfg(test)]
    if take_marker_write_failure() {
        return Err(io::Error::new(io::ErrorKind::StorageFull, "injected marker write failure"));
    }
    let pubkeys = marker
        .pubkeys
        .iter()
        .map(|pk| {
            normalize_pubkey(pk).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "detection marker pubkey is invalid")
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let doc = MarkerDocument {
        version: MARKER_VERSION,
        epoch: marker.epoch,
        unix_secs: marker.unix_secs,
        pubkeys,
    };
    let body = serde_json::to_vec_pretty(&doc)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(data_dir, MARKER_FILENAME, &body)
}

fn atomic_write(data_dir: &Path, filename: &str, body: &[u8]) -> io::Result<()> {
    let final_path = data_dir.join(filename);
    let tmp_path = data_dir.join(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(body)?;
        sync_file(&file)?;
        drop(file);
        fs::rename(&tmp_path, &final_path)?;
        sync_dir(data_dir)?;
        Ok(())
    })();
    if write_result.is_err() && tmp_path.exists() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

/// Unlink the marker and fsync the directory. A missing file is success.
pub fn clear_marker(data_dir: &Path) -> io::Result<ClearOutcome> {
    let path = marker_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => {
            sync_dir(data_dir)?;
            Ok(ClearOutcome::Removed)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(ClearOutcome::Absent),
        Err(source) => Err(source),
    }
}

/// Unix seconds for a marker timestamp. A clock before the epoch records 0.
pub fn unix_secs_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Fixed-size detection record in the keystore directory.
///
/// Boot creates it full of a `not-detected` header. Detection overwrites those
/// same bytes and keeps the length at [`RECORD_LEN`]. An in-place overwrite
/// does not allocate a new directory entry. On copy-on-write or thin storage
/// (btrfs, ZFS, thin LVM) it can still allocate a new block.
pub const RECORD_FILENAME: &str = ".rvc.doppelganger_record";

/// Bytes occupied by [`RECORD_FILENAME`]. Both states write this many bytes.
pub const RECORD_LEN: usize = 4096;

/// What a start-up read of the pre-allocated record found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordInspect {
    /// No record file.
    Absent,
    /// A pre-allocated file whose header is `not-detected`.
    Clear,
    /// The header is `detected`. The next start must refuse.
    Detected { epoch: u64, unix_secs: u64 },
    /// Present, but not a fixed-size record this process can trust.
    Unreadable { path: PathBuf, reason: String },
}

/// `true` when the record is `detected` or cannot be trusted as `not-detected`.
///
/// A missing file and a clear pre-allocated file are not a durable latch.
pub fn record_blocks_restart(data_dir: &Path) -> bool {
    !matches!(inspect_record(data_dir), RecordInspect::Absent | RecordInspect::Clear)
}

/// Path of the pre-allocated record in `data_dir`.
pub fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECORD_FILENAME)
}

/// Read the pre-allocated record. A missing file is [`RecordInspect::Absent`].
pub fn inspect_record(data_dir: &Path) -> RecordInspect {
    let path = record_path(data_dir);
    match doppelganger::marker_file::read_marker_file(&path) {
        doppelganger::marker_file::MarkerFile::Absent => RecordInspect::Absent,
        doppelganger::marker_file::MarkerFile::Unreadable(source) => {
            RecordInspect::Unreadable { path, reason: source.to_string() }
        }
        doppelganger::marker_file::MarkerFile::Bytes(bytes) => match parse_record(&bytes) {
            Ok(ParsedRecord::Clear) => RecordInspect::Clear,
            Ok(ParsedRecord::Detected { epoch, unix_secs }) => {
                RecordInspect::Detected { epoch, unix_secs }
            }
            Err(reason) => RecordInspect::Unreadable { path, reason },
        },
    }
}

/// Create the fixed-size record when it is missing, filled with `not-detected`.
///
/// A file that is already a clear record is left in place. A detected record
/// is not overwritten. Anything else, including a symlink, is an error: this
/// does not unlink and recreate, because that recreation can fail with no
/// space left. The new file is mode `0600`, a regular file, and fsynced.
pub fn preallocate_detection_record(data_dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    if take_preallocate_failure() {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected detection-record preallocation failure",
        ));
    }
    match inspect_record(data_dir) {
        RecordInspect::Clear => return Ok(()),
        RecordInspect::Detected { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "detection record is already in the detected state",
            ));
        }
        RecordInspect::Unreadable { reason, .. } => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
        }
        RecordInspect::Absent => {}
    }
    let path = record_path(data_dir);
    let bytes = encode_record(false, 0, 0)?;
    let mut file = open_record(&path, true)?;
    let write_result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        write_record_bytes(&mut file, &bytes)?;
        sync_file(&file)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        drop(file);
        let _ = fs::remove_file(&path);
        let _ = sync_dir(data_dir);
        return Err(err);
    }
    drop(file);
    sync_dir(data_dir)?;
    Ok(())
}

/// Overwrite the pre-allocated record with `detected` and fsync it.
///
/// The file must already be a regular file of [`RECORD_LEN`] bytes. This does
/// not create a file and does not extend one.
pub fn commit_detection_record(data_dir: &Path, epoch: u64, unix_secs: u64) -> io::Result<()> {
    let path = record_path(data_dir);
    let mut file = open_record(&path, false)?;
    let bytes = encode_record(true, epoch, unix_secs)?;
    write_record_bytes(&mut file, &bytes)?;
    sync_file(&file)?;
    Ok(())
}

/// Write `not-detected` over a detected record. A missing record is success.
///
/// A record that is not the pre-allocated size is left untouched and this
/// returns an error. `clear-detection` then leaves the marker in place. Stop
/// the process, remove [`RECORD_FILENAME`], and run
/// `clear-detection` again. A valid `detected` record is reset by that
/// command; deleting the file by hand skips the force-window file.
pub fn reset_detection_record(data_dir: &Path) -> io::Result<ClearOutcome> {
    match inspect_record(data_dir) {
        RecordInspect::Absent | RecordInspect::Clear => Ok(ClearOutcome::Absent),
        RecordInspect::Detected { .. } => {
            let path = record_path(data_dir);
            let mut file = open_record(&path, false)?;
            let bytes = encode_record(false, 0, 0)?;
            write_record_bytes(&mut file, &bytes)?;
            sync_file(&file)?;
            Ok(ClearOutcome::Removed)
        }
        RecordInspect::Unreadable { reason, .. } => {
            Err(io::Error::new(io::ErrorKind::InvalidData, reason))
        }
    }
}

/// Persist the in-place record when it exists, then the marker file.
///
/// `Ok` only after a `pwrite` and its file `fsync` both succeeded, or the
/// marker write, file `fsync`, rename, and directory `fsync` all succeeded.
/// Callers record durability from that `Ok`. A later read is not a substitute:
/// the page cache can show `detected` when `fsync` failed. An in-place
/// overwrite does not allocate a new directory entry. On copy-on-write or
/// thin storage (btrfs, ZFS, thin LVM) it can still allocate a new block.
pub fn persist_detection(data_dir: &Path, marker: &DetectionMarker) -> io::Result<()> {
    let record_ok = commit_detection_record(data_dir, marker.epoch, marker.unix_secs).is_ok();
    match write_marker(data_dir, marker) {
        Ok(()) => Ok(()),
        Err(_) if record_ok => Ok(()),
        Err(err) => Err(err),
    }
}

enum ParsedRecord {
    Clear,
    Detected { epoch: u64, unix_secs: u64 },
}

fn encode_record(detected: bool, epoch: u64, unix_secs: u64) -> io::Result<[u8; RECORD_LEN]> {
    let state = if detected { "detected" } else { "not-detected" };
    let text = format!("version=1\nstate={state}\nepoch={epoch}\nunix_secs={unix_secs}\n");
    if text.len() > RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "detection record header exceeds the fixed size",
        ));
    }
    let mut buf = [0u8; RECORD_LEN];
    buf[..text.len()].copy_from_slice(text.as_bytes());
    Ok(buf)
}

fn parse_record(bytes: &[u8]) -> Result<ParsedRecord, String> {
    if bytes.len() != RECORD_LEN {
        return Err(format!("record length {} is not {RECORD_LEN}", bytes.len()));
    }
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|&byte| byte != 0) {
        return Err("record has non-zero bytes after the header".to_string());
    }
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| "record is not utf-8".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err("record version is not 1".to_string());
    }
    let detected = match lines.next() {
        Some("state=detected") => true,
        Some("state=not-detected") => false,
        _ => return Err("record state is not detected or not-detected".to_string()),
    };
    let epoch = parse_record_u64(lines.next(), "epoch")?;
    let unix_secs = parse_record_u64(lines.next(), "unix_secs")?;
    if lines.next().is_some() {
        return Err("record header has extra lines".to_string());
    }
    if detected {
        Ok(ParsedRecord::Detected { epoch, unix_secs })
    } else {
        Ok(ParsedRecord::Clear)
    }
}

fn parse_record_u64(line: Option<&str>, field: &str) -> Result<u64, String> {
    let Some(line) = line else {
        return Err(format!("record is missing {field}"));
    };
    let Some(value) = line.strip_prefix(&format!("{field}=")) else {
        return Err(format!("record {field} is missing"));
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("record {field} is not a u64"));
    }
    value.parse().map_err(|_| format!("record {field} is not a u64"))
}

fn open_record(path: &Path, create: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    if create {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if create {
            opts.mode(0o600);
        }
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "detection record is not a regular file",
        ));
    }
    if !create && meta.len() != RECORD_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "detection record is not the preallocated size",
        ));
    }
    Ok(file)
}

fn write_record_bytes(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut offset = 0u64;
        while offset < bytes.len() as u64 {
            let wrote = file.write_at(&bytes[offset as usize..], offset)?;
            if wrote == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "detection record write made no progress",
                ));
            }
            offset += wrote as u64;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static MARKER_WRITE_FAILS_LEFT: Cell<u32> = const { Cell::new(0) };
    static PREALLOCATE_FAILS: Cell<bool> = const { Cell::new(false) };
    static FSYNC_FAILS_LEFT: Cell<u32> = const { Cell::new(0) };
}

/// Fail the next `count` [`write_marker`] calls on this thread.
///
/// `u32::MAX` keeps failing until the guard drops. The in-place record write
/// is not affected.
#[cfg(test)]
pub(crate) fn arm_marker_write_failures(count: u32) -> MarkerWriteFailGuard {
    MARKER_WRITE_FAILS_LEFT.with(|left| left.set(count));
    MarkerWriteFailGuard
}

/// Fail the next `count` fsyncs on this thread with `EIO`.
///
/// `u32::MAX` keeps failing until the guard drops. `pwrite` still updates the
/// page cache, so a later read can show `detected` with nothing durable.
#[cfg(test)]
pub(crate) fn arm_fsync_failures(count: u32) -> FsyncFailGuard {
    FSYNC_FAILS_LEFT.with(|left| left.set(count));
    FsyncFailGuard
}

/// Fail the next [`preallocate_detection_record`] call on this thread.
#[cfg(test)]
pub(crate) fn arm_preallocate_failure() -> PreallocateFailGuard {
    PREALLOCATE_FAILS.with(|fail| fail.set(true));
    PreallocateFailGuard
}

#[cfg(test)]
fn take_marker_write_failure() -> bool {
    MARKER_WRITE_FAILS_LEFT.with(|left| {
        let remaining = left.get();
        if remaining == 0 {
            false
        } else {
            if remaining != u32::MAX {
                left.set(remaining - 1);
            }
            true
        }
    })
}

#[cfg(test)]
fn take_fsync_failure() -> bool {
    FSYNC_FAILS_LEFT.with(|left| {
        let remaining = left.get();
        if remaining == 0 {
            false
        } else {
            if remaining != u32::MAX {
                left.set(remaining - 1);
            }
            true
        }
    })
}

#[cfg(test)]
fn take_preallocate_failure() -> bool {
    PREALLOCATE_FAILS.with(|fail| {
        let armed = fail.get();
        if armed {
            fail.set(false);
        }
        armed
    })
}

/// Clears injected marker-write failures when dropped.
#[cfg(test)]
pub(crate) struct MarkerWriteFailGuard;

#[cfg(test)]
impl Drop for MarkerWriteFailGuard {
    fn drop(&mut self) {
        MARKER_WRITE_FAILS_LEFT.with(|left| left.set(0));
    }
}

/// Clears injected fsync failures when dropped.
#[cfg(test)]
pub(crate) struct FsyncFailGuard;

#[cfg(test)]
impl Drop for FsyncFailGuard {
    fn drop(&mut self) {
        FSYNC_FAILS_LEFT.with(|left| left.set(0));
    }
}

/// Clears an injected pre-allocation failure when dropped.
#[cfg(test)]
pub(crate) struct PreallocateFailGuard;

#[cfg(test)]
impl Drop for PreallocateFailGuard {
    fn drop(&mut self) {
        PREALLOCATE_FAILS.with(|fail| fail.set(false));
    }
}

fn sync_file(file: &File) -> io::Result<()> {
    #[cfg(test)]
    if take_fsync_failure() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    file.sync_all()
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    let path = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    sync_file(&File::open(path)?)
}

fn parse_marker(bytes: &[u8]) -> Result<DetectionMarker, String> {
    let doc: MarkerDocument =
        serde_json::from_slice(bytes).map_err(|e| format!("marker json: {e}"))?;
    if doc.version != MARKER_VERSION {
        return Err(format!("marker version {} is not {MARKER_VERSION}", doc.version));
    }
    let mut pubkeys = Vec::with_capacity(doc.pubkeys.len());
    for pk in &doc.pubkeys {
        let normalized =
            normalize_pubkey(pk).ok_or_else(|| "marker pubkey is invalid".to_string())?;
        if pubkeys.iter().any(|seen: &String| seen == &normalized) {
            return Err("marker repeats a pubkey".to_string());
        }
        pubkeys.push(normalized);
    }
    Ok(DetectionMarker { epoch: doc.epoch, unix_secs: doc.unix_secs, pubkeys })
}

fn normalize_pubkey(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    if hex.len() != 96 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", hex.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey() -> String {
        format!("0x{}", "ab".repeat(48))
    }

    #[test]
    fn write_then_inspect_round_trips_pubkeys_epoch_and_time() {
        let dir = tempfile::tempdir().expect("temp");
        let marker =
            DetectionMarker { epoch: 42, unix_secs: 1_700_000_000, pubkeys: vec![pubkey()] };
        write_marker(dir.path(), &marker).expect("write");
        let MarkerInspect::Present(read) = inspect(dir.path()) else {
            panic!("marker must be present");
        };
        assert_eq!(read.epoch, 42);
        assert_eq!(read.unix_secs, 1_700_000_000);
        assert_eq!(read.pubkeys, vec![pubkey()]);
        assert!(blocks_window_skip(dir.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(marker_path(dir.path())).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the marker must be owner-read/write only");
        }
        let tmp_left = fs::read_dir(dir.path())
            .expect("dir")
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".tmp"));
        assert!(!tmp_left, "the temp file must not remain after rename");
    }

    #[test]
    fn clear_removes_the_marker_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("temp");
        write_marker(
            dir.path(),
            &DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![pubkey()] },
        )
        .expect("write");
        assert_eq!(clear_marker(dir.path()).expect("clear"), ClearOutcome::Removed);
        assert!(matches!(inspect(dir.path()), MarkerInspect::Absent));
        assert_eq!(clear_marker(dir.path()).expect("second"), ClearOutcome::Absent);
        assert!(!blocks_window_skip(dir.path()));
    }

    #[test]
    fn corrupt_and_unreadable_markers_fail_closed() {
        let dir = tempfile::tempdir().expect("temp");
        fs::write(marker_path(dir.path()), b"not-json").expect("corrupt");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Corrupt { .. }));
        assert!(blocks_window_skip(dir.path()));

        let dir = tempfile::tempdir().expect("temp");
        fs::create_dir(marker_path(dir.path())).expect("dir-as-marker");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Unreadable { .. }));
        assert!(blocks_window_skip(dir.path()));

        let dir = tempfile::tempdir().expect("temp");
        fs::write(
            marker_path(dir.path()),
            br#"{"version":1,"epoch":1,"unix_secs":1,"pubkeys":["0xzz"]}"#,
        )
        .expect("bad pubkey");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Corrupt { .. }));

        let dir = tempfile::tempdir().expect("temp");
        fs::write(
            marker_path(dir.path()),
            br#"{"version":2,"epoch":1,"unix_secs":1,"pubkeys":[]}"#,
        )
        .expect("bad version");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Corrupt { .. }));
        assert!(blocks_window_skip(dir.path()));

        let repeated = pubkey();
        let dir = tempfile::tempdir().expect("temp");
        fs::write(
            marker_path(dir.path()),
            format!(
                r#"{{"version":1,"epoch":1,"unix_secs":1,"pubkeys":["{repeated}","{repeated}"]}}"#
            ),
        )
        .expect("duplicate pubkey");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Corrupt { .. }));
        assert!(blocks_window_skip(dir.path()));

        let dir = tempfile::tempdir().expect("temp");
        fs::write(marker_path(dir.path()), vec![b'x'; (MAX_MARKER_BYTES as usize) + 1])
            .expect("huge");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Unreadable { .. }));
        assert!(blocks_window_skip(dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_at_the_marker_path_is_not_absent() {
        let dir = tempfile::tempdir().expect("temp");
        std::os::unix::fs::symlink("missing-target", marker_path(dir.path())).expect("symlink");
        assert!(
            matches!(inspect(dir.path()), MarkerInspect::Unreadable { .. }),
            "a dangling symlink must not look absent"
        );
        assert!(blocks_window_skip(dir.path()));

        let dir = tempfile::tempdir().expect("temp");
        let target = dir.path().join("real");
        fs::write(&target, br#"{"version":1,"epoch":1,"unix_secs":1,"pubkeys":[]}"#)
            .expect("target");
        std::os::unix::fs::symlink(&target, marker_path(dir.path())).expect("symlink");
        assert!(
            matches!(inspect(dir.path()), MarkerInspect::Unreadable { .. }),
            "a symlink to a regular file is not followed"
        );
    }

    #[test]
    fn probe_rejects_a_missing_directory_and_accepts_a_writable_one() {
        let missing = std::env::temp_dir().join(format!(
            "rvc-dg-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos()
        ));
        assert!(probe_marker_dir_writable(&missing).is_err());

        let dir = tempfile::tempdir().expect("temp");
        probe_marker_dir_writable(dir.path()).expect("writable");
        let left = fs::read_dir(dir.path()).expect("dir").count();
        assert_eq!(left, 0, "the probe file must be removed");
    }

    #[test]
    fn metadata_read_error_is_not_absent() {
        let dir = tempfile::tempdir().expect("temp");
        let not_a_dir = dir.path().join("file");
        fs::write(&not_a_dir, b"x").expect("file");
        let inspected = inspect(&not_a_dir);
        assert!(
            matches!(inspected, MarkerInspect::Unreadable { .. }),
            "a metadata error must not look absent, got {inspected:?}"
        );
        assert!(blocks_window_skip(&not_a_dir));
    }

    #[test]
    fn fallback_dir_is_the_slashing_parent_only_when_it_differs() {
        let root = tempfile::tempdir().expect("temp");
        let keys = root.path().join("keys");
        let slash = root.path().join("slash");
        fs::create_dir_all(&keys).expect("keys");
        fs::create_dir_all(&slash).expect("slash");
        assert_eq!(
            fallback_marker_dir(&keys, &slash.join("slashing.sqlite")).as_deref(),
            Some(slash.as_path())
        );
        assert_eq!(fallback_marker_dir(&keys, &keys.join("slashing.sqlite")), None);
        assert_eq!(fallback_marker_dir(&keys, Path::new("slashing.sqlite")), None);
    }

    #[test]
    fn preallocate_writes_a_clear_fixed_record_and_commit_overwrites_it() {
        let dir = tempfile::tempdir().expect("temp");
        preallocate_detection_record(dir.path()).expect("preallocate");
        let path = record_path(dir.path());
        let meta = fs::metadata(&path).expect("meta");
        assert!(meta.is_file());
        assert_eq!(meta.len(), RECORD_LEN as u64);
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Clear));
        assert!(!record_blocks_restart(dir.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            let inode = meta.ino();
            commit_detection_record(dir.path(), 9, 1_700).expect("commit");
            let after = fs::metadata(&path).expect("meta");
            assert_eq!(after.ino(), inode, "detection must overwrite the preallocated file");
            assert_eq!(after.len(), RECORD_LEN as u64);
        }
        #[cfg(not(unix))]
        commit_detection_record(dir.path(), 9, 1_700).expect("commit");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Detected { epoch: 9, unix_secs: 1_700 }
        );
        assert!(record_blocks_restart(dir.path()));
        let bytes = fs::read(&path).expect("bytes");
        assert_eq!(bytes.len(), RECORD_LEN);
        assert!(bytes.iter().skip(80).all(|byte| *byte == 0));
        preallocate_detection_record(dir.path()).expect_err("must not clobber a detected record");
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Detected { .. }));
        assert_eq!(reset_detection_record(dir.path()).expect("reset"), ClearOutcome::Removed);
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Clear));
        assert_eq!(fs::metadata(&path).expect("meta").len(), RECORD_LEN as u64);
    }

    #[test]
    fn preallocate_leaves_a_clear_record_and_rejects_a_short_or_linked_one() {
        let dir = tempfile::tempdir().expect("temp");
        preallocate_detection_record(dir.path()).expect("first");
        preallocate_detection_record(dir.path()).expect("second is a no-op");
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Clear));

        let dir = tempfile::tempdir().expect("temp");
        fs::write(record_path(dir.path()), b"short").expect("short");
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Unreadable { .. }));
        assert!(record_blocks_restart(dir.path()));
        assert!(preallocate_detection_record(dir.path()).is_err());
        assert!(reset_detection_record(dir.path()).is_err());
        assert_eq!(fs::read(record_path(dir.path())).expect("untouched"), b"short");

        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("temp");
            std::os::unix::fs::symlink("missing-target", record_path(dir.path())).expect("link");
            assert!(matches!(inspect_record(dir.path()), RecordInspect::Unreadable { .. }));
            assert!(preallocate_detection_record(dir.path()).is_err());
            assert!(record_path(dir.path())
                .symlink_metadata()
                .expect("lstat")
                .file_type()
                .is_symlink());
        }
    }

    #[test]
    fn injected_marker_failure_does_not_block_the_in_place_record() {
        let dir = tempfile::tempdir().expect("temp");
        preallocate_detection_record(dir.path()).expect("preallocate");
        let _guard = arm_marker_write_failures(u32::MAX);
        let marker = DetectionMarker { epoch: 3, unix_secs: 4, pubkeys: vec![pubkey()] };
        persist_detection(dir.path(), &marker).expect("record is enough");
        assert!(matches!(inspect(dir.path()), MarkerInspect::Absent));
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Detected { .. }));
    }
}
