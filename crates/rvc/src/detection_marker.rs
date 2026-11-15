//! Durable doppelganger detection marker and the pre-allocated record.
//!
//! At boot the process creates a fixed-size `.rvc.doppelganger_record` in the
//! keystore directory and fills it with a `not-detected` header. It writes
//! and fsyncs a temp file first, and a hard link then gives that file the
//! final name, so the final name never holds a partial record. Detection
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
use std::cell::{Cell, RefCell};
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
/// A file that is already a clear record keeps its bytes. The effective user
/// of this process must own it, and its mode must have no group or other
/// bits. This function then fsyncs the record and `data_dir` again, because
/// an earlier boot can stop before its directory fsync. A detected record
/// is not overwritten. Anything else, including a symlink, is an error: this
/// does not unlink and recreate, because that recreation can fail with no
/// space left. The new file is mode `0600`, a regular file, and fsynced
/// before a hard link gives it the final name. The link does not replace a
/// record that another process created in the meantime: this function then
/// reads that record and gives the same result as for a record that was there
/// first. A crash during the create leaves at most a temp file, which
/// [`sweep_stale_record_temps`] removes.
pub fn preallocate_detection_record(data_dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    if take_preallocate_failure() {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected detection-record preallocation failure",
        ));
    }
    if let Some(existing) = existing_record_result(data_dir) {
        return existing;
    }
    let Err(err) = create_clear_record(data_dir) else {
        return Ok(());
    };
    if err.kind() != io::ErrorKind::AlreadyExists {
        return Err(err);
    }
    #[cfg(test)]
    run_record_path_hook(&BEFORE_SECOND_RECORD_READ, data_dir);
    existing_record_result(data_dir).unwrap_or_else(|| {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the detection record was removed while this process created it",
        ))
    })
}

/// The result for the record in `data_dir`, or `None` when there is no
/// record. This does not write the record. A clear record must pass
/// [`reverify_clear_record`].
fn existing_record_result(data_dir: &Path) -> Option<io::Result<()>> {
    match inspect_record(data_dir) {
        RecordInspect::Absent => None,
        RecordInspect::Clear => Some(reverify_clear_record(data_dir)),
        RecordInspect::Detected { .. } => Some(Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "detection record is already in the detected state",
        ))),
        RecordInspect::Unreadable { reason, .. } => {
            Some(Err(io::Error::new(io::ErrorKind::InvalidData, reason)))
        }
    }
}

/// Check the clear record in `data_dir` again, then fsync it and `data_dir`.
///
/// The read-write [`open_record`] refuses a symlink, a file that is not
/// regular, a file that is not [`RECORD_LEN`] bytes, and a file that this
/// process cannot write. The effective user of this process must own the
/// record, and its mode must have no group or other bits. An earlier boot
/// can stop before its directory fsync, so this boot fsyncs the record and
/// its directory again. This does not write the record, because a process
/// that holds the keystore lock can write `detected` into it at that time.
fn reverify_clear_record(data_dir: &Path) -> io::Result<()> {
    let path = record_path(data_dir);
    let file = open_record(&path, false)?;
    #[cfg(unix)]
    check_record_owner_and_mode(&path, &file.metadata()?)?;
    sync_file(&file)?;
    sync_dir(data_dir)
}

/// Refuse a record that another user owns, or whose mode has group or
/// other bits.
#[cfg(unix)]
#[allow(unsafe_code)]
fn check_record_owner_and_mode(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid only reads the effective user ID of this process.
    let euid = unsafe { libc::geteuid() };
    #[cfg(test)]
    let euid = OWNER_UID_OVERRIDE.with(Cell::get).unwrap_or(euid);
    let owner = meta.uid();
    if owner != euid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the owner of the detection record {} is uid {owner}, not uid {euid} of this \
                 process. Change the owner to uid {euid} and set mode 0600",
                path.display()
            ),
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the detection record {} has mode 0o{mode:o}, which gives access to the group or \
                 to other users. Set mode 0600",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Write a clear record to a temp file in `data_dir`, fsync it, and give it
/// the final name with a hard link.
///
/// The link fails with `AlreadyExists` when the final name exists, so this
/// never replaces a record. A failed exclusive open of the temp file removes
/// nothing, because that name can belong to another create. After the open,
/// an error before the link removes the temp file.
fn create_clear_record(data_dir: &Path) -> io::Result<()> {
    let bytes = encode_record(false, 0, 0)?;
    let tmp_path = data_dir.join(format!(
        ".{RECORD_FILENAME}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
    ));
    #[cfg(test)]
    run_record_path_hook(&BEFORE_RECORD_TEMP_OPEN, &tmp_path);
    let mut file = open_record(&tmp_path, true)?;
    let linked = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        write_record_bytes(&mut file, &bytes)?;
        sync_file(&file)?;
        drop(file);
        #[cfg(test)]
        run_before_record_link();
        link_record(&tmp_path, data_dir).map_err(explain_link_error)
    })();
    if let Err(err) = linked {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    fs::remove_file(&tmp_path)?;
    sync_dir(data_dir)
}

/// Give the temp file `tmp_path` the record name in `data_dir` with a hard link.
fn link_record(tmp_path: &Path, data_dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    if let Some(kind) = take_record_link_failure() {
        return Err(io::Error::from(kind));
    }
    fs::hard_link(tmp_path, record_path(data_dir))
}

/// Remove the temp files that a crashed record create left in `data_dir`.
///
/// This removes only a regular file whose name is exactly
/// `.{RECORD_FILENAME}.<digits>.<digits>.tmp`. It does not follow or remove a
/// symlink or a directory with that name. When it removes a file, it fsyncs
/// the directory. Call it only while the keystore lock is held: the temp file
/// of a create in another process is not stale.
///
/// Returns the number of removed files.
pub fn sweep_stale_record_temps(data_dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(data_dir)? {
        let path = entry?.path();
        if is_record_temp_name(&path) && fs::symlink_metadata(&path)?.is_file() {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    if removed > 0 {
        sync_dir(data_dir)?;
    }
    Ok(removed)
}

/// `true` when the file name of `path` is `.{RECORD_FILENAME}.<digits>.<digits>.tmp`.
fn is_record_temp_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    name.strip_prefix(&format!(".{RECORD_FILENAME}."))
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(|middle| middle.split_once('.'))
        .is_some_and(|(pid, nanos)| digits(pid) && digits(nanos))
}

/// Name the missing hard-link support in a link error of that kind.
///
/// A filesystem without hard links fails the link with `PermissionDenied`
/// or `Unsupported`. Other errors do not change.
fn explain_link_error(err: io::Error) -> io::Error {
    match err.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported => io::Error::new(
            err.kind(),
            format!(
                "the keystore filesystem does not support hard links, which the detection \
                 record create needs: {err}"
            ),
        ),
        _ => err,
    }
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
        use std::ops::BitOr;
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(
            [libc::O_NOFOLLOW, libc::O_NONBLOCK, libc::O_CLOEXEC].into_iter().fold(0, BitOr::bitor),
        );
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
    #[cfg(test)]
    if take_record_write_panic() {
        file.write_all(&bytes[..RECORD_WRITE_PANIC_AFTER])?;
        panic!("The test injects a crash after {RECORD_WRITE_PANIC_AFTER} record bytes.");
    }
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
type BeforeRecordLinkHook = Box<dyn FnOnce()>;

#[cfg(test)]
type RecordPathHook = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
type RecordPathHookSlot = std::thread::LocalKey<RefCell<Option<RecordPathHook>>>;

#[cfg(test)]
thread_local! {
    static MARKER_WRITE_FAILS_LEFT: Cell<u32> = const { Cell::new(0) };
    static PREALLOCATE_FAILS: Cell<bool> = const { Cell::new(false) };
    static FSYNC_SKIPS_LEFT: Cell<u32> = const { Cell::new(0) };
    static FSYNC_FAILS_LEFT: Cell<u32> = const { Cell::new(0) };
    static FSYNC_CALLS: Cell<u32> = const { Cell::new(0) };
    static RECORD_WRITE_PANICS: Cell<bool> = const { Cell::new(false) };
    static BEFORE_RECORD_LINK: RefCell<Option<BeforeRecordLinkHook>> = const { RefCell::new(None) };
    static BEFORE_RECORD_TEMP_OPEN: RefCell<Option<RecordPathHook>> = const { RefCell::new(None) };
    static BEFORE_SECOND_RECORD_READ: RefCell<Option<RecordPathHook>> =
        const { RefCell::new(None) };
    static RECORD_LINK_FAILURE: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
    static OWNER_UID_OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Make the owner check compare the file owner with `uid` on this thread.
/// The check must use `uid` instead of the effective user ID.
///
/// The guard removes the override when it drops.
#[cfg(test)]
pub(crate) fn arm_owner_uid_override(uid: u32) -> OwnerUidGuard {
    OWNER_UID_OVERRIDE.with(|slot| slot.set(Some(uid)));
    OwnerUidGuard
}

/// Run `hook` one time on this thread, before the exclusive open of the temp
/// file. The hook gets the temp path.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_before_record_temp_open(
    hook: impl FnOnce(&Path) + 'static,
) -> RecordPathHookGuard {
    arm_record_path_hook(&BEFORE_RECORD_TEMP_OPEN, hook)
}

/// Run `hook` one time on this thread, after the create fails with
/// `AlreadyExists` and before the second record read. The hook gets the
/// keystore directory.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_before_second_record_read(
    hook: impl FnOnce(&Path) + 'static,
) -> RecordPathHookGuard {
    arm_record_path_hook(&BEFORE_SECOND_RECORD_READ, hook)
}

#[cfg(test)]
fn arm_record_path_hook(
    slot: &'static RecordPathHookSlot,
    hook: impl FnOnce(&Path) + 'static,
) -> RecordPathHookGuard {
    slot.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    RecordPathHookGuard(slot)
}

#[cfg(test)]
fn run_record_path_hook(slot: &'static RecordPathHookSlot, path: &Path) {
    let hook = slot.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

/// Make the next record link on this thread fail with `kind`. The link does
/// not run.
///
/// The guard clears the injection when it drops.
#[cfg(test)]
pub(crate) fn arm_record_link_failure(kind: io::ErrorKind) -> RecordLinkFailGuard {
    RECORD_LINK_FAILURE.with(|failure| failure.set(Some(kind)));
    RecordLinkFailGuard
}

#[cfg(test)]
fn take_record_link_failure() -> Option<io::ErrorKind> {
    RECORD_LINK_FAILURE.with(Cell::take)
}

/// The injected record-write panic occurs after this number of bytes.
#[cfg(test)]
const RECORD_WRITE_PANIC_AFTER: usize = 64;

/// Make the next record write on this thread panic after
/// [`RECORD_WRITE_PANIC_AFTER`] bytes.
///
/// The panic skips all cleanup paths, as a crash does. The guard clears the
/// injection when it drops.
#[cfg(test)]
pub(crate) fn arm_record_write_panic() -> RecordWritePanicGuard {
    RECORD_WRITE_PANICS.with(|armed| armed.set(true));
    RecordWritePanicGuard
}

/// Run `hook` one time on this thread. Run it after the fsync of the new
/// record and before the record gets its final name.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_before_record_link(hook: impl FnOnce() + 'static) -> BeforeRecordLinkGuard {
    BEFORE_RECORD_LINK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    BeforeRecordLinkGuard
}

#[cfg(test)]
fn take_record_write_panic() -> bool {
    RECORD_WRITE_PANICS.with(|armed| armed.replace(false))
}

#[cfg(test)]
fn run_before_record_link() {
    let hook = BEFORE_RECORD_LINK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
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
    arm_fsync_failures_after(0, count)
}

/// Let the next `skip` fsyncs on this thread pass, then fail the next `fail`.
///
/// If `fail == u32::MAX`, the injector fails all fsync calls after the skipped
/// calls. The guard stops these failures when it drops.
#[cfg(test)]
pub(crate) fn arm_fsync_failures_after(skip: u32, fail: u32) -> FsyncFailGuard {
    FSYNC_SKIPS_LEFT.with(|left| left.set(skip));
    FSYNC_FAILS_LEFT.with(|left| left.set(fail));
    FsyncFailGuard
}

/// The function returns this thread's fsync call count. The count includes
/// calls that return an injected error.
#[cfg(test)]
pub(crate) fn fsync_calls() -> u32 {
    FSYNC_CALLS.with(Cell::get)
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
    let skipped = FSYNC_SKIPS_LEFT.with(|left| {
        let remaining = left.get();
        left.set(remaining.saturating_sub(1));
        remaining > 0
    });
    if skipped {
        return false;
    }
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
        FSYNC_SKIPS_LEFT.with(|left| left.set(0));
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

/// The guard clears the injected record-write panic when it drops.
#[cfg(test)]
pub(crate) struct RecordWritePanicGuard;

#[cfg(test)]
impl Drop for RecordWritePanicGuard {
    fn drop(&mut self) {
        RECORD_WRITE_PANICS.with(|armed| armed.set(false));
    }
}

/// The guard removes an unused before-link hook when it drops.
#[cfg(test)]
pub(crate) struct BeforeRecordLinkGuard;

#[cfg(test)]
impl Drop for BeforeRecordLinkGuard {
    fn drop(&mut self) {
        BEFORE_RECORD_LINK.with(|slot| *slot.borrow_mut() = None);
    }
}

/// The guard removes its unused record-path hook when it drops.
#[cfg(test)]
pub(crate) struct RecordPathHookGuard(&'static RecordPathHookSlot);

#[cfg(test)]
impl Drop for RecordPathHookGuard {
    fn drop(&mut self) {
        self.0.with(|slot| *slot.borrow_mut() = None);
    }
}

/// The guard clears the injected record-link failure when it drops.
#[cfg(test)]
pub(crate) struct RecordLinkFailGuard;

#[cfg(test)]
impl Drop for RecordLinkFailGuard {
    fn drop(&mut self) {
        RECORD_LINK_FAILURE.with(|failure| failure.set(None));
    }
}

/// The guard removes the owner uid override when it drops.
#[cfg(test)]
pub(crate) struct OwnerUidGuard;

#[cfg(test)]
impl Drop for OwnerUidGuard {
    fn drop(&mut self) {
        OWNER_UID_OVERRIDE.with(|slot| slot.set(None));
    }
}

fn sync_file(file: &File) -> io::Result<()> {
    #[cfg(test)]
    FSYNC_CALLS.with(|calls| calls.set(calls.get() + 1));
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
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Absent | RecordInspect::Clear));
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
        assert!(!matches!(
            inspect_record(dir.path()),
            RecordInspect::Absent | RecordInspect::Clear
        ));
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
        assert!(!matches!(
            inspect_record(dir.path()),
            RecordInspect::Absent | RecordInspect::Clear
        ));
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

    /// Return `header` followed by zero bytes, to a total of `len` bytes.
    fn padded_record(header: &[u8], len: usize) -> Vec<u8> {
        let mut bytes = header.to_vec();
        bytes.resize(len, 0);
        bytes
    }

    /// Each malformed record is `Unreadable`. The two valid headers are
    /// `Clear` and `Detected`, so each row tests the parser.
    #[test]
    fn parse_record_rejects_malformed_headers() {
        const CLEAR: &[u8] = b"version=1\nstate=not-detected\nepoch=0\nunix_secs=0\n";
        const DETECTED: &[u8] = b"version=1\nstate=detected\nepoch=9\nunix_secs=1700\n";
        let mut tail = padded_record(CLEAR, RECORD_LEN);
        tail[4000] = b'x';
        // The tear is at the middle of the header. The state line becomes
        // `state=detectedcted`.
        let half = DETECTED.len() / 2;
        let torn = [&DETECTED[..half], &CLEAR[half..]].concat();
        let malformed = [
            ("4096 zero bytes", vec![0; RECORD_LEN]),
            ("0 bytes", Vec::new()),
            ("4097 bytes", padded_record(CLEAR, RECORD_LEN + 1)),
            ("a non-zero byte at offset 4000", tail),
            (
                "version=2",
                padded_record(b"version=2\nstate=not-detected\nepoch=0\nunix_secs=0\n", RECORD_LEN),
            ),
            (
                "state=maybe",
                padded_record(b"version=1\nstate=maybe\nepoch=0\nunix_secs=0\n", RECORD_LEN),
            ),
            (
                "no unix_secs line",
                padded_record(b"version=1\nstate=not-detected\nepoch=0\n", RECORD_LEN),
            ),
            (
                "an extra line",
                padded_record(
                    b"version=1\nstate=not-detected\nepoch=0\nunix_secs=0\nextra=1\n",
                    RECORD_LEN,
                ),
            ),
            (
                "epoch=18446744073709551616",
                padded_record(
                    b"version=1\nstate=not-detected\nepoch=18446744073709551616\nunix_secs=0\n",
                    RECORD_LEN,
                ),
            ),
            (
                "epoch=+5",
                padded_record(
                    b"version=1\nstate=not-detected\nepoch=+5\nunix_secs=0\n",
                    RECORD_LEN,
                ),
            ),
            ("a torn header", padded_record(&torn, RECORD_LEN)),
        ];
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let write = |bytes: Vec<u8>| {
            fs::write(record_path(dir.path()), bytes)
                .expect("The test must write the record file.");
        };
        for (case, bytes) in malformed {
            write(bytes);
            let inspected = inspect_record(dir.path());
            assert!(
                matches!(inspected, RecordInspect::Unreadable { .. }),
                "The record with {case} must be Unreadable. The result is {inspected:?}."
            );
        }
        write(padded_record(CLEAR, RECORD_LEN));
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "A valid not-detected header must be Clear."
        );
        write(padded_record(DETECTED, RECORD_LEN));
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Detected { epoch: 9, unix_secs: 1700 },
            "A valid detected header must be Detected."
        );
    }

    /// No record exists, so `persist_detection` writes only the marker. The
    /// temp-file fsync passes and the directory fsync after the rename fails.
    #[test]
    fn dir_fsync_failure_after_rename_is_not_durable() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "The directory must not contain a record."
        );
        let marker = DetectionMarker { epoch: 5, unix_secs: 6, pubkeys: vec![pubkey()] };
        let before = fsync_calls();
        let guard = arm_fsync_failures_after(1, 1);
        let result = persist_detection(dir.path(), &marker);
        drop(guard);
        assert!(
            result.is_err(),
            "persist_detection must return Err when the directory fsync fails."
        );
        assert_eq!(
            fsync_calls() - before,
            2,
            "The marker write must fsync the temp file and then the directory."
        );
        assert!(
            matches!(inspect(dir.path()), MarkerInspect::Present(_)),
            "The marker must be at its final path before the directory fsync fails."
        );
    }

    /// Return the sorted names in `dir`, without the record name.
    fn names_other_than_the_record(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("The test must read the directory.")
            .map(|entry| {
                let entry = entry.expect("The test must read a directory entry.");
                entry.file_name().to_string_lossy().into_owned()
            })
            .filter(|name| name != RECORD_FILENAME)
            .collect();
        names.sort();
        names
    }

    /// Return the boot error for the keystore `dir` with detection off.
    ///
    /// The config is the config that `bootstrap::run::tests::boot_with_keystore`
    /// builds.
    async fn boot_with_detection_off(dir: &Path) -> crate::bootstrap::BootstrapError {
        let config = crate::config::Config {
            keystore_path: dir.to_path_buf(),
            doppelganger_detection: false,
            ..Default::default()
        };
        let (executor, rx) =
            crate::bootstrap::TaskExecutor::new(tokio_util::sync::CancellationToken::new());
        let options = crate::bootstrap::RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: bn_manager::OperationTimeouts::default(),
        };
        crate::bootstrap::run(config, options, executor, rx)
            .await
            .expect_err("The boot must stop, because the test has no slashing database.")
    }

    /// The first record write panics after 64 bytes, as a crash in the first
    /// boot does. The test requires these results:
    ///
    /// - No record is at the final name after the panic.
    /// - A boot with detection off does not exit 12.
    /// - The next `preallocate_detection_record` call makes a `Clear` record.
    /// - The sweep removes the temp file of the crash and no other file.
    #[tokio::test(flavor = "current_thread")]
    async fn crash_during_create_leaves_no_record_at_the_final_name() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let guard = arm_record_write_panic();
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            preallocate_detection_record(dir.path())
        }));
        drop(guard);
        assert!(crashed.is_err(), "The injected panic must stop preallocate_detection_record.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "The crash must not leave a record at the final name."
        );
        let err = boot_with_detection_off(dir.path()).await;
        assert_ne!(
            err.exit_code(),
            crate::startup::EXIT_DOPPELGANGER_DETECTED,
            "The boot after the crash must not exit 12. The error is: {err}"
        );
        let result = preallocate_detection_record(dir.path());
        assert!(
            result.is_ok(),
            "preallocate_detection_record after the crash must succeed. The result is {result:?}."
        );
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "preallocate_detection_record after the crash must make a Clear record."
        );
        let swept = sweep_stale_record_temps(dir.path());
        assert!(
            matches!(swept, Ok(1)),
            "The sweep must remove the temp file of the crash. The result is {swept:?}."
        );
        assert_eq!(
            names_other_than_the_record(dir.path()),
            Vec::<String>::new(),
            "Only the record must stay in the directory after the sweep."
        );
    }

    /// A hook writes a full record at the final name after the fsync of the
    /// new record and before the link. The hook sets mode `0o600` on that
    /// record, because the boot refuses a reused record with group or other
    /// mode bits. Each row requires these results:
    ///
    /// - The hook runs.
    /// - `preallocate_detection_record` returns the error kind of the row, or `Ok`.
    /// - The record keeps the state that the hook wrote.
    /// - No temp file stays in the directory.
    #[test]
    fn create_does_not_replace_a_record_that_appeared() {
        let rows = [
            (
                "detected",
                encode_record(true, 77, 1_234),
                RecordInspect::Detected { epoch: 77, unix_secs: 1_234 },
                Some(io::ErrorKind::AlreadyExists),
            ),
            ("not-detected", encode_record(false, 0, 0), RecordInspect::Clear, None),
        ];
        for (state, bytes, record, error) in rows {
            let bytes = bytes.expect("The test must encode the record.");
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let final_path = record_path(dir.path());
            let ran = std::rc::Rc::new(Cell::new(false));
            let hook_ran = std::rc::Rc::clone(&ran);
            let guard = arm_before_record_link(move || {
                fs::write(&final_path, bytes).expect("The hook must write the record.");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600))
                        .expect("The hook must set mode 0o600 on the record.");
                }
                hook_ran.set(true);
            });
            let result = preallocate_detection_record(dir.path());
            drop(guard);
            assert!(ran.get(), "The hook must run before the link in the {state} row.");
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                error,
                "In the {state} row, the error kind of preallocate_detection_record must be \
                 {error:?}. The result is {result:?}."
            );
            assert_eq!(
                inspect_record(dir.path()),
                record,
                "The {state} record from the hook must stay at the final name."
            );
            assert_eq!(
                names_other_than_the_record(dir.path()),
                Vec::<String>::new(),
                "No temp file must stay in the directory after the {state} row."
            );
        }
    }

    /// The directory holds a record and six names that have the temp-file
    /// shape or a shape near it. The test requires these results:
    ///
    /// - The sweep removes only the regular file `.{RECORD_FILENAME}.1.2.tmp`.
    /// - The sweep does not remove or follow a symlink with the temp-file shape.
    /// - The sweep does not remove a directory with the temp-file shape.
    /// - The sweep does not remove the three operator files. One of them has
    ///   a PID part that is not digits.
    /// - The record stays `Clear`.
    /// - The sweep fsyncs the directory one time after a removal, and not when
    ///   it removes no file.
    #[cfg(unix)]
    #[test]
    fn sweep_removes_only_stale_record_temps() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must preallocate the record.");
        let name = |middle: &str| format!(".{RECORD_FILENAME}.{middle}.tmp");
        let path = |middle: &str| dir.path().join(name(middle));
        let target = dir.path().join("link-target");
        fs::write(path("1.2"), b"partial").expect("The test must write the stale temp file.");
        fs::write(&target, b"operator data").expect("The test must write the link target.");
        std::os::unix::fs::symlink(&target, path("3.4")).expect("The test must make the symlink.");
        fs::create_dir(path("5.6")).expect("The test must make the directory.");
        fs::write(path("x"), b"operator file").expect("The test must write an operator file.");
        fs::write(path("1.x"), b"operator file").expect("The test must write an operator file.");
        fs::write(path("x.1"), b"operator file").expect("The test must write an operator file.");

        let before = fsync_calls();
        let removed = sweep_stale_record_temps(dir.path());
        let fsyncs = fsync_calls() - before;
        assert!(
            matches!(removed, Ok(1)),
            "The sweep must remove one file. The result is {removed:?}."
        );
        assert_eq!(fsyncs, 1, "The sweep must fsync the directory one time after the removal.");
        let mut kept = vec![
            name("1.x"),
            name("3.4"),
            name("5.6"),
            name("x"),
            name("x.1"),
            "link-target".into(),
        ];
        kept.sort();
        assert_eq!(
            names_other_than_the_record(dir.path()),
            kept,
            "The sweep must remove only the stale regular temp file."
        );
        assert!(
            fs::symlink_metadata(path("3.4"))
                .expect("The test must read the symlink metadata.")
                .file_type()
                .is_symlink(),
            "The symlink with the temp-file shape must stay a symlink."
        );
        assert_eq!(
            fs::read(&target).expect("The test must read the link target."),
            b"operator data",
            "The sweep must not change the file that the symlink points to."
        );
        assert!(path("5.6").is_dir(), "The directory with the temp-file shape must stay.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "The sweep must not change the record."
        );

        let before = fsync_calls();
        let again = sweep_stale_record_temps(dir.path());
        assert!(
            matches!(again, Ok(0)),
            "The second sweep must remove no file. The result is {again:?}."
        );
        assert_eq!(
            fsync_calls() - before,
            0,
            "A sweep that removes no file must not fsync the directory."
        );
    }

    /// Return the argument text of each `custom_flags(` call in `src` that
    /// does not contain `O_NONBLOCK`, and the number of calls. The argument
    /// text of a call ends at the next `;`.
    fn custom_flags_without_nonblock(src: &str) -> (usize, Vec<&str>) {
        let calls: Vec<&str> = src
            .split("custom_flags(")
            .skip(1)
            .map(|rest| rest.split(';').next().unwrap_or(rest))
            .collect();
        let missing = calls.iter().copied().filter(|call| !call.contains("O_NONBLOCK")).collect();
        (calls.len(), missing)
    }

    /// Every `custom_flags(` call in the production part of this file must
    /// set `O_NONBLOCK`. The production part ends at `mod tests`. The fixture
    /// makes sure that the scan finds a call without the flag.
    #[test]
    fn record_opens_are_non_blocking() {
        let fixture = "opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);\n\
                       opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);\n";
        assert_eq!(
            custom_flags_without_nonblock(fixture),
            (2, vec!["libc::O_NOFOLLOW | libc::O_CLOEXEC)"]),
            "The scan must find the two fixture calls and report the call without O_NONBLOCK."
        );

        let src = include_str!("detection_marker.rs");
        let (production, _) =
            src.split_once("\nmod tests {").expect("detection_marker.rs must have a tests module.");
        let (calls, missing) = custom_flags_without_nonblock(production);
        assert!(calls > 0, "The production code must call custom_flags.");
        assert!(
            missing.is_empty(),
            "Every record open must set O_NONBLOCK. The calls without it are {missing:?}."
        );
    }

    /// The fsync of the new record fails. The test requires these results:
    ///
    /// - `preallocate_detection_record` returns an error.
    /// - No record is at the final name.
    /// - No temp file stays in the directory.
    #[test]
    fn temp_file_fsync_failure_publishes_no_record() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let guard = arm_fsync_failures(1);
        let result = preallocate_detection_record(dir.path());
        drop(guard);
        assert!(
            result.is_err(),
            "preallocate_detection_record must fail when the record fsync fails."
        );
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "A record whose fsync failed must not get the final name."
        );
        assert_eq!(
            names_other_than_the_record(dir.path()),
            Vec::<String>::new(),
            "The failed create must remove its temp file."
        );
    }

    /// The test checks link errors. It requires these results:
    ///
    /// - The message names the missing hard-link support for
    ///   `PermissionDenied` and `Unsupported`.
    /// - The error kind does not change.
    /// - Other link errors keep their messages.
    #[test]
    fn link_error_names_the_missing_hard_link_support() {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Unsupported] {
            let err = explain_link_error(io::Error::from(kind));
            assert_eq!(err.kind(), kind, "The error kind {kind:?} must not change.");
            assert!(
                err.to_string().contains("does not support hard links"),
                "The {kind:?} error must name the missing hard-link support. The error is: {err}"
            );
        }
        let err = explain_link_error(io::Error::from(io::ErrorKind::AlreadyExists));
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "The AlreadyExists error kind must not change."
        );
        assert!(
            !err.to_string().contains("hard links"),
            "An AlreadyExists error must not name the hard-link support. The error is: {err}"
        );
    }

    /// Another create owns a file at the temp name of this create. The test
    /// requires these results:
    ///
    /// - `preallocate_detection_record` returns `NotFound`, because no record
    ///   exists.
    /// - The file at the temp name keeps its bytes.
    /// - No record is at the final name.
    #[test]
    fn failed_temp_open_keeps_the_file_of_another_create() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let temp = std::rc::Rc::new(RefCell::new(None));
        let hook_temp = std::rc::Rc::clone(&temp);
        let guard = arm_before_record_temp_open(move |tmp_path| {
            fs::write(tmp_path, b"other create").expect("The hook must write the other file.");
            *hook_temp.borrow_mut() = Some(tmp_path.to_path_buf());
        });
        let result = preallocate_detection_record(dir.path());
        drop(guard);
        let temp = temp.borrow_mut().take().expect("The hook must run before the temp open.");
        assert_eq!(
            result.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::NotFound),
            "The collision at the temp name must give NotFound. The result is {result:?}."
        );
        assert_eq!(
            fs::read(&temp).ok(),
            Some(b"other create".to_vec()),
            "The failed temp open must not remove or change the file of the other create."
        );
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "The failed temp open must not put a record at the final name."
        );
    }

    /// The link fails with `AlreadyExists`, because a hook writes a file at
    /// the final name. Each row requires these results:
    ///
    /// - `preallocate_detection_record` returns the error kind of the row.
    /// - The final name keeps the bytes of the row, or it stays absent.
    /// - No temp file stays in the directory.
    ///
    /// In the `removed` row, a second hook removes the record before the
    /// second read.
    #[test]
    fn collision_rejects_an_unreadable_or_absent_record() {
        let detected = encode_record(true, 5, 6).expect("The test must encode the record.");
        let rows = [
            (
                "short",
                b"short".to_vec(),
                false,
                io::ErrorKind::InvalidData,
                Some(b"short".to_vec()),
            ),
            ("removed", detected.to_vec(), true, io::ErrorKind::NotFound, None),
        ];
        for (case, bytes, remove, kind, kept) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let final_path = record_path(dir.path());
            let link_guard = arm_before_record_link(move || {
                fs::write(&final_path, bytes).expect("The hook must write the record.");
            });
            let read_guard = remove.then(|| {
                arm_before_second_record_read(|data_dir| {
                    fs::remove_file(record_path(data_dir))
                        .expect("The hook must remove the record.");
                })
            });
            let result = preallocate_detection_record(dir.path());
            drop(read_guard);
            drop(link_guard);
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                Some(kind),
                "In the {case} row, the error kind of preallocate_detection_record must be \
                 {kind:?}. The result is {result:?}."
            );
            assert_eq!(
                fs::read(record_path(dir.path())).ok(),
                kept,
                "In the {case} row, the create must not change the final name."
            );
            assert_eq!(
                names_other_than_the_record(dir.path()),
                Vec::<String>::new(),
                "In the {case} row, no temp file must stay in the directory."
            );
        }
    }

    /// The fsync of the new record passes, and the directory fsync after the
    /// link fails. The test requires these results:
    ///
    /// - `preallocate_detection_record` returns an error.
    /// - The create calls fsync two times.
    /// - The complete `Clear` record is at the final name.
    /// - No temp file stays in the directory.
    #[test]
    fn directory_fsync_failure_after_the_link_returns_an_error() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "The directory must not contain a record at the start."
        );
        let before = fsync_calls();
        let guard = arm_fsync_failures_after(1, 1);
        let result = preallocate_detection_record(dir.path());
        drop(guard);
        let fsyncs = fsync_calls() - before;
        assert!(
            result.is_err(),
            "preallocate_detection_record must fail when the directory fsync fails. The result \
             is {result:?}."
        );
        assert_eq!(fsyncs, 2, "The create must fsync the temp file and then the directory.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "The complete record must stay at the final name."
        );
        assert_eq!(
            names_other_than_the_record(dir.path()),
            Vec::<String>::new(),
            "The create must remove the temp name before the directory fsync."
        );
    }

    /// The guard sets the umask of this process. It sets the previous umask
    /// again when it drops.
    #[cfg(unix)]
    struct UmaskGuard(libc::mode_t);

    #[cfg(unix)]
    impl UmaskGuard {
        #[allow(unsafe_code)]
        fn set(mask: libc::mode_t) -> Self {
            // SAFETY: umask only changes the file-mode creation mask of this process.
            Self(unsafe { libc::umask(mask) })
        }
    }

    #[cfg(unix)]
    impl Drop for UmaskGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: umask only changes the file-mode creation mask of this process.
            unsafe { libc::umask(self.0) };
        }
    }

    /// The umask `0o200` removes the owner write bit from a new file. The
    /// test makes the directory before it sets that umask, and it requires
    /// mode `0o600` on the new record.
    ///
    /// The umask is a value of the process. nextest runs each test in a
    /// different process.
    #[cfg(unix)]
    #[test]
    fn create_sets_mode_0600_under_a_restrictive_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let umask = UmaskGuard::set(0o200);
        let result = preallocate_detection_record(dir.path());
        drop(umask);
        assert!(
            result.is_ok(),
            "preallocate_detection_record must succeed under the umask 0o200. The result is \
             {result:?}."
        );
        let mode = fs::metadata(record_path(dir.path()))
            .expect("The test must read the record metadata.")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "The new record must have mode 0o600 under the umask 0o200. The mode is 0o{mode:o}."
        );
    }

    /// Return the file status flags of `file` from `fcntl(F_GETFL)`.
    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn status_flags(file: &File) -> libc::c_int {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` keeps the descriptor open, and F_GETFL only reads its flags.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(
            flags >= 0,
            "fcntl(F_GETFL) must succeed. The error is: {}",
            io::Error::last_os_error()
        );
        flags
    }

    /// `open_record` opens a new temp file, the record, and names that exist
    /// already. The test requires these results:
    ///
    /// - Each open descriptor has the `O_NONBLOCK` status flag.
    /// - The create mode returns `AlreadyExists` for the record, a hard link
    ///   to it, and a symlink to it.
    /// - The open of the record does not follow a leaf symlink.
    /// - The bytes of the record do not change.
    #[cfg(unix)]
    #[test]
    fn record_opens_are_nonblocking_and_refuse_existing_names() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let record = record_path(dir.path());
        let hard_link = dir.path().join("hard-link");
        let symlink = dir.path().join("symlink");
        preallocate_detection_record(dir.path()).expect("The test must preallocate the record.");
        let created = open_record(&dir.path().join("new-temp"), true)
            .expect("The test must create a temp file.");
        let existing = open_record(&record, false).expect("The test must open the record.");
        for (case, file) in [("new temp file", &created), ("record", &existing)] {
            assert_ne!(
                status_flags(file) & libc::O_NONBLOCK,
                0,
                "The descriptor of the {case} must have O_NONBLOCK."
            );
        }
        let bytes = fs::read(&record).expect("The test must read the record.");
        fs::hard_link(&record, &hard_link).expect("The test must make the hard link.");
        std::os::unix::fs::symlink(&record, &symlink).expect("The test must make the symlink.");
        for (case, path) in [("record", &record), ("hard link", &hard_link), ("symlink", &symlink)]
        {
            let result = open_record(path, true);
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                Some(io::ErrorKind::AlreadyExists),
                "The create mode must return AlreadyExists for the {case}. The result is \
                 {result:?}."
            );
        }
        let result = open_record(&symlink, false);
        assert_eq!(
            result.as_ref().err().and_then(io::Error::raw_os_error),
            Some(libc::ELOOP),
            "The open of the record must not follow a leaf symlink. The result is {result:?}."
        );
        assert_eq!(
            fs::read(&record).ok(),
            Some(bytes),
            "The record opens must not change the bytes of the record."
        );
    }

    /// The first call is the record step of a boot. The temp-file fsync
    /// passes, and the directory fsync after the link fails. The second call
    /// is the record step of the next boot. The test requires these results:
    ///
    /// - The first call returns an error, and the `Clear` record is at the
    ///   final name.
    /// - The second call returns `Ok`.
    /// - The second call fsyncs the record and the directory.
    #[test]
    fn failed_dir_fsync_after_create_is_resynced_on_the_next_boot() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let guard = arm_fsync_failures_after(1, 1);
        let first = preallocate_detection_record(dir.path());
        drop(guard);
        assert!(
            first.is_err(),
            "The first call must fail when the directory fsync fails. The result is {first:?}."
        );
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "The first call must leave the Clear record at the final name."
        );
        let before = fsync_calls();
        let second = preallocate_detection_record(dir.path());
        let fsyncs = fsync_calls() - before;
        assert!(second.is_ok(), "The next boot must accept the record. The result is {second:?}.");
        assert!(
            fsyncs >= 2,
            "The next boot must fsync the record and the directory. The fsync count is {fsyncs}."
        );
    }

    /// The record is `Clear`, and the owner check expects a uid that is not
    /// the uid of the record owner. The test requires these results:
    ///
    /// - `preallocate_detection_record` returns `InvalidData`.
    /// - The error names the uid of the record owner.
    #[cfg(unix)]
    #[test]
    fn reused_clear_record_owned_by_another_uid_is_rejected() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must preallocate the record.");
        let uid = fs::metadata(record_path(dir.path()))
            .expect("The test must read the record metadata.")
            .uid();
        let guard = arm_owner_uid_override(uid + 1);
        let result = preallocate_detection_record(dir.path());
        drop(guard);
        assert_eq!(
            result.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::InvalidData),
            "A record of another uid must give InvalidData. The result is {result:?}."
        );
        let text = result.err().map(|err| err.to_string()).unwrap_or_default();
        assert!(
            text.contains(&format!("uid {uid}")),
            "The error must name the uid {uid} of the record owner. The error is: {text}"
        );
    }

    /// The record is a `not-detected` header with `epoch=7` and
    /// `unix_secs=9`. It has mode `0o600`, and the test user owns it. The
    /// test requires these results:
    ///
    /// - `preallocate_detection_record` returns `Ok`.
    /// - The bytes of the record do not change.
    /// - The inode of the record does not change.
    #[cfg(unix)]
    #[test]
    fn reused_clear_record_with_mode_0600_is_accepted_and_unchanged() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let path = record_path(dir.path());
        let bytes =
            padded_record(b"version=1\nstate=not-detected\nepoch=7\nunix_secs=9\n", RECORD_LEN);
        fs::write(&path, &bytes).expect("The test must write the record.");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("The test must set mode 0o600 on the record.");
        let inode = fs::metadata(&path).expect("The test must read the record metadata.").ino();
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Clear,
            "The test record must be a Clear record."
        );
        let result = preallocate_detection_record(dir.path());
        assert!(
            result.is_ok(),
            "The check must accept a Clear record with mode 0o600. The result is {result:?}."
        );
        assert_eq!(
            fs::read(&path).ok(),
            Some(bytes),
            "The check must not change the bytes of the record."
        );
        assert_eq!(
            fs::metadata(&path).ok().map(|meta| meta.ino()),
            Some(inode),
            "The check must not replace the record file."
        );
    }
}
