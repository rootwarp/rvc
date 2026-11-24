//! Durable doppelganger detection marker and the pre-allocated record.
//!
//! At boot the process creates a fixed-size `.rvc.doppelganger_record` in the
//! keystore directory and fills it with a `not-detected` header. It writes
//! and fsyncs a temp file first, and a hard link then gives that file the
//! final name, so the final name never holds a partial record. Detection
//! overwrites that file in place (`pwrite`, then `fsync`). An in-place
//! overwrite does not allocate a new directory entry. On copy-on-write or
//! thin storage (btrfs, ZFS, thin LVM) it can still allocate a new block.
//! The keystore marker and, when that directory is different, a marker beside
//! the slashing database are additional paths. The marker beside the database
//! is named after the database file and records the keystore directory, so
//! two instances that share a database directory do not share it. Its writes
//! and clears hold one lock and use one directory handle, which a walk that
//! follows no symlink opens. The selection of that directory uses the same
//! walk, and boot reads the marker unless the two handles show that the
//! database directory is the keystore directory. Boot refuses a second name
//! of a database (a symlink, a hard link or a `..`), so it has one marker
//! name. A write is durable only after its `fsync` returns `Ok`, and a
//! rename also needs the directory `fsync`. A later read is not a
//! substitute. Exit 12 follows that
//! acknowledgement. A `SIGKILL` before the first of them is durable loses
//! the latch. The next start refuses to run while a marker is present or the
//! record is `detected`, including when a file cannot be read, is a symlink,
//! or is not valid. Clearing it is `rvc doppelganger clear-detection
//! --datadir … --slashing-db-path … --confirm`, which also forces a full
//! forward window on the next boot. Deleting only the keystore marker by
//! hand does not force that window and does not clear a detected record.
//! `clear-detection` resets a detected record in place. It replaces a record
//! that does not parse when that record is a regular file: it writes a clear
//! record to a temp file and exchanges the temp file with the old record in
//! one atomic step. It does not replace a record that it cannot read or a
//! record that changed after its read. A symlink, directory or FIFO at that
//! path still needs `rm`: stop the process, remove
//! `.rvc.doppelganger_record`, and run `clear-detection` again. Do not
//! remove a valid `detected` record by hand; that skips the force-window
//! file.

#[cfg(any(test, feature = "test-utils"))]
use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use doppelganger::marker_file::MarkerFile;
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
    /// Keystore directory that owns a fallback marker. The keystore marker
    /// and a version-1 document without the field have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keystore_dir: Option<String>,
}

/// `Removed` when a marker file was unlinked. `Absent` when there was none.
/// `Replaced` when [`reset_or_replace_detection_record`] replaced a record
/// that does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    Removed,
    Replaced,
    Absent,
}

/// Path of the marker in `data_dir`.
pub fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MARKER_FILENAME)
}

/// The directory of the fallback marker of `slashing_db_path`: the parent of
/// the database, or `.` for a bare file name. `None` when that directory is
/// `keystore_dir`.
///
/// The selection opens the two directories with the walk that the read, the
/// write and the clear use (no path resolution, no symlink, no `..`). Then it
/// compares the device and inode numbers that `fstat` gives for the two
/// handles. It does not compare paths. When a walk or an `fstat` fails, the
/// selection cannot show that the two are one directory. It then gives the
/// directory, so the caller reads the fallback and fails closed. The fallback
/// marker in this directory has the name that [`fallback_marker_name`]
/// gives. The keystore directory is not a second disk, so for it the caller
/// keeps retrying the keystore write instead.
pub fn fallback_marker_dir(keystore_dir: &Path, slashing_db_path: &Path) -> Option<PathBuf> {
    let dir = match slashing_db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if same_dir(dir, keystore_dir) {
        None
    } else {
        Some(dir.to_path_buf())
    }
}

/// `true` only when the walk opens `left` and `right` and `fstat` gives the
/// same device and inode numbers for the two handles. An error gives `false`.
fn same_dir(left: &Path, right: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let id = |dir: &Path| -> io::Result<(u64, u64)> {
            let meta = MarkerDir::open(dir)?.file.metadata()?;
            Ok((meta.dev(), meta.ino()))
        };
        match (id(left), id(right)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

/// File name of the lock that serializes the writes and the clears of the
/// fallback markers in one database directory. The file stays after the
/// lock ends.
pub const FALLBACK_LOCK_FILENAME: &str = ".rvc.doppelganger_lock";

/// A slashing database file name that starts with one of these prefixes is
/// refused. rvc uses the names in this name space for its detection files.
const RESERVED_NAME_PREFIXES: [&str; 2] = [".rvc.doppelganger", "..rvc.doppelganger"];

/// The longest file name on Linux file systems such as ext4, XFS and btrfs.
const MAX_NAME_BYTES: usize = 255;

/// Refuse a slashing database name that rvc cannot protect: a file name in
/// the name space of the detection files and, when the database directory
/// gets a fallback marker, a name that does not give one clear marker name.
/// That is a marker name of more than 255 bytes, a database directory that
/// the walk with no symlink cannot open (a missing directory, or a symlink
/// or a `..` in its path), and a database file that is a symlink, is not a
/// regular file or has more than one link. Boot calls this before SQLite
/// opens the database.
pub fn check_slashing_db_name(keystore_dir: &Path, slashing_db_path: &Path) -> io::Result<()> {
    let name = slashing_db_path.file_name().unwrap_or_default().as_encoded_bytes();
    if RESERVED_NAME_PREFIXES.iter().any(|prefix| name.starts_with(prefix.as_bytes())) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the file name of the slashing database {} is in the name space of the rvc \
                 detection files ({}). Use a different file name",
                slashing_db_path.display(),
                RESERVED_NAME_PREFIXES[0]
            ),
        ));
    }
    let Some(fallback) = FallbackMarkerPath::for_config(keystore_dir, slashing_db_path) else {
        return Ok(());
    };
    let len = fallback_marker_name(slashing_db_path).len();
    if len > MAX_NAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the fallback detection marker name for the slashing database {} has {len} \
                 bytes, but a file name can have at most {MAX_NAME_BYTES} bytes. Use a shorter \
                 database file name",
                slashing_db_path.display()
            ),
        ));
    }
    #[cfg(unix)]
    MarkerDir::open(&fallback.dir)?.check_db_entry(slashing_db_path)?;
    #[cfg(not(unix))]
    let _ = fallback;
    Ok(())
}

/// File name of the fallback marker of the database at `slashing_db_path`:
/// [`MARKER_FILENAME`], a dot, and the file name of the database.
///
/// The name keeps the native bytes of the database file name, so two
/// databases in one directory get two names. The legacy name
/// [`MARKER_FILENAME`] in that directory has no owner and is only read.
pub fn fallback_marker_name(slashing_db_path: &Path) -> OsString {
    let mut name = OsString::from(format!("{MARKER_FILENAME}."));
    name.push(slashing_db_path.file_name().unwrap_or_default());
    name
}

/// The fallback marker of one slashing database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackMarkerPath {
    /// Parent of the slashing database, or `.` for a bare file name.
    pub dir: PathBuf,
    /// The slashing database. Its file name names the owned marker.
    pub slashing_db_path: PathBuf,
}

impl FallbackMarkerPath {
    /// `None` when [`fallback_marker_dir`] gives no fallback directory.
    pub fn for_config(keystore_dir: &Path, slashing_db_path: &Path) -> Option<Self> {
        let dir = fallback_marker_dir(keystore_dir, slashing_db_path)?;
        Some(Self { dir, slashing_db_path: slashing_db_path.to_path_buf() })
    }

    /// Path of the owned marker of this database.
    pub fn owned_path(&self) -> PathBuf {
        self.dir.join(fallback_marker_name(&self.slashing_db_path))
    }
}

/// What a start-up read found at the owned name and at the legacy name.
#[derive(Debug)]
pub struct FallbackInspect {
    pub owned: MarkerInspect,
    pub legacy: MarkerInspect,
}

/// Read the owned and the legacy fallback markers through one handle of the
/// database directory. Boot refuses unless both are [`MarkerInspect::Absent`],
/// whatever owner the owned marker records. A directory that the walk with no
/// symlink cannot open, a missing one too, gives two `Unreadable` results.
pub fn inspect_fallback(fallback: &FallbackMarkerPath) -> FallbackInspect {
    let owned = fallback.owned_path();
    let legacy = marker_path(&fallback.dir);
    #[cfg(unix)]
    {
        match MarkerDir::open(&fallback.dir) {
            Ok(dir) => FallbackInspect {
                owned: inspect_file(
                    owned,
                    dir.read(&fallback_marker_name(&fallback.slashing_db_path)),
                ),
                legacy: inspect_file(legacy, dir.read(OsStr::new(MARKER_FILENAME))),
            },
            Err(source) => FallbackInspect {
                owned: MarkerInspect::Unreadable {
                    path: owned,
                    source: io::Error::new(source.kind(), source.to_string()),
                },
                legacy: MarkerInspect::Unreadable { path: legacy, source },
            },
        }
    }
    #[cfg(not(unix))]
    {
        FallbackInspect { owned: inspect_at(&owned), legacy: inspect_at(&legacy) }
    }
}

/// Write the owned fallback marker of `fallback` under the fallback lock,
/// with the absolute keystore path that the writer resolves now as its owner
/// (no owner when that path is not UTF-8). An entry at the owned path that
/// is not a marker with the same owner stays: the write returns
/// `AlreadyExists` with the path. Nothing writes the legacy name.
pub fn write_fallback_marker(
    fallback: &FallbackMarkerPath,
    keystore_dir: &Path,
    marker: &DetectionMarker,
) -> io::Result<()> {
    #[cfg(test)]
    dir_marker_write_fault(&fallback.dir)?;
    #[cfg(unix)]
    {
        let owner = resolved_owner(keystore_dir);
        let body = encode_marker(marker, owner.clone())?;
        let dir = MarkerDir::open(&fallback.dir)?;
        let _lock = dir.lock()?;
        let name = fallback_marker_name(&fallback.slashing_db_path);
        let update = match dir.read(&name) {
            MarkerFile::Absent => true,
            MarkerFile::Bytes(bytes) => owner.is_some() && marker_owner(&bytes) == Ok(owner),
            MarkerFile::Unreadable(_) => false,
        };
        if !update {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} is not a fallback detection marker of this keystore, so the write does \
                     not replace it",
                    fallback.owned_path().display()
                ),
            ));
        }
        dir.replace(&name, &body)
    }
    #[cfg(not(unix))]
    {
        let _ = (fallback, keystore_dir, marker);
        Err(io::Error::new(io::ErrorKind::Unsupported, "a fallback marker needs a Unix platform"))
    }
}

/// `path` made absolute with the working directory now, with no `.`
/// component and no trailing slash. The function reads no file system
/// entry, and it does not resolve a symlink or a `..`. A fallback marker
/// records its keystore in this form, and a boot refusal prints the paths of
/// its `clear-detection` command in this form.
pub(crate) fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    Ok(std::path::absolute(path)?.components().collect())
}

/// The owner that a fallback marker of `keystore_dir` records: the
/// [`absolute_path`] of the keystore. The keystore directory can be missing
/// (the drain writes the marker when the keystore write fails). A second
/// path of one keystore (a symlink or a `..`) records a different owner, and
/// a clear through that path keeps the marker. `None` when the path is empty
/// or not valid UTF-8.
fn resolved_owner(keystore_dir: &Path) -> Option<String> {
    absolute_path(keystore_dir).ok()?.into_os_string().into_string().ok()
}

/// What [`clear_fallback_marker`] did with the owned fallback marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackClear {
    /// The owned marker of this keystore was removed.
    Removed { path: PathBuf },
    /// The owned marker names another keystore and stays.
    OtherOwner { path: PathBuf, owner: String },
}

/// Remove the owned fallback marker of `fallback` under the fallback lock,
/// only when its recorded owner is the path that a write for `keystore_dir`
/// records now. The recorded owner is not resolved again. A marker of another
/// keystore stays ([`FallbackClear::OtherOwner`]). An owned marker that
/// cannot be read, does not parse or records no owner, and a legacy marker,
/// stay: the function returns `InvalidData` with the path and the recovery
/// step. The result has at most one entry; empty means no owned marker. As
/// [`check_slashing_db_name`] does, the clear fails when the walk cannot open
/// the database directory, or when the database file has a second name.
pub fn clear_fallback_marker(
    fallback: &FallbackMarkerPath,
    keystore_dir: &Path,
) -> io::Result<Vec<FallbackClear>> {
    #[cfg(unix)]
    {
        let dir = MarkerDir::open(&fallback.dir)?;
        dir.check_db_entry(&fallback.slashing_db_path)?;
        let _lock = dir.lock()?;
        let path = fallback.owned_path();
        let name = fallback_marker_name(&fallback.slashing_db_path);
        let owner = match dir.read(&name) {
            MarkerFile::Absent => None,
            MarkerFile::Bytes(bytes) => Some(marker_owner(&bytes)),
            MarkerFile::Unreadable(source) => Some(Err(source.to_string())),
        };
        let owner = match owner {
            None => None,
            Some(Err(reason)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the fallback detection marker {path} cannot be read or does not parse \
                         ({reason}), so its owner is unknown. Make sure that no other validator \
                         client uses this slashing database, remove {path}, then run \
                         `rvc doppelganger clear-detection` again",
                        path = path.display()
                    ),
                ));
            }
            Some(Ok(None)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    no_owner_message(&path, &fallback.dir),
                ));
            }
            Some(Ok(Some(owner))) => Some(owner),
        };
        if !matches!(dir.read(OsStr::new(MARKER_FILENAME)), MarkerFile::Absent) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                no_owner_message(&marker_path(&fallback.dir), &fallback.dir),
            ));
        }
        let Some(owner) = owner else {
            return Ok(Vec::new());
        };
        if resolved_owner(keystore_dir).as_ref() != Some(&owner) {
            return Ok(vec![FallbackClear::OtherOwner { path, owner }]);
        }
        #[cfg(test)]
        run_record_path_hook(&BEFORE_FALLBACK_UNLINK, &path);
        dir.unlink(&name)?;
        sync_file(&dir.file, &dir.path)?;
        Ok(vec![FallbackClear::Removed { path }])
    }
    #[cfg(not(unix))]
    {
        let _ = (fallback, keystore_dir);
        Err(io::Error::new(io::ErrorKind::Unsupported, "a fallback marker needs a Unix platform"))
    }
}

/// The error text for a fallback marker at `path` in `dir` that records no
/// owner: a legacy marker, or an owned marker without `keystore_dir`.
fn no_owner_message(path: &Path, dir: &Path) -> String {
    format!(
        "the fallback detection marker {path} records no owner, so this command does not remove \
         it. Stop each validator client whose slashing database is in {dir}, and make sure that \
         its validators do not run in another place. Remove {path}. Then run `rvc doppelganger \
         clear-detection` for each of those clients before it starts again",
        path = path.display(),
        dir = dir.display()
    )
}

/// Read the marker. A missing file is [`MarkerInspect::Absent`].
///
/// A symlink, including a dangling one, is [`MarkerInspect::Unreadable`].
pub fn inspect(data_dir: &Path) -> MarkerInspect {
    inspect_at(&marker_path(data_dir))
}

/// Read the marker at `path`. A missing file is [`MarkerInspect::Absent`].
pub fn inspect_at(path: &Path) -> MarkerInspect {
    inspect_file(path.to_path_buf(), doppelganger::marker_file::read_marker_file(path))
}

/// What a read of the marker at `path` found, as a [`MarkerInspect`].
fn inspect_file(path: PathBuf, file: MarkerFile) -> MarkerInspect {
    match file {
        MarkerFile::Absent => MarkerInspect::Absent,
        MarkerFile::Unreadable(source) => MarkerInspect::Unreadable { path, source },
        MarkerFile::Bytes(bytes) => match parse_marker(&bytes) {
            Ok(marker) => MarkerInspect::Present(marker),
            Err(reason) => MarkerInspect::Corrupt { path, reason },
        },
    }
}

/// A directory that this process opened one time. Each marker read, temp
/// create, rename, unlink, lock and fsync in it uses this handle, so a later
/// change to the path does not move these steps to a different directory.
#[cfg(unix)]
struct MarkerDir {
    /// The directory, opened with `O_RDONLY`.
    file: File,
    /// The path as configured, for messages and test hooks.
    path: PathBuf,
}

#[cfg(unix)]
impl MarkerDir {
    /// Open the database directory `dir` (or, for the selection in
    /// [`fallback_marker_dir`], the keystore directory) with a walk that
    /// resolves nothing first and follows no symlink. The walk starts at `/`
    /// for an absolute path and at the working directory for a relative
    /// path, and opens each name with `O_NOFOLLOW | O_DIRECTORY` (`O_PATH` on
    /// Linux: search permission is enough). A missing name, a symlink, a file
    /// or a `..` in the path stops the walk with an error.
    fn open(dir: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let search = libc::O_PATH;
        #[cfg(not(target_os = "linux"))]
        let search = libc::O_RDONLY;
        let context = |err: io::Error| {
            let text = format!(
                "the slashing database directory {} must exist and have no symlink and no `..` \
                 in its path: {err}",
                dir.display()
            );
            io::Error::new(err.kind(), text)
        };
        #[cfg(not(test))]
        let mut walk = None;
        #[cfg(test)]
        let mut walk = walk_start()?;
        for part in dir.components() {
            if matches!(part, std::path::Component::ParentDir | std::path::Component::Prefix(_)) {
                let err = io::Error::new(io::ErrorKind::InvalidInput, "the path has a `..`");
                return Err(context(err));
            }
            let flags = [search, libc::O_DIRECTORY, libc::O_NOFOLLOW];
            walk = Some(open_at(walk.as_ref(), part.as_os_str(), &flags).map_err(context)?);
        }
        let flags = [libc::O_RDONLY, libc::O_DIRECTORY];
        let file = open_at(walk.as_ref(), OsStr::new("."), &flags).map_err(context)?;
        Ok(Self { file, path: dir.to_path_buf() })
    }

    /// Refuse a database file `db_path` in this directory that has a second
    /// name: a symlink, an entry that is not a regular file, or a file with
    /// more than one link. A missing file (a new database) passes.
    fn check_db_entry(&self, db_path: &Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        #[cfg(target_os = "linux")]
        let flags = [libc::O_PATH, libc::O_NOFOLLOW];
        #[cfg(not(target_os = "linux"))]
        let flags = [libc::O_RDONLY, libc::O_NOFOLLOW, libc::O_NONBLOCK];
        let name = db_path.file_name().unwrap_or_default();
        let meta = match open_at(Some(&self.file), name, &flags) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            opened => opened?.metadata()?,
        };
        if meta.is_file() && meta.nlink() == 1 {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the slashing database {} must be a regular file with one link, not a symlink \
                 and not a file with a second hard link, because its fallback detection marker \
                 is found by this one name",
                db_path.display()
            ),
        ))
    }

    /// Read the entry `name` without a symlink follow and without a block
    /// on a FIFO, by the rule of [`doppelganger::marker_file`].
    fn read(&self, name: &OsStr) -> MarkerFile {
        let flags = [libc::O_RDONLY, libc::O_NOFOLLOW, libc::O_NONBLOCK];
        match open_at(Some(&self.file), name, &flags) {
            Ok(file) => doppelganger::marker_file::read_open_marker(file),
            Err(err) if err.kind() == io::ErrorKind::NotFound => MarkerFile::Absent,
            Err(err) => MarkerFile::Unreadable(err),
        }
    }

    /// Take the fallback lock of this directory without a wait. The lock
    /// ends when the returned file closes.
    #[allow(unsafe_code)]
    fn lock(&self) -> io::Result<File> {
        use std::ops::BitOr;
        use std::os::fd::AsRawFd;
        let flags = [libc::O_RDWR, libc::O_CREAT, libc::O_NOFOLLOW];
        let file = open_at(Some(&self.file), OsStr::new(FALLBACK_LOCK_FILENAME), &flags)?;
        let operation = [libc::LOCK_EX, libc::LOCK_NB].into_iter().fold(0, BitOr::bitor);
        // SAFETY: `file` keeps the descriptor open during the call. flock
        // takes no pointer.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "the fallback detection marker lock {} cannot be taken: {err}. Another \
                     process can hold it for a short time. Do the step again",
                    self.path.join(FALLBACK_LOCK_FILENAME).display()
                ),
            ));
        }
        Ok(file)
    }

    /// Write `body` to `name`: temp file `.rvc.doppelganger_tmp.<pid>.<nanos>.tmp`
    /// (at most 57 bytes, exclusive create), fsync, rename, directory fsync. A
    /// failed step removes only the temp file that this call created and did
    /// not rename.
    fn replace(&self, name: &OsStr, body: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let temp = OsString::from(format!(
            ".rvc.doppelganger_tmp.{}.{}.tmp",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        ));
        #[cfg(test)]
        run_record_path_hook(&BEFORE_MARKER_TEMP_OPEN, &self.path.join(&temp));
        let flags = [libc::O_WRONLY, libc::O_CREAT, libc::O_EXCL, libc::O_NOFOLLOW];
        let mut file = open_at(Some(&self.file), &temp, &flags)?;
        let staged = file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(body))
            .and_then(|()| sync_file(&file, &self.path))
            .and_then(|()| self.rename(&temp, name));
        if let Err(err) = staged {
            let _ = self.unlink(&temp);
            return Err(err);
        }
        sync_file(&self.file, &self.path)
    }

    /// Rename the entry `from` to `to` in this directory.
    #[allow(unsafe_code)]
    fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let (from, to) = (c_name(from)?, c_name(to)?);
        let fd = self.file.as_raw_fd();
        // SAFETY: `from` and `to` are NUL-terminated strings that live during
        // the call, and `self.file` keeps `fd` open.
        cvt(unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) })
    }

    /// Remove the entry `name` from this directory.
    #[allow(unsafe_code)]
    fn unlink(&self, name: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let name = c_name(name)?;
        // SAFETY: `name` is a NUL-terminated string that lives during the
        // call, and `self.file` keeps the descriptor open.
        cvt(unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) })
    }

    /// Create the directory `name` in this directory with mode `0700`. The
    /// call fails when the name exists.
    #[allow(unsafe_code)]
    fn mkdir(&self, name: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let name = c_name(name)?;
        // SAFETY: `name` is a NUL-terminated string that lives during the
        // call, and `self.file` keeps the descriptor open.
        cvt(unsafe { libc::mkdirat(self.file.as_raw_fd(), name.as_ptr(), 0o700) })
    }

    /// Remove the empty directory `name` from this directory. The call
    /// removes nothing when the entry is not a directory or is not empty.
    #[allow(unsafe_code)]
    fn rmdir(&self, name: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let name = c_name(name)?;
        let fd = self.file.as_raw_fd();
        // SAFETY: `name` is a NUL-terminated string that lives during the
        // call, and `self.file` keeps the descriptor open.
        cvt(unsafe { libc::unlinkat(fd, name.as_ptr(), libc::AT_REMOVEDIR) })
    }

    /// Prove that this directory can hold a marker. On Linux, the probe uses
    /// a file with no name ([`MarkerDir::probe_unnamed`]), so it creates no
    /// entry and removes no entry. Other systems, and a Linux file system
    /// with no `O_TMPFILE`, use [`MarkerDir::probe_in_subdir`].
    fn probe(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(probed) = self.probe_unnamed() {
            return probed;
        }
        self.probe_in_subdir()
    }

    /// `openat(dir, ".", O_TMPFILE | O_WRONLY | O_CLOEXEC, 0600)` through the
    /// handle of this directory, then the write, the fsync of the file and
    /// the fsync of this directory. The file closes at the end. `None` when
    /// the open fails with `EOPNOTSUPP` (the file system has no `O_TMPFILE`)
    /// or `EISDIR` (the kernel has no `O_TMPFILE`). Each other error stops
    /// the probe.
    #[cfg(target_os = "linux")]
    fn probe_unnamed(&self) -> Option<io::Result<()>> {
        let at = |step: &str, err: io::Error| {
            let text =
                format!("a probe file with no name in {} {step}: {err}", self.path.display());
            io::Error::new(err.kind(), text)
        };
        #[cfg(test)]
        run_probe_step(&self.path, ProbeStep::Unnamed, &self.path);
        let flags = [libc::O_TMPFILE, libc::O_WRONLY];
        let opened = open_at(Some(&self.file), OsStr::new("."), &flags);
        #[cfg(test)]
        let opened = opened.map(UnnamedProbeFile);
        #[cfg(test)]
        let opened =
            take_unnamed_probe_error().map_or(opened, |n| Err(io::Error::from_raw_os_error(n)));
        let mut file = match opened {
            Ok(file) => file,
            Err(err) if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EISDIR)) => {
                return None;
            }
            Err(err) => return Some(Err(at("cannot be created", err))),
        };
        let written = file.write_all(b"ok").and_then(|()| sync_file(&file, &self.path));
        #[cfg(test)]
        run_probe_step(&self.path, ProbeStep::SyncDir, &self.path);
        Some(
            written
                .map_err(|err| at("cannot be written", err))
                .and_then(|()| sync_file(&self.file, &self.path)),
        )
    }

    /// The probe in a private subdirectory. Each step uses a handle, so the
    /// probe does not look up the path again:
    ///
    /// 1. Create a private subdirectory (`mkdirat`, mode `0700`) with a
    ///    unique name.
    /// 2. Open it with `O_NOFOLLOW | O_DIRECTORY`. Check that it is the
    ///    directory of step 1 ([`MarkerDir::check_created_dir`]).
    /// 3. In the subdirectory, create a file (exclusive create), write it,
    ///    fsync it, and remove it.
    /// 4. Remove the empty subdirectory, and fsync this directory.
    ///
    /// A failed step stops the probe with an error. After an error in step 1
    /// or step 2, the probe removes nothing.
    fn probe_in_subdir(&self) -> io::Result<()> {
        #[cfg(test)]
        FALLBACK_PROBES.with(|count| count.set(count.get() + 1));
        let name = OsString::from(format!(
            ".{MARKER_FILENAME}.{}.{}.probe",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        ));
        let entry = self.path.join(&name);
        let at = |step: &str, err: io::Error| {
            io::Error::new(
                err.kind(),
                format!("the probe directory {} {step}: {err}", entry.display()),
            )
        };
        #[cfg(test)]
        run_probe_step(&self.path, ProbeStep::Create, &entry);
        self.mkdir(&name).map_err(|err| at("cannot be created", err))?;
        #[cfg(test)]
        run_probe_step(&self.path, ProbeStep::Open, &entry);
        let flags = [libc::O_RDONLY, libc::O_DIRECTORY, libc::O_NOFOLLOW];
        let file =
            open_at(Some(&self.file), &name, &flags).map_err(|err| at("cannot be opened", err))?;
        let sub = Self { file, path: entry.clone() };
        #[cfg(test)]
        run_probe_step(&self.path, ProbeStep::Check, &entry);
        self.check_created_dir(&name, &sub.file)?;
        let file_name = OsStr::new("probe");
        let flags = [libc::O_WRONLY, libc::O_CREAT, libc::O_EXCL, libc::O_NOFOLLOW];
        let probed = open_at(Some(&sub.file), file_name, &flags).and_then(|mut file| {
            let written = file.write_all(b"ok").and_then(|()| sync_file(&file, &self.path));
            #[cfg(test)]
            run_probe_step(&self.path, ProbeStep::Remove, &entry);
            written.and(sub.unlink(file_name))
        });
        // The removal uses the name, because POSIX has no call that removes a
        // directory through its handle. Threat model: a process that can
        // already write the database directory can move the subdirectory away
        // after the check and put a new empty directory at the name. Then this
        // call removes that empty directory, which that process made and can
        // remove itself. `AT_REMOVEDIR` removes only an empty directory, so
        // the probe does not touch a marker file or other data. Ash accepted
        // this residual race in the review of PR #1016 (fix round 3).
        let removed = self.rmdir(&name).map_err(|err| at("cannot be removed", err));
        probed.and(removed)?;
        sync_file(&self.file, &self.path)
    }

    /// Check that `sub`, the open entry `name` of this directory, is the
    /// private directory that [`MarkerDir::probe_in_subdir`] created.
    /// `mkdirat` gives no handle, so the check uses these facts:
    ///
    /// - The entry `name` has the device and inode numbers of `sub`.
    /// - The effective uid of this process owns `sub`.
    /// - The mode of `sub` gives no access to the group or to other users.
    ///
    /// Only a process with this uid, or with a privilege that overrides file
    /// permissions, can make a different directory that passes the check.
    /// When a fact is false, the result is an error, and the entry stays.
    #[allow(unsafe_code)]
    fn check_created_dir(&self, name: &OsStr, sub: &File) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        #[cfg(target_os = "linux")]
        let flags = [libc::O_PATH, libc::O_NOFOLLOW];
        #[cfg(not(target_os = "linux"))]
        let flags = [libc::O_RDONLY, libc::O_NOFOLLOW, libc::O_NONBLOCK];
        let (named, meta) = (open_at(Some(&self.file), name, &flags)?.metadata()?, sub.metadata()?);
        // SAFETY: geteuid only reads the effective user ID of this process.
        let euid = unsafe { libc::geteuid() };
        let id = |meta: &fs::Metadata| (meta.dev(), meta.ino());
        if id(&named) != id(&meta) || meta.uid() != euid || meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "the probe directory {} is not the private directory that the probe \
                     created, so the probe does not remove it",
                    self.path.join(name).display()
                ),
            ));
        }
        Ok(())
    }
}

/// Open `name` relative to `dir`, or to the working directory when `dir` is
/// `None`, with `flags` and `O_CLOEXEC`. A create gets mode `0600`.
#[cfg(unix)]
#[allow(unsafe_code)]
fn open_at(dir: Option<&File>, name: &OsStr, flags: &[libc::c_int]) -> io::Result<File> {
    use std::ops::BitOr;
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let base = dir.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    let flags = flags.iter().copied().fold(libc::O_CLOEXEC, BitOr::bitor);
    let mode: libc::c_uint = 0o600;
    // SAFETY: `name` is a NUL-terminated string that lives during the call,
    // and `dir` keeps `base` open. The mode is a plain integer.
    let fd = unsafe { libc::openat(base, name.as_ptr(), flags, mode) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `name` as a C string. A name with a NUL byte is `InvalidInput`.
#[cfg(unix)]
fn c_name(name: &OsStr) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(name.as_encoded_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

/// `Ok` for a libc result of 0. Else the error of the last call.
#[cfg(unix)]
fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Path of the one-shot force-window file in `data_dir`.
pub fn force_window_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FORCE_WINDOW_FILENAME)
}

/// Prove `data_dir` can hold a marker: create a temp file, fsync, and remove it.
pub fn probe_marker_dir_writable(data_dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    note_probe(data_dir)?;
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
        sync_file(&file, data_dir)?;
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

/// Prove that the slashing database directory `dir` can hold a fallback
/// marker. The walk that the marker read, write and clear use (no symlink, no
/// `..`) opens `dir` one time. Through that handle, the probe writes and
/// fsyncs a file with no name (Linux). The fallback makes a private
/// subdirectory, writes and fsyncs a file in it, and removes the file and the
/// subdirectory. Its only removal by name in `dir` is the removal of the
/// subdirectory, and that removal cannot remove a file or a directory that is
/// not empty.
pub fn probe_fallback_dir_writable(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        #[cfg(test)]
        note_probe(dir)?;
        MarkerDir::open(dir)?.probe()
    }
    #[cfg(not(unix))]
    {
        probe_marker_dir_writable(dir)
    }
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
/// The keystore marker records no owner.
pub fn write_marker(data_dir: &Path, marker: &DetectionMarker) -> io::Result<()> {
    #[cfg(test)]
    dir_marker_write_fault(data_dir)?;
    atomic_write(data_dir, MARKER_FILENAME, &encode_marker(marker, None)?)
}

fn encode_marker(marker: &DetectionMarker, keystore_dir: Option<String>) -> io::Result<Vec<u8>> {
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
        keystore_dir,
    };
    serde_json::to_vec_pretty(&doc).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write `body` to `filename` in `data_dir` with [`MarkerDir::replace`], the
/// marker writer that the fallback marker also uses. The keystore marker and
/// the force-window file use this function. It opens the keystore directory
/// by its path, as boot does for its reads of the keystore marker; the walk
/// with no symlink is for the database directory.
fn atomic_write(data_dir: &Path, filename: &str, body: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        let path = if data_dir.as_os_str().is_empty() { Path::new(".") } else { data_dir };
        let file = open_at(None, path.as_os_str(), &[libc::O_RDONLY, libc::O_DIRECTORY])?;
        MarkerDir { file, path: path.to_path_buf() }.replace(OsStr::new(filename), body)
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, filename, body);
        Err(io::Error::new(io::ErrorKind::Unsupported, "a marker write needs a Unix platform"))
    }
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
    #[cfg(test)]
    if let Some(secs) = UNIX_SECS_OVERRIDE.with(Cell::get) {
        return secs;
    }
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
    sync_file(&file, data_dir)?;
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
/// never replaces a record. An error before the link removes the temp file.
fn create_clear_record(data_dir: &Path) -> io::Result<()> {
    let tmp_path = write_clear_record_temp(data_dir)?;
    #[cfg(test)]
    run_before_record_link();
    if let Err(err) = link_record(&tmp_path, data_dir).map_err(explain_link_error) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    fs::remove_file(&tmp_path)?;
    sync_dir(data_dir)
}

/// Write a clear record to a new temp file in `data_dir` and fsync it.
/// Returns the path of the temp file.
///
/// The temp file is `.{RECORD_FILENAME}.<pid>.<nanos>.tmp`, a regular file
/// with mode `0600`, opened with `O_NOFOLLOW` and `O_NONBLOCK`. A failed
/// exclusive open of the temp file removes nothing, because that name can
/// belong to another create. After the open, an error removes the temp file.
fn write_clear_record_temp(data_dir: &Path) -> io::Result<PathBuf> {
    let bytes = encode_record(false, 0, 0)?;
    let tmp_path = data_dir.join(format!(
        ".{RECORD_FILENAME}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
    ));
    #[cfg(test)]
    run_record_path_hook(&BEFORE_RECORD_TEMP_OPEN, &tmp_path);
    let mut file = open_record(&tmp_path, true)?;
    let written = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        write_record_bytes(&mut file, &bytes)?;
        sync_file(&file, data_dir)
    })();
    if let Err(err) = written {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(tmp_path)
}

/// What a read of the record path found.
enum RecordFile {
    /// No entry is at the path.
    Absent,
    /// The entry is not a regular file.
    NotRegular,
    /// A regular file: the `fstat` metadata of the read descriptor, and at
    /// most [`RECORD_LEN`] + 1 bytes. A longer file does not parse.
    Read(fs::Metadata, Vec<u8>),
}

/// Read the entry at `path` through one descriptor.
///
/// The read does not follow a symlink, and the open does not block on a
/// FIFO. An error is a read error, not a parse result.
fn read_record_file(path: &Path) -> io::Result<RecordFile> {
    #[cfg(any(test, feature = "test-utils"))]
    if take_durable_fault(DurableFault::RecordRead) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(RecordFile::Absent),
        Err(err) => return Err(err),
        Ok(meta) if !meta.is_file() => return Ok(RecordFile::NotRegular),
        Ok(_) => {}
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::ops::BitOr;
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(
            [libc::O_NOFOLLOW, libc::O_NONBLOCK, libc::O_CLOEXEC].into_iter().fold(0, BitOr::bitor),
        );
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(RecordFile::NotRegular);
    }
    let mut bytes = Vec::new();
    file.take(RECORD_LEN as u64 + 1).read_to_end(&mut bytes)?;
    Ok(RecordFile::Read(meta, bytes))
}

/// Replace the record at `path` in `data_dir` with a clear record.
///
/// The caller read that record through one descriptor, and the record does
/// not parse. `checked` is the `fstat` metadata of that descriptor, and
/// `checked_bytes` are the bytes that it read. This writes and fsyncs a
/// clear temp record with the writer of [`create_clear_record`]. Then
/// `renameat2` with `RENAME_EXCHANGE` swaps the temp record and the entry at
/// `path` in one atomic step, so a reader sees the old entry or the new
/// record. The old entry is then at the temp path. If it is not the checked
/// file with the checked bytes, another process changed `path` after the
/// read: a second exchange puts that entry back at `path`, the clear temp
/// record is removed, and this returns an error. Else this removes the old
/// entry and fsyncs `data_dir`. An exchange error removes the temp record.
///
/// Call this only while this process holds the keystore lock. A crash after
/// the first exchange leaves the old entry at the temp path, which
/// [`sweep_stale_record_temps`] removes.
fn replace_unparseable_record(
    data_dir: &Path,
    path: &Path,
    checked: &fs::Metadata,
    checked_bytes: &[u8],
) -> io::Result<()> {
    let tmp_path = write_clear_record_temp(data_dir)?;
    #[cfg(any(test, feature = "test-utils"))]
    run_before_record_exchange(path);
    if let Err(err) = exchange_record(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            err.kind(),
            format!(
                "the clear record could not be exchanged with the detection record {}: {err}",
                path.display()
            ),
        ));
    }
    if !is_checked_record(&tmp_path, checked, checked_bytes) {
        if let Err(err) = exchange_record(&tmp_path, path) {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "the detection record {} changed after this command read it, and the \
                     command could not put the changed entry back: {err}. The changed entry is \
                     at {}. Stop the process and examine the two paths",
                    path.display(),
                    tmp_path.display()
                ),
            ));
        }
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the detection record {} changed after this command read it, so the command did \
                 not replace it. Run `rvc doppelganger clear-detection` again",
                path.display()
            ),
        ));
    }
    fs::remove_file(&tmp_path)?;
    sync_dir(data_dir)
}

/// `true` when `path` is the regular file that the caller read: the same
/// device number, inode number, length and bytes.
fn is_checked_record(path: &Path, checked: &fs::Metadata, checked_bytes: &[u8]) -> bool {
    let Ok(RecordFile::Read(meta, bytes)) = read_record_file(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != checked.dev() || meta.ino() != checked.ino() {
            return false;
        }
    }
    meta.len() == checked.len() && bytes == checked_bytes
}

/// Swap the entries at `tmp_path` and `path` in one atomic step with
/// `renameat2` and `RENAME_EXCHANGE`. Both entries must exist. Only Linux
/// has this exchange, so other platforms return `Unsupported`.
#[allow(unsafe_code)]
fn exchange_record(tmp_path: &Path, path: &Path) -> io::Result<()> {
    #[cfg(any(test, feature = "test-utils"))]
    if take_durable_fault(DurableFault::Exchange) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = |path: &Path| {
            CString::new(path.as_os_str().as_bytes())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        };
        let (from, to) = (c_path(tmp_path)?, c_path(path)?);
        // SAFETY: `from` and `to` are NUL-terminated strings that live during
        // the call, and the kernel only reads them. The syscall takes no
        // other pointer.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::c_long::from(libc::AT_FDCWD),
                from.as_ptr(),
                libc::c_long::from(libc::AT_FDCWD),
                to.as_ptr(),
                libc::RENAME_EXCHANGE as libc::c_long,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(any(test, feature = "test-utils"))]
        DURABLE_STEPS.with(|steps| steps.borrow_mut().push(DurableStep::Exchange));
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = tmp_path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "this platform has no atomic exchange for the detection record {path}. Remove \
                 {path}, then run `rvc doppelganger clear-detection` again",
                path = path.display()
            ),
        ))
    }
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
    sync_file(&file, data_dir)?;
    Ok(())
}

/// Write `not-detected` over a detected record, or replace a record that
/// does not parse. A missing or clear record is [`ClearOutcome::Absent`].
///
/// A `detected` record gets `not-detected` in place, and the result is
/// [`ClearOutcome::Removed`]. A record that does not parse is replaced when
/// it is a regular file that this function read, and the result is
/// [`ClearOutcome::Replaced`]: this writes a clear record to a temp file and
/// exchanges it with the record in one atomic step. If the record changed
/// after the read, the record stays and this returns an error. A read error
/// is not a parse result, so the record stays and this returns an error. A
/// symlink, directory or FIFO at that path does not change, and the error
/// names the path. Stop the process, remove that path with `rm`, and run
/// `clear-detection` again. Call this only while this process holds the
/// keystore lock and after the force-window file is durable. A valid
/// `detected` record is reset by that command; deleting the file by hand
/// skips the force-window file.
pub fn reset_or_replace_detection_record(data_dir: &Path) -> io::Result<ClearOutcome> {
    let path = record_path(data_dir);
    let (checked, bytes) = match read_record_file(&path) {
        Ok(RecordFile::Absent) => return Ok(ClearOutcome::Absent),
        Ok(RecordFile::NotRegular) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the detection record {path} does not parse and is not a regular file. \
                     Remove {path}, then run `rvc doppelganger clear-detection` again",
                    path = path.display()
                ),
            ));
        }
        Ok(RecordFile::Read(checked, bytes)) => (checked, bytes),
        Err(err) => {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "the detection record {} cannot be read: {err}. The command does not \
                     replace a record that it cannot read",
                    path.display()
                ),
            ));
        }
    };
    match parse_record(&bytes) {
        Ok(ParsedRecord::Clear) => Ok(ClearOutcome::Absent),
        Ok(ParsedRecord::Detected { .. }) => {
            let mut file = open_record(&path, false)?;
            let bytes = encode_record(false, 0, 0)?;
            write_record_bytes(&mut file, &bytes)?;
            sync_file(&file, data_dir)?;
            Ok(ClearOutcome::Removed)
        }
        Err(_) => {
            replace_unparseable_record(data_dir, &path, &checked, &bytes)?;
            Ok(ClearOutcome::Replaced)
        }
    }
}

/// The paths of one detection: the keystore directory, which holds the
/// record and the keystore marker, and the owned fallback marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionPaths {
    /// Keystore directory. The record and the keystore marker are in it.
    pub keystore_dir: PathBuf,
    /// Owned fallback marker beside the slashing database. `None` when that
    /// directory is the keystore directory.
    pub fallback: Option<FallbackMarkerPath>,
}

/// One path of [`persist_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistPath {
    /// The pre-allocated record, overwritten in place.
    Record,
    /// The marker in the keystore directory.
    KeystoreMarker,
    /// The owned fallback marker beside the slashing database.
    FallbackMarker,
}

/// The longest time that [`DetectionPersister::persist`] waits for the
/// write of one path.
pub const DETECTION_PERSIST_TIMEOUT: Duration = Duration::from_secs(5);

/// The failure of one path of a persist round.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// The write or its fsync returned this error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The write did not return within [`DETECTION_PERSIST_TIMEOUT`], or an
    /// earlier write of this path is still running. The blocking call can
    /// still be running, so its result is not known.
    #[error("the write did not return within {DETECTION_PERSIST_TIMEOUT:?}")]
    TimedOut,
}

/// The result of each path of one [`persist_all`] call or one
/// [`DetectionPersister::persist`] round.
#[derive(Debug)]
pub struct PersistReport {
    /// The in-place write of the record.
    pub record: Result<(), PersistError>,
    /// The write of the keystore marker.
    pub keystore_marker: Result<(), PersistError>,
    /// The write of the owned fallback marker. `None` when no fallback is
    /// configured.
    pub fallback_marker: Option<Result<(), PersistError>>,
    /// The paths of the call. Each failure gives its file path from them.
    paths: DetectionPaths,
}

impl PersistReport {
    /// `true` when at least one path returned `Ok`. A path returns `Ok` only
    /// after its write and its fsync returned `Ok` (a rename also needs the
    /// directory fsync).
    pub fn durable(&self) -> bool {
        self.record.is_ok()
            || self.keystore_marker.is_ok()
            || self.fallback_marker.as_ref().is_some_and(Result::is_ok)
    }

    /// Each failed path, with its file path and its error, in the write
    /// order.
    pub fn failures(&self) -> impl Iterator<Item = (PersistPath, PathBuf, &PersistError)> + '_ {
        let keystore_dir = &self.paths.keystore_dir;
        let record = self
            .record
            .as_ref()
            .err()
            .map(|err| (PersistPath::Record, record_path(keystore_dir), err));
        let keystore_marker = self
            .keystore_marker
            .as_ref()
            .err()
            .map(|err| (PersistPath::KeystoreMarker, marker_path(keystore_dir), err));
        let fallback_marker =
            self.paths.fallback.as_ref().zip(self.fallback_marker.as_ref()).and_then(
                |(fallback, result)| {
                    result
                        .as_ref()
                        .err()
                        .map(|err| (PersistPath::FallbackMarker, fallback.owned_path(), err))
                },
            );
        record.into_iter().chain(keystore_marker).chain(fallback_marker)
    }
}

/// Write the detection to each configured path: the record in place, the
/// keystore marker, and the owned fallback marker when one is configured.
///
/// Each call attempts each configured path. The result of one path does not
/// stop the write of a different path: a failed keystore volume does not
/// stop the fallback marker, and a written record does not stop the two
/// markers. The record is attempted also when it does not exist. With
/// detection on, boot pre-allocates it, so a missing record is a failure.
pub fn persist_all(paths: &DetectionPaths, marker: &DetectionMarker) -> PersistReport {
    let write = |path| write_path(path, paths, marker).map_err(PersistError::Io);
    let record = write(PersistPath::Record);
    let keystore_marker = write(PersistPath::KeystoreMarker);
    let fallback_marker = paths.fallback.as_ref().map(|_| write(PersistPath::FallbackMarker));
    PersistReport { record, keystore_marker, fallback_marker, paths: paths.clone() }
}

/// The write of one path of [`persist_all`].
fn write_path(
    path: PersistPath,
    paths: &DetectionPaths,
    marker: &DetectionMarker,
) -> io::Result<()> {
    let keystore_dir = &paths.keystore_dir;
    #[cfg(test)]
    if let Some(faults) = dir_faults(keystore_dir) {
        if faults.write_panics {
            panic!("The test injects a panic in the write of {path:?}.");
        }
        if let Some((gated, gate)) = &faults.path_gate {
            if *gated == path {
                gate.wait_open(|| {});
            }
        }
    }
    match (path, &paths.fallback) {
        (PersistPath::Record, _) => {
            commit_detection_record(keystore_dir, marker.epoch, marker.unix_secs)
        }
        (PersistPath::KeystoreMarker, _) => write_marker(keystore_dir, marker),
        (PersistPath::FallbackMarker, Some(fallback)) => {
            write_fallback_marker(fallback, keystore_dir, marker)
        }
        (PersistPath::FallbackMarker, None) => {
            Err(io::Error::new(io::ErrorKind::NotFound, "no fallback marker is configured"))
        }
    }
}

/// Writes the detection to each path of a [`DetectionPaths`] off the async
/// runtime, with a timeout for each path.
///
/// Each round writes each configured path on its own blocking thread, with
/// the write of [`persist_all`] for that path. The paths run at the same
/// time, and a round waits at most [`DETECTION_PERSIST_TIMEOUT`]. A blocking
/// thread cannot be cancelled. Thus a path whose earlier write is still
/// running gets no second thread: its result is [`PersistError::TimedOut`]
/// until that write returns.
///
/// The paths share the Tokio blocking pool. A hung path holds at most one
/// pool thread, so a hung keystore mount holds at most two and does not stop
/// the fallback write. Other blocking work that fills the pool can still
/// queue the fallback write; the round then gives it `TimedOut`.
///
/// # Examples
///
/// ```
/// use rvc::detection_marker::{
///     preallocate_detection_record, DetectionMarker, DetectionPaths, DetectionPersister,
/// };
///
/// let dir = tempfile::tempdir().expect("dir");
/// preallocate_detection_record(dir.path()).expect("record");
/// let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
/// let persister = DetectionPersister::new(paths);
/// let marker = DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: Vec::new() };
/// let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("rt");
/// assert!(runtime.block_on(persister.persist(&marker)).durable());
/// ```
#[derive(Debug)]
pub struct DetectionPersister {
    paths: Arc<DetectionPaths>,
    record: Arc<PathSlot>,
    keystore_marker: Arc<PathSlot>,
    fallback_marker: Arc<PathSlot>,
    #[cfg(test)]
    rounds: AtomicUsize,
}

#[derive(Debug, Default)]
struct PathSlot {
    in_flight: AtomicBool,
    #[cfg(test)]
    spawned: AtomicUsize,
    #[cfg(test)]
    finished: AtomicUsize,
}

/// Clears the in-flight flag of a path when the blocking write ends, also on
/// a panic and when the closure is dropped before it runs.
struct InFlight(Arc<PathSlot>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::SeqCst);
    }
}

impl DetectionPersister {
    /// A persister for `paths` with no write in flight.
    pub fn new(paths: DetectionPaths) -> Arc<Self> {
        Arc::new(Self {
            paths: Arc::new(paths),
            record: Arc::default(),
            keystore_marker: Arc::default(),
            fallback_marker: Arc::default(),
            #[cfg(test)]
            rounds: AtomicUsize::new(0),
        })
    }

    /// Write `marker` to each configured path, as [`persist_all`] does, and
    /// return the result of each path. A path that does not return within
    /// [`DETECTION_PERSIST_TIMEOUT`], or whose earlier write is still running,
    /// gives [`PersistError::TimedOut`].
    pub async fn persist(&self, marker: &DetectionMarker) -> PersistReport {
        #[cfg(test)]
        self.rounds.fetch_add(1, Ordering::SeqCst);
        let fallback = async {
            match self.paths.fallback {
                Some(_) => Some(self.persist_path(PersistPath::FallbackMarker, marker).await),
                None => None,
            }
        };
        let (record, keystore_marker, fallback_marker) = tokio::join!(
            self.persist_path(PersistPath::Record, marker),
            self.persist_path(PersistPath::KeystoreMarker, marker),
            fallback,
        );
        PersistReport { record, keystore_marker, fallback_marker, paths: (*self.paths).clone() }
    }

    fn slot(&self, path: PersistPath) -> &Arc<PathSlot> {
        match path {
            PersistPath::Record => &self.record,
            PersistPath::KeystoreMarker => &self.keystore_marker,
            PersistPath::FallbackMarker => &self.fallback_marker,
        }
    }

    async fn persist_path(
        &self,
        path: PersistPath,
        marker: &DetectionMarker,
    ) -> Result<(), PersistError> {
        let slot = self.slot(path);
        if slot.in_flight.swap(true, Ordering::SeqCst) {
            return Err(PersistError::TimedOut);
        }
        #[cfg(test)]
        slot.spawned.fetch_add(1, Ordering::SeqCst);
        let in_flight = InFlight(Arc::clone(slot));
        let paths = Arc::clone(&self.paths);
        let marker = marker.clone();
        let write = tokio::task::spawn_blocking(move || {
            let _in_flight = in_flight;
            write_path(path, &paths, &marker)
        });
        let joined = tokio::time::timeout(DETECTION_PERSIST_TIMEOUT, write).await;
        #[cfg(test)]
        if joined.is_ok() {
            slot.finished.fetch_add(1, Ordering::SeqCst);
        }
        match joined {
            Ok(Ok(result)) => result.map_err(PersistError::Io),
            Ok(Err(join)) => Err(PersistError::Io(io::Error::other(format!(
                "the blocking write of {path:?} stopped: {join}"
            )))),
            Err(_elapsed) => Err(PersistError::TimedOut),
        }
    }

    /// The number of blocking writes that rounds started for `path`.
    #[cfg(test)]
    pub(crate) fn spawned(&self, path: PersistPath) -> usize {
        self.slot(path).spawned.load(Ordering::SeqCst)
    }

    /// The number of writes for `path` whose result reached the round
    /// before the timeout.
    #[cfg(test)]
    pub(crate) fn finished(&self, path: PersistPath) -> usize {
        self.slot(path).finished.load(Ordering::SeqCst)
    }

    /// `true` while a blocking write of `path` has not ended.
    #[cfg(test)]
    pub(crate) fn in_flight(&self, path: PersistPath) -> bool {
        self.slot(path).in_flight.load(Ordering::SeqCst)
    }

    /// The number of [`DetectionPersister::persist`] calls.
    #[cfg(test)]
    pub(crate) fn rounds(&self) -> usize {
        self.rounds.load(Ordering::SeqCst)
    }
}

/// Log each failed path of `report` at the error level with its `path`, its
/// `error` and `context`, and count each failed path in
/// [`crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL`].
pub fn log_persist_report(report: &PersistReport, context: &str) {
    for (kind, path, error) in report.failures() {
        crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
        tracing::error!(
            context,
            kind = ?kind,
            path = %path.display(),
            error = %error,
            "failed to persist the doppelganger detection on this path"
        );
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
    #[cfg(test)]
    run_record_path_hook(&AFTER_RECORD_OPEN, path);
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

#[cfg(any(test, feature = "test-utils"))]
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
    static AFTER_RECORD_OPEN: RefCell<Option<RecordPathHook>> = const { RefCell::new(None) };
    static FSYNC_TARGETS: RefCell<Vec<FileId>> = const { RefCell::new(Vec::new()) };
    static FSYNC_TARGET_FAILURE: Cell<Option<(FileId, u32)>> = const { Cell::new(None) };
    static BEFORE_MARKER_TEMP_OPEN: RefCell<Option<RecordPathHook>> = const { RefCell::new(None) };
    static BEFORE_FALLBACK_UNLINK: RefCell<Option<RecordPathHook>> = const { RefCell::new(None) };
    static PROBE_FAILURE_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static PROBE_ATTEMPTS: Cell<u32> = const { Cell::new(0) };
    static PROBE_STEP_HOOK: RefCell<Option<(PathBuf, ProbeStep, RecordPathHook)>> =
        const { RefCell::new(None) };
    static FALLBACK_PROBES: Cell<u32> = const { Cell::new(0) };
    static UNIX_SECS_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

#[cfg(test)]
#[cfg(target_os = "linux")]
thread_local! {
    static UNNAMED_PROBE_ERROR: Cell<Option<i32>> = const { Cell::new(None) };
    static UNNAMED_PROBE_WRITE_ERROR: Cell<Option<i32>> = const { Cell::new(None) };
}

#[cfg(test)]
#[cfg(unix)]
thread_local! {
    static WALK_START: RefCell<Option<File>> = const { RefCell::new(None) };
}

/// Start each walk of a relative path on this thread at `dir`, in place of
/// the working directory. A walk then gives the result that it gives when
/// `dir` is the working directory. A test that uses this function does not
/// change the working directory of the process, so it does not change the
/// result of a different test.
///
/// The guard ends the override when it drops.
#[cfg(test)]
#[cfg(unix)]
pub(crate) fn arm_walk_start(dir: &Path) -> WalkStartGuard {
    let start = File::open(dir).expect("The test must open the start directory of the walk.");
    WALK_START.with(|slot| *slot.borrow_mut() = Some(start));
    WalkStartGuard
}

/// A new handle of the start directory that [`arm_walk_start`] set on this
/// thread. `None` is the working directory.
#[cfg(test)]
#[cfg(unix)]
fn walk_start() -> io::Result<Option<File>> {
    WALK_START.with(|slot| slot.borrow().as_ref().map(File::try_clone).transpose())
}

/// The guard ends the start directory of [`arm_walk_start`] when it drops.
#[cfg(test)]
#[cfg(unix)]
pub(crate) struct WalkStartGuard;

#[cfg(test)]
#[cfg(unix)]
impl Drop for WalkStartGuard {
    fn drop(&mut self) {
        WALK_START.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Run `hook` one time on this thread, before [`MarkerDir::replace`] opens
/// its temp file. The hook gets the temp path.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_before_marker_temp_open(
    hook: impl FnOnce(&Path) + 'static,
) -> RecordPathHookGuard {
    arm_record_path_hook(&BEFORE_MARKER_TEMP_OPEN, hook)
}

/// Run `hook` one time on this thread, after [`clear_fallback_marker`]
/// checks the owner and before it removes the owned marker. The hook gets
/// the owned path.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_before_fallback_unlink(
    hook: impl FnOnce(&Path) + 'static,
) -> RecordPathHookGuard {
    arm_record_path_hook(&BEFORE_FALLBACK_UNLINK, hook)
}

/// The device number and the inode number of a file.
#[cfg(test)]
pub(crate) type FileId = (u64, u64);

/// Run `hook` one time on this thread, after the next record open and before
/// the checks of the open descriptor. The hook gets the record path.
///
/// The guard removes the hook when it drops, if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_after_record_open(hook: impl FnOnce(&Path) + 'static) -> RecordPathHookGuard {
    arm_record_path_hook(&AFTER_RECORD_OPEN, hook)
}

/// Return the device number and the inode number of the file at `path`.
#[cfg(test)]
#[cfg(unix)]
pub(crate) fn file_id(path: &Path) -> FileId {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).expect("The test must read the metadata of the file.");
    (meta.dev(), meta.ino())
}

/// Return the file of each fsync on this thread, in the order of the calls.
#[cfg(test)]
pub(crate) fn fsync_targets() -> Vec<FileId> {
    FSYNC_TARGETS.with(|targets| targets.borrow().clone())
}

/// Let the next `skip` fsyncs of the file at `path` on this thread pass.
/// Then fail each fsync of that file with `EIO`.
///
/// The guard stops these failures when it drops.
#[cfg(test)]
#[cfg(unix)]
pub(crate) fn arm_fsync_failure_for(path: &Path, skip: u32) -> FsyncTargetFailGuard {
    FSYNC_TARGET_FAILURE.with(|failure| failure.set(Some((file_id(path), skip))));
    FsyncTargetFailGuard
}

/// Add the file of this fsync to the list of fsync targets. Return `true`
/// when the injector fails this fsync.
#[cfg(test)]
#[cfg(unix)]
fn note_fsync_target(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = file.metadata() else {
        return false;
    };
    let id = (meta.dev(), meta.ino());
    FSYNC_TARGETS.with(|targets| targets.borrow_mut().push(id));
    FSYNC_TARGET_FAILURE.with(|failure| match failure.get() {
        Some((target, 0)) => target == id,
        Some((target, skip)) if target == id => {
            failure.set(Some((target, skip - 1)));
            false
        }
        _ => false,
    })
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

/// Cause the next `count` marker writes on this thread to fail. This applies
/// to calls to [`write_marker`] and [`write_fallback_marker`].
///
/// `u32::MAX` keeps failing until the guard drops. The in-place record write
/// is not affected.
#[cfg(test)]
pub(crate) fn arm_marker_write_failures(count: u32) -> MarkerWriteFailGuard {
    MARKER_WRITE_FAILS_LEFT.with(|left| left.set(count));
    MarkerWriteFailGuard
}

/// Make [`unix_secs_now`] return `secs` on this thread. A test then knows the
/// Unix time that a writer records, and the test does not read the clock.
///
/// The guard removes the override when it drops.
#[cfg(test)]
pub(crate) fn arm_unix_secs(secs: u64) -> UnixSecsGuard {
    UNIX_SECS_OVERRIDE.with(|slot| slot.set(Some(secs)));
    UnixSecsGuard
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

/// The faults of one directory for each thread of the process, also the
/// threads of the blocking pool. [`arm_dir_faults`] sets them.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct DirFaults {
    /// Each marker write in the directory fails with `StorageFull`.
    pub(crate) marker_write_fails: bool,
    /// Each fsync in the directory fails with `EIO`.
    pub(crate) fsync_fails: bool,
    /// Each fsync in the directory waits until this gate opens.
    pub(crate) fsync_gate: Option<Arc<FsyncGate>>,
    /// Each path write of a persist round with this keystore directory
    /// panics.
    pub(crate) write_panics: bool,
    /// The write of this one path of a persist round with this keystore
    /// directory waits until the gate opens.
    pub(crate) path_gate: Option<(PersistPath, Arc<FsyncGate>)>,
}

#[cfg(test)]
static DIR_FAULTS: std::sync::Mutex<Vec<(PathBuf, DirFaults)>> = std::sync::Mutex::new(Vec::new());

/// Arm `faults` for the directory `dir` in each thread of the process. A test
/// gives its own temporary directory, so parallel tests do not share faults.
///
/// The guard opens the gates and removes the faults when it drops.
#[cfg(test)]
pub(crate) fn arm_dir_faults(dir: &Path, faults: DirFaults) -> DirFaultGuard {
    let path_gate = faults.path_gate.as_ref().map(|(_, gate)| Arc::clone(gate));
    let gates = faults.fsync_gate.iter().cloned().chain(path_gate).collect();
    let mut registry = DIR_FAULTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.retain(|(armed, _)| armed != dir);
    registry.push((dir.to_path_buf(), faults));
    DirFaultGuard { dir: dir.to_path_buf(), gates }
}

/// Removes the faults of [`arm_dir_faults`] and opens their gates on drop.
#[cfg(test)]
pub(crate) struct DirFaultGuard {
    dir: PathBuf,
    gates: Vec<Arc<FsyncGate>>,
}

#[cfg(test)]
impl Drop for DirFaultGuard {
    fn drop(&mut self) {
        let mut registry = DIR_FAULTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.retain(|(armed, _)| armed != &self.dir);
        drop(registry);
        for gate in &self.gates {
            gate.open();
        }
    }
}

#[cfg(test)]
fn dir_faults(dir: &Path) -> Option<DirFaults> {
    let registry = DIR_FAULTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.iter().find(|(armed, _)| armed == dir).map(|(_, faults)| faults.clone())
}

#[cfg(test)]
fn dir_marker_write_fault(dir: &Path) -> io::Result<()> {
    match dir_faults(dir) {
        Some(faults) if faults.marker_write_fails => Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected directory marker write failure",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
fn dir_fsync_fault(dir: &Path) -> io::Result<()> {
    let Some(faults) = dir_faults(dir) else {
        return Ok(());
    };
    if let Some(gate) = &faults.fsync_gate {
        gate.wait_open(|| {});
    }
    if faults.fsync_fails {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

/// A gate that holds each thread in [`FsyncGate::wait_open`] until it opens.
/// The registry lock is not held while a thread waits.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FsyncGate {
    open: std::sync::Mutex<bool>,
    opened: std::sync::Condvar,
    blocked: AtomicUsize,
    watchdog_fired: AtomicBool,
}

#[cfg(test)]
impl FsyncGate {
    /// A closed gate that opens only by [`FsyncGate::open`] or a guard drop.
    pub(crate) fn without_watchdog() -> Arc<Self> {
        Arc::default()
    }

    /// A closed gate with an OS-thread watchdog. When the gate is still closed
    /// after `limit` of real time, the watchdog opens it and records that it
    /// fired. The watchdog is hang protection only.
    pub(crate) fn with_watchdog(limit: Duration) -> Arc<Self> {
        let gate = Self::without_watchdog();
        let watched = Arc::clone(&gate);
        std::thread::spawn(move || {
            let open = watched.lock_open();
            let (mut open, _) = watched
                .opened
                .wait_timeout_while(open, limit, |open| !*open)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !*open {
                watched.watchdog_fired.store(true, Ordering::SeqCst);
                *open = true;
                watched.opened.notify_all();
            }
        });
        gate
    }

    fn lock_open(&self) -> std::sync::MutexGuard<'_, bool> {
        self.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Open the gate and release each waiting thread.
    pub(crate) fn open(&self) {
        *self.lock_open() = true;
        self.opened.notify_all();
    }

    /// Wait until the gate opens. `parked` runs after this thread counts in
    /// [`FsyncGate::blocked`] and before it waits.
    pub(crate) fn wait_open(&self, parked: impl FnOnce()) {
        let mut open = self.lock_open();
        if *open {
            return;
        }
        self.blocked.fetch_add(1, Ordering::SeqCst);
        parked();
        while !*open {
            open = self.opened.wait(open).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        self.blocked.fetch_sub(1, Ordering::SeqCst);
    }

    /// The number of threads that wait in the gate now.
    pub(crate) fn blocked(&self) -> usize {
        self.blocked.load(Ordering::SeqCst)
    }

    /// `true` when the watchdog opened the gate.
    pub(crate) fn watchdog_fired(&self) -> bool {
        self.watchdog_fired.load(Ordering::SeqCst)
    }
}

/// Fail the next [`preallocate_detection_record`] call on this thread.
#[cfg(test)]
pub(crate) fn arm_preallocate_failure() -> PreallocateFailGuard {
    PREALLOCATE_FAILS.with(|fail| fail.set(true));
    PreallocateFailGuard
}

/// Fail each probe of the marker directory `dir` on this thread with
/// `PermissionDenied`. The probe fails before it opens the directory, so it
/// leaves no file. The hook does not change the probe of a different path.
/// The match compares the path components.
///
/// `ProbeFailGuard::drop` stops the probe failures that the hook injects.
#[cfg(test)]
pub(crate) fn arm_probe_failure(dir: &Path) -> ProbeFailGuard {
    PROBE_FAILURE_DIR.with(|slot| *slot.borrow_mut() = Some(dir.to_path_buf()));
    ProbeFailGuard
}

/// `true` when [`arm_probe_failure`] armed the directory `dir` on this thread.
#[cfg(test)]
fn probe_fails_for(dir: &Path) -> bool {
    PROBE_FAILURE_DIR.with(|slot| slot.borrow().as_deref() == Some(dir))
}

/// Return the number of marker directory probes on this thread. The number
/// includes each probe that fails.
#[cfg(test)]
pub(crate) fn probe_attempts() -> u32 {
    PROBE_ATTEMPTS.with(Cell::get)
}

/// Add one probe of the marker directory `dir` to the count of this thread.
/// Return the error of [`arm_probe_failure`] when it armed `dir`.
#[cfg(test)]
fn note_probe(dir: &Path) -> io::Result<()> {
    PROBE_ATTEMPTS.with(|count| count.set(count.get() + 1));
    if probe_fails_for(dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected marker directory probe failure",
        ));
    }
    Ok(())
}

/// A step of [`probe_fallback_dir_writable`]. The hook of [`arm_probe_step`]
/// runs immediately before the step. `Create`, `Open`, `Check` and `Remove`
/// are steps of the probe in the private subdirectory.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeStep {
    /// The probe creates its entry in the database directory.
    Create,
    /// The probe opens its entry. The entry exists at this step.
    Open,
    /// The probe checks the identity of its open entry.
    Check,
    /// The probe removes its entries. The identity check and the fsync of
    /// the probe file are complete at this step.
    Remove,
    /// The probe with no name opens its file (`O_TMPFILE`). The file has no
    /// name, so the hook gets the database directory.
    #[cfg(target_os = "linux")]
    Unnamed,
    /// The probe with no name fsyncs the database directory. The write and
    /// the fsync of its file are complete at this step. The hook gets the
    /// database directory.
    #[cfg(target_os = "linux")]
    SyncDir,
}

/// Return the number of probes on this thread that use the private
/// subdirectory. On Linux, each of these probes is a fallback from the probe
/// with no name.
#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) fn fallback_probes() -> u32 {
    FALLBACK_PROBES.with(Cell::get)
}

/// Make the next `O_TMPFILE` open of a probe on this thread fail with the
/// error number `errno`. The open runs, and the probe gets the error in
/// place of the file.
///
/// `UnnamedProbeErrorGuard::drop` removes the error if no probe used it.
#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) fn arm_unnamed_probe_error(errno: i32) -> UnnamedProbeErrorGuard {
    UNNAMED_PROBE_ERROR.with(|slot| slot.set(Some(errno)));
    UnnamedProbeErrorGuard
}

/// Take the error of [`arm_unnamed_probe_error`].
#[cfg(test)]
#[cfg(target_os = "linux")]
fn take_unnamed_probe_error() -> Option<i32> {
    UNNAMED_PROBE_ERROR.with(Cell::take)
}

/// Make the write of the next probe file with no name on this thread fail
/// with the error number `errno`. The write runs, and the probe gets the
/// error in place of the result.
///
/// `UnnamedProbeWriteErrorGuard::drop` removes the error if no probe used it.
#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) fn arm_unnamed_probe_write_error(errno: i32) -> UnnamedProbeWriteErrorGuard {
    UNNAMED_PROBE_WRITE_ERROR.with(|slot| slot.set(Some(errno)));
    UnnamedProbeWriteErrorGuard
}

/// Take the error of [`arm_unnamed_probe_write_error`].
#[cfg(test)]
#[cfg(target_os = "linux")]
fn take_unnamed_probe_write_error() -> Option<i32> {
    UNNAMED_PROBE_WRITE_ERROR.with(Cell::take)
}

/// The probe file with no name in the test build. A write gives the error of
/// [`arm_unnamed_probe_write_error`] in place of its result. Each other use
/// goes to the file through `Deref`, so the code of the probe does not change.
#[cfg(test)]
#[cfg(target_os = "linux")]
struct UnnamedProbeFile(File);

#[cfg(test)]
#[cfg(target_os = "linux")]
impl Write for UnnamedProbeFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.0.write(buf);
        take_unnamed_probe_write_error().map_or(written, |n| Err(io::Error::from_raw_os_error(n)))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
impl std::ops::Deref for UnnamedProbeFile {
    type Target = File;

    fn deref(&self) -> &File {
        &self.0
    }
}

/// Run `hook` one time on this thread, at the step `step` of
/// [`probe_fallback_dir_writable`] for the directory `dir`. The hook gets
/// the path of the probe entry in `dir`. A probe of a different path does
/// not run it.
///
/// `ProbeStepHookGuard::drop` removes the hook if the hook did not run.
#[cfg(test)]
pub(crate) fn arm_probe_step(
    dir: &Path,
    step: ProbeStep,
    hook: impl FnOnce(&Path) + 'static,
) -> ProbeStepHookGuard {
    let armed = (dir.to_path_buf(), step, Box::new(hook) as RecordPathHook);
    PROBE_STEP_HOOK.with(|slot| *slot.borrow_mut() = Some(armed));
    ProbeStepHookGuard
}

/// Run the hook of [`arm_probe_step`] when it armed `dir` and `step`. The
/// hook gets the probe entry `entry`.
#[cfg(test)]
fn run_probe_step(dir: &Path, step: ProbeStep, entry: &Path) {
    let armed = PROBE_STEP_HOOK.with(|slot| {
        slot.borrow_mut().take_if(|(at, armed, _)| at.as_path() == dir && *armed == step)
    });
    if let Some((_, _, hook)) = armed {
        hook(entry);
    }
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

/// The guard removes the Unix time override when it drops.
#[cfg(test)]
pub(crate) struct UnixSecsGuard;

#[cfg(test)]
impl Drop for UnixSecsGuard {
    fn drop(&mut self) {
        UNIX_SECS_OVERRIDE.with(|slot| slot.set(None));
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

/// `ProbeFailGuard::drop` stops the probe failures that the hook injects.
#[cfg(test)]
pub(crate) struct ProbeFailGuard;

#[cfg(test)]
impl Drop for ProbeFailGuard {
    fn drop(&mut self) {
        PROBE_FAILURE_DIR.with(|slot| *slot.borrow_mut() = None);
    }
}

/// `ProbeStepHookGuard::drop` removes the hook if the hook did not run.
#[cfg(test)]
pub(crate) struct ProbeStepHookGuard;

#[cfg(test)]
impl Drop for ProbeStepHookGuard {
    fn drop(&mut self) {
        PROBE_STEP_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

/// `UnnamedProbeErrorGuard::drop` removes the error if no probe used it.
#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) struct UnnamedProbeErrorGuard;

#[cfg(test)]
#[cfg(target_os = "linux")]
impl Drop for UnnamedProbeErrorGuard {
    fn drop(&mut self) {
        UNNAMED_PROBE_ERROR.with(|slot| slot.set(None));
    }
}

/// `UnnamedProbeWriteErrorGuard::drop` removes the error if no probe used it.
#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) struct UnnamedProbeWriteErrorGuard;

#[cfg(test)]
#[cfg(target_os = "linux")]
impl Drop for UnnamedProbeWriteErrorGuard {
    fn drop(&mut self) {
        UNNAMED_PROBE_WRITE_ERROR.with(|slot| slot.set(None));
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

/// The guard stops the injected fsync failures of one file when it drops.
#[cfg(test)]
pub(crate) struct FsyncTargetFailGuard;

#[cfg(test)]
impl Drop for FsyncTargetFailGuard {
    fn drop(&mut self) {
        FSYNC_TARGET_FAILURE.with(|failure| failure.set(None));
    }
}

/// A step of a durable write on this thread, for tests. The seam adds a
/// step for each fsync and for each exchange of a temp record with the
/// record path. [`take_durable_steps`] returns the steps.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStep {
    /// An fsync of a regular file: the device number, the inode number and
    /// the length of the file at the fsync.
    SyncFile(u64, u64, u64),
    /// An fsync of a directory: the device number and the inode number.
    SyncDir(u64, u64),
    /// An exchange of a temp record with the record path.
    Exchange,
}

/// A failure that the seam injects one time on this thread.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableFault {
    /// The fsync with this index fails with `EIO`. The first fsync after
    /// the arm has the index 0.
    Sync(u32),
    /// The next exchange of a temp record with the record path fails with
    /// `EIO`. The exchange does not occur.
    Exchange,
    /// The next read of the record by [`reset_or_replace_detection_record`]
    /// fails with `EIO`.
    RecordRead,
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static DURABLE_STEPS: RefCell<Vec<DurableStep>> = const { RefCell::new(Vec::new()) };
    static DURABLE_FAULT: Cell<Option<DurableFault>> = const { Cell::new(None) };
    static BEFORE_RECORD_EXCHANGE: RefCell<Option<RecordPathHook>> = const { RefCell::new(None) };
}

/// Return the durable steps of this thread since the last call. The seam
/// then has no steps.
#[cfg(any(test, feature = "test-utils"))]
pub fn take_durable_steps() -> Vec<DurableStep> {
    DURABLE_STEPS.with(RefCell::take)
}

/// Inject `fault` one time on this thread. A new arm replaces a fault that
/// did not occur.
#[cfg(any(test, feature = "test-utils"))]
pub fn arm_durable_fault(fault: DurableFault) {
    DURABLE_FAULT.with(|slot| slot.set(Some(fault)));
}

/// Run `hook` one time on this thread, after the clear temp record is
/// durable and before its exchange with the record path. The hook gets the
/// record path.
#[cfg(any(test, feature = "test-utils"))]
pub fn arm_before_record_exchange(hook: impl FnOnce(&Path) + 'static) {
    BEFORE_RECORD_EXCHANGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(any(test, feature = "test-utils"))]
fn run_before_record_exchange(path: &Path) {
    let hook = BEFORE_RECORD_EXCHANGE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

/// `true` when the armed fault is `fault`. The fault then does not occur
/// again.
#[cfg(any(test, feature = "test-utils"))]
fn take_durable_fault(fault: DurableFault) -> bool {
    DURABLE_FAULT.with(|slot| {
        let armed = slot.get() == Some(fault);
        if armed {
            slot.set(None);
        }
        armed
    })
}

/// Add the step of this fsync. Return `true` when the armed fault fails
/// this fsync.
#[cfg(any(test, feature = "test-utils"))]
fn note_durable_sync(file: &File) -> bool {
    #[cfg(unix)]
    if let Ok(meta) = file.metadata() {
        use std::os::unix::fs::MetadataExt;
        let step = if meta.is_dir() {
            DurableStep::SyncDir(meta.dev(), meta.ino())
        } else {
            DurableStep::SyncFile(meta.dev(), meta.ino(), meta.len())
        };
        DURABLE_STEPS.with(|steps| steps.borrow_mut().push(step));
    }
    DURABLE_FAULT.with(|slot| match slot.get() {
        Some(DurableFault::Sync(0)) => {
            slot.set(None);
            true
        }
        Some(DurableFault::Sync(index)) => {
            slot.set(Some(DurableFault::Sync(index - 1)));
            false
        }
        _ => false,
    })
}

/// Fsync `file`, an entry of the directory `dir` or `dir` itself. A test
/// arms faults for `dir` with [`arm_dir_faults`].
fn sync_file(file: &File, dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    dir_fsync_fault(dir)?;
    #[cfg(not(test))]
    let _ = dir;
    #[cfg(test)]
    FSYNC_CALLS.with(|calls| calls.set(calls.get() + 1));
    #[cfg(all(test, unix))]
    if note_fsync_target(file) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    #[cfg(test)]
    if take_fsync_failure() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    #[cfg(any(test, feature = "test-utils"))]
    if note_durable_sync(file) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    file.sync_all()
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    let path = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    sync_file(&File::open(path)?, dir)
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

/// The owner that a valid marker records. `Err` when `bytes` is not a marker
/// that [`parse_marker`] accepts.
fn marker_owner(bytes: &[u8]) -> Result<Option<String>, String> {
    parse_marker(bytes)?;
    let doc: MarkerDocument =
        serde_json::from_slice(bytes).map_err(|e| format!("marker json: {e}"))?;
    Ok(doc.keystore_dir)
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

    /// The `io::Error` of a path result. A test that calls this expects no
    /// [`PersistError::TimedOut`].
    fn io_result(result: &Result<(), PersistError>) -> Result<(), &io::Error> {
        match result {
            Ok(()) => Ok(()),
            Err(PersistError::Io(err)) => Err(err),
            Err(PersistError::TimedOut) => panic!("The path must not time out."),
        }
    }

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

    /// The fallback directory is the parent of the database, or `.` for a
    /// bare file name. The selection compares the directories that the walk
    /// opens. [`arm_walk_start`] gives the working directory of each walk.
    /// The test requires these results:
    ///
    /// - The names `slashing.sqlite` and `./slashing.sqlite` select `.` and
    ///   the same marker when the working directory is not the keystore
    ///   directory.
    /// - A database in a different directory selects that directory.
    /// - A database in the keystore directory selects no directory. A bare
    ///   file name and a relative path of the keystore directory give the
    ///   same result.
    #[cfg(unix)]
    #[test]
    fn fallback_dir_is_the_slashing_parent_only_when_it_differs() {
        let (root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let selected = |name: &str| {
            FallbackMarkerPath::for_config(&keys, Path::new(name))
                .map(|found| (found.dir.clone(), found.owned_path()))
        };
        let in_cwd = Some((
            PathBuf::from("."),
            PathBuf::from("./.rvc.doppelganger_detected.slashing.sqlite"),
        ));
        let start = arm_walk_start(&slash);

        assert_eq!(
            [selected("slashing.sqlite"), selected("./slashing.sqlite")],
            [in_cwd.clone(), in_cwd],
            "The names slashing.sqlite and ./slashing.sqlite must select the working directory \
             and the same marker."
        );
        assert_eq!(
            fallback_marker_dir(&keys, &slash.join("slashing.sqlite")).as_deref(),
            Some(slash.as_path()),
            "A database in a different directory must select that directory."
        );
        assert_eq!(
            fallback_marker_dir(&keys, &keys.join("slashing.sqlite")),
            None,
            "A database in the keystore directory must select no directory."
        );
        drop(start);
        let start = arm_walk_start(&keys);
        assert_eq!(
            fallback_marker_dir(&keys, Path::new("slashing.sqlite")),
            None,
            "A bare file name must select no directory when the working directory is the \
             keystore directory."
        );
        drop(start);
        let _start = arm_walk_start(root.path());
        assert_eq!(
            fallback_marker_dir(&keys, Path::new("keys/slashing.sqlite")),
            None,
            "A relative path of the keystore directory must select no directory."
        );
    }

    /// `fallback_marker_dir` uses `.` as the directory of a bare file name.
    /// [`arm_walk_start`] gives the working directory of each walk. The test
    /// requires these results:
    ///
    /// - When the keystore is in a different directory, the names
    ///   `slashing.sqlite` and `./slashing.sqlite` select `.`.
    /// - When the keystore is `.`, the two names select no directory.
    #[cfg(unix)]
    #[test]
    fn fallback_dir_treats_an_empty_parent_as_cwd() {
        let (_root, [keys, cwd]) = temp_dirs(["keys", "cwd"]);
        let _start = arm_walk_start(&cwd);
        let selected = |keystore: &Path| {
            ["slashing.sqlite", "./slashing.sqlite"]
                .map(|name| fallback_marker_dir(keystore, Path::new(name)))
        };

        assert_eq!(
            selected(&keys),
            [Some(PathBuf::from(".")), Some(PathBuf::from("."))],
            "For a keystore in a different directory, `fallback_marker_dir` must return \
             `Some(\".\")` for each name."
        );
        assert_eq!(
            selected(Path::new(".")),
            [None, None],
            "For a keystore in `.`, `fallback_marker_dir` must return `None` for each name."
        );
    }

    /// The reader returns `Present` for a version-1 marker without
    /// `keystore_dir`.
    #[test]
    fn marker_without_keystore_dir_still_parses() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        fs::write(
            marker_path(dir.path()),
            format!(r#"{{"version":1,"epoch":5,"unix_secs":6,"pubkeys":["{}"]}}"#, pubkey()),
        )
        .expect("The test must write the marker.");
        let expected = DetectionMarker { epoch: 5, unix_secs: 6, pubkeys: vec![pubkey()] };

        let inspected = inspect(dir.path());

        assert!(
            matches!(&inspected, MarkerInspect::Present(marker) if *marker == expected),
            "The reader must return Present for a version-1 marker without keystore_dir. The \
             result is {inspected:?}."
        );
    }

    /// The reader returns `Corrupt` for a field that the document does not define.
    #[test]
    fn marker_with_an_unknown_field_is_corrupt() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        fs::write(
            marker_path(dir.path()),
            br#"{"version":1,"epoch":5,"unix_secs":6,"pubkeys":[],"foo":1}"#,
        )
        .expect("The test must write the marker.");

        let inspected = inspect(dir.path());

        assert!(
            matches!(inspected, MarkerInspect::Corrupt { .. }),
            "The reader must return Corrupt for the unknown field foo. The result is {inspected:?}."
        );
    }

    /// The marker file name must contain the legacy name, a dot, and the
    /// database file name. The path must use the database directory.
    #[test]
    fn fallback_marker_name_appends_the_db_file_name() {
        let fallback = FallbackMarkerPath {
            dir: PathBuf::from("/srv/db"),
            slashing_db_path: PathBuf::from("/srv/db/a.sqlite"),
        };

        assert_eq!(
            fallback.owned_path(),
            PathBuf::from("/srv/db/.rvc.doppelganger_detected.a.sqlite"),
            "The path must be in the database directory. The file name must contain the legacy \
             name, a dot, and the database file name."
        );
    }

    /// A marker with one key for the fallback tests.
    fn sample_marker() -> DetectionMarker {
        DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![pubkey()] }
    }

    /// Create the directories `names` in a new temporary directory. Return
    /// the temporary directory and the paths of the new directories.
    fn temp_dirs<const N: usize>(names: [&str; N]) -> (tempfile::TempDir, [PathBuf; N]) {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let paths = names.map(|name| root.path().join(name));
        for path in &paths {
            fs::create_dir(path).expect("The test must create a directory.");
        }
        (root, paths)
    }

    /// The fallback path of `a.sqlite` in `slash` for the keystore `keys`.
    fn fallback_of(keys: &Path, slash: &Path) -> FallbackMarkerPath {
        FallbackMarkerPath::for_config(keys, &slash.join("a.sqlite"))
            .expect("The test must find a fallback path beside the database.")
    }

    /// Try the fallback lock of `dir` through a new open file description.
    /// Return `true` when the try gets the lock.
    fn try_fallback_lock(dir: &Path) -> bool {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(FALLBACK_LOCK_FILENAME))
            .expect("The test must open the fallback lock file.");
        fd_lock::RwLock::new(file).try_write().is_ok()
    }

    /// Return the text of an `InvalidData` error, or a text that names the
    /// other result.
    fn invalid_data_text(result: io::Result<Vec<FallbackClear>>) -> String {
        match result {
            Err(err) if err.kind() == io::ErrorKind::InvalidData => err.to_string(),
            other => format!("The result is not InvalidData: {other:?}"),
        }
    }

    /// `clear_fallback_marker` reads the owner of the owned marker. The test
    /// requires these results:
    ///
    /// 1. When a different keystore owns the marker, the function keeps the
    ///    marker. It returns the marker path and the absolute path of that
    ///    keystore.
    /// 2. When this keystore owns the marker and a legacy marker exists, the
    ///    function keeps the two markers. It returns `InvalidData` with the
    ///    legacy path and the recovery step.
    /// 3. When only the marker of this keystore exists, the function removes
    ///    it.
    /// 4. When the marker records no owner, the function keeps it. It returns
    ///    `InvalidData` with the marker path and the recovery step.
    /// 5. When the marker has invalid JSON, the function keeps it. It returns
    ///    `InvalidData` with the marker path.
    #[test]
    fn clear_fallback_marker_removes_only_an_owned_marker_of_this_keystore() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keys");
        let other = root.path().join("other");
        let slash = root.path().join("slash");
        for dir in [&keys, &other, &slash] {
            fs::create_dir(dir).expect("The test must create a directory.");
        }
        let fallback = FallbackMarkerPath::for_config(&keys, &slash.join("a.sqlite"))
            .expect("The test must find a fallback path beside the database.");
        let owned = fallback.owned_path();
        let marker = DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![pubkey()] };
        let absolute_other = std::path::absolute(&other)
            .expect("The test must make the path of the other keystore absolute.")
            .to_string_lossy()
            .into_owned();

        write_fallback_marker(&fallback, &other.join("."), &marker)
            .expect("The test must write the marker of the other keystore.");
        assert_eq!(
            clear_fallback_marker(&fallback, &keys).map_err(|err| err.to_string()),
            Ok(vec![FallbackClear::OtherOwner { path: owned.clone(), owner: absolute_other }]),
            "The function must keep the marker of the other keystore and return the absolute \
             path of that keystore."
        );
        assert!(
            matches!(inspect_at(&owned), MarkerInspect::Present(_)),
            "The function must keep the marker of the other keystore."
        );

        fs::remove_file(&owned).expect("The test must remove the marker of the other keystore.");
        write_fallback_marker(&fallback, &keys, &marker)
            .expect("The test must write the marker of this keystore.");
        write_marker(&slash, &marker).expect("The test must write a legacy marker.");
        let text = invalid_data_text(clear_fallback_marker(&fallback, &keys));
        assert!(
            text.contains(&marker_path(&slash).display().to_string())
                && text.contains("records no owner")
                && text.contains("clear-detection"),
            "The function must return InvalidData with the legacy path and the recovery step. \
             The text is: {text}"
        );
        let after = inspect_fallback(&fallback);
        assert!(
            matches!(after.owned, MarkerInspect::Present(_))
                && matches!(after.legacy, MarkerInspect::Present(_)),
            "The function must keep the two markers. The result is {after:?}."
        );

        fs::remove_file(marker_path(&slash)).expect("The test must remove the legacy marker.");
        assert_eq!(
            clear_fallback_marker(&fallback, &keys).map_err(|err| err.to_string()),
            Ok(vec![FallbackClear::Removed { path: owned.clone() }]),
            "The function must remove the marker of this keystore."
        );
        assert!(
            matches!(inspect_at(&owned), MarkerInspect::Absent),
            "The marker of this keystore must be absent."
        );

        let no_owner = br#"{"version":1,"epoch":1,"unix_secs":2,"pubkeys":[]}"#;
        fs::write(&owned, no_owner).expect("The test must write a marker with no owner.");
        let text = invalid_data_text(clear_fallback_marker(&fallback, &keys));
        assert!(
            text.contains(&owned.display().to_string())
                && text.contains("records no owner")
                && text.contains("clear-detection"),
            "The function must return InvalidData with the marker path and the recovery step \
             for a marker with no owner. The text is: {text}"
        );
        assert_eq!(
            fs::read(&owned).map_err(|err| err.to_string()),
            Ok(no_owner.to_vec()),
            "The function must keep the marker with no owner."
        );

        fs::write(&owned, b"{").expect("The test must write a marker with invalid JSON.");
        let text = invalid_data_text(clear_fallback_marker(&fallback, &keys));
        assert!(
            text.contains(&owned.display().to_string()) && text.contains("does not parse"),
            "The function must return InvalidData with the path of the marker with invalid JSON. \
             The text is: {text}"
        );
        assert_eq!(
            fs::read(&owned).map_err(|err| err.to_string()),
            Ok(b"{".to_vec()),
            "The function must keep the marker with invalid JSON."
        );
    }

    /// A directory is at the owned path, and a legacy marker exists. The
    /// test requires these results:
    ///
    /// - The clear returns `InvalidData` with the owned path. The error says
    ///   that the marker cannot be read.
    /// - The directory at the owned path stays.
    /// - The legacy marker stays.
    #[test]
    fn clear_fallback_marker_keeps_an_unreadable_owned_entry() {
        let (_root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let fallback = fallback_of(&keys, &slash);
        let owned = fallback.owned_path();
        fs::create_dir(&owned).expect("The test must create a directory at the owned path.");
        write_marker(&slash, &sample_marker()).expect("The test must write a legacy marker.");

        let text = invalid_data_text(clear_fallback_marker(&fallback, &keys));

        assert!(
            text.contains(&owned.display().to_string()) && text.contains("cannot be read"),
            "The clear must return InvalidData with the owned path. The text is: {text}"
        );
        assert!(owned.is_dir(), "The directory at the owned path must stay.");
        assert!(
            matches!(inspect(&slash), MarkerInspect::Present(_)),
            "The legacy marker must stay."
        );
    }

    /// The file names of databases A and B are different only in a byte
    /// that is not valid UTF-8, so the lossy strings of the two names are
    /// the same. The test requires these results:
    ///
    /// - The owned paths of A and B are different.
    /// - The marker of A does not show at the owned path of B.
    /// - A clear for B finds no marker, and the marker of A stays.
    #[cfg(unix)]
    #[test]
    fn fallback_names_keep_the_native_bytes_of_the_db_file_name() {
        use std::os::unix::ffi::OsStrExt;
        let (_root, [keys_a, keys_b, slash]) = temp_dirs(["a", "b", "slash"]);
        let db = |name: &[u8]| slash.join(std::ffi::OsStr::from_bytes(name));
        let fallback_a = FallbackMarkerPath::for_config(&keys_a, &db(b"a\xff.sqlite"))
            .expect("The configuration of A must have a fallback path.");
        let fallback_b = FallbackMarkerPath::for_config(&keys_b, &db(b"a\xfe.sqlite"))
            .expect("The configuration of B must have a fallback path.");

        assert_ne!(
            fallback_a.owned_path(),
            fallback_b.owned_path(),
            "Databases A and B must have different owned paths."
        );
        write_fallback_marker(&fallback_a, &keys_a, &sample_marker())
            .expect("The test must write the marker of database A.");
        assert!(
            matches!(inspect_fallback(&fallback_b).owned, MarkerInspect::Absent),
            "The marker of database A must not show at the owned path of database B."
        );
        assert_eq!(
            clear_fallback_marker(&fallback_b, &keys_b).map_err(|err| err.to_string()),
            Ok(vec![]),
            "A clear for database B must find no marker."
        );
        assert!(
            matches!(inspect_fallback(&fallback_a).owned, MarkerInspect::Present(_)),
            "The marker of database A must stay."
        );
    }

    /// The keystore path `keys` is relative. The directory does not exist in
    /// the working directory of the writer. The test requires these results:
    ///
    /// - The write succeeds.
    /// - A clear from a different working directory keeps the marker. It
    ///   returns the absolute keystore path that the writer resolved.
    /// - After the keystore directory exists in the working directory of
    ///   the writer, a clear from that directory removes the marker.
    #[test]
    fn fallback_owner_of_a_relative_keystore_is_resolved_at_write_time() {
        let (_root, [writer, other, slash]) = temp_dirs(["writer", "other", "slash"]);
        fs::create_dir(other.join("keys"))
            .expect("The test must create the keystore in the other directory.");
        let fallback =
            FallbackMarkerPath { dir: slash.clone(), slashing_db_path: slash.join("a.sqlite") };
        let owned = fallback.owned_path();
        let owner = fs::canonicalize(&writer)
            .expect("The test must read the canonical path of the writer directory.")
            .join("keys")
            .into_os_string()
            .into_string()
            .expect("The test path must be valid UTF-8.");
        let keys = Path::new("keys");
        let start = std::env::current_dir().expect("The test must read the working directory.");

        std::env::set_current_dir(&writer).expect("The test must change the working directory.");
        let written = write_fallback_marker(&fallback, keys, &sample_marker());
        std::env::set_current_dir(&other).expect("The test must change the working directory.");
        let from_other = clear_fallback_marker(&fallback, keys).map_err(|err| err.to_string());
        let kept = matches!(inspect_at(&owned), MarkerInspect::Present(_));
        std::env::set_current_dir(&writer).expect("The test must change the working directory.");
        fs::create_dir(keys).expect("The test must create the keystore of the writer.");
        let from_writer = clear_fallback_marker(&fallback, keys).map_err(|err| err.to_string());
        std::env::set_current_dir(start).expect("The test must restore the working directory.");

        assert!(written.is_ok(), "The write must succeed. The result is {written:?}.");
        assert_eq!(
            from_other,
            Ok(vec![FallbackClear::OtherOwner { path: owned.clone(), owner }]),
            "A clear from a different working directory must return the absolute keystore \
             path that the writer resolved."
        );
        assert!(kept, "A clear from a different working directory must keep the marker.");
        assert_eq!(
            from_writer,
            Ok(vec![FallbackClear::Removed { path: owned }]),
            "A clear from the working directory of the writer must remove the marker."
        );
    }

    /// The keystore directory `keys-\xff` is not valid UTF-8. Its lossy
    /// string is the name of a different directory, `keys-\u{FFFD}`. The
    /// marker cannot record that owner without loss, so it records no owner.
    /// For a clear for each of the two directories, the test requires these
    /// results:
    ///
    /// - The clear returns `InvalidData` with the marker path.
    /// - The marker stays.
    #[cfg(unix)]
    #[test]
    fn fallback_owner_that_is_not_utf8_keeps_the_marker() {
        use std::os::unix::ffi::OsStrExt;
        let (root, [slash]) = temp_dirs(["slash"]);
        let native = root.path().join(std::ffi::OsStr::from_bytes(b"keys-\xff"));
        let lossy = root.path().join("keys-\u{FFFD}");
        for dir in [&native, &lossy] {
            fs::create_dir(dir).expect("The test must create a keystore directory.");
        }
        let fallback = fallback_of(&native, &slash);
        let owned = fallback.owned_path();
        write_fallback_marker(&fallback, &native, &sample_marker())
            .expect("The test must write the marker.");

        for keys in [&lossy, &native] {
            let text = invalid_data_text(clear_fallback_marker(&fallback, keys));
            assert!(
                text.contains(&owned.display().to_string()) && text.contains("records no owner"),
                "A clear for {} must return InvalidData with the marker path, because the \
                 marker records no owner. The text is: {text}",
                keys.display()
            );
            assert!(
                matches!(inspect_at(&owned), MarkerInspect::Present(_)),
                "The marker must stay after a clear for {}.",
                keys.display()
            );
        }
    }

    /// Each row gives one state of the fallback paths: a missing database
    /// directory, a file in the path of the directory, or a symlink at the
    /// owned path. For each row, the read must give `Unreadable` and the
    /// clear must fail.
    #[cfg(unix)]
    #[test]
    fn fallback_reads_fail_closed_for_each_directory_state() {
        let (root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        fs::write(root.path().join("file"), b"x").expect("The test must write a file.");
        std::os::unix::fs::symlink("missing", slash.join(".rvc.doppelganger_detected.a.sqlite"))
            .expect("The test must create a symlink at the owned path.");
        let rows = [
            ("a missing directory", root.path().join("missing")),
            ("a directory path under a file", root.path().join("file").join("db")),
            ("a symlink at the owned path", slash),
        ];
        for (case, dir) in rows {
            let fallback = FallbackMarkerPath { slashing_db_path: dir.join("a.sqlite"), dir };
            let owned = inspect_fallback(&fallback).owned;
            let cleared = clear_fallback_marker(&fallback, &keys).map_err(|err| err.to_string());
            assert!(
                matches!(owned, MarkerInspect::Unreadable { .. }) && cleared.is_err(),
                "The read must give Unreadable and the clear must fail for {case}. The results \
                 are {owned:?} and {cleared:?}."
            );
        }
    }

    /// The owned fallback marker of `<real>/slash/a.sqlite` exists. Each row
    /// gives a second path of the database directory: a symlink in an
    /// intermediate component, a symlink at the last component, or a `..`
    /// component. For each row, the test requires these results:
    ///
    /// - The read gives `Unreadable` for the owned marker and the legacy
    ///   marker.
    /// - The write and the clear fail.
    /// - The marker keeps its bytes.
    #[cfg(unix)]
    #[test]
    fn fallback_paths_with_a_symlink_or_a_parent_name_are_refused() {
        let (root, [keys, real]) = temp_dirs(["keys", "real"]);
        let slash = real.join("slash");
        fs::create_dir(&slash).expect("The test must create the database directory.");
        let fallback = fallback_of(&keys, &slash);
        write_fallback_marker(&fallback, &keys, &sample_marker())
            .expect("The test must write the marker.");
        let before = fs::read(fallback.owned_path()).map_err(|err| err.to_string());
        std::os::unix::fs::symlink(&real, root.path().join("link"))
            .expect("The test must create a symlink to the parent directory.");
        std::os::unix::fs::symlink(&slash, real.join("slash-link"))
            .expect("The test must create a symlink to the database directory.");
        let rows = [
            ("a symlink in an intermediate component", root.path().join("link").join("slash")),
            ("a symlink at the last component", real.join("slash-link")),
            ("a `..` component", keys.join("..").join("real").join("slash")),
        ];
        for (case, dir) in rows {
            let alias = FallbackMarkerPath { slashing_db_path: dir.join("a.sqlite"), dir };
            let update = DetectionMarker { epoch: 9, ..sample_marker() };

            let found = inspect_fallback(&alias);
            let written = write_fallback_marker(&alias, &keys, &update).map_err(|e| e.to_string());
            let cleared = clear_fallback_marker(&alias, &keys).map_err(|err| err.to_string());

            assert!(
                matches!(found.owned, MarkerInspect::Unreadable { .. })
                    && matches!(found.legacy, MarkerInspect::Unreadable { .. }),
                "The read must give Unreadable for the two markers for {case}. The result is \
                 {found:?}."
            );
            assert!(
                written.is_err() && cleared.is_err(),
                "The write and the clear must fail for {case}. The results are {written:?} and \
                 {cleared:?}."
            );
            assert_eq!(
                fs::read(fallback.owned_path()).map_err(|err| err.to_string()),
                before,
                "The marker must keep its bytes after the steps for {case}."
            );
        }
    }

    /// A symlink can make two paths of one directory. The walk does not
    /// follow it, so the selection cannot show that the database directory
    /// is the keystore directory. The owned marker of `a.sqlite` is in `keys`
    /// and in `slash`. Each row gives a configuration with a symlink:
    ///
    /// - The database directory is a symlink to the keystore directory.
    /// - The keystore path is a symlink to the database directory.
    ///
    /// For each row, the test requires these results:
    ///
    /// - The selection gives the configured database directory.
    /// - The read does not give `Absent` for the owned marker.
    /// - The clear fails.
    #[cfg(unix)]
    #[test]
    fn fallback_selection_does_not_skip_a_directory_behind_a_symlink() {
        let (root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let (keys_link, slash_link) =
            (root.path().join("keys-link"), root.path().join("slash-link"));
        std::os::unix::fs::symlink(&keys, &slash_link)
            .expect("The test must create a symlink to the keystore directory.");
        std::os::unix::fs::symlink(&slash, &keys_link)
            .expect("The test must create a symlink to the database directory.");
        let no_owner = br#"{"version":1,"epoch":1,"unix_secs":2,"pubkeys":[]}"#;
        for dir in [&keys, &slash] {
            fs::write(dir.join(fallback_marker_name(Path::new("a.sqlite"))), no_owner)
                .expect("The test must write the owned marker.");
        }
        let rows = [
            ("a database directory that is a symlink to the keystore", &keys, &slash_link),
            ("a keystore path that is a symlink to the database directory", &keys_link, &slash),
        ];
        for (case, keystore, dir) in rows {
            let selected = FallbackMarkerPath::for_config(keystore, &dir.join("a.sqlite"));
            assert_eq!(
                selected.as_ref().map(|found| &found.dir),
                Some(dir),
                "The selection must give the database directory for {case}. The result is \
                 {selected:?}."
            );
            let fallback = selected.expect("The selection must give a directory.");

            let found = inspect_fallback(&fallback);
            let cleared = clear_fallback_marker(&fallback, keystore).map_err(|err| err.to_string());

            assert!(
                !matches!(found.owned, MarkerInspect::Absent),
                "The read must not give Absent for the owned marker for {case}. The result is \
                 {found:?}."
            );
            assert!(cleared.is_err(), "The clear must fail for {case}. The result is {cleared:?}.");
        }
    }

    /// The keystore path `keys-link` is a symlink to `keys`. The writer
    /// records the keystore path as an absolute path and does not resolve
    /// the symlink. The test requires these results:
    ///
    /// - A clear for `keys` keeps the marker. It returns the path of
    ///   `keys-link` as the owner.
    /// - A clear for `keys-link/` (with a trailing slash) removes the marker.
    #[cfg(unix)]
    #[test]
    fn fallback_owner_keeps_a_symlink_in_the_keystore_path() {
        let (root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let link = root.path().join("keys-link");
        std::os::unix::fs::symlink(&keys, &link)
            .expect("The test must create a symlink to the keystore directory.");
        let fallback = fallback_of(&keys, &slash);
        let owned = fallback.owned_path();
        let owner = link.to_str().expect("The test path must be valid UTF-8.").to_string();
        write_fallback_marker(&fallback, &link, &sample_marker())
            .expect("The test must write the marker.");

        assert_eq!(
            clear_fallback_marker(&fallback, &keys).map_err(|err| err.to_string()),
            Ok(vec![FallbackClear::OtherOwner { path: owned.clone(), owner }]),
            "A clear for keys must keep the marker and return the path of the symlink as the \
             owner."
        );
        assert_eq!(
            clear_fallback_marker(&fallback, &link.join("")).map_err(|err| err.to_string()),
            Ok(vec![FallbackClear::Removed { path: owned }]),
            "A clear for the path of the symlink with a trailing slash must remove the marker."
        );
    }

    /// A directory is at the keystore marker path, so the rename of the
    /// write fails. The write must return an error, and its temp file must
    /// not stay.
    #[test]
    fn marker_write_reports_a_failed_rename_and_removes_its_temp_file() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        fs::create_dir_all(marker_path(dir.path()).join("entry"))
            .expect("The test must create a directory at the marker path.");

        let result = write_marker(dir.path(), &sample_marker());

        let names: Vec<String> = fs::read_dir(dir.path())
            .expect("The test must read the directory.")
            .map(|entry| entry.expect("The test must read an entry.").file_name().into_string())
            .collect::<Result<_, _>>()
            .expect("The names must be valid UTF-8.");
        assert!(result.is_err(), "The write must fail. The result is {result:?}.");
        assert_eq!(names, [MARKER_FILENAME], "The temp file of the write must not stay.");
    }

    /// The owned path of `a.sqlite` holds an entry that is not a marker of
    /// the keystore `keys`. Each row requires these results:
    ///
    /// - `write_fallback_marker` for `keys` returns `AlreadyExists` with the
    ///   owned path.
    /// - The entry stays and does not change.
    ///
    /// After the rows, the owned path holds a marker of `keys`. A write for
    /// `keys` must replace that marker.
    #[test]
    fn fallback_write_replaces_only_a_marker_of_the_same_keystore() {
        let (_root, [keys, other, slash]) = temp_dirs(["keys", "other", "slash"]);
        let fallback = fallback_of(&keys, &slash);
        let owned = fallback.owned_path();
        let other_owner = fs::canonicalize(&other)
            .expect("The test must read the canonical path of the other keystore.")
            .into_os_string()
            .into_string()
            .expect("The test path must be valid UTF-8.");
        let rows: [(&str, Option<String>); 5] = [
            ("a slashing database file", Some("SQLite format 3\0".to_string())),
            (
                "a marker of another keystore",
                Some(format!(
                    r#"{{"version":1,"epoch":1,"unix_secs":2,"pubkeys":[],"keystore_dir":"{other_owner}"}}"#
                )),
            ),
            (
                "a marker that records no owner",
                Some(r#"{"version":1,"epoch":1,"unix_secs":2,"pubkeys":[]}"#.to_string()),
            ),
            ("a file that does not parse", Some("{".to_string())),
            ("a directory", None),
        ];
        for (case, text) in rows {
            let made = match &text {
                Some(text) => fs::write(&owned, text),
                None => fs::create_dir(&owned),
            };
            made.expect("The test must create the entry at the owned path.");

            let result = write_fallback_marker(&fallback, &keys, &sample_marker())
                .map_err(|err| (err.kind(), err.to_string()));

            assert!(
                matches!(
                    &result,
                    Err((io::ErrorKind::AlreadyExists, message))
                        if message.contains(&owned.display().to_string())
                ),
                "The write must return AlreadyExists with the owned path for {case}. The \
                 result is {result:?}."
            );
            if let Some(text) = text {
                assert_eq!(
                    fs::read_to_string(&owned).map_err(|err| err.to_string()),
                    Ok(text),
                    "The write must not change {case}."
                );
                fs::remove_file(&owned).expect("The test must remove the entry.");
            } else {
                assert!(owned.is_dir(), "The write must not change {case}.");
                fs::remove_dir(&owned).expect("The test must remove the entry.");
            }
        }

        write_fallback_marker(&fallback, &keys, &sample_marker())
            .expect("The test must write the marker of keys.");
        let update = DetectionMarker { epoch: 9, ..sample_marker() };
        assert_eq!(
            write_fallback_marker(&fallback, &keys, &update).map_err(|err| err.to_string()),
            Ok(()),
            "The write must replace a marker of the same keystore."
        );
        assert!(
            matches!(inspect_at(&owned), MarkerInspect::Present(marker) if marker == update),
            "The owned path must hold the second marker."
        );
    }

    /// Before the exclusive open of the temp file, the hook creates an entry at
    /// the temp path. A marker of the same keystore is at the owned path. The
    /// write must fail, and the entry and the marker must keep their bytes.
    #[test]
    fn fallback_write_keeps_an_entry_that_it_did_not_create() {
        let (_root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let fallback = fallback_of(&keys, &slash);
        write_fallback_marker(&fallback, &keys, &sample_marker())
            .expect("The test must write the first marker.");
        let before = fs::read(fallback.owned_path()).map_err(|err| err.to_string());
        let temp = std::rc::Rc::new(std::cell::RefCell::new(PathBuf::new()));
        let seen = std::rc::Rc::clone(&temp);
        let _hook = arm_before_marker_temp_open(move |path| {
            fs::write(path, b"other entry")
                .expect("The hook must create an entry at the temp path.");
            *seen.borrow_mut() = path.to_path_buf();
        });

        let result = write_fallback_marker(
            &fallback,
            &keys,
            &DetectionMarker { epoch: 9, ..sample_marker() },
        );

        let temp = temp.borrow().clone();
        assert!(
            result.is_err(),
            "The write must fail when an entry is at the temp path. The result is {result:?}."
        );
        assert_eq!(
            fs::read(&temp).map_err(|err| err.to_string()),
            Ok(b"other entry".to_vec()),
            "The entry at the temp path {} must keep its bytes.",
            temp.display()
        );
        assert_eq!(
            fs::read(fallback.owned_path()).map_err(|err| err.to_string()),
            before,
            "The owned marker must keep its bytes."
        );
    }

    /// Return a hook and the cell of its result. The hook tries the fallback
    /// lock of `slash` and puts the result in the cell. Then it moves `slash`
    /// to `moved` and creates a new empty directory at `slash`.
    fn lock_try_then_move(
        slash: &Path,
        moved: &Path,
    ) -> (std::rc::Rc<Cell<Option<bool>>>, impl FnOnce(&Path) + 'static) {
        let attempt = std::rc::Rc::new(Cell::new(None));
        let seen = std::rc::Rc::clone(&attempt);
        let (from, to) = (slash.to_path_buf(), moved.to_path_buf());
        let hook = move |_: &Path| {
            seen.set(Some(try_fallback_lock(&from)));
            fs::rename(&from, &to).expect("The hook must move the database directory.");
            fs::create_dir(&from).expect("The hook must create a new directory at the old path.");
        };
        (attempt, hook)
    }

    /// A hook runs in the write before the temp open, and in the clear
    /// before the unlink. Each hook tries the fallback lock. Then it moves
    /// the database directory and creates a new empty directory at the old
    /// path. The test requires these results:
    ///
    /// - Each lock try fails.
    /// - The write puts the marker in the directory that it opened.
    /// - The clear removes the marker from the directory that it opened.
    #[test]
    fn fallback_write_and_clear_hold_the_lock_and_one_directory_handle() {
        let (root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let (first, second) = (root.path().join("first"), root.path().join("second"));
        let fallback = fallback_of(&keys, &slash);
        let name = fallback_marker_name(&fallback.slashing_db_path);

        let (write_try, hook) = lock_try_then_move(&slash, &first);
        let _write_hook = arm_before_marker_temp_open(hook);
        let written = write_fallback_marker(&fallback, &keys, &sample_marker())
            .map_err(|err| err.to_string());
        let in_first = matches!(inspect_at(&first.join(&name)), MarkerInspect::Present(_));
        fs::remove_dir_all(&slash).expect("The test must remove the new directory.");
        fs::rename(&first, &slash).expect("The test must move the database directory back.");
        let (clear_try, hook) = lock_try_then_move(&slash, &second);
        let _clear_hook = arm_before_fallback_unlink(hook);
        let cleared = clear_fallback_marker(&fallback, &keys).map_err(|err| err.to_string());

        assert_eq!(write_try.get(), Some(false), "The lock try in the write must fail.");
        assert_eq!(written, Ok(()), "The write must succeed.");
        assert!(in_first, "The write must put the marker in the directory that it opened.");
        assert_eq!(clear_try.get(), Some(false), "The lock try in the clear must fail.");
        assert_eq!(
            cleared,
            Ok(vec![FallbackClear::Removed { path: fallback.owned_path() }]),
            "The clear must remove the marker of keys."
        );
        assert!(
            matches!(inspect_at(&second.join(&name)), MarkerInspect::Absent),
            "The clear must remove the marker from the directory that it opened."
        );
    }

    /// `check_slashing_db_name` checks the file name of the database. Each
    /// row gives the database directory, the file name, and the reason of
    /// the refusal. A row without a reason must pass the check. Then the test
    /// writes the marker for the name of 228 bytes, whose marker name has 255
    /// bytes. The write must succeed, because the temp name has a fixed
    /// length.
    #[test]
    fn fallback_name_limits_hold_for_the_check_and_the_write() {
        let (_root, [keys, slash]) = temp_dirs(["keys", "slash"]);
        let long = |len: usize| format!("{}.sqlite", "x".repeat(len - 7));
        let rows = [
            ("a name of 228 bytes", &slash, long(228), None),
            ("a name of 229 bytes", &slash, long(229), Some("at most 255 bytes")),
            ("a name of 229 bytes in the keystore directory", &keys, long(229), None),
            (
                "an owned marker name",
                &slash,
                format!("{MARKER_FILENAME}.a.sqlite"),
                Some("name space"),
            ),
            (
                "a record temp name",
                &slash,
                "..rvc.doppelganger_record.1.2.tmp".to_string(),
                Some("name space"),
            ),
            (
                "the marker name without its first dot",
                &slash,
                format!("{}.sqlite", MARKER_FILENAME.trim_start_matches('.')),
                None,
            ),
            ("a name with a NUL byte", &slash, "a\0.sqlite".to_string(), Some("nul byte")),
        ];
        for (case, dir, name, reason) in rows {
            let result = check_slashing_db_name(&keys, &dir.join(&name))
                .map_err(|err| (err.kind(), err.to_string()));
            if let Some(reason) = reason {
                assert!(
                    matches!(
                        &result,
                        Err((io::ErrorKind::InvalidInput, text)) if text.contains(reason)
                    ),
                    "The check must refuse {case} and give the reason \"{reason}\". The result \
                     is {result:?}."
                );
            } else {
                assert_eq!(result, Ok(()), "The check must accept {case}.");
            }
        }
        let fallback = fallback_of(&keys, &slash);
        let fallback = FallbackMarkerPath { slashing_db_path: slash.join(long(228)), ..fallback };
        let name_len = fallback.owned_path().file_name().map(OsStr::len);
        assert_eq!(name_len, Some(255), "The marker name must have 255 bytes.");
        assert_eq!(
            write_fallback_marker(&fallback, &keys, &sample_marker())
                .map_err(|err| err.to_string()),
            Ok(()),
            "The write must succeed for a database file name of 228 bytes."
        );
        assert!(
            matches!(inspect_fallback(&fallback).owned, MarkerInspect::Present(_)),
            "A read must give Present for the owned marker of 228 bytes."
        );
    }

    /// The database `<slash>/a.sqlite` has an owned fallback marker. A
    /// symlink and a hard link in `other` give the database two more names.
    /// For each of the three names, the test requires these results:
    ///
    /// - The check refuses the name and gives the reason "one link".
    /// - The clear fails.
    /// - The marker keeps its bytes.
    #[cfg(unix)]
    #[test]
    fn second_names_of_a_database_are_refused_by_the_check_and_the_clear() {
        let (_root, [keys, slash, other]) = temp_dirs(["keys", "slash", "other"]);
        let db = slash.join("a.sqlite");
        fs::write(&db, b"db").expect("The test must write the database file.");
        let fallback = fallback_of(&keys, &slash);
        write_fallback_marker(&fallback, &keys, &sample_marker())
            .expect("The test must write the marker.");
        let before = fs::read(fallback.owned_path()).map_err(|err| err.to_string());
        std::os::unix::fs::symlink(&db, other.join("link.sqlite"))
            .expect("The test must create a symlink to the database file.");
        fs::hard_link(&db, other.join("hard.sqlite"))
            .expect("The test must create a hard link of the database file.");

        for name in [other.join("link.sqlite"), other.join("hard.sqlite"), db] {
            let checked = check_slashing_db_name(&keys, &name).map_err(|err| err.to_string());
            let alias = FallbackMarkerPath::for_config(&keys, &name)
                .expect("The test must find a fallback path beside the database.");
            let cleared = clear_fallback_marker(&alias, &keys).map_err(|err| err.to_string());

            assert!(
                matches!(&checked, Err(text) if text.contains("one link")),
                "The check must refuse {} and give the reason \"one link\". The result is \
                 {checked:?}.",
                name.display()
            );
            assert!(
                cleared.is_err(),
                "The clear for {} must fail. The result is {cleared:?}.",
                name.display()
            );
            assert_eq!(
                fs::read(fallback.owned_path()).map_err(|err| err.to_string()),
                before,
                "The marker must keep its bytes after the clear for {}.",
                name.display()
            );
        }
    }

    #[test]
    fn preallocate_writes_a_clear_fixed_record_and_commit_overwrites_it() {
        let dir = tempfile::tempdir().expect("temp");
        assert_eq!(
            reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string()),
            Ok(ClearOutcome::Absent),
            "The reset must return Absent when no record exists."
        );
        preallocate_detection_record(dir.path()).expect("preallocate");
        let path = record_path(dir.path());
        let meta = fs::metadata(&path).expect("meta");
        assert!(meta.is_file());
        assert_eq!(meta.len(), RECORD_LEN as u64);
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Clear));
        assert_eq!(
            reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string()),
            Ok(ClearOutcome::Absent),
            "The reset must return Absent for a clear record."
        );
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
        #[cfg(unix)]
        let detected_id = file_id(&path);
        assert_eq!(
            reset_or_replace_detection_record(dir.path()).expect("reset"),
            ClearOutcome::Removed
        );
        assert!(matches!(inspect_record(dir.path()), RecordInspect::Clear));
        assert_eq!(fs::metadata(&path).expect("meta").len(), RECORD_LEN as u64);
        #[cfg(unix)]
        assert_eq!(
            file_id(&path),
            detected_id,
            "The reset must keep the device number and the inode number of a detected record."
        );
        assert_eq!(
            temp_file_names(dir.path()),
            Vec::<String>::new(),
            "The reset of a detected record must not leave a temp file."
        );
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

    /// Return the names of the temp files in `dir`.
    fn temp_file_names(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
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

    /// The function handles a regular record that does not parse. A hard
    /// link keeps the old inode for the checks. The test requires these
    /// results:
    ///
    /// - The function returns `Replaced`.
    /// - The new record is Clear, a regular file, mode `0600` and
    ///   `RECORD_LEN` bytes.
    /// - The new record has a new inode, and the old inode keeps its bytes.
    /// - The durable steps are the fsync of the full temp record, the
    ///   exchange, and the fsync of the keystore directory, in that order.
    /// - No temp file stays.
    /// - The next preallocation accepts the record.
    #[cfg(target_os = "linux")]
    #[test]
    fn reset_or_replace_replaces_an_unparseable_regular_record() {
        let clear = encode_record(false, 0, 0).expect("The test must encode a clear record.");
        let rows: [(&str, Vec<u8>); 3] = [
            ("4096 zero bytes", vec![0; RECORD_LEN]),
            ("a 5-byte regular file", b"short".to_vec()),
            ("a clear record with one more zero byte", [clear.as_slice(), &[0]].concat()),
        ];
        for (case, bytes) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let path = record_path(dir.path());
            let old_link = dir.path().join("old-record-link");
            fs::write(&path, &bytes).expect("The test must write the record file.");
            fs::hard_link(&path, &old_link).expect("The test must make a hard link to the record.");
            take_durable_steps();

            let outcome =
                reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string());
            let steps = take_durable_steps();

            assert_eq!(
                outcome,
                Ok(ClearOutcome::Replaced),
                "The function must replace the record. The input case is {case}."
            );
            assert_eq!(
                inspect_record(dir.path()),
                RecordInspect::Clear,
                "The record must be clear after the replace. The input case is {case}."
            );
            let meta = fs::symlink_metadata(&path)
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
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "The new record must have mode 0600. The input case is {case}."
                );
            }
            let (new_dev, new_ino) = file_id(&path);
            assert_ne!(
                (new_dev, new_ino),
                file_id(&old_link),
                "The new record must have a new inode. The input case is {case}."
            );
            assert_eq!(
                fs::read(&old_link).map_err(|err| err.to_string()),
                Ok(bytes.clone()),
                "The old inode must keep its bytes. The input case is {case}."
            );
            let (dir_dev, dir_ino) = file_id(dir.path());
            assert_eq!(
                steps,
                vec![
                    DurableStep::SyncFile(new_dev, new_ino, RECORD_LEN as u64),
                    DurableStep::Exchange,
                    DurableStep::SyncDir(dir_dev, dir_ino),
                ],
                "The durable steps must be the fsync of the full temp record, the exchange and \
                 the fsync of the keystore directory. The input case is {case}."
            );
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The function must not leave a temp file. The input case is {case}."
            );
            assert_eq!(
                preallocate_detection_record(dir.path()).map_err(|err| err.to_string()),
                Ok(()),
                "The next boot must accept the new record. The input case is {case}."
            );
        }
    }

    /// The function replaces a record of 4096 zero bytes, and the seam fails
    /// one step. Each row requires these results:
    ///
    /// - The function returns an error that gives the injected `EIO`.
    /// - The durable steps stop at the failed step.
    /// - When the temp-record fsync or the exchange fails, the record keeps
    ///   its inode and its bytes.
    /// - When the keystore-directory fsync fails, the exchange is done, and
    ///   the record is Clear.
    /// - No temp file stays.
    #[cfg(target_os = "linux")]
    #[test]
    fn reset_or_replace_stops_at_a_failed_replace_step() {
        let rows = [
            ("the temp-record fsync fails", DurableFault::Sync(0)),
            ("the exchange fails", DurableFault::Exchange),
            ("the keystore-directory fsync fails", DurableFault::Sync(1)),
        ];
        for (case, fault) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let path = record_path(dir.path());
            fs::write(&path, vec![0; RECORD_LEN]).expect("The test must write the record file.");
            let before = file_id(&path);
            take_durable_steps();
            arm_durable_fault(fault);

            let result =
                reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string());
            let steps = take_durable_steps();

            let message = result.err().unwrap_or_default();
            let injected = io::Error::from_raw_os_error(libc::EIO).to_string();
            assert!(
                message.contains(&injected),
                "The function must return the injected error. The input case is {case}. The \
                 error is: {message:?}"
            );
            if fault == DurableFault::Sync(1) {
                let (new_dev, new_ino) = file_id(&path);
                let (dir_dev, dir_ino) = file_id(dir.path());
                assert_eq!(
                    steps,
                    vec![
                        DurableStep::SyncFile(new_dev, new_ino, RECORD_LEN as u64),
                        DurableStep::Exchange,
                        DurableStep::SyncDir(dir_dev, dir_ino),
                    ],
                    "The durable steps must stop at the keystore-directory fsync."
                );
                assert_eq!(
                    inspect_record(dir.path()),
                    RecordInspect::Clear,
                    "The record must be clear after the exchange."
                );
            } else {
                assert!(
                    matches!(
                        steps.as_slice(),
                        [DurableStep::SyncFile(_, _, len)] if *len == RECORD_LEN as u64
                    ),
                    "The durable steps must stop after the temp-record fsync. The input case is \
                     {case}. The steps are {steps:?}."
                );
                assert_eq!(
                    file_id(&path),
                    before,
                    "The record must keep its inode. The input case is {case}."
                );
                assert_eq!(
                    fs::read(&path).map_err(|err| err.to_string()),
                    Ok(vec![0; RECORD_LEN]),
                    "The record must keep its bytes. The input case is {case}."
                );
            }
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The function must not leave a temp file. The input case is {case}."
            );
        }
    }

    /// The replace runs under the umask `0o022`. A hook reads the temp
    /// record right after the exclusive open, before `set_permissions` and
    /// before the write. The test requires these results:
    ///
    /// - The hook gets a record temp path.
    /// - At that time, the temp record has mode `0o600` and no bytes.
    /// - The function returns `Replaced`.
    #[cfg(target_os = "linux")]
    #[test]
    fn replace_opens_the_temp_record_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        fs::write(record_path(dir.path()), b"short").expect("The test must write the record file.");
        let seen = std::rc::Rc::new(Cell::new(None));
        let hook_seen = std::rc::Rc::clone(&seen);
        let _hook = arm_after_record_open(move |path| {
            let meta =
                fs::symlink_metadata(path).expect("The hook must read the temp record metadata.");
            hook_seen.set(Some((
                is_record_temp_name(path),
                meta.permissions().mode() & 0o777,
                meta.len(),
            )));
        });
        let umask = UmaskGuard::set(0o022);

        let outcome = reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string());
        drop(umask);

        assert_eq!(
            seen.get(),
            Some((true, 0o600, 0)),
            "Right after the exclusive open, the temp record must have mode 0o600 and no bytes."
        );
        assert_eq!(outcome, Ok(ClearOutcome::Replaced), "The function must replace the record.");
    }

    /// The function handles a symlink, a directory or a FIFO at the record
    /// path. Each row requires these results:
    ///
    /// - The function returns `InvalidData`.
    /// - The error names the record path and says that it is not a regular
    ///   file.
    /// - The entry keeps its type and its inode.
    /// - The symlink keeps its target, and the target keeps its bytes.
    /// - The directory stays empty.
    /// - The FIFO row has a marker, and the marker stays.
    /// - No temp file stays.
    #[cfg(unix)]
    #[test]
    fn reset_or_replace_keeps_a_record_that_is_not_a_regular_file() {
        use std::os::unix::fs::FileTypeExt;
        let marker = DetectionMarker { epoch: 7, unix_secs: 8, pubkeys: vec![pubkey()] };
        for case in ["a symlink", "a directory", "a FIFO"] {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let path = record_path(dir.path());
            let target = dir.path().join("symlink-target");
            if case == "a FIFO" {
                write_marker(dir.path(), &marker).expect("The test must write the marker.");
            }
            if case == "a symlink" {
                fs::write(&target, b"short").expect("The test must write the link target.");
                std::os::unix::fs::symlink(&target, &path)
                    .expect("The test must create a symlink at the record path.");
            } else if case == "a directory" {
                fs::create_dir(&path)
                    .expect("The test must create a directory at the record path.");
            } else {
                make_fifo(&path);
            }
            let before = entry_id(&path);

            let result = reset_or_replace_detection_record(dir.path());

            assert_eq!(
                result.as_ref().copied().map_err(|err| err.kind()),
                Err(io::ErrorKind::InvalidData),
                "The function must refuse the record path when it is {case}."
            );
            let message = result.err().map(|err| err.to_string()).unwrap_or_default();
            assert!(
                message.contains(&path.display().to_string()),
                "The error must name the record path when it is {case}. The error is: \
                 {message:?}"
            );
            assert!(
                message.contains("is not a regular file"),
                "The error must say that the record path is not a regular file. The input case \
                 is {case}. The error is: {message:?}"
            );
            assert_eq!(
                entry_id(&path),
                before,
                "The entry must keep its inode. The input case is {case}."
            );
            let file_type = fs::symlink_metadata(&path)
                .map(|meta| meta.file_type())
                .map_err(|err| err.to_string());
            if case == "a FIFO" {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_fifo()),
                    "The FIFO must stay a FIFO. The file type is {file_type:?}."
                );
                let found = inspect(dir.path());
                assert!(
                    matches!(&found, MarkerInspect::Present(read) if *read == marker),
                    "The marker must stay when the record path is a FIFO. The marker read gives \
                     {found:?}."
                );
            } else if case == "a symlink" {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_symlink()),
                    "The symlink must stay a symlink. The file type is {file_type:?}."
                );
                assert_eq!(
                    fs::read_link(&path).map_err(|err| err.to_string()),
                    Ok(target.clone()),
                    "The symlink must point to the same target."
                );
                assert_eq!(
                    fs::read(&target).map_err(|err| err.to_string()),
                    Ok(b"short".to_vec()),
                    "The function must not write through the symlink."
                );
            } else {
                assert!(
                    file_type.as_ref().is_ok_and(|kind| kind.is_dir()),
                    "The directory must stay a directory. The file type is {file_type:?}."
                );
                assert_eq!(
                    fs::read_dir(&path)
                        .map(|entries| entries.count())
                        .map_err(|err| err.to_string()),
                    Ok(0),
                    "The directory must stay empty."
                );
            }
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The function must not leave a temp file when the record path is {case}."
            );
        }
    }

    /// Make a FIFO at `path` with the `mkfifo` command.
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("The test must start mkfifo.");
        assert!(status.success(), "The mkfifo command must succeed. The status is {status}.");
    }

    /// Return the device number and the inode number of the entry at
    /// `path`. The function does not follow a symlink.
    #[cfg(unix)]
    fn entry_id(path: &Path) -> FileId {
        use std::os::unix::fs::MetadataExt;
        let meta =
            fs::symlink_metadata(path).expect("The test must read the metadata of the entry.");
        (meta.dev(), meta.ino())
    }

    /// The function reads a record of 4096 zero bytes. Then a hook changes
    /// the record path after the temp record is durable and before the
    /// exchange. Each row requires these results:
    ///
    /// - The function returns `InvalidData`, and the error names the record
    ///   path.
    /// - The record path has the entry from the hook, with the same device
    ///   number and inode number.
    /// - A regular file from the hook keeps its bytes. A symlink keeps its
    ///   target, and a FIFO stays a FIFO.
    /// - No temp file stays.
    #[cfg(target_os = "linux")]
    #[test]
    fn reset_or_replace_keeps_a_record_that_changes_before_the_exchange() {
        use std::os::unix::fs::FileTypeExt;
        let detected = encode_record(true, 7, 8).expect("The test must encode a detected record.");
        let rows = [
            "a new inode with the same bytes",
            "detected bytes in the same inode",
            "a symlink",
            "a FIFO",
        ];
        for case in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            let path = record_path(dir.path());
            let side = dir.path().join("side");
            fs::write(&path, vec![0; RECORD_LEN]).expect("The test must write the record file.");
            let changed = std::rc::Rc::new(Cell::new(None));
            let seen = std::rc::Rc::clone(&changed);
            let hook_side = side.clone();
            arm_before_record_exchange(move |path| {
                if case == "a new inode with the same bytes" {
                    fs::write(&hook_side, vec![0; RECORD_LEN])
                        .expect("The hook must write the new file.");
                    fs::rename(&hook_side, path).expect("The hook must move the new file.");
                } else if case == "detected bytes in the same inode" {
                    let data_dir = path.parent().expect("The record path must have a parent.");
                    commit_detection_record(data_dir, 7, 8)
                        .expect("The hook must write a detected record.");
                } else if case == "a symlink" {
                    fs::write(&hook_side, vec![0; RECORD_LEN])
                        .expect("The hook must write the symlink target.");
                    fs::remove_file(path).expect("The hook must remove the record.");
                    std::os::unix::fs::symlink(&hook_side, path)
                        .expect("The hook must make the symlink.");
                } else {
                    fs::remove_file(path).expect("The hook must remove the record.");
                    make_fifo(path);
                }
                seen.set(Some(entry_id(path)));
            });

            let result = reset_or_replace_detection_record(dir.path())
                .map_err(|err| (err.kind(), err.to_string()));

            assert_eq!(
                result.as_ref().map_err(|(kind, _)| *kind),
                Err(io::ErrorKind::InvalidData),
                "The function must refuse the record. The input case is {case}."
            );
            let message = result.err().map(|(_, message)| message).unwrap_or_default();
            assert!(
                message.contains(&path.display().to_string()),
                "The error must name the record path. The input case is {case}. The error is: \
                 {message:?}"
            );
            assert_eq!(
                Some(entry_id(&path)),
                changed.get(),
                "The record path must have the entry from the hook. The input case is {case}."
            );
            if case == "a symlink" {
                assert_eq!(
                    fs::read_link(&path).map_err(|err| err.to_string()),
                    Ok(side.clone()),
                    "The symlink must keep its target."
                );
            } else if case == "a FIFO" {
                assert!(
                    fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_fifo()),
                    "The FIFO must stay a FIFO."
                );
            } else {
                let expected = if case == "a new inode with the same bytes" {
                    [0; RECORD_LEN]
                } else {
                    detected
                };
                assert_eq!(
                    fs::read(&path).map_err(|err| err.to_string()),
                    Ok(expected.to_vec()),
                    "The file from the hook must keep its bytes. The input case is {case}."
                );
            }
            assert_eq!(
                temp_file_names(dir.path()),
                Vec::<String>::new(),
                "The function must not leave a temp file. The input case is {case}."
            );
        }
    }

    /// The read of a detected record fails with an injected `EIO`. Then a
    /// keystore path that is a regular file makes the metadata read fail
    /// with an error other than `NotFound`. The test requires these results:
    ///
    /// - The function returns an error that names the record path and the
    ///   read error.
    /// - The record keeps its device number and inode number, and it stays
    ///   `Detected`.
    /// - No temp file stays.
    /// - The metadata error is a read error, not an absent record.
    #[cfg(unix)]
    #[test]
    fn reset_or_replace_keeps_a_record_that_cannot_be_read() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must create the record.");
        commit_detection_record(dir.path(), 7, 8).expect("The test must write a detected record.");
        let path = record_path(dir.path());
        let before = file_id(&path);
        arm_durable_fault(DurableFault::RecordRead);

        let result = reset_or_replace_detection_record(dir.path()).map_err(|err| err.to_string());

        assert!(result.is_err(), "The function must refuse a record that it cannot read.");
        let message = result.err().unwrap_or_default();
        assert!(
            message.contains(&path.display().to_string()),
            "The error must name the record path. The error is: {message:?}"
        );
        let read_error = io::Error::from_raw_os_error(libc::EIO).to_string();
        assert!(
            message.contains(&read_error),
            "The error must give the read error. The error is: {message:?}"
        );
        assert_eq!(file_id(&path), before, "The record must keep its device and inode numbers.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Detected { epoch: 7, unix_secs: 8 },
            "The record must stay Detected."
        );
        assert_eq!(
            temp_file_names(dir.path()),
            Vec::<String>::new(),
            "The function must not leave a temp file."
        );

        let not_a_dir = dir.path().join("not-a-directory");
        fs::write(&not_a_dir, b"x").expect("The test must write a regular file.");
        let result = reset_or_replace_detection_record(&not_a_dir).map_err(|err| err.to_string());
        assert!(
            result.as_ref().is_err_and(|message| message.contains("cannot be read")),
            "A metadata error other than NotFound must give a read error. The result is \
             {result:?}."
        );
    }

    /// W4-D3c: the record write returns `Ok`. The test sets no fallback path.
    /// The keystore marker write returns the injected error. The test checks
    /// these conditions:
    ///
    /// - The report is durable, because the record write returned `Ok`.
    /// - The keystore marker write returns the injected error, and the
    ///   marker is missing.
    /// - The record contains the epoch and the Unix time of the input.
    #[test]
    fn persist_all_keeps_the_record_when_the_marker_fails() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must pre-allocate the record.");
        let _guard = arm_marker_write_failures(u32::MAX);
        let marker = DetectionMarker { epoch: 3, unix_secs: 4, pubkeys: vec![pubkey()] };
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let report = persist_all(&paths, &marker);
        assert!(
            report.durable(),
            "The record write must make the report durable. The report is {report:?}."
        );
        assert_eq!(
            io_result(&report.keystore_marker).map_err(|err| (err.kind(), err.to_string())),
            Err((io::ErrorKind::StorageFull, "injected marker write failure".to_string())),
            "The keystore marker write must return the test error. The report is {report:?}."
        );
        assert!(
            matches!(inspect(dir.path()), MarkerInspect::Absent),
            "The keystore marker must be absent."
        );
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Detected { epoch: 3, unix_secs: 4 },
            "The record must contain the epoch and the Unix time of the input."
        );
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

    /// The test gives no record and no fallback path. As a result,
    /// `persist_all` writes only the keystore marker. The temporary file fsync
    /// returns `Ok`. The directory fsync returns `EIO` after the rename.
    #[test]
    fn dir_fsync_failure_after_rename_is_not_durable() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Absent,
            "The directory must not contain a record."
        );
        let marker = DetectionMarker { epoch: 5, unix_secs: 6, pubkeys: vec![pubkey()] };
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let before = fsync_calls();
        let guard = arm_fsync_failures_after(1, 1);
        let report = persist_all(&paths, &marker);
        drop(guard);
        assert_eq!(
            io_result(&report.keystore_marker).map_err(io::Error::raw_os_error),
            Err(Some(libc::EIO)),
            "The keystore marker write must return the EIO of the directory fsync. The report is \
             {report:?}."
        );
        assert!(
            !report.durable(),
            "The report must not be durable when the directory fsync fails. The report is \
             {report:?}."
        );
        assert_eq!(
            fsync_calls() - before,
            2,
            "The marker write must fsync the temp file and then the directory."
        );
        assert_eq!(
            present_marker(inspect(dir.path())),
            Some(marker),
            "The marker must be at its final path before the directory fsync fails. The marker \
             must contain the keys, the epoch and the Unix time of the input."
        );
    }

    /// W4-D3c fix1: the keystore directory is missing. Because of this, the
    /// record write and the keystore marker write fail. The fallback
    /// directory exists. The fsync of the temporary fallback file returns
    /// `Ok`. Each fsync of the database directory returns `EIO`. The test
    /// checks these conditions:
    ///
    /// - The record write and the keystore marker write return `NotFound`.
    /// - The fallback marker write returns the `EIO` of the directory fsync
    ///   after the rename.
    /// - The report is not durable.
    /// - The call does two fsyncs: the temporary fallback file, then the
    ///   database directory.
    /// - The owned fallback marker is at its final path. It contains the
    ///   keys, the epoch and the Unix time of the input.
    #[cfg(unix)]
    #[test]
    fn fallback_dir_fsync_failure_after_rename_is_not_durable() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let db_dir = root.path().join("db");
        fs::create_dir(&db_dir).expect("The test must create the database directory.");
        let fallback =
            FallbackMarkerPath { dir: db_dir.clone(), slashing_db_path: db_dir.join("a.sqlite") };
        let paths = DetectionPaths {
            keystore_dir: root.path().join("keys"),
            fallback: Some(fallback.clone()),
        };
        let marker = DetectionMarker { epoch: 5, unix_secs: 6, pubkeys: vec![pubkey()] };
        let targets_before = fsync_targets().len();
        let guard = arm_fsync_failure_for(&db_dir, 0);
        let report = persist_all(&paths, &marker);
        drop(guard);
        assert_eq!(
            (
                io_result(&report.record).map_err(io::Error::kind),
                io_result(&report.keystore_marker).map_err(io::Error::kind),
            ),
            (Err(io::ErrorKind::NotFound), Err(io::ErrorKind::NotFound)),
            "The record write and the keystore marker write must return NotFound, because the \
             keystore directory is missing. The report is {report:?}."
        );
        assert_eq!(
            report
                .fallback_marker
                .as_ref()
                .map(|result| io_result(result).map_err(io::Error::raw_os_error)),
            Some(Err(Some(libc::EIO))),
            "The fallback marker write must return the EIO of the database directory fsync. The \
             report is {report:?}."
        );
        assert!(
            !report.durable(),
            "The report must not be durable, because each path failed. The report is {report:?}."
        );
        assert_eq!(
            fsync_targets()[targets_before..].to_vec(),
            [file_id(&fallback.owned_path()), file_id(&db_dir)],
            "The call must fsync the temporary fallback file and then the database directory. \
             After the rename, the temporary file is the owned fallback marker."
        );
        assert_eq!(
            present_marker(inspect_fallback(&fallback).owned),
            Some(marker),
            "The owned fallback marker must be at its final path before the directory fsync \
             fails. It must contain the keys, the epoch and the Unix time of the input."
        );
    }

    /// The fallback directory of a row of the `persist_all` table.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FallbackRow {
        /// The directory exists, so the write succeeds.
        Ok,
        /// A regular file is at the directory path, so the write fails.
        Fails,
        /// No fallback is configured.
        None,
    }

    /// `persist_all` writes each configured path on each call. The result of
    /// one path does not stop the write of a different path. Each row sets
    /// these conditions:
    ///
    /// - The record is pre-allocated (`Ok`) or absent (`Err`).
    /// - The keystore marker write passes (`Ok`), or
    ///   `arm_marker_write_failures(1)` stops it (`Err`).
    /// - The fallback directory exists (`Ok`), is a regular file (`Err`), or
    ///   is not configured.
    ///
    /// The test requires these results for each row:
    ///
    /// - The report has one result for each configured path. Each result
    ///   agrees with the row.
    /// - A successful path contains a detected record or a valid marker. The
    ///   other paths contain neither in this test.
    /// - Each `Ok` path contains the epoch and the Unix time of the input.
    ///   Each `Ok` marker also contains the keys of the input.
    /// - `failures` gives each `Err` path one time, with its file path and
    ///   the error of the report.
    /// - `durable` is `true` only when at least one path is `Ok`.
    #[test]
    fn persist_all_attempts_every_path_independently() {
        let input = DetectionMarker {
            epoch: 7,
            unix_secs: 1_700_000_000,
            pubkeys: vec![pubkey(), format!("0x{}", "cd".repeat(48))],
        };
        for record_ok in [true, false] {
            for marker_ok in [true, false] {
                for fallback_row in [FallbackRow::Ok, FallbackRow::Fails, FallbackRow::None] {
                    let row = format!(
                        "record {record_ok}, keystore marker {marker_ok}, fallback {fallback_row:?}"
                    );
                    let (root, [keys]) = temp_dirs(["keys"]);
                    if record_ok {
                        preallocate_detection_record(&keys)
                            .expect("The test must pre-allocate the record.");
                    }
                    let slash = root.path().join("slash");
                    match fallback_row {
                        FallbackRow::Ok => fs::create_dir(&slash)
                            .expect("The test must create the fallback directory."),
                        FallbackRow::Fails => fs::write(&slash, b"")
                            .expect("The test must put a regular file at the fallback path."),
                        FallbackRow::None => {}
                    }
                    let fallback =
                        (fallback_row != FallbackRow::None).then(|| FallbackMarkerPath {
                            dir: slash.clone(),
                            slashing_db_path: slash.join("a.sqlite"),
                        });
                    let fallback_ok = fallback_row == FallbackRow::Ok;
                    let paths =
                        DetectionPaths { keystore_dir: keys.clone(), fallback: fallback.clone() };

                    let guard = (!marker_ok).then(|| arm_marker_write_failures(1));
                    let report = persist_all(&paths, &input);
                    drop(guard);

                    let expected = (record_ok, marker_ok, fallback.as_ref().map(|_| fallback_ok));
                    assert_eq!(
                        (
                            report.record.is_ok(),
                            report.keystore_marker.is_ok(),
                            report.fallback_marker.as_ref().map(Result::is_ok),
                        ),
                        expected,
                        "The report must have one result for each configured path. Each result \
                         must agree with the row. The row is: {row}. The report is {report:?}."
                    );
                    assert_eq!(
                        (
                            matches!(inspect_record(&keys), RecordInspect::Detected { .. }),
                            matches!(inspect(&keys), MarkerInspect::Present(_)),
                            fallback.as_ref().map(|fallback| {
                                matches!(
                                    inspect_fallback(fallback).owned,
                                    MarkerInspect::Present(_)
                                )
                            }),
                        ),
                        expected,
                        "A successful path must contain a detected record or a valid marker. The \
                         other paths must contain neither in this test. The row is: {row}."
                    );
                    assert_eq!(
                        (
                            record_ok.then(|| inspect_record(&keys)),
                            marker_ok.then(|| present_marker(inspect(&keys))),
                            fallback.as_ref().filter(|_| fallback_ok).map(|fallback| {
                                present_marker(inspect_fallback(fallback).owned)
                            }),
                        ),
                        (
                            record_ok.then_some(RecordInspect::Detected {
                                epoch: input.epoch,
                                unix_secs: input.unix_secs,
                            }),
                            marker_ok.then(|| Some(input.clone())),
                            fallback_ok.then(|| Some(input.clone())),
                        ),
                        "Each Ok path must contain the epoch and the Unix time of the input. Each \
                         Ok marker must also contain the keys of the input. The row is: {row}."
                    );
                    let failures: Vec<(PersistPath, PathBuf)> =
                        report.failures().map(|(path, file, _)| (path, file)).collect();
                    let failed: Vec<(PersistPath, PathBuf)> = [
                        (!record_ok).then(|| (PersistPath::Record, record_path(&keys))),
                        (!marker_ok).then(|| (PersistPath::KeystoreMarker, marker_path(&keys))),
                        fallback
                            .as_ref()
                            .filter(|_| !fallback_ok)
                            .map(|fallback| (PersistPath::FallbackMarker, fallback.owned_path())),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();
                    assert_eq!(
                        failures, failed,
                        "failures must give each Err path one time, with its file path. The row \
                         is: {row}."
                    );
                    for (path, _, error) in report.failures() {
                        let field = match path {
                            PersistPath::Record => report.record.as_ref().err(),
                            PersistPath::KeystoreMarker => report.keystore_marker.as_ref().err(),
                            PersistPath::FallbackMarker => report
                                .fallback_marker
                                .as_ref()
                                .and_then(|result| result.as_ref().err()),
                        };
                        assert!(
                            field.is_some_and(|field| std::ptr::eq(field, error)),
                            "failures must give the error of the report for {path:?}. The row \
                             is: {row}."
                        );
                    }
                    assert_eq!(
                        report.durable(),
                        record_ok || marker_ok || fallback_ok,
                        "durable must be true only when at least one path is Ok. The row is: \
                         {row}."
                    );
                }
            }
        }
    }

    /// Return the marker of a `Present` result. Return `None` for each other
    /// result.
    fn present_marker(result: MarkerInspect) -> Option<DetectionMarker> {
        if let MarkerInspect::Present(marker) = result {
            Some(marker)
        } else {
            None
        }
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

    /// The keystore holds a `Clear` record. In each row after the first, a
    /// hook runs after the open of the record and puts a different file at
    /// the record path. Each row requires these results:
    ///
    /// - `preallocate_detection_record` returns the error kind of the row, or
    ///   `Ok`.
    /// - An error names the mode of the open record, not the mode of the new
    ///   file.
    /// - The check fsyncs the open record and then the directory. When the
    ///   check fails, it fsyncs no file.
    #[cfg(unix)]
    #[test]
    fn reuse_checks_and_fsyncs_the_descriptor_that_it_opened() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        enum Change {
            Nothing,
            File(Vec<u8>),
            Directory,
        }
        let clear = encode_record(false, 0, 0).expect("The test must encode the record.").to_vec();
        let invalid = Some(io::ErrorKind::InvalidData);
        let rows = [
            ("no change", 0o600, Change::Nothing, None),
            ("a new Clear record", 0o600, Change::File(clear.clone()), None),
            ("a file of 5 bytes", 0o600, Change::File(b"short".to_vec()), None),
            ("a directory", 0o600, Change::Directory, None),
            ("a new Clear record with mode 0o600", 0o644, Change::File(clear), invalid),
        ];
        for (case, mode, change, kind) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            preallocate_detection_record(dir.path())
                .expect("The test must preallocate the record.");
            let path = record_path(dir.path());
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("The test must set the mode of the record.");
            let opened = file_id(&path);
            let guard = match change {
                Change::Nothing => None,
                Change::File(bytes) => {
                    let other = dir.path().join("other");
                    fs::write(&other, bytes).expect("The test must write the other file.");
                    fs::set_permissions(&other, fs::Permissions::from_mode(0o600))
                        .expect("The test must set mode 0o600 on the other file.");
                    Some(arm_after_record_open(move |path| {
                        fs::rename(&other, path)
                            .expect("The hook must move the other file to the record path.");
                    }))
                }
                Change::Directory => Some(arm_after_record_open(|path| {
                    fs::remove_file(path).expect("The hook must remove the record.");
                    fs::create_dir(path).expect("The hook must make a directory.");
                })),
            };
            let hooked = guard.is_some();
            let before = fsync_targets().len();
            let result = preallocate_detection_record(dir.path());
            drop(guard);
            let fsyncs = fsync_targets().split_off(before);
            if hooked {
                let now = fs::symlink_metadata(&path).ok().map(|meta| (meta.dev(), meta.ino()));
                assert_ne!(now, Some(opened), "The hook must put {case} at the record path.");
            }
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                kind,
                "With {case} at the record path, the error kind must be {kind:?}. The result is \
                 {result:?}."
            );
            if let Err(err) = &result {
                assert!(
                    err.to_string().contains(&format!("mode 0o{mode:o}")),
                    "The error must name the mode 0o{mode:o} of the open record. The error is: \
                     {err}"
                );
                assert_eq!(fsyncs, Vec::<FileId>::new(), "A failed check must not fsync a file.");
            } else {
                assert_eq!(
                    fsyncs,
                    vec![opened, file_id(dir.path())],
                    "With {case} at the record path, the check must fsync the open record and \
                     then the directory."
                );
            }
        }
    }

    /// Return the bytes, the mode bits, the owner uid and the inode of the
    /// file at `path`.
    #[cfg(unix)]
    fn record_state(path: &Path) -> (Vec<u8>, u32, u32, u64) {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path).expect("The test must read the record metadata.");
        let bytes = fs::read(path).expect("The test must read the record.");
        (bytes, meta.mode() & 0o7777, meta.uid(), meta.ino())
    }

    /// The keystore holds a `Clear` record, and each row sets a mode on it.
    /// The rule refuses each group bit and each other bit. Mode `0o700` has
    /// no group or other bit, so the rule accepts it. Each row requires these
    /// results:
    ///
    /// - `preallocate_detection_record` returns `InvalidData`, or `Ok` for
    ///   mode `0o700`.
    /// - The error names the mode of the row.
    /// - The bytes, the mode, the owner and the inode of the record do not
    ///   change.
    #[cfg(unix)]
    #[test]
    fn reuse_mode_rule_rejects_each_group_or_other_bit() {
        use std::os::unix::fs::PermissionsExt;
        let invalid = Some(io::ErrorKind::InvalidData);
        let rows = [
            (0o640, invalid),
            (0o620, invalid),
            (0o610, invalid),
            (0o604, invalid),
            (0o602, invalid),
            (0o601, invalid),
            (0o700, None),
        ];
        for (mode, kind) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            preallocate_detection_record(dir.path())
                .expect("The test must preallocate the record.");
            let path = record_path(dir.path());
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("The test must set the mode of the record.");
            let before = record_state(&path);
            let result = preallocate_detection_record(dir.path());
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                kind,
                "For mode 0o{mode:o}, the error kind must be {kind:?}. The result is {result:?}."
            );
            if let Err(err) = &result {
                assert!(
                    err.to_string().contains(&format!("mode 0o{mode:o}")),
                    "The error must name the mode 0o{mode:o}. The error is: {err}"
                );
            }
            assert!(
                record_state(&path) == before,
                "For mode 0o{mode:o}, the check must not change the bytes, the mode, the owner \
                 or the inode of the record."
            );
        }
    }

    /// An inotify watch on one file. It reports each write and each metadata
    /// change of the file.
    #[cfg(target_os = "linux")]
    struct ChangeWatch(std::os::fd::OwnedFd);

    #[cfg(target_os = "linux")]
    impl ChangeWatch {
        /// Watch the file at `path` for `IN_MODIFY` and `IN_ATTRIB` events.
        #[allow(unsafe_code)]
        fn new(path: &Path) -> Self {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::os::unix::ffi::OsStrExt;
            // SAFETY: inotify_init1 has no pointer argument. It returns a new
            // descriptor or -1.
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(
                fd >= 0,
                "inotify_init1 must succeed. The error is: {}",
                io::Error::last_os_error()
            );
            // SAFETY: `fd` is a new open descriptor, and only this value owns it.
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .expect("The path must not contain a zero byte.");
            let mask = libc::IN_MODIFY | libc::IN_ATTRIB;
            // SAFETY: `name` is a C string, and `owned` keeps the descriptor open.
            let watch = unsafe { libc::inotify_add_watch(owned.as_raw_fd(), name.as_ptr(), mask) };
            assert!(
                watch >= 0,
                "inotify_add_watch must succeed. The error is: {}",
                io::Error::last_os_error()
            );
            Self(owned)
        }

        /// Read the queued events. Return the mask of each event.
        #[allow(unsafe_code)]
        fn events(&self) -> Vec<u32> {
            use std::os::fd::AsRawFd;
            let mut buf = [0u8; 4096];
            // SAFETY: `buf` is valid for `buf.len()` bytes, and `self.0` keeps
            // the descriptor open.
            let read =
                unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            let Ok(read) = usize::try_from(read) else {
                let err = io::Error::last_os_error();
                assert_eq!(
                    err.kind(),
                    io::ErrorKind::WouldBlock,
                    "The read of the inotify queue must succeed. The error is: {err}"
                );
                return Vec::new();
            };
            let header = std::mem::size_of::<libc::inotify_event>();
            let mut masks = Vec::new();
            let mut at = 0;
            while at + header <= read {
                let field = |offset: usize| {
                    let start = at + offset;
                    u32::from_ne_bytes([buf[start], buf[start + 1], buf[start + 2], buf[start + 3]])
                };
                let mask = field(4);
                let name_len = field(12) as usize;
                masks.push(mask);
                at += header + name_len;
            }
            masks
        }
    }

    /// The keystore holds a `Clear` record, and an inotify watch reports each
    /// write and each metadata change of the record. Each row requires these
    /// results:
    ///
    /// - `preallocate_detection_record` returns the error kind of the row, or
    ///   `Ok`.
    /// - The watch reports no event during the check.
    ///
    /// A write of the same bytes and a `chown` to the same owner each give an
    /// event. The last part of the test makes sure that the watch reports them.
    #[cfg(target_os = "linux")]
    #[test]
    fn reuse_check_does_not_write_or_change_the_record() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let invalid = Some(io::ErrorKind::InvalidData);
        let rows = [
            ("mode 0o600", 0o600, false, None),
            ("another owner", 0o600, true, invalid),
            ("mode 0o620", 0o620, false, invalid),
        ];
        for (case, mode, other_owner, kind) in rows {
            let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
            preallocate_detection_record(dir.path())
                .expect("The test must preallocate the record.");
            let path = record_path(dir.path());
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("The test must set the mode of the record.");
            let uid = fs::metadata(&path).expect("The test must read the record metadata.").uid();
            let owner = other_owner.then(|| arm_owner_uid_override(uid + 1));
            let watch = ChangeWatch::new(&path);
            let result = preallocate_detection_record(dir.path());
            drop(owner);
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                kind,
                "In the {case} row, the error kind must be {kind:?}. The result is {result:?}."
            );
            assert_eq!(
                watch.events(),
                Vec::<u32>::new(),
                "In the {case} row, the check must not write the record or change its metadata."
            );
        }

        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must preallocate the record.");
        let path = record_path(dir.path());
        let uid = fs::metadata(&path).expect("The test must read the record metadata.").uid();
        let bytes = fs::read(&path).expect("The test must read the record.");
        let watch = ChangeWatch::new(&path);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut file| file.write_all(&bytes))
            .expect("The test must write the same bytes into the record.");
        assert!(
            watch.events().iter().any(|mask| mask & libc::IN_MODIFY != 0),
            "The watch must report a write of the same bytes."
        );
        std::os::unix::fs::chown(&path, Some(uid), None)
            .expect("The test must set the same owner on the record.");
        assert!(
            watch.events().iter().any(|mask| mask & libc::IN_ATTRIB != 0),
            "The watch must report a chown to the same owner."
        );
    }

    /// Return each line of `src`, with `true` when a `#[cfg(test)]` line
    /// gates it.
    ///
    /// A `#[cfg(test)]` line gates the next item or statement. That item ends
    /// at the line that closes its braces. An item without braces ends at
    /// its first line that ends with `;`.
    fn cfg_test_gates(src: &str) -> Vec<(bool, &str)> {
        let lines: Vec<&str> = src.lines().collect();
        let mut gated = vec![false; lines.len()];
        let mut at = 0;
        while at < lines.len() {
            if lines[at].trim() != "#[cfg(test)]" {
                at += 1;
                continue;
            }
            let mut depth = 0;
            let mut end = at + 1;
            while end < lines.len() {
                let line = lines[end].trim();
                depth += line.matches('{').count();
                depth -= line.matches('}').count().min(depth);
                let attribute = line.starts_with("#[") || line.starts_with("//");
                if depth == 0 && !attribute && (line.ends_with(';') || line.ends_with('}')) {
                    break;
                }
                end += 1;
            }
            let end = end.min(lines.len() - 1);
            gated[at..=end].fill(true);
            at = end + 1;
        }
        gated.into_iter().zip(lines).collect()
    }

    /// Return the code lines of `src` that name one of `names` and that no
    /// `#[cfg(test)]` line gates.
    fn ungated_lines<'a>(src: &'a str, names: &[&str]) -> Vec<&'a str> {
        cfg_test_gates(src)
            .into_iter()
            .filter(|(gated, line)| {
                !gated
                    && !line.trim_start().starts_with("//")
                    && names.iter().any(|name| line.contains(name))
            })
            .map(|(_, line)| line)
            .collect()
    }

    /// Each code line in the production part of this file that names the
    /// owner uid override must be in a `#[cfg(test)]` item or statement. The
    /// test requires these results:
    ///
    /// - The scan finds the three ungated lines of the fixture. A `cfg` that
    ///   the `test-utils` feature can enable does not gate a line.
    /// - The production part has no ungated line that names the override.
    /// - The scan finds these gated parts: the storage, the arm function, the
    ///   guard, the `Drop` implementation of the guard, and the read in the
    ///   owner check.
    #[test]
    fn owner_uid_override_is_test_only() {
        let names = ["OWNER_UID_OVERRIDE", "OwnerUidGuard", "arm_owner_uid_override"];
        let fixture = "thread_local! {\n\
                       \x20   static OWNER_UID_OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };\n\
                       }\n\
                       #[cfg(test)]\n\
                       fn arm() -> OwnerUidGuard {\n\
                       \x20   OwnerUidGuard\n\
                       }\n\
                       fn check() {\n\
                       \x20   #[cfg(test)]\n\
                       \x20   let other = 1;\n\
                       \x20   let euid = OWNER_UID_OVERRIDE.with(Cell::get).unwrap_or(0);\n\
                       }\n\
                       #[cfg(any(test, feature = \"test-utils\"))]\n\
                       pub(crate) struct OwnerUidGuard;\n";
        assert_eq!(
            ungated_lines(fixture, &names),
            vec![
                "    static OWNER_UID_OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };",
                "    let euid = OWNER_UID_OVERRIDE.with(Cell::get).unwrap_or(0);",
                "pub(crate) struct OwnerUidGuard;",
            ],
            "The scan must find the three ungated lines of the fixture."
        );

        let src = include_str!("detection_marker.rs");
        let (production, _) =
            src.split_once("\nmod tests {").expect("detection_marker.rs must have a tests module.");
        assert_eq!(
            ungated_lines(production, &names),
            Vec::<&str>::new(),
            "Each line that names the owner uid override must be in a #[cfg(test)] item or \
             statement."
        );
        let gated: Vec<&str> = cfg_test_gates(production)
            .into_iter()
            .filter_map(|(gated, line)| gated.then_some(line))
            .collect();
        for part in [
            "static OWNER_UID_OVERRIDE:",
            "fn arm_owner_uid_override(",
            "struct OwnerUidGuard;",
            "impl Drop for OwnerUidGuard",
            "let euid = OWNER_UID_OVERRIDE.with(",
        ] {
            assert!(
                gated.iter().any(|line| line.contains(part)),
                "The scan must find `{part}` in a #[cfg(test)] item or statement."
            );
        }
    }

    /// The real-time limit of [`wait_until`]. It is hang protection only.
    const WAIT_LIMIT: Duration = Duration::from_secs(10);

    /// Poll `done` and yield to the runtime until it returns `true` or
    /// [`WAIT_LIMIT`] of real time has gone by. The caller then asserts the
    /// condition, so a condition that never holds fails by assertion. Paused
    /// time does not move here: the test never sleeps, and the blocking
    /// writes that it waits for stop auto-advance.
    async fn wait_until(mut done: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !done() && start.elapsed() < WAIT_LIMIT {
            tokio::task::yield_now().await;
        }
    }

    fn timed_out(result: &Result<(), PersistError>) -> bool {
        matches!(result, Err(PersistError::TimedOut))
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hung_path_is_not_spawned_twice() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must pre-allocate the record.");
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let faults = DirFaults { fsync_gate: Some(Arc::clone(&gate)), ..DirFaults::default() };
        let _faults = arm_dir_faults(dir.path(), faults);
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let persister = DetectionPersister::new(paths);
        let hung = DetectionMarker { epoch: 7, unix_secs: 70, pubkeys: vec![pubkey()] };
        let round = persister.persist(&hung);
        tokio::pin!(round);
        assert!(futures::poll!(&mut round).is_pending(), "Round 1 must wait for its writes.");
        wait_until(|| gate.blocked() == 2).await;
        assert_eq!(gate.blocked(), 2, "The record and the keystore marker must wait in the gate.");
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT - Duration::from_millis(1)).await;
        assert!(
            futures::poll!(&mut round).is_pending(),
            "Round 1 must still wait 1 ms before DETECTION_PERSIST_TIMEOUT."
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let first = round.await;
        assert!(
            timed_out(&first.record) && timed_out(&first.keystore_marker) && !first.durable(),
            "Round 1 must time out on both gated paths and not be durable. The report is \
             {first:?}."
        );
        assert!(first.fallback_marker.is_none(), "No fallback is configured.");

        let second = persister.persist(&hung).await;
        assert!(
            timed_out(&second.record) && timed_out(&second.keystore_marker) && !second.durable(),
            "Round 2 must time out at once on both paths and not be durable. The report is \
             {second:?}."
        );
        let spawned = |persister: &DetectionPersister| {
            (persister.spawned(PersistPath::Record), persister.spawned(PersistPath::KeystoreMarker))
        };
        assert_eq!(spawned(&persister), (1, 1), "Round 2 must start no second thread on a path.");
        assert_eq!(gate.blocked(), 2, "The writes of round 1 must still wait in the gate.");

        gate.open();
        let in_flight = |persister: &DetectionPersister| {
            (
                persister.in_flight(PersistPath::Record),
                persister.in_flight(PersistPath::KeystoreMarker),
            )
        };
        wait_until(|| in_flight(&persister) == (false, false)).await;
        assert_eq!(
            in_flight(&persister),
            (false, false),
            "The record write and the keystore marker write of round 1 must each end and free \
             their path after the gate opens (record, keystore marker)."
        );
        let finished = |persister: &DetectionPersister| {
            (
                persister.finished(PersistPath::Record),
                persister.finished(PersistPath::KeystoreMarker),
            )
        };
        assert_eq!(finished(&persister), (0, 0), "No result of round 1 reached a round.");

        let recovered = DetectionMarker { epoch: 8, unix_secs: 80, pubkeys: vec![pubkey()] };
        let third = persister.persist(&recovered).await;
        assert!(
            third.record.is_ok() && third.keystore_marker.is_ok() && third.durable(),
            "Round 3 must write both paths. The report is {third:?}."
        );
        assert_eq!(spawned(&persister), (2, 2), "Round 3 must start a new thread on each path.");
        assert_eq!(finished(&persister), (1, 1), "The results of round 3 must reach the round.");
        assert_eq!(persister.rounds(), 3);
        assert_eq!(
            inspect_record(dir.path()),
            RecordInspect::Detected { epoch: 8, unix_secs: 80 },
            "The record must contain the marker of round 3."
        );
        let MarkerInspect::Present(written) = inspect(dir.path()) else {
            panic!("The keystore marker must be present after round 3.");
        };
        assert_eq!(written, recovered, "The keystore marker must contain the marker of round 3.");
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
    }

    /// `true` when neither keystore write of `persister` is in flight.
    fn keystore_writes_ended(persister: &DetectionPersister) -> bool {
        !persister.in_flight(PersistPath::Record)
            && !persister.in_flight(PersistPath::KeystoreMarker)
    }

    /// A keystore directory and a slashing database directory, with a
    /// pre-allocated record and the owned fallback of the database.
    fn paths_with_a_fallback() -> (tempfile::TempDir, tempfile::TempDir, DetectionPaths) {
        let keys = tempfile::tempdir().expect("The test must create a keystore directory.");
        let db = tempfile::tempdir().expect("The test must create a database directory.");
        preallocate_detection_record(keys.path()).expect("The test must pre-allocate the record.");
        let fallback = FallbackMarkerPath::for_config(keys.path(), &db.path().join("db.sqlite"))
            .expect("The database directory must give a fallback.");
        let paths =
            DetectionPaths { keystore_dir: keys.path().to_path_buf(), fallback: Some(fallback) };
        (keys, db, paths)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hung_keystore_paths_do_not_delay_the_fallback() {
        let (keys, _db, paths) = paths_with_a_fallback();
        let fallback = paths.fallback.clone().expect("The paths have a fallback.");
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let faults = DirFaults { fsync_gate: Some(Arc::clone(&gate)), ..DirFaults::default() };
        let _faults = arm_dir_faults(keys.path(), faults);
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 9, unix_secs: 90, pubkeys: vec![pubkey()] };
        let round = persister.persist(&marker);
        tokio::pin!(round);
        assert!(futures::poll!(&mut round).is_pending(), "The round must wait for its writes.");
        let start = std::time::Instant::now();
        let fallback_done = || persister.finished(PersistPath::FallbackMarker) == 1;
        while !(gate.blocked() == 2 && fallback_done()) && start.elapsed() < WAIT_LIMIT {
            assert!(futures::poll!(&mut round).is_pending(), "The keystore writes still wait.");
            tokio::task::yield_now().await;
        }
        assert_eq!(gate.blocked(), 2, "The record and the keystore marker must wait in the gate.");
        assert!(fallback_done(), "The fallback result must reach the round before time moves.");
        let MarkerInspect::Present(written) = inspect_fallback(&fallback).owned else {
            panic!("The fallback marker must be written before the keystore writes time out.");
        };
        assert_eq!(written, marker, "The fallback marker must contain the marker of the round.");
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT).await;
        let report = round.await;
        assert!(
            timed_out(&report.record)
                && timed_out(&report.keystore_marker)
                && matches!(report.fallback_marker, Some(Ok(())))
                && report.durable(),
            "Only the fallback must succeed, and it must make the round durable. The report is \
             {report:?}."
        );
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
        gate.open();
        wait_until(|| keystore_writes_ended(&persister)).await;
        assert!(keystore_writes_ended(&persister), "The parked keystore writes must end.");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_retry_succeeds_while_the_keystore_writes_stay_parked() {
        let (keys, db, paths) = paths_with_a_fallback();
        let fallback = paths.fallback.clone().expect("The paths have a fallback.");
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let faults = DirFaults { fsync_gate: Some(Arc::clone(&gate)), ..DirFaults::default() };
        let _keys = arm_dir_faults(keys.path(), faults);
        let db_faults = DirFaults { marker_write_fails: true, ..DirFaults::default() };
        let db_guard = arm_dir_faults(db.path(), db_faults);
        let persister = DetectionPersister::new(paths);
        let first_marker = DetectionMarker { epoch: 10, unix_secs: 100, pubkeys: vec![pubkey()] };
        let round = persister.persist(&first_marker);
        tokio::pin!(round);
        assert!(futures::poll!(&mut round).is_pending(), "Round 1 must wait for its writes.");
        let start = std::time::Instant::now();
        let fallback_done = || persister.finished(PersistPath::FallbackMarker) == 1;
        while !(gate.blocked() == 2 && fallback_done()) && start.elapsed() < WAIT_LIMIT {
            assert!(futures::poll!(&mut round).is_pending(), "The keystore writes still wait.");
            tokio::task::yield_now().await;
        }
        assert_eq!(gate.blocked(), 2, "The record and the keystore marker must wait in the gate.");
        assert!(fallback_done(), "The failed fallback result must reach round 1.");
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT).await;
        let first = round.await;
        assert!(
            timed_out(&first.record)
                && timed_out(&first.keystore_marker)
                && matches!(&first.fallback_marker, Some(Err(PersistError::Io(err))) if err.kind() == io::ErrorKind::StorageFull)
                && !first.durable(),
            "Round 1 must fail each path and not be durable. The report is {first:?}."
        );
        drop(db_guard);
        let retry_marker = DetectionMarker { epoch: 11, unix_secs: 110, pubkeys: vec![pubkey()] };
        let retry = persister.persist(&retry_marker).await;
        assert!(
            timed_out(&retry.record)
                && timed_out(&retry.keystore_marker)
                && matches!(retry.fallback_marker, Some(Ok(())))
                && retry.durable(),
            "The retry must write only the fallback while the keystore writes stay parked. The \
             report is {retry:?}."
        );
        let MarkerInspect::Present(written) = inspect_fallback(&fallback).owned else {
            panic!("The fallback marker must be present after the retry.");
        };
        assert_eq!(written, retry_marker, "The fallback marker must contain the retry marker.");
        assert_eq!(gate.blocked(), 2, "The keystore writes must still wait in the gate.");
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
        gate.open();
        wait_until(|| keystore_writes_ended(&persister)).await;
        assert!(keystore_writes_ended(&persister), "The parked keystore writes must end.");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn parked_fallback_is_not_spawned_twice_and_a_timeout_is_not_durable() {
        let (keys, db, paths) = paths_with_a_fallback();
        let failing =
            DirFaults { marker_write_fails: true, fsync_fails: true, ..DirFaults::default() };
        let _keys = arm_dir_faults(keys.path(), failing);
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let parked = DirFaults { fsync_gate: Some(Arc::clone(&gate)), ..DirFaults::default() };
        let _db = arm_dir_faults(db.path(), parked);
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 12, unix_secs: 120, pubkeys: vec![pubkey()] };
        let round = persister.persist(&marker);
        tokio::pin!(round);
        assert!(futures::poll!(&mut round).is_pending(), "Round 1 must wait for the fallback.");
        let start = std::time::Instant::now();
        let keystore_done = || {
            persister.finished(PersistPath::Record) == 1
                && persister.finished(PersistPath::KeystoreMarker) == 1
        };
        while !(gate.blocked() == 1 && keystore_done()) && start.elapsed() < WAIT_LIMIT {
            assert!(futures::poll!(&mut round).is_pending(), "The fallback write still waits.");
            tokio::task::yield_now().await;
        }
        assert_eq!(gate.blocked(), 1, "The fallback write must wait in the gate.");
        assert!(keystore_done(), "The two keystore results must reach round 1.");
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT).await;
        let first = round.await;
        let io_failed =
            |result: &Result<(), PersistError>| matches!(result, Err(PersistError::Io(_)));
        let parked_fallback = |report: &PersistReport| {
            io_failed(&report.record)
                && io_failed(&report.keystore_marker)
                && matches!(report.fallback_marker, Some(Err(PersistError::TimedOut)))
                && !report.durable()
        };
        assert!(
            parked_fallback(&first),
            "Round 1 must fail both keystore paths, time out the fallback, and not be durable. \
             The report is {first:?}."
        );
        let second = persister.persist(&marker).await;
        assert!(
            parked_fallback(&second),
            "Round 2 must fail both keystore paths again, time out the parked fallback at once, \
             and not be durable. The report is {second:?}."
        );
        let fallback = PersistPath::FallbackMarker;
        assert_eq!(
            (
                persister.spawned(fallback),
                persister.in_flight(fallback),
                persister.spawned(PersistPath::Record)
            ),
            (1, true, 2),
            "Round 2 must start no second fallback write while the first one is parked, and it \
             must write the record again (fallback spawned, fallback in flight, record spawned)."
        );
        gate.open();
        wait_until(|| !persister.in_flight(fallback)).await;
        assert!(!persister.in_flight(fallback), "The parked fallback write must end.");
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
    }

    /// Park only the write of `parked`; the two other paths succeed at once.
    /// The round must still wait 1 ms before `DETECTION_PERSIST_TIMEOUT` and
    /// give `TimedOut` for `parked` at the timeout.
    async fn one_parked_path_times_out_at_the_deadline(parked: PersistPath) {
        let (keys, _db, paths) = paths_with_a_fallback();
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let faults =
            DirFaults { path_gate: Some((parked, Arc::clone(&gate))), ..DirFaults::default() };
        let _keys = arm_dir_faults(keys.path(), faults);
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 13, unix_secs: 130, pubkeys: vec![pubkey()] };
        let round = persister.persist(&marker);
        tokio::pin!(round);
        let others: Vec<PersistPath> =
            [PersistPath::Record, PersistPath::KeystoreMarker, PersistPath::FallbackMarker]
                .into_iter()
                .filter(|path| *path != parked)
                .collect();
        let others_done = || others.iter().all(|path| persister.finished(*path) == 1);
        let start = std::time::Instant::now();
        while !(gate.blocked() == 1 && others_done()) && start.elapsed() < WAIT_LIMIT {
            assert!(futures::poll!(&mut round).is_pending(), "{parked:?} still waits.");
            tokio::task::yield_now().await;
        }
        assert!(gate.blocked() == 1 && others_done(), "Only {parked:?} must wait in the gate.");
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT - Duration::from_millis(1)).await;
        assert!(
            futures::poll!(&mut round).is_pending(),
            "The write of {parked:?} must still wait 1 ms before DETECTION_PERSIST_TIMEOUT."
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let report = round.await;
        let results = [
            (PersistPath::Record, &report.record),
            (PersistPath::KeystoreMarker, &report.keystore_marker),
            (PersistPath::FallbackMarker, report.fallback_marker.as_ref().expect("fallback")),
        ];
        for (path, result) in results {
            assert_eq!(
                timed_out(result),
                path == parked,
                "Only {parked:?} must time out at DETECTION_PERSIST_TIMEOUT. The report is \
                 {report:?}."
            );
        }
        gate.open();
        wait_until(|| !persister.in_flight(parked)).await;
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn dropped_round_keeps_the_claim_of_its_parked_write() {
        let (keys, _db, paths) = paths_with_a_fallback();
        let gate = FsyncGate::with_watchdog(Duration::from_secs(10));
        let parked = Some((PersistPath::Record, Arc::clone(&gate)));
        let _keys =
            arm_dir_faults(keys.path(), DirFaults { path_gate: parked, ..DirFaults::default() });
        let persister = DetectionPersister::new(paths);
        let first = DetectionMarker { epoch: 14, unix_secs: 140, pubkeys: vec![pubkey()] };
        let mut round = Box::pin(persister.persist(&first));
        assert!(futures::poll!(&mut round).is_pending(), "Round 1 must wait for the record.");
        let others_ended = || {
            !persister.in_flight(PersistPath::KeystoreMarker)
                && !persister.in_flight(PersistPath::FallbackMarker)
        };
        let start = std::time::Instant::now();
        while !(gate.blocked() == 1 && others_ended()) && start.elapsed() < WAIT_LIMIT {
            assert!(futures::poll!(&mut round).is_pending(), "The record write still waits.");
            tokio::task::yield_now().await;
        }
        assert!(
            gate.blocked() == 1 && others_ended(),
            "Only the record write must wait in the gate."
        );
        tokio::time::advance(DETECTION_PERSIST_TIMEOUT / 2).await;
        drop(round);
        let record = PersistPath::Record;
        assert!(
            persister.in_flight(record),
            "Dropping the round must not free the path of the parked record write."
        );
        let retry = persister.persist(&first).await;
        assert!(
            timed_out(&retry.record)
                && retry.keystore_marker.is_ok()
                && matches!(retry.fallback_marker, Some(Ok(()))),
            "The retry must time out the record at once and write the two markers. The report \
             is {retry:?}."
        );
        assert_eq!(persister.spawned(record), 1, "The record must have one submission.");
        gate.open();
        wait_until(|| !persister.in_flight(record)).await;
        assert!(!persister.in_flight(record), "The parked record write must end.");
        let later = DetectionMarker { epoch: 15, unix_secs: 150, pubkeys: vec![pubkey()] };
        let report = persister.persist(&later).await;
        assert!(report.record.is_ok(), "A later round must write the record. {report:?}");
        assert_eq!(
            inspect_record(keys.path()),
            RecordInspect::Detected { epoch: 15, unix_secs: 150 },
            "The record must contain the marker of the later round."
        );
        assert!(!gate.watchdog_fired(), "The watchdog must not open the gate.");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn parked_record_times_out_at_the_deadline() {
        one_parked_path_times_out_at_the_deadline(PersistPath::Record).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn parked_keystore_marker_times_out_at_the_deadline() {
        one_parked_path_times_out_at_the_deadline(PersistPath::KeystoreMarker).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn parked_fallback_marker_times_out_at_the_deadline() {
        one_parked_path_times_out_at_the_deadline(PersistPath::FallbackMarker).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persister_returns_the_io_error_of_each_failed_path() {
        let (keys, db, paths) = paths_with_a_fallback();
        let faults = DirFaults { fsync_fails: true, ..DirFaults::default() };
        let _keys = arm_dir_faults(keys.path(), faults.clone());
        let _db = arm_dir_faults(db.path(), faults);
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 5, unix_secs: 50, pubkeys: vec![pubkey()] };
        let report = persister.persist(&marker).await;
        let eio = |result: Option<&Result<(), PersistError>>| match result {
            Some(Err(PersistError::Io(err))) => err.raw_os_error(),
            _ => None,
        };
        assert_eq!(
            (
                eio(Some(&report.record)),
                eio(Some(&report.keystore_marker)),
                eio(report.fallback_marker.as_ref())
            ),
            (Some(libc::EIO), Some(libc::EIO), Some(libc::EIO)),
            "Each path must return the EIO of its fsync. The report is {report:?}."
        );
        assert!(!report.durable(), "The report must not be durable. The report is {report:?}.");
    }

    #[test]
    fn a_closure_dropped_before_it_starts_frees_its_path() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must pre-allocate the record.");
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 6, unix_secs: 60, pubkeys: vec![pubkey()] };
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("The test needs a runtime.")
        };
        let closed = runtime();
        let handle = closed.handle().clone();
        closed.shutdown_timeout(Duration::ZERO);
        let dropped = handle.block_on(persister.persist(&marker));
        assert!(
            matches!(&dropped.record, Err(PersistError::Io(err)) if err.to_string().contains("stopped"))
                && inspect_record(dir.path()) == RecordInspect::Clear
                && !persister.in_flight(PersistPath::Record),
            "The pool of a shut-down runtime must drop the closure before it writes, and free the \
             path. The report is {dropped:?}."
        );
        let retry = runtime().block_on(persister.persist(&marker));
        assert!(
            retry.record.is_ok() && retry.keystore_marker.is_ok(),
            "The next round must write each path again. The report is {retry:?}."
        );
        assert_eq!(persister.spawned(PersistPath::Record), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dir_faults_reach_a_blocking_pool_thread_and_only_their_dir() {
        let faulty = tempfile::tempdir().expect("The test must create a temporary directory.");
        let healthy = tempfile::tempdir().expect("The test must create a temporary directory.");
        for dir in [&faulty, &healthy] {
            preallocate_detection_record(dir.path()).expect("The test must pre-allocate a record.");
        }
        let faults =
            DirFaults { marker_write_fails: true, fsync_fails: true, ..DirFaults::default() };
        let guard = arm_dir_faults(faulty.path(), faults);
        let marker = DetectionMarker { epoch: 3, unix_secs: 30, pubkeys: vec![pubkey()] };
        let paths = |dir: &tempfile::TempDir| DetectionPaths {
            keystore_dir: dir.path().to_path_buf(),
            fallback: None,
        };
        let (faulty_paths, healthy_paths) = (paths(&faulty), paths(&healthy));
        let on_pool = |paths: DetectionPaths, marker: DetectionMarker| async move {
            let report = tokio::task::spawn_blocking(move || persist_all(&paths, &marker));
            let report = report.await.expect("The blocking write must not panic.");
            (
                io_result(&report.record).map_err(io::Error::raw_os_error),
                io_result(&report.keystore_marker).map_err(|err| (err.kind(), err.to_string())),
            )
        };
        assert_eq!(
            on_pool(faulty_paths.clone(), marker.clone()).await,
            (
                Err(Some(libc::EIO)),
                Err((
                    io::ErrorKind::StorageFull,
                    "injected directory marker write failure".to_string()
                ))
            ),
            "The faults of the directory must reach a blocking-pool thread."
        );
        assert_eq!(
            on_pool(healthy_paths, marker.clone()).await,
            (Ok(()), Ok(())),
            "The faults of one directory must not reach a different directory."
        );
        drop(guard);
        assert_eq!(
            on_pool(faulty_paths, marker).await,
            (Ok(()), Ok(())),
            "The guard must remove the faults when it drops."
        );
    }

    #[test]
    fn in_flight_flag_clears_when_the_write_panics() {
        let slot = Arc::new(PathSlot::default());
        slot.in_flight.store(true, Ordering::SeqCst);
        let in_flight = InFlight(Arc::clone(&slot));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _in_flight = in_flight;
            panic!("The test injects a panic in the blocking write.");
        }));
        assert!(panicked.is_err());
        assert!(
            !slot.in_flight.load(Ordering::SeqCst),
            "The guard must clear the flag on a panic."
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_panicked_write_is_an_io_failure_and_frees_its_path() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        preallocate_detection_record(dir.path()).expect("The test must pre-allocate the record.");
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let persister = DetectionPersister::new(paths);
        let marker = DetectionMarker { epoch: 4, unix_secs: 40, pubkeys: vec![pubkey()] };
        let faults = DirFaults { write_panics: true, ..DirFaults::default() };
        let guard = arm_dir_faults(dir.path(), faults);
        let panicked = persister.persist(&marker).await;
        drop(guard);
        let stopped = |result: &Result<(), PersistError>| matches!(result, Err(PersistError::Io(err)) if err.to_string().contains("stopped"));
        assert!(
            stopped(&panicked.record) && stopped(&panicked.keystore_marker) && !panicked.durable(),
            "A panicked write must be an Io failure. The report is {panicked:?}."
        );
        let next = persister.persist(&marker).await;
        assert!(
            next.record.is_ok() && next.keystore_marker.is_ok(),
            "The next round must write each path again. The report is {next:?}."
        );
    }

    #[test]
    fn dir_fault_guard_drop_opens_the_gate() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let gate = FsyncGate::without_watchdog();
        let path_gate = FsyncGate::without_watchdog();
        let faults = DirFaults {
            fsync_gate: Some(Arc::clone(&gate)),
            path_gate: Some((PersistPath::Record, Arc::clone(&path_gate))),
            ..DirFaults::default()
        };
        drop(arm_dir_faults(dir.path(), faults));
        gate.wait_open(|| panic!("The guard drop must open the fsync gate."));
        path_gate.wait_open(|| panic!("The guard drop must open the path gate."));
        assert_eq!((gate.blocked(), path_gate.blocked()), (0, 0));
    }

    #[test]
    fn gate_watchdog_opens_the_gate_and_records_that_it_fired() {
        let gate = FsyncGate::with_watchdog(Duration::ZERO);
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_gate = Arc::clone(&gate);
        let waiter = std::thread::spawn(move || {
            waiter_gate.wait_open(|| {});
            let _ = tx.send(());
        });
        let returned = rx.recv_timeout(WAIT_LIMIT).is_ok();
        gate.open();
        waiter.join().expect("The waiter must not panic.");
        assert!(returned, "The watchdog must open the gate before the cleanup opens it.");
        assert!(gate.watchdog_fired(), "The watchdog must record that it opened the gate.");
    }

    #[derive(Clone, Default)]
    struct EventLog(Arc<std::sync::Mutex<Vec<String>>>);

    struct FieldLine<'a>(&'a mut String);

    impl tracing::field::Visit for FieldLine<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventLog {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = event.metadata().level().to_string();
            event.record(&mut FieldLine(&mut line));
            self.0.lock().expect("The test must store the log line.").push(line);
        }
    }

    #[test]
    fn log_persist_report_logs_and_counts_a_timed_out_path() {
        use tracing_subscriber::layer::SubscriberExt;

        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let paths = DetectionPaths { keystore_dir: dir.path().to_path_buf(), fallback: None };
        let report = PersistReport {
            record: Ok(()),
            keystore_marker: Err(PersistError::TimedOut),
            fallback_marker: None,
            paths,
        };
        let log = EventLog::default();
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        {
            let subscriber = tracing_subscriber::registry().with(log.clone());
            let _log = tracing::subscriber::set_default(subscriber);
            log_persist_report(&report, "test round");
        }
        let after = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let lines = log.0.lock().expect("The test must read the log.").clone();
        assert_eq!(
            lines,
            vec![format!(
                "ERROR message=failed to persist the doppelganger detection on this path \
                 context=test round kind=KeystoreMarker path={} error=the write did not return \
                 within 5s",
                marker_path(dir.path()).display()
            )],
            "The log must have one error line with the path of the timed-out write."
        );
        assert_eq!(after - before, 1, "The timed-out path must count one failure.");
    }
}
