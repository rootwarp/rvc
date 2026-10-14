//! Connection open, preflight, pragmas, and file-permission helpers for [`SlashingDb`].
//!
//! Pure code motion from the former monolithic `db.rs` (E2 part 1).

use std::io::Read;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use super::SlashingDb;
use crate::error::SlashingError;

/// SQLite main-database file magic (`"SQLite format 3\0"`).
///
/// Used by SEC-3 preflight so a truncated/garbage file is rejected before
/// `Connection::open` / `migrate()` would treat a 0-byte path as a fresh DB.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

impl SlashingDb {
    /// Open a database at the specified path.
    ///
    /// Creates the file and runs schema migrations if it doesn't exist or is at v1.
    /// Schema v2 migration runs **eagerly** and is idempotent (re-opening a v2 DB is a no-op).
    /// A backup `<path>.bak.<UNIX_TS>` is written before any ALTER fires.
    ///
    /// # SEC-3 fail-closed preflight
    ///
    /// A **0-byte** or **non-SQLite-header** file is always rejected as
    /// [`SlashingError::CorruptOrEmpty`] — SQLite would otherwise treat a
    /// truncated file as a brand-new empty DB and `migrate()` would populate
    /// schema with zero history. Missing paths are still created here (library
    /// / test convenience); production startup gates fresh create behind an
    /// operator opt-in in `ServiceBuilder::build_slashing_db`.
    ///
    /// # Errors
    /// Returns `SlashingError::MigrationFailed` if the backup or migration fails.
    /// Returns `SlashingError::CorruptOrEmpty` for 0-byte / bad-header files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingError> {
        let (db, _created_fresh) = Self::open_with_create_info(path)?;
        Ok(db)
    }

    /// Like [`Self::open`], but reports whether a new file was created.
    ///
    /// `created_fresh == true` means the path did not exist and a new empty DB
    /// was initialized (zero history). Callers that care about fail-closed
    /// startup (the VC builder) must gate that path on an explicit opt-in.
    pub fn open_with_create_info<P: AsRef<Path>>(path: P) -> Result<(Self, bool), SlashingError> {
        let path = path.as_ref();
        let created_fresh = Self::preflight_path(path)?;

        // Existing files: open without CREATE so we never silently re-create.
        // Missing files: CREATE is required (caller already opted in, or this
        // is a library/test path that still allows fresh create).
        let flags = if created_fresh {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI
        };
        let conn = Connection::open_with_flags(path, flags)?;

        Self::configure_pragmas(&conn)?;

        // Set restrictive file permissions (owner-only read/write) on the
        // main DB file before any data is written.
        #[cfg(unix)]
        Self::chmod_main_file(path)?;

        let db = Self::from_connection(conn, Some(path.to_path_buf()));

        // `migrate()` creates tables if they don't exist (v2-native CREATE TABLE).
        // Then `migrate_to_v2` checks if the existing schema is v1 and upgrades.
        // For a brand-new DB, `migrate()` creates v2 tables and `migrate_to_v2` will
        // set schema_version=2 without needing a backup (tables are fresh/empty).
        // Finally `migrate_to_v3` re-keys indices from CN-scoped to pubkey-scoped.
        db.migrate()?;
        db.migrate_to_v2(path)?;
        db.migrate_to_v3()?;
        {
            let conn = db.conn.lock();
            crate::history::ensure_history_indexes(&conn)?;
        }

        // ISSUE-4.8 / L-8: chmod 0o600 on `<path>-wal` / `<path>-shm` sidecars.
        //
        // SQLite materialises the -shm when WAL mode is engaged and the -wal
        // when the first write transaction commits.  Both `migrate()` and
        // `migrate_to_v2` perform write transactions, so by this point the
        // sidecars exist.  Without this chmod they inherit the process umask
        // (typically 0o022), making them group/world-readable — an attacker
        // with read-only host access could exfiltrate the slashing journal,
        // defeating the 0o600 protection on the main file.
        //
        // SQLite WAL filenames use `-wal` / `-shm` suffixes (no separator dot)
        // — see https://www.sqlite.org/wal.html § "Activating and Configuring
        // WAL Mode".  This chmod is best-effort: missing sidecars (e.g. on
        // a pre-WAL fallback) and chmod errors are warn-logged, not fatal.
        #[cfg(unix)]
        Self::chmod_sidecars(path);

        if created_fresh {
            tracing::info!(
                path = %path.display(),
                "slashing protection database created (fresh, zero history)"
            );
        } else {
            tracing::info!(path = %path.display(), "slashing protection database opened");
        }
        Ok((db, created_fresh))
    }

    /// SEC-3: inspect `path` before SQLite open.
    ///
    /// Returns `true` if the path is missing (caller will create). Returns
    /// `false` if a non-empty SQLite-header file is present. Rejects 0-byte
    /// and corrupt-header files as [`SlashingError::CorruptOrEmpty`].
    fn preflight_path(path: &Path) -> Result<bool, SlashingError> {
        if !path.exists() {
            return Ok(true);
        }

        let meta = std::fs::metadata(path).map_err(|e| SlashingError::InspectFailed {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let size = meta.len();
        if size == 0 {
            return Err(SlashingError::CorruptOrEmpty {
                path: path.display().to_string(),
                size: 0,
            });
        }

        let mut file = std::fs::File::open(path).map_err(|e| SlashingError::InspectFailed {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let mut header = [0u8; 16];
        let n = file.read(&mut header).map_err(|e| SlashingError::InspectFailed {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        if n < SQLITE_HEADER.len() || header != *SQLITE_HEADER {
            return Err(SlashingError::CorruptOrEmpty { path: path.display().to_string(), size });
        }
        Ok(false)
    }

    /// Set 0o600 on the main slashing-DB file (Unix only). Failure is a
    /// fatal `SlashingError::UnsafePermissions` — the protection contract
    /// for the main journal must hold or startup aborts.
    #[cfg(unix)]
    fn chmod_main_file(path: &Path) -> Result<(), SlashingError> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| SlashingError::UnsafePermissions {
            path: path.display().to_string(),
            mode: format!("failed to set permissions: {}", e),
        })
    }

    /// Set 0o600 on the SQLite WAL/SHM sidecars (Unix only;
    /// ISSUE-4.8 / L-8).
    ///
    /// Best-effort: sidecars may not yet exist when this is called (e.g. on
    /// a pre-WAL fallback opened with `RVC_ALLOW_NON_WAL_SLASHING_DB=true`),
    /// and on some filesystems chmod is a no-op or unsupported. Missing
    /// sidecars are skipped silently; chmod errors are `warn!`-logged so
    /// operators can investigate without blocking startup.
    #[cfg(unix)]
    fn chmod_sidecars(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        for suffix in &["-wal", "-shm"] {
            let sidecar = parent.join(format!("{}{}", stem, suffix));
            if !sidecar.exists() {
                continue;
            }
            if let Err(e) = std::fs::set_permissions(&sidecar, perms.clone()) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %e,
                    "failed to chmod 0o600 on slashing-db sidecar (ISSUE-4.8 / L-8); \
                     continuing — sidecar may be group/world-readable"
                );
            }
        }
    }

    /// Apply durability pragmas to an open SQLite connection.
    ///
    /// Pragma sequence (per architecture A4 §"Internal data flow"):
    /// 1. `journal_mode=wal` — attempt WAL. If the result is not "wal", check
    ///    `RVC_ALLOW_NON_WAL_SLASHING_DB`. Absent/false → fatal error. True → loud
    ///    `error!` log and continue (durability degraded).
    /// 2. `synchronous=EXTRA` — FULL + dir-fsync; belt-and-braces in case anything
    ///    ever falls through to DELETE journal mode.
    /// 3. `fullfsync=ON` (macOS only) — force F_FULLFSYNC so device caches are
    ///    flushed; macOS's `fsync(2)` does not guarantee this without F_FULLFSYNC.
    fn configure_pragmas(conn: &Connection) -> Result<(), SlashingError> {
        // --- 1. WAL mode ---
        let journal_mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            const HINT: &str = "Set RVC_ALLOW_NON_WAL_SLASHING_DB=true to override \
                (durability degraded), or move the DB to a WAL-capable filesystem \
                (avoid tmpfs / NFSv3 / SMB).";
            let allow = std::env::var("RVC_ALLOW_NON_WAL_SLASHING_DB")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow {
                return Err(SlashingError::JournalMode {
                    actual: journal_mode,
                    hint: HINT.to_owned(),
                });
            }
            tracing::error!(
                actual_mode = %journal_mode,
                "running without WAL — slashing protection durability degraded"
            );
        }

        // --- 2. synchronous=EXTRA ---
        conn.pragma_update(None, "synchronous", "EXTRA")?;

        // --- 3. fullfsync=ON (macOS only) ---
        #[cfg(target_os = "macos")]
        conn.pragma_update(None, "fullfsync", "ON")?;

        Ok(())
    }

    /// Open a database with a pre-configured connection.
    ///
    /// # Purpose
    /// Allows integration tests (and any code with access to a `Connection`) to inject
    /// a connection whose journal mode has been forced to a non-WAL value (e.g. an
    /// in-memory DB where WAL returns `"memory"`) in order to exercise the WAL hard-fail
    /// and env-var opt-out code paths.
    ///
    /// Runs `configure_pragmas` and the schema migration, but skips file-permission
    /// checks because the connection may not be backed by a file.
    ///
    /// # Note
    /// This is a test helper. Do not use it in production paths; prefer `open` or
    /// `open_in_memory` instead.
    ///
    /// Compiled only for this crate's tests or when the `test-utils` feature
    /// is enabled. This crate's integration tests see it through the self
    /// dev-dependency that turns `test-utils` on.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_with_conn_for_testing(conn: Connection) -> Result<Self, SlashingError> {
        Self::configure_pragmas(&conn)?;
        let db = Self::from_connection(conn, None);
        db.migrate()?;
        {
            let mut conn = db.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
                .map_err(|e| SlashingError::MigrationFailed(format!("{e}")))?;
        }
        db.migrate_to_v3()?;
        {
            let conn = db.conn.lock();
            crate::history::ensure_history_indexes(&conn)?;
        }
        Ok(db)
    }

    /// Open an in-memory database for testing.
    ///
    /// Creates the full v3 schema directly (no backup needed — there is no file).
    pub fn open_in_memory() -> Result<Self, SlashingError> {
        let conn = Connection::open_in_memory()?;
        let db = Self::from_connection(conn, None);
        // Create tables (v2-native layout).
        db.migrate()?;
        // Set schema_version = 2 (CN-keyed indices are created transiently here
        // and immediately replaced by migrate_to_v3 below).
        // No backup is taken for in-memory DBs.
        {
            let mut conn = db.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
                .map_err(|e| SlashingError::MigrationFailed(format!("{e}")))?;
        }
        // Migrate to v3: replace CN-keyed indices with pubkey+gvr-scoped indices.
        db.migrate_to_v3()?;
        {
            let conn = db.conn.lock();
            crate::history::ensure_history_indexes(&conn)?;
        }
        Ok(db)
    }

    /// Check file permissions and warn if the slashing DB is group- or world-accessible (Unix only).
    #[cfg(unix)]
    pub fn check_file_permissions(&self) {
        use std::os::unix::fs::PermissionsExt;
        if let Some(path) = &self.path {
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                let dangerous_bits = 0o077; // group + world bits
                if mode & dangerous_bits != 0 {
                    let mut issues = Vec::new();
                    if mode & 0o040 != 0 {
                        issues.push("group-readable");
                    }
                    if mode & 0o020 != 0 {
                        issues.push("group-writable");
                    }
                    if mode & 0o010 != 0 {
                        issues.push("group-executable");
                    }
                    if mode & 0o004 != 0 {
                        issues.push("world-readable");
                    }
                    if mode & 0o002 != 0 {
                        issues.push("world-writable");
                    }
                    if mode & 0o001 != 0 {
                        issues.push("world-executable");
                    }
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode),
                        "slashing protection database is {}; consider restricting permissions to 0600",
                        issues.join(" and "),
                    );
                }
            }
        }
    }

    /// Check file permissions (no-op on non-Unix platforms).
    #[cfg(not(unix))]
    pub fn check_file_permissions(&self) {}

    /// Check file permissions and return an error if the slashing DB is group- or world-accessible (Unix only).
    ///
    /// Use this with the `--strict-permissions` CLI flag to make unsafe permissions fatal at startup.
    /// Unlike `check_file_permissions`, this also returns an error if file metadata cannot be read.
    #[cfg(unix)]
    pub fn check_file_permissions_strict(&self) -> Result<(), SlashingError> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(path) = &self.path {
            let metadata =
                std::fs::metadata(path).map_err(|e| SlashingError::UnsafePermissions {
                    path: path.display().to_string(),
                    mode: format!("unreadable: {}", e),
                })?;
            let mode = metadata.permissions().mode();
            let dangerous_bits = 0o077; // group + world bits
            if mode & dangerous_bits != 0 {
                return Err(SlashingError::UnsafePermissions {
                    path: path.display().to_string(),
                    mode: format!("{:o}", mode),
                });
            }
        }
        Ok(())
    }

    /// Check file permissions strictly (no-op on non-Unix platforms).
    #[cfg(not(unix))]
    pub fn check_file_permissions_strict(&self) -> Result<(), SlashingError> {
        Ok(())
    }

    /// Query a PRAGMA that returns a single integer value.
    ///
    /// Allows integration tests to verify connection-level pragma settings
    /// (e.g. `synchronous`, `fullfsync`) that cannot be read from a separate connection
    /// because they are per-connection settings that reset on every new open.
    ///
    /// # Note
    /// This is a test helper. Do not use it in production paths.
    #[doc(hidden)]
    pub fn query_pragma_i64(&self, name: &str) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();
        conn.pragma_query_value(None, name, |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::SlashingDb;
    use crate::error::SlashingError;
    use eth_types::Root;
    use tempfile::tempdir;

    const TEST_GVR: Root = [0u8; 32];

    #[test]
    fn test_open_in_memory_database() {
        let db = SlashingDb::open_in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn test_open_file_database() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.db");

        let db = SlashingDb::open(&path);
        assert!(db.is_ok());
        assert!(path.exists());
    }

    /// SEC-3: a 0-byte file must never be treated as a fresh init.
    #[test]
    fn test_open_zero_byte_file_is_corrupt() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("zero.db");
        std::fs::write(&path, b"").expect("write empty");

        match SlashingDb::open(&path) {
            Ok(_) => panic!("0-byte DB must fail closed"),
            Err(SlashingError::CorruptOrEmpty { size, .. }) => assert_eq!(size, 0),
            Err(other) => panic!("expected CorruptOrEmpty, got {other}"),
        }
        // File must not have been wiped/replaced with a valid DB.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    /// SEC-3: a non-empty file without a SQLite header is corruption.
    #[test]
    fn test_open_corrupt_header_is_rejected() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("garbage.db");
        std::fs::write(&path, b"not a sqlite database!!!!").expect("write garbage");

        match SlashingDb::open(&path) {
            Ok(_) => panic!("corrupt header must fail closed"),
            Err(SlashingError::CorruptOrEmpty { .. }) => {}
            Err(other) => panic!("expected CorruptOrEmpty, got {other}"),
        }
        // Must not wipe the non-empty garbage file.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"not a sqlite database!!!!");
    }

    /// SEC-3: open_with_create_info reports created_fresh for a missing path.
    #[test]
    fn test_open_with_create_info_flags_fresh() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("fresh.db");

        let (_db, created_fresh) = SlashingDb::open_with_create_info(&path).expect("create fresh");
        assert!(created_fresh);

        let (_db2, created_again) =
            SlashingDb::open_with_create_info(&path).expect("re-open existing");
        assert!(!created_again);
    }

    #[test]
    fn test_open_sets_wal_journal_mode() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("wal_test.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        let conn = db.conn.lock();
        let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn test_open_sets_synchronous_extra() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("sync_test.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        let conn = db.conn.lock();
        let sync_mode: i64 =
            conn.pragma_query_value(None, "synchronous", |row| row.get(0)).unwrap();
        // EXTRA = 3 (belt-and-braces: FULL + dir-fsync on DELETE-mode journal unlink)
        assert_eq!(sync_mode, 3, "synchronous should be 3 (EXTRA), got {sync_mode}");
    }

    #[test]
    fn test_wal_crash_durability() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("durability_test.db");

        let pubkey = "0xabcdef1234567890";

        // Write a record, then drop without explicit close
        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.seed_attestation(pubkey, 1, 2, Some("0xroot".to_string()), &TEST_GVR)
                .expect("record failed");
            // Drop db without explicit close — WAL should ensure durability
        }

        // Reopen and verify the record persisted
        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let attestations = db.get_attestations(pubkey).expect("query failed");
            assert_eq!(attestations.len(), 1);
            assert_eq!(attestations[0].source_epoch, 1);
            assert_eq!(attestations[0].target_epoch, 2);
        }
    }

    // LOW-17: File permissions on DB creation
    #[cfg(unix)]
    #[test]
    fn test_open_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_perms.db");
        let _db = SlashingDb::open(&path).expect("open");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "DB file should have 0o600 permissions, got {:o}",
            mode & 0o777
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("failed to set permissions");

        // Should not panic, just log a warning
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_writable.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o602))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about world-writable
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_readable_and_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_both.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about both world-readable and world-writable
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_restricted.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("failed to set permissions");

        // Should not warn
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_ok_for_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_safe.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("failed to set permissions");

        assert!(db.check_file_permissions_strict().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_readable.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_readable.db"));
                assert_eq!(mode, "100644");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0666() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_both.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_both.db"));
                assert_eq!(mode, "100666");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0660_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_group.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_group.db"));
                assert_eq!(mode, "100660");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_in_memory_returns_ok() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.check_file_permissions_strict().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_deleted_file_returns_err() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("deleted.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::remove_file(&path).expect("failed to delete file");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref mode, .. } => {
                assert!(
                    mode.starts_with("unreadable:"),
                    "expected 'unreadable:' prefix, got: {}",
                    mode
                );
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_warn_detects_group_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_group.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about group-readable and group-writable
        db.check_file_permissions();
    }

    #[cfg(not(unix))]
    #[test]
    fn test_check_file_permissions_strict_returns_ok_on_non_unix() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.check_file_permissions_strict().is_ok());
    }
}
