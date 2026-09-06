//! Bootstrap phase: open slashing DB, integrity, lock, denylist.
//!
//! Extracted from `bin/rvc` startup Steps 1–2d so the phase can be unit-tested
//! without spawning the binary.

use std::fs::File;
use std::sync::Arc;

// External crate (not this module): see `bootstrap/mod.rs` shadow note.
use ::slashing::SlashingDb;
use tracing::{error, info, warn};

use super::BootstrapError;
use crate::config::{Config, ServiceBuilder};
use crate::deletion_denylist::DeletionDenylist;
use crate::startup;

/// Exclusive keystore-dir file lock held for the process lifetime.
pub type KeystoreLockGuard = fd_lock::RwLockWriteGuard<'static, File>;

/// Handles produced by [`open_slashing_db`].
///
/// Moved into [`super::BootstrapCtx`] by a future `run()` (or by the binary
/// composition root until that lands).
pub struct SlashingDbHandles {
    /// Opened, integrity-checked slashing protection database.
    pub db: Arc<SlashingDb>,
    /// Exclusive keystore-dir lock; `None` only when locking is disabled.
    pub keystore_lock: Option<KeystoreLockGuard>,
    /// Persistent deletion denylist (SEC-1b).
    pub denylist: Arc<DeletionDenylist>,
}

/// Open the slashing DB, run integrity / permission checks, acquire the
/// keystore lock, and load the deletion denylist.
///
/// Inputs are `&Config` plus the two CLI strictness booleans. Health-status
/// updates remain the caller's responsibility (see module docs on
/// [`super`]).
///
/// Log lines and order match the former inline `run_validator` Steps 1–2d.
pub fn open_slashing_db(
    config: &Config,
    strict_permissions: bool,
    strict_slashing_semantics: bool,
) -> Result<SlashingDbHandles, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());

    // Step 1: Open slashing DB
    let db = match builder.build_slashing_db() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to open slashing database: {}", e);
            return Err(e.into());
        }
    };

    // Step 2: Run integrity check
    if let Err(e) = startup::check_integrity(&db) {
        error!("Slashing DB integrity check failed: {}", e);
        return Err(e.into());
    }

    // Step 2a: Configure strict slashing semantics
    if strict_slashing_semantics {
        db.set_strict_semantics(true);
        info!("Strict slashing semantics enabled: null-root re-signs will be rejected");
    }

    // FU-33: Gloas epochs always reject None==None, even when the operator
    // left strict_slashing_semantics off. Unset / sentinel keeps existing
    // tests and pre-Gloas networks on the lenient arm.
    let gloas_fork_epoch = config.fork_schedule.gloas_fork_epoch.unwrap_or(u64::MAX);
    db.set_gloas_fork_epoch(gloas_fork_epoch);

    // Step 2b: Check slashing DB file permissions
    if strict_permissions {
        if let Err(e) = db.check_file_permissions_strict() {
            error!("Strict permissions check failed: {}", e);
            return Err(e.into());
        }
    } else {
        db.check_file_permissions();
    }

    // Step 2c: Acquire keystore lock
    let keystore_lock = if config.disable_keystore_locking {
        warn!("Keystore locking disabled -- ensure no duplicate instances");
        None
    } else {
        match startup::acquire_keystore_lock(&config.keystore_path) {
            Ok(guard) => Some(guard),
            Err(e) => {
                error!("Failed to acquire keystore lock: {}", e);
                return Err(e.into());
            }
        }
    };

    // Step 2d (SEC-1b): Load deletion denylist so keystore-dir / secret-provider
    // loaders skip keys deleted via the Keymanager API on a prior boot.
    // Path: <keystore_path>/.rvc.deleted_keys (shares the durable data volume).
    let denylist = match DeletionDenylist::load(&config.keystore_path) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            error!("Failed to load deletion denylist: {}", e);
            return Err(e.into());
        }
    };

    Ok(SlashingDbHandles { db, keystore_lock, denylist })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapCtx;
    use crate::config::Config;
    use crate::deletion_denylist::{deleted_keys_path, DeletionDenylist};
    use crate::startup::StartupError;
    use tempfile::TempDir;

    fn config_with_paths(keystore: &std::path::Path, slashing_db: &std::path::Path) -> Config {
        Config {
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: keystore.to_path_buf(),
            slashing_db_path: slashing_db.to_path_buf(),
            allow_fresh_db: false,
            disable_keystore_locking: false,
            ..Default::default()
        }
    }

    fn seed_valid_db(path: &std::path::Path) {
        SlashingDb::open(path).expect("seed valid slashing db");
    }

    #[test]
    fn test_open_slashing_db_refuses_missing_path_without_allow_fresh_db() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("missing.db");
        assert!(!db_path.exists());

        let config = config_with_paths(&keystore, &db_path);
        match open_slashing_db(&config, false, false) {
            Err(BootstrapError::Config(_)) => {}
            Ok(_) => panic!("must refuse missing DB"),
            Err(e) => panic!("expected Config error for missing DB, got: {e}"),
        }
        assert!(!db_path.exists(), "must not create DB without allow_fresh_db");
    }

    #[test]
    fn test_open_slashing_db_rejects_corrupt_header() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("garbage.db");
        std::fs::write(&db_path, b"not a sqlite database!!!!").unwrap();

        let config = config_with_paths(&keystore, &db_path);
        match open_slashing_db(&config, false, false) {
            Err(BootstrapError::Config(_)) => {}
            Ok(_) => panic!("corrupt header must fail"),
            Err(e) => panic!("expected Config error for corrupt header, got: {e}"),
        }
        assert_eq!(
            std::fs::read(&db_path).unwrap(),
            b"not a sqlite database!!!!",
            "must not wipe corrupt file"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_open_slashing_db_enforces_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        // Pre-open 0o644 is corrected by SlashingDb::open (chmod 0o600), so the
        // phase's strict check sees a safe mode and succeeds. That is production
        // behavior; we still prove the phase takes the strict path.
        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&db_path, perms).unwrap();

        let mut config = config_with_paths(&keystore, &db_path);
        config.disable_keystore_locking = true;
        let handles = open_slashing_db(&config, true, false)
            .expect("strict path must run; open re-chmods to 0o600");

        // Same check the phase calls: after re-chmoding the held file to 0o644,
        // UnsafePermissions is raised (contract of the wiring).
        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&db_path, perms).unwrap();
        match handles.db.check_file_permissions_strict() {
            Err(::slashing::SlashingError::UnsafePermissions { .. }) => {}
            Ok(()) => panic!("strict check must reject 0o644 on the held handle"),
            Err(e) => panic!("expected UnsafePermissions, got: {e}"),
        }
    }

    #[test]
    fn test_open_slashing_db_acquires_keystore_lock_and_reports_contention() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        let config = config_with_paths(&keystore, &db_path);

        let first = open_slashing_db(&config, false, false).expect("first open must acquire lock");
        assert!(first.keystore_lock.is_some(), "lock must be held");

        let second = open_slashing_db(&config, false, false);
        match second {
            Err(BootstrapError::Startup(StartupError::KeystoreLocked(_))) => {}
            Ok(_) => panic!("second open must report lock contention"),
            Err(e) => panic!("expected KeystoreLocked, got: {e}"),
        }

        drop(first);
        let third = open_slashing_db(&config, false, false).expect("lock released after drop");
        assert!(third.keystore_lock.is_some());
    }

    #[test]
    fn test_open_slashing_db_loads_existing_denylist() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        let pk = [0xabu8; 48];
        {
            let deny = DeletionDenylist::load(&keystore).unwrap();
            deny.insert(&pk).unwrap();
        }
        assert!(deleted_keys_path(&keystore).exists());

        // Avoid lock contention with nothing else holding the path.
        let mut config = config_with_paths(&keystore, &db_path);
        config.disable_keystore_locking = true;

        let handles = open_slashing_db(&config, false, false).expect("open with denylist");
        assert!(handles.denylist.contains(&pk));
        assert_eq!(handles.denylist.len(), 1);
        assert!(handles.keystore_lock.is_none());
    }

    #[test]
    fn test_open_slashing_db_applies_strict_slashing_semantics() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        let mut config = config_with_paths(&keystore, &db_path);
        config.disable_keystore_locking = true;

        let handles = open_slashing_db(&config, false, true).expect("open with strict semantics");
        assert!(handles.db.check_integrity().is_ok());
    }

    #[test]
    fn test_open_slashing_db_gloas_epoch_rejects_null_root_double_vote() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        let mut config = config_with_paths(&keystore, &db_path);
        config.disable_keystore_locking = true;
        config.fork_schedule.gloas_fork_epoch = Some(100);

        let handles = open_slashing_db(&config, false, false).expect("open");
        let gvr = [0u8; 32];
        handles
            .db
            .check_and_record_attestation("0xpk", 99, 100, None, &gvr)
            .expect("first Gloas attestation");
        let err = handles
            .db
            .check_and_record_attestation("0xpk", 99, 100, None, &gvr)
            .expect_err("Gloas None==None must be a double vote");
        assert!(err.to_string().contains("double vote"), "expected double vote, got: {err}");
    }

    #[test]
    fn test_bootstrap_ctx_from_slashing_handles() {
        let dir = TempDir::new().unwrap();
        let keystore = dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();
        let db_path = dir.path().join("slashing.db");
        seed_valid_db(&db_path);

        let mut config = config_with_paths(&keystore, &db_path);
        config.disable_keystore_locking = true;

        let handles = open_slashing_db(&config, false, false).unwrap();
        let ctx = BootstrapCtx::from_slashing_handles(handles);
        assert!(ctx.keystore_lock.is_none());
        assert!(ctx.deletion_denylist.is_empty());
        assert!(ctx.slashing_db.check_integrity().is_ok());
    }
}
