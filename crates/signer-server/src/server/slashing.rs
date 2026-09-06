//! Slashing-protection gate and DB open for the signer server.
//!
//! Extracted from `server::run` so the two-factor insecure gate, SEC-3
//! fail-closed policy, and TOCTOU re-check are unit-testable without
//! binding listeners.

use std::sync::Arc;

use tracing::{error, info};

use crate::config::ResolvedConfig;
use crate::error::ServerError;
use crate::slashing;

/// Open the signer slashing-protection database (or disable it under both
/// insecure conditions).
///
/// Preserves:
/// - two-condition insecure gate (`--disable-slashing-protection` **and**
///   `RVC_ALLOW_INSECURE=true`);
/// - SEC-3 fail-closed on missing path without `--init-slashing-db`;
/// - always-reject on 0-byte / corrupt header;
/// - TOCTOU re-check if the path vanished mid-startup.
pub(crate) fn open_slashing_db(
    resolved: &ResolvedConfig,
) -> Result<Option<Arc<::slashing::SlashingDb>>, ServerError> {
    // ── Slashing protection gate (OQ-A4 binding decision) ────────────────────
    //
    // rvc-signer refuses to start without a SlashingDb unless:
    //   (a) --disable-slashing-protection is on the CLI, AND
    //   (b) RVC_ALLOW_INSECURE=true is set in the environment.
    //
    // Both checks are required so a stray env-var leak cannot silently disable
    // slashing protection.
    let data_dir = resolved.data_dir.as_deref().or_else(|| resolved.keystore_dir.parent());

    let slashing_cfg = slashing::SlashingDbConfig::from_env(
        data_dir,
        resolved.disable_slashing_protection,
        resolved.gloas_fork_epoch,
    );
    slashing_cfg.validate().map_err(|e| {
        error!(error = %e, "slashing protection configuration error");
        ServerError::slashing_db(e)
    })?;

    let slashing_db_opt: Option<Arc<::slashing::SlashingDb>> =
        if slashing_cfg.mode == slashing::SlashingProtectionMode::DisabledBothFlags {
            None
        } else if let Some(ref db_path) = slashing_cfg.db_path {
            info!(path = %db_path.display(), "Opening slashing protection database");
            // SEC-3: fail closed on missing path without --init-slashing-db; 0-byte /
            // corrupt header is always rejected inside open_with_create_info.
            if db_path.exists() {
                let meta = std::fs::metadata(db_path).map_err(|e| {
                    ServerError::slashing_db(format!(
                        "failed to stat slashing DB at {}: {}",
                        db_path.display(),
                        e
                    ))
                })?;
                if meta.len() == 0 {
                    return Err(ServerError::slashing_db(format!(
                        "slashing protection database at {} is empty (0-byte). \
                     This is corruption, not a fresh init — restore from backup. \
                     --init-slashing-db cannot override this.",
                        db_path.display()
                    )));
                }
            } else if !resolved.init_slashing_db {
                return Err(ServerError::slashing_db(format!(
                    "slashing protection database does not exist at {}. \
                 Refusing to create a fresh empty DB (would sign with zero history). \
                 For a genuine new deployment, pass --init-slashing-db. \
                 If this path should hold existing history, restore the DB from backup.",
                    db_path.display()
                )));
            } else {
                error!(
                    path = %db_path.display(),
                    "CREATING A NEW EMPTY SIGNER SLASHING PROTECTION DATABASE. \
                     This DB has ZERO signing history. If this signer was previously \
                     active, signing with a fresh DB can DOUBLE-SIGN and get validators \
                     SLASHED. Only proceed for a genuine first-time deployment. \
                     Opt-in was granted via --init-slashing-db."
                );
            }

            let (db, created_fresh) = ::slashing::SlashingDb::open_with_create_info(db_path)
                .map_err(|e| {
                    ServerError::slashing_db(format!(
                        "failed to open slashing DB at {}: {}",
                        db_path.display(),
                        e
                    ))
                })?;
            // TOCTOU close: refuse accidental create if path vanished mid-startup.
            if created_fresh && !resolved.init_slashing_db {
                drop(db);
                let _ = std::fs::remove_file(db_path);
                return Err(ServerError::slashing_db(format!(
                    "slashing protection database was created at {} without \
                 --init-slashing-db (possible TOCTOU / missing volume). \
                 Refusing to sign with zero history. Restore from backup or \
                 re-run with --init-slashing-db for a genuine first deploy.",
                    db_path.display()
                )));
            }
            db.set_gloas_fork_epoch(slashing_cfg.gloas_fork_epoch);
            db.set_group_commit(
                ::slashing::GroupCommitConfig::try_from_knobs(
                    resolved.group_commit_batch_size,
                    resolved.group_commit_wait_to_fill_ms,
                )
                .map_err(|e| ServerError::slashing_db(e.to_string()))?,
            );
            Some(Arc::new(db))
        } else {
            None
        };

    Ok(slashing_db_opt)
}

#[cfg(test)]
// RF1-12: unit tests may mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::server::env_lock;
    use tempfile::TempDir;

    fn base_resolved(tmp: &TempDir) -> ResolvedConfig {
        let keystore_dir = tmp.path().join("keystores");
        std::fs::create_dir_all(&keystore_dir).unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        ResolvedConfig {
            listen_address: "127.0.0.1:0".to_string(),
            keystore_dir,
            password_file: None,
            backend: Backend::Basic,
            dry_run: false,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            reload_interval_secs: 0,
            enable_hot_reload: false,
            dvt_peers: vec![],
            dvt_threshold: None,
            dvt_index: None,
            dvt_timeout_ms: 2000,
            http_enabled: false,
            http_listen_address: "127.0.0.1:9000".to_string(),
            http_tls_mode: HttpTlsMode::Mtls,
            http_tls_cert: None,
            http_tls_key: None,
            http_tls_ca_cert: None,
            genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
            insecure: true,
            data_dir: Some(data_dir),
            disable_slashing_protection: false,
            init_slashing_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            gloas_fork_epoch: u64::MAX,
            metrics_address: "127.0.0.1:0".to_string(),
            enable_log_reload: false,
            allowed_client_cns: None,
            #[cfg(feature = "dvt")]
            dvt_allowed_peers: None,
        }
    }

    /// Insecure gate requires **both** CLI flag and `RVC_ALLOW_INSECURE=true`.
    #[test]
    fn test_open_slashing_db_refuses_without_both_insecure_conditions() {
        let _g = env_lock();
        let prev = std::env::var("RVC_ALLOW_INSECURE").ok();

        let tmp = TempDir::new().unwrap();

        // (1) CLI flag alone — env unset/false → refuse.
        unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") };
        let mut resolved = base_resolved(&tmp);
        resolved.disable_slashing_protection = true;
        let err = match open_slashing_db(&resolved) {
            Err(e) => e,
            Ok(_) => panic!("CLI-only disable must refuse"),
        };
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("RVC_ALLOW_INSECURE") || msg.contains("insecure"),
            "message should mention missing env: {msg}"
        );

        // (2) Env alone without CLI flag → still Required mode; missing DB fails closed.
        unsafe { std::env::set_var("RVC_ALLOW_INSECURE", "true") };
        let mut resolved = base_resolved(&tmp);
        resolved.disable_slashing_protection = false;
        resolved.init_slashing_db = false;
        let err = match open_slashing_db(&resolved) {
            Err(e) => e,
            Ok(_) => panic!("env-only must not disable protection"),
        };
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist") || msg.contains("slashing"),
            "expected missing-DB fail-closed: {msg}"
        );

        // (3) Both conditions → disabled (Ok(None)).
        let mut resolved = base_resolved(&tmp);
        resolved.disable_slashing_protection = true;
        let out = open_slashing_db(&resolved).expect("both flags should disable protection");
        assert!(out.is_none(), "disabled mode must not open a DB");

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    #[test]
    fn test_open_slashing_db_fails_closed_on_missing_path() {
        let _g = env_lock();
        let prev = std::env::var("RVC_ALLOW_INSECURE").ok();
        // Ensure we are not in the dual-flag disable path.
        unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") };

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.init_slashing_db = false;
        assert!(!resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        let err = match open_slashing_db(&resolved) {
            Err(e) => e,
            Ok(_) => panic!("missing DB without init must fail"),
        };
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist") || msg.contains("--init-slashing-db"),
            "message should mention missing path / init flag: {msg}"
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    #[test]
    fn test_open_slashing_db_rejects_corrupt_header_even_with_init_flag() {
        let _g = env_lock();
        let prev = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") };

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.init_slashing_db = true; // must not override corruption

        let db_path = resolved.data_dir.as_ref().unwrap().join("signer-slashing.db");
        // Non-empty, non-SQLite header → corrupt (distinct from 0-byte path).
        std::fs::write(&db_path, b"not-a-sqlite-database-header!!").unwrap();

        let err = match open_slashing_db(&resolved) {
            Err(e) => e,
            Ok(_) => panic!("corrupt header must fail"),
        };
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt")
                || msg.contains("failed to open")
                || msg.contains("empty")
                || msg.contains("header"),
            "message should indicate corruption: {msg}"
        );

        // 0-byte is also always rejected even with init.
        std::fs::write(&db_path, b"").unwrap();
        let err = match open_slashing_db(&resolved) {
            Err(e) => e,
            Ok(_) => panic!("0-byte must fail"),
        };
        assert!(matches!(err, ServerError::SlashingDb(_)), "expected SlashingDb, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("0-byte") || msg.contains("empty") || msg.contains("corrupt"),
            "message should mention empty/0-byte: {msg}"
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    #[test]
    fn test_open_slashing_db_creates_with_init_flag() {
        let _g = env_lock();
        let prev = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") };

        let tmp = TempDir::new().unwrap();
        let mut resolved = base_resolved(&tmp);
        resolved.init_slashing_db = true;

        let db = open_slashing_db(&resolved).expect("init should create fresh DB");
        assert!(db.is_some());
        assert!(resolved.data_dir.as_ref().unwrap().join("signer-slashing.db").exists());

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }

    #[test]
    fn test_open_slashing_db_fork_schedule_gloas_epoch_rejects_null_root_double_vote() {
        let _g = env_lock();
        let prev = std::env::var("RVC_ALLOW_INSECURE").ok();
        unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") };

        let tmp = TempDir::new().unwrap();
        let keystore_dir = tmp.path().join("keystores");
        std::fs::create_dir_all(&keystore_dir).unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Operator surface is `[fork_schedule]`, the same table the VC reads.
        // `[signer] gloas_fork_epoch` must not exist and is not set here.
        let cfg_path = tmp.path().join("signer.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[signer]\nkeystore_dir = \"{}\"\n\n[fork_schedule]\ngloas_fork_epoch = 100\n",
                keystore_dir.display()
            ),
        )
        .unwrap();
        let file_cfg = crate::config::load_config(&cfg_path).expect("load signer.toml");
        assert_eq!(file_cfg.fork_schedule.gloas_fork_epoch, Some(100));

        let cli = crate::config::ServeArgs {
            keystore_dir: Some(keystore_dir),
            data_dir: Some(data_dir),
            init_slashing_db: true,
            insecure: true,
            ..Default::default()
        };
        let resolved = crate::config::merge_with_cli(file_cfg, &cli).expect("merge");
        assert_eq!(resolved.gloas_fork_epoch, 100);

        let db = open_slashing_db(&resolved)
            .expect("init should create fresh DB")
            .expect("protection required");
        const GVR: [u8; 32] = [0u8; 32];
        db.check_and_record_attestation("0xpk", 99, 100, None, &GVR)
            .expect("first Gloas attestation");
        let err = db
            .check_and_record_attestation("0xpk", 99, 100, None, &GVR)
            .expect_err("fork_schedule alone must not leave the remote-signer DB lenient");
        assert!(err.to_string().contains("double vote"), "expected double vote, got: {err}");

        match prev {
            Some(v) => unsafe { std::env::set_var("RVC_ALLOW_INSECURE", v) },
            None => unsafe { std::env::remove_var("RVC_ALLOW_INSECURE") },
        }
    }
}
