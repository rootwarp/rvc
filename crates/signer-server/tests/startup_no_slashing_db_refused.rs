//! Startup integration tests: rvc-signer refuses to start without slashing DB
//! unless both `--disable-slashing-protection` and `RVC_ALLOW_INSECURE=true` are set.

use signer_server::slashing::config::{SlashingDbConfig, SlashingProtectionMode};

// --------------------------------------------------------------------------
// Test: startup check refuses when no DB and no flags set
// --------------------------------------------------------------------------

#[test]
fn test_refuse_without_db() {
    let cfg = SlashingDbConfig {
        db_path: None,
        mode: SlashingProtectionMode::Required,
        gloas_fork_epoch: u64::MAX,
    };
    let result = cfg.validate();
    assert!(result.is_err(), "should refuse to start without slashing DB");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("slashing") || msg.contains("SlashingDb") || msg.contains("protection"),
        "error message must mention slashing protection, got: {msg}"
    );
}

// --------------------------------------------------------------------------
// Test: only CLI flag set (no env) should refuse
// --------------------------------------------------------------------------

#[test]
fn test_disable_slashing_requires_both_flags() {
    let cfg = SlashingDbConfig {
        db_path: None,
        mode: SlashingProtectionMode::DisabledCliOnly,
        gloas_fork_epoch: u64::MAX,
    };
    let result = cfg.validate();
    assert!(result.is_err(), "must require both flags");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("RVC_ALLOW_INSECURE") || msg.contains("insecure"),
        "error must mention RVC_ALLOW_INSECURE, got: {msg}"
    );
}

// --------------------------------------------------------------------------
// Test: both flags set allows starting without DB
// --------------------------------------------------------------------------

#[test]
fn test_both_flags_set_allows_no_db() {
    let cfg = SlashingDbConfig {
        db_path: None,
        mode: SlashingProtectionMode::DisabledBothFlags,
        gloas_fork_epoch: u64::MAX,
    };
    let result = cfg.validate();
    assert!(result.is_ok(), "both flags must allow starting without DB, got: {:?}", result.err());
}

// --------------------------------------------------------------------------
// Test: providing a DB path with Required mode is valid
// --------------------------------------------------------------------------

#[test]
fn test_db_path_provided_is_valid() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = SlashingDbConfig {
        db_path: Some(tmp.path().to_path_buf()),
        mode: SlashingProtectionMode::Required,
        gloas_fork_epoch: u64::MAX,
    };
    let result = cfg.validate();
    assert!(result.is_ok(), "providing a DB path should be valid, got: {:?}", result.err());
}
