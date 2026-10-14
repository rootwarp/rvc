//! H-10 regression tests: RemoteSigner (Web3Signer HTTP client) plaintext URL
//! gating.
//!
//! Per ISSUE-2.12 (updated for ISSUE-3.13 GA): `http://` URLs must be gated
//! by `InsecureGate`.  `https://` URLs always pass.  GA default is `Refuse`
//! mode (NFR-10): `http://` without env var hard-fails.  `Warn` mode tests
//! document the legacy Phase-2 gate behaviour — not the production default.
//!
//! # Env-var isolation
//!
//! Tests that mutate `RVC_REMOTE_SIGNER_ALLOW_INSECURE` hold `ENV_LOCK` so
//! parallel test threads don't race on this global.

// RF1-12: Tests must set/clear env vars via unsafe std::env::{set_var,remove_var}.
#![allow(unsafe_code)]

use std::sync::Mutex;

use crypto::insecure::InsecureMode;
use rvc_remote_signer_client::{check_remote_signer_url, REMOTE_SIGNER_INSECURE_ENV_VAR};

/// Serialises access to `RVC_REMOTE_SIGNER_ALLOW_INSECURE` across the test
/// threads within this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ─── helpers ───────────────────────────────────────────────────────────────

fn with_env_var<F: FnOnce()>(value: &str, f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe { std::env::set_var(REMOTE_SIGNER_INSECURE_ENV_VAR, value) };
    f();
    unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
}

fn without_env_var<F: FnOnce()>(f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
    f();
}

// ─── https:// URLs always pass ─────────────────────────────────────────────

#[test]
fn test_https_url_always_passes_refuse_mode() {
    without_env_var(|| {
        assert!(
            check_remote_signer_url("https://signer.example.com:9000", InsecureMode::Refuse)
                .is_ok(),
            "https:// must always pass, even in Refuse mode without env var"
        );
    });
}

#[test]
fn test_https_url_passes_without_env_var() {
    without_env_var(|| {
        assert!(
            check_remote_signer_url("https://signer.example.com:9000", InsecureMode::Warn).is_ok()
        );
    });
}

// ─── http:// URLs in Refuse mode ───────────────────────────────────────────

#[test]
fn test_http_url_refused_without_env_var() {
    without_env_var(|| {
        assert!(
            check_remote_signer_url("http://localhost:9000", InsecureMode::Refuse).is_err(),
            "http:// without env var must return Err in Refuse mode"
        );
    });
}

#[test]
fn test_http_url_allowed_with_env_var_in_refuse_mode() {
    with_env_var("true", || {
        assert!(
            check_remote_signer_url("http://localhost:9000", InsecureMode::Refuse).is_ok(),
            "http:// with env var must return Ok in Refuse mode"
        );
    });
}

// ─── http:// URLs in Warn mode (legacy Phase-2 behaviour; not the GA default) ─

#[test]
fn test_http_url_warns_with_env_var() {
    with_env_var("true", || {
        assert!(
            check_remote_signer_url("http://localhost:9000", InsecureMode::Warn).is_ok(),
            "Warn mode always returns Ok"
        );
    });
}

#[test]
fn test_http_url_warn_mode_always_ok_even_without_env_var() {
    without_env_var(|| {
        assert!(
            check_remote_signer_url("http://localhost:9000", InsecureMode::Warn).is_ok(),
            "Warn mode must always return Ok — error is emitted as a log, not a hard failure"
        );
    });
}

// ─── Error message quality ─────────────────────────────────────────────────

#[test]
fn test_http_url_error_contains_env_var_name() {
    without_env_var(|| {
        let err =
            check_remote_signer_url("http://localhost:9000", InsecureMode::Refuse).unwrap_err();
        assert!(
            err.to_string().contains(REMOTE_SIGNER_INSECURE_ENV_VAR),
            "Error must name the env var; got: {err}"
        );
    });
}

// ─── URL variants ──────────────────────────────────────────────────────────

#[test]
fn test_http_url_with_trailing_slash_refused() {
    without_env_var(|| {
        assert!(check_remote_signer_url("http://localhost:9000/", InsecureMode::Refuse).is_err());
    });
}

#[test]
fn test_https_url_with_path_passes() {
    without_env_var(|| {
        assert!(
            check_remote_signer_url("https://localhost:9000/api/v1", InsecureMode::Refuse).is_ok()
        );
    });
}
