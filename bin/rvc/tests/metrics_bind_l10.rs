//! ISSUE-4.10 / L-10: refuse non-loopback metrics binds without explicit
//! opt-in.
//!
//! These tests exercise the `InsecureGate` configuration that `bin/rvc`'s
//! `main.rs` uses to gate the metrics server bind address (Phase 4 fix).
//!
//! The same gate construction is used in production:
//!
//! ```text
//! if !metrics_address.is_loopback() {
//!     let gate = InsecureGate::with_predicate(
//!         "RVC_METRICS_ALLOW_NON_LOOPBACK",
//!         InsecureMode::default(),  // = Refuse (Phase 3 ISSUE-3.13 / NFR-10)
//!         || true,
//!     );
//!     gate.check()?;
//! }
//! // Loopback: skip the gate entirely (secure default).
//! ```
//!
//! End-to-end binary tests are not included here because they require a
//! full validator stack to be runnable; the gate behaviour is fully covered
//! by these contract tests against the same helper.

// RF1-12: Tests must set/clear env vars via unsafe std::env::{set_var,remove_var}.
#![allow(unsafe_code)]

use crypto::insecure::{InsecureGate, InsecureMode};
use rvc::config::{Config, StartArgs};
use std::io::Write;

const ENV_VAR: &str = "RVC_METRICS_ALLOW_NON_LOOPBACK";

/// Holds and restores the env var used by these tests, so concurrent runs
/// don't leak state into each other.  Mirrors the env-var-mutex pattern used
/// for H-9 / GA Refuse contract tests (commit ec74f5c).
///
/// Uses `MutexGuard::map(...)` rather than `lock().expect(...)` so that a
/// panicking test does not poison the lock for the remaining tests in the
/// suite.
fn with_env_var<F: FnOnce()>(value: Option<&str>, f: F) {
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    // Recover from any prior poisoning — we only care about serializing
    // env mutations, not propagating earlier test failures.
    let _guard = match ENV_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let prev = std::env::var(ENV_VAR).ok();
    // SAFETY: env mutations are serialized by ENV_LOCK above.
    unsafe {
        match value {
            Some(v) => std::env::set_var(ENV_VAR, v),
            None => std::env::remove_var(ENV_VAR),
        }
    }
    f();
    // SAFETY: same lock.
    unsafe {
        match prev {
            Some(p) => std::env::set_var(ENV_VAR, p),
            None => std::env::remove_var(ENV_VAR),
        }
    }
}

/// Build the same InsecureGate the production code constructs in the
/// non-loopback branch.
fn metrics_gate() -> InsecureGate {
    InsecureGate::with_predicate(ENV_VAR, InsecureMode::default(), || true)
}

#[test]
fn test_non_loopback_metrics_refused_without_env_var() {
    with_env_var(None, || {
        let err = metrics_gate().check().expect_err("non-loopback bind must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains(ENV_VAR),
            "error message must reference the opt-in env var, got: {msg}"
        );
    });
}

#[test]
fn test_non_loopback_metrics_allowed_with_env_var() {
    with_env_var(Some("true"), || {
        metrics_gate().check().expect("non-loopback bind with env var=true must pass");
    });
}

#[test]
fn test_non_loopback_metrics_env_var_must_be_true_literal() {
    // Spec: env var must equal exactly "true" (case-sensitive); other
    // truthy values should NOT bypass the gate.
    with_env_var(Some("1"), || {
        assert!(metrics_gate().check().is_err(), "env=\"1\" must not bypass the gate");
    });
    with_env_var(Some("TRUE"), || {
        assert!(metrics_gate().check().is_err(), "env=\"TRUE\" must not bypass the gate");
    });
}

/// ADR-009 falsifier: a TOML `metrics_port = 9090` is the bind port when the
/// clap flag is absent. Same shape as the L-10 gate tests — no full process.
#[test]
fn toml_metrics_port_9090_binds_9090() {
    let mut file = tempfile::NamedTempFile::new().expect("temp config");
    writeln!(file, "metrics_port = 9090").expect("write");
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("load");
    assert_eq!(cfg.metrics_port, 9090);
}
