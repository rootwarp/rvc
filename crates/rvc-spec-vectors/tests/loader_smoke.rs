//! Hermetic smoke test for the path-injected vector loader.
//!
//! The only input is the committed fixture tree under `tests/fixtures/`.
//! Env mutation for skip-vs-required lives here (one test); every other
//! case passes the directory explicitly.

// RF1-12: Tests must set/clear env vars via unsafe std::env::{set_var,remove_var}.
#![allow(unsafe_code)]

mod support;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rvc_spec_vectors::loader::{decode_snappy, roots_yaml, VectorError, VectorRoot};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvRestore {
    dir: Option<OsString>,
    required: Option<OsString>,
}

impl EnvRestore {
    fn set(dir: Option<&Path>, required: Option<&str>) -> Self {
        let prev = Self {
            dir: std::env::var_os("RVC_SPEC_VECTORS_DIR"),
            required: std::env::var_os("RVC_SPEC_VECTORS_REQUIRED"),
        };
        unsafe {
            match dir {
                Some(p) => std::env::set_var("RVC_SPEC_VECTORS_DIR", p),
                None => std::env::remove_var("RVC_SPEC_VECTORS_DIR"),
            }
            match required {
                Some(v) => std::env::set_var("RVC_SPEC_VECTORS_REQUIRED", v),
                None => std::env::remove_var("RVC_SPEC_VECTORS_REQUIRED"),
            }
        }
        prev
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        unsafe {
            match &self.dir {
                Some(v) => std::env::set_var("RVC_SPEC_VECTORS_DIR", v),
                None => std::env::remove_var("RVC_SPEC_VECTORS_DIR"),
            }
            match &self.required {
                Some(v) => std::env::set_var("RVC_SPEC_VECTORS_REQUIRED", v),
                None => std::env::remove_var("RVC_SPEC_VECTORS_REQUIRED"),
            }
        }
    }
}

fn with_vector_env<T>(dir: Option<&Path>, required: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _restore = EnvRestore::set(dir, required);
    f()
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_loader_parses_electra_ssz_static_attestation_data() {
    let root = VectorRoot::new(fixtures_root()).expect("fixture tree must exist");
    let cases = root.cases("electra", "ssz_static", "AttestationData").expect("walk cases");
    assert!(cases.cases_run() > 0, "vacuous AttestationData suite");

    let mut seen = 0usize;
    for case in cases {
        let yaml = fs::read_to_string(case.path.join("roots.yaml"))
            .unwrap_or_else(|e| panic!("read roots.yaml in {}: {e}", case.path.display()));
        let roots = roots_yaml(&yaml)
            .unwrap_or_else(|e| panic!("parse roots.yaml in {}: {e}", case.path.display()));
        assert!(
            roots.root.starts_with("0x"),
            "{}: root must be 0x-prefixed, got {:?}",
            case.path.display(),
            roots.root
        );

        let compressed = fs::read(case.path.join("serialized.ssz_snappy")).unwrap_or_else(|e| {
            panic!("read serialized.ssz_snappy in {}: {e}", case.path.display())
        });
        let decoded = decode_snappy(&compressed)
            .unwrap_or_else(|e| panic!("decode snappy in {}: {e}", case.path.display()));
        assert!(!decoded.is_empty(), "{}: decompressed SSZ must not be empty", case.path.display());
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn test_malformed_snappy_is_typed_error() {
    let err = decode_snappy(&[0xff, 0x00, 0xff, 0x00]).expect_err("corrupt snappy must fail");
    assert!(matches!(err, VectorError::Snappy(_)), "expected VectorError::Snappy, got {err:?}");
}

#[test]
fn test_malformed_yaml_is_typed_error() {
    let err = roots_yaml(": this is not: valid: yaml: [").expect_err("corrupt YAML must fail");
    assert!(matches!(err, VectorError::Yaml(_)), "expected VectorError::Yaml, got {err:?}");
}

#[test]
fn test_missing_root_directory_is_typed_error_naming_path() {
    let missing = fixtures_root().join("does-not-exist-229");
    let err = VectorRoot::new(&missing).expect_err("missing root must fail");
    match &err {
        VectorError::MissingRoot { path } => {
            assert_eq!(path, &missing);
        }
        other => panic!("expected VectorError::MissingRoot, got {other:?}"),
    }
    let rendered = err.to_string();
    assert!(
        rendered.contains(&missing.display().to_string()),
        "error must name the path: {rendered}"
    );
}

#[test]
fn test_vector_root_from_env_skip_vs_required() {
    let fixtures = fixtures_root();
    with_vector_env(Some(&fixtures), None, || {
        let root = support::vector_root_from_env().expect("fixture tree must resolve from env");
        assert_eq!(root.path(), fixtures.as_path());
    });

    let missing = fixtures.join("does-not-exist-230");
    with_vector_env(Some(&missing), None, || {
        assert!(
            support::vector_root_from_env().is_none(),
            "unset REQUIRED must skip when the cache dir is missing"
        );
    });

    with_vector_env(Some(&missing), Some("1"), || {
        let panicked = std::panic::catch_unwind(|| {
            let _ = support::vector_root_from_env();
        });
        let payload = panicked.expect_err("REQUIRED=1 must fail when the cache dir is missing");
        let msg = panic_message(payload);
        assert!(
            msg.contains(&missing.display().to_string()),
            "failure must name the missing dir: {msg}"
        );
        assert!(msg.contains("make spec-vectors"), "failure must name the make target: {msg}");
    });

    let empty = tempfile::tempdir().expect("empty cache dir");
    with_vector_env(Some(empty.path()), None, || {
        assert!(
            support::vector_root_from_env().is_none(),
            "mkdir-only cache dir must skip when REQUIRED is unset"
        );
    });
    with_vector_env(Some(empty.path()), Some("1"), || {
        let panicked = std::panic::catch_unwind(|| {
            let _ = support::vector_root_from_env();
        });
        let payload = panicked.expect_err("REQUIRED=1 must fail on an empty cache dir");
        let msg = panic_message(payload);
        assert!(
            msg.contains(&empty.path().display().to_string()),
            "failure must name the empty dir: {msg}"
        );
        assert!(msg.contains("make spec-vectors"), "failure must name the make target: {msg}");
    });
}

#[test]
fn test_spec_tag_rejects_dot_and_dotdot() {
    assert!(!support::is_safe_tag(""));
    assert!(!support::is_safe_tag("."));
    assert!(!support::is_safe_tag(".."));
    assert!(support::is_safe_tag("v1.7.0-beta.0"));
}
