//! Env-resolved vector root for integration tests.
//!
//! Lives under `tests/` so G-3 (`env_allowlist.rs`) never sees a production
//! `RVC_SPEC_VECTORS_*` read. Do not move this into `src/`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rvc_spec_vectors::loader::VectorRoot;

/// `RVC_SPEC_VECTORS_DIR`, or `crates/rvc-spec-vectors/vectors/<tag>` from `vectors.lock`.
///
/// Missing cache: `RVC_SPEC_VECTORS_REQUIRED=1` panics (names the dir and
/// `make spec-vectors`); otherwise prints a skip line and returns `None`.
pub fn vector_root_from_env() -> Option<VectorRoot> {
    let dir = std::env::var("RVC_SPEC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_vector_dir());
    // `is_dir()` alone is not enough: an empty mkdir would green REQUIRED=1.
    if is_vector_cache(&dir) {
        Some(VectorRoot::new(&dir).unwrap_or_else(|e| panic!("vector root {}: {e}", dir.display())))
    } else if vectors_required() {
        panic!("{}", cache_absent_message(&dir));
    } else {
        eprintln!("skipping: {}", cache_absent_message(&dir));
        None
    }
}

fn is_vector_cache(dir: &Path) -> bool {
    dir.join("tests").is_dir()
}

fn vectors_required() -> bool {
    matches!(std::env::var("RVC_SPEC_VECTORS_REQUIRED"), Ok(v) if v == "1")
}

fn cache_absent_message(dir: &Path) -> String {
    format!("vector cache missing at {}; run `make spec-vectors`", dir.display())
}

fn default_vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors").join(spec_tag())
}

fn spec_tag() -> String {
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors.lock");
    let text =
        std::fs::read_to_string(&lock).unwrap_or_else(|e| panic!("read {}: {e}", lock.display()));
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(tag) = line.strip_prefix("SPEC_TAG=") else {
            continue;
        };
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        assert!(
            is_safe_tag(tag),
            "SPEC_TAG `{tag}` in {} must match [A-Za-z0-9._-]+ and must not be `.` or `..`",
            lock.display()
        );
        return tag.to_owned();
    }
    panic!("SPEC_TAG missing from {}", lock.display());
}

/// Same constraints as `require_tag` in `scripts/fetch_spec_vectors.sh`.
pub(crate) fn is_safe_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag != "."
        && tag != ".."
        && tag.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
