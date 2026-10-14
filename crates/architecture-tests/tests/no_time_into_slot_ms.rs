//! T16 / TRC-4d: the non-canonical key `time_into_slot_ms` must not appear.
//!
//! The registry spelling is `observability::logging::fields::TIME_INTO_SLOT`
//! (`time_into_slot`). Gate 5's curated event set does not cover
//! `timing` `current_slot`, so this literal grep is the standing check that
//! the old key cannot return under `crates/*/src` or `bin/*/src`.
//!
//! Same production walk as `no_rvc_prefixed_keys_outside_allow_lists`
//! (`no_rvc_prefix.rs`). Integration tests under `crates/*/tests` and
//! `bin/*/tests` are not scanned, which is why this file may name the
//! forbidden string. No comment strip: any occurrence of the literal fails.

use std::path::{Path, PathBuf};

/// Non-canonical span field key. Emit `time_into_slot` instead.
const FORBIDDEN_KEY: &str = "time_into_slot_ms";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/crates/architecture-tests`; the workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// All production source files: `crates/*/src/**.rs` + `bin/*/src/**.rs`.
fn production_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        let Ok(entries) = std::fs::read_dir(root.join(base)) else { continue };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out
}

fn file_has_forbidden_key(src: &str) -> bool {
    src.contains(FORBIDDEN_KEY)
}

/// T16: `time_into_slot_ms` appears nowhere in tracked production source.
#[test]
fn t16_no_time_into_slot_ms_in_production_source() {
    let root = workspace_root();
    let files = production_rs_files(&root);
    // Floor against a vacuous pass if directory enumeration ever silently fails.
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());
    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if file_has_forbidden_key(&std::fs::read_to_string(&file).unwrap_or_default()) {
            offenders.push(rel);
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "non-canonical key `{FORBIDDEN_KEY}` found in production source.\n\
         Emit `time_into_slot` (observability::logging::fields::TIME_INTO_SLOT):\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn matcher_flags_old_key_and_ignores_canonical() {
    assert!(file_has_forbidden_key(
        r#"tracing::trace!(slot, epoch, time_into_slot_ms, "slot transition");"#
    ));
    assert!(file_has_forbidden_key("let time_into_slot_ms = 0;"));
    // The canonical key is a prefix of the forbidden literal and must not match.
    assert!(!file_has_forbidden_key(
        r#"tracing::trace!(slot, epoch, time_into_slot, "slot transition");"#
    ));
    assert!(!file_has_forbidden_key("let time_into_slot = 0u64;"));
}
