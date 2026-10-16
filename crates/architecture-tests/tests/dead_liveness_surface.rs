//! RV-1.5: the unused liveness-checker surface stays deleted.
//!
//! `ValidatorLivenessData` is the live sample type and is not part of this ban.

use std::path::{Path, PathBuf};

const BANNED: &[&str] =
    &["LivenessChecker", "DoppelgangerStatus", "DoppelgangerResult", "BeaconLivenessAdapter"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() || needle.len() > bytes.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
            let after = i + needle.len();
            let after_ok = after == bytes.len() || !is_ident_char(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[test]
fn dead_liveness_names_are_absent_from_rust_sources() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs(&root.join("crates"), &mut files);
    collect_rs(&root.join("bin"), &mut files);
    let mut hits = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.ends_with("dead_liveness_surface.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for word in BANNED {
            if contains_word(&text, word) {
                hits.push(format!("{rel}: {word}"));
            }
        }
    }
    assert!(hits.is_empty(), "dead liveness surface returned:\n{}", hits.join("\n"));
}

#[test]
fn doppelganger_crate_does_not_depend_on_async_trait() {
    let path = workspace_root().join("crates/doppelganger/Cargo.toml");
    let text = std::fs::read_to_string(&path).expect("doppelganger Cargo.toml");
    assert!(
        !text.lines().any(|line| line.contains("async-trait")),
        "async-trait must not return to the doppelganger crate"
    );
}

#[test]
fn validator_liveness_data_remains() {
    let path = workspace_root().join("crates/doppelganger/src/traits.rs");
    let text = std::fs::read_to_string(&path).expect("traits.rs");
    assert!(
        contains_word(&text, "ValidatorLivenessData"),
        "ValidatorLivenessData is the live sample type"
    );
}
