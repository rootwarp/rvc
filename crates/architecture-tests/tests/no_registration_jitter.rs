//! W4-E6a (654-AC7): builder registration has no random delay.
//!
//! The scan reads each tracked `*.rs` file under `crates/` (`git ls-files`).
//! A file fails when it contains the name of the old delay helper or the old
//! delay log text. This file builds the two strings from parts, so the scan
//! does not find them in this file.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The strings that must not come back.
const FORBIDDEN: [&str; 2] = [concat!("jitter", "_seconds"), concat!("with", " jitter")];

fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().and_then(Path::parent).expect("The workspace root must exist.").to_path_buf()
}

/// The tracked `*.rs` files under `crates/`, relative to the workspace root.
fn tracked_rs_files(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["-c", "core.quotePath=false", "ls-files", "-z", "--", "crates"])
        .current_dir(root)
        .output()
        .expect("The test must run git ls-files.");
    assert!(
        output.status.success(),
        "git ls-files must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
        .map(|raw| String::from_utf8(raw.to_vec()).expect("Each tracked path must be UTF-8."))
        .filter(|path| path.ends_with(".rs"))
        .collect()
}

#[test]
fn no_jitter_seconds_in_crates() {
    let root = workspace_root();
    let files = tracked_rs_files(&root);
    assert!(
        files.len() > 100,
        "The scan must read the tracked crate sources, but it read {} files.",
        files.len()
    );
    let mut offenders = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(root.join(path))
            .unwrap_or_else(|error| panic!("The test must read {path}: {error}"));
        for needle in FORBIDDEN.iter().filter(|needle| source.contains(**needle)) {
            offenders.push(format!("{path}: {needle}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "Builder registration must not have a random delay. Found:\n  {}",
        offenders.join("\n  ")
    );
}
