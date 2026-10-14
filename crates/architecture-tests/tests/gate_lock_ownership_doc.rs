//! RR0-04 / #497: signing-gate docs must not describe a cancellation-released lock
//! or a SQLite transaction held across the sign.
//!
//! Scans `crates/signer/src/gate.rs` and `ARCHITECTURE.md` for the three literals
//! that stated the old model. The corrected text must not contain them.

use std::path::{Path, PathBuf};

/// Literals from the pre-fix docs. Presence in either scanned file fails the gate.
const FORBIDDEN: &[&str] = &[
    "the tokio lock is released",
    "AUTHORITATIVE double-sign serializer",
    "across the stage→sign→commit window",
];

/// Workspace-relative paths. Resolved from the crate manifest, two levels up.
const SCANNED: &[&str] = &["crates/signer/src/gate.rs", "ARCHITECTURE.md"];

fn workspace_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<root>/crates/architecture-tests`.
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn forbidden_in(text: &str) -> Vec<&'static str> {
    FORBIDDEN.iter().copied().filter(|lit| text.contains(lit)).collect()
}

#[test]
fn gate_doc_does_not_claim_cancellation_releases_lock() {
    let root = workspace_root();
    assert!(!FORBIDDEN.is_empty(), "scan has no literals");
    assert!(!SCANNED.is_empty(), "scan has no files");
    for rel in SCANNED {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {rel} ({}): {e}", path.display()));
        assert!(!text.is_empty(), "{rel} was read but is empty");
        let found = forbidden_in(&text);
        assert!(found.is_empty(), "{rel} contains forbidden literal: {}", found.join("; "));
    }
}

/// The matcher itself reports each needle. A clean tree alone would not prove that.
#[test]
fn forbidden_literal_scan_is_not_vacuous() {
    assert_eq!(FORBIDDEN.len(), 3);
    for lit in FORBIDDEN {
        let sample = format!("before {lit} after");
        let found = forbidden_in(&sample);
        assert_eq!(found, vec![*lit], "scanner missed {lit:?}");
    }
    assert!(forbidden_in("the per-pubkey lock stays on the blocking task").is_empty());
}
