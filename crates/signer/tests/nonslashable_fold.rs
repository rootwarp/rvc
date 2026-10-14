//! ARCH-5c / ARCH-P1-6: one `DEFAULT_SIGN_TIMEOUT` and one non-slashable flow.
//!
//! `SigningGate` and `SignerService` must differ only in policy inputs, not in a
//! duplicated timeout constant or a second copy of the non-slashable sign path.
//! These source-text assertions are the workspace grep gate the PRD names.

use std::path::{Path, PathBuf};

fn signer_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn production_text(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

/// `rg -c 'const DEFAULT_SIGN_TIMEOUT' crates/signer/src` must return 1.
#[test]
fn test_one_default_sign_timeout_declaration() {
    let mut files = Vec::new();
    collect_rs(&signer_src_dir(), &mut files);
    files.sort();

    let mut hits = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read signer src");
        for (idx, line) in source.lines().enumerate() {
            if line.contains("const DEFAULT_SIGN_TIMEOUT") {
                hits.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }

    assert_eq!(
        hits.len(),
        1,
        "ARCH-P1-6: expected exactly one `const DEFAULT_SIGN_TIMEOUT` in crates/signer/src; found:\n{}",
        hits.join("\n")
    );
}

/// Both facades delegate; the timeout+sign match lives only in `core.rs`.
#[test]
fn test_nonslashable_entry_points_delegate_to_core() {
    let src = signer_src_dir();
    let core = std::fs::read_to_string(src.join("core.rs")).expect("read core.rs");
    let gate = std::fs::read_to_string(src.join("gate.rs")).expect("read gate.rs");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("read lib.rs");

    assert!(
        production_text(&core).contains("async fn sign_nonslashable_core"),
        "ARCH-5c: sign_nonslashable_core must be defined in crates/signer/src/core.rs"
    );

    let gate_prod = production_text(&gate);
    let lib_prod = production_text(&lib);
    assert!(
        gate_prod.contains("sign_nonslashable_core"),
        "SigningGate must delegate the non-slashable flow to sign_nonslashable_core"
    );
    assert!(
        lib_prod.contains("sign_nonslashable_core"),
        "SignerService must delegate the non-slashable flow to sign_nonslashable_core"
    );

    assert!(
        !gate_prod.contains("tokio::time::timeout("),
        "SigningGate must not own a second timeout(sign) implementation"
    );
    assert!(
        !lib_prod.contains("tokio::time::timeout("),
        "SignerService must not own a second timeout(sign) implementation"
    );
}
