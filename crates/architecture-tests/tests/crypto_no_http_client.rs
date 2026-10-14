//! ARCH-6f: `rvc-crypto` must not declare an HTTP client.
//!
//! `reqwest` is an external crate, so cargo-metadata gates such as G-5a cannot
//! see it (VD-P5). This scan is the only detector that `remote_signer/` has
//! left `crypto`.

use std::path::{Path, PathBuf};

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
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// No file under `crates/crypto/src` may mention `reqwest`.
#[test]
fn crypto_declares_no_http_client() {
    let root = workspace_root();
    let src_dir = root.join("crates/crypto/src");
    let mut files = Vec::new();
    collect_rs(&src_dir, &mut files);
    assert!(!files.is_empty(), "crates/crypto/src walk returned no .rs files");

    let mut hits = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        for (i, line) in text.lines().enumerate() {
            if line.contains("reqwest") {
                hits.push(format!("{}:{}: {}", rel, i + 1, line.trim()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "rvc-crypto must not mention reqwest under crates/crypto/src \
         (HTTP client lives in rvc-remote-signer-client):\n  {}",
        hits.join("\n  ")
    );
}
