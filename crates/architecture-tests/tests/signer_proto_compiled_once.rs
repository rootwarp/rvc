//! RF3-14: `signer.v2.proto` must be compiled by exactly one `build.rs`.
//!
//! Allowed `compile_protos` call sites:
//! - `crates/signer-proto/build.rs` (signer.v2)
//!
//! Any other build script compiling protos is a regression of dual-type generation.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_build_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip target and hidden dirs.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_build_rs(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("build.rs") {
            out.push(path);
        }
    }
}

/// Returns workspace-relative `/`-separated path for stable assertions.
fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn test_v2_proto_compiled_once() {
    let root = workspace_root();
    let mut build_scripts = Vec::new();
    collect_build_rs(&root.join("crates"), &mut build_scripts);
    collect_build_rs(&root.join("bin"), &mut build_scripts);

    let mut compile_sites: Vec<String> = Vec::new();
    for script in &build_scripts {
        let Ok(src) = std::fs::read_to_string(script) else {
            continue;
        };
        // Comment-strip is unnecessary: we only care about live compile_protos calls.
        // A commented-out call would still be a smell but is not the dual-type
        // regression this gate targets.
        if src.contains("compile_protos") {
            compile_sites.push(rel_path(&root, script));
        }
    }
    compile_sites.sort();

    let expected = ["crates/signer-proto/build.rs"];
    assert_eq!(
        compile_sites, expected,
        "signer.v2.proto must be compiled only in crates/signer-proto/build.rs; found {compile_sites:?}"
    );

    let signer_proto_build = std::fs::read_to_string(root.join("crates/signer-proto/build.rs"))
        .expect("signer-proto build.rs");
    assert!(
        signer_proto_build.contains("signer.v2.proto"),
        "crates/signer-proto/build.rs must compile signer.v2.proto"
    );
    assert!(
        !signer_proto_build.contains("duty_tracker.proto"),
        "crates/signer-proto must not compile duty_tracker.proto"
    );

    assert!(
        !root.join("crates/rvc/build.rs").exists(),
        "crates/rvc/build.rs must be deleted (ARCH-7d)"
    );

    // Consumers must not keep a local build.rs.
    assert!(
        !root.join("bin/rvc-signer/build.rs").exists(),
        "bin/rvc-signer/build.rs must be deleted (RF3-14)"
    );
    assert!(
        !root.join("crates/grpc-signer/build.rs").exists(),
        "crates/grpc-signer/build.rs must be deleted (RF3-14)"
    );
}
