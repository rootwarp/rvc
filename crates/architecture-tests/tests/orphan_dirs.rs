//! G-1 detector D1 — every `crates/*` / `bin/*` directory with a `Cargo.toml` is a
//! workspace member (`cargo metadata --no-deps`).
//!
//! Closes the hole where non-member package trees are invisible to every architecture
//! gate that reads cargo metadata (historical: `crates/rvc-signer/`, `crates/rvc-keygen/`).
//!
//! Non-vacuity is **two** checks: directory count == member count **and** both equal the
//! absolute pin [`EXPECTED_MEMBER_COUNT`]. A bare `dirs == members` would pass on `0 == 0`.
//! ARCH-3 lowered the pin from 29 → 28 when `sync-service` is deleted.
//! ARCH-4e (`rvc-config`) raises it to 29.
//! ARCH-6f (`rvc-remote-signer-client`) raises it to 30.
//! Issue 3.1 (`rvc-spec-vectors`) raises it to 31.
//! Issue 5.1a (`rvc-gloas`) raises it to 32.
//!
//! Failure copy (VD-P1): never recommend adding to `[workspace] members` unconditionally —
//! historical orphans collide by package name with live members.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rvc_architecture_tests::{load_cargo_metadata, load_workspace_graph, workspace_root};

/// Absolute G-1 pin. ARCH-4e raised to 29; ARCH-6f (`rvc-remote-signer-client`) raises to 30.
/// Issue 3.1 (`rvc-spec-vectors`) raises to 31. Issue 5.1a (`rvc-gloas`) raises to 32.
const EXPECTED_MEMBER_COUNT: usize = 32;

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Workspace-relative package dirs under `{crates,bin}/*` that contain a `Cargo.toml`.
fn enumerate_package_dirs(root: &Path) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for top in ["crates", "bin"] {
        let parent = root.join(top);
        let Ok(entries) = fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join("Cargo.toml").is_file() {
                let name = entry.file_name();
                let rel = format!("{top}/{}", name.to_string_lossy()).replace('\\', "/");
                dirs.insert(rel);
            }
        }
    }
    dirs
}

/// Workspace-relative package dirs derived from each package's `manifest_path`.
fn member_package_dirs(root: &Path, metadata: &serde_json::Value) -> BTreeSet<String> {
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

    let mut dirs = BTreeSet::new();
    for pkg in packages {
        let mp = pkg["manifest_path"].as_str().expect("package must have a string manifest_path");
        let manifest = PathBuf::from(mp);
        let parent = manifest.parent().expect("manifest_path must have a parent directory");
        let parent_canon = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        let rel = parent_canon
            .strip_prefix(&root_canon)
            .or_else(|_| parent.strip_prefix(root))
            .unwrap_or(parent);
        dirs.insert(rel.to_string_lossy().replace('\\', "/"));
    }
    dirs
}

// ---------------------------------------------------------------------------
// Comparison (pure — synthetic tests feed crafted sets)
// ---------------------------------------------------------------------------

/// D1: every package dir is a workspace member; counts match each other and the pin.
///
/// Returns `Err` with a multi-line message naming every orphan path. Callers that only
/// need the live tree should use the integration tests below.
fn check_orphan_dirs(
    package_dirs: &BTreeSet<String>,
    member_dirs: &BTreeSet<String>,
    expected_count: usize,
) -> Result<(), String> {
    // Non-vacuity: empty filesystem walk must never pass (0 == 0 is useless).
    if package_dirs.is_empty() {
        return Err("D1 non-vacuity failed: package directory set is empty \
             (0 directories == 0 members would pass vacuously). \
             Expected at least one {crates,bin}/*/Cargo.toml under the workspace root."
            .to_string());
    }

    let dir_count = package_dirs.len();
    let member_count = member_dirs.len();
    let mut errors: Vec<String> = Vec::new();

    if dir_count != expected_count {
        errors.push(format!("directory count {dir_count} != absolute pin {expected_count}"));
    }
    if member_count != expected_count {
        errors.push(format!(
            "workspace member count {member_count} != absolute pin {expected_count}"
        ));
    }
    if dir_count != member_count {
        errors.push(format!("directory count {dir_count} != member count {member_count}"));
    }

    for orphan in package_dirs.difference(member_dirs) {
        errors.push(format!(
            "orphan package directory `{orphan}` has a Cargo.toml but is not a cargo \
             metadata workspace member. Either add it to [workspace] members **or** delete \
             it — do not add unconditionally: a same-named package elsewhere in the tree is \
             the likely cause (duplicate package names are a hard cargo error)."
        ));
    }

    for missing in member_dirs.difference(package_dirs) {
        errors.push(format!(
            "workspace member `{missing}` has no matching {{crates,bin}}/*/Cargo.toml directory"
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_every_crate_dir_is_a_workspace_member() {
    let root = workspace_root();
    let metadata = load_cargo_metadata();
    let graph = load_workspace_graph();

    let package_dirs = enumerate_package_dirs(&root);
    let member_dirs = member_package_dirs(&root, &metadata);

    assert_eq!(
        graph.package_count(),
        EXPECTED_MEMBER_COUNT,
        "WorkspaceGraph::package_count() must match absolute pin {EXPECTED_MEMBER_COUNT}"
    );

    check_orphan_dirs(&package_dirs, &member_dirs, EXPECTED_MEMBER_COUNT).unwrap_or_else(|e| {
        panic!("G-1 D1 orphan-directory gate failed:\n{e}");
    });
}

#[test]
fn test_d1_rejects_an_unregistered_manifest() {
    let root = workspace_root();
    let metadata = load_cargo_metadata();
    let member_dirs = member_package_dirs(&root, &metadata);

    let mut package_dirs = member_dirs.clone();
    package_dirs.insert("crates/scratch-orphan".to_string());

    let err = check_orphan_dirs(&package_dirs, &member_dirs, EXPECTED_MEMBER_COUNT)
        .expect_err("D1 must reject an unregistered crates/scratch-orphan manifest");

    assert!(
        err.contains("crates/scratch-orphan"),
        "failure must name the orphan path; got:\n{err}"
    );
    assert!(
        err.contains("Either add it to [workspace] members **or** delete"),
        "failure must offer members **or** delete (not add-only); got:\n{err}"
    );
    assert!(
        err.contains("same-named package"),
        "failure must note same-named package collision risk; got:\n{err}"
    );
}

#[test]
fn test_d1_empty_directory_set_fails_non_vacuity() {
    let empty = BTreeSet::new();
    let err = check_orphan_dirs(&empty, &empty, EXPECTED_MEMBER_COUNT)
        .expect_err("empty package directory set must fail (0==0 is vacuous)");

    assert!(
        err.contains("non-vacuity") || err.contains("empty"),
        "failure must cite non-vacuity / empty set; got:\n{err}"
    );
}

/// VD-P1: `rvc-config` must not collide with `rvc` / `rvc-bin` (or any other member).
#[test]
fn rvc_config_package_name_is_unique_in_the_workspace() {
    let metadata = load_cargo_metadata();
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");
    let names: Vec<&str> = packages
        .iter()
        .map(|p| p["name"].as_str().expect("package must have a string name"))
        .collect();
    assert_eq!(
        names.iter().filter(|n| **n == "rvc-config").count(),
        1,
        "package name rvc-config must appear exactly once (not rvc / rvc-bin); got {names:?}"
    );
}
