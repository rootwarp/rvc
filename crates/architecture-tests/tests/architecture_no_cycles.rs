//! Standing CI gate: workspace-internal dependency DAG invariants.
//!
//! Purpose
//! -------
//! Parses `cargo metadata --format-version=1 --no-deps` (via `serde_json`; the
//! `cargo_metadata` crate is NOT used — Phase-1 rule P6 prohibits new external
//! dependencies) and enforces three layers of the level-graded DAG:
//!
//! 1. The workspace-internal production dependency graph is acyclic.
//! 2. Documented forbidden edges are absent (slashing->doppelganger,
//!    signer->keymanager-api, block-service->builder, plus the general
//!    no-domain→domain rule with a grandfather allowlist).
//! 3. The expected `rvc-signer → rvc-doppelganger` edge (Issue 1.5) is present.
//! 4. The single new production edge the logging initiative introduces in Phase 2,
//!    `rvc-signer-bin → rvc-telemetry`, is allowed (never forbidden) and provably acyclic
//!    because `rvc-telemetry` is pinned as a zero-out-edge leaf sink (Issue 1.7).
//!
//! Manual verification
//! -------------------
//! During development, the forbidden-edge injection was verified once:
//!   `keymanager-api.workspace = true` was temporarily added to
//!   `crates/signer/Cargo.toml` [dependencies], the test was run, it failed with
//!   a clear "forbidden edge rvc-signer -> rvc-keymanager-api" message, and the
//!   change was immediately reverted.  `crates/signer/Cargo.toml` is back to its
//!   committed state.
//!
//! Logging initiative: the new rvc-signer-bin -> rvc-telemetry edge (Issue 1.7)
//! -----------------------------------------------------------------------------
//! `ZERO_OUT_EDGE_IF_PRESENT` lists crate names that must have zero workspace-internal
//! PRODUCTION out-edges even if they exist (leaf sinks); absent crates are skipped, so the
//! list stays forward-compatible.  Issue 1.7 pins `rvc-telemetry` there to lock the
//! acyclicity of the single new production edge the logging initiative introduces in Phase 2
//! (Issue 2.3), `rvc-signer-bin -> rvc-telemetry` (see `EXPECTED_EDGE`).  That *edge* is absent
//! on `develop` during Phase 1 (the `rvc-telemetry` *crate* exists and is leaf-checked now);
//! this gate stays green both before AND after Phase 2 adds it.
//! (`rvc-signer-registry`, a dev-only const table with no runtime out-edges, is also pinned.)

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------

/// Production edges that must never appear in the workspace graph.
///
/// Single source of truth: `rvc_architecture_tests::FORBIDDEN_EDGES`.
const FORBIDDEN: &[(&str, &str)] = rvc_architecture_tests::FORBIDDEN_EDGES;

/// Domain packages for the no-domain→domain rule.
const DOMAIN_PACKAGES: &[&str] = rvc_architecture_tests::DOMAIN_PACKAGES;

/// Grandfathered domain→domain edges (see `DOMAIN_EDGE_ALLOWLIST` docs).
const DOMAIN_EDGE_ALLOWLIST: &[(&str, &str)] = rvc_architecture_tests::DOMAIN_EDGE_ALLOWLIST;

/// Crates that must have zero workspace-internal PRODUCTION out-edges (leaf SINKS).
/// If a name is absent from `cargo metadata` output the check is skipped,
/// so this list is forward-compatible with crates that do not yet exist.
///
/// - `rvc-eth-types`: keeping it at zero out-edges is what blocks "fixing" a field-constant
///   import by adding a `uuid`/`rvc-telemetry` (or any workspace) edge to it.
/// - `rvc-signer-registry`: dev-only const table, no runtime out-edges.
/// - `rvc-telemetry`: a zero-internal-dependency leaf sink. Pinning it here locks the
///   acyclicity of the logging edges into telemetry (`EXPECTED_EDGE` and the
///   `rvc-signer-server` production edge): attaching an edge *to* a zero-out-edge
///   node can never create a cycle.
/// - `rvc-observability`: logging/hex/pubkey leaf sink (RF3-01); zero workspace out-edges so
///   dependents can take the light path without pulling BLS/KDF/HTTP via crypto.
/// - `rvc-test-support`: dev-only rcgen PKI + mTLS harness (RF6-14); external deps only
///   (rcgen/tonic/tokio), never a production edge into the workspace graph.
/// - `rvc-spec-vectors`: integration-only spec vectors + KAT codegen; external deps only
///   (none yet), never a production edge into the workspace graph.
const ZERO_OUT_EDGE_IF_PRESENT: &[&str] = &[
    "rvc-eth-types",
    "rvc-signer-registry",
    "rvc-telemetry",
    "rvc-observability",
    "rvc-signer-proto",
    "rvc-test-support",
    "rvc-spec-vectors",
];
/// Edge that MUST be present (Issue 1.5 regression guard).
const REQUIRED_EDGE: (&str, &str) = ("rvc-signer", "rvc-doppelganger");

/// Logging → telemetry leaf attachments (must stay allowed, never forbidden).
/// The bin keeps the init/reload edge; the server library carries HTTP parent
/// extraction (`set_parent_from_headers`). Both targets are the zero-out-edge
/// leaf `rvc-telemetry`, so the attachments are provably acyclic.
const EXPECTED_EDGE: (&str, &str) = ("rvc-signer-bin", "rvc-telemetry");
const EXPECTED_EDGE_SERVER: (&str, &str) = ("rvc-signer-server", "rvc-telemetry");

/// Workspace production deps that `rvc-signer-server` is allowed to take.
/// Any new production edge must be reviewed and added here deliberately —
/// do not widen this table to silence a real layering violation.
const SIGNER_SERVER_ALLOWED_EDGES: &[&str] = &[
    "rvc-crypto",
    "rvc-eth-types",
    "rvc-observability",
    "rvc-signer",
    "rvc-signer-proto",
    "rvc-slashing",
    "rvc-telemetry",
    "rvc-web3signer-wire",
];

// ---------------------------------------------------------------------------
// Helper: build the workspace-internal production edge map
// ---------------------------------------------------------------------------

/// Returns `HashMap<package_name, Vec<dep_name>>` for workspace-internal
/// **production** dependencies only (`kind == null`, `path` is a string).
fn build_edge_map(packages: &[serde_json::Value]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for pkg in packages {
        let name = pkg["name"].as_str().expect("package must have a string name").to_string();

        let deps = pkg["dependencies"].as_array().expect("package dependencies must be an array");

        let ws_production_deps: Vec<String> = deps
            .iter()
            .filter(|dep| {
                // Workspace-internal: `path` is a string (not null).
                dep["path"].as_str().is_some()
                    // Production only: `kind` is null / absent (not "dev" or "build").
                    && dep["kind"].is_null()
            })
            .map(|dep| {
                dep["name"].as_str().expect("dependency must have a string name").to_string()
            })
            .collect();

        // Always insert the key so acyclic-check sees every node.
        map.insert(name, ws_production_deps);
    }

    map
}

// ---------------------------------------------------------------------------
// Helper: DFS cycle detection (3-colour)
// ---------------------------------------------------------------------------

/// Returns `Some(cycle_path)` if a cycle exists, `None` if the graph is acyclic.
fn find_cycle(edges: &HashMap<String, Vec<String>>) -> Option<Vec<String>> {
    // 0 = white (unvisited), 1 = grey (in stack), 2 = black (done)
    let mut color: HashMap<&str, u8> = HashMap::new();
    let mut path: Vec<String> = Vec::new();

    for start in edges.keys() {
        if color.get(start.as_str()).copied().unwrap_or(0) == 0 {
            if let Some(cycle) = dfs(start, edges, &mut color, &mut path) {
                return Some(cycle);
            }
        }
    }
    None
}

fn dfs<'a>(
    node: &'a str,
    edges: &'a HashMap<String, Vec<String>>,
    color: &mut HashMap<&'a str, u8>,
    path: &mut Vec<String>,
) -> Option<Vec<String>> {
    color.insert(node, 1); // grey
    path.push(node.to_string());

    if let Some(neighbours) = edges.get(node) {
        for next in neighbours {
            let next_str: &'a str = {
                // Re-borrow from the map key whose lifetime is 'a.
                edges
                    .keys()
                    .find(|k| k.as_str() == next.as_str())
                    .map(|k| k.as_str())
                    .unwrap_or(next.as_str())
            };
            match color.get(next_str).copied().unwrap_or(0) {
                1 => {
                    // Back-edge found: reconstruct the cycle portion.
                    let cycle_start = path
                        .iter()
                        .position(|n| n == next_str)
                        .expect("invariant: grey node must be in DFS path");
                    let mut cycle = path[cycle_start..].to_vec();
                    cycle.push(next_str.to_string());
                    return Some(cycle);
                }
                0 => {
                    if let Some(cycle) = dfs(next_str, edges, color, path) {
                        return Some(cycle);
                    }
                }
                _ => {} // black: already fully explored
            }
        }
    }

    path.pop();
    color.insert(node, 2); // black
    None
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn architecture_no_cycles() {
    // ------------------------------------------------------------------
    // 1. Run `cargo metadata`
    // ------------------------------------------------------------------
    // CARGO_MANIFEST_DIR is crates/architecture-tests; cargo walks up to
    // the workspace root automatically.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");

    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(manifest_dir)
        .output()
        .expect("cargo metadata must run; cargo must be on PATH");

    assert!(
        output.status.success(),
        "cargo metadata exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output must be valid JSON");

    // ------------------------------------------------------------------
    // 2. Assert metadata_version >= 1
    // ------------------------------------------------------------------
    let version = metadata["version"].as_u64().expect("metadata 'version' field must be a number");
    assert!(
        version == 1,
        "cargo metadata format version 1 expected, got {version}; update this gate if the schema changed"
    );

    // ------------------------------------------------------------------
    // 3. Build workspace-internal production edge map
    // ------------------------------------------------------------------
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");

    let edges = build_edge_map(packages);

    // ------------------------------------------------------------------
    // 4. Cycle detection
    // ------------------------------------------------------------------
    if let Some(cycle) = find_cycle(&edges) {
        panic!(
            "workspace-internal production dependency graph contains a cycle: {}",
            cycle.join(" -> ")
        );
    }

    // ------------------------------------------------------------------
    // 5. Forbidden edges must be absent
    // ------------------------------------------------------------------
    for (from, to) in FORBIDDEN {
        let has_edge = edges.get(*from).is_some_and(|deps| deps.contains(&to.to_string()));
        assert!(!has_edge, "forbidden edge present in workspace graph: {from} -> {to}");
    }

    // ------------------------------------------------------------------
    // 5b. Expected/allowed leaf-attachment edges into rvc-telemetry
    //     (bin init/reload + signer-server HTTP parent extraction).
    //     Must never be forbidden; target must stay a zero-out-edge leaf sink.
    // ------------------------------------------------------------------
    for edge in [EXPECTED_EDGE, EXPECTED_EDGE_SERVER] {
        assert!(
            !FORBIDDEN.contains(&edge),
            "expected leaf-attachment edge {} -> {} must remain allowed, not forbidden",
            edge.0,
            edge.1
        );
        if edges.get(edge.0).is_some_and(|d| d.contains(&edge.1.to_string())) {
            assert!(
                ZERO_OUT_EDGE_IF_PRESENT.contains(&edge.1),
                "edge {} -> {} is present but its target is not pinned as a zero-out-edge leaf sink",
                edge.0,
                edge.1
            );
        }
    }

    // ------------------------------------------------------------------
    // 5c. RF6-25: no domain→domain edges except the grandfather allowlist.
    //     Domain set = Layer::Domain (yellow) packages. Peer duty crates must
    //     not depend on each other; shared helpers live in non-domain homes
    //     (e.g. CircuitBreakerState in rvc-signer::service_util).
    // ------------------------------------------------------------------
    {
        let domain: HashSet<&str> = DOMAIN_PACKAGES.iter().copied().collect();
        let allow: HashSet<(&str, &str)> = DOMAIN_EDGE_ALLOWLIST.iter().copied().collect();
        let mut violations: Vec<String> = Vec::new();
        for (from, deps) in &edges {
            if !domain.contains(from.as_str()) {
                continue;
            }
            for to in deps {
                if domain.contains(to.as_str()) && !allow.contains(&(from.as_str(), to.as_str())) {
                    violations.push(format!("{from} -> {to}"));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "forbidden domain→domain edge(s): [{}]. \
             Domain crates must not depend on peer domain crates. \
             Fix the edge (shared type in a non-domain / shared home) or add a \
             deliberate grandfather entry to DOMAIN_EDGE_ALLOWLIST with a comment.",
            violations.join(", ")
        );
    }

    // ------------------------------------------------------------------
    // 6. Zero-out-edge crates (rvc-eth-types always; others if present)
    // ------------------------------------------------------------------
    let all_package_names: HashSet<&str> =
        packages.iter().filter_map(|p| p["name"].as_str()).collect();

    for crate_name in ZERO_OUT_EDGE_IF_PRESENT {
        if !all_package_names.contains(*crate_name) {
            // Crate not yet in workspace — forward-compat skip.
            continue;
        }
        let out_edges = edges.get(*crate_name).map_or(0, |deps| deps.len());
        assert!(
            out_edges == 0,
            "{crate_name} must be a workspace leaf (zero production out-edges) \
             but has {out_edges} edge(s): {:?}",
            edges.get(*crate_name).unwrap()
        );
    }

    // ------------------------------------------------------------------
    // 7. Required edge: rvc-signer -> rvc-doppelganger (Issue 1.5 guard)
    // ------------------------------------------------------------------
    let (req_from, req_to) = REQUIRED_EDGE;
    let signer_deps = edges.get(req_from).unwrap_or_else(|| {
        panic!("package '{req_from}' not found in workspace metadata");
    });
    assert!(
        signer_deps.contains(&req_to.to_string()),
        "required edge missing: {req_from} -> {req_to} \
         (Issue 1.5 regression — rvc-signer must depend on rvc-doppelganger)"
    );

    // ------------------------------------------------------------------
    // 8. RF3-02: beacon must not take a production edge into rvc-crypto
    //    (logging/hex/pubkey live in rvc-observability; beacon is the
    //    low-level HTTP client that previously pulled blst/scrypt/reqwest
    //    via crypto just to redact a URL).
    //    Package name is `beacon` (not `rvc-beacon`) per crates/beacon/Cargo.toml.
    // ------------------------------------------------------------------
    let beacon_deps = edges.get("beacon").unwrap_or_else(|| {
        panic!("package 'beacon' not found in workspace metadata");
    });
    assert!(
        !beacon_deps.contains(&"rvc-crypto".to_string()),
        "RF3-02: forbidden production edge beacon -> rvc-crypto still present; \
         beacon must depend on rvc-observability only for logging"
    );
}

/// RF3-02 named gate: beacon has no production dependency on rvc-crypto.
///
/// Implemented as a focused test so the acceptance criterion
/// `beacon_has_no_crypto_production_edge` is greppable; the body reuses the
/// same metadata edge map as the standing acyclicity gate above.
#[test]
fn beacon_has_no_crypto_production_edge() {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap())
        .output()
        .expect("failed to run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output must be valid JSON");
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");
    let edges = build_edge_map(packages);
    let beacon_deps = edges.get("beacon").expect("package 'beacon' must exist");
    assert!(
        !beacon_deps.iter().any(|d| d == "rvc-crypto"),
        "beacon must not depend on rvc-crypto in production; deps={beacon_deps:?}"
    );
    // Positive check: the light path is present.
    assert!(
        beacon_deps.iter().any(|d| d == "rvc-observability"),
        "beacon should depend on rvc-observability; deps={beacon_deps:?}"
    );
}

/// RF5-25: `rvc-signer-server` is a first-class workspace package whose
/// production edges are named in `SIGNER_SERVER_ALLOWED_EDGES`.
#[test]
fn test_signer_server_crate_edges_conform_to_layer_policy() {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap())
        .output()
        .expect("failed to run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output must be valid JSON");
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");
    let edges = build_edge_map(packages);

    let server_deps = edges.get("rvc-signer-server").unwrap_or_else(|| {
        panic!(
            "package 'rvc-signer-server' not found in workspace metadata — \
             crates/signer-server must be a workspace member"
        );
    });

    let allowed: HashSet<&str> = SIGNER_SERVER_ALLOWED_EDGES.iter().copied().collect();
    let unexpected: Vec<&str> =
        server_deps.iter().map(String::as_str).filter(|d| !allowed.contains(d)).collect();
    assert!(
        unexpected.is_empty(),
        "rvc-signer-server has production edges not in SIGNER_SERVER_ALLOWED_EDGES: {unexpected:?}; \
         deps={server_deps:?}. Fix the edge or add it deliberately to the allow table."
    );

    // Shim edge: the bin depends on the library (and keeps telemetry for init).
    let bin_deps = edges.get("rvc-signer-bin").expect("rvc-signer-bin must exist");
    assert!(
        bin_deps.iter().any(|d| d == "rvc-signer-server"),
        "rvc-signer-bin must depend on rvc-signer-server; deps={bin_deps:?}"
    );
}

/// RF5-25: `bin/rvc-signer/src` is a CLI-only shim — no library modules.
#[test]
fn test_bin_rvc_signer_contains_only_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let src = root.join("bin/rvc-signer/src");
    assert!(src.is_dir(), "bin/rvc-signer/src missing at {}", src.display());

    let mut entries: Vec<String> = std::fs::read_dir(&src)
        .expect("read bin/rvc-signer/src")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();

    assert_eq!(
        entries,
        vec!["main.rs".to_string()],
        "bin/rvc-signer/src must contain only main.rs after the signer-server promotion; found {entries:?}"
    );

    // Cargo.toml must not declare a [lib] target.
    let cargo_toml = std::fs::read_to_string(root.join("bin/rvc-signer/Cargo.toml"))
        .expect("read bin/rvc-signer/Cargo.toml");
    assert!(
        !cargo_toml.contains("[lib]"),
        "bin/rvc-signer/Cargo.toml must not declare [lib]; library lives in crates/signer-server"
    );
}
