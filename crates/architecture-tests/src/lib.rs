//! Architecture documentation generator and shared cargo-metadata helpers.
//!
//! The standing CI gate for ARCHITECTURE.md is:
//! `tests/architecture_doc_matches_graph.rs` — generated block must equal the
//! in-file block between `<!-- BEGIN GENERATED -->` / `<!-- END GENERATED -->`.
//!
//! Regenerate with:
//! ```text
//! make architecture-doc
//! # or
//! cargo run -p rvc-architecture-tests --bin generate-architecture-md
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Markers that delimit the auto-generated section of `ARCHITECTURE.md`.
pub const BEGIN_GENERATED: &str = "<!-- BEGIN GENERATED -->";
pub const END_GENERATED: &str = "<!-- END GENERATED -->";

/// Exact command printed on mismatch and documented in ARCHITECTURE.md.
pub const REGENERATE_COMMAND: &str =
    "make architecture-doc   # or: cargo run -p rvc-architecture-tests --bin generate-architecture-md";

/// Layer used for mermaid node styling (human judgement; edges come from cargo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Binary entry points (`bin/*`).
    Binary,
    /// Core orchestrator library (`rvc`).
    Orchestrator,
    /// Domain crates (duty-specific logic).
    Domain,
    /// Base crates (pure leaves; Base may depend only on Base).
    Base,
    /// Infra crates (I/O services; must not depend on Domain).
    Infra,
    /// Dev/meta crates (tests, harnesses) — not production runtime.
    Meta,
}

impl Layer {
    fn mermaid_style(self) -> &'static str {
        match self {
            Layer::Binary => "fill:#4a9eff,color:#fff",
            Layer::Orchestrator => "fill:#ff6b6b,color:#fff",
            Layer::Domain => "fill:#ffd43b,color:#333",
            Layer::Base => "fill:#51cf66,color:#fff",
            Layer::Infra => "fill:#20c997,color:#fff",
            Layer::Meta => "fill:#adb5bd,color:#333",
        }
    }
}

/// Checked-in classification: package name → (layer, short label, one-line blurb).
///
/// Every workspace package from `cargo metadata` must appear here. Adding a
/// crate without updating this table fails generation (and thus CI).
const CLASSIFICATION: &[(&str, Layer, &str, &str)] = &[
    // Unchanged — CLI entry point.
    ("rvc-bin", Layer::Binary, "bin/rvc", "CLI entry point"),
    // Unchanged — key generation binary.
    ("rvc-keygen", Layer::Binary, "bin/rvc-keygen", "key generation"),
    // Unchanged — gRPC signing server binary.
    ("rvc-signer-bin", Layer::Binary, "bin/rvc-signer", "gRPC signing server"),
    // Unchanged — composition root.
    ("rvc", Layer::Orchestrator, "rvc", "orchestrator"),
    // Duty logic: block proposal.
    ("rvc-block-service", Layer::Domain, "block-service", "block proposals"),
    // Duty logic: MEV registration.
    ("rvc-builder", Layer::Domain, "builder", "MEV registration"),
    // Duty-safety policy: duplicate detection.
    ("rvc-doppelganger", Layer::Domain, "doppelganger", "duplicate detection"),
    // Duty cache.
    ("rvc-duty-tracker", Layer::Domain, "duty-tracker", "duty cache"),
    // Safe-signing choke point (C9 anchor 2/5).
    ("rvc-signer", Layer::Domain, "signer", "safe signing"),
    // Remote-signing library over the domain signing stack.
    ("rvc-signer-server", Layer::Domain, "signer-server", "remote signing lib"),
    // Domain is deliberate (A-4.2): operator config names duty/slashing/proposer
    // concepts (Network, SlashedAction, slashing/proposer/builder sections). Sole
    // WS edge is eth-types, so G-5a does not force Domain. Phase 4 member; draft
    // 28-row table is pre-rvc-config.
    ("rvc-config", Layer::Domain, "config", "operator config names domain concepts"),
    // Reclassified Domain → Base (VD-3): pure slot arithmetic; sole WS out-edge
    // is eth-types (Base). No I/O, no duty policy. Lock-step with DOMAIN_PACKAGES.
    ("rvc-timing", Layer::Base, "timing", "slot clock"),
    // Consensus types + SSZ; zero workspace out-edges, already pinned.
    ("rvc-eth-types", Layer::Base, "eth-types", "consensus types"),
    // Gloas progressive SSZ island. Permitted production out-edge: rvc-eth-types.
    ("rvc-gloas", Layer::Base, "rvc-gloas", "Gloas progressive SSZ"),
    // Zero WS out-edges; ADR-011 pure leaf. Tension (A-6-3): axum listener in server.rs.
    ("rvc-metrics", Layer::Base, "metrics", "prometheus"),
    // Logging-field registry + redaction helpers; zero out-edges, already pinned.
    ("rvc-observability", Layer::Base, "observability", "logging helpers"),
    // Generated protobuf types only; zero out-edges, already pinned.
    ("rvc-signer-proto", Layer::Base, "signer-proto", "gRPC protobuf"),
    // Const sign-type table; already pinned. Review omits this member (VD-A1).
    ("rvc-signer-registry", Layer::Base, "signer-registry", "sign type table"),
    // OTel/subscriber construction; zero out-edges, already pinned.
    ("rvc-telemetry", Layer::Base, "telemetry", "OTel tracing"),
    // Pure serde wire types; sole out-edge eth-types (Base).
    ("rvc-web3signer-wire", Layer::Base, "web3signer-wire", "remote sign wire"),
    // BLS + EIP-2333 + keystore. ARCH-6f extracted remote_signer/ (reqwest +
    // web3signer-wire). Remaining WS out-edges: observability, eth-types (Base).
    ("rvc-crypto", Layer::Base, "crypto", "BLS, EIP-2333, keystore"),
    // Beacon-API HTTP client — network I/O.
    ("beacon", Layer::Infra, "beacon", "HTTP client"),
    // Multi-BN pool, failover, SSE — network I/O.
    ("rvc-bn-manager", Layer::Infra, "bn-manager", "multi-BN"),
    // tonic/gRPC client — network I/O. Review omits this member (VD-A1).
    ("rvc-grpc-signer", Layer::Infra, "grpc-signer", "gRPC signer client"),
    // Key-management REST surface — network I/O.
    ("rvc-keymanager-api", Layer::Infra, "keymanager-api", "key mgmt REST"),
    // Web3Signer HTTP client; reqwest — network I/O. Out-edges crypto(Base)/
    // eth-types/web3signer-wire/observability: Infra→Base only (ARCH-6f).
    ("rvc-remote-signer-client", Layer::Infra, "remote-signer-client", "Web3Signer HTTP client"),
    // Cloud KMS clients — network I/O.
    ("rvc-secret-provider", Layer::Infra, "secret-provider", "cloud key mgmt"),
    // EIP-3076 SQLite store. Structurally Base-eligible; deliberately Infra (A-6-8).
    ("rvc-slashing", Layer::Infra, "slashing", "EIP-3076"),
    // Persists validator config to disk. Structurally Base-eligible; deliberately Infra (A-6-8).
    ("rvc-validator-store", Layer::Infra, "validator-store", "validator config"),
    // Unchanged — dev-only gate harness (C9 anchor 1).
    ("rvc-architecture-tests", Layer::Meta, "architecture-tests", "DAG + doc gates"),
    // Unchanged — dev-only PKI/mTLS harness; already zero-out-edge pinned.
    ("rvc-test-support", Layer::Meta, "test-support", "PKI + mTLS harness"),
    // Integration-only spec vectors + KAT codegen; zero workspace out-edges.
    ("rvc-spec-vectors", Layer::Meta, "spec-vectors", "spec vectors + KAT codegen"),
];

/// Workspace package snapshot used by generators and gates.
#[derive(Debug, Clone)]
pub struct WorkspaceGraph {
    /// Package name → sorted production workspace dependency names.
    pub edges: BTreeMap<String, BTreeSet<String>>,
}

impl WorkspaceGraph {
    pub fn package_count(&self) -> usize {
        self.edges.len()
    }

    /// Application binaries from the classification table (not cargo target kinds).
    ///
    /// A package may expose an incidental `[[bin]]` (e.g. the architecture-doc
    /// regenerator on `rvc-architecture-tests`) without being an operator-facing
    /// binary. Layer::Binary is the human-facing inventory split; the **total**
    /// package count still matches `cargo metadata` exactly.
    pub fn binary_count(&self) -> usize {
        let class = classification_map();
        self.edges
            .keys()
            .filter(|name| {
                class
                    .get(name.as_str())
                    .map(|(layer, _, _)| *layer == Layer::Binary)
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn library_count(&self) -> usize {
        self.package_count().saturating_sub(self.binary_count())
    }
}

/// Resolve workspace root from this crate's manifest dir (`crates/architecture-tests`).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Path to root `ARCHITECTURE.md`.
pub fn architecture_md_path() -> PathBuf {
    workspace_root().join("ARCHITECTURE.md")
}

/// Run `cargo metadata --format-version=1 --no-deps` and parse packages.
pub fn load_cargo_metadata() -> serde_json::Value {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must run; cargo must be on PATH");

    assert!(
        output.status.success(),
        "cargo metadata exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output must be valid JSON");

    let version = metadata["version"].as_u64().expect("metadata 'version' field must be a number");
    assert!(
        version == 1,
        "cargo metadata format version 1 expected, got {version}; update the generator if the schema changed"
    );

    metadata
}

/// Build a deterministic workspace-internal production edge map.
///
/// Production deps only: `path` is present and `kind` is null (not dev/build).
pub fn build_workspace_graph(packages: &[serde_json::Value]) -> WorkspaceGraph {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for pkg in packages {
        let name = pkg["name"].as_str().expect("package must have a string name").to_string();

        let deps = pkg["dependencies"].as_array().expect("package dependencies must be an array");
        let ws_production: BTreeSet<String> = deps
            .iter()
            .filter(|dep| dep["path"].as_str().is_some() && dep["kind"].is_null())
            .map(|dep| {
                dep["name"].as_str().expect("dependency must have a string name").to_string()
            })
            .collect();
        edges.insert(name, ws_production);
    }

    WorkspaceGraph { edges }
}

/// Load graph from a live `cargo metadata` invocation.
pub fn load_workspace_graph() -> WorkspaceGraph {
    let metadata = load_cargo_metadata();
    let packages =
        metadata["packages"].as_array().expect("metadata 'packages' field must be an array");
    build_workspace_graph(packages)
}

/// Package name → (layer, short label, one-line blurb).
pub fn classification_map() -> HashMap<&'static str, (Layer, &'static str, &'static str)> {
    CLASSIFICATION
        .iter()
        .map(|(name, layer, label, blurb)| (*name, (*layer, *label, *blurb)))
        .collect()
}

/// Mermaid node id: alphanumeric + underscore (hyphens are awkward unquoted).
fn node_id(package_name: &str) -> String {
    package_name.chars().map(|c| if c == '-' { '_' } else { c }).collect::<String>().to_uppercase()
}

/// Render the generated ARCHITECTURE.md section (no surrounding markers).
pub fn generate_architecture_section(graph: &WorkspaceGraph) -> String {
    let class = classification_map();

    // Every cargo package must be classified.
    let mut missing: Vec<&String> =
        graph.edges.keys().filter(|name| !class.contains_key(name.as_str())).collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "CLASSIFICATION is missing workspace package(s): {missing:?}. \
         Add each to crates/architecture-tests/src/lib.rs CLASSIFICATION \
         (layer is a human judgement; edges come from cargo metadata)."
    );

    // Classification must not list packages that no longer exist.
    let mut stale: Vec<&str> =
        class.keys().copied().filter(|name| !graph.edges.contains_key(*name)).collect();
    stale.sort_unstable();
    assert!(
        stale.is_empty(),
        "CLASSIFICATION lists package(s) absent from cargo metadata: {stale:?}. \
         Remove them from CLASSIFICATION."
    );

    let n = graph.package_count();
    let bins = graph.binary_count();
    let libs = graph.library_count();

    let mut out = String::new();
    // Note: body must NOT contain the literal BEGIN/END marker strings, or
    // extract_generated_body would truncate early on the first END occurrence.
    out.push_str(&format!(
        "RVC is a Rust-based Ethereum Validator Client built as a modular workspace of \
         {n} crates ({bins} binaries + {libs} libraries).\n\
         \n\
         > **Generated section.** Crate count and the dependency graph below are produced from \
         `cargo metadata --format-version=1 --no-deps`. Do not hand-edit this block \
         (the HTML comment markers that wrap it). Regenerate with:\n\
         > ```\n\
         > {REGENERATE_COMMAND}\n\
         > ```\n\
         \n\
         ## Crate Dependency Graph\n\
         \n\
         ```mermaid\n\
         graph TD\n"
    ));

    // Nodes: stable package-name order.
    for name in graph.edges.keys() {
        let (_layer, label, blurb) = class[name.as_str()];
        let id = node_id(name);
        out.push_str(&format!("    {id}[\"{label}<br/><i>{blurb}</i>\"]\n"));
    }
    out.push('\n');

    // Edges: from-package order, then to-package order.
    for (from, deps) in &graph.edges {
        let from_id = node_id(from);
        for to in deps {
            // Only draw workspace edges (deps already filtered).
            if graph.edges.contains_key(to) {
                let to_id = node_id(to);
                out.push_str(&format!("    {from_id} --> {to_id}\n"));
            }
        }
    }
    out.push('\n');

    // Styles.
    for name in graph.edges.keys() {
        let (layer, _, _) = class[name.as_str()];
        let id = node_id(name);
        out.push_str(&format!("    style {id} {}\n", layer.mermaid_style()));
    }

    out.push_str(
        "```\n\
         \n\
         **Layer colors:**\n\
         - **Blue** — Binary entry point\n\
         - **Red** — Core orchestrator (depends on domain + base/infra crates)\n\
         - **Yellow** — Domain crates (duty-specific logic)\n\
         - **Green** — Base crates (pure leaves; no I/O)\n\
         - **Teal** — Infra crates (I/O services; no domain orchestration)\n\
         - **Gray** — Meta / dev-only crates (architecture gates, test harnesses)\n",
    );

    out
}

/// Wrap generated body with markers (as stored in ARCHITECTURE.md).
pub fn generated_block_with_markers(body: &str) -> String {
    format!("{BEGIN_GENERATED}\n{body}{END_GENERATED}")
}

/// Extract the body between markers (without the marker lines themselves).
pub fn extract_generated_body(doc: &str) -> Result<String, String> {
    let begin = doc
        .find(BEGIN_GENERATED)
        .ok_or_else(|| format!("ARCHITECTURE.md missing marker `{BEGIN_GENERATED}`"))?;
    let after_begin = begin + BEGIN_GENERATED.len();
    // Body starts after the newline following BEGIN.
    let body_start =
        if doc[after_begin..].starts_with('\n') { after_begin + 1 } else { after_begin };
    let end_rel = doc[body_start..]
        .find(END_GENERATED)
        .ok_or_else(|| format!("ARCHITECTURE.md missing marker `{END_GENERATED}`"))?;
    let body = &doc[body_start..body_start + end_rel];
    Ok(body.to_string())
}

/// Replace the generated region in `doc` with `new_block` (markers included).
pub fn replace_generated_region(doc: &str, new_block: &str) -> Result<String, String> {
    let begin = doc
        .find(BEGIN_GENERATED)
        .ok_or_else(|| format!("ARCHITECTURE.md missing marker `{BEGIN_GENERATED}`"))?;
    let end = doc
        .find(END_GENERATED)
        .ok_or_else(|| format!("ARCHITECTURE.md missing marker `{END_GENERATED}`"))?;
    let end_inclusive = end + END_GENERATED.len();
    let mut out = String::with_capacity(doc.len() + new_block.len());
    out.push_str(&doc[..begin]);
    out.push_str(new_block);
    // Preserve trailing content; if END was not followed by newline and new_block
    // already ends at the marker, keep the rest as-is.
    out.push_str(&doc[end_inclusive..]);
    Ok(out)
}

/// Write generated section into ARCHITECTURE.md on disk. Returns true if file changed.
pub fn regenerate_architecture_md() -> Result<bool, String> {
    let path = architecture_md_path();
    let doc =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let graph = load_workspace_graph();
    let body = generate_architecture_section(&graph);
    let block = generated_block_with_markers(&body);
    let updated = replace_generated_region(&doc, &block)?;
    if updated == doc {
        return Ok(false);
    }
    std::fs::write(&path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(true)
}

/// Production edges that must never appear in the workspace graph.
///
/// Kept here (and consumed by `architecture_no_cycles` + the doc policy
/// cross-check) so the generated ARCHITECTURE.md cannot contradict the DAG gate.
pub const FORBIDDEN_EDGES: &[(&str, &str)] = &[
    ("rvc-slashing", "rvc-doppelganger"),
    ("rvc-signer", "rvc-keymanager-api"),
    // RF6-25 / F112: block-service must not pull the MEV builder crate for one type.
    ("rvc-block-service", "rvc-builder"),
];

/// Domain package names (`Layer::Domain` in [`CLASSIFICATION`]).
///
/// Used by the no-domain→domain edge rule. Keep in lock-step with CLASSIFICATION
/// yellow nodes; the unit test `domain_packages_match_classification` enforces this.
pub const DOMAIN_PACKAGES: &[&str] = &[
    "rvc-block-service",
    "rvc-builder",
    "rvc-config",
    "rvc-doppelganger",
    "rvc-duty-tracker",
    "rvc-signer",
    "rvc-signer-server",
];

/// Domain→domain edges that are intentionally allowed (grandfathered).
///
/// Enumerated from `cargo metadata` after removing `block-service → builder`
/// (RF6-25). Do **not** add entries to silence new peer-duty edges — fix the
/// edge (shared type in a non-domain home) or document a genuine exception.
pub const DOMAIN_EDGE_ALLOWLIST: &[(&str, &str)] = &[
    // Duty services take the signing trait from the domain signing crate.
    ("rvc-block-service", "rvc-signer"),
    ("rvc-builder", "rvc-signer"),
    // Issue 1.5: enablement gate lives in doppelganger (REQUIRED_EDGE).
    ("rvc-signer", "rvc-doppelganger"),
    // Shared `[fork_schedule]` parse with the VC (FU-33 / 4.14). Not an island/BN edge.
    ("rvc-signer-server", "rvc-config"),
    // Remote signing library wraps the in-process signing stack.
    ("rvc-signer-server", "rvc-signer"),
];

/// Cross-check generated edges against standing policy tables used by
/// `architecture_no_cycles` (REQUIRED / FORBIDDEN). Shared so the doc cannot
/// contradict the DAG gate (F109: signer→doppelganger was missing from the doc).
pub fn assert_generated_agrees_with_policy(graph: &WorkspaceGraph) {
    // REQUIRED_EDGE from architecture_no_cycles.rs
    const REQUIRED: (&str, &str) = ("rvc-signer", "rvc-doppelganger");
    let (from, to) = REQUIRED;
    let deps = graph
        .edges
        .get(from)
        .unwrap_or_else(|| panic!("package '{from}' missing from workspace graph"));
    assert!(
        deps.contains(to),
        "required edge missing from cargo metadata (and thus from generated doc): {from} -> {to}"
    );

    // FORBIDDEN edges must not appear.
    for (f, t) in FORBIDDEN_EDGES {
        if let Some(deps) = graph.edges.get(*f) {
            assert!(!deps.contains(*t), "forbidden edge present in cargo metadata: {f} -> {t}");
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn classification_covers_unique_names() {
        let mut seen = BTreeSet::new();
        for (name, _, _, _) in CLASSIFICATION {
            assert!(seen.insert(*name), "duplicate CLASSIFICATION entry: {name}");
        }
    }

    #[test]
    fn domain_packages_match_classification() {
        let from_class: BTreeSet<&str> = CLASSIFICATION
            .iter()
            .filter(|(_, layer, _, _)| *layer == Layer::Domain)
            .map(|(name, _, _, _)| *name)
            .collect();
        let from_const: BTreeSet<&str> = DOMAIN_PACKAGES.iter().copied().collect();
        assert_eq!(
            from_class, from_const,
            "DOMAIN_PACKAGES must match CLASSIFICATION Layer::Domain entries"
        );
    }

    #[test]
    fn every_classification_row_has_a_reason() {
        let graph = load_workspace_graph();
        assert_eq!(
            CLASSIFICATION.len(),
            graph.package_count(),
            "CLASSIFICATION.len() must equal cargo metadata member count"
        );
        for (name, _, _, blurb) in CLASSIFICATION {
            assert!(!blurb.trim().is_empty(), "empty CLASSIFICATION blurb for {name}");
        }
    }

    #[test]
    fn extract_roundtrip() {
        let body = "hello\nworld\n";
        let doc = format!("pre\n{}\npost\n", generated_block_with_markers(body));
        let extracted = extract_generated_body(&doc).unwrap();
        assert_eq!(extracted, body);
    }
}
