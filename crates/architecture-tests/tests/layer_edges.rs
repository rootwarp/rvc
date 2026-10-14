//! G-5a layer-edge gate: a `Base` package may depend only on `Base` (A-P2).
//!
//! The literal G-5a wording in `architecture.md` ("No `Layer::Base` package may
//! declare a production workspace dependency on any other workspace package") is
//! **rejected**. That zero-out-edge reading is unsatisfiable for ADR-011's own
//! decision (VD-P5): `crates/crypto/Cargo.toml:19-26` declares `observability`,
//! `eth-types`, and `web3signer-wire`, and extracting `remote_signer/` removes
//! none of them. Under the literal rule `crypto` can never be `Base`.
//!
//! The existing six-crate pin `ZERO_OUT_EDGE_IF_PRESENT`
//! (`architecture_no_cycles.rs:72-79`) is retained unchanged for the true
//! leaves. This file does not edit that table.
//!
//! G-5a is a **necessary constraint on** `Base`, not a definition of it (A-6-8).
//! `rvc-slashing` and `rvc-validator-store` pass G-5a today (out-edges are all
//! Base) and are deliberately `Infra` because they own I/O.
//!
//! G-5b: no `Layer::Infra` package may declare a production workspace
//! dependency on a `Layer::Domain` package. Domain membership is
//! `DOMAIN_PACKAGES` (lock-step with `CLASSIFICATION` via
//! `domain_packages_match_classification`). Failure names both packages.
//!
//! VD-P4: G-5b is green at HEAD; the RED demo is why this gate is
//! trustworthy. A gate that is green the day it lands and has never been
//! seen red is indistinguishable from a gate that scans nothing (R10).
//!
//! Production edges only (`kind == null`), via `load_workspace_graph` /
//! `WorkspaceGraph` — the same filter as `build_edge_map`.

use std::collections::{BTreeMap, BTreeSet};

use rvc_architecture_tests::{
    classification_map, load_workspace_graph, Layer, WorkspaceGraph, DOMAIN_PACKAGES,
};

fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Binary => "Binary",
        Layer::Orchestrator => "Orchestrator",
        Layer::Domain => "Domain",
        Layer::Base => "Base",
        Layer::Infra => "Infra",
        Layer::Meta => "Meta",
    }
}

/// G-5a: every production workspace out-edge from a `Base` package must land
/// on another `Base` package. Failure copy names both packages and both layers.
fn g5a_violations(graph: &WorkspaceGraph) -> Vec<String> {
    let class = classification_map();
    let mut violations = Vec::new();
    for (from, deps) in &graph.edges {
        let Some((from_layer, _, _)) = class.get(from.as_str()) else {
            continue;
        };
        if *from_layer != Layer::Base {
            continue;
        }
        for to in deps {
            let to_layer = class.get(to.as_str()).map(|(layer, _, _)| *layer);
            if to_layer == Some(Layer::Base) {
                continue;
            }
            let to_layer_name = to_layer.map(layer_name).unwrap_or("unclassified");
            violations.push(format!(
                "G-5a: Base package '{from}' depends on '{to}' ({to_layer_name}); \
                 a Base package may depend only on Base packages"
            ));
        }
    }
    violations
}

#[test]
fn g5a_is_red_against_a_scratch_violating_edge() {
    // Synthetic Base → Infra production edge. Uses real CLASSIFICATION names
    // so the predicate (which reads `classification_map`) can resolve layers.
    // Mirrors the discarded real-tree scratch: `slashing.workspace = true` on
    // `crates/timing/Cargo.toml`.
    let mut edges = BTreeMap::new();
    edges.insert("rvc-timing".to_string(), BTreeSet::from(["rvc-slashing".to_string()]));
    edges.insert("rvc-slashing".to_string(), BTreeSet::new());
    let graph = WorkspaceGraph { edges };

    let violations = g5a_violations(&graph);
    assert!(
        !violations.is_empty(),
        "G-5a must report a Base→Infra production edge (a gate never seen red is unfalsifiable)"
    );
    let msg = violations.join("\n");
    assert!(
        msg.contains("rvc-timing") && msg.contains("rvc-slashing"),
        "G-5a failure must name both packages; got: {msg}"
    );
    assert!(
        msg.contains("Base") && msg.contains("Infra"),
        "G-5a failure must name both layers; got: {msg}"
    );
}

/// Real-tree G-5a. Green on develop with `rvc-crypto` still `Infra` (ARCH-6f
/// is the flip). This is the test that goes red against the discarded
/// `crates/timing/Cargo.toml` scratch edge.
#[test]
fn g5a_holds_on_the_real_workspace_graph() {
    let graph = load_workspace_graph();
    let violations = g5a_violations(&graph);
    assert!(
        violations.is_empty(),
        "G-5a (Base may depend only on Base) failed:\n{}",
        violations.join("\n")
    );
}

/// Non-vacuity: the Base set is large enough to scan, and at least one
/// scanned member actually has production out-edges.
#[test]
fn g5a_scans_a_nonempty_base_set() {
    let graph = load_workspace_graph();
    let class = classification_map();
    let base: Vec<&String> = graph
        .edges
        .keys()
        .filter(|name| class.get(name.as_str()).is_some_and(|(layer, _, _)| *layer == Layer::Base))
        .collect();
    assert!(
        base.len() >= 8,
        "G-5a would be vacuous: Base set has {} members, need ≥ 8",
        base.len()
    );
    let has_inspectable_out_edges = ["rvc-web3signer-wire", "rvc-timing"].iter().any(|name| {
        base.iter().any(|b| b.as_str() == *name)
            && graph.edges.get(*name).is_some_and(|deps| !deps.is_empty())
    });
    assert!(
        has_inspectable_out_edges,
        "G-5a would be vacuous: neither rvc-web3signer-wire nor rvc-timing is a Base package \
         with production out-edges"
    );
}

/// G-5b: no production workspace out-edge from an `Infra` package may land
/// on a `DOMAIN_PACKAGES` member. Failure copy names both packages.
fn g5b_violations(graph: &WorkspaceGraph) -> Vec<String> {
    let class = classification_map();
    let domain: BTreeSet<&str> = DOMAIN_PACKAGES.iter().copied().collect();
    let mut violations = Vec::new();
    for (from, deps) in &graph.edges {
        let Some((from_layer, _, _)) = class.get(from.as_str()) else {
            continue;
        };
        if *from_layer != Layer::Infra {
            continue;
        }
        for to in deps {
            if !domain.contains(to.as_str()) {
                continue;
            }
            violations.push(format!(
                "G-5b: Infra package '{from}' depends on '{to}'; \
                 an Infra package may not depend on a Domain package"
            ));
        }
    }
    violations
}

#[test]
fn g5b_is_red_against_a_scratch_infra_to_domain_edge() {
    // Synthetic Infra → Domain production edge. Uses real CLASSIFICATION /
    // DOMAIN_PACKAGES names so the predicate can resolve membership.
    // Mirrors the discarded real-tree scratch: `signer.workspace = true` on
    // `crates/beacon/Cargo.toml`.
    let mut edges = BTreeMap::new();
    edges.insert("beacon".to_string(), BTreeSet::from(["rvc-signer".to_string()]));
    edges.insert("rvc-signer".to_string(), BTreeSet::new());
    let graph = WorkspaceGraph { edges };

    let violations = g5b_violations(&graph);
    assert!(
        !violations.is_empty(),
        "G-5b must report an Infra→Domain production edge (a gate never seen red is unfalsifiable)"
    );
    let msg = violations.join("\n");
    assert!(
        msg.contains("beacon") && msg.contains("rvc-signer"),
        "G-5b failure must name both packages; got: {msg}"
    );
}

/// Real-tree G-5b. Green on develop (VD-P4). This is the test that goes red
/// against the discarded `crates/beacon/Cargo.toml` scratch edge.
#[test]
fn g5b_holds_on_the_real_workspace_graph() {
    let graph = load_workspace_graph();
    let violations = g5b_violations(&graph);
    assert!(
        violations.is_empty(),
        "G-5b (Infra may not depend on Domain) failed:\n{}",
        violations.join("\n")
    );
}

/// Non-vacuity: the Infra set is non-empty, and at least one scanned
/// member actually has production out-edges.
#[test]
fn g5b_scans_a_nonempty_infra_set_with_real_out_edges() {
    let graph = load_workspace_graph();
    let class = classification_map();
    let infra: Vec<&String> = graph
        .edges
        .keys()
        .filter(|name| class.get(name.as_str()).is_some_and(|(layer, _, _)| *layer == Layer::Infra))
        .collect();
    // 7 members after ARCH-6a, 8 after ARCH-6f (`rvc-crypto` is still Infra).
    assert!(
        infra.len() >= 7,
        "G-5b would be vacuous: Infra set has {} members, need ≥ 7",
        infra.len()
    );
    let has_inspectable_out_edges = ["beacon", "rvc-slashing"].iter().any(|name| {
        infra.iter().any(|b| b.as_str() == *name)
            && graph.edges.get(*name).is_some_and(|deps| !deps.is_empty())
    });
    assert!(
        has_inspectable_out_edges,
        "G-5b would be vacuous: neither beacon nor rvc-slashing is an Infra package \
         with production out-edges"
    );
}
