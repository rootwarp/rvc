//! RR4-03 follow-up (#602): `test-utils` must not be reachable from a production
//! binary's normal feature graph.
//!
//! Walks workspace manifests from `cargo metadata --no-deps` (resolver 2).
//! Dev-dependency edges are not followed, so a `[dev-dependencies]` line that
//! turns `test-utils` on for tests does not count. Normal and build edges do,
//! including feature forwarding (`dep/test-utils`, `default = ["test-utils"]`).
//!
//! Roots / builds checked:
//! - `rvc-bin` with every Docker allow-listed combo: default, `gcp-trace`,
//!   `gcp-secret`, and both
//! - `rvc-signer-bin` with default and with `dvt`
//! - `rvc-keygen` with its default features
//! - the workspace `default-members` build as a whole (`cargo build --release`
//!   of those members). Feature unification across those roots must not enable
//!   `test-utils` on any crate a release binary links, using the joint resolve's
//!   activated edges and features (not each crate's defaults alone).
//!
//! The checker is not vacuous: injected normal / feature-forward / keygen /
//! default-members / optional-dep (G9) edges fail, and the real metadata still
//! has dev edges that request `test-utils`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

use rvc_architecture_tests::workspace_root;

#[derive(Clone, Debug)]
struct DepEdge {
    package: String,
    manifest_name: String,
    /// `None` is a normal edge. `"build"` is followed. `"dev"` is not.
    kind: Option<String>,
    optional: bool,
    uses_default_features: bool,
    features: Vec<String>,
}

#[derive(Clone, Debug)]
struct Package {
    features: BTreeMap<String, Vec<String>>,
    deps: Vec<DepEdge>,
}

#[derive(Clone, Debug)]
struct Req {
    use_default: bool,
    features: BTreeSet<String>,
}

struct Expanded {
    enabled: BTreeSet<String>,
    /// Optional dependencies turned on by `dep:` or a strong `name/feat` token.
    forced_deps: BTreeSet<String>,
    /// `(manifest name, feature, weak)`.
    forwards: Vec<(String, String, bool)>,
}

/// Joint feature-resolve state: per-package requirements and enabled features.
struct UnifiedResolve {
    reqs: BTreeMap<String, Req>,
    enabled_of: BTreeMap<String, BTreeSet<String>>,
}

struct WorkspaceMeta {
    packages: BTreeMap<String, Package>,
    /// Package names from `workspace_default_members`.
    default_members: Vec<String>,
}

fn load_workspace() -> WorkspaceMeta {
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
    parse_workspace(&metadata)
}

fn load_packages() -> BTreeMap<String, Package> {
    load_workspace().packages
}

/// Exact `packages[].id` → `packages[].name` map. No substring fallback.
fn package_id_to_name(metadata: &serde_json::Value) -> BTreeMap<String, String> {
    metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .map(|pkg| {
            (
                pkg["id"].as_str().expect("package id").to_string(),
                pkg["name"].as_str().expect("package name").to_string(),
            )
        })
        .collect()
}

fn parse_workspace(metadata: &serde_json::Value) -> WorkspaceMeta {
    let packages = parse_packages(metadata);
    let id_to_name = package_id_to_name(metadata);
    let default_members = metadata["workspace_default_members"]
        .as_array()
        .expect("workspace_default_members")
        .iter()
        .map(|id| {
            let id = id.as_str().expect("member id");
            id_to_name
                .get(id)
                .cloned()
                .unwrap_or_else(|| panic!("workspace_default_members id not in packages[]: {id}"))
        })
        .collect();
    WorkspaceMeta { packages, default_members }
}

fn parse_packages(metadata: &serde_json::Value) -> BTreeMap<String, Package> {
    let packages = metadata["packages"].as_array().expect("metadata packages");
    let mut out = BTreeMap::new();
    for pkg in packages {
        let name = pkg["name"].as_str().expect("package name").to_string();
        let mut features = BTreeMap::new();
        for (feat, tokens) in pkg["features"].as_object().expect("features object") {
            let list = tokens
                .as_array()
                .expect("feature tokens")
                .iter()
                .map(|t| t.as_str().expect("feature token").to_string())
                .collect();
            features.insert(feat.clone(), list);
        }
        let mut deps = Vec::new();
        for dep in pkg["dependencies"].as_array().expect("dependencies") {
            let package = dep["name"].as_str().expect("dep name").to_string();
            let manifest_name = dep["rename"].as_str().unwrap_or(&package).to_string();
            let features = dep["features"]
                .as_array()
                .expect("dep features")
                .iter()
                .map(|t| t.as_str().expect("dep feature").to_string())
                .collect();
            deps.push(DepEdge {
                package,
                manifest_name,
                kind: dep["kind"].as_str().map(str::to_string),
                optional: dep["optional"].as_bool().expect("optional"),
                uses_default_features: dep["uses_default_features"].as_bool().expect("defaults"),
                features,
            });
        }
        out.insert(name, Package { features, deps });
    }
    out
}

fn parse_token(token: &str) -> Token {
    if let Some(name) = token.strip_prefix("dep:") {
        return Token::Dep(name.to_string());
    }
    if let Some((name, feature)) = token.split_once('/') {
        if let Some(name) = name.strip_suffix('?') {
            return Token::DepFeature {
                name: name.to_string(),
                feature: feature.to_string(),
                weak: true,
            };
        }
        return Token::DepFeature {
            name: name.to_string(),
            feature: feature.to_string(),
            weak: false,
        };
    }
    Token::Feature(token.to_string())
}

enum Token {
    Feature(String),
    Dep(String),
    DepFeature { name: String, feature: String, weak: bool },
}

fn expand(pkg: &Package, req: &Req) -> Expanded {
    let mut enabled = BTreeSet::new();
    let mut forced_deps = BTreeSet::new();
    let mut forwards = Vec::new();
    let mut queue = VecDeque::new();
    if req.use_default {
        queue.push_back("default".to_string());
    }
    for feat in &req.features {
        queue.push_back(feat.clone());
    }
    while let Some(feat) = queue.pop_front() {
        if !enabled.insert(feat.clone()) {
            continue;
        }
        let Some(tokens) = pkg.features.get(&feat) else {
            if pkg.deps.iter().any(|d| d.optional && d.manifest_name == feat) {
                forced_deps.insert(feat);
            }
            continue;
        };
        for token in tokens {
            match parse_token(token) {
                Token::Feature(name) => queue.push_back(name),
                Token::Dep(name) => {
                    forced_deps.insert(name);
                }
                Token::DepFeature { name, feature, weak } => {
                    if !weak {
                        forced_deps.insert(name.clone());
                    }
                    forwards.push((name, feature, weak));
                }
            }
        }
    }
    Expanded { enabled, forced_deps, forwards }
}

fn follows(kind: &Option<String>) -> bool {
    match kind.as_deref() {
        None | Some("build") => true,
        Some("dev") => false,
        Some(_) => false,
    }
}

/// Docker allow-listed feature combos for production image roots (#602).
fn docker_allowlisted_roots() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("rvc-bin", &[]),
        ("rvc-bin", &["gcp-trace"]),
        ("rvc-bin", &["gcp-secret"]),
        ("rvc-bin", &["gcp-trace", "gcp-secret"]),
        ("rvc-signer-bin", &[]),
        ("rvc-signer-bin", &["dvt"]),
    ]
}

/// Every single-package root the production guard resolves (Docker combos + keygen).
fn production_guard_roots() -> Vec<(&'static str, &'static [&'static str])> {
    let mut roots = docker_allowlisted_roots();
    roots.push(("rvc-keygen", &[]));
    roots
}

fn guard_failures(packages: &BTreeMap<String, Package>) -> Vec<String> {
    let mut failures = Vec::new();
    for (root, extra) in production_guard_roots() {
        match reached_test_utils(packages, root, extra) {
            Ok(hits) if hits.is_empty() => {}
            Ok(hits) => {
                failures.push(format!("{root} features {extra:?} reach test-utils on {hits:?}"))
            }
            Err(e) => failures.push(e),
        }
    }
    failures
}

/// Resolve `roots` together (feature unification across roots).
fn resolve_unified(
    packages: &BTreeMap<String, Package>,
    roots: &[(&str, &[&str])],
) -> Result<UnifiedResolve, String> {
    let mut reqs: BTreeMap<String, Req> = BTreeMap::new();
    let mut queue = VecDeque::new();

    for (root, extra) in roots {
        let root_pkg =
            packages.get(*root).ok_or_else(|| format!("package {root} is not in metadata"))?;
        for feat in *extra {
            if !root_pkg.features.contains_key(*feat) {
                return Err(format!("{root} has no feature {feat}"));
            }
        }
        let entry = reqs
            .entry((*root).to_string())
            .or_insert_with(|| Req { use_default: false, features: BTreeSet::new() });
        let mut changed = false;
        if !entry.use_default {
            entry.use_default = true;
            changed = true;
        }
        for feat in *extra {
            if entry.features.insert((*feat).to_string()) {
                changed = true;
            }
        }
        if changed || !queue.contains(&(*root).to_string()) {
            queue.push_back((*root).to_string());
        }
    }

    let mut enabled_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    while let Some(name) = queue.pop_front() {
        let pkg = packages.get(&name).expect("queued package is in the workspace");
        let req = reqs.get(&name).expect("queued package has a requirement").clone();
        let expanded = expand(pkg, &req);
        enabled_of.insert(name.clone(), expanded.enabled.clone());

        for edge in &pkg.deps {
            if !follows(&edge.kind) || !packages.contains_key(&edge.package) {
                continue;
            }
            let included = !edge.optional
                || expanded.enabled.contains(&edge.manifest_name)
                || expanded.forced_deps.contains(&edge.manifest_name);
            if !included {
                continue;
            }
            let mut child_feats = BTreeSet::from_iter(edge.features.iter().cloned());
            for (dep_name, feat, _weak) in &expanded.forwards {
                // Edge is already included; weak `dep?/feat` applies here.
                if dep_name == &edge.manifest_name {
                    child_feats.insert(feat.clone());
                }
            }
            let existed = reqs.contains_key(&edge.package);
            let entry = reqs
                .entry(edge.package.clone())
                .or_insert_with(|| Req { use_default: false, features: BTreeSet::new() });
            let mut changed = !existed;
            if edge.uses_default_features && !entry.use_default {
                entry.use_default = true;
                changed = true;
            }
            for feat in child_feats {
                if entry.features.insert(feat) {
                    changed = true;
                }
            }
            if changed {
                queue.push_back(edge.package.clone());
            }
        }
    }

    Ok(UnifiedResolve { reqs, enabled_of })
}

fn test_utils_hits(resolve: &UnifiedResolve) -> Vec<String> {
    let mut hits: Vec<String> = resolve
        .enabled_of
        .iter()
        .filter(|(_, enabled)| enabled.contains("test-utils"))
        .map(|(name, _)| name.clone())
        .collect();
    hits.sort();
    hits
}

/// Resolve `roots` together and return every workspace package whose `test-utils`
/// feature is on.
fn reached_test_utils_unified(
    packages: &BTreeMap<String, Package>,
    roots: &[(&str, &[&str])],
) -> Result<Vec<String>, String> {
    Ok(test_utils_hits(&resolve_unified(packages, roots)?))
}

/// Workspace packages in `root`'s normal/build closure whose `test-utils` feature is on.
fn reached_test_utils(
    packages: &BTreeMap<String, Package>,
    root: &str,
    extra: &[&str],
) -> Result<Vec<String>, String> {
    reached_test_utils_unified(packages, &[(root, extra)])
}

/// Packages reachable from `root` via normal/build edges when expanding each
/// crate with only its own default features (the pre-fix linked-set bug).
fn normal_build_closure_defaults_only(
    packages: &BTreeMap<String, Package>,
    root: &str,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([root.to_string()]);
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(pkg) = packages.get(&name) else {
            continue;
        };
        let expanded = expand(pkg, &Req { use_default: true, features: BTreeSet::new() });
        for edge in &pkg.deps {
            if !follows(&edge.kind) || !packages.contains_key(&edge.package) {
                continue;
            }
            let included = !edge.optional
                || expanded.enabled.contains(&edge.manifest_name)
                || expanded.forced_deps.contains(&edge.manifest_name);
            if included {
                queue.push_back(edge.package.clone());
            }
        }
    }
    seen
}

/// Packages a release binary links under a joint resolve: BFS from the bins
/// following edges activated by that resolve's features (resolve-node deps +
/// features), not each crate's defaults alone.
fn release_linked_from_resolve(
    packages: &BTreeMap<String, Package>,
    resolve: &UnifiedResolve,
    release_bins: &[&str],
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    for bin in release_bins {
        if resolve.reqs.contains_key(*bin) {
            queue.push_back((*bin).to_string());
        }
    }
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(pkg) = packages.get(&name) else {
            continue;
        };
        let Some(req) = resolve.reqs.get(&name) else {
            continue;
        };
        let expanded = expand(pkg, req);
        for edge in &pkg.deps {
            if !follows(&edge.kind) || !packages.contains_key(&edge.package) {
                continue;
            }
            let included = !edge.optional
                || expanded.enabled.contains(&edge.manifest_name)
                || expanded.forced_deps.contains(&edge.manifest_name);
            if included {
                queue.push_back(edge.package.clone());
            }
        }
    }
    seen
}

/// Among packages with `test-utils` on in a unified default-members resolve,
/// those also linked by a release binary that is itself a default member —
/// using the joint resolve's activated edges/features.
fn default_members_test_utils_on_release_link(meta: &WorkspaceMeta) -> Result<Vec<String>, String> {
    let roots: Vec<(&str, &[&str])> =
        meta.default_members.iter().map(|n| (n.as_str(), &[][..])).collect();
    assert!(!roots.is_empty(), "workspace_default_members must not be empty");
    let resolve = resolve_unified(&meta.packages, &roots)?;
    let hits = test_utils_hits(&resolve);
    let release_bins: Vec<&str> = meta
        .default_members
        .iter()
        .map(String::as_str)
        // Architecture-tests is a default member but not a shipped release binary.
        .filter(|n| *n != "rvc-architecture-tests")
        .collect();
    assert!(!release_bins.is_empty(), "default-members must include at least one release binary");
    let linked = release_linked_from_resolve(&meta.packages, &resolve, &release_bins);
    let mut bad: Vec<String> = hits.into_iter().filter(|pkg| linked.contains(pkg)).collect();
    bad.sort();
    Ok(bad)
}

fn dev_edges_requesting(packages: &BTreeMap<String, Package>, feature: &str) -> Vec<String> {
    let mut edges = Vec::new();
    for (from, pkg) in packages {
        for dep in &pkg.deps {
            if dep.kind.as_deref() == Some("dev") && dep.features.iter().any(|f| f == feature) {
                edges.push(format!("{from} -> {}", dep.package));
            }
        }
    }
    edges.sort();
    edges
}

#[test]
fn package_ids_map_exactly_from_metadata() {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata");
    assert!(output.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id_to_name = package_id_to_name(&metadata);
    // `rvc` uses the `#0.7.0` form (name is the path basename); substring
    // fallbacks are forbidden — only the exact id map is used.
    let rvc_id =
        metadata["packages"].as_array().unwrap().iter().find(|p| p["name"] == "rvc").unwrap()["id"]
            .as_str()
            .unwrap();
    assert!(
        rvc_id.ends_with("#0.7.0") || rvc_id.contains("#rvc@"),
        "expected a path-package id for rvc, got {rvc_id}"
    );
    assert_eq!(id_to_name.get(rvc_id).map(String::as_str), Some("rvc"));
    for id in metadata["workspace_default_members"].as_array().unwrap() {
        let id = id.as_str().unwrap();
        assert!(id_to_name.contains_key(id), "default member id missing from map: {id}");
    }
}

#[test]
fn production_bins_do_not_reach_test_utils() {
    let meta = load_workspace();
    let packages = &meta.packages;
    let dev = dev_edges_requesting(packages, "test-utils");
    for expected in
        ["rvc -> rvc", "rvc-crypto -> rvc-crypto", "rvc-signer -> rvc-remote-signer-client"]
    {
        assert!(
            dev.iter().any(|e| e == expected),
            "dev-edge positive control missing {expected}; saw {dev:?}"
        );
    }

    let mut failures = guard_failures(packages);
    match default_members_test_utils_on_release_link(&meta) {
        Ok(hits) if hits.is_empty() => {}
        Ok(hits) => failures.push(format!(
            "default-members unified build enables test-utils on release-linked crates {hits:?}"
        )),
        Err(e) => failures.push(e),
    }
    assert!(
        failures.is_empty(),
        "test-utils is reachable from a production binary's normal feature graph:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn injected_normal_edge_reaches_test_utils() {
    let mut packages = load_packages();
    let bin = packages.get_mut("rvc-bin").expect("rvc-bin");
    let dep = bin
        .deps
        .iter_mut()
        .find(|d| d.package == "rvc-crypto" && d.kind.is_none())
        .expect("rvc-bin normal edge to rvc-crypto");
    dep.features.push("test-utils".to_string());
    let hits = reached_test_utils(&packages, "rvc-bin", &[]).expect("resolve");
    assert!(
        hits.iter().any(|h| h == "rvc-crypto"),
        "a normal edge requesting test-utils must fail the guard, hits={hits:?}"
    );
}

#[test]
fn injected_dvt_forward_reaches_test_utils_only_when_dvt_is_on() {
    let mut packages = load_packages();
    let server = packages.get_mut("rvc-signer-server").expect("rvc-signer-server");
    server.features.get_mut("dvt").expect("dvt feature").push("crypto/test-utils".to_string());

    let plain = reached_test_utils(&packages, "rvc-signer-bin", &[]).expect("default resolve");
    assert!(
        plain.is_empty(),
        "dvt forwarding must not affect the default signer graph, hits={plain:?}"
    );
    let with_dvt = reached_test_utils(&packages, "rvc-signer-bin", &["dvt"]).expect("dvt resolve");
    assert!(
        with_dvt.iter().any(|h| h == "rvc-crypto"),
        "dvt -> crypto/test-utils must fail the guard, hits={with_dvt:?}"
    );
}

#[test]
fn injected_docker_feature_forward_reaches_test_utils() {
    // G2: a defaults-only root list leaves every prior guard test green.
    for feature in ["gcp-secret", "gcp-trace"] {
        let mut packages = load_packages();
        let bin = packages.get_mut("rvc-bin").expect("rvc-bin");
        bin.features
            .get_mut(feature)
            .unwrap_or_else(|| panic!("{feature} feature"))
            .push("crypto/test-utils".to_string());

        let plain = reached_test_utils(&packages, "rvc-bin", &[]).expect("default resolve");
        assert!(
            plain.is_empty(),
            "{feature} forwarding must not affect the default rvc-bin graph, hits={plain:?}"
        );
        let defaults_and_dvt_only =
            [("rvc-bin", &[][..]), ("rvc-signer-bin", &[][..]), ("rvc-signer-bin", &["dvt"][..])];
        for (root, extra) in defaults_and_dvt_only {
            let hits = reached_test_utils(&packages, root, extra).expect("resolve");
            assert!(
                hits.is_empty(),
                "pre-fix roots must miss {feature} -> crypto/test-utils for {root} {extra:?}, hits={hits:?}"
            );
        }
        let failures = guard_failures(&packages);
        assert!(
            failures.iter().any(|f| f.contains("rvc-crypto")),
            "allow-listed Docker combos must catch {feature} -> crypto/test-utils; failures={failures:?}"
        );
    }
}

#[test]
fn injected_keygen_normal_edge_reaches_test_utils() {
    // G3: without rvc-keygen as a root, a normal test-utils edge there is invisible.
    let mut packages = load_packages();
    let keygen = packages.get_mut("rvc-keygen").expect("rvc-keygen");
    let dep = keygen
        .deps
        .iter_mut()
        .find(|d| d.package == "rvc-crypto" && d.kind.is_none())
        .expect("rvc-keygen normal edge to rvc-crypto");
    dep.features.push("test-utils".to_string());

    for (root, extra) in docker_allowlisted_roots() {
        let hits = reached_test_utils(&packages, root, extra).expect("resolve");
        assert!(
            hits.is_empty(),
            "keygen-only edge must not affect {root} {extra:?}, hits={hits:?}"
        );
    }
    let failures = guard_failures(&packages);
    assert!(
        failures.iter().any(|f| f.contains("rvc-keygen") && f.contains("rvc-crypto")),
        "production guard roots must include rvc-keygen and catch the edge; failures={failures:?}"
    );
}

#[test]
fn injected_default_members_edge_unifies_test_utils_into_release_link() {
    // G4: a normal test-utils edge on rvc-architecture-tests (a default member)
    // unifies into crates rvc-bin links under a plain `cargo build --release`.
    let mut meta = load_workspace();
    assert!(
        meta.default_members.iter().any(|m| m == "rvc-bin"),
        "default-members must include rvc-bin, got {:?}",
        meta.default_members
    );
    assert!(
        meta.default_members.iter().any(|m| m == "rvc-architecture-tests"),
        "default-members must include rvc-architecture-tests, got {:?}",
        meta.default_members
    );

    let arch = meta.packages.get_mut("rvc-architecture-tests").expect("arch tests");
    arch.deps.push(DepEdge {
        package: "rvc-crypto".to_string(),
        manifest_name: "crypto".to_string(),
        kind: None,
        optional: false,
        uses_default_features: true,
        features: vec!["test-utils".to_string()],
    });

    assert!(
        guard_failures(&meta.packages).is_empty(),
        "single-root production roots must miss an architecture-tests-only edge"
    );

    let bad = default_members_test_utils_on_release_link(&meta).expect("unified resolve");
    assert!(
        bad.iter().any(|h| h == "rvc-crypto"),
        "default-members unification must fail the guard when arch-tests enables test-utils on a release-linked crate, bad={bad:?}"
    );
}

#[test]
fn injected_optional_dep_activated_by_default_member_feature_reaches_release_link() {
    // G9: rvc gains an optional rvc-test-support dep requesting test-utils;
    // rvc-architecture-tests activates it via feature `g9`. Feature unification
    // makes rvc-bin link that optional dep, but a defaults-only linked-set walk
    // drops the hit.
    let mut meta = load_workspace();

    let support = meta.packages.get_mut("rvc-test-support").expect("rvc-test-support");
    support.features.entry("default".to_string()).or_default();
    support.features.entry("test-utils".to_string()).or_default();

    let rvc = meta.packages.get_mut("rvc").expect("rvc");
    rvc.features.insert("g9".to_string(), vec!["dep:rvc-test-support".to_string()]);
    rvc.deps.push(DepEdge {
        package: "rvc-test-support".to_string(),
        manifest_name: "rvc-test-support".to_string(),
        kind: None,
        optional: true,
        uses_default_features: true,
        features: vec!["test-utils".to_string()],
    });

    let arch = meta.packages.get_mut("rvc-architecture-tests").expect("arch tests");
    arch.features.insert("g9".to_string(), vec!["rvc/g9".to_string()]);
    arch.features.insert("default".to_string(), vec!["g9".to_string()]);
    arch.deps.push(DepEdge {
        package: "rvc".to_string(),
        manifest_name: "rvc".to_string(),
        kind: None,
        optional: false,
        uses_default_features: true,
        features: vec![],
    });

    assert!(
        guard_failures(&meta.packages).is_empty(),
        "single-root production roots must miss a g9-only optional-dep activation"
    );

    let roots: Vec<(&str, &[&str])> =
        meta.default_members.iter().map(|n| (n.as_str(), &[][..])).collect();
    let resolve = resolve_unified(&meta.packages, &roots).expect("joint resolve");
    let hits = test_utils_hits(&resolve);
    assert!(
        hits.iter().any(|h| h == "rvc-test-support"),
        "joint resolve must see test-utils on rvc-test-support, hits={hits:?}"
    );

    // Pre-fix bug: expand each crate with only its own defaults → miss.
    let defaults_linked = normal_build_closure_defaults_only(&meta.packages, "rvc-bin");
    assert!(
        !defaults_linked.contains("rvc-test-support"),
        "defaults-only closure must miss the optional dep (the bug G9 guards against)"
    );
    let defaults_bad: Vec<_> =
        hits.iter().filter(|pkg| defaults_linked.contains(pkg.as_str())).cloned().collect();
    assert!(
        defaults_bad.is_empty(),
        "defaults-only filter must drop the G9 hit; got {defaults_bad:?}"
    );

    let bad = default_members_test_utils_on_release_link(&meta).expect("guard");
    assert!(
        bad.iter().any(|h| h == "rvc-test-support"),
        "joint-resolve linked set must catch g9 → optional rvc-test-support/test-utils, bad={bad:?}"
    );
}

#[test]
fn synthetic_feature_graph_cases() {
    fn pkg(features: &[(&str, &[&str])], deps: Vec<DepEdge>) -> Package {
        Package {
            features: features
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.iter().map(|s| (*s).to_string()).collect()))
                .collect(),
            deps,
        }
    }
    fn edge(
        package: &str,
        manifest: &str,
        kind: Option<&str>,
        optional: bool,
        features: &[&str],
    ) -> DepEdge {
        DepEdge {
            package: package.to_string(),
            manifest_name: manifest.to_string(),
            kind: kind.map(str::to_string),
            optional,
            uses_default_features: true,
            features: features.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    let mut packages = BTreeMap::new();
    packages.insert(
        "bin".to_string(),
        pkg(
            &[("default", &[]), ("dvt", &["lib/dvt"])],
            vec![
                edge("lib", "lib", None, false, &[]),
                edge("lib", "lib", Some("dev"), false, &["test-utils"]),
            ],
        ),
    );
    packages.insert(
        "lib".to_string(),
        pkg(
            &[("default", &[]), ("dvt", &[]), ("test-utils", &[])],
            vec![edge("helper", "helper", None, true, &["test-utils"])],
        ),
    );
    packages.insert("helper".to_string(), pkg(&[("default", &[]), ("test-utils", &[])], vec![]));

    let plain = reached_test_utils(&packages, "bin", &[]).unwrap();
    assert!(plain.is_empty(), "dev edge and disabled optional dep must not count: {plain:?}");

    packages
        .get_mut("lib")
        .unwrap()
        .features
        .insert("default".to_string(), vec!["test-utils".to_string()]);
    let via_default = reached_test_utils(&packages, "bin", &[]).unwrap();
    assert_eq!(via_default, vec!["lib".to_string()], "{via_default:?}");

    packages.get_mut("lib").unwrap().features.insert("default".to_string(), vec![]);
    packages
        .get_mut("lib")
        .unwrap()
        .features
        .insert("dvt".to_string(), vec!["helper?/test-utils".to_string()]);
    let weak_off = reached_test_utils(&packages, "bin", &["dvt"]).unwrap();
    assert!(weak_off.is_empty(), "weak dep feature must not enable an optional dep: {weak_off:?}");

    packages.get_mut("lib").unwrap().features.insert(
        "dvt".to_string(),
        vec!["dep:helper".to_string(), "helper?/test-utils".to_string()],
    );
    let weak_on = reached_test_utils(&packages, "bin", &["dvt"]).unwrap();
    assert!(
        weak_on.iter().any(|h| h == "helper"),
        "weak feature applies once dep: enables the optional dep: {weak_on:?}"
    );
}
