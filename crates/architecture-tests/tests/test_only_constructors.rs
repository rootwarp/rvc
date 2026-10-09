//! RR4-03 / #539: test-only constructors are gated by the compiler.
//!
//! Three items bypass production construction and compile into a default build
//! unless an attribute keeps them out:
//!
//! - `RemoteSigner::new_for_tests` in `crates/remote-signer-client/src/client.rs`
//!   (skips the insecure-URL gate)
//! - its alias `new_unchecked` immediately below (delegates to `new_for_tests`)
//! - `OrchestratorDeps::for_test` in `crates/rvc/src/orchestrator/coordinator/mod.rs`
//!
//! `#[cfg(test)]` alone is not enough. Integration tests are a separate crate,
//! so `cfg(test)` is false on the library they link. The attribute is exactly
//! `#[cfg(any(test, feature = "test-utils"))]`. Downstream integration tests
//! see the items through the self dev-dependency feature unification from
//! RR0-01 (`rvc`) and the signer dev-dependency feature (`remote-signer-client`).
//!
//! ## Predecessor rule
//!
//! From the item's declaration line, walk upward. Skip blank lines and lines
//! whose trimmed text starts with `///` (outer line doc comments, including a
//! bare `///`). Do not skip `//!`, block comments, other attributes, or code.
//! The first remaining line, after trim, must equal
//! `#[cfg(any(test, feature = "test-utils"))]` and nothing else (no trailing
//! comment). Leading indentation is ignored.
//!
//! A `///` doc comment may sit between that attribute and the item, or above
//! the attribute. Any other attribute between the gate and the item —
//! `#[cfg(test)]`, `#[allow(...)]`, or `#[cfg(feature = "test-utils")]` alone —
//! fails. This file is the only automated mechanism. A `cargo check` that must
//! fail is PR evidence, not a second gate.
//!
//! No test name matches `.*(tree_hash|signing_root|_root)$`.

use std::path::{Path, PathBuf};

const GATE: &str = "#[cfg(any(test, feature = \"test-utils\"))]";

const CLIENT_REL: &str = "crates/remote-signer-client/src/client.rs";
const COORD_REL: &str = "crates/rvc/src/orchestrator/coordinator/mod.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn read_lines(rel: &str) -> Vec<String> {
    let path = workspace_root().join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    text.lines().map(str::to_string).collect()
}

fn find_decl(lines: &[String], pred: impl Fn(&str) -> bool, what: &str) -> Result<usize, String> {
    let hits: Vec<usize> =
        lines.iter().enumerate().filter(|(_, line)| pred(line.trim())).map(|(i, _)| i).collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("{what}: declaration not found")),
        many => Err(format!(
            "{what}: expected 1 declaration, found {} at lines {:?}",
            many.len(),
            many.iter().map(|i| i + 1).collect::<Vec<_>>()
        )),
    }
}

fn is_fn_item(trim: &str, name: &str) -> bool {
    let sig = format!("fn {name}(");
    (trim.starts_with("pub fn ") || trim.starts_with("pub(crate) fn ") || trim.starts_with("fn "))
        && trim.contains(&sig)
}

/// Walk described in the module docs.
fn predecessor_gate(lines: &[String], decl_idx: usize) -> Result<(), String> {
    let mut i = decl_idx;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with("///") {
            continue;
        }
        if t == GATE {
            return Ok(());
        }
        return Err(format!("line {}: preceded by {t:?}, expected {GATE:?}", decl_idx + 1));
    }
    Err(format!("line {}: reached start of file without the gate", decl_idx + 1))
}

#[test]
fn test_only_constructors_are_feature_gated() {
    // The walker is not vacuous: ungated, `cfg(test)`-only, feature-only, and
    // "another attribute between the gate and the item" all fail. Docs between
    // the gate and the item, and an allow-attribute *above* the gate, pass.
    let ungated = vec!["    /// docs".to_string(), "    pub fn new_for_tests(".to_string()];
    assert!(predecessor_gate(&ungated, 1).is_err(), "ungated item must fail");

    let cfg_test_only = vec![
        "    /// docs".to_string(),
        "    #[cfg(test)]".to_string(),
        "    pub(crate) fn new_unchecked(".to_string(),
    ];
    assert!(predecessor_gate(&cfg_test_only, 2).is_err(), "cfg(test) alone must fail");

    let feature_only = vec![
        "    #[cfg(feature = \"test-utils\")]".to_string(),
        "    pub fn new_for_tests(".to_string(),
    ];
    assert!(predecessor_gate(&feature_only, 1).is_err(), "feature-only cfg must fail");

    let attr_between = vec![
        "    #[cfg(any(test, feature = \"test-utils\"))]".to_string(),
        "    #[allow(clippy::too_many_arguments)]".to_string(),
        "    pub fn for_test(".to_string(),
    ];
    assert!(
        predecessor_gate(&attr_between, 2).is_err(),
        "attribute between the gate and the item must fail"
    );

    let docs_between = vec![
        "    #[cfg(any(test, feature = \"test-utils\"))]".to_string(),
        "    /// still the same item".to_string(),
        "    pub fn new_for_tests(".to_string(),
    ];
    assert!(
        predecessor_gate(&docs_between, 2).is_ok(),
        "/// between the gate and the item is accepted"
    );

    let allow_then_gate = vec![
        "    #[allow(clippy::too_many_arguments)]".to_string(),
        "    #[cfg(any(test, feature = \"test-utils\"))]".to_string(),
        "    pub fn for_test(".to_string(),
    ];
    assert!(
        predecessor_gate(&allow_then_gate, 2).is_ok(),
        "gate immediately above the item is accepted"
    );

    let client = read_lines(CLIENT_REL);
    let new_for_tests =
        find_decl(&client, |t| is_fn_item(t, "new_for_tests"), "RemoteSigner::new_for_tests")
            .unwrap_or_else(|e| panic!("{e}"));
    let new_unchecked =
        find_decl(&client, |t| is_fn_item(t, "new_unchecked"), "RemoteSigner::new_unchecked")
            .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        new_unchecked > new_for_tests,
        "new_unchecked (line {}) must sit below new_for_tests (line {})",
        new_unchecked + 1,
        new_for_tests + 1
    );
    for (idx, line) in client.iter().enumerate().take(new_unchecked).skip(new_for_tests + 1) {
        let t = line.trim();
        let is_fn =
            t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ");
        assert!(
            !is_fn,
            "{CLIENT_REL}:{} unexpected fn between new_for_tests and its alias: {t}",
            idx + 1
        );
    }
    let alias_end = client.len().min(new_unchecked + 8);
    let alias_body = client[new_unchecked..alias_end].join("\n");
    assert!(
        alias_body.contains("Self::new_for_tests"),
        "new_unchecked must delegate to Self::new_for_tests"
    );

    let coord = read_lines(COORD_REL);
    let for_test = find_decl(&coord, |t| is_fn_item(t, "for_test"), "OrchestratorDeps::for_test")
        .unwrap_or_else(|e| panic!("{e}"));
    let mut impl_ok = false;
    for line in coord[..=for_test].iter().rev() {
        let t = line.trim();
        if t.starts_with("impl") {
            assert!(
                t.contains("OrchestratorDeps"),
                "{COORD_REL}:{} for_test is inside {t:?}, expected OrchestratorDeps",
                for_test + 1
            );
            impl_ok = true;
            break;
        }
    }
    assert!(impl_ok, "{COORD_REL}: for_test has no enclosing impl");

    let mut failures = Vec::new();
    for (lines, idx, what) in [
        (client.as_slice(), new_for_tests, format!("{CLIENT_REL} new_for_tests")),
        (client.as_slice(), new_unchecked, format!("{CLIENT_REL} new_unchecked")),
        (coord.as_slice(), for_test, format!("{COORD_REL} OrchestratorDeps::for_test")),
    ] {
        if let Err(e) = predecessor_gate(lines, idx) {
            failures.push(format!("{what}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "test-only constructors are missing #[cfg(any(test, feature = \"test-utils\"))]:\n  {}",
        failures.join("\n  ")
    );
}
