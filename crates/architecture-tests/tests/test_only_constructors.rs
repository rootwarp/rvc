//! RR4-03 / #539, follow-up #602: test-only constructors are gated by the compiler.
//!
//! `RemoteSigner::new_for_tests` and `OrchestratorDeps::for_test` are `pub`
//! constructors that skip production checks. Without a cfg they compile into
//! a default library build. `new_unchecked` is the `pub(crate)` alias of
//! `new_for_tests`. Before the gate it was already `#[cfg(test)]` (this crate's
//! unit tests only); it did not compile into a default build. The named check
//! still requires the same attribute on all three, and requires the alias to
//! stay `pub(crate)`:
//!
//! - `RemoteSigner::new_for_tests` in `crates/remote-signer-client/src/client.rs`
//!   (skips the insecure-URL gate)
//! - its alias `new_unchecked` immediately below (delegates to `new_for_tests`)
//! - `OrchestratorDeps::for_test` in `crates/rvc/src/orchestrator/coordinator/mod.rs`
//!
//! `#[cfg(test)]` alone is not enough for those three. Integration tests are a
//! separate crate, so `cfg(test)` is false on the library they link. The
//! attribute is exactly `#[cfg(any(test, feature = "test-utils"))]`. Downstream
//! integration tests see the items through the self dev-dependency feature
//! unification from RR0-01 (`rvc`) and the signer dev-dependency feature
//! (`remote-signer-client`).
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
//! fails the named check. A `cargo check` that must fail is PR evidence, not a
//! second gate. The feature-graph walk in `test_utils_feature_graph.rs` is a
//! separate gate: it fails if a normal or build edge can turn `test-utils` on
//! for `rvc-bin` (every Docker allow-listed feature combo), `rvc-signer-bin`
//! (default and `dvt`), `rvc-keygen`, or a unified workspace `default-members`
//! release build.
//!
//! ## Every `pub` `*for_test*` item
//!
//! The named check covers three items. A second scan walks `crates/*/src` and
//! `bin/*/src` for every `pub` / `pub(...)` function whose name contains
//! `for_test` (including generic signatures such as `fn name<T>(`, generics
//! containing `->`, and multi-line generics). The contiguous attribute block
//! above the item (skipping blank lines and `///`, stopping at any other line)
//! must contain either `#[cfg(any(test, feature = "test-utils"))]` or
//! `#[cfg(test)]`, as a single line. `#[cfg(feature = "test-utils")]` alone
//! does not count. Private functions are out of scope; `#[cfg(test)]` modules
//! already drop them from library builds, and a private item is not a
//! cross-crate helper.
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
    let unchecked_decl = client[new_unchecked].trim();
    assert!(
        unchecked_decl.starts_with("pub(crate) fn new_unchecked("),
        "{CLIENT_REL}: new_unchecked must stay pub(crate), found {unchecked_decl}"
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

const CFG_TEST: &str = "#[cfg(test)]";

struct ForTestFn {
    rel: String,
    line: usize,
    decl: String,
}

fn strip_kw<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(kw)?;
    if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(rest.trim_start())
}

/// Skip a balanced `<…>` generic list. `->` / `=>` are not closers.
/// Returns `None` if the generics are unclosed (multi-line continuation).
fn skip_generics(after: &str) -> Option<&str> {
    if !after.starts_with('<') {
        return Some(after);
    }
    let mut depth = 0usize;
    let bytes = after.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'-' | b'=' if i + 1 < bytes.len() && bytes[i + 1] == b'>' => {
                // `->` / `=>` inside bounds (e.g. `F: Fn() -> u8`).
                i += 2;
            }
            b'<' => {
                depth += 1;
                i += 1;
            }
            b'>' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if depth == 0 {
                    return Some(after[i..].trim_start());
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// `Some(true)` / `Some(false)` when the signature is complete enough to decide;
/// `None` when generics look unclosed (caller should join the next line).
fn parse_pub_for_test_complete(trim: &str) -> Option<bool> {
    let mut rest = strip_kw(trim, "pub")?;
    if let Some(after) = rest.strip_prefix('(') {
        let end = after.find(')')?;
        rest = after[end + 1..].trim_start();
    }
    loop {
        if let Some(next) = strip_kw(rest, "async") {
            rest = next;
            continue;
        }
        if let Some(next) = strip_kw(rest, "const") {
            rest = next;
            continue;
        }
        if let Some(next) = strip_kw(rest, "unsafe") {
            rest = next;
            continue;
        }
        break;
    }
    let rest = strip_kw(rest, "fn")?;
    let name: String =
        rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if name.is_empty() || !name.contains("for_test") {
        return Some(false);
    }
    let after = rest[name.len()..].trim_start();
    let after = skip_generics(after)?;
    if after.is_empty() {
        return None;
    }
    Some(after.starts_with('('))
}

/// `pub` / `pub(...)` function whose name contains `for_test`.
fn parse_pub_for_test(trim: &str) -> bool {
    parse_pub_for_test_complete(trim).unwrap_or(false)
}

/// True when `lines[idx..]` forms a `pub … fn *for_test*` signature, joining
/// subsequent lines while generics remain unclosed.
fn parse_pub_for_test_at(lines: &[String], idx: usize) -> bool {
    let mut buf = String::new();
    for line in lines.iter().skip(idx).take(16) {
        let t = line.trim();
        if t.is_empty() {
            break;
        }
        if t.starts_with("//") && buf.is_empty() {
            return false;
        }
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(t);
        match parse_pub_for_test_complete(&buf) {
            Some(decision) => return decision,
            None => continue,
        }
    }
    false
}

fn attribute_block(lines: &[String], decl_idx: usize) -> Vec<String> {
    let mut attrs = Vec::new();
    let mut i = decl_idx;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with("///") {
            continue;
        }
        if t.starts_with("#[") {
            attrs.push(t.to_string());
            continue;
        }
        break;
    }
    attrs
}

fn block_is_gated(attrs: &[String]) -> bool {
    attrs.iter().any(|a| a == GATE || a == CFG_TEST)
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("read dir entry: {e}"));
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn workspace_src_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut out = Vec::new();
    for top in ["crates", "bin"] {
        let base = root.join(top);
        let entries = std::fs::read_dir(&base).unwrap_or_else(|e| panic!("read {top}: {e}"));
        for entry in entries {
            let src = entry.unwrap_or_else(|e| panic!("{e}")).path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out.sort();
    out
}

fn ungated_pub_for_test_fns() -> Vec<ForTestFn> {
    let root = workspace_root();
    let mut found = Vec::new();
    for path in workspace_src_files() {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut idx = 0usize;
        while idx < lines.len() {
            let trim = lines[idx].trim();
            if trim.starts_with("//") || !parse_pub_for_test_at(&lines, idx) {
                idx += 1;
                continue;
            }
            if block_is_gated(&attribute_block(&lines, idx)) {
                idx += 1;
                continue;
            }
            let rel = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
            found.push(ForTestFn { rel, line: idx + 1, decl: trim.to_string() });
            idx += 1;
        }
    }
    found
}

#[test]
fn pub_for_test_helpers_are_cfg_gated() {
    let ungated =
        vec!["    /// docs".to_string(), "    pub fn scrypt_cheap_for_tests(".to_string()];
    assert!(!block_is_gated(&attribute_block(&ungated, 1)), "ungated item must fail");

    let cfg_test = vec!["    #[cfg(test)]".to_string(), "    pub(crate) fn for_test(".to_string()];
    assert!(
        block_is_gated(&attribute_block(&cfg_test, 1)),
        "cfg(test) keeps the item out of library builds"
    );

    let combined = vec![
        "    #[allow(dead_code)]".to_string(),
        "    #[cfg(any(test, feature = \"test-utils\"))]".to_string(),
        "    #[doc(hidden)]".to_string(),
        "    pub async fn acquire_signing_lock_for_test(".to_string(),
    ];
    assert!(
        block_is_gated(&attribute_block(&combined, 3)),
        "the combined gate anywhere in the attribute block is accepted"
    );

    let feature_only = vec![
        "    #[cfg(feature = \"test-utils\")]".to_string(),
        "    pub fn open_with_conn_for_testing(".to_string(),
    ];
    assert!(!block_is_gated(&attribute_block(&feature_only, 1)), "feature-only cfg must fail");

    assert!(parse_pub_for_test("pub fn scrypt_cheap_for_tests() -> Self {"));
    assert!(parse_pub_for_test("pub(crate) fn for_test(deadline_ms: u64) -> Self {"));
    assert!(parse_pub_for_test("pub async fn drive_once_for_test(&self) {"));
    assert!(parse_pub_for_test("pub fn make_for_test<T>(value: T) -> T {"));
    assert!(parse_pub_for_test("pub(crate) fn for_test<'a, T: Clone>(x: &'a T) {"));
    assert!(parse_pub_for_test("pub fn map_for_test<F: Fn() -> u8>(f: F) {"));
    assert!(parse_pub_for_test("pub fn for_test<F: FnOnce() -> Result<(), E>, E>(f: F) {"));
    assert!(!parse_pub_for_test("fn with_channel_for_test() {"));
    assert!(!parse_pub_for_test("// pub fn new_for_tests("));
    assert!(!parse_pub_for_test("pub fn for_test_name_only {"));
    assert_eq!(parse_pub_for_test_complete("pub fn for_test<T: Foo"), None);
    let multiline = vec![
        "    pub fn for_test<".to_string(),
        "        T: Clone,".to_string(),
        "    >(value: T) {".to_string(),
    ];
    assert!(parse_pub_for_test_at(&multiline, 0), "multi-line generics must match");
    let arrow_multiline = vec![
        "    pub fn for_test<F: Fn() -> u8,".to_string(),
        "        E,".to_string(),
        "    >(f: F) {".to_string(),
    ];
    assert!(
        parse_pub_for_test_at(&arrow_multiline, 0),
        "multi-line generics containing -> must match"
    );

    let found = ungated_pub_for_test_fns();
    let rendered: Vec<String> =
        found.iter().map(|f| format!("{}:{} {}", f.rel, f.line, f.decl)).collect();
    assert!(
        found.is_empty(),
        "pub *for_test* items need #[cfg(any(test, feature = \"test-utils\"))] or #[cfg(test)]:\n  {}",
        rendered.join("\n  ")
    );
}
