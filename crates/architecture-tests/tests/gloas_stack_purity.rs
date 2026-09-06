//! Issue 5.15 / #290: `rvc-gloas` stack-purity gate.
//!
//! Two name-based rules (not crate bans — a crate-level `libssz` ban would be a
//! rule the phase itself breaks; 5.3 may later drop `libssz-merkle`):
//!
//! 1. No `tree_hash::`, `ssz::`, or `ssz08::` import outside `#[cfg(test)]`
//!    under `crates/rvc-gloas/src`. `libssz_derive` / `libssz_types` / `libssz`
//!    trait imports are permitted crate-wide.
//! 2. `merkleize_progressive` and `mix_in_active_fields` are called in no file
//!    but `crates/rvc-gloas/src/merkle.rs`.
//!
//! Graph: `rvc-gloas` production out-edges == `{rvc-eth-types}`; neither
//! `rvc-crypto` nor `rvc-signer-server` depends on `rvc-gloas`;
//! `SIGNER_SERVER_ALLOWED_EDGES` stays unwidened.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, `no_rvc_prefix.rs`
//! idiom.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use rvc_architecture_tests::{load_workspace_graph, workspace_root, WorkspaceGraph};

const MERKLE_RS: &str = "crates/rvc-gloas/src/merkle.rs";
const GLOAS_DIR: &str = "crates/rvc-gloas";
const FORBIDDEN_IMPORT_PATHS: &[&str] = &["tree_hash::", "ssz::", "ssz08::"];
const PRIMITIVE_FNS: &[&str] = &["merkleize_progressive", "mix_in_active_fields"];
const GLOAS_ALLOWED_OUT_EDGES: &[&str] = &["rvc-eth-types"];

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn gloas_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&root.join(GLOAS_DIR), &mut out);
    out.sort();
    out
}

fn rel_path(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")
}

fn module_dir_for_file(file: &Path) -> PathBuf {
    let name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
    match name {
        "lib.rs" | "main.rs" | "mod.rs" => file.parent().unwrap_or(file).to_path_buf(),
        _ => {
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");
            file.parent().unwrap_or(file).join(stem)
        }
    }
}

// ---------------------------------------------------------------------------
// Comment / cfg(test) partition (house style: `#[cfg(test)]` then next item)
// ---------------------------------------------------------------------------

fn code_portion(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => {
                i += 2;
                continue;
            }
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn is_exact_cfg_test_attr(trimmed: &str) -> bool {
    matches!(trimmed, "#[cfg(test)]" | "#![cfg(test)]")
}

fn is_inner_cfg_test(trimmed: &str) -> bool {
    trimmed == "#![cfg(test)]"
}

fn strip_leading_attrs(s: &str) -> &str {
    let mut t = s.trim_start();
    while t.starts_with("#[") || t.starts_with("#![") {
        let Some(close) = t.find(']') else {
            return "";
        };
        t = t[close + 1..].trim_start();
    }
    t
}

fn brace_delta(line: &str) -> i32 {
    let mut d = 0i32;
    let mut in_str = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_str {
            if ch == '\\' {
                chars.next();
            } else if ch == '"' {
                in_str = false;
            }
        } else {
            match ch {
                '"' => in_str = true,
                '{' => d += 1,
                '}' => d -= 1,
                _ => {}
            }
        }
    }
    d
}

fn item_end_line(lines: &[&str], cfg_i: usize) -> usize {
    let mut start = cfg_i;
    let same = strip_leading_attrs(lines[cfg_i]);
    if same.is_empty() || same.starts_with("//") {
        start = cfg_i + 1;
        while start < lines.len() {
            let t = lines[start].trim();
            if t.is_empty() || t.starts_with("//") {
                start += 1;
                continue;
            }
            if t.starts_with("#[") && strip_leading_attrs(t).is_empty() {
                start += 1;
                continue;
            }
            break;
        }
        if start >= lines.len() {
            return lines.len();
        }
    }

    let mut depth = 0i32;
    let mut seen_brace = false;
    for (k, line) in lines.iter().enumerate().skip(start) {
        depth += brace_delta(line);
        if line.contains('{') {
            seen_brace = true;
        }
        if seen_brace && depth <= 0 {
            return k + 1;
        }
        if !seen_brace && line.contains(';') {
            return k + 1;
        }
    }
    lines.len()
}

fn cfg_test_spans(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if !is_exact_cfg_test_attr(trimmed) {
            i += 1;
            continue;
        }
        let start = i + 1;
        if is_inner_cfg_test(trimmed) {
            spans.push((start, lines.len().max(1)));
            break;
        }
        let end = item_end_line(&lines, i);
        spans.push((start, end));
        i = end;
    }
    spans
}

fn is_tests_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    parts.contains(&"tests") || parts.last().is_some_and(|p| *p == "tests.rs")
}

fn parse_mod_semi(item: &str) -> Option<&str> {
    let mut t = item.trim();
    if let Some(rest) = t.strip_prefix("pub") {
        t = rest.trim_start();
        if t.starts_with('(') {
            let close = t.find(')')?;
            t = t[close + 1..].trim_start();
        }
    }
    let rest = t.strip_prefix("mod ")?;
    let name = rest.trim().strip_suffix(';')?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name)
}

fn cfg_test_external_mod_names(src: &str) -> Vec<&str> {
    let lines: Vec<&str> = src.lines().collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if !is_exact_cfg_test_attr(trimmed) || is_inner_cfg_test(trimmed) {
            i += 1;
            continue;
        }
        let end = item_end_line(&lines, i);
        for line in &lines[i..end] {
            let t = strip_leading_attrs(line).trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if let Some(name) = parse_mod_semi(t) {
                names.push(name);
            }
            break;
        }
        i = end;
    }
    names
}

fn cfg_test_file_set(root: &Path, files: &[PathBuf]) -> HashSet<String> {
    let mut out = HashSet::new();
    for file in files {
        let src = std::fs::read_to_string(file).unwrap_or_default();
        let dir = module_dir_for_file(file);
        for name in cfg_test_external_mod_names(&src) {
            for candidate in [dir.join(format!("{name}.rs")), dir.join(name).join("mod.rs")] {
                if candidate.is_file() {
                    out.insert(rel_path(root, &candidate));
                }
            }
        }
    }
    out
}

fn is_test_region(
    rel: &str,
    src: &str,
    line_1based: usize,
    cfg_test_files: &HashSet<String>,
) -> bool {
    if cfg_test_files.contains(rel) || is_tests_path(rel) {
        return true;
    }
    cfg_test_spans(src).iter().any(|&(s, e)| line_1based >= s && line_1based <= e)
}

// ---------------------------------------------------------------------------
// Name matchers
// ---------------------------------------------------------------------------

fn contains_ident_path(code: &str, path: &str) -> bool {
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(rel) = code[from..].find(path) {
        let at = from + rel;
        let before_ok = at == 0 || {
            let b = bytes[at - 1];
            !(b.is_ascii_alphanumeric() || b == b'_')
        };
        if before_ok {
            return true;
        }
        from = at + path.len();
    }
    false
}

fn contains_call(code: &str, name: &str) -> bool {
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(rel) = code[from..].find(name) {
        let at = from + rel;
        let before_ok = at == 0 || {
            let b = bytes[at - 1];
            !(b.is_ascii_alphanumeric() || b == b'_')
        };
        let after = at + name.len();
        let after_ok = after < bytes.len() && code[after..].trim_start().starts_with('(');
        if before_ok && after_ok {
            return true;
        }
        from = at + name.len();
    }
    false
}

fn forbidden_legacy_imports(rel: &str, src: &str, cfg_test_files: &HashSet<String>) -> Vec<String> {
    let mut hits = Vec::new();
    if !rel.starts_with("crates/rvc-gloas/src/") {
        return hits;
    }
    for (i, line) in src.lines().enumerate() {
        let line_no = i + 1;
        if is_test_region(rel, src, line_no, cfg_test_files) {
            continue;
        }
        let code = code_portion(line);
        for path in FORBIDDEN_IMPORT_PATHS {
            if contains_ident_path(code, path) {
                hits.push(format!("{rel}:{line_no}: `{path}` import outside #[cfg(test)]"));
            }
        }
    }
    hits
}

fn primitive_calls_outside_merkle(rel: &str, src: &str) -> Vec<String> {
    let mut hits = Vec::new();
    if rel == MERKLE_RS {
        return hits;
    }
    for (i, line) in src.lines().enumerate() {
        let code = code_portion(line);
        for name in PRIMITIVE_FNS {
            if contains_call(code, name) {
                hits.push(format!("{rel}:{}: `{name}(` call outside {MERKLE_RS}", i + 1));
            }
        }
    }
    hits
}

fn production_mentions(
    rel: &str,
    src: &str,
    needle: &str,
    cfg_test_files: &HashSet<String>,
) -> bool {
    src.lines().enumerate().any(|(i, line)| {
        let line_no = i + 1;
        !is_test_region(rel, src, line_no, cfg_test_files) && code_portion(line).contains(needle)
    })
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

fn check_gloas_edges(graph: &WorkspaceGraph) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    match graph.edges.get("rvc-gloas") {
        None => errors.push("package 'rvc-gloas' not found in workspace metadata".to_string()),
        Some(deps) => {
            let expected: BTreeSet<String> =
                GLOAS_ALLOWED_OUT_EDGES.iter().copied().map(str::to_string).collect();
            if deps != &expected {
                errors.push(format!(
                    "rvc-gloas production out-edges must equal {{rvc-eth-types}}; got {deps:?}"
                ));
            }
        }
    }
    for pkg in ["rvc-crypto", "rvc-signer-server"] {
        if graph.edges.get(pkg).is_some_and(|d| d.contains("rvc-gloas")) {
            errors.push(format!("{pkg} must not depend on rvc-gloas"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn parse_signer_server_allowed_edges(src: &str) -> Vec<&str> {
    const HDR: &str = "const SIGNER_SERVER_ALLOWED_EDGES";
    let start =
        src.find(HDR).expect("SIGNER_SERVER_ALLOWED_EDGES missing from architecture_no_cycles.rs");
    let after = &src[start..];
    let end = after.find("];").expect("SIGNER_SERVER_ALLOWED_EDGES unclosed");
    let block = &after[..end];
    let mut names = Vec::new();
    let mut rest = block;
    while let Some(q) = rest.find('"') {
        rest = &rest[q + 1..];
        let Some(close) = rest.find('"') else { break };
        names.push(&rest[..close]);
        rest = &rest[close + 1..];
    }
    names
}

// ---------------------------------------------------------------------------
// Real tree
// ---------------------------------------------------------------------------

#[test]
fn real_tree_has_no_legacy_ssz_imports_outside_cfg_test() {
    let root = workspace_root();
    let files = gloas_rs_files(&root);
    assert!(
        files.len() >= 10,
        "scanned only {} rvc-gloas .rs files; walk likely broke",
        files.len()
    );
    let cfg_test_files = cfg_test_file_set(&root, &files);

    let mut hits = Vec::new();
    let mut saw_derive = false;
    let mut saw_types = false;
    let mut saw_libssz = false;
    for file in &files {
        let rel = rel_path(&root, file);
        let src = std::fs::read_to_string(file).unwrap_or_default();
        hits.extend(forbidden_legacy_imports(&rel, &src, &cfg_test_files));
        if production_mentions(&rel, &src, "libssz_derive", &cfg_test_files) {
            saw_derive = true;
        }
        if production_mentions(&rel, &src, "libssz_types", &cfg_test_files) {
            saw_types = true;
        }
        if production_mentions(&rel, &src, "libssz::", &cfg_test_files) {
            saw_libssz = true;
        }
    }
    assert!(
        hits.is_empty(),
        "rvc-gloas production must not import tree_hash:: / ssz:: / ssz08:: outside #[cfg(test)]:\n  {}",
        hits.join("\n  ")
    );
    assert!(
        saw_derive && saw_types && saw_libssz,
        "non-vacuity: container modules must import libssz_derive / libssz_types / libssz \
         (otherwise a crate-level libssz ban would also be green); \
         derive={saw_derive} types={saw_types} libssz={saw_libssz}"
    );
}

#[test]
fn real_tree_confines_primitive_calls_to_merkle_rs() {
    let root = workspace_root();
    let files = gloas_rs_files(&root);
    let mut saw_merkle = false;
    let mut hits = Vec::new();
    for file in &files {
        let rel = rel_path(&root, file);
        let src = std::fs::read_to_string(file).unwrap_or_default();
        if rel == MERKLE_RS {
            saw_merkle = true;
            for name in PRIMITIVE_FNS {
                assert!(
                    src.contains(name),
                    "{MERKLE_RS} must still name `{name}` (otherwise rule 2 is vacuous)"
                );
            }
        }
        hits.extend(primitive_calls_outside_merkle(&rel, &src));
    }
    assert!(saw_merkle, "walk missed {MERKLE_RS}");
    assert!(hits.is_empty(), "primitive calls must stay in {MERKLE_RS}:\n  {}", hits.join("\n  "));
}

#[test]
fn real_tree_gloas_production_edges_are_eth_types_only() {
    let graph = load_workspace_graph();
    check_gloas_edges(&graph).unwrap_or_else(|errors| {
        panic!("{}", errors.join("\n"));
    });
}

#[test]
fn signer_server_allowed_edges_is_not_widened_with_rvc_gloas() {
    let src = include_str!("architecture_no_cycles.rs");
    let names = parse_signer_server_allowed_edges(src);
    assert!(
        !names.is_empty(),
        "SIGNER_SERVER_ALLOWED_EDGES must be parseable from architecture_no_cycles.rs"
    );
    assert!(
        !names.contains(&"rvc-gloas"),
        "SIGNER_SERVER_ALLOWED_EDGES must stay unwidened (no rvc-gloas); found {names:?}"
    );
}

// ---------------------------------------------------------------------------
// Red paths (failure-message content so the gate is falsifiable)
// ---------------------------------------------------------------------------

#[test]
fn production_tree_hash_import_is_rejected() {
    let empty = HashSet::new();
    let src = "use libssz_derive::HashTreeRoot;\nuse tree_hash::TreeHash;\n";
    let rel = "crates/rvc-gloas/src/containers/attestation.rs";
    let hits = forbidden_legacy_imports(rel, src, &empty);
    assert!(
        !hits.is_empty(),
        "gate must fail on synthetic `use tree_hash::TreeHash;` in a production island module"
    );
    let msg = hits.join("\n");
    assert!(msg.contains("tree_hash::"), "failure must name `tree_hash::`; got: {msg}");
    assert!(msg.contains(rel), "failure must name the production module; got: {msg}");
    assert!(
        msg.contains("#[cfg(test)]"),
        "failure must say the import is outside #[cfg(test)]; got: {msg}"
    );
}

#[test]
fn production_ssz_and_ssz08_imports_are_rejected() {
    let empty = HashSet::new();
    let rel = "crates/rvc-gloas/src/lib.rs";
    for (path, src) in [("ssz::", "use ssz::Decode;\n"), ("ssz08::", "use ssz08::Encode;\n")] {
        let hits = forbidden_legacy_imports(rel, src, &empty);
        assert!(!hits.is_empty(), "gate must fail on synthetic `{path}` import");
        let msg = hits.join("\n");
        assert!(msg.contains(path), "failure must name `{path}`; got: {msg}");
    }
}

#[test]
fn cfg_test_tree_hash_import_is_permitted() {
    let empty = HashSet::new();
    let src = "\
use libssz_derive::HashTreeRoot;
use libssz_types::ProgressiveList;

#[cfg(test)]
mod tests {
    use tree_hash::TreeHash;
    use ssz::Decode;
    use ssz08::Encode;
}
";
    let hits = forbidden_legacy_imports("crates/rvc-gloas/src/containers/leaves.rs", src, &empty);
    assert!(
        hits.is_empty(),
        "tree_hash:: / ssz:: / ssz08:: inside #[cfg(test)] must be permitted; got {hits:?}"
    );
}

#[test]
fn libssz_paths_are_not_flagged_as_ssz() {
    let empty = HashSet::new();
    let src = "\
use libssz::SszDecode;
use libssz_derive::HashTreeRoot;
use libssz_types::ProgressiveList;
use libssz_merkle::Sha2Hasher;
";
    let hits = forbidden_legacy_imports("crates/rvc-gloas/src/roots.rs", src, &empty);
    assert!(
        hits.is_empty(),
        "libssz / libssz_derive / libssz_types must not match ssz::; got {hits:?}"
    );
}

#[test]
fn merkleize_progressive_outside_merkle_rs_is_rejected() {
    let src = "fn f(chunks: &[[u8; 32]]) { let _ = merkleize_progressive(chunks); }\n";
    let rel = "crates/rvc-gloas/src/roots.rs";
    let hits = primitive_calls_outside_merkle(rel, src);
    assert!(
        !hits.is_empty(),
        "gate must fail on synthetic merkleize_progressive( call outside merkle.rs"
    );
    let msg = hits.join("\n");
    assert!(
        msg.contains("merkleize_progressive"),
        "failure must name merkleize_progressive; got: {msg}"
    );
    assert!(msg.contains(rel), "failure must name the offending file; got: {msg}");
    assert!(msg.contains(MERKLE_RS), "failure must name the only allowed file; got: {msg}");
}

#[test]
fn mix_in_active_fields_outside_merkle_rs_is_rejected() {
    let src = "fn f(root: [u8; 32], bits: &[bool]) { let _ = mix_in_active_fields(root, bits); }\n";
    let hits = primitive_calls_outside_merkle("crates/rvc-gloas/src/containers/block_body.rs", src);
    let msg = hits.join("\n");
    assert!(!hits.is_empty(), "gate must fail on mix_in_active_fields( outside merkle.rs");
    assert!(
        msg.contains("mix_in_active_fields"),
        "failure must name mix_in_active_fields; got: {msg}"
    );
}

#[test]
fn primitive_calls_in_merkle_rs_are_permitted() {
    let src = "\
pub(crate) fn merkleize_progressive(chunks: &[[u8; 32]]) -> [u8; 32] {
    libssz_merkle::merkleize_progressive(&Sha2Hasher, chunks)
}
pub(crate) fn mix_in_active_fields(root: [u8; 32], bits: &[bool]) -> [u8; 32] {
    libssz_merkle::mix_in_active_fields(&Sha2Hasher, &root, bits)
}
";
    let hits = primitive_calls_outside_merkle(MERKLE_RS, src);
    assert!(hits.is_empty(), "calls inside merkle.rs must be permitted; got {hits:?}");
}

#[test]
fn comment_primitive_mention_is_not_a_call() {
    let src = "/// `merkleize_progressive(chunk_run(0))` from the 3.4b pyspec artifact.\nconst X: u8 = 0;\n";
    let hits = primitive_calls_outside_merkle("crates/rvc-gloas/src/spec_kat.rs", src);
    assert!(hits.is_empty(), "doc-comment mentions must not count as calls; got {hits:?}");
}

#[test]
fn synthetic_second_production_out_edge_is_rejected() {
    let mut graph = load_workspace_graph();
    let deps = graph.edges.get_mut("rvc-gloas").expect("rvc-gloas must exist in cargo metadata");
    assert!(
        deps.contains("rvc-eth-types"),
        "real graph helper must already show rvc-gloas -> rvc-eth-types; got {deps:?}"
    );
    deps.insert("rvc-crypto".to_string());
    let err =
        check_gloas_edges(&graph).expect_err("synthetic second production out-edge must fail");
    let msg = err.join("\n");
    assert!(msg.contains("rvc-gloas"), "failure must name rvc-gloas; got: {msg}");
    assert!(
        msg.contains("rvc-eth-types"),
        "failure must name the allowed set {{rvc-eth-types}}; got: {msg}"
    );
    assert!(
        msg.contains("rvc-crypto"),
        "failure must name the extra production out-edge; got: {msg}"
    );
}

#[test]
fn matcher_ignores_non_keys() {
    assert!(contains_ident_path("use tree_hash::TreeHash;", "tree_hash::"));
    assert!(contains_ident_path("use ssz::Decode;", "ssz::"));
    assert!(!contains_ident_path("use libssz::SszDecode;", "ssz::"));
    assert!(!contains_ident_path("use libssz_types::ProgressiveList;", "ssz::"));
    assert!(contains_call("let _ = merkleize_progressive(&chunks);", "merkleize_progressive"));
    assert!(contains_call("mix_in_active_fields (root, bits)", "mix_in_active_fields"));
    assert!(!contains_call("let merkleize_progressive = 1;", "merkleize_progressive"));
}
