//! ARCH-5l / X5: no production caller outside `crates/slashing/src/` uses
//! `stage_block(` / `stage_attestation(`.
//!
//! After ADR-005 the owner of `stage_*` is `crates/slashing/src/**` (wrappers +
//! the retained pre-switchover API). Production signing goes through
//! `reserve_then_sign` + `PubkeyScopedDb::reserve_*`. What makes two staging
//! APIs safe is this gate, not a convention.
//!
//! Path-scoped exclusions:
//!
//! - `crates/slashing/src/**` — owner
//! - `**/tests/**` and true `#[cfg(test)]` / `#![cfg(test)]` regions
//!   (house style: bottom `#[cfg(test)] mod tests`; next-item brace walk).
//!   `#[cfg(any(test, feature = "test-utils"))]` on a single item is **not**
//!   a test region — that would hide `core.rs` after `for_tests`.
//! - **C10 orphans:** `crates/rvc-signer/`, `crates/rvc-keygen/`,
//!   `crates/rvc/src/main.rs`, `crates/rvc/src/commands/`
//!
//! DVT is **not** C10. `crates/signer-server/src/dvt/peer_service.rs` is a
//! shrinking-only exact pin (Phase 7 / C9-anchor-5 remaining bypass): exactly
//! three production `stage_*` sites (two `stage_block`, one `stage_attestation`),
//! fail if a fourth appears or if they vanish.
//!
//! Non-vacuity: the walk visits > 0 files; a synthetic `scoped.stage_block(`
//! and `.stage_then_sign(` are reported; a core.rs-shaped fixture (for_tests
//! cfg, then production `stage_*`) is reported.
//!
//! Hand-rolled walk, same idiom as `raw_spawn.rs` / `env_allowlist.rs`.
//! No test name matches `.*(tree_hash|signing_root|_root)$` (A-5.10).

use std::path::{Path, PathBuf};

const THIS_GATE: &str = "crates/architecture-tests/tests/stage_api_scope.rs";

/// Shrinking-only pin: Phase 7 / C9-anchor-5 remaining SigningGate bypass.
/// Not a C10 orphan. ARCH-5l does not migrate DVT.
const DVT_STAGE_ALLOW: &str = "crates/signer-server/src/dvt/peer_service.rs";
const DVT_STAGE_ALLOW_HITS: usize = 3;

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
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// `crates/*/src/**/*.rs` + `bin/*/src/**/*.rs`.
fn scan_root_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for top in ["crates", "bin"] {
        let parent = root.join(top);
        let Ok(entries) = std::fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out
}

fn rel_path(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")
}

/// Path exclusions: slashing owner, tests paths, C10 orphans.
/// DVT is scanned (shrinking pin), not skipped.
fn is_path_excluded(rel: &str) -> bool {
    if rel == THIS_GATE {
        return true;
    }
    if rel.starts_with("crates/slashing/src/") {
        return true;
    }
    if rel.starts_with("crates/rvc-signer/") || rel.starts_with("crates/rvc-keygen/") {
        return true;
    }
    if rel == "crates/rvc/src/main.rs" || rel.starts_with("crates/rvc/src/commands/") {
        return true;
    }
    if is_tests_path(rel) {
        return true;
    }
    false
}

/// `**/tests/**` or a `tests.rs` filename (crate-level and `src/**/tests`).
fn is_tests_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.contains(&"tests") {
        return true;
    }
    parts.last().is_some_and(|p| *p == "tests.rs")
}

/// Exact `#[cfg(test)]` / `#![cfg(test)]` only — not `cfg(any(test, …))`.
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

/// 1-based last line of the item gated by `#[cfg(test)]` at 0-based `cfg_i`.
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

/// Inclusive 1-based spans of true `#[cfg(test)]` items (`#![cfg(test)]` → EOF).
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

fn is_test_region(rel: &str, src: &str, line_1based: usize) -> bool {
    if is_tests_path(rel) {
        return true;
    }
    cfg_test_spans(src).iter().any(|&(s, e)| line_1based >= s && line_1based <= e)
}

fn code_portion(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
            i += 1;
            continue;
        }
        if !in_str && b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn is_comment_only_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") || t.starts_with('*')
}

const STAGE_NEEDLES: &[&str] = &["stage_block(", "stage_attestation("];

fn line_has_stage_call(code: &str) -> bool {
    for needle in STAGE_NEEDLES {
        if !code.contains(needle) {
            continue;
        }
        let name = needle.trim_end_matches('(');
        if code.contains(&format!("fn {name}")) {
            continue;
        }
        return true;
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StageHit {
    rel_path: String,
    line: u32,
    text: String,
}

fn find_production_stage_calls(rel_path: &str, src: &str) -> Vec<StageHit> {
    if is_path_excluded(rel_path) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let line_1based = i + 1;
        if is_comment_only_line(line) {
            continue;
        }
        let code = code_portion(line);
        if !line_has_stage_call(code) {
            continue;
        }
        if is_test_region(rel_path, src, line_1based) {
            continue;
        }
        out.push(StageHit {
            rel_path: rel_path.to_string(),
            line: line_1based as u32,
            text: line.trim().to_string(),
        });
    }
    out
}

fn find_production_stage_then_sign(rel_path: &str, src: &str) -> Vec<StageHit> {
    if is_path_excluded(rel_path) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let line_1based = i + 1;
        if is_comment_only_line(line) {
            continue;
        }
        let code = code_portion(line);
        if !code.contains(".stage_then_sign(") {
            continue;
        }
        if is_test_region(rel_path, src, line_1based) {
            continue;
        }
        out.push(StageHit {
            rel_path: rel_path.to_string(),
            line: line_1based as u32,
            text: line.trim().to_string(),
        });
    }
    out
}

fn scanned_production_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for file in scan_root_rs_files(root) {
        let rel = rel_path(root, &file);
        if is_path_excluded(&rel) {
            continue;
        }
        out.push((rel, file));
    }
    out
}

fn format_hits(hits: &[StageHit]) -> String {
    hits.iter()
        .map(|h| format!("{}:{}: {}", h.rel_path, h.line, h.text))
        .collect::<Vec<_>>()
        .join("\n  ")
}

#[test]
fn test_no_production_caller_uses_stage_block_outside_slashing() {
    let root = workspace_root();
    let files = scanned_production_files(&root);
    assert!(
        !files.is_empty(),
        "scanned 0 files under crates/*/src + bin/*/src after exclusions; walk likely broke"
    );
    assert!(files.len() > 50, "scanned only {} files; workspace walk likely broke", files.len());

    let mut dvt_hits = Vec::new();
    let mut violations: Vec<String> = Vec::new();
    for (rel, file) in &files {
        let src = std::fs::read_to_string(file).unwrap_or_default();
        let hits = find_production_stage_calls(rel, &src);
        if rel.as_str() == DVT_STAGE_ALLOW {
            dvt_hits.extend(hits);
            continue;
        }
        for hit in hits {
            violations.push(format!("{}:{}: {}", hit.rel_path, hit.line, hit.text));
        }
    }
    violations.sort();
    assert!(
        violations.is_empty(),
        "ARCH-5l / X5: production `stage_block(` / `stage_attestation(` must live only in \
         crates/slashing/src (owner) or the DVT shrinking pin. Offenders:\n  {}",
        violations.join("\n  ")
    );
    assert_eq!(
        dvt_hits.len(),
        DVT_STAGE_ALLOW_HITS,
        "Phase 7 / C9-anchor-5 pin {DVT_STAGE_ALLOW}: expected exactly {DVT_STAGE_ALLOW_HITS} \
         production stage_* sites (remove the pin if they vanished; fail if a fourth appears).\n  {}",
        format_hits(&dvt_hits)
    );
}

#[test]
fn test_no_production_caller_uses_stage_then_sign() {
    let root = workspace_root();
    let files = scanned_production_files(&root);
    assert!(!files.is_empty(), "scanned 0 files; walk likely broke");

    let mut violations: Vec<String> = Vec::new();
    for (rel, file) in &files {
        let src = std::fs::read_to_string(file).unwrap_or_default();
        for hit in find_production_stage_then_sign(rel, &src) {
            violations.push(format!("{}:{}: {}", hit.rel_path, hit.line, hit.text));
        }
    }
    violations.sort();
    assert!(
        violations.is_empty(),
        "ARCH-5l: production `.stage_then_sign(` hits must be none \
         (`#[cfg(test)] mod tests` is excluded). Offenders:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn test_dvt_peer_service_stage_sites_are_a_shrinking_pin() {
    let root = workspace_root();
    let path = root.join(DVT_STAGE_ALLOW);
    let src = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(!src.is_empty(), "{DVT_STAGE_ALLOW} must exist and be readable");

    let hits = find_production_stage_calls(DVT_STAGE_ALLOW, &src);
    assert_eq!(
        hits.len(),
        DVT_STAGE_ALLOW_HITS,
        "Phase 7 / C9-anchor-5: {DVT_STAGE_ALLOW} must contain exactly {DVT_STAGE_ALLOW_HITS} \
         production stage_block(/stage_attestation( sites (not C10). Found:\n  {}",
        format_hits(&hits)
    );

    let mut other = Vec::new();
    let dvt_dir = root.join("crates/signer-server/src/dvt");
    let mut dvt_files = Vec::new();
    collect_rs(&dvt_dir, &mut dvt_files);
    for file in dvt_files {
        let rel = rel_path(&root, &file);
        if rel == DVT_STAGE_ALLOW || is_path_excluded(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(&file).unwrap_or_default();
        other.extend(find_production_stage_calls(&rel, &src));
    }
    assert!(
        other.is_empty(),
        "Phase 7 / C9-anchor-5: no stage_* outside {DVT_STAGE_ALLOW} under dvt/. Offenders:\n  {}",
        format_hits(&other)
    );
}

#[test]
fn test_stage_api_scanner_reports_a_synthetic_violation() {
    let rel = "crates/signer/src/core.rs";
    let src = "    let (staged, audit) = scoped.stage_block(&pk, slot, None);\n";
    let hits = find_production_stage_calls(rel, src);
    assert_eq!(hits.len(), 1, "synthetic scoped.stage_block( must be reported; got {hits:?}");
    assert_eq!(hits[0].line, 1);
    assert!(hits[0].text.contains("stage_block("));

    let src_att = "    scoped.stage_attestation(&pk, 1, 2, None)?;\n";
    let hits_att = find_production_stage_calls(rel, src_att);
    assert_eq!(hits_att.len(), 1, "synthetic stage_attestation( must be reported");

    let src_then = "    session.stage_then_sign(|| stage());\n";
    let hits_then = find_production_stage_then_sign(rel, src_then);
    assert_eq!(
        hits_then.len(),
        1,
        "synthetic .stage_then_sign( must be reported; got {hits_then:?}"
    );
}

#[test]
fn test_scanner_sees_production_after_cfg_any_test_utils_item() {
    // core.rs-shaped: for_tests cfg sits *above* the production consumer.
    let rel = "crates/signer/src/core.rs";
    let src = r#"
impl SlashableSignSession {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_tests() {}

    fn reserve_then_sign_duty() {
        scoped.stage_block(&pk, slot, None);
        session.stage_then_sign(|| ok());
    }
}

#[cfg(test)]
mod tests {
    fn t() {
        scoped.stage_block(&pk, slot, None);
        session.stage_then_sign(|| ok());
    }
}
"#;
    let stage = find_production_stage_calls(rel, src);
    assert_eq!(
        stage.len(),
        1,
        "production scoped.stage_block( after cfg(any(test,…)) must be reported; got {stage:?}"
    );
    assert!(stage[0].text.contains("stage_block("));
    assert!(
        stage[0].line < first_exact_cfg_test_line(src).unwrap() as u32
            || !is_test_region(rel, src, stage[0].line as usize),
        "reported hit must not be inside #[cfg(test)] mod tests"
    );

    let then = find_production_stage_then_sign(rel, src);
    assert_eq!(
        then.len(),
        1,
        "production session.stage_then_sign( after cfg(any(test,…)) must be reported; got {then:?}"
    );
    assert!(then[0].text.contains(".stage_then_sign("));
}

fn first_exact_cfg_test_line(src: &str) -> Option<usize> {
    for (i, line) in src.lines().enumerate() {
        if is_exact_cfg_test_attr(line.trim()) {
            return Some(i + 1);
        }
    }
    None
}

#[test]
fn test_scanner_excludes_cfg_test_bodies_and_owner() {
    let rel = "crates/signer/src/core.rs";
    let src = r#"
fn production() {}

#[cfg(test)]
mod tests {
    fn t() {
        scoped.stage_block(&pk, slot, None);
    }
}
"#;
    assert!(
        find_production_stage_calls(rel, src).is_empty(),
        "hits inside #[cfg(test)] must be excluded"
    );

    let owner = "crates/slashing/src/scoped.rs";
    let owner_src = "    scoped.stage_block(&pk, slot, None);\n";
    assert!(
        find_production_stage_calls(owner, owner_src).is_empty(),
        "crates/slashing/src is the owner and must be excluded"
    );
}

#[test]
fn test_scanner_excludes_c10_orphans() {
    let src = "    scoped.stage_block(&pk, slot, None);\n";
    for rel in [
        "crates/rvc-signer/src/service.rs",
        "crates/rvc-signer/src/dvt/peer_service.rs",
        "crates/rvc-keygen/src/main.rs",
        "crates/rvc/src/main.rs",
        "crates/rvc/src/commands/signed_exit.rs",
    ] {
        assert!(find_production_stage_calls(rel, src).is_empty(), "C10 exclusion missed {rel}");
    }
}

#[test]
fn test_scan_visited_a_plausible_number_of_files() {
    let root = workspace_root();
    let files = scanned_production_files(&root);
    assert!(files.len() > 50, "scanned only {} files; workspace walk likely broke", files.len());
    assert!(
        files.iter().any(|(r, _)| r.starts_with("crates/signer/src/")),
        "expected crates/signer/src in the scan set"
    );
    assert!(
        files.iter().any(|(r, _)| r == DVT_STAGE_ALLOW),
        "DVT pin file must be in the scan set (not a directory skip)"
    );
    assert!(
        files.iter().all(|(r, _)| !r.starts_with("crates/slashing/src/")),
        "owner crates/slashing/src must not be in the scanned set"
    );
}
