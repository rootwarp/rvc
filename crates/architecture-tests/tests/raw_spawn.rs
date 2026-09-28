//! G-4 / ARCH-2k: ban raw `tokio::spawn` outside `TaskExecutor` and a shrinking allow-list.
//!
//! Path-scoped to `crates/rvc/src/**` + `bin/rvc/src/**`. Production hits must live only in
//! `crates/rvc/src/bootstrap/executor.rs` (the composition-root executor) or on the shrinking-only
//! [`ALLOW_LIST`]. Test regions are excluded by the **union** of:
//!
//! 1. **Line rule** — hits on or after a file-local `#[cfg(test)]` (bottom `mod tests` style), and
//! 2. **Path rule (VD-2c)** — any file under `src/**/tests/` or named `tests.rs`, because some
//!    test modules are gated externally (`#[cfg(test)] mod tests;` at
//!    `crates/rvc/src/orchestrator/coordinator/mod.rs`) and contain **no** in-file `#[cfg(test)]`.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled walk, same idiom as `kat_policy.rs`.
//!
//! ## Out of scan scope by path, not by exemption (VD-2f / VD-2d)
//!
//! G-4's original seed listed four Infra library sites. All four live **outside** this scanner's
//! path scope, so they are **not** allow-list rows (a never-matching row is dead weight in a
//! shrinking-only table). Recorded here for reviewers and Phase 3 (ADR-013):
//!
//! | Out-of-scope site | Reason |
//! |---|---|
//! | `crates/bn-manager/src/manager.rs` (`start_sse`) | Infra crate; cannot depend on the composition-root executor without violating the DAG gate. ARCH-3l `register`s the returned `JoinHandle` from `bootstrap/tasks.rs` (`"bn.sse"`). |
//! | `crates/bn-manager/src/sse.rs` | Same, plus: nested inside `subscribe_events`, whose handle is **discarded**. ARCH-3l makes the subscriber live (the inner dispatch task still exits when `subscribe_events` returns). |
//! | `crates/bn-manager/src/sync_status.rs` (`start_sync_monitor`) | Same; DSR-2.1 `register`s the returned `JoinHandle` from `bootstrap/tasks.rs` (`"bn.sync_monitor"`). |
//! | `crates/keymanager-api/src/lifecycle.rs` | Live, but **per-pubkey/per-import**: a `&'static str`-named registry entry per key is the wrong shape, and its cancellation is the C5 `stop_monitoring`/`cancel_monitoring` contract, unguarded until **G-6 lands in Phase 7**. |
//!
//! ## `spawn_blocking` (C9 anchor 7)
//!
//! Explicitly **not** scanned and must never enter the ban list.
//! `crates/signer/src/core.rs` is the cancellation-proof core;
//! `crates/signer-server/src/dvt/peer_service.rs` carries `!Send` guards. A ban that catches them
//! is a C9 regression wearing a hygiene costume.
//!
//! Cross-ref: plan/architecture-2026-08-12 issues ARCH-2k, M8, ADR-001.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Ban list — free-function names that count as raw spawns
// ---------------------------------------------------------------------------

/// Patterns matched as raw spawns. `spawn_blocking` / `spawn_local` must never appear here
/// (C9 anchor 7); `test_ban_list_excludes_spawn_blocking` pins that.
const BAN_LIST: &[&str] = &["tokio::spawn"];

// ---------------------------------------------------------------------------
// Shrinking-only allow-list (path, 1-based line) — empty after ARCH-2g (M8 = 0)
// ---------------------------------------------------------------------------

/// Workspace-relative `/`-separated paths + 1-based line numbers of raw production
/// `tokio::spawn` sites still permitted outside [`EXECUTOR_PATH`].
///
/// **Shrinking-only:** entries may be **removed**, never **added**. ARCH-2g migrated all nine
/// in-scope production sites onto `TaskExecutor`, so this list is empty (M8 = 0).
///
/// Infra sites are **not** listed here (VD-2f): they are outside the scan path; see module docs.
const ALLOW_LIST: &[(&str, u32)] = &[];

/// Sole production path permitted to call `tokio::spawn` without an allow-list entry
/// (the executor's own `register` / `spawn` implementation).
const EXECUTOR_PATH: &str = "crates/rvc/src/bootstrap/executor.rs";

// ---------------------------------------------------------------------------
// Workspace walk (scan roots only)
// ---------------------------------------------------------------------------

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

/// `crates/rvc/src/**/*.rs` + `bin/rvc/src/**/*.rs` only (G-4 path scope).
fn scan_root_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in ["crates/rvc/src", "bin/rvc/src"] {
        let dir = root.join(rel);
        if dir.is_dir() {
            collect_rs(&dir, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Path + cfg(test) exclusion (VD-2c)
// ---------------------------------------------------------------------------

/// `**/src/**/tests/**` or `**/src/**/tests.rs` — full file is a test region (VD-2c).
///
/// Pins the shape where `#[cfg(test)] mod tests;` lives in a parent module and child files under
/// `src/**/tests/` have no in-file `#[cfg(test)]` (e.g. `orchestrator/coordinator/tests/spans.rs`).
fn is_src_tests_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    let Some(src_i) = parts.iter().position(|&p| p == "src") else {
        return false;
    };
    let after = &parts[src_i + 1..];
    if after.contains(&"tests") {
        return true;
    }
    after.last().is_some_and(|p| *p == "tests.rs")
}

/// True if `trimmed` is a `#[cfg(test)]` / `#![cfg(test)]` attribute (common forms).
fn is_cfg_test_attr(trimmed: &str) -> bool {
    let t = trimmed.trim_end_matches(',').trim();
    if !(t.starts_with("#[cfg(") || t.starts_with("#![cfg(")) {
        return false;
    }
    // Predicate contains `test` as a cfg key, not a substring of another ident.
    // Forms: #[cfg(test)], #[cfg(test, feature = "x")], #[cfg(all(test, ...))], #![cfg(test)]
    let inner_start = t.find('(').map(|i| i + 1).unwrap_or(0);
    let inner_end = t.rfind(')').unwrap_or(t.len());
    if inner_start >= inner_end {
        return false;
    }
    let inner = &t[inner_start..inner_end];
    for token in inner.split(|c: char| c == ',' || c == '(' || c == ')' || c.is_whitespace()) {
        if token == "test" {
            return true;
        }
    }
    false
}

/// First 1-based line of a file-local `#[cfg(test)]` (or `#![cfg(test)]`). Hits on or after this
/// line are treated as test-region (house style: tests module at file bottom).
fn first_cfg_test_line(src: &str) -> Option<usize> {
    for (i, line) in src.lines().enumerate() {
        if is_cfg_test_attr(line.trim()) {
            return Some(i + 1);
        }
    }
    None
}

fn is_test_region(rel: &str, src: &str, line_1based: usize) -> bool {
    if is_src_tests_path(rel) {
        return true;
    }
    if let Some(cfg_line) = first_cfg_test_line(src) {
        if line_1based >= cfg_line {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

/// Strip `//` line comments outside of strings (best-effort; adequate for spawn call sites).
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

/// True if the line is a doc or plain comment-only line.
fn is_comment_only_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") || t.starts_with('*')
}

/// Does `code` contain a banned raw-spawn call (BAN_LIST), excluding `spawn_blocking` / `spawn_local`?
fn line_has_raw_spawn(code: &str) -> bool {
    for ban in BAN_LIST {
        let mut from = 0;
        while let Some(rel) = code[from..].find(ban) {
            let at = from + rel;
            let after = &code[at + ban.len()..];
            // Refuse longer identifiers: tokio::spawn_blocking, tokio::spawn_local, …
            let continues_ident =
                after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if continues_ident {
                from = at + ban.len();
                continue;
            }
            let before_ok = at == 0 || {
                let b = code.as_bytes()[at - 1];
                !(b.is_ascii_alphanumeric() || b == b'_')
            };
            if !before_ok {
                from = at + ban.len();
                continue;
            }
            // Call form: optional whitespace then `(`
            if after.trim_start().starts_with('(') {
                return true;
            }
            from = at + ban.len();
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpawnHit {
    rel_path: String,
    line: u32,
    /// Trimmed source line (for failure messages).
    text: String,
}

/// Classify one synthetic or real file: return production raw-spawn hits (test regions excluded).
fn find_production_spawns(rel_path: &str, src: &str) -> Vec<SpawnHit> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let line_1based = i + 1;
        if is_comment_only_line(line) {
            continue;
        }
        let code = code_portion(line);
        if !line_has_raw_spawn(code) {
            continue;
        }
        if is_test_region(rel_path, src, line_1based) {
            continue;
        }
        out.push(SpawnHit {
            rel_path: rel_path.to_string(),
            line: line_1based as u32,
            text: line.trim().to_string(),
        });
    }
    out
}

fn is_allowed(hit: &SpawnHit, allow: &HashSet<(&str, u32)>) -> bool {
    if hit.rel_path == EXECUTOR_PATH {
        return true;
    }
    allow.contains(&(hit.rel_path.as_str(), hit.line))
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn no_raw_spawns_outside_executor_and_allowlist() {
    let root = workspace_root();
    let files = scan_root_rs_files(&root);
    assert!(
        files.len() > 40,
        "scanned only {} files under crates/rvc/src + bin/rvc/src; workspace walk likely broke",
        files.len()
    );

    let allow: HashSet<(&str, u32)> = ALLOW_LIST.iter().copied().collect();
    assert_eq!(allow.len(), ALLOW_LIST.len(), "duplicate ALLOW_LIST entries");

    let mut violations: Vec<String> = Vec::new();
    let mut production_hits = 0usize;
    let mut used_allow: HashSet<(String, u32)> = HashSet::new();

    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let src = std::fs::read_to_string(file).unwrap_or_default();
        for hit in find_production_spawns(&rel, &src) {
            production_hits += 1;
            if is_allowed(&hit, &allow) {
                used_allow.insert((hit.rel_path.clone(), hit.line));
                continue;
            }
            violations.push(format!("{}:{}: {}", hit.rel_path, hit.line, hit.text));
        }
    }

    // Non-vacuity: after ARCH-2g, production hits remain only in the executor (ALLOW_LIST empty).
    // Require the walk still sees files and at least the executor's own spawns.
    assert!(
        production_hits >= ALLOW_LIST.len(),
        "found only {production_hits} production raw-spawn hit(s); matcher or walk likely broke \
         (ALLOW_LIST has {})",
        ALLOW_LIST.len()
    );
    assert!(
        production_hits > 0,
        "expected production hits inside {EXECUTOR_PATH}; matcher or walk likely broke"
    );

    violations.sort();
    assert!(
        violations.is_empty(),
        "G-4 raw-spawn gate (ARCH-2k / M8): raw `tokio::spawn` under crates/rvc/src/** + \
         bin/rvc/src/** must live only in {EXECUTOR_PATH} (ALLOW_LIST empty after ARCH-2g).\n\
         Offenders:\n  {}",
        violations.join("\n  ")
    );

    // Stale allow-list rows (site migrated or line moved) fail deliberately.
    let mut stale: Vec<String> = Vec::new();
    for &(path, line) in ALLOW_LIST {
        if !used_allow.contains(&(path.to_string(), line)) {
            stale.push(format!("{path}:{line}"));
        }
    }
    assert!(
        stale.is_empty(),
        "ALLOW_LIST entries not observed as production hits (remove after ARCH-2g or fix line):\n  {}",
        stale.join("\n  ")
    );
}

#[test]
fn allow_list_is_sorted_unique_and_documented_size() {
    // ARCH-2g emptied the list (M8 = 0). Shrinking-only: never grow again.
    assert_eq!(
        ALLOW_LIST.len(),
        0,
        "post-ARCH-2g ALLOW_LIST must be empty (M8 = 0); do not re-seed without a plan amendment"
    );
    let mut seen = HashSet::new();
    let mut prev: Option<(&str, u32)> = None;
    for &(path, line) in ALLOW_LIST {
        assert!(seen.insert((path, line)), "duplicate allow-list entry: {path}:{line}");
        if let Some((pp, pl)) = prev {
            assert!(
                (pp, pl) < (path, line),
                "ALLOW_LIST must stay sorted by (path, line); {pp}:{pl} precedes {path}:{line}"
            );
        }
        prev = Some((path, line));
    }
}

#[test]
fn ban_list_excludes_spawn_blocking() {
    for ban in BAN_LIST {
        assert!(
            !ban.contains("spawn_blocking"),
            "C9 anchor 7: BAN_LIST must not contain spawn_blocking; found {ban:?}"
        );
        assert!(
            *ban != "tokio::spawn_blocking" && *ban != "spawn_blocking",
            "C9 anchor 7: BAN_LIST must not ban spawn_blocking"
        );
    }
    // Mechanical: the only banned free function is tokio::spawn itself.
    assert_eq!(BAN_LIST, &["tokio::spawn"]);
}

// ---------------------------------------------------------------------------
// Matcher unit tests (synthetic RED / exclusions)
// ---------------------------------------------------------------------------

#[test]
fn test_matcher_flags_a_raw_spawn_in_a_production_path() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "    tokio::spawn(foo());\n";
    let hits = find_production_spawns(rel, src);
    assert_eq!(hits.len(), 1, "expected one production raw spawn, got {hits:?}");
    assert_eq!(hits[0].rel_path, rel);
    assert_eq!(hits[0].line, 1);
    // Failure message contract (NFR-5/R10): path must be nameable from the hit.
    let msg = format!("{}:{}: {}", hits[0].rel_path, hits[0].line, hits[0].text);
    assert!(
        msg.contains("crates/rvc/src/bootstrap/tasks.rs:1:"),
        "failure message must name path:line; got {msg}"
    );
}

#[test]
fn test_matcher_excludes_src_tests_directory_without_a_cfg_test_line() {
    // VD-2c: coordinator tests live under src/**/tests/ with no in-file #[cfg(test)] —
    // gating is external (`#[cfg(test)] mod tests;` at coordinator/mod.rs).
    let rel = "crates/rvc/src/orchestrator/coordinator/tests/spans.rs";
    let src = "tokio::spawn(async move { /* synthetic */ });\n";
    assert!(
        !src.contains("cfg(test)"),
        "synthetic content must not contain #[cfg(test)] so only the path rule applies"
    );
    let hits = find_production_spawns(rel, src);
    assert!(
        hits.is_empty(),
        "VD-2c path rule must exclude src/**/tests/** even without #[cfg(test)]; got {hits:?}"
    );
}

#[test]
fn test_matcher_excludes_tests_rs_filename() {
    let rel = "crates/rvc/src/orchestrator/foo/tests.rs";
    let src = "tokio::spawn(async {});\n";
    assert!(find_production_spawns(rel, src).is_empty());
}

#[test]
fn test_matcher_excludes_after_a_file_local_cfg_test_line() {
    // Ordinary case: config/builder.rs-style — production code, then #[cfg(test)] mod tests.
    let rel = "crates/rvc/src/config/builder.rs";
    let src = r#"
fn production() {}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn t() {
        let server = tokio::spawn(async move {});
    }
}
"#;
    let hits = find_production_spawns(rel, src);
    assert!(hits.is_empty(), "spawn after file-local #[cfg(test)] must be excluded; got {hits:?}");
}

#[test]
fn test_matcher_flags_spawn_before_cfg_test() {
    let rel = "crates/rvc/src/bootstrap/run.rs";
    let src = r#"
fn spawn_refresh() {
    let handle = tokio::spawn(async move {});
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn t() {
        let server = tokio::spawn(async move {});
    }
}
"#;
    let hits = find_production_spawns(rel, src);
    assert_eq!(hits.len(), 1, "only the production spawn; got {hits:?}");
    assert!(hits[0].line < first_cfg_test_line(src).unwrap() as u32);
}

#[test]
fn test_matcher_never_flags_spawn_blocking() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "    let h = tokio::spawn_blocking(|| heavy());\n";
    let hits = find_production_spawns(rel, src);
    assert!(hits.is_empty(), "C9 anchor 7: spawn_blocking must not be flagged; got {hits:?}");
}

#[test]
fn test_matcher_ignores_doc_comment_mentions() {
    let rel = "crates/rvc/src/liveness_loop.rs";
    let src = "    /// Run until cancelled. Spawns no tasks — call from `tokio::spawn`.\n";
    assert!(find_production_spawns(rel, src).is_empty());
}

#[test]
fn test_scan_visited_a_plausible_number_of_files() {
    let root = workspace_root();
    let files = scan_root_rs_files(&root);
    assert!(files.len() > 40, "scanned only {} files; workspace walk likely broke", files.len());
    // Both roots present.
    let rels: HashSet<String> = files
        .iter()
        .map(|f| f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(rels.iter().any(|r| r.starts_with("crates/rvc/src/")), "expected crates/rvc/src hits");
    assert!(rels.iter().any(|r| r.starts_with("bin/rvc/src/")), "expected bin/rvc/src hits");
}

#[test]
fn test_path_rule_helpers() {
    assert!(is_src_tests_path("crates/rvc/src/orchestrator/coordinator/tests/spans.rs"));
    assert!(is_src_tests_path("crates/rvc/src/orchestrator/coordinator/tests/core.rs"));
    assert!(is_src_tests_path("crates/rvc/src/foo/tests.rs"));
    assert!(!is_src_tests_path("crates/rvc/src/bootstrap/tasks.rs"));
    assert!(!is_src_tests_path("bin/rvc/src/logging.rs"));
    // Integration tests outside src/ are outside the scan roots entirely; path helper still false.
    assert!(!is_src_tests_path("crates/rvc/tests/sync_independent_of_attesting.rs"));
}

#[test]
fn test_cfg_test_attr_detection() {
    assert!(is_cfg_test_attr("#[cfg(test)]"));
    assert!(is_cfg_test_attr("#![cfg(test)]"));
    assert!(is_cfg_test_attr("#[cfg(all(test, feature = \"x\"))]"));
    assert!(!is_cfg_test_attr("#[cfg(feature = \"test-utils\")]"));
    assert!(!is_cfg_test_attr("#[test]"));
}
