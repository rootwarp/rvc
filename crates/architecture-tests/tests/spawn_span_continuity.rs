//! TRC-6c: pin production executor sites to tracing ADR-009.
//!
//! Scans **tracked** sources only:
//!
//! ```text
//! git ls-files 'crates/rvc/**/*.rs' 'bin/rvc/**/*.rs'
//! ```
//!
//! Paths containing `/tests/` are dropped. A site is `executor.spawn(`,
//! `executor.spawn_result(`, `executor.register(`, `executor.register_result(`,
//! or `executor.register_opt(` whose handle argument is
//! `Some` (any non-`None` handle expression counts, so a future `Some(_)` cannot
//! hide). `register_opt(..., None)` is not a site. `spawn_blocking` is not scanned.
//!
//! The production region ends at the first column-0 `#[cfg(test)]` followed by
//! `mod` (visibility and a `//` / attribute gap are allowed). A bare `#[cfg(test)]`
//! does not end the region: `liveness_loop.rs` has method-level attributes above
//! the production spawn, and truncating there drops that site. Lines whose trimmed
//! form starts with `///` or `//!` are skipped, so the `run` doc comment in
//! `liveness_loop.rs` ("Spawns no tasks") is not a spawn.
//!
//! A site passes only when:
//!
//! 1. the immediately preceding non-empty line is a `// detached:` comment, or
//! 2. it is one of the five shape-B spawns in
//!    `plan/tracing-2026-08-06/spawn-census.md`, and the loop **file** named there
//!    contains `parent: None` and `follows_from` for that task.
//!
//! A window around the spawn line is not classification (2). `monitoring_push` and
//! `proposer_config_refresh` are spawned in `bootstrap/tasks.rs`; their loops live
//! in other files. The allow-list is empty. The pin is 16 (5 shape B, 11 detached,
//! shape A = 0).
//!
//! The executor pin is a hand-rolled text scan, same style as `raw_spawn.rs`.
//! Its `production_region_end` line cut is unchanged. The bn-manager section
//! is separate: `tokio::spawn` and the `#[cfg(test)] mod` cut come from
//! `ra_ap_rustc_lexer` tokens, and the row names the enclosing item. An
//! untrusted token stream fails that file.

use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, LiteralKind, TokenKind};
use rvc_architecture_tests::{non_code_spans, SourceItems};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Production-site pin. 5 shape B + 11 detached + shape A = 0.
const PIN: usize = 16;
const SHAPE_B_PIN: usize = 5;
const DETACHED_PIN: usize = 11;
const SHAPE_A_PIN: usize = 0;

const CENSUS: &str = "plan/tracing-2026-08-06/spawn-census.md";

/// Empty. A site is classified by a `// detached:` comment or a census shape-B
/// row. Entries are never an escape hatch.
const ALLOW_LIST: &[(&str, u32)] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Spawn,
    Register,
    RegisterOpt,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Register => "register",
            Self::RegisterOpt => "register_opt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    path: String,
    line: usize,
    kind: Kind,
    /// Immediately preceding non-empty line is a `// detached:` comment.
    detached: bool,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShapeBRow {
    task: String,
    spawn_path: String,
    spawn_line: usize,
    loop_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Detached,
    ShapeB,
    /// Census row matched, but the loop file lacks `parent: None` / `follows_from`.
    ShapeBLoopMissing,
    /// Shape-B spawn line also carries `// detached:`.
    ShapeBWithDetached,
    Unclassified,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

// ---------------------------------------------------------------------------
// Tracked-file scan
// ---------------------------------------------------------------------------

fn tracked_rs_files(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "--", "crates/rvc/**/*.rs", "bin/rvc/**/*.rs"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git ls-files utf-8")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.ends_with(".rs"))
        .filter(|l| !l.contains("/tests/"))
        .map(|l| l.replace('\\', "/"))
        .collect()
}

// ---------------------------------------------------------------------------
// Production region: #[cfg(test)] followed by mod
// ---------------------------------------------------------------------------

/// 1-based line of the first column-0 `#[cfg(test)]` followed by `mod`.
///
/// Lines at and after this line are outside the production region. Returns
/// `None` when the file has no such module attribute (the whole file is
/// production for this gate).
fn production_region_end(lines: &[&str]) -> Option<usize> {
    for (i, line) in lines.iter().enumerate() {
        if is_column0_cfg_test(line) && cfg_test_followed_by_mod(lines, i) {
            return Some(i + 1);
        }
    }
    None
}

/// Column-0 `#[cfg(test)]`, not `#[cfg(test, ...)]` or `#[cfg(testing)]`.
fn is_column0_cfg_test(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("#[cfg(test)]") else {
        return false;
    };
    rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace())
}

/// `#[cfg(test)]` then `mod`, skipping blank lines, `//` comments, and attributes.
///
/// Same-line `#[cfg(test)] mod tests` counts. `pub` / `pub(crate)` / `pub(super)`
/// may precede `mod`. An indented method attribute is not column-0, so it never
/// reaches this check.
fn cfg_test_followed_by_mod(lines: &[&str], idx: usize) -> bool {
    let rest = lines[idx].trim().strip_prefix("#[cfg(test)]").unwrap_or("").trim_start();
    if !rest.is_empty() && !rest.starts_with("//") {
        return is_mod_item(rest);
    }
    for line in lines.iter().skip(idx + 1) {
        let n = line.trim();
        if n.is_empty() || n.starts_with("//") || n.starts_with('#') {
            continue;
        }
        return is_mod_item(n);
    }
    false
}

fn is_mod_item(trimmed: &str) -> bool {
    let rest = if let Some(after_pub) = trimmed.strip_prefix("pub") {
        let after_pub = after_pub.trim_start();
        if let Some(inside) = after_pub.strip_prefix('(') {
            let Some(end) = inside.find(')') else {
                return false;
            };
            inside[end + 1..].trim_start()
        } else {
            after_pub
        }
    } else {
        trimmed
    };
    let Some(after_mod) = rest.strip_prefix("mod") else {
        return false;
    };
    after_mod.is_empty() || after_mod.starts_with(|c: char| c.is_whitespace() || c == '{')
}

/// First 1-based line whose trim is exactly `#[cfg(test)]`, indented or not.
///
/// This is the truncation this gate refuses: it hides `liveness_loop.rs`'s
/// production spawn, which sits above the column-0 module attribute.
fn first_bare_cfg_test_line(lines: &[&str]) -> Option<usize> {
    lines.iter().position(|l| l.trim() == "#[cfg(test)]").map(|i| i + 1)
}

// ---------------------------------------------------------------------------
// Call scan
// ---------------------------------------------------------------------------

fn code_portion(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str && b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'"' {
            in_str = !in_str;
            i += 1;
            continue;
        }
        if !in_str && b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Production code with comment-only lines blanked, cut at the module attribute.
///
/// Line numbers match the original file. Doc comments (`///`, `//!`) and other
/// `//` lines contribute no tokens.
fn production_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let end = production_region_end(&lines).unwrap_or(lines.len() + 1);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i + 1 >= end {
            break;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") || trimmed.starts_with("//") {
            out.push('\n');
        } else {
            out.push_str(code_portion(line));
            out.push('\n');
        }
    }
    out
}

struct CallHit {
    kind: Kind,
    line: usize,
    is_site: bool,
    close_paren: usize,
}

fn find_calls(code: &str) -> Vec<CallHit> {
    let bytes = code.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    let mut hits = Vec::new();
    while i < bytes.len() {
        if in_str {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if code[i..].starts_with("executor.") {
            if let Some(hit) = parse_call(code, i) {
                let next = hit.close_paren + 1;
                hits.push(hit);
                i = next;
                continue;
            }
        }
        i += 1;
    }
    hits
}

fn parse_call(code: &str, at: usize) -> Option<CallHit> {
    let rest_at = at + "executor.".len();
    let rest = &code[rest_at..];
    let (kind, name_len) = method_kind(rest)?;
    let mut j = name_len;
    j += ws_len(&rest[j..]);
    if rest[j..].starts_with("::") {
        j = skip_turbofish(rest, j)?;
        j += ws_len(&rest[j..]);
    }
    if rest.as_bytes().get(j) != Some(&b'(') {
        return None;
    }
    let paren = rest_at + j;
    let close = matching_paren(code, paren)?;
    let args = &code[paren + 1..close];
    let is_site = match kind {
        Kind::RegisterOpt => !last_arg_is_none(args),
        Kind::Spawn | Kind::Register => true,
    };
    let line = code[..at].bytes().filter(|&c| c == b'\n').count() + 1;
    Some(CallHit { kind, line, is_site, close_paren: close })
}

fn method_kind(rest: &str) -> Option<(Kind, usize)> {
    const CANDIDATES: &[(&str, Kind)] = &[
        ("register_opt", Kind::RegisterOpt),
        ("register_result", Kind::Register),
        ("register", Kind::Register),
        ("spawn_result", Kind::Spawn),
        ("spawn", Kind::Spawn),
    ];
    for &(name, kind) in CANDIDATES {
        if let Some(after) = rest.strip_prefix(name) {
            let continues = after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
            if !continues {
                return Some((kind, name.len()));
            }
        }
    }
    None
}

fn ws_len(s: &str) -> usize {
    s.chars().take_while(|c| c.is_whitespace()).map(char::len_utf8).sum()
}

fn skip_turbofish(rest: &str, mut j: usize) -> Option<usize> {
    if !rest[j..].starts_with("::") {
        return Some(j);
    }
    j += 2;
    j += ws_len(&rest[j..]);
    let bytes = rest.as_bytes();
    if bytes.get(j) != Some(&b'<') {
        return None;
    }
    let mut depth = 0i32;
    while j < bytes.len() {
        match bytes[j] {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j + 1);
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

fn matching_paren(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Top-level comma-separated arguments. A trailing comma does not invent an empty last arg.
fn top_level_args(args: &str) -> Vec<&str> {
    let bytes = args.as_bytes();
    let mut depth_paren = 0i32;
    let mut depth_brack = 0i32;
    let mut depth_brace = 0i32;
    let mut in_str = false;
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_brack += 1,
            b']' => depth_brack -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b',' if depth_paren == 0 && depth_brack == 0 && depth_brace == 0 => {
                parts.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&args[start..]);
    parts
}

/// `None` or `None::<...>`. `Some(...)` is not `None`. A trailing comma is ignored.
fn last_arg_is_none(args: &str) -> bool {
    let last = top_level_args(args).into_iter().rev().find(|p| !p.trim().is_empty()).unwrap_or("");
    let Some(rest) = last.trim().strip_prefix("None") else {
        return false;
    };
    rest.is_empty() || !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn is_detached_comment(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("// detached:") && !t.starts_with("///")
}

fn preceding_nonempty<'a>(lines: &[&'a str], line_1based: usize) -> Option<&'a str> {
    let mut i = line_1based;
    while i > 1 {
        i -= 1;
        if !lines[i - 1].trim().is_empty() {
            return Some(lines[i - 1]);
        }
    }
    None
}

fn find_production_sites(path: &str, src: &str) -> Vec<Site> {
    let lines: Vec<&str> = src.lines().collect();
    let code = production_code(src);
    let mut sites = Vec::new();
    for hit in find_calls(&code) {
        if !hit.is_site {
            continue;
        }
        let text = lines.get(hit.line - 1).map(|l| l.trim().to_string()).unwrap_or_default();
        let detached = preceding_nonempty(&lines, hit.line).is_some_and(is_detached_comment);
        sites.push(Site { path: path.to_string(), line: hit.line, kind: hit.kind, detached, text });
    }
    sites
}

// ---------------------------------------------------------------------------
// Census shape B
// ---------------------------------------------------------------------------

fn parse_shape_b(census: &str) -> Vec<ShapeBRow> {
    let mut rows = Vec::new();
    let mut in_section = false;
    for line in census.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if in_section {
                break;
            }
            if heading.trim() == "Shape B loop sites" {
                in_section = true;
            }
            continue;
        }
        if !in_section || !line.starts_with('|') || line.contains("---") {
            continue;
        }
        let cells: Vec<&str> =
            line.trim().trim_matches('|').split('|').map(|c| c.trim().trim_matches('`')).collect();
        if cells.len() < 3 || cells[0] == "Task" || cells[0].is_empty() {
            continue;
        }
        let Some((spawn_path, spawn_line)) = split_path_line(cells[1]) else {
            continue;
        };
        let Some((loop_path, _)) = split_path_line(cells[2]) else {
            continue;
        };
        rows.push(ShapeBRow { task: cells[0].to_string(), spawn_path, spawn_line, loop_path });
    }
    rows
}

fn split_path_line(spec: &str) -> Option<(String, usize)> {
    let (path, line) = spec.rsplit_once(':')?;
    let line = line.parse().ok()?;
    if path.is_empty() {
        return None;
    }
    Some((path.to_string(), line))
}

/// The loop file contains `parent: None` on the task's span and a `follows_from`.
///
/// The task quote is exact (`"index.resolve"` does not match `"index.resolve.tick"`).
/// Comments are ignored. This reads the census loop file, not a window around the spawn.
fn loop_file_has_shape_b(loop_src: &str, task: &str) -> bool {
    let quoted = format!("\"{task}\"");
    let mut parent_for_task = false;
    let mut follows = false;
    for line in loop_src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let code = code_portion(line);
        if code.contains("parent: None") && code.contains(&quoted) {
            parent_for_task = true;
        }
        if code.contains("follows_from") {
            follows = true;
        }
    }
    parent_for_task && follows
}

fn classify(site: &Site, rows: &[ShapeBRow], loop_ok: impl Fn(&ShapeBRow) -> bool) -> Class {
    if let Some(row) = rows.iter().find(|r| r.spawn_path == site.path && r.spawn_line == site.line)
    {
        if site.detached {
            return Class::ShapeBWithDetached;
        }
        if loop_ok(row) {
            return Class::ShapeB;
        }
        return Class::ShapeBLoopMissing;
    }
    if site.detached {
        Class::Detached
    } else {
        Class::Unclassified
    }
}

// ---------------------------------------------------------------------------
// Failure text (count drift)
// ---------------------------------------------------------------------------

fn pin_failure(found: usize, detail: &str) -> String {
    format!(
        "production executor site count is {found}, pin is {PIN} \
         ({SHAPE_B_PIN} shape B, {DETACHED_PIN} detached, shape A = {SHAPE_A_PIN}).\n\
         Exclusion rule: end each file's production region at the first column-0 \
         `#[cfg(test)]` followed by `mod` (do not truncate at the first bare \
         `#[cfg(test)]`); skip lines whose trimmed form starts with `///` or `//!`; \
         `register_opt(..., None)` is not a site; drop paths containing `/tests/`.\n\
         A site passes only when (1) the immediately preceding non-empty line is a \
         `// detached:` comment, or (2) it is one of the five census shape-B spawns \
         and the loop file named in {CENSUS} contains `parent: None` and \
         `follows_from` for that task. A same-file window is not enough.\n\
         This pin is tracing ADR-009.\n\
         {detail}"
    )
}

fn scan_workspace(root: &Path) -> (Vec<Site>, Vec<ShapeBRow>) {
    let files = tracked_rs_files(root);
    assert!(
        files.len() > 40,
        "scanned only {} tracked files under crates/rvc and bin/rvc; git ls-files likely broke",
        files.len()
    );
    let census = std::fs::read_to_string(root.join(CENSUS)).unwrap_or_default();
    let rows = parse_shape_b(&census);
    let mut sites = Vec::new();
    for rel in &files {
        let src = std::fs::read_to_string(root.join(rel)).unwrap_or_default();
        sites.extend(find_production_sites(rel, &src));
    }
    sites.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    (sites, rows)
}

fn loop_ok_for<'a>(root: &'a Path) -> impl Fn(&ShapeBRow) -> bool + 'a {
    move |row: &ShapeBRow| {
        let src = std::fs::read_to_string(root.join(&row.loop_path)).unwrap_or_default();
        loop_file_has_shape_b(&src, &row.task)
    }
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

#[test]
fn production_executor_sites_pin_fourteen() {
    assert!(
        ALLOW_LIST.is_empty(),
        "allow-list stays empty; classify with a // detached: comment or a census shape-B row"
    );

    let root = workspace_root();
    let (sites, rows) = scan_workspace(&root);
    assert_eq!(
        rows.len(),
        SHAPE_B_PIN,
        "shape-B table in {CENSUS} must name {SHAPE_B_PIN} loop files; found {}",
        rows.len()
    );

    let loop_ok = loop_ok_for(&root);
    let mut detached = 0usize;
    let mut shape_b = 0usize;
    let shape_a = 0usize;
    let mut problems: Vec<String> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();

    for site in &sites {
        let class = classify(site, &rows, &loop_ok);
        let label = match class {
            Class::Detached => {
                detached += 1;
                "detached"
            }
            Class::ShapeB => {
                shape_b += 1;
                "shape-B"
            }
            Class::ShapeBLoopMissing => "shape-B-loop-missing",
            Class::ShapeBWithDetached => "shape-B-has-detached-comment",
            Class::Unclassified => "unclassified",
        };
        rendered.push(format!(
            "{}:{}: {} {label} {}",
            site.path,
            site.line,
            site.kind.as_str(),
            site.text
        ));
        if !matches!(class, Class::Detached | Class::ShapeB) {
            problems.push(format!("{}:{}: {label}", site.path, site.line));
        }
    }

    for row in &rows {
        let seen = sites.iter().any(|s| s.path == row.spawn_path && s.line == row.spawn_line);
        if !seen {
            problems.push(format!(
                "census shape-B row {}:{} ({}) is not a production site",
                row.spawn_path, row.spawn_line, row.task
            ));
        }
    }

    let ok = sites.len() == PIN
        && detached == DETACHED_PIN
        && shape_b == SHAPE_B_PIN
        && shape_a == SHAPE_A_PIN
        && problems.is_empty();
    assert!(
        ok,
        "{}",
        pin_failure(
            sites.len(),
            &format!(
                "counted {detached} detached, {shape_b} shape B, shape A = {shape_a}.\n\
                 problems:\n  {}\n\
                 sites:\n  {}",
                if problems.is_empty() { "(none)".to_string() } else { problems.join("\n  ") },
                rendered.join("\n  ")
            )
        )
    );
}

#[test]
fn allow_list_stays_empty() {
    assert!(
        ALLOW_LIST.is_empty(),
        "allow-list stays empty under tracing ADR-009; do not seed exemptions"
    );
}

#[test]
fn failure_names_the_exclusion_rule_and_tracing_adr_009() {
    let msg = pin_failure(15, "synthetic count drift");
    assert!(msg.contains("tracing ADR-009"), "{msg}");
    assert!(msg.contains("#[cfg(test)]"), "{msg}");
    assert!(msg.contains("followed by `mod`"), "{msg}");
    assert!(msg.contains("///"), "{msg}");
    assert!(msg.contains("register_opt(..., None)"), "{msg}");
    assert!(msg.contains("// detached:"), "{msg}");
    assert!(msg.contains("parent: None"), "{msg}");
    assert!(msg.contains("follows_from"), "{msg}");
    assert!(msg.contains(CENSUS), "{msg}");
    assert!(msg.contains("same-file window is not enough"), "{msg}");
    // The phrase must be the tracing decision, not a bare ADR-009.
    assert!(!msg.contains("architecture ADR-009"), "{msg}");
}

#[test]
fn bare_cfg_test_does_not_hide_the_liveness_loop_spawn() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/rvc/src/liveness_loop.rs")).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let bare = first_bare_cfg_test_line(&lines).expect("method-level #[cfg(test)]");
    let end = production_region_end(&lines).expect("column-0 module attribute");
    let spawn = lines
        .iter()
        .position(|l| code_portion(l).contains("executor.spawn("))
        .map(|i| i + 1)
        .expect("production liveness spawn");
    assert!(
        bare < spawn,
        "first bare #[cfg(test)] at {bare} must sit above the spawn at {spawn} \
         (truncating there drops the production site)"
    );
    assert!(spawn < end, "spawn at {spawn} must stay in the production region that ends at {end}");
    assert_eq!(lines[end - 1].trim(), "#[cfg(test)]");
    assert!(
        lines[end].trim().starts_with("mod"),
        "module line after the attribute: {}",
        lines[end]
    );
    // The doc comment is still in the production region and is not a site.
    assert!(
        lines.iter().any(|l| l.trim_start().starts_with("///") && l.contains("Spawns no tasks")),
        "re-locate the run() doc comment; it must not be scanned as a spawn"
    );
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", &src);
    assert_eq!(sites.len(), 1, "doc comment and test-module spawns must not count: {sites:?}");
    assert_eq!(sites[0].line, spawn);
    assert!(!sites[0].detached, "the shape-B spawn line has no // detached: comment");
}

#[test]
fn doc_comment_mentioning_a_spawn_is_not_a_site() {
    let src = "\
/// Run until cancelled. Spawns no tasks — call from `tokio::spawn`.\n\
/// Also not a site: executor.spawn(\n\
//! module doc executor.register(\n\
pub async fn run(self) {}\n\
";
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", src);
    assert!(sites.is_empty(), "doc comments are not spawns: {sites:?}");
}

#[test]
fn register_opt_none_is_not_a_site_and_some_is() {
    let src = "\
        executor.register_opt::<()>(SSE_TASK_NAME, ShutdownTier::Background, None);\n\
        executor.register_opt::<()>(\n\
            NAME,\n\
            ShutdownTier::Background,\n\
            None,\n\
        );\n\
        executor.register_opt(\"enabled\", ShutdownTier::Background, Some(handle));\n\
        executor.register_opt(\n\
            \"later\",\n\
            ShutdownTier::Background,\n\
            Some(handle),\n\
        );\n\
        executor.spawn_blocking(\"not-a-site\", || {});\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/tasks.rs", src);
    assert_eq!(
        sites.len(),
        2,
        "None is excluded, Some counts, spawn_blocking is not a site: {sites:?}"
    );
    assert!(sites.iter().all(|s| s.kind == Kind::RegisterOpt));
    assert_eq!(sites[0].line, 7, "single-line Some");
    assert_eq!(sites[1].line, 8, "multiline Some");
}

/// RR1-09: result-bearing entry points are the same sites as `spawn` / `register`.
#[test]
fn spawn_result_and_register_result_are_sites() {
    let src = "\
        // detached: result-bearing task.\n\
        executor.spawn_result(\"duty_orchestrator\", ShutdownTier::Orchestrator, async move {});\n\
        executor.register_result(\"metrics_like\", ShutdownTier::Telemetry, handle);\n\
        executor.spawn_blocking(\"not-a-site\", || {});\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/run.rs", src);
    assert_eq!(
        sites.len(),
        2,
        "spawn_result and register_result count; spawn_blocking does not: {sites:?}"
    );
    assert_eq!(sites[0].kind, Kind::Spawn);
    assert!(sites[0].detached, "preceding // detached: still classifies spawn_result");
    assert_eq!(sites[1].kind, Kind::Register);
    assert!(!sites[1].detached);
}

#[test]
fn cfg_test_mod_keeps_code_above_the_module_and_drops_the_module() {
    let src = "\
fn prod() {\n\
    #[cfg(test)]\n\
    async fn helper() {}\n\
    executor.spawn(\"liveness_loop\", ShutdownTier::Orchestrator, async move {});\n\
}\n\
#[cfg(test)]\n\
// gap\n\
#[allow(unsafe_code)]\n\
mod tests {\n\
    fn t() {\n\
        executor.spawn(\"hidden\", ShutdownTier::Background, async move {});\n\
    }\n\
}\n\
";
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", src);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].line, 4);
    assert!(sites[0].text.contains("liveness_loop"));
}

#[test]
fn shape_b_reads_the_census_loop_file_not_a_spawn_window() {
    let spawn_file = "\
        executor.spawn(\"monitoring_push\", ShutdownTier::Background, async move {});\n\
";
    // A same-file window that looks like shape B must not classify the spawn
    // when the census names a different loop file.
    let window_only = "\
        executor.spawn(\"monitoring_push\", ShutdownTier::Background, async move {});\n\
        let loop_span = tracing::info_span!(parent: None, \"monitoring_push\");\n\
        tick.follows_from(&loop_span);\n\
";
    let loop_file = "\
        let loop_span = tracing::info_span!(parent: None, \"monitoring_push\");\n\
        let tick = tracing::info_span!(parent: None, \"monitoring_push.tick\");\n\
        tick.follows_from(&loop_span);\n\
";
    let other_task = "\
        let loop_span = tracing::info_span!(parent: None, \"other\");\n\
        tick.follows_from(&loop_span);\n\
";
    let row = ShapeBRow {
        task: "monitoring_push".to_string(),
        spawn_path: "crates/rvc/src/bootstrap/tasks.rs".to_string(),
        spawn_line: 1,
        loop_path: "crates/rvc/src/background_tasks/monitoring.rs".to_string(),
    };
    let site = find_production_sites(&row.spawn_path, spawn_file).pop().unwrap();
    assert!(!site.detached);
    assert_eq!(
        classify(&site, std::slice::from_ref(&row), |_| {
            loop_file_has_shape_b(loop_file, "monitoring_push")
        }),
        Class::ShapeB
    );
    assert_eq!(
        classify(&site, std::slice::from_ref(&row), |_| {
            loop_file_has_shape_b(other_task, "monitoring_push")
        }),
        Class::ShapeBLoopMissing,
        "parent: None for a different task is not shape B"
    );
    let window_site = find_production_sites(&row.spawn_path, window_only).pop().unwrap();
    assert_eq!(
        classify(&window_site, std::slice::from_ref(&row), |_| false),
        Class::ShapeBLoopMissing,
        "a same-file window is not enough when the census loop file does not carry the spans"
    );
    assert!(loop_file_has_shape_b(loop_file, "monitoring_push"));
    assert!(!loop_file_has_shape_b(other_task, "monitoring_push"));
}

#[test]
fn detached_comment_is_the_preceding_nonempty_line() {
    let src = "\
\n\
    // detached: metrics server; out of scope.\n\
    executor.spawn(\"metrics_server\", ShutdownTier::Telemetry, async move {});\n\
    executor.spawn(\"bare\", ShutdownTier::Background, async move {});\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/tasks.rs", src);
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites[0].detached);
    assert!(!sites[1].detached);
    assert_eq!(classify(&sites[0], &[], |_| false), Class::Detached);
    assert_eq!(classify(&sites[1], &[], |_| false), Class::Unclassified);
}

#[test]
fn shape_b_spawn_must_not_carry_a_detached_comment() {
    let src = "\
    // detached: do not mark a shape-B spawn this way.\n\
    executor.spawn(\"liveness_loop\", ShutdownTier::Orchestrator, async move {});\n\
";
    let row = ShapeBRow {
        task: "liveness_loop".to_string(),
        spawn_path: "crates/rvc/src/liveness_loop.rs".to_string(),
        spawn_line: 2,
        loop_path: "crates/rvc/src/liveness_loop.rs".to_string(),
    };
    let site = find_production_sites(&row.spawn_path, src).pop().unwrap();
    assert!(site.detached);
    assert_eq!(classify(&site, &[row], |_| true), Class::ShapeBWithDetached);
}

// ---------------------------------------------------------------------------
// Census line pins (first table, shape-B loop lines, liveness prose)
// ---------------------------------------------------------------------------

fn section_body(census: &str, heading_contains: &str) -> String {
    let mut collecting = false;
    let mut found = false;
    let mut out = String::new();
    for line in census.lines() {
        if line.starts_with("## ") {
            if collecting {
                break;
            }
            if line.contains(heading_contains) {
                collecting = true;
                found = true;
            }
            continue;
        }
        if collecting {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(found, "census section containing {heading_contains:?} not found");
    out
}

fn markdown_table(section: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for line in section.lines() {
        if !line.starts_with('|') || line.contains("---") {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_string())
            .collect();
        if cells.iter().any(|c| c == "File" || c == "Task") || cells.iter().all(|c| c.is_empty()) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

fn cite_after(section: &str, phrase: &str) -> usize {
    let idx = section.find(phrase).unwrap_or_else(|| panic!("census prose missing {phrase:?}"));
    let rest = section[idx + phrase.len()..].trim_start_matches('`');
    assert!(rest.starts_with(':'), "expected :LINE after {phrase:?}, rest starts {rest:?}");
    let digits: String = rest[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or_else(|_| panic!("line number after {phrase:?}"))
}

fn line_is_loop(line: &str) -> bool {
    let code = code_portion(line).trim();
    code == "loop" || code.starts_with("loop ") || code.starts_with("loop{")
}

fn next_code_line<'a>(lines: &[&'a str], after_1based: usize) -> &'a str {
    for line in lines.iter().skip(after_1based) {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") || t.starts_with("///") {
            continue;
        }
        return t;
    }
    ""
}

fn register_opt_none_sites(root: &std::path::Path) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for rel in tracked_rs_files(root) {
        let src = std::fs::read_to_string(root.join(&rel)).unwrap_or_default();
        let code = production_code(&src);
        for hit in find_calls(&code) {
            if hit.kind == Kind::RegisterOpt && !hit.is_site {
                out.push((rel.clone(), hit.line));
            }
        }
    }
    out.sort();
    out
}

/// The census's first table, shape-B loop lines, not-site rows, and the
/// `liveness_loop.rs` prose pins must match the sources. Reverting a table
/// line while leaving the shape-B spawn row alone used to stay green.
#[test]
fn census_line_pins_match_sources() {
    let root = workspace_root();
    let census = std::fs::read_to_string(root.join(CENSUS)).unwrap_or_default();
    assert!(
        census.contains(&format!("## Production sites ({PIN})")),
        "production-sites heading must name the pin {PIN}"
    );

    let (sites, _) = scan_workspace(&root);
    let mut scanned: Vec<(String, usize, String)> =
        sites.iter().map(|s| (s.path.clone(), s.line, s.kind.as_str().to_string())).collect();
    scanned.sort();
    let mut table: Vec<(String, usize, String)> =
        markdown_table(&section_body(&census, "Production sites"))
            .into_iter()
            .map(|cells| {
                assert!(cells.len() >= 4, "production row {cells:?}");
                let line: usize =
                    cells[1].parse().unwrap_or_else(|_| panic!("line {:?}", cells[1]));
                (cells[0].clone(), line, cells[3].clone())
            })
            .collect();
    table.sort();
    assert_eq!(
        table,
        scanned,
        "production-sites table (file, line, call) must match scanned executor sites.\n\
         table:\n  {}\nscanned:\n  {}",
        table.iter().map(|r| format!("{}:{} {}", r.0, r.1, r.2)).collect::<Vec<_>>().join("\n  "),
        scanned.iter().map(|r| format!("{}:{} {}", r.0, r.1, r.2)).collect::<Vec<_>>().join("\n  ")
    );

    for cells in markdown_table(&section_body(&census, "Shape B loop sites")) {
        assert!(cells.len() >= 3, "shape-B row {cells:?}");
        let (path, line) =
            split_path_line(&cells[2]).unwrap_or_else(|| panic!("loop spec {:?}", cells[2]));
        let src = std::fs::read_to_string(root.join(&path)).unwrap_or_default();
        let text = src.lines().nth(line - 1).unwrap_or("");
        assert!(
            line_is_loop(text),
            "{path}:{line} is not a `loop` (shape-B loop column): {text:?}"
        );
    }

    let mut not_sites: Vec<(String, usize)> = markdown_table(&section_body(&census, "Not sites"))
        .into_iter()
        .map(|cells| {
            assert!(cells.len() >= 2, "not-site row {cells:?}");
            let line: usize = cells[1].parse().unwrap_or_else(|_| panic!("line {:?}", cells[1]));
            (cells[0].clone(), line)
        })
        .collect();
    not_sites.sort();
    let scanned_none = register_opt_none_sites(&root);
    assert_eq!(
        not_sites, scanned_none,
        "not-site table must match production register_opt(..., None) calls.\n\
         table: {not_sites:?}\nscanned: {scanned_none:?}"
    );

    let prose = section_body(&census, "liveness_loop.rs");
    let method_line = cite_after(&prose, "method-level `#[cfg(test)]` at ");
    let inner_line = cite_after(&prose, "inner `#[cfg(test)]` at ");
    let module_line = cite_after(&prose, "column-0 module attribute is at ");
    let spawn_line = cite_after(&prose, "production spawn is ");
    assert_eq!(
        cite_after(&prose, "method-level attribute at "),
        method_line,
        "truncate sentence must cite the same method-level attribute"
    );
    assert_eq!(
        cite_after(&prose, "hides "),
        spawn_line,
        "truncate sentence must cite the production spawn"
    );

    let src = std::fs::read_to_string(root.join("crates/rvc/src/liveness_loop.rs")).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    assert_eq!(lines[method_line - 1].trim(), "#[cfg(test)]", "method-level pin");
    assert!(!is_column0_cfg_test(lines[method_line - 1]), "method-level attribute is indented");
    let method_next = next_code_line(&lines, method_line);
    assert!(
        method_next.contains("fn "),
        "method-level #[cfg(test)] at {method_line} must sit on a function, next is {method_next:?}"
    );
    assert_eq!(lines[inner_line - 1].trim(), "#[cfg(test)]", "inner pin");
    assert!(!is_column0_cfg_test(lines[inner_line - 1]), "inner attribute is indented");
    let inner_next = next_code_line(&lines, inner_line);
    assert!(
        !inner_next.contains("fn "),
        "inner #[cfg(test)] at {inner_line} is not a method attribute, next is {inner_next:?}"
    );
    assert!(is_column0_cfg_test(lines[module_line - 1]), "column-0 module attribute");
    assert!(
        cfg_test_followed_by_mod(&lines, module_line - 1),
        "column-0 attribute must be followed by mod"
    );
    assert!(
        code_portion(lines[spawn_line - 1]).contains("executor.spawn"),
        "production spawn line {spawn_line}: {:?}",
        lines[spawn_line - 1]
    );
    assert!(method_line < spawn_line && inner_line < spawn_line && spawn_line < module_line);
    assert_eq!(
        first_bare_cfg_test_line(&lines),
        Some(method_line),
        "the first bare #[cfg(test)] is the method-level pin"
    );
}

// ---------------------------------------------------------------------------
// bn-manager census: (file, enclosing item), lexer tokens only
// ---------------------------------------------------------------------------

fn tracked_bn_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["-c", "core.quotePath=false", "ls-files", "-z", "--", "crates/bn-manager/**/*.rs"])
        .current_dir(root)
        .output()
        .map_err(|err| format!("git ls-files: {err}"))?;
    if !output.status.success() {
        return Err(format!("git ls-files failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8(raw.to_vec())
            .map_err(|_| format!("non-utf8 bn-manager path: {}", String::from_utf8_lossy(raw)))?;
        if path.ends_with(".rs") && !path.contains("/tests/") {
            files.push(path);
        }
    }
    Ok(files)
}

fn lit_unterminated(kind: LiteralKind) -> Option<bool> {
    match kind {
        LiteralKind::Char { terminated }
        | LiteralKind::Byte { terminated }
        | LiteralKind::Str { terminated }
        | LiteralKind::ByteStr { terminated }
        | LiteralKind::CStr { terminated } => Some(!terminated),
        LiteralKind::RawStr { n_hashes }
        | LiteralKind::RawByteStr { n_hashes }
        | LiteralKind::RawCStr { n_hashes } => Some(n_hashes.is_none()),
        LiteralKind::Int { .. } | LiteralKind::Float { .. } => None,
    }
}

/// Lexer tokens, or why the file cannot be trusted.
///
/// Spans come from the lexer. A length that is not a char boundary is an
/// error, not a slice. Comment and string tokens are masked; a disagreement
/// with [`non_code_spans`] fails the file.
fn lex_file(src: &str) -> Result<Vec<(usize, usize, TokenKind)>, String> {
    let first = src.lines().next().unwrap_or("");
    if first.starts_with("#!") && !first.starts_with("#![") {
        return Err("shebang".to_string());
    }
    let mut pos = 0usize;
    let mut toks = Vec::new();
    let mut masked = Vec::new();
    for tok in tokenize(src, FrontmatterAllowed::No) {
        let len = tok.len as usize;
        let end = pos.saturating_add(len);
        if len == 0 || end > src.len() || !src.is_char_boundary(end) {
            return Err("token stream broke".to_string());
        }
        let (mask, bad) = match tok.kind {
            TokenKind::LineComment { .. } => (true, false),
            TokenKind::BlockComment { terminated, .. } => (true, !terminated),
            TokenKind::Unknown
            | TokenKind::InvalidIdent
            | TokenKind::GuardedStrPrefix
            | TokenKind::UnknownPrefix
            | TokenKind::UnknownPrefixLifetime => (false, true),
            TokenKind::Literal { kind, .. } => match lit_unterminated(kind) {
                Some(bad) => (true, bad),
                None => (false, false),
            },
            _ => (false, false),
        };
        if bad {
            return Err("unterminated or unknown token".to_string());
        }
        if mask {
            masked.push((pos, end));
        }
        toks.push((pos, end, tok.kind));
        pos = end;
    }
    if pos != src.len() {
        return Err("token stream did not cover the file".to_string());
    }
    if masked != non_code_spans(src) {
        return Err("lexer mask disagreed".to_string());
    }
    Ok(toks)
}

fn is_gap(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Whitespace | TokenKind::LineComment { .. } | TokenKind::BlockComment { .. }
    )
}

fn next_solid(toks: &[(usize, usize, TokenKind)], mut i: usize) -> usize {
    while i < toks.len() && is_gap(toks[i].2) {
        i += 1;
    }
    i
}

fn word_is(src: &str, toks: &[(usize, usize, TokenKind)], i: usize, want: &str) -> bool {
    toks.get(i)
        .is_some_and(|tok| matches!(tok.2, TokenKind::Ident) && src.get(tok.0..tok.1) == Some(want))
}

/// `Ident` or `RawIdent` with the `r#` prefix removed. Keywords stay `Ident` only.
fn call_word<'a>(src: &'a str, tok: &(usize, usize, TokenKind)) -> Option<&'a str> {
    let text = src.get(tok.0..tok.1)?;
    match tok.2 {
        TokenKind::Ident => Some(text),
        TokenKind::RawIdent => text.strip_prefix("r#").filter(|rest| !rest.is_empty()),
        _ => None,
    }
}

/// Byte offset of each `tokio::spawn(` call. Comments and strings are not idents.
fn tokio_spawn_calls(src: &str, toks: &[(usize, usize, TokenKind)]) -> Vec<usize> {
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if call_word(src, &toks[i]) != Some("tokio") {
            continue;
        }
        let colon = next_solid(toks, i + 1);
        let colon2 = next_solid(toks, colon + 1);
        let name = next_solid(toks, colon2 + 1);
        let open = next_solid(toks, name + 1);
        if open < toks.len()
            && matches!(toks[colon].2, TokenKind::Colon)
            && matches!(toks[colon2].2, TokenKind::Colon)
            && toks.get(name).is_some_and(|tok| call_word(src, tok) == Some("spawn"))
            && matches!(toks[open].2, TokenKind::OpenParen)
        {
            out.push(toks[i].0);
        }
    }
    out
}

fn line_starts(src: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    starts.push(0);
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn line_text_at(src: &str, starts: &[usize], at: usize) -> String {
    let line = starts.partition_point(|start| *start <= at);
    let from = starts[line - 1];
    let to = starts.get(line).copied().unwrap_or(src.len());
    src[from..to].trim().to_string()
}

fn cfg_test_attr_end(src: &str, toks: &[(usize, usize, TokenKind)], i: usize) -> Option<usize> {
    if !matches!(toks.get(i)?.2, TokenKind::Pound) {
        return None;
    }
    let bracket = next_solid(toks, i + 1);
    if !matches!(toks.get(bracket)?.2, TokenKind::OpenBracket) {
        return None;
    }
    let cfg = next_solid(toks, bracket + 1);
    if !word_is(src, toks, cfg, "cfg") {
        return None;
    }
    let open = next_solid(toks, cfg + 1);
    if !matches!(toks.get(open)?.2, TokenKind::OpenParen) {
        return None;
    }
    let test = next_solid(toks, open + 1);
    if !word_is(src, toks, test, "test") {
        return None;
    }
    let close = next_solid(toks, test + 1);
    if !matches!(toks.get(close)?.2, TokenKind::CloseParen) {
        return None;
    }
    let end = next_solid(toks, close + 1);
    if !matches!(toks.get(end)?.2, TokenKind::CloseBracket) {
        return None;
    }
    Some(end + 1)
}

fn skip_until(
    toks: &[(usize, usize, TokenKind)],
    from: usize,
    open: TokenKind,
    close: TokenKind,
) -> Option<usize> {
    let mut depth = 0usize;
    for (n, tok) in toks.iter().enumerate().skip(from) {
        if tok.2 == open {
            depth += 1;
        } else if tok.2 == close {
            depth -= 1;
            if depth == 0 {
                return Some(n + 1);
            }
        }
    }
    None
}

fn mod_after(src: &str, toks: &[(usize, usize, TokenKind)], mut i: usize) -> Option<usize> {
    loop {
        i = next_solid(toks, i);
        if matches!(toks.get(i)?.2, TokenKind::Pound) {
            let bracket = next_solid(toks, i + 1);
            if !matches!(toks.get(bracket)?.2, TokenKind::OpenBracket) {
                return None;
            }
            i = skip_until(toks, bracket, TokenKind::OpenBracket, TokenKind::CloseBracket)?;
            continue;
        }
        break;
    }
    if word_is(src, toks, i, "pub") {
        let next = next_solid(toks, i + 1);
        if matches!(toks.get(next).map(|tok| tok.2), Some(TokenKind::OpenParen)) {
            i = next_solid(
                toks,
                skip_until(toks, next, TokenKind::OpenParen, TokenKind::CloseParen)?,
            );
        } else {
            i = next;
        }
    }
    word_is(src, toks, i, "mod").then_some(i)
}

fn module_end(toks: &[(usize, usize, TokenKind)], mod_i: usize) -> Option<usize> {
    let name = next_solid(toks, mod_i + 1);
    toks.get(name)?;
    let after = next_solid(toks, name + 1);
    match toks.get(after).map(|tok| tok.2) {
        Some(TokenKind::Semi) => Some(toks[after].1),
        Some(TokenKind::OpenBrace) => {
            skip_until(toks, after, TokenKind::OpenBrace, TokenKind::CloseBrace)
                .map(|idx| toks[idx - 1].1)
        }
        _ => None,
    }
}

/// Byte where the test module's `#[cfg(test)]` starts, or an error when code follows it.
fn bn_test_cut(src: &str, toks: &[(usize, usize, TokenKind)]) -> Result<Option<usize>, String> {
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i].2, TokenKind::Pound) {
            if let Some(after) = cfg_test_attr_end(src, toks, i) {
                if let Some(mod_i) = mod_after(src, toks, after) {
                    let end = module_end(toks, mod_i).ok_or("unclosed test module")?;
                    let follows = toks.iter().any(|tok| tok.0 >= end && !is_gap(tok.2));
                    if follows {
                        return Err("production code follows the test module".to_string());
                    }
                    return Ok(Some(toks[i].0));
                }
            }
        }
        i += 1;
    }
    Ok(None)
}

#[derive(Debug)]
struct BnHit {
    file: String,
    item: String,
    fp: String,
}

#[derive(Debug)]
struct BnRow {
    file: String,
    item: String,
    raw: String,
}

fn bn_hits(files: &[(String, String)]) -> Result<Vec<BnHit>, String> {
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    for (path, src) in files {
        let toks = match lex_file(src) {
            Ok(toks) => toks,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        let items = match SourceItems::parse(src) {
            Ok(items) => items,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        let starts = line_starts(src);
        let cut = match bn_test_cut(src, &toks) {
            Ok(cut) => cut,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        for at in tokio_spawn_calls(src, &toks) {
            if cut.is_some_and(|cut| at >= cut) {
                continue;
            }
            let fp = line_text_at(src, &starts, at);
            match items.enclosing(at) {
                Err(err) => errors.push(format!("row {path} fingerprint {fp:?}: {err}")),
                Ok(id) if id.as_str().is_empty() || id.as_str() == "<module>" => {
                    errors.push(format!("row {path} fingerprint {fp:?}: refusing <module>"));
                }
                Ok(id) => {
                    hits.push(BnHit { file: path.clone(), item: id.as_str().to_string(), fp })
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(hits)
    } else {
        Err(errors.join("\n"))
    }
}

fn is_line_number(cell: &str) -> bool {
    !cell.is_empty() && cell.chars().all(|c| c.is_ascii_digit())
}

fn parse_bn_rows(section: &str) -> Result<Vec<BnRow>, String> {
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    for cells in markdown_table(section) {
        let raw = cells.join(" | ");
        if cells.len() < 3 {
            errors.push(format!("bn-manager row needs file, item, call: {raw}"));
            continue;
        }
        if is_line_number(&cells[1]) {
            errors.push(format!("bn-manager row uses a line number as the item: {raw}"));
            continue;
        }
        if cells[2] != "tokio::spawn" {
            errors.push(format!("bn-manager row call must be tokio::spawn: {raw}"));
            continue;
        }
        rows.push(BnRow { file: cells[0].clone(), item: cells[1].clone(), raw });
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors.join("\n"))
    }
}

fn reconcile_bn(rows: &[BnRow], hits: &[BnHit]) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut expected: HashMap<String, String> = HashMap::new();
    for row in rows {
        let detail = format!("bn-manager {} item `{}` ({})", row.file, row.item, row.raw);
        let key = format!("{}\n{}", row.file, row.item);
        if expected.insert(key, detail.clone()).is_some() {
            errors.push(format!("duplicate {detail}"));
        }
    }
    let mut seen: HashMap<String, String> = HashMap::new();
    for hit in hits {
        let detail =
            format!("bn-manager {} item `{}` fingerprint {:?}", hit.file, hit.item, hit.fp);
        let key = format!("{}\n{}", hit.file, hit.item);
        if let Some(prev) = seen.insert(key.clone(), detail.clone()) {
            errors.push(format!("duplicate hit {detail}; also {prev}"));
            continue;
        }
        if !expected.contains_key(&key) {
            errors.push(format!("extra {detail}"));
        }
    }
    for (key, detail) in &expected {
        if !seen.contains_key(key) {
            errors.push(format!("missing {detail}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn bn_section_matches(census: &str, files: &[(String, String)]) -> Result<(), String> {
    let rows = parse_bn_rows(&section_body(census, "bn-manager raw"))?;
    reconcile_bn(&rows, &bn_hits(files)?)
}

fn check_bn(rows: &[(&str, &str)], files: &[(&str, &str)]) -> Result<(), String> {
    let owned: Vec<(String, String)> =
        files.iter().map(|(path, src)| ((*path).to_string(), (*src).to_string())).collect();
    let content: Vec<BnRow> = rows
        .iter()
        .map(|(file, item)| BnRow {
            file: (*file).to_string(),
            item: (*item).to_string(),
            raw: format!("{file} {item}"),
        })
        .collect();
    reconcile_bn(&content, &bn_hits(&owned)?)
}

fn load_bn(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for rel in tracked_bn_files(root)? {
        let src =
            std::fs::read_to_string(root.join(&rel)).map_err(|err| format!("row {rel}: {err}"))?;
        out.push((rel, src));
    }
    Ok(out)
}

#[test]
fn census_bn_manager_rows_match_sources() {
    let root = workspace_root();
    let census = std::fs::read_to_string(root.join(CENSUS)).unwrap();
    let files = load_bn(&root).unwrap_or_else(|err| panic!("{err}"));
    bn_section_matches(&census, &files).unwrap_or_else(|err| panic!("{err}"));
}

#[test]
fn census_accepts_a_spawn_inside_a_closure() {
    let src = "fn outer() {\n    let _ = || { tokio::spawn(async {}); };\n}\n";
    check_bn(&[("a.rs", "outer")], &[("a.rs", src)]).unwrap();
    let err = check_bn(&[("a.rs", "<closure>")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("<closure>") && err.contains("outer"), "{err}");
}

#[test]
fn census_accepts_a_spawn_inside_a_macro() {
    let src = "macro_rules! m {\n    () => { tokio::spawn(async {}); };\n}\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_accepts_a_spawn_inside_a_nested_mod() {
    let src = "mod outer {\n    fn inner() {\n        tokio::spawn(async {});\n    }\n}\n";
    check_bn(&[("a.rs", "outer::inner")], &[("a.rs", src)]).unwrap();
    let err = check_bn(&[("a.rs", "inner")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("inner") && err.contains("outer::inner"), "{err}");
}

#[test]
fn census_accepts_spaced_tokio_spawn_tokens() {
    let src = "fn item() {\n    tokio /* gap */ :: spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_tokio_spawn_in_a_comment_or_string() {
    let src = "fn item() {\n    // tokio::spawn(async {});\n    let _ = \"tokio::spawn\";\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_a_spawn_inside_a_cfg_test_module() {
    let src = "\
fn item() {\n\
    tokio::spawn(async {});\n\
}\n\
#[cfg(test)]\n\
mod tests {\n\
    fn hidden() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_a_use_of_tokio_spawn() {
    let src = "use tokio::spawn;\nfn item() {\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_rejects_a_row_whose_item_is_gone() {
    let src = "fn now() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "gone")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("gone") && err.contains("now"), "{err}");
}

#[test]
fn census_rejects_a_duplicated_row() {
    let src = "fn item() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item"), ("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("duplicate"), "{err}");
    let twin = "fn item() {\n    tokio::spawn(async {});\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", twin)]).unwrap_err();
    assert!(err.contains("duplicate hit"), "{err}");
}

#[test]
fn census_rejects_a_row_moved_to_another_file() {
    let src = "fn item() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("b.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("b.rs"), "{err}");
}

#[test]
fn census_rejects_an_ambiguous_item() {
    let src = "fn f() {\n    tokio::spawn(async {});\n}\nfn f() {}\n";
    let err = check_bn(&[("a.rs", "f")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("ambiguous"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_rejects_an_untrusted_file() {
    let src = "fn f() {\n    tokio::spawn(async {});\n    let _ = \"unterminated;\n}\n";
    let err = check_bn(&[("a.rs", "f")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("unclosed") || err.contains("unterminated"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_rejects_a_shebang_file() {
    let src = "#!/usr/bin/env rust\nfn item() { tokio::spawn(async {}); }\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("shebang"), "{err}");
}

#[test]
fn census_rejects_a_module_level_spawn() {
    let src = "tokio::spawn(async {});\n";
    let err = check_bn(&[("a.rs", "<module>")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("refusing <module>"), "{err}");
}

#[test]
fn census_rejects_a_line_numbered_item() {
    let section = "\
| File | Item | Call |\n\
|---|---|---|\n\
| `crates/bn-manager/src/manager.rs` | 785 | `tokio::spawn` in `start_sse` |\n\
";
    let err = parse_bn_rows(section).unwrap_err();
    assert!(
        err.contains("line number") && err.contains("785") && err.contains("start_sse"),
        "{err}"
    );
}

#[test]
fn census_rejects_a_production_multibyte_char_literal() {
    let src = "fn item() {\n    let _ = '€';\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("lexer mask disagreed"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_accepts_a_multibyte_char_inside_a_string() {
    let src = "fn item() {\n    let _ = \"€\";\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

fn init_bn_repo(files: &[(&str, &str)]) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "bn-census-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("crates/bn-manager/src")).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).current_dir(&root).output().expect("git");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    git(&["init", "-q"]);
    for (rel, src) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, src).unwrap();
    }
    git(&["add", "-A"]);
    root
}

#[test]
fn census_reads_non_ascii_and_quoted_tracked_paths() {
    let cafe = "crates/bn-manager/src/café.rs";
    let messy = "crates/bn-manager/src/q\"b\\c\td.rs";
    let body = "fn h() { tokio::spawn(async {}); }\n";
    let root = init_bn_repo(&[(cafe, body), (messy, body)]);
    let hits = bn_hits(&load_bn(&root).unwrap()).unwrap();
    assert!(hits.iter().any(|hit| hit.file.contains("café")), "dropped non-ascii: {hits:?}");
    assert!(
        hits.iter().any(|hit| hit.file.contains('"')
            && hit.file.contains('\\')
            && hit.file.contains('\t')),
        "dropped quoted path: {hits:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_names_a_non_utf8_tracked_path() {
    use std::os::unix::ffi::OsStringExt;
    let root = init_bn_repo(&[]);
    let mut name = b"bad".to_vec();
    name.push(0xff);
    name.extend(b".rs");
    let path = root.join("crates/bn-manager/src").join(std::ffi::OsString::from_vec(name));
    std::fs::write(&path, "fn h() { tokio::spawn(async {}); }\n").unwrap();
    let out = Command::new("git").args(["add", "-A"]).current_dir(&root).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let err = tracked_bn_files(&root).unwrap_err();
    assert!(err.contains("non-utf8") && err.contains("bad"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_names_an_unreadable_tracked_file() {
    let rel = "crates/bn-manager/src/gone.rs";
    let root = init_bn_repo(&[(rel, "fn h() { tokio::spawn(async {}); }\n")]);
    std::fs::remove_file(root.join(rel)).unwrap();
    let err = load_bn(&root).unwrap_err();
    assert!(err.contains(rel), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_accepts_r_hash_tokio_spawn_inside_a_macro() {
    let src = "macro_rules! m { () => { r#tokio::spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
    let both = "macro_rules! m { () => { r#tokio::r#spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", both)]).unwrap();
}

#[test]
fn census_accepts_r_hash_spawn_inside_a_macro() {
    let src = "macro_rules! m { () => { tokio::r#spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_keeps_a_spawn_after_a_raw_string_cfg_decoy() {
    let src = "\
fn item() {\n\
    let _ = r#\"\n\
#[cfg(test)]\n\
mod x\n\
\"#;\n\
    tokio::spawn(async {});\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_keeps_a_spawn_after_a_block_comment_cfg_decoy() {
    let src = "\
fn item() {\n\
    /*\n\
#[cfg(test)]\n\
mod x\n\
*/\n\
    tokio::spawn(async {});\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_rejects_production_code_after_the_test_module() {
    let braced = "\
fn item() {\n\
    tokio::spawn(async {});\n\
}\n\
#[cfg(test)]\n\
mod tests {\n\
    fn hidden() { tokio::spawn(async {}); }\n\
}\n\
fn after() {}\n\
";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", braced)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
    let semi = "fn item() { tokio::spawn(async {}); }\n#[cfg(test)] mod tests;\nfn after() {}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", semi)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn census_keeps_a_spawn_inside_a_non_test_cfg_module() {
    let unix = "\
fn item() { tokio::spawn(async {}); }\n\
#[cfg(unix)]\n\
mod p {\n\
    pub fn g() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item"), ("a.rs", "p::g")], &[("a.rs", unix)]).unwrap();
    let not_test = "\
fn item() { tokio::spawn(async {}); }\n\
#[cfg(not(test))]\n\
mod p {\n\
    pub fn g() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item"), ("a.rs", "p::g")], &[("a.rs", not_test)]).unwrap();
}
