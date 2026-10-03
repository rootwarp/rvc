//! TRC-6c: pin production executor sites to tracing ADR-009.
//!
//! Scans **tracked** sources only:
//!
//! ```text
//! git ls-files 'crates/rvc/**/*.rs' 'bin/rvc/**/*.rs'
//! ```
//!
//! Paths containing `/tests/` are dropped. A site is `executor.spawn(`,
//! `executor.register(`, or `executor.register_opt(` whose handle argument is
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
//! in other files. The allow-list is empty. The pin is 14 (5 shape B, 9 detached,
//! shape A = 0).
//!
//! No external dependency: hand-rolled scan, same style as `raw_spawn.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Production-site pin. 5 shape B + 9 detached + shape A = 0.
const PIN: usize = 14;
const SHAPE_B_PIN: usize = 5;
const DETACHED_PIN: usize = 9;
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
                if hit.is_site {
                    hits.push(hit);
                }
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
        ("register", Kind::Register),
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
