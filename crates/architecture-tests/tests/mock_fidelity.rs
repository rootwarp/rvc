//! G-8 / ARCH-3g: mock-fidelity scan of `with_get_block_root` stubs.
//!
//! No `with_get_block_root` closure in `crates/**` may:
//!
//! * **(i)** return `Ok(` on every path (`Ok` present, `Err` absent) — an
//!   unconditional-success stub, including head-vs-else that still `Ok`s every
//!   slot-qualified id (pre-3f site 1);
//! * **(ii)** return `Err(` on every path as a 404 stand-in — an error-for-everything stub.
//!
//! Failures name file, line, and the call site, and state the remedy:
//! `use MockBeaconNodeClient::with_slot_aware_block_root`.
//!
//! After ARCH-3f the original seven fixtures are slot-aware (`with_slot_aware_block_root`).
//! Remaining `with_get_block_root` sites either branch on the slot id or inject a **transport**
//! `HttpError` (ARCH-3f site 2 + two empty-slot harnesses). Those transport injectors are not
//! 404 stand-ins and must stay green (3f: do not treat the transport helper as a 404).
//!
//! The builder definition lives in [`MOCK_BUILDER_PATH`] and is excluded by exact path.
//!
//! Non-vacuity: the walk must observe at least [`MIN_SITES`] `with_get_block_root(` call
//! sites, or a rename of the builder silently turns the gate into a no-op.
//!
//! RED is demonstrated on **synthetic** strings (ADR-012: do not merge a failing workspace
//! scan). No external dependency (Phase-1 rule P6): brace-aware extraction in the
//! `kat_policy.rs` idiom.
//!
//! Cross-ref: architecture §6 G-8; plan issue ARCH-3g / VD-36.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Builder definition (and its unit tests) — not a stub call site.
const MOCK_BUILDER_PATH: &str = "crates/bn-manager/src/mock.rs";

/// This gate's own sources mention the needle inside synthetic fixtures.
const THIS_GATE: &str = "crates/architecture-tests/tests/mock_fidelity.rs";

/// Floor at ARCH-3g land (seven remaining `with_get_block_root` call sites after 3f,
/// excluding [`MOCK_BUILDER_PATH`]). A future rename of the builder must not go silent.
const MIN_SITES: usize = 7;

const NEEDLE: &str = "with_get_block_root(";

const REMEDY: &str = "use `MockBeaconNodeClient::with_slot_aware_block_root`";

// ---------------------------------------------------------------------------
// Workspace walk
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
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Every `*.rs` under `crates/**` (src + tests + benches + examples).
fn crates_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&root.join("crates"), &mut out);
    out
}

fn is_excluded(rel: &str) -> bool {
    rel == MOCK_BUILDER_PATH || rel == THIS_GATE
}

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn line_at(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

fn line_start(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

fn line_end(src: &str, byte: usize) -> usize {
    src[byte.min(src.len())..].find('\n').map(|i| byte + i).unwrap_or(src.len())
}

/// Best-effort: drop `//` line comments outside of strings (same class as `raw_spawn`).
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
    t.starts_with("//") || t.starts_with("///") || t.starts_with("//!")
}

fn strip_line_comments(src: &str) -> String {
    src.lines().map(code_portion).collect::<Vec<_>>().join("\n")
}

fn has_ident(src: &str, name: &str) -> bool {
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(rel) = src[from..].find(name) {
        let at = from + rel;
        let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
        let after = at + name.len();
        let after_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + name.len();
    }
    false
}

/// `Ok(` / `Err(` — identifier-bounded, optional whitespace before `(`.
fn has_ctor(src: &str, name: &str) -> bool {
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(rel) = src[from..].find(name) {
        let at = from + rel;
        let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
        let after = at + name.len();
        let not_prefix = after >= bytes.len() || !is_ident_char(bytes[after]);
        if before_ok && not_prefix && src[after..].trim_start().starts_with('(') {
            return true;
        }
        from = at + name.len();
    }
    false
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    while i < src.len() && src.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Brace-aware `{ … }` span. `open` must point at `{`. Returns exclusive end.
fn close_brace(src: &str, open: usize) -> Option<usize> {
    if open >= src.len() || src.as_bytes()[open] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    for (k, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Closure extraction
// ---------------------------------------------------------------------------

struct Closure {
    param: String,
    body: String,
}

/// Parse `|param| { body }`, `move |param| { body }`, or expression-bodied
/// `|param| Ok(...)` / `|param| Err(...)` (rustfmt Max one-liners) starting at `i`.
fn parse_closure(src: &str, mut i: usize) -> Option<Closure> {
    i = skip_ws(src, i);
    if src[i..].starts_with("move") {
        let after = i + 4;
        if after < src.len() && is_ident_char(src.as_bytes()[after]) {
            return None;
        }
        i = skip_ws(src, after);
    }
    if i >= src.len() || src.as_bytes()[i] != b'|' {
        return None;
    }
    let param_start = i + 1;
    let rel = src[param_start..].find('|')?;
    let params = src[param_start..param_start + rel].trim();
    let param = first_param_name(params);
    i = skip_ws(src, param_start + rel + 1);
    if i >= src.len() {
        return None;
    }
    if src.as_bytes()[i] == b'{' {
        let end = close_brace(src, i)?;
        let body = src[i + 1..end - 1].trim().to_string();
        return Some(Closure { param, body });
    }
    // Expression body: run until the enclosing `with_get_block_root(` `)`, or
    // EOF when the closure sits inside a `{ let …; |…| expr }` wrapper.
    let end = close_expr(src, i)?;
    let body = src[i..end].trim().trim_end_matches(',').trim().to_string();
    if body.is_empty() {
        return None;
    }
    Some(Closure { param, body })
}

/// Exclusive end of an expression body inside `with_get_block_root( … )`.
/// Starts at depth 1 (already inside the call); the `)` that returns to 0 is
/// the call closer and is not part of the body. EOF at depth > 0 is a wrapper.
fn close_expr(src: &str, start: usize) -> Option<usize> {
    let mut depth = 1i32;
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
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
    if i > start {
        Some(i)
    } else {
        None
    }
}

/// `|block_id|` / `|block_id: String|` / `|_block_id|` / `|_|`.
fn first_param_name(params: &str) -> String {
    let token = params.split(',').next().unwrap_or(params).trim();
    let name = token.split(':').next().unwrap_or(token).trim();
    if name.is_empty() {
        "_".to_string()
    } else {
        name.to_string()
    }
}

/// Closure at a `with_get_block_root(` argument: bare `|…| {…}`, `move |…| {…}`,
/// or a block wrapper `{ let …; move |…| {…} }`.
fn extract_call_closure(src: &str, open_paren: usize) -> Option<Closure> {
    let i = skip_ws(src, open_paren + 1);
    if i >= src.len() {
        return None;
    }
    if src.as_bytes()[i] == b'{' {
        let end = close_brace(src, i)?;
        let inner = &src[i + 1..end - 1];
        // First closure inside the wrapper (captures, then `move |…|`).
        for j in 0..inner.len() {
            if let Some(c) = parse_closure(inner, j) {
                return Some(c);
            }
        }
        return None;
    }
    parse_closure(src, i)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Honest,
    UnconditionalOk,
    ErrorForEverything,
}

fn looks_like_404(body: &str) -> bool {
    body.contains("404")
        || has_ident(body, "not_found")
        || has_ident(body, "NotFound")
        || body.contains("not found")
        || body.contains("Block not found")
}

/// Clause (ii): `Err(` on every path, standing in for a 404.
///
/// A transport-only `HttpError` injector (ARCH-3f site 2, empty-slot harnesses) is
/// not a 404 stand-in unless the body also names a 404.
fn is_404_standin(body: &str) -> bool {
    let err = has_ctor(body, "Err");
    let ok = has_ctor(body, "Ok");
    if !err || ok {
        return false;
    }
    if has_ident(body, "HttpError") && !looks_like_404(body) {
        return false;
    }
    true
}

fn classify(_param: &str, body: &str) -> Class {
    let cleaned = strip_line_comments(body);
    let body = cleaned.as_str();
    // (i) always-Ok — every path succeeds, even if the body branches on "head".
    if has_ctor(body, "Ok") && !has_ctor(body, "Err") {
        return Class::UnconditionalOk;
    }
    if is_404_standin(body) {
        return Class::ErrorForEverything;
    }
    Class::Honest
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundStub {
    rel_path: String,
    line: usize,
    site: String,
    class: Class,
}

impl FoundStub {
    fn violation_message(&self) -> Option<String> {
        let kind = match self.class {
            Class::Honest => return None,
            Class::UnconditionalOk => "unconditional Ok — every path returns Ok",
            Class::ErrorForEverything => "error-for-everything standing in for 404",
        };
        Some(format!("{}:{}: {}: {}; {REMEDY}", self.rel_path, self.line, self.site, kind))
    }
}

fn ident_boundary_before(src: &str, at: usize) -> bool {
    at == 0 || !is_ident_char(src.as_bytes()[at - 1])
}

/// All `with_get_block_root(` closures in `src` (synthetic or real).
fn scan_source(rel: &str, src: &str) -> Vec<FoundStub> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel_off) = src[from..].find(NEEDLE) {
        let at = from + rel_off;
        from = at + NEEDLE.len();
        if !ident_boundary_before(src, at) {
            continue;
        }
        let ls = line_start(src, at);
        let le = line_end(src, at);
        let line_text = &src[ls..le];
        if is_comment_only_line(line_text) {
            continue;
        }
        // Needle after `//` on this line is a comment mention, not a call.
        let code = code_portion(line_text);
        if at - ls >= code.len() {
            continue;
        }
        let Some(closure) = extract_call_closure(src, at + "with_get_block_root".len()) else {
            continue;
        };
        let class = classify(&closure.param, &closure.body);
        out.push(FoundStub {
            rel_path: rel.to_string(),
            line: line_at(src, at),
            site: line_text.trim().to_string(),
            class,
        });
    }
    out
}

struct WorkspaceScan {
    sites: Vec<FoundStub>,
    files: usize,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = crates_rs_files(&root);
    let mut sites = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if is_excluded(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        sites.extend(scan_source(&rel, &src));
    }
    WorkspaceScan { sites, files: files.len() }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn g8_no_dishonest_block_root_stubs() {
    let scan = scan_workspace();
    assert!(
        scan.files > 100,
        "scanned only {} files under crates/; workspace walk likely broke",
        scan.files
    );
    assert!(
        scan.sites.len() >= MIN_SITES,
        "found only {} with_get_block_root site(s); matcher or walk likely broke (need >= {MIN_SITES})",
        scan.sites.len()
    );
    assert!(
        scan.sites.iter().all(|s| s.rel_path != MOCK_BUILDER_PATH),
        "builder definition at {MOCK_BUILDER_PATH} must be excluded by exact path"
    );

    let mut violations: Vec<String> =
        scan.sites.iter().filter_map(FoundStub::violation_message).collect();
    violations.sort();
    assert!(
        violations.is_empty(),
        "G-8 mock-fidelity (ARCH-3g / VD-36): with_get_block_root stubs must not Ok \
         unconditionally and must not Err on every path as a 404 stand-in. {REMEDY}.\n\
         Offenders:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Matcher unit tests (synthetic RED / GREEN)
// ---------------------------------------------------------------------------

#[test]
fn test_scanner_flags_a_synthetic_unconditional_ok_stub() {
    let src = r#"
        fn fixture() {
            MockBeaconNodeClient::new().with_get_block_root(|_block_id| {
                Ok(BlockRootResponse { data: BlockRootData { root: "0xab".into() } })
            });
        }
    "#;
    let found = scan_source("crates/rvc/src/orchestrator/fixture.rs", src);
    assert_eq!(found.len(), 1, "expected one site, got {found:?}");
    assert_eq!(found[0].class, Class::UnconditionalOk);
    assert_eq!(found[0].rel_path, "crates/rvc/src/orchestrator/fixture.rs");
    let msg = found[0].violation_message().expect("unconditional Ok must be a violation");
    assert!(
        msg.contains("crates/rvc/src/orchestrator/fixture.rs:"),
        "failure must name file; got {msg}"
    );
    assert!(msg.contains(&format!(":{}:", found[0].line)), "failure must name line; got {msg}");
    assert!(msg.contains("with_get_block_root"), "failure must name the site; got {msg}");
    assert!(
        msg.contains("MockBeaconNodeClient::with_slot_aware_block_root"),
        "failure must state the remedy; got {msg}"
    );

    // F1: rustfmt Max leaves `(|_| Ok(...))` as a one-liner — must not be dropped.
    let oneline = "MockBeaconNodeClient::new().with_get_block_root(|_| Ok(root()));\n";
    let found = scan_source("crates/rvc/src/orchestrator/fixture.rs", oneline);
    assert_eq!(found.len(), 1, "expression-bodied Ok must be a site, got {found:?}");
    assert_eq!(found[0].class, Class::UnconditionalOk);

    // F2: pre-3f site 1 — head-vs-else still Ok on every path.
    let site1 = r#"
        MockBeaconNodeClient::new().with_get_block_root(move |block_id| {
            let root = if block_id == "head" { head_root.clone() } else { slot_root.clone() };
            Ok(DataResponse { data: BlockRootData { root } })
        })
    "#;
    let found = scan_source("crates/rvc/src/orchestrator/slot_context.rs", site1);
    assert_eq!(found.len(), 1, "pre-3f site 1 must be a site, got {found:?}");
    assert_eq!(
        found[0].class,
        Class::UnconditionalOk,
        "always-Ok head-vs-else must be UnconditionalOk; got {found:?}"
    );
}

#[test]
fn test_scanner_accepts_a_synthetic_slot_aware_stub() {
    let src = r#"
        fn fixture(head_slot: u64) {
            MockBeaconNodeClient::new().with_get_block_root(move |block_id| {
                if block_id == "head" || block_id == "finalized" {
                    return Ok(root());
                }
                let parsed = match block_id.parse::<u64>() {
                    Ok(s) => s,
                    Err(_) => return Err(not_found()),
                };
                if parsed >= head_slot {
                    return Err(not_found());
                }
                Ok(root())
            });
        }
    "#;
    let found = scan_source("crates/rvc/src/orchestrator/fixture.rs", src);
    assert_eq!(found.len(), 1, "expected one site, got {found:?}");
    assert_eq!(found[0].class, Class::Honest, "slot-aware stub must not be flagged; got {found:?}");
    assert!(found[0].violation_message().is_none());
}

#[test]
fn test_scanner_flags_error_for_everything() {
    let src = r#"
        fn fixture() {
            MockBeaconNodeClient::new().with_get_block_root(|_| {
                Err(BeaconError::ApiError { status: 404, message: "Block not found".into() })
            });
        }
    "#;
    let found = scan_source("crates/rvc/src/orchestrator/fixture.rs", src);
    assert_eq!(found.len(), 1, "expected one site, got {found:?}");
    assert_eq!(found[0].class, Class::ErrorForEverything);
    let msg = found[0].violation_message().expect("404-for-everything must be a violation");
    assert!(
        msg.contains("crates/rvc/src/orchestrator/fixture.rs:"),
        "failure must name file; got {msg}"
    );
    assert!(msg.contains(&format!(":{}:", found[0].line)), "failure must name line; got {msg}");
    assert!(
        msg.contains("MockBeaconNodeClient::with_slot_aware_block_root"),
        "failure must state the remedy; got {msg}"
    );

    // ARCH-3f site 2: transport HttpError for every id is not a 404 stand-in.
    let transport = r#"
        fn error_beacon() {
            MockBeaconNodeClient::new().with_get_block_root(|_| {
                Err(beacon::BeaconError::HttpError("simulated BN error".to_string()))
            });
        }
    "#;
    let t = scan_source("crates/rvc/src/orchestrator/slot_context.rs", transport);
    assert_eq!(t.len(), 1);
    assert_eq!(
        t[0].class,
        Class::Honest,
        "transport HttpError injector must stay honest; got {t:?}"
    );

    // F1: rustfmt Max leaves `(|_| Err(...))` as a one-liner — must not be dropped.
    let oneline = "MockBeaconNodeClient::new().with_get_block_root(|_| Err(not_found()));\n";
    let found = scan_source("crates/rvc/src/orchestrator/fixture.rs", oneline);
    assert_eq!(found.len(), 1, "expression-bodied Err must be a site, got {found:?}");
    assert_eq!(found[0].class, Class::ErrorForEverything);
}

#[test]
fn test_scanner_is_non_vacuous() {
    let scan = scan_workspace();
    assert!(
        scan.files > 100,
        "scanned only {} files under crates/; workspace walk likely broke",
        scan.files
    );
    assert!(
        scan.sites.len() >= MIN_SITES,
        "found only {} with_get_block_root site(s); need >= {MIN_SITES}",
        scan.sites.len()
    );
    assert!(
        scan.sites.iter().all(|s| s.rel_path != MOCK_BUILDER_PATH),
        "{MOCK_BUILDER_PATH} must be excluded by exact path"
    );
    assert!(
        scan.sites.iter().all(|s| s.rel_path != THIS_GATE),
        "{THIS_GATE} must not scan its own synthetic fixtures"
    );
}

#[test]
fn test_block_wrapper_and_move_closure_extract() {
    let src = r#"
        let beacon = MockBeaconNodeClient::new().with_get_block_root({
            let parent_hex = parent_hex.clone();
            move |block_id| {
                if block_id == slot.to_string() {
                    return Ok(curr);
                }
                Err(e)
            }
        });
    "#;
    let found = scan_source("crates/rvc/src/orchestrator/block_proposal/tests.rs", src);
    assert_eq!(found.len(), 1, "block-wrapper call must yield one site; got {found:?}");
    assert_eq!(found[0].class, Class::Honest);
}
