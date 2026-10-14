//! G-7 / ARCH-P0-9 (ADR-006): audit-log scope scanner.
//!
//! Asserts **no `audit_log` call site is lexically inside a scope holding a staged
//! guard**, over both block and attestation paths. Without this gate the next
//! refactor can re-introduce the landmine and CI says nothing — the exact
//! enforced-by-discipline failure ADR-006 / C2 exist to end.
//!
//! ## Scan surface
//!
//! Every `*.rs` file under `crates/slashing/src/**` and `crates/signer/src/**`.
//! For each `audit_log(` call, walk enclosing brace scopes and fail if any
//! binding still live at that point was produced by a `stage_block(` /
//! `stage_attestation(` call (the staged-guard half of a `(staged, PendingAudit)`
//! tuple, or a bare `let guard = stage_*` binding).
//!
//! ## Non-vacuity
//!
//! `assert!(scanned_files >= 2)` and `assert!(stage_call_sites_found >= 6)` so a
//! rename or a file move turns the gate red rather than silent (2 production
//! stage sites in `scoped.rs` + 4 in `crates/signer` — VD-E2 — is the floor).
//!
//! ## Matcher limits
//!
//! Brace-aware, best-effort (same class as `kat_policy` / `config_drift`). Does
//! not model full borrowck: a deliberate greenwash that renames the guard into
//! an alias without `commit`/`discard`/`drop` may still pass. The behavioural
//! proof lives in `crates/signer/tests/audit_subscriber_deadlock.rs`; this gate
//! is the structural half.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as
//! `kat_policy.rs` / `config_drift.rs`.
//!
//! Cross-ref: architecture §6 G-7; plan issue ARCH-1c.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Workspace helpers
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

/// Scan roots for G-7: slashing + signer production sources only.
fn scan_roots(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in ["crates/slashing/src", "crates/signer/src"] {
        let dir = root.join(rel);
        if dir.is_dir() {
            collect_rs(&dir, &mut out);
        }
    }
    out.sort();
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Byte offset → 1-based line number (works on original or newline-preserving cleaned src).
fn line_at(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

// ---------------------------------------------------------------------------
// Comment / string strip (length-preserving; newlines kept for line numbers)
// ---------------------------------------------------------------------------

/// Strip `//` line comments and `/* … */` block comments; blank string / char
/// / raw-string contents. Preserve length and newlines so byte offsets map to
/// the original source lines.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Raw string: r#"..."# / r##"..."## / r"..."
        if c == b'r' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                let hashes = j - (i + 1);
                // blank `r###"`
                out.extend(std::iter::repeat_n(b' ', j - i + 1));
                i = j + 1;
                loop {
                    if i >= bytes.len() {
                        break;
                    }
                    if bytes[i] == b'"' {
                        let mut k = 0;
                        while k < hashes && i + 1 + k < bytes.len() && bytes[i + 1 + k] == b'#' {
                            k += 1;
                        }
                        if k == hashes {
                            out.extend(std::iter::repeat_n(b' ', hashes + 1)); // "###
                            i += 1 + hashes;
                            break;
                        }
                    }
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                continue;
            }
        }
        // Ordinary string
        if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i];
                out.push(if ch == b'\n' { b'\n' } else { b' ' });
                i += 1;
                if ch == b'\\' && i < bytes.len() {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                    continue;
                }
                if ch == b'"' {
                    break;
                }
            }
            continue;
        }
        // Char literal
        if c == b'\'' {
            out.push(b' ');
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i];
                out.push(if ch == b'\n' { b'\n' } else { b' ' });
                i += 1;
                if ch == b'\\' && i < bytes.len() {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                    continue;
                }
                if ch == b'\'' {
                    break;
                }
            }
            continue;
        }
        // Line comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Block comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Identifier-bounded needle search
// ---------------------------------------------------------------------------

/// Find identifier-bounded occurrences of `needle` ending at `(` (call form).
/// Skips `fn needle` / `pub … fn needle` definitions.
fn find_call_sites(cleaned: &str, needle: &str) -> Vec<usize> {
    let hay = cleaned.as_bytes();
    let n = needle.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while from + n.len() < hay.len() {
        let Some(rel) = cleaned[from..].find(needle) else {
            break;
        };
        let at = from + rel;
        let after_name = at + n.len();
        let before_ok = at == 0 || !is_ident_char(hay[at - 1]);
        // Allow whitespace between name and `(`
        let mut j = after_name;
        while j < hay.len() && hay[j].is_ascii_whitespace() {
            j += 1;
        }
        let is_call = j < hay.len() && hay[j] == b'(';
        if before_ok && is_call && !is_fn_definition(cleaned, at) {
            out.push(at);
        }
        from = at + n.len();
    }
    out
}

/// True if `name_at` points at a `fn <name>` definition (not a call).
fn is_fn_definition(cleaned: &str, name_at: usize) -> bool {
    let before = &cleaned[..name_at];
    // Walk back over whitespace
    let trimmed = before.trim_end();
    // `fn stage_block` / `async fn` / `pub fn` / `pub(crate) fn`
    if let Some(rest) = trimmed.strip_suffix("fn") {
        let rest = rest.trim_end();
        if rest.is_empty() {
            return true;
        }
        // pub / pub(…) / async immediately before fn
        if rest.ends_with("async") || rest.ends_with(')') || rest.ends_with("pub") {
            return true;
        }
        // bare: last token is not an identifier continuation into `fn`
        let last = rest.as_bytes().last().copied().unwrap_or(0);
        if !is_ident_char(last) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Brace-depth map
// ---------------------------------------------------------------------------

/// Brace depth just before each byte (depth at index i = opens−closes in [0, i)).
fn brace_depths(cleaned: &str) -> Vec<i32> {
    let bytes = cleaned.as_bytes();
    let mut depths = vec![0i32; bytes.len()];
    let mut d = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        depths[i] = d;
        match b {
            b'{' => d += 1,
            b'}' => d -= 1,
            _ => {}
        }
    }
    depths
}

// ---------------------------------------------------------------------------
// Guard binding extraction
// ---------------------------------------------------------------------------

/// From a `let` pattern text, extract the **staged-guard** binding name.
///
/// ADR-006 / PendingAudit shape: `let (staged, audit) = stage_*` — first tuple
/// element is the guard. Bare `let s = stage_*` — the single binding is the guard.
/// Nested `Ok(…)` unwraps one layer.
fn guard_name_from_let_pat(pat: &str) -> Option<String> {
    let p = pat.trim();
    if p.is_empty() || p == "_" {
        return None;
    }
    // Mut binding: `mut staged`
    let p = p.strip_prefix("mut ").map(str::trim).unwrap_or(p);
    // Type ascription: `staged: StagedBlock<'_>`
    let p = p.split(':').next()?.trim();

    if let Some(inner) = p.strip_prefix("Ok(").and_then(|s| s.strip_suffix(')')) {
        return guard_name_from_let_pat(inner);
    }
    if let Some(inner) = p.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        // Tuple: first element is the staged guard (PendingAudit is second).
        let first = split_top_level_commas(inner).into_iter().next()?;
        return guard_name_from_let_pat(&first);
    }
    // Simple ident
    if p.bytes().next().map(is_ident_start).unwrap_or(false)
        && p.bytes().all(is_ident_char)
        && p != "self"
    {
        return Some(p.to_string());
    }
    None
}

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Skip balanced `(…)` starting at `open` (byte of `(`). Returns index after `)`.
fn skip_balanced_parens(bytes: &[u8], open: usize) -> usize {
    debug_assert_eq!(bytes[open], b'(');
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

// ---------------------------------------------------------------------------
// Stage-guard live-set tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StageGuard {
    name: String,
    /// Byte offset of the `let` / arm binding.
    intro: usize,
    /// Brace depth at introduction (binding dies when depth falls below this).
    depth: i32,
    /// Byte offset at which the guard was consumed (`commit`/`discard`/`drop`), if any.
    consumed_at: Option<usize>,
}

#[derive(Debug, Clone)]
struct AuditCall {
    /// Byte offset of `audit_log`.
    at: usize,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Violation {
    line: usize,
    binding: String,
    stage_line: usize,
}

#[derive(Debug, Default)]
struct ScanOutcome {
    stage_call_sites: usize,
    audit_calls: usize,
    violations: Vec<Violation>,
}

/// Pure matcher: comment-/string-stripped source → stage/audit stats + violations.
fn scan_source(src: &str) -> ScanOutcome {
    let cleaned = strip_comments_and_strings(src);
    let depths = brace_depths(&cleaned);

    let stage_block_sites = find_call_sites(&cleaned, "stage_block");
    let stage_att_sites = find_call_sites(&cleaned, "stage_attestation");
    let stage_sites: Vec<usize> = {
        let mut v = stage_block_sites;
        v.extend(stage_att_sites);
        v.sort_unstable();
        v
    };
    let stage_call_sites = stage_sites.len();

    let audit_sites = find_call_sites(&cleaned, "audit_log");
    let audit_calls: Vec<AuditCall> =
        audit_sites.iter().map(|&at| AuditCall { at, line: line_at(src, at) }).collect();

    // --- Collect stage-guard bindings (let + match Ok arms) -----------------
    let mut guards: Vec<StageGuard> = Vec::new();

    // (1) `let PAT = … stage_*(…)`  — stage call on the RHS of a let.
    for &stage_at in &stage_sites {
        if let Some(g) = binding_for_stage_let(&cleaned, &depths, stage_at) {
            guards.push(g);
        }
        if let Some(g) = binding_for_stage_match_ok(&cleaned, &depths, stage_at) {
            guards.push(g);
        }
    }

    // Dedup identical (name, intro)
    guards.sort_by_key(|g| (g.intro, g.name.clone()));
    guards.dedup_by(|a, b| a.intro == b.intro && a.name == b.name);

    // --- Mark consumption: name.commit / name.discard / drop(name) ---------
    for g in &mut guards {
        g.consumed_at = find_consumption(&cleaned, &g.name, g.intro);
    }

    // --- For each audit_log, any live guard in an enclosing scope? ----------
    let mut violations = Vec::new();
    for ac in &audit_calls {
        let ad = depths.get(ac.at).copied().unwrap_or(0);
        for g in &guards {
            if g.intro >= ac.at {
                continue; // bound after the call
            }
            // Guard's declaring scope must still be open (brace depth has not
            // fallen below the intro depth between intro and the audit call).
            if !scope_still_open(&depths, g.intro, ac.at, g.depth) {
                continue;
            }
            // Enclosing: audit is at same or deeper depth than the binding.
            if ad < g.depth {
                continue;
            }
            // Consumed before audit_log?
            if let Some(c) = g.consumed_at {
                if c < ac.at {
                    continue;
                }
            }
            violations.push(Violation {
                line: ac.line,
                binding: g.name.clone(),
                stage_line: line_at(src, g.intro),
            });
        }
    }

    violations.sort_by_key(|v| (v.line, v.binding.clone()));
    violations.dedup();

    ScanOutcome { stage_call_sites, audit_calls: audit_calls.len(), violations }
}

/// True if brace depth never drops below `intro_depth` on any byte in `(intro, at]`.
///
/// `intro` is the binding site (or the arm `{`); the binding's live region is the
/// bytes *after* it at depth ≥ `intro_depth`. Including `intro` itself would fail
/// for arm braces, where `depths[brace] == intro_depth - 1`.
fn scope_still_open(depths: &[i32], intro: usize, at: usize, intro_depth: i32) -> bool {
    if at <= intro || depths.is_empty() {
        return false;
    }
    let end = at.min(depths.len() - 1);
    for d in &depths[intro + 1..=end] {
        if *d < intro_depth {
            return false;
        }
    }
    true
}

/// If `stage_at` sits on the RHS of `let PAT = …`, return the guard binding.
fn binding_for_stage_let(cleaned: &str, depths: &[i32], stage_at: usize) -> Option<StageGuard> {
    // Walk left from stage_at to find `let` at the same statement (no `;` / `{` / `}` in between
    // that would end the expression — allow nested parens/brackets).
    let bytes = cleaned.as_bytes();
    let mut i = stage_at;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren += 1,
            b'(' => {
                if paren == 0 {
                    // naked open — keep going (method receiver)
                } else {
                    paren -= 1;
                }
            }
            b']' => bracket += 1,
            b'[' => {
                if bracket > 0 {
                    bracket -= 1;
                }
            }
            b';' | b'}' if paren == 0 && bracket == 0 => break,
            b';' if paren == 0 && bracket == 0 => break,
            _ => {}
        }
    }
    let window = &cleaned[i..stage_at];
    // Find the rightmost `let` in the window that is a keyword.
    let let_rel = window.rmatch_indices("let").find(|(rel, _)| {
        let at = i + rel;
        let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
        let after = at + 3;
        let after_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        before_ok && after_ok
    })?;
    let let_at = i + let_rel.0;
    // Pattern: between `let` and `=`
    let after_let = let_at + 3;
    let eq_rel = cleaned[after_let..stage_at].find('=')?;
    let pat = cleaned[after_let..after_let + eq_rel].trim();
    // Ensure this `=` is the let-binding equals (not `==` / `!=` / `<=`).
    let eq_at = after_let + eq_rel;
    if eq_at > 0 && matches!(bytes[eq_at - 1], b'!' | b'<' | b'>' | b'=') {
        return None;
    }
    if eq_at + 1 < bytes.len() && bytes[eq_at + 1] == b'=' {
        return None;
    }
    let name = guard_name_from_let_pat(pat)?;
    let depth = depths.get(let_at).copied().unwrap_or(0);
    Some(StageGuard { name, intro: let_at, depth, consumed_at: None })
}

/// If `stage_at` is the scrutinee of `match stage_*(…) { Ok(PAT) => … }`, bind PAT.
fn binding_for_stage_match_ok(
    cleaned: &str,
    depths: &[i32],
    stage_at: usize,
) -> Option<StageGuard> {
    let bytes = cleaned.as_bytes();
    // Require a `match` keyword to the left of the stage call (scrutinee position).
    let before = &cleaned[..stage_at];
    let match_rel = before.rmatch_indices("match").find(|(rel, _)| {
        let at = *rel;
        let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
        let after = at + 5;
        let after_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        // No `{` or `;` between match and stage (scrutinee span).
        if before_ok && after_ok {
            let span = &cleaned[after..stage_at];
            !span.contains('{') && !span.contains(';')
        } else {
            false
        }
    })?;
    let match_at = match_rel.0;

    // Find the opening `{` of the match after the stage call's closing `)`.
    let mut j = stage_at;
    // advance to `(` of the call
    while j < bytes.len() && bytes[j] != b'(' {
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    j = skip_balanced_parens(bytes, j);
    // skip `?` / whitespace
    while j < bytes.len() && (bytes[j].is_ascii_whitespace() || bytes[j] == b'?') {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'{' {
        return None;
    }
    let match_brace = j;
    let arm_depth = depths.get(match_brace).copied().unwrap_or(0) + 1;

    // Search for `Ok(` pattern at the start of an arm inside this match (depth == arm_depth).
    let match_end = find_matching_brace(bytes, match_brace)?;
    let body = &cleaned[match_brace + 1..match_end];
    // Look for Ok(… ) at top level of match body (not nested deeper).
    let mut search_from = 0;
    while let Some(rel) = body[search_from..].find("Ok(") {
        let ok_at = match_brace + 1 + search_from + rel;
        let abs_rel = search_from + rel;
        // Identifier boundary
        let before_ok = ok_at == 0 || !is_ident_char(bytes[ok_at - 1]);
        if !before_ok {
            search_from = abs_rel + 2;
            continue;
        }
        // Only top-level arms: depth at Ok should equal arm_depth (just inside match brace).
        let d = depths.get(ok_at).copied().unwrap_or(0);
        if d != arm_depth {
            search_from = abs_rel + 2;
            continue;
        }
        let open = ok_at + 2; // points at `(`
        let close = skip_balanced_parens(bytes, open);
        let inner = cleaned[open + 1..close - 1].trim();
        if let Some(name) = guard_name_from_let_pat(inner) {
            // Prefer the arm body `{` as intro so the guard is live only inside
            // that block (sibling `Err` arms at the same match depth stay clean).
            let mut k = close;
            while k < match_end && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            let (intro, intro_depth) =
                if k + 1 < bytes.len() && bytes[k] == b'=' && bytes[k + 1] == b'>' {
                    k += 2;
                    while k < match_end && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < match_end && bytes[k] == b'{' {
                        let d = depths.get(k).copied().unwrap_or(arm_depth) + 1;
                        (k, d)
                    } else {
                        // Expression arm: live at match-arm depth until the arm ends.
                        (ok_at, arm_depth)
                    }
                } else {
                    (ok_at, arm_depth)
                };
            let _ = match_at; // structure validated above via scrutinee span
            return Some(StageGuard { name, intro, depth: intro_depth, consumed_at: None });
        }
        search_from = abs_rel + 2;
    }
    None
}

fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    if open >= bytes.len() || bytes[open] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    for (i, &byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// First consumption site for `name` after `from`: `.commit` / `.discard` / `drop(name)`.
fn find_consumption(cleaned: &str, name: &str, from: usize) -> Option<usize> {
    let bytes = cleaned.as_bytes();
    let hay = &cleaned[from..];

    // name.commit / name.discard (method call consuming self)
    for method in ["commit", "discard"] {
        let needle = format!("{name}.{method}");
        let mut search = 0;
        while let Some(rel) = hay[search..].find(&needle) {
            let at = from + search + rel;
            let after = at + needle.len();
            let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
            let after_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
            if before_ok && after_ok {
                return Some(at);
            }
            search += rel + 1;
        }
    }

    // drop(name) / drop( name )
    let drop_needle = "drop";
    let mut search = 0;
    while let Some(rel) = hay[search..].find(drop_needle) {
        let at = from + search + rel;
        let after_drop = at + 4;
        let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
        let after_kw = after_drop >= bytes.len() || !is_ident_char(bytes[after_drop]);
        if before_ok && after_kw {
            let mut j = after_drop;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                let inner_start = j + 1;
                let inner_end = skip_balanced_parens(bytes, j) - 1;
                if inner_end > inner_start {
                    let inner = cleaned[inner_start..inner_end].trim();
                    // drop(name) or drop(name as …) — take first token
                    let tok = inner
                        .split(|c: char| c == ',' || c.is_whitespace())
                        .find(|t| !t.is_empty())
                        .unwrap_or("");
                    if tok == name {
                        return Some(at);
                    }
                }
            }
        }
        search += rel + 1;
    }

    // name goes out of scope is handled by brace tracking, not here.
    None
}

// ---------------------------------------------------------------------------
// Live gate
// ---------------------------------------------------------------------------

#[test]
fn no_audit_log_call_is_inside_a_staged_guard_scope() {
    let root = workspace_root();
    let files = scan_roots(&root);
    let scanned_files = files.len();
    assert!(
        scanned_files >= 2,
        "scanned only {scanned_files} files under crates/slashing/src and crates/signer/src; \
         walk likely broke"
    );

    let mut stage_call_sites_found = 0usize;
    let mut report: Vec<String> = Vec::new();

    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let src = std::fs::read_to_string(file).unwrap_or_default();
        let outcome = scan_source(&src);
        stage_call_sites_found += outcome.stage_call_sites;
        for v in outcome.violations {
            report.push(format!(
                "{rel}:{} — `audit_log` while staged guard `{}` (from stage at line {}) is still live",
                v.line, v.binding, v.stage_line
            ));
        }
    }

    assert!(
        stage_call_sites_found >= 6,
        "found only {stage_call_sites_found} stage_block/stage_attestation call sites; \
         expected ≥ 6 (scoped.rs ×2 + signer production sites — VD-E2). Scanner or tree moved."
    );

    report.sort();
    assert!(
        report.is_empty(),
        "G-7 / ARCH-P0-9 (ADR-006): `audit_log` must not run while a staged guard is live.\n\
         Emit via `PendingAudit::emit` only after `commit`/`discard` releases the mutex.\n\
         Offenders:\n  {}",
        report.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Matcher unit tests — synthetic RED / GREEN (permanent falsifiability)
// ---------------------------------------------------------------------------

#[test]
fn scanner_flags_a_synthetic_in_scope_audit_call() {
    // Mandatory RED: classic hazard — audit while the guard binding is live.
    let src = r#"
fn bad_block(db: &Db) {
    let s = db.stage_block(pk, slot, None);
    audit_log("cn", "pk", "staged");
    drop(s);
}

fn bad_attestation(db: &Db) {
    let result = db.stage_attestation(pk, src, tgt, None)?;
    audit_log("cn", "pk", "staged");
    Ok(result)
}
"#;
    let outcome = scan_source(src);
    assert!(
        outcome.violations.iter().any(|v| v.binding == "s"),
        "expected guard `s` flagged, got {:?}",
        outcome.violations
    );
    assert!(
        outcome.violations.iter().any(|v| v.binding == "result"),
        "expected guard `result` flagged, got {:?}",
        outcome.violations
    );
    // Both synthetic paths (block + attestation) must light up — VD-S5.
    assert!(
        outcome.violations.len() >= 2,
        "expected ≥2 violations (block + attestation fixtures), got {:?}",
        outcome.violations
    );
}

#[test]
fn scanner_accepts_emission_after_the_guard_is_consumed() {
    // Synthetic GREEN: PendingAudit shape — guard released before audit_log.
    let src = r#"
fn pending_audit_shape(db: &Db) {
    let (staged, audit) = db.stage_block(pk, slot, None);
    // Guard released HERE (commit consumes staged).
    staged.commit().ok();
    // Emission after the guard is gone — safe even as a direct audit_log.
    let _ = audit;
    audit_log("cn", "pk", "staged");
}

fn emit_helper(client_cn: &str, pubkey_hex: &str, outcome: &str) {
    // PendingAudit::emit body — no stage binding in this scope.
    audit_log(client_cn, pubkey_hex, outcome);
}

fn rejected_path(db: &Db) {
    match db.stage_block(pk, slot, None) {
        Ok(staged) => {
            let _ = staged;
        }
        Err(e) => {
            // No guard was ever created — safe.
            audit_log("cn", "pk", "rejected");
            return Err(e);
        }
    }
}
"#;
    let outcome = scan_source(src);
    assert!(
        outcome.violations.is_empty(),
        "PendingAudit / post-commit / Err-path shapes must not be flagged: {:?}",
        outcome.violations
    );
    assert!(
        outcome.stage_call_sites >= 2,
        "fixture must exercise stage calls; found {}",
        outcome.stage_call_sites
    );
    assert!(
        outcome.audit_calls >= 3,
        "fixture must exercise audit_log calls; found {}",
        outcome.audit_calls
    );
}

#[test]
fn scanner_flags_audit_inside_ok_arm_holding_guard() {
    // Match Ok arm: guard live across audit_log (pre-ARCH-1a shape).
    let src = r#"
fn old_scoped(db: &Db) {
    match db.stage_block(pk, slot, None) {
        Ok(staged) => {
            audit_log("cn", "pk", "staged");
            Ok(staged)
        }
        Err(e) => Err(e),
    }
}
"#;
    let outcome = scan_source(src);
    assert!(
        outcome.violations.iter().any(|v| v.binding == "staged"),
        "expected Ok(staged) arm flagged, got {:?}",
        outcome.violations
    );
}

#[test]
fn guard_name_extracts_pending_audit_tuple_first_element() {
    assert_eq!(guard_name_from_let_pat("s").as_deref(), Some("s"));
    assert_eq!(guard_name_from_let_pat("mut result").as_deref(), Some("result"));
    assert_eq!(guard_name_from_let_pat("(staged, audit)").as_deref(), Some("staged"));
    assert_eq!(guard_name_from_let_pat("(staged, audit, _extra)").as_deref(), Some("staged"));
    assert_eq!(guard_name_from_let_pat("Ok(staged)").as_deref(), Some("staged"));
    assert_eq!(guard_name_from_let_pat("Ok((staged, audit))").as_deref(), Some("staged"));
    assert_eq!(guard_name_from_let_pat("_").as_deref(), None);
}

#[test]
fn fn_definition_is_not_counted_as_call_site() {
    let src = r#"
pub fn stage_block<'db>(...) -> Result<StagedBlock<'db>, E> { todo!() }
pub fn audit_log(a: &str, b: &str, c: &str) {}
fn user() {
    let g = db.stage_block(1, 2, None);
    drop(g);
}
"#;
    let outcome = scan_source(src);
    assert_eq!(outcome.stage_call_sites, 1, "only the call, not the fn def");
    assert_eq!(outcome.audit_calls, 0, "fn audit_log definition is not a call");
}
