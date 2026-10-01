//! G-6 / ARCH-7a: KM-2 teardown classification gate (`km2_lifecycle.rs`).
//!
//! Pins the contract C5 / ADR-015 require a gate for:
//!
//! * `stop_monitoring` must **not** tear down forward-window enablement state
//!   (M-12 wall-clock elapse ≠ cancel).
//! * `cancel_monitoring` is the DELETE / hard-remove path
//!   (`ForwardWindowMachine::cancel`) so a re-import starts a fresh window.
//! * The trait default `cancel_monitoring → stop_monitoring` is **correct** for
//!   time-based / log-only / test-double implementors and **fatal** for
//!   machine-backed ones. This gate is therefore a **classification**, not a ban.
//!
//! Five load-bearing clauses:
//!
//! 1. Every workspace `impl DoppelgangerMonitor for <T>` appears in **exactly
//!    one** of [`MUST_OVERRIDE_CANCEL`] / [`DEFAULT_IS_SAFE`]. A new
//!    implementor fails CI until it is classified (non-vacuity).
//! 2. [`MUST_OVERRIDE_CANCEL`] impls textually declare `fn cancel_monitoring`.
//! 3. The trait still declares **both** `fn stop_monitoring` and
//!    `fn cancel_monitoring` — the collapse detector ADR-015 names.
//! 4. `DoppelgangerLifecycle::on_delete` still calls `cancel_monitoring`
//!    paired with `remove_validator` (HTTP handlers must still go through it).
//! 5. ARCH-7b: the GVR-blind slashing-history reader identifier is gone from
//!    `crates/` and `bin/` (`no_legacy_slashing_history_reader_symbol`).
//!
//! The behavioural half (`stop_monitoring` ⇒ `Pending`, `cancel_monitoring` ⇒
//! `Unmonitored`) stays in `keymanager_adapters/tests/misc_adapters.rs` and is
//! not this gate's job.
//!
//! No external dependency (Phase-1 rule P6): brace-aware extraction in the
//! `kat_policy.rs` idiom. RED is demonstrated on a scratch tree (ADR-012),
//! never merged.
//!
//! Cross-ref: architecture §6 G-6; plan issue ARCH-7a; VD-6; C5; ADR-015.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Classification tables
// ---------------------------------------------------------------------------

/// Machine-backed monitors: inheriting the trait default would leave a DELETE
/// on a stale forward window. `(file, impl type)`.
const MUST_OVERRIDE_CANCEL: &[(&str, &str)] =
    &[("crates/rvc/src/keymanager_adapters/doppelganger.rs", "ForwardWindowMonitor")];

/// Implementors for which `cancel_monitoring` defaulting to `stop_monitoring`
/// is correct. `(file, impl type, reason)`.
const DEFAULT_IS_SAFE: &[(&str, &str, &str)] = &[
    (
        "crates/keymanager-api/src/lifecycle.rs",
        "PendingSetMonitor",
        "test double; pending-set, cancel defaults to stop — lifecycle.rs:356",
    ),
    ("crates/keymanager-api/src/server.rs", "StubDoppelganger", "test double"),
    (
        "crates/keymanager-api/tests/common/mod.rs",
        "MockDoppelgangerMonitor",
        "test double; in-memory pending list, cancel defaults to stop",
    ),
    (
        "crates/keymanager-api/tests/common/mod.rs",
        "PendingSetMonitor",
        "test double; pending-set, cancel defaults to stop",
    ),
    (
        "crates/keymanager-api/tests/delete_export_error_fail_closed.rs",
        "NoopDoppelgangerMonitor",
        "test double",
    ),
    (
        "crates/keymanager-api/tests/error_sanitization_m8.rs",
        "NoopDoppelgangerMonitor",
        "test double",
    ),
    (
        "crates/keymanager-api/tests/km2_cancel_token_race.rs",
        "GatedDoppelgangerMonitor",
        "test double wrapping a pending-set monitor",
    ),
    ("crates/keymanager-api/tests/set_attesting_m9.rs", "NoopDoppelgangerMonitor", "test double"),
    (
        "crates/rvc/src/keymanager_adapters/doppelganger.rs",
        "DoppelgangerDisabledMonitor",
        "opt-out always-safe; log-only, no teardown state",
    ),
    (
        "crates/rvc/src/keymanager_adapters/tests/export_floor.rs",
        "NoopMonitor",
        "test double; no-op monitor for export-floor tests, cancel defaults to stop",
    ),
    (
        "crates/rvc/tests/post_import_doppelganger_signing_block_m12.rs",
        "RecordingMonitor",
        "test double; records start_monitoring for re-arm scan",
    ),
];

/// This gate's own sources mention the needle inside synthetic fixtures.
const THIS_GATE: &str = "crates/architecture-tests/tests/km2_lifecycle.rs";

const TRAIT_PATH: &str = "crates/keymanager-api/src/traits.rs";
const TRAIT_NAME: &str = "DoppelgangerMonitor";

const DELETE_HANDLER_PATH: &str = "crates/keymanager-api/src/lifecycle.rs";
const DELETE_HANDLER_FN: &str = "on_delete";
const DELETE_HTTP_PATH: &str = "crates/keymanager-api/src/handlers.rs";

/// Floor so a silent empty walk cannot go green. Seeded at ARCH-7c
/// (gate.rs deleted; PendingSetMonitor test doubles classified).
const MIN_IMPLS: usize = 11;

// ---------------------------------------------------------------------------
// Workspace walk
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// Parse `members = [...]` from the workspace `Cargo.toml` (no TOML crate — P6).
fn workspace_member_dirs(root: &Path) -> Vec<PathBuf> {
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let mut dirs = Vec::new();
    let Some(start) = cargo.find("members") else {
        return dirs;
    };
    let rest = &cargo[start..];
    let Some(bracket) = rest.find('[') else {
        return dirs;
    };
    let rest = &rest[bracket + 1..];
    let Some(end) = rest.find(']') else {
        return dirs;
    };
    for part in rest[..end].split(',') {
        let s = part.trim().trim_matches('"').trim_matches('\'').trim();
        if s.is_empty() {
            continue;
        }
        dirs.push(root.join(s));
    }
    dirs
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

/// All `*.rs` under each workspace member (src + tests + benches + examples).
fn workspace_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for member in workspace_member_dirs(root) {
        if member.is_dir() {
            collect_rs(&member, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source helpers (length-preserving strip; brace-aware extract)
// ---------------------------------------------------------------------------

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    while i < src.len() && src.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Identifier immediately before `at`, skipping whitespace. Used to tell
/// `b'x'` / `c'…'` / `br'…'` / `cr'…'` from a lifetime `'static`.
fn prev_ident_token(bytes: &[u8], at: usize) -> Option<&str> {
    let mut j = at;
    while j > 0 && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    let end = j;
    while j > 0 && is_ident_char(bytes[j - 1]) {
        j -= 1;
    }
    if j == end {
        return None;
    }
    std::str::from_utf8(&bytes[j..end]).ok()
}

/// `'static` / `'a` / `'_` — but not the opener of `b'x'` / `c'x'` / `br'…'` / `cr'…'`.
fn is_lifetime_quote(bytes: &[u8], at: usize) -> bool {
    if at + 1 >= bytes.len() || !is_ident_start(bytes[at + 1]) {
        return false;
    }
    !matches!(prev_ident_token(bytes, at), Some("b" | "c" | "br" | "cr"))
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

/// Strip `//` line comments and `/* … */` block comments; blank string / char /
/// raw-string contents. Preserve length and newlines so byte offsets stay valid.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'r' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                let hashes = j - (i + 1);
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
                            out.extend(std::iter::repeat_n(b' ', 1 + hashes));
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
        if c == b'\'' {
            // Lifetime `'static` / `'a` / `'_` — must not be treated as a char
            // literal or the rest of the file is blanked (server.rs: `'static str`
            // sits above `impl DoppelgangerMonitor for StubDoppelganger`).
            // `b'x'` / `c'…'` must stay char literals (LOW-2).
            if is_lifetime_quote(bytes, i) {
                out.push(b' ');
                i += 1;
                while i < bytes.len() && is_ident_char(bytes[i]) {
                    out.push(bytes[i]);
                    i += 1;
                }
                continue;
            }
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
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
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

fn ident_at(src: &str, at: usize, name: &str) -> bool {
    let bytes = src.as_bytes();
    if at + name.len() > src.len() || &src[at..at + name.len()] != name {
        return false;
    }
    let before_ok = at == 0 || !is_ident_char(bytes[at - 1]);
    let after = at + name.len();
    let after_ok = after >= src.len() || !is_ident_char(bytes[after]);
    before_ok && after_ok
}

fn parse_ident(src: &str, i: usize) -> Option<(&str, usize)> {
    let i = skip_ws(src, i);
    let bytes = src.as_bytes();
    if i >= bytes.len() || !is_ident_start(bytes[i]) {
        return None;
    }
    let mut j = i + 1;
    while j < bytes.len() && is_ident_char(bytes[j]) {
        j += 1;
    }
    Some((&src[i..j], j))
}

/// Skip a `< … >` generic / where-clause argument list (best-effort).
fn skip_angles(src: &str, mut i: usize) -> usize {
    if i >= src.len() || src.as_bytes()[i] != b'<' {
        return i;
    }
    let mut depth = 0i32;
    while i < src.len() {
        match src.as_bytes()[i] {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    i
}

fn skip_path(src: &str, mut i: usize) -> Option<(&str, usize)> {
    let (mut last, mut j) = parse_ident(src, i)?;
    loop {
        i = skip_ws(src, j);
        if src[i..].starts_with("::") {
            let next = parse_ident(src, i + 2)?;
            last = next.0;
            j = next.1;
            continue;
        }
        return Some((last, i));
    }
}

fn skip_type(src: &str, mut i: usize) -> Option<(&str, usize)> {
    i = skip_ws(src, i);
    // `&'a mut` / `&mut` / `dyn`
    loop {
        i = skip_ws(src, i);
        if i < src.len() && src.as_bytes()[i] == b'&' {
            i += 1;
            i = skip_ws(src, i);
            if i < src.len() && src.as_bytes()[i] == b'\'' {
                if let Some((_, j)) = parse_ident(src, i + 1) {
                    i = j;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if ident_at(src, i, "mut") {
            i += 3;
            continue;
        }
        if ident_at(src, i, "dyn") {
            i += 3;
            continue;
        }
        break;
    }
    let (name, mut j) = skip_path(src, i)?;
    j = skip_ws(src, j);
    if j < src.len() && src.as_bytes()[j] == b'<' {
        j = skip_angles(src, j);
    }
    Some((name, j))
}

/// True if `name_at` points at a `fn <name>` definition (not a call).
fn is_fn_definition(cleaned: &str, name_at: usize) -> bool {
    let before = cleaned[..name_at].trim_end();
    before.ends_with("fn")
        && (before.len() == 2 || {
            let b = before.as_bytes()[before.len() - 3];
            !is_ident_char(b)
        })
}

/// Brace depth at `at` (number of unclosed `{` in `src[..at]`).
fn brace_depth_at(src: &str, at: usize) -> i32 {
    let mut depth = 0i32;
    for ch in src[..at.min(src.len())].chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// `fn name` declared as a **top-level** item of an impl/trait body (`{` depth 1).
/// Nested helpers (`fn stop { fn cancel_monitoring() {} }`) do not count.
fn has_fn_decl(body: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = body[from..].find(name) {
        let at = from + rel;
        if ident_at(body, at, name) && is_fn_definition(body, at) && brace_depth_at(body, at) == 1 {
            return true;
        }
        from = at + name.len().max(1);
    }
    false
}

fn has_call(body: &str, name: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(rel) = body[from..].find(name) {
        let at = from + rel;
        if ident_at(body, at, name) && !is_fn_definition(body, at) {
            let mut j = skip_ws(body, at + name.len());
            if j < bytes.len() && bytes[j] == b'(' {
                return true;
            }
            // UFCS / method: already identifier-bounded; tolerate turbofish.
            if j < body.len() && body.as_bytes()[j] == b':' && body[j..].starts_with("::") {
                j = skip_ws(body, j + 2);
                if j < body.len() && body.as_bytes()[j] == b'<' {
                    j = skip_ws(body, skip_angles(body, j));
                }
                if j < body.len() && body.as_bytes()[j] == b'(' {
                    return true;
                }
            }
        }
        from = at + name.len().max(1);
    }
    false
}

// ---------------------------------------------------------------------------
// `impl DoppelgangerMonitor for <T>` extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundImpl {
    rel_path: String,
    type_name: String,
    body: String,
}

fn extract_impls(rel_path: &str, src: &str) -> Vec<FoundImpl> {
    let cleaned = strip_comments_and_strings(src);
    let bytes = cleaned.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = cleaned[from..].find("impl") {
        let at = from + rel;
        if !ident_at(&cleaned, at, "impl") {
            from = at + 4;
            continue;
        }
        let mut i = skip_ws(&cleaned, at + 4);
        if i < bytes.len() && bytes[i] == b'<' {
            i = skip_ws(&cleaned, skip_angles(&cleaned, i));
        }
        let Some((trait_name, after_trait)) = skip_path(&cleaned, i) else {
            from = at + 4;
            continue;
        };
        if trait_name != TRAIT_NAME {
            from = at + 4;
            continue;
        }
        i = skip_ws(&cleaned, after_trait);
        if !ident_at(&cleaned, i, "for") {
            from = at + 4;
            continue;
        }
        i += 3;
        let Some((type_name, after_ty)) = skip_type(&cleaned, i) else {
            from = at + 4;
            continue;
        };
        i = skip_ws(&cleaned, after_ty);
        // Skip a `where` clause until the impl body `{`.
        while i < cleaned.len() && bytes[i] != b'{' {
            if bytes[i] == b'<' {
                i = skip_angles(&cleaned, i);
                continue;
            }
            if bytes[i] == b';' {
                break;
            }
            i += 1;
        }
        if i >= cleaned.len() || bytes[i] != b'{' {
            from = at + 4;
            continue;
        }
        let Some(end) = close_brace(&cleaned, i) else {
            from = at + 4;
            continue;
        };
        out.push(FoundImpl {
            rel_path: rel_path.to_string(),
            type_name: type_name.to_string(),
            body: cleaned[i..end].to_string(),
        });
        from = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Trait + DELETE-path extractors
// ---------------------------------------------------------------------------

fn extract_trait_body(src: &str, name: &str) -> Option<String> {
    let cleaned = strip_comments_and_strings(src);
    let bytes = cleaned.as_bytes();
    let mut from = 0;
    while let Some(rel) = cleaned[from..].find("trait") {
        let at = from + rel;
        if !ident_at(&cleaned, at, "trait") {
            from = at + 5;
            continue;
        }
        let Some((ident, after)) = parse_ident(&cleaned, at + 5) else {
            from = at + 5;
            continue;
        };
        if ident != name {
            from = at + 5;
            continue;
        }
        let mut i = skip_ws(&cleaned, after);
        while i < cleaned.len() && bytes[i] != b'{' {
            i += 1;
        }
        if i >= cleaned.len() || bytes[i] != b'{' {
            return None;
        }
        let end = close_brace(&cleaned, i)?;
        return Some(cleaned[i..end].to_string());
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundFn {
    name: String,
    body: String,
}

fn extract_fns(src: &str) -> Vec<FoundFn> {
    let cleaned = strip_comments_and_strings(src);
    let bytes = cleaned.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = cleaned[from..].find("fn") {
        let at = from + rel;
        if !ident_at(&cleaned, at, "fn") {
            from = at + 2;
            continue;
        }
        let Some((name, after_name)) = parse_ident(&cleaned, at + 2) else {
            from = at + 2;
            continue;
        };
        let mut i = after_name;
        let mut paren = 0i32;
        let mut angle = 0i32;
        let mut square = 0i32;
        let mut body_open = None;
        while i < cleaned.len() {
            match bytes[i] {
                b'<' => angle += 1,
                b'>' => angle = (angle - 1).max(0),
                b'(' => paren += 1,
                b')' => paren = (paren - 1).max(0),
                b'[' => square += 1,
                b']' => square = (square - 1).max(0),
                b'{' if paren == 0 && angle == 0 && square == 0 => {
                    body_open = Some(i);
                    break;
                }
                b';' if paren == 0 && angle == 0 && square == 0 => break,
                _ => {}
            }
            i += 1;
        }
        let Some(open) = body_open else {
            from = after_name;
            continue;
        };
        let Some(end) = close_brace(&cleaned, open) else {
            from = after_name;
            continue;
        };
        out.push(FoundFn { name: name.to_string(), body: cleaned[open..end].to_string() });
        from = end;
    }
    out
}

fn paired_delete_fns(src: &str) -> Vec<String> {
    extract_fns(src)
        .into_iter()
        .filter(|f| has_call(&f.body, "remove_validator") && has_call(&f.body, "cancel_monitoring"))
        .map(|f| f.name)
        .collect()
}

// ---------------------------------------------------------------------------
// Workspace scan
// ---------------------------------------------------------------------------

struct WorkspaceScan {
    impls: Vec<FoundImpl>,
    files: usize,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = workspace_rs_files(&root);
    let mut impls = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == THIS_GATE {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        impls.extend(extract_impls(&rel, &src));
    }
    WorkspaceScan { impls, files: files.len() }
}

type Classified = HashSet<(&'static str, &'static str)>;

fn classified_keys() -> (Classified, Classified, Vec<String>) {
    let mut must = HashSet::new();
    let mut safe = HashSet::new();
    let mut dups = Vec::new();
    for &(file, ty) in MUST_OVERRIDE_CANCEL {
        if !must.insert((file, ty)) {
            dups.push(format!("MUST_OVERRIDE_CANCEL duplicate: {file}::{ty}"));
        }
    }
    for &(file, ty, _) in DEFAULT_IS_SAFE {
        if !safe.insert((file, ty)) {
            dups.push(format!("DEFAULT_IS_SAFE duplicate: {file}::{ty}"));
        }
        if must.contains(&(file, ty)) {
            dups.push(format!("listed in both tables: {file}::{ty}"));
        }
    }
    (must, safe, dups)
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn km2_tables_are_unique_and_disjoint() {
    let (_, _, dups) = classified_keys();
    assert!(
        dups.is_empty(),
        "G-6 classification tables overlap or repeat:\n  {}",
        dups.join("\n  ")
    );
}

#[test]
fn km2_every_implementor_is_classified() {
    let scan = scan_workspace();
    assert!(scan.files > 100, "scanned only {} files; workspace walk likely broke", scan.files);
    assert!(
        scan.impls.len() >= MIN_IMPLS,
        "found only {} impl DoppelgangerMonitor for site(s); matcher or walk likely broke (need >= {MIN_IMPLS})",
        scan.impls.len()
    );

    let (must, safe, dups) = classified_keys();
    assert!(
        dups.is_empty(),
        "G-6 classification tables overlap or repeat:\n  {}",
        dups.join("\n  ")
    );

    let mut unclassified = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for site in &scan.impls {
        let key = (site.rel_path.as_str(), site.type_name.as_str());
        if !must.contains(&key) && !safe.contains(&key) {
            unclassified.push(format!("{}::{}", site.rel_path, site.type_name));
        }
        seen.insert((site.rel_path.clone(), site.type_name.clone()));
    }
    unclassified.sort();
    assert!(
        unclassified.is_empty(),
        "G-6 KM-2 teardown: unclassified implementor — add the type to MUST_OVERRIDE_CANCEL \
         (machine-backed; must declare fn cancel_monitoring) or DEFAULT_IS_SAFE (inheriting \
         the cancel→stop default is correct):\n  {}",
        unclassified.join("\n  ")
    );

    let mut stale = Vec::new();
    for &(file, ty) in MUST_OVERRIDE_CANCEL {
        if !seen.contains(&(file.to_string(), ty.to_string())) {
            stale.push(format!("MUST_OVERRIDE_CANCEL: {file}::{ty}"));
        }
    }
    for &(file, ty, _) in DEFAULT_IS_SAFE {
        if !seen.contains(&(file.to_string(), ty.to_string())) {
            stale.push(format!("DEFAULT_IS_SAFE: {file}::{ty}"));
        }
    }
    stale.sort();
    assert!(
        stale.is_empty(),
        "G-6 KM-2 teardown: classification row has no matching impl DoppelgangerMonitor for \
         (remove the row or fix the path/type):\n  {}",
        stale.join("\n  ")
    );
}

#[test]
fn km2_must_override_declares_cancel_monitoring() {
    let scan = scan_workspace();
    let mut missing = Vec::new();
    for &(file, ty) in MUST_OVERRIDE_CANCEL {
        let sites: Vec<_> =
            scan.impls.iter().filter(|s| s.rel_path == file && s.type_name == ty).collect();
        if sites.is_empty() {
            missing.push(format!("{file}::{ty} (implementor not found)"));
            continue;
        }
        if sites.iter().any(|s| !has_fn_decl(&s.body, "cancel_monitoring")) {
            missing.push(format!("{file}::{ty}"));
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "G-6 KM-2 teardown: MUST_OVERRIDE_CANCEL implementor does not declare \
         fn cancel_monitoring (inheriting the trait default would leave DELETE on a \
         stale forward window):\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn km2_trait_declares_stop_and_cancel() {
    let root = workspace_root();
    let path = root.join(TRAIT_PATH);
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {TRAIT_PATH}: {e}"));
    let body = extract_trait_body(&src, TRAIT_NAME).unwrap_or_else(|| {
        panic!("G-6 collapse detector: trait {TRAIT_NAME} not found in {TRAIT_PATH}")
    });
    let has_stop = has_fn_decl(&body, "stop_monitoring");
    let has_cancel = has_fn_decl(&body, "cancel_monitoring");
    assert!(
        has_stop && has_cancel,
        "G-6 collapse detector: trait {TRAIT_NAME} in {TRAIT_PATH} must declare both \
         fn stop_monitoring and fn cancel_monitoring (missing: {}{})",
        if has_stop { "" } else { "stop_monitoring" },
        match (has_stop, has_cancel) {
            (false, false) => " and cancel_monitoring",
            (true, false) => "cancel_monitoring",
            _ => "",
        }
    );
}

#[test]
fn km2_delete_path_pairs_cancel_with_remove_validator() {
    let root = workspace_root();
    let lifecycle = std::fs::read_to_string(root.join(DELETE_HANDLER_PATH))
        .unwrap_or_else(|e| panic!("failed to read {DELETE_HANDLER_PATH}: {e}"));
    let paired = paired_delete_fns(&lifecycle);
    assert!(
        paired.iter().any(|n| n == DELETE_HANDLER_FN),
        "G-6 KM-2 teardown: {DELETE_HANDLER_PATH}::{DELETE_HANDLER_FN} must call \
         cancel_monitoring paired with remove_validator (got {paired:?})"
    );

    let handlers = std::fs::read_to_string(root.join(DELETE_HTTP_PATH))
        .unwrap_or_else(|e| panic!("failed to read {DELETE_HTTP_PATH}: {e}"));
    assert!(
        has_call(&strip_comments_and_strings(&handlers), DELETE_HANDLER_FN),
        "G-6 KM-2 teardown: {DELETE_HTTP_PATH} must still call {DELETE_HANDLER_FN}"
    );
}

// ---------------------------------------------------------------------------
// Matcher unit tests (synthetic RED / GREEN)
// ---------------------------------------------------------------------------

#[test]
fn km2_scanner_extracts_impl_blocks() {
    let src = r#"
        impl DoppelgangerMonitorAdapter {
            fn new() -> Self { Self }
        }
        impl DoppelgangerMonitor for ForwardWindowMonitor {
            fn stop_monitoring(&self, _pubkey: &Pubkey) {}
            fn cancel_monitoring(&self, _pubkey: &Pubkey) {}
            fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool { true }
        }
        impl<T: DoppelgangerMonitor> Wrapper<T> {
            fn inner(&self) -> &T { &self.0 }
        }
        /// impl DoppelgangerMonitor for CommentedOut
        impl crate::traits::DoppelgangerMonitor for StubDoppelganger {
            fn stop_monitoring(&self, _: &Pubkey) {}
        }
    "#;
    let found = extract_impls("crates/rvc/src/keymanager_adapters/doppelganger.rs", src);
    let names: Vec<_> = found.iter().map(|s| s.type_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["ForwardWindowMonitor", "StubDoppelganger"],
        "only `impl DoppelgangerMonitor for <T>` sites; inherent/generic impls excluded: {found:?}"
    );
    assert!(has_fn_decl(&found[0].body, "cancel_monitoring"));
    assert!(!has_fn_decl(&found[1].body, "cancel_monitoring"));
}

#[test]
fn km2_scanner_nested_cancel_fn_is_not_an_override() {
    let src = r#"
        impl DoppelgangerMonitor for ForwardWindowMonitor {
            fn stop_monitoring(&self, _pubkey: &Pubkey) {
                fn cancel_monitoring() {}
                let _ = cancel_monitoring;
            }
            fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool { true }
        }
    "#;
    let found = extract_impls("crates/rvc/src/keymanager_adapters/doppelganger.rs", src);
    assert_eq!(found.len(), 1);
    assert!(
        !has_fn_decl(&found[0].body, "cancel_monitoring"),
        "nested fn cancel_monitoring must not satisfy MUST_OVERRIDE_CANCEL"
    );
}

#[test]
fn km2_scanner_flags_missing_cancel_override() {
    let src = r#"
        impl DoppelgangerMonitor for ForwardWindowMonitor {
            fn stop_monitoring(&self, _pubkey: &Pubkey) {}
            fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool { true }
        }
    "#;
    let found = extract_impls("crates/rvc/src/keymanager_adapters/doppelganger.rs", src);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].type_name, "ForwardWindowMonitor");
    assert!(
        !has_fn_decl(&found[0].body, "cancel_monitoring"),
        "inherited default must not count as a declaration"
    );
}

#[test]
fn km2_scanner_flags_trait_collapse() {
    let both = r#"
        pub trait DoppelgangerMonitor: Send + Sync {
            fn stop_monitoring(&self, pubkey: &Pubkey);
            fn cancel_monitoring(&self, pubkey: &Pubkey) {
                self.stop_monitoring(pubkey);
            }
        }
    "#;
    let body = extract_trait_body(both, TRAIT_NAME).expect("trait present");
    assert!(has_fn_decl(&body, "stop_monitoring"));
    assert!(has_fn_decl(&body, "cancel_monitoring"));

    let collapsed = r#"
        pub trait DoppelgangerMonitor: Send + Sync {
            fn stop_monitoring(&self, pubkey: &Pubkey);
        }
    "#;
    let body = extract_trait_body(collapsed, TRAIT_NAME).expect("trait present");
    assert!(has_fn_decl(&body, "stop_monitoring"));
    assert!(
        !has_fn_decl(&body, "cancel_monitoring"),
        "deleting fn cancel_monitoring from the trait must trip the collapse detector"
    );
}

#[test]
fn km2_scanner_does_not_treat_lifetimes_as_char_literals() {
    let src = r#"
        fn primary_method(template: &str) -> &'static str { "GET" }
        impl DoppelgangerMonitor for StubDoppelganger {
            fn stop_monitoring(&self, _: &Pubkey) {}
        }
    "#;
    let found = extract_impls("crates/keymanager-api/src/server.rs", src);
    assert_eq!(
        found.iter().map(|s| s.type_name.as_str()).collect::<Vec<_>>(),
        vec!["StubDoppelganger"],
        "'static in a signature must not hide a later impl: {found:?}"
    );
}

#[test]
fn km2_scanner_does_not_treat_byte_chars_as_lifetimes() {
    let src = r#"
        const X: u8 = b'x';
        const Y: u8 = c'y';
        impl DoppelgangerMonitor for AfterByteChar {
            fn stop_monitoring(&self, _: &Pubkey) {}
        }
    "#;
    let found = extract_impls("crates/keymanager-api/src/auth.rs", src);
    assert_eq!(
        found.iter().map(|s| s.type_name.as_str()).collect::<Vec<_>>(),
        vec!["AfterByteChar"],
        "b'x' / c'y' must not hide a later impl: {found:?}"
    );
}

#[test]
fn km2_scanner_flags_unpaired_delete() {
    let paired = r#"
        impl Lifecycle {
            pub fn on_delete(&self, pubkey: &Pubkey) {
                self.validator_manager.remove_validator(pubkey);
                self.monitor.cancel_monitoring(pubkey);
            }
        }
    "#;
    assert_eq!(paired_delete_fns(paired), vec!["on_delete".to_string()]);

    let only_cancel = r#"
        pub fn on_delete(&self, pubkey: &Pubkey) {
            self.monitor.cancel_monitoring(pubkey);
        }
    "#;
    assert!(paired_delete_fns(only_cancel).is_empty());

    let commented = r#"
        pub fn on_delete(&self, pubkey: &Pubkey) {
            // self.validator_manager.remove_validator(pubkey);
            self.monitor.cancel_monitoring(pubkey);
        }
    "#;
    assert!(
        paired_delete_fns(commented).is_empty(),
        "commented remove_validator must not satisfy the pairing clause"
    );
}

// ---------------------------------------------------------------------------
// ARCH-7b: GVR-blind reader identifier is gone
// ---------------------------------------------------------------------------

/// Split so this file is not itself a hit for the identifier.
fn legacy_slashing_history_reader_ident() -> String {
    format!("{}{}", "Legacy", "SlashingHistoryReader")
}

fn collect_all_files(dir: &Path, out: &mut Vec<PathBuf>) {
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
            collect_all_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

#[test]
fn no_legacy_slashing_history_reader_symbol() {
    let needle = legacy_slashing_history_reader_ident();
    let root = workspace_root();
    let mut files = Vec::new();
    collect_all_files(&root.join("crates"), &mut files);
    collect_all_files(&root.join("bin"), &mut files);
    assert!(
        files.len() > 100,
        "scanned only {} files under crates/ and bin/; walk likely broke",
        files.len()
    );

    let mut hits = Vec::new();
    for file in &files {
        let Ok(src) = std::fs::read_to_string(file) else {
            continue;
        };
        if src.contains(&needle) {
            hits.push(file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"));
        }
    }
    hits.sort();
    assert!(
        hits.is_empty(),
        "ARCH-7b: `{needle}` must not appear under crates/ or bin/ (got {} hit(s)):\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}
