//! #596: test helpers must not persist a `tempfile::TempDir` past the test.
//!
//! `TempDir::drop` removes the directory. `mem::forget` on that guard, and
//! `TempDir::keep` / `TempDir::into_path`, detach the directory so it stays
//! under `/tmp` after the test binary exits. This gate scans test code and
//! fails on those calls unless the line (or the comment immediately above it)
//! carries `// tempdir_persist: <reason>`.
//!
//! Test code is the union of:
//!
//! 1. **Path rule** — any file under a `tests/` directory or named `tests.rs`
//!    (modules included from `#[cfg(test)] mod tests;`, which have no in-file
//!    `#[cfg(test)]`).
//! 2. **Line rule** — in every other file, lines on or after the first
//!    `#[cfg(test)]`.
//!
//! A hit counts only when the call targets a temp-dir guard: `mem::forget`'s
//! argument (also `Box::leak` / `ManuallyDrop::new`), or the receiver of
//! `.keep()` / `.into_path()`, is bound from `TempDir` / `tempdir(`, from a
//! wrapper (`TempDbPath`, `LoadFixture`, `BuiltTestServer`), or from a helper
//! that returns one of those. Callers that never spell `TempDir` are still
//! scanned. Destructured bindings are followed. `.keep()` / `.into_path()` are
//! matched after collapsing each whitespace run to a single space (so
//! `return dir.keep()` stays `return dir.keep()`, and a receiver on the
//! previous line still matches). Whitespace around `.` is allowed.
//! `.into_path_buf()` is not `.into_path()`.
//!
//! `// tempdir_persist: <reason>` on the hit line (including a trailing
//! comment) exempts only that line. A standalone `//` comment line
//! immediately above the hit also exempts it. Reasons inside string literals
//! do not count.
//!
//! This file is not scanned. It holds the detector fixtures.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as
//! `no_rvc_prefix.rs`.

use std::path::{Path, PathBuf};

/// Scanner source. Fixtures below would otherwise trip the workspace gate.
const SCANNER_REL: &str = "crates/architecture-tests/tests/no_tempdir_leak.rs";

/// Helpers named by #596. The walk must open each one (non-vacuity).
const MUST_SCAN: &[&str] = &[
    "crates/rvc/src/keymanager_adapters/tests/config.rs",
    "crates/rvc/src/keymanager_adapters/tests/server.rs",
    "crates/signer-server/tests/helpers.rs",
];

/// Types and helpers that own (or return) a temp-dir guard.
/// (`tempdir(` / `tempdir (` are matched separately — see [`contains_tempdir_call`].)
const GUARD_MARKERS: &[&str] = &[
    "TempDir",
    "TempDbPath",
    "LoadFixture",
    "BuiltTestServer",
    "make_temp_db_path",
    "make_service_with_db",
    "make_service_with_genesis",
    "make_service_with_db_unknown_key",
    "make_load_fixture",
    "build_test_server",
    "create_config_adapter_with_store",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    line: usize,
    kind: &'static str,
}

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
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn workspace_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        collect_rs(&root.join(base), &mut out);
    }
    out
}

fn is_test_path(rel: &str) -> bool {
    let path = Path::new(rel);
    if path.file_name().and_then(|s| s.to_str()) == Some("tests.rs") {
        return true;
    }
    path.components().any(|c| c.as_os_str() == "tests")
}

fn push_masked(out: &mut Vec<u8>, byte: u8) {
    out.push(if byte == b'\n' { b'\n' } else { b' ' });
}

fn ident_boundary_before(bytes: &[u8], i: usize) -> bool {
    i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
}

/// `r"…"`, `r#"…"#`, `br"…"`, `cr#"…"#`, … Returns true and advances `i` when
/// a raw string starts at `i`.
fn try_mask_raw_string(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> bool {
    if !ident_boundary_before(bytes, *i) {
        return false;
    }
    let mut j = *i;
    if matches!(bytes.get(j), Some(b'b' | b'B' | b'c' | b'C')) {
        j += 1;
    }
    if !matches!(bytes.get(j), Some(b'r' | b'R')) {
        return false;
    }
    j += 1;
    let mut hashes = 0usize;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return false;
    }
    j += 1;
    // Blank the opener (`br##"` etc.).
    while *i < j {
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    let closer = {
        let mut c = vec![b'"'];
        c.extend(std::iter::repeat_n(b'#', hashes));
        c
    };
    while *i < bytes.len() {
        if bytes[*i..].starts_with(&closer) {
            for _ in 0..closer.len() {
                push_masked(out, bytes[*i]);
                *i += 1;
            }
            return true;
        }
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    true
}

/// Cooked `"…"` or `b"…"` with escapes. Opener is at `i` (`"` or `b`/`B`).
fn mask_cooked_string(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) {
    if matches!(bytes.get(*i), Some(b'b' | b'B')) && bytes.get(*i + 1) == Some(&b'"') {
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    debug_assert_eq!(bytes.get(*i), Some(&b'"'));
    push_masked(out, b'"');
    *i += 1;
    while *i < bytes.len() {
        let ch = bytes[*i];
        if ch == b'\\' {
            push_masked(out, ch);
            *i += 1;
            if *i < bytes.len() {
                push_masked(out, bytes[*i]);
                *i += 1;
            }
            continue;
        }
        push_masked(out, ch);
        *i += 1;
        if ch == b'"' {
            break;
        }
    }
}

/// `'x'`, `'\n'`, `'"'`, `b'"'`. Lifetimes (`'a`, `'static`) return false.
fn try_mask_char_literal(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> bool {
    if !ident_boundary_before(bytes, *i) {
        return false;
    }
    let mut j = *i;
    if matches!(bytes.get(j), Some(b'b' | b'B')) {
        j += 1;
    }
    if bytes.get(j) != Some(&b'\'') {
        return false;
    }
    let body = j + 1;
    if bytes.get(body) == Some(&b'\\') {
        // Escaped char: scan to the closing `'`.
        let mut k = body + 2;
        while k < bytes.len() && bytes[k] != b'\'' {
            if bytes[k] == b'\n' {
                return false;
            }
            k += 1;
        }
        if k >= bytes.len() {
            return false;
        }
        while *i <= k {
            push_masked(out, bytes[*i]);
            *i += 1;
        }
        return true;
    }
    // Single-byte body + closing quote (covers '"' and b'"').
    if bytes.get(body).is_some()
        && bytes.get(body) != Some(&b'\'')
        && bytes.get(body + 1) == Some(&b'\'')
    {
        let end = body + 1;
        while *i <= end {
            push_masked(out, bytes[*i]);
            *i += 1;
        }
        return true;
    }
    false
}

/// Replace comments and string/char/raw-string contents with spaces. Newlines
/// and byte length stay put so line numbers still match the original file.
fn mask_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Line comment
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Nested block comment
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    depth += 1;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    depth -= 1;
                } else {
                    push_masked(&mut out, bytes[i]);
                    i += 1;
                }
            }
            continue;
        }
        // Raw string (r"…", r#"…"#, br#"…"#, …)
        if try_mask_raw_string(bytes, &mut out, &mut i) {
            continue;
        }
        // Cooked byte string b"…"
        if matches!(bytes.get(i), Some(b'b' | b'B'))
            && bytes.get(i + 1) == Some(&b'"')
            && ident_boundary_before(bytes, i)
        {
            mask_cooked_string(bytes, &mut out, &mut i);
            continue;
        }
        // Cooked string "…"
        if bytes[i] == b'"' {
            mask_cooked_string(bytes, &mut out, &mut i);
            continue;
        }
        // Char / byte-char literal; lifetimes fall through.
        if try_mask_char_literal(bytes, &mut out, &mut i) {
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    debug_assert_eq!(out.len(), bytes.len());
    String::from_utf8(out).expect("masking preserves UTF-8")
}

fn function_name(line: &str) -> Option<&str> {
    let mut t = line.trim_start();
    if t.starts_with("const ") || t.starts_with("static ") {
        return None;
    }
    if let Some(rest) = t.strip_prefix("pub") {
        t = rest.trim_start();
        if let Some(rest) = t.strip_prefix('(') {
            let after = rest.find(')')?;
            t = rest[after + 1..].trim_start();
        }
    }
    t = t.strip_prefix("async ").unwrap_or(t).trim_start();
    t = t.strip_prefix("unsafe ").unwrap_or(t).trim_start();
    t = t.strip_prefix("fn ")?.trim_start();
    let name = t.split(|c: char| c == '(' || c == '<' || c.is_whitespace()).next()?;
    if name.is_empty() {
        return None;
    }
    Some(name)
}

struct FnSpan {
    start: usize,
    end: usize,
}

fn extract_functions(lines: &[&str]) -> Vec<FnSpan> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if function_name(lines[i]).is_none() {
            i += 1;
            continue;
        }
        let mut brace_line = None;
        let mut signature_only = false;
        let search_end = lines.len().min(i + 40);
        for (k, line) in lines.iter().enumerate().take(search_end).skip(i) {
            if line.contains('{') {
                brace_line = Some(k);
                break;
            }
            if line.contains(';') {
                signature_only = true;
                break;
            }
        }
        if signature_only {
            i += 1;
            continue;
        }
        let Some(brace_line) = brace_line else {
            i += 1;
            continue;
        };
        let mut depth = 0i32;
        let mut end = brace_line;
        let mut closed = false;
        for (k, line) in lines.iter().enumerate().skip(brace_line) {
            for ch in line.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = k;
                            closed = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if closed {
                break;
            }
        }
        out.push(FnSpan { start: i, end });
        i = end + 1;
    }
    out
}

/// Skip one raw/cooked string or char literal starting at `i` on a single line.
/// Returns the new index, or `None` if `i` is not such a start.
fn skip_line_literal(bytes: &[u8], i: usize) -> Option<usize> {
    let mut scratch = Vec::new();
    let mut j = i;
    if try_mask_raw_string(bytes, &mut scratch, &mut j) {
        return Some(j);
    }
    if matches!(bytes.get(i), Some(b'b' | b'B'))
        && bytes.get(i + 1) == Some(&b'"')
        && ident_boundary_before(bytes, i)
    {
        mask_cooked_string(bytes, &mut scratch, &mut j);
        return Some(j);
    }
    if bytes.get(i) == Some(&b'"') {
        mask_cooked_string(bytes, &mut scratch, &mut j);
        return Some(j);
    }
    if try_mask_char_literal(bytes, &mut scratch, &mut j) {
        return Some(j);
    }
    None
}

/// `//` comment text on this line, ignoring `//` inside string/char literals.
fn line_comment(line: &str) -> Option<&str> {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if let Some(next) = skip_line_literal(b, i) {
            i = next;
            continue;
        }
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            return Some(&line[i..]);
        }
        i += 1;
    }
    None
}

fn has_persist_reason(line: &str) -> bool {
    let Some(comment) = line_comment(line) else {
        return false;
    };
    let Some((_, rest)) = comment.split_once("tempdir_persist:") else {
        return false;
    };
    !rest.trim().is_empty()
}

fn is_standalone_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn annotated(lines: &[&str], idx: usize) -> bool {
    // Trailing (or whole-line) comment on the hit line exempts only this line.
    if has_persist_reason(lines[idx]) {
        return true;
    }
    // The line above counts only when it is a standalone `//` comment line.
    idx > 0 && is_standalone_comment_line(lines[idx - 1]) && has_persist_reason(lines[idx - 1])
}

fn contains_tempdir_call(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(rel) = text[search..].find("tempdir") {
        let at = search + rel;
        let before_ok = at == 0 || {
            let prev = text[..at].chars().next_back().unwrap();
            !is_ident_char(prev)
        };
        let mut j = at + "tempdir".len();
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if before_ok && j < bytes.len() && bytes[j] == b'(' {
            return true;
        }
        search = at + "tempdir".len();
    }
    false
}

fn is_guard_source(text: &str) -> bool {
    GUARD_MARKERS.iter().any(|m| text.contains(m)) || contains_tempdir_call(text)
}

/// Direct `TempDir` / `tempdir(` / `tempdir (` construction (not wrapper helpers).
fn is_tempdir_type(text: &str) -> bool {
    text.contains("TempDir") || contains_tempdir_call(text)
}

/// Statement/expression text immediately before a collapsed offset.
fn expression_before(collapsed: &str, at: usize) -> &str {
    let before = &collapsed[..at];
    let start = before.rfind([';', '{', '}']).map(|i| i + 1).unwrap_or(0);
    &collapsed[start..at]
}

fn is_ident_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(is_ident_char)
}

fn pattern_binds_ident(pattern: &str, ident: &str) -> bool {
    let mut search = 0;
    while let Some(rel) = pattern[search..].find(ident) {
        let at = search + rel;
        let before_ok = at == 0 || !is_ident_char(pattern[..at].chars().next_back().unwrap());
        let after = at + ident.len();
        let after_ok =
            after >= pattern.len() || !is_ident_char(pattern[after..].chars().next().unwrap());
        if before_ok && after_ok {
            return true;
        }
        search = at + 1;
    }
    false
}

fn binding_statement(func: &str, ident: &str) -> Option<String> {
    let mut search = 0;
    while let Some(rel) = func[search..].find("let ") {
        let at = search + rel;
        let tail = &func[at..];
        let end = tail.find(';').map(|p| p + 1).unwrap_or(tail.len());
        let stmt = &tail[..end];
        if let Some(eq) = stmt.find('=') {
            let pattern = &stmt["let ".len()..eq];
            if pattern_binds_ident(pattern, ident) {
                return Some(stmt.to_string());
            }
        }
        search = at + 4;
    }
    None
}

fn binding_is_tempdir(func: &str, ident: &str) -> bool {
    binding_statement(func, ident).is_some_and(|stmt| is_guard_source(&stmt))
}

fn call_arg<'a>(line: &'a str, call: &str) -> Option<&'a str> {
    let idx = line.find(call)?;
    let rest = &line[idx + call.len()..];
    let end = rest.find(')')?;
    Some(rest[..end].trim())
}

fn idents_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if is_ident_char(ch) {
            cur.push(ch);
        } else if !cur.is_empty() {
            if is_ident(&cur) {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if !cur.is_empty() && is_ident(&cur) {
        out.push(cur);
    }
    out
}

fn arg_is_guard(func: &str, arg: &str) -> bool {
    if is_guard_source(arg) {
        return true;
    }
    if is_ident(arg) {
        return binding_is_tempdir(func, arg);
    }
    idents_in(arg).into_iter().any(|id| binding_is_tempdir(func, &id))
}

fn forgets_tempdir(func: &str, line: &str) -> bool {
    const CALLS: &[&str] = &["mem::forget(", "Box::leak(", "ManuallyDrop::new("];
    for call in CALLS {
        if !line.contains(call) {
            continue;
        }
        match call_arg(line, call) {
            Some(arg) => {
                if arg_is_guard(func, arg) {
                    return true;
                }
            }
            // Multiline call. Fail closed when this function builds a guard.
            None => {
                if is_guard_source(func) {
                    return true;
                }
            }
        }
    }
    false
}

fn leak_kind(line: &str) -> &'static str {
    if line.contains("Box::leak(") {
        "Box::leak"
    } else if line.contains("ManuallyDrop::new(") {
        "ManuallyDrop::new"
    } else {
        "mem::forget"
    }
}

fn trailing_ident(before: &str) -> Option<String> {
    let before = before.trim_end();
    let ident: String = before
        .chars()
        .rev()
        .take_while(|c| is_ident_char(*c))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if ident.is_empty() {
        None
    } else {
        Some(ident)
    }
}

fn push_collapsed_char(
    ch: char,
    li: usize,
    collapsed: &mut String,
    line_of: &mut Vec<usize>,
    last_was_space: &mut bool,
) {
    if ch.is_whitespace() {
        if !*last_was_space && !collapsed.is_empty() {
            collapsed.push(' ');
            line_of.push(li);
        }
        *last_was_space = true;
        return;
    }
    let mut buf = [0u8; 4];
    let enc = ch.encode_utf8(&mut buf);
    for _ in enc.as_bytes() {
        line_of.push(li);
    }
    collapsed.push_str(enc);
    *last_was_space = false;
}

/// Collapse each whitespace run to a single space. `line_of[i]` is the
/// function-local line for **byte** offset `i` in the collapsed string.
fn collapse_ws_with_lines(lines: &[&str]) -> (String, Vec<usize>) {
    let mut collapsed = String::new();
    let mut line_of = Vec::new();
    let mut last_was_space = false;
    for (li, line) in lines.iter().enumerate() {
        for ch in line.chars() {
            push_collapsed_char(ch, li, &mut collapsed, &mut line_of, &mut last_was_space);
        }
        if li + 1 < lines.len() {
            push_collapsed_char('\n', li, &mut collapsed, &mut line_of, &mut last_was_space);
        }
    }
    debug_assert_eq!(collapsed.len(), line_of.len());
    (collapsed, line_of)
}

/// Find `.name()` / `.name::<…>()` allowing spaces around `.` and inside `()`.
/// Returns byte offsets `(dot, after_close_paren)` in the collapsed text.
fn find_dotted_call(collapsed: &str, name: &str, search_from: usize) -> Option<(usize, usize)> {
    let bytes = collapsed.as_bytes();
    let mut search = search_from;
    while search < collapsed.len() {
        let rel = collapsed[search..].find(name)?;
        let name_at = search + rel;
        // Reject prefix matches (`keeper`, `into_path_buf`).
        let after_name = name_at + name.len();
        if after_name < bytes.len()
            && (bytes[after_name].is_ascii_alphanumeric() || bytes[after_name] == b'_')
        {
            search = after_name;
            continue;
        }
        let before = collapsed[..name_at].trim_end();
        if !before.ends_with('.') {
            search = after_name;
            continue;
        }
        let dot_at = before.len() - 1;
        if !collapsed[dot_at + 1..name_at].bytes().all(|b| b == b' ') {
            search = after_name;
            continue;
        }
        let mut pos = after_name;
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }
        // Optional turbofish: `:: < … >`
        if bytes.get(pos..).is_some_and(|s| s.starts_with(b"::")) {
            pos += 2;
            while pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'<' {
                let mut depth = 0i32;
                while pos < bytes.len() {
                    match bytes[pos] {
                        b'<' => depth += 1,
                        b'>' => {
                            depth -= 1;
                            pos += 1;
                            if depth == 0 {
                                break;
                            }
                            continue;
                        }
                        _ => {}
                    }
                    pos += 1;
                }
                while pos < bytes.len() && bytes[pos] == b' ' {
                    pos += 1;
                }
            }
        }
        if pos >= bytes.len() || bytes[pos] != b'(' {
            search = after_name;
            continue;
        }
        pos += 1;
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] != b')' {
            search = after_name;
            continue;
        }
        pos += 1;
        return Some((dot_at, pos));
    }
    None
}

struct CollapsedScan<'a> {
    func: &'a str,
    collapsed: &'a str,
    line_of: &'a [usize],
    span_start: usize,
    original_lines: &'a [&'a str],
    n: usize,
}

fn persists_tempdir_collapsed(
    scan: &CollapsedScan<'_>,
    method_name: &str,
    kind: &'static str,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut search = 0;
    while let Some((dot_at, end)) = find_dotted_call(scan.collapsed, method_name, search) {
        let local_line = scan.line_of.get(dot_at).copied().unwrap_or(0);
        let file_idx = scan.span_start + local_line;
        if file_idx < scan.n && !annotated(scan.original_lines, file_idx) {
            let expr = expression_before(scan.collapsed, dot_at);
            let recv = trailing_ident(expr);
            // Named receiver → follow its binding (destructured helpers included).
            // No/paren receiver → only flag when this expression builds a TempDir
            // (e.g. TempDir::new().unwrap().into_path()), not merely because the
            // enclosing function mentioned a helper earlier.
            let is_hit = match recv.as_deref() {
                Some(r) if binding_is_tempdir(scan.func, r) => true,
                Some(_) => false,
                None => is_tempdir_type(expr),
            };
            if is_hit {
                hits.push(Hit { line: file_idx + 1, kind });
            }
        }
        search = end;
    }
    hits
}

fn hits_in(rel: &str, src: &str) -> Vec<Hit> {
    let masked = mask_comments_and_strings(src);
    let masked_lines: Vec<&str> = masked.lines().collect();
    let original_lines: Vec<&str> = src.lines().collect();
    // Masking keeps newlines, so the two splits have the same length.
    let n = masked_lines.len().min(original_lines.len());
    let scope_from = if is_test_path(rel) {
        0
    } else {
        match masked_lines.iter().position(|l| l.contains("#[cfg(test)]")) {
            Some(i) => i,
            None => return Vec::new(),
        }
    };
    let mut hits = Vec::new();
    for span in extract_functions(&masked_lines[..n]) {
        if span.start < scope_from {
            continue;
        }
        let func_lines = &masked_lines[span.start..=span.end];
        let func = func_lines.join("\n");
        // Scan any function that mentions a guard type/helper — including callers
        // that never spell `TempDir` (T5: make_service_with_db → TempDbPath).
        if !is_guard_source(&func) {
            continue;
        }
        let (collapsed, line_of) = collapse_ws_with_lines(func_lines);
        for (idx, line) in masked_lines.iter().enumerate().take(span.end + 1).skip(span.start) {
            if annotated(&original_lines[..n], idx) {
                continue;
            }
            if forgets_tempdir(&func, line) {
                hits.push(Hit { line: idx + 1, kind: leak_kind(line) });
            }
        }
        let scan = CollapsedScan {
            func: &func,
            collapsed: &collapsed,
            line_of: &line_of,
            span_start: span.start,
            original_lines: &original_lines[..n],
            n,
        };
        hits.extend(persists_tempdir_collapsed(&scan, "keep", ".keep()"));
        hits.extend(persists_tempdir_collapsed(&scan, "into_path", ".into_path()"));
    }
    hits
}

fn format_hits(rel: &str, hits: &[Hit]) -> Vec<String> {
    hits.iter().map(|h| format!("{rel}:{}: {}", h.line, h.kind)).collect()
}

#[test]
fn detector_flags_unannotated_tempdir_persist() {
    let forget = r#"
        fn leak_forget() {
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", forget);
    assert_eq!(hits, vec![Hit { line: 4, kind: "mem::forget" }]);

    let keep = r#"
        fn leak_keep() {
            let dir = TempDir::new().unwrap();
            let _path = dir.keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", keep);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".keep()" }]);

    let into_path = r#"
        fn leak_into_path() {
            let dir = tempfile::tempdir().unwrap();
            let _path = dir.into_path();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", into_path);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".into_path()" }]);

    let chained = r#"
        fn leak_chained() {
            let _path = TempDir::new().unwrap().into_path();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", chained);
    assert_eq!(hits, vec![Hit { line: 3, kind: ".into_path()" }]);
}

#[test]
fn detector_flags_t5_forget_helper_guard_without_tempdir_mention() {
    // Caller never spells TempDir; the guard is TempDbPath from the helper.
    let forget_db = r#"
        fn leak_forget_db_path() {
            let (_svc, _db_path) = make_service_with_db();
            std::mem::forget(_db_path);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", forget_db);
    assert_eq!(hits, vec![Hit { line: 4, kind: "mem::forget" }]);

    let forget_fixture = r#"
        fn leak_load_fixture() {
            let fixture = make_load_fixture();
            std::mem::forget(fixture);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", forget_fixture);
    assert_eq!(hits, vec![Hit { line: 4, kind: "mem::forget" }]);

    let forget_server = r#"
        fn leak_built_server() {
            let server = build_test_server();
            std::mem::forget(server);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", forget_server);
    assert_eq!(hits, vec![Hit { line: 4, kind: "mem::forget" }]);

    let box_leak = r#"
        fn leak_box() {
            let (_svc, db_path) = make_service_with_db();
            let _ = Box::leak(Box::new(db_path));
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", box_leak);
    assert_eq!(hits, vec![Hit { line: 4, kind: "Box::leak" }]);

    let manually_drop = r#"
        fn leak_manually_drop() {
            let server = build_test_server();
            let _md = std::mem::ManuallyDrop::new(server);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", manually_drop);
    assert_eq!(hits, vec![Hit { line: 4, kind: "ManuallyDrop::new" }]);
}

#[test]
fn detector_flags_t7_destructured_helper_binding() {
    let keep = r#"
        fn leak_destructured_keep() {
            let (leaky, _x) = make_temp_db_path();
            let _path = leaky.keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", keep);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".keep()" }]);

    let into_path = r#"
        fn leak_destructured_into_path() {
            let (leaky, _x) = make_temp_db_path();
            let _path = leaky.into_path();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", into_path);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".into_path()" }]);
}

#[test]
fn detector_flags_t9_method_on_line_after_receiver() {
    let keep = r#"
        fn leak_multiline_keep() {
            let dir = TempDir::new().unwrap();
            let _path = dir
                .keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", keep);
    assert_eq!(hits, vec![Hit { line: 5, kind: ".keep()" }]);

    let into_path = r#"
        fn leak_multiline_into_path() {
            let dir = tempfile::tempdir().unwrap();
            let _path = dir
                .into_path();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", into_path);
    assert_eq!(hits, vec![Hit { line: 5, kind: ".into_path()" }]);
}

#[test]
fn detector_flags_return_and_break_keep() {
    // Deleting all whitespace glued `return`/`break` onto the receiver
    // (`returndir`); collapsing runs to a single space keeps the boundary.
    let ret = r#"
        fn leak_return_keep() {
            let dir = TempDir::new().unwrap();
            return dir.keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", ret);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".keep()" }]);

    let brk = r#"
        fn leak_break_keep() {
            let dir = TempDir::new().unwrap();
            loop {
                break dir.keep();
            }
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", brk);
    assert_eq!(hits, vec![Hit { line: 5, kind: ".keep()" }]);
}

#[test]
fn detector_maps_hits_after_non_ascii_prefix() {
    // Char-indexed line maps + `unwrap_or(0)` attributed `.keep()` to the fn
    // line; a `tempdir_persist` comment above the fn then suppressed the leak.
    let src = r#"
        // tempdir_persist: owned by a different site, not this leak
        fn leak_after_unicode() {
            let ラベル = 1;
            let dir = TempDir::new().unwrap();
            let _path = dir.keep();
            let _ = ラベル;
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", src);
    assert_eq!(hits, vec![Hit { line: 6, kind: ".keep()" }]);
}

#[test]
fn detector_trailing_comment_does_not_exempt_next_line() {
    let src = r#"
        fn two_keeps() {
            let a = TempDir::new().unwrap();
            let b = TempDir::new().unwrap();
            let _ = a.keep(); // tempdir_persist: intentional for a only
            let _ = b.keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", src);
    assert_eq!(hits, vec![Hit { line: 6, kind: ".keep()" }]);
}

#[test]
fn detector_flags_keep_turbofish_and_spaced_tempdir_call() {
    let turbo = r#"
        fn leak_turbofish() {
            let dir = TempDir::new().unwrap();
            let _path = dir.keep::<()>();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", turbo);
    assert_eq!(hits, vec![Hit { line: 4, kind: ".keep()" }]);

    let spaced = r#"
        fn leak_spaced_tempdir() {
            let dir = tempfile::tempdir ().unwrap();
            std::mem::forget(dir);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", spaced);
    assert_eq!(hits, vec![Hit { line: 4, kind: "mem::forget" }]);
}

#[test]
fn detector_lexer_keeps_bindings_after_raw_string_and_char_quote() {
    // Embedded `"` in a raw string must not blank the rest of the function.
    let after_raw = r##"
        fn leak_after_raw() {
            let _toml = r#"
fee_recipient = "0xabc"
"#;
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
    "##;
    let hits = hits_in("crates/example/tests/fixture.rs", after_raw);
    assert_eq!(hits, vec![Hit { line: 7, kind: "mem::forget" }]);

    // `'"'` / `b'"'` char literals must not open a cooked string.
    let after_char = r#"
        fn leak_after_char_quote() {
            let _q = '"';
            let _bq = b'"';
            let dir = TempDir::new().unwrap();
            let _path = dir.keep();
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", after_char);
    assert_eq!(hits, vec![Hit { line: 6, kind: ".keep()" }]);

    // Lifetimes are not char literals; code after `'a` stays visible.
    let after_lifetime = r#"
        fn leak_after_lifetime<'a>(x: &'a str) {
            let _ = x;
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", after_lifetime);
    assert_eq!(hits, vec![Hit { line: 5, kind: "mem::forget" }]);

    // Nested block comments.
    let nested = r#"
        fn leak_after_nested_comment() {
            /* outer /* inner */ still comment */
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
    "#;
    let hits = hits_in("crates/example/tests/fixture.rs", nested);
    assert_eq!(hits, vec![Hit { line: 5, kind: "mem::forget" }]);

    // br#"…"# raw byte string with embedded quotes.
    let br_raw = r##"
        fn leak_after_br_raw() {
            let _b = br#"say "hi""#;
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
    "##;
    let hits = hits_in("crates/example/tests/fixture.rs", br_raw);
    assert_eq!(hits, vec![Hit { line: 5, kind: "mem::forget" }]);
}

#[test]
fn detector_allows_annotated_and_unrelated_calls() {
    let annotated = r#"
        fn kept() {
            let dir = TempDir::new().unwrap();
            // tempdir_persist: process-lifetime fixture shared with a child
            std::mem::forget(dir);
        }
    "#;
    assert!(hits_in("crates/example/tests/fixture.rs", annotated).is_empty());

    let same_line = r#"
        fn kept() {
            let dir = TempDir::new().unwrap();
            let _path = dir.keep(); // tempdir_persist: asserted by an external process
        }
    "#;
    assert!(hits_in("crates/example/tests/fixture.rs", same_line).is_empty());

    let empty_reason = r#"
        fn leak() {
            let dir = TempDir::new().unwrap();
            // tempdir_persist:
            std::mem::forget(dir);
        }
    "#;
    assert_eq!(
        hits_in("crates/example/tests/fixture.rs", empty_reason),
        vec![Hit { line: 5, kind: "mem::forget" }]
    );

    let other_forget = r#"
        fn not_a_tempdir() {
            let dir = TempDir::new().unwrap();
            let boxed = Box::new(1u8);
            std::mem::forget(boxed);
            drop(dir);
        }
    "#;
    assert!(hits_in("crates/example/tests/fixture.rs", other_forget).is_empty());

    let into_path_buf = r#"
        fn path_buf_is_not_into_path() {
            let dir = TempDir::new().unwrap();
            let _p = dir.path().to_path_buf();
            let _q = something.into_path_buf();
        }
    "#;
    assert!(hits_in("crates/example/tests/fixture.rs", into_path_buf).is_empty());

    let comment_only = r#"
        fn comment() {
            let dir = TempDir::new().unwrap();
            // std::mem::forget(dir); dir.keep(); dir.into_path();
            drop(dir);
        }
    "#;
    assert!(hits_in("crates/example/tests/fixture.rs", comment_only).is_empty());

    // T10: `tempdir_persist` inside a string is not an annotation.
    let string_annotation = r#"
        fn leak_string_annotation() {
            let dir = TempDir::new().unwrap();
            let _ = "tempdir_persist: not a real annotation";
            std::mem::forget(dir);
        }
    "#;
    assert_eq!(
        hits_in("crates/example/tests/fixture.rs", string_annotation),
        vec![Hit { line: 5, kind: "mem::forget" }]
    );

    // Production code above the first `#[cfg(test)]` is out of scope.
    let split = r#"
        fn production() {
            let dir = TempDir::new().unwrap();
            std::mem::forget(dir);
        }
        #[cfg(test)]
        mod tests {
            fn leak() {
                let dir = TempDir::new().unwrap();
                std::mem::forget(dir);
            }
        }
    "#;
    let hits = hits_in("crates/example/src/lib.rs", split);
    assert_eq!(hits, vec![Hit { line: 10, kind: "mem::forget" }]);
}

#[test]
fn test_helpers_do_not_leak_tempdirs() {
    let root = workspace_root();
    let files = workspace_rs_files(&root);
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());

    let mut scanned = 0usize;
    let mut saw_must = [false; MUST_SCAN.len()];
    let mut violations = Vec::new();
    for file in files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == SCANNER_REL {
            continue;
        }
        let src = std::fs::read_to_string(&file).unwrap_or_default();
        let in_scope =
            is_test_path(&rel) || mask_comments_and_strings(&src).contains("#[cfg(test)]");
        if !in_scope {
            continue;
        }
        scanned += 1;
        for (i, must) in MUST_SCAN.iter().enumerate() {
            if rel == *must {
                saw_must[i] = true;
            }
        }
        violations.extend(format_hits(&rel, &hits_in(&rel, &src)));
    }
    assert!(scanned > 80, "scanned only {scanned} test-scoped files; walk likely broke");
    for (i, must) in MUST_SCAN.iter().enumerate() {
        assert!(saw_must[i], "scan missed {must}");
    }
    violations.sort();
    assert!(
        violations.is_empty(),
        "test code persists a TempDir (annotate with `// tempdir_persist: <reason>`):\n{}",
        violations.join("\n")
    );
}
