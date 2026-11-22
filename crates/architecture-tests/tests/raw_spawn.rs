//! G-4 / ARCH-2k: ban raw `tokio::spawn` outside `TaskExecutor` and a shrinking allow-list.
//!
//! Path-scoped to `crates/rvc/src/**`, `bin/rvc/src/**`, and `crates/bn-manager/src/**`.
//! Production hits must live only in `crates/rvc/src/bootstrap/executor.rs` (the composition-root
//! executor) or on the shrinking-only [`ALLOW_LIST`]. [`ALLOW_LIST`] is empty.
//!
//! A hit is test code only when one of these holds:
//!
//! 1. **Path rule (VD-2c)** — the file is under `src/**/tests/` or named `tests.rs`. Some test
//!    modules are gated externally (`#[cfg(test)] mod tests;` in
//!    `crates/rvc/src/orchestrator/coordinator/mod.rs`) and contain no in-file `#[cfg(test)]`.
//! 2. **Item rule** — the call sits in a `#[cfg(test)]` or `#[cfg(all(…, test, …))]` module, or in
//!    a module-level item whose attributes include `#[cfg(test)]`, `#[test]`, or `#[tokio::test]`.
//!    `any(…)` is not a test cfg. A `#[cfg(test)]` use does not cover the next item. Code after a
//!    test module is scanned.
//!
//! Tokens come from `ra_ap_rustc_lexer`. An unterminated literal, a shebang, or a mask
//! disagreement is one untrusted hit. A `// detached:` line comment that starts its line
//! classifies a `crates/bn-manager` spawn. The same text elsewhere does not.
//! `crates/keymanager-api` stays outside the scan.
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

use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, LiteralKind, TokenKind};
use rvc_architecture_tests::{non_code_spans, SourceItems};

// ---------------------------------------------------------------------------
// Ban list — free-function names that count as raw spawns
// ---------------------------------------------------------------------------

/// Paths matched as raw spawns. `spawn_blocking` / `spawn_local` must never appear here.
const BAN_LIST: &[&str] = &["tokio::spawn", "tokio::task::spawn"];

/// Production `crates/bn-manager` spawns classified by a preceding `// detached:` comment.
/// Shrinking this means a spawn was removed. Growing it means a new raw spawn landed.
const DETACHED_BN_SPAWNS: usize = 6;

/// Nesting limit for braces, items, and header parentheses, brackets, and angles.
/// Past this the file is one untrusted hit.
const MAX_DEPTH: usize = 256;

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

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|err| format!("{}: cannot read scan directory: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("{}: {err}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out)?;
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
}

/// `crates/rvc/src/**/*.rs`, `bin/rvc/src/**/*.rs`, and `crates/bn-manager/src/**/*.rs`.
fn scan_root_rs_files(root: &Path) -> (Vec<PathBuf>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for rel in ["crates/rvc/src", "bin/rvc/src", "crates/bn-manager/src"] {
        let dir = root.join(rel);
        if !dir.is_dir() {
            errors.push(format!("{rel}: scan root is missing"));
            continue;
        }
        if let Err(err) = collect_rs(&dir, &mut out) {
            errors.push(err);
        }
    }
    (out, errors)
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

// ---------------------------------------------------------------------------
// Lexer. A failed lex is the trust boundary: one hit, nothing dropped.
// ---------------------------------------------------------------------------

type Tok = (usize, usize, TokenKind);

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

fn lex_file(src: &str) -> Result<Vec<Tok>, &'static str> {
    // A shebang is not a Rust token. Rejecting the file is fail-closed. This
    // check does not classify a spawn.
    let first = src.lines().next().unwrap_or("");
    if first.starts_with("#!") && !first.starts_with("#![") {
        return Err("shebang");
    }
    let mut pos = 0usize;
    let mut toks = Vec::new();
    let mut masked: Vec<Masked> = Vec::new();
    for tok in tokenize(src, FrontmatterAllowed::No) {
        let len = tok.len as usize;
        let end = pos.saturating_add(len);
        if len == 0 || end > src.len() || !src.is_char_boundary(end) {
            return Err("token stream broke");
        }
        let (mask, bad, char_lit) = match tok.kind {
            TokenKind::LineComment { .. } => (true, false, false),
            TokenKind::BlockComment { terminated, .. } => (true, !terminated, false),
            TokenKind::Unknown
            | TokenKind::InvalidIdent
            | TokenKind::GuardedStrPrefix
            | TokenKind::UnknownPrefix
            | TokenKind::UnknownPrefixLifetime => (false, true, false),
            TokenKind::Literal { kind, .. } => match lit_unterminated(kind) {
                Some(bad) => {
                    let char_lit = matches!(
                        kind,
                        LiteralKind::Char { terminated: true }
                            | LiteralKind::Byte { terminated: true }
                    );
                    (true, bad, char_lit)
                }
                None => (false, false, false),
            },
            _ => (false, false, false),
        };
        if bad {
            return Err("unterminated or unknown token");
        }
        if mask {
            masked.push(Masked { start: pos, end, char_lit });
        }
        toks.push((pos, end, tok.kind));
        pos = end;
    }
    if pos != src.len() {
        return Err("token stream did not cover the file");
    }
    if !masks_agree(&masked, &non_code_spans(src)) {
        return Err("lexer mask disagreed");
    }
    Ok(toks)
}

struct Masked {
    start: usize,
    end: usize,
    char_lit: bool,
}

fn masks_agree(masked: &[Masked], spans: &[(usize, usize)]) -> bool {
    let mut j = 0usize;
    for span in masked {
        if j < spans.len() && spans[j] == (span.start, span.end) {
            j += 1;
            continue;
        }
        if !span.char_lit || (j < spans.len() && spans[j].0 < span.end) {
            return false;
        }
    }
    j == spans.len()
}

fn is_gap(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Whitespace | TokenKind::LineComment { .. } | TokenKind::BlockComment { .. }
    )
}

fn next_solid(toks: &[Tok], mut i: usize) -> usize {
    while i < toks.len() && is_gap(toks[i].2) {
        i += 1;
    }
    i
}

/// Keyword or path segment. `Ident` only: a raw ident is not `test`, `any`, `fn`, or `cfg`.
fn word<'a>(src: &'a str, toks: &[Tok], i: usize) -> Option<&'a str> {
    let tok = toks.get(i)?;
    if !matches!(tok.2, TokenKind::Ident) {
        return None;
    }
    src.get(tok.0..tok.1)
}

fn word_is(src: &str, toks: &[Tok], i: usize, want: &str) -> bool {
    word(src, toks, i) == Some(want)
}

/// `Ident` or `RawIdent` with `r#` removed. Spawn paths count; keywords do not use this.
fn call_word<'a>(src: &'a str, tok: &Tok) -> Option<&'a str> {
    let text = src.get(tok.0..tok.1)?;
    match tok.2 {
        TokenKind::Ident => Some(text),
        TokenKind::RawIdent => text.strip_prefix("r#").filter(|rest| !rest.is_empty()),
        _ => None,
    }
}

fn is_name(src: &str, tok: &Tok) -> bool {
    call_word(src, tok).is_some()
}

/// `tokio::spawn` or `tokio::task::spawn`, whatever token follows the path.
fn is_spawn_path(src: &str, toks: &[Tok], i: usize) -> bool {
    if toks.get(i).is_none_or(|tok| call_word(src, tok) != Some("tokio")) {
        return false;
    }
    let c1 = next_solid(toks, i + 1);
    let c2 = next_solid(toks, c1 + 1);
    if !matches!(toks.get(c1).map(|t| t.2), Some(TokenKind::Colon))
        || !matches!(toks.get(c2).map(|t| t.2), Some(TokenKind::Colon))
    {
        return false;
    }
    let name = next_solid(toks, c2 + 1);
    let Some(tok) = toks.get(name) else {
        return false;
    };
    if call_word(src, tok) == Some("spawn") {
        return true;
    }
    if call_word(src, tok) != Some("task") {
        return false;
    }
    let c3 = next_solid(toks, name + 1);
    let c4 = next_solid(toks, c3 + 1);
    let spawn = next_solid(toks, c4 + 1);
    matches!(toks.get(c3).map(|t| t.2), Some(TokenKind::Colon))
        && matches!(toks.get(c4).map(|t| t.2), Some(TokenKind::Colon))
        && toks.get(spawn).is_some_and(|tok| call_word(src, tok) == Some("spawn"))
}

fn brace_ends(toks: &[Tok]) -> Result<Vec<Option<usize>>, ()> {
    let mut ends = vec![None; toks.len()];
    let mut stack = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        match tok.2 {
            TokenKind::OpenBrace => {
                if stack.len() >= MAX_DEPTH {
                    return Err(());
                }
                stack.push(i);
            }
            TokenKind::CloseBrace => {
                let Some(open) = stack.pop() else {
                    return Err(());
                };
                ends[open] = Some(i);
            }
            _ => {}
        }
    }
    Ok(ends)
}

fn matching_delim(
    toks: &[Tok],
    open: usize,
    open_kind: TokenKind,
    close_kind: TokenKind,
) -> Option<usize> {
    let mut depth = 0usize;
    for (i, tok) in toks.iter().enumerate().skip(open) {
        if tok.2 == open_kind {
            depth += 1;
            if depth > MAX_DEPTH {
                return None;
            }
        } else if tok.2 == close_kind {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn attr_close(toks: &[Tok], open_bracket: usize) -> Option<usize> {
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    for (i, tok) in toks.iter().enumerate().skip(open_bracket) {
        match tok.2 {
            TokenKind::OpenParen => paren += 1,
            TokenKind::CloseParen => paren -= 1,
            TokenKind::OpenBracket => bracket += 1,
            TokenKind::CloseBracket => {
                bracket -= 1;
                if paren == 0 && bracket == 0 && brace == 0 {
                    return Some(i);
                }
            }
            TokenKind::OpenBrace => brace += 1,
            TokenKind::CloseBrace => brace -= 1,
            _ => {}
        }
        if paren < 0 || bracket < 0 || brace < 0 {
            return None;
        }
        if paren as usize > MAX_DEPTH || bracket as usize > MAX_DEPTH || brace as usize > MAX_DEPTH
        {
            return None;
        }
    }
    None
}

/// Bare `test` as a cfg predicate: the next solid token ends the predicate.
/// `test = "…"`, `test(...)`, and `test::…` are not `cfg(test)`.
fn boolean_test(src: &str, toks: &[Tok], i: usize, limit: usize) -> bool {
    if !word_is(src, toks, i, "test") {
        return false;
    }
    let next = next_solid(toks, i + 1);
    next >= limit || matches!(toks[next].2, TokenKind::Comma | TokenKind::CloseParen)
}

/// `cfg(test)` and `cfg(test, …)` are test. `any` and `not` are not.
/// `all(…)` is test only when a boolean `test` sits directly inside `all`.
fn cfg_is_test(src: &str, toks: &[Tok], from: usize, to: usize) -> bool {
    let first = next_solid(toks, from);
    if first >= to {
        return false;
    }
    if word_is(src, toks, first, "any") || word_is(src, toks, first, "not") {
        return false;
    }
    if word_is(src, toks, first, "test") {
        return boolean_test(src, toks, first, to);
    }
    if !word_is(src, toks, first, "all") {
        return false;
    }
    let open = next_solid(toks, first + 1);
    if open >= to || !matches!(toks[open].2, TokenKind::OpenParen) {
        return false;
    }
    let mut depth = 0i32;
    for i in open..to {
        match toks[i].2 {
            TokenKind::OpenParen => depth += 1,
            TokenKind::CloseParen => depth -= 1,
            TokenKind::Ident if depth == 1 && boolean_test(src, toks, i, to) => return true,
            _ => {}
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttrKind {
    CfgTest,
    TestFn,
    Other,
}

fn classify_attr(src: &str, toks: &[Tok], open: usize, close: usize) -> AttrKind {
    let i = next_solid(toks, open + 1);
    if i >= close {
        return AttrKind::Other;
    }
    if word_is(src, toks, i, "test") {
        // `#[test]` is the whole path. `#[test::instrument]` is not.
        let next = next_solid(toks, i + 1);
        if next >= close {
            return AttrKind::TestFn;
        }
    }
    if word_is(src, toks, i, "cfg") {
        let paren = next_solid(toks, i + 1);
        if paren < close && matches!(toks[paren].2, TokenKind::OpenParen) {
            if let Some(end) =
                matching_delim(toks, paren, TokenKind::OpenParen, TokenKind::CloseParen)
            {
                if end < close && cfg_is_test(src, toks, paren + 1, end) {
                    return AttrKind::CfgTest;
                }
            }
        }
        return AttrKind::Other;
    }
    if toks.get(i).is_some_and(|tok| call_word(src, tok) == Some("tokio")) {
        let c1 = next_solid(toks, i + 1);
        let c2 = next_solid(toks, c1 + 1);
        let name = next_solid(toks, c2 + 1);
        let after = next_solid(toks, name + 1);
        // `#[tokio::test]` and `#[tokio::test(...)]`. `#[tokio::test::…]` is not.
        if name < close
            && matches!(toks.get(c1).map(|t| t.2), Some(TokenKind::Colon))
            && matches!(toks.get(c2).map(|t| t.2), Some(TokenKind::Colon))
            && toks.get(name).is_some_and(|tok| call_word(src, tok) == Some("test"))
            && (after >= close || !matches!(toks.get(after).map(|t| t.2), Some(TokenKind::Colon)))
        {
            return AttrKind::TestFn;
        }
    }
    AttrKind::Other
}

struct Attr {
    kind: AttrKind,
    inner: bool,
    start: usize,
    end: usize,
}

fn parse_attr(src: &str, toks: &[Tok], pound: usize) -> Option<Attr> {
    let mut j = next_solid(toks, pound + 1);
    let inner = matches!(toks.get(j).map(|t| t.2), Some(TokenKind::Bang));
    if inner {
        j = next_solid(toks, j + 1);
    }
    if !matches!(toks.get(j).map(|t| t.2), Some(TokenKind::OpenBracket)) {
        return None;
    }
    let close = attr_close(toks, j)?;
    Some(Attr { kind: classify_attr(src, toks, j, close), inner, start: toks[pound].0, end: close })
}

enum HeaderEnd {
    Semi(usize),
    Brace(usize),
    Stop,
    Overflow,
}

fn arrow_gt(toks: &[Tok], i: usize) -> bool {
    let mut j = i;
    while j > 0 {
        j -= 1;
        match toks[j].2 {
            TokenKind::Whitespace => continue,
            TokenKind::Minus | TokenKind::Eq => return true,
            _ => return false,
        }
    }
    false
}

fn prev_solid_kind(toks: &[Tok], i: usize) -> Option<TokenKind> {
    let mut j = i;
    while j > 0 {
        j -= 1;
        if !is_gap(toks[j].2) {
            return Some(toks[j].2);
        }
    }
    None
}

/// `0 < 1`, `n() < 1`. A generic `<` follows a path, not a literal or a closer.
fn comparison_lt(toks: &[Tok], i: usize) -> bool {
    matches!(
        prev_solid_kind(toks, i),
        Some(TokenKind::Literal { .. } | TokenKind::CloseParen | TokenKind::CloseBracket)
    )
}

enum MacroGroup {
    NotMacro,
    Close(usize),
    Unclosed,
    Overflow,
}

/// Strict and reserved keywords. `r#for` is a raw ident, so it stays a path segment.
#[rustfmt::skip]
fn reserved_keyword(word: &str) -> bool {
    matches!(word, "as"|"async"|"await"|"break"|"const"|"continue"|"crate"|"dyn"|"else"|"enum"|"extern"|"false"|"fn"|"for"|"if"|"impl"|"in"|"let"|"loop"|"match"|"mod"|"move"|"mut"|"pub"|"ref"|"return"|"self"|"Self"|"static"|"struct"|"super"|"trait"|"true"|"type"|"unsafe"|"use"|"where"|"while"|"abstract"|"become"|"box"|"do"|"final"|"macro"|"override"|"priv"|"typeof"|"unsized"|"virtual"|"yield"|"try")
}

fn union_name(src: &str, toks: &[Tok], i: usize) -> bool {
    let n = next_solid(toks, i + 1);
    matches!(toks.get(n).map(|t| t.2), Some(TokenKind::RawIdent))
        || word(src, toks, n).is_some_and(|w| !reserved_keyword(w))
}

fn macro_path(src: &str, toks: &[Tok], bang: usize) -> bool {
    let mut j = bang;
    while j > 0 {
        j -= 1;
        if is_gap(toks[j].2) {
            continue;
        }
        return match toks[j].2 {
            TokenKind::RawIdent => true,
            TokenKind::Ident => word(src, toks, j).is_some_and(|text| !reserved_keyword(text)),
            _ => false,
        };
    }
    false
}

fn macro_group(src: &str, toks: &[Tok], bang: usize) -> MacroGroup {
    if !macro_path(src, toks, bang) {
        return MacroGroup::NotMacro;
    }
    let open = next_solid(toks, bang + 1);
    let Some(open_kind) = toks.get(open).map(|tok| tok.2) else {
        return MacroGroup::NotMacro;
    };
    let close_kind = match open_kind {
        TokenKind::OpenParen => TokenKind::CloseParen,
        TokenKind::OpenBracket => TokenKind::CloseBracket,
        TokenKind::OpenBrace => TokenKind::CloseBrace,
        _ => return MacroGroup::NotMacro,
    };
    let mut depth = 0usize;
    for (i, tok) in toks.iter().enumerate().skip(open) {
        if tok.2 == open_kind {
            depth += 1;
            if depth > MAX_DEPTH {
                return MacroGroup::Overflow;
            }
        } else if tok.2 == close_kind {
            depth -= 1;
            if depth == 0 {
                return MacroGroup::Close(i);
            }
        }
    }
    MacroGroup::Unclosed
}

fn scan_header(src: &str, toks: &[Tok], start: usize) -> HeaderEnd {
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut angle = 0i32;
    let mut array_expr = [0i32; MAX_DEPTH];
    let mut array_n = 0usize;
    let mut i = start;
    while i < toks.len() {
        let kind = toks[i].2;
        if i != start && paren == 0 && bracket == 0 && brace == 0 && angle == 0 {
            match kind {
                TokenKind::Semi => return HeaderEnd::Semi(i),
                TokenKind::OpenBrace => return HeaderEnd::Brace(i),
                _ => {}
            }
        }
        if kind == TokenKind::Bang {
            match macro_group(src, toks, i) {
                MacroGroup::NotMacro => {}
                MacroGroup::Close(end) => {
                    i = end + 1;
                    continue;
                }
                MacroGroup::Unclosed => return HeaderEnd::Stop,
                MacroGroup::Overflow => return HeaderEnd::Overflow,
            }
        }
        if kind == TokenKind::Pound {
            if let Some(attr) = parse_attr(src, toks, i) {
                i = attr.end + 1;
                continue;
            }
        }
        let operators = brace > 0 || array_n > 0;
        match kind {
            TokenKind::OpenParen => paren += 1,
            TokenKind::CloseParen => paren -= 1,
            TokenKind::OpenBracket => bracket += 1,
            TokenKind::CloseBracket => {
                bracket -= 1;
                while array_n > 0 && array_expr[array_n - 1] > bracket {
                    array_n -= 1;
                }
            }
            TokenKind::OpenBrace => brace += 1,
            TokenKind::CloseBrace => brace -= 1,
            TokenKind::Semi if brace == 0 && bracket > 0 => {
                if array_n >= MAX_DEPTH {
                    return HeaderEnd::Overflow;
                }
                array_expr[array_n] = bracket;
                array_n += 1;
            }
            TokenKind::Lt if !operators && !comparison_lt(toks, i) => angle += 1,
            TokenKind::Gt if !operators && angle > 0 && !arrow_gt(toks, i) => angle -= 1,
            _ => {}
        }
        if paren < 0 || bracket < 0 || brace < 0 || angle < 0 {
            return HeaderEnd::Stop;
        }
        if paren as usize > MAX_DEPTH
            || bracket as usize > MAX_DEPTH
            || brace as usize > MAX_DEPTH
            || angle as usize > MAX_DEPTH
        {
            return HeaderEnd::Overflow;
        }
        i += 1;
    }
    HeaderEnd::Stop
}

fn scan_semi(toks: &[Tok], start: usize) -> Option<usize> {
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    for (i, tok) in toks.iter().enumerate().skip(start) {
        if i != start
            && paren == 0
            && bracket == 0
            && brace == 0
            && matches!(tok.2, TokenKind::Semi)
        {
            return Some(i);
        }
        match tok.2 {
            TokenKind::OpenParen => paren += 1,
            TokenKind::CloseParen => paren -= 1,
            TokenKind::OpenBracket => bracket += 1,
            TokenKind::CloseBracket => bracket -= 1,
            TokenKind::OpenBrace => brace += 1,
            TokenKind::CloseBrace => brace -= 1,
            _ => {}
        }
        if paren < 0
            || bracket < 0
            || brace < 0
            || paren as usize > MAX_DEPTH
            || bracket as usize > MAX_DEPTH
            || brace as usize > MAX_DEPTH
        {
            return None;
        }
    }
    None
}

fn delim_end(toks: &[Tok], braces: &[Option<usize>], before: usize) -> Option<usize> {
    let delim = next_solid(toks, before + 1);
    match toks.get(delim).map(|t| t.2) {
        Some(TokenKind::OpenParen) => {
            matching_delim(toks, delim, TokenKind::OpenParen, TokenKind::CloseParen)
        }
        Some(TokenKind::OpenBracket) => {
            matching_delim(toks, delim, TokenKind::OpenBracket, TokenKind::CloseBracket)
        }
        Some(TokenKind::OpenBrace) => braces.get(delim).copied().flatten(),
        _ => None,
    }
}

struct Pending {
    kinds: Vec<AttrKind>,
    start: Option<usize>,
}

impl Pending {
    fn clear(&mut self) {
        self.kinds.clear();
        self.start = None;
    }

    fn push(&mut self, kind: AttrKind, start: usize) {
        if self.start.is_none() {
            self.start = Some(start);
        }
        self.kinds.push(kind);
    }

    fn cfg_test(&self) -> bool {
        self.kinds.contains(&AttrKind::CfgTest)
    }

    fn fn_test(&self) -> bool {
        self.kinds.iter().any(|kind| matches!(kind, AttrKind::CfgTest | AttrKind::TestFn))
    }

    fn start_or(&self, fallback: usize) -> usize {
        self.start.unwrap_or(fallback)
    }
}

struct Walk<'a> {
    src: &'a str,
    toks: &'a [Tok],
    braces: &'a [Option<usize>],
    ranges: &'a mut Vec<(usize, usize)>,
    /// Set when nesting passes [`MAX_DEPTH`]. [`test_ranges`] turns that into `Err`.
    overflow: &'a mut bool,
}

impl Walk<'_> {
    fn push_range(&mut self, start: usize, end: usize) {
        if start < end {
            self.ranges.push((start, end));
        }
    }

    fn body_close(&self, open: usize, limit: usize) -> Result<usize, ()> {
        match self.braces.get(open).copied().flatten() {
            Some(close) if close < limit => Ok(close),
            _ => Err(()),
        }
    }

    fn scope(
        &mut self,
        mut i: usize,
        limit: usize,
        scope_end: usize,
        depth: usize,
    ) -> Result<(), ()> {
        if depth > MAX_DEPTH {
            *self.overflow = true;
            return Err(());
        }
        let mut pending = Pending { kinds: Vec::new(), start: None };
        let mut started = false;
        while i < limit {
            i = next_solid(self.toks, i);
            if i >= limit {
                break;
            }
            if matches!(self.toks[i].2, TokenKind::CloseBrace) {
                break;
            }
            if matches!(self.toks[i].2, TokenKind::Pound) {
                let Some(attr) = parse_attr(self.src, self.toks, i) else {
                    pending.clear();
                    i += 1;
                    continue;
                };
                if attr.end >= limit {
                    return Ok(());
                }
                if attr.inner {
                    if attr.kind == AttrKind::CfgTest && !started {
                        self.push_range(attr.start, scope_end);
                    }
                    pending.clear();
                } else {
                    pending.push(attr.kind, attr.start);
                }
                i = attr.end + 1;
                continue;
            }
            started = true;
            if let Some(next) = self.qualifier(i) {
                i = next;
                continue;
            }
            if let Some(next) = self.item(i, limit, &pending, depth)? {
                pending.clear();
                i = next;
                continue;
            }
            if let Some(next) = self.macro_call(i, limit) {
                if pending.cfg_test() {
                    self.push_range(pending.start_or(self.toks[i].0), self.toks[next - 1].1);
                }
                pending.clear();
                i = next;
                continue;
            }
            pending.clear();
            i += 1;
        }
        Ok(())
    }

    fn qualifier(&self, i: usize) -> Option<usize> {
        if word_is(self.src, self.toks, i, "pub") {
            let next = next_solid(self.toks, i + 1);
            if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::OpenParen)) {
                let end =
                    matching_delim(self.toks, next, TokenKind::OpenParen, TokenKind::CloseParen)?;
                return Some(end + 1);
            }
            return Some(i + 1);
        }
        if word_is(self.src, self.toks, i, "unsafe") {
            let next = next_solid(self.toks, i + 1);
            if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::OpenBrace)) {
                return None;
            }
            if word_is(self.src, self.toks, next, "fn")
                || word_is(self.src, self.toks, next, "async")
                || word_is(self.src, self.toks, next, "trait")
                || word_is(self.src, self.toks, next, "impl")
                || word_is(self.src, self.toks, next, "extern")
            {
                return Some(i + 1);
            }
            return None;
        }
        if word_is(self.src, self.toks, i, "async") {
            let next = next_solid(self.toks, i + 1);
            if word_is(self.src, self.toks, next, "fn")
                || word_is(self.src, self.toks, next, "unsafe")
            {
                return Some(i + 1);
            }
            return None;
        }
        if word_is(self.src, self.toks, i, "const") {
            let next = next_solid(self.toks, i + 1);
            if word_is(self.src, self.toks, next, "fn")
                || word_is(self.src, self.toks, next, "unsafe")
                || word_is(self.src, self.toks, next, "async")
                || word_is(self.src, self.toks, next, "extern")
            {
                return Some(i + 1);
            }
        }
        if word_is(self.src, self.toks, i, "extern") {
            let mut next = next_solid(self.toks, i + 1);
            if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::Literal { .. })) {
                next = next_solid(self.toks, next + 1);
            }
            if word_is(self.src, self.toks, next, "fn") {
                return Some(next);
            }
        }
        None
    }

    fn item(
        &mut self,
        i: usize,
        limit: usize,
        pending: &Pending,
        depth: usize,
    ) -> Result<Option<usize>, ()> {
        let is = |name: &str| word_is(self.src, self.toks, i, name);
        if is("fn") || is("mod") {
            let name = next_solid(self.toks, i + 1);
            if self.toks.get(name).is_none_or(|tok| !is_name(self.src, tok)) {
                return Ok(None);
            }
            return self.finish(i, limit, pending, depth, is("mod"), is("fn"));
        }
        if is("trait") || is("impl") {
            return self.finish(i, limit, pending, depth, true, false);
        }
        if is("struct") || is("enum") || (is("union") && union_name(self.src, self.toks, i)) {
            return self.finish(i, limit, pending, depth, false, false);
        }
        if is("const") || is("static") || is("type") || is("use") {
            return Ok(self.semi_item(i, pending.cfg_test(), pending.start_or(self.toks[i].0)));
        }
        if is("extern") {
            return self.extern_item(i, limit);
        }
        if is("unsafe") {
            let next = next_solid(self.toks, i + 1);
            if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::OpenBrace)) {
                let close = self.body_close(next, limit)?;
                return Ok(Some(close + 1));
            }
        }
        Ok(None)
    }

    fn finish(
        &mut self,
        i: usize,
        limit: usize,
        pending: &Pending,
        depth: usize,
        walk: bool,
        fn_attrs: bool,
    ) -> Result<Option<usize>, ()> {
        let start = pending.start_or(self.toks[i].0);
        let test = if fn_attrs { pending.fn_test() } else { pending.cfg_test() };
        match scan_header(self.src, self.toks, i) {
            HeaderEnd::Semi(at) => {
                if test {
                    self.push_range(start, self.toks[at].1);
                }
                Ok(Some(at + 1))
            }
            HeaderEnd::Brace(open) => {
                let close = self.body_close(open, limit)?;
                if test {
                    self.push_range(start, self.toks[close].1);
                } else if walk {
                    self.scope(open + 1, close, self.toks[close].1, depth + 1)?;
                }
                Ok(Some(close + 1))
            }
            HeaderEnd::Overflow => {
                *self.overflow = true;
                Err(())
            }
            HeaderEnd::Stop => Err(()),
        }
    }

    fn semi_item(&mut self, i: usize, test: bool, start: usize) -> Option<usize> {
        let at = scan_semi(self.toks, i)?;
        if test {
            self.push_range(start, self.toks[at].1);
        }
        Some(at + 1)
    }

    fn extern_item(&mut self, i: usize, limit: usize) -> Result<Option<usize>, ()> {
        let mut next = next_solid(self.toks, i + 1);
        if word_is(self.src, self.toks, next, "crate") {
            let at = scan_semi(self.toks, i).ok_or(())?;
            return Ok(Some(at + 1));
        }
        if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::Literal { .. })) {
            next = next_solid(self.toks, next + 1);
        }
        if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::OpenBrace)) {
            let close = self.body_close(next, limit)?;
            return Ok(Some(close + 1));
        }
        Ok(None)
    }

    fn macro_call(&self, i: usize, limit: usize) -> Option<usize> {
        let end = if word_is(self.src, self.toks, i, "macro_rules") {
            let bang = next_solid(self.toks, i + 1);
            if !matches!(self.toks.get(bang).map(|t| t.2), Some(TokenKind::Bang)) {
                return None;
            }
            let name = next_solid(self.toks, bang + 1);
            let anchor = if self.toks.get(name).is_some_and(|tok| is_name(self.src, tok)) {
                name
            } else {
                bang
            };
            delim_end(self.toks, self.braces, anchor)?
        } else {
            let mut j = i;
            loop {
                if self.toks.get(j).is_none_or(|tok| call_word(self.src, tok).is_none()) {
                    return None;
                }
                let next = next_solid(self.toks, j + 1);
                if matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::Colon)) {
                    let c2 = next_solid(self.toks, next + 1);
                    if !matches!(self.toks.get(c2).map(|t| t.2), Some(TokenKind::Colon)) {
                        return None;
                    }
                    j = next_solid(self.toks, c2 + 1);
                    continue;
                }
                if !matches!(self.toks.get(next).map(|t| t.2), Some(TokenKind::Bang)) {
                    return None;
                }
                break delim_end(self.toks, self.braces, next)?;
            }
        };
        if end >= limit {
            return None;
        }
        Some(end + 1)
    }
}

fn item_is_test(src: &str, at: usize) -> bool {
    let Ok(toks) = lex_file(src) else {
        return false;
    };
    match test_ranges(src, &toks) {
        Ok(ranges) => in_range(&ranges, at),
        Err(()) => false,
    }
}

fn test_ranges(src: &str, toks: &[Tok]) -> Result<Vec<(usize, usize)>, ()> {
    let braces = brace_ends(toks)?;
    let mut ranges = Vec::new();
    let mut overflow = false;
    let mut walk =
        Walk { src, toks, braces: &braces, ranges: &mut ranges, overflow: &mut overflow };
    let _ = walk.scope(0, toks.len(), src.len(), 0);
    if overflow {
        return Err(());
    }
    Ok(ranges)
}

fn in_range(ranges: &[(usize, usize)], at: usize) -> bool {
    ranges.iter().any(|(start, end)| *start <= at && at < *end)
}

/// Display line of a byte offset. Not used to decide whether a spawn is a hit.
fn line_of(src: &str, at: usize) -> u32 {
    let mut line = 1u32;
    for (i, byte) in src.bytes().enumerate() {
        if i >= at {
            break;
        }
        if byte == b'\n' {
            line += 1;
        }
    }
    line
}

/// Trimmed source line for a hit message. Not used to classify a spawn.
fn line_text(src: &str, line: u32) -> String {
    src.lines().nth(line.saturating_sub(1) as usize).unwrap_or("").trim().to_string()
}

/// The previous non-whitespace token is a non-doc `// detached:` line comment,
/// and that comment is the first token on its line.
fn preceding_detached(src: &str, toks: &[Tok], spawn: usize) -> bool {
    let mut i = spawn;
    while i > 0 {
        i -= 1;
        match toks[i].2 {
            TokenKind::Whitespace => continue,
            TokenKind::LineComment { doc_style: None } => {
                let text = src.get(toks[i].0..toks[i].1).unwrap_or("");
                return text.starts_with("// detached:") && comment_starts_line(src, toks, i);
            }
            _ => return false,
        }
    }
    false
}

fn comment_starts_line(src: &str, toks: &[Tok], comment: usize) -> bool {
    let mut i = comment;
    while i > 0 {
        i -= 1;
        if !matches!(toks[i].2, TokenKind::Whitespace) {
            return false;
        }
        if src.get(toks[i].0..toks[i].1).is_some_and(|text| text.contains('\n')) {
            return true;
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpawnHit {
    rel_path: String,
    line: u32,
    /// Trimmed source line, or `untrusted token stream` for a file the lexer rejected.
    text: String,
    untrusted: bool,
}

struct FileScan {
    hits: Vec<SpawnHit>,
    detached: usize,
}

fn untrusted_hit(rel_path: &str) -> SpawnHit {
    SpawnHit {
        rel_path: rel_path.to_string(),
        line: 1,
        text: "untrusted token stream".to_string(),
        untrusted: true,
    }
}

fn scan_file(rel_path: &str, src: &str) -> FileScan {
    if is_src_tests_path(rel_path) {
        return FileScan { hits: Vec::new(), detached: 0 };
    }
    let toks = match lex_file(src) {
        Ok(toks) => toks,
        Err(_) => return FileScan { hits: vec![untrusted_hit(rel_path)], detached: 0 },
    };
    let ranges = match test_ranges(src, &toks) {
        Ok(ranges) => ranges,
        Err(()) => return FileScan { hits: vec![untrusted_hit(rel_path)], detached: 0 },
    };
    let parsed = SourceItems::parse(src).ok();
    let bn = rel_path.starts_with("crates/bn-manager/");
    let mut hits = Vec::new();
    let mut detached = 0usize;
    for (i, _) in toks.iter().enumerate() {
        if !is_spawn_path(src, &toks, i) {
            continue;
        }
        let at = toks[i].0;
        if in_range(&ranges, at) {
            continue;
        }
        let line = line_of(src, at);
        if bn && preceding_detached(src, &toks, i) {
            detached += 1;
            continue;
        }
        let mut text = line_text(src, line);
        if let Some(items) = &parsed {
            if let Ok(id) = items.enclosing(at) {
                text = format!("{text} ({id})");
            }
        }
        hits.push(SpawnHit { rel_path: rel_path.to_string(), line, text, untrusted: false });
    }
    FileScan { hits, detached }
}

/// Classify one synthetic or real file: production raw-spawn hits, test regions excluded.
fn find_production_spawns(rel_path: &str, src: &str) -> Vec<SpawnHit> {
    scan_file(rel_path, src).hits
}

fn is_allowed(hit: &SpawnHit, allow: &HashSet<(&str, u32)>) -> bool {
    if hit.untrusted {
        return false;
    }
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
    let (files, walk_errors) = scan_root_rs_files(&root);
    assert!(
        files.len() > 40,
        "scanned only {} files under crates/rvc/src + bin/rvc/src + crates/bn-manager/src; \
         workspace walk likely broke",
        files.len()
    );

    let allow: HashSet<(&str, u32)> = ALLOW_LIST.iter().copied().collect();
    assert_eq!(allow.len(), ALLOW_LIST.len(), "duplicate ALLOW_LIST entries");

    let mut violations: Vec<String> = walk_errors;
    let mut production_hits = 0usize;
    let mut detached = 0usize;
    let mut used_allow: HashSet<(String, u32)> = HashSet::new();

    for file in &files {
        let rel = match file.strip_prefix(&root) {
            Ok(path) => path.to_string_lossy().replace('\\', "/"),
            Err(_) => {
                violations.push(format!("{}: path is outside the workspace", file.display()));
                continue;
            }
        };
        let src = match std::fs::read_to_string(file) {
            Ok(src) => src,
            Err(err) => {
                violations.push(format!("{rel}: cannot read source: {err}"));
                continue;
            }
        };
        let scan = scan_file(&rel, &src);
        detached += scan.detached;
        for hit in scan.hits {
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
        "G-4 raw-spawn gate (ARCH-2k / M8): raw `tokio::spawn` and `tokio::task::spawn` under \
         crates/rvc/src/**, bin/rvc/src/**, and crates/bn-manager/src/** must live only in \
         {EXECUTOR_PATH} or carry a bn-manager `// detached:` comment (ALLOW_LIST empty).\n\
         Offenders:\n  {}",
        violations.join("\n  ")
    );
    assert_eq!(
        detached, DETACHED_BN_SPAWNS,
        "expected {DETACHED_BN_SPAWNS} bn-manager spawns classified by a preceding // detached: \
         comment (fan_out wait_for_complete_detached, spawn_detached, health_sender; \
         manager start_sse; sse subscribe_events_admitted_inner; sync_status \
         start_sync_monitor_publishing)"
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
    assert_eq!(BAN_LIST, &["tokio::spawn", "tokio::task::spawn"]);
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
    // Path rule wins before the lexer. An untrusted tests.rs file is still empty.
    let open = "fn production() { /* tokio::spawn(async {});";
    assert!(find_production_spawns(rel, open).is_empty(), "path rule drops an untrusted file");
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
    assert!(hits[0].text.contains("handle"), "{hits:?}");
}

#[test]
fn test_matcher_never_flags_spawn_blocking() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "    let h = tokio::spawn_blocking(|| heavy());\n";
    let hits = find_production_spawns(rel, src);
    assert!(hits.is_empty(), "C9 anchor 7: spawn_blocking must not be flagged; got {hits:?}");
    let task = "    let h = tokio::task::spawn_blocking(|| heavy());\n";
    assert!(
        find_production_spawns(rel, task).is_empty(),
        "tokio::task::spawn_blocking is not tokio::task::spawn"
    );
}

#[test]
fn test_matcher_ignores_doc_comment_mentions() {
    let rel = "crates/rvc/src/liveness_loop.rs";
    let src = "    /// Run until cancelled. Spawns no tasks — call from `tokio::spawn`.\n";
    assert!(find_production_spawns(rel, src).is_empty());
    let block = "fn production() { /* tokio::spawn(async {}); */ }\n";
    assert!(
        find_production_spawns(rel, block).is_empty(),
        "a terminated block comment is not a spawn"
    );
    // `'…'` is a multibyte scalar. The shared masker does not span it. `'\u{00E9}'`
    // is an escape, which the masker does span. Either way the spawn stays a normal hit.
    let scalar = "fn production() { let _ = '…'; tokio::spawn(async {}); }\n";
    let hits = find_production_spawns(rel, scalar);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(!hits[0].untrusted && hits[0].text.contains("tokio::spawn"), "{hits:?}");
    let escape = "fn production() { let _ = '\\u{00E9}'; tokio::spawn(async {}); }\n";
    let escaped = find_production_spawns(rel, escape);
    assert_eq!(escaped.len(), 1, "{escaped:?}");
    assert!(!escaped[0].untrusted, "{escaped:?}");
    let quoted = "fn production() { let _ = \"tokio::spawn(async {});\"; }\n";
    assert!(find_production_spawns(rel, quoted).is_empty(), "a string is not a spawn path");
}

#[test]
fn test_scan_visited_a_plausible_number_of_files() {
    let root = workspace_root();
    let (files, errors) = scan_root_rs_files(&root);
    assert!(errors.is_empty(), "scan walk failed: {errors:?}");
    assert!(files.len() > 40, "scanned only {} files; workspace walk likely broke", files.len());
    let rels: HashSet<String> = files
        .iter()
        .map(|f| f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(rels.iter().any(|r| r.starts_with("crates/rvc/src/")), "expected crates/rvc/src hits");
    assert!(rels.iter().any(|r| r.starts_with("bin/rvc/src/")), "expected bin/rvc/src hits");
    assert!(
        rels.iter().any(|r| r.starts_with("crates/bn-manager/src/")),
        "expected crates/bn-manager/src hits"
    );
    let missing = collect_rs(Path::new("/no/such/raw-spawn-dir"), &mut Vec::new());
    assert!(missing.is_err(), "a missing scan directory is a violation, not an empty walk");
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
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let excluded = [
        "#[cfg(all(test, feature = \"x\"))]\nmod tests { fn t() { tokio::spawn(async {}); } }\n",
        "#[cfg(all(feature = \"x\", test))]\nfn t() { tokio::spawn(async {}); }\n",
        "#[test]\nfn t() { tokio::spawn(async {}); }\n",
        "#![cfg(test)]\nfn t() { tokio::spawn(async {}); }\n",
    ];
    for src in excluded {
        assert!(find_production_spawns(rel, src).is_empty(), "{src}");
    }
    let flagged = [
        "#[cfg(feature = \"test-utils\")]\nfn t() { tokio::spawn(async {}); }\n",
        "#[cfg(all(any(test, feature = \"x\")))]\nfn t() { tokio::spawn(async {}); }\n",
        "#[cfg(all(not(test)))]\nfn t() { tokio::spawn(async {}); }\n",
        "#[cfg(test)]\nmod tests {\nfn t() { tokio::spawn(async {}); }\n",
        "#[cfg(test)]\nextern \"C\" { fn t() { tokio::spawn(async {}); } }\n",
        "fn production() {\n    #[cfg(test)]\n    tokio::spawn(async {});\n}\n",
    ];
    for src in flagged {
        assert_eq!(find_production_spawns(rel, src).len(), 1, "{src}");
    }
}

#[test]
fn test_matcher_flags_spawn_after_a_cfg_any_test_item() {
    let rel = "crates/rvc/src/orchestrator/coordinator/mod.rs";
    let src = "\
#[cfg(any(test, feature = \"test-utils\"))]\n\
fn for_test() {\n\
    tokio::spawn(async {});\n\
}\n\
fn production() {\n\
    tokio::spawn(async {});\n\
}\n\
";
    let hits = find_production_spawns(rel, src);
    assert_eq!(
        hits.len(),
        2,
        "any(test, ...) is not a test region; both spawns stay production; got {hits:?}"
    );
}

#[test]
fn test_matcher_flags_spawn_after_a_cfg_test_use_line() {
    let rel = "crates/rvc/src/config/builder.rs";
    let src = "\
#[cfg(test)]\n\
use std::sync::Arc;\n\
fn production() {\n\
    tokio::spawn(async {});\n\
}\n\
";
    let hits = find_production_spawns(rel, src);
    assert_eq!(hits.len(), 1, "a cfg(test) use does not mask the rest of the file; got {hits:?}");
}

#[test]
fn test_matcher_excludes_free_standing_tokio_test_fn() {
    let rel = "crates/rvc/src/quiesce.rs";
    let src = "\
#[tokio::test]\n\
async fn inside_the_test() {\n\
    tokio::spawn(async {});\n\
}\n\
fn production() {\n\
    tokio::spawn(async {});\n\
}\n\
";
    let hits = find_production_spawns(rel, src);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].line > 4, "the free #[tokio::test] spawn is not production; got {hits:?}");
    let inside = src.find("inside_the_test").expect("fixture");
    let production = src.rfind("fn production").expect("fixture");
    assert!(item_is_test(src, inside), "the tokio::test fn is a test item");
    assert!(!item_is_test(src, production), "the following fn is production");
}

#[test]
fn test_matcher_flags_spawn_after_a_cfg_test_module() {
    let rel = "crates/rvc/src/bootstrap/run.rs";
    let src = "\
#[cfg(test)]\n\
mod tests {\n\
    fn t() { tokio::spawn(async {}); }\n\
}\n\
fn production() { tokio::spawn(async {}); }\n\
";
    let hits = find_production_spawns(rel, src);
    assert_eq!(
        hits.len(),
        1,
        "a cfg(test) module does not mask the rest of the file; got {hits:?}"
    );
    assert!(hits[0].text.contains("production"), "{hits:?}");
}

#[test]
fn test_matcher_flags_tokio_task_spawn() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "fn production() { tokio::task::spawn(async {}); }\n";
    assert_eq!(find_production_spawns(rel, src).len(), 1, "tokio::task::spawn is a raw spawn");
}

#[test]
fn test_matcher_flags_unrecognised_spawn_forms() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let macro_form = "fn production() { tokio::spawn!(async {}); }\n";
    assert_eq!(
        find_production_spawns(rel, macro_form).len(),
        1,
        "an unrecognised spawn macro is a hit"
    );
    let turbofish = "fn production() { tokio::spawn::<()>(async {}); }\n";
    assert_eq!(find_production_spawns(rel, turbofish).len(), 1, "turbofish spawn is a hit");
    let not_test = "\
#[cfg(not(test))]\n\
fn production() { tokio::spawn(async {}); }\n\
";
    assert_eq!(
        find_production_spawns(rel, not_test).len(),
        1,
        "cfg(not(test)) is not a test region"
    );
    let raw = "fn production() { r#tokio::r#spawn(async {}); }\n";
    assert_eq!(find_production_spawns(rel, raw).len(), 1, "raw idents still name the spawn");
    let eof = "fn production() { tokio::spawn";
    assert_eq!(find_production_spawns(rel, eof).len(), 1, "a spawn path at EOF is a hit");
}

#[test]
fn test_matcher_keeps_a_hit_when_the_token_stream_is_untrusted() {
    // The unterminated string begins after a cfg(test) use. The line rule
    // treats the rest of the file as a test region and drops the spawn. The
    // string also swallows the call, so a trusted parse must not be required
    // to keep the hit.
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "\
#[cfg(test)]\n\
use std::sync::Arc;\n\
fn production() {\n\
    let _ = \"\n\
    tokio::spawn(async {});\n\
}\n\
";
    let hits = find_production_spawns(rel, src);
    assert!(
        hits.iter().any(|hit| hit.text == "untrusted token stream"),
        "an untrusted token stream must not drop the spawn; got {hits:?}"
    );
    assert!(!item_is_test(src, 0), "an untrusted stream is not a proven test region");
    let open_block = "fn production() { /* tokio::spawn(async {}); }\n";
    let block_hits = find_production_spawns(rel, open_block);
    assert!(
        block_hits.iter().any(|hit| hit.text == "untrusted token stream"),
        "an unterminated block comment must not drop the spawn; got {block_hits:?}"
    );
    assert!(
        !is_allowed(&untrusted_hit(EXECUTOR_PATH), &HashSet::new()),
        "an untrusted file is not saved by the executor path"
    );
}

#[test]
fn test_matcher_classifies_only_bn_manager_detached_spawns() {
    let src = "// detached: drain finishes after the caller returns\ntokio::spawn(async {});\n";
    let bn = find_production_spawns("crates/bn-manager/src/fan_out.rs", src);
    assert!(bn.is_empty(), "a bn-manager detached spawn is classified, not banned; got {bn:?}");
    let rvc = find_production_spawns("crates/rvc/src/bootstrap/tasks.rs", src);
    assert_eq!(
        rvc.len(),
        1,
        "a detached comment outside bn-manager is not an exemption; got {rvc:?}"
    );
}

#[test]
fn test_matcher_does_not_apply_cfg_test_inside_a_macro() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    // `#[cfg(test)]` inside the body is not an item. The following function stays production.
    let inside = "\
macro_rules! m {\n\
    () => { #[cfg(test)] fn hidden() { tokio::spawn(async {}); } };\n\
}\n\
fn production() { tokio::spawn(async {}); }\n\
";
    let hits = find_production_spawns(rel, inside);
    assert!(
        hits.iter().any(|hit| hit.text.contains("production") && !hit.untrusted),
        "a cfg(test) token inside a macro must not mask the next item; got {hits:?}"
    );
    let on_macro = "\
#[cfg(test)]\n\
macro_rules! m { () => { tokio::spawn(async {}); }; }\n\
fn production() { tokio::spawn(async {}); }\n\
";
    let after = find_production_spawns(rel, on_macro);
    assert_eq!(after.len(), 1, "cfg(test) on the macro stops at the macro; got {after:?}");
    assert!(after[0].text.contains("production"), "{after:?}");
}

#[test]
fn test_matcher_rejects_a_token_nest_past_the_depth_cap() {
    let mut src = "{".repeat(MAX_DEPTH + 1);
    src.push_str("tokio::spawn(async {});");
    src.push_str(&"}".repeat(MAX_DEPTH + 1));
    let hits = find_production_spawns("crates/rvc/src/bootstrap/tasks.rs", &src);
    assert!(
        hits.iter().any(|hit| hit.text == "untrusted token stream"),
        "a nest past {MAX_DEPTH} is not scanned as trusted code; got {hits:?}"
    );
    assert!(!item_is_test(&src, 0));
}

#[test]
fn test_matcher_ignores_detached_text_that_is_not_a_line_comment() {
    let rel = "crates/bn-manager/src/fan_out.rs";
    let fixtures = [
        "fn production() {\n    /*\n// detached: pretend */\n    tokio::spawn(async {});\n}\n",
        "fn production() {\n    let _ = \"\n// detached: pretend\n\";\n    tokio::spawn(async {});\n}\n",
        "fn production() {\n    let _ = r#\"\n// detached: pretend\n\"#;\n    tokio::spawn(async {});\n}\n",
        "fn production() {\n    let _ = 1; // detached: pretend\n    tokio::spawn(async {});\n}\n",
    ];
    for src in fixtures {
        let scan = scan_file(rel, src);
        assert_eq!(scan.detached, 0, "{src}");
        assert_eq!(scan.hits.len(), 1, "{src} -> {:?}", scan.hits);
        assert!(!scan.hits[0].untrusted, "{src}");
    }
}

#[test]
fn test_matcher_flags_cfg_test_key_value() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "#[cfg(test=\"production\")]\nfn production() { tokio::spawn(async {}); }\n",
        "#[cfg(all(test=\"production\"))]\nfn production() { tokio::spawn(async {}); }\n",
        "#[cfg(all(feature = \"x\", test = \"production\"))]\nfn production() { tokio::spawn(async {}); }\n",
    ];
    for src in fixtures {
        assert_eq!(find_production_spawns(rel, src).len(), 1, "{src}");
    }
}

#[test]
fn test_matcher_flags_a_test_path_prefix_attribute() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "use tracing as test;\n#[test::instrument]\nfn production() { tokio::spawn(async {}); }\n",
        "#[tokio::test::instrument]\nfn production() { tokio::spawn(async {}); }\n",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "a path through test is not #[test]; got {hits:?} for {src}");
    }
    let with_args = "\
#[tokio::test(flavor = \"current_thread\")]\n\
async fn inside() { tokio::spawn(async {}); }\n\
fn production() { tokio::spawn(async {}); }\n\
";
    let hits = find_production_spawns(rel, with_args);
    assert_eq!(hits.len(), 1, "tokio::test arguments stay a test fn; got {hits:?}");
    assert!(hits[0].text.contains("production"), "{hits:?}");
}

#[test]
fn test_matcher_does_not_extend_cfg_test_past_const_unsafe_fn() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "mod m {\n    #[cfg(test)] const unsafe fn helper() {}\n    fn production() { tokio::spawn(async {}); }\n    const END: () = ();\n}\n",
        "mod m {\n    #[cfg(test)] const extern \"C\" fn helper() {}\n    fn production() { tokio::spawn(async {}); }\n    const END: () = ();\n}\n",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production"), "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_treat_a_const_generic_brace_as_the_body() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
struct Tag<const N: usize>;\n\
fn test_only() -> Tag<{ 0 }> { #![cfg(test)] Tag }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
struct Tag<const N: usize>;\n\
impl Tag<{ 0 }> {\n\
    #![cfg(test)]\n\
    fn hidden() { tokio::spawn(async {}); }\n\
}\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
struct Tag<const N: usize>;\n\
fn test_only<T: Fn() -> u8, const N: usize = { 1 }>() { #![cfg(test)] }\n\
fn production() { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production"), "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_a_comparison_extend_a_cfg_test_header() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
#[cfg(test)]\n\
fn helper() -> [u8; { if 0 < 1 { 1 } else { 2 } }] { [0] }\n\
fn production() { if 1 > 0 { tokio::spawn(async {}); } }\n\
",
        "\
#[cfg(test)]\n\
fn helper() -> [u8; if 0 < 1 { 1 } else { 2 }] { [0] }\n\
fn production() -> [u8; (1 > 0) as usize] { tokio::spawn(async {}); }\n\
",
        "\
#[cfg(test)]\n\
fn helper() -> [u8; { let n = 0; if n < 1 { 1 } else { 2 } }] { [0] }\n\
fn production() -> [u8; (1 > 0) as usize] { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_a_shift_open_a_cfg_test_header() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
#[cfg(test)]\n\
fn helper() -> [u8; 1 << 0] { [0] }\n\
fn production() -> [u8; (1 > 0) as usize] {\n\
    tokio::spawn(async {});\n\
    [0]\n\
}\n\
",
        "\
#[cfg(test)]\n\
fn helper() -> Vec<[u8; 1 << 0]> { Vec::new() }\n\
fn production() { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_a_fat_arrow_close_a_generic() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let src = "\
macro_rules! ty { ($condition:expr => $t:ty) => { $t }; }\n\
struct Tag<T, const N: usize>(T);\n\
fn helper() -> Tag<ty!((0 < 1) => u8), {0}> { #![cfg(test)] Tag(0) }\n\
fn production() { tokio::spawn(async {}); }\n\
";
    let hits = find_production_spawns(rel, src);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
}

#[test]
fn test_matcher_does_not_let_a_macro_comparison_extend_a_cfg_test_header() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
const N: usize = 0;\n\
macro_rules! ty { ($condition:expr => $t:ty) => { $t }; }\n\
#[cfg(test)]\n\
fn helper() -> ty!((N < 1) => u8) { 0 }\n\
fn production(_: ty!((1 > 0) => u8)) {\n\
    tokio::spawn(async {});\n\
}\n\
",
        "\
macro_rules! ty { ($t:ty) => { $t }; }\n\
fn helper() -> ty! { u8 } { #![cfg(test)] 0 }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
macro_rules! ty { ($($t:tt)*) => { u8 }; }\n\
struct Tag<T, const N: usize>(T);\n\
fn helper() -> Tag<ty!((1 > 0)), {0}> { #![cfg(test)] Tag(0) }\n\
fn production() { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_a_bracket_macro_arm_an_array_length() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
macro_rules! ty { ($($t:tt)*) => { u8 }; }\n\
#[cfg(test)]\n\
fn helper() -> ty![Vec<u8; >] { 0 }\n\
fn production(_: ty!((1 > 0))) {\n\
    tokio::spawn(async {});\n\
}\n\
",
        "\
macro_rules! ty { ($($t:tt)*) => { u8 }; }\n\
#[cfg(test)]\n\
fn helper() -> ty![Vec<u8; >] { 0 }\n\
fn production(_: ty![(1 > 0)]) {\n\
    tokio::spawn(async {});\n\
}\n\
",
        "\
macro_rules! ty { ($($t:tt)*) => { u8 }; }\n\
#[cfg(test)]\n\
fn helper() -> ty![1 << 0] { 0 }\n\
fn production(_: ty![(1 > 0)]) {\n\
    tokio::spawn(async {});\n\
}\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_treat_the_never_type_as_a_macro_group() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
#[cfg(test)]\n\
fn helper() -> ! { loop {} }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
#[cfg(test)]\n\
fn helper() -> u8 { loop {} }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
fn helper() -> ! { loop {} }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
macro_rules! ty { ($t:ty) => { $t }; }\n\
fn helper() -> m::ty! { u8 } { #![cfg(test)] 0 }\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
#[cfg(test)]\n\
fn helper() -> [u8; if 0 != 1 { !0usize } else { 1 }] { [0] }\n\
fn production() { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_a_nameless_macro_inner_cfg_hide_production() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "macro_rules! { #![cfg(test)] }\nfn production() { tokio::spawn(async {}); }\n",
        "macro_rules! ( #![cfg(test)] )\nfn production() { tokio::spawn(async {}); }\n",
        "macro_rules! [ #![cfg(test)] ]\nfn production() { tokio::spawn(async {}); }\n",
        "mod m {\nmacro_rules!{#![cfg(test)]}\nfn production() { tokio::spawn(async {}); }\n}\n",
        "mod m {\nmacro_rules!(#![cfg(test)])\nfn production() { tokio::spawn(async {}); }\n}\n",
        "mod m {\nmacro_rules![#![cfg(test)]]\nfn production() { tokio::spawn(async {}); }\n}\n",
        "macro m { #![cfg(test)] }\nfn production() { tokio::spawn(async {}); }\n",
        "mod m {\nmacro m{#![cfg(test)]}\nfn production() { tokio::spawn(async {}); }\n}\n",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_let_an_attr_angle_delay_the_header_brace() {
    let hits = find_production_spawns(
        "crates/rvc/src/bootstrap/tasks.rs",
        "#[cfg(test)]\nfn f(#[a(T<)] _: u8) {}\nfn production() -> u8> { tokio::spawn(async {}); }\n",
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
}

#[test]
fn test_matcher_does_not_let_a_union_path_macro_extend_cfg_test() {
    let hits = find_production_spawns(
        "crates/rvc/src/bootstrap/tasks.rs",
        "#[cfg(all(test, any()))]\nunion::m! {}\nfn production() { tokio::spawn(async {}); }\n",
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
}

#[test]
fn test_matcher_does_not_treat_union_bang_as_a_union_item() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "#[cfg(all(test, any()))]\nunion ! {}\nfn production() { tokio::spawn(async {}); }\n",
        "#[cfg(all(test, any()))]\nunion Foo { x: [u8; { tokio::spawn(async {}); 1 }] }\nfn production() { tokio::spawn(async {}); }\n",
        "#[cfg(all(test, any()))]\nunion r#type { x: [u8; { tokio::spawn(async {}); 1 }] }\nfn production() { tokio::spawn(async {}); }\n",
        "fn helper() -> union! { u8 } { #![cfg(test)] 0 }\nfn production() { tokio::spawn(async {}); }\n",
        "fn helper() -> r#for! { u8 } { #![cfg(test)] 0 }\nfn production() { tokio::spawn(async {}); }\n",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_does_not_treat_a_keyword_bang_as_a_macro_group() {
    let rel = "crates/rvc/src/bootstrap/tasks.rs";
    let fixtures = [
        "\
trait Marker {}\n\
#[cfg(all(test, any()))]\n\
impl Marker for ! {}\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
trait Marker {}\n\
#[cfg(all(test, any()))]\n\
impl Marker for u8 {}\n\
fn production() { tokio::spawn(async {}); }\n\
",
        "\
#[cfg(all(test, any()))]\n\
impl ! {}\n\
fn production() { tokio::spawn(async {}); }\n\
",
    ];
    for src in fixtures {
        let hits = find_production_spawns(rel, src);
        assert_eq!(hits.len(), 1, "{src} -> {hits:?}");
        assert!(hits[0].text.contains("production") && !hits[0].untrusted, "{hits:?}");
    }
}

#[test]
fn test_matcher_rejects_angle_nesting_past_the_depth_cap() {
    let mut src = String::from("fn deep(_: ");
    for _ in 0..=MAX_DEPTH {
        src.push_str("Wrap<");
    }
    src.push_str("u8");
    for _ in 0..=MAX_DEPTH {
        src.push('>');
    }
    src.push_str(") { tokio::spawn(async {}); }\n");
    let hits = find_production_spawns("crates/rvc/src/bootstrap/tasks.rs", &src);
    assert!(
        hits.iter().any(|hit| hit.untrusted && hit.text == "untrusted token stream"),
        "angle nesting past {MAX_DEPTH} is one untrusted hit; got {hits:?}"
    );
}
