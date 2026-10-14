//! TRC-7d: advisory span-name conformance.
//!
//! Field names stopped drifting when [`observability::logging::fields`] gained a
//! registry and Gate 5 started failing the build on a miss. Span names have the
//! registry ([`observability::span_names`]) and this scan, but the scan does not
//! fail the build. It prints every `info_span!("…")` and `#[instrument(name = "…")]`
//! in tracked non-test source whose name is absent from the registry.
//!
//! Non-test source is `git ls-files` of `crates/**/*.rs` and `bin/**/*.rs`,
//! dropping:
//!
//! - any path component `tests`, `benches`, or `examples` (integration tests,
//!   unit-test modules that live under `src/**/tests/`, benches, examples);
//! - `tests.rs` and `*_tests.rs` (`#[cfg(test)] #[path = "client_tests.rs"]`).
//!
//! Inside a kept file, a `#[cfg(test)]` item is skipped and scanning continues
//! after it. A helper `#[cfg(test)] mod` in the middle of a file must not hide
//! the production spans that follow (`block_proposal/mod.rs`).
//!
//! `#[instrument(name = "…")]` includes `#[tracing::instrument]` and a `name`
//! on a later line. `target:` / `parent:` meta arguments on `info_span!` are
//! not the span name. `debug_span!` / `trace_span!` and `#[instrument]` without
//! an explicit `name` are out of scope.
//!
//! Follow-up **[TRC-7d-block]** flips this report to a blocking assert once the
//! registry has settled. Do not assert that the unregistered set is empty here.
//!
//! No external dependency: hand-rolled scan, same style as `no_rvc_prefix.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use observability::span_names;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    InfoSpan,
    Instrument,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::InfoSpan => "info_span",
            Self::Instrument => "instrument",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    path: String,
    line: usize,
    kind: Kind,
    name: String,
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

struct Cur<'a> {
    src: &'a str,
    i: usize,
    line: usize,
}

impl<'a> Cur<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, i: 0, line: 1 }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.i..]
    }

    fn eof(&self) -> bool {
        self.i >= self.src.len()
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            if ch == '\n' {
                self.line += 1;
            }
            self.i += ch.len_utf8();
        }
    }

    fn starts_with(&self, lit: &str) -> bool {
        self.rest().starts_with(lit)
    }

    /// Previous char is not an identifier byte, or this is the start of the source.
    fn boundary(&self) -> bool {
        match self.src[..self.i].chars().next_back() {
            None => true,
            Some(prev) => !prev.is_ascii_alphanumeric() && prev != '_',
        }
    }

    fn consume_ident(&mut self, want: &str) -> bool {
        if !self.starts_with(want) {
            return false;
        }
        let after = self.i + want.len();
        let cont = self.src[after..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if cont {
            return false;
        }
        self.i = after;
        true
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(ch) if ch.is_whitespace() => self.bump(),
                Some('/') if self.rest().starts_with("//") => self.skip_line_comment(),
                Some('/') if self.rest().starts_with("/*") => self.skip_block_comment(),
                _ => break,
            }
        }
    }

    fn skip_line_comment(&mut self) {
        self.bump();
        self.bump();
        while let Some(ch) = self.peek() {
            if ch == '\n' {
                break;
            }
            self.bump();
        }
    }

    fn skip_block_comment(&mut self) {
        self.bump();
        self.bump();
        let mut depth = 1;
        while depth > 0 && !self.eof() {
            if self.starts_with("/*") {
                self.bump();
                self.bump();
                depth += 1;
            } else if self.starts_with("*/") {
                self.bump();
                self.bump();
                depth -= 1;
            } else {
                self.bump();
            }
        }
    }

    /// `r"…"`, `r#"…"#`, `br"…"`, `cr"…"`. Returns false without consuming when
    /// the bytes are not a raw string (`return`, `r#ident`, `b"…"`).
    fn try_skip_raw_string(&mut self) -> bool {
        if !self.boundary() {
            return false;
        }
        let bytes = self.rest().as_bytes();
        let mut j = 0;
        if matches!(bytes.first(), Some(b'b' | b'B' | b'c' | b'C')) {
            j += 1;
        }
        if !matches!(bytes.get(j), Some(b'r' | b'R')) {
            return false;
        }
        j += 1;
        let mut hashes = 0;
        while bytes.get(j) == Some(&b'#') {
            hashes += 1;
            j += 1;
        }
        if bytes.get(j) != Some(&b'"') {
            return false;
        }
        j += 1;
        let term = format!("\"{}", "#".repeat(hashes));
        let end = match self.rest()[j..].find(&term) {
            Some(rel) => self.i + j + rel + term.len(),
            None => self.src.len(),
        };
        while self.i < end {
            self.bump();
        }
        true
    }

    /// `'x'`, `'\n'`, `b'x'`. Lifetimes (`'static`) are left alone.
    fn try_skip_char(&mut self) -> bool {
        if !self.boundary() {
            return false;
        }
        let bytes = self.rest().as_bytes();
        let mut j = 0;
        if matches!(bytes.first(), Some(b'b' | b'B')) {
            j = 1;
        }
        if bytes.get(j) != Some(&b'\'') {
            return false;
        }
        let body = j + 1;
        if bytes.get(body) == Some(&b'\\') {
            // prefix + quote + backslash + escaped byte(s) + closing quote.
            // `\u{…}` can contain several bytes; scan to the closing `'`.
            let mut k = body + 2;
            while k < bytes.len() && bytes[k] != b'\'' {
                k += 1;
            }
            if k >= bytes.len() {
                return false;
            }
            let end = self.i + k + 1;
            while self.i < end {
                self.bump();
            }
            return true;
        }
        if bytes.get(body).is_some()
            && bytes.get(body) != Some(&b'\'')
            && bytes.get(body + 1) == Some(&b'\'')
        {
            let end = self.i + body + 2;
            while self.i < end {
                self.bump();
            }
            return true;
        }
        false
    }

    fn skip_cooked_string(&mut self) {
        debug_assert_eq!(self.peek(), Some('"'));
        self.bump();
        while let Some(ch) = self.peek() {
            if ch == '\\' {
                self.bump();
                if self.peek() == Some('\r') {
                    self.bump();
                }
                if self.peek() == Some('\n') {
                    self.bump();
                    while matches!(self.peek(), Some(' ' | '\t')) {
                        self.bump();
                    }
                } else if self.peek().is_some() {
                    self.bump();
                }
                continue;
            }
            self.bump();
            if ch == '"' {
                break;
            }
        }
    }

    /// Opening quote is at the cursor. Returns the decoded literal and leaves
    /// the cursor just past the closing quote.
    fn decode_string(&mut self) -> String {
        debug_assert_eq!(self.peek(), Some('"'));
        self.bump();
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            if ch == '\\' {
                self.bump();
                match self.peek() {
                    Some('\r') => {
                        self.bump();
                        if self.peek() == Some('\n') {
                            self.bump();
                        }
                        while matches!(self.peek(), Some(' ' | '\t')) {
                            self.bump();
                        }
                    }
                    Some('\n') => {
                        self.bump();
                        while matches!(self.peek(), Some(' ' | '\t')) {
                            self.bump();
                        }
                    }
                    Some(escaped) => {
                        self.bump();
                        out.push(match escaped {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            other => other,
                        });
                    }
                    None => break,
                }
                continue;
            }
            if ch == '"' {
                self.bump();
                break;
            }
            out.push(ch);
            self.bump();
        }
        out
    }

    fn skip_token_tree(&mut self) {
        let mut paren = 0i32;
        let mut brack = 0i32;
        let mut brace = 0i32;
        let mut seen_brace = false;
        while !self.eof() {
            if self.starts_with("//") {
                self.skip_line_comment();
                continue;
            }
            if self.starts_with("/*") {
                self.skip_block_comment();
                continue;
            }
            if self.try_skip_raw_string() {
                continue;
            }
            if self.peek() == Some('"') {
                self.skip_cooked_string();
                continue;
            }
            if self.try_skip_char() {
                continue;
            }
            match self.peek() {
                Some('(') => {
                    paren += 1;
                    self.bump();
                }
                Some(')') => {
                    paren = paren.saturating_sub(1);
                    self.bump();
                }
                Some('[') => {
                    brack += 1;
                    self.bump();
                }
                Some(']') => {
                    brack = brack.saturating_sub(1);
                    self.bump();
                }
                Some('{') => {
                    brace += 1;
                    seen_brace = true;
                    self.bump();
                }
                Some('}') => {
                    brace = brace.saturating_sub(1);
                    self.bump();
                    if seen_brace && brace == 0 && paren == 0 && brack == 0 {
                        break;
                    }
                }
                Some(';') if !seen_brace && paren == 0 && brack == 0 => {
                    self.bump();
                    break;
                }
                Some(_) => self.bump(),
                None => break,
            }
        }
    }
}

/// Byte length of a `#[cfg(test)]` attribute at `rest`, or `None`.
fn cfg_test_attr_len(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    let mut j = 0;
    if b.first() != Some(&b'#') {
        return None;
    }
    j += 1;
    j = skip_ascii_ws(b, j);
    if b.get(j) != Some(&b'[') {
        return None;
    }
    j += 1;
    j = skip_ascii_ws(b, j);
    if !rest[j..].starts_with("cfg") {
        return None;
    }
    j += 3;
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    j = skip_ascii_ws(b, j);
    if b.get(j) != Some(&b'(') {
        return None;
    }
    j += 1;
    j = skip_ascii_ws(b, j);
    if !rest[j..].starts_with("test") {
        return None;
    }
    j += 4;
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    j = skip_ascii_ws(b, j);
    if b.get(j) != Some(&b')') {
        return None;
    }
    j += 1;
    j = skip_ascii_ws(b, j);
    if b.get(j) != Some(&b']') {
        return None;
    }
    j += 1;
    Some(j)
}

fn skip_ascii_ws(b: &[u8], mut j: usize) -> usize {
    while matches!(b.get(j), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        j += 1;
    }
    j
}

/// Replace `#[cfg(test)]` items with spaces. Newlines stay, so later line
/// numbers still match the original file.
fn blank_cfg_test_items(src: &str) -> String {
    let mut buf = src.as_bytes().to_vec();
    let mut cur = Cur::new(src);
    while !cur.eof() {
        if cur.starts_with("//") {
            cur.skip_line_comment();
            continue;
        }
        if cur.starts_with("/*") {
            cur.skip_block_comment();
            continue;
        }
        if cur.try_skip_raw_string() || cur.try_skip_char() {
            continue;
        }
        if cur.peek() == Some('"') {
            cur.skip_cooked_string();
            continue;
        }
        if cur.boundary() {
            if let Some(attr_len) = cfg_test_attr_len(cur.rest()) {
                let start = cur.i;
                let attr_end = start + attr_len;
                while cur.i < attr_end {
                    cur.bump();
                }
                loop {
                    cur.skip_trivia();
                    if cur.starts_with("#[") {
                        cur.bump();
                        cur.bump();
                        skip_brackets(&mut cur);
                        continue;
                    }
                    break;
                }
                cur.skip_token_tree();
                blank_keep_newlines(&mut buf, start, cur.i);
                continue;
            }
        }
        cur.bump();
    }
    String::from_utf8(buf).expect("blanked source stays utf-8")
}

fn skip_brackets(cur: &mut Cur<'_>) {
    let mut depth = 1i32;
    while depth > 0 && !cur.eof() {
        if cur.starts_with("//") {
            cur.skip_line_comment();
            continue;
        }
        if cur.starts_with("/*") {
            cur.skip_block_comment();
            continue;
        }
        if cur.try_skip_raw_string() {
            continue;
        }
        if cur.peek() == Some('"') {
            cur.skip_cooked_string();
            continue;
        }
        match cur.peek() {
            Some('[') => {
                depth += 1;
                cur.bump();
            }
            Some(']') => {
                depth -= 1;
                cur.bump();
            }
            Some(_) => cur.bump(),
            None => break,
        }
    }
}

fn blank_keep_newlines(buf: &mut [u8], start: usize, end: usize) {
    for byte in &mut buf[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

// ---------------------------------------------------------------------------
// Span-name extraction
// ---------------------------------------------------------------------------

fn scan_text(src: &str) -> Vec<Site> {
    let blanked = blank_cfg_test_items(src);
    let mut cur = Cur::new(&blanked);
    let mut sites = Vec::new();
    while !cur.eof() {
        if cur.starts_with("//") {
            cur.skip_line_comment();
            continue;
        }
        if cur.starts_with("/*") {
            cur.skip_block_comment();
            continue;
        }
        if cur.try_skip_raw_string() || cur.try_skip_char() {
            continue;
        }
        if cur.peek() == Some('"') {
            cur.skip_cooked_string();
            continue;
        }
        if cur.boundary() && cur.starts_with("info_span!") {
            let line = cur.line;
            for _ in 0.."info_span!".len() {
                cur.bump();
            }
            cur.skip_trivia();
            if cur.peek() == Some('(') {
                let name = info_span_name(&mut cur);
                sites.push(Site { path: String::new(), line, kind: Kind::InfoSpan, name });
            }
            continue;
        }
        if cur.starts_with("#[") || cur.starts_with("#![") {
            let line = cur.line;
            let inner = take_attribute_inner(&mut cur);
            if let Some(name) = instrument_name(&inner) {
                sites.push(Site { path: String::new(), line, kind: Kind::Instrument, name });
            }
            continue;
        }
        cur.bump();
    }
    sites
}

fn info_span_name(cur: &mut Cur<'_>) -> String {
    debug_assert_eq!(cur.peek(), Some('('));
    cur.bump();
    loop {
        cur.skip_trivia();
        if cur.eof() || cur.peek() == Some(')') {
            return "<missing>".to_string();
        }
        if is_meta_prefix(cur) {
            skip_until_comma(cur);
            continue;
        }
        if cur.peek() == Some('"') {
            return cur.decode_string();
        }
        let start = cur.i;
        skip_until_comma(cur);
        let raw = cur.src[start..cur.i].trim().trim_end_matches(',').trim();
        let snippet: String = raw.chars().take(80).collect();
        return format!("<nonliteral:{snippet}>");
    }
}

fn is_meta_prefix(cur: &Cur<'_>) -> bool {
    let rest = cur.rest();
    for key in ["target", "parent"] {
        if !rest.starts_with(key) {
            continue;
        }
        let after = &rest[key.len()..];
        let mut k = 0;
        for ch in after.chars() {
            if ch.is_whitespace() {
                k += ch.len_utf8();
                continue;
            }
            return ch == ':' && !after[k..].starts_with("::");
        }
    }
    false
}

fn skip_until_comma(cur: &mut Cur<'_>) {
    let mut paren = 0i32;
    let mut brack = 0i32;
    let mut brace = 0i32;
    while !cur.eof() {
        if cur.starts_with("//") {
            cur.skip_line_comment();
            continue;
        }
        if cur.starts_with("/*") {
            cur.skip_block_comment();
            continue;
        }
        if cur.try_skip_raw_string() {
            continue;
        }
        if cur.peek() == Some('"') {
            cur.skip_cooked_string();
            continue;
        }
        if cur.try_skip_char() {
            continue;
        }
        match cur.peek() {
            Some('(') => {
                paren += 1;
                cur.bump();
            }
            Some(')') => {
                if paren == 0 && brack == 0 && brace == 0 {
                    break;
                }
                paren = paren.saturating_sub(1);
                cur.bump();
            }
            Some('[') => {
                brack += 1;
                cur.bump();
            }
            Some(']') => {
                brack = brack.saturating_sub(1);
                cur.bump();
            }
            Some('{') => {
                brace += 1;
                cur.bump();
            }
            Some('}') => {
                brace = brace.saturating_sub(1);
                cur.bump();
            }
            Some(',') if paren == 0 && brack == 0 && brace == 0 => {
                cur.bump();
                break;
            }
            Some(_) => cur.bump(),
            None => break,
        }
    }
}

fn take_attribute_inner(cur: &mut Cur<'_>) -> String {
    // At `#` of `#[` or `#![`.
    cur.bump();
    if cur.peek() == Some('!') {
        cur.bump();
    }
    if cur.peek() == Some('[') {
        cur.bump();
    }
    let start = cur.i;
    let mut depth = 1i32;
    while depth > 0 && !cur.eof() {
        if cur.starts_with("//") {
            cur.skip_line_comment();
            continue;
        }
        if cur.starts_with("/*") {
            cur.skip_block_comment();
            continue;
        }
        if cur.try_skip_raw_string() {
            continue;
        }
        if cur.peek() == Some('"') {
            cur.skip_cooked_string();
            continue;
        }
        match cur.peek() {
            Some('[') => {
                depth += 1;
                cur.bump();
            }
            Some(']') => {
                depth -= 1;
                if depth == 0 {
                    let inner = cur.src[start..cur.i].to_string();
                    cur.bump();
                    return inner;
                }
                cur.bump();
            }
            Some(_) => cur.bump(),
            None => break,
        }
    }
    cur.src[start..cur.i].to_string()
}

fn instrument_name(inner: &str) -> Option<String> {
    let mut cur = Cur::new(inner);
    cur.skip_trivia();
    if cur.starts_with("::") {
        cur.bump();
        cur.bump();
        cur.skip_trivia();
    }
    if cur.consume_ident("tracing") {
        cur.skip_trivia();
        if !cur.starts_with("::") {
            return None;
        }
        cur.bump();
        cur.bump();
        cur.skip_trivia();
    }
    if !cur.consume_ident("instrument") {
        return None;
    }
    cur.skip_trivia();
    if cur.peek() != Some('(') {
        return None;
    }
    cur.bump();
    loop {
        cur.skip_trivia();
        if cur.eof() || cur.peek() == Some(')') {
            return None;
        }
        let start = cur.i;
        skip_until_comma(&mut cur);
        let arg = cur.src[start..cur.i].trim().trim_end_matches(',').trim();
        if let Some(name) = name_binding(arg) {
            return Some(name);
        }
    }
}

fn name_binding(arg: &str) -> Option<String> {
    let mut cur = Cur::new(arg);
    cur.skip_trivia();
    if !cur.consume_ident("name") {
        return None;
    }
    cur.skip_trivia();
    if cur.peek() != Some('=') {
        return None;
    }
    cur.bump();
    cur.skip_trivia();
    if cur.peek() == Some('"') {
        return Some(cur.decode_string());
    }
    let rest = cur.rest().trim();
    let snippet: String = rest.chars().take(60).collect();
    Some(format!("<nonliteral:{snippet}>"))
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn is_non_test_path(rel: &str) -> bool {
    let rel = rel.replace('\\', "/");
    if rel.split('/').any(|p| p == "tests" || p == "benches" || p == "examples") {
        return false;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel.as_str());
    if name == "tests.rs" || name.strip_suffix(".rs").is_some_and(|stem| stem.ends_with("_tests")) {
        return false;
    }
    name.ends_with(".rs")
}

fn tracked_non_test_rs(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "--", "crates/**/*.rs", "bin/**/*.rs"])
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
        .filter(|l| !l.is_empty())
        .map(|l| l.replace('\\', "/"))
        .filter(|l| is_non_test_path(l))
        .collect()
}

fn scan_tree(root: &Path) -> Vec<Site> {
    let mut sites = Vec::new();
    for rel in tracked_non_test_rs(root) {
        let path = root.join(&rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"));
        for mut site in scan_text(&src) {
            site.path = rel.clone();
            sites.push(site);
        }
    }
    sites
}

fn unregistered(sites: &[Site]) -> Vec<&Site> {
    let mut missing: Vec<&Site> =
        sites.iter().filter(|site| !span_names::contains(&site.name)).collect();
    missing.sort_by(|a, b| {
        (&a.path, a.line, a.name.as_str()).cmp(&(&b.path, b.line, b.name.as_str()))
    });
    missing
}

/// Advisory report. Prints nothing when every scanned name is registered.
fn report_unregistered(missing: &[&Site]) {
    if missing.is_empty() {
        return;
    }
    let mut distinct: Vec<&str> = missing.iter().map(|site| site.name.as_str()).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let site_word = if missing.len() == 1 { "site" } else { "sites" };
    let name_word = if distinct.len() == 1 { "name" } else { "names" };
    eprintln!(
        "span-name registry (advisory): {} unregistered span {site_word}, {} distinct {name_word}. \
         Register each in `observability::span_names::ALL` (dotted, lowercase, unprefixed — \
         `span_names::follows_naming_rule`). This report does not fail the build. \
         Follow-up [TRC-7d-block] flips the report to blocking once the registry has settled.",
        missing.len(),
        distinct.len(),
    );
    for site in missing {
        eprintln!("  {}  {}:{}  {}", site.name, site.path, site.line, site.kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn span_names_are_registered_advisory() {
    let root = workspace_root();
    let files = tracked_non_test_rs(&root);
    assert!(files.len() > 100, "scanned only {} files; git ls-files likely broke", files.len());
    let sites = scan_tree(&root);
    let distinct = {
        let mut names: Vec<&str> = sites.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names.len()
    };
    assert!(
        sites.len() > 50,
        "span scan found only {} sites; the walker likely broke",
        sites.len()
    );
    assert!(
        distinct > 40,
        "span scan found only {distinct} distinct names; the walker likely broke"
    );

    // ADVISORY ONLY. A miss is printed for the reviewer. It does not fail CI.
    // [TRC-7d-block] is the flip to `assert!(missing.is_empty(), ...)`.
    let missing = unregistered(&sites);
    report_unregistered(&missing);
}

#[test]
fn non_test_path_filter_drops_tests_benches_examples_and_test_modules() {
    assert!(is_non_test_path("crates/beacon/src/client.rs"));
    assert!(is_non_test_path("bin/rvc/src/main.rs"));
    assert!(!is_non_test_path("crates/beacon/tests/client_http.rs"));
    assert!(!is_non_test_path("crates/rvc/src/orchestrator/coordinator/tests/spans.rs"));
    assert!(!is_non_test_path("crates/rvc/benches/per_slot.rs"));
    assert!(!is_non_test_path("crates/crypto/examples/log_sample.rs"));
    assert!(!is_non_test_path("crates/remote-signer-client/src/client_tests.rs"));
    assert!(!is_non_test_path("crates/rvc/src/orchestrator/block_proposal/tests.rs"));
}

#[test]
fn info_span_name_skips_target_and_parent() {
    let src = r#"
        fn f() {
            let _a = tracing::info_span!("plain.name");
            let _b = tracing::info_span!(parent: None, "parent.name");
            let _c = info_span!(target: "app", parent: &p, "both.name", slot = 1);
            let _d = tracing::debug_span!("debug.only");
            let _e = tracing::trace_span!("trace.only");
        }
    "#;
    let names: Vec<_> = scan_text(src).into_iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec!["plain.name".to_string(), "parent.name".to_string(), "both.name".to_string()]
    );
}

#[test]
fn instrument_name_is_read_on_its_own_line() {
    let src = r#"
        #[tracing::instrument(name = "one.line", skip_all)]
        fn a() {}

        #[tracing::instrument(
            level = "debug",
            name = "next.line",
            skip_all,
            fields(note = "not.the.span")
        )]
        fn b() {}

        #[instrument(name = "bare.attr")]
        fn c() {}

        #[tracing::instrument(skip_all)]
        fn d() {}

        #[derive(Debug)]
        struct E;
    "#;
    let names: Vec<_> = scan_text(src).into_iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec!["one.line".to_string(), "next.line".to_string(), "bare.attr".to_string()]
    );
}

#[test]
fn comments_and_strings_are_not_span_sites() {
    let src = r#"
        fn f() {
            // info_span!("commented.name")
            /* #[instrument(name = "block.comment")] */
            let s = "info_span!(\"string.name\")";
            let _real = tracing::info_span!("real.name");
        }
    "#;
    let names: Vec<_> = scan_text(src).into_iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["real.name".to_string()]);
}

#[test]
fn cfg_test_items_are_skipped_and_later_spans_remain() {
    let src = r#"
fn prod() {
    #[cfg(test)]
    if !on() {
        let _h = tracing::info_span!("hidden.in.if");
    }
    let _k = tracing::info_span!("kept.after.if");
}

#[cfg(test)]
mod helper {
    fn t() {
        let _h = tracing::info_span!("hidden.in.mod");
    }
}

#[cfg(not(test))]
fn kept_cfg() {
    let _k = tracing::info_span!("kept.not_test");
}

fn later() {
    let _k = tracing::info_span!(parent: None, "kept.after.mod");
}
"#;
    let names: Vec<_> = scan_text(src).into_iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec![
            "kept.after.if".to_string(),
            "kept.not_test".to_string(),
            "kept.after.mod".to_string(),
        ]
    );
}

#[test]
fn string_continuation_does_not_shift_later_span_lines() {
    let src = "fn f() {\n    let _m = \"abc\\\n        def\";\n    let _s = tracing::info_span!(\"after.continuation\");\n}\n";
    let sites = scan_text(src);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].name, "after.continuation");
    assert_eq!(sites[0].line, 4, "continuation newline must still count: {sites:?}");
}

#[test]
fn unregistered_fixture_is_reported_not_asserted() {
    // The fixture name is not seeded, so `contains` stays false after the
    // registry is filled. The tree scan's eprintln is what prints this shape.
    let src = "fn f() {\n    let _s = tracing::info_span!(\"zz.advisory_plant\");\n}\n";
    let mut sites = scan_text(src);
    assert_eq!(sites.len(), 1);
    sites[0].path = "crates/observability/src/span_names.rs".to_string();
    assert_eq!(sites[0].line, 2);
    assert!(!span_names::contains("zz.advisory_plant"));
    let missing = unregistered(&sites);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].name, "zz.advisory_plant");
}
