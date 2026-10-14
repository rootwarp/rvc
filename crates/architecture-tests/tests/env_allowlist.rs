//! G-3 / ARCH-4b: four-class allow-list over the ARCH-4a extractor.
//!
//! The gate scans **call sites and named constants**, not the `RVC_` prefix.
//! A prefix scan was measured at **438 hits across 57 files**, ~95 % Prometheus
//! metric-name constants, and it misses live reads of `RUST_LOG` and both
//! `OTEL_*` variables (ADR-010). That mechanism is rejected; do not "simplify"
//! this scanner back to a prefix match.
//!
//! Four classes (ADR-010), plus the VD-4.5 [`DYNAMIC_READS`] table:
//!
//! 1. [`SECURITY_OPT_OUT`] — sanctioned `RVC_*_ALLOW_*` names, via **constants
//!    and** inline literals.
//! 2. [`GRANDFATHERED`] — shrinking-only non-security (`RVC_LOG_FORMAT`).
//! 3. [`ECOSYSTEM_CONFIG_WINS`] — `RUST_LOG` / `OTEL_*`. Precedence is
//!    **config-else-env** (config wins, env fills `None`; `tracing.rs:136`
//!    `or_else`, `:146` `None =>`). This is the **opposite** of figment's
//!    idiomatic `Env` layer. Adopting a figment-style `Env` layer would
//!    violate this gate; ADR-008 avoids it by not taking the dependency at
//!    all (C3).
//! 4. Anything else — **fail**, naming file and variable.
//!
//! [`DYNAMIC_READS`] is an allow-list of **exprs** at a file:line, not a skip
//! (VD-4.5). The one sanctioned indirect site is
//! `crates/crypto/src/insecure.rs:168` (`self.env_var`). Names that reach it
//! are classified at every production `InsecureGate::new` / `with_predicate`
//! first argument (string literal or joined ident) via [`class_for_name`].
//! A `Dynamic` whose expr is a simple ident is **joined** to a `*_ENV` /
//! `*_ENV_VAR` constant of that name (VD-4.4: `LOG_FORMAT_ENV` at
//! `format.rs:89`). Any other dynamic read fails.
//!
//! The hit set is measured **post-Phase-0**. The orphan trees carried their
//! own reads (`crates/rvc-signer/src/main.rs:1122, :1213`;
//! `crates/rvc/src/main.rs:992, :997`) and must not be allow-listed.
//!
//! Three shapes land in one [`EnvRead`]:
//!
//! * **literal** — `std::env::var("LITERAL")` / `env::var("LITERAL")` (and
//!   `var_os`);
//! * **dynamic** — `env::var(<anything else>)` as [`Shape::Dynamic`] `{ expr }`.
//!   Captured, never skipped (VD-4.5: the sanctioned opt-outs flow through
//!   `std::env::var(self.env_var)`). `env::vars` / `vars_os` are recorded as
//!   Dynamic so they are not silently dropped;
//! * **constant** — `const <NAME>_ENV: &str = "…"` / `<NAME>_ENV_VAR`.
//!
//! `env::set_var` / `remove_var` are scanned only so they can be excluded from
//! the read set (test scaffolding is not a read).
//!
//! Test-region partition is the **union** of:
//!
//! 1. **Path** — any `tests` path component or a `tests.rs` filename (crate-level
//!    `{bin,crates}/*/tests/**`, `src/**/tests/**`, `src/**/tests.rs`). G-4's
//!    `is_src_tests_path` is not enough: it requires a `src/` prefix and would
//!    miss `bin/rvc/tests` / `crates/*/tests`.
//! 2. **Item** — `#![cfg(test)]` takes the rest of the file; `#[cfg(test)]`
//!    applies to the **next item only** (brace-aware). A mid-file
//!    `#[cfg(test)] fn helper()` does not hide later production reads.
//!    `#[cfg(not(test))]` is not a test region.
//!
//! Remaining limitation: a `cfg(test)` *statement* inside a production function,
//! and `cfg_attr`, are not modelled. House style puts tests in `#[cfg(test)]
//! mod tests` or under a `tests/` path.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled walk, same idiom as
//! `kat_policy.rs`.
//!
//! ## 3. M4 wording — VD-4.3 (done)
//!
//! Project-plan milestone M4 writes `rg 'figment'` returns nothing. Unscoped,
//! that is false at HEAD and after a flawless execution (planning documents name
//! the crate). The corrected guard is source-scoped to `crates/`, `bin/`, root
//! `Cargo.toml`, and `Cargo.lock`, and matches a **dependency** signal, not the
//! English word.
//!
//! Cross-ref: architecture §6 G-3; ADR-008; ADR-010; plan ARCH-4a / ARCH-4b /
//! ARCH-4c; VD-4.3 / VD-4.4 / VD-4.5 / C3.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// This gate's own sources mention the needles inside synthetic fixtures.
// ---------------------------------------------------------------------------

const THIS_GATE: &str = "crates/architecture-tests/tests/env_allowlist.rs";

// ---------------------------------------------------------------------------
// Four-class allow-list + DYNAMIC_READS (ARCH-4b). Reason string required.
// ---------------------------------------------------------------------------

/// Class 1 — sanctioned security opt-outs. Reached via `*_ENV` / `*_ENV_VAR`
/// constants **and** inline `env::var("…")` literals; both routes must classify.
const SECURITY_OPT_OUT: &[(&str, &str)] = &[
    (
        "RVC_ALLOW_INSECURE",
        "operator opt-in for insecure / slashing-off paths (`types.rs`, `signer-server` slashing config)",
    ),
    (
        "RVC_ALLOW_NON_WAL_SLASHING_DB",
        "operator opt-in when WAL cannot be enabled (`slashing/src/db/open.rs`); class-1 without touching the slashing-DB critical section (C1)",
    ),
    (
        "RVC_METRICS_ALLOW_NON_LOOPBACK",
        "operator opt-in for a non-loopback metrics bind (L-10 / `METRICS_ALLOW_NON_LOOPBACK_ENV`)",
    ),
    (
        "RVC_REMOTE_SIGNER_ALLOW_INSECURE",
        "operator opt-in for plaintext remote-signer URLs (`REMOTE_SIGNER_INSECURE_ENV_VAR`)",
    ),
    (
        "RVC_SIGNER_ALLOW_INSECURE",
        "operator opt-in for `--insecure` signer bind (`INSECURE_ENV_VAR`)",
    ),
];

/// Class 2 — grandfathered non-security. Exactly `RVC_LOG_FORMAT`.
///
/// **Shrinking-only:** entries may be **removed**, never **added**. Prefer
/// deleting the env knob (CLI already wins in `telemetry/src/format.rs`) over
/// growing this list. See module docs + `kat_policy.rs` `EXEMPTIONS`.
const GRANDFATHERED: &[(&str, &str)] = &[(
    "RVC_LOG_FORMAT",
    "non-security console-format fallback; CLI wins (`telemetry/src/format.rs`); grandfathered until the env path is deleted",
)];

/// Class 3 — ecosystem-standard **config-else-env** fallbacks.
///
/// Precedence is **config-else-env**: config wins, env only fills a `None`
/// (`tracing.rs:136` `or_else`, `:146` `None =>`). This is the **opposite** of
/// figment's idiomatic `Env` layer (env-wins overlay). Adopting a figment-style
/// `Env` layer would violate this gate; ADR-008 avoids it by not taking the
/// dependency at all (C3).
const ECOSYSTEM_CONFIG_WINS: &[(&str, &str)] = &[
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTLP endpoint; config-else-env (`tracing.rs:136` `or_else`)"),
    ("OTEL_TRACES_SAMPLER_ARG", "OTLP sampler; config-else-env (`tracing.rs:146` `None =>`)"),
    (
        "RUST_LOG",
        "tracing-subscriber filter; ecosystem default, env fills unset (`telemetry/src/init.rs`)",
    ),
];

/// One shrinking-only row: file, 1-based line, allowed expr, constructor-arg
/// idents that flow in, reason.
struct DynamicRead {
    file: &'static str,
    line: usize,
    expr: &'static str,
    flows: &'static [&'static str],
    reason: &'static str,
}

/// VD-4.5: dynamic `env::var(<not-a-literal>)` sites that cannot be joined to a
/// `*_ENV` / `*_ENV_VAR` constant. An allow-list of **exprs**, **not** a skip.
///
/// **Shrinking-only:** entries may be **removed**, never **added**. A new
/// dynamic read at any other file:line, or a different expr at this site, fails.
/// [`flows`](DynamicRead::flows) must equal the production `InsecureGate`
/// first-arg ident set.
const DYNAMIC_READS: &[DynamicRead] = &[DynamicRead {
    file: "crates/crypto/src/insecure.rs",
    line: 168,
    expr: "self.env_var",
    flows: &[
        "INSECURE_ENV_VAR",
        "METRICS_ALLOW_NON_LOOPBACK_ENV",
        "REMOTE_SIGNER_INSECURE_ENV_VAR",
    ],
    reason: "InsecureGate::check reads env::var(self.env_var). Class-1 names \
             that flow in: REMOTE_SIGNER_INSECURE_ENV_VAR \
             (RVC_REMOTE_SIGNER_ALLOW_INSECURE), INSECURE_ENV_VAR \
             (RVC_SIGNER_ALLOW_INSECURE), METRICS_ALLOW_NON_LOOPBACK_ENV \
             (RVC_METRICS_ALLOW_NON_LOOPBACK). RVC_ALLOW_INSECURE and \
             RVC_ALLOW_NON_WAL_SLASHING_DB are inline literals and do not \
             pass through this site.",
}];

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvRead {
    file: String,
    line: usize,
    shape: Shape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Literal { name: String },
    Dynamic { expr: String },
    Constant { ident: String, value: String },
}

impl EnvRead {
    /// NFR-5 / R10: every diagnostic names file, line, and variable (or the
    /// dynamic expression).
    fn diagnostic(&self) -> String {
        match &self.shape {
            Shape::Literal { name } => format!("{}:{}: env read `{name}`", self.file, self.line),
            Shape::Dynamic { expr } => format!("{}:{}: env read `{expr}`", self.file, self.line),
            Shape::Constant { ident, value } => {
                format!("{}:{}: env constant `{ident}` = `{value}`", self.file, self.line)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace walk (kat_policy.rs idiom)
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

/// Best-effort: drop `//` line comments outside of strings.
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

fn skip_ws(src: &str, mut i: usize) -> usize {
    while i < src.len() && src.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_cfg_key_char(b: u8) -> bool {
    is_ident_char(b) || b == b'-'
}

/// `test` as a cfg key that is not the operand of `not`.
fn cfg_has_positive_test(inner: &str) -> bool {
    let bytes = inner.as_bytes();
    let mut from = 0;
    while let Some(rel) = inner[from..].find("test") {
        let at = from + rel;
        from = at + 4;
        // `test-utils` is one cfg key; hyphen stays inside the token.
        let before_ok = at == 0 || !is_cfg_key_char(bytes[at - 1]);
        let after_ok = from >= bytes.len() || !is_cfg_key_char(bytes[from]);
        if !before_ok || !after_ok {
            continue;
        }
        if !test_token_negated(inner, at) {
            return true;
        }
    }
    false
}

fn test_token_negated(inner: &str, at: usize) -> bool {
    let before = inner[..at].trim_end();
    let Some(rest) = before.strip_suffix('(') else {
        return false;
    };
    let rest = rest.trim_end();
    if !rest.ends_with("not") {
        return false;
    }
    let start = rest.len() - 3;
    start == 0 || !is_ident_char(rest.as_bytes()[start - 1])
}

/// True if `trimmed` is a positive `#[cfg(test)]` / `#![cfg(test)]` (not `not(test)`).
fn is_cfg_test_attr(trimmed: &str) -> bool {
    let t = trimmed.trim_end_matches(',').trim();
    if !(t.starts_with("#[cfg(") || t.starts_with("#![cfg(")) {
        return false;
    }
    let inner_start = t.find('(').map(|i| i + 1).unwrap_or(0);
    let inner_end = t.rfind(')').unwrap_or(t.len());
    if inner_start >= inner_end {
        return false;
    }
    cfg_has_positive_test(&t[inner_start..inner_end])
}

fn is_inner_cfg_test_attr(trimmed: &str) -> bool {
    is_cfg_test_attr(trimmed) && trimmed.trim_start().starts_with("#![cfg")
}

fn hit_is_in_comment(src: &str, at: usize) -> bool {
    let ls = line_start(src, at);
    let le = line_end(src, at);
    let line_text = &src[ls..le];
    if is_comment_only_line(line_text) {
        return true;
    }
    let code = code_portion(line_text);
    at - ls >= code.len()
}

// ---------------------------------------------------------------------------
// Test-region partition (path ∪ item-scoped cfg(test))
// ---------------------------------------------------------------------------

/// Crate-level `{bin,crates}/*/tests/**`, `src/**/tests/**`, or `tests.rs`.
///
/// Broader than G-4's `is_src_tests_path`: that helper requires a `src/`
/// component and would miss `bin/rvc/tests` / `crates/*/tests`.
fn is_tests_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split(['/', '\\']).collect();
    parts.contains(&"tests") || parts.last().is_some_and(|p| *p == "tests.rs")
}

fn close_matched(src: &str, open: usize, open_ch: u8, close_ch: u8) -> Option<usize> {
    let bytes = src.as_bytes();
    if open >= bytes.len() || bytes[open] != open_ch {
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
        if b == b'"' {
            in_str = true;
        } else if b == open_ch {
            depth += 1;
        } else if b == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn close_paren(src: &str, open: usize) -> Option<usize> {
    close_matched(src, open, b'(', b')')
}

fn close_brace(src: &str, open: usize) -> Option<usize> {
    close_matched(src, open, b'{', b'}')
}

fn close_bracket(s: &str, open: usize) -> Option<usize> {
    close_matched(s, open, b'[', b']')
}

fn strip_leading_attrs(s: &str) -> &str {
    let mut t = s.trim_start();
    loop {
        let open = if t.starts_with("#![") {
            2
        } else if t.starts_with("#[") {
            1
        } else {
            return t;
        };
        let Some(close) = close_bracket(t, open) else {
            return t;
        };
        t = t[close + 1..].trim_start();
    }
}

fn is_attr_only_line(line: &str) -> bool {
    let code = code_portion(line).trim();
    !code.is_empty() && strip_leading_attrs(code).is_empty()
}

/// Byte offset of the first `{` or `;` outside strings and parentheses.
fn item_end_byte(src: &str, start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut in_str = false;
    let mut paren = 0i32;
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
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' if paren == 0 => return close_brace(src, i),
            b';' if paren == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn line_byte_range(src: &str, line_0: usize) -> (usize, usize) {
    let mut start = 0;
    for _ in 0..line_0 {
        start = match src[start..].find('\n') {
            Some(rel) => start + rel + 1,
            None => return (src.len(), src.len()),
        };
    }
    let end = src[start..].find('\n').map(|rel| start + rel).unwrap_or(src.len());
    (start, end)
}

/// 1-based inclusive spans of `#[cfg(test)]` items (`#![cfg(test)]` → EOF).
fn cfg_test_item_spans(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if !is_cfg_test_attr(trimmed) {
            i += 1;
            continue;
        }
        let start_line = i + 1;
        if is_inner_cfg_test_attr(trimmed) {
            spans.push((start_line, lines.len().max(1)));
            break;
        }
        let Some(item_byte) = find_item_byte_after_cfg(src, &lines, i) else {
            spans.push((start_line, start_line));
            i += 1;
            continue;
        };
        let end_byte = item_end_byte(src, item_byte).unwrap_or(item_byte);
        let end_line = line_at(src, end_byte);
        spans.push((start_line, end_line));
        i = end_line;
    }
    spans
}

fn find_item_byte_after_cfg(src: &str, lines: &[&str], cfg_i: usize) -> Option<usize> {
    for k in cfg_i..lines.len() {
        let (ls, le) = line_byte_range(src, k);
        let line = &src[ls..le.min(src.len())];
        if is_comment_only_line(line) {
            continue;
        }
        let code = code_portion(line);
        let rest =
            if k == cfg_i { strip_leading_attrs(code).trim_start() } else { code.trim_start() };
        if rest.is_empty() {
            continue;
        }
        if k > cfg_i && is_attr_only_line(line) {
            continue;
        }
        let rel = line.find(rest).unwrap_or(0);
        return Some(ls + rel);
    }
    None
}

fn line_in_cfg_test_item(src: &str, line: usize) -> bool {
    cfg_test_item_spans(src).iter().any(|&(s, e)| line >= s && line <= e)
}

fn is_test_region(rel: &str, src: &str, line: usize) -> bool {
    is_tests_path(rel) || line_in_cfg_test_item(src, line)
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

fn parse_string_literal(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        if inner.bytes().any(|b| b == b'"' || b == b'\n') {
            return None;
        }
        return Some(inner);
    }
    None
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_ident_at(src: &str, start: usize) -> &str {
    let bytes = src.as_bytes();
    let mut end = start;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    &src[start..end]
}

/// `set_var` / `remove_var` are recognized here so they never enter the read set.
fn env_method_at(src: &str, env_at: usize) -> Option<(&str, usize)> {
    if env_at > 0 && is_ident_char(src.as_bytes()[env_at - 1]) {
        return None;
    }
    let method_start = env_at + "env::".len();
    if method_start > src.len() {
        return None;
    }
    let method = parse_ident_at(src, method_start);
    if method.is_empty() {
        return None;
    }
    Some((method, method_start + method.len()))
}

fn parse_str_constant(code: &str) -> Option<(String, String)> {
    let mut t = code.trim();
    if let Some(rest) = t.strip_prefix("pub") {
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            let close = rest.find(')')?;
            t = rest[close + 1..].trim_start();
        } else {
            t = rest;
        }
    }
    t = t.strip_prefix("const ")?.trim_start();
    let ident_len = t.bytes().take_while(|&b| is_ident_char(b)).count();
    if ident_len == 0 {
        return None;
    }
    let ident = &t[..ident_len];
    t = t[ident_len..].trim_start();
    if let Some(rest) = t.strip_prefix(':') {
        t = rest.trim_start();
        let eq = t.find('=')?;
        t = t[eq + 1..].trim_start();
    } else {
        t = t.strip_prefix('=')?.trim_start();
    }
    t = t.trim_end().trim_end_matches(';').trim();
    let value = parse_string_literal(t)?;
    Some((ident.to_string(), value.to_string()))
}

fn parse_env_constant(code: &str) -> Option<(String, String)> {
    let (ident, value) = parse_str_constant(code)?;
    if ident.ends_with("_ENV_VAR") || ident.ends_with("_ENV") {
        Some((ident, value))
    } else {
        None
    }
}

fn extract_env_constants(file: &str, src: &str) -> Vec<EnvRead> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if is_comment_only_line(line) {
            continue;
        }
        let Some((ident, value)) = parse_env_constant(code_portion(line)) else {
            continue;
        };
        out.push(EnvRead {
            file: file.to_string(),
            line: i + 1,
            shape: Shape::Constant { ident, value },
        });
    }
    out
}

fn push_call_read(out: &mut Vec<EnvRead>, file: &str, src: &str, at: usize, after_method: usize) {
    let open = skip_ws(src, after_method);
    if open >= src.len() || src.as_bytes()[open] != b'(' {
        return;
    }
    let Some(close) = close_paren(src, open) else {
        return;
    };
    let arg = src[open + 1..close].trim();
    if arg.is_empty() {
        return;
    }
    let shape = match parse_string_literal(arg) {
        Some(name) => Shape::Literal { name: name.to_string() },
        None => Shape::Dynamic { expr: collapse_ws(arg) },
    };
    out.push(EnvRead { file: file.to_string(), line: line_at(src, at), shape });
}

fn extract_env_reads(file: &str, src: &str) -> Vec<EnvRead> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find("env::") {
        let at = from + rel;
        from = at + "env::".len();
        if hit_is_in_comment(src, at) {
            continue;
        }
        let Some((method, after_method)) = env_method_at(src, at) else {
            continue;
        };
        // Writes are scanned so test scaffolding is not mistaken for a read.
        if method == "set_var" || method == "remove_var" {
            continue;
        }
        match method {
            "var" | "var_os" => push_call_read(&mut out, file, src, at, after_method),
            "vars" | "vars_os" => {
                let open = skip_ws(src, after_method);
                if open >= src.len() || src.as_bytes()[open] != b'(' {
                    continue;
                }
                out.push(EnvRead {
                    file: file.to_string(),
                    line: line_at(src, at),
                    shape: Shape::Dynamic { expr: format!("{method}()") },
                });
            }
            _ => {}
        }
    }
    out.extend(extract_env_constants(file, src));
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GateArg {
    Literal { name: String },
    Ident { ident: String },
    Other { expr: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateCtor {
    file: String,
    line: usize,
    arg: GateArg,
}

fn first_call_arg(src: &str, open: usize) -> Option<&str> {
    let close = close_paren(src, open)?;
    let inside = &src[open + 1..close];
    let bytes = inside.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
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
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return Some(inside[..i].trim()),
            _ => {}
        }
        i += 1;
    }
    let t = inside.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn parse_gate_arg(arg: &str) -> GateArg {
    if let Some(name) = parse_string_literal(arg) {
        return GateArg::Literal { name: name.to_string() };
    }
    let collapsed = collapse_ws(arg);
    if is_simple_ident(&collapsed) {
        return GateArg::Ident { ident: collapsed };
    }
    if let Some(ident) = collapsed.rsplit("::").next() {
        if is_simple_ident(ident) && collapsed.bytes().all(|b| is_ident_char(b) || b == b':') {
            return GateArg::Ident { ident: ident.to_string() };
        }
    }
    GateArg::Other { expr: collapsed }
}

fn extract_insecure_gate_ctors(file: &str, src: &str) -> Vec<GateCtor> {
    let mut out = Vec::new();
    for needle in ["InsecureGate::new", "InsecureGate::with_predicate"] {
        let mut from = 0;
        while let Some(rel) = src[from..].find(needle) {
            let at = from + rel;
            from = at + needle.len();
            if hit_is_in_comment(src, at) {
                continue;
            }
            if from < src.len() && is_ident_char(src.as_bytes()[from]) {
                continue;
            }
            let open = skip_ws(src, from);
            if open >= src.len() || src.as_bytes()[open] != b'(' {
                continue;
            }
            let Some(arg) = first_call_arg(src, open) else {
                continue;
            };
            out.push(GateCtor {
                file: file.to_string(),
                line: line_at(src, at),
                arg: parse_gate_arg(arg),
            });
        }
    }
    out
}

fn file_str_consts(file: &str, src: &str) -> HashMap<String, String> {
    if is_tests_path(file) {
        return HashMap::new();
    }
    let spans = cfg_test_item_spans(src);
    let mut out = HashMap::new();
    for (i, line) in src.lines().enumerate() {
        if is_comment_only_line(line) {
            continue;
        }
        let Some((ident, value)) = parse_str_constant(code_portion(line)) else {
            continue;
        };
        let line_no = i + 1;
        if spans.iter().any(|&(s, e)| line_no >= s && line_no <= e) {
            continue;
        }
        out.insert(ident, value);
    }
    out
}

#[derive(Debug)]
struct Partitioned {
    production: Vec<EnvRead>,
    test: Vec<EnvRead>,
    production_ctors: Vec<GateCtor>,
}

fn scan_source(file: &str, src: &str) -> Partitioned {
    let mut production = Vec::new();
    let mut test = Vec::new();
    for read in extract_env_reads(file, src) {
        if is_test_region(file, src, read.line) {
            test.push(read);
        } else {
            production.push(read);
        }
    }
    let mut production_ctors = Vec::new();
    for ctor in extract_insecure_gate_ctors(file, src) {
        if !is_test_region(file, src, ctor.line) {
            production_ctors.push(ctor);
        }
    }
    Partitioned { production, test, production_ctors }
}

struct WorkspaceScan {
    files: Vec<PathBuf>,
    production: Vec<EnvRead>,
    gate_ctors: Vec<GateCtor>,
    str_consts: HashMap<String, String>,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = workspace_rs_files(&root);
    let mut production = Vec::new();
    let mut gate_ctors = Vec::new();
    let mut str_consts = HashMap::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == THIS_GATE {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        let scan = scan_source(&rel, &src);
        production.extend(scan.production);
        gate_ctors.extend(scan.production_ctors);
        str_consts.extend(file_str_consts(&rel, &src));
    }
    WorkspaceScan { files, production, gate_ctors, str_consts }
}

// ---------------------------------------------------------------------------
// Classification (ARCH-4b)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    SecurityOptOut,
    Grandfathered,
    EcosystemConfigWins,
    DynamicAllowlisted,
}

fn name_in(table: &[(&str, &str)], name: &str) -> bool {
    table.iter().any(|(n, _)| *n == name)
}

fn class_for_name(name: &str) -> Option<Class> {
    if name_in(SECURITY_OPT_OUT, name) {
        Some(Class::SecurityOptOut)
    } else if name_in(GRANDFATHERED, name) {
        Some(Class::Grandfathered)
    } else if name_in(ECOSYSTEM_CONFIG_WINS, name) {
        Some(Class::EcosystemConfigWins)
    } else {
        None
    }
}

fn is_simple_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|&c| is_ident_char(c))
}

fn dynamic_row(file: &str, line: usize) -> Option<&'static DynamicRead> {
    DYNAMIC_READS.iter().find(|d| d.file == file && d.line == line)
}

fn constant_map(reads: &[EnvRead]) -> HashMap<&str, &str> {
    reads
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Constant { ident, value } => Some((ident.as_str(), value.as_str())),
            _ => None,
        })
        .collect()
}

fn unsanctioned(read: &EnvRead) -> String {
    format!("{} (not on the G-3 allow-list)", read.diagnostic())
}

fn unsanctioned_name(file: &str, line: usize, name: &str) -> String {
    format!("{file}:{line}: env read `{name}` (not on the G-3 allow-list)")
}

fn classify_read(read: &EnvRead, constants: &HashMap<&str, &str>) -> Result<Class, String> {
    match &read.shape {
        Shape::Literal { name } => class_for_name(name).ok_or_else(|| unsanctioned(read)),
        Shape::Constant { value, .. } => class_for_name(value).ok_or_else(|| unsanctioned(read)),
        Shape::Dynamic { expr } => {
            if let Some(row) = dynamic_row(&read.file, read.line) {
                if expr == row.expr {
                    return Ok(Class::DynamicAllowlisted);
                }
                return Err(unsanctioned(read));
            }
            // VD-4.4: join `env::var(LOG_FORMAT_ENV)` to the constant's value.
            if is_simple_ident(expr) {
                if let Some(value) = constants.get(expr.as_str()) {
                    return class_for_name(value).ok_or_else(|| unsanctioned(read));
                }
            }
            Err(unsanctioned(read))
        }
    }
}

fn classify_ctor(ctor: &GateCtor, constants: &HashMap<String, String>) -> Result<Class, String> {
    match &ctor.arg {
        GateArg::Literal { name } => {
            class_for_name(name).ok_or_else(|| unsanctioned_name(&ctor.file, ctor.line, name))
        }
        GateArg::Ident { ident } => match constants.get(ident) {
            Some(value) => {
                class_for_name(value).ok_or_else(|| unsanctioned_name(&ctor.file, ctor.line, value))
            }
            None => Err(unsanctioned_name(&ctor.file, ctor.line, ident)),
        },
        GateArg::Other { expr } => Err(unsanctioned_name(&ctor.file, ctor.line, expr)),
    }
}

fn classify_all(reads: &[EnvRead]) -> Vec<Result<Class, String>> {
    let constants = constant_map(reads);
    reads.iter().map(|r| classify_read(r, &constants)).collect()
}

fn classify_violations(reads: &[EnvRead]) -> Vec<String> {
    classify_all(reads).into_iter().filter_map(Result::err).collect()
}

fn classify_ctor_violations(file: &str, src: &str) -> Vec<String> {
    let scan = scan_source(file, src);
    let consts = file_str_consts(file, src);
    scan.production_ctors.iter().filter_map(|c| classify_ctor(c, &consts).err()).collect()
}

fn classify_workspace(scan: &WorkspaceScan) -> Vec<String> {
    let mut violations = classify_violations(&scan.production);
    for ctor in &scan.gate_ctors {
        if let Err(e) = classify_ctor(ctor, &scan.str_consts) {
            violations.push(e);
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Matcher unit tests (RED first on the dynamic shape)
// ---------------------------------------------------------------------------

#[test]
fn dynamic_env_read_is_captured_not_skipped() {
    let src = r#"
        let ok = std::env::var(self.env_var).as_deref() == Ok("true");
    "#;
    let reads = extract_env_reads("crates/crypto/src/insecure.rs", src);
    assert_eq!(
        reads.len(),
        1,
        "VD-4.5: dynamic env::var(self.env_var) must be a record, not a skip; got {reads:?}"
    );
    match &reads[0].shape {
        Shape::Dynamic { expr } => {
            assert_eq!(expr, "self.env_var", "dynamic expr must be the argument; got {expr:?}");
        }
        other => panic!("expected Shape::Dynamic, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/crypto/src/insecure.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains(&format!(":{}:", reads[0].line)), "diagnostic must name line; got {msg}");
    assert!(msg.contains("self.env_var"), "diagnostic must name the expression; got {msg}");
}

#[test]
fn cfg_test_region_reads_are_partitioned_out() {
    let src = r#"
fn production() {
    let _ = std::env::var("PROD_VAR");
}

#[cfg(test)]
mod tests {
    fn t() {
        let _ = std::env::var("TEST_VAR");
    }
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    assert_eq!(scan.production.len(), 1, "one production read; got {scan:?}");
    assert_eq!(scan.test.len(), 1, "one test read; got {:?}", scan.test);
    match &scan.production[0].shape {
        Shape::Literal { name } => assert_eq!(name, "PROD_VAR"),
        other => panic!("expected literal PROD_VAR, got {other:?}"),
    }
    match &scan.test[0].shape {
        Shape::Literal { name } => assert_eq!(name, "TEST_VAR"),
        other => panic!("expected literal TEST_VAR, got {other:?}"),
    }
    let prod_msg = scan.production[0].diagnostic();
    assert!(
        prod_msg.contains("crates/example/src/lib.rs"),
        "diagnostic must name file; got {prod_msg}"
    );
    assert!(prod_msg.contains("PROD_VAR"), "diagnostic must name variable; got {prod_msg}");
}

#[test]
fn integration_test_path_reads_are_partitioned_out() {
    let src = "    let _ = std::env::var(\"X\");\n";
    assert!(!src.contains("cfg(test)"), "path rule must apply with no in-file #[cfg(test)]");
    for rel in ["bin/rvc/tests/foo.rs", "crates/foo/tests/bar.rs", "crates/rvc/src/foo/tests.rs"] {
        let scan = scan_source(rel, src);
        assert!(
            scan.production.is_empty(),
            "{rel}: integration/src tests path must not be production; got {scan:?}"
        );
        assert_eq!(scan.test.len(), 1, "{rel}: expected one test read; got {:?}", scan.test);
        match &scan.test[0].shape {
            Shape::Literal { name } => assert_eq!(name, "X"),
            other => panic!("{rel}: expected literal X, got {other:?}"),
        }
    }
}

#[test]
fn mid_file_cfg_test_helper_does_not_hide_later_production() {
    let src = r#"
fn before() {
    let _ = std::env::var("BEFORE");
}

#[cfg(test)]
fn helper() {
    let _ = std::env::var("HELPER");
}

fn after() {
    let _ = std::env::var("PROD");
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    let prod: Vec<_> = scan
        .production
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Literal { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let test: Vec<_> = scan
        .test
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Literal { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(prod, ["BEFORE", "PROD"], "later production must stay production; got {scan:?}");
    assert_eq!(test, ["HELPER"], "cfg(test) helper is test-only; got {scan:?}");
}

#[test]
fn not_test_cfg_does_not_start_a_test_region() {
    let src = r#"
#[cfg(not(test))]
fn prod() {
    let _ = std::env::var("PROD_VAR");
}

fn also() {
    let _ = std::env::var("ALSO");
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    assert_eq!(scan.test.len(), 0, "not(test) must not be a test region; got {scan:?}");
    assert_eq!(scan.production.len(), 2, "both reads stay production; got {scan:?}");
}

#[test]
fn cfg_test_attr_detection() {
    assert!(is_cfg_test_attr("#[cfg(test)]"));
    assert!(is_cfg_test_attr("#![cfg(test)]"));
    assert!(is_cfg_test_attr("#[cfg(all(test, feature = \"x\"))]"));
    assert!(!is_cfg_test_attr("#[cfg(feature = \"test-utils\")]"));
    assert!(!is_cfg_test_attr("#[test]"));
    assert!(!is_cfg_test_attr("#[cfg(not(test))]"));
    assert!(!is_cfg_test_attr("#[cfg(all(not(test), unix))]"));
}

#[test]
fn env_constant_declaration_is_extracted() {
    let src = r#"pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";"#;
    let reads = extract_env_reads("crates/telemetry/src/format.rs", src);
    assert_eq!(reads.len(), 1, "constant declaration must be a record; got {reads:?}");
    match &reads[0].shape {
        Shape::Constant { ident, value } => {
            assert_eq!(ident, "LOG_FORMAT_ENV");
            assert_eq!(value, "RVC_LOG_FORMAT");
        }
        other => panic!("expected Shape::Constant LOG_FORMAT_ENV → RVC_LOG_FORMAT, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/telemetry/src/format.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains(&format!(":{}:", reads[0].line)), "diagnostic must name line; got {msg}");
    assert!(msg.contains("LOG_FORMAT_ENV"), "diagnostic must name the ident; got {msg}");
    assert!(msg.contains("RVC_LOG_FORMAT"), "diagnostic must name the variable; got {msg}");

    let src = r#"pub const INSECURE_ENV_VAR: &str = "RVC_SIGNER_ALLOW_INSECURE";"#;
    let reads = extract_env_reads("crates/signer-server/src/insecure_startup.rs", src);
    assert_eq!(reads.len(), 1, "_ENV_VAR suffix must be a record; got {reads:?}");
    match &reads[0].shape {
        Shape::Constant { ident, value } => {
            assert_eq!(ident, "INSECURE_ENV_VAR");
            assert_eq!(value, "RVC_SIGNER_ALLOW_INSECURE");
        }
        other => panic!("expected INSECURE_ENV_VAR → RVC_SIGNER_ALLOW_INSECURE, got {other:?}"),
    }
}

#[test]
fn set_var_is_not_a_read() {
    let src = r#"
        std::env::set_var("FOO", "1");
        env::set_var("BAR", "2");
        std::env::remove_var("FOO");
        env::remove_var("BAR");
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert!(reads.is_empty(), "set_var/remove_var must not produce EnvRead; got {reads:?}");
}

#[test]
fn var_os_is_captured_as_a_read() {
    let src = r#"
        let _ = std::env::var_os("RUST_LOG");
        let _ = env::var_os(self.env_var);
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert_eq!(reads.len(), 2, "var_os is a read; got {reads:?}");
    match &reads[0].shape {
        Shape::Literal { name } => assert_eq!(name, "RUST_LOG"),
        other => panic!("expected literal RUST_LOG, got {other:?}"),
    }
    match &reads[1].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "self.env_var"),
        other => panic!("expected dynamic self.env_var, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/example/src/lib.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains("RUST_LOG"), "diagnostic must name the variable; got {msg}");
}

#[test]
fn vars_family_is_captured_not_skipped() {
    let src = r#"
        for (k, _) in std::env::vars() {}
        for (k, _) in env::vars_os() {}
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert_eq!(reads.len(), 2, "vars/vars_os must be recorded, not dropped; got {reads:?}");
    match &reads[0].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "vars()"),
        other => panic!("expected Dynamic vars(), got {other:?}"),
    }
    match &reads[1].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "vars_os()"),
        other => panic!("expected Dynamic vars_os(), got {other:?}"),
    }
}

#[test]
fn scanner_is_non_vacuous_over_the_real_workspace() {
    let scan = scan_workspace();
    let files = &scan.files;
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());
    let production_reads = scan.production.len();
    assert!(
        production_reads >= 8,
        "found only {production_reads} production env read(s); workspace walk likely broke"
    );
    assert!(
        scan.production.iter().all(|r| r.file != THIS_GATE),
        "{THIS_GATE} must not scan its own synthetic fixtures"
    );
    assert!(
        scan.production.iter().all(|r| !is_tests_path(&r.file)),
        "production set must not include tests/ paths: {:?}",
        scan.production.iter().filter(|r| is_tests_path(&r.file)).collect::<Vec<_>>()
    );
    assert!(
        scan.production.iter().any(|r| {
            r.file.ends_with("crates/crypto/src/insecure.rs")
                && matches!(&r.shape, Shape::Dynamic { expr } if expr == "self.env_var")
        }),
        "workspace walk must see insecure.rs self.env_var; got {:?}",
        scan.production
    );
    assert!(
        scan.production.iter().any(|r| {
            r.file.ends_with("crates/telemetry/src/init.rs")
                && matches!(&r.shape, Shape::Literal { name } if name == "RUST_LOG")
        }),
        "workspace walk must see init.rs RUST_LOG; got {:?}",
        scan.production
    );
}

// ---------------------------------------------------------------------------
// Classification (ARCH-4b) — RED first on the unsanctioned name
// ---------------------------------------------------------------------------

#[test]
fn unsanctioned_env_read_fails_naming_file_and_variable() {
    let src = r#"
fn prod() {
    let _ = std::env::var("RVC_TOTALLY_NEW_KNOB");
}
"#;
    let file = "crates/example/src/lib.rs";
    let scan = scan_source(file, src);
    assert_eq!(scan.production.len(), 1, "expected one production read; got {scan:?}");
    let violations = classify_violations(&scan.production);
    assert_eq!(violations.len(), 1, "unsanctioned knob must fail; got {violations:?}");
    let msg = &violations[0];
    assert!(msg.contains(file), "failure must name file; got {msg}");
    assert!(msg.contains("RVC_TOTALLY_NEW_KNOB"), "failure must name variable; got {msg}");

    let src = r#"
fn prod() {
    let _ = InsecureGate::new("RVC_TOTALLY_NEW_KNOB", addr, InsecureMode::Refuse);
}
"#;
    let violations = classify_ctor_violations(file, src);
    assert!(!violations.is_empty(), "InsecureGate literal must fail; got {violations:?}");
    let msg = violations.join("\n");
    assert!(msg.contains(file), "failure must name file; got {msg}");
    assert!(msg.contains("RVC_TOTALLY_NEW_KNOB"), "failure must name variable; got {msg}");

    let src = r#"
const FOO: &str = "RVC_TOTALLY_NEW_KNOB";
fn prod() {
    let _ = InsecureGate::new(FOO, addr, InsecureMode::Refuse);
}
"#;
    let violations = classify_ctor_violations(file, src);
    assert!(!violations.is_empty(), "non-suffix const FOO must fail; got {violations:?}");
    let msg = violations.join("\n");
    assert!(msg.contains(file), "failure must name file; got {msg}");
    assert!(msg.contains("RVC_TOTALLY_NEW_KNOB"), "failure must name variable; got {msg}");
}

#[test]
fn dynamic_read_not_on_the_table_fails() {
    let src = r#"
fn prod() {
    let _ = env::var(other.var_name);
}
"#;
    let file = "crates/example/src/elsewhere.rs";
    assert!(
        !DYNAMIC_READS.iter().any(|d| d.file == file),
        "fixture file must be absent from DYNAMIC_READS"
    );
    let scan = scan_source(file, src);
    assert_eq!(scan.production.len(), 1, "expected one dynamic read; got {scan:?}");
    let violations = classify_violations(&scan.production);
    assert!(
        !violations.is_empty(),
        "dynamic read off DYNAMIC_READS must fail (allow-list, not a skip); got {violations:?}"
    );
    let msg = violations.join("\n");
    assert!(msg.contains(file), "failure must name file; got {msg}");
    assert!(msg.contains("other.var_name"), "failure must name the expression; got {msg}");
}

#[test]
fn dynamic_read_wrong_expr_at_allowlisted_site_fails() {
    let file = DYNAMIC_READS[0].file;
    let mut src = String::new();
    for _ in 1..DYNAMIC_READS[0].line {
        src.push('\n');
    }
    src.push_str("let _ = std::env::var(other.var_name);\n");
    let scan = scan_source(file, &src);
    assert!(
        scan.production.iter().any(|r| {
            r.line == DYNAMIC_READS[0].line
                && matches!(&r.shape, Shape::Dynamic { expr } if expr == "other.var_name")
        }),
        "expected dynamic other.var_name at allowlisted line; got {scan:?}"
    );
    let violations = classify_violations(&scan.production);
    assert!(
        !violations.is_empty(),
        "different expr at DYNAMIC_READS site must fail; got {violations:?}"
    );
    let msg = violations.join("\n");
    assert!(msg.contains(file), "failure must name file; got {msg}");
    assert!(msg.contains("other.var_name"), "failure must name the expression; got {msg}");
}

#[test]
fn all_five_security_opt_outs_classify_via_constant_and_literal() {
    assert_eq!(
        SECURITY_OPT_OUT.len(),
        5,
        "class 1 is the five sanctioned opt-outs; got {SECURITY_OPT_OUT:?}"
    );
    for (i, &(name, reason)) in SECURITY_OPT_OUT.iter().enumerate() {
        assert!(!reason.trim().is_empty(), "{name} missing reason");
        let ident = format!("KNOB_{i}_ENV_VAR");
        let src = format!(
            "pub const {ident}: &str = \"{name}\";\nfn f() {{ let _ = std::env::var(\"{name}\"); }}\n"
        );
        let scan = scan_source("crates/example/src/opt_out.rs", &src);
        assert_eq!(scan.production.len(), 2, "{name}: expected constant + literal; got {scan:?}");
        let classes = classify_all(&scan.production);
        assert_eq!(
            classes.len(),
            2,
            "{name}: classifier must return one result per read; got {classes:?}"
        );
        for (read, class) in scan.production.iter().zip(&classes) {
            match class {
                Ok(Class::SecurityOptOut) => {}
                other => panic!(
                    "{name}: {read:?} must be class 1 via constant and literal; got {other:?}"
                ),
            }
        }
    }
}

#[test]
fn real_workspace_is_green() {
    assert_eq!(DYNAMIC_READS.len(), 1, "DYNAMIC_READS is shrinking-only; HEAD has one site");
    assert_eq!(DYNAMIC_READS[0].file, "crates/crypto/src/insecure.rs");
    assert_eq!(DYNAMIC_READS[0].line, 168);
    assert_eq!(DYNAMIC_READS[0].expr, "self.env_var");
    assert!(!DYNAMIC_READS[0].reason.trim().is_empty(), "DYNAMIC_READS reason required");
    assert!(
        !DYNAMIC_READS[0].flows.is_empty(),
        "DYNAMIC_READS must name the constants that flow in"
    );

    let scan = scan_workspace();
    let violations = classify_workspace(&scan);
    assert!(
        violations.is_empty(),
        "G-3: unsanctioned production env read(s):\n  {}",
        violations.join("\n  ")
    );

    let mut actual_flows: Vec<&str> = scan
        .gate_ctors
        .iter()
        .map(|c| match &c.arg {
            GateArg::Ident { ident } => ident.as_str(),
            GateArg::Literal { name } => name.as_str(),
            GateArg::Other { expr } => expr.as_str(),
        })
        .collect();
    actual_flows.sort_unstable();
    actual_flows.dedup();
    let mut expected_flows: Vec<&str> = DYNAMIC_READS[0].flows.to_vec();
    expected_flows.sort_unstable();
    assert_eq!(
        actual_flows, expected_flows,
        "DYNAMIC_READS.flows must equal the production InsecureGate first-arg set"
    );
    for flow in DYNAMIC_READS[0].flows {
        let value = scan
            .str_consts
            .get(*flow)
            .unwrap_or_else(|| panic!("DYNAMIC_READS flow `{flow}` has no production const"));
        assert_eq!(
            class_for_name(value),
            Some(Class::SecurityOptOut),
            "flow `{flow}` = `{value}` must be class 1"
        );
    }

    let names: HashSet<&str> = scan
        .production
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Literal { name } => Some(name.as_str()),
            Shape::Constant { value, .. } => Some(value.as_str()),
            Shape::Dynamic { .. } => None,
        })
        .collect();
    for &(name, _) in SECURITY_OPT_OUT {
        assert!(names.contains(name), "class 1 `{name}` missing from production scan");
    }
    for &(name, _) in GRANDFATHERED {
        assert!(names.contains(name), "class 2 `{name}` missing from production scan");
    }
    for &(name, _) in ECOSYSTEM_CONFIG_WINS {
        assert!(names.contains(name), "class 3 `{name}` missing from production scan");
    }

    assert!(
        scan.production.iter().any(|r| {
            r.file == DYNAMIC_READS[0].file
                && r.line == DYNAMIC_READS[0].line
                && matches!(&r.shape, Shape::Dynamic { expr } if expr == "self.env_var")
        }),
        "DYNAMIC_READS site missing from production scan; got {:?}",
        scan.production
    );

    let idents: HashSet<&str> = scan
        .production
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Constant { ident, .. } => Some(ident.as_str()),
            _ => None,
        })
        .collect();
    for flow in DYNAMIC_READS[0].flows {
        assert!(
            idents.contains(flow),
            "DYNAMIC_READS flow `{flow}` is not a production *_ENV constant"
        );
    }

    let insecure = std::fs::read_to_string(workspace_root().join(DYNAMIC_READS[0].file))
        .expect("insecure.rs readable");
    let line =
        insecure.lines().nth(DYNAMIC_READS[0].line - 1).expect("DYNAMIC_READS line in range");
    assert!(
        line.contains("self.env_var") && line.contains("env::var"),
        "DYNAMIC_READS line drifted: {line}"
    );
}

#[test]
fn grandfathered_table_is_documented_shrinking_only() {
    assert_eq!(GRANDFATHERED.len(), 1, "class 2 is exactly RVC_LOG_FORMAT");
    assert_eq!(GRANDFATHERED[0].0, "RVC_LOG_FORMAT");
    assert!(!GRANDFATHERED[0].1.trim().is_empty(), "GRANDFATHERED reason required");

    let src = include_str!("env_allowlist.rs");
    let at = src.find("const GRANDFATHERED").expect("GRANDFATHERED table");
    let window = &src[at.saturating_sub(800)..at];
    assert!(
        window.contains("**Shrinking-only:** entries may be **removed**, never **added**"),
        "GRANDFATHERED must use the kat_policy EXEMPTIONS shrinking-only wording; window={window}"
    );

    let at = src.find("const ECOSYSTEM_CONFIG_WINS").expect("class 3 table");
    let window = &src[at.saturating_sub(1200)..at];
    assert!(
        window.contains("config-else-env"),
        "class 3 must state config-else-env; window={window}"
    );
    assert!(window.contains("tracing.rs:136"), "class 3 must cite tracing.rs:136; window={window}");
    assert!(window.contains(":146"), "class 3 must cite :146; window={window}");
    assert!(
        window.contains("figment") && window.contains("ADR-008"),
        "C3: class 3 must say a figment Env layer would violate this gate and ADR-008 avoids the dep; window={window}"
    );
}

// ---------------------------------------------------------------------------
// Figment absence (ARCH-4c / VD-4.3)
// ---------------------------------------------------------------------------

/// Why the dependency is forbidden. Failure copy must include this sentence.
const FIGMENT_ABSENCE_WHY: &str = "ADR-008 rejects figment outright; C3 forbids an env layer, and this repo honours it by not taking the dependency.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct FigmentHit {
    file: String,
    line: usize,
}

impl FigmentHit {
    fn diagnostic(&self) -> String {
        format!("{}:{}: figment dependency", self.file, self.line)
    }
}

fn figment_absence_message(hits: &[FigmentHit]) -> String {
    let listed = hits.iter().map(FigmentHit::diagnostic).collect::<Vec<_>>().join("\n  ");
    format!("{listed}\n{FIGMENT_ABSENCE_WHY}")
}

/// Source-scoped roots: `crates/`, `bin/`, workspace `Cargo.toml`, `Cargo.lock`.
fn is_figment_source_path(rel: &str) -> bool {
    let rel = rel.replace('\\', "/");
    let rel = rel.trim_start_matches("./");
    rel == "Cargo.toml"
        || rel == "Cargo.lock"
        || rel.starts_with("crates/")
        || rel.starts_with("bin/")
}

enum FigmentFile {
    Toml,
    Lock,
    Rust,
    Other,
}

fn figment_file_kind(rel: &str) -> FigmentFile {
    let rel = rel.replace('\\', "/");
    let base = rel.rsplit('/').next().unwrap_or(rel.as_str());
    if base == "Cargo.lock" {
        FigmentFile::Lock
    } else if base == "Cargo.toml" || base.ends_with(".toml") {
        FigmentFile::Toml
    } else if base.ends_with(".rs") {
        FigmentFile::Rust
    } else {
        FigmentFile::Other
    }
}

fn figment_hits_in(rel: &str, src: &str) -> Vec<FigmentHit> {
    if !is_figment_source_path(rel) {
        return Vec::new();
    }
    match figment_file_kind(rel) {
        FigmentFile::Toml => figment_line_hits(rel, src, toml_line_is_figment_dep),
        FigmentFile::Lock => figment_line_hits(rel, src, lock_line_is_figment),
        FigmentFile::Rust => figment_line_hits(rel, src, rust_line_is_figment_crate_use),
        FigmentFile::Other => Vec::new(),
    }
}

fn figment_line_hits(file: &str, src: &str, pred: fn(&str) -> bool) -> Vec<FigmentHit> {
    src.lines()
        .enumerate()
        .filter(|(_, line)| pred(line))
        .map(|(i, _)| FigmentHit { file: file.to_string(), line: i + 1 })
        .collect()
}

fn hash_comment_code(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
        } else if !in_str && b == b'#' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn strip_toml_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn toml_key_is_figment(key: &str) -> bool {
    let key = strip_toml_quotes(key);
    key == "figment" || key.starts_with("figment.")
}

fn toml_table_names_figment(inner: &str) -> bool {
    inner.split('.').any(|seg| strip_toml_quotes(seg.trim()) == "figment")
}

fn toml_has_package_figment(code: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = code[from..].find("package") {
        let at = from + rel;
        from = at + "package".len();
        if at > 0 && is_ident_char(code.as_bytes()[at - 1]) {
            continue;
        }
        if from < code.len() && is_ident_char(code.as_bytes()[from]) {
            continue;
        }
        let rest = code[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("\"figment\"") || rest.starts_with("'figment'") {
            return true;
        }
    }
    false
}

fn toml_line_is_figment_dep(line: &str) -> bool {
    let code = hash_comment_code(line).trim();
    if code.is_empty() {
        return false;
    }
    if let Some(inner) = code.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return toml_table_names_figment(inner);
    }
    if let Some(eq) = code.find('=') {
        let key = code[..eq].trim();
        if !key.is_empty() && !key.contains('[') && toml_key_is_figment(key) {
            return true;
        }
    }
    toml_has_package_figment(code)
}

fn lock_line_is_figment(line: &str) -> bool {
    let t = line.trim();
    if t == "name = \"figment\"" {
        return true;
    }
    let item = t.trim_end_matches(',').trim();
    item == "\"figment\"" || item.starts_with("\"figment ")
}

fn ident_is_figment_at(src: &str, at: usize) -> bool {
    const NEEDLE: &str = "figment";
    if !src[at..].starts_with(NEEDLE) {
        return false;
    }
    let bytes = src.as_bytes();
    if at > 0 && is_ident_char(bytes[at - 1]) {
        return false;
    }
    let end = at + NEEDLE.len();
    end >= bytes.len() || !is_ident_char(bytes[end])
}

fn keyword_at_end(s: &str, kw: &str) -> bool {
    if !s.ends_with(kw) {
        return false;
    }
    let start = s.len() - kw.len();
    start == 0 || !is_ident_char(s.as_bytes()[start - 1])
}

fn span_is_in_double_quotes(code: &str, at: usize) -> bool {
    let bytes = code.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < at && i < bytes.len() {
        let b = bytes[i];
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
        }
        i += 1;
    }
    in_str
}

fn rust_is_crate_use(code: &str, at: usize) -> bool {
    let after = &code[at + "figment".len()..];
    if after.starts_with("::") {
        return true;
    }
    let before = code[..at].trim_end();
    let before = before.strip_suffix("::").map(str::trim_end).unwrap_or(before);
    if keyword_at_end(before, "use") {
        return true;
    }
    if keyword_at_end(before, "crate") {
        let rest = before[..before.len() - "crate".len()].trim_end();
        return keyword_at_end(rest, "extern");
    }
    false
}

fn rust_line_is_figment_crate_use(line: &str) -> bool {
    if is_comment_only_line(line) {
        return false;
    }
    let code = code_portion(line);
    let mut from = 0;
    while let Some(rel) = code[from..].find("figment") {
        let at = from + rel;
        from = at + "figment".len();
        if !ident_is_figment_at(code, at) || span_is_in_double_quotes(code, at) {
            continue;
        }
        if rust_is_crate_use(code, at) {
            return true;
        }
    }
    false
}

fn is_figment_scan_filename(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "Cargo.toml"
        || name == "Cargo.lock"
        || path.extension().is_some_and(|e| e == "rs" || e == "toml")
}

fn collect_figment_tree(dir: &Path, out: &mut Vec<PathBuf>) {
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
            collect_figment_tree(&path, out);
        } else if is_figment_scan_filename(&path) {
            out.push(path);
        }
    }
}

fn collect_figment_scan_files(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    collect_figment_tree(&root.join("crates"), &mut out);
    collect_figment_tree(&root.join("bin"), &mut out);
    out
}

fn scan_figment_workspace() -> (Vec<PathBuf>, Vec<FigmentHit>) {
    let root = workspace_root();
    let files = collect_figment_scan_files(&root);
    let mut hits = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy().replace('\\', "/");
        let src = std::fs::read_to_string(file).unwrap_or_default();
        hits.extend(figment_hits_in(&rel, &src));
    }
    (files, hits)
}

fn assert_figment_hit_names_file(file: &str, src: &str) {
    let hits = figment_hits_in(file, src);
    assert!(!hits.is_empty(), "expected a figment hit in {file}; src={src:?}");
    assert!(hits.iter().all(|h| h.file == file), "hit must name the file; got {hits:?}");
    let msg = figment_absence_message(&hits);
    assert!(msg.contains(file), "failure must name the file; got {msg}");
    assert!(msg.contains(FIGMENT_ABSENCE_WHY), "failure must say why; got {msg}");
}

#[test]
fn figment_manifest_dep_line_names_the_file() {
    assert_figment_hit_names_file("crates/rvc/Cargo.toml", "figment = \"0.10\"\n");
}

#[test]
fn figment_toml_table_and_rename_and_git_name_the_file() {
    assert_figment_hit_names_file(
        "crates/rvc/Cargo.toml",
        "[dependencies.figment]\nversion = \"0.10\"\n",
    );
    assert_figment_hit_names_file(
        "crates/rvc/Cargo.toml",
        "cfg = { package = \"figment\", version = \"0.10\" }\n",
    );
    assert_figment_hit_names_file(
        "crates/rvc/Cargo.toml",
        "figment = { git = \"https://github.com/SergioBenitez/Figment\" }\n",
    );
}

#[test]
fn figment_lock_lines_name_the_file() {
    assert_figment_hit_names_file("Cargo.lock", "name = \"figment\"\n");
    assert_figment_hit_names_file("Cargo.lock", " \"figment 0.10.19\",\n");
}

#[test]
fn figment_rust_crate_use_names_the_file() {
    assert_figment_hit_names_file("crates/rvc/src/lib.rs", "extern crate figment;\n");
    assert_figment_hit_names_file("crates/rvc/src/lib.rs", "let _ = figment::Figment::new();\n");
}

#[test]
fn figment_scan_ignores_plan_documents() {
    let src = "use figment::providers::Env;\nfigment = \"0.10\"\n";
    let plan = "plan/architecture-2026-08-12/project-plan.md";
    assert!(!is_figment_source_path(plan), "plan/ is outside crates/ bin/ Cargo.toml Cargo.lock");
    assert!(
        figment_hits_in(plan, src).is_empty(),
        "a plan/ path containing figment must not trip the gate"
    );
    let rust_hits = figment_hits_in("crates/rvc/src/lib.rs", "use figment::providers::Env;\n");
    assert!(!rust_hits.is_empty(), "the same crate-use under crates/ must be in scope");
}

#[test]
fn figment_dependency_is_absent_from_source() {
    let root = workspace_root();
    let lock = root.join("Cargo.lock");
    assert!(lock.is_file(), "workspace Cargo.lock must exist; lock backstop otherwise vacuous");
    let lock_src = std::fs::read_to_string(&lock).expect("workspace Cargo.lock must be readable");
    assert!(
        !lock_src.is_empty() && lock_src.contains("[[package]]"),
        "workspace Cargo.lock is empty or not a lockfile; lock backstop did not run"
    );

    let (files, hits) = scan_figment_workspace();
    assert!(files.len() > 100, "figment scan walked only {} files; walk likely broke", files.len());
    assert!(
        files.iter().any(|f| f.file_name().is_some_and(|n| n == "Cargo.toml")),
        "figment scan must include Cargo.toml"
    );
    assert!(
        files.iter().any(|f| f == &lock),
        "figment scan must include the workspace-root Cargo.lock path"
    );
    let files_norm: Vec<String> =
        files.iter().map(|f| f.to_string_lossy().replace('\\', "/")).collect();
    assert!(
        files_norm.iter().any(|s| s.contains("/crates/") && s.ends_with(".rs")),
        "figment scan must walk crates/"
    );
    assert!(
        files_norm.iter().any(|s| s.contains("/bin/") && s.ends_with(".rs")),
        "figment scan must walk bin/"
    );
    assert!(hits.is_empty(), "{}", figment_absence_message(&hits));
}
