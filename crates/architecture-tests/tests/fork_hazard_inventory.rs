//! Issue 2.2 / #216: CI inventory of fork-addition hazards.
//!
//! A new `ForkName` arm must not silently change behaviour. This gate scans
//! `crates/**` and `bin/**` for five greppable classes and asserts every hit
//! is in the checked-in inventory with a verdict — no `unclassified`, exact
//! per-class counts. The human table is `docs/gloas-fork-hazard-audit.md`;
//! this file is the machine copy. The two must agree.
//!
//! Classes: (1) `>= ForkName::X` (2) `.index = 0` / `.index = "0"` (3) `match`
//! on `ForkName` exhaustive vs `_ =>` (4) string-literal fork dispatch
//! (5) `.entries()` call sites.
//!
//! Self-exclusion (D7): this file's inventory literals contain the snippets
//! it searches for, so the walker skips its own path
//! (`kat_policy.rs:381-386` precedent).
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same idiom as
//! `no_rvc_prefix.rs` / `kat_policy.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Classes / verdicts / inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Class {
    GeForkName = 1,
    IndexZero = 2,
    MatchForkName = 3,
    StringDispatch = 4,
    Entries = 5,
}

impl Class {
    fn n(self) -> u8 {
        self as u8
    }

    fn from_n(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::GeForkName),
            2 => Some(Self::IndexZero),
            3 => Some(Self::MatchForkName),
            4 => Some(Self::StringDispatch),
            5 => Some(Self::Entries),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::GeForkName => ">= ForkName::X",
            Self::IndexZero => "index = 0",
            Self::MatchForkName => "match ForkName",
            Self::StringDispatch => "string-literal fork dispatch",
            Self::Entries => ".entries()",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    InheritIntentionally,
    MustBound,
    DecidedNotInherited,
    TestOnly,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::InheritIntentionally => "inherit-intentionally",
            Self::MustBound => "must-bound",
            Self::DecidedNotInherited => "decided-not-inherited",
            Self::TestOnly => "test-only",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "inherit-intentionally" => Some(Self::InheritIntentionally),
            "must-bound" => Some(Self::MustBound),
            "decided-not-inherited" => Some(Self::DecidedNotInherited),
            "test-only" => Some(Self::TestOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Inv {
    path: &'static str,
    line: usize,
    class: Class,
    wildcard: bool,
    snippet: &'static str,
    verdict: Verdict,
    issue: &'static str,
}

const fn inv(
    path: &'static str,
    line: usize,
    class: Class,
    wildcard: bool,
    snippet: &'static str,
    verdict: Verdict,
    issue: &'static str,
) -> Inv {
    Inv { path, line, class, wildcard, snippet, verdict, issue }
}

/// Exact per-class counts. Update together with [`INVENTORY`] and the audit doc.
const EXPECTED_COUNTS: [(Class, usize); 5] = [
    (Class::GeForkName, 6),
    (Class::IndexZero, 6),
    (Class::MatchForkName, 3),
    (Class::StringDispatch, 6),
    (Class::Entries, 6),
];

/// Checked-in `(path, snippet)` inventory. Sorted by (class, path, line).
const INVENTORY: &[Inv] = &[
    // Class 1
    inv(
        "bin/rvc-keygen/src/exit.rs",
        107,
        Class::GeForkName,
        false,
        ">= ForkName::Capella",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/signing_root.rs",
        228,
        Class::GeForkName,
        false,
        ">= ForkName::Capella",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/signing_root.rs",
        286,
        Class::GeForkName,
        false,
        ">= ForkName::Capella",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/aggregation.rs",
        88,
        Class::GeForkName,
        false,
        ">= ForkName::Fulu",
        Verdict::DecidedNotInherited,
        "phase-6",
    ),
    inv(
        "crates/rvc/src/orchestrator/aggregation.rs",
        130,
        Class::GeForkName,
        false,
        ">= ForkName::Fulu",
        Verdict::DecidedNotInherited,
        "phase-6",
    ),
    inv(
        "crates/rvc/src/orchestrator/attestation.rs",
        423,
        Class::GeForkName,
        false,
        ">= ForkName::Fulu",
        Verdict::DecidedNotInherited,
        "phase-6",
    ),
    // Class 2
    inv(
        "crates/rvc/src/orchestrator/attestation.rs",
        416,
        Class::IndexZero,
        false,
        ".index = \"0\"",
        Verdict::MustBound,
        "2.8",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        513,
        Class::IndexZero,
        false,
        ".index = 0",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        636,
        Class::IndexZero,
        false,
        ".index = 0",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        665,
        Class::IndexZero,
        false,
        ".index = 0",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        673,
        Class::IndexZero,
        false,
        ".index = \"0\"",
        Verdict::TestOnly,
        "2.8",
    ),
    inv(
        "crates/rvc/src/orchestrator/utils.rs",
        152,
        Class::IndexZero,
        false,
        ".index = 0",
        Verdict::MustBound,
        "2.3",
    ),
    // Class 3
    inv(
        "bin/rvc/tests/common/mock_bn.rs",
        266,
        Class::MatchForkName,
        false,
        "match fork {",
        Verdict::TestOnly,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        148,
        Class::MatchForkName,
        false,
        "match self {",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        164,
        Class::MatchForkName,
        false,
        "match self {",
        Verdict::InheritIntentionally,
        "2.7",
    ),
    // Class 4
    inv(
        "crates/beacon/src/client.rs",
        751,
        Class::StringDispatch,
        false,
        "match proofs {",
        Verdict::InheritIntentionally,
        "phase-6",
    ),
    inv(
        "crates/beacon/src/client.rs",
        886,
        Class::StringDispatch,
        false,
        "match attestations {",
        Verdict::InheritIntentionally,
        "phase-6",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        581,
        Class::StringDispatch,
        true,
        "match consensus_version {",
        Verdict::DecidedNotInherited,
        "phase-6",
    ),
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        520,
        Class::StringDispatch,
        true,
        "match consensus_version {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        534,
        Class::StringDispatch,
        true,
        "match consensus_version {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        627,
        Class::StringDispatch,
        false,
        "matches!(consensus_version",
        Verdict::TestOnly,
        "—",
    ),
    // Class 5
    inv(
        "crates/crypto/src/typed_signer.rs",
        58,
        Class::Entries,
        false,
        ".entries()",
        Verdict::MustBound,
        "2.6",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        177,
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        187,
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        196,
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        560,
        Class::Entries,
        false,
        "schedule.entries()",
        Verdict::TestOnly,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        576,
        Class::Entries,
        false,
        "schedule.entries()",
        Verdict::TestOnly,
        "2.1",
    ),
];

const SCANNER_REL: &str = "crates/architecture-tests/tests/fork_hazard_inventory.rs";
const AUDIT_DOC: &str = "docs/gloas-fork-hazard-audit.md";
const BEGIN_INVENTORY: &str = "<!-- BEGIN INVENTORY -->";
const END_INVENTORY: &str = "<!-- END INVENTORY -->";

const FORK_STRINGS: &[&str] = &[
    "\"phase0\"",
    "\"altair\"",
    "\"bellatrix\"",
    "\"capella\"",
    "\"deneb\"",
    "\"electra\"",
    "\"fulu\"",
    "\"gloas\"",
];

const SELF_FORK_VARIANTS: &[&str] =
    &["Phase0", "Altair", "Bellatrix", "Capella", "Deneb", "Electra", "Fulu", "Gloas"];

// ---------------------------------------------------------------------------
// Workspace walk
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn is_scanner_path(rel: &str) -> bool {
    rel.ends_with("architecture-tests/tests/fork_hazard_inventory.rs")
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

/// `crates/**` + `bin/**` `*.rs` (src + tests + benches + examples).
fn crates_and_bin_rs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        let dir = root.join(base);
        if dir.is_dir() {
            collect_rs(&dir, &mut out);
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

fn ident_boundary_before(src: &str, at: usize) -> bool {
    at == 0 || !is_ident_char(src.as_bytes()[at - 1])
}

fn ident_boundary_after(src: &str, after: usize) -> bool {
    after >= src.len() || !is_ident_char(src.as_bytes()[after])
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

/// True if `at` sits after a `//` comment marker on its line (outside strings).
fn in_line_comment(src: &str, at: usize) -> bool {
    let ls = line_start(src, at);
    let prefix = &src[ls..at.min(src.len())];
    let bytes = prefix.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        if !in_str && bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            return true;
        }
        if bytes[i] == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
        }
        i += 1;
    }
    false
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    let b = src.as_bytes();
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn skip_ws_comments(src: &str, mut i: usize) -> usize {
    let b = src.as_bytes();
    let n = b.len();
    loop {
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < n && b[i] == b'/' && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < n && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        return i;
    }
}

fn close_brace(src: &str, open: usize) -> Option<usize> {
    if open >= src.len() || src.as_bytes()[open] != b'{' {
        return None;
    }
    let b = src.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
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

fn close_paren(src: &str, open: usize) -> Option<usize> {
    if open >= src.len() || src.as_bytes()[open] != b'(' {
        return None;
    }
    let b = src.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
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

/// `{` that opens a `match` body, skipping parens so closures in the scrutinee
/// are not mistaken for the body.
fn match_body_span(src: &str, match_kw: usize) -> Option<(usize, usize)> {
    let mut i = skip_ws_comments(src, match_kw + "match".len());
    let b = src.as_bytes();
    let mut paren = 0i32;
    let mut brack = 0i32;
    while i < b.len() {
        i = skip_ws_comments(src, i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => brack += 1,
            b']' => brack -= 1,
            b'{' if paren == 0 && brack == 0 => {
                let close = close_brace(src, i)?;
                return Some((i, close));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn matches_macro_span(src: &str, at: usize) -> Option<(usize, usize)> {
    let i = skip_ws_comments(src, at + "matches!".len());
    let close = close_paren(src, i)?;
    Some((i, close))
}

fn has_bare_underscore_token(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' && ident_boundary_before(body, i) && ident_boundary_after(body, i + 1) {
            return true;
        }
        i += 1;
    }
    false
}

fn top_level_wildcard(body: &str) -> bool {
    let mut depth = 0i32;
    for line in body.lines() {
        let start_depth = depth;
        let t = line.trim_start();
        if start_depth == 1 && (t.starts_with("_ =>") || t.starts_with("_=>")) {
            return true;
        }
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }
    false
}

fn line_has_forkname_pattern(line: &str) -> bool {
    let Some(idx) = line.find("ForkName::") else {
        return false;
    };
    match line.find("=>") {
        Some(arrow) => idx < arrow,
        None => line[idx..].contains('|'),
    }
}

fn line_has_self_fork_pattern(line: &str) -> bool {
    for v in SELF_FORK_VARIANTS {
        let pat = format!("Self::{v}");
        let Some(idx) = line.find(&pat) else {
            continue;
        };
        let before_arrow = match line.find("=>") {
            Some(arrow) => idx < arrow,
            None => line[idx..].contains('|'),
        };
        if before_arrow {
            return true;
        }
    }
    false
}

fn body_is_forkname_match(path: &str, body: &str) -> bool {
    let mut forkname = false;
    let mut self_hits = 0usize;
    for line in body.lines() {
        if line_has_forkname_pattern(line) {
            forkname = true;
        }
        if path.ends_with("eth-types/src/fork.rs") && line_has_self_fork_pattern(line) {
            self_hits += 1;
        }
    }
    forkname || self_hits >= 2
}

fn body_has_fork_string(body: &str) -> bool {
    FORK_STRINGS.iter().any(|s| body.contains(s))
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    path: String,
    line: usize,
    class: Class,
    wildcard: bool,
    snippet: String,
}

fn push_hit(out: &mut Vec<Hit>, path: &str, src: &str, at: usize, class: Class, wildcard: bool) {
    let line = line_at(src, at);
    let ls = line_start(src, at);
    let le = line_end(src, at);
    out.push(Hit {
        path: path.to_string(),
        line,
        class,
        wildcard,
        snippet: src[ls..le].trim().to_string(),
    });
}

fn scan_ge_fork_name(path: &str, src: &str, out: &mut Vec<Hit>) {
    let mut from = 0;
    while let Some(rel) = src[from..].find(">=") {
        let at = from + rel;
        from = at + 2;
        if in_line_comment(src, at) {
            continue;
        }
        let rest = skip_ws(src, at + 2);
        if src[rest..].starts_with("ForkName::") {
            push_hit(out, path, src, at, Class::GeForkName, false);
        }
    }
}

fn scan_index_zero(path: &str, src: &str, out: &mut Vec<Hit>) {
    let mut from = 0;
    while let Some(rel) = src[from..].find(".index") {
        let at = from + rel;
        from = at + 6;
        if in_line_comment(src, at) {
            continue;
        }
        if !ident_boundary_after(src, at + 6) {
            continue;
        }
        let mut i = skip_ws(src, at + 6);
        if i >= src.len() || src.as_bytes()[i] != b'=' {
            continue;
        }
        i = skip_ws(src, i + 1);
        if i >= src.len() {
            continue;
        }
        let b = src.as_bytes();
        let is_int_zero = b[i] == b'0' && ident_boundary_after(src, i + 1);
        let is_str_zero = src[i..].starts_with("\"0\"");
        if is_int_zero || is_str_zero {
            push_hit(out, path, src, at, Class::IndexZero, false);
        }
    }
}

fn scan_entries(path: &str, src: &str, out: &mut Vec<Hit>) {
    let mut from = 0;
    while let Some(rel) = src[from..].find(".entries") {
        let at = from + rel;
        from = at + 8;
        if in_line_comment(src, at) {
            continue;
        }
        if !ident_boundary_after(src, at + 8) {
            continue;
        }
        let i = skip_ws(src, at + 8);
        if i < src.len() && src.as_bytes()[i] == b'(' {
            push_hit(out, path, src, at, Class::Entries, false);
        }
    }
}

fn scan_match_sites(path: &str, src: &str, out: &mut Vec<Hit>) {
    let mut from = 0;
    while let Some(rel) = src[from..].find("match") {
        let at = from + rel;
        from = at + 5;
        if !ident_boundary_before(src, at) || in_line_comment(src, at) {
            continue;
        }
        if src[at..].starts_with("matches!") {
            if let Some((open, close)) = matches_macro_span(src, at) {
                let body = &src[open..=close];
                if body_has_fork_string(body) {
                    let wildcard = has_bare_underscore_token(body);
                    push_hit(out, path, src, at, Class::StringDispatch, wildcard);
                }
            }
            continue;
        }
        if !ident_boundary_after(src, at + 5) {
            continue;
        }
        let Some((open, close)) = match_body_span(src, at) else {
            continue;
        };
        let body = &src[open..=close];
        let wildcard = top_level_wildcard(body);
        if body_is_forkname_match(path, body) {
            push_hit(out, path, src, at, Class::MatchForkName, wildcard);
        }
        if body_has_fork_string(body) {
            push_hit(out, path, src, at, Class::StringDispatch, wildcard);
        }
    }
}

/// All five classes in `src` attributed to workspace-relative `path`.
fn scan_source(path: &str, src: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    scan_ge_fork_name(path, src, &mut out);
    scan_index_zero(path, src, &mut out);
    scan_match_sites(path, src, &mut out);
    scan_entries(path, src, &mut out);
    out.sort_by(|a, b| (a.class, a.path.as_str(), a.line).cmp(&(b.class, b.path.as_str(), b.line)));
    out
}

struct WorkspaceScan {
    hits: Vec<Hit>,
    files: usize,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = crates_and_bin_rs(&root);
    let mut hits = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if is_scanner_path(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        hits.extend(scan_source(&rel, &src));
    }
    hits.sort_by(|a, b| {
        (a.class, a.path.as_str(), a.line).cmp(&(b.class, b.path.as_str(), b.line))
    });
    WorkspaceScan { hits, files: files.len() }
}

// ---------------------------------------------------------------------------
// Audit-doc parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct DocRow {
    path: String,
    line: usize,
    class: Class,
    wildcard: Option<bool>,
    verdict: Verdict,
    issue: String,
}

fn parse_site_cell(cell: &str) -> Option<(String, usize)> {
    let t = cell.trim();
    if !t.starts_with('`') {
        return None;
    }
    let rest = &t[1..];
    let end = rest.find('`')?;
    let path = rest[..end].to_string();
    let line = rest[end + 1..].trim().parse().ok()?;
    Some((path, line))
}

fn parse_kind_wildcard(kind: &str) -> Option<bool> {
    match kind.trim() {
        "_" | "wildcard" => Some(true),
        "exhaustive" => Some(false),
        "—" | "-" | "–" => None,
        _ => None,
    }
}

fn parse_inventory_table(doc: &str) -> Result<Vec<DocRow>, String> {
    let start = doc.find(BEGIN_INVENTORY).ok_or("missing BEGIN INVENTORY marker")?;
    let rest = &doc[start + BEGIN_INVENTORY.len()..];
    let end = rest.find(END_INVENTORY).ok_or("missing END INVENTORY marker")?;
    let table = &rest[..end];
    let mut rows = Vec::new();
    for raw in table.lines() {
        let line = raw.trim();
        if !line.starts_with('|') || line.contains("---") || line.contains("Site") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).filter(|c| !c.is_empty()).collect();
        if cells.len() < 6 {
            return Err(format!("inventory row needs 6 cells, got {}: {line}", cells.len()));
        }
        let (path, lineno) =
            parse_site_cell(cells[0]).ok_or_else(|| format!("bad Site cell: {}", cells[0]))?;
        let class_n: u8 = cells[1].parse().map_err(|_| format!("bad Class cell: {}", cells[1]))?;
        let class = Class::from_n(class_n).ok_or_else(|| format!("unknown class {class_n}"))?;
        let wildcard = parse_kind_wildcard(cells[2]);
        let verdict = Verdict::parse(cells[3])
            .ok_or_else(|| format!("unclassified or unknown verdict '{}'", cells[3]))?;
        let issue = cells[5].to_string();
        rows.push(DocRow { path, line: lineno, class, wildcard, verdict, issue });
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn fork_hazard_inventory_matches_workspace() {
    let scan = scan_workspace();
    assert!(
        scan.files > 100,
        "scanned only {} files under crates/ and bin/; workspace walk likely broke",
        scan.files
    );
    assert!(
        scan.hits.iter().all(|h| !is_scanner_path(&h.path)),
        "scanner source must be self-excluded"
    );

    let mut seen = HashSet::new();
    for row in INVENTORY {
        assert!(
            seen.insert((row.path, row.line, row.class)),
            "duplicate inventory entry {} :{} class {}",
            row.path,
            row.line,
            row.class.n()
        );
    }

    for (class, expected) in EXPECTED_COUNTS {
        let inv_n = INVENTORY.iter().filter(|r| r.class == class).count();
        let scan_n = scan.hits.iter().filter(|h| h.class == class).count();
        assert_eq!(
            inv_n,
            expected,
            "INVENTORY class {} ({}) count {inv_n} != pinned {expected}",
            class.n(),
            class.label()
        );
        assert_eq!(
            scan_n,
            expected,
            "scan class {} ({}) count {scan_n} != pinned {expected}",
            class.n(),
            class.label()
        );
    }
    assert_eq!(scan.hits.len(), INVENTORY.len(), "scan hit count != inventory len");

    let mut extra = Vec::new();
    let mut missing = Vec::new();
    let mut mismatch = Vec::new();

    let mut inv_by_key = std::collections::HashMap::new();
    for row in INVENTORY {
        inv_by_key.insert((row.path, row.line, row.class), row);
    }
    let mut hit_keys = HashSet::new();
    for hit in &scan.hits {
        let key = (hit.path.as_str(), hit.line, hit.class);
        hit_keys.insert((hit.path.clone(), hit.line, hit.class));
        match inv_by_key.get(&key) {
            None => extra.push(format!(
                "{}:{} class {} ({}) {:?}",
                hit.path,
                hit.line,
                hit.class.n(),
                hit.class.label(),
                hit.snippet
            )),
            Some(row) => {
                if !hit.snippet.contains(row.snippet) {
                    mismatch.push(format!(
                        "{}:{} class {}: line {:?} does not contain snippet {:?}",
                        hit.path,
                        hit.line,
                        hit.class.n(),
                        hit.snippet,
                        row.snippet
                    ));
                }
                if hit.wildcard != row.wildcard {
                    mismatch.push(format!(
                        "{}:{} class {}: wildcard scan={} inventory={}",
                        hit.path,
                        hit.line,
                        hit.class.n(),
                        hit.wildcard,
                        row.wildcard
                    ));
                }
            }
        }
    }
    for row in INVENTORY {
        if !hit_keys.contains(&(row.path.to_string(), row.line, row.class)) {
            missing.push(format!(
                "{}:{} class {} ({}) snippet {:?}",
                row.path,
                row.line,
                row.class.n(),
                row.class.label(),
                row.snippet
            ));
        }
    }

    assert!(
        extra.is_empty() && missing.is_empty() && mismatch.is_empty(),
        "fork-hazard inventory (issue 2.2): every scan hit under crates/** and bin/** must have a \
         classified row in INVENTORY and docs/gloas-fork-hazard-audit.md.\n\
         Extra (in scan, not inventory):\n  {}\n\
         Missing (in inventory, not scan):\n  {}\n\
         Mismatch:\n  {}",
        extra.join("\n  "),
        missing.join("\n  "),
        mismatch.join("\n  ")
    );
}

#[test]
fn audit_doc_lists_every_inventory_row() {
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join(AUDIT_DOC))
        .unwrap_or_else(|e| panic!("read {AUDIT_DOC}: {e}"));
    let rows = parse_inventory_table(&doc).unwrap_or_else(|e| panic!("parse {AUDIT_DOC}: {e}"));
    assert_eq!(rows.len(), INVENTORY.len(), "{AUDIT_DOC} row count != INVENTORY");

    let mut doc_keys = HashSet::new();
    for row in &rows {
        assert!(
            doc_keys.insert((row.path.clone(), row.line, row.class)),
            "duplicate doc row {} :{} class {}",
            row.path,
            row.line,
            row.class.n()
        );
        let inv = INVENTORY
            .iter()
            .find(|r| r.path == row.path && r.line == row.line && r.class == row.class);
        let Some(inv) = inv else {
            panic!(
                "{AUDIT_DOC} has unclassified/unknown site {} :{} class {}",
                row.path,
                row.line,
                row.class.n()
            );
        };
        assert_eq!(
            row.verdict,
            inv.verdict,
            "{}:{} class {} verdict doc={} inventory={}",
            row.path,
            row.line,
            row.class.n(),
            row.verdict.as_str(),
            inv.verdict.as_str()
        );
        assert_eq!(
            row.issue,
            inv.issue,
            "{}:{} class {} issue doc={} inventory={}",
            row.path,
            row.line,
            row.class.n(),
            row.issue,
            inv.issue
        );
        if let Some(wc) = row.wildcard {
            assert_eq!(
                wc,
                inv.wildcard,
                "{}:{} class {} kind wildcard doc={wc} inventory={}",
                row.path,
                row.line,
                row.class.n(),
                inv.wildcard
            );
        }
    }
    for inv in INVENTORY {
        assert!(
            doc_keys.contains(&(inv.path.to_string(), inv.line, inv.class)),
            "{AUDIT_DOC} missing {} :{} class {}",
            inv.path,
            inv.line,
            inv.class.n()
        );
    }
}

#[test]
fn inventory_is_sorted_and_counts_sum() {
    let mut prev: Option<(u8, &str, usize)> = None;
    for row in INVENTORY {
        let cur = (row.class.n(), row.path, row.line);
        if let Some(p) = prev {
            assert!(p < cur, "INVENTORY must stay sorted by (class, path, line)");
        }
        prev = Some(cur);
    }
    let sum: usize = EXPECTED_COUNTS.iter().map(|(_, n)| n).sum();
    assert_eq!(sum, INVENTORY.len());
}

// ---------------------------------------------------------------------------
// Matcher unit tests (synthetic RED / self-exclusion)
// ---------------------------------------------------------------------------

#[test]
fn new_ge_fork_name_site_is_detected_outside_inventory() {
    // AC: a new `>= ForkName::` site not on the inventory fails membership.
    let src = "fn f(fork: ForkName) {\n    if fork >= ForkName::Electra {\n        let _ = 1;\n    }\n}\n";
    let rel = "crates/rvc/src/orphan_fork_guard.rs";
    let hits = scan_source(rel, src);
    let ge: Vec<_> = hits.iter().filter(|h| h.class == Class::GeForkName).collect();
    assert_eq!(ge.len(), 1, "expected one class-1 hit, got {hits:?}");
    assert_eq!(ge[0].path, rel);
    assert!(ge[0].snippet.contains(">= ForkName::Electra"));
    assert!(
        !INVENTORY.iter().any(|r| r.path == rel),
        "fixture path must not be on the inventory — that is the RED"
    );
    let on_inventory = INVENTORY
        .iter()
        .any(|r| r.path == ge[0].path && r.line == ge[0].line && r.class == Class::GeForkName);
    assert!(!on_inventory, "new >= ForkName:: site must not match any inventory row");
}

#[test]
fn scanner_path_is_self_excluded() {
    assert!(is_scanner_path(SCANNER_REL));
    assert!(is_scanner_path("foo/architecture-tests/tests/fork_hazard_inventory.rs"));
    assert!(!is_scanner_path("crates/architecture-tests/tests/kat_policy.rs"));

    let root = workspace_root();
    let src = std::fs::read_to_string(root.join(SCANNER_REL)).expect("read scanner");
    assert!(
        src.contains(">= ForkName::"),
        "inventory literals must contain the class-1 needle (that is why we self-exclude)"
    );
    let unfiltered = scan_source(SCANNER_REL, &src);
    assert!(
        unfiltered.iter().any(|h| h.class == Class::GeForkName),
        "unfiltered scan of the scanner must see its own >= ForkName:: literals; got {unfiltered:?}"
    );

    let walk = scan_workspace();
    assert!(
        walk.hits.iter().all(|h| h.path != SCANNER_REL),
        "workspace walk must skip {SCANNER_REL}"
    );
}

#[test]
fn class_matchers_on_synthetic_snippets() {
    let ge = scan_source("t.rs", "let x = fork >= ForkName::Fulu;\n");
    assert_eq!(ge.iter().filter(|h| h.class == Class::GeForkName).count(), 1);

    let idx = scan_source("t.rs", "data.index = 0;\nsingle.index = \"0\".to_string();\n");
    assert_eq!(idx.iter().filter(|h| h.class == Class::IndexZero).count(), 2);

    let ent = scan_source("t.rs", "schedule.entries().into_iter();\n");
    assert_eq!(ent.iter().filter(|h| h.class == Class::Entries).count(), 1);

    let exhaustive = scan_source(
        "bin/rvc/tests/common/mock_bn.rs",
        "fn f(fork: ForkName) {\n    match fork {\n        ForkName::Phase0 => 0,\n        ForkName::Fulu => 6,\n    }\n}\n",
    );
    let m: Vec<_> = exhaustive.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert!(!m[0].wildcard, "no _ => arm is exhaustive");

    let wild = scan_source(
        "bin/rvc/tests/common/mock_bn.rs",
        "fn f(fork: ForkName) {\n    match fork {\n        ForkName::Fulu => 6,\n        _ => 0,\n    }\n}\n",
    );
    let m: Vec<_> = wild.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert!(m[0].wildcard, "_ => arm is wildcard");

    let ssz = scan_source(
        "crates/block-service/src/service/mod.rs",
        "match consensus_version {\n    \"deneb\" | \"electra\" | \"fulu\" => A,\n    _ => B,\n}\n",
    );
    let s: Vec<_> = ssz.iter().filter(|h| h.class == Class::StringDispatch).collect();
    assert_eq!(s.len(), 1);
    assert!(s[0].wildcard);

    let matches_macro = scan_source(
        "t.rs",
        "let x = matches!(consensus_version, \"deneb\" | \"electra\" | \"fulu\");\n",
    );
    assert_eq!(matches_macro.iter().filter(|h| h.class == Class::StringDispatch).count(), 1);

    // Comments are not hits.
    let commented = scan_source("t.rs", "// if fork >= ForkName::Electra { }\n");
    assert!(commented.iter().all(|h| h.class != Class::GeForkName));
}

#[test]
fn self_fork_match_in_fork_rs_is_class_three() {
    let src = r#"
    pub fn id(self) -> u32 {
        match self {
            Self::Phase0 => 0,
            Self::Altair => 1,
            Self::Fulu => 6,
        }
    }
"#;
    let hits = scan_source("crates/eth-types/src/fork.rs", src);
    let m: Vec<_> = hits.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert!(!m[0].wildcard);
}

#[test]
fn comment_mentions_of_entries_are_ignored() {
    let src = "/// Resolve from `schedule.entries()`.\nfn f() {}\n";
    let hits = scan_source("crates/eth-types/src/fork.rs", src);
    assert!(hits.iter().all(|h| h.class != Class::Entries));
}
