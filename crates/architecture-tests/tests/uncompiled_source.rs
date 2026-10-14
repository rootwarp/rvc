//! ARCH-2b / G-1 detector **D2**: no uncompiled `.rs` under a member crate's `src/`.
//!
//! D1 (orphan *directories*) only sees crates missing from `cargo metadata`. D2 catches
//! orphans *inside* a member — historically `crates/rvc/src/main.rs` and
//! `crates/rvc/src/commands/` under `autobins = false` with no `mod` edge from `lib.rs`.
//!
//! Algorithm (per workspace member):
//! 1. **Compilation roots** from `cargo metadata` targets whose `src_path` lies under the
//!    package's `src/` (covers `lib.rs`, `main.rs` when autobins/explicit bin apply,
//!    `src/bin/*.rs`, and any `[[bin]]`/`[[example]]`/`[[bench]]`/`[[test]]` path in `src/`).
//! 2. Transitive walk of `mod <name>;` / `mod <name> { … }` from each root, resolving
//!    `<name>.rs` and `<name>/mod.rs`, and **`#[path = "…"]`** (A-E4). `cfg` predicates are
//!    ignored: a declared module counts as reachable whether or not the cfg is active.
//! 3. Orphans = all `.rs` under `src/` minus the reachable set (minus `orphan_exempt` files).
//!
//! **Escape hatch (shrinking-only):** a file whose first non-empty line is
//! `// orphan_exempt: <reason>` is skipped. Prefer declaring the module (or deleting the
//! file) over growing exemptions. After ARCH-1b the expected exemption count is **zero**.
//!
//! Cross-ref: plan `architecture-2026-08-12` issue ARCH-2b / ARCH-P0-2 / ADR-012; A-E4/A-E5.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled module-graph walk, same style as
//! `kat_policy.rs` / `docs_freshness.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use rvc_architecture_tests::{load_cargo_metadata, workspace_root};

// ---------------------------------------------------------------------------
// Non-vacuity + exemption policy
// ---------------------------------------------------------------------------

/// Walker must visit a non-trivial file count so a silent empty walk cannot go green.
///
/// Plan/issue text used `>= 300`; member `src/` currently holds 299 `.rs` files (all
/// reachable after ARCH-1b), so the floor is set just under that inventory.
const MIN_VISITED_RS: usize = 290;

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

fn collect_rs_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// First non-empty line is `// orphan_exempt: <reason>` (shrinking-only escape hatch).
fn is_orphan_exempt(source: &str) -> bool {
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return trimmed.starts_with("// orphan_exempt:");
    }
    false
}

// ---------------------------------------------------------------------------
// Module-graph resolution
// ---------------------------------------------------------------------------

/// Directory used to resolve `mod name;` → `name.rs` / `name/mod.rs` for a physical file.
///
/// Matches rustc: `lib.rs` / `main.rs` / `mod.rs` resolve children in their parent directory;
/// a file module `foo.rs` resolves children under `foo/`.
fn module_dir_for_file(file: &Path) -> PathBuf {
    let name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
    match name {
        "lib.rs" | "main.rs" | "mod.rs" => file.parent().unwrap_or(file).to_path_buf(),
        _ => {
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");
            file.parent().unwrap_or(file).join(stem)
        }
    }
}

/// Resolve an external `mod name` (optional `#[path]`) relative to the declaring file.
fn resolve_external_mod(
    declaring_file: &Path,
    module_dir: &Path,
    name: &str,
    path_attr: Option<&str>,
    files: &HashMap<PathBuf, String>,
) -> Option<PathBuf> {
    if let Some(p) = path_attr {
        let candidate = declaring_file.parent()?.join(p);
        let key = normalize_key(&candidate, files)?;
        return Some(key);
    }
    let as_file = module_dir.join(format!("{name}.rs"));
    if let Some(key) = normalize_key(&as_file, files) {
        return Some(key);
    }
    let as_mod_rs = module_dir.join(name).join("mod.rs");
    normalize_key(&as_mod_rs, files)
}

/// Map a candidate path onto a key present in `files` (exact, then by `canonicalize`-less
/// string equality of the path components we already built from the same root).
fn normalize_key(candidate: &Path, files: &HashMap<PathBuf, String>) -> Option<PathBuf> {
    if files.contains_key(candidate) {
        return Some(candidate.to_path_buf());
    }
    // Fall back: compare via Path components string form (handles non-canonical joins).
    let cand = candidate.to_string_lossy().replace('\\', "/");
    for k in files.keys() {
        if k.to_string_lossy().replace('\\', "/") == cand {
            return Some(k.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Source scanner (mod declarations + #[path], ignore cfg)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ModDecl<'a> {
    /// `mod name;` — may carry `#[path = "…"]`.
    External { name: &'a str, path_attr: Option<&'a str> },
    /// `mod name { body }` — children resolve under `module_dir/name/`.
    Inline { name: &'a str, body: &'a str },
}

/// Scan one source unit for `mod` declarations. Attributes immediately preceding `mod`
/// are collected; only `path = "…"` affects resolution. Other attrs (including `cfg`) are
/// ignored so cfg-gated modules still count as declared.
fn scan_mod_decls(source: &str) -> Vec<ModDecl<'_>> {
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut out = Vec::new();

    while i < n {
        skip_ws_and_comments(bytes, &mut i);
        if i >= n {
            break;
        }

        if bytes[i] == b'#' && i + 1 < n && bytes[i + 1] == b'[' {
            let save = i;
            let path_attr = parse_attr_block_path(source, bytes, &mut i);
            if try_parse_mod(source, bytes, &mut i, path_attr, &mut out) {
                continue;
            }
            if i == save {
                i += 1;
            }
            continue;
        }

        if try_parse_mod(source, bytes, &mut i, None, &mut out) {
            continue;
        }

        let j = skip_string_or_char(bytes, i);
        if j != i {
            i = j;
            continue;
        }
        i += 1;
    }

    out
}

fn try_parse_mod<'a>(
    source: &'a str,
    bytes: &[u8],
    i: &mut usize,
    path_attr: Option<&'a str>,
    out: &mut Vec<ModDecl<'a>>,
) -> bool {
    let save = *i;
    skip_visibility(bytes, i);
    skip_ws_and_comments(bytes, i);
    if !match_keyword(bytes, i, b"mod") {
        *i = save;
        return false;
    }
    let Some(name) = parse_ident(source, bytes, i) else {
        *i = save;
        return false;
    };
    skip_ws_and_comments(bytes, i);
    if *i < bytes.len() && bytes[*i] == b';' {
        *i += 1;
        out.push(ModDecl::External { name, path_attr });
        return true;
    }
    if *i < bytes.len() && bytes[*i] == b'{' {
        let body = extract_brace_body(source, bytes, i);
        out.push(ModDecl::Inline { name, body });
        return true;
    }
    *i = save;
    false
}

fn skip_ws_and_comments(bytes: &[u8], i: &mut usize) {
    let n = bytes.len();
    while *i < n {
        match bytes[*i] {
            b' ' | b'\t' | b'\r' | b'\n' => *i += 1,
            b'/' if *i + 1 < n && bytes[*i + 1] == b'/' => {
                *i += 2;
                while *i < n && bytes[*i] != b'\n' {
                    *i += 1;
                }
            }
            b'/' if *i + 1 < n && bytes[*i + 1] == b'*' => {
                *i += 2;
                while *i + 1 < n && !(bytes[*i] == b'*' && bytes[*i + 1] == b'/') {
                    *i += 1;
                }
                *i = (*i + 2).min(n);
            }
            _ => break,
        }
    }
}

fn skip_visibility(bytes: &[u8], i: &mut usize) {
    skip_ws_and_comments(bytes, i);
    if !match_keyword(bytes, i, b"pub") {
        return;
    }
    skip_ws_and_comments(bytes, i);
    if *i < bytes.len() && bytes[*i] == b'(' {
        let mut depth = 1usize;
        *i += 1;
        while *i < bytes.len() && depth > 0 {
            match bytes[*i] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            *i += 1;
        }
    }
}

fn match_keyword(bytes: &[u8], i: &mut usize, kw: &[u8]) -> bool {
    let n = kw.len();
    if *i + n > bytes.len() {
        return false;
    }
    if &bytes[*i..*i + n] != kw {
        return false;
    }
    let after = *i + n;
    if after < bytes.len() && (bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_') {
        return false;
    }
    *i = after;
    true
}

fn parse_ident<'a>(source: &'a str, bytes: &[u8], i: &mut usize) -> Option<&'a str> {
    skip_ws_and_comments(bytes, i);
    if *i >= bytes.len() {
        return None;
    }
    let b = bytes[*i];
    if !(b.is_ascii_alphabetic() || b == b'_') {
        return None;
    }
    let start = *i;
    *i += 1;
    while *i < bytes.len() && (bytes[*i].is_ascii_alphanumeric() || bytes[*i] == b'_') {
        *i += 1;
    }
    Some(&source[start..*i])
}

/// Parse one or more `#[…]` attributes; return the last `path = "…"` value if any.
fn parse_attr_block_path<'a>(source: &'a str, bytes: &[u8], i: &mut usize) -> Option<&'a str> {
    let mut path_attr = None;
    loop {
        skip_ws_and_comments(bytes, i);
        if *i + 1 >= bytes.len() || bytes[*i] != b'#' || bytes[*i + 1] != b'[' {
            break;
        }
        *i += 2;
        let body_start = *i;
        let mut depth = 1usize;
        while *i < bytes.len() && depth > 0 {
            let j = skip_string_or_char(bytes, *i);
            if j != *i {
                *i = j;
                continue;
            }
            match bytes[*i] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            *i += 1;
        }
        let body_end = i.saturating_sub(1);
        if body_end >= body_start {
            if let Some(p) = extract_path_attr(&source[body_start..body_end]) {
                path_attr = Some(p);
            }
        }
    }
    path_attr
}

fn extract_path_attr(attr_body: &str) -> Option<&str> {
    // path = "…"  (whitespace-tolerant; only form used in this workspace)
    let bytes = attr_body.as_bytes();
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if &bytes[i..i + 4] == b"path" {
            let after = i + 4;
            if after < bytes.len() && (bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_')
            {
                i += 1;
                continue;
            }
            let mut j = after;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    j += 1;
                    let start = j;
                    while j < bytes.len() && bytes[j] != b'"' {
                        j += 1;
                    }
                    if j < bytes.len() {
                        return Some(&attr_body[start..j]);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn extract_brace_body<'a>(source: &'a str, bytes: &[u8], i: &mut usize) -> &'a str {
    debug_assert_eq!(bytes[*i], b'{');
    *i += 1;
    let start = *i;
    let mut depth = 1usize;
    while *i < bytes.len() && depth > 0 {
        let j = skip_string_or_char(bytes, *i);
        if j != *i {
            *i = j;
            continue;
        }
        if bytes[*i] == b'/' && *i + 1 < bytes.len() && bytes[*i + 1] == b'/' {
            *i += 2;
            while *i < bytes.len() && bytes[*i] != b'\n' {
                *i += 1;
            }
            continue;
        }
        if bytes[*i] == b'/' && *i + 1 < bytes.len() && bytes[*i + 1] == b'*' {
            *i += 2;
            while *i + 1 < bytes.len() && !(bytes[*i] == b'*' && bytes[*i + 1] == b'/') {
                *i += 1;
            }
            *i = (*i + 2).min(bytes.len());
            continue;
        }
        match bytes[*i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        *i += 1;
    }
    let end = i.saturating_sub(1);
    if end >= start {
        &source[start..end]
    } else {
        ""
    }
}

/// Skip a double-quoted / raw / byte string, or a one-character char literal.
///
/// **Does not** treat `'ident` lifetimes as strings (that bug swallowed trailing `mod`
/// declarations after `'static` in real sources).
fn skip_string_or_char(bytes: &[u8], i: usize) -> usize {
    let n = bytes.len();
    if i >= n {
        return i;
    }

    // Char literal `'x'` / `'\n'` — not lifetime `'static`.
    if bytes[i] == b'\'' {
        if i + 1 < n && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_') {
            let mut j = i + 1;
            while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            // Single-letter char literal `'x'` (ident of length 1 closed by `'`).
            if j == i + 2 && j < n && bytes[j] == b'\'' {
                return j + 1;
            }
            // Lifetime — leave `'` for the main scanner to step over.
            return i;
        }
        let mut j = i + 1;
        if j < n && bytes[j] == b'\\' {
            j += 1;
            if j < n {
                j += 1;
            }
            if j < n && bytes[j] == b'\'' {
                return j + 1;
            }
            return i;
        }
        if j < n {
            j += 1;
        }
        if j < n && bytes[j] == b'\'' {
            return j + 1;
        }
        return i;
    }

    let mut j = i;
    if j < n && bytes[j] == b'b' {
        j += 1;
    }
    let raw = j < n && bytes[j] == b'r';
    if raw {
        j += 1;
        let mut hashes = 0usize;
        while j < n && bytes[j] == b'#' {
            hashes += 1;
            j += 1;
        }
        if j >= n || bytes[j] != b'"' {
            return i;
        }
        j += 1;
        // end delimiter: " followed by `hashes` times #
        'scan: while j < n {
            if bytes[j] == b'"' {
                let mut k = 0usize;
                while k < hashes && j + 1 + k < n && bytes[j + 1 + k] == b'#' {
                    k += 1;
                }
                if k == hashes {
                    return j + 1 + hashes;
                }
            }
            j += 1;
            if j >= n {
                break 'scan;
            }
        }
        return n;
    }

    if j < n && bytes[j] == b'"' {
        j += 1;
        while j < n {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == b'"' {
                return j + 1;
            }
            j += 1;
        }
        return n;
    }

    i
}

// ---------------------------------------------------------------------------
// Reachability walk
// ---------------------------------------------------------------------------

/// Files reachable from `roots` by following `mod` edges through `files`.
///
/// `files` is the virtual filesystem (path → source). Paths not present are unresolved
/// and skipped (rustc would error; D2 only cares about on-disk orphans under `src/`).
fn reachable_from_roots(roots: &[PathBuf], files: &HashMap<PathBuf, String>) -> HashSet<PathBuf> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    for root in roots {
        if files.contains_key(root) && visited.insert(root.clone()) {
            queue.push_back(root.clone());
        }
    }

    while let Some(file) = queue.pop_front() {
        let Some(source) = files.get(&file) else {
            continue;
        };
        let module_dir = module_dir_for_file(&file);
        walk_unit(source, &file, &module_dir, files, &mut visited, &mut queue);
    }

    visited
}

fn walk_unit(
    source: &str,
    file: &Path,
    module_dir: &Path,
    files: &HashMap<PathBuf, String>,
    visited: &mut HashSet<PathBuf>,
    queue: &mut VecDeque<PathBuf>,
) {
    for decl in scan_mod_decls(source) {
        match decl {
            ModDecl::External { name, path_attr } => {
                let Some(child) = resolve_external_mod(file, module_dir, name, path_attr, files)
                else {
                    continue;
                };
                if visited.insert(child.clone()) {
                    queue.push_back(child);
                }
            }
            ModDecl::Inline { name, body } => {
                let child_dir = module_dir.join(name);
                walk_unit(body, file, &child_dir, files, visited, queue);
            }
        }
    }
}

/// Orphans = `all_src_rs − reachable − orphan_exempt`.
///
/// Returns `(visited, orphans, exemptions)` with paths as given in `all_src_rs` / `files`.
fn orphan_report(
    roots: &[PathBuf],
    all_src_rs: &[PathBuf],
    files: &HashMap<PathBuf, String>,
) -> (HashSet<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
    let visited = reachable_from_roots(roots, files);
    let mut orphans = Vec::new();
    let mut exemptions = Vec::new();
    for path in all_src_rs {
        if visited.contains(path) {
            continue;
        }
        let source = files.get(path).map(String::as_str).unwrap_or("");
        if is_orphan_exempt(source) {
            exemptions.push(path.clone());
        } else {
            orphans.push(path.clone());
        }
    }
    orphans.sort();
    exemptions.sort();
    (visited, orphans, exemptions)
}

// ---------------------------------------------------------------------------
// Workspace scan (cargo metadata members)
// ---------------------------------------------------------------------------

struct MemberOrphans {
    package: String,
    orphans: Vec<PathBuf>,
    exemptions: Vec<PathBuf>,
    total_src_rs: usize,
}

fn scan_workspace() -> (Vec<MemberOrphans>, usize, PathBuf) {
    let root = workspace_root();
    let metadata = load_cargo_metadata();
    let packages = metadata["packages"].as_array().expect("metadata packages must be an array");

    let mut members = Vec::new();
    let mut total_visited = 0usize;

    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or("<unknown>").to_string();
        let manifest =
            pkg["manifest_path"].as_str().expect("package manifest_path must be a string");
        let pkg_dir = Path::new(manifest).parent().expect("manifest_path has a parent");
        let src_dir = pkg_dir.join("src");
        if !src_dir.is_dir() {
            continue;
        }

        let mut all_src_rs = Vec::new();
        collect_rs_under(&src_dir, &mut all_src_rs);
        all_src_rs.sort();

        let mut files: HashMap<PathBuf, String> = HashMap::new();
        for path in &all_src_rs {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            files.insert(path.clone(), text);
        }

        let mut roots = Vec::new();
        let targets = pkg["targets"].as_array().expect("package targets must be an array");
        for target in targets {
            let src_path = target["src_path"].as_str().expect("target src_path must be a string");
            let sp = PathBuf::from(src_path);
            if is_under(&sp, &src_dir) && files.contains_key(&sp) {
                roots.push(sp);
            } else if is_under(&sp, &src_dir) {
                // Target path may differ by symlink/canonical form — match via string.
                let sp_norm = sp.to_string_lossy().replace('\\', "/");
                if let Some(k) =
                    files.keys().find(|k| k.to_string_lossy().replace('\\', "/") == sp_norm)
                {
                    roots.push(k.clone());
                }
            }
        }

        let (visited, orphans, exemptions) = orphan_report(&roots, &all_src_rs, &files);
        total_visited += visited.len();
        members.push(MemberOrphans {
            package: name,
            orphans,
            exemptions,
            total_src_rs: all_src_rs.len(),
        });
    }

    (members, total_visited, root)
}

fn is_under(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir)
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// GREEN on develop after ARCH-1b: zero orphans, zero exemptions, non-vacuous walk.
#[test]
fn test_no_uncompiled_source_under_member_src() {
    let (members, total_visited, root) = scan_workspace();

    let mut orphan_lines = Vec::new();
    let mut exemption_lines = Vec::new();
    let mut total_src = 0usize;
    for m in &members {
        total_src += m.total_src_rs;
        for p in &m.orphans {
            orphan_lines.push(format!("{} ({})", rel_display(&root, p), m.package));
        }
        for p in &m.exemptions {
            exemption_lines.push(format!("{} ({})", rel_display(&root, p), m.package));
        }
    }

    assert!(
        orphan_lines.is_empty(),
        "D2 uncompiled-source gate (ARCH-2b / G-1): every `.rs` under a member's `src/` must be \
         reachable from a compilation root via `mod` (or `#[path]`).\n\
         Fix: declare the module, delete the file, or (shrinking-only) add \
         `// orphan_exempt: <reason>` on the first non-empty line.\n\
         Orphans:\n  {}",
        orphan_lines.join("\n  ")
    );

    assert!(
        exemption_lines.is_empty(),
        "D2 orphan_exempt inventory must be empty after ARCH-1b (shrinking-only).\n\
         Remaining exemptions:\n  {}",
        exemption_lines.join("\n  ")
    );

    assert!(
        total_visited >= MIN_VISITED_RS,
        "D2 non-vacuity: visited only {total_visited} `.rs` files across members \
         (need >= {MIN_VISITED_RS}); walker likely broke. total_src={total_src}"
    );
}

/// Permanent RED probe: an undeclared `ghost.rs` next to a root is reported by name.
#[test]
fn test_d2_rejects_a_module_no_root_declares() {
    let lib = PathBuf::from("/synth/src/lib.rs");
    let real = PathBuf::from("/synth/src/real.rs");
    let ghost = PathBuf::from("/synth/src/ghost.rs");

    let mut files = HashMap::new();
    files.insert(lib.clone(), "mod real;\n".to_string());
    files.insert(real.clone(), "// real module\n".to_string());
    files.insert(ghost.clone(), "// never declared\n".to_string());

    let all = vec![lib.clone(), real.clone(), ghost.clone()];
    let roots = vec![lib];
    let (visited, orphans, exemptions) = orphan_report(&roots, &all, &files);

    assert!(visited.contains(&real), "declared real.rs must be reachable");
    assert!(!visited.contains(&ghost), "undeclared ghost.rs must not be reachable");
    assert!(
        orphans.iter().any(|p| p.ends_with("ghost.rs")),
        "orphan report must name ghost.rs; got {orphans:?}"
    );
    assert!(exemptions.is_empty(), "no exemptions in synthetic tree");
}

/// Pins A-E4: the workspace's only `#[path]` site must keep `client_tests.rs` reachable.
#[test]
fn test_d2_resolves_path_attribute_modules() {
    let root = workspace_root();
    let client_tests = root.join("crates/remote-signer-client/src/client_tests.rs");
    assert!(client_tests.is_file(), "expected {} on disk", client_tests.display());

    // Build the client package graph only — cheaper and sufficient for the path pin.
    let metadata = load_cargo_metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let crypto = packages
        .iter()
        .find(|p| p["name"].as_str() == Some("rvc-remote-signer-client"))
        .expect("rvc-remote-signer-client package in workspace");

    let manifest = Path::new(crypto["manifest_path"].as_str().unwrap());
    let src_dir = manifest.parent().unwrap().join("src");
    let mut all_src_rs = Vec::new();
    collect_rs_under(&src_dir, &mut all_src_rs);

    let mut files = HashMap::new();
    for path in &all_src_rs {
        files.insert(
            path.clone(),
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
        );
    }

    let mut roots = Vec::new();
    for target in crypto["targets"].as_array().unwrap() {
        let sp = PathBuf::from(target["src_path"].as_str().unwrap());
        if is_under(&sp, &src_dir) {
            if files.contains_key(&sp) {
                roots.push(sp);
            } else if let Some(k) = files.keys().find(|k| {
                k.to_string_lossy().replace('\\', "/") == sp.to_string_lossy().replace('\\', "/")
            }) {
                roots.push(k.clone());
            }
        }
    }

    let visited = reachable_from_roots(&roots, &files);
    let key = files
        .keys()
        .find(|k| k.to_string_lossy().replace('\\', "/").ends_with("client_tests.rs"))
        .cloned()
        .expect("client_tests.rs must be under remote-signer-client src/");

    assert!(
        visited.contains(&key),
        "D2 must resolve #[path = \"client_tests.rs\"] on \
         crates/remote-signer-client/src/client.rs so client_tests.rs is reachable; \
         without path handling this is the workspace's only false positive (A-E4)"
    );
}

// ---------------------------------------------------------------------------
// Scanner unit probes
// ---------------------------------------------------------------------------

#[test]
fn scanner_finds_path_attribute_mod() {
    let src = r#"
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "client_tests.rs"]
mod tests;
"#;
    let decls = scan_mod_decls(src);
    assert_eq!(decls.len(), 1);
    match &decls[0] {
        ModDecl::External { name: "tests", path_attr: Some("client_tests.rs") } => {}
        other => panic!("expected path-attr external mod, got {other:?}"),
    }
}

#[test]
fn scanner_ignores_lifetime_ticks() {
    // Regression: treating `'static` as a string swallowed trailing `mod` lines.
    let src = r#"
fn foo() -> &'static str {
    "hello"
}
mod auth;
mod errors;
"#;
    let decls = scan_mod_decls(src);
    let names: Vec<&str> = decls
        .iter()
        .filter_map(|d| match d {
            ModDecl::External { name, .. } => Some(*name),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec!["auth", "errors"]);
}

#[test]
fn orphan_exempt_marker_on_first_non_empty_line() {
    assert!(is_orphan_exempt("// orphan_exempt: legacy fixture\nfn x() {}\n"));
    assert!(is_orphan_exempt("\n\n// orphan_exempt: reason\n"));
    assert!(!is_orphan_exempt("// just a comment\nfn x() {}\n"));
    assert!(!is_orphan_exempt("fn x() {}\n// orphan_exempt: too late\n"));
}
