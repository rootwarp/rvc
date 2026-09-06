//! ADR-005: `gen_spec_kat` reads vector files only (issue 3.6 / D28).
//!
//! Hand-rolled scan (no extra crate; `no_rvc_prefix.rs` idiom). Scratch
//! violations live in `#[test]` strings, not in `src/bin/gen_spec_kat.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Crate-name segment of `use` / `extern crate` / path-form `crate::` — not a substring.
const FORBIDDEN_CRATES: &[&str] = &[
    "eth_types",
    "rvc_gloas",
    "tree_hash",
    "tree_hash_derive",
    "ssz",
    "ssz08",
    "libssz",
    "libssz_merkle",
    "libssz_types",
    "libssz_derive",
    "ethereum_ssz",
];

const ORACLE_FNS: &[&str] = &["compute_domain", "compute_fork_data_root", "compute_signing_root"];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_dir().parent().unwrap().parent().unwrap().to_path_buf()
}

fn generator_path() -> PathBuf {
    crate_dir().join("src/bin/gen_spec_kat.rs")
}

fn spec_kat_path() -> PathBuf {
    crate_dir().join("src/spec_kat.rs")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn bin_rs_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&crate_dir().join("src/bin"), &mut out);
    out.sort();
    out
}

fn read_bin_sources() -> Vec<(PathBuf, String)> {
    let files = bin_rs_files();
    let gen = generator_path();
    assert!(
        files.iter().any(|p| p == &gen),
        "src/bin/gen_spec_kat.rs is missing; ADR-005 scan would be vacuous ({})",
        gen.display()
    );
    files
        .into_iter()
        .map(|path| {
            let src = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            (path, src)
        })
        .collect()
}

fn strip_comments(src: &str) -> String {
    src.lines().map(strip_line_comment).collect::<Vec<_>>().join("\n")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn ident_boundary(src: &str, at: usize, len: usize) -> bool {
    let before_ok = at == 0 || !src[..at].chars().next_back().is_some_and(is_ident_char);
    let after = at + len;
    let after_ok = after >= src.len() || !src[after..].chars().next().is_some_and(is_ident_char);
    before_ok && after_ok
}

fn take_ident(s: &str) -> Option<&str> {
    let s = s.trim_start();
    let mut chars = s.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    let end = chars.find(|(_, c)| !is_ident_char(*c)).map(|(i, _)| i).unwrap_or(s.len());
    Some(&s[..end])
}

fn has_ident(s: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = s[from..].find(name) {
        let at = from + rel;
        if ident_boundary(s, at, name.len()) {
            return true;
        }
        from = at + name.len();
    }
    false
}

/// Code portion of a line with a trailing `//` comment removed (string-aware).
fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => {
                i += 2;
                continue;
            }
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn strip_leading_attrs(s: &str) -> &str {
    let mut s = s.trim_start();
    while s.starts_with("#[") {
        match s.find(']') {
            Some(end) => s = s[end + 1..].trim_start(),
            None => break,
        }
    }
    s
}

fn strip_visibility(s: &str) -> &str {
    let s = s.trim_start();
    if !s.starts_with("pub") {
        return s;
    }
    let after_pub = &s[3..];
    if after_pub.starts_with(is_ident_char) {
        return s;
    }
    let rest = after_pub.trim_start();
    if rest.starts_with('(') {
        if let Some(end) = rest.find(')') {
            return rest[end + 1..].trim_start();
        }
    }
    rest
}

fn keyword_rest<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(keyword)?;
    if rest.starts_with(is_ident_char) {
        return None;
    }
    Some(rest)
}

fn use_item_rest(line: &str) -> Option<&str> {
    let s = strip_visibility(strip_leading_attrs(strip_line_comment(line)).trim());
    keyword_rest(s, "use")
}

fn extern_crate_name(line: &str) -> Option<&str> {
    let s = strip_visibility(strip_leading_attrs(strip_line_comment(line)).trim());
    let rest = keyword_rest(s, "extern")?.trim_start();
    let rest = keyword_rest(rest, "crate")?.trim_start();
    take_ident(rest)
}

fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                items.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&s[start..]);
    items
}

/// Crate-name segment(s) of a use-tree (not modules under a named crate).
fn use_tree_crate_names(s: &str) -> Vec<&str> {
    let s = s.trim().trim_start_matches("::").trim();
    if s.starts_with('{') {
        let inner = s.trim_start_matches('{').trim_end_matches(['}', ';', ',']);
        return split_top_level_commas(inner).into_iter().flat_map(use_tree_crate_names).collect();
    }
    take_ident(s).into_iter().collect()
}

fn is_crate_group(rest: &str) -> bool {
    rest.trim_start().trim_start_matches("::").trim_start().starts_with('{')
}

fn push_forbidden_crates(hits: &mut Vec<String>, names: &[&str]) {
    for name in names {
        if FORBIDDEN_CRATES.contains(name) && !hits.iter().any(|h| h == name) {
            hits.push((*name).to_owned());
        }
    }
}

fn forbidden_import_crates(src: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut brace_depth = 0i32;
    let mut in_crate_group = false;
    for raw in src.lines() {
        let line = strip_line_comment(raw).trim();
        if brace_depth > 0 {
            brace_depth += line.chars().filter(|&c| c == '{').count() as i32;
            brace_depth -= line.chars().filter(|&c| c == '}').count() as i32;
            if in_crate_group {
                push_forbidden_crates(&mut hits, &use_tree_crate_names(line));
            }
            if brace_depth <= 0 {
                brace_depth = 0;
                in_crate_group = false;
            }
            continue;
        }
        if let Some(rest) = use_item_rest(line) {
            push_forbidden_crates(&mut hits, &use_tree_crate_names(rest));
            let opens = rest.chars().filter(|&c| c == '{').count() as i32;
            let closes = rest.chars().filter(|&c| c == '}').count() as i32;
            brace_depth = opens - closes;
            in_crate_group = brace_depth > 0 && is_crate_group(rest);
        } else if let Some(name) = extern_crate_name(line) {
            push_forbidden_crates(&mut hits, &[name]);
        }
    }
    hits
}

/// `name::` is a crate root (`ssz::Decode`, `::libssz_merkle::…`), not `foo::ssz::`.
fn is_crate_root_path(src: &str, at: usize) -> bool {
    if at == 0 {
        return true;
    }
    match src[..at].chars().next_back() {
        None => true,
        Some(':') => {
            let rest = src[..at].trim_end_matches(':').trim_end();
            rest.is_empty() || !rest.chars().next_back().is_some_and(is_ident_char)
        }
        Some(c) if is_ident_char(c) => false,
        _ => true,
    }
}

fn forbidden_path_crates(src: &str) -> Vec<String> {
    let stripped = strip_comments(src);
    let mut hits = Vec::new();
    for name in FORBIDDEN_CRATES {
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(name) {
            let at = from + rel;
            let after = at + name.len();
            if ident_boundary(&stripped, at, name.len())
                && stripped[after..].starts_with("::")
                && is_crate_root_path(&stripped, at)
            {
                push_forbidden_crates(&mut hits, &[name]);
                break;
            }
            from = at + name.len();
        }
    }
    hits
}

fn forbidden_crates(src: &str) -> Vec<String> {
    let mut hits = forbidden_import_crates(src);
    for name in forbidden_path_crates(src) {
        if !hits.iter().any(|h| h == &name) {
            hits.push(name);
        }
    }
    hits
}

fn oracle_fn_defs(src: &str) -> Vec<String> {
    let stripped = strip_comments(src);
    let mut hits = Vec::new();
    let mut i = 0;
    while let Some(rel) = stripped[i..].find("fn") {
        let at = i + rel;
        if ident_boundary(&stripped, at, 2) {
            if let Some(name) = take_ident(&stripped[at + 2..]) {
                if ORACLE_FNS.contains(&name) && !hits.iter().any(|h| h == name) {
                    hits.push(name.to_owned());
                }
                i = at + 2 + name.len();
                continue;
            }
        }
        i = at + 2;
    }
    hits
}

fn is_sha256_input_line(line: &str) -> bool {
    line.contains("Sha256::") || line.contains(".update(") || line.contains(".digest(")
}

fn paren_inner(s: &str) -> Option<&str> {
    let s = s.trim_start();
    if !s.starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[1..i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_provenance_file_digest(args: &str) -> bool {
    matches!(args.trim(), "&bytes" | "bytes")
}

fn matching_brace(src: &str, open: usize) -> Option<usize> {
    if src.as_bytes().get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut i = open;
    let bytes = src.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 2,
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'{' if !in_string => {
                depth += 1;
                i += 1;
            }
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn find_fn_body_open(src: &str, mut i: usize) -> Option<usize> {
    let mut paren = 0i32;
    let mut in_string = false;
    while i < src.len() {
        let b = src.as_bytes()[i];
        match b {
            b'\\' if in_string => i += 2,
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'(' if !in_string => {
                paren += 1;
                i += 1;
            }
            b')' if !in_string => {
                paren -= 1;
                i += 1;
            }
            b'{' if !in_string && paren <= 0 => return Some(i),
            b';' if !in_string && paren <= 0 => return None,
            _ => i += 1,
        }
    }
    None
}

fn fn_body_ranges(src: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while let Some(rel) = src[i..].find("fn") {
        let at = i + rel;
        if ident_boundary(src, at, 2) {
            if let Some(open) = find_fn_body_open(src, at + 2) {
                if let Some(close) = matching_brace(src, open) {
                    ranges.push((open + 1, close));
                }
            }
        }
        i = at + 2;
    }
    ranges
}

fn body_containing(src: &str, pos: usize) -> &str {
    let mut best: Option<(usize, usize)> = None;
    for (start, end) in fn_body_ranges(src) {
        if start <= pos && pos < end {
            let keep = match best {
                None => true,
                Some((s, e)) => (end - start) < (e - s),
            };
            if keep {
                best = Some((start, end));
            }
        }
    }
    match best {
        Some((s, e)) => &src[s..e],
        None => src,
    }
}

fn contains_fs_read_call(s: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = s[from..].find("fs::read") {
        let at = from + rel;
        let after = at + "fs::read".len();
        if ident_boundary(s, at + "fs::".len(), "read".len()) {
            let rest = s[after..].trim_start();
            if rest.starts_with('(') {
                return true;
            }
        }
        from = after;
    }
    false
}

fn assignment_eq(s: &str) -> Option<usize> {
    let mut paren = 0i32;
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'=' if paren == 0
                && bytes.get(i + 1) != Some(&b'=')
                && bytes.get(i + 1) != Some(&b'>') =>
            {
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn bytes_assigned_from_fs_read(body: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = body[from..].find("let") {
        let at = from + rel;
        if !ident_boundary(body, at, 3) {
            from = at + 3;
            continue;
        }
        let mut rest = body[at + 3..].trim_start();
        if let Some(after_mut) = keyword_rest(rest, "mut") {
            rest = after_mut.trim_start();
        }
        if let Some(name) = take_ident(rest) {
            if name == "bytes" {
                let after_name = rest[name.len()..].trim_start();
                if let Some(eq) = assignment_eq(after_name) {
                    let rhs = &after_name[eq + 1..];
                    let stmt_end = rhs.find(';').unwrap_or(rhs.len());
                    if contains_fs_read_call(&rhs[..stmt_end]) {
                        return true;
                    }
                }
            }
        }
        from = at + 3;
    }
    false
}

/// D28: any `Sha256::digest` / `.update` except provenance hashing of `fs::read` bytes.
fn sha256_oracle_hits(src: &str) -> Vec<String> {
    let stripped = strip_comments(src);
    if !stripped.contains("Sha256::") {
        return Vec::new();
    }
    let mut hits = Vec::new();
    if stripped.contains(".update(") {
        hits.push("Sha256 hasher .update (not provenance file hashing)".into());
    }
    if stripped.contains("[u8; 64]")
        || stripped.contains("[u8;64]")
        || stripped.contains("[u8; 32]")
        || stripped.contains("[u8;32]")
    {
        hits.push("Sha256 of a 32/64-byte array (SigningData pack)".into());
    }
    if stripped.contains("[32..]") || stripped.contains("[32..64]") {
        hits.push("Sha256 32-byte suffix pack".into());
    }
    for line in stripped.lines() {
        if is_sha256_input_line(line) && has_ident(line, "domain") {
            hits.push("Sha256:: call fed a 32-byte domain suffix".into());
            break;
        }
    }
    let needle = "Sha256::digest";
    let mut from = 0;
    while let Some(rel) = stripped[from..].find(needle) {
        let at = from + rel;
        if let Some(args) = paren_inner(&stripped[at + needle.len()..]) {
            if is_provenance_file_digest(args) {
                let body = body_containing(&stripped, at);
                if !bytes_assigned_from_fs_read(body) {
                    hits.push(
                        "Sha256::digest(&bytes) without fs::read assignment in the same function"
                            .into(),
                    );
                }
            } else {
                hits.push(format!(
                    "Sha256::digest except provenance file hashing (`&bytes`): {}",
                    args.trim()
                ));
            }
        }
        from = at + needle.len();
    }
    hits
}

fn hidden_source_pulls(src: &str) -> Vec<String> {
    let stripped = strip_comments(src);
    let mut hits = Vec::new();
    for name in ["include", "include_str", "include_bytes"] {
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(name) {
            let at = from + rel;
            if ident_boundary(&stripped, at, name.len()) {
                let rest = stripped[at + name.len()..].trim_start();
                if rest.starts_with('!') {
                    hits.push(format!("hidden source pull `{name}!`"));
                    break;
                }
            }
            from = at + name.len();
        }
    }
    if stripped.contains("#[path") {
        hits.push("hidden source pull `#[path]`".into());
    }
    let mut i = 0;
    while let Some(rel) = stripped[i..].find("mod") {
        let at = i + rel;
        if ident_boundary(&stripped, at, 3) {
            let after_kw = stripped[at + 3..].trim_start();
            if let Some(name) = take_ident(after_kw) {
                let after_name = after_kw[name.len()..].trim_start();
                if after_name.starts_with(';') {
                    hits.push(format!("file module `mod {name}`"));
                }
                i = at + 3 + name.len();
                continue;
            }
        }
        i = at + 3;
    }
    hits
}

fn adr005_violations(src: &str) -> Vec<String> {
    let mut v = Vec::new();
    for name in forbidden_crates(src) {
        v.push(format!("forbidden crate `{name}`"));
    }
    for name in oracle_fn_defs(src) {
        v.push(format!("D28 signing-root oracle `fn {name}`"));
    }
    v.extend(sha256_oracle_hits(src));
    v.extend(hidden_source_pulls(src));
    v
}

fn parse_provenance_inputs(header: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in header.lines() {
        let Some(rest) = line.strip_prefix("//! provenance-input:") else {
            continue;
        };
        let rest = rest.trim();
        let Some((path, sha)) = rest.split_once(" sha256:") else {
            continue;
        };
        out.push((path.trim().to_owned(), sha.trim().to_ascii_lowercase()));
    }
    out
}

/// Recompute each present input's sha256 against the `spec_kat.rs` header.
/// Missing files (unfetched cache) are skipped; a mismatch names the input.
fn recheck_input_digests(header: &str, root: &Path) -> Result<usize, String> {
    let inputs = parse_provenance_inputs(header);
    if inputs.is_empty() {
        return Err("spec_kat.rs header has no provenance-input lines".into());
    }
    let mut checked = 0usize;
    for (rel, expected) in inputs {
        let path = root.join(&rel);
        if !path.is_file() {
            continue;
        }
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("malformed provenance digest for {rel}: {expected}"));
        }
        let bytes = fs::read(&path).map_err(|e| format!("read {rel}: {e}"))?;
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return Err(format!(
                "stale provenance digest for {rel}: header {expected} disk {actual}"
            ));
        }
        checked += 1;
    }
    Ok(checked)
}

#[test]
fn test_generator_source_is_present_and_nonempty() {
    let sources = read_bin_sources();
    let lines: usize = sources.iter().map(|(_, src)| src.lines().count()).sum();
    assert!(
        lines > 0,
        "ADR-005 scan of src/bin covered 0 lines (vacuous); files={}",
        sources.len()
    );
}

#[test]
fn test_generator_at_head_is_clean() {
    let mut hits = Vec::new();
    for (path, src) in read_bin_sources() {
        for hit in adr005_violations(&src) {
            hits.push(format!("{}: {hit}", path.display()));
        }
    }
    assert!(hits.is_empty(), "ADR-005 violations:\n  {}", hits.join("\n  "));
}

#[test]
fn test_scratch_eth_types_import_is_rejected() {
    let hits = forbidden_crates("use eth_types::Root;\n");
    assert_eq!(hits, ["eth_types"], "scratch `use eth_types::Root;` must be RED");
    assert!(
        forbidden_crates("extern crate ssz;\n").contains(&"ssz".to_owned()),
        "extern crate ssz must be RED"
    );
    for (src, crate_name) in [
        ("use rvc_gloas::BeaconBlock;\n", "rvc_gloas"),
        ("use tree_hash::TreeHash;\n", "tree_hash"),
        ("use tree_hash_derive::TreeHash;\n", "tree_hash_derive"),
        ("use ssz::Decode;\n", "ssz"),
        ("use ssz08::Encode;\n", "ssz08"),
        ("use libssz::HashTreeRoot;\n", "libssz"),
        ("use libssz_merkle::merkleize_progressive;\n", "libssz_merkle"),
        ("use libssz_types::BitList;\n", "libssz_types"),
        ("use libssz_derive::Encode;\n", "libssz_derive"),
        ("use ethereum_ssz::Decode;\n", "ethereum_ssz"),
        ("pub use eth_types::Root;\n", "eth_types"),
        ("use {eth_types::Root, tree_hash::TreeHash};\n", "eth_types"),
    ] {
        let hits = forbidden_crates(src);
        assert!(
            hits.iter().any(|h| h == crate_name),
            "expected `{crate_name}` in {src:?}, got {hits:?}"
        );
    }
}

#[test]
fn test_scratch_path_form_forbidden_crates_are_rejected() {
    for (src, crate_name) in [
        ("let _ = ssz::Decode::is_ssz_fixed_len();\n", "ssz"),
        ("let r = libssz_merkle::merkleize_progressive(&chunks);\n", "libssz_merkle"),
        ("let _ = ::libssz_types::BitList::default();\n", "libssz_types"),
        ("let _ = ethereum_ssz::Encode::as_ssz_bytes(&v);\n", "ethereum_ssz"),
        ("let _ = tree_hash_derive::TreeHash;\n", "tree_hash_derive"),
        ("let _ = libssz_derive::Encode;\n", "libssz_derive"),
    ] {
        let hits = forbidden_crates(src);
        assert!(
            hits.iter().any(|h| h == crate_name),
            "path-form `{crate_name}::` must be RED without a use line; {src:?} → {hits:?}"
        );
    }
}

#[test]
fn test_ssz_static_and_ssz_snappy_literals_are_allowed() {
    let src = r#"
        let p = "ssz_static";
        let q = "case.ssz_snappy";
        const SSZ_STATIC: &str = "ssz_static";
        const SSZ_SNAPPY_SUFFIX: &str = ".ssz_snappy";
        use sha2::{Digest, Sha256};
        use foo::ssz::Decode;
        use ssz_static::Case;
        use ssz_snappy::Decoder;
        let _ = foo::ssz::Decode;
    "#;
    let hits = forbidden_crates(src);
    assert!(
        hits.is_empty(),
        "`ssz_static` / `.ssz_snappy` / `foo::ssz` must stay GREEN (crate-name, not substring): {hits:?}"
    );
}

#[test]
fn test_scratch_compute_signing_root_is_rejected() {
    let hits = oracle_fn_defs("fn compute_signing_root\n");
    assert_eq!(
        hits,
        ["compute_signing_root"],
        "scratch `fn compute_signing_root` must be RED (D28)"
    );
    assert_eq!(
        oracle_fn_defs("pub fn compute_domain(domain_type: [u8; 4]) {}\n"),
        ["compute_domain"]
    );
    assert_eq!(oracle_fn_defs("fn compute_fork_data_root<T>() {}\n"), ["compute_fork_data_root"]);
    assert!(
        oracle_fn_defs("let compute_signing_root = 1;\nfn compute_signing_roots() {}\n").is_empty(),
        "non-exact names must stay GREEN"
    );
}

#[test]
fn test_scratch_sha256_domain_suffix_is_rejected() {
    let red = r#"
        let mut h = Sha256::new();
        h.update(&object_root);
        h.update(&domain);
    "#;
    assert!(
        !sha256_oracle_hits(red).is_empty(),
        "Sha256:: fed a 32-byte domain suffix must be RED"
    );
    assert!(!sha256_oracle_hits("Sha256::digest([object_root, domain].concat())\n").is_empty());
    let green = r#"
        fn push_input(path: &Path) -> Result<(), String> {
            let bytes = fs::read(path).map_err(|e| format!("read {e}"))?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            Ok(())
        }
    "#;
    assert!(
        sha256_oracle_hits(green).is_empty(),
        "push_input fs::read + Sha256::digest(&bytes) must stay GREEN: hits={:?}",
        sha256_oracle_hits(green)
    );
}

#[test]
fn test_scratch_vec_extend_digest_bytes_is_rejected() {
    let red = r#"
        fn oracle() {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&object_root);
            bytes.extend_from_slice(&domain);
            let _ = hex::encode(Sha256::digest(&bytes));
        }
    "#;
    let hits = sha256_oracle_hits(red);
    assert!(
        !hits.is_empty(),
        "Vec extend_from_slice twice then Sha256::digest(&bytes) must be RED"
    );
}

#[test]
fn test_scratch_64_byte_sha256_pack_is_rejected() {
    let red = r#"
        let mut packed = [0u8; 64];
        packed[..32].copy_from_slice(&object_root);
        packed[32..].copy_from_slice(&suffix);
        let _ = Sha256::digest(packed);
    "#;
    let hits = sha256_oracle_hits(red);
    assert!(!hits.is_empty(), "64-byte SigningData pack then Sha256::digest must be RED");
}

#[test]
fn test_scratch_include_and_path_are_rejected() {
    assert!(
        hidden_source_pulls("include!(\"oracle.rs\");\n").iter().any(|h| h.contains("include!")),
        "include! must be RED"
    );
    assert!(
        hidden_source_pulls("#[path = \"oracle.rs\"]\nmod oracle;\n")
            .iter()
            .any(|h| h.contains("#[path]") || h.contains("mod oracle")),
        "#[path] / file mod must be RED"
    );
    assert!(
        hidden_source_pulls("let sha256 = hex::encode(Sha256::digest(&bytes));\n").is_empty(),
        "provenance-only source must not look like a hidden pull"
    );
}

#[test]
fn test_header_input_digests_match_on_disk_when_present() {
    let path = spec_kat_path();
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let checked = recheck_input_digests(&src, &workspace_root()).unwrap_or_else(|e| panic!("{e}"));
    assert!(checked > 0, "no provenance-input files present on disk to re-check");
}

#[test]
fn test_stale_header_digest_fails_naming_the_input_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let rel = "tests/fixtures/case.ssz_snappy";
    let path = tmp.path().join(rel);
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, b"vector-bytes").expect("write");
    let stale = "0".repeat(64);
    assert_ne!(sha256_hex(b"vector-bytes"), stale);
    let header = format!("//! provenance-input: {rel} sha256:{stale}\n");
    let err = recheck_input_digests(&header, tmp.path())
        .expect_err("header digest ≠ on-disk digest must fail");
    assert!(err.contains(rel), "failure must name the input file: {err}");
}
