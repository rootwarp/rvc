//! Production signer call sites install an admission scope.
//!
//! A new `self.signer.sign_*` in the validator client, block service, or
//! builder service must sit in the same block as `under_admission`,
//! `with_beacon_admission`, or `BeaconAdmission::unbound`. Whitespace and
//! newlines do not matter. A marker in another function, or in a nested block
//! that has already closed, does not cover the call. A previous call in the
//! same block does not cover the next one. Voluntary exit does not require an
//! admission scope: the signed message is the exit epoch and validator index.
//! The keymanager may still read the index from a beacon node. Trait bridges
//! in `traits.rs` only forward the call.

use std::path::{Path, PathBuf};

const SIGN_METHODS: &[&str] = &[
    "sign_execution_payload_envelope_root",
    "sign_sync_committee_selection_proof",
    "sign_electra_aggregate_and_proof",
    "sign_aggregate_and_proof_root",
    "sign_contribution_and_proof",
    "sign_sync_committee_message",
    "sign_proposer_preferences",
    "sign_builder_request_auth",
    "sign_builder_registration",
    "sign_aggregate_and_proof",
    "sign_payload_attestation",
    "sign_randao_reveal",
    "sign_selection_proof",
    "sign_block_header",
    "sign_attestation",
    "sign_block",
];

const SCOPE_MARKERS: &[&str] =
    &["under_admission", "with_beacon_admission", "BeaconAdmission::unbound"];

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
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') || name == "tests" {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_cfg_test_attr(trimmed: &str) -> bool {
    let t = trimmed.trim_end_matches(',').trim();
    if !(t.starts_with("#[cfg(") || t.starts_with("#![cfg(")) {
        return false;
    }
    let inner_start = t.find('(').map(|index| index + 1).unwrap_or(0);
    let inner_end = t.rfind(')').unwrap_or(t.len());
    if inner_start >= inner_end {
        return false;
    }
    t[inner_start..inner_end]
        .split(|c: char| c == ',' || c == '(' || c == ')' || c.is_whitespace())
        .any(|token| token == "test")
}

/// Bottom `#[cfg(test)] mod tests`, not a mid-file `#[cfg(test)]` field.
fn tests_module_line(src: &str) -> Option<usize> {
    let lines: Vec<&str> = src.lines().collect();
    lines.iter().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim();
        if trimmed != "mod tests {" && trimmed != "mod tests{" {
            return None;
        }
        let start = index.saturating_sub(4);
        lines[start..index].iter().any(|prev| is_cfg_test_attr(prev.trim())).then_some(index + 1)
    })
}

/// Code with comments and whitespace removed. Each kept byte maps back to `src`.
fn compact_code(src: &str) -> (String, Vec<usize>) {
    let mut out = String::new();
    let mut at = Vec::new();
    let mut chars = src.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '/' {
            if matches!(chars.peek(), Some((_, '/'))) {
                for (_, next) in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
                continue;
            }
            if matches!(chars.peek(), Some((_, '*'))) {
                chars.next();
                while let Some((_, next)) = chars.next() {
                    if next == '*' && matches!(chars.peek(), Some((_, '/'))) {
                        chars.next();
                        break;
                    }
                }
                continue;
            }
        }
        if ch.is_whitespace() {
            continue;
        }
        out.push(ch);
        at.push(index);
    }
    (out, at)
}

fn line_of(src: &str, byte: usize) -> usize {
    src[..byte].bytes().filter(|b| *b == b'\n').count() + 1
}

fn skip_string(src: &str, start: usize) -> usize {
    let bytes = src.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn skip_line_comment(src: &str, start: usize) -> usize {
    src[start..].find('\n').map(|offset| start + offset).unwrap_or(src.len())
}

fn skip_block_comment(src: &str, start: usize) -> usize {
    src[start + 2..].find("*/").map(|offset| start + 2 + offset + 2).unwrap_or(src.len())
}

/// `{` of the block that directly contains `call_at`.
fn enclosing_brace(src: &str, call_at: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut index = 0;
    let mut stack = Vec::new();
    while index < call_at {
        if bytes[index] == b'"' {
            index = skip_string(src, index);
            continue;
        }
        if bytes[index] == b'/' && index + 1 < call_at && bytes[index + 1] == b'/' {
            index = skip_line_comment(src, index);
            continue;
        }
        if bytes[index] == b'/' && index + 1 < call_at && bytes[index + 1] == b'*' {
            index = skip_block_comment(src, index);
            continue;
        }
        match bytes[index] {
            b'{' => stack.push(index),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
        index += 1;
    }
    stack.pop()
}

fn ends_with_sign_call(buf: &str) -> bool {
    SIGN_METHODS.iter().any(|method| buf.ends_with(&format!("self.signer.{method}(")))
}

/// Scope marker at this block's depth, after the previous `self.signer.sign_*` there.
fn scope_governs_call(src: &str, open_brace: usize, call_at: usize) -> bool {
    let bytes = src.as_bytes();
    let mut index = open_brace + 1;
    let mut depth = 1i32;
    let mut buf = String::new();
    while index < call_at && depth > 0 {
        if bytes[index] == b'"' {
            index = skip_string(src, index);
            continue;
        }
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            index = skip_line_comment(src, index);
            continue;
        }
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            index = skip_block_comment(src, index);
            continue;
        }
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ if depth == 1 && !bytes[index].is_ascii_whitespace() => {
                buf.push(bytes[index] as char);
                if ends_with_sign_call(&buf) {
                    buf.clear();
                }
            }
            _ => {}
        }
        index += 1;
    }
    SCOPE_MARKERS.iter().any(|marker| buf.contains(marker))
}

fn sign_calls(compact: &str) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    let mut from = 0;
    while from < compact.len() {
        let Some(rel) = compact[from..].find("self.signer.") else {
            break;
        };
        let at = from + rel;
        let after = at + "self.signer.".len();
        let method = SIGN_METHODS.iter().copied().find(|method| {
            compact[after..].starts_with(method) && compact[after + method.len()..].starts_with('(')
        });
        let Some(method) = method else {
            from = after;
            continue;
        };
        hits.push((at, method));
        from = after + method.len() + 1;
    }
    hits
}

fn unsigned_sites(rel: &str, src: &str) -> Vec<String> {
    if rel.ends_with("/traits.rs") {
        return Vec::new();
    }
    let cutoff = tests_module_line(src);
    let (compact, bytes) = compact_code(src);
    let mut misses = Vec::new();
    for (at, method) in sign_calls(&compact) {
        let byte = bytes[at];
        let line_no = line_of(src, byte);
        if cutoff.is_some_and(|cutoff| line_no >= cutoff) {
            break;
        }
        let Some(open) = enclosing_brace(src, byte) else {
            misses.push(format!("{rel}:{line_no} .{method}( has no admission scope"));
            continue;
        };
        if scope_governs_call(src, open, byte) {
            continue;
        }
        misses.push(format!("{rel}:{line_no} .{method}( has no admission scope"));
    }
    misses
}

#[test]
fn production_signer_calls_install_an_admission_scope() {
    let root = workspace_root();
    let mut files = Vec::new();
    for rel in ["crates/builder/src", "crates/block-service/src", "crates/rvc/src"] {
        collect_rs(&root.join(rel), &mut files);
    }
    let mut misses = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        misses.extend(unsigned_sites(&rel, &src));
    }
    assert!(
        misses.is_empty(),
        "signer call without under_admission, with_beacon_admission, or BeaconAdmission::unbound:\n{}",
        misses.join("\n")
    );
}

#[test]
fn multiline_call_needs_a_marker_in_its_own_block() {
    let src = r#"
        fn earlier() {
            under_admission(self.signer.sign_block(&header, pubkey, &schedule, &root));
        }
        fn sign_two() {
            {
                let _closed = "under_admission";
            }
            signer::with_beacon_admission(
                signer::BeaconAdmission::unbound(),
                self
                    .signer
                    .sign_builder_registration(&registration, &pk, fork),
            );
            match self
                .signer
                .sign_proposer_preferences(&prefs, &pk, &schedule, &root)
            {
                Ok(_) => {}
                Err(_) => {}
            }
        }
    "#;
    let misses = unsigned_sites("crates/builder/src/service.rs", src);
    assert!(misses.iter().any(|miss| miss.contains("sign_proposer_preferences")), "{misses:?}");
    assert!(!misses.iter().any(|miss| miss.contains("sign_builder_registration")), "{misses:?}");
    assert!(!misses.iter().any(|miss| miss.contains("sign_block")), "{misses:?}");
}
