//! Source lock: every slot and epoch bind goes through `to_sql_i64`.
//!
//! Scans `crates/slashing/src/**/*.rs`, including `#[cfg(test)]` modules, and
//! rejects an `as i64` cast in code. Comments are ignored.

use std::fs;
use std::path::Path;

#[test]
fn no_as_i64_cast_remains_in_slashing_src() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk(&root, &mut hits);
    assert!(
        hits.is_empty(),
        "unchecked `as i64` casts remain in crates/slashing/src:\n{}",
        hits.join("\n")
    );
}

fn walk(dir: &Path, hits: &mut Vec<String>) {
    let mut entries: Vec<_> =
        fs::read_dir(dir).expect("read_dir").map(|e| e.expect("entry")).collect();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, hits);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            scan(&path, hits);
        }
    }
}

fn scan(path: &Path, hits: &mut Vec<String>) {
    let text = fs::read_to_string(path).expect("read source");
    let code = strip_comments(&text);
    for (idx, line) in code.lines().enumerate() {
        if line.contains("as i64") {
            hits.push(format!("{}:{}: {line}", path.display(), idx + 1));
        }
    }
}

/// Drop `//` and `/* */` comments. Strings are left intact; a cast inside a
/// string would still be reported.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if next == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for next in chars.by_ref() {
                        if prev == '*' && next == '/' {
                            break;
                        }
                        if next == '\n' {
                            out.push('\n');
                        }
                        prev = next;
                    }
                }
                _ => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}
