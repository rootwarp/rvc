//! ARCH-P2-5 / ARCH-6: docs-freshness — backticked workspace paths in tracked docs must exist.
//!
//! Scans **tracked** markdown under `docs/` (`git ls-files`) for inline-backtick tokens that look
//! like workspace paths (`crates/…`, `bin/…`, `plan/…`, `docs/…`) and asserts each resolves on
//! disk (file or directory). Fenced code blocks (including mermaid) and URLs are ignored.
//!
//! `docs/architecture.md` is a stale test-audit remediation plan (not the generated
//! `ARCHITECTURE.md`) whose source paths have rotted. NG8 forbids editing it in this initiative,
//! so it is the sole entry on the **shrinking-only** [`STALE_DOC_EXEMPTIONS`] inventory. Entries
//! may be **removed**, never **added** without a deliberate policy exception — prefer fixing the
//! doc or moving it (`plan/test-architecture-audit.md`) over growing this list.
//!
//! Cross-ref: plan `architecture-2026-08-12` issue ARCH-6 / VD-E3; PRD ARCH-P2-5 (scan half only).
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `kat_policy.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Shrinking-only exemption inventory (doc path → reason)
// ---------------------------------------------------------------------------

/// Tracked docs that may cite dead paths until a named removal trigger lands.
///
/// **Shrinking-only:** entries may be **removed**, never **added**. Prefer fixing the doc or
/// executing ARCH-P2-5's proposed move over growing this list. See module docs.
const STALE_DOC_EXEMPTIONS: &[(&str, &str)] = &[(
    "docs/architecture.md",
    "NG8: owned by the Test Audit Remediation initiative; ARCH-P2-5 proposes moving it to \
     plan/test-architecture-audit.md — remove this entry when that move lands",
)];

/// Non-vacuity floor: at least this many path tokens from non-exempt docs must resolve.
const MIN_RESOLVED_FROM_NON_EXEMPT: usize = 1;

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// Tracked markdown under `docs/` (includes top-level `docs/*.md` and nested paths).
///
/// Uses `git ls-files -- docs` rather than a single `docs/**/*.md` glob: git's pathspec does not
/// always match top-level files under `docs/`, and those files (including the exempt
/// `docs/architecture.md`) must participate in the scan.
fn tracked_docs_markdown(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "--", "docs"])
        .current_dir(root)
        .output()
        .expect("git ls-files docs");
    assert!(
        output.status.success(),
        "git ls-files docs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.ends_with(".md"))
        .map(|l| l.replace('\\', "/"))
        .collect()
}

// ---------------------------------------------------------------------------
// Markdown scan (fences / mermaid / inline backticks)
// ---------------------------------------------------------------------------

/// Drop fenced code blocks (``` … ```), including mermaid diagrams.
fn strip_fenced_code_blocks(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_fence = false;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// True if `token` is a workspace-relative path-like reference we should resolve.
fn is_path_like_token(token: &str) -> bool {
    let prefixes = ["crates/", "bin/", "plan/", "docs/"];
    if !prefixes.iter().any(|p| token.starts_with(p)) {
        return false;
    }
    // URLs / schemes (ignore even if somehow backticked).
    if token.contains("://") || token.starts_with("http:") || token.starts_with("https:") {
        return false;
    }
    // Placeholders in release notes (`docs/releases/vX.Y.Z.md`) and globs.
    if token.contains("X.Y.Z") || token.contains('*') || token.contains('…') || token.contains('?')
    {
        return false;
    }
    // Path characters only (no spaces / prose punctuation).
    if !token.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-' | '+'))
    {
        return false;
    }
    // Reject `.` / `..` / empty segments so join+exists cannot leave the tree or
    // false-green aliases like `crates/../Cargo.toml` (S-ARCH6-4).
    if token.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return false;
    }
    // Need at least one path segment after the prefix root (`crates/foo`, not `crates/`).
    let rest = &token[token.find('/').unwrap() + 1..];
    !rest.is_empty()
}

/// Extract path-like tokens from inline `` `…` `` spans (fences already stripped).
fn extract_path_tokens(markdown: &str) -> Vec<String> {
    let body = strip_fenced_code_blocks(markdown);
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        // Skip fenced leftovers (should already be stripped) and double-backtick.
        if i + 1 < bytes.len() && bytes[i + 1] == b'`' {
            i += 2;
            continue;
        }
        let start = i + 1;
        let Some(rel) = body[start..].find('`') else {
            break;
        };
        let end = start + rel;
        let token = body[start..end].trim();
        // Single-line inline code only; multi-line spans are not path citations.
        if !token.is_empty() && !token.contains('\n') && is_path_like_token(token) {
            out.push(token.to_string());
        }
        i = end + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Freshness check
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeadPath {
    doc: String,
    path: String,
}

/// Check markdown `body` attributed to workspace-relative `doc` against `root`.
///
/// Returns dead path citations. When `doc` is listed in `exempt_docs`, returns no dead paths
/// (the whole file is skipped).
fn dead_paths_in_doc(
    root: &Path,
    doc: &str,
    body: &str,
    exempt_docs: &HashSet<&str>,
) -> Vec<DeadPath> {
    if exempt_docs.contains(doc) {
        return Vec::new();
    }
    let mut dead = Vec::new();
    let mut seen = HashSet::new();
    for path in extract_path_tokens(body) {
        if !seen.insert(path.clone()) {
            continue;
        }
        if !root.join(&path).exists() {
            dead.push(DeadPath { doc: doc.to_string(), path });
        }
    }
    dead
}

/// Scan all tracked docs; returns (dead paths, count of resolved tokens from non-exempt docs).
fn scan_tracked_docs(root: &Path, exempt_docs: &HashSet<&str>) -> (Vec<DeadPath>, usize) {
    let docs = tracked_docs_markdown(root);
    assert!(!docs.is_empty(), "git ls-files returned no docs/**/*.md; workspace walk likely broke");

    let mut dead = Vec::new();
    let mut resolved_non_exempt = 0usize;

    for doc in &docs {
        let abs = root.join(doc);
        let body =
            std::fs::read_to_string(&abs).unwrap_or_else(|e| panic!("read {}: {e}", abs.display()));
        if exempt_docs.contains(doc.as_str()) {
            continue;
        }
        let mut seen = HashSet::new();
        for path in extract_path_tokens(&body) {
            if !seen.insert(path.clone()) {
                continue;
            }
            if root.join(&path).exists() {
                resolved_non_exempt += 1;
            } else {
                dead.push(DeadPath { doc: doc.clone(), path });
            }
        }
    }
    dead.sort_by(|a, b| (&a.doc, &a.path).cmp(&(&b.doc, &b.path)));
    (dead, resolved_non_exempt)
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn test_docs_reference_only_existing_paths() {
    let root = workspace_root();
    let exempt: HashSet<&str> = STALE_DOC_EXEMPTIONS.iter().map(|(p, _)| *p).collect();
    assert_eq!(exempt.len(), STALE_DOC_EXEMPTIONS.len(), "duplicate STALE_DOC_EXEMPTIONS paths");
    assert_eq!(
        STALE_DOC_EXEMPTIONS.len(),
        1,
        "STALE_DOC_EXEMPTIONS must stay a single NG8 entry until docs/architecture.md moves"
    );
    assert_eq!(STALE_DOC_EXEMPTIONS[0].0, "docs/architecture.md");
    assert!(STALE_DOC_EXEMPTIONS[0].1.contains("NG8"), "exemption reason must cite NG8");
    assert!(
        STALE_DOC_EXEMPTIONS[0].1.contains("plan/test-architecture-audit.md"),
        "exemption reason must name the removal trigger path"
    );

    let (dead, resolved) = scan_tracked_docs(&root, &exempt);
    assert!(
        dead.is_empty(),
        "docs-freshness (ARCH-P2-5 / ARCH-6): backticked workspace paths in tracked docs must \
         resolve on disk (file or directory).\n\
         Fix the citation in the doc. Do not grow STALE_DOC_EXEMPTIONS (shrinking-only; the \
         one-entry NG8 ratchet is intentional).\n\
         Offenders:\n  {}",
        dead.iter().map(|d| format!("{}: `{}`", d.doc, d.path)).collect::<Vec<_>>().join("\n  ")
    );
    assert!(
        resolved >= MIN_RESOLVED_FROM_NON_EXEMPT,
        "docs-freshness non-vacuity: resolved only {resolved} path token(s) from non-exempt docs; \
         extractor likely broke (need >= {MIN_RESOLVED_FROM_NON_EXEMPT})"
    );
}

/// Permanent falsifiability: checker must name a synthetic dead path.
#[test]
fn test_docs_freshness_rejects_a_dead_path() {
    let root = workspace_root();
    let exempt: HashSet<&str> = HashSet::new();
    let body = "See the helper at `crates/does-not-exist/src/lib.rs` for details.\n";
    let dead = dead_paths_in_doc(&root, "docs/synthetic-freshness.md", body, &exempt);
    assert!(
        dead.iter().any(|d| d.path == "crates/does-not-exist/src/lib.rs"),
        "expected synthetic dead path in {dead:?}"
    );
}

/// Documents the RED that justifies the one-entry exemption (empty list fails on architecture.md).
#[test]
fn test_empty_exemption_flags_architecture_md_dead_paths() {
    let root = workspace_root();
    let abs = root.join("docs/architecture.md");
    let body =
        std::fs::read_to_string(&abs).unwrap_or_else(|e| panic!("read {}: {e}", abs.display()));
    let empty: HashSet<&str> = HashSet::new();
    let dead = dead_paths_in_doc(&root, "docs/architecture.md", &body, &empty);
    assert!(
        dead.iter().any(|d| d.path == "crates/propagator/src/lib.rs"),
        "empty exemption must flag crates/propagator/src/lib.rs; got {dead:?}"
    );
    assert!(
        dead.iter().all(|d| d.doc == "docs/architecture.md"),
        "architecture.md scan should only report that doc; got {dead:?}"
    );
}

#[test]
fn test_stale_doc_exemptions_are_unique_and_documented() {
    let mut seen = HashSet::new();
    for &(path, reason) in STALE_DOC_EXEMPTIONS {
        assert!(seen.insert(path), "duplicate exemption path: {path}");
        assert!(!reason.is_empty(), "exemption {path} needs a reason");
        assert!(
            path.starts_with("docs/") && path.ends_with(".md"),
            "exemption paths must be docs/**/*.md: {path}"
        );
    }
}

// ---------------------------------------------------------------------------
// Matcher unit tests
// ---------------------------------------------------------------------------

#[test]
fn path_token_extractor_ignores_fences_urls_and_placeholders() {
    let src = r#"
Live path: `crates/signer/src/lib.rs`
URL should ignore: `https://example.com/crates/foo`
Fenced:

```rust
crates/does-not-exist/src/lib.rs
`crates/also-fenced/src/lib.rs`
```

```mermaid
graph TD
  A[`crates/mermaid-ignored/src/lib.rs`]
```

Placeholder: `docs/releases/vX.Y.Z.md`
Prose not a path: `some random code`
Dot segments rejected: `crates/../Cargo.toml` `crates/./foo.rs` `crates/foo//bar.rs`
"#;
    let tokens = extract_path_tokens(src);
    assert_eq!(tokens, vec!["crates/signer/src/lib.rs".to_string()]);
}

#[test]
fn path_like_token_rejects_dot_and_parent_segments() {
    assert!(!is_path_like_token("crates/../Cargo.toml"));
    assert!(!is_path_like_token("crates/.."));
    assert!(!is_path_like_token("crates/../../.git/config"));
    assert!(!is_path_like_token("docs/../../.env"));
    assert!(!is_path_like_token("bin/../crates/rvc"));
    assert!(!is_path_like_token("crates/./lib.rs"));
    assert!(!is_path_like_token("crates//lib.rs"));
    assert!(is_path_like_token("crates/signer/src/lib.rs"));
    assert!(is_path_like_token("bin/rvc"));
}

#[test]
fn path_token_extractor_accepts_plan_and_docs_prefixes() {
    let src = "See `plan/logging/STANDARD.md` and `docs/running-guide.md` plus dir `bin/rvc`.";
    let mut tokens = extract_path_tokens(src);
    tokens.sort();
    assert_eq!(
        tokens,
        vec![
            "bin/rvc".to_string(),
            "docs/running-guide.md".to_string(),
            "plan/logging/STANDARD.md".to_string(),
        ]
    );
}

/// `allow_unsupported_fork` is the opt-out in `apply_fork_compatibility_result`.
///
/// A line range in `docs/forks.md` drifted (RR4-04 S3). The checklist names the
/// function. `173–176` / `173-176` must not come back.
#[test]
fn forks_md_names_allow_unsupported_fork_opt_out() {
    let text = std::fs::read_to_string(workspace_root().join("docs/forks.md"))
        .expect("read docs/forks.md");
    assert!(
        text.contains("`apply_fork_compatibility_result`"),
        "docs/forks.md must name apply_fork_compatibility_result"
    );
    assert!(
        text.contains("crates/rvc/src/bootstrap/services.rs"),
        "the opt-out still lives in bootstrap/services.rs"
    );
    assert!(
        !text.contains("173–176") && !text.contains("173-176"),
        "stale services.rs line range must not return"
    );
}

#[test]
fn dead_path_helper_skips_exempt_docs() {
    let root = workspace_root();
    let body = "`crates/does-not-exist/src/lib.rs`";
    let mut exempt = HashSet::new();
    exempt.insert("docs/architecture.md");
    let dead = dead_paths_in_doc(&root, "docs/architecture.md", body, &exempt);
    assert!(dead.is_empty(), "exempt doc must be skipped entirely: {dead:?}");
}
