//! RF6-22 / H5: KAT-first policy — CI-enforced ban on self-consistency-only root tests.
//!
//! F122 (AUDIT-2026-05-30 theme 2) records three bugs that each shipped with a **green test
//! asserting the bug**. The worst pattern is tautological self-consistency
//! (`compute_block_root(x) == x.tree_hash_root()`), which cannot catch a shared wrong tree-hash
//! implementation. This gate makes the review convention falsifiable:
//!
//! For every `#[test]` / `#[tokio::test]` whose name matches
//! `.*(tree_hash|signing_root|_root)$`, the body must either
//!
//! 1. reference an `EXTERNAL_*` / `KAT_*` / `SPEC_*` constant (known-answer / reference vector), or
//! 2. carry a documented `kat_exempt` marker (comment or attribute text), or
//! 3. appear on the **shrinking-only** [`EXEMPTIONS`] inventory seeded at RF6-22 land.
//!
//! New root tests that only self-compare in-tree helpers will fail CI until they gain a KAT
//! anchor or an explicit exemption. Entries may be **removed** from [`EXEMPTIONS`], never added
//! without a deliberate policy exception (prefer KAT vectors or a `// kat_exempt: reason` marker
//! next to the test instead).
//!
//! Cross-ref: issue **6.8** KAT-anchored `test_compute_block_root_matches_tree_hash` and
//! `test_propose_block_ssz_block_root_uses_tree_hash` via `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX`.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `no_rvc_prefix.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Shrinking-only exemption inventory (path, test_fn)
// ---------------------------------------------------------------------------

/// Workspace-relative `/`-separated paths + test function names that matched the name pattern
/// at RF6-22 land without an `EXTERNAL_*`/`KAT_*`/`SPEC_*` body reference or `kat_exempt` marker.
///
/// **Shrinking-only:** entries may be **removed**, never **added**. Prefer converting a row to a
/// KAT-anchored assertion (or an in-source `// kat_exempt: <reason>` marker for intentional
/// false positives) over growing this list. See module docs + CLAUDE.md Testing.
// Sorted by (path, name). Categories (for humans; order is lexical):
// - name-pattern false positives (genesis_root, dependent_root, wire paths, …)
// - self-consistency / relative root coverage (H5 targets; test-audit 3.4 shrinks block-service rows)
const EXEMPTIONS: &[(&str, &str)] = &[
    ("bin/rvc-keygen/src/bls_to_execution.rs", "test_bls_to_execution_uses_actual_genesis_root"),
    ("bin/rvc-keygen/src/deposit.rs", "test_sign_deposit_uses_zeroed_genesis_root"),
    ("bin/rvc-keygen/src/deposit.rs", "test_to_launchpad_json_deposit_data_root"),
    ("bin/rvc-keygen/src/deposit.rs", "test_to_launchpad_json_deposit_message_root"),
    ("bin/rvc-keygen/src/network.rs", "test_holesky_genesis_root"),
    ("bin/rvc-keygen/src/network.rs", "test_hoodi_genesis_root"),
    ("bin/rvc-keygen/src/network.rs", "test_mainnet_genesis_root"),
    ("bin/rvc-keygen/src/network.rs", "test_sepolia_genesis_root"),
    ("bin/rvc-keygen/tests/compatibility.rs", "test_deposit_domain_uses_zeroed_genesis_root"),
    ("bin/rvc-keygen/tests/compatibility.rs", "test_deposit_message_root_differs_from_data_root"),
    ("crates/beacon/tests/client_http.rs", "test_get_proposer_duties_with_dependent_root"),
    (
        "crates/block-service/src/service/tests/mocks.rs",
        "test_sign_block_captures_fork_schedule_and_genesis_root",
    ),
    (
        "crates/block-service/src/service/tests/propose.rs",
        "test_compute_blinded_block_root_matches_tree_hash",
    ),
    ("crates/crypto/src/signing.rs", "test_attestation_data_tree_hash_root"),
    ("crates/crypto/src/signing.rs", "test_checkpoint_tree_hash_root"),
    ("crates/crypto/src/signing.rs", "test_hash_tree_root_uses_spec_compliant_tree_hash"),
    ("crates/crypto/src/signing.rs", "test_signing_data_tree_hash_root"),
    (
        "crates/crypto/src/signing_root.rs",
        "test_signing_root_for_blinded_block_matches_compute_signing_root",
    ),
    (
        "crates/crypto/src/signing_root.rs",
        "test_signing_root_for_full_block_matches_compute_signing_root",
    ),
    ("crates/duty-tracker/src/tracker.rs", "test_get_cached_proposer_dependent_root"),
    ("crates/rvc/src/config/builder.rs", "test_parse_genesis_validators_root"),
    ("crates/rvc/src/config/network.rs", "test_network_genesis_validators_root"),
    (
        "crates/rvc/src/orchestrator/sync_committee.rs",
        "test_messages_and_contributions_share_head_root",
    ),
    (
        "crates/signer-server/src/http_api/dispatch.rs",
        "block_v2_uses_proposer_domain_and_block_header_root",
    ),
    (
        "crates/signer-server/src/http_api/routes/tests/sign.rs",
        "attestation_happy_path_signs_the_expected_root",
    ),
    (
        "crates/signer-server/src/http_api/routes/tests/sign.rs",
        "block_v2_happy_path_signs_the_block_header_root",
    ),
    (
        "crates/signer-server/src/http_api/routes/tests/sign.rs",
        "electra_v2_frozen_fixture_parses_and_signs_to_eth_types_root",
    ),
    (
        "crates/signer-server/src/http_api/routes/tests/sign.rs",
        "sync_committee_message_kat_signs_the_block_root",
    ),
    ("crates/signer-server/tests/raw_root_rejected.rs", "test_no_v2_rpc_accepts_raw_signing_root"),
    (
        "crates/slashing/src/db/interchange.rs",
        "test_existing_bare_hex_metadata_matches_canonical_prefixed_root",
    ),
    ("crates/slashing/src/db/interchange.rs", "test_integrity_set_genesis_validators_root"),
    ("crates/slashing/src/db/records.rs", "test_insert_attestation_without_signing_root"),
    ("crates/slashing/src/db/records.rs", "test_insert_block_without_signing_root"),
    ("crates/slashing/src/db/records.rs", "test_seed_attestation_without_signing_root"),
    ("crates/slashing/src/types.rs", "test_interchange_attestation_without_signing_root"),
    ("crates/slashing/src/types.rs", "test_interchange_block_without_signing_root"),
    ("crates/slashing/src/types.rs", "test_signed_attestation_without_signing_root"),
    ("crates/telemetry/src/propagation.rs", "test_set_parent_after_enter_is_noop_root"),
];

// ---------------------------------------------------------------------------
// Workspace walk
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// Parse `members = [...]` from the workspace `Cargo.toml` (no TOML crate — P6).
fn workspace_member_dirs(root: &Path) -> Vec<PathBuf> {
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let mut dirs = Vec::new();
    // members = ["bin/rvc", "crates/foo", ...] possibly multi-line
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
// Name pattern + body classification
// ---------------------------------------------------------------------------

/// Name matches `.*(tree_hash|signing_root|_root)$` (issue sketch).
fn name_matches_root_pattern(name: &str) -> bool {
    name.ends_with("tree_hash") || name.ends_with("signing_root") || name.ends_with("_root")
}

/// True if `body` references an EXTERNAL_*/KAT_*/SPEC_* identifier.
fn body_has_kat_constant(body: &str) -> bool {
    // Identifier-prefix scan (no regex crate). Match EXTERNAL_FOO, KAT_BAR, SPEC_BAZ.
    let bytes = body.as_bytes();
    let needles: &[&[u8]] = &[b"EXTERNAL_", b"KAT_", b"SPEC_"];
    for needle in needles {
        let mut from = 0;
        while let Some(rel) = body[from..].find(std::str::from_utf8(needle).unwrap()) {
            let at = from + rel;
            let before_ok = at == 0
                || !{
                    let b = bytes[at - 1];
                    b.is_ascii_alphanumeric() || b == b'_'
                };
            if before_ok {
                let after = at + needle.len();
                if after < bytes.len()
                    && (bytes[after].is_ascii_uppercase() || bytes[after].is_ascii_digit())
                {
                    return true;
                }
                // Also accept bare prefix used as part of a longer SCREAMING name that continues
                // with uppercase after underscore already consumed — require at least one more
                // identifier char.
                if after < bytes.len()
                    && (bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_')
                {
                    return true;
                }
            }
            from = at + needle.len();
        }
    }
    false
}

/// Documented exemption marker: `kat_exempt` in attributes/comments/body (e.g. `// kat_exempt:`
/// or `#[allow(kat_exempt)]`-style).
fn body_has_kat_exempt_marker(body: &str) -> bool {
    body.contains("kat_exempt")
}

// ---------------------------------------------------------------------------
// Test extraction (brace-aware, best-effort)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundTest {
    rel_path: String,
    name: String,
    /// Attribute lines + signature + body (used for KAT / exempt detection).
    span: String,
}

fn is_test_attr(line: &str) -> bool {
    let t = line.trim_start();
    // #[test] / #[tokio::test] / #[tokio::test(flavor = "multi_thread")]
    t.starts_with("#[test") || t.starts_with("#[tokio::test")
}

fn extract_tests(rel_path: &str, src: &str) -> Vec<FoundTest> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_test_attr(lines[i]) {
            i += 1;
            continue;
        }
        let attr_start = i;
        i += 1;
        // Skip further attributes / blank / comments before `fn`.
        while i < lines.len() {
            let t = lines[i].trim_start();
            if t.is_empty() || t.starts_with("//") || t.starts_with("#[") || t.starts_with("#!") {
                i += 1;
                continue;
            }
            break;
        }
        if i >= lines.len() {
            break;
        }
        let name = match parse_fn_name(lines[i]) {
            Some(n) => n,
            None => continue,
        };
        if !name_matches_root_pattern(name) {
            continue;
        }
        // Find opening `{` for the function body.
        let mut brace_line = None;
        for (k, line) in lines.iter().enumerate().skip(i).take(12) {
            if line.contains('{') {
                brace_line = Some(k);
                break;
            }
        }
        let Some(brace_line) = brace_line else {
            continue;
        };
        let mut depth = 0i32;
        let mut end = brace_line;
        'outer: for (k, line) in lines.iter().enumerate().skip(brace_line) {
            for ch in line.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = k;
                            break 'outer;
                        }
                    }
                    _ => {}
                }
            }
        }
        let span = lines[attr_start..=end].join("\n");
        out.push(FoundTest { rel_path: rel_path.to_string(), name: name.to_string(), span });
    }
    out
}

fn parse_fn_name(line: &str) -> Option<&str> {
    // `fn name` / `async fn name` / `pub(crate) async fn name`
    let mut t = line.trim_start();
    if let Some(rest) = t.strip_prefix("pub") {
        t = rest.trim_start();
        if let Some(rest) = t.strip_prefix('(') {
            // pub(crate) / pub(super) / pub(in path)
            let after = rest.find(')')?;
            t = rest[after + 1..].trim_start();
        }
    }
    t = t.strip_prefix("async ").unwrap_or(t).trim_start();
    t = t.strip_prefix("fn ")?.trim_start();
    let name = t.split(|c: char| c == '(' || c.is_whitespace()).next()?;
    if name.is_empty() {
        return None;
    }
    Some(name)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Class {
    HasKat,
    ExemptMarker,
    ExemptListed,
    Violation,
}

fn classify(test: &FoundTest, exempt: &HashSet<(&str, &str)>) -> Class {
    if body_has_kat_constant(&test.span) {
        return Class::HasKat;
    }
    if body_has_kat_exempt_marker(&test.span) {
        return Class::ExemptMarker;
    }
    if exempt.contains(&(test.rel_path.as_str(), test.name.as_str())) {
        return Class::ExemptListed;
    }
    Class::Violation
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn kat_policy_no_unanchored_root_tests() {
    let root = workspace_root();
    let files = workspace_rs_files(&root);
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());

    let exempt: HashSet<(&str, &str)> = EXEMPTIONS.iter().copied().collect();
    assert_eq!(exempt.len(), EXEMPTIONS.len(), "duplicate EXEMPTIONS entries");

    let mut violations: Vec<String> = Vec::new();
    let mut matched = 0usize;
    let mut used_exemptions: HashSet<(String, String)> = HashSet::new();

    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        // Do not scan this gate's own sources for the policy (matcher unit tests may mention patterns).
        if rel.ends_with("architecture-tests/tests/kat_policy.rs") {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        for test in extract_tests(&rel, &src) {
            matched += 1;
            match classify(&test, &exempt) {
                Class::HasKat | Class::ExemptMarker => {}
                Class::ExemptListed => {
                    used_exemptions.insert((test.rel_path.clone(), test.name.clone()));
                }
                Class::Violation => {
                    violations.push(format!("{}::{}", test.rel_path, test.name));
                }
            }
        }
    }

    assert!(matched > 20, "matched only {matched} root-pattern tests; name scanner likely broke");

    violations.sort();
    assert!(
        violations.is_empty(),
        "KAT-first policy (RF6-22 / H5): root/tree_hash/signing_root tests must assert against \
         EXTERNAL_*/KAT_*/SPEC_* vectors, carry `// kat_exempt: reason`, or be on the shrinking-only \
         EXEMPTIONS list in crates/architecture-tests/tests/kat_policy.rs.\n\
         Offenders:\n  {}",
        violations.join("\n  ")
    );

    // Stale exemptions (file/fn removed) are allowed to linger briefly but should shrink.
    // We do not fail on unused exemptions so renames/deletes can land without a paired EXEMPTIONS
    // edit in the same PR — reviewers still remove rows when converting to KATs.
    let _ = used_exemptions;
}

/// Shrinking-only ratchet (ARCH-7l). Never raise this bound.
#[test]
#[allow(non_snake_case)]
fn kat_policy_exemptions_count_is_at_most_N() {
    assert!(
        EXEMPTIONS.len() <= 38,
        "EXEMPTIONS is shrinking-only; len={} exceeds ratchet 38",
        EXEMPTIONS.len()
    );
}

#[test]
fn kat_policy_exemptions_are_sorted_and_unique() {
    let mut seen = HashSet::new();
    let mut prev: Option<(&str, &str)> = None;
    for &(path, name) in EXEMPTIONS {
        assert!(seen.insert((path, name)), "duplicate exemption: {path}::{name}");
        if let Some((pp, pn)) = prev {
            assert!(
                (pp, pn) < (path, name),
                "EXEMPTIONS must stay sorted by (path, name); {pp}::{pn} precedes {path}::{name}"
            );
        }
        prev = Some((path, name));
    }
}

// ---------------------------------------------------------------------------
// Matcher unit tests (non-vacuous)
// ---------------------------------------------------------------------------

#[test]
fn name_pattern_matches_expected_suffixes() {
    assert!(name_matches_root_pattern("test_compute_block_root"));
    assert!(name_matches_root_pattern("test_foo_tree_hash"));
    assert!(name_matches_root_pattern("kat_bar_signing_root"));
    assert!(name_matches_root_pattern("test_genesis_validators_root"));
    assert!(!name_matches_root_pattern("test_compute_block_root_matches_external_vector"));
    assert!(!name_matches_root_pattern("test_electra_attestation_tree_hash_known_answer"));
    assert!(!name_matches_root_pattern("test_something_else"));
}

#[test]
fn kat_constant_detector_flags_prefixes() {
    assert!(body_has_kat_constant("assert_eq!(r, EXTERNAL_ELECTRA_BLOCK_ROOT_HEX);"));
    assert!(body_has_kat_constant("const KAT_EXPECTED: Root = [0; 32];"));
    assert!(body_has_kat_constant("use eth_types::SPEC_DOMAIN_BEACON_ATTESTER;"));
    // Not a prefix of an identifier:
    assert!(!body_has_kat_constant("let external_root = [0u8; 32];"));
    assert!(!body_has_kat_constant("let kat = 1;"));
    assert!(!body_has_kat_constant("const EXPECTED_ROOT: Root = [0; 32];"));
}

#[test]
fn kat_exempt_marker_detected() {
    assert!(body_has_kat_exempt_marker("// kat_exempt: logging truncation only"));
    assert!(body_has_kat_exempt_marker("#[allow(kat_exempt)]"));
    assert!(!body_has_kat_exempt_marker("assert_eq!(a, b);"));
}

#[test]
fn extract_and_classify_sample() {
    let src = r#"
#[test]
fn test_compute_block_root() {
    let a = 1;
    assert_eq!(a, a);
}

#[test]
fn test_compute_block_root_kat() {
    assert_eq!(root, EXTERNAL_ELECTRA_BLOCK_ROOT_HEX);
}

#[test]
fn test_parent_root() {
    // kat_exempt: not a container root KAT; parent-root wire field only
    assert!(true);
}

#[test]
fn test_unrelated() {
    assert!(true);
}
"#;
    let tests = extract_tests("sample.rs", src);
    let names: Vec<_> = tests.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["test_compute_block_root", "test_parent_root"],
        "only names ending in _root / tree_hash / signing_root; kat-suffixed non-match excluded"
    );
    // Wait: test_compute_block_root_kat ends with _kat, not _root — correctly excluded.
    // test_compute_block_root ends with _root — included, no KAT → violation without exemption.
    // test_parent_root ends with _root — has kat_exempt marker → ExemptMarker.

    let exempt: HashSet<(&str, &str)> = HashSet::new();
    assert_eq!(classify(&tests[0], &exempt), Class::Violation);
    assert_eq!(classify(&tests[1], &exempt), Class::ExemptMarker);

    let with_list: HashSet<(&str, &str)> =
        [("sample.rs", "test_compute_block_root")].into_iter().collect();
    assert_eq!(classify(&tests[0], &with_list), Class::ExemptListed);

    let kat_src = r#"
#[test]
fn test_block_root() {
    assert_eq!(x, KAT_BLOCK_ROOT);
}
"#;
    let kat_tests = extract_tests("k.rs", kat_src);
    assert_eq!(classify(&kat_tests[0], &exempt), Class::HasKat);
}
