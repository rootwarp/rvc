//! Provenance + freshness tests for generated `SPEC_PROGRESSIVE_*` constants.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rvc_spec_vectors::spec_kat::{
    SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS, SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS,
    SPEC_PROGRESSIVE_CHUNKS_0, SPEC_PROGRESSIVE_CHUNK_COUNTS, SPEC_PROGRESSIVE_CHUNK_ROOTS,
};

const CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
const WIDTHS: &[u32] = &[3, 4, 13];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures_root() -> PathBuf {
    crate_dir().join("tests/fixtures")
}

fn spec_kat_path() -> PathBuf {
    crate_dir().join("src/spec_kat.rs")
}

fn gen_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gen-spec-kat"))
}

fn run_gen(vectors: &Path, out: &Path) -> Output {
    Command::new(gen_bin())
        .arg("--vectors")
        .arg(vectors)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap_or_else(|e| panic!("spawn gen-spec-kat: {e}"))
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn spec_kat_src() -> String {
    let path = spec_kat_path();
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn header_field(src: &str, key: &str) -> String {
    let prefix = format!("//! {key}:");
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest.trim().to_owned();
        }
    }
    String::new()
}

fn parse_root(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
    assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("hex digits are utf8");
        out[i] = u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"));
    }
    out
}

fn yaml_root_hex(line: &str) -> String {
    let v = line.trim().strip_prefix("root:").expect("root:").trim();
    let v = v.trim_matches('\'').trim_matches('"');
    v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v).to_ascii_lowercase()
}

fn parse_artifact_roots(body: &str) -> (BTreeMap<u32, String>, BTreeMap<(u32, String), String>) {
    let mut chunks = BTreeMap::new();
    let mut mix = BTreeMap::new();
    let mut section = "";
    let mut chunk_count = None;
    let mut width = None;
    let mut pattern = None;
    for line in body.lines() {
        let t = line.trim().trim_start_matches('-').trim();
        if t.starts_with("merkleize_progressive:") {
            section = "merkleize";
            continue;
        }
        if t.starts_with("mix_in_active_fields:") {
            section = "mix";
            continue;
        }
        match section {
            "merkleize" => {
                if let Some(v) = t.strip_prefix("chunk_count:") {
                    chunk_count = Some(v.trim().parse().expect("chunk_count"));
                } else if t.starts_with("root:") {
                    let count = chunk_count.take().expect("root without chunk_count");
                    chunks.insert(count, yaml_root_hex(t));
                }
            }
            "mix" => {
                if let Some(v) = t.strip_prefix("width:") {
                    width = Some(v.trim().parse().expect("width"));
                } else if let Some(v) = t.strip_prefix("pattern:") {
                    pattern = Some(v.trim().to_owned());
                } else if t.starts_with("root:") {
                    let w = width.take().expect("root without width");
                    let p = pattern.take().expect("root without pattern");
                    mix.insert((w, p), yaml_root_hex(t));
                }
            }
            _ => {}
        }
    }
    (chunks, mix)
}

#[test]
fn test_spec_kat_header_provenance_fields_are_nonempty() {
    let src = spec_kat_src();
    for key in
        ["provenance-source", "provenance-generated", "provenance-generator", "provenance-date"]
    {
        let value = header_field(&src, key);
        assert!(!value.is_empty(), "{key} must be non-empty");
    }
    let generated = header_field(&src, "provenance-generated");
    assert!(
        generated.contains("id="),
        "provenance-generated must name [[generated]] id: {generated}"
    );
    let sha = generated.split_once("sha256=").map(|(_, s)| s.trim()).unwrap_or("");
    assert_eq!(sha.len(), 64, "provenance-generated sha256 must be 64 hex chars: {generated}");
    assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "sha256 is not hex: {generated}");
    let inputs: Vec<&str> =
        src.lines().filter(|line| line.starts_with("//! provenance-input:")).collect();
    assert!(!inputs.is_empty(), "provenance-input must be present");
    let mut saw_progressive = false;
    for line in &inputs {
        let rest = line.strip_prefix("//! provenance-input:").expect("prefix").trim();
        let (path, sha) = rest.split_once(" sha256:").unwrap_or_else(|| {
            panic!("provenance-input must be `<path> sha256:<hex>`: {line}");
        });
        assert!(!path.trim().is_empty(), "provenance-input path is empty: {line}");
        assert_eq!(sha.len(), 64, "input sha256 must be 64 hex chars: {line}");
        assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "sha256 is not hex: {line}");
        if path.contains("vectors-generated/progressive/roots.yaml") {
            saw_progressive = true;
        }
    }
    assert!(saw_progressive, "header must hash the 3.4b progressive artifact");
}

#[test]
fn test_spec_kat_regeneration_is_byte_identical() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("spec_kat.rs");
    let first = run_gen(&fixtures_root(), &out);
    assert!(first.status.success(), "first gen failed: {}", combined(&first));
    let a = fs::read(&out).expect("read first");
    let second = run_gen(&fixtures_root(), &out);
    assert!(second.status.success(), "second gen failed: {}", combined(&second));
    let b = fs::read(&out).expect("read second");
    assert_eq!(a, b, "make spec-kat twice must be byte-identical");
}

#[test]
fn test_spec_kat_checked_in_regeneration_is_noop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("spec_kat.rs");
    let checked = spec_kat_path();
    fs::copy(&checked, &out).unwrap_or_else(|e| panic!("copy {}: {e}", checked.display()));
    let before = fs::read(&out).expect("read copy");
    let result = run_gen(&fixtures_root(), &out);
    assert!(result.status.success(), "regen failed: {}", combined(&result));
    let after = fs::read(&out).expect("read regenerated");
    assert_eq!(
        before, after,
        "regeneration must be a no-op (checked-in spec_kat.rs is stale); run `make spec-kat`"
    );
}

#[test]
fn test_spec_kat_covers_progressive_chunk_counts_and_widths() {
    assert_eq!(SPEC_PROGRESSIVE_CHUNK_COUNTS, CHUNK_COUNTS);
    assert_eq!(SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS, WIDTHS);
    let counts: Vec<u32> = SPEC_PROGRESSIVE_CHUNK_ROOTS.iter().map(|(c, _)| *c).collect();
    assert_eq!(
        counts, CHUNK_COUNTS,
        "SPEC_PROGRESSIVE_CHUNK_ROOTS must cover 3.4a's twelve counts"
    );
    for width in WIDTHS {
        assert!(
            SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                .iter()
                .any(|(w, pattern, _)| w == width && *pattern == "all_ones"),
            "missing width {width} all_ones"
        );
        assert!(
            SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                .iter()
                .any(|(w, pattern, _)| w == width && *pattern == "sparse_bit0_clear"),
            "missing width {width} sparse_bit0_clear"
        );
    }
}

#[test]
fn test_spec_kat_constants_parse_as_32_byte_hex() {
    assert_eq!(parse_root(SPEC_PROGRESSIVE_CHUNKS_0), [0u8; 32]);
    for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
        let _root: [u8; 32] = parse_root(hex);
        assert_eq!(hex.len(), 64, "chunk_count {count}");
    }
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        let _root: [u8; 32] = parse_root(hex);
        assert_eq!(hex.len(), 64, "width {width} {pattern}");
    }
}

#[test]
fn test_spec_kat_hexes_match_artifact_roots() {
    let path = crate_dir().join("vectors-generated/progressive/roots.yaml");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (chunks, mix) = parse_artifact_roots(&body);
    for (count, hex) in SPEC_PROGRESSIVE_CHUNK_ROOTS {
        let expected =
            chunks.get(count).unwrap_or_else(|| panic!("artifact missing chunk_count {count}"));
        assert_eq!(
            *hex,
            expected.as_str(),
            "SPEC_PROGRESSIVE_CHUNKS_{count} must equal roots.yaml root"
        );
    }
    for (width, pattern, hex) in SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS {
        let expected = mix
            .get(&(*width, (*pattern).to_owned()))
            .unwrap_or_else(|| panic!("artifact missing width {width} pattern {pattern}"));
        assert_eq!(
            *hex,
            expected.as_str(),
            "SPEC_PROGRESSIVE_ACTIVE_FIELDS_{width}_{pattern} must equal roots.yaml root"
        );
    }
}

#[test]
fn test_gen_spec_kat_source_has_no_env_var() {
    let path = crate_dir().join("src/bin/gen_spec_kat.rs");
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(!src.contains("env::var"), "{} must not read process environment", path.display());
}

#[test]
fn test_gen_spec_kat_rejects_missing_args() {
    let output = Command::new(gen_bin()).output().expect("spawn");
    assert!(!output.status.success(), "missing argv must fail: {}", combined(&output));
    let log = combined(&output);
    assert!(log.contains("--vectors"), "{log}");
    assert!(log.contains("--out"), "{log}");
}

#[test]
fn test_gen_spec_kat_rejects_missing_vectors_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join("no-such-vectors");
    let out = tmp.path().join("spec_kat.rs");
    let result = run_gen(&missing, &out);
    assert!(!result.status.success(), "missing --vectors must fail: {}", combined(&result));
    let log = combined(&result);
    assert!(log.contains(&missing.display().to_string()), "error must name the path: {log}");
}

#[cfg(unix)]
#[test]
fn test_gen_spec_kat_refuses_symlink_inputs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vectors = tmp.path().join("vectors");
    let case = vectors.join("tests/minimal/electra/ssz_static/AttestationData/ssz_random");
    fs::create_dir_all(&case).expect("mkdir case");
    let outside = tmp.path().join("outside.yaml");
    fs::write(&outside, "root: '0x00'\n").expect("write outside");
    std::os::unix::fs::symlink(&outside, case.join("roots.yaml")).expect("symlink");
    let out = tmp.path().join("spec_kat.rs");
    let result = run_gen(&vectors, &out);
    assert!(!result.status.success(), "symlink input must fail: {}", combined(&result));
    let log = combined(&result);
    assert!(log.contains("symlink"), "error must name symlink: {log}");
}
