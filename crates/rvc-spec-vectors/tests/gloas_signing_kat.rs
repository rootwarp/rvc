//! Provenance + copy tests for generated `gloas_signing_kat.rs` (issue 5.13a).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rvc_spec_vectors::gloas_signing_kat::{
    GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS, KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT,
    KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT, KAT_GLOAS_BLOCK_SIGNING_ROOT,
    KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT,
};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures_root() -> PathBuf {
    crate_dir().join("tests/fixtures")
}

fn signing_kat_path() -> PathBuf {
    crate_dir().join("src/gloas_signing_kat.rs")
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

fn signing_kat_src() -> String {
    let path = signing_kat_path();
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
    assert_eq!(hex.len(), 64, "KAT hex must be 64 chars, got {} ({hex:?})", hex.len());
    assert!(!hex.starts_with("0x"), "KAT hex follows EXTERNAL_* style (no 0x prefix)");
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

fn parse_signing_roots(body: &str) -> (std::collections::BTreeMap<String, String>, Option<String>) {
    let mut signing = std::collections::BTreeMap::new();
    let mut flip = None;
    let mut name = None;
    for line in body.lines() {
        let t = line.trim().trim_start_matches('-').trim();
        if let Some(v) = t.strip_prefix("name:") {
            name = Some(v.trim().to_owned());
        } else if t.starts_with("argv_flip_signing_root:") {
            flip = Some(yaml_root_hex(&t.replacen("argv_flip_signing_root:", "root:", 1)));
        } else if t.starts_with("signing_root:") {
            let n = name.clone().expect("signing_root without name");
            signing.insert(n, yaml_root_hex(&t.replacen("signing_root:", "root:", 1)));
        }
    }
    (signing, flip)
}

fn lock_signing_argv() -> String {
    let lock = fs::read_to_string(crate_dir().join("vectors.lock")).expect("vectors.lock");
    let mut in_block = false;
    let mut id = String::new();
    let mut argv = String::new();
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[generated]]" {
            if id == "gloas-signing-roots" && !argv.is_empty() {
                return argv;
            }
            in_block = true;
            id.clear();
            argv.clear();
            continue;
        }
        if !in_block {
            continue;
        }
        if line.is_empty() || line.starts_with("[[") || line.starts_with("archive ") {
            if id == "gloas-signing-roots" && !argv.is_empty() {
                return argv;
            }
            in_block = false;
            continue;
        }
        if let Some(v) = line.strip_prefix("id=") {
            id = v.trim().to_owned();
        } else if let Some(v) = line.strip_prefix("argv=") {
            argv = v.trim().to_owned();
        }
    }
    if id == "gloas-signing-roots" {
        return argv;
    }
    String::new()
}

#[test]
fn test_gloas_signing_kat_header_provenance_fields_are_nonempty() {
    let src = signing_kat_src();
    for key in [
        "provenance-source",
        "provenance-pyspec-revision",
        "provenance-eth-ssz-specs",
        "provenance-python",
        "provenance-argv",
        "provenance-generated",
        "provenance-date",
        "provenance-input",
    ] {
        let value = header_field(&src, key);
        assert!(!value.is_empty(), "{key} must be non-empty");
    }
    let argv = header_field(&src, "provenance-argv");
    assert!(argv.contains("--fork-version"), "argv must record fork version: {argv}");
    assert!(argv.contains("--genesis-validators-root"), "argv must record GVR: {argv}");
    assert!(!argv.contains("gloas_fork_version"), "argv must not name an rs-vc symbol: {argv}");
    assert_eq!(argv, lock_signing_argv(), "header argv must match vectors.lock");
    let python = header_field(&src, "provenance-python");
    assert!(python.starts_with("3."), "python patch version: {python}");
    let ssz = header_field(&src, "provenance-eth-ssz-specs");
    assert!(ssz.contains("0.1.0"), "eth-ssz-specs version: {ssz}");
    let input = header_field(&src, "provenance-input");
    assert!(
        input.contains("vectors-generated/gloas-signing-roots/signing_roots.yaml"),
        "input digest must name the island artifact: {input}"
    );
    assert!(
        !src.to_ascii_lowercase().contains("remerkleable"),
        "Gloas signing provenance must not be remerkleable-derived (D15)"
    );
}

#[test]
fn test_gloas_signing_kat_constants_match_pyspec_artifact() {
    let path = crate_dir().join("vectors-generated/gloas-signing-roots/signing_roots.yaml");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (signing, flip) = parse_signing_roots(&body);
    assert_eq!(
        KAT_GLOAS_BLOCK_SIGNING_ROOT,
        signing.get("BeaconBlock").expect("BeaconBlock").as_str()
    );
    assert_eq!(
        KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT,
        signing.get("AggregateAndProof").expect("AggregateAndProof").as_str()
    );
    assert_eq!(
        KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT,
        signing.get("ExecutionPayloadEnvelope").expect("ExecutionPayloadEnvelope").as_str()
    );
    assert_eq!(
        KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT,
        signing.get("AttestationData").expect("AttestationData").as_str()
    );
    assert_eq!(
        GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS,
        flip.expect("argv_flip_signing_root").as_str()
    );
    assert!(body.contains("index: 1"), "AttestationData row must have index = 1");
    for hex in [
        KAT_GLOAS_BLOCK_SIGNING_ROOT,
        KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT,
        KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT,
        KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT,
        GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS,
    ] {
        let _root: [u8; 32] = parse_root(hex);
    }
}

#[test]
fn test_gloas_signing_recipe_argv_fork_version_changes_constant() {
    assert_ne!(
        KAT_GLOAS_BLOCK_SIGNING_ROOT, GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS,
        "changing argv --fork-version must yield a different signing root"
    );
}

#[test]
fn test_gloas_signing_kat_regeneration_is_byte_identical() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("spec_kat.rs");
    let kat = tmp.path().join("gloas_signing_kat.rs");
    let first = run_gen(&fixtures_root(), &out);
    assert!(first.status.success(), "first gen failed: {}", combined(&first));
    let a = fs::read(&kat).expect("read first gloas_signing_kat.rs");
    let second = run_gen(&fixtures_root(), &out);
    assert!(second.status.success(), "second gen failed: {}", combined(&second));
    let b = fs::read(&kat).expect("read second gloas_signing_kat.rs");
    assert_eq!(a, b, "make spec-kat twice must emit byte-identical gloas_signing_kat.rs");
}

#[test]
fn test_gloas_signing_kat_checked_in_regeneration_is_noop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("spec_kat.rs");
    let kat = tmp.path().join("gloas_signing_kat.rs");
    let checked = signing_kat_path();
    fs::copy(&checked, &kat).unwrap_or_else(|e| panic!("copy {}: {e}", checked.display()));
    let before = fs::read(&kat).expect("read copy");
    let result = run_gen(&fixtures_root(), &out);
    assert!(result.status.success(), "regen failed: {}", combined(&result));
    let after = fs::read(&kat).expect("read regenerated");
    assert_eq!(
        before, after,
        "regeneration must be a no-op (checked-in gloas_signing_kat.rs is stale); run `make spec-kat`"
    );
}

#[test]
fn test_gen_spec_kat_source_has_no_compute_oracle_fn() {
    let path = crate_dir().join("src/bin/gen_spec_kat.rs");
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    for name in ["compute_domain", "compute_fork_data_root", "compute_signing_root"] {
        let needle = format!("fn {name}");
        assert!(
            !src.contains(&needle),
            "3.6 function-body rule: {needle} must not appear in {}",
            path.display()
        );
    }
}

#[test]
fn test_gloas_signing_lock_argv_is_not_an_rsvc_symbol() {
    let argv = lock_signing_argv();
    assert!(!argv.is_empty(), "gloas-signing-roots argv missing from vectors.lock");
    assert!(argv.contains("--fork-version 0x"), "{argv}");
    assert!(argv.contains("--genesis-validators-root 0x"), "{argv}");
    assert!(!argv.contains("gloas_fork_version"), "{argv}");
}
