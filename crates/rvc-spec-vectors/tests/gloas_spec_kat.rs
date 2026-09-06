//! Gloas output target for `gen-spec-kat` (issue 5.1b).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn gloas_fixtures() -> PathBuf {
    crate_dir().join("tests/gloas_fixtures")
}

fn p3_fixtures() -> PathBuf {
    crate_dir().join("tests/fixtures")
}

fn gen_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gen-spec-kat"))
}

fn run_gen(vectors: &Path, out: &Path, gloas_vectors: &Path, gloas_out: &Path) -> Output {
    Command::new(gen_bin())
        .arg("--vectors")
        .arg(vectors)
        .arg("--out")
        .arg(out)
        .arg("--gloas-vectors")
        .arg(gloas_vectors)
        .arg("--gloas-out")
        .arg(gloas_out)
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

fn header_field(src: &str, key: &str) -> String {
    let prefix = format!("//! {key}:");
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest.trim().to_owned();
        }
    }
    String::new()
}

#[test]
fn test_gloas_spec_kat_regeneration_is_byte_identical() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let gloas_out = tmp.path().join("gloas.rs");
    let first = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(first.status.success(), "first gen failed: {}", combined(&first));
    let a = fs::read(&gloas_out).expect("read first");
    let second = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(second.status.success(), "second gen failed: {}", combined(&second));
    let b = fs::read(&gloas_out).expect("read second");
    assert_eq!(a, b, "gloas spec_kat twice must be byte-identical");
}

#[test]
fn test_gloas_spec_kat_header_provenance_fields_are_nonempty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let gloas_out = tmp.path().join("gloas.rs");
    let result = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(result.status.success(), "gen failed: {}", combined(&result));
    let src = fs::read_to_string(&gloas_out).expect("read gloas");
    for key in
        ["provenance-source", "provenance-generated", "provenance-generator", "provenance-date"]
    {
        let value = header_field(&src, key);
        assert!(!value.is_empty(), "{key} must be non-empty");
    }
    assert!(src.contains("pub mod minimal"), "missing pub mod minimal");
    assert!(src.contains("pub mod mainnet"), "missing pub mod mainnet");
    assert!(src.contains("pub use minimal::*;"), "missing default pub use minimal");
    assert!(src.contains("SPEC_GLOAS_SYNC_AGGREGATE_ROOT"), "missing SyncAggregate root");
    assert!(src.contains("SPEC_PROGRESSIVE_ACTIVE_FIELDS_5_ALL_ONES"), "missing width 5");
}

#[test]
fn test_gloas_spec_kat_sync_aggregate_roots_differ_in_generated_source() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let gloas_out = tmp.path().join("gloas.rs");
    let result = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(result.status.success(), "gen failed: {}", combined(&result));
    let src = fs::read_to_string(&gloas_out).expect("read gloas");
    let min_idx = src.find("pub mod minimal").expect("minimal");
    let main_idx = src.find("pub mod mainnet").expect("mainnet");
    let min_mod = &src[min_idx..main_idx];
    let main_mod = &src[main_idx..];
    fn module_root(mod_src: &str) -> Option<&str> {
        let needle = "pub const SPEC_GLOAS_SYNC_AGGREGATE_ROOT";
        let at = mod_src.find(needle)?;
        for line in mod_src[at..].lines().take(4) {
            let t = line.trim().trim_end_matches(';').trim_matches('"');
            if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(t);
            }
        }
        None
    }
    let min_root = module_root(min_mod).expect("minimal SyncAggregate root hex");
    let main_root = module_root(main_mod).expect("mainnet SyncAggregate root hex");
    assert_ne!(min_root, main_root, "fixture SyncAggregate roots must differ");
}

#[test]
fn test_gloas_spec_kat_checked_in_regeneration_is_noop_when_archives_present() {
    let tag = {
        let lock = fs::read_to_string(crate_dir().join("vectors.lock")).expect("vectors.lock");
        lock.lines()
            .find_map(|l| l.strip_prefix("SPEC_TAG=").map(str::trim))
            .expect("SPEC_TAG")
            .to_owned()
    };
    let archives = crate_dir().join("vectors").join(&tag);
    let minimal = archives.join("minimal.tar.gz");
    let mainnet = archives.join("mainnet.tar.gz");
    if !minimal.is_file() || !mainnet.is_file() {
        eprintln!("skipping: gloas archives missing at {}", archives.display());
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let gloas_out = tmp.path().join("gloas.rs");
    let checked = crate_dir().join("../rvc-gloas/src/spec_kat.rs");
    fs::copy(&checked, &gloas_out).unwrap_or_else(|e| panic!("copy {}: {e}", checked.display()));
    let before = fs::read(&gloas_out).expect("read copy");
    let result = run_gen(&p3_fixtures(), &out, &archives, &gloas_out);
    assert!(result.status.success(), "regen failed: {}", combined(&result));
    let after = fs::read(&gloas_out).expect("read regenerated");
    assert_eq!(
        before, after,
        "regeneration must be a no-op (checked-in rvc-gloas spec_kat.rs is stale); run `make spec-kat`"
    );
}

#[test]
fn test_gloas_spec_kat_refuses_to_drop_previously_emitted_root_names() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let gloas_out = tmp.path().join("gloas.rs");
    let first = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(first.status.success(), "first gen failed: {}", combined(&first));
    let mut src = fs::read_to_string(&gloas_out).expect("read gloas");
    src.push_str("\npub const SPEC_GLOAS_MUST_NOT_DISAPPEAR_ROOT: &str =\n    \"0000000000000000000000000000000000000000000000000000000000000000\";\n");
    fs::write(&gloas_out, src).expect("inject extra root name");
    let second = run_gen(&p3_fixtures(), &out, &gloas_fixtures(), &gloas_out);
    assert!(!second.status.success(), "dropping a previously emitted name must fail");
    let log = combined(&second);
    assert!(
        log.contains("SPEC_GLOAS_MUST_NOT_DISAPPEAR_ROOT"),
        "error must name the dropped constant: {log}"
    );
}

#[test]
fn test_gloas_vectors_requires_gloas_out() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("p3.rs");
    let output = Command::new(gen_bin())
        .arg("--vectors")
        .arg(p3_fixtures())
        .arg("--out")
        .arg(&out)
        .arg("--gloas-vectors")
        .arg(gloas_fixtures())
        .output()
        .expect("spawn");
    assert!(!output.status.success(), "gloas-vectors without gloas-out must fail");
    let log = combined(&output);
    assert!(log.contains("--gloas-out"), "{log}");
}
