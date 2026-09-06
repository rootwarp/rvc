//! Hermetic smoke test for the path-injected vector loader.
//!
//! The only input is the committed fixture tree under `tests/fixtures/`.

use std::fs;
use std::path::PathBuf;

use rvc_spec_vectors::loader::{decode_snappy, roots_yaml, VectorError, VectorRoot};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_loader_parses_electra_ssz_static_attestation_data() {
    let root = VectorRoot::new(fixtures_root()).expect("fixture tree must exist");
    let cases = root.cases("electra", "ssz_static", "AttestationData").expect("walk cases");
    assert!(cases.cases_run() > 0, "vacuous AttestationData suite");

    let mut seen = 0usize;
    for case in cases {
        let yaml = fs::read_to_string(case.path.join("roots.yaml"))
            .unwrap_or_else(|e| panic!("read roots.yaml in {}: {e}", case.path.display()));
        let roots = roots_yaml(&yaml)
            .unwrap_or_else(|e| panic!("parse roots.yaml in {}: {e}", case.path.display()));
        assert!(
            roots.root.starts_with("0x"),
            "{}: root must be 0x-prefixed, got {:?}",
            case.path.display(),
            roots.root
        );

        let compressed = fs::read(case.path.join("serialized.ssz_snappy")).unwrap_or_else(|e| {
            panic!("read serialized.ssz_snappy in {}: {e}", case.path.display())
        });
        let decoded = decode_snappy(&compressed)
            .unwrap_or_else(|e| panic!("decode snappy in {}: {e}", case.path.display()));
        assert!(!decoded.is_empty(), "{}: decompressed SSZ must not be empty", case.path.display());
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn test_malformed_snappy_is_typed_error() {
    let err = decode_snappy(&[0xff, 0x00, 0xff, 0x00]).expect_err("corrupt snappy must fail");
    assert!(matches!(err, VectorError::Snappy(_)), "expected VectorError::Snappy, got {err:?}");
}

#[test]
fn test_malformed_yaml_is_typed_error() {
    let err = roots_yaml(": this is not: valid: yaml: [").expect_err("corrupt YAML must fail");
    assert!(matches!(err, VectorError::Yaml(_)), "expected VectorError::Yaml, got {err:?}");
}

#[test]
fn test_missing_root_directory_is_typed_error_naming_path() {
    let missing = fixtures_root().join("does-not-exist-229");
    let err = VectorRoot::new(&missing).expect_err("missing root must fail");
    match &err {
        VectorError::MissingRoot { path } => {
            assert_eq!(path, &missing);
        }
        other => panic!("expected VectorError::MissingRoot, got {other:?}"),
    }
    let rendered = err.to_string();
    assert!(
        rendered.contains(&missing.display().to_string()),
        "error must name the path: {rendered}"
    );
}
