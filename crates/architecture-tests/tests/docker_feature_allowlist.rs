//! #602: the image build accepts only an allow-list of cargo features.
//!
//! `RVC_FEATURES` / `SIGNER_FEATURES` used to be passed straight to
//! `cargo build --features`. A build-arg of `test-utils` (or `rvc/test-utils`)
//! would compile the test helpers into the shipped binary. The builder stage
//! must run `scripts/docker-cargo-features.sh`, which rejects anything outside
//! `gcp-trace`/`gcp-secret` (validator) and `dvt` (signer).

use std::path::Path;
use std::process::Command;

use rvc_architecture_tests::workspace_root;

fn script() -> std::path::PathBuf {
    workspace_root().join("scripts/docker-cargo-features.sh")
}

fn run_script(target: &str, features: &str) -> std::process::Output {
    Command::new("sh")
        .arg(script())
        .arg(target)
        .arg(features)
        .output()
        .unwrap_or_else(|e| panic!("run docker-cargo-features.sh: {e}"))
}

fn assert_ok(target: &str, features: &str, expect: &str) {
    let out = run_script(target, features);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{target} {features:?} should be accepted, stderr={stderr}");
    assert_eq!(stdout.trim(), expect, "stdout for {target} {features:?}");
}

fn assert_reject(target: &str, features: &str) {
    let out = run_script(target, features);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "{target} {features:?} must be rejected, stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("not allow-listed") || stderr.contains("unknown image target"),
        "rejection of {target} {features:?} should name the allow-list, stderr={stderr}"
    );
}

#[test]
fn dockerfile_delegates_feature_args_to_the_allowlist_script() {
    let path = workspace_root().join("Dockerfile");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read Dockerfile: {e}"));
    assert!(
        text.contains("scripts/docker-cargo-features.sh rvc"),
        "Dockerfile must filter RVC_FEATURES through scripts/docker-cargo-features.sh"
    );
    assert!(
        text.contains("scripts/docker-cargo-features.sh signer"),
        "Dockerfile must filter SIGNER_FEATURES through scripts/docker-cargo-features.sh"
    );
    for banned in [
        "--features \"$RVC_FEATURES\"",
        "--features \"$SIGNER_FEATURES\"",
        "--features ${RVC_FEATURES",
        "--features ${SIGNER_FEATURES",
        "--features \"$RVC_FEATURES",
        "--features \"$SIGNER_FEATURES",
    ] {
        assert!(!text.contains(banned), "Dockerfile still passes build-args through: {banned}");
    }
    let feature_flags: Vec<_> =
        text.lines().filter(|l| l.contains("--features")).map(str::trim).collect();
    assert_eq!(
        feature_flags.len(),
        2,
        "expected exactly two --features uses (rvc and signer), found {feature_flags:?}"
    );
    assert!(
        feature_flags.iter().any(|l| l.contains("\"$rvc_feats\"")),
        "rvc build must use the script output, found {feature_flags:?}"
    );
    assert!(
        feature_flags.iter().any(|l| l.contains("\"$signer_feats\"")),
        "signer build must use the script output, found {feature_flags:?}"
    );
    assert!(Path::new(&script()).is_file(), "scripts/docker-cargo-features.sh is missing");
    let script_text =
        std::fs::read_to_string(script()).unwrap_or_else(|e| panic!("read script: {e}"));
    assert!(
        script_text.lines().any(|l| l.trim() == "set -f"),
        "docker-cargo-features.sh must disable pathname expansion before splitting FEATURES"
    );
}

#[test]
fn allowlist_accepts_production_features_and_rejects_test_utils() {
    assert_ok("rvc", "", "");
    assert_ok("rvc", "gcp-trace", "gcp-trace");
    assert_ok("rvc", "gcp-secret", "gcp-secret");
    assert_ok("rvc", "gcp-trace,gcp-secret", "gcp-trace gcp-secret");
    assert_ok("rvc", "gcp-secret gcp-trace", "gcp-secret gcp-trace");
    assert_ok("rvc", "gcp-trace,gcp-trace", "gcp-trace");
    assert_ok("signer", "", "");
    assert_ok("signer", "dvt", "dvt");

    for (target, features) in [
        ("rvc", "test-utils"),
        ("rvc", "gcp-trace,test-utils"),
        ("rvc", "rvc/test-utils"),
        ("rvc", "crypto/test-utils"),
        ("rvc", "dvt"),
        ("signer", "test-utils"),
        ("signer", "dvt test-utils"),
        ("signer", "signer-server/test-utils"),
        ("signer", "gcp-trace"),
        ("other", "dvt"),
    ] {
        assert_reject(target, features);
    }
}
