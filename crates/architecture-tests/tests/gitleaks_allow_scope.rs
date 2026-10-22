//! The source-tree gitleaks allow for the running-guide sample is one path plus
//! one exact secret. A line target is not set, so a secret beside `verify=false`
//! stays visible.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_gitleaks_allow_is_path_scoped_and_false_lines_stay_scanned() {
    let root = workspace_root();
    let config = std::fs::read_to_string(root.join(".gitleaks.toml")).expect("gitleaks config");
    // Case-fold: viper matches these keys either way. This string scan does
    // not load the allowlists useDefault merges in from the default rules.
    let folded = config.to_ascii_lowercase();
    assert!(
        !folded.contains("regextarget"),
        "the source-tree config must leave the regex target on the secret"
    );
    assert!(
        !folded.contains("gitleaks:allow"),
        "the config prose must not embed the inline allow token"
    );
    assert!(
        !folded.contains("condition = \"or\""),
        "OR allows the whole file when the path matches"
    );
    assert_eq!(
        folded.lines().filter(|line| line.trim() == "[allowlist]").count(),
        1,
        "a second allowlist table is merged by gitleaks"
    );
    assert!(
        folded.lines().all(|line| line.trim() != "[[allowlists]]"),
        "a top-level allowlists array is not a second baseline"
    );
    assert!(
        folded.lines().all(|line| line.trim() != "[rules.allowlist]"),
        "the singular rule allowlist overrides the per-rule array"
    );
    assert!(config.contains("condition = \"AND\""));
    assert!(config.contains("docs/running-guide"));
    assert!(config.contains("^0x97f1d3a731\\.\\.\\.db22c6bb$"));

    let gitleaks = std::env::var("GITLEAKS_BIN").unwrap_or_else(|_| "gitleaks".to_string());
    let present = Command::new(&gitleaks).arg("version").output().is_ok();
    if !present {
        assert!(
            std::env::var_os("REQUIRE_GITLEAKS").is_none(),
            "REQUIRE_GITLEAKS is set but {gitleaks} is not runnable"
        );
        return;
    }

    let script = root.join("scripts/gitleaks_verify_false_canary.sh");
    let output =
        Command::new(&script).env("GITLEAKS_BIN", &gitleaks).output().expect("run gitleaks canary");
    assert!(
        output.status.success(),
        "canary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
