//! Drive `scripts/fetch_spec_vectors.sh` over local `file://` fixtures.
//!
//! No network: every archive URL is a temp-dir tarball.

mod support;

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const SPEC_TAG: &str = "v-test";
const SSZ_SPECS_TAG: &str = "ssz-test";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn fetch_script() -> PathBuf {
    workspace_root().join("scripts/fetch_spec_vectors.sh")
}

fn sha256_hex(path: &Path) -> String {
    let try_cmd = |bin: &str, args: &[&str]| -> Option<String> {
        let out = Command::new(bin).args(args).arg(path).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8(out.stdout).ok()?;
        Some(stdout.split_whitespace().next()?.to_ascii_lowercase())
    };
    try_cmd("sha256sum", &[])
        .or_else(|| try_cmd("shasum", &["-a", "256"]))
        .unwrap_or_else(|| panic!("need sha256sum or shasum to hash {}", path.display()))
}

fn file_url(path: &Path) -> String {
    let abs =
        fs::canonicalize(path).unwrap_or_else(|e| panic!("canonicalize {}: {e}", path.display()));
    format!("file://{}", abs.display())
}

fn make_tar_gz(staging: &Path, archive: &Path, entries: &[(&str, &[u8])]) {
    let tree = staging.join("tree");
    if tree.exists() {
        fs::remove_dir_all(&tree).expect("reset tar staging");
    }
    for (rel, bytes) in entries {
        let path = tree.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir tar entry");
        }
        fs::write(&path, bytes).expect("write tar entry");
    }
    let mut cmd = Command::new("tar");
    cmd.current_dir(&tree).arg("-czf").arg(archive);
    for (rel, _) in entries {
        cmd.arg(rel);
    }
    let status = cmd.status().expect("spawn tar");
    assert!(status.success(), "tar -czf {} failed", archive.display());
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

struct Fixture {
    _tmp: TempDir,
    lock: PathBuf,
    dest: PathBuf,
    minimal_tar: PathBuf,
    ssz_tar: PathBuf,
    minimal_sha: String,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        let fixtures = root.join("fixtures");
        let staging = root.join("staging");
        fs::create_dir_all(&fixtures).expect("mkdir fixtures");
        fs::create_dir_all(&staging).expect("mkdir staging");

        let minimal_tar = fixtures.join("minimal.tar.gz");
        make_tar_gz(
            &staging.join("minimal"),
            &minimal_tar,
            &[("tests/minimal/marker.txt", b"minimal-vector\n")],
        );
        let ssz_tar = fixtures.join("ssz.tar.gz");
        make_tar_gz(&staging.join("ssz"), &ssz_tar, &[("progressive/marker.txt", b"ssz-vector\n")]);

        let minimal_sha = sha256_hex(&minimal_tar);
        let ssz_sha = sha256_hex(&ssz_tar);
        let lock = root.join("vectors.lock");
        write_lock(
            &lock,
            Some(SPEC_TAG),
            Some(SSZ_SPECS_TAG),
            &[
                ("minimal", SPEC_TAG, &file_url(&minimal_tar), &minimal_sha),
                ("ssz", SSZ_SPECS_TAG, &file_url(&ssz_tar), &ssz_sha),
            ],
        );
        let dest = root.join("vectors");
        Self { _tmp: tmp, lock, dest, minimal_tar, ssz_tar, minimal_sha }
    }

    fn run(&self, extra_env: &[(&str, &str)]) -> Output {
        run_fetch(&self.lock, &self.dest, extra_env)
    }
}

fn write_lock(
    path: &Path,
    spec_tag: Option<&str>,
    ssz_tag: Option<&str>,
    archives: &[(&str, &str, &str, &str)],
) {
    let mut body = String::new();
    if let Some(tag) = spec_tag {
        body.push_str(&format!("SPEC_TAG={tag}\n"));
    }
    if let Some(tag) = ssz_tag {
        body.push_str(&format!("SSZ_SPECS_TAG={tag}\n"));
    }
    body.push('\n');
    for (name, tag, url, sha) in archives {
        body.push_str(&format!("archive {name} {tag} {url} {sha}\n"));
    }
    fs::write(path, body).expect("write vectors.lock");
}

fn run_fetch(lock: &Path, dest: &Path, extra_env: &[(&str, &str)]) -> Output {
    let script = fetch_script();
    assert!(script.is_file(), "missing fetch script at {}", script.display());
    let mut cmd = Command::new("bash");
    cmd.arg(&script).env("VECTORS_LOCK", lock).env("VECTORS_DIR", dest).env("PRESET", "minimal");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.output().unwrap_or_else(|e| panic!("spawn {}: {e}", script.display()))
}

fn assert_extracted(dest: &Path) {
    let minimal = dest.join(SPEC_TAG).join("tests/minimal/marker.txt");
    let ssz = dest.join(SSZ_SPECS_TAG).join("progressive/marker.txt");
    assert_eq!(
        fs::read_to_string(&minimal).unwrap_or_default(),
        "minimal-vector\n",
        "missing {}",
        minimal.display()
    );
    assert_eq!(
        fs::read_to_string(&ssz).unwrap_or_default(),
        "ssz-vector\n",
        "missing {}",
        ssz.display()
    );
}

#[test]
fn test_fetch_script_cold_cache_downloads_verifies_extracts() {
    let fx = Fixture::new();
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(output.status.success(), "cold fetch failed: {log}");
    assert!(log.contains("downloading:"), "expected a download on cold cache: {log}");
    assert_extracted(&fx.dest);
}

fn truncate_file(path: &Path) -> String {
    let len = fs::metadata(path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display())).len();
    assert!(len > 1, "{} too small to truncate", path.display());
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()))
        .set_len(len - 1)
        .unwrap_or_else(|e| panic!("truncate {}: {e}", path.display()));
    sha256_hex(path)
}

#[test]
fn test_fetch_script_corrupt_archive_fails_closed() {
    let fx = Fixture::new();
    let actual = truncate_file(&fx.minimal_tar);
    let tag_dir = fx.dest.join(SPEC_TAG);
    fs::create_dir_all(&tag_dir).expect("mkdir cache");
    let cached = tag_dir.join("minimal.tar.gz");
    fs::copy(&fx.minimal_tar, &cached).expect("seed truncated cache");

    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "corrupt archive must fail: {log}");
    assert!(log.contains("minimal.tar.gz"), "error must name the file: {log}");
    assert!(log.contains(&fx.minimal_sha), "error must name expected digest: {log}");
    assert!(log.contains(&actual), "error must name actual digest: {log}");
    assert!(
        log.contains("re-downloading once") || log.contains("cache mismatch"),
        "mismatch must re-download once: {log}"
    );
    assert!(
        !tag_dir.join("tests").exists(),
        "corrupt archive must not extract, found {}",
        tag_dir.join("tests").display()
    );
    assert!(
        !fx.dest.join(SSZ_SPECS_TAG).join("progressive").exists(),
        "corrupt archive must extract nothing"
    );
}

#[test]
fn test_fetch_script_corrupt_cached_archive_redownloads_once() {
    let fx = Fixture::new();
    let tag_dir = fx.dest.join(SPEC_TAG);
    fs::create_dir_all(&tag_dir).expect("mkdir cache");
    let cached = tag_dir.join("minimal.tar.gz");
    fs::copy(&fx.minimal_tar, &cached).expect("seed cache");
    let actual = truncate_file(&cached);
    assert_ne!(actual, fx.minimal_sha, "truncate must change digest");

    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(output.status.success(), "good source must recover after one re-download: {log}");
    assert!(log.contains("cache mismatch") || log.contains("re-downloading once"), "{log}");
    assert!(log.contains("downloading:"), "must re-download after mismatch: {log}");
    assert!(log.contains(&fx.minimal_sha), "error must name expected digest: {log}");
    assert!(log.contains(&actual), "error must name cached digest: {log}");
    assert_extracted(&fx.dest);
}

#[test]
fn test_fetch_script_missing_spec_tag_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let lock = tmp.path().join("vectors.lock");
    write_lock(
        &lock,
        None,
        Some(SSZ_SPECS_TAG),
        &[("minimal", SPEC_TAG, "file:///dev/null", "00")],
    );
    let dest = tmp.path().join("vectors");
    let output = run_fetch(&lock, &dest, &[]);
    let log = combined(&output);
    assert!(!output.status.success(), "missing SPEC_TAG must fail: {log}");
    assert!(log.contains("SPEC_TAG"), "error must name SPEC_TAG: {log}");
    assert!(log.contains("vectors.lock"), "error must name the lock file: {log}");
    assert!(!dest.exists() || fs::read_dir(&dest).map(|i| i.count()).unwrap_or(0) == 0);
}

#[test]
fn test_fetch_script_unknown_spec_tag_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let lock = tmp.path().join("vectors.lock");
    write_lock(
        &lock,
        Some("v-unknown"),
        Some(SSZ_SPECS_TAG),
        &[("minimal", SPEC_TAG, "file:///dev/null", "00")],
    );
    let dest = tmp.path().join("vectors");
    let output = run_fetch(&lock, &dest, &[]);
    let log = combined(&output);
    assert!(!output.status.success(), "unknown SPEC_TAG must fail: {log}");
    assert!(log.contains("v-unknown"), "error must name the unknown tag: {log}");
    assert!(log.contains("vectors.lock"), "error must name the lock file: {log}");
    assert!(!dest.join("v-unknown").exists(), "unknown tag must not extract");
}

#[test]
fn test_fetch_script_second_invocation_skips_download() {
    let fx = Fixture::new();
    let first = fx.run(&[]);
    let first_log = combined(&first);
    assert!(first.status.success(), "first fetch failed: {first_log}");
    assert_extracted(&fx.dest);

    fs::remove_file(&fx.minimal_tar)
        .expect("remove minimal fixture so a re-download cannot succeed");
    fs::remove_file(&fx.ssz_tar).expect("remove ssz fixture so a re-download cannot succeed");

    let second = fx.run(&[]);
    let second_log = combined(&second);
    assert!(second.status.success(), "warm fetch failed (must not re-download): {second_log}");
    assert!(!second_log.contains("downloading:"), "second invocation re-downloaded: {second_log}");
    assert!(
        second_log.contains("cache hit:") || second_log.contains("skip download"),
        "warm path must report a cache hit: {second_log}"
    );
    assert!(
        second_log.contains("extracting:"),
        "warm path must re-extract from the verified tarball: {second_log}"
    );
    assert!(
        !second_log.contains("already extracted:"),
        "stamp skip would persist a restored tree: {second_log}"
    );
    assert_extracted(&fx.dest);
}

#[test]
fn test_fetch_script_reextracts_over_poisoned_tree() {
    let fx = Fixture::new();
    let first = fx.run(&[]);
    let first_log = combined(&first);
    assert!(first.status.success(), "first fetch failed: {first_log}");
    assert_extracted(&fx.dest);

    let marker = fx.dest.join(SPEC_TAG).join("tests/minimal/marker.txt");
    let extra = fx.dest.join(SPEC_TAG).join("tests/minimal/pwned.txt");
    let stamp = fx.dest.join(SPEC_TAG).join(".extracted.minimal.tar.gz");
    fs::write(&marker, b"poisoned\n").expect("poison marker");
    fs::write(&extra, b"extra\n").expect("write extra file");
    fs::write(&stamp, format!("{}\n", fx.minimal_sha)).expect("write extract stamp");

    fs::remove_file(&fx.minimal_tar).expect("remove minimal fixture");
    fs::remove_file(&fx.ssz_tar).expect("remove ssz fixture");

    let second = fx.run(&[]);
    let second_log = combined(&second);
    assert!(second.status.success(), "re-extract failed: {second_log}");
    assert!(!second_log.contains("downloading:"), "must not re-download: {second_log}");
    assert!(
        second_log.contains("extracting:"),
        "must extract from the verified tarball: {second_log}"
    );
    assert_extracted(&fx.dest);
    assert!(!extra.exists(), "extra file from a restored tree must not survive extract");
}

fn valid_zero_sha() -> String {
    "0".repeat(64)
}

fn non_hex_sha() -> String {
    "g".repeat(64)
}

fn write_lock_raw(path: &Path, body: &str) {
    fs::write(path, body).expect("write vectors.lock");
}

fn fixture_lock_body(
    spec_tag: &str,
    minimal_url: &str,
    minimal_sha: &str,
    ssz_url: &str,
    ssz_sha: &str,
) -> String {
    format!(
        "SPEC_TAG={spec_tag}\nSSZ_SPECS_TAG={SSZ_SPECS_TAG}\n\n\
         archive minimal {spec_tag} {minimal_url} {minimal_sha}\n\
         archive ssz {SSZ_SPECS_TAG} {ssz_url} {ssz_sha}\n"
    )
}

#[test]
fn test_fetch_script_missing_sha_fails_without_extract() {
    let fx = Fixture::new();
    let url = file_url(&fx.minimal_tar);
    let ssz = file_url(&fx.ssz_tar);
    write_lock_raw(
        &fx.lock,
        &format!(
            "SPEC_TAG={SPEC_TAG}\nSSZ_SPECS_TAG={SSZ_SPECS_TAG}\n\n\
             archive minimal {SPEC_TAG} {url}\n\
             archive ssz {SSZ_SPECS_TAG} {ssz} {}\n",
            valid_zero_sha()
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "missing sha must fail: {log}");
    assert!(
        log.contains("malformed") || log.contains("sha256"),
        "error must mention the lock line: {log}"
    );
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "missing sha must not extract");
}

#[test]
fn test_fetch_script_short_sha_fails_without_extract() {
    let fx = Fixture::new();
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            &file_url(&fx.minimal_tar),
            "00",
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "short sha must fail: {log}");
    assert!(
        log.contains("00") || log.contains("64") || log.contains("sha256"),
        "error must mention the digest: {log}"
    );
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "short sha must not extract");
}

#[test]
fn test_fetch_script_non_hex_sha_fails_without_extract() {
    let fx = Fixture::new();
    let bad = non_hex_sha();
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            &file_url(&fx.minimal_tar),
            &bad,
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "non-hex sha must fail: {log}");
    assert!(log.contains("sha256") || log.contains(&bad), "error must name the digest: {log}");
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "non-hex sha must not extract");
}

#[test]
fn test_fetch_script_path_traversal_tag_fails() {
    let fx = Fixture::new();
    let outside = fx.lock.parent().unwrap().join("pwned");
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            "../pwned",
            &file_url(&fx.minimal_tar),
            &valid_zero_sha(),
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "traversal tag must fail: {log}");
    assert!(log.contains("../pwned"), "error must name the tag: {log}");
    assert!(!outside.exists(), "tag must not write outside the cache, found {}", outside.display());
    assert!(!fx.dest.join("pwned").exists(), "traversal tag must not extract under the cache");
}

#[test]
fn test_fetch_script_duplicate_archive_fails() {
    let fx = Fixture::new();
    let url = file_url(&fx.minimal_tar);
    let ssz = file_url(&fx.ssz_tar);
    let sha = valid_zero_sha();
    write_lock_raw(
        &fx.lock,
        &format!(
            "SPEC_TAG={SPEC_TAG}\nSSZ_SPECS_TAG={SSZ_SPECS_TAG}\n\n\
             archive minimal {SPEC_TAG} {url} {sha}\n\
             archive minimal {SPEC_TAG} {url} {sha}\n\
             archive ssz {SSZ_SPECS_TAG} {ssz} {sha}\n"
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "duplicate archive must fail: {log}");
    assert!(log.contains("duplicate"), "error must say duplicate: {log}");
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "duplicate archive must not extract");
}

#[test]
fn test_fetch_script_rejects_uppercase_file_scheme() {
    let fx = Fixture::new();
    let path = fs::canonicalize(&fx.minimal_tar).unwrap();
    let upper = format!("FILE://{}", path.display());
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            &upper,
            &valid_zero_sha(),
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "FILE:// must fail: {log}");
    assert!(
        log.contains("rejected URL") || log.contains("FILE://"),
        "error must reject the scheme: {log}"
    );
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "rejected URL must not extract");
}

#[test]
fn test_fetch_script_rejects_non_github_https() {
    let fx = Fixture::new();
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            "https://evil.example/minimal.tar.gz",
            &valid_zero_sha(),
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "non-github https must fail: {log}");
    assert!(
        log.contains("rejected URL") || log.contains("evil.example"),
        "error must reject the host: {log}"
    );
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "rejected URL must not extract");
}

fn assert_rejected_before_download(output: &Output, needle: &str) {
    let log = combined(output);
    assert!(!output.status.success(), "must fail: {log}");
    assert!(log.contains("rejected URL") || log.contains(needle), "error must name the URL: {log}");
    assert!(!log.contains("downloading:"), "must reject before curl: {log}");
}

#[test]
fn test_fetch_script_rejects_github_url_dotdot() {
    let fx = Fixture::new();
    let url =
        "https://github.com/ethereum/consensus-specs/releases/download/v1.7.0-beta.0/../evil.tar.gz";
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            url,
            &valid_zero_sha(),
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    assert_rejected_before_download(&output, "..");
    assert!(!fx.dest.join(SPEC_TAG).join("tests").exists(), "dotdot github URL must not extract");
}

#[test]
fn test_fetch_script_rejects_github_url_percent_dotdot() {
    let fx = Fixture::new();
    let url = "https://github.com/ethereum/consensus-specs/releases/download/%2e%2e/evil.tar.gz";
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(
            SPEC_TAG,
            url,
            &valid_zero_sha(),
            &file_url(&fx.ssz_tar),
            &valid_zero_sha(),
        ),
    );
    let output = fx.run(&[]);
    assert_rejected_before_download(&output, "%2e%2e");
    assert!(
        !fx.dest.join(SPEC_TAG).join("tests").exists(),
        "percent-encoded github URL must not extract"
    );
}

fn assert_tag_does_not_escape(fx: &Fixture) {
    let parent = fx.dest.parent().expect("vectors parent");
    assert!(!fx.dest.join("tests").exists(), "must not extract into the cache root");
    assert!(!parent.join("tests").exists(), "must not extract outside VECTORS_DIR");
    assert!(!parent.join("minimal.tar.gz").exists(), "must not write archives outside VECTORS_DIR");
}

#[test]
fn test_fetch_script_dot_tag_fails() {
    let fx = Fixture::new();
    let sha = sha256_hex(&fx.minimal_tar);
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body(".", &file_url(&fx.minimal_tar), &sha, &file_url(&fx.ssz_tar), &sha),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "SPEC_TAG=. must fail: {log}");
    assert!(
        log.contains("invalid SPEC_TAG") || log.contains("'.'"),
        "error must name the tag: {log}"
    );
    assert_tag_does_not_escape(&fx);
}

#[test]
fn test_fetch_script_dotdot_tag_fails() {
    let fx = Fixture::new();
    let sha = sha256_hex(&fx.minimal_tar);
    write_lock_raw(
        &fx.lock,
        &fixture_lock_body("..", &file_url(&fx.minimal_tar), &sha, &file_url(&fx.ssz_tar), &sha),
    );
    let output = fx.run(&[]);
    let log = combined(&output);
    assert!(!output.status.success(), "SPEC_TAG=.. must fail: {log}");
    assert!(
        log.contains("invalid SPEC_TAG") || log.contains("'..'"),
        "error must name the tag: {log}"
    );
    assert_tag_does_not_escape(&fx);
}
