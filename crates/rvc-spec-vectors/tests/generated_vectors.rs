//! Drive `scripts/fetch_spec_vectors.sh verify` over [[generated]] lock entries.
//!
//! Hermetic: no network, no Python toolchain.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const ID: &str = "progressive";
const PYTHON: &str = "3.13.7";
const PIP: &str =
    "eth-ssz-specs==0.1.0 -r crates/rvc-spec-vectors/vectors-generated/progressive/requirements.txt";
const SCRIPT: &str = "scripts/gen_progressive_vectors.py";
const STUB_REQUIREMENTS: &str = "\
eth-ssz-specs==0.1.0 --hash=sha256:466c6cef854cca45022a7cdc3922dd636e30b1a1dd5385845819e3d45ddddf41
pydantic==2.13.5 --hash=sha256:346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73
pydantic-core==2.46.5 --hash=sha256:f332f0e72a5a0400141f830744e141bf9f97917878dbe968669e8a7fefea78ff
";
const ZERO_ROOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
const WIDTHS: &[u32] = &[3, 4, 5, 13];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn fetch_script() -> PathBuf {
    workspace_root().join("scripts/fetch_spec_vectors.sh")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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

fn stub_recipe() -> &'static str {
    "#!/usr/bin/env python3\n# stub recipe used only in lock-shape tests\nprint('ok')\n"
}

struct GeneratedFields<'a> {
    id: &'a str,
    python: &'a str,
    pip: &'a str,
    script: &'a str,
    argv: &'a str,
    output: &'a str,
    sha256: &'a str,
}

fn write_generated_lock(path: &Path, fields: GeneratedFields<'_>) {
    let body = format!(
        "SPEC_TAG=v-test\nSSZ_SPECS_TAG=ssz-test\n\n\
         [[generated]]\n\
         id={id}\n\
         python={python}\n\
         pip={pip}\n\
         script={script}\n\
         argv={argv}\n\
         output={output}\n\
         sha256={sha256}\n",
        id = fields.id,
        python = fields.python,
        pip = fields.pip,
        script = fields.script,
        argv = fields.argv,
        output = fields.output,
        sha256 = fields.sha256,
    );
    fs::write(path, body).expect("write vectors.lock");
}

struct GenFixture {
    _tmp: TempDir,
    repo: PathBuf,
    lock: PathBuf,
    output: PathBuf,
}

impl GenFixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let repo = tmp.path().to_path_buf();
        let output_rel = format!("crates/rvc-spec-vectors/vectors-generated/{ID}/roots.yaml");
        let output = repo.join(&output_rel);
        fs::create_dir_all(output.parent().unwrap()).expect("mkdir generated");
        fs::create_dir_all(repo.join("scripts")).expect("mkdir scripts");
        fs::write(repo.join(SCRIPT), stub_recipe()).expect("write stub recipe");
        fs::write(output.parent().unwrap().join("requirements.txt"), STUB_REQUIREMENTS)
            .expect("write stub requirements");
        fs::write(&output, b"artifact-body\n").expect("write artifact");
        let sha = sha256_hex(&output);
        let lock = repo.join("crates/rvc-spec-vectors/vectors.lock");
        fs::create_dir_all(lock.parent().unwrap()).expect("mkdir lock dir");
        write_generated_lock(
            &lock,
            GeneratedFields {
                id: ID,
                python: PYTHON,
                pip: PIP,
                script: SCRIPT,
                argv: &format!("--out {output_rel}"),
                output: &output_rel,
                sha256: &sha,
            },
        );
        Self { _tmp: tmp, repo, lock, output }
    }

    fn verify(&self) -> Output {
        run_verify(&self.lock, &self.repo)
    }
}

fn run_verify(lock: &Path, repo: &Path) -> Output {
    let script = fetch_script();
    assert!(script.is_file(), "missing fetch script at {}", script.display());
    Command::new("bash")
        .arg(&script)
        .arg("verify")
        .env("VECTORS_LOCK", lock)
        .env("REPO_ROOT", repo)
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", script.display()))
}

#[test]
fn test_verify_generated_accepts_checked_in_artifact() {
    let root = workspace_root();
    let output = Command::new("bash")
        .arg(fetch_script())
        .arg("verify")
        .current_dir(&root)
        .output()
        .expect("spawn verify");
    let log = combined(&output);
    assert!(output.status.success(), "checked-in artifact must verify: {log}");
    assert!(log.contains("generated ok: progressive"), "verify must name the id: {log}");
    assert!(
        log.contains("generated ok: signing-roots"),
        "verify must name the signing-roots id: {log}"
    );
}

#[test]
fn test_verify_generated_empty_field_fails() {
    let fx = GenFixture::new();
    let output_rel = format!("crates/rvc-spec-vectors/vectors-generated/{ID}/roots.yaml");
    let sha = sha256_hex(&fx.output);
    let argv = format!("--out {output_rel}");
    let fields = ["id", "python", "pip", "script", "argv", "output", "sha256"];
    for empty in fields {
        let id = if empty == "id" { "" } else { ID };
        let python = if empty == "python" { "" } else { PYTHON };
        let pip = if empty == "pip" { "" } else { PIP };
        let script = if empty == "script" { "" } else { SCRIPT };
        let argv_v = if empty == "argv" { "" } else { argv.as_str() };
        let output_v = if empty == "output" { "" } else { output_rel.as_str() };
        let sha_v = if empty == "sha256" { "" } else { sha.as_str() };
        write_generated_lock(
            &fx.lock,
            GeneratedFields {
                id,
                python,
                pip,
                script,
                argv: argv_v,
                output: output_v,
                sha256: sha_v,
            },
        );
        let result = fx.verify();
        let log = combined(&result);
        assert!(!result.status.success(), "empty {empty} must fail: {log}");
        assert!(
            log.contains("empty") || log.contains("missing") || log.contains(empty),
            "error must name empty field {empty}: {log}"
        );
    }
}

#[test]
fn test_verify_generated_one_byte_edit_fails() {
    let fx = GenFixture::new();
    let expected = sha256_hex(&fx.output);
    let mut bytes = fs::read(&fx.output).expect("read artifact");
    assert!(!bytes.is_empty(), "artifact too small to edit");
    bytes[0] ^= 0x01;
    fs::write(&fx.output, &bytes).expect("edit artifact");
    let actual = sha256_hex(&fx.output);
    assert_ne!(actual, expected, "edit must change digest");

    let result = fx.verify();
    let log = combined(&result);
    assert!(!result.status.success(), "one-byte edit must fail verify: {log}");
    assert!(log.contains("digest mismatch") || log.contains("mismatch"), "{log}");
    assert!(log.contains(&expected), "error must name expected digest: {log}");
    assert!(log.contains(&actual), "error must name actual digest: {log}");
}

#[test]
fn test_verify_generated_recipe_must_not_reference_rsvc() {
    let fx = GenFixture::new();
    let poisoned = fx.repo.join(SCRIPT);
    fs::write(&poisoned, "import rvc\nprint('no')\n").expect("poison recipe");
    let result = fx.verify();
    let log = combined(&result);
    assert!(!result.status.success(), "recipe mentioning rvc must fail: {log}");
    assert!(
        log.contains("rs-vc") || log.contains("rvc") || log.contains("recipe"),
        "error must mention the recipe grep: {log}"
    );
}

#[test]
fn test_verify_generated_pip_must_hash_full_closure() {
    let fx = GenFixture::new();
    let output_rel = format!("crates/rvc-spec-vectors/vectors-generated/{ID}/roots.yaml");
    let sha = sha256_hex(&fx.output);
    let argv = format!("--out {output_rel}");
    write_generated_lock(
        &fx.lock,
        GeneratedFields {
            id: ID,
            python: PYTHON,
            pip: "eth-ssz-specs==0.1.0 sha256:466c6cef854cca45022a7cdc3922dd636e30b1a1dd5385845819e3d45ddddf41",
            script: SCRIPT,
            argv: &argv,
            output: &output_rel,
            sha256: &sha,
        },
    );
    let result = fx.verify();
    let log = combined(&result);
    assert!(!result.status.success(), "single-hash pip pin must fail: {log}");
    assert!(
        log.contains("pip") || log.contains("closure") || log.contains("hash"),
        "error must mention the hashed pip closure: {log}"
    );
}

#[test]
fn test_verify_generated_requirements_must_pin_pydantic() {
    let fx = GenFixture::new();
    let req = fx.output.parent().unwrap().join("requirements.txt");
    fs::write(
        &req,
        "eth-ssz-specs==0.1.0 --hash=sha256:466c6cef854cca45022a7cdc3922dd636e30b1a1dd5385845819e3d45ddddf41\n",
    )
    .expect("write incomplete requirements");
    let result = fx.verify();
    let log = combined(&result);
    assert!(!result.status.success(), "requirements without pydantic must fail: {log}");
    assert!(log.contains("pydantic") || log.contains("closure"), "{log}");
}

#[test]
fn test_verify_generated_missing_block_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = tmp.path();
    let lock = repo.join("vectors.lock");
    fs::write(&lock, "SPEC_TAG=v-test\nSSZ_SPECS_TAG=ssz-test\n").expect("write lock");
    let result = run_verify(&lock, repo);
    let log = combined(&result);
    assert!(!result.status.success(), "lock without [[generated]] must fail: {log}");
    assert!(log.contains("[[generated]]") || log.contains("generated"), "{log}");
}

#[test]
fn test_generated_artifact_lists_every_pyspec_count_and_width() {
    let path =
        workspace_root().join("crates/rvc-spec-vectors/vectors-generated/progressive/roots.yaml");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    for count in CHUNK_COUNTS {
        // Trailing newline so `chunk_count: 2` is not a prefix of `20`/`21`/`22`.
        let needle = format!("  - chunk_count: {count}\n");
        assert!(body.contains(&needle), "missing {needle:?} in {}", path.display());
    }
    for width in WIDTHS {
        let needle = format!("  - width: {width}\n");
        assert!(body.contains(&needle), "missing {needle:?} in {}", path.display());
        assert!(
            body.contains("pattern: all_ones"),
            "missing all_ones pattern in {}",
            path.display()
        );
        assert!(
            body.contains("pattern: sparse_bit0_clear"),
            "missing sparse_bit0_clear pattern in {}",
            path.display()
        );
    }
    assert!(
        body.contains(&format!("chunk_count: 0\n    chunks: []\n    root: '{ZERO_ROOT}'")),
        "empty progressive input must be the zero root, not mix_in_length: {}",
        path.display()
    );
    assert!(body.contains("bits: [1, 1, 1]"), "missing width-3 all-ones bits");
    assert!(body.contains("bits: [0, 1, 1]"), "missing width-3 sparse bits");
    assert!(body.contains("bits: [1, 1, 1, 1]"), "missing width-4 all-ones bits");
    assert!(body.contains("bits: [0, 1, 1, 1]"), "missing width-4 sparse bits");
    assert!(body.contains("bits: [1, 1, 1, 1, 1]"), "missing width-5 all-ones bits");
    assert!(body.contains("bits: [0, 1, 1, 1, 1]"), "missing width-5 sparse bits");
    assert!(
        body.contains("bits: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]"),
        "missing width-13 all-ones bits"
    );
    assert!(
        body.contains("bits: [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]"),
        "missing width-13 sparse bits"
    );
}

#[test]
fn test_recipe_script_has_no_rsvc_path() {
    for rel in [SCRIPT, "scripts/gen_signing_roots.py"] {
        let path = workspace_root().join(rel);
        let body =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(!body.contains("rvc"), "recipe must not mention rvc: {}", path.display());
        assert!(
            !body.contains("vectors-generated"),
            "recipe must not name the output dir: {}",
            path.display()
        );
    }
}

#[test]
fn test_signing_roots_recipe_does_not_hardcode_domain_bytes() {
    let path = workspace_root().join("scripts/gen_signing_roots.py");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let lower = body.to_ascii_lowercase();
    assert!(
        !lower.contains("0c000000"),
        "DOMAIN_PTC_ATTESTER must be parsed from the pinned spec, not hardcoded: {}",
        path.display()
    );
    assert!(
        !lower.contains("0d000000"),
        "DOMAIN_PROPOSER_PREFERENCES must be parsed from the pinned spec, not hardcoded: {}",
        path.display()
    );
}
