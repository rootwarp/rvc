//! Emit `spec_kat.rs` (`SPEC_PROGRESSIVE_*`, `SPEC_GLOAS_*`, `KAT_GLOAS_*`)
//! and `gloas_signing_kat.rs` from vector files.
//!
//! Argv only: `--vectors <dir> --out <path>` and optional `--gloas-out` /
//! `--gloas-vectors`. L1 roots are copied from the 3.4b pyspec artifact
//! (`vectors-generated/progressive/roots.yaml`), never from shipped JSON
//! `root` fields (`mix_in_length`-wrapped). `--out` copies P4 Gloas container
//! roots from `ssz_static` when present, else the 4.0 pyspec artifact, and
//! copies L3 signing roots from `gen_signing_roots.py` (this binary never
//! computes a domain). A sibling `gloas_signing_kat.rs` copies island L3
//! signing roots from the same recipe. `--gloas-out` emits the rvc-gloas
//! per-preset island KATs from official `ssz_static` (or a documented residual).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

use rvc_spec_vectors::loader::{decode_snappy, roots_yaml};

const GENERATOR_NAME: &str = "gen-spec-kat";
const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");
const DATE_PLACEHOLDER: &str = "YYYY-MM-DD";
const PROVENANCE_DATE_PREFIX: &str = "//! provenance-date:";

/// Layout runner the Phase 5 walk will reuse; hashed here for provenance.
const SSZ_STATIC: &str = "ssz_static";
/// Case payload suffix under the vector layout.
const SSZ_SNAPPY_SUFFIX: &str = ".ssz_snappy";

const REQUIRED_CHUNK_COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
const REQUIRED_WIDTHS: &[u32] = &[3, 4, 13];
const GLOAS_WIDTHS: &[u32] = &[3, 4, 5, 13];
const REQUIRED_PATTERNS: &[&str] = &["all_ones", "sparse_bit0_clear"];

const GLOAS_FORK: &str = "gloas";
const GLOAS_SUITE: &str = "ssz_random";
const GLOAS_CASE: &str = "case_0";
const GLOAS_PRESETS: &[&str] = &["minimal", "mainnet"];

/// Island containers that 5.4–5.16 assert as `SPEC_GLOAS_<TYPE>_ROOT`.
const GLOAS_TYPES: &[&str] = &[
    "Checkpoint",
    "AttestationData",
    "Eth1Data",
    "BeaconBlockHeader",
    "SignedBeaconBlockHeader",
    "ProposerSlashing",
    "DepositData",
    "Deposit",
    "VoluntaryExit",
    "SignedVoluntaryExit",
    "SyncAggregate",
    "BLSToExecutionChange",
    "SignedBLSToExecutionChange",
    "DepositRequest",
    "WithdrawalRequest",
    "ConsolidationRequest",
    "BuilderDepositRequest",
    "BuilderExitRequest",
    "Attestation",
    "IndexedAttestation",
    "AttesterSlashing",
    "AggregateAndProof",
    "SignedAggregateAndProof",
    "ExecutionRequests",
    "PayloadAttestationData",
    "PayloadAttestation",
    "ExecutionPayloadBid",
    "SignedExecutionPayloadBid",
    "BeaconBlockBody",
    "BeaconBlock",
    "ExecutionPayload",
    "ExecutionPayloadEnvelope",
    "SignedExecutionPayloadEnvelope",
];

const ZERO_ROOT_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const PROGRESSIVE_ID: &str = "progressive";
const SIGNING_ROOTS_ID: &str = "signing-roots";
const GLOAS_SIGNING_ROOTS_ID: &str = "gloas-signing-roots";

/// Island L3 signing roots copied from the 4.0 pyspec recipe (issue 5.13a).
const GLOAS_SIGNING_KAT: &[(&str, &str)] = &[
    ("BeaconBlock", "KAT_GLOAS_BLOCK_SIGNING_ROOT"),
    ("AggregateAndProof", "KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT"),
    ("ExecutionPayloadEnvelope", "KAT_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SIGNING_ROOT"),
    ("AttestationData", "KAT_GLOAS_ATTESTATION_DATA_SIGNING_ROOT"),
];

/// P4 ssz_static handlers only (issue 4.0). Const name is `SPEC_GLOAS_<CONTAINER>_ROOT`.
const GLOAS_SSZ_STATIC: &[(&str, &str)] = &[
    ("PayloadAttestationData", "SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT"),
    ("PayloadAttestationMessage", "SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT"),
    ("ProposerPreferences", "SPEC_GLOAS_PROPOSERPREFERENCES_ROOT"),
];

fn main() -> ExitCode {
    match run(std::env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "usage: {GENERATOR_NAME} --vectors <dir> --out <path> [--gloas-out <path>] [--gloas-vectors <dir>]"
            );
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), String> {
    let args = parse_args(args)?;
    if !args.vectors.is_dir() {
        return Err(format!("--vectors is not a directory: {}", args.vectors.display()));
    }
    refuse_symlink(&args.vectors)?;

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("canonicalize workspace root: {e}"))?;
    let lock_path = crate_dir.join("vectors.lock");
    let lock = read_to_string(&lock_path)?;
    let (spec_tag, ssz_tag) = lock_tags(&lock)?;
    let generated = lock_generated_pins(&lock)?;
    require_generated_id(&generated, PROGRESSIVE_ID)?;
    require_generated_id(&generated, SIGNING_ROOTS_ID)?;
    require_generated_id(&generated, GLOAS_SIGNING_ROOTS_ID)?;

    let mut inputs = Vec::new();
    let mut progressive_parsed = None;
    let mut signing_artifact = None;
    let mut gloas_signing_artifact = None;
    let mut gloas_signing_pin = None;
    for pin in &generated {
        let path = workspace.join(&pin.output);
        if !path.is_file() {
            return Err(format!(
                "missing [[generated]] artifact id={}: {}",
                pin.id,
                path.display()
            ));
        }
        refuse_symlink(&path)?;
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let digest = hex::encode(Sha256::digest(&bytes));
        if digest != pin.sha256 {
            return Err(format!(
                "[[generated]] id={} digest mismatch: lock {} disk {}",
                pin.id, pin.sha256, digest
            ));
        }
        let text = String::from_utf8(bytes)
            .map_err(|e| format!("{} is not utf-8: {e}", path.display()))?;
        if text.to_ascii_lowercase().contains("remerkleable") {
            return Err(format!(
                "[[generated]] id={} artifact mentions remerkleable (D15): {}",
                pin.id,
                path.display()
            ));
        }
        if pin.id == PROGRESSIVE_ID {
            let parsed = parse_progressive_artifact(&text)?;
            parsed.validate()?;
            progressive_parsed = Some(parsed);
        }
        if pin.id == SIGNING_ROOTS_ID {
            signing_artifact = Some(parse_signing_roots_artifact(&text)?);
        }
        if pin.id == GLOAS_SIGNING_ROOTS_ID {
            gloas_signing_artifact = Some(parse_signing_roots_artifact(&text)?);
            gloas_signing_pin = Some(pin.clone());
        }
        push_input(&mut inputs, &workspace, &path)?;
    }
    let parsed = progressive_parsed
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={PROGRESSIVE_ID}"))?;
    let signing = signing_artifact
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={SIGNING_ROOTS_ID}"))?;
    let gloas_signing = gloas_signing_artifact
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={GLOAS_SIGNING_ROOTS_ID}"))?;
    let gloas_pin = gloas_signing_pin
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={GLOAS_SIGNING_ROOTS_ID}"))?;

    let ssz_static_files = collect_ssz_static_inputs(&args.vectors)?;
    for path in &ssz_static_files {
        push_input(&mut inputs, &workspace, path)?;
    }
    inputs.sort_by(|a, b| a.rel.cmp(&b.rel));
    inputs.dedup_by(|a, b| a.rel == b.rel);

    let gloas = resolve_gloas_kat(&ssz_static_files, &signing)?;

    let source = format!("ethereum/consensus-specs@{spec_tag} ethereum/ssz-specs@{ssz_tag}");
    let generator = format!("{GENERATOR_NAME} {GENERATOR_VERSION}");
    let body = render(&RenderInput {
        date: DATE_PLACEHOLDER,
        source: &source,
        generated: &generated,
        generator: &generator,
        inputs: &inputs,
        parsed: &parsed,
        gloas: &gloas,
    })?;

    write_stable(&args.out, &body)?;

    let island_kat = resolve_island_signing_kat(&gloas_signing, &gloas_pin)?;
    let signing_kat_path = args
        .out
        .parent()
        .map(|p| p.join("gloas_signing_kat.rs"))
        .unwrap_or_else(|| PathBuf::from("gloas_signing_kat.rs"));
    let signing_kat_body = render_gloas_signing_kat(&RenderGloasSigningInput {
        date: DATE_PLACEHOLDER,
        source: &source,
        pin: &gloas_pin,
        generator: &generator,
        artifact: &gloas_signing,
        kat: &island_kat,
    })?;
    write_stable(&signing_kat_path, &signing_kat_body)?;

    if let Some(gloas_out) = args.gloas_out.as_ref() {
        let gloas_vectors =
            args.gloas_vectors.clone().unwrap_or_else(|| crate_dir.join("vectors").join(&spec_tag));
        if !gloas_vectors.is_dir() {
            return Err(format!(
                "--gloas-vectors is not a directory: {} (fetch both presets: PRESET=minimal make spec-vectors && PRESET=mainnet make spec-vectors)",
                gloas_vectors.display()
            ));
        }
        refuse_symlink(&gloas_vectors)?;
        let progressive_rel = generated
            .iter()
            .find(|p| p.id == PROGRESSIVE_ID)
            .map(|p| p.output.as_str())
            .ok_or_else(|| format!("vectors.lock [[generated]] missing id={PROGRESSIVE_ID}"))?;
        let progressive_path = workspace.join(progressive_rel);
        let (families, residuals, mut island_inputs) =
            collect_gloas(&workspace, &gloas_vectors, &progressive_path, &parsed)?;
        for pin in &generated {
            let path = workspace.join(&pin.output);
            if path.is_file() {
                push_input(&mut island_inputs, &workspace, &path)?;
            }
        }
        island_inputs.sort_by(|a, b| a.rel.cmp(&b.rel));
        island_inputs.dedup_by(|a, b| a.rel == b.rel);
        refuse_dropped_gloas_names(gloas_out, &families)?;
        let island_body = render_island(&IslandRenderInput {
            date: DATE_PLACEHOLDER,
            source: &source,
            generated: &generated,
            generator: &generator,
            inputs: &island_inputs,
            parsed: &parsed,
            families: &families,
            residuals: &residuals,
        })?;
        write_stable(gloas_out, &island_body)?;
    }
    Ok(())
}

struct Args {
    vectors: PathBuf,
    out: PathBuf,
    gloas_out: Option<PathBuf>,
    gloas_vectors: Option<PathBuf>,
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut args = args.into_iter();
    let _argv0 = args.next();
    let mut vectors = None;
    let mut out = None;
    let mut gloas_out = None;
    let mut gloas_vectors = None;
    while let Some(raw) = args.next() {
        let flag = raw.to_string_lossy();
        match flag.as_ref() {
            "--vectors" => {
                let value = args.next().ok_or("missing value for --vectors")?;
                if vectors.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --vectors".into());
                }
            }
            "--out" => {
                let value = args.next().ok_or("missing value for --out")?;
                if out.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --out".into());
                }
            }
            "--gloas-out" => {
                let value = args.next().ok_or("missing value for --gloas-out")?;
                if gloas_out.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --gloas-out".into());
                }
            }
            "--gloas-vectors" => {
                let value = args.next().ok_or("missing value for --gloas-vectors")?;
                if gloas_vectors.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --gloas-vectors".into());
                }
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    if gloas_vectors.is_some() && gloas_out.is_none() {
        return Err("--gloas-vectors requires --gloas-out".into());
    }
    Ok(Args {
        vectors: vectors.ok_or("missing --vectors <dir>")?,
        out: out.ok_or("missing --out <path>")?,
        gloas_out,
        gloas_vectors,
    })
}

struct InputHash {
    rel: String,
    sha256: String,
}

fn push_input(out: &mut Vec<InputHash>, workspace: &Path, path: &Path) -> Result<(), String> {
    refuse_symlink(path)?;
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let rel = display_input_path(workspace, path)?;
    out.push(InputHash { rel, sha256 });
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("refusing symlink input: {}", path.display()));
    }
    Ok(())
}

fn display_input_path(workspace: &Path, path: &Path) -> Result<String, String> {
    let canon = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let rel = match canon.strip_prefix(workspace) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    };
    if rel.chars().any(|c| c.is_control()) {
        return Err(format!("input path contains control characters: {rel:?}"));
    }
    Ok(rel)
}

fn collect_ssz_static_inputs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    visit_ssz_static(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn visit_ssz_static(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    refuse_symlink(dir)?;
    let entries = fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    for ent in entries {
        let ent = ent.map_err(|e| format!("read {}: {e}", dir.display()))?;
        let path = ent.path();
        refuse_symlink(&path)?;
        if path.is_dir() {
            visit_ssz_static(&path, out)?;
            continue;
        }
        if is_ssz_static_input(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_ssz_static_input(path: &Path) -> bool {
    let in_ssz_static = path.components().any(|c| c.as_os_str() == SSZ_STATIC);
    if !in_ssz_static {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "roots.yaml" || name.ends_with(SSZ_SNAPPY_SUFFIX)
}

fn lock_tags(lock: &str) -> Result<(String, String), String> {
    let mut spec = None;
    let mut ssz = None;
    for line in lock.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("SPEC_TAG=") {
            spec = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("SSZ_SPECS_TAG=") {
            ssz = Some(v.trim().to_owned());
        }
    }
    match (spec, ssz) {
        (Some(spec), Some(ssz)) if !spec.is_empty() && !ssz.is_empty() => Ok((spec, ssz)),
        _ => Err("vectors.lock missing SPEC_TAG or SSZ_SPECS_TAG".into()),
    }
}

#[derive(Clone)]
struct GeneratedPin {
    id: String,
    output: String,
    sha256: String,
    python: String,
    argv: String,
}

fn require_generated_id(pins: &[GeneratedPin], id: &str) -> Result<(), String> {
    if pins.iter().any(|p| p.id == id) {
        Ok(())
    } else {
        Err(format!("vectors.lock [[generated]] missing id={id}"))
    }
}

fn finish_generated_pin(
    id: Option<String>,
    output: Option<String>,
    sha256: Option<String>,
    python: Option<String>,
    argv: Option<String>,
) -> Result<GeneratedPin, String> {
    match (id, output, sha256) {
        (Some(id), Some(output), Some(sha256))
            if !id.is_empty()
                && !output.is_empty()
                && sha256.len() == 64
                && sha256.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(GeneratedPin {
                id,
                output,
                sha256,
                python: python.unwrap_or_default(),
                argv: argv.unwrap_or_default(),
            })
        }
        _ => Err("vectors.lock [[generated]] missing id, output, or sha256".into()),
    }
}

/// Names every `[[generated]]` pin in the header. Disk re-check of those digests is 3.6.
fn lock_generated_pins(lock: &str) -> Result<Vec<GeneratedPin>, String> {
    let mut pins = Vec::new();
    let mut in_block = false;
    let mut id = None;
    let mut output = None;
    let mut sha256 = None;
    let mut python = None;
    let mut argv = None;
    let mut flush = |id: &mut Option<String>,
                     output: &mut Option<String>,
                     sha256: &mut Option<String>,
                     python: &mut Option<String>,
                     argv: &mut Option<String>|
     -> Result<(), String> {
        if id.is_none() && output.is_none() && sha256.is_none() {
            python.take();
            argv.take();
            return Ok(());
        }
        pins.push(finish_generated_pin(
            id.take(),
            output.take(),
            sha256.take(),
            python.take(),
            argv.take(),
        )?);
        Ok(())
    };
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[generated]]" {
            flush(&mut id, &mut output, &mut sha256, &mut python, &mut argv)?;
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if line.is_empty() || line.starts_with("[[") || line.starts_with("archive ") {
            flush(&mut id, &mut output, &mut sha256, &mut python, &mut argv)?;
            in_block = false;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("id=") {
            id = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("output=") {
            output = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("sha256=") {
            sha256 = Some(v.trim().to_ascii_lowercase());
        } else if let Some(v) = line.strip_prefix("python=") {
            python = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("argv=") {
            argv = Some(v.trim().to_owned());
        }
    }
    flush(&mut id, &mut output, &mut sha256, &mut python, &mut argv)?;
    if pins.is_empty() {
        return Err("vectors.lock [[generated]] missing id, output, or sha256".into());
    }
    pins.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(pins)
}

struct ProgressiveVectors {
    merkleize: BTreeMap<u32, String>,
    mix_in: BTreeMap<(u32, String), String>,
}

impl ProgressiveVectors {
    fn validate(&self) -> Result<(), String> {
        for count in REQUIRED_CHUNK_COUNTS {
            if !self.merkleize.contains_key(count) {
                return Err(format!(
                    "3.4b artifact missing merkleize_progressive chunk_count {count}"
                ));
            }
        }
        let empty = self.merkleize.get(&0).map(String::as_str).unwrap_or("");
        if empty != ZERO_ROOT_HEX {
            return Err(format!(
                "chunk_count 0 must be the zero root (not mix_in_length), got {empty}"
            ));
        }
        for width in REQUIRED_WIDTHS {
            for pattern in REQUIRED_PATTERNS {
                if !self.mix_in.contains_key(&(*width, (*pattern).to_owned())) {
                    return Err(format!(
                        "3.4b artifact missing mix_in_active_fields width {width} pattern {pattern}"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn parse_progressive_artifact(text: &str) -> Result<ProgressiveVectors, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("parse 3.4b roots.yaml: {e}"))?;
    let mapping = value.as_mapping().ok_or("3.4b roots.yaml must be a mapping")?;

    let mut merkleize = BTreeMap::new();
    let merkle_seq = yaml_seq(mapping, "merkleize_progressive")?;
    for (i, item) in merkle_seq.iter().enumerate() {
        let item = item
            .as_mapping()
            .ok_or_else(|| format!("merkleize_progressive[{i}] must be a mapping"))?;
        let count = yaml_u32(item, "chunk_count")?;
        let root = normalize_root_hex(&yaml_string(item, "root")?)?;
        if merkleize.insert(count, root).is_some() {
            return Err(format!("duplicate merkleize_progressive chunk_count {count}"));
        }
    }

    let mut mix_in = BTreeMap::new();
    let mix_seq = yaml_seq(mapping, "mix_in_active_fields")?;
    for (i, item) in mix_seq.iter().enumerate() {
        let item = item
            .as_mapping()
            .ok_or_else(|| format!("mix_in_active_fields[{i}] must be a mapping"))?;
        let width = yaml_u32(item, "width")?;
        let pattern = yaml_string(item, "pattern")?;
        if pattern.is_empty() {
            return Err(format!("mix_in_active_fields[{i}] pattern is empty"));
        }
        let root = normalize_root_hex(&yaml_string(item, "root")?)?;
        if mix_in.insert((width, pattern.clone()), root).is_some() {
            return Err(format!("duplicate mix_in_active_fields width {width} pattern {pattern}"));
        }
    }

    Ok(ProgressiveVectors { merkleize, mix_in })
}

fn yaml_seq<'a>(
    mapping: &'a serde_yaml::Mapping,
    field: &str,
) -> Result<&'a Vec<serde_yaml::Value>, String> {
    let key = serde_yaml::Value::String(field.to_owned());
    mapping
        .get(&key)
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| format!("missing sequence field `{field}` in artifact"))
}

fn yaml_u32(mapping: &serde_yaml::Mapping, field: &str) -> Result<u32, String> {
    let key = serde_yaml::Value::String(field.to_owned());
    let value = mapping.get(&key).ok_or_else(|| format!("missing field `{field}`"))?;
    let n =
        value.as_u64().ok_or_else(|| format!("field `{field}` must be a non-negative integer"))?;
    u32::try_from(n).map_err(|_| format!("field `{field}` exceeds u32"))
}

fn yaml_string(mapping: &serde_yaml::Mapping, field: &str) -> Result<String, String> {
    let key = serde_yaml::Value::String(field.to_owned());
    match mapping.get(&key) {
        Some(serde_yaml::Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!("field `{field}` must be a string, got {other:?}")),
        None => Err(format!("missing field `{field}`")),
    }
}

fn normalize_root_hex(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("root is not 32-byte hex: {raw}"));
    }
    Ok(s.to_ascii_lowercase())
}

fn path_has_component(path: &Path, name: &str) -> bool {
    path.components().any(|c| c.as_os_str() == name)
}

struct SigningRootsArtifact {
    containers: BTreeMap<String, String>,
    signing_roots: BTreeMap<String, String>,
    argv_flip_signing_root: Option<String>,
    package: String,
    spec_tag: String,
    python: String,
    argv: String,
    input_sha256: String,
    fork_version: String,
    genesis_validators_root: String,
}

fn optional_yaml_string(mapping: &serde_yaml::Mapping, field: &str) -> String {
    yaml_string(mapping, field).unwrap_or_default()
}

fn parse_signing_roots_artifact(text: &str) -> Result<SigningRootsArtifact, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("parse signing_roots.yaml: {e}"))?;
    let mapping = value.as_mapping().ok_or("signing_roots.yaml must be a mapping")?;
    let seq = yaml_seq(mapping, "containers")?;
    let mut containers = BTreeMap::new();
    let mut signing_roots = BTreeMap::new();
    let mut argv_flip_signing_root = None;
    for (i, item) in seq.iter().enumerate() {
        let item = item
            .as_mapping()
            .ok_or_else(|| format!("signing_roots.yaml containers[{i}] must be a mapping"))?;
        let name = yaml_string(item, "name")?;
        if name.is_empty() {
            return Err(format!("signing_roots.yaml containers[{i}] name is empty"));
        }
        let root = normalize_root_hex(&yaml_string(item, "root")?)?;
        if containers.insert(name.clone(), root).is_some() {
            return Err(format!("duplicate signing_roots.yaml container {name}"));
        }
        if item.get(serde_yaml::Value::String("signing_root".into())).is_some() {
            let signing = normalize_root_hex(&yaml_string(item, "signing_root")?)?;
            signing_roots.insert(name.clone(), signing);
        }
        if item.get(serde_yaml::Value::String("argv_flip_signing_root".into())).is_some() {
            let flip = normalize_root_hex(&yaml_string(item, "argv_flip_signing_root")?)?;
            if argv_flip_signing_root.replace(flip).is_some() {
                return Err("duplicate argv_flip_signing_root in signing_roots.yaml".into());
            }
        }
    }
    Ok(SigningRootsArtifact {
        containers,
        signing_roots,
        argv_flip_signing_root,
        package: optional_yaml_string(mapping, "package"),
        spec_tag: optional_yaml_string(mapping, "spec_tag"),
        python: optional_yaml_string(mapping, "python"),
        argv: optional_yaml_string(mapping, "argv"),
        input_sha256: optional_yaml_string(mapping, "input_sha256"),
        fork_version: optional_yaml_string(mapping, "fork_version"),
        genesis_validators_root: optional_yaml_string(mapping, "genesis_validators_root"),
    })
}

fn parse_ssz_static_root(text: &str) -> Result<String, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("parse ssz_static roots.yaml: {e}"))?;
    let mapping = value.as_mapping().ok_or("ssz_static roots.yaml must be a mapping")?;
    normalize_root_hex(&yaml_string(mapping, "root")?)
}

fn official_ssz_static_root(
    files: &[PathBuf],
    container: &str,
) -> Result<Option<(PathBuf, String)>, String> {
    let mut matches: Vec<&PathBuf> = files
        .iter()
        .filter(|path| {
            path.file_name().and_then(|n| n.to_str()) == Some("roots.yaml")
                && path_has_component(path, SSZ_STATIC)
                && path_has_component(path, container)
        })
        .collect();
    matches.sort();
    let Some(path) = matches.first() else {
        return Ok(None);
    };
    let text = read_to_string(path)?;
    let root = parse_ssz_static_root(&text)?;
    Ok(Some(((*path).clone(), root)))
}

struct GloasRoot {
    container: &'static str,
    const_name: &'static str,
    hex: String,
    source: String,
}

struct GloasKat {
    containers: Vec<GloasRoot>,
    payload_attestation_signing_root: String,
    proposer_preferences_signing_root: String,
}

fn resolve_gloas_kat(
    ssz_static_files: &[PathBuf],
    artifact: &SigningRootsArtifact,
) -> Result<GloasKat, String> {
    let mut containers = Vec::new();
    for (name, const_name) in GLOAS_SSZ_STATIC {
        let Some(hex) = artifact.containers.get(*name) else {
            return Err(format!(
                "blocked: no ssz_static case and no pyspec artifact root for {name} (ADR-005 / D15)"
            ));
        };
        if let Some((path, official)) = official_ssz_static_root(ssz_static_files, name)? {
            if official != *hex {
                return Err(format!(
                    "ssz_static {} root {official} disagrees with pyspec object root {hex} for {name}",
                    path.display()
                ));
            }
        }
        containers.push(GloasRoot {
            container: name,
            const_name,
            hex: hex.clone(),
            source: "4.0 pyspec signing-roots artifact".to_owned(),
        });
    }
    let payload_attestation_signing_root =
        artifact.signing_roots.get("PayloadAttestationData").cloned().ok_or_else(|| {
            "blocked: signing_roots.yaml missing PayloadAttestationData signing_root (D28)"
                .to_owned()
        })?;
    let proposer_preferences_signing_root =
        artifact.signing_roots.get("ProposerPreferences").cloned().ok_or_else(|| {
            "blocked: signing_roots.yaml missing ProposerPreferences signing_root (D28)".to_owned()
        })?;
    Ok(GloasKat { containers, payload_attestation_signing_root, proposer_preferences_signing_root })
}

struct IslandSigningKat {
    rows: Vec<(&'static str, String)>,
    argv_flip_signing_root: String,
}

fn resolve_island_signing_kat(
    artifact: &SigningRootsArtifact,
    pin: &GeneratedPin,
) -> Result<IslandSigningKat, String> {
    if pin.python.is_empty() {
        return Err(format!(
            "vectors.lock [[generated]] id={GLOAS_SIGNING_ROOTS_ID} missing python"
        ));
    }
    if pin.argv.is_empty() {
        return Err(format!("vectors.lock [[generated]] id={GLOAS_SIGNING_ROOTS_ID} missing argv"));
    }
    if !pin.argv.contains("--fork-version") || !pin.argv.contains("--genesis-validators-root") {
        return Err(
            "gloas signing-roots argv must record --fork-version and --genesis-validators-root"
                .into(),
        );
    }
    if pin.argv.contains("gloas_fork_version") {
        return Err("gloas signing-roots argv must not name an rs-vc symbol".into());
    }
    if !artifact.argv.is_empty() && artifact.argv != pin.argv {
        return Err(format!(
            "island YAML argv does not match vectors.lock argv (yaml {} lock {})",
            artifact.argv, pin.argv
        ));
    }
    if !artifact.python.is_empty() && artifact.python != pin.python {
        return Err(format!(
            "island YAML python does not match vectors.lock python (yaml {} lock {})",
            artifact.python, pin.python
        ));
    }
    let mut rows = Vec::new();
    for (name, const_name) in GLOAS_SIGNING_KAT {
        let hex = artifact.signing_roots.get(*name).cloned().ok_or_else(|| {
            format!("blocked: {GLOAS_SIGNING_ROOTS_ID} missing {name} signing_root (D28)")
        })?;
        rows.push((*const_name, hex));
    }
    let argv_flip_signing_root = artifact.argv_flip_signing_root.clone().ok_or_else(|| {
        "blocked: island signing_roots.yaml missing argv_flip_signing_root (argv sensitivity)"
            .to_owned()
    })?;
    if Some(&argv_flip_signing_root) == rows.first().map(|(_, hex)| hex) {
        return Err("argv_flip_signing_root must differ from KAT_GLOAS_BLOCK_SIGNING_ROOT".into());
    }
    Ok(IslandSigningKat { rows, argv_flip_signing_root })
}

struct RenderGloasSigningInput<'a> {
    date: &'a str,
    source: &'a str,
    pin: &'a GeneratedPin,
    generator: &'a str,
    artifact: &'a SigningRootsArtifact,
    kat: &'a IslandSigningKat,
}

fn render_gloas_signing_kat(input: &RenderGloasSigningInput<'_>) -> Result<String, String> {
    let mut out = String::new();
    writeln!(out, "//! Generated Gloas island L3 signing-root KATs. Do not edit by hand.")
        .map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! Regenerate with `make spec-kat`.").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! # Provenance").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! provenance-source: {}", input.source).map_err(write_err)?;
    let revision = if input.artifact.spec_tag.is_empty() {
        input.source.to_owned()
    } else {
        format!("ethereum/consensus-specs@{}", input.artifact.spec_tag)
    };
    writeln!(out, "//! provenance-pyspec-revision: {revision}").map_err(write_err)?;
    let ssz = if input.artifact.package.is_empty() {
        "eth-ssz-specs==0.1.0".to_owned()
    } else {
        input.artifact.package.clone()
    };
    writeln!(out, "//! provenance-eth-ssz-specs: {ssz}").map_err(write_err)?;
    writeln!(out, "//! provenance-python: {}", input.pin.python).map_err(write_err)?;
    writeln!(out, "//! provenance-argv: {}", input.pin.argv).map_err(write_err)?;
    writeln!(out, "//! provenance-generated: id={} sha256={}", input.pin.id, input.pin.sha256)
        .map_err(write_err)?;
    writeln!(out, "//! provenance-generator: {}", input.generator).map_err(write_err)?;
    writeln!(out, "{PROVENANCE_DATE_PREFIX} {}", input.date).map_err(write_err)?;
    writeln!(out, "//! provenance-input: {} sha256:{}", input.pin.output, input.pin.sha256)
        .map_err(write_err)?;
    if !input.artifact.input_sha256.is_empty() {
        writeln!(
            out,
            "//! provenance-input-spec: phase0+gloas beacon-chain.md sha256:{}",
            input.artifact.input_sha256
        )
        .map_err(write_err)?;
    }
    if !input.artifact.fork_version.is_empty() {
        writeln!(out, "//! provenance-fork-version: {}", input.artifact.fork_version)
            .map_err(write_err)?;
    }
    if !input.artifact.genesis_validators_root.is_empty() {
        writeln!(
            out,
            "//! provenance-genesis-validators-root: {}",
            input.artifact.genesis_validators_root
        )
        .map_err(write_err)?;
    }
    writeln!(out).map_err(write_err)?;

    let docs = [
        "BeaconBlock signing root under DOMAIN_BEACON_PROPOSER, copied from the pyspec artifact.",
        "AggregateAndProof signing root under DOMAIN_AGGREGATE_AND_PROOF, copied from the pyspec artifact.",
        "ExecutionPayloadEnvelope signing root under DOMAIN_BEACON_BUILDER, copied from the pyspec artifact.",
        "AttestationData signing root (index = 1) under DOMAIN_BEACON_ATTESTER, copied from the pyspec artifact.",
    ];
    for ((name, hex), doc) in input.kat.rows.iter().zip(docs) {
        emit_hex_const(&mut out, name, hex, doc)?;
    }
    emit_hex_const(
        &mut out,
        "GLOAS_SIGNING_ROOT_ARGV_FLIP_WITNESS",
        &input.kat.argv_flip_signing_root,
        "BeaconBlock signing root with argv --fork-version last byte xor 1 (not a KAT).",
    )?;
    Ok(format!("{}\n", out.trim_end()))
}

struct RenderInput<'a> {
    date: &'a str,
    source: &'a str,
    generated: &'a [GeneratedPin],
    generator: &'a str,
    inputs: &'a [InputHash],
    parsed: &'a ProgressiveVectors,
    gloas: &'a GloasKat,
}

fn render(input: &RenderInput<'_>) -> Result<String, String> {
    let mut out = String::new();
    writeln!(out, "//! Generated KAT constants. Do not edit by hand.").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! Regenerate with `make spec-kat`.").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! # Provenance").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! provenance-source: {}", input.source).map_err(write_err)?;
    if input.generated.is_empty() {
        return Err("no [[generated]] pins in provenance header".into());
    }
    for pin in input.generated {
        writeln!(out, "//! provenance-generated: id={} sha256={}", pin.id, pin.sha256)
            .map_err(write_err)?;
    }
    writeln!(out, "//! provenance-generator: {}", input.generator).map_err(write_err)?;
    writeln!(out, "{PROVENANCE_DATE_PREFIX} {}", input.date).map_err(write_err)?;
    if input.inputs.is_empty() {
        return Err("no provenance inputs hashed".into());
    }
    for item in input.inputs {
        writeln!(out, "//! provenance-input: {} sha256:{}", item.rel, item.sha256)
            .map_err(write_err)?;
    }
    writeln!(out).map_err(write_err)?;

    writeln!(out, "/// Chunk counts from eth-ssz-specs `PROGRESSIVE_CHUNK_COUNTS` (issue 3.4a).")
        .map_err(write_err)?;
    write!(out, "pub const SPEC_PROGRESSIVE_CHUNK_COUNTS: &[u32] = &[").map_err(write_err)?;
    for (i, count) in REQUIRED_CHUNK_COUNTS.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").map_err(write_err)?;
        }
        write!(out, "{count}").map_err(write_err)?;
    }
    writeln!(out, "];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    writeln!(
        out,
        "/// Active-field widths 3 / 4 / 13 (`IndexedAttestation` / `Attestation` / `BeaconBlockBody`)."
    )
    .map_err(write_err)?;
    writeln!(out, "pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS: &[u32] = &[3, 4, 13];")
        .map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    for count in REQUIRED_CHUNK_COUNTS {
        let hex = &input.parsed.merkleize[count];
        let name = format!("SPEC_PROGRESSIVE_CHUNKS_{count}");
        emit_hex_const(
            &mut out,
            &name,
            hex,
            &format!("`merkleize_progressive(chunk_run({count}))` from the 3.4b pyspec artifact."),
        )?;
    }

    writeln!(
        out,
        "/// `(chunk_count, root_hex)` pairs, same order as [`SPEC_PROGRESSIVE_CHUNK_COUNTS`]."
    )
    .map_err(write_err)?;
    writeln!(out, "pub const SPEC_PROGRESSIVE_CHUNK_ROOTS: &[(u32, &str)] = &[")
        .map_err(write_err)?;
    for count in REQUIRED_CHUNK_COUNTS {
        writeln!(out, "    ({count}, SPEC_PROGRESSIVE_CHUNKS_{count}),").map_err(write_err)?;
    }
    writeln!(out, "];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    let mut mix_const_names = Vec::new();
    for ((width, pattern), hex) in &input.parsed.mix_in {
        if !REQUIRED_WIDTHS.contains(width) || !REQUIRED_PATTERNS.contains(&pattern.as_str()) {
            continue;
        }
        let ident_pattern = pattern.to_ascii_uppercase();
        let name = format!("SPEC_PROGRESSIVE_ACTIVE_FIELDS_{width}_{ident_pattern}");
        emit_hex_const(
            &mut out,
            &name,
            hex,
            &format!(
                "`mix_in_active_fields(sample_root, {pattern})` at width {width} from the 3.4b pyspec artifact."
            ),
        )?;
        mix_const_names.push((*width, pattern.clone(), name));
    }

    writeln!(
        out,
        "/// `(width, pattern, root_hex)` pairs for widths 3 / 4 / 13 (all-ones + bit-0-clear sparse)."
    )
    .map_err(write_err)?;
    writeln!(out, "pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS: &[(u32, &str, &str)] = &[")
        .map_err(write_err)?;
    for (width, pattern, name) in &mix_const_names {
        writeln!(out, "    ({width}, \"{pattern}\", {name}),").map_err(write_err)?;
    }
    writeln!(out, "];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    for item in &input.gloas.containers {
        emit_hex_const(
            &mut out,
            item.const_name,
            &item.hex,
            &format!("{} hash tree root from {}.", item.container, item.source),
        )?;
    }

    emit_hex_const(
        &mut out,
        "KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT",
        &input.gloas.payload_attestation_signing_root,
        "PayloadAttestationData signing root copied from the 4.0 pyspec artifact.",
    )?;
    emit_hex_const(
        &mut out,
        "KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT",
        &input.gloas.proposer_preferences_signing_root,
        "ProposerPreferences signing root copied from the 4.0 pyspec artifact.",
    )?;

    Ok(format!("{}\n", out.trim_end()))
}

fn emit_hex_const(out: &mut String, name: &str, hex: &str, doc: &str) -> Result<(), String> {
    writeln!(out, "/// {doc}").map_err(write_err)?;
    writeln!(out, "pub const {name}: &str =").map_err(write_err)?;
    writeln!(out, "    \"{hex}\";").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;
    Ok(())
}

struct IslandCase {
    type_name: &'static str,
    suffix: String,
    root_hex: String,
    ssz_hex: String,
    rel: String,
}

struct IslandFamily {
    preset: &'static str,
    cases: Vec<IslandCase>,
}

struct IslandRenderInput<'a> {
    date: &'a str,
    source: &'a str,
    generated: &'a [GeneratedPin],
    generator: &'a str,
    inputs: &'a [InputHash],
    parsed: &'a ProgressiveVectors,
    families: &'a [IslandFamily],
    residuals: &'a [String],
}

fn render_island(input: &IslandRenderInput<'_>) -> Result<String, String> {
    let mut out = String::new();
    writeln!(out, "//! Generated KAT constants. Do not edit by hand.").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! Regenerate with `make spec-kat`.").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! # Provenance").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! provenance-source: {}", input.source).map_err(write_err)?;
    if input.generated.is_empty() {
        return Err("no [[generated]] pins in provenance header".into());
    }
    for pin in input.generated {
        writeln!(out, "//! provenance-generated: id={} sha256={}", pin.id, pin.sha256)
            .map_err(write_err)?;
    }
    writeln!(out, "//! provenance-generator: {}", input.generator).map_err(write_err)?;
    writeln!(out, "{PROVENANCE_DATE_PREFIX} {}", input.date).map_err(write_err)?;
    if input.inputs.is_empty() {
        return Err("no provenance inputs hashed".into());
    }
    for item in input.inputs {
        writeln!(out, "//! provenance-input: {} sha256:{}", item.rel, item.sha256)
            .map_err(write_err)?;
    }
    writeln!(out, "//!").map_err(write_err)?;
    writeln!(out, "//! # Residuals").map_err(write_err)?;
    writeln!(out, "//!").map_err(write_err)?;
    if input.residuals.is_empty() {
        writeln!(
            out,
            "//! residual: none — every island container has an official ssz_static case"
        )
        .map_err(write_err)?;
    } else {
        for line in input.residuals {
            writeln!(out, "//! residual: {line}").map_err(write_err)?;
        }
    }
    writeln!(out).map_err(write_err)?;
    writeln!(out, "#![allow(dead_code)]").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    if input.families.len() != GLOAS_PRESETS.len() {
        return Err("gloas families must cover both presets".into());
    }
    for family in input.families {
        writeln!(out, "pub mod {} {{", family.preset).map_err(write_err)?;
        render_island_progressive(&mut out, input.parsed)?;
        render_island_family(&mut out, family)?;
        trim_trailing_blank(&mut out);
        writeln!(out, "}}").map_err(write_err)?;
        writeln!(out).map_err(write_err)?;
    }
    writeln!(out, "pub use minimal::*;").map_err(write_err)?;
    Ok(out)
}

fn render_island_progressive(out: &mut String, parsed: &ProgressiveVectors) -> Result<(), String> {
    let indent = "    ";
    for width in GLOAS_WIDTHS {
        for pattern in REQUIRED_PATTERNS {
            if !parsed.mix_in.contains_key(&(*width, (*pattern).to_owned())) {
                return Err(format!(
                    "3.4b artifact missing mix_in_active_fields width {width} pattern {pattern}"
                ));
            }
        }
    }

    writeln!(
        out,
        "{indent}/// Chunk counts from eth-ssz-specs `PROGRESSIVE_CHUNK_COUNTS` (issue 3.4a)."
    )
    .map_err(write_err)?;
    write!(out, "{indent}pub const SPEC_PROGRESSIVE_CHUNK_COUNTS: &[u32] = &[")
        .map_err(write_err)?;
    for (i, count) in REQUIRED_CHUNK_COUNTS.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").map_err(write_err)?;
        }
        write!(out, "{count}").map_err(write_err)?;
    }
    writeln!(out, "];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    writeln!(
        out,
        "{indent}/// Active-field widths 3 / 4 / 5 / 13 (`IndexedAttestation` / `Attestation` / `ExecutionRequests` / `BeaconBlockBody`)."
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "{indent}pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS: &[u32] = &[3, 4, 5, 13];"
    )
    .map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    for count in REQUIRED_CHUNK_COUNTS {
        let hex = &parsed.merkleize[count];
        let name = format!("SPEC_PROGRESSIVE_CHUNKS_{count}");
        emit_str_const(
            out,
            indent,
            &name,
            hex,
            &format!("`merkleize_progressive(chunk_run({count}))` from the 3.4b pyspec artifact."),
        )?;
    }

    writeln!(
        out,
        "{indent}/// `(chunk_count, root_hex)` pairs, same order as [`SPEC_PROGRESSIVE_CHUNK_COUNTS`]."
    )
    .map_err(write_err)?;
    writeln!(out, "{indent}pub const SPEC_PROGRESSIVE_CHUNK_ROOTS: &[(u32, &str)] = &[")
        .map_err(write_err)?;
    for count in REQUIRED_CHUNK_COUNTS {
        writeln!(out, "{indent}    ({count}, SPEC_PROGRESSIVE_CHUNKS_{count}),")
            .map_err(write_err)?;
    }
    writeln!(out, "{indent}];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    let mut mix_const_names = Vec::new();
    for width in GLOAS_WIDTHS {
        for pattern in REQUIRED_PATTERNS {
            let hex = &parsed.mix_in[&(*width, (*pattern).to_owned())];
            let ident_pattern = pattern.to_ascii_uppercase();
            let name = format!("SPEC_PROGRESSIVE_ACTIVE_FIELDS_{width}_{ident_pattern}");
            emit_str_const(
                out,
                indent,
                &name,
                hex,
                &format!(
                    "`mix_in_active_fields(sample_root, {pattern})` at width {width} from the 3.4b pyspec artifact."
                ),
            )?;
            mix_const_names.push((*width, *pattern, name));
        }
    }

    writeln!(
        out,
        "{indent}/// `(width, pattern, root_hex)` pairs for widths 3 / 4 / 5 / 13 (all-ones + bit-0-clear sparse)."
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "{indent}pub const SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS: &[(u32, &str, &str)] = &["
    )
    .map_err(write_err)?;
    for (width, pattern, name) in &mix_const_names {
        writeln!(out, "{indent}    ({width}, \"{pattern}\", {name}),").map_err(write_err)?;
    }
    writeln!(out, "{indent}];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;
    Ok(())
}

fn render_island_family(out: &mut String, family: &IslandFamily) -> Result<(), String> {
    let indent = "    ";
    writeln!(out, "{indent}/// Official `ssz_static` suite selected for Gloas KATs.")
        .map_err(write_err)?;
    writeln!(out, "{indent}pub const SPEC_GLOAS_SUITE: &str = \"{GLOAS_SUITE}\";")
        .map_err(write_err)?;
    writeln!(out).map_err(write_err)?;
    writeln!(out, "{indent}/// Official `ssz_static` case selected for Gloas KATs.")
        .map_err(write_err)?;
    writeln!(out, "{indent}pub const SPEC_GLOAS_CASE: &str = \"{GLOAS_CASE}\";")
        .map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    writeln!(out, "{indent}/// `SPEC_GLOAS_<TYPE>_ROOT` constant names in this module.")
        .map_err(write_err)?;
    writeln!(out, "{indent}pub const SPEC_GLOAS_ROOT_NAMES: &[&str] = &[").map_err(write_err)?;
    for case in &family.cases {
        writeln!(out, "{indent}    \"SPEC_GLOAS_{}_ROOT\",", case.suffix).map_err(write_err)?;
    }
    writeln!(out, "{indent}];").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    for case in &family.cases {
        emit_str_const(
            out,
            indent,
            &format!("SPEC_GLOAS_{}_ROOT", case.suffix),
            &case.root_hex,
            &format!(
                "Official `ssz_static` `{}` root from `{}` (preset {}).",
                case.type_name, case.rel, family.preset
            ),
        )?;
        emit_long_hex_const(
            out,
            indent,
            &format!("SPEC_GLOAS_{}_SSZ", case.suffix),
            &case.ssz_hex,
            &format!(
                "Decoded `serialized.ssz_snappy` for `{}` from `{}` (preset {}, lowercase hex).",
                case.type_name, case.rel, family.preset
            ),
        )?;
    }
    Ok(())
}

fn emit_str_const(
    out: &mut String,
    indent: &str,
    name: &str,
    value: &str,
    doc: &str,
) -> Result<(), String> {
    writeln!(out, "{indent}/// {doc}").map_err(write_err)?;
    let one_line = format!("{indent}pub const {name}: &str = \"{value}\";");
    if one_line.len() <= 100 {
        writeln!(out, "{one_line}").map_err(write_err)?;
    } else {
        writeln!(out, "{indent}pub const {name}: &str =").map_err(write_err)?;
        writeln!(out, "{indent}    \"{value}\";").map_err(write_err)?;
    }
    writeln!(out).map_err(write_err)?;
    Ok(())
}

fn emit_long_hex_const(
    out: &mut String,
    indent: &str,
    name: &str,
    hex: &str,
    doc: &str,
) -> Result<(), String> {
    if hex.len() <= 64 {
        return emit_str_const(out, indent, name, hex, doc);
    }
    writeln!(out, "{indent}/// {doc}").map_err(write_err)?;
    writeln!(out, "{indent}pub const {name}: &str = concat!(").map_err(write_err)?;
    for chunk in hex.as_bytes().chunks(64) {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("ssz hex utf8: {e}"))?;
        writeln!(out, "{indent}    \"{s}\",").map_err(write_err)?;
    }
    writeln!(out, "{indent});").map_err(write_err)?;
    writeln!(out).map_err(write_err)?;
    Ok(())
}

fn trim_trailing_blank(out: &mut String) {
    if out.ends_with("\n\n") {
        out.pop();
    }
}

fn write_stable(path: &Path, body: &str) -> Result<(), String> {
    let existing = fs::read_to_string(path).ok();
    let out_text = match existing {
        Some(old) if with_date_placeholder(&old) == body => old,
        _ => body.replace(
            &format!("{PROVENANCE_DATE_PREFIX} {DATE_PLACEHOLDER}"),
            &format!("{PROVENANCE_DATE_PREFIX} {}", today_utc()?),
        ),
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }
    fs::write(path, out_text).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn camel_to_screaming(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev.is_lowercase() || (prev.is_uppercase() && next_lower) {
                out.push('_');
            }
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

fn emitted_gloas_root_const_names(src: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("pub const SPEC_GLOAS_") else {
            continue;
        };
        let Some(name) = rest.split(':').next() else {
            continue;
        };
        if name.ends_with("_ROOT") {
            names.insert(format!("SPEC_GLOAS_{name}"));
        }
    }
    names
}

fn refuse_dropped_gloas_names(path: &Path, families: &[IslandFamily]) -> Result<(), String> {
    let Ok(old) = fs::read_to_string(path) else {
        return Ok(());
    };
    let prev = emitted_gloas_root_const_names(&old);
    if prev.is_empty() {
        return Ok(());
    }
    let next: BTreeSet<String> = families
        .iter()
        .flat_map(|f| f.cases.iter().map(|c| format!("SPEC_GLOAS_{}_ROOT", c.suffix)))
        .collect();
    let missing: Vec<String> = prev.difference(&next).cloned().collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "refusing to drop previously emitted Gloas KAT names in {}: {}",
        path.display(),
        missing.join(", ")
    ))
}

struct RawGloasFiles {
    roots: Option<Vec<u8>>,
    ssz: Option<Vec<u8>>,
}

type GloasCollect = (Vec<IslandFamily>, Vec<String>, Vec<InputHash>);

fn collect_gloas(
    workspace: &Path,
    gloas_vectors: &Path,
    progressive: &Path,
    parsed: &ProgressiveVectors,
) -> Result<GloasCollect, String> {
    for width in GLOAS_WIDTHS {
        for pattern in REQUIRED_PATTERNS {
            if !parsed.mix_in.contains_key(&(*width, (*pattern).to_owned())) {
                return Err(format!(
                    "3.4b artifact missing mix_in_active_fields width {width} pattern {pattern} (needed for Gloas SPEC_PROGRESSIVE_*)"
                ));
            }
        }
    }

    let mut files: BTreeMap<(&'static str, &'static str), RawGloasFiles> = BTreeMap::new();
    let mut hashed = Vec::new();
    push_input(&mut hashed, workspace, progressive)?;

    let mut used_archives = false;
    for preset in GLOAS_PRESETS {
        let archive = gloas_vectors.join(format!("{preset}.tar.gz"));
        if archive.is_file() {
            refuse_symlink(&archive)?;
            push_input(&mut hashed, workspace, &archive)?;
            load_gloas_from_tar(&archive, preset, &mut files)?;
            used_archives = true;
        }
    }
    if !used_archives {
        load_gloas_from_tree(gloas_vectors, &mut files)?;
        for ((preset, type_name), raw) in &files {
            let rel_dir = format!(
                "tests/{preset}/{GLOAS_FORK}/{SSZ_STATIC}/{type_name}/{GLOAS_SUITE}/{GLOAS_CASE}"
            );
            let roots_path = gloas_vectors.join(&rel_dir).join("roots.yaml");
            let ssz_path = gloas_vectors.join(&rel_dir).join("serialized.ssz_snappy");
            if raw.roots.is_some() && roots_path.is_file() {
                push_input(&mut hashed, workspace, &roots_path)?;
            }
            if raw.ssz.is_some() && ssz_path.is_file() {
                push_input(&mut hashed, workspace, &ssz_path)?;
            }
        }
    }

    hashed.sort_by(|a, b| a.rel.cmp(&b.rel));
    hashed.dedup_by(|a, b| a.rel == b.rel);

    let mut residuals = Vec::new();
    let mut families = Vec::new();
    for preset in GLOAS_PRESETS {
        let mut cases = Vec::new();
        for type_name in GLOAS_TYPES {
            match files.get(&(*preset, *type_name)) {
                Some(raw) if raw.roots.is_some() && raw.ssz.is_some() => {
                    let roots_bytes = raw
                        .roots
                        .as_ref()
                        .ok_or_else(|| format!("{preset}/{type_name} missing roots.yaml"))?;
                    let roots_text = String::from_utf8(roots_bytes.clone())
                        .map_err(|e| format!("{preset}/{type_name} roots.yaml utf8: {e}"))?;
                    let parsed_roots = roots_yaml(&roots_text)
                        .map_err(|e| format!("{preset}/{type_name} roots.yaml: {e}"))?;
                    let root_hex = normalize_root_hex(&parsed_roots.root)?;
                    let snappy = raw
                        .ssz
                        .as_ref()
                        .ok_or_else(|| format!("{preset}/{type_name} missing serialized.ssz_snappy"))?;
                    let ssz = decode_snappy(snappy)
                        .map_err(|e| format!("{preset}/{type_name} snappy: {e}"))?;
                    let rel = format!(
                        "tests/{preset}/{GLOAS_FORK}/{SSZ_STATIC}/{type_name}/{GLOAS_SUITE}/{GLOAS_CASE}"
                    );
                    cases.push(IslandCase {
                        type_name,
                        suffix: camel_to_screaming(type_name),
                        root_hex,
                        ssz_hex: hex::encode(ssz),
                        rel,
                    });
                }
                _ => residuals.push(format!(
                    "{type_name} ({preset}) — official ssz_static {GLOAS_SUITE}/{GLOAS_CASE} missing at SPEC_TAG; not synthesized"
                )),
            }
        }
        families.push(IslandFamily { preset, cases });
    }

    let names: Vec<Vec<String>> =
        families.iter().map(|f| f.cases.iter().map(|c| c.suffix.clone()).collect()).collect();
    if names.len() == 2 && names[0] != names[1] {
        return Err(format!(
            "gloas ssz_static type set differs between presets (refusing to drop names): minimal={:?} mainnet={:?}",
            names[0], names[1]
        ));
    }

    if families.iter().any(|f| !f.cases.iter().any(|c| c.type_name == "SyncAggregate")) {
        return Err(
            "SyncAggregate ssz_static case missing in a preset; cannot emit SPEC_GLOAS_SYNC_AGGREGATE_ROOT"
                .into(),
        );
    }

    residuals.sort();
    residuals.dedup();
    Ok((families, residuals, hashed))
}

fn load_gloas_from_tree(
    root: &Path,
    files: &mut BTreeMap<(&'static str, &'static str), RawGloasFiles>,
) -> Result<(), String> {
    for preset in GLOAS_PRESETS {
        for type_name in GLOAS_TYPES {
            let dir = root
                .join("tests")
                .join(preset)
                .join(GLOAS_FORK)
                .join(SSZ_STATIC)
                .join(type_name)
                .join(GLOAS_SUITE)
                .join(GLOAS_CASE);
            if !dir.is_dir() {
                continue;
            }
            refuse_symlink(&dir)?;
            let roots_path = dir.join("roots.yaml");
            let ssz_path = dir.join("serialized.ssz_snappy");
            let mut raw = RawGloasFiles { roots: None, ssz: None };
            if roots_path.is_file() {
                refuse_symlink(&roots_path)?;
                raw.roots = Some(
                    fs::read(&roots_path)
                        .map_err(|e| format!("read {}: {e}", roots_path.display()))?,
                );
            }
            if ssz_path.is_file() {
                refuse_symlink(&ssz_path)?;
                raw.ssz = Some(
                    fs::read(&ssz_path).map_err(|e| format!("read {}: {e}", ssz_path.display()))?,
                );
            }
            files.insert((*preset, *type_name), raw);
        }
    }
    Ok(())
}

fn load_gloas_from_tar(
    archive: &Path,
    preset: &'static str,
    files: &mut BTreeMap<(&'static str, &'static str), RawGloasFiles>,
) -> Result<(), String> {
    let file = fs::File::open(archive).map_err(|e| format!("open {}: {e}", archive.display()))?;
    let dec = GzDecoder::new(file);
    let mut tar = Archive::new(dec);
    let entries = tar.entries().map_err(|e| format!("read {}: {e}", archive.display()))?;
    for ent in entries {
        let mut ent = ent.map_err(|e| format!("read {}: {e}", archive.display()))?;
        if ent.header().entry_type().is_symlink() {
            return Err(format!(
                "refusing symlink member in {}: {}",
                archive.display(),
                ent.path().map(|p| p.display().to_string()).unwrap_or_default()
            ));
        }
        let path = ent.path().map_err(|e| format!("tar member path: {e}"))?;
        let rel = path.to_string_lossy().replace('\\', "/");
        let rel = rel.trim_start_matches("./");
        let Some((type_name, kind)) = match_gloas_member(rel, preset) else {
            continue;
        };
        let mut buf = Vec::new();
        ent.read_to_end(&mut buf).map_err(|e| format!("read {rel}: {e}"))?;
        let raw =
            files.entry((preset, type_name)).or_insert(RawGloasFiles { roots: None, ssz: None });
        match kind {
            "roots" => raw.roots = Some(buf),
            "ssz" => raw.ssz = Some(buf),
            _ => {}
        }
    }
    Ok(())
}

fn match_gloas_member(rel: &str, preset: &str) -> Option<(&'static str, &'static str)> {
    let prefix = format!("tests/{preset}/{GLOAS_FORK}/{SSZ_STATIC}/");
    let rest = rel.strip_prefix(&prefix)?;
    let mut parts = rest.split('/');
    let type_name = parts.next()?;
    let suite = parts.next()?;
    let case = parts.next()?;
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if suite != GLOAS_SUITE || case != GLOAS_CASE {
        return None;
    }
    let type_name = GLOAS_TYPES.iter().copied().find(|t| *t == type_name)?;
    let kind = if file == "roots.yaml" {
        "roots"
    } else if file == "serialized.ssz_snappy" || file.ends_with(SSZ_SNAPPY_SUFFIX) {
        "ssz"
    } else {
        return None;
    };
    Some((type_name, kind))
}

fn write_err(e: std::fmt::Error) -> String {
    format!("write generated source: {e}")
}

fn with_date_placeholder(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        if line.starts_with(PROVENANCE_DATE_PREFIX) {
            let _ = writeln!(out, "{PROVENANCE_DATE_PREFIX} {DATE_PLACEHOLDER}");
        } else {
            let _ = writeln!(out, "{line}");
        }
    }
    out
}

fn today_utc() -> Result<String, String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before epoch: {e}"))?
        .as_secs();
    let (y, m, d) = utc_ymd_from_unix_secs(secs);
    Ok(format!("{y:04}-{m:02}-{d:02}"))
}

/// Howard Hinnant `civil_from_days` on Unix epoch days.
fn utc_ymd_from_unix_secs(secs: u64) -> (i32, u8, u8) {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    (y, m as u8, d as u8)
}

fn read_to_string(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}
