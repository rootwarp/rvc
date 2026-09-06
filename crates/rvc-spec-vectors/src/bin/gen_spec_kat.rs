//! Emit `spec_kat.rs` (`SPEC_PROGRESSIVE_*`, `SPEC_GLOAS_*`, `KAT_GLOAS_*`)
//! from vector files.
//!
//! Argv only: `--vectors <dir> --out <path>`. L1 roots are copied from the
//! 3.4b pyspec artifact (`vectors-generated/progressive/roots.yaml`), never
//! from shipped JSON `root` fields (`mix_in_length`-wrapped). Gloas container
//! roots come from `ssz_static/<Container>/**/roots.yaml` when present, else
//! the 4.0 pyspec artifact. L3 signing roots are copied from
//! `gen_signing_roots.py` output; this binary never computes a domain.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

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
const REQUIRED_PATTERNS: &[&str] = &["all_ones", "sparse_bit0_clear"];

const ZERO_ROOT_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const PROGRESSIVE_ID: &str = "progressive";
const SIGNING_ROOTS_ID: &str = "signing-roots";

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
            eprintln!("usage: {GENERATOR_NAME} --vectors <dir> --out <path>");
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

    let mut inputs = Vec::new();
    let mut progressive_parsed = None;
    let mut signing_artifact = None;
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
        push_input(&mut inputs, &workspace, &path)?;
    }
    let parsed = progressive_parsed
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={PROGRESSIVE_ID}"))?;
    let signing = signing_artifact
        .ok_or_else(|| format!("vectors.lock [[generated]] missing id={SIGNING_ROOTS_ID}"))?;

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

    let existing = fs::read_to_string(&args.out).ok();
    let out_text = match existing {
        Some(old) if with_date_placeholder(&old) == body => old,
        _ => body.replace(
            &format!("{PROVENANCE_DATE_PREFIX} {DATE_PLACEHOLDER}"),
            &format!("{PROVENANCE_DATE_PREFIX} {}", today_utc()?),
        ),
    };

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }
    fs::write(&args.out, out_text).map_err(|e| format!("write {}: {e}", args.out.display()))?;
    Ok(())
}

struct Args {
    vectors: PathBuf,
    out: PathBuf,
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut args = args.into_iter();
    let _argv0 = args.next();
    let mut vectors = None;
    let mut out = None;
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
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(Args {
        vectors: vectors.ok_or("missing --vectors <dir>")?,
        out: out.ok_or("missing --out <path>")?,
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

struct GeneratedPin {
    id: String,
    output: String,
    sha256: String,
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
) -> Result<GeneratedPin, String> {
    match (id, output, sha256) {
        (Some(id), Some(output), Some(sha256))
            if !id.is_empty()
                && !output.is_empty()
                && sha256.len() == 64
                && sha256.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(GeneratedPin { id, output, sha256 })
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
    let mut flush = |id: &mut Option<String>,
                     output: &mut Option<String>,
                     sha256: &mut Option<String>|
     -> Result<(), String> {
        if id.is_none() && output.is_none() && sha256.is_none() {
            return Ok(());
        }
        pins.push(finish_generated_pin(id.take(), output.take(), sha256.take())?);
        Ok(())
    };
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[generated]]" {
            flush(&mut id, &mut output, &mut sha256)?;
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if line.is_empty() || line.starts_with("[[") || line.starts_with("archive ") {
            flush(&mut id, &mut output, &mut sha256)?;
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
        }
    }
    flush(&mut id, &mut output, &mut sha256)?;
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
}

fn parse_signing_roots_artifact(text: &str) -> Result<SigningRootsArtifact, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("parse signing_roots.yaml: {e}"))?;
    let mapping = value.as_mapping().ok_or("signing_roots.yaml must be a mapping")?;
    let seq = yaml_seq(mapping, "containers")?;
    let mut containers = BTreeMap::new();
    let mut signing_roots = BTreeMap::new();
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
            signing_roots.insert(name, signing);
        }
    }
    Ok(SigningRootsArtifact { containers, signing_roots })
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
