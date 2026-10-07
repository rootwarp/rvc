//! G-2 / ARCH-P1-1 config-drift gate — clauses (iii) and (iv), plus an
//! `apply_cli` presence scan (successor to clause (ii), no bypass/alias tables).
//!
//! ## Retired tables (ARCH-4k)
//!
//! Original seam α was group `Args` → `From<StartArgs>` / `CliOverrides` /
//! `merge_with_cli`. ARCH-4i deleted that **translation**. The tables that
//! existed only for it (`BYPASS`, `ALIASES`) and the `bindings.len() == 13` /
//! `checked == 74` non-vacuity checks were deleted here (R10: do not leave a
//! gate that can only ever be green).
//!
//! `From<StartArgs>` / `CliOverrides` is gone. `Config::apply_cli` remains a
//! **field-access overlay**: `StartArgs`' destructure is exhaustive over
//! groups, not fields, so rustc will not fail a new clap leaf that `apply_cli`
//! never writes. That overlay is **not** rustc-guarded; the presence scan
//! below is what keeps it falsifiable.
//!
//! ## apply_cli presence scan
//!
//! Every clap leaf field must appear as an identifier-bounded
//! `{section}.{field}` access in `Config::apply_cli`, or be listed on
//! [`CLI_ONLY_ARGS`]. No bypass/alias tables. The four CLI-only names must
//! still have a second-leg read in `bin/rvc/src/cli.rs`.
//!
//! ## Clause (iii) — validation coverage
//!
//! Every operator knob — a **section-struct field path** in `rvc-config`
//! (plus the six wrapper knobs on `start.rs`) — appears in `Config::validate`
//! (`types.rs`) **or** on the shrinking-only [`UNVALIDATED`] list. Inventory is
//! **72** (`OPERATOR_KNOB_NAMES` in `crates/rvc/src/config/knobs.rs`). Adding
//! a section field without a check or a list entry fails CI.
//!
//! ## Clause (iv) — clap default clobber (ADR-009 / F9)
//!
//! [`CLAP_DEFAULT_CLOBBERS`] is **empty** (Phase 1 / ARCH-6b) and must stay
//! empty. The live property is structural: no `clap::Args` field in
//! `rvc-config` has both a `default_value` / `default_value_t` and a
//! non-`Option` type. Present-only `bool` + `default_value_t` + exact
//! `#[serde(skip)]` polarity flags are excluded (`apply_cli` is present-only).
//! `serde(skip_serializing_if)` is **not** a skip. A valued non-`Option` with
//! `default_value` still fails.
//!
//! ## CLI-only args (VD-4.8)
//!
//! Four flags have **no** Config / TOML representation. They used to sit on
//! clause (ii)'s bypass table; that table is gone, so they are listed as
//! [`CLI_ONLY_ARGS`]. Losing the list would hide the only CLI-only args.
//!
//! ## Lifetime
//!
//! Interim `BYPASS` / `ALIASES` tables were retired by ARCH-4k with the
//! From/CliOverrides translation. `apply_cli` remains a manual field-access
//! overlay and is gated by the presence scan, not by rustc.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as
//! `kat_policy.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

const CLI_RS: &str = "bin/rvc/src/cli.rs";
const START_RS: &str = "crates/rvc/src/config/start.rs";
const TYPES_RS: &str = "crates/rvc/src/config/types.rs";
const KNOBS_RS: &str = "crates/rvc/src/config/knobs.rs";
const SECTIONS_DIR: &str = "crates/rvc-config/src/sections";

/// clap `*Args` groups that declare operator knobs, with the section path prefix.
const SECTION_GROUPS: &[(&str, &str)] = &[
    ("BeaconArgs", "beacon"),
    ("BuilderArgs", "builder"),
    ("BuilderLimitsArgs", "builder_limits"),
    ("DutiesArgs", "duties"),
    ("GcpSecretArgs", "secret_provider.gcp"),
    ("GrpcSignerArgs", "grpc_signer"),
    ("KeymanagerArgs", "keymanager"),
    ("KeysArgs", "keys"),
    ("LogfileArgs", "logfile"),
    ("LoggingArgs", "logging"),
    ("MonitoringArgs", "monitoring"),
    ("NetworkArgs", "network"),
    ("ProposerArgs", "proposer"),
    ("ProposerConfigArgs", "proposer_config"),
    ("SafetyArgs", "safety"),
    ("SecretProviderArgs", "secret_provider"),
    ("ServerArgs", "server"),
    ("SlashingArgs", "slashing"),
    ("TracingArgs", "tracing"),
];

/// Flags with no Config / TOML field (VD-4.8). Sorted by name.
///
/// Documented here because the clause-(ii) bypass table was deleted in ARCH-4k.
/// Each name must still have a second-leg read in `bin/rvc/src/cli.rs`.
const CLI_ONLY_ARGS: &[&str] =
    &["enable_log_reload", "log_format", "strict_permissions", "strict_slashing_semantics"];

/// clap fields that are not operator knobs: CLI-only args plus the `--no-keymanager`
/// half of the 2:1 collapse into `keymanager.enabled`.
const NOT_A_KNOB: &[&str] = &[
    "enable_log_reload",
    "log_format",
    "no_keymanager",
    "strict_permissions",
    "strict_slashing_semantics",
];

/// Clause (iv) / ADR-009. Emptied by ARCH-6b; must remain empty.
///
/// Tuple: `(field, reason)`. Sorted by field name.
const CLAP_DEFAULT_CLOBBERS: &[(&str, &str)] = &[];

/// Clause (iii): section-struct field paths whose names do **not** appear
/// (identifier-bounded) in `Config::validate`'s body.
///
/// **Shrinking-only.** Entries may be **removed** (by adding a check to
/// `validate`), never **added** without acknowledging a new unvalidated knob.
/// A new section field that is neither mentioned in `validate` nor listed here
/// fails the gate.
///
/// Tuple: `(section.path, reason)`. Sorted by path.
const UNVALIDATED: &[(&str, &str)] = &[
    ("beacon.max_body_bytes", "no field-name check in Config::validate"),
    ("builder.block_selection_mode", "no field-name check in Config::validate"),
    ("builder.validator_registration_batch_delay", "no field-name check in Config::validate"),
    ("builder.validator_registration_batch_size", "no field-name check in Config::validate"),
    ("builder_limits.circuit_breaker_consecutive_limit", "no field-name check in Config::validate"),
    ("builder_limits.circuit_breaker_epoch_limit", "no field-name check in Config::validate"),
    ("grpc_signer.tls_ca_cert", "no field-name check in Config::validate"),
    ("grpc_signer.tls_cert", "no field-name check in Config::validate"),
    ("grpc_signer.tls_key", "no field-name check in Config::validate"),
    ("grpc_signer.url", "no field-name check in Config::validate"),
    ("keymanager.address", "no field-name check in Config::validate"),
    ("keymanager.body_limit", "no field-name check in Config::validate"),
    ("keymanager.cors_origins", "no field-name check in Config::validate"),
    ("keymanager.enabled", "no field-name check in Config::validate"),
    ("keymanager.remote_signer_allowed_hosts", "no field-name check in Config::validate"),
    ("keymanager.remote_signer_url", "no field-name check in Config::validate"),
    ("keymanager.token_file", "no field-name check in Config::validate"),
    ("keys.disable_keystore_locking", "no field-name check in Config::validate"),
    ("keys.key_decrypt_threads", "no field-name check in Config::validate"),
    ("keys.keystore_path", "no field-name check in Config::validate"),
    ("keys.password_file", "no field-name check in Config::validate"),
    ("keys.validators_config", "no field-name check in Config::validate"),
    ("logfile.compress", "no field-name check in Config::validate"),
    ("logfile.level", "no field-name check in Config::validate"),
    ("logfile.max_number", "no field-name check in Config::validate"),
    ("logfile.max_size", "no field-name check in Config::validate"),
    ("logfile.path", "no field-name check in Config::validate"),
    ("logging.log_level", "no field-name check in Config::validate"),
    ("monitoring.endpoint", "no field-name check in Config::validate"),
    ("monitoring.endpoint_insecure", "no field-name check in Config::validate"),
    ("monitoring.interval", "no field-name check in Config::validate"),
    ("network.genesis_time", "checked via effective_genesis_time(); name not in validate body"),
    (
        "network.genesis_validators_root",
        "checked via effective_genesis_validators_root(); name not in validate body",
    ),
    ("network.network", "no field-name check in Config::validate"),
    ("proposer_config.refresh_interval", "no field-name check in Config::validate"),
    ("proposer_config.url_insecure", "no field-name check in Config::validate"),
    ("proposer_config.url_token", "no field-name check in Config::validate"),
    ("safety.allow_unsupported_fork", "no field-name check in Config::validate"),
    ("safety.disable_attesting", "no field-name check in Config::validate"),
    ("safety.doppelganger_detection", "no field-name check in Config::validate"),
    ("safety.slashed_validators_action", "no field-name check in Config::validate"),
    ("secret_provider.gcp.secret_prefix", "no field-name check in Config::validate"),
    ("secret_provider.refresh_interval", "no field-name check in Config::validate"),
    ("secret_provider.strict", "no field-name check in Config::validate"),
    ("server.metrics_address", "no field-name check in Config::validate"),
    ("slashing.init_slashing_db", "no field-name check in Config::validate"),
    ("slashing.slashing_db_path", "no field-name check in Config::validate"),
    ("tracing.endpoint", "no field-name check in Config::validate"),
    ("tracing.exporter", "no field-name check in Config::validate"),
    ("tracing.max_export_batch_size", "no field-name check in Config::validate"),
    ("tracing.max_queue_size", "no field-name check in Config::validate"),
    ("tracing.sample_rate", "no field-name check in Config::validate"),
    ("tracing.service_name", "no field-name check in Config::validate"),
];

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn rvc_config_sections_source(root: &Path) -> String {
    let dir = root.join(SECTIONS_DIR);
    let mut src = String::new();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{SECTIONS_DIR} must exist: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    files.sort();
    for path in files {
        src.push_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        }));
        src.push('\n');
    }
    src
}

fn operator_knob_names(src: &str) -> Vec<String> {
    let marker = "pub const OPERATOR_KNOB_NAMES";
    let start = src.find(marker).expect("OPERATOR_KNOB_NAMES must exist");
    let rest = &src[start..];
    let open = rest.find('[').expect("OPERATOR_KNOB_NAMES array");
    let close = rest.find("];").expect("OPERATOR_KNOB_NAMES terminator");
    rest[open + 1..close]
        .lines()
        .filter_map(|line| {
            let t = line.trim().trim_end_matches(',');
            t.strip_prefix('"')?.strip_suffix('"').map(str::to_string)
        })
        .collect()
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_option_type(ty: &str) -> bool {
    let t = ty.trim();
    t.starts_with("Option<") || t.starts_with("Option <")
}

/// Collapse whitespace around `.` so `foo\n    .bar` → `foo.bar`.
fn compact_ws(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let prev_is_dot = out.ends_with('.');
            let next_is_dot = j < chars.len() && chars[j] == '.';
            if !(prev_is_dot || next_is_dot) && !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Identifier-bounded `{binding}.{field}` (rejects `logfile` satisfied by `logfile_max_size`).
fn has_field_access(compact: &str, binding: &str, field: &str) -> bool {
    let needle = format!("{binding}.{field}");
    let n_bytes = needle.as_bytes();
    let hay = compact.as_bytes();
    let mut from = 0;
    while from + n_bytes.len() <= hay.len() {
        let Some(rel) = compact[from..].find(&needle) else {
            return false;
        };
        let at = from + rel;
        let after = at + n_bytes.len();
        let before_ok = at == 0 || !is_ident_char(hay[at - 1]);
        let after_ok = after >= hay.len() || !is_ident_char(hay[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Strip `//` line comments and `/* … */` block comments; blank string literals
/// so comment-only / string-only mentions cannot satisfy a presence scan.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i];
                out.push(b' ');
                i += 1;
                if ch == b'\\' && i < bytes.len() {
                    out.push(b' ');
                    i += 1;
                    continue;
                }
                if ch == b'"' {
                    break;
                }
            }
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn scan_text(src: &str) -> String {
    compact_ws(&strip_comments_and_strings(src))
}

/// Identifier-bounded presence of `name` in `text`.
fn has_ident(text: &str, name: &str) -> bool {
    let n_bytes = name.as_bytes();
    let hay = text.as_bytes();
    let mut from = 0;
    while from + n_bytes.len() <= hay.len() {
        let Some(rel) = text[from..].find(name) else {
            return false;
        };
        let at = from + rel;
        let after = at + n_bytes.len();
        let before_ok = at == 0 || !is_ident_char(hay[at - 1]);
        let after_ok = after >= hay.len() || !is_ident_char(hay[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Extraction — brace-aware, same technique as kat_policy::extract_tests
// ---------------------------------------------------------------------------

/// Body of `pub struct Name { … }` (outermost braces), or empty if not found.
fn struct_body<'a>(src: &'a str, struct_name: &str) -> Option<&'a str> {
    let needle = format!("struct {struct_name}");
    let mut from = 0;
    loop {
        let rel = src[from..].find(&needle)?;
        let at = from + rel;
        if at > 0 {
            let b = src.as_bytes()[at - 1];
            if b.is_ascii_alphanumeric() || b == b'_' {
                from = at + needle.len();
                continue;
            }
        }
        let after = &src[at + needle.len()..];
        let Some(brace_rel) = after.find('{') else {
            from = at + needle.len();
            continue;
        };
        let between = after[..brace_rel].trim();
        if !between.is_empty() {
            from = at + needle.len();
            continue;
        }
        let open = at + needle.len() + brace_rel;
        let mut depth = 0i32;
        for (i, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[open + 1..open + i]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
}

fn struct_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find("struct ") {
        let at = from + rel;
        if at > 0 {
            let b = src.as_bytes()[at - 1];
            if is_ident_char(b) {
                from = at + 7;
                continue;
            }
        }
        let after = src[at + 7..].trim_start();
        if after.is_empty() || !is_ident_start(after.as_bytes()[0]) {
            from = at + 7;
            continue;
        }
        let name: String =
            after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if !name.is_empty() {
            names.push(name);
        }
        from = at + 7;
    }
    names
}

/// Field identifiers declared directly inside `pub struct Name { … }`.
fn struct_fields(src: &str, struct_name: &str) -> Vec<String> {
    fields_with_attrs(src, struct_name).into_iter().map(|(name, _, _)| name).collect()
}

/// `(field, joined_attrs, type)` for each `pub field: Type` in `struct_name`.
///
/// Skips `#[command(flatten)]` nestings. Accumulates multi-line attributes.
fn fields_with_attrs(src: &str, struct_name: &str) -> Vec<(String, String, String)> {
    let Some(body) = struct_body(src, struct_name) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut pending_attrs = String::new();
    let mut attr_depth = 0i32;
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("#[") || attr_depth > 0 {
            pending_attrs.push_str(t);
            pending_attrs.push(' ');
            for ch in t.chars() {
                match ch {
                    '[' | '(' => attr_depth += 1,
                    ']' | ')' => attr_depth = attr_depth.saturating_sub(1),
                    _ => {}
                }
            }
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("///") {
            continue;
        }
        let attrs = std::mem::take(&mut pending_attrs);
        if attrs.contains("command(flatten)") {
            continue;
        }
        let mut rest = t;
        if let Some(r) = rest.strip_prefix("pub") {
            rest = r.trim_start();
            if let Some(r) = rest.strip_prefix('(') {
                let Some(close) = r.find(')') else {
                    continue;
                };
                rest = r[close + 1..].trim_start();
            }
        } else {
            continue;
        }
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            continue;
        }
        let after_name = rest[name.len()..].trim_start();
        if !after_name.starts_with(':') {
            continue;
        }
        let ty = after_name[1..].trim().trim_end_matches(',').trim().to_string();
        out.push((name, attrs, ty));
    }
    out
}

fn clap_id_from_attrs(attrs: &str) -> Option<String> {
    for key in ["id = \"", "long = \""] {
        if let Some(start) = attrs.find(key) {
            let rest = &attrs[start + key.len()..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].replace('-', "_"));
            }
        }
    }
    None
}

fn knob_name(field: &str, attrs: &str) -> String {
    if field == "no_doppelganger_detection" {
        return "doppelganger_detection".to_string();
    }
    clap_id_from_attrs(attrs).unwrap_or_else(|| field.to_string())
}

// ---------------------------------------------------------------------------
// Clause (iv) — structural default_value + non-Option scan
// ---------------------------------------------------------------------------

/// clap fields whose type is not `Option<_>` and whose attrs mention `default_value`.
fn defaulted_non_option_fields(src: &str) -> Vec<(String, String)> {
    defaulted_non_option_fields_with_attrs(src)
        .into_iter()
        .map(|f| (f.struct_name, f.field))
        .collect()
}

struct DefaultedField {
    struct_name: String,
    field: String,
    attrs: String,
    ty: String,
}

fn defaulted_non_option_fields_with_attrs(src: &str) -> Vec<DefaultedField> {
    let mut out = Vec::new();
    for st in struct_names(src) {
        for (field, attrs, ty) in fields_with_attrs(src, &st) {
            if is_option_type(&ty) {
                continue;
            }
            if attrs.contains("default_value") {
                out.push(DefaultedField { struct_name: st.clone(), field, attrs, ty });
            }
        }
    }
    out
}

/// Exact `serde(skip)` / `serde(skip, …)` — not `serde(skip_serializing_if)`.
fn has_exact_serde_skip(attrs: &str) -> bool {
    let bytes = attrs.as_bytes();
    let mut from = 0;
    while from + 10 <= bytes.len() {
        let Some(rel) = attrs[from..].find("serde(skip") else {
            return false;
        };
        let at = from + rel;
        let after_skip = at + "serde(skip".len();
        if after_skip >= bytes.len() {
            return false;
        }
        let next = bytes[after_skip];
        // `serde(skip)` or `serde(skip,` or `serde(skip )` — reject `skip_serializing_if`.
        if next == b')' || next == b',' || next.is_ascii_whitespace() {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Present-only polarity bool: `bool` + `default_value_t` + exact `#[serde(skip)]`.
/// These cannot clobber TOML (`apply_cli` only applies when the flag is true).
fn is_present_only_skipped_bool(attrs: &str, ty: &str) -> bool {
    ty.trim() == "bool" && attrs.contains("default_value") && has_exact_serde_skip(attrs)
}

/// Section-facing clap fields: excludes only present-only skipped bools.
/// A valued `default_value` + non-`Option` still flags, even with
/// `serde(skip_serializing_if)` or `#[serde(skip)]`.
fn defaulted_non_option_section_fields(src: &str) -> Vec<(String, String)> {
    defaulted_non_option_fields_with_attrs(src)
        .into_iter()
        .filter(|f| !is_present_only_skipped_bool(&f.attrs, &f.ty))
        .map(|f| (f.struct_name, f.field))
        .collect()
}

// ---------------------------------------------------------------------------
// Clause (iii) — section-struct field paths
// ---------------------------------------------------------------------------

struct SectionField {
    path: String,
    knob: String,
}

fn collect_section_fields_from(src: &str) -> Vec<SectionField> {
    let skip: HashSet<&str> = NOT_A_KNOB.iter().copied().collect();
    let mut fields = Vec::new();
    for (st, prefix) in SECTION_GROUPS {
        for (field, attrs, _) in fields_with_attrs(src, st) {
            let knob = knob_name(&field, &attrs);
            if skip.contains(knob.as_str()) || skip.contains(field.as_str()) {
                continue;
            }
            let path_field = if field == "no_doppelganger_detection" {
                "doppelganger_detection".to_string()
            } else {
                field
            };
            fields.push(SectionField { path: format!("{prefix}.{path_field}"), knob });
        }
    }
    fields.sort_by(|a, b| a.path.cmp(&b.path));
    fields
}

fn collect_section_fields(root: &Path) -> Vec<SectionField> {
    let mut src = rvc_config_sections_source(root);
    src.push_str(
        &std::fs::read_to_string(root.join(START_RS)).expect("crates/rvc/src/config/start.rs"),
    );
    collect_section_fields_from(&src)
}

fn collect_section_field_paths(root: &Path) -> Vec<String> {
    collect_section_fields(root).into_iter().map(|f| f.path).collect()
}

/// Every clap leaf (including CLI-only and polarity flags), as `(section_prefix, rust_field)`.
fn collect_clap_leaves_from(src: &str) -> Vec<(String, String)> {
    let mut leaves = Vec::new();
    for (st, prefix) in SECTION_GROUPS {
        for (field, _, _) in fields_with_attrs(src, st) {
            leaves.push(((*prefix).to_string(), field));
        }
    }
    leaves.sort();
    leaves
}

fn group_args_source(root: &Path) -> String {
    let mut src = rvc_config_sections_source(root);
    src.push_str(
        &std::fs::read_to_string(root.join(START_RS)).expect("crates/rvc/src/config/start.rs"),
    );
    src
}

/// Body of `fn apply_cli(&mut self, cli: &StartArgs) { … }`.
fn apply_cli_body(src: &str) -> String {
    let markers = [
        "fn apply_cli(&mut self, cli: &StartArgs)",
        "fn apply_cli(&mut self, cli: &super::start::StartArgs)",
    ];
    let mut start = None;
    for m in markers {
        if let Some(at) = src.find(m) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return String::new();
    };
    let rest = &src[start..];
    let Some(brace_rel) = rest.find('{') else {
        return String::new();
    };
    let open = start + brace_rel;
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Unread clap leaves: each `{prefix}.{field}` must appear in `apply_cli` unless
/// the rust field name is on `cli_only`.
fn apply_cli_unread(
    leaves: &[(String, String)],
    apply_body: &str,
    cli_only: &HashSet<&str>,
) -> Vec<String> {
    let compact = scan_text(apply_body);
    let mut violations = Vec::new();
    for (prefix, field) in leaves {
        if cli_only.contains(field.as_str()) {
            continue;
        }
        if !has_field_access(&compact, prefix, field) {
            violations.push(format!(
                "{prefix}.{field} is a clap leaf but is never read by `Config::apply_cli`; \
                 overlay it, or add the rust field name to CLI_ONLY_ARGS if it has no Config field"
            ));
        }
    }
    violations.sort();
    violations
}

/// Body of `pub fn validate(&self) -> Result<(), ConfigError>` (first match).
fn config_validate_body(src: &str) -> String {
    let markers = [
        "pub fn validate(&self) -> Result<(), ConfigError>",
        "fn validate(&self) -> Result<(), ConfigError>",
    ];
    let mut start = None;
    for m in markers {
        if let Some(at) = src.find(m) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return String::new();
    };
    let rest = &src[start..];
    let Some(brace_rel) = rest.find('{') else {
        return String::new();
    };
    let open = start + brace_rel;
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

fn path_mentioned_in_validate(path: &str, knob: &str, validate: &str) -> bool {
    if has_ident(validate, knob) {
        return true;
    }
    let compact = compact_ws(validate);
    let Some((parent, field)) = path.rsplit_once('.') else {
        return false;
    };
    if has_field_access(&compact, parent, field) {
        return true;
    }
    if let Some((_, bind)) = parent.rsplit_once('.') {
        if has_field_access(&compact, bind, field) {
            return true;
        }
    }
    false
}

fn unvalidated_violations(
    fields: &[SectionField],
    validate_body: &str,
    unvalidated: &HashSet<&str>,
) -> Vec<String> {
    let mut missing = Vec::new();
    for f in fields {
        if path_mentioned_in_validate(&f.path, &f.knob, validate_body) {
            continue;
        }
        if unvalidated.contains(f.path.as_str()) {
            continue;
        }
        missing.push(format!(
            "section field `{}` (knob `{}`) is neither mentioned in Config::validate \
             nor listed in UNVALIDATED; add a validation check or a shrinking-only \
             UNVALIDATED entry with a reason",
            f.path, f.knob
        ));
    }
    missing.sort();
    missing
}

// ---------------------------------------------------------------------------
// Live gate — clause (iii)
// ---------------------------------------------------------------------------

#[test]
fn clause_iii_covers_every_section_field() {
    let root = workspace_root();
    let paths = collect_section_field_paths(&root);
    assert_eq!(
        paths.len(),
        72,
        "clause (iii) must cover every section-struct field path (OPERATOR_KNOB_NAMES is 72); \
         got {paths:?}"
    );
    let fields = collect_section_fields(&root);

    let knobs_src = std::fs::read_to_string(root.join(KNOBS_RS)).expect("knobs.rs");
    let knobs = operator_knob_names(&knobs_src);
    assert_eq!(knobs.len(), 72, "OPERATOR_KNOB_NAMES count drifted; expected 72");

    let field_knobs: HashSet<&str> = fields.iter().map(|f| f.knob.as_str()).collect();
    let knob_set: HashSet<&str> = knobs.iter().map(String::as_str).collect();
    assert_eq!(
        field_knobs,
        knob_set,
        "section field knobs must match OPERATOR_KNOB_NAMES;\n  extra: {:?}\n  missing: {:?}",
        field_knobs.difference(&knob_set).collect::<Vec<_>>(),
        knob_set.difference(&field_knobs).collect::<Vec<_>>()
    );

    let types = std::fs::read_to_string(root.join(TYPES_RS)).expect("types.rs");
    let validate_body = config_validate_body(&types);
    assert!(!validate_body.is_empty(), "failed to extract Config::validate body from types.rs");
    assert!(
        has_ident(&validate_body, "metrics_port"),
        "validate body extraction broke (missing metrics_port)"
    );

    let unvalidated: HashSet<&str> = UNVALIDATED.iter().map(|&(p, _)| p).collect();
    assert_eq!(unvalidated.len(), UNVALIDATED.len(), "duplicate UNVALIDATED entries");

    for &(path, _) in UNVALIDATED {
        assert!(
            fields.iter().any(|f| f.path == path),
            "UNVALIDATED entry `{path}` is not a section-struct field path"
        );
    }

    for f in &fields {
        if !unvalidated.contains(f.path.as_str()) {
            continue;
        }
        assert!(
            !path_mentioned_in_validate(&f.path, &f.knob, &validate_body),
            "UNVALIDATED entry `{}` appears in Config::validate — remove it from the list \
             (shrinking-only)",
            f.path
        );
    }

    let violations = unvalidated_violations(&fields, &validate_body, &unvalidated);
    assert!(violations.is_empty(), "ARCH-P1-1 / G-2 clause (iii):\n  {}", violations.join("\n  "));
}

#[test]
fn unvalidated_list_is_shrinking_only() {
    let mut seen = HashSet::new();
    let mut prev: Option<&str> = None;
    for &(path, reason) in UNVALIDATED {
        assert!(!reason.trim().is_empty(), "UNVALIDATED::{path} missing reason");
        assert!(seen.insert(path), "duplicate UNVALIDATED entry: {path}");
        if let Some(p) = prev {
            assert!(p < path, "UNVALIDATED must stay sorted by path; {p:?} precedes {path}");
        }
        prev = Some(path);
    }
    assert!(
        UNVALIDATED.len() >= 40,
        "UNVALIDATED unexpectedly small ({}); table parse/seed failed?",
        UNVALIDATED.len()
    );
}

#[test]
fn unvalidated_detector_flags_an_unlist_field() {
    let fields = vec![
        SectionField { path: "server.metrics_port".into(), knob: "metrics_port".into() },
        SectionField { path: "server.brand_new_knob".into(), knob: "brand_new_knob".into() },
        SectionField { path: "network.graffiti".into(), knob: "graffiti".into() },
    ];
    let validate_body =
        "if self.metrics_port == 0 { ... } if let Some(ref graffiti) = self.graffiti";
    let unvalidated: HashSet<&str> = HashSet::new();
    let violations = unvalidated_violations(&fields, validate_body, &unvalidated);
    assert!(
        violations.iter().any(|v| v.contains("brand_new_knob")),
        "unlist + unvalidated field must be flagged: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("metrics_port")),
        "validated field must not be flagged: {violations:?}"
    );

    let mut listed = HashSet::new();
    listed.insert("server.brand_new_knob");
    let ok = unvalidated_violations(&fields, validate_body, &listed);
    assert!(ok.is_empty(), "listed field must pass: {ok:?}");
}

// ---------------------------------------------------------------------------
// Live gate — clause (iv)
// ---------------------------------------------------------------------------

#[test]
fn no_clap_field_has_both_a_default_value_and_a_non_option_type() {
    let src = r#"
#[derive(Args, Debug)]
pub struct ServerArgs {
    #[arg(long, default_value = "8080")]
    pub port: u16,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub threads: u16,
}
"#;
    let found = defaulted_non_option_fields(src);
    assert!(
        found.iter().any(|(st, f)| st == "ServerArgs" && f == "port"),
        "synthetic default_value + non-Option must be flagged, got {found:?}"
    );
    assert!(!found.iter().any(|(_, f)| f == "name"), "Option field must not be flagged: {found:?}");
    assert!(
        !found.iter().any(|(_, f)| f == "threads"),
        "non-Option without default_value must not be flagged: {found:?}"
    );

    // F2: `serde(skip_serializing_if)` is not `#[serde(skip)]`.
    let skip_if = r#"
pub struct ServerArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[arg(long, default_value = "8080")]
    pub port: u16,
}
"#;
    let found = defaulted_non_option_section_fields(skip_if);
    assert!(
        found.iter().any(|(_, f)| f == "port"),
        "valued default_value + skip_serializing_if must still be flagged, got {found:?}"
    );

    let valued_skip = r#"
pub struct ServerArgs {
    #[serde(skip)]
    #[arg(long, default_value = "8080")]
    pub port: u16,
}
"#;
    let found = defaulted_non_option_section_fields(valued_skip);
    assert!(
        found.iter().any(|(_, f)| f == "port"),
        "valued default_value + exact serde(skip) must still be flagged, got {found:?}"
    );

    let present_only = r#"
pub struct SafetyArgs {
    #[arg(long = "allow-unsupported-fork", default_value_t = false)]
    #[serde(skip)]
    pub allow_unsupported_fork: bool,
}
"#;
    let found = defaulted_non_option_section_fields(present_only);
    assert!(
        found.is_empty(),
        "present-only bool + default_value_t + exact serde(skip) is excluded, got {found:?}"
    );
    let raw = defaulted_non_option_fields(present_only);
    assert!(
        raw.iter().any(|(_, f)| f == "allow_unsupported_fork"),
        "unfiltered matcher must still see the present-only bool, got {raw:?}"
    );
}

#[test]
fn rvc_config_has_no_defaulted_non_option_clap_field() {
    let root = workspace_root();
    let src = rvc_config_sections_source(&root);
    let found = defaulted_non_option_section_fields(&src);
    assert!(
        found.is_empty(),
        "no clap::Args field in rvc-config may have both default_value and a non-Option type \
         (ADR-009 / G-2 iv): {found:?}"
    );
    assert!(
        CLAP_DEFAULT_CLOBBERS.is_empty(),
        "CLAP_DEFAULT_CLOBBERS must stay empty after ARCH-6b / ARCH-4k; got {} entries",
        CLAP_DEFAULT_CLOBBERS.len()
    );
}

#[test]
fn every_clobber_entry_carries_a_reason() {
    let mut seen = HashSet::new();
    let mut prev: Option<&str> = None;
    for &(field, reason) in CLAP_DEFAULT_CLOBBERS {
        assert!(!reason.trim().is_empty(), "CLAP_DEFAULT_CLOBBERS::{field} missing reason");
        assert!(seen.insert(field), "duplicate CLAP_DEFAULT_CLOBBERS entry: {field}");
        if let Some(p) = prev {
            assert!(
                p < field,
                "CLAP_DEFAULT_CLOBBERS must stay sorted by field; {p:?} precedes {field}"
            );
        }
        prev = Some(field);
    }
}

// ---------------------------------------------------------------------------
// Retirement + CLI-only inventory
// ---------------------------------------------------------------------------

#[test]
fn retired_clauses_are_absent() {
    let src = include_str!("config_drift.rs");
    // Build needles so this test does not mention the retired `const` tables.
    let bypass = format!("const {}:", "BYPASS");
    let aliases = format!("const {}:", "ALIASES");
    assert!(
        !src.contains(&bypass),
        "clause (ii) bypass table must be deleted with seam α (ARCH-4k)"
    );
    assert!(
        !src.contains(&aliases),
        "clause (ii) aliases table must be deleted with seam α (ARCH-4k)"
    );
    let bindings_nv = format!("bindings.len(), {}", 13);
    let checked_nv = format!("checked, {}", 74);
    assert!(!src.contains(&bindings_nv), "clause (ii) non-vacuity bindings.len()==13 must be gone");
    assert!(!src.contains(&checked_nv), "clause (ii) non-vacuity checked==74 must be gone");
}

#[test]
fn cli_only_args_are_documented() {
    assert_eq!(
        CLI_ONLY_ARGS,
        &["enable_log_reload", "log_format", "strict_permissions", "strict_slashing_semantics",]
    );
    let root = workspace_root();
    let src = group_args_source(&root);
    let logging = struct_fields(&src, "LoggingArgs");
    let slashing = struct_fields(&src, "SlashingArgs");
    assert!(logging.iter().any(|f| f == "log_format"), "log_format missing on LoggingArgs");
    assert!(
        logging.iter().any(|f| f == "enable_log_reload"),
        "enable_log_reload missing on LoggingArgs"
    );
    assert!(
        slashing.iter().any(|f| f == "strict_permissions"),
        "strict_permissions missing on SlashingArgs"
    );
    assert!(
        slashing.iter().any(|f| f == "strict_slashing_semantics"),
        "strict_slashing_semantics missing on SlashingArgs"
    );

    // Second-leg: CLI-only flags must still be consumed in bin/rvc (run/logging).
    let cli = std::fs::read_to_string(root.join(CLI_RS)).expect("bin/rvc/src/cli.rs");
    let cli_scan = scan_text(&cli);
    assert!(
        has_field_access(&cli_scan, "logging", "log_format"),
        "CLI_ONLY log_format has no second-leg read as logging.log_format in cli.rs"
    );
    assert!(
        has_field_access(&cli_scan, "logging", "enable_log_reload"),
        "CLI_ONLY enable_log_reload has no second-leg read as logging.enable_log_reload in cli.rs"
    );
    assert!(
        has_field_access(&cli_scan, "slashing", "strict_permissions"),
        "CLI_ONLY strict_permissions has no second-leg read as slashing.strict_permissions in cli.rs"
    );
    assert!(
        has_field_access(&cli_scan, "slashing", "strict_slashing_semantics"),
        "CLI_ONLY strict_slashing_semantics has no second-leg read as \
         slashing.strict_slashing_semantics in cli.rs"
    );
}

#[test]
fn apply_cli_presence_scan_flags_an_unread_field() {
    let leaves = vec![("beacon".into(), "url".into()), ("beacon".into(), "unread_field".into())];
    let body = "if let Some(v) = &beacon.url { self.beacon_url = v.clone(); }";
    let cli_only = HashSet::new();
    let violations = apply_cli_unread(&leaves, body, &cli_only);
    assert!(
        violations.iter().any(|v| v.contains("unread_field")),
        "unread clap leaf must be flagged, got {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("beacon.url") && !v.contains("unread")),
        "read field must not be flagged: {violations:?}"
    );

    let mut cli_only = HashSet::new();
    cli_only.insert("log_format");
    let leaves = vec![("logging".into(), "log_format".into())];
    let ok = apply_cli_unread(&leaves, body, &cli_only);
    assert!(ok.is_empty(), "CLI_ONLY field must not require apply_cli: {ok:?}");

    let body_comment = "// remember to wire beacon.unread_field later\nbeacon.url";
    let leaves = vec![("beacon".into(), "unread_field".into())];
    let empty = HashSet::new();
    let violations = apply_cli_unread(&leaves, body_comment, &empty);
    assert!(
        violations.iter().any(|v| v.contains("unread_field")),
        "comment-only mention must still be unread: {violations:?}"
    );
}

#[test]
fn every_clap_leaf_is_read_by_apply_cli_or_is_cli_only() {
    let root = workspace_root();
    let groups = group_args_source(&root);
    let leaves = collect_clap_leaves_from(&groups);
    assert!(
        leaves.len() > 60,
        "apply_cli presence scan walked too few clap leaves ({}); extractor broke?",
        leaves.len()
    );

    let types = std::fs::read_to_string(root.join(TYPES_RS)).expect("types.rs");
    let body = apply_cli_body(&types);
    assert!(!body.is_empty(), "failed to extract Config::apply_cli body from types.rs");
    assert!(
        has_field_access(&scan_text(&body), "beacon", "url"),
        "apply_cli body extraction broke (missing beacon.url)"
    );

    let cli_only: HashSet<&str> = CLI_ONLY_ARGS.iter().copied().collect();
    let violations = apply_cli_unread(&leaves, &body, &cli_only);
    assert!(
        violations.is_empty(),
        "G-2 apply_cli presence scan (unread clap leaf):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_overrides_type_no_longer_exists() {
    let root = workspace_root();
    let mut hits = Vec::new();
    for dir in ["crates/rvc", "crates/rvc-config", "bin"] {
        walk_rs(&root.join(dir), &mut hits);
    }
    assert!(
        hits.is_empty(),
        "M4: `struct CliOverrides` must not exist under crates/ or bin/: {hits:?}"
    );
}

fn walk_rs(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, hits);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        if src.contains("pub struct CliOverrides") || src.contains("struct CliOverrides {") {
            hits.push(path.display().to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Matcher unit tests
// ---------------------------------------------------------------------------

#[test]
fn struct_fields_extracts_and_skips_attributes() {
    let src = r#"
#[derive(Args, Debug)]
pub struct BeaconArgs {
    /// Beacon node URL
    #[arg(long)]
    pub beacon_url: Option<String>,

    #[arg(long, value_delimiter = ',')]
    pub beacon_nodes: Option<Vec<String>>,
}
"#;
    assert_eq!(struct_fields(src, "BeaconArgs"), vec!["beacon_url", "beacon_nodes"]);
}

#[test]
fn section_field_paths_use_clap_id_and_skip_flatten() {
    let src = r#"
pub struct BeaconArgs {
    #[arg(id = "beacon_url", long = "beacon-url")]
    pub url: Option<String>,

    #[command(flatten)]
    pub nested: OtherArgs,
}

pub struct LoggingArgs {
    #[arg(long)]
    pub log_level: Option<String>,

    #[arg(long, default_value = "pretty")]
    pub log_format: String,
}
"#;
    let fields = collect_section_fields_from(src);
    let paths: Vec<&str> = fields.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"beacon.url"), "got {paths:?}");
    assert!(fields.iter().any(|f| f.path == "beacon.url" && f.knob == "beacon_url"));
    assert!(paths.contains(&"logging.log_level"), "got {paths:?}");
    assert!(!paths.iter().any(|p| p.contains("nested")));
    assert!(!paths.iter().any(|p| p.contains("log_format")));
}
