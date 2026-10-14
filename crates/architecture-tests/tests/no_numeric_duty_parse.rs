//! RR3-05: no numeric duty-field parse remains downstream of the duty cache.
//!
//! `TypedAttesterDuty` / `TypedProposerDuty` / `TypedPtcDuty` parse `slot`,
//! `committee_index`, `validator_index`, `committee_length`, and
//! `validator_committee_index` once, when the cache is filled. Orchestrator
//! code must read those typed fields. A `.parse()` on the same field of a
//! duty (or `proposer_duty`) is a second parse.
//!
//! The allow-set names the three beacon *response* parses that are not duty
//! fields. They stay in the tree, and the matcher still has to see the `slot`
//! ones, so dropping a field from the pattern (or requiring the receiver to
//! be exactly `duty` on one line) cannot turn this test green.
//!
//! A copied wire index is the same bug one step later: `sort_source_validators`
//! used to `parse::<u64>()` the `validator_index` string after it had been
//! cloned off the duty. That call has no `duty.<field>` receiver, so the field
//! matcher does not see it. [`local_u64_parses`] does. The one allow-listed
//! `parse::<u64>()` is a test assertion on a submitted attestation index, and
//! the scan still has to see it.

use std::path::{Path, PathBuf};

/// The five numeric fields parsed at the duty cache. Order is fixed so a
/// narrower list fails [`numeric_fields_cover_the_cache_contract`].
const NUMERIC_DUTY_FIELDS: &[&str] = &[
    "slot",
    "committee_index",
    "validator_index",
    "committee_length",
    "validator_committee_index",
];

/// One beacon response parse that is not a duty-cache field.
struct ResponseFieldParse {
    file: &'static str,
    /// Identifiers from the value to the parsed field. Whitespace around `.`
    /// is allowed, so a split `beacon_data` / `.slot` / `.parse()` still matches.
    parts: &'static [&'static str],
}

/// The three response-field parses. Named explicitly so the scan cannot be
/// satisfied by loosening the duty-field pattern until these disappear from
/// the match set.
const RESPONSE_FIELD_PARSES: &[ResponseFieldParse] = &[
    // `attestation.rs`: `beacon_attestation_data.target.epoch.parse()`.
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/attestation.rs",
        parts: &["beacon_attestation_data", "target", "epoch"],
    },
    // `utils.rs` `convert_attestation_data` (~173-194): slot, index, source epoch, target epoch.
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/utils.rs",
        parts: &["beacon_data", "slot"],
    },
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/utils.rs",
        parts: &["beacon_data", "index"],
    },
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/utils.rs",
        parts: &["beacon_data", "source", "epoch"],
    },
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/utils.rs",
        parts: &["beacon_data", "target", "epoch"],
    },
    // `head_events.rs`: `head.slot.parse()` (issue text said ~116; the call is `event_matches`).
    ResponseFieldParse {
        file: "crates/rvc/src/orchestrator/head_events.rs",
        parts: &["head", "slot"],
    },
];

/// Hits the numeric-field matcher sees that are response fields, not duties.
const ALLOWED_NUMERIC_HITS: &[(&str, &str, &str)] = &[
    ("crates/rvc/src/orchestrator/head_events.rs", "head", "slot"),
    ("crates/rvc/src/orchestrator/utils.rs", "beacon_data", "slot"),
];

/// `ident.parse::<u64>()` that is not a second parse of a duty validator index.
///
/// Named so dropping `::<u64>` from the matcher (or skipping every local
/// parse) fails the "must still see this hit" check.
const ALLOWED_LOCAL_U64_PARSES: &[(&str, &str)] =
    &[("crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs", "submitted_index")];

struct Hit {
    file: String,
    line: usize,
    receiver: String,
    field: &'static str,
}

struct LocalU64Parse {
    file: String,
    line: usize,
    receiver: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_whitespace(src: &str, mut index: usize) -> usize {
    let bytes = src.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_turbofish(src: &str, mut index: usize) -> usize {
    let bytes = src.as_bytes();
    if !src[index..].starts_with("::") {
        return index;
    }
    index += 2;
    if index >= bytes.len() || bytes[index] != b'<' {
        return index;
    }
    let mut depth = 0i32;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    index
}

/// `<receiver>.<field>.parse(...)`, with whitespace allowed around the dots
/// and an optional turbofish (`parse::<u64>()`).
fn numeric_duty_parses(file: &str, src: &str) -> Vec<Hit> {
    let bytes = src.as_bytes();
    let mut hits = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'.' {
            let rest = &src[index + 1..];
            for field in NUMERIC_DUTY_FIELDS {
                if !rest.starts_with(field) {
                    continue;
                }
                let mut after_field = index + 1 + field.len();
                if after_field < bytes.len() && is_ident_continue(bytes[after_field]) {
                    continue;
                }
                after_field = skip_whitespace(src, after_field);
                if !src[after_field..].starts_with(".parse") {
                    continue;
                }
                let mut after_parse = after_field + ".parse".len();
                if after_parse < bytes.len() && is_ident_continue(bytes[after_parse]) {
                    continue;
                }
                after_parse = skip_turbofish(src, after_parse);
                after_parse = skip_whitespace(src, after_parse);
                if after_parse >= bytes.len() || bytes[after_parse] != b'(' {
                    continue;
                }
                let mut receiver_end = index;
                while receiver_end > 0 && bytes[receiver_end - 1].is_ascii_whitespace() {
                    receiver_end -= 1;
                }
                let mut receiver_start = receiver_end;
                while receiver_start > 0 && is_ident_continue(bytes[receiver_start - 1]) {
                    receiver_start -= 1;
                }
                if receiver_start == receiver_end || !is_ident_start(bytes[receiver_start]) {
                    continue;
                }
                let line = src[..receiver_start].bytes().filter(|byte| *byte == b'\n').count() + 1;
                hits.push(Hit {
                    file: file.to_string(),
                    line,
                    receiver: src[receiver_start..receiver_end].to_string(),
                    field,
                });
                break;
            }
        }
        index += 1;
    }
    hits
}

fn contains_dotted_parse(src: &str, parts: &[&str]) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return false;
    };
    let bytes = src.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = src[search_from..].find(first) {
        let start = search_from + rel;
        let end = start + first.len();
        let ident_bounded = (start == 0 || !is_ident_continue(bytes[start - 1]))
            && (end >= bytes.len() || !is_ident_continue(bytes[end]));
        if ident_bounded && path_continues_to_parse(src, end, rest) {
            return true;
        }
        search_from = start + 1;
    }
    false
}

fn path_continues_to_parse(src: &str, mut index: usize, parts: &[&str]) -> bool {
    let bytes = src.as_bytes();
    for part in parts {
        index = skip_whitespace(src, index);
        if !src[index..].starts_with('.') {
            return false;
        }
        index = skip_whitespace(src, index + 1);
        if !src[index..].starts_with(part) {
            return false;
        }
        let after = index + part.len();
        if after < bytes.len() && is_ident_continue(bytes[after]) {
            return false;
        }
        index = after;
    }
    index = skip_whitespace(src, index);
    if !src[index..].starts_with(".parse") {
        return false;
    }
    let mut after_parse = index + ".parse".len();
    if after_parse < bytes.len() && is_ident_continue(bytes[after_parse]) {
        return false;
    }
    after_parse = skip_turbofish(src, after_parse);
    after_parse = skip_whitespace(src, after_parse);
    after_parse < bytes.len() && bytes[after_parse] == b'('
}

fn is_allowed(hit: &Hit) -> bool {
    ALLOWED_NUMERIC_HITS.iter().any(|(file, receiver, field)| {
        hit.file == *file && hit.receiver == *receiver && hit.field == *field
    })
}

/// `receiver.parse::<u64>(...)`. Whitespace may surround `::`, `<`, `u64`, and
/// `>`. A bare `.parse()` (response fields) and `parse::<u32>()` do not match.
fn local_u64_parses(file: &str, src: &str) -> Vec<LocalU64Parse> {
    let bytes = src.as_bytes();
    let mut hits = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"parse") {
            let end = index + "parse".len();
            let ident_bounded = (index == 0 || !is_ident_continue(bytes[index - 1]))
                && (end >= bytes.len() || !is_ident_continue(bytes[end]));
            if ident_bounded {
                if let Some(after_call) = u64_turbofish_call(src, end) {
                    if let Some((receiver_start, receiver_end)) = method_receiver(src, index) {
                        let line =
                            src[..receiver_start].bytes().filter(|byte| *byte == b'\n').count() + 1;
                        hits.push(LocalU64Parse {
                            file: file.to_string(),
                            line,
                            receiver: src[receiver_start..receiver_end].to_string(),
                        });
                        index = after_call;
                        continue;
                    }
                }
            }
        }
        index += 1;
    }
    hits
}

/// The identifier immediately before `.` at `parse_index`.
fn method_receiver(src: &str, parse_index: usize) -> Option<(usize, usize)> {
    let bytes = src.as_bytes();
    let mut receiver_end = parse_index;
    while receiver_end > 0 && bytes[receiver_end - 1].is_ascii_whitespace() {
        receiver_end -= 1;
    }
    if receiver_end == 0 || bytes[receiver_end - 1] != b'.' {
        return None;
    }
    receiver_end -= 1;
    while receiver_end > 0 && bytes[receiver_end - 1].is_ascii_whitespace() {
        receiver_end -= 1;
    }
    let mut receiver_start = receiver_end;
    while receiver_start > 0 && is_ident_continue(bytes[receiver_start - 1]) {
        receiver_start -= 1;
    }
    if receiver_start == receiver_end || !is_ident_start(bytes[receiver_start]) {
        return None;
    }
    Some((receiver_start, receiver_end))
}

/// `::<u64>(` starting at `index`, or `None` when the turbofish is absent or
/// not `u64`.
fn u64_turbofish_call(src: &str, mut index: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    index = skip_whitespace(src, index);
    if !src[index..].starts_with("::") {
        return None;
    }
    index = skip_whitespace(src, index + 2);
    if index >= bytes.len() || bytes[index] != b'<' {
        return None;
    }
    index = skip_whitespace(src, index + 1);
    if !src[index..].starts_with("u64") {
        return None;
    }
    let after_ty = index + "u64".len();
    if after_ty < bytes.len() && is_ident_continue(bytes[after_ty]) {
        return None;
    }
    index = skip_whitespace(src, after_ty);
    if index >= bytes.len() || bytes[index] != b'>' {
        return None;
    }
    index = skip_whitespace(src, index + 1);
    if index >= bytes.len() || bytes[index] != b'(' {
        return None;
    }
    Some(index + 1)
}

fn is_allowed_local_u64(hit: &LocalU64Parse) -> bool {
    ALLOWED_LOCAL_U64_PARSES
        .iter()
        .any(|(file, receiver)| hit.file == *file && hit.receiver == *receiver)
}

fn assert_no_local_u64_reparse(sources: &[(String, String)]) {
    let mut hits = Vec::new();
    for (file, src) in sources {
        hits.extend(local_u64_parses(file, src));
    }

    let allowed: Vec<_> = hits.iter().filter(|hit| is_allowed_local_u64(hit)).collect();
    assert_eq!(
        allowed.len(),
        ALLOWED_LOCAL_U64_PARSES.len(),
        "the matcher must still see the allow-listed `submitted_index.parse::<u64>()`; \
         a narrower pattern hides it\n  {}",
        allowed
            .iter()
            .map(|hit| format!("{}:{} {}", hit.file, hit.line, hit.receiver))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    let mut forbidden: Vec<_> = hits.into_iter().filter(|hit| !is_allowed_local_u64(hit)).collect();
    forbidden.sort_by(|left, right| {
        (&left.file, left.line, &left.receiver).cmp(&(&right.file, right.line, &right.receiver))
    });
    let rendered = forbidden
        .iter()
        .map(|hit| format!("{}:{} {}", hit.file, hit.line, hit.receiver))
        .collect::<Vec<_>>()
        .join("\n  ");
    assert!(
        forbidden.is_empty(),
        "validator-index strings are parsed again as u64 ({}):\n  {rendered}",
        forbidden.len()
    );
}

fn orchestrator_sources(root: &Path) -> Vec<(String, String)> {
    let dir = root.join("crates/rvc/src/orchestrator");
    let mut files = Vec::new();
    collect_rs(&dir, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            (rel, src)
        })
        .collect()
}

/// Downstream of the cache, orchestrator source has zero `duty.<numeric>.parse()`
/// (and the same for `proposer_duty`). Response-field parses stay, by name.
#[test]
fn no_numeric_duty_parse_remains_downstream_of_the_cache() {
    let root = workspace_root();
    let sources = orchestrator_sources(&root);
    assert!(
        sources.len() > 10,
        "scanned only {} orchestrator files; the walk likely broke",
        sources.len()
    );

    let mut hits = Vec::new();
    for (file, src) in &sources {
        hits.extend(numeric_duty_parses(file, src));
    }

    let mut missing_response_parses = Vec::new();
    for allowed in RESPONSE_FIELD_PARSES {
        let Some((_, src)) = sources.iter().find(|(file, _)| file == allowed.file) else {
            missing_response_parses.push(format!("{} (file missing)", allowed.file));
            continue;
        };
        if !contains_dotted_parse(src, allowed.parts) {
            missing_response_parses.push(format!("{} {}", allowed.file, allowed.parts.join(".")));
        }
    }
    assert!(
        missing_response_parses.is_empty(),
        "allow-set response-field parses must stay in the tree so the pattern \
         cannot be loosened until they fall out of the scan:\n  {}",
        missing_response_parses.join("\n  ")
    );

    let allowed_hits: Vec<_> = hits.iter().filter(|hit| is_allowed(hit)).collect();
    assert_eq!(
        allowed_hits.len(),
        ALLOWED_NUMERIC_HITS.len(),
        "the matcher must still see the allowed response `slot` parses \
         (head.slot, beacon_data.slot); a narrower field list hides them\n  {}",
        allowed_hits
            .iter()
            .map(|hit| format!("{}:{} {}.{}", hit.file, hit.line, hit.receiver, hit.field))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    let mut forbidden: Vec<_> = hits.into_iter().filter(|hit| !is_allowed(hit)).collect();
    forbidden.sort_by(|left, right| {
        (&left.file, left.line, &left.receiver, left.field).cmp(&(
            &right.file,
            right.line,
            &right.receiver,
            right.field,
        ))
    });
    let rendered = forbidden
        .iter()
        .map(|hit| format!("{}:{} {}.{}", hit.file, hit.line, hit.receiver, hit.field))
        .collect::<Vec<_>>()
        .join("\n  ");
    assert!(
        forbidden.is_empty(),
        "numeric duty parses remain downstream of the cache ({}):\n  {rendered}",
        forbidden.len()
    );

    assert_no_local_u64_reparse(&sources);
}

#[test]
fn numeric_fields_cover_the_cache_contract() {
    assert_eq!(
        NUMERIC_DUTY_FIELDS,
        [
            "slot",
            "committee_index",
            "validator_index",
            "committee_length",
            "validator_committee_index",
        ]
    );
}

/// Locks the matcher shape: split receivers, turbofish, and `proposer_duty`
/// count; `epoch` / bare `index` / a local `.parse()` do not.
#[test]
fn matcher_sees_split_turbofish_and_proposer_duty_shapes() {
    let src = r#"
        duty.slot.parse()?;
        proposer_duty.validator_index.parse()
        let committee_index: u64 = duty
            .committee_index
            .parse()
            .map_err(|_| ())?;
        duty.committee_length.parse().ok()?;
        duty.validator_committee_index.parse()
        duty.validator_index.parse::<u64>()
        head.slot.parse().ok()
        let slot: u64 = beacon_data
            .slot
            .parse()
            .map_err(|_| ())?;
        beacon_attestation_data.target.epoch.parse().unwrap();
        beacon_data.index.parse().unwrap();
        beacon_data
            .source
            .epoch
            .parse()
            .unwrap();
        let validator_index = "1";
        validator_index.parse::<u64>().unwrap();
    "#;
    let hits = numeric_duty_parses("fixture.rs", src);
    let rendered: Vec<_> =
        hits.iter().map(|hit| format!("{}.{}", hit.receiver, hit.field)).collect();
    assert_eq!(
        rendered,
        [
            "duty.slot",
            "proposer_duty.validator_index",
            "duty.committee_index",
            "duty.committee_length",
            "duty.validator_committee_index",
            "duty.validator_index",
            "head.slot",
            "beacon_data.slot",
        ]
    );
    assert!(contains_dotted_parse(src, &["beacon_attestation_data", "target", "epoch"]));
    assert!(contains_dotted_parse(src, &["beacon_data", "index"]));
    assert!(contains_dotted_parse(src, &["beacon_data", "source", "epoch"]));
    assert!(contains_dotted_parse(src, &["head", "slot"]));
}

/// The old `sort_source_validators` body is two `parse::<u64>()` hits.
/// Response `.parse()` calls and a non-`u64` turbofish are not.
#[test]
fn local_u64_parse_matcher_flags_the_old_sort() {
    let src = r#"
        fn sort_source_validators(indices: &mut [String]) {
            indices.sort_by(|left, right| {
                left.parse::<u64>()
                    .ok()
                    .cmp(&right.parse::<u64>().ok())
                    .then_with(|| left.cmp(right))
            });
        }
        head.slot.parse().ok();
        beacon_data.slot.parse().unwrap();
        beacon_attestation_data.target.epoch.parse().unwrap();
        submitted_index.parse::<u64>().unwrap();
        validator_index.parse().unwrap();
        count.parse::<u32>().unwrap();
        parse::<u64>();
    "#;
    let hits = local_u64_parses("fixture.rs", src);
    let rendered: Vec<_> = hits.iter().map(|hit| hit.receiver.as_str()).collect();
    assert_eq!(rendered, ["left", "right", "submitted_index"]);
}

/// Fails while orchestrator code still `parse::<u64>()`s a copied validator index.
#[test]
fn no_validator_index_string_reparsed_as_u64() {
    let sources = orchestrator_sources(&workspace_root());
    assert_no_local_u64_reparse(&sources);
}
