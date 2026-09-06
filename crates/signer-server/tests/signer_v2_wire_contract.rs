//! Additive-only freeze of `proto/signer.v2.proto` (issue 4.20a / D18/B5).
//!
//! Baseline is develop including 4.11a `PartialSignPayloadAttestation` and
//! 4.11b `PartialSignPayloadAttestationRequest.object_root = 6`.
//! Adding rows is allowed; changing or deleting a snapshot row fails.

const PROTO: &str = include_str!("../../../proto/signer.v2.proto");
const SNAPSHOT: &str = include_str!("signer_v2_wire_snapshot.txt");

/// 4.20a additions vs the develop+4.11a+4.11b snapshot. Future additive rows
/// may appear; these must remain present. `object_root = 6` is baseline, not
/// a 4.20a addition.
const ISSUE_4_20A_ADDITIONS: &[&str] = &[
    "rpc SignerService.SignBlockHeader (SignBlockHeaderRequest) returns (SignResponse)",
    "rpc SignerService.SignRoot (SignRootRequest) returns (SignResponse)",
    "rpc PeerSignerService.PartialSignBlockHeader (PartialSignBlockHeaderRequest) returns (PartialSignResponse)",
    "rpc PeerSignerService.PartialSignRoot (PartialSignRootRequest) returns (PartialSignResponse)",
    "message BeaconBlockHeader",
    "BeaconBlockHeader.slot : uint64 = 1",
    "BeaconBlockHeader.proposer_index : uint64 = 2",
    "BeaconBlockHeader.parent_root : bytes = 3",
    "BeaconBlockHeader.state_root : bytes = 4",
    "BeaconBlockHeader.body_root : bytes = 5",
    "message SignBlockHeaderRequest",
    "SignBlockHeaderRequest.pubkey : bytes = 1",
    "SignBlockHeaderRequest.fork_info : ForkInfo = 2",
    "SignBlockHeaderRequest.header : BeaconBlockHeader = 3",
    "SignBlockHeaderRequest.fork_id : uint32 = 4",
    "message SignRootRequest",
    "SignRootRequest.pubkey : bytes = 1",
    "SignRootRequest.fork_info : ForkInfo = 2",
    "SignRootRequest.object_root : bytes = 3",
    "SignRootRequest.duty : Duty = 4",
    "SignRootRequest.fork_id : uint32 = 5",
    "message PartialSignBlockHeaderRequest",
    "PartialSignBlockHeaderRequest.requester_index : uint64 = 1",
    "PartialSignBlockHeaderRequest.pubkey : bytes = 2",
    "PartialSignBlockHeaderRequest.fork_info : ForkInfo = 3",
    "PartialSignBlockHeaderRequest.header : BeaconBlockHeader = 4",
    "PartialSignBlockHeaderRequest.fork_id : uint32 = 5",
    "message PartialSignRootRequest",
    "PartialSignRootRequest.requester_index : uint64 = 1",
    "PartialSignRootRequest.pubkey : bytes = 2",
    "PartialSignRootRequest.fork_info : ForkInfo = 3",
    "PartialSignRootRequest.object_root : bytes = 4",
    "PartialSignRootRequest.duty : Duty = 5",
    "PartialSignRootRequest.fork_id : uint32 = 6",
    "enum Duty",
    "enum Duty.UNSPECIFIED = 0",
    "enum Duty.AGGREGATE_AND_PROOF = 1",
    "enum Duty.CONTRIBUTION_AND_PROOF = 2",
    "enum Duty.PAYLOAD_ATTESTATION = 3",
    "enum Duty.PROPOSER_PREFERENCES = 4",
    "enum Duty.EXECUTION_PAYLOAD_ENVELOPE = 5",
    "enum Duty.BUILDER_REQUEST_AUTH = 6",
];

const NEW_MESSAGES: &[&str] = &[
    "BeaconBlockHeader",
    "SignBlockHeaderRequest",
    "SignRootRequest",
    "PartialSignBlockHeaderRequest",
    "PartialSignRootRequest",
];

fn strip_line_comments(src: &str) -> String {
    src.lines().map(|line| line.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

fn next_ident(src: &str) -> Option<(&str, &str)> {
    let rest = src.trim_start();
    if rest.is_empty() {
        return None;
    }
    let len = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(rest.len());
    if len == 0 {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

fn extract_braced<'a>(src: &'a str, keyword: &str) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    let mut search_from = 0;
    let pat = format!("{keyword} ");
    while let Some(rel) = src[search_from..].find(&pat) {
        let after_kw = search_from + rel + pat.len();
        let Some((name, after_name)) = next_ident(&src[after_kw..]) else {
            search_from = after_kw;
            continue;
        };
        let trimmed = after_name.trim_start();
        if !trimmed.starts_with('{') {
            search_from = after_kw + name.len();
            continue;
        }
        let brace = after_kw + (src[after_kw..].len() - trimmed.len());
        let body_start = brace + 1;
        let mut depth = 1usize;
        let mut i = body_start;
        let bytes = src.as_bytes();
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        let body_end = i.saturating_sub(1);
        out.push((name, &src[body_start..body_end]));
        search_from = i;
    }
    out
}

fn parse_fields(body: &str) -> Vec<(String, String, u32)> {
    let mut fields = Vec::new();
    for stmt in body.split(';') {
        let stmt = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
        if stmt.is_empty() || !stmt.contains('=') {
            continue;
        }
        let Some((left, right)) = stmt.split_once('=') else {
            continue;
        };
        let left = left.trim();
        let Some(name) = left.split_whitespace().last() else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let typ = left[..left.len() - name.len()].trim();
        if typ.is_empty() {
            continue;
        }
        let Some(num_tok) = right.split_whitespace().next() else {
            continue;
        };
        let Ok(num) = num_tok.parse::<u32>() else {
            continue;
        };
        fields.push((typ.to_string(), name.to_string(), num));
    }
    fields
}

fn parse_rpc_sig(after_rpc: &str) -> Option<(&str, &str, &str, &str)> {
    let (name, rest) = next_ident(after_rpc)?;
    let rest = rest.trim_start().strip_prefix('(')?.trim_start();
    let (req, rest) = next_ident(rest)?;
    let rest = rest.trim_start().strip_prefix(')')?.trim_start();
    let rest = rest.strip_prefix("returns")?.trim_start().strip_prefix('(')?.trim_start();
    let (resp, rest) = next_ident(rest)?;
    Some((name, req, resp, rest))
}

fn parse_proto_rows(src: &str) -> Vec<String> {
    let text = strip_line_comments(src);
    let mut rows = Vec::new();
    for (svc, body) in extract_braced(&text, "service") {
        let mut search_from = 0;
        while let Some(rel) = body[search_from..].find("rpc ") {
            let after = search_from + rel + 4;
            if let Some((name, req, resp, rest)) = parse_rpc_sig(&body[after..]) {
                rows.push(format!("rpc {svc}.{name} ({req}) returns ({resp})"));
                search_from = body.len() - rest.len();
            } else {
                search_from = after;
            }
        }
    }
    for (msg, body) in extract_braced(&text, "message") {
        rows.push(format!("message {msg}"));
        for (typ, name, num) in parse_fields(body) {
            rows.push(format!("{msg}.{name} : {typ} = {num}"));
        }
    }
    for (en, body) in extract_braced(&text, "enum") {
        rows.push(format!("enum {en}"));
        for stmt in body.split(';') {
            let stmt = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
            if stmt.is_empty() || !stmt.contains('=') {
                continue;
            }
            let Some((left, right)) = stmt.split_once('=') else {
                continue;
            };
            let name = left.trim();
            let Some(num_tok) = right.split_whitespace().next() else {
                continue;
            };
            let Ok(num) = num_tok.parse::<u32>() else {
                continue;
            };
            rows.push(format!("enum {en}.{name} = {num}"));
        }
    }
    rows
}

fn parse_snapshot_rows(src: &str) -> Vec<String> {
    src.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn row_key(row: &str) -> &str {
    if row.starts_with("rpc ") {
        return row.split_once(" (").map(|(k, _)| k).unwrap_or(row);
    }
    if row.starts_with("message ") {
        return row;
    }
    if row.starts_with("enum ") {
        return row.split_once(" = ").map(|(k, _)| k).unwrap_or(row);
    }
    row.split_once(" : ").map(|(k, _)| k).unwrap_or(row)
}

fn message_of_field_row(row: &str) -> Option<&str> {
    if row.starts_with("rpc ") || row.starts_with("enum ") || row.starts_with("message ") {
        return None;
    }
    row.split_once('.').map(|(msg, _)| msg)
}

fn snapshot_message_names(rows: &[String]) -> std::collections::BTreeSet<&str> {
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        if let Some(name) = row.strip_prefix("message ") {
            names.insert(name);
        }
        if let Some(msg) = message_of_field_row(row) {
            names.insert(msg);
        }
    }
    names
}

#[test]
fn test_signer_v2_wire_snapshot_additions_only() {
    let stripped = strip_line_comments(PROTO);
    assert!(
        !stripped.split_whitespace().any(|tok| tok == "reserved"),
        "signer.v2.proto must not use reserved (additive-only; D18/B5)"
    );

    let snapshot = parse_snapshot_rows(SNAPSHOT);
    let current = parse_proto_rows(PROTO);
    assert!(!snapshot.is_empty(), "snapshot must not be empty");
    assert!(!current.is_empty(), "proto parse produced no rows");

    use std::collections::BTreeMap;
    let snap_map: BTreeMap<&str, &str> =
        snapshot.iter().map(|r| (row_key(r), r.as_str())).collect();
    let cur_map: BTreeMap<&str, &str> = current.iter().map(|r| (row_key(r), r.as_str())).collect();

    let mut removed = Vec::new();
    let mut modified = Vec::new();
    for (key, snap_row) in &snap_map {
        match cur_map.get(key) {
            None => removed.push(*key),
            Some(cur_row) if cur_row != snap_row => modified.push((*key, *snap_row, *cur_row)),
            Some(_) => {}
        }
    }
    assert!(removed.is_empty(), "snapshot rows removed (D18/B5 forbids deletions): {removed:?}");
    assert!(
        modified.is_empty(),
        "snapshot rows changed (D18/B5 forbids renumber/rename/retype): {modified:?}"
    );

    let added: Vec<&str> =
        cur_map.iter().filter(|(k, _)| !snap_map.contains_key(*k)).map(|(_, row)| *row).collect();

    let baseline_messages = snapshot_message_names(&snapshot);
    let added_to_existing: Vec<&str> = added
        .iter()
        .copied()
        .filter(|row| message_of_field_row(row).is_some_and(|m| baseline_messages.contains(m)))
        .collect();
    assert!(
        added_to_existing.is_empty(),
        "new fields on existing messages are forbidden; add a new message instead: {added_to_existing:?}"
    );

    for expected in ISSUE_4_20A_ADDITIONS {
        assert!(added.contains(expected), "missing 4.20a addition {expected:?}; added={added:?}");
    }
}

#[test]
fn test_new_messages_number_fields_from_1_without_ssz() {
    let current = parse_proto_rows(PROTO);
    for msg in NEW_MESSAGES {
        let fields: Vec<(String, String, u32)> = current
            .iter()
            .filter_map(|row| {
                let prefix = format!("{msg}.");
                let rest = row.strip_prefix(&prefix)?;
                let (name_ty, num) = rest.split_once(" = ")?;
                let (name, ty) = name_ty.split_once(" : ")?;
                Some((name.to_string(), ty.to_string(), num.parse().ok()?))
            })
            .collect();
        assert!(!fields.is_empty(), "{msg} must declare fields");
        assert_eq!(fields[0].2, 1, "{msg} must number fields from 1, got {fields:?}");
        for (name, _ty, _) in &fields {
            assert!(
                !name.ends_with("_ssz"),
                "{msg}.{name} is an SSZ-bytes field; 4.20a messages must not carry SSZ bytes"
            );
        }
    }

    let header: Vec<&str> = current
        .iter()
        .filter(|row| row.starts_with("BeaconBlockHeader."))
        .map(String::as_str)
        .collect();
    assert_eq!(
        header,
        [
            "BeaconBlockHeader.slot : uint64 = 1",
            "BeaconBlockHeader.proposer_index : uint64 = 2",
            "BeaconBlockHeader.parent_root : bytes = 3",
            "BeaconBlockHeader.state_root : bytes = 4",
            "BeaconBlockHeader.body_root : bytes = 5",
        ]
    );
}
