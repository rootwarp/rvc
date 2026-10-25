//! Issue 2.2 / #216: CI inventory of fork-addition hazards.
//!
//! A new `ForkName` arm must not silently change behaviour. This gate scans
//! `crates/**` and `bin/**` for five greppable classes and asserts every hit
//! is in the checked-in inventory with a verdict — no `unclassified`, exact
//! per-class counts. The human table is `docs/gloas-fork-hazard-audit.md`;
//! this file is the machine copy. The two must agree.
//!
//! Classes: (1) `>= ForkName::X` (2) `.index = 0` / `.index = "0"` (3) `match`
//! on `ForkName` exhaustive vs `_ =>` (4) string-literal fork dispatch
//! (5) `.entries()` call sites.
//!
//! Identity is `(path, class, item, fingerprint)`. The fingerprint is the
//! normalised source line. Issue and verdict are bound to that key, so two
//! hits in one function cannot swap Issue cells by reordering rows.
//!
//! Self-exclusion (D7): this file's inventory literals contain the snippets
//! it searches for, so the walker skips its own path
//! (`kat_policy.rs:381-386` precedent).
//!
//! Spans come from `ra_ap_rustc_lexer`. An untrusted file keeps every raw hit.

use ra_ap_rustc_lexer::{strip_shebang, tokenize, FrontmatterAllowed, LiteralKind, TokenKind};
use rvc_architecture_tests::{byte_in_code, is_rust_ws, non_code_spans, ResolveError, SourceItems};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Classes / verdicts / inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Class {
    GeForkName = 1,
    IndexZero = 2,
    MatchForkName = 3,
    StringDispatch = 4,
    Entries = 5,
}

impl Class {
    fn n(self) -> u8 {
        self as u8
    }

    fn from_n(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::GeForkName),
            2 => Some(Self::IndexZero),
            3 => Some(Self::MatchForkName),
            4 => Some(Self::StringDispatch),
            5 => Some(Self::Entries),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::GeForkName => ">= ForkName::X",
            Self::IndexZero => "index = 0",
            Self::MatchForkName => "match ForkName",
            Self::StringDispatch => "string-literal fork dispatch",
            Self::Entries => ".entries()",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    InheritIntentionally,
    MustBound,
    DecidedNotInherited,
    TestOnly,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::InheritIntentionally => "inherit-intentionally",
            Self::MustBound => "must-bound",
            Self::DecidedNotInherited => "decided-not-inherited",
            Self::TestOnly => "test-only",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "inherit-intentionally" => Some(Self::InheritIntentionally),
            "must-bound" => Some(Self::MustBound),
            "decided-not-inherited" => Some(Self::DecidedNotInherited),
            "test-only" => Some(Self::TestOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Inv {
    path: &'static str,
    item: &'static str,
    class: Class,
    wildcard: bool,
    /// Normalised full source line: trim, then collapse ASCII whitespace to one space.
    fp: &'static str,
    verdict: Verdict,
    issue: &'static str,
}

const fn inv(
    path: &'static str,
    item: &'static str,
    class: Class,
    wildcard: bool,
    fp: &'static str,
    verdict: Verdict,
    issue: &'static str,
) -> Inv {
    Inv { path, item, class, wildcard, fp, verdict, issue }
}

/// Exact per-class counts. Update together with [`INVENTORY`] and the audit doc.
const EXPECTED_COUNTS: [(Class, usize); 5] = [
    (Class::GeForkName, 28),
    (Class::IndexZero, 8),
    (Class::MatchForkName, 10),
    (Class::StringDispatch, 11),
    (Class::Entries, 9),
];

/// Checked-in content anchors. Sorted by (class, path, item, fingerprint).
const INVENTORY: &[Inv] = &[
    // Class 1
    inv(
        "bin/rvc-keygen/src/exit.rs",
        "tests::test_exit_round_trip_encrypt_decrypt_sign",
        Class::GeForkName,
        false,
        "let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/beacon/src/client.rs",
        "BeaconClient::proposer_duties_path",
        Class::GeForkName,
        false,
        "if ForkName::from_epoch(epoch, schedule) >= ForkName::Gloas { \"v2\" } else { \"v1\" };",
        Verdict::InheritIntentionally,
        "4.5",
    ),
    inv(
        "crates/beacon/src/prepare_check.rs",
        "compute_preparable",
        Class::GeForkName,
        false,
        "&& (slot_fork >= ForkName::Gloas || response.consensus_version == \"gloas\")",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/beacon/src/prepare_check.rs",
        "compute_preparable",
        Class::GeForkName,
        false,
        "Ok(_) if slot_fork >= ForkName::Gloas => {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "BlockService<S, B>::propose_block_impl",
        Class::GeForkName,
        false,
        "let produce_result = if fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "BlockService<S, B>::propose_block_impl",
        Class::GeForkName,
        false,
        "let signed = if fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "record_produced_response",
        Class::GeForkName,
        false,
        "if slot_fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "reject_blinded_at_gloas",
        Class::GeForkName,
        false,
        "if slot_fork >= ForkName::Gloas || consensus_version == \"gloas\" {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "reject_gloas_version_pre_gloas",
        Class::GeForkName,
        false,
        "if got >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "reject_gloas_version_pre_gloas",
        Class::GeForkName,
        false,
        "if slot_fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "6.4",
    ),
    inv(
        "crates/builder/src/service.rs",
        "legacy_proposer_ops_retired",
        Class::GeForkName,
        false,
        "fork >= ForkName::Gloas",
        Verdict::InheritIntentionally,
        "6.10",
    ),
    inv(
        "crates/crypto/src/signing_root.rs",
        "capella_capped_fork_version",
        Class::GeForkName,
        false,
        "let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/signing_root.rs",
        "tests::legacy_voluntary_exit_root",
        Class::GeForkName,
        false,
        "let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/typed_signer.rs",
        "<LocalSigner as TypedSigner>::sign_aggregate_and_proof",
        Class::GeForkName,
        false,
        "if ctx.fork_name >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/typed_signer.rs",
        "<LocalSigner as TypedSigner>::sign_electra_aggregate_and_proof",
        Class::GeForkName,
        false,
        "if ctx.fork_name >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/grpc-signer/src/client.rs",
        "GrpcRemoteSigner::uses_gloas_rpc",
        Class::GeForkName,
        false,
        "ctx.fork_name >= ForkName::Gloas",
        Verdict::InheritIntentionally,
        "4.20c",
    ),
    inv(
        "crates/rvc/benches/deadline_rebenchmark.rs",
        "main",
        Class::GeForkName,
        false,
        "assert!(fork >= ForkName::Gloas, \"6.14 must resolve a Gloas-epoch slot; got {}\", fork.as_ref());",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/aggregation.rs",
        "AggregationService::fetch_sign_aggregate",
        Class::GeForkName,
        false,
        "if fork_name >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/aggregation.rs",
        "aggregate_fork_matches",
        Class::GeForkName,
        false,
        "VersionedAggregateAttestation::Gloas(_) => fork >= ForkName::Gloas,",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/mod.rs",
        "DutyOrchestrator<C, S, B>::run_payload_attestation_phase",
        Class::GeForkName,
        false,
        "if fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "4.13",
    ),
    inv(
        "crates/rvc/src/orchestrator/duty_management.rs",
        "DutyManagementService::check_reorg_at_epoch_boundary",
        Class::GeForkName,
        false,
        "if ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/duty_management.rs",
        "DutyManagementService::fetch_epoch_duties",
        Class::GeForkName,
        false,
        "let ptc_active = ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas;",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/utils.rs",
        "uses_electra_attestation_wire",
        Class::GeForkName,
        false,
        "fork >= ForkName::Electra",
        Verdict::InheritIntentionally,
        "2.8",
    ),
    inv(
        "crates/signer-server/src/dvt/peer_client.rs",
        "GrpcPeerRequester::uses_gloas_rpc",
        Class::GeForkName,
        false,
        "matches!(ForkName::try_from(fork_id), Ok(name) if name >= ForkName::Gloas)",
        Verdict::InheritIntentionally,
        "4.20c",
    ),
    inv(
        "crates/signer/src/lib.rs",
        "<SignerService as ValidatorSigner>::sign_aggregate_and_proof",
        Class::GeForkName,
        false,
        "if ForkName::from_epoch(epoch, fork_schedule) >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/signer/src/lib.rs",
        "<SignerService as ValidatorSigner>::sign_block_header",
        Class::GeForkName,
        false,
        "if sign_ctx.fork_name >= ForkName::Gloas || header_owned.body_ssz.is_empty() {",
        Verdict::InheritIntentionally,
        "4.20c",
    ),
    inv(
        "crates/signer/src/lib.rs",
        "<SignerService as ValidatorSigner>::sign_electra_aggregate_and_proof",
        Class::GeForkName,
        false,
        "if ForkName::from_epoch(epoch, fork_schedule) >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "4.20c",
    ),
    inv(
        "crates/timing/src/clock.rs",
        "DeadlineSchedule::for_fork",
        Class::GeForkName,
        false,
        "if fork >= ForkName::Gloas {",
        Verdict::InheritIntentionally,
        "4.19",
    ),
    // Class 2
    inv(
        "crates/rvc/src/orchestrator/attestation.rs",
        "AttestationService<C, S>::attest",
        Class::IndexZero,
        false,
        "single_data.index = \"0\".to_string();",
        Verdict::MustBound,
        "2.8",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        "test_electra_crypto_attestation_data_index_zeroed",
        Class::IndexZero,
        false,
        "crypto_data.index = 0;",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        "test_electra_signing_root_matches_submitted_data",
        Class::IndexZero,
        false,
        "crypto_data.index = 0; // EIP-7549",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        "test_electra_signing_root_matches_submitted_data",
        Class::IndexZero,
        false,
        "submitted_beacon_data.index = \"0\".to_string();",
        Verdict::TestOnly,
        "2.8",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        "test_pre_electra_data_index_preserved",
        Class::IndexZero,
        false,
        "crypto_data.index = 0;",
        Verdict::TestOnly,
        "2.3",
    ),
    inv(
        "crates/rvc/src/orchestrator/utils.rs",
        "convert_and_normalize_attestation_data",
        Class::IndexZero,
        false,
        "data.index = 0;",
        Verdict::MustBound,
        "2.3",
    ),
    inv(
        "crates/rvc/tests/gloas_data_index_round_trip.rs",
        "test_electra_and_fulu_still_zero_index_on_signing_and_submission",
        Class::IndexZero,
        false,
        "expected.index = 0;",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/rvc/tests/gloas_data_index_round_trip.rs",
        "test_gloas_data_index_0_and_1_round_trip",
        Class::IndexZero,
        false,
        "zeroed.index = 0;",
        Verdict::TestOnly,
        "—",
    ),
    // Class 3
    inv(
        "bin/rvc/tests/common/mock_bn.rs",
        "fork_version_hex",
        Class::MatchForkName,
        false,
        "match fork {",
        Verdict::TestOnly,
        "2.5b",
    ),
    inv(
        "crates/beacon/src/client.rs",
        "BeaconClient::get_aggregate_attestation",
        Class::MatchForkName,
        false,
        "match fork {",
        Verdict::InheritIntentionally,
        "RR-3.2",
    ),
    inv(
        "crates/beacon/src/client.rs",
        "decode_versioned_aggregate",
        Class::MatchForkName,
        false,
        "match requested {",
        Verdict::InheritIntentionally,
        "RR-3.2",
    ),
    inv(
        "crates/beacon/src/prepare_check.rs",
        "compute_preparable",
        Class::MatchForkName,
        false,
        "match ForkName::from_str(&response.consensus_version) {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/beacon/src/prepare_check.rs",
        "ssz_format",
        Class::MatchForkName,
        false,
        "Ok(match fork {",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/block-service/src/service/mod.rs",
        "ssz_block_format",
        Class::MatchForkName,
        false,
        "let format = match fork {",
        Verdict::InheritIntentionally,
        "6.4",
    ),
    inv(
        "crates/eth-types/src/block.rs",
        "expected_kzg_proof_count",
        Class::MatchForkName,
        false,
        "match fork {",
        Verdict::InheritIntentionally,
        "RR-3.9",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkName::body_layout",
        Class::MatchForkName,
        false,
        "match self {",
        Verdict::InheritIntentionally,
        "2.7",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkName::id",
        Class::MatchForkName,
        false,
        "match self {",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/rvc/tests/gloas_data_index_round_trip.rs",
        "epoch_for",
        Class::MatchForkName,
        false,
        "match fork {",
        Verdict::TestOnly,
        "—",
    ),
    // Class 4
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        "build_ssz_bytes",
        Class::StringDispatch,
        false,
        "!is_blinded && matches!(consensus_version, \"deneb\" | \"electra\" | \"fulu\");",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        "test_blinded_body_ssz_for_version",
        Class::StringDispatch,
        true,
        "match consensus_version {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/mocks.rs",
        "test_body_ssz_for_version",
        Class::StringDispatch,
        false,
        "match consensus_version {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/propose.rs",
        "test_propose_block_gloas_slot_deneb_version_mismatch_drops_duty",
        Class::StringDispatch,
        false,
        "matches!(",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/ssz.rs",
        "test_propose_block_ssz_gloas_slot_deneb_version_mismatch_drops_duty",
        Class::StringDispatch,
        false,
        "matches!(",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/v4.rs",
        "test_fulu_slot_gloas_version_unblinded_json_drops_duty_before_hasher",
        Class::StringDispatch,
        false,
        "matches!(",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/v4.rs",
        "test_fulu_slot_gloas_version_unblinded_ssz_drops_duty_before_hasher",
        Class::StringDispatch,
        false,
        "matches!(",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/block-service/src/service/tests/v4.rs",
        "test_v4_consensus_version_mismatch_drops_duty_before_signer",
        Class::StringDispatch,
        false,
        "matches!(",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/bn-manager/src/manager.rs",
        "ssz_produce_format",
        Class::StringDispatch,
        true,
        "match consensus_version {",
        Verdict::MustBound,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs",
        "test_gloas_slot_dispatches_produce_block_v4",
        Class::StringDispatch,
        false,
        "match &envelopes[0] {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/sync_committee.rs",
        "tests::contribution_kat",
        Class::StringDispatch,
        false,
        "match name {",
        Verdict::TestOnly,
        "—",
    ),
    // Class 5
    inv(
        "crates/beacon/src/types.rs",
        "compare_fork_schedule",
        Class::Entries,
        false,
        "expected.entries().into_iter().zip(FORK_SCHEDULE_KEYS)",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/crypto/src/typed_signer.rs",
        "SignContext::resolve",
        Class::Entries,
        false,
        ".entries()",
        Verdict::MustBound,
        "2.6",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkName::activation_epoch",
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkName::fork_version",
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkName::from_epoch",
        Class::Entries,
        false,
        ".entries()",
        Verdict::InheritIntentionally,
        "2.5b",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "ForkSchedule::next_activation",
        Class::Entries,
        false,
        "self.entries()",
        Verdict::InheritIntentionally,
        "—",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "tests::test_entries_contains_each_all_variant_exactly_once",
        Class::Entries,
        false,
        "let entries = schedule.entries();",
        Verdict::TestOnly,
        "2.1",
    ),
    inv(
        "crates/eth-types/src/fork.rs",
        "tests::test_fork_version_and_activation_epoch_unchanged_for_all_eight",
        Class::Entries,
        false,
        "let entries = schedule.entries();",
        Verdict::TestOnly,
        "2.5b",
    ),
    inv(
        "crates/rvc-spec-vectors/src/bin/gen_spec_kat.rs",
        "load_gloas_from_tar",
        Class::Entries,
        false,
        "let entries = tar.entries().map_err(|e| format!(\"read {}: {e}\", archive.display()))?;",
        Verdict::TestOnly,
        "—",
    ),
];

const SCANNER_REL: &str = "crates/architecture-tests/tests/fork_hazard_inventory.rs";
const AUDIT_DOC: &str = "docs/gloas-fork-hazard-audit.md";
const BEGIN_INVENTORY: &str = "<!-- BEGIN INVENTORY -->";
const END_INVENTORY: &str = "<!-- END INVENTORY -->";

const FORK_STRINGS: &[&str] = &[
    "\"phase0\"",
    "\"altair\"",
    "\"bellatrix\"",
    "\"capella\"",
    "\"deneb\"",
    "\"electra\"",
    "\"fulu\"",
    "\"gloas\"",
];

const SELF_FORK_VARIANTS: &[&str] =
    &["Phase0", "Altair", "Bellatrix", "Capella", "Deneb", "Electra", "Fulu", "Gloas"];

// ---------------------------------------------------------------------------
// Workspace walk
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn is_scanner_path(rel: &str) -> bool {
    rel.ends_with("architecture-tests/tests/fork_hazard_inventory.rs")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// `crates/**` + `bin/**` `*.rs` (src + tests + benches + examples).
fn crates_and_bin_rs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        let dir = root.join(base);
        if dir.is_dir() {
            collect_rs(&dir, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn ident_boundary_before(src: &str, at: usize) -> bool {
    at == 0 || !is_ident_char(src.as_bytes()[at - 1])
}

fn ident_boundary_after(src: &str, after: usize) -> bool {
    after >= src.len() || !is_ident_char(src.as_bytes()[after])
}

fn line_start(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

fn line_end(src: &str, byte: usize) -> usize {
    src[byte.min(src.len())..].find('\n').map(|i| byte + i).unwrap_or(src.len())
}

/// Trim, then collapse each `is_rust_ws` run to a single space.
fn normalise_line(line: &str) -> String {
    let mut out = String::new();
    let mut blank = false;
    for c in line.trim().chars() {
        if c.is_ascii() && is_rust_ws(c as u8) {
            if !blank && !out.is_empty() {
                out.push(' ');
                blank = true;
            }
        } else {
            out.push(c);
            blank = false;
        }
    }
    out
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    let b = src.as_bytes();
    while i < b.len() && is_rust_ws(b[i]) {
        i += 1;
    }
    i
}

fn skip_ws_comments(src: &str, mut i: usize) -> usize {
    let b = src.as_bytes();
    let n = b.len();
    loop {
        while i < n && is_rust_ws(b[i]) {
            i += 1;
        }
        if i + 1 < n && b[i] == b'/' && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < n && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        return i;
    }
}

fn close_brace(src: &str, open: usize) -> Option<usize> {
    if open >= src.len() || src.as_bytes()[open] != b'{' {
        return None;
    }
    let b = src.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn close_paren(src: &str, open: usize) -> Option<usize> {
    if open >= src.len() || src.as_bytes()[open] != b'(' {
        return None;
    }
    let b = src.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// `{` that opens a `match` body, skipping parens so closures in the scrutinee
/// are not mistaken for the body.
fn match_body_span(src: &str, match_kw: usize) -> Option<(usize, usize)> {
    let mut i = skip_ws_comments(src, match_kw + "match".len());
    let b = src.as_bytes();
    let mut paren = 0i32;
    let mut brack = 0i32;
    while i < b.len() {
        i = skip_ws_comments(src, i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => brack += 1,
            b']' => brack -= 1,
            b'{' if paren == 0 && brack == 0 => {
                let close = close_brace(src, i)?;
                return Some((i, close));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn matches_macro_span(src: &str, at: usize) -> Option<(usize, usize)> {
    let i = skip_ws_comments(src, at + "matches!".len());
    let close = close_paren(src, i)?;
    Some((i, close))
}

fn has_bare_underscore_token(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' && ident_boundary_before(body, i) && ident_boundary_after(body, i + 1) {
            return true;
        }
        i += 1;
    }
    false
}

fn top_level_wildcard(body: &str) -> bool {
    let mut depth = 0i32;
    for line in body.lines() {
        let start_depth = depth;
        let t = line.trim_start();
        if start_depth == 1 && (t.starts_with("_ =>") || t.starts_with("_=>")) {
            return true;
        }
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }
    false
}

fn line_has_forkname_pattern(line: &str) -> bool {
    let Some(idx) = line.find("ForkName::") else {
        return false;
    };
    match line.find("=>") {
        Some(arrow) => idx < arrow,
        None => line[idx..].contains('|'),
    }
}

fn line_has_self_fork_pattern(line: &str) -> bool {
    for v in SELF_FORK_VARIANTS {
        let pat = format!("Self::{v}");
        let Some(idx) = line.find(&pat) else {
            continue;
        };
        let before_arrow = match line.find("=>") {
            Some(arrow) => idx < arrow,
            None => line[idx..].contains('|'),
        };
        if before_arrow {
            return true;
        }
    }
    false
}

fn body_is_forkname_match(path: &str, body: &str) -> bool {
    let mut forkname = false;
    let mut self_hits = 0usize;
    for line in body.lines() {
        if line_has_forkname_pattern(line) {
            forkname = true;
        }
        if path.ends_with("eth-types/src/fork.rs") && line_has_self_fork_pattern(line) {
            self_hits += 1;
        }
    }
    forkname || self_hits >= 2
}

fn body_has_fork_string(body: &str) -> bool {
    FORK_STRINGS.iter().any(|s| body.contains(s))
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    path: String,
    class: Class,
    /// `None` skips the wildcard check (doc rows whose Kind cell is `—`).
    wildcard: Option<bool>,
    item: String,
    fp: String,
    resolve_error: Option<String>,
    verdict: Option<Verdict>,
    issue: Option<String>,
}

struct Scan<'a> {
    path: &'a str,
    src: &'a str,
    parsed: &'a Result<SourceItems, ResolveError>,
    non_code: &'a [(usize, usize)],
    uncertain: bool,
    covered: bool,
    toks: &'a [(u32, u32, u8)],
}

fn push_hit(out: &mut Vec<Hit>, scan: &Scan<'_>, at: usize, class: Class, wildcard: bool) {
    // Drop a comment or string hit only when the file is fully trusted.
    if !byte_in_code(scan.non_code, at) && !scan.uncertain {
        return;
    }
    let ls = line_start(scan.src, at);
    let le = line_end(scan.src, at);
    let (item, mut resolve_error) = match scan.parsed {
        Ok(items) => match items.enclosing(at) {
            Ok(id) => (id.as_str().to_string(), None),
            Err(e) => (String::new(), Some(e.to_string())),
        },
        Err(e) => (String::new(), Some(e.to_string())),
    };
    if scan.uncertain && resolve_error.is_none() {
        resolve_error = Some("lexer mask disagreed".to_string());
    }
    out.push(Hit {
        path: scan.path.to_string(),
        class,
        wildcard: Some(wildcard),
        item,
        fp: normalise_line(&scan.src[ls..le]),
        resolve_error,
        verdict: None,
        issue: None,
    });
}

const T_WS: u8 = 0;
const T_WS_HI: u8 = 1;
const T_COM: u8 = 2;
const T_ID: u8 = 3;
const T_COL: u8 = 4;

struct Lex {
    non_code: Vec<(usize, usize)>,
    uncertain: bool,
    covered: bool,
    toks: Vec<(u32, u32, u8)>,
}

fn lit_open(kind: LiteralKind) -> Option<bool> {
    match kind {
        LiteralKind::Char { terminated }
        | LiteralKind::Byte { terminated }
        | LiteralKind::Str { terminated }
        | LiteralKind::ByteStr { terminated }
        | LiteralKind::CStr { terminated } => Some(!terminated),
        LiteralKind::RawStr { n_hashes }
        | LiteralKind::RawByteStr { n_hashes }
        | LiteralKind::RawCStr { n_hashes } => Some(n_hashes.is_none()),
        LiteralKind::Int { .. } | LiteralKind::Float { .. } => None,
    }
}

fn shebang_untrusted(src: &str) -> bool {
    let line = src.lines().next().unwrap_or("");
    line.starts_with("#!") && !line.starts_with("#![")
}

fn lex_file(src: &str) -> Lex {
    let skip = strip_shebang(src).unwrap_or(0);
    let mut non_code = Vec::new();
    let mut toks = Vec::new();
    let mut uncertain = shebang_untrusted(src);
    let mut broke = false;
    let mut pos = skip;
    for tok in tokenize(&src[skip..], FrontmatterAllowed::No) {
        let len = tok.len as usize;
        let end = pos.saturating_add(len);
        if len == 0 || end > src.len() {
            uncertain = true;
            broke = true;
            break;
        }
        let (mask, bad, class) = match tok.kind {
            TokenKind::LineComment { .. } => (true, false, T_COM),
            TokenKind::BlockComment { terminated, .. } => (true, !terminated, T_COM),
            TokenKind::Whitespace => {
                let hi = src[pos..end].bytes().any(|b| b >= 0x80);
                (false, false, if hi { T_WS_HI } else { T_WS })
            }
            TokenKind::Ident => (false, false, T_ID),
            TokenKind::Colon => (false, false, T_COL),
            TokenKind::Unknown | TokenKind::InvalidIdent => (false, true, 5),
            TokenKind::GuardedStrPrefix
            | TokenKind::UnknownPrefix
            | TokenKind::UnknownPrefixLifetime => (false, true, 5),
            TokenKind::Literal { kind, .. } => match lit_open(kind) {
                Some(bad) => (true, bad, 5),
                None => (false, false, 5),
            },
            _ => (false, false, 5),
        };
        if mask {
            non_code.push((pos, end));
        }
        uncertain |= bad;
        toks.push((pos as u32, end as u32, class));
        pos = end;
    }
    let covered = !broke && pos == src.len();
    if !covered {
        uncertain = true;
    }
    let mut hand = non_code_spans(&src[skip..]);
    for span in &mut hand {
        span.0 += skip;
        span.1 += skip;
    }
    if non_code != hand {
        uncertain = true;
    }
    Lex { non_code, uncertain, covered, toks }
}

fn tok_at(toks: &[(u32, u32, u8)], pos: usize) -> Option<(usize, u8)> {
    let i = toks.binary_search_by_key(&pos, |t| t.0 as usize).ok()?;
    Some((toks[i].1 as usize, toks[i].2))
}

fn skip_gap(toks: &[(u32, u32, u8)], mut pos: usize) -> Result<usize, ()> {
    loop {
        match tok_at(toks, pos) {
            Some((end, T_WS | T_COM)) => pos = end,
            Some((_, T_WS_HI)) => return Err(()),
            _ => return Ok(pos),
        }
    }
}

fn gap_end(src: &str, mut i: usize) -> Result<usize, ()> {
    let b = src.as_bytes();
    while i < b.len() {
        if b[i] >= 0x80 || (b[i] == b'/' && matches!(b.get(i + 1), Some(b'*' | b'/'))) {
            return Err(());
        }
        if !is_rust_ws(b[i]) {
            break;
        }
        i += 1;
    }
    Ok(i)
}

/// Gap rule for a broken token stream: do not skip comments.
fn broken_ge(src: &str, at: usize) -> bool {
    let Ok(mut i) = gap_end(src, at + 2) else {
        return true;
    };
    if !src[i..].starts_with("ForkName") || !ident_boundary_after(src, i + 8) {
        return src.as_bytes().get(i).is_some_and(|b| *b >= 0x80);
    }
    i += 8;
    for _ in 0..2 {
        let Ok(j) = gap_end(src, i) else {
            return true;
        };
        if !src[j..].starts_with(':') {
            return src.as_bytes().get(j).is_some_and(|b| *b >= 0x80);
        }
        i = j + 1;
    }
    true
}

fn token_ge(src: &str, toks: &[(u32, u32, u8)], at: usize) -> bool {
    let Ok(pos) = skip_gap(toks, at + 2) else {
        return true;
    };
    let Some((end, class)) = tok_at(toks, pos) else {
        return false;
    };
    if class != T_ID || &src[pos..end] != "ForkName" {
        return src.as_bytes().get(pos).is_some_and(|b| *b >= 0x80);
    }
    let mut pos = end;
    for _ in 0..2 {
        let Ok(next) = skip_gap(toks, pos) else {
            return true;
        };
        let Some((end, class)) = tok_at(toks, next) else {
            return false;
        };
        if class != T_COL {
            return false;
        }
        pos = end;
    }
    true
}

fn scan_ge_fork_name(scan: &Scan<'_>, out: &mut Vec<Hit>) {
    let src = scan.src;
    let mut from = 0;
    while let Some(rel) = src[from..].find(">=") {
        let at = from + rel;
        from = at + 2;
        let hit = if scan.covered && tok_at(scan.toks, at).is_some() {
            token_ge(src, scan.toks, at)
        } else {
            broken_ge(src, at)
        };
        if hit {
            push_hit(out, scan, at, Class::GeForkName, false);
        }
    }
}

fn scan_index_zero(scan: &Scan<'_>, out: &mut Vec<Hit>) {
    let src = scan.src;
    let mut from = 0;
    while let Some(rel) = src[from..].find(".index") {
        let at = from + rel;
        from = at + 6;
        if !ident_boundary_after(src, at + 6) {
            continue;
        }
        let mut i = skip_ws(src, at + 6);
        if i >= src.len() || src.as_bytes()[i] != b'=' {
            continue;
        }
        i = skip_ws(src, i + 1);
        if i >= src.len() {
            continue;
        }
        let b = src.as_bytes();
        let is_int_zero = b[i] == b'0' && ident_boundary_after(src, i + 1);
        let is_str_zero = src[i..].starts_with("\"0\"");
        if is_int_zero || is_str_zero {
            push_hit(out, scan, at, Class::IndexZero, false);
        }
    }
}

fn scan_entries(scan: &Scan<'_>, out: &mut Vec<Hit>) {
    let src = scan.src;
    let mut from = 0;
    while let Some(rel) = src[from..].find(".entries") {
        let at = from + rel;
        from = at + 8;
        if !ident_boundary_after(src, at + 8) {
            continue;
        }
        let i = skip_ws(src, at + 8);
        if i < src.len() && src.as_bytes()[i] == b'(' {
            push_hit(out, scan, at, Class::Entries, false);
        }
    }
}

fn scan_match_sites(scan: &Scan<'_>, out: &mut Vec<Hit>) {
    let src = scan.src;
    let mut from = 0;
    while let Some(rel) = src[from..].find("match") {
        let at = from + rel;
        from = at + 5;
        if !ident_boundary_before(src, at) {
            continue;
        }
        if src[at..].starts_with("matches!") {
            if let Some((open, close)) = matches_macro_span(src, at) {
                let body = &src[open..=close];
                if body_has_fork_string(body) {
                    let wildcard = has_bare_underscore_token(body);
                    push_hit(out, scan, at, Class::StringDispatch, wildcard);
                }
            }
            continue;
        }
        if !ident_boundary_after(src, at + 5) {
            continue;
        }
        let Some((open, close)) = match_body_span(src, at) else {
            continue;
        };
        let body = &src[open..=close];
        let wildcard = top_level_wildcard(body);
        if body_is_forkname_match(scan.path, body) {
            push_hit(out, scan, at, Class::MatchForkName, wildcard);
        }
        if body_has_fork_string(body) {
            push_hit(out, scan, at, Class::StringDispatch, wildcard);
        }
    }
}

fn hit_ord(hit: &Hit) -> (Class, &str, &str, &str) {
    (hit.class, hit.path.as_str(), hit.item.as_str(), hit.fp.as_str())
}

/// All five classes in `src` attributed to workspace-relative `path`.
fn scan_source(path: &str, src: &str) -> Vec<Hit> {
    let lexed = lex_file(src);
    let parsed = SourceItems::parse(src);
    let scan = Scan {
        path,
        src,
        parsed: &parsed,
        non_code: &lexed.non_code,
        uncertain: lexed.uncertain,
        covered: lexed.covered,
        toks: &lexed.toks,
    };
    let mut out = Vec::new();
    scan_ge_fork_name(&scan, &mut out);
    scan_index_zero(&scan, &mut out);
    scan_match_sites(&scan, &mut out);
    scan_entries(&scan, &mut out);
    out.sort_by(|a, b| hit_ord(a).cmp(&hit_ord(b)));
    out
}

struct WorkspaceScan {
    hits: Vec<Hit>,
    files: usize,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = crates_and_bin_rs(&root);
    let mut hits = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if is_scanner_path(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        hits.extend(scan_source(&rel, &src));
    }
    hits.sort_by(|a, b| hit_ord(a).cmp(&hit_ord(b)));
    WorkspaceScan { hits, files: files.len() }
}

// ---------------------------------------------------------------------------
// Audit-doc parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct DocRow {
    path: String,
    item: String,
    fp: String,
    class: Class,
    wildcard: Option<bool>,
    verdict: Verdict,
    issue: String,
}

/// Code spans, including a longer fence when the span contains a backtick.
fn code_spans(cell: &str) -> Vec<String> {
    let chars: Vec<char> = cell.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        if chars[i] != '`' {
            i += 1;
            continue;
        }
        let mut n = 0;
        while i < chars.len() && chars[i] == '`' {
            n += 1;
            i += 1;
        }
        let start = i;
        while i < chars.len() {
            if chars[i] != '`' {
                i += 1;
                continue;
            }
            let tick_at = i;
            let mut m = 0;
            while i < chars.len() && chars[i] == '`' {
                m += 1;
                i += 1;
            }
            if m == n {
                out.push(chars[start..tick_at].iter().collect());
                break;
            }
        }
    }
    out
}

fn parse_site_cell(cell: &str) -> Option<(String, String, String)> {
    let spans = code_spans(cell);
    if spans.len() != 3 || spans.iter().any(|s| s.is_empty()) {
        return None;
    }
    Some((spans[0].clone(), spans[1].clone(), spans[2].clone()))
}

/// Split a markdown row on `|` that is outside a code span.
fn split_table_row(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '`' {
            let mut n = 0;
            while i < chars.len() && chars[i] == '`' {
                n += 1;
                cur.push('`');
                i += 1;
            }
            while i < chars.len() {
                if chars[i] != '`' {
                    cur.push(chars[i]);
                    i += 1;
                    continue;
                }
                let mut m = 0;
                while i < chars.len() && chars[i] == '`' {
                    m += 1;
                    cur.push('`');
                    i += 1;
                }
                if m == n {
                    break;
                }
            }
            continue;
        }
        if chars[i] == '|' {
            cells.push(cur.trim().to_string());
            cur.clear();
            i += 1;
            continue;
        }
        cur.push(chars[i]);
        i += 1;
    }
    cells.push(cur.trim().to_string());
    cells.into_iter().filter(|c| !c.is_empty()).collect()
}

fn parse_kind_wildcard(kind: &str) -> Option<bool> {
    match kind.trim() {
        "_" | "wildcard" => Some(true),
        "exhaustive" => Some(false),
        "—" | "-" | "–" => None,
        _ => None,
    }
}

fn parse_inventory_table(doc: &str) -> Result<Vec<DocRow>, String> {
    let start = doc.find(BEGIN_INVENTORY).ok_or("missing BEGIN INVENTORY marker")?;
    let rest = &doc[start + BEGIN_INVENTORY.len()..];
    let end = rest.find(END_INVENTORY).ok_or("missing END INVENTORY marker")?;
    let table = &rest[..end];
    let mut rows = Vec::new();
    for raw in table.lines() {
        let line = raw.trim();
        if !line.starts_with('|') || line.contains("---") || line.contains("Site") {
            continue;
        }
        let cells = split_table_row(line);
        if cells.len() != 6 {
            return Err(format!("inventory row needs 6 cells, got {}: {line}", cells.len()));
        }
        let (path, item, fp) =
            parse_site_cell(&cells[0]).ok_or_else(|| format!("bad Site cell: {}", cells[0]))?;
        let class_n: u8 = cells[1].parse().map_err(|_| format!("bad Class cell: {}", cells[1]))?;
        let class = Class::from_n(class_n).ok_or_else(|| format!("unknown class {class_n}"))?;
        let wildcard = parse_kind_wildcard(&cells[2]);
        let verdict = Verdict::parse(&cells[3])
            .ok_or_else(|| format!("unclassified or unknown verdict '{}'", cells[3]))?;
        let issue = cells[5].clone();
        rows.push(DocRow { path, item, fp, class, wildcard, verdict, issue });
    }
    Ok(rows)
}

fn row_key(path: &str, class: Class, item: &str, fp: &str) -> (String, u8, String, String) {
    (path.to_string(), class.n(), item.to_string(), fp.to_string())
}

/// Multiset equality of `(path, class, item, fingerprint)`, plus wildcard,
/// verdict, and issue when the hit carries them. A resolver error is a miss:
/// the gate does not substitute `<module>`.
fn reconcile(found: &[Hit], expected: &[Inv]) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut exp: HashMap<(String, u8, String, String), &Inv> = HashMap::new();
    for row in expected {
        let key = row_key(row.path, row.class, row.item, row.fp);
        if exp.insert(key, row).is_some() {
            errors.push(format!(
                "duplicate row {} class {} item {} fingerprint {:?}",
                row.path,
                row.class.n(),
                row.item,
                row.fp
            ));
        }
    }
    let mut seen = HashSet::new();
    for hit in found {
        if let Some(err) = &hit.resolve_error {
            errors.push(format!("resolver failed on {} fingerprint {:?}: {err}", hit.path, hit.fp));
            continue;
        }
        let key = row_key(&hit.path, hit.class, &hit.item, &hit.fp);
        match exp.get(&key) {
            None => errors.push(format!(
                "extra {} class {} item {} fingerprint {:?}",
                hit.path,
                hit.class.n(),
                hit.item,
                hit.fp
            )),
            Some(row) => {
                if !seen.insert(key) {
                    errors.push(format!(
                        "duplicate hit {} class {} item {} fingerprint {:?}",
                        hit.path,
                        hit.class.n(),
                        hit.item,
                        hit.fp
                    ));
                    continue;
                }
                if let Some(wc) = hit.wildcard {
                    if wc != row.wildcard {
                        errors.push(format!(
                            "wildcard mismatch {} class {} item {} fingerprint {:?}: scan={wc} inventory={}",
                            hit.path,
                            hit.class.n(),
                            hit.item,
                            hit.fp,
                            row.wildcard
                        ));
                    }
                }
                if let Some(verdict) = hit.verdict {
                    if verdict != row.verdict {
                        errors.push(format!(
                            "verdict mismatch {} class {} item {} fingerprint {:?}: {} vs {}",
                            hit.path,
                            hit.class.n(),
                            hit.item,
                            hit.fp,
                            verdict.as_str(),
                            row.verdict.as_str()
                        ));
                    }
                }
                if let Some(issue) = &hit.issue {
                    if issue != row.issue {
                        errors.push(format!(
                            "issue mismatch {} class {} item {} fingerprint {:?}: {issue} vs {}",
                            hit.path,
                            hit.class.n(),
                            hit.item,
                            hit.fp,
                            row.issue
                        ));
                    }
                }
            }
        }
    }
    for row in expected {
        let key = row_key(row.path, row.class, row.item, row.fp);
        if !seen.contains(&key) {
            errors.push(format!(
                "missing {} class {} item {} fingerprint {:?}",
                row.path,
                row.class.n(),
                row.item,
                row.fp
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[test]
fn fork_hazard_inventory_matches_workspace() {
    let scan = scan_workspace();
    assert!(
        scan.files > 100,
        "scanned only {} files under crates/ and bin/; workspace walk likely broke",
        scan.files
    );
    assert!(
        scan.hits.iter().all(|h| !is_scanner_path(&h.path)),
        "scanner source must be self-excluded"
    );

    for (class, expected) in EXPECTED_COUNTS {
        let inv_n = INVENTORY.iter().filter(|r| r.class == class).count();
        let scan_n = scan.hits.iter().filter(|h| h.class == class).count();
        assert_eq!(
            inv_n,
            expected,
            "INVENTORY class {} ({}) count {inv_n} != pinned {expected}",
            class.n(),
            class.label()
        );
        assert_eq!(
            scan_n,
            expected,
            "scan class {} ({}) count {scan_n} != pinned {expected}",
            class.n(),
            class.label()
        );
    }
    assert_eq!(scan.hits.len(), INVENTORY.len(), "scan hit count != inventory len");
    reconcile(&scan.hits, INVENTORY).unwrap_or_else(|e| {
        panic!(
            "fork-hazard inventory (issue 2.2): every scan hit under crates/** and bin/** must \
             equal a classified row in INVENTORY (path, class, item, fingerprint).\n{e}"
        )
    });
}

#[test]
fn audit_doc_lists_every_inventory_row() {
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join(AUDIT_DOC))
        .unwrap_or_else(|e| panic!("read {AUDIT_DOC}: {e}"));
    let rows = parse_inventory_table(&doc).unwrap_or_else(|e| panic!("parse {AUDIT_DOC}: {e}"));
    assert_eq!(rows.len(), INVENTORY.len(), "{AUDIT_DOC} row count != INVENTORY");
    let found: Vec<Hit> = rows
        .into_iter()
        .map(|row| Hit {
            path: row.path,
            class: row.class,
            wildcard: row.wildcard,
            item: row.item,
            fp: row.fp,
            resolve_error: None,
            verdict: Some(row.verdict),
            issue: Some(row.issue),
        })
        .collect();
    reconcile(&found, INVENTORY)
        .unwrap_or_else(|e| panic!("{AUDIT_DOC} disagrees with INVENTORY:\n{e}"));
}

#[test]
fn inventory_is_sorted_and_counts_sum() {
    let mut prev: Option<(u8, &str, &str, &str)> = None;
    for row in INVENTORY {
        let cur = (row.class.n(), row.path, row.item, row.fp);
        if let Some(p) = prev {
            assert!(
                p < cur,
                "INVENTORY must stay sorted by (class, path, item, fingerprint): {p:?} then {cur:?}"
            );
        }
        prev = Some(cur);
    }
    let sum: usize = EXPECTED_COUNTS.iter().map(|(_, n)| n).sum();
    assert_eq!(sum, INVENTORY.len());
}

// ---------------------------------------------------------------------------
// Matcher unit tests (synthetic RED / self-exclusion)
// ---------------------------------------------------------------------------

#[test]
fn new_ge_fork_name_site_is_detected_outside_inventory() {
    // AC: a new `>= ForkName::` site not on the inventory fails membership.
    let src = "fn f(fork: ForkName) {\n    if fork >= ForkName::Electra {\n        let _ = 1;\n    }\n}\n";
    let rel = "crates/rvc/src/orphan_fork_guard.rs";
    let hits = scan_source(rel, src);
    let ge: Vec<_> = hits.iter().filter(|h| h.class == Class::GeForkName).collect();
    assert_eq!(ge.len(), 1, "expected one class-1 hit, got {hits:?}");
    assert_eq!(ge[0].path, rel);
    assert_eq!(ge[0].item, "f");
    assert!(ge[0].fp.contains(">= ForkName::Electra"));
    assert!(ge[0].resolve_error.is_none(), "{:?}", ge[0].resolve_error);
    let err = reconcile(&hits, INVENTORY).unwrap_err();
    assert!(err.contains("extra"), "{err}");
    assert!(err.contains(&ge[0].fp), "{err}");
    assert!(err.contains("f"), "{err}");
}

#[test]
fn scanner_path_is_self_excluded() {
    assert!(is_scanner_path(SCANNER_REL));
    assert!(is_scanner_path("foo/architecture-tests/tests/fork_hazard_inventory.rs"));
    assert!(!is_scanner_path("crates/architecture-tests/tests/kat_policy.rs"));

    let root = workspace_root();
    let src = std::fs::read_to_string(root.join(SCANNER_REL)).expect("read scanner");
    assert!(
        src.contains(">= ForkName::"),
        "inventory literals must contain the class-1 needle (that is why we self-exclude)"
    );
    let unfiltered = scan_source(SCANNER_REL, &src);
    assert!(
        unfiltered.iter().all(|h| h.class != Class::GeForkName),
        ">= ForkName:: inside a string is not a code hit; got {unfiltered:?}"
    );

    let walk = scan_workspace();
    assert!(
        walk.hits.iter().all(|h| h.path != SCANNER_REL),
        "workspace walk must skip {SCANNER_REL}"
    );
}

#[test]
fn class_matchers_on_synthetic_snippets() {
    let ge = scan_source("t.rs", "let x = fork >= ForkName::Fulu;\n");
    assert_eq!(ge.iter().filter(|h| h.class == Class::GeForkName).count(), 1);

    let idx = scan_source("t.rs", "data.index = 0;\nsingle.index = \"0\".to_string();\n");
    assert_eq!(idx.iter().filter(|h| h.class == Class::IndexZero).count(), 2);

    let ent = scan_source("t.rs", "schedule.entries().into_iter();\n");
    assert_eq!(ent.iter().filter(|h| h.class == Class::Entries).count(), 1);

    let exhaustive = scan_source(
        "bin/rvc/tests/common/mock_bn.rs",
        "fn f(fork: ForkName) {\n    match fork {\n        ForkName::Phase0 => 0,\n        ForkName::Fulu => 6,\n    }\n}\n",
    );
    let m: Vec<_> = exhaustive.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].wildcard, Some(false), "no _ => arm is exhaustive");

    let wild = scan_source(
        "bin/rvc/tests/common/mock_bn.rs",
        "fn f(fork: ForkName) {\n    match fork {\n        ForkName::Fulu => 6,\n        _ => 0,\n    }\n}\n",
    );
    let m: Vec<_> = wild.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].wildcard, Some(true), "_ => arm is wildcard");

    let ssz = scan_source(
        "crates/block-service/src/service/mod.rs",
        "match consensus_version {\n    \"deneb\" | \"electra\" | \"fulu\" => A,\n    _ => B,\n}\n",
    );
    let s: Vec<_> = ssz.iter().filter(|h| h.class == Class::StringDispatch).collect();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].wildcard, Some(true));

    let matches_macro = scan_source(
        "t.rs",
        "let x = matches!(consensus_version, \"deneb\" | \"electra\" | \"fulu\");\n",
    );
    assert_eq!(matches_macro.iter().filter(|h| h.class == Class::StringDispatch).count(), 1);

    // Comments are not hits.
    let commented = scan_source("t.rs", "// if fork >= ForkName::Electra { }\n");
    assert!(commented.iter().all(|h| h.class != Class::GeForkName));
}

#[test]
fn self_fork_match_in_fork_rs_is_class_three() {
    let src = r#"
    pub fn id(self) -> u32 {
        match self {
            Self::Phase0 => 0,
            Self::Altair => 1,
            Self::Fulu => 6,
        }
    }
"#;
    let hits = scan_source("crates/eth-types/src/fork.rs", src);
    let m: Vec<_> = hits.iter().filter(|h| h.class == Class::MatchForkName).collect();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].wildcard, Some(false));
}

fn negate_first_ge_in_fn(src: &str, fn_name: &str) -> String {
    let marker = format!("fn {fn_name}");
    let at = src.find(&marker).unwrap_or_else(|| panic!("missing {marker}"));
    let rel = src[at..].find(">=").unwrap_or_else(|| panic!("no >= after {marker}"));
    let mut out = src.to_string();
    out.replace_range(at + rel..at + rel + 2, "<");
    out
}

/// The real `slot_fork` line, then that line copied through `wrapper` (`{line}`)
/// inside the function, with the real `>=` negated.
fn copy_slot_fork_line_and_negate(src: &str, wrapper: &str) -> String {
    let fn_name = "reject_gloas_version_pre_gloas";
    let marker = format!("fn {fn_name}");
    let fn_at = src.find(&marker).unwrap_or_else(|| panic!("missing {marker}"));
    let needle = "if slot_fork >= ForkName::Gloas {";
    let rel = src[fn_at..].find(needle).unwrap_or_else(|| panic!("missing {needle}"));
    let at = fn_at + rel;
    let line = src[line_start(src, at)..line_end(src, at)].to_string();
    let negated = negate_first_ge_in_fn(src, fn_name);
    let fn_at = negated.find(&marker).unwrap();
    let brace = negated[fn_at..].find('{').unwrap_or_else(|| panic!("no brace"));
    let pos = fn_at + brace + 1;
    let snippet = wrapper.replace("{line}", &line);
    format!("{}{snippet}{}", &negated[..pos], &negated[pos..])
}

#[test]
fn negated_gloas_compare_fails_reconcile_on_the_fingerprint() {
    let path = "crates/block-service/src/service/mod.rs";
    let src = std::fs::read_to_string(workspace_root().join(path)).expect("read block service");
    let rows: Vec<Inv> = INVENTORY.iter().copied().filter(|r| r.path == path).collect();
    let live = scan_source(path, &src);
    reconcile(&live, &rows).unwrap_or_else(|e| panic!("live file must reconcile:\n{e}"));
    let mutated = negate_first_ge_in_fn(&src, "reject_gloas_version_pre_gloas");
    assert_ne!(mutated, src);
    let err = reconcile(&scan_source(path, &mutated), &rows).unwrap_err();
    assert!(err.contains("missing"), "{err}");
    assert!(err.contains("reject_gloas_version_pre_gloas"), "{err}");
    assert!(err.contains("if slot_fork >= ForkName::Gloas {"), "{err}");
    assert!(!err.contains("if got >= ForkName::Gloas {"), "{err}");
}

#[test]
fn reject_gloas_issue_cells_are_bound_to_fingerprints() {
    let slot_fp = "if slot_fork >= ForkName::Gloas {";
    let got_fp = "if got >= ForkName::Gloas {";
    let slot = *INVENTORY
        .iter()
        .find(|r| r.item == "reject_gloas_version_pre_gloas" && r.fp == slot_fp)
        .expect("slot_fork row");
    let got = *INVENTORY
        .iter()
        .find(|r| r.item == "reject_gloas_version_pre_gloas" && r.fp == got_fp)
        .expect("got row");
    assert_eq!(slot.issue, "6.4");
    assert_eq!(got.issue, "—");
    assert_eq!(slot.item, got.item);
    assert_ne!(slot.fp, got.fp);
    assert!(
        (got.class.n(), got.path, got.item, got.fp)
            < (slot.class.n(), slot.path, slot.item, slot.fp),
        "fingerprint order fixes these two rows; swapping them fails the sort"
    );

    let src = std::fs::read_to_string(workspace_root().join(slot.path)).unwrap();
    let mut hits: Vec<Hit> = scan_source(slot.path, &src)
        .into_iter()
        .filter(|h| h.item == "reject_gloas_version_pre_gloas")
        .collect();
    assert_eq!(hits.len(), 2, "{hits:?}");
    for hit in &mut hits {
        let row = if hit.fp == slot_fp { slot } else { got };
        assert_eq!(hit.fp, row.fp, "fingerprint equality, not a substring");
        hit.issue = Some(row.issue.to_string());
        hit.verdict = Some(row.verdict);
    }
    reconcile(&hits, &[got, slot]).unwrap_or_else(|e| panic!("{e}"));
    let swapped = [Inv { issue: slot.issue, ..got }, Inv { issue: got.issue, ..slot }];
    let err = reconcile(&hits, &swapped).unwrap_err();
    assert!(err.contains("issue mismatch"), "{err}");
    assert!(err.contains(slot_fp), "{err}");
    assert!(err.contains(got_fp), "{err}");
    assert!(err.contains("6.4"), "{err}");
}

#[test]
fn non_ascii_item_fails_the_gate_closed() {
    let src = "fn é() {\n    if fork >= ForkName::Gloas {\n    }\n}\n";
    let hits = scan_source("crates/rvc/src/non_ascii_gate.rs", src);
    assert!(hits.iter().any(|h| h.class == Class::GeForkName));
    assert!(hits.iter().all(|h| h.item != "<module>"));
    let err = reconcile(&hits, &[]).unwrap_err();
    assert!(err.contains("resolver failed"), "{err}");
    assert!(err.contains("non-ascii"), "{err}");
}

#[test]
fn site_cell_keeps_pipes_and_backticks() {
    let doc = r#"
<!-- BEGIN INVENTORY -->
| Site | Class | Kind | Verdict | Rationale | Issue |
|---|---|---|---|---|---|
| `crates/t.rs` `build_ssz_bytes` `!is_blinded && matches!(consensus_version, "deneb" | "electra" | "fulu");` | 4 | exhaustive | test-only | r | — |
| `crates/t.rs` `f` ``"epoch `>= ForkName::Gloas`"`` | 1 | — | test-only | r | — |
<!-- END INVENTORY -->
"#;
    let rows = parse_inventory_table(doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].fp.contains("| \"electra\" |"), "{}", rows[0].fp);
    assert!(rows[1].fp.contains("`>= ForkName::Gloas`"), "{}", rows[1].fp);
}

#[test]
fn reconcile_rejects_wildcard_verdict_and_prefix_drift() {
    let row = *INVENTORY.iter().find(|r| r.wildcard).expect("a wildcard row");
    let base = Hit {
        path: row.path.to_string(),
        class: row.class,
        wildcard: Some(row.wildcard),
        item: row.item.to_string(),
        fp: row.fp.to_string(),
        resolve_error: None,
        verdict: Some(row.verdict),
        issue: Some(row.issue.to_string()),
    };
    let mut wild = base.clone();
    wild.wildcard = Some(!row.wildcard);
    let err = reconcile(std::slice::from_ref(&wild), std::slice::from_ref(&row)).unwrap_err();
    assert!(err.contains("wildcard mismatch"), "{err}");
    let mut verdict = base.clone();
    verdict.verdict = Some(match row.verdict {
        Verdict::TestOnly => Verdict::MustBound,
        _ => Verdict::TestOnly,
    });
    let err = reconcile(std::slice::from_ref(&verdict), std::slice::from_ref(&row)).unwrap_err();
    assert!(err.contains("verdict mismatch"), "{err}");
    let mut prefix = base;
    prefix.fp.push_str(" extra");
    let err = reconcile(std::slice::from_ref(&prefix), std::slice::from_ref(&row)).unwrap_err();
    assert!(err.contains("missing"), "{err}");
    assert!(err.contains("extra"), "{err}");
    assert!(err.contains(row.fp), "{err}");
}

#[test]
fn comment_mentions_of_entries_are_ignored() {
    let src = "/// Resolve from `schedule.entries()`.\nfn f() {}\n";
    let hits = scan_source("crates/eth-types/src/fork.rs", src);
    assert!(hits.iter().all(|h| h.class != Class::Entries));
}

#[test]
fn negated_line_is_not_satisfied_by_a_comment_or_string_copy() {
    let path = "crates/block-service/src/service/mod.rs";
    let src = std::fs::read_to_string(workspace_root().join(path)).expect("read block service");
    let rows: Vec<Inv> = INVENTORY.iter().copied().filter(|r| r.path == path).collect();
    let wrappers = [
        "\n/*\n{line}\n*/\n",
        "\n    let _s = \"\n{line}\n    \";\n",
        "\n    let _s = r#\"\n{line}\n    \"#;\n",
    ];
    for wrapper in wrappers {
        let edited = copy_slot_fork_line_and_negate(&src, wrapper);
        let err = reconcile(&scan_source(path, &edited), &rows).unwrap_err();
        assert!(err.contains("missing"), "{wrapper}\n{err}");
        assert!(err.contains("reject_gloas_version_pre_gloas"), "{wrapper}\n{err}");
        assert!(err.contains("if slot_fork >= ForkName::Gloas {"), "{wrapper}\n{err}");
        assert!(!err.contains("if got >= ForkName::Gloas {"), "{wrapper}\n{err}");
    }
}

#[test]
fn ge_gap_sees_vertical_tab_and_fails_closed_on_non_ascii() {
    let vt = "fn f() {\n    if slot_fork >=\u{000B}ForkName::Gloas { }\n}\n";
    let hits = scan_source("crates/block-service/src/gap.rs", vt);
    let ge: Vec<_> = hits.iter().filter(|h| h.class == Class::GeForkName).collect();
    assert_eq!(ge.len(), 1, "{hits:?}");
    assert!(ge[0].resolve_error.is_none(), "{:?}", ge[0].resolve_error);
    assert_eq!(ge[0].item, "f");
    assert_eq!(ge[0].fp, "if slot_fork >= ForkName::Gloas { }");
    let err = reconcile(&hits, &[]).unwrap_err();
    assert!(err.contains("extra"), "{err}");

    for (label, gap) in [("line-sep", '\u{2028}'), ("nel", '\u{0085}')] {
        let src = format!("fn f() {{\n    if slot_fork >={gap}ForkName::Gloas {{ }}\n}}\n");
        let hits = scan_source("crates/block-service/src/gap.rs", &src);
        let ge: Vec<_> = hits.iter().filter(|h| h.class == Class::GeForkName).collect();
        assert_eq!(ge.len(), 1, "{label}: {hits:?}");
        let resolve = ge[0].resolve_error.as_deref().unwrap_or("");
        assert!(resolve.contains("non-ascii"), "{label}: {resolve}");
        let err = reconcile(&hits, &[]).unwrap_err();
        assert!(err.contains("resolver failed"), "{label}: {err}");
    }

    let header = "#[derive(PartialEq, PartialOrd)]\nenum ForkName { Gloas }\n";
    for (name, gap) in [("vt", "\u{000B}"), ("line-sep", "\u{2028}"), ("nel", "\u{0085}")] {
        let src = format!("{header}pub fn b(slot_fork: ForkName) -> bool {{ slot_fork >={gap}ForkName::Gloas }}\n");
        assert_rustc_lib_accepts(name, &src);
    }
}

fn assert_rustc_lib_accepts(name: &str, src: &str) {
    let dir = std::env::temp_dir().join(format!("rvc-gap-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rs = dir.join("case.rs");
    std::fs::write(&rs, src).unwrap();
    let out = std::process::Command::new("rustc")
        .args(["--edition", "2021", "--crate-type", "lib", "--error-format", "short"])
        .arg(&rs)
        .arg("-o")
        .arg(dir.join("case.rlib"))
        .output()
        .expect("spawn rustc");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{name}\n{src}\n{}", String::from_utf8_lossy(&out.stderr));
}

fn fork_prog(body: &str) -> String {
    format!("#[derive(PartialEq, PartialOrd)]\nenum ForkName {{ Gloas }}\n{body}")
}

fn assert_one_ge(name: &str, src: &str) -> Hit {
    let hits = scan_source("crates/block-service/src/gap.rs", src);
    let ge: Vec<_> = hits.iter().filter(|h| h.class == Class::GeForkName).collect();
    assert_eq!(ge.len(), 1, "{name}: {hits:?}");
    let err = reconcile(&hits, &[]).unwrap_err();
    assert!(err.contains("extra") || err.contains("resolver failed"), "{name}: {err}");
    ge[0].clone()
}

#[test]
fn comment_and_spaced_path_in_the_ge_gap_are_hits() {
    let block = fork_prog(
        "pub fn f(slot_fork: ForkName) {\n    if slot_fork >= /* c */ ForkName::Gloas {}\n}\n",
    );
    assert_rustc_lib_accepts("gap-block", &block);
    let hit = assert_one_ge("gap-block", &block);
    assert!(hit.resolve_error.is_none(), "{:?}", hit.resolve_error);
    assert_eq!(hit.item, "f");
    assert!(hit.fp.contains("/* c */") && hit.fp.contains("ForkName::Gloas"), "{}", hit.fp);

    let line = fork_prog(
        "pub fn f(slot_fork: ForkName) {\n    if slot_fork >= // c\n ForkName::Gloas {}\n}\n",
    );
    assert_rustc_lib_accepts("gap-line", &line);
    let hit = assert_one_ge("gap-line", &line);
    assert_eq!(hit.item, "f");
    assert!(!hit.fp.contains("ForkName"), "{}", hit.fp);

    let spaced =
        fork_prog("pub fn f(slot_fork: ForkName) {\n    if slot_fork >= ForkName :: Gloas {}\n}\n");
    assert_rustc_lib_accepts("gap-spaced", &spaced);
    let hit = assert_one_ge("gap-spaced", &spaced);
    assert!(hit.fp.contains("ForkName :: Gloas"), "{}", hit.fp);
}

#[test]
fn lexer_keeps_the_hazard_after_a_confusable_literal() {
    let cases = [
        ("mm-pair", "pub fn f(slot_fork: ForkName) {\n    let _ = stringify!(0'\"');\n    if slot_fork >= ForkName::Gloas {}\n    let _ = stringify!(\"'\" );\n}\n"),
        ("mm-u8", "pub fn f(slot_fork: ForkName) {\n    let _ = stringify!(1u8'\"');\n    if slot_fork >= ForkName::Gloas {}\n}\n"),
        ("mm-ltraw", "pub fn f(slot_fork: ForkName) {\n    let _ = stringify!('r\"\\\"\");\n    if slot_fork >= ForkName::Gloas {}\n}\n"),
        ("mb-dq", "pub fn f(slot_fork: ForkName) {\n    let _ = ('é','\"');\n    if slot_fork >= ForkName::Gloas {}\n}\n"),
        ("mb-arr", "pub fn f(slot_fork: ForkName) {\n    let _ = ['é','\"'];\n    if slot_fork >= ForkName::Gloas {}\n}\n"),
        ("ignore-raw", "macro_rules! ignore { ($($t:tt)*) => {}; }\npub fn f(slot_fork: ForkName) {\n    ignore!(r#r\"\\\"\");\n    if slot_fork >= ForkName::Gloas {}\n}\n"),
        ("macro-num", "macro_rules! m { (0'\"' $($t:tt)*) => { $($t)* }; }\npub fn f(slot_fork: ForkName) {\n    m!(0'\"' if slot_fork >= ForkName::Gloas {});\n}\n"),
    ];
    for (name, body) in cases {
        let src = fork_prog(body);
        assert_rustc_lib_accepts(name, &src);
        let hit = assert_one_ge(name, &src);
        assert!(hit.resolve_error.is_some() || hit.item == "f", "{name}: {hit:?}");
    }
    let ls = fork_prog(&format!(
        "pub fn f(slot_fork: ForkName) {{\n    let _ = ('é','\"');\n    if slot_fork >={}\n}}\n",
        "\u{2028}ForkName::Gloas {}"
    ));
    assert_rustc_lib_accepts("mb-ls-gap", &ls);
    assert_one_ge("mb-ls-gap", &ls);
}

#[test]
fn unterminated_string_does_not_drop_the_hazard() {
    let src = "fn f() {\n    let _ = \"open\n    if slot_fork >= ForkName::Gloas { }\n}\n";
    let resolve = assert_one_ge("unterminated", src).resolve_error.unwrap_or_default();
    assert!(resolve.contains("unclosed"), "{resolve}");
}

#[test]
fn char_literal_span_is_not_code() {
    let src = "fn f() { let _ = '\"'; let _ = b'\"'; if slot_fork >= ForkName::Gloas {} }\n";
    let lexed = lex_file(src);
    for lit in ["'\"'", "b'\"'"] {
        let at = src.find(lit).unwrap();
        let quote = at + lit.find('"').unwrap();
        assert!(!byte_in_code(&lexed.non_code, quote), "{lit} interior is code");
    }
    assert!(byte_in_code(&lexed.non_code, src.find(">=").unwrap()));
}

#[test]
fn stringify_char_quote_does_not_promote_a_string_copy() {
    let mini = fork_prog(
        "pub fn reject_gloas_version_pre_gloas(slot_fork: ForkName) {\n    let _a = stringify!(0'\"');\n    let _s = \"\n    if slot_fork >= ForkName::Gloas {\n    \";\n    let _b = stringify!(0'\"');\n    if slot_fork < ForkName::Gloas {}\n}\n",
    );
    assert_rustc_lib_accepts("g2-mismask", &mini);
    for hit in scan_source("crates/block-service/src/service/mod.rs", &mini) {
        if hit.class == Class::GeForkName {
            assert!(hit.resolve_error.is_some(), "string copy is a clean hit: {hit:?}");
        }
    }
    let path = "crates/block-service/src/service/mod.rs";
    let src = std::fs::read_to_string(workspace_root().join(path)).expect("read block service");
    let rows: Vec<Inv> = INVENTORY.iter().copied().filter(|r| r.path == path).collect();
    let wrapper = "\n    let _a = stringify!(0'\"');\n    let _s = \"\n{line}\n    \";\n    let _b = stringify!(0'\"');\n";
    let edited = copy_slot_fork_line_and_negate(&src, wrapper);
    let err = reconcile(&scan_source(path, &edited), &rows).unwrap_err();
    assert!(err.contains("missing"), "{err}");
    assert!(err.contains("if slot_fork >= ForkName::Gloas {"), "{err}");
}

fn ge_count(src: &str) -> usize {
    scan_source("g.rs", src).iter().filter(|h| h.class == Class::GeForkName).count()
}

#[test]
fn shebang_does_not_hide_hits() {
    let quote = "#!\"\n#[derive(PartialEq, PartialOrd)]\nenum ForkName { Gloas }\npub fn f(slot_fork: ForkName) {\n    if slot_fork >= ForkName::Gloas {}\n}\n";
    assert_rustc_lib_accepts("sb-quote", quote);
    let at = quote.find(">=").unwrap();
    assert!(byte_in_code(&lex_file(quote).non_code, at), "shebang quote swallowed the hazard");
    assert_one_ge("sb-quote", quote);

    let clean = "#!/bin/x\n#[derive(PartialEq, PartialOrd)]\nenum ForkName { Gloas }\npub fn f(slot_fork: ForkName) {\n    if slot_fork >= ForkName::Gloas {}\n}\n";
    assert_rustc_lib_accepts("sb-clean", clean);
    let hit = assert_one_ge("sb-clean", clean);
    assert!(hit.resolve_error.is_some(), "{hit:?}");

    let idx = "#!/bin/x\nfn f() {\n    // x.index = 0\n}\n";
    assert_rustc_lib_accepts("sb-index", idx);
    let hits = scan_source("g.rs", idx);
    assert_eq!(hits.iter().filter(|h| h.class == Class::IndexZero).count(), 1, "{hits:?}");
    assert!(hits.iter().any(|h| h.class == Class::IndexZero && h.resolve_error.is_some()));
}

#[test]
fn guarded_prefix_keeps_a_later_hit() {
    let src = "fn f() {\n    let _ = stringify!(##);\n    // x.index = 0\n}\n";
    assert_rustc_lib_accepts("guard-hash", src);
    let lexed = lex_file(src);
    assert_eq!(lexed.non_code, non_code_spans(src), "prefix shifted the mask");
    assert!(lexed.uncertain, "guarded prefix left the file trusted");
    let hits = scan_source("g.rs", src);
    assert_eq!(hits.iter().filter(|h| h.class == Class::IndexZero).count(), 1, "{hits:?}");
}

#[test]
fn nested_comment_in_the_ge_gap_is_a_hit() {
    let nested = "s >= /* a /* b */ c */ ForkName::Gloas";
    let trusted = fork_prog(&format!("pub fn f(s: ForkName) -> bool {{ {nested} }}\n"));
    assert_rustc_lib_accepts("nest-trust", &trusted);
    let hit = assert_one_ge("nest-trust", &trusted);
    assert!(hit.resolve_error.is_none(), "{:?}", hit.resolve_error);
    assert_eq!(hit.item, "f");
    let other = fork_prog("pub fn f(s: ForkName) -> bool { s >= /* a /* b */ c */ s }\n");
    assert_rustc_lib_accepts("nest-other", &other);
    assert_eq!(ge_count(&other), 0);

    let cases = [
        ("c", "pub fn f(s: ForkName) -> bool { let _ = c\"\"; s >= /* a /* b */ c */ ForkName::Gloas }\n"),
        ("bom", "pub fn f(s: ForkName) -> bool { s >= /* a /* b */ c */ ForkName::Gloas }\n"),
        ("str", "pub fn f(s: ForkName) -> bool { let _ = stringify!(0'\"'); s >= /* a /* b */ c */ ForkName::Gloas }\n"),
        ("ls", "pub fn f(s: ForkName) -> bool { let _ = c\"\"; s >= ForkName\u{2028}::Gloas }\n"),
    ];
    for (name, body) in cases {
        let src =
            if name == "bom" { format!("\u{feff}{}", fork_prog(body)) } else { fork_prog(body) };
        assert_rustc_lib_accepts(name, &src);
        let hit = assert_one_ge(name, &src);
        assert!(hit.resolve_error.is_some(), "{name}: {hit:?}");
    }
    let no =
        fork_prog("pub fn f(s: ForkName) -> bool { let _ = c\"\"; s >= /* a /* b */ c */ s }\n");
    assert_rustc_lib_accepts("c-no", &no);
    assert_eq!(ge_count(&no), 0, "nested comment is not ForkName");
}

#[test]
fn broken_token_gap_treats_comment_and_non_ascii_as_hits() {
    let block = "if s >= /* a /* b */ c */ ForkName::Gloas {}";
    assert!(broken_ge(block, block.find(">=").unwrap()));
    let line = "if s >= // c\n ForkName::Gloas {}";
    assert!(broken_ge(line, line.find(">=").unwrap()));
    let hi = "if s >= ForkName\u{2028}::Gloas {}";
    assert!(broken_ge(hi, hi.find(">=").unwrap()));
    let plain = "if s >= Other::Gloas {}";
    assert!(!broken_ge(plain, plain.find(">=").unwrap()));
}
