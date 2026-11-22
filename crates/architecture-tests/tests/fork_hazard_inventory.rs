//! Issue 2.2 / #216: CI inventory of fork-addition hazards.
//!
//! A new `ForkName` arm must not silently change behaviour. This gate scans
//! `crates/**` and `bin/**` for five greppable classes and asserts every hit
//! is in the checked-in inventory with a verdict — no `unclassified`, exact
//! per-class counts. The human table is `docs/gloas-fork-hazard-audit.md`;
//! this file is the machine copy. The two must agree.
//!
//! Classes: (1) `>= ForkName::X` (2) `.index = 0` / `.index = "0"` (3) `match`
//! on `ForkName` exhaustive vs catch-all (4) string-literal fork dispatch
//! (5) `.entries()` call sites. A catch-all arm is `_ =>` or an irrefutable
//! binding such as `other =>` or `x @ _ =>`, with no guard.
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
//! `syn` parses each `match` and `matches!` site, so the parser decides the
//! scrutinee, the arms, the patterns and the guards. A site or a file that syn
//! does not parse gives failing hits (fail closed).

use ra_ap_rustc_lexer::{strip_shebang, tokenize, FrontmatterAllowed, LiteralKind, TokenKind};
use rvc_architecture_tests::{byte_in_code, is_rust_ws, non_code_spans, ResolveError, SourceItems};
use syn::buffer::Cursor;
use syn::ext::IdentExt;
use syn::parse::{ParseStream, Parser};
use syn::visit::{self, Visit};
use syn::{braced, Arm, Attribute, Expr, LitByteStr, LitStr, Pat, Token, Type, UseTree};

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
        true,
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
        true,
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
        true,
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
        true,
        "match &envelopes[0] {",
        Verdict::TestOnly,
        "—",
    ),
    inv(
        "crates/rvc/src/orchestrator/sync_committee.rs",
        "tests::contribution_kat",
        Class::StringDispatch,
        true,
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

/// Alias-gate findings allowed at the definition site in `impl ForkName`: the
/// variant list `ALL` (syn) and the name table `NAMES` (syn and the token
/// check). Each is anchored on its type text and must occur exactly once.
const ALIAS_EXEMPT: &[(&str, &str)] = &[
    ("crates/eth-types/src/fork.rs", "impl ForkName: const ALL: [Self; 8]"),
    (
        "crates/eth-types/src/fork.rs",
        "impl ForkName: const NAMES: [(ForkName, &str, u32); Self::COUNT]",
    ),
    ("crates/eth-types/src/fork.rs", "const NAMES: [(ForkName, &str, u32); Self::COUNT]"),
];

/// Alias-gate errors for `(path, source)` files. An exempt finding that does
/// not occur exactly once is an error too.
fn alias_gate(files: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut exempt_seen = vec![0usize; ALIAS_EXEMPT.len()];
    for (rel, src) in files {
        for line in fork_name_aliases(src) {
            match ALIAS_EXEMPT.iter().position(|&(p, f)| p == rel && f == line) {
                Some(k) => exempt_seen[k] += 1,
                None => errors.push(format!("{rel}: {line}")),
            }
        }
    }
    for (&(path, finding), n) in ALIAS_EXEMPT.iter().zip(exempt_seen) {
        if n != 1 {
            errors.push(format!("{path}: exemption `{finding}` matched {n} times, not once"));
        }
    }
    errors
}
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

/// One code token of a delimiter walk. Comments are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeKind {
    Ident,
    Lit,
    Punct,
}

#[derive(Debug, Clone, Copy)]
struct CodeTok {
    start: usize,
    end: usize,
    kind: CodeKind,
}

fn is_comment_span(src: &str, start: usize) -> bool {
    src[start..].starts_with("//") || src[start..].starts_with("/*")
}

fn is_word_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

fn word_end(src: &str, from: usize) -> usize {
    src[from..].find(|c| !is_word_char(c)).map_or(src.len(), |n| from + n)
}

/// Code tokens of `src` under one non-code mask. A masked span is one literal
/// token or a dropped comment, so a delimiter in a string, char or comment never counts.
fn code_tokens(src: &str, non_code: &[(usize, usize)]) -> Vec<CodeTok> {
    let mut spans = non_code.iter().copied().peekable();
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        if !src.is_char_boundary(i) {
            i += 1;
            continue;
        }
        while spans.next_if(|&(_, end)| end <= i).is_some() {}
        if let Some(&(start, end)) = spans.peek() {
            if start <= i {
                if !is_comment_span(src, start) {
                    out.push(CodeTok { start: i, end, kind: CodeKind::Lit });
                }
                i = end;
                continue;
            }
        }
        let ch = src[i..].chars().next().expect("i is a char boundary");
        if ch.is_whitespace() {
            i += ch.len_utf8();
            continue;
        }
        if !is_word_char(ch) {
            out.push(CodeTok { start: i, end: i + ch.len_utf8(), kind: CodeKind::Punct });
            i += ch.len_utf8();
            continue;
        }
        let mut end = word_end(src, i);
        let raw = &src[i..end] == "r" && src[end..].starts_with('#');
        if raw && src[end + 1..].starts_with(|c: char| c == '_' || c.is_alphabetic()) {
            end = word_end(src, end + 1);
        }
        out.push(CodeTok { start: i, end, kind: CodeKind::Ident });
        i = end;
    }
    out
}

fn is_punct(src: &str, t: &CodeTok, c: u8) -> bool {
    t.kind == CodeKind::Punct && src.as_bytes()[t.start] == c
}

fn is_word(src: &str, t: &CodeTok, word: &str) -> bool {
    t.kind == CodeKind::Ident && &src[t.start..t.end] == word
}

fn is_open(src: &str, t: &CodeTok) -> bool {
    b"([{".iter().any(|c| is_punct(src, t, *c))
}

fn is_close(src: &str, t: &CodeTok) -> bool {
    b")]}".iter().any(|c| is_punct(src, t, *c))
}

/// Index of the token that closes the group that `toks[open]` opens.
fn close_group(src: &str, toks: &[CodeTok], open: usize) -> Option<usize> {
    if !toks.get(open).is_some_and(|t| is_open(src, t)) {
        return None;
    }
    let mut depth = 0;
    for (i, t) in toks.iter().enumerate().skip(open) {
        if is_open(src, t) {
            depth += 1;
        } else if is_close(src, t) {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// An identifier token equal to `name` after `r#` is removed.
fn is_name(src: &str, t: &CodeTok, name: &str) -> bool {
    let text = &src[t.start..t.end];
    t.kind == CodeKind::Ident && text.strip_prefix("r#").unwrap_or(text) == name
}

/// Start byte of the token that closes the delimiter group around token `i`.
fn group_end(src: &str, toks: &[CodeTok], i: usize) -> usize {
    let mut depth = 0usize;
    for t in &toks[i..] {
        if is_open(src, t) {
            depth += 1;
        } else if is_close(src, t) {
            if depth == 0 {
                return t.start;
            }
            depth -= 1;
        }
    }
    src.len()
}

// ---------------------------------------------------------------------------
// Match sites (syn)
// ---------------------------------------------------------------------------

/// Fork string literals and `ForkName::` paths in a token cursor, macro bodies included.
#[derive(Default)]
struct TokenScan {
    fork_string: bool,
    fork_path: bool,
}

fn lit_is_fork_string(text: &str) -> bool {
    let value = syn::parse_str::<LitStr>(text).map(|l| l.value()).or_else(|_| {
        syn::parse_str::<LitByteStr>(text).map(|l| String::from_utf8_lossy(&l.value()).into_owned())
    });
    value.is_ok_and(|v| FORK_STRINGS.iter().any(|s| s.trim_matches('"') == v))
}

fn scan_cursor(mut c: Cursor<'_>, out: &mut TokenScan) {
    while !c.eof() {
        if let Some((lit, next)) = c.literal() {
            out.fork_string |= lit_is_fork_string(&lit.to_string());
            c = next;
        } else if let Some((ident, next)) = c.ident() {
            out.fork_path |= ident.unraw() == "ForkName"
                && next.punct().is_some_and(|(p, _)| p.as_char() == ':');
            c = next;
        } else if let Some((inner, _, _, next)) = c.any_group() {
            scan_cursor(inner, out);
            c = next;
        } else if let Some((_, next)) = c.token_tree() {
            c = next;
        } else {
            break;
        }
    }
}

fn skip_rest(input: ParseStream) -> syn::Result<()> {
    input.step(|c| {
        let mut rest = *c;
        while let Some((_, next)) = rest.token_tree() {
            rest = next;
        }
        Ok(((), rest))
    })
}

/// Paths that name a fork in arm patterns and guards: a `ForkName` segment
/// with a segment after it, a `<…ForkName>::` qualified self, or `Self::…`.
#[derive(Default)]
struct ArmPaths {
    fork: bool,
    self_path: bool,
}

impl<'ast> Visit<'ast> for ArmPaths {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        let segs: Vec<_> = p.segments.iter().collect();
        self.fork |= segs.iter().rev().skip(1).any(|s| s.ident.unraw() == "ForkName");
        self.self_path |=
            segs.len() > 1 && segs[0].ident == "Self" && is_fork_variant(&segs[1].ident);
        visit::visit_path(self, p);
    }

    fn visit_expr_path(&mut self, e: &'ast syn::ExprPath) {
        self.qualified_self(e.qself.as_ref(), &e.path);
        visit::visit_expr_path(self, e);
    }

    fn visit_pat_tuple_struct(&mut self, p: &'ast syn::PatTupleStruct) {
        self.qualified_self(p.qself.as_ref(), &p.path);
        visit::visit_pat_tuple_struct(self, p);
    }

    fn visit_pat_struct(&mut self, p: &'ast syn::PatStruct) {
        self.qualified_self(p.qself.as_ref(), &p.path);
        visit::visit_pat_struct(self, p);
    }

    fn visit_qself(&mut self, q: &'ast syn::QSelf) {
        if let Type::Path(tp) = strip_type(&q.ty) {
            self.fork |= tp.path.segments.last().is_some_and(|s| s.ident.unraw() == "ForkName");
        }
        visit::visit_qself(self, q);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let mut scan = TokenScan::default();
        let _ = m.parse_body_with(|input: ParseStream| {
            scan_cursor(input.cursor(), &mut scan);
            skip_rest(input)
        });
        self.fork |= scan.fork_path;
        visit::visit_macro(self, m);
    }
}

impl ArmPaths {
    /// `<Self>::X`, `<(Self)>::X` or `<Self as Tr>::X` where `X` is a fork variant.
    fn qualified_self(&mut self, qself: Option<&syn::QSelf>, path: &syn::Path) {
        let Some(q) = qself else {
            return;
        };
        let is_self = matches!(strip_type(&q.ty), Type::Path(tp) if tp.qself.is_none() && tp.path.is_ident("Self"));
        self.self_path |=
            is_self && path.segments.get(q.position).is_some_and(|s| is_fork_variant(&s.ident));
    }
}

/// `ty` without its `( … )` and invisible-group layers.
fn strip_type(mut ty: &Type) -> &Type {
    while let Type::Paren(syn::TypeParen { elem, .. }) | Type::Group(syn::TypeGroup { elem, .. }) =
        ty
    {
        ty = elem;
    }
    ty
}

/// Variant names of `pub enum ForkName` in `crates/eth-types/src/fork.rs`,
/// read with syn at test time so a new fork is picked up.
fn fork_variants() -> &'static HashSet<String> {
    static VARIANTS: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
    VARIANTS.get_or_init(|| {
        let path = workspace_root().join("crates/eth-types/src/fork.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let file =
            syn::parse_file(&src).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        let variants: HashSet<String> = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Enum(e) if e.ident.unraw() == "ForkName" => {
                    Some(e.variants.iter().map(|v| v.ident.unraw().to_string()).collect())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("no `enum ForkName` in {}", path.display()));
        assert!(!variants.is_empty(), "`enum ForkName` has no variants");
        variants
    })
}

fn is_fork_variant(ident: &syn::Ident) -> bool {
    fork_variants().contains(&ident.unraw().to_string())
}

/// Last path segments of the tuple-struct and struct patterns in a pattern.
#[derive(Default)]
struct WrapperNames(HashSet<String>);

fn wrapper_names(p: &Pat) -> HashSet<String> {
    let mut names = WrapperNames::default();
    names.visit_pat(p);
    names.0
}

impl<'ast> Visit<'ast> for WrapperNames {
    fn visit_pat_tuple_struct(&mut self, p: &'ast syn::PatTupleStruct) {
        self.0.extend(p.path.segments.last().map(|s| s.ident.unraw().to_string()));
        visit::visit_pat_tuple_struct(self, p);
    }

    fn visit_pat_struct(&mut self, p: &'ast syn::PatStruct) {
        self.0.extend(p.path.segments.last().map(|s| s.ident.unraw().to_string()));
        visit::visit_pat_struct(self, p);
    }
}

/// Wrappers whose catch-all form takes every fork value only next to the same wrapper.
const SIBLING_WRAPPERS: &[&str] = &["Ok", "Err", "Some", "None"];

/// `true` if a pattern holds an or-pattern, so the wrapper around it has its own sibling case.
#[derive(Default)]
struct HasOr(bool);

impl<'ast> Visit<'ast> for HasOr {
    fn visit_pat_or(&mut self, _: &'ast syn::PatOr) {
        self.0 = true;
    }
}

/// A pattern that catches every fork value: `_`, `..`, a binding (any
/// identifier except `None`; a bare `Phase0` is a binding because source
/// must not import the variants), `name @ <catch-all>`, `&p`, a macro, a
/// tuple, slice or group of catch-alls, and an or-pattern with one catch-all
/// case. A tuple-struct or struct pattern whose fields are all catch-alls is a
/// catch-all. For `Ok`, `Err`, `Some` and `None` (last path segment) one more
/// condition applies: another arm, another case of an enclosing or-pattern
/// (at any depth), or an or-pattern in its own fields uses the same wrapper. Thus `Ok(got)` after
/// `Ok(ForkName::Fulu)` is a catch-all, but `Err(_)` next to `Ok(…)` arms is not.
fn pat_catch_all(p: &Pat, siblings: &HashSet<String>) -> bool {
    let all = |pats: Vec<&Pat>| pats.into_iter().all(|p| pat_catch_all(p, siblings));
    let shared = |path: &syn::Path, inner: &Pat| {
        let name = path.segments.last().map(|s| s.ident.unraw().to_string()).unwrap_or_default();
        let mut or = HasOr::default();
        or.visit_pat(inner);
        !SIBLING_WRAPPERS.contains(&name.as_str()) || siblings.contains(&name) || or.0
    };
    match p {
        Pat::Wild(_) | Pat::Rest(_) | Pat::Macro(_) | Pat::Verbatim(_) => true,
        Pat::Ident(i) => match &i.subpat {
            Some((_, sub)) => pat_catch_all(sub, siblings),
            None => i.ident.unraw() != "None",
        },
        Pat::Reference(r) => pat_catch_all(&r.pat, siblings),
        Pat::Paren(g) => pat_catch_all(&g.pat, siblings),
        Pat::Type(t) => pat_catch_all(&t.pat, siblings),
        Pat::Or(o) => o.cases.iter().enumerate().any(|(c, case)| {
            let mut own = siblings.clone();
            own.extend(
                o.cases
                    .iter()
                    .enumerate()
                    .filter(|(d, _)| *d != c)
                    .flat_map(|(_, p)| wrapper_names(p)),
            );
            pat_catch_all(case, &own)
        }),
        Pat::Tuple(t) => all(t.elems.iter().collect()),
        Pat::Slice(s) => all(s.elems.iter().collect()),
        Pat::TupleStruct(t) => shared(&t.path, p) && all(t.elems.iter().collect()),
        Pat::Struct(s) => shared(&s.path, p) && all(s.fields.iter().map(|f| &*f.pat).collect()),
        Pat::Lit(_) | Pat::Range(_) | Pat::Path(_) | Pat::Const(_) => false,
        _ => true,
    }
}

/// Alternatives of a const-only arm: a bare name, a one-segment path, a macro or `_`.
fn pat_const_names(p: &Pat) -> Option<usize> {
    match p {
        Pat::Or(o) => o.cases.iter().map(pat_const_names).sum(),
        Pat::Wild(_) => Some(0),
        Pat::Ident(i) if i.subpat.is_none() => Some(1),
        Pat::Path(e) if e.qself.is_none() && e.path.segments.len() == 1 => Some(1),
        Pat::Macro(_) => Some(1),
        _ => None,
    }
}

struct MatchFacts {
    fork: bool,
    self_path: bool,
    const_only: bool,
    catch_all: bool,
    fork_string: bool,
}

fn match_facts(arms: &[Arm], fork_string: bool) -> MatchFacts {
    let mut paths = ArmPaths::default();
    for arm in arms {
        paths.visit_pat(&arm.pat);
        if let Some((_, guard)) = &arm.guard {
            paths.visit_expr(guard);
        }
    }
    let names: Option<usize> = arms.iter().map(|a| pat_const_names(&a.pat)).sum();
    let wrappers: Vec<HashSet<String>> = arms.iter().map(|a| wrapper_names(&a.pat)).collect();
    let catch_all = arms.iter().enumerate().any(|(k, a)| {
        let siblings: HashSet<String> = wrappers
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != k)
            .flat_map(|(_, w)| w.clone())
            .collect();
        a.guard.is_none() && pat_catch_all(&a.pat, &siblings)
    });
    MatchFacts {
        fork: paths.fork,
        self_path: paths.self_path,
        const_only: names.is_some_and(|n| n > 0),
        catch_all,
        fork_string,
    }
}

/// Arms of `match <scrutinee> { … }` that starts `text`, and if the body has a fork string.
fn parse_match_site(text: &str) -> syn::Result<(Vec<Arm>, bool)> {
    let parser = |input: ParseStream| {
        input.parse::<Token![match]>()?;
        Expr::parse_without_eager_brace(input)?;
        let content;
        braced!(content in input);
        let mut scan = TokenScan::default();
        scan_cursor(content.cursor(), &mut scan);
        content.call(Attribute::parse_inner)?;
        let mut arms = Vec::new();
        while !content.is_empty() {
            arms.push(content.parse::<Arm>()?);
        }
        skip_rest(input)?;
        Ok((arms, scan.fork_string))
    };
    parser.parse_str(text)
}

/// Pattern and guard of a `matches!` body (`expr, pat (if guard)?`) as one arm.
fn parse_matches_body(text: &str) -> syn::Result<(Arm, bool)> {
    let parser = |input: ParseStream| {
        let mut scan = TokenScan::default();
        scan_cursor(input.cursor(), &mut scan);
        input.parse::<Expr>()?;
        input.parse::<Token![,]>()?;
        let pat = Pat::parse_multi_with_leading_vert(input)?;
        let guard = match input.parse::<Option<Token![if]>>()? {
            Some(kw) => Some((kw, Box::new(input.parse::<Expr>()?))),
            None => None,
        };
        input.parse::<Option<Token![,]>>()?;
        let body = Box::new(syn::parse_quote!(()));
        let arm = Arm {
            attrs: Vec::new(),
            pat,
            guard,
            fat_arrow_token: Default::default(),
            body,
            comma: None,
        };
        Ok((arm, scan.fork_string))
    };
    parser.parse_str(text)
}

/// Alias, rename and variant-import findings of a parsed file.
#[derive(Default)]
struct AliasFinder {
    found: Vec<String>,
    /// For each enclosing `impl`, `true` if its self type ends in `ForkName`.
    impls: Vec<bool>,
}

fn use_tree_aliases(tree: &UseTree, prefix: &str, after_fork: bool, out: &mut Vec<String>) {
    let name = |ident: &syn::Ident| format!("use {prefix}{}", ident.unraw());
    match tree {
        UseTree::Path(p) if after_fork => out.push(name(&p.ident)),
        UseTree::Path(p) => {
            let next = format!("{prefix}{}::", p.ident.unraw());
            use_tree_aliases(&p.tree, &next, p.ident.unraw() == "ForkName", out);
        }
        UseTree::Name(n) if after_fork => out.push(name(&n.ident)),
        UseTree::Rename(r) if after_fork || r.ident.unraw() == "ForkName" => {
            out.push(name(&r.ident))
        }
        UseTree::Glob(_) if after_fork => out.push(format!("use {prefix}*")),
        UseTree::Group(g) => {
            g.items.iter().for_each(|t| use_tree_aliases(t, prefix, after_fork, out))
        }
        _ => {}
    }
}

/// A `ForkName` path segment that no `::` follows. With `self_is_fork`, a path
/// that starts with `Self` also counts. An array length is not read, so
/// `[u32; Self::N]` is not a finding.
#[derive(Default)]
struct TypeNamesFork {
    found: bool,
    /// Count a `Self` path too: inside an impl of `ForkName`, or in a trait.
    self_is_fork: bool,
}

impl<'ast> Visit<'ast> for TypeNamesFork {
    fn visit_type_array(&mut self, a: &'ast syn::TypeArray) {
        self.visit_type(&a.elem);
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        self.found |= p.segments.last().is_some_and(|s| s.ident.unraw() == "ForkName");
        self.found |= self.self_is_fork && p.segments.first().is_some_and(|s| s.ident == "Self");
        visit::visit_path(self, p);
    }
}

/// Source-like text of a type for an anchored exemption: paths, generic
/// arguments, arrays, tuples, references and slices. Other parts print as `?`.
fn render_type(ty: &Type) -> String {
    let list =
        |tys: &mut dyn Iterator<Item = &Type>| tys.map(render_type).collect::<Vec<_>>().join(", ");
    match ty {
        Type::Path(tp) if tp.qself.is_none() => render_path(&tp.path),
        Type::Array(a) => format!("[{}; {}]", render_type(&a.elem), render_expr(&a.len)),
        Type::Slice(s) => format!("[{}]", render_type(&s.elem)),
        Type::Tuple(t) => format!("({})", list(&mut t.elems.iter())),
        Type::Paren(p) => format!("({})", render_type(&p.elem)),
        Type::Reference(r) => {
            format!("&{}{}", if r.mutability.is_some() { "mut " } else { "" }, render_type(&r.elem))
        }
        _ => "?".to_string(),
    }
}

fn render_path(p: &syn::Path) -> String {
    let segment = |s: &syn::PathSegment| match &s.arguments {
        syn::PathArguments::None => s.ident.unraw().to_string(),
        syn::PathArguments::AngleBracketed(a) => {
            let args: Vec<String> = a
                .args
                .iter()
                .map(|g| match g {
                    syn::GenericArgument::Type(t) => render_type(t),
                    _ => "?".to_string(),
                })
                .collect();
            format!("{}<{}>", s.ident.unraw(), args.join(", "))
        }
        syn::PathArguments::Parenthesized(_) => format!("{}(?)", s.ident.unraw()),
    };
    p.segments.iter().map(segment).collect::<Vec<_>>().join("::")
}

fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.base10_digits().to_string(),
        Expr::Path(p) if p.qself.is_none() => render_path(&p.path),
        _ => "?".to_string(),
    }
}

impl<'ast> Visit<'ast> for AliasFinder {
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        use_tree_aliases(&u.tree, "", false, &mut self.found);
    }

    fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
        let defaults = t.generics.type_params().filter_map(|p| p.default.as_ref());
        for ty in std::iter::once(&*t.ty).chain(defaults) {
            self.names_fork("type", &t.ident, ty);
        }
        visit::visit_item_type(self, t);
    }

    fn visit_impl_item_type(&mut self, t: &'ast syn::ImplItemType) {
        self.names_fork("type", &t.ident, &t.ty);
        visit::visit_impl_item_type(self, t);
    }

    fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
        self.names_fork("const", &c.ident, &c.ty);
        visit::visit_item_const(self, c);
    }

    fn visit_item_static(&mut self, c: &'ast syn::ItemStatic) {
        self.names_fork("static", &c.ident, &c.ty);
        visit::visit_item_static(self, c);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let mut names = TypeNamesFork { found: false, self_is_fork: false };
        names.visit_type(&i.self_ty);
        self.impls.push(names.found);
        visit::visit_item_impl(self, i);
        self.impls.pop();
    }

    fn visit_impl_item_const(&mut self, c: &'ast syn::ImplItemConst) {
        let in_fork = self.impls.last() == Some(&true);
        let kw = if in_fork { "impl ForkName: const" } else { "const" };
        self.names_fork_or_self(kw, &c.ident, &c.ty, in_fork);
        visit::visit_impl_item_const(self, c);
    }

    fn visit_trait_item_const(&mut self, c: &'ast syn::TraitItemConst) {
        self.names_fork_or_self("trait const", &c.ident, &c.ty, true);
        visit::visit_trait_item_const(self, c);
    }
}

impl AliasFinder {
    fn names_fork(&mut self, kw: &str, ident: &syn::Ident, ty: &Type) {
        self.names_fork_or_self(kw, ident, ty, false);
    }

    /// A finding `<kw> <name>: <type>` if `ty` names `ForkName`, or `Self`
    /// when `self_is_fork` is set.
    fn names_fork_or_self(&mut self, kw: &str, ident: &syn::Ident, ty: &Type, self_is_fork: bool) {
        let mut names = TypeNamesFork { found: false, self_is_fork };
        names.visit_type(ty);
        if names.found {
            self.found.push(format!("{kw} {}: {}", ident.unraw(), render_type(ty)));
        }
    }
}

/// End of a type range that starts at `from`: the first top-level `;`, or
/// with `item` also a top-level `=`, `,` or `{`, or a close that leaves the range.
fn type_range_end(src: &str, toks: &[CodeTok], from: usize, item: bool) -> usize {
    let mut depth = 0i32;
    for (j, t) in toks.iter().enumerate().skip(from) {
        let arrow = j > 0 && is_punct(src, &toks[j - 1], b'-');
        if is_open(src, t) || is_punct(src, t, b'<') {
            depth += 1;
        } else if is_close(src, t) || (is_punct(src, t, b'>') && !arrow) {
            depth -= 1;
            if depth < 0 {
                return j;
            }
        } else if depth == 0
            && (is_punct(src, t, b';') || (item && b"=,{".iter().any(|c| is_punct(src, t, *c))))
        {
            return j;
        }
    }
    toks.len()
}

/// Token check of every `use`, `type`, `const` and `static` in the lexer view,
/// macro bodies included.
/// In macro bodies (`name! { … }`, `macro_rules! name { … }`, not `if !x {`),
/// or in the whole file when `self_everywhere` is set, a `Self` type in a
/// `const` or `static` counts as `ForkName`, because syn cannot see the impl
/// around it. In a macro body, a `$` metavariable in the type also counts.
fn token_aliases(src: &str, self_everywhere: bool) -> Vec<String> {
    let toks = code_tokens(src, &lex_file(src).non_code);
    let fork = |j: usize| toks.get(j).is_some_and(|t| is_name(src, t, "ForkName"));
    let sep = |j: usize| toks.get(j).is_some_and(|n| is_punct(src, n, b':'));
    let named = |from: usize, to: usize| (from..to).any(|j| fork(j) && !sep(j + 1));
    let keyword = ["if", "while", "match", "return", "let", "in", "else", "break"];
    let macros: Vec<(usize, usize)> = (1..toks.len())
        .filter(|&j| is_punct(src, &toks[j], b'!') && toks[j - 1].kind == CodeKind::Ident)
        .filter(|&j| !keyword.iter().any(|k| is_word(src, &toks[j - 1], k)))
        .filter_map(|j| {
            let open = j + 1 + usize::from(is_word(src, &toks[j - 1], "macro_rules"));
            Some((open, close_group(src, &toks, open)?))
        })
        .collect();
    let in_macro = |j: usize| macros.iter().any(|&(o, c)| o < j && j < c);
    let self_type = |j: usize| is_word(src, &toks[j], "Self") && (self_everywhere || in_macro(j));
    let metavar = |j: usize| is_punct(src, &toks[j], b'$') && in_macro(j);
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if is_word(src, t, "use") {
            let end = type_range_end(src, &toks, i + 1, false);
            let as_kw = |j: usize| toks.get(j).is_some_and(|n| is_word(src, n, "as"));
            if (i..end).any(|j| fork(j) && (sep(j + 1) || as_kw(j + 1))) {
                out.push(normalise_line(&src[line_start(src, t.start)..line_end(src, t.start)]));
            }
            continue;
        }
        let kw = ["type", "const", "static"].into_iter().find(|k| is_word(src, t, k));
        let Some(kw) = kw else {
            continue;
        };
        let name = i + 1 + usize::from(toks.get(i + 1).is_some_and(|n| is_word(src, n, "mut")));
        let name = name + usize::from(toks.get(name).is_some_and(|n| is_punct(src, n, b'$')));
        let Some(ident) = toks.get(name).filter(|n| n.kind == CodeKind::Ident) else {
            continue;
        };
        let text = &src[ident.start..ident.end];
        let text = text.strip_prefix("r#").unwrap_or(text);
        if kw == "type" {
            if named(name + 1, type_range_end(src, &toks, name + 1, false)) {
                out.push(format!("type {text}"));
            }
        } else if sep(name + 1) && !sep(name + 2) {
            let end = type_range_end(src, &toks, name + 2, true);
            let hidden = (name + 2..end).any(|j| self_type(j) || metavar(j));
            if (named(name + 2, end) || hidden) && end > name + 2 {
                let ty = normalise_line(&src[toks[name + 2].start..toks[end - 1].end]);
                out.push(format!("{kw} {text}: {ty}"));
            }
        }
    }
    out
}

/// Findings that alias `ForkName`, rename it, import its variants, or give a
/// `const`, `static` or associated const a type that names `ForkName`. syn
/// reads each file that it parses, and a token check reads every file, macro
/// bodies included.
fn fork_name_aliases(src: &str) -> Vec<String> {
    let parsed = syn::parse_file(src);
    let mut found = token_aliases(src, parsed.is_err());
    if let Ok(file) = parsed {
        let mut finder = AliasFinder::default();
        finder.visit_file(&file);
        found.extend(finder.found);
    }
    found.sort();
    found
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
    hand: &'a [(usize, usize)],
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
    hand: Vec<(usize, usize)>,
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
    Lex { non_code, hand, uncertain, covered, toks }
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

fn push_red_hit(out: &mut Vec<Hit>, scan: &Scan<'_>, at: usize, class: Class, why: &str) {
    let before = out.len();
    push_hit(out, scan, at, class, true);
    for hit in &mut out[before..] {
        hit.resolve_error.get_or_insert_with(|| why.to_string());
    }
}

/// Class 4 hit of the `matches!` site at token `i`, or `None` if syn does not parse it.
fn syn_macro_hits(src: &str, toks: &[CodeTok], i: usize) -> Option<Vec<(Class, bool)>> {
    let close = close_group(src, toks, i + 2)?;
    let (arm, fork_string) = parse_matches_body(&src[toks[i + 2].end..toks[close].start]).ok()?;
    let facts = match_facts(std::slice::from_ref(&arm), fork_string);
    Some(if facts.fork_string {
        vec![(Class::StringDispatch, facts.catch_all)]
    } else {
        Vec::new()
    })
}

/// Class 3 and class 4 hits of the `match` site at token `i`, or `None` if
/// syn does not parse the site.
fn syn_match_hits(
    src: &str,
    toks: &[CodeTok],
    i: usize,
    names_fork: bool,
) -> Option<Vec<(Class, bool)>> {
    let (arms, fork_string) =
        parse_match_site(&src[toks[i].start..group_end(src, toks, i + 1)]).ok()?;
    let facts = match_facts(&arms, fork_string);
    let self_scope = facts.self_path && names_fork;
    let mut hits = Vec::new();
    if facts.fork || self_scope || (facts.const_only && names_fork) {
        hits.push((Class::MatchForkName, facts.catch_all));
    }
    if facts.fork_string {
        hits.push((Class::StringDispatch, facts.catch_all));
    }
    Some(hits)
}

/// Each `match` and `matches!` site. syn decides the scrutinee, the arms, the
/// patterns and the guards. If the lexer is uncertain or syn rejects the file
/// or the site, the site is a failing class 3 hit when the file names
/// `ForkName` and a failing class 4 hit when the file has a fork string. An
/// uncertain file also walks the hand mask and no mask (fail closed).
fn scan_match_sites(scan: &Scan<'_>, out: &mut Vec<Hit>) {
    let src = scan.src;
    let parsed = !scan.uncertain && syn::parse_file(src).is_ok();
    let masks = if parsed { vec![scan.non_code] } else { vec![scan.non_code, scan.hand, &[]] };
    let crude_fork = src.contains("ForkName");
    let crude_string = body_has_fork_string(src);
    let mut seen = HashSet::new();
    for mask in masks {
        let toks = code_tokens(src, mask);
        let names_fork = toks.iter().any(|t| is_name(src, t, "ForkName"));
        for (i, t) in toks.iter().enumerate() {
            let is_macro = is_name(src, t, "matches")
                && toks.get(i + 1).is_some_and(|n| is_punct(src, n, b'!'))
                && toks.get(i + 2).is_some_and(|n| is_open(src, n));
            if !is_macro && !is_word(src, t, "match") && !(is_name(src, t, "matches") && !parsed) {
                continue;
            }
            let site = match (parsed, is_macro) {
                (false, _) => None,
                (true, true) => syn_macro_hits(src, &toks, i),
                (true, false) => syn_match_hits(src, &toks, i, names_fork),
            };
            let why = if parsed { "syn rejected the match site" } else { "syn rejected the file" };
            let hits = site
                .map(|h| h.into_iter().map(|(c, w)| (c, w, false)).collect::<Vec<_>>())
                .unwrap_or_else(|| {
                    let fork = crude_fork && is_word(src, t, "match");
                    [(fork, Class::MatchForkName), (crude_string, Class::StringDispatch)]
                        .into_iter()
                        .filter(|(on, _)| *on)
                        .map(|(_, c)| (c, true, true))
                        .collect()
                });
            for (class, wildcard, red) in hits {
                if !seen.insert((t.start, class)) {
                    continue;
                }
                if red {
                    push_red_hit(out, scan, t.start, class, why);
                } else {
                    push_hit(out, scan, t.start, class, wildcard);
                }
            }
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
        hand: &lexed.hand,
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
impl ForkName {
    pub fn id(self) -> u32 {
        match self {
            Self::Phase0 => 0,
            Self::Altair => 1,
            Self::Fulu => 6,
        }
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

// ---------------------------------------------------------------------------
// Delimiter walkers and arm patterns (code-only view)
// ---------------------------------------------------------------------------

fn class_hits(hits: &[Hit], class: Class) -> Vec<Hit> {
    hits.iter().filter(|h| h.class == class).cloned().collect()
}

fn one_class_hit(name: &str, path: &str, src: &str, class: Class) -> Hit {
    let hits = scan_source(path, src);
    let found = class_hits(&hits, class);
    assert_eq!(found.len(), 1, "{name}: {hits:?}");
    let err = reconcile(&hits, &[]).unwrap_err();
    assert!(err.contains("extra") || err.contains("resolver failed"), "{name}: {err}");
    found[0].clone()
}

fn fork_enum_prog(body: &str) -> String {
    format!(
        "#[derive(Clone, Copy, PartialEq, PartialOrd)]\npub enum ForkName {{ Fulu, Gloas }}\n{body}"
    )
}

#[test]
fn string_paren_after_a_guarded_prefix_is_a_hit() {
    let src =
        "fn f(s:&str)->bool{ let _ = stringify!(#\"a\"); matches!(s, \")\" | \"gloas\") }\n// \"\n";
    assert_rustc_lib_accepts("e01", src);
    assert!(lex_file(src).uncertain, "the guarded prefix makes e01 an uncertain file");
    let hit = one_class_hit("e01", "crates/t/src/e01.rs", src, Class::StringDispatch);
    assert!(hit.fp.contains("matches!(s, \")\" | \"gloas\")"), "{}", hit.fp);
}

#[test]
fn string_paren_in_a_trusted_matches_macro_is_a_clean_hit() {
    let src = "pub fn f(s: &str) -> bool {\n    matches!(s, \")\" | \"gloas\")\n}\n";
    assert_rustc_lib_accepts("e01b", src);
    assert!(!lex_file(src).uncertain, "e01b must be a trusted file");
    let hit = one_class_hit("e01b", "crates/t/src/e01b.rs", src, Class::StringDispatch);
    assert!(hit.resolve_error.is_none(), "{:?}", hit.resolve_error);
    assert_eq!(hit.item, "f");
    assert_eq!(hit.wildcard, Some(false));
}

#[test]
fn string_paren_in_a_trusted_match_is_a_clean_hit() {
    let src = "pub fn f(s: &str) -> u8 {\n    match (s, \")\") {\n        (\")\", _) => 0,\n        (\"gloas\", _) => 1,\n        _ => 2,\n    }\n}\n";
    assert_rustc_lib_accepts("e01c", src);
    assert!(!lex_file(src).uncertain, "e01c must be a trusted file");
    let hit = one_class_hit("e01c", "crates/t/src/e01c.rs", src, Class::StringDispatch);
    assert!(hit.resolve_error.is_none(), "{:?}", hit.resolve_error);
    assert_eq!(hit.fp, "match (s, \")\") {");
    assert_eq!(hit.wildcard, Some(true));
}

#[test]
fn matches_macro_with_bracket_or_brace_delimiters_is_a_hit() {
    for (name, call) in
        [("bracket", "matches![s, \"gloas\"]"), ("brace", "matches! { s, \"gloas\" }")]
    {
        let src = format!("pub fn f(s: &str) -> bool {{\n    {call}\n}}\n");
        assert_rustc_lib_accepts(name, &src);
        let hit = one_class_hit(name, "crates/t/src/m.rs", &src, Class::StringDispatch);
        assert_eq!(hit.wildcard, Some(false), "{name}");
    }
    let src = "pub fn f(p: (&str, u8)) -> bool {\n    matches!(p, (\"gloas\", _))\n}\n";
    assert_rustc_lib_accepts("macro-wildcard", src);
    let hit = one_class_hit("macro-wildcard", "crates/t/src/m.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(false), "`(\"gloas\", _)` is refutable");
}

#[test]
fn brace_in_a_comment_before_an_arm_keeps_the_wildcard() {
    let src = fork_enum_prog(
        "pub fn f(fork: ForkName) -> u8 {\n    match fork {\n        ForkName::Fulu => 1,\n        // }\n        _ => 0,\n    }\n}\n",
    );
    assert_rustc_lib_accepts("brace-cmt", &src);
    let hit = one_class_hit("brace-cmt", "crates/t/src/b.rs", &src, Class::MatchForkName);
    assert_eq!(hit.wildcard, Some(true), "the `_ =>` arm after the comment brace is in the body");
}

#[test]
fn paren_in_a_char_in_the_scrutinee_is_a_hit() {
    let src = fork_enum_prog(
        "pub fn f(fork: ForkName, c: char) -> u8 {\n    match (fork, c == '(') {\n        (ForkName::Gloas, true) => 1,\n        _ => 0,\n    }\n}\n",
    );
    assert_rustc_lib_accepts("paren-char", &src);
    let hit = one_class_hit("paren-char", "crates/t/src/p.rs", &src, Class::MatchForkName);
    assert_eq!(hit.fp, "match (fork, c == '(') {");
    assert_eq!(hit.wildcard, Some(true));
}

#[test]
fn brace_string_arm_keeps_the_string_dispatch() {
    let src = "pub fn f(v: &str) -> u8 {\n    match v {\n        \"}\" => 0,\n        \"gloas\" => 1,\n        _ => 2,\n    }\n}\n";
    assert_rustc_lib_accepts("brace-str", src);
    let hit = one_class_hit("brace-str", "crates/t/src/s.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(true));
}

#[test]
fn block_scrutinee_is_not_the_match_body() {
    let src = "pub fn f(s: &str) -> u8 {\n    match unsafe { s } {\n        \"gloas\" => 1,\n        _ => 0,\n    }\n}\n";
    assert_rustc_lib_accepts("block-scrutinee", src);
    let hit = one_class_hit("block-scrutinee", "crates/t/src/u.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(true));

    let src = "pub fn f(c: bool, s: &str, t: &str) -> u8 {\n    match if c { s } else { t } {\n        \"gloas\" => 1,\n        _ => 0,\n    }\n}\n";
    assert_rustc_lib_accepts("if-scrutinee", src);
    let hit = one_class_hit("if-scrutinee", "crates/t/src/u.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(true));
}

#[test]
fn uncertain_file_keeps_a_match_that_only_the_raw_walk_sees() {
    let src = "fn f(fork: ForkName) -> u8 {\n    let _ = \"open\n    match fork {\n        ForkName::Gloas => 1,\n        _ => 0,\n    }\n}\n";
    let lexed = lex_file(src);
    assert!(lexed.uncertain, "an unterminated string makes the file uncertain");
    let at = src.find("match fork").unwrap();
    assert!(!byte_in_code(&lexed.non_code, at), "the lexer mask hides the match");
    let hit = one_class_hit("raw-walk", "crates/t/src/o.rs", src, Class::MatchForkName);
    assert!(hit.resolve_error.is_some(), "{hit:?}");
    assert_eq!(hit.fp, "match fork {");
}

fn fork_arm_wildcard(name: &str, arm: &str) -> Option<bool> {
    let src = format!(
        "#![allow(unused, unreachable_patterns, non_snake_case)]\n#[derive(Clone, Copy, PartialEq)]\npub enum ForkName {{ Fulu, Gloas }}\nuse crate::ForkName::*;\nmacro_rules! any {{ () => {{ _ }}; }}\npub fn f(mut fork: ForkName, c: bool) -> u8 {{\n    match fork {{\n        ForkName::Fulu => 1,\n        {arm} => 2,\n        ForkName::Gloas => 3,\n    }}\n}}\n"
    );
    assert_rustc_lib_accepts(&format!("arm-{name}"), &src);
    let hits = scan_source("crates/t/src/w.rs", &src);
    let m = class_hits(&hits, Class::MatchForkName);
    assert_eq!(m.len(), 1, "{name}: {hits:?}");
    m[0].wildcard
}

#[test]
fn binding_catch_all_arms_are_wildcards() {
    let catch_all = [
        ("bare", "_"),
        ("binding", "other"),
        ("underscore-binding", "_other"),
        ("at-wildcard", "x @ _"),
        ("ref", "ref other"),
        ("mut", "mut other"),
        ("ref-mut", "ref mut other"),
        ("paren", "(other)"),
        ("or-wildcard", "ForkName::Gloas | _"),
        ("raw-ident", "r#other"),
        ("attr", "#[allow(unused_variables)] other"),
        ("multi-line", "other\n       "),
        ("comment", "/* c */ other"),
        ("upper-camel-binding", "#[allow(non_snake_case)] Other"),
        ("screaming-binding", "MAX_FORK"),
        ("pattern-macro", "any!()"),
        ("glob-variant", "Gloas"),
    ];
    for (name, arm) in catch_all {
        assert_eq!(fork_arm_wildcard(name, arm), Some(true), "{name}: `{arm}` is a catch-all");
    }
    let refutable = [
        ("guard", "other if c"),
        ("guard-at", "x @ _ if c"),
        ("fork-path", "ForkName::Gloas"),
        ("qualified-path", "<ForkName>::Gloas"),
        ("at-path", "x @ ForkName::Gloas"),
    ];
    for (name, arm) in refutable {
        assert_eq!(fork_arm_wildcard(name, arm), Some(false), "{name}: `{arm}` is not a catch-all");
    }
}

#[test]
fn tuple_and_reference_bindings_are_wildcards() {
    let src = "pub fn f(s: &str, t: &str) -> u8 {\n    match (s, t) {\n        (\"gloas\", _) => 1,\n        (a, ..) => { let _ = a; 0 }\n    }\n}\n";
    assert_rustc_lib_accepts("tuple-binding", src);
    let hit = one_class_hit("tuple-binding", "crates/t/src/t.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(true));

    let src = "pub fn f(s: &&str) -> u8 {\n    match s {\n        &\"gloas\" => 1,\n        &other => other.len() as u8,\n    }\n}\n";
    assert_rustc_lib_accepts("ref-binding", src);
    let hit = one_class_hit("ref-binding", "crates/t/src/r.rs", src, Class::StringDispatch);
    assert_eq!(hit.wildcard, Some(true));
}

fn kzg_mutant(src: &str, arm: &str) -> String {
    let fn_at = src.find("fn expected_kzg_proof_count").expect("expected_kzg_proof_count");
    let first = fn_at + src[fn_at..].find("ForkName::Phase0").expect("Phase0 arm");
    let arrow = first + src[first..].find("=>").expect("arm arrow");
    format!("{}{arm} {}", &src[..first], &src[arrow..])
}

#[test]
fn binding_catch_all_on_an_inventoried_match_fails_reconcile() {
    let path = "crates/eth-types/src/block.rs";
    let src = std::fs::read_to_string(workspace_root().join(path)).expect("read block.rs");
    let rows: Vec<Inv> = INVENTORY.iter().copied().filter(|r| r.path == path).collect();
    assert!(rows.iter().any(|r| r.item == "expected_kzg_proof_count" && !r.wildcard));
    reconcile(&scan_source(path, &src), &rows).unwrap_or_else(|e| panic!("live block.rs:\n{e}"));
    let catch_all = [
        "_",
        "other",
        "x @ _",
        "ref other",
        "fork_name @ _",
        "#[allow(non_snake_case)] Other",
        "Phase0",
        "any!()",
    ];
    for arm in catch_all {
        let err = reconcile(&scan_source(path, &kzg_mutant(&src, arm)), &rows).unwrap_err();
        assert!(err.contains("wildcard mismatch"), "`{arm}`: {err}");
        assert!(err.contains("expected_kzg_proof_count"), "`{arm}`: {err}");
    }
    let guarded = kzg_mutant(&src, "other if blobs > 0");
    reconcile(&scan_source(path, &guarded), &rows)
        .unwrap_or_else(|e| panic!("a guarded binding is not a catch-all:\n{e}"));
}

#[test]
fn fork_name_arm_split_across_lines_is_class_three() {
    let arms = [
        ("leading-vert", "        | ForkName::Fulu\n        => 1,\n        | ForkName::Gloas\n        => 2,"),
        ("split-path", "        ForkName\n            ::Fulu => 1,\n        ForkName\n            ::Gloas => 2,"),
        ("spaced-path", "        ForkName :: Fulu => 1,\n        ForkName :: Gloas => 2,"),
    ];
    for (name, body) in arms {
        let src = fork_enum_prog(&format!(
            "pub fn f(fork: ForkName) -> u8 {{\n    match fork {{\n{body}\n    }}\n}}\n"
        ));
        assert_rustc_lib_accepts(name, &src);
        let hit = one_class_hit(name, "crates/t/src/f.rs", &src, Class::MatchForkName);
        assert_eq!(hit.wildcard, Some(false), "{name}");
        assert_eq!(hit.fp, "match fork {", "{name}");
    }
}

#[test]
fn struct_pattern_brace_does_not_end_the_arm() {
    let src = fork_enum_prog(
        "pub struct S { pub f: ForkName }\npub fn f(s: S) -> u8 {\n    match s {\n        S { f: ForkName::Fulu } => 1,\n        S { f: ForkName::Gloas } | S { f: ForkName::Fulu } if false => 2,\n        S { f: ForkName::Gloas } => 3,\n    }\n}\n",
    );
    assert_rustc_lib_accepts("struct-pattern", &src);
    let hit = one_class_hit("struct-pattern", "crates/t/src/s.rs", &src, Class::MatchForkName);
    assert_eq!(hit.wildcard, Some(false));
    assert_eq!(hit.fp, "match s {");
}

#[test]
fn fork_name_outside_an_arm_pattern_is_not_class_three() {
    let cases = [
        ("comment", "pub fn f(x: u8) -> u8 {\n    match x {\n        // ForkName::Gloas => 9,\n        1 => 1,\n        _ => 0,\n    }\n}\n"),
        ("arm-body", "pub fn f(x: u8) -> ForkName {\n    match x {\n        1 => ForkName::Gloas,\n        _ => ForkName::Fulu,\n    }\n}\n"),
    ];
    for (name, body) in cases {
        let src = fork_enum_prog(body);
        assert_rustc_lib_accepts(name, &src);
        let hits = scan_source("crates/t/src/n.rs", &src);
        assert!(class_hits(&hits, Class::MatchForkName).is_empty(), "{name}: {hits:?}");
    }
}

const ALL_FORKS_PROG: &str = "#[derive(Clone, Copy, PartialEq)]\npub enum ForkName { Phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas }\n#[derive(Clone, Copy)]\npub enum BodyForkLayout { Deneb, Electra, Gloas }\n";

#[test]
fn self_fork_rule_applies_to_impls_of_fork_name() {
    let one_arm = "impl ForkName {\n    pub fn last(self) -> bool {\n        match self {\n            Self::Gloas => true,\n            _ => false,\n        }\n    }\n}\n";
    let trait_impl = "impl std::fmt::Display for ForkName {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Gloas => f.write_str(\"g\"),\n            _ => f.write_str(\"o\"),\n        }\n    }\n}\n";
    for (name, body, path) in [
        ("self-one-arm", one_arm, "crates/eth-types/src/fork.rs"),
        ("self-other-file", one_arm, "crates/eth-types/src/other.rs"),
        ("self-trait-impl", trait_impl, "crates/eth-types/src/display.rs"),
        ("self-trait-impl-outside", trait_impl, "crates/beacon/src/display.rs"),
    ] {
        let src = format!("{ALL_FORKS_PROG}{body}");
        assert_rustc_lib_accepts(name, &src);
        let hit = one_class_hit(name, path, &src, Class::MatchForkName);
        assert_eq!(hit.wildcard, Some(true), "{name}");
        assert_eq!(hit.fp, "match self {", "{name}");
    }
    let layout = "impl BodyForkLayout {\n    pub fn last(self) -> bool {\n        match self {\n            Self::Deneb | Self::Electra => false,\n            Self::Gloas => true,\n        }\n    }\n}\n";
    let src = format!(
        "#[derive(Clone, Copy)]\npub enum BodyForkLayout {{ Deneb, Electra, Gloas }}\n{layout}"
    );
    assert_rustc_lib_accepts("self-layout", &src);
    let hits = scan_source("crates/eth-types/src/block.rs", &src);
    assert!(class_hits(&hits, Class::MatchForkName).is_empty(), "no ForkName token: {hits:?}");
}

fn assert_hits(name: &str, src: &str, class: Class, n: usize) -> Vec<Hit> {
    assert_rustc_lib_accepts(name, src);
    let hits = class_hits(&scan_source("crates/t/src/x.rs", src), class);
    assert_eq!(hits.len(), n, "{name}: {hits:?}");
    hits
}

#[test]
fn match_body_before_a_following_block_is_found() {
    let exhaustive = "match fork { ForkName::Fulu => true, ForkName::Gloas => false }";
    let cases = [
        ("if-cond", format!("pub fn a(fork: ForkName) -> u8 {{ if {exhaustive} {{ 1 }} else {{ 0 }} }}\n")),
        ("while-cond", format!("pub fn b(fork: ForkName) {{ while {exhaustive} {{}} }}\n")),
        ("stmt-then-block", "pub fn e(fork: ForkName) { match fork { ForkName::Fulu => {}, ForkName::Gloas => {} } { let _ = 1; } }\n".to_string()),
        ("async-await", "pub async fn f(fork: ForkName) -> u8 { match async { fork }.await { ForkName::Fulu => 1, ForkName::Gloas => 2 } }\n".to_string()),
    ];
    for (name, body) in cases {
        let hits = assert_hits(name, &fork_enum_prog(&body), Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(false), "{name}");
    }
    let nested = fork_enum_prog("pub fn c(fork: ForkName, s: &str) -> u8 { match match fork { ForkName::Fulu => s, ForkName::Gloas => \"x\" } { \"gloas\" => 1, _ => 0 } }\n");
    assert_hits("match-match", &nested, Class::MatchForkName, 1);
    assert_eq!(
        assert_hits("match-match", &nested, Class::StringDispatch, 1)[0].wildcard,
        Some(true)
    );
    let for_in = "pub fn d(s: &str) { for _ in match s { \"gloas\" => 0..1, _ => 0..0 } {} }\n";
    assert_hits("for-in", for_in, Class::StringDispatch, 1);
}

#[test]
fn guard_commas_and_braces_do_not_start_an_arm() {
    let header = "use std::collections::HashMap;\npub struct Cfg { pub on: bool }\npub fn g<A, B>() -> bool { true }\n";
    let guards = [
        ("turbofish-call", "g::<u8, u8>()"),
        ("turbofish-type", "HashMap::<u8, u8>::new().is_empty()"),
        ("struct-literal", "Cfg { on: c }.on"),
        ("block-guard", "{ c } && c"),
    ];
    for (name, guard) in guards {
        let src = fork_enum_prog(&format!(
            "{header}pub fn f(fork: ForkName, c: bool) -> u8 {{\n    match fork {{\n        ForkName::Gloas if {guard} => 1,\n        _ => 0,\n    }}\n}}\n"
        ));
        let hits = assert_hits(name, &src, Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(true), "{name}");
    }
    let vert = fork_enum_prog("pub fn v(fork: ForkName, c: bool) -> u8 {\n    match fork {\n        ForkName::Fulu => if c { 1 } else { 2 }\n        | other => { let _ = other; 3 }\n    }\n}\n");
    let hits = assert_hits("vert-after-if", &vert, Class::MatchForkName, 1);
    assert_eq!(hits[0].wildcard, Some(true), "`| other` after an if-else arm body is a catch-all");
}

#[test]
fn inner_attribute_does_not_join_the_first_arm() {
    let src = fork_enum_prog("pub fn f(fork: ForkName) -> u8 {\n    match fork {\n        #![allow(unreachable_patterns)]\n        _ => 0,\n        ForkName::Fulu => 1,\n    }\n}\n");
    let hits = assert_hits("inner-attr", &src, Class::MatchForkName, 1);
    assert_eq!(hits[0].wildcard, Some(true));
}

#[test]
fn catch_all_inside_a_wrapper_pattern_is_a_wildcard() {
    let header = "#[derive(Clone, Copy)]\npub struct S { pub f: ForkName, pub n: u8 }\n";
    let cases = [
        ("ok-binding", "r: Result<ForkName, ()>", "r", "Ok(ForkName::Gloas) => 1,\n        Ok(got) => { let _ = got; 2 }\n        Err(()) => 0,"),
        ("ok-wildcard", "r: Result<ForkName, ()>", "r", "Ok(ForkName::Gloas) => 1,\n        Ok(_) => 2,\n        Err(()) => 0,"),
        ("some-binding", "o: Option<ForkName>", "o", "Some(ForkName::Gloas) => 1,\n        Some(x) => { let _ = x; 2 }\n        None => 0,"),
        ("struct-rest", "s: S", "s", "S { f: ForkName::Gloas, .. } => 1,\n        S { .. } => 2,"),
        ("struct-fields", "s: S", "s", "S { f: ForkName::Gloas, .. } => 1,\n        S { f, n: _ } => { let _ = f; 2 }"),
    ];
    for (name, arg, scrutinee, arms) in cases {
        let src = fork_enum_prog(&format!(
            "{header}pub fn f({arg}) -> u8 {{\n    match {scrutinee} {{\n        {arms}\n    }}\n}}\n"
        ));
        let hits = assert_hits(name, &src, Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(true), "{name}");
    }
    let exhaustive = fork_enum_prog("pub fn f(o: Option<ForkName>) -> u8 {\n    match o {\n        Some(ForkName::Fulu) => 1,\n        Some(ForkName::Gloas) => 2,\n        None => 0,\n    }\n}\n");
    let hits = assert_hits("some-exhaustive", &exhaustive, Class::MatchForkName, 1);
    assert_eq!(hits[0].wildcard, Some(false));
}

#[test]
fn glob_and_qualified_fork_paths_are_class_three() {
    let glob = "#[derive(Clone, Copy, PartialEq)]\npub enum ForkName { Fulu, Gloas }\nuse crate::ForkName::*;\npub fn f(fork: ForkName) -> u8 {\n    match fork {\n        Fulu => 1,\n        Gloas => 2,\n    }\n}\n";
    let hits = assert_hits("glob-bare", glob, Class::MatchForkName, 1);
    assert_eq!(hits[0].wildcard, Some(true), "a bare variant name is a binding");
    let qualified = fork_enum_prog("pub fn f(fork: ForkName) -> u8 {\n    match fork {\n        <ForkName>::Fulu => 1,\n        <ForkName>::Gloas => 2,\n    }\n}\n");
    let hits = assert_hits("qualified", &qualified, Class::MatchForkName, 1);
    assert_eq!(hits[0].wildcard, Some(false));
    let layout = "#[derive(Clone, Copy)]\npub enum BodyForkLayout { Deneb, Gloas }\npub fn f(l: BodyForkLayout) -> u8 {\n    match l {\n        BodyForkLayout::Deneb => 1,\n        BodyForkLayout::Gloas => 2,\n    }\n}\n";
    assert_hits("other-enum-path", layout, Class::MatchForkName, 0);
}

#[test]
fn fork_name_alias_finder_sees_glob_alias_and_rename() {
    let cases = [
        ("alias-glob", "use crate::ForkName::*;\n", true),
        ("alias-list", "use crate::ForkName::{Fulu, Gloas};\n", true),
        ("alias-variant-rename", "use crate::ForkName::Gloas as G;\n", true),
        ("alias-raw-glob", "use crate::r#ForkName::*;\n", true),
        ("alias-rename", "use crate::ForkName as Fork;\n", true),
        ("alias-type", "pub type Fork = ForkName;\n", true),
        ("alias-type-path", "pub type Fork = crate::ForkName;\n", true),
        ("alias-type-paren", "#[allow(unused_parens)]\npub type Fork = (ForkName);\n", true),
        ("alias-type-empty-args", "pub type Fork = ForkName<>;\n", true),
        ("alias-type-raw", "pub type Fork = r#ForkName;\n", true),
        ("alias-type-default", "pub type Fork<T = ForkName> = T;\n", true),
        (
            "alias-macro-type",
            "macro_rules! a {\n    () => { pub type F = crate::ForkName; };\n}\n",
            true,
        ),
        ("alias-macro-use", "macro_rules! b {\n    () => { use crate::ForkName::*; };\n}\n", true),
        ("alias-const", "pub const EARLY: ForkName = ForkName::Fulu;\n", true),
        ("alias-static", "pub static LAST: Option<ForkName> = None;\n", true),
        (
            "alias-assoc-const",
            "impl ForkName {\n    pub const LAST: ForkName = ForkName::Gloas;\n}\n",
            true,
        ),
        ("alias-trait-const", "pub trait T {\n    const F: ForkName;\n}\n", true),
        ("alias-const-fn", "pub const fn f(x: ForkName) -> ForkName { x }\n", false),
        ("alias-const-generic", "pub fn g<const N: usize>(x: ForkName) -> ForkName { x }\n", false),
        ("alias-other-const", "pub const N: usize = 1;\n", false),
        ("alias-plain-use", "mod m {\n    pub use crate::ForkName;\n}\n", false),
        ("alias-comment", "// use crate::ForkName::*;\npub type Other = u8;\n", false),
        ("alias-path-use", "pub fn f() -> ForkName { crate::ForkName::Gloas }\n", false),
    ];
    for (name, body, flagged) in cases {
        let src = format!("#![allow(unused)]\n{}{body}", fork_enum_prog(""));
        assert_rustc_lib_accepts(name, &src);
        let found = fork_name_aliases(&src);
        assert_eq!(!found.is_empty(), flagged, "{name}: {found:?}");
        let broken = format!("{src}fn broken( {{\n");
        assert_eq!(!fork_name_aliases(&broken).is_empty(), flagged, "{name}: token fallback");
    }
}

#[test]
fn source_has_no_fork_name_alias_or_variant_import() {
    let root = workspace_root();
    let files: Vec<(String, String)> = crates_and_bin_rs(&root)
        .into_iter()
        .map(|file| {
            let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            (rel, std::fs::read_to_string(&file).unwrap_or_default())
        })
        .collect();
    assert!(
        files.iter().filter(|(rel, _)| rel.contains("/tests/")).count() > 10,
        "scan tests/ too"
    );
    let errors = alias_gate(&files);
    assert!(
        errors.is_empty(),
        "a ForkName alias, rename, variant import or fork constant hides class 3 arms:\n{}",
        errors.join("\n")
    );
}

#[test]
fn alias_exemption_is_the_name_table_in_impl_fork_name_once() {
    let all = "    pub const ALL: [Self; 8] = [Self::Phase0, Self::Altair, Self::Bellatrix, Self::Capella, Self::Deneb, Self::Electra, Self::Fulu, Self::Gloas];\n";
    let names = "    const NAMES: [(ForkName, &str, u32); Self::COUNT] = [(Self::Phase0, \"phase0\", 0), (Self::Altair, \"altair\", 1), (Self::Bellatrix, \"bellatrix\", 2), (Self::Capella, \"capella\", 3), (Self::Deneb, \"deneb\", 4), (Self::Electra, \"electra\", 5), (Self::Fulu, \"fulu\", 6), (Self::Gloas, \"gloas\", 7)];\n";
    let table = format!(
        "impl ForkName {{\n{all}    pub const COUNT: usize = Self::ALL.len();\n{names}}}\n"
    );
    let no_all = format!("impl ForkName {{\n    pub const COUNT: usize = 8;\n{names}}}\n");
    let shadow = "pub mod n {\n    use super::ForkName;\n    pub const NAMES: ForkName = ForkName::Gloas;\n}\n";
    let next = "impl ForkName {\n    pub const NEXT: Option<Self> = None;\n}\n";
    let cases = [
        ("exempt-table", table.clone(), true),
        ("exempt-shadow", format!("{table}{shadow}"), false),
        ("exempt-next", format!("{table}{next}"), false),
        ("exempt-no-all", no_all, false),
        ("exempt-missing", String::new(), false),
    ];
    for (name, body, clean) in cases {
        let src = format!("#![allow(unused)]\n{ALL_FORKS_PROG}{body}");
        assert_rustc_lib_accepts(name, &src);
        let errors = alias_gate(&[("crates/eth-types/src/fork.rs".to_string(), src)]);
        assert_eq!(errors.is_empty(), clean, "{name}: {errors:?}");
    }
}

#[test]
fn matches_macro_binding_pattern_is_a_wildcard() {
    for (name, call) in [
        ("macro-at-group", "matches!(v, x @ (\"gloas\" | _))"),
        ("macro-at-binding", "matches!(v, x @ \"gloas\" | x)"),
    ] {
        let src = format!("pub fn f(v: &str) -> bool {{\n    {call}\n}}\n");
        let hits = assert_hits(name, &src, Class::StringDispatch, 1);
        assert_eq!(hits[0].wildcard, Some(true), "{name}");
    }
    let guarded =
        "pub fn f(v: &str, c: bool) -> bool {\n    matches!(v, x @ \"gloas\" | x if c)\n}\n";
    let hits = assert_hits("macro-guarded", guarded, Class::StringDispatch, 1);
    assert_eq!(hits[0].wildcard, Some(false));
}

#[test]
fn syn_decides_the_scrutinee_and_the_arm_bodies() {
    let header = "#[derive(Clone, Copy)]\npub struct S { pub f: u8 }\n";
    let cases = [
        ("if-let-struct", "ForkName::Fulu => if let S { f: 0 } = s { }"),
        ("while-let-struct", "ForkName::Fulu => while let S { f: 0 } = s { break }"),
        ("for-struct", "ForkName::Fulu => for S { f } in [s] { let _ = f; }"),
        ("for-open-range", "ForkName::Fulu => for _ in 0.. { break }"),
    ];
    for (name, arm) in cases {
        let src = fork_enum_prog(&format!(
            "{header}pub fn f(fork: ForkName, s: S) {{\n    match fork {{\n        {arm}\n        other => {{ let _ = other; }}\n    }}\n}}\n"
        ));
        let hits = assert_hits(name, &src, Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(true), "{name}: the `other` arm is a catch-all");
    }
    let cast = "pub fn f(s: &str) -> u8 {\n    match s.as_ptr() as *const u8 as usize {\n        _ if s == \"gloas\" => 1,\n        _ => 0,\n    }\n}\n";
    assert_eq!(assert_hits("const-cast", cast, Class::StringDispatch, 1)[0].wildcard, Some(true));
    let block = fork_enum_prog("pub fn f(fork: ForkName) -> u8 {\n    match &mut { fork } {\n        ForkName::Fulu => 1,\n        ForkName::Gloas => 2,\n    }\n}\n");
    assert_eq!(assert_hits("mut-block", &block, Class::MatchForkName, 1)[0].wildcard, Some(false));
}

#[test]
fn self_rule_follows_the_impl_self_type() {
    let body = "    pub fn last(self) -> bool {\n        match self {\n            Self::Gloas => true,\n            _ => false,\n        }\n    }\n";
    for (name, header) in [
        ("impl-crate-path", "impl crate::ForkName {\n"),
        ("impl-raw", "impl r#ForkName {\n"),
        ("impl-module-path", "mod m {\n    pub use crate::ForkName;\n}\nimpl m::ForkName {\n"),
    ] {
        let src = format!("{ALL_FORKS_PROG}{header}{body}}}\n");
        let hits = assert_hits(name, &src, Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(true), "{name}");
    }
}

#[test]
fn raw_and_qualified_fork_paths_are_class_three() {
    let cases = [
        ("raw-path", "r#ForkName::Fulu => 1,\n        r#ForkName::Gloas => 2,"),
        (
            "qualified-crate",
            "<crate::ForkName>::Fulu => 1,\n        <crate::ForkName>::Gloas => 2,",
        ),
        ("prefix-path", "crate::ForkName::Fulu => 1,\n        self::ForkName::Gloas => 2,"),
    ];
    for (name, arms) in cases {
        let src = fork_enum_prog(&format!(
            "pub fn f(fork: ForkName) -> u8 {{\n    match fork {{\n        {arms}\n    }}\n}}\n"
        ));
        let hits = assert_hits(name, &src, Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(false), "{name}");
    }
}

#[test]
fn kzg_shaped_mutants_compile_and_are_catch_alls() {
    let prog = |arm: &str| {
        format!(
            "#![allow(unused, non_snake_case, bindings_with_variant_name, unreachable_patterns)]\n{ALL_FORKS_PROG}macro_rules! any {{ () => {{ _ }}; }}\npub fn expected_kzg_proof_count(fork: ForkName, blobs: usize) -> Result<usize, ()> {{\n    match fork {{\n        ForkName::Deneb | ForkName::Electra => Ok(blobs),\n        ForkName::Fulu => {{\n            blobs.checked_mul(128).ok_or(())\n        }}\n        {arm} => Err(()),\n    }}\n}}\n"
        )
    };
    let original = "ForkName::Phase0\n        | ForkName::Altair\n        | ForkName::Bellatrix\n        | ForkName::Capella\n        | ForkName::Gloas";
    let guarded = format!("other if blobs > 0 => Err(()),\n        {original}");
    let cases = [
        ("kzg-original", original.to_string(), false),
        ("kzg-guarded", guarded, false),
        ("kzg-wild", "_".to_string(), true),
        ("kzg-binding", "other".to_string(), true),
        ("kzg-at", "fork_name @ _".to_string(), true),
        ("kzg-upper", "#[allow(non_snake_case)] Other".to_string(), true),
        ("kzg-macro", "any!()".to_string(), true),
        ("kzg-variant-binding", "Phase0".to_string(), true),
    ];
    for (name, arm, catch_all) in cases {
        let hits = assert_hits(name, &prog(&arm), Class::MatchForkName, 1);
        assert_eq!(hits[0].wildcard, Some(catch_all), "{name}");
    }
}

#[test]
fn turbofish_wrapper_with_a_binding_is_a_wildcard() {
    let src = fork_enum_prog("pub struct Wrap<T>(pub T);\npub fn f(w: Wrap<ForkName>) -> u8 {\n    match w {\n        Wrap::<ForkName>(ForkName::Gloas) => 1,\n        Wrap::<ForkName>(x) => { let _ = x; 2 }\n    }\n}\n");
    assert_eq!(
        assert_hits("turbofish-wrap", &src, Class::MatchForkName, 1)[0].wildcard,
        Some(true)
    );
}

#[test]
fn const_only_match_in_a_fork_file_is_class_three() {
    let fork = "#[derive(Clone, Copy, PartialEq, Eq)]\npub enum ForkName { Fulu, Gloas }\npub const EARLY: ForkName = ForkName::Fulu;\npub fn f(fork: ForkName) -> u8 {\n    match fork {\n        EARLY => 1,\n        _ => 0,\n    }\n}\n";
    assert_eq!(assert_hits("const-only", fork, Class::MatchForkName, 1)[0].wildcard, Some(true));
    let other = "pub const A: u8 = 1;\npub fn f(x: u8) -> u8 {\n    match x {\n        A => 1,\n        _ => 0,\n    }\n}\n";
    assert_hits("const-only-other", other, Class::MatchForkName, 0);
}

#[test]
fn match_site_that_syn_rejects_fails_closed() {
    let src = fork_enum_prog(
        "macro_rules! pick {\n    ($fork:expr) => {\n        match $fork {\n            ForkName::Gloas => 1,\n            _ => 0,\n        }\n    };\n}\npub fn f(fork: ForkName) -> u8 {\n    pick!(fork)\n}\n",
    );
    let hits = assert_hits("macro-rules-site", &src, Class::MatchForkName, 1);
    assert_eq!(hits[0].resolve_error.as_deref(), Some("syn rejected the match site"));
}

#[test]
fn self_rule_reads_the_impl_around_an_associated_const() {
    let body = "impl ForkName {\n    pub const LAST: Self = Self::Gloas;\n    pub const LAST_IS_GLOAS: bool = match Self::LAST {\n        Self::Gloas => true,\n        Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella | Self::Deneb | Self::Electra | Self::Fulu => false,\n    };\n}\n";
    let src = format!("{ALL_FORKS_PROG}{body}");
    assert_rustc_lib_accepts("assoc-const-match", &src);
    for path in ["crates/eth-types/src/x.rs", "crates/beacon/src/x.rs"] {
        let hits = class_hits(&scan_source(path, &src), Class::MatchForkName);
        assert_eq!(hits.len(), 1, "{path}: {hits:?}");
        assert_eq!(hits[0].wildcard, Some(false), "{path}");
    }
}

#[test]
fn raw_matches_macro_is_a_site() {
    let src = "pub fn f(s: &str) -> bool {\n    r#matches!(s, \"gloas\")\n}\n";
    assert_eq!(assert_hits("raw-matches", src, Class::StringDispatch, 1)[0].wildcard, Some(false));
}

#[test]
fn qualified_self_paths_count_inside_an_impl_of_fork_name() {
    let header = "#[derive(Clone, Copy, PartialEq, Eq)]\npub enum ForkName { Fulu, Gloas }\npub trait Tr {\n    const X: Self;\n}\nimpl Tr for ForkName {\n    const X: Self = Self::Fulu;\n}\n";
    let method = |arms: &str| {
        format!("{header}impl ForkName {{\n    pub fn f(self) -> u8 {{\n        match self {{\n            {arms}\n        }}\n    }}\n}}\n")
    };
    let qself = method("<Self>::Fulu => 1,\n            <Self>::Gloas => 2,");
    assert_eq!(assert_hits("qself-self", &qself, Class::MatchForkName, 1)[0].wildcard, Some(false));
    let assoc = method("<Self as Tr>::X => 1,\n            _ => 0,");
    assert_rustc_lib_accepts("qself-self-as", &assoc);
    let found = fork_name_aliases(&assoc);
    assert!(
        found.iter().any(|e| e.contains("const X")),
        "a Self-typed const hides the arm: {found:?}"
    );
}

#[test]
fn self_typed_consts_fail_the_alias_gate() {
    let cases = [
        ("self-const-last", "impl ForkName {\n    pub const LAST: Self = Self::Gloas;\n    pub fn f(self) -> u8 {\n        match self {\n            Self::LAST => 1,\n            _ => 0,\n        }\n    }\n}\n", "const LAST"),
        ("self-const-next", "impl ForkName {\n    pub const NEXT: Option<Self> = None;\n}\n", "const NEXT"),
        ("self-trait-const", "pub trait Tr {\n    const X: Self;\n}\n", "const X"),
        ("self-macro-const", "macro_rules! m {\n    () => { pub const LAST: Self = Self::Gloas; };\n}\nimpl ForkName {\n    m!();\n    pub fn f(self) -> u8 {\n        match self {\n            Self::LAST => 1,\n            _ => 0,\n        }\n    }\n}\n", "const LAST"),
        ("self-macro-impl", "macro_rules! m {\n    () => { impl ForkName { pub const LAST: Self = Self::Gloas; } };\n}\nm!();\n", "const LAST"),
        ("self-macro-trait", "macro_rules! m {\n    () => { pub trait Tr { const X: Self; } impl Tr for ForkName { const X: Self = Self::Fulu; } };\n}\nm!();\n", "const X"),
        ("self-impl-option", "pub trait Tr {\n    const X: Self;\n}\nimpl Tr for Option<ForkName> {\n    const X: Self = None;\n}\n", "impl ForkName: const X"),
        ("self-macro-metavar-name", "macro_rules! mm {\n    ($n:ident) => { pub const $n: Self = Self::Gloas; };\n}\nimpl ForkName {\n    mm!(LAST);\n    pub fn f(self) -> u8 {\n        match self {\n            Self::LAST => 1,\n            _ => 0,\n        }\n    }\n}\n", "const n: Self"),
        ("fork-macro-metavar-name", "macro_rules! mf {\n    ($n:ident) => { pub const $n: ForkName = ForkName::Gloas; };\n}\nmf!(EARLY);\n", "const n: ForkName"),
        ("self-macro-assoc", "macro_rules! m {\n    () => { pub trait Tr { type Me; const X: Self::Me; } impl Tr for ForkName { type Me = Self; const X: Self::Me = Self::Gloas; } };\n}\nm!();\nimpl ForkName {\n    pub fn f(self) -> u8 {\n        match self {\n            <Self as Tr>::X => 1,\n            _ => 0,\n        }\n    }\n}\n", "const X: Self::Me"),
        ("macro-dollar-type", "macro_rules! mt {\n    ($t:ty) => { pub const LAST: $t = <$t>::Gloas; };\n}\nimpl ForkName {\n    mt!(Self);\n}\n", "const LAST: $t"),
    ];
    for (name, body, finding) in cases {
        let src = format!("#![allow(unused)]\n#[derive(Clone, Copy, PartialEq, Eq)]\npub enum ForkName {{ Fulu, Gloas }}\n{body}");
        assert_rustc_lib_accepts(name, &src);
        let found = fork_name_aliases(&src);
        assert!(found.iter().any(|e| e.contains(finding)), "{name}: {found:?}");
    }
    let ids = "#[derive(Clone, Copy)]\npub enum ForkName { Fulu, Gloas }\nimpl ForkName {\n    pub const N: usize = 2;\n    pub const IDS: [u32; Self::N] = [6, 7];\n}\n";
    let other = "#[derive(Clone, Copy)]\npub struct Mode;\nimpl Mode {\n    pub const DEFAULT: Self = Mode;\n}\n";
    let not_macro = "pub fn g(x: bool) {\n    if !x {\n        struct Mode;\n        impl Mode {\n            const D: Self = Mode;\n        }\n    }\n}\n";
    for (name, src) in
        [("self-const-other", other), ("self-array-len", ids), ("self-not-macro", not_macro)]
    {
        assert_rustc_lib_accepts(name, src);
        assert!(fork_name_aliases(src).is_empty(), "{name}: {:?}", fork_name_aliases(src));
    }
}

#[test]
fn a_wrapper_is_a_catch_all_only_next_to_the_same_wrapper() {
    let arms = [
        (
            "ok-err-exhaustive",
            "Ok(ForkName::Fulu) => 1,\n        Ok(ForkName::Gloas) => 2,\n        Err(_) => 0,",
            false,
        ),
        ("ok-err-wild-mutant", "Ok(ForkName::Fulu) => 1,\n        _ => 2,", true),
        (
            "ok-binding-sibling",
            "Ok(ForkName::Fulu) => 1,\n        Ok(got) => { let _ = got; 2 }\n        Err(_) => 0,",
            true,
        ),
    ];
    for (name, arms, wildcard) in arms {
        let src = fork_enum_prog(&format!(
            "pub fn f(r: Result<ForkName, ()>) -> u8 {{\n    match r {{\n        {arms}\n    }}\n}}\n"
        ));
        assert_eq!(
            assert_hits(name, &src, Class::MatchForkName, 1)[0].wildcard,
            Some(wildcard),
            "{name}"
        );
    }
}

#[test]
fn self_path_counts_in_a_file_that_names_fork_name() {
    let arms = "Self::Gloas => 1,\n            _ => 0,";
    let tr = "pub trait Tr<const N: usize> {\n    fn f(self) -> u8;\n}\n";
    let tp = "pub trait Tp {\n    fn f(self) -> u8;\n}\n";
    let tq = "pub trait Tq<const N: usize> {}\nimpl Tq<0> for ForkName {}\n";
    let pubf = "pub fn f(self) -> u8";
    let cases = [
        ("self-const-arg", tr, "impl Tr<{ 0 }> for ForkName", "fn f(self) -> u8", arms),
        ("self-where-const", tq, "impl ForkName where Self: Tq<{ 0 }>", pubf, arms),
        ("self-paren-impl", "", "impl (ForkName)", pubf, arms),
        ("self-paren-trait", tp, "impl Tp for (ForkName)", "fn f(self) -> u8", arms),
        (
            "self-paren-qself",
            "",
            "impl ForkName",
            pubf,
            "<(Self)>::Gloas => 1,\n            _ => 0,",
        ),
    ];
    for (name, extra, header, f, arms) in cases {
        let src = format!(
            "#![allow(unused_parens, unused_braces)]\n{ALL_FORKS_PROG}{extra}{header} {{\n    {f} {{\n        match self {{\n            {arms}\n        }}\n    }}\n}}\n"
        );
        assert_rustc_lib_accepts(name, &src);
        let hits =
            class_hits(&scan_source("crates/eth-types/src/fork.rs", &src), Class::MatchForkName);
        assert_eq!(hits.len(), 1, "{name}: {hits:?}");
    }
}

#[test]
fn or_cases_and_plain_wrappers_are_catch_alls() {
    let result = [
        (
            "or-ok-binding",
            "Ok(other @ ForkName::Fulu) | Ok(other) => { let _ = other; 1 }\n        Err(_) => 0,",
        ),
        ("or-ok-wild", "Ok(ForkName::Fulu) | Ok(_) => 1,\n        Err(_) => 0,"),
        ("nested-or", "Ok(ForkName::Fulu | _) => 1,\n        Err(_) => 0,"),
    ];
    for (name, arms) in result {
        let src = fork_enum_prog(&format!(
            "pub fn f(r: Result<ForkName, ()>) -> u8 {{\n    match r {{\n        {arms}\n    }}\n}}\n"
        ));
        assert_eq!(
            assert_hits(name, &src, Class::MatchForkName, 1)[0].wildcard,
            Some(true),
            "{name}"
        );
    }
    let wrappers = [
        ("self-tuple", "pub struct W(pub ForkName);\nimpl W {\n    pub fn f(self) -> u8 {\n        match self {\n            Self(ForkName::Gloas) => 1,\n            Self(_) => 0,\n        }\n    }\n}\n"),
        ("self-struct", "pub struct W { pub f: ForkName }\nimpl W {\n    pub fn f(self) -> u8 {\n        match self {\n            Self { f: ForkName::Gloas } => 1,\n            Self { .. } => 0,\n        }\n    }\n}\n"),
        ("alias-struct", "pub struct S { pub f: ForkName }\npub type A = S;\npub fn f(s: S) -> u8 {\n    match s {\n        S { f: ForkName::Gloas } => 1,\n        A { .. } => 0,\n    }\n}\n"),
        ("renamed-ok", "use Result::Ok as Good;\npub fn f(r: Result<ForkName, ()>) -> u8 {\n    match r {\n        Ok(ForkName::Gloas) => 1,\n        Good(_) => 2,\n        Err(_) => 0,\n    }\n}\n"),
        ("paren-or", "pub fn f(r: Result<ForkName, ()>) -> u8 {\n    match r {\n        (Ok(ForkName::Fulu) | Ok(_)) => 1,\n        Err(_) => 0,\n    }\n}\n"),
        ("ref-paren-or", "pub fn f(o: &Option<ForkName>) -> u8 {\n    match o {\n        &(Some(ForkName::Fulu) | Some(_)) => 1,\n        &None => 0,\n    }\n}\n"),
        ("at-paren-or", "pub fn f(r: Result<ForkName, ()>) -> u8 {\n    match r {\n        v @ (Ok(ForkName::Fulu) | Ok(_)) => { let _ = v; 1 }\n        Err(_) => 0,\n    }\n}\n"),
        ("tuple-or", "pub fn f(r: Result<ForkName, ()>) -> u8 {\n    match (r, 0u8) {\n        (Ok(ForkName::Fulu) | Ok(_), _x) => 1,\n        (Err(_), _x) => 0,\n    }\n}\n"),
    ];
    for (name, body) in wrappers {
        let src = format!("#![allow(unreachable_patterns)]\n{}", fork_enum_prog(body));
        assert_eq!(
            assert_hits(name, &src, Class::MatchForkName, 1)[0].wildcard,
            Some(true),
            "{name}"
        );
    }
}

#[test]
fn self_path_of_another_enum_is_not_class_three() {
    let src = fork_enum_prog("#[derive(Clone, Copy)]\npub enum Mode { A, B }\nimpl Mode {\n    pub fn f(self) -> u8 {\n        match self {\n            Self::A => 1,\n            Self::B => 2,\n        }\n    }\n}\n");
    assert_hits("self-other-enum", &src, Class::MatchForkName, 0);
    assert!(
        fork_variants().contains("Gloas") && fork_variants().len() >= 8,
        "{:?}",
        fork_variants()
    );
}
