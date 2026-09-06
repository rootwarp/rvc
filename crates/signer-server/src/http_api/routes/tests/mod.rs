//! Router-level HTTP sign suites (`tower::oneshot` over the full `Router`).
//!
//! Split by topic from the former in-file `routes` tests module: happy-path /
//! KAT signing, error status paths, and CN/audit/metrics.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt; // oneshot

use crate::http_api::accept_loop::PeerCert;
use crate::http_api::router;
use crate::http_api::test_support::{test_keypair, test_state, MockBackend, RealSigningBackend};

use crypto::{compute_domain, compute_signing_root};
// Import BeaconBlockHeader EXPLICITLY from eth_types: an unrelated all-String
// `rvc-beacon::BeaconBlockHeader` DTO exists and would compute a garbage root.
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, Checkpoint,
    ContributionAndProof, ElectraAggregateAndProof, ElectraAttestation, PayloadAttestationData,
    ProposerPreferences, Root, SyncAggregatorSelectionData, SyncCommitteeContribution,
    SyncCommitteeMessage, ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};

const CURRENT_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

fn fork_info_json() -> &'static str {
    r#""fork_info": { "fork": { "previous_version": "0x03000000",
                                "current_version": "0x04000000",
                                "epoch": "100" },
         "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
}

fn expected_gvr() -> Root {
    let half = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let mut g = [0u8; 32];
    g[..16].copy_from_slice(&half);
    g[16..].copy_from_slice(&half);
    g
}

/// The canonical attestation used by the happy-path tests, matching
/// `attestation_body`.
fn sample_attestation() -> AttestationData {
    AttestationData {
        slot: 5,
        index: 0,
        beacon_block_root: [0u8; 32],
        source: Checkpoint { epoch: 1, root: [0u8; 32] },
        target: Checkpoint { epoch: 2, root: [0u8; 32] },
    }
}

fn attestation_body(extra_signing_root: Option<&str>) -> String {
    let sr = extra_signing_root.map(|r| format!(r#""signingRoot": "{r}","#)).unwrap_or_default();
    format!(
        r#"{{ "type": "ATTESTATION", {fi}, {sr}
              "attestation": {{ "slot": "5", "index": "0",
                                "beacon_block_root": "0x{z}",
                                "source": {{ "epoch": "1", "root": "0x{z}" }},
                                "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
        fi = fork_info_json(),
        z = "00".repeat(32),
    )
}

/// An ATTESTATION body with the same source/target epochs (1/2) as
/// `attestation_body` but a caller-chosen `beacon_block_root`, so two calls
/// with different bytes produce two DISTINCT attestations sharing a target
/// epoch — a double vote (Issue 2.8b slashing harness, reused by 2.9).
fn attestation_body_with_block_root(block_root_byte: u8) -> String {
    let br = format!("{block_root_byte:02x}").repeat(32);
    format!(
        r#"{{ "type": "ATTESTATION", {fi},
              "attestation": {{ "slot": "5", "index": "0",
                                "beacon_block_root": "0x{br}",
                                "source": {{ "epoch": "1", "root": "0x{z}" }},
                                "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
        fi = fork_info_json(),
        z = "00".repeat(32),
    )
}

/// A `BeaconBlockHeader` (slot 3_000_000) with a caller-chosen `state_root`,
/// so two headers at the same slot with different bytes are two DISTINCT
/// blocks — a double block proposal. Matches `block_v2_body`.
fn sample_block_header(state_root_byte: u8) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: 3_000_000,
        proposer_index: 12_345,
        parent_root: [0xaa; 32],
        state_root: [state_root_byte; 32],
        body_root: [0xcc; 32],
    }
}

fn block_v2_body(state_root_byte: u8) -> String {
    format!(
        r#"{{ "type": "BLOCK_V2", {fi},
              "beacon_block": {{ "version": "DENEB",
                                 "block_header": {{ "slot": "3000000",
                                                    "proposer_index": "12345",
                                                    "parent_root": "0x{aa}",
                                                    "state_root": "0x{sr}",
                                                    "body_root": "0x{cc}" }} }} }}"#,
        fi = fork_info_json(),
        aa = "aa".repeat(32),
        sr = format!("{state_root_byte:02x}").repeat(32),
        cc = "cc".repeat(32),
    )
}

fn randao_body(epoch: u64) -> String {
    format!(
        r#"{{ "type": "RANDAO_REVEAL", {fi}, "randao_reveal": {{ "epoch": "{epoch}" }} }}"#,
        fi = fork_info_json(),
    )
}

fn aggregation_slot_body(slot: u64) -> String {
    format!(
        r#"{{ "type": "AGGREGATION_SLOT", {fi}, "aggregation_slot": {{ "slot": "{slot}" }} }}"#,
        fi = fork_info_json(),
    )
}

async fn post_sign(
    state: crate::http_api::Web3SignerState,
    identifier: &str,
    accept: Option<&str>,
    body: String,
) -> Response {
    let mut rb = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{identifier}"))
        .header("content-type", "application/json");
    if let Some(a) = accept {
        rb = rb.header("accept", a);
    }
    router(state).oneshot(rb.body(Body::from(body)).unwrap()).await.unwrap()
}

async fn body_bytes(resp: Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
}

// ── RANDAO_REVEAL + AGGREGATION_SLOT (Issue 2.10): non-slashable KATs ─────

/// Sign `body` with a fresh real-key gate and return the raw 96-byte sig.
async fn sign_ok(body: String) -> Vec<u8> {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, Some("application/json"), body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let hexsig = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap().to_string();
    hex::decode(hexsig).unwrap()
}

// ── P1 aggregation + sync-committee arms (Issue 4.1) ─────────────────────

fn dummy_sig() -> Vec<u8> {
    vec![0xAB; 96]
}

/// A valid (small, in-limit) pre-Electra aggregation bitlist: `0x01` is a
/// 0-data-bit bitlist (just the length delimiter).
fn valid_agg_bits() -> Vec<u8> {
    vec![0x01]
}

fn sample_aggregate_and_proof() -> AggregateAndProof {
    AggregateAndProof {
        aggregator_index: 1,
        aggregate: Attestation {
            aggregation_bits: valid_agg_bits(),
            data: sample_attestation(),
            signature: dummy_sig(),
        },
        selection_proof: vec![0xCD; 96],
    }
}

fn sample_contribution_and_proof() -> ContributionAndProof {
    ContributionAndProof {
        aggregator_index: 1,
        contribution: SyncCommitteeContribution {
            slot: 5,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 0,
            aggregation_bits: vec![0u8; 16],
            signature: dummy_sig(),
        },
        selection_proof: vec![0xCD; 96],
    }
}

/// Wrap a serialized payload object in the sign envelope with `fork_info`.
fn p1_body(type_name: &str, payload_key: &str, payload_json: String) -> String {
    format!(
        r#"{{ "type": "{type_name}", {fi}, "{payload_key}": {payload_json} }}"#,
        fi = fork_info_json(),
    )
}

// ── SYNC_COMMITTEE_SELECTION_PROOF (Issue 4.2): the 0x08 disambiguation ───

fn sync_selection_body(slot: u64, subcommittee_index: u64) -> String {
    format!(
        r#"{{ "type": "SYNC_COMMITTEE_SELECTION_PROOF", {fi},
              "sync_aggregator_selection_data": {{ "slot": "{slot}",
                                                   "subcommittee_index": "{subcommittee_index}" }} }}"#,
        fi = fork_info_json(),
    )
}

// ── VALIDATOR_REGISTRATION (Issue 4.3): no fork_info, fixed builder domain ─

fn sample_registration() -> ValidatorRegistrationV1 {
    ValidatorRegistrationV1 {
        fee_recipient: [0x11; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: test_keypair().1,
    }
}

fn registration_body(reg: &ValidatorRegistrationV1, with_fork_info: bool) -> String {
    let reg_json = serde_json::to_string(reg).unwrap();
    if with_fork_info {
        format!(
            r#"{{ "type": "VALIDATOR_REGISTRATION", {fi}, "validator_registration": {reg_json} }}"#,
            fi = fork_info_json(),
        )
    } else {
        format!(r#"{{ "type": "VALIDATOR_REGISTRATION", "validator_registration": {reg_json} }}"#)
    }
}

/// Independently compute the builder signing root: fixed builder fork version
/// `0x00000000` + a ZERO genesis validators root (ADR-008), NOT a fork_info gvr.
fn expected_registration_sig(reg: &ValidatorRegistrationV1) -> Vec<u8> {
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, [0, 0, 0, 0], [0u8; 32]);
    let (sk, _) = test_keypair();
    sk.sign(&compute_signing_root(reg, domain)).to_bytes().to_vec()
}

// ── Issue 4.4: HTTP audit logging ────────────────────────────────────────
//
// Every sign request emits exactly one structured audit entry (success at
// `info`, every rejection at `warn` via `log_audit`) carrying only
// metadata — pubkey identifier, Web3Signer `type`, outcome, peer CN,
// backend, latency — NEVER the body, signing root, or signature. These tests
// capture the emitted tracing events with `tracing-test` and assert the
// field set plus the absence of secrets.

/// Mint a self-signed leaf whose subject CN is `cn`. Only the CN is read by
/// the audit extractor and no chain validation happens at the audit layer, so
/// a self-signed cert suffices to drive the cert-bearing CN path.
fn peer_cert_with_cn(cn: &str) -> PeerCert {
    let der = rvc_test_support::self_signed_leaf_der(cn);
    PeerCert(Some(rustls::pki_types::CertificateDer::from(der)))
}

/// `post_sign` with a Phase-3 `PeerCert` request extension injected, so the
/// handler derives the audit CN from a (test) client cert instead of the
/// default.
async fn post_sign_with_peer(
    state: crate::http_api::Web3SignerState,
    identifier: &str,
    body: String,
    peer: PeerCert,
) -> Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{identifier}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    req.extensions_mut().insert(peer);
    router(state).oneshot(req).await.unwrap()
}

/// Pull the `0x`-prefixed signature out of a JSON `{"signature":"0x.."}` body.
fn signature_hex(json_body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(json_body).unwrap();
    v["signature"].as_str().unwrap().to_string()
}

// ── Issue 5.1: VOLUNTARY_EXIT (P2, non-slashable, FR-13) ──────────────────

fn voluntary_exit_body(epoch: u64, validator_index: u64) -> String {
    format!(
        r#"{{ "type": "VOLUNTARY_EXIT", {fi},
              "voluntary_exit": {{ "epoch": "{epoch}", "validator_index": "{validator_index}" }} }}"#,
        fi = fork_info_json(),
    )
}

/// A VOLUNTARY_EXIT body with an explicit `current_version` (drives the
/// EIP-7044 cap test) over the same gvr the other helpers use.
fn voluntary_exit_body_with_version(
    epoch: u64,
    validator_index: u64,
    current_version_hex: &str,
) -> String {
    format!(
        r#"{{ "type": "VOLUNTARY_EXIT",
              "fork_info": {{ "fork": {{ "previous_version": "0x03000000",
                                         "current_version": "0x{cv}",
                                         "epoch": "100" }},
                   "genesis_validators_root": "0x{gvr}" }},
              "voluntary_exit": {{ "epoch": "{epoch}", "validator_index": "{validator_index}" }} }}"#,
        cv = current_version_hex,
        gvr = hex::encode(expected_gvr()),
    )
}

// ── Issue 5.2: AGGREGATE_AND_PROOF_V2 (Electra, P2, FR-14) ────────────────

/// The Electra sibling of `sample_aggregate_and_proof`: same data, but the
/// `aggregate` is an `ElectraAttestation` carrying `committee_bits`.
fn sample_electra_aggregate_and_proof() -> ElectraAggregateAndProof {
    ElectraAggregateAndProof {
        aggregator_index: 1,
        aggregate: ElectraAttestation {
            aggregation_bits: valid_agg_bits(),
            data: sample_attestation(),
            signature: dummy_sig(),
            committee_bits: vec![0x01; 8], // 64-bit committee bitvector (EIP-7549)
        },
        selection_proof: vec![0xCD; 96],
    }
}

// ── Issue 5.3: freeze the Electra mapping (spec-derived fixture) ──────────
//
// FR-31 freeze. Unlike the 5.2 KAT (which round-trips our OWN struct through
// serde_json::to_string and back — self-consistent, so blind to a
// Serialize/Deserialize field-name mismatch), this fixture is HAND-AUTHORED
// as a client sends it: the JSON structure + field names + encodings are
// written out literally, so it independently pins the wire shape the server's
// Deserialize must accept. CAVEAT: spec-derived (Ethereum Remote Signing API
// AGGREGATE_AND_PROOF_V2 schema), NOT a primary-source Lighthouse/Prysm
// Electra capture (none reachable here); a follow-up confirms it against a
// live capture once Electra traffic is available, fixing any casing/encoding
// discrepancy in request.rs/dispatch.rs then.

/// Wrap an Electra aggregate object in the Consensys `{version, data}` envelope.
fn versioned_aggregate_v2_json(version: &str, data_json: String) -> String {
    format!(r#"{{ "version": "{version}", "data": {data_json} }}"#)
}

// ── Issue 4.9b: PAYLOAD_ATTESTATION (Gloas PTC, fail-closed version) ──────

fn ptc_kat_data() -> PayloadAttestationData {
    PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot: 1,
        payload_present: true,
        blob_data_available: false,
    }
}

fn payload_attestation_body(version: &str) -> String {
    format!(
        r#"{{ "type": "PAYLOAD_ATTESTATION",
              "fork_info": {{ "fork": {{ "previous_version": "0x07000000",
                                         "current_version": "0x07000001",
                                         "epoch": "0" }},
                   "genesis_validators_root": "0x{gvr}" }},
              "payload_attestation": {{ "version": "{version}", "data": {data} }} }}"#,
        gvr = "00".repeat(32),
        data = serde_json::to_string(&ptc_kat_data()).unwrap(),
    )
}

fn prefs_kat_data() -> ProposerPreferences {
    ProposerPreferences {
        dependent_root: [0x33; 32],
        proposal_slot: 32,
        validator_index: 3,
        fee_recipient: [0x44; 20],
        target_gas_limit: 36_000_000,
    }
}

fn proposer_preferences_body(version: &str) -> String {
    format!(
        r#"{{ "type": "PROPOSER_PREFERENCES",
              "fork_info": {{ "fork": {{ "previous_version": "0x07000000",
                                         "current_version": "0x07000001",
                                         "epoch": "0" }},
                   "genesis_validators_root": "0x{gvr}" }},
              "proposer_preferences": {{ "version": "{version}", "data": {data} }} }}"#,
        gvr = "00".repeat(32),
        data = serde_json::to_string(&prefs_kat_data()).unwrap(),
    )
}

/// A frozen, spec-derived Electra `AGGREGATE_AND_PROOF_V2` wire body. Field
/// names and encodings (quoted `u64`, `0x`-lowercase hex bitlists, nested
/// `data`) match the remote-signing schema; `committee_bits` is the EIP-7549
/// Electra addition. Only the repetitive hex blobs are generated.
fn electra_v2_frozen_fixture() -> String {
    let inner = format!(
        r#"{{
                "aggregator_index": "1",
                "aggregate": {{
                  "aggregation_bits": "0x01",
                  "data": {{ "slot": "5", "index": "0",
                            "beacon_block_root": "0x{z}",
                            "source": {{ "epoch": "1", "root": "0x{z}" }},
                            "target": {{ "epoch": "2", "root": "0x{z}" }} }},
                  "signature": "0x{sig}",
                  "committee_bits": "0x0101010101010101"
                }},
                "selection_proof": "0x{sp}"
              }}"#,
        z = "00".repeat(32),
        sig = "ab".repeat(96),
        sp = "cd".repeat(96),
    );
    format!(
        r#"{{ "type": "AGGREGATE_AND_PROOF_V2",
              "fork_info": {{ "fork": {{ "previous_version": "0x03000000",
                                         "current_version": "0x04000000",
                                         "epoch": "100" }},
                   "genesis_validators_root": "0x{gvr}" }},
              "aggregate_and_proof": {payload} }}"#,
        gvr = hex::encode(expected_gvr()),
        payload = versioned_aggregate_v2_json("ELECTRA", inner),
    )
}

// ── Issue 5.4: all-types completeness + regression gate ──────────────────

/// One valid body per supported Web3Signer `type` (FR-4..FR-14) — every duty
/// a running validator performs. The full Web3Signer protocol also defines
/// BLOCK v1 / DEPOSIT etc., which are out of scope for a VC (PRD); the 13
/// here are the complete dispatchable set.
fn all_supported_type_bodies() -> Vec<(&'static str, String)> {
    vec![
        ("BLOCK_V2", block_v2_body(0x11)),
        ("ATTESTATION", attestation_body(None)),
        ("RANDAO_REVEAL", randao_body(42)),
        ("AGGREGATION_SLOT", aggregation_slot_body(77)),
        (
            "AGGREGATE_AND_PROOF",
            p1_body(
                "AGGREGATE_AND_PROOF",
                "aggregate_and_proof",
                serde_json::to_string(&sample_aggregate_and_proof()).unwrap(),
            ),
        ),
        (
            "SYNC_COMMITTEE_MESSAGE",
            p1_body(
                "SYNC_COMMITTEE_MESSAGE",
                "sync_committee_message",
                serde_json::to_string(&SyncCommitteeMessage {
                    slot: 5,
                    beacon_block_root: [0x22; 32],
                    validator_index: 0,
                    signature: dummy_sig(),
                })
                .unwrap(),
            ),
        ),
        (
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            p1_body(
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                "contribution_and_proof",
                serde_json::to_string(&sample_contribution_and_proof()).unwrap(),
            ),
        ),
        ("SYNC_COMMITTEE_SELECTION_PROOF", sync_selection_body(5, 1)),
        ("VALIDATOR_REGISTRATION", registration_body(&sample_registration(), true)),
        ("VOLUNTARY_EXIT", voluntary_exit_body(256, 99)),
        ("AGGREGATE_AND_PROOF_V2", electra_v2_frozen_fixture()),
        ("PAYLOAD_ATTESTATION", payload_attestation_body("GLOAS")),
        ("PROPOSER_PREFERENCES", proposer_preferences_body("GLOAS")),
    ]
}

// Re-export production helpers used by topic suites (`super::sign_span`).
pub(super) use super::{http_a7_sign_type, sign_span};

mod auth;
mod errors;
mod sign;
