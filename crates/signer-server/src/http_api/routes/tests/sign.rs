//! Happy-path KATs, domain checks, slashing 412 on re-sign, span/request-id.

use super::*;
use tracing_test::traced_test;

// ── Real-gate 412 slashing harness (Issue 2.8b, reused by 2.9) ───────────

#[tokio::test]
async fn conflicting_attestation_same_target_epoch_returns_412() {
    let (sk, pk_bytes) = test_keypair();
    // One real gate over one in-memory slashing DB shared across both POSTs.
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    // First attestation (target epoch 2) stages + commits → 200.
    let first = post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x00)).await;
    assert_eq!(first.status(), StatusCode::OK, "first attestation signs");

    // A DISTINCT attestation with the SAME target epoch (different
    // beacon_block_root → different signing root) is a double vote → 412.
    let second = post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x11)).await;
    assert_eq!(
        second.status(),
        StatusCode::PRECONDITION_FAILED,
        "double vote must be rejected by the gate as 412"
    );
    // The 412 body must not leak slashing-DB internals (paths/rusqlite).
    let body = String::from_utf8(body_bytes(second).await).unwrap();
    assert!(
        !body.contains(".db") && !body.to_lowercase().contains("sqlite"),
        "no DB internals: {body}"
    );
}

#[tokio::test]
async fn randao_reveal_kat_signs_epoch_under_randao_domain() {
    let (sk, _) = test_keypair();
    let domain = compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr());
    let expected = sk.sign(&compute_signing_root(&42u64, domain)).to_bytes();
    assert_eq!(sign_ok(randao_body(42)).await, expected.to_vec());
}

#[tokio::test]
async fn aggregation_slot_kat_signs_slot_under_selection_proof_domain() {
    let (sk, _) = test_keypair();
    let domain = compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr());
    let expected = sk.sign(&compute_signing_root(&77u64, domain)).to_bytes();
    assert_eq!(sign_ok(aggregation_slot_body(77)).await, expected.to_vec());
}

/// RANDAO and AGGREGATION_SLOT share neither domain nor gate method; the same
/// scalar must NOT collide (0x02 RANDAO vs 0x05 SELECTION_PROOF).
#[tokio::test]
async fn randao_and_aggregation_slot_domains_do_not_collide() {
    assert_ne!(sign_ok(randao_body(7)).await, sign_ok(aggregation_slot_body(7)).await);
}

/// Non-slashable: re-signing the same RANDAO succeeds (no slashing-DB row).
#[tokio::test]
async fn randao_reveal_is_non_slashable_resign_ok() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    for _ in 0..2 {
        let resp = post_sign(state.clone(), &id, None, randao_body(9)).await;
        assert_eq!(resp.status(), StatusCode::OK, "randao is non-slashable");
    }
}

#[tokio::test]
async fn aggregate_and_proof_kat() {
    let agg = sample_aggregate_and_proof();
    let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, CURRENT_VERSION, expected_gvr());
    let object_root = agg.try_tree_hash_root().unwrap().0;
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&object_root, domain)).to_bytes();
    let body =
        p1_body("AGGREGATE_AND_PROOF", "aggregate_and_proof", serde_json::to_string(&agg).unwrap());
    assert_eq!(sign_ok(body).await, expected.to_vec());
}

#[tokio::test]
async fn sync_committee_message_kat_signs_the_block_root() {
    let msg = SyncCommitteeMessage {
        slot: 5,
        beacon_block_root: [0x22; 32],
        validator_index: 0,
        signature: dummy_sig(),
    };
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, CURRENT_VERSION, expected_gvr());
    // The signed object is the block ROOT, not the message container.
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&msg.beacon_block_root, domain)).to_bytes();
    let body = p1_body(
        "SYNC_COMMITTEE_MESSAGE",
        "sync_committee_message",
        serde_json::to_string(&msg).unwrap(),
    );
    assert_eq!(sign_ok(body).await, expected.to_vec());
}

#[tokio::test]
async fn sync_committee_contribution_and_proof_kat() {
    let cap = sample_contribution_and_proof();
    let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, CURRENT_VERSION, expected_gvr());
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&cap, domain)).to_bytes();
    let body = p1_body(
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        "contribution_and_proof",
        serde_json::to_string(&cap).unwrap(),
    );
    assert_eq!(sign_ok(body).await, expected.to_vec());
}

/// 4.1-review polish: lock the no-panic property at the ROUTE layer for the
/// contribution arm — a multi-KB `aggregation_bits` signs cleanly (200), not
/// a panic (`SyncCommitteeContribution` hashes the bits via a self-sizing
/// `vec_u8_tree_hash_root`, so any length is safe).
#[tokio::test]
async fn sync_committee_contribution_large_bits_is_200() {
    let mut cap = sample_contribution_and_proof();
    cap.contribution.aggregation_bits = vec![0xff; 4096];
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = p1_body(
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        "contribution_and_proof",
        serde_json::to_string(&cap).unwrap(),
    );
    let resp = post_sign(state, &id, Some("application/json"), body).await;
    assert_eq!(resp.status(), StatusCode::OK, "large contribution bits sign cleanly, no panic");
}

#[tokio::test]
async fn sync_committee_selection_proof_kat() {
    let sasd = SyncAggregatorSelectionData { slot: 7, subcommittee_index: 3 };
    let domain =
        compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, CURRENT_VERSION, expected_gvr());
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&sasd, domain)).to_bytes();
    assert_eq!(sign_ok(sync_selection_body(7, 3)).await, expected.to_vec());
}

/// The load-bearing test: `SYNC_COMMITTEE_SELECTION_PROOF` (0x08 over the
/// `SyncAggregatorSelectionData` struct) must NOT collide with
/// `AGGREGATION_SLOT` (0x05 over a bare slot) for the same slot — a
/// regression pointing this arm at `DOMAIN_SELECTION_PROOF` would pass every
/// other check but fail here.
#[tokio::test]
async fn sync_selection_and_aggregation_slot_domains_do_not_collide() {
    assert_ne!(
        sign_ok(aggregation_slot_body(7)).await,
        sign_ok(sync_selection_body(7, 0)).await,
        "0x08 sync-selection must not equal 0x05 aggregation-slot for the same slot"
    );
}

#[tokio::test]
async fn validator_registration_without_fork_info_signs_kat() {
    // A body that OMITS fork_info must parse + sign (not 400), and sign the
    // builder root (zero gvr, fixed builder fork version).
    let reg = sample_registration();
    assert_eq!(
        sign_ok(registration_body(&reg, false)).await,
        expected_registration_sig(&reg),
        "VALIDATOR_REGISTRATION omitting fork_info signs the builder root"
    );
}

#[tokio::test]
async fn validator_registration_with_fork_info_is_ignored_not_rejected() {
    // A body that DOES include fork_info still signs and produces the SAME
    // signature — fork_info is ignored for this type, not rejected.
    let reg = sample_registration();
    assert_eq!(
        sign_ok(registration_body(&reg, true)).await,
        expected_registration_sig(&reg),
        "fork_info is ignored for VALIDATOR_REGISTRATION (same builder root)"
    );
}

// ── BLOCK_V2 (Issue 2.9): KAT over the block header + double-proposal 412 ─

#[tokio::test]
async fn block_v2_happy_path_signs_the_block_header_root() {
    // BLOCK_V2 signs the `block_header` (a BeaconBlockHeader), never a
    // reconstructed block, under DOMAIN_BEACON_PROPOSER.
    let header = sample_block_header(0xbb);
    let domain = compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_VERSION, expected_gvr());
    let expected_root = compute_signing_root(&header, domain);

    let (sk, pk_bytes) = test_keypair();
    let expected_sig = sk.sign(&expected_root).to_bytes();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, Some("application/json"), block_v2_body(0xbb)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let got = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap();
    assert_eq!(hex::decode(got).unwrap(), expected_sig.to_vec(), "route signs the header root");
}

#[tokio::test]
async fn conflicting_block_same_slot_returns_412() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    // First block at slot 3_000_000 stages + commits → 200.
    let first = post_sign(state.clone(), &id, None, block_v2_body(0xaa)).await;
    assert_eq!(first.status(), StatusCode::OK, "first block signs");

    // A DISTINCT block at the SAME slot (different state_root → different
    // signing root) is a double block proposal → 412.
    let second = post_sign(state.clone(), &id, None, block_v2_body(0xbb)).await;
    assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED, "double proposal → 412");

    // Safe-body check (2.8b review polish): the 412 surfaces only the safe
    // slashing-violation detail, never the signature or DB internals.
    let body = String::from_utf8(body_bytes(second).await).unwrap();
    assert!(body.contains("slashing protection violation"), "safe violation message: {body}");
    assert!(!body.contains("0x") && !body.contains(".db"), "no signature/DB internals: {body}");
}

// ── ATTESTATION happy path — KAT: the route signs the correct root ───────

#[tokio::test]
async fn attestation_happy_path_signs_the_expected_root() {
    let att = sample_attestation();
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_VERSION, expected_gvr());
    let expected_root = compute_signing_root(&att, domain);

    let (sk, pk_bytes) = test_keypair();
    let expected_sig = sk.sign(&expected_root).to_bytes();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, Some("application/json"), attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let got = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap();
    let got_sig = hex::decode(got).unwrap();
    assert_eq!(got_sig, expected_sig.to_vec(), "route must sign the dispatcher-computed root");
}

#[tokio::test]
async fn attestation_text_plain_returns_bare_hex_signature() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, Some("text/plain"), attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.starts_with("0x") && !body.contains('{'), "bare 0x.. body: {body}");
    assert_eq!(body.len(), 2 + 192, "0x + 96-byte sig hex");
}

/// Gate 3 (:9000): a real sign over the HTTP frontend proves the exported
/// handler span carries the late-bound canonical fields — `pubkey` (truncated),
/// `duty`, `slot`, `request_id` — and that no raw secret (full pubkey hex or
/// the returned signature) reaches any handler or audit line.
#[tokio::test]
async fn sign_span_records_truncated_fields_and_logs_no_secrets() {
    use std::sync::Mutex;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    struct ValueVisitor<'a>(&'a mut Vec<(String, String)>);
    impl tracing::field::Visit for ValueVisitor<'_> {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            self.0.push((f.name().to_string(), format!("{v:?}")));
        }
        fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
            self.0.push((f.name().to_string(), v.to_string()));
        }
        fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
            self.0.push((f.name().to_string(), v.to_string()));
        }
    }
    struct LineVisitor(String);
    impl tracing::field::Visit for LineVisitor {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={v:?} ", f.name()));
        }
        fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
            self.0.push_str(&format!("{}={v} ", f.name()));
        }
        fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
            self.0.push_str(&format!("{}={v} ", f.name()));
        }
    }
    struct SignCapture {
        span_fields: Arc<Mutex<Vec<(String, String)>>>,
        event_lines: Arc<Mutex<Vec<String>>>,
    }
    impl<S> Layer<S> for SignCapture
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut buf = self.span_fields.lock().unwrap();
            attrs.record(&mut ValueVisitor(&mut buf));
        }
        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut buf = self.span_fields.lock().unwrap();
            values.record(&mut ValueVisitor(&mut buf));
        }
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = LineVisitor(String::new());
            event.record(&mut line);
            self.event_lines.lock().unwrap().push(line.0);
        }
    }

    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let full_pubkey_hex = hex::encode(pk_bytes);

    let span_fields = Arc::new(Mutex::new(Vec::new()));
    let event_lines = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(SignCapture { span_fields: span_fields.clone(), event_lines: event_lines.clone() });
    let guard = tracing::subscriber::set_default(subscriber);

    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_body = String::from_utf8(body_bytes(resp).await).unwrap();
    let sig = signature_hex(&resp_body);
    drop(guard);

    // (a) The exported handler span carries the late-bound canonical fields.
    let fields = span_fields.lock().unwrap();
    let pubkey = fields.iter().find(|(k, _)| k == "pubkey").expect("sign span must record pubkey");
    assert!(pubkey.1.contains("..."), "exported pubkey must be truncated: {}", pubkey.1);
    assert!(
        !pubkey.1.contains(&full_pubkey_hex),
        "exported pubkey must not be the full hex: {}",
        pubkey.1
    );
    assert!(
        fields.iter().any(|(k, v)| k == "duty" && v == "attestation"),
        "sign span must record duty=attestation; fields were {fields:?}"
    );
    assert!(
        fields.iter().any(|(k, _)| k == "slot"),
        "sign span must record slot; fields were {fields:?}"
    );
    assert!(
        fields.iter().any(|(k, _)| k == "request_id"),
        "sign span must record request_id; fields were {fields:?}"
    );

    // (b) No raw secret reaches any handler or audit line.
    let lines = event_lines.lock().unwrap();
    assert!(
        lines.iter().any(|l| l.contains("sign request audit")),
        "audit line must be captured; lines were {lines:?}"
    );
    for l in lines.iter() {
        assert!(!l.contains(&full_pubkey_hex), "full pubkey hex leaked into a log line: {l}");
        assert!(!l.contains(&sig), "signature leaked into a log line: {l}");
    }
}

/// KAT: the signing root is `DOMAIN_VOLUNTARY_EXIT` over the eth-types
/// `VoluntaryExit` SSZ object, and the BLS signature verifies.
#[tokio::test]
async fn voluntary_exit_kat_signs_under_voluntary_exit_domain() {
    let (sk, _) = test_keypair();
    let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CURRENT_VERSION, expected_gvr());
    let exit = VoluntaryExit { epoch: 256, validator_index: 99 };
    let expected = sk.sign(&compute_signing_root(&exit, domain)).to_bytes();
    assert_eq!(sign_ok(voluntary_exit_body(256, 99)).await, expected.to_vec());
}

/// EIP-7044: the domain uses the request's `current_version` verbatim, so a
/// Capella-capped caller gets the Capella domain. Non-tautological — a
/// different fork version yields a different signature.
#[tokio::test]
async fn voluntary_exit_domain_uses_request_fork_version_eip7044() {
    let (sk, _) = test_keypair();
    let exit = VoluntaryExit { epoch: 300, validator_index: 7 };

    // Caller supplies the Capella fork version (0x03000000) per EIP-7044.
    let capella = [0x03u8, 0x00, 0x00, 0x00];
    let domain_capella = compute_domain(DOMAIN_VOLUNTARY_EXIT, capella, expected_gvr());
    let expected = sk.sign(&compute_signing_root(&exit, domain_capella)).to_bytes();
    let got = sign_ok(voluntary_exit_body_with_version(300, 7, "03000000")).await;
    assert_eq!(got, expected.to_vec(), "domain must use the request's (capped) version");

    // A DIFFERENT fork version (Deneb) would produce a DIFFERENT signature —
    // proving the request's version actually drives the domain.
    let domain_deneb = compute_domain(DOMAIN_VOLUNTARY_EXIT, CURRENT_VERSION, expected_gvr());
    let under_deneb = sk.sign(&compute_signing_root(&exit, domain_deneb)).to_bytes();
    assert_ne!(got, under_deneb.to_vec(), "fork version must change the domain");
}

/// KAT: the server root is `DOMAIN_AGGREGATE_AND_PROOF` (SAME as the base
/// type) over the eth-types Electra `tree_hash_root`, and the sig verifies.
/// The use of `DOMAIN_AGGREGATE_AND_PROOF` here is the domain assertion (not
/// a new/wrong constant).
#[tokio::test]
async fn aggregate_and_proof_v2_electra_kat() {
    let agg = sample_electra_aggregate_and_proof();
    let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, CURRENT_VERSION, expected_gvr());
    let object_root = agg.try_tree_hash_root().unwrap().0;
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&object_root, domain)).to_bytes();
    let body = p1_body(
        "AGGREGATE_AND_PROOF_V2",
        "aggregate_and_proof",
        versioned_aggregate_v2_json("ELECTRA", serde_json::to_string(&agg).unwrap()),
    );
    assert_eq!(sign_ok(body).await, expected.to_vec());
}

/// The base `AGGREGATE_AND_PROOF` arm is unaffected and does NOT collide with
/// the Electra V2 arm: same aggregator/data/sigs, but Electra's extra
/// `committee_bits` leaf yields a different SSZ root → a different signature.
#[tokio::test]
async fn base_and_electra_aggregate_and_proof_do_not_collide() {
    let base = sample_aggregate_and_proof();
    let electra = sample_electra_aggregate_and_proof();
    let base_body = p1_body(
        "AGGREGATE_AND_PROOF",
        "aggregate_and_proof",
        serde_json::to_string(&base).unwrap(),
    );
    let electra_body = p1_body(
        "AGGREGATE_AND_PROOF_V2",
        "aggregate_and_proof",
        versioned_aggregate_v2_json("ELECTRA", serde_json::to_string(&electra).unwrap()),
    );
    assert_ne!(sign_ok(base_body).await, sign_ok(electra_body).await);
}

/// The frozen wire body decodes (independent of this crate's Serialize) and
/// signs to the eth-types Electra `tree_hash_root` over the
/// `DOMAIN_AGGREGATE_AND_PROOF` domain — pinning the Electra serde shape.
#[tokio::test]
async fn electra_v2_frozen_fixture_parses_and_signs_to_eth_types_root() {
    let fixture = electra_v2_frozen_fixture();

    // Decode the inner Electra object straight from the frozen wire JSON
    // (the same `ElectraAggregateAndProof` serde the server's variant uses),
    // NOT from our own serializer — this is the wire-shape freeze check.
    let v: serde_json::Value = serde_json::from_str(&fixture).unwrap();
    assert_eq!(v["aggregate_and_proof"]["version"], "ELECTRA");
    let electra: ElectraAggregateAndProof =
        serde_json::from_value(v["aggregate_and_proof"]["data"].clone()).unwrap();
    assert!(!electra.aggregate.committee_bits.is_empty(), "Electra committee_bits decoded");

    let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, CURRENT_VERSION, expected_gvr());
    let object_root = electra.try_tree_hash_root().unwrap().0;
    let (sk, _) = test_keypair();
    let expected = sk.sign(&compute_signing_root(&object_root, domain)).to_bytes();

    // The full frozen body through the real route signs to the same root →
    // the server's parse + dispatch agree with the eth-types Electra root.
    assert_eq!(sign_ok(fixture).await, expected.to_vec());
}

/// L3: HTTP `PAYLOAD_ATTESTATION` signs the plan-engine / pyspec root.
#[tokio::test]
async fn payload_attestation_kat_signs_kat_gloas_payload_attestation_signing_root() {
    let (sk, _) = test_keypair();
    let kat: [u8; 32] =
        hex::decode(rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat root");
    let expected = sk.sign(&kat).to_bytes();
    assert_eq!(sign_ok(payload_attestation_body("GLOAS")).await, expected.to_vec());
}

/// L3: HTTP `PROPOSER_PREFERENCES` signs the plan-engine / pyspec root.
#[tokio::test]
async fn proposer_preferences_kat_signs_kat_gloas_proposer_preferences_signing_root() {
    let (sk, _) = test_keypair();
    let kat: [u8; 32] =
        hex::decode(rvc_spec_vectors::spec_kat::KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat root");
    let expected = sk.sign(&kat).to_bytes();
    assert_eq!(sign_ok(proposer_preferences_body("GLOAS")).await, expected.to_vec());
}

/// HTTP `PROPOSER_PREFERENCES` must not stage or commit a slashing-DB row.
#[tokio::test]
async fn proposer_preferences_http_writes_no_slashing_row() {
    let (sk, pk_bytes) = test_keypair();
    let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("in-memory slashing DB"));
    let backend: Arc<dyn crate::backend::SigningBackend> =
        Arc::new(RealSigningBackend::with_key(sk));
    let gate = Arc::new(crate::service::SignerServiceImpl::build_gate(
        Arc::clone(&backend),
        Arc::clone(&db),
    ));
    let state = crate::http_api::Web3SignerState {
        gate,
        backend,
        audit: crate::http_api::AuditCfg::default(),
        metrics: Arc::new(crate::metrics::SignerMetrics::new()),
        client_cn_allow_list: None,
        genesis_fork_version: crate::sign_plan::BUILDER_FORK_VERSION_MAINNET,
    };
    let pk_hex = hex::encode(pk_bytes);
    let before_blocks = db.get_blocks(&pk_hex).expect("query blocks").len();
    let before_attestations = db.get_attestations(&pk_hex).expect("query attestations").len();
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, proposer_preferences_body("GLOAS")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        db.get_blocks(&pk_hex).expect("query blocks").len(),
        before_blocks,
        "proposer preferences must not write a block row"
    );
    assert_eq!(
        db.get_attestations(&pk_hex).expect("query attestations").len(),
        before_attestations,
        "proposer preferences must not write an attestation row"
    );
}

/// A7 label is the bounded `grpc_sign_type::PAYLOAD_ATTESTATION` constant, never
/// the request's `type` discriminator.
#[test]
fn http_a7_sign_type_payload_attestation_is_bounded() {
    use crate::http_api::request::SignPayload;
    use crate::metrics::grpc_sign_type;
    use eth_types::ForkName;
    use web3signer_wire::VersionedPayload;

    let payload = SignPayload::PayloadAttestation {
        payload_attestation: VersionedPayload { version: ForkName::Gloas, data: ptc_kat_data() },
    };
    let label = http_a7_sign_type(&payload);
    assert_eq!(label, grpc_sign_type::PAYLOAD_ATTESTATION);
    assert_eq!(label, "payload_attestation");
    assert_ne!(label, payload.type_name(), "must not use the request type discriminator");
}

#[tokio::test]
async fn payload_attestation_http_a7_records_bounded_label() {
    use crate::metrics::grpc_sign_type;

    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let metrics = Arc::clone(&state.metrics);
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, payload_attestation_body("GLOAS")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        metrics
            .sign_total
            .with_label_values(&["basic", grpc_sign_type::PAYLOAD_ATTESTATION, "success"])
            .get(),
        1,
        "A7 sign_total uses the bounded payload_attestation label"
    );
    assert_eq!(
        metrics.sign_total.with_label_values(&["basic", "PAYLOAD_ATTESTATION", "success"]).get(),
        0,
        "must not record the request type discriminator as the A7 label"
    );
}

/// A7 label is the bounded `grpc_sign_type::PROPOSER_PREFERENCES` constant, never
/// the request's `type` discriminator.
#[test]
fn http_a7_sign_type_proposer_preferences_is_bounded() {
    use crate::http_api::request::SignPayload;
    use crate::metrics::grpc_sign_type;
    use eth_types::ForkName;
    use web3signer_wire::VersionedPayload;

    let payload = SignPayload::ProposerPreferences {
        proposer_preferences: VersionedPayload { version: ForkName::Gloas, data: prefs_kat_data() },
    };
    let label = http_a7_sign_type(&payload);
    assert_eq!(label, grpc_sign_type::PROPOSER_PREFERENCES);
    assert_eq!(label, "proposer_preferences");
    assert_ne!(label, payload.type_name(), "must not use the request type discriminator");
}

#[tokio::test]
async fn proposer_preferences_http_a7_records_bounded_label() {
    use crate::metrics::grpc_sign_type;

    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let metrics = Arc::clone(&state.metrics);
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, proposer_preferences_body("GLOAS")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        metrics
            .sign_total
            .with_label_values(&["basic", grpc_sign_type::PROPOSER_PREFERENCES, "success"])
            .get(),
        1,
        "A7 sign_total uses the bounded proposer_preferences label"
    );
    assert_eq!(
        metrics.sign_total.with_label_values(&["basic", "PROPOSER_PREFERENCES", "success"]).get(),
        0,
        "must not record the request type discriminator as the A7 label"
    );
}

/// Completeness: every supported type dispatches end-to-end to `200` with a
/// signature, after the P2 arms landed. A regression in any arm fails here.
#[tokio::test]
async fn all_supported_types_dispatch_to_200() {
    let bodies = all_supported_type_bodies();
    assert_eq!(
        bodies.len(),
        13,
        "all FR-4..FR-14 types plus PAYLOAD_ATTESTATION and PROPOSER_PREFERENCES are covered"
    );
    for (type_name, body) in bodies {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let resp = post_sign(state, &id, None, body).await;
        assert_eq!(resp.status(), StatusCode::OK, "{type_name} must dispatch to 200");
    }
}

/// `Accept` negotiation holds for the new P2 types: `text/plain` → bare
/// `0x..` (2 + 192 hex), JSON default → `{"signature":"0x.."}`.
#[tokio::test]
async fn p2_types_honor_accept_text_plain_and_json() {
    for body in [voluntary_exit_body(7, 1), electra_v2_frozen_fixture()] {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let r = post_sign(state.clone(), &id, Some("text/plain"), body.clone()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let t = String::from_utf8(body_bytes(r).await).unwrap();
        assert!(t.starts_with("0x") && !t.contains('{'), "bare 0x body: {t}");
        assert_eq!(t.len(), 2 + 192, "0x + 96-byte sig hex");

        let r = post_sign(state, &id, None, body).await;
        assert_eq!(r.status(), StatusCode::OK);
        let j = String::from_utf8(body_bytes(r).await).unwrap();
        assert!(j.contains("\"signature\"") && j.contains("0x"), "json body: {j}");
    }
}

// ── Issue 2.3: :9000 trace-continuity bridge ─────────────────────────────

/// `sign_span` parents the handler span from an inbound W3C `traceparent`
/// BEFORE the span is entered, so re-injecting from the (now parented) span
/// yields the SAME trace id — the duty trace continues across :9000. Uses the
/// proven `inject_trace_context` oracle under a real OTel layer.
#[test]
fn sign_span_continues_inbound_trace() {
    use tracing_subscriber::layer::SubscriberExt;

    // `_guard` keeps the OTel pipeline alive for the test; it shuts down on
    // drop (its `provider` is telemetry-private — no explicit flush needed,
    // since these assertions read the span context locally, not an export).
    let (layer, _guard) =
        telemetry::init_tracing(&telemetry::TelemetryConfig::default()).expect("otel init");
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _default = tracing::subscriber::set_default(subscriber);

    let trace_id = "0af7651916cd43dd8448eb211c80319c";
    let mut inbound = axum::http::HeaderMap::new();
    inbound.insert("traceparent", format!("00-{trace_id}-b7ad6b7169203331-01").parse().unwrap());

    let span = super::sign_span(&inbound);
    let _enter = span.enter();
    let mut outbound = reqwest::header::HeaderMap::new();
    telemetry::inject_trace_context(&mut outbound);
    let tp =
        outbound.get("traceparent").and_then(|v| v.to_str().ok()).expect("traceparent present");
    assert!(tp.contains(trace_id), "sign_span must continue the inbound trace (got {tp})");
}

/// No inbound `traceparent`: `sign_span` yields a root span and does not panic.
#[test]
fn sign_span_without_traceparent_is_root_no_panic() {
    use tracing_subscriber::layer::SubscriberExt;

    // `_guard` keeps the OTel pipeline alive for the test; it shuts down on
    // drop (its `provider` is telemetry-private — no explicit flush needed,
    // since these assertions read the span context locally, not an export).
    let (layer, _guard) =
        telemetry::init_tracing(&telemetry::TelemetryConfig::default()).expect("otel init");
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _default = tracing::subscriber::set_default(subscriber);

    let span = super::sign_span(&axum::http::HeaderMap::new()); // must not panic
    let _enter = span.enter();
    let mut outbound = reqwest::header::HeaderMap::new();
    telemetry::inject_trace_context(&mut outbound);
    if let Some(tp) = outbound.get("traceparent").and_then(|v| v.to_str().ok()) {
        assert!(!tp.contains("00000000000000000000000000000000"), "fresh valid root");
    }
}

/// A minted request_id is echoed as `x-request-id` on the response.
#[tokio::test]
async fn sign_echoes_minted_request_id() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rid = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id echoed");
    // A v4 uuid string: 36 chars, 4 hyphens.
    assert_eq!(rid.len(), 36, "minted request id is a uuid string: {rid}");
    assert_eq!(rid.matches('-').count(), 4, "uuid hyphen grouping: {rid}");
}

/// A caller-supplied `x-request-id` is reused verbatim (not replaced).
#[tokio::test]
async fn sign_reuses_caller_request_id() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{id}"))
        .header("content-type", "application/json")
        .header("x-request-id", "caller-correlator-xyz")
        .body(Body::from(attestation_body(None)))
        .unwrap();
    let resp = router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-request-id").and_then(|v| v.to_str().ok()),
        Some("caller-correlator-xyz"),
    );
}

/// SEC-2.3-01: an over-long caller `x-request-id` is NOT reused (it would
/// otherwise pollute the signing audit log); a fresh uuid is minted instead.
#[tokio::test]
async fn sign_ignores_unbounded_caller_request_id() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let oversized = "a".repeat(200); // past the 128-char cap → must be replaced
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{id}"))
        .header("content-type", "application/json")
        .header("x-request-id", &oversized)
        .body(Body::from(attestation_body(None)))
        .unwrap();
    let resp = router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rid = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id echoed");
    assert_ne!(rid, oversized, "oversized caller id must not be reused");
    assert_eq!(rid.len(), 36, "a fresh uuid is minted instead: {rid}");
}

/// The handler records the canonical correlators (`request_id`, `duty`,
/// `slot`, truncated `pubkey`) on the sign span; events under it (the audit
/// line) inherit them, and the FULL pubkey never appears.
#[traced_test]
#[tokio::test]
async fn sign_records_canonical_correlators_on_span() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(logs_contain("duty=attestation"), "canonical duty on span");
    assert!(logs_contain("slot=5"), "canonical slot on span");
    assert!(logs_contain("request_id="), "request_id on span");
    assert!(logs_contain("pubkey="), "truncated pubkey on span");
    let full = hex::encode(pk_bytes);
    assert!(!logs_contain(&full), "full pubkey must never appear in logs");
}

/// A synthetic inbound `traceparent` does not break the live handler.
#[tokio::test]
async fn sign_with_inbound_traceparent_still_succeeds() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{id}"))
        .header("content-type", "application/json")
        .header("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        .body(Body::from(attestation_body(None)))
        .unwrap();
    let resp = router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "handler works with inbound traceparent");
}
