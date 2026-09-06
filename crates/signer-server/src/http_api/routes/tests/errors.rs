//! Pre-gate and payload error paths (400/404/413) for the sign route.

use super::*;

#[tokio::test]
async fn aggregate_and_proof_malformed_bits_is_400_not_panic() {
    // An over-length aggregation_bits bitlist must surface as 400 via
    // try_tree_hash_root, never a panic (the liveness-DoS class).
    let mut agg = sample_aggregate_and_proof();
    agg.aggregate.aggregation_bits = vec![0xff; 4096]; // far past the committee limit
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body =
        p1_body("AGGREGATE_AND_PROOF", "aggregate_and_proof", serde_json::to_string(&agg).unwrap());
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "malformed bits → 400, not panic");
}

// ── Request hardening (Issue 2.11) ───────────────────────────────────────

#[tokio::test]
async fn oversized_body_returns_413() {
    // Empty backend: were the body cap missing, the route would resolve the
    // (unloaded) key and return 404 — so a 413 strictly proves the cap fired
    // at extraction, before any handler/gate work.
    let state = test_state(Arc::new(MockBackend::empty()));
    let id = format!("0x{}", "ab".repeat(48));
    let oversized = "x".repeat((1 << 20) + 1); // 1 MiB + 1 byte
    let resp = post_sign(state, &id, None, oversized).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ── Pre-gate error paths ─────────────────────────────────────────────────

#[tokio::test]
async fn unloaded_key_returns_404() {
    let state = test_state(Arc::new(MockBackend::empty()));
    // A well-formed 48-byte hex key that is simply not loaded.
    let id = format!("0x{}", "ab".repeat(48));
    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_identifier_returns_400() {
    let state = test_state(Arc::new(MockBackend::empty()));
    let resp = post_sign(state, "0xdeadbeef", None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_body_returns_400_without_decoder_detail() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, "{ this is not json".to_string()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    // SEC-INFO-01: a fixed body, no serde decoder text (no line/column/"expected").
    assert_eq!(body, "invalid sign request body");
    assert!(!body.contains("column") && !body.contains("expected"), "no decoder detail: {body}");
}

#[tokio::test]
async fn signing_root_mismatch_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let bad = format!("0x{}", "ff".repeat(32));
    let resp = post_sign(state, &id, None, attestation_body(Some(&bad))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_fork_info_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = format!(
        r#"{{ "type": "ATTESTATION",
              "attestation": {{ "slot": "5", "index": "0",
                                "beacon_block_root": "0x{z}",
                                "source": {{ "epoch": "1", "root": "0x{z}" }},
                                "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
        z = "00".repeat(32),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// VOLUNTARY_EXIT requires fork_info (it is NOT the VALIDATOR_REGISTRATION
/// exception): an absent fork_info is a pre-gate 400.
#[tokio::test]
async fn voluntary_exit_missing_fork_info_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = r#"{ "type": "VOLUNTARY_EXIT",
                    "voluntary_exit": { "epoch": "5", "validator_index": "9" } }"#
        .to_string();
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A present, non-zero `signingRoot` that mismatches the server root → 400,
/// no gate call (the per-type signingRoot policy applies to this arm too).
#[tokio::test]
async fn voluntary_exit_signing_root_mismatch_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let bad = format!("0x{}", "ff".repeat(32));
    let body = format!(
        r#"{{ "type": "VOLUNTARY_EXIT", {fi}, "signingRoot": "{bad}",
              "voluntary_exit": {{ "epoch": "5", "validator_index": "9" }} }}"#,
        fi = fork_info_json(),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A malformed `voluntary_exit` payload (the required `validator_index` field
/// is missing) → fixed 400, no decoder leak.
#[tokio::test]
async fn voluntary_exit_malformed_payload_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = format!(
        r#"{{ "type": "VOLUNTARY_EXIT", {fi},
              "voluntary_exit": {{ "epoch": "5" }} }}"#,
        fi = fork_info_json(),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// An over-length `aggregation_bits` bitlist surfaces as 400 via
/// `try_tree_hash_root`, never a panic (the liveness-DoS class).
#[tokio::test]
async fn aggregate_and_proof_v2_malformed_bits_is_400_not_panic() {
    let mut agg = sample_electra_aggregate_and_proof();
    // Past the EIP-7549 Electra limit (2048*64 = 131072 bits ≈ 16384 bytes).
    agg.aggregate.aggregation_bits = vec![0xff; 20000];
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = p1_body(
        "AGGREGATE_AND_PROOF_V2",
        "aggregate_and_proof",
        versioned_aggregate_v2_json("ELECTRA", serde_json::to_string(&agg).unwrap()),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "malformed bits → 400, not panic");
}

/// An Electra `aggregate` missing the required `committee_bits` field is a
/// malformed V2 payload → fixed 400 (SEC-INFO-01, no decoder leak).
#[tokio::test]
async fn aggregate_and_proof_v2_missing_committee_bits_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let agg_json = format!(
        r#"{{ "aggregator_index": "1",
              "aggregate": {{ "aggregation_bits": "0x01",
                              "data": {data},
                              "signature": "0x{sig}" }},
              "selection_proof": "0x{sp}" }}"#,
        data = serde_json::to_string(&sample_attestation()).unwrap(),
        sig = "ab".repeat(96),
        sp = "cd".repeat(96),
    );
    let body = p1_body(
        "AGGREGATE_AND_PROOF_V2",
        "aggregate_and_proof",
        versioned_aggregate_v2_json("ELECTRA", agg_json),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// AGGREGATE_AND_PROOF_V2 requires fork_info (not the VALIDATOR_REGISTRATION
/// exception): an absent fork_info is a pre-gate 400.
#[tokio::test]
async fn aggregate_and_proof_v2_missing_fork_info_returns_400() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = format!(
        r#"{{ "type": "AGGREGATE_AND_PROOF_V2", "aggregate_and_proof": {agg} }}"#,
        agg = versioned_aggregate_v2_json(
            "ELECTRA",
            serde_json::to_string(&sample_electra_aggregate_and_proof()).unwrap(),
        ),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A bogus/unknown `type` is rejected with `400`, never a panic — the
/// dispatcher's tagged-enum decode fails closed.
#[tokio::test]
async fn unknown_type_returns_400_not_panic() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));
    let body = format!(
        r#"{{ "type": "NOT_A_REAL_TYPE", {fi}, "whatever": {{}} }}"#,
        fi = fork_info_json(),
    );
    let resp = post_sign(state, &id, None, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Unknown `version` on a known type is a 4xx naming the value; serde fails
/// closed so the backend is never invoked.
#[tokio::test]
async fn unknown_version_returns_400_naming_value_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = format!(
        r#"{{ "type": "BLOCK_V2", {fi},
              "beacon_block": {{ "version": "NOT_A_FORK",
                                 "block_header": {{ "slot": "3000000",
                                                    "proposer_index": "12345",
                                                    "parent_root": "0x{aa}",
                                                    "state_root": "0x{aa}",
                                                    "body_root": "0x{aa}" }} }} }}"#,
        fi = fork_info_json(),
        aa = "aa".repeat(32),
    );
    let resp = post_sign(state, &id, None, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(text.contains("NOT_A_FORK"), "names the version: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// Empty `version` is a generic 400 — never serde `at line N column M`.
#[tokio::test]
async fn empty_version_returns_generic_400_without_decoder_text() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = format!(
        r#"{{ "type": "BLOCK_V2", {fi},
              "beacon_block": {{ "version": "",
                                 "block_header": {{ "slot": "3000000",
                                                    "proposer_index": "12345",
                                                    "parent_root": "0x{aa}",
                                                    "state_root": "0x{aa}",
                                                    "body_root": "0x{aa}" }} }} }}"#,
        fi = fork_info_json(),
        aa = "aa".repeat(32),
    );
    let resp = post_sign(state, &id, None, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert_eq!(text, "invalid sign request body");
    assert!(!text.contains("line") && !text.contains("column"), "no decoder text: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// D19: GLOAS on BLOCK_V2 is a typed 4xx naming the HTTP wire; no backend call.
#[tokio::test]
async fn gloas_block_v2_returns_400_naming_wire_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = format!(
        r#"{{ "type": "BLOCK_V2", {fi},
              "beacon_block": {{ "version": "GLOAS",
                                 "block_header": {{ "slot": "3000000",
                                                    "proposer_index": "12345",
                                                    "parent_root": "0x{aa}",
                                                    "state_root": "0x{aa}",
                                                    "body_root": "0x{aa}" }} }} }}"#,
        fi = fork_info_json(),
        aa = "aa".repeat(32),
    );
    let resp = post_sign(state, &id, None, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(text.contains("BLOCK_V2"), "names the type: {text}");
    assert!(text.contains("Web3Signer HTTP wire"), "names the wire: {text}");
    assert!(text.contains("deferred"), "names the deferral: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// Unknown `version` on PAYLOAD_ATTESTATION is a 4xx naming the value; serde
/// fails closed so the backend is never invoked.
#[tokio::test]
async fn payload_attestation_unknown_version_returns_400_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, payload_attestation_body("NOT_A_FORK")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(text.contains("NOT_A_FORK"), "names the version: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// Unknown `version` on PROPOSER_PREFERENCES is a 4xx naming the value; serde
/// fails closed so the backend is never invoked.
#[tokio::test]
async fn proposer_preferences_unknown_version_returns_400_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, proposer_preferences_body("NOT_A_FORK")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(text.contains("NOT_A_FORK"), "names the version: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// Unknown `version` on BUILDER_REQUEST_AUTH is a 4xx naming the value; serde
/// fails closed so the backend is never invoked.
#[tokio::test]
async fn builder_request_auth_unknown_version_returns_400_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let resp = post_sign(state, &id, None, builder_request_auth_body("NOT_A_FORK")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(text.contains("NOT_A_FORK"), "names the version: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// D19: GLOAS on AGGREGATE_AND_PROOF_V2 is the same typed 4xx; no backend call.
#[tokio::test]
async fn gloas_aggregate_and_proof_v2_returns_400_naming_wire_and_skips_backend() {
    let (_, pk_bytes) = test_keypair();
    let backend = Arc::new(MockBackend::with_keys(vec![pk_bytes]));
    let state = test_state(backend.clone());
    let id = format!("0x{}", hex::encode(pk_bytes));
    let req = format!(
        r#"{{ "type": "AGGREGATE_AND_PROOF_V2", {fi},
              "aggregate_and_proof": {payload} }}"#,
        fi = fork_info_json(),
        payload = versioned_aggregate_v2_json("GLOAS", {
            let mut agg = sample_electra_aggregate_and_proof();
            // Unhashable: if D19 ran *after* tree_hash the body would be
            // `invalid aggregate_and_proof`, not the deferral.
            agg.aggregate.aggregation_bits = vec![0xff; 20_000];
            serde_json::to_string(&agg).unwrap()
        },),
    );
    let resp = post_sign(state, &id, None, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert_ne!(text, "invalid aggregate_and_proof", "must not have hashed first");
    assert!(text.contains("AGGREGATE_AND_PROOF_V2"), "names the type: {text}");
    assert!(text.contains("Web3Signer HTTP wire"), "names the wire: {text}");
    assert!(text.contains("deferred"), "names the deferral: {text}");
    assert_eq!(backend.sign_call_count(), 0, "backend must not be invoked");
}

/// Status-mapping spot-check after the P2 arms: a valid body to an unloaded
/// key still resolves to `404` pre-gate (the `412`/`500`/signingRoot-`400`
/// paths are covered by the per-type tests above).
#[tokio::test]
async fn completeness_unknown_key_still_404() {
    let state = test_state(Arc::new(MockBackend::empty()));
    let id = format!("0x{}", "ab".repeat(48));
    let resp = post_sign(state, &id, None, voluntary_exit_body(7, 1)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
