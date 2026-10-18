//! Self-build vs builder-win Gloas proposal flows.

use super::*;
use beacon::WireBody;
use eth_types::BeaconBlock;
use signer::SignerError;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use timing::{DeadlineBps, DeadlineSchedule};

fn gloas_service(
    signer: Arc<MockSigner>,
    beacon: Arc<MockBeaconClient>,
    pubkey: &PublicKey,
) -> BlockService<MockSigner, MockBeaconClient> {
    BlockService::new(
        signer,
        beacon,
        Arc::new(test_validator_store(pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    )
}

fn tight_payload_schedule() -> DeadlineSchedule {
    DeadlineSchedule::uniform(DeadlineBps { payload: 0, ..DeadlineBps::default() })
}

#[tokio::test]
async fn test_self_build_json_signs_block_then_envelope() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let spec_root = rvc_gloas::gloas_execution_payload_envelope_root(&gloas_envelope_ssz())
        .expect("spec envelope SSZ");
    assert_eq!(
        hex::encode(spec_root),
        rvc_gloas::test_fixtures::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT
    );
    let response = self_build_json_response(slot);
    let envelope_hex = response.data["execution_payload_envelope"]
        .as_str()
        .expect("bound envelope hex")
        .to_string();
    let envelope_ssz = hex::decode(envelope_hex.strip_prefix("0x").expect("0x prefix"))
        .expect("bound envelope hex");
    let expected_root =
        rvc_gloas::gloas_execution_payload_envelope_root(&envelope_ssz).expect("bound envelope");

    let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let signer = Arc::new(MockSigner::new().with_trace(trace.clone()));
    let beacon = Arc::new(MockBeaconClient::from_response(response).with_trace(trace.clone()));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "self-build JSON must succeed: {result:?}");

    assert_eq!(signer.header_calls.lock().unwrap().len(), 1);
    assert_eq!(signer.envelope_calls.lock().unwrap().len(), 1);
    assert_eq!(signer.envelope_calls.lock().unwrap()[0].object_root, expected_root);
    assert_eq!(signer.envelope_calls.lock().unwrap()[0].slot, slot);
    assert_eq!(beacon.publish_full_calls.lock().unwrap().len(), 1);
    assert!(beacon.publish_full_calls.lock().unwrap()[0].builder_url.is_none());
    let envelopes = beacon.envelope_publish_calls.lock().unwrap();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].blobs, WireBody::Json(serde_json::json!(["0xbb"])));
    assert_eq!(envelopes[0].kzg_proofs, WireBody::Json(serde_json::json!(["0xaa"])));
    assert_eq!(envelopes[0].consensus_version, "gloas");
    match &envelopes[0].signed_envelope {
        WireBody::Json(value) => {
            assert_eq!(value["message"], serde_json::json!(envelope_hex));
            assert_eq!(
                value["signature"],
                serde_json::json!(format!("0x{}", hex::encode(mock_envelope_sig().to_bytes())))
            );
        }
        other => panic!("expected JSON signed envelope, got {other:?}"),
    }
    assert_eq!(
        *trace.lock().unwrap(),
        vec!["sign_block", "publish_block", "sign_envelope", "publish_envelope"]
    );
}

#[tokio::test]
async fn test_self_build_ssz_signs_block_then_envelope() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let response = self_build_ssz_response(slot);
    let envelope_ssz = bound_self_build_envelope(&BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: self_build_body(slot, [0x11; 32]),
    });
    let expected_root =
        rvc_gloas::gloas_execution_payload_envelope_root(&envelope_ssz).expect("bound envelope");

    let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let signer = Arc::new(MockSigner::new().with_trace(trace.clone()));
    let beacon = Arc::new(MockBeaconClient::from_response(response).with_trace(trace.clone()));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "self-build SSZ must succeed: {result:?}");

    assert_eq!(signer.header_calls.lock().unwrap().len(), 1);
    assert_eq!(signer.envelope_calls.lock().unwrap().len(), 1);
    assert_eq!(signer.envelope_calls.lock().unwrap()[0].object_root, expected_root);
    assert_eq!(beacon.publish_ssz_calls.lock().unwrap().len(), 1);
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    let envelopes = beacon.envelope_publish_calls.lock().unwrap();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].blobs, WireBody::Ssz(vec![0xbb, 0xbc, 0xbd]));
    assert_eq!(envelopes[0].kzg_proofs, WireBody::Ssz(vec![0xaa, 0xab]));
    match &envelopes[0].signed_envelope {
        WireBody::Ssz(bytes) => {
            assert_eq!(&bytes[0..4], &100u32.to_le_bytes());
            assert_eq!(&bytes[4..100], mock_envelope_sig().to_bytes().as_slice());
            assert_eq!(&bytes[100..], envelope_ssz.as_slice());
        }
        other => panic!("expected SSZ signed envelope, got {other:?}"),
    }
    assert_eq!(
        *trace.lock().unwrap(),
        vec!["sign_block", "publish_block", "sign_envelope", "publish_envelope"]
    );
}

#[tokio::test]
async fn test_builder_win_echoes_url_and_skips_envelope() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let builder = "https://relay.example/v1";
    let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let signer = Arc::new(MockSigner::new().with_trace(trace.clone()));
    let beacon = Arc::new(
        MockBeaconClient::unblinded(gloas_block(slot))
            .with_consensus_version("gloas")
            .with_builder_url(builder)
            .with_trace(trace.clone()),
    );
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "builder-win must succeed: {result:?}");

    assert_eq!(signer.header_calls.lock().unwrap().len(), 1);
    assert!(signer.envelope_calls.lock().unwrap().is_empty());
    let publishes = beacon.publish_full_calls.lock().unwrap();
    assert_eq!(publishes.len(), 1);
    assert_eq!(publishes[0].builder_url.as_deref(), Some(builder));
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
    assert_eq!(*trace.lock().unwrap(), vec!["sign_block", "publish_block"]);
}

#[tokio::test]
async fn test_builder_win_ssz_echoes_url_and_skips_envelope() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let builder = "https://relay.example/ssz";
    let signer = Arc::new(MockSigner::new());
    let mut beacon = gloas_ssz_builder_win(slot);
    beacon = beacon.with_builder_url(builder);
    let beacon = Arc::new(beacon);
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(signer.envelope_calls.lock().unwrap().is_empty());
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
    let ssz = beacon.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz.len(), 1);
    assert_eq!(ssz[0].builder_url.as_deref(), Some(builder));
}

fn gloas_ssz_builder_win(slot: Slot) -> MockBeaconClient {
    let body = external_bid_body(slot, [0x11; 32]);
    let ssz_bytes = build_gloas_beacon_block_ssz(slot, 42, [0x11; 32], [0x22; 32], &body);
    MockBeaconClient::from_response(ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz_bytes),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    })
}

#[tokio::test]
async fn test_json_envelope_object_drops_duty_before_sign() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let mut response = self_build_json_response(slot);
    response.data["execution_payload_envelope"] = serde_json::json!({ "builder_index": "0" });
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("envelope must drop");
    assert!(matches!(err, BlockServiceError::Parse(_)), "expected Parse, got {err:?}");
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_full_calls.lock().unwrap().is_empty());
    assert!(signer.envelope_calls.lock().unwrap().is_empty());
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_invalid_envelope_ssz_drops_duty_before_sign() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let block_ssz = build_gloas_beacon_block_ssz(
        slot,
        42,
        [0x11; 32],
        [0x22; 32],
        &self_build_body(slot, [0x11; 32]),
    );
    let ssz_bytes = build_gloas_block_contents_ssz(&block_ssz, &[0xde, 0xad], &[0xaa], &[0xbb]);
    let response = ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz_bytes),
        payload_included: true,
        builder_url: None,
        consensus_block_value: None,
    };
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("GloasError");
    assert!(matches!(err, BlockServiceError::Gloas(_)), "expected Gloas, got {err:?}");
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_ssz_calls.lock().unwrap().is_empty());
    assert!(signer.envelope_calls.lock().unwrap().is_empty());
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_envelope_signer_refusal_drops_envelope_after_block() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let signer = Arc::new(MockSigner::new().with_envelope_error());
    let beacon = Arc::new(MockBeaconClient::from_response(self_build_json_response(slot)));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("signer refusal");
    assert!(
        matches!(err, BlockServiceError::EnvelopeAfterPublish(_)),
        "expected EnvelopeAfterPublish, got {err:?}"
    );
    assert_eq!(beacon.publish_full_calls.lock().unwrap().len(), 1);
    assert_eq!(signer.envelope_calls.lock().unwrap().len(), 1);
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_block_contents_with_builder_url_drops_unsigned() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let mut response = self_build_json_response(slot);
    response.builder_url = Some("https://relay.example/confused".to_string());
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("mixed shape");
    assert!(
        matches!(err, BlockServiceError::Parse(ref msg) if msg.contains("Eth-Builder-Url")),
        "expected mixed-shape Parse, got {err:?}"
    );
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_shape_header_mismatch_drops_duty_before_sign() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(
        MockBeaconClient::unblinded(gloas_block(slot))
            .with_consensus_version("gloas")
            .with_payload_included(true),
    );
    let service = gloas_service(signer.clone(), beacon.clone(), &pubkey);

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("shape mismatch");
    assert!(matches!(err, BlockServiceError::Parse(ref msg) if msg.contains("payload_included")));
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    assert!(beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_envelope_late_increments_on_slow_publish() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(
        MockBeaconClient::from_response(self_build_json_response(slot))
            .with_envelope_delay(Duration::from_millis(5)),
    );
    let service = gloas_service(signer, beacon.clone(), &pubkey)
        .with_deadline_schedule(tight_payload_schedule());

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "late envelope still publishes: {result:?}");
    assert_eq!(beacon.envelope_publish_calls.lock().unwrap().len(), 1);
    let note = service.last_envelope_deadline_note().expect("deadline note");
    assert!(
        note.overrun_stage.is_some(),
        "overrun must record the first crossing stage, got {note:?}"
    );
    assert!(note.elapsed_ms > note.deadline_ms);
}

#[tokio::test]
async fn test_default_deadline_does_not_mark_fast_envelope_late() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(self_build_json_response(slot)));
    let service = gloas_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    let note = service.last_envelope_deadline_note().expect("deadline note");
    assert!(note.overrun_stage.is_none(), "fast self-build must not be late, got {note:?}");
    assert!(note.elapsed_ms <= note.deadline_ms);
}

#[test]
fn test_first_overrun_stage_is_the_first_crossing() {
    let mut deadline = PayloadDeadline::for_test(5);
    deadline.mark_at("produce", 1);
    deadline.mark_at("sign_block", 6);
    deadline.mark_at("publish_envelope", 20);
    assert_eq!(deadline.first_overrun_stage(), Some("sign_block"));
}

#[test]
fn test_v4_envelope_deadline_is_injected_schedule_not_literal() {
    let src = include_str!("../mod.rs");
    let start = src.find("impl PayloadDeadline").expect("PayloadDeadline");
    let rest = &src[start..];
    let end = rest.find("\nimpl ").unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(body.contains("for_fork"), "{body}");
    assert!(body.contains("due_ms"), "{body}");
    assert!(body.contains(".payload"), "{body}");
    assert!(!body.contains("5000"), "{body}");
    assert!(!body.contains("payload_due_bps"), "{body}");
    assert!(!body.contains("std::env"), "{body}");

    let start = src.find("fn note_envelope_deadline").expect("deadline helper");
    let rest = &src[start..];
    let end = rest.find("\n    async fn ").or_else(|| rest.find("\nfn ")).unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(body.contains("first_overrun_stage"), "{body}");
    assert!(!body.contains("5000"), "{body}");
}

fn signer_service_for(secret: crypto::SecretKey) -> Arc<signer::SignerService> {
    let mut keys = crypto::KeyManager::new();
    keys.insert(secret);
    let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(keys)));
    let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("memory slashing db"));
    Arc::new(signer::SignerService::new(composite, db).with_enablement(signer::always_enabled()))
}

/// The envelope signs under the produce fence. A capture fence that no longer
/// holds is discarded before that sign, so dropping `capture_fence` from the
/// re-check (or deleting the re-check) publishes the envelope. A call with no
/// scope is `BeaconAdmissionRevoked`.
#[tokio::test]
async fn gloas_envelope_signs_under_its_scope_and_is_refused_without_one() {
    let secret = crypto::SecretKey::generate();
    let pubkey = secret.public_key();
    let signer = signer_service_for(secret);
    let slot = test_gloas_slot();
    let beacon = Arc::new(MockBeaconClient::from_response(self_build_json_response(slot)));
    let schedule = Arc::new(test_fork_schedule_with_near_gloas());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        schedule.clone(),
        [0xaa; 32],
    );
    let response = self_build_json_response(slot);
    let envelope = WireBody::Json(serde_json::json!("0x01"));
    let blobs = WireBody::Json(serde_json::json!([]));
    let proofs = WireBody::Json(serde_json::json!([]));
    let root = [0x11; 32];
    let fork = eth_types::ForkName::Gloas;
    let generation = Arc::new(AtomicU64::new(0));
    let fence = beacon::DutyFence::at(0, Arc::clone(&generation));
    let capture = beacon::DutyFence::at(0, generation);

    let published = signer::require_beacon_admission_scope(service.sign_and_publish_envelope(
        &response,
        &envelope,
        &blobs,
        &proofs,
        root,
        slot,
        &pubkey,
        fork,
        &mut PayloadDeadline::for_test(60_000),
        &fence,
        &capture,
    ))
    .await;
    assert!(published.is_ok(), "{published:?}");
    assert_eq!(beacon.envelope_publish_calls.lock().unwrap().len(), 1);

    let refused =
        signer::require_beacon_admission_scope(signer.sign_execution_payload_envelope_root(
            &root,
            slot + 2,
            &pubkey,
            schedule.as_ref(),
            &[0xaa; 32],
        ))
        .await;
    assert!(matches!(refused, Err(SignerError::BeaconAdmissionRevoked)), "{refused:?}");

    let held = beacon::DutyFence::at(0, Arc::new(AtomicU64::new(0)));
    let closed = beacon::DutyFence::closed();
    let blocked = signer::require_beacon_admission_scope(service.sign_and_publish_envelope(
        &response,
        &envelope,
        &blobs,
        &proofs,
        root,
        slot + 1,
        &pubkey,
        fork,
        &mut PayloadDeadline::for_test(60_000),
        &held,
        &closed,
    ))
    .await;
    let err = blocked.expect_err("revoked capture fence");
    assert!(err.to_string().contains("admission revoked in flight"), "{err}");
    assert_eq!(beacon.envelope_publish_calls.lock().unwrap().len(), 1);
}
