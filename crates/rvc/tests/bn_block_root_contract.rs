//! ARCH-3a HTTP contract pin for `GET /eth/v1/beacon/blocks/{block_id}/root`.
//!
//! A spec-conformant beacon node answers **404** with the standard error body
//! for a slot-qualified id whose block does not yet exist, and **200** for
//! `"head"` (beacon-APIs `apis/beacon/blocks/root.yaml`). This suite drives the
//! real [`beacon::BeaconClient`] / [`bn_manager::BnManager`] HTTP path — not
//! [`bn_manager::MockBeaconNodeClient`] — so the assertion is about transport
//! behaviour: the status the mock is configured with is the status the client
//! surfaces as [`beacon::BeaconError`].
//!
//! `SlotContext` is `pub(crate)` and is not widened here. Capture collapsing a
//! 404 to `head_root = None` is pinned in
//! `orchestrator::slot_context::tests::test_capture_yields_no_context_when_bn_404s_current_slot`.

use beacon::{BeaconClient, BeaconClientConfig, BeaconError};
use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Slot with no block yet (t=0 of the current slot).
const CURRENT_SLOT: u64 = 1000;

/// Beacon-API `HttpErrorResponse` body for a missing slot-qualified block.
///
/// Matches lighthouse `WhenSlotSkipped::None` → `custom_not_found`
/// (`NOT_FOUND: beacon block at slot {slot}`).
const SLOT_MISSING_BLOCK_BODY: &str =
    r#"{"code":404,"message":"NOT_FOUND: beacon block at slot 1000"}"#;

/// Canonical head root returned for `block_id = "head"`.
const HEAD_BLOCK_HEX: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn mount_spec_conformant_block_root_bn(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/beacon/blocks/{CURRENT_SLOT}/root")))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(SLOT_MISSING_BLOCK_BODY)
                .insert_header("content-type", "application/json"),
        )
        .expect(2)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/blocks/head/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "finalized": false,
            "data": { "root": HEAD_BLOCK_HEX }
        })))
        .expect(2)
        .mount(server)
        .await;
}

fn assert_missing_slot_is_api_404(err: BeaconError, via: &str) {
    match err {
        BeaconError::ApiError { status, message } => {
            assert_eq!(
                status, 404,
                "{via}: transport must surface the configured 404, not rewrite it"
            );
            assert_eq!(
                message, SLOT_MISSING_BLOCK_BODY,
                "{via}: transport must surface the configured error body unchanged"
            );
        }
        other => panic!("{via}: expected BeaconError::ApiError {{ status: 404 }}, got {other:?}"),
    }
}

/// Spec-conformant BN: 404 for a slot-qualified id with no block; 200 for `"head"`.
///
/// The mock is configured from the beacon-API contract (not from the client's
/// own output). The client must surface that 404 as `BeaconError::ApiError`
/// with the same status and body — the transport layer does not silently
/// rewrite it.
#[tokio::test]
async fn test_bn_returns_404_for_slot_qualified_id_with_no_block() {
    let server = MockServer::start().await;
    mount_spec_conformant_block_root_bn(&server).await;

    let slot_id = CURRENT_SLOT.to_string();

    let client = BeaconClient::new(BeaconClientConfig::new(server.uri()).with_max_retries(0))
        .expect("BeaconClient");

    assert_missing_slot_is_api_404(
        client.get_block_root(&slot_id).await.expect_err("slot-qualified id must 404"),
        "BeaconClient",
    );
    let head = client.get_block_root("head").await.expect("head must 200");
    assert_eq!(head.data.root, HEAD_BLOCK_HEX);

    let manager = BnManager::new(BnManagerConfig::new(vec![server.uri()])).expect("BnManager");
    let dyn_client: &dyn BeaconNodeClient = &manager;

    assert_missing_slot_is_api_404(
        dyn_client.get_block_root(&slot_id).await.expect_err("slot-qualified id must 404"),
        "BnManager",
    );
    let head = dyn_client.get_block_root("head").await.expect("head must 200");
    assert_eq!(head.data.root, HEAD_BLOCK_HEX);

    // Default retry budget (`max_retries=3`): 404 is not in the 429/5xx set, so
    // the slot-qualified mock is hit once. Policy check, not a transport rewrite.
    let retry_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/beacon/blocks/{CURRENT_SLOT}/root")))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(SLOT_MISSING_BLOCK_BODY)
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&retry_server)
        .await;
    let default_client = BeaconClient::new(BeaconClientConfig::new(retry_server.uri()))
        .expect("default-retry client");
    assert_missing_slot_is_api_404(
        default_client
            .get_block_root(&slot_id)
            .await
            .expect_err("slot-qualified id must 404 under default retries"),
        "BeaconClient (default retries)",
    );
}
