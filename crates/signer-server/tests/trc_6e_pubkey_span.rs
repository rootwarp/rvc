//! TRC-6e: the 18 signer `pubkey` span attributes are `TruncatedPubkey`.
//!
//! The assertion reads span fields recorded by the subscriber. A success
//! `tracing::info!` line still carries the full hex on the event; that value
//! is not part of the truncation check.

#![cfg(feature = "dvt")]

use std::collections::HashMap;
use std::sync::Arc;

use observability::logging::TruncatedPubkey;
use tonic::Request;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

use signer_server::dvt::allow_list::{AllowedPeer, AllowedPeers};
use signer_server::dvt::peer_service::PeerSignerServiceImpl;
use signer_server::proto::signer_v2 as sv2;
use signer_server::proto::signer_v2::peer_signer_service_server::PeerSignerService;
use signer_server::proto::signer_v2::signer_service_server::SignerService;

mod helpers;
use helpers::{make_service_with_db, sample_block_ssz, sample_fork_info, KNOWN_PUBKEY_BYTES};

const SIGNER_SPANS: &[&str] = &[
    "signer.v2.sign_beacon_block",
    "signer.v2.sign_blinded_beacon_block",
    "signer.v2.sign_randao_reveal",
    "signer.v2.sign_attestation_data",
    "signer.v2.sign_aggregate_and_proof",
    "signer.v2.sign_sync_committee_message",
    "signer.v2.sign_sync_aggregator_selection_data",
    "signer.v2.sign_contribution_and_proof",
    "signer.v2.sign_builder_registration",
    "signer.v2.sign_voluntary_exit",
    "signer.v2.sign_block_header",
    "signer.v2.sign_root",
];

const PEER_SPANS: &[&str] = &[
    "signer.dvt.partial_sign_beacon_block",
    "signer.dvt.partial_sign_attestation_data",
    "signer.dvt.partial_sign_sync_committee",
    "signer.dvt.partial_sign_payload_attestation",
    "signer.dvt.partial_sign_block_header",
    "signer.dvt.partial_sign_root",
];

struct CapturedSpan {
    name: String,
    fields: Vec<(String, String)>,
}

struct ValueVisitor(Vec<(String, String)>);

impl tracing::field::Visit for ValueVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

type Spans = Arc<parking_lot::Mutex<HashMap<u64, CapturedSpan>>>;
type Events = Arc<parking_lot::Mutex<Vec<Vec<(String, String)>>>>;

struct Capture {
    spans: Spans,
    events: Events,
}

impl<S> Layer<S> for Capture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = ValueVisitor(Vec::new());
        attrs.record(&mut visitor);
        self.spans.lock().insert(
            id.into_u64(),
            CapturedSpan { name: attrs.metadata().name().to_string(), fields: visitor.0 },
        );
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = ValueVisitor(Vec::new());
        values.record(&mut visitor);
        if let Some(span) = self.spans.lock().get_mut(&id.into_u64()) {
            span.fields.extend(visitor.0);
        }
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = ValueVisitor(Vec::new());
        event.record(&mut visitor);
        self.events.lock().push(visitor.0);
    }
}

fn is_full_hex_pubkey(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 96 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn span_identity(span: &CapturedSpan) -> String {
    if span.name == "grpc.sign" {
        span.fields
            .iter()
            .find(|(key, _)| key == "otel.name")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| span.name.clone())
    } else {
        span.name.clone()
    }
}

fn peer_service() -> PeerSignerServiceImpl {
    PeerSignerServiceImpl::new(
        Arc::new(HashMap::new()),
        Arc::new(AllowedPeers {
            peers: vec![AllowedPeer { peer_cn: "unknown".into(), share_index: 1, addr: None }],
        }),
        Some(Arc::new(slashing::SlashingDb::open_in_memory().expect("in-memory slashing db"))),
    )
}

#[tokio::test]
async fn test_signer_span_pubkey_attributes_are_truncated() {
    let spans: Spans = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let events: Events = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(Capture { spans: Arc::clone(&spans), events: Arc::clone(&events) });
    tracing::subscriber::set_global_default(subscriber)
        .expect("span capture is the only global dispatcher in this test target");

    let pubkey = KNOWN_PUBKEY_BYTES.to_vec();
    let full_hex = format!("0x{}", hex::encode(pubkey.as_slice()));
    let expected = TruncatedPubkey::new(&full_hex).to_string();

    let (svc, _db) = make_service_with_db();
    svc.sign_beacon_block(Request::new(sv2::SignBeaconBlockRequest {
        pubkey: pubkey.clone(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    }))
    .await
    .expect("sign_beacon_block");

    // The other eleven v2 handlers record `pubkey` before payload decode.
    // An empty fork is enough to reach that record and then fail closed.
    let _ = svc
        .sign_blinded_beacon_block(Request::new(sv2::SignBlindedBeaconBlockRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            block_ssz: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_randao_reveal(Request::new(sv2::SignRandaoRevealRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            epoch: 0,
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_attestation_data(Request::new(sv2::SignAttestationDataRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            data: None,
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_aggregate_and_proof(Request::new(sv2::SignAggregateAndProofRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            aggregator_index: 0,
            aggregate_ssz: Vec::new(),
            selection_proof: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_sync_committee_message(Request::new(sv2::SignSyncCommitteeMessageRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            slot: 0,
            beacon_block_root: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_sync_aggregator_selection_data(Request::new(
            sv2::SignSyncAggregatorSelectionDataRequest {
                pubkey: pubkey.clone(),
                fork_info: None,
                slot: 0,
                subcommittee_index: 0,
                fork_id: 0,
            },
        ))
        .await;
    let _ = svc
        .sign_contribution_and_proof(Request::new(sv2::SignContributionAndProofRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            aggregator_index: 0,
            contribution_ssz: Vec::new(),
            selection_proof: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_builder_registration(Request::new(sv2::SignBuilderRegistrationRequest {
            pubkey: pubkey.clone(),
            fee_recipient: Vec::new(),
            gas_limit: 0,
            timestamp: 0,
            genesis_fork_version: Vec::new(),
        }))
        .await;
    let _ = svc
        .sign_voluntary_exit(Request::new(sv2::SignVoluntaryExitRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            epoch: 0,
            validator_index: 0,
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_block_header(Request::new(sv2::SignBlockHeaderRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            header: None,
            fork_id: 0,
        }))
        .await;
    let _ = svc
        .sign_root(Request::new(sv2::SignRootRequest {
            pubkey: pubkey.clone(),
            fork_info: None,
            object_root: Vec::new(),
            duty: 0,
            fork_id: 0,
        }))
        .await;

    let peer = peer_service();
    let _ = peer
        .partial_sign_beacon_block(Request::new(sv2::PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            block_ssz: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = peer
        .partial_sign_attestation_data(Request::new(sv2::PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            data: None,
            fork_id: 0,
        }))
        .await;
    let _ = peer
        .partial_sign_sync_committee(Request::new(sv2::PartialSignSyncCommitteeRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            slot: 0,
            beacon_block_root: Vec::new(),
            fork_id: 0,
        }))
        .await;
    let _ = peer
        .partial_sign_payload_attestation(Request::new(sv2::PartialSignPayloadAttestationRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            data: None,
            fork_id: 0,
            object_root: Vec::new(),
        }))
        .await;
    let _ = peer
        .partial_sign_block_header(Request::new(sv2::PartialSignBlockHeaderRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            header: None,
            fork_id: 0,
        }))
        .await;
    let _ = peer
        .partial_sign_root(Request::new(sv2::PartialSignRootRequest {
            requester_index: 1,
            pubkey: pubkey.clone(),
            fork_info: None,
            object_root: Vec::new(),
            duty: 0,
            fork_id: 0,
        }))
        .await;

    let captured = spans.lock();
    let mut pubkey_by_span: HashMap<String, Vec<String>> = HashMap::new();
    let mut full_hex_span_fields = Vec::new();
    for span in captured.values() {
        let identity = span_identity(span);
        for (key, value) in &span.fields {
            if key != "pubkey" {
                continue;
            }
            pubkey_by_span.entry(identity.clone()).or_default().push(value.clone());
            if is_full_hex_pubkey(value) {
                full_hex_span_fields.push(format!("{identity}={value}"));
            }
        }
    }

    let event_full_hex = events
        .lock()
        .iter()
        .any(|fields| fields.iter().any(|(key, value)| key == "pubkey" && value == &full_hex));
    assert!(
        event_full_hex,
        "a success tracing::info! event must still carry the full pubkey ({full_hex}); \
         this assertion does not treat that event field as a span attribute"
    );

    let mut missing = Vec::new();
    for name in SIGNER_SPANS.iter().chain(PEER_SPANS.iter()) {
        match pubkey_by_span.get(*name).map(Vec::as_slice) {
            Some([value]) if value == &expected => {}
            other => missing.push(format!("{name}: {other:?}")),
        }
    }
    assert!(
        full_hex_span_fields.is_empty() && missing.is_empty(),
        "span pubkey attributes must be TruncatedPubkey ({expected}), not a 96-hex pubkey.\n\
         full-hex span fields (event fields are not inspected):\n{full_hex_span_fields:?}\n\
         sites that did not record that display:\n{}",
        missing.join("\n")
    );
}
