//! Parent-span correlation for the three DVT `spawn_blocking` closures.
//!
//! This is its own test target because the lib tests already install one global
//! dispatcher via `#[tracing_test::traced_test]`. That harness filters to
//! `signer_server=trace`, so it cannot see the in-closure `slashing.audit`
//! event. A second `set_global_default` in the lib binary panics under
//! `cargo test --lib`.

#![cfg(feature = "dvt")]
#![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface

use std::collections::HashMap;
use std::sync::Arc;

use tonic::Request;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;
use zeroize::Zeroizing;

use signer_server::dvt::allow_list::{AllowedPeer, AllowedPeers};
use signer_server::dvt::peer_service::PeerSignerServiceImpl;
use signer_server::dvt::types::ShareInfo;
use signer_server::proto::signer_v2 as sv2;
use signer_server::proto::signer_v2::peer_signer_service_server::PeerSignerService;

#[derive(Clone)]
struct CapturedEvent {
    message: String,
    /// `(span name, fields recorded on that span)` from the event scope, leaf
    /// first. Empty when the blocking thread did not re-enter.
    scope: Vec<(String, Vec<(String, String)>)>,
}

struct CapturedSpan {
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
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
}
impl tracing::field::Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

type Events = Arc<parking_lot::Mutex<Vec<CapturedEvent>>>;
type Spans = Arc<parking_lot::Mutex<HashMap<u64, CapturedSpan>>>;

struct Capture {
    events: Events,
    spans: Spans,
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
        self.spans.lock().insert(id.into_u64(), CapturedSpan { fields: visitor.0 });
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

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let scope = ctx
            .event_scope(event)
            .into_iter()
            .flatten()
            .map(|span| {
                let fields = self
                    .spans
                    .lock()
                    .get(&span.id().into_u64())
                    .map(|captured| captured.fields.clone())
                    .unwrap_or_default();
                (span.name().to_string(), fields)
            })
            .collect();
        self.events
            .lock()
            .push(CapturedEvent { message: visitor.message.unwrap_or_default(), scope });
    }
}

fn make_share(index: u64) -> ([u8; 48], ShareInfo) {
    let sk = crypto::SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let scalar_bytes = Zeroizing::new(sk.to_bytes());
    let share = ShareInfo { index, threshold: 2, total: 3, scalar_bytes, aggregate_pubkey: pk };
    (pk, share)
}

fn make_allow_list(entries: Vec<(&str, u64)>) -> Arc<AllowedPeers> {
    Arc::new(AllowedPeers {
        peers: entries
            .into_iter()
            .map(|(cn, idx)| AllowedPeer { peer_cn: cn.to_string(), share_index: idx, addr: None })
            .collect(),
    })
}

fn make_db() -> Arc<slashing::SlashingDb> {
    Arc::new(slashing::SlashingDb::open_in_memory().expect("open in-memory test DB"))
}

fn make_service(
    shares: Vec<([u8; 48], ShareInfo)>,
    allow_list: Arc<AllowedPeers>,
    db: Option<Arc<slashing::SlashingDb>>,
) -> PeerSignerServiceImpl {
    let map: HashMap<[u8; 48], ShareInfo> = shares.into_iter().collect();
    PeerSignerServiceImpl::new(Arc::new(map), allow_list, db)
}

fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

fn sample_fork_info() -> sv2::ForkInfo {
    sv2::ForkInfo {
        previous_version: vec![0x04, 0x00, 0x00, 0x00],
        current_version: vec![0x04, 0x00, 0x00, 0x00],
        epoch: 0,
        genesis_validators_root: vec![0x00; 32],
    }
}

fn sample_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::{encode_beacon_block_ssz, BeaconBlock};
    let block = BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };
    encode_beacon_block_ssz(&block, 4)
}

fn sample_header(slot: u64) -> sv2::BeaconBlockHeader {
    sv2::BeaconBlockHeader {
        slot,
        proposer_index: 1,
        parent_root: vec![0x11; 32],
        state_root: vec![0x22; 32],
        body_root: vec![0x33; 32],
    }
}

/// The `slashing audit` event emitted inside each `spawn_blocking` closure must
/// carry the handler span's correlation fields. The success `tracing::info!`
/// after `.await` is already on that span and is not the proof.
///
/// TRC-6e has not landed, so the pubkey field is the full hex recorded by the
/// handler prologue. This test does not assert truncation.
#[tokio::test]
async fn test_spawn_blocking_audit_carries_parent_span_fields() {
    let events: Events = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let spans: Spans = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(Capture { events: Arc::clone(&events), spans });
    // This binary has no `traced_test` global. `spawn_blocking` runs on a
    // thread a thread-local dispatcher would not reach.
    tracing::subscriber::set_global_default(subscriber)
        .expect("span capture is the only global dispatcher in this test target");

    const BLOCK_SLOT: u64 = 274_441;
    const HEADER_SLOT: u64 = 621_441;
    const SOURCE_EPOCH: u64 = 379_001;
    const TARGET_EPOCH: u64 = 379_002;

    let (block_pk, block_share) = make_share(1);
    let block_pubkey = pubkey_hex(&block_pk);
    let block_svc = make_service(
        vec![(block_pk, block_share)],
        make_allow_list(vec![("unknown", 1)]),
        Some(make_db()),
    );
    block_svc
        .partial_sign_beacon_block(Request::new(sv2::PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: block_pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(BLOCK_SLOT),
            fork_id: 4,
        }))
        .await
        .expect("partial_sign_beacon_block");

    let (header_pk, header_share) = make_share(1);
    let header_pubkey = pubkey_hex(&header_pk);
    let header_svc = make_service(
        vec![(header_pk, header_share)],
        make_allow_list(vec![("unknown", 1)]),
        Some(make_db()),
    );
    header_svc
        .partial_sign_block_header(Request::new(sv2::PartialSignBlockHeaderRequest {
            requester_index: 1,
            pubkey: header_pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            header: Some(sample_header(HEADER_SLOT)),
            fork_id: 7,
        }))
        .await
        .expect("partial_sign_block_header");

    let (att_pk, att_share) = make_share(1);
    let att_pubkey = pubkey_hex(&att_pk);
    let att_svc = make_service(
        vec![(att_pk, att_share)],
        make_allow_list(vec![("unknown", 1)]),
        Some(make_db()),
    );
    att_svc
        .partial_sign_attestation_data(Request::new(sv2::PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: att_pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            data: Some(sv2::AttestationData {
                slot: TARGET_EPOCH,
                index: 0,
                beacon_block_root: vec![0xAB; 32],
                source: Some(sv2::Checkpoint { epoch: SOURCE_EPOCH, root: vec![0x01; 32] }),
                target: Some(sv2::Checkpoint { epoch: TARGET_EPOCH, root: vec![0x02; 32] }),
            }),
            fork_id: 4,
        }))
        .await
        .expect("partial_sign_attestation_data");

    let captured = events.lock().clone();
    let assert_parent = |span_name: &str, pubkey: &str, extras: &[(&str, &str)]| {
        let parents: Vec<&Vec<(String, String)>> = captured
            .iter()
            .filter(|event| event.message.contains("slashing audit"))
            .filter_map(|event| {
                event.scope.iter().find(|(name, _)| name == span_name).map(|(_, fields)| fields)
            })
            .collect();
        let fields = parents
            .iter()
            .find(|fields| fields.iter().any(|(key, value)| key == "pubkey" && value == pubkey));
        assert!(
            fields.is_some(),
            "blocking-section slashing audit event is detached from {span_name} \
             (pubkey {pubkey} not on the event's parent span); parents={parents:?}"
        );
        let fields = fields.expect("parent span");
        assert_eq!(
            pubkey.len(),
            2 + 96,
            "parent pubkey correlation field must be the full hex, not a truncation"
        );
        assert!(!pubkey.contains("..."), "parent pubkey correlation field must not be truncated");
        for (key, value) in extras {
            assert!(
                fields.iter().any(|(field, recorded)| field == key && recorded == value),
                "{span_name} parent must record {key}={value}; fields were {fields:?}"
            );
        }
    };
    let block_slot = BLOCK_SLOT.to_string();
    let header_slot = HEADER_SLOT.to_string();
    let source_epoch = SOURCE_EPOCH.to_string();
    let target_epoch = TARGET_EPOCH.to_string();
    assert_parent(
        "signer.dvt.partial_sign_beacon_block",
        &block_pubkey,
        &[("slot", block_slot.as_str())],
    );
    assert_parent(
        "signer.dvt.partial_sign_block_header",
        &header_pubkey,
        &[("slot", header_slot.as_str())],
    );
    assert_parent(
        "signer.dvt.partial_sign_attestation_data",
        &att_pubkey,
        &[("source_epoch", source_epoch.as_str()), ("target_epoch", target_epoch.as_str())],
    );
}
