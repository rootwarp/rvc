//! `rvc_dvt_peer_ready{peer}` — 0 after lazy connect, 1 after the first successful RPC.
//!
//! `peer` is the configured address. The family lives on the signer-server
//! registry (`:9101`), not the validator-client `REGISTRY`.

use std::sync::LazyLock;

use prometheus::{IntGaugeVec, Opts};

/// 0 until the first successful RPC to that configured peer, then 1.
pub static RVC_DVT_PEER_READY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "rvc_dvt_peer_ready",
            "DVT peer readiness (1 after the first successful RPC to the configured address, else 0)",
        ),
        &["peer"],
    )
    .expect("rvc_dvt_peer_ready")
});

/// Force the lazy family so [`crate::metrics::SignerMetrics`] can register it.
pub fn init() {
    LazyLock::force(&RVC_DVT_PEER_READY);
}

pub(crate) fn record_configured(peer: &str) {
    RVC_DVT_PEER_READY.with_label_values(&[peer]).set(0);
}

pub(crate) fn record_ready(peer: &str) {
    RVC_DVT_PEER_READY.with_label_values(&[peer]).set(1);
}
