use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::info;

use observability::logging::TruncatedRoot;

use super::{SigningBackend, SigningBackendError};
use crate::dvt::lagrange::{combine_partial_signatures, verify_combined_signature};
use crate::dvt::types::ShareInfo;
use crate::metrics::DvtMetrics;
use crate::proto::signer_v2::{AttestationData, ForkInfo, PayloadAttestationData};

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Typed duty payload for a DVT peer partial-sign request (v2 `PeerSignerService`).
///
/// The v2 peer RPCs compute the signing root server-side from the duty (same
/// C-2/C-3 fix as the main signing path). A raw 32-byte root must not cross the
/// DVT client API.
#[derive(Debug, Clone)]
pub enum PartialSignDuty {
    BeaconBlock {
        fork_info: ForkInfo,
        block_ssz: Vec<u8>,
        fork_id: u32,
    },
    AttestationData {
        fork_info: ForkInfo,
        data: AttestationData,
        fork_id: u32,
    },
    SyncCommittee {
        fork_info: ForkInfo,
        slot: u64,
        beacon_block_root: Vec<u8>,
        fork_id: u32,
    },
    PayloadAttestation {
        fork_info: ForkInfo,
        data: PayloadAttestationData,
        fork_id: u32,
        object_root: Vec<u8>,
    },
}

/// PTC aggregation session: the requesting VC's planned root and fork version.
///
/// Peers cannot consult a BN (`SIGNER_SERVER_ALLOWED_EDGES` forbids a
/// `beacon` / `bn-manager` edge). Agreement is this pair only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtcSessionIdentity {
    pub object_root: [u8; 32],
    pub fork_version: [u8; 4],
}

/// Partial signature collected from a DVT peer.
#[derive(Debug, Clone, Copy)]
pub struct PeerPartial {
    pub share_index: u64,
    pub signature: [u8; 96],
    /// Session the peer signed, when known. PTC aggregation excludes a
    /// partial whose planned root or `fork_version` differs from the
    /// coordinator's — never aggregate across fork versions (4.11c).
    ///
    /// Production gRPC responses have no session fields (`None`). Do not
    /// stamp the request session onto a response; bind `None` partials to
    /// the coordinator signing root instead of treating `None` as agree.
    pub ptc_session: Option<PtcSessionIdentity>,
}

impl From<(u64, [u8; 96])> for PeerPartial {
    fn from((share_index, signature): (u64, [u8; 96])) -> Self {
        Self { share_index, signature, ptc_session: None }
    }
}

/// Coordinator view of a `PartialSignDuty` for the PTC aggregation filter.
enum PtcDutyKind {
    NotPtc,
    Session(PtcSessionIdentity),
    /// `PayloadAttestation` whose `object_root` is not 32 bytes or
    /// `fork_info.current_version` is not 4 bytes.
    Unparsable,
}

impl PartialSignDuty {
    fn ptc_duty_kind(&self) -> PtcDutyKind {
        match self {
            Self::PayloadAttestation { fork_info, object_root, .. } => {
                match (
                    <[u8; 32]>::try_from(object_root.as_slice()),
                    <[u8; 4]>::try_from(fork_info.current_version.as_slice()),
                ) {
                    (Ok(object_root), Ok(fork_version)) => {
                        PtcDutyKind::Session(PtcSessionIdentity { object_root, fork_version })
                    }
                    _ => PtcDutyKind::Unparsable,
                }
            }
            _ => PtcDutyKind::NotPtc,
        }
    }
}

/// Whether a tagged PTC session may enter the combine set.
///
/// Non-PTC duties always agree. `None` is unknown (gRPC wire) and is kept
/// here — [`bind_ptc_partials_to_signing_root`] binds those to the
/// coordinator signing root. Unparsable coordinator identity is fail-closed.
fn ptc_partial_agrees_with_session(duty: &PartialSignDuty, partial: &PeerPartial) -> bool {
    match duty.ptc_duty_kind() {
        PtcDutyKind::NotPtc => true,
        PtcDutyKind::Unparsable => false,
        PtcDutyKind::Session(session) => match partial.ptc_session {
            None => true,
            Some(peer) => {
                peer.object_root == session.object_root && peer.fork_version == session.fork_version
            }
        },
    }
}

/// `ShareInfo` has only this node's scalar and the aggregate pubkey — no
/// per-share verification keys. Bind PTC partials by selecting a subset
/// whose Lagrange combine verifies on the coordinator `signing_root`.
fn bind_ptc_partials_to_signing_root(
    partials: &[(u64, [u8; 96])],
    threshold: u64,
    pubkey: &[u8; 48],
    signing_root: &[u8; 32],
) -> Vec<(u64, [u8; 96])> {
    let n = partials.len();
    let t = threshold as usize;
    if n < t {
        return partials.to_vec();
    }
    for size in (t..=n).rev() {
        let mut found = None;
        each_index_combination(n, size, |idxs| {
            let subset: Vec<_> = idxs.iter().map(|&i| partials[i]).collect();
            if let Ok(combined) = combine_partial_signatures(&subset) {
                if verify_combined_signature(&combined, pubkey, signing_root).is_ok() {
                    found = Some(subset);
                    return true;
                }
            }
            false
        });
        if let Some(subset) = found {
            return subset;
        }
    }
    // No verifying subset ≥ threshold: keep the local share so the
    // existing threshold check fires (not combined-signature verification).
    partials.first().copied().into_iter().collect()
}

/// Visit k-combinations of `0..n`. `visit` returns true to stop.
fn each_index_combination(n: usize, k: usize, mut visit: impl FnMut(&[usize]) -> bool) -> bool {
    if k == 0 || k > n {
        return false;
    }
    let mut c: Vec<usize> = (0..k).collect();
    loop {
        if visit(&c) {
            return true;
        }
        let mut i = k;
        loop {
            if i == 0 {
                return false;
            }
            i -= 1;
            if c[i] < n - k + i {
                c[i] += 1;
                for j in i + 1..k {
                    c[j] = c[j - 1] + 1;
                }
                break;
            }
        }
    }
}

/// Trait for requesting partial signatures from remote DVT peers.
#[async_trait]
pub trait PeerRequester: Send + Sync {
    /// Request a partial signature for `duty` from `peer_addr`.
    ///
    /// `requester_index` is this node's share index; the peer server enforces
    /// it matches the mTLS client CN's allow-list entry (C-3).
    async fn request_partial(
        &self,
        peer_addr: &str,
        duty: &PartialSignDuty,
        pubkey: &[u8; 48],
        requester_index: u64,
    ) -> Result<PeerPartial, PeerRequestError>;
}

/// Error returned by peer partial-signature requests.
#[derive(Debug, thiserror::Error)]
pub enum PeerRequestError {
    #[error("peer request failed: {0}")]
    RequestFailed(String),

    #[error("peer request timed out")]
    Timeout,
}

/// Loaded share info plus peer addresses for a single validator key.
struct DvtKeyInfo {
    share: ShareInfo,
    peer_addrs: Vec<String>,
}

/// DVT signing backend that produces partial signatures and coordinates with peers
/// to collect threshold partials and combine via Lagrange interpolation.
pub struct DvtSigner {
    keys: HashMap<[u8; 48], DvtKeyInfo>,
    own_index: u64,
    peer_requester: Option<Arc<dyn PeerRequester>>,
    timeout: Duration,
    metrics: Option<Arc<DvtMetrics>>,
}

impl fmt::Debug for DvtSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvtSigner")
            .field("key_count", &self.keys.len())
            .field("own_index", &self.own_index)
            .finish()
    }
}

impl DvtSigner {
    /// Create a new `DvtSigner` from pre-loaded shares.
    ///
    /// `shares`: loaded Shamir shares (one per validator).
    /// `own_index`: this node's share index in the Shamir scheme.
    /// `peer_addrs`: addresses of peer DVT nodes (used for all keys).
    /// `peer_requester`: optional requester for collecting remote partials.
    /// `timeout`: per-peer request timeout.
    pub fn new(
        shares: Vec<ShareInfo>,
        own_index: u64,
        peer_addrs: Vec<String>,
        peer_requester: Option<Arc<dyn PeerRequester>>,
        timeout: Duration,
    ) -> Self {
        let mut keys = HashMap::new();

        for share in shares {
            let pubkey = share.aggregate_pubkey;
            keys.insert(pubkey, DvtKeyInfo { share, peer_addrs: peer_addrs.clone() });
        }

        info!(
            key_count = keys.len(),
            own_index,
            peer_count = peer_addrs.len(),
            "DvtSigner initialized"
        );

        Self { keys, own_index, peer_requester, timeout, metrics: None }
    }

    pub fn with_metrics(mut self, metrics: Arc<DvtMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Produce this node's own partial signature for the given signing root.
    fn own_partial(
        &self,
        signing_root: &[u8; 32],
        share: &ShareInfo,
    ) -> Result<(u64, [u8; 96]), SigningBackendError> {
        let sk = blst::min_pk::SecretKey::from_bytes(&*share.scalar_bytes).map_err(|_| {
            SigningBackendError::SigningFailed("invalid share scalar bytes".to_string())
        })?;

        let sig = sk.sign(signing_root, BLS_DST, &[]);
        Ok((self.own_index, sig.to_bytes()))
    }

    /// Coordinate a threshold signature: own partial + peer partials for `duty`.
    ///
    /// Peers receive the typed duty and derive the same signing root server-side
    /// (v2 `PeerSignerService`). `signing_root` is used for this node's own
    /// partial and for combined-signature verification — callers must pass the
    /// root that matches `duty`.
    #[tracing::instrument(
        name = "signer.dvt.coordinate",
        skip_all,
        fields(threshold, peers_contacted, partials_received, peers_responded, peers_failed,)
    )]
    pub async fn sign_with_duty(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
        duty: &PartialSignDuty,
    ) -> Result<[u8; 96], SigningBackendError> {
        self.coordinate(signing_root, pubkey, Some(duty)).await
    }

    async fn coordinate(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
        duty: Option<&PartialSignDuty>,
    ) -> Result<[u8; 96], SigningBackendError> {
        let key_info = self.keys.get(pubkey).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;

        if let Some(d) = duty {
            if matches!(d.ptc_duty_kind(), PtcDutyKind::Unparsable) {
                return Err(SigningBackendError::SigningFailed(
                    "PTC duty has unparsable object_root or fork_version".to_string(),
                ));
            }
        }

        let threshold = key_info.share.threshold;
        let span = tracing::Span::current();
        span.record("threshold", threshold);

        // 1. Produce own partial
        let own_partial = self.own_partial(signing_root, &key_info.share)?;

        let mut partials = vec![own_partial];

        // 2. Request partials from peers (concurrent)
        let coordination_start = Instant::now();

        if let Some(ref requester) = self.peer_requester {
            let duty = duty.ok_or_else(|| {
                SigningBackendError::SigningFailed(
                    "DVT peer partial requests require a typed duty payload \
                     (call sign_with_duty); the v2 PeerSignerService does not \
                     accept a raw signing root"
                        .to_string(),
                )
            })?;

            let peers_contacted = key_info.peer_addrs.len();
            span.record("peers_contacted", peers_contacted as u64);

            let mut join_set = tokio::task::JoinSet::new();
            let requester_index = self.own_index;

            for addr in &key_info.peer_addrs {
                let requester = Arc::clone(requester);
                let addr = addr.clone();
                let duty = duty.clone();
                let pk = *pubkey;
                let timeout = self.timeout;

                join_set.spawn(async move {
                    let peer_start = Instant::now();
                    let result = tokio::time::timeout(
                        timeout,
                        requester.request_partial(&addr, &duty, &pk, requester_index),
                    )
                    .await;
                    let peer_elapsed = peer_start.elapsed();
                    (addr, result, peer_elapsed)
                });
            }

            let mut peers_responded: u64 = 0;
            let mut peers_failed: u64 = 0;

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok((addr, Ok(Ok(partial)), elapsed)) => {
                        if let Some(ref m) = self.metrics {
                            m.partial_sign_duration_seconds
                                .with_label_values(&[&addr])
                                .observe(elapsed.as_secs_f64());
                        }
                        peers_responded += 1;
                        // 4.11c: drop PTC partials that disagree on planned
                        // root or fork_version so they cannot enter combine.
                        if !ptc_partial_agrees_with_session(duty, &partial) {
                            let (root, fork) = match partial.ptc_session {
                                Some(s) => (
                                    TruncatedRoot::new(&s.object_root).to_string(),
                                    TruncatedRoot::new(&s.fork_version).to_string(),
                                ),
                                None => ("unknown".to_string(), "unknown".to_string()),
                            };
                            tracing::warn!(
                                peer = %addr,
                                object_root = %root,
                                fork_version = %fork,
                                "excluding DVT PTC partial: planned root or fork_version disagrees with session"
                            );
                            continue;
                        }
                        partials.push((partial.share_index, partial.signature));
                    }
                    Ok((addr, Ok(Err(e)), elapsed)) => {
                        peers_failed += 1;
                        if let Some(ref m) = self.metrics {
                            m.partial_sign_duration_seconds
                                .with_label_values(&[&addr])
                                .observe(elapsed.as_secs_f64());
                        }
                        tracing::warn!(error = %e, "Peer partial request failed");
                    }
                    Ok((addr, Err(_), elapsed)) => {
                        peers_failed += 1;
                        if let Some(ref m) = self.metrics {
                            m.partial_sign_duration_seconds
                                .with_label_values(&[&addr])
                                .observe(elapsed.as_secs_f64());
                        }
                        tracing::warn!("Peer partial request timed out");
                    }
                    Err(e) => {
                        peers_failed += 1;
                        tracing::warn!(error = %e, "Peer partial task panicked");
                    }
                }
            }

            span.record("peers_responded", peers_responded);
            span.record("peers_failed", peers_failed);

            if let Some(ref m) = self.metrics {
                m.coordination_duration_seconds
                    .with_label_values(&[] as &[&str])
                    .observe(coordination_start.elapsed().as_secs_f64());
                m.peers_responded.with_label_values(&[] as &[&str]).observe(peers_responded as f64);
            }
        } else {
            span.record("peers_contacted", 0u64);
            span.record("peers_responded", 0u64);
            span.record("peers_failed", 0u64);
        }

        // 4.11c: ShareInfo has no per-share verification keys. Bind PTC
        // partials (including gRPC `None` session) to the coordinator
        // signing_root before Lagrange so a lying 96-byte share cannot
        // poison an otherwise threshold-met aggregate.
        if matches!(duty, Some(PartialSignDuty::PayloadAttestation { .. })) {
            let before = partials.len();
            partials =
                bind_ptc_partials_to_signing_root(&partials, threshold, pubkey, signing_root);
            if partials.len() < before {
                tracing::warn!(
                    dropped = before - partials.len(),
                    remaining = partials.len(),
                    "excluding DVT PTC partials that do not bind to the coordinator signing_root"
                );
            }
        }

        span.record("partials_received", partials.len() as u64);

        // 3. Check threshold
        if (partials.len() as u64) < threshold {
            if let Some(ref m) = self.metrics {
                m.threshold_failures_total.with_label_values(&[] as &[&str]).inc();
            }
            return Err(SigningBackendError::SigningFailed(format!(
                "insufficient partials: got {}, need {}",
                partials.len(),
                threshold
            )));
        }

        // 4. Combine via Lagrange interpolation
        let combined = combine_partial_signatures(&partials).map_err(|e| {
            SigningBackendError::SigningFailed(format!("failed to combine partials: {}", e))
        })?;

        // 5. Verify combined signature
        verify_combined_signature(&combined, pubkey, signing_root).map_err(|e| {
            SigningBackendError::SigningFailed(format!(
                "combined signature verification failed: {}",
                e
            ))
        })?;

        Ok(combined)
    }
}

#[async_trait]
impl SigningBackend for DvtSigner {
    /// Standalone / gate path: own partial only (no peer coordination).
    ///
    /// Peer-coordinated threshold signing requires a typed duty payload — use
    /// [`DvtSigner::sign_with_duty`]. Calling this with a peer requester and
    /// non-empty peer list returns a clear error rather than dialling the
    /// retired v1 raw-root peer RPC.
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError> {
        if self.peer_requester.is_some() {
            if let Some(key_info) = self.keys.get(pubkey) {
                if !key_info.peer_addrs.is_empty() {
                    return Err(SigningBackendError::SigningFailed(
                        "DVT peer partial requests require a typed duty payload \
                         (call sign_with_duty); the v2 PeerSignerService does not \
                         accept a raw signing root"
                            .to_string(),
                    ));
                }
            }
        }
        self.coordinate(signing_root, pubkey, None).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.keys.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;

    #[cfg(feature = "dvt")]
    mod dvt_tests {
        use super::*;
        use bls12_381_plus::Scalar;
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};
        use zeroize::Zeroizing;

        use crate::dvt::bridge::blst_sk_to_scalar;

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        /// Helper: split a secret key into Shamir shares.
        fn split_key(
            sk: &crypto::SecretKey,
            threshold: usize,
            total: usize,
        ) -> Vec<(u64, [u8; 32], [u8; 48])> {
            let pk = sk.public_key().to_bytes();
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
            let secret = blst_sk_to_scalar(&blst_sk).unwrap();

            let shares: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
                threshold,
                total,
                &IdentifierPrimeField(secret),
                OsRng,
            )
            .unwrap();

            shares
                .iter()
                .map(|share| {
                    use vsss_rs::Share;
                    let idx_field: &IdentifierPrimeField<Scalar> = share.identifier();
                    let val_field: &IdentifierPrimeField<Scalar> = share.value();
                    let idx_bytes = idx_field.0.to_be_bytes();
                    let idx = u64::from_be_bytes(idx_bytes[24..32].try_into().unwrap());
                    let val_bytes = val_field.0.to_be_bytes();
                    (idx, val_bytes, pk)
                })
                .collect()
        }

        fn make_share_info(
            idx: u64,
            scalar: [u8; 32],
            aggregate_pubkey: [u8; 48],
            threshold: u64,
            total: u64,
        ) -> ShareInfo {
            ShareInfo {
                index: idx,
                threshold,
                total,
                scalar_bytes: Zeroizing::new(scalar),
                aggregate_pubkey,
            }
        }

        // ---- Mock PeerRequester ----

        /// Mock that returns a pre-computed partial signature.
        struct MockPeerRequester {
            partials: HashMap<String, (u64, [u8; 96])>,
        }

        #[async_trait]
        impl PeerRequester for MockPeerRequester {
            async fn request_partial(
                &self,
                peer_addr: &str,
                _duty: &PartialSignDuty,
                _pubkey: &[u8; 48],
                _requester_index: u64,
            ) -> Result<PeerPartial, PeerRequestError> {
                self.partials
                    .get(peer_addr)
                    .copied()
                    .map(PeerPartial::from)
                    .ok_or_else(|| PeerRequestError::RequestFailed("unknown peer".to_string()))
            }
        }

        /// Mock that always fails.
        struct FailingPeerRequester;

        #[async_trait]
        impl PeerRequester for FailingPeerRequester {
            async fn request_partial(
                &self,
                _peer_addr: &str,
                _duty: &PartialSignDuty,
                _pubkey: &[u8; 48],
                _requester_index: u64,
            ) -> Result<PeerPartial, PeerRequestError> {
                Err(PeerRequestError::RequestFailed("peer down".to_string()))
            }
        }

        fn partial_sign(scalar_bytes: &[u8; 32], message: &[u8]) -> [u8; 96] {
            let sk = blst::min_pk::SecretKey::from_bytes(scalar_bytes).unwrap();
            let sig = sk.sign(message, BLS_DST, &[]);
            sig.to_bytes()
        }

        /// Dummy duty for unit tests that exercise mock peer requesters.
        /// Content is ignored by mocks; real peers would reject a malformed payload.
        fn dummy_duty() -> PartialSignDuty {
            PartialSignDuty::SyncCommittee {
                fork_info: ForkInfo {
                    previous_version: vec![0x04, 0x00, 0x00, 0x00],
                    current_version: vec![0x04, 0x00, 0x00, 0x00],
                    epoch: 0,
                    genesis_validators_root: vec![0x00; 32],
                },
                slot: 0,
                beacon_block_root: vec![0xAB; 32],
                fork_id: 4,
            }
        }

        const PTC_FORK: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
        const PTC_ROOT: [u8; 32] = [0xAA; 32];

        fn ptc_duty(object_root: [u8; 32], fork_version: [u8; 4]) -> PartialSignDuty {
            PartialSignDuty::PayloadAttestation {
                fork_info: ForkInfo {
                    previous_version: fork_version.to_vec(),
                    current_version: fork_version.to_vec(),
                    epoch: 0,
                    genesis_validators_root: vec![0x00; 32],
                },
                data: PayloadAttestationData {
                    beacon_block_root: vec![0x11; 32],
                    slot: 1,
                    payload_present: true,
                    blob_data_available: false,
                },
                fork_id: 7,
                object_root: object_root.to_vec(),
            }
        }

        /// Scripted peer that returns a partial tagged with an explicit PTC session.
        struct ScriptedPtcPeer {
            responses: HashMap<String, (u64, [u8; 96], PtcSessionIdentity)>,
        }

        #[async_trait]
        impl PeerRequester for ScriptedPtcPeer {
            async fn request_partial(
                &self,
                peer_addr: &str,
                _duty: &PartialSignDuty,
                _pubkey: &[u8; 48],
                _requester_index: u64,
            ) -> Result<PeerPartial, PeerRequestError> {
                let (share_index, signature, session) =
                    self.responses.get(peer_addr).copied().ok_or_else(|| {
                        PeerRequestError::RequestFailed("unknown peer".to_string())
                    })?;
                Ok(PeerPartial { share_index, signature, ptc_session: Some(session) })
            }
        }

        fn assert_threshold_failure(err: SigningBackendError) {
            let msg = err.to_string();
            assert!(
                msg.contains("insufficient partials"),
                "must fail threshold rather than emitting a signature, got: {msg}"
            );
            assert!(
                !msg.contains("verification failed"),
                "disagreeing partials must be excluded before combine, got: {msg}"
            );
        }

        // ---- RED/GREEN tests ----

        #[tokio::test]
        async fn test_sign_unknown_key_returns_key_not_found() {
            let signer = DvtSigner::new(vec![], 1, vec![], None, Duration::from_secs(5));
            let result = signer.sign(&[0u8; 32], &[0u8; 48]).await;
            assert!(matches!(result, Err(SigningBackendError::KeyNotFound(_))));
        }

        #[tokio::test]
        async fn test_public_keys_returns_aggregate_pubkeys() {
            let sk = crypto::SecretKey::generate();
            let shares = split_key(&sk, 2, 3);

            let share_info = make_share_info(shares[0].0, shares[0].1, shares[0].2, 2, 3);
            let signer =
                DvtSigner::new(vec![share_info], shares[0].0, vec![], None, Duration::from_secs(5));

            let keys = signer.public_keys();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], sk.public_key().to_bytes());
        }

        #[tokio::test]
        async fn test_own_partial_only_threshold_1() {
            // Shamir requires threshold >= 2, so we use a raw share with threshold=1
            // by directly using the secret key bytes as the "share"
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let own_idx = 1u64;

            let share_info = make_share_info(own_idx, sk.to_bytes(), pk, 1, 1);
            let signer =
                DvtSigner::new(vec![share_info], own_idx, vec![], None, Duration::from_secs(5));

            let signing_root = [42u8; 32];
            let sig = signer.sign(&signing_root, &pk).await.unwrap();

            // With threshold=1 and a single participant (index=1), Lagrange coefficient is 1,
            // so the combined sig equals the partial sig, which equals direct signing.
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        #[tokio::test]
        async fn test_sign_with_mock_peers_2_of_3() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [99u8; 32];

            let shares = split_key(&sk, 2, 3);

            // Node 0 is "us" (own_index = shares[0].0)
            // Node 1 is a mock peer
            let own_idx = shares[0].0;
            let peer_idx = shares[1].0;
            let peer_partial = partial_sign(&shares[1].1, &signing_root);

            let mut peer_partials = HashMap::new();
            peer_partials.insert("peer1:5000".to_string(), (peer_idx, peer_partial));

            let requester = Arc::new(MockPeerRequester { partials: peer_partials });

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(requester),
                Duration::from_secs(5),
            );

            let duty = dummy_duty();
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();

            // Verify: combined sig matches direct signing
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        #[tokio::test]
        async fn test_sign_with_mock_peers_3_of_5() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [77u8; 32];

            let shares = split_key(&sk, 3, 5);

            // Node 0 is us, nodes 1 and 2 are peers
            let own_idx = shares[0].0;

            let mut peer_partials = HashMap::new();
            for (i, share) in shares[1..=2].iter().enumerate() {
                let partial = partial_sign(&share.1, &signing_root);
                peer_partials.insert(format!("peer{}:5000", i + 1), (share.0, partial));
            }

            let requester = Arc::new(MockPeerRequester { partials: peer_partials });
            let peer_addrs: Vec<String> = (1..=2).map(|i| format!("peer{}:5000", i)).collect();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 3, 5);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                peer_addrs,
                Some(requester),
                Duration::from_secs(5),
            );

            let duty = dummy_duty();
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        #[tokio::test]
        async fn test_sign_insufficient_partials_fails() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [11u8; 32];

            let shares = split_key(&sk, 3, 5);
            let own_idx = shares[0].0;

            // All peers fail → only own partial (1 of 3 needed)
            let requester = Arc::new(FailingPeerRequester);
            let peer_addrs: Vec<String> = (1..=4).map(|i| format!("peer{}:5000", i)).collect();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 3, 5);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                peer_addrs,
                Some(requester),
                Duration::from_secs(5),
            );

            let duty = dummy_duty();
            let result = signer.sign_with_duty(&signing_root, &pk, &duty).await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(matches!(err, SigningBackendError::SigningFailed(_)));
            assert!(err.to_string().contains("insufficient partials"));
        }

        #[tokio::test]
        async fn test_sign_partial_peer_failure_still_succeeds() {
            // 2-of-3 scheme: one peer fails, one succeeds → still enough
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [55u8; 32];

            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            // Peer 1 succeeds, peer 2 (mapped to unknown addr) fails
            let peer_partial = partial_sign(&shares[1].1, &signing_root);
            let mut peer_partials = HashMap::new();
            peer_partials.insert("peer1:5000".to_string(), (shares[1].0, peer_partial));
            // "peer2:5000" is not in the map → will fail

            let requester = Arc::new(MockPeerRequester { partials: peer_partials });

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string(), "peer2:5000".to_string()],
                Some(requester),
                Duration::from_secs(5),
            );

            let duty = dummy_duty();
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        #[tokio::test]
        async fn test_sign_backend_path_requires_duty_when_peers_configured() {
            // SigningBackend::sign must not dial peers without a typed duty.
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let requester = Arc::new(FailingPeerRequester);
            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(requester),
                Duration::from_secs(5),
            );

            let err = signer.sign(&[0u8; 32], &pk).await.unwrap_err();
            assert!(
                err.to_string().contains("typed duty"),
                "error should mention typed duty: {err}"
            );
        }

        #[tokio::test]
        async fn test_sign_no_peer_requester_threshold_1() {
            // No peer requester, threshold=1 → succeeds with own partial only
            // Use raw key bytes directly since Shamir requires threshold >= 2
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let own_idx = 1u64;

            let share_info = make_share_info(own_idx, sk.to_bytes(), pk, 1, 3);
            let signer =
                DvtSigner::new(vec![share_info], own_idx, vec![], None, Duration::from_secs(5));

            let signing_root = [88u8; 32];
            let sig = signer.sign(&signing_root, &pk).await.unwrap();

            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        #[tokio::test]
        async fn test_sign_no_peer_requester_threshold_2_fails() {
            // No peer requester, threshold=2 → only own partial, not enough
            let sk = crypto::SecretKey::generate();
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;
            let pk = sk.public_key().to_bytes();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer =
                DvtSigner::new(vec![share_info], own_idx, vec![], None, Duration::from_secs(5));

            let result = signer.sign(&[0u8; 32], &pk).await;
            assert!(matches!(result, Err(SigningBackendError::SigningFailed(_))));
        }

        #[tokio::test]
        async fn test_multiple_keys() {
            // Use raw keys as threshold=1 shares (Shamir requires threshold >= 2)
            let sk1 = crypto::SecretKey::generate();
            let sk2 = crypto::SecretKey::generate();
            let pk1 = sk1.public_key().to_bytes();
            let pk2 = sk2.public_key().to_bytes();

            let share_info1 = make_share_info(1, sk1.to_bytes(), pk1, 1, 1);
            let share_info2 = make_share_info(1, sk2.to_bytes(), pk2, 1, 1);

            let signer = DvtSigner::new(
                vec![share_info1, share_info2],
                1,
                vec![],
                None,
                Duration::from_secs(5),
            );

            let keys = signer.public_keys();
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&pk1));
            assert!(keys.contains(&pk2));

            let root = [1u8; 32];
            let sig1 = signer.sign(&root, &pk1).await.unwrap();
            let sig2 = signer.sign(&root, &pk2).await.unwrap();
            assert_ne!(sig1, sig2);
        }

        #[tokio::test]
        async fn test_debug_format() {
            let signer = DvtSigner::new(vec![], 42, vec![], None, Duration::from_secs(5));
            let debug = format!("{:?}", signer);
            assert!(debug.contains("DvtSigner"));
            assert!(debug.contains("key_count: 0"));
            assert!(debug.contains("own_index: 42"));
        }

        #[tokio::test]
        async fn test_sign_updates_dvt_metrics_on_success() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [99u8; 32];

            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;
            let peer_idx = shares[1].0;
            let peer_partial = partial_sign(&shares[1].1, &signing_root);

            let mut peer_partials = HashMap::new();
            peer_partials.insert("peer1:5000".to_string(), (peer_idx, peer_partial));
            let requester = Arc::new(MockPeerRequester { partials: peer_partials });

            let metrics = Arc::new(crate::metrics::SignerMetrics::new());
            let dvt_metrics = Arc::new(metrics.dvt.clone());

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(requester),
                Duration::from_secs(5),
            )
            .with_metrics(dvt_metrics.clone());

            let duty = dummy_duty();
            signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();

            assert_eq!(
                dvt_metrics
                    .coordination_duration_seconds
                    .with_label_values(&[] as &[&str])
                    .get_sample_count(),
                1
            );
            assert_eq!(
                dvt_metrics.peers_responded.with_label_values(&[] as &[&str]).get_sample_count(),
                1
            );
            assert!(
                (dvt_metrics.peers_responded.with_label_values(&[] as &[&str]).get_sample_sum()
                    - 1.0)
                    .abs()
                    < 1e-9
            );
            assert_eq!(
                dvt_metrics
                    .partial_sign_duration_seconds
                    .with_label_values(&["peer1:5000"])
                    .get_sample_count(),
                1
            );
            assert_eq!(
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get(),
                0
            );
        }

        #[tokio::test]
        async fn test_sign_updates_dvt_metrics_on_threshold_failure() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 3, 5);
            let own_idx = shares[0].0;

            let requester = Arc::new(FailingPeerRequester);
            let peer_addrs: Vec<String> = (1..=4).map(|i| format!("peer{}:5000", i)).collect();

            let metrics = Arc::new(crate::metrics::SignerMetrics::new());
            let dvt_metrics = Arc::new(metrics.dvt.clone());

            let share_info = make_share_info(own_idx, shares[0].1, pk, 3, 5);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                peer_addrs,
                Some(requester),
                Duration::from_secs(5),
            )
            .with_metrics(dvt_metrics.clone());

            let duty = dummy_duty();
            let result = signer.sign_with_duty(&[11u8; 32], &pk, &duty).await;
            assert!(result.is_err());

            assert_eq!(
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get(),
                1
            );
            assert_eq!(
                dvt_metrics
                    .coordination_duration_seconds
                    .with_label_values(&[] as &[&str])
                    .get_sample_count(),
                1
            );
        }

        #[tokio::test]
        async fn test_peer_timeout() {
            // Test that a slow peer is correctly timed out
            struct SlowPeerRequester;

            #[async_trait]
            impl PeerRequester for SlowPeerRequester {
                async fn request_partial(
                    &self,
                    _peer_addr: &str,
                    _duty: &PartialSignDuty,
                    _pubkey: &[u8; 48],
                    _requester_index: u64,
                ) -> Result<PeerPartial, PeerRequestError> {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    unreachable!()
                }
            }

            let sk = crypto::SecretKey::generate();
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;
            let pk = sk.public_key().to_bytes();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["slow-peer:5000".to_string()],
                Some(Arc::new(SlowPeerRequester)),
                Duration::from_millis(50), // very short timeout
            );

            let duty = dummy_duty();
            let result = signer.sign_with_duty(&[0u8; 32], &pk, &duty).await;
            // Should fail because timeout → only 1 partial, need 2
            assert!(matches!(result, Err(SigningBackendError::SigningFailed(_))));
        }

        // ---- 4.11c PTC aggregation policy ----

        #[test]
        fn test_ptc_partial_agrees_when_root_and_fork_match() {
            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let partial = PeerPartial {
                share_index: 2,
                signature: [0u8; 96],
                ptc_session: Some(PtcSessionIdentity {
                    object_root: PTC_ROOT,
                    fork_version: PTC_FORK,
                }),
            };
            assert!(super::super::ptc_partial_agrees_with_session(&duty, &partial));
        }

        #[test]
        fn test_ptc_partial_disagrees_when_planned_root_differs() {
            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let partial = PeerPartial {
                share_index: 2,
                signature: [0u8; 96],
                ptc_session: Some(PtcSessionIdentity {
                    object_root: [0xBB; 32],
                    fork_version: PTC_FORK,
                }),
            };
            assert!(!super::super::ptc_partial_agrees_with_session(&duty, &partial));
        }

        #[test]
        fn test_ptc_partial_disagrees_on_fork_version_when_root_matches() {
            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let partial = PeerPartial {
                share_index: 2,
                signature: [0u8; 96],
                ptc_session: Some(PtcSessionIdentity {
                    object_root: PTC_ROOT,
                    fork_version: [0x06, 0x00, 0x00, 0x00],
                }),
            };
            assert!(!super::super::ptc_partial_agrees_with_session(&duty, &partial));
        }

        #[test]
        fn test_non_ptc_duty_is_not_filtered_by_ptc_session_policy() {
            let duty = dummy_duty();
            let partial = PeerPartial {
                share_index: 2,
                signature: [0u8; 96],
                ptc_session: Some(PtcSessionIdentity {
                    object_root: [0xFF; 32],
                    fork_version: [0xFF; 4],
                }),
            };
            assert!(super::super::ptc_partial_agrees_with_session(&duty, &partial));
        }

        #[test]
        fn test_ptc_none_session_kept_at_tag_filter() {
            // gRPC `None` must not be fail-closed-dropped at the tag layer.
            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let partial = PeerPartial { share_index: 2, signature: [0u8; 96], ptc_session: None };
            assert!(super::super::ptc_partial_agrees_with_session(&duty, &partial));
        }

        #[tokio::test]
        async fn test_ptc_mismatched_planned_root_excluded_fails_threshold() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let session_root = [0x11u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            // Peer signs a different message so accidental inclusion cannot
            // produce a session signature — it must be excluded first.
            let peer_sig = partial_sign(&shares[1].1, &[0xEEu8; 32]);
            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (
                    shares[1].0,
                    peer_sig,
                    PtcSessionIdentity { object_root: [0xBB; 32], fork_version: PTC_FORK },
                ),
            );

            let metrics = Arc::new(crate::metrics::SignerMetrics::new());
            let dvt_metrics = Arc::new(metrics.dvt.clone());
            let before =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(Arc::new(ScriptedPtcPeer { responses })),
                Duration::from_secs(5),
            )
            .with_metrics(dvt_metrics.clone());

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let err = signer.sign_with_duty(&session_root, &pk, &duty).await.unwrap_err();
            assert_threshold_failure(err);

            let after =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();
            assert_eq!(
                after.saturating_sub(before),
                1,
                "one disagreement-driven threshold failure"
            );
        }

        #[tokio::test]
        async fn test_ptc_mismatched_fork_version_excluded_when_root_matches() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let session_root = [0x22u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let peer_sig = partial_sign(&shares[1].1, &[0xEEu8; 32]);
            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (
                    shares[1].0,
                    peer_sig,
                    PtcSessionIdentity {
                        object_root: PTC_ROOT,
                        fork_version: [0x06, 0x00, 0x00, 0x00],
                    },
                ),
            );

            let metrics = Arc::new(crate::metrics::SignerMetrics::new());
            let dvt_metrics = Arc::new(metrics.dvt.clone());
            let before =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(Arc::new(ScriptedPtcPeer { responses })),
                Duration::from_secs(5),
            )
            .with_metrics(dvt_metrics.clone());

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let err = signer.sign_with_duty(&session_root, &pk, &duty).await.unwrap_err();
            assert_threshold_failure(err);

            let after =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();
            assert_eq!(
                after.saturating_sub(before),
                1,
                "one disagreement-driven threshold failure"
            );
        }

        #[tokio::test]
        async fn test_ptc_disagreement_increments_threshold_failures_once() {
            // Two disagreeing peers in one session: still one threshold failure.
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let session_root = [0x33u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (
                    shares[1].0,
                    partial_sign(&shares[1].1, &[0xE1u8; 32]),
                    PtcSessionIdentity { object_root: [0xBB; 32], fork_version: PTC_FORK },
                ),
            );
            responses.insert(
                "peer2:5000".to_string(),
                (
                    shares[2].0,
                    partial_sign(&shares[2].1, &[0xE2u8; 32]),
                    PtcSessionIdentity {
                        object_root: PTC_ROOT,
                        fork_version: [0x05, 0x00, 0x00, 0x00],
                    },
                ),
            );

            let metrics = Arc::new(crate::metrics::SignerMetrics::new());
            let dvt_metrics = Arc::new(metrics.dvt.clone());
            let before =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string(), "peer2:5000".to_string()],
                Some(Arc::new(ScriptedPtcPeer { responses })),
                Duration::from_secs(5),
            )
            .with_metrics(dvt_metrics.clone());

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let err = signer.sign_with_duty(&session_root, &pk, &duty).await.unwrap_err();
            assert_threshold_failure(err);

            let after =
                dvt_metrics.threshold_failures_total.with_label_values(&[] as &[&str]).get();
            assert_eq!(
                after.saturating_sub(before),
                1,
                "two excluded partials must still increment threshold_failures_total once"
            );
        }

        #[tokio::test]
        async fn test_ptc_agreeing_peer_still_aggregates() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0x44u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;
            let peer_sig = partial_sign(&shares[1].1, &signing_root);

            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (
                    shares[1].0,
                    peer_sig,
                    PtcSessionIdentity { object_root: PTC_ROOT, fork_version: PTC_FORK },
                ),
            );

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(Arc::new(ScriptedPtcPeer { responses })),
                Duration::from_secs(5),
            );

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();
            assert_eq!(sig, sk.sign(&signing_root).to_bytes());
        }

        #[tokio::test]
        async fn test_ptc_mixed_cluster_combines_agreeing_set() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0x55u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (
                    shares[1].0,
                    partial_sign(&shares[1].1, &signing_root),
                    PtcSessionIdentity { object_root: PTC_ROOT, fork_version: PTC_FORK },
                ),
            );
            responses.insert(
                "peer2:5000".to_string(),
                (
                    shares[2].0,
                    partial_sign(&shares[2].1, &[0xEEu8; 32]),
                    PtcSessionIdentity { object_root: [0xBB; 32], fork_version: PTC_FORK },
                ),
            );

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string(), "peer2:5000".to_string()],
                Some(Arc::new(ScriptedPtcPeer { responses })),
                Duration::from_secs(5),
            );

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap();
            assert_eq!(sig, sk.sign(&signing_root).to_bytes());
        }

        /// Mimics production `GrpcPeerRequester`: `ptc_session: None`.
        struct GrpcLikePtcPeer {
            responses: HashMap<String, (u64, [u8; 96])>,
        }

        #[async_trait]
        impl PeerRequester for GrpcLikePtcPeer {
            async fn request_partial(
                &self,
                peer_addr: &str,
                _duty: &PartialSignDuty,
                _pubkey: &[u8; 48],
                _requester_index: u64,
            ) -> Result<PeerPartial, PeerRequestError> {
                self.responses
                    .get(peer_addr)
                    .copied()
                    .map(PeerPartial::from)
                    .ok_or_else(|| PeerRequestError::RequestFailed("unknown peer".to_string()))
            }
        }

        /// Mimics the pre-fix gRPC stamp: tags the *request* session on every Ok.
        struct RequestStampedPtcPeer {
            responses: HashMap<String, (u64, [u8; 96])>,
        }

        #[async_trait]
        impl PeerRequester for RequestStampedPtcPeer {
            async fn request_partial(
                &self,
                peer_addr: &str,
                duty: &PartialSignDuty,
                _pubkey: &[u8; 48],
                _requester_index: u64,
            ) -> Result<PeerPartial, PeerRequestError> {
                let (share_index, signature) =
                    self.responses.get(peer_addr).copied().ok_or_else(|| {
                        PeerRequestError::RequestFailed("unknown peer".to_string())
                    })?;
                let ptc_session = match duty {
                    PartialSignDuty::PayloadAttestation { fork_info, object_root, .. } => {
                        match (
                            <[u8; 32]>::try_from(object_root.as_slice()),
                            <[u8; 4]>::try_from(fork_info.current_version.as_slice()),
                        ) {
                            (Ok(object_root), Ok(fork_version)) => {
                                Some(PtcSessionIdentity { object_root, fork_version })
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                Ok(PeerPartial { share_index, signature, ptc_session })
            }
        }

        #[tokio::test]
        async fn test_ptc_grpc_like_lying_peer_fails_threshold_not_verify() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0x66u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (shares[1].0, partial_sign(&shares[1].1, &[0xEEu8; 32])),
            );

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(Arc::new(GrpcLikePtcPeer { responses })),
                Duration::from_secs(5),
            );

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let err = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap_err();
            assert_threshold_failure(err);
        }

        #[tokio::test]
        async fn test_ptc_grpc_like_own_honest_lying_still_aggregates() {
            // n=3,t=2: a None-tagged liar must not poison Lagrange (DoS) and
            // must not emit a verify-failed error; the honest subset aggregates.
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0x77u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let mut responses = HashMap::new();
            responses.insert(
                "honest:5000".to_string(),
                (shares[1].0, partial_sign(&shares[1].1, &signing_root)),
            );
            responses.insert(
                "liar:5000".to_string(),
                (shares[2].0, partial_sign(&shares[2].1, &[0xEEu8; 32])),
            );

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["honest:5000".to_string(), "liar:5000".to_string()],
                Some(Arc::new(GrpcLikePtcPeer { responses })),
                Duration::from_secs(5),
            );

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let sig = signer.sign_with_duty(&signing_root, &pk, &duty).await.expect(
                "own+honest must still aggregate; liar must not take the verify-failed path",
            );
            assert_eq!(sig, sk.sign(&signing_root).to_bytes());
        }

        #[tokio::test]
        async fn test_ptc_request_stamped_liar_excluded_by_signing_root_bind() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0x88u8; 32];
            let shares = split_key(&sk, 2, 3);
            let own_idx = shares[0].0;

            let mut responses = HashMap::new();
            responses.insert(
                "peer1:5000".to_string(),
                (shares[1].0, partial_sign(&shares[1].1, &[0xEEu8; 32])),
            );

            let share_info = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![share_info],
                own_idx,
                vec!["peer1:5000".to_string()],
                Some(Arc::new(RequestStampedPtcPeer { responses })),
                Duration::from_secs(5),
            );

            let duty = ptc_duty(PTC_ROOT, PTC_FORK);
            let err = signer.sign_with_duty(&signing_root, &pk, &duty).await.unwrap_err();
            assert_threshold_failure(err);
        }

        #[tokio::test]
        async fn test_ptc_unparsable_object_root_fails_closed() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let share_info = make_share_info(1, sk.to_bytes(), pk, 1, 1);
            let signer = DvtSigner::new(vec![share_info], 1, vec![], None, Duration::from_secs(5));

            let mut duty = ptc_duty(PTC_ROOT, PTC_FORK);
            if let PartialSignDuty::PayloadAttestation { object_root, .. } = &mut duty {
                *object_root = vec![0xAA; 16];
            }
            let err = signer.sign_with_duty(&[0x11u8; 32], &pk, &duty).await.unwrap_err();
            assert!(
                err.to_string().contains("unparsable"),
                "unparsable PTC identity must fail closed, got: {err}"
            );
        }

        #[tokio::test]
        async fn test_ptc_unparsable_fork_version_fails_closed() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let share_info = make_share_info(1, sk.to_bytes(), pk, 1, 1);
            let signer = DvtSigner::new(vec![share_info], 1, vec![], None, Duration::from_secs(5));

            let mut duty = ptc_duty(PTC_ROOT, PTC_FORK);
            if let PartialSignDuty::PayloadAttestation { fork_info, .. } = &mut duty {
                fork_info.current_version = vec![0x07, 0x00, 0x00];
            }
            let err = signer.sign_with_duty(&[0x11u8; 32], &pk, &duty).await.unwrap_err();
            assert!(
                err.to_string().contains("unparsable"),
                "unparsable PTC fork_version must fail closed, got: {err}"
            );
        }
    }
}
