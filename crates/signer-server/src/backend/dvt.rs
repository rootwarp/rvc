use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::info;

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
    ) -> Result<(u64, [u8; 96]), PeerRequestError>;
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
                        partials.push(partial);
                        peers_responded += 1;
                        if let Some(ref m) = self.metrics {
                            m.partial_sign_duration_seconds
                                .with_label_values(&[&addr])
                                .observe(elapsed.as_secs_f64());
                        }
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
            ) -> Result<(u64, [u8; 96]), PeerRequestError> {
                self.partials
                    .get(peer_addr)
                    .cloned()
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
            ) -> Result<(u64, [u8; 96]), PeerRequestError> {
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
                ) -> Result<(u64, [u8; 96]), PeerRequestError> {
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
    }
}
