use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, warn};

use crate::backend::dvt::{PartialSignDuty, PeerPartial, PeerRequestError, PeerRequester};
use crate::dvt::allow_list::AllowedPeers;
use crate::grpc_tls::TlsConfig;
use crate::proto::signer_v2::peer_signer_service_client::PeerSignerServiceClient;
use crate::proto::signer_v2::{
    PartialSignAttestationDataRequest, PartialSignBeaconBlockRequest,
    PartialSignPayloadAttestationRequest, PartialSignResponse, PartialSignSyncCommitteeRequest,
};

#[derive(Error, Debug)]
pub enum PeerClientError {
    #[error("failed to connect to peer {addr}: {source}")]
    Connect { addr: String, source: tonic::transport::Error },

    #[error("failed to build TLS config: {0}")]
    Tls(String),

    #[error("peer {addr} RPC failed: {source}")]
    Rpc { addr: String, source: tonic::Status },

    #[error("peer {addr} timed out after {timeout:?}")]
    Timeout { addr: String, timeout: Duration },

    #[error("peer not found: {0}")]
    PeerNotFound(String),
}

/// Per-peer connection parameters for DVT gRPC connections.
///
/// Carries the TCP address **and** the TLS SNI hostname to pin.
///
/// # SNI pinning (ISSUE-4.1 / L-1 fix)
///
/// `sni_cn` is set as `domain_name` on the per-peer `ClientTlsConfig` clone
/// before dialling.  rustls then refuses any server certificate that is not
/// valid for `sni_cn`, preventing a certificate issued for peer-A from being
/// silently accepted when the client intended to connect to peer-B.
///
/// When TLS is disabled (insecure mode) `sni_cn` is ignored.
#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    /// TCP address of the peer (e.g. `"peer-a.cluster.local:50051"`).
    pub addr: String,
    /// Expected TLS SNI hostname — the peer's `peer_cn` from the allow-list.
    ///
    /// Must be a valid DNS name accepted by rustls `ServerName` (e.g.
    /// `"peer-a.cluster.local"`).  Leave empty only when TLS is disabled —
    /// under TLS, an empty `sni_cn` is rejected at startup by
    /// [`build_peer_connect_infos`] and at connect time by
    /// [`GrpcPeerRequester::connect`] (ISSUE-4.1 / L-1).
    pub sni_cn: String,
}

/// Build the per-peer connection info list, deriving SNI from the allow-list.
///
/// # Security invariant (ISSUE-4.1 / L-1)
///
/// When TLS is enabled:
/// - An allow-list **must** be provided; `None` is a startup error.
/// - Every address in `peer_addrs` must have a matching `[[peer]]` entry with
///   `addr =` set; missing entries are startup errors.
///
/// Both conditions are hard failures so there is **no silent fallback** to
/// un-pinned TLS.  An allow-list entry without an `addr` field that happens
/// to be absent from the addr lookup fails loudly rather than connecting
/// without hostname verification.
///
/// When TLS is disabled, SNI is not applicable; `sni_cn` is set to the empty
/// string and no allow-list lookup is performed.
pub fn build_peer_connect_infos(
    peer_addrs: &[String],
    allow_list: Option<&AllowedPeers>,
    tls_enabled: bool,
) -> Result<Vec<PeerConnectInfo>, String> {
    if !tls_enabled {
        return Ok(peer_addrs
            .iter()
            .map(|addr| PeerConnectInfo { addr: addr.clone(), sni_cn: String::new() })
            .collect());
    }

    let al = allow_list.ok_or_else(|| {
        "DVT with TLS requires --dvt-allowed-peers for per-peer SNI pinning \
         (ISSUE-4.1 / L-1). Provide a dvt-allowed-peers.toml with an `addr` \
         field for each peer."
            .to_string()
    })?;

    peer_addrs
        .iter()
        .map(|addr| {
            let peer = al.lookup_by_addr(addr).ok_or_else(|| {
                format!(
                    "DVT peer '{addr}' has no matching `addr = \"{addr}\"` entry in \
                     dvt-allowed-peers.toml; refusing to connect without SNI pinning \
                     (ISSUE-4.1 / L-1). Add the `addr` field to the [[peer]] entry \
                     that corresponds to this address."
                )
            })?;
            Ok(PeerConnectInfo { addr: addr.clone(), sni_cn: peer.peer_cn.clone() })
        })
        .collect()
}

/// gRPC-based peer requester that connects to DVT peers via v2 `PeerSignerService`.
pub struct GrpcPeerRequester {
    peers: Vec<(String, PeerSignerServiceClient<Channel>)>,
    timeout: Duration,
}

impl GrpcPeerRequester {
    /// Connect to a list of peers, pinning SNI per peer.
    ///
    /// If `tls_config` is provided, mTLS is used.  For each peer, the
    /// `domain_name` on the `ClientTlsConfig` is set to `peer.sni_cn` before
    /// dialling, so rustls verifies the server certificate against the
    /// peer-specific hostname.
    ///
    /// # SNI pinning (ISSUE-4.1 / L-1 fix)
    ///
    /// Without this pinning, any certificate valid under the shared CA would
    /// be accepted regardless of which peer it was issued to.  By setting
    /// `domain_name(sni_cn)` per peer, rustls refuses certificates that are
    /// not issued for the expected peer hostname.
    ///
    /// If `peer.sni_cn` is empty and TLS is active, `connect` returns
    /// `Err(PeerClientError::Tls)`.  Callers must go through
    /// [`build_peer_connect_infos`] to guarantee `sni_cn` is populated.
    pub async fn connect(
        peers: &[PeerConnectInfo],
        tls_config: Option<&TlsConfig>,
        timeout: Duration,
    ) -> Result<Self, PeerClientError> {
        let client_tls = match tls_config {
            Some(tls) => {
                Some(tls.to_client_tls_config().map_err(|e| PeerClientError::Tls(e.to_string()))?)
            }
            None => None,
        };

        let mut connected = Vec::with_capacity(peers.len());

        for peer in peers {
            let scheme = if client_tls.is_some() { "https" } else { "http" };
            let uri = format!("{}://{}", scheme, peer.addr);
            let mut endpoint = Endpoint::from_shared(uri)
                .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?
                .timeout(timeout);

            if let Some(ref tls) = client_tls {
                // L-1 SNI pinning: set domain_name per peer so rustls verifies
                // the server certificate is issued for this specific peer's
                // expected hostname.  Without this, any cert valid under the
                // shared CA passes for any peer — a silent impersonation path.
                //
                // Empty sni_cn is a hard error here: callers MUST go through
                // `build_peer_connect_infos` which enforces allow-list coverage
                // before any TLS handshake is attempted.
                if peer.sni_cn.is_empty() {
                    return Err(PeerClientError::Tls(format!(
                        "peer '{}' has no SNI hostname; refusing TLS handshake without \
                         certificate hostname pinning (ISSUE-4.1 / L-1). Call \
                         build_peer_connect_infos() to derive SNI from the allow-list.",
                        peer.addr
                    )));
                }
                debug!(addr = %peer.addr, sni = %peer.sni_cn, "SNI pinned for DVT peer");
                let pinned_tls = tls.clone().domain_name(&peer.sni_cn);
                endpoint = endpoint
                    .tls_config(pinned_tls)
                    .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?;
            }

            let channel = endpoint
                .connect()
                .await
                .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?;

            connected.push((peer.addr.clone(), PeerSignerServiceClient::new(channel)));
        }

        Ok(Self { peers: connected, timeout })
    }

    /// Return the list of connected peer addresses.
    pub fn peer_addrs(&self) -> Vec<&str> {
        self.peers
            .iter()
            .map(|(addr, _client): &(String, PeerSignerServiceClient<Channel>)| addr.as_str())
            .collect()
    }

    /// Dispatch a typed partial-sign RPC for `duty` on `client`.
    async fn partial_sign_rpc(
        client: &mut PeerSignerServiceClient<Channel>,
        duty: &PartialSignDuty,
        pubkey: &[u8; 48],
        requester_index: u64,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        match duty {
            PartialSignDuty::BeaconBlock { fork_info, block_ssz, fork_id } => {
                let req = PartialSignBeaconBlockRequest {
                    requester_index,
                    pubkey: pubkey.to_vec(),
                    fork_info: Some(fork_info.clone()),
                    block_ssz: block_ssz.clone(),
                    fork_id: *fork_id,
                };
                client.partial_sign_beacon_block(req).await
            }
            PartialSignDuty::AttestationData { fork_info, data, fork_id } => {
                let req = PartialSignAttestationDataRequest {
                    requester_index,
                    pubkey: pubkey.to_vec(),
                    fork_info: Some(fork_info.clone()),
                    data: Some(data.clone()),
                    fork_id: *fork_id,
                };
                client.partial_sign_attestation_data(req).await
            }
            PartialSignDuty::SyncCommittee { fork_info, slot, beacon_block_root, fork_id } => {
                let req = PartialSignSyncCommitteeRequest {
                    requester_index,
                    pubkey: pubkey.to_vec(),
                    fork_info: Some(fork_info.clone()),
                    slot: *slot,
                    beacon_block_root: beacon_block_root.clone(),
                    fork_id: *fork_id,
                };
                client.partial_sign_sync_committee(req).await
            }
            PartialSignDuty::PayloadAttestation { fork_info, data, fork_id, object_root } => {
                let req = PartialSignPayloadAttestationRequest {
                    requester_index,
                    pubkey: pubkey.to_vec(),
                    fork_info: Some(fork_info.clone()),
                    data: Some(data.clone()),
                    fork_id: *fork_id,
                    object_root: object_root.clone(),
                };
                client.partial_sign_payload_attestation(req).await
            }
        }
    }

    /// Request partial signatures from all connected peers concurrently.
    ///
    /// Returns a vector of `(share_index, partial_signature)` for successful responses.
    /// Peers that fail or timeout are logged and skipped.
    ///
    /// **Unused by `DvtSigner`.** Aggregation (including the 4.11c PTC bind to
    /// the coordinator signing root) lives in `DvtSigner::coordinate`. This
    /// helper does not apply that filter; do not combine its results for PTC.
    pub async fn request_all_partials(
        &self,
        duty: &PartialSignDuty,
        pubkey: &[u8; 48],
        requester_index: u64,
    ) -> Vec<(u64, [u8; 96])> {
        let mut handles = tokio::task::JoinSet::new();

        for (addr, client) in &self.peers {
            let addr: String = addr.clone();
            let mut client: PeerSignerServiceClient<Channel> = client.clone();
            let duty = duty.clone();
            let pubkey = *pubkey;
            let timeout = self.timeout;

            handles.spawn(async move {
                let result: Result<tonic::Response<PartialSignResponse>, tonic::Status> =
                    match tokio::time::timeout(
                        timeout,
                        Self::partial_sign_rpc(&mut client, &duty, &pubkey, requester_index),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => return Err(PeerClientError::Timeout { addr, timeout }),
                    };

                match result {
                    Ok(resp) => {
                        let inner = resp.into_inner();
                        let sig: [u8; 96] = inner.partial_signature.try_into().map_err(|_| {
                            PeerClientError::Rpc {
                                addr: addr.clone(),
                                source: tonic::Status::internal("invalid signature length"),
                            }
                        })?;
                        Ok((addr, inner.share_index, sig))
                    }
                    Err(status) => Err(PeerClientError::Rpc { addr, source: status }),
                }
            });
        }

        let mut results = Vec::new();
        while let Some(join_result) = handles.join_next().await {
            match join_result {
                Ok(Ok((_addr, share_index, sig))) => {
                    results.push((share_index, sig));
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "peer partial sign request failed");
                }
                Err(e) => {
                    warn!(error = %e, "peer task panicked");
                }
            }
        }

        results
    }
}

#[async_trait]
impl PeerRequester for GrpcPeerRequester {
    async fn request_partial(
        &self,
        peer_addr: &str,
        duty: &PartialSignDuty,
        pubkey: &[u8; 48],
        requester_index: u64,
    ) -> Result<PeerPartial, PeerRequestError> {
        let (_, client) =
            self.peers.iter().find(|(addr, _)| addr == peer_addr).ok_or_else(|| {
                PeerRequestError::RequestFailed(format!("peer not found: {}", peer_addr))
            })?;

        let mut client = client.clone();

        let result = tokio::time::timeout(
            self.timeout,
            Self::partial_sign_rpc(&mut client, duty, pubkey, requester_index),
        )
        .await
        .map_err(|_| PeerRequestError::Timeout)?
        .map_err(|e| PeerRequestError::RequestFailed(format!("RPC failed: {}", e)))?;

        let inner = result.into_inner();
        let sig: [u8; 96] = inner.partial_signature.try_into().map_err(|_| {
            PeerRequestError::RequestFailed("invalid signature length from peer".to_string())
        })?;

        // gRPC `PartialSignResponse` has no session fields. Do not stamp the
        // request session onto the response (that made the 4.11c tag filter a
        // tautology). `ptc_session: None`; `DvtSigner::coordinate` binds the
        // 96-byte share to the coordinator signing root.
        Ok(PeerPartial { share_index: inner.share_index, signature: sig, ptc_session: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_client_error_display_timeout() {
        let err = PeerClientError::Timeout {
            addr: "127.0.0.1:50053".to_string(),
            timeout: Duration::from_millis(2000),
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:50053"));
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn test_peer_client_error_display_tls() {
        let err = PeerClientError::Tls("bad cert".to_string());
        assert!(err.to_string().contains("TLS"));
    }

    #[test]
    fn test_peer_client_error_display_rpc() {
        let err = PeerClientError::Rpc {
            addr: "peer1:50053".to_string(),
            source: tonic::Status::not_found("key missing"),
        };
        let msg = err.to_string();
        assert!(msg.contains("peer1:50053"));
        assert!(msg.contains("RPC failed"));
    }

    #[test]
    fn test_peer_client_error_display_not_found() {
        let err = PeerClientError::PeerNotFound("unknown:1234".to_string());
        assert!(err.to_string().contains("unknown:1234"));
    }
}
