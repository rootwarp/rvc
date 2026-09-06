//! DVT `PeerSignerService` v2 implementation.
//!
//! This module provides the gRPC server implementation for the typed
//! `PeerSignerService` RPCs defined in `proto/signer.v2.proto`.
//!
//! # Security: `requester_index ↔ peer_cn` enforcement (C-3)
//!
//! Each `Partial*` request carries a `requester_index` field (field 1). The
//! server enforces that this value matches the `share_index` in the DVT
//! allow-list entry keyed by the peer's mTLS CN. Without this check, any
//! peer with a valid client certificate could claim any share index,
//! bypassing the cryptographic binding between identity and share position.
//!
//! # Pubkey-scoped slashing (Issue 2.5)
//!
//! The `PubkeyScopedDb` is scoped by `(pubkey, genesis_validators_root)` only.
//! A second request from any peer for `(pubkey-X, slot=42)` with a different root
//! is rejected (cross-CN double-sign protection).  The peer CN is passed to
//! `PubkeyScopedDb::new` for audit-log emission only — it does not affect the
//! slashing check.
//!
//! # spawn_blocking + block_on
//!
//! `StagedBlock<'_>` and `StagedAttestation<'_>` hold a
//! `parking_lot::MutexGuard` (`!Send`).  Holding them across an `.await` is
//! a compile error.  The same `spawn_blocking + Handle::block_on` pattern
//! used in `service.rs` is applied here.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::Span;

use crate::audit;
use crate::dvt::allow_list::AllowedPeers;
use crate::dvt::types::ShareInfo;
use slashing::PubkeyScopedDb;

// V2 proto imports
use crate::proto::signer_v2::peer_signer_service_server::PeerSignerService;
use crate::proto::signer_v2::{
    PartialSignAttestationDataRequest, PartialSignBeaconBlockRequest,
    PartialSignPayloadAttestationRequest, PartialSignResponse, PartialSignSyncCommitteeRequest,
};

use slashing::SlashingDb;

use crate::grpc_common::{
    decode_attestation_data, decode_beacon_block, decode_fork_info, validate_pubkey,
    validate_root32,
};
use crate::sign_plan::{plan_sign, PlanInput};

// ─────────────────────────────────────────────────────────────────────────────
// PeerSignerServiceImpl (v2)
// ─────────────────────────────────────────────────────────────────────────────

/// DVT `PeerSignerService` implementation for the v2 typed RPCs.
///
/// Enforces:
/// 1. The peer's mTLS CN is on the allow-list.
/// 2. The request's `requester_index` matches the CN's `share_index` in the
///    allow-list (closes C-3).
/// 3. EIP-3076 slashing protection for block and attestation RPCs, scoped
///    per peer CN (each peer has its own watermark namespace).
pub struct PeerSignerServiceImpl {
    /// Loaded share info, keyed by aggregate public key.
    shares: Arc<std::collections::HashMap<[u8; 48], ShareInfo>>,
    /// DVT allow-list loaded at startup from `dvt-allowed-peers.toml`.
    allow_list: Arc<AllowedPeers>,
    /// Slashing DB — `None` when slashing protection is disabled.
    slashing_db: Option<Arc<SlashingDb>>,
}

impl PeerSignerServiceImpl {
    /// Create a new service.
    ///
    /// `slashing_db` must be `Some` in production; pass `None` only when both
    /// `--disable-slashing-protection` and `RVC_ALLOW_INSECURE=true` are set.
    pub fn new(
        shares: Arc<std::collections::HashMap<[u8; 48], ShareInfo>>,
        allow_list: Arc<AllowedPeers>,
        slashing_db: Option<Arc<SlashingDb>>,
    ) -> Self {
        Self { shares, allow_list, slashing_db }
    }

    #[allow(clippy::result_large_err)]
    fn require_db(&self) -> Result<&Arc<SlashingDb>, Status> {
        self.slashing_db.as_ref().ok_or_else(|| {
            Status::internal(
                "slashing protection database is not configured; \
                 restart with a valid --data-dir or --disable-slashing-protection + \
                 RVC_ALLOW_INSECURE=true",
            )
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Field validators + proto decode live in `crate::grpc_common` (shared with SignerService).

fn slashing_err(e: slashing::SlashingError) -> Status {
    use slashing::SlashingError;
    match e {
        SlashingError::SlashableBlock(_) | SlashingError::SlashableAttestation(_) => {
            // Terminal rejection log for the DVT partial-sign path: the slashing
            // crate logs the decision at debug, so this is the one record at the
            // layer that treats the rejection as terminal. It MUST be `error!`:
            // rvc-signer's default EnvFilter is ERROR-only (RUST_LOG unset), so a
            // warn! here would be dropped and the rejection would go unlogged.
            tracing::error!(error = %e, "DVT partial sign rejected by slashing protection");
            Status::failed_precondition(format!("slashing protection violation: {e}"))
        }
        _ => Status::failed_precondition(format!("slashing check failed: {e}")),
    }
}

fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

fn root_hex(root: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(root))
}

/// Sign the given `signing_root` using the share's secret key.
#[allow(clippy::result_large_err)]
fn partial_sign_with_share(signing_root: &[u8; 32], share: &ShareInfo) -> Result<[u8; 96], Status> {
    const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sk = blst::min_pk::SecretKey::from_bytes(&*share.scalar_bytes)
        .map_err(|_| Status::internal("invalid share scalar bytes"))?;
    let sig = sk.sign(signing_root, BLS_DST, &[]);
    Ok(sig.to_bytes())
}

/// Authenticate the peer and validate `requester_index`.
///
/// Returns the peer's allow-list entry on success.
#[allow(clippy::result_large_err)]
fn authenticate_peer<'a>(
    allow_list: &'a AllowedPeers,
    peer_cn: &str,
    requester_index: u64,
) -> Result<&'a crate::dvt::allow_list::AllowedPeer, Status> {
    let allowed = allow_list.lookup_by_cn(peer_cn).ok_or_else(|| {
        Status::unauthenticated(format!("peer CN '{peer_cn}' is not on the DVT allow-list"))
    })?;

    if allowed.share_index != requester_index {
        return Err(Status::unauthenticated(format!(
            "requester_index mismatch: allow-list assigns {peer_cn} share_index={}, \
             but request carries requester_index={requester_index}",
            allowed.share_index
        )));
    }

    Ok(allowed)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerSignerService v2 impl
// ─────────────────────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl PeerSignerService for PeerSignerServiceImpl {
    // ── PartialSignBeaconBlock ────────────────────────────────────────────────

    /// `signer.v2.PeerSignerService/PartialSignBeaconBlock` (ARCH-7i).
    ///
    /// Enforcement: `GateRouting::SlashingScopedShare` via `stage_block`.
    /// Not `SigningGate`-routed.
    #[tracing::instrument(
        name = "signer.dvt.partial_sign_beacon_block",
        skip_all,
        fields(pubkey, slot, peer_cn, share_index)
    )]
    #[allow(clippy::result_large_err)]
    async fn partial_sign_beacon_block(
        &self,
        req: Request<PartialSignBeaconBlockRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        // Extract Arc clones at the start so all borrows of `self` end here.
        let allow_list = Arc::clone(&self.allow_list);
        let shares = Arc::clone(&self.shares);
        let db_arc: Arc<SlashingDb> = Arc::clone(self.require_db()?);

        let peer_cn = audit::cn::extract_client_cn(&req);
        Span::current().record("peer_cn", peer_cn.as_str());

        let r = req.into_inner();

        // 1. Authenticate peer: CN on allow-list AND requester_index matches.
        let share_index = {
            let allowed = authenticate_peer(&allow_list, &peer_cn, r.requester_index)?;
            allowed.share_index
        };
        Span::current().record("share_index", share_index);

        // 2. Validate fields.
        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;

        // 3. Decode block and compute signing root via shared plan engine.
        let block = decode_beacon_block(&r.block_ssz, r.fork_id)?;
        let slot = block.slot;
        Span::current().record("slot", slot);

        // SEC-6c: typed body leaf — malformed Electra body SSZ must error, not panic.
        let object_root = block.try_tree_hash_root().map_err(|e| {
            Status::invalid_argument(format!("invalid block body for tree_hash_root: {e}"))
        })?;
        let plan =
            plan_sign(&PlanInput::Block { object_root: object_root.0, slot, fork_version, gvr });
        let signing_root = plan.signing_root;
        let signing_root_hex = Some(root_hex(&signing_root));

        // 4. Get share — clone to own, then explicitly drop the Arc<HashMap> so the
        // borrow checker sees the borrow of `shares` is finished before spawn_blocking.
        let share =
            shares.get(&pubkey).ok_or_else(|| Status::not_found("unknown public key"))?.clone();
        drop(shares);

        // 5. Stage → sign → commit.
        let scoped = PubkeyScopedDb::new(db_arc, peer_cn.clone(), gvr);
        let peer_cn_for_log = peer_cn;

        // spawn_blocking is required because StagedBlock holds a !Send MutexGuard.
        let sig = tokio::task::spawn_blocking(move || -> Result<[u8; 96], Status> {
            let (staged, audit) = scoped
                .stage_block(&pubkey_hex_str, slot, signing_root_hex)
                .map_err(slashing_err)?;

            let sign_result = partial_sign_with_share(&signing_root, &share);

            match sign_result {
                Ok(sig) => {
                    // Emit after commit attempt regardless of success (matches StagedRow bridge).
                    let commit_result = staged
                        .commit()
                        .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")));
                    audit.emit();
                    commit_result?;
                    Ok(sig)
                }
                Err(e) => {
                    staged.discard();
                    audit.emit();
                    Err(e)
                }
            }
        })
        .await
        .map_err(|join_err| {
            Status::internal(format!(
                "partial_sign_beacon_block blocking task panicked: {join_err}"
            ))
        })??;

        tracing::info!(
            pubkey = %pubkey_hex(&pubkey),
            slot,
            peer_cn = %peer_cn_for_log,
            share_index,
            "partial_sign_beacon_block: success"
        );
        Ok(Response::new(PartialSignResponse { partial_signature: sig.to_vec(), share_index }))
    }

    // ── PartialSignAttestationData ────────────────────────────────────────────

    /// `signer.v2.PeerSignerService/PartialSignAttestationData` (ARCH-7i).
    ///
    /// Enforcement: `GateRouting::SlashingScopedShare` via `stage_attestation`.
    /// Not `SigningGate`-routed.
    #[tracing::instrument(
        name = "signer.dvt.partial_sign_attestation_data",
        skip_all,
        fields(pubkey, source_epoch, target_epoch, peer_cn, share_index)
    )]
    #[allow(clippy::result_large_err)]
    async fn partial_sign_attestation_data(
        &self,
        req: Request<PartialSignAttestationDataRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        // Extract Arc clones at start so all borrows of `self` end here.
        let allow_list = Arc::clone(&self.allow_list);
        let shares = Arc::clone(&self.shares);
        let db_arc: Arc<SlashingDb> = Arc::clone(self.require_db()?);

        let peer_cn = audit::cn::extract_client_cn(&req);
        Span::current().record("peer_cn", peer_cn.as_str());

        let r = req.into_inner();

        // 1. Authenticate.
        let share_index = {
            let allowed = authenticate_peer(&allow_list, &peer_cn, r.requester_index)?;
            allowed.share_index
        };
        Span::current().record("share_index", share_index);

        // 2. Validate.
        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;

        // 3. Decode AttestationData from proto fields; plan via shared engine.
        let (att_data, source_epoch, target_epoch) = decode_attestation_data(r.data)?;
        Span::current().record("source_epoch", source_epoch);
        Span::current().record("target_epoch", target_epoch);

        let plan = plan_sign(&PlanInput::Attestation { data: att_data, fork_version, gvr });
        let signing_root = plan.signing_root;
        let signing_root_hex = Some(root_hex(&signing_root));

        // 4. Get share — clone to own, explicitly drop Arc<HashMap>.
        let share =
            shares.get(&pubkey).ok_or_else(|| Status::not_found("unknown public key"))?.clone();
        drop(shares);

        // 5. Stage → sign → commit.
        let scoped = PubkeyScopedDb::new(db_arc, peer_cn.clone(), gvr);
        let peer_cn_for_log = peer_cn;

        // spawn_blocking is required because StagedAttestation holds a !Send MutexGuard.
        let sig = tokio::task::spawn_blocking(move || -> Result<[u8; 96], Status> {
            let (staged, audit) = scoped
                .stage_attestation(&pubkey_hex_str, source_epoch, target_epoch, signing_root_hex)
                .map_err(slashing_err)?;

            let sign_result = partial_sign_with_share(&signing_root, &share);

            match sign_result {
                Ok(sig) => {
                    // Emit after commit attempt regardless of success (matches StagedRow bridge).
                    let commit_result = staged
                        .commit()
                        .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")));
                    audit.emit();
                    commit_result?;
                    Ok(sig)
                }
                Err(e) => {
                    staged.discard();
                    audit.emit();
                    Err(e)
                }
            }
        })
        .await
        .map_err(|join_err| {
            Status::internal(format!(
                "partial_sign_attestation_data blocking task panicked: {join_err}"
            ))
        })??;

        tracing::info!(
            pubkey = %pubkey_hex(&pubkey),
            source_epoch,
            target_epoch,
            peer_cn = %peer_cn_for_log,
            share_index,
            "partial_sign_attestation_data: success"
        );
        Ok(Response::new(PartialSignResponse { partial_signature: sig.to_vec(), share_index }))
    }

    // ── PartialSignSyncCommittee ──────────────────────────────────────────────

    /// `signer.v2.PeerSignerService/PartialSignSyncCommittee` (ARCH-7j).
    ///
    /// Enforcement: `GateRouting::NonSlashable` (FR-P0-3 / DOMAIN_SYNC_COMMITTEE).
    /// No `SLASHING_STAGE_METHODS` member — sync is not slashable.
    #[tracing::instrument(
        name = "signer.dvt.partial_sign_sync_committee",
        skip_all,
        fields(pubkey, slot, peer_cn, share_index)
    )]
    async fn partial_sign_sync_committee(
        &self,
        req: Request<PartialSignSyncCommitteeRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        // Extract Arc clones at start so all borrows of `self` end here.
        let allow_list = Arc::clone(&self.allow_list);
        let shares = Arc::clone(&self.shares);

        let peer_cn = audit::cn::extract_client_cn(&req);
        Span::current().record("peer_cn", peer_cn.as_str());

        let r = req.into_inner();

        // 1. Authenticate.
        let share_index = {
            let allowed = authenticate_peer(&allow_list, &peer_cn, r.requester_index)?;
            allowed.share_index
        };
        Span::current().record("share_index", share_index);

        // 2. Validate.
        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;

        let slot = r.slot;
        let beacon_block_root = validate_root32(&r.beacon_block_root, "beacon_block_root")?;
        Span::current().record("slot", slot);

        // 3. Signing root via shared plan engine (DOMAIN_SYNC_COMMITTEE).
        let plan =
            plan_sign(&PlanInput::SyncCommitteeMessage { beacon_block_root, fork_version, gvr });
        let signing_root = plan.signing_root;

        // 4. Get share — clone to own, explicitly drop Arc<HashMap>.
        let share =
            shares.get(&pubkey).ok_or_else(|| Status::not_found("unknown public key"))?.clone();
        drop(shares);

        // 5. Sign directly — no slashing check for sync committee (FR-P0-3).
        let sig = partial_sign_with_share(&signing_root, &share)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            peer_cn = %peer_cn,
            share_index,
            "partial_sign_sync_committee: success"
        );
        Ok(Response::new(PartialSignResponse { partial_signature: sig.to_vec(), share_index }))
    }

    // ── PartialSignPayloadAttestation ─────────────────────────────────────────

    /// Wire stub for `PeerSignerService/PartialSignPayloadAttestation` (4.11a).
    /// Handler logic is 4.11b.
    async fn partial_sign_payload_attestation(
        &self,
        _req: Request<PartialSignPayloadAttestationRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        Err(Status::unimplemented("PartialSignPayloadAttestation (issue 4.11b)"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use std::collections::HashMap;
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::*;
    use crate::dvt::allow_list::{AllowedPeer, AllowedPeers};
    use crate::dvt::types::ShareInfo;

    /// Issue 2.7: the DVT terminal slashing-rejection log MUST be `error!` so it
    /// survives rvc-signer's default ERROR-only EnvFilter (RUST_LOG unset). A
    /// `warn!` here would be dropped and the rejection would go unlogged.
    #[test]
    #[tracing_test::traced_test]
    fn test_dvt_slashing_rejection_logged_at_error() {
        let _status = slashing_err(slashing::SlashingError::SlashableBlock(
            slashing::BlockSlashingViolation::DoubleBlockProposal { slot: 42 },
        ));
        logs_assert(|lines: &[&str]| {
            let line = lines
                .iter()
                .find(|l| l.contains("DVT partial sign rejected by slashing protection"))
                .ok_or_else(|| "no DVT slashing-rejection log captured".to_string())?;
            if !line.contains("ERROR") {
                return Err(format!(
                    "DVT rejection must be ERROR to survive the default filter: {line}"
                ));
            }
            Ok(())
        });
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
                .map(|(cn, idx)| AllowedPeer {
                    peer_cn: cn.to_string(),
                    share_index: idx,
                    addr: None,
                })
                .collect(),
        })
    }

    fn make_db() -> Arc<SlashingDb> {
        // In-memory: avoids SEC-3 CorruptOrEmpty on 0-byte NamedTempFile paths.
        Arc::new(SlashingDb::open_in_memory().expect("open test DB"))
    }

    fn make_service(
        shares: Vec<([u8; 48], ShareInfo)>,
        allow_list: Arc<AllowedPeers>,
        db: Option<Arc<SlashingDb>>,
    ) -> PeerSignerServiceImpl {
        let map: HashMap<[u8; 48], ShareInfo> = shares.into_iter().collect();
        PeerSignerServiceImpl::new(Arc::new(map), allow_list, db)
    }

    fn sample_fork_info() -> crate::proto::signer_v2::ForkInfo {
        crate::proto::signer_v2::ForkInfo {
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

    fn sample_attestation_data_proto() -> crate::proto::signer_v2::AttestationData {
        crate::proto::signer_v2::AttestationData {
            slot: 10,
            index: 0,
            beacon_block_root: vec![0xAB; 32],
            source: Some(crate::proto::signer_v2::Checkpoint { epoch: 1, root: vec![0x01; 32] }),
            target: Some(crate::proto::signer_v2::Checkpoint { epoch: 2, root: vec![0x02; 32] }),
        }
    }

    // ── authenticate_peer unit tests ─────────────────────────────────────────

    #[test]
    fn test_authenticate_peer_success() {
        let al = make_allow_list(vec![("peer-A", 1)]);
        let result = authenticate_peer(&al, "peer-A", 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().share_index, 1);
    }

    #[test]
    fn test_authenticate_peer_cn_not_on_list() {
        let al = make_allow_list(vec![("peer-A", 1)]);
        let err = authenticate_peer(&al, "peer-X", 1).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("not on the DVT allow-list"));
    }

    #[test]
    fn test_authenticate_peer_requester_index_mismatch() {
        let al = make_allow_list(vec![("peer-A", 1)]);
        let err = authenticate_peer(&al, "peer-A", 2).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("mismatch"));
    }

    // ── partial_sign_beacon_block unit tests ──────────────────────────────────

    #[tokio::test]
    async fn test_partial_sign_block_happy_path() {
        // Without TLS, extract_client_cn returns "unknown".
        let (pk, share) = make_share(1);
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share)], al, Some(db));

        let req = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });

        let resp = svc.partial_sign_beacon_block(req).await.unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.partial_signature.len(), 96);
        assert_eq!(inner.share_index, 1);
    }

    #[tokio::test]
    async fn test_partial_sign_block_unauth_cn_not_on_allow_list() {
        let (pk, share) = make_share(1);
        let al = make_allow_list(vec![("peer-A", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share)], al, Some(db));

        let req = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        // CN extracted from the request without TLS info → "unknown"
        let err = svc.partial_sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn test_partial_sign_block_unauth_requester_index_mismatch() {
        let (pk, share) = make_share(1);
        // TLS info absent → CN = "unknown"; allow-list says "unknown" → 1
        // but request sends requester_index=2 → mismatch
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share)], al, Some(db));

        let req = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 2, // mismatch: allow-list says "unknown" → 1
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });

        let err = svc.partial_sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("mismatch"));
    }

    #[tokio::test]
    async fn test_partial_sign_block_replay_rejected() {
        let (pk, share1) = make_share(1);
        let share2 = ShareInfo {
            index: share1.index,
            threshold: share1.threshold,
            total: share1.total,
            scalar_bytes: share1.scalar_bytes.clone(),
            aggregate_pubkey: share1.aggregate_pubkey,
        };
        // CN will be "unknown" (no TLS); allow-list maps "unknown" → 1
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share1)], Arc::clone(&al), Some(Arc::clone(&db)));

        // First request — slot 42
        let req1 = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        svc.partial_sign_beacon_block(req1).await.expect("first sign succeeded");

        // Second request — same slot 42, different block body (different signing root)
        let mut different_body = sample_block_ssz(42);
        for b in &mut different_body[16..48] {
            *b ^= 0xFF;
        }
        let req2 = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: different_body,
            fork_id: 4,
        });

        let svc2 = make_service(vec![(pk, share2)], al, Some(db));
        let err = svc2.partial_sign_beacon_block(req2).await.unwrap_err();
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );
    }

    /// Proves pubkey-scoped enforcement across peers on a SHARED `SlashingDb`.
    ///
    /// Post-Issue-2.5, the slashing check is keyed by (pubkey, slot) only — not by CN.
    /// Two peers signing the same (pubkey, slot=42) with DIFFERENT block bodies (different
    /// signing roots) MUST produce a `DoubleBlockProposal` rejection for the second peer,
    /// regardless of which CN it presents.  Two separate DBs would only test DB isolation,
    /// not the pubkey-scoped enforcement that matters for DVT safety.
    #[tokio::test]
    async fn test_partial_sign_cross_peer_double_block_rejected() {
        let (pk, share_a_info) = make_share(1);
        let share_b_info = ShareInfo {
            index: 2,
            threshold: share_a_info.threshold,
            total: share_a_info.total,
            scalar_bytes: share_a_info.scalar_bytes.clone(),
            aggregate_pubkey: share_a_info.aggregate_pubkey,
        };

        // Both peers share ONE SlashingDb — this is what tests pubkey-scoped enforcement.
        // Each peer's CN goes to the audit log only (via PubkeyScopedDb); the slashing
        // check sees (pubkey, slot) regardless of CN.
        let shared_db = make_db();
        let al = make_allow_list(vec![("unknown", 1)]);
        let svc_a =
            make_service(vec![(pk, share_a_info)], Arc::clone(&al), Some(Arc::clone(&shared_db)));
        let svc_b =
            make_service(vec![(pk, share_b_info)], Arc::clone(&al), Some(Arc::clone(&shared_db)));

        // Peer-A signs slot 42 with block body A (requester_index=1 per allow-list).
        let req_a = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        svc_a.partial_sign_beacon_block(req_a).await.expect("peer-A first sign must succeed");

        // Peer-B attempts slot 42 with a DIFFERENT block body → different signing root.
        // Must be rejected as DoubleBlockProposal (pubkey-scoped enforcement).
        let mut different_body = sample_block_ssz(42);
        for b in &mut different_body[16..48] {
            *b ^= 0xFF;
        }
        let req_b_conflict = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: different_body,
            fork_id: 4,
        });
        let err = svc_b
            .partial_sign_beacon_block(req_b_conflict)
            .await
            .expect_err("peer-B with conflicting root must be rejected");
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection (DoubleBlockProposal), got: {:?}",
            err.code()
        );

        // Peer-B with the SAME block body/root as peer-A → idempotent re-sign, must succeed.
        let req_b_resign = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        svc_b
            .partial_sign_beacon_block(req_b_resign)
            .await
            .expect("peer-B with same root must succeed (idempotent re-sign)");
    }

    // ── partial_sign_attestation_data tests ───────────────────────────────────

    #[tokio::test]
    async fn test_partial_sign_attestation_happy_path() {
        let (pk, share) = make_share(1);
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share)], al, Some(db));

        let req = Request::new(PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            data: Some(sample_attestation_data_proto()),
            fork_id: 4,
        });

        let resp = svc.partial_sign_attestation_data(req).await.unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.partial_signature.len(), 96);
        assert_eq!(inner.share_index, 1);
    }

    #[tokio::test]
    async fn test_partial_sign_attestation_double_vote_rejected() {
        let (pk, share1) = make_share(1);
        let share2 = ShareInfo {
            index: share1.index,
            threshold: share1.threshold,
            total: share1.total,
            scalar_bytes: share1.scalar_bytes.clone(),
            aggregate_pubkey: share1.aggregate_pubkey,
        };
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();

        let svc1 = make_service(vec![(pk, share1)], Arc::clone(&al), Some(Arc::clone(&db)));
        let svc2 = make_service(vec![(pk, share2)], Arc::clone(&al), Some(Arc::clone(&db)));

        // First sign succeeds.
        let req1 = Request::new(PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            data: Some(sample_attestation_data_proto()),
            fork_id: 4,
        });
        svc1.partial_sign_attestation_data(req1).await.expect("first attestation sign succeeded");

        // Second sign — same (source=1, target=2) but different beacon_block_root → double vote.
        let mut data2 = sample_attestation_data_proto();
        data2.beacon_block_root = vec![0xFF; 32]; // different root

        let req2 = Request::new(PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            data: Some(data2),
            fork_id: 4,
        });

        let err = svc2.partial_sign_attestation_data(req2).await.unwrap_err();
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );
    }

    // ── partial_sign_sync_committee tests ─────────────────────────────────────

    #[tokio::test]
    async fn test_partial_sign_sync_committee_happy_path() {
        let (pk, share) = make_share(1);
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share)], al, Some(db));

        let req = Request::new(PartialSignSyncCommitteeRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            slot: 100,
            beacon_block_root: vec![0xAB; 32],
            fork_id: 4,
        });

        let resp = svc.partial_sign_sync_committee(req).await.unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.partial_signature.len(), 96);
        assert_eq!(inner.share_index, 1);
    }

    #[tokio::test]
    async fn test_partial_sign_sync_committee_no_replay_check() {
        // Sync is NOT slashable — two identical requests must both succeed.
        let (pk, share1) = make_share(1);
        let share2 = ShareInfo {
            index: share1.index,
            threshold: share1.threshold,
            total: share1.total,
            scalar_bytes: share1.scalar_bytes.clone(),
            aggregate_pubkey: share1.aggregate_pubkey,
        };
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();

        let svc1 = make_service(vec![(pk, share1)], Arc::clone(&al), Some(Arc::clone(&db)));
        let svc2 = make_service(vec![(pk, share2)], Arc::clone(&al), Some(Arc::clone(&db)));

        let make_req = || {
            Request::new(PartialSignSyncCommitteeRequest {
                requester_index: 1,
                pubkey: pk.to_vec(),
                fork_info: Some(sample_fork_info()),
                slot: 50,
                beacon_block_root: vec![0xCC; 32],
                fork_id: 4,
            })
        };

        let resp1 = svc1.partial_sign_sync_committee(make_req()).await.unwrap();
        assert_eq!(resp1.into_inner().partial_signature.len(), 96);

        // Second request with identical inputs — must succeed (no replay check for sync).
        let resp2 = svc2.partial_sign_sync_committee(make_req()).await.unwrap();
        assert_eq!(resp2.into_inner().partial_signature.len(), 96);
    }

    #[tokio::test]
    async fn test_partial_sign_signer_failure_does_not_persist_row() {
        // Use an empty shares map so the sign will fail with `not_found`.
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![], al, Some(Arc::clone(&db)));

        let (pk, _) = make_share(1);
        let req = Request::new(PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(99),
            fork_id: 4,
        });

        let err = svc.partial_sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Verify no row was committed in the DB.
        let pubkey_hex_str = pubkey_hex(&pk);
        let blocks = db.get_blocks(&pubkey_hex_str).expect("get_blocks");
        assert!(blocks.is_empty(), "no row must be committed after signer failure");
    }
}
