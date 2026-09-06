//! gRPC signer service implementation.
//!
//! # V2 service (`SignerService` from `signer.v2.proto`)
//! All 10 typed RPCs are implemented (ISSUE-1.6a–d) and route through
//! `SigningGate` (Issue 2.10a — D-3).  The legacy v1 raw-root proto surface
//! was retired in RF2-17; only `signer.v2` is compiled and registered.
//!
//! # Gate routing (D-3 wiring, Issue 2.10a)
//!
//! Every typed v2 handler now routes through `SigningGate::sign_*`:
//!
//! - Slashable handlers (`sign_beacon_block`, `sign_blinded_beacon_block`,
//!   `sign_attestation_data`): `gate.sign_block` / `gate.sign_attestation`.
//!   The gate manages: per-pubkey lock → doppelganger check →
//!   stage → sign (timeout) → commit/discard.
//!
//! - Non-slashable handlers: `gate.sign_*` (gate check → sign, NO slashing DB).
//!
//! # AlwaysEnabled enablement
//!
//! The standalone `rvc-signer` is a remote signer.  Doppelganger detection is
//! a VC-side concern (the orchestrator enforces it; wired in 2.10b/main.rs).
//! The bin's gate therefore uses an `AlwaysEnabled` `SigningEnablement` so that
//! the doppelganger check always passes here.  The gate still provides:
//! - Slashing protection (stage → commit/discard with `SlashingDb`)
//! - Per-pubkey serialization locks (`ValidatorLockMap`)
//! - Sign timeout (BUG-003 mitigation)
//!
//! # SS-2/SS-3 fix (aggregate-and-proof, Issue 2.10a)
//!
//! The previous `sign_aggregate_and_proof` handler erroneously called
//! `stage_attestation` on the inner attestation's epochs.  This constituted:
//! - SS-2: double-staging an attestation that the VC already committed via
//!   `sign_attestation`.
//! - SS-3: treating `DOMAIN_AGGREGATE_AND_PROOF` signing roots as attestation
//!   slashing watermarks.
//!
//! Routing through `gate.sign_aggregate_and_proof` removes the attestation
//! staging.  The gate's `sign_aggregate_and_proof` is explicitly non-slashable
//! per the Ethereum consensus spec.

use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::Span;
use tree_hash::TreeHash;

use crate::audit;
use crate::backend::signer_adapter::SigningBackendAsSigner;
use crate::backend::{SigningBackend, SigningBackendError};
use crate::grpc_common::{
    decode_attestation, decode_attestation_data, decode_beacon_block, decode_blinded_beacon_block,
    decode_fork_info, decode_sync_committee_contribution, validate_pubkey, validate_root32,
    validate_selection_proof,
};
use crate::metrics::{grpc_sign_type, SignerMetrics};
use crate::sign_plan::{
    dispatch_non_slashable, dispatch_slashable, plan_builder_registration, plan_sign,
    plan_voluntary_exit, DispatchError, NonSlashableOp, PlanInput, RequestCtx,
};

// V2 imports
use crate::proto::signer_v2::signer_service_server::SignerService as SignerServiceV2;
use crate::proto::signer_v2::{
    GetStatusRequest as GetStatusRequestV2, GetStatusResponse as GetStatusResponseV2,
    ListPublicKeysRequest as ListPublicKeysRequestV2,
    ListPublicKeysResponse as ListPublicKeysResponseV2, SignAggregateAndProofRequest,
    SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
    SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
    SignRandaoRevealRequest, SignResponse as SignResponseV2, SignRootRequest,
    SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
    SignVoluntaryExitRequest,
};

use crypto::PublicKey;
use eth_types::{
    AggregateAndProof, ContributionAndProof, SyncAggregatorSelectionData, ValidatorRegistrationV1,
    VoluntaryExit,
};
use signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb; // kept for new_v2 constructor parameter type

/// Default per-sign timeout passed to the gate: 4 seconds.
///
/// Well under a 12-second Ethereum slot.  Bounds the SQLite write-lock hold
/// duration per BUG-003.  The `with_sign_timeout` builder is available but
/// not yet wired to a CLI flag; it exists for future operator configuration.
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4);

// ─────────────────────────────────────────────────────────────────────────────
// AlwaysEnabled — the standalone signer's gate enablement
// ─────────────────────────────────────────────────────────────────────────────

/// A `SigningEnablement` that always allows signing.
///
/// The standalone `rvc-signer` is a REMOTE signer; doppelganger detection is a
/// VC-side concern (the orchestrator wired in 2.10b/main.rs enforces it).
/// The gate here provides slashing-protection + per-pubkey-lock layers only;
/// the doppelganger gate is effectively a no-op.
struct AlwaysEnabled;

impl signer::SigningEnablement for AlwaysEnabled {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignerServiceImpl
// ─────────────────────────────────────────────────────────────────────────────

pub struct SignerServiceImpl {
    backend: Arc<dyn SigningBackend>,
    backend_name: String,
    metrics: Option<Arc<SignerMetrics>>,
    /// Gate — `None` when no slashing DB is configured.
    ///
    /// Slashable sign requests fail-closed with `Status::internal` when the gate
    /// is absent (same `require_db` semantics as before).  The gate internally
    /// holds the `Arc<SlashingDb>` so the DB stays alive for the service lifetime.
    ///
    /// Stored as `Arc<SigningGate>` so the **same** gate instance can be shared
    /// across transports (gRPC here, HTTP in Phase 3): the gate is built once at
    /// the composition root (`run_serve`, ADR-003) and cloned into each transport,
    /// keeping slashing protection and the in-memory `ValidatorLockMap` unified
    /// (FR-26).
    gate: Option<Arc<SigningGate>>,
    /// Optional client-CN allow-list for the primary (non-DVT) path (SEC-4).
    ///
    /// When `Some`, only listed mTLS CNs may invoke signing RPCs (exact,
    /// case-sensitive match; `"unknown"` is rejected unless explicitly listed).
    /// When `None`, all mTLS clients are accepted (backward compatible; startup
    /// logs a warning). mTLS remains mandatory either way.
    client_cn_allow_list: Option<Arc<audit::ClientCnAllowList>>,
    /// Network genesis fork version ([`eth_types::NetworkPreset`]).
    ///
    /// Sole source for builder-registration domain computation across gRPC and
    /// HTTP. Default is mainnet (`0x00000000`).
    genesis_fork_version: [u8; 4],
}

impl SignerServiceImpl {
    /// Create a service with no slashing DB / gate (insecure / tests only).
    ///
    /// Production with a DB should use `new_v2` or `new_v2_with_gate`.
    /// Without a gate, slashable RPCs fail closed; non-slashable RPCs fall
    /// through to the backend (BUG-001).
    pub fn new(backend: Arc<dyn SigningBackend>, backend_name: String) -> Self {
        Self {
            backend,
            backend_name,
            metrics: None,
            gate: None,
            client_cn_allow_list: None,
            genesis_fork_version: crate::sign_plan::BUILDER_FORK_VERSION_MAINNET,
        }
    }

    /// Create a v2-capable service with an embedded slashing DB and `SigningGate`.
    ///
    /// The gate is built from:
    /// - `slashing_db`: provides slashing protection for block and attestation paths.
    /// - `SigningBackendAsSigner` adapter: wraps the backend as `Arc<dyn crypto::Signer>`.
    /// - `AlwaysEnabled` enablement: doppelganger detection is the calling VC's
    ///   responsibility; the gate here provides slashing + lock layers only.
    /// - A fresh `ValidatorLockMap`: per-pubkey serialization.
    /// - Default 4-second sign timeout (BUG-003 mitigation).
    pub fn new_v2(
        backend: Arc<dyn SigningBackend>,
        backend_name: String,
        slashing_db: Arc<SlashingDb>,
    ) -> Self {
        let gate = Arc::new(Self::build_gate(Arc::clone(&backend), slashing_db));
        Self::new_v2_with_gate(backend, backend_name, gate)
    }

    /// Build the shared [`SigningGate`] from a backend + slashing DB.
    ///
    /// Hoisted out of `new_v2` (ADR-003) so the composition root (`run_serve`)
    /// can build **one** gate and inject the same `Arc<SigningGate>` into every
    /// transport (gRPC here, HTTP in Phase 3), keeping slashing protection and the
    /// in-memory per-pubkey `ValidatorLockMap` unified across transports (FR-26).
    ///
    /// Construction is unchanged from the previous in-`new_v2` build:
    /// - `SigningBackendAsSigner` adapter wraps the backend as `Arc<dyn crypto::Signer>`.
    /// - `AlwaysEnabled` enablement (doppelganger is the calling VC's concern).
    /// - A fresh `ValidatorLockMap` for per-pubkey serialization.
    /// - Default 4-second sign timeout (BUG-003 mitigation).
    pub fn build_gate(
        backend: Arc<dyn SigningBackend>,
        slashing_db: Arc<SlashingDb>,
    ) -> SigningGate {
        let adapted_signer = Arc::new(SigningBackendAsSigner(backend)) as Arc<dyn crypto::Signer>;
        SigningGate::new_with_raw_signer(
            slashing_db,
            Arc::new(AlwaysEnabled),
            adapted_signer,
            Arc::new(ValidatorLockMap::new()),
            DEFAULT_SIGN_TIMEOUT,
        )
    }

    /// Create a v2-capable service from an already-built, shared `Arc<SigningGate>`.
    ///
    /// This is the injection point for the hoisted gate (ADR-003): `run_serve`
    /// builds the gate once and passes a clone here and (Phase 3) into the HTTP
    /// `Web3SignerState`, so both transports share one signing authority.
    pub fn new_v2_with_gate(
        backend: Arc<dyn SigningBackend>,
        backend_name: String,
        gate: Arc<SigningGate>,
    ) -> Self {
        Self {
            backend,
            backend_name,
            metrics: None,
            gate: Some(gate),
            client_cn_allow_list: None,
            genesis_fork_version: crate::sign_plan::BUILDER_FORK_VERSION_MAINNET,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<SignerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// The shared [`SigningGate`] injected at the composition root (FR-26), if any.
    ///
    /// Used by server-phase tests to assert gRPC and HTTP hold the same `Arc`.
    #[cfg(test)]
    pub(crate) fn shared_gate(&self) -> Option<&Arc<SigningGate>> {
        self.gate.as_ref()
    }

    /// The shared [`SignerMetrics`] registry injected at the composition root.
    #[cfg(test)]
    pub(crate) fn shared_metrics(&self) -> Option<&Arc<SignerMetrics>> {
        self.metrics.as_ref()
    }

    /// Set the network genesis fork version used for builder registration.
    ///
    /// Both gRPC and HTTP must be configured with the same value (typically from
    /// [`eth_types::NetworkPreset`]) so identical registrations produce identical
    /// signatures across transports.
    pub fn with_genesis_fork_version(mut self, genesis_fork_version: [u8; 4]) -> Self {
        self.genesis_fork_version = genesis_fork_version;
        self
    }

    /// Attach an optional primary-path client-CN allow-list (SEC-4).
    ///
    /// Builder-style; call after `new` / `new_v2` / `new_v2_with_gate`.
    pub fn with_client_cn_allow_list(
        mut self,
        allow_list: Option<Arc<audit::ClientCnAllowList>>,
    ) -> Self {
        self.client_cn_allow_list = allow_list;
        self
    }

    /// Build a [`RequestCtx`] with this service's network genesis fork version.
    fn request_ctx(
        &self,
        client_cn: String,
        pubkey: PublicKey,
        pubkey_bytes: [u8; 48],
        rpc_type: &'static str,
    ) -> RequestCtx {
        RequestCtx {
            client_cn,
            pubkey,
            pubkey_bytes,
            rpc_type,
            genesis_fork_version: self.genesis_fork_version,
        }
    }

    /// Resolve builder-registration genesis fork version.
    ///
    /// The configured network genesis is the sole source. An empty request field
    /// accepts the server value; a non-empty field must be exactly 4 bytes and
    /// equal the server network (catches client/server network mismatch).
    #[allow(clippy::result_large_err)]
    fn resolve_builder_genesis_fork_version(
        &self,
        request_bytes: &[u8],
    ) -> Result<[u8; 4], Status> {
        if request_bytes.is_empty() {
            return Ok(self.genesis_fork_version);
        }
        let requested: [u8; 4] = request_bytes.try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "genesis_fork_version must be 4 bytes, got {}",
                request_bytes.len()
            ))
        })?;
        if requested != self.genesis_fork_version {
            return Err(Status::invalid_argument(
                "genesis_fork_version does not match server network configuration",
            ));
        }
        Ok(self.genesis_fork_version)
    }

    /// Override the sign timeout on the embedded gate (builder style).
    ///
    /// Available for future CLI-flag wiring; not yet operator-configurable.
    /// Has no effect when no gate is present (i.e. `new()` path).
    pub fn with_sign_timeout(mut self, timeout: Duration) -> Self {
        if let Some(gate) = self.gate.take() {
            // The gate is shared via `Arc` (FR-26).  Re-timing only makes sense
            // before the gate is cloned into another transport, i.e. while this
            // `Arc` is the sole owner — in that case `try_unwrap` succeeds and the
            // behavior is identical to the pre-hoist value-typed gate.  If the gate
            // is already shared, leave the timeout untouched rather than break the
            // shared-instance invariant.
            match Arc::try_unwrap(gate) {
                Ok(g) => self.gate = Some(Arc::new(g.with_sign_timeout(timeout))),
                Err(shared) => self.gate = Some(shared),
            }
        }
        self
    }

    /// Borrow the gate or return an `internal` status if it's missing.
    ///
    /// Used only by **slashable** handlers (block + attestation), which must fail
    /// closed when no slashing DB is configured.
    #[allow(clippy::result_large_err)]
    fn require_gate(&self) -> Result<&SigningGate, Status> {
        self.gate.as_deref().ok_or_else(|| {
            Status::internal(
                "slashing protection database is not configured; \
                 restart with a valid --data-dir or --disable-slashing-protection + \
                 RVC_ALLOW_INSECURE=true",
            )
        })
    }

    /// Reject the request when a client-CN allow-list is configured and `client_cn`
    /// is not listed (SEC-4). Emits an audit-log entry on rejection so operators
    /// can see denied sign attempts. Runs before any signing / staging logic.
    #[allow(clippy::result_large_err)]
    fn authorize_client_cn(&self, client_cn: &str) -> Result<(), Status> {
        match audit::authorize_client_cn(self.client_cn_allow_list.as_deref(), client_cn) {
            Ok(()) => Ok(()),
            Err(status) => {
                audit::log_audit(&audit::AuditEntry {
                    timestamp: audit::now_rfc3339(),
                    pubkey_hex: String::new(),
                    client_cn: client_cn.to_string(),
                    backend: self.backend_name.clone(),
                    result: "client_cn_not_allowed".to_string(),
                    duration_ms: 0,
                    rpc: None,
                });
                Err(status)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-slashable backend fallback (BUG-001 fix, Issue 2.10a review)
// ─────────────────────────────────────────────────────────────────────────────
//
// Pre-2.10a, non-slashable handlers called `backend.sign` directly.  Post-2.10a
// the gate owns signing, but the gate is `None` when `--disable-slashing-protection
// + RVC_ALLOW_INSECURE=true` is set (no DB, SignerServiceImpl::new path).
//
// Slashable handlers (block, attestation) keep `require_gate()` — fail-closed
// without a DB, correct.
//
// Non-slashable handlers must work without a DB.  When no gate is present they
// fall through to the backend via `finish_backend_sign` (which also records
// RF1-09 metrics), preserving pre-2.10a semantics.

/// Map a backend error to a gRPC `Status`.
fn backend_err_to_status(e: SigningBackendError) -> Status {
    match e {
        SigningBackendError::KeyNotFound(_) => Status::not_found("unknown public key"),
        other => {
            tracing::error!(error = %other, "signing backend error");
            Status::internal("internal signing error")
        }
    }
}

/// Map a SignPlan dispatcher error to gRPC `Status`.
///
/// Metrics are already recorded inside the dispatcher (A7 absorption).
#[allow(clippy::result_large_err)]
fn dispatch_err_to_status(e: DispatchError) -> Status {
    match e {
        DispatchError::Gate(ge) => gate_err_to_status(ge),
        DispatchError::Backend(be) => backend_err_to_status(be),
        DispatchError::GateRequired => Status::internal(
            "slashing protection database is not configured; \
             restart with a valid --data-dir or --disable-slashing-protection + \
             RVC_ALLOW_INSECURE=true",
        ),
        DispatchError::PlanMismatch => {
            tracing::error!("sign_plan dispatcher: plan class / entry-point mismatch");
            Status::internal("internal dispatch mismatch")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Field validators + proto decode live in `crate::grpc_common` (shared with DVT).

/// Map a `SigningGateError` to a gRPC `Status` via shared [`signer::classify`].
///
/// Does **not** match on `SigningGateError` variants — only on [`GateErrClass`].
/// Sanitization, client messages, and server-side detail logging are owned by
/// the library classifier so HTTP cannot drift.
///
/// # Status mapping
///
/// | [`GateErrClass`] | gRPC code |
/// |---|---|
/// | `BlockedByDoppelganger` / `SlashingBlocked` | `FailedPrecondition` |
/// | `CommitFailed` / `Internal` | `Internal` |
/// | `KeyNotFound` | `NotFound` |
/// Map a gate error to gRPC `Status` via [`signer::classify`].
///
/// `pub(crate)` so the HTTP mapper's agreement test can call the same path.
pub(crate) fn gate_err_to_status(e: SigningGateError) -> Status {
    use signer::GateErrClass;
    let class = signer::classify(&e);
    class.emit_server_log();
    let msg = class.client_message().to_string();
    match class {
        GateErrClass::BlockedByDoppelganger | GateErrClass::SlashingBlocked { .. } => {
            Status::failed_precondition(msg)
        }
        GateErrClass::CommitFailed { .. } | GateErrClass::Internal { .. } => Status::internal(msg),
        GateErrClass::KeyNotFound => Status::not_found(msg),
    }
}

/// Encode a pubkey as `0x<hex>` for use in audit logs.
fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

/// Convert a `PublicKey` from raw bytes, mapping failure to `Status::invalid_argument`.
#[allow(clippy::result_large_err)]
fn pubkey_from_bytes(bytes: &[u8; 48]) -> Result<PublicKey, Status> {
    PublicKey::from_bytes(bytes)
        .map_err(|_| Status::invalid_argument("pubkey bytes are not a valid BLS public key"))
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 SignerService impl — all handlers route through SigningGate (D-3, Issue 2.10a)
// RF2-17: v1 SignerService trait impl and proto compilation are gone.
// ADR-010's hypothetical off-by-default insecure listener was never built; if
// needed later it can be rebuilt on the v2 surface.
// ─────────────────────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl SignerServiceV2 for SignerServiceImpl {
    // ── SignBeaconBlock ───────────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(name = "signer.v2.sign_beacon_block", skip_all, fields(pubkey, slot))]
    async fn sign_beacon_block(
        &self,
        req: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let block = decode_beacon_block(&r.block_ssz, r.fork_id)?;
        let slot = block.slot;
        Span::current().record("slot", slot);

        // SEC-6c: typed body leaf — malformed Electra body SSZ must error, not panic.
        let object_root = block.try_tree_hash_root().map_err(|e| {
            Status::invalid_argument(format!("invalid block body for tree_hash_root: {e}"))
        })?;
        let plan =
            plan_sign(&PlanInput::Block { object_root: object_root.0, slot, fork_version, gvr });

        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::BEACON_BLOCK,
        );
        let sig = dispatch_slashable(
            self.require_gate()?,
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignBlindedBeaconBlock ────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "signer.v2.sign_blinded_beacon_block",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_blinded_beacon_block(
        &self,
        req: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let block = decode_blinded_beacon_block(&r.block_ssz, r.fork_id)?;
        let slot = block.slot;
        Span::current().record("slot", slot);

        let object_root = block.try_tree_hash_root().map_err(|e| {
            Status::invalid_argument(format!("invalid blinded block body for tree_hash_root: {e}"))
        })?;
        let plan =
            plan_sign(&PlanInput::Block { object_root: object_root.0, slot, fork_version, gvr });

        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::BLINDED_BEACON_BLOCK,
        );
        let sig = dispatch_slashable(
            self.require_gate()?,
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_blinded_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignRandaoReveal ──────────────────────────────────────────────────────

    #[tracing::instrument(name = "signer.v2.sign_randao_reveal", skip_all, fields(pubkey, epoch))]
    async fn sign_randao_reveal(
        &self,
        req: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let epoch = r.epoch;
        Span::current().record("epoch", epoch);

        let plan = plan_sign(&PlanInput::Randao { epoch, fork_version, gvr });
        let ctx = self.request_ctx(
            client_cn,
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::RANDAO_REVEAL,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::RandaoReveal,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            epoch,
            "sign_randao_reveal: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignAttestationData ───────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "signer.v2.sign_attestation_data",
        skip_all,
        fields(pubkey, source_epoch, target_epoch)
    )]
    async fn sign_attestation_data(
        &self,
        req: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        // EIP-7549 index-zeroing is the client's responsibility (H-2 / Phase 2).
        let (att_data, source_epoch, target_epoch) = decode_attestation_data(r.data)?;
        Span::current().record("source_epoch", source_epoch);
        Span::current().record("target_epoch", target_epoch);

        let plan = plan_sign(&PlanInput::Attestation { data: att_data, fork_version, gvr });
        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::ATTESTATION_DATA,
        );
        let sig = dispatch_slashable(
            self.require_gate()?,
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            source_epoch,
            target_epoch,
            client_cn = %client_cn,
            "sign_attestation_data: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignAggregateAndProof ─────────────────────────────────────────────────
    //
    // SS-2/SS-3: non-slashable. Aggregate staging is intentionally NOT performed.

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "signer.v2.sign_aggregate_and_proof",
        skip_all,
        fields(pubkey, source_epoch, target_epoch)
    )]
    async fn sign_aggregate_and_proof(
        &self,
        req: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let attestation = decode_attestation(&r.aggregate_ssz, r.fork_id)?;
        let source_epoch = attestation.data.source.epoch;
        let target_epoch = attestation.data.target.epoch;
        Span::current().record("source_epoch", source_epoch);
        Span::current().record("target_epoch", target_epoch);

        let selection_proof = validate_selection_proof(&r.selection_proof)?;
        let agg_and_proof = AggregateAndProof {
            aggregator_index: r.aggregator_index,
            aggregate: attestation,
            selection_proof,
        };
        // Fallible HTR — match HTTP: oversize aggregation_bits → 400, never panic.
        let object_root = agg_and_proof
            .try_tree_hash_root()
            .map_err(|_| Status::invalid_argument("invalid aggregate_and_proof"))?;
        let plan = plan_sign(&PlanInput::AggregateAndProof {
            object_root: object_root.0,
            fork_version,
            gvr,
        });

        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::AGGREGATE_AND_PROOF,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::AggregateAndProof,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            source_epoch,
            target_epoch,
            client_cn = %client_cn,
            "sign_aggregate_and_proof: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignSyncCommitteeMessage ──────────────────────────────────────────────

    /// Sign a sync committee message over `beacon_block_root`.
    ///
    /// Per FR-P0-3 / NFR-1: sync messages are **not slashable** — no staging.
    #[tracing::instrument(
        name = "signer.v2.sign_sync_committee_message",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_sync_committee_message(
        &self,
        req: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let slot = r.slot;
        Span::current().record("slot", slot);
        let beacon_block_root = validate_root32(&r.beacon_block_root, "beacon_block_root")?;

        let plan =
            plan_sign(&PlanInput::SyncCommitteeMessage { beacon_block_root, fork_version, gvr });
        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::SYNC_COMMITTEE_MESSAGE,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::SyncCommitteeMessage,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_sync_committee_message: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignSyncAggregatorSelectionData ───────────────────────────────────────

    /// Sign a sync aggregator selection proof over `(slot, subcommittee_index)`.
    ///
    /// Per FR-P0-3 / NFR-1: not slashable — no staging.
    #[tracing::instrument(
        name = "signer.v2.sign_sync_aggregator_selection_data",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_sync_aggregator_selection_data(
        &self,
        req: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let slot = r.slot;
        Span::current().record("slot", slot);

        let plan = plan_sign(&PlanInput::SyncCommitteeSelection {
            data: SyncAggregatorSelectionData { slot, subcommittee_index: r.subcommittee_index },
            fork_version,
            gvr,
        });
        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::SYNC_AGGREGATOR_SELECTION_DATA,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::SelectionProof,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            subcommittee_index = r.subcommittee_index,
            client_cn = %client_cn,
            "sign_sync_aggregator_selection_data: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignContributionAndProof ───────────────────────────────────────────────

    /// Sign a `ContributionAndProof`.
    ///
    /// `contribution_ssz` is SSZ-encoded `SyncCommitteeContribution`; the server
    /// decodes it and wraps it in `ContributionAndProof { aggregator_index,
    /// contribution, selection_proof }` before signing.
    ///
    /// Per FR-P0-3 / NFR-1: not slashable — no staging.
    #[tracing::instrument(
        name = "signer.v2.sign_contribution_and_proof",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_contribution_and_proof(
        &self,
        req: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let contribution = decode_sync_committee_contribution(&r.contribution_ssz, r.fork_id)?;
        let slot = contribution.slot;
        Span::current().record("slot", slot);

        let selection_proof = validate_selection_proof(&r.selection_proof)?;
        let cap = ContributionAndProof {
            aggregator_index: r.aggregator_index,
            contribution,
            selection_proof,
        };
        let object_root = cap.tree_hash_root().0;
        let plan = plan_sign(&PlanInput::ContributionAndProof { object_root, fork_version, gvr });

        let ctx = self.request_ctx(
            client_cn.clone(),
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::CONTRIBUTION_AND_PROOF,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::ContributionAndProof,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            aggregator_index = r.aggregator_index,
            client_cn = %client_cn,
            "sign_contribution_and_proof: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignBuilderRegistration ────────────────────────────────────────────────
    //
    // domain = DOMAIN_APPLICATION_BUILDER + network genesis fork version + ZERO_HASH.
    // Network genesis comes from server config (NetworkPreset); request field if
    // present must match. Not slashable.
    #[tracing::instrument(name = "signer.v2.sign_builder_registration", skip_all, fields(pubkey))]
    async fn sign_builder_registration(
        &self,
        req: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fee_recipient: [u8; 20] = r.fee_recipient.as_slice().try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "fee_recipient must be 20 bytes, got {}",
                r.fee_recipient.len()
            ))
        })?;

        let registration = ValidatorRegistrationV1 {
            fee_recipient,
            gas_limit: r.gas_limit,
            timestamp: r.timestamp,
            pubkey: pubkey_bytes,
        };

        // Sole source: server network config. Non-empty request must match.
        let genesis_fork_version =
            self.resolve_builder_genesis_fork_version(&r.genesis_fork_version)?;
        let plan = plan_builder_registration(&registration, genesis_fork_version);

        let ctx = self.request_ctx(
            client_cn,
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::BUILDER_REGISTRATION,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::BuilderRegistration,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            "sign_builder_registration: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignVoluntaryExit ──────────────────────────────────────────────────────
    //
    // EIP-7044: caller supplies Capella-capped current_version. Not slashable.
    #[tracing::instrument(
        name = "signer.v2.sign_voluntary_exit",
        skip_all,
        fields(pubkey, epoch, validator_index)
    )]
    async fn sign_voluntary_exit(
        &self,
        req: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        self.authorize_client_cn(&client_cn)?;
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let (fork_version, gvr) = decode_fork_info(r.fork_info)?;
        let epoch = r.epoch;
        let validator_index = r.validator_index;
        Span::current().record("epoch", epoch);
        Span::current().record("validator_index", validator_index);

        let exit = VoluntaryExit { epoch, validator_index };
        let plan = plan_voluntary_exit(&exit, fork_version, gvr);

        let ctx = self.request_ctx(
            client_cn,
            pubkey_from_bytes(&pubkey_bytes)?,
            pubkey_bytes,
            grpc_sign_type::VOLUNTARY_EXIT,
        );
        let sig = dispatch_non_slashable(
            self.gate.as_deref(),
            self.backend.as_ref(),
            self.metrics.as_deref(),
            &self.backend_name,
            &ctx,
            &plan,
            NonSlashableOp::VoluntaryExit,
        )
        .await
        .map_err(dispatch_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            epoch,
            validator_index,
            "sign_voluntary_exit: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // Wire stubs for 4.20a; handler logic is 4.20b.
    async fn sign_block_header(
        &self,
        _req: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("SignBlockHeader (issue 4.20b)"))
    }

    async fn sign_root(
        &self,
        _req: Request<SignRootRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("SignRoot (issue 4.20b)"))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        let pubkeys = self.backend.public_keys().into_iter().map(|pk| pk.to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponseV2 { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        let key_count = self.backend.public_keys().len() as u32;
        Ok(Response::new(GetStatusResponseV2 {
            ready: true,
            backend: self.backend_name.clone(),
            key_count,
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SigningBackendError;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[test]
    fn test_validate_selection_proof_accepts_96_bytes() {
        let buf = [0u8; 96];
        let result = validate_selection_proof(&buf).expect("96 bytes should pass");
        assert_eq!(result.len(), 96);
    }

    #[test]
    fn test_validate_selection_proof_rejects_short() {
        let err = validate_selection_proof(&[0u8; 95]).expect_err("95 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
        assert!(err.message().contains("95"));
    }

    #[test]
    fn test_validate_selection_proof_rejects_long() {
        let err = validate_selection_proof(&[0u8; 97]).expect_err("97 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
    }

    #[test]
    fn test_validate_selection_proof_rejects_empty() {
        let err = validate_selection_proof(&[]).expect_err("empty must fail");
        assert!(err.message().contains("96 bytes"));
    }

    // ── Test backend — real BLS signing ──────────────────────────────────────
    //
    // The gate validates pubkeys as BLS points and reconstructs `Signature` from
    // the backend's raw [u8; 96] output.  `MockBackend` must therefore:
    // (a) store real `SecretKey` instances, not arbitrary [u8; 48] values; and
    // (b) produce valid BLS signatures so that `Signature::from_bytes` succeeds.
    //
    // `test_pubkey()` generates a deterministic BLS keypair for unit tests.

    use crypto::{KeyManager, SecretKey};

    /// Generate a deterministic BLS `SecretKey` / pubkey pair for unit tests.
    fn test_secret_key() -> SecretKey {
        use crypto::eip2333::derive_master_sk;
        let seed = [0x11u8; 32];
        derive_master_sk(&seed).expect("derive master sk")
    }

    /// Return the raw 48-byte pubkey for `test_secret_key()`.
    fn test_pubkey_bytes() -> [u8; 48] {
        test_secret_key().public_key().to_bytes()
    }

    struct MockBackend {
        km: Arc<KeyManager>,
    }

    impl MockBackend {
        /// Create a backend pre-loaded with `test_secret_key()`.
        fn with_test_key() -> Self {
            let sk = test_secret_key();
            let mut km = KeyManager::new();
            km.insert(sk);
            Self { km: Arc::new(km) }
        }

        /// Create a backend with no keys.
        fn empty() -> Self {
            Self { km: Arc::new(KeyManager::new()) }
        }
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(
            &self,
            signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            let pk = crypto::PublicKey::from_bytes(pubkey)
                .map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
            let sk =
                self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
            Ok(sk.sign(signing_root).to_bytes())
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
        }
    }

    fn make_service(backend: MockBackend) -> SignerServiceImpl {
        SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
    }

    fn make_service_v2(backend: MockBackend) -> SignerServiceImpl {
        // In-memory: avoids SEC-3 CorruptOrEmpty on 0-byte NamedTempFile paths.
        let db = Arc::new(slashing::SlashingDb::open_in_memory().unwrap());
        SignerServiceImpl::new_v2(Arc::new(backend), "basic".to_string(), db)
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

    fn sample_fork_info() -> crate::proto::signer_v2::ForkInfo {
        crate::proto::signer_v2::ForkInfo {
            previous_version: vec![0x04, 0x00, 0x00, 0x00],
            current_version: vec![0x04, 0x00, 0x00, 0x00],
            epoch: 0,
            genesis_validators_root: vec![0x00; 32],
        }
    }

    // --- V2 tests ---
    // These tests use `test_pubkey_bytes()` / `MockBackend::with_test_key()` so
    // the gate's BLS pubkey validation and `Signature::from_bytes` succeed.
    // RF2-17: v1 Unimplemented unit tests deleted with the dead v1 trait impl.
    // Raw-root guard: `tests/raw_root_rejected.rs` greps generated signer.v2.rs.

    #[tokio::test]
    async fn test_v2_sign_beacon_block_happy_path() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp = svc.sign_beacon_block(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_missing_fork_info() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: None,
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_bad_pubkey_length() {
        let svc = make_service_v2(MockBackend::empty());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: vec![1u8; 32], // wrong length — caught before BLS validation
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_unknown_key_returns_not_found() {
        let db = Arc::new(slashing::SlashingDb::open_in_memory().unwrap());
        // Empty backend: sign will fail with KeyNotFound.
        let svc = SignerServiceImpl::new_v2(
            Arc::new(MockBackend::empty()),
            "basic".to_string(),
            Arc::clone(&db),
        );

        // Use a valid BLS pubkey so it passes gate validation.
        let pubkey = test_pubkey_bytes();
        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Critical: signer failure must NOT leave a phantom row (M-1 fix, A15).
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert!(
            blocks.is_empty(),
            "signer failure must not commit a slashing row (stage→sign→commit A15)"
        );
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_double_proposal_rejected() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        // First sign
        let req1 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(100),
            fork_id: 4,
        });
        svc.sign_beacon_block(req1).await.unwrap();

        // Second sign — different block body → different signing root
        let mut different_ssz = sample_block_ssz(100);
        for b in &mut different_ssz[16..48] {
            *b ^= 0xFF;
        }
        let req2 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: different_ssz,
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req2).await.unwrap_err();
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );
    }

    #[tokio::test]
    async fn test_v2_sign_randao_reveal_happy_path() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignRandaoRevealRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 10,
            fork_id: 4,
        });
        let resp = svc.sign_randao_reveal(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_randao_same_epoch_twice_both_succeed() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        for _ in 0..2 {
            let req = Request::new(SignRandaoRevealRequest {
                pubkey: pubkey.to_vec(),
                fork_info: Some(sample_fork_info()),
                epoch: 50,
                fork_id: 4,
            });
            svc.sign_randao_reveal(req).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_sign_blinded_beacon_block_happy_path() {
        use eth_types::{encode_blinded_beacon_block_ssz, BlindedBeaconBlock};
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let blinded = BlindedBeaconBlock {
            slot: 200,
            proposer_index: 1,
            parent_root: [0x33; 32],
            state_root: [0x44; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        let ssz = encode_blinded_beacon_block_ssz(&blinded, 4);

        let req = Request::new(SignBlindedBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: ssz,
            fork_id: 4,
        });
        let resp = svc.sign_blinded_beacon_block(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_no_db_returns_internal() {
        // No gate (no DB): gate validation returns Internal before BLS validation.
        let pubkey = test_pubkey_bytes();
        let svc = make_service(MockBackend::with_test_key()); // no DB, no gate

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    // --- BUG-001 regression: non-slashable ops work without a slashing DB ---

    /// BUG-001 regression: `sign_randao_reveal` (a non-slashable operation) on a
    /// service with no slashing DB (`SignerServiceImpl::new`, i.e.
    /// `--disable-slashing-protection` mode) must return a 96-byte signature, NOT
    /// `Internal`.  Pre-fix, every non-slashable handler called `require_gate()?`
    /// which returned `Internal` when `gate.is_none()`.
    #[tokio::test]
    async fn test_v2_sign_randao_no_db_returns_signature() {
        let pubkey = test_pubkey_bytes();
        // `make_service` uses `SignerServiceImpl::new` — no DB, no gate.
        let svc = make_service(MockBackend::with_test_key());

        let req = Request::new(SignRandaoRevealRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 5,
            fork_id: 4,
        });
        // Must succeed: RANDAO is non-slashable and must not require the DB.
        let resp = svc
            .sign_randao_reveal(req)
            .await
            .expect("sign_randao_reveal without a slashing DB must succeed (BUG-001 regression)");
        assert_eq!(
            resp.into_inner().signature.len(),
            96,
            "expected 96-byte BLS signature, got wrong length"
        );
    }

    /// Companion to BUG-001: slashable ops (sign_beacon_block) still fail closed
    /// without a DB — the fail-closed invariant must not be disturbed.
    #[tokio::test]
    async fn test_v2_sign_beacon_block_still_fails_closed_without_db() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service(MockBackend::with_test_key()); // no DB

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Internal,
            "slashable op without DB must return Internal (fail-closed)"
        );
    }

    // --- Issue 1.2: gate-hoist (ADR-003 / FR-26) ---

    /// The gate is built ONCE at the composition root and injected via
    /// `new_v2_with_gate`; the gRPC service must hold *that same* `Arc<SigningGate>`
    /// instance, so a future HTTP transport sharing a clone shares the same slashing
    /// DB + in-memory `ValidatorLockMap` (FR-26).  The no-DB path keeps `gate = None`.
    #[tokio::test]
    async fn test_gate_hoist_injects_shared_gate_and_no_db_is_none() {
        // No-DB path: gate is None (the fail-closed path is preserved post-hoist).
        let no_db = make_service(MockBackend::with_test_key());
        assert!(no_db.gate.is_none(), "no-DB service must have gate = None");

        // Hoisted path: build ONE gate at the composition root, inject a clone.
        let db = Arc::new(slashing::SlashingDb::open_in_memory().unwrap());
        let backend = Arc::new(MockBackend::with_test_key());
        let shared_gate = Arc::new(SignerServiceImpl::build_gate(backend.clone(), db));

        let svc = SignerServiceImpl::new_v2_with_gate(
            backend,
            "basic".to_string(),
            Arc::clone(&shared_gate),
        );

        let svc_gate = svc.gate.as_ref().expect("v2 service must have a gate");
        assert!(
            Arc::ptr_eq(svc_gate, &shared_gate),
            "new_v2_with_gate must inject the SAME Arc<SigningGate> (one shared gate, FR-26)"
        );
        assert_eq!(
            Arc::strong_count(&shared_gate),
            2,
            "exactly the composition-root Arc + the injected clone share the gate"
        );
    }

    // --- ListPublicKeys / GetStatus v2 ---

    #[tokio::test]
    async fn test_v2_list_public_keys() {
        // Use one real key for the backend (list_public_keys doesn't require valid BLS).
        let svc = make_service_v2(MockBackend::with_test_key());

        let resp =
            SignerServiceV2::list_public_keys(&svc, Request::new(ListPublicKeysRequestV2 {}))
                .await
                .unwrap();
        let pubkeys = resp.into_inner().pubkeys;
        assert_eq!(pubkeys.len(), 1);
    }

    #[tokio::test]
    async fn test_v2_get_status() {
        let svc = make_service_v2(MockBackend::with_test_key());

        let resp =
            SignerServiceV2::get_status(&svc, Request::new(GetStatusRequestV2 {})).await.unwrap();
        let status = resp.into_inner();
        assert!(status.ready);
        assert_eq!(status.key_count, 1);
    }

    // ── RF1-09: gRPC sign metrics via shared free-standing helper ─────────────

    fn make_service_v2_with_metrics(
        backend: MockBackend,
    ) -> (SignerServiceImpl, Arc<SignerMetrics>) {
        let metrics = Arc::new(SignerMetrics::new());
        let svc = make_service_v2(backend).with_metrics(Arc::clone(&metrics));
        (svc, metrics)
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_records_sign_total() {
        let pubkey = test_pubkey_bytes();
        let (svc, metrics) = make_service_v2_with_metrics(MockBackend::with_test_key());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp = svc.sign_beacon_block(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);

        assert_eq!(
            metrics
                .sign_total
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK, "success"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .sign_duration_seconds
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            0
        );
        // Encode scrape text after a real gRPC sign (RF1-09 scrape AC / L1).
        let scrape = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(scrape.contains("rvc_signer_sign_total"), "scrape: {scrape}");
        assert!(scrape.contains("beacon_block"), "scrape: {scrape}");
        assert!(scrape.contains("success"), "scrape: {scrape}");
    }

    #[tokio::test]
    async fn test_v2_sign_unknown_key_records_sign_error() {
        let db = Arc::new(slashing::SlashingDb::open_in_memory().unwrap());
        let metrics = Arc::new(SignerMetrics::new());
        let svc = SignerServiceImpl::new_v2(
            Arc::new(MockBackend::empty()),
            "basic".to_string(),
            Arc::clone(&db),
        )
        .with_metrics(Arc::clone(&metrics));

        let pubkey = test_pubkey_bytes();
        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        assert_eq!(
            metrics
                .sign_total
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK, "error"])
                .get(),
            1
        );
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            1,
            "classify_gate_error must feed sign_errors_total for KeyNotFound"
        );
        // Encode scrape text after a failing gRPC sign (RF1-09 scrape AC / L1).
        let scrape = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(scrape.contains("rvc_signer_sign_errors_total"), "scrape: {scrape}");
        assert!(scrape.contains("key_not_found"), "scrape: {scrape}");
    }

    #[tokio::test]
    async fn test_v2_sign_double_proposal_records_slashing_error_type() {
        // M1: gate slashing rejections must not collapse to error_type=internal.
        let pubkey = test_pubkey_bytes();
        let (svc, metrics) = make_service_v2_with_metrics(MockBackend::with_test_key());

        let req1 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(100),
            fork_id: 4,
        });
        svc.sign_beacon_block(req1).await.unwrap();

        let mut different_ssz = sample_block_ssz(100);
        for b in &mut different_ssz[16..48] {
            *b ^= 0xFF;
        }
        let req2 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: different_ssz,
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req2).await.unwrap_err();
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );

        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "slashing"]).get(),
            1,
            "slashable rejection must record error_type=slashing (not internal)"
        );
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "internal"]).get(),
            0,
            "must not collapse slashing to internal"
        );
    }

    #[test]
    fn test_sign_recording_helper_no_ops_without_metrics() {
        // Free-standing helper is safe with None (also covered in metrics unit tests).
        // A7 absorption: the dispatcher calls this helper; handlers do not.
        use crate::metrics::record_sign;
        use std::time::Instant;
        record_sign(None, "basic", grpc_sign_type::BEACON_BLOCK, Instant::now(), Ok(()));
        record_sign(
            None,
            "basic",
            grpc_sign_type::BEACON_BLOCK,
            Instant::now(),
            Err("key_not_found"),
        );
    }

    /// A7 scrape gate: after a real gRPC sign via the dispatcher, the scrape
    /// text still contains the RF1-09 series (helper absorbed, not deleted).
    #[tokio::test]
    async fn test_a7_scrape_test_still_green() {
        let pubkey = test_pubkey_bytes();
        let (svc, metrics) = make_service_v2_with_metrics(MockBackend::with_test_key());
        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        svc.sign_beacon_block(req).await.unwrap();
        let scrape = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(scrape.contains("rvc_signer_sign_total"), "scrape: {scrape}");
        assert!(scrape.contains("rvc_signer_sign_duration_seconds"), "scrape: {scrape}");
        // sign_errors_total is always registered even when zero.
        assert!(scrape.contains("rvc_signer_sign_errors_total") || scrape.contains("sign_total"));
        assert!(scrape.contains("beacon_block"), "scrape: {scrape}");
        assert!(scrape.contains("success"), "scrape: {scrape}");
        assert_eq!(
            metrics
                .sign_total
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK, "success"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .sign_duration_seconds
                .with_label_values(&["basic", grpc_sign_type::BEACON_BLOCK])
                .get_sample_count(),
            1
        );
    }

    #[tokio::test]
    async fn test_all_v2_handlers_record_sign_total() {
        // Table-driven across all 10 RPCs so a future handler added without
        // recording fails the test (RF1-09 / D4 safety net).
        use eth_types::{
            encode_attestation_ssz, encode_blinded_beacon_block_ssz,
            encode_sync_committee_contribution_ssz, Attestation, AttestationData,
            BlindedBeaconBlock, Checkpoint, SyncCommitteeContribution,
        };

        let pubkey = test_pubkey_bytes();
        let (svc, metrics) = make_service_v2_with_metrics(MockBackend::with_test_key());

        // 1. beacon_block
        svc.sign_beacon_block(Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(1000),
            fork_id: 4,
        }))
        .await
        .expect("beacon_block");

        // 2. blinded_beacon_block
        let blinded = BlindedBeaconBlock {
            slot: 1001,
            proposer_index: 1,
            parent_root: [0x33; 32],
            state_root: [0x44; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        svc.sign_blinded_beacon_block(Request::new(SignBlindedBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: encode_blinded_beacon_block_ssz(&blinded, 4),
            fork_id: 4,
        }))
        .await
        .expect("blinded_beacon_block");

        // 3. randao_reveal
        svc.sign_randao_reveal(Request::new(SignRandaoRevealRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 10,
            fork_id: 4,
        }))
        .await
        .expect("randao_reveal");

        // 4. attestation_data
        svc.sign_attestation_data(Request::new(SignAttestationDataRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            data: Some(crate::proto::signer_v2::AttestationData {
                slot: 320,
                index: 0,
                beacon_block_root: vec![0x33u8; 32],
                source: Some(crate::proto::signer_v2::Checkpoint {
                    epoch: 9,
                    root: vec![0x44u8; 32],
                }),
                target: Some(crate::proto::signer_v2::Checkpoint {
                    epoch: 10,
                    root: vec![0x55u8; 32],
                }),
            }),
            fork_id: 4,
        }))
        .await
        .expect("attestation_data");

        // 5. aggregate_and_proof
        let att = Attestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot: 320,
                index: 0,
                beacon_block_root: [0x33u8; 32],
                source: Checkpoint { epoch: 9, root: [0x44u8; 32] },
                target: Checkpoint { epoch: 10, root: [0x55u8; 32] },
            },
            signature: vec![0xaa; 96],
        };
        svc.sign_aggregate_and_proof(Request::new(SignAggregateAndProofRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            aggregator_index: 42,
            aggregate_ssz: encode_attestation_ssz(&att, 4),
            selection_proof: vec![0xbb; 96],
            fork_id: 4,
        }))
        .await
        .expect("aggregate_and_proof");

        // 6. sync_committee_message
        svc.sign_sync_committee_message(Request::new(SignSyncCommitteeMessageRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            slot: 500,
            beacon_block_root: vec![0xBB; 32],
            fork_id: 4,
        }))
        .await
        .expect("sync_committee_message");

        // 7. sync_aggregator_selection_data
        svc.sign_sync_aggregator_selection_data(Request::new(
            SignSyncAggregatorSelectionDataRequest {
                pubkey: pubkey.to_vec(),
                fork_info: Some(sample_fork_info()),
                slot: 600,
                subcommittee_index: 3,
                fork_id: 4,
            },
        ))
        .await
        .expect("sync_aggregator_selection_data");

        // 8. contribution_and_proof
        let contrib = SyncCommitteeContribution {
            slot: 700,
            beacon_block_root: [0xBB; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xcc; 96],
        };
        svc.sign_contribution_and_proof(Request::new(SignContributionAndProofRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            aggregator_index: 42,
            contribution_ssz: encode_sync_committee_contribution_ssz(&contrib, 4),
            selection_proof: vec![0xcc; 96],
            fork_id: 4,
        }))
        .await
        .expect("contribution_and_proof");

        // 9. builder_registration
        svc.sign_builder_registration(Request::new(SignBuilderRegistrationRequest {
            pubkey: pubkey.to_vec(),
            fee_recipient: vec![0x11; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            genesis_fork_version: vec![],
        }))
        .await
        .expect("builder_registration");

        // 10. voluntary_exit
        svc.sign_voluntary_exit(Request::new(SignVoluntaryExitRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 100,
            validator_index: 7,
            fork_id: 4,
        }))
        .await
        .expect("voluntary_exit");

        // Every type in the bounded set must have recorded a success.
        assert_eq!(grpc_sign_type::ALL.len(), 10, "bounded type set must list all 10 RPCs");
        for rpc_type in grpc_sign_type::ALL {
            assert_eq!(
                metrics.sign_total.with_label_values(&["basic", rpc_type, "success"]).get(),
                1,
                "handler for type={rpc_type} must record sign_total success via shared helper"
            );
            assert!(
                metrics
                    .sign_duration_seconds
                    .with_label_values(&["basic", rpc_type])
                    .get_sample_count()
                    >= 1,
                "handler for type={rpc_type} must record duration"
            );
        }
    }

    // ── SEC-4: primary client-CN allow-list ───────────────────────────────────
    //
    // Without real TLS on the request, extract_client_cn returns "unknown".
    // That matches production when a cert has no parseable CN and is the same
    // harness the DVT peer_service tests use for unauth CN checks.

    fn make_service_v2_with_allow_list(backend: MockBackend, cns: &[&str]) -> SignerServiceImpl {
        let list = Arc::new(audit::ClientCnAllowList::from_cns(cns.iter().copied()));
        make_service_v2(backend).with_client_cn_allow_list(Some(list))
    }

    /// Non-allow-listed CN is rejected before signing; no signature is returned
    /// and an audit-log entry is emitted (`result=client_cn_not_allowed`).
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_non_allowlisted_cn_rejected_no_signature() {
        let pubkey = test_pubkey_bytes();
        // Allow-list does not include "unknown" (the no-TLS CN).
        let svc = make_service_v2_with_allow_list(MockBackend::with_test_key(), &["vc-A"]);

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(
            err.message().contains("not on the allow-list"),
            "unexpected message: {}",
            err.message()
        );
        assert!(
            logs_contain("client_cn_not_allowed") || logs_contain("sign request audit"),
            "expected audit-log entry on rejection"
        );
    }

    /// Allow-listed CN succeeds (no-TLS harness lists `"unknown"` explicitly).
    #[tokio::test]
    async fn test_allowlisted_cn_succeeds() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2_with_allow_list(MockBackend::with_test_key(), &["unknown"]);

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp = svc.sign_beacon_block(req).await.expect("allow-listed CN must sign");
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    /// No allow-list configured → request succeeds, and the startup warning
    /// helper emits the SEC-4 operator message.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_no_allowlist_configured_succeeds_with_startup_warning() {
        let pubkey = test_pubkey_bytes();
        // Default constructors leave client_cn_allow_list = None.
        let svc = make_service_v2(MockBackend::with_test_key());
        assert!(svc.client_cn_allow_list.is_none());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp = svc.sign_beacon_block(req).await.expect("no allow-list must accept");
        assert_eq!(resp.into_inner().signature.len(), 96);

        // Startup path (main.rs) calls this when --allowed-client-cns is unset.
        audit::log_missing_client_cn_allow_list_warning();
        assert!(
            logs_contain("No client-CN allow-list configured")
                || logs_contain("allowed-client-cns")
                || logs_contain("SEC-4"),
            "expected SEC-4 startup warning"
        );
    }

    /// DVT allow-list semantics stay independent of the primary path (SEC-4).
    /// Primary `ClientCnAllowList` and DVT `AllowedPeers` share exact CN match
    /// only; DVT still binds CN → share_index via its own loader/API.
    #[test]
    fn test_dvt_path_unchanged() {
        // Primary allow-list is CN-only and does not involve share_index.
        let primary = audit::ClientCnAllowList::from_cns(["peer-A"]);
        assert!(primary.contains("peer-A"));
        assert!(!primary.contains("peer-X"));

        // DVT AllowedPeers API (lookup + contains_cn) remains the authorization
        // primitive for PeerSignerServiceImpl; SEC-4 does not alter it.
        // When the dvt feature is off this still documents the contract via the
        // primary type; with dvt on we exercise AllowedPeers directly.
        #[cfg(feature = "dvt")]
        {
            use crate::dvt::allow_list::{AllowedPeer, AllowedPeers};
            let dvt = AllowedPeers {
                peers: vec![AllowedPeer {
                    peer_cn: "peer-A".to_string(),
                    share_index: 1,
                    addr: None,
                }],
            };
            assert!(dvt.contains_cn("peer-A"));
            assert_eq!(dvt.lookup_by_cn("peer-A").map(|p| p.share_index), Some(1));
            assert!(dvt.lookup_by_cn("peer-X").is_none());
            // share_index binding is DVT-only — primary has no equivalent field.
            assert_ne!(dvt.lookup_by_cn("peer-A").unwrap().share_index, 0);
        }
    }
}
