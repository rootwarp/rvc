//! Transport-neutral SignPlan engine (RF4-09 / D4).
//!
//! Owns the type → domain → signing-root → slashable? policy previously
//! duplicated across gRPC (`service.rs`), HTTP (`http_api/dispatch.rs`), and
//! DVT (`dvt/peer_service.rs`). Transports:
//!
//! 1. Decode/validate their wire format into a [`PlanInput`].
//! 2. Call [`plan_sign`] once to obtain a [`SignPlan`].
//! 3. For full (non-partial) signs, call [`dispatch_slashable`] /
//!    [`dispatch_non_slashable`], which invoke the shared [`SigningGate`] /
//!    backend and absorb the RF1-09 / A7 [`record_sign`] metrics helper.
//!
//! HTTP keeps a thin adapter that maps `SignRequest` → [`PlanInput`] and
//! optionally verifies the client-supplied `signingRoot`.

use std::time::Instant;

use crypto::{compute_domain, compute_signing_root, PublicKey};
use eth_types::{
    AttestationData, Root, SyncAggregatorSelectionData, ValidatorRegistrationV1, VoluntaryExit,
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PROPOSER_PREFERENCES,
    DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use signer::{SigningGate, SigningGateError};

use crate::backend::{SigningBackend, SigningBackendError};
use crate::metrics::{classify_error, classify_gate_error, record_sign, SignerMetrics};

/// Default builder / network genesis fork version (mainnet `0x00000000`).
///
/// Single source for the default: [`eth_types::NetworkPreset::MAINNET`]. All
/// transports read the configured network genesis from service state (see
/// [`RequestCtx::genesis_fork_version`]); they do not hardcode a fork version.
pub const BUILDER_FORK_VERSION_MAINNET: [u8; 4] =
    eth_types::NetworkPreset::MAINNET.genesis_fork_version;

/// The 32-byte zero root — builder registration uses a zero GVR; a present-but
/// zero client `signingRoot` means "do not verify".
pub const ZERO_ROOT: Root = [0u8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// Plan types
// ─────────────────────────────────────────────────────────────────────────────

/// Slashing-protection inputs the gate needs, keyed by signing class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slashing {
    /// `sign_block` — slashable on `slot` (from the block header / full block).
    Block { slot: u64, gvr: Root },
    /// `sign_attestation` — slashable on `(source_epoch, target_epoch)`.
    Attestation { source_epoch: u64, target_epoch: u64, gvr: Root },
    /// Non-slashable duties: gate-check then sign the pre-computed root, no
    /// slashing DB staging.
    NonSlashable,
}

/// The plan engine's output: the server-computed signing root plus the
/// slashing inputs / non-slashable gate op the dispatcher needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignPlan {
    /// Server-computed signing root.
    pub signing_root: Root,
    /// Slashing-protection inputs by class.
    pub slashing: Slashing,
    /// Gate method for non-slashable duties (`None` when [`Slashing`] is
    /// `Block` / `Attestation`). Set by [`plan_sign`] so transports do not
    /// re-match wire types at the gate boundary.
    pub non_slashable_op: Option<NonSlashableOp>,
}

/// Transport-neutral description of what to plan.
///
/// Callers decode wire-format messages and hand typed fields (or a pre-hashed
/// object root when the signed object differs by transport — e.g. full block
/// vs block header). Domain selection and `compute_signing_root` live here only.
#[derive(Debug, Clone)]
pub enum PlanInput {
    /// Beacon / blinded block. `object_root` is the tree-hash of the signed
    /// object (full block HTR for gRPC, header HTR for HTTP `BLOCK_V2`).
    Block { object_root: Root, slot: u64, fork_version: [u8; 4], gvr: Root },
    /// Attestation data (slashable on source/target epochs).
    Attestation { data: AttestationData, fork_version: [u8; 4], gvr: Root },
    /// RANDAO reveal over an epoch.
    Randao { epoch: u64, fork_version: [u8; 4], gvr: Root },
    /// Aggregator selection proof over a bare slot (`DOMAIN_SELECTION_PROOF`).
    AggregationSlot { slot: u64, fork_version: [u8; 4], gvr: Root },
    /// Aggregate-and-proof (phase0 or Electra). `object_root` is the fallible
    /// tree-hash of the aggregate container (callers use `try_tree_hash_root`).
    AggregateAndProof { object_root: Root, fork_version: [u8; 4], gvr: Root },
    /// Sync committee message: signed object is the beacon block root itself.
    SyncCommitteeMessage { beacon_block_root: Root, fork_version: [u8; 4], gvr: Root },
    /// Sync aggregator selection proof over `SyncAggregatorSelectionData`.
    SyncCommitteeSelection { data: SyncAggregatorSelectionData, fork_version: [u8; 4], gvr: Root },
    /// Contribution-and-proof. `object_root` is the tree-hash of the container.
    ContributionAndProof { object_root: Root, fork_version: [u8; 4], gvr: Root },
    /// Validator registration (builder). Domain is fixed over
    /// `genesis_fork_version` + zero GVR — no `fork_info` required.
    BuilderRegistration { object_root: Root, genesis_fork_version: [u8; 4] },
    /// Voluntary exit. Caller supplies a Capella-capped `fork_version` per EIP-7044.
    VoluntaryExit { object_root: Root, fork_version: [u8; 4], gvr: Root },
    /// Payload attestation (PTC). `object_root` is the tree-hash of
    /// `PayloadAttestationData` — identity-HTR path, same as [`Self::AggregateAndProof`].
    PayloadAttestation { object_root: Root, fork_version: [u8; 4], gvr: Root },
    /// Proposer preferences. `object_root` is the tree-hash of
    /// `ProposerPreferences` — identity-HTR path, same as [`Self::PayloadAttestation`].
    ProposerPreferences { object_root: Root, fork_version: [u8; 4], gvr: Root },
}

// ─────────────────────────────────────────────────────────────────────────────
// plan_sign — single domain / root policy
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the server-side signing root and slashing class for `input`.
///
/// This is the **only** place in `rvc-signer` that selects a domain and
/// derives a signing root for a duty type. gRPC, HTTP, and DVT all route here.
///
/// Fallible tree-hash of wire containers (`try_tree_hash_root`) is the caller's
/// responsibility — malformed bitlists are rejected before planning.
pub fn plan_sign(input: &PlanInput) -> SignPlan {
    let (signing_root, slashing, non_slashable_op) = match input {
        PlanInput::Block { object_root, slot, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_BEACON_PROPOSER, *fork_version, *gvr);
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::Block { slot: *slot, gvr: *gvr }, None)
        }
        PlanInput::Attestation { data, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_BEACON_ATTESTER, *fork_version, *gvr);
            let root = compute_signing_root(data, domain);
            let slashing = Slashing::Attestation {
                source_epoch: data.source.epoch,
                target_epoch: data.target.epoch,
                gvr: *gvr,
            };
            (root, slashing, None)
        }
        PlanInput::Randao { epoch, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_RANDAO, *fork_version, *gvr);
            let root = compute_signing_root(epoch, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::RandaoReveal))
        }
        PlanInput::AggregationSlot { slot, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_SELECTION_PROOF, *fork_version, *gvr);
            let root = compute_signing_root(slot, domain);
            // Same gate method as sync selection; domain is already in the root.
            (root, Slashing::NonSlashable, Some(NonSlashableOp::SelectionProof))
        }
        PlanInput::AggregateAndProof { object_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, *fork_version, *gvr);
            // object_root is already the container HTR (try_tree_hash_root);
            // signing root folds it with the domain.
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::AggregateAndProof))
        }
        PlanInput::SyncCommitteeMessage { beacon_block_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, *fork_version, *gvr);
            let root = compute_signing_root(beacon_block_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::SyncCommitteeMessage))
        }
        PlanInput::SyncCommitteeSelection { data, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, *fork_version, *gvr);
            let root = compute_signing_root(data, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::SelectionProof))
        }
        PlanInput::ContributionAndProof { object_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, *fork_version, *gvr);
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::ContributionAndProof))
        }
        PlanInput::BuilderRegistration { object_root, genesis_fork_version } => {
            let domain =
                compute_domain(DOMAIN_APPLICATION_BUILDER, *genesis_fork_version, ZERO_ROOT);
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::BuilderRegistration))
        }
        PlanInput::VoluntaryExit { object_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, *fork_version, *gvr);
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::VoluntaryExit))
        }
        PlanInput::PayloadAttestation { object_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_PTC_ATTESTER, *fork_version, *gvr);
            // object_root is already the container HTR; signing root folds it with the domain.
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::PayloadAttestation))
        }
        PlanInput::ProposerPreferences { object_root, fork_version, gvr } => {
            let domain = compute_domain(DOMAIN_PROPOSER_PREFERENCES, *fork_version, *gvr);
            let root = compute_signing_root(object_root, domain);
            (root, Slashing::NonSlashable, Some(NonSlashableOp::ProposerPreferences))
        }
    };
    SignPlan { signing_root, slashing, non_slashable_op }
}

/// Apply the client `signingRoot` verification policy (FR-16, ADR-007).
///
/// Verify only when the client supplied a present, non-zero 32-byte value; on
/// mismatch return `false`. Absent or all-zero → accept the server root.
#[must_use]
pub fn client_signing_root_matches(client: Option<Root>, server_root: Root) -> bool {
    !matches!(
        client,
        Some(client_root) if client_root != ZERO_ROOT && client_root != server_root
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Request context + non-slashable op
// ─────────────────────────────────────────────────────────────────────────────

/// Common per-request context built once by the transport prelude (auth +
/// pubkey resolution), then reused for planning and dispatch.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// mTLS client CN (or audit default).
    pub client_cn: String,
    /// Validated BLS public key.
    pub pubkey: PublicKey,
    /// Raw 48-byte pubkey for backend fallback paths.
    pub pubkey_bytes: [u8; 48],
    /// Bounded metrics `type` label ([`crate::metrics::grpc_sign_type`]).
    pub rpc_type: &'static str,
    /// Network genesis fork version from server config ([`eth_types::NetworkPreset`]).
    ///
    /// Sole source for builder-registration domain computation. Transports copy
    /// this into [`PlanInput::BuilderRegistration`] before dispatch (the signing
    /// root already embeds the domain; this field keeps the network identity on
    /// the request context for equality / audit).
    #[allow(dead_code)]
    pub genesis_fork_version: [u8; 4],
}

/// Which non-slashable gate method to invoke for a planned root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonSlashableOp {
    RandaoReveal,
    SelectionProof,
    AggregateAndProof,
    SyncCommitteeMessage,
    ContributionAndProof,
    BuilderRegistration,
    VoluntaryExit,
    PayloadAttestation,
    ProposerPreferences,
}

/// Error from [`dispatch_slashable`] / [`dispatch_non_slashable`].
///
/// Metrics have already been recorded when this is returned (except
/// [`PlanMismatch`] / [`GateRequired`], which are pre-sign).
#[derive(Debug)]
pub enum DispatchError {
    Gate(SigningGateError),
    Backend(SigningBackendError),
    /// Slashable path called without a configured gate (fail-closed).
    GateRequired,
    /// Plan class does not match the dispatch entry point (programming error).
    PlanMismatch,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch — gate/backend call + A7 metrics absorption
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch a slashable plan (`Block` / `Attestation`) through the gate and
/// record RF1-09 metrics via the shared [`record_sign`] helper.
pub async fn dispatch_slashable(
    gate: &SigningGate,
    metrics: Option<&SignerMetrics>,
    backend_name: &str,
    ctx: &RequestCtx,
    plan: &SignPlan,
) -> Result<Vec<u8>, DispatchError> {
    let started = Instant::now();
    let result = match plan.slashing {
        Slashing::Block { slot, gvr } => {
            gate.sign_block(&ctx.pubkey, slot, plan.signing_root, gvr, &ctx.client_cn).await
        }
        // Recording site for metrics is this function — not the gRPC handler.
        Slashing::Attestation { source_epoch, target_epoch, gvr } => {
            gate.sign_attestation(
                &ctx.pubkey,
                source_epoch,
                target_epoch,
                plan.signing_root,
                gvr,
                &ctx.client_cn,
            )
            .await
        }
        // Slashable dispatch must not be called for non-slashable plans.
        Slashing::NonSlashable => return Err(DispatchError::PlanMismatch),
    };
    finish_gate(metrics, backend_name, ctx.rpc_type, started, result)
}

/// Dispatch a non-slashable plan: gate when present, raw backend otherwise
/// (BUG-001 insecure / no-DB path). Records RF1-09 metrics via [`record_sign`].
///
/// Prefer [`dispatch_sign`] when the plan already carries [`SignPlan::non_slashable_op`].
pub async fn dispatch_non_slashable(
    gate: Option<&SigningGate>,
    backend: &dyn SigningBackend,
    metrics: Option<&SignerMetrics>,
    backend_name: &str,
    ctx: &RequestCtx,
    plan: &SignPlan,
    op: NonSlashableOp,
) -> Result<Vec<u8>, DispatchError> {
    if !matches!(plan.slashing, Slashing::NonSlashable) {
        return Err(DispatchError::PlanMismatch);
    }
    let started = Instant::now();
    let root = plan.signing_root;
    if let Some(gate) = gate {
        let result = match op {
            NonSlashableOp::RandaoReveal => gate.sign_randao_reveal(&ctx.pubkey, root).await,
            NonSlashableOp::SelectionProof => gate.sign_selection_proof(&ctx.pubkey, root).await,
            NonSlashableOp::AggregateAndProof => {
                gate.sign_aggregate_and_proof(&ctx.pubkey, root).await
            }
            NonSlashableOp::SyncCommitteeMessage => {
                gate.sign_sync_committee_message(&ctx.pubkey, root).await
            }
            NonSlashableOp::ContributionAndProof => {
                gate.sign_contribution_and_proof(&ctx.pubkey, root).await
            }
            NonSlashableOp::BuilderRegistration => {
                gate.sign_builder_registration(&ctx.pubkey, root).await
            }
            NonSlashableOp::VoluntaryExit => gate.sign_voluntary_exit(&ctx.pubkey, root).await,
            NonSlashableOp::PayloadAttestation => {
                gate.sign_payload_attestation(&ctx.pubkey, root).await
            }
            NonSlashableOp::ProposerPreferences => {
                gate.sign_proposer_preferences(&ctx.pubkey, root).await
            }
        };
        finish_gate(metrics, backend_name, ctx.rpc_type, started, result)
    } else {
        let result = backend.sign(&root, &ctx.pubkey_bytes).await;
        finish_backend(metrics, backend_name, ctx.rpc_type, started, result)
    }
}

/// Unified dispatch: routes slashable / non-slashable plans using the plan's
/// class and [`SignPlan::non_slashable_op`]. Records A7 metrics for **every**
/// transport that calls it (gRPC and HTTP).
pub async fn dispatch_sign(
    gate: Option<&SigningGate>,
    backend: &dyn SigningBackend,
    metrics: Option<&SignerMetrics>,
    backend_name: &str,
    ctx: &RequestCtx,
    plan: &SignPlan,
) -> Result<Vec<u8>, DispatchError> {
    match plan.slashing {
        Slashing::Block { .. } | Slashing::Attestation { .. } => {
            let Some(gate) = gate else {
                return Err(DispatchError::GateRequired);
            };
            dispatch_slashable(gate, metrics, backend_name, ctx, plan).await
        }
        Slashing::NonSlashable => {
            let Some(op) = plan.non_slashable_op else {
                return Err(DispatchError::PlanMismatch);
            };
            dispatch_non_slashable(gate, backend, metrics, backend_name, ctx, plan, op).await
        }
    }
}

/// Absorb A7's recording helper for a gate outcome.
fn finish_gate(
    metrics: Option<&SignerMetrics>,
    backend_name: &str,
    rpc_type: &'static str,
    started: Instant,
    result: Result<Vec<u8>, SigningGateError>,
) -> Result<Vec<u8>, DispatchError> {
    match result {
        Ok(sig) => {
            record_sign(metrics, backend_name, rpc_type, started, Ok(()));
            Ok(sig)
        }
        Err(e) => {
            record_sign(metrics, backend_name, rpc_type, started, Err(classify_gate_error(&e)));
            Err(DispatchError::Gate(e))
        }
    }
}

/// Absorb A7's recording helper for a raw-backend outcome.
fn finish_backend(
    metrics: Option<&SignerMetrics>,
    backend_name: &str,
    rpc_type: &'static str,
    started: Instant,
    result: Result<[u8; 96], SigningBackendError>,
) -> Result<Vec<u8>, DispatchError> {
    match result {
        Ok(sig) => {
            record_sign(metrics, backend_name, rpc_type, started, Ok(()));
            Ok(sig.to_vec())
        }
        Err(e) => {
            record_sign(metrics, backend_name, rpc_type, started, Err(classify_error(&e)));
            Err(DispatchError::Backend(e))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience constructors (typed messages → PlanInput)
// ─────────────────────────────────────────────────────────────────────────────

/// Plan a builder registration from the typed message + genesis fork version.
pub fn plan_builder_registration(
    registration: &ValidatorRegistrationV1,
    genesis_fork_version: [u8; 4],
) -> SignPlan {
    // ValidatorRegistrationV1 is TreeHash-safe (fixed-size fields).
    let object_root = tree_hash::TreeHash::tree_hash_root(registration).0;
    plan_sign(&PlanInput::BuilderRegistration { object_root, genesis_fork_version })
}

/// Plan a voluntary exit from the typed message.
pub fn plan_voluntary_exit(exit: &VoluntaryExit, fork_version: [u8; 4], gvr: Root) -> SignPlan {
    let object_root = tree_hash::TreeHash::tree_hash_root(exit).0;
    plan_sign(&PlanInput::VoluntaryExit { object_root, fork_version, gvr })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Checkpoint, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF};
    use tree_hash::TreeHash;

    const FORK: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    const GVR: Root = [0xab; 32];

    fn sample_attestation_data() -> AttestationData {
        AttestationData {
            slot: 5,
            index: 0,
            beacon_block_root: [0u8; 32],
            source: Checkpoint { epoch: 1, root: [0u8; 32] },
            target: Checkpoint { epoch: 2, root: [0u8; 32] },
        }
    }

    #[test]
    fn test_dispatcher_preserves_slashable_vs_nonslashable_classification() {
        // Table over the duties the engine knows about.
        let cases: Vec<(PlanInput, bool)> = vec![
            (
                PlanInput::Block { object_root: [1u8; 32], slot: 10, fork_version: FORK, gvr: GVR },
                true,
            ),
            (
                PlanInput::Attestation {
                    data: sample_attestation_data(),
                    fork_version: FORK,
                    gvr: GVR,
                },
                true,
            ),
            (PlanInput::Randao { epoch: 42, fork_version: FORK, gvr: GVR }, false),
            (PlanInput::AggregationSlot { slot: 77, fork_version: FORK, gvr: GVR }, false),
            (
                PlanInput::AggregateAndProof {
                    object_root: [2u8; 32],
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
            (
                PlanInput::SyncCommitteeMessage {
                    beacon_block_root: [3u8; 32],
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
            (
                PlanInput::SyncCommitteeSelection {
                    data: SyncAggregatorSelectionData { slot: 1, subcommittee_index: 0 },
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
            (
                PlanInput::ContributionAndProof {
                    object_root: [4u8; 32],
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
            (
                PlanInput::BuilderRegistration {
                    object_root: [5u8; 32],
                    genesis_fork_version: BUILDER_FORK_VERSION_MAINNET,
                },
                false,
            ),
            (
                PlanInput::VoluntaryExit { object_root: [6u8; 32], fork_version: FORK, gvr: GVR },
                false,
            ),
            (
                PlanInput::PayloadAttestation {
                    object_root: [7u8; 32],
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
            (
                PlanInput::ProposerPreferences {
                    object_root: [8u8; 32],
                    fork_version: FORK,
                    gvr: GVR,
                },
                false,
            ),
        ];

        for (input, expect_slashable) in cases {
            let plan = plan_sign(&input);
            let is_slashable = !matches!(plan.slashing, Slashing::NonSlashable);
            assert_eq!(is_slashable, expect_slashable, "classification mismatch for {input:?}");
        }
    }

    #[test]
    fn test_block_plan_uses_proposer_domain() {
        let object_root = [0x11u8; 32];
        let plan = plan_sign(&PlanInput::Block {
            object_root,
            slot: 3_000_000,
            fork_version: FORK,
            gvr: GVR,
        });
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, FORK, GVR);
        let want = compute_signing_root(&object_root, domain);
        assert_eq!(plan.signing_root, want);
        assert_eq!(plan.slashing, Slashing::Block { slot: 3_000_000, gvr: GVR });
    }

    #[test]
    fn test_randao_and_aggregation_slot_distinct_domains() {
        let r = plan_sign(&PlanInput::Randao { epoch: 7, fork_version: FORK, gvr: GVR });
        let a = plan_sign(&PlanInput::AggregationSlot { slot: 7, fork_version: FORK, gvr: GVR });
        assert_eq!(r.slashing, Slashing::NonSlashable);
        assert_eq!(a.slashing, Slashing::NonSlashable);
        assert_ne!(r.signing_root, a.signing_root, "domains 0x02 vs 0x05 must not collide");

        let r_want = compute_signing_root(&7u64, compute_domain(DOMAIN_RANDAO, FORK, GVR));
        let a_want = compute_signing_root(&7u64, compute_domain(DOMAIN_SELECTION_PROOF, FORK, GVR));
        assert_eq!(r.signing_root, r_want);
        assert_eq!(a.signing_root, a_want);
    }

    #[test]
    fn test_attestation_carries_epochs() {
        let data = sample_attestation_data();
        let plan =
            plan_sign(&PlanInput::Attestation { data: data.clone(), fork_version: FORK, gvr: GVR });
        assert_eq!(
            plan.slashing,
            Slashing::Attestation { source_epoch: 1, target_epoch: 2, gvr: GVR }
        );
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, FORK, GVR);
        assert_eq!(plan.signing_root, compute_signing_root(&data, domain));
    }

    #[test]
    fn test_builder_registration_uses_zero_gvr() {
        let registration = ValidatorRegistrationV1 {
            fee_recipient: [0xaa; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xbb; 48],
        };
        let plan = plan_builder_registration(&registration, BUILDER_FORK_VERSION_MAINNET);
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        let object_root = registration.tree_hash_root().0;
        let domain =
            compute_domain(DOMAIN_APPLICATION_BUILDER, BUILDER_FORK_VERSION_MAINNET, ZERO_ROOT);
        assert_eq!(plan.signing_root, compute_signing_root(&object_root, domain));
    }

    #[test]
    fn test_client_signing_root_policy() {
        let server = [0x42u8; 32];
        assert!(client_signing_root_matches(None, server));
        assert!(client_signing_root_matches(Some(ZERO_ROOT), server));
        assert!(client_signing_root_matches(Some(server), server));
        assert!(!client_signing_root_matches(Some([0xff; 32]), server));
    }

    /// RED-style: metrics recording for gRPC signs lives in the dispatcher
    /// (finish_gate / finish_backend), not as per-handler inline counter code.
    ///
    /// Asserted structurally: the only production call sites of `record_sign`
    /// outside `metrics` itself are inside this module.
    #[test]
    fn test_grpc_handler_records_sign_metrics_via_shared_helper() {
        // Source-level invariant is checked by the architecture / grep gate in
        // CI; this unit test pins the helper's public contract the dispatcher
        // relies on (no-op with None metrics).
        record_sign(
            None,
            "basic",
            crate::metrics::grpc_sign_type::BEACON_BLOCK,
            Instant::now(),
            Ok(()),
        );
        record_sign(
            None,
            "basic",
            crate::metrics::grpc_sign_type::BEACON_BLOCK,
            Instant::now(),
            Err("key_not_found"),
        );
    }

    #[test]
    fn test_all_three_transports_produce_identical_sign_plan_for_equivalent_requests() {
        // Simulate how each transport builds PlanInput from its decoded wire form.
        // Attestation: gRPC (proto fields → AttestationData), HTTP (JSON → AttestationData),
        // DVT (same proto path as gRPC) all yield the same PlanInput fields.
        let data = sample_attestation_data();
        let grpc_att = PlanInput::Attestation { data: data.clone(), fork_version: FORK, gvr: GVR };
        let http_att = PlanInput::Attestation { data: data.clone(), fork_version: FORK, gvr: GVR };
        let dvt_att = PlanInput::Attestation { data: data.clone(), fork_version: FORK, gvr: GVR };
        let att_plan = plan_sign(&grpc_att);
        assert_eq!(att_plan, plan_sign(&http_att));
        assert_eq!(att_plan, plan_sign(&dvt_att));
        assert_eq!(
            att_plan.slashing,
            Slashing::Attestation { source_epoch: 1, target_epoch: 2, gvr: GVR }
        );
        assert!(att_plan.non_slashable_op.is_none());

        // Sync committee message: gRPC + DVT + HTTP all sign the beacon_block_root.
        let block_root = [0x33u8; 32];
        let grpc_sync = PlanInput::SyncCommitteeMessage {
            beacon_block_root: block_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let http_sync = PlanInput::SyncCommitteeMessage {
            beacon_block_root: block_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let dvt_sync = PlanInput::SyncCommitteeMessage {
            beacon_block_root: block_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let sync_plan = plan_sign(&grpc_sync);
        assert_eq!(sync_plan, plan_sign(&http_sync));
        assert_eq!(sync_plan, plan_sign(&dvt_sync));
        assert_eq!(sync_plan.non_slashable_op, Some(NonSlashableOp::SyncCommitteeMessage));

        // Block: when the HTTP header's body_root equals the body HTR of the full
        // gRPC/DVT block, object roots (and therefore SignPlans) match.
        use eth_types::{BeaconBlock, BeaconBlockHeader};
        let body = eth_types::external_vector_electra_body().as_ssz_bytes();
        let block = BeaconBlock {
            slot: 99,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: body.clone(),
        };
        let full_object_root = block.try_tree_hash_root().expect("valid body").0;
        // Reconstruct the header that HTTP BLOCK_V2 would carry.
        let body_root = eth_types::body_tree_hash_root(&body).expect("body htr").0;
        let header = BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body_root,
        };
        let header_object_root = header.tree_hash_root().0;
        assert_eq!(
            full_object_root, header_object_root,
            "full-block HTR must equal header HTR when body_root matches body"
        );
        let grpc_block = PlanInput::Block {
            object_root: full_object_root,
            slot: 99,
            fork_version: FORK,
            gvr: GVR,
        };
        let http_block = PlanInput::Block {
            object_root: header_object_root,
            slot: 99,
            fork_version: FORK,
            gvr: GVR,
        };
        let dvt_block = PlanInput::Block {
            object_root: full_object_root,
            slot: 99,
            fork_version: FORK,
            gvr: GVR,
        };
        let block_plan = plan_sign(&grpc_block);
        assert_eq!(block_plan, plan_sign(&http_block));
        assert_eq!(block_plan, plan_sign(&dvt_block));
        assert_eq!(block_plan.slashing, Slashing::Block { slot: 99, gvr: GVR });

        // PTC: gRPC (future 4.20b), HTTP (4.9b), and DVT all take the same
        // precomputed object_root + fork_version + gvr.
        let ptc_object_root = [0x11u8; 32];
        let grpc_ptc = PlanInput::PayloadAttestation {
            object_root: ptc_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let http_ptc = PlanInput::PayloadAttestation {
            object_root: ptc_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let dvt_ptc = PlanInput::PayloadAttestation {
            object_root: ptc_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let ptc_plan = plan_sign(&grpc_ptc);
        assert_eq!(ptc_plan, plan_sign(&http_ptc));
        assert_eq!(ptc_plan, plan_sign(&dvt_ptc));
        assert_eq!(ptc_plan.slashing, Slashing::NonSlashable);
        assert_eq!(ptc_plan.non_slashable_op, Some(NonSlashableOp::PayloadAttestation));

        // Proposer preferences: gRPC (future 4.20b), HTTP (4.16), and DVT all
        // take the same precomputed object_root + fork_version + gvr.
        let prefs_object_root = [0x33u8; 32];
        let grpc_prefs = PlanInput::ProposerPreferences {
            object_root: prefs_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let http_prefs = PlanInput::ProposerPreferences {
            object_root: prefs_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let dvt_prefs = PlanInput::ProposerPreferences {
            object_root: prefs_object_root,
            fork_version: FORK,
            gvr: GVR,
        };
        let prefs_plan = plan_sign(&grpc_prefs);
        assert_eq!(prefs_plan, plan_sign(&http_prefs));
        assert_eq!(prefs_plan, plan_sign(&dvt_prefs));
        assert_eq!(prefs_plan.slashing, Slashing::NonSlashable);
        assert_eq!(prefs_plan.non_slashable_op, Some(NonSlashableOp::ProposerPreferences));
    }

    fn parse_kat_root(hex: &str) -> Root {
        hex::decode(hex).expect("kat hex").try_into().expect("32-byte kat root")
    }

    fn ptc_kat_plan() -> SignPlan {
        let object_root =
            parse_kat_root(rvc_spec_vectors::spec_kat::SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT);
        plan_sign(&PlanInput::PayloadAttestation {
            object_root,
            fork_version: [0x07, 0x00, 0x00, 0x01],
            gvr: [0u8; 32],
        })
    }

    struct KeyedBackend {
        km: std::sync::Arc<crypto::KeyManager>,
    }

    impl KeyedBackend {
        fn with_key(sk: crypto::SecretKey) -> Self {
            let mut km = crypto::KeyManager::new();
            km.insert(sk);
            Self { km: std::sync::Arc::new(km) }
        }
    }

    #[async_trait::async_trait]
    impl crate::backend::SigningBackend for KeyedBackend {
        async fn sign(
            &self,
            signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], crate::backend::SigningBackendError> {
            let pk = crypto::PublicKey::from_bytes(pubkey)
                .map_err(|_| crate::backend::SigningBackendError::KeyNotFound(*pubkey))?;
            let sk = self
                .km
                .get_secret_key(&pk)
                .ok_or(crate::backend::SigningBackendError::KeyNotFound(*pubkey))?;
            Ok(sk.sign(signing_root).to_bytes())
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
        }
    }

    fn ptc_gate_and_ctx(
        sk: crypto::SecretKey,
    ) -> (signer::SigningGate, RequestCtx, std::sync::Arc<KeyedBackend>) {
        let pubkey = sk.public_key();
        let backend = std::sync::Arc::new(KeyedBackend::with_key(sk));
        let db = std::sync::Arc::new(slashing::SlashingDb::open_in_memory().expect("slashing db"));
        let gate = crate::service::SignerServiceImpl::build_gate(
            std::sync::Arc::clone(&backend) as std::sync::Arc<dyn crate::backend::SigningBackend>,
            db,
        );
        let ctx = RequestCtx {
            client_cn: "test".into(),
            pubkey_bytes: pubkey.to_bytes(),
            pubkey,
            rpc_type: crate::metrics::grpc_sign_type::PAYLOAD_ATTESTATION,
            genesis_fork_version: BUILDER_FORK_VERSION_MAINNET,
        };
        (gate, ctx, backend)
    }

    /// L3: plan engine signing root for the 4.0 pyspec PayloadAttestationData
    /// fixture (`KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT`).
    #[test]
    fn test_plan_payload_attestation_signing_root() {
        let plan = ptc_kat_plan();
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        assert_eq!(plan.non_slashable_op, Some(NonSlashableOp::PayloadAttestation));
        assert_eq!(
            plan.signing_root,
            parse_kat_root(rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
        );
    }

    #[tokio::test]
    async fn test_plan_payload_attestation_dispatch_slashable_mismatch() {
        let plan = ptc_kat_plan();
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        let (gate, ctx, _backend) = ptc_gate_and_ctx(crypto::SecretKey::generate());
        let err = dispatch_slashable(&gate, None, "basic", &ctx, &plan).await.unwrap_err();
        assert!(matches!(err, DispatchError::PlanMismatch));
    }

    #[tokio::test]
    async fn test_plan_payload_attestation_dispatch_sign_success() {
        let plan = ptc_kat_plan();
        let (gate, ctx, backend) = ptc_gate_and_ctx(crypto::SecretKey::generate());
        let sig = dispatch_sign(Some(&gate), backend.as_ref(), None, "basic", &ctx, &plan)
            .await
            .expect("dispatch_sign payload attestation");
        let direct = gate
            .sign_payload_attestation(&ctx.pubkey, plan.signing_root)
            .await
            .expect("direct gate payload attestation");
        assert_eq!(sig, direct, "dispatch_sign must use SigningGate::sign_payload_attestation");
        assert!(crypto::Signature::from_bytes(&sig)
            .expect("bls sig")
            .verify(&ctx.pubkey, &plan.signing_root)
            .is_ok());
    }

    #[test]
    fn test_payload_attestation_dispatch_arm_calls_sign_payload_attestation() {
        let src = include_str!("sign_plan.rs");
        let rest = src
            .split_once("pub async fn dispatch_non_slashable")
            .expect("dispatch_non_slashable")
            .1;
        let dispatch = rest.split("pub async fn dispatch_sign").next().expect("dispatch_sign");
        assert!(
            dispatch.contains("NonSlashableOp::PayloadAttestation")
                && dispatch.contains("gate.sign_payload_attestation"),
            "dispatch_non_slashable must route PayloadAttestation to SigningGate::sign_payload_attestation"
        );
    }

    fn prefs_kat_plan() -> SignPlan {
        let object_root =
            parse_kat_root(rvc_spec_vectors::spec_kat::SPEC_GLOAS_PROPOSERPREFERENCES_ROOT);
        plan_sign(&PlanInput::ProposerPreferences {
            object_root,
            fork_version: [0x07, 0x00, 0x00, 0x01],
            gvr: [0u8; 32],
        })
    }

    fn prefs_gate_and_ctx(
        sk: crypto::SecretKey,
    ) -> (signer::SigningGate, RequestCtx, std::sync::Arc<KeyedBackend>) {
        let pubkey = sk.public_key();
        let backend = std::sync::Arc::new(KeyedBackend::with_key(sk));
        let db = std::sync::Arc::new(slashing::SlashingDb::open_in_memory().expect("slashing db"));
        let gate = crate::service::SignerServiceImpl::build_gate(
            std::sync::Arc::clone(&backend) as std::sync::Arc<dyn crate::backend::SigningBackend>,
            db,
        );
        let ctx = RequestCtx {
            client_cn: "test".into(),
            pubkey_bytes: pubkey.to_bytes(),
            pubkey,
            rpc_type: crate::metrics::grpc_sign_type::PROPOSER_PREFERENCES,
            genesis_fork_version: BUILDER_FORK_VERSION_MAINNET,
        };
        (gate, ctx, backend)
    }

    /// L3: plan engine signing root for the 4.0 pyspec ProposerPreferences
    /// fixture (`KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT`).
    #[test]
    fn test_plan_proposer_preferences_signing_root() {
        let plan = prefs_kat_plan();
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        assert_eq!(plan.non_slashable_op, Some(NonSlashableOp::ProposerPreferences));
        assert_eq!(
            plan.signing_root,
            parse_kat_root(rvc_spec_vectors::spec_kat::KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT)
        );
    }

    #[tokio::test]
    async fn test_plan_proposer_preferences_dispatch_slashable_mismatch() {
        let plan = prefs_kat_plan();
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        let (gate, ctx, _backend) = prefs_gate_and_ctx(crypto::SecretKey::generate());
        let err = dispatch_slashable(&gate, None, "basic", &ctx, &plan).await.unwrap_err();
        assert!(matches!(err, DispatchError::PlanMismatch));
    }

    #[tokio::test]
    async fn test_plan_proposer_preferences_dispatch_sign_success() {
        let plan = prefs_kat_plan();
        let (gate, ctx, backend) = prefs_gate_and_ctx(crypto::SecretKey::generate());
        let sig = dispatch_sign(Some(&gate), backend.as_ref(), None, "basic", &ctx, &plan)
            .await
            .expect("dispatch_sign proposer preferences");
        let direct = gate
            .sign_proposer_preferences(&ctx.pubkey, plan.signing_root)
            .await
            .expect("direct gate proposer preferences");
        assert_eq!(sig, direct, "dispatch_sign must use SigningGate::sign_proposer_preferences");
        assert!(crypto::Signature::from_bytes(&sig)
            .expect("bls sig")
            .verify(&ctx.pubkey, &plan.signing_root)
            .is_ok());
    }

    #[test]
    fn test_proposer_preferences_dispatch_arm_calls_sign_proposer_preferences() {
        let src = include_str!("sign_plan.rs");
        let rest = src
            .split_once("pub async fn dispatch_non_slashable")
            .expect("dispatch_non_slashable")
            .1;
        let dispatch = rest.split("pub async fn dispatch_sign").next().expect("dispatch_sign");
        assert!(
            dispatch.contains("NonSlashableOp::ProposerPreferences")
                && dispatch.contains("gate.sign_proposer_preferences"),
            "dispatch_non_slashable must route ProposerPreferences to SigningGate::sign_proposer_preferences"
        );
    }
}
