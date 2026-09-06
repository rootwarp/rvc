//! Compile-time registry of every gRPC signing entry point on `rvc-signer`.
//!
//! DEV-ONLY (ADR-010): this crate MUST remain a `[dev-dependencies]` entry only.
//! Promoting it to `[dependencies]` in any production crate violates ADR-010 and
//! will be caught by the `architecture_no_cycles` CI gate (which asserts zero
//! workspace-internal production out-edges for `rvc-signer-registry`).
//!
//! Consumed by the PRD M4 enumeration test (Phase 2 Task 2.1) to assert every
//! registered handler is a non-slashable message type, routes through
//! `SigningGate`, or is DVT slashing-scoped share signing
//! (`GateRouting::SlashingScopedShare` on `signer.v2.PeerSignerService`).
//!
//! Logging disposition (Phase 4): this crate is **intentionally excluded** from the
//! structured-logging breadth. It is a compile-time `const` table consumed only by
//! enumeration tests — there is no runtime or hot path to instrument, so adding
//! `info`/`debug` here would be noise. This is a documented, deliberate deviation from the
//! PRD's "100% of near-silent crates get `info`+`debug`" metric (`plan/logging/prd.md`); the
//! structured-logging standard the crate opts out of is `plan/logging/STANDARD.md`.
//! No `tracing` dependency is added, preserving the zero-production-out-edge Gate-6 pin.
#![forbid(unsafe_code)]

/// Class of consensus message a signing method handles.
///
/// One variant per distinct signing domain / SSZ message shape so the Phase 2 M4
/// enumeration test can apply per-domain policy precisely. Splitting domains that share
/// a Rust type but differ in SSZ payload or domain constant (e.g. beacon vs sync-committee
/// selection, base vs Electra aggregate) is deliberate: collapsing them would make a
/// gate-completeness check imprecise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// `SignBeaconBlock` / `SignBlindedBeaconBlock` — `DOMAIN_BEACON_PROPOSER` (slashable).
    Block,
    /// `SignAttestation` — `DOMAIN_BEACON_ATTESTER` (slashable).
    Attestation,
    /// `AggregateAndProof` (Phase0/Altair) — `DOMAIN_AGGREGATE_AND_PROOF`.
    Aggregate,
    /// `ElectraAggregateAndProof` — `DOMAIN_AGGREGATE_AND_PROOF`, distinct SSZ type.
    ElectraAggregate,
    /// `SyncCommitteeMessage` — `DOMAIN_SYNC_COMMITTEE`.
    SyncMessage,
    /// `ContributionAndProof` — `DOMAIN_CONTRIBUTION_AND_PROOF`.
    SyncContribution,
    /// RANDAO reveal — `DOMAIN_RANDAO`.
    RandaoReveal,
    /// Voluntary exit — `DOMAIN_VOLUNTARY_EXIT`.
    VoluntaryExit,
    /// Validator/builder registration — `DOMAIN_APPLICATION_BUILDER`.
    BuilderRegistration,
    /// Beacon committee aggregator selection — `DOMAIN_SELECTION_PROOF`.
    Selection,
    /// Sync committee aggregator selection — `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`.
    SyncSelection,
    /// Legacy v1 raw-root `sign(signing_root, pubkey)` — no typed domain.
    V1RawRoot,
    /// Payload attestation (PTC) — `DOMAIN_PTC_ATTESTER` (non-slashable).
    PayloadAttestation,
}

impl MessageKind {
    /// Slashable kinds must never be `GateRouting::NonSlashable`.
    pub const fn is_slashable(self) -> bool {
        matches!(self, Self::Block | Self::Attestation | Self::Aggregate | Self::ElectraAggregate)
    }
}

/// Whether a signing method routes through the slashing/doppelganger `SigningGate`.
///
/// An enum (rather than a bare `bool`) so a mis-typed registry entry for a slashable
/// message is a visible, reviewable mistake rather than a silent boolean flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateRouting {
    /// Routes through `SigningGate::sign_*` (required for slashable message kinds
    /// on [`V2_SIGNER_SERVICE`]).
    Gated,
    /// Does not route through the gate (only valid for non-slashable message kinds).
    NonSlashable,
    /// Slashing-scoped share signing on the DVT peer service (ARCH-7i).
    ///
    /// Stages via `PubkeyScopedDb::stage_*` then `partial_sign_with_share`.
    /// Not `SigningGate`-routed — share signing is not a full-BLS `CompositeSigner`
    /// path. Valid **only** on [`DVT_PEER_SERVICE`]. `gate_method` must name a
    /// member of [`SLASHING_STAGE_METHODS`].
    SlashingScopedShare,
}

/// Compile-time metadata for one gRPC signing method on the live listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningMethod {
    pub service: &'static str,
    pub method: &'static str,
    pub message_kind: MessageKind,
    pub gate_routing: GateRouting,
    /// Enforcement method this handler invokes.
    ///
    /// - [`GateRouting::Gated`] / [`GateRouting::NonSlashable`]: a
    ///   `crates/signer::SigningGate::sign_*` method. Every live-listener
    ///   signing handler routes through `SigningGate` (slashable handlers
    ///   stage the slashing DB; non-slashable handlers only run the
    ///   doppelganger gate-decision), so this is `Some(_)` for all current
    ///   v2 entries. It MUST be `Some(_)` for any `Gated` entry — that is
    ///   the strict PRD M4 invariant enforced by `signing_path_enumeration.rs`
    ///   (Issue 2.13): a slashable method that does not name a
    ///   `SigningGate::sign_*` method cannot be confirmed to consult EIP-3076.
    ///   The named method MUST be one of [`SIGNING_GATE_METHODS`].
    /// - [`GateRouting::SlashingScopedShare`]: a `PubkeyScopedDb::stage_*`
    ///   method. `None` is a hard failure. The named method MUST be one of
    ///   [`SLASHING_STAGE_METHODS`].
    pub gate_method: Option<&'static str>,
}

impl SigningMethod {
    /// C9-anchor-5 enforcement contract for one registry entry.
    ///
    /// [`GateRouting::SlashingScopedShare`] may appear only on [`DVT_PEER_SERVICE`]
    /// and must name a member of [`SLASHING_STAGE_METHODS`].
    pub fn enforcement_error(self) -> Option<&'static str> {
        match self.gate_routing {
            GateRouting::SlashingScopedShare => {
                if self.service != DVT_PEER_SERVICE {
                    return Some(
                        "GateRouting::SlashingScopedShare is only valid on signer.v2.PeerSignerService",
                    );
                }
                match self.gate_method {
                    None => Some(
                        "SlashingScopedShare must name a SLASHING_STAGE_METHODS member (gate_method = None)",
                    ),
                    Some(name) if SLASHING_STAGE_METHODS.contains(&name) => None,
                    Some(_) => {
                        Some("SlashingScopedShare gate_method is not in SLASHING_STAGE_METHODS")
                    }
                }
            }
            // Inverse: a slashable kind on the DVT service that is not
            // SlashingScopedShare would bypass the registered share-signing contract.
            GateRouting::Gated | GateRouting::NonSlashable => {
                if self.service == DVT_PEER_SERVICE && self.message_kind.is_slashable() {
                    Some("DVT-service slashable kind must be GateRouting::SlashingScopedShare")
                } else {
                    None
                }
            }
        }
    }
}

/// Fully-qualified protobuf name of the live v2 typed signer service.
pub const V2_SIGNER_SERVICE: &str = "signer.v2.SignerService";

/// Fully-qualified protobuf name of the DVT `PeerSignerService`.
pub const DVT_PEER_SERVICE: &str = "signer.v2.PeerSignerService";

/// The canonical set of `crates/signer::SigningGate::sign_*` method names.
///
/// This is the authoritative list a `SigningMethod::gate_method` is validated
/// against by the strict enumeration gate.  Keep it in lockstep with the public
/// `SigningGate` API in `crates/signer/src/gate.rs`: adding a `SigningGate`
/// signing method (or renaming one) requires updating this list and any
/// `REGISTERED_METHODS` entry that routes through it.
///
/// DEV-ONLY: this list is consumed by the M4 enumeration gate, not by
/// production code (ADR-010 — this crate is `[dev-dependencies]` only).
pub const SIGNING_GATE_METHODS: &[&str] = &[
    "sign_block",
    "sign_attestation",
    "sign_sync_committee_message",
    "sign_aggregate_and_proof",
    "sign_contribution_and_proof",
    "sign_selection_proof",
    "sign_randao_reveal",
    "sign_voluntary_exit",
    "sign_builder_registration",
    "sign_payload_attestation",
    "sign_proposer_preferences",
];

/// Canonical `PubkeyScopedDb::stage_*` methods used by DVT share signing.
///
/// Analogous to [`SIGNING_GATE_METHODS`]: a [`GateRouting::SlashingScopedShare`]
/// entry must name a member of this list. These are **not** `SigningGate`
/// methods — DVT stages then `partial_sign_with_share` (ARCH-7i / ARCH-P1-7).
pub const SLASHING_STAGE_METHODS: &[&str] = &["stage_block", "stage_attestation"];

/// Every gRPC signing method on the live listener, classified by message kind and gate routing.
///
/// This is the canonical surface enumerated by the PRD M4 gate.  Adding a new signing RPC
/// without a matching entry here (or mis-classifying its `gate_routing`) will be caught by
/// `crates/signer-server/tests/signing_path_enumeration.rs`.  Issue 2.13 strengthens the
/// gate to verify each entry actually invokes `SigningGate` at runtime. ARCH-7i adds the
/// DVT `PeerSignerService` partial-sign surface behind `--features dvt`.
///
/// Only live-listener signing methods are listed:
/// - `list_public_keys` and `get_status` are informational, not signing methods.
/// - The v1 raw-root `sign` RPC has been removed from the live listener (SS-1, Issue 2.2).
/// - DVT `PartialSignSyncCommittee` and `PartialSignPayloadAttestation` are
///   registered as [`GateRouting::NonSlashable`] with `gate_method = None`
///   (neither is slashable; no stage method).
///
/// Service path is the protobuf fully-qualified service name (`package.ServiceName`).
pub const REGISTERED_METHODS: &[SigningMethod] = &[
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::Gated,
        gate_method: Some("sign_block"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignBlindedBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::Gated,
        gate_method: Some("sign_block"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignAttestationData",
        message_kind: MessageKind::Attestation,
        gate_routing: GateRouting::Gated,
        gate_method: Some("sign_attestation"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignAggregateAndProof",
        message_kind: MessageKind::Aggregate,
        gate_routing: GateRouting::Gated,
        gate_method: Some("sign_aggregate_and_proof"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignRandaoReveal",
        message_kind: MessageKind::RandaoReveal,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_randao_reveal"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignSyncCommitteeMessage",
        message_kind: MessageKind::SyncMessage,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_sync_committee_message"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignSyncAggregatorSelectionData",
        message_kind: MessageKind::SyncSelection,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_selection_proof"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignContributionAndProof",
        message_kind: MessageKind::SyncContribution,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_contribution_and_proof"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignBuilderRegistration",
        message_kind: MessageKind::BuilderRegistration,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_builder_registration"),
    },
    SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignVoluntaryExit",
        message_kind: MessageKind::VoluntaryExit,
        gate_routing: GateRouting::NonSlashable,
        gate_method: Some("sign_voluntary_exit"),
    },
    #[cfg(feature = "dvt")]
    SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::SlashingScopedShare,
        gate_method: Some("stage_block"),
    },
    #[cfg(feature = "dvt")]
    SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignAttestationData",
        message_kind: MessageKind::Attestation,
        gate_routing: GateRouting::SlashingScopedShare,
        gate_method: Some("stage_attestation"),
    },
    #[cfg(feature = "dvt")]
    SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignSyncCommittee",
        message_kind: MessageKind::SyncMessage,
        gate_routing: GateRouting::NonSlashable,
        gate_method: None,
    },
    #[cfg(feature = "dvt")]
    SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignPayloadAttestation",
        message_kind: MessageKind::PayloadAttestation,
        gate_routing: GateRouting::NonSlashable,
        gate_method: None,
    },
];
