//! PRD M4 — canonical phase-exit enumeration test (Issue 2.13).
//!
//! Formerly `m4_enumeration.rs` (PRD M4 / Issue 2.13). Enumerates live-listener
//! signing paths to prove every slashable path consults the slashing DB.
//!
//! # What M4 requires
//!
//! > No signing path on `rvc-signer`'s LIVE listener can produce a signature for
//! > a slashable message type without EIP-3076 (slashing-DB) consultation.
//!
//! # How this test verifies M4
//!
//! The proof is two-pronged: the **static** signing-method metadata in
//! `signer-registry` (`REGISTERED_METHODS`) describes the live listener's
//! signing surface, and a `cfg(test)` **introspection of the live listener**
//! (the tonic `NamedService` constants for the services actually registered via
//! `add_service` in `bin/rvc-signer/src/main.rs`) confirms that metadata
//! corresponds to what is wired.
//!
//! Concretely this test asserts:
//!
//! 1. The live listener serves **only** the v2 typed service
//!    `signer.v2.SignerService` (and, under the `dvt` feature, the v2
//!    `signer.v2.PeerSignerService`).  RF2-17 deleted the v1 proto; the legacy
//!    fully-qualified name `signer.SignerService` no longer exists in the build.
//! 2. The live-listener enumeration shows **zero** v1 raw-root entries: no
//!    `REGISTERED_METHODS` entry carries `MessageKind::V1RawRoot`, and no entry's
//!    `service` string is the retired v1 service name.
//! 3. Every **slashable** signing handler is either `GateRouting::Gated` on
//!    `signer.v2.SignerService` or `GateRouting::SlashingScopedShare` on
//!    `signer.v2.PeerSignerService`.  A slashable method classified
//!    `NonSlashable` would be a method that can sign without slashing-DB
//!    consultation — the exact thing M4 forbids.
//! 4. Every `REGISTERED_METHODS` entry's `service` string is on the live
//!    listener allow-list (`signer.v2.SignerService`, plus
//!    `signer.v2.PeerSignerService` under `--features dvt`).
//!
//! # Relationship to `signing_path_enumeration.rs`
//!
//! `signing_path_enumeration.rs` is the standing CI gate (per-method
//! classification + count floor); this file is the milestone artifact for the
//! PRD M4 closeout, expressed against the live-listener introspection. The two
//! overlap deliberately — the standing gate prevents regressions; this test is
//! the auditor-facing M4 evidence.

use signer_registry::{
    GateRouting, MessageKind, SigningMethod, DVT_PEER_SERVICE, REGISTERED_METHODS,
    V2_SIGNER_SERVICE,
};
use tonic::server::NamedService;

// The v2 typed service — the ONLY signing service registered on the live
// listener (see `bin/rvc-signer/src/main.rs`'s `add_service`).
use signer_server::SignerServiceServerV2;

/// Historical fully-qualified name of the retired v1 raw-root service.
/// Kept as a string so the M4 gate can still assert the registry never
/// reintroduces entries on that surface (RF2-17 deleted the generated type).
const RETIRED_V1_SERVICE_NAME: &str = "signer.SignerService";

/// The introspected name of the v2 service the live listener registers.
///
/// `NamedService::NAME` is the tonic-generated, protobuf fully-qualified service
/// name; reading it here is the `cfg(test)` introspection of what `add_service`
/// wires on the live listener.
fn live_listener_service_name() -> &'static str {
    <SignerServiceServerV2<()> as NamedService>::NAME
}

/// The slashable message kinds.  A handler for any of these MUST route through
/// `SigningGate` (and therefore consult the slashing DB) per PRD M4.
const SLASHABLE_KINDS: &[MessageKind] = &[
    MessageKind::Block,
    MessageKind::Attestation,
    MessageKind::Aggregate,
    MessageKind::ElectraAggregate,
];

fn is_slashable(kind: MessageKind) -> bool {
    SLASHABLE_KINDS.contains(&kind)
}

/// M4 sanity: the live listener introspects to the v2 typed service only.
#[test]
fn live_listener_serves_v2_only() {
    let live = live_listener_service_name();

    assert_eq!(
        live, "signer.v2.SignerService",
        "the live listener must serve the v2 typed service"
    );
    assert_ne!(
        live, RETIRED_V1_SERVICE_NAME,
        "the live listener must not serve the retired v1 raw-root service"
    );
}

/// ARCH-7j: the DVT peer service tonic name matches the registry constant.
#[cfg(feature = "dvt")]
#[test]
fn live_listener_dvt_peer_service_name_matches_registry() {
    use signer_server::PeerSignerServiceServerV2;
    assert_eq!(
        <PeerSignerServiceServerV2<()> as NamedService>::NAME,
        DVT_PEER_SERVICE,
        "PeerSignerServiceServerV2 NamedService name must equal DVT_PEER_SERVICE"
    );
}

/// M4 core (zero v1 raw-root on the live listener): no enumerated method is a
/// v1 raw-root entry — neither by `MessageKind::V1RawRoot` nor by carrying the
/// retired v1 service name.
#[test]
fn live_listener_enumeration_has_zero_v1_raw_root_entries() {
    let v1_kind_entries: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| m.message_kind == MessageKind::V1RawRoot).collect();
    assert!(
        v1_kind_entries.is_empty(),
        "live-listener enumeration must contain ZERO V1RawRoot entries; found: {v1_kind_entries:?}"
    );

    let v1_service_entries: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| m.service == RETIRED_V1_SERVICE_NAME).collect();
    assert!(
        v1_service_entries.is_empty(),
        "live-listener enumeration must contain ZERO entries on the retired v1 service \
         '{RETIRED_V1_SERVICE_NAME}'; found: {v1_service_entries:?}"
    );
}

/// M4 core (no slashable signing without the gate): every slashable handler on
/// the live listener routes through `SigningGate`.
#[test]
fn every_slashable_method_routes_through_signing_gate() {
    let slashable: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| is_slashable(m.message_kind)).collect();

    assert!(
        !slashable.is_empty(),
        "the live listener must expose at least one slashable signing method \
         (block/attestation); none found — registry is likely misconfigured"
    );

    for m in slashable {
        if m.gate_routing == GateRouting::SlashingScopedShare {
            assert_eq!(
                m.service, DVT_PEER_SERVICE,
                "SlashingScopedShare is only valid on {DVT_PEER_SERVICE}, got {}/{}",
                m.service, m.method
            );
            continue;
        }
        assert_eq!(
            m.gate_routing,
            GateRouting::Gated,
            "slashable method {}/{} (kind={:?}) MUST route through SigningGate \
             (GateRouting::Gated) — a NonSlashable classification would let it sign \
             without EIP-3076 consultation, violating PRD M4",
            m.service,
            m.method,
            m.message_kind,
        );
    }
}

/// M4 consistency: every enumerated method's service string equals the live
/// listener's introspected v2 service name — the static registry does not drift
/// from the wired service.
#[test]
fn every_registered_method_is_on_the_live_listener_service() {
    let live = live_listener_service_name();
    assert_eq!(live, V2_SIGNER_SERVICE);
    let allowed: &[&str] = if cfg!(feature = "dvt") {
        &[V2_SIGNER_SERVICE, DVT_PEER_SERVICE]
    } else {
        &[V2_SIGNER_SERVICE]
    };
    for m in REGISTERED_METHODS {
        assert!(
            allowed.contains(&m.service),
            "REGISTERED_METHODS entry {}/{} is on service '{}', but the live listener \
             serves {:?} ; the registry has drifted from the wired service",
            m.service,
            m.method,
            m.service,
            allowed,
        );
    }
}

/// M4 completeness: the live listener must expose the two canonical slashable
/// signing methods (block + attestation), each `Gated`.  A regression that
/// silently drops one of these from the registry would weaken the M4 evidence.
#[test]
fn block_and_attestation_are_present_and_gated() {
    let live = live_listener_service_name();

    let has_gated = |method: &str| {
        REGISTERED_METHODS.iter().any(|m| {
            m.service == live && m.method == method && m.gate_routing == GateRouting::Gated
        })
    };

    assert!(
        has_gated("SignBeaconBlock"),
        "live listener must expose a gated SignBeaconBlock (slashable, EIP-3076-consulting)"
    );
    assert!(
        has_gated("SignAttestationData"),
        "live listener must expose a gated SignAttestationData (slashable, EIP-3076-consulting)"
    );
}
