//! Standing invariant checks for REGISTERED_METHODS (SS-1/M4, Issue 2.2).
//!
//! Phase 1 asserted the array was empty (tripwire).  Phase 2 (Issue 2.2) populates
//! it; this test now asserts the populated invariants instead.  The M4 enumeration
//! gate in `crates/signer-server/tests/signing_path_enumeration.rs` contains the full
//! per-method policy check.
use rvc_signer_registry::{
    GateRouting, MessageKind, SigningMethod, DVT_PEER_SERVICE, REGISTERED_METHODS,
    SLASHING_STAGE_METHODS, V2_SIGNER_SERVICE,
};

/// REGISTERED_METHODS is non-empty after Phase 2 population (SS-1, Issue 2.2).
#[test]
fn registered_methods_is_populated() {
    assert!(
        !REGISTERED_METHODS.is_empty(),
        "REGISTERED_METHODS must be populated after Phase 2 (Issue 2.2)"
    );
}

/// Every entry has non-empty service and method strings.
#[test]
fn every_entry_has_non_empty_service_and_method() {
    for m in REGISTERED_METHODS {
        assert!(!m.service.is_empty(), "entry has empty service: {:?}", m);
        assert!(!m.method.is_empty(), "entry has empty method: {:?}", m);
    }
}

/// No slashable message kind is marked NonSlashable.
#[test]
fn no_slashable_method_is_marked_non_slashable() {
    let slashable = [
        MessageKind::Block,
        MessageKind::Attestation,
        MessageKind::Aggregate,
        MessageKind::ElectraAggregate,
    ];
    for m in REGISTERED_METHODS {
        if slashable.contains(&m.message_kind) {
            if m.service == DVT_PEER_SERVICE {
                assert_ne!(
                    m.gate_routing,
                    GateRouting::NonSlashable,
                    "slashable method {}/{} must not be GateRouting::NonSlashable, got {:?}",
                    m.service,
                    m.method,
                    m.gate_routing,
                );
                assert_eq!(
                    m.gate_routing,
                    GateRouting::SlashingScopedShare,
                    "DVT slashable method {}/{} must be SlashingScopedShare, got {:?}",
                    m.service,
                    m.method,
                    m.gate_routing,
                );
                let stage_method =
                    m.gate_method.expect("DVT slashable method must name a stage method");
                assert!(
                    SLASHING_STAGE_METHODS.contains(&stage_method),
                    "DVT slashable method {}/{} stages via '{}', not in SLASHING_STAGE_METHODS {:?}",
                    m.service,
                    m.method,
                    stage_method,
                    SLASHING_STAGE_METHODS,
                );
                continue;
            }
            assert_eq!(
                m.gate_routing,
                GateRouting::Gated,
                "slashable method {}/{} must be GateRouting::Gated, got {:?}",
                m.service,
                m.method,
                m.gate_routing,
            );
        }
    }
}

/// C9: `SlashingScopedShare` on the v2 service is a hole; reject it.
#[test]
fn dvt_enforcement_variant_is_rejected_on_the_v2_service() {
    let scratch = SigningMethod {
        service: V2_SIGNER_SERVICE,
        method: "SignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::SlashingScopedShare,
        gate_method: Some("stage_block"),
    };
    let err = scratch
        .enforcement_error()
        .expect("SlashingScopedShare on signer.v2.SignerService must be rejected");
    assert!(
        err.contains("PeerSignerService"),
        "rejection must name the DVT service constraint: {err}"
    );
}

/// Inverse C9: a DVT-service slashable kind that is not `SlashingScopedShare`.
#[test]
fn dvt_service_slashable_kind_must_be_slashing_scoped_share() {
    let scratch = SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::NonSlashable,
        gate_method: None,
    };
    let err = scratch
        .enforcement_error()
        .expect("DVT slashable kind classified NonSlashable must be rejected");
    assert!(err.contains("SlashingScopedShare"), "rejection must name the required routing: {err}");

    let gated = SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::Gated,
        gate_method: Some("sign_block"),
    };
    let err =
        gated.enforcement_error().expect("DVT slashable kind classified Gated must be rejected");
    assert!(err.contains("SlashingScopedShare"), "rejection must name the required routing: {err}");
}

/// C9: `SlashingScopedShare` with `gate_method = None` is a hard failure.
#[test]
fn slashing_scoped_share_requires_a_named_stage_method() {
    let scratch = SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::SlashingScopedShare,
        gate_method: None,
    };
    let err = scratch
        .enforcement_error()
        .expect("SlashingScopedShare with gate_method = None must be rejected");
    assert!(
        err.contains("SLASHING_STAGE_METHODS") && err.contains("None"),
        "rejection must name the missing stage method: {err}"
    );

    let unknown = SigningMethod {
        service: DVT_PEER_SERVICE,
        method: "PartialSignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::SlashingScopedShare,
        gate_method: Some("stage_foo"),
    };
    let err = unknown
        .enforcement_error()
        .expect("SlashingScopedShare with a non-canonical stage name must be rejected");
    assert!(
        err.contains("SLASHING_STAGE_METHODS"),
        "rejection must name the canonical stage list: {err}"
    );
}

/// Every published entry satisfies the enforcement contract.
#[test]
fn every_registered_method_satisfies_enforcement_contract() {
    for m in REGISTERED_METHODS {
        assert!(
            m.enforcement_error().is_none(),
            "{}/{} failed enforcement: {:?}",
            m.service,
            m.method,
            m.enforcement_error()
        );
    }
}

/// `SLASHING_STAGE_METHODS` is the canonical stage list and is well-formed.
#[test]
fn slashing_stage_methods_list_is_well_formed() {
    assert!(!SLASHING_STAGE_METHODS.is_empty(), "SLASHING_STAGE_METHODS must be non-empty");
    let mut seen = std::collections::HashSet::new();
    for name in SLASHING_STAGE_METHODS {
        assert!(!name.is_empty(), "SLASHING_STAGE_METHODS contains an empty method name");
        assert!(
            name.starts_with("stage_"),
            "SLASHING_STAGE_METHODS entry '{name}' must be a PubkeyScopedDb stage_* method"
        );
        assert!(seen.insert(*name), "SLASHING_STAGE_METHODS has a duplicate: '{name}'");
    }
    assert!(SLASHING_STAGE_METHODS.contains(&"stage_block"));
    assert!(SLASHING_STAGE_METHODS.contains(&"stage_attestation"));
}
