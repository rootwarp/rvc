//! M4 standing CI gate: every live-listener signing method is enumerated and
//! correctly classified in `REGISTERED_METHODS`.
//!
//! # Purpose
//!
//! Adding a new gRPC signing method to `rvc-signer` without a matching entry in
//! `REGISTERED_METHODS` (or mis-classifying its `gate_routing` / `gate_method`)
//! will cause this test to fail, blocking CI.
//!
//! # Invariants checked (STRICT set — flipped on by Issue 2.13)
//!
//! 1. `REGISTERED_METHODS` is non-empty.
//! 2. Every slashable message kind (`Block | Attestation | Aggregate | ElectraAggregate`)
//!    is either `GateRouting::Gated` on `signer.v2.SignerService` or
//!    `GateRouting::SlashingScopedShare` on `signer.v2.PeerSignerService` (ARCH-7i).
//!    No slashable method may be `NonSlashable`.
//! 3. Every entry has non-empty `service` and `method` strings. Service is the
//!    two-name allow-list: `signer.v2.SignerService`, plus
//!    `signer.v2.PeerSignerService` under `--features dvt`.
//! 4. **STRICT (Issue 2.13 / ARCH-7i):** every registered method is either
//!    non-slashable (`gate_routing == NonSlashable`), confirmed via
//!    `signer-registry` to invoke `SigningGate::sign_*` (`gate_method` ∈
//!    `SIGNING_GATE_METHODS`), **or** DVT slashing-scoped share signing
//!    (`gate_method` ∈ `SLASHING_STAGE_METHODS`). A slashable method with no
//!    recognized enforcement method named cannot be confirmed to consult
//!    EIP-3076; this is the strengthening that locks PRD M4 into place.
//!
//! # What changed in the strict flip
//!
//! Issue 2.2 landed the weaker invariant ("every method is non-slashable OR
//! tagged `Gated`").  Issue 2.13 flips it to the stronger one above by recording,
//! per registry entry, the concrete `SigningGate::sign_*` method the handler
//! routes through (`SigningMethod::gate_method`) and validating that name against
//! the canonical `SIGNING_GATE_METHODS` list.  The link from a live RPC to a
//! `SigningGate` method is now machine-checked, not merely a boolean tag.
//!
//! Note: cross-checking registry method names against the actual v2 proto service
//! descriptor via tonic reflection would add heavy build-time overhead.  Instead,
//! the live-listener service name is introspected via `NamedService` in the
//! companion `key_enumeration.rs` (Issue 2.13 / former `m4_enumeration.rs`), and the gate linkage is confirmed
//! via the `gate_method` cross-check below.

// The dep key in Cargo.toml is `signer-registry` (package = "rvc-signer-registry"),
// so the import alias is `signer_registry` from rvc-signer-server's perspective.
use signer_registry::{
    GateRouting, MessageKind, DVT_PEER_SERVICE, REGISTERED_METHODS, SIGNING_GATE_METHODS,
    SLASHING_STAGE_METHODS, V2_SIGNER_SERVICE,
};

/// REGISTERED_METHODS must be non-empty — the live listener has signing methods.
#[test]
fn registered_methods_is_non_empty() {
    assert!(
        !REGISTERED_METHODS.is_empty(),
        "REGISTERED_METHODS is empty; every live-listener signing method must be listed"
    );
}

/// Every entry must have non-empty service and method strings.
#[test]
fn every_entry_has_non_empty_service_and_method() {
    for m in REGISTERED_METHODS {
        assert!(
            !m.service.is_empty(),
            "REGISTERED_METHODS entry has an empty service string: {:?}",
            m
        );
        assert!(
            !m.method.is_empty(),
            "REGISTERED_METHODS entry has an empty method string: {:?}",
            m
        );
    }
}

/// No slashable message kind may be marked NonSlashable.
///
/// This is the core M4 policy invariant: a mis-classified slashable method would
/// bypass the slashing/doppelganger gate.
#[test]
fn no_slashable_method_is_marked_non_slashable() {
    let slashable_kinds = [
        MessageKind::Block,
        MessageKind::Attestation,
        MessageKind::Aggregate,
        MessageKind::ElectraAggregate,
    ];

    for m in REGISTERED_METHODS {
        if slashable_kinds.contains(&m.message_kind) {
            if m.service == DVT_PEER_SERVICE {
                assert_ne!(
                    m.gate_routing,
                    GateRouting::NonSlashable,
                    "slashable method {}/{} (kind={:?}) is classified as NonSlashable — \
                     this would bypass the slashing gate; fix REGISTERED_METHODS or Issue 2.13 \
                     reclassification",
                    m.service,
                    m.method,
                    m.message_kind,
                );
                assert_eq!(
                    m.gate_routing,
                    GateRouting::SlashingScopedShare,
                    "DVT slashable method {}/{} (kind={:?}) must be SlashingScopedShare, got {:?}",
                    m.service,
                    m.method,
                    m.message_kind,
                    m.gate_routing,
                );
                let stage_method = m.gate_method.unwrap_or_else(|| {
                    panic!(
                        "DVT slashable method {}/{} names no stage method (gate_method = None)",
                        m.service, m.method
                    )
                });
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
                "slashable method {}/{} (kind={:?}) is classified as NonSlashable — \
                 this would bypass the slashing gate; fix REGISTERED_METHODS or Issue 2.13 \
                 reclassification",
                m.service,
                m.method,
                m.message_kind,
            );
        }
    }
}

/// All entries use the expected live-listener service path.
///
/// The live listener serves `signer.v2.SignerService` and, under `--features dvt`,
/// `signer.v2.PeerSignerService`.  An entry with any other service string
/// indicates a stale registry entry or a new service that needs explicit policy
/// review.
#[test]
fn all_entries_use_v2_service_path() {
    // Two-name allow-list (ARCH-7i / VD-7D): v2 signer plus, under `--features dvt`,
    // the DVT peer service. Default-features stays single-valued in practice
    // (no DVT entries are compiled in).
    let allowed: &[&str] = if cfg!(feature = "dvt") {
        &[V2_SIGNER_SERVICE, DVT_PEER_SERVICE]
    } else {
        &[V2_SIGNER_SERVICE]
    };
    for m in REGISTERED_METHODS {
        assert!(
            allowed.contains(&m.service),
            "unexpected service path in REGISTERED_METHODS: got '{}', allowed {:?}; \
             if a new service was added, review its gate_routing classification and \
             update this test (Issue 2.13 / ARCH-7i)",
            m.service,
            allowed,
        );
    }
}

/// Count floor: adding a v2 signing method without a `REGISTERED_METHODS` entry fails CI.
///
/// Update `EXPECTED` (and add the entry in `crates/signer-registry/src/lib.rs`)
/// when a new v2 signing method is added or an existing one is removed.
#[test]
fn registered_methods_count_matches_live_listener() {
    // Update when a v2 (or DVT) signing method is added/removed
    // (see crates/signer-registry/src/lib.rs). 10 default / 14 with `--features dvt`.
    #[cfg(not(feature = "dvt"))]
    const EXPECTED: usize = 10;
    #[cfg(feature = "dvt")]
    const EXPECTED: usize = 14;
    let run = if cfg!(feature = "dvt") { " --features dvt" } else { " default features" };
    assert_eq!(
        signer_registry::REGISTERED_METHODS.len(),
        EXPECTED,
        "REGISTERED_METHODS count changed: expected {EXPECTED} on{run}; \
         add the new method's entry or update EXPECTED"
    );
}

/// STRICT invariant (Issue 2.13 flip): every registered method is non-slashable
/// OR confirmed via `signer-registry` to invoke `SigningGate::sign_*`.
///
/// This is the strengthening of the Issue 2.2 weaker invariant.  Previously a
/// slashable method only had to be *tagged* `Gated`; now a `Gated` method must
/// name the concrete `SigningGate::sign_*` method it routes through
/// (`gate_method`), and that name must be a recognized member of
/// `SIGNING_GATE_METHODS`.  A slashable method that names no recognized gate
/// method would be one that cannot be confirmed to consult EIP-3076 — exactly
/// the PRD M4 failure mode this gate locks out.
#[test]
fn every_registered_method_is_nonslashable_or_invokes_signing_gate() {
    for m in REGISTERED_METHODS {
        // ARCH-7i: slashing-scoped DVT share signing is not SigningGate-routed.
        // It must name a SLASHING_STAGE_METHODS member (None is a hard failure).
        if m.gate_routing == GateRouting::SlashingScopedShare {
            let stage_method = m.gate_method.unwrap_or_else(|| {
                panic!(
                    "STRICT M4: slashing-scoped method {}/{} (kind={:?}) names no stage method \
                     (gate_method = None); it cannot be confirmed to consult EIP-3076",
                    m.service, m.method, m.message_kind,
                )
            });
            assert!(
                SLASHING_STAGE_METHODS.contains(&stage_method),
                "STRICT M4: slashing-scoped method {}/{} stages via '{}', which is not a \
                 recognized PubkeyScopedDb::stage_* method ({:?})",
                m.service,
                m.method,
                stage_method,
                SLASHING_STAGE_METHODS,
            );
            continue;
        }

        // The "OR non-slashable" escape clause: non-slashable methods are not
        // required to route through the gate for M4 (they carry no slashing
        // watermark).  In the current architecture they do route through the
        // gate anyway, but M4 does not mandate it.
        if m.gate_routing == GateRouting::NonSlashable {
            continue;
        }

        // Otherwise the method is Gated and MUST be confirmed to invoke a
        // recognized SigningGate::sign_* method.
        let gate_method = m.gate_method.unwrap_or_else(|| {
            panic!(
                "STRICT M4: gated method {}/{} (kind={:?}) names no SigningGate method \
                 (gate_method = None); it cannot be confirmed to consult EIP-3076",
                m.service, m.method, m.message_kind,
            )
        });

        assert!(
            SIGNING_GATE_METHODS.contains(&gate_method),
            "STRICT M4: gated method {}/{} routes through '{}', which is not a recognized \
             SigningGate::sign_* method ({:?}); update SIGNING_GATE_METHODS or fix the entry",
            m.service,
            m.method,
            gate_method,
            SIGNING_GATE_METHODS,
        );
    }
}

/// STRICT support: every entry that names a `gate_method` names a recognized one.
///
/// This also covers the non-slashable entries (which, in the current
/// architecture, all route through the gate too); it catches a typo'd
/// `gate_method` on any entry, slashable or not.
#[test]
fn every_named_gate_method_is_recognized() {
    for m in REGISTERED_METHODS {
        if let Some(gate_method) = m.gate_method {
            if m.gate_routing == GateRouting::SlashingScopedShare {
                assert!(
                    SLASHING_STAGE_METHODS.contains(&gate_method),
                    "method {}/{} names gate_method '{}', not in SLASHING_STAGE_METHODS {:?}",
                    m.service,
                    m.method,
                    gate_method,
                    SLASHING_STAGE_METHODS,
                );
                continue;
            }
            assert!(
                SIGNING_GATE_METHODS.contains(&gate_method),
                "method {}/{} names gate_method '{}', not in SIGNING_GATE_METHODS {:?}",
                m.service,
                m.method,
                gate_method,
                SIGNING_GATE_METHODS,
            );
        }
    }
}

/// STRICT support: `SIGNING_GATE_METHODS` is the canonical list and is non-empty,
/// well-formed (no empty strings, no duplicates), so the cross-check above is
/// meaningful.
#[test]
fn signing_gate_methods_list_is_well_formed() {
    assert!(!SIGNING_GATE_METHODS.is_empty(), "SIGNING_GATE_METHODS must be non-empty");
    for name in SIGNING_GATE_METHODS {
        assert!(!name.is_empty(), "SIGNING_GATE_METHODS contains an empty method name");
        assert!(
            name.starts_with("sign_"),
            "SIGNING_GATE_METHODS entry '{name}' must be a SigningGate sign_* method"
        );
    }
    let mut seen = std::collections::HashSet::new();
    for name in SIGNING_GATE_METHODS {
        assert!(seen.insert(*name), "SIGNING_GATE_METHODS has a duplicate: '{name}'");
    }
}

/// ARCH-7i: both DVT partial-sign methods are registered with slashing-scoped
/// share signing and a named `PubkeyScopedDb::stage_*` method.
#[cfg(feature = "dvt")]
#[test]
fn dvt_partial_sign_methods_are_registered() {
    let find = |method: &str| {
        REGISTERED_METHODS.iter().find(|m| m.service == DVT_PEER_SERVICE && m.method == method)
    };

    let block = find("PartialSignBeaconBlock")
        .expect("PartialSignBeaconBlock must be in REGISTERED_METHODS under --features dvt");
    assert_eq!(block.message_kind, MessageKind::Block);
    assert_eq!(block.gate_routing, GateRouting::SlashingScopedShare);
    assert_eq!(block.gate_method, Some("stage_block"));
    assert!(SLASHING_STAGE_METHODS.contains(&block.gate_method.unwrap()));
    assert!(block.enforcement_error().is_none(), "{:?}", block.enforcement_error());

    let att = find("PartialSignAttestationData")
        .expect("PartialSignAttestationData must be in REGISTERED_METHODS under --features dvt");
    assert_eq!(att.message_kind, MessageKind::Attestation);
    assert_eq!(att.gate_routing, GateRouting::SlashingScopedShare);
    assert_eq!(att.gate_method, Some("stage_attestation"));
    assert!(SLASHING_STAGE_METHODS.contains(&att.gate_method.unwrap()));
    assert!(att.enforcement_error().is_none(), "{:?}", att.enforcement_error());

    // proto/signer.v2.proto PeerSignerService — non-slashable.
    let sync = find("PartialSignSyncCommittee")
        .expect("PartialSignSyncCommittee must be in REGISTERED_METHODS under --features dvt");
    assert_eq!(sync.message_kind, MessageKind::SyncMessage);
    assert_eq!(sync.gate_routing, GateRouting::NonSlashable);
    assert_eq!(sync.gate_method, None);
    assert!(sync.enforcement_error().is_none(), "{:?}", sync.enforcement_error());

    let ptc = find("PartialSignPayloadAttestation")
        .expect("PartialSignPayloadAttestation must be in REGISTERED_METHODS under --features dvt");
    assert_eq!(ptc.message_kind, MessageKind::PayloadAttestation);
    assert_eq!(ptc.gate_routing, GateRouting::NonSlashable);
    assert_eq!(ptc.gate_method, None);
    assert!(ptc.enforcement_error().is_none(), "{:?}", ptc.enforcement_error());

    // Unlisted live DVT RPC fails CI: registry rows must match the proto inventory.
    const LIVE_DVT_RPCS: &[&str] = &[
        "PartialSignBeaconBlock",
        "PartialSignAttestationData",
        "PartialSignSyncCommittee",
        "PartialSignPayloadAttestation",
    ];
    let dvt_count = REGISTERED_METHODS.iter().filter(|m| m.service == DVT_PEER_SERVICE).count();
    assert_eq!(
        dvt_count,
        LIVE_DVT_RPCS.len(),
        "REGISTERED_METHODS DVT rows must match proto PeerSignerService RPCs {LIVE_DVT_RPCS:?}"
    );
    for method in LIVE_DVT_RPCS {
        assert!(find(method).is_some(), "live DVT RPC {method} is missing from REGISTERED_METHODS");
    }
}

/// ARCH-7i / C9: the new enforcement variant must never appear on the v2 service.
///
/// The scratch-entry half is not feature-gated: `SlashingScopedShare` exists on
/// all feature sets. The published-row walk is always-on too (DVT rows only
/// exist under `--features dvt`).
#[test]
fn dvt_enforcement_variant_is_rejected_on_the_v2_service() {
    use signer_registry::SigningMethod;

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

    for m in REGISTERED_METHODS {
        if m.service == V2_SIGNER_SERVICE {
            assert_ne!(
                m.gate_routing,
                GateRouting::SlashingScopedShare,
                "v2 method {}/{} must not carry SlashingScopedShare",
                m.service,
                m.method
            );
        }
        assert!(
            m.enforcement_error().is_none(),
            "{}/{} failed enforcement: {:?}",
            m.service,
            m.method,
            m.enforcement_error()
        );
    }
}

/// ARCH-7i: a DVT partial signature cannot be produced outside the registered
/// contract (stage → sign → commit on the real `PubkeyScopedDb` path).
#[cfg(feature = "dvt")]
mod dvt_committed_slashing_row {
    #![allow(clippy::disallowed_methods)] // test helper round-trips raw key bytes

    use std::collections::HashMap;
    use std::sync::Arc;

    use tonic::Request;
    use zeroize::Zeroizing;

    use signer_server::dvt::allow_list::{AllowedPeer, AllowedPeers};
    use signer_server::dvt::peer_service::PeerSignerServiceImpl;
    use signer_server::dvt::types::ShareInfo;
    use signer_server::proto::signer_v2 as sv2;
    use signer_server::proto::signer_v2::peer_signer_service_server::PeerSignerService;

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

    fn make_db() -> Arc<slashing::SlashingDb> {
        Arc::new(slashing::SlashingDb::open_in_memory().expect("open in-memory test DB"))
    }

    fn make_service(
        shares: Vec<([u8; 48], ShareInfo)>,
        allow_list: Arc<AllowedPeers>,
        db: Option<Arc<slashing::SlashingDb>>,
    ) -> PeerSignerServiceImpl {
        let map: HashMap<[u8; 48], ShareInfo> = shares.into_iter().collect();
        PeerSignerServiceImpl::new(Arc::new(map), allow_list, db)
    }

    fn sample_fork_info() -> sv2::ForkInfo {
        sv2::ForkInfo {
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

    fn sample_attestation_data(source_epoch: u64, target_epoch: u64) -> sv2::AttestationData {
        sv2::AttestationData {
            slot: target_epoch * 32,
            index: 0,
            beacon_block_root: vec![0xABu8; 32],
            source: Some(sv2::Checkpoint { epoch: source_epoch, root: vec![0x01u8; 32] }),
            target: Some(sv2::Checkpoint { epoch: target_epoch, root: vec![0x02u8; 32] }),
        }
    }

    #[tokio::test]
    async fn dvt_partial_signature_requires_a_committed_slashing_row() {
        let (pk, share) = make_share(1);
        let al = make_allow_list(vec![("unknown", 1)]);
        let db = make_db();
        let svc = make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
        let pubkey_hex = format!("0x{}", hex::encode(pk));

        assert!(
            db.get_blocks(&pubkey_hex).expect("get_blocks").is_empty(),
            "no slashing row may exist before the first successful partial sign"
        );

        // Registered contract: stage_block → partial_sign_with_share → commit.
        let req = Request::new(sv2::PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp =
            svc.partial_sign_beacon_block(req).await.expect("first partial sign must succeed");
        assert_eq!(resp.into_inner().partial_signature.len(), 96);

        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks after sign");
        assert_eq!(blocks.len(), 1, "successful partial sign must commit exactly one slashing row");
        assert_eq!(blocks[0].slot, 42);

        // Staging fails (double proposal) → no signature is produced.
        let mut different_body = sample_block_ssz(42);
        for b in &mut different_body[16..48] {
            *b ^= 0xFF;
        }
        let svc2 = make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
        let err = svc2
            .partial_sign_beacon_block(Request::new(sv2::PartialSignBeaconBlockRequest {
                requester_index: 1,
                pubkey: pk.to_vec(),
                fork_info: Some(sample_fork_info()),
                block_ssz: different_body,
                fork_id: 4,
            }))
            .await
            .expect_err("conflicting block must fail staging");
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );
        assert_eq!(
            db.get_blocks(&pubkey_hex).expect("get_blocks after reject").len(),
            1,
            "failed staging must not write another row"
        );

        // Same contract for attestation: stage_attestation → sign → commit.
        let svc_att =
            make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
        let att_ok = svc_att
            .partial_sign_attestation_data(Request::new(sv2::PartialSignAttestationDataRequest {
                requester_index: 1,
                pubkey: pk.to_vec(),
                fork_info: Some(sample_fork_info()),
                data: Some(sample_attestation_data(1, 2)),
                fork_id: 4,
            }))
            .await
            .expect("attestation partial sign must succeed");
        assert_eq!(att_ok.into_inner().partial_signature.len(), 96);
        let atts = db.get_attestations(&pubkey_hex).expect("get_attestations");
        assert_eq!(atts.len(), 1, "successful attestation partial sign must commit a slashing row");
        assert_eq!(atts[0].source_epoch, 1);
        assert_eq!(atts[0].target_epoch, 2);

        let mut data2 = sample_attestation_data(1, 2);
        data2.beacon_block_root = vec![0xFFu8; 32];
        let svc_att2 =
            make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
        let att_err = svc_att2
            .partial_sign_attestation_data(Request::new(sv2::PartialSignAttestationDataRequest {
                requester_index: 1,
                pubkey: pk.to_vec(),
                fork_info: Some(sample_fork_info()),
                data: Some(data2),
                fork_id: 4,
            }))
            .await
            .expect_err("double vote must fail staging");
        assert!(
            att_err.code() == tonic::Code::FailedPrecondition
                || att_err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            att_err.code()
        );

        // No slashing DB → require_db fails; no signature can be produced.
        let svc_no_db = make_service(vec![(pk, share)], al, None);
        let no_db_err = svc_no_db
            .partial_sign_beacon_block(Request::new(sv2::PartialSignBeaconBlockRequest {
                requester_index: 1,
                pubkey: pk.to_vec(),
                fork_info: Some(sample_fork_info()),
                block_ssz: sample_block_ssz(99),
                fork_id: 4,
            }))
            .await
            .expect_err("partial sign without a slashing DB must fail");
        assert_eq!(
            no_db_err.code(),
            tonic::Code::Internal,
            "missing slashing DB must fail closed, got {:?}",
            no_db_err.code()
        );
    }
}
