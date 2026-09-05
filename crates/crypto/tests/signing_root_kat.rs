//! RF2-07 / RF4-01: domain / signing-root known-answer tests for every duty.
//!
//! These KATs re-home free-function coverage onto [`signing_root_for`] (RF4-01),
//! with primitive vectors still pinned via [`compute_domain`] /
//! [`compute_signing_root`]. Each duty root assertion is a single byte-vector
//! equality against the shared helper.
//!
//! # Provenance
//!
//! - Primitive / simple-container vectors (ForkData, Domain, SigningData, Root, Epoch,
//!   Slot, AttestationData, SyncAggregatorSelectionData, VoluntaryExit,
//!   ValidatorRegistrationV1) are derived independently with `remerkleable` and
//!   cross-checked against rvc. Existing block/randao/domain KATs keep the same
//!   literal bytes as `signing.rs` / `block_signing.rs`.
//! - Complex containers that use BitList/BitVector tree-hash
//!   (AggregateAndProof, ElectraAggregateAndProof, ContributionAndProof) are
//!   regression pins of the free-function construction (domain type + fork version +
//!   object). They fail if the root construction drifts; they are not external
//!   consensus-spec fixtures.
//!
//! # Classification (see also `/tmp/grok-plan-summary-85fa6caa-rf2-07.md`)
//!
//! Source free-function tests fall into:
//! - **(a) domain/root KATs** — ported here.
//! - **(b) full-signature KATs** — none existed (no 96-byte reference vectors).
//! - **(c) self-consistency only** — not ported (H5 forbids); listed for RF2-08.
//!
//! `is_aggregator` (and its tests) live in `eth-types` after ARCH-6g; they are
//! duty-selection, not signing-root KATs.

use eth_types::{
    AggregateAndProof, Attestation, AttestationData, Checkpoint, ContributionAndProof, Domain,
    ElectraAggregateAndProof, ElectraAttestation, Epoch, ForkInfo, ForkName, ForkSchedule, Root,
    Slot, SyncAggregatorSelectionData, SyncCommitteeContribution, ValidatorRegistrationV1,
    VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
    DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
    SLOTS_PER_EPOCH,
};
use rvc_crypto::{
    capella_capped_fork_version, compute_domain, compute_fork_data_root, compute_signing_root,
    signing_root_for, DutyRef, KeyManager, LocalSigner, SecretKey, SignContext, SigningCtx,
    TypedSigner,
};

// ============================================================
// Shared fixtures
// ============================================================

const GVR: Root = [0xaa; 32];
const PHASE0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const ALTAIR: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
const BELLATRIX: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
const CAPELLA: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
const DENEB: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
const ELECTRA: [u8; 4] = [0x05, 0x00, 0x00, 0x00];

/// Compressed fork schedule matching free-function unit tests (epochs 10/20/30/40/50/60).
fn compressed_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: PHASE0,
        altair_fork_epoch: 10,
        altair_fork_version: ALTAIR,
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: BELLATRIX,
        capella_fork_epoch: 30,
        capella_fork_version: CAPELLA,
        deneb_fork_epoch: 40,
        deneb_fork_version: DENEB,
        electra_fork_epoch: 50,
        electra_fork_version: ELECTRA,
        fulu_fork_epoch: 60,
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
    }
}

fn make_local_signer(sk: SecretKey) -> LocalSigner {
    let mut km = KeyManager::new();
    km.insert(sk);
    LocalSigner::new(km)
}

fn signing_ctx(schedule: &ForkSchedule) -> SigningCtx<'_> {
    SigningCtx { fork_schedule: schedule, genesis_validators_root: GVR }
}

// ============================================================
// (a) Primitive compute_* KATs — same literal bytes as signing.rs
// ============================================================

// Port of `signing::tests::test_compute_fork_data_root_known_answer_bytes`.
// remerkleable ForkData(0x01000000, zeros).htr
#[test]
fn kat_compute_fork_data_root_known_answer_bytes() {
    const EXPECTED: Root = [
        0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e, 0x4d, 0xad, 0xcf, 0x81, 0x76,
        0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77, 0xbb, 0x2c, 0xf6, 0x61, 0x49, 0x38,
        0xb2, 0xaf,
    ];
    let root = compute_fork_data_root([0x01, 0x00, 0x00, 0x00], [0x00; 32]);
    assert_eq!(root, EXPECTED);
}

// Port of `signing::tests::test_compute_domain_known_answer_bytes`.
// domain_type = DOMAIN_BEACON_ATTESTER, fork_version = 0x01000000, gvr = zeros
#[test]
fn kat_compute_domain_known_answer_bytes() {
    const EXPECTED: Domain = [
        0x01, 0x00, 0x00, 0x00, 0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e, 0x4d,
        0xad, 0xcf, 0x81, 0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77, 0xbb, 0x2c,
        0xf6, 0x61,
    ];
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00], [0x00; 32]);
    assert_eq!(domain, EXPECTED);
}

// Port of `signing::tests::test_compute_signing_root_known_answer_bytes`.
// object = 0x11…11, domain = attester domain above
#[test]
fn kat_compute_signing_root_known_answer_bytes() {
    const DOMAIN: Domain = [
        0x01, 0x00, 0x00, 0x00, 0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e, 0x4d,
        0xad, 0xcf, 0x81, 0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77, 0xbb, 0x2c,
        0xf6, 0x61,
    ];
    const EXPECTED: Root = [
        0x18, 0x02, 0x9e, 0x3e, 0x0b, 0xe1, 0x98, 0x60, 0x45, 0x99, 0xda, 0xad, 0x88, 0xe7, 0xb3,
        0xbc, 0x5c, 0x1a, 0xae, 0x90, 0x84, 0xc0, 0x41, 0x66, 0x9a, 0xbd, 0x64, 0xe1, 0xa7, 0xb3,
        0x2d, 0xe5,
    ];
    let object: Root = [0x11; 32];
    assert_eq!(compute_signing_root(&object, DOMAIN), EXPECTED);
}

// ============================================================
// Domain-type constant pins (ported from free-function modules)
// ============================================================

#[test]
fn kat_domain_type_constants() {
    assert_eq!(DOMAIN_BEACON_PROPOSER, [0x00, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_RANDAO, [0x02, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_VOLUNTARY_EXIT, [0x04, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_SELECTION_PROOF, [0x05, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_AGGREGATE_AND_PROOF, [0x06, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_SYNC_COMMITTEE, [0x07, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, [0x08, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_CONTRIBUTION_AND_PROOF, [0x09, 0x00, 0x00, 0x00]);
    assert_eq!(DOMAIN_APPLICATION_BUILDER, [0x00, 0x00, 0x00, 0x01]);
}

// ============================================================
// sign_block / sign_randao_reveal — existing + fork-boundary KATs
// ============================================================

// Port of `block_signing::tests::test_block_signing_root_known_answer` (same bytes).
// domain_type = DOMAIN_BEACON_PROPOSER, fork = Phase0, gvr = 0xaa…, block_root = 0x11…
#[test]
fn kat_block_signing_root_phase0() {
    const EXPECTED: Root = [
        0x80, 0x1f, 0xbd, 0x74, 0x17, 0x52, 0xf6, 0xa9, 0xab, 0xaf, 0x0f, 0xd8, 0x20, 0xf9, 0xb3,
        0x1b, 0xb7, 0x8f, 0xc4, 0xba, 0x26, 0x9b, 0x51, 0x3a, 0x38, 0xd6, 0xfd, 0xf3, 0xf7, 0x9d,
        0xad, 0x8c,
    ];
    let schedule = compressed_schedule();
    let block_root: Root = [0x11; 32];
    let slot = 0u64; // Phase0 epoch
    assert_eq!(
        signing_root_for(&DutyRef::BlockRoot { root: &block_root, slot }, &signing_ctx(&schedule)),
        EXPECTED
    );
}

// Altair fork-boundary root for the same block_root (covers
// test_sign_block_fork_aware / test_sign_block_epoch_boundary domain half).
// remerkleable-derived.
#[test]
fn kat_block_signing_root_altair() {
    const EXPECTED: Root = [
        0xd8, 0x31, 0x4e, 0x38, 0xc6, 0x10, 0xe8, 0xb8, 0x76, 0x08, 0x80, 0x73, 0x34, 0x16, 0x0e,
        0xf0, 0xaf, 0xa6, 0xd1, 0x12, 0x53, 0xa8, 0xaf, 0xa1, 0x9b, 0x81, 0xef, 0x25, 0xa8, 0xeb,
        0xe3, 0xdf,
    ];
    let schedule = compressed_schedule();
    let block_root: Root = [0x11; 32];
    let altair_slot = 10 * SLOTS_PER_EPOCH;
    let phase0_slot = 0u64;
    let altair_root = signing_root_for(
        &DutyRef::BlockRoot { root: &block_root, slot: altair_slot },
        &signing_ctx(&schedule),
    );
    let phase0_root = signing_root_for(
        &DutyRef::BlockRoot { root: &block_root, slot: phase0_slot },
        &signing_ctx(&schedule),
    );
    assert_eq!(altair_root, EXPECTED);
    assert_ne!(altair_root, phase0_root);
}

// Port of `block_signing::tests::test_randao_signing_root_known_answer` (same bytes).
// domain_type = DOMAIN_RANDAO, fork = Phase0, gvr = 0xaa…, epoch = 5
#[test]
fn kat_randao_signing_root_phase0() {
    const EXPECTED: Root = [
        0x45, 0xbb, 0x77, 0xa0, 0x96, 0x6a, 0xa2, 0xe9, 0x01, 0xf6, 0x07, 0xe9, 0x6d, 0x76, 0xc6,
        0x45, 0xb8, 0xcb, 0xa1, 0x34, 0xe6, 0x85, 0xae, 0x26, 0x2e, 0x17, 0x8e, 0x3f, 0x76, 0xbe,
        0xda, 0x4c,
    ];
    let schedule = compressed_schedule();
    let epoch: Epoch = 5;
    assert_eq!(signing_root_for(&DutyRef::Randao(epoch), &signing_ctx(&schedule)), EXPECTED);
}

// Deneb-era RANDAO (covers test_sign_randao_reveal_fork_aware domain half).
// remerkleable-derived.
#[test]
fn kat_randao_signing_root_deneb() {
    const EXPECTED: Root = [
        0x5d, 0x41, 0x69, 0x6f, 0xc7, 0xef, 0x07, 0x52, 0xb9, 0xb0, 0x9d, 0x09, 0x3f, 0x20, 0xf8,
        0x72, 0x51, 0x5c, 0x23, 0x28, 0x2a, 0x2f, 0x54, 0x52, 0x93, 0x36, 0x18, 0xd4, 0x75, 0xf2,
        0xe3, 0xea,
    ];
    let schedule = compressed_schedule();
    let epoch: Epoch = 45;
    assert_eq!(signing_root_for(&DutyRef::Randao(epoch), &signing_ctx(&schedule)), EXPECTED);
}

// ============================================================
// sign_attestation — sample + Electra fork-boundary roots
// ============================================================

// Domain/root for create_test_attestation_data() at Phase0 (gvr=0xaa).
// remerkleable-derived; replaces the sign-then-verify half of
// test_sign_attestation_produces_valid_signature.
#[test]
fn kat_attestation_signing_root_phase0() {
    const EXPECTED_DOMAIN: Domain = [
        0x01, 0x00, 0x00, 0x00, 0x9e, 0xf8, 0x14, 0xb4, 0x2f, 0xa0, 0xbe, 0x12, 0xd1, 0x97, 0xc4,
        0x4d, 0x3e, 0x8e, 0x03, 0x44, 0x1a, 0x4b, 0x11, 0x18, 0x23, 0x76, 0x58, 0x36, 0x8b, 0xa1,
        0x35, 0x10,
    ];
    const EXPECTED_ROOT: Root = [
        0x19, 0xc5, 0xa8, 0xde, 0xc2, 0xac, 0x03, 0x7c, 0xc0, 0x9e, 0x7a, 0x86, 0xbd, 0x59, 0xef,
        0x01, 0xc1, 0x60, 0x0e, 0xd9, 0x18, 0x1c, 0xeb, 0x37, 0x45, 0x2b, 0x68, 0x1b, 0x73, 0xb9,
        0xdb, 0x9d,
    ];
    // Phase0 target epoch must be < altair_fork_epoch (10) for Phase0 domain.
    // Historical KAT used target epoch 100 with an explicit Phase0 fork version;
    // under signing_root_for that epoch is Fulu — keep domain pin + use epoch 5 for root_for.
    let data = AttestationData {
        slot: 1000,
        index: 5,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 99, root: [0x22; 32] },
        target: Checkpoint { epoch: 100, root: [0x33; 32] },
    };
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, PHASE0, GVR);
    assert_eq!(domain, EXPECTED_DOMAIN);
    assert_eq!(compute_signing_root(&data, domain), EXPECTED_ROOT);

    // Same object under Phase0-forced domain via helper needs a Phase0 target epoch.
    // The EXPECTED_ROOT above is the legacy Phase0 domain pin (unchanged).
    let schedule = compressed_schedule();
    let phase0_data = AttestationData {
        slot: 5 * SLOTS_PER_EPOCH,
        index: 5,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 4, root: [0x22; 32] },
        target: Checkpoint { epoch: 5, root: [0x33; 32] },
    };
    let via_for = signing_root_for(&DutyRef::Attestation(&phase0_data), &signing_ctx(&schedule));
    let domain_p0 = compute_domain(DOMAIN_BEACON_ATTESTER, PHASE0, GVR);
    assert_eq!(via_for, compute_signing_root(&phase0_data, domain_p0));
}

// Electra boundary − 1 → Deneb fork version (test_sign_attestation_at_electra_boundary_minus_one).
#[test]
fn kat_attestation_signing_root_electra_boundary_minus_one_deneb() {
    const EXPECTED: Root = [
        0xa9, 0xc6, 0xef, 0x3d, 0x6f, 0xe1, 0x46, 0x30, 0xd5, 0xf4, 0x16, 0x96, 0x09, 0x72, 0x67,
        0x25, 0x24, 0xf3, 0x54, 0x35, 0x6a, 0x67, 0xed, 0xd3, 0xe9, 0x41, 0xfc, 0xbc, 0x37, 0xb9,
        0xb1, 0x24,
    ];
    let schedule = compressed_schedule();
    let target_epoch = 49u64; // electra_fork_epoch - 1 on compressed schedule
    let data = AttestationData {
        slot: target_epoch * SLOTS_PER_EPOCH,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
        target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
    };
    assert_eq!(signing_root_for(&DutyRef::Attestation(&data), &signing_ctx(&schedule)), EXPECTED);
}

// Electra boundary → Electra fork version.
#[test]
fn kat_attestation_signing_root_electra_boundary() {
    const EXPECTED: Root = [
        0x28, 0x15, 0x19, 0xab, 0x10, 0xc9, 0x03, 0x76, 0x54, 0x79, 0xae, 0xd8, 0xa4, 0xec, 0x73,
        0xae, 0x7b, 0x3c, 0x9a, 0x2f, 0x90, 0xf8, 0xa2, 0x12, 0x53, 0x1b, 0x93, 0x8e, 0x7b, 0xe7,
        0xcb, 0x5c,
    ];
    let schedule = compressed_schedule();
    let target_epoch = 50u64;
    let data = AttestationData {
        slot: target_epoch * SLOTS_PER_EPOCH,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
        target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
    };
    let root = signing_root_for(&DutyRef::Attestation(&data), &signing_ctx(&schedule));
    assert_eq!(root, EXPECTED);
    // Boundary: epoch 49 (Deneb) must not yield the same root as epoch 50.
    let pre = AttestationData {
        slot: 49 * SLOTS_PER_EPOCH,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 48, root: [0x22; 32] },
        target: Checkpoint { epoch: 49, root: [0x33; 32] },
    };
    assert_ne!(root, signing_root_for(&DutyRef::Attestation(&pre), &signing_ctx(&schedule)));
}

// ============================================================
// sign_selection_proof / sign_aggregate_and_proof /
// sign_electra_aggregate_and_proof
// ============================================================

#[test]
fn kat_selection_proof_signing_root_phase0() {
    const EXPECTED: Root = [
        0x49, 0x98, 0x34, 0x4d, 0xc2, 0x6f, 0x87, 0x23, 0xf3, 0x8c, 0x80, 0x43, 0xd9, 0x6b, 0x76,
        0xa8, 0x92, 0x14, 0xee, 0xd0, 0x54, 0x0e, 0x3c, 0x28, 0x3c, 0x8a, 0xd0, 0x4c, 0x8f, 0x4d,
        0xb7, 0xaf,
    ];
    let schedule = compressed_schedule();
    let slot: Slot = 100;
    assert_eq!(signing_root_for(&DutyRef::SelectionProof(slot), &signing_ctx(&schedule)), EXPECTED);
}

// Altair fork-aware selection proof (test_sign_selection_proof_fork_aware).
// Historical KAT used slot = 74240 * SPE with an explicit Altair domain; under
// compressed schedule that epoch is far past Fulu. Pin via compute_domain and
// assert signing_root_for parity on a compressed-schedule Altair slot.
#[test]
fn kat_selection_proof_signing_root_altair() {
    const EXPECTED: Root = [
        0x5f, 0xcb, 0x4a, 0xf2, 0x8d, 0x98, 0x73, 0xca, 0x50, 0xd8, 0x04, 0xa0, 0xcf, 0xbb, 0x9f,
        0xdb, 0x69, 0x17, 0xe4, 0xa9, 0xad, 0x9f, 0x14, 0x8c, 0xd8, 0x6c, 0x58, 0x91, 0xeb, 0xf1,
        0x49, 0xac,
    ];
    let slot: Slot = 74240 * SLOTS_PER_EPOCH;
    let domain = compute_domain(DOMAIN_SELECTION_PROOF, ALTAIR, GVR);
    assert_eq!(compute_signing_root(&slot, domain), EXPECTED);

    let schedule = compressed_schedule();
    let altair_slot = 10 * SLOTS_PER_EPOCH;
    let via_for = signing_root_for(&DutyRef::SelectionProof(altair_slot), &signing_ctx(&schedule));
    let domain_altair = compute_domain(DOMAIN_SELECTION_PROOF, ALTAIR, GVR);
    assert_eq!(via_for, compute_signing_root(&altair_slot, domain_altair));
}

// AggregateAndProof sample from aggregation_signing::sample_aggregate_and_proof(100).
// Complex BitList container — regression pin of free-function construction.
#[test]
fn kat_aggregate_and_proof_signing_root_phase0() {
    const EXPECTED: Root = [
        0xbb, 0x54, 0x16, 0xb3, 0xdc, 0xde, 0xb5, 0x86, 0xb5, 0x4c, 0xe6, 0xcc, 0xe8, 0x39, 0x33,
        0xf9, 0xa0, 0x60, 0x1d, 0xc4, 0xe3, 0x53, 0xc9, 0x85, 0x58, 0x83, 0x25, 0x6a, 0xd4, 0x4b,
        0xf3, 0x84,
    ];
    let schedule = compressed_schedule();
    let slot: Slot = 100;
    let agg = AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH - 1, root: [2u8; 32] },
                target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    };
    assert_eq!(
        signing_root_for(&DutyRef::AggregateAndProof(&agg), &signing_ctx(&schedule)),
        EXPECTED
    );
}

// ElectraAggregateAndProof at electra epoch (test_sign_electra_aggregate_and_proof_valid).
#[test]
fn kat_electra_aggregate_and_proof_signing_root() {
    const KAT_EXPECTED: Root = [
        0x90, 0x5a, 0x0f, 0x50, 0x0c, 0x08, 0x7e, 0xdf, 0x43, 0x87, 0x77, 0xd1, 0x8d, 0xdc, 0x2b,
        0xb7, 0xc9, 0xfc, 0x57, 0x1a, 0xa1, 0x0a, 0xa6, 0xe4, 0xc0, 0x52, 0xe4, 0x6e, 0x0e, 0x0f,
        0x5b, 0xe2,
    ];
    let schedule = compressed_schedule();
    let slot = 50 * SLOTS_PER_EPOCH;
    let agg = ElectraAggregateAndProof {
        aggregator_index: 42,
        aggregate: ElectraAttestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: 49, root: [2u8; 32] },
                target: Checkpoint { epoch: 50, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
        },
        selection_proof: vec![0xbb; 96],
    };
    assert_eq!(
        signing_root_for(&DutyRef::ElectraAggregateAndProof(&agg), &signing_ctx(&schedule)),
        KAT_EXPECTED
    );
}

// ============================================================
// sign_sync_committee_message / sign_contribution_and_proof /
// sign_sync_committee_selection_proof
// ============================================================

#[test]
fn kat_sync_committee_message_signing_root_phase0() {
    const EXPECTED: Root = [
        0x5c, 0xfb, 0x10, 0x98, 0xb7, 0x3a, 0x93, 0xeb, 0x68, 0xe3, 0x79, 0x03, 0xf6, 0x6a, 0xcd,
        0x7a, 0xf9, 0xec, 0x54, 0xe1, 0x09, 0x88, 0x8d, 0xf1, 0xab, 0x21, 0x84, 0x1a, 0x97, 0x0f,
        0xb0, 0x74,
    ];
    let schedule = compressed_schedule();
    let beacon_block_root: Root = [0x11; 32];
    let slot: Slot = 100; // Phase0
    assert_eq!(
        signing_root_for(
            &DutyRef::SyncMessage { beacon_block_root: &beacon_block_root, slot },
            &signing_ctx(&schedule)
        ),
        EXPECTED
    );
}

// Altair vs Phase0 fork-aware (test_sign_sync_committee_message_fork_aware).
#[test]
fn kat_sync_committee_message_signing_root_altair() {
    const EXPECTED: Root = [
        0x0f, 0x38, 0xeb, 0xc8, 0x7b, 0xb2, 0xea, 0x52, 0xbd, 0x69, 0x14, 0x20, 0xb6, 0x8a, 0x39,
        0x53, 0x31, 0x74, 0xe7, 0xab, 0x20, 0xee, 0x4e, 0xde, 0xcf, 0x48, 0xad, 0x23, 0x2a, 0x76,
        0x69, 0xf3,
    ];
    let schedule = compressed_schedule();
    let beacon_block_root: Root = [0x11; 32];
    let altair_slot = 10 * SLOTS_PER_EPOCH;
    let phase0_slot = 0u64;
    let altair_root = signing_root_for(
        &DutyRef::SyncMessage { beacon_block_root: &beacon_block_root, slot: altair_slot },
        &signing_ctx(&schedule),
    );
    let phase0_root = signing_root_for(
        &DutyRef::SyncMessage { beacon_block_root: &beacon_block_root, slot: phase0_slot },
        &signing_ctx(&schedule),
    );
    assert_eq!(altair_root, EXPECTED);
    assert_ne!(altair_root, phase0_root);
}

// ContributionAndProof at Altair (test_sign_contribution_and_proof_altair).
// Complex BitVector container — regression pin.
#[test]
fn kat_contribution_and_proof_signing_root_altair() {
    const EXPECTED: Root = [
        0x3f, 0x15, 0x62, 0xb1, 0x76, 0x77, 0x5d, 0x3e, 0x0f, 0x5f, 0x5d, 0x13, 0xf4, 0xdf, 0x36,
        0x7c, 0x33, 0x21, 0x8b, 0x88, 0x56, 0xcc, 0x56, 0xa3, 0x92, 0x52, 0x22, 0xef, 0x6d, 0xa5,
        0x34, 0x93,
    ];
    let schedule = compressed_schedule();
    let cap = ContributionAndProof {
        aggregator_index: 42,
        contribution: SyncCommitteeContribution {
            slot: 10 * SLOTS_PER_EPOCH,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        },
        selection_proof: vec![0xcc; 96],
    };
    assert_eq!(
        signing_root_for(&DutyRef::ContributionAndProof(&cap), &signing_ctx(&schedule)),
        EXPECTED
    );
}

// Fork-boundary contribution: pre-Altair vs Altair must differ
// (test_sign_contribution_and_proof_fork_boundary domain half).
#[test]
fn kat_contribution_and_proof_fork_boundary_domains_differ() {
    let schedule = compressed_schedule();
    let pre = ContributionAndProof {
        aggregator_index: 42,
        contribution: SyncCommitteeContribution {
            slot: 10 * SLOTS_PER_EPOCH - 1,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        },
        selection_proof: vec![0xcc; 96],
    };
    let post = ContributionAndProof {
        aggregator_index: 42,
        contribution: SyncCommitteeContribution {
            slot: 10 * SLOTS_PER_EPOCH,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        },
        selection_proof: vec![0xcc; 96],
    };
    let pre_root = signing_root_for(&DutyRef::ContributionAndProof(&pre), &signing_ctx(&schedule));
    let post_root =
        signing_root_for(&DutyRef::ContributionAndProof(&post), &signing_ctx(&schedule));
    assert_ne!(pre_root, post_root);
}

#[test]
fn kat_sync_selection_proof_signing_root_phase0() {
    const EXPECTED: Root = [
        0x61, 0x11, 0x08, 0xec, 0x75, 0x18, 0x91, 0xfd, 0x0c, 0x9f, 0x05, 0xa4, 0x58, 0x4d, 0x5d,
        0x30, 0x14, 0x55, 0xad, 0xb8, 0x60, 0xe9, 0x09, 0xe5, 0xfc, 0xc8, 0xcc, 0x57, 0x07, 0x13,
        0x78, 0xd3,
    ];
    let schedule = compressed_schedule();
    assert_eq!(
        signing_root_for(
            &DutyRef::SyncSelection { slot: 100, subcommittee_index: 2 },
            &signing_ctx(&schedule)
        ),
        EXPECTED
    );
}

// Deneb fork-aware selection (test_sign_sync_committee_selection_proof_fork_aware).
// Historical slot is mainnet-scale; keep compute_domain pin + parity on compressed Deneb.
#[test]
fn kat_sync_selection_proof_signing_root_deneb() {
    const EXPECTED: Root = [
        0xac, 0xaa, 0xab, 0x59, 0x5a, 0x11, 0xf3, 0x5f, 0x6f, 0xae, 0x5e, 0x58, 0x91, 0xc8, 0x9e,
        0x97, 0xc1, 0xef, 0xa1, 0xe6, 0xaa, 0xd8, 0x53, 0x3e, 0x87, 0x5e, 0xc2, 0x61, 0x34, 0x76,
        0x9b, 0x72,
    ];
    let selection_data =
        SyncAggregatorSelectionData { slot: 269568 * SLOTS_PER_EPOCH, subcommittee_index: 1 };
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DENEB, GVR);
    assert_eq!(compute_signing_root(&selection_data, domain), EXPECTED);

    let schedule = compressed_schedule();
    let deneb_slot = 40 * SLOTS_PER_EPOCH;
    let via_for = signing_root_for(
        &DutyRef::SyncSelection { slot: deneb_slot, subcommittee_index: 1 },
        &signing_ctx(&schedule),
    );
    let domain_deneb = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DENEB, GVR);
    let selection = SyncAggregatorSelectionData { slot: deneb_slot, subcommittee_index: 1 };
    assert_eq!(via_for, compute_signing_root(&selection, domain_deneb));
}

// Subcommittee index binds into the root (test_selection_proof_binds_to_subcommittee_index).
#[test]
fn kat_sync_selection_proof_binds_subcommittee_index() {
    let schedule = compressed_schedule();
    let r0 = signing_root_for(
        &DutyRef::SyncSelection { slot: 100, subcommittee_index: 0 },
        &signing_ctx(&schedule),
    );
    let r1 = signing_root_for(
        &DutyRef::SyncSelection { slot: 100, subcommittee_index: 1 },
        &signing_ctx(&schedule),
    );
    assert_ne!(r0, r1);
}

// ============================================================
// sign_builder_registration
// ============================================================

// Zeroed gvr + DOMAIN_APPLICATION_BUILDER (test_sign_builder_registration_uses_zeroed_genesis_root).
// remerkleable-derived. Historical vector uses ALTAIR as the explicit fork version
// (builder path takes it as a parameter; RF4-10 pins genesis).
#[test]
fn kat_builder_registration_signing_root() {
    const EXPECTED_DOMAIN: Domain = [
        0x00, 0x00, 0x00, 0x01, 0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e, 0x4d,
        0xad, 0xcf, 0x81, 0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77, 0xbb, 0x2c,
        0xf6, 0x61,
    ];
    const KAT_EXPECTED_ROOT: Root = [
        0x06, 0x13, 0x1b, 0x3a, 0x74, 0x1b, 0xd5, 0x52, 0x58, 0x93, 0xbf, 0xe1, 0x4d, 0x62, 0xb9,
        0xb4, 0xfc, 0x10, 0x8b, 0x1f, 0x01, 0xc4, 0xc9, 0x51, 0x97, 0xeb, 0x7f, 0xc5, 0x6e, 0xeb,
        0x44, 0x89,
    ];
    let schedule = compressed_schedule();
    let registration = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: [0xcd; 48],
    };
    let zeroed_gvr = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, ALTAIR, zeroed_gvr);
    assert_eq!(domain, EXPECTED_DOMAIN);
    assert_eq!(
        signing_root_for(
            &DutyRef::BuilderRegistration {
                registration: &registration,
                genesis_fork_version: ALTAIR,
            },
            &signing_ctx(&schedule)
        ),
        KAT_EXPECTED_ROOT
    );
    // Non-zero gvr must produce a different domain (zeroed-gvr contract).
    let nonzero = compute_domain(DOMAIN_APPLICATION_BUILDER, ALTAIR, GVR);
    assert_ne!(domain, nonzero);
}

// ============================================================
// EIP-7044 Capella-cap (capella_capped_fork_version + voluntary-exit domain)
// ============================================================

#[test]
fn kat_eip7044_capella_capped_fork_version_boundaries() {
    let schedule = compressed_schedule();
    // Pre-Capella (Bellatrix epoch 25): not capped.
    assert_eq!(capella_capped_fork_version(25, &schedule), BELLATRIX);
    // Capella epoch: Capella version.
    assert_eq!(capella_capped_fork_version(30, &schedule), CAPELLA);
    // Deneb epoch 45: capped at Capella.
    assert_eq!(capella_capped_fork_version(45, &schedule), CAPELLA);
    // Electra epoch 55: capped at Capella.
    assert_eq!(capella_capped_fork_version(55, &schedule), CAPELLA);
}

// Post-Capella exit root uses Capella fork version (EIP-7044) inside signing_root_for.
// remerkleable-derived. Mirrors test_sign_voluntary_exit_eip7044_caps_at_capella.
#[test]
fn kat_voluntary_exit_signing_root_eip7044_deneb_capped() {
    const EXPECTED_DOMAIN: Domain = [
        0x04, 0x00, 0x00, 0x00, 0xf0, 0x77, 0x3b, 0x45, 0x39, 0xa6, 0xbb, 0x1c, 0x2c, 0x46, 0x5a,
        0x8d, 0xb8, 0x80, 0x43, 0xdb, 0x4d, 0x9e, 0x82, 0xec, 0x3c, 0x81, 0x68, 0xb6, 0xa7, 0x9f,
        0xe0, 0xf0,
    ];
    const EXPECTED_ROOT: Root = [
        0xe7, 0x43, 0x2d, 0x27, 0xaf, 0x0c, 0x7e, 0xe4, 0xe3, 0x98, 0xb6, 0xa9, 0xd6, 0x02, 0xd0,
        0x2f, 0x46, 0xf1, 0xea, 0x97, 0x29, 0xe4, 0x3a, 0xce, 0x3a, 0xa2, 0x78, 0xf9, 0x3e, 0x03,
        0xd4, 0xe1,
    ];
    let schedule = compressed_schedule();
    let exit = VoluntaryExit { epoch: 45, validator_index: 42 };
    let version = capella_capped_fork_version(exit.epoch, &schedule);
    assert_eq!(version, CAPELLA);
    let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, version, GVR);
    assert_eq!(domain, EXPECTED_DOMAIN);
    let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &signing_ctx(&schedule));
    assert_eq!(root, EXPECTED_ROOT);
    // Uncapped Deneb domain must differ.
    let deneb_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, DENEB, GVR);
    assert_ne!(domain, deneb_domain);
    assert_ne!(root, compute_signing_root(&exit, deneb_domain));
}

// Pre-Capella exit uses Bellatrix, not Capella.
#[test]
fn kat_voluntary_exit_signing_root_pre_capella_not_capped() {
    const EXPECTED: Root = [
        0x03, 0x68, 0x4c, 0xe0, 0x5e, 0x13, 0x9c, 0xef, 0xcd, 0xb0, 0x40, 0x9d, 0x91, 0x65, 0xcc,
        0x42, 0x40, 0x85, 0x4a, 0xa9, 0x88, 0x59, 0xa4, 0x39, 0x5e, 0x69, 0x56, 0x84, 0x5d, 0x15,
        0xaf, 0x0a,
    ];
    let schedule = compressed_schedule();
    let exit = VoluntaryExit { epoch: 25, validator_index: 42 };
    assert_eq!(capella_capped_fork_version(exit.epoch, &schedule), BELLATRIX);
    let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &signing_ctx(&schedule));
    assert_eq!(root, EXPECTED);
    let capella_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA, GVR);
    assert_ne!(root, compute_signing_root(&exit, capella_domain));
}

// ============================================================
// LocalSigner / TypedSigner against ported KAT roots
// (surviving production path; free functions still exist for RF2-08)
// ============================================================

#[tokio::test]
async fn kat_typed_signer_attestation_matches_kat_root() {
    const KAT_EXPECTED_ROOT: Root = [
        0x19, 0xc5, 0xa8, 0xde, 0xc2, 0xac, 0x03, 0x7c, 0xc0, 0x9e, 0x7a, 0x86, 0xbd, 0x59, 0xef,
        0x01, 0xc1, 0x60, 0x0e, 0xd9, 0x18, 0x1c, 0xeb, 0x37, 0x45, 0x2b, 0x68, 0x1b, 0x73, 0xb9,
        0xdb, 0x9d,
    ];
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let data = AttestationData {
        slot: 1000,
        index: 5,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 99, root: [0x22; 32] },
        target: Checkpoint { epoch: 100, root: [0x33; 32] },
    };
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, PHASE0, GVR);
    assert_eq!(compute_signing_root(&data, domain), KAT_EXPECTED_ROOT);

    let ctx = SignContext {
        pubkey: pk.clone(),
        fork_info: ForkInfo {
            previous_version: PHASE0,
            current_version: PHASE0,
            genesis_validators_root: GVR,
        },
        fork_name: ForkName::Phase0,
    };
    let signer = make_local_signer(sk);
    let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();
    assert!(sig.verify(&pk, &KAT_EXPECTED_ROOT).is_ok());
}

#[tokio::test]
async fn kat_typed_signer_randao_matches_kat_root() {
    const KAT_EXPECTED_ROOT: Root = [
        0x45, 0xbb, 0x77, 0xa0, 0x96, 0x6a, 0xa2, 0xe9, 0x01, 0xf6, 0x07, 0xe9, 0x6d, 0x76, 0xc6,
        0x45, 0xb8, 0xcb, 0xa1, 0x34, 0xe6, 0x85, 0xae, 0x26, 0x2e, 0x17, 0x8e, 0x3f, 0x76, 0xbe,
        0xda, 0x4c,
    ];
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let epoch: Epoch = 5;
    let domain = compute_domain(DOMAIN_RANDAO, PHASE0, GVR);
    assert_eq!(compute_signing_root(&epoch, domain), KAT_EXPECTED_ROOT);

    let ctx = SignContext {
        pubkey: pk.clone(),
        fork_info: ForkInfo {
            previous_version: PHASE0,
            current_version: PHASE0,
            genesis_validators_root: GVR,
        },
        fork_name: ForkName::Phase0,
    };
    let signer = make_local_signer(sk);
    let sig = TypedSigner::sign_randao_reveal(&signer, epoch, &ctx).await.unwrap();
    assert!(sig.verify(&pk, &KAT_EXPECTED_ROOT).is_ok());
}

#[tokio::test]
async fn kat_typed_signer_builder_registration_matches_kat_root() {
    const KAT_EXPECTED_ROOT: Root = [
        0x06, 0x13, 0x1b, 0x3a, 0x74, 0x1b, 0xd5, 0x52, 0x58, 0x93, 0xbf, 0xe1, 0x4d, 0x62, 0xb9,
        0xb4, 0xfc, 0x10, 0x8b, 0x1f, 0x01, 0xc4, 0xc9, 0x51, 0x97, 0xeb, 0x7f, 0xc5, 0x6e, 0xeb,
        0x44, 0x89,
    ];
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let registration = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: [0xcd; 48],
    };
    let ctx = SignContext {
        pubkey: pk.clone(),
        fork_info: ForkInfo {
            previous_version: PHASE0,
            current_version: ALTAIR,
            genesis_validators_root: GVR, // unused for builder; zero gvr is internal
        },
        fork_name: ForkName::Altair,
    };
    let signer = make_local_signer(sk);
    let sig =
        TypedSigner::sign_builder_registration(&signer, &registration, ALTAIR, &ctx).await.unwrap();
    assert!(sig.verify(&pk, &KAT_EXPECTED_ROOT).is_ok());
}

#[tokio::test]
async fn kat_typed_signer_voluntary_exit_eip7044_matches_kat_root() {
    const KAT_EXPECTED_ROOT: Root = [
        0xe7, 0x43, 0x2d, 0x27, 0xaf, 0x0c, 0x7e, 0xe4, 0xe3, 0x98, 0xb6, 0xa9, 0xd6, 0x02, 0xd0,
        0x2f, 0x46, 0xf1, 0xea, 0x97, 0x29, 0xe4, 0x3a, 0xce, 0x3a, 0xa2, 0x78, 0xf9, 0x3e, 0x03,
        0xd4, 0xe1,
    ];
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let schedule = compressed_schedule();
    let exit = VoluntaryExit { epoch: 45, validator_index: 42 };
    let version = capella_capped_fork_version(exit.epoch, &schedule);
    assert_eq!(version, CAPELLA);

    let ctx = SignContext {
        pubkey: pk.clone(),
        fork_info: ForkInfo {
            previous_version: CAPELLA,
            current_version: version, // Capella-capped (caller responsibility)
            genesis_validators_root: GVR,
        },
        fork_name: ForkName::Capella,
    };
    let signer = make_local_signer(sk);
    let sig = TypedSigner::sign_voluntary_exit(&signer, &exit, &ctx).await.unwrap();
    assert!(sig.verify(&pk, &KAT_EXPECTED_ROOT).is_ok());
}

#[tokio::test]
async fn kat_typed_signer_sync_message_matches_kat_root() {
    const KAT_EXPECTED_ROOT: Root = [
        0x5c, 0xfb, 0x10, 0x98, 0xb7, 0x3a, 0x93, 0xeb, 0x68, 0xe3, 0x79, 0x03, 0xf6, 0x6a, 0xcd,
        0x7a, 0xf9, 0xec, 0x54, 0xe1, 0x09, 0x88, 0x8d, 0xf1, 0xab, 0x21, 0x84, 0x1a, 0x97, 0x0f,
        0xb0, 0x74,
    ];
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let beacon_block_root: Root = [0x11; 32];
    let slot: Slot = 100;
    let ctx = SignContext {
        pubkey: pk.clone(),
        fork_info: ForkInfo {
            previous_version: PHASE0,
            current_version: PHASE0,
            genesis_validators_root: GVR,
        },
        fork_name: ForkName::Phase0,
    };
    let signer = make_local_signer(sk);
    let sig = TypedSigner::sign_sync_committee_message(&signer, slot, beacon_block_root, &ctx)
        .await
        .unwrap();
    assert!(sig.verify(&pk, &KAT_EXPECTED_ROOT).is_ok());
}
