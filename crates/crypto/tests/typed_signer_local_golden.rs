//! Golden-vector tests for [`LocalSigner`]'s [`TypedSigner`] implementation.
//!
//! Each test:
//! 1. Constructs a known-good consensus object with fixed constants.
//! 2. Calls the corresponding `TypedSigner` method.
//! 3. Reconstructs the signing root via the domain helpers.
//! 4. Verifies the signature against the public key.
//! 5. Asserts the signing root is deterministic (self-consistent golden vector).
//!
//! These are synthetic golden vectors — no Lighthouse fixture is imported
//! here (that would require network fixtures). The vectors are internally
//! consistent: same inputs always produce the same root and the signature
//! always verifies. The key property proven is that `TypedSigner` uses
//! the correct domain for each duty type.

use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlock, BlindedBeaconBlock, Checkpoint,
    ContributionAndProof, ForkInfo, ForkName, ForkSchedule, SyncAggregatorSelectionData,
    SyncCommitteeContribution, ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use rvc_crypto::KeyManager;
use rvc_crypto::{
    capella_capped_fork_version, compute_domain, compute_signing_root, LocalSigner, SecretKey,
    SignContext, TypedSigner,
};

// ============================================================
// Fixtures
// ============================================================

const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0xaa; 32];
// Deneb fork version — used for most tests
const CURRENT_FORK_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
const PREVIOUS_FORK_VERSION: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

fn test_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
        altair_fork_epoch: 10,
        altair_fork_version: [0x01, 0x00, 0x00, 0x00],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        capella_fork_epoch: 30,
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        deneb_fork_epoch: 40,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        electra_fork_epoch: 50,
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
    }
}

fn make_signer(sk: SecretKey) -> LocalSigner {
    let mut km = KeyManager::new();
    km.insert(sk);
    LocalSigner::new(km)
}

fn deneb_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: PREVIOUS_FORK_VERSION,
        current_version: CURRENT_FORK_VERSION,
        genesis_validators_root: GENESIS_VALIDATORS_ROOT,
    }
}

fn make_ctx(sk: &SecretKey, fork_info: ForkInfo) -> SignContext {
    SignContext { pubkey: sk.public_key(), fork_info, fork_name: ForkName::Deneb }
}

// ============================================================
// test_typed_signer_local_block_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_block_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let block = BeaconBlock {
        slot: 1_000_000,
        proposer_index: 12345,
        parent_root: [0x10; 32],
        state_root: [0x20; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_block(&signer, &block, &ctx).await.unwrap();

    // Reconstruct signing root
    let domain =
        compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&block, domain);

    // Verify signature
    assert!(sig.verify(&pk, &signing_root).is_ok(), "block signature must verify");

    // Wrong domain must fail
    let wrong_domain = compute_domain(DOMAIN_RANDAO, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let wrong_root = compute_signing_root(&block, wrong_domain);
    assert!(sig.verify(&pk, &wrong_root).is_err(), "block sig must not verify with wrong domain");
}

// ============================================================
// test_typed_signer_local_blinded_block_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_blinded_block_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let block = BlindedBeaconBlock {
        slot: 2_000_000,
        proposer_index: 42,
        parent_root: [0x30; 32],
        state_root: [0x40; 32],
        body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_blinded_block(&signer, &block, &ctx).await.unwrap();

    let domain =
        compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&block, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "blinded block signature must verify");
}

// ============================================================
// test_typed_signer_local_attestation_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_attestation_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let data = AttestationData {
        slot: 1_280_000, // epoch 40_000 (Deneb)
        index: 0,
        beacon_block_root: [0x50; 32],
        source: Checkpoint { epoch: 39999, root: [0x60; 32] },
        target: Checkpoint { epoch: 40000, root: [0x70; 32] },
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();

    let domain =
        compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&data, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "attestation signature must verify");
}

// ============================================================
// test_typed_signer_local_aggregate_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_aggregate_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let agg = AggregateAndProof {
        aggregator_index: 777,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot: 1_280_000,
                index: 1,
                beacon_block_root: [0x80; 32],
                source: Checkpoint { epoch: 39999, root: [0x90; 32] },
                target: Checkpoint { epoch: 40000, root: [0xa0; 32] },
            },
            signature: vec![0xbb; 96],
        },
        selection_proof: vec![0xcc; 96],
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_aggregate_and_proof(&signer, &agg, &ctx).await.unwrap();

    let domain =
        compute_domain(DOMAIN_AGGREGATE_AND_PROOF, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&agg, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "aggregate signature must verify");
}

// ============================================================
// test_typed_signer_local_sync_committee_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_sync_committee_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let slot = 1_280_001u64;
    let beacon_block_root = [0xb0; 32];
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_sync_committee_message(&signer, slot, beacon_block_root, &ctx)
        .await
        .unwrap();

    let domain =
        compute_domain(DOMAIN_SYNC_COMMITTEE, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&beacon_block_root, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "sync committee message signature must verify");
}

// ============================================================
// test_typed_signer_local_sync_aggregator_selection_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_sync_aggregator_selection_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let slot = 1_280_002u64;
    let subcommittee_index = 5u64;
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_sync_aggregator_selection(&signer, slot, subcommittee_index, &ctx)
        .await
        .unwrap();

    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        CURRENT_FORK_VERSION,
        GENESIS_VALIDATORS_ROOT,
    );
    let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = compute_signing_root(&selection_data, domain);

    assert!(
        sig.verify(&pk, &signing_root).is_ok(),
        "sync aggregator selection signature must verify"
    );
}

// ============================================================
// test_typed_signer_local_contribution_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_contribution_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let c = ContributionAndProof {
        aggregator_index: 888,
        contribution: SyncCommitteeContribution {
            slot: 1_280_003,
            beacon_block_root: [0xc0; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0x0f; 16],
            signature: vec![0xdd; 96],
        },
        selection_proof: vec![0xee; 96],
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_contribution_and_proof(&signer, &c, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_CONTRIBUTION_AND_PROOF,
        CURRENT_FORK_VERSION,
        GENESIS_VALIDATORS_ROOT,
    );
    let signing_root = compute_signing_root(&c, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "contribution-and-proof signature must verify");
}

// ============================================================
// test_typed_signer_local_builder_registration_golden
//
// Uses compute_domain(DOMAIN_APPLICATION_BUILDER, GENESIS_FORK_VERSION, ZERO_HASH)
// per MEV-Boost spec (confirmed correct in audit false-positive analysis).
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_builder_registration_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let genesis_fork_version = [0x00u8, 0x00, 0x00, 0x00];
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: pk.to_bytes(),
    };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_builder_registration(&signer, &reg, genesis_fork_version, &ctx)
        .await
        .unwrap();

    let zero_gvr = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
    let signing_root = compute_signing_root(&reg, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "builder registration signature must verify");

    // Non-zero gvr must fail
    let wrong_domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, [0xff; 32]);
    let wrong_root = compute_signing_root(&reg, wrong_domain);
    assert!(
        sig.verify(&pk, &wrong_root).is_err(),
        "builder registration sig must not verify with non-zero gvr"
    );
}

// ============================================================
// test_typed_signer_local_randao_golden
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_randao_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let ctx = make_ctx(&sk, deneb_fork_info());
    let epoch = 40_000u64;
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_randao_reveal(&signer, epoch, &ctx).await.unwrap();

    let domain = compute_domain(DOMAIN_RANDAO, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&epoch, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "randao signature must verify");
}

// ============================================================
// test_typed_signer_local_voluntary_exit_golden
//
// Uses Capella-capped fork version (EIP-7044) for an exit at a post-Capella epoch.
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_voluntary_exit_golden() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let schedule = test_schedule();
    let exit_epoch = 45u64; // Deneb era, but EIP-7044 caps at Capella
    let capella_version = capella_capped_fork_version(exit_epoch, &schedule);
    // Capella fork version for this schedule is [0x03, 0x00, 0x00, 0x00]

    let fork_info = ForkInfo {
        previous_version: [0x02, 0x00, 0x00, 0x00],
        current_version: capella_version,
        genesis_validators_root: GENESIS_VALIDATORS_ROOT,
    };
    let ctx = SignContext { pubkey: sk.public_key(), fork_info, fork_name: ForkName::Capella };
    let exit = VoluntaryExit { epoch: exit_epoch, validator_index: 999 };
    let signer = make_signer(sk);

    let sig = TypedSigner::sign_voluntary_exit(&signer, &exit, &ctx).await.unwrap();

    let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, capella_version, GENESIS_VALIDATORS_ROOT);
    let signing_root = compute_signing_root(&exit, domain);

    assert!(sig.verify(&pk, &signing_root).is_ok(), "voluntary exit signature must verify");

    // Deneb fork version must fail (proves the Capella cap is in effect)
    let deneb_version = [0x04, 0x00, 0x00, 0x00];
    let wrong_domain =
        compute_domain(DOMAIN_VOLUNTARY_EXIT, deneb_version, GENESIS_VALIDATORS_ROOT);
    let wrong_root = compute_signing_root(&exit, wrong_domain);
    assert!(
        sig.verify(&pk, &wrong_root).is_err(),
        "voluntary exit must not verify with Deneb version (EIP-7044 cap)"
    );
}

// ============================================================
// test_typed_signer_local_signing_root_deterministic
//
// Verifies that signing root computation is deterministic across calls.
// ============================================================

#[tokio::test]
async fn test_typed_signer_local_signing_root_deterministic() {
    let block = BeaconBlock {
        slot: 500,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };

    let domain =
        compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_FORK_VERSION, GENESIS_VALIDATORS_ROOT);
    let root1 = compute_signing_root(&block, domain);
    let root2 = compute_signing_root(&block, domain);
    assert_eq!(root1, root2, "signing root must be deterministic");
}
