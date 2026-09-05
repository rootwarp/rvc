//! Single signing-root derivation for all consensus duties (D1).
//!
//! [`signing_root_for`] is the sole **schedule-aware** derivation path: it
//! resolves the active fork, applies the EIP-7044 Capella cap for
//! [`DutyRef::VoluntaryExit`], and returns the BLS signing root.
//!
//! Paths that already hold a resolved fork version (TypedSigner / Web3Signer
//! wire `ForkInfo`) use [`signing_root_with_fork_version`] so `compute_domain`
//! is not scattered across consumers. Prefer [`signing_root_for`] whenever a
//! [`ForkSchedule`] is available.

use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlock, BlindedBeaconBlock, ContributionAndProof,
    DomainType, ElectraAggregateAndProof, Epoch, ForkName, ForkSchedule, Root, Slot,
    SyncAggregatorSelectionData, ValidatorRegistrationV1, VoluntaryExit,
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
    DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
    SLOTS_PER_EPOCH,
};
use tree_hash::TreeHash;

use crate::signing::{compute_domain, compute_signing_root};

/// Context for [`signing_root_for`]: network fork schedule and genesis validators root.
#[derive(Debug, Clone, Copy)]
pub struct SigningCtx<'a> {
    pub fork_schedule: &'a ForkSchedule,
    pub genesis_validators_root: Root,
}

/// Reference to a consensus duty whose BLS signing root is needed.
///
/// Covers every production sign path: attestation, block (full / root),
/// blinded block, RANDAO, sync message/selection, attester selection proof,
/// aggregate-and-proof (Phase0 and Electra), contribution-and-proof, voluntary
/// exit, and builder registration.
#[derive(Debug, Clone, Copy)]
pub enum DutyRef<'a> {
    Attestation(&'a AttestationData),
    /// Full beacon block (TypedSigner path; tree-hashes the block container).
    Block(&'a BeaconBlock),
    /// Precomputed block root + slot for fork resolution (SignerService path).
    BlockRoot {
        root: &'a Root,
        slot: Slot,
    },
    BlindedBlock(&'a BlindedBeaconBlock),
    Randao(Epoch),
    SyncMessage {
        beacon_block_root: &'a Root,
        slot: Slot,
    },
    SyncSelection {
        slot: Slot,
        subcommittee_index: u64,
    },
    /// Attester selection proof (`DOMAIN_SELECTION_PROOF` over the slot).
    SelectionProof(Slot),
    AggregateAndProof(&'a AggregateAndProof),
    ElectraAggregateAndProof(&'a ElectraAggregateAndProof),
    ContributionAndProof(&'a ContributionAndProof),
    VoluntaryExit(&'a VoluntaryExit),
    /// Builder registration uses genesis fork version + zero GVR (MEV-Boost).
    ///
    /// The fork version is an explicit field so transports can pass whatever
    /// they currently supply; RF4-10 unifies them onto
    /// `ForkSchedule::genesis_fork_version`.
    BuilderRegistration {
        registration: &'a ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
    },
}

/// Derive the BLS signing root for `duty` under `ctx`.
///
/// Resolves the active fork via [`ForkName::from_epoch`] → `fork_version`,
/// applies the EIP-7044 Capella cap for [`DutyRef::VoluntaryExit`] only,
/// computes the domain, and returns [`compute_signing_root`].
pub fn signing_root_for(duty: &DutyRef<'_>, ctx: &SigningCtx<'_>) -> Root {
    match duty {
        DutyRef::Attestation(data) => {
            let fork_version = fork_version_at(data.target.epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, ctx.genesis_validators_root);
            compute_signing_root(data, domain)
        }
        DutyRef::Block(block) => {
            let epoch = block.slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, ctx.genesis_validators_root);
            compute_signing_root(block, domain)
        }
        DutyRef::BlockRoot { root, slot } => {
            let epoch = *slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, ctx.genesis_validators_root);
            compute_signing_root(root, domain)
        }
        DutyRef::BlindedBlock(block) => {
            let epoch = block.slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, ctx.genesis_validators_root);
            compute_signing_root(block, domain)
        }
        DutyRef::Randao(epoch) => {
            let fork_version = fork_version_at(*epoch, ctx.fork_schedule);
            let domain = compute_domain(DOMAIN_RANDAO, fork_version, ctx.genesis_validators_root);
            compute_signing_root(epoch, domain)
        }
        DutyRef::SyncMessage { beacon_block_root, slot } => {
            let epoch = *slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, ctx.genesis_validators_root);
            compute_signing_root(beacon_block_root, domain)
        }
        DutyRef::SyncSelection { slot, subcommittee_index } => {
            let epoch = *slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain = compute_domain(
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                fork_version,
                ctx.genesis_validators_root,
            );
            let selection_data = SyncAggregatorSelectionData {
                slot: *slot,
                subcommittee_index: *subcommittee_index,
            };
            compute_signing_root(&selection_data, domain)
        }
        DutyRef::SelectionProof(slot) => {
            let epoch = *slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_SELECTION_PROOF, fork_version, ctx.genesis_validators_root);
            compute_signing_root(slot, domain)
        }
        DutyRef::AggregateAndProof(agg) => {
            let epoch = agg.aggregate.data.slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain = compute_domain(
                DOMAIN_AGGREGATE_AND_PROOF,
                fork_version,
                ctx.genesis_validators_root,
            );
            compute_signing_root(agg, domain)
        }
        DutyRef::ElectraAggregateAndProof(agg) => {
            let epoch = agg.aggregate.data.slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain = compute_domain(
                DOMAIN_AGGREGATE_AND_PROOF,
                fork_version,
                ctx.genesis_validators_root,
            );
            compute_signing_root(agg, domain)
        }
        DutyRef::ContributionAndProof(cap) => {
            let epoch = cap.contribution.slot / SLOTS_PER_EPOCH;
            let fork_version = fork_version_at(epoch, ctx.fork_schedule);
            let domain = compute_domain(
                DOMAIN_CONTRIBUTION_AND_PROOF,
                fork_version,
                ctx.genesis_validators_root,
            );
            compute_signing_root(cap, domain)
        }
        DutyRef::VoluntaryExit(exit) => {
            // EIP-7044: sole automatic Capella-cap application path in crypto.
            // Definition is `capella_capped_fork_version` (same module).
            let fork_version = capella_capped_fork_version(exit.epoch, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_VOLUNTARY_EXIT, fork_version, ctx.genesis_validators_root);
            compute_signing_root(exit, domain)
        }
        DutyRef::BuilderRegistration { registration, genesis_fork_version } => {
            // Per MEV-Boost / builder-specs: DOMAIN_APPLICATION_BUILDER +
            // genesis fork version + zero genesis validators root.
            let zero_gvr = [0u8; 32];
            let domain =
                compute_domain(DOMAIN_APPLICATION_BUILDER, *genesis_fork_version, zero_gvr);
            compute_signing_root(registration, domain)
        }
    }
}

fn fork_version_at(epoch: Epoch, schedule: &ForkSchedule) -> [u8; 4] {
    ForkName::from_epoch(epoch, schedule).fork_version(schedule)
}

/// Signing root when the active fork version is already resolved.
///
/// Used by TypedSigner / Web3Signer wire builders / gRPC remote local-verify
/// that receive `ForkInfo` from the BN rather than a full [`ForkSchedule`].
/// Call sites must not invoke [`compute_domain`] / [`compute_signing_root`]
/// directly for consensus duties.
///
/// # EIP-7044 Capella (voluntary exits)
///
/// This helper does **not** apply the Capella cap: `fork_version` is used
/// verbatim. Callers **must** pass a Capella-capped version (via
/// [`capella_capped_fork_version`]) when signing a post-Capella exit over the
/// pre-resolved path, or prefer [`signing_root_for`] +
/// [`DutyRef::VoluntaryExit`] / free [`crate::sign_voluntary_exit`] which apply
/// the cap automatically when a schedule is available.
pub fn signing_root_with_fork_version<T: TreeHash>(
    ssz_object: &T,
    domain_type: DomainType,
    fork_version: [u8; 4],
    genesis_validators_root: Root,
) -> Root {
    let domain = compute_domain(domain_type, fork_version, genesis_validators_root);
    compute_signing_root(ssz_object, domain)
}

/// EIP-7044: Capella-capped fork version for voluntary-exit domains.
///
/// Sole **definition** of the cap in `crates/crypto`. Applied automatically
/// only via [`signing_root_for`] + [`DutyRef::VoluntaryExit`]. Exposed for
/// KATs and residual pre-resolved-version callers that still need the cap
/// bytes (e.g. to populate wire `ForkInfo.current_version`).
pub fn capella_capped_fork_version(epoch: Epoch, schedule: &ForkSchedule) -> [u8; 4] {
    let fork_name = ForkName::from_epoch(epoch, schedule);
    let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };
    capped.fork_version(schedule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Attestation, Checkpoint, ElectraAttestation, SyncCommitteeContribution};

    const GVR: Root = [0xaa; 32];
    const PHASE0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    const ALTAIR: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
    const BELLATRIX: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
    const CAPELLA: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
    const DENEB: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    const ELECTRA: [u8; 4] = [0x05, 0x00, 0x00, 0x00];

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

    fn ctx(schedule: &ForkSchedule) -> SigningCtx<'_> {
        SigningCtx { fork_schedule: schedule, genesis_validators_root: GVR }
    }

    fn legacy_attestation_root(data: &AttestationData, schedule: &ForkSchedule) -> Root {
        let fork_name = ForkName::from_epoch(data.target.epoch, schedule);
        let fork_version = fork_name.fork_version(schedule);
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, GVR);
        compute_signing_root(data, domain)
    }

    fn legacy_block_root(block_root: &Root, slot: Slot, schedule: &ForkSchedule) -> Root {
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, schedule);
        let fork_version = fork_name.fork_version(schedule);
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, GVR);
        compute_signing_root(block_root, domain)
    }

    fn legacy_voluntary_exit_root(exit: &VoluntaryExit, schedule: &ForkSchedule) -> Root {
        let fork_name = ForkName::from_epoch(exit.epoch, schedule);
        let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };
        let fork_version = capped.fork_version(schedule);
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, fork_version, GVR);
        compute_signing_root(exit, domain)
    }

    /// RED-first AC: Deneb-era exit must use Capella fork version inside the new helper.
    #[test]
    fn test_signing_root_for_voluntary_exit_deneb_epoch_uses_capella_fork_version() {
        let schedule = compressed_schedule();
        let exit = VoluntaryExit { epoch: 45, validator_index: 42 };
        let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx(&schedule));

        let capella_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA, GVR);
        let expected = compute_signing_root(&exit, capella_domain);
        assert_eq!(root, expected);

        let deneb_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, DENEB, GVR);
        assert_ne!(root, compute_signing_root(&exit, deneb_domain));
    }

    #[test]
    fn test_signing_root_for_matches_legacy_attestation_derivation_at_every_fork_boundary() {
        let schedule = compressed_schedule();
        // One epoch per fork, including activation-epoch boundaries.
        let epochs = [0, 9, 10, 19, 20, 29, 30, 39, 40, 49, 50, 59, 60, 100];
        for target_epoch in epochs {
            let data = AttestationData {
                slot: target_epoch * SLOTS_PER_EPOCH,
                index: 0,
                beacon_block_root: [0x11; 32],
                source: Checkpoint { epoch: target_epoch.saturating_sub(1), root: [0x22; 32] },
                target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
            };
            let got = signing_root_for(&DutyRef::Attestation(&data), &ctx(&schedule));
            let want = legacy_attestation_root(&data, &schedule);
            assert_eq!(got, want, "attestation root mismatch at epoch {target_epoch}");
        }
    }

    #[test]
    fn test_signing_root_for_matches_legacy_block_derivation_at_every_fork_boundary() {
        let schedule = compressed_schedule();
        let block_root: Root = [0x11; 32];
        let epochs = [0, 9, 10, 19, 20, 29, 30, 39, 40, 49, 50, 59, 60, 100];
        for epoch in epochs {
            let slot = epoch * SLOTS_PER_EPOCH;
            let got =
                signing_root_for(&DutyRef::BlockRoot { root: &block_root, slot }, &ctx(&schedule));
            let want = legacy_block_root(&block_root, slot, &schedule);
            assert_eq!(got, want, "block root mismatch at epoch {epoch}");
        }
    }

    #[test]
    fn test_signing_root_for_voluntary_exit_pre_capella_uses_actual_fork_version() {
        let schedule = compressed_schedule();
        let exit = VoluntaryExit { epoch: 25, validator_index: 42 };
        let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx(&schedule));

        let bellatrix_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, BELLATRIX, GVR);
        assert_eq!(root, compute_signing_root(&exit, bellatrix_domain));

        let capella_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA, GVR);
        assert_ne!(root, compute_signing_root(&exit, capella_domain));
    }

    #[test]
    fn test_signing_root_for_builder_registration_uses_genesis_fork_version() {
        let schedule = compressed_schedule();
        let registration = ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        };
        // Explicit genesis (Phase0) fork version — documented builder rule.
        let root = signing_root_for(
            &DutyRef::BuilderRegistration {
                registration: &registration,
                genesis_fork_version: schedule.genesis_fork_version,
            },
            &ctx(&schedule),
        );
        let zero_gvr = [0u8; 32];
        let domain =
            compute_domain(DOMAIN_APPLICATION_BUILDER, schedule.genesis_fork_version, zero_gvr);
        assert_eq!(root, compute_signing_root(&registration, domain));

        // Non-genesis version must not be silently substituted from schedule.
        let altair_root = signing_root_for(
            &DutyRef::BuilderRegistration {
                registration: &registration,
                genesis_fork_version: ALTAIR,
            },
            &ctx(&schedule),
        );
        assert_ne!(root, altair_root);
    }

    #[test]
    fn test_eip7044_kat_vectors_unchanged() {
        let schedule = compressed_schedule();
        // Table: (epoch, expected_fork_version) — remerkleable-derived roots in integration KATs.
        let cases: &[(Epoch, [u8; 4])] = &[
            (25, BELLATRIX),      // pre-Capella
            (30, CAPELLA),        // Capella activation
            (45, CAPELLA),        // Deneb epoch — capped
            (55, CAPELLA),        // Electra epoch — capped
            (1_000_000, CAPELLA), // Fulu under sentinel Gloas — still Capella
            (u64::MAX, CAPELLA),  // from_epoch(MAX) is Gloas; cap still Capella
        ];
        for &(epoch, expected_version) in cases {
            assert_eq!(
                capella_capped_fork_version(epoch, &schedule),
                expected_version,
                "cap version at epoch {epoch}"
            );
            let exit = VoluntaryExit { epoch, validator_index: 42 };
            let got = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx(&schedule));
            let want = legacy_voluntary_exit_root(&exit, &schedule);
            assert_eq!(got, want, "exit root at epoch {epoch}");
        }
    }

    #[test]
    fn test_signing_root_for_randao_sync_selection_aggregate_contribution() {
        let schedule = compressed_schedule();
        let c = ctx(&schedule);

        // RANDAO at Deneb epoch.
        let epoch: Epoch = 45;
        let randao = signing_root_for(&DutyRef::Randao(epoch), &c);
        let domain = compute_domain(DOMAIN_RANDAO, DENEB, GVR);
        assert_eq!(randao, compute_signing_root(&epoch, domain));

        // Sync message at Altair.
        let block_root: Root = [0x11; 32];
        let slot = 10 * SLOTS_PER_EPOCH;
        let sync =
            signing_root_for(&DutyRef::SyncMessage { beacon_block_root: &block_root, slot }, &c);
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, ALTAIR, GVR);
        assert_eq!(sync, compute_signing_root(&block_root, domain));

        // Sync selection.
        let sel =
            signing_root_for(&DutyRef::SyncSelection { slot: 100, subcommittee_index: 2 }, &c);
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, PHASE0, GVR);
        let selection_data = SyncAggregatorSelectionData { slot: 100, subcommittee_index: 2 };
        assert_eq!(sel, compute_signing_root(&selection_data, domain));

        // Selection proof (attester).
        let slot: Slot = 100;
        let sp = signing_root_for(&DutyRef::SelectionProof(slot), &c);
        let domain = compute_domain(DOMAIN_SELECTION_PROOF, PHASE0, GVR);
        assert_eq!(sp, compute_signing_root(&slot, domain));

        // AggregateAndProof Phase0.
        let agg = AggregateAndProof {
            aggregator_index: 42,
            aggregate: Attestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot: 100,
                    index: 1,
                    beacon_block_root: [1u8; 32],
                    source: Checkpoint { epoch: 2, root: [2u8; 32] },
                    target: Checkpoint { epoch: 3, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        };
        let agg_root = signing_root_for(&DutyRef::AggregateAndProof(&agg), &c);
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, PHASE0, GVR);
        assert_eq!(agg_root, compute_signing_root(&agg, domain));

        // Electra aggregate.
        let electra_slot = 50 * SLOTS_PER_EPOCH;
        let eagg = ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: ElectraAttestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot: electra_slot,
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
        let eagg_root = signing_root_for(&DutyRef::ElectraAggregateAndProof(&eagg), &c);
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, ELECTRA, GVR);
        assert_eq!(eagg_root, compute_signing_root(&eagg, domain));

        // ContributionAndProof Altair.
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
        let cap_root = signing_root_for(&DutyRef::ContributionAndProof(&cap), &c);
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, ALTAIR, GVR);
        assert_eq!(cap_root, compute_signing_root(&cap, domain));
    }

    #[test]
    fn test_capella_capped_fork_version_is_shared_with_signing_root_for() {
        let schedule = compressed_schedule();
        for epoch in [0, 25, 30, 45, 55, 100, 1_000_000, u64::MAX] {
            let exit = VoluntaryExit { epoch, validator_index: 1 };
            let via_helper = {
                let version = capella_capped_fork_version(epoch, &schedule);
                let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, version, GVR);
                compute_signing_root(&exit, domain)
            };
            let via_for = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx(&schedule));
            assert_eq!(via_helper, via_for, "cap helper parity at epoch {epoch}");
        }
    }

    /// Smoke: full BeaconBlock arm matches compute_signing_root at Electra.
    #[test]
    fn test_signing_root_for_full_block_matches_compute_signing_root() {
        let schedule = compressed_schedule();
        let block = BeaconBlock {
            slot: 50 * SLOTS_PER_EPOCH, // Electra on compressed schedule
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        let got = signing_root_for(&DutyRef::Block(&block), &ctx(&schedule));
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, ELECTRA, GVR);
        assert_eq!(got, compute_signing_root(&block, domain));
    }

    /// Smoke: BlindedBeaconBlock arm matches compute_signing_root at Electra.
    #[test]
    fn test_signing_root_for_blinded_block_matches_compute_signing_root() {
        let schedule = compressed_schedule();
        let block = BlindedBeaconBlock {
            slot: 50 * SLOTS_PER_EPOCH,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        let got = signing_root_for(&DutyRef::BlindedBlock(&block), &ctx(&schedule));
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, ELECTRA, GVR);
        assert_eq!(got, compute_signing_root(&block, domain));
    }
}
