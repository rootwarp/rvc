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
    AggregateAndProof, AttestationData, BeaconBlock, BlindedBeaconBlock, BuilderRequestAuth,
    ContributionAndProof, DomainType, ElectraAggregateAndProof, Epoch, ForkName, ForkSchedule,
    PayloadAttestationData, ProposerPreferences, Root, Slot, SyncAggregatorSelectionData,
    ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_BUILDER_REQUEST_AUTH,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT, SLOTS_PER_EPOCH,
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
/// Covers every production sign path: attestation, PTC payload attestation,
/// proposer preferences, block (full / root), blinded block, RANDAO, sync
/// message/selection, attester selection proof, aggregate-and-proof (Phase0
/// and Electra), contribution-and-proof, voluntary exit, and builder
/// registration.
#[derive(Debug, Clone, Copy)]
pub enum DutyRef<'a> {
    Attestation(&'a AttestationData),
    /// Payload attestation (`DOMAIN_PTC_ATTESTER`); fork at `epoch_of(data.slot)`.
    PtcAttestation(&'a PayloadAttestationData),
    /// Proposer preferences (`DOMAIN_PROPOSER_PREFERENCES`); fork at `epoch_of(proposal_slot)`.
    ProposerPreferences(&'a ProposerPreferences),
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
    /// Builder request auth (`DOMAIN_BUILDER_REQUEST_AUTH`).
    ///
    /// Uses the genesis-fork and zero-GVR idiom of [`Self::BuilderRegistration`]
    /// (builder-specs: analogous to `ValidatorRegistrationV1`).
    BuilderRequestAuth {
        auth: &'a BuilderRequestAuth,
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
        DutyRef::PtcAttestation(data) => {
            // Spec: compute_epoch_at_slot(data.slot) — not an attestation target epoch.
            let fork_version = fork_version_at(data.slot / SLOTS_PER_EPOCH, ctx.fork_schedule);
            let domain =
                compute_domain(DOMAIN_PTC_ATTESTER, fork_version, ctx.genesis_validators_root);
            compute_signing_root(data, domain)
        }
        DutyRef::ProposerPreferences(prefs) => {
            // Spec: compute_epoch_at_slot(proposal_slot).
            let fork_version =
                fork_version_at(prefs.proposal_slot / SLOTS_PER_EPOCH, ctx.fork_schedule);
            let domain = compute_domain(
                DOMAIN_PROPOSER_PREFERENCES,
                fork_version,
                ctx.genesis_validators_root,
            );
            compute_signing_root(prefs, domain)
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
        DutyRef::BuilderRequestAuth { auth, genesis_fork_version } => {
            // builder-specs: compute_domain(DOMAIN_BUILDER_REQUEST_AUTH) with
            // genesis fork version and zero GVR (ValidatorRegistrationV1 idiom).
            let zero_gvr = [0u8; 32];
            let domain =
                compute_domain(DOMAIN_BUILDER_REQUEST_AUTH, *genesis_fork_version, zero_gvr);
            compute_signing_root(auth, domain)
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
    use eth_types::{
        Attestation, Checkpoint, ElectraAttestation, PayloadAttestationData, ProposerPreferences,
        SyncCommitteeContribution,
    };
    use rvc_spec_vectors::spec_kat::{
        KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT, KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT,
    };

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

    fn parse_kat_root(hex: &str) -> Root {
        hex::decode(hex).expect("kat hex").try_into().expect("32-byte kat root")
    }

    /// L3: PayloadAttestationData signing root from the 4.0 pyspec artifact
    /// (`KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT`) under `DOMAIN_PTC_ATTESTER`.
    #[test]
    fn test_ptc_attester_signing_root() {
        assert_eq!(DOMAIN_PTC_ATTESTER, [0x0C, 0x00, 0x00, 0x00]);

        let mut schedule = compressed_schedule();
        // Artifact: fork_version 0x07000001, GVR zeros, slot 1 (epoch 0).
        schedule.gloas_fork_epoch = 0;
        schedule.gloas_fork_version = [0x07, 0x00, 0x00, 0x01];
        let data = PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0u8; 32] };
        let got = signing_root_for(&DutyRef::PtcAttestation(&data), &ctx);
        assert_eq!(got, parse_kat_root(KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT));
    }

    /// DomainType bytes copied from the 4.0 pyspec artifact (parsed from
    /// `consensus-specs` `SPEC_TAG` gloas beacon-chain.md — not hardcoded).
    fn pinned_domain_proposer_preferences() -> [u8; 4] {
        const YAML: &str = include_str!(
            "../../rvc-spec-vectors/vectors-generated/signing-roots/signing_roots.yaml"
        );
        let line = YAML
            .lines()
            .find(|l| l.trim_start().starts_with("domain_proposer_preferences:"))
            .expect("domain_proposer_preferences in 4.0 signing-roots artifact");
        let hex = line
            .split_once(':')
            .expect("domain_proposer_preferences value")
            .1
            .trim()
            .trim_matches('\'')
            .trim_start_matches("0x");
        hex::decode(hex).expect("domain hex").try_into().expect("4-byte domain")
    }

    /// L3: ProposerPreferences signing root from the 4.0 pyspec artifact
    /// (`KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT`) under
    /// `DOMAIN_PROPOSER_PREFERENCES` bytes from the pinned spec tag.
    #[test]
    fn test_proposer_preferences_signing_root() {
        const SPEC_KAT: &str = include_str!("../../rvc-spec-vectors/src/spec_kat.rs");
        let header: String = SPEC_KAT.lines().take_while(|l| l.starts_with("//!")).collect();
        assert!(
            !header.to_ascii_lowercase().contains("remerkleable"),
            "KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT provenance must not be remerkleable (D15)"
        );

        let spec_domain = pinned_domain_proposer_preferences();
        assert_eq!(DOMAIN_PROPOSER_PREFERENCES, spec_domain);

        let mut schedule = compressed_schedule();
        // Artifact: fork_version 0x07000001, GVR zeros, proposal_slot 32 (epoch 1).
        schedule.gloas_fork_epoch = 0;
        schedule.gloas_fork_version = [0x07, 0x00, 0x00, 0x01];
        let prefs = ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 3,
            fee_recipient: [0x44; 20],
            target_gas_limit: 36_000_000,
        };
        let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0u8; 32] };
        let got = signing_root_for(&DutyRef::ProposerPreferences(&prefs), &ctx);
        assert_eq!(got, parse_kat_root(KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT));
    }

    /// L3: BuilderRequestAuth signing root from the 4.0 pyspec recipe
    /// (`KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT`) under
    /// `DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001` with genesis fork + zero GVR.
    #[test]
    fn test_builder_request_auth_signing_root() {
        use eth_types::BuilderRequestAuth;
        use rvc_spec_vectors::builder_request_auth_kat::{
            BUILDER_SPECS_REVISION, KAT_BUILDER_REQUEST_AUTH_DATA_HEX,
            KAT_BUILDER_REQUEST_AUTH_SLOT, KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT,
        };

        const KAT: &str = include_str!("../../rvc-spec-vectors/src/builder_request_auth_kat.rs");
        let header: String = KAT.lines().take_while(|l| l.starts_with("//!")).collect();
        assert!(
            !header.to_ascii_lowercase().contains("remerkleable"),
            "KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT provenance must not be remerkleable (D15)"
        );
        assert!(
            header.contains(BUILDER_SPECS_REVISION),
            "provenance must name the builder-specs revision"
        );
        assert!(
            header.contains("0x0B000001") || header.contains("0x0b000001"),
            "provenance must name DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001"
        );
        assert_eq!(DOMAIN_BUILDER_REQUEST_AUTH, [0x0B, 0x00, 0x00, 0x01]);

        let auth = BuilderRequestAuth::new(
            hex::decode(KAT_BUILDER_REQUEST_AUTH_DATA_HEX).expect("kat data"),
            KAT_BUILDER_REQUEST_AUTH_SLOT,
        )
        .expect("kat data valid");
        let schedule = compressed_schedule();
        let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0xff; 32] };
        // Genesis-fork + zero GVR idiom: GVR on ctx must not affect the root.
        let got = signing_root_for(
            &DutyRef::BuilderRequestAuth { auth: &auth, genesis_fork_version: PHASE0 },
            &ctx,
        );
        assert_eq!(got, parse_kat_root(KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT));
    }

    /// PTC fork version is `epoch_of(data.slot)`, unlike attestations (`target.epoch`).
    #[test]
    fn test_ptc_attester_fork_version_uses_slot_epoch_not_target_epoch() {
        let mut schedule = compressed_schedule();
        schedule.gloas_fork_epoch = 70;
        let slot = 70 * SLOTS_PER_EPOCH;
        let data = PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot,
            payload_present: true,
            blob_data_available: false,
        };
        let got = signing_root_for(&DutyRef::PtcAttestation(&data), &ctx(&schedule));

        let gloas_domain = compute_domain(DOMAIN_PTC_ATTESTER, schedule.gloas_fork_version, GVR);
        assert_eq!(got, compute_signing_root(&data, gloas_domain));

        // Attestation-style target.epoch can sit in the previous fork (Fulu here).
        let target_epoch = 69;
        assert_eq!(ForkName::from_epoch(target_epoch, &schedule), ForkName::Fulu);
        let fulu_domain =
            compute_domain(DOMAIN_PTC_ATTESTER, ForkName::Fulu.fork_version(&schedule), GVR);
        assert_ne!(got, compute_signing_root(&data, fulu_domain));
    }

    /// EIP-7044: with Gloas actually scheduled, a post-Gloas exit still uses Capella.
    #[test]
    fn test_eip7044_post_gloas_exit_still_capella() {
        let mut schedule = compressed_schedule();
        schedule.gloas_fork_epoch = 70;
        let epoch = 80;
        assert_eq!(ForkName::from_epoch(epoch, &schedule), ForkName::Gloas);
        assert_eq!(capella_capped_fork_version(epoch, &schedule), CAPELLA);

        let exit = VoluntaryExit { epoch, validator_index: 42 };
        let root = signing_root_for(&DutyRef::VoluntaryExit(&exit), &ctx(&schedule));
        let capella_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA, GVR);
        assert_eq!(root, compute_signing_root(&exit, capella_domain));
        let gloas_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, schedule.gloas_fork_version, GVR);
        assert_ne!(root, compute_signing_root(&exit, gloas_domain));
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
