use crate::DomainType;

pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0x00, 0x00, 0x00];
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];
pub const DOMAIN_RANDAO: DomainType = [0x02, 0x00, 0x00, 0x00];
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0x00, 0x00, 0x00];
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0x00, 0x00, 0x00];
pub const DOMAIN_SELECTION_PROOF: DomainType = [0x05, 0x00, 0x00, 0x00];
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [0x06, 0x00, 0x00, 0x00];
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0x00, 0x00, 0x00];
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0x00, 0x00, 0x00];
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0x00, 0x00, 0x00];
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType = [0x0A, 0x00, 0x00, 0x00];
pub const DOMAIN_PTC_ATTESTER: DomainType = [0x0C, 0x00, 0x00, 0x00];
pub const DOMAIN_PROPOSER_PREFERENCES: DomainType = [0x0D, 0x00, 0x00, 0x00];
pub const DOMAIN_APPLICATION_BUILDER: DomainType = [0x00, 0x00, 0x00, 0x01];

#[cfg(test)]
mod tests {
    use super::*;

    /// Single table pin against consensus-specs DomainType values.
    ///
    /// Replaces twelve per-constant echo tests (RF3-19 / G6): one edit point when
    /// a legitimate domain value changes. Expected bytes are the spec literals;
    /// constants are the production bindings under test.
    #[test]
    fn test_domains_table_matches_spec() {
        // consensus-specs: phase0 DomainTypes + altair/capella + builder domain.
        // https://github.com/ethereum/consensus-specs
        let table: &[(&str, DomainType, [u8; 4])] = &[
            ("DOMAIN_BEACON_PROPOSER", DOMAIN_BEACON_PROPOSER, [0x00, 0x00, 0x00, 0x00]),
            ("DOMAIN_BEACON_ATTESTER", DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00]),
            ("DOMAIN_RANDAO", DOMAIN_RANDAO, [0x02, 0x00, 0x00, 0x00]),
            ("DOMAIN_DEPOSIT", DOMAIN_DEPOSIT, [0x03, 0x00, 0x00, 0x00]),
            ("DOMAIN_VOLUNTARY_EXIT", DOMAIN_VOLUNTARY_EXIT, [0x04, 0x00, 0x00, 0x00]),
            ("DOMAIN_SELECTION_PROOF", DOMAIN_SELECTION_PROOF, [0x05, 0x00, 0x00, 0x00]),
            ("DOMAIN_AGGREGATE_AND_PROOF", DOMAIN_AGGREGATE_AND_PROOF, [0x06, 0x00, 0x00, 0x00]),
            ("DOMAIN_SYNC_COMMITTEE", DOMAIN_SYNC_COMMITTEE, [0x07, 0x00, 0x00, 0x00]),
            (
                "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF",
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                [0x08, 0x00, 0x00, 0x00],
            ),
            (
                "DOMAIN_CONTRIBUTION_AND_PROOF",
                DOMAIN_CONTRIBUTION_AND_PROOF,
                [0x09, 0x00, 0x00, 0x00],
            ),
            (
                "DOMAIN_BLS_TO_EXECUTION_CHANGE",
                DOMAIN_BLS_TO_EXECUTION_CHANGE,
                [0x0A, 0x00, 0x00, 0x00],
            ),
            ("DOMAIN_PTC_ATTESTER", DOMAIN_PTC_ATTESTER, [0x0C, 0x00, 0x00, 0x00]),
            ("DOMAIN_PROPOSER_PREFERENCES", DOMAIN_PROPOSER_PREFERENCES, [0x0D, 0x00, 0x00, 0x00]),
            ("DOMAIN_APPLICATION_BUILDER", DOMAIN_APPLICATION_BUILDER, [0x00, 0x00, 0x00, 0x01]),
        ];
        for (name, actual, expected) in table {
            assert_eq!(actual, expected, "{name} must match consensus-specs DomainType");
        }

        // Timing / consensus-spec metadata (replaces three lib.rs constant-echo tests).
        assert_eq!(crate::SLOTS_PER_EPOCH, 32, "SLOTS_PER_EPOCH");
        assert_eq!(crate::SLOT_DURATION_MS, 12_000, "SLOT_DURATION_MS");
        assert_eq!(crate::CONSENSUS_SPEC_VERSION, "v1.5.0-alpha.12", "CONSENSUS_SPEC_VERSION");
    }

    #[test]
    fn test_all_domains_are_unique() {
        let domains = [
            DOMAIN_BEACON_PROPOSER,
            DOMAIN_BEACON_ATTESTER,
            DOMAIN_RANDAO,
            DOMAIN_DEPOSIT,
            DOMAIN_VOLUNTARY_EXIT,
            DOMAIN_SELECTION_PROOF,
            DOMAIN_AGGREGATE_AND_PROOF,
            DOMAIN_SYNC_COMMITTEE,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            DOMAIN_PTC_ATTESTER,
            DOMAIN_PROPOSER_PREFERENCES,
            DOMAIN_APPLICATION_BUILDER,
        ];
        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(domains[i], domains[j], "Domain {} and {} are identical", i, j);
            }
        }
    }

    #[test]
    fn test_domain_type_is_4_bytes() {
        assert_eq!(std::mem::size_of_val(&DOMAIN_BEACON_PROPOSER), 4);
    }
}
