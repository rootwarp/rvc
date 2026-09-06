//! Gloas progressive SSZ merkleization island.
//!
//! Declares progressively-merkleized Gloas containers and exports roots only.
//! This crate currently has no path dependencies. The only path dependency it
//! may ever gain is `{rvc-eth-types}`.

/// Pinned `ethereum/consensus-specs` release this island is generated against.
pub const SPEC_TAG: &str = "v1.7.0-beta.0";

mod merkle;

#[cfg(test)]
mod spec_kat;

#[cfg(test)]
mod spec_kat_tests {
    #[test]
    fn test_spec_gloas_sync_aggregate_root() {
        assert_ne!(
            super::spec_kat::minimal::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
            super::spec_kat::mainnet::SPEC_GLOAS_SYNC_AGGREGATE_ROOT,
        );
        assert_eq!(super::spec_kat::minimal::SPEC_GLOAS_SYNC_AGGREGATE_ROOT.len(), 64);
        assert_eq!(super::spec_kat::mainnet::SPEC_GLOAS_SYNC_AGGREGATE_ROOT.len(), 64);
    }

    #[test]
    fn test_spec_kat_minimal_and_mainnet_constant_names_match() {
        assert_eq!(
            super::spec_kat::minimal::SPEC_GLOAS_ROOT_NAMES,
            super::spec_kat::mainnet::SPEC_GLOAS_ROOT_NAMES
        );
        assert!(!super::spec_kat::minimal::SPEC_GLOAS_ROOT_NAMES.is_empty());
    }

    #[test]
    fn test_spec_progressive_covers_twelve_counts_and_widths_3_4_5_13() {
        const COUNTS: &[u32] = &[0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86];
        const WIDTHS: &[u32] = &[3, 4, 5, 13];
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_CHUNK_COUNTS, COUNTS);
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS, WIDTHS);
        assert_eq!(
            super::spec_kat::minimal::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS,
            super::spec_kat::mainnet::SPEC_PROGRESSIVE_ACTIVE_FIELD_WIDTHS
        );
        assert_eq!(super::spec_kat::SPEC_PROGRESSIVE_CHUNK_ROOTS.len(), COUNTS.len());
        for width in WIDTHS {
            assert!(
                super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                    .iter()
                    .any(|(w, pattern, _)| w == width && *pattern == "all_ones"),
                "missing width {width} all_ones"
            );
            assert!(
                super::spec_kat::SPEC_PROGRESSIVE_ACTIVE_FIELD_ROOTS
                    .iter()
                    .any(|(w, pattern, _)| w == width && *pattern == "sparse_bit0_clear"),
                "missing width {width} sparse_bit0_clear"
            );
        }
    }
}
