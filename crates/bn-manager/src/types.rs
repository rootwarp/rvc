use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Health tier based on sync distance from chain head.
///
/// Ordered from healthiest to least healthy. The discriminant values
/// enable `<=` comparisons: a BN "meets" a tier requirement when
/// `bn.tier() <= required_tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HealthTier {
    /// Head within threshold_synced slots of wall clock. Eligible for all duties.
    Synced = 1,
    /// Small lag (threshold_synced..threshold_small). Eligible for attestations, sync committee.
    SmallLag = 2,
    /// Large lag (threshold_small..threshold_large). Eligible for submissions only.
    LargeLag = 3,
    /// Beyond threshold_large or unreachable. Not eligible for any duty.
    Unsynced = 4,
}

impl HealthTier {
    /// Returns the numeric value (1-4) for metric reporting.
    pub fn as_metric_value(&self) -> i64 {
        *self as i64
    }
}

impl fmt::Display for HealthTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Synced => write!(f, "synced"),
            Self::SmallLag => write!(f, "small-lag"),
            Self::LargeLag => write!(f, "large-lag"),
            Self::Unsynced => write!(f, "unsynced"),
        }
    }
}

/// Bounded `capability` label values for `rvc_bn_capability_state` (issue 6.7).
///
/// Code-derived only — never request-derived (cardinality). Issue 8.3 owns
/// `ALL` membership tests and endpoint-label redaction checks.
pub mod bn_capability {
    pub const FORK_RECOGNISED: &str = "fork_recognised";
    pub const PRODUCE_BLOCK_V4: &str = "produce_block_v4";
}

/// Tier threshold configuration.
///
/// Defines the width of each sync distance tier:
/// - Synced: `0..=synced`
/// - SmallLag: `synced+1..=synced+small`
/// - LargeLag: `synced+small+1..=synced+small+large`
/// - Unsynced: everything beyond
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierThresholds {
    /// Width of the Synced tier (default: 8).
    pub synced: u64,
    /// Width of the SmallLag tier (default: 8).
    pub small: u64,
    /// Width of the LargeLag tier (default: 48).
    pub large: u64,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self { synced: 8, small: 8, large: 48 }
    }
}

impl TierThresholds {
    /// Computes the health tier for a given sync distance.
    pub fn tier_for_distance(&self, distance: u64) -> HealthTier {
        if distance <= self.synced {
            HealthTier::Synced
        } else if distance <= self.synced + self.small {
            HealthTier::SmallLag
        } else if distance <= self.synced + self.small + self.large {
            HealthTier::LargeLag
        } else {
            HealthTier::Unsynced
        }
    }

    /// Parses from a comma-separated string like "8,8,48".
    pub fn from_csv(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 3 {
            return Err(format!(
                "expected 3 comma-separated values (synced,small,large), got {}",
                parts.len()
            ));
        }
        let synced =
            parts[0].trim().parse::<u64>().map_err(|e| format!("invalid synced value: {e}"))?;
        let small =
            parts[1].trim().parse::<u64>().map_err(|e| format!("invalid small value: {e}"))?;
        let large =
            parts[2].trim().parse::<u64>().map_err(|e| format!("invalid large value: {e}"))?;
        Ok(Self { synced, small, large })
    }
}

/// Duty-type roles assignable to each BN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BnRole {
    Attestation,
    Proposal,
    SyncCommittee,
    Aggregation,
    Submission,
    All,
}

impl BnRole {
    /// Returns all concrete roles (excluding `All`).
    pub fn all_concrete() -> HashSet<BnRole> {
        let mut set = HashSet::new();
        set.insert(BnRole::Attestation);
        set.insert(BnRole::Proposal);
        set.insert(BnRole::SyncCommittee);
        set.insert(BnRole::Aggregation);
        set.insert(BnRole::Submission);
        set
    }

    /// Expands `All` into all concrete roles; returns a singleton set otherwise.
    pub fn expand(roles: &HashSet<BnRole>) -> HashSet<BnRole> {
        if roles.contains(&BnRole::All) {
            Self::all_concrete()
        } else {
            roles.clone()
        }
    }

    /// Returns true if this role set matches the given role requirement.
    /// A set containing `All` matches any role.
    pub fn matches(roles: &HashSet<BnRole>, required: BnRole) -> bool {
        roles.contains(&BnRole::All) || roles.contains(&required)
    }
}

impl fmt::Display for BnRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attestation => write!(f, "attestation"),
            Self::Proposal => write!(f, "proposal"),
            Self::SyncCommittee => write!(f, "sync-committee"),
            Self::Aggregation => write!(f, "aggregation"),
            Self::Submission => write!(f, "submission"),
            Self::All => write!(f, "all"),
        }
    }
}

impl FromStr for BnRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "attestation" => Ok(Self::Attestation),
            "proposal" => Ok(Self::Proposal),
            "sync-committee" | "sync_committee" | "synccommittee" => Ok(Self::SyncCommittee),
            "aggregation" => Ok(Self::Aggregation),
            "submission" => Ok(Self::Submission),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "invalid BN role: '{}'. Valid roles: attestation, proposal, sync-committee, aggregation, submission, all",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- HealthTier tests --

    #[test]
    fn test_health_tier_ordering() {
        assert!(HealthTier::Synced < HealthTier::SmallLag);
        assert!(HealthTier::SmallLag < HealthTier::LargeLag);
        assert!(HealthTier::LargeLag < HealthTier::Unsynced);
    }

    #[test]
    fn test_health_tier_metric_values() {
        assert_eq!(HealthTier::Synced.as_metric_value(), 1);
        assert_eq!(HealthTier::SmallLag.as_metric_value(), 2);
        assert_eq!(HealthTier::LargeLag.as_metric_value(), 3);
        assert_eq!(HealthTier::Unsynced.as_metric_value(), 4);
    }

    #[test]
    fn test_health_tier_display() {
        assert_eq!(HealthTier::Synced.to_string(), "synced");
        assert_eq!(HealthTier::SmallLag.to_string(), "small-lag");
        assert_eq!(HealthTier::LargeLag.to_string(), "large-lag");
        assert_eq!(HealthTier::Unsynced.to_string(), "unsynced");
    }

    #[test]
    fn test_health_tier_meets_requirement() {
        // Synced meets all requirements
        assert!(HealthTier::Synced <= HealthTier::Synced);
        assert!(HealthTier::Synced <= HealthTier::SmallLag);
        assert!(HealthTier::Synced <= HealthTier::LargeLag);

        // SmallLag meets SmallLag and below
        assert!(HealthTier::SmallLag <= HealthTier::SmallLag);
        assert!(HealthTier::SmallLag <= HealthTier::LargeLag);
        assert!(HealthTier::SmallLag > HealthTier::Synced);

        // LargeLag only meets LargeLag and Unsynced
        assert!(HealthTier::LargeLag <= HealthTier::LargeLag);
        assert!(HealthTier::LargeLag > HealthTier::SmallLag);
    }

    // -- TierThresholds tests --

    #[test]
    fn test_tier_thresholds_default() {
        let t = TierThresholds::default();
        assert_eq!(t.synced, 8);
        assert_eq!(t.small, 8);
        assert_eq!(t.large, 48);
    }

    #[test]
    fn test_tier_for_distance_synced_boundary() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(0), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(8), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(9), HealthTier::SmallLag);
    }

    #[test]
    fn test_tier_for_distance_small_lag_boundary() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(9), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(16), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(17), HealthTier::LargeLag);
    }

    #[test]
    fn test_tier_for_distance_large_lag_boundary() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(17), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(64), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(65), HealthTier::Unsynced);
    }

    #[test]
    fn test_tier_for_distance_unsynced() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(65), HealthTier::Unsynced);
        assert_eq!(t.tier_for_distance(1000), HealthTier::Unsynced);
    }

    #[test]
    fn test_tier_for_distance_custom_thresholds() {
        let t = TierThresholds { synced: 4, small: 4, large: 16 };
        assert_eq!(t.tier_for_distance(0), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(4), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(5), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(8), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(9), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(24), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(25), HealthTier::Unsynced);
    }

    #[test]
    fn test_tier_thresholds_from_csv() {
        let t = TierThresholds::from_csv("8,8,48").unwrap();
        assert_eq!(t, TierThresholds::default());
    }

    #[test]
    fn test_tier_thresholds_from_csv_with_spaces() {
        let t = TierThresholds::from_csv("4, 4, 16").unwrap();
        assert_eq!(t, TierThresholds { synced: 4, small: 4, large: 16 });
    }

    #[test]
    fn test_tier_thresholds_from_csv_wrong_count() {
        assert!(TierThresholds::from_csv("8,8").is_err());
        assert!(TierThresholds::from_csv("8,8,48,64").is_err());
    }

    #[test]
    fn test_tier_thresholds_from_csv_invalid_number() {
        assert!(TierThresholds::from_csv("abc,8,48").is_err());
    }

    // -- BnRole tests --

    #[test]
    fn test_bn_role_display() {
        assert_eq!(BnRole::Attestation.to_string(), "attestation");
        assert_eq!(BnRole::Proposal.to_string(), "proposal");
        assert_eq!(BnRole::SyncCommittee.to_string(), "sync-committee");
        assert_eq!(BnRole::Aggregation.to_string(), "aggregation");
        assert_eq!(BnRole::Submission.to_string(), "submission");
        assert_eq!(BnRole::All.to_string(), "all");
    }

    #[test]
    fn test_bn_role_from_str() {
        assert_eq!(BnRole::from_str("attestation").unwrap(), BnRole::Attestation);
        assert_eq!(BnRole::from_str("proposal").unwrap(), BnRole::Proposal);
        assert_eq!(BnRole::from_str("sync-committee").unwrap(), BnRole::SyncCommittee);
        assert_eq!(BnRole::from_str("sync_committee").unwrap(), BnRole::SyncCommittee);
        assert_eq!(BnRole::from_str("aggregation").unwrap(), BnRole::Aggregation);
        assert_eq!(BnRole::from_str("submission").unwrap(), BnRole::Submission);
        assert_eq!(BnRole::from_str("all").unwrap(), BnRole::All);
    }

    #[test]
    fn test_bn_role_from_str_invalid() {
        assert!(BnRole::from_str("invalid").is_err());
        assert!(BnRole::from_str("").is_err());
    }

    #[test]
    fn test_bn_role_all_concrete() {
        let concrete = BnRole::all_concrete();
        assert_eq!(concrete.len(), 5);
        assert!(concrete.contains(&BnRole::Attestation));
        assert!(concrete.contains(&BnRole::Proposal));
        assert!(concrete.contains(&BnRole::SyncCommittee));
        assert!(concrete.contains(&BnRole::Aggregation));
        assert!(concrete.contains(&BnRole::Submission));
        assert!(!concrete.contains(&BnRole::All));
    }

    #[test]
    fn test_bn_role_expand_all() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::All);
        let expanded = BnRole::expand(&roles);
        assert_eq!(expanded, BnRole::all_concrete());
    }

    #[test]
    fn test_bn_role_expand_specific() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::Attestation);
        roles.insert(BnRole::Proposal);
        let expanded = BnRole::expand(&roles);
        assert_eq!(expanded.len(), 2);
        assert!(expanded.contains(&BnRole::Attestation));
        assert!(expanded.contains(&BnRole::Proposal));
    }

    #[test]
    fn test_bn_role_matches_all() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::All);
        assert!(BnRole::matches(&roles, BnRole::Attestation));
        assert!(BnRole::matches(&roles, BnRole::Proposal));
        assert!(BnRole::matches(&roles, BnRole::SyncCommittee));
    }

    #[test]
    fn test_bn_role_matches_specific() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::Attestation);
        assert!(BnRole::matches(&roles, BnRole::Attestation));
        assert!(!BnRole::matches(&roles, BnRole::Proposal));
    }

    #[test]
    fn test_bn_role_serde_roundtrip() {
        let role = BnRole::SyncCommittee;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"sync-committee\"");
        let deserialized: BnRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, BnRole::SyncCommittee);
    }

    #[test]
    fn test_bn_role_serde_all_variants() {
        let variants = vec![
            (BnRole::Attestation, "\"attestation\""),
            (BnRole::Proposal, "\"proposal\""),
            (BnRole::SyncCommittee, "\"sync-committee\""),
            (BnRole::Aggregation, "\"aggregation\""),
            (BnRole::Submission, "\"submission\""),
            (BnRole::All, "\"all\""),
        ];
        for (role, expected_json) in variants {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, expected_json, "failed for {:?}", role);
            let deserialized: BnRole = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, role, "roundtrip failed for {:?}", role);
        }
    }
}
