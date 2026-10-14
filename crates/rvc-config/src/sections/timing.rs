//! Duty-deadline knobs. TOML `[timing]` only — no clap group.
//!
//! Defaults stay literals so this crate does not grow an `rvc-timing` edge.
//! Gloas keys parse and validate here; runtime fork selection is not this crate's job.

use serde::{Deserialize, Serialize};

fn default_attestation_due_bps() -> u64 {
    3333
}

fn default_aggregate_due_bps() -> u64 {
    6667
}

fn default_attestation_due_bps_gloas() -> u64 {
    2500
}

fn default_aggregate_due_bps_gloas() -> u64 {
    5000
}

fn default_sync_message_due_bps_gloas() -> u64 {
    2500
}

fn default_contribution_due_bps_gloas() -> u64 {
    5000
}

fn default_payload_due_bps() -> u64 {
    5000
}

fn default_payload_attestation_due_bps() -> u64 {
    7500
}

/// Duty deadlines as basis points of the slot.
///
/// Unknown `[timing]` keys fail deserialize so a typo cannot sit inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimingConfig {
    #[serde(default = "default_attestation_due_bps")]
    pub attestation_due_bps: u64,
    #[serde(default = "default_aggregate_due_bps")]
    pub aggregate_due_bps: u64,
    #[serde(default = "default_attestation_due_bps_gloas")]
    pub attestation_due_bps_gloas: u64,
    #[serde(default = "default_aggregate_due_bps_gloas")]
    pub aggregate_due_bps_gloas: u64,
    #[serde(default = "default_sync_message_due_bps_gloas")]
    pub sync_message_due_bps_gloas: u64,
    #[serde(default = "default_contribution_due_bps_gloas")]
    pub contribution_due_bps_gloas: u64,
    #[serde(default = "default_payload_due_bps")]
    pub payload_due_bps: u64,
    #[serde(default = "default_payload_attestation_due_bps")]
    pub payload_attestation_due_bps: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            attestation_due_bps: default_attestation_due_bps(),
            aggregate_due_bps: default_aggregate_due_bps(),
            attestation_due_bps_gloas: default_attestation_due_bps_gloas(),
            aggregate_due_bps_gloas: default_aggregate_due_bps_gloas(),
            sync_message_due_bps_gloas: default_sync_message_due_bps_gloas(),
            contribution_due_bps_gloas: default_contribution_due_bps_gloas(),
            payload_due_bps: default_payload_due_bps(),
            payload_attestation_due_bps: default_payload_attestation_due_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_uses_pre_gloas_and_gloas_defaults() {
        let cfg: TimingConfig = toml::from_str("").expect("empty");
        assert_eq!(cfg.attestation_due_bps, 3333);
        assert_eq!(cfg.aggregate_due_bps, 6667);
        assert_eq!(cfg.attestation_due_bps_gloas, 2500);
        assert_eq!(cfg.aggregate_due_bps_gloas, 5000);
        assert_eq!(cfg.sync_message_due_bps_gloas, 2500);
        assert_eq!(cfg.contribution_due_bps_gloas, 5000);
        assert_eq!(cfg.payload_due_bps, 5000);
        assert_eq!(cfg.payload_attestation_due_bps, 7500);
    }

    #[test]
    fn toml_round_trip_preserves_values() {
        let cfg: TimingConfig = toml::from_str(
            r#"
attestation_due_bps = 2500
aggregate_due_bps = 4000
"#,
        )
        .expect("parse");
        assert_eq!(cfg.attestation_due_bps, 2500);
        assert_eq!(cfg.aggregate_due_bps, 4000);
        let encoded = toml::to_string(&cfg).expect("serialize");
        let again: TimingConfig = toml::from_str(&encoded).expect("deserialize");
        assert_eq!(cfg, again);
    }

    #[test]
    fn six_gloas_keys_parse_from_toml() {
        let cfg: TimingConfig = toml::from_str(
            r#"
attestation_due_bps_gloas = 2500
aggregate_due_bps_gloas = 6667
sync_message_due_bps_gloas = 2500
contribution_due_bps_gloas = 5000
payload_due_bps = 5000
payload_attestation_due_bps = 7500
"#,
        )
        .expect("six Gloas timing keys must parse");
        assert_eq!(cfg.attestation_due_bps_gloas, 2500);
        assert_eq!(cfg.aggregate_due_bps_gloas, 6667);
        assert_eq!(cfg.sync_message_due_bps_gloas, 2500);
        assert_eq!(cfg.contribution_due_bps_gloas, 5000);
        assert_eq!(cfg.payload_due_bps, 5000);
        assert_eq!(cfg.payload_attestation_due_bps, 7500);
        assert_eq!(cfg.attestation_due_bps, 3333);
        assert_eq!(cfg.aggregate_due_bps, 6667);
    }

    #[test]
    fn aggregate_due_bps_gloas_default_is_5000() {
        let cfg = TimingConfig::default();
        assert_eq!(cfg.aggregate_due_bps_gloas, 5000);
        let parsed: TimingConfig = toml::from_str("").expect("empty");
        assert_eq!(parsed.aggregate_due_bps_gloas, 5000);
    }

    #[test]
    fn unknown_timing_key_fails_naming_the_key() {
        let err = toml::from_str::<TimingConfig>("not_a_timing_key = 1")
            .expect_err("unknown timing key must fail");
        let msg = err.to_string();
        assert!(msg.contains("not_a_timing_key"), "{msg}");
    }
}
