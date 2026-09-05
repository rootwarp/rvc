//! Local Gloas fork schedule. TOML `[fork_schedule]` only — no clap group.
//!
//! Unset and the `u64::MAX` sentinel are both unscheduled. Runtime
//! reconciliation against the BN spec lives in the validator client.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Local Gloas epoch/version pair for two-source startup reconciliation.
///
/// Unknown `[fork_schedule]` keys fail deserialize so a typo cannot sit inert.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForkScheduleConfig {
    /// `u64::MAX` (and the decimal string form) is the unscheduled sentinel.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_epoch",
        skip_serializing_if = "Option::is_none"
    )]
    pub gloas_fork_epoch: Option<u64>,
    /// Hex text (`0x` / `0X`); compared as 4 bytes at startup, not as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gloas_fork_version: Option<String>,
}

/// TOML integers are i64, so the far-future sentinel must also accept a decimal string.
fn deserialize_optional_epoch<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EpochVisitor;

    impl<'de> Visitor<'de> for EpochVisitor {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a u64 epoch, or a decimal string")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            u64::try_from(v).map(Some).map_err(E::custom)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u64>().map(Some).map_err(E::custom)
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_any(EpochVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_is_unset() {
        let cfg: ForkScheduleConfig = toml::from_str("").expect("empty");
        assert!(cfg.gloas_fork_epoch.is_none());
        assert!(cfg.gloas_fork_version.is_none());
    }

    #[test]
    fn integer_epoch_and_version_parse() {
        let cfg: ForkScheduleConfig = toml::from_str(
            r#"
gloas_fork_epoch = 600000
gloas_fork_version = "0x07000000"
"#,
        )
        .expect("parse");
        assert_eq!(cfg.gloas_fork_epoch, Some(600000));
        assert_eq!(cfg.gloas_fork_version.as_deref(), Some("0x07000000"));
    }

    #[test]
    fn sentinel_epoch_string_parses_as_u64_max() {
        let cfg: ForkScheduleConfig = toml::from_str(
            r#"
gloas_fork_epoch = "18446744073709551615"
"#,
        )
        .expect("sentinel decimal string");
        assert_eq!(cfg.gloas_fork_epoch, Some(u64::MAX));
        assert!(cfg.gloas_fork_version.is_none());
    }

    #[test]
    fn unknown_fork_schedule_key_fails_naming_the_key() {
        let err = toml::from_str::<ForkScheduleConfig>("not_a_fork_key = 1")
            .expect_err("unknown fork_schedule key must fail");
        let msg = err.to_string();
        assert!(msg.contains("not_a_fork_key"), "{msg}");
    }
}
