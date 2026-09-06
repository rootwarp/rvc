//! Global builder URLs and `min_bid` for `produceBlockV4`. TOML `[builder]` only.
//!
//! Empty `builders` is legal (local-only). Unknown keys fail deserialize so a
//! typo cannot sit inert. No clap group — `OPERATOR_KNOB_NAMES` stays at 69.

use serde::{Deserialize, Serialize};

use crate::{ConfigError, ConfigSource};

/// SSZ `MAX_BUILDER_URL_SIZE` (beacon-APIs PR #630); keep in lock-step with
/// `beacon::v4_wire::MAX_BUILDER_URL_SIZE` without taking a beacon edge.
const MAX_BUILDER_URL_SIZE: usize = 2048;

/// Global builder settings that populate `ValidatorStore` at startup.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuilderSettings {
    /// Builder URLs. Empty means request none (local-only / p2p-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builders: Vec<String>,
    /// Minimum bid in Gwei. `None` uses the store's built-in fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_bid: Option<u64>,
    /// Global `builder_boost_factor`. `None` uses the store's built-in fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<u64>,
}

impl BuilderSettings {
    /// `true` when every field is at its TOML-default (omit from Config snapshots).
    pub fn is_default(&self) -> bool {
        self.builders.is_empty() && self.min_bid.is_none() && self.builder_boost_factor.is_none()
    }

    /// Reject a malformed builder URL, naming the offending value.
    ///
    /// Same http/https+host rules as `validator_store::validate_builder_url`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for raw in &self.builders {
            validate_builder_url(raw)?;
        }
        Ok(())
    }
}

fn validate_builder_url(raw: &str) -> Result<(), ConfigError> {
    let invalid = |message: String| ConfigError::Invalid {
        field: "builder.builders",
        message,
        source_layer: ConfigSource::Default,
    };

    if raw.len() > MAX_BUILDER_URL_SIZE {
        return Err(invalid(format!("builder URL exceeds {MAX_BUILDER_URL_SIZE} bytes: {raw:?}")));
    }

    let parsed =
        url::Url::parse(raw).map_err(|_| invalid(format!("malformed builder URL: {raw:?}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(invalid(format!("builder URL must start with http:// or https://: {raw:?}")));
    }
    if parsed.host_str().is_none() {
        return Err(invalid(format!("malformed builder URL: {raw:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_is_legal_local_only() {
        let cfg: BuilderSettings = toml::from_str("").expect("empty");
        assert!(cfg.builders.is_empty());
        assert!(cfg.min_bid.is_none());
        assert!(cfg.builder_boost_factor.is_none());
        cfg.validate().expect("empty builders list is legal");
    }

    #[test]
    fn empty_builders_array_is_legal() {
        let cfg: BuilderSettings = toml::from_str("builders = []").expect("empty array");
        assert!(cfg.builders.is_empty());
        cfg.validate().expect("[] is legal");
    }

    #[test]
    fn url_list_and_min_bid_parse() {
        let cfg: BuilderSettings = toml::from_str(
            r#"
builders = ["https://relay.example", "http://127.0.0.1:18550"]
min_bid = 10000000
builder_boost_factor = 80
"#,
        )
        .expect("parse");
        assert_eq!(
            cfg.builders,
            vec!["https://relay.example".to_string(), "http://127.0.0.1:18550".to_string()]
        );
        assert_eq!(cfg.min_bid, Some(10_000_000));
        assert_eq!(cfg.builder_boost_factor, Some(80));
        cfg.validate().expect("well-formed URLs");
    }

    #[test]
    fn malformed_url_errors_naming_the_value() {
        let cfg = BuilderSettings {
            builders: vec!["not a url".to_string()],
            ..BuilderSettings::default()
        };
        let err = cfg.validate().expect_err("malformed URL");
        let msg = err.to_string();
        assert!(msg.contains("not a url"), "{msg}");
        assert!(msg.contains("builder.builders"), "{msg}");
    }

    #[test]
    fn ftp_url_errors_naming_the_value() {
        let cfg = BuilderSettings {
            builders: vec!["ftp://relay.example".to_string()],
            ..BuilderSettings::default()
        };
        let err = cfg.validate().expect_err("ftp rejected");
        let msg = err.to_string();
        assert!(msg.contains("ftp://relay.example"), "{msg}");
    }

    #[test]
    fn file_url_errors_naming_the_value() {
        let cfg = BuilderSettings {
            builders: vec!["file:///tmp/builder".to_string()],
            ..BuilderSettings::default()
        };
        let err = cfg.validate().expect_err("file:// rejected");
        let msg = err.to_string();
        assert!(msg.contains("file:///tmp/builder"), "{msg}");
    }

    #[test]
    fn unknown_builder_key_fails_naming_the_key() {
        let err = toml::from_str::<BuilderSettings>("not_a_builder_key = 1")
            .expect_err("unknown builder key must fail");
        let msg = err.to_string();
        assert!(msg.contains("not_a_builder_key"), "{msg}");
    }
}
