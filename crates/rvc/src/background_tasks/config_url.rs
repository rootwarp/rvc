//! Proposer configuration from URL with auto-refresh.
//!
//! Implements Prysm/Teku-compatible JSON schema for proposer configuration
//! fetched from a remote URL. Supports per-epoch refresh.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use validator_store::{DefaultUpdate, ValidatorStore};

/// Literal pubkey key used for `default_config` entries (Prysm/Teku convention).
pub const DEFAULT_PUBKEY: &str = "default";

/// Error mapping a URL-fetched proposer config entry into store types.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid fee_recipient hex: {0}")]
    InvalidFeeRecipient(String),
    /// Zero address burns MEV/priority fees; refused like startup ZeroFeeRecipient / keymanager.
    #[error("fee_recipient cannot be the zero address")]
    ZeroFeeRecipient,
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),
    #[error("invalid gas_limit: {0}")]
    InvalidGasLimit(String),
    #[error("pubkey is the literal \"default\"; use to_default_update")]
    IsDefaultPubkey,
    #[error("to_default_update requires pubkey \"default\"")]
    NotDefaultPubkey,
}

/// Top-level proposer config response from URL endpoint.
///
/// Compatible with both Prysm (`--proposer-settings-url`) and
/// Teku (`--validators-proposer-config`) JSON schemas.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerConfigResponse {
    #[serde(default)]
    pub proposer_config: HashMap<String, ProposerEntry>,
    pub default_config: Option<ProposerEntry>,
}

/// Per-validator proposer configuration entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerEntry {
    pub fee_recipient: Option<String>,
    #[serde(default)]
    pub builder: Option<BuilderEntry>,
}

/// Builder configuration within a proposer entry.
#[derive(Debug, Clone, Deserialize)]
pub struct BuilderEntry {
    pub enabled: Option<bool>,
    pub gas_limit: Option<String>,
}

/// Parsed proposer configuration update for a single validator.
///
/// Distinct from [`validator_store::ValidatorConfigUpdate`] (VD-E3): this type
/// carries the wire/JSON field names (`builder_enabled`, hex strings). Map with
/// [`ValidatorConfigUpdate::to_store_update`] or
/// [`ValidatorConfigUpdate::to_default_update`].
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorConfigUpdate {
    pub pubkey: String,
    pub fee_recipient: Option<String>,
    pub builder_enabled: Option<bool>,
    pub gas_limit: Option<u64>,
}

impl ValidatorConfigUpdate {
    /// Returns `true` when this entry is the `default_config` sentinel (`"default"`).
    pub fn is_default_entry(&self) -> bool {
        self.pubkey == DEFAULT_PUBKEY
    }

    /// Map a per-validator entry to store types.
    ///
    /// - Absent optional fields become outer `None` (leave alone), never
    ///   `Some(None)` (clear).
    /// - `builder_enabled` renames to `builder_proposals`.
    /// - Malformed hex or the zero fee-recipient address is `Err` (never silent).
    /// - The literal pubkey `"default"` is rejected; use [`Self::to_default_update`].
    pub fn to_store_update(
        &self,
    ) -> Result<([u8; 48], validator_store::ValidatorConfigUpdate), ParseError> {
        if self.is_default_entry() {
            return Err(ParseError::IsDefaultPubkey);
        }
        let pubkey = parse_pubkey_hex(&self.pubkey)?;
        let fee_recipient = match &self.fee_recipient {
            None => None,
            Some(s) => Some(Some(parse_fee_recipient_hex(s)?)),
        };
        Ok((
            pubkey,
            validator_store::ValidatorConfigUpdate {
                fee_recipient,
                gas_limit: self.gas_limit.map(Some),
                graffiti: None,
                builder_proposals: self.builder_enabled,
                builder_boost_factor: None,
                block_selection_mode: None,
                builders: None,
                min_bid: None,
            },
        ))
    }

    /// Map a `default_config` entry to a store defaults partial update.
    ///
    /// Requires [`Self::is_default_entry`] (`pubkey == "default"`). Call only
    /// for the optional `default_config` value from fetch, not for per-validator
    /// `proposer_config` entries — elevating an arbitrary pubkey to store-wide
    /// defaults is refused with [`ParseError::NotDefaultPubkey`].
    ///
    /// Absent fields become `None` (leave alone). Malformed or zero fee-recipient
    /// hex is `Err`. Builder fields are not part of store defaults and are ignored.
    pub fn to_default_update(&self) -> Result<DefaultUpdate, ParseError> {
        if !self.is_default_entry() {
            return Err(ParseError::NotDefaultPubkey);
        }
        let fee_recipient = match &self.fee_recipient {
            None => None,
            Some(s) => Some(parse_fee_recipient_hex(s)?),
        };
        Ok(DefaultUpdate { fee_recipient, gas_limit: self.gas_limit, graffiti: None })
    }
}

/// Parse a 20-byte execution address from hex (optional single `0x`/`0X`).
///
/// Rejects the zero address (aligns with startup `ZeroFeeRecipient` and keymanager).
fn parse_fee_recipient_hex(s: &str) -> Result<[u8; 20], ParseError> {
    let hex = strip_hex_prefix(s)?;
    let bytes = hex::decode(hex).map_err(|e| {
        // Avoid embedding raw non-hex characters (may be sensitive) in logs.
        let msg = match e {
            hex::FromHexError::OddLength => "odd number of hex digits".to_owned(),
            hex::FromHexError::InvalidHexCharacter { index, .. } => {
                format!("non-hex character at index {index}")
            }
            hex::FromHexError::InvalidStringLength => "invalid string length".to_owned(),
        };
        ParseError::InvalidFeeRecipient(msg)
    })?;
    let addr: [u8; 20] = bytes.try_into().map_err(|v: Vec<u8>| {
        ParseError::InvalidFeeRecipient(format!("expected 20 bytes, got {}", v.len()))
    })?;
    if addr == [0u8; 20] {
        return Err(ParseError::ZeroFeeRecipient);
    }
    Ok(addr)
}

/// Parse a 48-byte BLS pubkey from hex (optional `0x`/`0X`, case-insensitive).
fn parse_pubkey_hex(s: &str) -> Result<[u8; 48], ParseError> {
    eth_types::canonical::pubkey_hex::parse_pubkey_hex(s)
        .map(|pk| *pk.as_bytes())
        .map_err(|e| ParseError::InvalidPubkey(e.to_string()))
}

/// Strip a single optional `0x`/`0X` prefix; reject doubled prefixes.
fn strip_hex_prefix(s: &str) -> Result<&str, ParseError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.starts_with("0x") || rest.starts_with("0X") {
            return Err(ParseError::InvalidFeeRecipient("double 0x prefix".to_owned()));
        }
        Ok(rest)
    } else {
        Ok(s)
    }
}

/// Configuration for the proposer config URL refresh task.
#[derive(Debug, Clone)]
pub struct ProposerConfigUrlSettings {
    pub url: String,
    pub refresh_interval: Duration,
    pub token: Option<String>,
    pub insecure: bool,
}

/// Fetches proposer configuration from the given URL.
///
/// Returns a list of per-validator config updates and an optional default config.
/// Supports Bearer token authentication and HTTPS enforcement.
pub async fn fetch_proposer_config(
    url: &str,
    token: Option<&str>,
    insecure: bool,
) -> Result<(Vec<ValidatorConfigUpdate>, Option<ValidatorConfigUpdate>), String> {
    if !insecure && !url.starts_with("https://") {
        return Err(
            "proposer config URL requires HTTPS; use --proposer-config-url-insecure for HTTP"
                .to_string(),
        );
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let mut request = client.get(url);
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let response =
        request.send().await.map_err(|e| format!("failed to fetch proposer config: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("proposer config URL returned HTTP {}", response.status()));
    }

    let body: ProposerConfigResponse =
        response.json().await.map_err(|e| format!("failed to parse proposer config JSON: {e}"))?;

    let mut updates = Vec::new();
    for (pubkey, entry) in &body.proposer_config {
        updates.push(
            entry_to_update(pubkey.clone(), entry)
                .map_err(|e| format!("invalid proposer config for pubkey {pubkey}: {e}"))?,
        );
    }

    let default_update = body
        .default_config
        .as_ref()
        .map(|entry| entry_to_update(DEFAULT_PUBKEY.to_string(), entry))
        .transpose()
        .map_err(|e| format!("invalid default_config: {e}"))?;

    Ok((updates, default_update))
}

/// Build a wire update from a JSON entry.
///
/// Malformed `builder.gas_limit` strings are `Err` (not silent `None`) so a
/// multi-field entry cannot partially apply fee_recipient while dropping gas.
fn entry_to_update(
    pubkey: String,
    entry: &ProposerEntry,
) -> Result<ValidatorConfigUpdate, ParseError> {
    let (builder_enabled, gas_limit) = match &entry.builder {
        Some(b) => {
            let gas_limit = match b.gas_limit.as_deref() {
                None => None,
                Some(g) => {
                    Some(g.parse::<u64>().map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?)
                }
            };
            (b.enabled, gas_limit)
        }
        None => (None, None),
    };

    Ok(ValidatorConfigUpdate {
        pubkey,
        fee_recipient: entry.fee_recipient.clone(),
        builder_enabled,
        gas_limit,
    })
}

/// Write URL-fetched proposer config into [`ValidatorStore`].
///
/// Malformed entries are skipped at `warn` and leave previous store values
/// intact (never a partial write of a bad entry, never a panic). Successful
/// defaults go through [`ValidatorStore::apply_default_update`]; per-validator
/// entries through [`ValidatorStore::update_config`].
pub fn apply_proposer_config_updates(
    store: &ValidatorStore,
    updates: Vec<ValidatorConfigUpdate>,
    default_update: Option<ValidatorConfigUpdate>,
) {
    if let Some(d) = default_update {
        match d.to_default_update() {
            Ok(u) => store.apply_default_update(u),
            Err(e) => {
                warn!(error = %e, "proposer config default entry ignored");
            }
        }
    }
    for update in updates {
        match update.to_store_update() {
            Ok((pk, u)) => {
                if let Err(e) = store.update_config(&pk, u) {
                    warn!(
                        error = %e,
                        pubkey = %update.pubkey,
                        "proposer config entry ignored"
                    );
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    pubkey = %update.pubkey,
                    "proposer config entry ignored"
                );
            }
        }
    }
}

/// Starts the background proposer config refresh task.
///
/// Fetches proposer config from URL at the configured interval and
/// calls `apply_fn` with the parsed updates. On failure, retains existing
/// config and logs at WARN level.
pub async fn start_proposer_config_refresh(
    settings: ProposerConfigUrlSettings,
    shutdown: CancellationToken,
    apply_fn: impl Fn(Vec<ValidatorConfigUpdate>, Option<ValidatorConfigUpdate>) + Send + 'static,
) {
    // Initial fetch at startup
    match fetch_proposer_config(&settings.url, settings.token.as_deref(), settings.insecure).await {
        Ok((updates, default_update)) => {
            let count = updates.len();
            apply_fn(updates, default_update);
            info!(count, "Initial proposer config loaded from URL");
            crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.inc();
        }
        Err(e) => {
            warn!(error = %e, "Failed to load initial proposer config from URL");
            crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.inc();
        }
    }

    let mut interval = tokio::time::interval(settings.refresh_interval);
    // Skip the immediate first tick (we already did the initial fetch)
    interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                debug!("Proposer config refresh task shutting down");
                return;
            }
            _ = interval.tick() => {
                match fetch_proposer_config(
                    &settings.url,
                    settings.token.as_deref(),
                    settings.insecure,
                ).await {
                    Ok((updates, default_update)) => {
                        let count = updates.len();
                        apply_fn(updates, default_update);
                        debug!(count, "Proposer config refreshed from URL");
                        crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.inc();
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to refresh proposer config from URL, retaining existing config");
                        crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.inc();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prysm_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "30000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "30000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.proposer_config.len(), 1);
        assert!(response.default_config.is_some());

        let entry = &response.proposer_config["0x98765"];
        assert_eq!(entry.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(entry.builder.as_ref().unwrap().enabled, Some(true));
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("30000000"));
    }

    #[test]
    fn test_parse_teku_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "36000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "36000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        let entry = &response.proposer_config["0x98765"];
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("36000000"));
    }

    #[test]
    fn test_entry_to_update_full() {
        let entry = ProposerEntry {
            fee_recipient: Some("0xabcd".to_string()),
            builder: Some(BuilderEntry {
                enabled: Some(true),
                gas_limit: Some("30000000".to_string()),
            }),
        };

        let update = entry_to_update("0x98765".to_string(), &entry).expect("valid entry");
        assert_eq!(update.pubkey, "0x98765");
        assert_eq!(update.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(update.builder_enabled, Some(true));
        assert_eq!(update.gas_limit, Some(30000000));
    }

    #[test]
    fn test_entry_to_update_no_builder() {
        let entry = ProposerEntry { fee_recipient: Some("0x1234".to_string()), builder: None };

        let update = entry_to_update("0xabc".to_string(), &entry).expect("valid entry");
        assert_eq!(update.builder_enabled, None);
        assert_eq!(update.gas_limit, None);
    }

    #[test]
    fn test_entry_to_update_invalid_gas_limit() {
        let entry = ProposerEntry {
            fee_recipient: Some(format!("0x{}", hex::encode([0xaau8; 20]))),
            builder: Some(BuilderEntry {
                enabled: Some(false),
                gas_limit: Some("not_a_number".to_string()),
            }),
        };

        // Fail the whole entry — do not silently drop gas while keeping fee_recipient.
        let err = entry_to_update("0xdef".to_string(), &entry).expect_err("invalid gas");
        assert!(matches!(err, ParseError::InvalidGasLimit(_)));
    }

    #[test]
    fn test_parse_empty_proposer_config() {
        let json = r#"{
            "proposer_config": {},
            "default_config": {
                "fee_recipient": "0x1234"
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert!(response.proposer_config.is_empty());
        assert!(response.default_config.is_some());
    }

    #[test]
    fn test_parse_no_default_config() {
        let json = r#"{
            "proposer_config": {
                "0x111": {
                    "fee_recipient": "0x222"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.proposer_config.len(), 1);
        assert!(response.default_config.is_none());
    }

    #[tokio::test]
    async fn test_fetch_rejects_http_without_insecure() {
        let result = fetch_proposer_config("http://example.com/config", None, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[tokio::test]
    async fn test_fetch_success_with_mock() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                }
            },
            "default_config": {
                "fee_recipient": "0xccc",
                "builder": { "enabled": false }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, default_update) =
            fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].pubkey, "0xaaa");
        assert_eq!(updates[0].fee_recipient.as_deref(), Some("0xbbb"));
        assert_eq!(updates[0].builder_enabled, Some(true));
        assert_eq!(updates[0].gas_limit, Some(30000000));

        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some("0xccc"));
        assert_eq!(default.builder_enabled, Some(false));
    }

    #[tokio::test]
    async fn test_fetch_with_bearer_token() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, _) =
            fetch_proposer_config(&mock_server.uri(), Some("test-token"), true).await.unwrap();

        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_http_error_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn test_refresh_clean_shutdown() {
        let settings = ProposerConfigUrlSettings {
            url: "http://nonexistent.invalid/config".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            start_proposer_config_refresh(settings, shutdown_clone, |_, _| {}).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }

    fn valid_pubkey_hex() -> String {
        format!("0x{}", hex::encode([0x11u8; 48]))
    }

    fn valid_fee_recipient_hex() -> String {
        format!("0x{}", hex::encode([0xaau8; 20]))
    }

    #[test]
    fn to_store_update_maps_builder_enabled_to_builder_proposals() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: None,
            builder_enabled: Some(true),
            gas_limit: Some(30_000_000),
        };

        let (pk, store_update) = update.to_store_update().expect("valid entry");
        assert_eq!(pk, [0x11u8; 48]);
        assert_eq!(store_update.builder_proposals, Some(true));
        assert_eq!(store_update.gas_limit, Some(Some(30_000_000)));
    }

    #[test]
    fn to_store_update_rejects_a_malformed_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some("not-a-hex-address".to_string()),
            builder_enabled: None,
            gas_limit: None,
        };

        // Malformed Some(hex) must be Err — never silently become outer None.
        match update.to_store_update() {
            Err(ParseError::InvalidFeeRecipient(_)) => {}
            Err(other) => panic!("expected InvalidFeeRecipient, got {other:?}"),
            Ok((_, store_update)) => panic!(
                "malformed fee_recipient must be Err, got Ok with fee_recipient={:?}",
                store_update.fee_recipient
            ),
        }
    }

    #[test]
    fn an_absent_fee_recipient_maps_to_outer_none_not_some_none() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: None,
            builder_enabled: Some(false),
            gas_limit: None,
        };

        let (_, store_update) = update.to_store_update().expect("valid entry");
        assert!(store_update.fee_recipient.is_none());
        assert_ne!(store_update.fee_recipient, Some(None));
    }

    #[test]
    fn the_literal_default_pubkey_routes_to_the_defaults_path() {
        let fr = valid_fee_recipient_hex();
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some(fr.clone()),
            builder_enabled: Some(true),
            gas_limit: Some(36_000_000),
        };

        assert!(update.is_default_entry());
        assert!(matches!(update.to_store_update(), Err(ParseError::IsDefaultPubkey)));

        let default = update.to_default_update().expect("defaults path");
        assert_eq!(default.fee_recipient, Some([0xaau8; 20]));
        assert_eq!(default.gas_limit, Some(36_000_000));
        // Builder is not a store-default field.
        assert!(default.graffiti.is_none());
    }

    #[test]
    fn to_store_update_accepts_fee_recipient_with_and_without_0x_prefix() {
        let with_prefix = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        let without_prefix = ValidatorConfigUpdate {
            pubkey: hex::encode([0x11u8; 48]),
            fee_recipient: Some(hex::encode([0xaau8; 20])),
            builder_enabled: None,
            gas_limit: None,
        };
        let upper_prefix = ValidatorConfigUpdate {
            pubkey: format!("0X{}", hex::encode([0x11u8; 48])),
            fee_recipient: Some(format!("0X{}", hex::encode([0xaau8; 20]))),
            builder_enabled: None,
            gas_limit: None,
        };

        for update in [with_prefix, without_prefix, upper_prefix] {
            let (pk, store_update) = update.to_store_update().expect("hex accepted");
            assert_eq!(pk, [0x11u8; 48]);
            assert_eq!(store_update.fee_recipient, Some(Some([0xaau8; 20])));
        }
    }

    #[test]
    fn to_default_update_absent_fee_recipient_is_none() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: None,
            builder_enabled: None,
            gas_limit: Some(30_000_000),
        };
        let default = update.to_default_update().expect("defaults path");
        assert!(default.fee_recipient.is_none());
        assert_eq!(default.gas_limit, Some(30_000_000));
    }

    #[test]
    fn to_default_update_rejects_malformed_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some("0xgg".to_string()),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::InvalidFeeRecipient(_))));
    }

    #[test]
    fn to_store_update_rejects_zero_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(format!("0x{}", hex::encode([0u8; 20]))),
            builder_enabled: Some(true),
            gas_limit: Some(30_000_000),
        };
        // Must not partially apply builder/gas while accepting a burn address.
        assert!(matches!(update.to_store_update(), Err(ParseError::ZeroFeeRecipient)));
    }

    #[test]
    fn to_default_update_rejects_zero_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some(format!("0x{}", "00".repeat(20))),
            builder_enabled: None,
            gas_limit: Some(30_000_000),
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::ZeroFeeRecipient)));
    }

    #[test]
    fn to_default_update_rejects_non_default_pubkey() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::NotDefaultPubkey)));
    }

    #[test]
    fn to_store_update_rejects_malformed_pubkey() {
        let update = ValidatorConfigUpdate {
            pubkey: "0xnot-a-pubkey".to_string(),
            fee_recipient: None,
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_store_update(), Err(ParseError::InvalidPubkey(_))));
    }

    #[test]
    fn an_absent_gas_limit_maps_to_outer_none_not_some_none() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        let (_, store_update) = update.to_store_update().expect("valid entry");
        assert!(store_update.gas_limit.is_none());
        assert_ne!(store_update.gas_limit, Some(None));
    }

    #[test]
    fn to_store_update_rejects_double_0x_fee_recipient_prefix() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(format!("0x0x{}", hex::encode([0xaau8; 20]))),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_store_update(), Err(ParseError::InvalidFeeRecipient(_))));
    }

    #[tokio::test]
    async fn test_fetch_rejects_invalid_gas_limit_entry() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "not_a_number" }
                }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("gas_limit"));
    }

    #[test]
    fn apply_proposer_config_updates_writes_per_validator_and_defaults() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let fr = valid_fee_recipient_hex();
        let default_fr = format!("0x{}", hex::encode([0xbbu8; 20]));
        apply_proposer_config_updates(
            &store,
            vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some(fr),
                builder_enabled: Some(true),
                gas_limit: Some(36_000_000),
            }],
            Some(ValidatorConfigUpdate {
                pubkey: DEFAULT_PUBKEY.to_string(),
                fee_recipient: Some(default_fr),
                builder_enabled: None,
                gas_limit: Some(40_000_000),
            }),
        );

        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);
        assert!(store.is_builder_enabled(&pk));
        assert_eq!(store.effective_gas_limit(&pk), 36_000_000);
        assert_eq!(store.default_fee_recipient(), [0xbbu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    #[test]
    #[tracing_test::traced_test]
    fn apply_proposer_config_updates_skips_malformed_and_warns() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some([0xaau8; 20]);
        store.add_validator(cfg).unwrap();

        apply_proposer_config_updates(
            &store,
            vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some("not-hex".to_string()),
                builder_enabled: Some(true),
                gas_limit: None,
            }],
            None,
        );

        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);
        assert!(logs_contain("proposer config entry ignored"));
    }
}
