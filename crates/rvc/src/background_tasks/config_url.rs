//! Proposer configuration from URL with auto-refresh.
//!
//! Implements Prysm/Teku-compatible JSON schema for proposer configuration
//! fetched from a remote URL. Supports per-epoch refresh.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn, Instrument};
use validator_store::{DefaultUpdate, ValidatorStore};

/// One successful proposer-config fetch.
///
/// `updates` is `None` when the document has no `proposer_config` object.
/// `Some` includes an empty object. An empty object omits every previously
/// named pubkey. A missing object does not.
#[derive(Debug, Clone, PartialEq)]
pub struct FetchedProposerConfig {
    pub updates: Option<Vec<ValidatorConfigUpdate>>,
    pub default_update: Option<ValidatorConfigUpdate>,
}

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
    /// Absent on a Teku document that carries only `default_config`.
    /// Present, including an empty object, is the per-pubkey map.
    #[serde(default)]
    pub proposer_config: Option<HashMap<String, ProposerEntry>>,
    #[serde(default)]
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
        if let Some(gl) = self.gas_limit {
            validator_store::ensure_toml_u64("gas_limit", gl)
                .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
        }
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
        if let Some(gl) = self.gas_limit {
            validator_store::ensure_toml_u64("gas_limit", gl)
                .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
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
) -> Result<FetchedProposerConfig, String> {
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

    if body.proposer_config.is_none() && body.default_config.is_none() {
        return Err(
            "proposer config JSON has neither proposer_config nor default_config".to_string()
        );
    }

    let updates = match &body.proposer_config {
        None => None,
        Some(map) => {
            let mut updates = Vec::new();
            for (pubkey, entry) in map {
                updates
                    .push(entry_to_update(pubkey.clone(), entry).map_err(|e| {
                        format!("invalid proposer config for pubkey {pubkey}: {e}")
                    })?);
            }
            Some(updates)
        }
    };

    let default_update = body
        .default_config
        .as_ref()
        .map(|entry| entry_to_update(DEFAULT_PUBKEY.to_string(), entry))
        .transpose()
        .map_err(|e| format!("invalid default_config: {e}"))?;

    // Validate every entry before the caller applies any of them. One bad
    // fee, pubkey, or gas limit rejects the whole fetch: a sibling is not
    // published and an omitted key is not restored.
    if let Some(updates) = &updates {
        for update in updates {
            update.to_store_update().map_err(|e| {
                format!("invalid proposer config for pubkey {}: {e}", update.pubkey)
            })?;
        }
    }
    if let Some(update) = &default_update {
        update.to_default_update().map_err(|e| format!("invalid default_config: {e}"))?;
    }

    Ok(FetchedProposerConfig { updates, default_update })
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
                    let parsed =
                        g.parse::<u64>().map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
                    validator_store::ensure_toml_u64("gas_limit", parsed)
                        .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
                    Some(parsed)
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

/// Pubkeys named by the last successful fetch that included `proposer_config`.
///
/// Call [`Self::apply`] only after a fetch succeeds and every entry validates.
/// A 401, a body that is not JSON, a body with neither `proposer_config` nor
/// `default_config`, or one bad entry must not call it.
///
/// Ownership of each fee recipient, gas limit, and builder flag lives in
/// [`ValidatorStore`]. When the URL starts owning a field, the store snapshots
/// that field's live value under the same lock as the write. A keymanager
/// write of a field the URL owns drops that ownership, even when the written
/// value equals the URL value. A later document owns the field again only by
/// setting a value, and the baseline is the live value at that moment.
/// Omitting a pubkey restores each field the URL still owns. A fetch with no
/// `proposer_config` object applies `default_config` only and does not restore.
///
/// `default_config` changes the live defaults. The store does not write it
/// into `[defaults]`. No block is signed or published.
#[derive(Default)]
pub struct ProposerConfigApplier {
    seen: HashSet<[u8; 48]>,
}

impl ProposerConfigApplier {
    /// An applier that has not yet seen a successful fetch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one fully validated fetch.
    ///
    /// `updates == None` means the document had no `proposer_config` object.
    /// Every entry is checked before any store write. One bad pubkey, fee, or
    /// gas limit leaves the previous URL values in place and does not restore
    /// omitted keys. No block is signed or published.
    pub fn apply(
        &mut self,
        store: &ValidatorStore,
        updates: Option<Vec<ValidatorConfigUpdate>>,
        default_update: Option<ValidatorConfigUpdate>,
    ) {
        let Some(updates) = updates else {
            let default_update = match default_update.as_ref() {
                None => None,
                Some(update) => match update.to_default_update() {
                    Ok(update) => Some(update),
                    Err(e) => {
                        warn!(error = %e, "proposer config rejected; previous values stay");
                        return;
                    }
                },
            };
            if let Some(update) = default_update {
                if let Err(e) = store.apply_remote_defaults(update) {
                    warn!(error = %e, "proposer config default entry ignored");
                }
            }
            return;
        };
        let Ok(prepared) = prepare_fetch(&updates, default_update.as_ref()) else {
            return;
        };
        if let Some(update) = prepared.default_update {
            if let Err(e) = store.apply_remote_defaults(update) {
                warn!(error = %e, "proposer config default entry ignored");
            }
        }
        let mut present = HashSet::new();
        for (pk, store_update) in prepared.rows {
            present.insert(pk);
            if let Err(e) = store.apply_remote_proposer(&pk, store_update) {
                warn!(
                    error = %e,
                    pubkey_prefix = %pubkey_prefix(&pk),
                    "proposer config entry ignored"
                );
            }
        }
        let missing: Vec<[u8; 48]> =
            self.seen.iter().copied().filter(|pk| !present.contains(pk)).collect();
        for pk in missing {
            store.release_remote_proposer(&pk);
        }
        self.seen = present;
    }
}

struct PreparedFetch {
    default_update: Option<DefaultUpdate>,
    rows: Vec<([u8; 48], validator_store::ValidatorConfigUpdate)>,
}

/// Parse every entry. `Err` means the caller must not write or restore.
fn prepare_fetch(
    updates: &[ValidatorConfigUpdate],
    default_update: Option<&ValidatorConfigUpdate>,
) -> Result<PreparedFetch, ()> {
    let default_update = match default_update {
        None => None,
        Some(update) => match update.to_default_update() {
            Ok(update) => Some(update),
            Err(e) => {
                warn!(error = %e, "proposer config rejected; previous values stay");
                return Err(());
            }
        },
    };
    let mut rows = Vec::with_capacity(updates.len());
    for update in updates {
        if update.is_default_entry() {
            warn_ignored_entry(&update.pubkey, &ParseError::IsDefaultPubkey);
            return Err(());
        }
        match update.to_store_update() {
            Ok((pk, store_update)) => rows.push((pk, store_update)),
            Err(e) => {
                warn_ignored_entry(&update.pubkey, &e);
                return Err(());
            }
        }
    }
    Ok(PreparedFetch { default_update, rows })
}

fn warn_ignored_entry(pubkey: &str, error: &impl std::fmt::Display) {
    warn!(error = %error, pubkey = %pubkey, "proposer config entry ignored");
}

fn pubkey_prefix(pk: &[u8; 48]) -> String {
    hex::encode(&pk[..4])
}

/// Starts the background proposer config refresh task.
///
/// Fetches proposer config from URL at the configured interval and
/// calls `apply_fn` with the parsed updates. On failure, retains existing
/// config and logs at WARN level.
pub async fn start_proposer_config_refresh(
    settings: ProposerConfigUrlSettings,
    shutdown: CancellationToken,
    apply_fn: impl Fn(FetchedProposerConfig) + Send + 'static,
) {
    // Initial fetch at startup
    match fetch_proposer_config(&settings.url, settings.token.as_deref(), settings.insecure).await {
        Ok(fetched) => {
            let count = fetched.updates.as_ref().map_or(0, Vec::len);
            apply_fn(fetched);
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

    // detached: process-lifetime loop root; the tick is the exported span.
    let loop_span = tracing::info_span!(parent: None, "proposer_config_refresh");
    loop {
        let tick = tracing::info_span!(parent: None, "proposer_config_refresh.tick");
        tick.follows_from(&loop_span);
        let stop = async {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("Proposer config refresh task shutting down");
                    true
                }
                _ = interval.tick() => {
                    match fetch_proposer_config(
                        &settings.url,
                        settings.token.as_deref(),
                        settings.insecure,
                    ).await {
                        Ok(fetched) => {
                            let count = fetched.updates.as_ref().map_or(0, Vec::len);
                            apply_fn(fetched);
                            debug!(count, "Proposer config refreshed from URL");
                            crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.inc();
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to refresh proposer config from URL, retaining existing config");
                            crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.inc();
                        }
                    }
                    false
                }
            }
        }
        .instrument(tick)
        .await;
        if stop {
            return;
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
        let proposer_config = response.proposer_config.expect("proposer_config");
        assert_eq!(proposer_config.len(), 1);
        assert!(response.default_config.is_some());

        let entry = &proposer_config["0x98765"];
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
        let proposer_config = response.proposer_config.expect("proposer_config");
        let entry = &proposer_config["0x98765"];
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
        assert!(response.proposer_config.expect("proposer_config").is_empty());
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
        assert_eq!(response.proposer_config.expect("proposer_config").len(), 1);
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

        let pubkey = valid_pubkey_hex();
        let fee = valid_fee_recipient_hex();
        let default_fee = fee_hex(0xcc);
        let body = format!(
            r#"{{
            "proposer_config": {{
                "{pubkey}": {{
                    "fee_recipient": "{fee}",
                    "builder": {{ "enabled": true, "gas_limit": "30000000" }}
                }}
            }},
            "default_config": {{
                "fee_recipient": "{default_fee}",
                "builder": {{ "enabled": false }}
            }}
        }}"#
        );

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let fetched = fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();
        let updates = fetched.updates.expect("proposer_config");
        let default_update = fetched.default_update;

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].pubkey, pubkey);
        assert_eq!(updates[0].fee_recipient.as_deref(), Some(fee.as_str()));
        assert_eq!(updates[0].builder_enabled, Some(true));
        assert_eq!(updates[0].gas_limit, Some(30000000));

        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some(default_fee.as_str()));
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

        let fetched =
            fetch_proposer_config(&mock_server.uri(), Some("test-token"), true).await.unwrap();

        assert!(fetched.updates.expect("proposer_config").is_empty());
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
            start_proposer_config_refresh(settings, shutdown_clone, |_| {}).await;
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
        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some(fr),
                builder_enabled: Some(true),
                gas_limit: Some(36_000_000),
            }]),
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

        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some("not-hex".to_string()),
                builder_enabled: Some(true),
                gas_limit: None,
            }]),
            None,
        );

        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);
        assert!(logs_contain("proposer config entry ignored"));
    }

    /// A refresher `gas_limit` above `i64::MAX` must not go live. TOML cannot
    /// serialize it, so a published value makes every later save fail.
    #[test]
    fn apply_proposer_config_updates_rejects_gas_limit_above_i64_max() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        let huge = (i64::MAX as u64).saturating_add(1);

        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: None,
                builder_enabled: None,
                gas_limit: Some(huge),
            }]),
            Some(ValidatorConfigUpdate {
                pubkey: DEFAULT_PUBKEY.to_string(),
                fee_recipient: None,
                builder_enabled: None,
                gas_limit: Some(huge),
            }),
        );

        assert_eq!(store.effective_gas_limit(&pk), 30_000_000);
        assert_eq!(store.default_gas_limit(), 30_000_000);
    }

    fn row(
        pubkey: &str,
        fee: Option<&str>,
        builder: Option<bool>,
        gas: Option<u64>,
    ) -> ValidatorConfigUpdate {
        ValidatorConfigUpdate {
            pubkey: pubkey.to_string(),
            fee_recipient: fee.map(str::to_string),
            builder_enabled: builder,
            gas_limit: gas,
        }
    }

    fn fee_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 20]))
    }

    fn tracked_row() -> (ValidatorStore, [u8; 48], ProposerConfigApplier) {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        let mut cfg = validator_store::ValidatorConfig::new(pk);
        cfg.fee_recipient = Some([0xaau8; 20]);
        cfg.gas_limit = Some(21_000_000);
        cfg.builder_proposals = false;
        cfg.graffiti = Some([0x47u8; 32]);
        store.add_validator(cfg).unwrap();
        (store, pk, ProposerConfigApplier::new())
    }

    fn assert_url_values(store: &ValidatorStore, pk: &[u8; 48]) {
        assert_eq!(store.effective_fee_recipient(pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(pk), 36_000_000);
        assert!(store.is_builder_enabled(pk));
    }

    fn assert_baseline(store: &ValidatorStore, pk: &[u8; 48]) {
        assert_eq!(store.effective_fee_recipient(pk), [0xaau8; 20]);
        assert_eq!(store.effective_gas_limit(pk), 21_000_000);
        assert!(!store.is_builder_enabled(pk));
        assert_eq!(store.get_config(pk).expect("row").graffiti, Some([0x47u8; 32]));
        assert!(store.get_config(pk).expect("row").enabled);
    }

    #[test]
    fn an_omitted_pubkey_restores_the_pre_url_triple_and_leaves_graffiti() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        assert_url_values(&store, &pk);
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn a_later_url_value_does_not_replace_the_original_snapshot() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xcc)), Some(false), Some(40_000_000))]),
            None,
        );
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
        assert!(!store.is_builder_enabled(&pk));
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn a_pubkey_named_again_after_reset_snapshots_the_restored_row() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    fee_recipient: Some(Some([0xeeu8; 20])),
                    gas_limit: Some(Some(22_000_000)),
                    builder_proposals: Some(true),
                    ..validator_store::ValidatorConfigUpdate::default()
                },
            )
            .unwrap();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xdd)), Some(false), Some(41_000_000))]),
            None,
        );
        applier.apply(&store, Some(Vec::new()), None);
        assert_eq!(store.effective_fee_recipient(&pk), [0xeeu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 22_000_000);
        assert!(store.is_builder_enabled(&pk));
    }

    #[test]
    fn a_malformed_fee_on_a_present_pubkey_does_not_restore_the_snapshot() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some("not-hex"), Some(false), Some(1))]),
            None,
        );
        assert_url_values(&store, &pk);
    }

    #[test]
    fn a_gas_limit_above_i64_max_on_a_tracked_pubkey_does_not_restore() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        let huge = (i64::MAX as u64).saturating_add(1);
        applier.apply(&store, Some(vec![row(&hex_pk, None, None, Some(huge))]), None);
        assert_url_values(&store, &pk);
    }

    #[test]
    fn an_unknown_pubkey_is_not_tracked_and_a_later_row_is_not_wiped() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let unknown = [0x99u8; 48];
        let unknown_hex = format!("0x{}", hex::encode(unknown));
        let mut applier = ProposerConfigApplier::new();
        applier.apply(
            &store,
            Some(vec![row(&unknown_hex, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        assert!(!store.has_validator(&unknown));
        let mut cfg = validator_store::ValidatorConfig::new(unknown);
        cfg.fee_recipient = Some([0xddu8; 20]);
        cfg.gas_limit = Some(22_000_000);
        cfg.builder_proposals = true;
        store.add_validator(cfg).unwrap();
        applier.apply(&store, Some(Vec::new()), None);
        assert_eq!(store.effective_fee_recipient(&unknown), [0xddu8; 20]);
        assert_eq!(store.effective_gas_limit(&unknown), 22_000_000);
        assert!(store.is_builder_enabled(&unknown));
    }

    #[test]
    fn a_cleared_fee_and_gas_inherit_the_default_current_at_restore() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(validator_store::ValidatorConfig::new(pk)).unwrap();
        let mut applier = ProposerConfigApplier::new();
        let default_fee = fee_hex(0xcc);
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            Some(row("default", Some(&default_fee), None, Some(40_000_000))),
        );
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        applier.apply(&store, Some(Vec::new()), None);
        assert_eq!(store.get_config(&pk).expect("row").fee_recipient, None);
        assert_eq!(store.get_config(&pk).expect("row").gas_limit, None);
        assert!(!store.is_builder_enabled(&pk));
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
    }

    #[test]
    fn an_uppercase_pubkey_is_the_same_tracked_key() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            None,
        );
        let upper = format!("0x{}", hex::encode(pk).to_uppercase());
        applier.apply(
            &store,
            Some(vec![row(&upper, Some(&fee_hex(0xcc)), Some(true), Some(36_000_000))]),
            None,
        );
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert!(store.is_builder_enabled(&pk));
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn omitting_one_pubkey_leaves_the_other_url_row_in_place() {
        let (store, pk, mut applier) = tracked_row();
        let other = [0x22u8; 48];
        let mut other_cfg = validator_store::ValidatorConfig::new(other);
        other_cfg.fee_recipient = Some([0x11u8; 20]);
        other_cfg.gas_limit = Some(23_000_000);
        other_cfg.builder_proposals = false;
        store.add_validator(other_cfg).unwrap();
        let other_hex = format!("0x{}", hex::encode(other));
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some(&fee_hex(0xbb)), Some(true), Some(36_000_000)),
                row(&other_hex, Some(&fee_hex(0xdd)), Some(true), Some(37_000_000)),
            ]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&other_hex, Some(&fee_hex(0xee)), Some(true), Some(38_000_000))]),
            None,
        );
        assert_baseline(&store, &pk);
        assert_eq!(store.effective_fee_recipient(&other), [0xeeu8; 20]);
        assert_eq!(store.effective_gas_limit(&other), 38_000_000);
        assert!(store.is_builder_enabled(&other));
    }

    #[test]
    fn a_malformed_default_rejects_the_whole_fetch() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            Some(row("default", Some(&fee_hex(0xcc)), None, Some(40_000_000))),
        );
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        applier.apply(&store, Some(Vec::new()), Some(row("default", Some("not-hex"), None, None)));
        assert_url_values(&store, &pk);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    #[test]
    fn one_bad_entry_does_not_apply_a_sibling_or_restore_an_omission() {
        let (store, pk, mut applier) = tracked_row();
        let other = [0x22u8; 48];
        let mut other_cfg = validator_store::ValidatorConfig::new(other);
        other_cfg.fee_recipient = Some([0x11u8; 20]);
        other_cfg.gas_limit = Some(23_000_000);
        other_cfg.builder_proposals = false;
        store.add_validator(other_cfg).unwrap();
        let other_hex = format!("0x{}", hex::encode(other));
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some(&fee_hex(0xbb)), Some(true), Some(36_000_000)),
                row(&other_hex, Some(&fee_hex(0xdd)), Some(true), Some(37_000_000)),
            ]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some("not-hex"), Some(false), Some(1)),
                row(&other_hex, Some(&fee_hex(0xee)), Some(false), Some(38_000_000)),
            ]),
            None,
        );
        assert_url_values(&store, &pk);
        assert_eq!(store.effective_fee_recipient(&other), [0xddu8; 20]);
        assert_eq!(store.effective_gas_limit(&other), 37_000_000);
        assert!(store.is_builder_enabled(&other));
    }

    #[test]
    fn a_body_with_neither_proposer_key_deserializes_and_is_not_a_document() {
        let body: ProposerConfigResponse =
            serde_json::from_str(r#"{"status":"ok"}"#).expect("unrelated JSON still parses");
        assert!(body.proposer_config.is_none());
        assert!(body.default_config.is_none());
    }

    #[test]
    fn a_document_with_only_default_config_parses() {
        let fee = valid_fee_recipient_hex();
        let body: ProposerConfigResponse =
            serde_json::from_str(&format!(r#"{{"default_config":{{"fee_recipient":"{fee}"}}}}"#))
                .expect("teku default-only document");
        assert!(body.proposer_config.is_none());
        assert!(body.default_config.is_some());
    }

    #[tokio::test]
    async fn fetch_rejects_a_body_with_neither_key_and_accepts_default_only() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let neither = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":"ok"}"#))
            .mount(&neither)
            .await;
        let err = fetch_proposer_config(&neither.uri(), None, true).await.expect_err("neither");
        assert!(err.contains("neither"), "{err}");

        let malformed = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":[]}"#))
            .mount(&malformed)
            .await;
        let err = fetch_proposer_config(&malformed.uri(), None, true).await.expect_err("malformed");
        assert!(err.contains("parse") || err.contains("proposer"), "{err}");

        let only_default = MockServer::start().await;
        let fee = valid_fee_recipient_hex();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{"default_config":{{"fee_recipient":"{fee}"}}}}"#
                )),
            )
            .mount(&only_default)
            .await;
        let fetched =
            fetch_proposer_config(&only_default.uri(), None, true).await.expect("default");
        assert!(fetched.updates.is_none());
        assert_eq!(
            fetched.default_update.expect("default").fee_recipient.as_deref(),
            Some(fee.as_str())
        );
    }

    #[test]
    fn a_default_only_fetch_does_not_restore_a_tracked_pubkey() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            None,
        );
        applier.apply(
            &store,
            None,
            Some(row("default", Some(&fee_hex(0xcc)), None, Some(40_000_000))),
        );
        assert_url_values(&store, &pk);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }
}
