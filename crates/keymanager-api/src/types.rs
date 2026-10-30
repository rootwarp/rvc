use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreInfo {
    pub validating_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
    pub readonly: bool,
    /// Whether this key has passed the post-import doppelganger window.
    ///
    /// `false` means the key was recently imported and is still in the
    /// doppelganger window — attestation is not yet enabled.
    /// `true` means the window has elapsed (or the key was not imported
    /// via the API) and the key may attest normally.
    ///
    /// Defaults to `true` when deserialising older responses that lack this
    /// field (backward-compat with pre-M-12 clients).
    #[serde(default = "default_doppelganger_safe")]
    pub doppelganger_safe: bool,
}

fn default_doppelganger_safe() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeystoresResponse {
    pub data: Vec<KeystoreInfo>,
}

#[derive(Deserialize)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<String>,
    pub passwords: Vec<String>,
    #[serde(default)]
    pub slashing_protection: Option<String>,
}

impl std::fmt::Debug for ImportKeystoresRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeystoresRequest")
            .field("keystores", &self.keystores)
            .field("passwords", &format_args!("[REDACTED; {}]", self.passwords.len()))
            .field("slashing_protection", &self.slashing_protection)
            .finish()
    }
}

// --- Fee recipient types ---

#[derive(Debug, Clone, Serialize)]
pub struct FeeRecipientData {
    pub pubkey: String,
    pub ethaddress: String,
}

#[derive(Debug, Serialize)]
pub struct FeeRecipientResponse {
    pub data: FeeRecipientData,
}

#[derive(Debug, Deserialize)]
pub struct SetFeeRecipientRequest {
    pub ethaddress: String,
}

// --- Gas limit types ---

#[derive(Debug, Clone, Serialize)]
pub struct GasLimitData {
    pub pubkey: String,
    pub gas_limit: String,
}

#[derive(Debug, Serialize)]
pub struct GasLimitResponse {
    pub data: GasLimitData,
}

#[derive(Debug, Deserialize)]
pub struct SetGasLimitRequest {
    pub gas_limit: String,
}

// --- Graffiti types ---

#[derive(Debug, Clone, Serialize)]
pub struct GraffitiData {
    pub pubkey: String,
    pub graffiti: String,
}

#[derive(Debug, Serialize)]
pub struct GraffitiResponse {
    pub data: GraffitiData,
}

#[derive(Debug, Deserialize)]
pub struct SetGraffitiRequest {
    pub graffiti: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_recipient_response_serialization() {
        let resp = FeeRecipientResponse {
            data: FeeRecipientData { pubkey: "0xabc".into(), ethaddress: "0x1234".into() },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["data"]["pubkey"], "0xabc");
        assert_eq!(json["data"]["ethaddress"], "0x1234");
    }

    #[test]
    fn test_set_fee_recipient_request_deserialization() {
        let json = r#"{"ethaddress": "0xAbcF8e0d4e9587369b2301D0790347320302cc09"}"#;
        let req: SetFeeRecipientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ethaddress, "0xAbcF8e0d4e9587369b2301D0790347320302cc09");
    }

    #[test]
    fn test_gas_limit_response_serialization() {
        let resp = GasLimitResponse {
            data: GasLimitData { pubkey: "0xabc".into(), gas_limit: "30000000".into() },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["data"]["gas_limit"], "30000000");
    }

    #[test]
    fn test_set_gas_limit_request_deserialization() {
        let json = r#"{"gas_limit": "30000000"}"#;
        let req: SetGasLimitRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.gas_limit, "30000000");
    }

    #[test]
    fn test_graffiti_response_serialization() {
        let resp = GraffitiResponse {
            data: GraffitiData { pubkey: "0xabc".into(), graffiti: "hello world".into() },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["data"]["graffiti"], "hello world");
    }

    #[test]
    fn test_set_graffiti_request_deserialization() {
        let json = r#"{"graffiti": "my graffiti"}"#;
        let req: SetGraffitiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.graffiti, "my graffiti");
    }

    #[test]
    fn test_import_keystores_request_debug_redacts_passwords() {
        let req = ImportKeystoresRequest {
            keystores: vec!["ks1".into()],
            passwords: vec!["super_secret_password".into(), "another_secret".into()],
            slashing_protection: None,
        };
        let debug_output = format!("{:?}", req);
        assert!(debug_output.contains("REDACTED"), "Debug output should contain REDACTED");
        assert!(debug_output.contains("[REDACTED; 2]"), "Debug output should show password count");
        assert!(
            !debug_output.contains("super_secret_password"),
            "Debug output must NOT contain actual passwords"
        );
        assert!(
            !debug_output.contains("another_secret"),
            "Debug output must NOT contain actual passwords"
        );
    }

    #[test]
    fn test_voluntary_exit_query_deserialize_with_epoch() {
        let json = r#"{"epoch": "300000"}"#;
        let query: VoluntaryExitQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.epoch, Some("300000".to_string()));
    }

    #[test]
    fn test_voluntary_exit_query_deserialize_without_epoch() {
        let json = r#"{}"#;
        let query: VoluntaryExitQuery = serde_json::from_str(json).unwrap();
        assert!(query.epoch.is_none());
    }

    #[test]
    fn test_voluntary_exit_response_serialization() {
        let resp = VoluntaryExitResponse {
            data: eth_types::SignedVoluntaryExit {
                message: eth_types::VoluntaryExit { epoch: 300000, validator_index: 12345 },
                signature: vec![0xaa; 96],
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["data"]["message"]["epoch"], "300000");
        assert_eq!(json["data"]["message"]["validator_index"], "12345");
        assert!(json["data"]["signature"].as_str().unwrap().starts_with("0x"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeystoreResult {
    pub status: ImportStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeystoresResponse {
    pub data: Vec<ImportKeystoreResult>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteKeystoresRequest {
    pub pubkeys: Vec<String>,
}

/// Per-key result of `DELETE /eth/v1/keystores`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteStatus {
    /// This call removed a loaded key, an on-disk keystore, or the validators row.
    Deleted,
    /// No local keystore remains and the key is not remote-registered, but
    /// slashing history was exported under the node's genesis validators root.
    NotActive,
    /// No keystore is loaded or on disk, and there is no slashing history.
    ///
    /// The interchange still carries an empty record under the node's genesis
    /// validators root.
    NotFound,
    /// The delete did not finish, or the pubkey is only a remote key.
    ///
    /// A remote-only pubkey is refused before `on_delete`: nothing is
    /// denylisted, no enable token is cancelled, and the key is not exported.
    /// Delete it through `DELETE /eth/v1/remotekeys`. A partial failure is
    /// `error`, never `deleted`.
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteKeystoreResult {
    pub status: DeleteStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteKeystoresResponse {
    pub data: Vec<DeleteKeystoreResult>,
    pub slashing_protection: String,
}

// --- Remote key types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteKeyEntry {
    pub pubkey: String,
    pub url: String,
    pub readonly: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRemoteKeysResponse {
    pub data: Vec<RemoteKeyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RemoteKeyImport {
    pub pubkey: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportRemoteKeysRequest {
    pub remote_keys: Vec<RemoteKeyImport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImportRemoteKeyStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRemoteKeyResult {
    pub status: ImportRemoteKeyStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRemoteKeysResponse {
    pub data: Vec<ImportRemoteKeyResult>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRemoteKeysRequest {
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRemoteKeyStatus {
    Deleted,
    NotFound,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRemoteKeyResult {
    pub status: DeleteRemoteKeyStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRemoteKeysResponse {
    pub data: Vec<DeleteRemoteKeyResult>,
}

// --- Voluntary Exit ---

#[derive(Debug, Deserialize)]
pub struct VoluntaryExitQuery {
    pub epoch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoluntaryExitResponse {
    pub data: eth_types::SignedVoluntaryExit,
}
