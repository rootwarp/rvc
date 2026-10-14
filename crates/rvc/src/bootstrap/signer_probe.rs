//! Startup probe of HTTP remote-signer Gloas sign types.
//!
//! Web3Signer has no Gloas types through 26.7.0. The gap must surface here with
//! operator-actionable text rather than as a dropped duty at the fork. Probe
//! failures are never treated as supported. Startup is not blocked.
//!
//! In-tree `rvc-signer` resolves `{identifier}` before decoding `type`, so a
//! dummy-key 404 is not evidence the type is supported. On 404 the probe lists
//! `/api/v1/eth2/publicKeys` and re-POSTs with a loaded key.

use std::time::Duration;

use crypto::{SecretKey, SignContext};
use eth_types::{
    BuilderRequestAuth, ForkInfo, ForkName, PayloadAttestationData, ProposerPreferences,
};
use remote_signer_client::{
    build_builder_request_auth_request, build_payload_attestation_request,
    build_proposer_preferences_request, sign_request_to_json,
};
use reqwest::StatusCode;
use tracing::{error, warn};

use crate::config::{redact_url, Config};
use crate::metrics::{signer_sign_type, RVC_SIGNER_CAPABILITY};

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    Supported,
    Unsupported,
    Unknown,
}

struct ProbeResult {
    outcome: ProbeOutcome,
    error: Option<String>,
}

enum RawProbe {
    Status(StatusCode),
    Failed(String),
}

fn gloas_epoch_is_scheduled(epoch: Option<u64>) -> bool {
    matches!(epoch, Some(e) if e != u64::MAX)
}

fn http_status_error(status: StatusCode) -> String {
    format!("HTTP {}", status.as_u16())
}

fn transport_error(err: &reqwest::Error) -> String {
    // reqwest's Display includes the sign path (full pubkey).
    if err.is_timeout() {
        "timeout".to_string()
    } else {
        "transport".to_string()
    }
}

fn probe_auth_fixture() -> BuilderRequestAuth {
    BuilderRequestAuth::new(vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef], 1)
        .expect("probe fixture data is non-empty and within limit")
}

/// Probe `PAYLOAD_ATTESTATION`, `PROPOSER_PREFERENCES`, and `BUILDER_REQUEST_AUTH`
/// on the configured HTTP remote signer. No-op when no URL is set. Never fails startup.
pub(super) async fn probe_configured_remote_signer(config: &Config) {
    let Some(url) = config.keymanager.remote_signer_url.as_deref() else {
        return;
    };
    // `ForkScheduleConfig` is Gloas-only; genesis is the network preset.
    // Custom networks have no preset — fall back to mainnet bytes (same as
    // the previous hardcode) rather than failing startup.
    let genesis_fork_version = config.network.genesis_fork_version().unwrap_or([0; 4]);
    probe_signer_url(
        url,
        config.fork_schedule.gloas_fork_epoch,
        genesis_fork_version,
        PROBE_TIMEOUT,
    )
    .await;
}

async fn probe_signer_url(
    url: &str,
    gloas_fork_epoch: Option<u64>,
    genesis_fork_version: [u8; 4],
    timeout: Duration,
) {
    let gloas_scheduled = gloas_epoch_is_scheduled(gloas_fork_epoch);
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(err) => {
            let err = err.to_string();
            for sign_type in signer_sign_type::ALL {
                record_probe_result(
                    sign_type,
                    url,
                    ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(err.clone()) },
                    gloas_scheduled,
                    gloas_fork_epoch,
                );
            }
            return;
        }
    };

    let pubkey = SecretKey::generate().public_key();
    let pk_bytes = pubkey.to_bytes();
    let ctx = SignContext::new(
        pubkey,
        ForkInfo {
            previous_version: [0x06, 0x00, 0x00, 0x00],
            current_version: [0x07, 0x00, 0x00, 0x00],
            genesis_validators_root: [0u8; 32],
        },
        ForkName::Gloas,
    );
    let dummy_id = format!("0x{}", hex::encode(pk_bytes));
    let base = url.trim_end_matches('/');
    let dummy_sign_url = format!("{base}/api/v1/eth2/sign/{dummy_id}");

    let (ptc_req, _) = build_payload_attestation_request(
        &PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: false,
            blob_data_available: false,
        },
        &ctx,
    );
    let (prefs_req, _) = build_proposer_preferences_request(
        &ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 0,
            fee_recipient: [0u8; 20],
            target_gas_limit: 0,
        },
        &ctx,
    );
    let (auth_req, _) =
        build_builder_request_auth_request(&probe_auth_fixture(), genesis_fork_version);

    let ptc_body = match sign_request_to_json(&ptc_req) {
        Ok(body) => Some(body),
        Err(err) => {
            record_probe_result(
                signer_sign_type::PAYLOAD_ATTESTATION,
                url,
                ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(err.to_string()) },
                gloas_scheduled,
                gloas_fork_epoch,
            );
            None
        }
    };
    let prefs_body = match sign_request_to_json(&prefs_req) {
        Ok(body) => Some(body),
        Err(err) => {
            record_probe_result(
                signer_sign_type::PROPOSER_PREFERENCES,
                url,
                ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(err.to_string()) },
                gloas_scheduled,
                gloas_fork_epoch,
            );
            None
        }
    };
    let auth_body = match sign_request_to_json(&auth_req) {
        Ok(body) => Some(body),
        Err(err) => {
            record_probe_result(
                signer_sign_type::BUILDER_REQUEST_AUTH,
                url,
                ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(err.to_string()) },
                gloas_scheduled,
                gloas_fork_epoch,
            );
            None
        }
    };

    let (ptc_raw, prefs_raw, auth_raw) = tokio::join!(
        async {
            match &ptc_body {
                Some(body) => Some(post_sign(&client, &dummy_sign_url, body).await),
                None => None,
            }
        },
        async {
            match &prefs_body {
                Some(body) => Some(post_sign(&client, &dummy_sign_url, body).await),
                None => None,
            }
        },
        async {
            match &auth_body {
                Some(body) => Some(post_sign(&client, &dummy_sign_url, body).await),
                None => None,
            }
        },
    );

    let need_keys =
        raw_is_not_found(&ptc_raw) || raw_is_not_found(&prefs_raw) || raw_is_not_found(&auth_raw);
    let loaded_key =
        if need_keys { Some(fetch_first_public_key(&client, base).await) } else { None };

    if let (Some(raw), Some(body)) = (ptc_raw, ptc_body.as_ref()) {
        let result = resolve_probe(&client, base, raw, body, loaded_key.as_ref()).await;
        record_probe_result(
            signer_sign_type::PAYLOAD_ATTESTATION,
            url,
            result,
            gloas_scheduled,
            gloas_fork_epoch,
        );
    }
    if let (Some(raw), Some(body)) = (prefs_raw, prefs_body.as_ref()) {
        let result = resolve_probe(&client, base, raw, body, loaded_key.as_ref()).await;
        record_probe_result(
            signer_sign_type::PROPOSER_PREFERENCES,
            url,
            result,
            gloas_scheduled,
            gloas_fork_epoch,
        );
    }
    if let (Some(raw), Some(body)) = (auth_raw, auth_body.as_ref()) {
        let result = resolve_probe(&client, base, raw, body, loaded_key.as_ref()).await;
        record_probe_result(
            signer_sign_type::BUILDER_REQUEST_AUTH,
            url,
            result,
            gloas_scheduled,
            gloas_fork_epoch,
        );
    }
}

fn raw_is_not_found(raw: &Option<RawProbe>) -> bool {
    matches!(raw, Some(RawProbe::Status(status)) if *status == StatusCode::NOT_FOUND)
}

async fn post_sign(client: &reqwest::Client, sign_url: &str, body: &serde_json::Value) -> RawProbe {
    match client.post(sign_url).json(body).send().await {
        Ok(response) => RawProbe::Status(response.status()),
        Err(err) => RawProbe::Failed(transport_error(&err)),
    }
}

async fn fetch_first_public_key(
    client: &reqwest::Client,
    base: &str,
) -> Result<Option<String>, String> {
    let url = format!("{base}/api/v1/eth2/publicKeys");
    let response = client.get(&url).send().await.map_err(|err| transport_error(&err))?;
    let status = response.status();
    if !status.is_success() {
        return Err(http_status_error(status));
    }
    let keys: Vec<String> =
        response.json().await.map_err(|_| "invalid publicKeys body".to_string())?;
    Ok(keys.into_iter().find(|key| !key.is_empty()))
}

async fn resolve_probe(
    client: &reqwest::Client,
    base: &str,
    raw: RawProbe,
    body: &serde_json::Value,
    loaded_key: Option<&Result<Option<String>, String>>,
) -> ProbeResult {
    match raw {
        RawProbe::Failed(error) => {
            ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(error) }
        }
        RawProbe::Status(status) if status == StatusCode::NOT_FOUND => {
            follow_up_loaded_key(client, base, body, loaded_key).await
        }
        RawProbe::Status(status) => classify_final_status(status),
    }
}

async fn follow_up_loaded_key(
    client: &reqwest::Client,
    base: &str,
    body: &serde_json::Value,
    loaded_key: Option<&Result<Option<String>, String>>,
) -> ProbeResult {
    match loaded_key {
        Some(Err(error)) => {
            ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(error.clone()) }
        }
        Some(Ok(None)) => {
            ProbeResult { outcome: ProbeOutcome::Unknown, error: Some("no loaded keys".into()) }
        }
        None => ProbeResult { outcome: ProbeOutcome::Unknown, error: Some("HTTP 404".into()) },
        Some(Ok(Some(identifier))) => {
            let sign_url = format!("{base}/api/v1/eth2/sign/{identifier}");
            match post_sign(client, &sign_url, body).await {
                RawProbe::Failed(error) => {
                    ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(error) }
                }
                RawProbe::Status(status) => classify_final_status(status),
            }
        }
    }
}

/// Final status after a type-bearing POST (dummy non-404, or loaded-key re-POST).
///
/// 404 is never supported here: rvc-signer looks up the identifier before
/// decoding `type`, so an unloaded dummy key 404s even when the type is missing.
fn classify_final_status(status: StatusCode) -> ProbeResult {
    if status.is_success() || status == StatusCode::PRECONDITION_FAILED {
        ProbeResult { outcome: ProbeOutcome::Supported, error: None }
    } else if status == StatusCode::BAD_REQUEST
        || status == StatusCode::NOT_IMPLEMENTED
        || status == StatusCode::UNPROCESSABLE_ENTITY
    {
        ProbeResult { outcome: ProbeOutcome::Unsupported, error: None }
    } else {
        ProbeResult { outcome: ProbeOutcome::Unknown, error: Some(http_status_error(status)) }
    }
}

fn record_probe_result(
    sign_type: &'static str,
    url: &str,
    result: ProbeResult,
    gloas_scheduled: bool,
    gloas_fork_epoch: Option<u64>,
) {
    let supported = result.outcome == ProbeOutcome::Supported;
    RVC_SIGNER_CAPABILITY.with_label_values(&[sign_type]).set(i64::from(supported as u8));
    if supported {
        return;
    }

    let redacted = redact_url(url);
    match result.outcome {
        ProbeOutcome::Unsupported => {
            if gloas_scheduled {
                error!(
                    sign_type,
                    url = %redacted,
                    gloas_fork_epoch,
                    "remote signer does not support sign type {} at {}",
                    sign_type,
                    redacted
                );
            } else {
                warn!(
                    sign_type,
                    url = %redacted,
                    "remote signer does not support sign type {} at {}",
                    sign_type,
                    redacted
                );
            }
        }
        ProbeOutcome::Unknown => {
            let probe_error = result.error.as_deref().unwrap_or("unknown");
            if gloas_scheduled {
                error!(
                    sign_type,
                    url = %redacted,
                    error = probe_error,
                    gloas_fork_epoch,
                    "remote signer capability probe failed for {} at {}; treating as unsupported",
                    sign_type,
                    redacted
                );
            } else {
                warn!(
                    sign_type,
                    url = %redacted,
                    error = probe_error,
                    "remote signer capability probe failed for {} at {}; treating as unsupported",
                    sign_type,
                    redacted
                );
            }
        }
        ProbeOutcome::Supported => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::load_signing_keys;
    use crate::config::Config;
    use crate::deletion_denylist::DeletionDenylist;
    use std::sync::OnceLock;
    use tempfile::TempDir;
    use tokio::sync::{Mutex, MutexGuard};
    use wiremock::matchers::{body_string_contains, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn probe_metric_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().await
    }

    fn capability(sign_type: &str) -> i64 {
        RVC_SIGNER_CAPABILITY.with_label_values(&[sign_type]).get()
    }

    fn write_password_file(dir: &TempDir) -> std::path::PathBuf {
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "*=unused\n").unwrap();
        path
    }

    fn empty_keystore_config(
        remote_url: String,
        gloas_fork_epoch: Option<u64>,
    ) -> (Config, TempDir) {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        let password_file = write_password_file(&dir);
        let mut config = Config {
            keystore_path: ks_dir,
            password_file: Some(password_file),
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        config.keymanager.remote_signer_url = Some(remote_url);
        config.fork_schedule.gloas_fork_epoch = gloas_fork_epoch;
        (config, dir)
    }

    async fn mock_sign_status(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({"error": "rejected"})),
            )
            .mount(&server)
            .await;
        server
    }

    async fn mock_public_keys(server: &MockServer, keys: &[String]) {
        Mock::given(method("GET"))
            .and(path("/api/v1/eth2/publicKeys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(keys))
            .mount(server)
            .await;
    }

    fn loaded_pubkey_hex() -> String {
        format!("0x{}", hex::encode(SecretKey::generate().public_key().to_bytes()))
    }

    #[test]
    fn test_classify_probe_failures_are_never_supported() {
        assert_eq!(classify_final_status(StatusCode::OK).outcome, ProbeOutcome::Supported);
        assert_eq!(
            classify_final_status(StatusCode::PRECONDITION_FAILED).outcome,
            ProbeOutcome::Supported
        );
        assert_eq!(
            classify_final_status(StatusCode::BAD_REQUEST).outcome,
            ProbeOutcome::Unsupported
        );
        assert_eq!(
            classify_final_status(StatusCode::NOT_IMPLEMENTED).outcome,
            ProbeOutcome::Unsupported
        );
        assert_eq!(
            classify_final_status(StatusCode::UNPROCESSABLE_ENTITY).outcome,
            ProbeOutcome::Unsupported
        );
        let not_found = classify_final_status(StatusCode::NOT_FOUND);
        assert_eq!(not_found.outcome, ProbeOutcome::Unknown);
        assert_eq!(not_found.error.as_deref(), Some("HTTP 404"));
        let forbidden = classify_final_status(StatusCode::FORBIDDEN);
        assert_eq!(forbidden.outcome, ProbeOutcome::Unknown);
        assert_eq!(forbidden.error.as_deref(), Some("HTTP 403"));
        let internal = classify_final_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(internal.outcome, ProbeOutcome::Unknown);
        assert_eq!(internal.error.as_deref(), Some("HTTP 500"));
        assert_ne!(
            classify_final_status(StatusCode::INTERNAL_SERVER_ERROR).outcome,
            ProbeOutcome::Supported
        );
        assert_ne!(classify_final_status(StatusCode::NOT_FOUND).outcome, ProbeOutcome::Supported);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_reports_missing_ptc_type() {
        let _lock = probe_metric_lock().await;
        let cases: &[(&str, u16)] = &[
            (signer_sign_type::PAYLOAD_ATTESTATION, 400),
            (signer_sign_type::PROPOSER_PREFERENCES, 400),
            (signer_sign_type::BUILDER_REQUEST_AUTH, 400),
            (signer_sign_type::PAYLOAD_ATTESTATION, 501),
            (signer_sign_type::PROPOSER_PREFERENCES, 501),
            (signer_sign_type::BUILDER_REQUEST_AUTH, 501),
        ];

        for &(sign_type, status) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/api/v1/eth2/sign/.*"))
                .and(body_string_contains(sign_type))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"error": "unknown type"})),
                )
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/api/v1/eth2/sign/.*"))
                .respond_with(
                    ResponseTemplate::new(404)
                        .set_body_json(serde_json::json!({"error": "Key not found"})),
                )
                .mount(&server)
                .await;
            mock_public_keys(&server, &[]).await;

            let (config, dir) = empty_keystore_config(server.uri(), Some(600_000));
            let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
            let loaded = load_signing_keys(&config, &denylist)
                .await
                .expect("startup still succeeds when the signer rejects a Gloas type");
            assert!(loaded.grpc_signer.is_none());

            let redacted = redact_url(&server.uri());
            assert!(logs_contain(sign_type), "error log must name {sign_type}");
            assert!(
                logs_contain(&redacted) || logs_contain(server.uri().trim_end_matches('/')),
                "error log must name the endpoint {redacted}"
            );
            assert!(
                logs_contain("does not support sign type"),
                "type rejection must be logged as missing, not as an unknown probe failure"
            );
            assert!(logs_contain("ERROR"), "scheduled Gloas must log missing type at error");
            assert_eq!(
                capability(sign_type),
                0,
                "rejected {sign_type} (HTTP {status}) must be unsupported"
            );
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_timeout_is_unknown_unsupported() {
        let _lock = probe_metric_lock().await;

        // Transport error: bound-then-closed port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let transport_url = format!("http://{addr}");
        let (config, dir) = empty_keystore_config(transport_url.clone(), Some(600_000));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist)
            .await
            .expect("startup still succeeds on probe transport error");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
        assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 0);
        assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 0);
        assert_ne!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 1);
        assert_ne!(capability(signer_sign_type::PROPOSER_PREFERENCES), 1);
        assert_ne!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 1);

        // Timeout: delayed mock with a short probe budget.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        probe_signer_url(&server.uri(), Some(600_000), [0; 4], Duration::from_millis(50)).await;
        assert_eq!(
            capability(signer_sign_type::PAYLOAD_ATTESTATION),
            0,
            "timeout must never be reported as supported"
        );
        assert_eq!(
            capability(signer_sign_type::PROPOSER_PREFERENCES),
            0,
            "timeout must never be reported as supported"
        );
        assert_eq!(
            capability(signer_sign_type::BUILDER_REQUEST_AUTH),
            0,
            "timeout must never be reported as supported"
        );
        assert!(logs_contain("treating as unsupported"));
        assert!(logs_contain("ERROR"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_dummy_404_empty_keys_is_unknown() {
        let _lock = probe_metric_lock().await;
        let server = mock_sign_status(404).await;
        mock_public_keys(&server, &[]).await;
        let (config, dir) = empty_keystore_config(server.uri(), Some(600_000));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
        assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 0);
        assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 0);
        assert_ne!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 1);
        assert!(logs_contain("no loaded keys"));
        assert!(logs_contain("ERROR"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_loaded_key_confirms_support() {
        let _lock = probe_metric_lock().await;
        let pk = loaded_pubkey_hex();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/eth2/sign/{pk}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "Key not found"})),
            )
            .mount(&server)
            .await;
        mock_public_keys(&server, &[pk]).await;

        let (config, dir) = empty_keystore_config(server.uri(), Some(600_000));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 1);
        assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 1);
        assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 1);
        assert!(!logs_contain("does not support sign type"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_loaded_key_rejects_type() {
        let _lock = probe_metric_lock().await;
        let pk = loaded_pubkey_hex();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/eth2/sign/{pk}")))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "unknown type"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "Key not found"})),
            )
            .mount(&server)
            .await;
        mock_public_keys(&server, &[pk]).await;

        let (config, dir) = empty_keystore_config(server.uri(), Some(600_000));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
        assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 0);
        assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 0);
        assert!(logs_contain(signer_sign_type::PAYLOAD_ATTESTATION));
        assert!(logs_contain(signer_sign_type::PROPOSER_PREFERENCES));
        assert!(logs_contain(signer_sign_type::BUILDER_REQUEST_AUTH));
        assert!(logs_contain("does not support sign type"));
        assert!(logs_contain("ERROR"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_http_500_logs_status_as_unknown() {
        let _lock = probe_metric_lock().await;
        let server = mock_sign_status(500).await;
        let (config, dir) = empty_keystore_config(server.uri(), Some(600_000));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
        assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 0);
        assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 0);
        assert!(logs_contain("HTTP 500"));
        assert!(logs_contain("ERROR"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_sentinel_gloas_warns_not_errors() {
        let _lock = probe_metric_lock().await;
        for epoch in [None, Some(u64::MAX)] {
            let server = mock_sign_status(400).await;
            let (config, dir) = empty_keystore_config(server.uri(), epoch);
            let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
            load_signing_keys(&config, &denylist).await.expect("pre-Gloas startup still succeeds");
            assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
            assert_eq!(capability(signer_sign_type::PROPOSER_PREFERENCES), 0);
            assert_eq!(capability(signer_sign_type::BUILDER_REQUEST_AUTH), 0);
            assert!(logs_contain(signer_sign_type::PAYLOAD_ATTESTATION));
            assert!(logs_contain(signer_sign_type::PROPOSER_PREFERENCES));
            assert!(logs_contain(signer_sign_type::BUILDER_REQUEST_AUTH));
            assert!(
                !logs_contain("ERROR"),
                "unset / u64::MAX Gloas must not error-log, epoch={epoch:?}"
            );
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_epoch_zero_logs_error() {
        let _lock = probe_metric_lock().await;
        let server = mock_sign_status(400).await;
        let (config, dir) = empty_keystore_config(server.uri(), Some(0));
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");
        assert_eq!(capability(signer_sign_type::PAYLOAD_ATTESTATION), 0);
        assert!(logs_contain("ERROR"), "gloas_fork_epoch Some(0) is scheduled and must error");
        assert!(logs_contain(signer_sign_type::PAYLOAD_ATTESTATION));
        assert!(logs_contain(signer_sign_type::PROPOSER_PREFERENCES));
        assert!(logs_contain(signer_sign_type::BUILDER_REQUEST_AUTH));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_capability_probe_builder_request_auth_uses_configured_genesis() {
        let _lock = probe_metric_lock().await;
        let holesky = eth_types::NetworkPreset::HOLESKY.genesis_fork_version;
        let mainnet = [0u8; 4];
        let auth = probe_auth_fixture();
        let (_, holesky_root) = build_builder_request_auth_request(&auth, holesky);
        let (_, mainnet_root) = build_builder_request_auth_request(&auth, mainnet);
        assert_ne!(holesky_root, mainnet_root);

        let holesky_hex = format!("0x{}", hex::encode(holesky_root));
        let mainnet_hex = format!("0x{}", hex::encode(mainnet_root));

        let server = MockServer::start().await;
        // Genesis-mismatch 400 must not be reachable when the probe uses
        // configured network genesis (would be recorded as "type missing").
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .and(body_string_contains(&mainnet_hex))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "signingRoot mismatch"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let (mut config, dir) = empty_keystore_config(server.uri(), Some(600_000));
        config.network = crate::config::Network::Holesky;
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        load_signing_keys(&config, &denylist).await.expect("startup still succeeds");

        let requests = server.received_requests().await.expect("mock received requests");
        let auth_bodies: Vec<serde_json::Value> = requests
            .iter()
            .filter_map(|req| serde_json::from_slice::<serde_json::Value>(&req.body).ok())
            .filter(|body| body["type"] == "BUILDER_REQUEST_AUTH")
            .collect();
        assert!(!auth_bodies.is_empty(), "probe must POST BUILDER_REQUEST_AUTH");
        for body in &auth_bodies {
            assert_eq!(
                body["signingRoot"], holesky_hex,
                "Holesky genesis must be used for the request-auth signing root"
            );
            assert_ne!(
                body["signingRoot"], mainnet_hex,
                "must not send the mainnet signing root against a Holesky schedule"
            );
        }
        assert_eq!(
            capability(signer_sign_type::BUILDER_REQUEST_AUTH),
            1,
            "correct-genesis 200 is support; a mainnet-root 400 must not be treated as type missing"
        );
        assert!(!logs_contain("does not support sign type"));
    }
}
