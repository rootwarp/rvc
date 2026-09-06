//! Bootstrap phase: load signing keys (keystore-dir, secret providers, gRPC).
//!
//! Extracted from `bin/rvc` startup so ownership is linear (no
//! `Arc::try_unwrap` dances) and denylist / gRPC behavior can be unit-tested
//! without spawning the binary.

use std::collections::HashSet;
use std::sync::Arc;

use crypto::{CompositeSigner, KeyManager, LocalSigner};
use grpc_signer::{GrpcRemoteSigner, GrpcRemoteSignerConfig};
use secret_provider::SecretProvider;
use tracing::{info, warn};

use super::BootstrapError;
use crate::config::{redact_url, Config, ServiceBuilder};
use crate::deletion_denylist::DeletionDenylist;
use crate::orchestrator::PubkeyMap;

/// Handles produced by [`load_signing_keys`].
///
/// Held as locals by the binary composition root until a future `run()` moves
/// them into [`super::BootstrapCtx`].
pub struct LoadedKeys {
    /// Shared composite signer (local keystore/provider keys + optional gRPC).
    pub composite_signer: Arc<CompositeSigner>,
    /// Keystore-dir key count after denylist filter (health metric; excludes
    /// secret-provider and gRPC remote keys — matches prior `run_validator`).
    pub validator_count: usize,
    /// Local (keystore-dir + secret-provider) public keys as raw 48-byte sets.
    /// Used by secret-provider refresh as the “already known” set.
    pub local_pubkeys: HashSet<[u8; 48]>,
    /// Hex-keyed pubkey map for enablement, duties, and keymanager adapters.
    pub pubkey_map: PubkeyMap,
    /// Configured secret providers (may be empty). Retained for refresh wiring.
    pub secret_providers: Vec<Arc<dyn SecretProvider>>,
    /// Connected gRPC remote signer when configured and connect succeeded.
    /// Connect failure is non-fatal: `None` with a warn log (lazy retry path).
    pub grpc_signer: Option<Arc<GrpcRemoteSigner>>,
}

/// Load local keys (keystore-dir + secret providers), build one
/// [`CompositeSigner`] by value, and optionally connect a gRPC remote signer.
///
/// `denylist` skips Keymanager-deleted pubkeys for both keystore-dir and
/// secret-provider sources (SEC-1b). Health-status updates remain the caller's
/// responsibility (see module docs on [`super`]).
///
/// Log lines and order match the former inline `run_validator` key-load block.
pub async fn load_signing_keys(
    config: &Config,
    denylist: &DeletionDenylist,
) -> Result<LoadedKeys, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());
    let denylist_snapshot = denylist.snapshot();

    // Keystore-dir load (non-fatal on failure: continue with empty manager).
    let mut key_manager = match builder.build_key_manager_owned_filtered(Some(&denylist_snapshot)) {
        Ok(km) => {
            let validator_count = km.len();
            info!(count = validator_count, "Loaded validator keys");
            km
        }
        Err(e) => {
            warn!("Failed to load keys, continuing without validators: {}", e);
            KeyManager::new()
        }
    };
    let validator_count = key_manager.len();

    // Initialize secret provider metrics eagerly so they appear in /metrics
    // output before any provider call.
    secret_provider::metrics::init_secret_provider_metrics();

    // Load keys from cloud secret providers (if configured), consulting denylist.
    let secret_providers: Vec<Arc<dyn SecretProvider>> =
        builder.build_secret_providers().await?.into_iter().map(Arc::from).collect();
    if !secret_providers.is_empty() {
        let ksm = secret_provider::KeySourceManager::from_arc(secret_providers.clone())
            .with_strict(config.secret_provider.strict);
        let summary = ksm
            .load_all_except(&mut key_manager, Some(&denylist_snapshot))
            .await
            .map_err(|e| crate::config::ConfigError::SecretProviderError(e.to_string()))?;
        let mut total_loaded = 0usize;
        let mut total_skipped = 0usize;
        let mut total_errors = 0usize;
        for ps in &summary.per_provider {
            info!(
                provider = %ps.name,
                loaded = ps.loaded,
                skipped = ps.skipped,
                "Loaded keys from cloud provider"
            );
            total_loaded += ps.loaded;
            total_skipped += ps.skipped;
            total_errors += ps.errors.len();
        }
        info!(
            loaded = total_loaded,
            providers = summary.per_provider.len(),
            skipped = total_skipped,
            errors = total_errors,
            "Loaded keys from cloud providers"
        );
    }

    let pubkey_map = builder.build_pubkey_map(&key_manager);
    let local_pubkeys: HashSet<[u8; 48]> =
        key_manager.list_public_keys().iter().map(|pk| pk.to_bytes()).collect();

    // Owned KeyManager → LocalSigner → CompositeSigner (no Arc::try_unwrap).
    let local_signer = LocalSigner::new(key_manager);
    let composite_signer = Arc::new(CompositeSigner::new(local_signer));

    // Connect gRPC remote signer if configured (non-fatal: lazy connection).
    let grpc_signer = connect_grpc_remote_signer(config, &composite_signer).await?;

    Ok(LoadedKeys {
        composite_signer,
        validator_count,
        local_pubkeys,
        pubkey_map,
        secret_providers,
        grpc_signer,
    })
}

/// Configure and connect the gRPC remote signer; register its keys on success.
///
/// Connect failure logs a warning and returns `Ok(None)` — same as prior
/// `run_validator` behavior. TLS material read failures are fatal.
async fn connect_grpc_remote_signer(
    config: &Config,
    composite_signer: &CompositeSigner,
) -> Result<Option<Arc<GrpcRemoteSigner>>, BootstrapError> {
    let Some(ref grpc_url) = config.grpc_signer.url else {
        return Ok(None);
    };

    info!(url = %redact_url(grpc_url), "Configuring gRPC remote signer");

    let mut grpc_config = GrpcRemoteSignerConfig::new(grpc_url.clone());

    if let (Some(ref cert_path), Some(ref key_path), Some(ref ca_path)) =
        (&config.grpc_signer.tls_cert, &config.grpc_signer.tls_key, &config.grpc_signer.tls_ca_cert)
    {
        let cert = std::fs::read(cert_path).map_err(|e| {
            crate::config::ConfigError::PasswordReadError(format!(
                "failed to read gRPC signer TLS cert: {e}"
            ))
        })?;
        let key = std::fs::read(key_path).map_err(|e| {
            crate::config::ConfigError::PasswordReadError(format!(
                "failed to read gRPC signer TLS key: {e}"
            ))
        })?;
        let ca_cert = std::fs::read(ca_path).map_err(|e| {
            crate::config::ConfigError::PasswordReadError(format!(
                "failed to read gRPC signer TLS CA cert: {e}"
            ))
        })?;
        grpc_config = grpc_config.with_tls(cert, key, ca_cert);
    }

    // Log the v2 gRPC contract version and validate the signer is running v2.
    info!("signer contract: v2 (typed RPCs)");

    match GrpcRemoteSigner::connect(grpc_config).await {
        Ok(signer) => {
            let key_count = signer.public_keys().len();
            info!(
                url = %redact_url(grpc_url),
                key_count,
                "gRPC remote signer connected (v2 typed RPCs)"
            );

            let pubkeys = signer.public_keys();
            let signer = Arc::new(signer);
            composite_signer.add_grpc_remote_signer(pubkeys, signer.clone());
            Ok(Some(signer))
        }
        Err(e) => {
            warn!(
                url = %redact_url(grpc_url),
                error = %e,
                "Failed to connect to gRPC remote signer; will retry on demand"
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
// RF1-12: tests mutate env via unsafe set_var/remove_var for plaintext gRPC gate.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crypto::{EncryptionKdf, Keystore, SecretKey, Signer};
    use grpc_signer::{SignerServiceServerV2, SignerServiceV2};
    use std::io::Write;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tonic::{Request, Response, Status};

    use grpc_signer::proto::signer_v2::{
        GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
        SignAggregateAndProofRequest, SignAttestationDataRequest, SignBeaconBlockRequest,
        SignBlindedBeaconBlockRequest, SignBlockHeaderRequest, SignBuilderRegistrationRequest,
        SignContributionAndProofRequest, SignRandaoRevealRequest, SignResponse, SignRootRequest,
        SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
        SignVoluntaryExitRequest,
    };

    const PASSWORD: &str = "rf5-05-testpass";

    fn write_password_file(dir: &TempDir) -> std::path::PathBuf {
        let path = dir.path().join("password.txt");
        // Wildcard so any keystore decrypts without per-pubkey lines.
        std::fs::write(&path, format!("*={PASSWORD}\n")).unwrap();
        path
    }

    fn write_keystore(dir: &std::path::Path, sk: &SecretKey) -> [u8; 48] {
        let keystore = Keystore::encrypt(
            sk,
            PASSWORD.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt keystore");
        let json = serde_json::to_string(&keystore).expect("serialize keystore");
        let pk = sk.public_key().to_bytes();
        let filename = format!("keystore-0x{}.json", hex::encode(pk));
        std::fs::write(dir.join(filename), json).unwrap();
        pk
    }

    fn base_config(keystore_path: std::path::PathBuf, password_file: std::path::PathBuf) -> Config {
        Config {
            keystore_path,
            password_file: Some(password_file),
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_load_signing_keys_returns_owned_composite_signer_without_try_unwrap() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        // Empty keystore dir → NoKeystoreFiles → non-fatal empty manager.
        let password_file = write_password_file(&dir);
        let config = base_config(ks_dir, password_file);
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));

        let loaded = load_signing_keys(&config, &denylist)
            .await
            .expect("empty keystore continues with zero validators");

        assert_eq!(loaded.validator_count, 0);
        assert!(loaded.local_pubkeys.is_empty());
        assert!(loaded.grpc_signer.is_none());
        assert!(loaded.secret_providers.is_empty());
        // CompositeSigner is usable Arc without any try_unwrap in this phase.
        assert_eq!(Signer::public_keys(loaded.composite_signer.as_ref()).len(), 0);
        assert_eq!(Arc::strong_count(&loaded.composite_signer), 1);
    }

    #[tokio::test]
    async fn test_load_signing_keys_skips_denylisted_pubkeys() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        let password_file = write_password_file(&dir);

        let kept = SecretKey::generate();
        let denied = SecretKey::generate();
        let kept_pk = write_keystore(&ks_dir, &kept);
        let denied_pk = write_keystore(&ks_dir, &denied);

        let denylist_path = dir.path().join(".rvc.deleted_keys");
        {
            let mut f = std::fs::File::create(&denylist_path).unwrap();
            writeln!(f, "0x{}", hex::encode(denied_pk)).unwrap();
        }
        let denylist = DeletionDenylist::load(dir.path()).expect("load denylist");
        assert!(denylist.contains(&denied_pk));

        let config = base_config(ks_dir, password_file);
        let loaded = load_signing_keys(&config, &denylist).await.expect("load keys");

        assert_eq!(loaded.validator_count, 1);
        assert!(loaded.local_pubkeys.contains(&kept_pk));
        assert!(!loaded.local_pubkeys.contains(&denied_pk));
        assert!(loaded.composite_signer.has_local_key(&kept_pk));
        assert!(!loaded.composite_signer.has_local_key(&denied_pk));
    }

    #[tokio::test]
    async fn test_load_signing_keys_initializes_secret_provider_metrics_eagerly() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        let password_file = write_password_file(&dir);
        let config = base_config(ks_dir, password_file);
        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));

        let _ = load_signing_keys(&config, &denylist).await.expect("load");

        // Phase calls init_secret_provider_metrics() before any provider load.
        // Touch each family so Prometheus materializes series for gather().
        secret_provider::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED
            .with_label_values(&["rf5_05_probe"])
            .set(0.0);
        secret_provider::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["rf5_05_probe", "provider"])
            .inc();
        secret_provider::metrics::RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["rf5_05_probe"])
            .observe(0.0);

        let gathered = metrics::REGISTRY.gather();
        let names: Vec<&str> = gathered.iter().map(|m| m.name()).collect();
        assert!(
            names.contains(&"rvc_secret_provider_keys_loaded"),
            "secret-provider series missing after load_signing_keys: {names:?}"
        );
        assert!(
            names.contains(&"rvc_secret_provider_errors_total"),
            "errors_total missing: {names:?}"
        );
        assert!(
            names.contains(&"rvc_secret_provider_load_duration_seconds"),
            "load_duration missing: {names:?}"
        );
    }

    #[tokio::test]
    async fn test_load_signing_keys_grpc_connect_failure_is_non_fatal() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        let password_file = write_password_file(&dir);

        // Bound-then-closed port → connection refused.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut config = base_config(ks_dir, password_file);
        config.grpc_signer.url = Some(format!("http://{addr}"));

        // Plaintext http requires the insecure env gate (Refuse mode).
        // SAFETY: test-only env mutation for the plaintext gRPC gate.
        unsafe {
            std::env::set_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
        }

        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        let loaded = load_signing_keys(&config, &denylist)
            .await
            .expect("gRPC connect failure must be non-fatal");

        assert!(loaded.grpc_signer.is_none());
        assert_eq!(loaded.validator_count, 0);

        // SAFETY: restore env after test.
        unsafe {
            std::env::remove_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR);
        }
    }

    // ── Minimal v2 mock for connect + ListPublicKeys ────────────────────────

    struct MockV2Signer {
        pubkeys: Vec<[u8; 48]>,
    }

    #[tonic::async_trait]
    impl SignerServiceV2 for MockV2Signer {
        async fn list_public_keys(
            &self,
            _request: Request<ListPublicKeysRequest>,
        ) -> Result<Response<ListPublicKeysResponse>, Status> {
            Ok(Response::new(ListPublicKeysResponse {
                pubkeys: self.pubkeys.iter().map(|p| p.to_vec()).collect(),
            }))
        }

        async fn get_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            Ok(Response::new(GetStatusResponse {
                ready: true,
                backend: "rf5-05-mock".into(),
                key_count: self.pubkeys.len() as u32,
            }))
        }

        async fn sign_beacon_block(
            &self,
            _: Request<SignBeaconBlockRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_blinded_beacon_block(
            &self,
            _: Request<SignBlindedBeaconBlockRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_attestation_data(
            &self,
            _: Request<SignAttestationDataRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_aggregate_and_proof(
            &self,
            _: Request<SignAggregateAndProofRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_randao_reveal(
            &self,
            _: Request<SignRandaoRevealRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_sync_committee_message(
            &self,
            _: Request<SignSyncCommitteeMessageRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_sync_aggregator_selection_data(
            &self,
            _: Request<SignSyncAggregatorSelectionDataRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_contribution_and_proof(
            &self,
            _: Request<SignContributionAndProofRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_builder_registration(
            &self,
            _: Request<SignBuilderRegistrationRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_voluntary_exit(
            &self,
            _: Request<SignVoluntaryExitRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_block_header(
            &self,
            _: Request<SignBlockHeaderRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_root(
            &self,
            _: Request<SignRootRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
    }

    async fn start_plaintext_mock(
        pubkeys: Vec<[u8; 48]>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(SignerServiceServerV2::new(MockV2Signer { pubkeys }))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, handle)
    }

    #[tokio::test]
    async fn test_load_signing_keys_registers_remote_signer_keys_in_composite() {
        let remote_sk = SecretKey::generate();
        let remote_pk = remote_sk.public_key().to_bytes();
        let (addr, _handle) = start_plaintext_mock(vec![remote_pk]).await;

        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keys");
        std::fs::create_dir_all(&ks_dir).unwrap();
        let password_file = write_password_file(&dir);

        let mut config = base_config(ks_dir, password_file);
        config.grpc_signer.url = Some(format!("http://{addr}"));

        // SAFETY: test-only env mutation for the plaintext gRPC gate.
        unsafe {
            std::env::set_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
        }

        let denylist = DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys"));
        let loaded =
            load_signing_keys(&config, &denylist).await.expect("connect to mock gRPC signer");

        assert!(loaded.grpc_signer.is_some());
        assert!(
            loaded.composite_signer.has_grpc_remote(&remote_pk),
            "remote pubkey must be registered on CompositeSigner"
        );
        // Local keystore was empty; remote keys are not in local_pubkeys.
        assert!(!loaded.local_pubkeys.contains(&remote_pk));

        // SAFETY: restore env after test.
        unsafe {
            std::env::remove_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR);
        }
    }
}
