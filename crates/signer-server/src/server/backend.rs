//! Signing-backend construction for the signer server.
//!
//! Extracted from `server::run` so basic/DVT assembly (including the once-only
//! DVT allow-list read that closes ISSUE-4.1 / L-1 TOCTOU double-read) is
//! unit-testable without binding listeners.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::backend;
use crate::config::{Backend, ResolvedConfig};
use crate::error::ServerError;
use crate::metrics::SignerMetrics;

#[cfg(feature = "dvt")]
use crate::dvt;

/// Aggregate public key → share-info map used by `PeerSignerService`.
#[cfg(feature = "dvt")]
pub(crate) type ShareMap = Arc<std::collections::HashMap<[u8; 48], dvt::types::ShareInfo>>;

/// Result of [`build_backend`].
///
/// Holds the signing backend plus the optional DVT share map / allow-list that
/// `server::run` needs later to construct `PeerSignerService` (after the
/// slashing DB is open).
pub(crate) struct BuiltBackend {
    pub signing_backend: Arc<dyn crate::backend::SigningBackend>,
    pub basic_signer: Option<Arc<crate::backend::basic::BasicSigner>>,
    #[cfg(feature = "dvt")]
    pub dvt_share_map: Option<ShareMap>,
    #[cfg(feature = "dvt")]
    pub dvt_allow_list: Option<Arc<dvt::allow_list::AllowedPeers>>,
}

/// Counting fixture for tests: number of DVT allow-list file loads performed
/// by this process since the last reset. Production builds keep the counter
/// at zero (cfg-gated out).
#[cfg(all(test, feature = "dvt"))]
pub(crate) static ALLOW_LIST_LOAD_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Load the DVT allow-list from `path` (single call site in [`build_backend`]).
#[cfg(feature = "dvt")]
fn load_dvt_allow_list(
    path: &std::path::Path,
) -> Result<Arc<dvt::allow_list::AllowedPeers>, ServerError> {
    #[cfg(all(test, feature = "dvt"))]
    ALLOW_LIST_LOAD_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let al = dvt::allow_list::AllowedPeers::load_from_path(path)
        .map_err(|e| ServerError::config(format!("failed to load DVT allow-list: {e}")))?;
    tracing::info!(
        path = %path.display(),
        peer_count = al.peers.len(),
        "Loaded DVT allow-list"
    );
    Ok(Arc::new(al))
}

/// Build the signing backend (basic or DVT) and optional DVT side products.
///
/// The DVT allow-list is loaded **exactly once** here and returned for reuse by
/// the peer service (ISSUE-4.1 / L-1). `build_dvt_backend` receives the same
/// `Arc` for client-side SNI derivation.
pub(crate) async fn build_backend(
    resolved: &ResolvedConfig,
    metrics: &SignerMetrics,
    password: &Zeroizing<String>,
    tls_config: Option<&crate::grpc_tls::TlsConfig>,
) -> Result<BuiltBackend, ServerError> {
    // The allow-list is loaded ONCE here (DVT arm only) and shared between the
    // client-side SNI derivation (build_dvt_backend) and the server-side
    // PeerSignerService (constructed by the caller).  This avoids a TOCTOU
    // double-read and ensures both paths see the same allow-list snapshot
    // (ISSUE-4.1 / L-1).
    match resolved.backend {
        Backend::Basic => {
            let _ = (metrics, tls_config);
            let signer = Arc::new(
                backend::basic::BasicSigner::load(&resolved.keystore_dir, password)
                    .map_err(|e| ServerError::backend(e.to_string()))?,
            );
            Ok(BuiltBackend {
                signing_backend: Arc::clone(&signer) as Arc<dyn crate::backend::SigningBackend>,
                basic_signer: Some(signer),
                #[cfg(feature = "dvt")]
                dvt_share_map: None,
                #[cfg(feature = "dvt")]
                dvt_allow_list: None,
            })
        }
        #[cfg(feature = "dvt")]
        Backend::Dvt => {
            let allow_list: Option<Arc<dvt::allow_list::AllowedPeers>> =
                if let Some(path) = resolved.dvt_allowed_peers.as_deref() {
                    Some(load_dvt_allow_list(path)?)
                } else {
                    None
                };

            let (backend, share_map) = build_dvt_backend(
                resolved,
                password,
                tls_config,
                Arc::new(metrics.dvt.clone()),
                allow_list.clone(),
            )
            .await?;

            Ok(BuiltBackend {
                signing_backend: backend,
                basic_signer: None,
                dvt_share_map: Some(share_map),
                dvt_allow_list: allow_list,
            })
        }
    }
}

/// Returns the DVT signing backend AND the share map (for `PeerSignerService`).
/// The share map is returned separately so the caller can build `PeerSignerServiceImpl`
/// AFTER the slashing DB is opened (allowing CN-scoped slashing for DVT peers).
///
/// `allow_list`: the pre-loaded allow-list (hoisted from `run_serve` to avoid a
/// double file-read).  When TLS is enabled, `build_peer_connect_infos` requires
/// this to be `Some` and every `dvt_peers` address to have a matching entry —
/// any gap is a startup error (ISSUE-4.1 / L-1: no silent SNI bypass).
#[cfg(feature = "dvt")]
pub(crate) async fn build_dvt_backend(
    resolved: &ResolvedConfig,
    password: &Zeroizing<String>,
    tls_config: Option<&crate::grpc_tls::TlsConfig>,
    dvt_metrics: Arc<crate::metrics::DvtMetrics>,
    allow_list: Option<Arc<crate::dvt::allow_list::AllowedPeers>>,
) -> Result<(Arc<dyn crate::backend::SigningBackend>, ShareMap), ServerError> {
    use std::collections::HashMap;
    use std::time::Duration;

    let dvt_index = resolved
        .dvt_index
        .ok_or_else(|| ServerError::config("dvt_index is required when using backend dvt"))?;

    let timeout = Duration::from_millis(resolved.dvt_timeout_ms);

    let shares = dvt::types::load_shares(&resolved.keystore_dir, password)
        .map_err(|e| ServerError::backend(format!("failed to load DVT shares: {e}")))?;

    if shares.is_empty() {
        return Err(ServerError::backend("no DVT shares found in keystore directory"));
    }

    tracing::info!(
        share_count = shares.len(),
        dvt_index,
        peer_count = resolved.dvt_peers.len(),
        "Loaded DVT shares"
    );

    let share_map: HashMap<[u8; 48], dvt::types::ShareInfo> =
        shares.iter().map(|s| (s.aggregate_pubkey, s.clone())).collect();
    let share_map = Arc::new(share_map);

    // ── L-1 SNI pinning: build per-peer connection info ──────────────────────
    //
    // `build_peer_connect_infos` enforces a hard invariant: when TLS is active,
    // every dvt_peers address must have a matching `addr=` entry in the
    // allow-list.  Missing entries are startup errors — there is no silent
    // fallback to un-pinned TLS (ISSUE-4.1 / L-1 review fix).
    let peer_infos: Vec<dvt::peer_client::PeerConnectInfo> =
        dvt::peer_client::build_peer_connect_infos(
            &resolved.dvt_peers,
            allow_list.as_deref(),
            tls_config.is_some(),
        )
        .map_err(|e| ServerError::config(format!("DVT peer SNI configuration error: {e}")))?;

    let peer_requester = if !peer_infos.is_empty() {
        let requester =
            dvt::peer_client::GrpcPeerRequester::connect(&peer_infos, tls_config, timeout)
                .await
                .map_err(|e| {
                    ServerError::backend(format!("failed to connect to DVT peers: {e}"))
                })?;

        tracing::info!(peers = ?requester.peer_addrs(), "Connected to DVT peers");
        Some(Arc::new(requester) as Arc<dyn backend::dvt::PeerRequester>)
    } else {
        tracing::info!("No DVT peers configured; running in standalone mode");
        None
    };

    let dvt_signer = backend::dvt::DvtSigner::new(
        shares,
        dvt_index,
        resolved.dvt_peers.clone(),
        peer_requester,
        timeout,
    )
    .with_metrics(dvt_metrics);

    Ok((Arc::new(dvt_signer), share_map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, HttpTlsMode, ResolvedConfig};
    use crate::metrics::SignerMetrics;
    use tempfile::TempDir;

    fn create_keystore(dir: &std::path::Path, password: &str) {
        use crypto::{EncryptionKdf, Keystore, SecretKey};
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let ks = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let filename = format!("{}.json", hex::encode(pubkey));
        std::fs::write(dir.join(filename), ks.to_json().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn base_resolved(tmp: &TempDir) -> (ResolvedConfig, Zeroizing<String>) {
        let keystore_dir = tmp.path().join("keystores");
        std::fs::create_dir(&keystore_dir).unwrap();
        let password = "test-password";
        create_keystore(&keystore_dir, password);
        let password_file = tmp.path().join("password.txt");
        std::fs::write(&password_file, password).unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();

        let resolved = ResolvedConfig {
            listen_address: "127.0.0.1:0".to_string(),
            keystore_dir,
            password_file: Some(password_file),
            backend: Backend::Basic,
            dry_run: false,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            reload_interval_secs: 0,
            enable_hot_reload: false,
            dvt_peers: vec![],
            dvt_threshold: None,
            dvt_index: None,
            dvt_timeout_ms: 2000,
            http_enabled: false,
            http_listen_address: "127.0.0.1:9000".to_string(),
            http_tls_mode: HttpTlsMode::Mtls,
            http_tls_cert: None,
            http_tls_key: None,
            http_tls_ca_cert: None,
            genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
            insecure: true,
            data_dir: Some(data_dir),
            disable_slashing_protection: false,
            init_slashing_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            gloas_fork_epoch: u64::MAX,
            metrics_address: "127.0.0.1:0".to_string(),
            enable_log_reload: false,
            allowed_client_cns: None,
            #[cfg(feature = "dvt")]
            dvt_allowed_peers: None,
        };
        (resolved, Zeroizing::new(password.to_string()))
    }

    #[tokio::test]
    async fn test_build_backend_basic_loads_keys() {
        let tmp = TempDir::new().unwrap();
        let (resolved, password) = base_resolved(&tmp);
        let metrics = SignerMetrics::new();

        let built =
            build_backend(&resolved, &metrics, &password, None).await.expect("basic backend");
        assert_eq!(built.signing_backend.public_keys().len(), 1);
        assert!(built.basic_signer.is_some());
        #[cfg(feature = "dvt")]
        {
            assert!(built.dvt_share_map.is_none());
            assert!(built.dvt_allow_list.is_none());
        }
    }

    #[cfg(feature = "dvt")]
    fn create_share_keystore(
        dir: &std::path::Path,
        sk: &crypto::SecretKey,
        password: &str,
        index: u64,
        threshold: u64,
        total: u64,
    ) {
        use crypto::{EncryptionKdf, Keystore};
        let mut keystore =
            Keystore::encrypt(sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
        keystore.description = Some("shamir-share".to_string());
        keystore.pubkey = Some(hex::encode(sk.public_key().to_bytes()));
        let json = keystore.to_json().unwrap();
        std::fs::write(dir.join(format!("share-{index}.json")), json).unwrap();
        let meta = serde_json::json!({
            "threshold": threshold,
            "total": total,
            "index": index,
        });
        std::fs::write(dir.join("share-meta.json"), meta.to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// DVT allow-list file is read exactly once per `build_backend` call.
    #[cfg(feature = "dvt")]
    #[tokio::test]
    async fn test_build_backend_reads_allow_list_exactly_once() {
        let tmp = TempDir::new().unwrap();
        let (mut resolved, password) = base_resolved(&tmp);

        // Replace the basic keystore with a DVT share.
        std::fs::remove_dir_all(&resolved.keystore_dir).unwrap();
        std::fs::create_dir(&resolved.keystore_dir).unwrap();
        let sk = crypto::SecretKey::generate();
        create_share_keystore(&resolved.keystore_dir, &sk, password.as_str(), 1, 2, 3);

        let allow_path = tmp.path().join("dvt-allowed-peers.toml");
        std::fs::write(
            &allow_path,
            r#"
[[peer]]
peer_cn = "peer-a.cluster.local"
share_index = 1
"#,
        )
        .unwrap();

        resolved.backend = Backend::Dvt;
        resolved.dvt_index = Some(1);
        resolved.dvt_allowed_peers = Some(allow_path);
        // No dvt_peers → standalone mode (no network).

        ALLOW_LIST_LOAD_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let metrics = SignerMetrics::new();
        let built = build_backend(&resolved, &metrics, &password, None).await.expect("dvt backend");

        assert_eq!(
            ALLOW_LIST_LOAD_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "allow-list must be read exactly once"
        );
        assert!(built.dvt_allow_list.is_some());
        assert!(built.dvt_share_map.is_some());
        assert!(built.basic_signer.is_none());

        // After the single load, deleting the file must not break the returned Arc.
        std::fs::remove_file(resolved.dvt_allowed_peers.as_ref().unwrap()).unwrap();
        let al = built.dvt_allow_list.as_ref().unwrap();
        assert!(al.lookup_by_cn("peer-a.cluster.local").is_some());
    }

    /// The allow-list Arc from `build_backend` is the same one the peer service
    /// would use (no second load).
    #[cfg(feature = "dvt")]
    #[tokio::test]
    async fn test_build_dvt_backend_shares_allow_list_with_peer_service() {
        let tmp = TempDir::new().unwrap();
        let (mut resolved, password) = base_resolved(&tmp);

        std::fs::remove_dir_all(&resolved.keystore_dir).unwrap();
        std::fs::create_dir(&resolved.keystore_dir).unwrap();
        let sk = crypto::SecretKey::generate();
        create_share_keystore(&resolved.keystore_dir, &sk, password.as_str(), 1, 2, 3);

        let allow_path = tmp.path().join("dvt-allowed-peers.toml");
        std::fs::write(
            &allow_path,
            r#"
[[peer]]
peer_cn = "peer-a.cluster.local"
share_index = 1
"#,
        )
        .unwrap();

        resolved.backend = Backend::Dvt;
        resolved.dvt_index = Some(1);
        resolved.dvt_allowed_peers = Some(allow_path);

        ALLOW_LIST_LOAD_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let metrics = SignerMetrics::new();
        let built = build_backend(&resolved, &metrics, &password, None).await.expect("dvt backend");

        let allow_list = built.dvt_allow_list.clone().expect("allow-list required");
        let share_map = built.dvt_share_map.clone().expect("share map required");

        // Construct peer service the same way `server::run` does — with the
        // hoisted Arc, not a second load.
        let peer_svc =
            dvt::peer_service::PeerSignerServiceImpl::new(share_map, allow_list.clone(), None);

        // Still only one load from build_backend; peer service did not re-read.
        assert_eq!(ALLOW_LIST_LOAD_COUNT.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Same Arc identity as returned by build_backend.
        assert!(Arc::ptr_eq(&allow_list, built.dvt_allow_list.as_ref().unwrap()));
        // Peer service is usable (smoke: type constructed).
        let _ = peer_svc;
    }
}
