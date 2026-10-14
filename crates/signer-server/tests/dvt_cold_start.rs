//! Three in-process DVT nodes start from stopped and complete a threshold signature.
//!
//! The public `Sign` RPC cannot carry a typed duty into `DvtSigner` (peer dials
//! require `sign_with_duty`). The harness serves all three nodes, then combines
//! share 1 locally with partials from the other two live `PeerSignerService`s.

#![cfg(feature = "dvt")]
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use signer_server::backend::dvt::{DvtSigner, PartialSignDuty, PeerRequester};
use signer_server::commands::split_key::{execute, SplitKeyArgs};
use signer_server::config::{Backend, HttpTlsMode, ResolvedConfig};
use signer_server::dvt::peer_client::{GrpcPeerRequester, PeerConnectInfo};
use signer_server::dvt::types::load_shares;
use signer_server::metrics::SignerMetrics;
use signer_server::proto::signer_v2::peer_signer_service_server::{
    PeerSignerService, PeerSignerServiceServer,
};
use signer_server::proto::signer_v2::{
    ForkInfo, PartialSignAttestationDataRequest, PartialSignBeaconBlockRequest,
    PartialSignBlockHeaderRequest, PartialSignPayloadAttestationRequest, PartialSignResponse,
    PartialSignRootRequest, PartialSignSyncCommitteeRequest,
};
use signer_server::server::run;
use signer_server::ServerError;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const SHARE_PASSWORD: &str = "share-pw";

fn allow_insecure() {
    unsafe {
        std::env::set_var("RVC_SIGNER_ALLOW_INSECURE", "true");
        std::env::set_var("RVC_ALLOW_INSECURE", "true");
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    listener.local_addr().expect("local_addr").port()
}

fn peer_ready_sample(metrics: &SignerMetrics, peer: &str) -> Option<i64> {
    let text = String::from_utf8(metrics.encode().expect("encode metrics")).expect("utf8");
    let key = format!("peer=\"{peer}\"");
    text.lines().find_map(|line| {
        if line.starts_with("rvc_dvt_peer_ready{") && line.contains(&key) {
            line.split_whitespace().last()?.parse().ok()
        } else {
            None
        }
    })
}

struct Running {
    listen: SocketAddr,
    shutdown: CancellationToken,
    handle: JoinHandle<Result<(), ServerError>>,
}

fn node_config(
    keystore_dir: PathBuf,
    password_file: PathBuf,
    data_dir: PathBuf,
    allow_list: PathBuf,
    listen: SocketAddr,
    peers: Vec<String>,
    index: u64,
) -> ResolvedConfig {
    ResolvedConfig {
        listen_address: listen.to_string(),
        keystore_dir,
        password_file: Some(password_file),
        backend: Backend::Dvt,
        dry_run: false,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        reload_interval_secs: 0,
        enable_hot_reload: false,
        dvt_peers: peers,
        dvt_threshold: Some(2),
        dvt_index: Some(index),
        dvt_timeout_ms: 2_000,
        http_enabled: false,
        http_listen_address: format!("127.0.0.1:{}", free_port()),
        http_tls_mode: HttpTlsMode::Mtls,
        http_tls_cert: None,
        http_tls_key: None,
        http_tls_ca_cert: None,
        genesis_fork_version: eth_types::NetworkPreset::MAINNET.genesis_fork_version,
        insecure: true,
        data_dir: Some(data_dir),
        disable_slashing_protection: true,
        init_slashing_db: false,
        group_commit_batch_size: None,
        group_commit_wait_to_fill_ms: None,
        gloas_fork_epoch: u64::MAX,
        metrics_address: format!("127.0.0.1:{}", free_port()),
        enable_log_reload: false,
        allowed_client_cns: None,
        dvt_allowed_peers: Some(allow_list),
    }
}

async fn wait_serving(node: &mut Running) {
    let bound = Duration::from_secs(20);
    let listen = node.listen;
    tokio::select! {
        joined = &mut node.handle => {
            let result = joined.expect("run task panicked");
            panic!("startup exited before {listen} served: {result:?}");
        }
        () = async {
            loop {
                if tokio::net::TcpStream::connect(listen).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        } => {}
        () = tokio::time::sleep(bound) => {
            panic!("gRPC listener {listen} was not accepting within {bound:?}");
        }
    }
}

fn sync_duty(fork_version: [u8; 4], gvr: [u8; 32], beacon_block_root: [u8; 32]) -> PartialSignDuty {
    PartialSignDuty::SyncCommittee {
        fork_info: ForkInfo {
            previous_version: vec![0, 0, 0, 0],
            current_version: fork_version.to_vec(),
            epoch: 0,
            genesis_validators_root: gvr.to_vec(),
        },
        slot: 1,
        beacon_block_root: beacon_block_root.to_vec(),
        fork_id: 4,
    }
}

#[tokio::test]
async fn three_nodes_threshold_two_start_from_cold_and_sign() {
    allow_insecure();
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src-keys");
    std::fs::create_dir(&src).unwrap();
    let fixture = crypto::test_utils::create_test_keystore(&src, "src-pw", None);
    let shares_root = tmp.path().join("shares");
    execute(SplitKeyArgs {
        keystore: fixture.path.clone(),
        password: Zeroizing::new("src-pw".to_string()),
        threshold: 2,
        shares: 3,
        output_dir: shares_root.clone(),
        output_password: Zeroizing::new(SHARE_PASSWORD.to_string()),
    })
    .expect("split key");

    let password = Zeroizing::new(SHARE_PASSWORD.to_string());
    let share_dirs: Vec<PathBuf> =
        (1..=3).map(|i| shares_root.join(format!("share-{i}"))).collect();
    let mut loaded: Vec<_> = share_dirs
        .iter()
        .map(|dir| {
            let mut shares = load_shares(dir, &password).expect("load share");
            assert_eq!(shares.len(), 1, "one share per node dir {}", dir.display());
            shares.pop().unwrap()
        })
        .collect();
    assert!(loaded.iter().all(|s| s.aggregate_pubkey == fixture.pubkey()));
    assert_eq!(loaded[0].threshold, 2);

    let password_file = tmp.path().join("password.txt");
    std::fs::write(&password_file, SHARE_PASSWORD).unwrap();
    let allow_list = tmp.path().join("dvt-allowed-peers.toml");
    // Insecure dials have no client cert, so every peer CN is "unknown".
    // The entry authorizes the coordinator's share index.
    std::fs::write(
        &allow_list,
        format!("[[peer]]\npeer_cn = \"unknown\"\nshare_index = {}\n", loaded[0].index),
    )
    .unwrap();

    let listens: Vec<SocketAddr> =
        (0..3).map(|_| SocketAddr::from(([127, 0, 0, 1], free_port()))).collect();
    let mut nodes = Vec::new();
    for (i, dir) in share_dirs.iter().enumerate() {
        let peers: Vec<String> = listens
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, addr)| addr.to_string())
            .collect();
        let data_dir = tmp.path().join(format!("data-{i}"));
        std::fs::create_dir(&data_dir).unwrap();
        let cfg = node_config(
            dir.clone(),
            password_file.clone(),
            data_dir,
            allow_list.clone(),
            listens[i],
            peers,
            loaded[i].index,
        );
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let handle = tokio::spawn(async move { run(cfg, token).await });
        nodes.push(Running { listen: listens[i], shutdown, handle });
    }
    for node in &mut nodes {
        wait_serving(node).await;
    }

    let fork_version = [0x01, 0x00, 0x00, 0x00];
    let gvr = [0x11; 32];
    let beacon_block_root = [0xAB; 32];
    let domain = crypto::compute_domain(eth_types::DOMAIN_SYNC_COMMITTEE, fork_version, gvr);
    let signing_root = crypto::compute_signing_root(&beacon_block_root, domain);
    let duty = sync_duty(fork_version, gvr, beacon_block_root);
    let peer_addrs: Vec<String> = listens[1..].iter().map(ToString::to_string).collect();
    let infos: Vec<PeerConnectInfo> = peer_addrs
        .iter()
        .map(|addr| PeerConnectInfo { addr: addr.clone(), sni_cn: String::new() })
        .collect();
    let requester =
        GrpcPeerRequester::connect(&infos, None, Duration::from_secs(5), Duration::from_secs(2))
            .await
            .expect("lazy connect");
    let coord = loaded.remove(0);
    let coord_index = coord.index;
    let pubkey = coord.aggregate_pubkey;
    let signer = DvtSigner::new(
        vec![coord],
        coord_index,
        peer_addrs,
        Some(Arc::new(requester) as Arc<dyn PeerRequester>),
        Duration::from_secs(5),
    );

    let started = Instant::now();
    let sig = loop {
        match signer.sign_with_duty(&signing_root, &pubkey, &duty).await {
            Ok(sig) => break sig,
            Err(err) => {
                let msg = err.to_string();
                let retryable = msg.contains("RPC failed")
                    || msg.contains("timed out")
                    || msg.contains("connect");
                if !retryable || started.elapsed() > Duration::from_secs(8) {
                    panic!("threshold signature failed: {msg}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    assert_eq!(sig, fixture.secret_key.sign(&signing_root).to_bytes());

    for node in &nodes {
        node.shutdown.cancel();
    }
    for node in nodes {
        let result = tokio::time::timeout(Duration::from_secs(5), node.handle)
            .await
            .expect("shutdown hung")
            .expect("run task panicked");
        assert!(result.is_ok(), "server failed after serving: {result:?}");
    }
}

struct StubPeer;

fn dummy_partial() -> PartialSignResponse {
    PartialSignResponse { partial_signature: vec![1u8; 96], share_index: 1 }
}

#[tonic::async_trait]
impl PeerSignerService for StubPeer {
    async fn partial_sign_beacon_block(
        &self,
        _request: tonic::Request<PartialSignBeaconBlockRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
    async fn partial_sign_attestation_data(
        &self,
        _request: tonic::Request<PartialSignAttestationDataRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
    async fn partial_sign_sync_committee(
        &self,
        _request: tonic::Request<PartialSignSyncCommitteeRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
    async fn partial_sign_payload_attestation(
        &self,
        _request: tonic::Request<PartialSignPayloadAttestationRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
    async fn partial_sign_block_header(
        &self,
        _request: tonic::Request<PartialSignBlockHeaderRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
    async fn partial_sign_root(
        &self,
        _request: tonic::Request<PartialSignRootRequest>,
    ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status> {
        Ok(tonic::Response::new(dummy_partial()))
    }
}

#[tokio::test]
async fn peer_ready_gauge_flips_zero_to_one_on_first_successful_rpc() {
    let metrics = SignerMetrics::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(PeerSignerServiceServer::new(StubPeer))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let peer = addr.to_string();
    assert!(
        peer_ready_sample(&metrics, &peer).is_none(),
        "gauge must not exist before connect_lazy"
    );
    let requester = GrpcPeerRequester::connect(
        &[PeerConnectInfo { addr: peer.clone(), sni_cn: String::new() }],
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("lazy connect");
    assert_eq!(peer_ready_sample(&metrics, &peer), Some(0));

    let duty = sync_duty([1, 0, 0, 0], [0; 32], [0xAB; 32]);
    requester.request_partial(&peer, &duty, &[0u8; 48], 1).await.expect("first rpc");
    assert_eq!(peer_ready_sample(&metrics, &peer), Some(1));
    requester.request_partial(&peer, &duty, &[0u8; 48], 1).await.expect("second rpc");
    assert_eq!(peer_ready_sample(&metrics, &peer), Some(1));
    handle.abort();
}
