//! Voluntary-exit signing adapter for the Keymanager API.

use std::sync::Arc;

use async_trait::async_trait;
use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use eth_types::{
    ForkSchedule, Root, SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH, SLOT_DURATION_MS,
};
use keymanager_api::error::ApiError;
use keymanager_api::traits::{Pubkey, VoluntaryExitManager};
use signer::{SignerService, ValidatorSigner};
use tracing::info;

use super::notifier::pubkey_hex;

pub struct VoluntaryExitManagerAdapter {
    beacon: Arc<dyn BeaconNodeClient>,
    signer: Arc<SignerService>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
}

impl VoluntaryExitManagerAdapter {
    pub fn new(
        beacon: Arc<dyn BeaconNodeClient>,
        signer: Arc<SignerService>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { beacon, signer, fork_schedule, genesis_validators_root }
    }
}

#[async_trait]
impl VoluntaryExitManager for VoluntaryExitManagerAdapter {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError> {
        let pubkey_hex = pubkey_hex(pubkey);

        // Resolve validator index from the beacon-node pool.
        let validators_response = self
            .beacon
            .get_validators(std::slice::from_ref(&pubkey_hex))
            .await
            .map_err(|e| ApiError::Internal(format!("beacon node error: {e}")))?;

        let validator = validators_response
            .data
            .iter()
            .find(|v| beacon::hex_ids_equal(&v.validator.pubkey, &pubkey_hex))
            .ok_or_else(|| {
                ApiError::NotFound(format!("validator {pubkey_hex} not found on beacon node"))
            })?;

        let validator_index: u64 = validator
            .index
            .parse()
            .map_err(|e| ApiError::Internal(format!("failed to parse validator index: {e}")))?;

        // Determine epoch
        let epoch = match epoch {
            Some(e) => e,
            None => {
                let expected_root = format!("0x{}", hex::encode(self.genesis_validators_root));
                // A 200 whose validators root is not ours is not this chain's clock.
                let genesis = self
                    .beacon
                    .get_genesis_matching_validators_root(&expected_root)
                    .await
                    .map_err(|e| ApiError::Internal(format!("failed to get genesis: {e}")))?;

                let genesis_time: u64 = genesis.data.genesis_time.parse().map_err(|e| {
                    ApiError::Internal(format!("failed to parse genesis time: {e}"))
                })?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time before UNIX epoch")
                    .as_secs();

                current_epoch_at(now, genesis_time)
            }
        };

        info!(epoch, validator_index, pubkey = %pubkey_hex, "Signing voluntary exit");

        // Construct and sign
        let voluntary_exit = VoluntaryExit { epoch, validator_index };

        let pk = PublicKey::from_bytes(pubkey)
            .map_err(|e| ApiError::Internal(format!("invalid public key: {e:?}")))?;

        let signature = self
            .signer
            .sign_voluntary_exit(
                &voluntary_exit,
                &pk,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("signing failed: {e}")))?;

        Ok(SignedVoluntaryExit {
            message: voluntary_exit,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

/// Current epoch at `now_unix_secs` given genesis, using millisecond slot duration.
fn current_epoch_at(now_unix_secs: u64, genesis_time: u64) -> u64 {
    let elapsed_ms = now_unix_secs.saturating_sub(genesis_time).saturating_mul(1000);
    elapsed_ms / SLOT_DURATION_MS / SLOTS_PER_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_current_epoch_at_genesis_is_zero() {
        let genesis = 1_606_824_023_u64;
        assert_eq!(current_epoch_at(genesis, genesis), 0);
    }

    #[test]
    fn test_current_epoch_after_one_epoch_is_one() {
        let genesis = 1_606_824_023_u64;
        let epoch_secs = SLOT_DURATION_MS / 1000 * SLOTS_PER_EPOCH;
        assert_eq!(epoch_secs, 384, "one epoch is 384 s");
        assert_eq!(current_epoch_at(genesis + epoch_secs, genesis), 1);
        assert_eq!(current_epoch_at(genesis + epoch_secs - 1, genesis), 0);
    }

    fn test_fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        })
    }

    fn adapter_for(
        beacon: Arc<dyn BeaconNodeClient>,
        secret_key: SecretKey,
    ) -> VoluntaryExitManagerAdapter {
        let key_manager = KeyManager::new();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        composite.add_local_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        VoluntaryExitManagerAdapter::new(beacon, signer, test_fork_schedule(), [0xaa; 32])
    }

    fn validator_body(pubkey_hex: &str) -> serde_json::Value {
        validator_body_at(pubkey_hex, "42")
    }

    fn validator_body_at(pubkey_hex: &str, index: &str) -> serde_json::Value {
        serde_json::json!({
            "data": [{
                "index": index,
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey_hex }
            }]
        })
    }

    fn empty_validators_body() -> serde_json::Value {
        serde_json::json!({ "data": [] })
    }

    async fn mount_validators(server: &MockServer, body: serde_json::Value, status: u16) {
        let template = if status == 200 {
            ResponseTemplate::new(200).set_body_json(body)
        } else {
            ResponseTemplate::new(status).set_body_string("down")
        };
        Mock::given(method("GET"))
            .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    fn pool(endpoints: Vec<String>) -> Arc<dyn BeaconNodeClient> {
        Arc::new(BnManager::new(BnManagerConfig::new(endpoints)).expect("bn manager"))
    }

    /// Config names only `beacon_nodes`. The single-endpoint URL is empty, so a
    /// `BeaconClient` built from it cannot serve the exit.
    #[tokio::test]
    async fn exit_routes_through_the_bn_manager_with_only_beacon_nodes_configured() {
        let pooled = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        mount_validators(&pooled, validator_body(&super::pubkey_hex(pubkey)), 200).await;

        let config = crate::config::Config {
            beacon_url: String::new(),
            beacon_nodes: vec![pooled.uri()],
            ..crate::config::Config::default()
        };
        assert!(config.beacon_url.is_empty(), "no single-endpoint URL");
        assert_eq!(config.effective_beacon_nodes(), vec![pooled.uri()]);

        let manager = crate::config::ServiceBuilder::new(config)
            .build_bn_manager()
            .expect("pool from beacon_nodes");
        let adapter = adapter_for(manager, sk);

        let signed = adapter.sign_voluntary_exit(&pubkey, Some(100)).await.expect("exit via pool");
        assert_eq!(signed.message.validator_index, 42);
        assert_eq!(signed.message.epoch, 100);

        let paths: Vec<String> = pooled
            .received_requests()
            .await
            .expect("requests")
            .into_iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(
            paths.iter().any(|p| p.contains("validators")),
            "pooled BN must see the validator lookup, paths={paths:?}"
        );
    }

    #[tokio::test]
    async fn exit_fails_over_when_the_first_bn_is_down() {
        let down = MockServer::start().await;
        let up = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let body = validator_body(&super::pubkey_hex(pubkey));
        mount_validators(&down, body.clone(), 500).await;
        mount_validators(&up, body, 200).await;

        let adapter = adapter_for(pool(vec![down.uri(), up.uri()]), sk);
        let signed = adapter.sign_voluntary_exit(&pubkey, Some(9)).await.expect("failover");
        assert_eq!(signed.message.epoch, 9);
        assert_eq!(signed.message.validator_index, 42);

        assert!(
            !down.received_requests().await.expect("down reqs").is_empty(),
            "the first BN must be attempted"
        );
        let up_paths: Vec<String> = up
            .received_requests()
            .await
            .expect("up reqs")
            .into_iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(
            up_paths.iter().any(|p| p.contains("validators")),
            "the second BN must serve the validator lookup, paths={up_paths:?}"
        );
    }

    #[tokio::test]
    async fn explicit_epoch_skips_the_genesis_lookup() {
        let server = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        mount_validators(&server, validator_body(&super::pubkey_hex(pubkey)), 200).await;

        let adapter = adapter_for(pool(vec![server.uri()]), sk);
        let signed = adapter.sign_voluntary_exit(&pubkey, Some(77)).await.expect("explicit epoch");
        assert_eq!(signed.message.epoch, 77);

        let paths: Vec<String> = server
            .received_requests()
            .await
            .expect("requests")
            .into_iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(paths.iter().all(|p| !p.contains("genesis")), "paths={paths:?}");
        assert!(paths.iter().any(|p| p.contains("validators")), "paths={paths:?}");
    }

    async fn request_paths(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("requests")
            .into_iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    #[tokio::test]
    async fn exit_fails_over_when_the_first_bn_returns_empty_validators() {
        let empty = MockServer::start().await;
        let full = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let hex = super::pubkey_hex(pubkey);
        mount_validators(&empty, empty_validators_body(), 200).await;
        mount_validators(&full, validator_body(&hex), 200).await;

        let adapter = adapter_for(pool(vec![empty.uri(), full.uri()]), sk);
        let signed =
            adapter.sign_voluntary_exit(&pubkey, Some(11)).await.expect("empty 200 fails over");
        assert_eq!(signed.message.validator_index, 42);
        assert_eq!(signed.message.epoch, 11);

        let full_paths = request_paths(&full).await;
        assert!(
            full_paths.iter().any(|p| p.contains("validators")),
            "the second BN must be contacted, paths={full_paths:?}"
        );
    }

    #[tokio::test]
    async fn exit_fails_over_when_the_first_record_pubkey_does_not_match() {
        let wrong = MockServer::start().await;
        let right = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let hex = super::pubkey_hex(pubkey);
        let other = format!("0x{}", "ab".repeat(48));
        mount_validators(&wrong, validator_body_at(&other, "7"), 200).await;
        mount_validators(&right, validator_body(&hex), 200).await;

        let adapter = adapter_for(pool(vec![wrong.uri(), right.uri()]), sk);
        let signed =
            adapter.sign_voluntary_exit(&pubkey, Some(12)).await.expect("wrong pubkey fails over");
        assert_eq!(signed.message.validator_index, 42);
        assert_ne!(signed.message.validator_index, 7, "must not sign the other index");

        let right_paths = request_paths(&right).await;
        assert!(
            right_paths.iter().any(|p| p.contains("validators")),
            "the second BN must be contacted, paths={right_paths:?}"
        );
    }

    #[tokio::test]
    async fn exit_fails_over_when_genesis_root_does_not_match() {
        let foreign = MockServer::start().await;
        let ours = MockServer::start().await;
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let hex = super::pubkey_hex(pubkey);
        let configured = format!("0x{}", hex::encode([0xaa_u8; 32]));
        let other_root = format!("0x{}", hex::encode([0xbb_u8; 32]));
        // Both nodes know the validator. Only the genesis root differs, so a
        // validators-only failover cannot explain which clock was signed.
        mount_validators(&foreign, validator_body(&hex), 200).await;
        mount_validators(&ours, validator_body(&hex), 200).await;
        mount_genesis(&foreign, "1", &other_root).await;
        // Far enough ahead of wall time that the epoch stays 0.
        mount_genesis(&ours, "4000000000", &configured).await;

        let adapter = adapter_for(pool(vec![foreign.uri(), ours.uri()]), sk);
        let signed =
            adapter.sign_voluntary_exit(&pubkey, None).await.expect("genesis root fails over");
        assert_eq!(signed.message.validator_index, 42);
        assert_eq!(signed.message.epoch, 0, "must not sign the foreign genesis_time");

        let foreign_paths = request_paths(&foreign).await;
        let our_paths = request_paths(&ours).await;
        assert!(
            foreign_paths.iter().any(|p| p.contains("genesis")),
            "the first BN's genesis must be checked, paths={foreign_paths:?}"
        );
        assert!(
            our_paths.iter().any(|p| p.contains("genesis")),
            "the second BN must be contacted for genesis, paths={our_paths:?}"
        );
    }

    async fn mount_genesis(server: &MockServer, genesis_time: &str, root_hex: &str) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": genesis_time,
                    "genesis_validators_root": root_hex,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(server)
            .await;
    }
}
