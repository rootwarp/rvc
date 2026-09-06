//! Adapter implementations for beacon client traits.
//!
//! Bridges `Arc<dyn BeaconNodeClient>` (main pool or proposer `BnManager`) to
//! the `BeaconBlockClient` interface required by `BlockService` via a newtype
//! wrapper (orphan rule compliance).

use std::sync::Arc;

use async_trait::async_trait;
use block_service::{BeaconBlockClient, BlockServiceError, BuilderConfig, ProduceBlockResponse};
use bn_manager::BeaconNodeClient;
use eth_types::{SignedBeaconBlock, SignedBlindedBeaconBlock, Slot};

/// Newtype adapter that implements [`BeaconBlockClient`] for any
/// [`BeaconNodeClient`] (typically a proposer or main-pool `BnManager`).
pub struct BeaconBlockAdapter(pub Arc<dyn BeaconNodeClient>);

#[async_trait]
impl BeaconBlockClient for BeaconBlockAdapter {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.0
            .produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor)
            .await
            .map_err(Into::into)
    }

    async fn produce_block_v4(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.0
            .produce_block_v4(slot, randao_reveal, graffiti, builder_config)
            .await
            .map_err(Into::into)
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_block(signed_block, consensus_version)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_blinded_block(signed_block, consensus_version)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_block_ssz(ssz_bytes, consensus_version, is_blinded)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon::HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED;
    use block_service::BeaconBlockClient;
    use bn_manager::{BnManager, BnManagerConfig};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn block_response_template(payload_value: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", payload_value)
            .set_body_string(
                r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
            )
    }

    /// First proposer node down → second is used and a block is produced.
    #[tokio::test]
    async fn test_block_production_fails_over_to_second_proposer_node() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/42"))
            .respond_with(ResponseTemplate::new(500).set_body_string("down"))
            .expect(1..)
            .mount(&primary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/42"))
            .respond_with(block_response_template("9001"))
            .expect(1..)
            .mount(&secondary)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![primary.uri(), secondary.uri()]))
            .expect("proposer BnManager");
        let adapter = BeaconBlockAdapter(Arc::new(manager));

        let produced = adapter
            .produce_block_v3(42, "0xrandao", None, None)
            .await
            .expect("failover produce_block_v3");
        assert_eq!(produced.execution_payload_value.as_deref(), Some("9001"));
        assert_eq!(produced.consensus_version, "deneb");
    }

    /// Empty proposer pool → main BnManager is used (request hits main endpoint).
    #[tokio::test]
    async fn test_empty_proposer_nodes_uses_main_bn_manager() {
        let main = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/7"))
            .respond_with(block_response_template("111"))
            .expect(1)
            .mount(&main)
            .await;

        let main_mgr =
            BnManager::new(BnManagerConfig::new(vec![main.uri()])).expect("main BnManager");
        // Mirrors main.rs: no proposer pool → wrap the main pool.
        let adapter = BeaconBlockAdapter(Arc::new(main_mgr) as Arc<dyn BeaconNodeClient>);

        let produced = adapter
            .produce_block_v3(7, "0xrandao", None, None)
            .await
            .expect("main-pool produce_block_v3");
        assert_eq!(produced.execution_payload_value.as_deref(), Some("111"));
    }

    /// Production path: adapter forwards `produce_block_v4` onto BnManager (POST /eth/v4/...).
    #[tokio::test]
    async fn test_produce_block_v4_forwards_to_bn_manager() {
        let server = MockServer::start().await;
        let slot = 42u64;
        let builder_config =
            BuilderConfig { min_bid: 10_000_000, builder_boost_factor: 50, builders: Vec::new() };

        Mock::given(method("POST"))
            .and(path("/eth/v4/validator/blocks/42"))
            .and(body_json(&builder_config))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Eth-Consensus-Version", "gloas")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Execution-Payload-Value", "4242")
                    .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true")
                    .set_body_string(
                        r#"{"data":{"slot":"42","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/42"))
            .respond_with(block_response_template("v3-should-not-be-hit"))
            .expect(0)
            .mount(&server)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![server.uri()])).expect("BnManager");
        let adapter = BeaconBlockAdapter(Arc::new(manager));

        let produced = adapter
            .produce_block_v4(slot, "0xrandao", None, &builder_config)
            .await
            .expect("produce_block_v4");
        assert_eq!(produced.execution_payload_value.as_deref(), Some("4242"));
        assert_eq!(produced.consensus_version, "gloas");
        assert!(produced.payload_included);
    }

    /// Configured proposer pool is preferred: request goes to proposer endpoint,
    /// not the main-pool endpoint.
    #[tokio::test]
    async fn test_proposer_pool_used_when_configured() {
        let main = MockServer::start().await;
        let proposer = MockServer::start().await;

        // Main pool must not be contacted for block production.
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/9"))
            .respond_with(block_response_template("main-should-not-be-hit"))
            .expect(0)
            .mount(&main)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/9"))
            .respond_with(block_response_template("proposer-value"))
            .expect(1)
            .mount(&proposer)
            .await;

        let _main_mgr =
            BnManager::new(BnManagerConfig::new(vec![main.uri()])).expect("main BnManager");
        let proposer_mgr =
            BnManager::new(BnManagerConfig::new(vec![proposer.uri()])).expect("proposer BnManager");
        // Mirrors main.rs: proposer pool configured → wrap proposer BnManager.
        let adapter = BeaconBlockAdapter(Arc::new(proposer_mgr) as Arc<dyn BeaconNodeClient>);

        let produced = adapter
            .produce_block_v3(9, "0xrandao", None, None)
            .await
            .expect("proposer-pool produce_block_v3");
        assert_eq!(produced.execution_payload_value.as_deref(), Some("proposer-value"));
    }

    /// Pins that the adapter hop keeps all ProduceBlockResponse fields,
    /// including the SSZ pair that a field-copy can drop. Passes with the
    /// current copy and after it is deleted.
    #[tokio::test]
    async fn beacon_adapter_preserves_all_fields_for_an_ssz_response() {
        let server = MockServer::start().await;
        let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/500"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb")
                    .insert_header("Eth-Execution-Payload-Value", "99999"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let manager =
            BnManager::new(BnManagerConfig::new(vec![server.uri()])).expect("ssz BnManager");
        let adapter = BeaconBlockAdapter(Arc::new(manager));

        let produced = adapter
            .produce_block_v3(500, "0xrandao", None, None)
            .await
            .expect("ssz produce_block_v3");

        assert_eq!(produced.data, serde_json::Value::Null);
        assert!(!produced.is_blinded);
        assert_eq!(produced.consensus_version, "deneb");
        assert_eq!(produced.execution_payload_value.as_deref(), Some("99999"));
        assert!(produced.is_ssz);
        assert_eq!(produced.ssz_bytes.as_deref(), Some(ssz_payload.as_slice()));
        assert!(!produced.payload_included);
        assert!(produced.builder_url.is_none());
        assert!(produced.consensus_block_value.is_none());
    }
}
