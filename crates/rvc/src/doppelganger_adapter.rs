//! Adapter implementations bridging production types to doppelganger detection traits.
//!
//! SEC-2c: [`BeaconLivenessAdapter`] queries liveness through
//! [`bn_manager::BeaconNodeClient`] (production: `BnManager` with multi-BN
//! `query_first` failover) and translates numeric validator indices to bare
//! pubkey-hex before returning samples for [`ForwardWindowMachine::observe_liveness`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bn_manager::BeaconNodeClient;
use doppelganger::{DoppelgangerError, LivenessChecker, ValidatorLivenessData};
use eth_types::Epoch;
use parking_lot::RwLock;

/// Adapter implementing [`LivenessChecker`] via
/// [`BeaconNodeClient::post_validator_liveness`] (bn-manager failover in production).
///
/// # Pubkey-hex translation (SEC-001)
///
/// Beacon nodes return **numeric** validator indices. The machine keys state by
/// bare lowercase `hex::encode(pubkey.to_bytes())`. This adapter translates
/// using `index_to_pubkey_hex` and **omits** untranslatable indices (fail-closed).
pub struct BeaconLivenessAdapter {
    beacon: Arc<dyn BeaconNodeClient>,
    /// Numeric index string → bare pubkey hex (machine state key).
    index_to_pubkey_hex: Arc<RwLock<HashMap<String, String>>>,
}

impl BeaconLivenessAdapter {
    /// Construct with an empty translation map.
    pub fn new(beacon: Arc<dyn BeaconNodeClient>) -> Self {
        Self { beacon, index_to_pubkey_hex: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Construct with a pre-built numeric-index → bare-pubkey-hex map (SEC-2c).
    pub fn with_index_map(
        beacon: Arc<dyn BeaconNodeClient>,
        index_to_pubkey_hex: Arc<RwLock<HashMap<String, String>>>,
    ) -> Self {
        Self { beacon, index_to_pubkey_hex }
    }

    /// Shared handle so keymanager / index refresh can update the map.
    pub fn index_map(&self) -> Arc<RwLock<HashMap<String, String>>> {
        Arc::clone(&self.index_to_pubkey_hex)
    }
}

#[async_trait]
impl LivenessChecker for BeaconLivenessAdapter {
    async fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[String],
    ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError> {
        let response = self
            .beacon
            .post_validator_liveness(epoch, validator_indices)
            .await
            .map_err(|e| DoppelgangerError::LivenessCheckFailed(e.to_string()))?;

        let map = self.index_to_pubkey_hex.read();
        let samples: Vec<ValidatorLivenessData> = response
            .data
            .into_iter()
            .filter_map(|v| {
                // Prefer translation map; if map is empty (legacy), pass index through.
                let index = if map.is_empty() { v.index } else { map.get(&v.index)?.clone() };
                Some(ValidatorLivenessData { index, is_live: v.is_live })
            })
            .collect();

        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_liveness_adapter_construction() {
        let config = beacon::BeaconClientConfig::new("http://localhost:5052");
        let client = Arc::new(beacon::BeaconClient::new(config).unwrap());
        let beacon: Arc<dyn BeaconNodeClient> = client;
        let _adapter = BeaconLivenessAdapter::new(beacon);
    }
}
