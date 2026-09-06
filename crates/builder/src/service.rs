use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{debug, error, info, warn};

use bn_manager::{
    BeaconError, ProposerPreparation, SignedValidatorRegistration, ValidatorRegistrationV1,
};
use signer::SignerError;
use validator_store::ValidatorStore;

use crate::traits::{BuilderBeaconClient, RegistrationSigner};

#[derive(Debug, Error)]
pub enum BuilderServiceError {
    #[error("beacon node error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("signer error: {0}")]
    SignerError(#[from] SignerError),
}

/// Cached registration data for change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedRegistration {
    fee_recipient: [u8; 20],
    gas_limit: u64,
}

pub struct BuilderService {
    signer: Arc<dyn RegistrationSigner>,
    bn: Arc<dyn BuilderBeaconClient>,
    validator_store: Arc<ValidatorStore>,
    genesis_fork_version: [u8; 4],
    cache: tokio::sync::RwLock<HashMap<[u8; 48], CachedRegistration>>,
    registration_batch_size: usize,
    registration_batch_delay_ms: u64,
}

impl BuilderService {
    pub fn new(
        signer: Arc<dyn RegistrationSigner>,
        bn: Arc<dyn BuilderBeaconClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
    ) -> Self {
        Self::with_batching(signer, bn, validator_store, genesis_fork_version, 0, 0)
    }

    pub fn with_batching(
        signer: Arc<dyn RegistrationSigner>,
        bn: Arc<dyn BuilderBeaconClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
        registration_batch_size: usize,
        registration_batch_delay_ms: u64,
    ) -> Self {
        Self {
            signer,
            bn,
            validator_store,
            genesis_fork_version,
            cache: tokio::sync::RwLock::new(HashMap::new()),
            registration_batch_size,
            registration_batch_delay_ms,
        }
    }

    #[tracing::instrument(name = "builder.register", skip_all, fields(builder.batch_size))]
    pub async fn register_validators(&self) -> Result<(), BuilderServiceError> {
        let enabled_pubkeys = self.validator_store.list_enabled_pubkeys();
        let builder_pubkeys: Vec<[u8; 48]> = enabled_pubkeys
            .into_iter()
            .filter(|pk| self.validator_store.is_builder_enabled(pk))
            .collect();

        if builder_pubkeys.is_empty() {
            debug!("no builder-enabled validators to register");
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        // Collect candidates that need (re-)registration by checking
        // the cache under a read lock, then release the lock before
        // performing any async signing.
        let candidates: Vec<([u8; 48], [u8; 20], u64)> = {
            let cache = self.cache.read().await;
            builder_pubkeys
                .iter()
                .filter_map(|pubkey| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pubkey);
                    let gas_limit = self.validator_store.effective_gas_limit(pubkey);
                    let new_cached = CachedRegistration { fee_recipient, gas_limit };
                    if cache.get(pubkey) == Some(&new_cached) {
                        None
                    } else {
                        Some((*pubkey, fee_recipient, gas_limit))
                    }
                })
                .collect()
        };

        let mut registrations = Vec::new();

        for (pubkey, fee_recipient, gas_limit) in &candidates {
            let registration = ValidatorRegistrationV1 {
                fee_recipient: *fee_recipient,
                gas_limit: *gas_limit,
                timestamp,
                pubkey: *pubkey,
            };

            let pk = match crypto::PublicKey::from_bytes(pubkey) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(pubkey = hex::encode(pubkey), error = %e, "skipping invalid pubkey");
                    continue;
                }
            };

            match self
                .signer
                .sign_builder_registration(&registration, &pk, self.genesis_fork_version)
                .await
            {
                Ok(signature) => {
                    // Wire boundary: eth_types::Signature is Vec<u8> for JSON serde.
                    registrations.push(SignedValidatorRegistration {
                        message: registration,
                        signature: signature.to_bytes().to_vec(),
                    });
                }
                Err(e) => {
                    error!(
                        pubkey = hex::encode(pubkey),
                        error = %e,
                        "failed to sign builder registration"
                    );
                }
            }
        }

        if registrations.is_empty() {
            debug!("no new registrations to submit");
            return Ok(());
        }

        let total_count = registrations.len();
        tracing::Span::current().record("builder.batch_size", total_count);

        // Batch size 0 means send all at once (legacy behavior)
        let effective_batch_size = if self.registration_batch_size == 0 {
            total_count
        } else {
            self.registration_batch_size
        };

        let mut successful_registrations = Vec::new();
        let mut batch_failures = 0u64;
        let chunks: Vec<&[SignedValidatorRegistration]> =
            registrations.chunks(effective_batch_size).collect();
        let num_batches = chunks.len();

        debug!(
            total_count = total_count,
            batch_size = effective_batch_size,
            num_batches = num_batches,
            "submitting builder registrations in batches"
        );

        for (i, chunk) in chunks.iter().enumerate() {
            if i > 0 && self.registration_batch_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    self.registration_batch_delay_ms,
                ))
                .await;
            }

            let start = Instant::now();
            match self.bn.register_validators(chunk).await {
                Ok(()) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    debug!(
                        batch = i + 1,
                        of = num_batches,
                        size = chunk.len(),
                        duration_ms = duration_ms,
                        "registration batch sent"
                    );
                    successful_registrations.extend_from_slice(chunk);
                }
                Err(e) => {
                    batch_failures += 1;
                    warn!(
                        batch = i + 1,
                        of = num_batches,
                        size = chunk.len(),
                        error = %e,
                        "registration batch failed, continuing with remaining batches"
                    );
                    // Don't abort — continue with remaining batches
                }
            }
        }

        info!(
            total = total_count,
            successful = successful_registrations.len(),
            batch_failures = batch_failures,
            "registration batching complete"
        );

        // Update cache for successfully submitted registrations
        {
            let mut cache = self.cache.write().await;
            for reg in &successful_registrations {
                cache.insert(
                    reg.message.pubkey,
                    CachedRegistration {
                        fee_recipient: reg.message.fee_recipient,
                        gas_limit: reg.message.gas_limit,
                    },
                );
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "builder.prepare_proposers", skip_all)]
    pub async fn prepare_proposers(
        &self,
        validator_indices: &HashMap<[u8; 48], u64>,
    ) -> Result<(), BuilderServiceError> {
        let enabled_pubkeys = self.validator_store.list_enabled_pubkeys();

        let preparations: Vec<ProposerPreparation> = enabled_pubkeys
            .iter()
            .filter_map(|pk| {
                validator_indices.get(pk).map(|index| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pk);
                    ProposerPreparation {
                        validator_index: index.to_string(),
                        fee_recipient: format!("0x{}", hex::encode(fee_recipient)),
                    }
                })
            })
            .collect();

        if preparations.is_empty() {
            debug!("no proposer preparations to submit");
            return Ok(());
        }

        let count = preparations.len();
        debug!(count = count, "submitting proposer preparations");
        match self.bn.prepare_beacon_proposer(&preparations).await {
            Ok(()) => {
                info!(count = count, "proposer preparation sent");
            }
            Err(e) => {
                warn!(error = %e, "proposer preparation failure");
                return Err(e.into());
            }
        }

        Ok(())
    }

    pub fn jitter_seconds() -> u64 {
        use rand::Rng;
        rand::thread_rng().gen_range(0..30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    use async_trait::async_trait;
    use crypto::PublicKey;
    use eth_types::ValidatorRegistrationV1;
    use validator_store::ValidatorConfig;

    // --- Narrow mock BN (only the two methods BuilderService uses) ---

    struct MockBn {
        register_calls: Mutex<Vec<Vec<SignedValidatorRegistration>>>,
        prepare_calls: Mutex<Vec<Vec<ProposerPreparation>>>,
        fail_register: bool,
        fail_prepare: bool,
        /// Fail only on these 0-based call indices (e.g. [1] fails the second call).
        fail_register_on_calls: Vec<usize>,
    }

    impl MockBn {
        fn new() -> Self {
            Self {
                register_calls: Mutex::new(Vec::new()),
                prepare_calls: Mutex::new(Vec::new()),
                fail_register: false,
                fail_prepare: false,
                fail_register_on_calls: Vec::new(),
            }
        }

        fn with_register_error(mut self) -> Self {
            self.fail_register = true;
            self
        }

        fn with_prepare_error(mut self) -> Self {
            self.fail_prepare = true;
            self
        }

        fn with_register_error_on_calls(mut self, indices: Vec<usize>) -> Self {
            self.fail_register_on_calls = indices;
            self
        }
    }

    #[async_trait]
    impl BuilderBeaconClient for MockBn {
        async fn prepare_beacon_proposer(
            &self,
            preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError> {
            if self.fail_prepare {
                return Err(BeaconError::HttpError("mock prepare failure".into()));
            }
            self.prepare_calls.lock().push(preparations.to_vec());
            Ok(())
        }

        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            let call_idx = self.register_calls.lock().len();
            if self.fail_register || self.fail_register_on_calls.contains(&call_idx) {
                // Still record the call so we can count it
                self.register_calls.lock().push(registrations.to_vec());
                return Err(BeaconError::HttpError("mock register failure".into()));
            }
            self.register_calls.lock().push(registrations.to_vec());
            Ok(())
        }
    }

    // --- Narrow mock signer (only sign_builder_registration) ---

    struct MockSigner {
        fail_sign: bool,
        sign_calls: Mutex<Vec<[u8; 48]>>,
        /// Fixed valid BLS signature for wire-boundary assertions.
        sig: crypto::Signature,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                fail_sign: false,
                sign_calls: Mutex::new(Vec::new()),
                sig: crypto::SecretKey::generate().sign(b"mock-builder-reg"),
            }
        }

        fn with_sign_error(mut self) -> Self {
            self.fail_sign = true;
            self
        }

        fn signature_bytes(&self) -> Vec<u8> {
            self.sig.to_bytes().to_vec()
        }
    }

    #[async_trait]
    impl RegistrationSigner for MockSigner {
        async fn sign_builder_registration(
            &self,
            _registration: &ValidatorRegistrationV1,
            pubkey: &PublicKey,
            _fork_version: [u8; 4],
        ) -> Result<crypto::Signature, SignerError> {
            if self.fail_sign {
                return Err(SignerError::KeyNotFound("mock sign failure".into()));
            }
            self.sign_calls.lock().push(pubkey.to_bytes());
            Ok(self.sig.clone())
        }
    }

    // --- Helpers ---

    fn gen_pubkey_bytes() -> [u8; 48] {
        let sk = crypto::SecretKey::generate();
        sk.public_key().to_bytes()
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    type ValidatorEntry = ([u8; 48], bool, Option<[u8; 20]>, Option<u64>);

    fn test_store_with_builder_validators(validators: &[ValidatorEntry]) -> ValidatorStore {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        for (pk, builder_enabled, fee_recipient, gas_limit) in validators {
            let mut config = ValidatorConfig::new(*pk);
            config.builder_proposals = *builder_enabled;
            config.fee_recipient = *fee_recipient;
            config.gas_limit = *gas_limit;
            store.add_validator(config).unwrap();
        }
        store
    }

    fn build_service(signer: MockSigner, bn: MockBn, store: ValidatorStore) -> BuilderService {
        BuilderService::new(
            Arc::new(signer),
            Arc::new(bn),
            Arc::new(store),
            [0x00, 0x00, 0x00, 0x00],
        )
    }

    fn build_service_with_batching(
        signer: Arc<MockSigner>,
        bn: Arc<MockBn>,
        store: Arc<ValidatorStore>,
        batch_size: usize,
        batch_delay_ms: u64,
    ) -> BuilderService {
        BuilderService::with_batching(
            signer,
            bn,
            store,
            [0x00, 0x00, 0x00, 0x00],
            batch_size,
            batch_delay_ms,
        )
    }

    /// RED→GREEN: BuilderService compiles against a two-method BN stub +
    /// one-method registration signer (no BeaconNodeClient / ValidatorSigner).
    #[tokio::test]
    async fn test_builder_service_compiles_against_two_method_stub() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        service.register_validators().await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        let mut indices = HashMap::new();
        indices.insert(pk, 1u64);
        service.prepare_proposers(&indices).await.unwrap();
        assert_eq!(bn.prepare_calls.lock().len(), 1);
    }

    // --- register_validators tests ---

    #[tokio::test]
    async fn test_register_validators_no_builder_enabled() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);
        let bn = Arc::new(MockBn::new());
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            [0x00, 0x00, 0x00, 0x00],
        );

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_empty_store() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = build_service(MockSigner::new(), MockBn::new(), store);

        let result = service.register_validators().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_validators_submits_for_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(fr), Some(35_000_000)),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            [0x00, 0x00, 0x00, 0x00],
        );

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].message.pubkey, pk1);
        assert_eq!(calls[0][0].message.fee_recipient, fr);
        assert_eq!(calls[0][0].message.gas_limit, 35_000_000);
        assert_eq!(calls[0][0].signature, signer.signature_bytes());

        let sign_calls = signer.sign_calls.lock();
        assert_eq!(sign_calls.len(), 1);
    }

    #[tokio::test]
    async fn test_register_validators_uses_default_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 25_000_000);
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls[0][0].message.fee_recipient, default_fr);
        assert_eq!(calls[0][0].message.gas_limit, 25_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_multiple_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let pk3 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(test_fee_recipient(1)), Some(30_000_000)),
            (pk2, true, Some(test_fee_recipient(2)), Some(31_000_000)),
            (pk3, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let pubkeys: Vec<[u8; 48]> = calls[0].iter().map(|r| r.message.pubkey).collect();
        assert!(pubkeys.contains(&pk1));
        assert!(pubkeys.contains(&pk2));
        assert!(!pubkeys.contains(&pk3));
    }

    #[tokio::test]
    async fn test_register_validators_beacon_error_continues() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new().with_register_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        // With batching, failed batches are logged but don't abort — returns Ok
        let result = service.register_validators().await;
        assert!(result.is_ok());

        // Cache should not be updated for failed registrations
        let cache = service.cache.read().await;
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_sign_error_skips_validator() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store =
            test_store_with_builder_validators(&[(pk1, true, None, None), (pk2, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new().with_sign_error());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        // No registrations submitted since signing failed
        let calls = bn.register_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_caches_and_skips_unchanged() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[(pk, true, Some(fr), Some(35_000_000))]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        // First call should register
        let result = service.register_validators().await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Second call should skip (cached)
        let result = service.register_validators().await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1); // Still 1, no new call
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_fee_recipient_change() {
        let pk = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0xab);
        let fr2 = test_fee_recipient(0xcd);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr1);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), [0x00, 0x00, 0x00, 0x00]);

        // First registration
        service.register_validators().await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change fee_recipient
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    fee_recipient: Some(Some(fr2)),
                    ..Default::default()
                },
            )
            .unwrap();

        // Should re-register
        service.register_validators().await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.fee_recipient, fr2);
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_gas_limit_change() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), [0x00, 0x00, 0x00, 0x00]);

        service.register_validators().await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change gas_limit
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    gas_limit: Some(Some(50_000_000)),
                    ..Default::default()
                },
            )
            .unwrap();

        service.register_validators().await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.gas_limit, 50_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_timestamp_is_reasonable() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        service.register_validators().await.unwrap();
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let calls = bn.register_calls.lock();
        let timestamp = calls[0][0].message.timestamp;
        assert!(timestamp >= before);
        assert!(timestamp <= after);
    }

    // --- prepare_proposers tests ---

    #[tokio::test]
    async fn test_prepare_proposers_submits_for_all_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0x01);
        let fr2 = test_fee_recipient(0x02);
        let store = test_store_with_builder_validators(&[
            (pk1, false, Some(fr1), None),
            (pk2, false, Some(fr2), None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);
        indices.insert(pk2, 200u64);

        let result = service.prepare_proposers(&indices).await;
        assert!(result.is_ok());

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let preps = &calls[0];
        let indices_submitted: Vec<&str> =
            preps.iter().map(|p| p.validator_index.as_str()).collect();
        assert!(indices_submitted.contains(&"100"));
        assert!(indices_submitted.contains(&"200"));
    }

    #[tokio::test]
    async fn test_prepare_proposers_uses_effective_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk, 42u64);

        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        let expected_fr = format!("0x{}", hex::encode(default_fr));
        assert_eq!(calls[0][0].fee_recipient, expected_fr);
        assert_eq!(calls[0][0].validator_index, "42");
    }

    #[tokio::test]
    async fn test_prepare_proposers_skips_unknown_indices() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, false, None, None),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        // Only provide index for pk1
        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);

        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].validator_index, "100");
    }

    #[tokio::test]
    async fn test_prepare_proposers_empty_indices() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let indices = HashMap::new();
        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_prepare_proposers_beacon_error_propagates() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new().with_prepare_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk, 100u64);

        let result = service.prepare_proposers(&indices).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("beacon node error"));
    }

    // --- jitter tests ---

    #[test]
    fn test_jitter_is_in_range() {
        for _ in 0..100 {
            let jitter = BuilderService::jitter_seconds();
            assert!(jitter < 30);
        }
    }

    // --- Error display tests ---

    #[test]
    fn test_builder_service_error_display_beacon() {
        let err = BuilderServiceError::BeaconError(BeaconError::HttpError("test".into()));
        assert!(err.to_string().contains("beacon node error"));
    }

    #[test]
    fn test_builder_service_error_display_signer() {
        let err = BuilderServiceError::SignerError(SignerError::KeyNotFound("test".into()));
        assert!(err.to_string().contains("signer error"));
    }

    // --- Construction test ---

    #[test]
    fn test_builder_service_new() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let _service = BuilderService::new(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
        );
    }

    // --- Batching tests ---

    #[tokio::test]
    async fn test_batching_splits_into_correct_batch_count() {
        // 5 validators with batch_size=2 should produce 3 batches (2+2+1)
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 2, 0);

        service.register_validators().await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].len(), 2);
        assert_eq!(calls[1].len(), 2);
        assert_eq!(calls[2].len(), 1);
    }

    #[tokio::test]
    async fn test_batching_zero_sends_all_at_once() {
        // batch_size=0 (legacy) should submit all in a single call
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 0, 0);

        service.register_validators().await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 5);
    }

    #[tokio::test]
    async fn test_batching_partial_failure_continues_remaining() {
        // Fail batch index 1 (second batch). Batches 0 and 2 should succeed.
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new().with_register_error_on_calls(vec![1]));
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 2, 0);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        // All 3 batches should have been attempted
        {
            let calls = bn.register_calls.lock();
            assert_eq!(calls.len(), 3);
        }

        // Cache should only contain validators from successful batches (0 and 2)
        let cache = service.cache.read().await;
        assert_eq!(cache.len(), 3); // 2 from batch 0 + 1 from batch 2
    }

    #[tokio::test]
    async fn test_batching_with_batching_constructor() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = BuilderService::with_batching(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
            100,
            50,
        );
        assert_eq!(service.registration_batch_size, 100);
        assert_eq!(service.registration_batch_delay_ms, 50);
    }

    #[tokio::test]
    async fn test_batching_delay_between_batches() {
        // Relocated from bin/rvc tier-4 registration_batching (unique timing cover).
        let pks: Vec<[u8; 48]> = (0..20).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 10, 50);

        let start = std::time::Instant::now();
        service.register_validators().await.unwrap();
        let elapsed = start.elapsed();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2, "20 validators / 10 batch = 2 requests");
        assert!(
            elapsed >= std::time::Duration::from_millis(40),
            "should have delay between batches, elapsed: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_batching_new_defaults_to_zero() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
        );
        assert_eq!(service.registration_batch_size, 0);
        assert_eq!(service.registration_batch_delay_ms, 0);
    }
}
