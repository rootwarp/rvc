use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use async_trait::async_trait;

use super::bls::{SecretKey, Signature, PUBLIC_KEY_BYTES_LEN};
use super::signer_trait::{LocalSigner, Signer, SigningError};
use super::typed_signer::TypedSigner;
use eth_types::Root;
use observability::logging::TruncatedPubkey;

pub struct CompositeSigner {
    local: LocalSigner,
    /// gRPC remote signers implement `TypedSigner` only (no raw-root path).
    /// The key is the BLS public key; the value is a `TypedSigner` handle.
    grpc_remote: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], Arc<dyn TypedSigner + Send + Sync>>>,
    remote: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], Arc<dyn Signer + Send + Sync>>>,
    dynamic_local: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], SecretKey>>,
}

impl CompositeSigner {
    pub fn new(local: LocalSigner) -> Self {
        Self {
            local,
            grpc_remote: RwLock::new(HashMap::new()),
            remote: RwLock::new(HashMap::new()),
            dynamic_local: RwLock::new(HashMap::new()),
        }
    }

    /// Register a gRPC remote signer for the given public keys.
    ///
    /// The signer must implement [`TypedSigner`] — the v2 gRPC contract carries
    /// typed consensus objects and has no raw-root signing path (per C-2/C-3 fix).
    pub fn add_grpc_remote_signer(
        &self,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
        signer: Arc<dyn TypedSigner + Send + Sync>,
    ) {
        let mut grpc = self.grpc_remote.write();
        for pubkey in &pubkeys {
            let pubkey_hex = hex::encode(pubkey);
            info!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Added gRPC remote signer key");
        }
        for pubkey in pubkeys {
            grpc.insert(pubkey, Arc::clone(&signer));
        }
    }

    pub fn remove_grpc_remote_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        let removed = self.grpc_remote.write().remove(pubkey).is_some();
        if removed {
            let pubkey_hex = hex::encode(pubkey);
            warn!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Removed gRPC remote signer key");
        }
        removed
    }

    /// Look up the gRPC remote signer for a given pubkey.
    pub fn get_grpc_remote(
        &self,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Option<Arc<dyn TypedSigner + Send + Sync>> {
        self.grpc_remote.read().get(pubkey).cloned()
    }

    /// Returns true if a gRPC remote signer is registered for the given pubkey.
    pub fn has_grpc_remote(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.grpc_remote.read().contains_key(pubkey)
    }

    /// Returns true if an HTTP (Web3Signer) remote is registered for the pubkey.
    pub fn has_remote_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.remote.read().contains_key(pubkey)
    }

    pub fn add_remote_key(
        &self,
        pubkey: [u8; PUBLIC_KEY_BYTES_LEN],
        signer: Arc<dyn Signer + Send + Sync>,
    ) {
        let pubkey_hex = hex::encode(pubkey);
        info!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Added remote signer key");
        self.remote.write().insert(pubkey, signer);
    }

    pub fn remove_remote_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        let removed = self.remote.write().remove(pubkey).is_some();
        if removed {
            let pubkey_hex = hex::encode(pubkey);
            warn!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Removed remote signer key");
        }
        removed
    }

    pub fn add_local_key(&self, secret_key: SecretKey) {
        let pubkey = secret_key.public_key().to_bytes();
        let pubkey_hex = hex::encode(pubkey);
        info!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Added local signer key");
        self.dynamic_local.write().insert(pubkey, secret_key);
    }

    /// Removes a local key from the signing registry.
    ///
    /// Checks both the dynamically-added set (`add_local_key` / keymanager import)
    /// and the boot-loaded `LocalSigner` / `KeyManager` set (keystore-dir and
    /// secret-provider). Returns `true` if the key was present in either.
    pub fn remove_local_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        let dynamic_removed = self.dynamic_local.write().remove(pubkey).is_some();
        let boot_removed = self.local.remove_key(pubkey);
        let removed = dynamic_removed || boot_removed;
        if removed {
            let pubkey_hex = hex::encode(pubkey);
            warn!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Removed local signer key");
        }
        removed
    }

    /// Local (non-remote) public keys the VC can sign with.
    ///
    /// Canonical "local keystores" set for the Keymanager API: union of boot-loaded
    /// keys (`LocalSigner` / keystore-dir / secret-provider) and keys added via
    /// `add_local_key` (API import / secret-provider refresh). Does **not** include
    /// HTTP or gRPC remote keys — those are managed via `RemoteKeyManager`.
    pub fn local_public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        let mut keys = self.local.public_keys();
        let dynamic = self.dynamic_local.read();
        keys.extend(dynamic.keys());
        keys.sort();
        keys.dedup();
        keys
    }

    /// Returns `true` if `pubkey` is a local (non-remote) signing key.
    pub fn has_local_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        if self.dynamic_local.read().contains_key(pubkey) {
            return true;
        }
        self.local.contains_key(pubkey)
    }
}

#[async_trait]
impl Signer for CompositeSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        // gRPC remote signers no longer implement the raw-root `Signer` trait.
        // They implement `TypedSigner` only. If a caller reaches here with a
        // pubkey that belongs to a gRPC remote signer, they must use
        // `TypedSigner` methods (via `CompositeSigner::get_grpc_remote`).
        // This is the permanent fix for C-2/C-3.
        {
            let grpc = self.grpc_remote.read();
            if grpc.contains_key(pubkey) {
                let pk_hex = hex::encode(pubkey);
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pk_hex),
                    "raw-root Signer::sign called for a gRPC remote key — use TypedSigner instead"
                );
                // LocalRejected: never contacted the remote — staged-row discard is safe.
                return Err(SigningError::LocalRejected(
                    "raw-root signing is not supported for gRPC remote signers; \
                     use TypedSigner::sign_block / sign_attestation / etc."
                        .to_string(),
                ));
            }
        }

        // Check HTTP remote signers — clone Arc to release the lock before await
        let remote_signer = {
            let remote = self.remote.read();
            remote.get(pubkey).cloned()
        };
        if let Some(signer) = remote_signer {
            let result = signer.sign(signing_root, pubkey).await;
            match &result {
                Ok(_) => debug!(backend = "remote", "Signing succeeded"),
                Err(e) => debug!(backend = "remote", error = %e, "Signing failed"),
            }
            return result;
        }

        // Check dynamically-added local keys
        {
            let dynamic = self.dynamic_local.read();
            if let Some(sk) = dynamic.get(pubkey) {
                debug!(backend = "local", "Signing succeeded");
                return Ok(sk.sign(signing_root));
            }
        }

        // Fall through to the base local signer
        let result = self.local.sign(signing_root, pubkey).await;
        match &result {
            Ok(_) => debug!(backend = "local", "Signing succeeded"),
            Err(e) => debug!(backend = "local", error = %e, "Signing failed"),
        }
        result
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        let mut keys = self.local.public_keys();

        let dynamic = self.dynamic_local.read();
        keys.extend(dynamic.keys());

        let remote = self.remote.read();
        for signer in remote.values() {
            keys.extend(signer.public_keys());
        }

        let grpc = self.grpc_remote.read();
        keys.extend(grpc.keys());

        keys.sort();
        keys.dedup();
        keys
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;
    use crate::bls::PublicKey;
    use crate::key_manager::KeyManager;

    fn create_empty_local_signer() -> LocalSigner {
        LocalSigner::new(KeyManager::new())
    }

    fn create_local_signer_with_key(sk: SecretKey) -> LocalSigner {
        let mut km = KeyManager::new();
        km.insert(sk);
        LocalSigner::new(km)
    }

    #[tokio::test]
    async fn test_composite_signer_local_sign() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);

        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();

        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_composite_signer_remote_raw_sign_returns_unsupported() {
        // SEC-8: HTTP remotes refuse raw-root signing (typed body required).
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_remote_key(pk_bytes, Arc::new(FakeUnsupportedRemote { pubkey: pk_bytes }));

        let result = composite.sign(&signing_root, &pk_bytes).await;
        match result.unwrap_err() {
            SigningError::UnsupportedSigningType(msg) => {
                assert!(msg.contains("TypedSigner"), "msg={msg}");
            }
            other => panic!("expected UnsupportedSigningType, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_composite_signer_unknown_key_returns_error() {
        let composite = CompositeSigner::new(create_empty_local_signer());

        let unknown_sk = SecretKey::generate();
        let unknown_pk = unknown_sk.public_key().to_bytes();
        let result = composite.sign(&[0xab; 32], &unknown_pk).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_composite_signer_public_keys_union() {
        let sk1 = SecretKey::generate();
        let pk1 = sk1.public_key().to_bytes();

        let sk2 = SecretKey::generate();
        let pk2 = sk2.public_key().to_bytes();

        let composite = CompositeSigner::new(create_local_signer_with_key(sk1));
        composite.add_remote_key(pk2, Arc::new(FakeUnsupportedRemote { pubkey: pk2 }));

        let keys = composite.public_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pk1));
        assert!(keys.contains(&pk2));
    }

    #[tokio::test]
    async fn test_composite_signer_dynamic_local_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_local_key(sk);

        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());

        assert_eq!(composite.public_keys().len(), 1);
        assert!(composite.public_keys().contains(&pk_bytes));
    }

    #[tokio::test]
    async fn test_composite_signer_remove_remote_key() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_remote_key(pk, Arc::new(FakeUnsupportedRemote { pubkey: pk }));
        assert_eq!(composite.public_keys().len(), 1);

        let removed = composite.remove_remote_key(&pk);
        assert!(removed);
        assert!(composite.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_composite_signer_remove_local_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_local_key(sk);
        assert_eq!(composite.public_keys().len(), 1);

        let removed = composite.remove_local_key(&pk_bytes);
        assert!(removed);
        assert!(composite.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_composite_signer_remove_boot_loaded_local_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xcd; 32];

        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        assert!(composite.has_local_key(&pk_bytes));
        assert!(composite.local_public_keys().contains(&pk_bytes));
        assert!(composite.sign(&signing_root, &pk_bytes).await.is_ok());

        let removed = composite.remove_local_key(&pk_bytes);
        assert!(removed);
        assert!(!composite.has_local_key(&pk_bytes));
        assert!(composite.local_public_keys().is_empty());
        assert!(matches!(
            composite.sign(&signing_root, &pk_bytes).await,
            Err(SigningError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_composite_signer_remove_nonexistent_key() {
        let composite = CompositeSigner::new(create_empty_local_signer());
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        assert!(!composite.remove_remote_key(&pk));
        assert!(!composite.remove_local_key(&pk));
    }

    #[tokio::test]
    async fn test_composite_signer_remote_takes_priority_over_local() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        // Same key in both local and remote — remote is consulted first and
        // refuses raw-root (SEC-8). Local is never reached for this pubkey.
        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        composite.add_remote_key(pk_bytes, Arc::new(FakeUnsupportedRemote { pubkey: pk_bytes }));

        let result = composite.sign(&signing_root, &pk_bytes).await;
        match result.unwrap_err() {
            SigningError::UnsupportedSigningType(_) => {}
            other => panic!("expected UnsupportedSigningType from remote priority, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_composite_signer_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        let signer: Box<dyn Signer> = Box::new(composite);

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }

    /// In-test `Signer` that is not a concrete HTTP client. ARCH-6e RED: `add_remote_key`
    /// must accept any `Signer` impl so `crypto` can drop the concrete type.
    struct FakeRemote {
        pubkey: [u8; PUBLIC_KEY_BYTES_LEN],
        signature: Signature,
    }

    /// Stands in for Web3Signer HTTP's SEC-8 raw-root refusal after ARCH-6f.
    struct FakeUnsupportedRemote {
        pubkey: [u8; PUBLIC_KEY_BYTES_LEN],
    }

    #[async_trait]
    impl Signer for FakeUnsupportedRemote {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        ) -> Result<Signature, SigningError> {
            Err(SigningError::UnsupportedSigningType(
                "raw-root signing is not supported; use TypedSigner".to_string(),
            ))
        }

        fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
            vec![self.pubkey]
        }
    }

    #[async_trait]
    impl Signer for FakeRemote {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        ) -> Result<Signature, SigningError> {
            Ok(self.signature.clone())
        }

        fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
            vec![self.pubkey]
        }
    }

    #[tokio::test]
    async fn composite_signer_accepts_any_signer_impl_for_a_remote_key() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let fixed = sk.sign(&signing_root);

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_remote_key(pk, Arc::new(FakeRemote { pubkey: pk, signature: fixed.clone() }));

        let sig = composite.sign(&signing_root, &pk).await.unwrap();
        assert_eq!(sig.to_bytes(), fixed.to_bytes());
    }

    // --- gRPC remote signer tests ---
    // MockGrpcSigner implements TypedSigner (not Signer) to mirror GrpcRemoteSigner.

    use crate::signing_root::signing_root_with_fork_version;
    use crate::typed_signer::SignContext;
    use eth_types::{
        AggregateAndProof, AttestationData, BeaconBlock, BlindedBeaconBlock, BuilderRequestAuth,
        ContributionAndProof, Epoch, ForkInfo, PayloadAttestationData, ProposerPreferences,
        Root as EthRoot, Slot, SyncAggregatorSelectionData, ValidatorRegistrationV1, VoluntaryExit,
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
        DOMAIN_BEACON_PROPOSER, DOMAIN_BUILDER_REQUEST_AUTH, DOMAIN_CONTRIBUTION_AND_PROOF,
        DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
    };

    struct MockGrpcSigner {
        keys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
        sk_bytes: [u8; 32],
    }

    impl MockGrpcSigner {
        fn new(sk: &SecretKey, keys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>) -> Self {
            Self { keys, sk_bytes: sk.to_bytes() }
        }

        fn sign_root(
            &self,
            signing_root: &[u8; 32],
            pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        ) -> Result<Signature, SigningError> {
            if self.keys.contains(pubkey) {
                let sk = SecretKey::from_bytes(&self.sk_bytes).unwrap();
                Ok(sk.sign(signing_root))
            } else {
                Err(SigningError::KeyNotFound(hex::encode(pubkey)))
            }
        }
    }

    #[async_trait]
    impl TypedSigner for MockGrpcSigner {
        async fn sign_block(
            &self,
            block: &BeaconBlock,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                block,
                DOMAIN_BEACON_PROPOSER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_blinded_block(
            &self,
            block: &BlindedBeaconBlock,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                block,
                DOMAIN_BEACON_PROPOSER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_attestation(
            &self,
            data: &AttestationData,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                data,
                DOMAIN_BEACON_ATTESTER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_aggregate_and_proof(
            &self,
            agg: &AggregateAndProof,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                agg,
                DOMAIN_AGGREGATE_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_sync_committee_message(
            &self,
            _slot: Slot,
            beacon_block_root: EthRoot,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                &beacon_block_root,
                DOMAIN_SYNC_COMMITTEE,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_sync_aggregator_selection(
            &self,
            slot: Slot,
            subcommittee_index: u64,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let sel = SyncAggregatorSelectionData { slot, subcommittee_index };
            let root = signing_root_with_fork_version(
                &sel,
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_contribution_and_proof(
            &self,
            c: &ContributionAndProof,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                c,
                DOMAIN_CONTRIBUTION_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_builder_registration(
            &self,
            reg: &ValidatorRegistrationV1,
            genesis_fork_version: [u8; 4],
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                reg,
                DOMAIN_APPLICATION_BUILDER,
                genesis_fork_version,
                [0u8; 32],
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_randao_reveal(
            &self,
            epoch: Epoch,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                &epoch,
                DOMAIN_RANDAO,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_voluntary_exit(
            &self,
            exit: &VoluntaryExit,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                exit,
                DOMAIN_VOLUNTARY_EXIT,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_payload_attestation(
            &self,
            data: &PayloadAttestationData,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                data,
                DOMAIN_PTC_ATTESTER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_proposer_preferences(
            &self,
            prefs: &ProposerPreferences,
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                prefs,
                DOMAIN_PROPOSER_PREFERENCES,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
        async fn sign_builder_request_auth(
            &self,
            auth: &BuilderRequestAuth,
            genesis_fork_version: [u8; 4],
            ctx: &SignContext,
        ) -> Result<Signature, SigningError> {
            let root = signing_root_with_fork_version(
                auth,
                DOMAIN_BUILDER_REQUEST_AUTH,
                genesis_fork_version,
                [0u8; 32],
            );
            self.sign_root(&root, &ctx.pubkey.to_bytes())
        }
    }

    fn test_fork_info() -> ForkInfo {
        ForkInfo {
            previous_version: [0x00, 0x00, 0x00, 0x00],
            current_version: [0x04, 0x00, 0x00, 0x00],
            genesis_validators_root: [0xaa; 32],
        }
    }

    fn test_sign_ctx(pk: PublicKey) -> SignContext {
        SignContext {
            pubkey: pk,
            fork_info: test_fork_info(),
            fork_name: eth_types::ForkName::Deneb,
        }
    }

    #[tokio::test]
    async fn test_composite_signer_grpc_remote_raw_sign_returns_error() {
        // After C-2/C-3 fix: calling raw-root Signer::sign for a gRPC-remote pubkey
        // must return an error, not forward to the remote.
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);

        let result = composite.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_err(), "raw-root sign on gRPC remote key must fail");
        let err = result.unwrap_err();
        assert!(err.is_unambiguous_no_signature(), "gRPC raw-root reject must be discard-safe");
        match err {
            SigningError::LocalRejected(msg) => {
                assert!(msg.contains("TypedSigner"), "error message should mention TypedSigner");
            }
            other => panic!("expected LocalRejected, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_composite_signer_get_grpc_remote_returns_typed_signer() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));
        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);

        // get_grpc_remote must return the typed signer
        let typed = composite.get_grpc_remote(&pk_bytes);
        assert!(typed.is_some(), "expected Some(TypedSigner)");
    }

    #[tokio::test]
    async fn test_composite_signer_public_keys_includes_grpc_remote() {
        let sk1 = SecretKey::generate();
        let pk1 = sk1.public_key().to_bytes();

        let sk2 = SecretKey::generate();
        let pk2 = sk2.public_key().to_bytes();

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk2, vec![pk2]));

        let composite = CompositeSigner::new(create_local_signer_with_key(sk1));
        composite.add_grpc_remote_signer(vec![pk2], mock_grpc);

        let keys = composite.public_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pk1));
        assert!(keys.contains(&pk2));
    }

    #[tokio::test]
    async fn test_composite_signer_remove_grpc_remote_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);
        assert_eq!(composite.public_keys().len(), 1);

        let removed = composite.remove_grpc_remote_key(&pk_bytes);
        assert!(removed);
        assert!(composite.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_composite_signer_remove_grpc_remote_nonexistent() {
        let composite = CompositeSigner::new(create_empty_local_signer());
        let pk = [0xbb; PUBLIC_KEY_BYTES_LEN];
        assert!(!composite.remove_grpc_remote_key(&pk));
    }

    #[tokio::test]
    async fn test_composite_signer_public_keys_deduplicates_grpc_and_local() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));

        // Same key in both local and gRPC remote
        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);

        let keys = composite.public_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&pk_bytes));
    }

    #[tokio::test]
    async fn test_composite_signer_has_grpc_remote() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let other_pk = SecretKey::generate().public_key().to_bytes();

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));
        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);

        assert!(composite.has_grpc_remote(&pk_bytes));
        assert!(!composite.has_grpc_remote(&other_pk));
    }

    #[tokio::test]
    async fn test_composite_signer_typed_sign_via_grpc_remote() {
        // Verify the typed signing path via get_grpc_remote works correctly.
        use eth_types::BeaconBlock;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let block = BeaconBlock {
            slot: 42,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };

        let mock_grpc = Arc::new(MockGrpcSigner::new(&sk, vec![pk_bytes]));
        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_grpc_remote_signer(vec![pk_bytes], mock_grpc);

        let ctx = test_sign_ctx(pk.clone());
        let typed = composite.get_grpc_remote(&pk_bytes).expect("should have grpc remote");
        let sig = typed.sign_block(&block, &ctx).await.unwrap();

        // Verify the signature against the shared derivation helper.
        let signing_root = signing_root_with_fork_version(
            &block,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[test]
    fn test_lock_survives_panic_in_another_thread() {
        use std::sync::Arc;
        use std::thread;

        let composite = Arc::new(CompositeSigner::new(create_empty_local_signer()));

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        composite.add_local_key(sk);

        // Spawn a thread that panics while holding a write lock
        let composite_clone = composite.clone();
        let handle = thread::spawn(move || {
            let _guard = composite_clone.dynamic_local.write();
            panic!("intentional panic while holding lock");
        });

        // Thread panicked — join returns Err
        assert!(handle.join().is_err());

        // With parking_lot, the lock is NOT poisoned — we can still use it
        assert!(composite.public_keys().contains(&pk_bytes));

        // Can still add/remove keys after the panic
        let sk2 = SecretKey::generate();
        let pk2 = sk2.public_key().to_bytes();
        composite.add_local_key(sk2);
        assert!(composite.public_keys().contains(&pk2));
        assert!(composite.remove_local_key(&pk2));
    }
}
