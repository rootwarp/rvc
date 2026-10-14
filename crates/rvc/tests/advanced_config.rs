//! Advanced feature config coverage relocated from bin/rvc tier-4 suites.
//!
//! ValidatorStore block-selection unit behaviour already lives in
//! `validator-store`; pure HealthTier/BnRole unit tests live in
//! `rvc-bn-manager`. This file keeps rvc Config TOML wiring and multi-crate
//! composition that includes `rvc::config`.

mod block_selection {
    use validator_store::BlockSelectionMode;

    #[test]
    fn config_block_selection_mode_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
block_selection_mode = "builder-only"
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderOnly);
    }
}

mod composition {
    use bn_manager::{BnManagerConfig, BnRole, HealthTier, TierThresholds};
    use signer::CircuitBreakerState;
    use std::collections::HashSet;
    use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    fn test_pubkey(id: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    #[test]
    fn block_selection_with_circuit_breaker_and_health_tiers() {
        let thresholds = TierThresholds::default();

        // Simulate a Synced BN (distance=3)
        let tier = thresholds.tier_for_distance(3);
        assert_eq!(tier, HealthTier::Synced);

        // Circuit breaker is NOT tripped
        let cb = CircuitBreakerState::new(3, 5);
        assert!(!cb.is_tripped());

        // BuilderAlways mode with healthy BN and no CB trip → should proceed with builder
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderAlways);
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderAlways);

        // Now trip the circuit breaker
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        // BuilderAlways + tripped CB → should fall back to local (boost=0)
        // BuilderOnly + tripped CB → should fail (proposal missed)
        // These are verified through the block service, but the state composition is valid
    }

    #[test]
    fn all_tier4_features_together() {
        let thresholds = TierThresholds { synced: 4, small: 4, large: 16 };

        // Block selection: per-validator override
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk1 = test_pubkey(1);
        let pk2 = test_pubkey(2);
        let mut config1 = ValidatorConfig::new(pk1);
        config1.block_selection_mode = Some(BlockSelectionMode::BuilderAlways);
        config1.builder_proposals = true;
        store.add_validator(config1).unwrap();
        let mut config2 = ValidatorConfig::new(pk2);
        config2.builder_proposals = true;
        store.add_validator(config2).unwrap();
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

        assert_eq!(
            store.effective_block_selection_mode(&pk1),
            BlockSelectionMode::BuilderAlways,
            "per-validator override"
        );
        assert_eq!(
            store.effective_block_selection_mode(&pk2),
            BlockSelectionMode::ExecutionOnly,
            "global fallback"
        );

        // Health tiers with custom thresholds
        assert_eq!(thresholds.tier_for_distance(4), HealthTier::Synced);
        assert_eq!(thresholds.tier_for_distance(5), HealthTier::SmallLag);
        assert_eq!(thresholds.tier_for_distance(25), HealthTier::Unsynced);

        // Role-based: BnManagerConfig with roles
        let mut bn_config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
        ]);
        let mut proposal_roles = HashSet::new();
        proposal_roles.insert(BnRole::Proposal);
        let mut attest_roles = HashSet::new();
        attest_roles.insert(BnRole::Attestation);
        bn_config.roles = vec![proposal_roles.clone(), attest_roles.clone()];
        bn_config.tier_thresholds = thresholds;

        assert!(BnRole::matches(&bn_config.roles[0], BnRole::Proposal));
        assert!(!BnRole::matches(&bn_config.roles[0], BnRole::Attestation));
        assert!(BnRole::matches(&bn_config.roles[1], BnRole::Attestation));
        assert!(!BnRole::matches(&bn_config.roles[1], BnRole::Proposal));

        // Circuit breaker
        let cb = CircuitBreakerState::new(3, 10);
        assert!(!cb.is_tripped());
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());
        cb.reset_epoch(1);
        assert!(!cb.is_tripped(), "epoch reset clears circuit breaker");

        // Config TOML with all tier4 fields
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    block_selection_mode = "builder-always"
    validator_registration_batch_size = 250
    validator_registration_batch_delay = 100
    bn_sync_tolerances = "4,4,16"

    [[beacon_nodes_config]]
    url = "http://bn1:5052"
    roles = ["proposal"]

    [[beacon_nodes_config]]
    url = "http://bn2:5052"
    roles = ["attestation"]
    "#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderAlways);
        assert_eq!(config.validator_registration_batch_size, 250);
        assert_eq!(config.validator_registration_batch_delay, 100);
        assert_eq!(config.bn_sync_tolerances.as_deref(), Some("4,4,16"));
        assert_eq!(config.beacon_nodes_config.len(), 2);
        assert_eq!(config.beacon_nodes_config[0].roles, vec![BnRole::Proposal]);
        assert_eq!(config.beacon_nodes_config[1].roles, vec![BnRole::Attestation]);
    }
}
