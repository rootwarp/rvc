//! Validator store manager adapter for the Keymanager API.

use std::sync::Arc;

use keymanager_api::traits::{Pubkey, ValidatorManager};
use tracing::{info, warn};
use validator_store::ValidatorStore;

use super::notifier::pubkey_hex;

pub struct ValidatorManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }
}

impl ValidatorManager for ValidatorManagerAdapter {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        let pubkey_hex = pubkey_hex(pubkey);
        let mut config = validator_store::ValidatorConfig::new(pubkey);
        config.enabled = enabled;
        self.validator_store.add_validator(config).expect("imported validator has no builder URLs");
        info!(pubkey = %pubkey_hex, enabled, "Added validator to store");
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        let pubkey_hex = pubkey_hex(pubkey);
        let removed = self.validator_store.remove_validator(pubkey).is_some();
        if removed {
            info!(pubkey = %pubkey_hex, "Removed validator from store");
        } else {
            warn!(pubkey = %pubkey_hex, "Validator not found in store for removal");
        }
        removed
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        let pubkey_hex = pubkey_hex(pubkey);
        self.validator_store.set_enabled(pubkey, enabled);
        info!(pubkey = %pubkey_hex, enabled, "Validator enabled state updated");
    }
}
