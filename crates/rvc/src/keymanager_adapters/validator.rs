//! Validator store manager adapter for the Keymanager API.

use std::sync::Arc;

use keymanager_api::traits::{Pubkey, ValidatorManager};
use tracing::{error, info, warn};
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
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
        let pubkey_hex = pubkey_hex(pubkey);
        // Disabling a key that can already sign publishes first. Inserting a
        // new key, including a disabled one, persists before it is visible.
        if !enabled && self.validator_store.has_validator(&pubkey) {
            return self.validator_store.set_enabled_durable(&pubkey, false).map_err(|e| {
                error!(
                    pubkey = %pubkey_hex,
                    error = %e,
                    "failed to persist doppelganger disable; validator stays disabled in memory"
                );
                e.to_string()
            });
        }
        let mut config = validator_store::ValidatorConfig::new(pubkey);
        config.enabled = enabled;
        self.validator_store.add_validator_durable(config).map_err(|e| {
            error!(
                pubkey = %pubkey_hex,
                error = %e,
                "failed to persist imported validator; store was not updated"
            );
            e.to_string()
        })?;
        info!(pubkey = %pubkey_hex, enabled, "Added validator to store");
        Ok(())
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
        let pubkey_hex = pubkey_hex(pubkey);
        match self.validator_store.remove_validator_durable(pubkey) {
            Ok(Some(_)) => {
                info!(pubkey = %pubkey_hex, "Removed validator from store");
                Ok(true)
            }
            Ok(None) => {
                warn!(pubkey = %pubkey_hex, "Validator not found in store for removal");
                Ok(false)
            }
            Err(e) => {
                error!(
                    pubkey = %pubkey_hex,
                    error = %e,
                    "failed to persist validator removal; validator remains in the store"
                );
                Err(e.to_string())
            }
        }
    }

    fn begin_doppelganger_hold(&self, pubkey: Pubkey, until_unix: u64) -> Result<bool, String> {
        let pubkey_hex = pubkey_hex(pubkey);
        self.validator_store.begin_doppelganger_hold(&pubkey, until_unix).map_err(|e| {
            error!(
                pubkey = %pubkey_hex,
                error = %e,
                "failed to persist doppelganger hold; validator stays disabled in memory"
            );
            e.to_string()
        })
    }

    fn armed_hold_unix(&self, pubkey: &Pubkey) -> Option<u64> {
        self.validator_store.get_config(pubkey).and_then(|cfg| cfg.doppelganger_hold_until)
    }

    fn is_doppelganger_hold(&self, pubkey: &Pubkey) -> bool {
        self.validator_store
            .get_config(pubkey)
            .and_then(|cfg| cfg.doppelganger_hold_until)
            .is_some()
    }

    fn release_doppelganger_hold(&self, pubkey: &Pubkey) -> Result<bool, String> {
        let pubkey_hex = pubkey_hex(*pubkey);
        self.validator_store.release_doppelganger_hold(pubkey).map_err(|e| {
            error!(
                pubkey = %pubkey_hex,
                error = %e,
                "failed to persist doppelganger re-enable"
            );
            e.to_string()
        })
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
        let pubkey_hex = pubkey_hex(pubkey);
        self.validator_store.set_enabled_durable(pubkey, enabled).map_err(|e| {
            error!(
                pubkey = %pubkey_hex,
                enabled,
                error = %e,
                "failed to persist validator enabled state"
            );
            e.to_string()
        })?;
        info!(pubkey = %pubkey_hex, enabled, "Validator enabled state updated");
        Ok(())
    }
}
