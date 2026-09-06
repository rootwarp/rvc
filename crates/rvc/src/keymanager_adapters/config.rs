//! Per-validator config (fee recipient / gas / graffiti) adapter.

use std::sync::Arc;

use keymanager_api::error::ApiError;
use keymanager_api::traits::{Pubkey, ValidatorConfigManager};
use validator_store::{ValidatorConfigUpdate, ValidatorStore};

use super::notifier::pubkey_hex;

pub struct ValidatorConfigManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorConfigManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }

    fn ensure_validator_exists(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        if !self.validator_store.has_validator(pubkey) {
            return Err(ApiError::NotFound(format!("validator {} not found", pubkey_hex(pubkey))));
        }
        Ok(())
    }

    fn update_and_save(
        &self,
        pubkey: &Pubkey,
        update: ValidatorConfigUpdate,
    ) -> Result<(), ApiError> {
        self.validator_store
            .update_config(pubkey, update)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        self.validator_store.save_config().map_err(|e| ApiError::Internal(e.to_string()))
    }
}

impl ValidatorConfigManager for ValidatorConfigManagerAdapter {
    fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_fee_recipient(pubkey))
    }

    fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { fee_recipient: Some(Some(address)), ..Default::default() },
        )
    }

    fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { fee_recipient: Some(None), ..Default::default() },
        )
    }

    fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_gas_limit(pubkey))
    }

    fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { gas_limit: Some(Some(limit)), ..Default::default() },
        )
    }

    fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { gas_limit: Some(None), ..Default::default() },
        )
    }

    fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        let graffiti = self.validator_store.effective_graffiti(pubkey);
        Ok(match graffiti {
            Some(g) => {
                let end = g.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                String::from_utf8_lossy(&g[..end]).into_owned()
            }
            None => String::new(),
        })
    }

    fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        let mut bytes = [0u8; 32];
        let src = graffiti.as_bytes();
        let len = src.len().min(32);
        bytes[..len].copy_from_slice(&src[..len]);
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { graffiti: Some(Some(bytes)), ..Default::default() },
        )
    }

    fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { graffiti: Some(None), ..Default::default() },
        )
    }
}
