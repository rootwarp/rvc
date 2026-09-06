use crate::BlockSelectionMode;

#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub pubkey: [u8; 48],
    pub fee_recipient: Option<[u8; 20]>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: bool,
    /// Per-validator override. `None` falls through to the store global, then 100.
    pub builder_boost_factor: Option<u64>,
    pub graffiti: Option<[u8; 32]>,
    pub enabled: bool,
    pub block_selection_mode: Option<BlockSelectionMode>,
    /// Per-validator builder URLs. `None` falls through to the store global, then `[]`.
    pub builders: Option<Vec<String>>,
    /// Per-validator min bid (Gwei). `None` falls through to the store global, then 0.
    pub min_bid: Option<u64>,
}

impl ValidatorConfig {
    pub fn new(pubkey: [u8; 48]) -> Self {
        Self {
            pubkey,
            fee_recipient: None,
            gas_limit: None,
            builder_proposals: false,
            builder_boost_factor: None,
            graffiti: None,
            enabled: true,
            block_selection_mode: None,
            builders: None,
            min_bid: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidatorConfigUpdate {
    pub fee_recipient: Option<Option<[u8; 20]>>,
    pub gas_limit: Option<Option<u64>>,
    pub graffiti: Option<Option<[u8; 32]>>,
    pub builder_proposals: Option<bool>,
    pub builder_boost_factor: Option<u64>,
    pub block_selection_mode: Option<Option<BlockSelectionMode>>,
    pub builders: Option<Vec<String>>,
    pub min_bid: Option<u64>,
}

/// Partial update for store-wide defaults ([`crate::ValidatorDefaults`]).
///
/// `None` leaves the current value unchanged. For `graffiti`, the outer
/// `Option` selects whether to touch the field and the inner value sets or
/// clears it (`Some(None)` clears), matching [`ValidatorConfigUpdate`].
#[derive(Debug, Default, Clone)]
pub struct DefaultUpdate {
    pub fee_recipient: Option<[u8; 20]>,
    pub gas_limit: Option<u64>,
    pub graffiti: Option<Option<[u8; 32]>>,
}
