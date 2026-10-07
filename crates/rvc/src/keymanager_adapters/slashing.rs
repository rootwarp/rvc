//! Slashing-protection interchange adapter for the Keymanager API.

use std::sync::Arc;

use async_trait::async_trait;
use keymanager_api::traits::{Pubkey, SlashingProtection, SlashingProtectionError};
use slashing::SlashingDb;

use super::notifier::pubkey_hex;

pub struct SlashingProtectionAdapter {
    slashing_db: Arc<SlashingDb>,
    genesis_validators_root: eth_types::Root,
}

impl SlashingProtectionAdapter {
    pub fn new(slashing_db: Arc<SlashingDb>, genesis_validators_root: eth_types::Root) -> Self {
        Self { slashing_db, genesis_validators_root }
    }
}

/// Map a slashing-DB error into a keymanager trait error.
///
/// Client-caused interchange/GVR problems become `InvalidInterchange`;
/// everything else (DB I/O, integrity, permissions with paths) is `Backend`.
fn map_slashing_db_error(e: slashing::SlashingError) -> SlashingProtectionError {
    use slashing::SlashingError;
    match e {
        SlashingError::InvalidInterchangeFormat(msg) => {
            SlashingProtectionError::InvalidInterchange(msg)
        }
        SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
            SlashingProtectionError::InvalidInterchange(format!(
                "genesis validators root mismatch: expected {expected}, got {actual}"
            ))
        }
        SlashingError::GenesisRootMismatch { expected, got } => {
            SlashingProtectionError::InvalidInterchange(format!(
                "genesis root mismatch: expected 0x{}, got 0x{}",
                hex::encode(expected),
                hex::encode(got)
            ))
        }
        other => SlashingProtectionError::Backend(other.to_string()),
    }
}

#[async_trait]
impl SlashingProtection for SlashingProtectionAdapter {
    async fn import_interchange(
        &self,
        interchange_json: &str,
    ) -> Result<(), SlashingProtectionError> {
        let interchange: slashing::InterchangeFormat = serde_json::from_str(interchange_json)
            .map_err(|e| {
                SlashingProtectionError::InvalidInterchange(format!("invalid JSON: {e}"))
            })?;
        self.slashing_db
            .import(&interchange, &self.genesis_validators_root)
            .map_err(map_slashing_db_error)
    }

    /// Export an EIP-3076 interchange blob for the specified public keys.
    ///
    /// # Atomicity contract (ADR-008 / KM-1)
    ///
    /// This function is all-or-nothing: either the interchange for every
    /// requested key is returned, or `Err` is returned and no partial
    /// interchange is emitted.  The underlying `SlashingDb::export` holds a
    /// single `Mutex<Connection>` lock for the entire read — `read_all_pubkeys`,
    /// `read_attestations`, and `read_blocks` all execute under that one held
    /// guard — so no concurrent `seed_attestation`/`seed_block` write can
    /// interleave and produce a stale snapshot.
    ///
    /// # Completeness (KM-1(a))
    ///
    /// Every requested pubkey is represented in the output. A key that
    /// [`SlashingDb::export`](slashing::SlashingDb::export) already emitted —
    /// including a watermark-only synthetic floor — is kept as exported.
    /// A requested key with neither rows nor watermarks is absent from that
    /// export and is filled in as an explicit empty record.
    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        let interchange = self
            .slashing_db
            .export(&self.genesis_validators_root)
            .map_err(map_slashing_db_error)?;

        // Build a canonical hex-string set for fast membership lookup.
        let requested: std::collections::HashSet<String> = pubkeys.iter().map(pubkey_hex).collect();

        // Collect DB records for requested keys.
        let mut filtered_data: Vec<_> = interchange
            .data
            .into_iter()
            .filter(|record| requested.contains(&record.pubkey))
            .collect();

        // KM-1(a): append an explicit empty record for every requested key
        // absent from the DB export, so the interchange covers all deleted keys.
        // Collect the keys to add first to avoid holding a shared borrow of
        // filtered_data while also pushing into it.
        let exported_pubkeys: std::collections::HashSet<String> =
            filtered_data.iter().map(|r| r.pubkey.clone()).collect();
        let missing: Vec<String> =
            requested.into_iter().filter(|pk| !exported_pubkeys.contains(pk)).collect();
        for pk_hex in missing {
            filtered_data.push(slashing::ValidatorRecord {
                pubkey: pk_hex,
                signed_blocks: vec![],
                signed_attestations: vec![],
            });
        }

        let filtered =
            slashing::InterchangeFormat { metadata: interchange.metadata, data: filtered_data };

        serde_json::to_string(&filtered)
            .map_err(|e| SlashingProtectionError::Backend(format!("serialization failed: {e}")))
    }
}
