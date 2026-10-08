//! Slashing-protection interchange adapter for the Keymanager API.

use std::sync::Arc;

use async_trait::async_trait;
use keymanager_api::traits::{Pubkey, SlashingProtection, SlashingProtectionError};
use slashing::SlashingDb;
use timing::SlotClock;

use super::import_window::{ImportDeferralError, ImportWindowGate};
use super::notifier::pubkey_hex;

pub struct SlashingProtectionAdapter {
    slashing_db: Arc<SlashingDb>,
    genesis_validators_root: eth_types::Root,
    /// The one gate for this database. A second `ImportWindowGate` would not
    /// share [`ImportWindowGate`]'s mutex, so production builds it once.
    gate: Arc<ImportWindowGate>,
    /// Runs inside the blocking import, after the fit re-check and before
    /// `SlashingDb::import`, while the admission guard is still held.
    #[cfg(test)]
    during_import: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl SlashingProtectionAdapter {
    pub(crate) fn new(
        slashing_db: Arc<SlashingDb>,
        genesis_validators_root: eth_types::Root,
        gate: Arc<ImportWindowGate>,
    ) -> Self {
        Self {
            slashing_db,
            genesis_validators_root,
            gate,
            #[cfg(test)]
            during_import: std::sync::Mutex::new(None),
        }
    }

    /// Adapter whose gate clock is already inside the free window.
    ///
    /// Each call builds a private gate. That is enough for a test that only
    /// needs `import_interchange` to proceed; production must pass the single
    /// gate from [`super::spawn::build_keymanager_api`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_in_free_window(
        slashing_db: Arc<SlashingDb>,
        genesis_validators_root: eth_types::Root,
    ) -> Self {
        let clock = Arc::new(timing::MockSlotClock::new(
            1_606_824_023,
            std::time::Duration::from_secs(12),
            32,
        ));
        // Default window is [4_499 ms, 11_800 ms). 8_000 ms is inside it.
        clock.set_slot_with_offset_ms(0, 8_000);
        let gate = Arc::new(ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>));
        Self::new(slashing_db, genesis_validators_root, gate)
    }

    #[cfg(test)]
    pub(crate) fn set_during_import(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.during_import.lock().expect("during_import") = hook;
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

/// Every deferral refuses the import. There is no ungated path.
fn map_deferral(err: ImportDeferralError) -> SlashingProtectionError {
    match err {
        ImportDeferralError::NoFreeWindow { .. } => {
            SlashingProtectionError::NoFreeWindow(format!("NoFreeWindow: {err}"))
        }
        ImportDeferralError::QueueSaturated { retry_after_secs, .. } => {
            SlashingProtectionError::ImportQueueFull { retry_after_secs }
        }
        ImportDeferralError::Clock(err) => SlashingProtectionError::Backend(err.to_string()),
    }
}

fn history_rows(interchange: &slashing::InterchangeFormat) -> usize {
    interchange.data.iter().fold(0usize, |rows, record| {
        rows.saturating_add(record.signed_attestations.len())
            .saturating_add(record.signed_blocks.len())
    })
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[async_trait]
impl SlashingProtection for SlashingProtectionAdapter {
    async fn import_interchange(
        &self,
        interchange_json: &str,
    ) -> Result<(), SlashingProtectionError> {
        // JSON, version, and GVR fail before the gate. `rows` is the parsed
        // history, not a second parse of the text.
        let interchange: slashing::InterchangeFormat = serde_json::from_str(interchange_json)
            .map_err(|e| {
                SlashingProtectionError::InvalidInterchange(format!("invalid JSON: {e}"))
            })?;
        SlashingDb::validate_interchange_metadata(&interchange, &self.genesis_validators_root)
            .map_err(map_slashing_db_error)?;
        let rows = history_rows(&interchange);
        let admission = self.gate.admit(rows).await.map_err(map_deferral)?;

        // Millisecond resolution: a sub-millisecond mutex handshake is not a
        // deferral, and the histogram would otherwise store a 0.
        let wait_ms = millis(admission.wait);
        if wait_ms > 0 {
            let window_ms = millis(admission.window);
            let estimated_hold_ms = millis(admission.estimated_hold);
            slashing::metrics::RVC_SLASHING_IMPORT_DEFERRED_MS.observe(wait_ms as f64);
            tracing::info!(wait_ms, window_ms, estimated_hold_ms, "interchange import deferred");
        }

        let db = Arc::clone(&self.slashing_db);
        let gvr = self.genesis_validators_root;
        #[cfg(test)]
        let during_import = self.during_import.lock().expect("during_import").clone();
        // `Handle::enter` makes `tokio::time::Instant` on the blocking thread
        // see this runtime, including a paused test clock. The re-check uses
        // the `latest_start` captured at admit time; it does not read the slot
        // clock again (a paused `MockSlotClock` would not have moved).
        let handle = tokio::runtime::Handle::current();
        let joined = tokio::task::spawn_blocking(move || {
            let _ctx = handle.enter();
            let result = (|| {
                admission.ensure_still_fits().map_err(map_deferral)?;
                #[cfg(test)]
                if let Some(hook) = during_import.as_ref() {
                    hook();
                }
                db.import(&interchange, &gvr).map_err(map_slashing_db_error)
            })();
            // The guard covers `conn` through COMMIT/rollback. Drop it as soon
            // as `import` returns, including when the HTTP task is gone.
            drop(admission.guard);
            result
        })
        .await
        .map_err(|e| {
            SlashingProtectionError::Backend(format!("interchange import task failed: {e}"))
        })?;
        joined
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
    /// Export is synchronous and does not take the import gate.
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
