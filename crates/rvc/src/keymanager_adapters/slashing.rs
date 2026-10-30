//! Slashing-protection interchange adapter for the Keymanager API.

use std::sync::Arc;

use async_trait::async_trait;
use keymanager_api::traits::{
    ExportedInterchange, Pubkey, SlashingProtection, SlashingProtectionError,
};
use slashing::SlashingDb;
#[cfg(any(test, feature = "test-utils"))]
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
    /// Runs on the blocking thread at the start of the history-row count,
    /// before `conn` is taken and before the gate.
    #[cfg(test)]
    during_row_count: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs on the async task after the row count returns and before
    /// `admit_capped`. Non-blocking.
    #[cfg(test)]
    before_export_admit: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs on the async task after `admit_capped` returns and before the
    /// export `spawn_blocking`. Non-blocking. The admission guard is held.
    #[cfg(test)]
    after_export_admitted: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs on the blocking export thread after `Handle::enter` and before
    /// `ensure_still_fits`. The admission guard is held.
    #[cfg(test)]
    before_export_fit: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs inside the blocking export, after the fit re-check and before
    /// `export_pubkeys`, while the admission guard is still held.
    #[cfg(test)]
    during_export: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs inside the blocking export after `export_pubkeys` returns and
    /// before the admission guard is dropped.
    #[cfg(test)]
    after_export_read: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// When set, the next row-count stage returns an error instead of the
    /// database count. One shot. The real count is not substituted with 0.
    #[cfg(test)]
    fail_row_count: std::sync::atomic::AtomicBool,
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
            #[cfg(test)]
            during_row_count: std::sync::Mutex::new(None),
            #[cfg(test)]
            before_export_admit: std::sync::Mutex::new(None),
            #[cfg(test)]
            after_export_admitted: std::sync::Mutex::new(None),
            #[cfg(test)]
            before_export_fit: std::sync::Mutex::new(None),
            #[cfg(test)]
            during_export: std::sync::Mutex::new(None),
            #[cfg(test)]
            after_export_read: std::sync::Mutex::new(None),
            #[cfg(test)]
            fail_row_count: std::sync::atomic::AtomicBool::new(false),
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

    /// Adapter whose gate follows `clock`.
    ///
    /// RR3-07 passes the pipeline fixture's clock so the import waits on that
    /// slot's free window. Each call builds a private gate, same as
    /// [`Self::new_in_free_window`]. Production still passes the single gate
    /// from [`super::spawn::build_keymanager_api`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_on_clock(
        slashing_db: Arc<SlashingDb>,
        genesis_validators_root: eth_types::Root,
        clock: Arc<dyn SlotClock>,
    ) -> Self {
        let gate = Arc::new(ImportWindowGate::new(clock));
        Self::new(slashing_db, genesis_validators_root, gate)
    }

    #[cfg(test)]
    pub(crate) fn set_during_import(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.during_import.lock().expect("during_import") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_during_row_count(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.during_row_count.lock().expect("during_row_count") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_before_export_admit(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.before_export_admit.lock().expect("before_export_admit") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_after_export_admitted(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.after_export_admitted.lock().expect("after_export_admitted") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_before_export_fit(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.before_export_fit.lock().expect("before_export_fit") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_during_export(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.during_export.lock().expect("during_export") = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_after_export_read(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.after_export_read.lock().expect("after_export_read") = hook;
    }

    /// The next `history_row_count` stage fails. The count is not read as 0.
    #[cfg(test)]
    pub(crate) fn fail_next_history_row_count(&self) {
        self.fail_row_count.store(true, std::sync::atomic::Ordering::SeqCst);
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
        SlashingError::OutOfRange { field, value } => SlashingProtectionError::InvalidInterchange(
            format!("out of range: {field}={value} exceeds i64::MAX ({})", i64::MAX),
        ),
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

fn export_task_error(err: tokio::task::JoinError) -> SlashingProtectionError {
    SlashingProtectionError::Backend(format!("interchange export task failed: {err}"))
}

#[cfg(test)]
fn run_test_hook(hook: &Option<Arc<dyn Fn() + Send + Sync>>) {
    if let Some(hook) = hook {
        hook();
    }
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
        SlashingDb::validate_interchange_ranges(&interchange).map_err(map_slashing_db_error)?;
        let rows = history_rows(&interchange);
        let admission = self.gate.admit(rows).await.map_err(map_deferral)?;

        // Millisecond resolution: a sub-millisecond mutex handshake is not a
        // deferral, and the histogram would otherwise store a 0.
        let wait_ms = millis(admission.wait);
        if wait_ms > 0 {
            let window_ms = millis(admission.window);
            let estimated_hold_ms = millis(admission.estimated_hold);
            let observe = || {
                slashing::metrics::RVC_SLASHING_IMPORT_DEFERRED_MS.observe(wait_ms as f64);
            };
            observe();
            #[cfg(any(test, feature = "test-utils"))]
            crate::test_metrics::add_import_deferred(wait_ms as f64);
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

    /// Export an EIP-3076 interchange for the requested public keys.
    ///
    /// # Atomicity contract (ADR-008 / KM-1)
    ///
    /// All-or-nothing over the requested keys: either every requested key is
    /// represented, or `Err` is returned and no partial interchange is emitted.
    /// [`SlashingDb::export_pubkeys`](slashing::SlashingDb::export_pubkeys) holds
    /// one `conn` lock for the whole read and runs the per-validator export
    /// only for those keys. An unrepresentable floor on a key that was not
    /// requested does not fail this call. A requested key that cannot be
    /// represented does.
    ///
    /// The history count and the export each run on a `spawn_blocking` thread.
    /// The count takes `conn` and drops it before this function awaits the
    /// import-window gate. [`ImportWindowGate::admit_capped`](super::import_window::ImportWindowGate::admit_capped)
    /// then admits the export. The admission guard moves into the export
    /// closure and is dropped only after `export_pubkeys` returns, including
    /// when the caller has gone. A count error, a [`tokio::task::JoinError`],
    /// or a late fit check fails the export and removes nothing.
    ///
    /// # Completeness (KM-1(a))
    ///
    /// Every requested pubkey is represented. A key with neither rows nor
    /// watermarks is an explicit empty record. `with_history` lists the
    /// requested keys that had any row or any watermark.
    async fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<ExportedInterchange, SlashingProtectionError> {
        let requested: Vec<String> = pubkeys.iter().map(pubkey_hex).collect();
        let count_keys = requested.clone();
        let db = Arc::clone(&self.slashing_db);
        let handle = tokio::runtime::Handle::current();
        #[cfg(test)]
        let during_row_count = self.during_row_count.lock().expect("during_row_count").clone();
        #[cfg(test)]
        let fail_row_count = self.fail_row_count.swap(false, std::sync::atomic::Ordering::SeqCst);
        // The count's `conn` guard lives inside `history_row_count` and is
        // dropped before this await completes. The gate is awaited next,
        // with no `conn` held.
        let rows = tokio::task::spawn_blocking(move || {
            let _ctx = handle.enter();
            #[cfg(test)]
            run_test_hook(&during_row_count);
            #[cfg(test)]
            if fail_row_count {
                return Err(slashing::SlashingError::InternalInvariant(
                    "injected history_row_count failure",
                ));
            }
            db.history_row_count(&count_keys)
        })
        .await
        .map_err(export_task_error)?
        .map_err(map_slashing_db_error)?;

        #[cfg(test)]
        {
            let hook = self.before_export_admit.lock().expect("before_export_admit").clone();
            run_test_hook(&hook);
        }
        let admission = self.gate.admit_capped(rows).await.map_err(map_deferral)?;
        #[cfg(test)]
        {
            let hook = self.after_export_admitted.lock().expect("after_export_admitted").clone();
            run_test_hook(&hook);
        }

        let wait_ms = millis(admission.wait);
        if wait_ms > 0 {
            let window_ms = millis(admission.window);
            let estimated_hold_ms = millis(admission.estimated_hold);
            tracing::info!(
                wait_ms,
                window_ms,
                estimated_hold_ms,
                "keymanager delete export deferred"
            );
        }

        let db = Arc::clone(&self.slashing_db);
        let gvr = self.genesis_validators_root;
        let handle = tokio::runtime::Handle::current();
        #[cfg(test)]
        let before_export_fit = self.before_export_fit.lock().expect("before_export_fit").clone();
        #[cfg(test)]
        let during_export = self.during_export.lock().expect("during_export").clone();
        #[cfg(test)]
        let after_export_read = self.after_export_read.lock().expect("after_export_read").clone();
        // `admission` moves into the closure here. `admission.guard` is
        // dropped only after `export_pubkeys` returns, on this blocking
        // thread, including when the caller has been dropped.
        let (json, with_history_hex) = tokio::task::spawn_blocking(move || {
            let _ctx = handle.enter();
            let result = (|| {
                #[cfg(test)]
                run_test_hook(&before_export_fit);
                admission.ensure_still_fits().map_err(map_deferral)?;
                #[cfg(test)]
                run_test_hook(&during_export);
                let (interchange, with_history) =
                    db.export_pubkeys(&gvr, &requested).map_err(map_slashing_db_error)?;
                #[cfg(test)]
                run_test_hook(&after_export_read);
                let json = serde_json::to_string(&interchange).map_err(|e| {
                    SlashingProtectionError::Backend(format!("serialization failed: {e}"))
                })?;
                Ok((json, with_history))
            })();
            drop(admission.guard);
            result
        })
        .await
        .map_err(export_task_error)??;

        let mut with_history = Vec::with_capacity(with_history_hex.len());
        for hex_key in with_history_hex {
            with_history.push(pubkey_from_canonical_hex(&hex_key)?);
        }
        Ok(ExportedInterchange { json, with_history })
    }
}

fn pubkey_from_canonical_hex(hex_key: &str) -> Result<Pubkey, SlashingProtectionError> {
    eth_types::canonical::pubkey_hex::parse_pubkey_hex(hex_key)
        .map(|parsed| *parsed.as_bytes())
        .map_err(|_| {
            SlashingProtectionError::Backend(
                "slashing export returned a pubkey that is not 48 bytes".into(),
            )
        })
}
