//! Doppelganger monitor adapters and import-meta re-arm helpers.

use std::sync::Arc;

use crypto::PublicKey;
use doppelganger::{ForwardWindowMachine, SigningEnablement};
use eth_types::{Epoch, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
use keymanager_api::traits::{DoppelgangerMonitor, Pubkey};
use observability::logging::TruncatedPubkey;
use tracing::{info, warn};

use super::notifier::pubkey_hex;

/// Scan `keystore_dir` for import-meta sidecars and re-arm the doppelganger
/// `gate` for any key whose import timestamp is recent enough that the
/// doppelganger window (`window_secs`) has not yet elapsed.
///
/// Recognizes final `*.import_meta.json` and leftover
/// `*.import_meta.json.removing.*` set-asides from older rename-aside cleanups.
/// A crash that left only the set-aside must still re-arm (fail closed).
///
/// Called once at startup after the doppelganger monitor is created to restore
/// in-memory monitoring state that was lost when the process was restarted.
///
/// # Safety guarantee
/// If the `now - imported_unix < window_secs` check passes, the key is added
/// to the gate's `pending` map with the *current* instant so the residual
/// window is honoured.  This means the gate will still block attestation for
/// the full configured window from the perspective of the restarted process,
/// which is slightly more conservative than replaying the exact residual but
/// is safe.
pub fn scan_and_rearm_gate(
    keystore_dir: &std::path::Path,
    gate: &dyn DoppelgangerMonitor,
    window_secs: u64,
) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(e) => e,
        Err(err) => {
            warn!(
                error = %err,
                dir = %keystore_dir.display(),
                "Could not read keystore directory when scanning import-meta sidecars"
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        let Some((pubkey_bytes, kind)) = crate::config::import_sidecar_pubkey(&name) else {
            continue;
        };
        // Partials are unfinished for boot register, but they have no durable
        // import timestamp yet; wall-clock re-arm only applies to final and
        // leftover `.removing.*` markers.
        if matches!(kind, crate::config::ImportSidecarKind::Partial) {
            continue;
        }

        // Read the sidecar JSON (leftover `.removing.*` still carries the body).
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                warn!(
                    error = %err,
                    path = %path.display(),
                    "Failed to read import_meta sidecar; skipping"
                );
                continue;
            }
        };

        let imported_unix: u64 = match serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| v["imported_unix_seconds"].as_u64())
        {
            Some(t) => t,
            None => {
                // Leftover set-aside: generation was also embedded in the name.
                if let Some(gen) = name.rsplit(".removing.").next().and_then(|s| s.parse().ok()) {
                    gen
                } else {
                    warn!(
                        path = %path.display(),
                        "import_meta sidecar has unexpected format; skipping"
                    );
                    continue;
                }
            }
        };

        let elapsed = now_unix.saturating_sub(imported_unix);
        if elapsed < window_secs {
            let residual = window_secs - elapsed;
            warn!(
                pubkey = %hex::encode(pubkey_bytes),
                residual_secs = residual,
                "Key was imported {elapsed}s ago; doppelganger window has {residual}s remaining \
                 — re-arming gate after restart"
            );
            gate.start_monitoring(pubkey_bytes);
        }
    }
}

/// Always-safe [`DoppelgangerMonitor`] for the doppelganger opt-out path.
///
/// `is_doppelganger_safe` is always `true`. `cancel_monitoring` inherits the
/// trait default (`stop_monitoring`) — both are log-only.
#[derive(Default)]
pub struct DoppelgangerDisabledMonitor;

impl DoppelgangerDisabledMonitor {
    pub fn new() -> Self {
        Self
    }
}

impl DoppelgangerMonitor for DoppelgangerDisabledMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        info!(pubkey = %pubkey_hex(pubkey), "Doppelganger monitoring requested for new key");
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        info!(pubkey = %pubkey_hex(pubkey), "Doppelganger monitoring stop requested");
    }

    fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
        true
    }
}

/// [`DoppelgangerMonitor`] that registers keymanager-imported keys with a
/// production [`ForwardWindowMachine`] (SEC-2b).
///
/// | Call | Machine effect |
/// |------|----------------|
/// | `start_monitoring` | [`ForwardWindowMachine::register_for_import`] (always Pending) |
/// | `stop_monitoring` | **no-op** — M-12 wall-clock elapsed must not cancel machine state |
/// | `cancel_monitoring` | [`ForwardWindowMachine::cancel`] — DELETE / re-import fresh window |
///
/// Safety is the machine's `SigningEnablement` status (fail-closed for
/// Pending/Detected/Unmonitored).
pub struct ForwardWindowMonitor {
    machine: Arc<ForwardWindowMachine>,
    /// Supplies the current epoch for `register_for_import` (prefer
    /// [`doppelganger::MonotonicEpochClock`] shared with boot registration).
    epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync>,
}

impl ForwardWindowMonitor {
    pub fn new(
        machine: Arc<ForwardWindowMachine>,
        epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync>,
    ) -> Self {
        Self { machine, epoch_provider }
    }

    /// Shared handle to the underlying machine (for tests / advanced wiring).
    pub fn machine(&self) -> &Arc<ForwardWindowMachine> {
        &self.machine
    }

    /// Register a newly discovered local key (secret-provider refresh, etc.)
    /// with the same import-strict rules as keymanager import.
    pub fn register_local_key(&self, pubkey: &PublicKey) {
        let epoch = (self.epoch_provider)();
        self.machine.register_for_import(pubkey, epoch);
        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey.to_bytes())),
            epoch,
            "Registered dynamically discovered local key with ForwardWindowMachine (SEC-2b)"
        );
    }
}

impl DoppelgangerMonitor for ForwardWindowMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        match PublicKey::from_bytes(&pubkey) {
            Ok(pk) => {
                let epoch = (self.epoch_provider)();
                // Import-strict: no restart safe-skip, no epoch-0 Safe bypass.
                self.machine.register_for_import(&pk, epoch);
                info!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    epoch,
                    "Registered keymanager-imported key with ForwardWindowMachine (SEC-2b)"
                );
            }
            Err(e) => {
                warn!(
                    pubkey = %hex::encode(pubkey),
                    error = %e,
                    "ForwardWindowMonitor: invalid pubkey on start_monitoring; key left unmonitored (fail-closed)"
                );
            }
        }
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        // SEC-2b review Finding 1: M-12 wall-clock elapsed calls stop_monitoring.
        // That must NOT map to machine.cancel (which would drop Pending/Safe →
        // Unmonitored and fight "window done → may sign" once SEC-2c opens).
        // Validator-store enable is handled separately by the import handler.
        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "ForwardWindowMonitor: stop_monitoring is a no-op for machine state \
             (M-12 wall-clock ≠ forward-window cancel; use cancel_monitoring on DELETE)"
        );
    }

    fn cancel_monitoring(&self, pubkey: &Pubkey) {
        match PublicKey::from_bytes(pubkey) {
            Ok(pk) => {
                self.machine.cancel(&pk);
                info!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    "Cancelled ForwardWindowMachine monitoring for deleted key"
                );
            }
            Err(e) => {
                warn!(
                    pubkey = %hex::encode(pubkey),
                    error = %e,
                    "ForwardWindowMonitor: invalid pubkey on cancel_monitoring"
                );
            }
        }
    }

    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        match PublicKey::from_bytes(pubkey) {
            Ok(pk) => self.machine.is_signing_enabled(&pk),
            // Invalid encoding → fail closed.
            Err(_) => false,
        }
    }
}

/// Wall-clock epoch from genesis.
///
/// Prefer [`doppelganger::MonotonicEpochClock`] for production register paths
/// (M-7). Kept for tests and non-critical fallbacks.
pub fn wall_clock_epoch(genesis_time: u64) -> Epoch {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(genesis_time).saturating_mul(1000) / SLOT_DURATION_MS / SLOTS_PER_EPOCH
}
