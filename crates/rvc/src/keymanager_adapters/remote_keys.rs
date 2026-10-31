//! Remote key manager adapter for the Keymanager API.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crypto::{CompositeSigner, PublicKey};
use keymanager_api::traits::{
    DeleteRemoteKeyError, ImportRemoteKeyError, Pubkey, RemoteKeyManager,
};
use remote_signer_client::{RemoteSigner, RemoteSignerConfig};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::PubkeyMap;
use crate::quiesce::TrackedKeys;

use super::notifier::{pubkey_hex, KeyChangeNotifier};

/// Adapts `CompositeSigner` HTTP remote keys to the Keymanager `RemoteKeyManager` trait.
///
/// # Lock order
///
/// `state_lock` (DELETE only) → [`TrackedKeys`] → `remote_keys` → composite
/// maps → `PubkeyMap`, the order the keystore adapter's DELETE uses. Import
/// and delete hold `tracked_keys` for the whole section, so the cross-backend
/// duplicate check and the insert cannot interleave with a keystore import.
pub struct RemoteKeyManagerAdapter {
    composite_signer: Arc<CompositeSigner>,
    /// Keymanager-imported remote keys and their URLs. Changed only while
    /// `tracked_keys` is held.
    remote_keys: Mutex<Vec<(Pubkey, String)>>,
    /// The key-set lock shared with the keystore adapter. Used only as a lock:
    /// remote pubkeys are not pushed into it.
    tracked_keys: Arc<TrackedKeys>,
    allowed_hosts: Option<Vec<String>>,
    warned_no_allowlist: AtomicBool,
    /// Shared pubkey map + generation notifier for the orchestrator (RF1-06 / RF1-07).
    notifier: KeyChangeNotifier,
    /// Runs inside import and delete with both locks held, at
    /// `"before_change"` and at `"after_change"`.
    #[cfg(test)]
    section_hook: Mutex<Option<SectionHook>>,
}

impl RemoteKeyManagerAdapter {
    pub fn new(
        composite_signer: Arc<CompositeSigner>,
        allowed_hosts: Option<Vec<String>>,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        Self {
            composite_signer,
            remote_keys: Mutex::new(Vec::new()),
            tracked_keys: Arc::new(TrackedKeys::new()),
            allowed_hosts,
            warned_no_allowlist: AtomicBool::new(false),
            notifier: KeyChangeNotifier::new(pubkey_map, key_gen_tx),
            #[cfg(test)]
            section_hook: Mutex::new(None),
        }
    }

    /// Share the process-wide key-set lock with the keystore adapter.
    ///
    /// Production passes the same [`TrackedKeys`] as
    /// `KeystoreManagerAdapter::with_tracked_keys`.
    #[must_use]
    pub fn with_tracked_keys(mut self, tracked_keys: Arc<TrackedKeys>) -> Self {
        self.tracked_keys = tracked_keys;
        self
    }
}

#[cfg(test)]
type SectionHook = Arc<dyn Fn(&'static str) + Send + Sync>;

#[cfg(test)]
impl RemoteKeyManagerAdapter {
    pub(crate) fn set_section_hook(&self, hook: SectionHook) {
        *self.section_hook.lock() = Some(hook);
    }

    fn run_section_hook(&self, point: &'static str) {
        let hook = self.section_hook.lock().clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }
}

impl RemoteKeyManager for RemoteKeyManagerAdapter {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.remote_keys.lock().clone()
    }

    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.remote_keys.lock().iter().any(|(pk, _)| pk == pubkey)
    }

    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError> {
        let parsed =
            url::Url::parse(&url).map_err(|e| ImportRemoteKeyError::InvalidUrl(e.to_string()))?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(ImportRemoteKeyError::InvalidUrl(format!(
                    "must be http:// or https://, got: {scheme}://"
                )));
            }
        }

        if let Some(ref allowed) = self.allowed_hosts {
            let host = parsed.host_str().unwrap_or("");
            if !allowed.iter().any(|h| h == host) {
                return Err(ImportRemoteKeyError::HostNotAllowed(host.to_string()));
            }
        } else if !self.warned_no_allowlist.swap(true, Ordering::Relaxed) {
            warn!(
                "No remote signer host allowlist configured; all HTTP/HTTPS hosts are accepted. \
                 Consider setting --remote-signer-allowed-hosts for production use"
            );
        }

        let _key_set = self.tracked_keys.lock();
        let mut keys = self.remote_keys.lock();
        // A pubkey in any backend, this one included, is a duplicate. The
        // keystore import makes the same check under `tracked_keys`.
        if self.composite_signer.has_any_backend(&pubkey) {
            return Err(ImportRemoteKeyError::Duplicate);
        }

        let config = RemoteSignerConfig::new(url.clone());
        let remote_signer = RemoteSigner::new(config, vec![pubkey])
            .map_err(|e| ImportRemoteKeyError::Backend(e.to_string()))?;

        #[cfg(test)]
        self.run_section_hook("before_change");
        self.composite_signer.add_remote_key(pubkey, Arc::new(remote_signer));
        keys.push((pubkey, url));

        // Update shared pubkey_map and notify under the same locks as the
        // registry mutation. Invalid BLS bytes skip the map entry but still
        // advance the generation counter; RF1-07 wires the orchestrator receiver
        // that will clear the duty cache on this notification.
        if let Ok(pk) = PublicKey::from_bytes(&pubkey) {
            self.notifier.pubkey_map().write().insert(pubkey, pk);
        }
        self.notifier.notify();
        #[cfg(test)]
        self.run_section_hook("after_change");

        info!(pubkey = %pubkey_hex(pubkey), "Imported remote key");
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let _key_set = self.tracked_keys.lock();
        let mut keys = self.remote_keys.lock();
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            #[cfg(test)]
            self.run_section_hook("before_change");
            keys.remove(pos);
            self.composite_signer.remove_remote_key(pubkey);

            // Map remove + notify under the same lock as registry mutation (S1).
            self.notifier.remove_and_notify(pubkey);
            #[cfg(test)]
            self.run_section_hook("after_change");
            drop(keys);

            info!(pubkey = %pubkey_hex(pubkey), "Deleted remote key");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
