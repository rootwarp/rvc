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

use super::notifier::{pubkey_hex, KeyChangeNotifier};

pub struct RemoteKeyManagerAdapter {
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<(Pubkey, String)>>,
    allowed_hosts: Option<Vec<String>>,
    warned_no_allowlist: AtomicBool,
    /// Shared pubkey map + generation notifier for the orchestrator (RF1-06 / RF1-07).
    notifier: KeyChangeNotifier,
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
            tracked_keys: Mutex::new(Vec::new()),
            allowed_hosts,
            warned_no_allowlist: AtomicBool::new(false),
            notifier: KeyChangeNotifier::new(pubkey_map, key_gen_tx),
        }
    }
}

impl RemoteKeyManager for RemoteKeyManagerAdapter {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.tracked_keys.lock().clone()
    }

    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.tracked_keys.lock().iter().any(|(pk, _)| pk == pubkey)
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

        let mut keys = self.tracked_keys.lock();
        if keys.iter().any(|(pk, _)| *pk == pubkey) {
            return Err(ImportRemoteKeyError::Duplicate);
        }

        let config = RemoteSignerConfig::new(url.clone());
        let remote_signer = RemoteSigner::new(config, vec![pubkey])
            .map_err(|e| ImportRemoteKeyError::Backend(e.to_string()))?;

        self.composite_signer.add_remote_key(pubkey, Arc::new(remote_signer));
        keys.push((pubkey, url));

        // Update shared pubkey_map and notify under `tracked_keys` (same lock
        // as registry mutation). Invalid BLS bytes skip the map entry but still
        // advance the generation counter; RF1-07 wires the orchestrator receiver
        // that will clear the duty cache on this notification.
        if let Ok(pk) = PublicKey::from_bytes(&pubkey) {
            self.notifier.pubkey_map().write().insert(pubkey, pk);
        }
        self.notifier.notify();

        info!(pubkey = %pubkey_hex(pubkey), "Imported remote key");
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.tracked_keys.lock();
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            keys.remove(pos);
            self.composite_signer.remove_remote_key(pubkey);

            // Map remove + notify under the same lock as registry mutation (S1).
            self.notifier.remove_and_notify(pubkey);
            drop(keys);

            info!(pubkey = %pubkey_hex(pubkey), "Deleted remote key");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
