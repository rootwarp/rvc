//! Keymanager API adapters bridging domain traits to VC runtime services.
//!
//! Split one file per adapter (RF6-26 / F6). Shared key-set notification lives in
//! [`notifier::KeyChangeNotifier`].

mod config;
mod doppelganger;
mod kdf_budget;
mod keystore;
mod notifier;
mod remote_keys;
mod slashing;
mod spawn;
mod validator;
mod voluntary_exit;

#[cfg(test)]
mod tests;

pub use config::ValidatorConfigManagerAdapter;
pub use doppelganger::{
    scan_and_rearm_gate, wall_clock_epoch, DoppelgangerDisabledMonitor, ForwardWindowMonitor,
};
pub use keystore::KeystoreManagerAdapter;
pub use notifier::KeyChangeNotifier;
pub use remote_keys::RemoteKeyManagerAdapter;
pub use slashing::SlashingProtectionAdapter;
pub use spawn::{
    build_keymanager_api, keymanager_bind_addr, spawn_keymanager_api, BuiltKeymanagerApi,
    DoppelgangerMonitorKind, KeymanagerApiDeps, SpawnKeymanagerApiError,
};
pub use validator::ValidatorManagerAdapter;
pub use voluntary_exit::VoluntaryExitManagerAdapter;
