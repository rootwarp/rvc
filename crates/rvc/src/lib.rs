//! rvc - Rust Validator Client

pub mod background_tasks;
pub mod beacon_adapter;
pub mod bootstrap;
pub mod config;
pub mod deletion_denylist;
pub mod detection_marker;
pub mod index_resolver;
pub mod key_admission;
pub mod keymanager_adapters;
pub mod liveness_loop;

#[cfg(test)]
mod detection_stop;
pub mod metrics;
pub mod orchestrator;
pub mod pubkey_index;
pub mod quiesce;
pub mod slashing_monitor;
pub mod startup;
