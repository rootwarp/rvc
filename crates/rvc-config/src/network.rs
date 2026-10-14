//! Network preset selector (ARCH-4h).
//!
//! Named-network constants (genesis time, GVR, …) are owned by
//! [`eth_types::NetworkPreset`]. This enum is the rvc-side selector, including
//! the `Custom` variant that deliberately has no preset.

use eth_types::NetworkPreset;
use serde::{Deserialize, Serialize};

/// Consensus-network preset used by `[network]` / `--network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Ethereum mainnet.
    #[default]
    Mainnet,
    /// Hoodi testnet.
    Hoodi,
    /// Holesky testnet.
    Holesky,
    /// Sepolia testnet.
    Sepolia,
    /// Operator-supplied genesis; no built-in preset.
    Custom,
}

impl Network {
    /// Shared preset for named networks; `Custom` has none.
    fn preset(self) -> Option<&'static NetworkPreset> {
        match self {
            Network::Mainnet => Some(&NetworkPreset::MAINNET),
            Network::Hoodi => Some(&NetworkPreset::HOODI),
            Network::Holesky => Some(&NetworkPreset::HOLESKY),
            Network::Sepolia => Some(&NetworkPreset::SEPOLIA),
            Network::Custom => None,
        }
    }

    /// Genesis Unix timestamp for named networks.
    pub fn genesis_time(&self) -> Option<u64> {
        self.preset().map(|p| p.genesis_time)
    }

    /// Genesis fork version for named networks.
    pub fn genesis_fork_version(&self) -> Option<[u8; 4]> {
        self.preset().map(|p| p.genesis_fork_version)
    }

    /// Genesis validators root hex for named networks.
    pub fn genesis_validators_root(&self) -> Option<String> {
        self.preset().map(NetworkPreset::genesis_validators_root_hex)
    }

    /// Slot duration in milliseconds (all named networks).
    pub fn slot_duration_ms(&self) -> u64 {
        eth_types::SLOT_DURATION_MS
    }

    /// Slots per epoch (all named networks).
    pub fn slots_per_epoch(&self) -> u64 {
        32
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "hoodi" => Ok(Network::Hoodi),
            "holesky" => Ok(Network::Holesky),
            "sepolia" => Ok(Network::Sepolia),
            "custom" => Ok(Network::Custom),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet | Network::Hoodi | Network::Holesky | Network::Sepolia => {
                // Named variants always have a preset; name is the single source of truth.
                write!(f, "{}", self.preset().expect("named network has preset").name)
            }
            Network::Custom => write!(f, "custom"),
        }
    }
}
