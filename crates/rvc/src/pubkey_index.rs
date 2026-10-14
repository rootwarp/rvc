//! Shared BLS pubkey ↔ beacon validator-index registry.
//!
//! Production previously kept three parallel stringly-keyed maps:
//! - `PubkeyMap` keys as `0x`-hex strings
//! - bootstrap `validator_index_map` (`0x`-pubkey → index)
//! - liveness `IndexToPubkeyHex` (index → bare hex)
//!
//! Hot paths (`prepare_proposers`, duty matching) paid O(validators × slots ×
//! duties) linear scans plus repeated hex normalization. This registry is the
//! single source of truth for index resolution, keyed by compressed BLS
//! pubkey bytes (`[u8; 48]`).

use std::collections::HashMap;
use std::sync::Arc;

use duty_tracker::ValidatorIndexSource;
use parking_lot::RwLock;

use crate::orchestrator::PubkeyMap;

/// Shared handle for the pubkey→index registry.
pub type SharedPubkeyIndexRegistry = Arc<RwLock<PubkeyIndexRegistry>>;

/// Bidirectional registry: compressed BLS pubkey ↔ numeric validator index.
///
/// The reverse direction stores **bare lowercase hex** so the forward-window
/// liveness machine can key state without a `0x` prefix (SEC-001).
#[derive(Debug, Default, Clone)]
pub struct PubkeyIndexRegistry {
    /// Compressed BLS pubkey bytes → numeric index string from the BN.
    by_pubkey: HashMap<[u8; 48], String>,
    /// Numeric index → bare lowercase pubkey hex (machine state key).
    by_index: HashMap<String, String>,
}

impl PubkeyIndexRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared empty registry handle (tests / opt-out paths).
    pub fn shared() -> SharedPubkeyIndexRegistry {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Insert or replace a pubkey → index mapping (both directions).
    pub fn insert(&mut self, pubkey: [u8; 48], index: String) {
        let bare = hex::encode(pubkey);
        // Drop stale reverse entry if this pubkey previously had another index.
        if let Some(old_index) = self.by_pubkey.insert(pubkey, index.clone()) {
            if old_index != index {
                self.by_index.remove(&old_index);
            }
        }
        self.by_index.insert(index, bare);
    }

    /// Insert from a hex pubkey string (`0x` / `0X` / bare, any case).
    ///
    /// Returns `false` if `pubkey_hex` is not valid 48-byte hex (entry skipped).
    pub fn insert_hex(&mut self, pubkey_hex: &str, index: String) -> bool {
        match parse_pubkey_bytes(pubkey_hex) {
            Some(bytes) => {
                self.insert(bytes, index);
                true
            }
            None => false,
        }
    }

    /// Look up the numeric index for a compressed pubkey.
    pub fn index_of(&self, pubkey: &[u8; 48]) -> Option<&str> {
        self.by_pubkey.get(pubkey).map(String::as_str)
    }

    /// Look up bare lowercase hex for a numeric index (liveness machine key).
    pub fn bare_hex_of_index(&self, index: &str) -> Option<&str> {
        self.by_index.get(index).map(String::as_str)
    }

    /// Borrow the reverse map (index → bare hex) for liveness observation.
    pub fn index_to_bare_hex(&self) -> &HashMap<String, String> {
        &self.by_index
    }

    /// All known numeric index strings (duty-tracker subscription set).
    pub fn indices(&self) -> impl Iterator<Item = &String> {
        self.by_index.keys()
    }

    /// Number of registered pubkeys.
    pub fn len(&self) -> usize {
        self.by_pubkey.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.by_pubkey.is_empty()
    }

    /// Merge entries from a pubkey-hex → index map (import / refresh paths).
    pub fn merge_hex_map(&mut self, pubkey_to_index: &HashMap<String, String>) {
        for (pubkey, index) in pubkey_to_index {
            let _ = self.insert_hex(pubkey, index.clone());
        }
    }

    /// Merge entries already keyed by compressed bytes.
    pub fn merge_bytes_map(&mut self, pubkey_to_index: &HashMap<[u8; 48], String>) {
        for (pubkey, index) in pubkey_to_index {
            self.insert(*pubkey, index.clone());
        }
    }

    /// Merge all entries from another registry.
    pub fn extend_from(&mut self, other: &PubkeyIndexRegistry) {
        for (pubkey, index) in &other.by_pubkey {
            self.insert(*pubkey, index.clone());
        }
    }
}

/// Decode a BLS pubkey hex string to compressed bytes.
///
/// Accepts optional `0x` / `0X` prefix; hex digits are case-insensitive.
/// Returns `None` if the string is not valid hex or not exactly 48 bytes.
pub fn parse_pubkey_bytes(s: &str) -> Option<[u8; 48]> {
    let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Format compressed pubkey bytes as `0x`-prefixed lowercase hex.
pub fn pubkey_bytes_to_0x(bytes: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Duty indices are [`PubkeyIndexRegistry`] ∩ [`PubkeyMap`] (ADR-R06).
///
/// [`PubkeyIndexRegistry`] has no `remove`. A deleted key stays in the registry
/// and drops out of this set when it leaves the pubkey map. `indices` holds one
/// read lock on each map for the whole intersection, then returns one snapshot.
/// Order is lexicographic (`sort` then `dedup`), a total order on the strings.
pub struct PubkeyIndexSource {
    pub registry: SharedPubkeyIndexRegistry,
    pub pubkey_map: PubkeyMap,
}

impl ValidatorIndexSource for PubkeyIndexSource {
    fn indices(&self) -> Vec<String> {
        let map = self.pubkey_map.read();
        let registry = self.registry.read();
        let mut indices: Vec<String> =
            map.keys().filter_map(|pk| registry.index_of(pk).map(str::to_owned)).collect();
        indices.sort();
        indices.dedup();
        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup_both_directions() {
        let mut reg = PubkeyIndexRegistry::new();
        let pk = [0xab; 48];
        reg.insert(pk, "42".to_string());
        assert_eq!(reg.index_of(&pk), Some("42"));
        assert_eq!(reg.bare_hex_of_index("42"), Some(hex::encode(pk).as_str()));
    }

    #[test]
    fn test_insert_hex_canonicalizes_case_and_prefix() {
        let mut reg = PubkeyIndexRegistry::new();
        let pk = [0xcd; 48];
        let upper = format!("0X{}", hex::encode(pk).to_uppercase());
        assert!(reg.insert_hex(&upper, "7".to_string()));
        assert_eq!(reg.index_of(&pk), Some("7"));
        assert_eq!(reg.bare_hex_of_index("7"), Some(hex::encode(pk).as_str()));
    }

    #[test]
    fn test_insert_hex_rejects_invalid() {
        let mut reg = PubkeyIndexRegistry::new();
        assert!(!reg.insert_hex("0xzz", "1".to_string()));
        assert!(!reg.insert_hex("0xabcd", "1".to_string())); // too short
        assert!(reg.is_empty());
    }

    #[test]
    fn test_parse_pubkey_bytes_case_insensitive() {
        let pk = [0x11; 48];
        let lower = format!("0x{}", hex::encode(pk));
        let upper = format!("0X{}", hex::encode(pk).to_uppercase());
        let bare = hex::encode(pk).to_uppercase();
        assert_eq!(parse_pubkey_bytes(&lower), Some(pk));
        assert_eq!(parse_pubkey_bytes(&upper), Some(pk));
        assert_eq!(parse_pubkey_bytes(&bare), Some(pk));
    }

    #[test]
    fn test_merge_hex_map() {
        let mut reg = PubkeyIndexRegistry::new();
        let pk = [0xee; 48];
        let mut m = HashMap::new();
        m.insert(format!("0x{}", hex::encode(pk)), "99".to_string());
        reg.merge_hex_map(&m);
        assert_eq!(reg.index_of(&pk), Some("99"));
    }

    #[test]
    fn indices_are_registry_intersect_pubkey_map() {
        use crypto::SecretKey;

        let registry = PubkeyIndexRegistry::shared();
        let kept = SecretKey::generate().public_key();
        let registry_only = SecretKey::generate().public_key();
        let map_only = SecretKey::generate().public_key();
        registry.write().insert(kept.to_bytes(), "10".to_string());
        registry.write().insert(registry_only.to_bytes(), "2".to_string());

        let mut map = HashMap::new();
        map.insert(kept.to_bytes(), kept);
        map.insert(map_only.to_bytes(), map_only);
        let source = PubkeyIndexSource {
            registry: Arc::clone(&registry),
            pubkey_map: Arc::new(RwLock::new(map)),
        };

        assert_eq!(source.indices(), vec!["10".to_string()]);
        assert_eq!(registry.read().index_of(&registry_only.to_bytes()), Some("2"));
    }

    #[test]
    fn index_snapshot_order_is_lexicographic() {
        use crypto::SecretKey;

        let registry = PubkeyIndexRegistry::shared();
        let two = SecretKey::generate().public_key();
        let ten = SecretKey::generate().public_key();
        registry.write().insert(two.to_bytes(), "2".to_string());
        registry.write().insert(ten.to_bytes(), "10".to_string());
        let mut map = HashMap::new();
        map.insert(two.to_bytes(), two);
        map.insert(ten.to_bytes(), ten);
        let source = PubkeyIndexSource { registry, pubkey_map: Arc::new(RwLock::new(map)) };
        // Total order: "10" < "2". Numeric order would panic or cycle on mixed keys.
        assert_eq!(source.indices(), vec!["10".to_string(), "2".to_string()]);
    }
}
