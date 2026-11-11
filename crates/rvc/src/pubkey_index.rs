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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bn_manager::RevocationCommit;
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
    /// Revocation generation the entries follow; `None` when untracked.
    revocation: Option<Arc<AtomicU64>>,
    /// Generation the entries were last validated under.
    validated_gen: Option<u64>,
    /// The revoker's commit lock; see [`RevocationCommit`].
    commit: Option<Arc<RevocationCommit>>,
}

/// Whether the registry's indices may be acted on.
///
/// `Fresh(g)` is a comparable token. A caller that awaits between reading
/// indices and acting on them can compare it again afterwards: it changes on
/// every revocation and on every revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryFreshness {
    /// No revocation generation is attached; every index is served.
    Untracked,
    /// Validated under generation `g`, which is still the current one.
    Fresh(u64),
    /// A revocation since the last validation; no index may be acted on.
    Stale,
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

    /// Follow `revocation`, with the entries validated under `validated_gen`.
    ///
    /// Boot passes a generation sampled before its index fetch, so a
    /// revocation during the fetch leaves the registry [`RegistryFreshness::Stale`].
    pub(crate) fn attach_revocation(&mut self, revocation: Arc<AtomicU64>, validated_gen: u64) {
        self.revocation = Some(revocation);
        self.validated_gen = Some(validated_gen);
    }

    /// Share `commit`, the lock the revoker holds around each generation bump.
    ///
    /// The index resolver holds it around [`Self::revalidate`], and the
    /// liveness loop from its freshness check through its state write.
    pub(crate) fn attach_commit(&mut self, commit: Arc<RevocationCommit>) {
        self.commit = Some(commit);
    }

    /// The attached commit lock, or `None` when none is attached.
    pub(crate) fn revocation_commit(&self) -> Option<Arc<RevocationCommit>> {
        self.commit.clone()
    }

    /// Current revocation generation, or `None` when untracked.
    pub(crate) fn generation(&self) -> Option<u64> {
        self.revocation.as_ref().map(|current| current.load(Ordering::Acquire))
    }

    /// Freshness of the entries. Call it under the registry lock you read them with.
    pub(crate) fn freshness(&self) -> RegistryFreshness {
        match self.generation() {
            None => RegistryFreshness::Untracked,
            Some(now) if self.validated_gen == Some(now) => RegistryFreshness::Fresh(now),
            Some(_) => RegistryFreshness::Stale,
        }
    }

    /// `false` only while [`RegistryFreshness::Stale`].
    pub(crate) fn is_fresh(&self) -> bool {
        self.freshness() != RegistryFreshness::Stale
    }

    /// Replace every entry with a revalidation `answer` requested under `seen`.
    ///
    /// Call it under the write lock. If the generation is no longer `seen`,
    /// nothing changes and this returns `false`. Otherwise the entries become
    /// exactly `answer` (an omitted key loses both directions), the registry is
    /// stamped `seen`, and this returns `true`.
    pub(crate) fn revalidate(&mut self, seen: u64, answer: &HashMap<[u8; 48], String>) -> bool {
        if self.generation() != Some(seen) {
            return false;
        }
        #[cfg(test)]
        hooks::after_revalidate_check();
        self.by_pubkey.clear();
        self.by_index.clear();
        for (pubkey, index) in answer {
            self.insert(*pubkey, index.clone());
        }
        self.validated_gen = Some(seen);
        true
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
/// A deleted key stays in the registry until the next revalidation, and drops
/// out of this set when it leaves the pubkey map. While a revocation leaves the
/// registry [`RegistryFreshness::Stale`], the set is empty. `indices` holds one
/// read lock on each map for the whole intersection, then returns one snapshot.
/// Order is lexicographic (`sort` then `dedup`), a total order on the strings.
/// The snapshot carries no generation: `DutyTracker` captures its revocation
/// stamp before calling `indices`, so a copy taken before a revocation is
/// never admitted under a later generation.
pub struct PubkeyIndexSource {
    pub registry: SharedPubkeyIndexRegistry,
    pub pubkey_map: PubkeyMap,
}

impl ValidatorIndexSource for PubkeyIndexSource {
    fn indices(&self) -> Vec<String> {
        let map = self.pubkey_map.read();
        let registry = self.registry.read();
        if !registry.is_fresh() {
            return Vec::new();
        }
        let mut indices: Vec<String> =
            map.keys().filter_map(|pk| registry.index_of(pk).map(str::to_owned)).collect();
        indices.sort();
        indices.dedup();
        indices
    }
}

/// Test-only rendezvous inside [`PubkeyIndexRegistry::revalidate`].
#[cfg(test)]
mod hooks {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut()>;

    thread_local! {
        static AFTER_REVALIDATE_CHECK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Runs the armed hook after the generation check, before the stamp.
    pub(super) fn after_revalidate_check() {
        AFTER_REVALIDATE_CHECK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    /// Clears the hook when dropped, also on a failed assert.
    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            AFTER_REVALIDATE_CHECK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    pub(super) fn arm_after_revalidate_check(hook: impl FnMut() + 'static) -> Armed {
        AFTER_REVALIDATE_CHECK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Armed
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

    fn source_with(
        pubkey: &crypto::PublicKey,
        registry: SharedPubkeyIndexRegistry,
    ) -> PubkeyIndexSource {
        let map = HashMap::from([(pubkey.to_bytes(), pubkey.clone())]);
        PubkeyIndexSource { registry, pubkey_map: Arc::new(RwLock::new(map)) }
    }

    #[test]
    fn freshness_token_changes_on_bump_and_on_revalidation() {
        use RegistryFreshness::{Fresh, Stale, Untracked};

        let (kept, omitted) = ([0x01; 48], [0x02; 48]);
        let mut reg = PubkeyIndexRegistry::new();
        reg.insert(kept, "4".to_string());
        reg.insert(omitted, "5".to_string());
        assert_eq!(reg.freshness(), Untracked, "no generation attached yet");
        let generation = Arc::new(AtomicU64::new(3));
        reg.attach_revocation(Arc::clone(&generation), 3);
        assert_eq!(reg.freshness(), Fresh(3));
        assert!(reg.is_fresh());

        generation.fetch_add(1, Ordering::Release);
        assert_eq!(reg.freshness(), Stale, "a bump makes every entry stale");
        assert!(!reg.is_fresh());
        let answer = HashMap::from([(kept, "9".to_string())]);
        assert!(!reg.revalidate(3, &answer), "an answer taken before the bump is refused");
        assert_eq!((reg.freshness(), reg.index_of(&kept)), (Stale, Some("4")));

        assert!(reg.revalidate(4, &answer));
        assert_eq!(reg.freshness(), Fresh(4), "the token moved: a holder of Fresh(3) sees it");
        assert_eq!(reg.index_of(&kept), Some("9"));
        assert_eq!(reg.bare_hex_of_index("4"), None, "the replaced index is gone both ways");
        assert_eq!(reg.index_of(&omitted), None, "an omitted key is removed");
        assert_eq!(reg.bare_hex_of_index("5"), None, "and its reverse entry");
        assert_eq!(reg.len(), 1);

        reg.attach_revocation(Arc::clone(&generation), 3);
        assert_eq!(reg.freshness(), Stale, "attached under an older sample: stale at once");
        reg.attach_revocation(generation, 4);
        assert_eq!(reg.freshness(), Fresh(4));
    }

    #[test]
    fn without_a_generation_the_registry_is_always_fresh() {
        use crypto::SecretKey;

        let registry = PubkeyIndexRegistry::shared();
        let pk = SecretKey::generate().public_key();
        registry.write().insert(pk.to_bytes(), "4".to_string());
        assert_eq!(registry.read().freshness(), RegistryFreshness::Untracked);
        assert!(registry.read().is_fresh());
        let source = source_with(&pk, Arc::clone(&registry));
        assert_eq!(source.indices(), vec!["4".to_string()], "today's behaviour");

        let omits_everything = HashMap::new();
        assert!(!registry.write().revalidate(0, &omits_everything), "nothing to revalidate");
        assert_eq!(registry.read().index_of(&pk.to_bytes()), Some("4"));
        assert_eq!(source.indices(), vec!["4".to_string()]);
    }

    #[test]
    fn duty_index_set_is_empty_while_the_registry_is_stale() {
        use crypto::SecretKey;

        let registry = PubkeyIndexRegistry::shared();
        let pk = SecretKey::generate().public_key();
        registry.write().insert(pk.to_bytes(), "4".to_string());
        let generation = Arc::new(AtomicU64::new(0));
        registry.write().attach_revocation(Arc::clone(&generation), 0);
        let source = source_with(&pk, Arc::clone(&registry));
        assert_eq!(source.indices(), vec!["4".to_string()]);

        generation.fetch_add(1, Ordering::Release);
        assert_eq!(source.indices(), Vec::<String>::new(), "no index from before the revocation");
        assert_eq!(registry.read().index_of(&pk.to_bytes()), Some("4"), "raw lookups stay raw");

        let answer = HashMap::from([(pk.to_bytes(), "4".to_string())]);
        assert!(registry.write().revalidate(1, &answer));
        assert_eq!(source.indices(), vec!["4".to_string()], "restored after revalidation");
    }

    /// A revocation between the generation check and the stamp leaves the
    /// answer stale: the stamp is the checked sample, not a later load.
    #[test]
    fn revalidation_stamps_the_checked_generation_not_a_later_one() {
        let pk = [0x44; 48];
        let mut reg = PubkeyIndexRegistry::new();
        let generation = Arc::new(AtomicU64::new(3));
        reg.attach_revocation(Arc::clone(&generation), 2);
        let revoker = Arc::clone(&generation);
        let _armed = hooks::arm_after_revalidate_check(move || {
            let revoker = Arc::clone(&revoker);
            std::thread::spawn(move || revoker.fetch_add(1, Ordering::Release))
                .join()
                .expect("revoking thread");
        });

        assert!(reg.revalidate(3, &HashMap::from([(pk, "4".to_string())])));

        assert_eq!(generation.load(Ordering::Acquire), 4, "the revocation ran after the check");
        assert_eq!(reg.index_of(&pk), Some("4"));
        assert_eq!(
            reg.freshness(),
            RegistryFreshness::Stale,
            "stamped 3, the generation the answer was checked under"
        );
    }

    /// Wraps the production source. After its first copy, another thread
    /// revokes (joined, so the order is fixed) before the copy is returned.
    struct RevokedAfterCopy {
        inner: PubkeyIndexSource,
        generation: Arc<AtomicU64>,
        revoke: bool,
        copies: std::sync::atomic::AtomicUsize,
    }

    impl ValidatorIndexSource for RevokedAfterCopy {
        fn indices(&self) -> Vec<String> {
            let copy = self.inner.indices();
            if self.copies.fetch_add(1, Ordering::SeqCst) == 0 && self.revoke {
                let generation = Arc::clone(&self.generation);
                std::thread::spawn(move || generation.fetch_add(1, Ordering::Release))
                    .join()
                    .expect("revoking thread");
                assert_eq!(self.inner.indices(), Vec::<String>::new(), "the source is stale now");
            }
            copy
        }
    }

    /// The tracker paths that take an index snapshot and cache the answer.
    #[derive(Debug, Clone, Copy)]
    enum DutyPath {
        Attester,
        AttesterReorg,
        Ptc,
        PtcColdReorg,
        Sync,
    }

    const EPOCH: u64 = 10;
    const SLOT: u64 = EPOCH * 32;

    /// Fetch along `path` with index 4 fresh under generation 0, where the
    /// first index copy is followed by a revocation if `revoke`. Returns the
    /// fetch result and how many duties a reader is then served.
    async fn fetch_after_copy(
        path: DutyPath,
        revoke: bool,
    ) -> (Result<(), duty_tracker::DutyTrackerError>, usize) {
        use beacon::{
            AttesterDutiesResponse, AttesterDuty, PtcDutiesResponse, PtcDuty,
            SyncCommitteeDutiesResponse,
        };
        use bn_manager::MockBeaconNodeClient;
        use duty_tracker::DutyTracker;
        use eth_types::SyncCommitteeDuty;

        let pk = crypto::SecretKey::generate().public_key();
        let bytes = pk.to_bytes();
        let hex = pubkey_bytes_to_0x(&bytes);
        let (attester_hex, ptc_hex) = (hex.clone(), hex);
        let asked_for_4 = |indices: &[String]| assert_eq!(indices, ["4".to_string()]);
        let mock = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(move |_, indices| {
                    asked_for_4(&indices);
                    Ok(AttesterDutiesResponse {
                        dependent_root: "0xaaa".to_string(),
                        execution_optimistic: false,
                        data: vec![AttesterDuty {
                            pubkey: attester_hex.clone(),
                            validator_index: "4".to_string(),
                            slot: SLOT.to_string(),
                            committee_index: "0".to_string(),
                            committee_length: "1".to_string(),
                            committees_at_slot: "1".to_string(),
                            validator_committee_index: "0".to_string(),
                        }],
                    })
                })
                .with_post_ptc_duties(move |_, indices| {
                    asked_for_4(&indices);
                    Ok(PtcDutiesResponse {
                        dependent_root: "0xaaa".to_string(),
                        execution_optimistic: false,
                        data: vec![PtcDuty {
                            pubkey: ptc_hex.clone(),
                            validator_index: "4".to_string(),
                            slot: SLOT.to_string(),
                        }],
                    })
                })
                .with_post_sync_committee_duties(move |_, indices| {
                    asked_for_4(&indices);
                    Ok(SyncCommitteeDutiesResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: bytes,
                            validator_index: 4,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                }),
        );
        let registry = PubkeyIndexRegistry::shared();
        registry.write().insert(bytes, "4".to_string());
        let generation = mock.track_admission();
        registry.write().attach_revocation(Arc::clone(&generation), 0);
        let source = Arc::new(RevokedAfterCopy {
            inner: source_with(&pk, registry),
            generation: Arc::clone(&generation),
            revoke,
            copies: std::sync::atomic::AtomicUsize::new(0),
        });
        let tracker = DutyTracker::new_with_source(mock, source);

        let fetched = match path {
            DutyPath::Attester => tracker.fetch_duties_for_epoch(EPOCH).await.map(drop),
            DutyPath::AttesterReorg => {
                tracker.check_and_refetch_if_root_changed(EPOCH).await.map(drop)
            }
            DutyPath::Ptc => tracker.fetch_ptc_duties_for_epoch(EPOCH).await.map(drop),
            DutyPath::PtcColdReorg => {
                tracker.check_and_refetch_ptc_if_root_changed(EPOCH).await.map(drop)
            }
            DutyPath::Sync => tracker.fetch_sync_committee_duties(EPOCH).await.map(drop),
        };
        let served = match path {
            DutyPath::Attester | DutyPath::AttesterReorg => {
                tracker.get_duties_for_slot(SLOT).await.len()
            }
            DutyPath::Ptc | DutyPath::PtcColdReorg => {
                tracker.get_ptc_duties_for_slot(SLOT).await.len()
            }
            DutyPath::Sync => tracker.get_sync_committee_duties(SLOT).await.len(),
        };
        assert_eq!(generation.load(Ordering::Acquire), u64::from(revoke), "{path:?}");
        (fetched, served)
    }

    async fn assert_a_pre_revocation_copy_is_not_served(path: DutyPath) {
        let (fetched, served) = fetch_after_copy(path, true).await;
        assert_eq!(served, 0, "{path:?}: duties fetched with a pre-revocation copy are not served");
        assert!(
            matches!(
                fetched,
                Err(duty_tracker::DutyTrackerError::RevokedDuringFetch { epoch: EPOCH })
            ),
            "{path:?}: the fetch fails closed: {fetched:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attester_duties_fetched_with_a_pre_revocation_copy_are_not_served() {
        assert_a_pre_revocation_copy_is_not_served(DutyPath::Attester).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attester_reorg_duties_fetched_with_a_pre_revocation_copy_are_not_served() {
        assert_a_pre_revocation_copy_is_not_served(DutyPath::AttesterReorg).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ptc_duties_fetched_with_a_pre_revocation_copy_are_not_served() {
        assert_a_pre_revocation_copy_is_not_served(DutyPath::Ptc).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_ptc_refetch_with_a_pre_revocation_copy_is_not_served() {
        assert_a_pre_revocation_copy_is_not_served(DutyPath::PtcColdReorg).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_duties_fetched_with_a_pre_revocation_copy_are_not_served() {
        assert_a_pre_revocation_copy_is_not_served(DutyPath::Sync).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duties_fetched_with_no_revocation_are_served_on_every_path() {
        for path in [
            DutyPath::Attester,
            DutyPath::AttesterReorg,
            DutyPath::Ptc,
            DutyPath::PtcColdReorg,
            DutyPath::Sync,
        ] {
            let (fetched, served) = fetch_after_copy(path, false).await;
            assert!(fetched.is_ok(), "{path:?}: {fetched:?}");
            assert_eq!(served, 1, "{path:?}: the cache is populated normally");
        }
    }
}
