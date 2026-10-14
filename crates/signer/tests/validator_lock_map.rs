//! ARCH-5n / ARCH-P2-1: `ValidatorLockMap` size bound.
//!
//! Eviction is an internal hygiene sweep, not a key-admission hook (C4).
//! Test names intentionally avoid the `*_root` KAT scanner (A-5.10).

use std::sync::Arc;
use std::time::Duration;

use rvc_signer::ValidatorLockMap;
use tokio::sync::OwnedMutexGuard;

fn pubkey(n: u32) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[..4].copy_from_slice(&n.to_be_bytes());
    pk
}

/// Churn N ≫ capacity distinct pubkeys through `lock()`, dropping each guard.
/// The map must not grow monotonically.
#[tokio::test]
async fn test_lock_map_size_is_bounded_under_key_churn() {
    const CAPACITY: usize = 8;
    let map = ValidatorLockMap::with_capacity(CAPACITY);
    let n = CAPACITY * 8;

    for i in 0..n {
        let _guard = map.lock(&pubkey(i as u32)).await;
    }

    assert!(
        map.len() <= map.capacity(),
        "lock map grew without bound under key churn: len={} capacity={}",
        map.len(),
        map.capacity()
    );
}

/// A held entry must keep the same mutex after the map is forced over capacity.
/// Returning a different `Arc` would drop per-validator serialization.
///
/// Hold only `lock()`'s `OwnedMutexGuard` across the churn — the production
/// `sign_slashable` pattern (`strong_count == 2`: map + guard). A leftover
/// `get()` Arc would make count 3 and miss a `> 2` eviction fencepost.
#[tokio::test]
async fn test_no_held_lock_is_evicted() {
    const CAPACITY: usize = 8;
    let map = ValidatorLockMap::with_capacity(CAPACITY);
    let held_pk = pubkey(0);
    let guard = map.lock(&held_pk).await;

    for i in 1..(CAPACITY as u32 * 4) {
        let _g = map.lock(&pubkey(i)).await;
    }

    let after = map.get(&held_pk);
    assert!(
        Arc::ptr_eq(OwnedMutexGuard::mutex(&guard), &after),
        "held lock was evicted; a new mutex would break per-validator serialization"
    );
}

/// If every cached entry is held, the sweep must grow rather than wait.
#[tokio::test]
async fn test_sweep_never_blocks_when_every_entry_is_held() {
    const CAPACITY: usize = 4;
    let map = ValidatorLockMap::with_capacity(CAPACITY);
    let mut guards = Vec::with_capacity(CAPACITY);
    for i in 0..CAPACITY as u32 {
        guards.push(map.lock(&pubkey(i)).await);
    }

    let extra = tokio::time::timeout(Duration::from_millis(200), map.lock(&pubkey(99)))
        .await
        .expect("sweep must grow when every entry is held; must not block a sign");

    assert!(
        map.len() > map.capacity(),
        "all-held insert must grow the map, not stall; len={} capacity={}",
        map.len(),
        map.capacity()
    );
    drop(extra);
    drop(guards);
}
