//! Admission budget for keystore KDF working sets.
//!
//! Scrypt's memory cost is `128 · r · N`. [`KdfBudget`] limits how many of those
//! derivations run at once and how much of that memory they may hold together.
//! The permit is owned and `'static` so a later import path can move it into
//! `spawn_blocking` and keep it until decrypt returns.
//!
//! Keystore import calls [`KdfBudget::admit`] in a follow-up. Until that call
//! site lands, this module's public items have no production caller.
#![allow(dead_code, reason = "keystore import calls KdfBudget::admit in a follow-up")]

use std::sync::Arc;

use crypto::MAX_KDF_WORKING_SET_BYTES;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MIB: u64 = 1024 * 1024;
const DEFAULT_CONCURRENCY: u32 = 2;
const DEFAULT_TOTAL_BYTES: u64 = 512 * MIB;

/// Knobs for [`KdfBudget`].
///
/// Defaults are the operator-facing import budget: two concurrent derivations,
/// 512 MiB of accounted working set, and a per-keystore cap equal to the
/// largest scrypt cost `decrypt` still attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfBudgetConfig {
    /// How many KDF derivations may run at once when each fits in [`Self::total_bytes`].
    pub concurrency: u32,
    /// Accounted working-set budget, in bytes. A single keystore above this is
    /// admitted alone.
    pub total_bytes: u64,
    /// Per-keystore working-set cap, in bytes. Above this, admission fails.
    pub max_keystore_bytes: u64,
}

impl Default for KdfBudgetConfig {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            total_bytes: DEFAULT_TOTAL_BYTES,
            max_keystore_bytes: MAX_KDF_WORKING_SET_BYTES,
        }
    }
}

/// `rvc-config` cannot name this type. The `[keymanager]` import-KDF defaults
/// repeat these numbers and must stay equal.
const _: () = {
    assert!(DEFAULT_CONCURRENCY == rvc_config::DEFAULT_IMPORT_KDF_CONCURRENCY);
    assert!(DEFAULT_TOTAL_BYTES == (rvc_config::DEFAULT_IMPORT_KDF_TOTAL_MIB as u64) * MIB);
    assert!(
        MAX_KDF_WORKING_SET_BYTES / MIB == rvc_config::DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB as u64
    );
};

/// Shared admission gate over a slot semaphore and a byte semaphore.
///
/// Byte permits are 1 MiB each. [`Self::admit`] waits asynchronously.
pub struct KdfBudget {
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    cfg: KdfBudgetConfig,
}

/// Owned permits held for one admitted derivation.
///
/// Dropping the value releases them. The type is `'static` and [`Send`] so it
/// can move onto a blocking thread and outlive the async waiter that acquired it.
#[derive(Debug)]
#[must_use = "dropping the admission releases the KDF budget permits"]
pub struct KdfAdmission {
    _slots: OwnedSemaphorePermit,
    _bytes: Option<OwnedSemaphorePermit>,
}

/// [`KdfBudget::admit`] rejected the keystore before taking a permit.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KdfBudgetError {
    /// Working set exceeds [`KdfBudgetConfig::max_keystore_bytes`].
    #[error("kdf working set {bytes} bytes exceeds per-keystore cap {max_keystore_bytes} bytes")]
    TooLarge { bytes: u64, max_keystore_bytes: u64 },
}

impl KdfBudget {
    /// Build a budget. `concurrency` must be at least 1 so the alone path can
    /// take every slot.
    pub fn new(cfg: KdfBudgetConfig) -> Self {
        assert!(cfg.concurrency >= 1, "kdf budget concurrency must be at least 1");
        Self {
            slots: Arc::new(Semaphore::new(concurrency_usize(cfg.concurrency))),
            bytes: Arc::new(Semaphore::new(mib_units_usize(cfg.total_bytes))),
            cfg,
        }
    }

    /// Reserve budget for a keystore whose KDF working set is `bytes`.
    ///
    /// The wait is asynchronous: a queued caller holds no blocking thread.
    ///
    /// * `bytes > max_keystore_bytes` returns [`KdfBudgetError::TooLarge`].
    /// * `bytes > total_bytes` takes every slot permit and no byte permit, so
    ///   nothing else is in flight.
    /// * otherwise takes one slot permit and `ceil(bytes / 1 MiB)` byte permits.
    pub async fn admit(&self, bytes: u64) -> Result<KdfAdmission, KdfBudgetError> {
        if bytes > self.cfg.max_keystore_bytes {
            return Err(KdfBudgetError::TooLarge {
                bytes,
                max_keystore_bytes: self.cfg.max_keystore_bytes,
            });
        }

        let admission = if bytes > self.cfg.total_bytes {
            let _slots = self
                .slots
                .clone()
                .acquire_many_owned(self.cfg.concurrency)
                .await
                .expect("kdf budget semaphore is never closed");
            KdfAdmission { _slots, _bytes: None }
        } else {
            // Slots before bytes. The alone path waits only on slots, so a
            // task must not hold byte permits while it is queued for a slot.
            let _slots = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("kdf budget semaphore is never closed");
            let permits = byte_permits(bytes);
            let _bytes = if permits == 0 {
                None
            } else {
                Some(
                    self.bytes
                        .clone()
                        .acquire_many_owned(permits)
                        .await
                        .expect("kdf budget semaphore is never closed"),
                )
            };
            KdfAdmission { _slots, _bytes }
        };
        Ok(assert_admission_send_static(admission))
    }
}

/// Working-set bytes rounded up to whole mebibytes, as a semaphore permit count.
fn byte_permits(bytes: u64) -> u32 {
    u32::try_from(mib_units(bytes)).unwrap_or(u32::MAX)
}

fn mib_units(bytes: u64) -> u64 {
    bytes.div_ceil(MIB)
}

fn mib_units_usize(bytes: u64) -> usize {
    usize::try_from(mib_units(bytes)).expect("kdf byte budget exceeds usize")
}

fn concurrency_usize(concurrency: u32) -> usize {
    usize::try_from(concurrency).expect("kdf budget concurrency fits in usize")
}

/// Compile-time gate: [`KdfAdmission`] must move into `spawn_blocking`.
fn assert_admission_send_static(admission: KdfAdmission) -> KdfAdmission {
    fn assert_send_static<T: Send + 'static>(value: T) -> T {
        value
    }
    assert_send_static(admission)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use futures::future::{join_all, FutureExt};

    use super::*;

    #[test]
    fn kdf_budget_config_defaults_match_the_accepted_ceiling() {
        let cfg = KdfBudgetConfig::default();
        assert_eq!(cfg.concurrency, 2);
        assert_eq!(cfg.total_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.max_keystore_bytes, MAX_KDF_WORKING_SET_BYTES);
        assert_eq!(cfg.max_keystore_bytes, 8u64 * 1024 * 1024 * 1024);
    }

    #[tokio::test]
    async fn kdf_budget_rejects_a_keystore_above_the_per_keystore_cap() {
        let budget = KdfBudget::new(KdfBudgetConfig::default());
        let cap = budget.cfg.max_keystore_bytes;

        let at_cap = budget.admit(cap).await.expect("ceiling is still admitted");
        drop(at_cap);
        assert_eq!(budget.slots.available_permits(), concurrency_usize(budget.cfg.concurrency));

        let err = budget.admit(cap + 1).await.expect_err("above the cap");
        assert_eq!(err, KdfBudgetError::TooLarge { bytes: cap + 1, max_keystore_bytes: cap });
        assert_eq!(budget.slots.available_permits(), concurrency_usize(budget.cfg.concurrency));
        assert_eq!(budget.bytes.available_permits(), mib_units_usize(budget.cfg.total_bytes));
    }

    #[tokio::test]
    async fn kdf_budget_charges_one_slot_and_ceiled_mib() {
        let cfg = KdfBudgetConfig {
            concurrency: 2,
            total_bytes: 8 * MIB,
            max_keystore_bytes: MAX_KDF_WORKING_SET_BYTES,
        };
        let budget = KdfBudget::new(cfg);

        let one_byte = budget.admit(1).await.expect("1 byte");
        assert_eq!(budget.slots.available_permits(), 1);
        assert_eq!(budget.bytes.available_permits(), 7);
        drop(one_byte);

        let over_a_mib = budget.admit(MIB + 1).await.expect("1 MiB + 1");
        assert_eq!(budget.slots.available_permits(), 1);
        assert_eq!(budget.bytes.available_permits(), 6);
        drop(over_a_mib);

        // PBKDF2's working set is 0: one slot, no byte permits.
        let pbkdf2 = budget.admit(0).await.expect("zero bytes");
        assert_eq!(budget.slots.available_permits(), 1);
        assert_eq!(budget.bytes.available_permits(), 8);
        drop(pbkdf2);
        assert_eq!(budget.slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn kdf_budget_admits_an_over_budget_keystore_alone() {
        let cfg = KdfBudgetConfig {
            concurrency: 2,
            total_bytes: 4 * MIB,
            max_keystore_bytes: MAX_KDF_WORKING_SET_BYTES,
        };
        let budget = Arc::new(KdfBudget::new(cfg));

        // Exactly `total_bytes` still shares the slot pool.
        let at_budget = budget.admit(cfg.total_bytes).await.expect("at the byte budget");
        assert_eq!(budget.slots.available_permits(), concurrency_usize(cfg.concurrency) - 1);
        drop(at_budget);
        assert_eq!(budget.slots.available_permits(), concurrency_usize(cfg.concurrency));

        let over = cfg.total_bytes + 1;
        let hold = budget.admit(over).await.expect("over the byte budget");
        assert_eq!(budget.slots.available_permits(), 0, "over-budget keystore holds every slot");
        assert_eq!(
            budget.bytes.available_permits(),
            mib_units_usize(cfg.total_bytes),
            "alone admission does not take byte permits"
        );

        let other = budget.admit(MIB);
        assert!(other.now_or_never().is_none(), "nothing else is in flight");

        drop(hold);
        assert_eq!(budget.slots.available_permits(), concurrency_usize(cfg.concurrency));

        // Each such keystore exceeds `total_bytes`, so the byte budget fits
        // zero of them. One may still run. Peak in-flight is budget + one.
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks = (0..8).map(|_| {
            let budget = Arc::clone(&budget);
            let inflight = Arc::clone(&inflight);
            let peak = Arc::clone(&peak);
            async move {
                let admission = budget.admit(over).await.expect("over-budget admit");
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                drop(admission);
            }
        });
        join_all(tasks).await;

        let peak = peak.load(Ordering::SeqCst);
        let fit_in_budget = 0;
        assert!(peak <= fit_in_budget + 1, "peak in-flight {peak} exceeds budget + one");
        assert_eq!(peak, 1);
        assert_eq!(inflight.load(Ordering::SeqCst), 0);
    }
}
