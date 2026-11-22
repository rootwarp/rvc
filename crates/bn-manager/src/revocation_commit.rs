//! The commit lock that orders index-provenance changes against doppelganger
//! admission.

use std::fmt;
use std::sync::{Mutex, MutexGuard, TryLockError};

#[cfg(any(test, feature = "test-utils"))]
use std::sync::Arc;

/// Commit lock shared by every writer that can change which validator an
/// index names, and by the doppelganger admission that relies on it.
///
/// [`crate::BnManager`] holds it around each revocation-generation bump. The
/// index resolver holds it around each registry revalidation. The liveness
/// loop holds it from its index-freshness check through its Pending→Safe
/// state write. So a revocation or revalidation either finishes before an
/// admission takes the lock, and that admission's check sees it and refuses,
/// or it waits until the admission has written its state.
///
/// Lock order. Every taker acquires in this order, never the reverse:
/// 1. a per-node admission gate (revocation only);
/// 2. this lock;
/// 3. the doppelganger forward-window state mutex (admission only);
/// 4. the index registry `RwLock` (read by admission, written by revalidation).
///
/// Hold it only around synchronous work: no taker holds it across an `.await`.
#[derive(Default)]
pub struct RevocationCommit {
    lock: Mutex<()>,
    #[cfg(any(test, feature = "test-utils"))]
    contended: Mutex<Option<ContentionHook>>,
}

/// Test seam called on the thread that is about to wait for the lock.
#[cfg(any(test, feature = "test-utils"))]
pub type ContentionHook = Arc<dyn Fn() + Send + Sync>;

/// A held [`RevocationCommit`]. The lock is released when this drops.
#[must_use = "the commit lock is released when the guard drops"]
pub struct RevocationCommitGuard<'a> {
    _held: MutexGuard<'a, ()>,
}

impl RevocationCommit {
    /// Hold the lock until the guard drops.
    ///
    /// The lock guards no data, so a poisoned lock is taken anyway.
    pub fn hold(&self) -> RevocationCommitGuard<'_> {
        let held = match self.lock.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                #[cfg(any(test, feature = "test-utils"))]
                self.report_contention();
                self.lock.lock().unwrap_or_else(|err| err.into_inner())
            }
        };
        RevocationCommitGuard { _held: held }
    }

    /// Test seam: call `hook` each time [`Self::hold`] has to wait for
    /// another holder, just before it waits. `None` removes the hook.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn on_contended(&self, hook: Option<ContentionHook>) {
        *self.contended.lock().unwrap_or_else(|err| err.into_inner()) = hook;
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn report_contention(&self) {
        let hook = self.contended.lock().unwrap_or_else(|err| err.into_inner()).clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl fmt::Debug for RevocationCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationCommit").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    /// Upper bound for a signal that arrives at once; only a broken lock waits it out.
    const WATCHDOG: Duration = Duration::from_secs(10);

    #[test]
    fn debug_names_the_lock() {
        assert_eq!(format!("{:?}", RevocationCommit::default()), "RevocationCommit { .. }");
    }

    #[test]
    fn an_uncontended_hold_reports_no_contention() {
        let commit = RevocationCommit::default();
        let reports = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reports);
        commit.on_contended(Some(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })));

        drop(commit.hold());
        drop(commit.hold());

        assert_eq!(reports.load(Ordering::SeqCst), 0);
    }

    /// A second holder reports that it waits, and gets the lock only after the
    /// first holder drops it.
    #[test]
    fn a_second_holder_waits_for_the_first() {
        let commit = Arc::new(RevocationCommit::default());
        let (reported, contention) = mpsc::channel();
        commit.on_contended(Some(Arc::new(move || {
            let _ = reported.send(());
        })));
        let held = commit.hold();
        let acquired = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (commit, acquired) = (Arc::clone(&commit), Arc::clone(&acquired));
            std::thread::spawn(move || {
                let _held = commit.hold();
                acquired.store(true, Ordering::SeqCst);
            })
        };

        contention.recv_timeout(WATCHDOG).expect("the second holder reports that it waits");
        assert!(!acquired.load(Ordering::SeqCst), "not while the first holder has it");
        drop(held);
        waiter.join().expect("waiter");
        assert!(acquired.load(Ordering::SeqCst));
    }
}
