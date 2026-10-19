// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Quiescence of broker helper threads around a native process clone.
//!
//! A native clone copies memory, including locks, but only the calling thread. The broker
//! notification receiver and association-failure handling run on helper threads that allocate,
//! log, and call into LiteBox. Cloning while one of them is mid-update could leave the child with
//! a lock that no surviving thread will release. Helper work runs inside [`HelperWork`], and the
//! cloning thread holds [`HelperThreadQuiescence`] across the clone so that no such work is in
//! progress at that instant.

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    active_work: usize,
    cloning: bool,
}

/// The current gate. A clone replaces it rather than reusing the copied one, whose condition
/// variable may still reference waiters that do not exist in the child.
static GATE: AtomicPtr<Gate> = AtomicPtr::new(core::ptr::null_mut());

fn gate() -> &'static Gate {
    let current = GATE.load(Ordering::Acquire);
    if !current.is_null() {
        // SAFETY: Installed gates are leaked and never freed.
        return unsafe { &*current };
    }
    let fresh = Box::into_raw(Box::default());
    match GATE.compare_exchange(
        core::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        // SAFETY: `fresh` is now the installed, leaked gate.
        Ok(_) => unsafe { &*fresh },
        Err(installed) => {
            // SAFETY: `fresh` was never published, so this is its only owner.
            drop(unsafe { Box::from_raw(fresh) });
            // SAFETY: Installed gates are leaked and never freed.
            unsafe { &*installed }
        }
    }
}

fn lock(gate: &Gate) -> MutexGuard<'_, GateState> {
    // The state is two plain counters that stay consistent even if a holder panicked.
    gate.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Exclusive hold, for the duration of a native clone, over broker helper work.
///
/// While held, no helper work is in progress and none can start. The holding thread must not
/// itself begin [`HelperWork`].
pub struct HelperThreadQuiescence {
    state: MutexGuard<'static, GateState>,
}

impl HelperThreadQuiescence {
    /// Waits up to `timeout` for in-progress helper work to finish, then blocks new work until
    /// the returned hold is dropped.
    ///
    /// Returns `None` if helper work does not finish in time.
    pub fn acquire(timeout: Duration) -> Option<Self> {
        let gate = gate();
        let mut state = lock(gate);
        debug_assert!(!state.cloning, "only one native clone runs at a time");
        state.cloning = true;
        let (mut state, timeout) = gate
            .changed
            .wait_timeout_while(state, timeout, |state| state.active_work != 0)
            .unwrap_or_else(PoisonError::into_inner);
        if timeout.timed_out() && state.active_work != 0 {
            state.cloning = false;
            drop(state);
            gate.changed.notify_all();
            return None;
        }
        Some(Self { state })
    }

    /// Discards this hold in the clone, where no helper threads survive, and installs a fresh
    /// gate for the helper threads the clone starts.
    ///
    /// # Safety
    ///
    /// The caller must be the sole thread of a process cloned while this hold was held, and
    /// nothing in the clone may use the copied gate afterwards.
    pub unsafe fn reset_after_clone(self) {
        // Releasing the copied lock could wake waiters that only exist in the parent.
        core::mem::forget(self);
        GATE.store(Box::into_raw(Box::default()), Ordering::Release);
    }
}

impl Drop for HelperThreadQuiescence {
    fn drop(&mut self) {
        self.state.cloning = false;
        gate().changed.notify_all();
    }
}

/// Helper-thread work that a native clone must not interrupt.
pub(crate) struct HelperWork {
    gate: &'static Gate,
}

impl HelperWork {
    /// Waits for any native clone in progress, then marks helper work as in progress until the
    /// returned value is dropped.
    pub(crate) fn begin() -> Self {
        let gate = gate();
        let mut state = gate
            .changed
            .wait_while(lock(gate), |state| state.cloning)
            .unwrap_or_else(PoisonError::into_inner);
        state.active_work += 1;
        Self { gate }
    }
}

impl Drop for HelperWork {
    fn drop(&mut self) {
        let mut state = lock(self.gate);
        state.active_work -= 1;
        if state.active_work == 0 && state.cloning {
            drop(state);
            self.gate.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    // The gate is process-global, so its behaviors are checked in one test.
    #[test]
    fn quiescence_waits_for_and_blocks_helper_work() {
        let work = HelperWork::begin();
        assert!(HelperThreadQuiescence::acquire(Duration::from_millis(10)).is_none());
        drop(work);

        let hold = HelperThreadQuiescence::acquire(Duration::from_secs(5)).unwrap();
        let started = Arc::new(AtomicBool::new(false));
        let helper = std::thread::spawn({
            let started = Arc::clone(&started);
            move || {
                let _work = HelperWork::begin();
                started.store(true, Ordering::Release);
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!started.load(Ordering::Acquire));
        drop(hold);
        helper.join().unwrap();
        assert!(started.load(Ordering::Acquire));

        let previous = GATE.load(Ordering::Acquire);
        let hold = HelperThreadQuiescence::acquire(Duration::from_secs(5)).unwrap();
        // SAFETY: No helper thread waits on the gate, and the forgotten hold leaves the previous
        // gate locked but unused, as in a clone.
        unsafe { hold.reset_after_clone() };
        assert_ne!(GATE.load(Ordering::Acquire), previous);
        drop(HelperWork::begin());
        drop(HelperThreadQuiescence::acquire(Duration::from_secs(5)).unwrap());
    }
}
