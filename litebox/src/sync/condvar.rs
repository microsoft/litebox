//! Condition variables

#![expect(unused, reason = "currently unimplemented")]

#![expect(unused, reason = "currently unimplemented")]

use crate::platform::{RawMutex as _, RawMutexProvider};

/// Condition variables, roughly analogous to Rust's
/// [`std::sync::Condvar`](https://doc.rust-lang.org/std/sync/struct.Condvar.html)
pub struct Condvar<Platform: RawMutexProvider> {
    inner: RawCondvar<Platform>,
}

impl<Platform: RawMutexProvider> Condvar<Platform> {
    #[inline]
    pub(super) fn new_from_platform(platform: &Platform) -> Self {
        Self {
            inner: RawCondvar::new_from_platform(platform),
        }
    }

    pub fn notify_one(&self) {
        self.inner.notify_one();
    }

    pub fn notify_all(&self) {
        self.inner.notify_all();
    }
}

// NOTE(jayb): I am not pulling in any functionality from `sandbox_core` here, because it is not
// actually similar to Rust's `Condvar` and I'd like to discuss some of the design decisions for why
// it has diverged before designing this one out.

/// Adapted from <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/sync/condvar/futex.rs>
pub struct RawCondvar<Platform: RawMutexProvider> {
    // The value of this atomic is simply incremented on every notification.
    // This is used by `.wait()` to not miss any notifications after
    // unlocking the mutex and before waiting for notifications.
    futex: Platform::RawMutex,
}

impl<Platform: RawMutexProvider> RawCondvar<Platform> {
    #[inline]
    pub fn new_from_platform(platform: &Platform) -> Self {
        Self {
            futex: platform.new_raw_mutex(),
        }
    }

    // All the memory orderings here are `Relaxed`,
    // because synchronization is done by unlocking and locking the mutex.

    pub fn notify_one(&self) {
        self.futex
            .underlying_atomic()
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.futex.wake_one();
    }

    pub fn notify_all(&self) {
        self.futex
            .underlying_atomic()
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.futex.wake_all();
    }

    unsafe fn wait<P: super::RawSyncPrimitivesProvider>(
        &self,
        mutex: &super::mutex::SpinEnabledRawMutex<P>,
    ) {
        unsafe { self.wait_optional_timeout(mutex, None) };
    }

    unsafe fn wait_timeout<P: super::RawSyncPrimitivesProvider>(
        &self,
        mutex: &super::mutex::SpinEnabledRawMutex<P>,
        timeout: core::time::Duration,
    ) -> bool {
        unsafe { self.wait_optional_timeout(mutex, Some(timeout)) }
    }

    unsafe fn wait_optional_timeout<P: super::RawSyncPrimitivesProvider>(
        &self,
        mutex: &super::mutex::SpinEnabledRawMutex<P>,
        timeout: Option<core::time::Duration>,
    ) -> bool {
        // Examine the notification counter _before_ we unlock the mutex.
        let futex_value = self
            .futex
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Relaxed);

        // Unlock the mutex before going to sleep.
        unsafe { mutex.unlock() };

        // Wait, but only if there hasn't been any
        // notification since we unlocked the mutex.
        let r = if let Some(timeout) = timeout {
            match self.futex.block_or_timeout(futex_value, timeout) {
                Ok(crate::platform::UnblockedOrTimedOut::TimedOut) => false,
                Ok(crate::platform::UnblockedOrTimedOut::Unblocked)
                | Err(crate::platform::ImmediatelyWokenUp) => true,
            }
        } else {
            let _ = self.futex.block(futex_value);
            true
        };

        // Lock the mutex again.
        mutex.lock();

        r
    }

    /// Different from `wait` in that it doesn't require a mutex to be passed in.
    /// However, it assumes there is only one waiter.
    pub unsafe fn simple_wait(&self) -> bool {
        unsafe { self.simple_wait_optional_timeout(None) }
    }

    pub unsafe fn simple_wait_optional_timeout(
        &self,
        timeout: Option<core::time::Duration>,
    ) -> bool {
        let futex = self.futex.underlying_atomic();
        if futex.swap(0, core::sync::atomic::Ordering::Relaxed) == 0 {
            if let Some(timeout) = timeout {
                match self.futex.block_or_timeout(0, timeout) {
                    Ok(crate::platform::UnblockedOrTimedOut::TimedOut) => false,
                    Ok(crate::platform::UnblockedOrTimedOut::Unblocked)
                    | Err(crate::platform::ImmediatelyWokenUp) => true,
                }
            } else {
                let _ = self.futex.block(0);
                true
            }
        } else {
            true
        }
    }
}
