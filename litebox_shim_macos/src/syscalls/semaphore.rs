// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach semaphores, after XNU's `osfmk/kern/sync_sema.c`, and
//! `__semwait_signal`, after `bsd/kern/kern_sig.c`.
//!
//! A semaphore's count is its value while nonnegative; -1 means threads may
//! be waiting (XNU keeps no count of them). Its port is a kernel object in
//! the task's IPC space; `semaphore_destroy` kills the port and removes the
//! semaphore here, ending its waiters with `KERN_TERMINATED`.

use crate::{
    ShimPlatform, Task,
    syscalls::cancel::TestCancel,
    wait::{WaitQueue, WaitResult},
};
use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    KernReturn,
    errno::Errno,
    syscall::{MachPortName, MachTimespec, SemaphoreSignalKind},
};

pub(crate) type SemaphoreId = u64;

/// `SYNC_POLICY_REVERSED`: waiters queue first, so the last to wait wakes
/// first.
const SYNC_POLICY_REVERSED: i32 = 0x2;
const NSEC_PER_SEC: i64 = 1_000_000_000;

struct Semaphore<P: ShimPlatform> {
    policy: i32,
    count: i32,
    waiters: WaitQueue<P>,
}

/// The task's live semaphores. Each has a port, so the port budget bounds
/// the table; waiters are bounded by the thread limit.
pub(crate) struct SemaphoreTable<P: ShimPlatform> {
    semaphores: BTreeMap<SemaphoreId, Semaphore<P>>,
    next: SemaphoreId,
}

impl<P: ShimPlatform> Default for SemaphoreTable<P> {
    fn default() -> Self {
        Self {
            semaphores: BTreeMap::new(),
            next: 0,
        }
    }
}

impl<P: ShimPlatform> SemaphoreTable<P> {
    /// `semaphore_create` with a validated policy and value.
    pub(crate) fn create(&mut self, policy: i32, value: i32) -> SemaphoreId {
        let id = self.next;
        self.next += 1;
        self.semaphores.insert(
            id,
            Semaphore {
                policy,
                count: value,
                waiters: WaitQueue::default(),
            },
        );
        id
    }

    /// `semaphore_destroy_internal`: deactivate the semaphore and wake its
    /// waiters with `THREAD_RESTART`.
    pub(crate) fn destroy(&mut self, id: SemaphoreId) {
        if let Some(mut semaphore) = self.semaphores.remove(&id) {
            semaphore.waiters.restart_all();
        }
    }

    /// The count of a live semaphore.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn count(&self, id: SemaphoreId) -> Option<i32> {
        self.semaphores.get(&id).map(|semaphore| semaphore.count)
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn semaphore_count(&self) -> usize {
        self.semaphores.len()
    }

    /// End every wait with `KERN_TERMINATED`; returns how many there were.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn release_all_waiters(&mut self) -> usize {
        let mut released = 0;
        for semaphore in self.semaphores.values_mut() {
            released += semaphore.waiters.len();
            semaphore.waiters.restart_all();
        }
        released
    }

    /// Threads queued on a live semaphore.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn waiters(&self, id: SemaphoreId) -> Option<usize> {
        self.semaphores
            .get(&id)
            .map(|semaphore| semaphore.waiters.len())
    }

    /// `semaphore_signal_internal`. `thread` wakes that thread only;
    /// `prepost` counts a signal that wakes nobody.
    fn signal(
        &mut self,
        id: SemaphoreId,
        thread: Option<crate::ThreadId>,
        all: bool,
        prepost: bool,
    ) -> KernReturn {
        let Some(semaphore) = self.semaphores.get_mut(&id) else {
            return KernReturn::TERMINATED;
        };
        if let Some(thread) = thread {
            return if semaphore.count < 0 && semaphore.waiters.wake_thread(thread) {
                KernReturn::SUCCESS
            } else {
                KernReturn::NOT_WAITING
            };
        }
        if all {
            if semaphore.count < 0 {
                semaphore.count = 0;
                let woken = !semaphore.waiters.is_empty();
                semaphore.waiters.wake_all();
                return if woken {
                    KernReturn::SUCCESS
                } else {
                    KernReturn::NOT_WAITING
                };
            }
            if prepost {
                semaphore.count += 1;
            }
            return KernReturn::SUCCESS;
        }
        if semaphore.count < 0 {
            if semaphore.waiters.wake_one().is_some() {
                return KernReturn::SUCCESS;
            }
            // Every waiter left (timed out or aborted).
            semaphore.count = 0;
        }
        if prepost {
            semaphore.count += 1;
        }
        KernReturn::NOT_WAITING
    }
}

/// How a semaphore wait ended, and whether it blocked (XNU returns a
/// blocked wait's result through a continuation).
struct WaitOutcome {
    result: KernReturn,
    blocked: bool,
}

impl<P: ShimPlatform> Task<P> {
    /// `semaphore_signal_trap`, `semaphore_signal_all_trap` and
    /// `semaphore_signal_thread_trap` (Mach 33-35).
    pub(crate) fn sys_semaphore_signal(
        &self,
        semaphore: MachPortName,
        kind: SemaphoreSignalKind,
    ) -> KernReturn {
        let thread = match kind {
            SemaphoreSignalKind::Thread(name) if name != MachPortName::NULL => {
                // port_name_to_thread, before the semaphore.
                let Some(thread) = self.global.ipc.lock().thread_for_name(name.0) else {
                    return KernReturn::INVALID_ARGUMENT;
                };
                Some(thread)
            }
            _ => None,
        };
        let id = match self.global.ipc.lock().semaphore_for_name(semaphore) {
            Ok(id) => id,
            Err(error) => return error,
        };
        let mut table = self.global.semaphores.lock();
        match kind {
            SemaphoreSignalKind::One => not_waiting_is_success(table.signal(id, None, false, true)),
            SemaphoreSignalKind::All => not_waiting_is_success(table.signal(id, None, true, false)),
            SemaphoreSignalKind::Thread(_) => table.signal(id, thread, false, false),
        }
    }

    /// `semaphore_signal_internal_trap`, for `bsdthread_terminate`.
    pub(crate) fn semaphore_signal_name(&self, semaphore: MachPortName) -> KernReturn {
        self.sys_semaphore_signal(semaphore, SemaphoreSignalKind::One)
    }

    /// `semaphore_wait_trap`, `semaphore_wait_signal_trap`,
    /// `semaphore_timedwait_trap` and `semaphore_timedwait_signal_trap`
    /// (Mach 36-39).
    pub(crate) fn sys_semaphore_wait(
        &self,
        semaphore: MachPortName,
        signal: Option<MachPortName>,
        timeout: Option<MachTimespec>,
    ) -> KernReturn {
        self.semaphore_wait_trap(semaphore, signal, timeout).result
    }

    /// The traps' common path. A `{0, 0}` timeout does not block.
    fn semaphore_wait_trap(
        &self,
        semaphore: MachPortName,
        signal: Option<MachPortName>,
        timeout: Option<MachTimespec>,
    ) -> WaitOutcome {
        let not_blocked = |result| WaitOutcome {
            result,
            blocked: false,
        };
        if let Some(timeout) = timeout
            && !(0..1_000_000_000).contains(&timeout.nanoseconds)
        {
            // BAD_MACH_TIMESPEC
            return not_blocked(KernReturn::INVALID_VALUE);
        }
        let mut ipc = self.global.ipc.lock();
        let signal = match signal.map(|name| ipc.semaphore_for_name(name)).transpose() {
            Ok(signal) => signal,
            Err(error) => return not_blocked(error),
        };
        let id = match ipc.semaphore_for_name(semaphore) {
            Ok(id) => id,
            Err(error) => return not_blocked(error),
        };
        drop(ipc);
        let timeout = timeout.map(|timeout| {
            Duration::new(
                u64::from(timeout.seconds),
                timeout.nanoseconds.cast_unsigned(),
            )
        });
        self.semaphore_wait(id, signal, timeout)
    }

    /// `semaphore_wait_internal`: take a count or block, after signaling
    /// `signal` once queued. `Some(Duration::ZERO)` does not block
    /// (`SEMAPHORE_TIMEOUT_NOBLOCK`).
    fn semaphore_wait(
        &self,
        id: SemaphoreId,
        signal: Option<SemaphoreId>,
        timeout: Option<Duration>,
    ) -> WaitOutcome {
        let mut table = self.global.semaphores.lock();
        let mut waiter = None;
        let mut result = match table.semaphores.get_mut(&id) {
            None => KernReturn::TERMINATED,
            Some(semaphore) if semaphore.count > 0 => {
                semaphore.count -= 1;
                KernReturn::SUCCESS
            }
            Some(_) if timeout == Some(Duration::ZERO) => KernReturn::OPERATION_TIMED_OUT,
            Some(semaphore) => {
                semaphore.count = -1;
                let queued = self.new_waiter();
                if semaphore.policy & SYNC_POLICY_REVERSED != 0 {
                    semaphore.waiters.push_front(Arc::clone(&queued));
                } else {
                    semaphore.waiters.push(Arc::clone(&queued));
                }
                waiter = Some(queued);
                KernReturn::SUCCESS
            }
        };
        if let Some(signal) = signal
            && table.signal(signal, None, false, true) == KernReturn::TERMINATED
        {
            // The semaphore to signal died; the wait must not hang on it.
            // A wakeup that already arrived still counts.
            if let Some(queued) = waiter.take()
                && let Some(semaphore) = table.semaphores.get_mut(&id)
                && !semaphore.waiters.withdraw(&queued)
                && !queued.was_restarted()
            {
                return WaitOutcome {
                    result: KernReturn::SUCCESS,
                    blocked: false,
                };
            }
            result = KernReturn::TERMINATED;
        }
        drop(table);
        let Some(waiter) = waiter else {
            return WaitOutcome {
                result,
                blocked: false,
            };
        };
        let mut ended = self.wait_for_wakeup(&waiter, timeout);
        if ended != WaitResult::Awakened {
            let mut table = self.global.semaphores.lock();
            // A destroyed semaphore restarted every waiter.
            let withdrawn = table
                .semaphores
                .get_mut(&id)
                .is_some_and(|semaphore| semaphore.waiters.withdraw(&waiter));
            if !withdrawn {
                ended = WaitResult::Awakened;
            }
        }
        let result = match ended {
            WaitResult::Awakened if waiter.was_restarted() => KernReturn::TERMINATED,
            WaitResult::Awakened => KernReturn::SUCCESS,
            WaitResult::TimedOut => KernReturn::OPERATION_TIMED_OUT,
            WaitResult::Interrupted => KernReturn::ABORTED,
        };
        WaitOutcome {
            result,
            blocked: true,
        }
    }

    /// `__semwait_signal` (BSD 334, a cancellation point when `cancelable`)
    /// and `__semwait_signal_nocancel` (BSD 423): wait on `semaphore` after
    /// signaling `signal` if it is not null, for at most the relative or
    /// absolute (`CLOCK_REALTIME`) `timeout`.
    pub(crate) fn sys_semwait_signal(
        &self,
        cancelable: bool,
        semaphore: MachPortName,
        signal: MachPortName,
        timeout: Option<(bool, i64, i32)>,
    ) -> Result<(), Errno> {
        if cancelable {
            let _ = self.testcancel(TestCancel::BeforeWait);
        }
        let signal = (signal != MachPortName::NULL).then_some(signal);
        let mut truncated = false;
        let timeout = timeout.map(|(relative, seconds, nanoseconds)| {
            let (seconds, nanoseconds) = if seconds.cast_unsigned() >> 32 != 0 {
                // Mach timeouts have 32-bit seconds.
                truncated = true;
                (0xffff_ffff, 0)
            } else {
                (seconds, nanoseconds)
            };
            if relative {
                return MachTimespec {
                    seconds: seconds.cast_unsigned().trunc(),
                    nanoseconds,
                };
            }
            let (now_seconds, now_nanoseconds) = self.realtime();
            let passed = if now_seconds == seconds {
                now_nanoseconds > i64::from(nanoseconds)
            } else {
                now_seconds > seconds
            };
            if passed {
                return MachTimespec {
                    seconds: 0,
                    nanoseconds: 0,
                };
            }
            let mut left_seconds = seconds - now_seconds;
            let mut left_nanoseconds = i64::from(nanoseconds) - now_nanoseconds;
            if left_nanoseconds < 0 {
                left_nanoseconds += NSEC_PER_SEC;
                left_seconds -= 1;
            }
            MachTimespec {
                seconds: left_seconds.cast_unsigned().trunc(),
                nanoseconds: left_nanoseconds.trunc(),
            }
        });
        let outcome = self.semaphore_wait_trap(semaphore, signal, timeout);
        match outcome.result {
            // Mach cannot wait that long; a wait that ended without blocking
            // reports it.
            KernReturn::SUCCESS if truncated && !outcome.blocked => Err(Errno::EINTR),
            KernReturn::SUCCESS => Ok(()),
            KernReturn::ABORTED => Err(Errno::EINTR),
            KernReturn::OPERATION_TIMED_OUT => Err(Errno::ETIMEDOUT),
            _ => Err(Errno::EINVAL),
        }
    }

    /// `nanotime`: `CLOCK_REALTIME` as seconds and nanoseconds.
    fn realtime(&self) -> (i64, i64) {
        use litebox_platform::time::{SystemTime as _, TimeProvider};
        let since_epoch = self
            .global
            .platform
            .current_time()
            .duration_since(&<P as TimeProvider>::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        (
            i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
            i64::from(since_epoch.subsec_nanos()),
        )
    }
}

/// `semaphore_signal` and `semaphore_signal_all` do not report whether a
/// thread was waiting.
fn not_waiting_is_success(result: KernReturn) -> KernReturn {
    if result == KernReturn::NOT_WAITING {
        KernReturn::SUCCESS
    } else {
        result
    }
}
