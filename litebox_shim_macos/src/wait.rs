// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest wait queues: XNU's `waitq` for the shim's blocking calls.
//!
//! A subsystem keeps one [`WaitQueue`] per address or object under its own
//! lock. A blocked thread enqueues a [`Waiter`] under that lock, releases it,
//! and sleeps in [`Task::wait_for_wakeup`] until a waker marks it woken under
//! the same lock, its timeout passes, the process exits, or the thread is
//! aborted (`thread_abort_safely`). Waits never reach a host wait queue: each
//! guest thread sleeps on its own shim wait state.
//!
//! Every guest wait the shim emulates is `THREAD_ABORTSAFE` in XNU (ulock,
//! psynch, semaphores, Mach message queues, `mach_wait_until`,
//! `thread_switch`, and blocked reads and writes), so every wait ends for a
//! pending safe abort, which the task's interrupt check also consumes.

use crate::{GuestThread, ShimPlatform, Task, ThreadId};
use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use litebox::event::wait::{WaitError, Waker};

/// A blocked guest thread.
pub(crate) struct Waiter<P: ShimPlatform> {
    pub(crate) thread: ThreadId,
    /// The blocked thread, whose cancellation state wakers may consult
    /// (`uthread_is_cancelled`).
    pub(crate) guest: Arc<GuestThread<P>>,
    /// Set by a waker, under the queue owner's lock, as it removes the
    /// waiter from its queue.
    woken: AtomicBool,
    /// Set before `woken` when the object waited on went away
    /// (`THREAD_RESTART`).
    restarted: AtomicBool,
    waker: Waker<P>,
}

impl<P: ShimPlatform> Waiter<P> {
    /// Mark the waiter woken and wake its thread. Callers hold the queue
    /// owner's lock and have removed the waiter from its queue.
    pub(crate) fn wake(&self) {
        self.woken.store(true, Ordering::Release);
        self.waker.wake();
    }

    /// [`Waiter::wake`] with `THREAD_RESTART`: the object is gone.
    pub(crate) fn restart(&self) {
        self.restarted.store(true, Ordering::Relaxed);
        self.wake();
    }

    /// Whether the wakeup was [`Waiter::restart`]. Read after the wait was
    /// awakened.
    pub(crate) fn was_restarted(&self) -> bool {
        self.restarted.load(Ordering::Relaxed)
    }
}

/// A [`Waiter`] whose platform type may be erased, for wait queues kept in
/// state that is not generic over the platform (Mach port queues).
pub(crate) trait AnyWaiter: Send + Sync {
    fn wake(&self);
    fn restart(&self);
}

impl<P: ShimPlatform> AnyWaiter for Waiter<P> {
    fn wake(&self) {
        Waiter::wake(self);
    }

    fn restart(&self) {
        Waiter::restart(self);
    }
}

/// Threads blocked on one address or object, in wakeup order. XNU orders a
/// turnstile wait queue by priority; every guest thread shares one priority
/// band, so the order is FIFO.
pub(crate) struct WaitQueue<W: ?Sized> {
    waiters: VecDeque<Arc<W>>,
}

/// Threads blocked on a Mach port's message queue.
pub(crate) type PortWaitQueue = WaitQueue<dyn AnyWaiter>;

impl<W: ?Sized> Default for WaitQueue<W> {
    fn default() -> Self {
        Self {
            waiters: VecDeque::new(),
        }
    }
}

impl<W: ?Sized> core::fmt::Debug for WaitQueue<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WaitQueue")
            .field("waiters", &self.waiters.len())
            .finish()
    }
}

impl<W: ?Sized + AnyWaiter> WaitQueue<W> {
    pub(crate) fn push(&mut self, waiter: Arc<W>) {
        self.waiters.push_back(waiter);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn len(&self) -> usize {
        self.waiters.len()
    }

    pub(crate) fn wake_all(&mut self) {
        for waiter in self.waiters.drain(..) {
            AnyWaiter::wake(&*waiter);
        }
    }

    /// Wake every waiter with `THREAD_RESTART`.
    pub(crate) fn restart_all(&mut self) {
        for waiter in self.waiters.drain(..) {
            AnyWaiter::restart(&*waiter);
        }
    }

    /// Withdraw a waiter whose wait ended without a wakeup. Returns `false`
    /// if a waker took it first, so the wait was satisfied after all.
    pub(crate) fn withdraw(&mut self, waiter: &Arc<W>) -> bool {
        let Some(index) = self
            .waiters
            .iter()
            .position(|w| core::ptr::addr_eq(Arc::as_ptr(w), Arc::as_ptr(waiter)))
        else {
            return false;
        };
        self.waiters.remove(index);
        true
    }
}

impl<P: ShimPlatform> WaitQueue<Waiter<P>> {
    /// Queue `waiter` first, as a `SYNC_POLICY_REVERSED` (LIFO) wait queue
    /// does (`waitq_thread_insert`).
    pub(crate) fn push_front(&mut self, waiter: Arc<Waiter<P>>) {
        self.waiters.push_front(waiter);
    }

    /// Wake the first waiter (`waitq_wakeup64_identify`).
    pub(crate) fn wake_one(&mut self) -> Option<ThreadId> {
        let waiter = self.waiters.pop_front()?;
        waiter.wake();
        Some(waiter.thread)
    }

    /// Wake `thread` if it waits here (`waitq_wakeup64_thread`).
    pub(crate) fn wake_thread(&mut self, thread: ThreadId) -> bool {
        let Some(index) = self.waiters.iter().position(|w| w.thread == thread) else {
            return false;
        };
        let waiter = self.waiters.remove(index).expect("index was just found");
        waiter.wake();
        true
    }
}

/// How a wait ended, like XNU's `wait_result_t`. A [`Waiter::restart`] ends
/// the wait as [`WaitResult::Awakened`]; [`Waiter::was_restarted`] tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitResult {
    Awakened,
    TimedOut,
    /// The process is exiting or the thread was aborted
    /// (`THREAD_INTERRUPTED`).
    Interrupted,
}

impl<P: ShimPlatform> Task<P> {
    /// A waiter for the calling thread, to enqueue under the queue owner's lock.
    pub(crate) fn new_waiter(&self) -> Arc<Waiter<P>> {
        Arc::new(Waiter {
            thread: self.thread.guest.id,
            guest: Arc::clone(&self.thread.guest),
            woken: AtomicBool::new(false),
            restarted: AtomicBool::new(false),
            waker: self.wait_cx().waker().clone(),
        })
    }

    /// Sleep until `waiter` is woken, `timeout` passes, the process exits, or
    /// the thread is aborted. Must be called without the queue owner's lock.
    /// Unless the result is [`WaitResult::Awakened`], the caller takes that
    /// lock again and [`WaitQueue::withdraw`]s the waiter; if a waker already
    /// took it, the wait was awakened after all.
    pub(crate) fn wait_for_wakeup(
        &self,
        waiter: &Waiter<P>,
        timeout: Option<core::time::Duration>,
    ) -> WaitResult {
        self.wait_for_wakeup_in(waiter, &self.wait_cx().with_timeout(timeout))
    }

    /// [`Task::wait_for_wakeup`] until `deadline`.
    pub(crate) fn wait_for_wakeup_until(
        &self,
        waiter: &Waiter<P>,
        deadline: Option<P::Instant>,
    ) -> WaitResult {
        self.wait_for_wakeup_in(waiter, &self.wait_cx().with_deadline(deadline))
    }

    fn wait_for_wakeup_in(
        &self,
        waiter: &Waiter<P>,
        cx: &litebox::event::wait::WaitContext<'_, P>,
    ) -> WaitResult {
        let mut aborted = false;
        let result = cx.wait_until(|| {
            if waiter.woken.load(Ordering::Acquire) {
                return true;
            }
            // A wakeup that already happened wins over a racing abort, as
            // `clear_wait` fails for a thread that is no longer waiting.
            aborted = self.thread.guest.take_abort();
            aborted
        });
        match result {
            Ok(()) if aborted => WaitResult::Interrupted,
            Ok(()) => WaitResult::Awakened,
            Err(WaitError::TimedOut) => WaitResult::TimedOut,
            Err(WaitError::Interrupted) => WaitResult::Interrupted,
        }
    }

    /// An abort-safe sleep with nothing to wake it (`assert_wait_deadline`
    /// on a private event, then `thread_block`): it ends when `timeout`
    /// passes ([`WaitResult::TimedOut`]) or the process exits or the thread
    /// is aborted ([`WaitResult::Interrupted`]).
    pub(crate) fn abortable_sleep(&self, timeout: Option<core::time::Duration>) -> WaitResult {
        let cx = self.wait_cx().with_timeout(timeout);
        match cx.wait_until(|| self.thread.guest.take_abort()) {
            Ok(()) | Err(WaitError::Interrupted) => WaitResult::Interrupted,
            Err(WaitError::TimedOut) => WaitResult::TimedOut,
        }
    }

    /// Whether `deadline` has passed, as a wait until it would find.
    pub(crate) fn deadline_passed(&self, deadline: Option<P::Instant>) -> bool {
        use litebox_platform::time::Instant as _;
        deadline.is_some_and(|deadline| {
            deadline
                .checked_duration_since(&self.global.platform.now())
                .is_none()
        })
    }

    /// The deadline of a Mach message timeout of `milliseconds`.
    pub(crate) fn msg_deadline(&self, milliseconds: u32) -> P::Instant {
        use litebox_platform::time::Instant as _;
        let now = self.global.platform.now();
        now.checked_add(core::time::Duration::from_millis(u64::from(milliseconds)))
            .unwrap_or(now)
    }

    /// The time left until `deadline` in `mach_absolute_time` units; zero if
    /// it has passed.
    pub(crate) fn mach_deadline_timeout(&self, deadline: u64) -> core::time::Duration {
        let platform = self.global.platform;
        let ticks = deadline.saturating_sub(platform.mach_absolute_time());
        let timebase = platform.mach_timebase_info();
        let nanoseconds =
            u128::from(ticks) * u128::from(timebase.numer) / u128::from(timebase.denom.max(1));
        core::time::Duration::from_nanos(u64::try_from(nanoseconds).unwrap_or(u64::MAX))
    }
}
