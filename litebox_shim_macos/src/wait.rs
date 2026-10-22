// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest wait queues: XNU's `waitq` for the shim's blocking calls.
//!
//! A subsystem keeps one [`WaitQueue`] per address or object under its own
//! lock. A blocked thread enqueues a [`Waiter`] under that lock, releases it,
//! and sleeps in [`Task::wait_for_wakeup`] until a waker marks it woken under
//! the same lock, its timeout passes, or the process exits. Waits never reach
//! a host wait queue: each guest thread sleeps on its own shim wait state.

use crate::{ShimPlatform, Task, ThreadId};
use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use litebox::event::wait::{WaitError, Waker};

/// A blocked guest thread.
pub(crate) struct Waiter<P: ShimPlatform> {
    pub(crate) thread: ThreadId,
    /// Set by a waker, under the queue owner's lock, as it removes the
    /// waiter from its queue.
    woken: AtomicBool,
    waker: Waker<P>,
}

impl<P: ShimPlatform> Waiter<P> {
    fn wake(&self) {
        self.woken.store(true, Ordering::Release);
        self.waker.wake();
    }
}

/// Threads blocked on one address or object, in wakeup order. XNU orders a
/// turnstile wait queue by priority; every guest thread shares one priority
/// band, so the order is FIFO.
pub(crate) struct WaitQueue<P: ShimPlatform> {
    waiters: VecDeque<Arc<Waiter<P>>>,
}

impl<P: ShimPlatform> Default for WaitQueue<P> {
    fn default() -> Self {
        Self {
            waiters: VecDeque::new(),
        }
    }
}

impl<P: ShimPlatform> WaitQueue<P> {
    pub(crate) fn push(&mut self, waiter: Arc<Waiter<P>>) {
        self.waiters.push_back(waiter);
    }

    /// Wake the first waiter (`waitq_wakeup64_identify`).
    pub(crate) fn wake_one(&mut self) -> Option<ThreadId> {
        let waiter = self.waiters.pop_front()?;
        waiter.wake();
        Some(waiter.thread)
    }

    pub(crate) fn wake_all(&mut self) {
        for waiter in self.waiters.drain(..) {
            waiter.wake();
        }
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

    /// Withdraw a waiter whose wait ended without a wakeup. Returns `false`
    /// if a waker took it first, so the wait was satisfied after all.
    pub(crate) fn withdraw(&mut self, waiter: &Arc<Waiter<P>>) -> bool {
        let Some(index) = self.waiters.iter().position(|w| Arc::ptr_eq(w, waiter)) else {
            return false;
        };
        self.waiters.remove(index);
        true
    }
}

/// How a wait ended, like XNU's `wait_result_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitResult {
    Awakened,
    TimedOut,
    /// The process is exiting (`THREAD_INTERRUPTED`).
    Interrupted,
}

impl<P: ShimPlatform> Task<P> {
    /// A waiter for the calling thread, to enqueue under the queue owner's lock.
    pub(crate) fn new_waiter(&self) -> Arc<Waiter<P>> {
        Arc::new(Waiter {
            thread: self.thread.guest.id,
            woken: AtomicBool::new(false),
            waker: self.wait_cx().waker().clone(),
        })
    }

    /// Sleep until `waiter` is woken, `timeout` passes, or the process exits.
    /// Must be called without the queue owner's lock. Unless the result is
    /// [`WaitResult::Awakened`], the caller takes that lock again and
    /// [`WaitQueue::withdraw`]s the waiter; if a waker already took it, the
    /// wait was awakened after all.
    pub(crate) fn wait_for_wakeup(
        &self,
        waiter: &Waiter<P>,
        timeout: Option<core::time::Duration>,
    ) -> WaitResult {
        let cx = self.wait_cx().with_timeout(timeout);
        match cx.wait_until(|| waiter.woken.load(Ordering::Acquire)) {
            Ok(()) => WaitResult::Awakened,
            Err(WaitError::TimedOut) => WaitResult::TimedOut,
            Err(WaitError::Interrupted) => WaitResult::Interrupted,
        }
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
