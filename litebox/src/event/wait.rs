// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Support infrastructure for interruptible waits.
//!
//! Ordinary waits in litebox, via the [`RawMutex`] trait, are not easily
//! interrupted--they can only be woken up by another thread explicitly
//! signaling the raw mutex. This is fine for ordinary uses of mutexes, locks,
//! and condition variables, cases where waits can be guaranteed to eventually
//! complete.
//!
//! However, waits on guest- or externally-controlled conditions (e.g., futexes,
//! eventfds, IO events) must be interruptible due to process termination or
//! asynchronous signals, since the waited-on event may never occur. This module
//! provides infrastructure for handling such cases.
//!
//! The core type is [`WaitState`], which models a per-thread wait state. The
//! thread can create a [`WaitContext`] from the wait state, which can then be
//! used to perform interruptible waits on a given condition. The wait context
//! produces a [`Waker`], which can be passed to other threads to wake up the
//! waiting thread. And finally, the wait state can produce a [`ThreadHandle`],
//! which can be used to interrupt the thread in any state, whether it is
//! waiting or running guest code.

use alloc::sync::Arc;
use core::{marker::PhantomData, sync::atomic::Ordering};

use crate::{
    platform::{
        ImmediatelyWokenUp, Instant as _, RawMutex, ThreadProvider, TimeProvider,
        UnblockedOrTimedOut,
    },
    sync::RawSyncPrimitivesProvider,
};
use thiserror::Error;

/// The wait state for a thread.
///
/// A thread can be running, waiting, or running in the guest. This object
/// tracks that state and provides the ability to wait and be woken up or
/// interrupted.
///
/// This is meant to be stored in a per-thread object and used for all waits for
/// that thread.
pub struct WaitState<Platform: RawSyncPrimitivesProvider> {
    waker: Waker<Platform>,
    /// Make sure this is `Send` but not `Sync` so that no one tries to share it
    /// across threads.
    _phantom: PhantomData<core::cell::Cell<()>>,
}

struct WaitStateInner<Platform: RawSyncPrimitivesProvider> {
    platform: &'static Platform,
    condvar: Platform::RawMutex,
}

/// A handle, returned by [`WaitContext::waker`], that can be used to wake up a
/// thread waiting on via [`WaitContext::wait_until`].
pub struct Waker<Platform: RawSyncPrimitivesProvider>(Arc<WaitStateInner<Platform>>);

impl<Platform: RawSyncPrimitivesProvider> Clone for Waker<Platform> {
    fn clone(&self) -> Self {
        Waker(self.0.clone())
    }
}

impl<Platform: RawSyncPrimitivesProvider> Waker<Platform> {
    /// Causes the thread blocked in [`WaitContext::wait_until`] to wake up and
    /// reevaluate its wait condition.
    ///
    /// Note that this does not interrupt guest execution; to interrupt guest
    /// execution, use [`ThreadHandle::interrupt`].
    pub fn wake(&self) {
        self.0.wake();
    }
}

impl<Platform: RawSyncPrimitivesProvider> WaitState<Platform> {
    /// Creates a new wait state.
    ///
    /// Typically, you should create just one wait state per thread.
    pub fn new(platform: &'static Platform) -> Self {
        Self {
            waker: Waker(Arc::new(WaitStateInner {
                platform,
                condvar: <Platform::RawMutex as RawMutex>::INIT,
            })),
            _phantom: PhantomData,
        }
    }

    /// Returns a wait context that can be used to wait for things.
    pub fn context(&self) -> WaitContext<'_, Platform>
    where
        Platform: TimeProvider,
    {
        WaitContext::new(&self.waker)
    }

    /// Returns a handle that can be used to interrupt the current thread,
    /// whether it is waiting or running guest code.
    pub fn thread_handle(&self) -> ThreadHandle<Platform>
    where
        Platform: ThreadProvider,
    {
        let current_thread = self.waker.0.platform.current_thread();
        ThreadHandle {
            waker: self.waker.clone(),
            thread: current_thread,
        }
    }

    /// Sets the wait state so that [`ThreadHandle::interrupt`] will interrupt
    /// the guest execution, then calls `f` to see if the guest is still ready
    /// to run.
    ///
    /// `f` should check if there is already a reason to not run the guest
    /// (e.g., pending interrupts or events).
    ///
    /// If this returns `true`, then you must call
    /// [`finish_running_guest`](Self::finish_running_guest) before using the
    /// wait state again.
    ///
    /// # Panics
    /// Panics if called while not in the running state.
    #[must_use]
    pub fn prepare_to_run_guest(&self, f: impl FnOnce() -> bool) -> bool {
        assert_eq!(
            self.waker.0.state_for_assert(),
            ThreadState::RUNNING_IN_HOST
        );
        self.waker
            .0
            .set_state(ThreadState::RUNNING_IN_GUEST, Ordering::SeqCst);
        let ready_to_run_guest = f();
        if !ready_to_run_guest {
            self.waker
                .0
                .set_state(ThreadState::RUNNING_IN_HOST, Ordering::Relaxed);
        }
        ready_to_run_guest
    }

    /// Sets the wait state back to running after running the guest.
    ///
    /// # Panics
    /// Panics if there was not a prior successful call to
    /// [`prepare_to_run_guest`](Self::prepare_to_run_guest).
    pub fn finish_running_guest(&self) {
        let state = self.waker.0.state_for_assert();
        assert!(
            state == ThreadState::RUNNING_IN_GUEST || state == ThreadState::INTERRUPTED_GUEST,
            "{state:?}"
        );
        self.waker
            .0
            .set_state(ThreadState::RUNNING_IN_HOST, Ordering::Relaxed);
    }

    /// Attempts to wake a thread that is in the WAITING state, then issuing a futex wake.
    ///
    /// Returns `true` if the thread was woken. Returns `false` if the thread was
    /// not in the WAITING state.
    pub fn try_wake_condvar(condvar: &Platform::RawMutex) {
        let v = condvar.underlying_atomic().fetch_update(
            Ordering::Release,
            Ordering::Relaxed,
            |state| match ThreadState(state) {
                ThreadState::RUNNING_IN_HOST
                | ThreadState::WOKEN
                | ThreadState::INTERRUPTED_GUEST
                | ThreadState::RUNNING_IN_GUEST => None,
                ThreadState::WAITING => Some(ThreadState::WOKEN.0),
                state => unreachable!("{state:?}"),
            },
        );
        match v.map(ThreadState) {
            Ok(ThreadState::WAITING) => {
                condvar.wake_one();
            }
            Ok(state) => unreachable!("{state:?}"),
            Err(_) => {
                // Provide a consistent release fence even if we didn't wake up
                // the thread.
                core::sync::atomic::fence(Ordering::Release);
            }
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> WaitStateInner<Platform> {
    /// Wakes up the thread if it is waiting (but not if it is running in the guest).
    fn wake(&self) {
        WaitState::<Platform>::try_wake_condvar(&self.condvar);
    }

    fn state_for_assert(&self) -> ThreadState {
        ThreadState(self.condvar.underlying_atomic().load(Ordering::Relaxed))
    }

    fn set_state(&self, new_state: ThreadState, ordering: Ordering) {
        self.condvar
            .underlying_atomic()
            .store(new_state.0, ordering);
    }
}

pub struct ThreadHandle<Platform: RawSyncPrimitivesProvider + ThreadProvider> {
    waker: Waker<Platform>,
    thread: Platform::ThreadHandle,
}

impl<Platform: RawSyncPrimitivesProvider + ThreadProvider> ThreadHandle<Platform> {
    /// Interrupts the thread, whether it is waiting or running guest code.
    ///
    /// If it is waiting in [`WaitContext::wait_until`] or
    /// [`WaitContext::sleep`], it will be woken up to reevaluate its wait
    /// condition and interrupt condition. If it is running guest code, the
    /// platform will interrupt the thread and re-enter the shim.
    pub fn interrupt(&self) {
        let condvar = &self.waker.0.condvar;
        let v = condvar.underlying_atomic().fetch_update(
            Ordering::Release,
            Ordering::Relaxed,
            |state| match ThreadState(state) {
                ThreadState::RUNNING_IN_HOST
                | ThreadState::WOKEN
                | ThreadState::INTERRUPTED_GUEST => None,
                ThreadState::WAITING => Some(ThreadState::WOKEN.0),
                ThreadState::RUNNING_IN_GUEST => Some(ThreadState::INTERRUPTED_GUEST.0),
                state => unreachable!("{state:?}"),
            },
        );
        match v.map(ThreadState) {
            Ok(ThreadState::WAITING) => {
                condvar.wake_one();
            }
            Ok(ThreadState::RUNNING_IN_GUEST) => {
                self.waker.0.platform.interrupt_thread(&self.thread);
            }
            Ok(state) => unreachable!("{state:?}"),
            Err(_) => {
                // Provide a consistent release fence even if we didn't wake up
                // the thread.
                core::sync::atomic::fence(Ordering::Release);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ThreadState(u32);

impl ThreadState {
    /// The thread is running in the host/shim (this includes waiting
    /// non-interruptibly via a [`RawMutex`]).
    const RUNNING_IN_HOST: Self = Self(0);
    /// The thread is waiting via [`WaitContext::wait_until`].
    const WAITING: Self = Self(1);
    /// The thread is waiting and has been woken up to reevaluate its wait
    /// condition.
    const WOKEN: Self = Self(2);
    /// The thread is running guest code (or transitioning to/from guest code).
    const RUNNING_IN_GUEST: Self = Self(3);
    /// The thread is running guest code and something has called the platform
    /// to interrupt it. It will return to the shim as soon as possible.
    const INTERRUPTED_GUEST: Self = Self(4);
}

impl core::fmt::Debug for ThreadState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = match *self {
            Self::RUNNING_IN_HOST => "RUNNING_IN_HOST",
            Self::WAITING => "WAITING",
            Self::WOKEN => "WOKEN",
            Self::RUNNING_IN_GUEST => "RUNNING_IN_GUEST",
            Self::INTERRUPTED_GUEST => "INTERRUPTED_GUEST",
            Self(v) => return write!(f, "UNKNOWN({v})"),
        };
        f.write_str(v)
    }
}

/// A context object used to perform interruptible waits.
///
/// This is created from a [`WaitState`] but can be augmented with timeouts and
/// with code to evaluate whether the wait should be interrupted.
pub struct WaitContext<'a, Platform: RawSyncPrimitivesProvider + TimeProvider> {
    waker: &'a Waker<Platform>,
    deadline: Option<Platform::Instant>,
    check_interrupt: &'a dyn CheckForInterrupt,
    // Not Send or Sync--this can only be used by the thread that created it.
    _phantom: PhantomData<*mut ()>,
}

/// A trait for checking whether the wait should be interrupted.
pub trait CheckForInterrupt {
    /// Returns `true` if the wait should be interrupted.
    ///
    /// This is called by [`WaitContext::wait_until`] each time it is about to
    /// block the thread. If this returns `true`, the wait will return with
    /// [`WaitError::Interrupted`].
    fn check_for_interrupt(&self) -> bool;
}

struct NeverInterrupt;

impl CheckForInterrupt for NeverInterrupt {
    fn check_for_interrupt(&self) -> bool {
        false
    }
}

impl<'a, Platform: RawSyncPrimitivesProvider + TimeProvider> WaitContext<'a, Platform> {
    fn new(waker: &'a Waker<Platform>) -> WaitContext<'a, Platform> {
        WaitContext {
            waker,
            deadline: None,
            check_interrupt: &NeverInterrupt,
            _phantom: PhantomData,
        }
    }

    /// Returns a new context that uses the given interrupt checker.
    ///
    /// Note that this _replaces_ any existing interrupt checker.
    #[must_use]
    pub fn with_check_for_interrupt(&self, f: &'a dyn CheckForInterrupt) -> Self {
        Self {
            check_interrupt: f,
            ..*self
        }
    }

    /// Returns a new context that has a deadline after the given duration.
    ///
    /// If the existing context already has an earlier deadline or if no timeout
    /// is provided, then this just clones the context.
    #[must_use]
    pub fn with_timeout(&self, timeout: impl Into<Option<core::time::Duration>>) -> Self {
        // If this overflows, treat that as no deadline.
        if let Some(deadline) = timeout
            .into()
            .and_then(|timeout| self.waker.0.platform.now().checked_add(timeout))
        {
            self.with_deadline(deadline)
        } else {
            Self { ..*self }
        }
    }

    /// Returns a new context that has the given deadline.
    ///
    /// If the existing context already has an earlier deadline, then this just
    /// clones the context.
    #[must_use]
    pub fn with_deadline(&self, deadline: impl Into<Option<Platform::Instant>>) -> Self {
        let mut this = Self { ..*self };
        if let Some(deadline) = deadline.into()
            && self.deadline.is_none_or(|d| deadline < d)
        {
            this.deadline = Some(deadline);
        }
        this
    }

    /// Returns the deadline for this wait context, if any.
    pub fn deadline(&self) -> Option<Platform::Instant> {
        self.deadline
    }

    /// Returns the remaining timeout for this wait context, if any.
    pub fn remaining_timeout(&self) -> Option<core::time::Duration> {
        self.deadline.and_then(|deadline| {
            let now = self.waker.0.platform.now();
            deadline.checked_duration_since(&now)
        })
    }

    /// Moves the thread into the waiting state. This must happen before
    /// evaluating the wait and interrupt conditions so that wakeups are not
    /// missed.
    fn start_wait(&self) {
        self.waker.0.condvar.on_wait_start();
        self.waker
            .0
            .set_state(ThreadState::WAITING, Ordering::SeqCst);
    }

    /// Returns the thread to the running state after a wait.
    fn end_wait(&self) {
        self.waker
            .0
            .set_state(ThreadState::RUNNING_IN_HOST, Ordering::Relaxed);
        self.waker.0.condvar.on_wait_end();
    }

    /// Checks whether the wait should be interrupted. If not, then performs
    /// the wait.
    ///
    /// `start_wait` must have already been called and the wait condition
    /// evaluated.
    fn commit_wait(&self) -> Result<(), WaitError> {
        // Check for timeout before checking for an interrupt. This is important
        // for things like sleep(), where we want to return `TimedOut` rather than
        // `Interrupted` if the deadline has already passed.
        let timeout = if self.deadline.is_some() {
            Some(self.remaining_timeout().ok_or(WaitError::TimedOut)?)
        } else {
            None
        };
        if self.check_interrupt.check_for_interrupt() {
            return Err(WaitError::Interrupted);
        }

        if let Some(timeout) = timeout {
            let r = self
                .waker
                .0
                .condvar
                .block_or_timeout(ThreadState::WAITING.0, timeout);
            match r {
                Ok(UnblockedOrTimedOut::Unblocked) | Err(ImmediatelyWokenUp) => Ok(()),
                Ok(UnblockedOrTimedOut::TimedOut) => Err(WaitError::TimedOut),
            }
        } else {
            let _ = self.waker.0.condvar.block(ThreadState::WAITING.0);
            Ok(())
        }
    }

    /// Sleep until the wait is interrupted or times out.
    ///
    /// A deadline can be provided with [`with_deadline`](Self::with_deadline)
    /// or [`with_timeout`](Self::with_timeout). If no deadline is provided,
    /// this sleeps until interrupted.
    ///
    /// If the deadline has already passed, this returns immediately with
    /// [`WaitError::TimedOut`], even if there is a pending interrupt.
    pub fn sleep(&self) -> WaitError {
        self.wait_until(|| false).unwrap_err()
    }

    /// Waits until `ready` returns `true`.
    ///
    /// `ready` is called once before the thread sleeps and then again each time the
    /// thread is woken up. The caller must arrange for wakeups at the
    /// appropriate time. This can be done by a call to [`Waker::wake`] or
    /// [`ThreadHandle::interrupt`].
    ///
    /// A deadline for the wait can be provided with
    /// [`with_deadline`](Self::with_deadline) or
    /// [`with_timeout`](Self::with_timeout).
    ///
    /// # Panics
    /// Panics if the thread is not currently in the running state, either
    /// because `ready` calls `wait_until` recursively, or  because
    /// [`prepare_to_run_guest`](WaitState::prepare_to_run_guest) was called
    /// without a subsequent call to
    /// [`finish_running_guest`](WaitState::finish_running_guest).
    pub fn wait_until(&self, mut ready: impl FnMut() -> bool) -> Result<(), WaitError> {
        assert_eq!(
            self.waker.0.state_for_assert(),
            ThreadState::RUNNING_IN_HOST
        );
        let _end_wait = crate::utils::defer(|| self.end_wait());
        loop {
            self.start_wait();
            if ready() {
                break Ok(());
            }
            self.commit_wait()?;
        }
    }

    /// Returns the waker associated with this wait context.
    pub fn waker(&self) -> &Waker<Platform> {
        self.waker
    }
}

/// An error that can occur during a wait.
#[derive(Debug, Error)]
pub enum WaitError {
    #[error("wait was interrupted")]
    Interrupted,
    #[error("wait timed out")]
    TimedOut,
}
