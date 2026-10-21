// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! pthread cancellation, after XNU's `bsd/kern/kern_sig.c`
//! (`__pthread_testcancel`, `__pthread_markcancel`, `__pthread_canceled`)
//! and `osfmk/kern/thread_act.c` (`thread_abort_safely`).
//!
//! `pthread_cancel` marks the target (`UT_CANCEL`) and, unless it is inside
//! a BSD call that is not a cancellation point or has cancellation disabled,
//! aborts its abort-safe wait. A cancellation point tests the mark: before a
//! cancelable call it fails the call with `EINTR`, and inside a cancelable
//! wait it aborts the calling thread's own wait, which then ends with
//! `EINTR` (`KERN_ABORTED`). libpthread acts on the `EINTR`.

use crate::{GuestThread, ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox_common_macos::{errno::Errno, syscall::MachPortName};

/// `uu_flag` bits (`bsd/sys/user.h`).
pub(crate) mod ut {
    /// The thread is in a BSD call that is not (yet) a cancellation point.
    pub const NOTCANCELPT: u32 = 0x0000_0004;
    /// Marked for cancellation by `__pthread_markcancel`.
    pub const CANCEL: u32 = 0x0000_0008;
    /// The cancellation was acted upon (`__pthread_canceled(0)`).
    pub const CANCELED: u32 = 0x0000_0010;
    pub const CANCELDISABLE: u32 = 0x0000_0020;
    /// No signal is delivered to the thread again.
    pub const NO_SIGMASK: u32 = 0x0010_0000;
}

/// Where `__pthread_testcancel` runs: before the call does anything
/// (`presyscall`), or inside a call that waits next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestCancel {
    BeforeCall,
    BeforeWait,
}

impl<P: ShimPlatform> GuestThread<P> {
    /// `uthread_is_cancelled`: marked, not yet acted upon, and enabled.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.flags.load(Ordering::Acquire) & (ut::CANCELDISABLE | ut::CANCEL | ut::CANCELED)
            == ut::CANCEL
    }

    /// Consume a pending safe abort.
    pub(crate) fn take_abort(&self) -> bool {
        self.abort.load(Ordering::Relaxed) && self.abort.swap(false, Ordering::Acquire)
    }

    /// `thread_abort_safely`: end the thread's abort-safe wait, or its next
    /// one if it is not waiting, unless it returns to the guest first. A
    /// thread running guest code is interrupted so that it re-enters the
    /// shim, which clears the abort before resuming it.
    pub(crate) fn abort_safely(&self) {
        self.abort.store(true, Ordering::Release);
        if let Some(handle) = &*self.interrupt.lock() {
            handle.interrupt();
        }
    }
}

impl<P: ShimPlatform> Task<P> {
    /// A BSD call starts (`unix_syscall`): it is not a cancellation point
    /// unless it tests for cancellation.
    pub(crate) fn enter_bsd_call(&self) {
        self.thread
            .guest
            .flags
            .fetch_or(ut::NOTCANCELPT, Ordering::AcqRel);
    }

    pub(crate) fn leave_bsd_call(&self) {
        self.thread
            .guest
            .flags
            .fetch_and(!ut::NOTCANCELPT, Ordering::AcqRel);
    }

    /// The thread returns to the guest: a pending safe abort that no wait
    /// consumed is dropped (`thread_apc_ast`).
    pub(crate) fn clear_abort(&self) {
        self.thread.guest.abort.store(false, Ordering::Relaxed);
    }

    /// `__pthread_testcancel`: the call becomes a cancellation point. A
    /// pending, enabled cancellation fails it with `EINTR` before it starts,
    /// or aborts the wait it makes next.
    pub(crate) fn testcancel(&self, at: TestCancel) -> Result<(), Errno> {
        let guest = &self.thread.guest;
        let flags = guest.flags.fetch_and(!ut::NOTCANCELPT, Ordering::AcqRel);
        if flags & (ut::CANCELDISABLE | ut::CANCEL | ut::CANCELED) != ut::CANCEL {
            return Ok(());
        }
        match at {
            TestCancel::BeforeCall => Err(Errno::EINTR),
            TestCancel::BeforeWait => {
                guest.abort.store(true, Ordering::Release);
                Ok(())
            }
        }
    }

    /// `__pthread_markcancel` (BSD 332): mark the thread a port name in this
    /// task names for cancellation, and abort its wait if it is at a
    /// cancellation point with cancellation enabled.
    pub(crate) fn sys_pthread_markcancel(&self, thread: MachPortName) -> Result<(), Errno> {
        let target = self
            .global
            .ipc
            .lock()
            .thread_for_name(thread.0)
            .and_then(|id| self.guest_thread(id))
            .ok_or(Errno::ESRCH)?;
        let marked = target
            .flags
            .try_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
                (flags & (ut::CANCEL | ut::CANCELED) == 0)
                    .then_some(flags | ut::CANCEL | ut::NO_SIGMASK)
            });
        if let Ok(flags) = marked
            && flags & (ut::NOTCANCELPT | ut::CANCELDISABLE) == 0
        {
            target.abort_safely();
        }
        Ok(())
    }

    /// `__pthread_canceled` (BSD 333): 1 enables and 2 disables
    /// cancellation; any other action turns a pending, enabled cancellation
    /// into an acted-upon one (EINVAL if there is none).
    pub(crate) fn sys_pthread_canceled(&self, action: i32) -> Result<(), Errno> {
        let flags = &self.thread.guest.flags;
        match action {
            1 => {
                flags.fetch_and(!ut::CANCELDISABLE, Ordering::AcqRel);
                Ok(())
            }
            2 => {
                flags.fetch_or(ut::CANCELDISABLE, Ordering::AcqRel);
                Ok(())
            }
            _ => flags
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current & (ut::CANCELDISABLE | ut::CANCEL | ut::CANCELED) == ut::CANCEL)
                        .then_some((current & !ut::CANCEL) | ut::CANCELED | ut::NO_SIGMASK)
                })
                .map(|_| ())
                .map_err(|_| Errno::EINVAL),
        }
    }
}
