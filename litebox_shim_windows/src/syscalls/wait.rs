// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT wait syscalls.

use alloc::sync::{Arc, Weak};

use litebox::event::observer::Observer;
use litebox::event::polling::TryOpError;
use litebox::event::wait::WaitError;
use litebox::event::{Events, IOPollable as _};
use litebox::platform::{RawConstPointer as _, SystemTime as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::AccessMask;
use crate::syscalls::event::{EventObject, EventSubsystem};
use crate::syscalls::mutant::{MutantObject, MutantSubsystem};
use crate::syscalls::semaphore::{SemaphoreObject, SemaphoreSubsystem};
use crate::syscalls::thread::{ThreadObject, ThreadSubsystem};
use crate::syscalls::{Handle, WaitAcquireResult};
use crate::{ConstPtr, ShimFS, ShimPlatform, Task};

/// A dispatcher object that a guest thread can block on.
enum WaitableObject<Platform: ShimPlatform> {
    Thread(Arc<ThreadObject<Platform>>),
    Event(Arc<EventObject<Platform>>),
    Mutant(Arc<MutantObject<Platform>>),
    Semaphore(Arc<SemaphoreObject<Platform>>),
}

impl<Platform: ShimPlatform> WaitableObject<Platform> {
    /// Registers `observer` to be woken when this object is signaled.
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            Self::Thread(thread) => thread.register_observer(observer, mask),
            Self::Event(event) => event.register_observer(observer, mask),
            Self::Mutant(mutant) => mutant.register_observer(observer, mask),
            Self::Semaphore(semaphore) => semaphore.register_observer(observer, mask),
        }
    }

    /// Attempts to satisfy a wait, consuming the signal if the object
    /// auto-resets. Returns `None` while the object is nonsignaled.
    fn try_acquire(
        &self,
        thread_id: usize,
        thread: &ThreadObject<Platform>,
    ) -> Option<WaitAcquireResult> {
        match self {
            // Thread completion is terminal, so readiness is enough.
            Self::Thread(thread) => thread
                .check_io_events()
                .contains(Events::IN)
                .then_some(WaitAcquireResult::Acquired),
            Self::Event(event) => event.try_acquire().then_some(WaitAcquireResult::Acquired),
            Self::Mutant(mutant) => mutant.try_acquire(thread_id, thread),
            Self::Semaphore(semaphore) => semaphore
                .try_acquire()
                .then_some(WaitAcquireResult::Acquired),
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Resolves `handle` to the dispatcher object it names, requiring
    /// `SYNCHRONIZE` access.
    fn waitable_object(&self, handle: Handle) -> Result<WaitableObject<Platform>, NtStatus> {
        macro_rules! try_wait {
            ($subsystem:ty, $variant:ident, $field:ident) => {
                match self.typed_handle_entry_with_access::<$subsystem>(
                    handle,
                    AccessMask::SYNCHRONIZE.bits(),
                ) {
                    Ok(entry) => {
                        return Ok(WaitableObject::$variant(
                            entry.with_entry(|entry| Arc::clone(&entry.$field)),
                        ));
                    }
                    // Not this object type; try the next waitable subsystem.
                    Err(NtStatus::OBJECT_TYPE_MISMATCH) => {}
                    Err(status) => return Err(status),
                }
            };
        }

        try_wait!(ThreadSubsystem<Platform>, Thread, thread);
        try_wait!(EventSubsystem<Platform>, Event, event);
        try_wait!(MutantSubsystem<Platform>, Mutant, mutant);
        try_wait!(SemaphoreSubsystem<Platform>, Semaphore, semaphore);

        // TODO(waitable-objects): timers, processes and
        // I/O completion ports are waitable on the host but not yet modeled.
        litebox_util_log::debug!(
            handle:? = handle;
            "Rejecting wait on a handle that names no waitable object"
        );
        Err(NtStatus::OBJECT_TYPE_MISMATCH)
    }

    pub(crate) fn sys_nt_wait_for_single_object(
        &self,
        handle: Handle,
        alertable: bool,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> NtStatus {
        let object = match self.waitable_object(handle) {
            Ok(object) => object,
            Err(status) => return status,
        };
        let timeout = match timeout {
            Some(timeout) => {
                let Some(timeout) = timeout.read_at_offset(0) else {
                    return NtStatus::ACCESS_VIOLATION;
                };
                Some(self.wait_timeout_duration(timeout))
            }
            None => None,
        };
        if alertable {
            // TODO(windows-apc): interrupt alertable waits when user APC delivery is modeled.
            litebox_util_log::debug!("Treating alertable wait as non-alertable");
        }

        match self.wait_on_events(
            false,
            timeout,
            Events::IN,
            |observer, mask| {
                object.register_observer(observer, mask);
                Ok(())
            },
            || {
                object
                    .try_acquire(self.thread_object.thread_id(), &self.thread_object)
                    .ok_or(TryOpError::<NtStatus>::TryAgain)
            },
        ) {
            Ok(acquire_result) => match acquire_result {
                WaitAcquireResult::Acquired => NtStatus::SUCCESS,
                WaitAcquireResult::Abandoned => NtStatus::ABANDONED_WAIT_0,
            },
            Err(TryOpError::WaitError(WaitError::TimedOut)) => NtStatus::TIMEOUT,
            Err(TryOpError::WaitError(WaitError::Interrupted)) => NtStatus::ALERTED,
            Err(TryOpError::TryAgain) => unreachable!("blocking wait cannot return TryAgain"),
            Err(TryOpError::Other(status)) => status,
        }
    }

    fn duration_from_100ns(intervals: u64) -> core::time::Duration {
        const INTERVALS_PER_SECOND: u64 = 10_000_000;

        core::time::Duration::new(
            intervals / INTERVALS_PER_SECOND,
            ((intervals % INTERVALS_PER_SECOND) * 100)
                .try_into()
                .expect("subsecond 100ns intervals fit in u32 nanoseconds"),
        )
    }

    pub(crate) fn wait_timeout_duration(&self, timeout: i64) -> core::time::Duration {
        const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;

        if timeout <= 0 {
            return Self::duration_from_100ns(timeout.unsigned_abs());
        }

        let target = Self::duration_from_100ns(timeout.cast_unsigned());
        let unix_now = self
            .global
            .platform
            .current_time()
            .duration_since(&Platform::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let windows_now = core::time::Duration::from_secs(WINDOWS_TO_UNIX_EPOCH_SECONDS) + unix_now;
        target.saturating_sub(windows_now)
    }
}
