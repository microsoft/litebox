// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT wait syscalls.

use alloc::sync::{Arc, Weak};

use litebox::event::observer::Observer;
use litebox::event::polling::TryOpError;
use litebox::event::wait::WaitError;
use litebox::event::{Events, IOPollable as _};
use litebox::fd::TypedFd;
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform::time::SystemTime as _;

use crate::nt_types::AccessMask;
use crate::syscalls::event::EventObject;
use crate::syscalls::mutant::MutantObject;
use crate::syscalls::semaphore::SemaphoreObject;
use crate::syscalls::thread::ThreadObject;
use crate::syscalls::{Handle, WaitAcquireResult};
use crate::{ConstPtr, ShimPlatform, Task, TypedHandleOperation, WindowsHandleSubsystem};

/// A dispatcher object that a guest thread can block on.
pub(crate) enum WaitableObject<Platform: ShimPlatform> {
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

/// Resolves a handle to its [`WaitableObject`].
///
/// Like the host, `SYNCHRONIZE` access is checked before whether the object is waitable at all.
struct ResolveWaitableObject;

impl<Platform: ShimPlatform> TypedHandleOperation<Platform> for ResolveWaitableObject {
    type Output = WaitableObject<Platform>;

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        _handle: Handle,
        typed: &TypedFd<Subsystem>,
    ) -> Result<WaitableObject<Platform>, NtStatus> {
        task.require_typed_handle_access(typed, AccessMask::SYNCHRONIZE.bits())?;
        task.entry_handle_for(typed)?
            .with_entry(Subsystem::waitable_object)
            .ok_or(NtStatus::OBJECT_TYPE_MISMATCH)
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Resolves `handle` to the dispatcher object it names, requiring
    /// `SYNCHRONIZE` access.
    fn waitable_object(&self, handle: Handle) -> Result<WaitableObject<Platform>, NtStatus> {
        let result = self.with_typed_handle(handle, ResolveWaitableObject);
        if matches!(result, Err(NtStatus::OBJECT_TYPE_MISMATCH)) {
            // TODO(waitable-objects): timers, processes and
            // I/O completion ports are waitable on the host but not yet modeled.
            litebox_util_log::debug!(
                handle:? = handle;
                "Rejecting wait on a handle that names no waitable object"
            );
        }
        result
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
        let timeout = match self.read_optional_wait_timeout(timeout) {
            Ok(timeout) => timeout,
            Err(status) => return status,
        };
        match self.wait_on_events(
            false,
            alertable,
            timeout,
            Events::IN,
            |observer, mask| {
                object.register_observer(observer, mask);
                Ok(())
            },
            || {
                if alertable && self.thread_object.take_pending_classic_alert() {
                    return Err(TryOpError::WaitError(WaitError::Interrupted));
                }
                object
                    .try_acquire(self.thread_object.thread_id(), &self.thread_object)
                    .ok_or(TryOpError::<NtStatus>::TryAgain)
            },
        ) {
            Ok(WaitAcquireResult::Acquired) => NtStatus::SUCCESS,
            Ok(WaitAcquireResult::Abandoned) => NtStatus::ABANDONED_WAIT_0,
            Err(TryOpError::WaitError(WaitError::TimedOut)) => NtStatus::TIMEOUT,
            Err(TryOpError::WaitError(WaitError::Interrupted)) => NtStatus::ALERTED,
            Err(TryOpError::TryAgain) => unreachable!("blocking wait cannot return TryAgain"),
            Err(TryOpError::Other(status)) => status,
        }
    }

    pub(crate) fn sys_nt_delay_execution(
        &self,
        alertable: bool,
        delay_interval: ConstPtr<Platform, i64>,
    ) -> NtStatus {
        let Some(delay_interval) = delay_interval.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        // TODO(windows-apc): deliver user APCs during alertable delays.
        if alertable && self.thread_object.take_pending_classic_alert() {
            return NtStatus::ALERTED;
        }

        match self.sleep(alertable, self.wait_timeout_duration(delay_interval)) {
            WaitError::TimedOut => NtStatus::SUCCESS,
            WaitError::Interrupted => NtStatus::ALERTED,
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

    /// Reads an optional guest NT timeout and converts it to a relative wait duration.
    pub(super) fn read_optional_wait_timeout(
        &self,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> Result<Option<core::time::Duration>, NtStatus> {
        Ok(crate::read_optional_guest_value::<Platform, _>(timeout)?
            .map(|timeout| self.wait_timeout_duration(timeout)))
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::syscalls::ThreadHandle;
    use crate::syscalls::thread::{ThreadAccess, ThreadHandleObject, ThreadSubsystem};
    use crate::tests::{const_ptr, mut_ptr, run_with_test_platform_pointers};
    use std::time::Duration;

    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const DIRECTORY_QUERY: u32 = 0x0001;

    fn unnamed_object_attributes() -> crate::nt_types::ObjectAttributes {
        crate::nt_types::ObjectAttributes {
            length: core::mem::size_of::<crate::nt_types::ObjectAttributes>()
                .try_into()
                .unwrap(),
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    /// Waits on `handle` without blocking and returns the status.
    fn poll_wait(task: &Task<crate::tests::TestPlatform>, handle: Handle) -> NtStatus {
        let timeout = 0i64;
        task.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout)))
    }

    #[test]
    fn wait_requires_synchronize_access_and_a_live_handle() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let attributes = unnamed_object_attributes();

            let mut directory = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut directory),
                    DIRECTORY_QUERY | AccessMask::SYNCHRONIZE.bits(),
                    Some(const_ptr(&attributes)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );
            // Windows checks SYNCHRONIZE before waitability, and directory objects never grant it
            // (verified by `wait_handle_rejections_match_host`).
            assert_eq!(poll_wait(&task, directory), NtStatus::ACCESS_DENIED);

            let mut event = Handle::default();
            assert_eq!(
                task.sys_nt_create_event(
                    mut_ptr(&mut event),
                    EVENT_MODIFY_STATE,
                    Some(const_ptr(&attributes)),
                    0,
                    true,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(poll_wait(&task, event), NtStatus::ACCESS_DENIED);

            assert_eq!(task.sys_nt_close(event), NtStatus::SUCCESS);
            assert_eq!(poll_wait(&task, event), NtStatus::INVALID_HANDLE);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn wait_handle_rejections_match_host() {
        use core::ffi::c_void;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtCreateDirectoryObject(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const crate::nt_types::ObjectAttributes,
            ) -> i32;
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const crate::nt_types::ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtWaitForSingleObject(
                handle: *mut c_void,
                alertable: u8,
                timeout: *const i64,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let attributes = unnamed_object_attributes();
        let timeout = 0i64;
        let mut directory = core::ptr::null_mut();
        let mut event = core::ptr::null_mut();
        // SAFETY: The output and attribute pointers reference live stack locals for the
        // duration of each call.
        let (directory_status, event_status) = unsafe {
            (
                NtCreateDirectoryObject(
                    &raw mut directory,
                    DIRECTORY_QUERY | AccessMask::SYNCHRONIZE.bits(),
                    &raw const attributes,
                ),
                NtCreateEvent(
                    &raw mut event,
                    EVENT_MODIFY_STATE,
                    &raw const attributes,
                    0,
                    1,
                ),
            )
        };
        assert_eq!(directory_status, NtStatus::SUCCESS.as_raw());
        assert_eq!(event_status, NtStatus::SUCCESS.as_raw());
        // SAFETY: Both handles were just created, and `timeout` is a live stack local.
        let (host_directory_wait, host_event_wait) = unsafe {
            (
                NtWaitForSingleObject(directory, 0, &raw const timeout),
                NtWaitForSingleObject(event, 0, &raw const timeout),
            )
        };
        // SAFETY: Both handles are live host handles owned by this test.
        unsafe {
            assert_eq!(NtClose(directory), NtStatus::SUCCESS.as_raw());
            assert_eq!(NtClose(event), NtStatus::SUCCESS.as_raw());
        }

        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut directory = Handle::default();
            let mut event = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut directory),
                    DIRECTORY_QUERY | AccessMask::SYNCHRONIZE.bits(),
                    Some(const_ptr(&attributes)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_create_event(
                    mut_ptr(&mut event),
                    EVENT_MODIFY_STATE,
                    Some(const_ptr(&attributes)),
                    0,
                    true,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(poll_wait(&task, directory).as_raw(), host_directory_wait);
            assert_eq!(poll_wait(&task, event).as_raw(), host_event_wait);
        });
    }

    #[test]
    fn nt_delay_execution_only_consumes_alert_when_alertable() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let interval = 0;

            assert_eq!(
                task.sys_nt_alert_thread(crate::syscalls::ThreadHandle::CURRENT),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_delay_execution(false, const_ptr(&interval)),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_delay_execution(true, const_ptr(&interval)),
                NtStatus::ALERTED
            );
            assert_eq!(
                task.sys_nt_delay_execution(true, const_ptr(&interval)),
                NtStatus::SUCCESS
            );
        });
    }

    #[test]
    fn nt_delay_execution_alertable_wait_wakes_for_alert() {
        run_with_test_platform_pointers(|| {
            let alerter = crate::tests::test_task();
            let waiter = alerter
                .clone_for_test()
                .expect("a live process should accept another thread");
            let handle = alerter
                .insert_typed_handle::<ThreadSubsystem<_>>(
                    ThreadHandleObject {
                        thread: Arc::clone(&waiter.thread_object),
                    },
                    ThreadAccess::ALERT.bits(),
                )
                .unwrap();
            let handle = ThreadHandle::from_raw(handle.as_raw());
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_with_test_platform_pointers(|| {
                    waiter.publish_thread_handle();
                    started_tx.send(()).unwrap();
                    let interval = -100_000_000i64;
                    result_tx
                        .send(waiter.sys_nt_delay_execution(true, const_ptr(&interval)))
                        .unwrap();
                });
            });

            started_rx.recv().unwrap();
            assert_eq!(alerter.sys_nt_alert_thread(handle), NtStatus::SUCCESS);
            assert_eq!(
                result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                NtStatus::ALERTED
            );
            thread.join().unwrap();
            assert_eq!(alerter.sys_nt_close(handle.as_handle()), NtStatus::SUCCESS);
        });
    }
}
