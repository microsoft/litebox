// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT semaphore object syscalls.

use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;

use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawMutPointer as _;
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes};
use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, Task, probe_guest_output_preserving_value};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct SemaphoreAccess: u32 {
        const QUERY_STATE = 0x0001;
        const MODIFY_STATE = 0x0002;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY_STATE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::MODIFY_STATE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | AccessMask::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY_STATE.bits()
            | Self::MODIFY_STATE.bits();

        const _ = !0;
    }
}

impl SemaphoreAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        Self::from_bits_retain(AccessMask::expand_generic_access(
            desired_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        ))
    }
}

pub(crate) struct SemaphoreSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for SemaphoreSubsystem<Platform> {
    type Entry = SemaphoreHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for SemaphoreHandleObject<Platform> {}

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem<Platform>
    for SemaphoreSubsystem<Platform>
{
    fn normalize_desired_access(desired_access: u32) -> u32 {
        SemaphoreAccess::from_desired_access(desired_access).bits()
    }

    fn waitable_object(
        entry: &Self::Entry,
    ) -> Option<crate::syscalls::wait::WaitableObject<Platform>> {
        Some(crate::syscalls::wait::WaitableObject::Semaphore(
            alloc::sync::Arc::clone(&entry.semaphore),
        ))
    }
}

pub(crate) struct SemaphoreHandleObject<Platform: crate::ShimPlatform> {
    pub(crate) semaphore: Arc<SemaphoreObject<Platform>>,
}

/// A counting dispatcher object. Positive counts are signaled and each
/// successful wait consumes one count.
pub(crate) struct SemaphoreObject<Platform: crate::ShimPlatform> {
    count: Mutex<Platform, i32>,
    maximum: i32,
    pollee: Pollee<Platform>,
}

impl<Platform: crate::ShimPlatform> SemaphoreObject<Platform> {
    fn new(initial_count: i32, maximum_count: i32) -> Self {
        Self {
            count: Mutex::new(initial_count),
            maximum: maximum_count,
            pollee: Pollee::new(),
        }
    }

    /// Attempts to satisfy one wait, consuming exactly one available count.
    pub(crate) fn try_acquire(&self) -> bool {
        let mut count = self.count.lock();
        if *count <= 0 {
            return false;
        }
        *count -= 1;
        true
    }

    fn release(&self, release_count: i32) -> Result<i32, NtStatus> {
        let mut count = self.count.lock();
        let previous = *count;
        let Some(next) = previous.checked_add(release_count) else {
            return Err(NtStatus::SEMAPHORE_LIMIT_EXCEEDED);
        };
        if next > self.maximum {
            return Err(NtStatus::SEMAPHORE_LIMIT_EXCEEDED);
        }
        *count = next;
        drop(count);

        self.pollee.notify_observers(Events::IN);
        Ok(previous)
    }
}

impl<Platform: crate::ShimPlatform> IOPollable for SemaphoreObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if *self.count.lock() > 0 {
            Events::IN
        } else {
            Events::empty()
        }
    }
}

impl<Platform: crate::ShimPlatform> Task<Platform> {
    pub(crate) fn sys_nt_create_semaphore(
        &self,
        semaphore_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        initial_count: i32,
        maximum_count: i32,
    ) -> NtStatus {
        self.create_named_dispatcher_object(
            semaphore_handle,
            desired_access,
            object_attributes,
            || {
                if maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                Ok(Arc::new(SemaphoreObject::new(initial_count, maximum_count)))
            },
            |_| {},
        )
    }

    pub(crate) fn sys_nt_open_semaphore(
        &self,
        semaphore_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        self.open_named_dispatcher_object::<SemaphoreObject<Platform>>(
            semaphore_handle,
            desired_access,
            object_attributes,
        )
    }

    pub(crate) fn sys_nt_release_semaphore(
        &self,
        semaphore_handle: Handle,
        release_count: i32,
        previous_count: Option<MutPtr<Platform, i32>>,
    ) -> NtStatus {
        if let Some(previous_count) = previous_count
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(previous_count)
        {
            return status;
        }
        if release_count <= 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let entry = match self.typed_handle_entry_with_access::<SemaphoreSubsystem<Platform>>(
            semaphore_handle,
            SemaphoreAccess::MODIFY_STATE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let previous = match entry.with_entry(|entry| entry.semaphore.release(release_count)) {
            Ok(previous) => previous,
            Err(status) => return status,
        };
        if let Some(previous_count) = previous_count
            && previous_count.write_at_offset(0, previous).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }
}

// TODO(semaphore-query): Implement NtQuerySemaphore.

#[cfg(test)]
mod tests {
    extern crate std;

    use core::time::Duration;

    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributesFlags;
    use crate::tests::{
        TestPlatform, const_ptr, mut_ptr, object_attributes, test_task, unicode_string, utf16_units,
    };

    const SEMAPHORE_ALL_ACCESS: u32 = 0x001f_0003;

    fn create_semaphore(initial_count: i32, maximum_count: i32) -> (Task<TestPlatform>, Handle) {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_semaphore(
                mut_ptr(&mut handle),
                SEMAPHORE_ALL_ACCESS,
                None,
                initial_count,
                maximum_count,
            ),
            NtStatus::SUCCESS
        );
        (task, handle)
    }

    fn zero_timeout_wait(task: &Task<TestPlatform>, handle: Handle) -> NtStatus {
        let timeout = 0i64;
        task.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout)))
    }

    #[test]
    fn exhausted_count_blocks_until_release() {
        let (task, handle) = create_semaphore(1, 1);

        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::SUCCESS);
        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::TIMEOUT);

        let waiter = task.clone_for_test().expect("process is live");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let timeout = -10_000_000i64;
            started_tx.send(()).unwrap();
            let status =
                waiter.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout)));
            result_tx.send(status).unwrap();
        });

        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            task.sys_nt_release_semaphore(handle, 1, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            NtStatus::SUCCESS
        );
        thread.join().unwrap();
        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::TIMEOUT);
    }

    #[test]
    fn release_overflow_preserves_count_and_previous_count() {
        let (task, handle) = create_semaphore(2, 2);
        let mut previous = 0x1234_5678;

        assert_eq!(
            task.sys_nt_release_semaphore(handle, 1, Some(mut_ptr(&mut previous))),
            NtStatus::SEMAPHORE_LIMIT_EXCEEDED
        );
        assert_eq!(previous, 0x1234_5678);
        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::SUCCESS);
        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::SUCCESS);
        assert_eq!(zero_timeout_wait(&task, handle), NtStatus::TIMEOUT);
    }

    #[test]
    fn named_create_and_open_share_count() {
        let task = test_task();
        let name_units = utf16_units(r"\BaseNamedObjects\LiteBoxSemaphore");
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
        let mut created = Handle::default();
        assert_eq!(
            task.sys_nt_create_semaphore(
                mut_ptr(&mut created),
                SEMAPHORE_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                0,
                1,
            ),
            NtStatus::SUCCESS
        );
        let mut opened = Handle::default();
        assert_eq!(
            task.sys_nt_open_semaphore(
                mut_ptr(&mut opened),
                SEMAPHORE_ALL_ACCESS,
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            task.sys_nt_release_semaphore(created, 1, None),
            NtStatus::SUCCESS
        );
        assert_eq!(zero_timeout_wait(&task, opened), NtStatus::SUCCESS);
        assert_eq!(zero_timeout_wait(&task, created), NtStatus::TIMEOUT);
    }
}
