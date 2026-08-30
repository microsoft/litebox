// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT I/O completion port syscalls.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;

use litebox::event::observer::Observer;
use litebox::event::polling::{Pollee, TryOpError};
use litebox::event::wait::WaitError;
use litebox::event::{Events, IOPollable};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ObjectAttributes, ObjectAttributesFlags};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_buffer, probe_guest_output_preserving_value,
};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct IoCompletionAccess: u32 {
        const QUERY_STATE = 0x0001;
        const MODIFY_STATE = 0x0002;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY_STATE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::MODIFY_STATE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits() | AccessMask::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY_STATE.bits()
            | Self::MODIFY_STATE.bits();

        const _ = !0;
    }
}

impl IoCompletionAccess {
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

pub(crate) struct IoCompletionSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for IoCompletionSubsystem<Platform> {
    type Entry = IoCompletionHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for IoCompletionHandleObject<Platform> {}

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem
    for IoCompletionSubsystem<Platform>
{
    fn normalize_desired_access(desired_access: u32) -> u32 {
        IoCompletionAccess::from_desired_access(desired_access).bits()
    }
}

pub(crate) struct IoCompletionHandleObject<Platform: crate::ShimPlatform> {
    port: Arc<IoCompletionObject<Platform>>,
}

pub(crate) struct IoCompletionObject<Platform: crate::ShimPlatform> {
    concurrency_limit: usize,
    active_threads: Mutex<Platform, BTreeSet<usize>>,
    packets: Mutex<Platform, VecDeque<IoCompletionPacket>>,
    pollee: Pollee<Platform>,
}

pub(crate) struct IoCompletionWorkerState<Platform: crate::ShimPlatform> {
    port: Option<Weak<IoCompletionObject<Platform>>>,
    suspended: bool,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes)]
pub(crate) struct IoCompletionPacket {
    completion_key: usize,
    completion_value: usize,
    status: usize,
    information: usize,
}

impl<Platform: crate::ShimPlatform> IoCompletionObject<Platform> {
    fn new(number_of_concurrent_threads: u32) -> Self {
        Self {
            concurrency_limit: number_of_concurrent_threads.max(1) as usize,
            active_threads: Mutex::new(BTreeSet::new()),
            packets: Mutex::new(VecDeque::new()),
            pollee: Pollee::new(),
        }
    }

    fn post(&self, packet: IoCompletionPacket) {
        // TODO(windows-iocp-file-posting): Post packets when associated asynchronous file I/O
        // completes, rather than relying exclusively on NtSetIoCompletion.
        self.packets.lock().push_back(packet);
        self.pollee.notify_observers(Events::IN);
    }

    fn remove_with(
        &self,
        count: usize,
        mut write_packet: impl FnMut(usize, IoCompletionPacket) -> Result<(), NtStatus>,
        mut write_count: impl FnMut(u32) -> Result<(), NtStatus>,
    ) -> Result<bool, NtStatus> {
        let mut packets = self.packets.lock();
        let remove_count = count.min(packets.len());
        if remove_count == 0 {
            return Ok(false);
        }
        for (index, packet) in packets.iter().take(remove_count).copied().enumerate() {
            write_packet(index, packet)?;
        }
        write_count(
            remove_count
                .try_into()
                .expect("packet count is bounded by the u32 input count"),
        )?;
        packets.drain(..remove_count);
        Ok(true)
    }

    fn remove_with_capacity(
        &self,
        thread_id: usize,
        count: usize,
        write_packet: impl FnMut(usize, IoCompletionPacket) -> Result<(), NtStatus>,
        write_count: impl FnMut(u32) -> Result<(), NtStatus>,
    ) -> Result<bool, NtStatus> {
        let mut active_threads = self.active_threads.lock();
        let already_active = active_threads.contains(&thread_id);
        if !already_active && active_threads.len() >= self.concurrency_limit {
            return Ok(false);
        }
        let removed = self.remove_with(count, write_packet, write_count)?;
        if removed && !already_active {
            active_threads.insert(thread_id);
        }
        Ok(removed)
    }

    fn deactivate(&self, thread_id: usize) {
        if self.active_threads.lock().remove(&thread_id) {
            self.pollee.notify_observers(Events::IN);
        }
    }

    fn reactivate(&self, thread_id: usize) {
        // Windows permits a previously associated worker that blocked elsewhere to resume even
        // when this temporarily exceeds the port's concurrency limit.
        self.active_threads.lock().insert(thread_id);
    }
}

impl<Platform: crate::ShimPlatform> IoCompletionWorkerState<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            port: None,
            suspended: false,
        }
    }
}

impl<Platform: crate::ShimPlatform> IOPollable for IoCompletionObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if self.packets.lock().is_empty() {
            Events::empty()
        } else {
            Events::IN
        }
    }
}

impl<Platform: crate::ShimPlatform> IoCompletionHandleObject<Platform> {
    pub(crate) fn port(&self) -> Arc<IoCompletionObject<Platform>> {
        self.port.clone()
    }
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn suspend_io_completion_worker(&self) {
        let mut worker = self.io_completion_worker.lock();
        debug_assert!(!worker.suspended);
        if let Some(port) = worker.port.as_ref().and_then(Weak::upgrade) {
            port.deactivate(self.thread_object.thread_id());
            worker.suspended = true;
        } else {
            worker.port = None;
        }
    }

    pub(crate) fn resume_io_completion_worker(&self) {
        let mut worker = self.io_completion_worker.lock();
        if worker.suspended {
            if let Some(port) = worker.port.as_ref().and_then(Weak::upgrade) {
                port.reactivate(self.thread_object.thread_id());
            } else {
                worker.port = None;
            }
            worker.suspended = false;
        }
    }

    pub(crate) fn release_io_completion_worker(&self) {
        let mut worker = self.io_completion_worker.lock();
        if let Some(port) = worker.port.take()
            && !worker.suspended
            && let Some(port) = port.upgrade()
        {
            port.deactivate(self.thread_object.thread_id());
        }
        worker.suspended = false;
    }

    /// Check if the task is associated with the given IO completion port. If the task is
    /// associated with a different port, it will be deactivated from that port.
    fn prepare_io_completion_wait(&self, port: &Arc<IoCompletionObject<Platform>>) -> bool {
        let mut worker = self.io_completion_worker.lock();
        debug_assert!(!worker.suspended);
        if worker
            .port
            .as_ref()
            .is_some_and(|active_port| active_port.as_ptr() == Arc::as_ptr(port))
        {
            return true;
        }
        if let Some(active_port) = worker.port.take().and_then(|port| port.upgrade()) {
            active_port.deactivate(self.thread_object.thread_id());
        }
        false
    }

    fn associate_io_completion_worker(&self, port: &Arc<IoCompletionObject<Platform>>) {
        let mut worker = self.io_completion_worker.lock();
        debug_assert!(worker.port.is_none());
        worker.port = Some(Arc::downgrade(port));
    }

    fn insert_io_completion_handle(
        &self,
        port: Arc<IoCompletionObject<Platform>>,
        granted_access: IoCompletionAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<IoCompletionSubsystem<Platform>>(
            IoCompletionHandleObject { port },
            granted_access.bits(),
            drop,
        )
    }

    pub(crate) fn close_io_completion_handle(&self, handle: Handle) {
        self.close_typed_handle::<IoCompletionSubsystem<Platform>>(handle, drop);
    }

    pub(crate) fn close_io_completion(io_completion: IoCompletionHandleObject<Platform>) {
        drop(io_completion);
    }

    pub(crate) fn sys_nt_create_io_completion(
        &self,
        io_completion_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        number_of_concurrent_threads: u32,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(io_completion_handle)
        {
            return status;
        }
        let (object_attributes, io_completion_name) =
            match self.read_dispatcher_object_attributes(object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = IoCompletionAccess::from_desired_access(desired_access);
        if let Some(io_completion_name) = io_completion_name {
            let port = Arc::new(IoCompletionObject::new(number_of_concurrent_threads));
            return self.process.object_manager.create_io_completion(
                &io_completion_name,
                &port,
                |port| {
                    let Some(object_attributes) = object_attributes else {
                        return NtStatus::INVALID_PARAMETER;
                    };
                    if !ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                        .contains(ObjectAttributesFlags::OPENIF)
                    {
                        return NtStatus::OBJECT_NAME_COLLISION;
                    }
                    self.publish_io_completion_handle(
                        io_completion_handle,
                        port,
                        granted_access,
                        NtStatus::OBJECT_NAME_EXISTS,
                    )
                },
                || {
                    self.publish_io_completion_handle(
                        io_completion_handle,
                        Arc::clone(&port),
                        granted_access,
                        NtStatus::SUCCESS,
                    )
                },
            );
        }

        let port = Arc::new(IoCompletionObject::new(number_of_concurrent_threads));
        self.publish_io_completion_handle(
            io_completion_handle,
            port,
            granted_access,
            NtStatus::SUCCESS,
        )
    }

    fn publish_io_completion_handle(
        &self,
        io_completion_handle: MutPtr<Platform, Handle>,
        port: Arc<IoCompletionObject<Platform>>,
        granted_access: IoCompletionAccess,
        success_status: NtStatus,
    ) -> NtStatus {
        let Ok(handle) = self.insert_io_completion_handle(port, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if io_completion_handle.write_at_offset(0, handle).is_none() {
            self.close_io_completion_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        success_status
    }

    pub(crate) fn sys_nt_open_io_completion(
        &self,
        io_completion_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(io_completion_handle)
        {
            return status;
        }
        let io_completion_name =
            match self.read_dispatcher_object_attributes(object_attributes, true) {
                Ok((_, Some(name))) => name,
                Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
                Err(status) => return status,
            };
        let port = match self
            .process
            .object_manager
            .resolve_io_completion(&io_completion_name)
        {
            Ok(port) => port,
            Err(status) => return status,
        };
        self.publish_io_completion_handle(
            io_completion_handle,
            port,
            IoCompletionAccess::from_desired_access(desired_access),
            NtStatus::SUCCESS,
        )
    }

    pub(crate) fn sys_nt_set_io_completion(
        &self,
        io_completion_handle: Handle,
        completion_key: usize,
        completion_value: usize,
        status: i32,
        information: usize,
    ) -> NtStatus {
        let entry = match self.typed_handle_entry_with_access::<IoCompletionSubsystem<Platform>>(
            io_completion_handle,
            IoCompletionAccess::MODIFY_STATE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        entry.with_entry(|entry| {
            entry.port.post(IoCompletionPacket {
                completion_key,
                completion_value,
                status: status.cast_unsigned() as usize,
                information,
            });
        });
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_remove_io_completion_ex(
        &self,
        io_completion_handle: Handle,
        io_completion_information: MutPtr<Platform, IoCompletionPacket>,
        count: u32,
        num_entries_removed: MutPtr<Platform, u32>,
        timeout: Option<ConstPtr<Platform, i64>>,
        alertable: bool,
    ) -> NtStatus {
        if count == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(buffer_length) =
            (count as usize).checked_mul(core::mem::size_of::<IoCompletionPacket>())
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        if let Err(status) = probe_guest_output_buffer::<Platform>(
            MutPtr::<Platform, u8>::from_usize(io_completion_information.as_usize()),
            buffer_length,
        ) {
            return status;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(num_entries_removed)
        {
            return status;
        }
        let timeout = match timeout {
            Some(timeout) => match timeout.read_at_offset(0) {
                Some(timeout) => Some(self.wait_timeout_duration(timeout)),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };
        let entry = match self.typed_handle_entry_with_access::<IoCompletionSubsystem<Platform>>(
            io_completion_handle,
            IoCompletionAccess::MODIFY_STATE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let port = entry.with_entry(IoCompletionHandleObject::port);
        let already_associated = self.prepare_io_completion_wait(&port);
        if alertable {
            // TODO(windows-apc): Interrupt alertable IOCP waits to deliver queued user APCs.
            litebox_util_log::debug!("Treating alertable IOCP wait as non-alertable");
        }

        match self.wait_on_events(
            false,
            timeout,
            Events::IN,
            |observer, mask| {
                port.register_observer(observer, mask);
                Ok(())
            },
            || match port.remove_with_capacity(
                self.thread_object.thread_id(),
                count as usize,
                |index, packet| {
                    io_completion_information
                        .write_at_offset(index.cast_signed(), packet)
                        .ok_or(NtStatus::ACCESS_VIOLATION)
                },
                |removed| {
                    num_entries_removed
                        .write_at_offset(0, removed)
                        .ok_or(NtStatus::ACCESS_VIOLATION)
                },
            ) {
                Ok(true) => {
                    if !already_associated {
                        self.associate_io_completion_worker(&port);
                    }
                    Ok(())
                }
                Ok(false) => Err(TryOpError::TryAgain),
                Err(status) => Err(TryOpError::Other(status)),
            },
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(TryOpError::WaitError(WaitError::TimedOut)) => NtStatus::TIMEOUT,
            Err(TryOpError::WaitError(WaitError::Interrupted)) => NtStatus::ALERTED,
            Err(TryOpError::TryAgain) => unreachable!("blocking wait cannot return TryAgain"),
            Err(TryOpError::Other(status)) => status,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::utils::TruncateExt as _;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributes;
    use crate::tests::{const_ptr, mut_ptr, test_task};

    const IO_COMPLETION_ALL_ACCESS: u32 = 0x001f_0003;

    fn object_attributes_size() -> u32 {
        size_of::<ObjectAttributes>().trunc()
    }

    fn packet(completion_key: usize) -> IoCompletionPacket {
        IoCompletionPacket {
            completion_key,
            completion_value: 0,
            status: 0,
            information: 0,
        }
    }

    fn remove_one<FS: ShimFS>(
        task: &Task<crate::tests::TestPlatform, FS>,
        port: &Arc<IoCompletionObject<crate::tests::TestPlatform>>,
    ) -> Result<Option<IoCompletionPacket>, NtStatus> {
        let already_associated = task.prepare_io_completion_wait(port);
        let mut packet = None;
        let removed = port.remove_with_capacity(
            task.thread_object.thread_id(),
            1,
            |_, value| {
                packet = Some(value);
                Ok(())
            },
            |_| Ok(()),
        )?;
        if removed && !already_associated {
            task.associate_io_completion_worker(port);
        }
        Ok(packet)
    }

    #[test]
    fn concurrency_limit_throttles_other_workers() {
        let first = test_task();
        let second = first.clone_for_test().unwrap();
        let port = Arc::new(IoCompletionObject::new(1));
        port.post(packet(1));
        port.post(packet(2));

        assert_eq!(
            remove_one(&first, &port).unwrap().unwrap().completion_key,
            1
        );
        assert!(remove_one(&second, &port).unwrap().is_none());
        assert_eq!(port.packets.lock().len(), 1);

        assert_eq!(
            remove_one(&first, &port).unwrap().unwrap().completion_key,
            2
        );
        first.release_io_completion_worker();
        second.release_io_completion_worker();
    }

    #[test]
    fn blocking_worker_releases_concurrency_capacity() {
        let first = test_task();
        let second = first.clone_for_test().unwrap();
        let port = Arc::new(IoCompletionObject::new(1));
        port.post(packet(1));
        port.post(packet(2));

        assert!(remove_one(&first, &port).unwrap().is_some());
        first.suspend_io_completion_worker();
        assert_eq!(
            remove_one(&second, &port).unwrap().unwrap().completion_key,
            2
        );

        port.post(packet(3));
        assert!(
            !port
                .remove_with_capacity(
                    first.thread_object.thread_id(),
                    1,
                    |_, _| unreachable!("a suspended worker must not dequeue at capacity"),
                    |_| unreachable!("a suspended worker must not dequeue at capacity"),
                )
                .unwrap()
        );
        assert_eq!(port.packets.lock().len(), 1);

        first.resume_io_completion_worker();
        assert_eq!(port.active_threads.lock().len(), 2);
        first.release_io_completion_worker();
        second.release_io_completion_worker();
        assert!(port.active_threads.lock().is_empty());
    }

    #[test]
    fn timed_out_wait_restores_worker_capacity() {
        let task = test_task();
        let port = Arc::new(IoCompletionObject::new(1));
        port.post(packet(1));
        assert!(remove_one(&task, &port).unwrap().is_some());

        let nonblocking_result: Result<(), TryOpError<NtStatus>> = task.wait_on_events(
            true,
            None,
            Events::IN,
            |_, _| unreachable!("a nonblocking wait must not register an observer"),
            || Err(TryOpError::TryAgain),
        );
        assert!(matches!(nonblocking_result, Err(TryOpError::TryAgain)));
        assert!(
            port.active_threads
                .lock()
                .contains(&task.thread_object.thread_id())
        );
        assert!(!task.io_completion_worker.lock().suspended);

        let result: Result<(), TryOpError<NtStatus>> = task.wait_on_events(
            false,
            Some(core::time::Duration::ZERO),
            Events::IN,
            |_, _| Ok::<(), NtStatus>(()),
            || Err(TryOpError::TryAgain),
        );

        assert!(matches!(
            result,
            Err(TryOpError::WaitError(WaitError::TimedOut))
        ));
        assert!(
            port.active_threads
                .lock()
                .contains(&task.thread_object.thread_id())
        );
        assert!(!task.io_completion_worker.lock().suspended);
        task.release_io_completion_worker();
    }

    #[test]
    fn create_validates_object_attributes_without_clobbering_output() {
        let task = test_task();
        let mut handle = Handle::from_raw(usize::MAX);
        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut handle),
                IO_COMPLETION_ALL_ACCESS,
                Some(const_ptr(&bad_length)),
                0,
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));

        let root_without_name = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::from_raw(4),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut handle),
                IO_COMPLETION_ALL_ACCESS,
                Some(const_ptr(&root_without_name)),
                0,
            ),
            NtStatus::OBJECT_NAME_INVALID
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_create_io_completion_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateIoCompletion(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                number_of_concurrent_threads: u32,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let mut host_handle = core::ptr::null_mut();
        // SAFETY: The output pointer is valid, object attributes are null as accepted by native
        // NtCreateIoCompletion, and the returned host handle is closed before leaving the test.
        let host_success = unsafe {
            let status = NtCreateIoCompletion(
                &raw mut host_handle,
                IO_COMPLETION_ALL_ACCESS,
                core::ptr::null(),
                0,
            );
            if status == NtStatus::SUCCESS.as_raw() && !host_handle.is_null() {
                assert_eq!(NtClose(host_handle), NtStatus::SUCCESS.as_raw());
            }
            status
        };

        let task = test_task();
        let mut shim_handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut shim_handle),
                IO_COMPLETION_ALL_ACCESS,
                None,
                0,
            )
            .as_raw(),
            host_success
        );
        assert!(!shim_handle.is_null());

        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        // SAFETY: The host output and attributes pointers are valid locals; the bad length is the
        // parameter being tested.
        let host_bad_length = unsafe {
            NtCreateIoCompletion(
                &raw mut host_handle,
                IO_COMPLETION_ALL_ACCESS,
                &raw const bad_length,
                0,
            )
        };
        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut shim_handle),
                IO_COMPLETION_ALL_ACCESS,
                Some(const_ptr(&bad_length)),
                0,
            )
            .as_raw(),
            host_bad_length
        );

        let root_without_name = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::from_raw(4),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        // SAFETY: The host output and attributes pointers are valid locals; root without an object
        // name is the probed native behavior.
        let host_root_without_name = unsafe {
            NtCreateIoCompletion(
                &raw mut host_handle,
                IO_COMPLETION_ALL_ACCESS,
                &raw const root_without_name,
                0,
            )
        };
        let mut shim_root_without_name_handle = Handle::from_raw(usize::MAX);
        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut shim_root_without_name_handle),
                IO_COMPLETION_ALL_ACCESS,
                Some(const_ptr(&root_without_name)),
                0,
            )
            .as_raw(),
            host_root_without_name
        );
    }
}
