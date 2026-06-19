// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT worker factory syscalls.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, read_object_attributes};
use crate::syscalls::iocp::{IoCompletionAccess, IoCompletionObject, IoCompletionSubsystem};
use crate::syscalls::{Handle, ProcessHandle};
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, probe_guest_output_preserving_value,
    remove_raw_handle,
};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct WorkerFactoryAccess: u32 {
        const RELEASE_WORKER = 0x0001;
        const WAIT = 0x0002;
        const SET_INFORMATION = 0x0004;
        const QUERY_INFORMATION = 0x0008;
        const READY_WORKER = 0x0010;
        const SHUTDOWN = 0x0020;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY_INFORMATION.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::SET_INFORMATION.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | AccessMask::SYNCHRONIZE.bits()
            | Self::WAIT.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::RELEASE_WORKER.bits()
            | Self::WAIT.bits()
            | Self::SET_INFORMATION.bits()
            | Self::QUERY_INFORMATION.bits()
            | Self::READY_WORKER.bits()
            | Self::SHUTDOWN.bits();

        const _ = !0;
    }
}

impl WorkerFactoryAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if desired_access & AccessMask::GENERIC_READ.bits() != 0 {
            access.insert(Self::READ);
        }
        if desired_access & AccessMask::GENERIC_WRITE.bits() != 0 {
            access.insert(Self::WRITE);
        }
        if desired_access & AccessMask::GENERIC_EXECUTE.bits() != 0 {
            access.insert(Self::EXECUTE);
        }
        if desired_access & AccessMask::GENERIC_ALL.bits() != 0 {
            access.insert(Self::ALL_ACCESS);
        }
        access.remove(Self::from_bits_retain(
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits()
                | AccessMask::GENERIC_ALL.bits(),
        ));
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerFactoryInformationClass {
    BindingCount = 3,
    ThreadMinimum = 4,
    ThreadMaximum = 5,
    ThreadSoftMaximum = 14,
}

impl WorkerFactoryInformationClass {
    fn from_raw(raw: u32) -> Result<Self, NtStatus> {
        match raw {
            3 => Ok(Self::BindingCount),
            4 => Ok(Self::ThreadMinimum),
            5 => Ok(Self::ThreadMaximum),
            14 => Ok(Self::ThreadSoftMaximum),
            _ => Err(NtStatus::INVALID_INFO_CLASS),
        }
    }
}

pub(crate) struct WorkerFactorySubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for WorkerFactorySubsystem<Platform> {
    type Entry = WorkerFactoryHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry
    for WorkerFactoryHandleObject<Platform>
{
}

pub(crate) struct WorkerFactoryHandleObject<Platform: crate::ShimPlatform> {
    factory: Arc<WorkerFactoryObject<Platform>>,
    granted_access: WorkerFactoryAccess,
}

pub(crate) struct WorkerFactoryObject<Platform: crate::ShimPlatform> {
    _completion_port: Arc<IoCompletionObject<Platform>>,
    _start_routine: usize,
    _start_parameter: usize,
    binding_count: AtomicU32,
    thread_minimum: AtomicU32,
    thread_maximum: AtomicU32,
    thread_soft_maximum: AtomicU32,
    shutdown: AtomicBool,
    _stack_reserve: usize,
    _stack_commit: usize,
}

pub(crate) struct WorkerFactoryCreateParameters<Platform: RawPointerProvider> {
    pub(crate) worker_factory_handle: MutPtr<Platform, Handle>,
    pub(crate) desired_access: u32,
    pub(crate) object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    pub(crate) completion_port_handle: Handle,
    pub(crate) worker_process_handle: ProcessHandle,
    pub(crate) start_routine: usize,
    pub(crate) start_parameter: usize,
    pub(crate) max_thread_count: u32,
    pub(crate) stack_reserve: usize,
    pub(crate) stack_commit: usize,
}

fn validate_worker_factory_object_attributes<Platform: RawPointerProvider>(
    object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
) -> Result<(), NtStatus> {
    let Some(object_attributes) = object_attributes else {
        return Ok(());
    };
    let object_attributes = read_object_attributes::<Platform>(object_attributes)?;
    if object_attributes.object_name == 0 && !object_attributes.root_directory.is_null() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(())
}

fn commit_worker_factory_shutdown<Platform: crate::ShimPlatform>(
    factory: &WorkerFactoryObject<Platform>,
    pending_worker_count: MutPtr<Platform, i32>,
) -> NtStatus {
    if pending_worker_count.write_at_offset(0, 0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    factory.shutdown.store(true, Ordering::Relaxed);
    NtStatus::SUCCESS
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn worker_factory_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, WorkerFactorySubsystem<Platform>>, NtStatus>
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<WorkerFactorySubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn io_completion_port(
        &self,
        handle: Handle,
    ) -> Result<Arc<IoCompletionObject<Platform>>, NtStatus> {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<IoCompletionSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        let Some(entry) = self.global.litebox.descriptor_table().entry_handle(&typed) else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        entry.with_entry(|entry| {
            entry.require_access(IoCompletionAccess::MODIFY_STATE)?;
            Ok(entry.port())
        })
    }

    fn validate_worker_process_handle(
        &self,
        process_handle: ProcessHandle,
    ) -> Result<(), NtStatus> {
        if process_handle.is_current() {
            return Ok(());
        }
        let Some(raw_fd) = process_handle.as_handle().raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        if self.process.handles.read().is_alive(raw_fd) {
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        } else {
            Err(NtStatus::INVALID_HANDLE)
        }
    }

    fn insert_worker_factory_handle(
        &self,
        factory: Arc<WorkerFactoryObject<Platform>>,
        granted_access: WorkerFactoryAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<WorkerFactorySubsystem<Platform>>(WorkerFactoryHandleObject {
                factory,
                granted_access,
            });
        insert_raw_handle::<Platform, WorkerFactorySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_worker_factory_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, WorkerFactorySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_worker_factory(worker_factory: WorkerFactoryHandleObject<Platform>) {
        drop(worker_factory);
    }

    pub(crate) fn sys_nt_create_worker_factory(
        &self,
        params: WorkerFactoryCreateParameters<Platform>,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(params.worker_factory_handle)
        {
            return status;
        }
        let completion_port = match self.io_completion_port(params.completion_port_handle) {
            Ok(port) => port,
            Err(status) => return status,
        };
        if let Err(status) = self.validate_worker_process_handle(params.worker_process_handle) {
            return status;
        }
        if let Err(status) =
            validate_worker_factory_object_attributes::<Platform>(params.object_attributes)
        {
            return status;
        }

        let factory = Arc::new(WorkerFactoryObject {
            // TODO: create and manage actual worker threads using start_routine/start_parameter
            // once worker dispatch, NtWaitForWorkViaWorkerFactory, and
            // NtReleaseWorkerFactoryWorker are implemented.
            _completion_port: completion_port,
            _start_routine: params.start_routine,
            _start_parameter: params.start_parameter,
            binding_count: AtomicU32::new(0),
            thread_minimum: AtomicU32::new(0),
            thread_maximum: AtomicU32::new(params.max_thread_count),
            thread_soft_maximum: AtomicU32::new(params.max_thread_count),
            shutdown: AtomicBool::new(false),
            _stack_reserve: params.stack_reserve,
            _stack_commit: params.stack_commit,
        });
        let granted_access = WorkerFactoryAccess::from_desired_access(params.desired_access);
        let Ok(handle) = self.insert_worker_factory_handle(factory, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if params
            .worker_factory_handle
            .write_at_offset(0, handle)
            .is_none()
        {
            self.close_worker_factory_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_set_information_worker_factory(
        &self,
        handle: Handle,
        information_class: u32,
        information: ConstPtr<Platform, u8>,
        information_length: u32,
    ) -> NtStatus {
        litebox_util_log::debug!(
            information_class = information_class,
            information_length = information_length;
            "NtSetInformationWorkerFactory parameters"
        );
        let Ok(information_class) = WorkerFactoryInformationClass::from_raw(information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if information_length as usize != size_of::<u32>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        let Some(value_bytes) = information.to_owned_slice(size_of::<u32>()) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let value = u32::from_le_bytes(
            value_bytes
                .as_ref()
                .try_into()
                .expect("ULONG input is four bytes"),
        );

        let entry = match self.worker_factory_entry(handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        entry
            .with_entry(|entry| {
                entry
                    .granted_access
                    .require(WorkerFactoryAccess::SET_INFORMATION)?;
                // TODO: enforce these limits against real worker creation/drain behavior
                // once worker threads are modeled; today they are only recorded.
                match information_class {
                    WorkerFactoryInformationClass::BindingCount => {
                        // TODO: bind this to real worker/IOCP association state once worker
                        // factories track live bindings.
                        entry.factory.binding_count.store(value, Ordering::Relaxed);
                    }
                    WorkerFactoryInformationClass::ThreadMinimum => {
                        let maximum = entry.factory.thread_maximum.load(Ordering::Relaxed);
                        if value > maximum {
                            return Err(NtStatus::INVALID_PARAMETER);
                        }
                        entry.factory.thread_minimum.store(value, Ordering::Relaxed);
                    }
                    WorkerFactoryInformationClass::ThreadMaximum => {
                        let minimum = entry.factory.thread_minimum.load(Ordering::Relaxed);
                        if value < minimum {
                            return Err(NtStatus::INVALID_PARAMETER);
                        }
                        entry.factory.thread_maximum.store(value, Ordering::Relaxed);
                    }
                    WorkerFactoryInformationClass::ThreadSoftMaximum => {
                        let maximum = entry.factory.thread_maximum.load(Ordering::Relaxed);
                        if value > maximum {
                            return Err(NtStatus::INVALID_PARAMETER);
                        }
                        entry
                            .factory
                            .thread_soft_maximum
                            .store(value, Ordering::Relaxed);
                    }
                }
                Ok(())
            })
            .map_or_else(|status| status, |()| NtStatus::SUCCESS)
    }

    pub(crate) fn sys_nt_shutdown_worker_factory(
        &self,
        handle: Handle,
        pending_worker_count: MutPtr<Platform, i32>,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(pending_worker_count)
        {
            return status;
        }
        let entry = match self.worker_factory_entry(handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let factory = match entry.with_entry(|entry| {
            entry
                .granted_access
                .require(WorkerFactoryAccess::SHUTDOWN)?;
            Ok(Arc::clone(&entry.factory))
        }) {
            Ok(factory) => factory,
            Err(status) => return status,
        };
        // TODO: report the actual pending worker count and wake/release workers once worker
        // threads are modeled; the current subset has no workers to drain.
        commit_worker_factory_shutdown(&factory, pending_worker_count)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::ThreadProvider;
    use litebox::utils::TruncateExt as _;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributes;
    use crate::tests::{TestFS, TestPlatform, mut_ptr, null_mut_ptr, test_platform, test_task};

    const EVENT_ALL_ACCESS: u32 = 0x001f_0003;
    const IO_COMPLETION_QUERY_STATE: u32 = 0x0000_0001;
    const IO_COMPLETION_ALL_ACCESS: u32 = 0x001f_0003;
    const WORKER_FACTORY_ALL_ACCESS: u32 = 0x001f_003f;
    const WORKER_FACTORY_QUERY_INFORMATION: u32 = 0x0008;
    const WORKER_FACTORY_SHUTDOWN: u32 = 0x0020;
    const START_ROUTINE: usize = 0x1234_5678;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn create_io_completion_handle(task: &Task<TestPlatform, TestFS>) -> Handle {
        create_io_completion_handle_with_access(task, IO_COMPLETION_ALL_ACCESS)
    }

    fn create_io_completion_handle_with_access(
        task: &Task<TestPlatform, TestFS>,
        access: u32,
    ) -> Handle {
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_io_completion(mut_ptr(&mut handle), access, None, 0),
            NtStatus::SUCCESS
        );
        handle
    }

    fn create_worker_factory(
        task: &Task<TestPlatform, TestFS>,
        worker_factory_handle: &mut Handle,
        object_attributes: Option<ConstPtr<TestPlatform, ObjectAttributes>>,
        completion_port_handle: Handle,
        worker_process_handle: ProcessHandle,
    ) -> NtStatus {
        create_worker_factory_with_access(
            task,
            worker_factory_handle,
            WORKER_FACTORY_ALL_ACCESS,
            object_attributes,
            completion_port_handle,
            worker_process_handle,
        )
    }

    fn create_worker_factory_with_access(
        task: &Task<TestPlatform, TestFS>,
        worker_factory_handle: &mut Handle,
        desired_access: u32,
        object_attributes: Option<ConstPtr<TestPlatform, ObjectAttributes>>,
        completion_port_handle: Handle,
        worker_process_handle: ProcessHandle,
    ) -> NtStatus {
        task.sys_nt_create_worker_factory(WorkerFactoryCreateParameters {
            worker_factory_handle: mut_ptr(worker_factory_handle),
            desired_access,
            object_attributes,
            completion_port_handle,
            worker_process_handle,
            start_routine: START_ROUTINE,
            start_parameter: 0,
            max_thread_count: 1,
            stack_reserve: 0,
            stack_commit: 0,
        })
    }

    fn information_ptr(value: &u32) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn create_requires_modify_state_on_completion_port() {
        let task = test_task();
        let io_completion =
            create_io_completion_handle_with_access(&task, IO_COMPLETION_QUERY_STATE);
        let mut worker_factory = Handle::from_raw(usize::MAX);

        assert_eq!(
            create_worker_factory(
                &task,
                &mut worker_factory,
                None,
                io_completion,
                ProcessHandle::CURRENT
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(worker_factory, Handle::from_raw(usize::MAX));
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
    }

    #[test]
    fn set_information_rejects_wrong_object_type_and_missing_access() {
        let task = test_task();
        let io_completion = create_io_completion_handle(&task);
        let value = 1;
        let mut event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(mut_ptr(&mut event), EVENT_ALL_ACCESS, None, 0, 0),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_set_information_worker_factory(
                event,
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                information_ptr(&value),
                size_of::<u32>().trunc(),
            ),
            NtStatus::OBJECT_TYPE_MISMATCH
        );

        let mut worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory_with_access(
                &task,
                &mut worker_factory,
                WORKER_FACTORY_QUERY_INFORMATION,
                None,
                io_completion,
                ProcessHandle::CURRENT,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_set_information_worker_factory(
                worker_factory,
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                information_ptr(&value),
                size_of::<u32>().trunc(),
            ),
            NtStatus::ACCESS_DENIED
        );

        assert_eq!(task.sys_nt_close(worker_factory), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(event), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
    }

    #[test]
    fn shutdown_sets_pending_worker_count_to_zero() {
        let task = test_task();
        let io_completion = create_io_completion_handle(&task);
        let mut worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory(
                &task,
                &mut worker_factory,
                None,
                io_completion,
                ProcessHandle::CURRENT,
            ),
            NtStatus::SUCCESS
        );

        let mut pending_worker_count = 7;
        assert_eq!(
            task.sys_nt_shutdown_worker_factory(worker_factory, mut_ptr(&mut pending_worker_count)),
            NtStatus::SUCCESS
        );
        assert_eq!(pending_worker_count, 0);

        assert_eq!(task.sys_nt_close(worker_factory), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
    }

    #[test]
    fn shutdown_output_fault_preserves_factory_state() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let io_completion = create_io_completion_handle(&task);
            let mut worker_factory = Handle::default();
            assert_eq!(
                create_worker_factory(
                    &task,
                    &mut worker_factory,
                    None,
                    io_completion,
                    ProcessHandle::CURRENT,
                ),
                NtStatus::SUCCESS
            );
            let factory = task
                .worker_factory_entry(worker_factory)
                .expect("worker factory handle is valid")
                .with_entry(|entry| Arc::clone(&entry.factory));
            assert!(!factory.shutdown.load(Ordering::Relaxed));

            assert_eq!(
                task.sys_nt_shutdown_worker_factory(worker_factory, null_mut_ptr()),
                NtStatus::ACCESS_VIOLATION
            );
            assert!(!factory.shutdown.load(Ordering::Relaxed));

            assert_eq!(
                commit_worker_factory_shutdown(&factory, null_mut_ptr()),
                NtStatus::ACCESS_VIOLATION
            );
            assert!(!factory.shutdown.load(Ordering::Relaxed));

            assert_eq!(task.sys_nt_close(worker_factory), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn shutdown_validates_pending_worker_count_before_handle() {
        run_with_test_platform_pointers(|| {
            let task = test_task();

            assert_eq!(
                task.sys_nt_shutdown_worker_factory(Handle::default(), null_mut_ptr()),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn shutdown_rejects_wrong_object_type_and_missing_access() {
        let task = test_task();
        let io_completion = create_io_completion_handle(&task);
        let mut pending_worker_count = 1;
        let mut event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(mut_ptr(&mut event), EVENT_ALL_ACCESS, None, 0, 0),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_shutdown_worker_factory(event, mut_ptr(&mut pending_worker_count)),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(pending_worker_count, 1);

        let mut worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory_with_access(
                &task,
                &mut worker_factory,
                WORKER_FACTORY_QUERY_INFORMATION,
                None,
                io_completion,
                ProcessHandle::CURRENT,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_shutdown_worker_factory(worker_factory, mut_ptr(&mut pending_worker_count)),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(pending_worker_count, 1);

        assert_eq!(task.sys_nt_close(worker_factory), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(event), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);

        let io_completion = create_io_completion_handle(&task);
        let mut worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory_with_access(
                &task,
                &mut worker_factory,
                WORKER_FACTORY_SHUTDOWN,
                None,
                io_completion,
                ProcessHandle::CURRENT,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_shutdown_worker_factory(worker_factory, mut_ptr(&mut pending_worker_count)),
            NtStatus::SUCCESS
        );

        assert_eq!(task.sys_nt_close(worker_factory), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_create_worker_factory_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtCreateIoCompletion(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                number_of_concurrent_threads: u32,
            ) -> i32;
            fn NtCreateWorkerFactory(
                handle: *mut *mut c_void,
                desired_access: u32,
                object_attributes: *const ObjectAttributes,
                completion_port_handle: *mut c_void,
                worker_process_handle: *mut c_void,
                start_routine: *mut c_void,
                start_parameter: *mut c_void,
                max_thread_count: u32,
                stack_reserve: usize,
                stack_commit: usize,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let mut host_io_completion = core::ptr::null_mut();
        // SAFETY: The output pointer is valid, attributes are null, and the handle is closed below.
        let status = unsafe {
            NtCreateIoCompletion(
                &raw mut host_io_completion,
                IO_COMPLETION_ALL_ACCESS,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(status, NtStatus::SUCCESS.as_raw());

        let task = test_task();
        let io_completion = create_io_completion_handle(&task);

        let mut host_worker_factory = core::ptr::null_mut();
        // SAFETY: All handles and pointers are valid for this status probe; the returned worker
        // factory handle is closed before leaving the test.
        let host_success = unsafe {
            let status = NtCreateWorkerFactory(
                &raw mut host_worker_factory,
                WORKER_FACTORY_ALL_ACCESS,
                core::ptr::null(),
                host_io_completion,
                usize::MAX as *mut c_void,
                START_ROUTINE as *mut c_void,
                core::ptr::null_mut(),
                1,
                0,
                0,
            );
            if status == NtStatus::SUCCESS.as_raw() && !host_worker_factory.is_null() {
                assert_eq!(NtClose(host_worker_factory), NtStatus::SUCCESS.as_raw());
            }
            status
        };

        let mut shim_worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory(
                &task,
                &mut shim_worker_factory,
                None,
                io_completion,
                ProcessHandle::CURRENT
            )
            .as_raw(),
            host_success
        );
        assert!(!shim_worker_factory.is_null());
        assert_eq!(task.sys_nt_close(shim_worker_factory), NtStatus::SUCCESS);

        let mut host_query_io_completion = core::ptr::null_mut();
        // SAFETY: The output pointer is valid, attributes are null, and the handle is closed below.
        let status = unsafe {
            NtCreateIoCompletion(
                &raw mut host_query_io_completion,
                IO_COMPLETION_QUERY_STATE,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(status, NtStatus::SUCCESS.as_raw());
        let mut shim_query_io_completion = Handle::default();
        assert_eq!(
            task.sys_nt_create_io_completion(
                mut_ptr(&mut shim_query_io_completion),
                IO_COMPLETION_QUERY_STATE,
                None,
                0
            ),
            NtStatus::SUCCESS
        );

        let mut host_query_worker_factory = core::ptr::null_mut();
        // SAFETY: All pointers are valid; the completion port intentionally lacks modify access to
        // compare native access checking with the shim.
        let host_query_only_completion = unsafe {
            let status = NtCreateWorkerFactory(
                &raw mut host_query_worker_factory,
                WORKER_FACTORY_ALL_ACCESS,
                core::ptr::null(),
                host_query_io_completion,
                usize::MAX as *mut c_void,
                START_ROUTINE as *mut c_void,
                core::ptr::null_mut(),
                1,
                0,
                0,
            );
            if status == NtStatus::SUCCESS.as_raw() && !host_query_worker_factory.is_null() {
                assert_eq!(
                    NtClose(host_query_worker_factory),
                    NtStatus::SUCCESS.as_raw()
                );
            }
            status
        };
        let mut shim_query_worker_factory = Handle::default();
        assert_eq!(
            create_worker_factory(
                &task,
                &mut shim_query_worker_factory,
                None,
                shim_query_io_completion,
                ProcessHandle::CURRENT
            )
            .as_raw(),
            host_query_only_completion
        );
        if !shim_query_worker_factory.is_null() {
            assert_eq!(
                task.sys_nt_close(shim_query_worker_factory),
                NtStatus::SUCCESS
            );
        }
        assert_eq!(
            task.sys_nt_close(shim_query_io_completion),
            NtStatus::SUCCESS
        );

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
            NtCreateWorkerFactory(
                &raw mut host_worker_factory,
                WORKER_FACTORY_ALL_ACCESS,
                &raw const bad_length,
                host_io_completion,
                usize::MAX as *mut c_void,
                START_ROUTINE as *mut c_void,
                core::ptr::null_mut(),
                1,
                0,
                0,
            )
        };
        assert_eq!(
            create_worker_factory(
                &task,
                &mut shim_worker_factory,
                Some(crate::tests::const_ptr(&bad_length)),
                io_completion,
                ProcessHandle::CURRENT
            )
            .as_raw(),
            host_bad_length
        );

        let mut host_event = core::ptr::null_mut();
        // SAFETY: The output pointer is valid, attributes are null, and the handle is closed below.
        let status = unsafe {
            NtCreateEvent(
                &raw mut host_event,
                EVENT_ALL_ACCESS,
                core::ptr::null(),
                0,
                0,
            )
        };
        assert_eq!(status, NtStatus::SUCCESS.as_raw());
        let mut shim_event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(mut_ptr(&mut shim_event), EVENT_ALL_ACCESS, None, 0, 0),
            NtStatus::SUCCESS
        );

        // SAFETY: The event handle is valid but intentionally has the wrong object type for the
        // completion-port argument.
        let host_wrong_completion_type = unsafe {
            NtCreateWorkerFactory(
                &raw mut host_worker_factory,
                WORKER_FACTORY_ALL_ACCESS,
                core::ptr::null(),
                host_event,
                usize::MAX as *mut c_void,
                START_ROUTINE as *mut c_void,
                core::ptr::null_mut(),
                1,
                0,
                0,
            )
        };
        assert_eq!(
            create_worker_factory(
                &task,
                &mut shim_worker_factory,
                None,
                shim_event,
                ProcessHandle::CURRENT
            )
            .as_raw(),
            host_wrong_completion_type
        );

        // SAFETY: All non-process arguments are valid; the event handle is intentionally passed as
        // the process handle to probe native type checking.
        let host_wrong_process_type = unsafe {
            NtCreateWorkerFactory(
                &raw mut host_worker_factory,
                WORKER_FACTORY_ALL_ACCESS,
                core::ptr::null(),
                host_io_completion,
                host_event,
                START_ROUTINE as *mut c_void,
                core::ptr::null_mut(),
                1,
                0,
                0,
            )
        };
        assert_eq!(
            create_worker_factory(
                &task,
                &mut shim_worker_factory,
                None,
                io_completion,
                ProcessHandle::from_raw(shim_event.as_raw())
            )
            .as_raw(),
            host_wrong_process_type
        );

        assert_eq!(task.sys_nt_close(shim_event), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(io_completion), NtStatus::SUCCESS);
        // SAFETY: Handles were created successfully above and have not yet been closed.
        unsafe {
            assert_eq!(NtClose(host_event), NtStatus::SUCCESS.as_raw());
            assert_eq!(NtClose(host_io_completion), NtStatus::SUCCESS.as_raw());
            assert_eq!(
                NtClose(host_query_io_completion),
                NtStatus::SUCCESS.as_raw()
            );
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_set_worker_factory_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtSetInformationWorkerFactory(
                handle: *mut c_void,
                worker_factory_information_class: u32,
                worker_factory_information: *const c_void,
                worker_factory_information_length: u32,
            ) -> i32;
        }

        let task = test_task();
        let value = 1;

        for (handle, class, info, length) in [
            (
                core::ptr::null_mut(),
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                (&raw const value).cast(),
                size_of::<u32>().trunc(),
            ),
            // This causes a crash
            // (
            //     core::ptr::null_mut(),
            //     WorkerFactoryInformationClass::ThreadMaximum as u32,
            //     core::ptr::null(),
            //     size_of::<u32>().trunc(),
            // ),
            (
                core::ptr::null_mut(),
                16,
                (&raw const value).cast(),
                size_of::<u32>().trunc(),
            ),
            (
                core::ptr::null_mut(),
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                (&raw const value).cast(),
                0,
            ),
        ] {
            // SAFETY: These probes intentionally use an invalid handle; any non-null input pointer
            // points to a live local and no native worker factory can be started.
            let host_status = unsafe { NtSetInformationWorkerFactory(handle, class, info, length) };
            assert_eq!(
                task.sys_nt_set_information_worker_factory(
                    Handle::default(),
                    class,
                    if info.is_null() {
                        crate::tests::null_const_ptr()
                    } else {
                        information_ptr(&value)
                    },
                    length,
                )
                .as_raw(),
                host_status
            );
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_set_worker_factory_wrong_type_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtSetInformationWorkerFactory(
                handle: *mut c_void,
                worker_factory_information_class: u32,
                worker_factory_information: *const c_void,
                worker_factory_information_length: u32,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let task = test_task();
        let value = 1;
        let mut host_event = core::ptr::null_mut();
        // SAFETY: The output pointer is valid, attributes are null, and the handle is closed below.
        let status = unsafe {
            NtCreateEvent(
                &raw mut host_event,
                EVENT_ALL_ACCESS,
                core::ptr::null(),
                0,
                0,
            )
        };
        assert_eq!(status, NtStatus::SUCCESS.as_raw());
        let mut shim_event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(mut_ptr(&mut shim_event), EVENT_ALL_ACCESS, None, 0, 0),
            NtStatus::SUCCESS
        );

        // SAFETY: The event handle is valid but intentionally has the wrong object type.
        let host_wrong_type = unsafe {
            NtSetInformationWorkerFactory(
                host_event,
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                (&raw const value).cast(),
                size_of::<u32>().trunc(),
            )
        };
        assert_eq!(
            task.sys_nt_set_information_worker_factory(
                shim_event,
                WorkerFactoryInformationClass::ThreadMaximum as u32,
                information_ptr(&value),
                size_of::<u32>().trunc(),
            )
            .as_raw(),
            host_wrong_type
        );

        assert_eq!(task.sys_nt_close(shim_event), NtStatus::SUCCESS);
        // SAFETY: The host event handle was created successfully above and has not yet been closed.
        unsafe {
            assert_eq!(NtClose(host_event), NtStatus::SUCCESS.as_raw());
        }
    }
}
