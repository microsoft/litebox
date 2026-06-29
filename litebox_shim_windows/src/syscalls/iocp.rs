// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT I/O completion port syscalls.

use alloc::sync::Arc;
use core::marker::PhantomData;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, read_object_attributes};
use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

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

    pub(crate) fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

pub(crate) struct IoCompletionSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for IoCompletionSubsystem<Platform> {
    type Entry = IoCompletionHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for IoCompletionHandleObject<Platform> {}

pub(crate) struct IoCompletionHandleObject<Platform: crate::ShimPlatform> {
    port: Arc<IoCompletionObject<Platform>>,
    granted_access: IoCompletionAccess,
}

pub(crate) struct IoCompletionObject<Platform: crate::ShimPlatform> {
    _number_of_concurrent_threads: u32,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

impl<Platform: crate::ShimPlatform> IoCompletionObject<Platform> {
    fn new(number_of_concurrent_threads: u32) -> Self {
        Self {
            _number_of_concurrent_threads: number_of_concurrent_threads,
            _not_send_without_platform: PhantomData,
        }
    }
}

impl<Platform: crate::ShimPlatform> IoCompletionHandleObject<Platform> {
    pub(crate) fn port(&self) -> Arc<IoCompletionObject<Platform>> {
        self.port.clone()
    }

    pub(crate) fn require_access(&self, required: IoCompletionAccess) -> Result<(), NtStatus> {
        self.granted_access.require(required)
    }
}

fn validate_io_completion_object_attributes<Platform: RawPointerProvider>(
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

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn insert_io_completion_handle(
        &self,
        port: Arc<IoCompletionObject<Platform>>,
        granted_access: IoCompletionAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<IoCompletionSubsystem<Platform>>(
            IoCompletionHandleObject {
                port,
                granted_access,
            },
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
        if let Err(status) = validate_io_completion_object_attributes::<Platform>(object_attributes)
        {
            return status;
        }

        // TODO: model the IOCP packet queue, concurrency accounting, named-object lookup,
        // and file-handle association once completion posting/removal and file completion
        // context syscalls are implemented.
        let port = Arc::new(IoCompletionObject::new(number_of_concurrent_threads));
        let granted_access = IoCompletionAccess::from_desired_access(desired_access);
        let Ok(handle) = self.insert_io_completion_handle(port, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if io_completion_handle.write_at_offset(0, handle).is_none() {
            self.close_io_completion_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
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
