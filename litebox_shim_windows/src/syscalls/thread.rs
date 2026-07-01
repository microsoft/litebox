// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable};

use crate::syscalls::{Handle, ThreadHandle};
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ThreadInformationClass {
    SchedulerSharedDataSlot = 57,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
struct ThreadSchedulerSharedDataSlotInformation {
    action: u32,
    _padding0: u32,
    scheduler_shared_data_handle: usize,
    slot: usize,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_set_information_thread(
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: ConstPtr<Platform, u8>,
        thread_information_length: u32,
    ) -> NtStatus {
        let Ok(thread_information_class) =
            ThreadInformationClass::try_from(thread_information_class)
        else {
            litebox_util_log::debug!(
                thread_information_class = thread_information_class;
                "Unsupported NtSetInformationThread class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match thread_information_class {
            ThreadInformationClass::SchedulerSharedDataSlot => {
                Self::set_thread_scheduler_shared_data_slot(
                    thread_handle,
                    thread_information,
                    thread_information_length,
                )
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                thread_information_class:? = thread_information_class,
                thread_information_length = thread_information_length;
                "Handled NtSetInformationThread syscall"
            );
        }

        status
    }

    fn set_thread_scheduler_shared_data_slot(
        thread_handle: ThreadHandle,
        thread_information: ConstPtr<Platform, u8>,
        thread_information_length: u32,
    ) -> NtStatus {
        let thread_information =
            ConstPtr::<Platform, ThreadSchedulerSharedDataSlotInformation>::from_usize(
                thread_information.as_usize(),
            );
        let Some(_thread_information) = thread_information.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if thread_information_length < size_of::<ThreadSchedulerSharedDataSlotInformation>().trunc()
        {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        // The scheduler-shared-data handle is never valid in the sandbox, matching the host
        // current-thread path for the observed all-zero slot request.
        NtStatus::INVALID_HANDLE
    }

    pub(crate) fn sys_nt_open_thread_token(
        thread_handle: ThreadHandle,
        _desired_access: u32,
        _open_as_self: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        Self::open_thread_token(thread_handle, token_handle)
    }

    pub(crate) fn sys_nt_open_thread_token_ex(
        thread_handle: ThreadHandle,
        _desired_access: u32,
        _open_as_self: u32,
        _handle_attributes: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        // TODO: HandleAttributes is outcome-independent while the sandbox has no impersonation
        // token. Once a real token subsystem exists it must be validated; host 25H2 returns
        // STATUS_INVALID_PARAMETER for attrs=0xffffffff after ImpersonateSelf.
        Self::open_thread_token(thread_handle, token_handle)
    }

    fn open_thread_token(
        thread_handle: ThreadHandle,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(token_handle) {
            return status;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        // A thread only has a token while it is actively impersonating (SetThreadToken /
        // ImpersonateSelf). Sandbox threads never impersonate, so real host 25H2 returns
        // STATUS_NO_TOKEN here as well: this is the host-faithful terminal answer, not a stub.
        NtStatus::NO_TOKEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::null_const_ptr;
    use litebox::platform::ThreadProvider;

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform, crate::tests::TestFS>;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn nt_set_information_thread_scheduler_shared_data_slot_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let information = ThreadSchedulerSharedDataSlotInformation {
                action: 0,
                _padding0: 0,
                scheduler_shared_data_handle: 0,
                slot: 0,
            };
            let information_len: u32 =
                size_of::<ThreadSchedulerSharedDataSlotInformation>().trunc();
            let bad_handle = ThreadHandle::from_raw(0x1234);

            assert_eq!(
                TestTask::sys_nt_set_information_thread(
                    bad_handle,
                    0xffff,
                    null_const_ptr::<u8>(),
                    information_len - 1,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                TestTask::sys_nt_set_information_thread(
                    bad_handle,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    null_const_ptr::<u8>(),
                    information_len,
                ),
                NtStatus::ACCESS_VIOLATION
            );

            assert_eq!(
                TestTask::sys_nt_set_information_thread(
                    bad_handle,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&information),
                    information_len - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );

            assert_eq!(
                TestTask::sys_nt_set_information_thread(
                    bad_handle,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&information),
                    information_len,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                TestTask::sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&information),
                    information_len,
                ),
                NtStatus::INVALID_HANDLE
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use core::ffi::c_void;

        use super::*;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtSetInformationThread(
                thread_handle: *mut c_void,
                thread_information_class: u32,
                thread_information: *const c_void,
                thread_information_length: u32,
            ) -> i32;
        }

        fn host_nt_set_information_thread(
            thread_handle: *mut c_void,
            thread_information_class: u32,
            thread_information: *const c_void,
            thread_information_length: u32,
        ) -> NtStatus {
            // SAFETY: The host ntdll call treats these as user-mode input pointers, probes them,
            // and does not retain them. Tests pass either valid locals or null to observe NTSTATUS.
            let status = unsafe {
                NtSetInformationThread(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                )
            };
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        #[test]
        fn nt_set_information_thread_scheduler_shared_data_slot_matches_host_statuses() {
            run_with_test_platform_pointers(|| {
                let information = ThreadSchedulerSharedDataSlotInformation {
                    action: 0,
                    _padding0: 0,
                    scheduler_shared_data_handle: 0,
                    slot: 0,
                };
                let information_len: u32 =
                    size_of::<ThreadSchedulerSharedDataSlotInformation>().trunc();
                let current_thread = (usize::MAX - 1) as *mut c_void;
                let bad_thread = 0x1234usize as *mut c_void;
                let scheduler_class = ThreadInformationClass::SchedulerSharedDataSlot as u32;
                let bad_class = 0xffff;

                if host_nt_set_information_thread(
                    current_thread,
                    scheduler_class,
                    core::ptr::from_ref(&information).cast::<c_void>(),
                    information_len,
                ) == NtStatus::INVALID_INFO_CLASS
                {
                    return;
                }

                for (
                    thread_handle,
                    shim_thread_handle,
                    thread_information_class,
                    host_thread_information,
                    shim_thread_information,
                    thread_information_length,
                ) in [
                    (
                        current_thread,
                        ThreadHandle::CURRENT,
                        scheduler_class,
                        core::ptr::from_ref(&information).cast::<c_void>(),
                        const_byte_ptr(&information),
                        information_len,
                    ),
                    (
                        current_thread,
                        ThreadHandle::CURRENT,
                        scheduler_class,
                        core::ptr::from_ref(&information).cast::<c_void>(),
                        const_byte_ptr(&information),
                        information_len - 1,
                    ),
                    (
                        current_thread,
                        ThreadHandle::CURRENT,
                        scheduler_class,
                        core::ptr::null(),
                        null_const_ptr::<u8>(),
                        information_len,
                    ),
                    (
                        current_thread,
                        ThreadHandle::CURRENT,
                        bad_class,
                        core::ptr::null(),
                        null_const_ptr::<u8>(),
                        information_len,
                    ),
                    (
                        bad_thread,
                        ThreadHandle::from_raw(0x1234),
                        scheduler_class,
                        core::ptr::from_ref(&information).cast::<c_void>(),
                        const_byte_ptr(&information),
                        information_len,
                    ),
                    (
                        bad_thread,
                        ThreadHandle::from_raw(0x1234),
                        scheduler_class,
                        core::ptr::null(),
                        null_const_ptr::<u8>(),
                        information_len,
                    ),
                    (
                        bad_thread,
                        ThreadHandle::from_raw(0x1234),
                        scheduler_class,
                        core::ptr::from_ref(&information).cast::<c_void>(),
                        const_byte_ptr(&information),
                        information_len - 1,
                    ),
                    (
                        bad_thread,
                        ThreadHandle::from_raw(0x1234),
                        bad_class,
                        core::ptr::from_ref(&information).cast::<c_void>(),
                        const_byte_ptr(&information),
                        information_len,
                    ),
                ] {
                    let host = host_nt_set_information_thread(
                        thread_handle,
                        thread_information_class,
                        host_thread_information,
                        thread_information_length,
                    );
                    let shim = TestTask::sys_nt_set_information_thread(
                        shim_thread_handle,
                        thread_information_class,
                        shim_thread_information,
                        thread_information_length,
                    );

                    assert_eq!(shim, host);
                }
            });
        }
    }
}
