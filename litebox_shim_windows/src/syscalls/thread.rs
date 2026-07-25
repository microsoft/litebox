// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

use int_enum::IntEnum;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawMutPointer as _;
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable};

use crate::loader::create_thread_environment;
use crate::nt_types::{AccessMask, ClientId, ObjectAttributes, X64Context};
use crate::syscalls::ProcessHandle;
use crate::syscalls::{Handle, ThreadHandle};
use crate::{
    ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, WindowsShimEntrypoints,
    probe_guest_output_preserving_value,
};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ThreadCreateFlags: u32 {
        const CREATE_SUSPENDED = 0x0000_0001;
        const SKIP_THREAD_ATTACH = 0x0000_0002;
        const HIDE_FROM_DEBUGGER = 0x0000_0004;
        const HAS_SECURITY_DESCRIPTOR = 0x0000_0010;
        const ACCESS_CHECK_IN_TARGET = 0x0000_0020;
        const INITIAL_THREAD = 0x0000_0080;
        const SKIP_LOADER_INIT = 0x0000_0100;
        const BYPASS_PROCESS_FREEZE = 0x0000_0040;

        const _ = !0;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ThreadAccess: u32 {
        const TERMINATE = 0x0001;
        const SUSPEND_RESUME = 0x0002;
        const GET_CONTEXT = 0x0008;
        const SET_CONTEXT = 0x0010;
        const SET_INFORMATION = 0x0020;
        const QUERY_INFORMATION = 0x0040;
        const SET_THREAD_TOKEN = 0x0080;
        const IMPERSONATE = 0x0100;
        const DIRECT_IMPERSONATION = 0x0200;
        const SET_LIMITED_INFORMATION = 0x0400;
        const QUERY_LIMITED_INFORMATION = 0x0800;
        const RESUME = 0x1000;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY_INFORMATION.bits()
            | Self::GET_CONTEXT.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::SET_INFORMATION.bits()
            | Self::SET_CONTEXT.bits()
            | Self::SET_THREAD_TOKEN.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | AccessMask::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits() | 0xffff;

        const _ = !0;
    }
}

impl ThreadAccess {
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

pub(crate) struct ThreadSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: ShimPlatform> FdEnabledSubsystem for ThreadSubsystem<Platform> {
    type Entry = ThreadHandleObject<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for ThreadHandleObject<Platform> {}

impl<Platform: ShimPlatform> crate::WindowsHandleSubsystem for ThreadSubsystem<Platform> {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        ThreadAccess::from_desired_access(desired_access).bits()
    }
}

pub(crate) struct ThreadHandleObject<Platform: ShimPlatform> {
    #[expect(
        dead_code,
        reason = "the wait slice will resolve handles to their shared thread object"
    )]
    pub(crate) thread: Arc<ThreadObject<Platform>>,
}

pub(crate) struct ThreadObject<Platform: ShimPlatform> {
    signaled: AtomicBool,
    pollee: Pollee<Platform>,
}

impl<Platform: ShimPlatform> ThreadObject<Platform> {
    fn new() -> Self {
        Self {
            signaled: AtomicBool::new(false),
            pollee: Pollee::new(),
        }
    }
}

impl<Platform: ShimPlatform> IOPollable for ThreadObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if self.signaled.load(Ordering::Acquire) {
            Events::IN
        } else {
            Events::empty()
        }
    }
}

struct NewThreadArgs<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<Platform, FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(
        self: Box<Self>,
    ) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>> {
        let Self { task } = *self;
        Box::new(WindowsShimEntrypoints {
            task,
            _not_send: PhantomData,
        })
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ThreadInformationClass {
    SchedulerSharedDataSlot = 57,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum QueryThreadInformationClass {
    AmILastThread = 12,
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
    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateThreadEx has eleven ABI parameters whose ordering must remain explicit"
    )]
    pub(crate) fn sys_nt_create_thread_ex(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        thread_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        process_handle: ProcessHandle,
        start_routine: usize,
        argument: usize,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: Option<ConstPtr<Platform, u8>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(thread_handle) {
            return status;
        }
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let create_flags = ThreadCreateFlags::from_bits_retain(create_flags);
        if !create_flags.is_empty() {
            // TODO(thread-model): support suspended creation and the remaining native flags.
            return NtStatus::NOT_SUPPORTED;
        }
        // TODO(thread-object-attributes): apply object attributes to the new thread handle.
        if object_attributes.is_some() {
            litebox_util_log::debug!("Ignoring NtCreateThreadEx object attributes");
        }
        // TODO(thread-stack-model): honor ZeroBits and distinguish committed from reserved stack.
        if zero_bits != 0 || maximum_stack_size != 0 {
            litebox_util_log::debug!(
                zero_bits,
                maximum_stack_size;
                "Ignoring unsupported NtCreateThreadEx stack constraints"
            );
        }
        // TODO(thread-attributes): populate supported PS_ATTRIBUTE_LIST output attributes.
        if attribute_list.is_some() {
            litebox_util_log::debug!("Ignoring NtCreateThreadEx attribute list");
        }

        let Some(rtl_user_thread_start) = self.process.rtl_user_thread_start else {
            return NtStatus::NOT_SUPPORTED;
        };
        let thread_id = self.process.next_thread_id.fetch_add(1, Ordering::Relaxed);
        let environment = match create_thread_environment(
            &self.global.page_manager,
            stack_size,
            self.process.peb_address,
            ClientId {
                unique_process: crate::syscalls::process::INITIAL_PROCESS_ID,
                unique_thread: thread_id,
            },
        ) {
            Ok(environment) => environment,
            Err(error) => {
                litebox_util_log::error!(error:% = error; "Failed to create Windows thread environment");
                return NtStatus::NO_MEMORY;
            }
        };
        let initial_context = X64Context::initial_thread_context(
            rtl_user_thread_start,
            start_routine,
            environment.stack_top,
            argument,
        );
        let mut child_ctx = ctx.clone();
        initial_context.apply_to_regs(&mut child_ctx);

        let thread = Arc::new(ThreadObject::new());
        let granted_access = ThreadAccess::from_desired_access(desired_access);
        let handle = match self.insert_typed_handle::<ThreadSubsystem<Platform>>(
            ThreadHandleObject {
                thread: thread.clone(),
            },
            granted_access.bits(),
            drop,
        ) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        let task = Task {
            global: self.global.clone(),
            process: self.process.clone(),
            fs: self.fs.clone(),
            entry_point: rtl_user_thread_start,
            stack_top: environment.stack_top,
            context: argument,
            teb_address: environment.teb,
            initial_context: Some(initial_context),
            thread_object: Some(thread),
        };
        self.process
            .active_thread_count
            .fetch_add(1, Ordering::AcqRel);
        // SAFETY: `child_ctx` points at mapped guest code and stack created above, and the
        // destination thread constructs its non-Send shim entrypoints inside `InitThread::init`.
        if let Err(error) = unsafe {
            self.global
                .platform
                .spawn_thread(&child_ctx, Box::new(NewThreadArgs { task }))
        } {
            litebox_util_log::error!(error:% = error; "Failed to spawn Windows guest thread");
            self.close_typed_handle::<ThreadSubsystem<Platform>>(handle, drop);
            self.process
                .active_thread_count
                .fetch_sub(1, Ordering::AcqRel);
            return NtStatus::NO_MEMORY;
        }

        if thread_handle.write_at_offset(0, handle).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_information_thread(
        &self,
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Ok(QueryThreadInformationClass::AmILastThread) =
            QueryThreadInformationClass::try_from(thread_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if thread_information_length as usize != core::mem::size_of::<u32>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::NOT_SUPPORTED;
        }

        let is_last_thread =
            u32::from(self.process.active_thread_count.load(Ordering::Acquire) == 1);
        let output = MutPtr::<Platform, u32>::from_usize(thread_information.as_usize());
        if output.write_at_offset(0, is_last_thread).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length
                .write_at_offset(0, core::mem::size_of::<u32>().trunc())
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn close_thread(thread: ThreadHandleObject<Platform>) {
        drop(thread);
    }

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
