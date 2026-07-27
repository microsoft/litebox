// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use int_enum::IntEnum;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::event::{polling::TryOpError, wait::WaitError};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, SystemTime as _};
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

const STATUS_ALERTED: NtStatus = NtStatus::from_raw(0x0000_0101);

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
    pub(crate) thread: Arc<ThreadObject<Platform>>,
}

pub(crate) struct ThreadObject<Platform: ShimPlatform> {
    completion_state: AtomicU8,
    exit_status: core::sync::atomic::AtomicI32,
    pollee: Pollee<Platform>,
    /// Set when the thread has been asked to exit, either by its own
    /// termination request or by a process-wide exit.
    is_exiting: AtomicBool,
    /// Handle used to interrupt the thread, published once by the thread itself
    /// when it starts running. Empty until then.
    wait_handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
}

impl<Platform: ShimPlatform> ThreadObject<Platform> {
    const RUNNING: u8 = 0;
    const COMPLETING: u8 = 1;
    const COMPLETE: u8 = 2;

    pub(crate) fn new() -> Self {
        Self {
            completion_state: AtomicU8::new(Self::RUNNING),
            exit_status: core::sync::atomic::AtomicI32::new(0),
            pollee: Pollee::new(),
            is_exiting: AtomicBool::new(false),
            wait_handle: once_cell::race::OnceBox::new(),
        }
    }

    /// Publishes the handle used to interrupt this thread.
    ///
    /// Must be called from the thread itself, because the handle captures the
    /// current platform thread. Only the first call takes effect.
    pub(crate) fn publish_wait_handle(&self, handle: litebox::event::wait::ThreadHandle<Platform>) {
        self.wait_handle.set(Box::new(handle)).ok();
    }

    /// Returns true if the thread has been asked to exit and must not re-enter
    /// guest code.
    pub(crate) fn is_exiting(&self) -> bool {
        self.is_exiting.load(Ordering::Relaxed)
    }

    /// Records `exit_status` and marks the thread as exiting.
    pub(crate) fn exit_thread(&self, exit_status: i32) {
        self.exit_status.store(exit_status, Ordering::Relaxed);
        self.is_exiting.store(true, Ordering::Relaxed);
    }

    /// Asks another thread to exit: records `exit_status`, marks the thread as
    /// exiting, and interrupts it so that it leaves an interruptible wait or
    /// guest execution and completes at the next return from the shim.
    pub(crate) fn begin_exit(&self, exit_status: i32) {
        self.exit_thread(exit_status);
        if let Some(handle) = self.wait_handle.get() {
            handle.interrupt();
        }
    }

    /// Publishes the exit status recorded by [`Self::exit_thread`] and wakes
    /// any waiters, running `before_publish` first. Only the first call takes
    /// effect; it returns `false` if the thread has already completed.
    pub(crate) fn complete(&self, before_publish: impl FnOnce()) -> bool {
        if self
            .completion_state
            .compare_exchange(
                Self::RUNNING,
                Self::COMPLETING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        before_publish();
        self.completion_state
            .store(Self::COMPLETE, Ordering::Release);
        self.pollee.notify_observers(Events::IN);
        true
    }
}

impl<Platform: ShimPlatform> IOPollable for ThreadObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if self.completion_state.load(Ordering::Acquire) == Self::COMPLETE {
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

        let (Some(ldr_initialize_thunk), Some(rtl_user_thread_start), Some(ntdll_mapping)) = (
            self.process.ldr_initialize_thunk,
            self.process.rtl_user_thread_start,
            self.process.ntdll_mapping,
        ) else {
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
            false,
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
        if MutPtr::<Platform, X64Context>::from_usize(environment.context)
            .write_at_offset(0, initial_context)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let mut child_ctx = ctx.clone();
        child_ctx.rip = ldr_initialize_thunk;
        child_ctx.rsp = environment.stack_top;
        child_ctx.eflags = 0x202;
        child_ctx.rcx = environment.context;
        child_ctx.rdx = ntdll_mapping.base_addr;

        let thread = Arc::new(ThreadObject::new());
        if !self.process.attach_thread(thread_id, &thread) {
            // The process is tearing down; refuse to start another thread.
            return NtStatus::PROCESS_IS_TERMINATING;
        }
        let granted_access = ThreadAccess::from_desired_access(desired_access);
        let handle = match self.insert_typed_handle::<ThreadSubsystem<Platform>>(
            ThreadHandleObject {
                thread: thread.clone(),
            },
            granted_access.bits(),
            drop,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                self.process.detach_thread(thread_id);
                return status;
            }
        };
        let task = Task {
            global: self.global.clone(),
            process: self.process.clone(),
            fs: self.fs.clone(),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            entry_point: ldr_initialize_thunk,
            stack_top: environment.stack_top,
            context: environment.context,
            teb_address: environment.teb,
            thread_id,
            thread_object: thread,
        };
        // SAFETY: `child_ctx` points at mapped guest code and stack created above, and the
        // destination thread constructs its non-Send shim entrypoints inside `InitThread::init`.
        if let Err(error) = unsafe {
            self.global
                .platform
                .spawn_thread(&child_ctx, Box::new(NewThreadArgs { task }))
        } {
            litebox_util_log::error!(error:% = error; "Failed to spawn Windows guest thread");
            self.close_typed_handle::<ThreadSubsystem<Platform>>(handle, drop);
            self.process.detach_thread(thread_id);
            return NtStatus::NO_MEMORY;
        }

        if thread_handle.write_at_offset(0, handle).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_wait_for_single_object(
        &self,
        handle: Handle,
        alertable: bool,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> NtStatus {
        let entry = match self.typed_handle_entry_with_access::<ThreadSubsystem<Platform>>(
            handle,
            AccessMask::SYNCHRONIZE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let thread = entry.with_entry(|entry| Arc::clone(&entry.thread));
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
            litebox_util_log::debug!("Treating alertable thread wait as non-alertable");
        }

        let wait_cx = self.wait_cx().with_timeout(timeout);
        match thread.pollee.wait(&wait_cx, false, Events::IN, || {
            if thread.completion_state.load(Ordering::Acquire) == ThreadObject::<Platform>::COMPLETE
            {
                Ok(())
            } else {
                Err(TryOpError::<NtStatus>::TryAgain)
            }
        }) {
            Ok(()) => {
                litebox_util_log::debug!(
                    exit_status = thread.exit_status.load(Ordering::Relaxed);
                    "Thread wait completed"
                );
                NtStatus::SUCCESS
            }
            Err(TryOpError::WaitError(WaitError::TimedOut)) => NtStatus::TIMEOUT,
            Err(TryOpError::WaitError(WaitError::Interrupted)) => STATUS_ALERTED,
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

    fn wait_timeout_duration(&self, timeout: i64) -> core::time::Duration {
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

        let is_last_thread = u32::from(self.process.live_thread_count() == 1);
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
    use crate::tests::{mut_byte_ptr, mut_ptr, null_const_ptr};
    use litebox::platform::ThreadProvider;
    use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};

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
    fn child_exception_completes_wait_before_last_thread_is_observed() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let thread = Arc::new(ThreadObject::new());
            let handle = parent
                .insert_typed_handle::<ThreadSubsystem<TestPlatform>>(
                    ThreadHandleObject {
                        thread: Arc::clone(&thread),
                    },
                    AccessMask::SYNCHRONIZE.bits(),
                    drop,
                )
                .expect("thread handle insertion should succeed");
            let child_thread_id = crate::syscalls::process::INITIAL_THREAD_ID + 1;
            assert!(parent.process.attach_thread(child_thread_id, &thread));
            let child = WindowsShimEntrypoints {
                task: Task {
                    global: Arc::clone(&parent.global),
                    process: Arc::clone(&parent.process),
                    fs: Arc::clone(&parent.fs),
                    wait_state: crate::wait::WaitState::new(parent.global.platform),
                    entry_point: 0,
                    stack_top: 0,
                    context: 0,
                    teb_address: 0,
                    thread_id: child_thread_id,
                    thread_object: thread,
                },
                _not_send: PhantomData,
            };
            let mut ctx = litebox_common_linux::PtRegs::default();
            // The child must look like it is running guest code before a fault is delivered.
            assert!(child.task.prepare_to_run_guest(&mut ctx));

            assert_eq!(
                child.exception(
                    &mut ctx,
                    &ExceptionInfo {
                        exception: Exception::PAGE_FAULT,
                        error_code: 0,
                        cr2: 0,
                        kernel_mode: false,
                    },
                ),
                ContinueOperation::Terminate
            );
            assert_eq!(
                parent.sys_nt_wait_for_single_object(handle, false, None),
                NtStatus::SUCCESS
            );
            let mut is_last_thread = u32::MAX;
            let mut return_length = 0;
            assert_eq!(
                parent.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    12,
                    mut_byte_ptr(&mut is_last_thread),
                    size_of::<u32>().trunc(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(is_last_thread, 1);
            assert_eq!(return_length as usize, size_of::<u32>());
            assert_eq!(parent.process.live_thread_count(), 1);
        });
    }

    #[test]
    fn process_exit_signals_every_thread_and_blocks_new_ones() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let sibling = Arc::new(ThreadObject::new());
            let sibling_id = crate::syscalls::process::INITIAL_THREAD_ID + 1;
            assert!(parent.process.attach_thread(sibling_id, &sibling));
            let sibling_task = Task {
                global: Arc::clone(&parent.global),
                process: Arc::clone(&parent.process),
                fs: Arc::clone(&parent.fs),
                wait_state: crate::wait::WaitState::new(parent.global.platform),
                entry_point: 0,
                stack_top: 0,
                context: 0,
                teb_address: 0,
                thread_id: sibling_id,
                thread_object: Arc::clone(&sibling),
            };

            parent.exit_process(42);

            // Every thread in the process is asked to exit, including the
            // caller, and the exit code is recorded.
            assert!(parent.thread_object.is_exiting());
            assert!(sibling.is_exiting());
            assert_eq!(parent.process.exit_code.load(Ordering::Relaxed), 42);

            // A signalled thread must not re-enter guest code.
            let mut ctx = litebox_common_linux::PtRegs::default();
            assert!(!sibling_task.prepare_to_run_guest(&mut ctx));

            // No new threads may join a process that is tearing down.
            assert!(
                !parent
                    .process
                    .attach_thread(sibling_id + 1, &Arc::new(ThreadObject::new()))
            );

            // Group exit is recorded once; a later exit does not overwrite the code.
            parent.exit_process(7);
            assert_eq!(parent.process.exit_code.load(Ordering::Relaxed), 42);
        });
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
