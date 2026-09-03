// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use int_enum::IntEnum;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::sync::Mutex;
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::loader::create_thread_environment;
use crate::nt_types::{AccessMask, ClientId, ObjectAttributes, X64Context};
use crate::syscalls::ProcessHandle;
use crate::syscalls::mutant::MutantObject;
use crate::syscalls::{Handle, ThreadHandle};
use crate::{
    ConstPtr, MutPtr, ShimPlatform, Task, WindowsShimEntrypoints,
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
        const ALERT = 0x0004;
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

#[derive(Default)]
struct KeyedAlertState {
    wait_address: Option<usize>,
    pending: bool,
}

pub(crate) struct ThreadObject<Platform: ShimPlatform> {
    thread_id: usize,
    teb_address: usize,
    completion_state: AtomicU8,
    exit_status: core::sync::atomic::AtomicI32,
    pollee: Pollee<Platform>,
    /// Set when the thread has been asked to exit, either by its own
    /// termination request or by a process-wide exit.
    is_exiting: AtomicBool,
    suspend_count: AtomicU32,
    /// Handle used to interrupt the thread, published once by the thread itself
    /// when it starts running. Empty until then.
    wait_handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
    thread_alert_pending: AtomicBool,
    keyed_alert_state: Mutex<Platform, KeyedAlertState>,
    owned_mutants: Mutex<Platform, Vec<Weak<MutantObject<Platform>>>>,
}

impl<Platform: ShimPlatform> ThreadObject<Platform> {
    const RUNNING: u8 = 0;
    const COMPLETING: u8 = 1;
    const COMPLETE: u8 = 2;

    pub(crate) fn new(thread_id: usize, teb_address: usize) -> Self {
        Self::new_with_suspend_count(thread_id, teb_address, 0)
    }

    fn new_with_suspend_count(thread_id: usize, teb_address: usize, suspend_count: u32) -> Self {
        Self {
            thread_id,
            teb_address,
            completion_state: AtomicU8::new(Self::RUNNING),
            exit_status: core::sync::atomic::AtomicI32::new(NtStatus::PENDING.as_raw()),
            pollee: Pollee::new(),
            is_exiting: AtomicBool::new(false),
            suspend_count: AtomicU32::new(suspend_count),
            wait_handle: once_cell::race::OnceBox::new(),
            thread_alert_pending: AtomicBool::new(false),
            keyed_alert_state: Mutex::new(KeyedAlertState::default()),
            owned_mutants: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn thread_id(&self) -> usize {
        self.thread_id
    }

    pub(crate) fn teb_address(&self) -> usize {
        self.teb_address
    }

    pub(crate) fn register_owned_mutant(&self, mutant: &Arc<MutantObject<Platform>>) {
        let mutant_ptr = Arc::as_ptr(mutant);
        let mut owned_mutants = self.owned_mutants.lock();
        owned_mutants.retain(|owned| owned.strong_count() != 0);
        if !owned_mutants
            .iter()
            .any(|owned| owned.as_ptr() == mutant_ptr)
        {
            owned_mutants.push(Arc::downgrade(mutant));
        }
    }

    pub(crate) fn unregister_owned_mutant(&self, mutant: &Arc<MutantObject<Platform>>) {
        let mutant_ptr = Arc::as_ptr(mutant);
        self.owned_mutants
            .lock()
            .retain(|owned| owned.strong_count() != 0 && owned.as_ptr() != mutant_ptr);
    }

    pub(crate) fn abandon_owned_mutants(&self, thread_id: usize) {
        let owned_mutants = core::mem::take(&mut *self.owned_mutants.lock());
        for mutant in owned_mutants {
            if let Some(mutant) = mutant.upgrade() {
                mutant.abandon(thread_id);
            }
        }
    }

    pub(crate) fn new_suspended(thread_id: usize, teb_address: usize) -> Self {
        Self::new_with_suspend_count(thread_id, teb_address, 1)
    }

    pub(crate) fn is_suspended(&self) -> bool {
        self.suspend_count.load(Ordering::Acquire) != 0
    }

    fn resume(&self) -> u32 {
        let mut previous = self.suspend_count.load(Ordering::Acquire);
        loop {
            if previous == 0 {
                return 0;
            }
            match self.suspend_count.compare_exchange_weak(
                previous,
                previous - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if previous == 1
                        && let Some(handle) = self.wait_handle.get()
                    {
                        handle.interrupt();
                    }
                    return previous;
                }
                Err(current) => previous = current,
            }
        }
    }

    fn begin_keyed_alert_wait(&self, address: usize) {
        let mut state = self.keyed_alert_state.lock();
        debug_assert!(state.wait_address.is_none());
        state.wait_address = Some(address);
    }

    fn take_keyed_alert(&self, address: usize) -> bool {
        let mut state = self.keyed_alert_state.lock();
        debug_assert_eq!(state.wait_address, Some(address));
        core::mem::take(&mut state.pending)
    }

    fn end_keyed_alert_wait(&self, address: usize) -> bool {
        let mut state = self.keyed_alert_state.lock();
        debug_assert_eq!(state.wait_address, Some(address));
        state.wait_address = None;
        core::mem::take(&mut state.pending)
    }

    fn alert_keyed_wait(&self, address: Option<usize>) {
        let mut state = self.keyed_alert_state.lock();
        if address.is_some() && state.wait_address != address {
            return;
        }
        state.pending = true;
        drop(state);
        if let Some(handle) = self.wait_handle.get() {
            handle.interrupt();
        }
    }

    pub(crate) fn take_pending_thread_alert(&self) -> bool {
        self.thread_alert_pending.swap(false, Ordering::AcqRel)
    }

    fn set_thread_alert(&self) {
        self.thread_alert_pending.store(true, Ordering::Release);
        if let Some(handle) = self.wait_handle.get() {
            handle.interrupt();
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
        self.is_exiting.load(Ordering::Acquire)
    }

    /// The exit status recorded by [`Self::exit_thread`].
    pub(crate) fn exit_status(&self) -> i32 {
        self.exit_status.load(Ordering::Relaxed)
    }

    /// Records `exit_status` and marks the thread as exiting.
    pub(crate) fn exit_thread(&self, exit_status: i32) {
        self.exit_status.store(exit_status, Ordering::Relaxed);
        self.is_exiting.store(true, Ordering::Release);
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

struct NewThreadArgs<Platform: ShimPlatform> {
    task: Task<Platform>,
}

impl<Platform: ShimPlatform> litebox::shim::InitThread for NewThreadArgs<Platform> {
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
    BasicInformation = 0,
    AmILastThread = 12,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
struct ThreadBasicInformation {
    exit_status: i32,
    _padding0: u32,
    teb_base_address: usize,
    client_id: ClientId,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
struct ThreadSchedulerSharedDataSlotInformation {
    action: u32,
    _padding0: u32,
    scheduler_shared_data_handle: usize,
    slot: usize,
}

impl<Platform: ShimPlatform> Task<Platform> {
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
        if !create_flags
            .difference(ThreadCreateFlags::CREATE_SUSPENDED)
            .is_empty()
        {
            litebox_util_log::debug!(
                create_flags:? = create_flags;
                "Rejecting NtCreateThreadEx with unsupported creation flags"
            );
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

        let Some(ntdll) = self.process.ntdll else {
            return NtStatus::NOT_SUPPORTED;
        };
        let thread_id = self.process.allocate_thread_id();
        let environment = match create_thread_environment(
            &self.global.page_manager,
            stack_size,
            self.process.peb_address,
            ClientId {
                unique_process: self.process.id,
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
            ntdll.rtl_user_thread_start,
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
        child_ctx.rip = ntdll.ldr_initialize_thunk;
        child_ctx.rsp = environment.stack_top;
        child_ctx.eflags = 0x202;
        child_ctx.rcx = environment.context;
        child_ctx.rdx = ntdll.mapping.base_addr;

        let thread = Arc::new(
            if create_flags.contains(ThreadCreateFlags::CREATE_SUSPENDED) {
                ThreadObject::new_suspended(thread_id, environment.teb)
            } else {
                ThreadObject::new(thread_id, environment.teb)
            },
        );
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
            io_completion_worker: Mutex::new(super::iocp::IoCompletionWorkerState::new()),
            entry_point: ntdll.ldr_initialize_thunk,
            stack_top: environment.stack_top,
            context: environment.context,
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

    pub(crate) fn sys_nt_resume_thread(
        &self,
        thread_handle: ThreadHandle,
        previous_suspend_count: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if let Some(previous_suspend_count) = previous_suspend_count
            && let Err(status) =
                probe_guest_output_preserving_value::<Platform, _>(previous_suspend_count)
        {
            return status;
        }
        let previous = if thread_handle.is_current() {
            self.thread_object.resume()
        } else {
            let entry = match self.typed_handle_entry_with_access::<ThreadSubsystem<Platform>>(
                thread_handle.as_handle(),
                ThreadAccess::SUSPEND_RESUME.bits(),
            ) {
                Ok(entry) => entry,
                Err(status) => return status,
            };
            entry.with_entry(|entry| entry.thread.resume())
        };
        if let Some(previous_suspend_count) = previous_suspend_count
            && previous_suspend_count
                .write_at_offset(0, previous)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_alert_thread(&self, thread_handle: ThreadHandle) -> NtStatus {
        if thread_handle.is_current() {
            self.thread_object.set_thread_alert();
        } else {
            let entry = match self.typed_handle_entry_with_access::<ThreadSubsystem<Platform>>(
                thread_handle.as_handle(),
                ThreadAccess::ALERT.bits(),
            ) {
                Ok(entry) => entry,
                Err(status) => return status,
            };
            entry.with_entry(|entry| entry.thread.set_thread_alert());
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_wait_for_alert_by_thread_id(
        &self,
        address: usize,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> NtStatus {
        let timeout = match timeout {
            Some(timeout) => match timeout.read_at_offset(0) {
                Some(timeout) => Some(self.wait_timeout_duration(timeout)),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };
        self.thread_object.begin_keyed_alert_wait(address);
        let result = self.wait_until(timeout, || self.thread_object.take_keyed_alert(address));
        let alert_raced_with_completion = self.thread_object.end_keyed_alert_wait(address);
        match result {
            Ok(()) | Err(litebox::event::wait::WaitError::Interrupted) => NtStatus::ALERTED,
            Err(litebox::event::wait::WaitError::TimedOut) if alert_raced_with_completion => {
                NtStatus::ALERTED
            }
            Err(litebox::event::wait::WaitError::TimedOut) => NtStatus::TIMEOUT,
        }
    }

    pub(crate) fn sys_nt_alert_thread_by_thread_id_ex(
        &self,
        thread_id: usize,
        address: usize,
    ) -> NtStatus {
        let Some(thread) = self.process.thread_by_id(thread_id) else {
            return NtStatus::INVALID_CID;
        };
        thread.alert_keyed_wait(Some(address));
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_alert_thread_by_thread_id(&self, thread_id: usize) -> NtStatus {
        let Some(thread) = self.process.thread_by_id(thread_id) else {
            return NtStatus::INVALID_CID;
        };
        thread.alert_keyed_wait(None);
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
        let Ok(thread_information_class) =
            QueryThreadInformationClass::try_from(thread_information_class)
        else {
            litebox_util_log::debug!(
                thread_information_class = thread_information_class;
                "Unsupported NtQueryInformationThread class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        match thread_information_class {
            QueryThreadInformationClass::BasicInformation => {
                let thread = if thread_handle.is_current() {
                    Arc::clone(&self.thread_object)
                } else {
                    let entry = match self
                        .typed_handle_entry_with_access::<ThreadSubsystem<Platform>>(
                            thread_handle.as_handle(),
                            ThreadAccess::QUERY_INFORMATION.bits(),
                        ) {
                        Ok(entry) => entry,
                        Err(status) => return status,
                    };
                    entry.with_entry(|entry| Arc::clone(&entry.thread))
                };
                let information = ThreadBasicInformation {
                    exit_status: thread.exit_status(),
                    _padding0: 0,
                    teb_base_address: thread.teb_address,
                    client_id: ClientId {
                        unique_process: self.process.id,
                        unique_thread: thread.thread_id,
                    },
                    affinity_mask: 1,
                    priority: 8,
                    base_priority: 8,
                };
                Self::write_thread_information(
                    thread_information,
                    thread_information_length,
                    return_length,
                    &information,
                )
            }
            QueryThreadInformationClass::AmILastThread => {
                if !thread_handle.is_current() {
                    return NtStatus::NOT_SUPPORTED;
                }
                let is_last_thread = u32::from(self.process.live_thread_count() == 1);
                Self::write_thread_information(
                    thread_information,
                    thread_information_length,
                    return_length,
                    &is_last_thread,
                )
            }
        }
    }

    fn write_thread_information<T: Immutable + IntoBytes>(
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_length = size_of::<T>().trunc();
        if thread_information_length < required_length {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if thread_information
            .write_slice_at_offset(0, information.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_length).is_none()
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
    extern crate std;

    use super::*;
    use crate::tests::{
        const_ptr, mut_byte_ptr, mut_ptr, null_const_ptr, run_with_test_platform_pointers,
    };
    use litebox::event::polling::TryOpError;
    use litebox::event::wait::WaitError;
    use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
    use std::sync::mpsc::TryRecvError;
    use std::time::{Duration, Instant};

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform>;

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn child_exception_completes_wait_before_last_thread_is_observed() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let child = parent
                .clone_for_test()
                .expect("a live process should accept another thread");
            let handle = parent
                .insert_typed_handle::<ThreadSubsystem<TestPlatform>>(
                    ThreadHandleObject {
                        thread: Arc::clone(&child.thread_object),
                    },
                    AccessMask::SYNCHRONIZE.bits(),
                    drop,
                )
                .expect("thread handle insertion should succeed");
            let child = WindowsShimEntrypoints {
                task: child,
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
    fn wait_for_alert_by_thread_id_blocks_until_matching_alert() {
        run_with_test_platform_pointers(|| {
            let alerter = crate::tests::test_task();
            let waiter = alerter
                .clone_for_test()
                .expect("a live process should accept another thread");
            let waiter_thread = Arc::clone(&waiter.thread_object);
            let thread_id = waiter_thread.thread_id();
            let wait_address = 0x1234;
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_with_test_platform_pointers(|| {
                    waiter.publish_thread_handle();
                    let timeout = -10_000_000i64;
                    result_tx
                        .send(waiter.sys_nt_wait_for_alert_by_thread_id(
                            wait_address,
                            Some(const_ptr(&timeout)),
                        ))
                        .unwrap();
                });
            });

            let deadline = Instant::now() + Duration::from_secs(2);
            while waiter_thread.keyed_alert_state.lock().wait_address != Some(wait_address) {
                assert!(Instant::now() < deadline, "waiter did not enter alert wait");
                std::thread::yield_now();
            }
            assert_eq!(result_rx.try_recv(), Err(TryRecvError::Empty));
            assert_eq!(
                alerter.sys_nt_alert_thread_by_thread_id_ex(thread_id, wait_address),
                NtStatus::SUCCESS
            );
            assert_eq!(
                result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                NtStatus::ALERTED
            );
            thread.join().unwrap();

            let timeout = 0i64;
            assert_eq!(
                alerter
                    .sys_nt_wait_for_alert_by_thread_id(wait_address, Some(const_ptr(&timeout)),),
                NtStatus::TIMEOUT
            );
        });
    }

    #[test]
    fn alert_wakes_an_alertable_wait() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let waiter = parent
                .clone_for_test()
                .expect("a live process should accept another thread");
            let waiter_thread = Arc::clone(&waiter.thread_object);
            let (registered_tx, registered_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_with_test_platform_pointers(|| {
                    waiter.publish_thread_handle();
                    let result: Result<(), TryOpError<NtStatus>> = waiter.wait_on_events(
                        false,
                        true,
                        None,
                        Events::IN,
                        |_, _| {
                            registered_tx.send(()).unwrap();
                            Ok(())
                        },
                        || Err(TryOpError::TryAgain),
                    );
                    result_tx.send(result).unwrap();
                });
            });

            registered_rx.recv().unwrap();
            waiter_thread.set_thread_alert();
            assert!(matches!(
                result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                Err(TryOpError::WaitError(WaitError::Interrupted))
            ));
            thread.join().unwrap();
            assert!(!waiter_thread.take_pending_thread_alert());
        });
    }

    #[test]
    fn non_alertable_wait_preserves_pending_alert() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let waiter = parent
                .clone_for_test()
                .expect("a live process should accept another thread");
            let waiter_thread = Arc::clone(&waiter.thread_object);
            let ready = Arc::new(AtomicBool::new(false));
            let wait_ready = Arc::clone(&ready);
            let (registered_tx, registered_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_with_test_platform_pointers(|| {
                    waiter.publish_thread_handle();
                    let result: Result<(), TryOpError<NtStatus>> = waiter.wait_on_events(
                        false,
                        false,
                        None,
                        Events::IN,
                        |observer, _| {
                            registered_tx.send(observer).unwrap();
                            Ok(())
                        },
                        || {
                            if wait_ready.load(Ordering::Acquire) {
                                Ok(())
                            } else {
                                Err(TryOpError::TryAgain)
                            }
                        },
                    );
                    result_tx.send(result).unwrap();
                });
            });

            let observer = registered_rx.recv().unwrap();
            waiter_thread.set_thread_alert();
            assert!(matches!(result_rx.try_recv(), Err(TryRecvError::Empty)));
            ready.store(true, Ordering::Release);
            observer.upgrade().unwrap().on_events(&Events::IN);
            assert!(
                result_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .is_ok()
            );
            thread.join().unwrap();
            assert!(waiter_thread.take_pending_thread_alert());
            assert!(!waiter_thread.take_pending_thread_alert());
        });
    }

    #[test]
    fn suspended_thread_does_not_enter_guest_until_resumed() {
        run_with_test_platform_pointers(|| {
            let parent = crate::tests::test_task();
            let child = parent
                .clone_for_test()
                .expect("a live process should accept another thread");
            let handle = parent
                .insert_typed_handle::<ThreadSubsystem<_>>(
                    ThreadHandleObject {
                        thread: Arc::clone(&child.thread_object),
                    },
                    ThreadAccess::SUSPEND_RESUME.bits(),
                    drop,
                )
                .unwrap();
            let handle = ThreadHandle::from_raw(handle.as_raw());
            child
                .thread_object
                .suspend_count
                .store(1, Ordering::Release);
            let suspended_thread = Arc::clone(&child.thread_object);
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_with_test_platform_pointers(|| {
                    child.publish_thread_handle();
                    started_tx.send(()).unwrap();
                    let mut ctx = litebox_common_linux::PtRegs::default();
                    let ready = child.prepare_to_run_guest(&mut ctx);
                    result_tx.send(ready).unwrap();
                });
            });

            started_rx.recv().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while suspended_thread.wait_handle.get().is_none() {
                assert!(
                    Instant::now() < deadline,
                    "child did not publish wait handle"
                );
                std::thread::yield_now();
            }
            assert_eq!(result_rx.try_recv(), Err(TryRecvError::Empty));
            let mut previous_suspend_count = u32::MAX;
            assert_eq!(
                parent.sys_nt_resume_thread(handle, Some(mut_ptr(&mut previous_suspend_count))),
                NtStatus::SUCCESS
            );
            assert_eq!(previous_suspend_count, 1);
            assert!(result_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            thread.join().unwrap();
            assert!(!suspended_thread.is_suspended());
            assert_eq!(parent.sys_nt_close(handle.as_handle()), NtStatus::SUCCESS);
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
