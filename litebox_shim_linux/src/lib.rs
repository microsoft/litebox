// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is generic over the choice of [LiteBox platform](../litebox/platform/index.html).
//! The concrete platform is threaded in by the runner via [`LinuxShimBuilder::new`].

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::cell::{Cell, RefCell};
use core::ops::Deref;
use litebox::{
    LiteBox,
    net::Network,
    pipes::Pipes,
    platform::{RawConstPointer, RawPointerProvider},
    shim::ContinueOperation,
    sync::Mutex,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_broker_protocol::fs::FileSeekWhence as SeekWhence;
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_common_linux::{
    FcntlArg, SyscallRequest,
    errno::Errno,
    mm::VmemManager,
    user_pointers::{UserPtr, UserPtrMut},
    vmem::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, VmemUnmapError,
    },
};
use litebox_platform::time::TimeProvider;
use syscalls::signal::SyscallRestart;

#[cfg(target_arch = "aarch64")]
const fn aarch64_rewrite_options() -> litebox_syscall_rewriter::RewriteOptions {
    #[cfg(target_os = "macos")]
    let host = litebox_syscall_rewriter::TargetHost::MacOs;
    #[cfg(not(target_os = "macos"))]
    let host = litebox_syscall_rewriter::TargetHost::Linux;
    litebox_syscall_rewriter::RewriteOptions::new(host, cfg!(feature = "aarch64_virtualize_x18"))
}

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) mod channel;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;
mod wait;

pub(crate) use litebox::fs::FileFd;

/// Aggregate bound capturing everything the shim requires of a platform.
///
/// This exists so that the (many) `impl` blocks throughout the shim can be written
/// as `impl<Platform: ShimPlatform, ..>` rather than repeating a large `where` clause.
pub trait ShimPlatform:
    litebox::platform::RawPointerProvider
    + TimeProvider
    + litebox::platform::PageManagementProvider<
        { PAGE_SIZE },
        Reservations = <Self as ShimPlatform>::VmemReservations,
    >
    + litebox_common_linux::vmem::VmemPageFaultHandler
    + litebox_platform::sync::RawMutexProvider
    + litebox::sync::RawSyncPrimitivesProvider
    + litebox::platform::SystemInfoProvider
    + litebox::platform::ArchSpecificProvider
    + litebox::platform::GuestVectorStateProvider<
        GuestVectorState = litebox_common_linux::GuestVectorState,
    >
    + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
    + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
    + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
    + 'static
    + Sized
{
    type VmemReservations: litebox_common_linux::vmem::LinuxReservationStore<Self, PAGE_SIZE>;
}

impl<T> ShimPlatform for T
where
    T: litebox::platform::RawPointerProvider
        + TimeProvider
        + litebox::platform::PageManagementProvider<{ PAGE_SIZE }>
        + litebox_common_linux::vmem::VmemPageFaultHandler
        + litebox_platform::sync::RawMutexProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::SystemInfoProvider
        + litebox::platform::ArchSpecificProvider
        + litebox::platform::GuestVectorStateProvider<
            GuestVectorState = litebox_common_linux::GuestVectorState,
        >
        + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
        + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
        + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
        + 'static
        + Sized,
    T::Reservations: litebox_common_linux::vmem::LinuxReservationStore<T, PAGE_SIZE>,
{
    type VmemReservations = T::Reservations;
}

// Linux-specific memory manager state and behavior.

struct ProgramBreakState {
    initial: usize,
    current: usize,
}

/// Linux memory manager.
pub struct MemoryManager<Platform: ShimPlatform> {
    vmem: VmemManager<Platform, PAGE_SIZE>,
    brk: Mutex<Platform, ProgramBreakState>,
}

impl<Platform: ShimPlatform> MemoryManager<Platform> {
    fn new(platform: &'static Platform) -> Self {
        Self {
            vmem: VmemManager::new(platform),
            brk: Mutex::new(ProgramBreakState {
                initial: 0,
                current: 0,
            }),
        }
    }

    /// Sets the initial program break address.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break has already been set or cannot be rounded up to a page
    /// boundary.
    fn set_initial_brk(&self, brk: usize) {
        let mut state = self.brk.lock();
        assert_eq!(state.initial, 0, "initial brk is already set");
        assert!(
            brk.checked_next_multiple_of(PAGE_SIZE).is_some(),
            "initial brk is too large"
        );
        state.initial = brk;
        state.current = brk;
    }

    /// Returns the initial and current program break.
    fn program_break(&self) -> (usize, usize) {
        let state = self.brk.lock();
        (state.initial, state.current)
    }

    /// Restores the program break of a process duplicated by `fork`, whose memory already
    /// covers it.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break has already been set.
    fn restore_program_break(&self, initial: usize, current: usize) {
        let mut state = self.brk.lock();
        assert_eq!(state.initial, 0, "initial brk is already set");
        state.initial = initial;
        state.current = current;
    }

    /// Sets or queries the Linux program break.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break has not been set.
    ///
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released region is no
    /// longer used.
    unsafe fn brk(&self, requested: usize) -> Result<usize, MappingError> {
        let mut state = self.brk.lock();
        assert_ne!(state.initial, 0, "initial brk is not set yet");
        if requested == 0 {
            return Ok(state.current);
        }
        if requested < state.initial {
            return Ok(state.current);
        }

        let old_page_end = state.current.next_multiple_of(PAGE_SIZE);
        let Some(new_page_end) = requested.checked_next_multiple_of(PAGE_SIZE) else {
            return Ok(state.current);
        };
        if new_page_end > Platform::TASK_ADDR_MAX {
            return Ok(state.current);
        }
        if state.current >= requested {
            if let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(old_page_end - new_page_end) {
                let ptr =
                    <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(new_page_end);
                if unsafe { self.vmem.remove_pages(ptr, length.as_usize()) }.is_err() {
                    return Ok(state.current);
                }
            }
            state.current = requested;
            return Ok(requested);
        }

        if let (Some(address), Some(length)) = (
            NonZeroAddress::new(old_page_end),
            NonZeroPageSize::new(new_page_end - old_page_end),
        ) {
            unsafe {
                self.vmem.create_writable_pages(
                    Some(address),
                    length,
                    CreatePagesFlags::FIXED_ADDR
                        | CreatePagesFlags::NOREPLACE
                        | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                    |_| Ok(0),
                )
            }?;
        }
        state.current = requested;
        Ok(requested)
    }

    /// Releases all mappings and resets Linux program-break state.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the released regions are no longer used.
    pub unsafe fn release_memory(&self) -> Result<(), VmemUnmapError> {
        let mut state = self.brk.lock();
        unsafe { self.vmem.release_memory() }?;
        state.initial = 0;
        state.current = 0;
        Ok(())
    }
}

impl<Platform: ShimPlatform> Deref for MemoryManager<Platform> {
    type Target = VmemManager<Platform, PAGE_SIZE>;

    fn deref(&self) -> &Self::Target {
        &self.vmem
    }
}

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    if cfg!(debug_assertions) {
        litebox_util_log::warn!(feature:% = args; "unsupported");
    }
}

#[cfg(target_pointer_width = "64")]
fn preadv_pwritev_offset(pos_l: usize, _pos_h: usize) -> i64 {
    pos_l.reinterpret_as_signed() as i64
}

#[cfg(target_pointer_width = "32")]
fn preadv_pwritev_offset(pos_l: usize, pos_h: usize) -> i64 {
    ((pos_h as u64) << 32 | pos_l as u64).reinterpret_as_signed()
}

pub struct LinuxShimEntrypoints<Platform: ShimPlatform> {
    task: Task<Platform>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<Platform: ShimPlatform> litebox::shim::EnterShim for LinuxShimEntrypoints<Platform> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, |task, ctx| {
            task.handle_init_request(ctx);
            None
        })
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        #[cfg(target_arch = "x86_64")]
        if info.kernel_mode && info.exception == litebox::shim::Exception::PAGE_FAULT {
            if unsafe {
                self.task
                    .global
                    .mm
                    .handle_page_fault(info.cr2, info.error_code.into())
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            } else {
                return ContinueOperation::Terminate;
            }
        }
        #[cfg(target_arch = "aarch64")]
        if info.kernel_mode
            && (info.exception == litebox::shim::Exception::DATA_ABORT_CURRENT_EL
                || info.exception == litebox::shim::Exception::INSTRUCTION_ABORT_CURRENT_EL)
        {
            unimplemented!(
                "aarch64: kernel-mode demand paging needs the ESR_EL1 ISS access bits, \
                 which no aarch64 platform currently supplies (esr={:#x}, far={:#x})",
                info.esr,
                info.fault_address
            );
        }
        self.enter_shim(false, ctx, |task, ctx| {
            task.handle_exception_request(info, ctx);
            None
        })
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| None)
    }
}

impl<Platform: ShimPlatform> LinuxShimEntrypoints<Platform> {
    /// Runs `f`, which returns how an interrupted syscall restarts, then prepares to resume the
    /// guest.
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<Platform>, &mut litebox_common_linux::PtRegs) -> Option<SyscallRestart>,
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        let restart = f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx, restart) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    process_id: i32,
}

impl<Platform: ShimPlatform> LinuxShimBuilder<Platform> {
    /// Returns a new shim builder using the given platform.
    pub fn new(platform: &'static Platform, process_id: i32) -> Self {
        Self::new_with_litebox(platform, LiteBox::new(platform), process_id)
    }

    /// Returns a new shim builder using an already-created LiteBox instance.
    pub fn new_with_litebox(
        platform: &'static Platform,
        litebox: LiteBox<Platform>,
        process_id: i32,
    ) -> Self {
        Self {
            platform,
            litebox,
            process_id,
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build the shim.
    pub fn build(self) -> LinuxShim<Platform> {
        let litebox = Arc::new(self.litebox);
        let net = Network::new(&litebox);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            mm: MemoryManager::new(self.platform),
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            process_id: self.process_id,
            litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
            elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
        });
        LinuxShim(global)
    }
}

pub struct LinuxShim<Platform: ShimPlatform>(Arc<GlobalState<Platform>>);
impl<Platform: ShimPlatform> Clone for LinuxShim<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform> LinuxShim<Platform> {
    /// Loads a program using the initial thread allocated during broker negotiation.
    pub fn load_program(
        &self,
        task: litebox_common_linux::TaskParams,
        initial_thread: litebox::thread::Thread,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            uid,
            euid,
            gid,
            egid,
            blocked_signals,
            ignored_signals,
            inherited_fds,
            cwd,
            umask,
        } = task;
        if pid != self.0.process_id {
            return Err(loader::elf::ElfLoaderError::InvalidProcessId);
        }

        let files = syscalls::file::FilesState::new();
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR);
        let files = Arc::new(files);
        let credentials = Arc::new(syscalls::process::Credentials {
            uid,
            euid,
            gid,
            egid,
        });
        let fs_state = syscalls::file::FsState::new(&credentials);
        if let Some(cwd) = cwd {
            fs_state
                .inherit_cwd(&cwd)
                .map_err(loader::elf::ElfLoaderError::OpenError)?;
        }
        if let Some(umask) = umask {
            fs_state.set_umask(umask);
        }
        let fs_state = Arc::new(fs_state);
        match inherited_fds {
            None => {
                files.initialize_stdio_in_shared_descriptors_table(
                    &self.0,
                    &fs_state.context.read(),
                );
            }
            Some(inherited_fds) => files.install_inherited_fds(&self.0, &inherited_fds)?,
        }

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                litebox_thread: Cell::new(Some(initial_thread)),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.0.platform),
                vfork: RefCell::new(None),
                pid,
                credentials,
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: fs_state.into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::inherited(blocked_signals, ignored_signals),
            },
        };
        // A program started by `execve` keeps an ignored `SIGCHLD`, while the broker starts
        // each process without child reaping.
        if entrypoints.task.signals.reaps_children() {
            entrypoints.task.set_child_reaping(true);
        }
        entrypoints.task.adopt_orphans_if_first();
        entrypoints.task.open_signals();

        let (path, argv) = entrypoints
            .task
            .resolve_shebang(alloc::string::String::from(path), argv)
            .map_err(loader::elf::ElfLoaderError::OpenError)?;

        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, &path)?,
            argv,
            envp,
        )?;
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Continues a process duplicated by `fork` using the initial thread allocated during broker
    /// negotiation.
    ///
    /// `load_image` fills page-aligned whole pages with the parent's process image from an
    /// offset, possibly by mapping the image over them privately. The pages start zero-filled,
    /// so ranges the image does not hold may be left untouched.
    ///
    /// Each memory region is restored at the parent's address and fails if the address is in
    /// use. Regions formerly backed by files are restored as anonymous memory.
    pub fn restore_fork(
        &self,
        startup: litebox_common_linux::program_startup::LinuxForkStartup,
        initial_thread: litebox::thread::Thread,
        load_image: impl FnMut(u64, &mut [u8]) -> Result<(), Errno>,
    ) -> Result<LoadedProgram<Platform>, ForkRestoreError> {
        let litebox_common_linux::program_startup::LinuxForkStartup {
            uid,
            euid,
            gid,
            egid,
            umask,
            cwd,
            comm,
            blocked_signals,
            signal_actions,
            alternate_signal_stack,
            registers,
            vector_state,
            thread_pointer,
            syscall_entry_point,
            set_child_tid,
            clear_child_tid,
            initial_program_break,
            program_break,
            regions,
            fds,
        } = startup;
        let pid = self.0.process_id;
        if syscall_entry_point != self.0.platform.get_syscall_entry_point() {
            return Err(ForkRestoreError::IncompatibleRunner);
        }

        Task::restore_fork_image(&self.0.mm, &regions, load_image)?;
        self.0
            .mm
            .restore_program_break(initial_program_break, program_break);

        let files = syscalls::file::FilesState::new();
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR);
        files
            .install_forked_fds(&self.0, &fds)
            .map_err(ForkRestoreError::Descriptors)?;
        let credentials = Arc::new(syscalls::process::Credentials {
            uid,
            euid,
            gid,
            egid,
        });
        let fs_state = syscalls::file::FsState::new(&credentials);
        fs_state
            .inherit_cwd(&cwd)
            .map_err(ForkRestoreError::WorkingDirectory)?;
        fs_state.set_umask(umask);

        let thread = syscalls::process::ThreadState::new_process(pid);
        thread.set_forked_init_state(
            registers,
            vector_state,
            thread_pointer,
            set_child_tid,
            clear_child_tid,
        );
        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                litebox_thread: Cell::new(Some(initial_thread)),
                thread,
                wait_state: wait::WaitState::new(self.0.platform),
                vfork: RefCell::new(None),
                pid,
                credentials,
                comm: comm.into(),
                fs: Arc::new(fs_state).into(),
                files: Arc::new(files).into(),
                signals: syscalls::signal::SignalState::forked(
                    blocked_signals,
                    &signal_actions,
                    alternate_signal_stack,
                ),
            },
        };
        // The broker starts each process without child reaping.
        if entrypoints.task.signals.reaps_children() {
            entrypoints.task.set_child_reaping(true);
        }
        entrypoints.task.open_signals();
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Returns the global memory manager.
    pub fn memory_manager(&self) -> &MemoryManager<Platform> {
        &self.0.mm
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        self.0.litebox.as_ref()
    }

    /// Returns the platform this shim was built with.
    pub fn platform(&self) -> &'static Platform {
        self.0.platform
    }
}

pub struct LoadedProgram<Platform: ShimPlatform> {
    pub entrypoints: LinuxShimEntrypoints<Platform>,
    pub process: LinuxShimProcess<Platform>,
}

/// A failure to continue a process duplicated by `fork`.
#[derive(Debug, thiserror::Error)]
pub enum ForkRestoreError {
    /// The runner's code addresses differ from the parent's runner.
    #[error("the runner's address layout differs from the parent's")]
    IncompatibleRunner,
    /// A memory region could not be restored at its address.
    #[error("failed to restore the memory region at {0:#x}")]
    Memory(usize, #[source] MappingError),
    /// The process image could not be read.
    #[error("failed to read the process image")]
    Image(#[source] Errno),
    /// The inherited descriptors could not be installed.
    #[error("failed to install the inherited descriptors")]
    Descriptors(#[source] loader::elf::ElfLoaderError),
    /// The working directory could not be restored.
    #[error("failed to restore the working directory")]
    WorkingDirectory(#[source] Errno),
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess<Platform: ShimPlatform>(Arc<syscalls::process::ProcessState<Platform>>);

impl<Platform: ShimPlatform> LinuxShimProcess<Platform> {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }

    /// Wait for the process to exit, returning its termination status.
    pub fn wait_for_exit_status(&self) -> ProcessExitStatus {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => ProcessExitStatus::Exited {
                code: u32::from(v.cast_unsigned()),
            },
            syscalls::process::ExitStatus::Signal(signal) => ProcessExitStatus::Signaled {
                signal: signal.as_i32().cast_unsigned(),
            },
        }
    }

    /// Wait for the process to exit, returning an exit code suitable for a Unix shell.
    pub fn wait_for_unix_shell_exit_code(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => i32::from(v) & 0xff,
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 128,
        }
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    fn close_on_exec(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            if let Ok(fd) = files.typed_fd_from_raw(raw_fd)
                && syscalls::file::get_file_descriptor_flags(&fd, &self.global)
                    .contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
            {
                let _ = self.do_close(raw_fd);
            }
        }
    }
}

impl<Platform: ShimPlatform> syscalls::file::FilesState<Platform> {
    /// Resolve a userland fd number, rejecting negative values with `EBADF`.
    pub(crate) fn typed_fd(&self, fd: i32) -> Result<syscalls::file::AnyTypedFd<Platform>, Errno> {
        self.typed_fd_from_raw(usize::try_from(fd).map_err(|_| Errno::EBADF)?)
    }

    pub(crate) fn typed_fd_from_raw(
        &self,
        fd: usize,
    ) -> Result<syscalls::file::AnyTypedFd<Platform>, Errno> {
        Self::typed_fd_locked(&self.raw_descriptor_store.read(), fd)
    }

    /// Like [`Self::typed_fd_from_raw`], with the raw descriptor store already locked.
    pub(crate) fn typed_fd_locked(
        rds: &litebox::fd::RawDescriptorStorage,
        fd: usize,
    ) -> Result<syscalls::file::AnyTypedFd<Platform>, Errno> {
        macro_rules! resolve_fd {
            ($subsystem:ty, $variant:ident) => {
                if let Ok(fd) = rds.fd_from_raw_integer::<$subsystem>(fd) {
                    return Ok(syscalls::file::AnyTypedFd::$variant(fd));
                }
            };
        }

        resolve_fd!(litebox::fs::BrokerFile, Fs);
        resolve_fd!(Network<Platform>, Network);
        resolve_fd!(Pipes<Platform>, Pipes);
        resolve_fd!(syscalls::eventfd::EventfdSubsystem<Platform>, Eventfd);
        resolve_fd!(syscalls::epoll::EpollSubsystem<Platform>, Epoll);
        resolve_fd!(syscalls::unix::UnixSocketSubsystem<Platform>, Unix);
        resolve_fd!(syscalls::timerfd::TimerfdSubsystem<Platform>, Timerfd);
        Err(Errno::EBADF)
    }
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

trait ToSyscallResult {
    fn to_syscall_result(self) -> Result<usize, Errno>;
}
impl ToSyscallResult for Result<(), Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|()| 0)
    }
}
impl ToSyscallResult for Result<usize, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self
    }
}
impl ToSyscallResult for Result<u32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|v| v as usize)
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// A wrapper function around `do_pread_with_user_buf` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        self.with_typed_fd(fd, |fd| self.do_pread_with_user_buf(fd, buf, count, offset))
    }

    fn do_pread_with_user_buf(
        &self,
        fd: &syscalls::file::AnyTypedFd<Platform>,
        buf: UserPtrMut<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
        let mut read_total = 0;
        while read_total < count {
            let to_read = (count - read_total).min(kernel_buf.len());
            let read_offset = offset
                .checked_add(read_total.reinterpret_as_signed() as i64)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(Errno::EINVAL)?;
            match self.do_read(fd, &mut kernel_buf[..to_read], Some(read_offset)) {
                Ok(0) => break, // EOF
                Ok(size) => {
                    buf.copy_from_slice::<Platform>(read_total, &kernel_buf[..size])
                        .ok_or(Errno::EFAULT)?;
                    read_total += size;
                }
                Err(e) => return Err(e),
            }
        }
        assert!(read_total <= count);
        Ok(read_total)
    }

    /// Handle Linux syscalls and dispatch them to LiteBox implementations.
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    ///
    /// Returns how the syscall restarts if a signal interrupted it. Its return value is then
    /// `EINTR` until signal delivery decides.
    fn handle_syscall_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> Option<SyscallRestart> {
        let result = self.do_syscall(ctx);
        let restart = result.err().and_then(SyscallRestart::from_errno);
        let return_value = match result {
            Ok(v) => v,
            Err(err) => (err.without_restart().as_neg() as isize).reinterpret_as_unsigned(),
        };
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            ctx.regs[0] = return_value;
        }
        restart
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        // AArch64 syscall ABI: `w8`, mirrored in `pt_regs::syscallno`.
        #[cfg(target_arch = "aarch64")]
        let syscall_number = ctx.syscallno.cast_unsigned() as usize;
        let request = SyscallRequest::try_from_raw(syscall_number, ctx, log_unsupported_fmt);
        // The constrained vfork child may only inspect its temporary identity and resource limits,
        // manage its own process group and session, signal state, descriptors, working directory,
        // and umask, open and write files, exit, or attempt execve. Any other syscall terminates
        // the shared runner.
        let is_vfork_child = self.vfork.borrow().is_some();
        if is_vfork_child
            && !matches!(
                &request,
                Ok(SyscallRequest::Exit { .. }
                    | SyscallRequest::ExitGroup { .. }
                    | SyscallRequest::Execve { .. }
                    | SyscallRequest::Getpid
                    | SyscallRequest::Getppid
                    | SyscallRequest::Gettid
                    | SyscallRequest::Setpgid { .. }
                    | SyscallRequest::Getpgid { .. }
                    | SyscallRequest::Getpgrp
                    | SyscallRequest::Setsid
                    | SyscallRequest::Getsid { .. }
                    | SyscallRequest::Prlimit {
                        pid: 0,
                        new_limit: None,
                        ..
                    }
                    | SyscallRequest::RtSigaction { .. }
                    | SyscallRequest::RtSigprocmask { .. }
                    | SyscallRequest::RtSigreturn
                    | SyscallRequest::Sigaltstack { .. }
                    | SyscallRequest::Close { .. }
                    | SyscallRequest::CloseRange { .. }
                    | SyscallRequest::Dup { .. }
                    | SyscallRequest::Fcntl {
                        arg: FcntlArg::GETFD | FcntlArg::SETFD(_) | FcntlArg::DUPFD { .. },
                        ..
                    }
                    | SyscallRequest::Openat { .. }
                    | SyscallRequest::Write { .. }
                    | SyscallRequest::Chdir { .. }
                    | SyscallRequest::Umask { .. })
            )
        {
            return Ok(self.abort_vfork_window());
        }

        let request = request?;
        match request {
            // The vfork child is the only thread of its process, so `exit` also ends the process.
            SyscallRequest::Exit { status } | SyscallRequest::ExitGroup { status }
                if is_vfork_child =>
            {
                // Like Linux, only the low byte of the status is reported.
                let code = status.cast_unsigned() & 0xff;
                Ok(self.exit_vfork_child(ProcessExitStatus::Exited { code }, ctx))
            }
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => self.sys_execve(pathname, argv, envp, ctx),
            SyscallRequest::Read { fd, buf, count } => {
                // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
                // requested indicates EOF.
                if count <= MAX_KERNEL_BUF_SIZE {
                    let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                } else {
                    // If the read size is too large, we need to do some extra work to avoid OOMing.
                    // We read data in chunks and update the file offset ourselves only if the read succeeds.
                    self.with_typed_fd(fd, |fd| {
                        let cur_loc = self.do_seek(fd, 0, SeekWhence::RelativeToCurrentOffset)?;
                        let read_total = self.do_pread_with_user_buf(
                            fd,
                            buf,
                            count,
                            i64::try_from(cur_loc).map_err(|_| Errno::EOVERFLOW)?,
                        )?;
                        let new_loc = cur_loc.checked_add(read_total).ok_or(Errno::EOVERFLOW)?;
                        self.do_seek(
                            fd,
                            isize::try_from(new_loc).map_err(|_| Errno::EOVERFLOW)?,
                            SeekWhence::RelativeToBeginning,
                        )?;
                        Ok(read_total)
                    })
                }
            }
            SyscallRequest::Write { fd, buf, count } => match buf.to_owned_slice::<Platform>(count)
            {
                Some(buf) => self.sys_write(fd, &buf, None),
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Close { fd } => syscall!(sys_close(fd)),
            SyscallRequest::CloseRange { first, last, flags } => {
                syscall!(sys_close_range(first, last, flags))
            }
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.trunc())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdirat {
                dirfd,
                pathname,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mkdirat(dirfd, path, mode))
                }),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
            SyscallRequest::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => self.sys_rt_sigprocmask(how, set, oldset, sigsetsize),
            SyscallRequest::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => self.sys_rt_sigaction(signum, act, oldact, sigsetsize),
            SyscallRequest::RtSigreturn => self.sys_rt_sigreturn(ctx),
            SyscallRequest::Ioctl { fd, arg } => syscall!(sys_ioctl(fd, arg)),
            SyscallRequest::Pread64 {
                fd,
                buf,
                count,
                offset,
            } => self.pread_with_user_buf(fd, buf, count, offset),
            SyscallRequest::Pwrite64 {
                fd,
                buf,
                count,
                offset,
            } => match buf.to_owned_slice::<Platform>(count) {
                Some(buf) => self.sys_pwrite64(fd, &buf, offset),
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Sendfile {
                out_fd,
                in_fd,
                offset,
                count,
            } => syscall!(sys_sendfile(out_fd, in_fd, offset, count)),
            SyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => self
                .sys_mmap(addr, length, prot, flags, fd, offset)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Mprotect { addr, length, prot } => {
                syscall!(sys_mprotect(addr, length, prot))
            }
            SyscallRequest::Mremap {
                old_addr,
                old_size,
                new_size,
                flags,
                new_addr,
            } => self
                .sys_mremap(old_addr, old_size, new_size, flags, new_addr)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Munmap { addr, length } => syscall!(sys_munmap(addr, length)),
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Preadv {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_preadv(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Pwritev {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_pwritev(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Faccessat {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_faccessat(dirfd, path, mode, flags))
                }),
            SyscallRequest::Madvise {
                addr,
                length,
                behavior,
            } => syscall!(sys_madvise(addr, length, behavior)),
            SyscallRequest::Dup {
                oldfd,
                newfd,
                flags,
            } => syscall!(sys_dup(oldfd, newfd, flags)),
            SyscallRequest::Socket {
                domain,
                type_and_flags,
                protocol,
            } => syscall!(sys_socket(domain, type_and_flags, protocol)),
            SyscallRequest::Socketpair {
                domain,
                type_and_flags,
                protocol,
                sockvec,
            } => syscall!(sys_socketpair(domain, type_and_flags, protocol, sockvec)),
            SyscallRequest::Connect {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_connect(sockfd, sockaddr, addrlen)),
            SyscallRequest::Accept {
                sockfd,
                addr,
                addrlen,
                flags,
            } => syscall!(sys_accept(sockfd, addr, addrlen, flags)),
            SyscallRequest::Sendto {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_sendto(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Sendmsg { sockfd, msg, flags } => self.sys_sendmsg(sockfd, msg, flags),
            SyscallRequest::Sendmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
            } => self.sys_sendmmsg(sockfd, msgvec, vlen, flags),
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Recvmsg { sockfd, msg, flags } => self.sys_recvmsg(sockfd, msg, flags),
            SyscallRequest::Recvmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
                timeout,
            } => self.sys_recvmmsg(sockfd, msgvec, vlen, flags, timeout),
            SyscallRequest::Shutdown { sockfd, how } => syscall!(sys_shutdown(sockfd, how)),
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Setsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_setsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_getsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockname {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getsockname(sockfd, addr, addrlen)),
            SyscallRequest::Getpeername {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getpeername(sockfd, addr, addrlen)),
            SyscallRequest::Uname { buf } => syscall!(sys_uname(buf)),
            SyscallRequest::Fcntl { fd, arg } => syscall!(sys_fcntl(fd, arg)),
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => syscall!(sys_epoll_ctl(epfd, op, fd, event)),
            SyscallRequest::EpollCreate { size, flags } => {
                // the `size` argument is ignored, but must be greater than zero;
                if size > 0 {
                    syscall!(sys_epoll_create(flags))
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::EpollPwait {
                epfd,
                events,
                maxevents,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize),
            SyscallRequest::Prctl { args } => self.sys_prctl(args),
            SyscallRequest::ArchPrctl { arg } => syscall!(sys_arch_prctl(arg)),
            SyscallRequest::Readlink {
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                }),
            SyscallRequest::Ppoll {
                fds,
                nfds,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_ppoll(fds, nfds, timeout, sigmask, sigsetsize),
            SyscallRequest::Pselect {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
                sigsetpack,
            } => self.sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigsetpack),
            SyscallRequest::Readlinkat {
                dirfd,
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                        .and_then(|size| {
                            buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                                .map(|()| size)
                                .ok_or(Errno::EFAULT)
                        })
                }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::ClockGettime { clockid, tp } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_gettime(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_gettime(clock_id, tp)))
            }
            SyscallRequest::ClockGetres { clockid, res } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_getres(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_getres(clock_id, res)))
            }
            SyscallRequest::ClockNanosleep {
                clockid,
                flags,
                request,
                remain,
            } => litebox_common_linux::ClockId::try_from(clockid)
                .map_err(|_| {
                    log_unsupported!("clock_nanosleep(clockid = {clockid})");
                    Errno::EINVAL
                })
                .and_then(|clock_id| {
                    syscall!(sys_clock_nanosleep(clock_id, flags, request, remain))
                }),
            SyscallRequest::Time { tloc } => self
                .sys_time(tloc)
                .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
            SyscallRequest::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_openat(dirfd, path, flags, mode))
                }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Mknodat {
                dirfd,
                pathname,
                mode_and_type,
                dev,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mknodat(dirfd, path, mode_and_type, dev))
                }),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_unlinkat(dirfd, path, flags))
                }),
            SyscallRequest::Stat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_stat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_lstat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                buf.write_at_offset::<Platform>(0, stat)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                        buf.write_at_offset::<Platform>(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                }),
            SyscallRequest::Statx {
                dirfd,
                pathname,
                flags,
                mask,
                statxbuf,
            } => {
                let (path, flags) = match pathname {
                    // Linux 6.11+ treats a NULL statx path as a request to stat dirfd.
                    None => (
                        Ok(c"".into()),
                        flags | litebox_common_linux::AtFlags::AT_EMPTY_PATH,
                    ),
                    Some(p) => (p.to_cstring::<Platform>().ok_or(Errno::EFAULT), flags),
                };
                path.and_then(|path| {
                    self.sys_statx(dirfd, path, flags, mask).and_then(|sx| {
                        statxbuf
                            .write_at_offset::<Platform>(0, sx)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::TimerfdCreate { clockid, flags } => {
                syscall!(sys_timerfd_create(clockid, flags))
            }
            SyscallRequest::TimerfdSettime {
                fd,
                flags,
                new_value,
                old_value,
            } => syscall!(sys_timerfd_settime(fd, flags, new_value, old_value)),
            SyscallRequest::TimerfdGettime { fd, curr_value } => {
                syscall!(sys_timerfd_gettime(fd, curr_value))
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    pipefd
                        .write_at_offset::<Platform>(0, read_fd)
                        .ok_or(Errno::EFAULT)?;
                    pipefd
                        .write_at_offset::<Platform>(1, write_fd)
                        .ok_or(Errno::EFAULT)?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::Fork => self.sys_fork(ctx),
            SyscallRequest::Vfork => self.sys_vfork(ctx),
            SyscallRequest::SetThreadArea { user_desc } => {
                // Neither x86-64 nor AArch64 supports `set_thread_area`.
                let _ = user_desc;
                Err(Errno::ENOSYS)
            }
            SyscallRequest::SetTidAddress { tidptr } => {
                Ok(self.sys_set_tid_address(tidptr).reinterpret_as_unsigned() as usize)
            }
            SyscallRequest::Gettid => Ok(self.sys_gettid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getrlimit { resource, rlim } => {
                syscall!(sys_getrlimit(resource, rlim))
            }
            SyscallRequest::Setrlimit { resource, rlim } => {
                syscall!(sys_setrlimit(resource, rlim))
            }
            SyscallRequest::Prlimit {
                pid,
                resource,
                new_limit,
                old_limit,
            } => syscall!(sys_prlimit(pid, resource, new_limit, old_limit)),
            SyscallRequest::SetRobustList { head } => {
                self.sys_set_robust_list(head);
                Ok(0)
            }
            SyscallRequest::GetRobustList { pid, head, len } => self
                .sys_get_robust_list(pid, head)
                .and_then(|()| {
                    len.write_at_offset::<Platform>(
                        0,
                        size_of::<litebox_common_linux::RobustListHead>(),
                    )
                    .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self.sys_wait4(pid, wstatus, options, rusage),
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Setpgid { pid, pgid } => self.sys_setpgid(pid, pgid),
            SyscallRequest::Getpgid { pid } => self.sys_getpgid(pid),
            SyscallRequest::Getpgrp => self.sys_getpgrp(),
            SyscallRequest::Setsid => self.sys_setsid(),
            SyscallRequest::Getsid { pid } => self.sys_getsid(pid),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset::<Platform>(0, sysinfo)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
            SyscallRequest::GetDirent64 { fd, dirp, count } => {
                self.sys_getdirent64(fd, dirp, count)
            }
            SyscallRequest::SchedGetAffinity { pid, len, mask } => {
                let cpuset = self.sys_sched_getaffinity(pid);
                let raw_bytes = cpuset.as_bytes();
                if len < raw_bytes.len() || len & (core::mem::size_of::<usize>() - 1) != 0 {
                    Err(Errno::EINVAL)
                } else {
                    mask.copy_from_slice::<Platform>(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Do nothing until we have more scheduler integration with the
                // platform.
                Ok(0)
            }
            SyscallRequest::Futex { args } => self.sys_futex(args),
            SyscallRequest::Umask { mask } => {
                let old_mask = self.sys_umask(mask);
                Ok(old_mask.bits() as usize)
            }
            SyscallRequest::Kill { pid, sig } => self.sys_kill(pid, sig),
            SyscallRequest::Tkill { tid, sig } => self.sys_tkill(tid, sig),
            SyscallRequest::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            SyscallRequest::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss, ctx),
            SyscallRequest::Alarm { seconds } => syscall!(sys_alarm(seconds)),
            SyscallRequest::Pause => syscall!(sys_pause()),
            SyscallRequest::GetITimer { which, curr_value } => {
                syscall!(sys_getitimer(which, curr_value))
            }
            SyscallRequest::SetITimer {
                which,
                new_value,
                old_value,
            } => syscall!(sys_setitimer(which, new_value, old_value)),
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<Platform: ShimPlatform> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: Arc<litebox::LiteBox<Platform>>,
    /// The memory manager for managing virtual memory.
    mm: MemoryManager<Platform>,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem.
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Process ID assigned to this shim.
    process_id: i32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<Platform>>,
    /// Per-process collection of ELF patching state for runtime syscall rewriting.
    elf_patch_cache: litebox::sync::Mutex<Platform, syscalls::mm::ElfPatchCache>,
}

struct Task<Platform: ShimPlatform> {
    global: Arc<GlobalState<Platform>>,
    litebox_thread: Cell<Option<litebox::thread::Thread>>,
    wait_state: wait::WaitState<Platform>,
    thread: syscalls::process::ThreadState<Platform>,
    vfork: RefCell<Option<VforkState<Platform>>>,
    /// Process ID
    pid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials.
    credentials: Arc<syscalls::process::Credentials>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState<Platform>>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState<Platform>>>,
    /// Signal state
    signals: syscalls::signal::SignalState<Platform>,
}

struct VforkState<Platform: ShimPlatform> {
    child: litebox::process::PendingChild,
    child_pid: i32,
    parent_context: litebox_common_linux::PtRegs,
    /// The parent's floating-point and vector state, which the child may change.
    parent_vector_state: litebox_common_linux::GuestVectorState,
    parent_fs: Arc<syscalls::file::FsState<Platform>>,
    parent_files: Arc<syscalls::file::FilesState<Platform>>,
    parent_signals: syscalls::signal::VforkParentSignals<Platform>,
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    fn create_thread(&self) -> Result<litebox::thread::Thread, litebox::thread::CreateError> {
        self.litebox.create_thread()
    }
}

impl<Platform: ShimPlatform> Drop for Task<Platform> {
    fn drop(&mut self) {
        // A thread can end inside a `vfork` window, as when a sibling thread execs. The process
        // goes on, so the child's descriptors must not keep their open file descriptions alive.
        if self.vfork.get_mut().is_some() {
            self.close_vfork_child_descriptors();
        }
        self.prepare_for_exit();
        // Remove the local identity before the broker can release it for reuse,
        // but keep the process thread count until broker exit is acknowledged.
        let detach = self.thread.begin_detach_from_process();
        if let Some(thread) = self.litebox_thread.take() {
            let thread_id = thread.id();
            if let Err(error) = thread.exit() {
                litebox_util_log::error!(
                    error:% = error,
                    thread_id;
                    "failed to record thread exit"
                );
            }
        }
        drop(detach);
    }
}

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<Platform: ShimPlatform> GlobalState<Platform> {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>) -> Task<Platform> {
            let pid = self.process_id;
            let files = Arc::new(syscalls::file::FilesState::new());
            let credentials = Arc::new(syscalls::process::Credentials {
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
            });
            let fs_state = Arc::new(syscalls::file::FsState::new(&credentials));
            files.initialize_stdio_in_shared_descriptors_table(&self, &fs_state.context.read());
            Task {
                wait_state: wait::WaitState::new(self.platform),
                litebox_thread: Cell::new(None),
                thread: syscalls::process::ThreadState::new_process(pid),
                vfork: RefCell::new(None),
                pid,
                credentials,
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: fs_state.into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                global: self,
            }
        }
    }

    impl<Platform: ShimPlatform> Task<Platform> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let litebox_thread = self.global.create_thread().ok()?;
            let tid = i32::try_from(litebox_thread.id())
                .expect("the assigned thread ID must fit Linux pid_t");
            let Some(thread) = self.thread.new_thread(tid) else {
                let _ = litebox_thread.exit();
                return None;
            };
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                litebox_thread: Cell::new(Some(litebox_thread)),
                thread,
                vfork: RefCell::new(None),
                pid: self.pid,
                credentials: self.credentials.clone(),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        #[must_use]
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<Platform>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
