// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is parametric in the choice of [LiteBox platform](../litebox/platform/index.html),
//! chosen by the [platform multiplex](../litebox_platform_multiplex/index.html).

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use core::fmt::Write as _;
use core::sync::atomic::Ordering;
use litebox::{
    LiteBox,
    fd::TypedFd,
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

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
pub mod transport;
mod wait;

use crate::syscalls::file::get_file_descriptor_flags;

pub type DefaultFS = LinuxFS;

pub(crate) type LinuxFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

pub(crate) type FileFd<FS> = litebox::fd::TypedFd<FS>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;

        let msg = alloc::format!("WARNING: unsupported: {args}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = args;
    }
}

pub struct LinuxShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<FS: ShimFS> litebox::shim::EnterShim for LinuxShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        // CoW fault (vfork snapshotting): check BEFORE kernel-mode page fault
        // handler, because kernel-mode (shim) code can touch guest pages that
        // we mprotected for CoW. bit 1 = write access.
        if info.exception == litebox::shim::Exception::PAGE_FAULT
            && (info.error_code & 0x2) == 0x2
            && self
                .task
                .try_handle_cow_fault(info.cr2, ctx, (info.error_code & 1) != 0)
        {
            return ContinueOperation::Resume;
        }
        if info.kernel_mode && info.exception == litebox::shim::Exception::PAGE_FAULT {
            if unsafe {
                self.task
                    .process_state
                    .borrow()
                    .pm
                    .handle_page_fault(info.cr2, info.error_code.into())
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            } else {
                return ContinueOperation::Terminate;
            }
        }
        self.enter_shim(false, ctx, |task, ctx| {
            task.handle_exception_request(info, ctx);
        })
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<FS: ShimFS> LinuxShimEntrypoints<FS> {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::ExecutionContext,
        f: impl FnOnce(&Task<FS>, &mut litebox_common_linux::ExecutionContext),
    ) -> ContinueOperation {
        // Clear syscall context flag. handle_syscall_request sets it back
        // to true; exception/interrupt handlers leave it false so that
        // signal frame construction preserves the real guest R11.
        self.task.in_syscall.set(false);

        if !is_init {
            self.task.enter_from_guest();
        }
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    load_filter: Option<LoadFilter>,
}

impl Default for LinuxShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxShimBuilder {
    /// Returns a new shim builder.
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
            load_filter: None,
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Create a default layered file system with the given in-memory and tar read-only layers.
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    /// Set the load filter, which can augment envp or auxv when starting a new program.
    pub fn set_load_filter(&mut self, callback: LoadFilter) {
        self.load_filter = Some(callback);
    }

    /// Build the shim.
    ///
    /// # Panics
    /// Panics if the platform cannot allocate an address space for the init process.
    pub fn build<FS: ShimFS>(self) -> LinuxShim<FS> {
        use litebox::platform::AddressSpaceProvider;
        use litebox::platform::RawMutex as _;

        let mut net = Network::new(&self.litebox);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);

        // Allocate the init process's address space (slot 0 on userland).
        let init_as_id = self
            .platform
            .create_address_space()
            .expect("init process address space allocation must succeed");
        let as_range = self
            .platform
            .address_space_range(init_as_id)
            .expect("init address space range must be valid");

        let process_state = Arc::new(ProcessState {
            pm: PageManager::new(&self.litebox, as_range),
            address_space_id: init_as_id,
            thread_count: core::sync::atomic::AtomicI32::new(1),
            active_cow: litebox::sync::Mutex::new(None),
            elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            main_bss_start: core::sync::atomic::AtomicUsize::new(0),
            main_bss_end: core::sync::atomic::AtomicUsize::new(0),
            proc_map_paths: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            vfork_parking: Arc::new(VforkParking {
                park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
            }),
        });
        let global = Arc::new(GlobalState {
            platform: self.platform,
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            load_filter: self.load_filter,
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            litebox: self.litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
            cross_process_signals: litebox::sync::Mutex::new(Vec::new()),
            process_thread_handles: litebox::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            transport_interrupt: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
        });
        LinuxShim {
            global,
            process_state,
        }
    }
}

pub struct LinuxShim<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Per-process state for the initial process.
    process_state: Arc<ProcessState>,
}
impl<FS: ShimFS> Clone for LinuxShim<FS> {
    fn clone(&self) -> Self {
        Self {
            global: self.global.clone(),
            process_state: self.process_state.clone(),
        }
    }
}

impl<FS: ShimFS> LinuxShim<FS> {
    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
        initial_cwd: Option<alloc::string::String>,
    ) -> Result<LoadedProgram<FS>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = syscalls::file::FilesState::new(fs);
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);
        let files = Arc::new(files);
        files.initialize_stdio_in_shared_descriptors_table(&self.global);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.global.clone(),
                process_state: self.process_state.clone().into(),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.global.platform),
                process_id: litebox::process::ProcessId::INIT,
                pid,
                ppid,
                tid: pid,
                credentials: syscalls::process::Credentials {
                    uid,
                    euid,
                    gid,
                    egid,
                }
                .into(),
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: Arc::new(match initial_cwd {
                    Some(cwd) => syscalls::file::FsState::with_cwd(cwd),
                    None => syscalls::file::FsState::new(),
                })
                .into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
            },
        };
        let exec_filename = alloc::ffi::CString::new(path).ok();
        let (resolved_path, argv) = entrypoints
            .task
            .resolve_shebang_program(path, argv)
            .map_err(loader::elf::ElfLoaderError::OpenError)?;
        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, resolved_path.as_str())?,
            argv,
            envp,
            exec_filename.as_ref(),
        )?;
        *entrypoints.task.fs.borrow().exe_path.write() =
            entrypoints.task.resolve_exe_path(resolved_path.as_str());
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Returns the page manager for the initial (PID 1) process.
    ///
    /// This is intended for use by runners during early boot (ELF loading,
    /// page-fault handling) before multi-process support is active. Child
    /// processes will have their own `PageManager` inside their
    /// `ProcessState`; callers should not use this accessor for them.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.process_state.pm
    }

    /// Perform queued network interactions with the outside world.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.global.net.lock().perform_platform_interaction()
    }

    /// Establish a TCP connection to the given address.
    ///
    /// Returns a [`transport::ShimTransport`] that can be used as a
    /// byte-stream transport (e.g., for a 9P filesystem client).
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport, Errno> {
        transport::ShimTransport::connect(
            self.global.clone(),
            addr,
            self.global.transport_interrupt.clone(),
            self.process_state.vfork_parking.clone(),
        )
    }

    /// Create a direct message channel for 9P (bypasses smoltcp).
    ///
    /// The actual fd must already be set on the platform via
    /// [`set_raw_message_fd`].  This method only wires up the interrupt /
    /// vfork-parking handles.
    pub fn message_channel(&self) -> transport::ShimMessageChannel {
        transport::ShimMessageChannel::new(
            self.global.transport_interrupt.clone(),
            self.process_state.vfork_parking.clone(),
        )
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.global.litebox
    }
}

pub struct LoadedProgram<FS: ShimFS> {
    pub entrypoints: LinuxShimEntrypoints<FS>,
    pub process: LinuxShimProcess,
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess(Arc<syscalls::process::Process>);

impl LinuxShimProcess {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }
}

/// Create a default layered file system with the given in-memory and tar read-only layers.
fn default_fs(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> LinuxFS {
    let dev_stdio = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}

// Special override so that `GETFL` can return stdio-specific flags
#[derive(Clone, Copy)]
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

/// Status flags for pipes
#[derive(Clone)]
pub(crate) struct PipeStatusFlags(pub litebox::fs::OFlags);

impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    fn initialize_stdio_in_shared_descriptors_table(&self, global: &GlobalState<FS>) {
        use litebox::fs::{Mode, OFlags};
        let stdin = self
            .fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = self
            .fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = self
            .fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let mut dt = global.litebox.descriptor_table_mut();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd) in [(0, stdin), (1, stdout), (2, stderr)] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

impl<FS: ShimFS> Task<FS> {
    /// If the current task's transport told a "deferred park lie" during a 9P
    /// spin loop, this method claims that lie and blocks until the vfork window
    /// closes. Must be called before any guest memory write in `do_syscall`.
    ///
    /// The flow:
    /// 1. Try to claim one lie via CAS on `deferred_lie_count`.
    /// 2. Set per-task `deferred_vfork_park = true`.
    /// 3. Block on `park` futex until it returns to 0.
    /// 4. Decrement `parked_count` (we were counted as parked, now we leave).
    /// 5. Clear `deferred_vfork_park`.
    ///
    fn try_handle_cow_fault(
        &self,
        fault_addr: usize,
        _ctx: &litebox_common_linux::PtRegs,
        page_present: bool,
    ) -> bool {
        #[cfg(all(feature = "trace_syscalls", target_arch = "x86_64"))]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-COW] pid={} tid={} rip={:#x} fault_addr={:#x} page_present={} child={}",
            self.pid,
            self.tid,
            _ctx.rip,
            fault_addr,
            page_present,
            self.fork_context.borrow().is_some(),
        );
        let ps = self.process_state.borrow();
        let cow_lock = ps.active_cow.lock();
        let Some(cow) = cow_lock.as_ref() else {
            return false;
        };

        let page_addr = fault_addr & !(PAGE_SIZE - 1);

        let orig_perms = cow
            .protected_ranges
            .iter()
            .find(|&&(base, len, _)| page_addr >= base && page_addr < base + len)
            .map(|&(_, _, perms)| perms);
        let Some(orig_perms) = orig_perms else {
            return false;
        };

        let is_child = self.fork_context.borrow().is_some();
        let page_range = page_addr..page_addr + PAGE_SIZE;

        if is_child {
            let mut dirty = cow.dirty_pages.lock();
            if dirty.iter().any(|(addr, _)| *addr == page_addr) {
                // SAFETY: restoring the page's original permissions.
                return unsafe {
                    cow_update_permissions(self.global.platform, page_range, orig_perms)
                };
            }
            let buf = if page_present {
                let mut buf = vec![0u8; PAGE_SIZE];
                // SAFETY: page is present (mapped), safe to read.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        page_addr as *const u8,
                        buf.as_mut_ptr(),
                        PAGE_SIZE,
                    );
                }
                buf
            } else {
                vec![0u8; PAGE_SIZE]
            };
            dirty.push((page_addr, buf));
            // SAFETY: restoring the page's original (writable) permissions.
            unsafe { cow_update_permissions(self.global.platform, page_range, orig_perms) }
        } else {
            let mut dirty = cow.dirty_pages.lock();
            if !dirty.iter().any(|(addr, _)| *addr == page_addr) {
                let buf = if page_present {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    // SAFETY: page is present (mapped), safe to read.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            page_addr as *const u8,
                            buf.as_mut_ptr(),
                            PAGE_SIZE,
                        );
                    }
                    buf
                } else {
                    vec![0u8; PAGE_SIZE]
                };
                dirty.push((page_addr, buf));
            }
            drop(dirty);
            // SAFETY: restoring the page's original (writable) permissions.
            unsafe { cow_update_permissions(self.global.platform, page_range, orig_perms) }
        }
    }

    /// Uses CAS (not `fetch_sub`) to avoid underflow races with
    /// `unpark_other_threads` which uses `swap(0)` to settle all remaining
    /// unclaimed lies.
    fn park_if_deferred(&self) {
        use core::sync::atomic::Ordering;
        use litebox::platform::RawMutex as _;

        // The vfork child shares the parent's ProcessState (and therefore
        // VforkParking). It must never claim a lie or block — it's the one
        // thread allowed to run during the vfork window.
        if self.fork_context.borrow().is_some() {
            return;
        }

        let ps = self.process_state.borrow();
        let parking = &ps.vfork_parking;

        // Try to atomically claim one lie. CAS avoids underflow when
        // unpark_other_threads concurrently swaps deferred_lie_count to 0.
        loop {
            let current = parking.deferred_lie_count.load(Ordering::Acquire);
            if current == 0 {
                return; // No outstanding lies (or all settled by unpark).
            }
            if parking
                .deferred_lie_count
                .compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break; // Successfully claimed one lie.
            }
        }

        // We own the lie. Mark ourselves as deferred-parked so that
        // prepare_for_exit can settle the parked_count if we exit early.
        self.deferred_vfork_park.set(true);

        // Block until the forking thread clears the park flag, or the
        // process is exiting (exit_group wakes vfork_park).
        loop {
            let v = parking.park.underlying_atomic().load(Ordering::Acquire);
            if v == 0 || self.is_exiting() {
                break;
            }
            let _ = parking.park.block(v);
        }

        // We're unblocked. Decrement parked_count (we were counted as parked).
        parking
            .parked_count
            .underlying_atomic()
            .fetch_sub(1, Ordering::Release);
        parking.parked_count.wake_all();

        self.deferred_vfork_park.set(false);
    }

    fn close_on_exec(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            if let Ok(flags) = get_file_descriptor_flags(raw_fd, &self.global, &files)
                && flags.contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
            {
                let _ = self.do_close(raw_fd);
            }
        }
    }

    fn close_all_fds(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            let _ = self.do_close(raw_fd);
        }
    }
}

/// A strongly-typed FD.
///
impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        fs: impl FnOnce(&TypedFd<FS>) -> R,
        net: impl FnOnce(&TypedFd<Network<Platform>>) -> R,
        pipes: impl FnOnce(&TypedFd<Pipes<Platform>>) -> R,
        eventfd: impl FnOnce(&TypedFd<syscalls::eventfd::EventfdSubsystem>) -> R,
        epoll: impl FnOnce(&TypedFd<syscalls::epoll::EpollSubsystem<FS>>) -> R,
        unix: impl FnOnce(&TypedFd<syscalls::unix::UnixSocketSubsystem<FS>>) -> R,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(fs(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(net(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(pipes(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(eventfd(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(epoll(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(unix(&fd));
        }
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

impl<FS: ShimFS> Task<FS> {
    /// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
        let mut read_total = 0;
        while read_total < count {
            let to_read = (count - read_total).min(kernel_buf.len());
            match self.sys_pread64(
                fd,
                &mut kernel_buf[..to_read],
                offset + (read_total.reinterpret_as_signed() as i64),
            ) {
                Ok(0) => break, // EOF
                Ok(size) => {
                    self.park_if_deferred();
                    buf.copy_from_slice(read_total, &kernel_buf[..size])
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
    fn task_comm_is(&self, name: &[u8]) -> bool {
        let comm = self.comm.get();
        name.len() < comm.len() && &comm[..name.len()] == name && comm[name.len()] == 0
    }

    fn task_comm_preview(&self) -> alloc::string::String {
        let comm = self.comm.get();
        let end = comm
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(comm.len());
        let mut out = alloc::string::String::new();
        for &byte in &comm[..end] {
            match byte {
                b' '..=b'~' => out.push(byte as char),
                _ => out.push('.'),
            }
        }
        out
    }

    fn address_mapping_summary(&self, addr: usize) -> alloc::string::String {
        let page_addr = addr & !(PAGE_SIZE - 1);
        let ps = self.process_state.borrow();
        let mappings = ps.pm.mappings();

        let containing = mappings
            .iter()
            .find(|(range, _)| range.start <= page_addr && page_addr < range.end);
        let prev = mappings
            .iter()
            .filter(|(range, _)| range.end <= page_addr)
            .max_by_key(|(range, _)| range.end);
        let next = mappings
            .iter()
            .filter(|(range, _)| range.start > page_addr)
            .min_by_key(|(range, _)| range.start);

        let trampoline =
            {
                let cache = ps.elf_patch_cache.lock();
                cache.iter().find_map(|(fd, state)| {
                let tramp_len = if state.pre_patched {
                    state.trampoline_file_size.next_multiple_of(PAGE_SIZE)
                } else if state.trampoline_mapped {
                    state.trampoline_cursor.max(PAGE_SIZE).next_multiple_of(PAGE_SIZE)
                } else {
                    0
                };
                if tramp_len == 0 {
                    return None;
                }
                let tramp_end = state.trampoline_addr.checked_add(tramp_len)?;
                if state.trampoline_addr <= page_addr && page_addr < tramp_end {
                    Some(alloc::format!(
                        " fd={} file={:?} tramp={:#x}..{:#x} mapped={} pre_patched={} cursor={:#x}",
                        fd,
                        state.file_path.as_deref().unwrap_or("<unknown>"),
                        state.trampoline_addr,
                        tramp_end,
                        state.trampoline_mapped,
                        state.pre_patched,
                        state.trampoline_cursor,
                    ))
                } else {
                    None
                }
            })
            };

        let bss_start = ps.main_bss_start.load(Ordering::Relaxed);
        let bss_end = ps.main_bss_end.load(Ordering::Relaxed);

        let mut out = alloc::format!(
            "addr={:#x} page={:#x} partition={:#x}..{:#x}",
            addr,
            page_addr,
            ps.pm.addr_min(),
            ps.pm.addr_max(),
        );

        if let Some((range, flags)) = containing {
            let _ = write!(
                out,
                " mapping={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        } else {
            out.push_str(" mapping=<none>");
        }

        if let Some((range, flags)) = prev {
            let _ = write!(
                out,
                " prev={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        }

        if let Some((range, flags)) = next {
            let _ = write!(
                out,
                " next={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        }

        if bss_start != 0 || bss_end != 0 {
            let _ = write!(out, " main_bss={bss_start:#x}..{bss_end:#x}");
        }

        if let Some(trampoline) = trampoline {
            out.push_str(" trampoline=");
            out.push_str(&trampoline);
        }

        out
    }

    fn shell_write_contains(buf: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && buf.windows(needle.len()).any(|window| window == needle)
    }

    fn should_trace_shell_write(buf: &[u8]) -> bool {
        Self::shell_write_contains(buf, b"___BEGIN___COMMAND_")
            || Self::shell_write_contains(buf, b"COMMAND_DONE_MARKER")
            || Self::shell_write_contains(buf, b"PS1=\"\"")
            || Self::shell_write_contains(buf, b"unset HISTFILE")
            || Self::shell_write_contains(buf, b"git --no-pager")
    }

    fn shell_write_preview(buf: &[u8]) -> alloc::string::String {
        let mut out = alloc::string::String::new();
        for &byte in buf.iter().take(SHELL_WRITE_PREVIEW_LEN) {
            match byte {
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                b' '..=b'~' => out.push(byte as char),
                _ => out.push('.'),
            }
        }
        if buf.len() > SHELL_WRITE_PREVIEW_LEN {
            out.push_str("...");
        }
        out
    }

    fn shell_write_target_preview(&self, fd: i32) -> alloc::string::String {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return alloc::string::String::from("<bad-fd>");
        };

        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |file_fd| {
                    let status = files.fs.fd_file_status(file_fd).ok();
                    match status
                        .and_then(|status| status.node_info.rdev.map(core::num::NonZero::get))
                    {
                        Some(rdev) => {
                            alloc::format!("raw={} fs rdev={}:{}", raw_fd, rdev >> 8, rdev & 0xff)
                        }
                        None => alloc::format!("raw={raw_fd} fs"),
                    }
                },
                |_fd| alloc::format!("raw={raw_fd} net"),
                |_fd| alloc::format!("raw={raw_fd} pipes"),
                |_fd| alloc::format!("raw={raw_fd} eventfd"),
                |_fd| alloc::format!("raw={raw_fd} epoll"),
                |_fd| alloc::format!("raw={raw_fd} unix"),
            )
            .unwrap_or_else(|_| alloc::format!("raw={raw_fd} invalid"))
    }

    #[allow(clippy::similar_names)] // rip/rsp are standard register names
    fn remember_traced_shell_write(
        &self,
        fd: i32,
        via: &'static str,
        total_len: usize,
        target: alloc::string::String,
        preview: alloc::string::String,
        ctx: Option<&litebox_common_linux::PtRegs>,
    ) {
        let (syscall_rip, syscall_rsp) = match ctx {
            Some(ctx) => (ctx.rip, ctx.rsp),
            None => (0, 0),
        };
        self.last_shell_write.replace(Some(RecentShellWrite {
            fd,
            via,
            total_len,
            target,
            preview,
            syscall_rip,
            syscall_rsp,
        }));
    }

    fn maybe_trace_shell_write(
        &self,
        ctx: Option<&litebox_common_linux::PtRegs>,
        fd: i32,
        via: &'static str,
        total_len: usize,
        buf: &[u8],
    ) {
        if self.task_comm_is(b"bash") || !Self::should_trace_shell_write(buf) {
            return;
        }

        let target = self.shell_write_target_preview(fd);
        let preview = Self::shell_write_preview(buf);
        self.remember_traced_shell_write(fd, via, total_len, target.clone(), preview.clone(), ctx);
    }

    fn maybe_trace_shell_writev(
        &self,
        ctx: Option<&litebox_common_linux::PtRegs>,
        fd: i32,
        iovs: &[litebox_common_linux::IoWriteVec<ConstPtr<u8>>],
    ) {
        if self.task_comm_is(b"bash") {
            return;
        }

        let mut total_len = 0usize;
        let mut sampled = alloc::vec::Vec::new();
        for iov in iovs {
            total_len = total_len.saturating_add(iov.iov_len);
            if sampled.len() >= SHELL_WRITE_SCAN_LEN {
                continue;
            }

            let to_copy = iov.iov_len.min(SHELL_WRITE_SCAN_LEN - sampled.len());
            if to_copy == 0 {
                continue;
            }
            let Some(slice) = iov.iov_base.to_owned_slice(to_copy) else {
                return;
            };
            sampled.extend_from_slice(&slice);
        }

        self.maybe_trace_shell_write(ctx, fd, "writev", total_len, &sampled);
    }

    fn record_syscall_entry(&self, ctx: &litebox_common_linux::PtRegs, syscall_number: usize) {
        self.last_syscall.set(Some(RecentSyscall {
            number: syscall_number,
            entry_rip: ctx.rip,
            entry_rsp: ctx.rsp,
            #[cfg(target_arch = "x86")]
            entry_rbp: ctx.ebp as usize,
            #[cfg(target_arch = "x86_64")]
            entry_rbp: ctx.rbp,
            arg0: ctx.syscall_arg(0),
            arg1: ctx.syscall_arg(1),
            arg2: ctx.syscall_arg(2),
        }));
    }

    #[cfg(all(feature = "trace_syscalls", target_arch = "x86_64"))]
    fn trace_stack_words(&self, rsp: usize) -> (Option<usize>, Option<usize>) {
        let stack0 = ConstPtr::<usize>::from_usize(rsp).read_at_offset(0);
        let stack1 =
            ConstPtr::<usize>::from_usize(rsp + core::mem::size_of::<usize>()).read_at_offset(0);
        (stack0, stack1)
    }

    fn log_fatal_signal_recent_activity(&self) {
        if let Some(last_syscall) = self.last_syscall.get() {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-LAST-SYSCALL] pid={} tid={} nr={} entry_rip={:#x} entry_rsp={:#x} arg0={:#x} arg1={:#x} arg2={:#x}",
                self.pid,
                self.tid,
                last_syscall.number,
                last_syscall.entry_rip,
                last_syscall.entry_rsp,
                last_syscall.arg0,
                last_syscall.arg1,
                last_syscall.arg2,
            );
        }

        if let Some(last_write) = self.last_shell_write.borrow().as_ref() {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-LAST-WRITE] pid={} tid={} fd={} target={} via={} len={} syscall_rip={:#x} syscall_rsp={:#x} preview={:?}",
                self.pid,
                self.tid,
                last_write.fd,
                last_write.target.as_str(),
                last_write.via,
                last_write.total_len,
                last_write.syscall_rip,
                last_write.syscall_rsp,
                last_write.preview.as_str(),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn log_fatal_signal_context(
        &self,
        signal: litebox_common_linux::signal::Signal,
        ctx: &litebox_common_linux::PtRegs,
    ) {
        let last_exception = self.signals.last_exception();
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-CONTEXT] pid={} tid={} comm={:?} signal={:?} rip={:#x} rsp={:#x} rax={:#x} orig_rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x} cr2={:#x} error_code={:#x}",
            self.pid,
            self.tid,
            self.task_comm_preview(),
            signal,
            ctx.rip,
            ctx.rsp,
            ctx.rax,
            ctx.orig_rax,
            ctx.rdi,
            ctx.rsi,
            ctx.rdx,
            last_exception.cr2,
            last_exception.error_code,
        );
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=rip summary={}",
            self.pid,
            self.tid,
            self.address_mapping_summary(ctx.rip),
        );
        if last_exception.cr2 != 0 {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=fault summary={}",
                self.pid,
                self.tid,
                self.address_mapping_summary(last_exception.cr2),
            );
        }
        self.log_fatal_signal_recent_activity();
    }

    #[cfg(target_arch = "x86")]
    pub(crate) fn log_fatal_signal_context(
        &self,
        signal: litebox_common_linux::signal::Signal,
        ctx: &litebox_common_linux::PtRegs,
    ) {
        let last_exception = self.signals.last_exception();
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-CONTEXT] pid={} tid={} comm={:?} signal={:?} eip={:#x} esp={:#x} eax={:#x} orig_eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} cr2={:#x} error_code={:#x}",
            self.pid,
            self.tid,
            self.task_comm_preview(),
            signal,
            ctx.eip,
            ctx.esp,
            ctx.eax,
            ctx.orig_eax,
            ctx.ebx,
            ctx.ecx,
            ctx.edx,
            last_exception.cr2,
            last_exception.error_code,
        );
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=eip summary={}",
            self.pid,
            self.tid,
            self.address_mapping_summary(ctx.eip),
        );
        if last_exception.cr2 != 0 {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=fault summary={}",
                self.pid,
                self.tid,
                self.address_mapping_summary(last_exception.cr2),
            );
        }
        self.log_fatal_signal_recent_activity();
    }

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::ExecutionContext) {
        // Mark that ctx.r11 holds the call-site scratch address (not the
        // real guest R11). Cleared by the exception/interrupt entry path.
        self.in_syscall.set(true);

        // Reset restart flag. Individual syscall implementations opt in to
        // restart semantics by setting this flag before returning EINTR
        // (mirroring Linux's ERESTARTSYS).
        self.syscall_restartable.set(false);

        #[cfg(feature = "trace_syscalls")]
        {
            #[cfg(target_arch = "x86_64")]
            {
                let (stack0, stack1) = self.trace_stack_words(ctx.rsp);
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall: pid={} tid={} nr={} rip={:#x} rsp={:#x} stack0={:?} stack1={:?} arg0={:#x} arg1={:#x} arg2={:#x}",
                    self.pid,
                    self.tid,
                    ctx.orig_rax,
                    ctx.rip,
                    ctx.rsp,
                    stack0,
                    stack1,
                    ctx.syscall_arg(0),
                    ctx.syscall_arg(1),
                    ctx.syscall_arg(2),
                );
            }
        }

        let return_value = match self.do_syscall(ctx) {
            Ok(v) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall done: pid={} tid={} ret=Ok({})",
                    self.pid,
                    self.tid,
                    v,
                );
                v
            }
            Err(err) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall done: pid={} tid={} ret=Err({})",
                    self.pid,
                    self.tid,
                    err.as_neg(),
                );
                (err.as_neg() as isize).reinterpret_as_unsigned()
            }
        };

        #[cfg(target_arch = "x86")]
        {
            ctx.eax = return_value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
            #[cfg(feature = "trace_syscalls")]
            let (stack0, stack1) = self.trace_stack_words(ctx.rsp);
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRACE] syscall resume: pid={} tid={} rip={:#x} rcx={:#x} r11={:#x} rsp={:#x} stack0={:?} stack1={:?} rax={:#x}",
                self.pid,
                self.tid,
                ctx.rip,
                ctx.rcx,
                ctx.r11,
                ctx.rsp,
                stack0,
                stack1,
                ctx.rax,
            );
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::ExecutionContext) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86")]
        let syscall_number = ctx.orig_eax;
        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;

        let request = match SyscallRequest::<Platform>::try_from_raw(
            syscall_number,
            ctx,
            log_unsupported_fmt,
        ) {
            Ok(req) => req,
            Err(e) => {
                return Err(e);
            }
        };

        self.record_syscall_entry(ctx, syscall_number);

        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self.sys_wait4(pid, wstatus, options, rusage),
            SyscallRequest::Waitid {
                idtype,
                id,
                infop,
                options,
            } => self.sys_waitid(idtype, id, infop, options),
            SyscallRequest::PidfdOpen { pid, flags } => syscall!(sys_pidfd_open(pid, flags)),
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
                        self.park_if_deferred();
                        buf.copy_from_slice(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                } else {
                    // Read is too large for a single kernel buffer. Try to get
                    // the current file offset so we can use pread in chunks.
                    match self.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset) {
                        Ok(cur_loc) => {
                            // Seekable fd — use pread in chunks, then update offset.
                            self.pread_with_user_buf(
                                fd,
                                buf,
                                count,
                                i64::try_from(cur_loc).unwrap(),
                            )
                            .inspect(|read_total| {
                                self.sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                .expect("lseek failed");
                            })
                        }
                        Err(Errno::ESPIPE) => {
                            // Non-seekable fd (pipe, socket) — read in chunks
                            // using sys_read directly.
                            let mut kernel_buf = vec![0u8; MAX_KERNEL_BUF_SIZE];
                            let mut read_total = 0;
                            while read_total < count {
                                let to_read = (count - read_total).min(kernel_buf.len());
                                match self.sys_read(fd, &mut kernel_buf[..to_read], None) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if buf
                                            .copy_from_slice(read_total, &kernel_buf[..n])
                                            .is_none()
                                        {
                                            return Err(Errno::EFAULT);
                                        }
                                        read_total += n;
                                        if n < to_read {
                                            break; // short read
                                        }
                                    }
                                    Err(e) if read_total > 0 => {
                                        let _ = e;
                                        break; // return partial read
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                            self.park_if_deferred();
                            Ok(read_total)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            SyscallRequest::Write { fd, buf, count } => match buf.to_owned_slice(count) {
                Some(buf) => {
                    let scan_len = buf.len().min(SHELL_WRITE_SCAN_LEN);
                    self.maybe_trace_shell_write(
                        Some(ctx),
                        fd,
                        "write",
                        buf.len(),
                        &buf[..scan_len],
                    );
                    self.sys_write(fd, &buf, None)
                }
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Close { fd } => {
                syscall!(sys_close(fd))
            }
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.truncate())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdir { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_mkdir(path, mode))),
            SyscallRequest::Mkdirat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_mkdirat(dirfd, path, mode))
            }),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
            SyscallRequest::Fchdir { fd } => syscall!(sys_fchdir(fd)),
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
            #[cfg(target_arch = "x86")]
            SyscallRequest::Sigreturn => self.sys_sigreturn(ctx),
            SyscallRequest::Ioctl { fd, arg } => {
                syscall!(sys_ioctl(fd, arg))
            }
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
            } => match buf.to_owned_slice(count) {
                Some(buf) => self.sys_pwrite64(fd, &buf, offset),
                None => Err(Errno::EFAULT),
            },
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
            SyscallRequest::Msync {
                addr,
                length,
                flags,
            } => {
                syscall!(sys_msync(addr, length, flags))
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
            SyscallRequest::Writev { fd, iovec, iovcnt } => {
                if let Some(iovs) = iovec.to_owned_slice(iovcnt) {
                    self.maybe_trace_shell_writev(Some(ctx), fd, &iovs);
                }
                self.sys_writev(fd, iovec, iovcnt)
            }
            SyscallRequest::Access { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_access(path, mode))),
            SyscallRequest::Faccessat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_faccessat(
                    dirfd,
                    path,
                    mode,
                    litebox_common_linux::AtFlags::empty()
                ))
            }),
            SyscallRequest::Faccessat2 {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
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
            } => {
                syscall!(sys_dup(oldfd, newfd, flags))
            }
            SyscallRequest::Socket {
                domain,
                type_and_flags,
                protocol,
            } => syscall!(sys_socket(domain, type_and_flags, protocol)),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Socketcall { call, args } => self.sys_socketcall(call, args),
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
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Shutdown { sockfd, how } => {
                syscall!(sys_shutdown(sockfd, how))
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
            } => self
                .sys_getsockopt(sockfd, level, optname, optval, optlen)
                .to_syscall_result(),
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
            SyscallRequest::Fcntl { fd, arg } => {
                syscall!(sys_fcntl(fd, arg))
            }
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    self.park_if_deferred();
                    buf.copy_from_slice(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => self.sys_epoll_ctl(epfd, op, fd, event).to_syscall_result(),
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
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                    self.park_if_deferred();
                    buf.copy_from_slice(0, &kernel_buf[..size])
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
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                    .and_then(|size| {
                        self.park_if_deferred();
                        buf.copy_from_slice(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
            }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::Getrusage { who, usage } => syscall!(sys_getrusage(who, usage)),
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
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_openat(dirfd, path, flags, mode))
            }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_unlinkat(dirfd, path, flags))
            }),
            SyscallRequest::Renameat2 {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => {
                let old = oldpath.to_cstring().ok_or(Errno::EFAULT)?;
                let new = newpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_renameat2(olddirfd, old, newdirfd, new, flags))
            }
            SyscallRequest::Symlinkat {
                target,
                newdirfd,
                linkpath,
            } => {
                let target = target.to_cstring().ok_or(Errno::EFAULT)?;
                let linkpath = linkpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_symlinkat(target, newdirfd, linkpath))
            }
            SyscallRequest::Linkat {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => {
                let old = oldpath.to_cstring().ok_or(Errno::EFAULT)?;
                let new = newpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_linkat(olddirfd, old, newdirfd, new, flags))
            }
            SyscallRequest::Fchmod { fd: _, mode: _ }
            | SyscallRequest::Fchown
            | SyscallRequest::Fchownat => {
                // Silently succeed; sandbox runs as a single user.
                Ok(0)
            }
            SyscallRequest::Fsync { fd: _ }
            | SyscallRequest::Fdatasync { fd: _ }
            | SyscallRequest::Utimensat => {
                // No-op for in-memory FS; data is always "persisted" and timestamps are ignored.
                Ok(0)
            }
            SyscallRequest::Fadvise64 { fd, .. } => {
                // No-op: file access advice is optional and safe to ignore.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::CopyFileRange {
                fd_in,
                off_in,
                fd_out,
                off_out,
                flags,
                ..
            } => {
                // Linux rejects nonzero flags before any fd checks.
                if flags != 0 {
                    return Err(Errno::EINVAL);
                }
                // Source must be a readable regular file; dest must be writable.
                self.validate_regular_file_fd(fd_in, true, false)?;
                self.validate_regular_file_fd(fd_out, false, true)?;
                // Validate non-null offset pointers are readable.
                if off_in.as_usize() != 0 {
                    off_in.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                if off_out.as_usize() != 0 {
                    off_out.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                Err(Errno::EOPNOTSUPP)
            }
            SyscallRequest::Flock { fd, .. } => {
                // No-op: single-process sandbox has no contention.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::Fallocate { fd, .. } => {
                // No-op: in-memory FS doesn't need preallocation.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::XattrGetPath {
                pathname,
                name,
                follow_symlinks,
            } => {
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                Err(Errno::ENODATA)
            }
            SyscallRequest::XattrSetPath {
                pathname,
                name,
                value,
                size,
                flags,
                follow_symlinks,
            } => {
                // XATTR_CREATE=1, XATTR_REPLACE=2; any other bits → EINVAL.
                if flags & !0x3 != 0 {
                    return Err(Errno::EINVAL);
                }
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                if size > 0 {
                    value.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                Err(Errno::EOPNOTSUPP)
            }
            SyscallRequest::XattrListPath {
                pathname,
                follow_symlinks,
            } => {
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                Ok(0)
            }
            SyscallRequest::XattrGetFd { fd, name } => {
                self.validate_fd(fd)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                Err(Errno::ENODATA)
            }
            SyscallRequest::XattrSetFd {
                fd,
                name,
                value,
                size,
                flags,
            } => {
                if flags & !0x3 != 0 {
                    return Err(Errno::EINVAL);
                }
                self.validate_fd(fd)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                if size > 0 {
                    value.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                Err(Errno::EOPNOTSUPP)
            }
            SyscallRequest::XattrListFd { fd } => {
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::Fchmodat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_fchmodat(dirfd, path, mode))
            }),
            SyscallRequest::Stat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_stat(path).and_then(|stat| {
                        self.park_if_deferred();
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_lstat(path).and_then(|stat| {
                        self.park_if_deferred();
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                self.park_if_deferred();
                buf.write_at_offset(0, stat)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            #[cfg(target_arch = "x86_64")]
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    self.park_if_deferred();
                    buf.write_at_offset(0, stat)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Fstatat64 {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    self.park_if_deferred();
                    buf.write_at_offset(0, stat.into())
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Statx {
                dirfd,
                pathname,
                flags,
                mask,
                buf,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_statx(dirfd, path, flags, mask).and_then(|statx| {
                    self.park_if_deferred();
                    buf.write_at_offset(0, statx)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Statfs { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_statfs(path)
                        .and_then(|s| buf.write_at_offset(0, s).ok_or(Errno::EFAULT).map(|()| 0))
                })
            }
            SyscallRequest::Fstatfs { fd, buf } => self
                .sys_fstatfs(fd)
                .and_then(|s| buf.write_at_offset(0, s).ok_or(Errno::EFAULT).map(|()| 0)),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::InotifyInit1 { flags } => syscall!(sys_inotify_init1(flags)),
            SyscallRequest::InotifyAddWatch { fd, pathname, mask } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_inotify_add_watch(fd, path, mask))
                })
            }
            SyscallRequest::InotifyRmWatch { fd, wd } => syscall!(sys_inotify_rm_watch(fd, wd)),
            SyscallRequest::TimerfdCreate { clockid, flags } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|clockid| syscall!(sys_timerfd_create(clockid, flags)))
            }
            SyscallRequest::TimerfdSettime {
                fd,
                flags,
                new_value,
                old_value,
            } => new_value
                .read_at_offset(0)
                .ok_or(Errno::EFAULT)
                .and_then(|new_value| self.sys_timerfd_settime(fd, flags, new_value, old_value))
                .map(|()| 0),
            SyscallRequest::TimerfdGettime { fd, curr_value } => {
                self.sys_timerfd_gettime(fd).and_then(|curr_value_value| {
                    curr_value
                        .write_at_offset(0, curr_value_value)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT)?;
                    pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT)?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::SetThreadArea { user_desc } => {
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = user_desc;
                    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
                }
                #[cfg(target_arch = "x86")]
                {
                    user_desc
                        .read_at_offset(0)
                        .ok_or(Errno::EFAULT)
                        .and_then(|mut desc| {
                            let idx = desc.entry_number;
                            self.set_thread_area(&mut desc)?;
                            if idx == u32::MAX {
                                // index -1 means the kernel should try to find and
                                // allocate an empty descriptor.
                                // return the allocated entry number
                                user_desc.write_at_offset(0, desc).ok_or(Errno::EFAULT)?;
                            }
                            Ok(0)
                        })
                }
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
                    len.write_at_offset(0, size_of::<litebox_common_linux::RobustListHead>())
                        .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::Rseq {
                rseq,
                rseq_len,
                flags,
                sig,
            } => syscall!(sys_rseq(rseq, rseq_len, flags, sig)),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::ProcessVmReadv {
                pid,
                local_iov,
                liovcnt,
                remote_iov,
                riovcnt,
                flags,
            } => self.sys_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags),
            SyscallRequest::Getpgid { pid } => self.sys_getpgid(pid).map(|v| v as usize),
            SyscallRequest::Setpgid { pid, pgid } => self.sys_setpgid(pid, pgid).map(|()| 0),
            SyscallRequest::Getsid { pid } => self.sys_getsid(pid).map(|v| v as usize),
            SyscallRequest::Setsid => self.sys_setsid().map(|v| v as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Getgroups { size, list } => self.sys_getgroups(size, list),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset(0, sysinfo)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
            SyscallRequest::GetDirent64 { fd, dirp, count } => {
                self.sys_getdirent64(fd, dirp, count)
            }
            SyscallRequest::SchedGetAffinity { pid, len, mask } => {
                const BITS_PER_BYTE: usize = 8;
                let cpuset = self.sys_sched_getaffinity(pid);
                if len * BITS_PER_BYTE < cpuset.len()
                    || len & (core::mem::size_of::<usize>() - 1) != 0
                {
                    Err(Errno::EINVAL)
                } else {
                    let raw_bytes = cpuset.as_bytes();
                    mask.copy_from_slice(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Yield the host thread so other host threads (including the
                // network worker) get a chance to run.
                // SAFETY: sched_yield is side-effect free.
                unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::sched_yield) };
                Ok(0)
            }
            SyscallRequest::SchedGetparam { pid: _, param } => {
                // Write sched_priority = 0 (SCHED_OTHER default).
                param.write_at_offset(0, 0i32).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            SyscallRequest::SchedGetscheduler { pid: _ } => {
                // Return SCHED_OTHER (0) — the default Linux scheduler policy.
                Ok(0)
            }
            SyscallRequest::SchedSetscheduler { pid, policy, param } => {
                self.sys_sched_setscheduler(pid, policy, param)
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
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<FS: ShimFS> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: litebox::LiteBox<Platform>,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem.
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Optional load filter function to modify environment variables during program loading.
    load_filter: Option<LoadFilter>,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<FS>>,
    /// Cross-process signal queue for delivering signals (e.g. SIGCHLD) between
    /// processes. Entries are consumed by the target task during signal processing.
    cross_process_signals: litebox::sync::Mutex<Platform, Vec<CrossProcessSignal>>,
    /// Thread handles for each process's main thread, used to interrupt a
    /// process when delivering a cross-process signal.
    process_thread_handles: litebox::sync::RwLock<
        Platform,
        alloc::collections::BTreeMap<i32, alloc::sync::Arc<syscalls::process::ThreadRemote>>,
    >,
    /// Flag set during vfork to break transport spin-loops and propagate EINTR.
    transport_interrupt: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
}

/// A signal that needs to be delivered to a different process.
struct CrossProcessSignal {
    /// The target process's internal ID (ProcessId).
    target_process_id: u32,
    /// The signal to deliver.
    signal: litebox_common_linux::signal::Signal,
    /// The siginfo data.
    siginfo: litebox_common_linux::signal::Siginfo,
}

/// Per-process state shared by all threads in a process.
///
/// Each process has its own `ProcessState` (wrapped in `Arc` so threads of the
/// same process share it). When multi-process support is complete, forking
/// will create a new `ProcessState` with a per-process `PageManager`
/// initialized to the child's VA sub-range.
struct ProcessState {
    /// The page manager for managing this process's virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The address space ID for this process (VA partition on userland).
    address_space_id: <Platform as litebox::platform::AddressSpaceProvider>::AddressSpaceId,
    /// Number of active threads in this process (including the main thread).
    /// Starts at 1 and is incremented on each `clone(CLONE_THREAD)`.
    thread_count: core::sync::atomic::AtomicI32,
    /// Active CoW state during a vfork window. Set by the forking thread
    /// before spawning the child; cleared after restore. All threads in the
    /// process check this on page faults and mprotect calls.
    active_cow: litebox::sync::Mutex<Platform, Option<Arc<CowState>>>,
    /// Per-fd ELF patching state for the runtime syscall rewriter.
    elf_patch_cache: litebox::sync::Mutex<Platform, syscalls::mm::ElfPatchCache>,
    /// Tracks `MAP_SHARED|PROT_WRITE` file-backed mappings for writeback on
    /// `munmap`. See [`syscalls::mm::SharedFileMapping`] for details.
    shared_file_mappings: litebox::sync::Mutex<Platform, syscalls::mm::SharedFileMappings>,
    /// Page-aligned start of the main binary's `.bss` region (zero-filled
    /// portion of the writable PT_LOAD segment). Set once during ELF loading.
    main_bss_start: core::sync::atomic::AtomicUsize,
    /// Page-aligned end of the main binary's `.bss` region. Set once during
    /// ELF loading.
    main_bss_end: core::sync::atomic::AtomicUsize,
    /// Best-effort pathname annotations for guest `/proc/self/maps`.
    proc_map_paths: litebox::sync::Mutex<
        Platform,
        alloc::vec::Vec<(core::ops::Range<usize>, alloc::string::String)>,
    >,
    /// Shared vfork parking state, wrapped in `Arc` so that both the
    /// syscall-boundary parking path (`park_for_vfork_if_requested`) and the
    /// transport spin-loop parking path (`ShimTransport::park_for_vfork`) can
    /// operate on the same underlying atomics.
    vfork_parking: Arc<VforkParking>,
}

/// Shared vfork parking primitives.
///
/// This struct is `Arc`-shared between the per-process `ProcessState` and the
/// `ShimTransport` so that threads spinning inside the 9P transport can park
/// in-place during vfork without corrupting the TCP byte stream.
pub(crate) struct VforkParking {
    /// Futex for parking threads during vfork. The underlying atomic stores:
    /// 0 = normal operation, 1 = park requested by the forking thread.
    /// Other threads check this in `prepare_to_run_guest` and block until
    /// the value returns to 0.
    pub park: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Counter of threads that have parked. The forking thread waits on this
    /// until the count reaches `thread_count - 1`, confirming all other
    /// threads are safely stopped before modifying page permissions.
    pub parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Number of outstanding "deferred lies" — transport spin loops that have
    /// incremented `parked_count` without actually blocking. Each lie must be
    /// claimed by a task via `park_if_deferred()` before it writes to guest
    /// memory, or at the syscall boundary as a fallback.
    pub deferred_lie_count: core::sync::atomic::AtomicU32,
}

/// One-shot synchronization primitive for vfork parent blocking.
///
/// The parent creates this before spawning the child and calls [`wait`](Self::wait)
/// after the spawn succeeds. The child holds a clone and calls [`signal`](Self::signal)
/// when it execs or exits, unblocking the parent.
struct VforkDone {
    done: core::sync::atomic::AtomicBool,
    /// Waker for the parent thread — calling `wake()` causes the parent's
    /// `wait_until` loop to re-evaluate the done flag.
    parent_waker: litebox::event::wait::Waker<Platform>,
}

impl VforkDone {
    fn new(parent_waker: litebox::event::wait::Waker<Platform>) -> Self {
        Self {
            done: core::sync::atomic::AtomicBool::new(false),
            parent_waker,
        }
    }

    /// Called by the child when it execs or exits.
    fn signal(&self) {
        self.done.store(true, Ordering::Release);
        self.parent_waker.wake();
    }

    /// Returns `true` once the child has called [`signal`](Self::signal).
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Copy-on-write state for vfork memory protection.
///
/// Created by the forking thread and stored in both `ProcessState` (for
/// fault-handler access by any thread) and `ForkContext` (for the child).
///
/// All other parent threads are parked during the vfork window, so FULL CoW
/// (all writable pages) is always used regardless of thread count.
///
/// **Eager vs lazy** (platform decision): Controls how pages are snapshotted.
/// - Eager: all protected pages copied upfront, left writable.
/// - Lazy: protected pages marked read-only, snapshotted on first fault.
struct CowState {
    /// Pages that were CoW-protected (base address, length, original permissions).
    /// For lazy CoW these were made read-only; for eager CoW they were copied.
    protected_ranges: Vec<(
        usize,
        usize,
        litebox::platform::page_mgmt::MemoryRegionPermissions,
    )>,
    /// Per-page snapshots taken on child's first write (lazy) or upfront (eager):
    /// (page-aligned addr, original content).
    dirty_pages: litebox::sync::Mutex<Platform, Vec<(usize, Vec<u8>)>>,
}

/// Call `update_permissions` with the correct `PAGE_SIZE` const generic.
/// Returns `true` on success, `false` on failure (so the fault is not
/// considered handled and will escalate to process termination).
///
/// # Safety
///
/// The caller must ensure the memory range is valid and the permissions
/// are appropriate for the mapped pages.
unsafe fn cow_update_permissions(
    platform: &Platform,
    range: core::ops::Range<usize>,
    perms: litebox::platform::page_mgmt::MemoryRegionPermissions,
) -> bool {
    use litebox::platform::PageManagementProvider;
    unsafe {
        <Platform as PageManagementProvider<PAGE_SIZE>>::update_permissions(platform, range, perms)
    }
    .is_ok()
}

/// Context for a vfork child process.
///
/// Stored in the child's `Task` after `do_fork`. The child temporarily uses
/// the **parent's** `ProcessState` (vfork sharing). When the child calls
/// `execve()`, it creates its own `ProcessState` using the partition range
/// from `address_space_id`. When it calls `_exit()`, the partition is released.
struct ForkContext {
    /// The child's own address space ID (VA partition on userland).
    address_space_id: <Platform as litebox::platform::AddressSpaceProvider>::AddressSpaceId,
    /// Signals the parent to resume after the vfork child execs or exits.
    vfork_done: Arc<VforkDone>,
}

const SHELL_WRITE_SCAN_LEN: usize = 1024;
const SHELL_WRITE_PREVIEW_LEN: usize = 192;

#[derive(Clone)]
struct RecentShellWrite {
    fd: i32,
    via: &'static str,
    total_len: usize,
    target: alloc::string::String,
    preview: alloc::string::String,
    syscall_rip: usize,
    syscall_rsp: usize,
}

#[derive(Clone, Copy)]
struct RecentSyscall {
    number: usize,
    entry_rip: usize,
    entry_rsp: usize,
    #[allow(dead_code)]
    entry_rbp: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
}

struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Per-process state shared across threads in the same process.
    /// `RefCell` to support swapping to the child's own state on `execve`
    /// after a vfork.
    process_state: RefCell<Arc<ProcessState>>,
    wait_state: wait::WaitState,
    thread: syscalls::process::ThreadState,
    /// The process identity from the core ProcessRegistry.
    process_id: litebox::process::ProcessId,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials.
    credentials: Arc<syscalls::process::Credentials>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState<FS>>>,
    /// Signal state
    signals: syscalls::signal::SignalState,
    /// Fork context for vfork children. `None` for the initial process and
    /// for threads. Set when `do_fork` creates a child process. `RefCell`
    /// because `sys_execve` consumes it via `take()` through `&self`.
    fork_context: RefCell<Option<ForkContext>>,
    /// Last traced shell write performed by this task, if any.
    last_shell_write: RefCell<Option<RecentShellWrite>>,
    /// Last syscall entry observed for this task.
    last_syscall: Cell<Option<RecentSyscall>>,
    /// Set when a blocking syscall returns `EINTR` due to a pending signal.
    /// Cleared after `process_signals` handles restart or delivers a handler.
    /// Mirrors the Linux kernel's `-ERESTARTSYS` internal error code.
    syscall_restartable: Cell<bool>,
    /// True when the current entry came through `handle_syscall_request`
    /// (ctx.r11 holds the call-site scratch address, not the real guest R11).
    /// False when the entry came from an async interrupt/exception (ctx.r11
    /// is the real architectural R11). Used by signal frame construction to
    /// decide whether to expose RFLAGS or the actual r11 in mcontext.
    in_syscall: Cell<bool>,
    /// Set by `park_if_deferred()` when this task has claimed a deferred lie
    /// from the transport and is now blocking at a park checkpoint. Cleared
    /// when the task resumes after vfork completes. `Cell` because the task
    /// owns this flag exclusively (no cross-thread sharing).
    deferred_vfork_park: Cell<bool>,
}

impl<FS: ShimFS> Drop for Task<FS> {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

pub type LoadFilter = fn(envp: &mut alloc::vec::Vec<alloc::ffi::CString>);

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<FS: ShimFS> LinuxShim<FS> {
        /// Create a new task with default values for testing.
        pub(crate) fn new_test_task(self, fs: alloc::sync::Arc<FS>) -> Task<FS> {
            let pid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(fs));
            files.initialize_stdio_in_shared_descriptors_table(&self.global);
            Task {
                wait_state: wait::WaitState::new(self.global.platform),
                thread: syscalls::process::ThreadState::new_process(pid),
                process_id: litebox::process::ProcessId::INIT,
                pid,
                ppid: 0,
                tid: pid,
                credentials: Arc::new(syscalls::process::Credentials {
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                }),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
                process_state: self.process_state.into(),
                global: self.global,
            }
        }
    }

    impl<FS: ShimFS> Task<FS> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let tid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                process_state: self.process_state.clone(),
                thread: self.thread.new_thread(tid)?,
                process_id: self.process_id,
                pid: self.pid,
                ppid: self.ppid,
                tid,
                credentials: self.credentials.clone(),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<FS>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
