// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin BSD and Mach shim for AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. A runtime provider may
//! supply dyld and a guest-private dyld shared-cache instance for dynamically
//! linked programs, which then run their own libSystem against this shim.
//!
//! Mach IPC is emulated per guest: the task has its own port name space,
//! messages between its ports queue in the shim, and its kernel objects
//! (task, thread, host, clocks, semaphores) are served by a typed MIG server.
//! No host Mach right is ever exposed to or used on behalf of the guest.
//! Unsupported calls return XNU's error for them, logged once.
//!
//! Each guest thread runs on its own host thread with its own Mach thread
//! port; the shim emulates XNU's thread lifecycle, ulock and yield calls on
//! guest-private wait queues. Networking, workqueue (GCD) threads and signal
//! delivery are unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{collections::BTreeMap, ffi::CString, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox,
    platform::PageManagementProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::{PtRegs, mm::VmemManager, vmem::VmFlags};
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, SIGINT, SIGSEGV, STACK_ALIGNMENT, SyscallRequest, TaskParams,
    errno::Errno, loader::MachoLoaderError,
};
use litebox_platform::sync::RawMutex as _;
use litebox_platform::time::TimeProvider;

use syscalls::misc::{HOST_SYSCTL_NAMES, HostSysctl};

const fn aarch64_rewrite_options() -> litebox_syscall_rewriter::RewriteOptions {
    #[cfg(target_os = "macos")]
    let host = litebox_trampoline::TargetHost::MacOs;
    #[cfg(not(target_os = "macos"))]
    let host = litebox_trampoline::TargetHost::Linux;
    litebox_syscall_rewriter::RewriteOptions::new(host, false)
}

mod loader;
pub mod shared_cache;
pub mod syscalls;
#[cfg(all(test, target_os = "macos"))]
mod tests;
mod thread;
mod wait;

/// Platform capabilities required for descriptor, page, gate, and wait management.
pub trait ShimPlatform:
    PageManagementProvider<PAGE_SIZE, Reservations = <Self as ShimPlatform>::VmemReservations>
    + RawSyncPrimitivesProvider
    + TimeProvider
    + litebox::platform::SignalProvider
    + litebox::platform::SystemInfoProvider
    + litebox::platform::ArchSpecificProvider
    + litebox::platform::ThreadProvider<ExecutionContext = PtRegs>
    + litebox::platform::GuestVectorStateProvider<
        GuestVectorState = litebox_common_linux::GuestVectorState,
    >
    + litebox_common_macos::MachClock
    + 'static
    + Sized
{
    type VmemReservations: litebox_common_linux::vmem::LinuxReservationStore<Self, PAGE_SIZE>;
}
impl<P> ShimPlatform for P
where
    P: PageManagementProvider<PAGE_SIZE>
        + RawSyncPrimitivesProvider
        + TimeProvider
        + litebox::platform::SignalProvider
        + litebox::platform::SystemInfoProvider
        + litebox::platform::ArchSpecificProvider
        + litebox::platform::ThreadProvider<ExecutionContext = PtRegs>
        + litebox::platform::GuestVectorStateProvider<
            GuestVectorState = litebox_common_linux::GuestVectorState,
        >
        + litebox_common_macos::MachClock
        + 'static
        + Sized,
    P::Reservations: litebox_common_linux::vmem::LinuxReservationStore<P, PAGE_SIZE>,
{
    type VmemReservations = P::Reservations;
}

pub struct MacosShimBuilder<P: ShimPlatform> {
    platform: &'static P,
    litebox: Arc<LiteBox<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    host_sysctls: Vec<HostSysctl>,
}

impl<P: ShimPlatform> MacosShimBuilder<P> {
    pub fn new(platform: &'static P) -> Self {
        Self::new_with_litebox(platform, LiteBox::new(platform))
    }

    /// Build a shim around an existing LiteBox instance. `platform` must be
    /// the same platform used to construct `litebox`.
    pub fn new_with_litebox(platform: &'static P, litebox: LiteBox<P>) -> Self {
        let litebox = Arc::new(litebox);
        Self {
            platform,
            files: Arc::new(syscalls::file::FilesState::new(Arc::clone(&litebox))),
            litebox,
            host_sysctls: Vec::new(),
        }
    }

    /// Mirror host sysctl nodes read-only into the guest. Each name must be
    /// in [`HOST_SYSCTL_NAMES`] and appear once.
    pub fn host_sysctls(mut self, sysctls: Vec<HostSysctl>) -> Result<Self, Errno> {
        for (index, sysctl) in sysctls.iter().enumerate() {
            if !HOST_SYSCTL_NAMES.contains(&sysctl.name)
                || !(2..=12).contains(&sysctl.mib.len())
                || sysctls[..index]
                    .iter()
                    .any(|other| other.name == sysctl.name)
            {
                return Err(Errno::EINVAL);
            }
        }
        self.host_sysctls = sysctls;
        Ok(self)
    }

    pub fn litebox(&self) -> &LiteBox<P> {
        &self.litebox
    }

    /// Transfer a LiteBox file into the guest's descriptor namespace.
    /// `file` must belong to this builder's LiteBox instance.
    pub fn inherit_file(&mut self, file: litebox::fs::File<P>) -> Result<u32, Errno> {
        self.files.insert_file(file)
    }

    pub fn build(self) -> MacosShim<P> {
        MacosShim {
            global: Arc::new(GlobalState {
                platform: self.platform,
                mm: VmemManager::new(self.platform),
                litebox: self.litebox,
                macho_mappings: Mutex::new(BTreeMap::new()),
                macho_trampolines: Mutex::new(BTreeMap::new()),
                shared_cache_base: AtomicUsize::new(0),
                shared_cache_reservation: Mutex::new(None),
                shared_cache: Mutex::new(None),
                host_sysctls: self.host_sysctls,
                ipc: Mutex::new(syscalls::mach_ipc::IpcSpace::default()),
                restartable_ranges: Mutex::new(None),
                reported_unsupported: Mutex::new(alloc::collections::BTreeSet::new()),
                reported_syscalls: Mutex::new(ReportedSyscalls::default()),
                next_thread_id: AtomicU64::new(FIRST_THREAD_ID),
                main_stack_top: AtomicUsize::new(0),
                pthread_registration: Mutex::new(None),
                ulocks: Mutex::new(syscalls::ulock::UlockTable::default()),
            }),
            files: self.files,
        }
    }
}

/// One guest address space. Loading consumes the shim; the entrypoints retain
/// its shared global state for the guest's lifetime.
pub struct MacosShim<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
}

impl<P: ShimPlatform> MacosShim<P> {
    /// Load a self-contained static executable from the guest filesystem.
    /// Dynamic executables require [`Self::load_program_with_dyld`].
    ///
    /// `path` also supplies the startup apple vector's `executable_path` entry,
    /// independently of `argv[0]`. Requires read access; execute permissions are not checked.
    pub fn load_program(
        self,
        params: TaskParams,
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        self.load(params, path, None, None, argv, envp)
    }

    /// Load a dynamically linked executable with a runtime-provided, unrewritten
    /// dyld image. dyld is rewritten like every other guest image.
    ///
    /// Without `image`, the executable is read from `path` in the guest
    /// filesystem. The provider must install the shared cache dyld uses before
    /// entering guest execution.
    pub fn load_program_with_dyld(
        self,
        params: TaskParams,
        path: &str,
        image: Option<&[u8]>,
        dyld: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        self.load(params, path, image, Some(dyld), argv, envp)
    }

    /// Load a self-contained static executable snapshot without file I/O.
    ///
    /// `path` supplies only the startup apple vector's `executable_path` entry;
    /// it is not opened and need not match `argv[0]`.
    pub fn load_program_from_bytes(
        self,
        params: TaskParams,
        path: &str,
        image: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        self.load(params, path, Some(image), None, argv, envp)
    }

    fn load(
        self,
        params: TaskParams,
        path: &str,
        image: Option<&[u8]>,
        dyld: Option<&[u8]>,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        let process = Process::new();
        let task = Task::new_main(self.global, self.files, params, process.clone());
        let initial_ctx = loader::load(&task, path, image, dyld, &argv, &envp)?;
        Ok(LoadedProgram {
            entrypoints: MacosShimEntrypoints {
                task,
                _not_send: core::marker::PhantomData,
            },
            process,
            initial_ctx,
        })
    }
}

/// A guest process: its exit status and its threads. It can outlive the
/// task without retaining its mappings or FDs.
pub struct Process<P: ShimPlatform>(Arc<ProcessState<P>>);

impl<P: ShimPlatform> Clone for Process<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<P: ShimPlatform> Process<P> {
    fn new() -> Self {
        Self(Arc::new(ProcessState {
            exit_status: AtomicI32::new(-1),
            live_threads: <P::RawMutex as litebox_platform::sync::RawMutex>::INIT,
            threads: Mutex::new(BTreeMap::new()),
        }))
    }

    /// The recorded exit status, once any thread has ended the process.
    pub fn exit_status(&self) -> Option<i32> {
        let status = self.0.exit_status.load(Ordering::Acquire);
        (status >= 0).then_some(status)
    }

    /// Block until every guest thread has ended and return the exit status,
    /// which the last thread records if no thread exited.
    pub fn wait_for_exit(&self) -> i32 {
        let live = &self.0.live_threads;
        loop {
            let count = live.underlying_atomic().load(Ordering::Acquire);
            if count == 0 {
                break;
            }
            let _ = live.block(count);
        }
        self.0.exit_status.load(Ordering::Acquire)
    }

    /// Record `status` unless the process already exited (`exit1`: the first
    /// exit wins). Returns whether this call recorded it.
    fn record_exit(&self, status: i32) -> bool {
        self.0
            .exit_status
            .compare_exchange(-1, status, Ordering::SeqCst, Ordering::Acquire)
            .is_ok()
    }

    /// Whether an exit is recorded, read after the caller's SeqCst store of
    /// its running state. With the SeqCst fence in `Task::exit_process`
    /// between recording and reading other threads' states, either this read
    /// sees the exit or the exiting thread sees the caller running guest code
    /// and interrupts it.
    fn exit_recorded_seqcst(&self) -> bool {
        self.0.exit_status.load(Ordering::SeqCst) >= 0
    }
}

struct ProcessState<P: ShimPlatform> {
    /// -1 until the process exits.
    exit_status: AtomicI32,
    /// Guest threads whose `Task` exists; changed only under `threads`.
    live_threads: P::RawMutex,
    /// Every guest thread that has not terminated, by thread ID.
    threads: Mutex<P, BTreeMap<ThreadId, Arc<GuestThread<P>>>>,
}

pub struct LoadedProgram<P: ShimPlatform> {
    pub entrypoints: MacosShimEntrypoints<P>,
    pub process: Process<P>,
    pub initial_ctx: PtRegs,
}

pub struct MacosShimEntrypoints<P: ShimPlatform> {
    task: Task<P>,
    // A bound task cannot be moved to another host thread.
    _not_send: core::marker::PhantomData<*const ()>,
}

struct GlobalState<P: ShimPlatform> {
    platform: &'static P,
    litebox: Arc<LiteBox<P>>,
    mm: VmemManager<P, PAGE_SIZE>,
    macho_mappings: Mutex<P, BTreeMap<usize, syscalls::mm::MachoMapping>>,
    macho_trampolines: Mutex<P, BTreeMap<usize, syscalls::mm::MachoRuntimeTrampoline>>,
    /// Base of the installed shared cache for `shared_region_check_np`; 0 before installation.
    shared_cache_base: AtomicUsize,
    shared_cache_reservation: Mutex<P, Option<core::ops::Range<usize>>>,
    shared_cache: Mutex<P, Option<shared_cache::SharedCacheState>>,
    host_sysctls: Vec<HostSysctl>,
    ipc: Mutex<P, syscalls::mach_ipc::IpcSpace>,
    /// `task_restartable_ranges_register` state.
    restartable_ranges: Mutex<P, Option<Vec<syscalls::mig::RestartableRange>>>,
    reported_unsupported: Mutex<P, alloc::collections::BTreeSet<&'static str>>,
    reported_syscalls: Mutex<P, ReportedSyscalls>,
    next_thread_id: AtomicU64,
    /// Top of the main thread's stack (`proc_get_user_stack`), set by the loader.
    main_stack_top: AtomicUsize,
    /// `bsdthread_register` state; set once per process.
    pthread_registration: Mutex<P, Option<syscalls::thread::PthreadRegistration>>,
    ulocks: Mutex<P, syscalls::ulock::UlockTable<P>>,
}

/// `thread_tid`: a system-wide unique 64-bit thread ID.
pub(crate) type ThreadId = u64;

/// XNU's thread IDs are large; the first guest thread's mirrors that.
const FIRST_THREAD_ID: ThreadId = 1 << 32;

/// Fixed-size record of the unsupported syscall selectors already logged, so a
/// guest cycling through selectors cannot grow host memory: one bit per BSD
/// number and Mach trap in XNU's tables, and one flag shared by all others.
#[derive(Default)]
struct ReportedSyscalls {
    bsd: [u64; Self::BSD_SELECTORS / 64],
    mach: [u64; Self::MACH_TRAPS / 64],
    other: bool,
}

impl ReportedSyscalls {
    /// Covers XNU's `nsysent` (about 560) with room to grow.
    const BSD_SELECTORS: usize = 1024;
    /// `MACH_TRAP_TABLE_COUNT`.
    const MACH_TRAPS: usize = 128;

    /// Records `selector` (x16) and returns whether it was not yet reported.
    /// Selectors outside both tables share one report.
    fn first_report(&mut self, selector: usize) -> bool {
        let low = selector & 0xffff_ffff;
        let (bits, index) = if litebox_common_macos::syscall::is_mach_trap_selector(selector) {
            (&mut self.mach[..], low.wrapping_neg() & 0xffff_ffff)
        } else {
            (&mut self.bsd[..], low)
        };
        let Some(word) = bits.get_mut(index / 64) else {
            return !core::mem::replace(&mut self.other, true);
        };
        let bit = 1u64 << (index % 64);
        let first = *word & bit == 0;
        *word |= bit;
        first
    }
}

impl<P: ShimPlatform> Drop for GlobalState<P> {
    fn drop(&mut self) {
        // SAFETY: the last task/loader owner is gone, so none of these mappings
        // are executing or borrowed. Vmem's platform reservations have empty
        // flags; our anonymous mappings have VM_MAY_ACCESS_FLAGS, even guards.
        for (range, flags) in self.mm.mappings() {
            if !flags.intersects(VmFlags::VM_MAY_ACCESS_FLAGS) {
                continue;
            }
            let ptr = litebox_common_macos::user_pointers::UserPtrMut::from_usize(range.start)
                .to_platform_ptr::<P>();
            // Best effort during Drop, including unwinding: a failed unmap
            // must not cause a second panic or prevent releasing later ranges.
            if let Err(error) = unsafe { self.mm.remove_pages(ptr, range.len()) } {
                litebox_util_log::warn!(error:? = error; "failed to release macOS guest mapping");
            }
        }
    }
}

/// A guest thread's state that other threads reach: XNU's `thread` and
/// `uthread` fields the shim emulates.
struct GuestThread<P: ShimPlatform> {
    id: ThreadId,
    /// The thread's control port; it dies when the thread terminates.
    port: syscalls::mach_ipc::PortId,
    /// The thread that started the process (`THREAD_TAG_MAINTHREAD`).
    is_main: bool,
    /// `uu_sigmask`; guest signals are never delivered.
    signal_mask: AtomicU32,
    /// `UT_NO_SIGMASK`, set by `__disable_threadsignal`.
    no_signals: AtomicBool,
    /// `UT_CANCELDISABLE`, set by `__disable_threadsignal`: the thread takes
    /// no further cancellation.
    cancel_disabled: AtomicBool,
    /// Scheduling policy set by the thread itself or, through `thread_policy`,
    /// by another thread (XNU's thread mutex).
    policy: Mutex<P, syscalls::thread::ThreadPolicy>,
    /// `machine.cthread_self`: the TSD base.
    tsd_base: AtomicUsize,
    /// Interrupts the thread's waits or guest execution; set when the thread
    /// first enters the shim.
    interrupt: Mutex<P, Option<litebox::event::wait::ThreadHandle<P>>>,
}

/// A guest thread's own state, used only by that thread.
struct ThreadState<P: ShimPlatform> {
    guest: Arc<GuestThread<P>>,
    wait_state: litebox::event::wait::WaitState<P>,
    /// The TSD base of a thread created by `bsdthread_create`, installed when
    /// the thread first enters the shim.
    start: core::cell::Cell<Option<usize>>,
    /// Set by `bsdthread_terminate`: the thread never returns to the guest.
    terminated: core::cell::Cell<bool>,
    /// `bsdthread_terminate`'s user-join ulock address and the thread's port
    /// name, written and woken once the thread has terminated.
    user_join: core::cell::Cell<Option<(usize, u32)>>,
}

struct Task<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    params: TaskParams,
    process: Process<P>,
    thread: ThreadState<P>,
}

impl<P: ShimPlatform> Task<P> {
    /// Returns a wait context that process exit and a host signal, such as
    /// Ctrl-C, interrupt.
    fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, P> {
        self.thread
            .wait_state
            .context()
            .with_check_for_interrupt(self)
    }

    /// Whether a host signal arrived; it ends the guest like `SIGINT` (guest
    /// signal delivery is unsupported).
    fn take_host_signal(&self) -> bool {
        let mut pending = false;
        self.global
            .platform
            .take_pending_signals(|_| pending = true);
        if pending {
            self.exit_process(128 + SIGINT);
        }
        pending
    }
}

impl<P: ShimPlatform> litebox::event::wait::CheckForInterrupt for Task<P> {
    fn check_for_interrupt(&self) -> bool {
        self.take_host_signal() || self.process.exit_status().is_some()
    }
}

const MAX_KERNEL_BUF_SIZE: usize = 64 * 1024;

// Normalize typed syscall handler results for register write-back.
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

impl<P: ShimPlatform> Task<P> {
    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        // BSD calls report errno through carry. Mach traps update x0 without
        // changing condition flags.
        const CARRY: u64 = 1 << 29;
        if litebox_common_macos::syscall::is_platform_syscall_selector(ctx.regs[16]) {
            self.handle_platform_syscall(ctx);
            return;
        }
        let is_mach = litebox_common_macos::syscall::is_mach_trap_selector(ctx.regs[16]);
        let result = self.do_syscall(ctx);
        litebox_util_log::trace!(
            number:? = ctx.regs[16].cast_signed(),
            args:? = format_args!("{:x?}", &ctx.regs[..6]),
            pc:? = format_args!("{:#x}", ctx.pc),
            lr:? = format_args!("{:#x}", ctx.regs[30]),
            result:? = result;
            "Darwin syscall"
        );
        match result {
            Ok(value) => {
                ctx.regs[0] = value;
                if !is_mach {
                    ctx.pstate &= !CARRY;
                }
            }
            Err(error) => {
                if is_mach {
                    // A trap XNU has but the shim does not implement reports
                    // KERN_NOT_SUPPORTED; malformed arguments are invalid.
                    ctx.regs[0] = if error == Errno::ENOSYS {
                        KernReturn::NOT_SUPPORTED
                    } else {
                        KernReturn::INVALID_ARGUMENT
                    }
                    .into();
                } else {
                    ctx.regs[0] = error.raw();
                    ctx.pstate |= CARRY;
                }
            }
        }
    }

    /// XNU's AArch64 `platform_syscall`: only the get path writes x0, and no
    /// path changes the condition flags.
    fn handle_platform_syscall(&self, ctx: &mut PtRegs) {
        use litebox::platform::ArchSpecificRegister;
        use litebox_common_macos::syscall::PlatformSyscall;

        let platform = self.global.platform;
        match PlatformSyscall::from_args(ctx.regs[0], ctx.regs[3]) {
            PlatformSyscall::SetCthreadSelf { tsd_base } => {
                // machine_thread_set_tsd_base: addresses beyond the map become 0.
                let tsd_base = if tsd_base > P::TASK_ADDR_MAX {
                    0
                } else {
                    tsd_base
                };
                if let Err(error) =
                    platform.set_arch_specific_register(&ArchSpecificRegister::TpidrroEl0, tsd_base)
                {
                    litebox_util_log::error!(error:?; "cannot set the guest TSD base");
                    self.exit_process(128 + SIGSEGV);
                } else {
                    self.thread
                        .guest
                        .tsd_base
                        .store(tsd_base, Ordering::Relaxed);
                }
            }
            PlatformSyscall::GetCthreadSelf => {
                match platform.get_arch_specific_register(&ArchSpecificRegister::TpidrroEl0) {
                    Ok(tsd_base) => ctx.regs[0] = tsd_base,
                    Err(error) => {
                        litebox_util_log::error!(error:?; "cannot read the guest TSD base");
                        self.exit_process(128 + SIGSEGV);
                    }
                }
            }
            PlatformSyscall::Ignored { code } => {
                litebox_util_log::debug!(code:?; "ignored Darwin platform syscall");
            }
        }
    }

    fn do_syscall(&self, ctx: &PtRegs) -> Result<usize, Errno> {
        let request = SyscallRequest::try_from_raw(ctx.regs[16], ctx, |args| {
            if self
                .global
                .reported_syscalls
                .lock()
                .first_report(ctx.regs[16])
            {
                litebox_util_log::warn!(feature:% = args; "unsupported");
            }
        })?;
        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::Read { fd, buf, count } => {
                let fd = self.files.typed_fd(fd)?;
                let length = Self::io_length(count)?;
                let mut bytes = vec![0; length];
                let size = self.do_read(&fd, &mut bytes, None)?;
                if size != 0 {
                    buf.copy_from_slice::<P>(0, &bytes[..size])
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(size)
            }
            SyscallRequest::Write { fd, buf, count } => {
                let fd = self.files.typed_fd(fd)?;
                let length = Self::io_length(count)?;
                if length == 0 {
                    return self.do_write(&fd, &[]);
                }
                let bytes = buf.to_owned_slice::<P>(length).ok_or(Errno::EFAULT)?;
                self.do_write(&fd, &bytes)
            }
            SyscallRequest::Open { path, flags, mode } => {
                let path = Self::read_path(path)?;
                self.sys_open(&path, flags, mode).to_syscall_result()
            }
            SyscallRequest::Openat {
                dirfd,
                path,
                flags,
                mode,
            } => {
                let path = Self::read_path(path)?;
                self.sys_openat(dirfd, &path, flags, mode)
                    .to_syscall_result()
            }
            SyscallRequest::Ioctl { fd, command, data } => {
                self.sys_ioctl(fd, command, data).to_syscall_result()
            }
            SyscallRequest::Close { fd } => self.sys_close(fd).to_syscall_result(),
            SyscallRequest::Dup { fd } => self.sys_dup(fd).to_syscall_result(),
            SyscallRequest::Dup2 { old, new } => self.sys_dup2(old, new).to_syscall_result(),
            SyscallRequest::Fcntl {
                fd,
                command,
                argument,
            } => self.sys_fcntl(fd, command, argument),
            SyscallRequest::Sysctl {
                name,
                name_length,
                old_value,
                old_length,
                new_value,
                new_length,
            } => self.sys_sysctl(
                name,
                name_length,
                old_value,
                old_length,
                new_value,
                new_length,
            ),
            SyscallRequest::Fsctl {
                path,
                command,
                data,
                options: _,
            } => {
                let path = Self::read_path(path)?;
                self.sys_fsctl(&path, command, data).to_syscall_result()
            }
            SyscallRequest::Mmap {
                address,
                length,
                protection,
                flags,
                fd,
                offset,
            } => self
                .sys_mmap(address, length, protection, flags, fd, offset)
                .to_syscall_result(),
            SyscallRequest::Munmap { address, length } => {
                self.sys_munmap(address, length).to_syscall_result()
            }
            SyscallRequest::Mprotect {
                address,
                length,
                protection,
            } => self
                .sys_mprotect(address, length, protection)
                .to_syscall_result(),
            SyscallRequest::Access { path, mode } => {
                let path = Self::read_path(path)?;
                self.sys_access(&path, mode).to_syscall_result()
            }
            SyscallRequest::CrossarchTrap { name } => {
                Self::sys_crossarch_trap(name).to_syscall_result()
            }
            SyscallRequest::Sigprocmask {
                how,
                mask,
                old_mask,
            } => self
                .sys_sigprocmask(how, mask, old_mask)
                .to_syscall_result(),
            SyscallRequest::PthreadSigmask {
                how,
                mask,
                old_mask,
            } => self
                .sys_pthread_sigmask(how, mask, old_mask)
                .to_syscall_result(),
            SyscallRequest::PthreadKill { thread, signal } => {
                self.sys_pthread_kill(thread, signal).to_syscall_result()
            }
            SyscallRequest::DisableThreadsignal => {
                self.sys_disable_threadsignal();
                Ok(0)
            }
            SyscallRequest::BsdthreadRegister {
                threadstart,
                wqthread,
                pthread_size,
                data,
                data_size,
                dispatch_queue_offset,
            } => self
                .sys_bsdthread_register(
                    threadstart,
                    wqthread,
                    pthread_size,
                    data,
                    data_size,
                    dispatch_queue_offset,
                )
                .to_syscall_result(),
            SyscallRequest::BsdthreadCreate {
                function,
                argument,
                stack,
                pthread,
                flags,
            } => self.sys_bsdthread_create(function, argument, stack, pthread, flags),
            SyscallRequest::BsdthreadTerminate {
                stack,
                size,
                port,
                semaphore_or_ulock,
            } => {
                self.sys_bsdthread_terminate(stack, size, port, semaphore_or_ulock);
                Ok(0)
            }
            SyscallRequest::BsdthreadCtl { command, arguments } => {
                self.sys_bsdthread_ctl(command, arguments)
            }
            SyscallRequest::UlockWait {
                operation,
                address,
                value,
                timeout,
            } => self.sys_ulock_wait(operation, address, value, timeout),
            SyscallRequest::UlockWake {
                operation,
                address,
                wake_value,
            } => self.sys_ulock_wake(operation, address, wake_value),
            SyscallRequest::Csops {
                pid,
                operation,
                buffer,
                size,
                audit_token,
            } => self
                .sys_csops(pid, operation, buffer, size, audit_token)
                .to_syscall_result(),
            SyscallRequest::Issetugid => Ok(Self::sys_issetugid()),
            SyscallRequest::Stat64 {
                path,
                buffer,
                follow: _,
            } => {
                let path = Self::read_path(path)?;
                self.sys_stat64(&path, buffer).to_syscall_result()
            }
            SyscallRequest::Fstat64 { fd, buffer } => {
                self.sys_fstat64(fd, buffer).to_syscall_result()
            }
            SyscallRequest::MacSyscall {
                policy,
                call,
                argument: _,
            } => Self::sys_mac_syscall(policy, call).to_syscall_result(),
            SyscallRequest::Csrctl {
                operation,
                buffer,
                size,
            } => Self::sys_csrctl(operation, buffer, size).to_syscall_result(),
            SyscallRequest::AbortWithPayload {
                reason_namespace,
                reason_code,
                reason_string,
            } => {
                self.sys_abort_with_payload(reason_namespace, reason_code, reason_string);
                Ok(0)
            }
            SyscallRequest::TerminateWithPayload {
                pid,
                reason_namespace,
                reason_code,
                reason_string,
            } => self
                .sys_terminate_with_payload(pid, reason_namespace, reason_code, reason_string)
                .to_syscall_result(),
            SyscallRequest::MapWithLinkingNp => {
                // XNU fails this with EINVAL once dyld disabled it or when no
                // page-in linking pager is available; dyld then applies the
                // fixups itself.
                Err(Errno::EINVAL)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().cast_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().cast_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::ThreadSelfid => {
                Ok(usize::try_from(self.thread.guest.id).expect("AArch64 thread IDs fit in usize"))
            }
            SyscallRequest::Getentropy { buffer, count } => self.sys_getentropy(buffer, count),
            SyscallRequest::MachVmAllocate {
                target,
                address,
                size,
                flags,
            } => Ok(self
                .sys_mach_vm_allocate(target, address, size, flags)
                .into()),
            SyscallRequest::MachVmDeallocate {
                target,
                address,
                size,
            } => Ok(self.sys_mach_vm_deallocate(target, address, size).into()),
            SyscallRequest::MachVmProtect {
                target,
                address,
                size,
                set_maximum,
                protection,
            } => Ok(self
                .sys_mach_vm_protect(target, address, size, set_maximum, protection)
                .into()),
            SyscallRequest::MachVmMap {
                target,
                address,
                size,
                mask,
                flags,
                current_protection,
            } => Ok(self
                .sys_mach_vm_map(target, address, size, mask, flags, current_protection)
                .into()),
            SyscallRequest::MachTaskSelf => Ok(self.sys_task_self()),
            SyscallRequest::MachThreadSelf => Ok(self.sys_thread_self()),
            SyscallRequest::MachHostSelf => Ok(self.sys_host_self()),
            SyscallRequest::MachReplyPort => Ok(self.sys_mach_reply_port()),
            SyscallRequest::MachPortAllocate {
                target,
                right,
                name,
            } => Ok(self.sys_mach_port_allocate(target, right, name).into()),
            SyscallRequest::MachPortDeallocate { target, name } => {
                Ok(self.sys_mach_port_deallocate(target, name).into())
            }
            SyscallRequest::MachPortModRefs {
                target,
                name,
                right,
                delta,
            } => Ok(self
                .sys_mach_port_mod_refs(target, name, right, delta)
                .into()),
            SyscallRequest::MachPortInsertRight {
                target,
                name,
                poly,
                poly_disposition,
            } => Ok(self
                .sys_mach_port_insert_right(target, name, poly, poly_disposition)
                .into()),
            SyscallRequest::MachPortConstruct {
                target,
                options,
                context,
                name,
            } => Ok(self
                .sys_mach_port_construct(target, options, context, name)
                .into()),
            SyscallRequest::MachPortDestruct {
                target,
                name,
                send_right_delta,
                guard,
            } => Ok(self
                .sys_mach_port_destruct(target, name, send_right_delta, guard)
                .into()),
            SyscallRequest::MachMsg2 {
                data,
                options,
                header,
                send_size,
                descriptor_count,
                receive_name,
                receive_size,
                priority: _,
                timeout,
            } => Ok(self.sys_mach_msg2(
                data,
                options,
                header,
                send_size,
                descriptor_count,
                receive_name,
                receive_size,
                timeout,
            ) as usize),
            SyscallRequest::SemaphoreSignal { semaphore } => {
                Ok(self.sys_semaphore_signal(semaphore).into())
            }
            SyscallRequest::SemaphoreWait { semaphore } => {
                Ok(self.sys_semaphore_wait(semaphore).into())
            }
            SyscallRequest::SwtchPri | SyscallRequest::Swtch => Ok(self.sys_swtch()),
            SyscallRequest::ThreadSwitch {
                thread: _,
                option,
                option_time,
            } => Ok(self.sys_thread_switch(option, option_time).into()),
            SyscallRequest::SharedRegionCheckNp { start_address } => self
                .sys_shared_region_check_np(start_address)
                .to_syscall_result(),
            SyscallRequest::SharedRegionMapAndSlide2Np {
                files_count,
                files,
                mappings_count,
            } => self
                .sys_shared_region_map_and_slide_2_np(files_count, files, mappings_count)
                .to_syscall_result(),
            SyscallRequest::MachAbsoluteTime => Ok(self.sys_mach_absolute_time()),
            SyscallRequest::MachTimebaseInfo { info } => {
                Ok(self.sys_mach_timebase_info(info).into())
            }
            SyscallRequest::MachWaitUntil { deadline } => {
                Ok(self.sys_mach_wait_until(deadline).into())
            }
        }
    }

    fn io_length(count: usize) -> Result<usize, Errno> {
        // XNU limits each read/write request to INT_MAX bytes.
        if count > core::ffi::c_int::MAX.cast_unsigned() as usize {
            return Err(Errno::EINVAL);
        }
        Ok(count.min(MAX_KERNEL_BUF_SIZE))
    }

    /// Whether the thread resumes the guest. Arms interruption of guest
    /// execution, so a process exit recorded from here on reaches the thread
    /// at its next shim entry.
    fn continuation(&self, ctx: &PtRegs) -> ContinueOperation {
        if self.thread.terminated.get() {
            return ContinueOperation::Terminate;
        }
        if !ctx.pc.is_multiple_of(size_of::<u32>()) || !ctx.sp.is_multiple_of(STACK_ALIGNMENT) {
            self.exit_process(128 + SIGSEGV);
            return ContinueOperation::Terminate;
        }
        let resume = self.thread.wait_state.prepare_to_run_guest(|| {
            !self.take_host_signal() && !self.process.exit_recorded_seqcst()
        });
        if resume {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

impl<P: ShimPlatform> EnterShim for MacosShimEntrypoints<P> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.start_thread();
        self.task.continuation(ctx)
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.thread.wait_state.finish_running_guest();
        self.task.handle_syscall_request(ctx);
        self.task.continuation(ctx)
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        self.task.thread.wait_state.finish_running_guest();
        if info.exception == litebox::shim::Exception::DATA_ABORT_LOWER_EL
            && (self.task.page_in_shared_cache(info.fault_address)
                || self
                    .task
                    .shared_cache_fault_resolved(info.fault_address, info.esr))
        {
            // Retry the access, like a page fault resolved by the kernel.
            return self.task.continuation(ctx);
        }
        // Syscalls enter through the rewriter's direct callback.
        litebox_util_log::error!(
            exception:? = info,
            pc:? = ctx.pc,
            lr:? = ctx.regs[30],
            fault_in:? = self.task.describe_shared_cache_address(info.fault_address),
            pc_in:? = self.task.describe_shared_cache_address(ctx.pc),
            lr_in:? = self.task.describe_shared_cache_address(ctx.regs[30]);
            "unhandled macOS guest exception"
        );
        self.task.exit_process(128 + SIGSEGV);
        ContinueOperation::Terminate
    }

    fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.thread.wait_state.finish_running_guest();
        // A host signal (Ctrl-C) ends the guest, since guest signal delivery
        // is unsupported; another thread's exit ends this one.
        self.task.continuation(ctx)
    }
}
