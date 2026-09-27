// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin BSD shim for AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. A runtime provider may
//! supply dyld and an external shared cache for dynamically linked programs.
//! Networking is unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{collections::BTreeMap, ffi::CString, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox,
    platform::PageManagementProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::{mm::VmemManager, vmem::VmFlags};
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, PtRegs, SIGINT, SIGSEGV, STACK_ALIGNMENT, SyscallRequest, TaskParams,
    VmProtection, errno::Errno, loader::MachoLoaderError,
};
use litebox_platform::{sync::RawMutex as _, time::TimeProvider};

const fn aarch64_rewrite_options() -> litebox_syscall_rewriter::RewriteOptions {
    #[cfg(target_os = "macos")]
    let host = litebox_syscall_rewriter::TargetHost::MacOs;
    #[cfg(not(target_os = "macos"))]
    let host = litebox_syscall_rewriter::TargetHost::Linux;
    litebox_syscall_rewriter::RewriteOptions::new(host, false)
}

mod loader;
pub mod syscalls;
#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Reservation store used by the Darwin shim's virtual memory manager.
pub type ShimReservations<Reservation> =
    litebox::platform::common_providers::reservations::NoTrackedReservations<
        PAGE_SIZE,
        Reservation,
    >;

/// Platform capabilities required for descriptor, page, gate, and wait management.
pub trait ShimPlatform:
    PageManagementProvider<PAGE_SIZE, Reservations = ShimReservations<Self::Reservation>>
    + RawSyncPrimitivesProvider
    + TimeProvider
    + litebox::platform::SignalProvider
    + litebox::platform::SystemInfoProvider
    + litebox_common_macos::MachClock
    + litebox::platform::ThreadProvider<ExecutionContext = PtRegs>
    + litebox::platform::ArchSpecificProvider
    + 'static
{
    /// Opaque page-reservation ownership type supplied by the platform.
    type Reservation: litebox::platform::page_mgmt::PageReservation + Send + Sync;
}
impl<P, Reservation> ShimPlatform for P
where
    P: PageManagementProvider<PAGE_SIZE, Reservations = ShimReservations<Reservation>>
        + RawSyncPrimitivesProvider
        + TimeProvider
        + litebox::platform::SignalProvider
        + litebox::platform::SystemInfoProvider
        + litebox_common_macos::MachClock
        + litebox::platform::ThreadProvider<ExecutionContext = PtRegs>
        + litebox::platform::ArchSpecificProvider
        + 'static,
    Reservation: litebox::platform::page_mgmt::PageReservation + Send + Sync,
{
    type Reservation = Reservation;
}

pub struct MacosShimBuilder<P: ShimPlatform> {
    platform: &'static P,
    litebox: Arc<LiteBox<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    pthread_runtime: Option<PthreadRuntime>,
}

/// Runtime-supplied libpthread entrypoint and registered TSD layout.
#[derive(Clone, Copy)]
pub struct PthreadRuntime {
    pub thread_start: usize,
    /// Guest libc exit entrypoint, used when the last guest calls pthread_exit.
    /// It must be rewritten for guest execution and must not return.
    pub process_exit: usize,
    pub tsd_offset: usize,
    pub mach_thread_self_offset: usize,
    /// Libpthread's reserved pthread/TSD span in bytes, starting at pthread_t.
    /// Only the pages intersecting this footprint are retained during cleanup.
    pub pthread_size: usize,
    /// Identity used by the runtime's underlying synchronization backend.
    pub current_thread_identity: fn() -> (u64, u32),
    pub synchronize: fn(PthreadSync) -> Result<usize, Errno>,
}

/// Native synchronization needed while the experimental runtime shares libpthread.
pub enum PthreadSync {
    UlockWait {
        operation: u32,
        address: usize,
        value: u64,
        timeout: u32,
    },
    UlockWait2 {
        operation: u32,
        address: usize,
        value: u64,
        timeout: u64,
        value2: u64,
    },
    UlockWake {
        operation: u32,
        address: usize,
        value: u64,
    },
    MutexWait {
        mutex: usize,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    },
    MutexDrop {
        mutex: usize,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    },
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
            pthread_runtime: None,
            files: Arc::new(syscalls::file::FilesState::new(Arc::clone(&litebox))),
            litebox,
        }
    }

    pub fn litebox(&self) -> &LiteBox<P> {
        &self.litebox
    }

    /// Transfer a LiteBox file into the guest's descriptor namespace.
    /// `fd` must belong to this builder's LiteBox instance.
    pub fn inherit_file(&mut self, fd: litebox::fs::FileFd) -> Result<u32, Errno> {
        self.files.insert_file(fd)
    }

    /// Enable the experimental pthread path for a prepared runtime.
    #[must_use]
    pub fn with_pthread_runtime(mut self, runtime: PthreadRuntime) -> Self {
        self.pthread_runtime = Some(runtime);
        self
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
                shared_cache_range: Mutex::new(None),
                shared_cache_mappings: Mutex::new(Vec::new()),
                privately_mapped_dyld_range: Mutex::new(None),
                next_thread_id: core::sync::atomic::AtomicU64::new(1u64 << 32),
                pthread_runtime: self.pthread_runtime,
                pthread_mappings: Mutex::new(syscalls::thread::PthreadMappings::default()),
                threads: Mutex::new(BTreeMap::new()),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedCacheInstallError {
    AlreadyInstalled,
    InvalidCacheRange,
    InvalidRegion,
    UnreadableAlias,
    Rewrite,
}

impl core::fmt::Display for SharedCacheInstallError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyInstalled => "shared cache already installed",
            Self::InvalidCacheRange => "invalid or uncovered shared-cache base",
            Self::InvalidRegion => "invalid shared-cache region",
            Self::UnreadableAlias => "shared-cache writable alias is unreadable",
            Self::Rewrite => "failed to rewrite shared-cache executable code",
        })
    }
}

impl core::error::Error for SharedCacheInstallError {}

/// Writable staging and final addresses for the cache's shared gate area.
pub struct SharedCacheTrampoline {
    pub range: core::ops::Range<usize>,
    pub writable_alias: usize,
}

/// One mapping in an externally prepared shared cache.
pub struct SharedCacheMapping {
    pub range: core::ops::Range<usize>,
    pub protection: VmProtection,
}

pub struct SharedCacheRegion<'a> {
    pub range: core::ops::Range<usize>,
    pub writable_alias: usize,
    /// Code that executes only in the guest context.
    pub guest_ranges: &'a [core::ops::Range<usize>],
    /// Code shared between the host and guest contexts.
    pub host_aware_ranges: &'a [core::ops::Range<usize>],
    /// Code whose TPIDRRO reads must remain native.
    pub native_thread_pointer_ranges: &'a [core::ops::Range<usize>],
}

/// Layout of an externally prepared shared cache.
pub struct SharedCacheLayout<'a> {
    pub range: core::ops::Range<usize>,
    pub mappings: &'a [SharedCacheMapping],
    pub executable_regions: &'a [SharedCacheRegion<'a>],
    pub trampoline: SharedCacheTrampoline,
}

/// How TPIDRRO reads in dyld should behave for the selected runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DyldThreadPointerMode {
    /// Read the physical thread register without rewriting it.
    Native,
    /// Read the guest thread pointer maintained by LiteBox.
    Guest,
}

/// A dyld image prepared by the runtime provider.
#[derive(Clone, Copy, Debug)]
pub struct DyldImage<'a> {
    pub data: &'a [u8],
    pub thread_pointer: DyldThreadPointerMode,
}

impl<P: ShimPlatform> MacosShim<P> {
    /// Load a self-contained static executable from the guest filesystem.
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

    /// Load a dynamically linked executable with a runtime-provided dyld.
    ///
    /// The provider selects dyld's thread-pointer behavior and must install any
    /// required shared cache before entering guest execution.
    pub fn load_program_with_dyld(
        self,
        params: TaskParams,
        path: &str,
        image: &[u8],
        dyld: DyldImage<'_>,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        self.load(params, path, Some(image), Some(dyld), argv, envp)
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
        dyld: Option<DyldImage<'_>>,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        let process = Process::new();
        let thread_id = self.global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        let thread = ThreadState::new(thread_id, self.global.platform);
        let task = Task {
            global: self.global,
            files: self.files,
            params,
            process: process.clone(),
            thread,
        };
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

/// Exit status can outlive the task without retaining its mappings or FDs.
pub struct Process<P: ShimPlatform>(Arc<ProcessState<P>>);

struct ProcessState<P: ShimPlatform> {
    /// Exit status, or `u32::MAX` while running.
    status: P::RawMutex,
    live_threads: AtomicUsize,
}

impl<P: ShimPlatform> Clone for Process<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: ShimPlatform> Process<P> {
    /// Create a process whose first task is already running.
    fn new() -> Self {
        let status = P::RawMutex::INIT;
        status
            .underlying_atomic()
            .store(u32::MAX, Ordering::Relaxed);
        Self(Arc::new(ProcessState {
            status,
            live_threads: AtomicUsize::new(1),
        }))
    }

    pub fn exit_status(&self) -> Option<i32> {
        let status = self.0.status.underlying_atomic().load(Ordering::Acquire);
        (status != u32::MAX).then(|| status.cast_signed())
    }

    /// Block until a thread exits the process or the last thread terminates.
    pub fn wait_for_exit(&self) -> i32 {
        loop {
            if let Some(status) = self.exit_status() {
                return status;
            }
            let _ = self.0.status.block(u32::MAX);
        }
    }

    /// Record `status` unless another thread already exited the process.
    /// Returns whether this call set the status.
    fn exit(&self, status: i32) -> bool {
        let won = self
            .0
            .status
            .underlying_atomic()
            .compare_exchange(
                u32::MAX,
                status.cast_unsigned(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if won {
            self.0.status.wake_all();
        }
        won
    }

    fn thread_started(&self) {
        self.0.live_threads.fetch_add(1, Ordering::AcqRel);
    }

    /// Retire a guest before dropping its host Task, leaving the last guest
    /// counted while it runs libc exit. This also handles simultaneous exits.
    fn retire_unless_last(&self) -> bool {
        self.0
            .live_threads
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count > 1).then(|| count - 1)
            })
            .is_ok()
    }

    /// Like XNU, the process exits when its last thread terminates.
    fn thread_stopped(&self) {
        if self.0.live_threads.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.exit(0);
        }
    }
}

pub struct LoadedProgram<P: ShimPlatform> {
    pub entrypoints: MacosShimEntrypoints<P>,
    pub process: Process<P>,
    pub initial_ctx: PtRegs,
}

/// Keeps mappings/descriptors alive without retaining live guest tasks.
pub struct RuntimeResources<P: ShimPlatform> {
    _global: Arc<GlobalState<P>>,
    _files: Arc<syscalls::file::FilesState<P>>,
}

impl<P: ShimPlatform> LoadedProgram<P> {
    /// Retain storage referenced by the shared runtime until native users stop.
    pub fn retain_runtime_resources(&self) -> RuntimeResources<P> {
        RuntimeResources {
            _global: self.entrypoints.task.global.clone(),
            _files: self.entrypoints.task.files.clone(),
        }
    }

    /// Rewrite and register an externally prepared shared cache.
    ///
    /// The provider must keep target mappings alive for the guest lifetime and
    /// supply writable aliases for the same bytes. No cache code may execute
    /// during installation. After success, publish staged mappings and
    /// synchronize instruction caches before guest entry. Discard the process
    /// on error because installation is not transactional.
    pub fn install_shared_cache(
        &self,
        cache: &SharedCacheLayout<'_>,
    ) -> Result<(), SharedCacheInstallError> {
        if self
            .entrypoints
            .task
            .global
            .shared_cache_base
            .load(Ordering::Acquire)
            != 0
        {
            return Err(SharedCacheInstallError::AlreadyInstalled);
        }
        if cache.range.start == 0
            || cache.range.start >= cache.range.end
            || !cache.range.start.is_multiple_of(PAGE_SIZE)
            || !cache.range.end.is_multiple_of(PAGE_SIZE)
            || cache.trampoline.range.start >= cache.trampoline.range.end
            || !cache.trampoline.range.start.is_multiple_of(PAGE_SIZE)
            || !cache.trampoline.range.end.is_multiple_of(PAGE_SIZE)
            || (cache.trampoline.range.start < cache.range.end
                && cache.range.start < cache.trampoline.range.end)
            || cache.trampoline.writable_alias == 0
        {
            return Err(SharedCacheInstallError::InvalidCacheRange);
        }
        if cache.mappings.is_empty()
            || cache.mappings.iter().any(|mapping| {
                mapping.range.start >= mapping.range.end
                    || mapping.range.start < cache.range.start
                    || mapping.range.end > cache.range.end
                    || !mapping.range.start.is_multiple_of(PAGE_SIZE)
                    || !mapping.range.end.is_multiple_of(PAGE_SIZE)
            })
            || cache
                .mappings
                .windows(2)
                .any(|pair| pair[0].range.end > pair[1].range.start)
        {
            return Err(SharedCacheInstallError::InvalidCacheRange);
        }
        let mut trampoline_cursor = 0;
        for region in cache.executable_regions {
            if region.range.start >= region.range.end
                || region.writable_alias == 0
                || !region.range.start.is_multiple_of(PAGE_SIZE)
                || !region.range.end.is_multiple_of(PAGE_SIZE)
                || region.range.start < cache.range.start
                || region.range.end > cache.range.end
            {
                return Err(SharedCacheInstallError::InvalidRegion);
            }
            trampoline_cursor = self.entrypoints.task.rewrite_shared_cache_region(
                region,
                &cache.trampoline,
                trampoline_cursor,
            )?;
        }
        let mut mappings = self.entrypoints.task.global.shared_cache_mappings.lock();
        mappings.extend(
            cache
                .mappings
                .iter()
                .map(|mapping| (mapping.range.clone(), mapping.protection)),
        );
        mappings.push((
            cache.trampoline.range.clone(),
            VmProtection::READ | VmProtection::EXECUTE,
        ));
        drop(mappings);
        *self.entrypoints.task.global.shared_cache_range.lock() = Some(cache.range.clone());
        self.entrypoints
            .task
            .global
            .shared_cache_base
            .store(cache.range.start, Ordering::Release);
        Ok(())
    }
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
    shared_cache_base: AtomicUsize,
    shared_cache_range: Mutex<P, Option<core::ops::Range<usize>>>,
    shared_cache_mappings: Mutex<P, Vec<(core::ops::Range<usize>, VmProtection)>>,
    privately_mapped_dyld_range: Mutex<P, Option<core::ops::Range<usize>>>,
    next_thread_id: core::sync::atomic::AtomicU64,
    pthread_runtime: Option<PthreadRuntime>,
    pthread_mappings: Mutex<P, syscalls::thread::PthreadMappings>,
    threads: Mutex<P, BTreeMap<u64, Arc<P::ThreadHandle>>>,
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

struct ThreadState<P: ShimPlatform> {
    id: u64,
    wait_state: litebox::event::wait::WaitState<P>,
    exited: AtomicBool,
    /// False once bsdthread_terminate retires this guest before host teardown.
    counted: core::cell::Cell<bool>,
    startup: Option<syscalls::thread::PthreadStartup<P>>,
    native_identity: core::cell::Cell<Option<(u64, u32)>>,
    /// LiteBox record for threads created by the guest.
    litebox_thread: core::cell::Cell<Option<litebox::thread::Thread>>,
}

impl<P: ShimPlatform> ThreadState<P> {
    fn new(id: u64, platform: &'static P) -> Self {
        Self {
            id,
            wait_state: litebox::event::wait::WaitState::new(platform),
            exited: AtomicBool::new(false),
            counted: core::cell::Cell::new(true),
            startup: None,
            native_identity: core::cell::Cell::new(None),
            litebox_thread: core::cell::Cell::new(None),
        }
    }
}

struct Task<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    params: TaskParams,
    process: Process<P>,
    thread: ThreadState<P>,
}

impl<P: ShimPlatform> Task<P> {
    /// Returns a wait context that a host signal, such as Ctrl-C, interrupts.
    fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, P> {
        self.thread
            .wait_state
            .context()
            .with_check_for_interrupt(self)
    }
}

impl<P: ShimPlatform> litebox::event::wait::CheckForInterrupt for Task<P> {
    fn check_for_interrupt(&self) -> bool {
        // Guest signal delivery is unsupported, so the signals themselves are dropped: the
        // platform also marks the thread interrupted, which terminates the guest through
        // `EnterShim::interrupt` once the interrupted syscall returns.
        let mut pending = false;
        self.global
            .platform
            .take_pending_signals(|_| pending = true);
        // Exit interrupts use the platform's private wake signal, not a guest
        // signal. A broker wait must also observe the published process status.
        pending
            || self.process.exit_status().is_some()
            || self.thread.exited.load(Ordering::Acquire)
    }
}

impl<P: ShimPlatform> Drop for Task<P> {
    fn drop(&mut self) {
        self.release_pthread_mapping();
        self.global.threads.lock().remove(&self.thread.id);
        if let Some(thread) = self.thread.litebox_thread.take() {
            let thread_id = thread.id();
            if let Err(error) = thread.exit() {
                litebox_util_log::error!(error:% = error, thread_id; "failed to record thread exit");
            }
        }
        if self.thread.counted.get() {
            self.process.thread_stopped();
        }
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
        let is_mach = litebox_common_macos::syscall::is_mach_trap_selector(ctx.regs[16]);
        match self.do_syscall(ctx) {
            Ok(value) => {
                ctx.regs[0] = value;
                if !is_mach {
                    ctx.pstate &= !CARRY;
                }
            }
            Err(error) => {
                if is_mach {
                    ctx.regs[0] = KernReturn::INVALID_ARGUMENT.into();
                } else {
                    ctx.regs[0] = error.raw();
                    ctx.pstate |= CARRY;
                }
            }
        }
    }

    fn do_syscall(&self, ctx: &mut PtRegs) -> Result<usize, Errno> {
        let request = SyscallRequest::try_from_raw(ctx.regs[16], ctx, |args| {
            litebox_util_log::warn!(feature:% = args; "unsupported");
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
                self.sys_open(path, flags, mode).to_syscall_result()
            }
            SyscallRequest::Close { fd } => self.sys_close(fd).to_syscall_result(),
            SyscallRequest::Dup { fd } => self.sys_dup(fd).to_syscall_result(),
            SyscallRequest::Sysctl {
                name,
                name_length,
                new_value,
                new_length,
                ..
            } => Self::sys_sysctl_compat(name, name_length, new_value, new_length),
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
            SyscallRequest::Getpid => Ok(self.sys_getpid().cast_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().cast_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
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
            } => self
                .sys_bsdthread_terminate(ctx, stack, size, port, semaphore_or_ulock)
                .to_syscall_result(),
            SyscallRequest::UlockWait {
                operation,
                address,
                value,
                timeout,
            } => self.sys_pthread_sync(PthreadSync::UlockWait {
                operation,
                address,
                value,
                timeout,
            }),
            SyscallRequest::UlockWake {
                operation,
                address,
                value,
            } => self.sys_pthread_sync(PthreadSync::UlockWake {
                operation,
                address,
                value,
            }),
            SyscallRequest::PsynchMutexWait {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            } => self.sys_pthread_sync(PthreadSync::MutexWait {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            }),
            SyscallRequest::PsynchMutexDrop {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            } => self.sys_pthread_sync(PthreadSync::MutexDrop {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            }),
            SyscallRequest::UlockWait2 {
                operation,
                address,
                value,
                timeout,
                value2,
            } => self.sys_pthread_sync(PthreadSync::UlockWait2 {
                operation,
                address,
                value,
                timeout,
                value2,
            }),
            SyscallRequest::ThreadSelfid => {
                // Workers use their registered host ID for native synchronization.
                // The initial pthread_t/thread_id remain donor-backed, but its
                // Mach-self slot names the executing thread. Without a registered
                // native ID, this syscall keeps the initial thread's shim ID.
                let id = self
                    .thread
                    .native_identity
                    .get()
                    .map_or(self.thread.id, |identity| identity.0);
                Ok(usize::try_from(id).expect("AArch64 thread IDs fit in usize"))
            }
            SyscallRequest::Getentropy { buffer, count } => self.sys_getentropy(buffer, count),
            SyscallRequest::MachVmAllocate {
                target,
                address,
                size,
                flags,
            } => Ok(self.sys_mach_vm_allocate_compat(target, address, size, flags)),
            SyscallRequest::MachVmDeallocate {
                target,
                address,
                size,
            } => Ok(self.sys_mach_vm_deallocate_compat(target, address, size)),
            SyscallRequest::MachVmProtect {
                target,
                address,
                size,
                set_maximum,
                protection,
            } => {
                Ok(self.sys_mach_vm_protect_compat(target, address, size, set_maximum, protection))
            }
            SyscallRequest::MachVmMap {
                target,
                address,
                size,
                mask,
                flags,
                current_protection,
            } => Ok(self.sys_mach_vm_map_compat(
                target,
                address,
                size,
                mask,
                flags,
                current_protection,
            )),
            SyscallRequest::MachTaskSelf => Ok(Self::synthetic_task_port().into()),
            SyscallRequest::SharedRegionCheckNp { start_address } => self
                .sys_shared_region_check_np(start_address)
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

    fn continuation(&self, ctx: &PtRegs) -> ContinueOperation {
        if self.process.exit_status().is_some() || self.thread.exited.load(Ordering::Acquire) {
            ContinueOperation::Terminate
        } else if !ctx.pc.is_multiple_of(size_of::<u32>())
            || !ctx.sp.is_multiple_of(STACK_ALIGNMENT)
        {
            self.sys_exit(128 + SIGSEGV);
            ContinueOperation::Terminate
        } else {
            ContinueOperation::Resume
        }
    }
}

impl<P: ShimPlatform> EnterShim for MacosShimEntrypoints<P> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.global.threads.lock().insert(
            self.task.thread.id,
            Arc::new(self.task.global.platform.current_thread()),
        );
        let initialized = self.task.initialize_pthread(ctx);
        if initialized.is_err() {
            self.task.thread.exited.store(true, Ordering::Release);
        }
        if let Some(startup) = &self.task.thread.startup {
            startup.publish(initialized.is_ok());
        }
        self.task.continuation(ctx)
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall_request(ctx);
        self.task.continuation(ctx)
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        // Syscalls enter through the rewriter's direct callback.
        litebox_util_log::error!(exception:? = info, pc:? = ctx.pc; "unhandled macOS guest exception");
        self.task.sys_exit(128 + SIGSEGV);
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        // Siblings are interrupted to observe process exit. Otherwise terminate,
        // because guest signal delivery is unsupported.
        if self.task.process.exit_status().is_none() {
            self.task.sys_exit(128 + SIGINT);
        }
        ContinueOperation::Terminate
    }
}
