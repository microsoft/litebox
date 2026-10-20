// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin BSD shim for AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. A runtime provider may
//! supply dyld and a guest-private dyld shared-cache instance for dynamically
//! linked programs.
//! Networking is unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{collections::BTreeMap, ffi::CString, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox,
    platform::PageManagementProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::{PtRegs, mm::VmemManager, vmem::VmFlags};
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, SIGINT, SIGSEGV, STACK_ALIGNMENT, SyscallRequest, TaskParams,
    VmProtection, errno::Errno, loader::MachoLoaderError,
};
use litebox_platform::time::TimeProvider;

const fn aarch64_rewrite_options() -> litebox_syscall_rewriter::RewriteOptions {
    #[cfg(target_os = "macos")]
    let host = litebox_trampoline::TargetHost::MacOs;
    #[cfg(not(target_os = "macos"))]
    let host = litebox_trampoline::TargetHost::Linux;
    litebox_syscall_rewriter::RewriteOptions::new(host, false)
}

mod loader;
pub mod syscalls;
#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Platform capabilities required for descriptor, page, gate, and wait management.
pub trait ShimPlatform:
    PageManagementProvider<PAGE_SIZE, Reservations = <Self as ShimPlatform>::VmemReservations>
    + RawSyncPrimitivesProvider
    + TimeProvider
    + litebox::platform::SignalProvider
    + litebox::platform::SystemInfoProvider
    + litebox::platform::ArchSpecificProvider
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
        }
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
                shared_cache_range: Mutex::new(None),
                shared_cache_mappings: Mutex::new(Vec::new()),
                privately_mapped_dyld_range: Mutex::new(None),
                next_thread_id: core::sync::atomic::AtomicU64::new(1u64 << 32),
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
    InvalidGateIsland,
    UnreadableAlias,
    Rewrite,
    /// No gate island with remaining capacity is within branch range of a site.
    UnreachableGates,
}

impl core::fmt::Display for SharedCacheInstallError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyInstalled => "shared cache already installed",
            Self::InvalidCacheRange => "invalid or uncovered shared-cache base",
            Self::InvalidRegion => "invalid shared-cache code region",
            Self::InvalidGateIsland => "invalid shared-cache gate island",
            Self::UnreadableAlias => "shared-cache writable alias is unreadable",
            Self::Rewrite => "failed to rewrite shared-cache executable code",
            Self::UnreachableGates => "no shared-cache gate island can serve a rewrite site",
        })
    }
}

impl core::error::Error for SharedCacheInstallError {}

/// One mapping of a guest shared-cache instance and its final protection.
pub struct SharedCacheMapping {
    pub range: core::ops::Range<usize>,
    pub protection: VmProtection,
}

/// Guest-executed shared-cache code to rewrite in place, such as one image's `__TEXT`.
pub struct SharedCacheCodeRegion<'a> {
    /// Final guest address range; page-aligned.
    pub range: core::ops::Range<usize>,
    /// Address at which the same bytes are writable during installation. It
    /// may equal `range.start` while the target is temporarily writable.
    pub writable_alias: usize,
    /// Instruction byte ranges relative to `range.start`: sorted,
    /// non-overlapping and 4-byte aligned.
    pub instruction_ranges: &'a [core::ops::Range<usize>],
}

/// Page-aligned, otherwise unused guest memory that receives rewrite gates.
///
/// Each rewritten site branches directly to its gate, so every site must lie
/// within AArch64 `B` range (+-128 MiB) of an island with remaining capacity.
pub struct SharedCacheGateIsland {
    pub range: core::ops::Range<usize>,
    /// Address at which the island is writable during installation.
    pub writable_alias: usize,
}

/// Layout of a guest-private shared-cache instance prepared by a runtime provider.
pub struct SharedCacheLayout<'a> {
    /// The whole reserved instance, `[base, base + sharedRegionSize)`.
    pub range: core::ops::Range<usize>,
    /// Final protections of the instance's pages, sorted and non-overlapping.
    /// Code regions and gate islands must be covered by read-execute mappings.
    pub mappings: &'a [SharedCacheMapping],
    pub code_regions: &'a [SharedCacheCodeRegion<'a>],
    pub gate_islands: &'a [SharedCacheGateIsland],
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

    /// Load a dynamically linked executable with a runtime-provided, unrewritten
    /// dyld image. dyld is rewritten like every other guest image.
    ///
    /// The provider must install any required shared cache before entering
    /// guest execution.
    pub fn load_program_with_dyld(
        self,
        params: TaskParams,
        path: &str,
        image: &[u8],
        dyld: &[u8],
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
        dyld: Option<&[u8]>,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        let process = Process(Arc::new(AtomicI32::new(-1)));
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
#[derive(Clone)]
pub struct Process(Arc<AtomicI32>);
impl Process {
    pub fn exit_status(&self) -> Option<i32> {
        let status = self.0.load(Ordering::Acquire);
        (status >= 0).then_some(status)
    }
    fn exit(&self, status: i32) {
        self.0.store(status, Ordering::Release);
    }
}

pub struct LoadedProgram<P: ShimPlatform> {
    pub entrypoints: MacosShimEntrypoints<P>,
    pub process: Process,
    pub initial_ctx: PtRegs,
}

impl<P: ShimPlatform> LoadedProgram<P> {
    /// Rewrite and register a guest-private shared-cache instance.
    ///
    /// The provider must keep the instance mapped for the guest lifetime and
    /// supply writable aliases for code regions and gate islands. No cache code
    /// may execute during installation. After success, apply the final
    /// protections from `cache.mappings` (code and islands read-execute) and
    /// synchronize instruction caches before guest entry. Discard the process
    /// on error because installation is not transactional.
    pub fn install_shared_cache(
        &self,
        cache: &SharedCacheLayout<'_>,
    ) -> Result<(), SharedCacheInstallError> {
        let task = &self.entrypoints.task;
        if task.global.shared_cache_base.load(Ordering::Acquire) != 0 {
            return Err(SharedCacheInstallError::AlreadyInstalled);
        }
        let page_aligned = |range: &core::ops::Range<usize>| {
            range.start < range.end
                && range.start.is_multiple_of(PAGE_SIZE)
                && range.end.is_multiple_of(PAGE_SIZE)
        };
        let inside = |range: &core::ops::Range<usize>| {
            range.start >= cache.range.start && range.end <= cache.range.end
        };
        let overlaps = |a: &core::ops::Range<usize>, b: &core::ops::Range<usize>| {
            a.start < b.end && b.start < a.end
        };
        // Whether `range` is covered by consecutive mappings with exactly `protection`.
        let covered_by = |range: &core::ops::Range<usize>, protection: VmProtection| {
            let mut covered = range.start;
            for mapping in cache.mappings {
                if mapping.range.end <= covered {
                    continue;
                }
                if mapping.range.start > covered || mapping.protection != protection {
                    return false;
                }
                covered = mapping.range.end;
                if covered >= range.end {
                    return true;
                }
            }
            false
        };
        if cache.range.start == 0 || !page_aligned(&cache.range) {
            return Err(SharedCacheInstallError::InvalidCacheRange);
        }
        if cache.mappings.is_empty()
            || cache
                .mappings
                .iter()
                .any(|mapping| !page_aligned(&mapping.range) || !inside(&mapping.range))
            || cache
                .mappings
                .windows(2)
                .any(|pair| pair[0].range.end > pair[1].range.start)
        {
            return Err(SharedCacheInstallError::InvalidCacheRange);
        }
        let executable = VmProtection::READ | VmProtection::EXECUTE;
        for (index, island) in cache.gate_islands.iter().enumerate() {
            if !page_aligned(&island.range)
                || island.writable_alias == 0
                || !inside(&island.range)
                || !covered_by(&island.range, executable)
                || cache.gate_islands[index + 1..]
                    .iter()
                    .any(|other| overlaps(&island.range, &other.range))
            {
                return Err(SharedCacheInstallError::InvalidGateIsland);
            }
        }
        for region in cache.code_regions {
            if !page_aligned(&region.range)
                || region.writable_alias == 0
                || !inside(&region.range)
                || !covered_by(&region.range, executable)
                || cache
                    .gate_islands
                    .iter()
                    .any(|island| overlaps(&island.range, &region.range))
            {
                return Err(SharedCacheInstallError::InvalidRegion);
            }
        }
        let mut island_cursors = alloc::vec![0; cache.gate_islands.len()];
        for region in cache.code_regions {
            task.rewrite_shared_cache_region(region, cache.gate_islands, &mut island_cursors)?;
        }
        task.global.shared_cache_mappings.lock().extend(
            cache
                .mappings
                .iter()
                .map(|mapping| (mapping.range.clone(), mapping.protection)),
        );
        *task.global.shared_cache_range.lock() = Some(cache.range.clone());
        task.global
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
}

impl<P: ShimPlatform> ThreadState<P> {
    fn new(id: u64, platform: &'static P) -> Self {
        Self {
            id,
            wait_state: litebox::event::wait::WaitState::new(platform),
        }
    }
}

struct Task<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    params: TaskParams,
    process: Process,
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
        pending
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
                    self.process.exit(128 + SIGSEGV);
                }
            }
            PlatformSyscall::GetCthreadSelf => {
                match platform.get_arch_specific_register(&ArchSpecificRegister::TpidrroEl0) {
                    Ok(tsd_base) => ctx.regs[0] = tsd_base,
                    Err(error) => {
                        litebox_util_log::error!(error:?; "cannot read the guest TSD base");
                        self.process.exit(128 + SIGSEGV);
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
                self.sys_open(&path, flags, mode).to_syscall_result()
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
            SyscallRequest::ThreadSelfid => {
                Ok(usize::try_from(self.thread.id).expect("AArch64 thread IDs fit in usize"))
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
        if self.process.exit_status().is_some() {
            ContinueOperation::Terminate
        } else if !ctx.pc.is_multiple_of(size_of::<u32>())
            || !ctx.sp.is_multiple_of(STACK_ALIGNMENT)
        {
            self.process.exit(128 + SIGSEGV);
            ContinueOperation::Terminate
        } else {
            ContinueOperation::Resume
        }
    }
}

impl<P: ShimPlatform> EnterShim for MacosShimEntrypoints<P> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.continuation(ctx)
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall_request(ctx);
        self.task.continuation(ctx)
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        // Syscalls enter through the rewriter's direct callback.
        litebox_util_log::error!(exception:? = info, pc:? = ctx.pc; "unhandled macOS guest exception");
        self.task.process.exit(128 + SIGSEGV);
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        // Terminate interrupted guests because guest signal delivery is unsupported.
        self.task.process.exit(128 + SIGINT);
        ContinueOperation::Terminate
    }
}
