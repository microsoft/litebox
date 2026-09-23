// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin BSD shim for AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. On macOS, dynamically linked
//! programs use a private, boot-local instance of the host's dyld shared cache.
//! Networking is unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{collections::BTreeMap, ffi::CString, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox,
    mm::PageManager,
    platform::PageManagementProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, PtRegs, SIGINT, SIGSEGV, STACK_ALIGNMENT, SyscallRequest, TaskParams,
    VmProtection, errno::Errno, loader::MachoLoaderError,
};

mod loader;
pub mod syscalls;
#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Platform capabilities required for descriptor, page, and gate management.
pub trait ShimPlatform:
    PageManagementProvider<PAGE_SIZE>
    + RawSyncPrimitivesProvider
    + litebox::platform::SystemInfoProvider
    + litebox_common_macos::MachClock
    + 'static
{
}
impl<
    P: PageManagementProvider<PAGE_SIZE>
        + RawSyncPrimitivesProvider
        + litebox::platform::SystemInfoProvider
        + litebox_common_macos::MachClock
        + 'static,
> ShimPlatform for P
{
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
    /// `fd` must belong to this builder's LiteBox instance.
    pub fn inherit_file(&mut self, fd: litebox::fs::FileFd) -> Result<u32, Errno> {
        self.files.insert_file(fd)
    }

    pub fn build(self) -> MacosShim<P> {
        MacosShim {
            global: Arc::new(GlobalState {
                platform: self.platform,
                pm: PageManager::new(&self.litebox),
                litebox: self.litebox,
                macho_mappings: Mutex::new(BTreeMap::new()),
                macho_trampolines: Mutex::new(BTreeMap::new()),
                shared_cache_base: AtomicUsize::new(0),
                shared_cache_range: Mutex::new(None),
                shared_cache_mappings: Mutex::new(Vec::new()),
                standalone_dyld_range: Mutex::new(None),
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
pub enum LiveSharedCacheError {
    InvalidCacheRange,
    InvalidRegion,
    UnreadableAlias,
    Rewrite,
}

impl core::fmt::Display for LiveSharedCacheError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCacheRange => "invalid or uncovered shared-cache base",
            Self::InvalidRegion => "invalid shared-cache region",
            Self::UnreadableAlias => "shared-cache writable alias is unreadable",
            Self::Rewrite => "failed to rewrite shared-cache executable code",
        })
    }
}

impl core::error::Error for LiveSharedCacheError {}

/// Writable staging and final addresses for the cache's shared gate area.
pub struct LiveSharedCacheTrampoline {
    pub range: core::ops::Range<usize>,
    pub writable_alias: usize,
}

/// One executable mapping in a boot-local private cache clone.
pub struct LiveSharedCacheMapping {
    pub range: core::ops::Range<usize>,
    pub protection: VmProtection,
}

pub struct LiveSharedCacheRegion<'a> {
    pub range: core::ops::Range<usize>,
    pub writable_alias: usize,
    pub code_ranges: &'a [core::ops::Range<usize>],
    /// Rewritten ranges whose TPIDRRO gates must select the physical pthread.
    pub native_tpidrro_ranges: &'a [core::ops::Range<usize>],
}

/// Complete layout needed to rewrite a boot-local cache instance.
pub struct LiveSharedCache<'a> {
    pub range: core::ops::Range<usize>,
    pub mappings: &'a [LiveSharedCacheMapping],
    pub executable_regions: &'a [LiveSharedCacheRegion<'a>],
    pub trampoline: LiveSharedCacheTrampoline,
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

    /// Load a dynamically linked executable with a standalone copy of host dyld.
    ///
    /// This maps the executable and standalone dyld before cache text is
    /// privatized. Call [`LoadedProgram::adopt_live_shared_cache`] on the
    /// result before entering guest execution.
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
        let task = Task {
            global: self.global,
            files: self.files,
            params,
            process: process.clone(),
            thread: ThreadState {
                blocked_signals: core::sync::atomic::AtomicU32::new(0),
                id: thread_id,
            },
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
    /// Rewrite a boot-local cache after all loader allocation and libc work is complete.
    pub fn adopt_live_shared_cache(
        &self,
        cache: &LiveSharedCache<'_>,
    ) -> Result<(), LiveSharedCacheError> {
        if cache.range.start == 0
            || cache.range.start >= cache.range.end
            || !cache.range.start.is_multiple_of(PAGE_SIZE)
            || !cache.range.end.is_multiple_of(PAGE_SIZE)
            || cache.trampoline.range.start >= cache.trampoline.range.end
            || !cache.trampoline.range.start.is_multiple_of(PAGE_SIZE)
            || !cache.trampoline.range.end.is_multiple_of(PAGE_SIZE)
            || cache.trampoline.writable_alias == 0
        {
            return Err(LiveSharedCacheError::InvalidCacheRange);
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
            return Err(LiveSharedCacheError::InvalidCacheRange);
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
                return Err(LiveSharedCacheError::InvalidRegion);
            }
            trampoline_cursor = self.entrypoints.task.rewrite_live_shared_cache_region(
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
    pm: PageManager<P, PAGE_SIZE>,
    macho_mappings: Mutex<P, BTreeMap<usize, syscalls::mm::MachoMapping>>,
    macho_trampolines: Mutex<P, BTreeMap<usize, syscalls::mm::MachoRuntimeTrampoline>>,
    shared_cache_base: AtomicUsize,
    shared_cache_range: Mutex<P, Option<core::ops::Range<usize>>>,
    shared_cache_mappings: Mutex<P, Vec<(core::ops::Range<usize>, VmProtection)>>,
    standalone_dyld_range: Mutex<P, Option<core::ops::Range<usize>>>,
    next_thread_id: core::sync::atomic::AtomicU64,
}

impl<P: ShimPlatform> Drop for GlobalState<P> {
    fn drop(&mut self) {
        // SAFETY: the last task/loader owner is gone, so none of these mappings
        // are executing or borrowed. Vmem's platform reservations have empty
        // flags; our anonymous mappings have VM_MAY_ACCESS_FLAGS, even guards.
        for (range, flags) in self.pm.mappings() {
            if !flags.intersects(litebox::mm::linux::VmFlags::VM_MAY_ACCESS_FLAGS) {
                continue;
            }
            let ptr = litebox_common_macos::user_pointers::UserPtrMut::from_usize(range.start)
                .to_platform_ptr::<P>();
            // Best effort during Drop, including unwinding: a failed unmap
            // must not cause a second panic or prevent releasing later ranges.
            if let Err(error) = unsafe { self.pm.remove_pages(ptr, range.len()) } {
                litebox_util_log::warn!(error:? = error; "failed to release macOS guest mapping");
            }
        }
    }
}

struct ThreadState {
    blocked_signals: core::sync::atomic::AtomicU32,
    id: u64,
}

struct Task<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    params: TaskParams,
    process: Process,
    thread: ThreadState,
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
                self.check_user_buffer(buf.as_usize(), length, Permissions::WRITE)?;
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
                self.check_user_buffer(buf.as_usize(), length, Permissions::READ)?;
                if length == 0 {
                    return self.do_write(&fd, &[]);
                }
                let bytes = buf.to_owned_slice::<P>(length).ok_or(Errno::EFAULT)?;
                self.do_write(&fd, &bytes)
            }
            SyscallRequest::Open { path, flags, mode } => {
                let path = self.read_path(path)?;
                self.sys_open(path, flags, mode).to_syscall_result()
            }
            SyscallRequest::Close { fd } => self.sys_close(fd).to_syscall_result(),
            SyscallRequest::Dup { fd } => self.sys_dup(fd).to_syscall_result(),
            SyscallRequest::Dup2 { oldfd, newfd } => {
                self.sys_dup2(oldfd, newfd).to_syscall_result()
            }
            SyscallRequest::Sysctl {
                new_value,
                new_length,
                ..
            } => Self::sys_sysctl_compat(new_value, new_length),
            SyscallRequest::Fcntl {
                fd,
                command,
                argument,
            } => self.sys_fcntl_compat(fd, command, argument),
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
            SyscallRequest::Sigprocmask { how, set, oldset } => {
                self.sys_sigprocmask_compat(how, set, oldset)
            }
            SyscallRequest::ThreadSelfid => {
                Ok(usize::try_from(self.thread.id).expect("AArch64 thread IDs fit in usize"))
            }
            // Native arm64 guests have no Rosetta translation state.
            SyscallRequest::CrossarchTrap { .. } => Ok(0),
            // Do not grant access to privileged host CSR policy.
            SyscallRequest::Csrctl { .. } => Err(Errno::EPERM),
            SyscallRequest::Csops {
                pid,
                operation,
                user_address,
                user_size,
            } => self.sys_csops_compat(pid, operation, user_address, user_size),
            // Let dyld fall back when these kernel services are unavailable.
            SyscallRequest::ProcRlimitControl { .. } | SyscallRequest::MapWithLinkingNp { .. } => {
                Err(Errno::ENOSYS)
            }
            // Thread creation is not implemented in this bootstrap path.
            SyscallRequest::BsdthreadCreate { .. } => Err(Errno::EAGAIN),
            // Never forward filesystem-control requests to the host filesystem.
            SyscallRequest::Fsctl { .. } => Err(Errno::ENOTTY),
            SyscallRequest::Fsgetpath { .. } => Self::sys_fsgetpath_compat(),
            SyscallRequest::Fstat64 { fd, buffer } => self.sys_fstat64_compat(fd, buffer),
            SyscallRequest::Stat64 { path, buffer } => self.sys_stat64_compat(path, buffer),
            SyscallRequest::Statfs64 { path, buffer } => self.sys_statfs64_compat(path, buffer),
            SyscallRequest::MacSyscall {
                policy,
                operation,
                argument,
            } => self.sys_mac_policy_compat(policy, operation, argument),
            SyscallRequest::AbortWithPayload {
                namespace,
                code,
                payload: _,
                payload_size: _,
                reason,
                reason_flags,
            } => {
                let reason = self.read_path(reason).ok();
                litebox_util_log::error!(namespace, code, reason_flags, reason:? = reason; "guest abort_with_payload");
                self.process.exit(134);
                Ok(0)
            }
            SyscallRequest::Getentropy { buffer, count } => {
                self.sys_getentropy_compat(buffer, count)
            }
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
            SyscallRequest::MachReplyPort => Ok(Self::synthetic_reply_port().into()),
            SyscallRequest::MachThreadSelf => Ok(Self::synthetic_thread_port().into()),
            SyscallRequest::MachTaskSelf => Ok(Self::synthetic_task_port().into()),
            SyscallRequest::MachHostSelf => Ok(Self::synthetic_host_port().into()),
            SyscallRequest::MachMsg2Trap { options, .. } => Ok(Self::sys_mach_msg2_compat(options)),
            SyscallRequest::SharedRegionCheckNp { start_address } => self
                .sys_shared_region_check_np(start_address)
                .to_syscall_result(),
            // The boot-local cache was installed before execution; dyld's map
            // request must not replace those validated mappings.
            SyscallRequest::SharedRegionMapAndSlide2Np { .. } => {
                litebox_util_log::warn!(
                    "absorbing shared-region map request for preinstalled cache"
                );
                Ok(0)
            }
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

    fn check_user_buffer(
        &self,
        address: usize,
        length: usize,
        permissions: Permissions,
    ) -> Result<(), Errno> {
        if length == 0 {
            return Ok(());
        }
        let end = address.checked_add(length).ok_or(Errno::EFAULT)?;
        if self
            .global
            .pm
            .range_has_permissions(address..end, permissions)
        {
            return Ok(());
        }
        self.global
            .shared_cache_mappings
            .lock()
            .iter()
            .any(|(range, protection)| {
                address >= range.start
                    && end <= range.end
                    && (!permissions.contains(Permissions::READ)
                        || protection.contains(VmProtection::READ))
                    && (!permissions.contains(Permissions::WRITE)
                        || protection.contains(VmProtection::WRITE))
                    && (!permissions.contains(Permissions::EXEC)
                        || protection.contains(VmProtection::EXECUTE))
            })
            .then_some(())
            .ok_or(Errno::EFAULT)
    }

    fn continuation(&self, ctx: &PtRegs) -> ContinueOperation {
        if self.process.exit_status().is_some() {
            ContinueOperation::Terminate
        } else if !ctx.pc.is_multiple_of(size_of::<u32>())
            || !ctx.sp.is_multiple_of(STACK_ALIGNMENT)
            || self
                .check_user_buffer(ctx.pc, size_of::<u32>(), Permissions::EXEC)
                .is_err()
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
