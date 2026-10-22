// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin BSD shim for AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. A runtime provider may
//! supply dyld for dynamically linked programs.
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
    errno::Errno, loader::MachoLoaderError,
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
    random_source: bool,
}

impl<P: ShimPlatform> MacosShimBuilder<P> {
    /// Build a shim without a broker, so without file I/O or a random source:
    /// only static executables load, without the apple[] entropy keys.
    pub fn new(platform: &'static P) -> Self {
        Self::with_litebox(platform, LiteBox::new(platform), false)
    }

    /// Build a shim around an existing broker-backed LiteBox instance.
    /// `platform` must be the same platform used to construct `litebox`.
    ///
    /// Loading requests the apple[] entropy keys from the broker's random
    /// source and fails with [`MachoLoaderError::Entropy`] if it cannot supply
    /// them.
    pub fn new_with_litebox(platform: &'static P, litebox: LiteBox<P>) -> Self {
        Self::with_litebox(platform, litebox, true)
    }

    fn with_litebox(platform: &'static P, litebox: LiteBox<P>, random_source: bool) -> Self {
        let litebox = Arc::new(litebox);
        Self {
            platform,
            files: Arc::new(syscalls::file::FilesState::new(Arc::clone(&litebox))),
            litebox,
            random_source,
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
                next_thread_id: core::sync::atomic::AtomicU64::new(1u64 << 32),
            }),
            files: self.files,
            random_source: self.random_source,
        }
    }
}

/// One guest address space. Loading consumes the shim; the entrypoints retain
/// its shared global state for the guest's lifetime.
pub struct MacosShim<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    random_source: bool,
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

    /// Load a dynamically linked executable with a runtime-provided dyld image.
    /// Like every other guest image, an unrewritten dyld is rewritten during
    /// loading and an AOT-rewritten dyld must carry valid rewrite metadata.
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
        let random_source = self.random_source;
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
        let initial_ctx = loader::load(&task, path, image, dyld, random_source, &argv, &envp)?;
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
