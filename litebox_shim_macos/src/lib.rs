// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Darwin BSD shim for self-contained static AArch64 Mach-O guests.
//!
//! Guest mappings and file operations use LiteBox. The runner supplies inherited
//! descriptors. Networking is unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{ffi::CString, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicI32, Ordering};
use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox, mm::PageManager, platform::PageManagementProvider, sync::RawSyncPrimitivesProvider,
};
use litebox_common_macos::{
    PAGE_SIZE, PtRegs, SIGINT, SIGSEGV, STACK_ALIGNMENT, SyscallRequest, TaskParams, errno::Errno,
    loader::MachoLoaderError,
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
    ///
    /// `path` also supplies the startup apple vector's `executable_path` entry,
    /// independently of `argv[0]`.
    pub fn load_program(
        self,
        params: TaskParams,
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        self.load(params, path, None, argv, envp)
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
        self.load(params, path, Some(image), argv, envp)
    }

    fn load(
        self,
        params: TaskParams,
        path: &str,
        image: Option<&[u8]>,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, MachoLoaderError> {
        let process = Process(Arc::new(AtomicI32::new(-1)));
        let task = Task {
            global: self.global,
            files: self.files,
            params,
            process: process.clone(),
        };
        let initial_ctx = loader::load(&task, path, image, &argv, &envp)?;
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
    pm: PageManager<P, PAGE_SIZE>,
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

struct Task<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    files: Arc<syscalls::file::FilesState<P>>,
    params: TaskParams,
    process: Process,
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
                ctx.regs[0] = error.raw();
                if !is_mach {
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
            Ok(())
        } else {
            Err(Errno::EFAULT)
        }
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

    fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
        // Syscalls enter through the rewriter's direct callback. Unhandled
        // guest faults terminate the process.
        self.task.process.exit(128 + SIGSEGV);
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        // Terminate interrupted guests because guest signal delivery is unsupported.
        self.task.process.exit(128 + SIGINT);
        ContinueOperation::Terminate
    }
}
