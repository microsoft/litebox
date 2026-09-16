// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Darwin BSD shim for static AArch64 Mach-O guests.
//!
//! Guest mappings use LiteBox's page manager. The `test-stdio` feature enables
//! a local I/O adapter with LiteBox-managed test descriptors. Filesystem,
//! networking, and broker-backed stdio are unsupported.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::{ffi::CString, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicI32, Ordering};
use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{
    LiteBox, mm::PageManager, platform::PageManagementProvider, sync::RawSyncPrimitivesProvider,
};
use litebox_common_macos::{PAGE_SIZE, PtRegs, SyscallRequest, TaskParams, errno::Errno};

pub mod loader;
pub mod syscalls;
#[cfg(any(test, feature = "test-stdio"))]
mod test_stdio;
#[cfg(any(test, feature = "test-stdio"))]
pub use test_stdio::Stdio;

#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Platform capabilities required for descriptor, page, and gate management.
pub trait ShimPlatform:
    PageManagementProvider<PAGE_SIZE>
    + RawSyncPrimitivesProvider
    + litebox::platform::SystemInfoProvider
    + 'static
{
}
impl<
    P: PageManagementProvider<PAGE_SIZE>
        + RawSyncPrimitivesProvider
        + litebox::platform::SystemInfoProvider
        + 'static,
> ShimPlatform for P
{
}

pub struct MacosShimBuilder<P: ShimPlatform> {
    platform: &'static P,
    litebox: LiteBox<P>,
    #[cfg(any(test, feature = "test-stdio"))]
    stdio: Option<Arc<dyn Stdio>>,
}

impl<P: ShimPlatform> MacosShimBuilder<P> {
    pub fn new(platform: &'static P) -> Self {
        Self::new_with_litebox(platform, LiteBox::new(platform))
    }

    /// Build a shim around an existing LiteBox instance. `platform` must be
    /// the same platform used to construct `litebox`.
    pub fn new_with_litebox(platform: &'static P, litebox: LiteBox<P>) -> Self {
        Self {
            platform,
            litebox,
            #[cfg(any(test, feature = "test-stdio"))]
            stdio: None,
        }
    }

    pub fn litebox(&self) -> &LiteBox<P> {
        &self.litebox
    }

    /// Install a test-only local stdio adapter. Without an adapter, no standard
    /// descriptors are installed and I/O returns EBADF.
    #[cfg(any(test, feature = "test-stdio"))]
    #[must_use]
    pub fn with_stdio(mut self, stdio: Arc<dyn Stdio>) -> Self {
        self.stdio = Some(stdio);
        self
    }

    pub fn build(self) -> MacosShim<P> {
        let litebox = Arc::new(self.litebox);
        MacosShim(Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&litebox),
            #[cfg(any(test, feature = "test-stdio"))]
            test_stdio: test_stdio::TestStdio::new(Arc::clone(&litebox), self.stdio),
            _litebox: litebox,
        }))
    }
}

/// One guest address space. Loading consumes the shim; the entrypoints retain
/// its shared global state for the guest's lifetime.
pub struct MacosShim<P: ShimPlatform>(Arc<GlobalState<P>>);

impl<P: ShimPlatform> MacosShim<P> {
    pub fn load_program(
        self,
        params: TaskParams,
        image: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<P>, loader::MachoLoaderError> {
        let initial_ctx = loader::load(&self.0.pm, self.0.platform, image, &argv, &envp)?;
        let process = Process(Arc::new(AtomicI32::new(-1)));
        let task = Task {
            global: self.0,
            params,
            process: process.clone(),
        };
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
    // Retain the LiteBox instance for the lifetime of the address space.
    _litebox: Arc<LiteBox<P>>,
    pm: PageManager<P, PAGE_SIZE>,
    #[cfg(any(test, feature = "test-stdio"))]
    test_stdio: test_stdio::TestStdio<P>,
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
    params: TaskParams,
    process: Process,
}

// Normalize typed syscall handler results for register write-back.
#[cfg(any(test, feature = "test-stdio"))]
trait ToSyscallResult {
    fn to_syscall_result(self) -> Result<usize, Errno>;
}
#[cfg(any(test, feature = "test-stdio"))]
impl ToSyscallResult for Result<(), Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|()| 0)
    }
}
#[cfg(any(test, feature = "test-stdio"))]
impl ToSyscallResult for Result<usize, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self
    }
}
#[cfg(any(test, feature = "test-stdio"))]
impl ToSyscallResult for Result<u32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|v| v as usize)
    }
}

impl<P: ShimPlatform> Task<P> {
    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        // Darwin returns positive errno in x0 with carry set. Success clears
        // carry; x1 and the other condition flags remain unchanged.
        const CARRY: u64 = 1 << 29;
        match self.do_syscall(ctx) {
            Ok(value) => {
                ctx.regs[0] = value;
                ctx.pstate &= !CARRY;
            }
            Err(error) => {
                ctx.regs[0] = error.raw();
                ctx.pstate |= CARRY;
            }
        }
    }

    fn do_syscall(&self, ctx: &PtRegs) -> Result<usize, Errno> {
        let request = SyscallRequest::try_from_raw(ctx.regs[16], ctx, |_| {})?;
        #[cfg(any(test, feature = "test-stdio"))]
        if let Some(result) = self.global.test_stdio.dispatch(self, request) {
            return result;
        }
        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            // No production descriptor provider is installed.
            SyscallRequest::Read { .. }
            | SyscallRequest::Write { .. }
            | SyscallRequest::Close { .. }
            | SyscallRequest::Dup { .. } => Err(Errno::EBADF),
            SyscallRequest::Getpid => Ok(self.sys_getpid().cast_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().cast_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
        }
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
        } else if !ctx.pc.is_multiple_of(4)
            || !ctx.sp.is_multiple_of(16)
            || self
                .check_user_buffer(ctx.pc, 4, Permissions::EXEC)
                .is_err()
        {
            self.process.exit(128 + 11);
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
        self.task.process.exit(128 + 11);
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        // Terminate interrupted guests because guest signal delivery is unsupported.
        self.task.process.exit(128 + 2);
        ContinueOperation::Terminate
    }
}
