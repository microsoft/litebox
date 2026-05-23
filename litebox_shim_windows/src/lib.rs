// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, Ordering};

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox_common_windows::NtSysno;
use litebox_common_windows::loader::{MappingInfo, PAGE_SIZE};
use litebox_platform_multiplex::Platform;

mod loader;

const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;

pub(crate) type WindowsPageManager = PageManager<Platform, PAGE_SIZE>;

pub type DefaultFS = WindowsFS;

pub(crate) type WindowsFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// A trait required for file systems to be used by the Windows shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder {
    litebox: LiteBox<Platform>,
}

impl Default for WindowsShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsShimBuilder {
    #[must_use]
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            litebox: LiteBox::new(platform),
        }
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build a default layered file system with the given in-memory and tar read-only layers.
    #[must_use]
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> WindowsShim<FS> {
        let global = Arc::new(GlobalState {
            page_manager: PageManager::new(&self.litebox),
            _fs: PhantomData,
        });
        WindowsShim(global)
    }
}

pub struct WindowsShim<FS: ShimFS>(Arc<GlobalState<FS>>);

impl<FS: ShimFS> WindowsShim<FS> {
    /// Loads the program at `path` as the shim's initial task.
    ///
    /// TODO: PEB/TEB setup and initial handle table state are not yet implemented.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        _argv: Vec<alloc::ffi::CString>,
        _envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<FS>, loader::WindowsLoadError> {
        let load_info = loader::PeLoader::new(fs, &self.0.page_manager).load(path)?;
        let process = Arc::new(Process {
            ntdll_mapping: load_info.ntdll_mapping,
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        });
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    process: process.clone(),
                    entry_point: load_info.entry_point,
                    stack_top: load_info.stack_top,
                    _phantom: PhantomData,
                },
                _not_send: PhantomData,
            },
            process,
        })
    }
}

/// Global shim state shared by all Windows tasks loaded by this shim.
struct GlobalState<FS: ShimFS> {
    page_manager: WindowsPageManager,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process {
    ntdll_mapping: Option<MappingInfo>,
    exit_code: AtomicI32,
}

impl Process {
    /// Wait for the process to exit, returning its exit code.
    ///
    /// Currently a placeholder that returns a fixed exit code immediately.
    /// Once NT process lifecycle exists, this will actually block.
    #[must_use]
    pub fn wait(&self) -> i32 {
        // TODO: Wait for the NT process object once process lifecycle exists.
        self.exit_code.load(Ordering::Relaxed)
    }
}

struct Task<FS: ShimFS> {
    process: Arc<Process>,
    entry_point: usize,
    stack_top: usize,
    _phantom: PhantomData<FS>,
}

impl<FS: ShimFS> Task<FS> {
    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        ctx.rip = self.entry_point;
        let stack_top_alignment = self.stack_top % 16;
        debug_assert!(stack_top_alignment == 0 || stack_top_alignment == 8);
        ctx.rsp = if stack_top_alignment == 0 {
            self.stack_top - core::mem::size_of::<usize>()
        } else {
            self.stack_top
        };
        ctx.eflags = 0x202;
        ctx.rdx = self
            .process
            .ntdll_mapping
            .as_ref()
            .map_or(0, |mapping| mapping.base_addr);
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Starting initial Windows guest thread"
        );

        ContinueOperation::Resume
    }

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        if NtSysno::from_raw(ctx.orig_rax) != Some(NtSysno::NtTerminateProcess) {
            litebox_util_log::debug!(
                syscall_number = ctx.orig_rax;
                "Unsupported Windows syscall"
            );
            return ContinueOperation::Terminate;
        }

        litebox_util_log::debug!(
            syscall_number = ctx.orig_rax,
            process_handle:% = format_args!("{:#x}", ctx.r10),
            exit_status:% = format_args!("{:#x}", ctx.rdx);
            "Handling NtTerminateProcess syscall"
        );
        self.process
            .exit_code
            .store(windows_exit_status_to_i32(ctx.rdx), Ordering::Relaxed);
        ContinueOperation::Terminate
    }

    fn handle_interrupt_request(
        &self,
        _ctx: &mut litebox_common_linux::PtRegs,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Windows guest interrupt"
        );
        ContinueOperation::Resume
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    _not_send: PhantomData<*const ()>,
}

impl<FS: ShimFS> EnterShim for WindowsShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.init(ctx)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.handle_syscall_request(ctx)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2);
            "Windows guest exception"
        );
        // TODO: Translate hardware exceptions into Windows SEH where appropriate.
        ContinueOperation::Terminate
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.task.handle_interrupt_request(ctx)
    }
}

fn windows_exit_status_to_i32(status: usize) -> i32 {
    let low_bits = u32::try_from(status & 0xffff_ffff).unwrap_or_default();
    i32::from_ne_bytes(low_bits.to_ne_bytes())
}

/// A loaded Windows program and the process handle used to wait for it.
pub struct LoadedProgram<FS: ShimFS> {
    /// The initial-thread entrypoint state passed to the platform's `run_thread`.
    pub entrypoints: WindowsShimEntrypoints<FS>,
    /// Handle used to wait for the loaded program to exit.
    pub process: Arc<Process>,
}

fn default_fs(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> WindowsFS {
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
