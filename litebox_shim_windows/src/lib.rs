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
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox_common_windows::NtSysno;
use litebox_common_windows::loader::{MappingInfo, PAGE_SIZE};
use litebox_platform_multiplex::Platform;

use crate::syscalls::SyscallRequest;

mod loader;
mod nt_types;
mod syscalls;

#[cfg(test)]
mod tests;

const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;

pub(crate) type ConstPtr<T> =
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
pub(crate) type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
pub(crate) type WindowsPageManager = PageManager<Platform, PAGE_SIZE>;
pub(crate) type WindowsHandleStore =
    litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>;

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

fn write_value<T>(address: usize, value: T) -> Option<()>
where
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    ptr.write_at_offset(0, value)
}

fn write_slice<T>(address: usize, values: &[T]) -> Option<()>
where
    T: Copy + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    for (index, value) in values.iter().copied().enumerate() {
        ptr.write_at_offset(index.try_into().ok()?, value)?;
    }
    Some(())
}

pub(crate) fn insert_raw_handle<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    typed: litebox::fd::TypedFd<Subsystem>,
) -> Result<syscalls::Handle, NtStatus> {
    let mut handles = handles.write();
    let raw_fd = handles.fd_into_raw_integer(typed);
    let Some(handle) = syscalls::Handle::from_raw_fd(raw_fd) else {
        let typed = handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok();
        drop(handles);
        if let Some(typed) = typed {
            let _ = litebox.descriptor_table_mut().remove(&typed);
        }
        return Err(NtStatus::QUOTA_EXCEEDED);
    };
    Ok(handle)
}

pub(crate) fn raw_handle_entry<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    handle: syscalls::Handle,
) -> Option<litebox::fd::EntryHandle<Platform, Subsystem>> {
    let raw_fd = handle.raw_fd()?;
    let typed = {
        let handles = handles.read();
        handles.fd_from_raw_integer::<Subsystem>(raw_fd).ok()
    }?;
    litebox.descriptor_table().entry_handle(&typed)
}

pub(crate) fn remove_raw_handle<Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    handle: syscalls::Handle,
) {
    let Some(raw_fd) = handle.raw_fd() else {
        return;
    };
    let typed = {
        let mut handles = handles.write();
        handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok()
    };
    if let Some(typed) = typed {
        let _ = litebox.descriptor_table_mut().remove(&typed);
    }
}

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
            registry: syscalls::registry::RegistryStore::new(&self.litebox),
            litebox: self.litebox,
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
            handles: WindowsHandleStore::new(litebox::fd::RawDescriptorStorage::new()),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        });
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
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
    registry: syscalls::registry::RegistryStore,
    litebox: LiteBox<Platform>,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process {
    ntdll_mapping: Option<MappingInfo>,
    handles: WindowsHandleStore,
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
    global: Arc<GlobalState<FS>>,
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
        let Some(req) = SyscallRequest::<Platform>::try_from_raw(ctx) else {
            litebox_util_log::debug!(
                syscall:? = NtSysno::from_raw(ctx.orig_rax);
                "Unsupported Windows syscall"
            );
            return ContinueOperation::Terminate;
        };
        litebox_util_log::debug!(
            syscall:? = req;
            "Handling Windows"
        );
        let (result, op) = match req {
            SyscallRequest::NtOpenKey {
                key_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_key(key_handle, desired_access, object_attributes);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryValueKey {
                key_handle,
                value_name,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            } => {
                let status = self.sys_nt_query_value_key(
                    key_handle,
                    value_name,
                    key_value_information_class,
                    key_value_information,
                    length,
                    result_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAllocateVirtualMemory {
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            } => {
                // TODO: placeholder for NtAllocateVirtualMemory
                litebox_util_log::debug!(
                    process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
                    base_address:% = format_args!("{:#x}", base_address.as_usize()),
                    zero_bits:% = format_args!("{:#x}", zero_bits),
                    region_size:% = format_args!("{:#x}", region_size.as_usize()),
                    allocation_type:% = format_args!("{:#x}", allocation_type),
                    protect:% = format_args!("{:#x}", protect);
                    "Handling NtAllocateVirtualMemory syscall"
                );
                (NtStatus::UNSUCCESSFUL, ContinueOperation::Terminate)
            }
            SyscallRequest::NtTerminateProcess {
                process_handle,
                exit_status,
            } => {
                if !process_handle.is_null() && !process_handle.is_current() {
                    // TODO: allow terminating other processes
                    litebox_util_log::error!("Terminating other processes is not yet supported");
                    (NtStatus::INVALID_HANDLE, ContinueOperation::Resume)
                } else {
                    // TODO: Terminate all threads except the calling one if process_handle is zero.
                    self.process.exit_code.store(exit_status, Ordering::Relaxed);
                    (NtStatus::SUCCESS, ContinueOperation::Terminate)
                }
            }
        };

        ctx.rax = result.as_raw().cast_unsigned() as usize;
        op
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
