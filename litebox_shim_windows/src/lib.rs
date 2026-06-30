// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::{
    CrngProvider, PageManagementProvider, PunchthroughProvider, PunchthroughToken,
    RawConstPointer as _, RawMutPointer as _, RawPointerProvider, StdioProvider,
    SystemInfoProvider, TimeProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_windows::NtSysno;
use litebox_common_windows::loader::{MappingInfo, PAGE_SIZE};

use crate::syscalls::directory::{
    DirectoryHandleObject, DirectoryNamespace, DirectoryObjectSubsystem,
};
use crate::syscalls::event::{EventHandleObject, EventObject, EventSubsystem};
use crate::syscalls::file::{FileObject, FileObjectSubsystem};
use crate::syscalls::iocp::{IoCompletionHandleObject, IoCompletionSubsystem};
use crate::syscalls::registry::{RegistryKeyObject, RegistryKeySubsystem};
use crate::syscalls::symlink::{SymbolicLinkHandleObject, SymbolicLinkSubsystem};
use crate::syscalls::timer::{TimerCreateParameters, TimerHandleObject, TimerSubsystem};
use crate::syscalls::wait_completion_packet::{
    WaitCompletionPacketAssociateParameters, WaitCompletionPacketHandleObject,
    WaitCompletionPacketSubsystem,
};
use crate::syscalls::worker_factory::{
    WorkerFactoryCreateParameters, WorkerFactoryHandleObject, WorkerFactorySubsystem,
};
use crate::syscalls::{SyscallRequest, mm};

mod loader;
mod nt_types;
mod syscalls;

#[cfg(test)]
mod tests;

const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;

/// A LiteBox platform with the services required by the Windows shim.
pub trait ShimPlatform:
    RawSyncPrimitivesProvider
    + RawPointerProvider
    + PageManagementProvider<PAGE_SIZE>
    + SystemInfoProvider
    + TimeProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: RawSyncPrimitivesProvider
        + RawPointerProvider
        + PageManagementProvider<PAGE_SIZE>
        + SystemInfoProvider
        + TimeProvider
        + 'static
{
}

pub(crate) type ConstPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
pub(crate) type MutPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
pub(crate) type WindowsPageManager<Platform> = PageManager<Platform, PAGE_SIZE>;
pub(crate) type WindowsHandleStore<Platform> =
    litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>;
pub(crate) type WindowsNlsSectionMappings<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<(u32, u32), (usize, usize)>>;
pub(crate) type WindowsVirtualAllocations<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsVirtualAllocation>>;
pub(crate) type WindowsEventNamespace<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<String, Weak<EventObject<Platform>>>>;
pub(crate) type WindowsDirectoryNamespace<Platform> = DirectoryNamespace<Platform>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVirtualAllocation {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) allocation_protect: syscalls::mm::PageProtection,
    pub(crate) type_: syscalls::mm::MemoryType,
    pub(crate) pages: rangemap::RangeMap<usize, syscalls::mm::PageProtection>,
}

pub type DefaultFS<Platform> = WindowsFS<Platform>;

pub type WindowsFS<Platform> = litebox::fs::layered::FileSystem<
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

fn write_value<Platform, T>(address: usize, value: T) -> Option<()>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    ptr.write_at_offset(0, value)
}

fn write_field_at_offset<Platform, Struct, Field>(
    base: MutPtr<Platform, Struct>,
    field_offset: usize,
    value: Field,
) -> Option<()>
where
    Platform: RawPointerProvider,
    Struct: zerocopy::FromBytes + zerocopy::IntoBytes,
    Field: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let address = base.as_usize().checked_add(field_offset)?;
    let ptr = MutPtr::<Platform, Field>::from_usize(address);
    ptr.write_at_offset(0, value)
}

fn write_slice<Platform, T>(address: usize, values: &[T]) -> Option<()>
where
    Platform: RawPointerProvider,
    T: Copy + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
        address,
    );
    for (index, value) in values.iter().copied().enumerate() {
        ptr.write_at_offset(index.try_into().ok()?, value)?;
    }
    Some(())
}

pub(crate) fn probe_guest_output_preserving_value<Platform, T>(
    ptr: MutPtr<Platform, T>,
) -> Result<(), NtStatus>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let value = ptr.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)?;
    ptr.write_at_offset(0, value)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

fn set_guest_teb<Platform>(platform: &Platform, teb_address: usize) -> bool
where
    Platform: PunchthroughProvider + RawPointerProvider,
    <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
        Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
    >,
{
    let punchthrough: litebox_common_linux::PunchthroughSyscall<'static, Platform> =
        litebox_common_linux::PunchthroughSyscall::SetFsBase { addr: teb_address };
    let Some(token) = platform.get_punchthrough_token_for(punchthrough) else {
        litebox_util_log::warn!(teb:% = format_args!("{teb_address:#x}"); "Failed to get punchthrough token for Windows TEB base");
        return false;
    };

    if let Err(error) = token.execute() {
        litebox_util_log::warn!(error:? = error, teb:% = format_args!("{teb_address:#x}"); "Failed to set Windows TEB base");
        return false;
    }

    true
}

fn insert_raw_handle<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    typed: litebox::fd::TypedFd<Subsystem>,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) -> Result<syscalls::Handle, NtStatus>
where
    Platform: RawSyncPrimitivesProvider,
{
    let mut handles = handles.write();
    let raw_fd = handles.fd_into_raw_integer(typed);
    let Some(handle) = syscalls::Handle::from_raw_fd(raw_fd) else {
        let typed = handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok();
        drop(handles);
        let entry = typed.and_then(|typed| {
            let mut descriptor_table = litebox.descriptor_table_mut();
            descriptor_table.remove(&typed)
        });
        if let Some(entry) = entry {
            cleanup_entry(entry);
        }
        return Err(NtStatus::QUOTA_EXCEEDED);
    };
    Ok(handle)
}

pub(crate) fn raw_handle_entry<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    handle: syscalls::Handle,
) -> Option<litebox::fd::EntryHandle<Platform, Subsystem>>
where
    Platform: RawSyncPrimitivesProvider,
{
    let raw_fd = handle.raw_fd()?;
    let typed = {
        let handles = handles.read();
        handles.fd_from_raw_integer::<Subsystem>(raw_fd).ok()
    }?;
    litebox.descriptor_table().entry_handle(&typed)
}

fn remove_raw_handle<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    handle: syscalls::Handle,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) where
    Platform: RawSyncPrimitivesProvider,
{
    let Some(raw_fd) = handle.raw_fd() else {
        return;
    };
    let _ =
        remove_raw_handle_by_raw_fd::<Platform, Subsystem>(litebox, handles, raw_fd, cleanup_entry);
}

fn remove_raw_handle_by_raw_fd<Platform, Subsystem: litebox::fd::FdEnabledSubsystem>(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore<Platform>,
    raw_fd: usize,
    cleanup_entry: impl FnOnce(Subsystem::Entry),
) -> bool
where
    Platform: RawSyncPrimitivesProvider,
{
    let typed = {
        let mut handles = handles.write();
        handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok()
    };
    let Some(typed) = typed else {
        return false;
    };
    let entry = {
        let mut descriptor_table = litebox.descriptor_table_mut();
        descriptor_table.remove(&typed)
    };
    if let Some(entry) = entry {
        cleanup_entry(entry);
    }
    true
}

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
}

impl<Platform: ShimPlatform> WindowsShimBuilder<Platform> {
    #[must_use]
    pub fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
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
    ) -> DefaultFS<Platform>
    where
        Platform: CrngProvider + StdioProvider,
    {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> WindowsShim<Platform, FS> {
        let global = Arc::new(GlobalState {
            platform: self.platform,
            page_manager: PageManager::new(&self.litebox),
            registry: syscalls::registry::RegistryStore::new(&self.litebox),
            qpc_boot_instant: TimeProvider::now(self.platform),
            litebox: self.litebox,
            _fs: PhantomData,
        });
        WindowsShim(global)
    }
}

pub struct WindowsShim<Platform: ShimPlatform, FS: ShimFS>(Arc<GlobalState<Platform, FS>>);

impl<Platform: ShimPlatform, FS: ShimFS> WindowsShim<Platform, FS> {
    /// Loads the program at `path` as the shim's initial task.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform, FS>, loader::WindowsLoadError> {
        let load_info = loader::PeLoader::new(self.0.platform, fs.clone(), &self.0.page_manager)
            .load(path, &argv, &envp)?;
        let directory_namespace = syscalls::directory::seed_directory_namespace();
        let process = Arc::new(Process {
            ntdll_mapping: load_info.ntdll_mapping,
            peb_address: load_info.environment.peb,
            handles: WindowsHandleStore::<Platform>::new(litebox::fd::RawDescriptorStorage::new()),
            directory_namespace,
            event_namespace: WindowsEventNamespace::<Platform>::new(BTreeMap::new()),
            nls_section_mappings: WindowsNlsSectionMappings::<Platform>::new(BTreeMap::new()),
            virtual_allocations: load_info.virtual_allocations,
            system_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_ui_language: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            default_hard_error_mode: AtomicU32::new(0),
            cookie: syscalls::process::default_process_cookie(),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        });
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
                    process: process.clone(),
                    fs,
                    entry_point: load_info.entry_point,
                    stack_top: load_info.stack_top,
                    teb_address: load_info.environment.teb,
                    context: load_info.environment.context,
                },
                _not_send: PhantomData,
            },
            process,
        })
    }
}

/// Global shim state shared by all Windows tasks loaded by this shim.
struct GlobalState<Platform: ShimPlatform, FS: ShimFS> {
    platform: &'static Platform,
    page_manager: WindowsPageManager<Platform>,
    registry: syscalls::registry::RegistryStore<Platform>,
    qpc_boot_instant: <Platform as TimeProvider>::Instant,
    litebox: LiteBox<Platform>,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process<Platform: ShimPlatform> {
    ntdll_mapping: Option<MappingInfo>,
    peb_address: usize,
    handles: WindowsHandleStore<Platform>,
    directory_namespace: WindowsDirectoryNamespace<Platform>,
    event_namespace: WindowsEventNamespace<Platform>,
    nls_section_mappings: WindowsNlsSectionMappings<Platform>,
    virtual_allocations: WindowsVirtualAllocations<Platform>,
    system_lcid: AtomicU32,
    user_lcid: AtomicU32,
    user_ui_language: AtomicU32,
    default_hard_error_mode: AtomicU32,
    cookie: u32,
    exit_code: AtomicI32,
}

impl<Platform: ShimPlatform> Process<Platform> {
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

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    process: Arc<Process<Platform>>,
    fs: Arc<FS>,
    entry_point: usize,
    stack_top: usize,
    context: usize,
    teb_address: usize,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation
    where
        Platform: PunchthroughProvider,
        <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
            Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
        >,
    {
        if !set_guest_teb(self.global.platform, self.teb_address) {
            return ContinueOperation::Terminate;
        }

        ctx.rip = self.entry_point;
        debug_assert!(self.stack_top % 16 == core::mem::size_of::<usize>());
        ctx.rsp = self.stack_top;
        ctx.eflags = 0x202;
        ctx.rcx = self.context;
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

    fn typed_handle_entry<Subsystem>(
        &self,
        handle: syscalls::Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<Subsystem>(raw_fd) {
                Ok(typed) => typed,
                Err(litebox::fd::ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_typed_handle<Subsystem>(
        &self,
        entry: Subsystem::Entry,
        cleanup_entry: impl FnOnce(Subsystem::Entry),
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<Subsystem>(entry);
        insert_raw_handle::<Platform, Subsystem>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            cleanup_entry,
        )
    }

    fn close_typed_handle<Subsystem>(
        &self,
        handle: syscalls::Handle,
        cleanup_entry: impl FnOnce(Subsystem::Entry),
    ) where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        remove_raw_handle::<Platform, Subsystem>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            cleanup_entry,
        );
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
            syscall:? = NtSysno::from_raw(ctx.orig_rax);
            "Handling Windows syscall"
        );
        let (result, op) = match req {
            SyscallRequest::NtClose { handle } => {
                let status = self.sys_nt_close(handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateEvent {
                event_handle,
                desired_access,
                object_attributes,
                event_type,
                initial_state,
            } => {
                let status = self.sys_nt_create_event(
                    event_handle,
                    desired_access,
                    object_attributes,
                    event_type,
                    initial_state,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_create_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                    syscalls::Handle::default(),
                    0,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateDirectoryObjectEx {
                directory_handle,
                desired_access,
                object_attributes,
                shadow_directory_handle,
                flags,
            } => {
                let status = self.sys_nt_create_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                    shadow_directory_handle,
                    flags,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDirectoryObject {
                directory_handle,
                buffer,
                buffer_length,
                return_single_entry,
                restart_scan,
                context,
                return_length,
            } => {
                let status = self.sys_nt_query_directory_object(
                    syscalls::directory::DirectoryQueryParameters {
                        directory_handle,
                        buffer,
                        buffer_length,
                        return_single_entry,
                        restart_scan,
                        context,
                        return_length,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
                link_target,
            } => {
                let status = self.sys_nt_create_symbolic_link_object(
                    link_handle,
                    desired_access,
                    object_attributes,
                    link_target,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_open_symbolic_link_object(
                    link_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySymbolicLinkObject {
                link_handle,
                link_target,
                returned_length,
            } => {
                let status = self.sys_nt_query_symbolic_link_object(
                    link_handle,
                    link_target,
                    returned_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateIoCompletion {
                io_completion_handle,
                desired_access,
                object_attributes,
                number_of_concurrent_threads,
            } => {
                let status = self.sys_nt_create_io_completion(
                    io_completion_handle,
                    desired_access,
                    object_attributes,
                    number_of_concurrent_threads,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWaitCompletionPacket {
                wait_completion_packet_handle,
                desired_access,
                object_attributes,
            } => {
                let status = self.sys_nt_create_wait_completion_packet(
                    wait_completion_packet_handle,
                    desired_access,
                    object_attributes,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAssociateWaitCompletionPacket {
                wait_completion_packet_handle,
                io_completion_handle,
                target_object_handle,
                key_context,
                apc_context,
                io_status,
                io_status_information,
                already_signaled,
            } => {
                let status = self.sys_nt_associate_wait_completion_packet(
                    WaitCompletionPacketAssociateParameters {
                        wait_completion_packet_handle,
                        io_completion_handle,
                        target_object_handle,
                        key_context,
                        apc_context,
                        io_status,
                        io_status_information,
                        already_signaled,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCancelWaitCompletionPacket {
                wait_completion_packet_handle,
                remove_signaled_packet,
            } => {
                let status = self.sys_nt_cancel_wait_completion_packet(
                    wait_completion_packet_handle,
                    remove_signaled_packet,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWorkerFactory {
                worker_factory_handle,
                desired_access,
                object_attributes,
                completion_port_handle,
                worker_process_handle,
                start_routine,
                start_parameter,
                max_thread_count,
                stack_reserve,
                stack_commit,
            } => {
                let status = self.sys_nt_create_worker_factory(WorkerFactoryCreateParameters {
                    worker_factory_handle,
                    desired_access,
                    object_attributes,
                    completion_port_handle,
                    worker_process_handle,
                    start_routine,
                    start_parameter,
                    max_thread_count,
                    stack_reserve,
                    stack_commit,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetInformationWorkerFactory {
                worker_factory_handle,
                worker_factory_information_class,
                worker_factory_information,
                worker_factory_information_length,
            } => {
                let status = self.sys_nt_set_information_worker_factory(
                    worker_factory_handle,
                    worker_factory_information_class,
                    worker_factory_information,
                    worker_factory_information_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtShutdownWorkerFactory {
                worker_factory_handle,
                pending_worker_count,
            } => {
                let status = self
                    .sys_nt_shutdown_worker_factory(worker_factory_handle, pending_worker_count);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateTimer2 {
                timer_handle,
                timer_id,
                object_attributes,
                attributes,
                desired_access,
            } => {
                let status = self.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle,
                    timer_id,
                    object_attributes,
                    attributes,
                    desired_access,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetTimer2 {
                timer_handle,
                due_time,
                period,
                parameters,
            } => {
                let status = self.sys_nt_set_timer2(timer_handle, due_time, period, parameters);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenEvent {
                event_handle,
                desired_access,
                object_attributes,
            } => {
                let status =
                    self.sys_nt_open_event(event_handle, desired_access, object_attributes);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_set_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtResetEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_reset_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtClearEvent { event_handle } => {
                let status = self.sys_nt_clear_event(event_handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtPulseEvent {
                event_handle,
                previous_state,
            } => {
                let status = self.sys_nt_pulse_event(event_handle, previous_state);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryEvent {
                event_handle,
                event_information_class,
                event_information,
                event_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_event(
                    event_handle,
                    event_information_class,
                    event_information,
                    event_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetEventBoostPriority { event_handle } => {
                let status = self.sys_nt_set_event_boost_priority(event_handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenFile {
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                share_access,
                open_options,
            } => {
                let status = self.sys_nt_open_file(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    share_access,
                    open_options,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateFile {
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                allocation_size,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea_buffer,
                ea_length,
            } => {
                let status = self.sys_nt_create_file(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    allocation_size,
                    file_attributes,
                    share_access,
                    create_disposition,
                    create_options,
                    ea_buffer,
                    ea_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryVolumeInformationFile {
                file_handle,
                io_status_block,
                fs_information,
                length,
                fs_information_class,
            } => {
                let status = self.sys_nt_query_volume_information_file(
                    file_handle,
                    io_status_block,
                    fs_information,
                    length,
                    fs_information_class,
                );
                (status, ContinueOperation::Resume)
            }
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
            SyscallRequest::NtGetNlsSectionPtr {
                section_type,
                section_data,
                context_data,
                section_pointer,
                section_size,
            } => {
                let status = self.sys_nt_get_nls_section_ptr(
                    section_type,
                    section_data,
                    context_data,
                    section_pointer,
                    section_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtInitializeNlsFiles {
                base_address,
                default_locale_id,
                default_casing_table_size,
            } => {
                let status = self.sys_nt_initialize_nls_files(
                    base_address,
                    default_locale_id,
                    default_casing_table_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDefaultLocale {
                user_profile,
                default_locale_id,
            } => {
                let status = self.sys_nt_query_default_locale(user_profile, default_locale_id);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetDefaultLocale {
                user_profile,
                default_locale_id,
            } => {
                let status = self.sys_nt_set_default_locale(user_profile, default_locale_id);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryDefaultUILanguage {
                default_ui_language,
            } => {
                let status = self.sys_nt_query_default_ui_language(default_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetDefaultUILanguage {
                default_ui_language,
            } => {
                let status = self.sys_nt_set_default_ui_language(default_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInstallUILanguage {
                install_ui_language,
            } => {
                let status = self.sys_nt_query_install_ui_language(install_ui_language);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryPerformanceCounter {
                performance_counter,
                performance_frequency,
            } => {
                let status = self
                    .sys_nt_query_performance_counter(performance_counter, performance_frequency);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySystemInformation {
                system_information_class,
                system_information,
                system_information_length,
                return_length,
            } => {
                let status = Self::sys_nt_query_system_information(
                    system_information_class,
                    system_information,
                    system_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySystemInformationEx {
                system_information_class,
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            } => {
                let status = Self::sys_nt_query_system_information_ex(
                    system_information_class,
                    input_buffer,
                    input_buffer_length,
                    system_information,
                    system_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_information_process(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
            } => {
                let status = Self::sys_nt_set_information_process(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSetInformationThread {
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
            } => {
                let status = Self::sys_nt_set_information_thread(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
                flag,
                source,
                destination,
                conversion_error,
            } => {
                let status = Self::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    flag,
                    source,
                    destination,
                    conversion_error,
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
                let status = self.sys_nt_allocate_virtual_memory(
                    process_handle,
                    base_address,
                    zero_bits,
                    region_size,
                    allocation_type,
                    protect,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtAllocateVirtualMemoryEx {
                process_handle,
                base_address,
                region_size,
                allocation_type,
                protect,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.sys_nt_allocate_virtual_memory_ex(
                    process_handle,
                    base_address,
                    region_size,
                    allocation_type,
                    protect,
                    mm::MemoryExtendedParameters {
                        parameters: extended_parameters,
                        count: extended_parameter_count,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtFreeVirtualMemory {
                process_handle,
                base_address,
                region_size,
                free_type,
            } => {
                let status = self.sys_nt_free_virtual_memory(
                    process_handle,
                    base_address,
                    region_size,
                    free_type,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtProtectVirtualMemory {
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            } => {
                let status = self.sys_nt_protect_virtual_memory(
                    process_handle,
                    base_address,
                    region_size,
                    new_protect,
                    old_protect,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryVirtualMemory {
                process_handle,
                base_address,
                memory_information_class,
                memory_information,
                memory_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_virtual_memory(
                    process_handle,
                    base_address,
                    memory_information_class,
                    memory_information,
                    memory_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
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
            SyscallRequest::NtManageHotPatch => {
                (NtStatus::NOT_IMPLEMENTED, ContinueOperation::Resume)
            }
        };

        ctx.rax = result.as_raw().cast_unsigned() as usize;
        op
    }

    pub(crate) fn sys_nt_close(&self, handle: syscalls::Handle) -> NtStatus {
        let Some(raw_fd) = handle.raw_fd() else {
            return NtStatus::INVALID_HANDLE;
        };
        self.close_raw_fd(raw_fd, CloseRawHandleVisitor { task: self })
    }

    fn close_raw_fd(
        &self,
        raw_fd: usize,
        visitor: impl RawHandleVisitor<Platform, FS>,
    ) -> NtStatus {
        if remove_raw_handle_by_raw_fd::<Platform, FileObjectSubsystem<FS>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |file| visitor.file(file),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, RegistryKeySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |key| visitor.registry_key(key),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |event| visitor.event(event),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |directory| visitor.directory(directory),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, SymbolicLinkSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |link| visitor.symbolic_link(link),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, IoCompletionSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |io_completion| visitor.io_completion(io_completion),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, TimerSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |timer| visitor.timer(timer),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, WaitCompletionPacketSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |wait_completion_packet| visitor.wait_completion_packet(wait_completion_packet),
        ) {
            return NtStatus::SUCCESS;
        }
        if remove_raw_handle_by_raw_fd::<Platform, WorkerFactorySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            raw_fd,
            |worker_factory| visitor.worker_factory(worker_factory),
        ) {
            return NtStatus::SUCCESS;
        }
        NtStatus::INVALID_HANDLE
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

trait RawHandleVisitor<Platform: ShimPlatform, FS: ShimFS> {
    fn file(&self, file: FileObject<FS>);

    fn registry_key(&self, key: RegistryKeyObject<Platform>);

    fn event(&self, event: EventHandleObject<Platform>);

    fn directory(&self, directory: DirectoryHandleObject<Platform>);

    fn symbolic_link(&self, link: SymbolicLinkHandleObject<Platform>);

    fn io_completion(&self, io_completion: IoCompletionHandleObject<Platform>);

    fn timer(&self, timer: TimerHandleObject<Platform>);

    fn wait_completion_packet(
        &self,
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    );

    fn worker_factory(&self, worker_factory: WorkerFactoryHandleObject<Platform>);
}

struct CloseRawHandleVisitor<'task, Platform: ShimPlatform, FS: ShimFS> {
    task: &'task Task<Platform, FS>,
}

impl<Platform: ShimPlatform, FS: ShimFS> RawHandleVisitor<Platform, FS>
    for CloseRawHandleVisitor<'_, Platform, FS>
{
    fn file(&self, file: FileObject<FS>) {
        self.task.close_file(file);
    }

    fn registry_key(&self, key: RegistryKeyObject<Platform>) {
        self.task.close_registry_key(key);
    }

    fn event(&self, event: EventHandleObject<Platform>) {
        Task::<Platform, FS>::close_event(event);
    }

    fn directory(&self, directory: DirectoryHandleObject<Platform>) {
        Task::<Platform, FS>::close_directory(directory);
    }

    fn symbolic_link(&self, link: SymbolicLinkHandleObject<Platform>) {
        Task::<Platform, FS>::close_symbolic_link(link);
    }

    fn io_completion(&self, io_completion: IoCompletionHandleObject<Platform>) {
        Task::<Platform, FS>::close_io_completion(io_completion);
    }

    fn timer(&self, timer: TimerHandleObject<Platform>) {
        Task::<Platform, FS>::close_timer(timer);
    }

    fn wait_completion_packet(
        &self,
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    ) {
        Task::<Platform, FS>::close_wait_completion_packet(wait_completion_packet);
    }

    fn worker_factory(&self, worker_factory: WorkerFactoryHandleObject<Platform>) {
        Task::<Platform, FS>::close_worker_factory(worker_factory);
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
    _not_send: PhantomData<*const ()>,
}

impl<Platform, FS> EnterShim for WindowsShimEntrypoints<Platform, FS>
where
    Platform: ShimPlatform + PunchthroughProvider,
    <Platform as PunchthroughProvider>::PunchthroughToken<'static>: PunchthroughToken<
        Punchthrough = litebox_common_linux::PunchthroughSyscall<'static, Platform>,
    >,
    FS: ShimFS,
{
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
pub struct LoadedProgram<Platform: ShimPlatform, FS: ShimFS> {
    /// The initial-thread entrypoint state passed to the platform's `run_thread`.
    pub entrypoints: WindowsShimEntrypoints<Platform, FS>,
    /// Handle used to wait for the loaded program to exit.
    pub process: Arc<Process<Platform>>,
}

fn default_fs<Platform>(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> WindowsFS<Platform>
where
    Platform: ShimPlatform + CrngProvider + StdioProvider,
{
    let devices = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            devices,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}
