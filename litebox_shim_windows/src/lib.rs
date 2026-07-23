// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::{
    ArchSpecificProvider, ArchSpecificRegister, CrngProvider, PageManagementProvider,
    RawConstPointer as _, RawMutPointer as _, RawPointerProvider, StdioProvider,
    SystemInfoProvider, TimeProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_windows::NtSysno;
use litebox_common_windows::loader::{MappingInfo, PAGE_SIZE};

use crate::syscalls::event::{EventHandleObject, EventSubsystem};
use crate::syscalls::file::{FileObject, FileObjectSubsystem};
use crate::syscalls::iocp::{IoCompletionHandleObject, IoCompletionSubsystem};
use crate::syscalls::lpc::{LpcPortHandleObject, LpcPortSubsystem};
use crate::syscalls::object_manager::{
    DirectoryHandleObject, DirectoryObjectSubsystem, ObjectManager,
};
use crate::syscalls::registry::{RegistryKeyObject, RegistryKeySubsystem};
use crate::syscalls::section::{
    MapViewOfSectionParameters, SectionHandleObject, SectionObject, SectionSubsystem,
};
use crate::syscalls::symlink::{SymbolicLinkHandleObject, SymbolicLinkSubsystem};
use crate::syscalls::timer::{TimerCreateParameters, TimerHandleObject, TimerSubsystem};
use crate::syscalls::token::{TokenHandleObject, TokenObject, TokenSubsystem};
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
    + ArchSpecificProvider
    + SystemInfoProvider
    + TimeProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: RawSyncPrimitivesProvider
        + RawPointerProvider
        + PageManagementProvider<PAGE_SIZE>
        + ArchSpecificProvider
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

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DuplicateOptions: u32 {
        const CLOSE_SOURCE = 0x0000_0001;
        const SAME_ACCESS = 0x0000_0002;
        const SAME_ATTRIBUTES = 0x0000_0004;

        const _ = !0;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct HandleAttributes: u32 {
        const PROTECT_FROM_CLOSE = 0x0000_0001;
        const INHERIT = 0x0000_0002;
        const AUDIT_OBJECT_CLOSE = 0x0000_0004;
        const HANDLE_BEHAVIOR_ATTRIBUTES = Self::PROTECT_FROM_CLOSE.bits()
            | Self::INHERIT.bits()
            | Self::AUDIT_OBJECT_CLOSE.bits();

        const _ = !0;
    }
}

impl HandleAttributes {
    fn from_token_open_attributes(attributes: u32) -> Option<Self> {
        const OBJ_EXCLUSIVE: u32 = 0x20;
        const OBJ_OPENLINK: u32 = 0x100;

        // NtOpenProcessTokenEx accepts and ignores unrelated object attributes, but native
        // Windows rejects the two attributes that cannot apply to opening an existing token.
        if attributes & (OBJ_EXCLUSIVE | OBJ_OPENLINK) != 0 {
            return None;
        }
        Some(Self::from_bits_retain(
            attributes & Self::HANDLE_BEHAVIOR_ATTRIBUTES.bits(),
        ))
    }

    fn from_duplicate_attributes(attributes: u32) -> Option<Self> {
        const OBJ_EXCLUSIVE: u32 = 0x20;

        // Native NtDuplicateObject accepts and ignores unrelated object attributes, but an
        // exclusive duplicate is invalid because the object already has an open handle.
        if attributes & OBJ_EXCLUSIVE != 0 {
            return None;
        }
        Some(Self::from_bits_retain(
            attributes & Self::HANDLE_BEHAVIOR_ATTRIBUTES.bits(),
        ))
    }
}

#[derive(Clone, Copy, Default)]
struct WindowsHandleMetadata {
    granted_access: u32,
    attributes: HandleAttributes,
}

pub(crate) trait WindowsHandleSubsystem: litebox::fd::FdEnabledSubsystem {
    fn normalize_desired_access(desired_access: u32) -> u32;

    fn resolve_duplicate_access(
        _entry: &Self::Entry,
        desired_access: u32,
    ) -> Result<u32, NtStatus> {
        let maximum_allowed = desired_access & nt_types::AccessMask::MAXIMUM_ALLOWED.bits() != 0;
        let explicit_access = desired_access & !nt_types::AccessMask::MAXIMUM_ALLOWED.bits();
        let normalized = Self::normalize_desired_access(explicit_access);
        Ok(if maximum_allowed {
            // TODO(dacl-access-check): Derive this grant from the caller's token and the
            // object's security descriptor instead of assuming a single trust context.
            normalized | Self::normalize_desired_access(nt_types::AccessMask::GENERIC_ALL.bits())
        } else {
            normalized
        })
    }
}
pub(crate) type WindowsNlsSectionMappings<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<(u32, u32), (usize, usize)>>;
pub(crate) type WindowsVirtualAllocations<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsVirtualAllocation>>;
pub(crate) type WindowsSectionViews<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsSectionView<Platform>>>;
pub(crate) type WindowsObjectManager<Platform> = ObjectManager<Platform>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVirtualAllocation {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) allocation_protect: syscalls::mm::PageProtection,
    pub(crate) type_: syscalls::mm::MemoryType,
    pub(crate) pages: rangemap::RangeMap<usize, syscalls::mm::PageProtection>,
}

pub(crate) struct WindowsSectionView<Platform: ShimPlatform> {
    pub(crate) size: usize,
    pub(crate) section_offset: usize,
    pub(crate) section: Option<Arc<SectionObject<Platform>>>,
}

impl<Platform: ShimPlatform> Clone for WindowsSectionView<Platform> {
    fn clone(&self) -> Self {
        Self {
            size: self.size,
            section_offset: self.section_offset,
            section: self.section.clone(),
        }
    }
}

pub type DefaultFS<Platform> = WindowsFS<Platform>;

pub type WindowsFS<Platform> = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
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

fn read_field_at_offset<Platform, Field>(base: usize, field_offset: usize) -> Option<Field>
where
    Platform: RawPointerProvider,
    Field: zerocopy::FromBytes,
{
    let address = base.checked_add(field_offset)?;
    let ptr = ConstPtr::<Platform, Field>::from_usize(address);
    ptr.read_at_offset(0)
}

fn write_field_at_offset<Platform, Field>(
    base: usize,
    field_offset: usize,
    value: Field,
) -> Option<()>
where
    Platform: RawPointerProvider,
    Field: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let address = base.checked_add(field_offset)?;
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

pub(crate) fn probe_guest_output_buffer<Platform>(
    buffer: MutPtr<Platform, u8>,
    buffer_length: usize,
) -> Result<(), NtStatus>
where
    Platform: RawPointerProvider,
{
    if buffer_length == 0 {
        return Ok(());
    }
    probe_guest_output_preserving_value::<Platform, u8>(buffer)?;
    let last_offset = isize::try_from(buffer_length - 1).map_err(|_| NtStatus::ACCESS_VIOLATION)?;
    let value = buffer
        .read_at_offset(last_offset)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    buffer
        .write_at_offset(last_offset, value)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

fn set_guest_teb<Platform: ArchSpecificProvider>(platform: &Platform, teb_address: usize) -> bool {
    if let Err(error) =
        platform.set_arch_specific_register(&ArchSpecificRegister::FsBase, teb_address)
    {
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
        tar_data: Cow<'static, [u8]>,
    ) -> DefaultFS<Platform>
    where
        Platform: CrngProvider + StdioProvider,
    {
        default_fs(&self.litebox, in_mem_fs, tar_data)
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> WindowsShim<Platform, FS> {
        let global = Arc::new(GlobalState {
            platform: self.platform,
            page_manager: PageManager::new(&self.litebox),
            registry: syscalls::registry::RegistryStore::new(&self.litebox),
            wnf_states: syscalls::wnf::WnfStateStore::new(
                syscalls::wnf::WnfStateStoreData::default(),
            ),
            qpc_boot_instant: TimeProvider::now(self.platform),
            litebox: self.litebox,
            _fs: PhantomData,
        });
        WindowsShim(global)
    }
}

/// Wine and ReactOS model KUSER_SHARED_DATA as a fixed user page at
/// 0x7FFE0000. Native Windows hosts already provide that page; Non-Windows hosts
/// need LiteBox to create it before guest ntdll reads it during startup.
#[cfg(not(target_os = "windows"))]
const WINDOWS_USER_SHARED_DATA_BASE: usize = 0x7FFE_0000;

#[cfg(not(target_os = "windows"))]
fn map_windows_user_shared_data<Platform: crate::ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
) -> Option<usize> {
    use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
    use zerocopy::IntoBytes as _;
    let address = NonZeroAddress::new(WINDOWS_USER_SHARED_DATA_BASE)?;
    let length =
        NonZeroPageSize::new(size_of::<nt_types::KUserSharedData>().next_multiple_of(PAGE_SIZE))?;
    let shared_data = windows_user_shared_data();
    let shared_data_bytes = shared_data.as_bytes();
    // SAFETY: `NOREPLACE` makes the fixed mapping fail instead of replacing any
    // existing host or guest mapping at the shared-data address.
    unsafe {
        page_manager.create_readable_pages(
            Some(address),
            length,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            |ptr| {
                ptr.copy_from_slice(0, shared_data_bytes)
                    .ok_or(MappingError::OutOfMemory)?;
                Ok(0)
            },
        )
    }
    .map(|ptr| ptr.as_usize())
    .ok()
}

// TODO: This is a temporary placeholder for the Windows shared data page.
// Once we have a proper shared mapping implementation, we can remove this
// and instead map the shared data page from the host into the guest.
#[cfg(not(target_os = "windows"))]
fn windows_user_shared_data() -> nt_types::KUserSharedData {
    use zerocopy::FromZeros as _;
    let mut shared_data = nt_types::KUserSharedData::new_zeroed();
    shared_data.nt_build_number = u32::from(syscalls::sysinfo::WINDOWS_OS_BUILD_NUMBER);
    shared_data.nt_product_type = syscalls::sysinfo::WINDOWS_NT_PRODUCT_WORKSTATION;
    shared_data.product_type_is_valid = 1;
    shared_data.nt_major_version = u32::from(syscalls::sysinfo::WINDOWS_OS_MAJOR_VERSION);
    shared_data.nt_minor_version = u32::from(syscalls::sysinfo::WINDOWS_OS_MINOR_VERSION);
    for (index, code_unit) in r"C:\Windows".encode_utf16().enumerate() {
        shared_data.nt_system_root[index] = code_unit;
    }

    shared_data
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
        // TODO: refactor the shared mapping
        #[cfg(not(target_os = "windows"))]
        let _ = map_windows_user_shared_data::<Platform>(&self.0.page_manager)
            .ok_or(loader::WindowsLoadError::MapSharedMemory)?;
        let load_info = loader::PeLoader::new(self.0.platform, fs.clone(), &self.0.page_manager)
            .load(path, &argv, &envp)?;
        // TODO: shared section should be only created once and shared across all processes, not created per-process.
        let windows_shared_section = crate::syscalls::section::load_time_windows_shared_section(
            load_info.environment.windows_shared_section,
        );
        let mut process =
            Process::default(Some(load_info.virtual_allocations), windows_shared_section);
        process.ntdll_mapping = load_info.ntdll_mapping;
        process.peb_address = load_info.environment.peb;
        let process = Arc::new(process);
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
    wnf_states: syscalls::wnf::WnfStateStore<Platform>,
    qpc_boot_instant: <Platform as TimeProvider>::Instant,
    litebox: LiteBox<Platform>,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process<Platform: ShimPlatform> {
    ntdll_mapping: Option<MappingInfo>,
    peb_address: usize,
    handles: WindowsHandleStore<Platform>,
    token: Arc<TokenObject>,
    condrv_console: syscalls::condrv::CondrvConsole<Platform>,
    object_manager: WindowsObjectManager<Platform>,
    section_views: WindowsSectionViews<Platform>,
    // TODO: move this into `GlobalState` once we have a proper shared mapping implementation.
    #[expect(
        dead_code,
        reason = "keeps alive the section registered weakly in the object namespace"
    )]
    windows_shared_section: Arc<SectionObject<Platform>>,
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

    fn default(
        virtual_allocations: Option<WindowsVirtualAllocations<Platform>>,
        windows_shared_section: Arc<SectionObject<Platform>>,
    ) -> Self {
        let object_manager = syscalls::object_manager::seed_object_manager();
        let status = object_manager.create_section(
            syscalls::section::WINDOWS_SESSION_SHARED_SECTION_OBJECT,
            &windows_shared_section,
        );
        assert!(
            status == NtStatus::SUCCESS,
            "seeded Windows shared section must have seeded ancestors: {status:?}"
        );
        Process {
            ntdll_mapping: None,
            peb_address: 0,
            handles: WindowsHandleStore::<Platform>::new(litebox::fd::RawDescriptorStorage::new()),
            token: Arc::new(TokenObject::primary()),
            // TODO(condrv-shared-console): move console ownership to shared state or a broker when
            // LiteBox supports AttachConsole/IOCTL_CONDRV_BIND_PID across guest processes.
            condrv_console: syscalls::condrv::CondrvConsole::new(),
            object_manager,
            windows_shared_section,
            section_views: WindowsSectionViews::<Platform>::new(BTreeMap::new()),
            nls_section_mappings: WindowsNlsSectionMappings::<Platform>::new(BTreeMap::new()),
            virtual_allocations: virtual_allocations
                .unwrap_or_else(|| WindowsVirtualAllocations::<Platform>::new(BTreeMap::new())),
            system_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_ui_language: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            default_hard_error_mode: AtomicU32::new(0),
            cookie: syscalls::process::default_process_cookie(),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
        }
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
    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        if !set_guest_teb(self.global.platform, self.teb_address) {
            return ContinueOperation::Terminate;
        }

        ctx.rip = self.entry_point;
        debug_assert_eq!(self.stack_top % 16, core::mem::size_of::<usize>());
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
        let typed = self.typed_handle::<Subsystem>(handle)?;
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn typed_handle_entry_with_access<Subsystem>(
        &self,
        handle: syscalls::Handle,
        required_access: u32,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = self.typed_handle::<Subsystem>(handle)?;
        self.require_typed_handle_access(&typed, required_access)?;
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn typed_handle<Subsystem>(
        &self,
        handle: syscalls::Handle,
    ) -> Result<Arc<litebox::fd::TypedFd<Subsystem>>, NtStatus>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let handles = self.process.handles.read();
        match handles.fd_from_raw_integer::<Subsystem>(raw_fd) {
            Ok(typed) => Ok(typed),
            Err(litebox::fd::ErrRawIntFd::NotFound) => Err(NtStatus::INVALID_HANDLE),
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        }
    }

    fn typed_handle_metadata<Subsystem>(
        &self,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<WindowsHandleMetadata, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        self.global
            .litebox
            .descriptor_table()
            .with_metadata::<Subsystem, WindowsHandleMetadata, _>(typed, |metadata| *metadata)
            .map_err(|_| NtStatus::INVALID_HANDLE)
    }

    pub(crate) fn require_handle_access<Subsystem>(
        &self,
        handle: syscalls::Handle,
        required_access: u32,
    ) -> Result<(), NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = self.typed_handle::<Subsystem>(handle)?;
        self.require_typed_handle_access(&typed, required_access)
    }

    pub(crate) fn require_typed_handle_access<Subsystem>(
        &self,
        typed: &litebox::fd::TypedFd<Subsystem>,
        required_access: u32,
    ) -> Result<(), NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        if self.typed_handle_metadata(typed)?.granted_access & required_access == required_access {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }

    fn insert_typed_handle<Subsystem>(
        &self,
        entry: Subsystem::Entry,
        granted_access: u32,
        cleanup_entry: impl FnOnce(Subsystem::Entry),
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        self.insert_typed_handle_with_attributes::<Subsystem>(
            entry,
            granted_access,
            HandleAttributes::empty(),
            cleanup_entry,
        )
    }

    fn insert_typed_handle_with_attributes<Subsystem>(
        &self,
        entry: Subsystem::Entry,
        granted_access: u32,
        attributes: HandleAttributes,
        cleanup_entry: impl FnOnce(Subsystem::Entry),
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            let typed = descriptors.insert::<Subsystem>(entry);
            let old = descriptors.set_fd_metadata(
                &typed,
                WindowsHandleMetadata {
                    granted_access,
                    attributes,
                },
            );
            debug_assert!(old.is_none());
            typed
        };
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
            let caller = ConstPtr::<Platform, usize>::from_usize(ctx.rsp)
                .read_at_offset(0)
                .unwrap_or_default();
            litebox_util_log::error!(
                syscall:? = NtSysno::from_raw(ctx.orig_rax),
                rip:% = format_args!("{:#x}", ctx.rip),
                caller:% = format_args!("{caller:#x}"),
                arg0:% = format_args!("{:#x}", ctx.r10),
                arg1:% = format_args!("{:#x}", ctx.rdx),
                arg2:% = format_args!("{:#x}", ctx.r8),
                arg3:% = format_args!("{:#x}", ctx.r9);
                "Unsupported Windows syscall; terminating Windows guest"
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
            SyscallRequest::NtDuplicateObject {
                source_process_handle,
                source_handle,
                target_process_handle,
                target_handle,
                desired_access,
                handle_attributes,
                options,
            } => {
                let status = self.sys_nt_duplicate_object(
                    source_process_handle,
                    source_handle,
                    target_process_handle,
                    target_handle,
                    desired_access,
                    handle_attributes,
                    options,
                );
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
            SyscallRequest::NtOpenSection {
                section_handle,
                desired_access,
                object_attributes,
            } => {
                let status =
                    self.sys_nt_open_section(section_handle, desired_access, object_attributes);
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
                    syscalls::object_manager::DirectoryQueryParameters {
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
            SyscallRequest::NtConnectPort {
                port_handle,
                port_name,
                security_qos,
                client_view,
                server_view,
                max_message_length,
                connection_information,
                connection_information_length,
            } => {
                let status = self.sys_nt_connect_port(syscalls::lpc::ConnectPortParameters {
                    port_handle,
                    port_name,
                    security_qos,
                    client_view,
                    server_view,
                    max_message_length,
                    connection_information,
                    connection_information_length,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtSecureConnectPort => {
                litebox_util_log::debug!(
                    "Rejected NtSecureConnectPort; only the CSR NtConnectPort subset is modeled"
                );
                (NtStatus::NOT_SUPPORTED, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSection {
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
            } => {
                let status = self.sys_nt_create_section(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateSectionEx {
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.sys_nt_create_section_ex(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                    extended_parameters,
                    extended_parameter_count,
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
            SyscallRequest::NtDeviceIoControlFile {
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                io_control_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
            } => {
                let status = self.sys_nt_device_io_control_file(
                    file_handle,
                    event,
                    apc_routine,
                    apc_context,
                    io_status_block,
                    io_control_code,
                    input_buffer,
                    input_buffer_length,
                    output_buffer,
                    output_buffer_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtApphelpCacheControl {
                service_class,
                service_data,
            } => {
                let status = syscalls::apphelp::sys_nt_apphelp_cache_control::<Platform>(
                    service_class,
                    service_data,
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
            SyscallRequest::NtQueryWnfStateData {
                state_name,
                type_id,
                explicit_scope,
                change_stamp,
                buffer,
                buffer_size,
            } => {
                let status = self.sys_nt_query_wnf_state_data(
                    state_name,
                    type_id,
                    explicit_scope,
                    change_stamp,
                    buffer,
                    buffer_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtCreateWnfStateName {
                state_name,
                name_lifetime,
                data_scope,
                persist_data,
                type_id,
                maximum_state_size,
                security_descriptor,
            } => {
                let status = self.sys_nt_create_wnf_state_name(
                    syscalls::wnf::WnfCreateStateNameParameters {
                        state_name,
                        name_lifetime,
                        data_scope,
                        persist_data,
                        type_id,
                        maximum_state_size,
                        security_descriptor,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUpdateWnfStateData {
                state_name,
                buffer,
                buffer_size,
                type_id,
                explicit_scope,
                matching_change_stamp,
                check_stamp,
            } => {
                let status = self.sys_nt_update_wnf_state_data(
                    syscalls::wnf::WnfUpdateStateDataParameters {
                        state_name,
                        buffer,
                        buffer_size,
                        type_id,
                        explicit_scope,
                        matching_change_stamp,
                        check_stamp,
                    },
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtDeleteWnfStateData {
                state_name,
                explicit_scope,
            } => {
                let status = self.sys_nt_delete_wnf_state_data(state_name, explicit_scope);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtDeleteWnfStateName { state_name } => {
                let status = self.sys_nt_delete_wnf_state_name(state_name);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryWnfStateNameInformation {
                state_name,
                name_information_class,
                explicit_scope,
                buffer,
                buffer_size,
            } => {
                let status = self.sys_nt_query_wnf_state_name_information(
                    state_name,
                    name_information_class,
                    explicit_scope,
                    buffer,
                    buffer_size,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySection {
                section_handle,
                section_information_class,
                section_information,
                section_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_section(
                    section_handle,
                    section_information_class,
                    section_information,
                    section_information_length,
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
                let status = self.sys_nt_set_information_process(
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
            SyscallRequest::NtOpenThreadToken {
                thread_handle,
                desired_access,
                open_as_self,
                token_handle,
            } => {
                let status = Self::sys_nt_open_thread_token(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenThreadTokenEx {
                thread_handle,
                desired_access,
                open_as_self,
                handle_attributes,
                token_handle,
            } => {
                let status = Self::sys_nt_open_thread_token_ex(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    handle_attributes,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenProcessToken {
                process_handle,
                desired_access,
                token_handle,
            } => {
                let status =
                    self.sys_nt_open_process_token(process_handle, desired_access, token_handle);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtOpenProcessTokenEx {
                process_handle,
                desired_access,
                handle_attributes,
                token_handle,
            } => {
                let status = self.sys_nt_open_process_token_ex(
                    process_handle,
                    desired_access,
                    handle_attributes,
                    token_handle,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQueryInformationToken {
                token_handle,
                token_information_class,
                token_information,
                token_information_length,
                return_length,
            } => {
                let status = self.sys_nt_query_information_token(
                    token_handle,
                    token_information_class,
                    token_information,
                    token_information_length,
                    return_length,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtQuerySecurityAttributesToken {
                token_handle,
                attributes,
                number_of_attributes,
                buffer,
                length,
                return_length,
            } => {
                let status = self.sys_nt_query_security_attributes_token(
                    token_handle,
                    attributes,
                    number_of_attributes,
                    buffer,
                    length,
                    return_length,
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
            SyscallRequest::NtMapViewOfSection {
                section_handle,
                process_handle,
                base_address,
                zero_bits,
                commit_size,
                section_offset,
                view_size,
                inherit_disposition,
                allocation_type,
                page_protection,
            } => {
                let status = self.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                    section_handle,
                    process_handle,
                    base_address,
                    zero_bits,
                    commit_size,
                    section_offset,
                    view_size,
                    inherit_disposition,
                    allocation_type,
                    page_protection,
                });
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtMapViewOfSectionEx {
                section_handle,
                process_handle,
                base_address,
                zero_bits,
                commit_size,
                section_offset,
                view_size,
                inherit_disposition,
                allocation_type,
                page_protection,
                extended_parameters,
                extended_parameter_count,
            } => {
                let status = self.sys_nt_map_view_of_section_ex(
                    MapViewOfSectionParameters {
                        section_handle,
                        process_handle,
                        base_address,
                        zero_bits,
                        commit_size,
                        section_offset,
                        view_size,
                        inherit_disposition,
                        allocation_type,
                        page_protection,
                    },
                    extended_parameters,
                    extended_parameter_count,
                );
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUnmapViewOfSection {
                process_handle,
                base_address,
            } => {
                let status = self.sys_nt_unmap_view_of_section(process_handle, base_address);
                (status, ContinueOperation::Resume)
            }
            SyscallRequest::NtUnmapViewOfSectionEx {
                process_handle,
                base_address,
                flags,
            } => {
                let status =
                    self.sys_nt_unmap_view_of_section_ex(process_handle, base_address, flags);
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
            SyscallRequest::NtTestAlert => {
                // TODO(apc-model): Deliver queued user-mode APCs once thread alert and APC state
                // are modeled.
                litebox_util_log::debug!(
                    "NtTestAlert is a no-op; user-mode APC delivery is not yet modeled"
                );
                (NtStatus::SUCCESS, ContinueOperation::Resume)
            }
            SyscallRequest::NtManageHotPatch => {
                (NtStatus::NOT_IMPLEMENTED, ContinueOperation::Resume)
            }
        };

        ctx.rax = result.as_raw().cast_unsigned() as usize;
        op
    }

    pub(crate) fn sys_nt_close(&self, handle: syscalls::Handle) -> NtStatus {
        self.close_handle(handle, CloseRawHandleVisitor { task: self })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "matches the native NtDuplicateObject contract"
    )]
    pub(crate) fn sys_nt_duplicate_object(
        &self,
        source_process_handle: syscalls::ProcessHandle,
        source_handle: syscalls::Handle,
        target_process_handle: syscalls::ProcessHandle,
        target_handle: Option<MutPtr<Platform, syscalls::Handle>>,
        desired_access: u32,
        handle_attributes: u32,
        options: u32,
    ) -> NtStatus {
        let options = DuplicateOptions::from_bits_retain(options);
        if let Some(target_handle) = target_handle
            && target_handle
                .write_at_offset(0, syscalls::Handle::default())
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !source_process_handle.is_current() {
            // TODO(duplicate-object-cross-process): resolve process handles once LiteBox supports
            // multiple guest processes and per-process handle tables.
            return NtStatus::INVALID_HANDLE;
        }

        let status = self.duplicate_object(
            source_handle,
            target_process_handle,
            target_handle,
            desired_access,
            handle_attributes,
            options,
        );

        if options.contains(DuplicateOptions::CLOSE_SOURCE) {
            let _ = self.sys_nt_close(source_handle);
        }
        status
    }

    fn duplicate_object(
        &self,
        source_handle: syscalls::Handle,
        target_process_handle: syscalls::ProcessHandle,
        target_handle: Option<MutPtr<Platform, syscalls::Handle>>,
        desired_access: u32,
        handle_attributes: u32,
        options: DuplicateOptions,
    ) -> NtStatus {
        if target_process_handle.is_null() {
            return if options.contains(DuplicateOptions::CLOSE_SOURCE) {
                NtStatus::SUCCESS
            } else {
                NtStatus::INVALID_PARAMETER
            };
        }
        if !target_process_handle.is_current() {
            // TODO(duplicate-object-cross-process): insert into the target process handle table.
            return NtStatus::INVALID_HANDLE;
        }
        let duplicate = match self.duplicate_handle(
            source_handle,
            desired_access,
            handle_attributes,
            options,
        ) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        if let Some(target_handle) = target_handle
            && target_handle.write_at_offset(0, duplicate).is_none()
        {
            let _ = self.remove_handle(duplicate, CloseRawHandleVisitor { task: self }, false);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn duplicate_handle(
        &self,
        source_handle: syscalls::Handle,
        desired_access: u32,
        handle_attributes: u32,
        options: DuplicateOptions,
    ) -> Result<syscalls::Handle, NtStatus> {
        macro_rules! try_duplicate {
            ($subsystem:ty) => {
                if let Some(result) = self.try_duplicate_handle::<$subsystem>(
                    source_handle,
                    desired_access,
                    handle_attributes,
                    options,
                ) {
                    return result;
                }
            };
        }

        try_duplicate!(FileObjectSubsystem<FS>);
        try_duplicate!(RegistryKeySubsystem<Platform>);
        try_duplicate!(EventSubsystem<Platform>);
        try_duplicate!(DirectoryObjectSubsystem<Platform>);
        try_duplicate!(SymbolicLinkSubsystem<Platform>);
        try_duplicate!(IoCompletionSubsystem<Platform>);
        try_duplicate!(LpcPortSubsystem<Platform>);
        try_duplicate!(TimerSubsystem<Platform>);
        try_duplicate!(WaitCompletionPacketSubsystem<Platform>);
        try_duplicate!(WorkerFactorySubsystem<Platform>);
        try_duplicate!(SectionSubsystem<Platform>);
        try_duplicate!(TokenSubsystem);

        Err(NtStatus::INVALID_HANDLE)
    }

    fn try_duplicate_handle<Subsystem>(
        &self,
        source_handle: syscalls::Handle,
        desired_access: u32,
        handle_attributes: u32,
        options: DuplicateOptions,
    ) -> Option<Result<syscalls::Handle, NtStatus>>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = match self.typed_handle::<Subsystem>(source_handle) {
            Ok(typed) => typed,
            Err(NtStatus::OBJECT_TYPE_MISMATCH) => return None,
            Err(status) => return Some(Err(status)),
        };
        let source_metadata = match self.typed_handle_metadata(&typed) {
            Ok(metadata) => metadata,
            Err(status) => return Some(Err(status)),
        };

        let source_access = source_metadata.granted_access;
        let duplicate_access = if options.contains(DuplicateOptions::SAME_ACCESS) {
            source_access
        } else {
            let descriptors = self.global.litebox.descriptor_table();
            match descriptors.with_entry(&typed, |entry| {
                Subsystem::resolve_duplicate_access(entry, desired_access)
            }) {
                Some(Ok(access)) => access,
                Some(Err(status)) => return Some(Err(status)),
                None => return Some(Err(NtStatus::INVALID_HANDLE)),
            }
        };
        let duplicate_attributes = if options.contains(DuplicateOptions::SAME_ATTRIBUTES) {
            source_metadata.attributes
        } else {
            let Some(attributes) = HandleAttributes::from_duplicate_attributes(handle_attributes)
            else {
                return Some(Err(NtStatus::INVALID_PARAMETER));
            };
            attributes
        };

        let duplicate = {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            let Some(duplicate) = descriptors.duplicate(&typed) else {
                return Some(Err(NtStatus::INVALID_HANDLE));
            };
            let old = descriptors.set_fd_metadata(
                &duplicate,
                WindowsHandleMetadata {
                    granted_access: duplicate_access,
                    attributes: duplicate_attributes,
                },
            );
            debug_assert!(old.is_none());
            duplicate
        };
        Some(insert_raw_handle::<Platform, Subsystem>(
            &self.global.litebox,
            &self.process.handles,
            duplicate,
            drop,
        ))
    }

    fn close_handle(
        &self,
        handle: syscalls::Handle,
        visitor: impl RawHandleVisitor<Platform, FS>,
    ) -> NtStatus {
        self.remove_handle(handle, visitor, true)
    }

    fn remove_handle(
        &self,
        handle: syscalls::Handle,
        visitor: impl RawHandleVisitor<Platform, FS>,
        enforce_protect_from_close: bool,
    ) -> NtStatus {
        macro_rules! try_close {
            ($subsystem:ty, $visit:ident) => {
                if let Some(status) = self.try_remove_handle::<$subsystem>(
                    handle,
                    enforce_protect_from_close,
                    |entry| visitor.$visit(entry),
                ) {
                    return status;
                }
            };
        }

        try_close!(FileObjectSubsystem<FS>, file);
        try_close!(RegistryKeySubsystem<Platform>, registry_key);
        try_close!(EventSubsystem<Platform>, event);
        try_close!(DirectoryObjectSubsystem<Platform>, directory);
        try_close!(SymbolicLinkSubsystem<Platform>, symbolic_link);
        try_close!(IoCompletionSubsystem<Platform>, io_completion);
        try_close!(LpcPortSubsystem<Platform>, lpc_port);
        try_close!(TimerSubsystem<Platform>, timer);
        try_close!(
            WaitCompletionPacketSubsystem<Platform>,
            wait_completion_packet
        );
        try_close!(WorkerFactorySubsystem<Platform>, worker_factory);
        try_close!(SectionSubsystem<Platform>, section);
        try_close!(TokenSubsystem, token);

        NtStatus::INVALID_HANDLE
    }

    fn try_remove_handle<Subsystem>(
        &self,
        handle: syscalls::Handle,
        enforce_protect_from_close: bool,
        cleanup_entry: impl FnOnce(Subsystem::Entry),
    ) -> Option<NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = match self.typed_handle::<Subsystem>(handle) {
            Ok(typed) => typed,
            Err(NtStatus::OBJECT_TYPE_MISMATCH) => return None,
            Err(status) => return Some(status),
        };
        let metadata = match self.typed_handle_metadata(&typed) {
            Ok(metadata) => metadata,
            Err(status) => return Some(status),
        };
        if enforce_protect_from_close
            && metadata
                .attributes
                .contains(HandleAttributes::PROTECT_FROM_CLOSE)
        {
            return Some(NtStatus::HANDLE_NOT_CLOSABLE);
        }

        remove_raw_handle::<Platform, Subsystem>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            cleanup_entry,
        );
        Some(NtStatus::SUCCESS)
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

    fn lpc_port(&self, lpc_port: LpcPortHandleObject);

    fn timer(&self, timer: TimerHandleObject<Platform>);

    fn wait_completion_packet(
        &self,
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    );

    fn worker_factory(&self, worker_factory: WorkerFactoryHandleObject<Platform>);

    fn section(&self, section: SectionHandleObject<Platform>);

    fn token(&self, token: TokenHandleObject);
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

    fn lpc_port(&self, lpc_port: LpcPortHandleObject) {
        Task::<Platform, FS>::close_lpc_port(lpc_port);
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

    fn section(&self, section: SectionHandleObject<Platform>) {
        Task::<Platform, FS>::close_section(section);
    }

    fn token(&self, token: TokenHandleObject) {
        Task::<Platform, FS>::close_token(token);
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
    _not_send: PhantomData<*const ()>,
}

impl<Platform: ShimPlatform, FS: ShimFS> EnterShim for WindowsShimEntrypoints<Platform, FS> {
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
    tar_data: Cow<'static, [u8]>,
) -> WindowsFS<Platform>
where
    Platform: ShimPlatform + CrngProvider + StdioProvider,
{
    let devices = litebox::fs::resolver::Resolver::new(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/dev", |allocator| {
                litebox::fs::devices::Devices::new(litebox, allocator)
            })
            .build()
            .unwrap(),
    );
    let tar_ro = litebox::fs::resolver::Resolver::new(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/", |allocator| {
                litebox::fs::tar_ro::TarRo::new(tar_data, allocator)
            })
            .build()
            .unwrap(),
    );
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            devices,
            tar_ro,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}
