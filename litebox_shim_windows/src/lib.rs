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
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::{
    ArchSpecificProvider, ArchSpecificRegister, CrngProvider, PageManagementProvider,
    RawConstPointer as _, RawMutPointer as _, RawPointerProvider, StdioProvider,
    SystemInfoProvider, TimeProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::sync::{Mutex, RawSyncPrimitivesProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::loader::PAGE_SIZE;
use litebox_common_windows::{NtSysno, Win32Sysno};

use crate::syscalls::event::{EventHandleObject, EventSubsystem};
use crate::syscalls::file::{FileObject, FileObjectSubsystem};
use crate::syscalls::iocp::{IoCompletionHandleObject, IoCompletionSubsystem};
use crate::syscalls::lpc::{LpcPortHandleObject, LpcPortSubsystem};
use crate::syscalls::mutant::{MutantHandleObject, MutantSubsystem};
use crate::syscalls::object_manager::{
    DirectoryHandleObject, DirectoryObjectSubsystem, ObjectManager,
};
use crate::syscalls::registry::{
    NtNotifyChangeKeyRequest, RegistryKeyObject, RegistryKeySubsystem,
};
use crate::syscalls::section::{
    MapViewOfSectionParameters, SectionHandleObject, SectionObject, SectionSubsystem,
};
use crate::syscalls::semaphore::{SemaphoreHandleObject, SemaphoreSubsystem};
use crate::syscalls::symlink::{SymbolicLinkHandleObject, SymbolicLinkSubsystem};
use crate::syscalls::thread::{ThreadHandleObject, ThreadSubsystem};
use crate::syscalls::timer::{TimerCreateParameters, TimerHandleObject, TimerSubsystem};
use crate::syscalls::token::{TokenHandleObject, TokenObject, TokenSubsystem};
use crate::syscalls::wait_completion_packet::{
    WaitCompletionPacketAssociateParameters, WaitCompletionPacketHandleObject,
    WaitCompletionPacketSubsystem,
};
use crate::syscalls::worker_factory::{
    WorkerFactoryCreateParameters, WorkerFactoryHandleObject, WorkerFactorySubsystem,
};
use crate::syscalls::{SyscallRequest, ThreadHandle, mm};

mod loader;
mod nt_types;
mod syscalls;
mod wait;

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
    + CrngProvider
    + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
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
        + CrngProvider
        + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
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
        Self::new_with_litebox(platform, LiteBox::new(platform))
    }

    /// Creates a builder backed by an existing LiteBox instance.
    #[must_use]
    pub fn new_with_litebox(platform: &'static Platform, litebox: LiteBox<Platform>) -> Self {
        Self { platform, litebox }
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
            mui_generation: AtomicU32::new(1),
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
        process.ntdll = load_info.ntdll;
        process.peb_address = load_info.environment.peb;
        let process = Arc::new(process);
        let thread_object = Arc::new(syscalls::thread::ThreadObject::new(
            syscalls::process::INITIAL_THREAD_ID,
            load_info.environment.teb,
        ));
        let attached = process.attach_thread(syscalls::process::INITIAL_THREAD_ID, &thread_object);
        debug_assert!(attached, "a freshly created process cannot be exiting");
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
                    process: process.clone(),
                    fs,
                    wait_state: wait::WaitState::new(self.0.platform),
                    io_completion_worker: Mutex::new(syscalls::iocp::IoCompletionWorkerState::new()),
                    entry_point: load_info.entry_point,
                    stack_top: load_info.stack_top,
                    context: load_info.environment.context,
                    thread_object,
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
    mui_generation: AtomicU32,
    qpc_boot_instant: <Platform as TimeProvider>::Instant,
    litebox: LiteBox<Platform>,
    _fs: PhantomData<FS>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process<Platform: ShimPlatform> {
    /// The NT process ID reported to the guest.
    id: usize,
    /// The ntdll image loaded into this process, if any.
    ntdll: Option<loader::NtDllInfo>,
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
    wnf_notification_event: Mutex<Platform, Option<Arc<syscalls::event::EventObject<Platform>>>>,
    wnf_subscriptions: Mutex<Platform, syscalls::wnf::WnfProcessSubscriptions>,
    trace_notifications: Mutex<Platform, syscalls::trace::TraceNotifications<Platform>>,
    gdi_state: Mutex<Platform, Option<syscalls::gdi::GdiProcessState>>,
    cookie: u32,
    exit_code: AtomicI32,
    next_thread_id: AtomicUsize,
    threads: litebox::sync::RwLock<Platform, ProcessThreads<Platform>>,
}

/// The live threads of a process, and whether the process is tearing down.
struct ProcessThreads<Platform: ShimPlatform> {
    /// Set once the process has started exiting. No further threads may be
    /// created, and the exit code is frozen.
    group_exit: bool,
    /// The thread objects of every thread that has not yet completed, keyed by
    /// thread ID.
    threads: BTreeMap<usize, Arc<syscalls::thread::ThreadObject<Platform>>>,
}

impl<Platform: ShimPlatform> Process<Platform> {
    /// Allocates the NT thread ID for a newly created thread.
    ///
    /// TODO: IDs are never reused, so a thread ID that has been observed by the guest
    /// can never name a different thread later.
    fn allocate_thread_id(&self) -> usize {
        self.next_thread_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a newly created thread, returning `false` if the process is
    /// already exiting and the thread must not start.
    fn attach_thread(
        &self,
        thread_id: usize,
        thread: &Arc<syscalls::thread::ThreadObject<Platform>>,
    ) -> bool {
        let mut threads = self.threads.write();
        if threads.group_exit {
            return false;
        }
        let previous = threads.threads.insert(thread_id, thread.clone());
        debug_assert!(previous.is_none(), "thread ID {thread_id} already exists");
        true
    }

    /// Unregisters a thread that failed to start or has completed.
    fn detach_thread(&self, thread_id: usize) {
        self.threads.write().threads.remove(&thread_id);
    }

    /// Returns the number of threads that have not yet completed.
    fn live_thread_count(&self) -> usize {
        self.threads.read().threads.len()
    }

    fn thread_teb_address(&self, thread_id: usize) -> Option<usize> {
        self.threads
            .read()
            .threads
            .get(&thread_id)
            .map(|thread| thread.teb_address())
    }

    fn thread_teb_addresses(&self) -> Vec<usize> {
        self.threads
            .read()
            .threads
            .values()
            .map(|thread| thread.teb_address())
            .collect()
    }

    fn thread_by_id(
        &self,
        thread_id: usize,
    ) -> Option<Arc<syscalls::thread::ThreadObject<Platform>>> {
        self.threads.read().threads.get(&thread_id).cloned()
    }

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
            id: syscalls::process::INITIAL_PROCESS_ID,
            ntdll: None,
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
            wnf_notification_event: Mutex::new(None),
            wnf_subscriptions: Mutex::new(syscalls::wnf::WnfProcessSubscriptions::default()),
            trace_notifications: Mutex::new(syscalls::trace::TraceNotifications::default()),
            gdi_state: Mutex::new(None),
            cookie: syscalls::process::default_process_cookie(),
            exit_code: AtomicI32::new(DEFAULT_PROCESS_EXIT_CODE),
            next_thread_id: AtomicUsize::new(syscalls::process::INITIAL_THREAD_ID + 1),
            threads: litebox::sync::RwLock::new(ProcessThreads {
                group_exit: false,
                threads: BTreeMap::new(),
            }),
        }
    }
}

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    process: Arc<Process<Platform>>,
    fs: Arc<FS>,
    wait_state: wait::WaitState<Platform>,
    io_completion_worker: Mutex<Platform, syscalls::iocp::IoCompletionWorkerState<Platform>>,
    entry_point: usize,
    stack_top: usize,
    context: usize,
    /// The NT thread object backing this task.
    thread_object: Arc<syscalls::thread::ThreadObject<Platform>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn complete_current_thread(&self) {
        let thread_id = self.thread_object.thread_id();
        self.thread_object.complete(|| {
            self.release_io_completion_worker();
            self.thread_object.abandon_owned_mutants(thread_id);
            self.process.detach_thread(thread_id);
        });
    }

    /// Marks the current thread as exiting with `exit_status`.
    fn exit_thread(&self, exit_status: i32) {
        self.thread_object.exit_thread(exit_status);
    }

    /// Starts a process-wide exit: records the exit code and asks every thread
    /// in the process, including this one, to stop running guest code.
    fn exit_process(&self, exit_status: i32) {
        let mut threads = self.process.threads.write();
        if threads.group_exit {
            return;
        }
        threads.group_exit = true;
        self.process.exit_code.store(exit_status, Ordering::Relaxed);
        // Interrupting the caller is a no-op, because it is running in the
        // host, so this does not need to single it out.
        for thread in threads.threads.values() {
            thread.begin_exit(exit_status);
        }
    }

    /// Asks every thread in the process except this one to stop running guest
    /// code, leaving the caller running and the process exit code untouched.
    fn exit_other_threads(&self, exit_status: i32) {
        let threads = self.process.threads.read();
        for (thread_id, thread) in &threads.threads {
            if *thread_id != self.thread_object.thread_id() {
                thread.begin_exit(exit_status);
            }
        }
    }

    fn init(&self, ctx: &mut litebox_common_linux::PtRegs) {
        // Publish the handle used to interrupt this thread. This must happen on
        // the thread itself, because the handle captures the current platform
        // thread.
        self.publish_thread_handle();
        if !set_guest_teb(self.global.platform, self.thread_object.teb_address()) {
            self.exit_thread(NtStatus::ACCESS_VIOLATION.as_raw());
            return;
        }

        ctx.rip = self.entry_point;
        debug_assert_eq!(self.stack_top % 16, core::mem::size_of::<usize>());
        ctx.rsp = self.stack_top;
        ctx.eflags = 0x202;
        ctx.rcx = self.context;
        ctx.rdx = self
            .process
            .ntdll
            .as_ref()
            .map_or(0, |ntdll| ntdll.mapping.base_addr);
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Starting initial Windows guest thread"
        );
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
        self.typed_handle_entry_with_access_check(handle, |granted_access| {
            granted_access & required_access == required_access
        })
    }

    fn typed_handle_entry_with_any_access<Subsystem>(
        &self,
        handle: syscalls::Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        self.typed_handle_entry_with_access_check(handle, |granted_access| granted_access != 0)
    }

    fn typed_handle_entry_with_access_check<Subsystem>(
        &self,
        handle: syscalls::Handle,
        access_check: impl FnOnce(u32) -> bool,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = self.typed_handle::<Subsystem>(handle)?;
        if !access_check(self.typed_handle_metadata(&typed)?.granted_access) {
            return Err(NtStatus::ACCESS_DENIED);
        }
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

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if let Some(syscall) = Win32Sysno::from_raw(ctx.orig_rax) {
            ctx.rax = match syscall {
                Win32Sysno::NtGdiInit2 => self.sys_nt_gdi_init2(),
                _ => NtStatus::NOT_SUPPORTED.as_raw().cast_unsigned() as usize,
            };
            return;
        }

        let Some(req) = SyscallRequest::<Platform>::try_from_raw(ctx) else {
            let caller = ConstPtr::<Platform, usize>::from_usize(ctx.rsp)
                .read_at_offset(0)
                .unwrap_or_default();
            #[cfg(debug_assertions)]
            if NtSysno::from_raw(ctx.orig_rax) == Some(NtSysno::NtRaiseHardError) {
                log_loader_hard_error::<Platform>(ctx);
            }
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
            self.exit_thread(NtStatus::NOT_SUPPORTED.as_raw());
            return;
        };
        litebox_util_log::debug!(
            syscall:? = NtSysno::from_raw(ctx.orig_rax);
            "Handling Windows syscall"
        );
        let result = match req {
            SyscallRequest::NtClose { handle } => self.sys_nt_close(handle),
            SyscallRequest::NtDuplicateObject {
                source_process_handle,
                source_handle,
                target_process_handle,
                target_handle,
                desired_access,
                handle_attributes,
                options,
            } => self.sys_nt_duplicate_object(
                source_process_handle,
                source_handle,
                target_process_handle,
                target_handle,
                desired_access,
                handle_attributes,
                options,
            ),
            SyscallRequest::NtCreateEvent {
                event_handle,
                desired_access,
                object_attributes,
                event_type,
                initial_state,
            } => self.sys_nt_create_event(
                event_handle,
                desired_access,
                object_attributes,
                event_type,
                initial_state,
            ),
            SyscallRequest::NtCreateMutant {
                mutant_handle,
                desired_access,
                object_attributes,
                initial_owner,
            } => self.sys_nt_create_mutant(
                mutant_handle,
                desired_access,
                object_attributes,
                initial_owner,
            ),
            SyscallRequest::NtCreateSemaphore {
                semaphore_handle,
                desired_access,
                object_attributes,
                initial_count,
                maximum_count,
            } => self.sys_nt_create_semaphore(
                semaphore_handle,
                desired_access,
                object_attributes,
                initial_count,
                maximum_count,
            ),
            SyscallRequest::NtCreateDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_create_directory_object(
                directory_handle,
                desired_access,
                object_attributes,
                syscalls::Handle::default(),
                0,
            ),
            SyscallRequest::NtCreateDirectoryObjectEx {
                directory_handle,
                desired_access,
                object_attributes,
                shadow_directory_handle,
                flags,
            } => self.sys_nt_create_directory_object(
                directory_handle,
                desired_access,
                object_attributes,
                shadow_directory_handle,
                flags,
            ),
            SyscallRequest::NtOpenDirectoryObject {
                directory_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_directory_object(
                directory_handle,
                desired_access,
                object_attributes,
            ),
            SyscallRequest::NtOpenSection {
                section_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_section(section_handle, desired_access, object_attributes),
            SyscallRequest::NtQueryDirectoryObject {
                directory_handle,
                buffer,
                buffer_length,
                return_single_entry,
                restart_scan,
                context,
                return_length,
            } => self.sys_nt_query_directory_object(
                syscalls::object_manager::DirectoryQueryParameters {
                    directory_handle,
                    buffer,
                    buffer_length,
                    return_single_entry,
                    restart_scan,
                    context,
                    return_length,
                },
            ),
            SyscallRequest::NtCreateSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
                link_target,
            } => self.sys_nt_create_symbolic_link_object(
                link_handle,
                desired_access,
                object_attributes,
                link_target,
            ),
            SyscallRequest::NtOpenSymbolicLinkObject {
                link_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_symbolic_link_object(
                link_handle,
                desired_access,
                object_attributes,
            ),
            SyscallRequest::NtQuerySymbolicLinkObject {
                link_handle,
                link_target,
                returned_length,
            } => self.sys_nt_query_symbolic_link_object(link_handle, link_target, returned_length),
            SyscallRequest::NtCreateIoCompletion {
                io_completion_handle,
                desired_access,
                object_attributes,
                number_of_concurrent_threads,
            } => self.sys_nt_create_io_completion(
                io_completion_handle,
                desired_access,
                object_attributes,
                number_of_concurrent_threads,
            ),
            SyscallRequest::NtOpenIoCompletion {
                io_completion_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_io_completion(
                io_completion_handle,
                desired_access,
                object_attributes,
            ),
            SyscallRequest::NtSetIoCompletion {
                io_completion_handle,
                completion_key,
                completion_value,
                status,
                information,
            } => self.sys_nt_set_io_completion(
                io_completion_handle,
                completion_key,
                completion_value,
                status,
                information,
            ),
            SyscallRequest::NtRemoveIoCompletionEx {
                io_completion_handle,
                io_completion_information,
                count,
                num_entries_removed,
                timeout,
                alertable,
            } => self.sys_nt_remove_io_completion_ex(
                io_completion_handle,
                io_completion_information,
                count,
                num_entries_removed,
                timeout,
                alertable,
            ),
            SyscallRequest::NtAlpcConnectPort {
                port_handle,
                port_name,
            } => Self::sys_nt_alpc_connect_port(port_handle, port_name),
            SyscallRequest::NtConnectPort {
                port_handle,
                port_name,
                security_qos,
                client_view,
                server_view,
                max_message_length,
                connection_information,
                connection_information_length,
            } => self.sys_nt_connect_port(syscalls::lpc::ConnectPortParameters {
                port_handle,
                port_name,
                security_qos,
                client_view,
                server_view,
                max_message_length,
                connection_information,
                connection_information_length,
            }),
            SyscallRequest::NtAlpcSendWaitReceivePort {
                port_handle,
                flags,
                send_message,
                send_message_attributes,
                receive_message,
                buffer_length,
                receive_message_attributes,
                timeout,
            } => self.sys_nt_alpc_send_wait_receive_port(
                port_handle,
                flags,
                send_message,
                send_message_attributes,
                receive_message,
                buffer_length,
                receive_message_attributes,
                timeout,
            ),
            SyscallRequest::NtSecureConnectPort => {
                litebox_util_log::debug!(
                    "Rejected NtSecureConnectPort; only the CSR NtConnectPort subset is modeled"
                );
                NtStatus::NOT_SUPPORTED
            }
            SyscallRequest::NtCreateSection {
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
            } => self.sys_nt_create_section(
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
            ),
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
            } => self.sys_nt_create_section_ex(
                section_handle,
                desired_access,
                object_attributes,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
                extended_parameters,
                extended_parameter_count,
            ),
            SyscallRequest::NtCreateWaitCompletionPacket {
                wait_completion_packet_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_create_wait_completion_packet(
                wait_completion_packet_handle,
                desired_access,
                object_attributes,
            ),
            SyscallRequest::NtAssociateWaitCompletionPacket {
                wait_completion_packet_handle,
                io_completion_handle,
                target_object_handle,
                key_context,
                apc_context,
                io_status,
                io_status_information,
                already_signaled,
            } => self.sys_nt_associate_wait_completion_packet(
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
            ),
            SyscallRequest::NtCancelWaitCompletionPacket {
                wait_completion_packet_handle,
                remove_signaled_packet,
            } => self.sys_nt_cancel_wait_completion_packet(
                wait_completion_packet_handle,
                remove_signaled_packet,
            ),
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
            } => self.sys_nt_create_worker_factory(WorkerFactoryCreateParameters {
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
            }),
            SyscallRequest::NtSetInformationWorkerFactory {
                worker_factory_handle,
                worker_factory_information_class,
                worker_factory_information,
                worker_factory_information_length,
            } => self.sys_nt_set_information_worker_factory(
                worker_factory_handle,
                worker_factory_information_class,
                worker_factory_information,
                worker_factory_information_length,
            ),
            SyscallRequest::NtShutdownWorkerFactory {
                worker_factory_handle,
                pending_worker_count,
            } => self.sys_nt_shutdown_worker_factory(worker_factory_handle, pending_worker_count),
            SyscallRequest::NtCreateTimer2 {
                timer_handle,
                timer_id,
                object_attributes,
                attributes,
                desired_access,
            } => self.sys_nt_create_timer2(TimerCreateParameters {
                timer_handle,
                timer_id,
                object_attributes,
                attributes,
                desired_access,
            }),
            SyscallRequest::NtSetTimer2 {
                timer_handle,
                due_time,
                period,
                parameters,
            } => self.sys_nt_set_timer2(timer_handle, due_time, period, parameters),
            SyscallRequest::NtOpenEvent {
                event_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_event(event_handle, desired_access, object_attributes),
            SyscallRequest::NtOpenMutant {
                mutant_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_mutant(mutant_handle, desired_access, object_attributes),
            SyscallRequest::NtOpenSemaphore {
                semaphore_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_semaphore(semaphore_handle, desired_access, object_attributes),
            SyscallRequest::NtReleaseMutant {
                mutant_handle,
                previous_count,
            } => self.sys_nt_release_mutant(mutant_handle, previous_count),
            SyscallRequest::NtReleaseSemaphore {
                semaphore_handle,
                release_count,
                previous_count,
            } => self.sys_nt_release_semaphore(semaphore_handle, release_count, previous_count),
            SyscallRequest::NtSetEvent {
                event_handle,
                previous_state,
            } => self.sys_nt_set_event(event_handle, previous_state),
            SyscallRequest::NtResetEvent {
                event_handle,
                previous_state,
            } => self.sys_nt_reset_event(event_handle, previous_state),
            SyscallRequest::NtClearEvent { event_handle } => self.sys_nt_clear_event(event_handle),
            SyscallRequest::NtPulseEvent {
                event_handle,
                previous_state,
            } => self.sys_nt_pulse_event(event_handle, previous_state),
            SyscallRequest::NtQueryEvent {
                event_handle,
                event_information_class,
                event_information,
                event_information_length,
                return_length,
            } => self.sys_nt_query_event(
                event_handle,
                event_information_class,
                event_information,
                event_information_length,
                return_length,
            ),
            SyscallRequest::NtQueryMutant {
                mutant_handle,
                mutant_information_class,
                mutant_information,
                mutant_information_length,
                return_length,
            } => self.sys_nt_query_mutant(
                mutant_handle,
                mutant_information_class,
                mutant_information,
                mutant_information_length,
                return_length,
            ),
            SyscallRequest::NtSetEventBoostPriority { event_handle } => {
                self.sys_nt_set_event_boost_priority(event_handle)
            }
            SyscallRequest::NtOpenFile {
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                share_access,
                open_options,
            } => self.sys_nt_open_file(
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                share_access,
                open_options,
            ),
            SyscallRequest::NtQueryAttributesFile {
                object_attributes,
                file_information,
            } => self.sys_nt_query_attributes_file(object_attributes, file_information),
            SyscallRequest::NtQueryInformationByName {
                object_attributes,
                io_status_block,
                file_information,
                length,
                file_information_class,
            } => self.sys_nt_query_information_by_name(
                object_attributes,
                io_status_block,
                file_information,
                length,
                file_information_class,
            ),
            SyscallRequest::NtQueryInformationFile {
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class,
            } => self.sys_nt_query_information_file(
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class,
            ),
            SyscallRequest::NtSetInformationFile {
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class,
            } => self.sys_nt_set_information_file(
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class,
            ),
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
            } => self.sys_nt_create_file(
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
            ),
            SyscallRequest::NtWriteFile {
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                buffer,
                length,
                byte_offset,
                key,
            } => self.sys_nt_write_file(
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                buffer,
                length,
                byte_offset,
                key,
            ),
            SyscallRequest::NtReadFile {
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                buffer,
                length,
                byte_offset,
                key,
            } => self.sys_nt_read_file(
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                buffer,
                length,
                byte_offset,
                key,
            ),
            SyscallRequest::NtGetCurrentProcessorNumberEx { processor_number } => {
                self.sys_nt_get_current_processor_number_ex(processor_number)
            }
            SyscallRequest::NtQueryDebugFilterState {
                component_id,
                level,
            } => {
                litebox_util_log::debug!(
                    component_id,
                    level;
                    "NtQueryDebugFilterState reports no attached debugger"
                );
                NtStatus::DEBUGGER_INACTIVE
            }
            SyscallRequest::NtQueryDirectoryFileEx {
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                file_information,
                length,
                file_information_class,
                query_flags,
                file_name,
            } => self.sys_nt_query_directory_file_ex(
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                file_information,
                length,
                file_information_class,
                query_flags,
                file_name,
            ),
            SyscallRequest::NtQueryVolumeInformationFile {
                file_handle,
                io_status_block,
                fs_information,
                length,
                fs_information_class,
            } => self.sys_nt_query_volume_information_file(
                file_handle,
                io_status_block,
                fs_information,
                length,
                fs_information_class,
            ),
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
            } => self.sys_nt_device_io_control_file(
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
            ),
            SyscallRequest::NtApphelpCacheControl {
                service_class,
                service_data,
            } => syscalls::apphelp::sys_nt_apphelp_cache_control::<Platform>(
                service_class,
                service_data,
            ),
            SyscallRequest::NtCreateKey {
                key_handle,
                desired_access,
                object_attributes,
                title_index,
                class,
                create_options,
                disposition,
            } => self.sys_nt_create_key(
                key_handle,
                desired_access,
                object_attributes,
                title_index,
                class,
                create_options,
                disposition,
            ),
            SyscallRequest::NtOpenKey {
                key_handle,
                desired_access,
                object_attributes,
            } => self.sys_nt_open_key(key_handle, desired_access, object_attributes),
            SyscallRequest::NtOpenKeyEx {
                key_handle,
                desired_access,
                object_attributes,
                open_options,
            } => {
                self.sys_nt_open_key_ex(key_handle, desired_access, object_attributes, open_options)
            }
            SyscallRequest::NtQueryKey {
                key_handle,
                key_information_class,
                key_information,
                length,
                result_length,
            } => self.sys_nt_query_key(
                key_handle,
                key_information_class,
                key_information,
                length,
                result_length,
            ),
            SyscallRequest::NtEnumerateKey {
                key_handle,
                index,
                key_information_class,
                key_information,
                length,
                result_length,
            } => self.sys_nt_enumerate_key(
                key_handle,
                index,
                key_information_class,
                key_information,
                length,
                result_length,
            ),
            SyscallRequest::NtQueryValueKey {
                key_handle,
                value_name,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            } => self.sys_nt_query_value_key(
                key_handle,
                value_name,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            ),
            SyscallRequest::NtEnumerateValueKey {
                key_handle,
                index,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            } => self.sys_nt_enumerate_value_key(
                key_handle,
                index,
                key_value_information_class,
                key_value_information,
                length,
                result_length,
            ),
            SyscallRequest::NtSetValueKey {
                key_handle,
                value_name,
                title_index,
                value_type,
                data,
                data_size,
            } => self.sys_nt_set_value_key(
                key_handle,
                value_name,
                title_index,
                value_type,
                data,
                data_size,
            ),
            SyscallRequest::NtNotifyChangeKey {
                key_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                completion_filter,
                watch_tree,
                buffer,
                buffer_size,
                asynchronous,
            } => self.sys_nt_notify_change_key(NtNotifyChangeKeyRequest {
                key_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                completion_filter,
                watch_tree,
                buffer,
                buffer_size,
                asynchronous,
            }),
            SyscallRequest::NtGetMUIRegistryInfo {
                flags,
                data_size,
                data,
            } => self.sys_nt_get_mui_registry_info(flags, data_size, data),
            SyscallRequest::NtGetNlsSectionPtr {
                section_type,
                section_data,
                context_data,
                section_pointer,
                section_size,
            } => self.sys_nt_get_nls_section_ptr(
                section_type,
                section_data,
                context_data,
                section_pointer,
                section_size,
            ),
            SyscallRequest::NtInitializeNlsFiles {
                base_address,
                default_locale_id,
                default_casing_table_size,
            } => self.sys_nt_initialize_nls_files(
                base_address,
                default_locale_id,
                default_casing_table_size,
            ),
            SyscallRequest::NtQueryDefaultLocale {
                user_profile,
                default_locale_id,
            } => self.sys_nt_query_default_locale(user_profile, default_locale_id),
            SyscallRequest::NtSetDefaultLocale {
                user_profile,
                default_locale_id,
            } => self.sys_nt_set_default_locale(user_profile, default_locale_id),
            SyscallRequest::NtQueryDefaultUILanguage {
                default_ui_language,
            } => self.sys_nt_query_default_ui_language(default_ui_language),
            SyscallRequest::NtSetDefaultUILanguage {
                default_ui_language,
            } => self.sys_nt_set_default_ui_language(default_ui_language),
            SyscallRequest::NtQueryInstallUILanguage {
                install_ui_language,
            } => self.sys_nt_query_install_ui_language(install_ui_language),
            SyscallRequest::NtQueryPerformanceCounter {
                performance_counter,
                performance_frequency,
            } => self.sys_nt_query_performance_counter(performance_counter, performance_frequency),
            SyscallRequest::NtQueryTimerResolution {
                minimum_resolution,
                maximum_resolution,
                current_resolution,
            } => Self::sys_nt_query_timer_resolution(
                minimum_resolution,
                maximum_resolution,
                current_resolution,
            ),
            SyscallRequest::NtQueryLicenseValue {
                value_name,
                value_type,
                data,
                data_size,
                result_data_size,
            } => Self::sys_nt_query_license_value(
                value_name,
                value_type,
                data,
                data_size,
                result_data_size,
            ),
            SyscallRequest::NtQuerySystemInformation {
                system_information_class,
                system_information,
                system_information_length,
                return_length,
            } => Self::sys_nt_query_system_information(
                system_information_class,
                system_information,
                system_information_length,
                return_length,
            ),
            SyscallRequest::NtQuerySystemInformationEx {
                system_information_class,
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            } => Self::sys_nt_query_system_information_ex(
                system_information_class,
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            ),
            SyscallRequest::NtQueryWnfStateData {
                state_name,
                type_id,
                explicit_scope,
                change_stamp,
                buffer,
                buffer_size,
            } => self.sys_nt_query_wnf_state_data(
                state_name,
                type_id,
                explicit_scope,
                change_stamp,
                buffer,
                buffer_size,
            ),
            SyscallRequest::NtCreateWnfStateName {
                state_name,
                name_lifetime,
                data_scope,
                persist_data,
                type_id,
                maximum_state_size,
                security_descriptor,
            } => self.sys_nt_create_wnf_state_name(syscalls::wnf::WnfCreateStateNameParameters {
                state_name,
                name_lifetime,
                data_scope,
                persist_data,
                type_id,
                maximum_state_size,
                security_descriptor,
            }),
            SyscallRequest::NtUpdateWnfStateData {
                state_name,
                buffer,
                buffer_size,
                type_id,
                explicit_scope,
                matching_change_stamp,
                check_stamp,
            } => self.sys_nt_update_wnf_state_data(syscalls::wnf::WnfUpdateStateDataParameters {
                state_name,
                buffer,
                buffer_size,
                type_id,
                explicit_scope,
                matching_change_stamp,
                check_stamp,
            }),
            SyscallRequest::NtDeleteWnfStateData {
                state_name,
                explicit_scope,
            } => self.sys_nt_delete_wnf_state_data(state_name, explicit_scope),
            SyscallRequest::NtDeleteWnfStateName { state_name } => {
                self.sys_nt_delete_wnf_state_name(state_name)
            }
            SyscallRequest::NtQueryWnfStateNameInformation {
                state_name,
                name_information_class,
                explicit_scope,
                buffer,
                buffer_size,
            } => self.sys_nt_query_wnf_state_name_information(
                state_name,
                name_information_class,
                explicit_scope,
                buffer,
                buffer_size,
            ),
            SyscallRequest::NtSetWnfProcessNotificationEvent { notification_event } => {
                self.sys_nt_set_wnf_process_notification_event(notification_event)
            }
            SyscallRequest::NtGetCompleteWnfStateSubscription {
                old_state_name,
                old_subscription_id,
                old_event_mask,
                old_status,
                delivery_descriptor,
                descriptor_size,
            } => self.sys_nt_get_complete_wnf_state_subscription(
                old_state_name,
                old_subscription_id,
                old_event_mask,
                old_status,
                delivery_descriptor,
                descriptor_size,
            ),
            SyscallRequest::NtSubscribeWnfStateChange {
                state_name,
                change_stamp,
                event_mask,
                subscription_id,
            } => self.sys_nt_subscribe_wnf_state_change(
                state_name,
                change_stamp,
                event_mask,
                subscription_id,
            ),
            SyscallRequest::NtUnsubscribeWnfStateChange { state_name } => {
                self.sys_nt_unsubscribe_wnf_state_change(state_name)
            }
            SyscallRequest::NtQuerySection {
                section_handle,
                section_information_class,
                section_information,
                section_information_length,
                return_length,
            } => self.sys_nt_query_section(
                section_handle,
                section_information_class,
                section_information,
                section_information_length,
                return_length,
            ),
            SyscallRequest::NtQueryObject {
                handle,
                object_information_class,
                object_information,
                object_information_length,
                return_length,
            } => self.sys_nt_query_object(
                handle,
                object_information_class,
                object_information,
                object_information_length,
                return_length,
            ),
            SyscallRequest::NtSetInformationObject {
                handle,
                object_information_class,
                object_information,
                object_information_length,
            } => self.sys_nt_set_information_object(
                handle,
                object_information_class,
                object_information,
                object_information_length,
            ),
            SyscallRequest::NtQueryInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
                return_length,
            } => self.sys_nt_query_information_process(
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
                return_length,
            ),
            SyscallRequest::NtSetInformationProcess {
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
            } => self.sys_nt_set_information_process(
                process_handle,
                process_information_class,
                process_information,
                process_information_length,
            ),
            SyscallRequest::NtSetInformationThread {
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
            } => Self::sys_nt_set_information_thread(
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
            ),
            SyscallRequest::NtQueryInformationThread {
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
                return_length,
            } => self.sys_nt_query_information_thread(
                thread_handle,
                thread_information_class,
                thread_information,
                thread_information_length,
                return_length,
            ),
            SyscallRequest::NtCreateThreadEx {
                thread_handle,
                desired_access,
                object_attributes,
                process_handle,
                start_routine,
                argument,
                create_flags,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list,
            } => self.sys_nt_create_thread_ex(
                ctx,
                thread_handle,
                desired_access,
                object_attributes,
                process_handle,
                start_routine,
                argument,
                create_flags,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list,
            ),
            SyscallRequest::NtResumeThread {
                thread_handle,
                previous_suspend_count,
            } => self.sys_nt_resume_thread(thread_handle, previous_suspend_count),
            SyscallRequest::NtWaitForAlertByThreadId { address, timeout } => {
                self.sys_nt_wait_for_alert_by_thread_id(address, timeout)
            }
            SyscallRequest::NtAlertThreadByThreadIdEx { thread_id, address } => {
                self.sys_nt_alert_thread_by_thread_id_ex(thread_id, address)
            }
            SyscallRequest::NtAlertThreadByThreadId { thread_id } => {
                self.sys_nt_alert_thread_by_thread_id(thread_id)
            }
            SyscallRequest::NtWaitForSingleObject {
                handle,
                alertable,
                timeout,
            } => self.sys_nt_wait_for_single_object(handle, alertable, timeout),
            SyscallRequest::NtOpenThreadToken {
                thread_handle,
                desired_access,
                open_as_self,
                token_handle,
            } => Self::sys_nt_open_thread_token(
                thread_handle,
                desired_access,
                open_as_self,
                token_handle,
            ),
            SyscallRequest::NtOpenThreadTokenEx {
                thread_handle,
                desired_access,
                open_as_self,
                handle_attributes,
                token_handle,
            } => Self::sys_nt_open_thread_token_ex(
                thread_handle,
                desired_access,
                open_as_self,
                handle_attributes,
                token_handle,
            ),
            SyscallRequest::NtOpenProcessToken {
                process_handle,
                desired_access,
                token_handle,
            } => self.sys_nt_open_process_token(process_handle, desired_access, token_handle),
            SyscallRequest::NtOpenProcessTokenEx {
                process_handle,
                desired_access,
                handle_attributes,
                token_handle,
            } => self.sys_nt_open_process_token_ex(
                process_handle,
                desired_access,
                handle_attributes,
                token_handle,
            ),
            SyscallRequest::NtQueryInformationToken {
                token_handle,
                token_information_class,
                token_information,
                token_information_length,
                return_length,
            } => self.sys_nt_query_information_token(
                token_handle,
                token_information_class,
                token_information,
                token_information_length,
                return_length,
            ),
            SyscallRequest::NtQuerySecurityAttributesToken {
                token_handle,
                attributes,
                number_of_attributes,
                buffer,
                length,
                return_length,
            } => self.sys_nt_query_security_attributes_token(
                token_handle,
                attributes,
                number_of_attributes,
                buffer,
                length,
                return_length,
            ),
            SyscallRequest::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
                flag,
                source,
                destination,
                conversion_error,
            } => Self::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                flag,
                source,
                destination,
                conversion_error,
            ),
            SyscallRequest::NtAllocateVirtualMemory {
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            } => self.sys_nt_allocate_virtual_memory(
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            ),
            SyscallRequest::NtAllocateVirtualMemoryEx {
                process_handle,
                base_address,
                region_size,
                allocation_type,
                protect,
                extended_parameters,
                extended_parameter_count,
            } => self.sys_nt_allocate_virtual_memory_ex(
                process_handle,
                base_address,
                region_size,
                allocation_type,
                protect,
                mm::MemoryExtendedParameters {
                    parameters: extended_parameters,
                    count: extended_parameter_count,
                },
            ),
            SyscallRequest::NtFreeVirtualMemory {
                process_handle,
                base_address,
                region_size,
                free_type,
            } => self.sys_nt_free_virtual_memory(
                process_handle,
                base_address,
                region_size,
                free_type,
            ),
            SyscallRequest::NtProtectVirtualMemory {
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            } => self.sys_nt_protect_virtual_memory(
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            ),
            SyscallRequest::NtReadVirtualMemory {
                process_handle,
                base_address,
                buffer,
                number_of_bytes_to_read,
                number_of_bytes_read,
            } => Self::sys_nt_read_virtual_memory(
                process_handle,
                base_address,
                buffer,
                number_of_bytes_to_read,
                number_of_bytes_read,
            ),
            SyscallRequest::NtQueryVirtualMemory {
                process_handle,
                base_address,
                memory_information_class,
                memory_information,
                memory_information_length,
                return_length,
            } => self.sys_nt_query_virtual_memory(
                process_handle,
                base_address,
                memory_information_class,
                memory_information,
                memory_information_length,
                return_length,
            ),
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
            } => self.sys_nt_map_view_of_section(MapViewOfSectionParameters {
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
            }),
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
            } => self.sys_nt_map_view_of_section_ex(
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
            ),
            SyscallRequest::NtUnmapViewOfSection {
                process_handle,
                base_address,
            } => self.sys_nt_unmap_view_of_section(process_handle, base_address),
            SyscallRequest::NtUnmapViewOfSectionEx {
                process_handle,
                base_address,
                flags,
            } => self.sys_nt_unmap_view_of_section_ex(process_handle, base_address, flags),
            SyscallRequest::NtContinue {
                context,
                test_alert,
            } => match Self::sys_nt_continue(ctx, context, test_alert) {
                Ok(()) => return,
                Err(status) => status,
            },
            SyscallRequest::NtTraceEvent {
                trace_handle,
                flags,
                field_size,
                fields,
            } => self.sys_nt_trace_event(trace_handle, flags, field_size, fields),
            SyscallRequest::NtTraceControl {
                function_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
                return_length,
            } => self.sys_nt_trace_control(
                function_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
                return_length,
            ),
            SyscallRequest::NtTerminateProcess {
                process_handle,
                exit_status,
            } => {
                if process_handle.is_null() {
                    // A null handle terminates every other thread in the
                    // current process but spares the caller.
                    self.exit_other_threads(exit_status);
                    NtStatus::SUCCESS
                } else if process_handle.is_current() {
                    self.exit_process(exit_status);
                    NtStatus::SUCCESS
                } else {
                    // TODO: allow terminating other processes
                    litebox_util_log::error!("Terminating other processes is not yet supported");
                    NtStatus::INVALID_HANDLE
                }
            }
            SyscallRequest::NtTerminateThread {
                thread_handle,
                exit_status,
            } => {
                if !thread_handle.is_null() && thread_handle != ThreadHandle::CURRENT {
                    NtStatus::NOT_SUPPORTED
                } else {
                    self.exit_thread(exit_status);
                    NtStatus::SUCCESS
                }
            }
            SyscallRequest::NtTestAlert => {
                Self::test_alert();
                NtStatus::SUCCESS
            }
            SyscallRequest::NtManageHotPatch => NtStatus::NOT_IMPLEMENTED,
        };

        ctx.rax = result.as_raw().cast_unsigned() as usize;
    }

    fn sys_nt_continue(
        ctx: &mut litebox_common_linux::PtRegs,
        context: ConstPtr<Platform, nt_types::X64Context>,
        test_alert: bool,
    ) -> Result<(), NtStatus> {
        if context.as_usize() == 0 {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        let context = context
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;

        if test_alert {
            Self::test_alert();
        }

        let context_flags = nt_types::ContextFlags::from_bits_retain(context.context_flags);

        if context_flags.contains(nt_types::ContextFlags::CONTROL) {
            ctx.rip = context.rip.trunc();
            ctx.rsp = context.rsp.trunc();
            ctx.eflags = context.e_flags as usize;
            ctx.cs = context.seg_cs as usize;
            ctx.ss = context.seg_ss as usize;
        }

        if context_flags.contains(nt_types::ContextFlags::INTEGER) {
            ctx.rax = context.rax.trunc();
            ctx.rbx = context.rbx.trunc();
            ctx.rcx = context.rcx.trunc();
            ctx.rdx = context.rdx.trunc();
            ctx.rsi = context.rsi.trunc();
            ctx.rdi = context.rdi.trunc();
            ctx.rbp = context.rbp.trunc();
            ctx.r8 = context.r8.trunc();
            ctx.r9 = context.r9.trunc();
            ctx.r10 = context.r10.trunc();
            ctx.r11 = context.r11.trunc();
            ctx.r12 = context.r12.trunc();
            ctx.r13 = context.r13.trunc();
            ctx.r14 = context.r14.trunc();
            ctx.r15 = context.r15.trunc();
        }

        // TODO(context-model): Restore floating-point, extended, and debug-register state.
        if context_flags.contains(nt_types::ContextFlags::FLOATING_POINT) {
            litebox_util_log::warn!(
                "NtContinue requested floating-point state, which is not yet restored"
            );
        }
        if context_flags.contains(nt_types::ContextFlags::XSTATE) {
            litebox_util_log::warn!(
                "NtContinue requested extended state, which is not yet restored"
            );
        }
        if context_flags.contains(nt_types::ContextFlags::DEBUG_REGISTERS) {
            litebox_util_log::warn!(
                "NtContinue requested debug-register state, which is not yet restored"
            );
        }

        Ok(())
    }

    fn test_alert() {
        // TODO(apc-model): Deliver queued user-mode APCs once thread alert and APC state
        // are modeled.
        litebox_util_log::debug!(
            "NtTestAlert is a no-op; user-mode APC delivery is not yet modeled"
        );
    }

    pub(crate) fn sys_nt_close(&self, handle: syscalls::Handle) -> NtStatus {
        self.close_handle(handle, CloseRawHandleVisitor { task: self })
    }

    fn handle_metadata(&self, handle: syscalls::Handle) -> Result<WindowsHandleMetadata, NtStatus> {
        macro_rules! try_metadata {
            ($subsystem:ty) => {
                if let Some(result) =
                    self.try_get_handle_metadata_for_subsystem::<$subsystem>(handle)
                {
                    return result;
                }
            };
        }

        try_metadata!(FileObjectSubsystem<FS>);
        try_metadata!(RegistryKeySubsystem<Platform>);
        try_metadata!(EventSubsystem<Platform>);
        try_metadata!(MutantSubsystem<Platform>);
        try_metadata!(SemaphoreSubsystem<Platform>);
        try_metadata!(DirectoryObjectSubsystem<Platform>);
        try_metadata!(SymbolicLinkSubsystem<Platform>);
        try_metadata!(IoCompletionSubsystem<Platform>);
        try_metadata!(LpcPortSubsystem<Platform>);
        try_metadata!(TimerSubsystem<Platform>);
        try_metadata!(WaitCompletionPacketSubsystem<Platform>);
        try_metadata!(WorkerFactorySubsystem<Platform>);
        try_metadata!(SectionSubsystem<Platform>);
        try_metadata!(TokenSubsystem);
        try_metadata!(ThreadSubsystem<Platform>);

        Err(NtStatus::INVALID_HANDLE)
    }

    fn try_get_handle_metadata_for_subsystem<Subsystem>(
        &self,
        handle: syscalls::Handle,
    ) -> Option<Result<WindowsHandleMetadata, NtStatus>>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = match self.typed_handle::<Subsystem>(handle) {
            Ok(typed) => typed,
            Err(NtStatus::OBJECT_TYPE_MISMATCH) => return None,
            Err(status) => return Some(Err(status)),
        };
        Some(self.typed_handle_metadata(&typed))
    }

    fn set_handle_attributes(
        &self,
        handle: syscalls::Handle,
        mask: HandleAttributes,
        attributes: HandleAttributes,
    ) -> Result<(), NtStatus> {
        macro_rules! try_set_attributes {
            ($subsystem:ty) => {
                if let Some(result) =
                    self.try_set_handle_attributes::<$subsystem>(handle, mask, attributes)
                {
                    return result;
                }
            };
        }

        try_set_attributes!(FileObjectSubsystem<FS>);
        try_set_attributes!(RegistryKeySubsystem<Platform>);
        try_set_attributes!(EventSubsystem<Platform>);
        try_set_attributes!(MutantSubsystem<Platform>);
        try_set_attributes!(SemaphoreSubsystem<Platform>);
        try_set_attributes!(DirectoryObjectSubsystem<Platform>);
        try_set_attributes!(SymbolicLinkSubsystem<Platform>);
        try_set_attributes!(IoCompletionSubsystem<Platform>);
        try_set_attributes!(LpcPortSubsystem<Platform>);
        try_set_attributes!(TimerSubsystem<Platform>);
        try_set_attributes!(WaitCompletionPacketSubsystem<Platform>);
        try_set_attributes!(WorkerFactorySubsystem<Platform>);
        try_set_attributes!(SectionSubsystem<Platform>);
        try_set_attributes!(TokenSubsystem);
        try_set_attributes!(ThreadSubsystem<Platform>);

        Err(NtStatus::INVALID_HANDLE)
    }

    fn try_set_handle_attributes<Subsystem>(
        &self,
        handle: syscalls::Handle,
        mask: HandleAttributes,
        attributes: HandleAttributes,
    ) -> Option<Result<(), NtStatus>>
    where
        Subsystem: WindowsHandleSubsystem,
    {
        let typed = match self.typed_handle::<Subsystem>(handle) {
            Ok(typed) => typed,
            Err(NtStatus::OBJECT_TYPE_MISMATCH) => return None,
            Err(status) => return Some(Err(status)),
        };
        Some(
            self.global
                .litebox
                .descriptor_table_mut()
                .with_metadata_mut::<Subsystem, WindowsHandleMetadata, _>(&typed, |metadata| {
                    metadata.attributes.remove(mask);
                    metadata.attributes.insert(attributes & mask);
                })
                .map_err(|_| NtStatus::INVALID_HANDLE),
        )
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
        if syscalls::ThreadHandle::from_raw(source_handle.as_raw()).is_current() {
            let duplicate_access = if options.contains(DuplicateOptions::SAME_ACCESS) {
                u32::MAX
            } else {
                <ThreadSubsystem<Platform> as WindowsHandleSubsystem>::normalize_desired_access(
                    desired_access,
                )
            };
            let duplicate_attributes = HandleAttributes::from_duplicate_attributes(
                if options.contains(DuplicateOptions::SAME_ATTRIBUTES) {
                    0
                } else {
                    handle_attributes
                },
            )
            .ok_or(NtStatus::INVALID_PARAMETER)?;
            return self.insert_typed_handle_with_attributes::<ThreadSubsystem<Platform>>(
                ThreadHandleObject {
                    thread: self.thread_object.clone(),
                },
                duplicate_access,
                duplicate_attributes,
                drop,
            );
        }

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
        try_duplicate!(MutantSubsystem<Platform>);
        try_duplicate!(SemaphoreSubsystem<Platform>);
        try_duplicate!(DirectoryObjectSubsystem<Platform>);
        try_duplicate!(SymbolicLinkSubsystem<Platform>);
        try_duplicate!(IoCompletionSubsystem<Platform>);
        try_duplicate!(LpcPortSubsystem<Platform>);
        try_duplicate!(TimerSubsystem<Platform>);
        try_duplicate!(WaitCompletionPacketSubsystem<Platform>);
        try_duplicate!(WorkerFactorySubsystem<Platform>);
        try_duplicate!(SectionSubsystem<Platform>);
        try_duplicate!(TokenSubsystem);
        try_duplicate!(ThreadSubsystem<Platform>);

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
        try_close!(MutantSubsystem<Platform>, mutant);
        try_close!(SemaphoreSubsystem<Platform>, semaphore);
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
        try_close!(ThreadSubsystem<Platform>, thread);

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

    fn handle_interrupt_request(&self, _ctx: &mut litebox_common_linux::PtRegs) {
        litebox_util_log::debug!(
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Windows guest interrupt"
        );
    }

    fn handle_exception_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        info: &ExceptionInfo,
    ) {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2);
            "Windows guest exception"
        );
        // TODO: Translate hardware exceptions into Windows SEH where appropriate.
        self.exit_thread(NtStatus::UNSUCCESSFUL.as_raw());
    }
}

#[cfg(debug_assertions)]
#[derive(Debug, Eq, PartialEq)]
struct DllNotFoundHardError {
    dll_name: alloc::string::String,
    search_path: Option<alloc::string::String>,
}

#[cfg(debug_assertions)]
fn decode_dll_not_found_hard_error<Platform: RawPointerProvider>(
    ctx: &litebox_common_linux::PtRegs,
) -> Result<Option<DllNotFoundHardError>, NtStatus> {
    let error_status = NtStatus::from_raw(ctx.r10.trunc());
    if error_status != NtStatus::DLL_NOT_FOUND {
        return Ok(None);
    }

    if ctx.rdx == 0 || ctx.r8 & 1 == 0 || ctx.r9 == 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let parameters = ConstPtr::<Platform, usize>::from_usize(ctx.r9);
    let dll_name = parameters
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)
        .and_then(nt_types::read_unicode_string_at::<Platform>)?;
    let search_path = if ctx.rdx >= 2 && ctx.r8 & 0b10 != 0 {
        Some(
            parameters
                .read_at_offset(1)
                .ok_or(NtStatus::ACCESS_VIOLATION)
                .and_then(nt_types::read_unicode_string_at::<Platform>)?,
        )
    } else {
        None
    };

    Ok(Some(DllNotFoundHardError {
        dll_name,
        search_path,
    }))
}

#[cfg(debug_assertions)]
fn log_loader_hard_error<Platform: RawPointerProvider>(ctx: &litebox_common_linux::PtRegs) {
    match decode_dll_not_found_hard_error::<Platform>(ctx) {
        Ok(Some(error)) if is_api_set_contract(&error.dll_name) => {
            litebox_util_log::error!(
                status:? = NtStatus::DLL_NOT_FOUND,
                contract:% = error.dll_name,
                search_path:% = error.search_path.as_deref().unwrap_or("<not supplied>");
                "Windows loader could not resolve an API-set contract; add the missing contract to loader::pe::API_SET_MAPPINGS"
            );
        }
        Ok(Some(error)) => {
            litebox_util_log::error!(
                status:? = NtStatus::DLL_NOT_FOUND,
                dll:% = error.dll_name,
                search_path:% = error.search_path.as_deref().unwrap_or("<not supplied>");
                "Windows loader could not find a required DLL"
            );
        }
        Err(decode_status) => {
            litebox_util_log::error!(
                status:? = NtStatus::DLL_NOT_FOUND,
                decode_status:? = decode_status,
                parameter_count = ctx.rdx,
                unicode_parameter_mask:% = format_args!("{:#x}", ctx.r8),
                parameters:% = format_args!("{:#x}", ctx.r9);
                "Windows loader raised STATUS_DLL_NOT_FOUND, but its diagnostic parameters could not be read"
            );
        }
        Ok(None) => {}
    }
}

#[cfg(debug_assertions)]
fn is_api_set_contract(dll_name: &str) -> bool {
    let file_name = dll_name.rsplit(['\\', '/']).next().unwrap_or(dll_name);
    ["api-ms-", "ext-ms-"].iter().any(|prefix| {
        file_name
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
    })
}

trait RawHandleVisitor<Platform: ShimPlatform, FS: ShimFS> {
    fn file(&self, file: FileObject<FS>);

    fn registry_key(&self, key: RegistryKeyObject<Platform>);

    fn event(&self, event: EventHandleObject<Platform>);

    fn mutant(&self, mutant: MutantHandleObject<Platform>);

    fn semaphore(&self, semaphore: SemaphoreHandleObject<Platform>);

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

    fn thread(&self, thread: ThreadHandleObject<Platform>);
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

    fn mutant(&self, mutant: MutantHandleObject<Platform>) {
        Task::<Platform, FS>::close_mutant(mutant);
    }

    fn semaphore(&self, semaphore: SemaphoreHandleObject<Platform>) {
        Task::<Platform, FS>::close_semaphore(semaphore);
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
        self.task.close_lpc_port(lpc_port);
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

    fn thread(&self, thread: ThreadHandleObject<Platform>) {
        Task::<Platform, FS>::close_thread(thread);
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
        self.enter_shim(true, ctx, Task::init)
    }

    fn reenter(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, |task, _| {
            task.exit_thread(NtStatus::NOT_SUPPORTED.as_raw());
        })
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        self.enter_shim(false, ctx, |task, ctx| {
            task.handle_exception_request(ctx, info);
        })
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_interrupt_request)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> WindowsShimEntrypoints<Platform, FS> {
    /// Runs a shim handler with the wait-state bookkeeping needed to keep the
    /// thread interruptible while it runs guest code.
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<Platform, FS>, &mut litebox_common_linux::PtRegs),
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            self.task.complete_current_thread();
            ContinueOperation::Terminate
        }
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
