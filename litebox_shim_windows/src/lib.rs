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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};
use litebox_common_windows::nt_status::NtStatus;

use litebox::LiteBox;
use litebox::platform::{
    ArchSpecificProvider, ArchSpecificRegister, PageManagementProvider, RawConstPointer as _,
    RawMutPointer as _, RawPointerProvider, SystemInfoProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::sync::{Mutex, RawSyncPrimitivesProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::loader::PAGE_SIZE;
use litebox_common_windows::{NtSysno, Win32Sysno};
use litebox_platform::sync::{RawMutex as _, RawMutexProvider};
use litebox_platform::time::TimeProvider;

use crate::syscalls::event::EventSubsystem;
use crate::syscalls::file::FileObject;
use crate::syscalls::iocp::IoCompletionSubsystem;
use crate::syscalls::lpc::LpcPortSubsystem;
use crate::syscalls::mutant::MutantSubsystem;
use crate::syscalls::object_manager::{DirectoryObjectSubsystem, ObjectManager};
use crate::syscalls::registry::RegistryKeyObject;
use crate::syscalls::section::{SectionObject, SectionSubsystem};
use crate::syscalls::semaphore::SemaphoreSubsystem;
use crate::syscalls::symlink::SymbolicLinkSubsystem;
use crate::syscalls::thread::{ThreadAccess, ThreadHandleObject, ThreadSubsystem};
use crate::syscalls::timer::TimerSubsystem;
use crate::syscalls::token::{TokenObject, TokenSubsystem};
use crate::syscalls::wait_completion_packet::WaitCompletionPacketSubsystem;
use crate::syscalls::worker_factory::WorkerFactorySubsystem;

mod fs;
mod loader;
mod nt_types;
mod page_manager;
mod syscalls;
mod wait;

#[cfg(test)]
mod test_broker;
#[cfg(test)]
mod tests;

const DEFAULT_PROCESS_EXIT_CODE: i32 = 1;

/// A LiteBox platform with the services required by the Windows shim.
pub trait ShimPlatform:
    RawSyncPrimitivesProvider
    + RawPointerProvider
    + PageManagementProvider<PAGE_SIZE, Reservations = <Self as ShimPlatform>::PlatformReservations>
    + ArchSpecificProvider
    + SystemInfoProvider
    + TimeProvider
    + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
    + 'static
    + Sized
{
    /// Opaque reservation handle retained by the Windows page manager.
    type Reservation: litebox::platform::page_mgmt::PageReservation + Send + Sync;
    /// Platform-selected storage whose handle type is retained by the Windows manager.
    type PlatformReservations: litebox::platform::page_mgmt::ReservationStore<
            Reservation = Self::Reservation,
            ReleaseTarget: From<Self::Reservation>,
        > + Default;
}

impl<T> ShimPlatform for T
where
    T: RawSyncPrimitivesProvider
        + RawPointerProvider
        + PageManagementProvider<PAGE_SIZE>
        + ArchSpecificProvider
        + SystemInfoProvider
        + TimeProvider
        + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
        + 'static,
    litebox::platform::page_mgmt::ReservationOf<T, PAGE_SIZE>: Send + Sync,
    litebox::platform::page_mgmt::ReleaseTargetOf<T, PAGE_SIZE>:
        From<litebox::platform::page_mgmt::ReservationOf<T, PAGE_SIZE>>,
{
    type Reservation = litebox::platform::page_mgmt::ReservationOf<T, PAGE_SIZE>;
    type PlatformReservations = T::Reservations;
}

pub(crate) type ConstPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
pub(crate) type MutPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
pub(crate) type WindowsPageManager<Platform> = page_manager::WindowsPageManager<Platform>;
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

pub(crate) trait WindowsHandleSubsystem<Platform: ShimPlatform>:
    litebox::fd::FdEnabledSubsystem
{
    fn normalize_desired_access(desired_access: u32) -> u32;

    /// Releases an entry once its last handle is closed, or when a handle that was just
    /// created is rolled back.
    fn close_entry(_task: &Task<Platform>, entry: Self::Entry) {
        drop(entry);
    }

    /// Returns the dispatcher object that a wait on `entry` observes, or `None` if handles of
    /// this subsystem are not waitable.
    fn waitable_object(_entry: &Self::Entry) -> Option<syscalls::wait::WaitableObject<Platform>> {
        None
    }

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
pub(crate) type WindowsSectionViews<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<usize, WindowsSectionView<Platform>>>;
pub(crate) type WindowsObjectManager<Platform> = ObjectManager<Platform>;

/// Windows placeholder lifecycle of a logical virtual allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsPlaceholderState {
    /// An ordinary allocation that never participates in placeholder operations.
    None,
    /// A `MEM_RESERVE_PLACEHOLDER` range that can be split, coalesced, or replaced, but not
    /// committed directly.
    Reserved,
    /// A private allocation created with `MEM_REPLACE_PLACEHOLDER`; releasing it with
    /// `MEM_PRESERVE_PLACEHOLDER` turns it back into a `Reserved` placeholder.
    Replaced,
}

/// A guest-visible allocation, stored on every page-manager area it spans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVirtualAllocation {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) allocation_protect: syscalls::mm::PageProtection,
    pub(crate) type_: syscalls::mm::MemoryType,
    /// Tracks both placeholders and private allocations that may be restored to placeholders.
    pub(crate) placeholder_state: WindowsPlaceholderState,
}

impl WindowsVirtualAllocation {
    /// Describes the allocation spanning `base..base + size`.
    pub(crate) fn new(
        base: usize,
        size: usize,
        type_: syscalls::mm::MemoryType,
        allocation_protect: syscalls::mm::PageProtection,
        placeholder_state: WindowsPlaceholderState,
    ) -> Self {
        Self {
            base,
            size,
            allocation_protect,
            type_,
            placeholder_state,
        }
    }

    /// Returns the exclusive end address, or `None` if it overflows.
    pub(crate) fn end(&self) -> Option<usize> {
        self.base.checked_add(self.size)
    }
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

/// Reads the value behind an optional guest input pointer.
///
/// Returns `Ok(None)` when no pointer was supplied and `ACCESS_VIOLATION` when the pointer is
/// unreadable.
pub(crate) fn read_optional_guest_value<Platform, T>(
    ptr: Option<ConstPtr<Platform, T>>,
) -> Result<Option<T>, NtStatus>
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes,
{
    ptr.map(|ptr| ptr.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION))
        .transpose()
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
        platform.set_arch_specific_register(&ArchSpecificRegister::GsBase, teb_address)
    {
        litebox_util_log::warn!(error:? = error, teb:% = format_args!("{teb_address:#x}"); "Failed to set Windows TEB base");
        return false;
    }

    true
}

/// Looks up `raw_fd` in `handles` as a handle of `Subsystem`.
///
/// Returns `INVALID_HANDLE` for an unknown handle and `OBJECT_TYPE_MISMATCH` for a handle of
/// another subsystem.
fn typed_fd_from_raw<Subsystem: litebox::fd::FdEnabledSubsystem>(
    handles: &litebox::fd::RawDescriptorStorage,
    raw_fd: usize,
) -> Result<Arc<litebox::fd::TypedFd<Subsystem>>, NtStatus> {
    handles
        .fd_from_raw_integer::<Subsystem>(raw_fd)
        .map_err(|error| match error {
            litebox::fd::ErrRawIntFd::NotFound => NtStatus::INVALID_HANDLE,
            litebox::fd::ErrRawIntFd::InvalidSubsystem => NtStatus::OBJECT_TYPE_MISMATCH,
        })
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

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    process_id: usize,
    parent_id: Option<usize>,
    initial_thread: litebox::thread::Thread,
}

impl<Platform: ShimPlatform> WindowsShimBuilder<Platform> {
    /// Creates a builder backed by an existing LiteBox instance.
    #[must_use]
    pub fn new_with_litebox(
        platform: &'static Platform,
        litebox: LiteBox<Platform>,
        process_id: usize,
        parent_id: Option<usize>,
        initial_thread: litebox::thread::Thread,
    ) -> Self {
        Self {
            platform,
            litebox,
            process_id,
            parent_id,
            initial_thread,
        }
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    #[must_use]
    pub fn build(self) -> WindowsShim<Platform> {
        debug_assert_ne!(self.initial_thread.id() as usize, self.process_id);
        let litebox = Arc::new(self.litebox);
        let fs = Arc::new(fs::Fs::regular(Arc::clone(&litebox)));
        let global = Arc::new(GlobalState {
            platform: self.platform,
            page_manager: WindowsPageManager::new(self.platform),
            registry: syscalls::registry::RegistryStore::new(fs::Fs::registry(Arc::clone(
                &litebox,
            ))),
            wnf_states: syscalls::wnf::WnfStateStore::new(
                syscalls::wnf::WnfStateStoreData::default(),
            ),
            mui_generation: AtomicU32::new(1),
            qpc_boot_instant: TimeProvider::now(self.platform),
            process_id: self.process_id,
            parent_id: self.parent_id,
            initial_thread: Mutex::new(Some(self.initial_thread)),
            fs,
            litebox,
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
    use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
    use litebox_common_linux::vmem::{CreatePagesFlags, MappingError};
    use zerocopy::IntoBytes as _;
    let address = NonZeroAddress::new(WINDOWS_USER_SHARED_DATA_BASE)?;
    let length =
        NonZeroPageSize::new(size_of::<nt_types::KUserSharedData>().next_multiple_of(PAGE_SIZE))?;
    let shared_data = windows_user_shared_data();
    let shared_data_bytes = shared_data.as_bytes();
    page_manager
        .create_initialized_pages(
            Some(address),
            length,
            crate::syscalls::mm::ALLOCATION_GRANULARITY,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            syscalls::mm::PageProtection::PAGE_READONLY,
            |ptr| {
                ptr.copy_from_slice(0, shared_data_bytes)
                    .ok_or(MappingError::OutOfMemory)?;
                Ok(0)
            },
        )
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
    shared_data.qpc_frequency = syscalls::sysinfo::QPC_FREQUENCY_HZ;
    for (index, code_unit) in r"C:\Windows".encode_utf16().enumerate() {
        shared_data.nt_system_root[index] = code_unit;
    }

    shared_data
}

pub struct WindowsShim<Platform: ShimPlatform>(Arc<GlobalState<Platform>>);

impl<Platform: ShimPlatform> WindowsShim<Platform> {
    /// Loads the program at `path` as the shim's initial task.
    ///
    /// # Panics
    ///
    /// Panics if another initial program has already been loaded from this
    /// shim.
    pub fn load_program(
        &self,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform>, loader::WindowsLoadError> {
        // TODO: refactor the shared mapping
        #[cfg(not(target_os = "windows"))]
        let _ = map_windows_user_shared_data::<Platform>(&self.0.page_manager)
            .ok_or(loader::WindowsLoadError::MapSharedMemory)?;
        let fs = Arc::clone(&self.0.fs);
        let initial_thread_id = self
            .0
            .initial_thread
            .lock()
            .as_ref()
            .expect("the initial thread may load only one program")
            .id();
        let load_info = loader::PeLoader::new(self.0.platform, fs.clone(), &self.0.page_manager)
            .load(
                path,
                &argv,
                &envp,
                self.0.process_id,
                initial_thread_id as usize,
            )?;
        // TODO: shared section should be only created once and shared across all processes, not created per-process.
        let windows_shared_section = crate::syscalls::section::load_time_windows_shared_section(
            load_info.environment.windows_shared_section,
        );
        let mut process = Process::new(self.0.process_id, self.0.parent_id, windows_shared_section);
        process.ntdll = load_info.ntdll;
        process.peb_address = load_info.environment.peb;
        let process = Arc::new(process);
        let thread_object = Arc::new(syscalls::thread::ThreadObject::new(
            initial_thread_id as usize,
            load_info.environment.teb,
        ));
        let attached = process.attach_thread(initial_thread_id as usize, &thread_object);
        debug_assert!(attached, "a freshly created process cannot be exiting");
        let litebox_thread = self
            .0
            .initial_thread
            .lock()
            .take()
            .expect("the initial thread must remain available after loading");
        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
                    process: process.clone(),
                    fs,
                    fs_context: litebox::fs::Context::new(),
                    wait_state: wait::WaitState::new(self.0.platform),
                    io_completion_worker: Mutex::new(syscalls::iocp::IoCompletionWorkerState::new()),
                    entry_point: load_info.entry_point,
                    stack_top: load_info.stack_top,
                    context: load_info.environment.context,
                    thread_object,
                    litebox_thread: Mutex::new(Some(litebox_thread)),
                },
                _not_send: PhantomData,
            },
            process,
        })
    }
}

/// Global shim state shared by all Windows tasks loaded by this shim.
struct GlobalState<Platform: ShimPlatform> {
    platform: &'static Platform,
    page_manager: WindowsPageManager<Platform>,
    registry: syscalls::registry::RegistryStore<Platform>,
    wnf_states: syscalls::wnf::WnfStateStore<Platform>,
    mui_generation: AtomicU32,
    qpc_boot_instant: <Platform as TimeProvider>::Instant,
    process_id: usize,
    parent_id: Option<usize>,
    initial_thread: Mutex<Platform, Option<litebox::thread::Thread>>,
    fs: Arc<fs::Fs<Platform>>,
    litebox: Arc<LiteBox<Platform>>,
}

/// Per-process Windows state shared by every thread in the process.
pub struct Process<Platform: ShimPlatform> {
    /// The NT process ID reported to the guest.
    id: usize,
    /// The NT parent process ID reported to the guest.
    parent_id: usize,
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
    system_lcid: AtomicU32,
    user_lcid: AtomicU32,
    user_ui_language: AtomicU32,
    default_hard_error_mode: AtomicU32,
    wnf_notification_event: Mutex<Platform, Option<Arc<syscalls::event::EventObject<Platform>>>>,
    wnf_subscriptions: Mutex<Platform, syscalls::wnf::WnfProcessSubscriptions>,
    trace_notifications: Mutex<Platform, syscalls::trace::TraceNotifications<Platform>>,
    gdi_state: Mutex<Platform, Option<syscalls::gdi::GdiProcessState>>,
    cookie: u32,
    nr_threads: <Platform as RawMutexProvider>::RawMutex,
    threads: litebox::sync::RwLock<Platform, ProcessThreads<Platform>>,
}

/// The live threads and exit state of a process.
struct ProcessThreads<Platform: ShimPlatform> {
    /// Set once the process has started exiting. No further threads may be
    /// created, and the exit code is frozen.
    group_exit: bool,
    /// The process exit code, updated by thread exits until group exit.
    exit_code: i32,
    /// The thread objects of every thread that has not yet completed, keyed by
    /// thread ID.
    threads: BTreeMap<usize, Arc<syscalls::thread::ThreadObject<Platform>>>,
}

impl<Platform: ShimPlatform> Process<Platform> {
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
        let nr_threads = self.nr_threads.underlying_atomic();
        nr_threads.store(nr_threads.load(Ordering::Relaxed) + 1, Ordering::Release);
        true
    }

    /// Unregisters a thread that failed to start or has completed.
    fn detach_thread(&self, thread_id: usize) {
        let notify = {
            let mut threads = self.threads.write();
            threads.threads.remove(&thread_id);

            let nr_threads = self.nr_threads.underlying_atomic();
            let count = nr_threads.load(Ordering::Relaxed);
            let new_count = count
                .checked_sub(1)
                .expect("decrementing from zero threads");
            nr_threads.store(new_count, Ordering::Release);
            if new_count == 0 {
                debug_assert!(threads.threads.is_empty());
                // The last thread exited. Prevent new threads.
                threads.group_exit = true;
            }
            new_count == 0
        };
        if notify {
            self.nr_threads.wake_all();
        }
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

    /// Waits for all guest threads in the process to complete, returning its exit code.
    #[must_use]
    pub fn wait(&self) -> i32 {
        loop {
            let remaining = self.nr_threads.underlying_atomic().load(Ordering::Acquire);
            if remaining == 0 {
                break;
            }
            let _ = self.nr_threads.block(remaining);
        }
        self.threads.read().exit_code
    }

    fn new(
        process_id: usize,
        parent_id: Option<usize>,
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
            id: process_id,
            parent_id: parent_id.unwrap_or(0),
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
            system_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_lcid: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            user_ui_language: AtomicU32::new(syscalls::nls::DEFAULT_LOCALE_ID),
            default_hard_error_mode: AtomicU32::new(0),
            wnf_notification_event: Mutex::new(None),
            wnf_subscriptions: Mutex::new(syscalls::wnf::WnfProcessSubscriptions::default()),
            trace_notifications: Mutex::new(syscalls::trace::TraceNotifications::default()),
            gdi_state: Mutex::new(None),
            cookie: syscalls::process::default_process_cookie(),
            nr_threads: <Platform as RawMutexProvider>::RawMutex::INIT,
            threads: litebox::sync::RwLock::new(ProcessThreads {
                group_exit: false,
                exit_code: DEFAULT_PROCESS_EXIT_CODE,
                threads: BTreeMap::new(),
            }),
        }
    }
}

struct Task<Platform: ShimPlatform> {
    global: Arc<GlobalState<Platform>>,
    process: Arc<Process<Platform>>,
    fs: Arc<fs::Fs<Platform>>,
    fs_context: litebox::fs::Context,
    wait_state: wait::WaitState<Platform>,
    io_completion_worker: Mutex<Platform, syscalls::iocp::IoCompletionWorkerState<Platform>>,
    entry_point: usize,
    stack_top: usize,
    context: usize,
    /// The NT thread object backing this task.
    thread_object: Arc<syscalls::thread::ThreadObject<Platform>>,
    /// LiteBox thread owned by this task.
    litebox_thread: Mutex<Platform, Option<litebox::thread::Thread>>,
}

impl<Platform: ShimPlatform> Task<Platform> {
    fn complete_current_thread(&self) {
        let thread_id = self.thread_object.thread_id();
        self.thread_object.complete(|| {
            self.release_io_completion_worker();
            self.thread_object.abandon_owned_mutants(thread_id);
            self.process.detach_thread(thread_id);
            let litebox_thread = self
                .litebox_thread
                .lock()
                .take()
                .expect("a live Windows task must own its LiteBox thread");
            debug_assert_eq!(litebox_thread.id() as usize, thread_id);
            let litebox_thread_id = litebox_thread.id();
            if let Err(error) = litebox_thread.exit() {
                litebox_util_log::error!(
                    error:% = error,
                    thread_id = litebox_thread_id;
                    "failed to record thread exit"
                );
            }
        });
    }

    /// Updates the process exit status and marks the current thread as exiting.
    fn exit_thread(&self, exit_status: i32) {
        let mut threads = self.process.threads.write();
        if self.thread_object.is_exiting() {
            return;
        }
        threads.exit_code = exit_status;
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
        threads.exit_code = exit_status;
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

    fn sys_nt_terminate_process(
        &self,
        process_handle: syscalls::ProcessHandle,
        exit_status: i32,
    ) -> NtStatus {
        if process_handle.is_null() {
            // A null handle terminates every other thread in the current process but spares the
            // caller.
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

    fn sys_nt_terminate_thread(
        &self,
        thread_handle: syscalls::ThreadHandle,
        exit_status: i32,
    ) -> NtStatus {
        if !thread_handle.is_null() && !thread_handle.is_current() {
            return NtStatus::NOT_SUPPORTED;
        }
        self.exit_thread(exit_status);
        NtStatus::SUCCESS
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
        self.entry_handle_for(&typed)
    }

    fn entry_handle_for<Subsystem>(
        &self,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn typed_handle_entry_with_access<Subsystem>(
        &self,
        handle: syscalls::Handle,
        required_access: u32,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
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
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        self.typed_handle_entry_with_access_check(handle, |granted_access| granted_access != 0)
    }

    fn typed_handle_entry_with_access_check<Subsystem>(
        &self,
        handle: syscalls::Handle,
        access_check: impl FnOnce(u32) -> bool,
    ) -> Result<litebox::fd::EntryHandle<Platform, Subsystem>, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        let typed = self.typed_handle::<Subsystem>(handle)?;
        if !access_check(self.typed_handle_metadata(&typed)?.granted_access) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        self.entry_handle_for(&typed)
    }

    fn typed_handle<Subsystem>(
        &self,
        handle: syscalls::Handle,
    ) -> Result<Arc<litebox::fd::TypedFd<Subsystem>>, NtStatus>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        let raw_fd = handle.raw_fd().ok_or(NtStatus::INVALID_HANDLE)?;
        typed_fd_from_raw::<Subsystem>(&self.process.handles.read(), raw_fd)
    }

    fn typed_handle_metadata<Subsystem>(
        &self,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<WindowsHandleMetadata, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
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
        Subsystem: WindowsHandleSubsystem<Platform>,
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
        Subsystem: WindowsHandleSubsystem<Platform>,
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
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        self.insert_typed_handle_with_attributes::<Subsystem>(
            entry,
            granted_access,
            HandleAttributes::empty(),
        )
    }

    fn insert_typed_handle_with_attributes<Subsystem>(
        &self,
        entry: Subsystem::Entry,
        granted_access: u32,
        attributes: HandleAttributes,
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
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
        self.publish_typed_handle(typed)
    }

    /// Assigns a handle value to `typed` in the process handle table.
    ///
    /// If no handle value is available, the descriptor is closed through
    /// [`WindowsHandleSubsystem::close_entry`] and `QUOTA_EXCEEDED` is returned.
    fn publish_typed_handle<Subsystem>(
        &self,
        typed: litebox::fd::TypedFd<Subsystem>,
    ) -> Result<syscalls::Handle, NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        let mut handles = self.process.handles.write();
        let raw_fd = handles.fd_into_raw_integer(typed);
        if let Some(handle) = syscalls::Handle::from_raw_fd(raw_fd) {
            return Ok(handle);
        }
        let typed = handles.fd_consume_raw_integer::<Subsystem>(raw_fd).ok();
        drop(handles);
        if let Some(typed) = typed {
            self.close_descriptor(&typed);
        }
        Err(NtStatus::QUOTA_EXCEEDED)
    }

    /// Removes `handle` from the process handle table and closes its descriptor.
    ///
    /// Does nothing if `handle` does not name a `Subsystem` handle.
    fn close_typed_handle<Subsystem>(&self, handle: syscalls::Handle)
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return;
        };
        let typed = self
            .process
            .handles
            .write()
            .fd_consume_raw_integer::<Subsystem>(raw_fd)
            .ok();
        if let Some(typed) = typed {
            self.close_descriptor(&typed);
        }
    }

    /// Removes `typed` from the descriptor table and releases its entry through
    /// [`WindowsHandleSubsystem::close_entry`] once no other descriptor refers to it.
    fn close_descriptor<Subsystem>(&self, typed: &litebox::fd::TypedFd<Subsystem>)
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        let entry = self.global.litebox.descriptor_table_mut().remove(typed);
        if let Some(entry) = entry {
            Subsystem::close_entry(self, entry);
        }
    }

    /// Inserts `entry` as a new handle and writes that handle to the guest pointer `output`.
    ///
    /// If `output` is not writable, the new handle is closed again and `ACCESS_VIOLATION` is
    /// returned.
    fn write_new_typed_handle<Subsystem>(
        &self,
        output: MutPtr<Platform, syscalls::Handle>,
        entry: Subsystem::Entry,
        granted_access: u32,
    ) -> Result<(), NtStatus>
    where
        Subsystem: WindowsHandleSubsystem<Platform>,
    {
        let handle = self.insert_typed_handle::<Subsystem>(entry, granted_access)?;
        if output.write_at_offset(0, handle).is_none() {
            self.close_typed_handle::<Subsystem>(handle);
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        Ok(())
    }

    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if let Some(syscall) = Win32Sysno::from_raw(ctx.orig_rax) {
            ctx.rax = match syscall {
                Win32Sysno::NtGdiInit2 => self.sys_nt_gdi_init2(),
                _ => NtStatus::NOT_SUPPORTED.as_raw().cast_unsigned() as usize,
            };
            return;
        }

        if self.dispatch_nt_syscall(ctx) {
            return;
        }

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
    }

    fn sys_nt_continue(
        &self,
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
            self.test_alert();
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

    fn test_alert(&self) -> NtStatus {
        // TODO(windows-apc): Deliver queued user-mode APCs here.
        if self.thread_object.take_pending_classic_alert() {
            NtStatus::ALERTED
        } else {
            NtStatus::SUCCESS
        }
    }

    pub(crate) fn sys_nt_close(&self, handle: syscalls::Handle) -> NtStatus {
        self.remove_handle(handle, true)
    }

    fn handle_metadata(&self, handle: syscalls::Handle) -> Result<WindowsHandleMetadata, NtStatus> {
        self.with_typed_handle(handle, QueryHandleMetadata)
    }

    fn set_handle_attributes(
        &self,
        handle: syscalls::Handle,
        mask: HandleAttributes,
        attributes: HandleAttributes,
    ) -> Result<(), NtStatus> {
        self.with_typed_handle(handle, SetHandleAttributes { mask, attributes })
    }

    /// Resolves `handle` to its handle subsystem and applies `operation` to it.
    ///
    /// This is the single list of every subsystem that can back a Windows handle.
    fn with_typed_handle<Operation: TypedHandleOperation<Platform>>(
        &self,
        handle: syscalls::Handle,
        operation: Operation,
    ) -> Result<Operation::Output, NtStatus> {
        let raw_fd = handle.raw_fd().ok_or(NtStatus::INVALID_HANDLE)?;
        // Resolve the subsystem under one read guard, then release it before `apply`, which may
        // take the handle table for writing.
        let handles = self.process.handles.read();
        macro_rules! try_subsystem {
            ($subsystem:ty) => {
                match typed_fd_from_raw::<$subsystem>(&handles, raw_fd) {
                    Ok(typed) => {
                        drop(handles);
                        return operation.apply(self, handle, &typed);
                    }
                    Err(NtStatus::OBJECT_TYPE_MISMATCH) => {}
                    Err(status) => return Err(status),
                }
            };
        }

        try_subsystem!(FileObject<Platform>);
        try_subsystem!(RegistryKeyObject<Platform>);
        try_subsystem!(EventSubsystem<Platform>);
        try_subsystem!(MutantSubsystem<Platform>);
        try_subsystem!(SemaphoreSubsystem<Platform>);
        try_subsystem!(DirectoryObjectSubsystem<Platform>);
        try_subsystem!(SymbolicLinkSubsystem<Platform>);
        try_subsystem!(IoCompletionSubsystem<Platform>);
        try_subsystem!(LpcPortSubsystem<Platform>);
        try_subsystem!(TimerSubsystem<Platform>);
        try_subsystem!(WaitCompletionPacketSubsystem<Platform>);
        try_subsystem!(WorkerFactorySubsystem<Platform>);
        try_subsystem!(SectionSubsystem<Platform>);
        try_subsystem!(TokenSubsystem);
        try_subsystem!(ThreadSubsystem<Platform>);

        Err(NtStatus::INVALID_HANDLE)
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
            let _ = self.remove_handle(duplicate, false);
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
                ThreadAccess::ALL_ACCESS.bits()
            } else {
                <ThreadSubsystem<Platform> as WindowsHandleSubsystem<Platform>>::normalize_desired_access(
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
            );
        }

        self.with_typed_handle(
            source_handle,
            DuplicateHandle {
                desired_access,
                handle_attributes,
                options,
            },
        )
    }

    fn remove_handle(
        &self,
        handle: syscalls::Handle,
        enforce_protect_from_close: bool,
    ) -> NtStatus {
        match self.with_typed_handle(
            handle,
            RemoveHandle {
                enforce_protect_from_close,
            },
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
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

/// An operation applied by [`Task::with_typed_handle`] once a handle's subsystem is known.
trait TypedHandleOperation<Platform: ShimPlatform> {
    type Output;

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        handle: syscalls::Handle,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<Self::Output, NtStatus>;
}

struct QueryHandleMetadata;

impl<Platform: ShimPlatform> TypedHandleOperation<Platform> for QueryHandleMetadata {
    type Output = WindowsHandleMetadata;

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        _handle: syscalls::Handle,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<WindowsHandleMetadata, NtStatus> {
        task.typed_handle_metadata(typed)
    }
}

struct SetHandleAttributes {
    mask: HandleAttributes,
    attributes: HandleAttributes,
}

impl<Platform: ShimPlatform> TypedHandleOperation<Platform> for SetHandleAttributes {
    type Output = ();

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        _handle: syscalls::Handle,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<(), NtStatus> {
        task.global
            .litebox
            .descriptor_table_mut()
            .with_metadata_mut::<Subsystem, WindowsHandleMetadata, _>(typed, |metadata| {
                metadata.attributes.remove(self.mask);
                metadata.attributes.insert(self.attributes & self.mask);
            })
            .map_err(|_| NtStatus::INVALID_HANDLE)
    }
}

struct DuplicateHandle {
    desired_access: u32,
    handle_attributes: u32,
    options: DuplicateOptions,
}

impl<Platform: ShimPlatform> TypedHandleOperation<Platform> for DuplicateHandle {
    type Output = syscalls::Handle;

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        _handle: syscalls::Handle,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<syscalls::Handle, NtStatus> {
        let source_metadata = task.typed_handle_metadata(typed)?;
        let duplicate_access = if self.options.contains(DuplicateOptions::SAME_ACCESS) {
            source_metadata.granted_access
        } else {
            task.global
                .litebox
                .descriptor_table()
                .with_entry(typed, |entry| {
                    Subsystem::resolve_duplicate_access(entry, self.desired_access)
                })
                .ok_or(NtStatus::INVALID_HANDLE)??
        };
        let duplicate_attributes = if self.options.contains(DuplicateOptions::SAME_ATTRIBUTES) {
            source_metadata.attributes
        } else {
            HandleAttributes::from_duplicate_attributes(self.handle_attributes)
                .ok_or(NtStatus::INVALID_PARAMETER)?
        };

        let duplicate = {
            let mut descriptors = task.global.litebox.descriptor_table_mut();
            let duplicate = descriptors
                .duplicate(typed)
                .ok_or(NtStatus::INVALID_HANDLE)?;
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
        task.publish_typed_handle(duplicate)
    }
}

struct RemoveHandle {
    enforce_protect_from_close: bool,
}

impl<Platform: ShimPlatform> TypedHandleOperation<Platform> for RemoveHandle {
    type Output = ();

    fn apply<Subsystem: WindowsHandleSubsystem<Platform>>(
        self,
        task: &Task<Platform>,
        handle: syscalls::Handle,
        typed: &litebox::fd::TypedFd<Subsystem>,
    ) -> Result<(), NtStatus> {
        let metadata = task.typed_handle_metadata(typed)?;
        if self.enforce_protect_from_close
            && metadata
                .attributes
                .contains(HandleAttributes::PROTECT_FROM_CLOSE)
        {
            return Err(NtStatus::HANDLE_NOT_CLOSABLE);
        }

        task.close_typed_handle::<Subsystem>(handle);
        Ok(())
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<Platform: ShimPlatform> {
    task: Task<Platform>,
    _not_send: PhantomData<*const ()>,
}

impl<Platform: ShimPlatform> EnterShim for WindowsShimEntrypoints<Platform> {
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

impl<Platform: ShimPlatform> WindowsShimEntrypoints<Platform> {
    /// Runs a shim handler with the wait-state bookkeeping needed to keep the
    /// thread interruptible while it runs guest code.
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<Platform>, &mut litebox_common_linux::PtRegs),
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
pub struct LoadedProgram<Platform: ShimPlatform> {
    /// The initial-thread entrypoint state passed to the platform's `run_thread`.
    pub entrypoints: WindowsShimEntrypoints<Platform>,
    /// Handle used to wait for the loaded program to exit.
    pub process: Arc<Process<Platform>>,
}
