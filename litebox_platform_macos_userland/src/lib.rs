// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 macOS userland platform.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::ops::Range;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};
use std::time::Duration;

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError, RemapError,
};
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, GuestVectorStateProvider,
    PageManagementProvider, Provider, RawConstPointer as _, RawPointerProvider, SignalProvider,
    SystemInfoProvider, ThreadLocalStorageProvider, ThreadProvider, TimerProvider,
    common_providers, trivial_providers,
};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::gate_recovery::{
    Aarch64GateSignalResult, GateInterruption, GateRuntimeState, canonicalize,
};
use litebox_common_linux::{GuestVectorState, PtRegs};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use litebox_syscall_rewriter::aarch64::{
    SVC_FRAME_BYTES, is_patchable_guest_tpidr_offset, is_patchable_guest_x18_offset,
};
use zerocopy::{FromBytes, IntoBytes};

pub use litebox::mm::linux::PAGE_SIZE;
/// The macOS host's Mach-O `__PAGEZERO` reserves the first 4 GiB.
pub const TASK_ADDR_MIN: usize = 0x1_0000_0000;
/// Exclusive upper bound for guest mappings (`MACH_VM_MAX_ADDRESS` on AArch64 macOS).
pub const TASK_ADDR_MAX: usize = 0x7FFF_FE00_0000;

#[derive(Debug)]
pub struct MacosUserland {
    pages: std::sync::Mutex<std::collections::BTreeSet<usize>>,
}

impl MacosUserland {
    /// Initialize the platform.
    pub fn new() -> std::io::Result<&'static Self> {
        // SAFETY: this scalar query has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if usize::try_from(page_size).ok() != Some(PAGE_SIZE) {
            return Err(std::io::Error::other("unexpected macOS page size"));
        }
        TLS_KEYS
            .get_or_init(create_tls_keys)
            .as_ref()
            .map_err(|error| std::io::Error::from_raw_os_error(*error))?;
        initialize_thread_tls()?;
        register_exception_handlers()?;
        Ok(Box::leak(Box::new(Self {
            pages: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        })))
    }
}

impl Provider for MacosUserland {}
impl RawPointerProvider for MacosUserland {
    type RawConstPointer<T: FromBytes> = common_providers::userspace_pointers::UserConstPtr<
        common_providers::userspace_pointers::NoValidation,
        T,
    >;
    type RawMutPointer<T: FromBytes + IntoBytes> = common_providers::userspace_pointers::UserMutPtr<
        common_providers::userspace_pointers::NoValidation,
        T,
    >;
}

// SAFETY: the pointer is isolated in this thread's macOS TSD block.
unsafe impl ThreadLocalStorageProvider for MacosUserland {
    fn get_thread_local_storage() -> *mut () {
        let Some(Ok(keys)) = TLS_KEYS.get() else {
            return core::ptr::null_mut();
        };
        // SAFETY: the process-wide key remains allocated for the process lifetime.
        unsafe {
            libc::pthread_getspecific(keys.slots[tls_offset::PLATFORM_TLS / size_of::<usize>()])
        }
        .cast()
    }
    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        let key = keys().slots[tls_offset::PLATFORM_TLS / size_of::<usize>()];
        // SAFETY: the process-wide key remains allocated for the process lifetime.
        let previous = unsafe { libc::pthread_getspecific(key) };
        // SAFETY: the caller guarantees value is valid and the key has no destructor.
        if unsafe { libc::pthread_setspecific(key, value.cast_const().cast()) } != 0 {
            fatal_signal(b"failed to set platform TLS", 0);
        }
        previous.cast()
    }
}

impl TimeProvider for MacosUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;
    fn now(&self) -> Instant {
        Instant(std::time::Instant::now())
    }
    fn current_time(&self) -> SystemTime {
        SystemTime(std::time::SystemTime::now())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(std::time::Instant);
impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }
    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}
pub struct SystemTime(std::time::SystemTime);
impl SystemTimeTrait for SystemTime {
    const UNIX_EPOCH: Self = Self(std::time::UNIX_EPOCH);
    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0.duration_since(earlier.0).map_err(|e| e.duration())
    }
}

/// Futex-like wait/wake using a host condition variable.
pub struct RawMutex {
    value: AtomicU32,
    gate: std::sync::Mutex<()>,
    ready: std::sync::Condvar,
}
impl RawMutexProvider for MacosUserland {
    type RawMutex = RawMutex;
}
impl RawMutexTrait for RawMutex {
    const INIT: Self = Self {
        value: AtomicU32::new(0),
        gate: std::sync::Mutex::new(()),
        ready: std::sync::Condvar::new(),
    };
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.value
    }
    fn wake_many(&self, n: usize) -> usize {
        let _guard = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if n >= i32::MAX as usize {
            self.ready.notify_all();
        } else {
            for _ in 0..n {
                self.ready.notify_one();
            }
        }
        0 // std::sync::Condvar does not report the number notified.
    }
    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        let guard = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.value.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        drop(
            self.ready
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        Ok(())
    }
    fn block_or_timeout(
        &self,
        val: u32,
        time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let guard = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.value.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        let (_guard, result) = self
            .ready
            .wait_timeout(guard, time)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(if result.timed_out() {
            UnblockedOrTimedOut::TimedOut
        } else {
            UnblockedOrTimedOut::Unblocked
        })
    }
}

impl TimerProvider for MacosUserland {
    type TimerHandle = trivial_providers::UnsupportedTimerHandle;
    type Signal = litebox_common_linux::signal::Signal;
}
impl SignalProvider for MacosUserland {
    type Signal = litebox_common_linux::signal::Signal;
}
impl litebox::mm::linux::VmemPageFaultHandler for MacosUserland {
    unsafe fn handle_page_fault(
        &self,
        _: usize,
        _: litebox::mm::linux::VmFlags,
        _: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("XNU handles page faults for macOS userland")
    }
    fn access_error(_: u64, _: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("XNU handles page faults for macOS userland")
    }
}

const KERN_PROTECTION_FAILURE: i32 = 2;
const KERN_RESOURCE_SHORTAGE: i32 = 6;

unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
    fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
}
fn is_page_aligned(range: &Range<usize>) -> bool {
    range.start < range.end
        && range.start.is_multiple_of(PAGE_SIZE)
        && range.end.is_multiple_of(PAGE_SIZE)
}
fn prot_flags(p: MemoryRegionPermissions) -> i32 {
    (i32::from(p.contains(MemoryRegionPermissions::READ)) * libc::PROT_READ)
        | (i32::from(p.contains(MemoryRegionPermissions::WRITE)) * libc::PROT_WRITE)
        | (i32::from(p.contains(MemoryRegionPermissions::EXEC)) * libc::PROT_EXEC)
}
fn wx(p: MemoryRegionPermissions) -> bool {
    p.contains(MemoryRegionPermissions::WRITE | MemoryRegionPermissions::EXEC)
}

fn allocation_error(errno: i32) -> AllocationError {
    match errno {
        libc::EACCES | libc::EPERM => AllocationError::PermissionDenied,
        libc::EEXIST => AllocationError::AddressInUse,
        _ => AllocationError::OutOfMemory,
    }
}

fn permission_update_error(errno: i32) -> PermissionUpdateError {
    match errno {
        libc::EACCES | libc::EPERM => PermissionUpdateError::PermissionDenied,
        libc::ENOMEM => PermissionUpdateError::OutOfMemory,
        _ => PermissionUpdateError::PlatformFailure,
    }
}

impl PageManagementProvider<PAGE_SIZE> for MacosUserland {
    const TASK_ADDR_MIN: usize = TASK_ADDR_MIN;
    const TASK_ADDR_MAX: usize = TASK_ADDR_MAX;
    fn allocate_pages(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        // TODO: grow the mapping from the signal path. macOS has no
        // MAP_GROWSDOWN equivalent, so the initial stack is currently fixed-size.
        let _ = can_grow_down;
        // Eager population is an optional performance hint.
        let _ = populate_pages_immediately;
        if !is_page_aligned(&range) {
            return Err(AllocationError::Unaligned);
        }
        if range.start < TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if wx(permissions) {
            return Err(AllocationError::PermissionDenied);
        }
        let mut pages = self.pages.lock().unwrap();
        if behavior == FixedAddressBehavior::Hint {
            let mut error = AllocationError::OutOfMemory;
            for hint in [range.start, 0] {
                // SAFETY: anonymous, page-aligned allocation; without MAP_FIXED the hint cannot replace memory.
                let mapped = unsafe {
                    libc::mmap(
                        hint as *mut _,
                        range.len(),
                        prot_flags(permissions),
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    // SAFETY: __error returns the current thread's live errno slot.
                    error = allocation_error(unsafe { *libc::__error() });
                    continue;
                }
                let start = mapped as usize;
                if start < TASK_ADDR_MIN
                    || start
                        .checked_add(range.len())
                        .is_none_or(|end| end > TASK_ADDR_MAX)
                {
                    // SAFETY: this is the unused mapping just returned by mmap.
                    unsafe {
                        libc::munmap(mapped, range.len());
                    }
                    continue;
                }
                pages.extend((start..start + range.len()).step_by(PAGE_SIZE));
                return Ok(Self::RawMutPointer::from_usize(start));
            }
            return Err(error);
        }
        if behavior != FixedAddressBehavior::Replace && pages.range(range.clone()).next().is_some()
        {
            return Err(AllocationError::AddressInUse);
        }
        let mut reserved = Vec::new();
        for page in range.clone().step_by(PAGE_SIZE) {
            if pages.contains(&page) {
                continue;
            }
            let mut address = page as u64;
            // SAFETY: address is writable, the size is page-aligned, and the task port is ours.
            // VM_FLAGS_FIXED (0) rejects occupied ranges rather than overwriting them.
            let result = unsafe {
                mach_vm_allocate(mach_task_self(), &raw mut address, PAGE_SIZE as u64, 0)
            };
            if result != 0 {
                for page in reserved {
                    // SAFETY: these pages were reserved by this call and have not been published.
                    unsafe {
                        libc::munmap(page as *mut _, PAGE_SIZE);
                    }
                }
                return Err(match result {
                    KERN_PROTECTION_FAILURE => AllocationError::PermissionDenied,
                    KERN_RESOURCE_SHORTAGE => AllocationError::OutOfMemory,
                    _ => AllocationError::AddressInUseByPlatform,
                });
            }
            reserved.push(page);
        }
        // SAFETY: every page is guest-owned or newly reserved; the lock prevents mapping changes.
        // MAP_FIXED cannot replace Rust allocations in this range.
        let mapped = unsafe {
            libc::mmap(
                range.start as *mut _,
                range.len(),
                prot_flags(permissions),
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            // SAFETY: __error returns the current thread's live errno slot.
            let errno = unsafe { *libc::__error() };
            for page in reserved {
                // SAFETY: release only this call's unpublished reservations.
                unsafe {
                    libc::munmap(page as *mut _, PAGE_SIZE);
                }
            }
            return Err(allocation_error(errno));
        }
        pages.extend(range.clone().step_by(PAGE_SIZE));
        Ok(Self::RawMutPointer::from_usize(range.start))
    }
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
        if !is_page_aligned(&range) {
            return Err(DeallocationError::Unaligned);
        }
        let mut pages = self.pages.lock().unwrap();
        // Leave host-owned pages in holes untouched, and make work proportional
        // to owned mappings rather than the requested virtual-address span.
        let owned = pages.range(range).copied().collect::<Vec<_>>();
        for page in owned {
            // SAFETY: the registry owns this page and the caller guarantees it is no longer in use.
            if unsafe { libc::munmap(page as *mut _, PAGE_SIZE) } != 0 {
                return Err(DeallocationError::AlreadyUnallocated);
            }
            pages.remove(&page);
        }
        Ok(())
    }
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        if !is_page_aligned(&old_range) || !is_page_aligned(&new_range) {
            return Err(RemapError::Unaligned);
        }
        if old_range.start < new_range.end && new_range.start < old_range.end {
            return Err(RemapError::Overlapping);
        }
        if new_range.len() <= old_range.len() {
            return Err(RemapError::OutOfMemory);
        }
        {
            let pages = self.pages.lock().unwrap();
            if old_range
                .clone()
                .step_by(PAGE_SIZE)
                .any(|page| !pages.contains(&page))
            {
                return Err(RemapError::AlreadyUnallocated);
            }
        }

        let mut temporary =
            permissions | MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        temporary.remove(MemoryRegionPermissions::EXEC);
        let map_error = |error| match error {
            AllocationError::Unaligned => RemapError::Unaligned,
            AllocationError::PermissionDenied => RemapError::PermissionDenied,
            AllocationError::AddressInUse
            | AllocationError::AddressPartiallyInUse
            | AllocationError::AddressInUseByPlatform => RemapError::AlreadyAllocated,
            _ => RemapError::OutOfMemory,
        };
        let preferred = self.allocate_pages(
            new_range.clone(),
            temporary,
            false,
            true,
            FixedAddressBehavior::NoReplace,
        );
        let new_ptr = match preferred {
            Ok(ptr) => ptr,
            Err(
                AllocationError::AddressInUse
                | AllocationError::AddressPartiallyInUse
                | AllocationError::AddressInUseByPlatform,
            ) => self
                .allocate_pages(
                    new_range.clone(),
                    temporary,
                    false,
                    true,
                    FixedAddressBehavior::Hint,
                )
                .map_err(map_error)?,
            Err(error) => return Err(map_error(error)),
        };
        let allocated_range = new_ptr.as_usize()..new_ptr.as_usize() + new_range.len();

        let source_readable = if permissions.contains(MemoryRegionPermissions::READ) {
            Ok(())
        } else {
            // SAFETY: the caller permits moving the idle source mapping.
            unsafe {
                self.update_permissions(
                    old_range.clone(),
                    permissions | MemoryRegionPermissions::READ,
                )
            }
        };
        if let Err(error) = source_readable {
            // SAFETY: this call allocated the destination and has not published it.
            let _ = unsafe { self.deallocate_pages(allocated_range) };
            return Err(match error {
                PermissionUpdateError::PermissionDenied => RemapError::PermissionDenied,
                PermissionUpdateError::Unallocated => RemapError::AlreadyUnallocated,
                _ => RemapError::OutOfMemory,
            });
        }

        // SAFETY: the destination is writable and the source was made readable above.
        if unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                allocated_range.start as *mut u8,
                old_range.start as *const u8,
                old_range.len(),
            )
        }
        .is_err()
        {
            if !permissions.contains(MemoryRegionPermissions::READ) {
                // SAFETY: restore the still-owned source mapping before returning.
                let _ = unsafe { self.update_permissions(old_range.clone(), permissions) };
            }
            // SAFETY: this call allocated the destination and has not published it.
            let _ = unsafe { self.deallocate_pages(allocated_range) };
            return Err(RemapError::AlreadyUnallocated);
        }
        let final_permissions = if temporary == permissions {
            Ok(())
        } else {
            // SAFETY: the destination is unpublished and exclusively owned by this call.
            unsafe { self.update_permissions(allocated_range.clone(), permissions) }
        };
        if let Err(error) = final_permissions {
            if !permissions.contains(MemoryRegionPermissions::READ) {
                // SAFETY: restore the still-owned source mapping before returning.
                let _ = unsafe { self.update_permissions(old_range.clone(), permissions) };
            }
            // SAFETY: this call allocated the destination and has not published it.
            let _ = unsafe { self.deallocate_pages(allocated_range) };
            return Err(match error {
                PermissionUpdateError::PermissionDenied => RemapError::PermissionDenied,
                _ => RemapError::OutOfMemory,
            });
        }
        // SAFETY: the copied source is no longer needed and the caller permits moving it.
        unsafe { self.deallocate_pages(old_range) }.map_err(|_| RemapError::AlreadyUnallocated)?;
        Ok(new_ptr)
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        if !is_page_aligned(&range) {
            return Err(PermissionUpdateError::Unaligned);
        }
        if wx(permissions) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        let pages = self.pages.lock().unwrap();
        if range
            .clone()
            .step_by(PAGE_SIZE)
            .any(|p| !pages.contains(&p))
        {
            return Err(PermissionUpdateError::Unallocated);
        }
        let executable = permissions.contains(MemoryRegionPermissions::EXEC);
        let cache_permissions = if executable {
            (permissions | MemoryRegionPermissions::READ) & !MemoryRegionPermissions::EXEC
        } else {
            permissions
        };
        // SAFETY: the locked registry covers the aligned range; the caller permits reprotection.
        if unsafe {
            libc::mprotect(
                range.start as *mut _,
                range.len(),
                prot_flags(cache_permissions),
            )
        } != 0
        {
            // SAFETY: __error returns the current thread's live errno slot.
            return Err(permission_update_error(unsafe { *libc::__error() }));
        }
        if executable {
            // SAFETY: mprotect made the entire owned range readable for cache maintenance.
            unsafe { sys_icache_invalidate(range.start as *mut _, range.len()) };
            if cache_permissions != permissions
                // SAFETY: the same owned range remains mapped; the caller permits the final permissions.
                && unsafe {
                    libc::mprotect(range.start as *mut _, range.len(), prot_flags(permissions))
                } != 0
            {
                // SAFETY: __error returns the current thread's live errno slot.
                return Err(permission_update_error(unsafe { *libc::__error() }));
            }
        }
        Ok(())
    }
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        std::iter::empty()
    }
}

// The macOS pthread TSD ABI addresses key slots relative to TPIDRRO_EL0.
// TODO: use one pthread key pointing to a LiteBox-owned TlsBlock, reducing the
// private ABI dependency to locating that single key slot.
#[repr(C)]
struct TlsBlock {
    platform_tls: usize,
    guest_thread_pointer: usize,
    guest_x18: usize,
    active: usize,
    current_thread: usize,
    in_guest: usize,
    vector_state: usize,
    host_fp_state: usize,
    initialized: usize,
}

mod tls_offset {
    use super::TlsBlock;

    pub const PLATFORM_TLS: usize = core::mem::offset_of!(TlsBlock, platform_tls);
    pub const GUEST_THREAD_POINTER: usize = core::mem::offset_of!(TlsBlock, guest_thread_pointer);
    pub const GUEST_X18: usize = core::mem::offset_of!(TlsBlock, guest_x18);
    pub const ACTIVE: usize = core::mem::offset_of!(TlsBlock, active);
    pub const CURRENT_THREAD: usize = core::mem::offset_of!(TlsBlock, current_thread);
    pub const IN_GUEST: usize = core::mem::offset_of!(TlsBlock, in_guest);
    pub const VECTOR_STATE: usize = core::mem::offset_of!(TlsBlock, vector_state);
    pub const HOST_FP_STATE: usize = core::mem::offset_of!(TlsBlock, host_fp_state);
    pub const INITIALIZED: usize = core::mem::offset_of!(TlsBlock, initialized);
}

const TLS_SLOT_COUNT: usize = size_of::<TlsBlock>() / size_of::<usize>();

#[derive(Debug)]
struct GuestTlsKeys {
    slots: [libc::pthread_key_t; TLS_SLOT_COUNT],
    interrupt_signal: i32,
}

static TLS_KEYS: OnceLock<Result<GuestTlsKeys, i32>> = OnceLock::new();
static TLS_BLOCK_OFFSET: AtomicUsize = AtomicUsize::new(0);

impl Drop for GuestTlsKeys {
    fn drop(&mut self) {
        for key in self.slots {
            // SAFETY: GuestTlsKeys owns every successfully allocated key.
            unsafe { libc::pthread_key_delete(key) };
        }
    }
}

fn keys() -> &'static GuestTlsKeys {
    let Some(Ok(keys)) = TLS_KEYS.get() else {
        fatal_signal(b"macOS TLS is not initialized", 0);
    };
    keys
}

unsafe extern "C" fn drop_vector_state(value: *mut libc::c_void) {
    if !value.is_null() {
        // SAFETY: the vector-state slot contains only pointers created by Box::into_raw below.
        unsafe { drop(Box::from_raw(value.cast::<GuestVectorState>())) };
    }
}

fn create_tls_keys() -> Result<GuestTlsKeys, i32> {
    let mut keys = [0; TLS_SLOT_COUNT];
    for index in 0..TLS_SLOT_COUNT {
        let destructor = (index * size_of::<usize>() == tls_offset::VECTOR_STATE)
            .then_some(drop_vector_state as unsafe extern "C" fn(*mut libc::c_void));
        // SAFETY: the array element is writable; only the vector slot owns its opaque pointer.
        let error = unsafe { libc::pthread_key_create(&raw mut keys[index], destructor) };
        if error != 0 {
            for key in &keys[..index] {
                // SAFETY: these keys were allocated by preceding iterations.
                unsafe { libc::pthread_key_delete(*key) };
            }
            return Err(error);
        }
    }
    let first: usize = keys[0].trunc();
    if keys.iter().enumerate().any(|(index, key)| {
        let key: usize = (*key).trunc();
        key != first + index
    }) || !u16::try_from(first * size_of::<usize>() + tls_offset::GUEST_THREAD_POINTER)
        .is_ok_and(is_patchable_guest_tpidr_offset)
        || !u16::try_from(first * size_of::<usize>() + tls_offset::GUEST_X18)
            .is_ok_and(is_patchable_guest_x18_offset)
    {
        for key in keys {
            // SAFETY: every key was allocated above and has not been published.
            unsafe { libc::pthread_key_delete(key) };
        }
        return Err(libc::ENOTSUP);
    }
    let mut interrupt_signal = None;
    for candidate in [libc::SIGUSR1, libc::SIGUSR2] {
        // SAFETY: macOS sigaction contains integer fields; zero is a valid representation.
        let mut disposition = unsafe { std::mem::zeroed::<libc::sigaction>() };
        // SAFETY: disposition is writable and null requests a query.
        if unsafe { libc::sigaction(candidate, core::ptr::null(), &raw mut disposition) } != 0 {
            for key in keys {
                // SAFETY: every key was allocated above and has not been published.
                unsafe { libc::pthread_key_delete(key) };
            }
            // SAFETY: __error returns the current thread's live errno slot.
            return Err(unsafe { *libc::__error() });
        }
        if disposition.sa_sigaction == libc::SIG_DFL {
            interrupt_signal = Some(candidate);
            break;
        }
    }
    let Some(interrupt_signal) = interrupt_signal else {
        for key in keys {
            // SAFETY: every key was allocated above and has not been published.
            unsafe { libc::pthread_key_delete(key) };
        }
        return Err(libc::EBUSY);
    };
    TLS_BLOCK_OFFSET.store(first * size_of::<usize>(), Ordering::Relaxed);
    Ok(GuestTlsKeys {
        slots: keys,
        interrupt_signal,
    })
}

fn anchor() -> usize {
    let value;
    // SAFETY: TPIDRRO_EL0 is readable at EL0 on macOS; this changes no memory or flags.
    unsafe {
        core::arch::asm!("mrs {value}, tpidrro_el0", value = out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn tls_block_offset() -> usize {
    let first: usize = keys().slots[0].trunc();
    first * size_of::<usize>()
}

fn tls_address(offset: usize) -> *mut usize {
    (anchor() + tls_block_offset() + offset) as *mut usize
}

fn read_tls(offset: usize) -> usize {
    // SAFETY: initialization verifies every allocated key maps to its TPIDRRO-relative slot.
    unsafe { tls_address(offset).read_volatile() }
}

fn write_tls(offset: usize, value: usize) {
    // SAFETY: initialization verifies every allocated key maps to its TPIDRRO-relative slot.
    unsafe { tls_address(offset).write_volatile(value) }
}

fn initialize_thread_tls() -> std::io::Result<()> {
    let keys = keys();
    let initialized_key = keys.slots[tls_offset::INITIALIZED / size_of::<usize>()];
    // SAFETY: the process-wide key remains allocated for the process lifetime.
    if !unsafe { libc::pthread_getspecific(initialized_key) }.is_null() {
        return Ok(());
    }
    for (index, key) in keys.slots.iter().copied().enumerate() {
        let sentinel = 0x1234usize + index;
        // SAFETY: the key remains allocated; pthread treats the value as opaque.
        let previous = unsafe { libc::pthread_getspecific(key) };
        // SAFETY: the key remains allocated and has no destructor.
        let error = unsafe { libc::pthread_setspecific(key, sentinel as *const libc::c_void) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
        let mut value = [0u8; size_of::<usize>()];
        let mut copied = 0;
        // SAFETY: value and copied are writable; Mach validates the source address without faulting.
        let valid = unsafe {
            mach_vm_read_overwrite(
                mach_task_self(),
                tls_address(index * size_of::<usize>()) as u64,
                value.len() as u64,
                value.as_mut_ptr() as u64,
                &raw mut copied,
            ) == 0
        } && copied == value.len() as u64
            && usize::from_ne_bytes(value) == sentinel;
        // SAFETY: restores the opaque value previously read from this allocated key.
        let error = unsafe { libc::pthread_setspecific(key, previous) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
        if !valid {
            return Err(std::io::Error::other(
                "unsupported macOS pthread TSD layout",
            ));
        }
    }
    let vector_slot = tls_address(tls_offset::VECTOR_STATE);
    // SAFETY: this thread's vector slot was validated above.
    let vector = unsafe { vector_slot.read_volatile() };
    if vector == 0 {
        let vector = Box::into_raw(Box::new(GuestVectorState::default())) as usize;
        // SAFETY: the key is allocated with drop_vector_state as its destructor.
        let error = unsafe {
            libc::pthread_setspecific(
                keys.slots[tls_offset::VECTOR_STATE / size_of::<usize>()],
                vector as *const libc::c_void,
            )
        };
        if error != 0 {
            // SAFETY: pthread did not take ownership after the failed call.
            unsafe { drop(Box::from_raw(vector as *mut GuestVectorState)) };
            return Err(std::io::Error::from_raw_os_error(error));
        }
    }
    // Publish initialization only after every slot and owned allocation is valid.
    // SAFETY: initialized_key is allocated and has no destructor.
    let error = unsafe { libc::pthread_setspecific(initialized_key, core::ptr::dangling()) };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error));
    }
    Ok(())
}

fn guest_thread_pointer_offset() -> usize {
    tls_block_offset() + tls_offset::GUEST_THREAD_POINTER
}
fn guest_thread_pointer_address() -> usize {
    tls_address(tls_offset::GUEST_THREAD_POINTER) as usize
}
fn get_guest_thread_pointer() -> usize {
    read_tls(tls_offset::GUEST_THREAD_POINTER)
}
fn get_guest_x18() -> usize {
    read_tls(tls_offset::GUEST_X18)
}
fn set_guest_thread_pointer(value: usize) {
    write_tls(tls_offset::GUEST_THREAD_POINTER, value);
}
fn set_guest_x18(value: usize) {
    write_tls(tls_offset::GUEST_X18, value);
}

impl ArchSpecificProvider for MacosUserland {
    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        match reg {
            ArchSpecificRegister::TpidrEl0 => Ok(get_guest_thread_pointer()),
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        value: usize,
    ) -> Result<(), ArchSpecificError> {
        match reg {
            ArchSpecificRegister::TpidrEl0 => {
                if litebox_common_linux::arch::is_valid_user_tls_base(value) {
                    set_guest_thread_pointer(value);
                    Ok(())
                } else {
                    Err(ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
}

fn interrupt_signal() -> i32 {
    keys().interrupt_signal
}

fn host_signals() -> [i32; 5] {
    [
        libc::SIGTRAP,
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGILL,
        interrupt_signal(),
    ]
}
static PREVIOUS: OnceLock<[libc::sigaction; 5]> = OnceLock::new();

#[derive(Clone, Copy)]
enum GuestExit {
    Syscall,
    Exception(ExceptionInfo),
    Interrupt,
}

struct ThreadContext<'a> {
    shim: &'a dyn EnterShim<ExecutionContext = PtRegs>,
    ctx: &'a mut PtRegs,
    host_sp: usize,
    interrupted: *const AtomicBool,
    thread: ThreadHandle,
    exit: GuestExit,
}

struct ThreadState {
    // Cleared before thread exit to prevent pthread ID-reuse races.
    identity: Mutex<Option<usize>>,
    interrupted: AtomicBool,
    waker: Mutex<Option<core::task::Waker>>,
}
#[derive(Clone)]
pub struct ThreadHandle(Arc<ThreadState>);
impl ThreadHandle {
    fn current() -> Self {
        let handle = read_tls(tls_offset::CURRENT_THREAD) as *const ThreadHandle;
        assert!(!handle.is_null(), "not running a LiteBox thread");
        // SAFETY: CURRENT_THREAD points to this thread's live stack-owned handle.
        unsafe { (*handle).clone() }
    }

    fn interrupt(&self) {
        self.0.interrupted.store(true, Ordering::Release);
        {
            let identity = self.0.identity.lock().unwrap();
            if let Some(identity) = *identity {
                // SAFETY: this lock prevents unregistering/reusing the saved pthread_t during delivery.
                unsafe { libc::pthread_kill(identity as libc::pthread_t, interrupt_signal()) };
            }
        }
        let waker = self.0.waker.lock().unwrap().clone();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl ThreadProvider for MacosUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;
    unsafe fn spawn_thread(
        &self,
        _ctx: &Self::ExecutionContext,
        _init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>>,
    ) -> Result<(), Self::ThreadSpawnError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "guest thread creation is not supported",
        ))
    }
    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }
    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        initialize_thread_tls().expect("unsupported macOS TLS layout");
        assert_eq!(read_tls(tls_offset::CURRENT_THREAD), 0);
        let handle = ThreadHandle(Arc::new(ThreadState {
            // SAFETY: pthread_self has no preconditions.
            identity: Mutex::new(Some(unsafe { libc::pthread_self() } as usize)),
            interrupted: AtomicBool::new(false),
            waker: Mutex::new(None),
        }));
        write_tls(tls_offset::CURRENT_THREAD, (&raw const handle) as usize);
        let cleanup_handle = handle.clone();
        let _cleanup = litebox::utils::defer(move || {
            *cleanup_handle.0.identity.lock().unwrap() = None;
            write_tls(tls_offset::CURRENT_THREAD, 0);
        });
        f()
    }
}

impl WaitWakerProvider for MacosUserland {
    fn update_waker(&self, waker: Option<core::task::Waker>) {
        if read_tls(tls_offset::CURRENT_THREAD) != 0 {
            *ThreadHandle::current().0.waker.lock().unwrap() = waker;
        }
    }
}
pub(crate) fn get_guest_vector_state() -> GuestVectorState {
    let state = read_tls(tls_offset::VECTOR_STATE) as *const GuestVectorState;
    assert!(!state.is_null(), "macOS TLS is not initialized");
    // SAFETY: this thread owns the allocation; volatile matches transition
    // assembly and signal-handler accesses hidden from the compiler.
    unsafe { state.read_volatile() }
}
pub(crate) fn set_guest_vector_state(state: &GuestVectorState) {
    let saved = read_tls(tls_offset::VECTOR_STATE) as *mut GuestVectorState;
    assert!(!saved.is_null(), "macOS TLS is not initialized");
    // SAFETY: this thread owns the allocation; volatile matches transition
    // assembly and signal-handler accesses hidden from the compiler.
    unsafe { saved.write_volatile(state.clone()) };
}

impl GuestVectorStateProvider for MacosUserland {
    type GuestVectorState = litebox_common_linux::GuestVectorState;
    fn get_guest_vector_state(&self) -> Self::GuestVectorState {
        get_guest_vector_state()
    }
    fn set_guest_vector_state(&self, state: &Self::GuestVectorState) {
        set_guest_vector_state(state);
    }
}
impl SystemInfoProvider for MacosUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }
    fn guest_thread_pointer_offset(&self) -> Option<usize> {
        Some(guest_thread_pointer_offset())
    }
    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

// SVC gate callback: the macOS signal frame captures the full register state at this PC.
unsafe extern "C" {
    fn litebox_macos_syscall_callback_end();
    fn switch_to_guest_via_signal_start();
    fn switch_to_guest_via_signal_end();
    fn switch_to_guest_via_outbound_stub_start();
    fn switch_to_guest_via_outbound_stub_end();
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_callback() {
    core::arch::naked_asm!(
        // Preserve guest x17 in the unused SVC-frame word before using it as scratch.
        "str x17, [sp, #24]",
        "mrs x16, tpidrro_el0",
        "adrp x17, {tls_block_offset}@PAGE",
        "ldr x17, [x17, {tls_block_offset}@PAGEOFF]",
        "add x16, x16, x17",
        "ldr x17, [x16, #{active}]", // ThreadContext
        "ldr x17, [x17, #{context}]", // PtRegs
        "stp x0, x1, [x17, #0]",
        "stp x2, x3, [x17, #16]",
        "stp x4, x5, [x17, #32]",
        "stp x6, x7, [x17, #48]",
        "stp x8, x9, [x17, #64]",
        "stp x10, x11, [x17, #80]",
        "stp x12, x13, [x17, #96]",
        "stp x14, x15, [x17, #112]",
        "ldr x0, [sp, #0]",
        "ldr x1, [sp, #24]",
        "stp x0, x1, [x17, #128]",
        "ldr x0, [x16, #{guest_x18}]",
        "str x0, [x17, #144]",
        "stp x19, x20, [x17, #152]",
        "stp x21, x22, [x17, #168]",
        "stp x23, x24, [x17, #184]",
        "stp x25, x26, [x17, #200]",
        "stp x27, x28, [x17, #216]",
        "stp x29, x30, [x17, #232]",
        "add x0, sp, #{svc_frame}",
        "str x0, [x17, #{regs_sp}]",
        "ldr x0, [sp, #8]",
        "str x0, [x17, #{regs_pc}]",
        "mrs x0, nzcv",
        "str x0, [x17, #{regs_pstate}]",
        "ldr x0, [x17, #0]",
        "str x0, [x17, #{regs_orig_x0}]",
        "str w8, [x17, #{regs_syscallno}]",
        "mov x0, #-38",
        "str x0, [x17, #0]",
        // Save guest vector state before entering host Rust code.
        "ldr x0, [x16, #{vector_state}]",
        "stp q0, q1, [x0, #0]",
        "stp q2, q3, [x0, #32]",
        "stp q4, q5, [x0, #64]",
        "stp q6, q7, [x0, #96]",
        "stp q8, q9, [x0, #128]",
        "stp q10, q11, [x0, #160]",
        "stp q12, q13, [x0, #192]",
        "stp q14, q15, [x0, #224]",
        "stp q16, q17, [x0, #256]",
        "stp q18, q19, [x0, #288]",
        "stp q20, q21, [x0, #320]",
        "stp q22, q23, [x0, #352]",
        "stp q24, q25, [x0, #384]",
        "stp q26, q27, [x0, #416]",
        "stp q28, q29, [x0, #448]",
        "stp q30, q31, [x0, #480]",
        "mrs x1, fpsr",
        "str w1, [x0, #{vector_fpsr}]",
        "mrs x1, fpcr",
        "str w1, [x0, #{vector_fpcr}]",
        // Restore the host's FP control state before entering Rust.
        "ldp w1, w2, [x16, #{host_fp_state}]",
        "msr fpsr, x1",
        "msr fpcr, x2",
        "str xzr, [x16, #{in_guest}]",
        "ldr x0, [x16, #{active}]", // ThreadContext
        "mov x2, sp", // SVC frame
        "ldr x1, [x0, #{host_sp}]",
        "mov sp, x1",
        "mov x1, x2",
        "bl {syscall_handler}",
        "b {finish_thread_arch}",
        ".globl _litebox_macos_syscall_callback_end",
        "_litebox_macos_syscall_callback_end:",
        tls_block_offset = sym TLS_BLOCK_OFFSET,
        active = const tls_offset::ACTIVE,
        in_guest = const tls_offset::IN_GUEST,
        guest_x18 = const tls_offset::GUEST_X18,
        vector_state = const tls_offset::VECTOR_STATE,
        context = const core::mem::offset_of!(ThreadContext, ctx),
        host_sp = const core::mem::offset_of!(ThreadContext, host_sp),
        regs_sp = const core::mem::offset_of!(PtRegs, sp),
        regs_pc = const core::mem::offset_of!(PtRegs, pc),
        regs_pstate = const core::mem::offset_of!(PtRegs, pstate),
        regs_orig_x0 = const core::mem::offset_of!(PtRegs, orig_x0),
        regs_syscallno = const core::mem::offset_of!(PtRegs, syscallno),
        vector_fpsr = const core::mem::offset_of!(GuestVectorState, fpsr),
        vector_fpcr = const core::mem::offset_of!(GuestVectorState, fpcr),
        host_fp_state = const tls_offset::HOST_FP_STATE,
        svc_frame = const SVC_FRAME_BYTES,
        syscall_handler = sym syscall_handler,
        finish_thread_arch = sym finish_thread_arch,
    );
}

// TODO: replace this synthetic signal return with a guest-side restoration
// stub that can resume an arbitrary context without relying on private XNU
// sigreturn-frame details.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_signal() -> ! {
    core::arch::naked_asm!(
        ".globl _switch_to_guest_via_signal_start",
        "_switch_to_guest_via_signal_start:",
        "mrs x16, tpidrro_el0",
        "adrp x17, {tls_block_offset}@PAGE",
        "ldr x17, [x17, {tls_block_offset}@PAGEOFF]",
        "add x16, x16, x17",
        "mrs x17, fpsr",
        "mrs x9, fpcr",
        "stp w17, w9, [x16, #{host_fp_state}]",
        "brk #0",
        ".globl _switch_to_guest_via_signal_end",
        "_switch_to_guest_via_signal_end:",
        tls_block_offset = sym TLS_BLOCK_OFFSET,
        host_fp_state = const tls_offset::HOST_FP_STATE,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_outbound_stub(_: &mut ThreadContext) -> ! {
    core::arch::naked_asm!(
        ".globl _switch_to_guest_via_outbound_stub_start",
        "_switch_to_guest_via_outbound_stub_start:",
        // x0 is ThreadContext and remains available if an interrupt is pending.
        "ldr x16, [x0, #{context}]",
        "mrs x17, tpidrro_el0",
        "adrp x1, {tls_block_offset}@PAGE",
        "ldr x1, [x1, {tls_block_offset}@PAGEOFF]",
        "add x17, x17, x1",
        // Save host FP control state before installing the guest's.
        "mrs x1, fpsr",
        "mrs x2, fpcr",
        "stp w1, w2, [x17, #{host_fp_state}]",
        "mov x1, #1",
        "str x1, [x17, #{in_guest}]",
        "ldr x1, [x0, #{interrupted}]",
        "ldarb w1, [x1]",
        "cbz w1, 1f",
        "b _switch_to_guest_via_outbound_stub_interrupted",
        "1:",
        "ldr x1, [x16, #144]",
        "str x1, [x17, #{guest_x18}]",
        "ldr x0, [x17, #{vector_state}]",
        "ldp q0, q1, [x0, #0]",
        "ldp q2, q3, [x0, #32]",
        "ldp q4, q5, [x0, #64]",
        "ldp q6, q7, [x0, #96]",
        "ldp q8, q9, [x0, #128]",
        "ldp q10, q11, [x0, #160]",
        "ldp q12, q13, [x0, #192]",
        "ldp q14, q15, [x0, #224]",
        "ldp q16, q17, [x0, #256]",
        "ldp q18, q19, [x0, #288]",
        "ldp q20, q21, [x0, #320]",
        "ldp q22, q23, [x0, #352]",
        "ldp q24, q25, [x0, #384]",
        "ldp q26, q27, [x0, #416]",
        "ldp q28, q29, [x0, #448]",
        "ldp q30, q31, [x0, #480]",
        "ldr w1, [x0, #{vector_fpsr}]",
        "msr fpsr, x1",
        "ldr w1, [x0, #{vector_fpcr}]",
        "msr fpcr, x1",
        "ldr x0, [x16, #{regs_pstate}]",
        "msr nzcv, x0",
        "ldp x0, x1, [x16, #0]",
        "ldp x2, x3, [x16, #16]",
        "ldp x4, x5, [x16, #32]",
        "ldp x6, x7, [x16, #48]",
        "ldp x8, x9, [x16, #64]",
        "ldp x10, x11, [x16, #80]",
        "ldp x12, x13, [x16, #96]",
        "ldp x14, x15, [x16, #112]",
        "ldr x17, [x16, #136]",
        "ldp x19, x20, [x16, #152]",
        "ldp x21, x22, [x16, #168]",
        "ldp x23, x24, [x16, #184]",
        "ldp x25, x26, [x16, #200]",
        "ldp x27, x28, [x16, #216]",
        "ldp x29, x30, [x16, #232]",
        "ldr x16, [x16, #{regs_sp}]",
        "sub sp, x16, #{svc_frame}",
        "ldr x16, [sp, #16]",
        "br x16",
        ".globl _switch_to_guest_via_outbound_stub_end",
        "_switch_to_guest_via_outbound_stub_end:",
        "_switch_to_guest_via_outbound_stub_interrupted:",
        "str xzr, [x17, #{in_guest}]",
        "bl {direct_interrupt_handler}",
        "b {finish_thread_arch}",
        tls_block_offset = sym TLS_BLOCK_OFFSET,
        in_guest = const tls_offset::IN_GUEST,
        guest_x18 = const tls_offset::GUEST_X18,
        vector_state = const tls_offset::VECTOR_STATE,
        host_fp_state = const tls_offset::HOST_FP_STATE,
        context = const core::mem::offset_of!(ThreadContext, ctx),
        interrupted = const core::mem::offset_of!(ThreadContext, interrupted),
        regs_sp = const core::mem::offset_of!(PtRegs, sp),
        regs_pstate = const core::mem::offset_of!(PtRegs, pstate),
        vector_fpsr = const core::mem::offset_of!(GuestVectorState, fpsr),
        vector_fpcr = const core::mem::offset_of!(GuestVectorState, fpcr),
        svc_frame = const SVC_FRAME_BYTES,
        direct_interrupt_handler = sym direct_interrupt_handler,
        finish_thread_arch = sym finish_thread_arch,
    );
}

/// Run a guest thread.
///
/// # Safety
/// The shim must supply valid mappings and macOS-targeted rewritten guest code.
pub unsafe fn run_thread<T: EnterShim<ExecutionContext = PtRegs>>(shim: T, regs: &mut PtRegs) {
    // SAFETY: the caller supplies valid guest mappings; shim and regs remain live for this call.
    unsafe { run_thread_inner(&shim, regs) };
}

unsafe fn run_thread_inner(shim: &dyn EnterShim<ExecutionContext = PtRegs>, ctx: &mut PtRegs) {
    assert!(
        read_tls(tls_offset::ACTIVE) == 0,
        "nested guest entry is not supported"
    );
    initialize_thread_tls().expect("unsupported macOS TLS layout");
    set_guest_thread_pointer(0);
    set_guest_x18(0);
    let thread = ThreadHandle(Arc::new(ThreadState {
        // SAFETY: pthread_self has no preconditions; unregister before thread exit.
        identity: Mutex::new(Some(unsafe { libc::pthread_self() } as usize)),
        interrupted: AtomicBool::new(false),
        waker: Mutex::new(None),
    }));
    let mut thread_ctx = ThreadContext {
        shim,
        ctx,
        host_sp: 0,
        interrupted: &raw const thread.0.interrupted,
        thread,
        exit: GuestExit::Interrupt,
    };
    write_tls(tls_offset::ACTIVE, (&raw mut thread_ctx) as usize);
    write_tls(
        tls_offset::CURRENT_THREAD,
        (&raw const thread_ctx.thread) as usize,
    );
    let thread_handle = thread_ctx.thread.clone();
    let _registration = litebox::utils::defer(move || {
        *thread_handle.0.identity.lock().unwrap() = None;
        write_tls(tls_offset::ACTIVE, 0);
        write_tls(tls_offset::CURRENT_THREAD, 0);
        write_tls(tls_offset::IN_GUEST, 0);
    });
    // SAFETY: macOS sigset_t is an integer bitmask; zero is valid output storage.
    let mut old_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: zero is valid for this integer bitmask.
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: both masks are live stack storage; only this thread's mask is changed.
    unsafe {
        libc::sigemptyset(&raw mut signals);
        for signal in host_signals() {
            libc::sigaddset(&raw mut signals, signal);
        }
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const signals, &raw mut old_mask),
            0
        );
    }
    let _mask_guard = litebox::utils::defer(|| {
        assert_eq!(
            // SAFETY: old_mask is this thread's saved mask and remains live.
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const old_mask,
                    core::ptr::null_mut(),
                )
            },
            0,
        );
    });
    with_signal_alt_stack(|| {
        // SAFETY: thread state, handlers and stack are initialized; the caller supplies valid guest mappings.
        unsafe { run_thread_arch(&mut thread_ctx) };
    });
}

fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = (libc::SIGSTKSZ * 2).next_multiple_of(PAGE_SIZE);
    let mapping_size = PAGE_SIZE + alt_stack_size;
    // SAFETY: allocate fresh anonymous memory without replacing any existing mapping.
    let stack_base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            mapping_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        stack_base,
        libc::MAP_FAILED,
        "failed to allocate signal stack"
    );
    let _unmap_guard = litebox::utils::defer(|| {
        assert_eq!(
            // SAFETY: the previous altstack is restored before this owned mapping is freed.
            unsafe { libc::munmap(stack_base, mapping_size) },
            0,
        );
    });
    assert_eq!(
        // SAFETY: the first page is exclusively owned and outside the usable signal stack.
        unsafe { libc::mprotect(stack_base, PAGE_SIZE, libc::PROT_NONE) },
        0,
    );
    let alternate = libc::stack_t {
        ss_sp: stack_base.wrapping_byte_add(PAGE_SIZE),
        ss_size: alt_stack_size,
        ss_flags: 0,
    };
    // SAFETY: stack_t consists of a nullable pointer and integers, all zero-valid.
    let mut previous = unsafe { std::mem::zeroed::<libc::stack_t>() };
    assert_eq!(
        // SAFETY: the writable mapping stays live until the previous altstack is restored.
        unsafe { libc::sigaltstack(&raw const alternate, &raw mut previous) },
        0,
    );
    let _restore_guard = litebox::utils::defer(|| {
        assert_eq!(
            // SAFETY: f and its handlers have returned; the saved descriptor remains live.
            unsafe { libc::sigaltstack(&raw const previous, core::ptr::null_mut()) },
            0,
        );
    });
    f()
}

impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(&dyn EnterShim<ExecutionContext = PtRegs>, &mut PtRegs) -> ContinueOperation,
    ) {
        self.call_shim_with_svc_frame(f, None);
    }

    fn call_shim_with_svc_frame(
        &mut self,
        f: impl FnOnce(&dyn EnterShim<ExecutionContext = PtRegs>, &mut PtRegs) -> ContinueOperation,
        svc_frame: Option<usize>,
    ) {
        let mut operation = f(self.shim, self.ctx);
        if operation == ContinueOperation::Resume
            && self.thread.0.interrupted.swap(false, Ordering::AcqRel)
        {
            operation = self.shim.interrupt(self.ctx);
        }
        if operation == ContinueOperation::Resume {
            // SAFETY: the shim prepared the guest context; no owned guards cross the switch.
            unsafe { switch_to_guest(self, svc_frame) };
        }
    }
}

unsafe fn switch_to_guest(thread_ctx: &mut ThreadContext, svc_frame: Option<usize>) -> ! {
    if let Some(frame_sp) = svc_frame {
        let mut frame = [[0u8; size_of::<usize>()]; 3];
        if read_guest(frame_sp, frame.as_flattened_mut()) {
            let [saved_x16, return_pc, outbound_stub] = frame.map(usize::from_ne_bytes);
            if outbound_stub != 0
                && thread_ctx.ctx.pc == return_pc
                && thread_ctx.ctx.regs[16] == saved_x16
            {
                // SAFETY: the frame and context satisfy the SVC outbound-stub ABI.
                unsafe { switch_to_guest_via_outbound_stub(thread_ctx) }
            }
        }
    }
    // SAFETY: generic resume obtains an XNU-created signal context to restore every register.
    unsafe { switch_to_guest_via_signal() }
}

extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext, svc_frame: usize) {
    thread_ctx.call_shim_with_svc_frame(|shim, ctx| shim.syscall(ctx), Some(svc_frame));
}

extern "C-unwind" fn direct_interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx
        .thread
        .0
        .interrupted
        .store(false, Ordering::Release);
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

extern "C-unwind" fn exit_handler(thread_ctx: &mut ThreadContext) {
    let exit = thread_ctx.exit;
    if matches!(exit, GuestExit::Interrupt) {
        thread_ctx
            .thread
            .0
            .interrupted
            .store(false, Ordering::Release);
    }
    thread_ctx.call_shim(|shim, ctx| match exit {
        GuestExit::Syscall => shim.syscall(ctx),
        GuestExit::Exception(info) => shim.exception(ctx, &info),
        GuestExit::Interrupt => shim.interrupt(ctx),
    });
}

fn set_signal_return(mc: &mut libc::__darwin_mcontext64, thread_ctx: &ThreadContext) {
    // Retain the function defining the assembly callback, including in platform-only builds.
    core::hint::black_box(run_thread_arch as *const ());
    let host_fp_state = read_tls(tls_offset::HOST_FP_STATE);
    mc.__ns.__fpsr = host_fp_state.trunc();
    mc.__ns.__fpcr = (host_fp_state >> 32).trunc();
    mc.__ss.__pc = litebox_macos_host_callback as *const () as u64;
    mc.__ss.__sp = thread_ctx.host_sp as u64;
    mc.__ss.__fp = (thread_ctx.host_sp + 16) as u64;
}

fn read_guest(address: usize, output: &mut [u8]) -> bool {
    // SAFETY: output is writable; callers read guest mappings or pthread-owned ABI storage.
    // Faulting source reads use the installed exception-table handler, not Rust references.
    unsafe {
        litebox::mm::exception_table::memcpy_fallible(
            output.as_mut_ptr(),
            address as *const u8,
            output.len(),
        )
        .is_ok()
    }
}
fn copy_signal_context(regs: &mut PtRegs, mc: &libc::__darwin_mcontext64) {
    for (dst, src) in regs.regs[..29].iter_mut().zip(&mc.__ss.__x) {
        *dst = src.trunc();
    }
    regs.regs[18] = get_guest_x18();
    regs.regs[29] = mc.__ss.__fp.trunc();
    regs.regs[30] = mc.__ss.__lr.trunc();
    regs.sp = mc.__ss.__sp.trunc();
    regs.pc = mc.__ss.__pc.trunc();
    regs.pstate = u64::from(mc.__ss.__cpsr) & litebox_common_linux::arch::SAFE_USER_PSTATE;
    regs.orig_x0 = regs.regs[0];
    regs.syscallno = litebox_common_linux::arch::NO_SYSCALL;
    let state = read_tls(tls_offset::VECTOR_STATE) as *mut GuestVectorState;
    if state.is_null() {
        fatal_signal(b"guest vector state is not initialized", regs.pc);
    }
    let captured = GuestVectorState {
        registers: mc.__ns.__v,
        fpsr: mc.__ns.__fpsr,
        fpcr: mc.__ns.__fpcr,
    };
    // SAFETY: state is this thread's allocation; volatile matches transition assembly.
    unsafe { state.write_volatile(captured) }
}
fn restore_signal_context(regs: &PtRegs, mc: &mut libc::__darwin_mcontext64) {
    set_guest_x18(regs.regs[18]);
    for (i, value) in regs.regs[..29].iter().enumerate() {
        if i != 18 {
            mc.__ss.__x[i] = *value as u64;
        }
    }
    mc.__ss.__fp = regs.regs[29] as u64;
    mc.__ss.__lr = regs.regs[30] as u64;
    mc.__ss.__sp = regs.sp as u64;
    mc.__ss.__pc = regs.pc as u64;
    mc.__ss.__cpsr = (regs.pstate & litebox_common_linux::arch::SAFE_USER_PSTATE).trunc();
    let state = read_tls(tls_offset::VECTOR_STATE) as *const GuestVectorState;
    if state.is_null() {
        fatal_signal(b"guest vector state is not initialized", regs.pc);
    }
    // SAFETY: state is this thread's allocation; volatile matches transition assembly.
    let state = unsafe { state.read_volatile() };
    mc.__ns.__v = state.registers;
    mc.__ns.__fpsr = state.fpsr;
    mc.__ns.__fpcr = state.fpcr;
}

fn fatal_signal(message: &[u8], pc: usize) -> ! {
    const DIGITS: usize = size_of::<usize>() * 2;
    let mut address = [b'0'; DIGITS + 1];
    for (index, byte) in address[..DIGITS].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[(pc >> ((DIGITS - index - 1) * 4)) & 15];
    }
    address[DIGITS] = b'\n';
    // SAFETY: all buffers are live for their lengths; write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
        libc::write(libc::STDERR_FILENO, b" pc=0x".as_ptr().cast(), 6);
        libc::write(libc::STDERR_FILENO, address.as_ptr().cast(), address.len());
        libc::_exit(128 + libc::SIGABRT);
    }
}

fn resume_or_interrupt(mc: &mut libc::__darwin_mcontext64, thread_ctx: &mut ThreadContext) {
    if thread_ctx.thread.0.interrupted.load(Ordering::Acquire) {
        thread_ctx.exit = GuestExit::Interrupt;
        set_signal_return(mc, thread_ctx);
    } else {
        restore_signal_context(thread_ctx.ctx, mc);
        write_tls(tls_offset::IN_GUEST, 1);
    }
}

pub(crate) fn register_exception_handlers() -> std::io::Result<()> {
    static INSTALLED: Mutex<bool> = Mutex::new(false);
    let mut installed = INSTALLED.lock().unwrap();
    if *installed {
        return Ok(());
    }
    // SAFETY: macOS sigaction contains integer fields; zero is a valid representation.
    let mut previous = unsafe { std::mem::zeroed::<[libc::sigaction; 5]>() };
    for (signal, previous) in host_signals().into_iter().zip(&mut previous) {
        // SAFETY: previous is writable and null requests a query without installing a handler.
        if unsafe { libc::sigaction(signal, core::ptr::null(), previous) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let previous = PREVIOUS.get_or_init(|| previous);
    // SAFETY: zero is valid for every field; the handler, flags and mask are filled below.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = exception_signal_handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
    // SAFETY: action.sa_mask is writable storage for these sigset operations.
    unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        // Allow nested memory faults for fallible reads, but not shim re-entry.
        libc::sigaddset(&raw mut action.sa_mask, interrupt_signal());
        libc::sigaddset(&raw mut action.sa_mask, libc::SIGTRAP);
    }
    let restore = |count| {
        for (signal, previous) in host_signals().into_iter().zip(previous.iter()).take(count) {
            // SAFETY: these immutable actions were returned by sigaction for the same signals.
            unsafe {
                libc::sigaction(signal, previous, core::ptr::null_mut());
            }
        }
    };
    for (index, signal) in host_signals().into_iter().enumerate() {
        // SAFETY: sigaction consists of zero-valid scalar fields.
        let mut replaced = unsafe { std::mem::zeroed::<libc::sigaction>() };
        // SAFETY: action is initialized, replaced is writable, and SA_SIGINFO matches the handler.
        let result = unsafe { libc::sigaction(signal, &raw const action, &raw mut replaced) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            restore(index);
            return Err(error);
        }
        if signal == interrupt_signal() && replaced.sa_sigaction != libc::SIG_DFL {
            // SAFETY: replaced was atomically returned while installing this signal's action.
            unsafe { libc::sigaction(signal, &raw const replaced, core::ptr::null_mut()) };
            restore(index);
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "interrupt signal already has a host handler",
            ));
        }
    }
    *installed = true;
    Ok(())
}

fn exception_class(esr: u64) -> u8 {
    (esr >> 26).trunc()
}

fn is_application_signal(code: i32) -> bool {
    const SI_USER: i32 = 0x1_0001;
    const SI_QUEUE: i32 = 0x1_0002;
    matches!(code, SI_USER | SI_QUEUE)
}

fn is_synchronous_memory_fault(signal: i32, code: i32, esr: u64) -> bool {
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    let abort = matches!(
        Exception(exception_class(esr)),
        Exception::INSTRUCTION_ABORT_LOWER_EL
            | Exception::INSTRUCTION_ABORT_CURRENT_EL
            | Exception::DATA_ABORT_LOWER_EL
            | Exception::DATA_ABORT_CURRENT_EL
    );
    abort
        && match signal {
            libc::SIGSEGV => matches!(code, SEGV_MAPERR | SEGV_ACCERR),
            libc::SIGBUS => matches!(code, libc::BUS_ADRALN | libc::BUS_ADRERR | libc::BUS_OBJERR),
            _ => false,
        }
}

fn gate_interruption(signal: i32, code: i32, esr: u64) -> GateInterruption {
    if is_synchronous_memory_fault(signal, code, esr) {
        GateInterruption::Synchronous
    } else if signal == libc::SIGTRAP && esr >> 26 == u64::from(Exception::BRK64.0) {
        GateInterruption::Breakpoint
    } else {
        GateInterruption::Asynchronous
    }
}

unsafe extern "C" fn exception_signal_handler(
    signal: i32,
    info: *mut libc::siginfo_t,
    raw: *mut libc::c_void,
) {
    // SAFETY: SA_SIGINFO supplies a live, aligned ucontext for this invocation.
    let uc = unsafe { &mut *raw.cast::<libc::ucontext_t>() };
    // SAFETY: the machine context is live; nested signals receive separate frames.
    let mc = unsafe { &mut *uc.uc_mcontext };
    let pc: usize = mc.__ss.__pc.trunc();
    let esr = u64::from(mc.__es.__esr);
    // SAFETY: SA_SIGINFO supplies a live siginfo for this invocation.
    let code = unsafe { (*info).si_code };
    if is_synchronous_memory_fault(signal, code, esr)
        && let Some(fixup) = litebox::mm::exception_table::search_exception_tables(pc)
    {
        mc.__ss.__pc = fixup as u64;
        return;
    }
    if signal != interrupt_signal() && is_application_signal(code) {
        // Application-originated signals are not a guest signal source.
        // SAFETY: the kernel-provided signal arguments remain live for forwarding.
        unsafe { next_signal_handler(signal, info, raw) };
        return;
    }
    let ptr = read_tls(tls_offset::ACTIVE) as *mut ThreadContext<'static>;
    let breakpoint = signal == libc::SIGTRAP && exception_class(esr) == Exception::BRK64.0;
    let resuming = breakpoint
        && (switch_to_guest_via_signal_start as *const () as usize
            ..switch_to_guest_via_signal_end as *const () as usize)
            .contains(&pc);
    let in_guest = read_tls(tls_offset::IN_GUEST) != 0;
    let in_syscall_transition = (syscall_callback as *const () as usize
        ..litebox_macos_syscall_callback_end as *const () as usize)
        .contains(&pc);
    let in_resume_transition = (switch_to_guest_via_outbound_stub_start as *const () as usize
        ..switch_to_guest_via_outbound_stub_end as *const () as usize)
        .contains(&pc);
    if !ptr.is_null() && in_guest && in_syscall_transition {
        if signal != interrupt_signal() {
            fatal_signal(b"fault in macOS syscall transition", pc);
        }
        // ThreadState::interrupt already recorded the request. Let the direct
        // callback finish saving a coherent guest context before dispatching it.
        return;
    }
    if !ptr.is_null() && in_guest && in_resume_transition {
        if signal != interrupt_signal() {
            fatal_signal(b"fault in macOS guest-resume transition", pc);
        }
        write_tls(tls_offset::IN_GUEST, 0);
        // SAFETY: ACTIVE remains live while run_thread_arch is suspended.
        let thread_ctx = unsafe { &mut *ptr };
        thread_ctx.exit = GuestExit::Interrupt;
        set_signal_return(mc, thread_ctx);
        return;
    }
    if ptr.is_null() || (!in_guest && !resuming) {
        if signal != interrupt_signal() {
            // SAFETY: the kernel-provided signal arguments remain live for forwarding.
            unsafe { next_signal_handler(signal, info, raw) };
        }
        return;
    }
    write_tls(tls_offset::IN_GUEST, 0);
    // SAFETY: ACTIVE remains live while run_thread_arch is suspended; nested shim access is disabled.
    let thread_ctx = unsafe { &mut *ptr };
    if resuming {
        resume_or_interrupt(mc, thread_ctx);
        return;
    }

    copy_signal_context(thread_ctx.ctx, mc);
    if pc == syscall_callback as *const () as usize && breakpoint {
        let ctx = &mut *thread_ctx.ctx;
        // Frame: [x16, return PC, outbound stub, padding]. Sigreturn skips the stub.
        let mut frame = [[0u8; 8]; 3];
        if !read_guest(ctx.sp, frame.as_flattened_mut()) {
            fatal_signal(b"unreadable SVC gate frame", pc);
        }
        let frame = frame.map(usize::from_ne_bytes);
        ctx.regs[16] = frame[0];
        ctx.pc = frame[1];
        ctx.sp = ctx.sp.wrapping_add(usize::from(SVC_FRAME_BYTES));
        let syscallno: u32 = ctx.regs[8].trunc();
        ctx.syscallno = syscallno.cast_signed();
        ctx.orig_x0 = ctx.regs[0];
        ctx.regs[0] = (-38isize).cast_unsigned(); // Linux ENOSYS on entry
        thread_ctx.exit = GuestExit::Syscall;
    } else {
        match canonicalize(
            thread_ctx.ctx,
            GateRuntimeState {
                guest_thread_pointer_addr: guest_thread_pointer_address(),
                // XNU resumes this context via sigreturn, never an outbound stub.
                expected_outbound_stub: 0,
                expected_outbound_pc: 0,
            },
            gate_interruption(signal, code, esr),
            litebox_syscall_rewriter::TargetHost::MacOs,
            true,
            read_guest,
        ) {
            Aarch64GateSignalResult::NotGate => {}
            Aarch64GateSignalResult::Canonicalized(ctx) => *thread_ctx.ctx = ctx,
            Aarch64GateSignalResult::ResumeGuest(ctx) => {
                *thread_ctx.ctx = ctx;
                resume_or_interrupt(mc, thread_ctx);
                return;
            }
            Aarch64GateSignalResult::InvalidRuntimeState => {
                fatal_signal(b"invalid AArch64 gate runtime state", pc)
            }
            Aarch64GateSignalResult::PreserveSavedContext => {
                fatal_signal(b"unexpected macOS outbound-stub recovery", pc)
            }
        }
        thread_ctx.exit = if signal == interrupt_signal() {
            GuestExit::Interrupt
        } else {
            let exception = match signal {
                libc::SIGILL => Exception::INSTRUCTION_ABORT_LOWER_EL,
                libc::SIGTRAP => Exception::BRK64,
                _ if is_synchronous_memory_fault(signal, code, esr)
                    && matches!(
                        Exception(exception_class(esr)),
                        Exception::INSTRUCTION_ABORT_LOWER_EL
                            | Exception::INSTRUCTION_ABORT_CURRENT_EL
                    ) =>
                {
                    Exception::INSTRUCTION_ABORT_LOWER_EL
                }
                _ => Exception::DATA_ABORT_LOWER_EL,
            };
            GuestExit::Exception(ExceptionInfo {
                exception,
                fault_address: mc.__es.__far.trunc(),
                esr,
                kernel_mode: false,
            })
        };
    }
    set_signal_return(mc, thread_ctx);
}

unsafe fn next_signal_handler(signal: i32, info: *mut libc::siginfo_t, raw: *mut libc::c_void) {
    let Some(previous) = host_signals()
        .iter()
        .position(|s| *s == signal)
        .and_then(|index| PREVIOUS.get()?.get(index))
    else {
        fatal_signal(b"missing host signal disposition", 0);
    };
    match previous.sa_sigaction {
        // SAFETY: signal came from host_signals(); these scalar APIs restore its default disposition.
        libc::SIG_DFL => unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        },
        libc::SIG_IGN => {}
        // SAFETY: sigaction returned a live callback, and the sentinel cases were excluded.
        // SA_SIGINFO selects this three-argument C ABI; info and raw remain live for the call.
        handler if previous.sa_flags & libc::SA_SIGINFO != 0 => unsafe {
            let handler: unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
                std::mem::transmute(handler);
            handler(signal, info, raw);
        },
        // SAFETY: the saved non-sentinel callback lacks SA_SIGINFO, selecting the one-argument C ABI.
        handler => unsafe {
            let handler: unsafe extern "C" fn(i32) = std::mem::transmute(handler);
            handler(signal);
        },
    }
}

unsafe extern "C" {
    fn litebox_macos_host_callback();
}

#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(_: &mut ThreadContext) {
    // SAFETY: the caller supplies live thread state and guest mappings. Both
    // entry paths use the same host frame, including during Rust unwinding.
    core::arch::naked_asm!(
        ".cfi_startproc",
        "stp x29, x30, [sp, #-160]!",
        ".cfi_def_cfa_offset 160",
        ".cfi_offset x29, -160",
        ".cfi_offset x30, -152",
        "mov x29, sp",
        ".cfi_def_cfa x29, 160",
        "stp x19, x20, [sp, #16]",
        ".cfi_offset x19, -144",
        ".cfi_offset x20, -136",
        "stp x21, x22, [sp, #32]",
        ".cfi_offset x21, -128",
        ".cfi_offset x22, -120",
        "stp x23, x24, [sp, #48]",
        ".cfi_offset x23, -112",
        ".cfi_offset x24, -104",
        "stp x25, x26, [sp, #64]",
        ".cfi_offset x25, -96",
        ".cfi_offset x26, -88",
        "stp x27, x28, [sp, #80]",
        ".cfi_offset x27, -80",
        ".cfi_offset x28, -72",
        "stp d8, d9, [sp, #96]",
        ".cfi_offset d8, -64",
        ".cfi_offset d9, -56",
        "stp d10, d11, [sp, #112]",
        ".cfi_offset d10, -48",
        ".cfi_offset d11, -40",
        "stp d12, d13, [sp, #128]",
        ".cfi_offset d12, -32",
        ".cfi_offset d13, -24",
        "stp d14, d15, [sp, #144]",
        ".cfi_offset d14, -16",
        ".cfi_offset d15, -8",
        "sub sp, sp, #16",
        "str x0, [sp]",
        "mov x1, sp",
        "str x1, [x0, #{host_sp}]",
        "bl {init_handler}",
        "b {finish_thread_arch}",
        // Mach-O requires a separate FDE for this alternate entry point.
        ".cfi_endproc",
        ".globl _litebox_macos_host_callback",
        "_litebox_macos_host_callback:",
        ".cfi_startproc",
        ".cfi_def_cfa x29, 160",
        ".cfi_offset x29, -160",
        ".cfi_offset x30, -152",
        ".cfi_offset x19, -144",
        ".cfi_offset x20, -136",
        ".cfi_offset x21, -128",
        ".cfi_offset x22, -120",
        ".cfi_offset x23, -112",
        ".cfi_offset x24, -104",
        ".cfi_offset x25, -96",
        ".cfi_offset x26, -88",
        ".cfi_offset x27, -80",
        ".cfi_offset x28, -72",
        ".cfi_offset d8, -64",
        ".cfi_offset d9, -56",
        ".cfi_offset d10, -48",
        ".cfi_offset d11, -40",
        ".cfi_offset d12, -32",
        ".cfi_offset d13, -24",
        ".cfi_offset d14, -16",
        ".cfi_offset d15, -8",
        "ldr x0, [sp]",
        "bl {exit_handler}",
        "b {finish_thread_arch}",
        ".cfi_endproc",
        host_sp = const core::mem::offset_of!(ThreadContext, host_sp),
        init_handler = sym init_handler,
        exit_handler = sym exit_handler,
        finish_thread_arch = sym finish_thread_arch,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn finish_thread_arch() {
    core::arch::naked_asm!(
        ".cfi_startproc",
        ".cfi_def_cfa x29, 160",
        ".cfi_offset x29, -160",
        ".cfi_offset x30, -152",
        "add sp, sp, #16",
        "ldp x19, x20, [sp, #16]",
        "ldp x21, x22, [sp, #32]",
        "ldp x23, x24, [sp, #48]",
        "ldp x25, x26, [sp, #64]",
        "ldp x27, x28, [sp, #80]",
        "ldp d8, d9, [sp, #96]",
        "ldp d10, d11, [sp, #112]",
        "ldp d12, d13, [sp, #128]",
        "ldp d14, d15, [sp, #144]",
        "ldp x29, x30, [sp], #160",
        ".cfi_def_cfa sp, 0",
        "ret",
        ".cfi_endproc",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawMutPointer as _;
    const RW: MemoryRegionPermissions =
        MemoryRegionPermissions::READ.union(MemoryRegionPermissions::WRITE);

    #[test]
    fn pstate_capture_and_restore_preserve_only_user_bits() {
        use litebox_common_linux::arch::{
            PSR_DIT_BIT, PSR_NZCV_MASK, PSR_SSBS_BIT, SAFE_USER_PSTATE,
        };

        MacosUserland::new().unwrap();
        let vector = get_guest_vector_state();
        let _restore = litebox::utils::defer(|| set_guest_vector_state(&vector));
        // SAFETY: this register-state struct contains only integers and arrays; zero is valid.
        let mut mc: libc::__darwin_mcontext64 = unsafe { core::mem::zeroed() };
        let mut regs = PtRegs::default();
        for (index, value) in mc.__ss.__x.iter_mut().enumerate() {
            *value = 0x1000 + index as u64;
        }
        mc.__ss.__fp = 0x2000;
        mc.__ss.__lr = 0x3000;
        mc.__ss.__sp = 0x4000;
        mc.__ss.__pc = 0x5000;
        for (index, value) in mc.__ns.__v.iter_mut().enumerate() {
            *value = 0x6000 + index as u128;
        }
        mc.__ns.__fpsr = 0x7000;
        mc.__ns.__fpcr = 0x8000;
        let input_mc = mc;
        for bits in [
            0,
            PSR_NZCV_MASK,
            PSR_SSBS_BIT,
            PSR_DIT_BIT,
            SAFE_USER_PSTATE,
        ] {
            mc = input_mc;
            set_guest_x18(0x1818);
            mc.__ss.__cpsr = (bits | !SAFE_USER_PSTATE).trunc();
            copy_signal_context(&mut regs, &mc);
            assert_eq!(regs.regs[..18], (0x1000..0x1012).collect::<Vec<_>>());
            assert_eq!(regs.regs[18], 0x1818);
            assert_eq!(regs.regs[19..29], (0x1013..0x101d).collect::<Vec<_>>());
            assert_eq!((regs.regs[29], regs.regs[30]), (0x2000, 0x3000));
            assert_eq!((regs.sp, regs.pc), (0x4000, 0x5000));
            assert_eq!(regs.pstate, bits);
            let saved_vector = get_guest_vector_state();
            assert_eq!(saved_vector.registers, mc.__ns.__v);
            assert_eq!((saved_vector.fpsr, saved_vector.fpcr), (0x7000, 0x8000));

            regs.regs = core::array::from_fn(|index| 0x9000 + index);
            regs.sp = 0xa000;
            regs.pc = 0xb000;
            regs.pstate = bits | !SAFE_USER_PSTATE;
            let restored_vector = GuestVectorState {
                registers: core::array::from_fn(|index| 0xc000 + index as u128),
                fpsr: 0xd000,
                fpcr: 0xe000,
            };
            set_guest_vector_state(&restored_vector);
            restore_signal_context(&regs, &mut mc);
            for (index, value) in mc.__ss.__x.iter().enumerate() {
                if index != 18 {
                    assert_eq!(*value, 0x9000 + index as u64);
                }
            }
            assert_eq!((mc.__ss.__fp, mc.__ss.__lr), (0x901d, 0x901e));
            assert_eq!((mc.__ss.__sp, mc.__ss.__pc), (0xa000, 0xb000));
            assert_eq!(u64::from(mc.__ss.__cpsr), bits);
            assert_eq!(mc.__ns.__v, restored_vector.registers);
            assert_eq!((mc.__ns.__fpsr, mc.__ns.__fpcr), (0xd000, 0xe000));
        }
    }

    #[test]
    fn initialization_preserves_tls_across_instances() {
        let first = MacosUserland::new().unwrap();
        let original = (
            get_guest_thread_pointer(),
            get_guest_x18(),
            read_tls(tls_offset::IN_GUEST),
        );
        let _restore = litebox::utils::defer(|| {
            set_guest_thread_pointer(original.0);
            set_guest_x18(original.1);
            write_tls(tls_offset::IN_GUEST, original.2);
        });
        set_guest_thread_pointer(0x1234);
        set_guest_x18(0x5678);
        write_tls(tls_offset::IN_GUEST, 1);
        let second = MacosUserland::new().unwrap();
        assert!(!core::ptr::eq(first, second));
        assert_eq!(
            (
                get_guest_thread_pointer(),
                get_guest_x18(),
                read_tls(tls_offset::IN_GUEST),
            ),
            (0x1234, 0x5678, 1)
        );
        initialize_thread_tls().unwrap();
        assert_eq!(
            (
                get_guest_thread_pointer(),
                get_guest_x18(),
                read_tls(tls_offset::IN_GUEST),
            ),
            (0x1234, 0x5678, 1)
        );
        std::thread::spawn(MacosUserland::new)
            .join()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn executable_protection_after_prot_none() {
        let p = MacosUserland::new().unwrap();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let range = ptr.as_usize()..ptr.as_usize() + PAGE_SIZE;
        let _unmap = litebox::utils::defer(|| {
            // SAFETY: the test owns the mapping and its code has returned before cleanup.
            unsafe {
                p.deallocate_pages(range.clone()).unwrap();
            }
        });
        // mov x0, #42; ret
        assert_eq!(
            ptr.write_slice_at_offset(0, &[0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]),
            Some(())
        );
        for permissions in [
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            MemoryRegionPermissions::EXEC,
        ] {
            // SAFETY: the test exclusively owns the mapping; its RX code is a C-ABI mov/ret stub.
            // The assembly declares the call's register clobbers.
            unsafe {
                p.update_permissions(range.clone(), MemoryRegionPermissions::empty())
                    .unwrap();
                p.update_permissions(range.clone(), permissions).unwrap();
                let value: usize;
                core::arch::asm!("blr {entry}", entry = in(reg) range.start,
                    lateout("x0") value, clobber_abi("C"));
                assert_eq!(value, 42);
            }
        }
    }

    #[test]
    fn executable_remap_preserves_code_without_wx() {
        let p = MacosUserland::new().unwrap();
        let source = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let source_range = source.as_usize()..source.as_usize() + PAGE_SIZE;
        assert_eq!(
            source.write_slice_at_offset(0, &[0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]),
            Some(())
        );
        // SAFETY: the test exclusively owns the idle source mapping.
        unsafe {
            p.update_permissions(
                source_range.clone(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            )
            .unwrap();
        }
        let target = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 2 * PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let target_range = target.as_usize()..target.as_usize() + 2 * PAGE_SIZE;
        // SAFETY: release the probe, then occupy its range as host memory so
        // remap_pages must choose a different destination without replacing it.
        unsafe { p.deallocate_pages(target_range.clone()).unwrap() };
        // SAFETY: target_range was just released and cannot overlap live Rust allocations.
        let host_mapping = unsafe {
            libc::mmap(
                target_range.start as *mut _,
                target_range.len(),
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(host_mapping as usize, target_range.start);
        let _host_unmap = litebox::utils::defer(|| {
            // SAFETY: this test owns the host mapping and the remap leaves it intact.
            assert_eq!(unsafe { libc::munmap(host_mapping, target_range.len()) }, 0);
        });
        // SAFETY: both guest ranges are idle, aligned, and non-overlapping.
        let remapped = unsafe {
            p.remap_pages(
                source_range,
                target_range.clone(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            )
            .unwrap()
        };
        assert_ne!(remapped.as_usize(), target_range.start);
        let remapped_range = remapped.as_usize()..remapped.as_usize() + target_range.len();
        let value: usize;
        // SAFETY: remap preserved the C-ABI mov/ret stub and installed RX permissions.
        unsafe {
            core::arch::asm!("blr {entry}", entry = in(reg) remapped.as_usize(),
                lateout("x0") value, clobber_abi("C"));
        }
        assert_eq!(value, 42);
        // SAFETY: the remapped code has returned and the test owns its actual range.
        unsafe { p.deallocate_pages(remapped_range).unwrap() };
    }

    #[test]
    fn permission_denials_are_not_reported_as_missing_pages() {
        unsafe extern "C" {
            fn mach_vm_protect(
                task: u32,
                address: u64,
                size: u64,
                set_maximum: i32,
                protection: i32,
            ) -> i32;
        }
        let p = MacosUserland::new().unwrap();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let range = ptr.as_usize()..ptr.as_usize() + PAGE_SIZE;
        let _unmap = litebox::utils::defer(|| {
            // SAFETY: the test owns this mapping and has no active accesses at cleanup.
            unsafe {
                p.deallocate_pages(range.clone()).unwrap();
            }
        });
        assert!(matches!(
            p.allocate_pages(
                range.clone(),
                RW | MemoryRegionPermissions::EXEC,
                false,
                true,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::PermissionDenied)
        ));
        assert!(matches!(
            // SAFETY: the test owns the idle mapping; denied permissions must leave it intact.
            unsafe { p.update_permissions(range.clone(), RW | MemoryRegionPermissions::EXEC) },
            Err(PermissionUpdateError::PermissionDenied)
        ));
        // SAFETY: this aligned range is exclusively test-owned; no live references require write access.
        unsafe {
            assert_eq!(
                mach_vm_protect(
                    mach_task_self(),
                    range.start as u64,
                    PAGE_SIZE as u64,
                    1,
                    libc::PROT_READ
                ),
                0
            );
            assert!(matches!(
                p.update_permissions(range.clone(), RW),
                Err(PermissionUpdateError::PermissionDenied)
            ));
        }
    }

    #[test]
    fn native_pages_preserve_neighbors_and_reject_collisions() {
        let p = MacosUserland::new().unwrap();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 2 * PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let base = ptr.as_usize();
        assert_eq!(base % PAGE_SIZE, 0);
        assert_eq!(ptr.read_at_offset(0), Some(0));
        assert_eq!(ptr.write_at_offset(PAGE_SIZE.cast_signed(), 0x5a), Some(()));
        assert!(matches!(
            p.allocate_pages(
                base..base + PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::NoReplace
            ),
            Err(AllocationError::AddressInUse)
        ));
        p.allocate_pages(
            base..base + PAGE_SIZE,
            RW,
            false,
            true,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(ptr.read_at_offset(PAGE_SIZE.cast_signed()), Some(0x5a));
        // SAFETY: no accesses to the first test-owned page overlap this permission change.
        unsafe {
            p.update_permissions(base..base + PAGE_SIZE, MemoryRegionPermissions::READ)
                .unwrap();
        }
        assert_eq!(ptr.write_at_offset(0, 1), None); // Fault-safe exception-table recovery
        assert_eq!(ptr.write_at_offset(PAGE_SIZE.cast_signed(), 0x6b), Some(()));
        // SAFETY: the first page is idle; subsequent probes use fallible raw accesses.
        unsafe {
            p.deallocate_pages(base..base + PAGE_SIZE).unwrap();
        }
        assert_eq!(ptr.read_at_offset(0), None);
        assert_eq!(ptr.read_at_offset(PAGE_SIZE.cast_signed()), Some(0x6b));
        // SAFETY: the remaining test-owned page is no longer accessed.
        unsafe {
            p.deallocate_pages(base + PAGE_SIZE..base + 2 * PAGE_SIZE)
                .unwrap();
        }
    }

    #[test]
    fn fixed_mappings_never_replace_host_memory() {
        let p = MacosUserland::new().unwrap();
        // SAFETY: request fresh anonymous memory with no fixed-address replacement.
        let host = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(host, libc::MAP_FAILED);
        // SAFETY: mmap succeeded with write permission; this test exclusively owns the byte.
        unsafe {
            host.cast::<u8>().write(0x42);
        }
        for behavior in [
            FixedAddressBehavior::NoReplace,
            FixedAddressBehavior::Replace,
        ] {
            assert!(matches!(
                p.allocate_pages(
                    host as usize..host as usize + PAGE_SIZE,
                    RW,
                    false,
                    true,
                    behavior
                ),
                Err(AllocationError::AddressInUseByPlatform)
            ));
        }
        // SAFETY: the range is idle; the platform must leave this unowned mapping intact.
        unsafe {
            p.deallocate_pages(host as usize..host as usize + PAGE_SIZE)
                .unwrap();
        }
        // SAFETY: rejected replacements and unowned deallocation leave the initialized byte mapped.
        assert_eq!(unsafe { host.cast::<u8>().read() }, 0x42);
        // SAFETY: this releases the test's still-live mapping after its last access.
        unsafe {
            libc::munmap(host, PAGE_SIZE);
        }
    }
}
