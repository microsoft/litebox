// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Apple Silicon userland platform with native 16 KiB pages.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{GuestVectorState, PtRegs};
use std::cell::{Cell, RefCell};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

use litebox_common_linux::gate_recovery::{
    Aarch64GateSignalResult, GateInterruption, GateRuntimeState, canonicalize,
};
use litebox_syscall_rewriter::aarch64::SVC_FRAME_BYTES;
use litebox_syscall_rewriter::aarch64::{
    is_patchable_guest_tpidr_offset, is_patchable_guest_x18_offset,
};

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError,
};
use litebox::platform::{PageManagementProvider, RawConstPointer as _};
use std::ops::Range;

use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, Provider, RawPointerProvider,
    SignalProvider, SystemInfoProvider, ThreadLocalStorageProvider, ThreadProvider, TimerProvider,
    common_providers, trivial_providers,
};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutexProvider, UnblockedOrTimedOut, WaitWakerProvider,
};
use litebox_platform::time::TimeProvider;
use std::time::Duration;
use zerocopy::{FromBytes, IntoBytes};

pub use litebox::mm::linux::PAGE_SIZE;
/// Darwin's Mach-O __PAGEZERO reserves the first 4 GiB.
pub const TASK_ADDR_MIN: usize = 0x1_0000_0000;
/// Exclusive upper bound for guest mappings.
pub const TASK_ADDR_MAX: usize = 0x0000_ffff_ffff_c000;

#[derive(Debug)]
pub struct MacosUserland {
    pages: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    keys: Keys,
}

static PLATFORM: OnceLock<std::io::Result<MacosUserland>> = OnceLock::new();

impl MacosUserland {
    /// Initialize the platform.
    pub fn new() -> std::io::Result<&'static Self> {
        PLATFORM
            .get_or_init(|| {
                // SAFETY: this scalar query has no pointer arguments.
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                if usize::try_from(page_size).ok() != Some(PAGE_SIZE) {
                    return Err(std::io::Error::other("unexpected macOS page size"));
                }
                install_handlers()?;
                let keys = create_tls_keys().map_err(std::io::Error::from_raw_os_error)?;
                initialize_thread_tls(&keys)?;
                Ok(Self {
                    pages: std::sync::Mutex::new(std::collections::BTreeSet::new()),
                    keys,
                })
            })
            .as_ref()
            .map_err(|error| {
                error.raw_os_error().map_or_else(
                    || std::io::Error::new(error.kind(), error.to_string()),
                    std::io::Error::from_raw_os_error,
                )
            })
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

thread_local! {
    static SHIM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

// SAFETY: the pointer is isolated by host TLS and initialized to null.
unsafe impl ThreadLocalStorageProvider for MacosUserland {
    fn get_thread_local_storage() -> *mut () {
        SHIM_TLS.get()
    }
    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        SHIM_TLS.replace(value)
    }
}

impl ArchSpecificProvider for MacosUserland {
    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        match reg {
            ArchSpecificRegister::TpidrEl0 => Ok(guest_tp()),
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
                set_guest_tp(value);
                Ok(())
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
}

impl SystemInfoProvider for MacosUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_entry_point()
    }
    fn guest_thread_pointer_offset(&self) -> Option<usize> {
        Some(guest_tp_offset())
    }
    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}
impl WaitWakerProvider for MacosUserland {
    fn update_waker(&self, waker: Option<core::task::Waker>) {
        update_waker(waker);
    }
}

impl litebox::platform::GuestVectorStateProvider for MacosUserland {
    type GuestVectorState = litebox_common_linux::GuestVectorState;
    fn get_guest_vector_state(&self) -> Self::GuestVectorState {
        get_guest_vector_state()
    }
    fn set_guest_vector_state(&self, state: &Self::GuestVectorState) {
        set_guest_vector_state(state);
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
impl litebox_platform::time::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }
    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}
pub struct SystemTime(std::time::SystemTime);
impl litebox_platform::time::SystemTime for SystemTime {
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
impl litebox_platform::sync::RawMutex for RawMutex {
    const INIT: Self = Self {
        value: AtomicU32::new(0),
        gate: std::sync::Mutex::new(()),
        ready: std::sync::Condvar::new(),
    };
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.value
    }
    fn wake_many(&self, n: usize) -> usize {
        let _guard = self.gate.lock().unwrap();
        if n >= i32::MAX as usize {
            self.ready.notify_all();
        } else {
            for _ in 0..n {
                self.ready.notify_one();
            }
        }
        0 // The host cannot report the number actually woken.
    }
    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        let guard = self.gate.lock().unwrap();
        if self.value.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        drop(self.ready.wait(guard).unwrap());
        Ok(())
    }
    fn block_or_timeout(
        &self,
        val: u32,
        time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let guard = self.gate.lock().unwrap();
        if self.value.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        let (_guard, result) = self.ready.wait_timeout(guard, time).unwrap();
        Ok(if result.timed_out() {
            UnblockedOrTimedOut::TimedOut
        } else {
            UnblockedOrTimedOut::Unblocked
        })
    }
}

impl ThreadProvider for MacosUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;
    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init: Box<dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>>,
    ) -> Result<(), Self::ThreadSpawnError> {
        let mut ctx = ctx.clone();
        let vector = get_guest_vector_state();
        std::thread::Builder::new().spawn(move || {
            let shim = init.init();
            set_guest_vector_state(&vector);
            // SAFETY: the caller supplies a valid child context; shim and ctx live through the run.
            unsafe { run_thread_ref(&*shim, &mut ctx) };
        })?;
        Ok(())
    }
    fn current_thread(&self) -> Self::ThreadHandle {
        current_thread()
    }
    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
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
        Err(litebox::mm::linux::PageFaultError::AccessError(
            "Darwin handles demand paging",
        ))
    }
    fn access_error(_: u64, _: litebox::mm::linux::VmFlags) -> bool {
        true
    }
}

unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
}
fn aligned(range: &Range<usize>) -> bool {
    range.start < range.end
        && range.start.is_multiple_of(PAGE_SIZE)
        && range.end.is_multiple_of(PAGE_SIZE)
}
fn protection(p: MemoryRegionPermissions) -> i32 {
    (i32::from(p.contains(MemoryRegionPermissions::READ)) * libc::PROT_READ)
        | (i32::from(p.contains(MemoryRegionPermissions::WRITE)) * libc::PROT_WRITE)
        | (i32::from(p.contains(MemoryRegionPermissions::EXEC)) * libc::PROT_EXEC)
}
fn wx(p: MemoryRegionPermissions) -> bool {
    p.contains(MemoryRegionPermissions::WRITE | MemoryRegionPermissions::EXEC)
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
        _: bool,
        _: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        if !aligned(&range) {
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
            for hint in [range.start, 0] {
                // SAFETY: anonymous, page-aligned allocation; without MAP_FIXED the hint cannot replace memory.
                let mapped = unsafe {
                    libc::mmap(
                        hint as *mut _,
                        range.len(),
                        protection(permissions),
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED {
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
            return Err(AllocationError::OutOfMemory);
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
                return Err(if result == 6 {
                    AllocationError::OutOfMemory
                } else {
                    AllocationError::AddressInUseByPlatform
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
                protection(permissions),
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            for page in reserved {
                // SAFETY: release only this call's unpublished reservations.
                unsafe {
                    libc::munmap(page as *mut _, PAGE_SIZE);
                }
            }
            return Err(AllocationError::OutOfMemory);
        }
        pages.extend(range.clone().step_by(PAGE_SIZE));
        Ok(Self::RawMutPointer::from_usize(range.start))
    }
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
        if !aligned(&range) {
            return Err(DeallocationError::Unaligned);
        }
        let mut pages = self.pages.lock().unwrap();
        // Leave host-owned pages in holes untouched.
        for page in range.step_by(PAGE_SIZE) {
            if pages.contains(&page) {
                // SAFETY: the registry owns this page and the caller guarantees it is no longer in use.
                if unsafe { libc::munmap(page as *mut _, PAGE_SIZE) } != 0 {
                    return Err(DeallocationError::AlreadyUnallocated);
                }
                pages.remove(&page);
            }
        }
        Ok(())
    }
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        if !aligned(&range) {
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
            permissions | MemoryRegionPermissions::READ
        } else {
            permissions
        };
        // SAFETY: the locked registry covers the aligned range; the caller permits reprotection.
        if unsafe {
            libc::mprotect(
                range.start as *mut _,
                range.len(),
                protection(cache_permissions),
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
                    libc::mprotect(range.start as *mut _, range.len(), protection(permissions))
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

// Gates address consecutive guest TP and x18 slots relative to TPIDRRO_EL0.

#[derive(Debug)]
struct Keys {
    tp: libc::pthread_key_t,
    x18: libc::pthread_key_t,
}

impl Drop for Keys {
    fn drop(&mut self) {
        // SAFETY: Keys owns both successfully allocated keys and deletes them once.
        unsafe {
            libc::pthread_key_delete(self.tp);
            libc::pthread_key_delete(self.x18);
        }
    }
}

fn keys() -> &'static Keys {
    let Some(Ok(platform)) = PLATFORM.get() else {
        fatal_signal(b"Darwin TLS is not initialized", 0);
    };
    &platform.keys
}

fn create_tls_keys() -> Result<Keys, i32> {
    let mut tp = 0;
    let mut x18 = 0;
    // SAFETY: tp is a writable output slot; no destructor will dereference stored guest values.
    let error = unsafe { libc::pthread_key_create(&raw mut tp, None) };
    if error != 0 {
        return Err(error);
    }
    // SAFETY: x18 is a writable output slot, also with no destructor.
    let error = unsafe { libc::pthread_key_create(&raw mut x18, None) };
    if error != 0 {
        // SAFETY: tp was allocated above and has not been published.
        unsafe { libc::pthread_key_delete(tp) };
        return Err(error);
    }
    if x18 != tp + 1
        || !u16::try_from(tp * 8).is_ok_and(is_patchable_guest_tpidr_offset)
        || !u16::try_from(x18 * 8).is_ok_and(is_patchable_guest_x18_offset)
    {
        // SAFETY: both keys were allocated above and rejected before publication.
        unsafe {
            libc::pthread_key_delete(tp);
            libc::pthread_key_delete(x18);
        }
        return Err(libc::ENOTSUP);
    }
    Ok(Keys { tp, x18 })
}

fn initialize_thread_tls(keys: &Keys) -> std::io::Result<()> {
    // Darwin's TSD ABI addresses slots as TPIDRRO_EL0 + key * sizeof(void*).
    for (key, sentinel) in [(keys.tp, 0x1234usize), (keys.x18, 0x5678usize)] {
        // SAFETY: Keys keeps key allocated; its opaque value is saved without dereferencing it.
        let previous = unsafe { libc::pthread_getspecific(key) };
        // SAFETY: pthread stores the sentinel as opaque data; the key has no destructor.
        let error = unsafe { libc::pthread_setspecific(key, sentinel as *const libc::c_void) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
        let key_offset: usize = (key * 8).trunc();
        let address = anchor() + key_offset;
        let mut value = [0u8; 8];
        // SAFETY: value is writable; the candidate is in pthread-owned TSD under the ABI above.
        // Installed exception handlers recover inaccessible reads; the value check rejects layout mismatches.
        let valid = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                value.as_mut_ptr(),
                address as *const u8,
                8,
            )
            .is_ok()
        } && usize::from_ne_bytes(value) == sentinel;
        // SAFETY: restore the opaque value from this still-allocated key.
        let error = unsafe { libc::pthread_setspecific(key, previous) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
        if !valid {
            return Err(std::io::Error::other(
                "unsupported Darwin pthread TSD layout",
            ));
        }
    }
    Ok(())
}

fn anchor() -> usize {
    let value;
    // SAFETY: TPIDRRO_EL0 is readable at EL0 on Darwin; this changes no memory or flags.
    unsafe {
        core::arch::asm!("mrs {value}, tpidrro_el0", value = out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn guest_tp_offset() -> usize {
    (keys().tp * 8).trunc()
}
fn guest_tp_address() -> usize {
    anchor() + guest_tp_offset()
}
fn guest_tp() -> usize {
    // SAFETY: the singleton keeps this key live; the value is treated as an integer, not dereferenced.
    unsafe { libc::pthread_getspecific(keys().tp) as usize }
}
fn guest_x18() -> usize {
    // SAFETY: the singleton keeps this key live; the value is an opaque guest register.
    unsafe { libc::pthread_getspecific(keys().x18) as usize }
}
fn set_guest_tp(value: usize) {
    // SAFETY: the key is live and has no destructor; pthread stores value without dereferencing it.
    if unsafe { libc::pthread_setspecific(keys().tp, value as *const libc::c_void) } != 0 {
        fatal_signal(b"failed to set guest TP", 0);
    }
}
fn set_guest_x18(value: usize) {
    // SAFETY: the key is live and has no destructor; pthread stores value without dereferencing it.
    if unsafe { libc::pthread_setspecific(keys().x18, value as *const libc::c_void) } != 0 {
        fatal_signal(b"failed to set guest x18", 0);
    }
}

const INTERRUPT: i32 = libc::SIGUSR1;
const SIGNALS: [i32; 5] = [
    libc::SIGTRAP,
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    INTERRUPT,
];
static PREVIOUS: OnceLock<[libc::sigaction; 5]> = OnceLock::new();

struct Context<'a> {
    shim: &'a dyn EnterShim<ExecutionContext = PtRegs>,
    regs: &'a mut PtRegs,
    host_sp: usize,
    thread: ThreadHandle,
}
thread_local! {
    static ACTIVE: Cell<*mut Context<'static>> = const { Cell::new(core::ptr::null_mut()) };
    static IN_SHIM: Cell<bool> = const { Cell::new(true) };
    static VECTOR_STATE: RefCell<GuestVectorState> = const { RefCell::new(GuestVectorState {
        registers: [0; 32], fpsr: 0, fpcr: 0,
    }) };
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
    fn interrupt(&self) {
        self.0.interrupted.store(true, Ordering::Release);
        {
            let identity = self.0.identity.lock().unwrap();
            if let Some(identity) = *identity {
                // SAFETY: this lock prevents unregistering/reusing the saved pthread_t during delivery.
                unsafe { libc::pthread_kill(identity as libc::pthread_t, INTERRUPT) };
            }
        }
        let waker = self.0.waker.lock().unwrap().clone();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
fn current_thread() -> ThreadHandle {
    let context = ACTIVE.get();
    assert!(!context.is_null(), "not running a guest thread");
    // SAFETY: ACTIVE refers to this thread's live stack-backed Context until run_thread_ref returns.
    unsafe { (*context).thread.clone() }
}
fn update_waker(waker: Option<core::task::Waker>) {
    if !ACTIVE.get().is_null() {
        *current_thread().0.waker.lock().unwrap() = waker;
    }
}
pub(crate) fn get_guest_vector_state() -> GuestVectorState {
    VECTOR_STATE.with_borrow(Clone::clone)
}
pub(crate) fn set_guest_vector_state(state: &GuestVectorState) {
    VECTOR_STATE.with_borrow_mut(|saved| saved.clone_from(state));
}
fn syscall_entry_point() -> usize {
    syscall_gate as *const () as usize
}

// SVC gate callback: Darwin captures the full register state at this PC.
#[unsafe(naked)]
unsafe extern "C" fn syscall_gate() {
    core::arch::naked_asm!("brk #0");
}
#[unsafe(naked)]
unsafe extern "C" fn start_gate() {
    core::arch::naked_asm!("brk #0");
}

pub(crate) fn install_handlers() -> std::io::Result<()> {
    static INSTALLED: Mutex<bool> = Mutex::new(false);
    let mut installed = INSTALLED.lock().unwrap();
    if *installed {
        return Ok(());
    }
    // SAFETY: Darwin sigaction contains integer fields; zero is a valid representation.
    let mut previous = unsafe { std::mem::zeroed::<[libc::sigaction; 5]>() };
    for (signal, previous) in SIGNALS.into_iter().zip(&mut previous) {
        // SAFETY: previous is writable and null requests a query without installing a handler.
        if unsafe { libc::sigaction(signal, core::ptr::null(), previous) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let previous = PREVIOUS.get_or_init(|| previous);
    // SAFETY: zero is valid for every field; the handler, flags and mask are filled below.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = signal_handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
    // SAFETY: action.sa_mask is writable storage for these sigset operations.
    unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        // Allow nested memory faults for fallible reads, but not shim re-entry.
        libc::sigaddset(&raw mut action.sa_mask, INTERRUPT);
        libc::sigaddset(&raw mut action.sa_mask, libc::SIGTRAP);
    }
    for (index, signal) in SIGNALS.into_iter().enumerate() {
        // SAFETY: action is initialized and SA_SIGINFO matches the static handler's C ABI.
        if unsafe { libc::sigaction(signal, &raw const action, core::ptr::null_mut()) } != 0 {
            let error = std::io::Error::last_os_error();
            for previous_index in 0..index {
                // SAFETY: these immutable actions were returned by sigaction for the same signals.
                unsafe {
                    libc::sigaction(
                        SIGNALS[previous_index],
                        &raw const previous[previous_index],
                        core::ptr::null_mut(),
                    )
                };
            }
            return Err(error);
        }
    }
    *installed = true;
    Ok(())
}

/// Run a guest thread.
///
/// # Safety
/// The shim must supply valid mappings and macOS-targeted rewritten guest code.
pub unsafe fn run_thread<T: EnterShim<ExecutionContext = PtRegs>>(shim: T, regs: &mut PtRegs) {
    // SAFETY: the caller supplies valid guest mappings; shim and regs remain live for this call.
    unsafe { run_thread_ref(&shim, regs) };
}

unsafe fn run_thread_ref(shim: &dyn EnterShim<ExecutionContext = PtRegs>, regs: &mut PtRegs) {
    assert!(
        ACTIVE.get().is_null(),
        "nested guest entry is not supported"
    );
    initialize_thread_tls(keys()).expect("unsupported Darwin TLS layout");
    VECTOR_STATE.with(|_| {});
    set_guest_tp(0);
    set_guest_x18(0);
    let thread = ThreadHandle(Arc::new(ThreadState {
        // SAFETY: pthread_self has no preconditions; the identity is cleared before thread exit.
        identity: Mutex::new(Some(unsafe { libc::pthread_self() } as usize)),
        interrupted: AtomicBool::new(false),
        waker: Mutex::new(None),
    }));
    let mut context = Context {
        shim,
        regs,
        host_sp: 0,
        thread,
    };
    ACTIVE.set((&raw mut context).cast());
    let _registration = litebox::utils::defer(|| {
        *context.thread.0.identity.lock().unwrap() = None;
        ACTIVE.set(core::ptr::null_mut());
        IN_SHIM.set(true);
    });
    if shim.init(context.regs) == ContinueOperation::Terminate {
        return;
    }
    let mut stack = vec![0u8; 2 * 1024 * 1024];
    let alternate = libc::stack_t {
        ss_sp: stack.as_mut_ptr().cast(),
        ss_size: stack.len(),
        ss_flags: 0,
    };
    // SAFETY: stack_t consists of a nullable pointer and integers, all valid when zeroed.
    let mut previous = unsafe { std::mem::zeroed::<libc::stack_t>() };
    assert_eq!(
        // SAFETY: stack owns stable writable storage until the previous altstack is restored.
        unsafe { libc::sigaltstack(&raw const alternate, &raw mut previous) },
        0
    );
    let _stack_guard = litebox::utils::defer(|| {
        assert_eq!(
            // SAFETY: previous came from sigaltstack; handlers have returned and stack is still alive.
            unsafe { libc::sigaltstack(&raw const previous, core::ptr::null_mut()) },
            0
        );
    });
    // Spawned pthreads inherit the syscall handler's blocked signal mask.
    // SAFETY: Darwin sigset_t is an integer bitmask; zero is valid.
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: the zeroed bitmask is valid writable output storage.
    let mut old_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: both masks are live stack storage; these operations affect only this thread.
    unsafe {
        libc::sigemptyset(&raw mut signals);
        for signal in SIGNALS {
            libc::sigaddset(&raw mut signals, signal);
        }
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const signals, &raw mut old_mask),
            0
        );
    }
    let _mask_guard = litebox::utils::defer(|| {
        assert_eq!(
            // SAFETY: old_mask is the mask returned for this thread and remains live.
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const old_mask,
                    core::ptr::null_mut(),
                )
            },
            0
        );
    });
    // SAFETY: ACTIVE, TLS, handlers and altstack are initialized; host_sp is writable.
    // IN_SHIM stays set until start_gate installs the caller-provided guest context.
    unsafe { enter_guest(&raw mut context.host_sp) };
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
fn capture(regs: &mut PtRegs, mc: &libc::__darwin_mcontext64) {
    for (dst, src) in regs.regs[..29].iter_mut().zip(&mc.__ss.__x) {
        *dst = src.trunc();
    }
    regs.regs[18] = guest_x18();
    regs.regs[29] = mc.__ss.__fp.trunc();
    regs.regs[30] = mc.__ss.__lr.trunc();
    regs.sp = mc.__ss.__sp.trunc();
    regs.pc = mc.__ss.__pc.trunc();
    regs.pstate = u64::from(mc.__ss.__cpsr) & litebox_common_linux::arch::SAFE_USER_PSTATE;
    regs.orig_x0 = regs.regs[0];
    regs.syscallno = litebox_common_linux::arch::NO_SYSCALL;
    VECTOR_STATE.with(|cell| {
        let Ok(mut state) = cell.try_borrow_mut() else {
            fatal_signal(b"guest vector state is already borrowed", regs.pc);
        };
        state.registers = mc.__ns.__v;
        state.fpsr = mc.__ns.__fpsr;
        state.fpcr = mc.__ns.__fpcr;
    });
}
fn restore(regs: &PtRegs, mc: &mut libc::__darwin_mcontext64) {
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
    VECTOR_STATE.with(|cell| {
        let Ok(state) = cell.try_borrow() else {
            fatal_signal(b"guest vector state is already borrowed", regs.pc);
        };
        mc.__ns.__v = state.registers;
        mc.__ns.__fpsr = state.fpsr;
        mc.__ns.__fpcr = state.fpcr;
    });
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

unsafe extern "C" fn signal_handler(
    signal: i32,
    info: *mut libc::siginfo_t,
    raw: *mut libc::c_void,
) {
    // SAFETY: SA_SIGINFO supplies a live, aligned ucontext for this invocation.
    let uc = unsafe { &mut *raw.cast::<libc::ucontext_t>() };
    // SAFETY: Darwin supplies a live machine context through uc_mcontext; nested signals get separate frames.
    let mc = unsafe { &mut *uc.uc_mcontext };
    let pc: usize = mc.__ss.__pc.trunc();
    if matches!(signal, libc::SIGSEGV | libc::SIGBUS)
        && let Some(fixup) = litebox::mm::exception_table::search_exception_tables(pc)
    {
        mc.__ss.__pc = fixup as u64;
        return;
    }
    let ptr = ACTIVE.get();
    let starting = pc == start_gate as *const () as usize && signal == libc::SIGTRAP;
    if ptr.is_null() || (IN_SHIM.get() && !starting) {
        if signal != INTERRUPT {
            // SAFETY: forward the kernel-provided arguments while their signal frame is live.
            unsafe { forward_signal(signal, info, raw) };
        }
        return;
    }
    IN_SHIM.set(true);
    // SAFETY: ACTIVE keeps this stack-backed Context live; IN_SHIM prevents nested shim access.
    let context = unsafe { &mut *ptr };
    context.thread.0.interrupted.store(false, Ordering::Release);
    let regs = &mut *context.regs;
    let mut operation = if starting {
        context.shim.interrupt(regs)
    } else {
        ContinueOperation::Resume
    };
    if !starting {
        capture(regs, mc);
        if pc == syscall_entry_point() {
            // Frame: [x16, return PC, outbound stub, padding]. Sigreturn skips the stub.
            let mut frame = [[0u8; 8]; 3];
            if read_guest(regs.sp, frame.as_flattened_mut()) {
                let frame = frame.map(usize::from_ne_bytes);
                regs.regs[16] = frame[0];
                regs.pc = frame[1];
                regs.sp = regs.sp.wrapping_add(usize::from(SVC_FRAME_BYTES));
                let syscallno: u32 = regs.regs[8].trunc();
                regs.syscallno = syscallno.cast_signed();
                regs.orig_x0 = regs.regs[0];
                regs.regs[0] = (-38isize).cast_unsigned(); // Linux ENOSYS on entry
                operation = context.shim.syscall(regs);
            } else {
                fatal_signal(b"unreadable SVC gate frame", pc);
            }
        } else {
            let kind = match signal {
                INTERRUPT => GateInterruption::Asynchronous,
                libc::SIGTRAP => GateInterruption::Breakpoint,
                _ => GateInterruption::Synchronous,
            };
            let recovery = canonicalize(
                regs,
                GateRuntimeState {
                    guest_thread_pointer_addr: guest_tp_address(),
                    // Darwin resumes via sigreturn, never an outbound stub.
                    expected_outbound_stub: 0,
                    expected_outbound_pc: 0,
                },
                kind,
                litebox_syscall_rewriter::TargetHost::MacOs,
                true,
                read_guest,
            );
            let mut consumed = false;
            match recovery {
                Aarch64GateSignalResult::NotGate => {}
                Aarch64GateSignalResult::Canonicalized(canonical) => *regs = canonical,
                Aarch64GateSignalResult::ResumeGuest(canonical) => {
                    *regs = canonical;
                    consumed = true;
                }
                Aarch64GateSignalResult::InvalidRuntimeState => {
                    fatal_signal(b"invalid AArch64 gate runtime state", pc);
                }
                Aarch64GateSignalResult::PreserveSavedContext => {
                    fatal_signal(b"unexpected Darwin outbound-stub recovery", pc);
                }
            }
            if !consumed {
                operation = if signal == INTERRUPT {
                    context.shim.interrupt(regs)
                } else {
                    context.shim.exception(
                        regs,
                        &ExceptionInfo {
                            exception: Exception((mc.__es.__esr >> 26) as u8),
                            fault_address: mc.__es.__far.trunc(),
                            esr: u64::from(mc.__es.__esr),
                            kernel_mode: false,
                        },
                    )
                };
            }
        }
    }
    if operation == ContinueOperation::Resume
        && context.thread.0.interrupted.swap(false, Ordering::AcqRel)
    {
        operation = context.shim.interrupt(regs);
    }
    if operation == ContinueOperation::Terminate {
        mc.__ss.__pc = leave_guest as *const () as u64;
        mc.__ss.__sp = context.host_sp as u64;
    } else {
        restore(regs, mc);
        IN_SHIM.set(false);
    }
}

unsafe fn forward_signal(signal: i32, info: *mut libc::siginfo_t, raw: *mut libc::c_void) {
    let Some(previous) = SIGNALS
        .iter()
        .position(|s| *s == signal)
        .and_then(|index| PREVIOUS.get()?.get(index))
    else {
        fatal_signal(b"missing host signal disposition", 0);
    };
    match previous.sa_sigaction {
        // SAFETY: signal was installed from SIGNALS; these scalar APIs restore its default disposition.
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

#[unsafe(naked)]
unsafe extern "C" fn enter_guest(_: *mut usize) {
    // SAFETY: caller initialized ACTIVE and passes writable host_sp storage.
    // This frame saves the C ABI's callee-saved state for leave_guest.
    core::arch::naked_asm!(
        "stp x29, x30, [sp, #-160]!",
        "stp x19, x20, [sp, #16]", "stp x21, x22, [sp, #32]",
        "stp x23, x24, [sp, #48]", "stp x25, x26, [sp, #64]", "stp x27, x28, [sp, #80]",
        "stp d8, d9, [sp, #96]", "stp d10, d11, [sp, #112]", "stp d12, d13, [sp, #128]", "stp d14, d15, [sp, #144]",
        "mov x1, sp", "str x1, [x0]", "bl {start}", "b {leave}",
        start = sym start_gate, leave = sym leave_guest,
    );
}
#[unsafe(naked)]
unsafe extern "C" fn leave_guest() {
    // SAFETY: signal_handler restores SP to the live frame saved by enter_guest.
    core::arch::naked_asm!(
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
        "ret",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::{RawMutPointer as _, RawPointerProvider};
    use litebox_common_linux::errno::Errno;
    type Ptr = <MacosUserland as RawPointerProvider>::RawMutPointer<u8>;
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
        for bits in [
            0,
            PSR_NZCV_MASK,
            PSR_SSBS_BIT,
            PSR_DIT_BIT,
            SAFE_USER_PSTATE,
        ] {
            mc.__ss.__cpsr = (bits | !SAFE_USER_PSTATE).trunc();
            capture(&mut regs, &mc);
            assert_eq!(regs.pstate, bits);

            regs.pstate = bits | !SAFE_USER_PSTATE;
            restore(&regs, &mut mc);
            assert_eq!(u64::from(mc.__ss.__cpsr), bits);

            capture(&mut regs, &mc);
            assert_eq!(regs.pstate, bits);
        }
    }

    #[test]
    fn initialization_preserves_tls_and_shares_page_ownership() {
        let first = MacosUserland::new().unwrap();
        let original = (guest_tp(), guest_x18());
        let _restore = litebox::utils::defer(|| {
            set_guest_tp(original.0);
            set_guest_x18(original.1);
        });
        set_guest_tp(0x1234);
        set_guest_x18(0x5678);
        let second = MacosUserland::new().unwrap();
        assert!(core::ptr::eq(first, second));
        assert_eq!((guest_tp(), guest_x18()), (0x1234, 0x5678));
        initialize_thread_tls(keys()).unwrap();
        assert_eq!((guest_tp(), guest_x18()), (0x1234, 0x5678));
        let other = std::thread::spawn(|| MacosUserland::new().unwrap())
            .join()
            .unwrap();
        assert!(core::ptr::eq(first, other));
        let ptr = first
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let range = ptr.as_usize()..ptr.as_usize() + PAGE_SIZE;
        assert!(matches!(
            second.allocate_pages(
                range.clone(),
                RW,
                false,
                true,
                FixedAddressBehavior::NoReplace
            ),
            Err(AllocationError::AddressInUse)
        ));
        // SAFETY: the test owns this unused mapping; both handles refer to the same platform.
        unsafe {
            second.deallocate_pages(range).unwrap();
        }
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
        assert_eq!(
            Errno::from(AllocationError::PermissionDenied),
            Errno::EACCES
        );
        assert_eq!(
            Errno::from(PermissionUpdateError::PermissionDenied),
            Errno::EACCES
        );
        assert!(matches!(
            permission_update_error(libc::ENOMEM),
            PermissionUpdateError::OutOfMemory
        ));
        assert!(matches!(
            permission_update_error(libc::EINVAL),
            PermissionUpdateError::PlatformFailure
        ));
        assert_eq!(
            Errno::from(PermissionUpdateError::PlatformFailure),
            Errno::EIO
        );
    }

    #[test]
    fn fatal_signal_writes_diagnostic() {
        const CHILD: &str = "LITEBOX_TEST_FATAL_SIGNAL";
        if std::env::var_os(CHILD).is_some() {
            fatal_signal(b"invalid AArch64 gate runtime state", 0x1234);
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::fatal_signal_writes_diagnostic",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(128 + libc::SIGABRT));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid AArch64 gate runtime state pc=0x0000000000001234"));
        assert!(!stderr.contains("panicked"));
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
        assert_eq!(ptr.write_at_offset(0, 1), None); // Mach-O exception table recovery
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

    #[test]
    fn rejects_low_unaligned_and_wx_requests() {
        let p = MacosUserland::new().unwrap();
        assert!(matches!(
            p.allocate_pages(0..PAGE_SIZE, RW, false, true, FixedAddressBehavior::Replace),
            Err(AllocationError::BelowMinAddress)
        ));
        assert!(matches!(
            p.allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 4096,
                RW,
                false,
                true,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::Unaligned)
        ));
        assert!(matches!(
            p.allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + PAGE_SIZE,
                RW | MemoryRegionPermissions::EXEC,
                false,
                true,
                FixedAddressBehavior::Hint
            ),
            Err(AllocationError::PermissionDenied)
        ));
        assert_eq!(Ptr::from_usize(1).read_at_offset(0), None);
    }
}
