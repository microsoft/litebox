// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 macOS userland platform.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::cell::Cell;
use std::ops::Range;
use std::sync::{
    Arc, Condvar, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};
use std::time::Duration;

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError, RemapError,
};
use litebox::platform::{ArchSpecificError, ArchSpecificRegister, RawConstPointer as _};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::gate_recovery::{
    Aarch64GateSignalResult, GateInterruption, GateRuntimeState, canonicalize,
};
use litebox_common_linux::{GuestVectorState, PtRegs};
use litebox_common_macos::{KernReturn, MachClock, syscall::MachTimebaseInfo};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use litebox_syscall_rewriter::aarch64::{
    GUEST_X18_OFFSET_FROM_GUEST_TP, IN_GUEST_OFFSET_FROM_GUEST_TP, SVC_FRAME_BYTES,
    SVC_FRAME_OFF_RETADDR, SVC_FRAME_OFF_STUB, SVC_FRAME_OFF_X16, is_patchable_guest_tpidr_offset,
};
use zerocopy::{FromBytes, IntoBytes};

/// Process-wide guest syscall convention. The discriminants are the gate
/// frame sizes used by the register-save assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum GuestAbi {
    Linux = SVC_FRAME_BYTES as usize,
    Darwin = litebox_syscall_rewriter::aarch64::DARWIN_SVC_FRAME_BYTES as usize,
}

struct GuestConfiguration {
    abi: GuestAbi,
    darwin_private_thread_state: AtomicBool,
    rewritten_host_sigreturn: AtomicBool,
}

static GUEST_CONFIGURATION: OnceLock<GuestConfiguration> = OnceLock::new();

/// Set the process-wide guest ABI before running or spawning guest threads.
///
/// # Panics
/// Panics if a different ABI has already been configured.
pub fn set_guest_abi(abi: GuestAbi) {
    assert_eq!(
        GUEST_CONFIGURATION
            .get_or_init(|| GuestConfiguration {
                abi,
                darwin_private_thread_state: AtomicBool::new(false),
                rewritten_host_sigreturn: AtomicBool::new(false),
            })
            .abi,
        abi,
        "guest ABI is already configured"
    );
}

/// Give a Darwin guest private, natively initialized libSystem thread state.
///
/// Dynamic guests execute code from the dual-use host shared cache. A parked
/// donor pthread supplies a valid pthread/TSD object that guest TPIDRRO gates
/// can expose without allowing guest libc to mutate the runner thread's state.
///
/// # Panics
///
/// Panics if the guest ABI has not been configured yet.
pub fn set_darwin_private_thread_state(enabled: bool) {
    GUEST_CONFIGURATION
        .get()
        .expect("guest ABI must be configured before selecting Darwin thread state")
        .darwin_private_thread_state
        .store(enabled, Ordering::Release);
}

fn guest_configuration() -> &'static GuestConfiguration {
    GUEST_CONFIGURATION
        .get()
        .expect("guest ABI must be configured before guest execution")
}

fn guest_abi() -> GuestAbi {
    guest_configuration().abi
}

fn darwin_private_thread_state_enabled() -> bool {
    guest_configuration()
        .darwin_private_thread_state
        .load(Ordering::Acquire)
}

fn rewritten_host_sigreturn_enabled() -> bool {
    GUEST_CONFIGURATION
        .get()
        .is_some_and(|config| config.rewritten_host_sigreturn.load(Ordering::Acquire))
}

/// Native page size on AArch64 macOS.
pub const HOST_PAGE_SIZE: usize = 16384;

/// Native 16 KiB page management.
pub type MacosUserland = MacosUserlandWithPageSize<HOST_PAGE_SIZE>;

/// Opt-in 4 KiB guest pages with best-effort subpage permissions.
#[cfg(feature = "subpage_compat")]
pub type MacosUserland4K = MacosUserlandWithPageSize<4096>;
mod subpage;
/// The macOS host's Mach-O `__PAGEZERO` reserves the first 4 GiB.
pub const TASK_ADDR_MIN: usize = 0x1_0000_0000;
/// Exclusive upper bound for guest mappings (`MACH_VM_MAX_ADDRESS` on AArch64 macOS).
pub const TASK_ADDR_MAX: usize = 0x7FFF_FE00_0000;

/// Shared platform implementation. Use [`MacosUserland`] for native pages or
/// `MacosUserland4K` (requires `subpage_compat`) for 4 KiB guests.
pub struct MacosUserlandWithPageSize<const PAGE_SIZE: usize> {
    pages: Mutex<subpage::Pages<PAGE_SIZE>>,
    /// One-time initialization snapshot of host mappings unavailable to guest programs.
    /// Host mappings created after [`Self::new`] are not included.
    reserved_pages: Vec<Range<usize>>,
}

impl<const PAGE_SIZE: usize> core::fmt::Debug for MacosUserlandWithPageSize<PAGE_SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacosUserland").finish_non_exhaustive()
    }
}

impl<const PAGE_SIZE: usize> MacosUserlandWithPageSize<PAGE_SIZE> {
    /// Initialize the platform.
    ///
    /// # Panics
    /// Panics if the host page size, pthread TSD layout, signal setup, or host memory-map
    /// snapshot is unsupported or cannot be initialized.
    pub fn new() -> &'static Self {
        const {
            assert!(
                PAGE_SIZE == HOST_PAGE_SIZE
                    || (cfg!(feature = "subpage_compat") && PAGE_SIZE == 4096),
                "4 KiB guest pages require subpage_compat"
            );
        }
        // SAFETY: this scalar query has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert_eq!(
            usize::try_from(page_size).ok(),
            Some(HOST_PAGE_SIZE),
            "unsupported macOS page size"
        );
        TLS_KEY
            .get_or_init(create_tls_key)
            .as_ref()
            .unwrap_or_else(|error| panic!("failed to initialize macOS TLS: {error}"));
        initialize_thread_tls();
        register_exception_handlers().expect("failed to install macOS signal handlers");
        let reserved_pages = Self::read_maps();
        Box::leak(Box::new(Self {
            pages: Mutex::new(subpage::Pages::default()),
            reserved_pages,
        }))
    }

    /// Take the macOS equivalent of a `/proc/self/maps` snapshot.
    fn read_maps() -> Vec<Range<usize>> {
        // SAFETY: `mach_task_self` takes no arguments and returns the calling task's send right.
        let task = unsafe { mach_task_self() };
        let mut reserved_pages = Vec::new();
        let mut cursor = 0_u64;

        loop {
            let mut address = cursor;
            let mut size = 0_u64;
            // Only the returned range matters: mappings with every protection, including
            // PROT_NONE reservations, must remain unavailable to the guest.
            let mut info = [0_i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
            let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name = MACH_PORT_NULL;
            // SAFETY: all output pointers refer to initialized, writable storage of the
            // sizes required by VM_REGION_BASIC_INFO_64, and `task` is our task port.
            let result = unsafe {
                mach_vm_region(
                    task,
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &raw mut info_count,
                    &raw mut object_name,
                )
            };
            if result == KernReturn::INVALID_ADDRESS {
                break;
            }
            assert_eq!(result, KernReturn::SUCCESS, "mach_vm_region failed");
            if object_name != MACH_PORT_NULL {
                // `mach_vm_region` transfers this send right to the caller.
                // SAFETY: `object_name` is the right returned by the successful call above.
                let deallocate_result = unsafe { mach_port_deallocate(task, object_name) };
                assert_eq!(
                    deallocate_result,
                    KernReturn::SUCCESS,
                    "mach_port_deallocate failed"
                );
            }

            let end = address
                .checked_add(size)
                .expect("mach_vm_region returned an overflowing range");
            assert!(size != 0 && end > cursor, "mach_vm_region did not advance");
            let start = usize::try_from(address).expect("mapping address does not fit usize");
            let end = usize::try_from(end).expect("mapping end does not fit usize");
            assert!(
                start.is_multiple_of(HOST_PAGE_SIZE) && end.is_multiple_of(HOST_PAGE_SIZE),
                "mach_vm_region returned an unaligned range"
            );
            reserved_pages.push(start..end);
            cursor = end as u64;
        }

        reserved_pages
    }
}

impl<const PAGE_SIZE: usize> litebox::platform::Provider for MacosUserlandWithPageSize<PAGE_SIZE> {}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl<const PAGE_SIZE: usize> litebox::platform::RawPointerProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

thread_local! {
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

// SAFETY: the pointer is isolated by host TLS and initialized to null.
unsafe impl<const PAGE_SIZE: usize> litebox::platform::ThreadLocalStorageProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }
}

impl<const PAGE_SIZE: usize> MachClock for MacosUserlandWithPageSize<PAGE_SIZE> {
    fn mach_absolute_time(&self) -> u64 {
        // SAFETY: this scalar query has no pointer arguments or preconditions.
        unsafe { mach_absolute_time() }
    }

    fn mach_timebase_info(&self) -> MachTimebaseInfo {
        let mut info = MachTimebaseInfo::default();
        // SAFETY: `info` is writable output storage for mach_timebase_info.
        let result = unsafe { mach_timebase_info(&raw mut info) };
        assert_eq!(result, KernReturn::SUCCESS, "mach_timebase_info failed");
        info
    }

    fn mach_wait_until(&self, deadline: u64) -> KernReturn {
        // SAFETY: the deadline is a scalar in mach_absolute_time's clock domain.
        unsafe { mach_wait_until(deadline) }
    }
}

impl<const PAGE_SIZE: usize> TimeProvider for MacosUserlandWithPageSize<PAGE_SIZE> {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: t is writable output storage for clock_gettime.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_RAW, t.as_mut_ptr()) };
        assert_eq!(result, 0, "clock_gettime(CLOCK_UPTIME_RAW) failed");
        // SAFETY: successful clock_gettime initialized t.
        let t = unsafe { t.assume_init() };
        Instant {
            #[expect(clippy::useless_conversion)]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: t is writable output storage for clock_gettime.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        assert_eq!(result, 0, "clock_gettime(CLOCK_REALTIME) failed");
        // SAFETY: successful clock_gettime initialized t.
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[expect(clippy::useless_conversion)]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl SystemTimeTrait for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    struct OsSyncFlags: u32 {
        const NONE = 0;
        const SHARED = 1;
    }
}

#[repr(u32)]
enum OsClockId {
    MachAbsoluteTime = 32,
}

unsafe extern "C" {
    fn os_sync_wait_on_address(
        address: *mut libc::c_void,
        value: u64,
        size: usize,
        flags: OsSyncFlags,
    ) -> i32;
    fn os_sync_wait_on_address_with_timeout(
        address: *mut libc::c_void,
        value: u64,
        size: usize,
        flags: OsSyncFlags,
        clock: OsClockId,
        timeout_ns: u64,
    ) -> i32;
    fn os_sync_wake_by_address_any(
        address: *mut libc::c_void,
        size: usize,
        flags: OsSyncFlags,
    ) -> i32;
    fn os_sync_wake_by_address_all(
        address: *mut libc::c_void,
        size: usize,
        flags: OsSyncFlags,
    ) -> i32;
}

pub struct RawMutex {
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn address(&self) -> *mut libc::c_void {
        std::ptr::from_ref(&self.inner).cast_mut().cast()
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        if self.inner.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Ok(UnblockedOrTimedOut::TimedOut);
        }

        let result = if let Some(timeout) = timeout {
            let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
            // SAFETY: address points to the aligned AtomicU32 compared by the kernel.
            unsafe {
                os_sync_wait_on_address_with_timeout(
                    self.address(),
                    u64::from(val),
                    size_of::<u32>(),
                    OsSyncFlags::NONE,
                    OsClockId::MachAbsoluteTime,
                    timeout_ns,
                )
            }
        } else {
            // SAFETY: address points to the aligned AtomicU32 compared by the kernel.
            unsafe {
                os_sync_wait_on_address(
                    self.address(),
                    u64::from(val),
                    size_of::<u32>(),
                    OsSyncFlags::NONE,
                )
            }
        };
        if result >= 0 {
            return Ok(UnblockedOrTimedOut::Unblocked);
        }

        // SAFETY: __error returns this thread's live errno slot.
        let error = unsafe { *libc::__error() };
        match error {
            libc::ETIMEDOUT => Ok(UnblockedOrTimedOut::TimedOut),
            // Documented transient failures are equivalent to spurious wakeups.
            libc::EINTR | libc::EFAULT | libc::ENOMEM => Ok(UnblockedOrTimedOut::Unblocked),
            _ => panic!("unexpected os_sync_wait_on_address errno {error}"),
        }
    }
}

impl<const PAGE_SIZE: usize> RawMutexProvider for MacosUserlandWithPageSize<PAGE_SIZE> {
    type RawMutex = RawMutex;
}

impl RawMutexTrait for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        if n >= i32::MAX as usize {
            // SAFETY: address points to the aligned AtomicU32 used by matching waits.
            let result = unsafe {
                os_sync_wake_by_address_all(self.address(), size_of::<u32>(), OsSyncFlags::NONE)
            };
            assert!(result == 0 || unsafe { *libc::__error() } == libc::ENOENT);
            return 0;
        }

        let mut woken = 0;
        for _ in 0..n {
            // SAFETY: address points to the aligned AtomicU32 used by matching waits.
            let result = unsafe {
                os_sync_wake_by_address_any(self.address(), size_of::<u32>(), OsSyncFlags::NONE)
            };
            if result == 0 {
                woken += 1;
            } else {
                // SAFETY: __error returns this thread's live errno slot.
                let error = unsafe { *libc::__error() };
                assert_eq!(error, libc::ENOENT);
                break;
            }
        }
        woken
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl<const PAGE_SIZE: usize> litebox::platform::TimerProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        Ok(TimerHandle::new(signal))
    }
}

struct TimerState {
    arming: Option<(std::time::Instant, Duration)>,
    target_process: Option<Arc<ProcessState>>,
    shutdown: bool,
}

struct TimerShared {
    state: Mutex<TimerState>,
    changed: Condvar,
}

/// A re-armable one-shot timer backed by a host worker thread.
///
/// macOS has no POSIX `timer_create`. At expiry the worker records the guest
/// signal and uses the platform's private interrupt signal to preempt a guest
/// busy-loop.
pub struct TimerHandle {
    shared: Arc<TimerShared>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl TimerHandle {
    fn new(signal: litebox_common_linux::signal::Signal) -> Self {
        assert!(
            (1..32).contains(&signal.as_i32()),
            "macOS timers do not support real-time guest signals"
        );
        let shared = Arc::new(TimerShared {
            state: Mutex::new(TimerState {
                arming: None,
                target_process: None,
                shutdown: false,
            }),
            changed: Condvar::new(),
        });
        let worker_shared = shared.clone();

        // Block before spawning so the worker inherits the mask and cannot
        // consume guest-directed host signals during startup.
        // SAFETY: both sigsets are initialized output storage and this changes
        // only the calling thread's mask, which is restored below.
        let old_mask = unsafe {
            let mut signals = core::mem::zeroed::<libc::sigset_t>();
            let mut old_mask = core::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&raw mut signals);
            for &(host_signal, _) in FORWARDED_SIGNALS {
                libc::sigaddset(&raw mut signals, host_signal);
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut old_mask),
                0
            );
            old_mask
        };
        let worker = std::thread::Builder::new()
            .name("litebox-macos-timer".into())
            .spawn(move || timer_worker(&worker_shared, signal));
        // SAFETY: old_mask was returned by pthread_sigmask for this thread.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const old_mask,
                    core::ptr::null_mut(),
                )
            },
            0
        );
        let worker = worker.expect("failed to create macOS timer worker");
        Self {
            shared,
            worker: Some(worker),
        }
    }
}

fn timer_worker(shared: &TimerShared, signal: litebox_common_linux::signal::Signal) {
    let mut state = shared.state.lock().unwrap();
    loop {
        if state.shutdown {
            return;
        }
        let Some((armed_at, duration)) = state.arming else {
            state = shared.changed.wait(state).unwrap();
            continue;
        };
        let elapsed = armed_at.elapsed();
        if elapsed < duration {
            // Avoid converting an arbitrarily large guest duration into an
            // absolute std::time::Instant or a platform condvar deadline.
            const MAX_WAIT: Duration = Duration::from_hours(24);
            let wait = duration.checked_sub(elapsed).unwrap().min(MAX_WAIT);
            let (new_state, _) = shared.changed.wait_timeout(state, wait).unwrap();
            state = new_state;
            continue;
        }

        state.arming = None;
        let target_process = state.target_process.take();
        drop(state);
        if let Some(target_process) = target_process {
            target_process.deliver_signal(signal);
        }
        state = shared.state.lock().unwrap();
    }
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock().unwrap();
            state.shutdown = true;
            state.arming = None;
            state.target_process = None;
            self.shared.changed.notify_one();
        }
        if let Some(worker) = self.worker.take() {
            worker.join().expect("macOS timer worker panicked");
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: Duration) {
        let mut state = self.shared.state.lock().unwrap();
        if duration.is_zero() {
            state.arming = None;
            state.target_process = None;
        } else {
            let current = ThreadHandle::current();
            state.arming = Some((std::time::Instant::now(), duration));
            state.target_process = Some(current.0.process.clone());
        }
        self.shared.changed.notify_one();
    }
}

impl<const PAGE_SIZE: usize> litebox::platform::SignalProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        // Atomic swap avoids losing handler updates; Relaxed suffices because
        // the bits publish no other data.
        let mut bits =
            with_signal_state(|pending, _| pending.swap(0, Ordering::Relaxed)).unwrap_or(0);
        if read_tls(tls_offset::CURRENT_THREAD) != 0 {
            // Drain process-wide timer signals once into the shim's shared queue.
            bits |= ThreadHandle::current()
                .0
                .process
                .pending_signals
                .swap(0, Ordering::Relaxed);
        }
        for signal in litebox_common_linux::signal::SigSet::from_u64(u64::from(bits)) {
            f(signal);
        }
    }
}
impl<const PAGE_SIZE: usize> litebox::mm::linux::VmemPageFaultHandler
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
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

bitflags::bitflags! {
    #[repr(transparent)]
    struct MachVmFlags: i32 {
        /// Mach uses zero to request the supplied fixed address.
        const FIXED = 0;
        const ANYWHERE = 0x0000_0001;
    }

    #[repr(transparent)]
    struct MachVmProtection: i32 {
        const READ = libc::VM_PROT_READ;
        const WRITE = libc::VM_PROT_WRITE;
        const EXECUTE = libc::VM_PROT_EXECUTE;
        const COPY = 0x10;
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct MachBoolean(i32);

impl MachBoolean {
    const FALSE: Self = Self(0);
    const TRUE: Self = Self(1);
}

#[derive(Clone, Copy)]
#[repr(u32)]
enum MachVmInheritance {
    None = 2,
}

const MACH_PORT_NULL: u32 = 0;
const BSD_SYS_MMAP: usize = 197;
const BSD_SYS_MPROTECT: usize = 74;
const BSD_SYS_SIGPROCMASK: usize = 48;
const BSD_SYS_SIGRETURN: usize = 184;
const MACH_VM_DEALLOCATE_TRAP: usize = 0u32.wrapping_sub(12) as usize;
const VM_REGION_BASIC_INFO_64: i32 = 9;
// sizeof(vm_region_basic_info_data_64_t) / sizeof(integer_t) on macOS. The
// SDK declares this structure with 4-byte packing, making it 36 bytes.
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> KernReturn;
    fn mach_wait_until(deadline: u64) -> KernReturn;
    fn mach_task_self() -> u32;
    fn mach_port_deallocate(task: u32, name: u32) -> KernReturn;
    fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: MachVmFlags) -> KernReturn;
    fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> KernReturn;
    fn mach_vm_protect(
        task: u32,
        address: u64,
        size: u64,
        set_maximum: MachBoolean,
        protection: MachVmProtection,
    ) -> KernReturn;
    fn mach_vm_remap(
        task: u32,
        target: *mut u64,
        size: u64,
        mask: u64,
        flags: MachVmFlags,
        source_task: u32,
        source: u64,
        copy: MachBoolean,
        current_protection: *mut MachVmProtection,
        max_protection: *mut MachVmProtection,
        inheritance: MachVmInheritance,
    ) -> KernReturn;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        info_count: *mut u32,
        object_name: *mut u32,
    ) -> KernReturn;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> KernReturn;
    fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
}
/// Failure while staging or publishing private dyld shared-cache mappings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedCacheMappingError {
    /// A requested range is empty or not aligned to the native host page size.
    Unaligned,
    /// A Mach VM operation returned this kernel status.
    Mach(KernReturn),
    /// A raw BSD VM syscall returned this errno.
    Errno(i32),
    /// A fixed-address operation did not produce the requested address.
    UnexpectedAddress,
}

impl core::fmt::Display for SharedCacheMappingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unaligned => formatter.write_str("shared-cache range is not host-page aligned"),
            Self::Mach(value) => write!(formatter, "Mach VM operation failed: {value:?}"),
            Self::Errno(value) => write!(formatter, "Darwin VM syscall failed with errno {value}"),
            Self::UnexpectedAddress => {
                formatter.write_str("Darwin VM syscall returned the wrong address")
            }
        }
    }
}

impl core::error::Error for SharedCacheMappingError {}

/// Replace a host mapping with an anonymous private copy at the same address.
///
/// This is used by the macOS runner child to privatize shared-cache code before
/// rewriting it. Keeping the virtual address unchanged preserves the cache's
/// boot-local ASLR slide and arm64e pointer signatures.
///
/// # Safety
///
/// No thread may execute from `range` while it is replaced. The caller must
/// ensure the range belongs to the current process's dyld shared cache.
pub unsafe fn prepare_shared_cache_copy(
    range: Range<usize>,
) -> Result<SharedCacheWriteAlias, SharedCacheMappingError> {
    if !is_page_aligned::<HOST_PAGE_SIZE>(&range) {
        return Err(SharedCacheMappingError::Unaligned);
    }
    let mut alias = 0u64;
    let mut current = MachVmProtection::empty();
    let mut maximum = MachVmProtection::empty();
    // SAFETY: output fields are writable, the source range is caller-validated,
    // and Mach validates both task-relative address ranges.
    let remapped = unsafe {
        mach_vm_remap(
            mach_task_self(),
            &raw mut alias,
            range.len() as u64,
            0,
            MachVmFlags::ANYWHERE,
            mach_task_self(),
            range.start as u64,
            MachBoolean::TRUE, // private COW copy
            &raw mut current,
            &raw mut maximum,
            MachVmInheritance::None,
        )
    };
    if remapped != KernReturn::SUCCESS {
        return Err(SharedCacheMappingError::Mach(remapped));
    }
    // VM_PROT_COPY permits a writable COW view of code-signed shared-cache
    // pages while retaining executable provenance for publication.
    // SAFETY: alias is the live mapping returned by mach_vm_remap above.
    let writable = unsafe {
        mach_vm_protect(
            mach_task_self(),
            alias,
            range.len() as u64,
            MachBoolean::FALSE,
            MachVmProtection::READ | MachVmProtection::WRITE | MachVmProtection::COPY,
        )
    };
    if writable != KernReturn::SUCCESS {
        // SAFETY: alias is still exclusively owned after the failed protection change.
        unsafe { mach_vm_deallocate(mach_task_self(), alias, range.len() as u64) };
        return Err(SharedCacheMappingError::Mach(writable));
    }
    Ok(SharedCacheWriteAlias {
        address: usize::try_from(alias).map_err(|_| SharedCacheMappingError::UnexpectedAddress)?,
        target: range.start,
        len: range.len(),
    })
}

/// Make shared-cache data privately writable in the forked runner.
///
/// # Safety
///
/// The caller must exclusively control `range`, ensure that it belongs to the
/// current process's shared cache, and prevent concurrent access while its
/// mapping protections are changed.
pub unsafe fn make_shared_cache_range_writable(
    range: Range<usize>,
) -> Result<(), SharedCacheMappingError> {
    if !is_page_aligned::<HOST_PAGE_SIZE>(&range) {
        return Err(SharedCacheMappingError::Unaligned);
    }
    // SAFETY: the caller guarantees exclusive control and validity of range;
    // Mach validates the task-relative mapping and requested protections.
    let result = unsafe {
        mach_vm_protect(
            mach_task_self(),
            range.start as u64,
            range.len() as u64,
            MachBoolean::FALSE,
            MachVmProtection::READ | MachVmProtection::WRITE | MachVmProtection::COPY,
        )
    };
    if result == KernReturn::SUCCESS {
        Ok(())
    } else {
        Err(SharedCacheMappingError::Mach(result))
    }
}

/// Prepare zero-filled RW staging for a trampoline installed as RX on commit.
pub fn prepare_private_cache_mapping(
    range: Range<usize>,
) -> Result<SharedCacheWriteAlias, SharedCacheMappingError> {
    if !is_page_aligned::<HOST_PAGE_SIZE>(&range) {
        return Err(SharedCacheMappingError::Unaligned);
    }
    let len = range.len();
    // mach_vm_allocate gives the anonymous object an RWX maximum protection.
    let mut temporary = 0u64;
    // SAFETY: temporary is writable and ANYWHERE requests a fresh mapping.
    let allocated = unsafe {
        mach_vm_allocate(
            mach_task_self(),
            &raw mut temporary,
            len as u64,
            MachVmFlags::ANYWHERE,
        )
    };
    if allocated != KernReturn::SUCCESS {
        return Err(SharedCacheMappingError::Mach(allocated));
    }
    let address =
        usize::try_from(temporary).map_err(|_| SharedCacheMappingError::UnexpectedAddress)?;
    Ok(SharedCacheWriteAlias {
        address,
        target: range.start,
        len,
    })
}

/// Invoke `mmap(MAP_FIXED)` without entering potentially replaced libSystem code.
///
/// # Safety
///
/// The caller must own the target range and permit its existing mapping to be
/// destroyed. `address..address + length` must not overflow.
unsafe fn raw_fixed_anonymous(address: usize, length: usize) -> Result<usize, i32> {
    let result: usize;
    let failed: usize;
    // SAFETY: registers follow the Darwin mmap syscall ABI; the caller supplies
    // the ownership and range validity required by MAP_FIXED.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            "cset {failed}, cs",
            in("x0") address,
            inlateout("x1") length => _,
            in("x2") (libc::PROT_READ | libc::PROT_WRITE) as usize,
            in("x3") (libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED) as usize,
            in("x4") usize::MAX,
            in("x5") 0usize,
            in("x16") BSD_SYS_MMAP,
            lateout("x0") result,
            failed = lateout(reg) failed,
            options(nostack),
        );
    }
    if failed == 0 {
        Ok(result)
    } else {
        Err(i32::try_from(result).unwrap_or(i32::MAX))
    }
}

/// Invoke `mprotect` without entering potentially replaced libSystem code.
///
/// # Safety
///
/// The range must be a live mapping controlled by the caller, and changing its
/// protections must not race any access from another thread.
unsafe fn raw_protect(address: usize, length: usize, protection: i32) -> Result<(), i32> {
    let result: usize;
    let failed: usize;
    // SAFETY: registers follow the Darwin mprotect syscall ABI and the caller
    // guarantees exclusive control of the live mapping.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            "cset {failed}, cs",
            in("x0") address,
            inlateout("x1") length => _,
            in("x2") protection.cast_unsigned() as usize,
            in("x16") BSD_SYS_MPROTECT,
            lateout("x0") result,
            failed = lateout(reg) failed,
            options(nostack),
        );
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(i32::try_from(result).unwrap_or(i32::MAX))
    }
}

unsafe fn raw_signal_mask(
    how: i32,
    set: &libc::sigset_t,
    previous: *mut libc::sigset_t,
) -> Result<(), i32> {
    let result: usize;
    let failed: usize;
    // SAFETY: pointers reference live signal-mask storage for this thread.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            "cset {failed}, cs",
            in("x0") how.cast_unsigned() as usize,
            inlateout("x1") core::ptr::from_ref(set) as usize => _,
            in("x2") previous as usize,
            in("x16") BSD_SYS_SIGPROCMASK,
            lateout("x0") result,
            failed = lateout(reg) failed,
            options(nostack),
        );
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(i32::try_from(result).unwrap_or(i32::MAX))
    }
}

unsafe fn raw_deallocate(task: u32, address: usize, length: usize) -> KernReturn {
    let result: usize;
    // SAFETY: arguments follow the mach_vm_deallocate trap ABI.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            inlateout("x0") task as usize => result,
            in("x1") address,
            in("x2") length,
            in("x16") MACH_VM_DEALLOCATE_TRAP,
            options(nostack),
        );
    }
    KernReturn::from_raw(i32::try_from(result).unwrap_or(i32::MAX))
}

/// Copy bytes without allowing LLVM to introduce a libSystem call.
///
/// # Safety
///
/// Both ranges must be valid for `length` bytes and must not overlap.
unsafe fn raw_copy(destination: *mut u8, source: *const u8, length: usize) {
    // SAFETY: the caller guarantees both ranges; the loop accesses exactly
    // length bytes and uses no stack or external code.
    unsafe {
        core::arch::asm!(
            "cbz {length}, 2f",
            "1:",
            "ldrb {byte:w}, [{source}], #1",
            "strb {byte:w}, [{destination}], #1",
            "subs {length}, {length}, #1",
            "b.ne 1b",
            "2:",
            destination = inlateout(reg) destination => _,
            source = inlateout(reg) source => _,
            length = inlateout(reg) length => _,
            byte = lateout(reg) _,
            options(nostack),
        );
    }
}

const RAW_FATAL_MESSAGE: [u8; 48] = *b"fatal shared-cache publication errno=0x00000000\n";

/// Report an unrecoverable post-publication errno and terminate via raw `_exit`.
///
/// # Safety
///
/// This unconditionally terminates the process and therefore may only be used
/// after shared-cache publication has made ordinary unwinding unsafe.
unsafe fn raw_fatal_exit(error: i32, message: &mut [u8; RAW_FATAL_MESSAGE.len()]) -> ! {
    let value = error.cast_unsigned();
    for (index, byte) in message[39..47].iter_mut().enumerate() {
        let nibble = ((value >> ((7 - index) * 4)) & 0xf) as usize;
        *byte = b"0123456789abcdef"[nibble];
    }
    raw_signal_write(message);
    // SAFETY: SYS_exit accepts the status in x0 and never returns.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x0") (128 + libc::SIGABRT) as usize,
            in("x16") 1usize,
            options(noreturn),
        );
    }
}

/// Writable staging alias for a private shared-cache mapping.
///
/// Drop releases an unpublished alias. Commit attempts a raw release; process
/// exit reclaims staging if that release fails.
pub struct SharedCacheWriteAlias {
    address: usize,
    target: usize,
    len: usize,
}

impl SharedCacheWriteAlias {
    /// Return the writable staging mapping's base address.
    pub fn address(&self) -> usize {
        self.address
    }

    /// Publish the fully rewritten staging copy at its original cache address.
    /// # Safety
    ///
    /// The caller must exclusively own the target address range and ensure no
    /// thread can execute from or otherwise access it until publication ends.
    pub unsafe fn commit(self) -> Result<(), SharedCacheMappingError> {
        // Materialize diagnostics while every libSystem mapping is still executable.
        let mut fatal_message = RAW_FATAL_MESSAGE;
        // Move into its final storage before replacement. No Rust move, Drop,
        // allocation, or libc call is permitted after the target may disappear.
        let this = core::mem::ManuallyDrop::new(self);
        let target = this.target;
        let len = this.len;
        let address = this.address;
        // SAFETY: mach_task_self has no preconditions.
        let task = unsafe { mach_task_self() };
        let all_signals = !0;
        let mut previous_signals = 0;
        // SAFETY: both masks are live and no mapping has been replaced yet.
        unsafe {
            raw_signal_mask(libc::SIG_BLOCK, &all_signals, &raw mut previous_signals)
                .map_err(SharedCacheMappingError::Errno)?;
        }
        // Use raw syscalls: the mapping being replaced contains the libc
        // wrappers for mmap/mprotect themselves. Returning through those
        // wrappers while the page is RW or empty is not safe.
        // SAFETY: commit's contract grants exclusive ownership of target.
        let mapped = match unsafe { raw_fixed_anonymous(target, len) } {
            Ok(mapped) => mapped,
            Err(error) => {
                // SAFETY: no mapping was replaced; staging is no longer needed.
                unsafe {
                    let _ = raw_deallocate(task, address, len);
                    raw_signal_mask(libc::SIG_SETMASK, &previous_signals, core::ptr::null_mut())
                        .map_err(SharedCacheMappingError::Errno)?;
                }
                return Err(SharedCacheMappingError::Errno(error));
            }
        };
        if mapped != target {
            // SAFETY: MAP_FIXED already destroyed the old mapping, so unwinding is unsafe.
            unsafe { raw_fatal_exit(libc::EFAULT, &mut fatal_message) }
        }
        // SAFETY: commit's contract covers the source and destination ranges;
        // post-replacement failures terminate without unwinding through the cache.
        unsafe {
            let destination = target as *mut u8;
            let source = address as *const u8;
            raw_copy(destination, source, len);
            if let Err(error) = raw_protect(target, len, libc::PROT_READ | libc::PROT_EXEC) {
                raw_fatal_exit(error, &mut fatal_message);
            }
            // The complete page is RX before this call. If this routine's own
            // cache page was replaced, stale instructions are byte-identical.
            sys_icache_invalidate(target as *mut libc::c_void, len);
            // Release staging with a raw trap because its wrapper may have been replaced.
            let _ = raw_deallocate(task, address, len);
            if let Err(error) =
                raw_signal_mask(libc::SIG_SETMASK, &previous_signals, core::ptr::null_mut())
            {
                raw_fatal_exit(error, &mut fatal_message);
            }
        }
        Ok(())
    }
}

impl Drop for SharedCacheWriteAlias {
    fn drop(&mut self) {
        // Best effort during setup failure. The runner child is short-lived and
        // the kernel reclaims any surviving staging mapping on exit.
        // SAFETY: an unpublished alias exclusively owns this live Mach allocation.
        let _ =
            unsafe { mach_vm_deallocate(mach_task_self(), self.address as u64, self.len as u64) };
    }
}

fn is_page_aligned<const PAGE_SIZE: usize>(range: &Range<usize>) -> bool {
    range.start < range.end
        && range.start.is_multiple_of(PAGE_SIZE)
        && range.end.is_multiple_of(PAGE_SIZE)
}
fn prot_flags(permissions: MemoryRegionPermissions) -> i32 {
    if permissions.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!("shared macOS mappings are not supported")
    }
    let mut flags = libc::PROT_NONE;
    if permissions.contains(MemoryRegionPermissions::READ) {
        flags |= libc::PROT_READ;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE) {
        flags |= libc::PROT_WRITE;
    }
    if permissions.contains(MemoryRegionPermissions::EXEC) {
        flags |= libc::PROT_EXEC;
    }
    flags
}
impl<const PAGE_SIZE: usize> litebox::platform::PageManagementProvider<PAGE_SIZE>
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
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
        if !is_page_aligned::<PAGE_SIZE>(&range) {
            return Err(AllocationError::Unaligned);
        }
        if range.start < TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if permissions.contains(MemoryRegionPermissions::WRITE | MemoryRegionPermissions::EXEC) {
            return Err(AllocationError::PermissionDenied);
        }
        self.pages
            .lock()
            .unwrap()
            .allocate(range, permissions, behavior)
            .map(Self::RawMutPointer::from_usize)
    }
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
        if !is_page_aligned::<PAGE_SIZE>(&range) {
            return Err(DeallocationError::Unaligned);
        }
        self.pages.lock().unwrap().deallocate(range)
    }
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        if !is_page_aligned::<PAGE_SIZE>(&old_range) || !is_page_aligned::<PAGE_SIZE>(&new_range) {
            return Err(RemapError::Unaligned);
        }
        if old_range.start < new_range.end && new_range.start < old_range.end {
            return Err(RemapError::Overlapping);
        }
        assert!(
            new_range.len() > old_range.len(),
            "remap_pages requires the new range to be larger than the old range"
        );
        {
            let pages = self.pages.lock().unwrap();
            if !pages.contains_range(old_range.clone()) {
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
        if !is_page_aligned::<PAGE_SIZE>(&range) {
            return Err(PermissionUpdateError::Unaligned);
        }
        if permissions.contains(MemoryRegionPermissions::WRITE | MemoryRegionPermissions::EXEC) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        self.pages
            .lock()
            .unwrap()
            .update_permissions(range, permissions)
    }
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        self.reserved_pages.iter()
    }
}

/// Layout of LiteBox's per-thread AArch64 state.
///
/// Field offsets are shared with transition assembly and rewritten guest gates.
#[repr(C)]
struct TlsBlock {
    guest_thread_pointer: usize,
    guest_x18: usize,
    active: usize,
    current_thread: usize,
    in_guest: usize,
    native_sigreturn_pending: usize,
    vector_state: usize,
    host_fp_state: usize,
    pending_host_signals: AtomicU32,
    wait_waker_addr: AtomicPtr<core::task::Waker>,
    page_recovery_lock: usize,
}

mod tls_offset {
    use super::TlsBlock;

    pub const GUEST_THREAD_POINTER: usize = core::mem::offset_of!(TlsBlock, guest_thread_pointer);
    pub const GUEST_X18: usize = core::mem::offset_of!(TlsBlock, guest_x18);
    pub const ACTIVE: usize = core::mem::offset_of!(TlsBlock, active);
    pub const CURRENT_THREAD: usize = core::mem::offset_of!(TlsBlock, current_thread);
    pub const IN_GUEST: usize = core::mem::offset_of!(TlsBlock, in_guest);
    pub const NATIVE_SIGRETURN_PENDING: usize =
        core::mem::offset_of!(TlsBlock, native_sigreturn_pending);
    pub const VECTOR_STATE: usize = core::mem::offset_of!(TlsBlock, vector_state);
    pub const HOST_FP_STATE: usize = core::mem::offset_of!(TlsBlock, host_fp_state);
    pub const PENDING_HOST_SIGNALS: usize = core::mem::offset_of!(TlsBlock, pending_host_signals);
    pub const WAIT_WAKER_ADDR: usize = core::mem::offset_of!(TlsBlock, wait_waker_addr);
    pub const PAGE_RECOVERY_LOCK: usize = core::mem::offset_of!(TlsBlock, page_recovery_lock);
}

// The macOS rewriter gates encode these offsets directly after loading the
// TlsBlock pointer from the pthread key slot.
const _: () = assert!(tls_offset::GUEST_THREAD_POINTER == 0);
const _: () = assert!(tls_offset::GUEST_X18 == GUEST_X18_OFFSET_FROM_GUEST_TP);
const _: () = assert!(tls_offset::IN_GUEST == IN_GUEST_OFFSET_FROM_GUEST_TP as usize);

#[derive(Debug)]
struct TlsKey(libc::pthread_key_t);

static TLS_KEY: OnceLock<Result<TlsKey, i32>> = OnceLock::new();
static TLS_KEY_OFFSET: AtomicUsize = AtomicUsize::new(0);

impl Drop for TlsKey {
    fn drop(&mut self) {
        // SAFETY: TlsKey owns this key.
        unsafe { libc::pthread_key_delete(self.0) };
    }
}

fn tls_key() -> libc::pthread_key_t {
    let Some(Ok(key)) = TLS_KEY.get() else {
        fatal_signal(b"macOS TLS is not initialized", 0);
    };
    key.0
}

unsafe extern "C" fn drop_tls_block(value: *mut libc::c_void) {
    if !value.is_null() {
        // SAFETY: initialize_thread_tls stores an owned TlsBlock in this key.
        let block = unsafe { Box::from_raw(value.cast::<TlsBlock>()) };
        if block.vector_state != 0 {
            // SAFETY: initialize_thread_tls gives the block ownership of this allocation.
            unsafe { drop(Box::from_raw(block.vector_state as *mut GuestVectorState)) };
        }
    }
}

fn validate_tls_layout(key: libc::pthread_key_t, key_offset: usize) -> Result<(), i32> {
    let sentinel = 0x1234usize;
    // SAFETY: the newly allocated key remains live; pthread treats the value as opaque.
    let previous = unsafe { libc::pthread_getspecific(key) };
    // SAFETY: no destructor can run before this value is restored.
    let error = unsafe { libc::pthread_setspecific(key, sentinel as *const libc::c_void) };
    if error != 0 {
        return Err(error);
    }
    let mut value = [0u8; size_of::<usize>()];
    let mut copied = 0;
    let address = anchor() + key_offset;
    // SAFETY: value and copied are writable; Mach validates the source address without faulting.
    let valid = unsafe {
        mach_vm_read_overwrite(
            mach_task_self(),
            address as u64,
            value.len() as u64,
            value.as_mut_ptr() as u64,
            &raw mut copied,
        ) == KernReturn::SUCCESS
    } && copied == value.len() as u64
        && usize::from_ne_bytes(value) == sentinel;
    // SAFETY: restore the opaque value that preceded this temporary probe.
    let error = unsafe { libc::pthread_setspecific(key, previous) };
    if error != 0 {
        return Err(error);
    }
    valid.then_some(()).ok_or(libc::ENOTSUP)
}

fn create_tls_key() -> Result<TlsKey, i32> {
    let mut key = 0;
    // SAFETY: key is writable; the destructor owns the block stored in it.
    let error = unsafe { libc::pthread_key_create(&raw mut key, Some(drop_tls_block)) };
    if error != 0 {
        return Err(error);
    }
    let key_offset: usize = key.trunc();
    let key_offset = key_offset * size_of::<usize>();
    if !u16::try_from(key_offset).is_ok_and(is_patchable_guest_tpidr_offset) {
        // SAFETY: key was allocated above and has not been published.
        unsafe { libc::pthread_key_delete(key) };
        return Err(libc::ENOTSUP);
    }
    if let Err(error) = validate_tls_layout(key, key_offset) {
        // SAFETY: key was allocated above and has not been published.
        unsafe { libc::pthread_key_delete(key) };
        return Err(error);
    }
    TLS_KEY_OFFSET.store(key_offset, Ordering::Relaxed);
    Ok(TlsKey(key))
}

struct PrivateDarwinThreadBootstrap {
    tpidrro: AtomicUsize,
    x18: AtomicUsize,
    errno: AtomicUsize,
    ready: AtomicBool,
}

#[unsafe(naked)]
unsafe extern "C" fn park_private_darwin_thread() -> ! {
    core::arch::naked_asm!(
        "1:",
        "mov x0, #-1",
        "mov w16, #-90", // mach_wait_until(UINT64_MAX)
        "svc #0x80",
        "b 1b",
    );
}

struct PrivateDarwinThreadState {
    tpidrro: usize,
    x18: usize,
    // Retained for an invariant test; guest code reaches this through its
    // private TSD rather than through a runner-owned address.
    #[cfg_attr(not(test), allow(dead_code))]
    errno: usize,
}

/// Create a native pthread/TSD donor, not a virtual pthread identity.
///
/// The donor never runs again outside a raw wait loop after publication and is
/// reclaimed only at process exit. Guest APIs that target `pthread_self()` or
/// `pthread_mach_thread_np()` therefore target this parked donor and remain
/// unsupported.
fn create_private_darwin_thread_state() -> PrivateDarwinThreadState {
    let bootstrap = Arc::new(PrivateDarwinThreadBootstrap {
        tpidrro: AtomicUsize::new(0),
        x18: AtomicUsize::new(0),
        errno: AtomicUsize::new(0),
        ready: AtomicBool::new(false),
    });
    let donor = Arc::clone(&bootstrap);
    let thread = std::thread::Builder::new()
        .name("litebox-darwin-tls".into())
        .spawn(move || {
            let mut signals = 0;
            // SAFETY: signals is writable and this donor remains blocked forever.
            unsafe {
                libc::sigfillset(&raw mut signals);
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const signals,
                        core::ptr::null_mut(),
                    ),
                    0,
                );
            }
            let tpidrro: usize;
            let x18: usize;
            // SAFETY: TPIDRRO_EL0 is readable at EL0 and x18 is a readable
            // Darwin-reserved register; neither operation changes machine state.
            unsafe {
                core::arch::asm!(
                    "mrs {tpidrro}, tpidrro_el0",
                    "mov {x18}, x18",
                    tpidrro = out(reg) tpidrro,
                    x18 = out(reg) x18,
                    options(nomem, nostack, preserves_flags),
                );
            }
            // SAFETY: __error returns this live pthread's errno slot.
            let errno = unsafe { libc::__error() } as usize;
            donor.tpidrro.store(tpidrro & !0b111, Ordering::Relaxed);
            donor.x18.store(x18, Ordering::Relaxed);
            donor.errno.store(errno, Ordering::Relaxed);
            donor.ready.store(true, Ordering::Release);
            // SAFETY: publication is complete; this function never returns or
            // touches pthread state again.
            unsafe { park_private_darwin_thread() }
        })
        .expect("failed to create private Darwin TLS owner");
    while !bootstrap.ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    drop(thread); // Detach; process exit reclaims the permanently parked donor.
    PrivateDarwinThreadState {
        tpidrro: bootstrap.tpidrro.load(Ordering::Relaxed),
        x18: bootstrap.x18.load(Ordering::Relaxed),
        errno: bootstrap.errno.load(Ordering::Relaxed),
    }
}

fn anchor() -> usize {
    let value: usize;
    // SAFETY: TPIDRRO_EL0 is readable at EL0 on macOS; this changes no memory or flags.
    unsafe {
        core::arch::asm!("mrs {value}, tpidrro_el0", value = out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & !0b111
}

fn tls_block_address() -> usize {
    let slot = (anchor() + TLS_KEY_OFFSET.load(Ordering::Relaxed)) as *const usize;
    // SAFETY: key creation validates this process-wide key-slot location.
    unsafe { slot.read_volatile() }
}

fn tls_address(offset: usize) -> *mut usize {
    let block = tls_block_address();
    assert_ne!(block, 0, "macOS TLS is not initialized for this thread");
    (block + offset) as *mut usize
}

/// Borrow only the atomic fields; transition code mutates the rest of TLS.
fn with_signal_state<R>(
    f: impl FnOnce(&AtomicU32, &AtomicPtr<core::task::Waker>) -> R,
) -> Option<R> {
    let block = tls_block_address();
    if block == 0 {
        return None;
    }
    // SAFETY: the slot holds this thread's live TlsBlock. The aligned atomic
    // references cannot escape the callback, and handlers use atomic access too.
    unsafe {
        Some(f(
            &*((block + tls_offset::PENDING_HOST_SIGNALS) as *const AtomicU32),
            &*((block + tls_offset::WAIT_WAKER_ADDR) as *const AtomicPtr<core::task::Waker>),
        ))
    }
}

fn read_tls(offset: usize) -> usize {
    let block = tls_block_address();
    if block == 0 {
        // Signal handlers are process-wide and may run on a non-LiteBox thread.
        return 0;
    }
    // SAFETY: a non-null key value is a live TlsBlock owned by this thread.
    unsafe { ((block + offset) as *const usize).read_volatile() }
}

fn write_tls(offset: usize, value: usize) {
    // SAFETY: create_tls_key validates the pthread slot before publishing the key,
    // and initialize_thread_tls installs this thread's TlsBlock.
    unsafe { tls_address(offset).write_volatile(value) }
}

fn initialize_thread_tls() {
    let key = tls_key();
    // SAFETY: the process-wide key remains allocated for the process lifetime.
    if !unsafe { libc::pthread_getspecific(key) }.is_null() {
        return;
    }
    let vector = Box::into_raw(Box::new(GuestVectorState::default())) as usize;
    let block = Box::new(TlsBlock {
        guest_thread_pointer: 0,
        guest_x18: 0,
        active: 0,
        current_thread: 0,
        in_guest: 0,
        native_sigreturn_pending: 0,
        vector_state: vector,
        host_fp_state: 0,
        pending_host_signals: AtomicU32::new(0),
        wait_waker_addr: AtomicPtr::new(core::ptr::null_mut()),
        page_recovery_lock: 0,
    });
    let block = Box::into_raw(block);
    // SAFETY: block matches the key destructor's contract.
    let error = unsafe { libc::pthread_setspecific(key, block.cast()) };
    if error != 0 {
        // SAFETY: pthread did not take ownership after the failed call.
        unsafe { drop_tls_block(block.cast()) };
        panic!(
            "failed to initialize macOS thread TLS: {}",
            std::io::Error::from_raw_os_error(error)
        );
    }
}

fn guest_thread_pointer_tp_offset() -> usize {
    TLS_KEY_OFFSET.load(Ordering::Relaxed)
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

impl<const PAGE_SIZE: usize> litebox::platform::ArchSpecificProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
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

const FORWARDED_SIGNALS: &[(i32, litebox_common_linux::signal::Signal)] = &[
    (libc::SIGINT, litebox_common_linux::signal::Signal::SIGINT),
    (libc::SIGALRM, litebox_common_linux::signal::Signal::SIGALRM),
];
const EXCEPTION_SIGNALS: [i32; 4] = [libc::SIGTRAP, libc::SIGSEGV, libc::SIGBUS, libc::SIGILL];
const HOST_SIGNAL_COUNT: usize = EXCEPTION_SIGNALS.len() + 1 + FORWARDED_SIGNALS.len();

struct SignalState {
    interrupt_signal: AtomicI32,
    previous: OnceLock<[libc::sigaction; HOST_SIGNAL_COUNT]>,
}

static SIGNAL_STATE: SignalState = SignalState {
    interrupt_signal: AtomicI32::new(0),
    previous: OnceLock::new(),
};

fn interrupt_signal() -> i32 {
    SIGNAL_STATE.interrupt_signal.load(Ordering::Relaxed)
}

fn forwarded_guest_signal(signal: i32) -> Option<litebox_common_linux::signal::Signal> {
    FORWARDED_SIGNALS
        .iter()
        .find_map(|&(host, guest)| (host == signal).then_some(guest))
}

fn host_signals() -> impl Iterator<Item = i32> {
    EXCEPTION_SIGNALS
        .into_iter()
        .chain(core::iter::once(interrupt_signal()))
        .chain(FORWARDED_SIGNALS.iter().map(|&(host, _)| host))
}
// Private Darwin si_code values absent from libc's public constants.
const SI_USER: i32 = 0x1_0001;
const SI_QUEUE: i32 = 0x1_0002;

#[derive(Clone, Copy)]
enum GuestExit {
    Exception(ExceptionInfo),
    Interrupt,
}

struct ThreadContext<'a> {
    guest_abi: GuestAbi,
    shim: &'a dyn EnterShim<ExecutionContext = PtRegs>,
    ctx: &'a mut PtRegs,
    host_sp: usize,
    svc_frame: usize,
    outbound_x16: usize,
    outbound_pc: usize,
    outbound_stub: usize,
    initial_entry: bool,
    interrupted: *const AtomicBool,
    thread: ThreadHandle,
    exit: GuestExit,
}

fn thread_start(
    init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = PtRegs>>,
    mut ctx: PtRegs,
    vector_state: GuestVectorState,
    process: Arc<ProcessState>,
) {
    initialize_thread_tls();
    set_guest_vector_state(&vector_state);
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();
    run_thread_inner_with_process(shim.as_ref(), &mut ctx, process, false);
}

#[derive(Default)]
struct ProcessState {
    /// Undrained timer signals survive any individual thread's exit.
    pending_signals: AtomicU32,
    /// Weak entries avoid a cycle with ThreadState::process.
    threads: Mutex<Vec<Weak<ThreadState>>>,
}

impl ProcessState {
    fn deliver_signal(&self, signal: litebox_common_linux::signal::Signal) {
        self.pending_signals
            .fetch_or(1u32 << (signal.as_i32() - 1), Ordering::Relaxed);
        let targets: Vec<_> = self
            .threads
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .map(ThreadHandle)
            .collect();
        // Wake all siblings outside the registry lock to tolerate exits.
        // New threads check pending signals before running or sleeping.
        for target in targets {
            target.interrupt();
        }
    }
}

struct ThreadState {
    // Cleared before thread exit to prevent pthread ID-reuse races.
    identity: Mutex<Option<usize>>,
    interrupted: AtomicBool,
    /// State shared by all host threads belonging to one guest process.
    process: Arc<ProcessState>,
    // Signal handlers use WAIT_WAKER_ADDR instead: they cannot lock this mutex.
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

    fn register(&self) {
        self.0
            .process
            .threads
            .lock()
            .unwrap()
            .push(Arc::downgrade(&self.0));
    }

    fn unregister(&self) {
        let entry = Arc::downgrade(&self.0);
        self.0
            .process
            .threads
            .lock()
            .unwrap()
            .retain(|active| !active.ptr_eq(&entry));
        *self.0.identity.lock().unwrap() = None;
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

impl<const PAGE_SIZE: usize> litebox::platform::ThreadProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;
    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>>,
    ) -> Result<(), Self::ThreadSpawnError> {
        if GUEST_CONFIGURATION.get().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "guest ABI must be configured before spawning guest threads",
            ));
        }
        let process = if read_tls(tls_offset::CURRENT_THREAD) == 0 {
            Arc::new(ProcessState::default())
        } else {
            ThreadHandle::current().0.process.clone()
        };
        let ctx = ctx.clone();
        let vector_state =
            litebox::platform::GuestVectorStateProvider::get_guest_vector_state(self);
        // TODO: report child TLS setup failures synchronously. pthread_setspecific
        // can still fail after spawn_thread has returned success, causing the child
        // to exit before running its initialization callback.
        let _handle = std::thread::Builder::new()
            .spawn(move || thread_start(init_thread, ctx, vector_state, process))?;
        Ok(())
    }
    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }
    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        initialize_thread_tls();
        assert_eq!(read_tls(tls_offset::CURRENT_THREAD), 0);
        with_signal_state(|pending, waker| {
            assert!(waker.load(Ordering::Relaxed).is_null());
            pending.store(0, Ordering::Relaxed);
        })
        .expect("initialized thread TLS");
        let handle = ThreadHandle(Arc::new(ThreadState {
            // SAFETY: pthread_self has no preconditions.
            identity: Mutex::new(Some(unsafe { libc::pthread_self() } as usize)),
            interrupted: AtomicBool::new(false),
            process: Arc::new(ProcessState::default()),
            waker: Mutex::new(None),
        }));
        write_tls(tls_offset::CURRENT_THREAD, (&raw const handle) as usize);
        handle.register();
        let cleanup_handle = handle.clone();
        let _cleanup = litebox::utils::defer(move || {
            cleanup_handle.unregister();
            write_tls(tls_offset::CURRENT_THREAD, 0);
        });
        f()
    }
}

impl<const PAGE_SIZE: usize> WaitWakerProvider for MacosUserlandWithPageSize<PAGE_SIZE> {
    fn update_waker(&self, waker: Option<core::task::Waker>) {
        if read_tls(tls_offset::CURRENT_THREAD) != 0 {
            ThreadHandle::current()
                .0
                .waker
                .lock()
                .unwrap()
                .clone_from(&waker);
        }
        with_signal_state(|_, slot| {
            let new = waker.map_or(core::ptr::null_mut(), |waker| {
                Box::into_raw(Box::new(waker))
            });
            // Same-thread handlers finish using the old pointer before we resume.
            let old = slot.swap(new, Ordering::AcqRel);
            if !old.is_null() {
                // SAFETY: every non-null value was produced by Box::into_raw above.
                unsafe { drop(Box::from_raw(old)) };
            }
        });
    }
}

/// Record a host signal and wake an interruptible shim wait.
///
/// # Safety
/// Requires initialized thread TLS and a signal-safe published waker.
unsafe fn record_pending_host_signal(signal: litebox_common_linux::signal::Signal) {
    // Signal delivery must not change the interrupted host operation's errno.
    // SAFETY: __error returns this thread's live errno slot.
    let errno = unsafe { libc::__error() };
    // SAFETY: errno points to a live c_int for this thread.
    let saved_errno = unsafe { errno.read() };
    let mask = 1u32 << (signal.as_i32() - 1);
    with_signal_state(|pending, slot| {
        pending.fetch_or(mask, Ordering::Relaxed);
        let waker = slot.load(Ordering::Acquire);
        if !waker.is_null() {
            // SAFETY: the handler interrupted this same thread, which cannot
            // replace or free its published waker until the handler returns.
            unsafe { (&*waker).wake_by_ref() };
        }
    })
    .expect("signal handler requires initialized thread TLS");
    // SAFETY: errno points to a live c_int for this thread.
    unsafe { errno.write(saved_errno) };
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

impl<const PAGE_SIZE: usize> litebox::platform::GuestVectorStateProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    type GuestVectorState = litebox_common_linux::GuestVectorState;
    fn get_guest_vector_state(&self) -> Self::GuestVectorState {
        get_guest_vector_state()
    }
    fn set_guest_vector_state(&self, state: &Self::GuestVectorState) {
        set_guest_vector_state(state);
    }
}
impl<const PAGE_SIZE: usize> litebox::platform::SystemInfoProvider
    for MacosUserlandWithPageSize<PAGE_SIZE>
{
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }
    fn guest_thread_pointer_offset(&self) -> Option<usize> {
        Some(guest_thread_pointer_tp_offset())
    }
    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

// Linux and Darwin gates share a 32-byte control-frame prefix. The fourth
// word is unused by the rewriter; Darwin adds 128 bytes to preserve its red zone.
const MACOS_SVC_FRAME_OFF_SCRATCH: u16 = 24;

const _: () = assert!(
    SVC_FRAME_OFF_X16 == 0
        && SVC_FRAME_OFF_RETADDR == 8
        && SVC_FRAME_OFF_STUB == 16
        && MACOS_SVC_FRAME_OFF_SCRATCH == 24
        && MACOS_SVC_FRAME_OFF_SCRATCH + 8 == SVC_FRAME_BYTES
);

// SVC gate callback: the macOS signal frame captures the full register state at this PC.
unsafe extern "C" {
    fn litebox_macos_syscall_callback_in_guest_cleared();
    fn switch_to_guest_via_sigreturn_start();
    fn switch_to_guest_via_sigreturn_end();
    fn switch_to_guest_direct_start();
    fn switch_to_guest_direct_end();
    fn switch_to_guest_via_outbound_stub_start();
    fn switch_to_guest_via_outbound_stub_end();
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_callback() {
    core::arch::naked_asm!(
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
        // Preserve guest x17 in the unused SVC-frame word before using it as scratch.
        "str x17, [sp, #{frame_scratch}]",
        "mrs x16, tpidrro_el0",
        "and x16, x16, #0xfffffffffffffff8",
        "adrp x17, {tls_key_offset}@PAGE",
        "ldr x17, [x17, {tls_key_offset}@PAGEOFF]",
        "add x16, x16, x17",
        "ldr x16, [x16]", // LiteBox TlsBlock pointer, or zero for host-only threads
        "cbz x16, 90f",
        "ldr x17, [x16, #{in_guest}]",
        "cbz x17, 90f",
        // A host signal handler returning into guest state must execute XNU's
        // sigreturn natively even though the restored context is guest-owned.
        "ldr x17, [sp, #{frame_x16}]",
        "sub x17, x17, #{sigreturn}",
        "cbnz x17, 91f",
        "ldr x17, [x16, #{native_sigreturn_pending}]",
        "cbz x17, 91f",
        "str xzr, [x16, #{native_sigreturn_pending}]",
        "mov x17, x16",
        "ldr x16, [sp, #{frame_x16}]",
        "svc #0x80",
        // A successful sigreturn never returns. Fail inside the transition
        // rather than treating its host registers as guest state.
        "str xzr, [x17, #{in_guest}]",
        "brk #0",
        "91:",
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
        "ldr x0, [sp, #{frame_x16}]",
        "ldr x1, [sp, #{frame_scratch}]",
        "stp x0, x1, [x17, #128]",
        // Preserve the gate-frame ABI before leaving the guest stack.
        "ldr x2, [x16, #{active}]", // ThreadContext
        "mov x3, sp",
        "str x3, [x2, #{thread_svc_frame}]",
        "str x0, [x2, #{thread_outbound_x16}]",
        "ldr x3, [sp, #{frame_retaddr}]",
        "str x3, [x2, #{thread_outbound_pc}]",
        "ldr x3, [sp, #{frame_stub}]",
        "str x3, [x2, #{thread_outbound_stub}]",
        "ldr x0, [x16, #{guest_x18}]",
        "str x0, [x17, #144]",
        "stp x19, x20, [x17, #152]",
        "stp x21, x22, [x17, #168]",
        "stp x23, x24, [x17, #184]",
        "stp x25, x26, [x17, #200]",
        "stp x27, x28, [x17, #216]",
        "stp x29, x30, [x17, #232]",
        "ldr x0, [x2, #{thread_guest_abi}]",
        "add x0, sp, x0",
        "str x0, [x17, #{regs_sp}]",
        "ldr x0, [sp, #{frame_retaddr}]",
        "str x0, [x17, #{regs_pc}]",
        "mrs x0, nzcv",
        "str x0, [x17, #{regs_pstate}]",
        "ldr x0, [x17, #0]",
        "str x0, [x17, #{regs_orig_x0}]",
        "str w8, [x17, #{regs_syscallno}]",
        // syscall_handler supplies the -ENOSYS entry value for Linux guests;
        // Darwin syscall dispatch reads the saved x0 argument.
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
        "b _litebox_macos_syscall_callback_in_guest_cleared",
        ".cfi_endproc",
        ".globl _litebox_macos_syscall_callback_in_guest_cleared",
        "_litebox_macos_syscall_callback_in_guest_cleared:",
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
        // This label is a separate Mach-O atom, so a linker veneer may have
        // clobbered x16/x17. Recompute the TLS base before dereferencing it.
        "mrs x16, tpidrro_el0",
        "and x16, x16, #0xfffffffffffffff8",
        "adrp x17, {tls_key_offset}@PAGE",
        "ldr x17, [x17, {tls_key_offset}@PAGEOFF]",
        "add x16, x16, x17",
        "ldr x16, [x16]", // LiteBox TlsBlock pointer
        "ldr x0, [x16, #{active}]", // ThreadContext
        "ldr x1, [x0, #{host_sp}]",
        "mov sp, x1",
        "add x29, sp, #16",
        "bl {syscall_handler}",
        "b {finish_thread_arch}",
        // A rewritten shared-cache stub may also be called by the runner.
        // Host execution has no active guest (or no LiteBox TLS entry). Restore
        // the gate-clobbered registers, issue the original syscall, and resume
        // after the patched SVC without entering Rust or the shim.
        "90:",
        "ldr x16, [sp, #{frame_x16}]",
        "ldr x17, [sp, #{frame_scratch}]",
        "svc #0x80",
        "ldr x16, [sp, #{frame_retaddr}]",
        "add sp, sp, #{darwin_frame_bytes}",
        "br x16",
        ".cfi_endproc",
        tls_key_offset = sym TLS_KEY_OFFSET,
        active = const tls_offset::ACTIVE,
        in_guest = const tls_offset::IN_GUEST,
        native_sigreturn_pending = const tls_offset::NATIVE_SIGRETURN_PENDING,
        sigreturn = const BSD_SYS_SIGRETURN,
        guest_x18 = const tls_offset::GUEST_X18,
        vector_state = const tls_offset::VECTOR_STATE,
        context = const core::mem::offset_of!(ThreadContext, ctx),
        host_sp = const core::mem::offset_of!(ThreadContext, host_sp),
        thread_svc_frame = const core::mem::offset_of!(ThreadContext, svc_frame),
        thread_outbound_x16 = const core::mem::offset_of!(ThreadContext, outbound_x16),
        thread_outbound_pc = const core::mem::offset_of!(ThreadContext, outbound_pc),
        thread_outbound_stub = const core::mem::offset_of!(ThreadContext, outbound_stub),
        regs_sp = const core::mem::offset_of!(PtRegs, sp),
        regs_pc = const core::mem::offset_of!(PtRegs, pc),
        regs_pstate = const core::mem::offset_of!(PtRegs, pstate),
        regs_orig_x0 = const core::mem::offset_of!(PtRegs, orig_x0),
        regs_syscallno = const core::mem::offset_of!(PtRegs, syscallno),
        vector_fpsr = const core::mem::offset_of!(GuestVectorState, fpsr),
        vector_fpcr = const core::mem::offset_of!(GuestVectorState, fpcr),
        host_fp_state = const tls_offset::HOST_FP_STATE,
        thread_guest_abi = const core::mem::offset_of!(ThreadContext, guest_abi),
        frame_x16 = const SVC_FRAME_OFF_X16,
        frame_retaddr = const SVC_FRAME_OFF_RETADDR,
        frame_stub = const SVC_FRAME_OFF_STUB,
        frame_scratch = const MACOS_SVC_FRAME_OFF_SCRATCH,
        darwin_frame_bytes = const litebox_syscall_rewriter::aarch64::DARWIN_SVC_FRAME_BYTES,
        syscall_handler = sym syscall_handler,
        finish_thread_arch = sym finish_thread_arch,
    );
}

// TODO: replace this synthetic signal return with a guest-side restoration
// stub that can resume an arbitrary context without relying on private XNU
// sigreturn-frame details.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_sigreturn() -> ! {
    core::arch::naked_asm!(
        "mrs x16, tpidrro_el0",
        "and x16, x16, #0xfffffffffffffff8",
        "adrp x17, {tls_key_offset}@PAGE",
        "ldr x17, [x17, {tls_key_offset}@PAGEOFF]",
        "add x16, x16, x17",
        "ldr x16, [x16]", // LiteBox TlsBlock pointer
        "mrs x17, fpsr",
        "mrs x9, fpcr",
        "stp w17, w9, [x16, #{host_fp_state}]",
        ".globl _switch_to_guest_via_sigreturn_start",
        ".alt_entry _switch_to_guest_via_sigreturn_start",
        "_switch_to_guest_via_sigreturn_start:",
        "mov x17, #1",
        "str x17, [x16, #{in_guest}]",
        "brk #0",
        ".globl _switch_to_guest_via_sigreturn_end",
        ".alt_entry _switch_to_guest_via_sigreturn_end",
        "_switch_to_guest_via_sigreturn_end:",
        // The signal handler redirects the first BRK. Trap again rather than
        // falling through if that invariant is ever violated.
        "brk #0",
        tls_key_offset = sym TLS_KEY_OFFSET,
        in_guest = const tls_offset::IN_GUEST,
        host_fp_state = const tls_offset::HOST_FP_STATE,
    );
}

/// Initial process entry. Unlike the generic sigreturn path, direct register
/// restoration preserves XNU's physical TPIDRRO_EL0 value. Host-cache gates use
/// it to locate LiteBox state, then expose either native host TLS or the private
/// guest pthread according to `in_guest`. Darwin does not define an initial x16
/// value, so x16 is used as the final branch register.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_direct(_: &mut ThreadContext) -> ! {
    core::arch::naked_asm!(
        "ldr x16, [x0, #{context}]",
        "mrs x17, tpidrro_el0",
        "and x17, x17, #0xfffffffffffffff8",
        "adrp x1, {tls_key_offset}@PAGE",
        "ldr x1, [x1, {tls_key_offset}@PAGEOFF]",
        "add x17, x17, x1",
        "ldr x17, [x17]",
        "mrs x1, fpsr",
        "mrs x2, fpcr",
        "stp w1, w2, [x17, #{host_fp_state}]",
        ".globl _switch_to_guest_direct_start",
        ".alt_entry _switch_to_guest_direct_start",
        "_switch_to_guest_direct_start:",
        "mov x1, #1",
        "str x1, [x17, #{in_guest}]",
        "ldr x1, [x0, #{interrupted}]",
        "ldarb w1, [x1]",
        "cbz w1, 1f",
        "str xzr, [x17, #{in_guest}]",
        "b _litebox_macos_interrupt_callback",
        "1:",
        "ldr x1, [x16, #{regs_x18}]",
        "str x1, [x17, #{guest_x18}]",
        "ldr x1, [x17, #{vector_state}]",
        "ldp q0, q1, [x1, #0]",
        "ldp q2, q3, [x1, #32]",
        "ldp q4, q5, [x1, #64]",
        "ldp q6, q7, [x1, #96]",
        "ldp q8, q9, [x1, #128]",
        "ldp q10, q11, [x1, #160]",
        "ldp q12, q13, [x1, #192]",
        "ldp q14, q15, [x1, #224]",
        "ldp q16, q17, [x1, #256]",
        "ldp q18, q19, [x1, #288]",
        "ldp q20, q21, [x1, #320]",
        "ldp q22, q23, [x1, #352]",
        "ldp q24, q25, [x1, #384]",
        "ldp q26, q27, [x1, #416]",
        "ldp q28, q29, [x1, #448]",
        "ldp q30, q31, [x1, #480]",
        "ldr w2, [x1, #{vector_fpsr}]",
        "msr fpsr, x2",
        "ldr w2, [x1, #{vector_fpcr}]",
        "msr fpcr, x2",
        "ldr x1, [x16, #{regs_pstate}]",
        "msr nzcv, x1",
        "ldr x9, [x16, #{regs_sp}]",
        "mov sp, x9",
        "ldp x0, x1, [x16, #0]",
        "ldp x2, x3, [x16, #16]",
        "ldp x4, x5, [x16, #32]",
        "ldp x6, x7, [x16, #48]",
        "ldp x8, x9, [x16, #64]",
        "ldp x10, x11, [x16, #80]",
        "ldp x12, x13, [x16, #96]",
        "ldp x14, x15, [x16, #112]",
        "ldr x17, [x16, #{regs_x17}]",
        "ldp x19, x20, [x16, #{regs_x19}]",
        "ldp x21, x22, [x16, #{regs_x21}]",
        "ldp x23, x24, [x16, #{regs_x23}]",
        "ldp x25, x26, [x16, #{regs_x25}]",
        "ldp x27, x28, [x16, #{regs_x27}]",
        "ldp x29, x30, [x16, #{regs_x29}]",
        "ldr x16, [x16, #{regs_pc}]",
        "br x16",
        ".globl _switch_to_guest_direct_end",
        ".alt_entry _switch_to_guest_direct_end",
        "_switch_to_guest_direct_end:",
        "brk #0",
        tls_key_offset = sym TLS_KEY_OFFSET,
        context = const core::mem::offset_of!(ThreadContext, ctx),
        in_guest = const tls_offset::IN_GUEST,
        guest_x18 = const tls_offset::GUEST_X18,
        vector_state = const tls_offset::VECTOR_STATE,
        host_fp_state = const tls_offset::HOST_FP_STATE,
        interrupted = const core::mem::offset_of!(ThreadContext, interrupted),
        regs_sp = const core::mem::offset_of!(PtRegs, sp),
        regs_pc = const core::mem::offset_of!(PtRegs, pc),
        regs_pstate = const core::mem::offset_of!(PtRegs, pstate),
        regs_x17 = const core::mem::offset_of!(PtRegs, regs) + 17 * size_of::<usize>(),
        regs_x18 = const core::mem::offset_of!(PtRegs, regs) + 18 * size_of::<usize>(),
        regs_x19 = const core::mem::offset_of!(PtRegs, regs) + 19 * size_of::<usize>(),
        regs_x21 = const core::mem::offset_of!(PtRegs, regs) + 21 * size_of::<usize>(),
        regs_x23 = const core::mem::offset_of!(PtRegs, regs) + 23 * size_of::<usize>(),
        regs_x25 = const core::mem::offset_of!(PtRegs, regs) + 25 * size_of::<usize>(),
        regs_x27 = const core::mem::offset_of!(PtRegs, regs) + 27 * size_of::<usize>(),
        regs_x29 = const core::mem::offset_of!(PtRegs, regs) + 29 * size_of::<usize>(),
        vector_fpsr = const core::mem::offset_of!(GuestVectorState, fpsr),
        vector_fpcr = const core::mem::offset_of!(GuestVectorState, fpcr),
    );
}

#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_outbound_stub(_: &mut ThreadContext) -> ! {
    core::arch::naked_asm!(
        // x0 is ThreadContext and remains available if an interrupt is pending.
        "ldr x16, [x0, #{context}]",
        "mrs x17, tpidrro_el0",
        "and x17, x17, #0xfffffffffffffff8",
        "adrp x1, {tls_key_offset}@PAGE",
        "ldr x1, [x1, {tls_key_offset}@PAGEOFF]",
        "add x17, x17, x1",
        "ldr x17, [x17]", // LiteBox TlsBlock pointer
        // Save host FP control state before installing the guest's.
        "mrs x1, fpsr",
        "mrs x2, fpcr",
        "stp w1, w2, [x17, #{host_fp_state}]",
        ".globl _switch_to_guest_via_outbound_stub_start",
        ".alt_entry _switch_to_guest_via_outbound_stub_start",
        "_switch_to_guest_via_outbound_stub_start:",
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
        // Restore SP to the captured SVC control frame. The outbound stub
        // restores guest x16 and releases the ABI-specific frame.
        "ldr x0, [x17, #{active}]",
        "ldr x0, [x0, #{thread_svc_frame}]",
        "mov sp, x0",
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
        "ldr x16, [sp, #{frame_stub}]",
        "br x16",
        "_switch_to_guest_via_outbound_stub_interrupted:",
        "str xzr, [x17, #{in_guest}]",
        ".globl _switch_to_guest_via_outbound_stub_end",
        ".alt_entry _switch_to_guest_via_outbound_stub_end",
        "_switch_to_guest_via_outbound_stub_end:",
        "b _litebox_macos_interrupt_callback",
        tls_key_offset = sym TLS_KEY_OFFSET,
        in_guest = const tls_offset::IN_GUEST,
        guest_x18 = const tls_offset::GUEST_X18,
        vector_state = const tls_offset::VECTOR_STATE,
        host_fp_state = const tls_offset::HOST_FP_STATE,
        context = const core::mem::offset_of!(ThreadContext, ctx),
        interrupted = const core::mem::offset_of!(ThreadContext, interrupted),
        active = const tls_offset::ACTIVE,
        thread_svc_frame = const core::mem::offset_of!(ThreadContext, svc_frame),
        regs_pstate = const core::mem::offset_of!(PtRegs, pstate),
        vector_fpsr = const core::mem::offset_of!(GuestVectorState, fpsr),
        vector_fpcr = const core::mem::offset_of!(GuestVectorState, fpcr),
        frame_stub = const SVC_FRAME_OFF_STUB,
    );
}

/// Run a guest thread using the process-wide syscall convention.
///
/// # Panics
/// Panics if [`set_guest_abi`] has not been called.
///
/// # Safety
/// The shim must retain valid guest mappings with code rewritten for a macOS
/// host and finalized gates matching the configured guest ABI.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut PtRegs)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(&shim, ctx);
}

fn run_thread_inner(shim: &dyn EnterShim<ExecutionContext = PtRegs>, ctx: &mut PtRegs) {
    run_thread_inner_with_process(shim, ctx, Arc::new(ProcessState::default()), true);
}

fn run_thread_inner_with_process(
    shim: &dyn EnterShim<ExecutionContext = PtRegs>,
    ctx: &mut PtRegs,
    process: Arc<ProcessState>,
    initial_darwin_process_entry: bool,
) {
    initialize_thread_tls();
    register_exception_handlers().expect("re-registering macOS exception handlers");
    assert!(
        read_tls(tls_offset::ACTIVE) == 0,
        "nested guest entry is not supported"
    );
    with_signal_state(|pending, waker| {
        assert!(waker.load(Ordering::Relaxed).is_null());
        pending.store(0, Ordering::Relaxed);
    })
    .expect("initialized thread TLS");
    let initial_guest_thread_state =
        if guest_abi() == GuestAbi::Darwin && darwin_private_thread_state_enabled() {
            Some(create_private_darwin_thread_state())
        } else {
            None
        };
    set_guest_thread_pointer(
        initial_guest_thread_state
            .as_ref()
            .map_or(0, |state| state.tpidrro),
    );
    set_guest_x18(
        initial_guest_thread_state
            .as_ref()
            .map_or(0, |state| state.x18),
    );
    let thread = ThreadHandle(Arc::new(ThreadState {
        // SAFETY: pthread_self has no preconditions; unregister before thread exit.
        identity: Mutex::new(Some(unsafe { libc::pthread_self() } as usize)),
        interrupted: AtomicBool::new(false),
        process,
        waker: Mutex::new(None),
    }));
    let mut thread_ctx = ThreadContext {
        guest_abi: guest_abi(),
        shim,
        ctx,
        host_sp: 0,
        svc_frame: 0,
        outbound_x16: 0,
        outbound_pc: 0,
        outbound_stub: 0,
        initial_entry: initial_darwin_process_entry,
        interrupted: &raw const thread.0.interrupted,
        thread,
        exit: GuestExit::Interrupt,
    };
    write_tls(tls_offset::NATIVE_SIGRETURN_PENDING, 0);
    write_tls(tls_offset::ACTIVE, (&raw mut thread_ctx) as usize);
    write_tls(
        tls_offset::CURRENT_THREAD,
        (&raw const thread_ctx.thread) as usize,
    );
    let thread_handle = thread_ctx.thread.clone();
    thread_handle.register();
    let _registration = litebox::utils::defer(move || {
        thread_handle.unregister();
        write_tls(tls_offset::ACTIVE, 0);
        write_tls(tls_offset::CURRENT_THREAD, 0);
        write_tls(tls_offset::IN_GUEST, 0);
        write_tls(tls_offset::NATIVE_SIGRETURN_PENDING, 0);
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
    let alt_stack_size = (libc::SIGSTKSZ * 2).next_multiple_of(HOST_PAGE_SIZE);
    let mapping_size = HOST_PAGE_SIZE + alt_stack_size;
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
    let retain_mapping = Cell::new(false);
    let _unmap_guard = litebox::utils::defer(|| {
        if !retain_mapping.get() {
            assert_eq!(
                // SAFETY: the previous altstack was restored before this owned mapping is freed.
                unsafe { libc::munmap(stack_base, mapping_size) },
                0,
            );
        }
    });
    assert_eq!(
        // SAFETY: the first page is exclusively owned and outside the usable signal stack.
        unsafe { libc::mprotect(stack_base, HOST_PAGE_SIZE, libc::PROT_NONE) },
        0,
    );
    let alternate = libc::stack_t {
        ss_sp: stack_base.wrapping_byte_add(HOST_PAGE_SIZE),
        ss_size: alt_stack_size,
        ss_flags: 0,
    };
    // SAFETY: stack_t consists of a nullable pointer and integers, all zero-valid.
    let mut previous = unsafe { std::mem::zeroed::<libc::stack_t>() };
    // SAFETY: the writable mapping stays live until the previous altstack is restored.
    let install_result = unsafe { libc::sigaltstack(&raw const alternate, &raw mut previous) };
    assert_eq!(
        install_result,
        0,
        "sigaltstack failed: {}",
        std::io::Error::last_os_error()
    );
    let tolerate_guest_altstack_change =
        guest_abi() == GuestAbi::Darwin && darwin_private_thread_state_enabled();
    let _restore_guard = litebox::utils::defer(|| {
        // SAFETY: previous was returned by sigaltstack for this thread and stays live.
        let result = unsafe { libc::sigaltstack(&raw const previous, core::ptr::null_mut()) };
        if result != 0 {
            // The kernel may still reference this mapping. Retain it even when
            // the failure is fatal; the process will reclaim it at exit.
            retain_mapping.set(true);
            if tolerate_guest_altstack_change {
                raw_signal_write(
                    b"warning: failed to restore host signal stack; retaining mapping\n",
                );
            } else {
                panic!("failed to restore the host signal stack");
            }
        }
    });
    f()
}

impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(&dyn EnterShim<ExecutionContext = PtRegs>, &mut PtRegs) -> ContinueOperation,
    ) {
        let mut operation = f(self.shim, self.ctx);
        if operation == ContinueOperation::Resume
            && self.thread.0.interrupted.swap(false, Ordering::AcqRel)
        {
            operation = self.shim.interrupt(self.ctx);
        }
        if operation == ContinueOperation::Resume {
            // SAFETY: the shim prepared the guest context; no owned guards cross the switch.
            unsafe { switch_to_guest(self) };
        }
    }
}

unsafe fn switch_to_guest(thread_ctx: &mut ThreadContext) -> ! {
    // Consume this before selecting a path: every later callback is an
    // arbitrary resume and must restore all registers, including x16.
    let initial_entry = core::mem::replace(&mut thread_ctx.initial_entry, false);
    if thread_ctx.outbound_stub != 0
        && thread_ctx.ctx.sp == thread_ctx.svc_frame + thread_ctx.guest_abi as usize
        && thread_ctx.ctx.pc == thread_ctx.outbound_pc
        && thread_ctx.ctx.regs[16] == thread_ctx.outbound_x16
    {
        let frame = [
            thread_ctx.outbound_x16,
            thread_ctx.outbound_pc,
            thread_ctx.outbound_stub,
        ];
        // Restage the frame immediately before use. If the guest stack became
        // inaccessible during the shim round trip, use generic sigreturn.
        // SAFETY: frame is readable. Faulting guest writes use the installed
        // exception-table handler and return failure instead of escaping to XNU.
        let frame_staged = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                thread_ctx.svc_frame as *mut u8,
                frame.as_ptr().cast(),
                core::mem::size_of_val(&frame),
            )
            .is_ok()
        };
        if frame_staged {
            // SAFETY: the captured frame still matches the guest context and
            // was restaged with an exception-table-protected write.
            unsafe { switch_to_guest_via_outbound_stub(thread_ctx) }
        }
    }
    if initial_entry && thread_ctx.guest_abi == GuestAbi::Darwin {
        // Initial Darwin process entry leaves x16 unspecified. Direct
        // restoration preserves the physical TPIDRRO_EL0 used by cache gates.
        unsafe { switch_to_guest_direct(thread_ctx) }
    }
    unsafe { switch_to_guest_via_sigreturn() }
}

extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    if thread_ctx.guest_abi == GuestAbi::Linux {
        thread_ctx.ctx.regs[0] =
            (litebox_common_linux::errno::Errno::ENOSYS.as_neg() as isize).cast_unsigned();
    }
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
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
    // This callback handles only signal-based exceptions and interrupts. Do
    // not let their resulting context accidentally reuse an older SVC frame.
    thread_ctx.outbound_stub = 0;
    let exit = thread_ctx.exit;
    if matches!(exit, GuestExit::Interrupt) {
        thread_ctx
            .thread
            .0
            .interrupted
            .store(false, Ordering::Release);
    }
    thread_ctx.call_shim(|shim, ctx| match exit {
        GuestExit::Exception(info) => shim.exception(ctx, &info),
        GuestExit::Interrupt => shim.interrupt(ctx),
    });
}

fn restore_host_fp_state() {
    let state = read_tls(tls_offset::HOST_FP_STATE);
    let status: u32 = state.trunc();
    let control: u32 = (state >> 32).trunc();
    // SAFETY: these are this thread's host control values, saved immediately
    // before entering guest execution.
    unsafe {
        core::arch::asm!(
            "msr fpsr, {status}",
            "msr fpcr, {control}",
            status = in(reg) u64::from(status),
            control = in(reg) u64::from(control),
            options(nomem, nostack, preserves_flags),
        );
    }
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

fn raw_signal_write(bytes: &[u8]) {
    let result: usize;
    // SAFETY: bytes is readable for x2 bytes; registers follow Darwin SYS_write,
    // and x1 is declared inlateout because XNU may overwrite it on return.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x0") libc::STDERR_FILENO as usize,
            inlateout("x1") bytes.as_ptr() => _,
            in("x2") bytes.len(),
            in("x16") 4usize,
            lateout("x0") result,
            options(nostack),
        );
    }
    let _ = result;
}

fn fatal_signal(message: &[u8], pc: usize) -> ! {
    const DIGITS: usize = size_of::<usize>() * 2;
    let mut address = [b'0'; DIGITS + 1];
    for (index, byte) in address[..DIGITS].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[(pc >> ((DIGITS - index - 1) * 4)) & 15];
    }
    address[DIGITS] = b'\n';
    raw_signal_write(message);
    raw_signal_write(b" pc=0x");
    raw_signal_write(&address);
    // SAFETY: SYS_exit accepts the status in x0 and never returns.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x0") (128 + libc::SIGABRT) as usize,
            in("x16") 1usize,
            options(noreturn),
        );
    }
}

struct SignalReturnGuard {
    restore_guest: bool,
}

impl SignalReturnGuard {
    fn new() -> Self {
        let restore_guest = read_tls(tls_offset::IN_GUEST) != 0;
        if restore_guest {
            write_tls(tls_offset::IN_GUEST, 0);
        }
        Self { restore_guest }
    }

    fn disarm(&mut self) {
        self.restore_guest = false;
    }
}

impl Drop for SignalReturnGuard {
    fn drop(&mut self) {
        if self.restore_guest {
            write_tls(
                tls_offset::NATIVE_SIGRETURN_PENDING,
                usize::from(rewritten_host_sigreturn_enabled()),
            );
            write_tls(tls_offset::IN_GUEST, 1);
        }
    }
}

fn resume_or_interrupt(mc: &mut libc::__darwin_mcontext64, thread_ctx: &mut ThreadContext) {
    if thread_ctx.thread.0.interrupted.load(Ordering::Acquire) {
        thread_ctx.exit = GuestExit::Interrupt;
        set_signal_return(mc, thread_ctx);
    } else {
        restore_signal_context(thread_ctx.ctx, mc);
        write_tls(
            tls_offset::NATIVE_SIGRETURN_PENDING,
            usize::from(rewritten_host_sigreturn_enabled()),
        );
        write_tls(tls_offset::IN_GUEST, 1);
    }
}

static EXCEPTION_HANDLERS_INSTALLED: Mutex<bool> = Mutex::new(false);

/// Mark host signal return as passing through rewritten shared-cache code.
pub fn enable_rewritten_host_sigreturn() {
    guest_configuration()
        .rewritten_host_sigreturn
        .store(true, Ordering::Release);
}

/// Disable platform handlers while libsystem_kernel is replaced in a forked child.
///
/// # Panics
/// Panics if the process-wide handler-state mutex is poisoned.
pub fn suspend_exception_handlers_for_cache_rewrite() -> std::io::Result<()> {
    let mut installed = EXCEPTION_HANDLERS_INSTALLED.lock().unwrap();
    *installed = false;
    // SAFETY: zero initializes SIG_DFL, an empty mask, and no flags.
    let action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    for signal in host_signals() {
        // SAFETY: action is a fully initialized SIG_DFL disposition; no old action is requested.
        if unsafe { libc::sigaction(signal, &raw const action, core::ptr::null_mut()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    drop(installed);
    Ok(())
}

pub(crate) fn register_exception_handlers() -> std::io::Result<()> {
    let mut installed = EXCEPTION_HANDLERS_INSTALLED.lock().unwrap();
    if *installed {
        return Ok(());
    }
    let mut selected_interrupt_signal = None;
    for candidate in [libc::SIGUSR1, libc::SIGUSR2] {
        // SAFETY: macOS sigaction contains integer fields; zero is a valid representation.
        let mut disposition = unsafe { std::mem::zeroed::<libc::sigaction>() };
        // SAFETY: disposition is writable and null requests a query.
        if unsafe { libc::sigaction(candidate, core::ptr::null(), &raw mut disposition) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if disposition.sa_sigaction == libc::SIG_DFL {
            selected_interrupt_signal = Some(candidate);
            break;
        }
    }
    let Some(selected_interrupt_signal) = selected_interrupt_signal else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no available interrupt signal",
        ));
    };
    SIGNAL_STATE
        .interrupt_signal
        .store(selected_interrupt_signal, Ordering::Relaxed);

    // SAFETY: macOS sigaction contains integer fields; zero is a valid representation.
    let mut previous = unsafe { std::mem::zeroed::<[libc::sigaction; HOST_SIGNAL_COUNT]>() };
    for (signal, previous) in host_signals().zip(&mut previous) {
        // SAFETY: previous is writable and null requests a query without installing a handler.
        if unsafe { libc::sigaction(signal, core::ptr::null(), previous) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let previous = SIGNAL_STATE.previous.get_or_init(|| previous);
    // SAFETY: zero is valid for every field; the handler, flags and mask are filled below.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = exception_signal_handler as *const () as usize;
    // SAFETY: action.sa_mask is writable storage for these sigset operations.
    unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        // Allow nested memory faults for fallible reads, but prevent forwarded
        // signals from re-entering this handler with IN_GUEST still set.
        libc::sigaddset(&raw mut action.sa_mask, interrupt_signal());
        for &(host_signal, _) in FORWARDED_SIGNALS {
            libc::sigaddset(&raw mut action.sa_mask, host_signal);
        }
        libc::sigaddset(&raw mut action.sa_mask, libc::SIGTRAP);
    }
    let restore = |count| {
        for (signal, previous) in host_signals().zip(previous.iter()).take(count) {
            // SAFETY: these immutable actions were returned by sigaction for the same signals.
            unsafe {
                libc::sigaction(signal, previous, core::ptr::null_mut());
            }
        }
    };
    for (index, signal) in host_signals().enumerate() {
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        if forwarded_guest_signal(signal).is_none() {
            action.sa_flags |= libc::SA_NODEFER;
        }
        // SAFETY: sigaction consists of zero-valid scalar fields.
        let mut replaced = unsafe { std::mem::zeroed::<libc::sigaction>() };
        // SAFETY: action is initialized, replaced is writable, and SA_SIGINFO matches the handler.
        let result = unsafe { libc::sigaction(signal, &raw const action, &raw mut replaced) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            restore(index);
            return Err(error);
        }
        if (signal == interrupt_signal() || forwarded_guest_signal(signal).is_some())
            && replaced.sa_sigaction != libc::SIG_DFL
        {
            // SAFETY: replaced was atomically returned while installing this signal's action.
            unsafe { libc::sigaction(signal, &raw const replaced, core::ptr::null_mut()) };
            restore(index);
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("signal {signal} already has a host handler"),
            ));
        }
    }
    *installed = true;
    Ok(())
}

fn exception_class(esr: u64) -> u8 {
    const EC_SHIFT: u32 = 26;
    const EC_MASK: u64 = 0x3f;
    ((esr >> EC_SHIFT) & EC_MASK).trunc()
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
    } else if signal == libc::SIGTRAP && exception_class(esr) == Exception::BRK64.0 {
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
    let mut signal_return = SignalReturnGuard::new();
    let pc: usize = mc.__ss.__pc.trunc();
    let esr = u64::from(mc.__es.__esr);
    // SAFETY: SA_SIGINFO supplies a live siginfo for this invocation.
    let code = unsafe { (*info).si_code };
    let memory_fault = is_synchronous_memory_fault(signal, code, esr);
    #[cfg(feature = "subpage_compat")]
    if memory_fault && subpage::recover_fault(pc, mc.__es.__far.trunc(), esr) {
        return;
    }
    if memory_fault && let Some(fixup) = litebox::mm::exception_table::search_exception_tables(pc) {
        mc.__ss.__pc = fixup as u64;
        return;
    }
    let ptr = read_tls(tls_offset::ACTIVE) as *mut ThreadContext<'static>;
    let breakpoint = signal == libc::SIGTRAP && exception_class(esr) == Exception::BRK64.0;
    let in_sigreturn_transition = (switch_to_guest_via_sigreturn_start as *const () as usize
        ..switch_to_guest_via_sigreturn_end as *const () as usize)
        .contains(&pc);
    let resuming = breakpoint && in_sigreturn_transition;
    let in_guest = signal_return.restore_guest;
    let in_syscall_callback_prologue = (syscall_callback as *const () as usize
        ..litebox_macos_syscall_callback_in_guest_cleared as *const () as usize)
        .contains(&pc);
    let in_direct_transition = (switch_to_guest_direct_start as *const () as usize
        ..switch_to_guest_direct_end as *const () as usize)
        .contains(&pc);
    let in_outbound_transition = (switch_to_guest_via_outbound_stub_start as *const () as usize
        ..switch_to_guest_via_outbound_stub_end as *const () as usize)
        .contains(&pc);
    let forwarded_signal = forwarded_guest_signal(signal);
    if let Some(guest_signal) = forwarded_signal
        && !ptr.is_null()
    {
        // SAFETY: ACTIVE implies initialized TLS; shim waits publish signal-safe wakers.
        unsafe { record_pending_host_signal(guest_signal) };
        // SAFETY: ACTIVE remains live for the duration of run_thread_arch.
        let thread_ctx = unsafe { &*ptr };
        thread_ctx
            .thread
            .0
            .interrupted
            .store(true, Ordering::Release);
    }
    if signal != interrupt_signal()
        && forwarded_signal.is_none()
        && matches!(code, SI_USER | SI_QUEUE)
    {
        // Application-originated fault signals are not a guest signal source. Restore
        // host FP control state before invoking arbitrary host signal code; XNU
        // restores the interrupted context if that handler returns.
        if !ptr.is_null()
            && (in_guest
                || in_syscall_callback_prologue
                || in_direct_transition
                || in_outbound_transition
                || in_sigreturn_transition)
        {
            restore_host_fp_state();
        }
        // SAFETY: the kernel-provided signal arguments remain live for forwarding.
        unsafe { next_signal_handler(signal, info, raw) };
        return;
    }
    if !ptr.is_null() && in_syscall_callback_prologue {
        if signal != interrupt_signal() && forwarded_signal.is_none() {
            // TODO: preserve transition diagnostics while forwarding this fault
            // to the previous host disposition instead of exiting directly.
            fatal_signal(b"fault in macOS syscall transition", pc);
        }
        // The interruption request is already recorded. Let the direct callback
        // finish saving a coherent guest context before dispatching it.
        return;
    }
    if !ptr.is_null() && (in_direct_transition || in_outbound_transition || in_sigreturn_transition)
    {
        if resuming {
            restore_host_fp_state();
            write_tls(tls_offset::IN_GUEST, 0);
            signal_return.disarm();
            // SAFETY: ACTIVE remains live while run_thread_arch is suspended.
            resume_or_interrupt(mc, unsafe { &mut *ptr });
            return;
        }
        if signal != interrupt_signal() && forwarded_signal.is_none() {
            // TODO: preserve transition diagnostics while forwarding this fault
            // to the previous host disposition instead of exiting directly.
            fatal_signal(b"fault in macOS guest-resume transition", pc);
        }
        restore_host_fp_state();
        write_tls(tls_offset::IN_GUEST, 0);
        // SAFETY: ACTIVE remains live while run_thread_arch is suspended.
        let thread_ctx = unsafe { &mut *ptr };
        thread_ctx.exit = GuestExit::Interrupt;
        signal_return.disarm();
        set_signal_return(mc, thread_ctx);
        return;
    }
    if ptr.is_null() || !in_guest {
        if (signal != interrupt_signal() && forwarded_signal.is_none())
            || (ptr.is_null() && forwarded_signal.is_some())
        {
            // Non-guest threads retain the host disposition.
            // SAFETY: the kernel-provided signal arguments remain live.
            unsafe { next_signal_handler(signal, info, raw) };
        }
        return;
    }
    restore_host_fp_state();
    write_tls(tls_offset::IN_GUEST, 0);
    // SAFETY: ACTIVE remains live while run_thread_arch is suspended; nested shim access is disabled.
    let thread_ctx = unsafe { &mut *ptr };

    copy_signal_context(thread_ctx.ctx, mc);
    let runtime = GateRuntimeState {
        guest_thread_pointer_addr: tls_address(tls_offset::GUEST_THREAD_POINTER) as usize,
        // Signal exits have an authoritative XNU context and do not
        // originate from the direct outbound-stub resume path.
        expected_outbound_stub: 0,
        expected_outbound_pc: 0,
    };
    let interruption = gate_interruption(signal, code, esr);
    let recovery = match thread_ctx.guest_abi {
        GuestAbi::Linux => canonicalize(
            thread_ctx.ctx,
            runtime,
            interruption,
            litebox_syscall_rewriter::TargetHost::MacOs,
            true,
            read_guest,
        ),
        GuestAbi::Darwin => litebox_common_linux::gate_recovery::canonicalize_darwin(
            thread_ctx.ctx,
            runtime,
            interruption,
            read_guest,
        ),
    };
    match recovery {
        Aarch64GateSignalResult::NotGate => {}
        Aarch64GateSignalResult::Canonicalized(ctx) => *thread_ctx.ctx = ctx,
        Aarch64GateSignalResult::ResumeGuest(ctx) => {
            *thread_ctx.ctx = ctx;
            signal_return.disarm();
            resume_or_interrupt(mc, thread_ctx);
            return;
        }
        Aarch64GateSignalResult::InvalidRuntimeState => {
            fatal_signal(b"invalid AArch64 gate runtime state", pc)
        }
        // With both expected outbound values zero, canonicalize cannot
        // classify a macOS signal context as an interrupted outbound stub.
        Aarch64GateSignalResult::PreserveSavedContext => {
            fatal_signal(b"unreachable macOS outbound-stub recovery", pc)
        }
    }
    thread_ctx.exit = if signal == interrupt_signal() || forwarded_signal.is_some() {
        GuestExit::Interrupt
    } else {
        let exception = match signal {
            libc::SIGILL => Exception::INSTRUCTION_ABORT_LOWER_EL,
            libc::SIGTRAP => Exception::BRK64,
            _ if is_synchronous_memory_fault(signal, code, esr)
                && matches!(
                    Exception(exception_class(esr)),
                    Exception::INSTRUCTION_ABORT_LOWER_EL | Exception::INSTRUCTION_ABORT_CURRENT_EL
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
    signal_return.disarm();
    set_signal_return(mc, thread_ctx);
}

unsafe fn next_signal_handler(signal: i32, info: *mut libc::siginfo_t, raw: *mut libc::c_void) {
    let Some(previous) = host_signals()
        .position(|s| s == signal)
        .and_then(|index| SIGNAL_STATE.previous.get()?.get(index))
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
        // Direct entry from the FDE-less outbound stub. x0 still carries
        // ThreadContext; reload the canonical host sp and x29 below.
        ".globl _litebox_macos_interrupt_callback",
        "_litebox_macos_interrupt_callback:",
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
        "ldr x1, [x0, #{host_sp}]",
        "mov sp, x1",
        "add x29, sp, #16",
        "bl {direct_interrupt_handler}",
        "b {finish_thread_arch}",
        ".cfi_endproc",
        host_sp = const core::mem::offset_of!(ThreadContext, host_sp),
        init_handler = sym init_handler,
        exit_handler = sym exit_handler,
        direct_interrupt_handler = sym direct_interrupt_handler,
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
    use litebox::platform::{
        PageManagementProvider as _, RawMutPointer as _, SignalProvider as _,
        SystemInfoProvider as _, ThreadProvider as _, TimerHandle as _, TimerProvider as _,
    };
    const RW: MemoryRegionPermissions =
        MemoryRegionPermissions::READ.union(MemoryRegionPermissions::WRITE);

    #[test]
    fn native_page_size_rejects_subpage_operations() {
        let platform = MacosUserland::new();
        assert_eq!(HOST_PAGE_SIZE, 16384);
        let base = platform
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 2 * HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap()
            .as_usize();
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: this test owns the range and never executes it.
            unsafe {
                platform
                    .deallocate_pages(base..base + 2 * HOST_PAGE_SIZE)
                    .unwrap();
            }
        });
        // Reject both a subpage length and a subpage-aligned start. These
        // assertions also run with subpage_compat enabled through another crate.
        for range in [base..base + 4096, base + 4096..base + HOST_PAGE_SIZE] {
            assert!(matches!(
                platform.allocate_pages(
                    range.clone(),
                    RW,
                    false,
                    true,
                    FixedAddressBehavior::Replace,
                ),
                Err(AllocationError::Unaligned)
            ));
            // SAFETY: these invalid ranges are within our idle mapping.
            unsafe {
                assert!(matches!(
                    platform.update_permissions(range.clone(), MemoryRegionPermissions::READ),
                    Err(PermissionUpdateError::Unaligned)
                ));
                assert!(matches!(
                    platform.deallocate_pages(range.clone()),
                    Err(DeallocationError::Unaligned)
                ));
                assert!(matches!(
                    platform.remap_pages(
                        range,
                        base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE,
                        RW
                    ),
                    Err(RemapError::Unaligned)
                ));
            }
        }
    }

    #[test]
    #[cfg(feature = "subpage_compat")]
    fn native_and_subpage_instances_keep_distinct_permissions() {
        let native = MacosUserland::new();
        let compat = MacosUserland4K::new();
        let native_memory = native
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let compat_memory = compat
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 8192,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let base = native_memory.as_usize();
        let subpage_base = compat_memory.as_usize();
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: both ranges belong to this test and have no active users.
            unsafe {
                native
                    .deallocate_pages(base..base + HOST_PAGE_SIZE)
                    .unwrap();
                compat
                    .deallocate_pages(subpage_base..subpage_base + 8192)
                    .unwrap();
            }
        });
        // A permitted access is recoverable only for a compatibility mapping.
        let write_permission_fault = (0x24 << 26) | (1 << 6) | 0x0f;
        assert!(!subpage::recover_fault(0, base, write_permission_fault));
        assert!(subpage::recover_fault(
            0,
            subpage_base,
            write_permission_fault
        ));
        // SAFETY: this test owns both idle ranges.
        unsafe {
            native
                .update_permissions(base..base + HOST_PAGE_SIZE, MemoryRegionPermissions::READ)
                .unwrap();
            compat
                .update_permissions(
                    subpage_base..subpage_base + 4096,
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
        }
        // Only the 4 KiB instance inherits WRITE from its neighboring subpage.
        assert_eq!(native_memory.write_at_offset(0, 42), None);
        assert_eq!(compat_memory.write_at_offset(0, 42), Some(()));
    }

    /// Run host-only test code with the same registration as a guest sibling.
    fn run_process_test_thread(process: Arc<ProcessState>, f: impl FnOnce()) {
        struct InitOnly<F>(std::cell::RefCell<Option<F>>);
        impl<F: FnOnce()> EnterShim for InitOnly<F> {
            type ExecutionContext = PtRegs;

            fn init(&self, _: &mut PtRegs) -> ContinueOperation {
                self.0.borrow_mut().take().unwrap()();
                ContinueOperation::Terminate
            }
            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }
            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }
        set_guest_abi(GuestAbi::Linux);
        run_thread_inner_with_process(
            &InitOnly(std::cell::RefCell::new(Some(f))),
            &mut PtRegs::default(),
            process,
            false,
        );
    }

    #[test]
    fn timer_notification_survives_targets_exiting_during_delivery() {
        use litebox_common_linux::signal::Signal;
        use std::sync::mpsc;

        // Pause the worker after it snapshots the thread list. This waker is
        // installed only in ThreadState, never in the signal-handler TLS slot.
        struct PauseDelivery {
            reached: mpsc::SyncSender<()>,
            resume: Mutex<mpsc::Receiver<()>>,
        }
        impl std::task::Wake for PauseDelivery {
            fn wake(self: Arc<Self>) {
                self.reached.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }

        let platform = MacosUserland::new();
        let process = Arc::new(ProcessState::default());
        let (reached_tx, reached_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let pause = core::task::Waker::from(Arc::new(PauseDelivery {
            reached: reached_tx,
            resume: Mutex::new(resume_rx),
        }));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (exit_first_tx, exit_first_rx) = mpsc::channel();
        let (exit_second_tx, exit_second_rx) = mpsc::channel();
        let first_process = process.clone();
        let first_ready = ready_tx.clone();
        let first = std::thread::spawn(move || {
            run_process_test_thread(first_process, || {
                *ThreadHandle::current().0.waker.lock().unwrap() = Some(pause);
                first_ready.send(()).unwrap();
                exit_first_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second_process = process.clone();
        let second = std::thread::spawn(move || {
            run_process_test_thread(second_process, || {
                ready_tx.send(()).unwrap();
                exit_second_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        run_process_test_thread(process.clone(), || {
            let timer = platform.create_timer(Signal::SIGALRM).unwrap();
            timer.set_timer(Duration::from_millis(1));
            reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // First exits without draining. Second's cloned identity is cleared
            // before the worker reaches it. Neither may discard the alarm.
            exit_first_tx.send(()).unwrap();
            exit_second_tx.send(()).unwrap();
            first.join().unwrap();
            second.join().unwrap();
            resume_tx.send(()).unwrap();
            // Joining the worker completes delivery to this surviving sibling.
            drop(timer);
            assert!(
                ThreadHandle::current()
                    .0
                    .interrupted
                    .load(Ordering::Acquire)
            );
            let mut signals = Vec::new();
            platform.take_pending_signals(|signal| signals.push(signal));
            assert_eq!(signals, [Signal::SIGALRM]);
        });
        run_process_test_thread(process, || {
            platform.take_pending_signals(|_| panic!("timer was delivered more than once"));
        });
    }

    #[test]
    fn reserved_pages_snapshot_contains_host_mappings() {
        let heap_value = Box::new(0_u8);
        let stack_value = 0_u8;
        let platform = MacosUserland::new();
        let reserved_pages: Vec<_> = <MacosUserland as litebox::platform::PageManagementProvider<
            HOST_PAGE_SIZE,
        >>::reserved_pages(platform)
        .collect();

        assert!(!reserved_pages.is_empty());
        let mut previous_end = 0;
        for range in &reserved_pages {
            assert!(range.start >= previous_end);
            assert!(range.end > range.start);
            assert!(range.start.is_multiple_of(HOST_PAGE_SIZE));
            assert!(range.end.is_multiple_of(HOST_PAGE_SIZE));
            previous_end = range.end;
        }
        for address in [
            reserved_pages_snapshot_contains_host_mappings as *const () as usize,
            std::ptr::from_ref(&stack_value) as usize,
            std::ptr::from_ref(heap_value.as_ref()) as usize,
        ] {
            assert!(
                reserved_pages.iter().any(|range| range.contains(&address)),
                "host address {address:#x} is absent from the snapshot"
            );
        }
    }

    #[test]
    fn host_thread_without_tls_still_receives_event_wakeups() {
        let platform = MacosUserland::new();
        let ready = Arc::new(AtomicBool::new(false));
        let worker_ready = ready.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            assert_eq!(tls_block_address(), 0);
            platform.take_pending_signals(|_| panic!("host thread has no guest signals"));
            let counter = Arc::new(SignalWakeCounter::default());
            let weak = Arc::downgrade(&counter);
            platform.update_waker(Some(core::task::Waker::from(counter)));
            assert!(
                weak.upgrade().is_none(),
                "host thread retained a signal waker"
            );
            let wait = litebox::event::wait::WaitState::new(platform);
            let mut notify = Some(send);
            let result = wait
                .context()
                .with_timeout(Duration::from_secs(5))
                .wait_until(|| {
                    if let Some(send) = notify.take() {
                        send.send(wait.context().waker().clone()).unwrap();
                    }
                    worker_ready.load(Ordering::Acquire)
                });
            result.expect("ordinary event wake must work without platform TLS");
            assert_eq!(tls_block_address(), 0);
        });
        let waker = receive.recv_timeout(Duration::from_secs(5)).unwrap();
        ready.store(true, Ordering::Release);
        waker.wake();
        worker.join().unwrap();
    }

    #[derive(Default)]
    struct SignalWakeCounter(AtomicUsize);

    impl std::task::Wake for SignalWakeCounter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn signal_waker_replacement_and_clear_release_ownership() {
        let platform = MacosUserland::new();
        MacosUserland::run_test_thread(|| {
            let first = Arc::new(SignalWakeCounter::default());
            let second = Arc::new(SignalWakeCounter::default());
            let first_weak = Arc::downgrade(&first);
            let second_weak = Arc::downgrade(&second);
            platform.update_waker(Some(core::task::Waker::from(first.clone())));
            // SAFETY: TLS is initialized and SignalWakeCounter is signal-safe.
            unsafe { record_pending_host_signal(litebox_common_linux::signal::Signal::SIGINT) };
            assert_eq!(first.0.load(Ordering::Relaxed), 1);
            platform.update_waker(Some(core::task::Waker::from(second.clone())));
            unsafe { record_pending_host_signal(litebox_common_linux::signal::Signal::SIGINT) };
            assert_eq!(first.0.load(Ordering::Relaxed), 1);
            assert_eq!(second.0.load(Ordering::Relaxed), 1);
            drop(first);
            assert!(first_weak.upgrade().is_none(), "replaced waker leaked");
            platform.update_waker(None);
            unsafe { record_pending_host_signal(litebox_common_linux::signal::Signal::SIGINT) };
            assert_eq!(second.0.load(Ordering::Relaxed), 1);
            drop(second);
            assert!(second_weak.upgrade().is_none(), "cleared waker leaked");
            platform.take_pending_signals(|_| {});
        });
    }

    #[test]
    fn recording_host_signal_preserves_errno_across_wake() {
        struct ErrnoWaker;
        impl std::task::Wake for ErrnoWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                // SAFETY: __error returns this thread's live errno slot.
                unsafe { *libc::__error() = libc::ENOENT };
            }
        }

        let platform = MacosUserland::new();
        MacosUserland::run_test_thread(|| {
            platform.update_waker(Some(core::task::Waker::from(Arc::new(ErrnoWaker))));
            // SAFETY: __error returns this thread's live errno slot.
            unsafe { *libc::__error() = libc::ETIMEDOUT };
            // SAFETY: run_test_thread initializes this thread's platform TLS.
            unsafe { record_pending_host_signal(litebox_common_linux::signal::Signal::SIGINT) };
            // SAFETY: __error returns this thread's live errno slot.
            assert_eq!(unsafe { *libc::__error() }, libc::ETIMEDOUT);
            platform.update_waker(None);
            platform.take_pending_signals(|_| {});
        });
    }

    #[test]
    fn host_signal_interrupts_wait_until() {
        struct WaitProbe(&'static MacosUserland);
        struct PendingSignal(&'static MacosUserland);

        impl litebox::event::wait::CheckForInterrupt for PendingSignal {
            fn check_for_interrupt(&self) -> bool {
                let mut pending = false;
                self.0.take_pending_signals(|_| pending = true);
                pending
            }
        }

        impl EnterShim for WaitProbe {
            type ExecutionContext = PtRegs;

            fn init(&self, _: &mut PtRegs) -> ContinueOperation {
                let wait = litebox::event::wait::WaitState::new(self.0);
                let check = PendingSignal(self.0);
                let target = unsafe { libc::pthread_self() } as usize;
                let (send, receive) = std::sync::mpsc::sync_channel(0);
                let sender = std::thread::spawn(move || {
                    receive.recv().unwrap();
                    assert_eq!(
                        unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGINT) },
                        0
                    );
                });
                let mut notify = Some(send);
                let result = wait
                    .context()
                    .with_check_for_interrupt(&check)
                    .with_timeout(Duration::from_secs(5))
                    .wait_until(|| {
                        if let Some(send) = notify.take() {
                            send.send(()).unwrap();
                        }
                        false
                    });
                sender.join().unwrap();
                assert!(
                    matches!(result, Err(litebox::event::wait::WaitError::Interrupted)),
                    "{result:?}"
                );
                ContinueOperation::Terminate
            }

            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }

        set_guest_abi(GuestAbi::Linux);
        let platform = MacosUserland::new();
        // SAFETY: init terminates before guest entry.
        unsafe { run_thread(WaitProbe(platform), &mut PtRegs::default()) };
    }

    #[test]
    fn asynchronous_signals_race_with_waker_replacement_and_drain() {
        struct SignalRace(&'static MacosUserland);

        impl EnterShim for SignalRace {
            type ExecutionContext = PtRegs;

            fn init(&self, _: &mut PtRegs) -> ContinueOperation {
                const ITERATIONS: usize = 2_000;
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let target = unsafe { libc::pthread_self() } as usize;
                let requested = Arc::new(AtomicUsize::new(0));
                let completed = Arc::new(AtomicUsize::new(0));
                let request = requested.clone();
                let complete = completed.clone();
                let sender = std::thread::spawn(move || {
                    for i in 1..=ITERATIONS {
                        while request.load(Ordering::Acquire) < i {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "signal request stalled"
                            );
                            std::thread::yield_now();
                        }
                        // SAFETY: the target thread stays live until join.
                        assert_eq!(
                            unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGINT) },
                            0
                        );
                        complete.store(i, Ordering::Release);
                    }
                });
                let counter = Arc::new(SignalWakeCounter::default());
                let mut observed = 0;
                for i in 1..=ITERATIONS {
                    self.0
                        .update_waker(Some(core::task::Waker::from(counter.clone())));
                    requested.store(i, Ordering::Release);
                    // One signal in flight prevents coalescing from hiding a lost update.
                    while completed.load(Ordering::Acquire) < i || observed < i {
                        assert!(std::time::Instant::now() < deadline, "signal {i} was lost");
                        self.0.update_waker(None);
                        self.0.take_pending_signals(|signal| {
                            assert_eq!(signal, litebox_common_linux::signal::Signal::SIGINT);
                            observed += 1;
                        });
                        self.0
                            .update_waker(Some(core::task::Waker::from(counter.clone())));
                        std::thread::yield_now();
                    }
                }
                sender.join().unwrap();
                assert_eq!(observed, ITERATIONS, "a pending signal was lost");
                assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
                self.0.take_pending_signals(|_| {});
                assert!(counter.0.load(Ordering::Relaxed) > 0);
                self.0.update_waker(None);
                assert_eq!(Arc::strong_count(&counter), 1);
                let wakes = counter.0.load(Ordering::Relaxed);
                assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
                assert_eq!(counter.0.load(Ordering::Relaxed), wakes);
                self.0.take_pending_signals(|_| {});
                ContinueOperation::Terminate
            }

            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }

        set_guest_abi(GuestAbi::Linux);
        let platform = MacosUserland::new();
        // SAFETY: init terminates without entering guest code.
        unsafe { run_thread(SignalRace(platform), &mut PtRegs::default()) };
    }

    #[test]
    fn non_guest_thread_uses_host_signal_disposition() {
        const CHILD_ENV: &str = "LITEBOX_MACOS_NON_GUEST_SIGNAL_TEST";
        if std::env::var_os(CHILD_ENV).is_none() {
            use std::os::unix::process::ExitStatusExt as _;

            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::non_guest_thread_uses_host_signal_disposition",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert_eq!(output.status.signal(), Some(libc::SIGINT), "{output:?}");
            return;
        }

        MacosUserland::new();
        // Bound a failure to restore the default SIGINT disposition.
        unsafe { libc::alarm(5) };
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        panic!("SIGINT returned on a non-guest thread");
    }

    #[test]
    fn host_signals_interrupt_and_reach_the_shim() {
        struct SignalProbe(&'static MacosUserland);

        impl EnterShim for SignalProbe {
            type ExecutionContext = PtRegs;

            fn init(&self, _: &mut PtRegs) -> ContinueOperation {
                assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
                assert_eq!(unsafe { libc::raise(libc::SIGALRM) }, 0);
                assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
                ContinueOperation::Resume
            }

            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                use litebox_common_linux::signal::Signal;

                let mut signals = Vec::new();
                self.0.take_pending_signals(|signal| {
                    signals.push(signal);
                    if signal == Signal::SIGINT {
                        // A signal arriving during drain must survive until the next poll.
                        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
                    }
                });
                assert_eq!(signals, [Signal::SIGINT, Signal::SIGALRM]);
                signals.clear();
                self.0.take_pending_signals(|signal| signals.push(signal));
                assert_eq!(signals, [Signal::SIGINT]);
                self.0
                    .take_pending_signals(|_| panic!("signals were not drained"));
                ContinueOperation::Terminate
            }
        }

        set_guest_abi(GuestAbi::Linux);
        let platform = MacosUserland::new();
        // SAFETY: queued signals dispatch interrupt, which terminates before guest entry.
        unsafe { run_thread(SignalProbe(platform), &mut PtRegs::default()) };
    }

    #[test]
    fn transition_ranges_have_stable_sizes() {
        let syscall_prologue = syscall_callback as *const () as usize
            ..litebox_macos_syscall_callback_in_guest_cleared as *const () as usize;
        let sigreturn = switch_to_guest_via_sigreturn_start as *const () as usize
            ..switch_to_guest_via_sigreturn_end as *const () as usize;
        let direct = switch_to_guest_direct_start as *const () as usize
            ..switch_to_guest_direct_end as *const () as usize;
        let outbound = switch_to_guest_via_outbound_stub_start as *const () as usize
            ..switch_to_guest_via_outbound_stub_end as *const () as usize;
        assert_eq!(syscall_prologue.len(), 86 * size_of::<u32>());
        assert_eq!(sigreturn.len(), 3 * size_of::<u32>());
        assert_eq!(direct.len(), 51 * size_of::<u32>());
        assert_eq!(outbound.len(), 52 * size_of::<u32>());
    }

    #[test]
    fn ptregs_layout_matches_transition_assembly() {
        assert_eq!(core::mem::size_of::<PtRegs>(), 288);
        assert_eq!(core::mem::align_of::<PtRegs>(), 16);
        assert_eq!(core::mem::offset_of!(PtRegs, regs) + 16 * 8, 128);
        assert_eq!(core::mem::offset_of!(PtRegs, sp), 248);
        assert_eq!(core::mem::offset_of!(PtRegs, pc), 256);
        assert_eq!(core::mem::offset_of!(PtRegs, pstate), 264);
        assert_eq!(core::mem::offset_of!(PtRegs, orig_x0), 272);
        assert_eq!(core::mem::offset_of!(PtRegs, syscallno), 280);
    }

    #[test]
    fn unwind_through_run_thread_arch() {
        struct PanickingShim;

        impl EnterShim for PanickingShim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                panic!("unwind out of init_handler");
            }

            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }

        set_guest_abi(GuestAbi::Linux);
        MacosUserland::new();
        let result = std::panic::catch_unwind(|| {
            let mut ctx = PtRegs::default();
            // SAFETY: init panics before the context is used for guest entry.
            unsafe { run_thread(PanickingShim, &mut ctx) };
        });
        assert!(result.is_err(), "the panic must propagate to the caller");
    }

    #[test]
    fn child_inherits_vector_state_and_dispatches_on_host_stack() {
        use litebox::shim::InitThread;
        use litebox_syscall_rewriter::{
            RewriteOptions, TargetHost, patch_code_segment_with_options,
        };

        #[derive(Debug, PartialEq)]
        enum Event {
            VectorStateInherited(bool),
            EnteredOnHostStack(bool),
            SyscallOnHostStackWithVectorState(bool),
            Done,
        }
        struct VectorStateProbe {
            entry: usize,
            stack: usize,
            vector_state: GuestVectorState,
            send: std::sync::mpsc::Sender<Event>,
        }
        fn altstack_is_installed_and_inactive() -> bool {
            // SAFETY: stack_t is zero-valid writable output for this thread's query.
            let mut stack = unsafe { core::mem::zeroed::<libc::stack_t>() };
            // SAFETY: null requests a query; stack remains writable for the call.
            let result = unsafe { libc::sigaltstack(core::ptr::null(), &raw mut stack) };
            result == 0 && stack.ss_flags & (libc::SS_ONSTACK | libc::SS_DISABLE) == 0
        }
        impl InitThread for VectorStateProbe {
            type ExecutionContext = PtRegs;
            fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = PtRegs>> {
                self.send
                    .send(Event::VectorStateInherited(
                        get_guest_vector_state() == self.vector_state,
                    ))
                    .unwrap();
                self
            }
        }
        impl EnterShim for VectorStateProbe {
            type ExecutionContext = PtRegs;
            fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
                self.send
                    .send(Event::EnteredOnHostStack(
                        altstack_is_installed_and_inactive(),
                    ))
                    .unwrap();
                ctx.pc = self.entry;
                ctx.sp = self.stack;
                ctx.regs[8] = 172; // getpid
                ContinueOperation::Resume
            }
            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                self.send
                    .send(Event::SyscallOnHostStackWithVectorState(
                        altstack_is_installed_and_inactive()
                            && get_guest_vector_state() == self.vector_state,
                    ))
                    .unwrap();
                ContinueOperation::Terminate
            }
            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                ContinueOperation::Terminate
            }
            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }
        }
        impl Drop for VectorStateProbe {
            fn drop(&mut self) {
                let _ = self.send.send(Event::Done);
            }
        }

        set_guest_abi(GuestAbi::Linux);
        let platform = MacosUserland::new();
        let memory = platform
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 3 * HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let base = memory.as_usize();
        let mut code = 0xd4000001u32.to_le_bytes();
        let (trampoline, trapped) = patch_code_segment_with_options(
            &mut code,
            base as u64,
            (base + HOST_PAGE_SIZE / 2) as u64,
            platform.get_syscall_entry_point() as u64,
            RewriteOptions::new(TargetHost::MacOs, true),
        )
        .unwrap();
        assert!(trapped.is_empty());
        assert_eq!(memory.write_slice_at_offset(0, &code), Some(()));
        assert_eq!(
            memory.write_slice_at_offset((HOST_PAGE_SIZE / 2).cast_signed(), &trampoline),
            Some(())
        );
        // SAFETY: code is initialized and has no active readers before publication.
        unsafe {
            platform
                .update_permissions(
                    base..base + HOST_PAGE_SIZE,
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                )
                .unwrap();
        }
        let original_vector_state = get_guest_vector_state();
        let _restore = litebox::utils::defer(|| set_guest_vector_state(&original_vector_state));
        let mut vector_state = GuestVectorState::default();
        vector_state.registers[0] = 0x1234;
        vector_state.registers[31] = 0x5678;
        set_guest_vector_state(&vector_state);
        let (send, receive) = std::sync::mpsc::channel();
        // SAFETY: the test retains the child's rewritten code and stack until
        // VectorStateProbe is dropped.
        unsafe {
            platform
                .spawn_thread(
                    &PtRegs::default(),
                    Box::new(VectorStateProbe {
                        entry: base,
                        stack: base + 3 * HOST_PAGE_SIZE,
                        vector_state,
                        send,
                    }),
                )
                .unwrap();
        }
        let observed: Vec<_> = (0..4)
            .map(|_| receive.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        assert_eq!(
            observed,
            [
                Event::VectorStateInherited(true),
                Event::EnteredOnHostStack(true),
                Event::SyscallOnHostStackWithVectorState(true),
                Event::Done
            ]
        );
        // SAFETY: VectorStateProbe has stopped, so the guest mappings are idle.
        unsafe {
            platform
                .deallocate_pages(base..base + 3 * HOST_PAGE_SIZE)
                .unwrap();
        }
    }

    #[test]
    fn pstate_capture_and_restore_preserve_only_user_bits() {
        use litebox_common_linux::arch::{
            PSR_DIT_BIT, PSR_NZCV_MASK, PSR_SSBS_BIT, SAFE_USER_PSTATE,
        };

        MacosUserland::new();
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
    fn private_darwin_thread_state_does_not_alias_the_runner() {
        let runner_tpidrro = anchor();
        // SAFETY: __error returns the current host pthread's live errno slot.
        let runner_errno = unsafe { libc::__error() } as usize;
        let private = create_private_darwin_thread_state();
        assert_ne!(private.tpidrro, runner_tpidrro);
        assert_ne!(private.errno, runner_errno);
    }

    #[test]
    fn initialization_preserves_tls_across_instances() {
        let first = MacosUserland::new();
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
        let second = MacosUserland::new();
        assert!(!core::ptr::eq(first, second));
        assert_eq!(
            (
                get_guest_thread_pointer(),
                get_guest_x18(),
                read_tls(tls_offset::IN_GUEST),
            ),
            (0x1234, 0x5678, 1)
        );
        initialize_thread_tls();
        assert_eq!(
            (
                get_guest_thread_pointer(),
                get_guest_x18(),
                read_tls(tls_offset::IN_GUEST),
            ),
            (0x1234, 0x5678, 1)
        );
        std::thread::spawn(MacosUserland::new).join().unwrap();
    }

    #[test]
    fn executable_protection_after_prot_none() {
        let p = MacosUserland::new();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let range = ptr.as_usize()..ptr.as_usize() + HOST_PAGE_SIZE;
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
        let p = MacosUserland::new();
        let source = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let source_range = source.as_usize()..source.as_usize() + HOST_PAGE_SIZE;
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
                TASK_ADDR_MIN..TASK_ADDR_MIN + 2 * HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let target_range = target.as_usize()..target.as_usize() + 2 * HOST_PAGE_SIZE;
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
        let p = MacosUserland::new();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let range = ptr.as_usize()..ptr.as_usize() + HOST_PAGE_SIZE;
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
                    HOST_PAGE_SIZE as u64,
                    MachBoolean::TRUE,
                    MachVmProtection::READ
                ),
                KernReturn::SUCCESS
            );
            assert!(matches!(
                p.update_permissions(range.clone(), RW),
                Err(PermissionUpdateError::PermissionDenied)
            ));
        }
    }

    #[test]
    fn native_pages_preserve_neighbors_and_reject_collisions() {
        // Native-page boundaries still provide exact hardware protection.
        let p = MacosUserland::new();
        let ptr = p
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + 2 * HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let base = ptr.as_usize();
        assert_eq!(base % HOST_PAGE_SIZE, 0);
        assert_eq!(ptr.read_at_offset(0), Some(0));
        assert_eq!(
            ptr.write_at_offset(HOST_PAGE_SIZE.cast_signed(), 0x5a),
            Some(())
        );
        assert!(matches!(
            p.allocate_pages(
                base..base + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::NoReplace
            ),
            Err(AllocationError::AddressInUse)
        ));
        p.allocate_pages(
            base..base + HOST_PAGE_SIZE,
            RW,
            false,
            true,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(ptr.read_at_offset(HOST_PAGE_SIZE.cast_signed()), Some(0x5a));
        // SAFETY: no accesses to the first test-owned page overlap this permission change.
        unsafe {
            p.update_permissions(base..base + HOST_PAGE_SIZE, MemoryRegionPermissions::READ)
                .unwrap();
        }
        assert_eq!(ptr.write_at_offset(0, 1), None); // Fault-safe exception-table recovery
        assert_eq!(
            ptr.write_at_offset(HOST_PAGE_SIZE.cast_signed(), 0x6b),
            Some(())
        );
        // SAFETY: the first page is idle; subsequent probes use fallible raw accesses.
        unsafe {
            p.deallocate_pages(base..base + HOST_PAGE_SIZE).unwrap();
        }
        assert_eq!(ptr.read_at_offset(0), None);
        assert_eq!(ptr.read_at_offset(HOST_PAGE_SIZE.cast_signed()), Some(0x6b));
        // SAFETY: the remaining test-owned page is no longer accessed.
        unsafe {
            p.deallocate_pages(base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE)
                .unwrap();
        }
    }

    #[test]
    fn fixed_mappings_never_replace_host_memory() {
        let p = MacosUserland::new();
        // SAFETY: request fresh anonymous memory with no fixed-address replacement.
        let host = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                HOST_PAGE_SIZE,
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
                    host as usize..host as usize + HOST_PAGE_SIZE,
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
            p.deallocate_pages(host as usize..host as usize + HOST_PAGE_SIZE)
                .unwrap();
        }
        // SAFETY: rejected replacements and unowned deallocation leave the initialized byte mapped.
        assert_eq!(unsafe { host.cast::<u8>().read() }, 0x42);
        // SAFETY: this releases the test's still-live mapping after its last access.
        unsafe {
            libc::munmap(host, HOST_PAGE_SIZE);
        }
    }
}
