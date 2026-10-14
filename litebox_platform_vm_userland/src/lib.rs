// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox platform for a ring-3 runner on the LiteBox VM kernel.
//!
//! Assumptions:
//! - The runner, its shim, and the guest share one address space and one
//!   thread; the guest can tamper with all of it. The kernel does not trust
//!   the runner.
//! - The kernel reaches this platform only through [`kcall`] and upcalls
//!   ([`VmUserland::upcall_entry_address`]); it does demand paging itself.
//! - The shim's VMAs decide the layout of the runner-managed area; the kernel
//!   keeps the authoritative record (see `litebox_common_vm_abi`, Memory).
//! - The guest owns the FS and GS bases; transitions between the guest and
//!   the runner leave them alone. So runner code uses no thread-local storage
//!   (no FS- or GS-relative accesses) until the VM kernel provides it.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod kcall;
/// Only for runners, which are bare-metal programs; host builds (e.g., tests)
/// keep `std`'s entry, allocator, and panic handler.
#[cfg(target_os = "none")]
pub mod start;
pub mod thread;
mod timer;

pub use timer::Timer;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, HintPlacementBehavior,
    MemoryRegionPermissions, PermissionUpdateError,
};
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, PageManagementProvider,
    RawPointerProvider, common_providers::reservations::NoTrackedReservations,
};
use litebox_common_linux::vmap::{
    NoopPhysPageMapInfo, PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use litebox_common_linux::vmem::{PAGE_SIZE, PageFaultError, VmFlags, VmemPageFaultHandler};
use litebox_common_vm_abi::{
    LogLevel, Placement, Populate, Prot, RUNNER_MANAGED_MAX, RUNNER_MANAGED_MIN, StartupInfo,
    Status, WallClock,
};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use zerocopy::{FromBytes, IntoBytes};

#[expect(clippy::cast_possible_truncation, reason = "x86-64 only")]
const MANAGED_MIN: usize = RUNNER_MANAGED_MIN as usize;
#[expect(clippy::cast_possible_truncation, reason = "x86-64 only")]
const MANAGED_MAX: usize = RUNNER_MANAGED_MAX as usize;

/// Guest pointers are confined to the runner-managed area, so the shim never
/// accesses runner memory on the guest's behalf.
pub struct VmUserland {
    wall_clock: WallClock,
}

impl VmUserland {
    /// # Panics
    ///
    /// Panics if the clock frequency is zero.
    pub fn new(info: &StartupInfo) -> Self {
        assert!(info.clock_khz != 0, "clock frequency must not be zero");
        TIMED_WAIT
            .clock_khz
            .store(info.clock_khz, Ordering::Relaxed);
        TIMED_WAIT
            .control_ring
            .store(info.broker_control_ring.start, Ordering::Relaxed);
        Self {
            wall_clock: info.wall_clock,
        }
    }

    /// For [`kcall::ready`].
    pub fn upcall_entry_address() -> usize {
        thread::upcall_entry as *const () as usize
    }
}

pub struct GuestValidateAccess;

impl litebox::platform::common_providers::userspace_pointers::ValidateAccess
    for GuestValidateAccess
{
    fn validate<T>(ptr: *mut T) -> Option<*mut T> {
        let addr = ptr as usize;
        let end = addr.checked_add(size_of::<T>())?;
        (addr >= MANAGED_MIN && end <= MANAGED_MAX).then_some(ptr)
    }

    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T> {
        let base = ptr.cast::<T>();
        let addr = base as usize;
        let end = addr.checked_add(ptr.len().checked_mul(size_of::<T>())?)?;
        (addr >= MANAGED_MIN && end <= MANAGED_MAX).then_some(base)
    }
}

type UserConstPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserConstPtr<GuestValidateAccess, T>;
type UserMutPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserMutPtr<GuestValidateAccess, T>;

impl RawPointerProvider for VmUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

impl ArchSpecificProvider for VmUserland {
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        val: usize,
    ) -> Result<(), ArchSpecificError> {
        match reg {
            ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    // Safety: the kernel enables FSGSBASE, and FS belongs to the
                    // guest.
                    unsafe { litebox_common_linux::wrfsbase(val) };
                    Ok(())
                } else {
                    Err(ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }

    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        match reg {
            // Safety: the kernel enables FSGSBASE.
            ArchSpecificRegister::FsBase => Ok(unsafe { litebox_common_linux::rdfsbase() }),
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
}

impl RawMutexProvider for VmUserland {
    type RawMutex = RawMutex;
}

impl WaitWakerProvider for VmUserland {}

/// One thread: nothing else in the runner can change a waiter's word. So a
/// wait blocks in the kernel until its timeout, a platform timer's deadline
/// (whose signal then interrupts it), or, with a [`NotificationReceiver`],
/// a broker notification, which it dispatches (possibly waking the waiter).
/// One that nothing could end panics.
pub struct RawMutex {
    inner: AtomicU32,
}

impl RawMutexTrait for RawMutex {
    const INIT: Self = Self {
        inner: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, _n: usize) -> usize {
        0
    }

    /// A wait without a timeout: blocks until a broker notification or an
    /// armed platform timer's deadline (whose signal may then be pending once
    /// resumed); panics if nothing could end it. So a wait the timer's signal
    /// does not end (e.g., `pause` with `SIGALRM` ignored) panics after it
    /// expires, unless input could still arrive, where Linux would block
    /// forever.
    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        if self.inner.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        let deadline = timer::next_deadline();
        let ended = receive(deadline).is_some()
            || deadline
                .map(|deadline| TIMED_WAIT.sleep_until(deadline))
                .is_some();
        assert!(
            ended,
            "a wait that nothing could end in the single-threaded VM userland runner would deadlock"
        );
        Ok(())
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        if self.inner.load(Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        let Some(deadline) = now().checked_add(time) else {
            // Too far off to represent: as a wait without a timeout.
            return self.block(val).map(|()| UnblockedOrTimedOut::Unblocked);
        };
        // A platform timer due first ends the wait early, to raise its signal.
        let timer = timer::next_deadline().filter(|&timer| timer < deadline);
        let wake = timer.unwrap_or(deadline);
        let received = receive(Some(wake)).unwrap_or_else(|| {
            TIMED_WAIT.sleep_until(wake);
            0
        });
        Ok(if received != 0 || timer.is_some() {
            UnblockedOrTimedOut::Unblocked
        } else {
            UnblockedOrTimedOut::TimedOut
        })
    }
}

/// Receives broker notifications (e.g., a timer file's expiry, or standard
/// input arriving) for the runner, dispatching them (e.g., with
/// `LiteBox::broker_notification_dispatcher`). They arrive while the guest
/// runs, too, not only while it waits: the kernel interrupts the process
/// once it publishes one, i.e., when a broker timer comes due, when a
/// device's interrupt brings input (e.g., standard input), or as the broker
/// serves the process's requests.
pub trait NotificationReceiver: Sync {
    /// Dispatches the published notifications, first waiting for one until
    /// `deadline` if there are none. Returns how many: zero at the deadline;
    /// `None`, without waiting, if nothing could publish (no deadline and
    /// nothing to come, or receiving failed for good).
    fn receive(&self, deadline: Option<Instant>) -> Option<usize>;

    /// Dispatches the published notifications, without waiting; enters the
    /// kernel only after reading a full ring, for it to publish the rest.
    fn drain(&self);
}

impl VmUserland {
    /// Lets waits end at broker notifications, and dispatches those that
    /// interrupt the guest. At most once.
    ///
    /// # Panics
    ///
    /// On a second call.
    pub fn set_notification_receiver(&self, receiver: &'static dyn NotificationReceiver) {
        let mut set = false;
        TIMED_WAIT.receiver.call_once(|| {
            set = true;
            receiver
        });
        assert!(set, "the notification receiver is already set");
    }
}

/// [`NotificationReceiver::receive`], if there is a receiver: `None`, without
/// waiting, if there is none or nothing could publish (waits then only
/// sleep until their deadline).
fn receive(deadline: Option<Instant>) -> Option<usize> {
    TIMED_WAIT.receiver.get()?.receive(deadline)
}

/// Dispatches the notifications an interrupt may be for.
pub(crate) fn drain_notifications() {
    if let Some(receiver) = TIMED_WAIT.receiver.get() {
        receiver.drain();
    }
}

/// Whether an interrupt may be for the shim: there is a notification
/// receiver, or a platform timer. Else the kernel interrupted for something
/// this runner does not take interrupts for (e.g., notifications it receives
/// only by waiting).
pub(crate) fn interrupts_for_shim() -> bool {
    TIMED_WAIT.receiver.get().is_some() || timer::any()
}

/// What [`RawMutex`] needs for waits, which get no platform reference; set
/// by [`VmUserland::new`] and [`VmUserland::set_notification_receiver`].
struct TimedWait {
    /// [`StartupInfo::clock_khz`], for [`now`].
    clock_khz: AtomicU64,
    /// [`StartupInfo::broker_control_ring`]'s start.
    control_ring: AtomicU64,
    receiver: spin::Once<&'static dyn NotificationReceiver>,
}

static TIMED_WAIT: TimedWait = TimedWait {
    clock_khz: AtomicU64::new(0),
    control_ring: AtomicU64::new(0),
    receiver: spin::Once::new(),
};

impl TimedWait {
    /// Blocks until `deadline` with the kernel's deadline wait (`BrokerEnter`'s
    /// Wait), on a control-ring word that only the kernel's serving changes:
    /// the request ring's consumer epoch.
    ///
    /// # Panics
    ///
    /// If the kernel refuses the wait, e.g., before the broker handshake.
    fn sleep_until(&self, deadline: Instant) {
        use litebox_broker_transport::control_ring::ControlRingDirection;
        let offset = ControlRingDirection::Requests.consumer_epoch_offset();
        let word = usize::try_from(self.control_ring.load(Ordering::Relaxed))
            .expect("x86-64 addresses fit usize")
            + offset;
        while now() < deadline {
            // Safety: the control ring is mapped for the process's lifetime,
            // and its words are aligned `u32`s.
            let current = unsafe { (*(word as *const AtomicU32)).load(Ordering::Acquire) };
            let request = litebox_common_vm_abi::BrokerEnterRequest::wait(
                offset as u64,
                current,
                deadline.as_nanos(),
            );
            match kcall::call(&request) {
                // The word changed (served requests), or the deadline passed.
                Ok(()) | Err(Status::TimedOut) => {}
                Err(status) => panic!("timed wait: {status:?}"),
            }
        }
    }
}

/// An instant on the kernel clock (see `litebox_common_vm_abi`); `from_nanos`
/// and `as_nanos` convert to and from ABI times.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// The counter the kernel clock is read from.
fn read_counter() -> u64 {
    // Safety: RDTSC has no side effects; the kernel allows it in ring 3.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// The kernel clock, once [`VmUserland::new`] has run.
pub(crate) fn now() -> Instant {
    let khz = u128::from(TIMED_WAIT.clock_khz.load(Ordering::Relaxed));
    debug_assert!(khz != 0, "the clock is read before `VmUserland::new`");
    Instant(u64::try_from(u128::from(read_counter()) * 1_000_000 / khz).unwrap_or(u64::MAX))
}

/// Nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemTime(u64);

impl TimeProvider for VmUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Instant {
        now()
    }

    /// The kernel's wall clock ([`StartupInfo::wall_clock`]), advanced by the
    /// kernel clock: `time`, `gettimeofday`, and `CLOCK_REALTIME`.
    fn current_time(&self) -> SystemTime {
        let WallClock { unix_ns, at } = self.wall_clock;
        SystemTime(unix_ns.saturating_add(now().0.saturating_sub(at)))
    }
}

impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        Some(core::time::Duration::from_nanos(
            self.0.checked_sub(earlier.0)?,
        ))
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let nanos: u64 = duration.as_nanos().try_into().ok()?;
        Some(Instant(self.0.checked_add(nanos)?))
    }
}

impl SystemTimeTrait for SystemTime {
    const UNIX_EPOCH: Self = SystemTime(0);

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        let nanos = core::time::Duration::from_nanos;
        match self.0.checked_sub(earlier.0) {
            Some(since) => Ok(nanos(since)),
            None => Err(nanos(earlier.0 - self.0)),
        }
    }
}

fn prot(permissions: MemoryRegionPermissions) -> Prot {
    Prot::from_rwx(
        permissions.contains(MemoryRegionPermissions::READ),
        permissions.contains(MemoryRegionPermissions::WRITE),
        permissions.contains(MemoryRegionPermissions::EXEC),
    )
}

litebox::define_page_reservation!(VmUserlandReservation);

impl<const ALIGN: usize> PageManagementProvider<ALIGN> for VmUserland {
    type Reservations = NoTrackedReservations<ALIGN, VmUserlandReservation<ALIGN>>;

    const TASK_ADDR_MIN: usize = MANAGED_MIN;
    const TASK_ADDR_MAX: usize = MANAGED_MAX;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Exact;

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate_pages_immediately: bool,
    ) -> Result<UserMutPtr<u8>, AllocationError>
    where
        Reservations: Iterator<Item = &'reservation VmUserlandReservation<ALIGN>>,
        VmUserlandReservation<ALIGN>: 'reservation,
    {
        kcall::protect(range.start, range.len(), prot(permissions)).map_err(
            |status| match status {
                Status::NoMemory => AllocationError::OutOfMemory,
                Status::Denied => AllocationError::PermissionDenied,
                Status::InvalidArgument => AllocationError::Unaligned,
                status => panic!("Protect while committing: unexpected {status:?}"),
            },
        )?;
        // TODO: The VM ABI cannot eagerly populate an existing mapping without replacing its contents.
        let _ = populate_pages_immediately;
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<VmUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = VmUserlandReservation<ALIGN>>,
    {
        if suggested_range.start == 0
            && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_))
        {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // The kernel never grows mappings; growth is the shim's bookkeeping.
        let _ = can_grow_down;
        let placement = match fixed_address_behavior {
            FixedAddressBehavior::Replace => Placement::Replace,
            FixedAddressBehavior::Hint(_) | FixedAddressBehavior::NoReplace => Placement::NoReplace,
        };
        let populate = if populate_pages_immediately {
            Populate::Now
        } else {
            Populate::Lazy
        };
        if suggested_range.start < MANAGED_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if suggested_range.end > MANAGED_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        let len = suggested_range.end.saturating_sub(suggested_range.start);
        let address = kcall::map(
            suggested_range.start,
            len,
            prot(initial_permissions),
            placement,
            populate,
        )
        .map_err(|status| match status {
            Status::NoMemory => AllocationError::OutOfMemory,
            Status::Exists => AllocationError::AddressInUse,
            Status::Denied => AllocationError::PermissionDenied,
            // Misaligned or a bad protection: the range was checked above.
            Status::InvalidArgument => AllocationError::Unaligned,
            status => panic!("Map: unexpected {status:?}"),
        })?;
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            replaced_reservations().for_each(drop);
        }
        // Safety: Map returned exclusive ownership of this exact extent.
        Ok(unsafe { VmUserlandReservation::new(address..address + len) })
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation VmUserlandReservation<ALIGN>>,
        VmUserlandReservation<ALIGN>: 'reservation,
    {
        kcall::map(
            range.start,
            range.len(),
            Prot::None,
            Placement::Replace,
            Populate::Lazy,
        )
        .map(|_| ())
        .map_err(|status| match status {
            Status::InvalidArgument | Status::Denied => DeallocationError::Unaligned,
            status => panic!("Map while decommitting: unexpected {status:?}"),
        })
    }

    unsafe fn release_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError> {
        kcall::unmap(range.start, range.end.saturating_sub(range.start)).map_err(|status| {
            match status {
                // Misaligned, or (`Denied`) outside the runner-managed range.
                Status::InvalidArgument | Status::Denied => DeallocationError::Unaligned,
                status => panic!("Unmap: unexpected {status:?}"),
            }
        })
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>
    where
        Reservations: Iterator<Item = &'reservation VmUserlandReservation<ALIGN>>,
        VmUserlandReservation<ALIGN>: 'reservation,
    {
        kcall::protect(
            range.start,
            range.end.saturating_sub(range.start),
            prot(new_permissions),
        )
        .map_err(|status| match status {
            Status::NoMemory => PermissionUpdateError::OutOfMemory,
            Status::Denied => PermissionUpdateError::PermissionDenied,
            Status::InvalidArgument => PermissionUpdateError::Unaligned,
            _ => PermissionUpdateError::PlatformFailure,
        })
    }
}

/// The kernel resolves faults on pages it has mapped. One that reaches the shim
/// is an access violation, or on a page the shim mapped only after the fault
/// (stack growth): that page is populated here, so the retry cannot fault
/// again.
impl VmemPageFaultHandler for VmUserland {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        if error_code & PF_PRESENT != 0 {
            return Err(PageFaultError::AccessError("not resolvable by the kernel"));
        }
        // A not-present page holds no data to replace.
        kcall::map(
            fault_addr,
            PAGE_SIZE,
            prot(flags.into()),
            Placement::Replace,
            Populate::Now,
        )
        .map(|_| ())
        .map_err(|_| PageFaultError::AllocationFailed)
    }

    fn access_error(error_code: u64, flags: VmFlags) -> bool {
        if error_code & PF_WRITE != 0 {
            return !flags.contains(VmFlags::VM_WRITE);
        }
        if error_code & PF_INSTRUCTION != 0 {
            return !flags.contains(VmFlags::VM_EXEC);
        }
        (flags & VmFlags::VM_ACCESS_FLAGS).is_empty()
    }
}

/// x86 page-fault error code bits.
const PF_PRESENT: u64 = 1 << 0;
const PF_WRITE: u64 = 1 << 1;
const PF_INSTRUCTION: u64 = 1 << 4;

impl litebox::platform::SystemInfoProvider for VmUserland {
    fn get_syscall_entry_point(&self) -> usize {
        thread::syscall_callback_address()
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

/// One guest thread: the runner's. New threads are unsupported, and nothing
/// interrupts the only one.
impl litebox::platform::ThreadProvider for VmUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadHandle = ();

    unsafe fn spawn_thread(
        &self,
        _ctx: &Self::ExecutionContext,
        _init_thread: alloc::boxed::Box<
            dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        Err(litebox_common_linux::errno::Errno::ENOSYS)
    }

    fn current_thread(&self) -> Self::ThreadHandle {}

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {}
}

/// The guest's vector state stays in the registers: the runner never touches
/// them (soft-float), and the kernel preserves them across its calls. No
/// snapshot or replacement is needed while the runner has neither `fork` nor
/// asynchronous signals, so, as on SNP, a snapshot is the initial state and a
/// replacement does nothing.
impl litebox::platform::GuestVectorStateProvider for VmUserland {
    type GuestVectorState = litebox_common_linux::GuestVectorState;

    fn get_guest_vector_state(&self) -> Self::GuestVectorState {
        litebox_common_linux::GuestVectorState::initial(
            litebox_common::arch::x86_64::xstate::XsaveLayout::get(),
        )
    }

    fn set_guest_vector_state(&self, _state: &Self::GuestVectorState) {}
}

/// Requires a shim KDF, which runs on a kernel-derived key bound to the
/// process's identity; the platform root key never leaves the kernel. The
/// shim KDF binds `params.context`, so the kernel key needs none (and the
/// kernel's context limit does not apply).
impl litebox::platform::DerivedKeyProvider for VmUserland {
    fn derive_key<E>(
        &self,
        shim_kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(shim_kdf) = shim_kdf else {
            return Err(litebox::platform::DerivedKeyError::ShimKDFRequired);
        };
        let reply = kcall::derive_key(&[]).map_err(|status| match status {
            // The kernel has no root key.
            Status::Unsupported => {
                litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey
            }
            status => panic!("DeriveKey: unexpected {status:?}"),
        })?;
        let mut key = reply.key;
        let result = shim_kdf(&key, params);
        zeroize::Zeroize::zeroize(&mut key);
        Ok(result?)
    }
}

/// Unsupported: physical memory is not accessible from ring 3.
// Safety: every operation fails, so no foreign memory is ever mapped.
unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for VmUserland {
    type MapInfo = NoopPhysPageMapInfo;

    fn validate_unowned(&self, _pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    unsafe fn protect(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }
}

/// Forwards `log` records to the kernel log, truncated to 1 KiB.
pub struct KernelLogger;

impl log::Log for KernelLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        };
        let mut buf = arrayvec::ArrayString::<1024>::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        // The kernel adds its own level prefix.
        let message = buf.split_once("] ").map_or(buf.as_str(), |(_, rest)| rest);
        kcall::log(level, message.trim_end());
    }

    fn flush(&self) {}
}
