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
pub mod thread;

use core::sync::atomic::AtomicU32;
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
    Status,
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
    tsc_khz: u64,
}

impl VmUserland {
    /// # Panics
    ///
    /// Panics if the TSC frequency is zero.
    pub fn new(info: &StartupInfo) -> Self {
        assert!(info.tsc_khz != 0, "TSC frequency must not be zero");
        Self {
            tsc_khz: info.tsc_khz,
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

/// Blocking panics: with one thread, nothing could wake the waiter.
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

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val).map(|_| ())
    }

    fn block_or_timeout(
        &self,
        val: u32,
        _time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val)
    }
}

impl RawMutex {
    fn block_or_maybe_timeout(&self, val: u32) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        if self.inner.load(core::sync::atomic::Ordering::Relaxed) != val {
            return Err(ImmediatelyWokenUp);
        }
        panic!("blocking in the single-threaded VM userland runner would deadlock")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

pub struct SystemTime;

impl TimeProvider for VmUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Instant {
        // Safety: RDTSC has no side effects; the kernel allows it in ring 3.
        let tsc = u128::from(unsafe { core::arch::x86_64::_rdtsc() });
        Instant(u64::try_from(tsc * 1_000_000 / u128::from(self.tsc_khz)).unwrap_or(u64::MAX))
    }

    /// Panics: the kernel has no wall clock.
    fn current_time(&self) -> SystemTime {
        panic!("no wall clock")
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
    const UNIX_EPOCH: Self = SystemTime;

    fn duration_since(
        &self,
        _earlier: &Self,
    ) -> Result<core::time::Duration, core::time::Duration> {
        panic!("no wall clock")
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

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<UserMutPtr<u8>, AllocationError> {
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
        kcall::map(
            suggested_range.start,
            len,
            prot(initial_permissions),
            placement,
            populate,
        )
        .map(|addr| UserMutPtr::from_ptr(addr as *mut u8))
        .map_err(|status| match status {
            Status::NoMemory => AllocationError::OutOfMemory,
            Status::Exists => AllocationError::AddressInUse,
            Status::Denied => AllocationError::PermissionDenied,
            // Misaligned or a bad protection: the range was checked above.
            Status::InvalidArgument => AllocationError::Unaligned,
            status => panic!("Map: unexpected {status:?}"),
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

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
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

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        core::iter::empty()
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
