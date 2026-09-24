// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]

use core::sync::atomic::AtomicU64;
use core::{arch::asm, sync::atomic::AtomicU32};

use litebox::mm::linux::PageRange;
use litebox::platform::RawPointerProvider;
use litebox::platform::page_mgmt::{NoReservations, ReservationOf};
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, PageManagementProvider, Provider,
};
use litebox_common_linux::errno::Errno;
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};

extern crate alloc;

pub mod arch;
pub mod host;
pub mod mm;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

pub fn update_cpu_mhz(freq: u64) {
    CPU_MHZ.store(freq, core::sync::atomic::Ordering::Relaxed);
}

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    // Invariant in `Host`: <https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns>
    host_and_task: core::marker::PhantomData<fn(Host) -> Host>,
    page_table: mm::PageTable<4096>,
    /// The system time captured at boot, used together with [`boot_instant`](Self::boot_instant)
    /// to derive the current system time from the monotonic clock.
    boot_system_time: core::time::Duration,
    /// The monotonic instant captured at boot.
    boot_instant: Instant,
}

impl<Host: HostInterface> core::fmt::Debug for LinuxKernel<Host> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(&alloc::format!(
            "LinuxKernel<{}>",
            core::any::type_name::<Host>()
        ))
        .finish_non_exhaustive()
    }
}

impl<Host: HostInterface> Provider for LinuxKernel<Host> {}

// TODO: implement pointer validation to ensure the pointers are in user space.
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl<Host: HostInterface> RawPointerProvider for LinuxKernel<Host> {
    type RawConstPointer<T: zerocopy::FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: zerocopy::FromBytes + zerocopy::IntoBytes> = UserMutPtr<T>;
}

impl<Host: HostInterface> ArchSpecificProvider for LinuxKernel<Host> {
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        val: usize,
    ) -> Result<(), ArchSpecificError> {
        match reg {
            ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    unsafe { litebox_common_linux::wrfsbase(val) };
                    Ok(())
                } else {
                    Err(ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            ArchSpecificRegister::GsBase => {
                // See https://github.com/microsoft/litebox/pull/806#discussion_r3210873538
                unimplemented!()
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }

    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        match reg {
            ArchSpecificRegister::FsBase => Ok(unsafe { litebox_common_linux::rdfsbase() }),
            ArchSpecificRegister::GsBase => {
                // See https://github.com/microsoft/litebox/pull/806#discussion_r3210873538
                unimplemented!()
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
}

impl<Host: HostInterface> LinuxKernel<Host> {
    pub fn new(init_page_table_addr: x86_64::PhysAddr) -> &'static Self {
        // Capture the initial system time and monotonic instant so that
        // subsequent `current_time` calls can be derived from the monotonic
        // clock without additional host calls.
        let boot_system_time = Host::current_system_time();
        let boot_instant = Instant::now();

        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host_and_task: core::marker::PhantomData,
            // TODO: Update the init physaddr
            page_table: unsafe { mm::PageTable::new(init_page_table_addr) },
            boot_system_time,
            boot_instant,
        }))
    }

    pub fn terminate(&self, reason_set: u64, reason_code: u64) -> ! {
        Host::terminate(reason_set, reason_code)
    }
}

impl<Host: HostInterface> RawMutexProvider for LinuxKernel<Host> {
    type RawMutex = RawMutex<Host>;
}

impl<Host: HostInterface> WaitWakerProvider for LinuxKernel<Host> {}

/// An implementation of [`litebox_platform::sync::RawMutex`].
pub struct RawMutex<Host: HostInterface> {
    inner: AtomicU32,
    host: core::marker::PhantomData<fn(Host) -> Host>,
}

unsafe impl<Host: HostInterface> Send for RawMutex<Host> {}
unsafe impl<Host: HostInterface> Sync for RawMutex<Host> {}

impl<Host: HostInterface> RawMutexTrait for RawMutex<Host> {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        Host::wake_many(&self.inner, n).unwrap()
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
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(time))
    }
}

impl<Host: HostInterface> RawMutex<Host> {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
            host: core::marker::PhantomData,
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        match Host::block_or_maybe_timeout(&self.inner, val, timeout) {
            Ok(()) | Err(Errno::EINTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(Errno::EAGAIN) => {
                // If the futex value does not match val, then the call fails
                // immediately with the error EAGAIN.
                Err(ImmediatelyWokenUp)
            }
            Err(Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => {
                todo!("Error: {:?}", e);
            }
        }
    }
}

/// An implementation of [`litebox_platform::time::Instant`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

/// An implementation of [`litebox_platform::time::SystemTime`].
pub struct SystemTime {
    inner: core::time::Duration,
}

impl<Host: HostInterface> TimeProvider for LinuxKernel<Host> {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn current_time(&self) -> Self::SystemTime {
        use litebox_platform::time::Instant as _;
        // Derive the current system time from the monotonic clock elapsed
        // since boot, avoiding repeated host calls.
        //
        // NOTE: Because the system time is only sampled once at boot and
        // subsequent values are computed from the monotonic clock, the returned
        // time will drift from the real system time if the host's clock
        // is adjusted after boot (e.g. NTP step, manual set, leap-second).
        let elapsed = Instant::now()
            .checked_duration_since(&self.boot_instant)
            .unwrap_or(core::time::Duration::ZERO);
        SystemTime {
            inner: self.boot_system_time + elapsed,
        }
    }
}

impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.0.checked_sub(earlier.0).map(|v| {
            core::time::Duration::from_micros(
                v / CPU_MHZ.load(core::sync::atomic::Ordering::Relaxed),
            )
        })
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_micros: u64 = duration.as_micros().try_into().ok()?;
        Some(Instant(self.0.checked_add(
            duration_micros.checked_mul(CPU_MHZ.load(core::sync::atomic::Ordering::Relaxed))?,
        )?))
    }
}

impl Instant {
    fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
            );
        }
        (u64::from(hi) << 32) | u64::from(lo)
    }

    fn now() -> Self {
        Instant(Self::rdtsc())
    }
}

impl SystemTimeTrait for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: core::time::Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

/// Platform-Host Interface
pub trait HostInterface: 'static {
    /// Page allocation from host.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)>;

    /// Returns the memory back to host.
    ///
    /// Note host should know the size of allocated memory and needs to check the validity
    /// of the given address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by this [`Self::alloc`].
    unsafe fn free(addr: usize);

    /// Switch back to host
    fn return_to_host() -> !;

    /// Terminate LiteBox
    fn terminate(reason_set: u64, reason_code: u64) -> !;

    fn wake_many(mutex: &AtomicU32, n: usize) -> Result<usize, Errno>;

    fn block_or_maybe_timeout(
        mutex: &AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno>;

    /// Terminate the current process.
    fn terminate_process(code: i32) -> !;

    /// Returns the current system time as a [`Duration`](core::time::Duration) since the
    /// UNIX epoch.
    fn current_system_time() -> core::time::Duration;

    /// For Debugging
    fn log(msg: &str);
}

impl<Host: HostInterface, const ALIGN: usize> PageManagementProvider<ALIGN> for LinuxKernel<Host> {
    type Reservations = NoReservations<ALIGN>;

    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;

    /// Represent a range already selected and owned by the page manager.
    ///
    /// No external allocator exists, so ordinary reservations require no platform operation.
    /// Replacement still removes any old page-table mappings before ownership is transferred.
    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        _can_grow_down: bool,
        behavior: litebox::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        use litebox::platform::page_mgmt::{AllocationError, FixedAddressBehavior};
        assert!(ALIGN.is_power_of_two() && ALIGN.is_multiple_of(4096));
        PageRange::<ALIGN>::new(range.start, range.end).ok_or(AllocationError::Unaligned)?;
        let pages = PageRange::<4096>::new(range.start, range.end).unwrap();
        if behavior == FixedAddressBehavior::Replace {
            // SAFETY: The caller transfers all overlapping ownership and excludes users of replaced pages.
            unsafe {
                self.page_table
                    .unmap_pages(PageRange::new(pages.start, pages.end).unwrap(), true)
            }
            .expect("failed to unmap replaced backing");
            replaced_reservations().for_each(drop);
        }
        // SAFETY: The manager already owns this free aligned range, or transferred ownership
        // through the replacement operation above.
        Ok(unsafe {
            litebox::platform::page_mgmt::NoReservations::<ALIGN>::from_owned_range(range)
        })
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        _can_grow_down: bool,
        populate: bool,
        behavior: litebox::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::ReserveAndCommitError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        use litebox::platform::page_mgmt::{AllocationError, FixedAddressBehavior};
        assert!(ALIGN.is_power_of_two() && ALIGN.is_multiple_of(4096));
        PageRange::<ALIGN>::new(range.start, range.end).ok_or(AllocationError::Unaligned)?;
        let pages = PageRange::<4096>::new(range.start, range.end).unwrap();
        if behavior == FixedAddressBehavior::Replace {
            // SAFETY: The caller authorizes replacement and excludes users of this range.
            unsafe {
                self.page_table
                    .unmap_pages(PageRange::new(pages.start, pages.end).unwrap(), true)
            }
            .expect("failed to unmap replaced backing");
            replaced_reservations().for_each(drop);
        }
        let flags = litebox::mm::linux::VmFlags::from(permissions);
        let pages = PageRange::new(pages.start, pages.end).unwrap();
        self.page_table.map_pages(pages, flags, populate);
        // SAFETY: The provider now owns this exact committed extent.
        Ok(unsafe {
            litebox::platform::page_mgmt::NoReservations::<ALIGN>::from_owned_range(range)
        })
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::PageStateUpdateError::Unaligned)?;
        let flags = litebox::mm::linux::VmFlags::from(permissions);
        // SAFETY: The caller owns the range and excludes conflicting accesses; existing frames
        // must be preserved while missing pages may be populated.
        unsafe { self.page_table.commit_pages(range, flags, populate) }
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::PageStateUpdateError::Unaligned)?;
        // SAFETY: The caller supplies committed pages and excludes conflicting accesses; frames are preserved.
        unsafe {
            self.page_table
                .mprotect_pages(range, litebox::mm::linux::VmFlags::from(permissions))
        }
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::PageStateUpdateError::Unaligned)?;
        // SAFETY: The caller excludes all users; physical frames are freed while ownership remains tracked.
        unsafe { self.page_table.unmap_pages(range, true) }
            .expect("failed to decommit owned pages");
        Ok(())
    }

    unsafe fn release_pages(&self, range: core::ops::Range<usize>) {
        let range = PageRange::new(range.start, range.end).expect("invalid release range");
        // SAFETY: The caller relinquishes all backing in this range and excludes mappings and users.
        unsafe { self.page_table.unmap_pages(range, true) }
            .expect("failed to release owned backing");
    }

    unsafe fn try_remap_pages<Reservations>(
        &self,
        source_reservations: impl FnOnce() -> Reservations,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::RemapError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        assert!(ALIGN.is_power_of_two() && ALIGN.is_multiple_of(4096));
        let Some(old_range) = PageRange::new(old_range.start, old_range.end) else {
            return Err(litebox::platform::page_mgmt::RemapError::Unaligned);
        };
        let Some(new_range) = PageRange::<ALIGN>::new(new_range.start, new_range.end) else {
            return Err(litebox::platform::page_mgmt::RemapError::Unaligned);
        };
        if old_range.start.max(new_range.start) < old_range.end.min(new_range.end) {
            return Err(litebox::platform::page_mgmt::RemapError::Overlapping);
        }
        assert!(new_range.len() > old_range.len());
        if new_range.start < <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
            || new_range.end > <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
        {
            return Err(litebox::platform::page_mgmt::RemapError::OutOfMemory);
        }
        self.page_table.map_pages(
            PageRange::new(new_range.start + old_range.len(), new_range.end).unwrap(),
            litebox::mm::linux::VmFlags::from(permissions),
            true,
        );
        // SAFETY: The caller keeps the destination free of mappings and reservations.
        // The caller excludes source users; moving PTEs leaves the source unmapped.
        unsafe {
            self.page_table.remap_pages(
                old_range,
                PageRange::new(new_range.start, new_range.end).unwrap(),
            )
        }
        .expect("failed to move remap page tables");
        source_reservations().for_each(drop);
        // SAFETY: Remapping acquired the caller-selected, previously unreserved destination.
        let reservation = unsafe {
            litebox::platform::page_mgmt::NoReservations::<ALIGN>::from_owned_range(
                new_range.into(),
            )
        };
        Ok(reservation)
    }
}

impl<Host: HostInterface> litebox::mm::linux::VmemPageFaultHandler for LinuxKernel<Host> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: litebox::mm::linux::VmFlags,
        error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unsafe {
            self.page_table
                .handle_page_fault(fault_addr, flags, error_code)
        }
    }

    fn access_error(error_code: u64, flags: litebox::mm::linux::VmFlags) -> bool {
        mm::PageTable::<4096>::access_error(error_code, flags)
    }
}

impl<Host: HostInterface> litebox::platform::SystemInfoProvider for LinuxKernel<Host> {
    fn get_syscall_entry_point(&self) -> usize {
        // Currently this is only used in ELF loader to fix trampoline code.
        // When running in kernel mode, we don't need a syscall trampoline.
        0
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

const RIP_OFFSET: usize = core::mem::offset_of!(litebox_common_linux::PtRegs, rip);
const EFLAGS_OFFSET: usize = core::mem::offset_of!(litebox_common_linux::PtRegs, eflags);

/// Switches to the guest context using sysretq.
///
/// # Safety
///
/// The context must be valid guest context.
unsafe fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    unsafe {
        core::arch::asm!(
            "mov     rsp, {0}",
            "mov     rcx, [rsp + {rip_off}]",
            "mov     r11, [rsp + {eflags_off}]",
            "pop     r15",
            "pop     r14",
            "pop     r13",
            "pop     r12",
            "pop     rbp",
            "pop     rbx",
            "pop     rsi",        /* skip r11 */
            "pop     r10",
            "pop     r9",
            "pop     r8",
            "pop     rax",
            "pop     rsi",        /* skip rcx */
            "pop     rdx",
            "pop     rsi",
            "pop     rdi",
            "mov     rsp, [rsp + 0x20]",   /* original rsp */
            "swapgs",
            "sysretq",
            in(reg) ctx,
            rip_off = const RIP_OFFSET,
            eflags_off = const EFLAGS_OFFSET,
            options(noreturn),
        );
    }
}
