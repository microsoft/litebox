// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox's kernel-mode VM platform library. The runner supplies boot,
//! allocators, logging, interrupt-controller setup, a [`clock::ClockSource`],
//! and the root key ([`providers::set_platform_root_key`]).
//!
//! After boot mappings and the heap are ready, [`VmKernel::boot`] owns CPU
//! initialization and the kernel-stack handoff. Its continuation receives the
//! initialized platform; key provisioning remains separate and must precede
//! execution that needs derived keys.
//!
//! Assumptions: a single CPU, no scheduler, and not a confidential VM (no
//! #VE/#VC/#HV).
//! There is no timer, so user code that never enters the kernel is never
//! preempted.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

use crate::arch::mm::paging::UnmapOptions;
use crate::per_cpu::{PerCpuVariablesAsm, with_per_cpu_variables};
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use hashbrown::HashMap;
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, PageManagementProvider,
    RawPointerProvider,
};
use litebox::{
    mm::exception_table::search_exception_tables,
    platform::page_mgmt::{
        AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
        PermissionUpdateError,
    },
    shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo},
    utils::TruncateExt,
};
use litebox_common_linux::vmap::{
    NoopPhysPageMapInfo, PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use litebox_common_linux::{
    PtRegs,
    errno::Errno,
    vmem::{PAGE_SIZE, PageFaultError, PageRange, VmFlags, VmemPageFaultHandler},
};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod arch;
mod boot;
pub mod clock;
pub mod mm;
mod per_cpu;
pub mod providers;

mod syscall_entry;

/// Inputs to the single-CPU kernel handoff. The runner owns device setup and
/// must keep the clock and allocator alive until reset.
pub struct BootConfig<'a> {
    pub page_allocator: &'static dyn mm::PageAllocator,
    pub clock: &'static dyn clock::ClockSource,
    /// Physical RAM to map; ranges are rounded inward to whole pages.
    pub ram: &'a [core::ops::Range<PhysAddr>],
    /// Page-aligned physical kernel code range, mapped RX.
    pub text: core::ops::Range<PhysAddr>,
    /// Page-aligned physical constants, mapped R/NX after relocation.
    /// Must not overlap `text`; remaining RAM is mapped RW/NX.
    pub read_only: core::ops::Range<PhysAddr>,
    /// External vectors that require neither handling nor acknowledgement.
    pub ignored_vectors: &'a [u8],
}

/// Valid until unregistered; its representation is private to the platform.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressSpaceId(usize);

impl AddressSpaceId {
    pub const KERNEL: Self = Self(0);
}

// Virtual address space:
//   0xFFFF_E200_0000_0000 ..  kernel: all owned RAM at PA + KERNEL_OFFSET
//   0x0000_0000_0001_0000 .. 0x0000_7FFF_FFFF_F000  user

/// `VA = PA + KERNEL_OFFSET` for kernel-owned RAM. Must be 512 GiB aligned
/// (one PML4 slot).
pub const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;

/// Exclusive; the last page of the low canonical half is a guard page.
const USER_ADDR_MAX: usize = 0x0000_7FFF_FFFF_F000;

/// The first 64 KiB stay unmapped to catch NULL dereferences.
const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;

/// A borrowed base table or an owned reference to a task table.
pub(crate) struct PageTableHandle<'a>(PageTableHandleInner<'a>);

enum PageTableHandleInner<'a> {
    Base(&'a mm::PageTable<PAGE_SIZE>),
    Task(Arc<mm::PageTable<PAGE_SIZE>>),
}

impl<'a> PageTableHandle<'a> {
    #[inline]
    fn base(page_table: &'a mm::PageTable<PAGE_SIZE>) -> Self {
        Self(PageTableHandleInner::Base(page_table))
    }

    #[inline]
    fn task(page_table: Arc<mm::PageTable<PAGE_SIZE>>) -> Self {
        Self(PageTableHandleInner::Task(page_table))
    }
}

impl core::ops::Deref for PageTableHandle<'_> {
    type Target = mm::PageTable<PAGE_SIZE>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            PageTableHandleInner::Base(page_table) => page_table,
            PageTableHandleInner::Task(page_table) => page_table,
        }
    }
}

/// Task tables share all kernel mappings; there is no KPTI isolation.
pub(crate) struct PageTableManager {
    /// Lives until reset; must never be dropped.
    base_page_table: mm::PageTable<PAGE_SIZE>,
    base_page_table_frame: PhysFrame<Size4KiB>,
    task_page_tables: spin::RwLock<HashMap<AddressSpaceId, Arc<mm::PageTable<PAGE_SIZE>>>>,
}

impl PageTableManager {
    fn new(base_pt: mm::PageTable<PAGE_SIZE>) -> Self {
        let base_frame = base_pt.physical_frame();
        Self {
            base_page_table: base_pt,
            base_page_table_frame: base_frame,
            task_page_tables: spin::RwLock::new(HashMap::new()),
        }
    }

    /// # Panics
    ///
    /// Panics if CR3 does not match the current core's retained page table.
    #[inline]
    pub(crate) fn current_page_table(&self) -> PageTableHandle<'_> {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();

        if self.base_page_table_frame == cr3_frame {
            return PageTableHandle::base(&self.base_page_table);
        }

        let cr3_id: usize = cr3_frame.start_address().as_u64().trunc();
        if let Some(pt) =
            with_per_cpu_variables(|pcv| pcv.active_page_table(AddressSpaceId(cr3_id)))
        {
            return PageTableHandle::task(pt);
        }

        unreachable!(
            "CR3 does not match the per-CPU page table: {:?}",
            cr3_frame.start_address()
        );
    }

    /// # Safety
    ///
    /// No references to user memory may be held across the switch.
    pub(crate) unsafe fn load_base(&self) {
        let previous = without_interrupts(|| {
            // Replace the per-CPU owner only after CR3 stops referencing it.
            // Safety: the base table maps all kernel RAM.
            unsafe { self.base_page_table.load() };
            with_per_cpu_variables(|pcv| {
                // Safety: CR3 now references the base page table and interrupts are disabled.
                unsafe { pcv.replace_active_page_table(None) }
            })
        });
        // Last-owner reclamation runs outside the interrupt-free section.
        drop(previous);
    }

    /// # Safety
    ///
    /// No references to the current address space's user memory may be held
    /// across the switch.
    ///
    /// # Errors
    ///
    /// `EINVAL` for the base table ID, `ENOENT` for an unknown ID.
    pub(crate) unsafe fn load_task(&self, task_pt_id: AddressSpaceId) -> Result<(), Errno> {
        if task_pt_id == AddressSpaceId::KERNEL {
            return Err(Errno::EINVAL);
        }

        let pt = {
            let task_pts = self.task_page_tables.read();
            Arc::clone(task_pts.get(&task_pt_id).ok_or(Errno::ENOENT)?)
        };

        let previous = without_interrupts(|| {
            // Replace the per-CPU owner only after CR3 stops referencing it.
            // Safety: task tables share the base table's kernel entries.
            unsafe { pt.load() };
            with_per_cpu_variables(|pcv| {
                // Safety: CR3 now references `pt` and interrupts are disabled.
                unsafe { pcv.replace_active_page_table(Some((task_pt_id, pt))) }
            })
        });
        // Last-owner reclamation runs outside the interrupt-free section.
        drop(previous);
        Ok(())
    }

    /// Shares the base table's kernel P3/P2/P1 tables.
    pub(crate) fn create_task_page_table(&self) -> AddressSpaceId {
        let pt = mm::PageTable::new_top_level();

        // Sharing is safe because the kernel mappings are fixed after boot.
        pt.copy_pml4_entries_from(&self.base_page_table);

        let pt = Arc::new(pt);
        let task_pt_id = AddressSpaceId(pt.physical_frame().start_address().as_u64().trunc());

        let mut task_pts = self.task_page_tables.write();
        task_pts.insert(task_pt_id, pt);

        task_pt_id
    }

    /// Unregisters a task table; retained handles keep it alive.
    ///
    /// # Safety
    ///
    /// The caller must ensure final destruction is safe: user leaf frames are
    /// exclusively owned and no access outlives all remaining handles.
    ///
    /// Returns `EINVAL` for the base ID and `ENOENT` if it is not registered.
    pub(crate) unsafe fn unregister_task_page_table(
        &self,
        task_pt_id: AddressSpaceId,
    ) -> Result<(), Errno> {
        if task_pt_id == AddressSpaceId::KERNEL {
            return Err(Errno::EINVAL);
        }

        let pt = {
            let mut task_pts = self.task_page_tables.write();
            task_pts.remove(&task_pt_id).ok_or(Errno::ENOENT)?
        };
        drop(pt);
        Ok(())
    }
}

/// The LiteBox platform for a VM guest kernel.
pub struct VmKernel {
    page_table_manager: PageTableManager,
    clock: &'static dyn clock::ClockSource,
    /// Guest RAM owned by this kernel (mapped at `PA + KERNEL_OFFSET`).
    ram_frame_ranges: alloc::vec::Vec<PhysFrameRange<Size4KiB>>,
}

/// Confines user pointers to the user range and opens SMAP around accesses.
pub struct VmValidateAccess;

impl litebox::platform::common_providers::userspace_pointers::ValidateAccess for VmValidateAccess {
    fn validate<T>(ptr: *mut T) -> Option<*mut T> {
        let addr = ptr as usize;
        let end = addr.checked_add(core::mem::size_of::<T>())?;
        if addr >= USER_ADDR_MIN && end <= USER_ADDR_MAX {
            Some(ptr)
        } else {
            None
        }
    }

    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T> {
        let base = ptr.cast::<T>();
        let addr = base as usize;
        let byte_len = ptr.len().checked_mul(core::mem::size_of::<T>())?;
        let end = addr.checked_add(byte_len)?;
        if addr >= USER_ADDR_MIN && end <= USER_ADDR_MAX {
            Some(base)
        } else {
            None
        }
    }

    #[inline]
    fn with_user_memory_access<R>(f: impl FnOnce() -> R) -> R {
        // Safety: only sets RFLAGS.AC. Not `nomem`, so memory accesses are not
        // moved out of the window; not `preserves_flags`, as it changes AC.
        unsafe {
            core::arch::asm!("stac", options(nostack));
        }
        let result = f();
        // Safety: only clears RFLAGS.AC (options as above).
        unsafe {
            core::arch::asm!("clac", options(nostack));
        }
        result
    }
}

type UserConstPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserConstPtr<VmValidateAccess, T>;
type UserMutPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserMutPtr<VmValidateAccess, T>;

impl RawPointerProvider for VmKernel {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

impl ArchSpecificProvider for VmKernel {
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        val: usize,
    ) -> Result<(), ArchSpecificError> {
        match reg {
            ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    // Safety: FSGSBASE is enabled, and `val` is a valid user FS
                    // base; the kernel does not use FS.
                    unsafe { litebox_common_linux::wrfsbase(val) };
                    Ok(())
                } else {
                    Err(ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            ArchSpecificRegister::GsBase => {
                panic!("GS belongs to the kernel (per-CPU data via `swapgs`)")
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }

    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        match reg {
            // Safety: FSGSBASE is enabled.
            ArchSpecificRegister::FsBase => Ok(unsafe { litebox_common_linux::rdfsbase() }),
            ArchSpecificRegister::GsBase => {
                panic!("GS belongs to the kernel (per-CPU data via `swapgs`)")
            }
            _ => Err(ArchSpecificError::RegisterUnsupported),
        }
    }
}

impl VmKernel {
    fn initialize(
        ram: &[core::ops::Range<PhysAddr>],
        text: &core::ops::Range<PhysAddr>,
        read_only: &core::ops::Range<PhysAddr>,
        clock: &'static dyn clock::ClockSource,
    ) -> &'static Self {
        let ram_frame_ranges: alloc::vec::Vec<PhysFrameRange<Size4KiB>> = ram
            .iter()
            .filter_map(|r| {
                let start = PhysFrame::containing_address(r.start.align_up(Size4KiB::SIZE));
                let end = PhysFrame::containing_address(r.end.align_down(Size4KiB::SIZE));
                (start < end).then(|| PhysFrame::range(start, end))
            })
            .collect();
        assert!(!text.is_empty(), "kernel text is empty");
        for region in [text, read_only] {
            assert!(region.start <= region.end, "reversed kernel image range");
            if region.is_empty() {
                continue;
            }
            assert!(
                region.start.is_aligned(Size4KiB::SIZE) && region.end.is_aligned(Size4KiB::SIZE),
                "kernel image ranges must be page-aligned"
            );
            assert!(
                ram_frame_ranges.iter().any(|r| {
                    r.start.start_address() <= region.start && region.end <= r.end.start_address()
                }),
                "kernel image range {region:?} is outside guest RAM"
            );
        }
        assert!(
            read_only.is_empty() || text.end <= read_only.start || read_only.end <= text.start,
            "kernel text and read-only data overlap"
        );

        let base_pt = mm::PageTable::new_top_level();
        for range in &ram_frame_ranges {
            if let Err(e) = base_pt.map_kernel_ram(*range, text, read_only) {
                panic!("failed to map guest RAM {range:?}: {e:?}");
            }
        }
        per_cpu::unmap_stack_guards(&base_pt);

        crate::arch::enable_dep();
        crate::arch::enable_write_protect();

        // Safety: maps all of `ram`, which holds the kernel, including the
        // running code and stack.
        unsafe { base_pt.load() };

        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            page_table_manager: PageTableManager::new(base_pt),
            clock,
            ram_frame_ranges,
        }))
    }

    /// Only valid for addresses in the kernel's direct mapping.
    pub fn va_to_pa(va: VirtAddr) -> PhysAddr {
        <Self as mm::MemoryProvider>::va_to_pa(va)
    }

    /// Only valid for physical addresses in the kernel's direct mapping.
    pub fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        <Self as mm::MemoryProvider>::pa_to_va(pa)
    }

    pub fn contains_ram(&self, range: core::ops::Range<PhysAddr>) -> bool {
        range.start < range.end
            && self.ram_frame_ranges.iter().any(|r| {
                r.start.start_address() <= range.start && range.end <= r.end.start_address()
            })
    }

    /// The new address space shares kernel mappings but has no user mappings.
    ///
    /// # Panics
    ///
    /// Panics if the page allocator is exhausted.
    pub fn create_address_space(&self) -> AddressSpaceId {
        self.page_table_manager.create_task_page_table()
    }

    /// Unregisters a task table; retained handles keep it alive.
    ///
    /// # Safety
    ///
    /// The caller must ensure final destruction is safe: user leaf frames are
    /// exclusively owned and no access outlives all remaining handles.
    ///
    /// Returns `EINVAL` for the base ID and `ENOENT` if it is not registered.
    pub unsafe fn unregister_address_space(&self, task_pt_id: AddressSpaceId) -> Result<(), Errno> {
        // Safety: the caller upholds the manager's destruction requirements.
        unsafe {
            self.page_table_manager
                .unregister_task_page_table(task_pt_id)
        }
    }

    /// Switch to a registered address space, or [`AddressSpaceId::KERNEL`].
    ///
    /// # Safety
    ///
    /// No references to the current address space's user memory may be held
    /// across the switch.
    ///
    /// # Errors
    ///
    /// `ENOENT` for an unknown ID.
    pub unsafe fn switch_address_space(&self, pt_id: AddressSpaceId) -> Result<(), Errno> {
        if pt_id == AddressSpaceId::KERNEL {
            // Safety: forwarded to the caller.
            unsafe { self.page_table_manager.load_base() };
            Ok(())
        } else {
            // Safety: forwarded to the caller.
            unsafe { self.page_table_manager.load_task(pt_id) }
        }
    }
}

impl RawMutexProvider for VmKernel {
    type RawMutex = RawMutex;
}

impl WaitWakerProvider for VmKernel {}

/// Without a scheduler, no thread can wake a blocked waiter; blocking panics.
pub struct RawMutex {
    inner: AtomicU32,
}

impl RawMutexTrait for RawMutex {
    const INIT: Self = Self {
        inner: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, _n: usize) -> usize {
        0
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

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        if self
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Relaxed)
            != val
        {
            return Err(ImmediatelyWokenUp);
        }
        panic!(
            "blocking on a single-CPU VM guest with no scheduler would deadlock \
             (see `RawMutex`)"
        )
    }
}

/// Nanoseconds from the installed [`clock::ClockSource`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

pub struct SystemTime;

impl TimeProvider for VmKernel {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        Instant(self.clock.monotonic_nanos())
    }

    /// There is no wall clock (no RTC driver).
    fn current_time(&self) -> Self::SystemTime {
        panic!("no wall clock (no RTC driver)")
    }
}

impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        let nanos = self.0.checked_sub(earlier.0)?;
        Some(core::time::Duration::from_nanos(nanos))
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
        panic!("no wall clock (no RTC driver)")
    }
}

/// The `MemoryRegionPermissions` bits are the low `VmFlags` bits.
fn vm_flags(permissions: MemoryRegionPermissions) -> VmFlags {
    VmFlags::from_bits(permissions.bits().into())
        .expect("MemoryRegionPermissions bits are VmFlags bits")
}

impl<const ALIGN: usize> PageManagementProvider<ALIGN> for VmKernel {
    const TASK_ADDR_MIN: usize = USER_ADDR_MIN;
    const TASK_ADDR_MAX: usize = USER_ADDR_MAX;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        let range = PageRange::new(suggested_range.start, suggested_range.end)
            .ok_or(AllocationError::Unaligned)?;
        if range.start < USER_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > USER_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        let current_pt = self.page_table_manager.current_page_table();
        match fixed_address_behavior {
            FixedAddressBehavior::Hint | FixedAddressBehavior::NoReplace => {}
            FixedAddressBehavior::Replace => {
                // Safety: the caller replaces this range, so nothing uses it.
                // Unmapping fails only for an unaligned range.
                unsafe { current_pt.unmap_pages(range, UnmapOptions::RELEASE) }
                    .map_err(|_| AllocationError::Unaligned)?;
            }
        }
        let mut flags = vm_flags(initial_permissions);
        flags.set(VmFlags::VM_GROWSDOWN, can_grow_down);
        // Safety: user address space (checked above) that the page manager
        // tracks as free (`Replace` unmapped it above).
        unsafe { current_pt.map_pages(range, flags, populate_pages_immediately) }
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError> {
        let range = PageRange::new(range.start, range.end).ok_or(DeallocationError::Unaligned)?;
        // Safety: forwarded to the caller, who no longer uses `range`.
        unsafe {
            self.page_table_manager
                .current_page_table()
                .unmap_pages(range, UnmapOptions::RELEASE)
        }
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        let range =
            PageRange::new(range.start, range.end).ok_or(PermissionUpdateError::Unaligned)?;
        let new_flags = vm_flags(new_permissions);
        // Safety: forwarded to the caller.
        unsafe {
            self.page_table_manager
                .current_page_table()
                .mprotect_pages(range, new_flags)
        }
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        core::iter::empty()
    }
}

impl VmemPageFaultHandler for VmKernel {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        // Safety: forwarded to the caller (the page fault handler).
        unsafe {
            self.page_table_manager
                .current_page_table()
                .handle_page_fault(fault_addr, flags, error_code)
        }
    }

    fn access_error(error_code: u64, flags: VmFlags) -> bool {
        mm::PageTable::<PAGE_SIZE>::access_error(error_code, flags)
    }
}

impl litebox::platform::SystemInfoProvider for VmKernel {
    fn get_syscall_entry_point(&self) -> usize {
        // User code traps directly with `syscall`; no trampoline.
        0
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

/// Mapping foreign physical memory is not supported.
// Safety: every operation fails, so no foreign memory is ever mapped.
unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for VmKernel {
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

/// Run a user thread until it terminates or returns to the kernel. The shim's
/// `init` fills `ctx`, which is sanitized before user mode.
///
/// # Safety
///
/// The platform must be set up (see the crate docs), and no other
/// `run_thread_ref`/`reenter_thread_ref` call may be in progress.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut PtRegs)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, false);
}

/// Re-enter a thread, e.g., after `load_ta_context`. The shim's `reenter`
/// fills `ctx`, which is sanitized before user mode.
///
/// # Safety
///
/// As for [`run_thread_ref`].
pub unsafe fn reenter_thread_ref<T>(shim: &T, ctx: &mut PtRegs)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, true);
}

/// Kernel faults can re-enter a shim handler. Only non-nesting user-entry
/// handlers may borrow `ctx`; kernel-fault handlers must not touch it.
struct ThreadContext<'a> {
    shim: &'a dyn EnterShim<ExecutionContext = PtRegs>,
    ctx: *mut PtRegs,
}

fn run_thread_inner(
    shim: &dyn EnterShim<ExecutionContext = PtRegs>,
    ctx: &mut PtRegs,
    reenter: bool,
) {
    // SWAPGS exposes KernelGsBase to user code.
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    with_per_cpu_variables(|pcv| pcv.asm.reset_user_xsave());
    let ctx = core::ptr::from_mut(ctx);
    let thread_ctx = ThreadContext { shim, ctx };
    // `ctx` is passed again so the assembly need not know `ThreadContext`'s layout.
    // Safety: `ctx` is valid and otherwise unused for the duration of the call,
    // and `run_thread_arch` returns exactly once.
    unsafe {
        run_thread_arch(&thread_ctx, ctx, u8::from(reenter));
    }
}

macro_rules! SAVE_CALLEE_SAVED_REGISTERS_ASM {
    () => {
        "
        push rbp
        mov rbp, rsp
        push rbx
        push r12
        push r13
        push r14
        push r15
        "
    };
}

macro_rules! RESTORE_CALLEE_SAVED_REGISTERS_ASM {
    () => {
        "
        lea rsp, [rbp - 5 * 8]
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        "
    };
}

// XSAVEOPT requires prior XRSTOR tracking for the same buffer (see XsaveState).
// The user area is reset at entry; the kernel area is saved before any restore.

/// Save extended state. Clobbers: rax, rcx, rdx
macro_rules! XSAVE_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt, $xsaved_off:tt) => {
        concat!(
            "mov rcx, gs:[",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, gs:[",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, gs:[",
            stringify!($mask_hi_off),
            "]\n",
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 2\n",
            "jne 2f\n",
            "xsaveopt [rcx]\n",
            "jmp 3f\n",
            "2:\n",
            "xsave [rcx]\n",
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 0\n",
            "jne 3f\n",
            "mov byte ptr gs:[",
            stringify!($xsaved_off),
            "], 1\n",
            "3:\n",
        )
    };
}

/// A reset area's XSTATE_BV initializes components instead of restoring them.
/// Clobbers: rax, rcx, rdx.
macro_rules! XRSTOR_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt, $xsaved_off:tt) => {
        concat!(
            "mov rcx, gs:[",
            stringify!($xsave_area_off),
            "]\n",
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 0\n",
            "jne 8f\n",
            "mov eax, -1\n",
            "mov edx, -1\n",
            "xrstor [rcx]\n",
            "jmp 9f\n",
            "8:\n",
            "mov eax, gs:[",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, gs:[",
            stringify!($mask_hi_off),
            "]\n",
            "xrstor [rcx]\n",
            "mov byte ptr gs:[",
            stringify!($xsaved_off),
            "], 2\n",
            "9:\n",
        )
    };
}

/// Push the user context at `syscall` entry as a `PtRegs` below `rsp`.
///
/// Requires: user `rsp` in `r11`, user `rflags` in `gs:[user_rflags]`, user
/// return address in `rcx` (as `syscall` leaves it).
macro_rules! SAVE_SYSCALL_USER_CONTEXT_ASM {
    () => {
        "
        push 0x2b       // pt_regs->ss = __USER_DS
        push r11        // pt_regs->rsp
        push qword ptr gs:[{user_rflags_off}] // pt_regs->eflags
        push 0x33       // pt_regs->cs = __USER_CS
        push rcx        // pt_regs->rip
        push rax        // pt_regs->orig_rax
        push rdi        // pt_regs->rdi
        push rsi        // pt_regs->rsi
        push rdx        // pt_regs->rdx
        push rcx        // pt_regs->rcx
        push -38        // pt_regs->rax = -ENOSYS
        push r8         // pt_regs->r8
        push r9         // pt_regs->r9
        push r10        // pt_regs->r10
        push [rsp + 88] // pt_regs->r11 = rflags
        push rbx        // pt_regs->rbx
        push rbp        // pt_regs->rbp
        push r12        // pt_regs->r12
        push r13        // pt_regs->r13
        push r14        // pt_regs->r14
        push r15        // pt_regs->r15
        "
    };
}

/// Push the user context at a user-mode exception as a `PtRegs` below `rsp`.
///
/// Requires: `rax` pointing at the ISR stack (`[rax]` vector, `[rax+8]` error
/// code, then the iret frame), every other GPR holding its user value, user
/// `rax` in `gs:[scratch]`, and the kernel GS (after `swapgs`).
///
/// Clobbers: rax
macro_rules! SAVE_PF_USER_CONTEXT_ASM {
    () => {
        "
        push [rax + 48]   // pt_regs->ss
        push [rax + 40]   // pt_regs->rsp
        push [rax + 32]   // pt_regs->eflags
        push [rax + 24]   // pt_regs->cs
        push [rax + 16]   // pt_regs->rip
        push [rax + 8]    // pt_regs->orig_rax (error code)
        push rdi          // pt_regs->rdi
        push rsi          // pt_regs->rsi
        push rdx          // pt_regs->rdx
        push rcx          // pt_regs->rcx
        mov rax, gs:[{scratch_off}]
        push rax          // pt_regs->rax
        push r8           // pt_regs->r8
        push r9           // pt_regs->r9
        push r10          // pt_regs->r10
        push r11          // pt_regs->r11
        push rbx          // pt_regs->rbx
        push rbp          // pt_regs->rbp
        push r12          // pt_regs->r12
        push r13          // pt_regs->r13
        push r14          // pt_regs->r14
        push r15          // pt_regs->r15
        "
    };
}

macro_rules! SAVE_CPU_CONTEXT_ASM {
    () => {
        "
        push rdi
        push rsi
        push rdx
        push rcx
        push rax
        push r8
        push r9
        push r10
        push r11
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        "
    };
}

/// Pop a `PtRegs` up to the iret frame.
macro_rules! RESTORE_CPU_CONTEXT_ASM {
    () => {
        "
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        pop r11
        pop r10
        pop r9
        pop r8
        pop rax
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        add rsp, 8 // skip pt_regs->orig_rax
        "
    };
}

#[unsafe(naked)]
unsafe extern "C" fn run_thread_arch(thread_ctx: &ThreadContext, ctx: *mut PtRegs, reenter: u8) {
    core::arch::naked_asm!(
        SAVE_CALLEE_SAVED_REGISTERS_ASM!(),
        // Save reenter flag (in dl) before XSAVE clobbers edx
        "mov r9b, dl",
        // Extended states are callee-saved, and the caller may have used any.
        XSAVE_ASM!({kernel_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {kernel_xsaved_off}),
        "push rdi", // save `thread_ctx`
        "mov gs:[{cur_kernel_sp_off}], rsp",
        "mov gs:[{cur_kernel_bp_off}], rbp",
        "lea r8, [rsi + {USER_CONTEXT_SIZE}]",
        "mov gs:[{user_context_top_off}], r8",
        "mov byte ptr gs:[{is_in_user_off}], 1",
        "test r9b, r9b",
        "jnz 1f",
        "call {init_handler}",
        "jmp done",
        "1:",
        "call {reenter_handler}",
        "jmp done",
        ".globl syscall_callback",
        "syscall_callback:",
        "swapgs",
        "mov gs:[{user_rflags_off}], r11", // store user `rflags`.
        "mov r11, rsp", // store user `rsp` in `r11`
        "mov rsp, gs:[{user_context_top_off}]",
        SAVE_SYSCALL_USER_CONTEXT_ASM!(),
        XSAVE_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        // Returns only if the thread exits; otherwise resumes user mode.
        "mov rdi, [rsp]", // pass `thread_ctx`
        "call {syscall_handler}",
        "jmp done",
        // From ISR stubs, for user-mode exceptions. On entry: rsp = ISR stack
        // [vector, error_code, rip, cs, rflags, rsp, ss], all GPRs hold user
        // values, IF is clear, and GS is still the user's.
        ".globl exception_callback",
        "exception_callback:",
        "cld",
        "clac",
        "swapgs",
        "mov gs:[{scratch_off}], rax",
        "mov al, [rsp]",
        "mov gs:[{exception_trapno_off}], al", // vector number from ISR stack
        "mov rax, rsp", // ISR stack, for SAVE_PF_USER_CONTEXT_ASM
        "mov rsp, gs:[{user_context_top_off}]",
        SAVE_PF_USER_CONTEXT_ASM!(),
        XSAVE_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        "mov rdi, [rsp]", // pass `thread_ctx`
        "mov rsi, cr2",   // not yet overwritten: no fault since
        "call {exception_handler}",
        "jmp done",
        // From the #PF stub, for kernel-mode page faults. On entry: rsp = ISR
        // stack [vector, error_code, rip, cs, rflags, rsp, ss], IF is clear, and
        // GS is the kernel's. The handlers try demand paging, then an
        // exception-table fixup, then panic.
        ".globl kernel_exception_callback",
        "kernel_exception_callback:",
        // The fault may hit inside `with_user_memory_access`; handle it with
        // SMAP on. `iretq` restores the interrupted RFLAGS.AC.
        "clac",
        "add rsp, 8",                       // skip vector number
        // Now stack: [error_code, rip, cs, rflags, rsp, ss]
        SAVE_CPU_CONTEXT_ASM!(),
        "mov rbp, rsp",
        "and rsp, -16",
        // [gs:cur_kernel_sp] holds a ThreadContext only while is_in_user is set.
        "cmp byte ptr gs:[{is_in_user_off}], 0",
        "je 6f",
        "mov rdi, gs:[{cur_kernel_sp_off}]",
        "mov rdi, [rdi]",                   // arg1: thread_ctx
        "mov rsi, rbp",                     // arg2: the saved kernel context
        "mov rdx, cr2",                     // arg3: cr2 (fault address)
        "call {kernel_exception_handler}",
        "jmp 7f",
        "6:",
        "mov rdi, cr2",                     // arg1: cr2
        "mov esi, [rbp + 120]",             // arg2: error_code
        "mov rdx, [rbp + 128]",             // arg3: faulting RIP
        "call {kernel_exception_handler_no_ctx}",
        "7:",
        // A non-zero rax is an exception-table fixup: resume there.
        "test rax, rax",
        "jz 5f",
        "mov [rbp + 128], rax",     // patch saved RIP (15 GPRs + error_code = 128)
        "5:",
        "mov rsp, rbp",
        RESTORE_CPU_CONTEXT_ASM!(),
        "iretq",
        "done:",
        // Clear first: from here on, a ThreadContext may no longer exist.
        "mov byte ptr gs:[{is_in_user_off}], 0",
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        "mov qword ptr gs:[{cur_kernel_sp_off}], 0",
        XRSTOR_ASM!({kernel_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {kernel_xsaved_off}),
        RESTORE_CALLEE_SAVED_REGISTERS_ASM!(),
        "ret",
        cur_kernel_sp_off = const { PerCpuVariablesAsm::cur_kernel_stack_ptr_offset() },
        cur_kernel_bp_off = const { PerCpuVariablesAsm::cur_kernel_base_ptr_offset() },
        user_context_top_off = const { PerCpuVariablesAsm::user_context_top_addr_offset() },
        kernel_xsave_area_off = const { PerCpuVariablesAsm::kernel_xsave_area_addr_offset() },
        user_xsave_area_off = const { PerCpuVariablesAsm::user_xsave_area_addr_offset() },
        xsave_mask_lo_off = const { PerCpuVariablesAsm::xsave_mask_lo_offset() },
        xsave_mask_hi_off = const { PerCpuVariablesAsm::xsave_mask_hi_offset() },
        kernel_xsaved_off = const { PerCpuVariablesAsm::kernel_xsaved_offset() },
        user_xsaved_off = const { PerCpuVariablesAsm::user_xsaved_offset() },
        USER_CONTEXT_SIZE = const core::mem::size_of::<PtRegs>(),
        scratch_off = const { PerCpuVariablesAsm::scratch_offset() },
        user_rflags_off = const { PerCpuVariablesAsm::user_rflags_offset() },
        exception_trapno_off = const { PerCpuVariablesAsm::exception_trapno_offset() },
        is_in_user_off = const { PerCpuVariablesAsm::is_in_user_offset() },
        init_handler = sym init_handler,
        reenter_handler = sym reenter_handler,
        syscall_handler = sym syscall_handler,
        exception_handler = sym exception_handler,
        kernel_exception_handler = sym kernel_exception_handler,
        kernel_exception_handler_no_ctx = sym kernel_exception_handler_no_ctx,
    );
}

unsafe extern "C" fn init_handler(thread_ctx: &ThreadContext) {
    // Safety: entered from user-mode setup; see `ThreadContext`.
    let ctx = unsafe { &mut *thread_ctx.ctx };
    if let ContinueOperation::Resume = thread_ctx.shim.init(ctx) {
        resume_user(ctx);
    }
}

unsafe extern "C" fn reenter_handler(thread_ctx: &ThreadContext) {
    // Safety: entered from user-mode setup; see `ThreadContext`.
    let ctx = unsafe { &mut *thread_ctx.ctx };
    if let ContinueOperation::Resume = thread_ctx.shim.reenter(ctx) {
        resume_user(ctx);
    }
}

unsafe extern "C" fn syscall_handler(thread_ctx: &ThreadContext) {
    // Safety: entered from user mode; see `ThreadContext`.
    let ctx = unsafe { &mut *thread_ctx.ctx };
    if !ctx.has_user_return_addresses() {
        return;
    }
    if let ContinueOperation::Resume = thread_ctx.shim.syscall(ctx) {
        resume_user(ctx);
    }
}

unsafe extern "C" fn exception_handler(thread_ctx: &ThreadContext, cr2: usize) {
    // Safety: entered from user mode; see `ThreadContext`.
    let ctx = unsafe { &mut *thread_ctx.ctx };
    let info = ExceptionInfo {
        exception: with_per_cpu_variables(|pcv| pcv.asm.exception()),
        error_code: ctx.orig_rax.trunc(),
        cr2,
        kernel_mode: false,
    };
    if let ContinueOperation::Resume = thread_ctx.shim.exception(ctx, &info) {
        resume_user(ctx);
    }
}

fn resume_user(ctx: &mut PtRegs) {
    if ctx.sanitize_for_user_return() {
        // Safety: sanitized for user mode.
        unsafe { switch_to_user(ctx) }
    }
    litebox_util_log::warn!("terminating thread with invalid user return context");
}

/// A kernel page fault outside `run_thread_arch`, where the shim cannot be
/// called. Returns the exception-table fixup address, or panics.
unsafe extern "C" fn kernel_exception_handler_no_ctx(
    cr2: usize,
    error_code: usize,
    faulting_rip: usize,
) -> usize {
    search_exception_tables(faulting_rip).unwrap_or_else(|| {
        panic!(
            "EXCEPTION: PAGE FAULT outside run_thread_arch (no ThreadContext)\n\
             Accessed Address: {cr2:#x}\n\
             Error Code: {error_code:#x}\n\
             Faulting RIP: {faulting_rip:#x}",
        )
    })
}

/// May interrupt a shim handler borrowing the user context. Pass a separate
/// kernel-frame copy so the shim cannot alter the kernel's return state.
/// Returns 0 to retry, a fixup address to recover, or panics if neither applies.
unsafe extern "C" fn kernel_exception_handler(
    thread_ctx: &ThreadContext,
    regs: &PtRegs,
    cr2: usize,
) -> usize {
    let info = ExceptionInfo {
        exception: Exception::PAGE_FAULT,
        error_code: regs.orig_rax.trunc(),
        cr2,
        kernel_mode: true,
    };
    match thread_ctx.shim.exception(&mut regs.clone(), &info) {
        ContinueOperation::Resume => 0,
        ContinueOperation::Terminate => search_exception_tables(regs.rip).unwrap_or_else(|| {
            panic!(
                "EXCEPTION: PAGE FAULT\n\
                     Accessed Address: {cr2:#x}\n\
                     Error Code: {:#x}\n\
                     Faulting RIP: {:#x}",
                info.error_code, regs.rip,
            )
        }),
    }
}

/// Enter user mode with `ctx`.
///
/// # Safety
/// `ctx` must be a valid user context.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_user(_ctx: &PtRegs) -> ! {
    // rustfmt would put spaces inside the braces, breaking `stringify!`.
    #[rustfmt::skip]
    core::arch::naked_asm!(
        "switch_to_user_start:",
        "cli",
        XRSTOR_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
        "mov rsp, rdi",
        RESTORE_CPU_CONTEXT_ASM!(),
        "swapgs",
        "iretq",
        "switch_to_user_end:",
        user_xsave_area_off = const { PerCpuVariablesAsm::user_xsave_area_addr_offset() },
        xsave_mask_lo_off = const { PerCpuVariablesAsm::xsave_mask_lo_offset() },
        xsave_mask_hi_off = const { PerCpuVariablesAsm::xsave_mask_hi_offset() },
        user_xsaved_off = const { PerCpuVariablesAsm::user_xsaved_offset() },
    );
}
