// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in VTL1 kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]

use crate::{host::per_cpu_variables::PerCpuVariablesAsm, mshv::vsm::Vtl0KernelInfo};
use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64},
};
use hashbrown::HashMap;
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, PageManagementProvider,
    Punchthrough, PunchthroughProvider, PunchthroughToken, RawMutex as _, RawMutexProvider,
    RawPointerProvider, StdioProvider, TimeProvider, UnblockedOrTimedOut,
    page_mgmt::DeallocationError,
};
use litebox::{
    mm::linux::{PAGE_SIZE, PageRange},
    platform::page_mgmt::FixedAddressBehavior,
    shim::ContinueOperation,
    utils::TruncateExt,
};
use litebox_common_linux::{
    PunchthroughSyscall,
    errno::Errno,
    vmap::{
        PhysPageAddr, PhysPageAddrArray, PhysPageMapInfo, PhysPageMapPermissions, PhysPointerError,
        VmapManager,
    },
};
use x86_64::{
    VirtAddr,
    structures::paging::{
        PageOffset, PageSize, PageTableFlags, PhysFrame, Size4KiB, frame::PhysFrameRange,
        mapper::MapToError,
    },
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

pub mod arch;
pub mod host;
pub mod mm;
pub mod mshv;

pub mod syscall_entry;

/// Allocate a zeroed `Box<T>` directly on the heap, avoiding stack intermediaries
/// for large types (e.g., 4096-byte `HekiPage`).
///
/// This is safe because `T: FromBytes` guarantees that all-zero bytes are a valid `T`.
///
/// # Panics
///
/// Panics if `T` is a zero-sized type, since `alloc_zeroed` with a zero-sized
/// layout is undefined behavior.
fn box_new_zeroed<T: FromBytes>() -> alloc::boxed::Box<T> {
    assert!(
        core::mem::size_of::<T>() > 0,
        "box_new_zeroed does not support zero-sized types"
    );
    let layout = core::alloc::Layout::new::<T>();
    // Safety: layout has a non-zero size and correct alignment for T.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    // Safety: ptr is a valid, zeroed, properly aligned heap allocation for T.
    // T: FromBytes guarantees all-zero is a valid bit pattern.
    unsafe { alloc::boxed::Box::from_raw(ptr) }
}

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// Special page table ID for the base (kernel-only) page table.
/// No real physical frame has address 0, so this is a safe sentinel.
pub const BASE_PAGE_TABLE_ID: usize = 0;

/// Maximum virtual address (exclusive) for user-space allocations.
/// This is set to (1 << 47) - PAGE_SIZE (upper limit of 4-level paging).
const USER_ADDR_MAX: usize = 0x7FFF_FFFF_F000;

/// Size of the user address space range.
const USER_ADDR_RANGE_SIZE: usize = 0x1000_0000_0000; // 16 TiB

/// Minimum virtual address for user-space allocations.
///
/// Kernel memory uses low addresses (identity mapped: VA == PA).
/// User memory uses addresses in range [`USER_ADDR_MIN`, `USER_ADDR_MAX`).
/// This separation allows easy identification during cleanup and supports
/// future designs where kernel VAs may be in higher addresses.
const USER_ADDR_MIN: usize = USER_ADDR_MAX - USER_ADDR_RANGE_SIZE;

/// Manages base and task page tables.
///
/// This struct maintains:
/// - A base page table (ID = 0) containing only kernel mappings
/// - Multiple task page tables (ID > 0) containing kernel + user-space mappings
/// - The current page table is determined by reading the CR3 register
///
/// # Security Note: No KPTI
///
/// Currently, task page tables include full VTL1 kernel mappings for syscall handling.
/// This is similar to pre-Meltdown Linux kernels. We do NOT implement Kernel Page Table
/// Isolation (KPTI), which would use separate page tables:
/// - **User PT**: User mappings + minimal kernel trampoline (entry/exit code only)
/// - **Kernel PT**: Full kernel mappings + user mappings
///
/// Future work could implement KPTI-style isolation to reduce the kernel attack surface
/// exposed to user TAs, mitigating potential side-channel attacks.
pub struct PageTableManager {
    /// The base page table, containing only VTL1 kernel mappings (no user-space).
    base_page_table: mm::PageTable<PAGE_SIZE>,
    /// Cached physical frame of the base page table (for fast CR3 comparison).
    base_page_table_frame: PhysFrame<Size4KiB>,
    /// Task page tables keyed by their P4 frame start address (the page table ID).
    task_page_tables: spin::Mutex<HashMap<usize, alloc::boxed::Box<mm::PageTable<PAGE_SIZE>>>>,
}

impl PageTableManager {
    /// The minimum virtual address for user-space allocations.
    pub const USER_ADDR_MIN: usize = USER_ADDR_MIN;
    /// The maximum virtual address (exclusive) for user-space allocations.
    pub const USER_ADDR_MAX: usize = USER_ADDR_MAX;

    /// Creates a new page table manager with the given base page table.
    fn new(base_pt: mm::PageTable<PAGE_SIZE>) -> Self {
        let base_frame = base_pt.get_physical_frame();
        Self {
            base_page_table: base_pt,
            base_page_table_frame: base_frame,
            task_page_tables: spin::Mutex::new(HashMap::new()),
        }
    }

    /// Returns a reference to the current page table based on the CR3 register.
    ///
    /// This reads the current CR3 value and finds the matching page table.
    /// If CR3 matches the base page table, returns that. Otherwise, it
    /// looks up the task page table by physical frame.
    ///
    /// # Panics
    ///
    /// Panics if CR3 contains an unknown page table address (should never happen
    /// in normal operation).
    #[inline]
    pub fn current_page_table(&self) -> &mm::PageTable<PAGE_SIZE> {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();

        // Fast path: check base page table first (most common case)
        if self.base_page_table_frame == cr3_frame {
            return &self.base_page_table;
        }

        let cr3_id: usize = cr3_frame.start_address().as_u64().truncate();
        let task_pts = self.task_page_tables.lock();
        if let Some(pt) = task_pts.get(&cr3_id) {
            // SAFETY: Three invariants guarantee this reference remains valid:
            // 1. The PageTable is Box-allocated, so HashMap rehashing does not
            //    move the PageTable itself (only the Box pointer moves).
            // 2. This page table is the current CR3, so `delete_task_page_table`
            //    will refuse to remove it (returns EBUSY).
            // 3. The PageTableManager is 'static, so neither it nor the HashMap
            //    will be deallocated.
            let pt_ref: &mm::PageTable<PAGE_SIZE> = pt;
            return unsafe { &*core::ptr::from_ref(pt_ref) };
        }

        // CR3 doesn't match any known page table - this shouldn't happen
        unreachable!(
            "CR3 contains unknown page table: {:?}",
            cr3_frame.start_address()
        );
    }

    /// Returns the ID of the current page table based on the CR3 register.
    ///
    /// Returns `BASE_PAGE_TABLE_ID` (0) if the base page table is active,
    /// or the task page table ID if a task page table is active.
    ///
    /// # Panics
    ///
    /// Panics if CR3 contains an unknown page table address (should never happen
    /// in normal operation).
    #[inline]
    pub fn current_page_table_id(&self) -> usize {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();

        // Fast path: check base page table first
        if self.base_page_table_frame == cr3_frame {
            return BASE_PAGE_TABLE_ID;
        }

        // The task page table ID is the start address of the P4 frame.
        cr3_frame.start_address().as_u64().truncate()
    }

    /// Returns `true` if the base page table is currently active.
    #[inline]
    pub fn is_base_page_table_active(&self) -> bool {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        self.base_page_table_frame == cr3_frame
    }

    /// Loads the base page table by updating CR3.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The base page table contains valid mappings for all memory that will be accessed
    ///   after the switch (including the code being executed and stack)
    /// - No references to user-space memory are held across the switch
    pub unsafe fn load_base(&self) {
        self.base_page_table.load();
    }

    /// Loads the specified task page table by updating CR3.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The target page table contains valid mappings for all memory that will be accessed
    ///   after the switch (including the code being executed and stack)
    /// - No references to the previous address space's memory are held across the switch
    ///
    /// # Returns
    ///
    /// -`Ok(())` if the switch was successful
    /// - `Err(Errno::ENOENT)` if the specified page table ID does not exist.
    /// - `Err(Errno::EINVAL)` if the specified page table ID is the base page table ID.
    pub unsafe fn load_task(&self, task_pt_id: usize) -> Result<(), Errno> {
        if task_pt_id == BASE_PAGE_TABLE_ID {
            // this function should not be used to load the base page table
            return Err(Errno::EINVAL);
        }

        let task_pts = self.task_page_tables.lock();
        if let Some(pt) = task_pts.get(&task_pt_id) {
            pt.load();
            Ok(())
        } else {
            Err(Errno::ENOENT)
        }
    }

    /// Creates a new task page table and returns its ID.
    ///
    /// The new page table is initialized with the VTL1 kernel memory mapped
    /// for proper syscall handling.
    ///
    /// # Arguments
    ///
    /// * `vtl1_phys_frame_range` - The physical frame range of VTL1 kernel memory to map
    ///
    /// # Returns
    ///
    /// The ID of the newly created task page table (its P4 frame start address),
    /// or `Err(Errno::ENOMEM)` if allocation fails.
    pub fn create_task_page_table(
        &self,
        vtl1_phys_frame_range: PhysFrameRange<Size4KiB>,
    ) -> Result<usize, Errno> {
        let pt = unsafe { mm::PageTable::new_top_level() };
        if pt
            .map_phys_frame_range(
                vtl1_phys_frame_range,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .is_err()
        {
            return Err(Errno::ENOMEM);
        }

        let pt = alloc::boxed::Box::new(pt);
        let task_pt_id: usize = pt.get_physical_frame().start_address().as_u64().truncate();

        let mut task_pts = self.task_page_tables.lock();
        task_pts.insert(task_pt_id, pt);

        Ok(task_pt_id)
    }

    /// Deletes a task page table by its ID.
    ///
    /// This function:
    /// 1. Unmaps all non-kernel pages (returning physical frames to the allocator)
    /// 2. Cleans up page table structure frames
    /// 3. Drops the page table (deallocating the top-level frame)
    ///
    /// # Arguments
    ///
    /// * `task_pt_id` - The ID of the task page table to delete
    ///
    /// # Safety
    ///
    /// The caller must ensure that no references or pointers to memory mapped
    /// by this page table are held after deletion.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the page table was successfully deleted
    /// - `Err(Errno::EINVAL)` if the page table ID is the base page table
    /// - `Err(Errno::ENOENT)` if the page table ID does not exist
    /// - `Err(Errno::EBUSY)` if the page table is currently active (switch away first)
    pub unsafe fn delete_task_page_table(&self, task_pt_id: usize) -> Result<(), Errno> {
        if task_pt_id == BASE_PAGE_TABLE_ID {
            return Err(Errno::EINVAL);
        }

        let mut task_pts = self.task_page_tables.lock();

        // Check CR3 under the same lock to avoid TOCTOU with the removal below.
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        let cr3_id: usize = cr3_frame.start_address().as_u64().truncate();
        if cr3_id == task_pt_id {
            return Err(Errno::EBUSY);
        }

        if let Some(pt) = task_pts.remove(&task_pt_id) {
            drop(task_pts);

            // Safety: We're about to delete this page table, so it's safe to unmap all pages.
            unsafe {
                pt.cleanup_user_mappings(Self::USER_ADDR_MIN, Self::USER_ADDR_MAX);
            }
            // The PageTable's Drop impl will deallocate the top-level (P4) frame
            Ok(())
        } else {
            Err(Errno::ENOENT)
        }
    }
}

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    host_and_task: core::marker::PhantomData<Host>,
    page_table_manager: PageTableManager,
    vtl1_phys_frame_range: PhysFrameRange<Size4KiB>,
    vtl0_kernel_info: Vtl0KernelInfo,
}

pub struct LinuxPunchthroughToken<'a, Host: HostInterface> {
    punchthrough: PunchthroughSyscall<'a, LinuxKernel<Host>>,
    host: core::marker::PhantomData<Host>,
}

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
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

impl<'a, Host: HostInterface> PunchthroughToken for LinuxPunchthroughToken<'a, Host> {
    type Punchthrough = PunchthroughSyscall<'a, LinuxKernel<Host>>;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        let r = match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                unsafe { litebox_common_linux::wrfsbase(addr) };
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase => Ok(unsafe { litebox_common_linux::rdfsbase() }),
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(litebox::platform::PunchthroughError::Failure(e)),
        }
    }
}

impl<Host: HostInterface> PunchthroughProvider for LinuxKernel<Host> {
    type PunchthroughToken<'a> = LinuxPunchthroughToken<'a, Host>;

    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(LinuxPunchthroughToken {
            punchthrough,
            host: core::marker::PhantomData,
        })
    }
}

impl<Host: HostInterface> LinuxKernel<Host> {
    /// This function initializes the VTL1 kernel platform (mostly the kernel page table).
    /// `init_page_table_addr` specifies the physical address of the initial page table prepared by the VTL0 kernel.
    /// `phys_start` and `phys_end` specify the entire range of physical memory that is reserved for the VTL1 kernel.
    /// Since the VTL0 kernel does not fully map this physical address range to the initial page table, this function
    /// creates and maintains a kernel page table covering the entire VTL1 physical memory range. The caller must
    /// ensure that the heap has enough space for this page table creation.
    ///
    /// # Panics
    ///
    /// Panics if the heap is not initialized yet or it does not have enough space to allocate page table entries.
    /// Panics if `phys_start` or `phys_end` is invalid
    pub fn new(
        init_page_table_addr: x86_64::PhysAddr,
        phys_start: x86_64::PhysAddr,
        phys_end: x86_64::PhysAddr,
    ) -> &'static Self {
        let pt = unsafe { mm::PageTable::new(init_page_table_addr) };
        let physframe_start = PhysFrame::containing_address(phys_start);
        let physframe_end = PhysFrame::containing_address(phys_end.align_up(Size4KiB::SIZE));
        if pt
            .map_phys_frame_range(
                PhysFrame::range(physframe_start, physframe_end),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .is_err()
        {
            panic!("Failed to map VTL1 physical memory");
        }

        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host_and_task: core::marker::PhantomData,
            page_table_manager: PageTableManager::new(pt),
            vtl1_phys_frame_range: PhysFrame::range(physframe_start, physframe_end),
            vtl0_kernel_info: Vtl0KernelInfo::new(),
        }))
    }

    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    /// This function maps VTL0 physical page frames containing the physical addresses
    /// from `phys_start` to `phys_end` to the VTL1 kernel page table. It internally page aligns
    /// the input addresses to ensure the mapped memory area covers the entire input addresses
    /// at the page level. It returns a page-aligned address (as `mmap` does) and the length of the mapped memory.
    ///
    /// Note: VTL0 physical memory is external/remote memory that this Rust binary doesn't own,
    /// so mapping it doesn't create aliasing issues within the Rust memory model.
    fn map_vtl0_phys_range(
        &self,
        phys_start: x86_64::PhysAddr,
        phys_end: x86_64::PhysAddr,
        flags: PageTableFlags,
    ) -> Result<(*mut u8, usize), MapToError<Size4KiB>> {
        let frame_range = PhysFrame::range(
            PhysFrame::containing_address(phys_start),
            PhysFrame::containing_address(phys_end.align_up(Size4KiB::SIZE)),
        );

        // ensure the input address range does not overlap with VTL1 memory
        if frame_range.start < self.vtl1_phys_frame_range.end
            && self.vtl1_phys_frame_range.start < frame_range.end
        {
            return Err(MapToError::FrameAllocationFailed);
        }

        Ok((
            self.page_table_manager
                .current_page_table()
                .map_phys_frame_range(frame_range, flags)?,
            usize::try_from(frame_range.len()).unwrap() * PAGE_SIZE,
        ))
    }

    /// This function unmaps VTL0 pages from the page table.
    ///
    /// Allocator does not allocate memory frames for VTL0 pages, so frame deallocation is not needed.
    ///
    /// Note: VTL0 physical memory is external memory not owned by LiteBox (similar to MMIO).
    /// LiteBox accesses it by creating a temporary non-shared mapping, copying data to/from a
    /// LiteBox-owned buffer, and unmapping immediately. No Rust references are created to the
    /// mapped VTL0 memory; all accesses use raw pointer operations (read_volatile /
    /// copy_nonoverlapping) to avoid violating Rust's aliasing model.
    fn unmap_vtl0_pages(
        &self,
        page_addr: *const u8,
        length: usize,
    ) -> Result<(), DeallocationError> {
        let page_addr = x86_64::VirtAddr::new(page_addr as u64);
        if page_addr.page_offset() != PageOffset::new(0) {
            return Err(DeallocationError::Unaligned);
        }
        unsafe {
            self.page_table_manager.current_page_table().unmap_pages(
                PageRange::<PAGE_SIZE>::new(
                    page_addr.as_u64().truncate(),
                    (page_addr + length as u64)
                        .align_up(Size4KiB::SIZE)
                        .as_u64()
                        .truncate(),
                )
                .ok_or(DeallocationError::Unaligned)?,
                false,
                true,
            )
        }
    }

    /// Map a VTL0 physical range and return a guard that unmaps on drop.
    fn map_vtl0_guard(
        &self,
        phys_addr: x86_64::PhysAddr,
        size: u64,
        flags: PageTableFlags,
    ) -> Option<Vtl0MappedGuard<'_, Host>> {
        let (page_addr, page_aligned_length) = self
            .map_vtl0_phys_range(phys_addr, phys_addr + size, flags)
            .ok()?;
        let page_offset: usize = (phys_addr - phys_addr.align_down(Size4KiB::SIZE)).truncate();
        Some(Vtl0MappedGuard {
            owner: self,
            page_addr,
            page_aligned_length,
            ptr: page_addr.wrapping_add(page_offset),
            size: size.truncate(),
        })
    }

    /// This function copies data from VTL0 physical memory to the VTL1 kernel through `Box`.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address
    pub unsafe fn copy_from_vtl0_phys<T: FromBytes + Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
    ) -> Option<alloc::boxed::Box<T>> {
        if core::mem::size_of::<T>() == 0 {
            return Some(alloc::boxed::Box::new(T::new_zeroed()));
        }

        let src_guard = self.map_vtl0_guard(
            phys_addr,
            core::mem::size_of::<T>() as u64,
            PageTableFlags::PRESENT,
        )?;

        let mut boxed = box_new_zeroed::<T>();
        // Use memcpy_fallible instead of ptr::copy_nonoverlapping to handle
        // the race where another core unmaps this page (via a shared page
        // table) between map_vtl0_guard and the copy.  The mapping is valid
        // at this point, so a fault is not expected in the common case.
        // TODO: Once VTL0 page-range locking is in place, this fallible copy
        // may become unnecessary since the lock would prevent concurrent
        // unmapping.  It could still serve as a safety net against callers
        // that forget to acquire the lock.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                core::ptr::from_mut::<T>(boxed.as_mut()).cast(),
                src_guard.ptr,
                src_guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault copying from VTL0 mapped page");

        result.ok().map(|()| boxed)
    }

    /// This function copies data from the VTL1 kernel to VTL0 physical memory.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address
    pub unsafe fn copy_to_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        value: &T,
    ) -> bool {
        if core::mem::size_of::<T>() == 0 {
            return true;
        }

        let Some(dst_guard) = self.map_vtl0_guard(
            phys_addr,
            core::mem::size_of::<T>() as u64,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        ) else {
            return false;
        };

        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                dst_guard.ptr,
                core::ptr::from_ref::<T>(value).cast::<u8>(),
                dst_guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault copying to VTL0 mapped page");
        result.is_ok()
    }

    /// This function copies a slice from the VTL1 kernel to VTL0 physical memory.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address.
    pub unsafe fn copy_slice_to_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        value: &[T],
    ) -> bool {
        if core::mem::size_of_val(value) == 0 {
            return true;
        }

        let Some(dst_guard) = self.map_vtl0_guard(
            phys_addr,
            core::mem::size_of_val(value) as u64,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        ) else {
            return false;
        };

        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                dst_guard.ptr,
                value.as_ptr().cast::<u8>(),
                dst_guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault copying to VTL0 mapped page");
        result.is_ok()
    }

    /// This function copies a slice from VTL0 physical memory to the VTL1 kernel.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address.
    pub unsafe fn copy_slice_from_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        buf: &mut [T],
    ) -> bool {
        if core::mem::size_of_val(buf) == 0 {
            return true;
        }

        let Some(src_guard) = self.map_vtl0_guard(
            phys_addr,
            core::mem::size_of_val(buf) as u64,
            PageTableFlags::PRESENT,
        ) else {
            return false;
        };

        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                buf.as_mut_ptr().cast::<u8>(),
                src_guard.ptr,
                src_guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault copying from VTL0 mapped page");
        result.is_ok()
    }

    /// Create a new task page table for VTL1 user space and returns its ID.
    ///
    /// See [`PageTableManager`] for security notes on KPTI.
    ///
    /// # Returns
    ///
    /// The ID of the newly created task page table, or `Err(Errno)` on failure.
    pub fn create_task_page_table(&self) -> Result<usize, Errno> {
        self.page_table_manager
            .create_task_page_table(self.vtl1_phys_frame_range)
    }

    /// Deletes a task page table by its ID.
    ///
    /// This function:
    /// 1. Unmaps all non-kernel pages (returning physical frames to the allocator)
    /// 2. Cleans up page table structure frames
    /// 3. Drops the page table (deallocating the top-level frame)
    ///
    /// Frames within the VTL1 kernel physical memory range are not deallocated
    /// (they belong to the kernel). Only user-allocated frames are returned to
    /// the allocator.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no references or pointers to memory mapped
    /// by this page table are held after deletion.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if successful
    /// - `Err(Errno::EINVAL)` if the page table is the base page table
    /// - `Err(Errno::ENOENT)` if the page table doesn't exist
    /// - `Err(Errno::EBUSY)` if the page table is currently active
    pub unsafe fn delete_task_page_table(&self, task_pt_id: usize) -> Result<(), Errno> {
        // Safety: caller guarantees no dangling references
        unsafe { self.page_table_manager.delete_task_page_table(task_pt_id) }
    }

    /// Switch to the specified page table.
    ///
    /// Use `BASE_PAGE_TABLE_ID` (0) for the base page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The target page table contains valid mappings for all memory that will be accessed
    ///   after the switch (including the code being executed and stack)
    /// - No references to the previous address space's memory are held across the switch
    ///
    /// # Returns
    ///
    /// `Ok(())` if the switch was successful, or `Err(Errno::ENOENT)` if the page table
    /// ID does not exist.
    pub unsafe fn switch_page_table(&self, pt_id: usize) -> Result<(), Errno> {
        if pt_id == BASE_PAGE_TABLE_ID {
            // Safety: caller guarantees safe switch conditions
            unsafe { self.page_table_manager.load_base() };
            Ok(())
        } else {
            // Safety: caller guarantees safe switch conditions
            unsafe { self.page_table_manager.load_task(pt_id) }
        }
    }

    /// Returns the ID of the current page table.
    pub fn current_page_table_id(&self) -> usize {
        self.page_table_manager.current_page_table_id()
    }

    /// Returns a reference to the page table manager.
    pub fn page_table_manager(&self) -> &PageTableManager {
        &self.page_table_manager
    }

    /// Enable syscall support in the platform.
    pub fn enable_syscall_support() {
        syscall_entry::init();
    }
}

/// RAII guard that unmaps VTL0 physical pages when dropped.
struct Vtl0MappedGuard<'a, Host: HostInterface> {
    owner: &'a LinuxKernel<Host>,
    page_addr: *mut u8,
    page_aligned_length: usize,
    ptr: *mut u8,
    size: usize,
}

impl<Host: HostInterface> Drop for Vtl0MappedGuard<'_, Host> {
    fn drop(&mut self) {
        assert!(
            self.owner
                .unmap_vtl0_pages(self.page_addr, self.page_aligned_length)
                .is_ok(),
            "Failed to unmap VTL0 pages"
        );
    }
}

impl<Host: HostInterface> RawMutexProvider for LinuxKernel<Host> {
    type RawMutex = RawMutex<Host>;
}

/// An implementation of [`litebox::platform::RawMutex`]
pub struct RawMutex<Host: HostInterface> {
    inner: AtomicU32,
    host: core::marker::PhantomData<fn(Host) -> Host>,
}

unsafe impl<Host: HostInterface> Send for RawMutex<Host> {}
unsafe impl<Host: HostInterface> Sync for RawMutex<Host> {}

/// TODO: common mutex implementation could be moved to a shared crate
impl<Host: HostInterface> litebox::platform::RawMutex for RawMutex<Host> {
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
    ) -> Result<litebox::platform::UnblockedOrTimedOut, ImmediatelyWokenUp> {
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
        loop {
            // No need to wait if the value already changed.
            if self
                .underlying_atomic()
                .load(core::sync::atomic::Ordering::Relaxed)
                != val
            {
                return Err(ImmediatelyWokenUp);
            }

            let ret = Host::block_or_maybe_timeout(&self.inner, val, timeout);

            match ret {
                Ok(()) => {
                    return Ok(UnblockedOrTimedOut::Unblocked);
                }
                Err(Errno::EAGAIN) => {
                    // If the futex value does not match val, then the call fails
                    // immediately with the error EAGAIN.
                    return Err(ImmediatelyWokenUp);
                }
                Err(Errno::EINTR) => {
                    // return Err(ImmediatelyWokenUp);
                    todo!("EINTR");
                }
                Err(Errno::ETIMEDOUT) => {
                    return Ok(UnblockedOrTimedOut::TimedOut);
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }
    }
}

impl<Host: HostInterface> DebugLogProvider for LinuxKernel<Host> {
    fn debug_log_print(&self, msg: &str) {
        Host::log(msg);
    }
}

/// An implementation of [`litebox::platform::Instant`]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

/// An implementation of [`litebox::platform::SystemTime`]
pub struct SystemTime();

impl<Host: HostInterface> TimeProvider for LinuxKernel<Host> {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn current_time(&self) -> Self::SystemTime {
        unimplemented!()
    }
}

impl litebox::platform::Instant for Instant {
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

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime();

    fn duration_since(
        &self,
        _earlier: &Self,
    ) -> Result<core::time::Duration, core::time::Duration> {
        unimplemented!()
    }
}

impl<Host: HostInterface> IPInterfaceProvider for LinuxKernel<Host> {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        match Host::send_ip_packet(packet) {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!()
                }
                Ok(())
            }
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        match Host::receive_ip_packet(packet) {
            Ok(n) => Ok(n),
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }
}

/// Platform-Host Interface
pub trait HostInterface: 'static {
    /// Page allocation from host.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)>;
    // TODO: leave this for now for testing. LVBS does not allow dynamic memory allocation,
    // so it should be no-op or removed.

    /// Returns the memory back to host.
    ///
    /// Note host should know the size of allocated memory and needs to check the validity
    /// of the given address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by this [`Self::alloc`].
    unsafe fn free(addr: usize);
    // TODO: leave this for now for testing. LVBS does not allow dynamic memory allocation,
    // so it should be no-op or removed.

    /// Exit
    ///
    /// Exit allows to come back to handle some requests from host,
    /// but it should not return back to the caller.
    fn exit() -> !;
    // TODO: leave this for now for testing. LVBS does exit (or return) but it resumes execution
    // from this instruction point (i.e., there is no separate entry point unlike SNP).

    /// Terminate LiteBox
    fn terminate(reason_set: u64, reason_code: u64) -> !;
    // TODO: leave this for now for testing. LVBS does not terminate, so it should be no-op or
    // removed.

    // TODO: leave this for now for testing. We might need this if we plan to run Linux apps inside VTL1.

    fn wake_many(mutex: &AtomicU32, n: usize) -> Result<usize, Errno>;

    fn block_or_maybe_timeout(
        mutex: &AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno>;

    /// For Network
    fn send_ip_packet(packet: &[u8]) -> Result<usize, Errno>;

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, Errno>;

    /// For Debugging
    fn log(msg: &str);

    /// Switch
    ///
    /// Switch enables a context switch from VTL1 kernel to VTL0 kernel while passing a value
    /// through a CPU register. VTL1 kernel will execute the next instruction of `switch()`
    /// when VTL0 kernel switches back to VTL1 kernel.
    fn switch(result: u64) -> !;
}

impl<Host: HostInterface, const ALIGN: usize> PageManagementProvider<ALIGN> for LinuxKernel<Host> {
    // Use a high address for user space to separate from kernel identity-mapped memory.
    // Kernel memory uses low addresses (identity mapped: VA == PA).
    // User memory allocated via mmap uses high addresses (VA >= TASK_ADDR_MIN).
    // This allows easy identification of user vs kernel pages during cleanup.
    const TASK_ADDR_MIN: usize = USER_ADDR_MIN;
    const TASK_ADDR_MAX: usize = USER_ADDR_MAX;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let range = PageRange::new(suggested_range.start, suggested_range.end)
            .ok_or(litebox::platform::page_mgmt::AllocationError::Unaligned)?;
        let current_pt = self.page_table_manager.current_page_table();
        match fixed_address_behavior {
            FixedAddressBehavior::Hint | FixedAddressBehavior::NoReplace => {}
            FixedAddressBehavior::Replace => {
                // Clear the existing mappings first.
                unsafe { current_pt.unmap_pages(range, true, true).unwrap() };
            }
        }
        let flags = u32::from(initial_permissions.bits())
            | if can_grow_down {
                litebox::mm::linux::VmFlags::VM_GROWSDOWN.bits()
            } else {
                0
            };
        let flags = litebox::mm::linux::VmFlags::from_bits(flags).unwrap();
        Ok(current_pt.map_pages(range, flags, populate_pages_immediately))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::DeallocationError::Unaligned)?;
        unsafe {
            self.page_table_manager
                .current_page_table()
                .unmap_pages(range, true, true)
        }
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<UserMutPtr<u8>, litebox::platform::page_mgmt::RemapError> {
        let old_range = PageRange::new(old_range.start, old_range.end)
            .ok_or(litebox::platform::page_mgmt::RemapError::Unaligned)?;
        let new_range = PageRange::new(new_range.start, new_range.end)
            .ok_or(litebox::platform::page_mgmt::RemapError::Unaligned)?;
        if old_range.start.max(new_range.start) <= old_range.end.min(new_range.end) {
            return Err(litebox::platform::page_mgmt::RemapError::Overlapping);
        }
        unsafe {
            self.page_table_manager
                .current_page_table()
                .remap_pages(old_range, new_range)
        }
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::PermissionUpdateError::Unaligned)?;
        let new_flags =
            litebox::mm::linux::VmFlags::from_bits(new_permissions.bits().into()).unwrap();
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

impl<Host: HostInterface> litebox::mm::linux::VmemPageFaultHandler for LinuxKernel<Host> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: litebox::mm::linux::VmFlags,
        error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unsafe {
            self.page_table_manager
                .current_page_table()
                .handle_page_fault(fault_addr, flags, error_code)
        }
    }

    fn access_error(error_code: u64, flags: litebox::mm::linux::VmFlags) -> bool {
        mm::PageTable::<PAGE_SIZE>::access_error(error_code, flags)
    }
}

impl<Host: HostInterface> StdioProvider for LinuxKernel<Host> {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        unimplemented!()
    }

    fn write_to(
        &self,
        _stream: litebox::platform::StdioOutStream,
        _buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        unimplemented!()
    }

    fn is_a_tty(&self, _stream: litebox::platform::StdioStream) -> bool {
        unimplemented!()
    }
}

impl<Host: HostInterface> litebox::platform::SystemInfoProvider for LinuxKernel<Host> {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        unimplemented!()
    }
}

/// Checks whether the given physical addresses are contiguous with respect to ALIGN.
///
/// Note: This is a temporary check to let `VmapManager` work with this platform
/// which does not yet support virtually contiguous mapping of non-contiguous physical pages
/// (for now, it maps physical pages with a fixed offset).
#[cfg(feature = "optee_syscall")]
fn check_contiguity<const ALIGN: usize>(
    addrs: &[PhysPageAddr<ALIGN>],
) -> Result<(), PhysPointerError> {
    for window in addrs.windows(2) {
        let first = window[0].as_usize();
        let second = window[1].as_usize();
        if second != first.checked_add(ALIGN).ok_or(PhysPointerError::Overflow)? {
            return Err(PhysPointerError::NonContiguousPages);
        }
    }
    Ok(())
}

#[cfg(feature = "optee_syscall")]
impl<Host: HostInterface, const ALIGN: usize> VmapManager<ALIGN> for LinuxKernel<Host> {
    unsafe fn vmap(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<PhysPageMapInfo<ALIGN>, PhysPointerError> {
        // TODO: Remove this check once this platform supports virtually contiguous
        // non-contiguous physical page mapping.
        check_contiguity(pages)?;

        if pages.is_empty() {
            return Err(PhysPointerError::InvalidPhysicalAddress(0));
        }
        let phys_start = x86_64::PhysAddr::new(pages[0].as_usize() as u64);
        let phys_end = x86_64::PhysAddr::new(
            pages
                .last()
                .unwrap()
                .as_usize()
                .checked_add(ALIGN)
                .ok_or(PhysPointerError::Overflow)? as u64,
        );
        let frame_range = if ALIGN == PAGE_SIZE {
            PhysFrame::range(
                PhysFrame::<Size4KiB>::containing_address(phys_start),
                PhysFrame::<Size4KiB>::containing_address(phys_end),
            )
        } else {
            unimplemented!("ALIGN other than 4KiB is not supported yet")
        };

        let mut flags = PageTableFlags::PRESENT;
        if perms.contains(PhysPageMapPermissions::WRITE) {
            flags |= PageTableFlags::WRITABLE;
        }

        if let Ok(page_addr) = self
            .page_table_manager
            .current_page_table()
            .map_phys_frame_range(frame_range, flags)
        {
            Ok(PhysPageMapInfo {
                base: page_addr,
                size: pages.len() * ALIGN,
            })
        } else {
            Err(PhysPointerError::InvalidPhysicalAddress(
                pages[0].as_usize(),
            ))
        }
    }

    unsafe fn vunmap(&self, vmap_info: PhysPageMapInfo<ALIGN>) -> Result<(), PhysPointerError> {
        if ALIGN == PAGE_SIZE {
            let Some(page_range) = PageRange::<PAGE_SIZE>::new(
                vmap_info.base as usize,
                vmap_info.base.wrapping_add(vmap_info.size) as usize,
            ) else {
                return Err(PhysPointerError::UnalignedPhysicalAddress(
                    vmap_info.base as usize,
                    ALIGN,
                ));
            };
            unsafe {
                self.page_table_manager
                    .current_page_table()
                    .unmap_pages(page_range, false, true)
                    .map_err(|_| PhysPointerError::Unmapped(vmap_info.base as usize))
            }
        } else {
            unimplemented!("ALIGN other than 4KiB is not supported yet")
        }
    }

    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        if pages.is_empty() {
            return Ok(());
        }
        let start_address = self.vtl1_phys_frame_range.start.start_address().as_u64();
        let end_address = self.vtl1_phys_frame_range.end.start_address().as_u64();
        for page in pages {
            let addr = page.as_usize() as u64;
            // a physical page belonging to LiteBox (VTL1) should not be used for `vmap`
            if addr >= start_address && addr < end_address {
                return Err(PhysPointerError::InvalidPhysicalAddress(page.as_usize()));
            }
        }
        Ok(())
    }

    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        let phys_start = x86_64::PhysAddr::new(pages[0].as_usize() as u64);
        let phys_end = x86_64::PhysAddr::new(
            pages
                .last()
                .unwrap()
                .as_usize()
                .checked_add(ALIGN)
                .ok_or(PhysPointerError::Overflow)? as u64,
        );
        let frame_range = if ALIGN == PAGE_SIZE {
            PhysFrame::range(
                PhysFrame::<Size4KiB>::containing_address(phys_start),
                PhysFrame::<Size4KiB>::containing_address(phys_end),
            )
        } else {
            unimplemented!("ALIGN other than 4KiB is not supported yet")
        };

        let mem_attr = if perms.contains(PhysPageMapPermissions::WRITE) {
            // VTL1 wants to write data to the pages, preventing VTL0 from reading/executing the pages.
            crate::mshv::heki::MemAttr::empty()
        } else if perms.contains(PhysPageMapPermissions::READ) {
            // VTL1 wants to read data from the pages, preventing VTL0 from writing to the pages.
            crate::mshv::heki::MemAttr::MEM_ATTR_READ | crate::mshv::heki::MemAttr::MEM_ATTR_EXEC
        } else {
            // VTL1 no longer protects the pages.
            crate::mshv::heki::MemAttr::all()
        };
        crate::mshv::vsm::protect_physical_memory_range(frame_range, mem_attr)
            .map_err(|_| PhysPointerError::UnsupportedPermissions(perms.bits()))
    }
}

/// Runs a user thread with the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    // Currently, `litebox_platform_lvbs` uses `swapgs` to efficiently switch between
    // kernel and user GS base values during kernel-user mode transitions.
    // This `swapgs` usage can pontetially leak a kernel address to the user, so
    // we clear the `KernelGsBase` MSR before running the user thread.
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(&shim, ctx, false);
}

/// Run a user thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership to do not
/// move `shim` to the platform for re-entry later.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(shim, ctx, false);
}

/// Re-enter a user thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn reenter_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(shim, ctx, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    // `thread_ctx` will be passed to `syscall_handler` later.
    // `ctx_ptr` is to let `run_thread_arch` easily access `ctx` (i.e., not to deal with
    // member variable offset calculation in assembly code).
    unsafe { run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter)) };
}

/// Save callee-saved registers onto the stack.
#[cfg(target_arch = "x86_64")]
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

/// Restore callee-saved registers from the stack.
#[cfg(target_arch = "x86_64")]
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

// NOTE: VTL1 extended states are currently stored in per-CPU storage (PerCpuVariablesAsm).
// In the future, we may need to use a global data structure for this because, if there is
// an RPC from VTL1 to VTL0, the core resuming execution might be different from the core
// that requested the RPC. In that case, we also need to save/restore general purpose
// registers in that global data structure.

// ============================================================================
// VTL1 XSAVE/XRSTOR macros (with XSAVEOPT optimization for kernel-user switches)
// ============================================================================
// XSAVE/XRSTOR state tracking (xsaved flag values):
//   0: never saved - use XSAVE, then set to 1
//   1: saved but not yet restored - use XSAVE (XSAVEOPT not safe yet)
//   2: restored at least once - XSAVEOPT is now safe
//
// XSAVEOPT requires that XRSTOR has established tracking for this buffer.
// Only after an XRSTOR can we safely use XSAVEOPT for subsequent saves.
// VTL1 xsaved flags are reset at each VTL1 entry since returning to VTL0 invalidates
// the CPU's tracking (VTL0 does XRSTOR from VTL0's buffer, not VTL1's).

/// Assembly macro to save VTL1 extended states (XSAVE/XSAVEOPT).
/// Uses xsaveopt only after XRSTOR has established tracking (xsaved == 2).
/// Clobbers: rax, rcx, rdx
#[cfg(target_arch = "x86_64")]
macro_rules! XSAVE_VTL1_ASM {
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
            // Set to 1 if it was 0 (first save). If already 1, keep it as 1.
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

/// Assembly macro to restore VTL1 extended states (XRSTOR).
/// Skips restore if state was never saved (xsaved == 0).
/// Sets xsaved to 2 after restore to enable XSAVEOPT optimization.
/// Clobbers: rax, rcx, rdx
#[cfg(target_arch = "x86_64")]
macro_rules! XRSTOR_VTL1_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt, $xsaved_off:tt) => {
        concat!(
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 0\n",
            "je 4f\n",
            "mov rcx, gs:[",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, gs:[",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, gs:[",
            stringify!($mask_hi_off),
            "]\n",
            "xrstor [rcx]\n",
            // After XRSTOR, tracking is established - XSAVEOPT is now safe
            "mov byte ptr gs:[",
            stringify!($xsaved_off),
            "], 2\n",
            "4:\n",
        )
    };
}

/// Save user context right after `syscall`-driven mode transition to the memory area
/// pointed by the current stack pointer (`rsp`).
///
/// `rsp` can point to the current CPU stack or the *top address* of a memory area which
/// has enough space for storing the `PtRegs` structure using the `push` instructions
/// (i.e., from high addresses down to low ones).
///
/// Prerequisite:
/// - Store user `rsp` in `r11` before calling this macro.
/// - Store the userspace return address in `rcx` (`syscall` does this automatically).
#[cfg(target_arch = "x86_64")]
macro_rules! SAVE_SYSCALL_USER_CONTEXT_ASM {
    () => {
        "
        push 0x2b       // pt_regs->ss = __USER_DS
        push r11        // pt_regs->rsp
        pushfq          // pt_regs->eflags
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

/// Save user context after an ISR exception into the user context area.
///
/// Similar to `SAVE_SYSCALL_USER_CONTEXT_ASM` but it preserves all GPRs.
/// The ISR stub pushes the vector number on top of the CPU-pushed error code
/// and iret frame. This macro copies them via a saved ISR stack pointer.
///
/// Prerequisites:
/// - `rsp` points to the top of the user context area (push target)
/// - `rax` points to the ISR stack: `[rax]`=vector, `[rax+8]`=error_code,
///   `[rax+16]`=RIP, `[rax+24]`=CS, `[rax+32]`=RFLAGS, `[rax+40]`=RSP,
///   `[rax+48]`=SS
/// - All GPRs except `rax` contain user-mode values
/// - User `rax` has been saved to per-CPU scratch
/// - `swapgs` has already been executed (GS = kernel)
///
/// Clobbers: rax
#[cfg(target_arch = "x86_64")]
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

/// Save all general-purpose registers onto the stack.
#[cfg(target_arch = "x86_64")]
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

/// Restore all general-purpose registers and skip `orig_rax` from the stack.
#[cfg(target_arch = "x86_64")]
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
        // Stack already has all the values needed for iretq (rip, cs, flags, rsp, ds)
        // from the `PtRegs` structure.
        "
    };
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
        SAVE_CALLEE_SAVED_REGISTERS_ASM!(),
        // Save reenter flag (in dl) before XSAVE clobbers edx
        "mov r9b, dl",
        // Extended states are callee-saved. Save all extended states for now because
        // we don't know whether the caller touched any of them.
        XSAVE_VTL1_ASM!({vtl1_kernel_xsave_area_off}, {vtl1_xsave_mask_lo_off}, {vtl1_xsave_mask_hi_off}, {vtl1_kernel_xsaved_off}),
        "push rdi", // save `thread_ctx`
        // Save kernel rsp and rbp and user context top in PerCpuVariablesAsm.
        "mov gs:[{cur_kernel_sp_off}], rsp",
        "mov gs:[{cur_kernel_bp_off}], rbp",
        "lea r8, [rsi + {USER_CONTEXT_SIZE}]",
        "mov gs:[{user_context_top_off}], r8",
        // Call init_handler or reenter_handler based on reenter flag (in dl)
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
        "mov r11, rsp", // store user `rsp` in `r11`
        "mov rsp, gs:[{user_context_top_off}]", // `rsp` points to the top address of user context area
        SAVE_SYSCALL_USER_CONTEXT_ASM!(),
        XSAVE_VTL1_ASM!({vtl1_user_xsave_area_off}, {vtl1_xsave_mask_lo_off}, {vtl1_xsave_mask_hi_off}, {vtl1_user_xsaved_off}),
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        // Handle the syscall. This will jump back to the user but
        // will return if the thread is exiting.
        "mov rdi, [rsp]", // pass `thread_ctx`
        "call {syscall_handler}",
        "jmp done",
        // Exception callback: entered from ISR stubs for user-mode exceptions.
        // At this point:
        // - rsp = ISR stack: [vector, error_code, rip, cs, rflags, rsp, ss]
        // - All GPRs contain user-mode values
        // - Interrupts are disabled (IDT gate clears IF)
        // - GS = user (swapgs has NOT happened yet)
        ".globl exception_callback",
        "exception_callback:",
        "swapgs",
        "mov gs:[{scratch_off}], rax", // Save `rax` to per-CPU scratch
        "mov al, [rsp]",
        "mov gs:[{exception_trapno_off}], al", // vector number from ISR stack
        "mov rax, rsp", // store ISR `rsp` in `rax`
        "mov rsp, gs:[{user_context_top_off}]", // `rsp` points to the top address of user context area
        SAVE_PF_USER_CONTEXT_ASM!(),
        XSAVE_VTL1_ASM!({vtl1_user_xsave_area_off}, {vtl1_xsave_mask_lo_off}, {vtl1_xsave_mask_hi_off}, {vtl1_user_xsaved_off}),
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        "mov rdi, [rsp]", // pass `thread_ctx`
        "xor esi, esi",   // kernel_mode = false
        "mov rdx, cr2",   // cr2 (still valid — nothing overwrites it)
        "call {exception_handler}",
        "jmp done",
        // Kernel-mode exception callback (currently used for #PF demand paging
        // and exception-table fixup).
        // At entry:
        // - rsp = ISR stack: [vector, error_code, rip, cs, rflags, rsp, ss]
        // - All GPRs = kernel values at time of fault
        // - Interrupts are disabled (IDT gate clears IF)
        // - GS = kernel (no swapgs needed)
        //
        // Saves GPRs, then passes exception info (CR2, error code, faulting
        // RIP) to exception_handler via registers. exception_handler will try
        // demand paging, exception table fixup, and kernel panic in that order.
        ".globl kernel_exception_callback",
        "kernel_exception_callback:",
        "add rsp, 8",                       // skip vector number
        // Now stack: [error_code, rip, cs, rflags, rsp, ss]
        SAVE_CPU_CONTEXT_ASM!(),
        "mov rbp, rsp",
        "and rsp, -16",
        // Pass exception info via registers (SysV ABI args 1-5)
        "mov rdi, gs:[{cur_kernel_sp_off}]",
        "mov rdi, [rdi]",                   // arg1: thread_ctx
        "mov esi, 1",                       // arg2: kernel_mode = true
        "mov rdx, cr2",                     // arg3: cr2 (fault address)
        "mov ecx, [rbp + 120]",             // arg4: error_code (orig_rax slot)
        "mov r8, [rbp + 128]",              // arg5: faulting RIP (iret frame)
        "call {exception_handler}",
        // If demand paging failed, rax contains the exception table fixup
        // address. Patch the saved RIP on the ISR stack so iretq resumes
        // at the fixup instead of re-faulting.
        "test rax, rax",
        "jz 5f",
        "mov [rbp + 128], rax",     // patch saved RIP (15 GPRs + error_code = 128)
        "5:",
        "mov rsp, rbp",
        RESTORE_CPU_CONTEXT_ASM!(),
        "iretq",
        ".globl interrupt_callback",
        "interrupt_callback:",
        "jmp done",
        "done:",
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        XRSTOR_VTL1_ASM!({vtl1_kernel_xsave_area_off}, {vtl1_xsave_mask_lo_off}, {vtl1_xsave_mask_hi_off}, {vtl1_kernel_xsaved_off}),
        RESTORE_CALLEE_SAVED_REGISTERS_ASM!(),
        "ret",
        cur_kernel_sp_off = const { PerCpuVariablesAsm::cur_kernel_stack_ptr_offset() },
        cur_kernel_bp_off = const { PerCpuVariablesAsm::cur_kernel_base_ptr_offset() },
        user_context_top_off = const { PerCpuVariablesAsm::user_context_top_addr_offset() },
        vtl1_kernel_xsave_area_off = const { PerCpuVariablesAsm::vtl1_kernel_xsave_area_addr_offset() },
        vtl1_user_xsave_area_off = const { PerCpuVariablesAsm::vtl1_user_xsave_area_addr_offset() },
        vtl1_xsave_mask_lo_off = const { PerCpuVariablesAsm::vtl1_xsave_mask_lo_offset() },
        vtl1_xsave_mask_hi_off = const { PerCpuVariablesAsm::vtl1_xsave_mask_hi_offset() },
        vtl1_kernel_xsaved_off = const { PerCpuVariablesAsm::vtl1_kernel_xsaved_offset() },
        vtl1_user_xsaved_off = const { PerCpuVariablesAsm::vtl1_user_xsaved_offset() },
        USER_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
        scratch_off = const { PerCpuVariablesAsm::scratch_offset() },
        exception_trapno_off = const { PerCpuVariablesAsm::exception_trapno_offset() },
        init_handler = sym init_handler,
        reenter_handler = sym reenter_handler,
        syscall_handler = sym syscall_handler,
        exception_handler = sym exception_handler,
    );
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
}

unsafe extern "C" fn init_handler(thread_ctx: &mut ThreadContext) {
    match thread_ctx.call_shim(|shim, ctx| shim.init(ctx)) {
        ContinueOperation::Resume => unsafe { switch_to_user(thread_ctx.ctx) },
        ContinueOperation::Terminate => {}
    }
}

unsafe extern "C" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    match thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx)) {
        ContinueOperation::Resume => unsafe { switch_to_user(thread_ctx.ctx) },
        ContinueOperation::Terminate => {}
    }
}

unsafe extern "C" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    match thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx)) {
        ContinueOperation::Resume => unsafe { switch_to_user(thread_ctx.ctx) },
        ContinueOperation::Terminate => {}
    }
}

/// Handles exceptions and routes to the shim's exception handler via `call_shim`.
///
/// `cr2` is passed by both kernel- and user-mode assembly callbacks.
/// For kernel-mode exceptions, `error_code` and `faulting_rip`
/// are also passed from the ISR stack.
/// For user-mode exceptions, `error_code` is read from the saved
/// `orig_rax` in the user context and the vector number is read from
/// the per-CPU trapno variable.
///
/// Returns 0 for normal flow (user-mode or successful demand paging), or
/// a fixup address when kernel-mode user-space demand paging fails and
/// an exception table entry exists. Panics if no fixup is found.
unsafe extern "C" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    kernel_mode: bool,
    cr2: usize,
    error_code: usize,
    faulting_rip: usize,
) -> usize {
    let info = if kernel_mode {
        use litebox::utils::TruncateExt as _;
        litebox::shim::ExceptionInfo {
            exception: litebox::shim::Exception::PAGE_FAULT,
            error_code: error_code.truncate(),
            cr2,
            kernel_mode: true,
        }
    } else {
        use crate::host::per_cpu_variables::{PerCpuVariablesAsm, with_per_cpu_variables_asm};
        use litebox::utils::TruncateExt as _;
        litebox::shim::ExceptionInfo {
            exception: with_per_cpu_variables_asm(PerCpuVariablesAsm::get_exception),
            error_code: thread_ctx.ctx.orig_rax.truncate(),
            cr2,
            kernel_mode: false,
        }
    };
    match thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info)) {
        ContinueOperation::Resume => {
            if kernel_mode {
                // Kernel-mode exception handled (e.g., demand paging succeeded).
                0
            } else {
                // User-mode exception handled; resume user execution.
                unsafe { switch_to_user(thread_ctx.ctx) }
            }
        }
        ContinueOperation::Terminate => {
            if kernel_mode {
                // Look up exception table fixup, panic if not found.
                litebox::mm::exception_table::search_exception_tables(faulting_rip).unwrap_or_else(
                    || {
                        panic!(
                            "EXCEPTION: PAGE FAULT\n\
                             Accessed Address: {:#x}\n\
                             Error Code: {:#x}\n\
                             Faulting RIP: {:#x}",
                            info.cr2, info.error_code, faulting_rip,
                        )
                    },
                )
            } else {
                // User-mode exception not handled; return 0 to exit the thread.
                0
            }
        }
    }
}

/// Calls `f` to invoke a shim entrypoint, returning the shim's
/// [`ContinueOperation`] for the caller to interpret.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) -> ContinueOperation {
        f(self.shim, self.ctx)
    }
}

// Switches to the provided user context with the user mode.
///
/// # Safety
/// The context must be valid user context.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_user(_ctx: &litebox_common_linux::PtRegs) -> ! {
    // rustfmt::skip is needed because rustfmt adds spaces inside braces in macro arguments,
    // which breaks stringify! (e.g., "{ name }" instead of "{name}").
    #[rustfmt::skip]
    core::arch::naked_asm!(
        "switch_to_user_start:",
        // Flush TLB by reloading CR3
        "mov rax, cr3",
        "mov cr3, rax",
        // Clear rax to not leak CR3 value to user
        "xor eax, eax",
        XRSTOR_VTL1_ASM!({vtl1_user_xsave_area_off}, {vtl1_xsave_mask_lo_off}, {vtl1_xsave_mask_hi_off}, {vtl1_user_xsaved_off}),
        // Restore user context from ctx.
        "mov rsp, rdi",
        RESTORE_CPU_CONTEXT_ASM!(),
        // clear the GS base register (as the `KernelGsBase` MSR contains 0)
        // while writing the current GS base value to `KernelGsBase`.
        "swapgs",
        "iretq",
        "switch_to_user_end:",
        vtl1_user_xsave_area_off = const { PerCpuVariablesAsm::vtl1_user_xsave_area_addr_offset() },
        vtl1_xsave_mask_lo_off = const { PerCpuVariablesAsm::vtl1_xsave_mask_lo_offset() },
        vtl1_xsave_mask_hi_off = const { PerCpuVariablesAsm::vtl1_xsave_mask_hi_offset() },
        vtl1_user_xsaved_off = const { PerCpuVariablesAsm::vtl1_user_xsaved_offset() },
    );
}

// NOTE: The below code is a naive workaround to let LVBS code to access the platform.
// Rather than doing this, we should implement LVBS interface/provider for the platform.

pub type Platform = crate::host::LvbsLinuxKernel;

static PLATFORM_LOW: once_cell::race::OnceRef<'static, Platform> = once_cell::race::OnceRef::new();

/// # Panics
///
/// Panics if invoked more than once
pub fn set_platform_low(platform: &'static Platform) {
    match PLATFORM_LOW.set(platform) {
        Ok(()) => {}
        Err(()) => panic!("set_platform should only be called once per crate"),
    }
}

/// # Panics
///
/// Panics if [`set_platform_low`] has not been invoked before this
pub fn platform_low() -> &'static Platform {
    PLATFORM_LOW
        .get()
        .expect("set_platform_low should have already been called before this point")
}
