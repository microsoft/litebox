// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in VTL1 kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]

use crate::execution::ExecutionTimer;
use crate::per_cpu_variables::{PerCpuVariablesAsm, with_per_cpu_variables};
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use hashbrown::HashMap;
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, IPInterfaceProvider,
    ImmediatelyWokenUp, PageManagementProvider, RawMutex as _, RawMutexProvider,
    RawPointerProvider, StdioProvider, TimeProvider, UnblockedOrTimedOut,
};
use litebox::{
    mm::vmem::{PAGE_SIZE, PageRange},
    platform::page_mgmt::FixedAddressBehavior,
    shim::ContinueOperation,
    utils::TruncateExt,
};
use litebox_common_linux::errno::Errno;
use x86_64::{
    VirtAddr,
    structures::paging::{PageTableFlags, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

pub mod arch;
pub mod console;
pub mod execution;
pub mod host;
pub mod mm;
#[cfg(feature = "lvbs")]
pub mod mshv;
pub mod per_cpu_variables;

pub mod syscall_entry;

/// Special page table ID for the base (kernel-only) page table.
/// No real physical frame has address 0, so this is a safe sentinel.
pub const BASE_PAGE_TABLE_ID: usize = 0;

// VTL1 virtual address space layout (4-level paging, canonical range)
//
// High canonical half (0xFFFF_8000_0000_0000 .. 0xFFFF_FFFF_FFFF_FFFF):
//  0xFFFF_FFFF_FFFF_FFFF  ┌─────────────────────────────────┐
//                         │ VTL1 kernel region (~30 TiB)    │
//                         │ VA = PA + KERNEL_OFFSET         │
//  0xFFFF_E200_0000_0000  ├─────────────────────────────────┤ ← KERNEL_OFFSET
//                         │ guard gap (1 TiB)               │
//  0xFFFF_E0FF_FFFF_F000  ├─────────────────────────────────┤ ← VMAP_END
//                         │ vmap region (32 TiB)            │
//                         │ non-contiguous PA→VA mappings   │
//  0xFFFF_C100_0000_0000  ├─────────────────────────────────┤ ← VMAP_START
//                         │ guard gap (1 TiB)               │
//  0xFFFF_C000_0000_0000  ├─────────────────────────────────┤
//                         │ Direct map region (64 TiB)      │
//                         │ VA = PA + GVA_OFFSET            │
//                         │ Currently unused                │
//                         │                                 │
//                         │  ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄    │
//                         │  VTL1 PA range = unmapped gap   │
//                         │  ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄    │
//                         │                                 │
//  0xFFFF_8000_0000_0000  └─────────────────────────────────┘ ← GVA_OFFSET
//
// Low canonical half  (0x0000_0000_0000_0000 .. 0x0000_7FFF_FFFF_F000):
//  0x0000_7FFF_FFFF_F000  ┌─────────────────────────────────┐ ← USER_ADDR_MAX
//                         │ User address space (~128 TiB)   │
//                         │ mmap / TA memory                │
//  0x0000_0000_0001_0000  └─────────────────────────────────┘ ← USER_ADDR_MIN
//
// The 64 TiB direct map region is reserved for possible future use (e.g., device
// drivers, persistent mapping). Foreign physical memory currently uses private
// mappings in the vmap region instead. If direct mapping is restored, physical
// addresses up to 64 TiB can use the PA + GVA_OFFSET formula without colliding
// with vmap. A 1 TiB guard gap catches stray accesses. VTL1 memory must never
// be mapped in the direct map; it lives exclusively in the VTL1 kernel region
// at KERNEL_OFFSET.
//
// The VTL1 kernel region at the top of the address space maps the
// entire VTL1 kernel via PA + KERNEL_OFFSET. A 1 TiB guard gap
// separates it from the vmap region.

/// Offset added to any physical address to obtain the corresponding kernel
/// virtual address in the high-canonical direct map.
pub const GVA_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Start of the vmap virtual address region.
#[cfg(any(feature = "lvbs", test))]
pub(crate) const VMAP_START: usize = 0xFFFF_C100_0000_0000;

/// End of the vmap virtual address region (exclusive).
/// Provides 32 TiB of virtual address space for vmap allocations.
#[cfg(any(feature = "lvbs", test))]
pub(crate) const VMAP_END: usize = 0xFFFF_E0FF_FFFF_F000;

/// Offset added to any physical address to obtain the corresponding
/// VTL1 kernel virtual address. Analogous to `GVA_OFFSET` for the
/// direct map, but for the VTL1 kernel region.
pub const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;

/// Maximum virtual address (exclusive) for user-space allocations.
/// This is the top of the low canonical half (4-level paging).
/// The last page (0x0000_7FFF_FFFF_F000 .. 0x0000_7FFF_FFFF_FFFF) reserved as a guard page.
const USER_ADDR_MAX: usize = 0x0000_7FFF_FFFF_F000;

/// Minimum virtual address for user-space allocations.
///
/// Start above the first 64 KiB to avoid mapping the zero page and
/// to provide a guard region against NULL pointer dereferences.
/// <https://cateee.net/lkddb/web-lkddb/LSM_MMAP_MIN_ADDR.html>
const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;

/// Provide access to a page table
pub struct PageTableHandle<'a, M: mm::MemoryProvider>(PageTableHandleInner<'a, M>);

enum PageTableHandleInner<'a, M: mm::MemoryProvider> {
    Base(&'a mm::PageTable<M, PAGE_SIZE>),
    Task(Arc<mm::PageTable<M, PAGE_SIZE>>),
}

impl<'a, M: mm::MemoryProvider> PageTableHandle<'a, M> {
    #[inline]
    fn base(page_table: &'a mm::PageTable<M, PAGE_SIZE>) -> Self {
        Self(PageTableHandleInner::Base(page_table))
    }

    #[inline]
    fn task(page_table: Arc<mm::PageTable<M, PAGE_SIZE>>) -> Self {
        Self(PageTableHandleInner::Task(page_table))
    }
}

impl<M: mm::MemoryProvider> core::ops::Deref for PageTableHandle<'_, M> {
    type Target = mm::PageTable<M, PAGE_SIZE>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            PageTableHandleInner::Base(page_table) => page_table,
            PageTableHandleInner::Task(page_table) => page_table,
        }
    }
}

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
pub struct PageTableManager<M: mm::MemoryProvider> {
    /// The base page table, containing only kernel mappings (no user-space).
    base_page_table: mm::PageTable<M, PAGE_SIZE>,
    /// Cached physical frame of the base page table (for fast CR3 comparison).
    base_page_table_frame: PhysFrame<Size4KiB>,
    /// Task page tables keyed by their P4 frame start address (the page table ID).
    task_page_tables: spin::RwLock<HashMap<usize, Arc<mm::PageTable<M, PAGE_SIZE>>>>,
}

impl<M: mm::MemoryProvider> PageTableManager<M> {
    /// The minimum virtual address for user-space allocations.
    pub const USER_ADDR_MIN: usize = USER_ADDR_MIN;
    /// The maximum virtual address (exclusive) for user-space allocations.
    pub const USER_ADDR_MAX: usize = USER_ADDR_MAX;

    /// Creates a new page table manager with the given base page table.
    fn new(base_pt: mm::PageTable<M, PAGE_SIZE>) -> Self {
        let base_frame = base_pt.get_physical_frame();
        Self {
            base_page_table: base_pt,
            base_page_table_frame: base_frame,
            task_page_tables: spin::RwLock::new(HashMap::new()),
        }
    }

    /// Returns a handle to the current page table.
    ///
    /// This returns the base page table or the task page table retained by the
    /// current core.
    ///
    /// # Panics
    ///
    /// Panics if CR3 does not match the current core's retained page table.
    #[inline]
    pub fn current_page_table(&self) -> PageTableHandle<'_, M> {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();

        if self.base_page_table_frame == cr3_frame {
            return PageTableHandle::base(&self.base_page_table);
        }

        let cr3_id: usize = cr3_frame.start_address().as_u64().trunc();
        if let Some(pt) = with_per_cpu_variables(|pcv| pcv.active_page_table::<M>(cr3_id)) {
            return PageTableHandle::task(pt);
        }

        unreachable!(
            "CR3 does not match the per-CPU page table: {:?}",
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
        cr3_frame.start_address().as_u64().trunc()
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
        x86_64::instructions::interrupts::without_interrupts(|| {
            // Ensure decreasing/dropping `Arc` for the previous page table (`set_active_page_table()`)
            // only after switching CR3 (`mm::PageTable::load()`).
            self.base_page_table.load();
            with_per_cpu_variables(|pcv| {
                // Safety: CR3 now references the base page table and interrupts are disabled.
                unsafe { pcv.set_active_page_table(None) }
            });
        });
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

        let pt = {
            let task_pts = self.task_page_tables.read();
            Arc::clone(task_pts.get(&task_pt_id).ok_or(Errno::ENOENT)?)
        };

        x86_64::instructions::interrupts::without_interrupts(|| {
            // Ensure decreasing/dropping `Arc` for the previous page table (`set_active_page_table()`)
            // only after switching CR3 (`mm::PageTable::load()`).
            pt.load();
            with_per_cpu_variables(|pcv| {
                // Safety: CR3 now references `pt` and interrupts are disabled.
                unsafe {
                    pcv.set_active_page_table(Some(mm::active::ActivePageTable::new(
                        task_pt_id, pt,
                    )));
                }
            });
        });
        Ok(())
    }

    /// Creates a new task page table and returns its ID.
    ///
    /// The new page table shares the base page table's kernel PML4 entries
    /// rather than allocating new intermediate page table frames. This avoids
    /// allocating P3/P2/P1 frames for every task, significantly reducing
    /// memory usage when creating/destroying many TAs.
    ///
    /// # Returns
    ///
    /// The ID of the newly created task page table (its P4 frame start address),
    /// or `Err(Errno::ENOMEM)` if the P4 frame allocation fails.
    pub fn create_task_page_table(&self) -> Result<usize, Errno> {
        let pt = unsafe { mm::PageTable::<M, PAGE_SIZE>::new_top_level() };

        // Share the base page table's kernel intermediate tables (kernel PML4
        // slots only). This is safe because the kernel mapping structure is
        // fixed after boot; lower slots are not shared (see `copy_pml4_entries_from`).
        pt.copy_pml4_entries_from(&self.base_page_table);

        let pt = Arc::new(pt);
        let task_pt_id: usize = pt.get_physical_frame().start_address().as_u64().trunc();

        let mut task_pts = self.task_page_tables.write();
        task_pts.insert(task_pt_id, pt);

        Ok(task_pt_id)
    }

    /// Deletes a task page table by its ID.
    ///
    /// This function:
    /// 1. Clean up page table structure frames (P1-P3)
    /// 2. Drop the page table (deallocating the top-level P4 frame)
    ///
    /// # Arguments
    ///
    /// * `task_pt_id` - The ID of the task page table to delete
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - All user data frames have been released before calling this function
    /// - No references or pointers to memory mapped by this page table are held after deletion
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the page table was successfully deleted
    /// - `Err(Errno::EINVAL)` if the page table ID is the base page table
    /// - `Err(Errno::ENOENT)` if the page table ID does not exist
    /// - `Err(Errno::EBUSY)` if the page table is active or has outstanding handles
    pub unsafe fn delete_task_page_table(&self, task_pt_id: usize) -> Result<(), Errno> {
        if task_pt_id == BASE_PAGE_TABLE_ID {
            return Err(Errno::EINVAL);
        }

        let mut task_pts = self.task_page_tables.write();

        // Fast path for the page table active on this core.
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        let cr3_id: usize = cr3_frame.start_address().as_u64().trunc();
        if cr3_id == task_pt_id {
            return Err(Errno::EBUSY);
        }

        if let Some(pt) = task_pts.remove(&task_pt_id) {
            // An active CR3 retains a per-CPU Arc.
            let pt = match Arc::try_unwrap(pt) {
                Ok(pt) => pt,
                Err(pt) => {
                    task_pts.insert(task_pt_id, pt);
                    return Err(Errno::EBUSY);
                }
            };
            drop(task_pts);

            // Safety: successful unwrap proves the table is neither active nor
            // borrowed. Kernel slots are base-owned and must not be freed.
            unsafe {
                pt.cleanup_page_table_frames();
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
    host: Host,
    page_table_manager: PageTableManager<Host::Memory>,
}

/// [`litebox::platform::common_providers::userspace_pointers::ValidateAccess`]
/// implementation for LVBS that provides SMAP support.
pub struct LvbsValidateAccess;

impl litebox::platform::common_providers::userspace_pointers::ValidateAccess
    for LvbsValidateAccess
{
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

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn with_user_memory_access<R>(f: impl FnOnce() -> R) -> R {
        // STAC: Set AC flag to temporarily allow supervisor access to user pages.
        // Safety: STAC is a privileged instruction that modifies the AC flag
        // in RFLAGS. It has no side effects beyond enabling SMAP bypass.
        //
        // Note:
        // - `preserves_flags` is omitted because STAC modifies RFLAGS.AC.
        // - `nomem` is omitted. to prevent reordering across the SMAP boundary.
        unsafe {
            core::arch::asm!("stac", options(nostack));
        }
        let result = f();
        // CLAC: Clear AC flag to re-enable SMAP protection.
        // Safety: CLAC is a privileged instruction that modifies the AC flag
        // in RFLAGS. It has no side effects beyond re-enabling SMAP enforcement.
        // Note: `preserves_flags` and `nomem` are intentionally omitted.
        unsafe {
            core::arch::asm!("clac", options(nostack));
        }
        result
    }
}

type UserConstPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserConstPtr<LvbsValidateAccess, T>;
type UserMutPtr<T> =
    litebox::platform::common_providers::userspace_pointers::UserMutPtr<LvbsValidateAccess, T>;

impl<Host: HostInterface> RawPointerProvider for LinuxKernel<Host> {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

unsafe impl<Host: HostInterface> litebox::platform::ThreadLocalStorageProvider
    for LinuxKernel<Host>
{
    fn get_thread_local_storage() -> *mut () {
        let tls = with_per_cpu_variables(|pcv| pcv.tls.get());
        tls.as_mut_ptr::<()>()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        with_per_cpu_variables(|pcv| {
            let old = pcv.tls.get();
            pcv.tls.set(x86_64::VirtAddr::new(value as u64));
            old.as_u64() as *mut ()
        })
    }
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
    /// Construct and load the kernel address space from explicit boot inputs.
    /// Only `exec_ranges` are executable; all other mapped pages are NX.
    /// The caller owns boot-resource reclamation after this returns.
    ///
    /// # Safety
    /// Call once, with a seeded allocator and completed relocation. `memory`
    /// must cover all live code, data, stacks and allocator memory at
    /// `PA + KERNEL_OFFSET`. `exec_ranges` must include every required code
    /// page. The active boot mappings must permit constructing the new tables.
    /// The memory provider's translations must remain stable for every live
    /// frame, and its allocator binding must be installed before this call.
    ///
    /// # Panics
    /// Panics if page-table allocation or mapping fails, or DEP is unavailable.
    pub unsafe fn from_memory(
        host: Host,
        memory: PhysFrameRange<Size4KiB>,
        exec_ranges: &[core::ops::Range<x86_64::PhysAddr>],
    ) -> &'static Self {
        let base_pt = unsafe { mm::PageTable::<Host::Memory, PAGE_SIZE>::new_top_level() };
        if base_pt
            .map_phys_frame_range(
                memory,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                Some(exec_ranges),
            )
            .is_err()
        {
            panic!("Failed to map kernel physical memory to base page table with DEP");
        }

        // Enable the NX (No-eXecute) bit in IA32_EFER before loading the new
        // page table. Without EFER.NXE set, the CPU treats bit 63 (NX/XD) of PTEs
        // as reserved; loading a CR3 whose page tables have that bit set would
        // trigger a reserved-bit violation.
        crate::arch::enable_dep();

        // Switch to the new base page table.
        // Safety: the caller guarantees that the new mappings cover all
        // live kernel state, including the executing code and current stack.
        base_pt.load();

        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host,
            page_table_manager: PageTableManager::new(base_pt),
        }))
    }

    /// Create a new task page table for VTL1 user space and returns its ID.
    ///
    /// The kernel address space is duplicated from the base page table,
    /// including its DEP policy (kernel text executable, everything else
    /// `NO_EXECUTE`).
    ///
    /// See [`PageTableManager`] for security notes on KPTI.
    ///
    /// # Returns
    ///
    /// The ID of the newly created task page table, or `Err(Errno)` on failure.
    pub fn create_task_page_table(&self) -> Result<usize, Errno> {
        self.page_table_manager.create_task_page_table()
    }

    /// Deletes a task page table by its ID.
    ///
    /// This function:
    /// 1. Cleans up page table structure frames (P1-P3)
    /// 2. Drops the page table (deallocating the top-level P4 frame)
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - All user data frames have been released before calling this function
    /// - No references or pointers to memory mapped by this page table are held after deletion
    ///
    /// # Returns
    ///
    /// - `Ok(())` if successful
    /// - `Err(Errno::EINVAL)` if the page table is the base page table
    /// - `Err(Errno::ENOENT)` if the page table doesn't exist
    /// - `Err(Errno::EBUSY)` if the page table is active or has outstanding handles
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
    pub fn page_table_manager(&self) -> &PageTableManager<Host::Memory> {
        &self.page_table_manager
    }

    /// Enable syscall support in the platform.
    pub fn enable_syscall_support() {
        syscall_entry::init();
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
        // No need to wait if the value already changed.
        if self
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Relaxed)
            != val
        {
            return Err(ImmediatelyWokenUp);
        }

        #[allow(clippy::match_same_arms)]
        match Host::block_or_maybe_timeout(&self.inner, val, timeout) {
            Ok(()) => Ok(UnblockedOrTimedOut::Unblocked),
            // If the futex value does not match val, then the call fails
            // immediately with the error EAGAIN.
            Err(Errno::EAGAIN) => Err(ImmediatelyWokenUp),
            Err(Errno::EINTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => panic!("Error: {e:?}"),
        }
    }
}

// Time representation and clock access belong to the selected host. In
// particular, the shared kernel must not assume Hyper-V counter units.
impl<Host: HostInterface + TimeProvider> TimeProvider for LinuxKernel<Host> {
    type Instant = Host::Instant;
    type SystemTime = Host::SystemTime;

    fn now(&self) -> Self::Instant {
        self.host.now()
    }

    fn current_time(&self) -> Self::SystemTime {
        self.host.current_time()
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
    /// Page allocation, address translation, and TLB completion for this host.
    /// The same provider owns base and task tables for the kernel's lifetime.
    type Memory: mm::MemoryProvider;

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
    // User space occupies the low canonical half (0 .. 0x0000_7FFF_FFFF_FFFF).
    // Kernel memory lives in the high canonical half (at KERNEL_OFFSET).
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
                unsafe { current_pt.unmap_pages(range, true, true, false).unwrap() };
            }
        }
        let flags = u32::from(initial_permissions.bits())
            | if can_grow_down {
                litebox::mm::vmem::VmFlags::VM_GROWSDOWN.bits()
            } else {
                0
            };
        let flags = litebox::mm::vmem::VmFlags::from_bits(flags).unwrap();
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
                .unmap_pages(range, true, true, false)
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
        if old_range.start.max(new_range.start) < old_range.end.min(new_range.end) {
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
            litebox::mm::vmem::VmFlags::from_bits(new_permissions.bits().into()).unwrap();
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

impl<Host: HostInterface> litebox::mm::vmem::VmemPageFaultHandler for LinuxKernel<Host> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: litebox::mm::vmem::VmFlags,
        error_code: u64,
    ) -> Result<(), litebox::mm::vmem::PageFaultError> {
        unsafe {
            self.page_table_manager
                .current_page_table()
                .handle_page_fault(fault_addr, flags, error_code)
        }
    }

    fn access_error(error_code: u64, flags: litebox::mm::vmem::VmFlags) -> bool {
        mm::PageTable::<Host::Memory, PAGE_SIZE>::access_error(error_code, flags)
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
        // Currently this is only used in ELF loader to fix trampoline code.
        // When running in kernel mode, we don't need a syscall trampoline.
        0
    }

    fn get_vdso_address(&self) -> Option<usize> {
        unimplemented!()
    }
}

/// Runs a user thread with the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn run_thread<T>(
    shim: T,
    ctx: &mut litebox_common_linux::PtRegs,
    timer: &dyn ExecutionTimer,
) where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    // Currently, `litebox_platform_lvbs` uses `swapgs` to efficiently switch between
    // kernel and user GS base values during kernel-user mode transitions.
    // This `swapgs` usage can pontetially leak a kernel address to the user, so
    // we clear the `KernelGsBase` MSR before running the user thread.
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(&shim, ctx, timer, false);
}

/// Run a user thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership to do not
/// move `shim` to the platform for re-entry later.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn run_thread_ref<T>(
    shim: &T,
    ctx: &mut litebox_common_linux::PtRegs,
    timer: &dyn ExecutionTimer,
) where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(shim, ctx, timer, false);
}

/// Re-enter a user thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid user context.
pub unsafe fn reenter_thread_ref<T>(
    shim: &T,
    ctx: &mut litebox_common_linux::PtRegs,
    timer: &dyn ExecutionTimer,
) where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    run_thread_inner(shim, ctx, timer, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
    timer: &'a dyn ExecutionTimer,
}

impl<'a> ThreadContext<'a> {
    fn new(
        shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
        ctx: &'a mut litebox_common_linux::PtRegs,
        timer: &'a dyn ExecutionTimer,
    ) -> Self {
        // Idempotent within the platform's execution window; reentry must not
        // extend its deadline. The platform/runner owns the disarm boundary.
        timer.arm();
        Self { shim, ctx, timer }
    }

    fn handle_exception(&mut self, info: &litebox::shim::ExceptionInfo) -> ContinueOperation {
        if !info.kernel_mode {
            self.timer.on_user_exception(info.exception);
        }
        self.call_shim(|shim, ctx| shim.exception(ctx, info))
    }
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    timer: &dyn ExecutionTimer,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext::new(shim, ctx, timer);
    // `thread_ctx` will be passed to `syscall_handler` later.
    // `ctx_ptr` is to let `run_thread_arch` easily access `ctx` (i.e., not to deal with
    // member variable offset calculation in assembly code).
    // SAFETY: `thread_ctx` and `ctx_ptr` alias the same valid `PtRegs`/shim for
    // the duration of the call, and `run_thread_arch` returns exactly once.
    unsafe {
        run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
    }
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

// Kernel/user extended state is per-CPU. Resuming an execution context on
// another CPU would require transferring both extended and general registers.

// ============================================================================
// XSAVE/XRSTOR macros (with XSAVEOPT optimization for kernel-user switches)
// ============================================================================
// XSAVE/XRSTOR state tracking (xsaved flag values):
//   0: never saved - use XSAVE, then set to 1
//   1: saved but not yet restored - use XSAVE (XSAVEOPT not safe yet)
//   2: restored at least once - XSAVEOPT is now safe
//
// XSAVEOPT requires that XRSTOR has established tracking for this buffer.
// Only after an XRSTOR can we safely use XSAVEOPT for subsequent saves.
// Platforms must reset xsaved flags when an external context may have changed
// the CPU's tracking. That transition policy is outside these common macros.

/// Assembly macro to save kernel/user extended states (XSAVE/XSAVEOPT).
/// Uses xsaveopt only after XRSTOR has established tracking (xsaved == 2).
/// Clobbers: rax, rcx, rdx
#[cfg(target_arch = "x86_64")]
macro_rules! XSAVE_TRACKED_ASM {
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

/// Assembly macro to restore kernel/user extended states (XRSTOR).
/// Skips restore if state was never saved (xsaved == 0).
/// Sets xsaved to 2 after restore to enable XSAVEOPT optimization.
/// Clobbers: rax, rcx, rdx
#[cfg(target_arch = "x86_64")]
macro_rules! XRSTOR_TRACKED_ASM {
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
/// - Store user `rflags` in `gs:[user_rflags]` before calling this macro.
/// - Store the userspace return address in `rcx` (`syscall` does this automatically).
#[cfg(target_arch = "x86_64")]
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

// ISR stubs target secondary labels emitted inside run_thread_arch. Rust cannot
// see those assembly-only references, so retain the trampoline even when a
// boot-only runner (or host test) builds an IDT without entering user mode.
#[used]
static USER_EXECUTION_ENTRY: unsafe extern "C" fn(
    &mut ThreadContext<'_>,
    *mut litebox_common_linux::PtRegs,
    u8,
) = run_thread_arch;

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
        XSAVE_TRACKED_ASM!({kernel_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {kernel_xsaved_off}),
        "push rdi", // save `thread_ctx`
        // Save kernel rsp and rbp and user context top in PerCpuVariablesAsm.
        "mov gs:[{cur_kernel_sp_off}], rsp",
        "mov gs:[{cur_kernel_bp_off}], rbp",
        "lea r8, [rsi + {USER_CONTEXT_SIZE}]",
        "mov gs:[{user_context_top_off}], r8",
        // Mark that we are inside a user/TA context so that
        // kernel_exception_callback knows a valid ThreadContext exists.
        "mov byte ptr gs:[{is_in_user_off}], 1",
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
        "mov gs:[{user_rflags_off}], r11", // store user `rflags`.
        "mov r11, rsp", // store user `rsp` in `r11`
        "mov rsp, gs:[{user_context_top_off}]", // `rsp` points to the top address of user context area
        SAVE_SYSCALL_USER_CONTEXT_ASM!(),
        XSAVE_TRACKED_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
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
        "cld",
        "clac",
        "swapgs",
        "mov gs:[{scratch_off}], rax", // Save `rax` to per-CPU scratch
        "mov al, [rsp]",
        "mov gs:[{exception_trapno_off}], al", // vector number from ISR stack
        "mov rax, rsp", // store ISR `rsp` in `rax`
        "mov rsp, gs:[{user_context_top_off}]", // `rsp` points to the top address of user context area
        SAVE_PF_USER_CONTEXT_ASM!(),
        XSAVE_TRACKED_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
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
        // Check if we are inside a user/TA context (is_in_user flag).
        // When is_in_user is set, a valid ThreadContext exists on the
        // kernel stack at [gs:cur_kernel_sp] and we can attempt demand
        // paging through the shim.  When clear, the page fault occurred
        // outside run_thread_arch and only exception-table fixup is available.
        "cmp byte ptr gs:[{is_in_user_off}], 0",
        "je 6f",
        // In-user path: load ThreadContext and call full exception_handler.
        "mov rdi, gs:[{cur_kernel_sp_off}]",
        // Pass exception info via registers (SysV ABI args 1-5)
        "mov rdi, [rdi]",                   // arg1: thread_ctx
        "mov esi, 1",                       // arg2: kernel_mode = true
        "mov rdx, cr2",                     // arg3: cr2 (fault address)
        "mov ecx, [rbp + 120]",             // arg4: error_code (orig_rax slot)
        "mov r8, [rbp + 128]",              // arg5: faulting RIP (iret frame)
        "call {exception_handler}",
        "jmp 7f",
        // No thread context: only exception table fixup is possible.
        "6:",
        "mov rdi, cr2",                     // arg1: cr2
        "mov esi, [rbp + 120]",             // arg2: error_code
        "mov rdx, [rbp + 128]",             // arg3: faulting RIP
        "call {kernel_exception_handler_no_ctx}",
        "7:",
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
        // We are leaving the user/TA context. Clear is_in_user first
        // so that any kernel-mode page fault from this point on takes the
        // exception-table-only path in kernel_exception_callback.
        "mov byte ptr gs:[{is_in_user_off}], 0",
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        // Zero cur_kernel_sp as defence in depth
        "mov qword ptr gs:[{cur_kernel_sp_off}], 0",
        XRSTOR_TRACKED_ASM!({kernel_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {kernel_xsaved_off}),
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
        USER_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
        scratch_off = const { PerCpuVariablesAsm::scratch_offset() },
        user_rflags_off = const { PerCpuVariablesAsm::user_rflags_offset() },
        exception_trapno_off = const { PerCpuVariablesAsm::exception_trapno_offset() },
        is_in_user_off = const { PerCpuVariablesAsm::is_in_user_offset() },
        init_handler = sym init_handler,
        reenter_handler = sym reenter_handler,
        syscall_handler = sym syscall_handler,
        exception_handler = sym exception_handler,
        kernel_exception_handler_no_ctx = sym kernel_exception_handler_no_ctx,
    );
}

unsafe extern "C" fn init_handler(thread_ctx: &mut ThreadContext) {
    match thread_ctx.call_shim(|shim, ctx| shim.init(ctx)) {
        ContinueOperation::Resume => {
            if thread_ctx.ctx.sanitize_for_user_return() {
                unsafe { switch_to_user(thread_ctx.ctx) }
            }
            litebox_util_log::warn!("terminating thread with invalid user return context");
        }
        ContinueOperation::Terminate => {}
    }
}

unsafe extern "C" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    match thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx)) {
        ContinueOperation::Resume => {
            if thread_ctx.ctx.sanitize_for_user_return() {
                unsafe { switch_to_user(thread_ctx.ctx) }
            }
            litebox_util_log::warn!("terminating thread with invalid user return context");
        }
        ContinueOperation::Terminate => {}
    }
}

unsafe extern "C" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    if !thread_ctx.ctx.has_user_return_addresses() {
        return;
    }

    match thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx)) {
        ContinueOperation::Resume => {
            if thread_ctx.ctx.sanitize_for_user_return() {
                unsafe { switch_to_user(thread_ctx.ctx) }
            }
            litebox_util_log::warn!("terminating thread with invalid user return context");
        }
        ContinueOperation::Terminate => {}
    }
}

/// Handles a kernel-mode page fault that occurs outside `run_thread_arch`
/// (i.e., when `cur_kernel_sp` is zero). Without a valid `ThreadContext`
/// we cannot call into the shim for demand paging, so the only option is
/// exception-table fixup (or panic).
///
/// Returns the fixup address on success (to be patched into the saved RIP)
/// or panics if no fixup entry is found.
unsafe extern "C" fn kernel_exception_handler_no_ctx(
    cr2: usize,
    error_code: usize,
    faulting_rip: usize,
) -> usize {
    litebox::mm::exception_table::search_exception_tables(faulting_rip).unwrap_or_else(|| {
        panic!(
            "EXCEPTION: PAGE FAULT outside run_thread_arch (no ThreadContext)\n\
             Accessed Address: {cr2:#x}\n\
             Error Code: {error_code:#x}\n\
             Faulting RIP: {faulting_rip:#x}",
        )
    })
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
            error_code: error_code.trunc(),
            cr2,
            kernel_mode: true,
        }
    } else {
        use crate::per_cpu_variables::with_per_cpu_variables;
        use litebox::utils::TruncateExt as _;
        litebox::shim::ExceptionInfo {
            exception: with_per_cpu_variables(|pcv| pcv.asm.get_exception()),
            error_code: thread_ctx.ctx.orig_rax.trunc(),
            cr2,
            kernel_mode: false,
        }
    };
    match thread_ctx.handle_exception(&info) {
        ContinueOperation::Resume => {
            if kernel_mode {
                // Kernel-mode exception handled (e.g., demand paging succeeded).
                0
            } else {
                // User-mode exception handled; resume user execution.
                if thread_ctx.ctx.sanitize_for_user_return() {
                    unsafe { switch_to_user(thread_ctx.ctx) }
                } else {
                    litebox_util_log::warn!("terminating thread with invalid user return context");
                    0
                }
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
        "cli",
        // Flush TLB by reloading CR3
        "mov rax, cr3",
        "mov cr3, rax",
        // Clear rax to not leak CR3 value to user
        "xor eax, eax",
        XRSTOR_TRACKED_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
        // Restore user context from ctx.
        "mov rsp, rdi",
        RESTORE_CPU_CONTEXT_ASM!(),
        // clear the GS base register (as the `KernelGsBase` MSR contains 0)
        // while writing the current GS base value to `KernelGsBase`.
        "swapgs",
        "iretq",
        "switch_to_user_end:",
        user_xsave_area_off = const { PerCpuVariablesAsm::user_xsave_area_addr_offset() },
        xsave_mask_lo_off = const { PerCpuVariablesAsm::xsave_mask_lo_offset() },
        xsave_mask_hi_off = const { PerCpuVariablesAsm::xsave_mask_hi_offset() },
        user_xsaved_off = const { PerCpuVariablesAsm::user_xsaved_offset() },
    );
}
