// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox's kernel-mode VM platform library. The runner supplies boot,
//! allocators, logging, interrupt-controller setup, a [`clock::ClockSource`],
//! and the root key ([`providers::set_platform_root_key`]).
//!
//! After boot mappings and the heap are ready, [`VmKernel::boot`] owns the
//! boot CPU's initialization and the kernel-stack handoff. Its continuation
//! receives the initialized platform; key provisioning remains separate and
//! must precede execution that needs derived keys. The runner may then start
//! the other CPUs ([`VmKernel::start_cpus`], [`cpu`]), which run its entry.
//!
//! Assumptions: no kernel threads (the runner may switch user threads), but
//! cooperative tasks ([`worker`]); kernel mappings changed after boot only to
//! add some, or to unmap a stack's guard page, flushed locally: a CPU's own
//! stacks' only there, a cooperative task's where it is unmapped, then on
//! each other CPU before it first runs on the stack (and mapped again as it
//! was before the stack is freed); synchronized TSCs (see [`cpu`]); and not a
//! confidential VM (no #VE/#VC/#HV). A task's address space may be current on
//! several CPUs at once: a change to its mappings that may leave stale
//! translations is shot down, by IPI, on those that may cache it (see `tlb`).
//!
//! Devices: [`VmKernel`] is the drivers' [`litebox_hal::dma::Hal`].
//!
//! Interrupts: the kernel runs with interrupts disabled, except while it
//! halts ([`cpu::halt`]) or spins in [`cpu::relax`]; user code runs with them
//! enabled. External interrupts, on any CPU, handle the TLB flushes other
//! CPUs requested of it, then go to the handler the runner installs
//! ([`set_interrupt_handler`]); one that interrupted user code then also
//! enters the shim's `interrupt` (e.g., for the runner's one-shot timer, a
//! device's input, or another CPU's wake IPI, see [`cpu`]), unless only a
//! doorbell ([`Handled::Doorbell`]); ending the run there lets the runner
//! preempt the thread ([`resume_thread_ref`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

use crate::arch::mm::paging::UnmapOptions;
use crate::per_cpu::{PerCpuVariablesAsm, with_per_cpu_variables};
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use hashbrown::HashMap;
use litebox::mm::page::PageRange;
use litebox::mm::vmap::{
    NoopPhysPageMapInfo, PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use litebox::platform::{
    ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, PageManagementProvider,
    RawPointerProvider,
};
use litebox::{
    mm::exception_table::search_exception_tables,
    platform::{
        common_providers::reservations::NoTrackedReservations,
        page_mgmt::{
            AllocationError, AllocationOptions, DeallocationError, FixedAddressBehavior,
            HintPlacementBehavior, MemoryRegionPermissions, PermissionUpdateError,
        },
    },
    shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo},
    utils::TruncateExt,
};
use litebox_common_linux::{
    PAGE_SIZE, PtRegs,
    errno::Errno,
    vmem::{PageFaultError, VmFlags, VmemPageFaultHandler},
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
pub mod cpu;
mod dma;
pub mod mm;
mod per_cpu;
pub mod providers;
mod reclaim;

mod syscall_entry;
mod tlb;
pub mod worker;

/// Inputs to the boot CPU's kernel handoff. The runner owns device setup and
/// must keep the clock and allocator alive until reset.
pub struct BootConfig<'a> {
    pub page_allocator: &'static dyn mm::PageAllocator,
    /// The kernel clock; see [`clock::ClockSource`] for what it must be.
    pub clock: &'static dyn clock::ClockSource,
    /// Physical RAM to map; ranges are rounded inward to whole pages. All
    /// but `image` is mapped RW/NX at `PA + KERNEL_OFFSET`.
    pub ram: &'a [core::ops::Range<PhysAddr>],
    /// Page-aligned physical kernel image, within `ram`, mapped only at
    /// `PA + KERNEL_IMAGE_OFFSET`: `text` RX, `read_only` R/NX, the rest RW/NX.
    pub image: core::ops::Range<PhysAddr>,
    /// Page-aligned physical kernel code range.
    pub text: core::ops::Range<PhysAddr>,
    /// Page-aligned physical constants, written no more after relocation.
    /// Must not overlap `text`.
    pub read_only: core::ops::Range<PhysAddr>,
    /// External vectors that require neither handling nor acknowledgement.
    pub ignored_vectors: &'a [u8],
}

/// See [`set_interrupt_handler`].
pub type InterruptHandler = dyn Fn(u8) -> Handled + Sync;

/// What [`set_interrupt_handler`]'s handler made of an interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handled {
    /// Not a vector it handles: the kernel panics.
    Unexpected,
    /// Ended, for the kernel to look at: user code it interrupted enters the
    /// shim's `interrupt`.
    Event,
    /// Ended, only a doorbell (e.g., [`cpu::Ipi::FlushTlb`]'s): user code it
    /// interrupted resumes at once.
    Doorbell,
}

/// Installs the handler for external interrupts (vectors 32 and up, except
/// [`BootConfig::ignored_vectors`]), which says what it made of the vector
/// ([`Handled`]). Before this, every external interrupt panics.
///
/// The handler runs with interrupts disabled, on the interrupted context's GS
/// (user mode, [`cpu::halt`], or a spin's [`cpu::relax`]), on any CPU: it
/// must not touch per-CPU data, block, or take locks; it should only end the
/// interrupt, maybe wake CPUs (e.g., [`cpu::wake_idle`]), and leave the work
/// to the kernel after the halt. It also handles the wake IPI
/// ([`cpu::Ipi::Wake`]) and the TLB-flush IPI ([`cpu::Ipi::FlushTlb`]), on
/// every CPU, the boot CPU too, from [`VmKernel::start_cpus`] on.
///
/// # Panics
///
/// On a second call.
pub fn set_interrupt_handler(handler: &'static InterruptHandler) {
    arch::interrupts::set_external_interrupt_handler(handler);
}

/// Valid until unregistered; its representation is private to the platform.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressSpaceId(usize);

impl AddressSpaceId {
    pub const KERNEL: Self = Self(0);
}

// Virtual address space, as in Linux's Documentation/arch/x86/x86_64/mm.rst:
//   0x0000_0000_0001_0000 .. 0x0000_7FFF_FFFF_F000  user, per task
//   0xFFFF_E200_0000_0000 .. 0xFFFF_E280_0000_0000  direct map of RAM but the
//                                                   kernel image, at
//                                                   PA + KERNEL_OFFSET
//   0xFFFF_E280_0000_0000 .. 0xFFFF_E300_0000_0000  ioremap: device memory
//   0xFFFF_FFFF_8000_0000 .. 0xFFFF_FFFF_FFFF_FFFF  kernel image, at
//                                                   PA + KERNEL_IMAGE_OFFSET

/// `VA = PA + KERNEL_OFFSET` for kernel-owned RAM but the kernel image (the
/// direct map). Must be 512 GiB aligned (one PML4 slot).
pub const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;

/// `VA = PA + KERNEL_IMAGE_OFFSET` for the kernel image, which must lie
/// below 2 GiB (Linux's `__START_KERNEL_map`).
pub const KERNEL_IMAGE_OFFSET: u64 = 0xFFFF_FFFF_8000_0000;

/// Device memory mappings ([`litebox_hal::dma::Hal::map_mmio`]), the slot
/// after the direct map, which RAM must end below.
const IOREMAP: core::ops::Range<u64> = KERNEL_OFFSET + (512 << 30)..KERNEL_OFFSET + (1024 << 30);

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
    /// Each table in the node that releases it once unregistered.
    task_page_tables: spin::RwLock<
        HashMap<AddressSpaceId, alloc::boxed::Box<reclaim::Node<Arc<mm::PageTable<PAGE_SIZE>>>>>,
    >,
    /// See [`Self::unregister_task_page_table`].
    unregistered: reclaim::Reclaim<Arc<mm::PageTable<PAGE_SIZE>>>,
}

impl PageTableManager {
    fn new(base_pt: mm::PageTable<PAGE_SIZE>) -> Self {
        let base_frame = base_pt.physical_frame();
        Self {
            base_page_table: base_pt,
            base_page_table_frame: base_frame,
            task_page_tables: spin::RwLock::new(HashMap::new()),
            unregistered: reclaim::Reclaim::new(),
        }
    }

    /// The calling CPU's current address space: the one whose table CR3
    /// holds.
    fn current_address_space(&self) -> AddressSpaceId {
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        if self.base_page_table_frame == cr3_frame {
            AddressSpaceId::KERNEL
        } else {
            AddressSpaceId(cr3_frame.start_address().as_u64().trunc())
        }
    }

    /// # Panics
    ///
    /// Panics if CR3 does not match the current core's retained page table.
    #[inline]
    pub(crate) fn current_page_table(&self) -> PageTableHandle<'_> {
        let id = self.current_address_space();
        if id == AddressSpaceId::KERNEL {
            return PageTableHandle::base(&self.base_page_table);
        }
        if let Some(pt) = with_per_cpu_variables(|pcv| pcv.active_page_table(id)) {
            return PageTableHandle::task(pt);
        }
        unreachable!("CR3 does not match the per-CPU page table: {:#x}", id.0);
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
                let previous = unsafe { pcv.replace_active_page_table(None) };
                // Only now that CR3 points elsewhere (see `tlb`).
                if let Some((_, table)) = &previous {
                    table.cpus().leave(pcv.cpu);
                }
                previous
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
            Arc::clone(task_pts.get(&task_pt_id).ok_or(Errno::ENOENT)?.item())
        };

        let previous = without_interrupts(|| {
            // Before CR3 points to it (see `tlb`).
            pt.cpus().enter(cpu::current());
            // Replace the per-CPU owner only after CR3 stops referencing it.
            // Safety: task tables share the base table's kernel entries.
            unsafe { pt.load() };
            with_per_cpu_variables(|pcv| {
                // Safety: CR3 now references `pt` and interrupts are disabled.
                let previous = unsafe { pcv.replace_active_page_table(Some((task_pt_id, pt))) };
                // Only now that CR3 points elsewhere, unless reloaded (see
                // `tlb`).
                if let Some((id, table)) = &previous
                    && *id != task_pt_id
                {
                    table.cpus().leave(pcv.cpu);
                }
                previous
            })
        });
        // Last-owner reclamation runs outside the interrupt-free section.
        drop(previous);
        Ok(())
    }

    /// Shares the base table's kernel P3/P2/P1 tables, and has `source`'s user
    /// mappings, if any (see [`VmKernel::clone_address_space`]).
    ///
    /// # Errors
    ///
    /// `ENOMEM`, as for [`VmKernel::clone_address_space`].
    pub(crate) fn create_task_page_table(
        &self,
        source: Option<&mm::PageTable<PAGE_SIZE>>,
    ) -> Result<AddressSpaceId, Errno> {
        let pt = mm::PageTable::new_top_level().ok_or(Errno::ENOMEM)?;

        // Sharing is safe because the kernel mappings are fixed after boot.
        pt.copy_pml4_entries_from(&self.base_page_table);
        if let Some(source) = source {
            // Not registered yet: on failure, dropping it releases what it
            // maps.
            source.clone_user_mappings(&pt).map_err(|_| Errno::ENOMEM)?;
        }

        let pt = Arc::new(pt);
        let task_pt_id = AddressSpaceId(pt.physical_frame().start_address().as_u64().trunc());
        // Its node now, so that unregistering it allocates nothing.
        let node = reclaim::Node::new(pt);

        let mut task_pts = self.task_page_tables.write();
        task_pts.insert(task_pt_id, node);

        Ok(task_pt_id)
    }

    /// See [`VmKernel::clone_address_space`].
    pub(crate) fn clone_task_page_table(
        &self,
        source: AddressSpaceId,
    ) -> Result<AddressSpaceId, Errno> {
        if source == AddressSpaceId::KERNEL {
            return Err(Errno::EINVAL);
        }
        let source = Arc::clone(
            self.task_page_tables
                .read()
                .get(&source)
                .ok_or(Errno::ENOENT)?
                .item(),
        );
        self.create_task_page_table(Some(&source))
    }

    /// Unregisters a task table; retained handles keep it alive. The
    /// registry's reference is released by one CPU at a time (see
    /// `reclaim`), with no allocation: this one, which then also releases
    /// those unregistered meanwhile, or one already doing so, which this
    /// leaves it to. It is queued as it leaves the registry, under the
    /// registry's lock, so that it is always registered or retiring (see
    /// `VmKernel::retiring_address_spaces`). This call releases only once it
    /// dropped that lock; a CPU already releasing may release this one
    /// sooner, while this one still holds the lock (it drops items under no
    /// lock of its own). If it is the last (as when a reaped process drops its
    /// address space: no thread of it runs, and its broker unpinned its
    /// pages), the releasing CPU destroys the table, freeing every frame it
    /// maps, with no time bound. Otherwise the last handle (a CPU's current
    /// table, or a pin) destroys it as it drops, on its CPU, unserialized, as a
    /// creation that fails before registering its table does.
    ///
    /// # Safety
    ///
    /// The caller must ensure final destruction is safe: no access outlives
    /// all remaining handles.
    ///
    /// Returns `EINVAL` for the base ID and `ENOENT` if it is not registered.
    pub(crate) unsafe fn unregister_task_page_table(
        &self,
        task_pt_id: AddressSpaceId,
    ) -> Result<(), Errno> {
        if task_pt_id == AddressSpaceId::KERNEL {
            return Err(Errno::EINVAL);
        }

        let drain = {
            let mut task_pts = self.task_page_tables.write();
            let node = task_pts.remove(&task_pt_id).ok_or(Errno::ENOENT)?;
            self.unregistered.enqueue(node)
        };
        if let Some(drain) = drain {
            drain.run();
        }
        Ok(())
    }
}

/// The LiteBox platform for a VM guest kernel.
pub struct VmKernel {
    page_table_manager: PageTableManager,
    clock: &'static dyn clock::ClockSource,
    /// Guest RAM owned by this kernel (mapped at `PA + KERNEL_OFFSET`, but the
    /// kernel image at `PA + KERNEL_IMAGE_OFFSET`).
    ram_frame_ranges: alloc::vec::Vec<PhysFrameRange<Size4KiB>>,
    /// The next free address in [`IOREMAP`].
    ioremap_next: spin::Mutex<u64>,
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
                if litebox::arch::x86_64::is_valid_user_fs_base(val) {
                    // Safety: FSGSBASE is enabled, and `val` is a valid user FS
                    // base; the kernel does not use FS.
                    unsafe { litebox::arch::x86_64::wrfsbase(val) };
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
            ArchSpecificRegister::FsBase => Ok(unsafe { litebox::arch::x86_64::rdfsbase() }),
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
        image: &core::ops::Range<PhysAddr>,
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
        for region in [image, text, read_only] {
            assert!(region.start <= region.end, "reversed kernel image range");
            assert!(
                region.start.is_aligned(Size4KiB::SIZE) && region.end.is_aligned(Size4KiB::SIZE),
                "kernel image ranges must be page-aligned"
            );
            assert!(
                region.is_empty() || (image.start <= region.start && region.end <= image.end),
                "kernel image range {region:?} is outside the image"
            );
        }
        assert!(
            ram_frame_ranges.iter().any(|r| {
                r.start.start_address() <= image.start && image.end <= r.end.start_address()
            }),
            "the kernel image is outside guest RAM"
        );
        assert!(
            image.end.as_u64() <= KERNEL_IMAGE_OFFSET.wrapping_neg(),
            "the kernel image extends past 2 GiB"
        );
        assert!(
            read_only.is_empty() || text.end <= read_only.start || read_only.end <= text.start,
            "kernel text and read-only data overlap"
        );

        assert!(
            ram_frame_ranges
                .iter()
                .all(|r| KERNEL_OFFSET + r.end.start_address().as_u64() <= IOREMAP.start),
            "guest RAM extends past the direct map"
        );
        let base_pt =
            mm::PageTable::new_top_level().expect("Failed to allocate a new page table frame");
        base_pt.preallocate_kernel_slot(VirtAddr::new(IOREMAP.start));
        let image_frames = PhysFrame::range(
            PhysFrame::containing_address(image.start),
            PhysFrame::containing_address(image.end),
        );
        let none = PhysAddr::zero()..PhysAddr::zero();
        for range in &ram_frame_ranges {
            let below = PhysFrame::range(range.start, range.end.min(image_frames.start));
            let above = PhysFrame::range(range.start.max(image_frames.end), range.end);
            for part in [below, above].into_iter().filter(|part| !part.is_empty()) {
                if let Err(e) = base_pt.map_kernel(part, KERNEL_OFFSET, &none, &none) {
                    panic!("failed to map guest RAM {part:?}: {e:?}");
                }
            }
        }
        if let Err(e) = base_pt.map_kernel(image_frames, KERNEL_IMAGE_OFFSET, text, read_only) {
            panic!("failed to map the kernel image: {e:?}");
        }
        per_cpu::with_per_cpu_variables(|pcv| pcv.unmap_stack_guards(&base_pt));

        // Safety: maps the image, which holds the running code, and the rest
        // of `ram`, which holds the stack (from the heap) at the same
        // addresses as the boot mappings.
        unsafe { base_pt.load() };

        let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            page_table_manager: PageTableManager::new(base_pt),
            clock,
            ram_frame_ranges,
            ioremap_next: spin::Mutex::new(IOREMAP.start),
        }));
        #[cfg(debug_assertions)]
        worker::self_check(platform);
        platform
    }

    /// [`cpu::halt`]: halts until an interrupt is handled, or another CPU
    /// wakes this one, with interrupts enabled only for the halt. An
    /// interrupt that became pending while they were disabled, or a wakeup
    /// since the last halt, ends it at once, so check for work first and halt
    /// after: none is missed.
    pub fn halt_until_interrupt(&self) {
        cpu::halt();
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
        self.page_table_manager
            .create_task_page_table(None)
            .expect("Failed to allocate a new page table frame")
    }

    /// Unregisters a task table; retained handles keep it alive. The
    /// registry's references are released by one CPU at a time: this one, or
    /// one already releasing them, which this call does not wait for. A table
    /// whose last reference is the registry's is destroyed, its frames freed,
    /// as that is released; one that another handle keeps (e.g., a pin) is
    /// destroyed as that drops, on its CPU, unserialized. If this one
    /// releases, it also releases those that other CPUs unregister
    /// meanwhile, with no time bound, holding what its caller holds.
    ///
    /// # Safety
    ///
    /// The caller must ensure final destruction is safe: no access outlives
    /// all remaining handles.
    ///
    /// Returns `EINVAL` for the base ID and `ENOENT` if it is not registered.
    pub unsafe fn unregister_address_space(&self, task_pt_id: AddressSpaceId) -> Result<(), Errno> {
        // Safety: the caller upholds the manager's destruction requirements.
        unsafe {
            self.page_table_manager
                .unregister_task_page_table(task_pt_id)
        }
    }

    /// The calling CPU's current address space: [`AddressSpaceId::KERNEL`], or
    /// a task's.
    pub fn current_address_space(&self) -> AddressSpaceId {
        self.page_table_manager.current_address_space()
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

    /// Pins the present, writable pages of `range` in `address_space` for
    /// access through the kernel mapping, whichever address space is current.
    ///
    /// # Safety
    ///
    /// Nothing may unmap or remap `range` while the result lives. The result
    /// keeps the whole address space alive (see [`PinnedUserPages`]).
    ///
    /// # Errors
    ///
    /// `EINVAL` for an invalid range or [`AddressSpaceId::KERNEL`], `ENOENT`
    /// for an unknown ID, and `EFAULT` for a page that is not present and
    /// writable.
    pub unsafe fn pin_user_pages(
        &self,
        address_space: AddressSpaceId,
        range: core::ops::Range<usize>,
    ) -> Result<PinnedUserPages, Errno> {
        let (page_table, range) = self.pin_target(address_space, range)?;
        let pages = page_table
            .pin(range)
            .ok_or(Errno::EFAULT)?
            .iter()
            .map(|frame| Self::pa_to_va(frame.start_address()).as_u64().trunc())
            .collect();
        Ok(PinnedUserPages {
            page_table,
            range,
            pages: Pages::Found(pages),
        })
    }

    /// As [`Self::pin_user_pages`], but the pages need not be present: each
    /// is found as it is accessed ([`PinnedUserPages::kernel_address`]), on
    /// any CPU, without loading the address space, and populated writable if
    /// not mapped. Nothing is kept per page.
    ///
    /// # Safety
    ///
    /// As for [`Self::pin_user_pages`]; and `range` must be mapped writable
    /// (e.g., lazily) meanwhile, as its pages are populated so.
    ///
    /// # Errors
    ///
    /// `EINVAL` for an invalid range or [`AddressSpaceId::KERNEL`], and
    /// `ENOENT` for an unknown ID.
    pub unsafe fn pin_user_pages_lazily(
        &self,
        address_space: AddressSpaceId,
        range: core::ops::Range<usize>,
    ) -> Result<PinnedUserPages, Errno> {
        let (page_table, range) = self.pin_target(address_space, range)?;
        // Safety: forwarded to the caller.
        unsafe { page_table.pin_lazily(range) };
        Ok(PinnedUserPages {
            page_table,
            range,
            pages: Pages::OnAccess,
        })
    }

    /// The table of `address_space`, and `range` as pages, for a pin.
    fn pin_target(
        &self,
        address_space: AddressSpaceId,
        range: core::ops::Range<usize>,
    ) -> Result<(Arc<mm::PageTable<PAGE_SIZE>>, PageRange<PAGE_SIZE>), Errno> {
        let range = PageRange::<PAGE_SIZE>::new(range.start, range.end).ok_or(Errno::EINVAL)?;
        if range.is_empty() || range.start() < USER_ADDR_MIN || range.end() > USER_ADDR_MAX {
            return Err(Errno::EINVAL);
        }
        if address_space == AddressSpaceId::KERNEL {
            return Err(Errno::EINVAL);
        }
        let page_table = Arc::clone(
            self.page_table_manager
                .task_page_tables
                .read()
                .get(&address_space)
                .ok_or(Errno::ENOENT)?
                .item(),
        );
        Ok((page_table, range))
    }

    /// A new address space with `source`'s user mappings, whose frames the
    /// two share copy-on-write: each gets its own copy of a page once either
    /// writes it. Pinned pages (see [`Self::pin_user_pages`]) are not cloned:
    /// the new address space leaves them unmapped. `source`'s leaves, but
    /// shared memory's, become read-only, which is shot down on every CPU that
    /// may cache it.
    ///
    /// # Errors
    ///
    /// `EINVAL` for [`AddressSpaceId::KERNEL`], `ENOENT` for an unknown ID,
    /// and `ENOMEM` if frames run out (for the new address space's page
    /// tables), or the kernel heap does (to count the shared frames).
    pub fn clone_address_space(&self, source: AddressSpaceId) -> Result<AddressSpaceId, Errno> {
        self.page_table_manager.clone_task_page_table(source)
    }

    /// How many address spaces are registered (see
    /// [`Self::create_address_space`]).
    pub fn address_space_count(&self) -> usize {
        self.page_table_manager.task_page_tables.read().len()
    }

    /// Whether the registry's references to unregistered address spaces (see
    /// [`Self::unregister_address_space`]) are still queued, or being
    /// released: for debug checks that nothing is left to free. Read it after
    /// [`Self::address_space_count`]: an address space is queued as it leaves
    /// the registry, under the registry's lock, so one that the count no
    /// longer includes shows here until released. Not the tables that other
    /// handles keep (e.g., a CPU's current table, or a pin).
    #[cfg(debug_assertions)]
    pub fn retiring_address_spaces(&self) -> bool {
        !self.page_table_manager.unregistered.is_idle()
    }

    /// How many frames address spaces share copy-on-write (see
    /// [`Self::clone_address_space`]).
    pub fn shared_frame_count(&self) -> usize {
        crate::arch::mm::paging::shared_frames().len()
    }
}

/// See [`VmKernel::pin_user_pages`] and [`VmKernel::pin_user_pages_lazily`].
/// The process may write these pages at any time: access them only with
/// peer-safe operations, never through Rust references. Keeps the whole
/// address space alive, every frame it maps, not only these, until dropped,
/// even once unregistered.
pub struct PinnedUserPages {
    /// Keeps the table, and every frame it owns, alive.
    page_table: Arc<mm::PageTable<PAGE_SIZE>>,
    range: PageRange<PAGE_SIZE>,
    pages: Pages,
}

/// How [`PinnedUserPages`] finds its pages' kernel addresses.
enum Pages {
    /// Each page's, found as it was pinned.
    Found(alloc::boxed::Box<[usize]>),
    /// Found, and populated if not mapped, at each access.
    OnAccess,
}

impl Drop for PinnedUserPages {
    fn drop(&mut self) {
        self.page_table.unpin(self.range);
    }
}

impl PinnedUserPages {
    /// In bytes.
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Never: pins reject empty ranges.
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// The kernel address of byte `offset` and the bytes left in its page.
    ///
    /// # Errors
    ///
    /// `EINVAL` past the end; for a lazy pin, `ENOMEM` if populating the page
    /// runs out of frames, and `EFAULT` if it is mapped but not writable.
    pub fn kernel_address(&self, offset: usize) -> Result<(*mut u8, usize), Errno> {
        if offset >= self.len() {
            return Err(Errno::EINVAL);
        }
        let page = match &self.pages {
            Pages::Found(pages) => pages[offset / PAGE_SIZE],
            Pages::OnAccess => {
                // In `self.range`, pinned lazily until `self` drops.
                let address = self.range.start() + offset / PAGE_SIZE * PAGE_SIZE;
                let frame = self
                    .page_table
                    .pinned_frame(x86_64::structures::paging::Page::containing_address(
                        VirtAddr::new(address as u64),
                    ))
                    .map_err(|error| match error {
                        PageFaultError::AllocationFailed => Errno::ENOMEM,
                        PageFaultError::AccessError(_) | PageFaultError::HugePage => Errno::EFAULT,
                    })?;
                VmKernel::pa_to_va(frame.start_address()).as_u64().trunc()
            }
        };
        let within = offset % PAGE_SIZE;
        Ok(((page + within) as *mut u8, PAGE_SIZE - within))
    }
}

impl RawMutexProvider for VmKernel {
    type RawMutex = RawMutex;
}

impl WaitWakerProvider for VmKernel {}

/// On a task ([`worker`]), a waiter suspends the task: a release, which
/// changes the value, makes it due (see [`worker::Wait`]). Elsewhere, no
/// kernel thread blocks, so nothing wakes a waiter: it spins until another
/// CPU changes the value (every wake follows a change), with [`cpu::relax`],
/// taking interrupts meanwhile, as a halt does. The holder may be a task
/// suspended on its CPU, until that resumes it: so code that is not a task
/// must not wait for a lock that a task may hold across a suspension (see
/// [`worker`]); debug builds panic if it would spin with a task suspended on
/// its CPU. A spin that sees no change for [`LOCK_WARNING`] warns, once, and
/// spins on: it may be a deadlock (e.g., the holder's CPU waits for the
/// spinning one; which CPU holds a lock is unknown), or a long hold. With no
/// other CPU online, spinning would deadlock, and panics; timeouts are
/// unsupported (no kernel code uses one), and panic.
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
        // For the waiting tasks; the others spin.
        worker::wake_blocked(cpu::current());
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

/// How long a [`RawMutex`] spins seeing no change, or a claim stays held for
/// a waiter (see the shim), before it warns of a possible deadlock (once per
/// wait); it then waits on, as some locks are held longer: e.g., an open
/// file's, across a whole read, which takes a 9P round trip per message, each
/// up to 30 s, the total unbounded.
pub const LOCK_WARNING: core::time::Duration = core::time::Duration::from_mins(1);

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let value = || {
            self.underlying_atomic()
                .load(core::sync::atomic::Ordering::Relaxed)
        };
        if timeout.is_none() && worker::on_task() {
            // Before the last look (see `worker::Wait`).
            let seen = worker::wakes();
            if value() != val {
                return Err(ImmediatelyWokenUp);
            }
            // Safety: `self` outlives the wait, which ends in this call.
            worker::suspend(unsafe { worker::Wait::lock(&self.inner, val, seen) });
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
        if value() != val {
            return Err(ImmediatelyWokenUp);
        }
        debug_assert_eq!(
            worker::live_here(),
            0,
            "code that is not a task waits for a lock, which a task suspended on its CPU may \
             hold (see `worker`)"
        );
        assert!(
            timeout.is_none() && cpu::online_count() > 1,
            "blocking in the VM guest kernel, with no other CPU to release the lock, or with a \
             timeout, would deadlock (see `RawMutex`)"
        );
        let platform = boot::started().expect("other CPUs are online once started");
        let deadline = platform
            .now()
            .checked_add(LOCK_WARNING)
            .expect("the clock is far from overflowing");
        let mut warned = false;
        while value() == val {
            if !warned && platform.now() >= deadline {
                litebox_util_log::warn!(
                    lock:? = core::ptr::from_ref(self),
                    waited:? = LOCK_WARNING;
                    "still spinning for a lock: a deadlock? (see `RawMutex`)"
                );
                warned = true;
            }
            cpu::relax();
        }
        Ok(UnblockedOrTimedOut::Unblocked)
    }
}

/// An instant on the kernel clock (see `litebox_common_vm_abi`), in
/// nanoseconds from the installed [`clock::ClockSource`]; `from_nanos` and
/// `as_nanos` convert to and from ABI times.
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
fn vm_flags(permissions: MemoryRegionPermissions, options: AllocationOptions) -> VmFlags {
    let mut flags = VmFlags::from_bits(permissions.bits().into())
        .expect("MemoryRegionPermissions bits are VmFlags bits");
    flags.set(
        VmFlags::VM_GROWSDOWN,
        options.contains(AllocationOptions::GROWS_DOWN),
    );
    flags.set(
        VmFlags::VM_SHARED,
        options.contains(AllocationOptions::SHARED),
    );
    flags
}

litebox::define_page_reservation!(VmReservation);

impl<const ALIGN: usize> PageManagementProvider<ALIGN> for VmKernel {
    type Reservations = NoTrackedReservations<ALIGN, VmReservation<ALIGN>>;

    const TASK_ADDR_MIN: usize = USER_ADDR_MIN;
    const TASK_ADDR_MAX: usize = USER_ADDR_MAX;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Exact;

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        options: AllocationOptions,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>
    where
        Reservations: Iterator<Item = &'reservation VmReservation<ALIGN>>,
        VmReservation<ALIGN>: 'reservation,
    {
        let range = PageRange::new(range.start, range.end).ok_or(AllocationError::Unaligned)?;
        let current_pt = self.page_table_manager.current_page_table();
        let flags = vm_flags(permissions, options);
        // Safety: the caller excludes conflicting accesses to the covered reservation.
        unsafe { current_pt.mprotect_pages(range, flags) }
            .expect("failed to protect committed pages");
        // Safety: the supplied reservations cover this user address range.
        unsafe { current_pt.map_pages(range, flags, options.contains(AllocationOptions::POPULATE)) }
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        options: AllocationOptions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<VmReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = VmReservation<ALIGN>>,
    {
        if suggested_range.start == 0
            && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_))
        {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        let range = PageRange::new(suggested_range.start, suggested_range.end)
            .ok_or(AllocationError::Unaligned)?;
        if range.start() < USER_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end() > USER_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        let current_pt = self.page_table_manager.current_page_table();
        match fixed_address_behavior {
            FixedAddressBehavior::Hint(_) | FixedAddressBehavior::NoReplace => {}
            FixedAddressBehavior::Replace => {
                // Safety: the caller replaces this range, so nothing uses it,
                // and, owning it, changes it no other way meanwhile.
                // Unmapping fails only for an unaligned range.
                unsafe { current_pt.unmap_pages(range, UnmapOptions::RELEASE) }
                    .map_err(|_| AllocationError::Unaligned)?;
                replaced_reservations().for_each(drop);
            }
        }
        let flags = vm_flags(initial_permissions, options);
        let populate = options.contains(AllocationOptions::POPULATE);
        // Safety: user address space (checked above) that the page manager
        // tracks as free (`Replace` unmapped it above).
        unsafe { current_pt.map_pages(range, flags, populate) }?;
        // Safety: the page table now exclusively owns this exact aligned extent.
        Ok(unsafe { VmReservation::new(suggested_range) })
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation VmReservation<ALIGN>>,
        VmReservation<ALIGN>: 'reservation,
    {
        // Safety: releasing backing preserves the caller's reservation ownership.
        unsafe { <Self as PageManagementProvider<ALIGN>>::release_pages(self, range) }
    }

    unsafe fn release_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError> {
        let range = PageRange::new(range.start, range.end).ok_or(DeallocationError::Unaligned)?;
        // Safety: forwarded to the caller, who no longer uses `range`, and,
        // owning it, changes it no other way meanwhile.
        unsafe {
            self.page_table_manager
                .current_page_table()
                .unmap_pages(range, UnmapOptions::RELEASE)
        }
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>
    where
        Reservations: Iterator<Item = &'reservation VmReservation<ALIGN>>,
        VmReservation<ALIGN>: 'reservation,
    {
        let range =
            PageRange::new(range.start, range.end).ok_or(PermissionUpdateError::Unaligned)?;
        let new_flags = vm_flags(new_permissions, AllocationOptions::empty());
        // Safety: forwarded to the caller.
        unsafe {
            self.page_table_manager
                .current_page_table()
                .mprotect_pages(range, new_flags)
        }
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
/// `init` fills `ctx`, which is sanitized before user mode. Resets `state`.
/// A context that cannot return to user mode (its instruction or stack
/// pointer outside user memory) ends the run too: at a `syscall`, before the
/// shim sees it, or once the shim resumes the thread.
///
/// # Safety
///
/// The platform must be set up (see the crate docs), and no other
/// `run_thread_ref`/`reenter_thread_ref` call may be in progress on the
/// calling CPU.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut PtRegs, state: &mut UserThreadState)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, false, state, true);
}

/// Re-enter a thread, e.g., after `load_ta_context`. The shim's `reenter`
/// fills `ctx`, which is sanitized before user mode. Resets `state`.
///
/// # Safety
///
/// As for [`run_thread_ref`].
pub unsafe fn reenter_thread_ref<T>(shim: &T, ctx: &mut PtRegs, state: &mut UserThreadState)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, true, state, true);
}

/// As [`reenter_thread_ref`], but keeps `state`, for a thread suspended
/// anywhere (e.g., preempted).
///
/// # Safety
///
/// As for [`run_thread_ref`].
pub unsafe fn resume_thread_ref<T>(shim: &T, ctx: &mut PtRegs, state: &mut UserThreadState)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, true, state, false);
}

/// A user thread's state that the platform keeps across its runs, besides
/// registers and the FS base (the caller's): extended state (x87, SSE), in
/// the thread's own XSAVE area, and the GS base.
pub struct UserThreadState {
    area: alloc::boxed::Box<per_cpu::XsaveArea>,
    xsaved: per_cpu::XsaveState,
    gs_base: VirtAddr,
}

/// The initial state, as a reset leaves it (see [`run_thread_ref`]), with a
/// zero GS base.
impl Default for UserThreadState {
    fn default() -> Self {
        Self {
            area: alloc::boxed::Box::new(per_cpu::XsaveArea::initial()),
            xsaved: per_cpu::XsaveState::default(),
            gs_base: VirtAddr::zero(),
        }
    }
}

impl UserThreadState {
    /// A new thread's: initial extended state, and `gs_base`, for
    /// [`resume_thread_ref`] to start it with. `None` unless `gs_base` is a
    /// user address, or zero.
    pub fn with_gs_base(gs_base: u64) -> Option<Self> {
        let user = usize::try_from(gs_base)
            .is_ok_and(|addr| addr == 0 || (USER_ADDR_MIN..USER_ADDR_MAX).contains(&addr));
        user.then(|| Self {
            gs_base: VirtAddr::new(gs_base),
            ..Self::default()
        })
    }

    /// A copy, with the same extended state and GS base, for
    /// [`resume_thread_ref`] to continue it with. XSAVEOPT may save to a
    /// buffer only after an XRSTOR from it, so the copy's area, a new buffer,
    /// is saved with XSAVE until restored.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            area: self.area.clone(),
            xsaved: match self.xsaved {
                per_cpu::XsaveState::NeverSaved => per_cpu::XsaveState::NeverSaved,
                per_cpu::XsaveState::Saved | per_cpu::XsaveState::Restored => {
                    per_cpu::XsaveState::Saved
                }
            },
            gs_base: self.gs_base,
        }
    }
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
    state: &mut UserThreadState,
    reset: bool,
) {
    // SWAPGS exposes KernelGsBase to user code.
    if reset {
        state.gs_base = VirtAddr::zero();
    }
    crate::arch::write_kernel_gsbase_msr(state.gs_base);
    let area = core::ptr::from_mut(&mut *state.area);
    with_per_cpu_variables(|pcv| {
        pcv.asm.install_user_xsave(area, state.xsaved);
        if reset {
            pcv.asm.reset_user_xsave();
        }
    });
    let ctx = core::ptr::from_mut(ctx);
    let thread_ctx = ThreadContext { shim, ctx };
    // `ctx` is passed again so the assembly need not know `ThreadContext`'s layout.
    // Safety: `ctx` is valid and otherwise unused for the duration of the call,
    // and `run_thread_arch` returns exactly once.
    unsafe {
        run_thread_arch(&thread_ctx, ctx, u8::from(reenter));
    }
    // Not left installed: the thread's area may be freed before the next run.
    state.xsaved = with_per_cpu_variables(|pcv| pcv.asm.uninstall_user_xsave());
    state.gs_base = crate::arch::read_kernel_gsbase_msr();
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
        // From `isr_external`, for an external interrupt of user mode. On
        // entry: rsp = ISR stack [vector, error_code, rip, cs,
        // rflags, rsp, ss] (vector and error code are placeholders, unused),
        // all GPRs hold the interrupted values, IF is clear, and GS is still
        // the user's.
        ".globl interrupt_callback",
        "interrupt_callback:",
        "cld",
        "clac",
        "swapgs",
        "mov gs:[{scratch_off}], rax",
        "mov rax, rsp", // ISR stack, for SAVE_PF_USER_CONTEXT_ASM
        "mov rsp, gs:[{user_context_top_off}]",
        SAVE_PF_USER_CONTEXT_ASM!(),
        XSAVE_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
        "mov rbp, gs:[{cur_kernel_bp_off}]",
        "mov rsp, gs:[{cur_kernel_sp_off}]",
        "mov rdi, [rsp]", // pass `thread_ctx`
        "call {interrupt_handler}",
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
        interrupt_handler = sym interrupt_handler,
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

/// An external interrupt, which [`set_interrupt_handler`]'s handler has
/// handled, interrupted a process. `ctx` is whatever it was running at the
/// time; the shim decides whether and how to act on it (e.g., deliver
/// `UpcallKind::Interrupt`, defined in `litebox_common_vm_abi`, which this
/// crate does not depend on).
unsafe extern "C" fn interrupt_handler(thread_ctx: &ThreadContext) {
    // Safety: entered from user mode; see `ThreadContext`.
    let ctx = unsafe { &mut *thread_ctx.ctx };
    if let ContinueOperation::Resume = thread_ctx.shim.interrupt(ctx) {
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
