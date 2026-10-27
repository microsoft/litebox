// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::ops::Range;
use core::sync::atomic::{Ordering, compiler_fence};
use hashbrown::HashMap;
use litebox::mm::page::PageRange;
use litebox::platform::page_mgmt;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmem::{PageFaultError, VmFlags, VmemPageFaultHandler};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            FrameAllocator, FrameDeallocator, MappedPageTable, Mapper, Page, PageSize, PageTable,
            PageTableFlags, PhysFrame, Size4KiB, Translate,
            frame::PhysFrameRange,
            mapper::{CleanUp, MapToError, MappedFrame, PageTableFrameMapping, TranslateResult},
            page_table::PageTableEntry,
        },
    },
};

use crate::UserMutPtr;
use crate::mm::{
    MemoryProvider,
    pgtable::{COW, PROT_NONE, PageTableAllocator, PageTableImpl, SHARED},
};
use crate::tlb;

const PAGE_SHIFT: usize = Size4KiB::SIZE.trailing_zeros() as usize;
const PAGE_TABLE_LEVEL_BITS: usize = 9;
const P2_SHIFT: usize = PAGE_SHIFT + PAGE_TABLE_LEVEL_BITS;
const P3_SHIFT: usize = P2_SHIFT + PAGE_TABLE_LEVEL_BITS;
const PML4_SHIFT: usize = P3_SHIFT + PAGE_TABLE_LEVEL_BITS;
const PML4_INDEX_MASK: u64 = (1 << PAGE_TABLE_LEVEL_BITS) - 1;

/// Kernel slots share fixed P3/P2/P1 tables; lower slots must be privately owned.
pub(crate) const KERNEL_PML4_START: usize =
    ((crate::KERNEL_OFFSET >> PML4_SHIFT) & PML4_INDEX_MASK) as usize;

/// The end of the user PML4 slots: the lower canonical half. The private
/// slots above it, up to [`KERNEL_PML4_START`], hold no user address.
const USER_PML4_END: usize = (1 << PAGE_TABLE_LEVEL_BITS) / 2;

/// The span of the leaves an operation changed whose old translations other
/// CPUs may still use, to flush once (Linux's `mmu_gather` range): present
/// leaves that lost a permission or their frame.
#[derive(Default)]
struct Stale(Option<x86_64::structures::paging::page::PageRange<Size4KiB>>);

impl Stale {
    fn add(&mut self, page: Page<Size4KiB>) {
        self.0 = Some(match self.0 {
            Some(pages) => Page::range(pages.start.min(page), pages.end.max(page + 1)),
            None => Page::range(page, page + 1),
        });
    }
}

/// Whether a leaf's flags changing from `old` to `new` may leave a stale
/// translation that matters: unless not present (so not cached), anything but
/// gaining `WRITABLE` (a write through a stale read-only translation faults,
/// which drops it, and then finds the leaf writable: see
/// `handle_page_fault`).
fn needs_flush(old: PageTableFlags, new: PageTableFlags) -> bool {
    old.contains(PageTableFlags::PRESENT)
        && !((old - new).is_empty() && (new - old - PageTableFlags::WRITABLE).is_empty())
}

#[inline]
fn frame_to_pointer<M: MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

/// The leaf entry of `page`; if a table on the way is absent (or its entry
/// maps a huge page, which none does: asserted in debug builds), `Err` with
/// the address where that entry's span ends, before which no page has a leaf
/// entry.
fn leaf_entry<M: MemoryProvider>(
    mut table: &mut PageTable,
    page: Page<Size4KiB>,
) -> Result<&mut PageTableEntry, u64> {
    for (index, shift) in [
        (page.p4_index(), PML4_SHIFT),
        (page.p3_index(), P3_SHIFT),
        (page.p2_index(), P2_SHIFT),
    ] {
        let entry = &table[index];
        let Ok(frame) = entry.frame() else {
            debug_assert!(
                !entry.flags().contains(PageTableFlags::HUGE_PAGE),
                "huge pages are not supported"
            );
            let span = (1u64 << shift) - 1;
            return Err((page.start_address().as_u64() | span).saturating_add(1));
        };
        // Safety: these are live intermediate tables reached under the owning
        // page table's lock; `frame()` rejects absent and huge-page entries.
        table = unsafe { &mut *frame_to_pointer::<M>(frame) };
    }
    Ok(&mut table[page.p1_index()])
}

/// Calls `f` with each of the first `limit` pages of `pages` that have a leaf
/// entry, and that entry, leaving the rest in `pages`. Skips the spans of
/// absent tables whole, so it takes time that follows the tables, not the
/// range (e.g., a whole address space with little mapped).
fn for_each_leaf<M: MemoryProvider>(
    p4: &mut PageTable,
    pages: &mut x86_64::structures::paging::page::PageRange<Size4KiB>,
    limit: usize,
    mut f: impl FnMut(Page<Size4KiB>, &mut PageTableEntry),
) {
    let mut leaves = 0;
    while leaves < limit && !pages.is_empty() {
        let page = pages.start;
        match leaf_entry::<M>(p4, page) {
            Ok(entry) => {
                pages.start = page + 1;
                leaves += 1;
                f(page, entry);
            }
            Err(next) if next < pages.end.start_address().as_u64() => {
                pages.start = Page::containing_address(VirtAddr::new(next));
            }
            Err(_) => pages.start = pages.end,
        }
    }
}

/// Calls `f` with each leaf entry of the user PML4 slots (below
/// [`USER_PML4_END`]) and its page.
fn for_each_user_leaf<'a, M: MemoryProvider>(
    p4: &'a mut PageTable,
    mut f: impl FnMut(Page<Size4KiB>, &mut PageTableEntry),
) {
    let next = |entry: &PageTableEntry| -> Option<&'a mut PageTable> {
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            litebox_util_log::error!("BUG: huge pages are not supported");
            debug_assert!(false, "huge pages are not supported");
            return None;
        }
        // Safety: a live intermediate table of the page table whose P4 the
        // caller holds exclusively.
        Some(unsafe { &mut *frame_to_pointer::<M>(entry.frame().ok()?) })
    };
    for (p4_index, p4_entry) in p4.iter().enumerate().take(USER_PML4_END) {
        let Some(p3) = next(p4_entry) else { continue };
        for (p3_index, p3_entry) in p3.iter().enumerate() {
            let Some(p2) = next(p3_entry) else { continue };
            for (p2_index, p2_entry) in p2.iter().enumerate() {
                let Some(p1) = next(p2_entry) else { continue };
                for (p1_index, p1_entry) in p1.iter_mut().enumerate() {
                    let address = (p4_index << PML4_SHIFT)
                        | (p3_index << P3_SHIFT)
                        | (p2_index << P2_SHIFT)
                        | (p1_index << PAGE_SHIFT);
                    let page = Page::from_start_address(VirtAddr::new(address as u64))
                        .expect("lower-half indices make an aligned canonical address");
                    f(page, p1_entry);
                }
            }
        }
    }
}

/// The frames that more than one user leaf maps, each with [`COW`] or [`SHARED`], and how many
/// leaves map each. A frame it does not count belongs to its one leaf.
static SHARED_FRAMES: spin::Once<spin::Mutex<SharedFrames>> = spin::Once::new();

/// [`SHARED_FRAMES`], locked.
pub(crate) fn shared_frames() -> spin::MutexGuard<'static, SharedFrames> {
    SHARED_FRAMES.call_once(Default::default).lock()
}

/// Frames per block of [`SharedFrames`]: a page of counts, for 4 MiB of RAM.
const BLOCK_FRAMES: usize = (1 << PAGE_SHIFT) / size_of::<u32>();

/// Leaf counts by frame number, in blocks of a page: the kernel heap, which
/// page frames come from too, may have no larger free block. A block lives
/// only while one of its frames is shared. Room to count a leaf is reserved,
/// fallibly, before a second leaf maps a frame ([`Self::reserve`]); nothing
/// else allocates.
#[derive(Default)]
pub(crate) struct SharedFrames {
    /// By frame number divided by [`BLOCK_FRAMES`].
    blocks: HashMap<u64, Block>,
}

struct Block {
    /// How many of its frames are shared.
    shared: usize,
    /// By frame number modulo [`BLOCK_FRAMES`]: a shared frame's leaves (at
    /// least 2), or 0.
    leaves: Vec<u32>,
}

impl Block {
    /// With no frame shared; `None` if the heap is exhausted.
    fn new() -> Option<Self> {
        let mut leaves = Vec::new();
        leaves.try_reserve_exact(BLOCK_FRAMES).ok()?;
        leaves.resize(BLOCK_FRAMES, 0);
        Some(Self { shared: 0, leaves })
    }
}

/// The key of `frame`'s block in [`SharedFrames`], and its index there.
fn block_index(frame: PhysFrame) -> (u64, usize) {
    let number = frame.start_address().as_u64() / Size4KiB::SIZE;
    let frames = BLOCK_FRAMES as u64;
    (number / frames, (number % frames).trunc())
}

impl SharedFrames {
    /// Whether more than one leaf maps `frame`.
    fn contains(&self, frame: PhysFrame) -> bool {
        let (key, index) = block_index(frame);
        self.blocks
            .get(&key)
            .is_some_and(|block| block.leaves[index] != 0)
    }

    /// Makes room for [`Self::add_leaf`] to count one more leaf of `frame`.
    /// If `frame` has no block, returns a new one, with room for it in the
    /// map, which `add_leaf` adds: until then, dropping it frees it.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if the heap is exhausted, or `frame`'s count is at its
    /// maximum.
    fn reserve(&mut self, frame: PhysFrame) -> Result<Option<Block>, page_mgmt::AllocationError> {
        let (key, index) = block_index(frame);
        if let Some(block) = self.blocks.get(&key) {
            return if block.leaves[index] == u32::MAX {
                Err(page_mgmt::AllocationError::OutOfMemory)
            } else {
                Ok(None)
            };
        }
        self.blocks
            .try_reserve(1)
            .map_err(|_| page_mgmt::AllocationError::OutOfMemory)?;
        Block::new()
            .map(Some)
            .ok_or(page_mgmt::AllocationError::OutOfMemory)
    }

    /// Counts one more leaf of `frame`, with the `room` that [`Self::reserve`]
    /// made.
    fn add_leaf(&mut self, frame: PhysFrame, room: Option<Block>) {
        let (key, index) = block_index(frame);
        let block = match room {
            Some(new) => self.blocks.entry(key).or_insert(new),
            None => self
                .blocks
                .get_mut(&key)
                .expect("a reserved frame has a block"),
        };
        let leaves = &mut block.leaves[index];
        if *leaves == 0 {
            // Its first leaf, and this one.
            *leaves = 2;
            block.shared += 1;
        } else {
            *leaves += 1;
        }
    }

    /// Counts one leaf of `frame` fewer; false if no other leaf maps it, so
    /// it was the leaf's alone.
    fn remove_leaf(&mut self, frame: PhysFrame) -> bool {
        let (key, index) = block_index(frame);
        let Some(block) = self.blocks.get_mut(&key) else {
            return false;
        };
        match block.leaves[index] {
            0 => return false,
            2 => {
                block.leaves[index] = 0;
                block.shared -= 1;
                if block.shared == 0 {
                    self.blocks.remove(&key);
                }
            }
            _ => block.leaves[index] -= 1,
        }
        true
    }

    /// How many frames are shared.
    pub(crate) fn len(&self) -> usize {
        self.blocks.values().map(|block| block.shared).sum()
    }

    /// Whether no block is left, as none is once no frame is shared.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Releases a user leaf's frame, mapped with `flags`, which the leaf no
/// longer maps: frees it unless another leaf maps it.
///
/// # Safety
///
/// No access or stale translation through the leaf may remain.
unsafe fn release_user_frame<M: MemoryProvider>(frame: PhysFrame, flags: PageTableFlags) {
    if flags.intersects(COW | SHARED) && shared_frames().remove_leaf(frame) {
        return;
    }
    // Safety: the leaf was the frame's only one, and the caller guarantees
    // nothing reaches it through it anymore.
    unsafe { PageTableAllocator::<M>::new().deallocate_frame(frame) };
}

/// Maps `page`, which has no leaf, to a fresh, zeroed frame with `flags`;
/// the frame.
///
/// # Safety
///
/// `page` must be user memory its owner may access as `flags` allow.
unsafe fn map_fresh_frame<M: MemoryProvider>(
    inner: &mut MappedPageTable<'_, FrameMapping<M>>,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame, PageFaultError> {
    let mut allocator = PageTableAllocator::<M>::new();
    let frame =
        PageTableAllocator::<M>::allocate_frame().ok_or(PageFaultError::AllocationFailed)?;
    // ACCESSED and DIRTY are preset in parent entries, so the page walker
    // never has to set them; it sets a leaf's (see `vmflags_to_pteflags`).
    let table_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::ACCESSED
        | PageTableFlags::DIRTY;
    // Safety: `frame` is fresh and exclusively owned, and the caller may map
    // `page` so.
    match unsafe { inner.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator) }
    {
        // A newly present entry needs no flush.
        Ok(flush) => {
            flush.ignore();
            Ok(frame)
        }
        Err(e) => {
            // Safety: never mapped.
            unsafe { allocator.deallocate_frame(frame) };
            match e {
                MapToError::PageAlreadyMapped(_) => unreachable!(),
                MapToError::ParentEntryHugePage => Err(PageFaultError::HugePage),
                MapToError::FrameAllocationFailed => Err(PageFaultError::AllocationFailed),
            }
        }
    }
}

pub(crate) struct X64PageTable<'a, M: MemoryProvider, const ALIGN: usize> {
    inner: spin::mutex::SpinMutex<MappedPageTable<'a, FrameMapping<M>>>,
    /// For CR3 and shootdowns, without `inner`.
    p4: PhysFrame,
    /// See [`tlb::Cpus`]; never set for the base and trampoline tables.
    cpus: tlb::Cpus,
    /// The ranges of [`Self::pin`] and [`Self::pin_lazily`]: their frames are
    /// never shared.
    pinned: spin::Mutex<Vec<Range<usize>>>,
}

struct FrameMapping<M: MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

// Safety: page-table frames come from `M`, whose memory is in the kernel
// mapping, so `pa_to_va` yields a valid pointer to each table.
unsafe impl<M: MemoryProvider> PageTableFrameMapping for FrameMapping<M> {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        frame_to_pointer::<M>(frame)
    }
}

// Safety: `allocate_frame` returns fresh, exclusively owned frames from `M`.
unsafe impl<M: MemoryProvider> FrameAllocator<Size4KiB> for PageTableAllocator<M> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        Self::allocate_frame()
    }
}

impl<M: MemoryProvider> FrameDeallocator<Size4KiB> for PageTableAllocator<M> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let vaddr = M::pa_to_va(frame.start_address());
        // Safety: the caller passes a frame from `allocate_frame`, i.e., an
        // order-0 allocation from `M`, that is no longer used.
        unsafe { M::mem_free_pages(vaddr.as_mut_ptr(), 0) };
    }
}

/// A user leaf's flags for `values`. Its ACCESSED and DIRTY are not tracked,
/// so the kernel's changes of the leaf's flags may discard them.
pub(crate) fn vmflags_to_pteflags(values: VmFlags) -> PageTableFlags {
    let mut flags = PageTableFlags::empty();
    if values.intersects(VmFlags::VM_ACCESS_FLAGS) {
        flags |= PageTableFlags::USER_ACCESSIBLE | PageTableFlags::PRESENT;
    } else {
        flags |= PROT_NONE;
    }
    if values.contains(VmFlags::VM_WRITE) {
        flags |= PageTableFlags::WRITABLE;
    }
    if !values.contains(VmFlags::VM_EXEC) {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    if values.contains(VmFlags::VM_SHARED) {
        flags |= SHARED;
    }
    flags
}

#[derive(Clone, Copy)]
pub(crate) struct UnmapOptions {
    /// Must be false for frames owned elsewhere, including stack guards.
    pub(crate) free_frames: bool,
    /// May be false only for a table that no CPU uses, now or ever again.
    pub(crate) flush_tlb: bool,
    /// Must be false for shared intermediate tables.
    pub(crate) free_empty_tables: bool,
}

impl UnmapOptions {
    pub(crate) const RELEASE: Self = Self {
        free_frames: true,
        flush_tlb: true,
        free_empty_tables: false,
    };
    pub(crate) const KEEP_FRAMES: Self = Self {
        free_frames: false,
        flush_tlb: true,
        free_empty_tables: false,
    };
}

impl<M: MemoryProvider, const ALIGN: usize> X64PageTable<'_, M, ALIGN> {
    /// # Safety
    ///
    /// `range` must be user address space the caller may map with `flags`, and
    /// nothing may be mapped in it yet.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if populating runs out of frames; the pages populated so
    /// far are unmapped again.
    pub(crate) unsafe fn map_pages(
        &self,
        range: PageRange<ALIGN>,
        flags: VmFlags,
        populate_pages: bool,
    ) -> Result<UserMutPtr<u8>, page_mgmt::AllocationError> {
        if populate_pages {
            let flags = vmflags_to_pteflags(flags);
            for addr in range {
                let page =
                    Page::<Size4KiB>::from_start_address(VirtAddr::new(addr as u64)).unwrap();
                // Safety: the caller may map `range` with `flags`.
                match unsafe {
                    PageTableImpl::handle_page_fault(self, page, flags, PageFaultErrorCode::empty())
                } {
                    Ok(()) => {}
                    Err(PageFaultError::AllocationFailed) => {
                        if addr != range.start() {
                            let populated = PageRange::new(range.start(), addr)
                                .expect("a nonempty prefix of an aligned range is aligned");
                            // Safety: mapped above and not yet handed out.
                            unsafe { self.unmap_pages(populated, UnmapOptions::RELEASE) }
                                .expect("unmapping an aligned range cannot fail");
                        }
                        return Err(page_mgmt::AllocationError::OutOfMemory);
                    }
                    // This table has no huge pages, and `range` was unmapped.
                    Err(e) => panic!("BUG: populating {addr:#x}: {e:?}"),
                }
            }
        }
        Ok(UserMutPtr::from_ptr(range.start() as *mut u8))
    }

    /// First revokes the present leaves of `range`, which keep their frames
    /// as `PROT_NONE` ones do, so that one shootdown covers them all, then
    /// removes the leaves, freeing their frames a batch at a time.
    ///
    /// # Safety
    ///
    /// Nothing may use the pages it unmaps, and the caller must serialize it
    /// with any other call that changes leaves of `range` (e.g.,
    /// `mprotect_pages`, which could make a revoked leaf present again, or
    /// another unmap, which could free its frame before the shootdown).
    /// Without `flush_tlb`, no CPU may use the table, now or ever again, as
    /// stale TLB entries may still reach the freed frames.
    pub(crate) unsafe fn unmap_pages(
        &self,
        range: PageRange<ALIGN>,
        options: UnmapOptions,
    ) -> Result<(), page_mgmt::DeallocationError> {
        /// Leaf entries walked per hold of `inner` (not counting the spans of
        /// absent tables, skipped whole), so leaves freed per batch.
        const UNMAP_BATCH: usize = 512;
        if range.is_empty() {
            return Ok(());
        }
        let start = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.start() as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let end = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.end() as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let mut allocator = PageTableAllocator::<M>::new();

        if options.flush_tlb {
            let mut stale = Stale::default();
            let mut rest = Page::range(start, end);
            while !rest.is_empty() {
                let mut inner = self.inner.lock();
                for_each_leaf::<M>(
                    inner.level_4_table_mut(),
                    &mut rest,
                    UNMAP_BATCH,
                    |page, entry| {
                        let flags = entry.flags();
                        if flags.contains(PageTableFlags::PRESENT) {
                            entry.set_flags((flags - PageTableFlags::PRESENT) | PROT_NONE);
                            stale.add(page);
                        }
                    },
                );
            }
            self.flush(stale);
        }
        let mut rest = Page::range(start, end);
        while !rest.is_empty() {
            let mut unmapped: ArrayVec<PageTableEntry, UNMAP_BATCH> = ArrayVec::new();
            let mut inner = self.inner.lock();
            for_each_leaf::<M>(
                inner.level_4_table_mut(),
                &mut rest,
                UNMAP_BATCH,
                |_, entry| {
                    if entry.is_unused() {
                        return;
                    }
                    debug_assert!(
                        !(options.flush_tlb && entry.flags().contains(PageTableFlags::PRESENT)),
                        "a revoked leaf made present again"
                    );
                    unmapped.push(entry.clone());
                    entry.set_unused();
                },
            );
            drop(inner);
            if options.free_frames {
                for entry in unmapped {
                    let frame = PhysFrame::containing_address(entry.addr());
                    // Safety: unmapped, and flushed (or never used again);
                    // the caller guarantees nothing else uses it.
                    unsafe { release_user_frame::<M>(frame, entry.flags()) };
                }
            }
        }

        if options.free_empty_tables {
            // Safety: all leaf entries in the range have been unmapped above;
            // the caller guarantees this VA range is no longer in use.
            unsafe {
                self.inner
                    .lock()
                    .clean_up_addr_range(Page::range_inclusive(start, end - 1u64), &mut allocator);
            }
        }

        Ok(())
    }

    /// Flushes the `stale` translations of the leaves the caller changed, on
    /// every CPU that may cache them (see [`tlb`]). Not under `inner`, nor
    /// any other spin lock; before freeing the leaves' old frames.
    fn flush(&self, stale: Stale) {
        if let Some(pages) = stale.0 {
            M::flush_tlb(&self.cpus, self.p4, pages);
        }
    }

    pub(crate) unsafe fn mprotect_pages(
        &self,
        range: PageRange<ALIGN>,
        new_flags: VmFlags,
    ) -> Result<(), page_mgmt::PermissionUpdateError> {
        let start = VirtAddr::new(range.start() as _);
        let end = VirtAddr::new(range.end() as _);
        let new_flags = vmflags_to_pteflags(new_flags) & Self::MPROTECT_PTE_MASK;
        let start: Page<Size4KiB> =
            Page::from_start_address(start).or(Err(page_mgmt::PermissionUpdateError::Unaligned))?;
        let end: Page<Size4KiB> = Page::containing_address(end - 1);

        let mut stale = Stale::default();
        let mut inner = self.inner.lock();
        let mut pages = Page::range(start, end + 1);
        for_each_leaf::<M>(
            inner.level_4_table_mut(),
            &mut pages,
            usize::MAX,
            |page, entry| {
                if entry.is_unused() {
                    return;
                }
                let flags = entry.flags();
                // A shared frame becomes writable only through a write fault.
                let new_flags = if flags.contains(COW) {
                    new_flags - PageTableFlags::WRITABLE
                } else {
                    new_flags
                };
                let old_flags = flags & Self::MPROTECT_PTE_MASK;
                if old_flags != new_flags {
                    // Retains the owned frame, including PROT_NONE leaves;
                    // stale translations are flushed below.
                    entry.set_flags((flags & !Self::MPROTECT_PTE_MASK) | new_flags);
                    if needs_flush(old_flags, new_flags) {
                        stale.add(page);
                    }
                }
            },
        );
        drop(inner);
        // Stale TLB entries may keep the old permissions (see `needs_flush`).
        self.flush(stale);
        Ok(())
    }

    /// The frames of `range`, all present, user-accessible, and writable
    /// (so none shared), which [`Self::clone_user_mappings`] leaves out of
    /// clones (so they are never shared), until [`Self::unpin`]; `None` if
    /// any is not.
    pub(crate) fn pin(&self, range: PageRange<ALIGN>) -> Option<Box<[PhysFrame]>> {
        let inner = self.inner.lock();
        let frames = range
            .into_iter()
            .map(|addr| match inner.translate(VirtAddr::new(addr as u64)) {
                TranslateResult::Mapped {
                    frame: MappedFrame::Size4KiB(frame),
                    offset: _,
                    flags,
                } if flags.contains(
                    PageTableFlags::PRESENT
                        | PageTableFlags::USER_ACCESSIBLE
                        | PageTableFlags::WRITABLE,
                ) =>
                {
                    Some(frame)
                }
                _ => None,
            })
            .collect::<Option<Box<_>>>()?;
        self.pinned.lock().push(range.start()..range.end());
        Some(frames)
    }

    /// Ends one [`Self::pin`] of `range`.
    pub(crate) fn unpin(&self, range: PageRange<ALIGN>) {
        let mut pinned = self.pinned.lock();
        let index = pinned
            .iter()
            .position(|pin| *pin == (range.start()..range.end()))
            .expect("unpinning a pinned range");
        pinned.swap_remove(index);
    }

    /// Pins `range` as [`Self::pin`] does, but its pages need not be present:
    /// [`Self::pinned_frame`] finds each, populating it if it has no leaf.
    ///
    /// # Safety
    ///
    /// Until [`Self::unpin`], nothing may unmap or remap `range`, and those of
    /// its pages with no leaf must be ones their owner may map read-write
    /// (e.g., in a lazy read-write mapping).
    pub(crate) unsafe fn pin_lazily(&self, range: PageRange<ALIGN>) {
        self.pinned.lock().push(range.start()..range.end());
    }

    /// The frame of `page`, if mapped writable, or, if it has no leaf,
    /// populated so. `page` must be in a range [pinned lazily](Self::pin_lazily)
    /// (asserted to be pinned in debug builds). Walks the table through the
    /// kernel mapping, so with whichever table is current.
    ///
    /// # Errors
    ///
    /// `AllocationFailed` if populating runs out of frames, and `AccessError`
    /// if the page is mapped but not writable (e.g., protected since it was
    /// pinned).
    pub(crate) fn pinned_frame(&self, page: Page<Size4KiB>) -> Result<PhysFrame, PageFaultError> {
        let address: usize = page.start_address().as_u64().trunc();
        debug_assert!(
            self.pinned
                .lock()
                .iter()
                .any(|range| range.contains(&address)),
            "page {address:#x} is not pinned"
        );
        let mut inner = self.inner.lock();
        match inner.translate(page.start_address()) {
            TranslateResult::Mapped {
                frame: MappedFrame::Size4KiB(frame),
                offset: _,
                flags,
            } if flags.contains(
                PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE,
            ) =>
            {
                Ok(frame)
            }
            TranslateResult::NotMapped => {
                let flags = vmflags_to_pteflags(VmFlags::VM_READ | VmFlags::VM_WRITE);
                // Safety: the caller's page is pinned lazily and has no leaf,
                // so its owner may map it read-write (see `pin_lazily`).
                unsafe { map_fresh_frame(&mut inner, page, flags) }
            }
            _ => Err(PageFaultError::AccessError("pinned page not writable")),
        }
    }

    /// Maps every user leaf of `self` but those of pinned ranges (see
    /// [`Self::pin`]) in `dst`, which has none. Pinned ranges are the
    /// kernel's (e.g., a broker control ring), and `dst`'s owner maps its own.
    /// Any other frame is shared: both leaves map it, [`SHARED`] ones as they
    /// are, and the rest [`COW`] (and so not writable).
    ///
    /// # Errors
    ///
    /// `OutOfMemory`, for frames of `dst`'s page tables or for room in
    /// [`SHARED_FRAMES`]; `dst` then maps only some of the leaves, which
    /// dropping it releases.
    pub(crate) fn clone_user_mappings(&self, dst: &Self) -> Result<(), page_mgmt::AllocationError> {
        let pinned = self.pinned.lock().clone();
        let mut allocator = PageTableAllocator::<M>::new();
        // ACCESSED and DIRTY are preset in parent entries, so the page walker
        // never has to set them; it sets a leaf's (see `vmflags_to_pteflags`).
        let table_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::ACCESSED
            | PageTableFlags::DIRTY;
        let mut src = self.inner.lock();
        let mut dst = dst.inner.lock();
        let mut result = Ok(());
        let mut stale = Stale::default();
        for_each_user_leaf::<M>(src.level_4_table_mut(), |page, entry| {
            let addr: usize = page.start_address().as_u64().trunc();
            if result.is_err()
                || entry.is_unused()
                || pinned.iter().any(|range| range.contains(&addr))
            {
                return;
            }
            let frame = PhysFrame::containing_address(entry.addr());
            let flags = if entry.flags().contains(SHARED) {
                entry.flags()
            } else {
                (entry.flags() | COW) - PageTableFlags::WRITABLE
            };
            // Per leaf, not across the walk: other CPUs' page faults, unmaps
            // and teardowns take it too, spinning. From `reserve` to
            // `add_leaf`, which adds the block `reserve` may make.
            let mut shared = shared_frames();
            // Room to count it below, before `dst` maps it.
            let room = match shared.reserve(frame) {
                Ok(room) => room,
                Err(error) => {
                    result = Err(error);
                    return;
                }
            };
            // Safety: `dst` has no user leaves, and both leaves share the frame, as COW unless it
            // is shared memory.
            match unsafe {
                dst.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator)
            } {
                Ok(flush) => flush.ignore(),
                Err(MapToError::FrameAllocationFailed) => {
                    result = Err(page_mgmt::AllocationError::OutOfMemory);
                    return;
                }
                Err(error) => panic!("BUG: mapping a leaf in an empty table: {error:?}"),
            }
            // Only those made read-only: shared memory's keep their flags, and
            // those already read-only only gain `COW`, which no CPU uses.
            if entry
                .flags()
                .contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
                && !flags.contains(PageTableFlags::WRITABLE)
            {
                stale.add(page);
            }
            entry.set_flags(flags);
            shared.add_leaf(frame, room);
        });
        drop(dst);
        drop(src);
        // The leaves made read-only may be cached writable.
        self.flush(stale);
        result
    }

    /// Maps `frame_range` at `PA + offset`: frames in `text` RX, in
    /// `read_only` R/NX, the rest RW/NX. Requires an inactive table. Kernel
    /// mappings must not demand-fault.
    pub(crate) fn map_kernel(
        &self,
        frame_range: PhysFrameRange<Size4KiB>,
        offset: u64,
        text: &Range<PhysAddr>,
        read_only: &Range<PhysAddr>,
    ) -> Result<(), MapToError<Size4KiB>> {
        let mut allocator = PageTableAllocator::<M>::new();
        // Parent entries are permissive; leaves carry the restrictions.
        // ACCESSED and DIRTY are preset in parent entries only: the page
        // walker sets a kernel leaf's itself, once.
        let table_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::ACCESSED
            | PageTableFlags::DIRTY;

        let mut inner = self.inner.lock();
        for frame in frame_range {
            let page =
                Page::from_start_address(VirtAddr::new(frame.start_address().as_u64() + offset))
                    .expect("frames are page-aligned");
            let flags = if text.contains(&frame.start_address()) {
                PageTableFlags::PRESENT
            } else if read_only.contains(&frame.start_address()) {
                PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE
            } else {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE
            };
            // Safety: `frame` is kernel-owned RAM, mapped only here.
            unsafe {
                inner.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator)
            }?
            .ignore();
        }
        Ok(())
    }

    /// Gives the kernel PML4 slot holding `va` its P3 table now, as Linux
    /// preallocates its vmalloc area's: task tables share the kernel's slots
    /// as they are at creation, so they see later mappings in it.
    ///
    /// # Panics
    ///
    /// Panics if `va` is below the kernel slots or the frame allocation fails.
    pub(crate) fn preallocate_kernel_slot(&self, va: VirtAddr) {
        assert!(usize::from(va.p4_index()) >= KERNEL_PML4_START);
        let mut inner = self.inner.lock();
        let entry = &mut inner.level_4_table_mut()[va.p4_index()];
        if entry.is_unused() {
            let frame = PageTableAllocator::<M>::allocate_frame()
                .expect("Failed to allocate a kernel P3 table");
            entry.set_frame(
                frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::ACCESSED
                    | PageTableFlags::DIRTY,
            );
        }
    }

    /// Maps device registers `frames` uncacheable at `start`, in the kernel
    /// tables that task tables share.
    ///
    /// # Safety
    ///
    /// The frames must be device registers, not RAM, and `start..` kernel
    /// address space in an existing kernel PML4 slot, used for nothing else.
    pub(crate) unsafe fn map_kernel_mmio(
        &self,
        start: Page<Size4KiB>,
        frames: PhysFrameRange<Size4KiB>,
    ) -> Result<(), MapToError<Size4KiB>> {
        let mut allocator = PageTableAllocator::<M>::new();
        let table_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::ACCESSED
            | PageTableFlags::DIRTY;
        // PCD and PWT select UC with the reset PAT.
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH;
        let mut inner = self.inner.lock();
        for (page, frame) in Page::range(start, start + frames.count() as u64).zip(frames) {
            // Safety: device registers (the caller's contract), mapped only here.
            unsafe {
                inner.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator)
            }?
            // A newly present entry needs no flush.
            .ignore();
        }
        Ok(())
    }

    /// `None` if the frame allocation fails.
    pub(crate) fn new_top_level() -> Option<Self> {
        let frame = PageTableAllocator::<M>::allocate_frame()?;
        // Safety: a fresh zeroed frame is a valid, empty top-level table, owned
        // by the returned object.
        Some(unsafe { Self::init(frame.start_address()) })
    }

    /// Share `source`'s kernel P3/P2/P1 tables (see [`KERNEL_PML4_START`]).
    /// Entries already present in `self` are kept.
    pub(crate) fn copy_pml4_entries_from(&self, source: &Self) {
        let mut dst = self.inner.lock();
        let src = source.inner.lock();
        for (dst_entry, src_entry) in dst
            .level_4_table_mut()
            .iter_mut()
            .zip(src.level_4_table().iter())
            .skip(KERNEL_PML4_START)
        {
            if !src_entry.is_unused() && dst_entry.is_unused() {
                dst_entry.set_addr(src_entry.addr(), src_entry.flags());
            }
        }
    }

    /// Load this table into CR3, keeping the CR3 flags, and return the previous
    /// P4 frame. For a task table, see `PageTableManager::load_task`, which
    /// keeps [`Self::cpus`].
    ///
    /// # Safety
    ///
    /// The table must map the whole kernel (code, data, and stacks), as the base
    /// table and the tables sharing its kernel entries do.
    pub(crate) unsafe fn load(&self) -> PhysFrame {
        let (frame, flags) = x86_64::registers::control::Cr3::read();
        // Safety: the caller guarantees the table maps the kernel, so the
        // running code stays mapped.
        unsafe {
            x86_64::registers::control::Cr3::write(self.p4, flags);
        }

        frame
    }

    pub(crate) fn physical_frame(&self) -> PhysFrame {
        self.p4
    }

    /// The CPUs that may cache the table: see [`tlb::Cpus`].
    pub(crate) fn cpus(&self) -> &tlb::Cpus {
        &self.cpus
    }
}

impl<M: MemoryProvider, const ALIGN: usize> Drop for X64PageTable<'_, M, ALIGN> {
    /// Requires a prior non-PCID CR3 reload.
    fn drop(&mut self) {
        debug_assert!(self.cpus.is_empty(), "a page table dropped in use");
        let mut allocator = PageTableAllocator::<M>::new();
        let mut inner = self.inner.lock();
        for_each_user_leaf::<M>(inner.level_4_table_mut(), |page, entry| {
            let flags = entry.flags();
            let addr: usize = page.start_address().as_u64().trunc();
            if (crate::USER_ADDR_MIN..crate::USER_ADDR_MAX).contains(&addr)
                && flags.intersects(PageTableFlags::PRESENT | PROT_NONE)
            {
                let frame = PhysFrame::containing_address(entry.addr());
                // Safety: the table is being dropped, so nothing reaches the
                // frame through this leaf anymore.
                unsafe { release_user_frame::<M>(frame, flags) };
            } else if !entry.is_unused() {
                litebox_util_log::error!("BUG: leaking malformed task leaf during destruction");
                debug_assert!(false, "malformed task leaf during destruction");
            }
            entry.set_unused();
        });
        let start = Page::<Size4KiB>::containing_address(VirtAddr::new(0));
        let end = Page::<Size4KiB>::containing_address(VirtAddr::new(crate::KERNEL_OFFSET - 1));
        debug_assert_eq!(usize::from(end.p4_index()), KERNEL_PML4_START - 1);

        // Safety: the range covers only the private slots, whose tables only
        // this table uses.
        unsafe {
            inner.clean_up_addr_range(Page::range_inclusive(start, end), &mut allocator);
        }
        debug_assert!(
            inner
                .level_4_table()
                .iter()
                .take(KERNEL_PML4_START)
                .all(PageTableEntry::is_unused),
            "task page table dropped with live private mappings"
        );
        drop(inner);

        // Safety: owned P4 frame.
        unsafe { allocator.deallocate_frame(self.p4) };
    }
}

impl<M: MemoryProvider, const ALIGN: usize> PageTableImpl<ALIGN> for X64PageTable<'_, M, ALIGN> {
    unsafe fn init(p4: PhysAddr) -> Self {
        assert!(p4.is_aligned(Size4KiB::SIZE));
        let frame = PhysFrame::from_start_address(p4).unwrap();
        let mapping = FrameMapping::<M> {
            _provider: core::marker::PhantomData,
        };
        let p4_va = mapping.frame_to_pointer(frame);
        // Safety: the caller passes a valid top-level table that outlives `Self`,
        // which owns all access to it.
        let p4 = unsafe { &mut *p4_va };
        X64PageTable {
            // Safety: `mapping` translates every frame of this table (see
            // `FrameMapping`).
            inner: unsafe { MappedPageTable::new(p4, mapping) }.into(),
            p4: frame,
            cpus: tlb::Cpus::default(),
            pinned: spin::Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        self.inner.lock().translate(addr)
    }

    unsafe fn handle_page_fault(
        &self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
        let mut inner = self.inner.lock();
        match inner.translate(page.start_address()) {
            TranslateResult::Mapped {
                frame,
                offset: _,
                flags: current,
            } => {
                if current.contains(PROT_NONE) {
                    return Err(PageFaultError::AccessError("PROT_NONE"));
                }
                if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
                    if current.contains(PageTableFlags::WRITABLE) {
                        return Ok(());
                    }
                    // The caller checked that `flags` allow the write.
                    if !current.contains(COW) || !flags.contains(PageTableFlags::WRITABLE) {
                        litebox_util_log::error!(addr:? = page.start_address(); "BUG: write fault on a read-only page");
                        return Err(PageFaultError::AccessError("write to a read-only page"));
                    }
                    let MappedFrame::Size4KiB(frame) = frame else {
                        return Err(PageFaultError::HugePage);
                    };
                    let entry = leaf_entry::<M>(inner.level_4_table_mut(), page)
                        .expect("a mapped page has a leaf");
                    if shared_frames().contains(frame) {
                        let copy = PageTableAllocator::<M>::allocate_frame()
                            .ok_or(PageFaultError::AllocationFailed)?;
                        // Safety: both frames are whole pages in the kernel
                        // mapping, and the copy is fresh. No leaf maps the
                        // shared frame writable.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                frame_to_pointer::<M>(frame).cast::<u8>(),
                                frame_to_pointer::<M>(copy).cast::<u8>(),
                                Size4KiB::SIZE.trunc(),
                            );
                        }
                        // The copy before the leaf that publishes it (see
                        // `PageTableAllocator::allocate_frame`).
                        compiler_fence(Ordering::Release);
                        entry.set_frame(copy, flags);
                        drop(inner);
                        // Other CPUs may still read the shared frame through
                        // the leaf, which the release may free.
                        let mut stale = Stale::default();
                        stale.add(page);
                        self.flush(stale);
                        // Safety: the leaf maps the copy now, and its stale
                        // translations are flushed.
                        unsafe { release_user_frame::<M>(frame, current) };
                    } else {
                        // No other leaf maps the frame anymore. Only gaining
                        // `WRITABLE`: no flush (see `needs_flush`).
                        entry.set_flags(flags);
                    }
                    return Ok(());
                }

                if !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
                    return Ok(());
                }

                #[cfg(debug_assertions)]
                todo!("Page fault on present page: {:#x}", page.start_address());
                #[cfg(not(debug_assertions))]
                {
                    litebox_util_log::error!(addr:? = page.start_address(); "page fault on a present page");
                    return Err(PageFaultError::AccessError("Page fault on present page"));
                }
            }
            TranslateResult::NotMapped => {
                // TODO: if it is file-backed, we need to read the page from file
                // Safety: the caller checked that the access is allowed.
                unsafe { map_fresh_frame(&mut inner, page, flags) }?;
            }
            TranslateResult::InvalidFrameAddress(pa) => {
                #[cfg(debug_assertions)]
                todo!("Invalid frame address: {:#x}", pa);
                #[cfg(not(debug_assertions))]
                {
                    litebox_util_log::error!(pa:? = pa; "invalid frame address");
                    return Err(PageFaultError::AccessError("Invalid frame address"));
                }
            }
        }
        Ok(())
    }
}

impl<M: MemoryProvider, const ALIGN: usize> VmemPageFaultHandler for X64PageTable<'_, M, ALIGN> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(fault_addr as u64));
        let error_code = PageFaultErrorCode::from_bits_truncate(error_code);
        let flags = vmflags_to_pteflags(flags);
        // Safety: called from the page fault handler (per the caller), after
        // the VMA check.
        unsafe { PageTableImpl::handle_page_fault(self, page, flags, error_code) }
    }

    fn access_error(error_code: u64, flags: VmFlags) -> bool {
        let error_code = PageFaultErrorCode::from_bits_truncate(error_code);
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            return !flags.contains(VmFlags::VM_WRITE);
        }

        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            return true;
        }

        if (flags & VmFlags::VM_ACCESS_FLAGS).is_empty() {
            return true;
        }

        false
    }
}
