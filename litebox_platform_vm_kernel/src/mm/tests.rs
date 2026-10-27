// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-table tests. [`HostMemory`] backs frames with host allocations
//! (PA == VA), tracks live blocks to catch wrong and double frees, and
//! records the TLB flushes it is asked for. [`TestHeap`] is the kernel
//! heap's stand-in, which a test can exhaust.

extern crate std;

use core::cell::RefCell;
use litebox::mm::page::PageRange;
use litebox_common_linux::{
    PAGE_SIZE,
    vmem::{PageFaultError, VmFlags},
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::vec::Vec;
use x86_64::structures::idt::PageFaultErrorCode;
use x86_64::structures::paging::{
    Page, PageTableFlags, PhysFrame, Size4KiB,
    mapper::{MappedFrame, TranslateResult},
    page::PageRange as Pages,
};
use x86_64::{PhysAddr, VirtAddr};

use super::{
    MemoryProvider,
    pgtable::{COW, PageTableImpl, SHARED},
};
use crate::arch::mm::paging::{UnmapOptions, X64PageTable, shared_frames, vmflags_to_pteflags};
use crate::boot::TrampolineTable;

#[derive(Default)]
struct HostState {
    /// Live blocks: start address -> order.
    live_blocks: HashMap<usize, u32>,
    /// Allocations left before `mem_allocate_pages` fails (`None`: no limit).
    alloc_budget: Option<usize>,
    /// The thread's heap allocations left before they fail (see
    /// [`TestHeap`]; `None`: no limit).
    heap_budget: Option<usize>,
    /// The flushes asked for since [`take_flushes`]: the table's P4 frame,
    /// the pages, and how many frames were live then (see [`live_frames`]):
    /// the change must not have freed its old frames yet.
    flushes: Vec<(PhysFrame, Pages, usize)>,
    /// See [`at_next_flush`].
    at_flush: Option<std::boxed::Box<dyn FnOnce()>>,
}

std::thread_local! {
    static HOST: RefCell<HostState> = RefCell::new(HostState::default());
}

fn live_frames() -> usize {
    HOST.with(|host| {
        host.borrow()
            .live_blocks
            .values()
            .map(|order| 1usize << order)
            .sum()
    })
}

fn set_alloc_budget(budget: Option<usize>) {
    HOST.with(|host| host.borrow_mut().alloc_budget = budget);
}

/// Makes the thread's heap allocations (see [`TestHeap`]) fail after
/// `budget` more, or not (`None`); frames ([`HostMemory`]) still come.
pub(crate) fn set_heap_budget(budget: Option<usize>) {
    HOST.with(|host| host.borrow_mut().heap_budget = budget);
}

/// The heap: the system's, but failing the allocations of a thread past its
/// [`set_heap_budget`], as an exhausted kernel heap would. [`HostMemory`]'s
/// frames come from the system directly.
struct TestHeap;

// Safety: the system's allocations, or none.
unsafe impl GlobalAlloc for TestHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Not for `HOST`'s own records, as they change (borrowed), nor once
        // it is gone.
        let exhausted = HOST
            .try_with(|host| {
                host.try_borrow_mut()
                    .is_ok_and(|mut host| match &mut host.heap_budget {
                        Some(0) => true,
                        Some(budget) => {
                            *budget -= 1;
                            false
                        }
                        None => false,
                    })
            })
            .unwrap_or(false);
        if exhausted {
            return core::ptr::null_mut();
        }
        // Safety: forwarded to the caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Safety: forwarded to the caller; `alloc` allocates with `System`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static HEAP: TestHeap = TestHeap;

fn frame_layout(order: u32) -> Layout {
    Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE).unwrap()
}

struct HostMemory;

impl MemoryProvider for HostMemory {
    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        let exhausted = HOST.with(|host| match &mut host.borrow_mut().alloc_budget {
            Some(0) => true,
            Some(budget) => {
                *budget -= 1;
                false
            }
            None => false,
        });
        if exhausted {
            return None;
        }
        // Safety: the layout has a non-zero size.
        let ptr = unsafe { System.alloc(frame_layout(order)) };
        if ptr.is_null() {
            return None;
        }
        let previous = HOST.with(|host| host.borrow_mut().live_blocks.insert(ptr as usize, order));
        assert!(previous.is_none(), "host allocator returned a live block");
        Some(ptr)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        // Deallocation must use the original block size.
        let allocated = HOST.with(|host| host.borrow_mut().live_blocks.remove(&(ptr as usize)));
        match allocated {
            Some(allocated) => assert_eq!(
                allocated, order,
                "block {ptr:p} allocated at order {allocated} freed at order {order}"
            ),
            None => panic!("double free or foreign free of {ptr:p}"),
        }
        // Safety: `ptr` came from `mem_allocate_pages(order)`.
        unsafe { System.dealloc(ptr, frame_layout(order)) };
    }

    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new(va.as_u64())
    }

    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new(pa.as_u64())
    }

    fn flush_tlb(_cpus: &crate::tlb::Cpus, root: PhysFrame, pages: Pages) {
        if let Some(change) = HOST.with(|host| host.borrow_mut().at_flush.take()) {
            change();
        }
        let live = live_frames();
        HOST.with(|host| host.borrow_mut().flushes.push((root, pages, live)));
    }
}

/// Makes `change` at the next TLB flush, before it is recorded, as another
/// CPU may as the flush waits.
fn at_next_flush(change: impl FnOnce() + 'static) {
    HOST.with(|host| host.borrow_mut().at_flush = Some(std::boxed::Box::new(change)));
}

/// The TLB flushes asked for since the last call, in order (see
/// [`HostState::flushes`]).
fn take_flushes() -> Vec<(PhysFrame, Pages, usize)> {
    HOST.with(|host| core::mem::take(&mut host.borrow_mut().flushes))
}

/// `pages` pages from `start`, as flushed.
fn span(start: usize, pages: u64) -> Pages {
    let start = Page::containing_address(VirtAddr::new(start as u64));
    Page::range(start, start + pages)
}

type TestPageTable = X64PageTable<'static, HostMemory, PAGE_SIZE>;

fn new_table() -> TestPageTable {
    TestPageTable::new_top_level().unwrap()
}

fn range(start: usize, pages: usize) -> PageRange<PAGE_SIZE> {
    PageRange::new(start, start + pages * PAGE_SIZE).unwrap()
}

fn check_mapped(pgtable: &TestPageTable, addr: usize, flags: PageTableFlags) {
    match pgtable.translate(VirtAddr::new(addr as u64)) {
        TranslateResult::Mapped {
            frame,
            offset,
            flags: f,
        } => {
            assert!(matches!(frame, MappedFrame::Size4KiB(_)));
            assert_eq!(offset, 0);
            assert_eq!(flags, f, "flags at {addr:#x}");
        }
        other => panic!("{addr:#x}: unexpected {other:?}"),
    }
}

fn check_unmapped(pgtable: &TestPageTable, addr: usize) {
    assert!(
        matches!(
            pgtable.translate(VirtAddr::new(addr as u64)),
            TranslateResult::NotMapped
        ),
        "{addr:#x} is still mapped"
    );
}

#[test]
fn fault_mprotect_unmap() {
    let pgtable = new_table();
    let writable = VmFlags::VM_READ | VmFlags::VM_WRITE;
    let writable_pte = vmflags_to_pteflags(writable) | PageTableFlags::PRESENT;
    let start = 0x1_0000;
    // Safety: host test; the table is never loaded.
    unsafe { pgtable.map_pages(range(start, 4), writable, true) }.unwrap();
    for page in range(start, 4) {
        check_mapped(&pgtable, page, writable_pte);
    }

    let read_only = VmFlags::VM_READ;
    let read_only_pte = vmflags_to_pteflags(read_only) | PageTableFlags::PRESENT;
    // Safety: host test; nothing uses the mapped memory.
    unsafe { pgtable.mprotect_pages(range(start + 2 * PAGE_SIZE, 2), read_only) }.unwrap();
    for page in range(start, 2) {
        check_mapped(&pgtable, page, writable_pte);
    }
    for page in range(start + 2 * PAGE_SIZE, 2) {
        check_mapped(&pgtable, page, read_only_pte);
    }

    let before = live_frames();
    for r in [range(start, 2), range(start + 2 * PAGE_SIZE, 2)] {
        // Safety: as above.
        unsafe { pgtable.unmap_pages(r, UnmapOptions::RELEASE) }.unwrap();
        for page in r {
            check_unmapped(&pgtable, page);
        }
    }
    assert_eq!(live_frames(), before - 4);
}

#[test]
fn unmap_without_dealloc_keeps_frames() {
    let pgtable = new_table();
    let start = 0x1_0000;
    // Safety: host test; the table is never loaded.
    unsafe { pgtable.map_pages(range(start, 2), VmFlags::VM_READ | VmFlags::VM_WRITE, true) }
        .unwrap();
    let before = live_frames();
    // Safety: host test; nothing uses the mapped memory.
    unsafe { pgtable.unmap_pages(range(start + PAGE_SIZE, 1), UnmapOptions::KEEP_FRAMES) }.unwrap();
    check_unmapped(&pgtable, start + PAGE_SIZE);
    assert_eq!(live_frames(), before);
}

#[test]
fn populate_failure_unmaps_populated_pages() {
    let pgtable = new_table();
    let flags = VmFlags::VM_READ | VmFlags::VM_WRITE;
    let start = 0x1_0000;
    // Preallocate intermediate tables so the failure budget covers only leaves.
    // Safety: host test; the table is never loaded.
    unsafe { pgtable.map_pages(range(start, 1), flags, true) }.unwrap();
    let rest = range(start + PAGE_SIZE, 4);
    let before = live_frames();
    take_flushes();

    set_alloc_budget(Some(2));
    // Safety: as above; nothing is mapped in `rest`.
    let result = unsafe { pgtable.map_pages(rest, flags, true) };
    set_alloc_budget(None);

    assert!(matches!(
        result,
        Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory)
    ));
    for page in rest {
        check_unmapped(&pgtable, page);
    }
    assert_eq!(live_frames(), before);
    // Others may have used the two populated meanwhile: flushed, then freed.
    assert_eq!(
        take_flushes(),
        [(pgtable.physical_frame(), span(rest.start(), 2), before + 2)]
    );
}

#[test]
fn populate_failure_on_first_page() {
    // Fail the leaf allocation, then each of the three intermediate-table allocations.
    for budget in 0..=3 {
        let before = live_frames();
        let pgtable = new_table();
        let pages = range(0x1_0000, 2);
        let flags = VmFlags::VM_READ | VmFlags::VM_WRITE;

        set_alloc_budget(Some(budget));
        // Safety: unused user range in a table that is never loaded.
        let result = unsafe { pgtable.map_pages(pages, flags, true) };
        set_alloc_budget(None);

        assert!(
            matches!(
                result,
                Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory)
            ),
            "allocation budget: {budget}"
        );
        for page in pages {
            check_unmapped(&pgtable, page);
        }

        // Safety: the failed call left no leaf mappings in `pages`.
        unsafe { pgtable.map_pages(pages, flags, true) }.unwrap();
        for page in pages {
            check_mapped(
                &pgtable,
                page,
                vmflags_to_pteflags(flags) | PageTableFlags::PRESENT,
            );
        }
        drop(pgtable);
        assert_eq!(live_frames(), before);
    }
}

fn mapped_frame(pgtable: &TestPageTable, addr: usize) -> PhysFrame<Size4KiB> {
    match pgtable.translate(VirtAddr::new(addr as u64)) {
        TranslateResult::Mapped {
            frame: MappedFrame::Size4KiB(frame),
            ..
        } => frame,
        other => panic!("expected an owned 4 KiB frame: {other:?}"),
    }
}

#[test]
fn prot_none_preserves_contents_and_can_be_unmapped() {
    let before = live_frames();
    let pgtable = new_table();
    let page = range(0x1_0000, 1);
    let writable = VmFlags::VM_READ | VmFlags::VM_WRITE;
    // Safety: unused user range in a table that is never loaded.
    unsafe { pgtable.map_pages(page, writable, true) }.unwrap();
    let frame = mapped_frame(&pgtable, page.start());
    let ptr = frame.start_address().as_u64() as *mut u64;
    // Safety: HostMemory uses PA == VA; the live frame is exclusively owned.
    unsafe { ptr.write(0x1234_5678_9abc_def0) };
    let allocated = live_frames();

    for flags in [
        VmFlags::empty(),
        VmFlags::VM_READ,
        writable,
        VmFlags::empty(),
    ] {
        // Safety: the table is not loaded and there are no references to its mappings.
        unsafe { pgtable.mprotect_pages(page, flags) }.unwrap();
        check_mapped(&pgtable, page.start(), vmflags_to_pteflags(flags));
        assert_eq!(mapped_frame(&pgtable, page.start()), frame);
        assert_eq!(live_frames(), allocated);
        // Safety: protection changes do not affect HostMemory's backing allocation.
        assert_eq!(unsafe { ptr.read() }, 0x1234_5678_9abc_def0);
    }
    assert!(!vmflags_to_pteflags(VmFlags::empty()).contains(PageTableFlags::PRESENT));
    // Safety: the table is never loaded and no access to the frame remains.
    unsafe { pgtable.unmap_pages(page, UnmapOptions::RELEASE) }.unwrap();
    check_unmapped(&pgtable, page.start());
    assert_eq!(live_frames(), allocated - 1);
    drop(pgtable);
    assert_eq!(live_frames(), before);
}

#[test]
fn populated_prot_none_keeps_and_drops_frames() {
    let before = live_frames();
    let pgtable = new_table();
    let pages = range(0x1_0000, 2);
    // Safety: unused user range in a table that is never loaded.
    unsafe { pgtable.map_pages(pages, VmFlags::empty(), true) }.unwrap();
    for page in pages {
        check_mapped(&pgtable, page, vmflags_to_pteflags(VmFlags::empty()));
    }
    let frame = mapped_frame(&pgtable, pages.start());
    let allocated = live_frames();
    // Safety: no access to these mappings; the retained frame is freed below.
    unsafe { pgtable.unmap_pages(range(pages.start(), 1), UnmapOptions::KEEP_FRAMES) }.unwrap();
    check_unmapped(&pgtable, pages.start());
    assert_eq!(live_frames(), allocated);
    drop(pgtable);
    assert_eq!(live_frames(), before + 1);
    // Safety: the retained frame was allocated by HostMemory at order 0.
    unsafe { HostMemory::mem_free_pages(frame.start_address().as_u64() as *mut u8, 0) };
    assert_eq!(live_frames(), before);
}

#[test]
fn kernel_image_permissions() {
    let before = live_frames();
    let pgtable = new_table();
    let frames = [(); 3].map(|()| {
        let ptr = HostMemory::mem_allocate_pages(0).unwrap();
        PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(ptr as u64))
    });
    let text = frames[0].start_address()..(frames[0] + 1).start_address();
    let read_only = frames[1].start_address()..(frames[1] + 1).start_address();
    let expected = [
        PageTableFlags::PRESENT,
        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE,
        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | PageTableFlags::WRITABLE,
    ];
    for (frame, flags) in frames.into_iter().zip(expected) {
        pgtable
            .map_kernel(PhysFrame::range(frame, frame + 1), 0, &text, &read_only)
            .unwrap();
        check_mapped(
            &pgtable,
            usize::try_from(frame.start_address().as_u64()).unwrap(),
            flags,
        );
    }
    // HostMemory's identity mapping places these owned frames in private slots.
    drop(pgtable);
    assert_eq!(live_frames(), before);
}

#[test]
fn stack_guards_are_mapped_again_as_they_were() {
    let before = live_frames();
    let pgtable = new_table();
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
        HostMemory::mem_allocate_pages(0).unwrap() as u64,
    ));
    let none = PhysAddr::zero()..PhysAddr::zero();
    // As the kernel maps RAM, here at `PA + 0`.
    pgtable
        .map_kernel(PhysFrame::range(frame, frame + 1), 0, &none, &none)
        .unwrap();
    let guard = usize::try_from(frame.start_address().as_u64()).unwrap();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    check_mapped(&pgtable, guard, flags);
    let frames = live_frames();
    take_flushes();
    // Safety: host test; nothing uses the page, and the table is never loaded.
    unsafe { crate::per_cpu::unmap_guard(&pgtable, guard) };
    check_unmapped(&pgtable, guard);
    assert_eq!(
        take_flushes(),
        [(pgtable.physical_frame(), span(guard, 1), frames)]
    );
    // Safety: as above; unmapped just now.
    unsafe { crate::per_cpu::restore_guard(&pgtable, guard) };
    check_mapped(&pgtable, guard, flags);
    assert_eq!(mapped_frame(&pgtable, guard), frame);
    // The leaf was absent: nothing to flush. No table allocated, no frame
    // freed.
    assert_eq!(take_flushes(), []);
    assert_eq!(live_frames(), frames);
    drop(pgtable);
    assert_eq!(live_frames(), before);
}

#[test]
fn task_tables_share_only_kernel_slots() {
    let base = new_table();
    let kernel_va = usize::try_from(crate::KERNEL_OFFSET).unwrap() + 0x20_0000;
    let kernel_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    // Safety: host test; maps a fresh frame at `kernel_va` in the base table.
    unsafe {
        base.handle_page_fault(
            Page::containing_address(VirtAddr::new(kernel_va as u64)),
            kernel_flags,
            PageFaultErrorCode::empty(),
        )
    }
    .unwrap();

    let before_task = live_frames();
    let task = new_table();
    task.copy_pml4_entries_from(&base);
    check_mapped(&task, kernel_va, kernel_flags);

    let user = range(0x1_0000, 2);
    // Safety: host test; the table is never loaded.
    unsafe { task.map_pages(user, VmFlags::VM_READ | VmFlags::VM_WRITE, true) }.unwrap();
    for page in user {
        check_unmapped(&base, page);
    }

    drop(task);
    assert_eq!(live_frames(), before_task);
    check_mapped(&base, kernel_va, kernel_flags);
}

#[test]
fn only_writable_pages_are_pinned() {
    let pgtable = new_table();
    let start = 0x1000_0000;
    let rw = VmFlags::VM_READ | VmFlags::VM_WRITE;
    // Safety: a fresh table; the range is unmapped user space.
    unsafe { pgtable.map_pages(range(start, 3), rw, true) }.unwrap();
    // Safety: nothing uses the page.
    unsafe { pgtable.mprotect_pages(range(start + PAGE_SIZE, 1), VmFlags::VM_READ) }.unwrap();
    // Safety: as above.
    unsafe { pgtable.mprotect_pages(range(start + 2 * PAGE_SIZE, 1), VmFlags::empty()) }.unwrap();
    assert_eq!(
        pgtable.pin(range(start, 1)).as_deref(),
        Some(&[mapped_frame(&pgtable, start)][..])
    );
    pgtable.unpin(range(start, 1));
    for page in 1..4 {
        assert!(pgtable.pin(range(start + page * PAGE_SIZE, 1)).is_none());
    }
    assert!(pgtable.pin(range(start, 2)).is_none());
}

const RW: VmFlags = VmFlags::VM_READ.union(VmFlags::VM_WRITE);

fn read(frame: PhysFrame<Size4KiB>) -> u64 {
    // Safety: HostMemory uses PA == VA, and the frame is live.
    unsafe { (frame.start_address().as_u64() as *const u64).read() }
}

fn write(frame: PhysFrame<Size4KiB>, value: u64) {
    // Safety: as for `read`; tests write only frames they own.
    unsafe { (frame.start_address().as_u64() as *mut u64).write(value) };
}

/// A write fault at `addr` of a page whose mapping allows `flags`.
fn write_fault(pgtable: &TestPageTable, addr: usize, flags: VmFlags) {
    let page = Page::containing_address(VirtAddr::new(addr as u64));
    // Safety: the mapping allows the write.
    unsafe {
        PageTableImpl::handle_page_fault(
            pgtable,
            page,
            vmflags_to_pteflags(flags),
            PageFaultErrorCode::CAUSED_BY_WRITE | PageFaultErrorCode::PROTECTION_VIOLATION,
        )
    }
    .unwrap();
}

/// `pages` pages at `start`, populated `RW`, each holding its index.
fn populated_table(start: usize, pages: usize) -> TestPageTable {
    let pgtable = new_table();
    // Safety: a fresh table; the range is unmapped user space.
    unsafe { pgtable.map_pages(range(start, pages), RW, true) }.unwrap();
    for index in 0..pages {
        write(
            mapped_frame(&pgtable, start + index * PAGE_SIZE),
            index as u64,
        );
    }
    pgtable
}

fn clone(pgtable: &TestPageTable) -> TestPageTable {
    let clone = new_table();
    pgtable.clone_user_mappings(&clone).unwrap();
    clone
}

/// Taken by the tests that share frames, as [`shared_frames`] is global,
/// unlike [`HOST`]: each leaves no frame shared, and so no block of counts.
static SHARING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// [`SHARING`], locked, even after a test failed holding it.
fn sharing() -> std::sync::MutexGuard<'static, ()> {
    SHARING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn clones_share_frames_until_written() {
    let _sharing = sharing();
    let before = live_frames();
    let start = 0x1_0000;
    let parent = populated_table(start, 2);
    let child = clone(&parent);
    let shared = mapped_frame(&parent, start);
    let cow_pte = (vmflags_to_pteflags(RW) | COW) - PageTableFlags::WRITABLE;
    for pgtable in [&parent, &child] {
        check_mapped(pgtable, start, cow_pte);
        assert_eq!(mapped_frame(pgtable, start), shared);
    }

    // The child's write copies the frame; the parent keeps it.
    let allocated = live_frames();
    write_fault(&child, start, RW);
    check_mapped(&child, start, vmflags_to_pteflags(RW));
    let copy = mapped_frame(&child, start);
    assert_ne!(copy, shared);
    assert_eq!(read(copy), 0);
    write(copy, 7);
    assert_eq!(read(shared), 0);
    assert_eq!(live_frames(), allocated + 1);

    // No other leaf maps the parent's frame now, so its write takes it over.
    write_fault(&parent, start, RW);
    check_mapped(&parent, start, vmflags_to_pteflags(RW));
    assert_eq!(mapped_frame(&parent, start), shared);
    assert_eq!(live_frames(), allocated + 1);

    drop(parent);
    assert_eq!(read(mapped_frame(&child, start + PAGE_SIZE)), 1);
    drop(child);
    assert_eq!(live_frames(), before);
    assert!(shared_frames().is_empty());
}

#[test]
fn shared_frames_outlive_all_but_their_last_leaf() {
    // A table mapping one page has a P4, P3, P2, and P1.
    const TABLE_FRAMES: usize = 4;
    let _sharing = sharing();
    let before = live_frames();
    let start = 0x1_0000;
    let parent = populated_table(start, 1);
    let shared = mapped_frame(&parent, start);
    let child = clone(&parent);
    let grandchild = clone(&child);
    let allocated = live_frames();

    // Safety: nothing uses the page.
    unsafe { parent.unmap_pages(range(start, 1), UnmapOptions::RELEASE) }.unwrap();
    assert_eq!(live_frames(), allocated);
    drop(child);
    assert_eq!(live_frames(), allocated - TABLE_FRAMES);
    assert_eq!(read(shared), 0);
    assert!(shared_frames().is_empty());

    // The last leaf takes the frame over, and frees it.
    write_fault(&grandchild, start, RW);
    assert_eq!(mapped_frame(&grandchild, start), shared);
    drop(grandchild);
    assert_eq!(live_frames(), allocated - 2 * TABLE_FRAMES - 1);
    drop(parent);
    assert_eq!(live_frames(), before);
}

#[test]
fn clones_share_shared_memory_writable_and_free_it_with_its_last_leaf() {
    let _sharing = sharing();
    let before = live_frames();
    let start = 0x1_0000;
    let shared_rw = RW | VmFlags::VM_SHARED;
    let parent = new_table();
    // Safety: a fresh table; the range is unmapped user space.
    unsafe { parent.map_pages(range(start, 1), shared_rw, true) }.unwrap();
    let frame = mapped_frame(&parent, start);
    let child = clone(&parent);
    let grandchild = clone(&child);
    let pte = vmflags_to_pteflags(shared_rw);
    assert!(pte.contains(SHARED | PageTableFlags::WRITABLE));
    for pgtable in [&parent, &child, &grandchild] {
        check_mapped(pgtable, start, pte);
        assert_eq!(mapped_frame(pgtable, start), frame);
    }
    // Every process writes the one frame, without faulting.
    write(frame, 7);
    assert_eq!(read(mapped_frame(&grandchild, start)), 7);

    // Protection changes keep the leaf shared.
    // Safety: nothing uses the page.
    unsafe { child.mprotect_pages(range(start, 1), VmFlags::VM_READ | VmFlags::VM_SHARED) }
        .unwrap();
    check_mapped(
        &child,
        start,
        vmflags_to_pteflags(VmFlags::VM_READ | VmFlags::VM_SHARED),
    );
    assert_eq!(mapped_frame(&child, start), frame);

    // The frame outlives every leaf but its last.
    // Safety: nothing uses the page.
    unsafe { parent.unmap_pages(range(start, 1), UnmapOptions::RELEASE) }.unwrap();
    drop(child);
    assert_eq!(read(mapped_frame(&grandchild, start)), 7);
    assert!(shared_frames().is_empty());
    drop(grandchild);
    drop(parent);
    assert_eq!(live_frames(), before);
}

#[test]
fn cow_leaves_stay_read_only_across_mprotect() {
    let _sharing = sharing();
    let start = 0x1_0000;
    let parent = populated_table(start, 1);
    let child = clone(&parent);
    let cow_pte = (vmflags_to_pteflags(RW) | COW) - PageTableFlags::WRITABLE;
    for flags in [VmFlags::empty(), VmFlags::VM_READ, RW] {
        // Safety: nothing uses the page.
        unsafe { child.mprotect_pages(range(start, 1), flags) }.unwrap();
        check_mapped(
            &child,
            start,
            (vmflags_to_pteflags(flags) | COW) - PageTableFlags::WRITABLE,
        );
    }
    check_mapped(&child, start, cow_pte);
    write_fault(&child, start, RW);
    check_mapped(&child, start, vmflags_to_pteflags(RW));
    assert_eq!(read(mapped_frame(&child, start)), 0);
    assert!(shared_frames().is_empty());
}

#[test]
fn pinned_pages_are_not_cloned() {
    let _sharing = sharing();
    let before = live_frames();
    let start = 0x1_0000;
    let parent = populated_table(start, 2);
    let pinned = parent.pin(range(start, 1)).unwrap();
    let child = clone(&parent);
    check_unmapped(&child, start);
    check_mapped(&parent, start, vmflags_to_pteflags(RW));
    assert_eq!(mapped_frame(&parent, start), pinned[0]);
    assert_eq!(
        mapped_frame(&child, start + PAGE_SIZE),
        mapped_frame(&parent, start + PAGE_SIZE)
    );

    // Once unpinned, the page is shared.
    parent.unpin(range(start, 1));
    let grandchild = clone(&parent);
    assert_eq!(mapped_frame(&grandchild, start), pinned[0]);
    drop((parent, child, grandchild));
    assert_eq!(live_frames(), before);
    assert!(shared_frames().is_empty());
}

#[test]
fn clone_failure_leaves_both_tables_consistent() {
    let _sharing = sharing();
    let start = 0x1_0000;
    // Leaves in two P1 tables, so the clone needs a second one partway.
    let far = start + 512 * PAGE_SIZE;
    let parent = populated_table(start, 1);
    // Safety: unmapped user space.
    unsafe { parent.map_pages(range(far, 1), RW, true) }.unwrap();
    write(mapped_frame(&parent, far), 9);
    let before = live_frames();
    let child = new_table();
    // The child's P3, P2, and first P1, but not its second P1.
    set_alloc_budget(Some(3));
    let result = parent.clone_user_mappings(&child);
    set_alloc_budget(None);
    assert!(matches!(
        result,
        Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory)
    ));
    assert_eq!(mapped_frame(&child, start), mapped_frame(&parent, start));
    check_unmapped(&child, far);
    drop(child);
    assert_eq!(live_frames(), before);
    assert!(shared_frames().is_empty());
    // The parent's leaves still work, and copy nothing.
    write_fault(&parent, start, RW);
    write_fault(&parent, far, RW);
    assert_eq!(read(mapped_frame(&parent, far)), 9);
    assert_eq!(live_frames(), before);
}

#[test]
fn clone_failure_for_the_heap_shares_only_counted_frames() {
    // The heap has two allocations left: a block of counts and room for it in
    // the map, or two blocks, but these frames span at least four blocks. So
    // the clone shares some, then fails.
    const PAGES: usize = 4096;
    let _sharing = sharing();
    let start = 0x1_0000;
    let address = |page: usize| start + page * PAGE_SIZE;
    let parent = populated_table(start, PAGES);
    let before = live_frames();
    let child = new_table();
    set_heap_budget(Some(2));
    let result = parent.clone_user_mappings(&child);
    set_heap_budget(None);
    assert!(matches!(
        result,
        Err(litebox::platform::page_mgmt::AllocationError::OutOfMemory)
    ));
    // The child shares the first pages, each counted; the parent keeps the
    // others to itself, as they were.
    let shared = (0..PAGES)
        .take_while(|&page| {
            !matches!(
                child.translate(VirtAddr::new(address(page) as u64)),
                TranslateResult::NotMapped
            )
        })
        .count();
    assert!(shared > 0, "the clone shared nothing");
    let cow_pte = (vmflags_to_pteflags(RW) | COW) - PageTableFlags::WRITABLE;
    for page in 0..PAGES {
        if page < shared {
            check_mapped(&child, address(page), cow_pte);
            check_mapped(&parent, address(page), cow_pte);
            assert_eq!(
                mapped_frame(&child, address(page)),
                mapped_frame(&parent, address(page))
            );
        } else {
            check_unmapped(&child, address(page));
            check_mapped(&parent, address(page), vmflags_to_pteflags(RW));
        }
    }
    drop(child);
    assert_eq!(live_frames(), before);
    assert!(shared_frames().is_empty());
    // The parent's shared leaves take their frames back, copying nothing.
    for page in 0..shared {
        write_fault(&parent, address(page), RW);
        assert_eq!(read(mapped_frame(&parent, address(page))), page as u64);
    }
    assert_eq!(live_frames(), before);
}

/// The CPU trampoline's page is not its table's: dropping the table frees
/// the table's frames, but not the page (which would be a foreign free).
#[test]
fn trampoline_table_leaves_the_trampoline() {
    #[repr(C, align(4096))]
    struct Page([u8; PAGE_SIZE]);
    let page = std::boxed::Box::new(Page([0; PAGE_SIZE]));
    let base = new_table();
    let before = live_frames();
    let table = TrampolineTable::new(&base, PhysAddr::new(core::ptr::from_ref(&*page) as u64));
    assert!(live_frames() > before);
    drop(table);
    assert_eq!(live_frames(), before);
}

#[test]
fn unmaps_flush_only_their_present_leaves() {
    let pgtable = new_table();
    let root = pgtable.physical_frame();
    let start = 0x1_0000;
    // Never populated: nothing to flush.
    // Safety: a fresh table, which is never loaded; unmapped user space.
    unsafe { pgtable.map_pages(range(start, 8), RW, false) }.unwrap();
    // Safety: nothing uses the pages.
    unsafe { pgtable.unmap_pages(range(start, 8), UnmapOptions::RELEASE) }.unwrap();
    assert_eq!(take_flushes(), []);

    // Present at 2, 3 and 5; at 7, PROT_NONE, which is not present.
    for page in [2, 3, 5, 7] {
        // Safety: unmapped user space.
        unsafe { pgtable.map_pages(range(start + page * PAGE_SIZE, 1), RW, true) }.unwrap();
    }
    // Safety: nothing uses the page.
    unsafe { pgtable.mprotect_pages(range(start + 7 * PAGE_SIZE, 1), VmFlags::empty()) }.unwrap();
    take_flushes();
    let before = live_frames();
    // Safety: nothing uses the pages.
    unsafe { pgtable.unmap_pages(range(start, 8), UnmapOptions::RELEASE) }.unwrap();
    assert_eq!(
        take_flushes(),
        [(root, span(start + 2 * PAGE_SIZE, 4), before)]
    );
    assert_eq!(live_frames(), before - 4);

    // One flush for more than a batch of leaves, before any is freed.
    // Safety: unmapped user space.
    unsafe { pgtable.map_pages(range(start, 600), RW, true) }.unwrap();
    assert_eq!(take_flushes(), [], "new leaves need no flush");
    let mapped = live_frames();
    // Safety: nothing uses the pages.
    unsafe { pgtable.unmap_pages(range(start, 600), UnmapOptions::RELEASE) }.unwrap();
    assert_eq!(take_flushes(), [(root, span(start, 600), mapped)]);
    assert_eq!(live_frames(), mapped - 600);
}

#[test]
fn huge_sparse_ranges_skip_absent_tables() {
    let pgtable = new_table();
    let root = pgtable.physical_frame();
    // Under different P2, P3 and P4 entries.
    let pages = [0x20_3000, 0x4000_5000, 0x80_00e0_1000, 0x7e00_0000_0000];
    for page in pages {
        // Safety: a fresh table, which is never loaded; unmapped user space.
        unsafe { pgtable.map_pages(range(page, 1), RW, true) }.unwrap();
    }
    take_flushes();
    let before = live_frames();
    // About 2^35 pages, which would take minutes to walk one by one.
    let all = PageRange::new(0x1_0000, 0x7f00_0000_0000).unwrap();

    // Safety: nothing uses the pages.
    unsafe { pgtable.mprotect_pages(all, VmFlags::VM_READ) }.unwrap();
    let read_only_pte = vmflags_to_pteflags(VmFlags::VM_READ) | PageTableFlags::PRESENT;
    for page in pages {
        check_mapped(&pgtable, page, read_only_pte);
    }
    let last = ((pages[3] - pages[0]) / PAGE_SIZE) as u64;
    assert_eq!(take_flushes(), [(root, span(pages[0], last + 1), before)]);

    // Safety: nothing uses the pages.
    unsafe { pgtable.unmap_pages(all, UnmapOptions::RELEASE) }.unwrap();
    for page in pages {
        check_unmapped(&pgtable, page);
    }
    assert_eq!(take_flushes(), [(root, span(pages[0], last + 1), before)]);
    assert_eq!(live_frames(), before - pages.len());
}

#[test]
fn protections_flush_unless_only_gaining_write() {
    let pgtable = new_table();
    let root = pgtable.physical_frame();
    let start = 0x1_0000;
    let page = range(start, 1);
    // Safety: a fresh table, which is never loaded; unmapped user space.
    unsafe { pgtable.map_pages(page, RW, true) }.unwrap();
    let live = live_frames();
    let rx = VmFlags::VM_READ | VmFlags::VM_EXEC;
    // From RW, each to the next, and whether it flushes.
    for (flags, flushes) in [
        (VmFlags::VM_READ, true),
        (VmFlags::VM_READ, false),
        (RW, false),
        (VmFlags::empty(), true),
        (VmFlags::VM_READ, false),
        (rx, true),
        (VmFlags::VM_READ, true),
    ] {
        // Safety: nothing uses the page.
        unsafe { pgtable.mprotect_pages(page, flags) }.unwrap();
        let expected = flushes.then_some((root, span(start, 1), live));
        assert_eq!(take_flushes(), expected.as_slice(), "to {flags:?}");
    }

    // Read-only at 0, writable at 1 and 2, not populated at 3: only the span
    // of those that lose a permission.
    // Safety: unmapped user space.
    unsafe { pgtable.map_pages(range(start + PAGE_SIZE, 2), RW, true) }.unwrap();
    let live = live_frames();
    // Safety: nothing uses the pages.
    unsafe { pgtable.mprotect_pages(range(start, 4), VmFlags::VM_READ) }.unwrap();
    assert_eq!(take_flushes(), [(root, span(start + PAGE_SIZE, 2), live)]);
}

#[test]
fn upgrades_and_spurious_write_faults_flush_nothing() {
    let start = 0x1_0000;
    let pgtable = populated_table(start, 1);
    let frame = mapped_frame(&pgtable, start);
    // Safety: nothing uses the page.
    unsafe { pgtable.mprotect_pages(range(start, 1), VmFlags::VM_READ) }.unwrap();
    take_flushes();
    let live = live_frames();
    // Safety: as above.
    unsafe { pgtable.mprotect_pages(range(start, 1), RW) }.unwrap();
    // A write through a stale read-only translation faults, and finds the
    // leaf writable already.
    write_fault(&pgtable, start, RW);
    check_mapped(&pgtable, start, vmflags_to_pteflags(RW));
    assert_eq!(mapped_frame(&pgtable, start), frame);
    assert_eq!(live_frames(), live);
    assert_eq!(take_flushes(), []);
}

#[test]
fn cow_copies_flush_their_page_and_take_overs_none() {
    let _sharing = sharing();
    let start = 0x1_0000;
    let parent = populated_table(start, 1);
    let child = clone(&parent);
    take_flushes();
    let allocated = live_frames();
    // Other CPUs may still read the shared frame through the child's leaf:
    // flushed with the copy mapped, before the leaf's frame is released.
    write_fault(&child, start, RW);
    assert_eq!(
        take_flushes(),
        [(child.physical_frame(), span(start, 1), allocated + 1)]
    );
    // Only gains WRITABLE.
    write_fault(&parent, start, RW);
    assert_eq!(take_flushes(), []);
    drop((parent, child));
    assert!(shared_frames().is_empty());
}

#[test]
fn cow_copies_free_the_shared_frame_only_once_flushed() {
    // A table mapping one page has a P4, P3, P2, and P1.
    const TABLE_FRAMES: usize = 4;
    let _sharing = sharing();
    let start = 0x1_0000;
    let parent = populated_table(start, 1);
    let child = clone(&parent);
    take_flushes();
    let allocated = live_frames();
    // The parent's leaf goes as the child's copy is flushed (e.g., its
    // process exits on another CPU), so that the child's release frees the
    // frame: only after the flush.
    at_next_flush(move || drop(parent));
    write_fault(&child, start, RW);
    assert_eq!(
        take_flushes(),
        [(
            child.physical_frame(),
            span(start, 1),
            allocated + 1 - TABLE_FRAMES
        )]
    );
    assert_eq!(live_frames(), allocated - TABLE_FRAMES);
    drop(child);
    assert!(shared_frames().is_empty());
}

#[test]
fn clones_flush_only_the_leaves_they_make_read_only() {
    let _sharing = sharing();
    let start = 0x1_0000;
    // Read-only at 0, writable at 1 and 2, PROT_NONE at 3, and shared memory,
    // writable, at 4.
    let parent = populated_table(start, 4);
    // Safety: nothing uses the pages.
    unsafe { parent.mprotect_pages(range(start, 1), VmFlags::VM_READ) }.unwrap();
    // Safety: as above.
    unsafe { parent.mprotect_pages(range(start + 3 * PAGE_SIZE, 1), VmFlags::empty()) }.unwrap();
    let shared_rw = RW | VmFlags::VM_SHARED;
    // Safety: unmapped user space.
    unsafe { parent.map_pages(range(start + 4 * PAGE_SIZE, 1), shared_rw, true) }.unwrap();
    take_flushes();
    let child = clone(&parent);
    assert_eq!(
        take_flushes(),
        [(
            parent.physical_frame(),
            span(start + PAGE_SIZE, 2),
            live_frames()
        )]
    );
    // The parent's leaves are all read-only but shared memory's, which stays
    // writable, so none loses WRITABLE.
    let grandchild = clone(&parent);
    assert_eq!(take_flushes(), []);
    drop((parent, child, grandchild));
    assert!(shared_frames().is_empty());
}

#[test]
fn lazily_pinned_pages_are_populated_as_found() {
    let _sharing = sharing();
    let start = 0x1_0000;
    let pgtable = new_table();
    let pages = range(start, 2);
    let page = |index: u64| Page::containing_address(VirtAddr::new(start as u64)) + index;
    // Safety: nothing unmaps or remaps `pages` while pinned, and the test,
    // their owner, may map them read-write.
    unsafe { pgtable.pin_lazily(pages) };
    let frame = pgtable.pinned_frame(page(0)).unwrap();
    check_mapped(&pgtable, start, vmflags_to_pteflags(RW));
    assert_eq!(pgtable.pinned_frame(page(0)).unwrap(), frame);
    assert_eq!(mapped_frame(&pgtable, start), frame);
    check_unmapped(&pgtable, start + PAGE_SIZE);
    assert_eq!(take_flushes(), [], "new leaves need no flush");

    set_alloc_budget(Some(0));
    let result = pgtable.pinned_frame(page(1));
    set_alloc_budget(None);
    assert!(matches!(result, Err(PageFaultError::AllocationFailed)));

    // Pinned: never shared.
    let child = clone(&pgtable);
    check_unmapped(&child, start);
    // Protected since it was pinned: refused.
    // Safety: nothing uses the page.
    unsafe { pgtable.mprotect_pages(range(start, 1), VmFlags::VM_READ) }.unwrap();
    assert!(matches!(
        pgtable.pinned_frame(page(0)),
        Err(PageFaultError::AccessError(_))
    ));
    pgtable.unpin(pages);
}
