// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-table tests. [`HostMemory`] backs frames with host allocations
//! (PA == VA) and tracks live blocks to catch wrong and double frees.

extern crate std;

use core::cell::RefCell;
use litebox_common_linux::vmem::{PAGE_SIZE, PageRange, VmFlags};
use std::collections::HashMap;
use x86_64::structures::idt::PageFaultErrorCode;
use x86_64::structures::paging::{
    Page, PageTableFlags, PhysFrame, Size4KiB,
    mapper::{MappedFrame, TranslateResult},
};
use x86_64::{PhysAddr, VirtAddr};

use super::{MemoryProvider, pgtable::PageTableImpl};
use crate::arch::mm::paging::{UnmapOptions, X64PageTable, vmflags_to_pteflags};

#[derive(Default)]
struct HostState {
    /// Live blocks: start address -> order.
    live_blocks: HashMap<usize, u32>,
    /// Allocations left before `mem_allocate_pages` fails (`None`: no limit).
    alloc_budget: Option<usize>,
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

fn frame_layout(order: u32) -> std::alloc::Layout {
    std::alloc::Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE).unwrap()
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
        let ptr = unsafe { std::alloc::alloc(frame_layout(order)) };
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
        unsafe { std::alloc::dealloc(ptr, frame_layout(order)) };
    }

    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new(va.as_u64())
    }

    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new(pa.as_u64())
    }
}

type TestPageTable = X64PageTable<'static, HostMemory, PAGE_SIZE>;

fn new_table() -> TestPageTable {
    TestPageTable::new_top_level()
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
    let frame = mapped_frame(&pgtable, page.start);
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
        check_mapped(&pgtable, page.start, vmflags_to_pteflags(flags));
        assert_eq!(mapped_frame(&pgtable, page.start), frame);
        assert_eq!(live_frames(), allocated);
        // Safety: protection changes do not affect HostMemory's backing allocation.
        assert_eq!(unsafe { ptr.read() }, 0x1234_5678_9abc_def0);
    }
    assert!(!vmflags_to_pteflags(VmFlags::empty()).contains(PageTableFlags::PRESENT));
    // Safety: the table is never loaded and no access to the frame remains.
    unsafe { pgtable.unmap_pages(page, UnmapOptions::RELEASE) }.unwrap();
    check_unmapped(&pgtable, page.start);
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
    let frame = mapped_frame(&pgtable, pages.start);
    let allocated = live_frames();
    // Safety: no access to these mappings; the retained frame is freed below.
    unsafe { pgtable.unmap_pages(range(pages.start, 1), UnmapOptions::KEEP_FRAMES) }.unwrap();
    check_unmapped(&pgtable, pages.start);
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
            .map_kernel_ram(PhysFrame::range(frame, frame + 1), &text, &read_only)
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
fn user_writable_frames_are_found_only_for_writable_pages() {
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
        pgtable.user_writable_frame(VirtAddr::new(start as u64 + 5)),
        Some(mapped_frame(&pgtable, start))
    );
    assert_eq!(
        pgtable.user_writable_frame(VirtAddr::new((start + PAGE_SIZE) as u64)),
        None
    );
    assert_eq!(
        pgtable.user_writable_frame(VirtAddr::new((start + 2 * PAGE_SIZE) as u64)),
        None
    );
    assert_eq!(
        pgtable.user_writable_frame(VirtAddr::new((start + 3 * PAGE_SIZE) as u64)),
        None
    );
}
