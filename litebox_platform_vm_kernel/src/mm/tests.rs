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
    Page, PageTableFlags,
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
