// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exercise real page-table mutations with an explicit recording invalidator.
//! These tables are software-only: never load them into CR3 or access their VAs.

extern crate std;

use super::*;
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    vec::Vec,
};
use core::{
    alloc::Layout,
    cell::{Cell, RefCell},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const PAGE_SIZE: usize = 4096;
const BASE: usize = 0x10000;

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Invalidate(u64, usize),
    Domain(u64),
    Complete,
    Free(u64),
}

std::thread_local! {
    static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    static FAIL_INVALIDATION: Cell<bool> = const { Cell::new(false) };
}

fn record(event: Event) {
    EVENTS.with_borrow_mut(|events| events.push(event));
}

fn take_events() -> Vec<Event> {
    EVENTS.with_borrow_mut(core::mem::take)
}

struct RecordingTlb<const OFFSET: u64 = 0>;

// SAFETY: this backend is only paired with tables that are never loaded in CR3.
// There are no hardware translations; returning models completed invalidation.
unsafe impl<const OFFSET: u64> TlbInvalidation for RecordingTlb<OFFSET> {
    fn invalidate(start: Page<Size4KiB>, count: usize) {
        if OFFSET != 0 {
            record(Event::Domain(OFFSET));
        }
        record(Event::Invalidate(start.start_address().as_u64(), count));
        assert!(!FAIL_INVALIDATION.get(), "simulated shootdown failure");
        record(Event::Complete);
    }
}

struct TestMemory<const OFFSET: u64 = 0>;

impl<const OFFSET: u64> MemoryProvider for TestMemory<OFFSET> {
    fn print(args: core::fmt::Arguments<'_>) {
        std::eprint!("{args}");
    }

    type Tlb = RecordingTlb<OFFSET>;
    const GVA_OFFSET: VirtAddr = VirtAddr::zero();
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        let layout = Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE).unwrap();
        // SAFETY: nonzero layout with page alignment. Test tables use the
        // allocation's address as a simulated PA, never as a hardware PA.
        let ptr = unsafe { alloc_zeroed(layout) };
        (!ptr.is_null()).then_some(ptr)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        record(Event::Free(ptr as u64));
        // SAFETY: the page-table allocator returns exactly the allocation/order
        // obtained above, after the test's synchronous invalidation completes.
        unsafe {
            dealloc(
                ptr,
                Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE).unwrap(),
            );
        };
    }

    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        unimplemented!("test memory uses the system allocator")
    }

    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new(va.as_u64() + OFFSET)
    }
    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new(pa.as_u64() - OFFSET)
    }
}

struct AddressSpace {
    table: X64PageTable<'static, TestMemory, PAGE_SIZE>,
    range: PageRange<PAGE_SIZE>,
}

impl AddressSpace {
    fn new(pages: usize) -> Self {
        let range = PageRange::new(BASE, BASE + pages * PAGE_SIZE).unwrap();
        // SAFETY: the test allocator supplies valid, zeroed backing frames.
        let table = unsafe { X64PageTable::new_top_level() };
        table.map_pages(range, VmFlags::VM_READ | VmFlags::VM_WRITE, true);
        take_events();
        Self { table, range }
    }

    fn frames(&self) -> Vec<u64> {
        let inner = self.table.inner.lock();
        self.range
            .into_iter()
            .map(|va| {
                inner
                    .translate_addr(VirtAddr::new(va as u64))
                    .unwrap()
                    .as_u64()
            })
            .collect()
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // SAFETY: no CPU ever loaded these tables, so remaining mappings can
        // be torn down without invalidation. Also reclaims intermediate tables.
        unsafe {
            self.table
                .unmap_pages(self.range, true, false, true)
                .unwrap();
        };
        // X64PageTable::drop subsequently frees the top-level frame.
    }
}

#[test]
fn each_unmap_batch_completes_before_any_of_its_frames_are_freed() {
    for count in [1, 32, 33, 65] {
        let space = AddressSpace::new(count);
        let frames = space.frames();
        // SAFETY: the fixture exclusively owns these software-only mappings.
        unsafe {
            space
                .table
                .unmap_pages(space.range, true, true, false)
                .unwrap();
        };

        let mut expected = Vec::new();
        for (batch, frames) in frames.chunks(32).enumerate() {
            expected.push(Event::Invalidate(
                (BASE + batch * 32 * PAGE_SIZE) as u64,
                frames.len(),
            ));
            expected.push(Event::Complete);
            expected.extend(frames.iter().copied().map(Event::Free));
        }
        assert_eq!(take_events(), expected);
    }
}

#[test]
fn foreign_frame_unmap_invalidates_without_freeing_frames() {
    let space = AddressSpace::new(3);
    let frames = space.frames();
    // SAFETY: mappings are exclusively owned; retain backing frames externally.
    unsafe {
        space
            .table
            .unmap_pages(space.range, false, true, false)
            .unwrap();
    };
    assert_eq!(
        take_events(),
        [Event::Invalidate(BASE as u64, 3), Event::Complete]
    );
    for frame in frames {
        // SAFETY: invalidation completed, and unmap did not free these frames.
        unsafe { TestMemory::<0>::mem_free_pages(frame as *mut u8, 0) };
    }
}

#[test]
fn failed_invalidation_does_not_release_unmapped_frames() {
    let space = AddressSpace::new(1);
    let frames = space.frames();
    FAIL_INVALIDATION.set(true);
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: fixture-owned inactive mappings. Inject failure precisely at
        // the completion boundary, after the PTE is cleared but before reuse.
        unsafe {
            space
                .table
                .unmap_pages(space.range, true, true, false)
                .unwrap();
        };
    }));
    FAIL_INVALIDATION.set(false);
    assert!(result.is_err());
    assert_eq!(take_events(), [Event::Invalidate(BASE as u64, 1)]);

    // The PTE is gone but its frame was deliberately retained. Only this test
    // can reclaim it without a successful shootdown: no hardware used the table.
    for frame in frames {
        unsafe { TestMemory::<0>::mem_free_pages(frame as *mut u8, 0) };
    }
}

#[test]
fn permission_updates_use_the_selected_invalidator() {
    let space = AddressSpace::new(2);
    // SAFETY: fixture-owned mappings, inaccessible to hardware or other threads.
    unsafe {
        space
            .table
            .mprotect_pages(space.range, VmFlags::VM_READ)
            .unwrap();
    };
    assert_eq!(
        take_events(),
        [Event::Invalidate(BASE as u64, 2), Event::Complete]
    );
    for va in space.range {
        let TranslateResult::Mapped { flags, .. } = space.table.translate(VirtAddr::new(va as u64))
        else {
            panic!("permission change lost a mapping");
        };
        assert!(!flags.contains(PageTableFlags::WRITABLE));
    }
}

#[test]
fn managers_and_retained_handles_keep_their_selected_memory_domain() {
    use crate::{PageTableHandle, PageTableManager, mm::active::ActivePageTable};
    use alloc::sync::Arc;

    fn exercise<const OFFSET: u64>() {
        take_events();
        // SAFETY: host allocations back these software-only tables; neither
        // manager loads CR3 or exposes its simulated VAs to hardware.
        let base =
            unsafe { crate::mm::PageTable::<TestMemory<OFFSET>, PAGE_SIZE>::new_top_level() };
        let manager = PageTableManager::new(base);
        let task_id = manager.create_task_page_table().unwrap();
        let base_handle = PageTableHandle::base(&manager.base_page_table);
        let task = Arc::clone(manager.task_page_tables.read().get(&task_id).unwrap());
        assert_ne!(
            task_id as u64,
            base_handle.get_physical_frame().start_address().as_u64()
        );
        let backing_va = TestMemory::<OFFSET>::pa_to_va(task.get_physical_frame().start_address());
        assert_eq!(task_id as u64, backing_va.as_u64() + OFFSET);

        let retained = ActivePageTable::new(task_id, Arc::clone(&task));
        let recovered = retained
            .get::<crate::mm::PageTable<TestMemory<OFFSET>, PAGE_SIZE>>(task_id)
            .unwrap();
        assert!(Arc::ptr_eq(&task, &recovered));
        // A same-ID request through a different provider must not reinterpret
        // the table using different translations or a different allocator.
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                retained.get::<crate::mm::PageTable<TestMemory<8192>, PAGE_SIZE>>(task_id);
            }))
            .is_err()
        );

        let handle = PageTableHandle::task(recovered);
        let range = PageRange::new(BASE, BASE + PAGE_SIZE).unwrap();
        handle.map_pages(range, VmFlags::VM_READ | VmFlags::VM_WRITE, true);
        take_events();
        // SAFETY: fixture-owned, software-only mappings.
        unsafe {
            handle.mprotect_pages(range, VmFlags::VM_READ).unwrap();
        }
        let mut expected = Vec::new();
        if OFFSET != 0 {
            expected.push(Event::Domain(OFFSET));
        }
        expected.extend([Event::Invalidate(BASE as u64, 1), Event::Complete]);
        assert_eq!(take_events(), expected);
        unsafe {
            handle.unmap_pages(range, true, true, true).unwrap();
        }
        take_events();

        // Same ownership rule used by delete_task_page_table: active/borrowed
        // tables cannot be unwrapped. Avoid the CR3 check in that method here.
        let owned = manager.task_page_tables.write().remove(&task_id).unwrap();
        let owned = Arc::try_unwrap(owned)
            .err()
            .expect("live handles retain the table");
        drop(task);
        drop(handle);
        drop(retained);
        let table = Arc::try_unwrap(owned).unwrap_or_else(|_| panic!("unexpected remaining owner"));
        drop(table);
        assert_eq!(take_events(), [Event::Free(backing_va.as_u64())]);
    }

    // Both providers coexist in one build; cfg(test) does not choose a global
    // memory backend. Allocation, PA translation, invalidation and destruction
    // all use the provider selected by each manager.
    exercise::<0>();
    exercise::<4096>();
}
