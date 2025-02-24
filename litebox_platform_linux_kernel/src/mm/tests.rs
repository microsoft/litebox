use core::alloc::{GlobalAlloc, Layout};

use arrayvec::ArrayVec;
use spin::mutex::SpinMutex;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            Page, PageSize, PageTableFlags, Size4KiB,
            mapper::{MappedFrame, TranslateResult},
            page::PageRange,
        },
    },
};

use crate::{
    HostInterface, LinuxKernel,
    arch::{PAGE_SIZE, X64PageTable},
    host::mock::MockHostInterface,
    mm::{MemoryProvider, pgtable::PageTableAllocator},
    mock_log_println,
};

use super::{alloc::SafeZoneAllocator, pgtable::PageTableImpl};

const MAX_ORDER: usize = 23;
type MockKernel = LinuxKernel<MockHostInterface>;

#[global_allocator]
static ALLOCATOR: SafeZoneAllocator<'static, MAX_ORDER, MockKernel> = SafeZoneAllocator::new();
/// const Array for VA to PA mapping
static MAPPING: SpinMutex<ArrayVec<VirtAddr, 8192>> = SpinMutex::new(ArrayVec::new_const());

impl super::MemoryProvider for MockKernel {
    const GVA_OFFSET: super::VirtAddr = super::VirtAddr::new(0);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno> {
        let mut mapping = MAPPING.lock();
        let (start, len) = MockHostInterface::alloc(layout)?;
        let begin = Page::<Size4KiB>::from_start_address(VirtAddr::new(start as _)).unwrap();
        let end = Page::<Size4KiB>::from_start_address(VirtAddr::new((start + len) as _)).unwrap();
        for page in Page::range(begin, end) {
            if mapping.is_full() {
                mock_log_println!("MAPPING is OOM");
            }
            mapping.push(page.start_address());
        }
        Ok((start, len))
    }

    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        ALLOCATOR.allocate_pages(order)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        unsafe { ALLOCATOR.free_pages(ptr, order) }
    }

    unsafe fn free(addr: usize) {
        unsafe { MockHostInterface::free(addr) };
    }

    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        let idx = MAPPING.lock().iter().position(|x| *x == va);
        assert!(idx.is_some());
        PhysAddr::new(idx.unwrap() as u64 * Size4KiB::SIZE + 0x1000_0000)
    }

    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        let mapping = MAPPING.lock();
        let idx = (pa.as_u64() - 0x1000_0000) / Size4KiB::SIZE;
        let va = mapping.get(idx as usize);
        assert!(va.is_some());
        let va = va.unwrap().clone();
        if va.is_null() {
            mock_log_println!("Invalid PA");
            panic!("Invalid PA");
        }
        va
    }
}

#[test]
fn test_buddy() {
    let ptr = MockKernel::mem_allocate_pages(1);
    assert!(ptr.is_some_and(|p| p as usize != 0));
    unsafe {
        MockKernel::mem_free_pages(ptr.unwrap(), 1);
    }
}

#[test]
fn test_slab() {
    unsafe {
        assert!(ALLOCATOR.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap()) as usize != 0);
        assert!(ALLOCATOR.alloc(Layout::from_size_align(0x10, 0x10).unwrap()) as usize != 0);
    }
}

fn check_flags(
    pgtable: &X64PageTable<'_, MockKernel>,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) {
    match pgtable.translate(page.start_address()) {
        TranslateResult::Mapped {
            frame,
            offset,
            flags: f,
        } => {
            assert!(matches!(frame, MappedFrame::Size4KiB(_)));
            assert_eq!(offset, 0);
            assert_eq!(flags, f);
        }
        _ => assert!(false),
    }
}

fn get_test_pgtable<'a>(
    range: PageRange,
    fault_flags: PageTableFlags,
) -> X64PageTable<'a, MockKernel> {
    let mut allocator = PageTableAllocator::<MockKernel>::new();
    let p4 = allocator.allocate_frame(true).unwrap();
    let mut pgtable = unsafe { X64PageTable::<MockKernel>::init(p4.start_address()) };

    for page in range {
        unsafe {
            pgtable
                .handle_page_fault(page, fault_flags, PageFaultErrorCode::USER_MODE, false)
                .unwrap();
        }
    }

    for page in range {
        check_flags(&pgtable, page, fault_flags);
    }

    pgtable
}

#[test]
fn test_page_table() {
    let start_addr = VirtAddr::new(0x1000);
    let start_page = Page::<Size4KiB>::containing_address(start_addr);
    let flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let range = Page::range(start_page, start_page + 4);
    let mut pgtable = get_test_pgtable(range, flags);

    // update flags
    let new_flags = PageTableFlags::PRESENT;
    unsafe {
        assert!(
            pgtable
                .mprotect_pages(
                    start_addr + 2 * PAGE_SIZE as u64,
                    4 * PAGE_SIZE,
                    new_flags,
                    false
                )
                .is_ok()
        )
    };
    for page in Page::range(start_page, start_page + 2) {
        check_flags(&pgtable, page, flags);
    }
    for page in Page::range(start_page + 2, start_page + 4) {
        check_flags(&pgtable, page, new_flags);
    }

    // remap pages
    let new_addr = VirtAddr::new(0x20_1000);
    let new_page = Page::<Size4KiB>::containing_address(new_addr);
    unsafe {
        assert!(
            pgtable
                .remap_pages(start_addr, new_addr, 2 * PAGE_SIZE, false)
                .is_ok()
        )
    };
    for page in Page::range(start_page, start_page + 2) {
        assert!(matches!(
            pgtable.translate(page.start_address()),
            TranslateResult::NotMapped
        ));
    }
    for page in Page::range(new_page, new_page + 2) {
        check_flags(&pgtable, page, flags);
    }

    // unmap all pages
    pgtable.unmap_pages(
        start_addr,
        (new_addr - start_addr) as usize + 4 * PAGE_SIZE,
        true,
        false,
    );
    for page in Page::range(start_page, new_page + 4) {
        assert!(matches!(
            pgtable.translate(page.start_address()),
            TranslateResult::NotMapped
        ));
    }
}
