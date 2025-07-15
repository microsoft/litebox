use core::alloc::{GlobalAlloc, Layout};

use alloc::vec;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use litebox::{
    LiteBox,
    mm::{
        PageManager,
        allocator::SafeZoneAllocator,
        linux::{PAGE_SIZE, PageFaultError, PageRange, VmFlags},
    },
    platform::RawConstPointer,
};
use spin::mutex::SpinMutex;

use crate::{
    HostInterface,
    arch::{
        MappedFrame, Page, PageFaultErrorCode, PageTableFlags, PhysAddr, Size4KiB, TranslateResult,
        VirtAddr,
        mm::paging::{X64PageTable, vmflags_to_pteflags},
    },
    host::mock::{MockHostInterface, MockKernel},
    mm::{MemoryProvider, pgtable::PageTableAllocator},
    mock_log_println,
    ptr::UserMutPtr,
};

use super::pgtable::PageTableImpl;

const MAX_ORDER: usize = 23;

static ALLOCATOR: SafeZoneAllocator<'static, MAX_ORDER, MockKernel> = SafeZoneAllocator::new();
/// const Array for VA to PA mapping
static MAPPING: SpinMutex<ArrayVec<VirtAddr, 1024>> = SpinMutex::new(ArrayVec::new_const());

impl litebox::mm::allocator::MemoryProvider for MockKernel {
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        let mut mapping = MAPPING.lock();
        let (start, len) = MockHostInterface::alloc(layout)?;
        let begin = Page::<Size4KiB>::from_start_address(VirtAddr::new(start as _)).unwrap();
        let end = Page::<Size4KiB>::from_start_address(VirtAddr::new((start + len) as _)).unwrap();
        for page in Page::range(begin, end) {
            if mapping.is_full() {
                mock_log_println!("MAPPING is OOM");
                panic!()
            }
            mapping.push(page.start_address());
        }
        Some((start, len))
    }

    unsafe fn free(addr: usize) {
        unsafe { MockHostInterface::free(addr) };
    }
}

impl super::MemoryProvider for MockKernel {
    const GVA_OFFSET: super::VirtAddr = super::VirtAddr::new(0);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        ALLOCATOR.allocate_pages(order)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        unsafe { ALLOCATOR.free_pages(ptr, order) }
    }

    unsafe fn mem_fill_pages(start: usize, size: usize) {
        unsafe { ALLOCATOR.fill_pages(start, size) }
    }

    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        let idx = MAPPING.lock().iter().position(|x| *x == va);
        assert!(idx.is_some());
        PhysAddr::new((idx.unwrap() * PAGE_SIZE + 0x1000_0000) as u64)
    }

    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        let mapping = MAPPING.lock();
        let idx = (pa.as_u64() - 0x1000_0000) / PAGE_SIZE as u64;
        let va = mapping.get(usize::try_from(idx).unwrap());
        assert!(va.is_some());
        let va = *va.unwrap();
        if va.is_null() {
            mock_log_println!("Invalid PA");
            panic!("Invalid PA");
        }
        va
    }
}

#[ignore]
#[test]
fn test_buddy() {
    let ptr = MockKernel::mem_allocate_pages(1);
    assert!(ptr.is_some_and(|p| p as usize != 0));
    unsafe {
        MockKernel::mem_free_pages(ptr.unwrap(), 1);
    }
}

#[ignore]
#[test]
fn test_slab() {
    unsafe {
        let ptr1 = ALLOCATOR.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap());
        assert!(ptr1 as usize != 0);
        let ptr2 = ALLOCATOR.alloc(Layout::from_size_align(0x10, 0x10).unwrap());
        assert!(ptr2 as usize != 0);
        ALLOCATOR.dealloc(ptr1, Layout::from_size_align(0x1000, 0x1000).unwrap());
        ALLOCATOR.dealloc(ptr2, Layout::from_size_align(0x10, 0x10).unwrap());
    }
}

fn check_flags(
    pgtable: &X64PageTable<'_, MockKernel, PAGE_SIZE>,
    addr: usize,
    flags: PageTableFlags,
) {
    match pgtable.translate(VirtAddr::new(addr as _)) {
        TranslateResult::Mapped {
            frame,
            offset,
            flags: f,
        } => {
            assert!(matches!(frame, MappedFrame::Size4KiB(_)));
            assert_eq!(offset, 0);
            assert_eq!(flags, f);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

fn get_test_pgtable<'a>(
    range: PageRange<PAGE_SIZE>,
    fault_flags: PageTableFlags,
) -> X64PageTable<'a, MockKernel, PAGE_SIZE> {
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let pgtable = unsafe { X64PageTable::<MockKernel, PAGE_SIZE>::init(p4.start_address()) };

    for page in range {
        unsafe {
            pgtable
                .handle_page_fault(
                    Page::containing_address(VirtAddr::new(page as _)),
                    fault_flags,
                    PageFaultErrorCode::USER_MODE,
                )
                .unwrap();
        }
    }

    for page in range {
        check_flags(&pgtable, page, fault_flags);
    }

    pgtable
}

#[ignore]
#[test]
fn test_page_table() {
    let start_addr: usize = 0x1000;
    let vmflags = VmFlags::VM_READ;
    let pteflags = vmflags_to_pteflags(vmflags) | PageTableFlags::PRESENT;
    let range = PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap();
    let pgtable = get_test_pgtable(range, pteflags);

    // update flags
    let new_vmflags = VmFlags::empty();
    let new_pteflags = vmflags_to_pteflags(new_vmflags) | PageTableFlags::PRESENT;
    unsafe {
        assert!(
            pgtable
                .mprotect_pages(
                    PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 6 * PAGE_SIZE).unwrap(),
                    new_vmflags
                )
                .is_ok()
        );
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, start_addr + 2 * PAGE_SIZE).unwrap() {
        check_flags(&pgtable, page, pteflags);
    }
    for page in
        PageRange::<PAGE_SIZE>::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap()
    {
        check_flags(&pgtable, page, new_pteflags);
    }

    // remap pages
    let new_addr: usize = 0x20_1000;
    unsafe {
        assert!(
            pgtable
                .remap_pages(
                    PageRange::new(start_addr, start_addr + 2 * PAGE_SIZE).unwrap(),
                    PageRange::new(new_addr, new_addr + 2 * PAGE_SIZE).unwrap()
                )
                .is_ok()
        );
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, start_addr + 2 * PAGE_SIZE).unwrap() {
        assert!(matches!(
            pgtable.translate(VirtAddr::new(page as _)),
            TranslateResult::NotMapped
        ));
    }
    for page in PageRange::<PAGE_SIZE>::new(new_addr, new_addr + 2 * PAGE_SIZE).unwrap() {
        check_flags(&pgtable, page, pteflags);
    }

    // unmap all pages
    let range = PageRange::new(start_addr, new_addr + 4 * PAGE_SIZE).unwrap();
    unsafe { pgtable.unmap_pages(range, true) }.unwrap();
    for page in PageRange::<PAGE_SIZE>::new(start_addr, new_addr + 4 * PAGE_SIZE).unwrap() {
        assert!(matches!(
            pgtable.translate(VirtAddr::new(page as _)),
            TranslateResult::NotMapped
        ));
    }
}

#[ignore]
#[test]
fn test_vmm_page_fault() {
    let start_addr: usize = 0x1_0000;
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let platform = MockKernel::new(
        p4.start_address(),
        x86_64::PhysAddr::new(0),
        x86_64::PhysAddr::new(0),
    );
    let litebox = LiteBox::new(platform);
    let mut vmm = PageManager::<_, PAGE_SIZE>::new(&litebox);
    unsafe {
        assert_eq!(
            vmm.create_writable_pages(
                Some(litebox::mm::linux::NonZeroAddress::new(start_addr).unwrap()),
                litebox::mm::linux::NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                litebox::mm::linux::CreatePagesFlags::FIXED_ADDR,
                |_: UserMutPtr<u8>| Ok(0),
            )
            .unwrap()
            .as_usize(),
            start_addr
        );
    }
    // [0x1_0000, 0x1_4000)

    // Access page w/o mapping
    assert!(matches!(
        unsafe {
            vmm.handle_page_fault(
                start_addr + 6 * PAGE_SIZE,
                PageFaultErrorCode::USER_MODE.bits(),
            )
        },
        Err(PageFaultError::AccessError(_))
    ));

    // Access non-present page w/ mapping
    assert!(
        unsafe {
            vmm.handle_page_fault(
                start_addr + 2 * PAGE_SIZE,
                PageFaultErrorCode::USER_MODE.bits(),
            )
        }
        .is_ok()
    );

    // insert stack mapping
    let stack_addr: usize = 0x1000_0000;
    unsafe {
        assert_eq!(
            vmm.create_stack_pages(
                Some(litebox::mm::linux::NonZeroAddress::new(stack_addr).unwrap()),
                litebox::mm::linux::NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                litebox::mm::linux::CreatePagesFlags::FIXED_ADDR,
            )
            .unwrap()
            .as_usize(),
            stack_addr
        );
    }
    // [0x1_0000, 0x1_4000), [0x1000_0000, 0x1000_4000)
    // Test stack growth
    assert!(
        unsafe {
            vmm.handle_page_fault(stack_addr - PAGE_SIZE, PageFaultErrorCode::USER_MODE.bits())
        }
        .is_ok()
    );
    assert_eq!(
        vmm.mappings()
            .iter()
            .map(|v| v.0.clone())
            .collect::<Vec<_>>(),
        vec![0x1_0000..0x1_4000, 0x0fff_f000..0x1000_4000]
    );
    // Cannot grow stack too far
    assert!(matches!(
        unsafe {
            vmm.handle_page_fault(
                start_addr + 100 * PAGE_SIZE,
                PageFaultErrorCode::USER_MODE.bits(),
            )
        },
        Err(PageFaultError::AllocationFailed)
    ));
}
