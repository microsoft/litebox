use core::{
    alloc::{GlobalAlloc, Layout},
    ops::Range,
};

use crate::arch::{
    MappedFrame, Page, PageFaultErrorCode, PageSize, PageTableFlags, PhysAddr, Size4KiB,
    TranslateResult, VirtAddr, mm::paging::vmflags_to_pteflags,
};
use alloc::vec;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use litebox::mm::vm::{PageRange, VmArea, VmFlags, VmemBackend};
use spin::mutex::SpinMutex;

use crate::{
    HostInterface, LinuxKernel,
    arch::{PAGE_SIZE, mm::paging::X64PageTable},
    host::mock::MockHostInterface,
    mm::{
        MemoryProvider,
        pgtable::{PageFaultError, PageTableAllocator},
    },
    mock_log_println,
};

use super::{alloc::SafeZoneAllocator, pgtable::PageTableImpl, vm::KernelVmem};

const MAX_ORDER: usize = 23;
type MockKernel = LinuxKernel<MockHostInterface>;

static ALLOCATOR: SafeZoneAllocator<'static, MAX_ORDER, MockKernel> = SafeZoneAllocator::new();
/// const Array for VA to PA mapping
static MAPPING: SpinMutex<ArrayVec<VirtAddr, 1024>> = SpinMutex::new(ArrayVec::new_const());

impl super::MemoryProvider for MockKernel {
    const GVA_OFFSET: super::VirtAddr = super::VirtAddr::new(0);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::Errno> {
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
        let va = *va.unwrap();
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
        let ptr1 = ALLOCATOR.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap());
        assert!(ptr1 as usize != 0);
        let ptr2 = ALLOCATOR.alloc(Layout::from_size_align(0x10, 0x10).unwrap());
        assert!(ptr2 as usize != 0);
        ALLOCATOR.dealloc(ptr1, Layout::from_size_align(0x1000, 0x1000).unwrap());
        ALLOCATOR.dealloc(ptr2, Layout::from_size_align(0x10, 0x10).unwrap());
    }
}

fn check_flags(pgtable: &X64PageTable<'_, MockKernel>, addr: usize, flags: PageTableFlags) {
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
    range: PageRange,
    fault_flags: PageTableFlags,
) -> X64PageTable<'a, MockKernel> {
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let mut pgtable = unsafe { X64PageTable::<MockKernel>::init(p4.start_address()) };

    for page in range.clone() {
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

#[test]
fn test_page_table() {
    let start_addr: usize = 0x1000;
    let vmflags = VmFlags::VM_READ;
    let pteflags = vmflags_to_pteflags(vmflags) | PageTableFlags::PRESENT;
    let range = PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE);
    let mut pgtable = get_test_pgtable(range, pteflags);

    // update flags
    let new_vmflags = VmFlags::empty();
    let new_pteflags = vmflags_to_pteflags(new_vmflags) | PageTableFlags::PRESENT;
    unsafe {
        assert!(
            pgtable
                .mprotect_pages(start_addr + 2 * PAGE_SIZE, 4 * PAGE_SIZE, new_vmflags,)
                .is_ok()
        );
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, start_addr + 2 * PAGE_SIZE) {
        check_flags(&pgtable, page, pteflags);
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE)
    {
        check_flags(&pgtable, page, new_pteflags);
    }

    // remap pages
    let new_addr: usize = 0x20_1000;
    unsafe {
        assert!(
            pgtable
                .remap_pages(start_addr, new_addr, 2 * PAGE_SIZE)
                .is_ok()
        );
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, start_addr + 2 * PAGE_SIZE) {
        assert!(matches!(
            pgtable.translate(VirtAddr::new(page as _)),
            TranslateResult::NotMapped
        ));
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, start_addr + 2 * PAGE_SIZE) {
        check_flags(&pgtable, page, pteflags);
    }

    // unmap all pages
    unsafe {
        pgtable.unmap_pages(
            start_addr,
            usize::try_from(new_addr - start_addr).unwrap() + 4 * PAGE_SIZE,
            true,
        );
    }
    for page in PageRange::<PAGE_SIZE>::new(start_addr, new_addr + 4 * PAGE_SIZE) {
        assert!(matches!(
            pgtable.translate(VirtAddr::new(page as _)),
            TranslateResult::NotMapped
        ));
    }
}

fn collect_mappings(vmm: &KernelVmem<X64PageTable<'_, MockKernel>>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
fn test_vmm_page_fault() {
    let start_addr: usize = 0x1000;
    let start_page = Page::from_start_address(VirtAddr::new(start_addr as _)).unwrap();
    let range = PageRange::new(start_addr, start_addr + 2 * PAGE_SIZE);
    let fault_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let pt = get_test_pgtable(range, fault_flags);
    let mut vmm = KernelVmem::new(pt);
    vmm.insert_mapping(
        PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE),
        VmArea::new(
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE,
        ),
    );
    // [0x1000, 0x5000)

    // Access page w/o mapping
    assert!(matches!(
        vmm.handle_page_fault(start_page + 6, PageFaultErrorCode::USER_MODE),
        Err(PageFaultError::AccessError(_))
    ));

    // Access non-present page w/ mapping
    assert!(
        vmm.handle_page_fault(start_page + 2, PageFaultErrorCode::USER_MODE)
            .is_ok()
    );
    check_flags(
        vmm.get_pgtable(),
        start_addr + 2 * PAGE_SIZE,
        PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE,
    );

    // insert stack mapping
    let stack_addr: usize = 0x1000_0000;
    let stack_page = Page::from_start_address(VirtAddr::new(stack_addr as _)).unwrap();
    vmm.insert_mapping(
        PageRange::new(stack_addr, stack_addr + 4 * PAGE_SIZE),
        VmArea::new(
            VmFlags::VM_READ
                | VmFlags::VM_WRITE
                | VmFlags::VM_MAYREAD
                | VmFlags::VM_MAYWRITE
                | VmFlags::VM_GROWSDOWN,
        ),
    );
    // [0x1000, 0x5000), [0x1000_0000, 0x1000_4000)
    // Test stack growth
    assert!(
        vmm.handle_page_fault(stack_page - 1, PageFaultErrorCode::USER_MODE)
            .is_ok()
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![0x1000..0x5000, 0x0fff_f000..0x1000_4000]
    );
    // Cannot grow stack too far
    assert!(matches!(
        vmm.handle_page_fault(start_page + 100, PageFaultErrorCode::USER_MODE),
        Err(PageFaultError::AllocationFailed)
    ));
}
