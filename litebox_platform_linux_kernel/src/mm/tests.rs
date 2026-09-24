// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::alloc::{GlobalAlloc, Layout};

use alloc::vec;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use litebox::platform::page_mgmt::PageReservation;
use litebox::{
    LiteBox,
    mm::{
        LinuxPageManager,
        allocator::SafeZoneAllocator,
        linux::{
            CreatePagesFlags, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, PageFaultError,
            PageRange, VmFlags,
        },
    },
    platform::RawConstPointer,
};
use spin::mutex::SpinMutex;

use crate::{
    HostInterface, UserMutPtr,
    arch::{
        MappedFrame, Page, PageFaultErrorCode, PageTableFlags, PhysAddr, Size4KiB, TranslateResult,
        VirtAddr,
        mm::paging::{X64PageTable, vmflags_to_pteflags},
    },
    host::mock::{MockHostInterface, MockKernel},
    mm::{MemoryProvider, pgtable::PageTableAllocator},
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
                litebox_util_log::error!("MAPPING is OOM");
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
            litebox_util_log::error!("Invalid PA");
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
    flags: VmFlags,
) -> X64PageTable<'a, MockKernel, PAGE_SIZE> {
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let pgtable = unsafe { X64PageTable::<MockKernel, PAGE_SIZE>::init(p4.start_address()) };
    pgtable.map_pages(range, flags, true);

    let fault_flags = vmflags_to_pteflags(flags) | PageTableFlags::PRESENT;
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
    let range = PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap();
    let pgtable = get_test_pgtable(range, vmflags);

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

#[test]
fn test_vmm_page_fault() {
    let start_addr: usize = 0x1_0000;
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let platform = MockKernel::new(p4.start_address());
    let litebox = LiteBox::new(platform);
    let vmm = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox);
    unsafe {
        assert_eq!(
            vmm.create_writable_pages(
                Some(NonZeroAddress::new(start_addr).unwrap()),
                NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
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
                Some(NonZeroAddress::new(stack_addr).unwrap()),
                NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
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

#[test]
fn test_release_committed_and_decommitted_backing() {
    use litebox::platform::{
        PageManagementProvider,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
    };

    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let platform = MockKernel::new(p4.start_address());
    let range = 0x90000..0x90000 + 5 * PAGE_SIZE;
    let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
    let release = <MockKernel as PageManagementProvider<PAGE_SIZE>>::release_pages;
    // SAFETY: The fixture owns all synthetic mappings; no users survive decommit or release.
    unsafe {
        let reservation = <MockKernel as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
            platform,
            || -> core::iter::Empty<_> {
                panic!("no-replace reserve must not request reservations")
            },
            range.clone(),
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            permissions,
            true,
        )
        .unwrap();
        let middle = range.start + PAGE_SIZE..range.end - PAGE_SIZE;
        let (prefix, released, suffix) = reservation.split(middle.clone());
        let prefix = prefix.unwrap();
        let suffix = suffix.unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&released),
            middle.start + PAGE_SIZE..middle.end - PAGE_SIZE,
        )
        .unwrap();
        release(platform, middle.clone());
        for address in middle.step_by(PAGE_SIZE) {
            assert!(matches!(
                platform.page_table.translate(VirtAddr::new(address as u64)),
                TranslateResult::NotMapped
            ));
        }
        for address in [prefix.range().start, suffix.range().start] {
            check_flags(
                &platform.page_table,
                address,
                vmflags_to_pteflags(VmFlags::from(permissions)) | PageTableFlags::PRESENT,
            );
        }
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&prefix),
            prefix.range(),
        )
        .unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, range.clone());
        for address in range.clone().step_by(PAGE_SIZE) {
            assert!(matches!(
                platform.page_table.translate(VirtAddr::new(address as u64)),
                TranslateResult::NotMapped
            ));
        }
    }
}

unsafe fn release_reservations<const ALIGN: usize>(
    platform: &MockKernel,
    reservations: Vec<litebox::platform::page_mgmt::ReservationOf<MockKernel, ALIGN>>,
) {
    use litebox::platform::PageManagementProvider;
    for reservation in reservations {
        let range = reservation.range();
        // SAFETY: The fixture relinquishes this exact owned extent without remaining users.
        unsafe { <MockKernel as PageManagementProvider<ALIGN>>::release_pages(platform, range) };
    }
}

#[test]
fn test_backing_primitives() {
    use litebox::platform::{
        PageManagementProvider,
        page_mgmt::{AllocationError, FixedAddressBehavior, MemoryRegionPermissions},
    };

    const HANDLE_ALIGN: usize = 2 * PAGE_SIZE;
    let p4 = PageTableAllocator::<MockKernel>::allocate_frame(true).unwrap();
    let platform = MockKernel::new(p4.start_address());
    // SAFETY: The fixture acquires and releases fresh uncommitted pages with no users.
    unsafe {
        let reservation = <MockKernel as PageManagementProvider<HANDLE_ALIGN>>::reserve_pages(
            platform,
            || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
            0x80000..0x80000 + HANDLE_ALIGN,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap();
        assert_eq!(reservation.range().start, 0x80000);
        assert_eq!(reservation.range().len(), HANDLE_ALIGN);
        <MockKernel as PageManagementProvider<HANDLE_ALIGN>>::release_pages(
            platform,
            0x80000..0x80000 + HANDLE_ALIGN,
        );
    }
    let range = 0x50000..0x50000 + 3 * PAGE_SIZE;
    let reserve = |platform: &MockKernel,
                   range: core::ops::Range<usize>,
                   behavior: FixedAddressBehavior,
                   grow| {
        assert_ne!(behavior, FixedAddressBehavior::Replace);
        // SAFETY: The fixture requests exclusively owned synthetic pages without replacement.
        unsafe {
            <MockKernel as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("non-replacing reserve must not request reservations")
                },
                range.clone(),
                grow,
                behavior,
            )
        }
    };
    let reservation = reserve(
        platform,
        range.clone(),
        FixedAddressBehavior::NoReplace,
        false,
    )
    .unwrap();
    let release = release_reservations::<PAGE_SIZE>;
    assert!(matches!(
        platform
            .page_table
            .translate(VirtAddr::new(range.start as u64)),
        TranslateResult::NotMapped
    ));
    assert_eq!(reservation.range(), range);
    assert!(matches!(
        reserve(
            platform,
            range.start + 1..range.end,
            FixedAddressBehavior::NoReplace,
            false
        ),
        Err(AllocationError::Unaligned)
    ));
    let physical_pointer =
        |address: usize| match platform.page_table.translate(VirtAddr::new(address as u64)) {
            TranslateResult::Mapped {
                frame: MappedFrame::Size4KiB(frame),
                ..
            } => MockKernel::pa_to_va(frame.start_address()).as_mut_ptr::<u8>(),
            other => panic!("expected committed physical page: {other:?}"),
        };
    // SAFETY: All frames and handles belong exclusively to this test; no users survive decommit or release.
    unsafe {
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.start..range.start + PAGE_SIZE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            true,
        )
        .unwrap();
        let original = physical_pointer(range.start);
        original.write(0x5a);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
            true,
        )
        .unwrap();
        assert_eq!(physical_pointer(range.start), original);
        assert_eq!(original.read(), 0x5a);
        assert!(matches!(
            platform.page_table.translate(VirtAddr::new(range.start as u64)),
            TranslateResult::Mapped { flags, .. } if !flags.contains(PageTableFlags::WRITABLE)
        ));
        for recommit in [true, false] {
            for permissions in [
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                MemoryRegionPermissions::EXEC,
                MemoryRegionPermissions::READ,
            ] {
                if recommit {
                    <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                        platform,
                        || core::iter::once(&reservation),
                        range.clone(),
                        permissions,
                        true,
                    )
                    .unwrap();
                } else {
                    <MockKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                        platform,
                        || core::iter::once(&reservation),
                        range.clone(),
                        permissions,
                    )
                    .unwrap();
                }
                let mut expected = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
                expected.set(
                    PageTableFlags::WRITABLE,
                    permissions.contains(MemoryRegionPermissions::WRITE),
                );
                expected.set(
                    PageTableFlags::NO_EXECUTE,
                    !permissions.contains(MemoryRegionPermissions::EXEC),
                );
                for address in range.clone().step_by(PAGE_SIZE) {
                    check_flags(&platform.page_table, address, expected);
                }
                assert_eq!(physical_pointer(range.start), original);
                assert_eq!(original.read(), 0x5a);
            }
        }
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
        )
        .unwrap();
        assert_eq!(physical_pointer(range.start), original);
        assert_eq!(original.read(), 0x5a);
        assert_eq!(physical_pointer(range.start + PAGE_SIZE).read(), 0);
        let old_range = range.start..range.start + PAGE_SIZE;
        let mut remaining = vec![reservation];
        let destination_reservation =
            <MockKernel as PageManagementProvider<PAGE_SIZE>>::try_remap_pages(
                platform,
                || {
                    let (prefix, source, suffix) =
                        remaining.pop().unwrap().split(old_range.clone());
                    remaining.extend(prefix);
                    remaining.extend(suffix);
                    core::iter::once(source)
                },
                old_range.clone(),
                0x70000..0x70000 + 2 * PAGE_SIZE,
                MemoryRegionPermissions::READ,
            )
            .unwrap();
        let destination_range = destination_reservation.range();
        remaining.push(destination_reservation);
        assert_eq!(
            remaining
                .iter()
                .map(litebox::platform::page_mgmt::PageReservation::range)
                .collect::<Vec<_>>(),
            vec![old_range.end..range.end, 0x70000..0x70000 + 2 * PAGE_SIZE]
        );
        let suffix = remaining.remove(0);
        assert_eq!(suffix.range(), old_range.end..range.end);
        assert_eq!(physical_pointer(suffix.range().start).read(), 0);
        assert_eq!(destination_range.start, 0x70000);
        assert_eq!(destination_range.len(), 2 * PAGE_SIZE);
        assert_eq!(physical_pointer(destination_range.start), original);
        assert_eq!(physical_pointer(destination_range.start).read(), 0x5a);
        assert_eq!(
            physical_pointer(destination_range.start + PAGE_SIZE).read(),
            0
        );
        assert!(matches!(
            platform
                .page_table
                .translate(VirtAddr::new(range.start as u64)),
            TranslateResult::NotMapped
        ));
        for destination in &remaining {
            <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                platform,
                || core::iter::once(destination),
                destination.range(),
            )
            .unwrap();
        }
        release(platform, remaining);
        let reservation = reserve(
            platform,
            old_range.clone(),
            FixedAddressBehavior::NoReplace,
            false,
        )
        .unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.start..range.start + PAGE_SIZE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            true,
        )
        .unwrap();
        physical_pointer(range.start).write(0x5a);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&suffix),
            suffix.range(),
        )
        .unwrap();
        let original = physical_pointer(range.start);
        let mut remaining = vec![reservation];
        let destination_reservation =
            <MockKernel as PageManagementProvider<PAGE_SIZE>>::try_remap_pages(
                platform,
                || remaining.drain(..),
                old_range.clone(),
                0x80000..0x80000 + 2 * PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
        let moved = destination_reservation.range();
        remaining.push(destination_reservation);
        assert_eq!(moved, 0x80000..0x80000 + 2 * PAGE_SIZE);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].range(), moved);
        assert_eq!(physical_pointer(moved.start), original);
        assert_eq!(physical_pointer(moved.start).read(), 0x5a);
        assert_eq!(physical_pointer(moved.end - PAGE_SIZE).read(), 0);
        assert!(matches!(
            platform
                .page_table
                .translate(VirtAddr::new(range.start as u64)),
            TranslateResult::NotMapped
        ));
        release(platform, remaining);
        release(platform, vec![suffix]);
        let reservation = reserve(
            platform,
            range.clone(),
            FixedAddressBehavior::NoReplace,
            false,
        )
        .unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
            true,
        )
        .unwrap();
        physical_pointer(range.start).write(0x5a);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
            platform,
            || -> core::iter::Once<
                &litebox::platform::page_mgmt::ReservationOf<MockKernel, PAGE_SIZE>,
            > {
                panic!("range protection must not request reservations")
            },
            range.clone(),
            MemoryRegionPermissions::empty(),
        )
        .unwrap();
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
        )
        .unwrap();
        assert_eq!(physical_pointer(range.start).read(), 0x5a);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
        )
        .unwrap();
        assert!(matches!(
            platform
                .page_table
                .translate(VirtAddr::new(range.start as u64)),
            TranslateResult::NotMapped
        ));
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
            true,
        )
        .unwrap();
        assert_eq!(physical_pointer(range.start).read(), 0);
        let middle = range.start + PAGE_SIZE..range.start + 2 * PAGE_SIZE;
        let prefix_frame = physical_pointer(range.start);
        let suffix_frame = physical_pointer(range.end - PAGE_SIZE);
        let mut remaining = vec![reservation];
        let replacement = <MockKernel as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
            platform,
            || {
                let (prefix, replaced, suffix) = remaining.pop().unwrap().split(middle.clone());
                remaining.extend(prefix);
                remaining.extend(suffix);
                core::iter::once(replaced)
            },
            middle.clone(),
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(replacement.range(), middle);
        assert!(matches!(
            platform
                .page_table
                .translate(VirtAddr::new(middle.start as u64)),
            TranslateResult::NotMapped
        ));
        assert_eq!(physical_pointer(range.start), prefix_frame);
        assert_eq!(physical_pointer(range.end - PAGE_SIZE), suffix_frame);
        assert_eq!(physical_pointer(range.start).read(), 0);
        assert_eq!(physical_pointer(range.end - PAGE_SIZE).read(), 0);
        assert_eq!(remaining.len(), 2);
        let suffix = remaining.pop().unwrap();
        let prefix = remaining.pop().unwrap();
        assert_eq!(prefix.range(), range.start..range.start + PAGE_SIZE);
        assert_eq!(suffix.range(), range.end - PAGE_SIZE..range.end);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&prefix),
            prefix.range(),
        )
        .unwrap();
        release(platform, vec![prefix]);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&suffix),
            suffix.range(),
        )
        .unwrap();
        release(platform, vec![suffix]);
        release(platform, vec![replacement]);
        let restored = reserve(
            platform,
            range.clone(),
            FixedAddressBehavior::NoReplace,
            false,
        )
        .unwrap();
        release(platform, vec![restored]);

        let reservation = <MockKernel as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
            platform,
            || -> core::iter::Empty<_> {
                panic!("no-replace reserve must not request reservations")
            },
            range.clone(),
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        assert_eq!(reservation.range(), range);
        for address in range.clone().step_by(PAGE_SIZE) {
            assert!(matches!(
                platform.page_table.translate(VirtAddr::new(address as u64)),
                TranslateResult::NotMapped
            ));
        }
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
            true,
        )
        .unwrap();
        assert_eq!(physical_pointer(range.start).read(), 0);
        <MockKernel as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
        )
        .unwrap();
        release(platform, vec![reservation]);
        assert!(matches!(
            platform
                .page_table
                .translate(VirtAddr::new(range.start as u64)),
            TranslateResult::NotMapped
        ));
        let restored = reserve(platform, range, FixedAddressBehavior::NoReplace, false).unwrap();
        release(platform, vec![restored]);
    }
}
