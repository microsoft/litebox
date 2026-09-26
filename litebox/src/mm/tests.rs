// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    mm::vmem::{CreatePagesFlags, NonZeroAddress},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::MemoryRegionPermissions,
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    },
};
use zerocopy::{FromBytes, IntoBytes};

use super::vmem::{
    NonZeroPageSize, PAGE_SIZE, PageRange, VmArea, VmFlags, Vmem, VmemProtectError, VmemResizeError,
};

/// A dummy implementation of [`VmemBackend`] that does nothing.
struct DummyVmemBackend;

impl crate::platform::RawPointerProvider for DummyVmemBackend {
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

#[expect(unused_variables, reason = "dummy/mock backend")]
impl crate::platform::PageManagementProvider<PAGE_SIZE> for DummyVmemBackend {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux/windows config
    // An arm64 Mach-O process reserves the first 4 GiB as `__PAGEZERO`.
    #[cfg(target_vendor = "apple")]
    const TASK_ADDR_MIN: usize = 0x1_0000_0000;
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000; // 48-bit VA space
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    // Matches `litebox_platform_macos_userland`'s deliberately conservative bound.
    #[cfg(target_vendor = "apple")]
    const TASK_ADDR_MAX: usize = 0x0000_4000_0000_0000;

    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: crate::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::AllocationError> {
        Ok(TransparentMutPtr::from_usize(suggested_range.start))
    }

    unsafe fn deallocate_pages(
        &self,
        range: Range<usize>,
    ) -> Result<(), crate::platform::page_mgmt::DeallocationError> {
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::RemapError> {
        Ok(TransparentMutPtr::from_usize(new_range.start))
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), crate::platform::page_mgmt::PermissionUpdateError> {
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        core::iter::empty()
    }
}

fn collect_mappings(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
fn test_vmm_mapping() {
    // Anchored to the backend's own floor rather than a literal, because that
    // floor is host-dependent: an arm64 Mach-O process reserves the first 4 GiB
    // as `__PAGEZERO`, so the Linux value this used to hardcode is not a mappable
    // address there and every insert failed with `BelowMinAddress`. The hex in
    // the comments below traces the Linux base; on another host the same layout
    // sits at that host's floor.
    let start_addr: usize =
        <DummyVmemBackend as crate::platform::PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
    let mut vmm = Vmem::new(&DummyVmemBackend);

    // []
    unsafe {
        vmm.insert_mapping(
            range,
            VmArea::new(
                VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE,
                false,
                None,
            ),
            false,
            crate::platform::page_mgmt::FixedAddressBehavior::Replace,
        )
    }
    .unwrap();
    // [(0x1_0000, 0x1_c000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![start_addr..start_addr + 12 * PAGE_SIZE]
    );

    unsafe {
        vmm.remove_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
        )
    }
    .unwrap();
    // [(0x1_0000, 0x1_2000), (0x1_4000, 0x1_c000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE
        ]
    );

    assert!(matches!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 3 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE * 2).unwrap(),
            )
        },
        // Failed to resize, remain [(0x1_0000, 0x1_2000), (0x1_4000, 0x1_c000)]
        Err(VmemResizeError::NotExist(_))
    ));

    assert!(matches!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr, start_addr + 3 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
            )
        },
        // Failed to resize, remain [(0x1_0000, 0x1_2000), (0x1_4000, 0x1_c000)]
        Err(VmemResizeError::InvalidAddr { .. })
    ));

    assert!(matches!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        },
        // Failed to protect, remain [(0x1_0000, 0x1_2000), (0x1_4000, 0x1_c000)]
        Err(VmemProtectError::InvalidRange(_))
    ));

    assert!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr, start_addr + 2 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
            )
        }
        .is_ok()
    );
    // Grow and merge, [(0x1_0000, 0x1_c000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![start_addr..start_addr + 12 * PAGE_SIZE]
    );

    assert!(matches!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            )
        },
        // Failed to protect, remain [(0x1_0000, 0x1_c000)]
        Err(VmemProtectError::NoAccess { .. })
    ));

    assert!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        }
        .is_ok()
    );
    // Change permission, [(0x1_0000, 0x1_2000), (0x1_2000, 0x1_4000), (0x1_4000, 0x1_c000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 2 * PAGE_SIZE..start_addr + 4 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE
        ]
    );

    // try to remap [0x1_2000, 0x1_4000)
    let r = PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap();
    assert!(matches!(
        unsafe { vmm.resize_mapping(r, NonZeroPageSize::new(PAGE_SIZE * 4).unwrap()) },
        Err(VmemResizeError::RangeOccupied(_))
    ));
    assert!(
        unsafe {
            vmm.move_mappings(
                r,
                Some(NonZeroAddress::new(start_addr + 12 * PAGE_SIZE).unwrap()),
                NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
            )
        }
        .is_ok_and(|v| v.as_usize() == start_addr + 12 * PAGE_SIZE)
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE
        ]
    );

    // create new mapping with no suggested address
    assert_eq!(
        unsafe {
            vmm.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false, None),
                CreatePagesFlags::empty(),
            )
        }
        .unwrap()
        .as_usize(),
        DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE,
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE..DummyVmemBackend::TASK_ADDR_MAX,
        ]
    );

    // create new mapping with fixed address that overlaps with other mapping
    assert_eq!(
        unsafe {
            vmm.create_mapping(
                Some(NonZeroAddress::new(start_addr + PAGE_SIZE).unwrap()),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false, None),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap()
        .as_usize(),
        start_addr + PAGE_SIZE
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + PAGE_SIZE,
            start_addr + PAGE_SIZE..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE..DummyVmemBackend::TASK_ADDR_MAX,
        ]
    );

    // shrink mapping
    assert!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr + 4 * PAGE_SIZE, start_addr + 8 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
            )
        }
        .is_ok()
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + PAGE_SIZE,
            start_addr + PAGE_SIZE..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 6 * PAGE_SIZE,
            start_addr + 8 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE..DummyVmemBackend::TASK_ADDR_MAX,
        ]
    );
}

/// A backend whose `reserved_pages` includes a region entirely *above*
/// `TASK_ADDR_MAX`, modeling a real host mapping that a platform's memory-map
/// scan reports without clipping to the guest's own (deliberately
/// conservative, on e.g. macOS) address ceiling -- see
/// `litebox_platform_macos_userland::read_memory_maps`, which walks every
/// `mach_vm_region` in the host process regardless of where it falls relative
/// to `MacOsUserland::TASK_ADDR_MAX`.
struct DummyVmemBackendWithHighReservedPage;

impl crate::platform::RawPointerProvider for DummyVmemBackendWithHighReservedPage {
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

#[expect(unused_variables, reason = "dummy/mock backend")]
impl crate::platform::PageManagementProvider<PAGE_SIZE> for DummyVmemBackendWithHighReservedPage {
    const TASK_ADDR_MIN: usize =
        <DummyVmemBackend as crate::platform::PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
    const TASK_ADDR_MAX: usize =
        <DummyVmemBackend as crate::platform::PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX;

    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: crate::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::AllocationError> {
        Ok(TransparentMutPtr::from_usize(suggested_range.start))
    }

    unsafe fn deallocate_pages(
        &self,
        range: Range<usize>,
    ) -> Result<(), crate::platform::page_mgmt::DeallocationError> {
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::RemapError> {
        Ok(TransparentMutPtr::from_usize(new_range.start))
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), crate::platform::page_mgmt::PermissionUpdateError> {
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        // A host mapping entirely above `TASK_ADDR_MAX` -- e.g. the dyld
        // shared cache or some other high host allocation that macOS's ASLR
        // occasionally slides above litebox's conservative 2^46 ceiling even
        // though the host's real address space extends further.
        const HIGH_RANGE: Range<usize> = (<DummyVmemBackendWithHighReservedPage as crate::platform::PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX + PAGE_SIZE * 10)
            ..(<DummyVmemBackendWithHighReservedPage as crate::platform::PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX + PAGE_SIZE * 20);
        core::iter::once(&HIGH_RANGE)
    }
}

/// Regression test for a top-down placement bug: when the *globally* highest
/// tracked region sits above `TASK_ADDR_MAX` (always true for a `reserved_pages`
/// entry the platform's memory-map scan picked up beyond the guest's own
/// ceiling), `get_unmmaped_area`'s fast path used to key off that region's end
/// unconditionally, see it exceed `high_limit`, and skip straight to the
/// per-gap loop -- which never re-tries "the top of the eligible range" as a
/// candidate, only the space immediately below each *tracked* region. With
/// nothing else tracked below the ceiling, the loop then exhausts and the
/// search fails outright, even though the entire guest range is free.
#[test]
fn test_top_down_search_ignores_reserved_page_above_ceiling() {
    let mut vmm = Vmem::new(&DummyVmemBackendWithHighReservedPage);

    let addr = unsafe {
        vmm.create_mapping(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false, None),
            CreatePagesFlags::empty(),
        )
    }
    .expect("the entire guest range below TASK_ADDR_MAX is free, so the top-down search should succeed rather than failing outright")
    .as_usize();

    assert_eq!(
        addr,
        <DummyVmemBackendWithHighReservedPage as crate::platform::PageManagementProvider<
            PAGE_SIZE,
        >>::TASK_ADDR_MAX
            - PAGE_SIZE,
        "the entire guest range below TASK_ADDR_MAX is free, so the top-down \
         search should return the highest slot rather than some lower address",
    );
}
