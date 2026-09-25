// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    mm::vmem::{CreatePagesFlags, NonZeroAddress},
    platform::{
        PageManagementProvider, RawConstPointer,
        common_providers::reservations::TrackedReservations,
        page_mgmt::{MemoryRegionPermissions, ReservationStore as _},
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    },
};
use zerocopy::{FromBytes, IntoBytes};

use super::vmem::{
    FindAreaRequest, MappingState, NoTrackedReservations, NonZeroPageSize, PAGE_SIZE, PageRange,
    VmArea, VmFlags, Vmem, VmemProtectError, VmemResizeError,
};

crate::define_page_reservation!(TestReservation);

#[test]
fn mapping_state_supports_untracked_reservations() {
    let mut state = MappingState::<NoTrackedReservations>::default();
    state
        .vmas
        .insert(0x1000..0x2000, VmArea::new(VmFlags::VM_READ, false));

    assert!(state.vmas.contains_key(&0x1000));
    assert_eq!(state.reservations.iter().count(), 0);
    assert_eq!(state.reservations.overlapping(0x1000..0x2000).count(), 0);
    assert!(
        state
            .reservations
            .take_overlapping(0x1000..0x2000)
            .is_empty()
    );
}

#[test]
fn find_area_optionally_excludes_tracked_reservations() {
    let mut reservations = TrackedReservations::default();
    let reserved = 0x1_7000..0x1_8000;
    // SAFETY: The test range is nonempty, aligned, and uniquely represented.
    let reservation = unsafe { TestReservation::<PAGE_SIZE>::new(reserved.clone()) };
    assert!(reservations.insert(reserved.start, reservation).is_none());
    let vmas = rangemap::RangeMap::new();
    let request = |include_reservations| FindAreaRequest {
        suggested_address: None,
        length: NonZeroPageSize::new(PAGE_SIZE).unwrap(),
        behavior: crate::platform::page_mgmt::FixedAddressBehavior::Hint,
        alignment: PAGE_SIZE,
        include_reservations,
        address_range: 0x1_0000..0x1_8000,
        top_down: true,
    };

    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(&reservations, &vmas, request(false))
            .unwrap(),
        Some(0x1_7000)
    );
    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(&reservations, &vmas, request(true))
            .unwrap(),
        Some(0x1_6000)
    );
}

/// A dummy implementation of [`VmemBackend`] that does nothing.
struct DummyVmemBackend<const RESERVATION_ALIGN: usize = PAGE_SIZE>;

impl<const RESERVATION_ALIGN: usize> crate::platform::RawPointerProvider
    for DummyVmemBackend<RESERVATION_ALIGN>
{
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

#[expect(unused_variables, reason = "dummy/mock backend")]
impl<const RESERVATION_ALIGN: usize> crate::platform::PageManagementProvider<PAGE_SIZE>
    for DummyVmemBackend<RESERVATION_ALIGN>
{
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux/windows config
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000; // 48-bit VA space
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    const RESERVATION_ALIGNMENT: usize = RESERVATION_ALIGN;

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

#[test]
fn automatic_placement_uses_reservation_alignment() {
    type Backend = DummyVmemBackend<0x1_0000>;
    let vmm = Vmem::<Backend, PAGE_SIZE>::new(&DummyVmemBackend::<0x1_0000>);
    let address = vmm
        .get_unmmaped_area(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            crate::platform::page_mgmt::FixedAddressBehavior::Hint,
            true,
        )
        .unwrap()
        .unwrap();

    assert!(address.is_multiple_of(Backend::RESERVATION_ALIGNMENT));
}

fn collect_mappings(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
fn test_vmm_mapping() {
    let start_addr: usize = 0x1_0000;
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
    let mut vmm = Vmem::new(&DummyVmemBackend);

    // []
    unsafe {
        vmm.insert_mapping(
            range,
            VmArea::new(
                VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE,
                false,
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
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
            )
        }
        .unwrap()
        .as_usize(),
        DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX - PAGE_SIZE,
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX,
        ]
    );

    // create new mapping with fixed address that overlaps with other mapping
    assert_eq!(
        unsafe {
            vmm.create_mapping(
                Some(NonZeroAddress::new(start_addr + PAGE_SIZE).unwrap()),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
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
            DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX,
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
            DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<PAGE_SIZE>::TASK_ADDR_MAX,
        ]
    );
}
