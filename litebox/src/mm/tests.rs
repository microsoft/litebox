// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::Range;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::{
    mm::vmem::{CreatePagesFlags, NonZeroAddress},
    platform::{
        PageManagementProvider, RawConstPointer,
        common_providers::reservations::TrackedReservations,
        page_mgmt::{
            AllocationDirection, AllocationError, FixedAddressBehavior, HintPlacementBehavior,
            MemoryRegionPermissions, ReservationStore as _,
        },
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    },
};
use zerocopy::{FromBytes, IntoBytes};

use super::vmem::{
    FindAreaRequest, NonZeroPageSize, PAGE_SIZE, PageRange, VmArea, VmFlags, Vmem,
    VmemProtectError, VmemResizeError,
};

crate::define_page_reservation!(TestReservation);

#[test]
fn find_area_respects_tracked_reservations_in_both_directions() {
    let mut reservations = TrackedReservations::default();
    for reserved in [0x1_0000..0x1_2000, 0x1_7000..0x1_8000] {
        // SAFETY: Each test range is nonempty, aligned, disjoint, and uniquely represented.
        let reservation = unsafe { TestReservation::<PAGE_SIZE>::new(reserved.clone()) };
        assert!(reservations.insert(reserved.start, reservation).is_none());
    }
    let vmas = rangemap::RangeMap::new();
    let request = |include_reservations, top_down| FindAreaRequest {
        suggested_address: None,
        length: NonZeroPageSize::new(PAGE_SIZE).unwrap(),
        behavior: crate::platform::page_mgmt::FixedAddressBehavior::Hint(if top_down {
            AllocationDirection::TopDown
        } else {
            AllocationDirection::BottomUp
        }),
        alignment: PAGE_SIZE,
        include_reservations,
        address_range: 0x1_0000..0x1_8000,
    };

    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(
            &reservations,
            &vmas,
            &request(false, true)
        )
        .unwrap(),
        Some(0x1_7000)
    );
    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(
            &reservations,
            &vmas,
            &request(true, true)
        )
        .unwrap(),
        Some(0x1_6000)
    );
    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(
            &reservations,
            &vmas,
            &request(false, false)
        )
        .unwrap(),
        Some(0x1_0000)
    );
    assert_eq!(
        Vmem::<DummyVmemBackend, PAGE_SIZE, _>::find_area(
            &reservations,
            &vmas,
            &request(true, false)
        )
        .unwrap(),
        Some(0x1_2000)
    );
}

type AllocationCall = (Range<usize>, FixedAddressBehavior);

/// A configurable dummy page-management backend.
struct DummyVmemBackend<const TOP_DOWN: bool = false> {
    rejected_address: Option<usize>,
    calls: Mutex<Vec<AllocationCall>>,
}

impl<const TOP_DOWN: bool> crate::platform::RawPointerProvider for DummyVmemBackend<TOP_DOWN> {
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

#[expect(unused_variables, reason = "dummy/mock backend")]
impl<const TOP_DOWN: bool> crate::platform::PageManagementProvider<PAGE_SIZE>
    for DummyVmemBackend<TOP_DOWN>
{
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux/windows config
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000; // 48-bit VA space
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior =
        HintPlacementBehavior::Directional(if TOP_DOWN {
            AllocationDirection::TopDown
        } else {
            AllocationDirection::BottomUp
        });

    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: crate::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::AllocationError> {
        self.calls
            .lock()
            .push((suggested_range.clone(), fixed_address_behavior));
        if fixed_address_behavior == FixedAddressBehavior::NoReplace
            && self.rejected_address == Some(suggested_range.start)
        {
            return Err(AllocationError::AddressInUse);
        }
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

fn dummy_backend<const TOP_DOWN: bool>(
    rejected_address: Option<usize>,
) -> &'static DummyVmemBackend<TOP_DOWN> {
    Box::leak(Box::new(DummyVmemBackend {
        rejected_address,
        calls: Mutex::new(Vec::new()),
    }))
}

#[test]
fn hint_allocation_capabilities_support_expected_directions() {
    assert!(!HintPlacementBehavior::Unspecified.supports(AllocationDirection::BottomUp));
    assert!(HintPlacementBehavior::Exact.supports(AllocationDirection::BottomUp));
    assert!(HintPlacementBehavior::Exact.supports(AllocationDirection::TopDown));
    assert!(HintPlacementBehavior::Bidirectional.supports(AllocationDirection::BottomUp));
    assert!(HintPlacementBehavior::Bidirectional.supports(AllocationDirection::TopDown));
    assert!(
        HintPlacementBehavior::Directional(AllocationDirection::TopDown)
            .supports(AllocationDirection::TopDown)
    );
    assert!(
        !HintPlacementBehavior::Directional(AllocationDirection::TopDown)
            .supports(AllocationDirection::BottomUp)
    );
}

#[test]
fn bottom_up_hint_does_not_limit_fallback_search() {
    let backend = dummy_backend::<false>(None);
    let mut vmem: Vmem<DummyVmemBackend, PAGE_SIZE> = Vmem::new(backend);
    let suggested_address = DummyVmemBackend::<false>::TASK_ADDR_MIN + PAGE_SIZE;
    unsafe {
        vmem.create_mapping(
            NonZeroAddress::new(suggested_address),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
            CreatePagesFlags::FIXED_ADDR,
        )
    }
    .unwrap();

    let address = unsafe {
        vmem.create_mapping(
            NonZeroAddress::new(suggested_address),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
            CreatePagesFlags::empty(),
        )
    }
    .unwrap()
    .as_usize();

    assert_eq!(address, DummyVmemBackend::<false>::TASK_ADDR_MIN);
    assert_eq!(
        *backend.calls.lock(),
        [
            (
                suggested_address..suggested_address + PAGE_SIZE,
                FixedAddressBehavior::NoReplace,
            ),
            (
                address..address + PAGE_SIZE,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            ),
        ]
    );
}

#[test]
fn matching_platform_direction_uses_hint() {
    let backend = dummy_backend::<true>(Some(DummyVmemBackend::<true>::TASK_ADDR_MAX));
    let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);

    let address = unsafe {
        vmem.create_mapping(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
            CreatePagesFlags::TOP_DOWN,
        )
    }
    .unwrap()
    .as_usize();

    assert_eq!(address, DummyVmemBackend::<true>::TASK_ADDR_MAX - PAGE_SIZE);
    assert_eq!(
        *backend.calls.lock(),
        [(
            address..address + PAGE_SIZE,
            FixedAddressBehavior::Hint(AllocationDirection::TopDown),
        )]
    );
}

#[test]
fn mismatched_platform_direction_retries_with_no_replace() {
    let bottom_up_backend = dummy_backend::<true>(Some(0x1_0000));
    let mut bottom_up_vmem = Vmem::<_, PAGE_SIZE>::new(bottom_up_backend);
    let bottom_up_address = unsafe {
        bottom_up_vmem.create_mapping(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
            CreatePagesFlags::empty(),
        )
    }
    .unwrap()
    .as_usize();
    assert_eq!(bottom_up_address, 0x1_1000);
    assert_eq!(
        *bottom_up_backend.calls.lock(),
        [
            (0x1_0000..0x1_1000, FixedAddressBehavior::NoReplace),
            (0x1_1000..0x1_2000, FixedAddressBehavior::NoReplace),
        ]
    );

    let rejected_address = DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE;
    let top_down_backend = dummy_backend::<false>(Some(rejected_address));
    let mut top_down_vmem = Vmem::<_, PAGE_SIZE>::new(top_down_backend);
    let top_down_address = unsafe {
        top_down_vmem.create_mapping(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
            CreatePagesFlags::TOP_DOWN,
        )
    }
    .unwrap()
    .as_usize();
    assert_eq!(top_down_address, rejected_address - PAGE_SIZE);
    assert_eq!(
        *top_down_backend.calls.lock(),
        [
            (
                rejected_address..DummyVmemBackend::<false>::TASK_ADDR_MAX,
                FixedAddressBehavior::NoReplace,
            ),
            (
                rejected_address - PAGE_SIZE..rejected_address,
                FixedAddressBehavior::NoReplace,
            ),
        ]
    );
}

fn collect_mappings(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
fn test_vmm_mapping() {
    let start_addr: usize = 0x1_0000;
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
    let mut vmm = Vmem::new(dummy_backend::<false>(None));

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
        DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE,
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
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
            DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
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
            DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
        ]
    );
}
