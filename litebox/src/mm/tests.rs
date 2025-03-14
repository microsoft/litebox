use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;

use crate::platform::{
    RawConstPointer,
    trivial_providers::{TransparentConstPtr, TransparentMutPtr},
};

use super::linux::{
    NonZeroPageSize, PAGE_SIZE, PageRange, VmArea, VmFlags, Vmem, VmemProtectError, VmemResizeError,
};

/// A dummy implementation of [`VmemBackend`] that does nothing.
struct DummyVmemBackend;

impl crate::platform::RawPointerProvider for DummyVmemBackend {
    type RawConstPointer<T: Clone> = TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = TransparentMutPtr<T>;
}

impl crate::platform::PageManagementProvider<PAGE_SIZE> for DummyVmemBackend {
    fn allocate_pages(
        &self,
        range: Range<usize>,
        initial_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        max_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::AllocationError> {
        Ok(unsafe {
            core::mem::transmute::<*mut u8, TransparentMutPtr<u8>>(range.start as *mut u8)
        })
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
    ) -> Result<(), crate::platform::page_mgmt::RemapError> {
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), crate::platform::page_mgmt::PermissionUpdateError> {
        Ok(())
    }
}

fn collect_mappings(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_vmm_mapping() {
    let start_addr: usize = 0x1000;
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
    let mut vmm = Vmem::new(&DummyVmemBackend);

    // []
    unsafe {
        vmm.insert_mapping(
            range,
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE),
        );
    }
    // [(0x1000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0xd000]);

    unsafe {
        vmm.remove_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
        );
    }
    // [(0x1000, 0x3000), (0x5000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0x3000, 0x5000..0xd000]);

    assert!(matches!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 3 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE * 2).unwrap(),
            )
        },
        // Failed to resize, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
        Err(VmemResizeError::NotExist(_))
    ));

    assert!(matches!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr, start_addr + 3 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
            )
        },
        // Failed to resize, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
        Err(VmemResizeError::InvalidAddr { .. })
    ));

    assert!(matches!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
            )
        },
        // Failed to protect, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
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
    // Grow and merge, [(0x1000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0xd000]);

    assert!(matches!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap(),
                VmFlags::VM_READ | VmFlags::VM_EXEC,
            )
        },
        // Failed to protect, remain [(0x1000, 0xd000)]
        Err(VmemProtectError::NoAccess { .. })
    ));

    assert!(
        unsafe {
            vmm.protect_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
            )
        }
        .is_ok()
    );
    // Change permission, [(0x1000, 0x3000), (0x3000, 0x5000), (0x5000, 0xd000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![0x1000..0x3000, 0x3000..0x5000, 0x5000..0xd000]
    );

    // try to remap [0x3000, 0x5000)
    let r = PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap();
    assert!(matches!(
        unsafe { vmm.resize_mapping(r, NonZeroPageSize::new(PAGE_SIZE * 4).unwrap()) },
        Err(VmemResizeError::RangeOccupied(_))
    ));
    assert!(
        unsafe { vmm.move_mappings(r, PageRange::new(0, PAGE_SIZE * 4).unwrap()) }
            .is_ok_and(|v| v == 0xd000)
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![0x1000..0x3000, 0x5000..0xd000, 0xd000..0x11000]
    );

    // create new mapping with no suggested address
    assert_eq!(
        unsafe {
            vmm.create_mapping(
                PageRange::new(0, start_addr).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD),
                false,
            )
        }
        .unwrap()
        .as_usize(),
        0x11000
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            0x1000..0x3000,
            0x5000..0xd000,
            0xd000..0x11000,
            0x11000..0x12000
        ]
    );

    // create new mapping with fixed address that overlaps with other mapping
    assert_eq!(
        unsafe {
            vmm.create_mapping(
                PageRange::new(start_addr + PAGE_SIZE, start_addr + 3 * PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD),
                true,
            )
        }
        .unwrap()
        .as_usize(),
        start_addr + PAGE_SIZE
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            0x1000..0x2000,
            0x2000..0x4000,
            0x5000..0xd000,
            0xd000..0x11000,
            0x11000..0x12000
        ]
    );

    // shrink mapping
    assert!(
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start_addr + 4 * PAGE_SIZE, start_addr + 8 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(0x2000).unwrap(),
            )
        }
        .is_ok()
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            0x1000..0x2000,
            0x2000..0x4000,
            0x5000..0x7000,
            0x9000..0xd000,
            0xd000..0x11000,
            0x11000..0x12000
        ]
    );
}
