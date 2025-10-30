use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    mm::linux::{CreatePagesFlags, NonZeroAddress},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::MemoryRegionPermissions,
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    },
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

#[expect(unused_variables, reason = "dummy/mock backend")]
impl crate::platform::PageManagementProvider<PAGE_SIZE> for DummyVmemBackend {
    #[cfg(target_os = "linux")]
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "x86", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0xC000_0000; // 3 GiB (see arch/x86/include/asm/page_32_types.h)

    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::AllocationError> {
        Ok(TransparentMutPtr {
            inner: suggested_range.start as *mut u8,
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
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::RemapError> {
        Ok(TransparentMutPtr {
            inner: new_range.start as *mut u8,
        })
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
            true,
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
                NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
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
            start_addr + PAGE_SIZE..start_addr + 3 * PAGE_SIZE,
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
            start_addr + PAGE_SIZE..start_addr + 3 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 6 * PAGE_SIZE,
            start_addr + 8 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE..DummyVmemBackend::TASK_ADDR_MAX,
        ]
    );
}
