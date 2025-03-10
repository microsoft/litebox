use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;

use super::vm::{
    NonZeroPageSize, PAGE_SIZE, PageRange, ProtectError, RemapError, VmArea, VmFlags, Vmem,
    VmemBackend, VmemProtectError, VmemResizeError,
};

/// A dummy implementation of [`VmemBackend`] that does nothing.
impl VmemBackend for () {
    unsafe fn unmap_pages(&mut self, start: usize, len: usize, free_page: bool) {}

    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        len: usize,
    ) -> Result<(), RemapError> {
        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError> {
        Ok(())
    }
}

fn collect_mappings(vmm: &Vmem<()>) -> Vec<Range<usize>> {
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_vmm_mapping() {
    let start_addr: usize = 0x1000;
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE);
    let mut vmm = Vmem::new(());

    // []
    vmm.insert_mapping(
        range,
        VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE),
    );
    // [(0x1000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0xd000]);

    vmm.remove_mapping(PageRange::new(
        start_addr + 2 * PAGE_SIZE,
        start_addr + 4 * PAGE_SIZE,
    ));
    // [(0x1000, 0x3000), (0x5000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0x3000, 0x5000..0xd000]);

    assert!(matches!(
        vmm.resize_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 3 * PAGE_SIZE),
            NonZeroPageSize::new(PAGE_SIZE * 2),
        ),
        // Failed to resize, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
        Err(VmemResizeError::NotExist(_))
    ));

    assert!(matches!(
        vmm.resize_mapping(
            PageRange::new(start_addr, start_addr + 3 * PAGE_SIZE),
            NonZeroPageSize::new(PAGE_SIZE * 4),
        ),
        // Failed to resize, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
        Err(VmemResizeError::InvalidAddr { .. })
    ));

    assert!(matches!(
        vmm.protect_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE),
            VmFlags::VM_READ | VmFlags::VM_WRITE,
        ),
        // Failed to protect, remain [(0x1000, 0x3000), (0x5000, 0xd000)]
        Err(VmemProtectError::InvalidRange(_))
    ));

    assert!(
        vmm.resize_mapping(
            PageRange::new(start_addr, start_addr + 2 * PAGE_SIZE),
            NonZeroPageSize::new(PAGE_SIZE * 4),
        )
        .is_ok()
    );
    // Grow and merge, [(0x1000, 0xd000)]
    assert_eq!(collect_mappings(&vmm), vec![0x1000..0xd000]);

    assert!(matches!(
        vmm.protect_mapping(
            PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE),
            VmFlags::VM_READ | VmFlags::VM_EXEC,
        ),
        // Failed to protect, remain [(0x1000, 0xd000)]
        Err(VmemProtectError::NoAccess { .. })
    ));

    assert!(
        vmm.protect_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE),
            VmFlags::VM_READ | VmFlags::VM_WRITE,
        )
        .is_ok()
    );
    // Change permission, [(0x1000, 0x3000), (0x3000, 0x5000), (0x5000, 0xd000)]
    assert_eq!(
        collect_mappings(&vmm),
        vec![0x1000..0x3000, 0x3000..0x5000, 0x5000..0xd000]
    );

    // try to remap [0x3000, 0x5000)
    let r = PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE);
    assert!(matches!(
        vmm.resize_mapping(r.clone(), NonZeroPageSize::new(PAGE_SIZE * 4)),
        Err(VmemResizeError::RangeOccupied(_))
    ));
    assert!(
        vmm.move_mappings(r, NonZeroPageSize::new(PAGE_SIZE * 4), 0)
            .is_ok_and(|v| v == 0xd000)
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![0x1000..0x3000, 0x5000..0xd000, 0xd000..0x11000]
    );

    // create new mapping with no suggested address
    assert_eq!(
        vmm.create_mapping(
            PageRange::new(0, start_addr),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD),
            false
        )
        .unwrap(),
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
        vmm.create_mapping(
            PageRange::new(start_addr + PAGE_SIZE, start_addr + 3 * PAGE_SIZE),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD),
            true
        )
        .unwrap(),
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
        vmm.resize_mapping(
            PageRange::new(start_addr + 4 * PAGE_SIZE, start_addr + 8 * PAGE_SIZE),
            NonZeroPageSize::new(0x2000)
        )
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
