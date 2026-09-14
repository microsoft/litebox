// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::Range;

extern crate std;

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
use zerocopy::{FromBytes, IntoBytes};

use super::linux::{
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
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(target_arch = "aarch64")]
    const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000; // 48-bit VA space

    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_state: crate::platform::page_mgmt::PageState,
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
        state: crate::platform::page_mgmt::PageState,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::RemapError> {
        Ok(TransparentMutPtr::from_usize(new_range.start))
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: crate::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), crate::platform::page_mgmt::PageStateUpdateError> {
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

/// Allocation can commit reserved ranges even when in-place decommit is unsupported.
#[test]
fn direct_mapping_keeps_noaccess_distinct_from_reserved() {
    use crate::platform::page_mgmt::{FixedAddressBehavior, PageState, PageStateUpdateError};

    let mut vmem = Vmem::new(&DummyVmemBackend);
    let range = PageRange::new(0x10000, 0x11000).unwrap();
    // SAFETY: The mock range has no real memory or concurrent users.
    unsafe {
        vmem.insert_mapping(
            range,
            VmArea::new(VmFlags::VM_MAYREAD, false),
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        assert_eq!(
            vmem.iter().next().unwrap().1.page_state(),
            PageState::Committed(MemoryRegionPermissions::empty())
        );
        vmem.protect_mapping(range, MemoryRegionPermissions::READ)
            .unwrap();
        vmem.protect_mapping(range, MemoryRegionPermissions::empty())
            .unwrap();
        assert!(matches!(
            vmem.update_mapping_state(range, PageState::Reserved),
            Err(VmemProtectError::ProtectError(
                PageStateUpdateError::UnsupportedByPlatform
            ))
        ));
        assert_eq!(
            vmem.iter().next().unwrap().1.page_state(),
            PageState::Committed(MemoryRegionPermissions::empty())
        );
        vmem.remove_mapping(range).unwrap();
        vmem.insert_mapping(
            range,
            VmArea::new_reserved(VmFlags::VM_MAYREAD, false),
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        vmem.update_mapping_state(range, PageState::Committed(MemoryRegionPermissions::READ))
            .unwrap();
        assert_eq!(
            vmem.iter().next().unwrap().1.page_state(),
            PageState::Committed(MemoryRegionPermissions::READ)
        );
        vmem.remove_mapping(range).unwrap();
    }
    assert_eq!(vmem.iter().count(), 0);
}

#[test]
fn test_decommit_default_is_unsupported() {
    use crate::platform::page_mgmt::{FixedAddressBehavior, PageState, PageStateUpdateError};

    let backend = DummyVmemBackend;
    let range = 0x10000..0x11000;

    assert_eq!(
        backend
            .allocate_pages(
                range.clone(),
                PageState::Reserved,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap()
            .as_usize(),
        range.start
    );

    assert!(matches!(
        unsafe {
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                &backend,
                range.clone(),
            )
        },
        Err(PageStateUpdateError::UnsupportedByPlatform)
    ));
    // SAFETY: The test owns this allocation and has no active accesses.
    unsafe { backend.deallocate_pages(range) }.unwrap();
}

use crate::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, PageState, PageStateUpdateError,
};

#[derive(Debug, PartialEq, Eq)]
enum PageOperation {
    Allocate(Range<usize>, PageState, bool, bool, FixedAddressBehavior),
    Remove(Range<usize>),
    Decommit(Range<usize>),
    Protect(Range<usize>),
    Remap(Range<usize>, Range<usize>, PageState),
}

struct RecordingBackend {
    operations: std::sync::Mutex<Vec<PageOperation>>,
    fail_allocate: core::sync::atomic::AtomicBool,
    foreign: Range<usize>,
    excluded: Range<usize>,
}

impl RecordingBackend {
    fn new(foreign: Range<usize>) -> &'static Self {
        Self::with_excluded(foreign, 0..0)
    }

    fn with_excluded(foreign: Range<usize>, excluded: Range<usize>) -> &'static Self {
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            operations: std::sync::Mutex::new(Vec::new()),
            fail_allocate: core::sync::atomic::AtomicBool::new(false),
            foreign,
            excluded,
        }))
    }
}

impl crate::platform::RawPointerProvider for RecordingBackend {
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

impl PageManagementProvider<PAGE_SIZE> for RecordingBackend {
    const TASK_ADDR_MIN: usize = 0x10000;
    const TASK_ADDR_MAX: usize = 0x4000000;

    fn allocate_pages(
        &self,
        range: Range<usize>,
        state: PageState,
        grow: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        self.operations
            .lock()
            .unwrap()
            .push(PageOperation::Allocate(
                range.clone(),
                state,
                grow,
                populate,
                behavior,
            ));
        if self
            .fail_allocate
            .load(core::sync::atomic::Ordering::Relaxed)
        {
            return Err(AllocationError::OutOfMemory);
        }
        if range.start < self.foreign.end && self.foreign.start < range.end {
            if behavior == FixedAddressBehavior::Hint {
                return Ok(TransparentMutPtr::from_usize(0x30000));
            }
            return Err(AllocationError::AddressInUseByPlatform);
        }
        Ok(TransparentMutPtr::from_usize(range.start))
    }

    unsafe fn deallocate_pages(
        &self,
        range: Range<usize>,
    ) -> Result<(), crate::platform::page_mgmt::DeallocationError> {
        self.operations
            .lock()
            .unwrap()
            .push(PageOperation::Remove(range));
        Ok(())
    }

    unsafe fn decommit_pages(&self, range: Range<usize>) -> Result<(), PageStateUpdateError> {
        self.operations
            .lock()
            .unwrap()
            .push(PageOperation::Decommit(range));
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<(), PageStateUpdateError> {
        self.operations
            .lock()
            .unwrap()
            .push(PageOperation::Protect(range));
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old: Range<usize>,
        new: Range<usize>,
        state: PageState,
    ) -> Result<Self::RawMutPointer<u8>, crate::platform::page_mgmt::RemapError> {
        self.operations
            .lock()
            .unwrap()
            .push(PageOperation::Remap(old, new.clone(), state));
        Ok(TransparentMutPtr::from_usize(new.start))
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        core::iter::once(&self.excluded).filter(|range| !range.is_empty())
    }
}

#[test]
fn mapping_operations_use_semantic_provider_calls() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    let range = PageRange::new(0x4f000, 0x51000).unwrap();
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    unsafe {
        vmem.create_pages(
            NonZeroAddress::new(range.start),
            NonZeroPageSize::new(range.len()).unwrap(),
            CreatePagesFlags::FIXED_ADDR
                | CreatePagesFlags::NOREPLACE
                | CreatePagesFlags::IS_STACK
                | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            PageState::Reserved,
        )
        .unwrap();
        vmem.update_mapping_state(range, PageState::Committed(MemoryRegionPermissions::READ))
            .unwrap();
        vmem.protect_mapping(range, MemoryRegionPermissions::empty())
            .unwrap();
        vmem.update_mapping_state(range, PageState::Reserved)
            .unwrap();
        vmem.remove_mapping(range).unwrap();
    }
    assert_eq!(
        *backend.operations.lock().unwrap(),
        vec![
            PageOperation::Allocate(
                range.into(),
                PageState::Reserved,
                true,
                true,
                FixedAddressBehavior::NoReplace
            ),
            PageOperation::Allocate(
                range.into(),
                PageState::Committed(MemoryRegionPermissions::READ),
                true,
                false,
                FixedAddressBehavior::Replace
            ),
            PageOperation::Protect(range.into()),
            PageOperation::Decommit(range.into()),
            PageOperation::Remove(range.into()),
        ]
    );
    assert!(vmem.iter().next().is_none());
}

#[test]
fn nonfixed_placement_tracks_backend_relocation() {
    let maximum = RecordingBackend::TASK_ADDR_MAX;
    for suggestion in [None, NonZeroAddress::new(maximum - PAGE_SIZE)] {
        for state in [
            PageState::Reserved,
            PageState::Committed(MemoryRegionPermissions::READ),
        ] {
            let backend = RecordingBackend::new(maximum - 3 * PAGE_SIZE..maximum);
            let mut vmem = Vmem::new(backend);
            // SAFETY: The mock ranges have no backing memory or concurrent users.
            let pointer = unsafe {
                vmem.create_pages(
                    suggestion,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::empty(),
                    state,
                )
            }
            .unwrap();
            assert_eq!(pointer.as_usize(), 0x30000);
            assert_eq!(
                *backend.operations.lock().unwrap(),
                vec![PageOperation::Allocate(
                    maximum - PAGE_SIZE..maximum,
                    state,
                    false,
                    false,
                    FixedAddressBehavior::Hint,
                )]
            );
            let mappings: Vec<_> = vmem
                .iter()
                .map(|(range, vma)| (range.clone(), vma.page_state()))
                .collect();
            assert_eq!(mappings, vec![(0x30000..0x31000, state)]);
            // SAFETY: The relocated mock mapping has no concurrent users.
            unsafe { vmem.remove_mapping(PageRange::new(0x30000, 0x31000).unwrap()) }.unwrap();
            assert_eq!(
                backend.operations.lock().unwrap().last(),
                Some(&PageOperation::Remove(0x30000..0x31000))
            );
            assert!(vmem.iter().next().is_none());
        }
    }
}

#[test]
fn placement_growth_space_is_a_hint() {
    let maximum = RecordingBackend::TASK_ADDR_MAX;
    let padding = super::linux::DEFAULT_RESERVED_SPACE_SIZE;
    let first = maximum - padding - PAGE_SIZE;
    let backend = RecordingBackend::new(first - PAGE_SIZE..first + PAGE_SIZE);
    let mut vmem = Vmem::new(backend);
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    let pointer = unsafe {
        vmem.create_pages(
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::ENSURE_SPACE_AFTER,
            PageState::Reserved,
        )
    }
    .unwrap();
    assert_eq!(pointer.as_usize(), 0x30000);
    assert_eq!(
        *backend.operations.lock().unwrap(),
        vec![PageOperation::Allocate(
            first..first + PAGE_SIZE,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::Hint,
        )]
    );
    assert_eq!(vmem.iter().next().unwrap().0, &(0x30000..0x31000));
}

#[test]
fn fixed_placement_does_not_relocate_or_replace_foreign_memory() {
    for flags in [
        CreatePagesFlags::FIXED_ADDR,
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
    ] {
        let backend = RecordingBackend::new(0x40000..0x41000);
        let mut vmem = Vmem::new(backend);
        // SAFETY: The mock ranges have no backing memory or concurrent users.
        assert!(matches!(
            unsafe {
                vmem.create_pages(
                    NonZeroAddress::new(0x40000),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    flags,
                    PageState::Reserved,
                )
            },
            Err(super::linux::MappingError::MapError(
                AllocationError::AddressInUseByPlatform
            ))
        ));
        assert_eq!(
            *backend.operations.lock().unwrap(),
            vec![PageOperation::Allocate(
                0x40000..0x41000,
                PageState::Reserved,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            )]
        );
        assert!(vmem.iter().next().is_none());
    }
}

#[test]
fn allocation_oom_is_not_retried() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    backend
        .fail_allocate
        .store(true, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    assert!(matches!(
        unsafe {
            vmem.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ, false),
                CreatePagesFlags::empty(),
            )
        },
        Err(AllocationError::OutOfMemory)
    ));
    assert_eq!(backend.operations.lock().unwrap().len(), 1);
    assert!(vmem.iter().next().is_none());
}

#[test]
fn guest_reservations_stay_owned_after_failed_commit() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    let range = PageRange::new(0x4f000, 0x51000).unwrap();
    let reserved = VmArea::new_reserved(VmFlags::VM_MAYREAD, false);
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    unsafe { vmem.insert_mapping(range, reserved, false, FixedAddressBehavior::NoReplace) }
        .unwrap();
    backend
        .fail_allocate
        .store(true, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: The mock allocation has no active users.
    unsafe {
        assert!(matches!(
            vmem.update_mapping_state(range, PageState::Committed(MemoryRegionPermissions::READ)),
            Err(VmemProtectError::ProtectError(
                PageStateUpdateError::OutOfMemory
            ))
        ));
        assert!(matches!(
            vmem.insert_mapping(range, reserved, false, FixedAddressBehavior::NoReplace),
            Err(AllocationError::AddressInUse)
        ));
    }
    assert_eq!(
        vmem.iter().next().unwrap().1.page_state(),
        PageState::Reserved
    );
    assert_eq!(backend.operations.lock().unwrap().len(), 2);
}

#[test]
fn committing_mixed_ranges_only_replaces_reserved_pages() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    let base = 0x40000;
    let permissions = MemoryRegionPermissions::READ;
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    unsafe {
        for (index, state) in [
            PageState::Committed(permissions),
            PageState::Reserved,
            PageState::Committed(MemoryRegionPermissions::empty()),
        ]
        .into_iter()
        .enumerate()
        {
            vmem.create_pages(
                NonZeroAddress::new(base + index * PAGE_SIZE),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                state,
            )
            .unwrap();
        }
        backend.operations.lock().unwrap().clear();
        vmem.update_mapping_state(
            PageRange::new(base, base + 3 * PAGE_SIZE).unwrap(),
            PageState::Committed(permissions),
        )
        .unwrap();
    }
    assert_eq!(
        *backend.operations.lock().unwrap(),
        vec![
            PageOperation::Allocate(
                base + PAGE_SIZE..base + 2 * PAGE_SIZE,
                PageState::Committed(permissions),
                false,
                false,
                FixedAddressBehavior::Replace,
            ),
            PageOperation::Protect(base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE),
        ]
    );
}

#[test]
fn manager_rejects_partial_replacement() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    let reserved = VmArea::new_reserved(VmFlags::empty(), false);
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    unsafe {
        vmem.insert_mapping(
            PageRange::new(0x40000, 0x41000).unwrap(),
            reserved,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        assert!(matches!(
            vmem.insert_mapping(
                PageRange::new(0x40000, 0x42000).unwrap(),
                reserved,
                false,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::AddressPartiallyInUse)
        ));
    }
    assert_eq!(
        *backend.operations.lock().unwrap(),
        vec![PageOperation::Allocate(
            0x40000..0x41000,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::NoReplace,
        )]
    );
}

#[test]
fn placement_avoids_platform_ranges_in_vmas() {
    let maximum = RecordingBackend::TASK_ADDR_MAX;
    let excluded = maximum - 3 * PAGE_SIZE..maximum;
    let guest = PageRange::new(excluded.start - PAGE_SIZE, excluded.start).unwrap();
    for flags in [VmFlags::empty(), VmFlags::VM_GROWSDOWN] {
        for suggestion in [None, NonZeroAddress::new(excluded.start)] {
            let backend = RecordingBackend::with_excluded(0..0, excluded.clone());
            let mut vmem = Vmem::new(backend);
            assert_eq!(vmem.iter().next().unwrap().0, &excluded);
            assert_eq!(vmem.iter().next().unwrap().1.flags(), VmFlags::empty());
            let guard = if flags.contains(VmFlags::VM_GROWSDOWN) {
                Vmem::<RecordingBackend, PAGE_SIZE>::STACK_GUARD_GAP << 1
            } else {
                0
            };
            let expected = guest.start - guard - PAGE_SIZE;
            // SAFETY: The mock ranges have no backing memory or concurrent users.
            unsafe {
                vmem.insert_mapping(
                    guest,
                    VmArea::new(flags, false),
                    false,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap();
                let first_range = if flags.is_empty() {
                    guest.start..excluded.end
                } else {
                    guest.into()
                };
                assert_eq!(vmem.iter().next().unwrap().0, &first_range);
                assert_eq!(
                    vmem.get_memory_permissions(guest),
                    Some(MemoryRegionPermissions::empty())
                );
                let pointer = vmem
                    .create_pages(
                        suggestion,
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                        CreatePagesFlags::empty(),
                        PageState::Reserved,
                    )
                    .unwrap();
                assert_eq!(pointer.as_usize(), expected);
                assert_eq!(
                    backend.operations.lock().unwrap().last(),
                    Some(&PageOperation::Allocate(
                        expected..expected + PAGE_SIZE,
                        PageState::Reserved,
                        false,
                        false,
                        FixedAddressBehavior::Hint,
                    ))
                );
                vmem.remove_mapping(guest).unwrap();
                vmem.remove_mapping(PageRange::new(expected, expected + PAGE_SIZE).unwrap())
                    .unwrap();
            }
            assert_eq!(
                vmem.iter()
                    .map(|(range, _)| range.clone())
                    .collect::<Vec<_>>(),
                vec![excluded.clone()]
            );
        }
    }
}

#[test]
fn remap_is_delegated_to_provider() {
    let backend = RecordingBackend::new(0..0);
    let mut vmem = Vmem::new(backend);
    let old = PageRange::new(0x40000, 0x41000).unwrap();
    // SAFETY: The mock ranges have no backing memory or concurrent users.
    let moved = unsafe {
        vmem.insert_mapping(
            old,
            VmArea::new_reserved(VmFlags::empty(), false),
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        vmem.move_mappings(
            old,
            NonZeroAddress::new(0x80000),
            NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(moved.as_usize(), 0x80000);
    assert_eq!(
        backend.operations.lock().unwrap().last(),
        Some(&PageOperation::Remap(
            old.into(),
            0x80000..0x82000,
            PageState::Reserved
        ))
    );
    assert_eq!(
        vmem.iter()
            .map(|(range, _)| range.clone())
            .collect::<Vec<_>>(),
        vec![0x80000..0x82000]
    );
}
