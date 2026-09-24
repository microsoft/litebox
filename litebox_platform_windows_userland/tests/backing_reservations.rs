#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use litebox::platform::{
    PageManagementProvider, RawConstPointer,
    page_mgmt::{
        AllocationError, FixedAddressBehavior, MemoryRegionPermissions, PageReservation,
        ReservationOf, ReserveAndCommitError,
    },
};
use litebox_platform_windows_userland::WindowsUserland;
use windows_sys::Win32::System::Memory as memory;

const RESERVATION_ALIGNMENT: usize =
    <WindowsUserland as PageManagementProvider<4096>>::RESERVATION_ALIGNMENT;
static VM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_vm_tests() -> std::sync::MutexGuard<'static, ()> {
    VM_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn query(address: usize) -> memory::MEMORY_BASIC_INFORMATION {
    let mut information = memory::MEMORY_BASIC_INFORMATION::default();
    // SAFETY: VirtualQuery inspects an address without dereferencing it; the output is valid.
    assert_ne!(
        unsafe {
            memory::VirtualQuery(
                address as *const _,
                &raw mut information,
                core::mem::size_of_val(&information),
            )
        },
        0
    );
    information
}

unsafe fn release_reservations<const ALIGN: usize, Platform: PageManagementProvider<ALIGN>>(
    platform: &Platform,
    reservations: Vec<ReservationOf<Platform, ALIGN>>,
) {
    // SAFETY: The fixture relinquishes these owned extents without remaining users.
    unsafe {
        for reservation in reservations {
            platform.release_pages(reservation.into());
        }
    }
}

fn reserve_backing<Platform: PageManagementProvider<4096>>(
    platform: &Platform,
    range: core::ops::Range<usize>,
    behavior: FixedAddressBehavior,
    can_grow_down: bool,
) -> Result<ReservationOf<Platform, 4096>, AllocationError> {
    assert_ne!(behavior, FixedAddressBehavior::Replace);
    // SAFETY: The fixture reserves inaccessible pages without replacement.
    unsafe {
        platform.reserve_pages(
            || -> core::iter::Empty<_> {
                panic!("non-replacing reserve must not request reservations")
            },
            range,
            can_grow_down,
            behavior,
        )
    }
}

#[test]
fn startup_reservations_preserve_exact_native_ranges() {
    const PAGE_SIZE: usize = 4096;
    const ALIGNMENT: usize =
        <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT;
    let _guard = lock_vm_tests();

    let owner = WindowsUserland::new();
    let reservation =
        reserve_backing(owner, 0..3 * PAGE_SIZE, FixedAddressBehavior::Hint, false).unwrap();
    let extent = reservation.range();
    // SAFETY: The fixture exclusively owns this reservation and has no active page users.
    unsafe {
        owner
            .commit_pages(
                || core::iter::once(&reservation),
                extent.start + PAGE_SIZE..extent.start + 2 * PAGE_SIZE,
                MemoryRegionPermissions::READ,
                false,
            )
            .unwrap();
    }
    assert_eq!(query(extent.start).State, memory::MEM_RESERVE);
    assert_eq!(query(extent.start + PAGE_SIZE).State, memory::MEM_COMMIT);
    assert_eq!(
        query(extent.start + 2 * PAGE_SIZE).State,
        memory::MEM_RESERVE
    );

    let padding = extent.end..extent.end.next_multiple_of(ALIGNMENT);
    assert_eq!(query(padding.start).State, memory::MEM_FREE);
    // SAFETY: Only the original owner releases the fixture.
    unsafe { release_reservations(owner, vec![reservation]) };
}

#[test]
fn native_reserve_and_commit_preserves_ownership() {
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
    // SAFETY: The test owns all returned extents and ends accesses before releasing them.
    unsafe {
        let reservation =
            <WindowsUserland as PageManagementProvider<4096>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                0..8192,
                writable,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let extent = reservation.range();
        assert_eq!(extent.len(), 8192);
        assert!(extent.start.is_multiple_of(0x10000));
        for address in extent.clone().step_by(4096) {
            assert_eq!(query(address).State, memory::MEM_COMMIT);
            assert_eq!(query(address).Protect, memory::PAGE_READWRITE);
            assert_eq!((address as *const u8).read(), 0);
        }
        (extent.start as *mut u8).write(0x5a);
        let collision =
            <WindowsUserland as PageManagementProvider<4096>>::reserve_and_commit_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("failed allocation must not request reservations")
                },
                extent.clone(),
                writable,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap_err();
        assert!(matches!(
            collision,
            ReserveAndCommitError::Allocation(AllocationError::AddressInUseByPlatform)
        ));
        let mut existing = vec![reservation];
        let replacement =
            <WindowsUserland as PageManagementProvider<4096>>::reserve_and_commit_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("unsupported replacement must not request reservations")
                },
                extent.clone(),
                writable,
                false,
                false,
                FixedAddressBehavior::Replace,
            )
            .unwrap_err();
        assert!(matches!(
            replacement,
            ReserveAndCommitError::UnsupportedByPlatform
        ));
        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].range(), extent);
        assert_eq!((extent.start as *const u8).read(), 0x5a);
        let relocated =
            <WindowsUserland as PageManagementProvider<4096>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                extent.clone(),
                MemoryRegionPermissions::empty(),
                false,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let relocated_extent = relocated.range();
        assert_ne!(relocated_extent.start, extent.start);
        assert_eq!(relocated_extent.len(), extent.len());
        assert_eq!(query(relocated_extent.start).State, memory::MEM_COMMIT);
        assert_eq!(query(relocated_extent.start).Protect, memory::PAGE_NOACCESS);
        assert_eq!((extent.start as *const u8).read(), 0x5a);
        existing.push(relocated);
        release_reservations::<4096, _>(platform, existing);
        assert_eq!(query(extent.start).State, memory::MEM_FREE);
        assert_eq!(query(relocated_extent.start).State, memory::MEM_FREE);
    }
}

#[test]
fn automatic_hint_relocates_after_native_collision() {
    use litebox::mm::{CreatePagesFlags, LinuxPageManager, NonZeroAddress, NonZeroPageSize};
    let _guard = lock_vm_tests();

    let platform = WindowsUserland::new();
    let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    let initial_reservations = manager.reservations();
    let foreign = reserve_backing(platform, 0..0x10000, FixedAddressBehavior::Hint, false).unwrap();
    let extent = foreign.range();
    // SAFETY: The test owns the foreign reservation; hint allocation must preserve it and all accesses end before release.
    unsafe {
        <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
            platform,
            || core::iter::once(&foreign),
            extent.clone(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            false,
        )
        .unwrap();
        (extent.start as *mut u8).write(0x5a);
        let pointer = manager
            .create_writable_pages(
                NonZeroAddress::new(extent.start + 4096),
                NonZeroPageSize::new(4096).unwrap(),
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )
            .unwrap();
        assert!(!extent.contains(&pointer.as_usize()));
        let reservations = manager.reservations();
        assert_eq!(reservations.len(), initial_reservations.len() + 1);
        assert_eq!(
            reservations
                .iter()
                .find(|range| range.contains(&pointer.as_usize()))
                .unwrap()
                .len(),
            0x10000
        );
        assert_eq!(query(pointer.as_usize()).State, memory::MEM_COMMIT);
        assert_eq!(query(pointer.as_usize() + 4096).State, memory::MEM_RESERVE);
        assert_eq!((extent.start as *const u8).read(), 0x5a);
        manager.unmap_pages(pointer, 4096).unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(pointer.as_usize()).State, memory::MEM_FREE);
        release_reservations::<4096, _>(platform, vec![foreign]);
    }
}

#[test]
fn explicit_backing_lifecycle() {
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let reservation_alignment =
        <WindowsUserland as PageManagementProvider<4096>>::RESERVATION_ALIGNMENT;
    assert_eq!(reservation_alignment, 0x10000);
    // SAFETY: Hint placement acquires fresh address space without replacing any mapping.
    let reservation = unsafe {
        <WindowsUserland as PageManagementProvider<4096>>::reserve_pages(
            platform,
            core::iter::empty,
            0..8192,
            false,
            FixedAddressBehavior::Hint,
        )
    }
    .unwrap();
    let extent = reservation.range();
    assert!(extent.start.is_multiple_of(reservation_alignment));
    assert_eq!(extent.len(), 8192);
    let range = extent.start..extent.start + 4096;
    for address in extent.clone().step_by(4096) {
        assert_eq!(query(address).State, memory::MEM_RESERVE);
    }
    // SAFETY: This test exclusively owns the reservation and all accesses end before release.
    unsafe {
        <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            false,
        )
        .unwrap();
        (range.start as *mut u8).write(0x5a);
        let mut original = vec![reservation];
        let error = <WindowsUserland as PageManagementProvider<4096>>::reserve_pages(
            platform,
            || -> core::iter::Empty<_> {
                panic!("occupied replacement must not request reservations")
            },
            extent.clone(),
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap_err();
        assert!(matches!(error, AllocationError::AddressInUseByPlatform));
        assert_eq!(original.len(), 1);
        let reservation = original.pop().unwrap();
        assert_eq!(reservation.range(), extent);
        assert_eq!(query(range.start).State, memory::MEM_COMMIT);
        assert_eq!(query(range.start).Protect, memory::PAGE_READWRITE);
        assert_eq!((range.start as *const u8).read(), 0x5a);
        assert_eq!(query(range.end).State, memory::MEM_RESERVE);
        for (permissions, protection) in [
            (MemoryRegionPermissions::empty(), memory::PAGE_NOACCESS),
            (MemoryRegionPermissions::READ, memory::PAGE_READONLY),
        ] {
            <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                extent.clone(),
                permissions,
                false,
            )
            .unwrap();
            for address in extent.clone().step_by(4096) {
                assert_eq!(query(address).State, memory::MEM_COMMIT);
                assert_eq!(query(address).Protect, protection);
            }
        }
        assert_eq!((range.start as *const u8).read(), 0x5a);
        assert_eq!((range.end as *const u8).read(), 0);
        <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
        )
        .unwrap();
        assert_eq!(query(range.start).State, memory::MEM_RESERVE);
        <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::READ,
            false,
        )
        .unwrap();
        assert_eq!((range.start as *const u8).read(), 0);
        <WindowsUserland as PageManagementProvider<4096>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range.clone(),
            MemoryRegionPermissions::empty(),
        )
        .unwrap();
        assert_eq!(query(range.start).State, memory::MEM_COMMIT);
        assert_eq!(query(range.start).Protect, memory::PAGE_NOACCESS);
        <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
            platform,
            || core::iter::once(&reservation),
            extent.clone(),
        )
        .unwrap();
        assert_eq!(query(range.start).State, memory::MEM_RESERVE);
        release_reservations::<4096, _>(platform, vec![reservation]);
    }
    assert_eq!(query(extent.start).State, memory::MEM_FREE);
}

#[test]
fn batched_page_operations_preserve_native_boundaries() {
    const ALIGNMENT: usize = 0x10000;
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
    let probe = reserve_backing(
        platform,
        0..4 * ALIGNMENT,
        FixedAddressBehavior::Hint,
        false,
    )
    .unwrap();
    let base = probe.range().start;
    // SAFETY: The test exclusively owns every acquired extent and ends accesses before release.
    unsafe {
        release_reservations::<4096, _>(platform, vec![probe]);
        let mut reservations = Vec::new();
        for offset in (0..4 * ALIGNMENT).step_by(ALIGNMENT) {
            let reservation = reserve_backing(
                platform,
                base + offset..base + offset + ALIGNMENT,
                FixedAddressBehavior::NoReplace,
                false,
            )
            .unwrap();
            <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                reservation.range(),
                writable,
                false,
            )
            .unwrap();
            assert_eq!(query(base + offset).AllocationBase.addr(), base + offset);
            ((base + offset) as *mut u8).write(0x5a);
            reservations.push(reservation);
        }
        let boundary = base + ALIGNMENT;
        ((boundary - 1) as *mut u8).write(0xa5);
        let protected = boundary - 4096..boundary + 4096;
        ((protected.start - 1) as *mut u8).write(0x7e);
        (protected.end as *mut u8).write(0x3c);
        for permissions in [
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ,
        ] {
            <WindowsUserland as PageManagementProvider<4096>>::protect_pages(
                platform,
                || reservations[..2].iter(),
                protected.clone(),
                permissions,
            )
            .unwrap();
        }
        assert_eq!(query(protected.start).Protect, memory::PAGE_READONLY);
        assert_eq!(query(boundary).Protect, memory::PAGE_READONLY);
        assert_eq!(query(protected.start - 1).Protect, memory::PAGE_READWRITE);
        assert_eq!(query(protected.end).Protect, memory::PAGE_READWRITE);
        assert_eq!(((boundary - 1) as *const u8).read(), 0xa5);
        assert_eq!((boundary as *const u8).read(), 0x5a);
        for _ in 0..2 {
            <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
                platform,
                || reservations[..2].iter(),
                protected.clone(),
            )
            .unwrap();
            assert_eq!(query(protected.start).State, memory::MEM_RESERVE);
            assert_eq!(query(boundary).State, memory::MEM_RESERVE);
            assert_eq!(query(protected.start).AllocationBase.addr(), base);
            assert_eq!(query(boundary).AllocationBase.addr(), boundary);
            for address in [protected.start - 1, protected.end] {
                assert_eq!(query(address).State, memory::MEM_COMMIT);
                assert_eq!(query(address).Protect, memory::PAGE_READWRITE);
            }
            assert_eq!(((protected.start - 1) as *const u8).read(), 0x7e);
            assert_eq!((protected.end as *const u8).read(), 0x3c);
        }
        for permissions in [
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ,
        ] {
            <WindowsUserland as PageManagementProvider<4096>>::commit_pages(
                platform,
                || reservations[..2].iter(),
                protected.start - 4096..protected.end + 4096,
                permissions,
                true,
            )
            .unwrap();
        }
        assert_eq!(((protected.start - 1) as *const u8).read(), 0x7e);
        assert_eq!((protected.end as *const u8).read(), 0x3c);
        assert_eq!(
            query(protected.start - 4097).Protect,
            memory::PAGE_READWRITE
        );
        assert_eq!(query(protected.end + 4096).Protect, memory::PAGE_READWRITE);
        assert!(
            core::slice::from_raw_parts(protected.start as *const u8, protected.len())
                .iter()
                .all(|&byte| byte == 0)
        );
        for (index, reservation) in reservations.iter().enumerate() {
            assert_eq!(
                reservation.range(),
                base + index * ALIGNMENT..base + (index + 1) * ALIGNMENT
            );
        }
        let retained = reservations.remove(2);
        for reservation in &reservations {
            <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
                platform,
                || core::iter::once(reservation),
                reservation.range(),
            )
            .unwrap();
        }
        let tail = reservations.pop().unwrap();
        release_reservations(platform, vec![tail]);
        release_reservations::<4096, _>(platform, reservations);
        for offset in [0, ALIGNMENT, 3 * ALIGNMENT] {
            assert_eq!(query(base + offset).State, memory::MEM_FREE);
        }
        assert_eq!(query(retained.range().start).State, memory::MEM_COMMIT);
        assert_eq!(
            query(retained.range().start).Protect,
            memory::PAGE_READWRITE
        );
        assert_eq!((retained.range().start as *const u8).read(), 0x5a);
        <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
            platform,
            || core::iter::once(&retained),
            retained.range(),
        )
        .unwrap();
        release_reservations::<4096, _>(platform, vec![retained]);
        assert_eq!(query(base + 2 * ALIGNMENT).State, memory::MEM_FREE);
    }
}

#[test]
fn program_break_changes_within_a_page() {
    use litebox::mm::{CreatePagesFlags, LinuxPageManager, NonZeroPageSize};
    let _guard = lock_vm_tests();

    let platform = WindowsUserland::new();
    let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    // SAFETY: The test owns the allocation and excludes all users while changing the break.
    unsafe {
        let pointer = manager
            .create_writable_pages(
                None,
                NonZeroPageSize::new(8192).unwrap(),
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )
            .unwrap();
        let base = pointer.as_usize();
        manager.set_initial_brk(base + 4096 + 128);
        for offset in [4096 + 128, 4096 + 64, 4096 + 128, 4096, 4096] {
            assert_eq!(manager.brk(base + offset).unwrap(), base + offset);
            assert_eq!(manager.brk(0).unwrap(), base + offset);
        }
        assert_eq!(query(base).State, memory::MEM_COMMIT);
        assert_eq!(query(base + 4096).State, memory::MEM_RESERVE);
        manager.unmap_pages(pointer, 4096).unwrap();
    }
}

#[test]
fn manager_reuses_unmapped_hole_and_releases_empty_backing() {
    use litebox::mm::{
        LinuxPageManager, WindowsPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    use litebox::platform::RawPointerProvider;
    let _guard = lock_vm_tests();

    let platform = WindowsUserland::new();
    let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    let initial_reservations = manager.reservations();
    // SAFETY: All test mappings are private and unused outside the operations below.
    unsafe {
        let original = manager
            .create_writable_pages(
                NonZeroAddress::new(0x6000_0000_0000),
                NonZeroPageSize::new(8192).unwrap(),
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )
            .unwrap();
        let address = original.as_usize();
        let native_base = query(address).AllocationBase;
        let extent = manager
            .reservations()
            .into_iter()
            .find(|range| range.contains(&address))
            .unwrap();
        manager.unmap_pages(original, 4096).unwrap();
        assert_eq!(query(address).State, memory::MEM_RESERVE);
        assert!(
            !manager
                .mappings()
                .iter()
                .any(|(range, _)| range.contains(&address))
        );
        let reused = manager
            .create_writable_pages(
                NonZeroAddress::new(address),
                NonZeroPageSize::new(4096).unwrap(),
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )
            .unwrap();
        assert_eq!(reused.as_usize(), address);
        assert_eq!(query(address).AllocationBase, native_base);
        manager.unmap_pages(reused, 4096).unwrap();
        let fixed = manager
            .create_writable_pages(
                NonZeroAddress::new(address),
                NonZeroPageSize::new(4096).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                |_| Ok(0),
            )
            .unwrap();
        assert_eq!(fixed.as_usize(), address);
        manager.unmap_pages(fixed, 8192).unwrap();
        assert_eq!(query(address).State, memory::MEM_FREE);
        assert_eq!(manager.reservations(), initial_reservations);
        assert!(
            !manager
                .mappings()
                .iter()
                .any(|(range, _)| { range.start < extent.end && extent.start < range.end })
        );
        let reused = manager
            .create_writable_pages(
                NonZeroAddress::new(address),
                NonZeroPageSize::new(4096).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                |_| Ok(0),
            )
            .unwrap();
        assert_eq!(reused.as_usize(), address);
        assert_eq!(query(address).AllocationBase, native_base);
        manager.unmap_pages(reused, 4096).unwrap();
        assert_eq!(query(address).State, memory::MEM_FREE);
        let backing_pointer =
            <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(extent.start);
        manager.unmap_pages(backing_pointer, extent.len()).unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(extent.start).State, memory::MEM_FREE);
        let explicit = WindowsPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
        manager.release_memory().unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        let manager = explicit;
        let initial_reservations = manager.reservations();
        let backing_pointer = manager
            .create_reserved_pages(
                NonZeroAddress::new(extent.start),
                NonZeroPageSize::new(extent.len()).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR,
            )
            .unwrap();
        manager
            .commit_pages(backing_pointer, 4096, MemoryRegionPermissions::READ)
            .unwrap();
        assert_eq!(query(extent.start).State, memory::MEM_COMMIT);
        let middle = <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
            extent.start + 4096,
        );
        manager.remove_pages(middle, 4096).unwrap();
        assert_eq!(query(extent.start).State, memory::MEM_COMMIT);
        assert_eq!(query(extent.start + 4096).State, memory::MEM_FREE);
        assert_eq!(query(extent.start + 8192).State, memory::MEM_RESERVE);
        assert_eq!(
            manager
                .reservations()
                .into_iter()
                .filter(|range| !initial_reservations.contains(range))
                .collect::<Vec<_>>(),
            vec![
                extent.start..extent.start + 4096,
                extent.start + 8192..extent.end
            ]
        );
        assert!(manager.remove_pages(backing_pointer, extent.len()).is_err());
        assert_eq!(query(extent.start).State, memory::MEM_COMMIT);
        manager.remove_pages(backing_pointer, 4096).unwrap();
        let suffix = <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
            extent.start + 8192,
        );
        manager.remove_pages(suffix, extent.len() - 8192).unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(address).State, memory::MEM_FREE);
        let reserved = manager
            .create_reserved_pages(
                NonZeroAddress::new(extent.start),
                NonZeroPageSize::new(extent.len()).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            )
            .unwrap();
        assert_eq!(reserved.as_usize(), extent.start);
        manager.remove_pages(reserved, extent.len()).unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(extent.start).State, memory::MEM_FREE);
    }
}

#[test]
fn manager_commit_decommit_and_protect_preserve_ownership() {
    use litebox::mm::{
        WindowsPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let manager = WindowsPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    let initial_mappings = manager.mappings();
    let initial_reservations = manager.reservations();
    assert!(initial_mappings.is_empty());
    assert!(initial_reservations.is_empty());
    // SAFETY: The test owns these pages; all accesses are within committed writable/readable states.
    unsafe {
        let pointer = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(8192).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        let address = pointer.as_usize();
        assert_eq!(manager.mappings(), initial_mappings);
        assert!(manager.reservations().contains(&(address..address + 8192)));
        let owned_reservations = manager.reservations();
        assert_eq!(owned_reservations.len(), initial_reservations.len() + 1);
        assert!(
            manager
                .create_reserved_pages(
                    NonZeroAddress::new(address),
                    NonZeroPageSize::new(4096).unwrap(),
                    RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                )
                .is_err()
        );
        assert!(manager.make_pages_readable(pointer, 4096).is_err());
        manager
            .commit_pages(
                pointer,
                4096,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
        (address as *mut u8).write(0x5a);
        manager
            .commit_pages(
                pointer,
                4096,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
        assert_eq!((address as *const u8).read(), 0x5a);
        manager.make_pages_inaccessible(pointer, 4096).unwrap();
        assert!(
            manager
                .mappings()
                .iter()
                .any(|(mapped, _)| mapped == &(address..address + 4096))
        );
        assert_eq!(query(address).State, memory::MEM_COMMIT);
        assert_eq!(query(address).Protect, memory::PAGE_NOACCESS);
        manager.make_pages_readable(pointer, 4096).unwrap();
        assert_eq!((address as *const u8).read(), 0x5a);
        manager.decommit_pages(pointer, 8192).unwrap();
        assert_eq!(query(address).State, memory::MEM_RESERVE);
        assert_eq!(manager.mappings(), initial_mappings);
        assert_eq!(manager.reservations(), owned_reservations);
        manager
            .commit_pages(pointer, 8192, MemoryRegionPermissions::READ)
            .unwrap();
        assert_eq!((address as *const u8).read(), 0);
        assert_eq!(((address + 8191) as *const u8).read(), 0);
        manager.decommit_pages(pointer, 8192).unwrap();
        assert_eq!(query(address).State, memory::MEM_RESERVE);
        assert_eq!(manager.mappings(), initial_mappings);
        assert_eq!(manager.reservations(), owned_reservations);
        manager.remove_pages(pointer, 8192).unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(address).State, memory::MEM_FREE);
    }
}

#[test]
fn manager_split_release_and_bulk_cleanup_match_native_extents() {
    use litebox::mm::{
        WindowsPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    use litebox::platform::RawPointerProvider;
    let _guard = lock_vm_tests();

    let platform = WindowsUserland::new();
    let manager = WindowsPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    let initial_mappings = manager.mappings();
    let initial_reservations = manager.reservations();
    // SAFETY: All reservations are private to this test, and released pages have no remaining users.
    unsafe {
        let original = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(3 * 4096).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        let base = original.as_usize();
        assert_eq!(query(base).RegionSize, 3 * 4096);
        manager
            .commit_pages(
                original,
                3 * 4096,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
        (base as *mut u8).write(0x5a);
        ((base + 8192) as *mut u8).write(0xa5);
        let middle =
            <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(base + 4096);
        manager.remove_pages(middle, 4096).unwrap();
        assert_eq!(query(base + 4096).State, memory::MEM_FREE);
        assert_eq!(
            manager
                .reservations()
                .into_iter()
                .filter(|range| !initial_reservations.contains(range))
                .collect::<Vec<_>>(),
            vec![base..base + 4096, base + 8192..base + 12288]
        );
        assert_eq!(query(base).RegionSize, 4096);
        assert_eq!(query(base + 8192).AllocationBase.addr(), base + 8192);
        assert_eq!((base as *const u8).read(), 0x5a);
        assert_eq!(((base + 8192) as *const u8).read(), 0xa5);
        let suffix =
            <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(base + 8192);
        manager.make_pages_readable(suffix, 4096).unwrap();
        manager.decommit_pages(original, 4096).unwrap();
        assert!(manager.make_pages_readable(original, 4096).is_err());
        assert!(
            manager
                .create_reserved_pages(
                    NonZeroAddress::new(base + 4096),
                    NonZeroPageSize::new(4096).unwrap(),
                    RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                )
                .is_err()
        );
        let stack = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(4096).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        manager
            .commit_pages(
                stack,
                4096,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
        let read_only = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(0x10000).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        manager
            .commit_pages(read_only, 0x10000, MemoryRegionPermissions::READ)
            .unwrap();
        let retained = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(3 * 4096).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        let retained_base = retained.as_usize();
        let no_access = <WindowsUserland as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
            retained_base + 8192,
        );
        for pointer in [retained, no_access] {
            manager
                .commit_pages(
                    pointer,
                    4096,
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                )
                .unwrap();
        }
        ((retained_base + 8192) as *mut u8).write(0x3c);
        manager.make_pages_inaccessible(no_access, 4096).unwrap();
        let empty = manager
            .create_reserved_pages(
                None,
                NonZeroPageSize::new(4096).unwrap(),
                RESERVATION_ALIGNMENT,
                CreatePagesFlags::empty(),
            )
            .unwrap();
        manager.release_memory().unwrap();
        assert_eq!(manager.mappings(), initial_mappings);
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(query(empty.as_usize()).State, memory::MEM_FREE);
        assert_eq!(query(base).State, memory::MEM_FREE);
        assert_eq!(query(base + 8192).State, memory::MEM_FREE);
        assert_eq!(query(stack.as_usize()).State, memory::MEM_FREE);
        assert_eq!(query(read_only.as_usize()).State, memory::MEM_FREE);
        assert_eq!(query(retained_base).State, memory::MEM_FREE);
        assert_eq!(query(retained_base + 8192).State, memory::MEM_FREE);
    }
}

#[test]
fn manager_remap_keeps_backing_and_page_state_consistent() {
    use litebox::mm::{
        LinuxPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    let _guard = lock_vm_tests();
    for permissions in [
        None,
        Some(MemoryRegionPermissions::empty()),
        Some(MemoryRegionPermissions::READ),
    ] {
        let platform = WindowsUserland::new();
        let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        // SAFETY: This test has exclusive access to each mapping and stops using old addresses after remap.
        unsafe {
            let original = manager
                .create_writable_pages(
                    NonZeroAddress::new(0x6000_0000_0000),
                    NonZeroPageSize::new(8192).unwrap(),
                    CreatePagesFlags::empty(),
                    |pointer| {
                        (pointer.as_usize() as *mut u8).write(0x5a);
                        Ok(0)
                    },
                )
                .unwrap();
            let address = original.as_usize();
            match permissions {
                None => {
                    manager.unmap_pages(original, 8192).unwrap();
                    let mappings = manager.mappings();
                    let reservations = manager.reservations();
                    for new_size in [4096, 8192, 3 * 4096] {
                        for may_move in [false, true] {
                            assert!(matches!(
                                manager.remap_pages(original, 8192, new_size, may_move),
                                Err(litebox::platform::page_mgmt::RemapError::AlreadyUnallocated)
                            ));
                            assert_eq!(manager.mappings(), mappings);
                            assert_eq!(manager.reservations(), reservations);
                            assert_eq!(query(address).State, memory::MEM_FREE);
                        }
                    }
                    manager.release_memory().unwrap();
                    assert_eq!(manager.mappings(), initial_mappings);
                    assert_eq!(manager.reservations(), initial_reservations);
                    assert_eq!(query(address).State, memory::MEM_FREE);
                    continue;
                }
                Some(permissions) if permissions.is_empty() => {
                    manager.make_pages_inaccessible(original, 4096).unwrap();
                }
                Some(_) => manager.make_pages_readable(original, 4096).unwrap(),
            }
            let moved = manager.remap_pages(original, 4096, 3 * 4096, true).unwrap();
            assert_ne!(moved.as_usize(), address);
            let information = query(moved.as_usize());
            assert_eq!(information.State, memory::MEM_COMMIT);
            let tail = moved.as_usize() + 2 * 4096..moved.as_usize() + 3 * 4096;
            let following_state = query(tail.end).State;
            let reservations = manager.reservations();
            let shrunk = manager
                .remap_pages(moved, 3 * 4096, 2 * 4096, false)
                .unwrap();
            assert_eq!(shrunk.as_usize(), moved.as_usize());
            assert_eq!(query(tail.start).State, memory::MEM_RESERVE);
            assert_eq!(query(tail.end).State, following_state);
            assert_eq!(query(shrunk.as_usize()).State, memory::MEM_COMMIT);
            assert_eq!(query(shrunk.as_usize()).Protect, information.Protect);
            assert_eq!(manager.reservations(), reservations);
            assert!(
                !manager
                    .mappings()
                    .iter()
                    .any(|(range, _)| { range.contains(&(moved.as_usize() + 2 * 4096)) })
            );
            manager.make_pages_readable(moved, 2 * 4096).unwrap();
            assert_eq!((moved.as_usize() as *const u8).read(), 0x5a);
            assert_eq!(((moved.as_usize() + 2 * 4096 - 1) as *const u8).read(), 0);
            manager.unmap_pages(moved, 2 * 4096).unwrap();
            manager.unmap_pages(original, 8192).unwrap();
            assert_eq!(query(address).State, memory::MEM_FREE);
            assert_eq!(manager.mappings(), initial_mappings);
            manager.release_memory().unwrap();
            assert_eq!(manager.reservations(), initial_reservations);
            assert_eq!(manager.mappings(), initial_mappings);
            assert_eq!(query(address).State, memory::MEM_FREE);
        }
    }
}

#[test]
fn manager_handles_native_boundaries_and_guest_replacement() {
    use litebox::mm::{
        LinuxPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    const GRANULARITY: usize = 0x10000;
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let probe = reserve_backing(
        platform,
        0x6000_0000_0000..0x6000_0000_0000 + 3 * GRANULARITY,
        FixedAddressBehavior::Hint,
        false,
    )
    .unwrap();
    let base = probe.range().start;
    // SAFETY: The probe has no users; later fixed requests must independently reacquire ownership.
    unsafe {
        release_reservations::<4096, _>(platform, vec![probe]);
    };
    let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    // SAFETY: The test exclusively owns every acquired mapping and stops accessing it before removal.
    unsafe {
        for address in [base, base + 2 * GRANULARITY] {
            manager
                .create_inaccessible_pages(
                    NonZeroAddress::new(address),
                    NonZeroPageSize::new(if address == base { GRANULARITY } else { 4096 }).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap();
        }
        let length = 2 * GRANULARITY + 4096;
        let pointer = manager
            .create_writable_pages(
                NonZeroAddress::new(base),
                NonZeroPageSize::new(length).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                |_| Ok(0),
            )
            .unwrap();
        assert_eq!(pointer.as_usize(), base);
        for offset in [0, GRANULARITY, 2 * GRANULARITY] {
            ((base + offset) as *mut u8).write(0x5a);
            assert_eq!(query(base + offset).AllocationBase.addr(), base + offset);
        }
        let middle = <WindowsUserland as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(base + GRANULARITY);
        manager.make_pages_readable(middle, GRANULARITY).unwrap();
        let hole = <WindowsUserland as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(base + GRANULARITY + 4096);
        manager.unmap_pages(hole, 4096).unwrap();
        let reservations = manager.reservations();
        manager
            .create_readable_pages(
                NonZeroAddress::new(base + 4096),
                NonZeroPageSize::new(2 * GRANULARITY - 4096).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                |_| Ok(0),
            )
            .unwrap();
        for offset in [
            4096,
            GRANULARITY,
            GRANULARITY + 4096,
            2 * GRANULARITY - 4096,
        ] {
            assert_eq!(query(base + offset).State, memory::MEM_COMMIT);
            assert_eq!(query(base + offset).Protect, memory::PAGE_READONLY);
            assert_eq!(((base + offset) as *const u8).read(), 0);
        }
        for offset in [0, 2 * GRANULARITY] {
            assert_eq!(query(base + offset).Protect, memory::PAGE_READWRITE);
            assert_eq!(((base + offset) as *const u8).read(), 0x5a);
        }
        assert_eq!(manager.reservations(), reservations);
        manager.make_pages_readable(pointer, length).unwrap();
        for (offset, expected) in [(0, 0x5a), (GRANULARITY, 0), (2 * GRANULARITY, 0x5a)] {
            assert_eq!(query(base + offset).Protect, memory::PAGE_READONLY);
            assert_eq!(((base + offset) as *const u8).read(), expected);
        }
        manager
            .create_readable_pages(
                NonZeroAddress::new(base),
                NonZeroPageSize::new(length).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                |_| Ok(0),
            )
            .unwrap();
        for offset in [0, GRANULARITY, 2 * GRANULARITY] {
            assert_eq!(((base + offset) as *const u8).read(), 0);
        }
        manager.unmap_pages(pointer, length).unwrap();
        assert!(manager.make_pages_readable(pointer, length).is_err());
        for offset in [0, GRANULARITY, 2 * GRANULARITY] {
            assert_eq!(query(base + offset).State, memory::MEM_FREE);
            manager
                .create_readable_pages(
                    NonZeroAddress::new(base + offset),
                    NonZeroPageSize::new((length - offset).min(GRANULARITY)).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap();
        }
        manager.unmap_pages(middle, GRANULARITY).unwrap();
        manager.release_memory().unwrap();
        assert_eq!(query(base + GRANULARITY).State, memory::MEM_FREE);
        for offset in [0, GRANULARITY, 2 * GRANULARITY] {
            assert_eq!(query(base + offset).State, memory::MEM_FREE);
        }
    }
}

#[test]
fn manager_rejects_foreign_backing_without_changing_existing_mapping() {
    use litebox::mm::{
        LinuxPageManager, WindowsPageManager,
        linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
    };
    const GRANULARITY: usize = 0x10000;
    let _guard = lock_vm_tests();
    let platform = WindowsUserland::new();
    let probe = reserve_backing(
        platform,
        0x6100_0000_0000..0x6100_0000_0000 + 3 * GRANULARITY,
        FixedAddressBehavior::Hint,
        false,
    )
    .unwrap();
    let base = probe.range().start;
    // SAFETY: The probe has no users; later acquisitions must independently establish ownership.
    unsafe {
        release_reservations::<4096, _>(platform, vec![probe]);
    };
    let manager = LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
    // SAFETY: This test acquires and exclusively owns a foreign native allocation after the manager snapshot.
    let foreign = unsafe {
        memory::VirtualAlloc(
            (base + 2 * GRANULARITY) as *const _,
            GRANULARITY,
            memory::MEM_RESERVE | memory::MEM_COMMIT,
            memory::PAGE_READWRITE,
        )
    };
    assert_eq!(foreign.addr(), base + 2 * GRANULARITY);
    let _cleanup = litebox::utils::defer(|| {
        // SAFETY: All guest operations have finished and this test owns the entire foreign extent.
        assert_ne!(
            unsafe { memory::VirtualFree(foreign, 0, memory::MEM_RELEASE) },
            0
        );
    });
    // SAFETY: The test owns both allocations and performs no accesses after their release.
    unsafe {
        foreign.cast::<u8>().write(0xa5);
        manager
            .create_writable_pages(
                NonZeroAddress::new(base),
                NonZeroPageSize::new(4096).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                |pointer| {
                    (pointer.as_usize() as *mut u8).write(0x5a);
                    Ok(0)
                },
            )
            .unwrap();
        let before = manager.mappings();
        assert!(
            manager
                .create_writable_pages(
                    NonZeroAddress::new(base),
                    NonZeroPageSize::new(2 * GRANULARITY + 4096).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    |_| Ok(0)
                )
                .is_err()
        );
        assert_eq!(manager.mappings(), before);
        assert_eq!((base as *const u8).read(), 0x5a);
        assert_eq!(foreign.cast::<u8>().read(), 0xa5);
        assert_eq!(query(base + GRANULARITY).State, memory::MEM_FREE);
        let explicit = WindowsPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
        assert!(
            explicit
                .create_reserved_pages(
                    NonZeroAddress::new(foreign.addr()),
                    NonZeroPageSize::new(4096).unwrap(),
                    RESERVATION_ALIGNMENT,
                    CreatePagesFlags::empty(),
                )
                .is_err()
        );
        manager.release_memory().unwrap();
        assert_eq!(foreign.cast::<u8>().read(), 0xa5);
    }
}
