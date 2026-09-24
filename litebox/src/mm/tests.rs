// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::Range;

extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    mm::linux::{self, CreatePagesFlags, NonZeroAddress},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{
            AllocationError, FixedAddressBehavior, MemoryRegionPermissions, NoReservations,
            PageReservation as PageReservationTrait, ReservationStore, TrackedReservations,
        },
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    },
};
use zerocopy::{FromBytes, IntoBytes};

use super::vmem::{
    FindAreaRequest, NonZeroPageSize, PAGE_SIZE, PageRange, VmArea, VmFlags, Vmem,
    VmemProtectError, VmemResizeError,
};
use super::{Linux, Windows};

#[derive(Debug)]
pub(super) struct PageReservation<const ALIGN: usize> {
    range: Range<usize>,
}

impl<const ALIGN: usize> PageReservation<ALIGN> {
    unsafe fn new(range: Range<usize>) -> Self {
        assert!(!range.is_empty());
        assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
        Self { range }
    }
}

unsafe impl<const ALIGN: usize> PageReservationTrait for PageReservation<ALIGN> {
    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn split(self, range: Range<usize>) -> (Option<Self>, Self, Option<Self>) {
        let extent = self.range;
        assert!(extent.start <= range.start && range.end <= extent.end && !range.is_empty());
        assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
        (
            (extent.start < range.start).then_some(Self {
                range: extent.start..range.start,
            }),
            Self {
                range: range.clone(),
            },
            (range.end < extent.end).then_some(Self {
                range: range.end..extent.end,
            }),
        )
    }
}

impl<const ALIGN: usize> From<PageReservation<ALIGN>> for Range<usize> {
    fn from(reservation: PageReservation<ALIGN>) -> Self {
        reservation.range
    }
}

trait TestReservationFactory<const ALIGN: usize> {
    unsafe fn create_reservation(&self, range: Range<usize>) -> PageReservation<ALIGN> {
        // SAFETY: Test callers establish synthetic exclusive ownership.
        unsafe { PageReservation::new(range) }
    }
}

impl<T, const ALIGN: usize> TestReservationFactory<ALIGN> for T {}

impl<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize, Style>
    Vmem<Platform, ALIGN, Style>
where
    Platform::Reservations: ReservationStore<Reservation = PageReservation<ALIGN>>,
    Style: super::PageManagerStyleFor<Platform, ALIGN>,
{
    unsafe fn register_committed_mapping(&mut self, range: PageRange<ALIGN>, vma: VmArea) {
        let range: Range<usize> = range.into();
        let mut cursor = range.start;
        let mut gaps = Vec::new();
        for (_, reservation) in self.reservations.overlapping(range.clone()) {
            let extent = reservation.range();
            if cursor < extent.start {
                gaps.push(cursor..extent.start);
            }
            cursor = extent.end.min(range.end);
        }
        if cursor < range.end {
            gaps.push(cursor..range.end);
        }
        for extent in gaps {
            // SAFETY: The fixture transfers raw ownership outside existing handles without changing pages.
            let backing = unsafe { self.platform.create_reservation(extent.clone()) };
            assert_eq!(backing.range(), extent);
            self.reservations.insert(extent.start, backing);
        }
        DUMMY_MEMORY.with_borrow_mut(|memory| {
            if let Some(memory) = memory {
                memory.committed.extend(
                    (range.start.max(memory.extent.start)..range.end.min(memory.extent.end))
                        .step_by(PAGE_SIZE),
                );
            }
        });
        self.vmas.insert(range, vma);
    }
}

/// A dummy implementation of [`VmemBackend`] that does nothing.
struct MockVmemBackend<
    const COMMIT: bool,
    const RESERVATION_ALIGN: usize = PAGE_SIZE,
    Reservations = TrackedReservations<PageReservation<PAGE_SIZE>>,
> {
    external: &'static [Range<usize>],
    reservations: core::marker::PhantomData<Reservations>,
}

type DummyVmemBackend = MockVmemBackend<true>;

impl<const COMMIT: bool, const RESERVATION_ALIGN: usize, Reservations>
    MockVmemBackend<COMMIT, RESERVATION_ALIGN, Reservations>
{
    const EMPTY: Self = Self {
        external: &[],
        reservations: core::marker::PhantomData,
    };

    fn assert_guest_range(&self, range: &Range<usize>) {
        assert!(
            self.external
                .iter()
                .all(|external| { range.end <= external.start || external.end <= range.start })
        );
    }
}

std::thread_local! {
    static DUMMY_FAIL_RESERVE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static DUMMY_FAIL_COMMIT_AT: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
    static DUMMY_PROTECTIONS: core::cell::RefCell<Vec<(Range<usize>, MemoryRegionPermissions)>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_RESERVE_INPUTS: core::cell::RefCell<Vec<Vec<Range<usize>>>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_RESERVES: core::cell::RefCell<Vec<(Range<usize>, bool)>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_COMMITS: core::cell::RefCell<Vec<Range<usize>>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_STATES: core::cell::RefCell<Vec<(MemoryRegionPermissions, bool, crate::platform::page_mgmt::FixedAddressBehavior)>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_RELEASES: core::cell::RefCell<Vec<Range<usize>>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_RANGE_RELEASES: core::cell::RefCell<Vec<Range<usize>>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_DECOMMITS: core::cell::RefCell<Vec<Range<usize>>> = const { core::cell::RefCell::new(Vec::new()) };
    static DUMMY_MEMORY: core::cell::RefCell<Option<MockMemory>> = const { core::cell::RefCell::new(None) };
}

struct MockMemory {
    extent: Range<usize>,
    committed: alloc::collections::BTreeSet<usize>,
}

struct MockMemoryGuard;

impl MockMemoryGuard {
    /// Track real mock backing, initially uncommitted.
    ///
    /// # Safety
    /// The aligned extent must remain allocated and exclusively accessible on this thread until
    /// the guard is dropped. Synthetic operations outside this extent never access native memory.
    unsafe fn new(extent: Range<usize>) -> Self {
        assert!(PageRange::<PAGE_SIZE>::new(extent.start, extent.end).is_some());
        DUMMY_MEMORY.with_borrow_mut(|memory| {
            assert!(memory.is_none());
            *memory = Some(MockMemory {
                extent,
                committed: alloc::collections::BTreeSet::new(),
            });
        });
        Self
    }
}

impl Drop for MockMemoryGuard {
    fn drop(&mut self) {
        DUMMY_MEMORY.with_borrow_mut(|memory| *memory = None);
    }
}

trait TestReservationStore: ReservationStore {
    unsafe fn new_reservation(range: Range<usize>) -> Self::Reservation;
    fn target_range(target: &Self::ReleaseTarget) -> Range<usize>;
    fn record_release(target: &Self::ReleaseTarget);
}

impl TestReservationStore for TrackedReservations<PageReservation<PAGE_SIZE>> {
    unsafe fn new_reservation(range: Range<usize>) -> Self::Reservation {
        // SAFETY: The caller establishes synthetic exclusive ownership.
        unsafe { PageReservation::new(range) }
    }

    fn target_range(target: &Self::ReleaseTarget) -> Range<usize> {
        target.range()
    }

    fn record_release(target: &Self::ReleaseTarget) {
        DUMMY_RELEASES.with_borrow_mut(|releases| releases.push(target.range()));
    }
}

impl TestReservationStore for NoReservations<PAGE_SIZE> {
    unsafe fn new_reservation(range: Range<usize>) -> Self::Reservation {
        // SAFETY: The caller establishes synthetic exclusive ownership.
        unsafe { NoReservations::from_owned_range(range) }
    }

    fn target_range(target: &Self::ReleaseTarget) -> Range<usize> {
        target.clone()
    }

    fn record_release(_: &Self::ReleaseTarget) {}
}

impl MockMemory {
    fn commit(range: &Range<usize>) {
        DUMMY_MEMORY.with_borrow_mut(|memory| {
            if let Some(memory) = memory {
                for page in (range.start.max(memory.extent.start)..range.end.min(memory.extent.end))
                    .step_by(PAGE_SIZE)
                {
                    if memory.committed.insert(page) {
                        // SAFETY: The guard limits writes to exclusively held live fixture storage.
                        unsafe {
                            core::ptr::with_exposed_provenance_mut::<u8>(page)
                                .write_bytes(0, PAGE_SIZE);
                        };
                    }
                }
            }
        });
    }

    fn decommit(range: &Range<usize>) {
        DUMMY_MEMORY.with_borrow_mut(|memory| {
            if let Some(memory) = memory {
                memory.committed.retain(|page| !range.contains(page));
            }
        });
    }
}

impl<const COMMIT: bool, const RESERVATION_ALIGN: usize, Store> crate::platform::RawPointerProvider
    for MockVmemBackend<COMMIT, RESERVATION_ALIGN, Store>
{
    type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
}

#[expect(unused_variables, reason = "dummy/mock backend")]
impl<const COMMIT: bool, const RESERVATION_ALIGN: usize, Store>
    crate::platform::PageManagementProvider<PAGE_SIZE>
    for MockVmemBackend<COMMIT, RESERVATION_ALIGN, Store>
where
    Store: TestReservationStore,
{
    type Reservations = Store;

    const RESERVATION_ALIGNMENT: usize = RESERVATION_ALIGN;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux/windows config
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000; // 48-bit VA space
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    const TASK_ADDR_MIN: usize = 0x1_0000; // Vmem unit-test bound
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FE00_0000; // MACH_VM_MAX_ADDRESS
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;

    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        can_grow_down: bool,
        behavior: crate::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Store::Reservation, AllocationError>
    where
        Reservations: Iterator<Item = Store::Reservation>,
    {
        if DUMMY_FAIL_RESERVE.get() {
            return Err(AllocationError::OutOfMemory);
        }
        if self
            .external
            .iter()
            .any(|external| range.start < external.end && external.start < range.end)
        {
            return Err(AllocationError::AddressInUse);
        }
        let replaced_reservations: Vec<_> =
            if behavior == crate::platform::page_mgmt::FixedAddressBehavior::Replace {
                replaced_reservations().collect()
            } else {
                Vec::new()
            };
        DUMMY_RESERVE_INPUTS.with_borrow_mut(|inputs| {
            inputs.push(
                replaced_reservations
                    .iter()
                    .map(<Store::Reservation as crate::platform::page_mgmt::PageReservation>::range)
                    .collect(),
            );
        });
        self.assert_guest_range(&range);
        DUMMY_RESERVES.with_borrow_mut(|reserves| reserves.push((range.clone(), can_grow_down)));
        DUMMY_STATES.with_borrow_mut(|states| {
            states.push((MemoryRegionPermissions::empty(), false, behavior));
        });
        for reservation in replaced_reservations {
            let extent = reservation.range();
            assert!(range.start <= extent.start && extent.end <= range.end);
            MockMemory::decommit(&extent);
        }
        // SAFETY: The mock acquired the synthetic extent and consumed overlapping ownership.
        Ok(unsafe { Store::new_reservation(range) })
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate: bool,
        behavior: crate::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Store::Reservation, crate::platform::page_mgmt::ReserveAndCommitError>
    where
        Reservations: Iterator<Item = Store::Reservation>,
    {
        if COMMIT {
            return Err(crate::platform::page_mgmt::ReserveAndCommitError::UnsupportedByPlatform);
        }
        // SAFETY: This fixture acquires synthetic ownership with the caller's replacement authorization.
        let reservation =
            unsafe { self.reserve_pages(replaced_reservations, range, can_grow_down, behavior) }?;
        DUMMY_STATES.with_borrow_mut(|states| {
            *states.last_mut().unwrap() = (permissions, populate, behavior);
        });
        MockMemory::commit(&reservation.range());
        Ok(reservation)
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), crate::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation Store::Reservation>,
    {
        self.assert_guest_range(&range);
        if DUMMY_FAIL_COMMIT_AT.get() == Some(range.start) {
            return Err(crate::platform::page_mgmt::PageStateUpdateError::OutOfMemory);
        }
        MockMemory::commit(&range);
        DUMMY_COMMITS.with_borrow_mut(|commits| commits.push(range));
        Ok(())
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), crate::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation Store::Reservation>,
    {
        self.assert_guest_range(&range);
        DUMMY_PROTECTIONS.with_borrow_mut(|protections| protections.push((range, permissions)));
        Ok(())
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _: impl FnOnce() -> Reservations,
        range: Range<usize>,
    ) -> Result<(), crate::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation Store::Reservation>,
    {
        self.assert_guest_range(&range);
        MockMemory::decommit(&range);
        DUMMY_DECOMMITS.with_borrow_mut(|decommits| decommits.push(range));
        Ok(())
    }

    unsafe fn release_pages(&self, target: Store::ReleaseTarget) {
        let range = Store::target_range(&target);
        self.assert_guest_range(&range);
        MockMemory::decommit(&range);
        DUMMY_RANGE_RELEASES.with_borrow_mut(|ranges| ranges.push(range));
        Store::record_release(&target);
    }
}

fn collect_mappings<Style>(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE, Style>) -> Vec<Range<usize>>
where
    Style: super::PageManagerStyleFor<DummyVmemBackend, PAGE_SIZE>,
{
    let owned: rangemap::RangeMap<usize, ()> =
        vmm.reservations().map(|range| (range, ())).collect();
    for (range, _) in vmm.iter() {
        assert!(owned.gaps(range).next().is_none());
    }
    vmm.iter().map(|v| v.0.start..v.0.end).collect()
}

#[test]
fn test_automatic_mapping_rounds_backing_not_commitment() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let base = 0x10000;
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    // SAFETY: These exclusively owned synthetic mappings are never dereferenced.
    unsafe {
        vmem.create_mapping(
            NonZeroAddress::new(base + PAGE_SIZE),
            page,
            vma,
            CreatePagesFlags::FIXED_ADDR,
        )
        .unwrap();
        assert_eq!(
            vmem.reservations().next().unwrap(),
            base + PAGE_SIZE..base + 2 * PAGE_SIZE
        );
        assert_eq!(
            collect_mappings(&vmem),
            core::slice::from_ref(&(base + PAGE_SIZE..base + 2 * PAGE_SIZE))
        );
        vmem.unmap_mapping(PageRange::new(base + PAGE_SIZE, base + 2 * PAGE_SIZE).unwrap());
        vmem.create_mapping(
            NonZeroAddress::new(base + 0xf000),
            NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
            vma,
            CreatePagesFlags::FIXED_ADDR,
        )
        .unwrap();
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![base + 0xf000..base + 0x11000]
        );
        assert_eq!(
            collect_mappings(&vmem),
            core::slice::from_ref(&(base + 0xf000..base + 0x11000))
        );
        vmem.unmap_mapping(PageRange::new(base + 0xf000, base + 0x11000).unwrap());
        assert!(vmem.iter().next().is_none());
        assert_eq!(vmem.reservations().count(), 0);
        let mut explicit = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
        explicit
            .create_private_pages(
                NonZeroAddress::new(base + 0x30000),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                page,
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap();
        assert_eq!(
            explicit.reservations().last().unwrap(),
            base + 0x30000..base + 0x30000 + PAGE_SIZE
        );
        explicit
            .remove_mapping(PageRange::new(base + 0x30000, base + 0x30000 + PAGE_SIZE).unwrap())
            .unwrap();
        vmem.release_memory();
    }
    assert!(vmem.reservations().next().is_none());
}

#[test]
fn test_unmap_releases_empty_backing_on_page_aligned_hosts() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let base = 0x10000;
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    let range = PageRange::new(base, base + PAGE_SIZE).unwrap();
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    // SAFETY: The test exclusively owns synthetic ranges that are never dereferenced.
    unsafe {
        vmem.create_mapping(
            NonZeroAddress::new(base),
            page,
            vma,
            CreatePagesFlags::FIXED_ADDR,
        )
        .unwrap();
        let reservations = vmem.reservations().collect::<Vec<_>>();
        vmem.unmap_mapping(range);
        assert!(vmem.iter().next().is_none());
        assert!(vmem.reservations().next().is_none());
        vmem.create_mapping(
            NonZeroAddress::new(base),
            page,
            vma,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
        )
        .unwrap();
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        assert_eq!(vmem.iter().next().unwrap().0, &(base..base + PAGE_SIZE));
        vmem.release_memory();
    }
    assert!(vmem.reservations().next().is_none());
}

#[test]
fn test_handle_free_reservations_remain_untracked() {
    type ManagedBackend = MockVmemBackend<false, PAGE_SIZE, NoReservations<PAGE_SIZE>>;

    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&ManagedBackend::EMPTY);
    let first = 0x10000..0x12000;
    let second = 0x14000..0x15000;
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    DUMMY_RANGE_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
    unsafe {
        for range in [first.clone(), second.clone()] {
            vmem.create_mapping(
                NonZeroAddress::new(range.start),
                NonZeroPageSize::new(range.len()).unwrap(),
                vma,
                CreatePagesFlags::FIXED_ADDR,
            )
            .unwrap();
        }
        assert!(vmem.reservations.is_empty());
        assert!(vmem.reservations().next().is_none());
        assert_eq!(
            vmem.iter()
                .map(|(range, _)| range.clone())
                .collect::<Vec<_>>(),
            [first.clone(), second.clone()]
        );

        vmem.unmap_mapping(PageRange::new(first.start, first.end).unwrap());
        assert!(vmem.reservations.is_empty());
        assert!(vmem.reservations().next().is_none());
        assert_eq!(
            vmem.iter()
                .map(|(range, _)| range.clone())
                .collect::<Vec<_>>(),
            core::slice::from_ref(&second)
        );

        vmem.release_memory();
    }
    assert!(vmem.reservations.is_empty());
    assert!(vmem.vmas.is_empty());
    assert_eq!(
        DUMMY_RANGE_RELEASES.with_borrow(Clone::clone),
        [first, second]
    );
    assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
}

#[test]
fn test_unmap_preserves_token_boundaries_across_vma_merges() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    // SAFETY: The test exclusively owns synthetic ranges that are never dereferenced.
    unsafe {
        for range in [
            0x10000..0x13000,
            0x13000..0x14000,
            0x16000..0x18000,
            0x18000..0x19000,
            0x1b000..0x1c000,
        ] {
            vmem.create_mapping(
                NonZeroAddress::new(range.start),
                NonZeroPageSize::new(range.len()).unwrap(),
                vma,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            )
            .unwrap();
        }
        assert_eq!(vmem.reservations.len(), 5);
        assert_eq!(vmem.iter().count(), 3);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        vmem.unmap_mapping(PageRange::new(0x11000, 0x18000).unwrap());
        assert_eq!(
            collect_mappings(&vmem),
            vec![0x10000..0x11000, 0x18000..0x19000, 0x1b000..0x1c000]
        );
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![0x10000..0x13000, 0x18000..0x19000, 0x1b000..0x1c000]
        );
        vmem.unmap_mapping(PageRange::new(0x11000, 0x18000).unwrap());
        assert_eq!(
            DUMMY_RELEASES.with_borrow(Clone::clone),
            vec![0x13000..0x14000, 0x16000..0x18000]
        );
        assert_eq!(
            DUMMY_DECOMMITS.with_borrow(Clone::clone),
            vec![0x11000..0x13000, 0x11000..0x13000]
        );
        vmem.release_memory();
    }
}

#[test]
fn test_windows_style_tracks_handle_free_linux_provider_reservations() {
    type ManagedBackend = MockVmemBackend<false, PAGE_SIZE, NoReservations<PAGE_SIZE>>;

    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&ManagedBackend::EMPTY);
    let range = 0x10000..0x12000;
    DUMMY_RANGE_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    // SAFETY: The synthetic reservation has no users and is released before the test returns.
    unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(range.start),
            ManagedBackend::TASK_ADDR_MIN..ManagedBackend::TASK_ADDR_MAX,
            NonZeroPageSize::new(range.len()).unwrap(),
            PAGE_SIZE,
            CreatePagesFlags::FIXED_ADDR,
            None,
        )
        .unwrap();
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), vec![range.clone()]);
        ManagedBackend::EMPTY
            .decommit_pages(
                || core::iter::once(&vmem.reservations[&range.start]),
                range.clone(),
            )
            .unwrap();
        vmem.vmas.remove(range.clone());
        assert!(vmem.iter().next().is_none());
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), vec![range.clone()]);
        vmem.release_memory();
    }
    assert_eq!(
        DUMMY_RANGE_RELEASES.with_borrow(Clone::clone),
        core::slice::from_ref(&range)
    );
    assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
}

#[test]
fn test_handle_free_remap_without_destination_reports_out_of_memory() {
    type ManagedBackend = MockVmemBackend<false, PAGE_SIZE, NoReservations<PAGE_SIZE>>;

    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&ManagedBackend::EMPTY);
    let source = PageRange::new(0x10000, 0x11000).unwrap();
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    vmem.vmas.insert(
        source.end..ManagedBackend::TASK_ADDR_MAX,
        VmArea::new(VmFlags::empty(), false),
    );
    // SAFETY: The synthetic source is never dereferenced, and no destination can fit.
    unsafe {
        vmem.vmas.insert(source.into(), vma);
        assert!(matches!(
            vmem.move_mappings(source, None, NonZeroPageSize::new(2 * PAGE_SIZE).unwrap()),
            Err(super::VmemMoveError::RemapError(
                crate::platform::page_mgmt::RemapError::OutOfMemory
            ))
        ));
    }
}

#[test]
fn test_handle_free_native_replacement_supplies_no_reservations() {
    type ManagedBackend = MockVmemBackend<false, PAGE_SIZE, NoReservations<PAGE_SIZE>>;

    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&ManagedBackend::EMPTY);
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    DUMMY_RESERVE_INPUTS.with_borrow_mut(Vec::clear);
    // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
    unsafe {
        for range in [0x10000..0x12000, 0x14000..0x15000] {
            vmem.insert_mapping(
                PageRange::new(range.start, range.end).unwrap(),
                vma,
                false,
                FixedAddressBehavior::Replace,
            )
            .unwrap();
        }

        vmem.insert_mapping(
            PageRange::new(0x11000, 0x15000).unwrap(),
            vma,
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(
            DUMMY_RESERVE_INPUTS.with_borrow(|attempts| attempts.last().cloned()),
            Some(Vec::new())
        );

        vmem.release_memory();
    }
}

#[test]
#[should_panic(expected = "providers using NoReservations must implement reserve_and_commit_pages")]
fn test_handle_free_mmap_requires_native_reserve_and_commit() {
    type ManagedBackend = MockVmemBackend<true, PAGE_SIZE, NoReservations<PAGE_SIZE>>;

    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&ManagedBackend::EMPTY);
    let range = 0x10000..0x12000;
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    // SAFETY: This synthetic mapping is exclusively owned and never dereferenced.
    unsafe {
        vmem.insert_mapping(
            PageRange::new(range.start, range.end).unwrap(),
            vma,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
    }
}

#[test]
fn test_create_mapping_relocates_hints_before_selecting_backing() {
    use crate::platform::page_mgmt::AllocationError;

    let original = PageRange::new(0x10000, 0x10000 + PAGE_SIZE).unwrap();
    let (address, length) = original.start_and_length();
    let retained = PageRange::new(
        DummyVmemBackend::TASK_ADDR_MAX - PAGE_SIZE,
        DummyVmemBackend::TASK_ADDR_MAX,
    )
    .unwrap();
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
    for reuse_backing in [false, true] {
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
        // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
        unsafe {
            vmem.create_mapping(
                Some(address),
                length,
                vma,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            )
            .unwrap();
            if reuse_backing {
                vmem.register_committed_mapping(retained, vma);
                vmem.platform
                    .decommit_pages(
                        || core::iter::once(&vmem.reservations[&retained.start]),
                        retained.into(),
                    )
                    .unwrap();
                vmem.vmas.remove(retained.into());
            }
            DUMMY_RESERVES.with_borrow_mut(Vec::clear);
            assert!(matches!(
                vmem.create_mapping(
                    Some(address),
                    length,
                    vma,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                ),
                Err(AllocationError::AddressInUse)
            ));
            let pointer = vmem
                .create_mapping(Some(address), length, vma, CreatePagesFlags::empty())
                .unwrap();
            let relocated =
                PageRange::new(pointer.as_usize(), pointer.as_usize() + PAGE_SIZE).unwrap();
            assert_ne!(relocated.start, original.start);
            assert_eq!(
                vmem.get_memory_permissions(original),
                Some(MemoryRegionPermissions::READ)
            );
            assert_eq!(
                vmem.get_memory_permissions(relocated),
                Some(MemoryRegionPermissions::READ)
            );
            assert_eq!(collect_mappings(&vmem).len(), 2);
            if reuse_backing {
                assert_eq!(relocated.start, retained.start);
                assert!(DUMMY_RESERVES.with_borrow(Vec::is_empty));
            } else {
                assert_eq!(DUMMY_RESERVES.with_borrow(Vec::len), 1);
            }
            vmem.release_memory();
        }
        assert!(vmem.reservations().next().is_none());
    }
}

#[test]
#[expect(
    clippy::reversed_empty_ranges,
    reason = "exercise an invalid overlap query"
)]
fn test_borrowed_reservation_overlaps() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    // SAFETY: Synthetic reservations are never dereferenced and have no active users.
    unsafe {
        for base in [0x10000, 0x12000, 0x16000] {
            vmem.create_private_pages(
                NonZeroAddress::new(base),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap();
        }
        for (range, expected) in [
            (0x10000..0x10000, vec![]),
            (0x14000..0x16000, vec![]),
            (0x11000..0x12000, vec![0x10000]),
            (0x11000..0x17000, vec![0x10000, 0x12000, 0x16000]),
            (0x12000..0x14000, vec![0x12000]),
            (0x17000..0x16000, vec![]),
        ] {
            assert_eq!(
                vmem.reservations
                    .overlapping(range)
                    .map(|(base, _)| base)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        vmem.release_memory();
    }
}

#[test]
fn test_checked_page_ranges_and_growth() {
    let largest = usize::MAX & !(PAGE_SIZE - 1);
    assert!(PageRange::<PAGE_SIZE>::from_start_len(largest, PAGE_SIZE).is_none());
    assert!(PageRange::<PAGE_SIZE>::from_start_len(0x10000, 0).is_none());
    assert!(PageRange::<PAGE_SIZE>::from_start_len(0x10001, PAGE_SIZE).is_none());
    assert_eq!(
        PageRange::<PAGE_SIZE>::from_start_len(0x10000, PAGE_SIZE)
            .unwrap()
            .end,
        0x11000
    );
    assert!((NonZeroPageSize::<PAGE_SIZE>::new(largest).unwrap() + PAGE_SIZE).is_none());
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let source = PageRange::new(0x10000, 0x11000).unwrap();
    // SAFETY: These synthetic allocations have no users and are never dereferenced.
    unsafe {
        vmem.create_pages(
            NonZeroAddress::new(source.start),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::FIXED_ADDR,
            MemoryRegionPermissions::READ,
        )
        .unwrap();
        let before = vmem.vmas.clone();
        let reservations = vmem.reservations().collect::<Vec<_>>();
        for size in [largest, DummyVmemBackend::TASK_ADDR_MAX] {
            assert!(matches!(
                vmem.resize_mapping(source, NonZeroPageSize::new(size).unwrap()),
                Err(VmemResizeError::OutOfMemory)
            ));
            assert_eq!(vmem.vmas, before);
            assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        }
        assert!(
            vmem.create_pages(
                None,
                NonZeroPageSize::new(largest).unwrap(),
                CreatePagesFlags::ENSURE_SPACE_AFTER,
                MemoryRegionPermissions::READ
            )
            .is_err()
        );
        assert_eq!(vmem.vmas, before);
        vmem.release_memory();
    }
}

#[test]
fn test_permission_queries_ignore_vma_metadata_boundaries() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let whole = PageRange::new(0x10000, 0x13000).unwrap();
    let middle = PageRange::new(0x11000, 0x12000).unwrap();
    let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
    // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
    unsafe {
        for (offset, flags) in [
            CreatePagesFlags::empty(),
            CreatePagesFlags::IS_STACK,
            CreatePagesFlags::MAP_FILE,
        ]
        .into_iter()
        .enumerate()
        {
            vmem.create_pages(
                NonZeroAddress::new(whole.start + offset * PAGE_SIZE),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR | flags,
                writable,
            )
            .unwrap();
        }
        assert_eq!(vmem.vmas.len(), 3);
        assert_eq!(vmem.get_memory_permissions(whole), Some(writable));
        vmem.protect_mapping(middle, MemoryRegionPermissions::READ)
            .unwrap();
        assert_eq!(vmem.get_memory_permissions(whole), None);
        vmem.protect_mapping(middle, writable).unwrap();
        assert_eq!(vmem.get_memory_permissions(whole), Some(writable));
        vmem.unmap_mapping(middle);
        assert_eq!(vmem.get_memory_permissions(whole), None);
        vmem.release_memory();
    }
}

#[test]
fn test_linux_resize_requires_committed_source() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let base = 0x10000;
    let whole = PageRange::new(base, base + 3 * PAGE_SIZE).unwrap();
    let first = PageRange::new(base, base + PAGE_SIZE).unwrap();
    // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
    unsafe {
        vmem.create_pages(
            NonZeroAddress::new(base),
            NonZeroPageSize::new(whole.len()).unwrap(),
            CreatePagesFlags::FIXED_ADDR,
            MemoryRegionPermissions::empty(),
        )
        .unwrap();
        vmem.unmap_mapping(whole);
        let reservations = vmem.reservations().collect::<Vec<_>>();
        for size in [PAGE_SIZE, whole.len(), whole.len() + PAGE_SIZE] {
            assert!(matches!(
                vmem.resize_mapping(whole, NonZeroPageSize::new(size).unwrap()),
                Err(VmemResizeError::NotExist(address)) if address == base
            ));
            assert!(collect_mappings(&vmem).is_empty());
            assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        }
        vmem.create_pages(
            NonZeroAddress::new(base),
            NonZeroPageSize::new(first.len()).unwrap(),
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            MemoryRegionPermissions::empty(),
        )
        .unwrap();
        let reservations = vmem.reservations().collect::<Vec<_>>();
        for size in [PAGE_SIZE, whole.len(), whole.len() + PAGE_SIZE] {
            assert!(matches!(
                vmem.resize_mapping(whole, NonZeroPageSize::new(size).unwrap()),
                Err(VmemResizeError::InvalidAddr { .. })
            ));
            assert_eq!(
                collect_mappings(&vmem),
                core::slice::from_ref(&(base..first.end))
            );
            assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        }
        vmem.resize_mapping(first, NonZeroPageSize::new(first.len()).unwrap())
            .unwrap();
        assert_eq!(
            vmem.get_memory_permissions(first),
            Some(MemoryRegionPermissions::empty())
        );
        vmem.release_memory();
        assert!(vmem.reservations().next().is_none());
    }
}

/// Zero-argument trait fallbacks compile only when the real inherent APIs are absent.
/// This checks the private engine without exposing it to external compile-fail doctests.
#[test]
fn test_vmem_api_families_are_disjoint() {
    type Automatic = Vmem<DummyVmemBackend, PAGE_SIZE, Linux>;
    type Explicit = Vmem<DummyVmemBackend, PAGE_SIZE, Windows>;

    trait NoAutomaticApi {
        fn create_pages() {}
        fn create_mapping() {}
        fn insert_mapping() {}
        fn reset_pages() {}
        fn resize_mapping() {}
        fn move_mappings() {}
        fn unmap_mapping() {}
        fn automatic_backing_range() {}
        fn acquire_backing() {}
        fn insert_backed_mapping() {}
    }
    impl NoAutomaticApi for Explicit {}

    trait NoExplicitApi {
        fn create_reserved_pages() {}
        fn commit_pages() {}
        fn decommit_pages() {}
        fn remove_mapping() {}
    }
    impl NoExplicitApi for Automatic {}

    trait NoUnrestrictedApi {
        fn update_mapping_state() {}
        fn update_backed_state() {}
    }
    impl NoUnrestrictedApi for Automatic {}
    impl NoUnrestrictedApi for Explicit {}

    Explicit::create_pages();
    Explicit::create_mapping();
    Explicit::insert_mapping();
    Explicit::reset_pages();
    Explicit::resize_mapping();
    Explicit::move_mappings();
    Explicit::unmap_mapping();
    Explicit::automatic_backing_range();
    Explicit::acquire_backing();
    Explicit::insert_backed_mapping();
    Automatic::create_reserved_pages();
    Automatic::commit_pages();
    Automatic::decommit_pages();
    Automatic::remove_mapping();
    Automatic::update_mapping_state();
    Explicit::update_mapping_state();
    Automatic::update_backed_state();
    Explicit::update_backed_state();
}

#[test]
fn test_automatic_backing_uses_no_replace_for_selected_hint() {
    use crate::platform::page_mgmt::FixedAddressBehavior;

    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
    let range = 0x21000..0x22000;
    DUMMY_RESERVES.with_borrow_mut(Vec::clear);
    DUMMY_STATES.with_borrow_mut(Vec::clear);
    // SAFETY: The fixture exclusively owns synthetic pages that are never dereferenced.
    unsafe {
        let pointer = vmem
            .create_pages(
                NonZeroAddress::new(range.start),
                NonZeroPageSize::new(range.len()).unwrap(),
                CreatePagesFlags::IS_STACK | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                MemoryRegionPermissions::READ,
            )
            .unwrap();
        assert_eq!(pointer.as_usize(), range.start);
        assert_eq!(
            DUMMY_RESERVES.with_borrow(Clone::clone),
            [(range.clone(), true)]
        );
        assert_eq!(
            DUMMY_STATES.with_borrow(Clone::clone),
            [(
                MemoryRegionPermissions::empty(),
                false,
                FixedAddressBehavior::NoReplace,
            )]
        );
        assert_eq!(vmem.reservations().next().unwrap(), range);
        vmem.release_memory();
    }
}

#[test]
fn test_detached_release_preserves_reservation_boundaries_and_gaps() {
    let backend = &MockVmemBackend::<false>::EMPTY;
    let extents = vec![0x14000..0x15000, 0x10000..0x11000, 0x11000..0x12000];
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_RANGE_RELEASES.with_borrow_mut(Vec::clear);
    // SAFETY: The fixture exclusively owns these synthetic extents and never accesses them.
    unsafe {
        let reservations: Vec<PageReservation<PAGE_SIZE>> = extents
            .iter()
            .map(|range| backend.create_reservation(range.clone()))
            .collect();
        for reservation in reservations {
            backend.release_pages(reservation);
        }
    }
    assert_eq!(DUMMY_RELEASES.with_borrow(Clone::clone), extents);
    assert_eq!(DUMMY_RANGE_RELEASES.with_borrow(Clone::clone), extents);
}

#[test]
fn test_direct_mapping_uses_initial_state_and_releases_on_unmap() {
    use crate::platform::page_mgmt::{AllocationError, FixedAddressBehavior};

    static EXTERNAL_BACKEND: MockVmemBackend<false> = MockVmemBackend {
        external: core::slice::from_ref(&(0x30000..0x40000)),
        reservations: core::marker::PhantomData,
    };
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&MockVmemBackend::<false>::EMPTY);
    let range = PageRange::new(0x11000, 0x14000).unwrap();
    let vma = VmArea::new(
        VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | VmFlags::VM_GROWSDOWN,
        false,
    );
    DUMMY_RESERVES.with_borrow_mut(Vec::clear);
    DUMMY_RESERVE_INPUTS.with_borrow_mut(Vec::clear);
    DUMMY_STATES.with_borrow_mut(Vec::clear);
    DUMMY_COMMITS.with_borrow_mut(Vec::clear);
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_RANGE_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
    // SAFETY: All synthetic addresses belong exclusively to this test and are never dereferenced.
    unsafe {
        let pointer = vmem
            .insert_mapping(range, vma, true, FixedAddressBehavior::Replace)
            .unwrap();
        assert_eq!(pointer.as_usize(), range.start);
        assert_eq!(
            DUMMY_RESERVES.with_borrow(Clone::clone),
            [(Range::from(range), true)]
        );
        assert_eq!(
            DUMMY_STATES.with_borrow(Clone::clone),
            [(
                MemoryRegionPermissions::READ,
                true,
                FixedAddressBehavior::Replace
            )]
        );
        assert_eq!(vmem.reservations().next().unwrap(), Range::from(range));
        assert!(matches!(
            vmem.insert_mapping(range, vma, false, FixedAddressBehavior::NoReplace),
            Err(AllocationError::AddressInUse)
        ));
        assert_eq!(DUMMY_RESERVES.with_borrow(Vec::len), 1);

        let replacement = PageRange::new(0x12000, 0x15000).unwrap();
        vmem.insert_mapping(replacement, vma, false, FixedAddressBehavior::Replace)
            .unwrap();
        assert_eq!(DUMMY_RESERVES.with_borrow(Vec::len), 2);
        assert_eq!(
            DUMMY_RESERVES.with_borrow(|reserves| reserves[1].clone()),
            (Range::from(replacement), true)
        );
        assert_eq!(
            DUMMY_STATES.with_borrow(|states| states.last().copied()),
            Some((
                MemoryRegionPermissions::READ,
                false,
                FixedAddressBehavior::Replace
            ))
        );
        assert!(DUMMY_COMMITS.with_borrow(Vec::is_empty));
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![0x11000..0x12000, 0x12000..0x15000]
        );
        let middle = PageRange::new(0x13000, 0x14000).unwrap();
        let writable = VmArea::new(
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | VmFlags::VM_WRITE,
            false,
        );
        vmem.insert_mapping(middle, writable, false, FixedAddressBehavior::Replace)
            .unwrap();
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![
                0x11000..0x12000,
                0x12000..0x13000,
                0x13000..0x14000,
                0x14000..0x15000
            ]
        );
        assert_eq!(
            vmem.iter()
                .map(|(extent, area)| (extent.clone(), *area))
                .collect::<Vec<_>>(),
            vec![
                (0x11000..0x13000, vma),
                (0x13000..0x14000, writable),
                (0x14000..0x15000, vma)
            ]
        );
        let mappings = vmem.vmas.clone();
        let reservations = vmem.reservations().collect::<Vec<_>>();
        let inputs = reservations.clone();
        let supplied_before_failure = DUMMY_RESERVE_INPUTS.with_borrow(Clone::clone);
        DUMMY_FAIL_RESERVE.set(true);
        let failed = vmem.insert_mapping(
            PageRange::new(0x11000, 0x15000).unwrap(),
            vma,
            false,
            FixedAddressBehavior::Replace,
        );
        DUMMY_FAIL_RESERVE.set(false);
        assert!(matches!(failed, Err(AllocationError::OutOfMemory)));
        assert_eq!(vmem.vmas, mappings);
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        assert_eq!(
            DUMMY_RESERVE_INPUTS.with_borrow(Clone::clone),
            supplied_before_failure
        );
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
        vmem.insert_mapping(
            PageRange::new(0x11000, 0x15000).unwrap(),
            vma,
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(
            DUMMY_RESERVE_INPUTS.with_borrow(|attempts| attempts.last().cloned()),
            Some(inputs)
        );
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            core::slice::from_ref(&(0x11000..0x15000))
        );
        assert_eq!(vmem.iter().next().unwrap().0, &(0x11000..0x15000));
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
        vmem.unmap_mapping(PageRange::new(0x12000, 0x14000).unwrap());
        assert_eq!(
            vmem.reservations
                .values()
                .map(PageReservation::range)
                .collect::<Vec<_>>(),
            vec![0x11000..0x15000]
        );
        assert_eq!(
            vmem.iter()
                .map(|(range, _)| range.clone())
                .collect::<Vec<_>>(),
            vec![0x11000..0x12000, 0x14000..0x15000]
        );
        let whole = PageRange::new(0x10000, 0x16000).unwrap();
        vmem.unmap_mapping(whole);
        vmem.unmap_mapping(whole);
        assert!(vmem.reservations().next().is_none());
        assert!(vmem.iter().next().is_none());
        assert_eq!(
            DUMMY_RELEASES.with_borrow(Clone::clone),
            vec![0x11000..0x15000]
        );
        assert_eq!(
            DUMMY_RANGE_RELEASES.with_borrow(Clone::clone),
            vec![0x11000..0x15000]
        );
        assert_eq!(
            DUMMY_DECOMMITS.with_borrow(Clone::clone),
            vec![0x12000..0x14000]
        );

        let mut external = Vmem::<_, PAGE_SIZE, Linux>::new(&EXTERNAL_BACKEND);
        for start in [0x30000 - PAGE_SIZE, 0x30000] {
            for behavior in [
                FixedAddressBehavior::NoReplace,
                FixedAddressBehavior::Replace,
            ] {
                assert!(matches!(
                    external.insert_mapping(
                        PageRange::new(start, start + 2 * PAGE_SIZE).unwrap(),
                        vma,
                        false,
                        behavior,
                    ),
                    Err(AllocationError::AddressInUse)
                ));
            }
        }
        assert_eq!(DUMMY_RESERVES.with_borrow(Vec::len), 4);
        assert!(external.reservations().next().is_none());
        assert!(external.iter().next().is_none());
    }
}

#[test]
fn test_replacement_decommits_overlaps_and_commits_segments() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&MockVmemBackend::<true, 0x4000>::EMPTY);
    let base = 0x10000;
    let middle = base + 4 * PAGE_SIZE;
    let end = middle + 4 * PAGE_SIZE;
    // SAFETY: The test exclusively owns synthetic mappings which are never dereferenced.
    unsafe {
        for start in [base, middle] {
            vmem.create_pages(
                NonZeroAddress::new(start),
                NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                MemoryRegionPermissions::READ,
            )
            .unwrap();
            vmem.unmap_mapping(
                PageRange::new(start + 2 * PAGE_SIZE, start + 3 * PAGE_SIZE).unwrap(),
            );
        }
        let before = vmem.reservations().collect::<Vec<_>>();
        DUMMY_COMMITS.with_borrow_mut(Vec::clear);
        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        vmem.create_pages(
            NonZeroAddress::new(base + PAGE_SIZE),
            NonZeroPageSize::new(6 * PAGE_SIZE).unwrap(),
            CreatePagesFlags::FIXED_ADDR,
            MemoryRegionPermissions::empty(),
        )
        .unwrap();
        assert_eq!(
            DUMMY_DECOMMITS.with_borrow(Clone::clone),
            vec![base + PAGE_SIZE..middle, middle..end - PAGE_SIZE,]
        );
        assert_eq!(
            DUMMY_COMMITS.with_borrow(Clone::clone),
            vec![base + PAGE_SIZE..middle, middle..end - PAGE_SIZE,]
        );
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), before);
        assert_eq!(
            vmem.iter()
                .map(|(range, area)| (range.clone(), MemoryRegionPermissions::from(area.flags())))
                .collect::<Vec<_>>(),
            vec![
                (base..base + PAGE_SIZE, MemoryRegionPermissions::READ),
                (
                    base + PAGE_SIZE..end - PAGE_SIZE,
                    MemoryRegionPermissions::empty()
                ),
                (end - PAGE_SIZE..end, MemoryRegionPermissions::READ),
            ]
        );
        vmem.release_memory();
    }
}

mod backing_commit {
    use super::{
        CreatePagesFlags, FromBytes, IntoBytes, Linux, MemoryRegionPermissions, NonZeroAddress,
        NonZeroPageSize, PAGE_SIZE, PageManagementProvider, PageRange, PageReservation, Range,
        RawConstPointer, TestReservationFactory, TransparentConstPtr, TransparentMutPtr, Vec,
        VmArea, VmFlags, Vmem, VmemProtectError, Windows, std, vec,
    };
    use crate::platform::page_mgmt::{
        AllocationError, FixedAddressBehavior, PageReservation as _, PageStateUpdateError,
        ReservationStore, ReserveAndCommitError, TrackedReservations,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Mutex,
    };

    #[derive(Default)]
    struct State {
        extents: BTreeMap<usize, Range<usize>>,
        committed: BTreeSet<usize>,
        non_decommittable: BTreeSet<usize>,
        fail_at: usize,
        fail_decommit_at: usize,
        fail_protect: bool,
        fail_reserve_at: Option<usize>,
        native_allocation: bool,
        fail_native_allocation: bool,
        native_allocations: Vec<(
            Range<usize>,
            MemoryRegionPermissions,
            bool,
            FixedAddressBehavior,
        )>,
        native_reservations: Vec<Vec<Range<usize>>>,
        relocate_to: Option<usize>,
        reserves: Vec<(Range<usize>, FixedAddressBehavior)>,
        releases: Vec<Range<usize>>,
        release_batches: Vec<Vec<Range<usize>>>,
        range_releases: Vec<Range<usize>>,
        commits: Vec<(Range<usize>, MemoryRegionPermissions, bool)>,
        protections: Vec<(Range<usize>, MemoryRegionPermissions)>,
        protection_reservations: Vec<Vec<Range<usize>>>,
        decommits: Vec<Range<usize>>,
    }
    struct Backend<const RESERVATION_ALIGNMENT: usize>(Mutex<State>);
    impl<const ALIGNMENT: usize> Backend<ALIGNMENT> {
        fn reserve_backing(
            &self,
            range: Range<usize>,
            behavior: FixedAddressBehavior,
            grow: bool,
        ) -> Result<PageReservation<PAGE_SIZE>, AllocationError> {
            assert_ne!(behavior, FixedAddressBehavior::Replace);
            // SAFETY: This fixture acquires fresh synthetic address space without replacement.
            unsafe { self.reserve_pages(core::iter::empty, range.clone(), grow, behavior) }
        }
    }
    impl<const RESERVATION_ALIGNMENT: usize> crate::platform::RawPointerProvider
        for Backend<RESERVATION_ALIGNMENT>
    {
        type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
        type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
    }
    impl<const ALIGNMENT: usize> PageManagementProvider<PAGE_SIZE> for Backend<ALIGNMENT> {
        type Reservations = TrackedReservations<PageReservation<PAGE_SIZE>>;

        const TASK_ADDR_MIN: usize = 0x10000;
        const TASK_ADDR_MAX: usize = 0x100000;
        const RESERVATION_ALIGNMENT: usize = ALIGNMENT;
        unsafe fn try_allocate_cow_pages<Reservations>(
            &self,
            replaced_reservations: impl FnOnce() -> Reservations,
            suggested_start: usize,
            source_data: &'static [u8],
            permissions: MemoryRegionPermissions,
            behavior: FixedAddressBehavior,
        ) -> Result<PageReservation<PAGE_SIZE>, crate::platform::page_mgmt::CowAllocationError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            // SAFETY: The fixture acquires the caller-authorized synthetic extent and commits it before publication.
            let reservation = unsafe {
                self.reserve_pages(
                    replaced_reservations,
                    suggested_start..suggested_start + source_data.len(),
                    false,
                    behavior,
                )
            }
            .map_err(|_| crate::platform::page_mgmt::CowAllocationError::InternalFailure)?;
            let extent = reservation.range();
            // SAFETY: The fresh synthetic extent has no users and is owned by this operation.
            unsafe {
                self.commit_pages(
                    || core::iter::once(&reservation),
                    extent.clone(),
                    permissions,
                    false,
                )
            }
            .unwrap();
            self.0
                .lock()
                .unwrap()
                .non_decommittable
                .extend(extent.step_by(PAGE_SIZE));
            Ok(reservation)
        }
        unsafe fn reserve_and_commit_pages<Reservations>(
            &self,
            replaced_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            permissions: MemoryRegionPermissions,
            _can_grow_down: bool,
            populate: bool,
            behavior: FixedAddressBehavior,
        ) -> Result<PageReservation<PAGE_SIZE>, ReserveAndCommitError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            let mut state = self.0.lock().unwrap();
            state
                .native_allocations
                .push((range.clone(), permissions, populate, behavior));
            if !state.native_allocation {
                return Err(ReserveAndCommitError::UnsupportedByPlatform);
            }
            if state.fail_native_allocation {
                return Err(AllocationError::OutOfMemory.into());
            }
            assert!(range.start.is_multiple_of(ALIGNMENT));
            let extent = if behavior == FixedAddressBehavior::Hint
                && let Some(address) = state.relocate_to
            {
                address..address + range.len()
            } else {
                range
            };
            let overlaps: Vec<_> = state
                .extents
                .values()
                .filter(|owned| owned.start < extent.end && extent.start < owned.end)
                .cloned()
                .collect();
            if !overlaps.is_empty() && behavior != FixedAddressBehavior::Replace {
                return Err(AllocationError::AddressInUse.into());
            }
            for owned in overlaps {
                state.extents.remove(&owned.start);
                for survivor in [owned.start..extent.start, extent.end..owned.end] {
                    if !survivor.is_empty() {
                        state.extents.insert(survivor.start, survivor);
                    }
                }
            }
            let replaced = if behavior == FixedAddressBehavior::Replace {
                replaced_reservations()
                    .map(|reservation| {
                        let replaced = reservation.range();
                        assert!(extent.start <= replaced.start && replaced.end <= extent.end);
                        replaced
                    })
                    .collect()
            } else {
                Vec::new()
            };
            state.native_reservations.push(replaced);
            state.extents.insert(extent.start, extent.clone());
            state
                .non_decommittable
                .retain(|address| !extent.contains(address));
            if permissions.contains(MemoryRegionPermissions::SHARED) {
                state
                    .non_decommittable
                    .extend(extent.clone().step_by(PAGE_SIZE));
            }
            state.committed.extend(extent.clone().step_by(PAGE_SIZE));
            // SAFETY: The mock acquired this extent and consumed all replaced ownership.
            Ok(unsafe { self.create_reservation(extent) })
        }
        unsafe fn reserve_pages<Reservations>(
            &self,
            replaced_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            _can_grow_down: bool,
            behavior: FixedAddressBehavior,
        ) -> Result<PageReservation<PAGE_SIZE>, AllocationError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            assert!(range.start.is_multiple_of(Self::RESERVATION_ALIGNMENT));
            let mut state = self.0.lock().unwrap();
            state.reserves.push((range.clone(), behavior));
            if state.fail_reserve_at == Some(range.start) {
                return Err(AllocationError::OutOfMemory);
            }
            let extent = if behavior == FixedAddressBehavior::Hint
                && let Some(address) = state.relocate_to
            {
                address..address + range.len()
            } else {
                range
            };
            let overlaps: Vec<_> = state
                .extents
                .values()
                .filter(|owned| owned.start < extent.end && extent.start < owned.end)
                .cloned()
                .collect();
            if !overlaps.is_empty() {
                if behavior != FixedAddressBehavior::Replace {
                    return Err(AllocationError::AddressInUse);
                }
                for owned in overlaps {
                    assert!(extent.start <= owned.start && owned.end <= extent.end);
                    state.extents.remove(&owned.start);
                }
                state.committed.retain(|address| !extent.contains(address));
                state
                    .non_decommittable
                    .retain(|address| !extent.contains(address));
            }
            state.extents.insert(extent.start, extent.clone());
            // SAFETY: The mock acquired this complete synthetic extent with no remaining owners.
            if behavior == FixedAddressBehavior::Replace {
                replaced_reservations().for_each(drop);
            }
            Ok(unsafe { self.create_reservation(extent) })
        }
        unsafe fn commit_pages<'reservation, Reservations>(
            &self,
            covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            permissions: MemoryRegionPermissions,
            populate: bool,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            let mut state = self.0.lock().unwrap();
            let mut cursor = range.start;
            for reservation in covering_reservations() {
                let extent = reservation.range();
                assert_eq!(state.extents[&extent.start], extent);
                assert_eq!(extent.start.max(range.start), cursor);
                assert!(extent.start < range.end && range.start < extent.end);
                cursor = extent.end.min(range.end);
            }
            assert_eq!(cursor, range.end);
            state.commits.push((range.clone(), permissions, populate));
            if range.contains(&state.fail_at) {
                return Err(PageStateUpdateError::OutOfMemory);
            }
            if permissions.contains(MemoryRegionPermissions::SHARED) {
                state
                    .non_decommittable
                    .extend(range.clone().step_by(PAGE_SIZE));
            }
            state.committed.extend(range.step_by(PAGE_SIZE));
            Ok(())
        }
        unsafe fn protect_pages<'reservation, Reservations>(
            &self,
            covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            permissions: MemoryRegionPermissions,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            let covering_reservations: Vec<_> = covering_reservations().collect();
            let mut state = self.0.lock().unwrap();
            let mut cursor = range.start;
            for reservation in &covering_reservations {
                let extent = reservation.range();
                assert_eq!(state.extents[&extent.start], extent);
                assert_eq!(extent.start.max(range.start), cursor);
                assert!(extent.start < range.end && range.start < extent.end);
                cursor = extent.end.min(range.end);
            }
            assert_eq!(cursor, range.end);
            assert!(
                range
                    .clone()
                    .step_by(PAGE_SIZE)
                    .all(|address| state.committed.contains(&address))
            );
            if state.fail_protect {
                return Err(PageStateUpdateError::OutOfMemory);
            }
            state.protection_reservations.push(
                covering_reservations
                    .iter()
                    .map(|reservation| reservation.range())
                    .collect(),
            );
            state.protections.push((range, permissions));
            Ok(())
        }
        unsafe fn decommit_pages<'reservation, Reservations>(
            &self,
            covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            let mut state = self.0.lock().unwrap();
            let mut cursor = range.start;
            for reservation in covering_reservations() {
                let extent = reservation.range();
                assert!(
                    state
                        .extents
                        .values()
                        .any(|owned| { owned.start <= extent.start && extent.end <= owned.end })
                );
                assert_eq!(extent.start.max(range.start), cursor);
                assert!(extent.start < range.end && range.start < extent.end);
                cursor = extent.end.min(range.end);
            }
            assert_eq!(cursor, range.end);
            state
                .non_decommittable
                .retain(|address| !range.contains(address));
            state.decommits.push(range.clone());
            if range.start == state.fail_decommit_at {
                return Err(PageStateUpdateError::OutOfMemory);
            }
            for address in range.step_by(PAGE_SIZE) {
                state.committed.remove(&address);
            }
            Ok(())
        }
        unsafe fn release_pages(&self, reservation: PageReservation<PAGE_SIZE>) {
            let range = reservation.range();
            assert!(!range.is_empty());
            let mut state = self.0.lock().unwrap();
            for extent in state.extents.values() {
                if extent.start < range.end && range.start < extent.end {
                    let overlap = extent.start.max(range.start)..extent.end.min(range.end);
                    assert_eq!(reservation.range(), overlap);
                }
            }
            state.range_releases.push(range.clone());
            state.release_batches.push(vec![range.clone()]);
            state.releases.push(range.clone());
            state.committed.retain(|address| !range.contains(address));
            state
                .non_decommittable
                .retain(|address| !range.contains(address));
            let (&base, extent) = state.extents.range(..=range.start).next_back().unwrap();
            let extent = extent.clone();
            assert!(range.end <= extent.end);
            state.extents.remove(&base);
            for remaining in [extent.start..range.start, range.end..extent.end] {
                if !remaining.is_empty() {
                    state.extents.insert(remaining.start, remaining);
                }
            }
        }
    }
    #[test]
    fn native_cow_fallback_decommits_partial_unmaps() {
        fn check<const ALIGNMENT: usize>() {
            for replace in [true, false] {
                let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    Backend::<ALIGNMENT>(Mutex::new(State::default())),
                ));
                let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
                let read = MemoryRegionPermissions::READ;
                let middle = PageRange::new(0x11000, 0x12000).unwrap();
                // SAFETY: The fixture exclusively owns these synthetic CoW mappings and all replacements.
                unsafe {
                    vmem.try_create_cow_pages(
                        0x10000,
                        &[0x5a; 3 * PAGE_SIZE],
                        read,
                        FixedAddressBehavior::NoReplace,
                        false,
                    )
                    .unwrap();
                    vmem.protect_mapping(middle, read | MemoryRegionPermissions::WRITE)
                        .unwrap();
                    if replace {
                        let result = vmem.create_pages(
                            NonZeroAddress::new(middle.start),
                            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                            CreatePagesFlags::FIXED_ADDR,
                            read,
                        );
                        if ALIGNMENT == PAGE_SIZE {
                            result.unwrap();
                            assert!(!vmem.vmas.get(&middle.start).unwrap().is_file_backed());
                        } else {
                            assert!(matches!(
                                result,
                                Err(super::linux::MappingError::MapError(
                                    AllocationError::AddressInUse
                                ))
                            ));
                            assert!(vmem.vmas.get(&middle.start).is_none());
                        }
                    } else {
                        vmem.unmap_mapping(middle);
                    }
                    assert!(vmem.vmas.get(&0x10000).unwrap().is_file_backed());
                    assert!(vmem.vmas.get(&0x12000).unwrap().is_file_backed());
                    assert_eq!(
                        backend.0.lock().unwrap().non_decommittable,
                        BTreeSet::from([0x10000, 0x12000])
                    );
                    assert_eq!(
                        backend.0.lock().unwrap().decommits,
                        core::slice::from_ref(&(0x11000..0x12000))
                    );
                    vmem.unmap_mapping(PageRange::new(0x10000, 0x13000).unwrap());
                    assert!(backend.0.lock().unwrap().extents.is_empty());
                    vmem.try_create_cow_pages(
                        0x10000,
                        &[0x5a; 3 * PAGE_SIZE],
                        read,
                        FixedAddressBehavior::NoReplace,
                        false,
                    )
                    .unwrap();
                    vmem.create_pages(
                        NonZeroAddress::new(0x10000),
                        NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                        CreatePagesFlags::FIXED_ADDR,
                        read,
                    )
                    .unwrap();
                    assert!(backend.0.lock().unwrap().non_decommittable.is_empty());
                    assert!(!vmem.vmas.get(&0x10000).unwrap().is_file_backed());
                    vmem.release_memory();
                    assert!(backend.0.lock().unwrap().extents.is_empty());
                }
            }
        }
        check::<PAGE_SIZE>();
    }

    #[test]
    fn shared_fallback_decommits_partial_unmaps() {
        fn check<const ALIGNMENT: usize>() {
            let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<ALIGNMENT>(
                Mutex::new(State::default()),
            )));
            let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
            let read = MemoryRegionPermissions::READ;
            // SAFETY: The fixture exclusively owns these synthetic shared and private mappings.
            unsafe {
                vmem.create_pages(
                    NonZeroAddress::new(0x10000),
                    NonZeroPageSize::new(0x10000).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::SHARED,
                    read,
                )
                .unwrap();
                vmem.unmap_mapping(PageRange::new(0x11000, 0x12000).unwrap());
                assert_eq!(
                    backend.0.lock().unwrap().decommits,
                    core::slice::from_ref(&(0x11000..0x12000))
                );
                assert!(
                    !backend
                        .0
                        .lock()
                        .unwrap()
                        .non_decommittable
                        .contains(&0x11000)
                );
                assert_eq!(vmem.reservations.len(), 1);
                vmem.unmap_mapping(PageRange::new(0x10000, 0x20000).unwrap());
                for base in [0x10000, 0x30000, 0x50000] {
                    vmem.create_pages(
                        NonZeroAddress::new(base),
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                        CreatePagesFlags::FIXED_ADDR,
                        read,
                    )
                    .unwrap();
                }
                backend.0.lock().unwrap().fail_at = 0x50000;
                assert!(matches!(
                    vmem.create_pages(
                        NonZeroAddress::new(0x10000),
                        NonZeroPageSize::new(0x41000).unwrap(),
                        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::SHARED,
                        read
                    ),
                    Err(super::linux::MappingError::MapError(
                        AllocationError::OutOfMemory
                    ))
                ));
                assert!(backend.0.lock().unwrap().committed.is_empty());
                assert!(backend.0.lock().unwrap().non_decommittable.is_empty());
                assert!(vmem.vmas.is_empty());
                vmem.release_memory();
                assert!(backend.0.lock().unwrap().extents.is_empty());
                assert!(vmem.reservations.is_empty());
            }
        }
        check::<PAGE_SIZE>();
    }

    #[test]
    fn unmap_retains_partially_live_reservations() {
        fn check<const ALIGNMENT: usize>() {
            for native_allocation in [false, true] {
                let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    Backend::<ALIGNMENT>(Mutex::new(State {
                        native_allocation,
                        ..State::default()
                    })),
                ));
                let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
                // SAFETY: These synthetic mappings are exclusively owned and never dereferenced.
                unsafe {
                    vmem.create_pages(
                        NonZeroAddress::new(0x10000),
                        NonZeroPageSize::new(0x10000).unwrap(),
                        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                        MemoryRegionPermissions::empty(),
                    )
                    .unwrap();
                    assert_eq!(backend.0.lock().unwrap().committed.len(), 16);
                    assert_eq!(
                        backend.0.lock().unwrap().commits.len(),
                        usize::from(!native_allocation)
                    );
                    vmem.unmap_mapping(PageRange::new(0x12000, 0x13000).unwrap());
                    assert_eq!(backend.0.lock().unwrap().committed.len(), 15);
                    assert!(!backend.0.lock().unwrap().committed.contains(&0x12000));
                    let reservations = vmem.reservations().collect::<Vec<_>>();
                    assert_eq!(reservations, vec![0x10000..0x20000]);
                    assert_eq!(
                        backend.0.lock().unwrap().decommits,
                        core::slice::from_ref(&(0x12000..0x13000))
                    );
                    assert!(backend.0.lock().unwrap().releases.is_empty());
                    assert_eq!(
                        vmem.create_pages(
                            NonZeroAddress::new(0x12000),
                            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                            MemoryRegionPermissions::empty(),
                        )
                        .unwrap()
                        .as_usize(),
                        0x12000
                    );
                    assert_eq!(backend.0.lock().unwrap().committed.len(), 16);
                    assert_eq!(backend.0.lock().unwrap().extents.len(), 1);
                    vmem.unmap_mapping(PageRange::new(0x12000, 0x13000).unwrap());
                    assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
                    vmem.release_memory();
                    assert!(vmem.reservations().next().is_none());
                    assert!(backend.0.lock().unwrap().extents.is_empty());
                    assert!(backend.0.lock().unwrap().committed.is_empty());
                }
            }
        }
        check::<PAGE_SIZE>();
        check::<0x10000>();
    }

    #[test]
    fn windows_bounded_allocation_retries_host_collisions() {
        for native_allocation in [false, true] {
            for top_down in [false, true] {
                for permissions in [
                    None,
                    Some(MemoryRegionPermissions::empty()),
                    Some(MemoryRegionPermissions::READ),
                ] {
                    let backend =
                        alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<PAGE_SIZE>(
                            Mutex::new(State {
                                native_allocation,
                                ..State::default()
                            }),
                        )));
                    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
                    let host_base = if top_down { 0x40000 } else { 0x10000 };
                    let expected = if top_down { 0x30000 } else { 0x20000 };
                    let host = backend
                        .reserve_backing(
                            host_base..host_base + PAGE_SIZE,
                            FixedAddressBehavior::NoReplace,
                            false,
                        )
                        .unwrap();
                    let length = NonZeroPageSize::new(3 * PAGE_SIZE).unwrap();
                    // SAFETY: The fixture owns all synthetic pages; the untracked host reservation must remain untouched.
                    unsafe {
                        assert!(matches!(
                            vmem.create_private_pages(
                                None,
                                host_base..host_base + length.as_usize(),
                                length,
                                0x10000,
                                if top_down {
                                    CreatePagesFlags::TOP_DOWN
                                } else {
                                    CreatePagesFlags::empty()
                                },
                                permissions
                            ),
                            Err(super::linux::MappingError::OutOfMemory)
                        ));
                        assert!(vmem.reservations.is_empty());
                        let pointer = vmem
                            .create_private_pages(
                                None,
                                0x10000..0x50000,
                                length,
                                0x10000,
                                if top_down {
                                    CreatePagesFlags::TOP_DOWN
                                } else {
                                    CreatePagesFlags::empty()
                                },
                                permissions,
                            )
                            .unwrap();
                        assert_eq!(pointer.as_usize(), expected);
                        let extent =
                            PageRange::from_start_len(expected, length.as_usize()).unwrap();
                        assert_eq!(vmem.reservations[&expected].range(), extent.into());
                        assert_eq!(backend.0.lock().unwrap().extents[&host_base], host.range());
                        vmem.remove_mapping(extent).unwrap();
                        backend.release_pages(host);
                    }
                    assert!(backend.0.lock().unwrap().extents.is_empty());
                }
            }
        }
    }

    #[test]
    fn windows_bounded_allocation_allows_aligned_hints_within_bounds() {
        fn check<const ALIGNMENT: usize>() {
            for native_allocation in [false, true] {
                for top_down in [false, true] {
                    for permissions in [
                        None,
                        Some(MemoryRegionPermissions::empty()),
                        Some(MemoryRegionPermissions::READ),
                    ] {
                        let candidate = if top_down { 0x60000 } else { 0x40000 };
                        let opposite = if top_down { 0x40000 } else { 0x60000 };
                        for relocated in [opposite, 0x20000, 0x80000] {
                            let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(
                                Backend::<ALIGNMENT>(Mutex::new(State {
                                    native_allocation,
                                    relocate_to: Some(relocated),
                                    ..State::default()
                                })),
                            ));
                            let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
                            let length = NonZeroPageSize::new(3 * PAGE_SIZE).unwrap();
                            let hint = ALIGNMENT >= 0x10000;
                            let rejected = hint && relocated != opposite;
                            let expected = if hint && !rejected {
                                relocated
                            } else {
                                candidate
                            };
                            // SAFETY: The fixture exclusively owns synthetic pages and never dereferences them.
                            unsafe {
                                let result = vmem.create_private_pages(
                                    None,
                                    0x40000..0x63000,
                                    length,
                                    0x10000,
                                    if top_down {
                                        CreatePagesFlags::TOP_DOWN
                                    } else {
                                        CreatePagesFlags::empty()
                                    },
                                    permissions,
                                );
                                if rejected {
                                    assert!(matches!(
                                        result,
                                        Err(super::linux::MappingError::OutOfMemory)
                                    ));
                                    let state = backend.0.lock().unwrap();
                                    let attempts = if permissions.is_some() && native_allocation {
                                        state.native_allocations.len()
                                    } else {
                                        state.reserves.len()
                                    };
                                    let expected_attempts =
                                        (0x63000 - length.as_usize() - 0x40000) / ALIGNMENT + 1;
                                    assert_eq!(attempts, expected_attempts);
                                    assert_eq!(
                                        state.releases,
                                        vec![
                                            relocated..relocated + length.as_usize();
                                            expected_attempts
                                        ]
                                    );
                                    assert!(state.extents.is_empty());
                                    continue;
                                }
                                let pointer = result.unwrap();
                                assert_eq!(pointer.as_usize(), expected);
                                let extent = expected..expected + length.as_usize();
                                assert_eq!(vmem.reservations.len(), 1);
                                assert_eq!(vmem.reservations[&expected].range(), extent);
                                assert_eq!(vmem.vmas.len(), usize::from(permissions.is_some()));
                                {
                                    let state = backend.0.lock().unwrap();
                                    let attempts: Vec<_> =
                                        if permissions.is_some() && native_allocation {
                                            state
                                                .native_allocations
                                                .iter()
                                                .map(|(range, _, _, behavior)| {
                                                    (range.clone(), *behavior)
                                                })
                                                .collect()
                                        } else {
                                            state.reserves.clone()
                                        };
                                    let expected_attempts = vec![(
                                        candidate..candidate + length.as_usize(),
                                        if hint {
                                            FixedAddressBehavior::Hint
                                        } else {
                                            FixedAddressBehavior::NoReplace
                                        },
                                    )];
                                    assert_eq!(attempts, expected_attempts);
                                    assert!(state.releases.is_empty());
                                    assert_eq!(
                                        state.extents.values().cloned().collect::<Vec<_>>(),
                                        core::slice::from_ref(&extent)
                                    );
                                    assert_eq!(
                                        state.committed.len(),
                                        if permissions.is_some() { 3 } else { 0 }
                                    );
                                    assert_eq!(
                                        state.commits.len(),
                                        usize::from(permissions.is_some() && !native_allocation)
                                    );
                                }
                                vmem.remove_mapping(
                                    PageRange::new(extent.start, extent.end).unwrap(),
                                )
                                .unwrap();
                            }
                            let state = backend.0.lock().unwrap();
                            assert!(state.extents.is_empty());
                            assert!(state.committed.is_empty());
                        }
                    }
                }
            }
        }
        check::<PAGE_SIZE>();
        check::<0x10000>();
        check::<0x20000>();
    }

    #[test]
    fn windows_private_allocation_enforces_requested_alignment() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<PAGE_SIZE>(
            Mutex::new(State::default()),
        )));
        let collision = 0xf0000;
        let host = backend
            .reserve_backing(
                collision..collision + PAGE_SIZE,
                FixedAddressBehavior::NoReplace,
                false,
            )
            .unwrap();
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        // SAFETY: This synthetic allocation has no users and is never dereferenced.
        unsafe {
            let pointer = vmem
                .create_private_pages(
                    None,
                    Backend::<PAGE_SIZE>::TASK_ADDR_MIN..Backend::<PAGE_SIZE>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    0x10000,
                    CreatePagesFlags::TOP_DOWN,
                    None,
                )
                .unwrap();
            assert!(pointer.as_usize().is_multiple_of(0x10000));
            assert_ne!(pointer.as_usize(), collision);
            assert_eq!(
                backend.0.lock().unwrap().reserves.last().unwrap().1,
                FixedAddressBehavior::NoReplace
            );
            vmem.release_memory();
            backend.release_pages(host);
        }
    }

    #[test]
    fn windows_native_allocation_and_fallback_publish_only_on_success() {
        for native_allocation in [false, true] {
            for fail in [false, true] {
                let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<0x10000>(
                    Mutex::new(State {
                        native_allocation,
                        fail_native_allocation: fail,
                        fail_at: if fail { 0x10000 } else { 0 },
                        relocate_to: Some(0x50000),
                        ..State::default()
                    }),
                )));
                let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
                let permissions = MemoryRegionPermissions::empty();
                // SAFETY: The test exclusively owns synthetic extents and never dereferences them.
                unsafe {
                    let result = vmem.create_private_pages(
                        NonZeroAddress::new(0x10000),
                        <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                            ..<Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                        NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                        <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                        CreatePagesFlags::TOP_DOWN,
                        Some(permissions),
                    );
                    assert_eq!(
                        backend.0.lock().unwrap().native_allocations,
                        [(
                            0x10000..0x13000,
                            permissions,
                            false,
                            FixedAddressBehavior::NoReplace
                        )]
                    );
                    if fail {
                        assert!(matches!(
                            result,
                            Err(super::linux::MappingError::MapError(
                                AllocationError::OutOfMemory
                            ))
                        ));
                        assert!(vmem.vmas.is_empty());
                        assert!(vmem.reservations.is_empty());
                        assert!(backend.0.lock().unwrap().extents.is_empty());
                        assert!(backend.0.lock().unwrap().committed.is_empty());
                        assert_eq!(
                            backend.0.lock().unwrap().releases.len(),
                            usize::from(!native_allocation)
                        );
                    } else {
                        assert_eq!(result.unwrap().as_usize(), 0x10000);
                        assert_eq!(vmem.reservations[&0x10000].range(), 0x10000..0x13000);
                        assert_eq!(
                            vmem.vmas.get(&0x10000).unwrap().flags,
                            VmFlags::VM_MAY_ACCESS_FLAGS
                        );
                        assert_eq!(backend.0.lock().unwrap().committed.len(), 3);
                        vmem.remove_mapping(PageRange::new(0x10000, 0x13000).unwrap())
                            .unwrap();
                    }
                    let state = backend.0.lock().unwrap();
                    assert_eq!(state.reserves.len(), usize::from(!native_allocation));
                    assert_eq!(state.commits.len(), usize::from(!native_allocation));
                }
            }
        }
    }

    #[test]
    fn linux_native_allocation_preserves_padding_and_existing_backing() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<0x10000>(
            Mutex::new(State {
                native_allocation: true,
                ..State::default()
            }),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        let permissions = MemoryRegionPermissions::READ;
        let area = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
        // SAFETY: The fixture exclusively owns synthetic pages, with no actual memory accesses.
        unsafe {
            let whole = PageRange::new(0x10000, 0x20000).unwrap();
            let pointer = vmem
                .insert_mapping(whole, area, true, FixedAddressBehavior::NoReplace)
                .unwrap();
            assert_eq!(pointer.as_usize(), whole.start);
            assert_eq!(
                backend.0.lock().unwrap().native_allocations,
                [(
                    whole.into(),
                    permissions,
                    true,
                    FixedAddressBehavior::NoReplace
                )]
            );
            assert!(backend.0.lock().unwrap().reserves.is_empty());
            assert!(backend.0.lock().unwrap().commits.is_empty());
            vmem.unmap_mapping(whole);

            let padded = PageRange::new(0x31000, 0x32000).unwrap();
            vmem.insert_mapping(padded, area, false, FixedAddressBehavior::NoReplace)
                .unwrap();
            assert_eq!(vmem.reservations[&0x30000].range(), 0x30000..0x40000);
            assert_eq!(
                backend.0.lock().unwrap().committed,
                padded.into_iter().collect::<BTreeSet<_>>()
            );
            let tail = PageRange::new(0x32000, 0x40000).unwrap();
            vmem.insert_mapping(tail, area, false, FixedAddressBehavior::NoReplace)
                .unwrap();
            vmem.unmap_mapping(PageRange::new(padded.start, tail.end).unwrap());

            let reserved = backend
                .reserve_backing(whole.into(), FixedAddressBehavior::NoReplace, false)
                .unwrap();
            vmem.reservations.insert(whole.start, reserved);
            vmem.insert_mapping(whole, area, false, FixedAddressBehavior::NoReplace)
                .unwrap();
            vmem.unmap_mapping(whole);
            assert_eq!(backend.0.lock().unwrap().native_allocations.len(), 1);

            backend.0.lock().unwrap().fail_native_allocation = true;
            let reserve_count = backend.0.lock().unwrap().reserves.len();
            assert!(matches!(
                vmem.insert_mapping(whole, area, false, FixedAddressBehavior::Hint),
                Err(AllocationError::OutOfMemory)
            ));
            assert_eq!(backend.0.lock().unwrap().reserves.len(), reserve_count);
            assert!(vmem.vmas.is_empty());
            assert!(vmem.reservations.is_empty());
            assert!(backend.0.lock().unwrap().extents.is_empty());

            backend.0.lock().unwrap().native_allocation = false;
            vmem.insert_mapping(whole, area, false, FixedAddressBehavior::NoReplace)
                .unwrap();
            assert_eq!(backend.0.lock().unwrap().reserves.len(), reserve_count + 1);
            vmem.unmap_mapping(whole);
        }
    }

    #[test]
    fn native_replacement_consumes_clipped_pieces_only_on_success() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<PAGE_SIZE>(
            Mutex::new(State {
                native_allocation: true,
                ..State::default()
            }),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        let area = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
        let extents = [0x10000..0x13000, 0x15000..0x18000];
        let replacement = PageRange::new(0x11000, 0x17000).unwrap();
        // SAFETY: The test exclusively owns synthetic extents and never dereferences them.
        unsafe {
            for extent in &extents {
                vmem.insert_mapping(
                    PageRange::new(extent.start, extent.end).unwrap(),
                    area,
                    false,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap();
            }
            let mappings = vmem.vmas.clone();
            let committed = backend.0.lock().unwrap().committed.clone();
            let supplied = backend.0.lock().unwrap().native_reservations.clone();
            backend.0.lock().unwrap().fail_native_allocation = true;
            assert!(matches!(
                vmem.insert_mapping(replacement, area, false, FixedAddressBehavior::Replace),
                Err(AllocationError::OutOfMemory)
            ));
            assert_eq!(vmem.vmas, mappings);
            assert_eq!(
                vmem.reservations
                    .values()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                extents
            );
            assert_eq!(backend.0.lock().unwrap().committed, committed);
            assert_eq!(backend.0.lock().unwrap().native_reservations, supplied);
            assert!(backend.0.lock().unwrap().decommits.is_empty());
            assert!(backend.0.lock().unwrap().reserves.is_empty());

            backend.0.lock().unwrap().fail_native_allocation = false;
            vmem.insert_mapping(replacement, area, true, FixedAddressBehavior::Replace)
                .unwrap();
            assert_eq!(
                backend
                    .0
                    .lock()
                    .unwrap()
                    .native_reservations
                    .last()
                    .unwrap(),
                &[0x11000..0x13000, 0x15000..0x17000]
            );
            assert_eq!(
                vmem.reservations
                    .values()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                [0x10000..0x11000, replacement.into(), 0x17000..0x18000]
            );
            assert_eq!(vmem.vmas.len(), 1);
            assert_eq!(backend.0.lock().unwrap().committed.len(), 8);
            assert!(backend.0.lock().unwrap().commits.is_empty());
            assert!(backend.0.lock().unwrap().decommits.is_empty());

            backend.0.lock().unwrap().native_allocation = false;
            vmem.insert_mapping(replacement, area, false, FixedAddressBehavior::Replace)
                .unwrap();
            assert_eq!(
                backend
                    .0
                    .lock()
                    .unwrap()
                    .native_reservations
                    .last()
                    .unwrap(),
                &[0x11000..0x13000, 0x15000..0x17000]
            );
            assert_eq!(
                backend.0.lock().unwrap().decommits,
                [Range::from(replacement)]
            );
            assert_eq!(
                backend.0.lock().unwrap().commits,
                [(replacement.into(), MemoryRegionPermissions::READ, false)]
            );
            assert!(backend.0.lock().unwrap().reserves.is_empty());
            vmem.unmap_mapping(PageRange::new(0x10000, 0x18000).unwrap());
            assert!(backend.0.lock().unwrap().extents.is_empty());
        }
    }

    #[test]
    fn protection_only_respects_reservations_and_validates_before_mutation() {
        fn check<Style>()
        where
            Style: crate::mm::PageManagerStyleFor<Backend<0x10000>, PAGE_SIZE>,
        {
            const ALIGNMENT: usize = 0x10000;
            let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<ALIGNMENT>(
                Mutex::new(State::default()),
            )));
            let mut vmem = Vmem::<_, PAGE_SIZE, Style>::new(backend);
            let read = MemoryRegionPermissions::READ;
            let writable = read | MemoryRegionPermissions::WRITE;
            let area = VmArea::new(
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | VmFlags::VM_GROWSDOWN,
                true,
            );
            let boundary = 2 * ALIGNMENT;
            let range = PageRange::new(boundary - PAGE_SIZE, boundary + PAGE_SIZE).unwrap();
            // SAFETY: The test exclusively owns synthetic committed extents, with no real accesses.
            unsafe {
                for base in [ALIGNMENT, boundary] {
                    let extent = base..base + ALIGNMENT;
                    let reservation = backend
                        .reserve_backing(extent.clone(), FixedAddressBehavior::NoReplace, false)
                        .unwrap();
                    backend
                        .commit_pages(
                            || core::iter::once(&reservation),
                            extent.clone(),
                            read,
                            false,
                        )
                        .unwrap();
                    vmem.reservations.insert(base, reservation);
                    vmem.vmas.insert(extent, area);
                }
                let committed = backend.0.lock().unwrap().committed.clone();
                backend.0.lock().unwrap().commits.clear();
                vmem.vmas.insert(
                    boundary..boundary + ALIGNMENT,
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, true),
                );
                assert!(matches!(
                    vmem.protect_mapping(range, writable),
                    Err(VmemProtectError::NoAccess { .. })
                ));
                assert!(backend.0.lock().unwrap().protections.is_empty());
                vmem.vmas.insert(boundary..boundary + ALIGNMENT, area);
                assert_eq!(vmem.vmas.len(), 1);
                let mappings = vmem.vmas.clone();
                backend.0.lock().unwrap().fail_protect = true;
                assert!(matches!(
                    vmem.protect_mapping(range, writable),
                    Err(VmemProtectError::ProtectError(
                        PageStateUpdateError::OutOfMemory
                    ))
                ));
                assert_eq!(vmem.vmas, mappings);
                assert!(backend.0.lock().unwrap().protections.is_empty());
                backend.0.lock().unwrap().fail_protect = false;
                vmem.protect_mapping(range, writable).unwrap();
                let state = backend.0.lock().unwrap();
                assert_eq!(state.protections, vec![(range.into(), writable)]);
                assert_eq!(
                    state.protection_reservations,
                    vec![vec![ALIGNMENT..boundary, boundary..boundary + ALIGNMENT,]]
                );
                assert_eq!(state.committed, committed);
                assert!(state.commits.is_empty());
                assert!(state.decommits.is_empty());
                assert!(state.releases.is_empty());
                drop(state);
                let protected = vmem.vmas.get(&range.start).unwrap();
                assert_eq!(protected.flags, area.flags | VmFlags::VM_WRITE);
                assert!(protected.is_file_backed());
                vmem.protect_mapping(range, writable).unwrap();
                assert_eq!(backend.0.lock().unwrap().protections.len(), 1);
                vmem.vmas.insert(
                    boundary..range.end,
                    VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false),
                );
                vmem.protect_mapping(range, read).unwrap();
                assert_eq!(
                    backend.0.lock().unwrap().protections.last(),
                    Some(&(range.into(), read))
                );
                assert_eq!(vmem.vmas.get(&range.start).unwrap().flags, area.flags);
                assert!(vmem.vmas.get(&range.start).unwrap().is_file_backed());
                let second = vmem.vmas.get(&boundary).unwrap();
                assert_eq!(
                    second.flags,
                    VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ
                );
                assert!(!second.is_file_backed());
                backend
                    .decommit_pages(
                        || core::iter::once(&vmem.reservations[&boundary]),
                        boundary..range.end,
                    )
                    .unwrap();
                vmem.vmas.remove(boundary..range.end);
                let mappings = vmem.vmas.clone();
                let decommits = backend.0.lock().unwrap().decommits.clone();
                assert!(matches!(
                    vmem.protect_mapping(range, read),
                    Err(VmemProtectError::NotCommitted(_))
                ));
                assert_eq!(vmem.vmas, mappings);
                let state = backend.0.lock().unwrap();
                assert_eq!(state.protections.len(), 2);
                assert_eq!(state.decommits, decommits);
                assert!(state.commits.is_empty());
                assert_eq!(state.extents.len(), 2);
                drop(state);
                vmem.release_memory();
                assert_eq!(
                    backend.0.lock().unwrap().release_batches,
                    [ALIGNMENT..boundary, boundary..boundary + ALIGNMENT]
                        .into_iter()
                        .map(|range| core::iter::once(range).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                );
            }
        }
        check::<Linux>();
        check::<Windows>();
    }

    #[test]
    fn windows_commit_and_decommit_are_atomic_within_one_reservation() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<PAGE_SIZE>(
            Mutex::new(State::default()),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        let base = 0x10000;
        let boundary = base + 2 * PAGE_SIZE;
        let whole = PageRange::new(base, base + 4 * PAGE_SIZE).unwrap();
        let first_reservation = PageRange::new(base, boundary).unwrap();
        let second_reservation = PageRange::new(boundary, whole.end).unwrap();
        let first = PageRange::new(base, base + PAGE_SIZE).unwrap();
        let third = PageRange::new(boundary, boundary + PAGE_SIZE).unwrap();
        let read = MemoryRegionPermissions::READ;
        let writable = read | MemoryRegionPermissions::WRITE;
        // SAFETY: The test owns all synthetic reservations and excludes concurrent page users.
        unsafe {
            for address in [base, boundary] {
                vmem.create_private_pages(
                    NonZeroAddress::new(address),
                    <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                    <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                    None,
                )
                .unwrap();
            }
            vmem.commit_pages(first, read).unwrap();
            vmem.commit_pages(third, MemoryRegionPermissions::empty())
                .unwrap();
            let mappings = vmem.vmas.clone();
            let extents = backend.0.lock().unwrap().extents.clone();
            backend.0.lock().unwrap().commits.clear();
            let invalid = PageRange::new(base, whole.end + PAGE_SIZE).unwrap();
            for rejected in [
                invalid,
                whole,
                PageRange::new(boundary - PAGE_SIZE, boundary + PAGE_SIZE).unwrap(),
                PageRange::new(base - PAGE_SIZE, base + PAGE_SIZE).unwrap(),
                PageRange::new(whole.end, whole.end + PAGE_SIZE).unwrap(),
            ] {
                assert!(matches!(
                    vmem.commit_pages(rejected, writable),
                    Err(VmemProtectError::InvalidRange(range)) if range == rejected.into()
                ));
                assert!(matches!(
                    vmem.decommit_pages(rejected),
                    Err(VmemProtectError::InvalidRange(range)) if range == rejected.into()
                ));
            }
            assert_eq!(vmem.vmas, mappings);
            {
                let mut state = backend.0.lock().unwrap();
                assert!(state.commits.is_empty());
                assert!(state.protections.is_empty());
                assert!(state.decommits.is_empty());
                assert_eq!(state.committed, BTreeSet::from([base, boundary]));
                state.fail_at = first.end;
            }
            assert!(matches!(
                vmem.commit_pages(first_reservation, writable),
                Err(VmemProtectError::ProtectError(
                    PageStateUpdateError::OutOfMemory
                ))
            ));
            assert_eq!(vmem.get_memory_permissions(first), Some(read));
            assert!(vmem.vmas.get(&first.end).is_none());
            assert_eq!(
                vmem.get_memory_permissions(third),
                Some(MemoryRegionPermissions::empty())
            );
            {
                let mut state = backend.0.lock().unwrap();
                assert!(state.protections.is_empty());
                assert_eq!(state.committed, BTreeSet::from([base, boundary]));
                state.fail_at = 0;
            }
            vmem.commit_pages(first_reservation, writable).unwrap();
            vmem.commit_pages(second_reservation, writable).unwrap();
            assert_eq!(vmem.get_memory_permissions(whole), Some(writable));
            let mappings = vmem.vmas.clone();
            let commits = backend.0.lock().unwrap().commits.clone();
            assert!(matches!(
                vmem.commit_pages(whole, writable),
                Err(VmemProtectError::InvalidRange(_))
            ));
            assert!(matches!(
                vmem.decommit_pages(whole),
                Err(VmemProtectError::InvalidRange(_))
            ));
            assert_eq!(vmem.vmas, mappings);
            assert_eq!(backend.0.lock().unwrap().commits, commits);
            assert!(backend.0.lock().unwrap().protections.is_empty());
            assert_eq!(backend.0.lock().unwrap().committed.len(), 4);
            backend.0.lock().unwrap().fail_decommit_at = boundary;
            assert!(matches!(
                vmem.decommit_pages(second_reservation),
                Err(VmemProtectError::ProtectError(
                    PageStateUpdateError::OutOfMemory
                ))
            ));
            assert_eq!(vmem.vmas, mappings);
            assert_eq!(
                backend.0.lock().unwrap().decommits,
                vec![second_reservation.into()]
            );
            assert_eq!(
                backend.0.lock().unwrap().committed,
                BTreeSet::from([base, base + PAGE_SIZE, boundary, boundary + PAGE_SIZE])
            );
            backend.0.lock().unwrap().fail_decommit_at = 0;
            vmem.decommit_pages(first_reservation).unwrap();
            assert_eq!(
                vmem.get_memory_permissions(second_reservation),
                Some(writable)
            );
            vmem.decommit_pages(second_reservation).unwrap();
            vmem.decommit_pages(second_reservation).unwrap();
            assert!(vmem.vmas.is_empty());
            let state = backend.0.lock().unwrap();
            assert!(state.committed.is_empty());
            assert_eq!(
                state.decommits,
                vec![
                    second_reservation.into(),
                    first_reservation.into(),
                    second_reservation.into(),
                    second_reservation.into(),
                ]
            );
            assert_eq!(state.extents, extents);
            assert_eq!(vmem.reservations.len(), 2);
            assert!(state.releases.is_empty());
        }
    }

    #[test]
    fn linux_unmap_reclaims_empty_reservations_across_holes() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<0x10000>(
            Mutex::new(State::default()),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        // SAFETY: The fixture exclusively owns these synthetic ranges and never dereferences them.
        unsafe {
            for base in [0x10000, 0x30000] {
                vmem.create_pages(
                    NonZeroAddress::new(base),
                    NonZeroPageSize::new(0x10000).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    MemoryRegionPermissions::empty(),
                )
                .unwrap();
            }
            vmem.unmap_mapping(PageRange::new(0x11000, 0x41000).unwrap());
            assert_eq!(
                vmem.iter()
                    .map(|(range, _)| range.clone())
                    .collect::<Vec<_>>(),
                vec![0x10000..0x11000]
            );
            assert_eq!(vmem.reservations[&0x10000].range(), 0x10000..0x20000);
            {
                let state = backend.0.lock().unwrap();
                assert_eq!(
                    state.decommits.as_slice(),
                    core::slice::from_ref(&(0x11000..0x20000))
                );
                assert_eq!(state.releases, vec![0x30000..0x40000]);
                assert_eq!(state.range_releases, vec![0x30000..0x40000]);
                assert_eq!(state.committed, BTreeSet::from([0x10000]));
            }
            let whole = PageRange::new(0xf000, 0x41000).unwrap();
            vmem.unmap_mapping(whole);
            vmem.unmap_mapping(whole);
            assert!(vmem.reservations.is_empty());
            assert!(vmem.vmas.is_empty());
            let state = backend.0.lock().unwrap();
            assert_eq!(
                state.decommits.as_slice(),
                core::slice::from_ref(&(0x11000..0x20000))
            );
            assert_eq!(state.releases, vec![0x30000..0x40000, 0x10000..0x20000]);
            assert_eq!(
                state.range_releases,
                vec![0x30000..0x40000, 0x10000..0x20000]
            );
            assert!(state.extents.is_empty());
            assert!(state.committed.is_empty());
            drop(state);

            for base in [0x11000, 0x31000] {
                vmem.create_pages(
                    NonZeroAddress::new(base),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
            }
            backend.0.lock().unwrap().range_releases.clear();
            vmem.unmap_mapping(PageRange::new(0x11000, 0x32000).unwrap());
            assert!(vmem.reservations.is_empty());
            assert!(vmem.vmas.is_empty());
            let state = backend.0.lock().unwrap();
            assert_eq!(
                state.range_releases,
                vec![0x10000..0x20000, 0x30000..0x40000]
            );
            let release_batches = &state.release_batches[state.release_batches.len() - 2..];
            assert_eq!(release_batches.len(), 2);
            assert_eq!(release_batches[0].len(), 1);
            assert_eq!(release_batches[0][0], 0x10000..0x20000);
            assert_eq!(release_batches[1].len(), 1);
            assert_eq!(release_batches[1][0], 0x30000..0x40000);
            assert!(state.extents.is_empty());
            assert!(state.committed.is_empty());
        }
    }

    #[test]
    fn windows_release_requires_one_reservation_and_allows_page_aligned_splits() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<0x10000>(
            Mutex::new(State::default()),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        // SAFETY: The fixture owns these synthetic reservations and relinquishes released pages without accesses.
        unsafe {
            for base in [0x10000, 0x20000] {
                vmem.create_private_pages(
                    NonZeroAddress::new(base),
                    <Backend<0x10000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<Backend<0x10000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(0x10000).unwrap(),
                    <Backend<0x10000> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                    None,
                )
                .unwrap();
                vmem.commit_pages(
                    PageRange::new(base, base + 0x10000).unwrap(),
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
            }
            let mappings = vmem.vmas.clone();
            let committed = backend.0.lock().unwrap().committed.clone();
            for request in [0x1f000..0x21000, 0xf000..0x11000, 0x2f000..0x31000] {
                assert!(
                    vmem.remove_mapping(PageRange::new(request.start, request.end).unwrap())
                        .is_err()
                );
                assert_eq!(vmem.vmas, mappings);
                let state = backend.0.lock().unwrap();
                assert_eq!(state.committed, committed);
                assert!(state.decommits.is_empty());
                assert!(state.releases.is_empty());
            }
            vmem.remove_mapping(PageRange::new(0x11000, 0x12000).unwrap())
                .unwrap();
            assert_eq!(
                vmem.reservations
                    .values()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![0x10000..0x11000, 0x12000..0x20000, 0x20000..0x30000]
            );
            {
                let state = backend.0.lock().unwrap();
                assert!(state.decommits.is_empty());
                assert_eq!(state.release_batches, vec![vec![0x11000..0x12000]]);
                assert!(state.committed.contains(&0x10000));
                assert!(state.committed.contains(&0x12000));
                assert!(!state.committed.contains(&0x11000));
            }
            vmem.release_memory();
            assert!(backend.0.lock().unwrap().extents.is_empty());
            assert!(backend.0.lock().unwrap().committed.is_empty());
        }
    }

    #[test]
    fn windows_commit_mixed_states_uses_one_vma_and_preserves_failure() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<PAGE_SIZE>(
            Mutex::new(State::default()),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        let base = 0x10000;
        let extent = base..base + 6 * PAGE_SIZE;
        let first = PageRange::new(base, base + 2 * PAGE_SIZE).unwrap();
        let middle = PageRange::new(base + 3 * PAGE_SIZE, base + 4 * PAGE_SIZE).unwrap();
        let request = PageRange::new(base + PAGE_SIZE, base + 5 * PAGE_SIZE).unwrap();
        let tail = PageRange::new(request.end, extent.end).unwrap();
        let first_gap = PageRange::new(first.end, middle.start).unwrap();
        let last_gap = PageRange::new(middle.end, request.end).unwrap();
        let read = MemoryRegionPermissions::READ;
        let writable = read | MemoryRegionPermissions::WRITE;
        let original = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
        // SAFETY: The test exclusively owns synthetic pages with no real accesses.
        unsafe {
            vmem.create_private_pages(
                NonZeroAddress::new(base),
                <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                NonZeroPageSize::new(extent.len()).unwrap(),
                <Backend<PAGE_SIZE> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap();
            vmem.commit_pages(first, read).unwrap();
            vmem.commit_pages(middle, MemoryRegionPermissions::empty())
                .unwrap();
            vmem.commit_pages(tail, read).unwrap();
            vmem.vmas
                .insert(first.into(), VmArea::new(VmFlags::empty(), false));
            let exclusions = vmem.vmas.clone();
            backend.0.lock().unwrap().commits.clear();
            assert!(matches!(
                vmem.commit_pages(first, MemoryRegionPermissions::empty()),
                Err(VmemProtectError::InvalidRange(_))
            ));
            assert_eq!(vmem.vmas, exclusions);
            assert!(backend.0.lock().unwrap().commits.is_empty());
            assert!(backend.0.lock().unwrap().decommits.is_empty());
            assert!(backend.0.lock().unwrap().releases.is_empty());
            vmem.vmas.insert(first.into(), original);
            vmem.vmas
                .insert(middle.into(), VmArea::new(VmFlags::VM_MAYREAD, false));
            let mappings = vmem.vmas.clone();
            backend.0.lock().unwrap().commits.clear();
            assert!(matches!(
                vmem.commit_pages(request, writable),
                Err(VmemProtectError::NoAccess { .. })
            ));
            assert_eq!(vmem.vmas, mappings);
            assert!(backend.0.lock().unwrap().commits.is_empty());
            assert!(backend.0.lock().unwrap().protections.is_empty());
            vmem.vmas.insert(
                middle.into(),
                VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false),
            );
            let mappings = vmem.vmas.clone();
            backend.0.lock().unwrap().fail_at = last_gap.start;
            assert!(matches!(
                vmem.commit_pages(request, writable),
                Err(VmemProtectError::ProtectError(
                    PageStateUpdateError::OutOfMemory
                ))
            ));
            assert_eq!(vmem.vmas, mappings);
            assert!(vmem.vmas.get(&first_gap.start).is_none());
            assert!(vmem.vmas.get(&last_gap.start).is_none());
            assert_eq!(vmem.get_memory_permissions(first), Some(read));
            assert_eq!(
                vmem.get_memory_permissions(middle),
                Some(MemoryRegionPermissions::empty())
            );
            {
                let mut state = backend.0.lock().unwrap();
                assert!(state.protections.is_empty());
                assert_eq!(
                    state.committed,
                    BTreeSet::from([base, base + PAGE_SIZE, middle.start, tail.start])
                );
                assert_eq!(state.commits, vec![(request.into(), writable, false)]);
                state.fail_at = 0;
                state.fail_protect = true;
                state.commits.clear();
            }
            vmem.commit_pages(request, writable).unwrap();
            assert_eq!(
                vmem.vmas
                    .iter()
                    .map(|(range, vma)| (range.clone(), *vma))
                    .collect::<Vec<_>>(),
                vec![
                    (base..request.start, original),
                    (
                        request.into(),
                        VmArea::new(original.flags | VmFlags::VM_WRITE, false)
                    ),
                    (tail.into(), original),
                ]
            );
            for segment in [first_gap, middle, last_gap] {
                assert_eq!(vmem.get_memory_permissions(segment), Some(writable));
                assert!(!vmem.vmas.get(&segment.start).unwrap().is_file_backed());
            }
            vmem.commit_pages(request, writable).unwrap();
            let state = backend.0.lock().unwrap();
            assert!(state.protections.is_empty());
            assert!(state.protection_reservations.is_empty());
            assert_eq!(state.commits, vec![(request.into(), writable, false); 2]);
            assert_eq!(state.committed.len(), 6);
            assert!(state.decommits.is_empty());
            assert!(state.releases.is_empty());
            drop(state);
            vmem.decommit_pages(middle).unwrap();
            vmem.decommit_pages(request).unwrap();
            vmem.decommit_pages(request).unwrap();
            assert_eq!(
                vmem.vmas
                    .iter()
                    .map(|(range, vma)| (range.clone(), *vma))
                    .collect::<Vec<_>>(),
                vec![(base..request.start, original), (tail.into(), original)]
            );
            let state = backend.0.lock().unwrap();
            assert_eq!(
                state.decommits,
                vec![middle.into(), request.into(), request.into()]
            );
            assert_eq!(state.committed, BTreeSet::from([base, tail.start]));
            assert_eq!(
                state.extents.values().cloned().collect::<Vec<_>>(),
                vec![extent]
            );
            assert_eq!(vmem.reservations.len(), 1);
            assert!(state.releases.is_empty());
        }
    }

    fn check_replacement_failure<const ALIGNMENT: usize>() {
        let first_gap = 0x10000 + ALIGNMENT;
        let second_gap = 0x30000 + ALIGNMENT;
        let read = MemoryRegionPermissions::READ;
        for (fail_reserve_at, fail_at) in [
            (Some(first_gap), 0),
            (Some(second_gap), 0),
            (None, 0x10000),
            (None, first_gap),
            (None, 0x50000),
        ] {
            let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<ALIGNMENT>(
                Mutex::new(State::default()),
            )));
            let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
            // SAFETY: Synthetic mappings are exclusively owned and never dereferenced.
            unsafe {
                for base in [0x10000, 0x30000, 0x50000] {
                    vmem.create_pages(
                        NonZeroAddress::new(base),
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                        read,
                    )
                    .unwrap();
                }
                let before = vmem
                    .iter()
                    .map(|(range, vma)| (range.clone(), *vma))
                    .collect::<Vec<_>>();
                let extents = backend.0.lock().unwrap().extents.clone();
                backend.0.lock().unwrap().fail_at = fail_at;
                backend.0.lock().unwrap().fail_reserve_at = fail_reserve_at;
                backend.0.lock().unwrap().commits.clear();
                backend.0.lock().unwrap().decommits.clear();
                let result = vmem.create_pages(
                    NonZeroAddress::new(0x10000),
                    NonZeroPageSize::new(0x41000).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    read,
                );
                assert!(matches!(
                    result,
                    Err(super::linux::MappingError::MapError(
                        AllocationError::OutOfMemory
                    ))
                ));
                if fail_reserve_at.is_some() {
                    assert_eq!(
                        vmem.iter()
                            .map(|(range, vma)| (range.clone(), *vma))
                            .collect::<Vec<_>>(),
                        before
                    );
                    assert_eq!(backend.0.lock().unwrap().extents, extents);
                    assert_eq!(
                        backend.0.lock().unwrap().committed,
                        BTreeSet::from([0x10000, 0x30000, 0x50000])
                    );
                } else {
                    assert_eq!(
                        backend.0.lock().unwrap().committed,
                        [0x10000, 0x30000, 0x50000]
                            .into_iter()
                            .filter(|&address| address > fail_at)
                            .collect::<BTreeSet<_>>()
                    );
                }
                let state = backend.0.lock().unwrap();
                if fail_reserve_at.is_none() {
                    let mut expected_decommits: Vec<_> = [0x10000, 0x30000, 0x50000]
                        .into_iter()
                        .filter(|&base| base <= fail_at)
                        .map(|base| base..(base + ALIGNMENT).min(0x51000))
                        .collect();
                    if state.commits.len() > 1 {
                        expected_decommits
                            .push(state.commits[0].0.start..state.commits.last().unwrap().0.start);
                    }
                    assert_eq!(state.decommits, expected_decommits);
                }
                assert_eq!(
                    vmem.iter()
                        .flat_map(|(range, _)| range.clone().step_by(PAGE_SIZE))
                        .collect::<BTreeSet<_>>(),
                    state.committed
                );
                assert_eq!(
                    vmem.reservations
                        .iter()
                        .map(|(&base, reservation)| (base, reservation.range()))
                        .collect::<BTreeMap<_, _>>(),
                    state.extents
                );
                drop(state);
                vmem.unmap_mapping(PageRange::new(0x10000, 0x51000).unwrap());
                assert!(vmem.reservations.is_empty());
                assert!(backend.0.lock().unwrap().extents.is_empty());
                assert!(backend.0.lock().unwrap().committed.is_empty());
            }
        }
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<ALIGNMENT>(
            Mutex::new(State::default()),
        )));
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        // SAFETY: The test exclusively owns the synthetic mapping and its surviving pages.
        unsafe {
            vmem.create_pages(
                NonZeroAddress::new(0x10000),
                NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                read,
            )
            .unwrap();
            backend.0.lock().unwrap().fail_at = 0x11000;
            assert!(matches!(
                vmem.create_pages(
                    NonZeroAddress::new(0x11000),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    read,
                ),
                Err(super::linux::MappingError::MapError(
                    AllocationError::OutOfMemory
                ))
            ));
            assert_eq!(
                vmem.iter()
                    .map(|(range, _)| range.clone())
                    .collect::<Vec<_>>(),
                vec![0x10000..0x11000, 0x12000..0x13000]
            );
            assert_eq!(
                backend.0.lock().unwrap().committed,
                BTreeSet::from([0x10000, 0x12000])
            );
            assert_eq!(
                vmem.reservations
                    .values()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![0x10000..0x13000usize.next_multiple_of(ALIGNMENT)]
            );
            backend.0.lock().unwrap().fail_at = 0;
            vmem.create_pages(
                NonZeroAddress::new(0x11000),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                read,
            )
            .unwrap();
            vmem.unmap_mapping(PageRange::new(0x10000, 0x13000).unwrap());
            assert!(vmem.reservations.is_empty());
            assert!(backend.0.lock().unwrap().extents.is_empty());
            assert!(backend.0.lock().unwrap().committed.is_empty());
        }
    }

    fn check_acquisition<const ALIGNMENT: usize>() {
        let backend = alloc::boxed::Box::leak(alloc::boxed::Box::new(Backend::<ALIGNMENT>(
            Mutex::new(State::default()),
        )));
        let read = MemoryRegionPermissions::READ;
        let requested = 0x50000..0x50000 + PAGE_SIZE;
        let reserved = backend
            .reserve_backing(requested.clone(), FixedAddressBehavior::NoReplace, false)
            .unwrap();
        assert_eq!(reserved.range(), requested);
        assert!(backend.0.lock().unwrap().commits.is_empty());
        assert!(matches!(
            backend.reserve_backing(requested.clone(), FixedAddressBehavior::NoReplace, false),
            Err(AllocationError::AddressInUse)
        ));
        assert!(backend.0.lock().unwrap().commits.is_empty());
        assert_eq!(backend.0.lock().unwrap().extents.len(), 1);
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        // SAFETY: Native collisions must preserve the synthetic foreign reservation without accessing it.
        unsafe {
            backend.0.lock().unwrap().reserves.clear();
            assert!(matches!(
                vmem.create_pages(
                    NonZeroAddress::new(requested.start),
                    NonZeroPageSize::new(requested.len()).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    read,
                ),
                Err(super::linux::MappingError::MapError(
                    AllocationError::AddressInUse
                ))
            ));
            assert_eq!(
                backend.0.lock().unwrap().reserves,
                [(
                    requested.start..requested.end.next_multiple_of(ALIGNMENT),
                    FixedAddressBehavior::NoReplace,
                )]
            );
            assert!(vmem.reservations().next().is_none());
            assert!(vmem.iter().next().is_none());
            if ALIGNMENT > PAGE_SIZE {
                backend.0.lock().unwrap().reserves.clear();
                assert!(matches!(
                    vmem.create_pages(
                        NonZeroAddress::new(requested.end),
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                        CreatePagesFlags::FIXED_ADDR,
                        read,
                    ),
                    Err(super::linux::MappingError::MapError(
                        AllocationError::AddressInUse
                    ))
                ));
                assert_eq!(
                    backend.0.lock().unwrap().reserves,
                    [(
                        requested.start..requested.start + ALIGNMENT,
                        FixedAddressBehavior::NoReplace,
                    )]
                );
                assert_eq!(
                    backend.0.lock().unwrap().extents[&requested.start],
                    requested
                );
                assert!(vmem.reservations().next().is_none());
            }
            vmem.create_pages(
                NonZeroAddress::new(0x30000),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                read,
            )
            .unwrap();
            vmem.unmap_mapping(PageRange::new(0x30000, 0x31000).unwrap());
            assert!(vmem.reservations().next().is_none());
            let retained = backend
                .reserve_backing(
                    0x30000..0x30000 + ALIGNMENT,
                    FixedAddressBehavior::NoReplace,
                    false,
                )
                .unwrap();
            vmem.reservations.insert(0x30000, retained);
            let before = backend.0.lock().unwrap().extents.clone();
            let length = requested.end - 0x10000;
            let relocated = PageRange::new(0x70000, 0x70000 + length).unwrap();
            let relocated_backing = relocated.start..relocated.end.next_multiple_of(ALIGNMENT);
            for (fail_reserve_at, fail_at) in [(Some(0), 0), (None, relocated.start), (None, 0)] {
                {
                    let mut state = backend.0.lock().unwrap();
                    state.reserves.clear();
                    state.releases.clear();
                    state.commits.clear();
                    state.relocate_to = Some(relocated.start);
                    state.fail_reserve_at = fail_reserve_at;
                    state.fail_at = fail_at;
                }
                let result = vmem.create_pages(
                    NonZeroAddress::new(0x10000),
                    NonZeroPageSize::new(length).unwrap(),
                    CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                    read,
                );
                assert_eq!(
                    backend.0.lock().unwrap().reserves,
                    [
                        (0x10000..0x30000, FixedAddressBehavior::NoReplace),
                        (
                            0x30000 + ALIGNMENT..requested.end.next_multiple_of(ALIGNMENT),
                            FixedAddressBehavior::NoReplace
                        ),
                        (
                            0..length.next_multiple_of(ALIGNMENT),
                            FixedAddressBehavior::Hint
                        ),
                    ]
                );
                assert_eq!(backend.0.lock().unwrap().releases[0], 0x10000..0x30000);
                if fail_reserve_at.is_some() || fail_at != 0 {
                    assert!(matches!(
                        result,
                        Err(super::linux::MappingError::MapError(
                            AllocationError::OutOfMemory
                        ))
                    ));
                    assert!(vmem.iter().next().is_none());
                } else {
                    assert_eq!(result.unwrap().as_usize(), relocated.start);
                    assert_eq!(vmem.iter().next().unwrap().0, &Range::from(relocated));
                    assert_eq!(vmem.reservations().count(), 2);
                    vmem.unmap_mapping(relocated);
                }
                assert_eq!(backend.0.lock().unwrap().extents, before);
                assert!(backend.0.lock().unwrap().committed.is_empty());
                assert_eq!(vmem.reservations().count(), 1);
                if fail_reserve_at.is_some() {
                    assert!(backend.0.lock().unwrap().commits.is_empty());
                } else {
                    assert_eq!(
                        backend.0.lock().unwrap().commits,
                        [(relocated.into(), read, true)]
                    );
                    assert_eq!(backend.0.lock().unwrap().releases[1], relocated_backing);
                }
            }
            vmem.release_memory();
        }
        // SAFETY: The test owns this uncommitted extent and has no active users.
        unsafe { backend.release_pages(reserved) };

        *backend.0.lock().unwrap() = State::default();
        // SAFETY: This synthetic native allocation has no active users.
        unsafe {
            let replacement = requested.start..requested.start + ALIGNMENT;
            let existing = backend
                .reserve_pages(
                    core::iter::empty,
                    replacement.clone(),
                    false,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap();
            backend.0.lock().unwrap().reserves.clear();
            assert!(matches!(
                vmem.create_pages(
                    NonZeroAddress::new(requested.start),
                    NonZeroPageSize::new(replacement.len()).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    read,
                ),
                Err(super::linux::MappingError::MapError(
                    AllocationError::AddressInUse
                ))
            ));
            assert_eq!(
                backend.0.lock().unwrap().reserves,
                [(replacement.clone(), FixedAddressBehavior::NoReplace)]
            );
            assert!(backend.0.lock().unwrap().committed.is_empty());
            backend.release_pages(existing);
        }

        backend.0.lock().unwrap().relocate_to = Some(0x70000);
        let actual = 0x70000..0x70000 + PAGE_SIZE;
        for permissions in [MemoryRegionPermissions::empty(), read] {
            let reservation = backend
                .reserve_backing(requested.clone(), FixedAddressBehavior::Hint, false)
                .unwrap();
            assert_eq!(reservation.range(), actual);
            // SAFETY: The test owns the fresh synthetic reservation without any pointer accesses.
            unsafe {
                backend.commit_pages(
                    || core::iter::once(&reservation),
                    actual.clone(),
                    permissions,
                    true,
                )
            }
            .unwrap();
            assert_eq!(
                backend.0.lock().unwrap().commits.last(),
                Some(&(actual.clone(), permissions, true))
            );
            assert_eq!(
                backend.0.lock().unwrap().committed,
                BTreeSet::from([actual.start])
            );
            let commits = backend.0.lock().unwrap().commits.clone();
            // SAFETY: These synthetic pages remain exclusively owned and have no active accesses.
            unsafe {
                backend.protect_pages(
                    || core::iter::once(&reservation),
                    actual.clone(),
                    MemoryRegionPermissions::empty(),
                )
            }
            .unwrap();
            assert_eq!(
                backend.0.lock().unwrap().protections.last(),
                Some(&(actual.clone(), MemoryRegionPermissions::empty()))
            );
            assert_eq!(backend.0.lock().unwrap().commits, commits);
            assert_eq!(
                backend.0.lock().unwrap().committed,
                BTreeSet::from([actual.start])
            );
            // SAFETY: The test relinquishes this entire owned extent without any pointer accesses.
            unsafe {
                backend
                    .decommit_pages(|| core::iter::once(&reservation), actual.clone())
                    .unwrap();
                backend.release_pages(reservation);
            }
        }
        {
            let mut state = backend.0.lock().unwrap();
            state.relocate_to = None;
            state.fail_at = requested.start;
            state.reserves.clear();
        }
        let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(backend);
        // SAFETY: The failing synthetic allocation has no active users.
        assert!(matches!(
            unsafe {
                vmem.create_pages(
                    NonZeroAddress::new(requested.start),
                    NonZeroPageSize::new(requested.len()).unwrap(),
                    CreatePagesFlags::empty(),
                    read,
                )
            },
            Err(super::linux::MappingError::MapError(
                AllocationError::OutOfMemory
            ))
        ));
        assert!(backend.0.lock().unwrap().extents.is_empty());
        assert!(backend.0.lock().unwrap().committed.is_empty());
        assert_eq!(
            backend.0.lock().unwrap().reserves,
            [(
                requested.start..requested.end.next_multiple_of(ALIGNMENT),
                FixedAddressBehavior::NoReplace,
            )]
        );
        *backend.0.lock().unwrap() = State::default();
        let extent = 0x50000..0x50000 + 3 * PAGE_SIZE;
        let reservation = backend
            .reserve_backing(extent.clone(), FixedAddressBehavior::NoReplace, false)
            .unwrap();
        // SAFETY: The test owns this extent and all survivor handles, with no pointer accesses.
        unsafe {
            backend
                .commit_pages(
                    || core::iter::once(&reservation),
                    extent.clone(),
                    read,
                    false,
                )
                .unwrap();
            let middle = extent.start + PAGE_SIZE..extent.start + 2 * PAGE_SIZE;
            backend
                .decommit_pages(|| core::iter::once(&reservation), middle.clone())
                .unwrap();
            let (prefix, released, suffix) = reservation.split(middle.clone());
            backend.release_pages(released);
            let prefix = prefix.unwrap();
            let suffix = suffix.unwrap();
            assert_eq!(prefix.range(), extent.start..middle.start);
            assert_eq!(suffix.range(), middle.end..extent.end);
            assert_eq!(
                backend.0.lock().unwrap().committed,
                BTreeSet::from([extent.start, middle.end])
            );
            backend
                .decommit_pages(|| core::iter::once(&prefix), prefix.range())
                .unwrap();
            backend.release_pages(prefix);
            backend
                .decommit_pages(|| core::iter::once(&suffix), suffix.range())
                .unwrap();
            backend.release_pages(suffix);
        }
        assert!(backend.0.lock().unwrap().extents.is_empty());
        assert!(backend.0.lock().unwrap().committed.is_empty());

        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        for permissions in [MemoryRegionPermissions::empty(), read] {
            *backend.0.lock().unwrap() = State::default();
            let reservation = backend
                .reserve_backing(extent.clone(), FixedAddressBehavior::NoReplace, false)
                .unwrap();
            // SAFETY: The test owns the fresh synthetic extent and transfers its handle below.
            unsafe {
                backend.commit_pages(
                    || core::iter::once(&reservation),
                    extent.clone(),
                    permissions,
                    false,
                )
            }
            .unwrap();
            let range = PageRange::new(extent.start, extent.end).unwrap();
            let middle =
                PageRange::new(extent.start + PAGE_SIZE, extent.start + 2 * PAGE_SIZE).unwrap();
            let area = VmArea::new(
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
                false,
            );
            let commits = backend.0.lock().unwrap().commits.clone();
            let committed = backend.0.lock().unwrap().committed.clone();
            assert!(
                vmem.reservations
                    .insert(extent.start, reservation)
                    .is_none()
            );
            // SAFETY: The test transfers this committed synthetic allocation without accessing it.
            unsafe {
                vmem.register_committed_mapping(range, area);
                assert_eq!(vmem.reservations[&extent.start].range(), extent);
                assert_eq!(
                    vmem.iter()
                        .map(|(range, area)| (range.clone(), area.flags()))
                        .collect::<Vec<_>>(),
                    [(extent.clone(), area.flags())]
                );
                vmem.register_committed_mapping(middle, area);
                let state = backend.0.lock().unwrap();
                assert_eq!(vmem.reservations.len(), 1);
                assert_eq!(
                    state.extents.values().cloned().collect::<Vec<_>>(),
                    core::slice::from_ref(&extent)
                );
                assert_eq!(state.committed, committed);
                assert_eq!(state.commits, commits);
                assert!(state.protections.is_empty());
                drop(state);
                vmem.decommit_pages(middle).unwrap();
                assert_eq!(vmem.reservations[&extent.start].range(), extent);
                vmem.remove_mapping(range).unwrap();
            }
            assert!(backend.0.lock().unwrap().extents.is_empty());
            assert!(backend.0.lock().unwrap().committed.is_empty());
        }
    }
    #[test]
    fn replacement_failure_returns_error_without_restoring_discarded_pages() {
        check_replacement_failure::<PAGE_SIZE>();
        check_replacement_failure::<0x10000>();
    }

    #[test]
    fn acquisition_relocation_and_lifecycle() {
        check_acquisition::<PAGE_SIZE>();
        check_acquisition::<0x10000>();
    }
}

#[test]
fn test_mappings_use_reservation_handles_without_raw_allocation() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    let base = 0x10000;
    let whole = PageRange::new(base, base + 3 * PAGE_SIZE).unwrap();
    let first = PageRange::new(base, base + PAGE_SIZE).unwrap();
    // SAFETY: The dummy backend's synthetic addresses are owned by this test and never dereferenced.
    unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(base),
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        assert!(collect_mappings(&vmem).is_empty());
        assert_eq!(
            vmem.reservations().next().unwrap(),
            base..base + 3 * PAGE_SIZE
        );
        assert!(
            vmem.create_private_pages(
                NonZeroAddress::new(base),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR
                    | CreatePagesFlags::NOREPLACE
                    | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .is_err()
        );
        vmem.commit_pages(first, MemoryRegionPermissions::empty())
            .unwrap();
        assert_eq!(collect_mappings(&vmem), vec![base..base + PAGE_SIZE]);
        assert!(
            vmem.protect_mapping(whole, MemoryRegionPermissions::READ)
                .is_err()
        );
        assert_eq!(
            vmem.get_memory_permissions(first),
            Some(MemoryRegionPermissions::empty())
        );
        assert!(
            vmem.commit_pages(
                PageRange::new(base, base + 4 * PAGE_SIZE).unwrap(),
                MemoryRegionPermissions::READ
            )
            .is_err()
        );
        assert_eq!(collect_mappings(&vmem), vec![base..base + PAGE_SIZE]);
        vmem.decommit_pages(whole).unwrap();
        assert!(collect_mappings(&vmem).is_empty());
        vmem.remove_mapping(PageRange::new(base + PAGE_SIZE, base + 2 * PAGE_SIZE).unwrap())
            .unwrap();
        for (query, overlaps) in [
            (base - PAGE_SIZE..base, false),
            (base..base, false),
            (base..base + PAGE_SIZE, true),
            (base + 1..base + PAGE_SIZE - 1, true),
            (base - 1..base + 1, true),
            (base + PAGE_SIZE - 1..base + PAGE_SIZE + 1, true),
            (base + PAGE_SIZE..base + 2 * PAGE_SIZE, false),
            (base + 2 * PAGE_SIZE - 1..base + 2 * PAGE_SIZE + 1, true),
            (base - PAGE_SIZE..whole.end + PAGE_SIZE, true),
            (whole.end..whole.end + PAGE_SIZE, false),
        ] {
            assert_eq!(vmem.overlaps(query.clone(), true), overlaps, "{query:?}");
        }
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![
                base..base + PAGE_SIZE,
                base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE
            ]
        );
        assert!(vmem.remove_mapping(whole).is_err());
        assert_eq!(vmem.reservations().count(), 2);
        vmem.remove_mapping(first).unwrap();
        vmem.remove_mapping(PageRange::new(base + 2 * PAGE_SIZE, whole.end).unwrap())
            .unwrap();
        assert_eq!(vmem.reservations().count(), 0);
        assert!(!vmem.overlaps(whole.into(), true));
        for permissions in [
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ,
        ] {
            let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
            let backing = base..whole.end;
            DUMMY_RESERVES.with_borrow_mut(Vec::clear);
            DUMMY_COMMITS.with_borrow_mut(Vec::clear);
            vmem.create_pages(
                NonZeroAddress::new(base),
                NonZeroPageSize::new(whole.len()).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::IS_STACK,
                permissions,
            )
            .unwrap();
            assert_eq!(
                DUMMY_RESERVES.with_borrow(Clone::clone),
                [(backing.clone(), true)]
            );
            assert_eq!(
                DUMMY_COMMITS.with_borrow(Clone::clone),
                core::slice::from_ref(&(base..whole.end))
            );
            assert_eq!(
                collect_mappings(&vmem),
                core::slice::from_ref(&(base..whole.end))
            );
            vmem.protect_mapping(
                first,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
            .unwrap();
            vmem.unmap_mapping(first);
            vmem.create_pages(
                NonZeroAddress::new(first.start),
                NonZeroPageSize::new(first.len()).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                permissions,
            )
            .unwrap();
            vmem.unmap_mapping(first);
            assert_eq!(vmem.reservations().next().unwrap(), backing);
            vmem.release_memory();
            assert_eq!(vmem.reservations().count(), 0);
        }
        let area = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ, false);
        vmem.register_committed_mapping(first, area);
        vmem.register_committed_mapping(
            PageRange::new(base + 2 * PAGE_SIZE, whole.end).unwrap(),
            area,
        );
        vmem.register_committed_mapping(whole, area);
        vmem.register_committed_mapping(first, area);
        assert_eq!(
            vmem.reservations
                .values()
                .map(PageReservation::range)
                .collect::<Vec<_>>(),
            vec![
                base..first.end,
                first.end..base + 2 * PAGE_SIZE,
                base + 2 * PAGE_SIZE..whole.end
            ]
        );
        assert_eq!(vmem.reservations().count(), 3);
        assert_eq!(
            collect_mappings(&vmem),
            core::slice::from_ref(&(base..whole.end))
        );
        assert!(vmem.remove_mapping(whole).is_err());
        for address in whole {
            vmem.remove_mapping(PageRange::new(address, address + PAGE_SIZE).unwrap())
                .unwrap();
        }
    }
}

#[test]
fn test_release_memory_reclaims_all_vmas_and_reservations() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&MockVmemBackend::<true, 0x2000>::EMPTY);
    let base = 0x10000;
    let whole = PageRange::<PAGE_SIZE>::new(base, base + 3 * PAGE_SIZE).unwrap();
    let first = PageRange::new(base, base + PAGE_SIZE).unwrap();
    let last = PageRange::new(base + 2 * PAGE_SIZE, whole.end).unwrap();
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    // SAFETY: The test owns synthetic ranges with no users and relinquishes all empty reservations.
    unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(base),
            <MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            NonZeroPageSize::new(whole.len()).unwrap(),
            <MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        vmem.commit_pages(first, MemoryRegionPermissions::READ)
            .unwrap();
        vmem.commit_pages(last, MemoryRegionPermissions::empty())
            .unwrap();
        vmem.create_private_pages(
            NonZeroAddress::new(base + 4 * PAGE_SIZE),
            <MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            page,
            <MockVmemBackend<true, 0x2000> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        vmem.brk = whole.end;
        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        vmem.release_memory();
        assert_eq!(vmem.brk, 0);
        assert!(DUMMY_DECOMMITS.with_borrow(Vec::is_empty));
        assert!(vmem.reservations().next().is_none());
        assert!(vmem.iter().next().is_none());
    }
}

#[test]
fn test_release_memory_releases_disjoint_reservations() {
    fn check<const COMMIT: bool, const RESERVATION_ALIGNMENT: usize>() {
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(
            &MockVmemBackend::<COMMIT, RESERVATION_ALIGNMENT>::EMPTY,
        );
        let retained = [0x10000..0x16000, 0x16000..0x1c000];
        // SAFETY: The fixture exclusively owns synthetic reservations and never accesses their addresses.
        unsafe {
            for range in retained
                .iter()
                .cloned()
                .chain([0x30000..0x32000, 0x40000..0x41000])
            {
                vmem.create_private_pages(
                    NonZeroAddress::new(range.start),
                    <MockVmemBackend<COMMIT, RESERVATION_ALIGNMENT> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<MockVmemBackend<COMMIT, RESERVATION_ALIGNMENT> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(range.len()).unwrap(),
                    <MockVmemBackend<COMMIT, RESERVATION_ALIGNMENT> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                    None,
                )
                .unwrap();
            }
            for range in [0x10000..0x11000, 0x1b000..0x1c000] {
                vmem.commit_pages(
                    PageRange::new(range.start, range.end).unwrap(),
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
            }
            for range in [
                0x12000..0x13000,
                0x14000..0x16000,
                0x16000..0x18000,
                0x30000..0x31000,
            ] {
                vmem.commit_pages(
                    PageRange::new(range.start, range.end).unwrap(),
                    MemoryRegionPermissions::WRITE,
                )
                .unwrap();
            }
            assert_eq!(
                vmem.vmas.get_key_value(&0x15000).unwrap().0,
                &(0x14000..0x18000)
            );
            DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
            DUMMY_RELEASES.with_borrow_mut(Vec::clear);
            vmem.release_memory();
            assert!(vmem.vmas.is_empty());
            assert!(vmem.reservations.is_empty());
            assert_eq!(
                DUMMY_RELEASES.with_borrow(Clone::clone),
                vec![
                    0x10000..0x16000,
                    0x16000..0x1c000,
                    0x30000..0x32000,
                    0x40000..0x41000,
                ]
            );
            assert!(DUMMY_DECOMMITS.with_borrow(Vec::is_empty));
        }
    }
    check::<true, PAGE_SIZE>();
    check::<false, PAGE_SIZE>();
    check::<true, 0x2000>();
    check::<false, 0x2000>();
}

#[test]
fn test_release_memory_releases_complete_reservation() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&MockVmemBackend::<false>::EMPTY);
    let first = PageRange::new(0x10000, 0x11000).unwrap();
    let last = PageRange::new(0x12000, 0x13000).unwrap();
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
    // SAFETY: The test exclusively owns these synthetic pages and relinquishes each selected subrange.
    unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(first.start),
            <MockVmemBackend<false> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<MockVmemBackend<false> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
            <MockVmemBackend<false> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        vmem.commit_pages(first, MemoryRegionPermissions::READ)
            .unwrap();
        vmem.commit_pages(last, MemoryRegionPermissions::empty())
            .unwrap();
        vmem.release_memory();
    }
    assert!(vmem.vmas.is_empty());
    assert!(vmem.reservations.is_empty());
    assert_eq!(
        DUMMY_RELEASES.with_borrow(Clone::clone),
        vec![first.start..last.end]
    );
    assert!(DUMMY_DECOMMITS.with_borrow(Vec::is_empty));
}

#[test]
fn test_release_memory_treats_empty_flag_vmas_as_owned() {
    fn check<const COMMIT: bool>() {
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&MockVmemBackend::<COMMIT>::EMPTY);
        let range = PageRange::new(0x10000, 0x12000).unwrap();
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        // SAFETY: This fixture owns the synthetic reservation and relinquishes it without any users.
        unsafe {
            vmem.create_private_pages(
                NonZeroAddress::new(range.start),
                <MockVmemBackend<COMMIT> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<MockVmemBackend<COMMIT> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                NonZeroPageSize::new(range.len()).unwrap(),
                <MockVmemBackend<COMMIT> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap();
            vmem.commit_pages(range, MemoryRegionPermissions::empty())
                .unwrap();
            vmem.vmas
                .insert(range.into(), VmArea::new(VmFlags::empty(), false));
            vmem.release_memory();
        }
        assert!(vmem.reservations.is_empty());
        assert!(vmem.vmas.is_empty());
        assert_eq!(
            DUMMY_RELEASES.with_borrow(Clone::clone),
            vec![Range::from(range)]
        );
        assert!(DUMMY_DECOMMITS.with_borrow(Vec::is_empty));
    }
    check::<true>();
    check::<false>();
}

#[test]
fn test_windows_bounded_placement_alignment_and_direction() {
    static BACKEND: DummyVmemBackend = DummyVmemBackend {
        external: &[0x10000..0x12000, 0x50000..0x51000],
        reservations: core::marker::PhantomData,
    };
    for (top_down, expected) in [(false, 0x20000), (true, 0x40000)] {
        for permissions in [None, Some(MemoryRegionPermissions::READ)] {
            let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&BACKEND);
            let length = NonZeroPageSize::new(2 * PAGE_SIZE).unwrap();
            // SAFETY: The fixture owns synthetic allocations without dereferencing them.
            unsafe {
                let pointer = vmem
                    .create_private_pages(
                        None,
                        0x11000..0x51000,
                        length,
                        0x10000,
                        if top_down {
                            CreatePagesFlags::TOP_DOWN
                        } else {
                            CreatePagesFlags::empty()
                        },
                        permissions,
                    )
                    .unwrap();
                assert_eq!(pointer.as_usize(), expected);
                assert_eq!(
                    vmem.reservations[&expected].range(),
                    expected..expected + 2 * PAGE_SIZE
                );
                assert!(matches!(
                    vmem.create_private_pages(
                        None,
                        expected..expected + PAGE_SIZE,
                        length,
                        0x10000,
                        if top_down {
                            CreatePagesFlags::TOP_DOWN
                        } else {
                            CreatePagesFlags::empty()
                        },
                        permissions
                    ),
                    Err(super::MappingError::OutOfMemory)
                ));
                vmem.remove_mapping(PageRange::new(expected, expected + 2 * PAGE_SIZE).unwrap())
                    .unwrap();
            }
            assert!(vmem.reservations.is_empty());
        }
    }

    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&BACKEND);
    let length = NonZeroPageSize::new(2 * PAGE_SIZE).unwrap();
    // SAFETY: The fixture owns synthetic allocations without dereferencing them.
    let pointer = unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(0x30000),
            0x11000..0x51000,
            length,
            0x10000,
            CreatePagesFlags::empty(),
            None,
        )
    }
    .unwrap();
    assert_eq!(pointer.as_usize(), 0x30000);
    // SAFETY: The test owns this synthetic reservation and never dereferences it.
    unsafe {
        vmem.remove_mapping(PageRange::new(0x30000, 0x32000).unwrap())
            .unwrap();
    }
    // SAFETY: The invalid suggestion is rejected before any allocation is attempted.
    assert!(matches!(
        unsafe {
            vmem.create_private_pages(
                NonZeroAddress::new(0x90000),
                0x11000..0x51000,
                length,
                0x10000,
                CreatePagesFlags::empty(),
                None,
            )
        },
        Err(super::MappingError::MapError(
            AllocationError::AboveMaxAddress
        ))
    ));
}

#[test]
fn test_placement_skips_multiple_reservation_overlaps() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    let reserved = [0x24000..0x26000, 0x27000..0x28000];
    // SAFETY: These synthetic reservations have no users and are never dereferenced.
    unsafe {
        for range in &reserved {
            vmem.create_private_pages(
                NonZeroAddress::new(range.start),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                NonZeroPageSize::new(range.len()).unwrap(),
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap();
        }
    }
    assert!(vmem.vmas.is_empty());
    {
        let mut overlaps = vmem.reservations.overlapping(0x25000..0x29000);
        assert_eq!(overlaps.next_back().unwrap().1.range(), reserved[1]);
        assert_eq!(overlaps.next().unwrap().1.range(), reserved[0]);
        assert!(overlaps.next_back().is_none());
    }
    assert!(
        vmem.reservations
            .overlapping(0x26000..0x27000)
            .next()
            .is_none()
    );
    assert!(
        vmem.reservations
            .overlapping(0x26000..0x27000)
            .next_back()
            .is_none()
    );

    let length = NonZeroPageSize::new(5 * PAGE_SIZE).unwrap();
    for (bounds, top_down, expected) in [
        (0x10000..0x2a000, true, Some(0x1f000)),
        (0x23000..0x2e000, false, Some(0x28000)),
        (0x23000..0x28000, true, None),
        (0x23000..0x28000, false, None),
    ] {
        assert_eq!(
            Vmem::<DummyVmemBackend, PAGE_SIZE, Windows>::find_area(
                &vmem.reservations,
                &vmem.vmas,
                FindAreaRequest {
                    suggested_address: None,
                    length,
                    behavior: FixedAddressBehavior::Hint,
                    alignment: PAGE_SIZE,
                    include_reservations: true,
                    address_range: bounds,
                    top_down,
                },
            )
            .unwrap(),
            expected
        );
    }
    // SAFETY: The test relinquishes all synthetic reservations without remaining users.
    unsafe { vmem.release_memory() };
}

#[test]
fn test_stack_guard_stops_at_intervening_vma() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    // SAFETY: Synthetic mappings are exclusively owned and never dereferenced.
    unsafe {
        vmem.register_committed_mapping(
            PageRange::new(0x30000, 0x31000).unwrap(),
            VmArea::new(VmFlags::VM_READ, false),
        );
        vmem.register_committed_mapping(
            PageRange::new(0x90000, 0x91000).unwrap(),
            VmArea::new(VmFlags::VM_READ | VmFlags::VM_GROWSDOWN, false),
        );
        let pointer = vmem
            .create_private_pages(
                None,
                0x10000..0xb0000,
                page,
                0x10000,
                CreatePagesFlags::empty(),
                None,
            )
            .unwrap();
        assert_eq!(pointer.as_usize(), 0x10000);
        assert!(matches!(
            vmem.create_private_pages(
                None,
                0x31000..0x90000,
                page,
                0x10000,
                CreatePagesFlags::empty(),
                None,
            ),
            Err(super::MappingError::OutOfMemory)
        ));
        vmem.release_memory();
    }
}

#[test]
fn test_windows_placement_respects_larger_provider_alignment() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&MockVmemBackend::<true, 0x20000>::EMPTY);
    let length = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    // SAFETY: Synthetic pages are owned by the fixture and never dereferenced.
    unsafe {
        for (top_down, expected) in [(false, 0x20000), (true, 0x60000)] {
            let flags = if top_down {
                CreatePagesFlags::TOP_DOWN
            } else {
                CreatePagesFlags::empty()
            };
            let pointer = vmem
                .create_private_pages(None, 0x10001..0x71000, length, 0x10000, flags, None)
                .unwrap();
            assert_eq!(pointer.as_usize(), expected);
        }
        for bounds in [
            0x10000..0x20000,
            0x30001..0x41000,
            0x80000..0x80000,
            usize::MAX - PAGE_SIZE..usize::MAX,
        ] {
            assert!(matches!(
                vmem.create_private_pages(
                    None,
                    bounds,
                    NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                    0x10000,
                    CreatePagesFlags::empty(),
                    None
                ),
                Err(super::MappingError::OutOfMemory)
            ));
        }
        for alignment in [0, 3 * PAGE_SIZE, usize::MAX] {
            assert!(matches!(
                vmem.create_private_pages(
                    None,
                    0x10000..0x80000,
                    length,
                    alignment,
                    CreatePagesFlags::empty(),
                    None,
                ),
                Err(super::MappingError::UnAligned)
            ));
        }
        vmem.release_memory();
    }
}

#[test]
fn test_windows_nonzero_address_requires_reservation_alignment() {
    let backend = &MockVmemBackend::<true, 0x10000>::EMPTY;
    for permissions in [None, Some(MemoryRegionPermissions::READ)] {
        let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(backend);
        // SAFETY: These synthetic allocations have no users and are never dereferenced.
        unsafe {
            assert!(matches!(
                vmem.create_private_pages(
                    NonZeroAddress::new(0x21000),
                    <MockVmemBackend<true, 0x10000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<MockVmemBackend<true, 0x10000> as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    <MockVmemBackend<true, 0x10000> as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::TOP_DOWN,
                    permissions,
                ),
                Err(super::MappingError::UnAligned)
            ));
            assert!(vmem.reservations().next().is_none());
            assert!(vmem.vmas.is_empty());
        }
    }
}

#[test]
fn test_placement_uses_reservations_and_stack_boundaries() {
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    let limit = DummyVmemBackend::TASK_ADDR_MAX;
    let base = limit - 4 * PAGE_SIZE;
    for (stack_offset, stack_flags) in [
        (None, VmFlags::empty()),
        (Some(0), VmFlags::empty()),
        (Some(0), VmFlags::VM_GROWSDOWN),
        (Some(PAGE_SIZE), VmFlags::VM_GROWSDOWN),
    ] {
        for hint in [None, NonZeroAddress::new(base + 2 * PAGE_SIZE)] {
            let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
            // SAFETY: The test exclusively owns synthetic ranges that are never dereferenced.
            unsafe {
                vmem.create_private_pages(
                    NonZeroAddress::new(base),
                    <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
                    <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
                    None,
                )
                .unwrap();
                if let Some(stack_offset) = stack_offset {
                    let range =
                        PageRange::new(base + stack_offset, base + stack_offset + PAGE_SIZE)
                            .unwrap();
                    vmem.commit_pages(range, MemoryRegionPermissions::READ)
                        .unwrap();
                    vmem.register_committed_mapping(
                        range,
                        VmArea::new(
                            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | stack_flags,
                            false,
                        ),
                    );
                }
                let guard = if stack_flags.contains(VmFlags::VM_GROWSDOWN) {
                    Vmem::<DummyVmemBackend, PAGE_SIZE, Windows>::STACK_GUARD_GAP << 1
                } else {
                    0
                };
                let expected = base + stack_offset.unwrap_or(0) - guard - PAGE_SIZE;
                let result = vmem.create_private_pages(
                    hint,
                    <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                        ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                    page,
                    <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                    CreatePagesFlags::TOP_DOWN,
                    None,
                );
                if hint.is_some() {
                    assert!(matches!(
                        result,
                        Err(super::MappingError::MapError(AllocationError::AddressInUse))
                    ));
                } else {
                    assert_eq!(result.unwrap().as_usize(), expected);
                }
                vmem.release_memory();
                let mut automatic = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);
                let whole = PageRange::new(base, limit).unwrap();
                automatic.register_committed_mapping(
                    whole,
                    VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false),
                );
                automatic.unmap_mapping(whole);
                if let Some(stack_offset) = stack_offset {
                    automatic
                        .create_mapping(
                            NonZeroAddress::new(base + stack_offset),
                            page,
                            VmArea::new(
                                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | stack_flags,
                                false,
                            ),
                            CreatePagesFlags::FIXED_ADDR,
                        )
                        .unwrap();
                }
                assert_eq!(
                    automatic
                        .create_pages(
                            None,
                            page,
                            CreatePagesFlags::empty(),
                            MemoryRegionPermissions::READ
                        )
                        .unwrap()
                        .as_usize(),
                    limit - PAGE_SIZE
                );
                automatic.release_memory();
                assert!(automatic.reservations().next().is_none());
            }
            assert!(vmem.reservations().next().is_none());
            assert!(vmem.iter().next().is_none());
        }
    }
}

#[test]
fn test_placement_preserves_stack_guard_after_reservation_collision() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    let page = NonZeroPageSize::new(PAGE_SIZE).unwrap();
    let limit = DummyVmemBackend::TASK_ADDR_MAX;
    let base = limit - 4 * PAGE_SIZE;
    let stack_start = base + PAGE_SIZE;
    let guard = Vmem::<DummyVmemBackend, PAGE_SIZE, Windows>::STACK_GUARD_GAP << 1;
    let blocked = stack_start - guard - PAGE_SIZE;
    // SAFETY: The test exclusively owns synthetic ranges that are never dereferenced.
    unsafe {
        vmem.create_private_pages(
            NonZeroAddress::new(base),
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        let stack = PageRange::new(stack_start, stack_start + PAGE_SIZE).unwrap();
        vmem.commit_pages(stack, MemoryRegionPermissions::READ)
            .unwrap();
        vmem.register_committed_mapping(
            stack,
            VmArea::new(
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::VM_READ | VmFlags::VM_GROWSDOWN,
                false,
            ),
        );
        vmem.create_private_pages(
            NonZeroAddress::new(blocked),
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            page,
            <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::TOP_DOWN,
            None,
        )
        .unwrap();
        assert_eq!(
            vmem.create_private_pages(
                None,
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                page,
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap()
            .as_usize(),
            blocked - PAGE_SIZE
        );
        vmem.commit_pages(
            PageRange::new(blocked, blocked + PAGE_SIZE).unwrap(),
            MemoryRegionPermissions::READ,
        )
        .unwrap();
        assert_eq!(
            vmem.create_private_pages(
                None,
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                    ..<DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
                page,
                <DummyVmemBackend as PageManagementProvider<PAGE_SIZE>>::RESERVATION_ALIGNMENT,
                CreatePagesFlags::TOP_DOWN,
                None,
            )
            .unwrap()
            .as_usize(),
            blocked - 2 * PAGE_SIZE
        );
        vmem.release_memory();
    }
    assert!(vmem.reservations().next().is_none());
    assert!(vmem.iter().next().is_none());
}

#[test]
fn test_reservations_do_not_inherit_vma_flags() {
    let mut vmem = Vmem::<_, PAGE_SIZE, Windows>::new(&DummyVmemBackend::EMPTY);
    let range = PageRange::new(0x10000, 0x10000 + PAGE_SIZE).unwrap();
    let restricted = VmArea::new(
        VmFlags::may_flags_for_mapping(true, true) | VmFlags::VM_READ,
        true,
    );
    // SAFETY: The test transfers exclusively owned, committed synthetic pages to the manager.
    unsafe { vmem.register_committed_mapping(range, restricted) };
    let reservations = [Range::from(range)];
    assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
    assert_eq!(
        vmem.vmas
            .overlapping(Range::<usize>::from(range))
            .next()
            .unwrap()
            .1,
        &restricted
    );

    // SAFETY: The test owns these synthetic mappings; the dummy backend never accesses them.
    unsafe {
        assert!(matches!(
            vmem.commit_pages(
                range,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            ),
            Err(VmemProtectError::NoAccess { .. })
        ));
        assert_eq!(vmem.iter().next().unwrap().1, &restricted);
        vmem.decommit_pages(range).unwrap();
        assert!(vmem.iter().next().is_none());
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        for permissions in [
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        ] {
            vmem.commit_pages(range, permissions).unwrap();
            assert_eq!(vmem.get_memory_permissions(range), Some(permissions));
            let vma = vmem.iter().next().unwrap().1;
            assert_eq!(
                vma.flags(),
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions)
            );
            assert!(!vma.is_file_backed());
            assert_eq!(vmem.reservations().collect::<Vec<_>>(), reservations);
        }
        vmem.remove_mapping(range).unwrap();
    }
    assert!(vmem.reservations().next().is_none());
}

#[test]
#[should_panic(expected = "tracked remap must use copy fallback")]
fn test_tracked_remap_uses_copy_fallback() {
    use crate::platform::page_mgmt::{
        FixedAddressBehavior, PageReservation as _, PageStateUpdateError, RemapError,
        ReserveAndCommitError,
    };
    struct InPlace<const COMMIT: bool> {
        fail: core::cell::Cell<bool>,
    }
    impl<const COMMIT: bool> crate::platform::RawPointerProvider for InPlace<COMMIT> {
        type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
        type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
    }
    impl<const COMMIT: bool> PageManagementProvider<PAGE_SIZE> for InPlace<COMMIT> {
        type Reservations = TrackedReservations<PageReservation<PAGE_SIZE>>;

        const TASK_ADDR_MIN: usize = 0x10000;
        const TASK_ADDR_MAX: usize = 0x100000;
        const RESERVATION_ALIGNMENT: usize = if COMMIT { 0x10000 } else { PAGE_SIZE };

        unsafe fn reserve_pages<Reservations>(
            &self,
            _: impl FnOnce() -> Reservations,
            _: Range<usize>,
            _: bool,
            _: FixedAddressBehavior,
        ) -> Result<PageReservation<PAGE_SIZE>, AllocationError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            panic!("tracked remap must use copy fallback");
        }
        unsafe fn reserve_and_commit_pages<Reservations>(
            &self,
            _: impl FnOnce() -> Reservations,
            _: Range<usize>,
            _: MemoryRegionPermissions,
            _: bool,
            _: bool,
            _: FixedAddressBehavior,
        ) -> Result<PageReservation<PAGE_SIZE>, ReserveAndCommitError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            Err(ReserveAndCommitError::UnsupportedByPlatform)
        }
        unsafe fn commit_pages<'reservation, Reservations>(
            &self,
            _: impl FnOnce() -> Reservations,
            _: Range<usize>,
            _: MemoryRegionPermissions,
            _: bool,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            panic!("native remap handles commitment");
        }
        unsafe fn protect_pages<'reservation, Reservations>(
            &self,
            _: impl FnOnce() -> Reservations,
            _: Range<usize>,
            _: MemoryRegionPermissions,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            panic!("native remap preserves permissions");
        }
        unsafe fn decommit_pages<'reservation, Reservations>(
            &self,
            _: impl FnOnce() -> Reservations,
            _: Range<usize>,
        ) -> Result<(), PageStateUpdateError>
        where
            Reservations: Iterator<Item = &'reservation PageReservation<PAGE_SIZE>>,
        {
            panic!("native remap handles source cleanup");
        }
        unsafe fn release_pages(&self, reservation: PageReservation<PAGE_SIZE>) {
            DUMMY_RELEASES.with_borrow_mut(|releases| {
                releases.push(reservation.range());
            });
        }
        unsafe fn try_remap_pages<Reservations>(
            &self,
            source_reservations: impl FnOnce() -> Reservations,
            old: Range<usize>,
            new: Range<usize>,
            permissions: MemoryRegionPermissions,
        ) -> Result<PageReservation<PAGE_SIZE>, RemapError>
        where
            Reservations: Iterator<Item = PageReservation<PAGE_SIZE>>,
        {
            assert_eq!(old, 0x11000..0x12000);
            assert_eq!(
                new,
                if COMMIT {
                    0xfe000..0x100000
                } else {
                    0x21000..0x23000
                }
            );
            assert_eq!(permissions, MemoryRegionPermissions::empty());
            if self.fail.get() {
                return Err(RemapError::OutOfMemory);
            }
            let reservations = source_reservations().collect::<Vec<_>>();
            assert_eq!(
                reservations
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                core::slice::from_ref(&old)
            );
            if COMMIT {
                drop(reservations);
                // SAFETY: The caller selected a fresh extent in this synthetic address space.
                let reservation = unsafe { self.create_reservation(new.clone()) };
                return Ok(reservation);
            }
            let destination_range = old.start..old.start + new.len();
            drop(reservations);
            // SAFETY: The synthetic remap consumed source ownership and owns the expanded range.
            let reservation = unsafe { self.create_reservation(destination_range.clone()) };
            Ok(reservation)
        }
    }
    let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(InPlace::<false> {
        fail: core::cell::Cell::new(true),
    }));
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(platform);
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false);
    let old = PageRange::new(0x11000, 0x12000).unwrap();
    let size = NonZeroPageSize::new(2 * PAGE_SIZE).unwrap();
    DUMMY_RELEASES.with_borrow_mut(Vec::clear);
    // SAFETY: All addresses are synthetic and exclusively owned by this fixture, never dereferenced.
    unsafe {
        vmem.register_committed_mapping(PageRange::new(0x10000, 0x12000).unwrap(), vma);
        assert!(matches!(
            vmem.move_mappings(old, NonZeroAddress::new(0x21000), size),
            Err(super::VmemMoveError::RemapError(RemapError::OutOfMemory))
        ));
        assert_eq!(
            vmem.vmas.get_key_value(&old.start),
            Some((&(0x10000..0x12000), &vma))
        );
        assert_eq!(vmem.reservations[&0x10000].range(), 0x10000..0x12000);
        platform.fail.set(false);
        let moved = vmem
            .move_mappings(old, NonZeroAddress::new(0x21000), size)
            .unwrap();
        assert_eq!(moved.as_usize(), old.start);
        assert_eq!(
            vmem.vmas.get_key_value(&old.start),
            Some((&(0x10000..0x13000), &vma))
        );
        assert_eq!(vmem.reservations.len(), 2);
        assert_eq!(vmem.reservations[&0x10000].range(), 0x10000..0x11000);
        assert_eq!(vmem.reservations[&0x11000].range(), 0x11000..0x13000);
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
        vmem.unmap_mapping(PageRange::new(0x10000, 0x13000).unwrap());
        DUMMY_RELEASES.with_borrow(|releases| {
            assert_eq!(releases, &vec![0x10000..0x11000, 0x11000..0x13000]);
        });
    }
    let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(InPlace::<true> {
        fail: core::cell::Cell::new(true),
    }));
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(platform);
    // SAFETY: Synthetic ownership is never dereferenced; the mock preserves or transfers it exclusively.
    unsafe {
        vmem.vmas.insert(old.into(), vma);
        vmem.register_committed_mapping(PageRange::new(0x23000, 0x30000).unwrap(), vma);
        vmem.reservations
            .insert(0x10000, platform.create_reservation(0x10000..0x22000));
        vmem.reservations
            .insert(0x22000, platform.create_reservation(0x22000..0x23000));
        let ownership = vmem.reservations().collect::<Vec<_>>();
        let mappings = vmem.vmas.clone();
        assert!(matches!(
            vmem.move_mappings(old, NonZeroAddress::new(0x21000), size),
            Err(super::VmemMoveError::RemapError(RemapError::OutOfMemory))
        ));
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), ownership);
        assert_eq!(vmem.vmas, mappings);
        platform.fail.set(false);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        let moved = vmem
            .move_mappings(old, NonZeroAddress::new(0x21000), size)
            .unwrap();
        assert_eq!(moved.as_usize(), 0xfe000);
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![0x22000..0x23000, 0x23000..0x30000, 0xfe000..0x100000]
        );
        assert!(!vmem.vmas.overlaps(&old.into()));
        assert_eq!(vmem.vmas.get(&0xfe000), Some(&vma));
        DUMMY_RELEASES.with_borrow(|releases| {
            assert_eq!(
                releases.as_slice(),
                &[0x10000..0x11000, 0x12000..0x22000, 0x11000..0x12000]
            );
        });
    }
}

#[test]
fn test_remap_across_backing_reservations() {
    fn check<const COMMIT: bool, const RESERVATION_ALIGN: usize>() {
        let mut storage = vec![0u8; 24 * PAGE_SIZE + RESERVATION_ALIGN];
        let offset = storage.as_mut_ptr().align_offset(RESERVATION_ALIGN);
        let pages = &mut storage[offset..offset + 24 * PAGE_SIZE];
        pages[..12 * PAGE_SIZE].fill(0x5a);
        pages[21 * PAGE_SIZE..].fill(0xa5);
        let base = pages.as_mut_ptr() as usize;
        let mut vmem =
            Vmem::<_, PAGE_SIZE, Linux>::new(&MockVmemBackend::<COMMIT, RESERVATION_ALIGN>::EMPTY);
        let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false);
        // SAFETY: This fixture exclusively owns aligned storage for all source/destination pages;
        // the mock uses real pointers but never frees or changes protection of the buffer.
        unsafe {
            let _memory = MockMemoryGuard::new(base..base + pages.len());
            for start in [0, 4, 8] {
                vmem.register_committed_mapping(
                    PageRange::new(base + start * PAGE_SIZE, base + (start + 4) * PAGE_SIZE)
                        .unwrap(),
                    vma,
                );
            }
            assert_eq!(vmem.vmas.len(), 1);
            assert_eq!(vmem.reservations.len(), 3);
            DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
            DUMMY_RELEASES.with_borrow_mut(Vec::clear);
            DUMMY_COMMITS.with_borrow_mut(Vec::clear);
            DUMMY_RESERVES.with_borrow_mut(Vec::clear);
            let old = PageRange::new(base + 2 * PAGE_SIZE, base + 10 * PAGE_SIZE).unwrap();
            let destination = base + 12 * PAGE_SIZE..base + 21 * PAGE_SIZE;
            let reserved = destination.start
                ..destination.start + destination.len().next_multiple_of(RESERVATION_ALIGN);
            let moved = vmem
                .move_mappings(
                    old,
                    NonZeroAddress::new(destination.start),
                    NonZeroPageSize::new(destination.len()).unwrap(),
                )
                .unwrap();
            assert_eq!(moved.as_usize(), destination.start);
            assert!(pages[..2 * PAGE_SIZE].iter().all(|&byte| byte == 0x5a));
            assert!(
                pages[10 * PAGE_SIZE..20 * PAGE_SIZE]
                    .iter()
                    .all(|&byte| byte == 0x5a)
            );
            assert!(
                pages[20 * PAGE_SIZE..21 * PAGE_SIZE]
                    .iter()
                    .all(|&byte| byte == 0)
            );
            assert_eq!(
                vmem.vmas.get_key_value(&destination.start),
                Some((&(base + 10 * PAGE_SIZE..destination.end), &vma))
            );
            assert!(!vmem.vmas.overlaps(&(destination.end..reserved.end)));
            assert!(pages[21 * PAGE_SIZE..].iter().all(|&byte| byte == 0xa5));
            DUMMY_RESERVES
                .with_borrow(|actual| assert_eq!(actual, &vec![(reserved.clone(), false)]));
            DUMMY_COMMITS.with_borrow(|actual| {
                if COMMIT {
                    assert_eq!(actual.as_slice(), core::slice::from_ref(&destination));
                } else {
                    assert!(actual.is_empty());
                }
            });
            assert!(!vmem.vmas.overlaps(&old.into()));
            let segments = [
                base + 2 * PAGE_SIZE..base + 4 * PAGE_SIZE,
                base + 4 * PAGE_SIZE..base + 8 * PAGE_SIZE,
                base + 8 * PAGE_SIZE..base + 10 * PAGE_SIZE,
            ];
            DUMMY_DECOMMITS.with_borrow(|actual| {
                assert_eq!(actual, &vec![segments[0].clone(), segments[2].clone()]);
            });
            DUMMY_RELEASES.with_borrow(|actual| {
                assert_eq!(
                    actual.as_slice(),
                    core::slice::from_ref(&(base + 4 * PAGE_SIZE..base + 8 * PAGE_SIZE))
                );
            });
            assert_eq!(
                vmem.reservations
                    .values()
                    .map(crate::platform::page_mgmt::PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![
                    base..base + 4 * PAGE_SIZE,
                    base + 8 * PAGE_SIZE..base + 12 * PAGE_SIZE,
                    reserved.clone(),
                ],
            );
            if destination.end < reserved.end {
                vmem.insert_mapping(
                    PageRange::new(destination.end, destination.end + PAGE_SIZE).unwrap(),
                    vma,
                    false,
                    crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                )
                .unwrap();
                assert_eq!(vmem.reservations[&reserved.start].range(), reserved);
                DUMMY_RESERVES.with_borrow(|actual| assert_eq!(actual.len(), 1));
            }
        }
    }
    check::<true, PAGE_SIZE>();
    check::<false, PAGE_SIZE>();
    check::<true, { 4 * PAGE_SIZE }>();
}

#[test]
fn test_native_remap_unsupported_preserves_ownership() {
    use crate::platform::page_mgmt::RemapError;
    let platform = MockVmemBackend::<true, { 4 * PAGE_SIZE }>::EMPTY;
    for source in [0x10000..0x11000, 0x10000..0x12000] {
        DUMMY_RESERVES.with_borrow_mut(Vec::clear);
        DUMMY_COMMITS.with_borrow_mut(Vec::clear);
        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        // SAFETY: The fixture owns this synthetic extent and never dereferences it.
        let remaining: [PageReservation<PAGE_SIZE>; 1] =
            [unsafe { platform.create_reservation(source.clone()) }];
        // SAFETY: The fixture owns synthetic committed pages; unsupported remapping must not access them.
        let error = unsafe {
            platform.try_remap_pages(
                || -> core::iter::Empty<_> {
                    panic!("unsupported remap must not request reservations")
                },
                source.clone(),
                0x20000..0x24000,
                MemoryRegionPermissions::READ,
            )
        }
        .unwrap_err();
        assert!(matches!(error, RemapError::UnsupportedByPlatform));
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].range(), source);
        assert!(DUMMY_RESERVES.with_borrow(Vec::is_empty));
        assert!(DUMMY_COMMITS.with_borrow(Vec::is_empty));
        assert!(DUMMY_DECOMMITS.with_borrow(Vec::is_empty));
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
    }
}

#[test]
fn test_remap_alignment_overflow_preserves_ownership() {
    let mut vmem =
        Vmem::<_, PAGE_SIZE, Linux>::new(&MockVmemBackend::<true, { 4 * PAGE_SIZE }>::EMPTY);
    let source = PageRange::new(0x10000, 0x11000).unwrap();
    // SAFETY: The synthetic source is never dereferenced; no destination can fit in the address space.
    unsafe {
        vmem.register_committed_mapping(source, VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false));
        let ownership = vmem.reservations().collect::<Vec<_>>();
        let mappings = vmem.vmas.clone();
        DUMMY_RESERVES.with_borrow_mut(Vec::clear);
        assert!(matches!(
            vmem.move_mappings(
                source,
                None,
                NonZeroPageSize::new(usize::MAX & !(PAGE_SIZE - 1)).unwrap()
            ),
            Err(super::VmemMoveError::OutOfMemory)
        ));
        assert!(DUMMY_RESERVES.with_borrow(Vec::is_empty));
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), ownership);
        assert_eq!(vmem.vmas, mappings);
    }
}

#[test]
fn test_remap_reuses_destination_backing_and_rolls_back() {
    const RESERVATION_ALIGN: usize = 4 * PAGE_SIZE;
    let platform = &MockVmemBackend::<true, RESERVATION_ALIGN>::EMPTY;
    let mut storage = vec![0xa5u8; 4 * RESERVATION_ALIGN];
    let offset = storage.as_mut_ptr().align_offset(RESERVATION_ALIGN);
    let pages = &mut storage[offset..offset + 3 * RESERVATION_ALIGN];
    let base = pages.as_mut_ptr() as usize;
    pages[..PAGE_SIZE].fill(0x5a);
    let source = PageRange::new(base, base + PAGE_SIZE).unwrap();
    let existing = base + RESERVATION_ALIGN..base + 2 * RESERVATION_ALIGN;
    let missing = existing.end..existing.end + RESERVATION_ALIGN;
    let destination = existing.start + PAGE_SIZE..existing.end + 2 * PAGE_SIZE;
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(platform);
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false);
    // SAFETY: All synthetic ownership lies in this exclusively held buffer; mocks do not free it.
    unsafe {
        let _memory = MockMemoryGuard::new(base..base + pages.len());
        vmem.reservations
            .insert(base, platform.create_reservation(base..existing.start));
        vmem.reservations.insert(
            existing.start,
            platform.create_reservation(existing.clone()),
        );
        vmem.register_committed_mapping(source, vma);
        let ownership = vmem.reservations().collect::<Vec<_>>();
        let mappings = vmem.vmas.clone();
        let hint = NonZeroAddress::new(destination.start);
        let length = NonZeroPageSize::new(destination.len()).unwrap();
        DUMMY_FAIL_RESERVE.set(true);
        assert!(vmem.move_mappings(source, hint, length).is_err());
        DUMMY_FAIL_RESERVE.set(false);
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), ownership);
        assert_eq!(vmem.vmas, mappings);

        DUMMY_DECOMMITS.with_borrow_mut(Vec::clear);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        DUMMY_FAIL_COMMIT_AT.set(Some(missing.start));
        assert!(matches!(
            vmem.move_mappings(source, hint, length),
            Err(super::VmemMoveError::RemapError(
                crate::platform::page_mgmt::RemapError::OutOfMemory
            ))
        ));
        DUMMY_FAIL_COMMIT_AT.set(None);
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![base..existing.start, existing.clone()]
        );
        assert_eq!(vmem.vmas, mappings);
        assert!(pages[..PAGE_SIZE].iter().all(|&byte| byte == 0x5a));
        assert_eq!(
            DUMMY_DECOMMITS.with_borrow(Clone::clone),
            vec![destination.start..existing.end]
        );
        assert_eq!(
            DUMMY_RELEASES.with_borrow(Clone::clone),
            vec![missing.clone()]
        );

        DUMMY_RESERVES.with_borrow_mut(Vec::clear);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        let moved = vmem.move_mappings(source, hint, length).unwrap();
        assert_eq!(moved.as_usize(), destination.start);
        assert_eq!(
            DUMMY_RESERVES.with_borrow(Clone::clone),
            vec![(missing.clone(), false)]
        );
        assert_eq!(
            DUMMY_RELEASES.with_borrow(Clone::clone),
            vec![base..existing.start]
        );
        assert_eq!(
            vmem.reservations().collect::<Vec<_>>(),
            vec![existing, missing]
        );
        assert_eq!(
            vmem.vmas.get_key_value(&destination.start),
            Some((&destination, &vma))
        );
        assert!(
            pages[5 * PAGE_SIZE..6 * PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0x5a)
        );
        assert!(
            pages[6 * PAGE_SIZE..10 * PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            pages[4 * PAGE_SIZE..5 * PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0xa5)
        );
        assert!(pages[10 * PAGE_SIZE..].iter().all(|&byte| byte == 0xa5));
    }
}

#[test]
fn test_remap_reuses_source_reservation() {
    const RESERVATION_ALIGN: usize = 4 * PAGE_SIZE;
    let platform = &MockVmemBackend::<true, RESERVATION_ALIGN>::EMPTY;
    let mut storage = vec![0xa5u8; 2 * RESERVATION_ALIGN];
    let offset = storage.as_mut_ptr().align_offset(RESERVATION_ALIGN);
    let pages = &mut storage[offset..offset + RESERVATION_ALIGN];
    pages[..PAGE_SIZE].fill(0x5a);
    let base = pages.as_mut_ptr() as usize;
    let extent = base..base + RESERVATION_ALIGN;
    let source = PageRange::new(base, base + PAGE_SIZE).unwrap();
    let destination = base + PAGE_SIZE..base + 3 * PAGE_SIZE;
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(platform);
    let vma = VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAY_ACCESS_FLAGS, false);
    let excluded = VmArea::new(VmFlags::empty(), false);
    vmem.vmas
        .insert(DummyVmemBackend::TASK_ADDR_MIN..base, excluded);
    vmem.vmas
        .insert(extent.end..DummyVmemBackend::TASK_ADDR_MAX, excluded);
    // SAFETY: Source and destination are disjoint subranges of this exclusively held buffer.
    unsafe {
        let _memory = MockMemoryGuard::new(base..base + pages.len());
        vmem.reservations
            .insert(base, platform.create_reservation(extent.clone()));
        vmem.register_committed_mapping(source, vma);
        assert!(matches!(
            Vmem::<MockVmemBackend<true, RESERVATION_ALIGN>, PAGE_SIZE, Linux>::find_area(
                &vmem.reservations,
                &vmem.vmas,
                FindAreaRequest {
                    suggested_address: NonZeroAddress::new(destination.start),
                    length: NonZeroPageSize::new(destination.len()).unwrap(),
                    behavior: crate::platform::page_mgmt::FixedAddressBehavior::Hint,
                    alignment: PAGE_SIZE,
                    include_reservations: true,
                    address_range: DummyVmemBackend::TASK_ADDR_MIN..DummyVmemBackend::TASK_ADDR_MAX,
                    top_down: true,
                },
            ),
            Ok(None)
        ));
        DUMMY_RESERVES.with_borrow_mut(Vec::clear);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        let moved = vmem
            .move_mappings(
                source,
                NonZeroAddress::new(destination.start),
                NonZeroPageSize::new(destination.len()).unwrap(),
            )
            .unwrap();
        assert_eq!(moved.as_usize(), destination.start);
        assert!(DUMMY_RESERVES.with_borrow(Vec::is_empty));
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), vec![extent]);
        assert_eq!(
            vmem.vmas.get_key_value(&destination.start),
            Some((&destination, &vma))
        );
        assert!(!vmem.vmas.overlaps(&source.into()));
        assert!(
            pages[PAGE_SIZE..2 * PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0x5a)
        );
        assert!(
            pages[2 * PAGE_SIZE..3 * PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(pages[3 * PAGE_SIZE..].iter().all(|&byte| byte == 0xa5));
    }
}

#[test]
fn test_optional_allocation_hooks_do_not_request_reservations() {
    use crate::platform::page_mgmt::{
        CowAllocationError, FixedAddressBehavior, ReserveAndCommitError,
    };

    let platform = DummyVmemBackend::EMPTY;
    // SAFETY: These fresh synthetic ranges have no users; unsupported hooks must not acquire ownership.
    unsafe {
        assert!(matches!(
            platform.reserve_and_commit_pages(
                || -> core::iter::Empty<_> {
                    panic!("unsupported allocation must not request reservations")
                },
                0x10000..0x11000,
                MemoryRegionPermissions::READ,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            ),
            Err(ReserveAndCommitError::UnsupportedByPlatform)
        ));
        assert!(matches!(
            platform.try_allocate_cow_pages(
                || -> core::iter::Empty<_> {
                    panic!("unsupported CoW must not request reservations")
                },
                0x10000,
                &[0u8; PAGE_SIZE],
                MemoryRegionPermissions::READ,
                FixedAddressBehavior::NoReplace,
            ),
            Err(CowAllocationError::UnsupportedByPlatform)
        ));
    }
}

#[test]
fn test_cow_unsupported_restores_reservation_ownership() {
    use crate::platform::page_mgmt::{CowAllocationError, FixedAddressBehavior};

    let platform = DummyVmemBackend::EMPTY;
    let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(platform));
    let mut vmem = Vmem::<_, PAGE_SIZE, Linux>::new(platform);
    let permissions = MemoryRegionPermissions::READ;
    let vma = VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAY_ACCESS_FLAGS, false);
    let content: &'static [u8] = &[0x5a; 2 * PAGE_SIZE];
    // SAFETY: This fixture exclusively owns synthetic extents; the unsupported provider never accesses them.
    unsafe {
        for range in [0x10000..0x12000, 0x12000..0x14000] {
            let reservation = platform.create_reservation(range.clone());
            vmem.reservations.insert(range.start, reservation);
            vmem.vmas.insert(range, vma);
        }
        let mappings = vmem.vmas.clone();
        let ownership = vmem.reservations().collect::<Vec<_>>();
        DUMMY_RESERVES.with_borrow_mut(Vec::clear);
        DUMMY_COMMITS.with_borrow_mut(Vec::clear);
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        assert!(matches!(
            vmem.try_create_cow_pages(
                0x11000,
                content,
                permissions,
                FixedAddressBehavior::Replace,
                false
            ),
            Err(CowAllocationError::UnsupportedByPlatform)
        ));
        assert_eq!(vmem.vmas, mappings);
        assert_eq!(vmem.reservations().collect::<Vec<_>>(), ownership);
        for (start, source) in [
            (0x11001, content),
            (0x11000, &content[..PAGE_SIZE - 1]),
            (0x11000, &content[..0]),
        ] {
            assert!(matches!(
                vmem.try_create_cow_pages(
                    start,
                    source,
                    permissions,
                    FixedAddressBehavior::Replace,
                    false
                ),
                Err(CowAllocationError::Unaligned)
            ));
            assert_eq!(vmem.vmas, mappings);
            assert_eq!(vmem.reservations().collect::<Vec<_>>(), ownership);
        }
        assert!(DUMMY_RESERVES.with_borrow(Vec::is_empty));
        assert!(DUMMY_COMMITS.with_borrow(Vec::is_empty));
        assert!(DUMMY_RELEASES.with_borrow(Vec::is_empty));
    }
}

#[test]
fn test_remap_releases_empty_partial_source_reservation() {
    const RESERVATION_ALIGN: usize = 4 * PAGE_SIZE;
    let mut storage = vec![0u8; 4 * RESERVATION_ALIGN];
    let offset = storage.as_mut_ptr().align_offset(RESERVATION_ALIGN);
    let pages = &mut storage[offset..offset + 3 * RESERVATION_ALIGN];
    pages[..2 * RESERVATION_ALIGN].fill(0x5a);
    let base = pages.as_mut_ptr() as usize;
    let source = base..base + 2 * RESERVATION_ALIGN;
    let destination = source.end..source.end + 2 * PAGE_SIZE;
    let mut vmem =
        Vmem::<_, PAGE_SIZE, Linux>::new(&MockVmemBackend::<true, RESERVATION_ALIGN>::EMPTY);
    let vma = VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS, false);
    // SAFETY: The fixture exclusively owns aligned storage; the mock never frees the buffer.
    unsafe {
        let _memory = MockMemoryGuard::new(base..base + pages.len());
        vmem.register_committed_mapping(PageRange::new(source.start, source.end).unwrap(), vma);
        vmem.unmap_mapping(PageRange::new(base, base + PAGE_SIZE).unwrap());
        vmem.unmap_mapping(PageRange::new(base + 2 * PAGE_SIZE, source.end).unwrap());
        vmem.vmas.insert(
            destination.start + RESERVATION_ALIGN..DummyVmemBackend::TASK_ADDR_MAX,
            VmArea::new(VmFlags::empty(), false),
        );
        DUMMY_RELEASES.with_borrow_mut(Vec::clear);
        let moved = vmem
            .move_mappings(
                PageRange::new(base + PAGE_SIZE, base + 2 * PAGE_SIZE).unwrap(),
                NonZeroAddress::new(destination.start),
                NonZeroPageSize::new(destination.len()).unwrap(),
            )
            .unwrap();
        assert_eq!(moved.as_usize(), destination.start);
        assert_eq!(vmem.vmas.len(), 2);
        assert_eq!(
            vmem.vmas.get_key_value(&destination.start),
            Some((&destination, &vma))
        );
        assert_eq!(vmem.reservations.len(), 1);
        assert_eq!(
            vmem.reservations[&destination.start].range(),
            destination.start..destination.start + RESERVATION_ALIGN
        );
        DUMMY_RELEASES
            .with_borrow(|actual| assert_eq!(actual.as_slice(), core::slice::from_ref(&source)));
        assert!(
            pages[2 * RESERVATION_ALIGN..2 * RESERVATION_ALIGN + PAGE_SIZE]
                .iter()
                .all(|&byte| byte == 0x5a)
        );
    }
}

#[test]
fn test_vmm_mapping() {
    let automatic_top = (DummyVmemBackend::TASK_ADDR_MAX & !(PAGE_SIZE - 1)) - PAGE_SIZE;
    let mut storage = vec![0u8; 17 * PAGE_SIZE];
    let offset = storage.as_mut_ptr().align_offset(PAGE_SIZE);
    let pages = &mut storage[offset..offset + 16 * PAGE_SIZE];
    let start_addr = pages.as_mut_ptr() as usize;
    // SAFETY: This aligned buffer outlives the guard and is exclusively held by this test.
    let _memory = unsafe { MockMemoryGuard::new(start_addr..start_addr + pages.len()) };
    let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
    let mut vmm = Vmem::<_, PAGE_SIZE, Linux>::new(&DummyVmemBackend::EMPTY);

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
        vmm.unmap_mapping(
            PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
        );
    }
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
        Err(VmemProtectError::NotCommitted(_))
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

    pages[2 * PAGE_SIZE] = 0x5a;
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
    assert_eq!(pages[12 * PAGE_SIZE], 0x5a);
    assert_eq!(pages[14 * PAGE_SIZE], 0);
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE
        ]
    );

    // create new mapping with no suggested address
    let owned: rangemap::RangeMap<usize, ()> =
        vmm.reservations().map(|range| (range, ())).collect();
    assert!(owned.overlaps(&(start_addr + 2 * PAGE_SIZE..start_addr + 4 * PAGE_SIZE)));
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
        automatic_top,
    );
    assert_eq!(
        collect_mappings(&vmm),
        vec![
            start_addr..start_addr + 2 * PAGE_SIZE,
            start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
            start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
            automatic_top..automatic_top + PAGE_SIZE,
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
            automatic_top..automatic_top + PAGE_SIZE,
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
            automatic_top..automatic_top + PAGE_SIZE,
        ]
    );
}
