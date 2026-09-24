// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::raw::c_void;

#[cfg(test)]
use core::sync::atomic::Ordering;
use litebox::platform::RawConstPointer as _;
use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions, PageReservation,
    PageStateUpdateError, ReserveAndCommitError, TrackedReservations,
};
use windows_sys::Win32::{
    Foundation::{self as Win32_Foundation, GetLastError},
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::Threading::GetCurrentProcess,
};

use crate::{UserMutPtr, WindowsUserland, WindowsUserlandReservation};

#[allow(
    clippy::match_same_arms,
    reason = "Iterate over all cases for prot_flags."
)]
fn prot_flags(flags: MemoryRegionPermissions) -> Win32_Memory::PAGE_PROTECTION_FLAGS {
    match (
        flags.contains(MemoryRegionPermissions::READ),
        flags.contains(MemoryRegionPermissions::WRITE),
        flags.contains(MemoryRegionPermissions::EXEC),
    ) {
        // no permissions
        (false, false, false) => Win32_Memory::PAGE_NOACCESS,
        // read-only
        (true, false, false) => Win32_Memory::PAGE_READONLY,
        // write-only (Windows doesn't have write-only, so we use r+w)
        (false, true, false) => Win32_Memory::PAGE_READWRITE,
        // read-write
        (true, true, false) => Win32_Memory::PAGE_READWRITE,
        // exeute-only (Windows doesn't have execute-only, so we use r+x)
        (false, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // read-execute
        (true, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // write-execute (Windows doesn't have write-execute, so we use rwx)
        (false, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
        // read-write-execute
        (true, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
    }
}

fn do_prefetch_on_range(start: usize, size: usize) {
    let ok = unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0) != 0
    };
    assert!(ok, "PrefetchVirtualMemory failed with error: {}", unsafe {
        GetLastError()
    });
}

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

impl WindowsUserland {
    /// Decommits pages within a native reservation.
    ///
    /// # Safety
    ///
    /// The caller must own the range and exclude all users.
    unsafe fn decommit_native(range: core::ops::Range<usize>) {
        // SAFETY: The caller owns this range within one reservation and excludes active users.
        assert_ne!(
            unsafe {
                VirtualFree(
                    range.start as *mut c_void,
                    range.len(),
                    Win32_Memory::MEM_DECOMMIT,
                )
            },
            0
        );
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "Failure injection uses self only in tests."
        )
    )]
    unsafe fn commit_native(
        &self,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PageStateUpdateError> {
        #[cfg(test)]
        if self.fail_commit_at.load(Ordering::Relaxed) == range.start {
            return Err(PageStateUpdateError::OutOfMemory);
        }
        // SAFETY: The caller owns this range within one native reservation and excludes conflicting accesses.
        let pointer = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                range.start as *mut c_void,
                range.len(),
                Win32_Memory::MEM_COMMIT,
                prot_flags(permissions),
                core::ptr::null_mut(),
                0,
            )
        };
        if pointer.is_null() {
            return Err(PageStateUpdateError::OutOfMemory);
        }
        assert_eq!(pointer.addr(), range.start);
        Ok(())
    }
}

impl WindowsUserland {
    pub(super) const RESERVATION_ALIGNMENT: usize = 0x10000;

    /// Reserves the requested range, optionally committing it. Hints may relocate.
    fn reserve_native<const ALIGN: usize>(
        suggested_range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<UserMutPtr<u8>, AllocationError> {
        if suggested_range.is_empty()
            || !suggested_range.start.is_multiple_of(
                <Self as litebox::platform::PageManagementProvider<ALIGN>>::RESERVATION_ALIGNMENT,
            )
            || !suggested_range.len().is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        if suggested_range.start == 0 && behavior != FixedAddressBehavior::Hint {
            return Err(AllocationError::BelowMinAddress);
        }
        let start = suggested_range.start;
        let size = suggested_range.len();
        let reserve = |address| {
            // SAFETY: MEM_RESERVE acquires fresh address space even when combined with MEM_COMMIT.
            unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    address,
                    size,
                    Win32_Memory::MEM_RESERVE
                        | if permissions.is_some() {
                            Win32_Memory::MEM_COMMIT
                        } else {
                            0
                        },
                    permissions.map_or(Win32_Memory::PAGE_NOACCESS, prot_flags),
                    core::ptr::null_mut(),
                    0,
                )
            }
        };
        let mut pointer = reserve(start as *mut c_void);
        if pointer.is_null() && start != 0 && behavior == FixedAddressBehavior::Hint {
            // The OS-selected fallback may not preserve the page manager's bottom-up or top-down
            // search direction; hints permit relocation to any available address.
            pointer = reserve(core::ptr::null_mut());
        }
        if pointer.is_null() {
            // SAFETY: Read the failure code from the immediately preceding allocation call.
            return Err(match unsafe { GetLastError() } {
                Win32_Foundation::ERROR_INVALID_ADDRESS => AllocationError::AddressInUseByPlatform,
                _ => AllocationError::OutOfMemory,
            });
        }
        Ok(UserMutPtr::from_ptr(pointer.cast()))
    }

    /// Releases a native reservation.
    ///
    /// # Safety
    ///
    /// `base` must identify an exclusively owned reservation with no remaining users.
    unsafe fn release_native(base: usize) {
        // SAFETY: The caller owns the complete native reservation and excludes all users.
        let released = unsafe { VirtualFree(base as *mut c_void, 0, Win32_Memory::MEM_RELEASE) };
        assert_ne!(
            released,
            0,
            "failed to release owned reservation: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl WindowsUserland {
    fn allocate_native_reservation<const ALIGN: usize>(
        &self,
        range: core::ops::Range<usize>,
        permissions: Option<MemoryRegionPermissions>,
        behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        let minimum = <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN;
        let maximum = <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
        if range.is_empty()
            || !range.start.is_multiple_of(ALIGN)
            || !range.end.is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        if range.start < minimum && !(range.start == 0 && behavior == FixedAddressBehavior::Hint) {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > maximum {
            return Err(AllocationError::AboveMaxAddress);
        }
        let reusable_backing = {
            let mut reservations = self.native_reservations.lock().unwrap();
            reservations.values_mut().find_map(|reservation| {
                let is_covered =
                    reservation.range.start <= range.start && range.end <= reservation.range.end;
                let is_available = reservation
                    .owned
                    .iter()
                    .all(|owned| range.end <= owned.start || owned.end <= range.start);
                (is_covered && is_available).then(|| {
                    reservation.owned.push(range.clone());
                    reservation.range.clone()
                })
            })
        };
        if let Some(backing) = reusable_backing {
            if let Some(permissions) = permissions {
                // SAFETY: The registry transferred this currently unowned reserved range.
                if unsafe { self.commit_native(range.clone(), permissions) }.is_err() {
                    let mut reservations = self.native_reservations.lock().unwrap();
                    let reservation = reservations
                        .get_mut(&backing.start)
                        .expect("registered backing must remain live");
                    reservation.owned.retain(|owned| owned != &range);
                    return Err(AllocationError::OutOfMemory);
                }
            }
            // SAFETY: The registry granted unique ownership within this live native backing.
            return Ok(unsafe { WindowsUserlandReservation::new_with_backing(range, backing) });
        }
        let extent = range;
        let base = Self::reserve_native::<ALIGN>(
            extent.clone(),
            match behavior {
                FixedAddressBehavior::Hint => FixedAddressBehavior::Hint,
                FixedAddressBehavior::NoReplace | FixedAddressBehavior::Replace => {
                    FixedAddressBehavior::NoReplace
                }
            },
            permissions,
        )?
        .as_usize();
        let end = base + extent.len();
        if base < minimum || end > maximum {
            // SAFETY: This fresh native reservation has not been published or accessed.
            unsafe { Self::release_native(base) };
            return Err(AllocationError::OutOfMemory);
        }
        let backing = base..end;
        self.native_reservations.lock().unwrap().insert(
            base,
            crate::NativeReservation {
                range: backing.clone(),
                owned: vec![backing.clone()],
            },
        );
        // SAFETY: Native reservation acquired this fresh exact extent with no other owner.
        Ok(unsafe { WindowsUserlandReservation::new_with_backing(backing.clone(), backing) })
    }
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    type Reservations = TrackedReservations<WindowsUserlandReservation<ALIGN>>;

    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    const RESERVATION_ALIGNMENT: usize = WindowsUserland::RESERVATION_ALIGNMENT;

    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        _can_grow_down: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        let reservation = self.allocate_native_reservation(range, None, behavior)?;
        if behavior == FixedAddressBehavior::Replace {
            replaced_reservations().for_each(drop);
        }
        Ok(reservation)
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        _can_grow_down: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, ReserveAndCommitError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        if behavior == FixedAddressBehavior::Replace {
            return Err(ReserveAndCommitError::UnsupportedByPlatform);
        }
        let reservation = self.allocate_native_reservation(range, Some(permissions), behavior)?;
        if populate {
            let extent = reservation.range();
            do_prefetch_on_range(extent.start, extent.len());
        }
        Ok(reservation)
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert_alignment!(range, ALIGN);
        let mut previous_regions = Vec::new();
        let mut cursor = range.start;
        while cursor < range.end {
            let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            // SAFETY: VirtualQuery only reads metadata for the supplied address.
            let queried = unsafe {
                Win32_Memory::VirtualQuery(
                    cursor as *const c_void,
                    &raw mut information,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                )
            };
            assert_ne!(
                queried,
                0,
                "failed to query owned backing: {}",
                std::io::Error::last_os_error()
            );
            let region_end = information.BaseAddress.addr() + information.RegionSize;
            assert!(information.BaseAddress.addr() <= cursor && cursor < region_end);
            let segment = cursor..region_end.min(range.end);
            previous_regions.push((segment.clone(), information.State, information.Protect));
            cursor = segment.end;
        }
        for reservation in covering_reservations() {
            let extent = reservation.range();
            let segment = extent.start.max(range.start)..extent.end.min(range.end);
            // SAFETY: The caller supplies pages in this live native reservation and excludes conflicting accesses.
            if let Err(error) = unsafe { self.commit_native(segment, permissions) } {
                for (previous, state, protection) in previous_regions {
                    if state == Win32_Memory::MEM_RESERVE {
                        // SAFETY: This range was uncommitted before the failed operation and has no users.
                        unsafe { Self::decommit_native(previous) };
                    } else {
                        assert_eq!(state, Win32_Memory::MEM_COMMIT);
                        let mut ignored = 0;
                        // SAFETY: This restores the protection recorded before the failed operation.
                        assert_ne!(
                            unsafe {
                                VirtualProtect(
                                    previous.start as *mut c_void,
                                    previous.len(),
                                    protection,
                                    &raw mut ignored,
                                )
                            },
                            0,
                            "failed to restore owned backing: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
                return Err(error);
            }
        }
        if populate {
            do_prefetch_on_range(range.start, range.len());
        }
        Ok(())
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert_alignment!(range, ALIGN);
        for reservation in covering_reservations() {
            let extent = reservation.range();
            let segment = extent.start.max(range.start)..extent.end.min(range.end);
            // SAFETY: The caller owns this subrange of one native reservation and excludes users.
            unsafe { Self::decommit_native(segment) };
        }
        Ok(())
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert_alignment!(range, ALIGN);
        for reservation in covering_reservations() {
            let extent = reservation.range();
            let segment = extent.start.max(range.start)..extent.end.min(range.end);
            let mut previous = 0;
            // SAFETY: The caller supplies committed pages within one reservation and excludes conflicting accesses.
            assert_ne!(
                unsafe {
                    VirtualProtect(
                        segment.start as *mut c_void,
                        segment.len(),
                        prot_flags(permissions),
                        &raw mut previous,
                    )
                },
                0,
                "failed to protect owned backing: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    unsafe fn release_pages(&self, reservation: WindowsUserlandReservation<ALIGN>) {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtFreeVirtualMemory(
                process: windows_sys::Win32::Foundation::HANDLE,
                address: *mut *mut c_void,
                length: *mut usize,
                kind: u32,
            ) -> i32;
        }
        let (range, backing) = reservation.into_parts();
        assert!(!range.is_empty());
        debug_assert_alignment!(range, ALIGN);
        let release_backing = {
            let mut reservations = self.native_reservations.lock().unwrap();
            let Some(native) = reservations.get_mut(&backing.start) else {
                drop(reservations);
                let mut address = range.start as *mut c_void;
                let mut length = range.len();
                // SAFETY: This unregistered fixture handle owns the supplied exact extent.
                let status = unsafe {
                    NtFreeVirtualMemory(
                        GetCurrentProcess(),
                        &raw mut address,
                        &raw mut length,
                        Win32_Memory::MEM_RELEASE,
                    )
                };
                assert_eq!(status, 0, "failed to release owned backing: {status:#x}");
                assert_eq!(address.addr(), range.start);
                assert_eq!(length, range.len());
                return;
            };
            let mut survivors = Vec::new();
            let mut removed = 0;
            for owned in native.owned.drain(..) {
                let start = owned.start.max(range.start);
                let end = owned.end.min(range.end);
                if start < end {
                    removed += end - start;
                    if owned.start < start {
                        survivors.push(owned.start..start);
                    }
                    if end < owned.end {
                        survivors.push(end..owned.end);
                    }
                } else {
                    survivors.push(owned);
                }
            }
            assert_eq!(removed, range.len());
            native.owned = survivors;
            if native.owned.is_empty() {
                reservations.remove(&backing.start);
                true
            } else {
                false
            }
        };
        if !release_backing {
            // SAFETY: The released logical extent remains inside live registered native backing.
            unsafe { Self::decommit_native(range) };
            return;
        }
        let mut address = backing.start as *mut c_void;
        let mut length = backing.len();
        // SAFETY: The handle owns this extent exclusively; no users depend on the released pages.
        let status = unsafe {
            NtFreeVirtualMemory(
                GetCurrentProcess(),
                &raw mut address,
                &raw mut length,
                Win32_Memory::MEM_RELEASE,
            )
        };
        assert_eq!(status, 0, "failed to release owned backing: {status:#x}");
        assert_eq!(address.addr(), backing.start);
        assert_eq!(length, backing.len());
    }
}

/// Page-fault handler stub for faults handled by the host kernel.
impl litebox::mm::linux::VmemPageFaultHandler for WindowsUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Windows userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Windows userland")
    }
}

#[cfg(test)]
mod tests {
    use std::os::raw::c_void;

    use crate::WindowsUserland;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::RawConstPointer;
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox::platform::page_mgmt::PageReservation as _;
    use windows_sys::Win32::System::Memory as Win32_Memory;

    use super::PageStateUpdateError;
    use windows_sys::Win32::Foundation::GetLastError;

    fn do_query_on_region(
        mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION,
        base_addr: *mut c_void,
    ) {
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                base_addr,
                mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        assert!(ok, "VirtualQuery addr={:p} failed: {}", base_addr, unsafe {
            GetLastError()
        });
    }

    unsafe fn release_reservations<const ALIGN: usize>(
        platform: &WindowsUserland,
        reservations: Vec<litebox::platform::page_mgmt::ReservationOf<WindowsUserland, ALIGN>>,
    ) {
        for reservation in reservations {
            // SAFETY: The fixture relinquishes this exact owned extent without remaining users.
            unsafe {
                platform.release_pages(reservation);
            }
        }
    }

    #[test]
    fn test_batched_commit_failure_restores_native_state() {
        const PAGE_SIZE: usize = 4096;
        const GRANULARITY: usize = 0x10000;
        let platform = WindowsUserland::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture exclusively owns all acquired private anonymous pages and excludes users during updates and release.
        unsafe {
            let probe = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                0..3 * GRANULARITY,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            let base = probe.range().start;
            release_reservations::<PAGE_SIZE>(platform, vec![probe]);
            let mut reservations = Vec::new();
            for offset in (0..3 * GRANULARITY).step_by(GRANULARITY) {
                let address = base + offset;
                let reservation =
                    <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                        platform,
                        || -> core::iter::Empty<_> {
                            panic!("no-replace reserve must not request reservations")
                        },
                        address..address + GRANULARITY,
                        false,
                        FixedAddressBehavior::NoReplace,
                    )
                    .unwrap();
                <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                    platform,
                    || core::iter::once(&reservation),
                    address..address + 3 * PAGE_SIZE,
                    writable,
                    false,
                )
                .unwrap();
                (address as *mut u8).write(0x5a);
                ((address + PAGE_SIZE) as *mut u8).write(0xa5);
                ((address + 2 * PAGE_SIZE) as *mut u8).write(0x7e);
                for (offset, permissions) in [
                    (PAGE_SIZE, MemoryRegionPermissions::READ),
                    (2 * PAGE_SIZE, MemoryRegionPermissions::empty()),
                ] {
                    <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                        platform,
                        || core::iter::once(&reservation),
                        address + offset..address + offset + PAGE_SIZE,
                        permissions,
                    )
                    .unwrap();
                }
                reservations.push(reservation);
            }
            let extent = base..base + 3 * GRANULARITY;
            let request = base + PAGE_SIZE..extent.end - PAGE_SIZE;
            let snapshot = || {
                extent
                    .clone()
                    .step_by(PAGE_SIZE)
                    .map(|address| {
                        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                        do_query_on_region(&mut information, address as *mut c_void);
                        (
                            information.State,
                            information.Protect,
                            information.AllocationBase.addr(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            let before = snapshot();
            for failure in [request.start, base + GRANULARITY, base + 2 * GRANULARITY] {
                platform
                    .fail_commit_at
                    .store(failure, core::sync::atomic::Ordering::Relaxed);
                assert!(matches!(
                    <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                        platform,
                        || reservations.iter(),
                        request.clone(),
                        writable,
                        true,
                    ),
                    Err(PageStateUpdateError::OutOfMemory)
                ));
                platform
                    .fail_commit_at
                    .store(0, core::sync::atomic::Ordering::Relaxed);
                assert_eq!(snapshot(), before);
                for (index, reservation) in reservations.iter().enumerate() {
                    let address = base + index * GRANULARITY;
                    assert_eq!(reservation.range(), address..address + GRANULARITY);
                    assert_eq!((address as *const u8).read(), 0x5a);
                    assert_eq!(((address + PAGE_SIZE) as *const u8).read(), 0xa5);
                    let hidden = address + 2 * PAGE_SIZE..address + 3 * PAGE_SIZE;
                    <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                        platform,
                        || core::iter::once(reservation),
                        hidden.clone(),
                        MemoryRegionPermissions::READ,
                    )
                    .unwrap();
                    assert_eq!((hidden.start as *const u8).read(), 0x7e);
                    <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                        platform,
                        || core::iter::once(reservation),
                        hidden,
                        MemoryRegionPermissions::empty(),
                    )
                    .unwrap();
                }
            }
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || reservations.iter(),
                request.clone(),
                MemoryRegionPermissions::READ,
                false,
            )
            .unwrap();
            for address in request.clone().step_by(PAGE_SIZE) {
                let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut information, address as *mut c_void);
                assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                assert_eq!(information.Protect, Win32_Memory::PAGE_READONLY);
                let expected = match (address - base) % GRANULARITY {
                    0 => 0x5a,
                    PAGE_SIZE => 0xa5,
                    offset if offset == 2 * PAGE_SIZE => 0x7e,
                    _ => 0,
                };
                assert_eq!((address as *const u8).read(), expected);
            }
            release_reservations::<PAGE_SIZE>(platform, reservations);
        }
    }

    #[test]
    fn test_page_backend_native_remap_is_unsupported() {
        type Pages = WindowsUserland;
        for permissions in [
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ,
        ] {
            let platform = WindowsUserland::new();
            // SAFETY: Hint placement acquires a fresh exact source extent owned by this fixture.
            let source = unsafe {
                <Pages as PageManagementProvider<4096>>::reserve_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("hint reserve must not request reservations")
                    },
                    0..4096,
                    false,
                    FixedAddressBehavior::Hint,
                )
            }
            .unwrap();
            let base = source.range().start;
            // SAFETY: The fixture owns the source; the unsupported native hook must not access the destination.
            unsafe {
                <Pages as PageManagementProvider<4096>>::commit_pages(
                    platform,
                    || core::iter::once(&source),
                    source.range(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                    false,
                )
                .unwrap();
                (base as *mut u8).write(0x5a);
                <Pages as PageManagementProvider<4096>>::protect_pages(
                    platform,
                    || core::iter::once(&source),
                    source.range(),
                    permissions,
                )
                .unwrap();
                let mut remaining = vec![source];
                let error = <Pages as PageManagementProvider<4096>>::try_remap_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("unsupported remap must not request reservations")
                    },
                    base..base + 4096,
                    0..8192,
                    permissions,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform
                ));
                assert_eq!(remaining.len(), 1);
                let source = remaining.pop().unwrap();
                assert_eq!(source.range(), base..base + 4096);
                let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut information, base as *mut c_void);
                assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                assert_eq!(information.Protect, super::prot_flags(permissions));
                <Pages as PageManagementProvider<4096>>::protect_pages(
                    platform,
                    || core::iter::once(&source),
                    source.range(),
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
                assert_eq!((base as *const u8).read(), 0x5a);
                <Pages as PageManagementProvider<4096>>::decommit_pages(
                    platform,
                    || core::iter::once(&source),
                    source.range(),
                )
                .unwrap();
                release_reservations::<4096>(platform, vec![source]);
            }
        }
    }

    #[test]
    fn test_page_reservation_alignment_and_exact_size() {
        use litebox::platform::page_mgmt::AllocationError;

        const PAGE_SIZE: usize = 4096;
        let base = WindowsUserland::reserve_native::<PAGE_SIZE>(
            0..PAGE_SIZE,
            FixedAddressBehavior::Hint,
            None,
        )
        .unwrap()
        .as_usize();
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: The test owns the complete reservation and has no active users.
            unsafe { WindowsUserland::release_native(base) };
        });
        assert!(base.is_multiple_of(WindowsUserland::RESERVATION_ALIGNMENT));
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, base as *mut c_void);
        assert_eq!(information.BaseAddress.addr(), base);
        assert_eq!(information.RegionSize, PAGE_SIZE);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        for behavior in [
            FixedAddressBehavior::Hint,
            FixedAddressBehavior::NoReplace,
            FixedAddressBehavior::Replace,
        ] {
            assert!(matches!(
                WindowsUserland::reserve_native::<PAGE_SIZE>(
                    base + PAGE_SIZE..base + 2 * PAGE_SIZE,
                    behavior,
                    None,
                ),
                Err(AllocationError::Unaligned)
            ));
        }
    }
}
