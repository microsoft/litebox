// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    AllocationError, FixedAddressBehavior, GetCurrentProcess, GetLastError, MEM_TOP_DOWN,
    MemoryRegionPermissions, PrefetchVirtualMemory, UserMutPtr, VirtualAlloc2, VirtualFree,
    VirtualProtect, Win32_Memory, WindowsUserland, c_void,
};
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{
    AllocationDirection, HintPlacementBehavior, PageReservation as _,
};

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

impl<const ALIGN: usize> WindowsUserland<ALIGN> {
    fn allocate_native_reservation(
        range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        debug_assert!(range.start.is_multiple_of(
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::RESERVATION_ALIGNMENT,
        ));
        debug_assert!(range.end.is_multiple_of(ALIGN));
        let reserve = |address| unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                address,
                range.len(),
                Win32_Memory::MEM_RESERVE
                    | if permissions.is_some() {
                        Win32_Memory::MEM_COMMIT
                    } else {
                        0
                    }
                    | if matches!(
                        behavior,
                        FixedAddressBehavior::Hint(AllocationDirection::TopDown)
                    ) {
                        MEM_TOP_DOWN
                    } else {
                        0
                    },
                permissions.map_or(Win32_Memory::PAGE_NOACCESS, prot_flags),
                core::ptr::null_mut(),
                0,
            )
        };
        let mut ptr = reserve(range.start as *mut c_void);
        if ptr.is_null() && range.start != 0 && matches!(behavior, FixedAddressBehavior::Hint(_)) {
            ptr = reserve(core::ptr::null_mut());
        }
        if ptr.is_null() {
            return Err(if range.start == 0 {
                AllocationError::OutOfMemory
            } else {
                AllocationError::AddressInUse
            });
        }

        let base = ptr as usize;
        let extent = base..base + range.len();
        // SAFETY: VirtualAlloc2 successfully returned exclusive ownership of this aligned extent.
        Ok(unsafe { WindowsUserlandReservation::new(extent) })
    }

    fn release_reservation(reservation: WindowsUserlandReservation<ALIGN>) {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtFreeVirtualMemory(
                process: windows_sys::Win32::Foundation::HANDLE,
                base: *mut *mut c_void,
                size: *mut usize,
                free_type: Win32_Memory::VIRTUAL_FREE_TYPE,
            ) -> windows_sys::Win32::Foundation::NTSTATUS;
        }
        let extent = reservation.range();
        let mut base = extent.start as *mut c_void;
        let mut size = extent.len();
        // Unlike `VirtualFree`, a sized native release frees page-aligned split sub-extents.
        // SAFETY: The reservation exclusively owns this extent and the caller excludes all users.
        let status = unsafe {
            NtFreeVirtualMemory(
                GetCurrentProcess(),
                &raw mut base,
                &raw mut size,
                Win32_Memory::MEM_RELEASE,
            )
        };
        assert!(
            status >= 0,
            "NtFreeVirtualMemory(RELEASE) failed: {status:#x}"
        );
        debug_assert_eq!(base as usize..base as usize + size, extent);
    }

    fn commit_reservations<'reservation>(
        reservations: impl Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        range: core::ops::Range<usize>,
        flags: Win32_Memory::PAGE_PROTECTION_FLAGS,
    ) -> bool
    where
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        for reservation in reservations {
            let reserved = reservation.range();
            let segment = range.start.max(reserved.start)..range.end.min(reserved.end);
            let ptr = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    segment.start as *mut c_void,
                    segment.len(),
                    Win32_Memory::MEM_COMMIT,
                    flags,
                    core::ptr::null_mut(),
                    0,
                )
            };
            if ptr.is_null() {
                return false;
            }
        }

        true
    }

    fn decommit_reservations<'reservation>(
        reservations: impl Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        range: core::ops::Range<usize>,
    ) where
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        for reservation in reservations {
            let reserved = reservation.range();
            let segment = range.start.max(reserved.start)..range.end.min(reserved.end);
            assert_ne!(
                unsafe {
                    VirtualFree(
                        segment.start as *mut c_void,
                        segment.len(),
                        Win32_Memory::MEM_DECOMMIT,
                    )
                },
                0,
                "VirtualFree(DECOMMIT) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

litebox::define_page_reservation!(WindowsUserlandReservation);

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN>
    for WindowsUserland<ALIGN>
{
    type Reservations = TrackedReservations<WindowsUserlandReservation<ALIGN>>;

    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_0000;
    const RESERVATION_ALIGNMENT: usize = 0x1_0000;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Bidirectional;

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert!(
            suggested_range.start >= Self::TASK_ADDR_MIN
                || (suggested_range.start == 0
                    && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
        );
        debug_assert!(suggested_range.end <= Self::TASK_ADDR_MAX);
        if !suggested_range
            .start
            .is_multiple_of(Self::RESERVATION_ALIGNMENT)
            || !suggested_range.end.is_multiple_of(ALIGN)
            || suggested_range.is_empty()
        {
            return Err(AllocationError::Unaligned);
        }
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN feature so far.
        let _ = can_grow_down;
        let reservation = Self::allocate_native_reservation(
            suggested_range,
            fixed_address_behavior,
            Some(permissions),
        )?;
        if populate_pages_immediately {
            let extent = reservation.range();
            do_prefetch_on_range(extent.start, extent.len());
        }
        Ok(reservation)
    }

    unsafe fn reserve_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert!(
            (suggested_range.start == 0
                && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
                || suggested_range.start
                    >= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
        );
        debug_assert!(
            suggested_range.end
                <= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
        );
        if !(suggested_range
            .start
            .is_multiple_of(Self::RESERVATION_ALIGNMENT))
            || !suggested_range.end.is_multiple_of(ALIGN)
            || suggested_range.is_empty()
        {
            return Err(AllocationError::Unaligned);
        }
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;
        let reservation =
            Self::allocate_native_reservation(suggested_range, fixed_address_behavior, None)?;
        Ok(reservation)
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate_pages_immediately: bool,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        if !Self::commit_reservations(
            covering_reservations(),
            range.clone(),
            prot_flags(permissions),
        ) {
            return Err(AllocationError::OutOfMemory);
        }
        if populate_pages_immediately {
            do_prefetch_on_range(range.start, range.len());
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        Self::decommit_reservations(covering_reservations(), range);
        Ok(())
    }

    unsafe fn release_pages(
        &self,
        reservation: WindowsUserlandReservation<ALIGN>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        Self::release_reservation(reservation);
        Ok(())
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(permissions);
        for reservation in covering_reservations() {
            let reserved = reservation.range();
            let segment = range.start.max(reserved.start)..range.end.min(reserved.end);
            let mut old_protect = 0;
            assert_ne!(
                unsafe {
                    VirtualProtect(
                        segment.start as *mut c_void,
                        segment.len(),
                        flags,
                        &raw mut old_protect,
                    )
                },
                0,
                "VirtualProtect failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;
    use litebox::platform::{PageManagementProvider, RawConstPointer};

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

    /// Helper method to process a memory range by iterating through Windows memory regions.
    ///
    /// Windows memory is managed in Virtual Address Descriptors (VADs) at the NT kernel level,
    /// which means a single user-space range might span multiple regions. This helper method
    /// queries each region within the specified range and applies the given operation.
    ///
    /// # Parameters
    /// - `range`: The memory range to process
    /// - `operation`: A closure that takes (region_range, region_state) and returns Result<bool, E>.
    ///
    /// # Panics
    ///
    /// Panics if the operation returns false for any region.
    fn process_memory_range_by_regions<F, E>(
        mut range: core::ops::Range<usize>,
        mut operation: F,
    ) -> Result<(), E>
    where
        F: FnMut(core::ops::Range<usize>, Win32_Memory::VIRTUAL_ALLOCATION_TYPE) -> Result<bool, E>,
    {
        while !range.is_empty() {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut mbi, range.start as *mut c_void);
            debug_assert_eq!(range.start, mbi.BaseAddress as usize);
            let len = mbi.RegionSize.min(range.len());
            let success = operation(range.start..range.start + len, mbi.State)?;
            assert!(
                success,
                "operation failed on region {:p}-{:p}: {}",
                range.start as *mut c_void,
                (range.start + len) as *mut c_void,
                std::io::Error::last_os_error()
            );
            range = (range.start + len)..range.end;
        }
        Ok(())
    }

    fn collect_regions(
        range: core::ops::Range<usize>,
    ) -> Vec<(
        core::ops::Range<usize>,
        Win32_Memory::VIRTUAL_ALLOCATION_TYPE,
    )> {
        let mut regions = Vec::new();
        process_memory_range_by_regions(
            range,
            |region, state| -> Result<bool, core::convert::Infallible> {
                regions.push((region, state));
                Ok(true)
            },
        )
        .unwrap();
        regions
    }

    #[test]
    fn test_release_split_reservations() {
        let platform = WindowsUserland::new();
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                suggested..suggested + 0x2_0000,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                false,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let (prefix, middle, suffix) = reservation.split(base + PAGE_SIZE..base + 2 * PAGE_SIZE);
        let (prefix, suffix) = (prefix.unwrap(), suffix.unwrap());

        // SAFETY: The split handle exclusively owns the unused middle page.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle)
        }
        .unwrap();
        assert_eq!(
            collect_regions(base..base + 0x2_0000),
            vec![
                (base..base + PAGE_SIZE, Win32_Memory::MEM_COMMIT),
                (
                    base + PAGE_SIZE..base + 2 * PAGE_SIZE,
                    Win32_Memory::MEM_FREE
                ),
                (
                    base + 2 * PAGE_SIZE..base + 0x2_0000,
                    Win32_Memory::MEM_COMMIT
                ),
            ]
        );

        for remainder in [prefix, suffix] {
            // SAFETY: Each split handle exclusively owns its unused remainder.
            unsafe {
                <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                    platform, remainder,
                )
            }
            .unwrap();
        }
        assert_eq!(
            collect_regions(base..base + 0x2_0000),
            vec![(base..base + 0x2_0000, Win32_Memory::MEM_FREE)]
        );
    }

    #[test]
    fn test_reserve_and_commit_pages() {
        let platform = WindowsUserland::new();
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains the returned exclusive ownership until release.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                suggested..suggested + PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                false,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let range = reservation.range();
        assert_eq!(range.len(), PAGE_SIZE);
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, range.start as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
        // SAFETY: The occupied range is only a hint, and the fixture retains both handles.
        let relocated = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                range.clone(),
                MemoryRegionPermissions::READ,
                false,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        assert_ne!(relocated.range().start, range.start);
        // SAFETY: The fixture relinquishes the relocated reservation before its original hint.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform, relocated,
            )
        }
        .unwrap();
        // SAFETY: The fixture relinquishes the reservation after all accesses are complete.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform,
                reservation,
            )
        }
        .unwrap();
    }

    #[test]
    fn test_page_provider() {
        let platform = WindowsUserland::new();
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Reserve one native extent, then commit only the requested pages within it.
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                core::iter::empty,
                suggested..suggested + system_allocation_granularity,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let addr = reservation.range().start;
        // SAFETY: The retained reservation covers this range and has no conflicting users.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                addr..addr + 0x1000,
                MemoryRegionPermissions::WRITE,
                true,
            )
        }
        .unwrap();
        assert_eq!(
            collect_regions(addr..addr + system_allocation_granularity),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + system_allocation_granularity,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
            ]
        );

        assert!(system_allocation_granularity >= 0x1_0000);
        // We should be able to allocate [addr + 0x8000, addr + 0x1_0000)
        // SAFETY: The retained reservation covers this range and has no conflicting users.
        let addr2 = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                (addr + 0x8000)..(addr + 0x1_0000),
                MemoryRegionPermissions::WRITE,
                true,
            )
        }
        .unwrap()
        .as_usize();
        // Even though `fixed_address` is false, we should still get the requested address if it's free.
        assert_eq!(addr2, addr + 0x8000);
        assert_eq!(
            collect_regions(addr..addr + 0x1_0000),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + 0x8000,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
                (
                    addr + 0x8000..addr + 0x1_0000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
            ]
        );
        // SAFETY: The fixture relinquishes its reservation after all accesses are complete.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform,
                reservation,
            )
        }
        .unwrap();
    }
}
