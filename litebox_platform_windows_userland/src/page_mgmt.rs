// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    AllocationError, FixedAddressBehavior, GetCurrentProcess, GetLastError, MEM_TOP_DOWN,
    MemoryRegionPermissions, PrefetchVirtualMemory, UserMutPtr, VirtualAlloc2, VirtualFree,
    VirtualProtect, Win32_Memory, WindowsUserland, c_void,
};
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{AllocationDirection, HintPlacementBehavior, PageReservation};

/// `MEM_COALESCE_PLACEHOLDERS`, which `windows-sys` does not define.
const MEM_COALESCE_PLACEHOLDERS: Win32_Memory::VIRTUAL_FREE_TYPE = 0x1;

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

/// Initial state of a fresh native reservation.
#[derive(Clone, Copy)]
enum NativeReservation {
    /// Inaccessible reserved address space.
    Reserved,
    /// Inaccessible reserved address space that can later be coalesced with adjacent
    /// mergeable reservations.
    Mergeable,
    /// Address space committed with the given permissions.
    Committed(MemoryRegionPermissions),
}

impl<const ALIGN: usize> WindowsUserland<ALIGN> {
    fn allocate_native_reservation(
        range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
        kind: NativeReservation,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        debug_assert!(range.start.is_multiple_of(
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::RESERVATION_ALIGNMENT,
        ));
        debug_assert!(range.end.is_multiple_of(ALIGN));
        let (state_flags, protection) = match kind {
            NativeReservation::Reserved => (0, Win32_Memory::PAGE_NOACCESS),
            // A mergeable reservation starts as a native placeholder so it can be coalesced later.
            NativeReservation::Mergeable => (
                Win32_Memory::MEM_RESERVE_PLACEHOLDER,
                Win32_Memory::PAGE_NOACCESS,
            ),
            NativeReservation::Committed(permissions) => {
                (Win32_Memory::MEM_COMMIT, prot_flags(permissions))
            }
        };
        let top_down = if matches!(
            behavior,
            FixedAddressBehavior::Hint(AllocationDirection::TopDown)
        ) {
            MEM_TOP_DOWN
        } else {
            0
        };
        // SAFETY: `range` is a nonempty, aligned request; any extent VirtualAlloc2 returns is
        // freshly allocated and exclusively owned by this call.
        let reserve = |address| unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                address,
                range.len(),
                Win32_Memory::MEM_RESERVE | state_flags | top_down,
                protection,
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
        if matches!(kind, NativeReservation::Mergeable) && !Self::replace_placeholder(&extent) {
            // SAFETY: The placeholder was just created by this call and has no other users.
            let freed = unsafe { VirtualFree(ptr, 0, Win32_Memory::MEM_RELEASE) };
            debug_assert_ne!(
                freed,
                0,
                "VirtualFree(RELEASE) of an unreplaced placeholder failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(AllocationError::OutOfMemory);
        }
        // SAFETY: VirtualAlloc2 successfully returned exclusive ownership of this aligned extent.
        Ok(unsafe { WindowsUserlandReservation::new(extent) })
    }

    /// Replaces the native placeholder at `extent` with an ordinary inaccessible reservation,
    /// which keeps it convertible back to a placeholder.
    fn replace_placeholder(extent: &core::ops::Range<usize>) -> bool {
        // SAFETY: The caller exclusively owns the placeholder at exactly `extent`.
        let ptr = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                extent.start as *mut c_void,
                extent.len(),
                Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_REPLACE_PLACEHOLDER,
                Win32_Memory::PAGE_NOACCESS,
                core::ptr::null_mut(),
                0,
            )
        };
        ptr as usize == extent.start
    }

    fn reserve_native_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
        kind: NativeReservation,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);
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
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;
        Self::allocate_native_reservation(suggested_range, fixed_address_behavior, kind)
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
        debug_assert!(!suggested_range.is_empty());
        debug_assert!(
            suggested_range
                .start
                .is_multiple_of(Self::RESERVATION_ALIGNMENT)
        );
        debug_assert!(suggested_range.end.is_multiple_of(ALIGN));
        debug_assert!(
            suggested_range.start >= Self::TASK_ADDR_MIN
                || (suggested_range.start == 0
                    && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
        );
        debug_assert!(suggested_range.end <= Self::TASK_ADDR_MAX);
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN feature so far.
        let _ = can_grow_down;
        let reservation = Self::allocate_native_reservation(
            suggested_range,
            fixed_address_behavior,
            NativeReservation::Committed(permissions),
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
        self.reserve_native_pages(
            suggested_range,
            can_grow_down,
            fixed_address_behavior,
            NativeReservation::Reserved,
        )
    }

    unsafe fn reserve_mergeable_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        self.reserve_native_pages(
            suggested_range,
            can_grow_down,
            fixed_address_behavior,
            NativeReservation::Mergeable,
        )
    }

    unsafe fn merge_reservations(
        &self,
        reservations: Vec<WindowsUserlandReservation<ALIGN>>,
    ) -> WindowsUserlandReservation<ALIGN> {
        assert!(!reservations.is_empty());
        if reservations.len() == 1 {
            return reservations.into_iter().next().unwrap();
        }
        // Native allocations cannot be joined directly: convert each uncommitted piece back to a
        // placeholder, coalesce the placeholders, and replace the result with one reservation.
        // The address range stays owned by placeholders throughout, so nothing can claim it.
        // Check contiguity before the first irreversible placeholder conversion.
        assert!(
            reservations
                .windows(2)
                .all(|pair| pair[0].range().end == pair[1].range().start),
            "merge_reservations requires ascending, contiguous reservations"
        );
        for reservation in &reservations {
            let extent = reservation.range();
            assert_ne!(
                // SAFETY: The caller guarantees this mergeable piece has no committed pages or
                // users, so discarding its (empty) contents is sound.
                unsafe {
                    VirtualFree(
                        extent.start as *mut c_void,
                        extent.len(),
                        Win32_Memory::MEM_RELEASE | Win32_Memory::MEM_PRESERVE_PLACEHOLDER,
                    )
                },
                0,
                "VirtualFree(PRESERVE_PLACEHOLDER) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let merged = reservations
            .into_iter()
            .reduce(PageReservation::merge)
            .unwrap();
        let extent = merged.range();
        assert_ne!(
            // SAFETY: The extent now consists solely of placeholders owned by `merged`.
            unsafe {
                VirtualFree(
                    extent.start as *mut c_void,
                    extent.len(),
                    Win32_Memory::MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS,
                )
            },
            0,
            "VirtualFree(COALESCE_PLACEHOLDERS) failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            Self::replace_placeholder(&extent),
            "VirtualAlloc2(REPLACE_PLACEHOLDER) failed: {}",
            std::io::Error::last_os_error()
        );
        merged
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
    fn test_merge_separately_reserved_mergeable_reservations() {
        type Provider = WindowsUserland;
        const UNIT: usize = 0x1_0000;
        let platform = WindowsUserland::new();
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                0..3 * UNIT,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let (head, middle, tail) = reservation.split(base + UNIT..base + 2 * UNIT);
        // SAFETY: The split handle exclusively owns the unused middle extent.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle) }
            .unwrap();
        // SAFETY: The middle extent was just released and is re-reserved without replacement.
        let middle = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                base + UNIT..base + 2 * UNIT,
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();

        // SAFETY: The pieces are adjacent, ascending, mergeable, uncommitted, and unused.
        let merged = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                platform,
                vec![head.unwrap(), middle, tail.unwrap()],
            )
        };
        assert_eq!(merged.range(), base..base + 3 * UNIT);
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, base as *mut c_void);
        assert_eq!(mbi.AllocationBase as usize, base);
        assert_eq!(mbi.RegionSize, 3 * UNIT);
        assert_eq!(mbi.State, Win32_Memory::MEM_RESERVE);

        // SAFETY: The merged reservation covers the range, which has no other users.
        unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&merged),
                base..base + 3 * UNIT,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                false,
            )
        }
        .unwrap();
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_COMMIT)]
        );
        // SAFETY: The merged reservation is unused after the checks above.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, merged) }
            .unwrap();
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_FREE)]
        );
    }

    #[test]
    fn test_mergeable_reservation_failure_paths() {
        type Provider = WindowsUserland;
        const UNIT: usize = 0x1_0000;
        let platform = WindowsUserland::new();
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                0..3 * UNIT,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;

        // A fixed mergeable reservation over owned space fails without disturbing it.
        // SAFETY: NoReplace cannot affect the existing reservation.
        let conflict = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                base..base + UNIT,
                false,
                FixedAddressBehavior::NoReplace,
            )
        };
        assert!(matches!(conflict, Err(AllocationError::AddressInUse)));
        // An ordinary reservation is not a placeholder, so replacing it fails.
        assert!(!WindowsUserland::<PAGE_SIZE>::replace_placeholder(
            &(base..base + 3 * UNIT)
        ));
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_RESERVE)]
        );

        let (head, middle, tail) = reservation.split(base + UNIT..base + 2 * UNIT);
        let (head, tail) = (head.unwrap(), tail.unwrap());
        // SAFETY: The split handle exclusively owns the unused middle extent.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle) }
            .unwrap();

        // A single reservation is returned unchanged.
        // SAFETY: The head is mergeable, uncommitted, and unused.
        let head = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                platform,
                vec![head],
            )
        };
        assert_eq!(head.range(), base..base + UNIT);

        // Non-contiguous pieces are rejected before any is converted to a placeholder.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: Deliberately violates contiguity to exercise the up-front check.
            unsafe {
                <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                    platform,
                    vec![head, tail],
                )
            }
        }));
        assert!(result.is_err());
        for start in [base, base + 2 * UNIT] {
            // Committing fails on a placeholder, so success proves the piece is still reserved.
            // SAFETY: The fixture owns this unused extent.
            let committed = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    start as *mut c_void,
                    UNIT,
                    Win32_Memory::MEM_COMMIT,
                    Win32_Memory::PAGE_READWRITE,
                    core::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(committed as usize, start);
            // SAFETY: The fixture owns this extent, whose handle was consumed by the panic.
            let piece =
                unsafe { WindowsUserlandReservation::<PAGE_SIZE>::new(start..start + UNIT) };
            WindowsUserland::<PAGE_SIZE>::release_reservation(piece);
        }
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_FREE)]
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
