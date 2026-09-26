// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    AllocationError, FixedAddressBehavior, GetCurrentProcess, GetLastError,
    MemoryRegionPermissions, PrefetchVirtualMemory, UserMutPtr, VirtualAlloc2, VirtualFree,
    VirtualProtect, Win32_Memory, WindowsUserland, c_void,
};
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{PageReservation as _, ReservationStore as _};

litebox::define_page_reservation!(WindowsUserlandReservation);

#[derive(Default)]
pub(super) struct WindowsReservationStore<const ALIGN: usize> {
    reservations: TrackedReservations<WindowsUserlandReservation<ALIGN>>,
}

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
    fn reserve_gap(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        let aligned_start = self.round_down_to_granu(range.start);
        let aligned_end = self.round_up_to_granu(range.end);
        let ptr = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                aligned_start as *mut c_void,
                aligned_end - aligned_start,
                Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_NOACCESS,
                core::ptr::null_mut(),
                0,
            )
        };
        if ptr.is_null() {
            return Err(if range.start == 0 {
                AllocationError::OutOfMemory
            } else {
                AllocationError::AddressInUse
            });
        }

        let base = ptr as usize;
        let extent = base..base + aligned_end - aligned_start;
        // SAFETY: VirtualAlloc2 successfully returned exclusive ownership of this aligned extent.
        Ok(unsafe { WindowsUserlandReservation::new(extent) })
    }

    fn release_reservation(reservation: WindowsUserlandReservation<ALIGN>) {
        let base = reservation.range().start;
        assert_ne!(
            unsafe { VirtualFree(base as *mut c_void, 0, Win32_Memory::MEM_RELEASE) },
            0,
            "VirtualFree(RELEASE) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    fn reserve_gaps(
        &self,
        store: &mut WindowsReservationStore<ALIGN>,
        range: core::ops::Range<usize>,
    ) -> Result<(), AllocationError> {
        let mut acquired = Vec::new();
        for (gap, base) in store.reservations.segments(range.clone()) {
            if base.is_some() {
                continue;
            }
            match self.reserve_gap(gap) {
                Ok(reservation) => acquired.push(reservation),
                Err(error) => {
                    for reservation in acquired {
                        Self::release_reservation(reservation);
                    }
                    return Err(error);
                }
            }
        }
        for reservation in acquired {
            let base = reservation.range().start;
            assert!(store.reservations.insert(base, reservation).is_none());
        }
        Ok(())
    }

    fn commit_pages(
        store: &WindowsReservationStore<ALIGN>,
        range: core::ops::Range<usize>,
        flags: Win32_Memory::PAGE_PROTECTION_FLAGS,
    ) -> bool {
        for (_, reservation) in store.reservations.overlapping(range.clone()) {
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
                Self::decommit_pages(store, range);
                return false;
            }
        }

        true
    }

    fn decommit_pages(store: &WindowsReservationStore<ALIGN>, range: core::ops::Range<usize>) {
        for (_, reservation) in store.reservations.overlapping(range.clone()) {
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

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN>
    for WindowsUserland<ALIGN>
{
    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);

        assert!(
            suggested_range.start
                >= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
        );
        assert!(
            suggested_range.end
                <= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
        );
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;
        let mut reservations = self.reservations.lock().unwrap();
        let range = match self.reserve_gaps(&mut reservations, suggested_range.clone()) {
            Ok(()) => suggested_range,
            Err(AllocationError::AddressInUse)
                if fixed_address_behavior == FixedAddressBehavior::Hint =>
            {
                let reservation = self.reserve_gap(0..suggested_range.len())?;
                let base = reservation.range().start;
                assert!(
                    reservations
                        .reservations
                        .insert(base, reservation)
                        .is_none()
                );
                base..base + suggested_range.len()
            }
            Err(error) => return Err(error),
        };
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            Self::decommit_pages(&reservations, range.clone());
        }
        assert!(Self::commit_pages(
            &reservations,
            range.clone(),
            prot_flags(initial_permissions)
        ));
        if populate_pages_immediately {
            do_prefetch_on_range(range.start, range.len());
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);
        Self::decommit_pages(&self.reservations.lock().unwrap(), range);
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(new_permissions);
        let reservations = self.reservations.lock().unwrap();
        for (_, reservation) in reservations.reservations.overlapping(range.clone()) {
            let reserved = reservation.range();
            let segment = range.start.max(reserved.start)..range.end.min(reserved.end);
            let mut old_protect: u32 = 0;
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

    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::mm::vmem::PAGE_SIZE;
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

    #[test]
    fn test_reserved_pages() {
        let platform = WindowsUserland::new();
        let reserved_pages: Vec<_> =
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserved_pages(platform)
                .collect();

        // Check that the reserved pages are not empty
        assert!(!reserved_pages.is_empty(), "No reserved pages found");

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[test]
    fn test_page_provider() {
        let collect_regions = |r| {
            let mut regions = Vec::new();
            process_memory_range_by_regions(
                r,
                |region, state| -> Result<bool, core::convert::Infallible> {
                    regions.push((region, state));
                    Ok(true)
                },
            )
            .unwrap();
            regions
        };

        let platform = WindowsUserland::new();
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Allocate some pages: it should reserve `system_allocation_granularity` bytes but only commit 0x1000 bytes
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        let addr = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::allocate_pages(
            platform,
            suggested..suggested + 0x1000,
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
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
        let addr2 = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::allocate_pages(
            platform,
            (addr + 0x8000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
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
    }
}
