// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::BTreeMap;
use std::os::raw::c_void;

#[cfg(test)]
use core::sync::atomic::Ordering;
use litebox::platform::RawConstPointer as _;
use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions, PageState, PageStateUpdateError,
};
use windows_sys::Win32::{
    Foundation::{self as Win32_Foundation, GetLastError},
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::Threading::GetCurrentProcess,
};

use crate::{UserMutPtr, WindowsUserland};

impl WindowsUserland {
    pub(super) fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut reserved_pages = alloc::vec::Vec::new();
        let mut address = 0usize;

        loop {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    address as *const c_void,
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            if !ok {
                break;
            }

            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                reserved_pages.push(core::ops::Range {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize + mbi.RegionSize),
                });
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }

        reserved_pages
    }

    fn round_up_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        (x + gran - 1) & !(gran - 1)
    }

    fn round_down_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x & !(gran - 1)
    }
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

fn do_query_on_region(mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION, base_addr: *mut c_void) {
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
/// - `operation`: A closure that takes the clipped region range and a reference to its
///   `MEMORY_BASIC_INFORMATION`, and returns Result<bool, E>.
///
/// # Panics
///
/// Panics if the operation returns false for any region.
fn process_memory_range_by_regions<F, E>(
    mut range: core::ops::Range<usize>,
    mut operation: F,
) -> Result<(), E>
where
    F: FnMut(core::ops::Range<usize>, &Win32_Memory::MEMORY_BASIC_INFORMATION) -> Result<bool, E>,
{
    while !range.is_empty() {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, range.start as *mut c_void);
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        assert!(mbi.BaseAddress as usize <= range.start && range.start < region_end);
        let len = region_end.min(range.end) - range.start;
        let success = operation(range.start..range.start + len, &mbi)?;
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

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

impl WindowsUserland {
    fn intersections(
        ranges: &BTreeMap<usize, core::ops::Range<usize>>,
        range: &core::ops::Range<usize>,
    ) -> Vec<core::ops::Range<usize>> {
        ranges
            .range(..range.end)
            .filter_map(|(_, owned)| {
                let start = range.start.max(owned.start);
                let end = range.end.min(owned.end);
                (start < end).then_some(start..end)
            })
            .collect()
    }

    /// Decommits a nonempty page-aligned range within one native reservation.
    ///
    /// # Safety
    ///
    /// The caller must own the range and ensure its contents are no longer in use.
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

    unsafe fn decommit(
        reservations: &BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
    ) {
        for segment in Self::intersections(reservations, &range) {
            // SAFETY: Each segment belongs to a recorded reservation and the caller excludes users.
            unsafe { Self::decommit_native(segment) };
        }
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
        // SAFETY: The caller owns this uncommitted range within one native reservation.
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

    unsafe fn commit(
        &self,
        reservations: &BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), PageStateUpdateError> {
        let segments = Self::intersections(reservations, &range);
        assert_eq!(
            segments.iter().map(core::ops::Range::len).sum::<usize>(),
            range.len()
        );
        for segment in segments {
            // SAFETY: Each uncommitted segment lies within a successfully acquired native extent.
            if let Err(error) = unsafe { self.commit_native(segment, permissions) } {
                // SAFETY: The caller supplied uncommitted pages; no new accesses have been published.
                unsafe { Self::decommit(reservations, range.clone()) };
                return Err(error);
            }
        }
        if populate {
            do_prefetch_on_range(range.start, range.len());
        }
        Ok(())
    }

    unsafe fn protect(
        reservations: &BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) {
        for segment in Self::intersections(reservations, &range) {
            let mut previous = 0;
            // SAFETY: The caller owns these committed pages within one reservation and excludes conflicting accesses.
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
                "failed to protect owned pages: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    unsafe fn replace_committed(
        &self,
        reservations: &BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), PageStateUpdateError> {
        let mut uncommitted = Vec::new();
        process_memory_range_by_regions(
            range.clone(),
            |segment, information| -> Result<bool, core::convert::Infallible> {
                if information.State == Win32_Memory::MEM_RESERVE {
                    uncommitted.push(segment);
                } else {
                    assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                }
                Ok(true)
            },
        )
        .unwrap();
        for (index, segment) in uncommitted.iter().enumerate() {
            // SAFETY: Ownership was validated before replacement; these segments are uncommitted.
            if let Err(error) =
                unsafe { self.commit(reservations, segment.clone(), permissions, populate) }
            {
                for earlier in &uncommitted[..index] {
                    // SAFETY: No accesses to these newly committed pages have been published.
                    unsafe { Self::decommit(reservations, earlier.clone()) };
                }
                return Err(error);
            }
        }
        // SAFETY: Commitment succeeded for the entire owned replacement range; its caller excludes users.
        unsafe {
            Self::protect(
                reservations,
                range.clone(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            );
            core::ptr::write_bytes(range.start as *mut u8, 0, range.len());
            Self::protect(reservations, range, permissions);
        }
        Ok(())
    }

    fn reserve_and_maybe_commit<const ALIGN: usize>(
        &self,
        reservations: &mut BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
        state: PageState,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<core::ops::Range<usize>, AllocationError> {
        let maximum = <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
        let backing =
            self.round_down_to_granu(range.start)..self.round_up_to_granu(range.end).min(maximum);
        let base = Self::reserve_native::<ALIGN>(backing.clone(), behavior)?.as_usize();
        let extent = base..base + backing.len();
        let range = if extent.start <= range.start && range.end <= extent.end {
            range
        } else {
            base..base + range.len()
        };
        reservations.insert(base, extent);
        if let PageState::Committed(permissions) = state {
            // SAFETY: The successful native reservation exclusively owns this uncommitted range.
            unsafe { self.commit_native(range.clone(), permissions) }
                .map_err(|_| AllocationError::OutOfMemory)?;
            if populate {
                do_prefetch_on_range(range.start, range.len());
            }
        }
        Ok(range)
    }

    fn acquire<const ALIGN: usize>(
        &self,
        reservations: &mut BTreeMap<usize, core::ops::Range<usize>>,
        range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
    ) -> Result<core::ops::Range<usize>, AllocationError> {
        let segments = Self::intersections(reservations, &range);
        let mut gaps = Vec::new();
        let mut cursor = range.start;
        for segment in &segments {
            if cursor < segment.start {
                gaps.push(cursor..segment.start);
            }
            cursor = segment.end;
        }
        if cursor < range.end {
            gaps.push(cursor..range.end);
        }
        for gap in gaps {
            let placement = if segments.is_empty() {
                behavior
            } else {
                FixedAddressBehavior::NoReplace
            };
            let acquired = match self.reserve_and_maybe_commit::<ALIGN>(
                reservations,
                gap,
                PageState::Reserved,
                false,
                placement,
            ) {
                Ok(acquired) => acquired,
                Err(error) => {
                    if behavior == FixedAddressBehavior::Hint
                        && !segments.is_empty()
                        && matches!(error, AllocationError::AddressInUseByPlatform)
                    {
                        return self.acquire::<ALIGN>(reservations, 0..range.len(), behavior);
                    }
                    return Err(error);
                }
            };
            if segments.is_empty() {
                return Ok(acquired);
            }
        }
        Ok(range)
    }
}

impl WindowsUserland {
    pub(super) const RESERVATION_ALIGNMENT: usize = 0x10000;

    /// Acquires exactly the requested extent with a native-aligned base, without adopting
    /// existing reservations. Only hints may relocate; fixed requests never replace memory.
    ///
    /// The caller must ensure nonzero starts and range ends are within the task address bounds.
    fn reserve_native<const ALIGN: usize>(
        suggested_range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
    ) -> Result<UserMutPtr<u8>, AllocationError> {
        if suggested_range.is_empty()
            || !suggested_range
                .start
                .is_multiple_of(Self::RESERVATION_ALIGNMENT)
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
            // SAFETY: MEM_RESERVE only acquires unused address space and never replaces mappings.
            unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    address,
                    size,
                    Win32_Memory::MEM_RESERVE,
                    Win32_Memory::PAGE_NOACCESS,
                    core::ptr::null_mut(),
                    0,
                )
            }
        };
        let mut pointer = reserve(start as *mut c_void);
        if pointer.is_null() && start != 0 && behavior == FixedAddressBehavior::Hint {
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

    /// Releases a complete native reservation.
    ///
    /// # Safety
    ///
    /// `base` must be returned by `reserve_native` for a live, exclusively owned reservation
    /// with no remaining allocations or active users. It must not be released again.
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

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_state: PageState,
        _can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);

        let mut reservations = self.reservations.lock().unwrap();
        if suggested_range.start == 0 {
            assert_eq!(fixed_address_behavior, FixedAddressBehavior::Hint);
            let range = self.reserve_and_maybe_commit::<ALIGN>(
                &mut reservations,
                suggested_range,
                initial_state,
                populate_pages_immediately,
                FixedAddressBehavior::Hint,
            )?;
            return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
        }

        let mut has_reserved_pages = false;
        let mut has_committed_pages = false;
        let mut has_foreign_pages = false;
        let _ = process_memory_range_by_regions(suggested_range.clone(), |_, information| {
            let state = information.State;
            if state != Win32_Memory::MEM_FREE
                && !reservations.contains_key(&information.AllocationBase.addr())
            {
                has_foreign_pages = true;
                return Err(());
            } else if state == Win32_Memory::MEM_COMMIT {
                has_committed_pages = true;
            } else if state == Win32_Memory::MEM_RESERVE {
                has_reserved_pages = true;
            }
            Ok(true)
        });

        // Handle `reserve` request
        if PageState::Reserved == initial_state {
            match fixed_address_behavior {
                FixedAddressBehavior::Hint
                    if has_foreign_pages || has_committed_pages || has_reserved_pages =>
                {
                    let range = self.reserve_and_maybe_commit::<ALIGN>(
                        &mut reservations,
                        0..suggested_range.len(),
                        initial_state,
                        populate_pages_immediately,
                        FixedAddressBehavior::Hint,
                    )?;
                    return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
                }
                FixedAddressBehavior::NoReplace if has_foreign_pages => {
                    return Err(AllocationError::AddressInUseByPlatform);
                }
                FixedAddressBehavior::NoReplace if has_committed_pages => {
                    return Err(AllocationError::AddressInUse);
                }
                FixedAddressBehavior::Hint | FixedAddressBehavior::NoReplace => {
                    let range = self.acquire::<ALIGN>(
                        &mut reservations,
                        suggested_range,
                        fixed_address_behavior,
                    )?;
                    return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
                }
                FixedAddressBehavior::Replace => {
                    if has_foreign_pages {
                        return Err(AllocationError::AddressInUseByPlatform);
                    }
                    let range = self.acquire::<ALIGN>(
                        &mut reservations,
                        suggested_range,
                        FixedAddressBehavior::Replace,
                    )?;
                    // SAFETY: The caller authorizes replacement of this fully owned range.
                    unsafe { Self::decommit(&reservations, range.clone()) };
                    return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
                }
            }
        }

        // Handle `commit` request
        match fixed_address_behavior {
            FixedAddressBehavior::Hint if has_committed_pages => {
                let range = self.reserve_and_maybe_commit::<ALIGN>(
                    &mut reservations,
                    0..suggested_range.len(),
                    initial_state,
                    populate_pages_immediately,
                    FixedAddressBehavior::Hint,
                )?;
                return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
            }
            FixedAddressBehavior::NoReplace if has_committed_pages => {
                return Err(AllocationError::AddressInUse);
            }
            _ => {}
        }
        // The suggested range is available or is okay to be replaced.
        // Reserve the whole range first to ensure we could commit the requested pages later.
        let range =
            self.acquire::<ALIGN>(&mut reservations, suggested_range, fixed_address_behavior)?;
        let PageState::Committed(permissions) = initial_state else {
            unreachable!("reserve request is already handled");
        };
        // SAFETY: The range is acquired backing or a caller-owned replacement, without users.
        let result = unsafe {
            if has_committed_pages {
                self.replace_committed(
                    &reservations,
                    range.clone(),
                    permissions,
                    populate_pages_immediately,
                )
            } else {
                self.commit(
                    &reservations,
                    range.clone(),
                    permissions,
                    populate_pages_immediately,
                )
            }
        };
        if let Err(error) = result {
            return Err(match error {
                PageStateUpdateError::OutOfMemory => AllocationError::OutOfMemory,
                other => panic!("failed to commit owned reservation: {other}"),
            });
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);
        let mut reservations = self.reservations.lock().unwrap();
        let overlapping: Vec<_> = reservations
            .range(..range.end)
            .filter(|(_, owned)| range.start < owned.end)
            .map(|(_, owned)| owned.clone())
            .collect();
        for owned in overlapping {
            if range.start <= owned.start && owned.end <= range.end {
                // SAFETY: The caller relinquishes this complete owned extent and excludes users.
                unsafe { Self::release_native(owned.start) };
                reservations.remove(&owned.start);
            } else {
                let segment = range.start.max(owned.start)..range.end.min(owned.end);
                // SAFETY: This segment is within owned backing; the caller excludes active users.
                unsafe { Self::decommit_native(segment) };
            }
        }
        Ok(())
    }

    unsafe fn decommit_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let reservations = self.reservations.lock().unwrap();
        // SAFETY: The caller guarantees ownership through this provider and excludes active users.
        unsafe { Self::decommit(&reservations, range) };
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let reservations = self.reservations.lock().unwrap();
        // SAFETY: The caller owns this committed range and excludes conflicting accesses.
        unsafe { Self::protect(&reservations, range, new_permissions) };
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Windows kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
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
    use litebox::platform::page_mgmt::PageState;
    use windows_sys::Win32::System::Memory as Win32_Memory;

    use super::{do_query_on_region, process_memory_range_by_regions};

    #[test]
    fn test_reserved_pages() {
        let platform = WindowsUserland::new();
        let reserved_pages: Vec<_> =
            <WindowsUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

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
                |region, information| -> Result<bool, core::convert::Infallible> {
                    regions.push((region, information.State));
                    Ok(true)
                },
            )
            .unwrap();
            regions
        };

        let platform = WindowsUserland::new();
        let _cleanup = litebox::utils::defer(|| {
            let ranges: Vec<_> = platform
                .reservations
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect();
            for range in ranges {
                // SAFETY: The test owns all backing extents on this platform and excludes users.
                unsafe {
                    <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(
                        platform, range,
                    )
                }
                .unwrap();
            }
        });
        let allocate_pages = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages;
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        let find_free_region = || {
            let mut address =
                <WindowsUserland as PageManagementProvider<4096>>::TASK_ADDR_MIN as *mut c_void;
            loop {
                let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut information, address);
                let aligned = platform.round_up_to_granu(information.BaseAddress as usize);
                if information.State == Win32_Memory::MEM_FREE
                    && aligned + system_allocation_granularity
                        <= information.BaseAddress as usize + information.RegionSize
                {
                    break aligned;
                }
                address =
                    (information.BaseAddress as usize + information.RegionSize) as *mut c_void;
            }
        };
        let first_hint = find_free_region();
        // Allocate some pages: it should reserve `system_allocation_granularity` bytes but only commit 0x1000 bytes
        let addr = allocate_pages(
            platform,
            first_hint..first_hint + 0x1000,
            PageState::Committed(MemoryRegionPermissions::WRITE),
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
        let addr2 = allocate_pages(
            platform,
            (addr + 0x8000)..(addr + 0x1_0000),
            PageState::Committed(MemoryRegionPermissions::WRITE),
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

        for initial_state in [
            PageState::Reserved,
            PageState::Committed(MemoryRegionPermissions::READ),
        ] {
            // SAFETY: The test owns this writable allocation and has no concurrent users.
            unsafe { ((addr + 0x8000) as *mut u8).write(0x5a) };
            let occupied = addr + 0x7000..addr + 0x9000;
            assert!(matches!(
                allocate_pages(
                    platform,
                    occupied.clone(),
                    initial_state,
                    false,
                    false,
                    FixedAddressBehavior::NoReplace,
                ),
                Err(litebox::platform::page_mgmt::AllocationError::AddressInUse)
            ));
            let relocated = allocate_pages(
                platform,
                occupied.clone(),
                initial_state,
                false,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap()
            .as_usize();
            assert!(relocated + occupied.len() <= addr || relocated >= addr + 0x1_0000);
            // SAFETY: Neither non-replacement request may change the existing readable page.
            assert_eq!(unsafe { ((addr + 0x8000) as *const u8).read() }, 0x5a);
        }

        let replacement = addr + 0x7000..addr + 0x9000;
        // SAFETY: The neighboring page remains owned, writable, and outside the replacement.
        unsafe { ((addr + 0x9000) as *mut u8).write(0xa5) };
        assert_eq!(
            allocate_pages(
                platform,
                replacement.clone(),
                PageState::Reserved,
                false,
                true,
                FixedAddressBehavior::Replace,
            )
            .unwrap()
            .as_usize(),
            replacement.start
        );
        assert_eq!(
            collect_regions(replacement.clone()),
            vec![(replacement.clone(), Win32_Memory::MEM_RESERVE)]
        );
        allocate_pages(
            platform,
            replacement,
            PageState::Committed(MemoryRegionPermissions::READ),
            false,
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        // SAFETY: The replacement and its unaffected neighbor are committed readable pages.
        unsafe {
            assert_eq!(((addr + 0x8000) as *const u8).read(), 0);
            assert_eq!(((addr + 0x9000) as *const u8).read(), 0xa5);
        }

        // Find a free allocation-granularity-sized region so this allocation
        // deterministically exercises the MEM_FREE path.
        let free_addr = find_free_region();
        // Populating an explicit reservation should not commit or prefetch it.
        let suggested_populated_inaccessible_addr = allocate_pages(
            platform,
            free_addr..free_addr + 0x1000,
            PageState::Reserved,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(suggested_populated_inaccessible_addr, free_addr);
        assert_eq!(
            collect_regions(free_addr..free_addr + 0x1000),
            vec![(
                free_addr..free_addr + 0x1000,
                windows_sys::Win32::System::Memory::MEM_RESERVE
            )]
        );

        // The same behavior applies when Windows chooses the base address.
        let populated_inaccessible_addr = allocate_pages(
            platform,
            0..0x1000,
            PageState::Reserved,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(populated_inaccessible_addr..populated_inaccessible_addr + 0x1000),
            vec![(
                populated_inaccessible_addr..populated_inaccessible_addr + 0x1000,
                windows_sys::Win32::System::Memory::MEM_RESERVE
            )]
        );
        allocate_pages(
            platform,
            populated_inaccessible_addr..populated_inaccessible_addr + 0x1000,
            PageState::Committed(MemoryRegionPermissions::WRITE),
            false,
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        assert_eq!(
            collect_regions(populated_inaccessible_addr..populated_inaccessible_addr + 0x1000),
            vec![(
                populated_inaccessible_addr..populated_inaccessible_addr + 0x1000,
                windows_sys::Win32::System::Memory::MEM_COMMIT
            )]
        );

        // A reserved mapping remains uncommitted until explicitly committed.
        let inaccessible_addr = allocate_pages(
            platform,
            0..0x1000,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(inaccessible_addr..inaccessible_addr + 0x1000),
            vec![(
                inaccessible_addr..inaccessible_addr + 0x1000,
                windows_sys::Win32::System::Memory::MEM_RESERVE
            )]
        );

        // SAFETY: This test owns the allocation and does not access it after removal.
        unsafe {
            <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                inaccessible_addr..inaccessible_addr + 0x1000,
            )
        }
        .unwrap();
        let reused_addr = allocate_pages(
            platform,
            inaccessible_addr..inaccessible_addr + 0x1000,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_ne!(reused_addr, inaccessible_addr);
        assert_eq!(
            collect_regions(reused_addr..reused_addr + 0x1000),
            vec![(reused_addr..reused_addr + 0x1000, Win32_Memory::MEM_RESERVE)]
        );
        assert_eq!(
            collect_regions(inaccessible_addr..inaccessible_addr + 0x1000),
            vec![(
                inaccessible_addr..inaccessible_addr + 0x1000,
                Win32_Memory::MEM_RESERVE
            )]
        );

        // Committed PAGE_NOACCESS is distinct from an address reservation.
        let committed_noaccess_addr = allocate_pages(
            platform,
            0..0x1000,
            PageState::Committed(MemoryRegionPermissions::empty()),
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(committed_noaccess_addr..committed_noaccess_addr + 0x1000),
            vec![(
                committed_noaccess_addr..committed_noaccess_addr + 0x1000,
                Win32_Memory::MEM_COMMIT
            )]
        );
        // SAFETY: This test owns the committed no-access allocation and has no active users.
        unsafe {
            <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
                platform,
                committed_noaccess_addr..committed_noaccess_addr + 0x1000,
            )
        }
        .unwrap();
        assert_eq!(
            collect_regions(committed_noaccess_addr..committed_noaccess_addr + 0x1000),
            vec![(
                committed_noaccess_addr..committed_noaccess_addr + 0x1000,
                Win32_Memory::MEM_RESERVE
            )]
        );
    }

    #[test]
    fn test_page_backend_reuses_partial_reservation() {
        type Pages = WindowsUserland;
        let platform = WindowsUserland::new();
        let first = <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..4096,
            PageState::Committed(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE),
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        let second = first + 4096;
        <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            second..second + 4096,
            PageState::Committed(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE),
            false,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        // SAFETY: Both pages belong exclusively to this test; the second remains live during reuse.
        unsafe {
            (second as *mut u8).write(0x5a);
            <Pages as PageManagementProvider<4096>>::deallocate_pages(platform, first..second)
                .unwrap();
        }
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            first..second,
            PageState::Committed(MemoryRegionPermissions::READ),
            false,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        // SAFETY: The test owns these readable pages and excludes accesses after their removal.
        unsafe {
            assert_eq!((first as *const u8).read(), 0);
            assert_eq!((second as *const u8).read(), 0x5a);
            <Pages as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                first..second + 4096,
            )
            .unwrap();
        }
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        assert_eq!(platform.reservations.lock().unwrap().len(), 1);
        // SAFETY: The test relinquishes the complete native backing, including unused padding.
        unsafe {
            <Pages as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                first..first + WindowsUserland::RESERVATION_ALIGNMENT,
            )
        }
        .unwrap();
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_FREE);
        assert!(platform.reservations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_page_backend_native_boundaries_and_rollback() {
        use litebox::platform::page_mgmt::AllocationError;

        const GRANULARITY: usize = 0x10000;
        type Pages = WindowsUserland;
        let platform = WindowsUserland::new();
        let probe = <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..4 * GRANULARITY,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        // SAFETY: The probe has no users; subsequent fixed allocations independently acquire ownership.
        unsafe {
            <Pages as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                probe..probe + 4 * GRANULARITY,
            )
        }
        .unwrap();
        let left = probe;
        let right = probe + 3 * GRANULARITY - 4096;
        for address in [left, right] {
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                address..address + 4096,
                PageState::Reserved,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap();
        }
        let range = probe + GRANULARITY - 4096..probe + 2 * GRANULARITY + 4096;
        platform
            .fail_commit_at
            .store(probe + GRANULARITY, core::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                range.clone(),
                PageState::Committed(MemoryRegionPermissions::READ),
                false,
                false,
                FixedAddressBehavior::NoReplace,
            ),
            Err(AllocationError::OutOfMemory)
        ));
        assert_eq!(platform.reservations.lock().unwrap().len(), 3);
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, range.start as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        do_query_on_region(&mut information, (probe + GRANULARITY) as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);

        <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            range.clone(),
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        assert!(matches!(
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                range.clone(),
                PageState::Committed(MemoryRegionPermissions::READ),
                false,
                false,
                FixedAddressBehavior::Replace,
            ),
            Err(AllocationError::OutOfMemory)
        ));
        for address in [range.start, probe + GRANULARITY, probe + 2 * GRANULARITY] {
            do_query_on_region(&mut information, address as *mut c_void);
            assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        }
        platform
            .fail_commit_at
            .store(0, core::sync::atomic::Ordering::Relaxed);
        // SAFETY: The test exclusively owns these allocations and stops using them before removal.
        unsafe {
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                range.clone(),
                PageState::Committed(
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                ),
                false,
                true,
                FixedAddressBehavior::Replace,
            )
            .unwrap();
            (range.start as *mut u8).write(0x5a);
            ((range.end - 1) as *mut u8).write(0xa5);
            <Pages as PageManagementProvider<4096>>::update_permissions(
                platform,
                probe + GRANULARITY..probe + GRANULARITY + 4096,
                MemoryRegionPermissions::empty(),
            )
            .unwrap();
            <Pages as PageManagementProvider<4096>>::update_permissions(
                platform,
                range.clone(),
                MemoryRegionPermissions::READ,
            )
            .unwrap();
            assert_eq!((range.start as *const u8).read(), 0x5a);
            assert_eq!(((range.end - 1) as *const u8).read(), 0xa5);
            for address in [range.start, probe + GRANULARITY, probe + 2 * GRANULARITY] {
                do_query_on_region(&mut information, address as *mut c_void);
                assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                assert_eq!(information.Protect, Win32_Memory::PAGE_READONLY);
            }
            <Pages as PageManagementProvider<4096>>::decommit_pages(platform, range.clone())
                .unwrap();
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                range.clone(),
                PageState::Committed(MemoryRegionPermissions::READ),
                false,
                false,
                FixedAddressBehavior::Replace,
            )
            .unwrap();
            assert_eq!((range.start as *const u8).read(), 0);
            assert_eq!(((range.end - 1) as *const u8).read(), 0);
            <Pages as PageManagementProvider<4096>>::deallocate_pages(platform, range).unwrap();
            for address in [left, right] {
                <Pages as PageManagementProvider<4096>>::deallocate_pages(
                    platform,
                    address..address + 4096,
                )
                .unwrap();
            }
        }
        assert_eq!(platform.reservations.lock().unwrap().len(), 2);
        // SAFETY: All allocations are gone; the test relinquishes the retained boundary extents.
        unsafe {
            for extent in [
                probe..probe + GRANULARITY,
                probe + 2 * GRANULARITY..probe + 3 * GRANULARITY,
            ] {
                <Pages as PageManagementProvider<4096>>::deallocate_pages(platform, extent)
                    .unwrap();
            }
        }
        assert!(platform.reservations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_page_backend_failed_replacement_preserves_existing_pages() {
        use litebox::platform::page_mgmt::AllocationError;

        type Pages = WindowsUserland;
        let platform = WindowsUserland::new();
        let pointer = <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..8192,
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        // SAFETY: The first page belongs exclusively to the test; the second remains reserved.
        unsafe {
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                pointer..pointer + 4096,
                PageState::Committed(
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                ),
                false,
                false,
                FixedAddressBehavior::Replace,
            )
            .unwrap();
            (pointer as *mut u8).write(0x5a);
        }
        platform
            .fail_commit_at
            .store(pointer + 4096, core::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                pointer..pointer + 8192,
                PageState::Committed(MemoryRegionPermissions::READ),
                false,
                false,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::OutOfMemory)
        ));
        // SAFETY: Failed replacement must leave the original committed page accessible and unchanged.
        assert_eq!(unsafe { (pointer as *const u8).read() }, 0x5a);
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, (pointer + 4096) as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        platform
            .fail_commit_at
            .store(0, core::sync::atomic::Ordering::Relaxed);
        <Pages as PageManagementProvider<4096>>::allocate_pages(
            platform,
            pointer..pointer + 8192,
            PageState::Committed(MemoryRegionPermissions::READ),
            false,
            false,
            FixedAddressBehavior::Replace,
        )
        .unwrap();
        // SAFETY: Successful replacement yields zeroed readable pages; no accesses follow removal.
        unsafe {
            assert_eq!((pointer as *const u8).read(), 0);
            <Pages as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                pointer..pointer + 8192,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_page_backend_remap_preserves_state_and_backing() {
        type Pages = WindowsUserland;
        for (state, collision) in [
            PageState::Reserved,
            PageState::Committed(MemoryRegionPermissions::empty()),
            PageState::Committed(MemoryRegionPermissions::READ),
        ]
        .into_iter()
        .flat_map(|state| [false, true].map(|collision| (state, collision)))
        {
            let platform = WindowsUserland::new();
            let base = <Pages as PageManagementProvider<4096>>::allocate_pages(
                platform,
                0..4096,
                PageState::Committed(
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                ),
                false,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap()
            .as_usize();
            let foreign = if collision {
                // SAFETY: This test acquires a private writable allocation outside the provider.
                let pointer = unsafe {
                    Win32_Memory::VirtualAlloc(
                        core::ptr::null(),
                        8192,
                        Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT,
                        Win32_Memory::PAGE_READWRITE,
                    )
                };
                assert!(!pointer.is_null());
                Some(pointer.addr())
            } else {
                None
            };
            let _cleanup = litebox::utils::defer(|| {
                if let Some(foreign) = foreign {
                    // SAFETY: This test exclusively owns the complete foreign allocation.
                    unsafe { WindowsUserland::release_native(foreign) };
                }
            });
            let destination_start = foreign.unwrap_or(base + 8192);
            let destination = destination_start
                ..destination_start
                    + if state == PageState::Reserved {
                        4096
                    } else {
                        8192
                    };
            // SAFETY: Source and destination are exclusively owned by this test and never overlap.
            unsafe {
                (base as *mut u8).write(0x5a);
                if let Some(foreign) = foreign {
                    (foreign as *mut u8).write(0xa5);
                    ((foreign + 8191) as *mut u8).write(0xa5);
                }
                match state {
                    PageState::Reserved => <Pages as PageManagementProvider<4096>>::decommit_pages(
                        platform,
                        base..base + 4096,
                    )
                    .unwrap(),
                    PageState::Committed(permissions) => {
                        <Pages as PageManagementProvider<4096>>::update_permissions(
                            platform,
                            base..base + 4096,
                            permissions,
                        )
                        .unwrap();
                    }
                }
                let moved = <Pages as PageManagementProvider<4096>>::remap_pages(
                    platform,
                    base..base + 4096,
                    destination.clone(),
                    state,
                )
                .unwrap();
                if collision || state == PageState::Reserved {
                    assert_ne!(moved.as_usize(), destination.start);
                } else {
                    assert_eq!(moved.as_usize(), destination.start);
                }
                let destination = moved.as_usize()..moved.as_usize() + destination.len();
                let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                if let Some(foreign) = foreign {
                    do_query_on_region(&mut information, foreign as *mut c_void);
                    assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                    assert_eq!(information.Protect, Win32_Memory::PAGE_READWRITE);
                    assert_eq!((foreign as *const u8).read(), 0xa5);
                    assert_eq!(((foreign + 8191) as *const u8).read(), 0xa5);
                }
                do_query_on_region(&mut information, destination.start as *mut c_void);
                match state {
                    PageState::Reserved => {
                        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
                        <Pages as PageManagementProvider<4096>>::allocate_pages(
                            platform,
                            destination.clone(),
                            PageState::Committed(MemoryRegionPermissions::READ),
                            false,
                            false,
                            FixedAddressBehavior::Replace,
                        )
                        .unwrap();
                    }
                    PageState::Committed(permissions) => {
                        assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                        assert_eq!(information.Protect, super::prot_flags(permissions));
                        <Pages as PageManagementProvider<4096>>::update_permissions(
                            platform,
                            destination.clone(),
                            MemoryRegionPermissions::READ,
                        )
                        .unwrap();
                    }
                }
                assert_eq!(
                    (destination.start as *const u8).read(),
                    if state == PageState::Reserved {
                        0
                    } else {
                        0x5a
                    }
                );
                assert_eq!(((destination.end - 1) as *const u8).read(), 0);
                do_query_on_region(&mut information, base as *mut c_void);
                assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
                <Pages as PageManagementProvider<4096>>::deallocate_pages(platform, destination)
                    .unwrap();
            }
            let reservations: Vec<_> = platform
                .reservations
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect();
            assert_eq!(
                reservations.len(),
                if collision || state == PageState::Reserved {
                    2
                } else {
                    1
                }
            );
            for reservation in reservations {
                // SAFETY: The test has released source and destination and owns the remaining padding.
                unsafe {
                    <Pages as PageManagementProvider<4096>>::deallocate_pages(platform, reservation)
                }
                .unwrap();
            }
            assert!(platform.reservations.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_page_reservation_alignment_and_exact_size() {
        use litebox::platform::page_mgmt::AllocationError;

        const PAGE_SIZE: usize = 4096;
        let base =
            WindowsUserland::reserve_native::<PAGE_SIZE>(0..PAGE_SIZE, FixedAddressBehavior::Hint)
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
                ),
                Err(AllocationError::Unaligned)
            ));
        }
    }

    #[test]
    fn test_page_reservation_rejects_foreign_memory() {
        use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
        use litebox::platform::page_mgmt::AllocationError;

        let platform = WindowsUserland::new();
        let manager = litebox::mm::PageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
        // SAFETY: Acquire a private native reservation after the platform snapshot was taken.
        let foreign = unsafe {
            Win32_Memory::VirtualAlloc(
                core::ptr::null(),
                0x10000,
                Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_NOACCESS,
            )
        };
        assert!(!foreign.is_null());
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: Guest mappings and the foreign reservation are unused; empty-flag
            // startup ranges are excluded from cleanup.
            unsafe {
                manager
                    .release_memory(|_, flags| !flags.is_empty())
                    .unwrap();
                assert_ne!(
                    Win32_Memory::VirtualFree(foreign, 0, Win32_Memory::MEM_RELEASE),
                    0
                );
            }
        });
        for state in [Win32_Memory::MEM_RESERVE, Win32_Memory::MEM_COMMIT] {
            if state == Win32_Memory::MEM_COMMIT {
                // SAFETY: The test exclusively owns this native reservation.
                unsafe {
                    assert_eq!(
                        Win32_Memory::VirtualAlloc(
                            foreign,
                            4096,
                            Win32_Memory::MEM_COMMIT,
                            Win32_Memory::PAGE_READWRITE
                        ),
                        foreign
                    );
                    foreign.cast::<u8>().write(0x5a);
                }
            }
            for behavior in [
                FixedAddressBehavior::NoReplace,
                FixedAddressBehavior::Replace,
            ] {
                assert!(matches!(
                    WindowsUserland::reserve_native::<4096>(
                        foreign.addr()..foreign.addr() + 4096,
                        behavior,
                    ),
                    Err(AllocationError::AddressInUseByPlatform)
                ));
                for initial_state in [
                    PageState::Reserved,
                    PageState::Committed(MemoryRegionPermissions::READ),
                ] {
                    assert!(matches!(
                        <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
                            platform,
                            foreign.addr()..foreign.addr() + 4096,
                            initial_state,
                            false,
                            false,
                            behavior,
                        ),
                        Err(AllocationError::AddressInUseByPlatform)
                    ));
                }
                let mut flags = CreatePagesFlags::FIXED_ADDR;
                flags.set(
                    CreatePagesFlags::NOREPLACE,
                    behavior == FixedAddressBehavior::NoReplace,
                );
                // SAFETY: The manager must reject this foreign address before any mutation.
                assert!(matches!(
                    unsafe {
                        manager.create_writable_pages(
                            NonZeroAddress::new(foreign.addr()),
                            NonZeroPageSize::new(4096).unwrap(),
                            flags,
                            |_| Ok(0),
                        )
                    },
                    Err(MappingError::MapError(
                        AllocationError::AddressInUseByPlatform
                    ))
                ));
            }
            for initial_state in [
                PageState::Reserved,
                PageState::Committed(MemoryRegionPermissions::READ),
            ] {
                let relocated = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
                    platform,
                    foreign.addr()..foreign.addr() + 4096,
                    initial_state,
                    false,
                    false,
                    FixedAddressBehavior::Hint,
                )
                .unwrap()
                .as_usize();
                assert!(
                    relocated + 4096 <= foreign.addr() || relocated >= foreign.addr() + 0x10000
                );
                let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut information, relocated as *mut c_void);
                assert_eq!(
                    information.State,
                    match initial_state {
                        PageState::Reserved => Win32_Memory::MEM_RESERVE,
                        PageState::Committed(_) => Win32_Memory::MEM_COMMIT,
                    }
                );
                // SAFETY: The direct hint acquired a fresh native extent with no active users.
                unsafe {
                    <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(
                        platform,
                        relocated..relocated + WindowsUserland::RESERVATION_ALIGNMENT,
                    )
                }
                .unwrap();
            }
            // SAFETY: A hint may relocate; the returned mapping has no concurrent users.
            let relocated = unsafe {
                manager.create_writable_pages(
                    NonZeroAddress::new(foreign.addr()),
                    NonZeroPageSize::new(4096).unwrap(),
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
            }
            .unwrap();
            assert_ne!(relocated.as_usize(), foreign.addr());
            let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut information, foreign);
            assert_eq!(information.State, state);
            if state == Win32_Memory::MEM_COMMIT {
                // SAFETY: The test's committed native page must remain readable and unchanged.
                assert_eq!(unsafe { foreign.cast::<u8>().read() }, 0x5a);
            }
        }
    }
}
