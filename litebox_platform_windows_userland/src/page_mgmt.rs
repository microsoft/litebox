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

    /// Acquires exactly the requested extent, optionally committed, without adopting existing
    /// reservations. Only hints may relocate; fixed requests never replace memory.
    ///
    /// The caller must ensure nonzero starts and range ends are within the task address bounds.
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

impl WindowsUserland {
    fn allocate_native_reservation<const ALIGN: usize>(
        range: core::ops::Range<usize>,
        permissions: Option<MemoryRegionPermissions>,
        behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        let minimum = <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN;
        let maximum = <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
        if range.is_empty()
            || !range.start.is_multiple_of(
                <Self as litebox::platform::PageManagementProvider<ALIGN>>::RESERVATION_ALIGNMENT,
            )
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
        // SAFETY: Native reservation acquired this fresh exact extent with no other owner.
        Ok(unsafe { WindowsUserlandReservation::new(base..end) })
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
        let reservation = Self::allocate_native_reservation(range, None, behavior)?;
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
        let reservation = Self::allocate_native_reservation(range, Some(permissions), behavior)?;
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
        for reservation in covering_reservations() {
            let extent = reservation.range();
            let segment = extent.start.max(range.start)..extent.end.min(range.end);
            // SAFETY: The caller supplies pages in this live native reservation and excludes conflicting accesses.
            unsafe { self.commit_native(segment, permissions) }?;
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
        let range = reservation.range();
        assert!(!range.is_empty());
        debug_assert_alignment!(range, ALIGN);
        let mut address = range.start as *mut c_void;
        let mut length = range.len();
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
        assert_eq!(address.addr(), range.start);
        assert_eq!(length, range.len());
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
    use litebox::platform::page_mgmt::PageReservation as _;
    use windows_sys::Win32::System::Memory as Win32_Memory;

    use super::{
        AllocationError, PageStateUpdateError, UserMutPtr, do_prefetch_on_range, prot_flags,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use windows_sys::Win32::{Foundation::GetLastError, System::Memory::VirtualProtect};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PageState {
        Reserved,
        Committed(MemoryRegionPermissions),
    }

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
        F: FnMut(
            core::ops::Range<usize>,
            &Win32_Memory::MEMORY_BASIC_INFORMATION,
        ) -> Result<bool, E>,
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

    struct TestPageAllocator {
        native: &'static WindowsUserland,
        reservations: Mutex<BTreeMap<usize, core::ops::Range<usize>>>,
    }

    impl TestPageAllocator {
        fn new() -> Self {
            Self {
                native: WindowsUserland::new(),
                reservations: Mutex::new(BTreeMap::new()),
            }
        }

        fn round_up_to_granu(&self, x: usize) -> usize {
            let gran = self.native.sys_info.read().unwrap().dwAllocationGranularity as usize;
            (x + gran - 1) & !(gran - 1)
        }

        fn round_down_to_granu(&self, x: usize) -> usize {
            let gran = self.native.sys_info.read().unwrap().dwAllocationGranularity as usize;
            x & !(gran - 1)
        }

        fn allocate_native_pages<const ALIGN: usize>(
            &self,
            suggested_range: core::ops::Range<usize>,
            initial_state: PageState,
            _can_grow_down: bool,
            populate_pages_immediately: bool,
            fixed_address_behavior: FixedAddressBehavior,
        ) -> Result<UserMutPtr<u8>, AllocationError> {
            debug_assert!(
                ALIGN.is_multiple_of(self.native.sys_info.read().unwrap().dwPageSize as usize)
            );
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
            let _ = process_memory_range_by_regions(suggested_range.clone(), |_, information| {
                let state = information.State;
                if state == Win32_Memory::MEM_COMMIT {
                    has_committed_pages = true;
                    return Err(());
                } else if state == Win32_Memory::MEM_RESERVE {
                    has_reserved_pages = true;
                    if !reservations.contains_key(&information.AllocationBase.addr()) {
                        // The region is reserved but not tracked in our reservations, treat it as unavailable.
                        has_committed_pages = true;
                        return Err(());
                    }
                }
                Ok(true)
            });

            // Handle `reserve` request
            if PageState::Reserved == initial_state {
                let address_in_use = has_committed_pages || has_reserved_pages;
                match fixed_address_behavior {
                    FixedAddressBehavior::Hint if address_in_use => {
                        let range = self.reserve_and_maybe_commit::<ALIGN>(
                            &mut reservations,
                            0..suggested_range.len(),
                            initial_state,
                            populate_pages_immediately,
                            FixedAddressBehavior::Hint,
                        )?;
                        return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
                    }
                    FixedAddressBehavior::NoReplace if address_in_use => {
                        return Err(AllocationError::AddressInUse);
                    }
                    FixedAddressBehavior::Hint | FixedAddressBehavior::NoReplace => {
                        let range = self.reserve_and_maybe_commit::<ALIGN>(
                            &mut reservations,
                            suggested_range,
                            initial_state,
                            populate_pages_immediately,
                            fixed_address_behavior,
                        )?;
                        return Ok(UserMutPtr::from_ptr(range.start as *mut u8));
                    }
                    FixedAddressBehavior::Replace => {
                        panic!("FixedAddressBehavior::Replace is not yet implemented");
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

        unsafe fn decommit(
            reservations: &BTreeMap<usize, core::ops::Range<usize>>,
            range: core::ops::Range<usize>,
        ) {
            for segment in Self::intersections(reservations, &range) {
                // SAFETY: Each segment belongs to a recorded reservation and the caller excludes users.
                unsafe { WindowsUserland::decommit_native(segment) };
            }
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
                if let Err(error) = unsafe { self.native.commit_native(segment, permissions) } {
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
            let maximum = <WindowsUserland as PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
            let backing = self.round_down_to_granu(range.start)
                ..self.round_up_to_granu(range.end).min(maximum);
            let base = WindowsUserland::reserve_native::<ALIGN>(backing.clone(), behavior, None)?
                .as_usize();
            let extent = base..base + backing.len();
            let range = if extent.start <= range.start && range.end <= extent.end {
                range
            } else {
                base..base + range.len()
            };
            reservations.insert(base, extent);
            if let PageState::Committed(permissions) = state {
                // SAFETY: The successful native reservation exclusively owns this uncommitted range.
                unsafe { self.native.commit_native(range.clone(), permissions) }
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

    unsafe fn release_fixture_pages(platform: &TestPageAllocator, range: core::ops::Range<usize>) {
        debug_assert_alignment!(range, 4096);
        let mut reservations = platform.reservations.lock().unwrap();
        let overlapping: Vec<_> = reservations
            .range(..range.end)
            .filter(|(_, owned)| range.start < owned.end)
            .map(|(_, owned)| owned.clone())
            .collect();
        if overlapping.is_empty() {
            // SAFETY: The fixture relinquishes raw ownership of this extent without another handle.
            let reservation = unsafe { crate::WindowsUserlandReservation::new(range.clone()) };
            // SAFETY: The fixture excludes all users while its extent is decommitted and released.
            unsafe {
                <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
                    platform.native,
                    || core::iter::once(&reservation),
                    range,
                )
                .unwrap();
                release_reservations::<4096>(platform.native, vec![reservation]);
            }
            return;
        }
        for owned in overlapping {
            let segment = range.start.max(owned.start)..range.end.min(owned.end);
            reservations.remove(&owned.start);
            // SAFETY: The locked legacy record transfers to a handle; the fixture excludes users of the released subrange.
            let (prefix, suffix) = unsafe {
                let reservation = crate::WindowsUserlandReservation::new(owned);
                <WindowsUserland as PageManagementProvider<4096>>::decommit_pages(
                    platform.native,
                    || core::iter::once(&reservation),
                    segment.clone(),
                )
                .unwrap();
                let (prefix, released, suffix) = reservation.split(segment);
                release_reservations::<4096>(platform.native, vec![released]);
                (prefix, suffix)
            };
            for survivor in [prefix, suffix].into_iter().flatten() {
                let extent = survivor.range();
                reservations.insert(extent.start, extent);
            }
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

        let allocator = TestPageAllocator::new();
        let platform = &allocator;
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
                unsafe { release_fixture_pages(platform, range) };
            }
        });
        let map_native = TestPageAllocator::allocate_native_pages::<4096>;
        let system_allocation_granularity = platform
            .native
            .sys_info
            .read()
            .unwrap()
            .dwAllocationGranularity as usize;
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
        let addr = map_native(
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
        let addr2 = map_native(
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
                map_native(
                    platform,
                    occupied.clone(),
                    initial_state,
                    false,
                    false,
                    FixedAddressBehavior::NoReplace,
                ),
                Err(litebox::platform::page_mgmt::AllocationError::AddressInUse)
            ));
            let relocated = map_native(
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
            map_native(
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
        map_native(
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
        let suggested_populated_inaccessible_addr = map_native(
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
        let populated_inaccessible_addr = map_native(
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
        map_native(
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
        let inaccessible_addr = map_native(
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
        unsafe { release_fixture_pages(platform, inaccessible_addr..inaccessible_addr + 0x1000) };
        let reused_addr = map_native(
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
        let committed_noaccess_addr = map_native(
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
            TestPageAllocator::decommit(
                &platform.reservations.lock().unwrap(),
                committed_noaccess_addr..committed_noaccess_addr + 0x1000,
            )
        };
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
        type Pages = TestPageAllocator;
        let allocator = Pages::new();
        let platform = &allocator;
        let first = Pages::allocate_native_pages::<4096>(
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
        Pages::allocate_native_pages::<4096>(
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
            release_fixture_pages(platform, first..second);
        }
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        Pages::allocate_native_pages::<4096>(
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
            release_fixture_pages(platform, first..second + 4096);
        }
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_RESERVE);
        assert_eq!(platform.reservations.lock().unwrap().len(), 1);
        // SAFETY: The test relinquishes the complete native backing, including unused padding.
        unsafe {
            release_fixture_pages(
                platform,
                first..first + WindowsUserland::RESERVATION_ALIGNMENT,
            )
        };
        do_query_on_region(&mut information, first as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_FREE);
        assert!(platform.reservations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_page_backend_native_boundaries_and_rollback() {
        use litebox::platform::page_mgmt::AllocationError;

        const GRANULARITY: usize = 0x10000;
        type Pages = TestPageAllocator;
        let allocator = Pages::new();
        let platform = &allocator;
        let probe = Pages::allocate_native_pages::<4096>(
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
        unsafe { release_fixture_pages(platform, probe..probe + 4 * GRANULARITY) };
        let left = probe;
        let right = probe + 3 * GRANULARITY - 4096;
        for address in [left, right] {
            Pages::allocate_native_pages::<4096>(
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
            .native
            .fail_commit_at
            .store(probe + GRANULARITY, core::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            Pages::allocate_native_pages::<4096>(
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

        Pages::allocate_native_pages::<4096>(
            platform,
            range.clone(),
            PageState::Reserved,
            false,
            false,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
        assert!(matches!(
            Pages::allocate_native_pages::<4096>(
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
            .native
            .fail_commit_at
            .store(0, core::sync::atomic::Ordering::Relaxed);
        // SAFETY: The test exclusively owns these allocations and stops using them before removal.
        unsafe {
            Pages::allocate_native_pages::<4096>(
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
            Pages::protect(
                &platform.reservations.lock().unwrap(),
                probe + GRANULARITY..probe + GRANULARITY + 4096,
                MemoryRegionPermissions::empty(),
            );
            Pages::protect(
                &platform.reservations.lock().unwrap(),
                range.clone(),
                MemoryRegionPermissions::READ,
            );
            assert_eq!((range.start as *const u8).read(), 0x5a);
            assert_eq!(((range.end - 1) as *const u8).read(), 0xa5);
            for address in [range.start, probe + GRANULARITY, probe + 2 * GRANULARITY] {
                do_query_on_region(&mut information, address as *mut c_void);
                assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                assert_eq!(information.Protect, Win32_Memory::PAGE_READONLY);
            }
            TestPageAllocator::decommit(&platform.reservations.lock().unwrap(), range.clone());
            Pages::allocate_native_pages::<4096>(
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
            release_fixture_pages(platform, range);
            for address in [left, right] {
                release_fixture_pages(platform, address..address + 4096);
            }
        }
        assert_eq!(platform.reservations.lock().unwrap().len(), 2);
        // SAFETY: All allocations are gone; the test relinquishes the retained boundary extents.
        unsafe {
            for extent in [
                probe..probe + GRANULARITY,
                probe + 2 * GRANULARITY..probe + 3 * GRANULARITY,
            ] {
                release_fixture_pages(platform, extent);
            }
        }
        assert!(platform.reservations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_page_backend_failed_replacement_preserves_existing_pages() {
        use litebox::platform::page_mgmt::AllocationError;

        type Pages = TestPageAllocator;
        let allocator = Pages::new();
        let platform = &allocator;
        let pointer = Pages::allocate_native_pages::<4096>(
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
            Pages::allocate_native_pages::<4096>(
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
            .native
            .fail_commit_at
            .store(pointer + 4096, core::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            Pages::allocate_native_pages::<4096>(
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
            .native
            .fail_commit_at
            .store(0, core::sync::atomic::Ordering::Relaxed);
        Pages::allocate_native_pages::<4096>(
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
            release_fixture_pages(platform, pointer..pointer + 8192);
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

    #[test]
    fn test_page_reservation_rejects_foreign_memory() {
        use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
        use litebox::platform::page_mgmt::AllocationError;

        let allocator = TestPageAllocator::new();
        let platform = allocator.native;
        let manager =
            litebox::mm::LinuxPageManager::<_, 4096>::new(&litebox::LiteBox::new(platform));
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
            // SAFETY: Guest mappings and the foreign reservation are unused.
            unsafe {
                manager.release_memory().unwrap();
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
                        None,
                    ),
                    Err(AllocationError::AddressInUseByPlatform)
                ));
                for initial_state in [
                    PageState::Reserved,
                    PageState::Committed(MemoryRegionPermissions::READ),
                ] {
                    assert!(matches!(
                        TestPageAllocator::allocate_native_pages::<4096>(
                            &allocator,
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
                let relocated = TestPageAllocator::allocate_native_pages::<4096>(
                    &allocator,
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
                    release_fixture_pages(
                        &allocator,
                        relocated..relocated + WindowsUserland::RESERVATION_ALIGNMENT,
                    )
                };
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
