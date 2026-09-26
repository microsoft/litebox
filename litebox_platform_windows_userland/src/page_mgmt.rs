// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    AllocationError, FixedAddressBehavior, GetCurrentProcess, GetLastError,
    MemoryRegionPermissions, PrefetchVirtualMemory, UserMutPtr, VirtualAlloc2, VirtualFree,
    VirtualProtect, Win32_Foundation, Win32_Memory, WindowsUserland, c_void,
};
use std::sync::Mutex;

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

#[derive(Clone, Copy)]
struct Win32CallError(u32);

impl Win32CallError {
    fn last() -> Self {
        Self(unsafe { GetLastError() })
    }
}

static VIRTUAL_MEMORY_MUTATION_LOCK: Mutex<()> = Mutex::new(());

fn lock_virtual_memory_mutation() -> std::sync::MutexGuard<'static, ()> {
    match VIRTUAL_MEMORY_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        // A panic while this lock was held could have interrupted a VM mutation. Continuing with
        // an untrusted address-space state would be less safe than terminating the process.
        Err(_) => std::process::abort(),
    }
}

fn query_memory_region(
    base_addr: *mut c_void,
) -> Result<Win32_Memory::MEMORY_BASIC_INFORMATION, Win32CallError> {
    let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            base_addr,
            &raw mut mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    if ok {
        Ok(mbi)
    } else {
        Err(Win32CallError::last())
    }
}

fn do_prefetch_on_range(start: usize, size: usize) -> Result<(), Win32CallError> {
    let ok = unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0) != 0
    };
    if ok {
        Ok(())
    } else {
        Err(Win32CallError::last())
    }
}

fn do_query_on_region(mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION, base_addr: *mut c_void) {
    match query_memory_region(base_addr) {
        Ok(result) => *mbi = result,
        Err(error) => panic!("VirtualQuery addr={base_addr:p} failed: {}", error.0),
    }
}

fn memory_range_is_in_state(
    mut range: core::ops::Range<usize>,
    expected_state: Win32_Memory::VIRTUAL_ALLOCATION_TYPE,
) -> Result<bool, Win32CallError> {
    while !range.is_empty() {
        let mbi = query_memory_region(range.start as *mut c_void)?;
        if mbi.State != expected_state {
            return Ok(false);
        }
        let len = mbi.RegionSize.min(range.len());
        if len == 0 {
            return Ok(false);
        }
        range.start += len;
    }
    Ok(true)
}

enum FixedAllocationAction {
    CommitReserved(core::ops::Range<usize>),
    ReserveAndCommit {
        reservation: core::ops::Range<usize>,
        commit: core::ops::Range<usize>,
    },
    /// `Replace` over pages that are already committed: discard them and commit afresh, as
    /// Linux's `MAP_FIXED` discards the mapping it lands on.
    RecommitCommitted(core::ops::Range<usize>),
}

enum AllocationUndo {
    /// Release the complete reservation identified by the exact base returned by `VirtualAlloc2`.
    ReleaseReservation { base: usize },
    /// Return pages that this transaction committed inside a reservation it did not create.
    DecommitReservedPages(core::ops::Range<usize>),
}

fn release_reservation(base: usize) -> Result<(), Win32CallError> {
    let ok = unsafe { VirtualFree(base as *mut c_void, 0, Win32_Memory::MEM_RELEASE) } != 0;
    if ok {
        Ok(())
    } else {
        Err(Win32CallError::last())
    }
}

fn decommit_reserved_pages(range: core::ops::Range<usize>) -> Result<(), Win32CallError> {
    let ok = unsafe {
        VirtualFree(
            range.start as *mut c_void,
            range.len(),
            Win32_Memory::MEM_DECOMMIT,
        )
    } != 0;
    if ok {
        Ok(())
    } else {
        Err(Win32CallError::last())
    }
}

fn rollback_allocation(
    journal: &mut alloc::vec::Vec<AllocationUndo>,
) -> Result<(), Win32CallError> {
    let mut first_error = None;
    while let Some(undo) = journal.pop() {
        let result = match undo {
            AllocationUndo::ReleaseReservation { base } => release_reservation(base),
            AllocationUndo::DecommitReservedPages(range) => decommit_reserved_pages(range),
        };
        if let Err(error) = result
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn rollback_allocation_or_abort(journal: &mut alloc::vec::Vec<AllocationUndo>) {
    if rollback_allocation(journal).is_err() {
        // Returning after an incomplete rollback would publish a partially-mutated address space.
        std::process::abort();
    }
}

fn fixed_allocation_error(error: Win32CallError) -> AllocationError {
    if error.0 == Win32_Foundation::ERROR_INVALID_ADDRESS {
        AllocationError::AddressInUse
    } else {
        AllocationError::OutOfMemory
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
        let Ok(sys_info) = self.sys_info.read() else {
            std::process::abort();
        };
        let page_size = sys_info.dwPageSize as usize;
        let allocation_granularity = sys_info.dwAllocationGranularity as usize;
        drop(sys_info);

        if ALIGN == 0
            || page_size == 0
            || allocation_granularity == 0
            || !allocation_granularity.is_power_of_two()
            || !ALIGN.is_multiple_of(page_size)
            || !suggested_range.start.is_multiple_of(ALIGN)
            || !suggested_range.end.is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        let Some(size) = suggested_range.end.checked_sub(suggested_range.start) else {
            return Err(AllocationError::OutOfMemory);
        };
        if size == 0 {
            return Err(AllocationError::OutOfMemory);
        }

        if suggested_range.start != 0 {
            if suggested_range.start
                < <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
            {
                return Err(AllocationError::BelowMinAddress);
            }
            if suggested_range.end
                > <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
            {
                return Err(AllocationError::AboveMaxAddress);
            }
        }

        // TODO: For Windows, there is no MAP_GROWDOWN feature so far.
        let _ = can_grow_down;
        let flags = prot_flags(initial_permissions);

        // The process address space is shared by every `WindowsUserland` value. Keep discovery,
        // application, prefetch, and any rollback in one critical section so another platform VM
        // operation cannot observe the plan and invalidate it between regions.
        let _vm_guard = lock_virtual_memory_mutation();

        if suggested_range.start != 0 {
            let mut plan = alloc::vec::Vec::new();
            let mut remaining = suggested_range.clone();
            let mut has_committed_page = false;

            // Discover the entire target before changing any page. Every potential allocation while
            // growing `plan` therefore happens before the final preflight below.
            while !remaining.is_empty() {
                let mbi = query_memory_region(remaining.start as *mut c_void)
                    .map_err(fixed_allocation_error)?;
                let len = mbi.RegionSize.min(remaining.len());
                if len == 0 {
                    return Err(AllocationError::AddressInUse);
                }
                let region = remaining.start..remaining.start + len;
                match mbi.State {
                    // `Vmem` only asks for `Replace` when its own mappings cover the whole
                    // range, so committed pages here are ones it is replacing.
                    Win32_Memory::MEM_COMMIT
                        if fixed_address_behavior == FixedAddressBehavior::Replace =>
                    {
                        plan.try_reserve(1)
                            .map_err(|_| AllocationError::OutOfMemory)?;
                        plan.push(FixedAllocationAction::RecommitCommitted(region.clone()));
                    }
                    Win32_Memory::MEM_COMMIT => has_committed_page = true,
                    Win32_Memory::MEM_RESERVE => {
                        plan.try_reserve(1)
                            .map_err(|_| AllocationError::OutOfMemory)?;
                        plan.push(FixedAllocationAction::CommitReserved(region.clone()));
                    }
                    Win32_Memory::MEM_FREE => {
                        if region.end.checked_add(allocation_granularity - 1).is_none() {
                            return Err(AllocationError::OutOfMemory);
                        }
                        let reservation = self.round_down_to_granu(region.start)
                            ..self.round_up_to_granu(region.end);
                        plan.try_reserve(1)
                            .map_err(|_| AllocationError::OutOfMemory)?;
                        plan.push(FixedAllocationAction::ReserveAndCommit {
                            reservation,
                            commit: region.clone(),
                        });
                    }
                    _ => return Err(AllocationError::AddressInUse),
                }
                remaining.start = region.end;
            }

            // Committed pages can only be taken over by `Replace` (planned above as
            // `RecommitCommitted`). Hint may fall back elsewhere; `NoReplace` rejects the occupied
            // target without touching it.
            if !has_committed_page {
                let mut journal = alloc::vec::Vec::new();
                journal
                    .try_reserve_exact(plan.len())
                    .map_err(|_| AllocationError::OutOfMemory)?;

                // Revalidate the complete plan after all journal storage is allocated. A free target
                // includes the allocation-granularity halo that `MEM_RESERVE` will actually claim.
                let mut plan_is_available = true;
                for action in &plan {
                    let available = match action {
                        FixedAllocationAction::CommitReserved(range) => {
                            memory_range_is_in_state(range.clone(), Win32_Memory::MEM_RESERVE)
                        }
                        FixedAllocationAction::ReserveAndCommit { reservation, .. } => {
                            memory_range_is_in_state(reservation.clone(), Win32_Memory::MEM_FREE)
                        }
                        FixedAllocationAction::RecommitCommitted(range) => {
                            memory_range_is_in_state(range.clone(), Win32_Memory::MEM_COMMIT)
                        }
                    }
                    .map_err(fixed_allocation_error)?;
                    plan_is_available &= available;
                }

                if plan_is_available {
                    for action in &plan {
                        match action {
                            FixedAllocationAction::CommitReserved(range) => {
                                let committed = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        range.start as *mut c_void,
                                        range.len(),
                                        Win32_Memory::MEM_COMMIT,
                                        flags,
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                if committed.is_null() {
                                    // Capture the originating failure before rollback can overwrite it.
                                    let error = Win32CallError::last();
                                    rollback_allocation_or_abort(&mut journal);
                                    return Err(fixed_allocation_error(error));
                                }
                                // Capacity was reserved before the final preflight, so publishing
                                // this undo record cannot allocate or fail.
                                journal.push(AllocationUndo::DecommitReservedPages(range.clone()));
                            }
                            FixedAllocationAction::ReserveAndCommit {
                                reservation,
                                commit,
                            } => {
                                let reserved = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        reservation.start as *mut c_void,
                                        reservation.len(),
                                        Win32_Memory::MEM_RESERVE,
                                        Win32_Memory::PAGE_NOACCESS,
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                if reserved.is_null() {
                                    let error = Win32CallError::last();
                                    rollback_allocation_or_abort(&mut journal);
                                    return Err(fixed_allocation_error(error));
                                }
                                // `MEM_RELEASE` must use this exact base and a zero size. Record it
                                // before the commit, which is the next fallible operation.
                                journal.push(AllocationUndo::ReleaseReservation {
                                    base: reserved as usize,
                                });

                                let committed = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        commit.start as *mut c_void,
                                        commit.len(),
                                        Win32_Memory::MEM_COMMIT,
                                        flags,
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                if committed.is_null() {
                                    let error = Win32CallError::last();
                                    rollback_allocation_or_abort(&mut journal);
                                    return Err(fixed_allocation_error(error));
                                }
                            }
                            // Destructive, so applied only after every reversible step below.
                            FixedAllocationAction::RecommitCommitted(_) => {}
                        }
                    }

                    // Replacing committed pages discards their contents and cannot be undone, so
                    // it runs last. A failure before the first page is discarded rolls back as
                    // usual; after that, returning would leave the caller believing the old
                    // mapping is intact, so it is fatal like an incomplete rollback.
                    let mut discarded_committed_pages = false;
                    for action in &plan {
                        let FixedAllocationAction::RecommitCommitted(range) = action else {
                            continue;
                        };
                        if let Err(error) = decommit_reserved_pages(range.clone()) {
                            if discarded_committed_pages {
                                std::process::abort();
                            }
                            rollback_allocation_or_abort(&mut journal);
                            return Err(fixed_allocation_error(error));
                        }
                        discarded_committed_pages = true;
                        let committed = unsafe {
                            VirtualAlloc2(
                                GetCurrentProcess(),
                                range.start as *mut c_void,
                                range.len(),
                                Win32_Memory::MEM_COMMIT,
                                flags,
                                core::ptr::null_mut(),
                                0,
                            )
                        };
                        if committed.is_null() {
                            std::process::abort();
                        }
                    }

                    if populate_pages_immediately
                        && let Err(error) =
                            do_prefetch_on_range(suggested_range.start, suggested_range.len())
                    {
                        if discarded_committed_pages {
                            std::process::abort();
                        }
                        rollback_allocation_or_abort(&mut journal);
                        return Err(fixed_allocation_error(error));
                    }

                    // Disarm rollback only after every requested step has succeeded.
                    journal.clear();
                    return Ok(UserMutPtr::from_ptr(suggested_range.start as *mut u8));
                }
            }

            match fixed_address_behavior {
                FixedAddressBehavior::Hint => {}
                FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => {
                    return Err(AllocationError::AddressInUse);
                }
            }
            Err(error) => return Err(error),
        };
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            Self::decommit_pages(&reservations, range.clone());
        }

        // Ask Windows to select an address. Reserve an allocation-granularity-sized VAD, but commit
        // only the requested pages so later commits inside the same reservation remain valid.
        if size.checked_add(allocation_granularity - 1).is_none() {
            return Err(AllocationError::OutOfMemory);
        }
        let reservation_size = self.round_up_to_granu(size);
        let reserved = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                core::ptr::null_mut(),
                reservation_size,
                Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_NOACCESS,
                core::ptr::null_mut(),
                0,
            )
        };
        if reserved.is_null() {
            return Err(AllocationError::OutOfMemory);
        }

        let committed = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                reserved,
                size,
                Win32_Memory::MEM_COMMIT,
                flags,
                core::ptr::null_mut(),
                0,
            )
        };
        if committed.is_null() {
            let _error = Win32CallError::last();
            if release_reservation(reserved as usize).is_err() {
                std::process::abort();
            }
            return Err(AllocationError::OutOfMemory);
        }

        if populate_pages_immediately
            && let Err(_error) = do_prefetch_on_range(committed as usize, size)
        {
            if release_reservation(reserved as usize).is_err() {
                std::process::abort();
            }
            return Err(AllocationError::OutOfMemory);
        }
        Ok(UserMutPtr::from_ptr(committed.cast::<u8>()))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);
        let _vm_guard = lock_virtual_memory_mutation();
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                Ok(state == Win32_Memory::MEM_FREE
                    || unsafe {
                        VirtualFree(r.start as *mut c_void, r.len(), Win32_Memory::MEM_DECOMMIT)
                    } != 0)
            },
        )
        .expect("deallocate_pages failed");
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(new_permissions);
        let _vm_guard = lock_virtual_memory_mutation();
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                debug_assert_eq!(
                    state,
                    Win32_Memory::MEM_COMMIT,
                    "Trying to change permissions on a non-committed region: {:p}-{:p}",
                    r.start as *mut c_void,
                    r.end as *mut c_void
                );
                let mut old_protect: u32 = 0;
                Ok(unsafe {
                    VirtualProtect(r.start as *mut c_void, r.len(), flags, &raw mut old_protect)
                } != 0)
            },
        )
        .expect("update_permissions failed");
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
