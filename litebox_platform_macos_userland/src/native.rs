// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native host-page management.
//!
//! Ranges reaching [`Pages`] must be nonempty and host-page aligned. Each operation issues a
//! constant number of syscalls, plus one per unowned gap or owned run where the semantics
//! require it.

use std::ops::Range;

use rangemap::RangeSet;

use super::{
    AllocationError, DeallocationError, FixedAddressBehavior, KernReturn, MachVmFlags,
    MemoryRegionPermissions as Perm, PermissionUpdateError, TASK_ADDR_MAX, TASK_ADDR_MIN,
    mach_task_self, mach_vm_allocate, prot_flags, sys_icache_invalidate,
};

#[derive(Default)]
pub(super) struct Pages {
    /// Mappings created by this instance. `mprotect`, `munmap`, and `MAP_FIXED` may target only
    /// these ranges or mappings the current call created itself: XNU applies `mprotect` to any
    /// mapped range, including host memory, so this set is the only guard against changing host
    /// protections.
    owned: RangeSet<usize>,
}

pub(super) fn permission_error() -> PermissionUpdateError {
    // SAFETY: __error returns this thread's errno slot.
    match unsafe { *libc::__error() } {
        libc::EACCES | libc::EPERM => PermissionUpdateError::PermissionDenied,
        libc::ENOMEM => PermissionUpdateError::OutOfMemory,
        _ => PermissionUpdateError::PlatformFailure,
    }
}

pub(super) fn allocation_error(error: PermissionUpdateError) -> AllocationError {
    match error {
        PermissionUpdateError::PermissionDenied => AllocationError::PermissionDenied,
        _ => AllocationError::OutOfMemory,
    }
}

/// Owned native mapping. Failing to unmap it on drop means the ownership invariant is broken.
pub(super) struct Mapping {
    base: usize,
    len: usize,
}

impl Mapping {
    /// # Safety
    ///
    /// The caller must exclusively own the native mapping `[base, base + len)`; dropping the
    /// result unmaps it.
    pub(super) unsafe fn new(base: usize, len: usize) -> Self {
        Self { base, len }
    }

    pub(super) fn base(&self) -> usize {
        self.base
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the entire native mapping.
        assert_eq!(unsafe { libc::munmap(self.base as *mut _, self.len) }, 0);
    }
}

/// EXEC implies READ: cache maintenance after enabling EXEC requires readable pages.
fn native_prot(permissions: Perm) -> i32 {
    if permissions.contains(Perm::EXEC) {
        prot_flags(permissions | Perm::READ)
    } else {
        prot_flags(permissions)
    }
}

/// Replace every page in `range` with fresh zero-filled memory. Callers leave `owned` unchanged on
/// error: if `MAP_FIXED` fails, `vm_map_enter` (osfmk/vm/vm_map.c) reinstates the replaced
/// mappings, which only superpages can prevent, and arm64 has none.
///
/// # Safety
///
/// `range` must be owned (in `owned` or reserved by the current call) and have no users.
unsafe fn map_fixed(range: &Range<usize>, permissions: Perm) -> Result<(), PermissionUpdateError> {
    // SAFETY: the caller owns the whole range, so MAP_FIXED replaces only this instance's pages.
    let mapped = unsafe {
        libc::mmap(
            range.start as *mut _,
            range.len(),
            native_prot(permissions),
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(permission_error());
    }
    Ok(())
}

impl Pages {
    pub(super) fn allocate(
        &mut self,
        range: Range<usize>,
        permissions: Perm,
        behavior: FixedAddressBehavior,
    ) -> Result<usize, AllocationError> {
        if permissions.contains(Perm::WRITE | Perm::EXEC) {
            return Err(AllocationError::PermissionDenied);
        }
        // Panics on SHARED before any side effect, including on the fixed path.
        let prot = native_prot(permissions);
        // No icache maintenance: XNU keeps fresh zero-fill pages instruction-coherent (on arm64 it
        // syncs a page first mapped executable: `vm_fault_enter_set_mapped`, osfmk/vm/vm_fault.c);
        // user-written bytes become executable only via `update_permissions`, which invalidates.
        if matches!(behavior, FixedAddressBehavior::Hint(_)) {
            let mut error = AllocationError::OutOfMemory;
            for hint in [range.start, 0] {
                // SAFETY: without MAP_FIXED the kernel chooses unused pages.
                let mapped = unsafe {
                    libc::mmap(
                        hint as *mut _,
                        range.len(),
                        prot,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    error = allocation_error(permission_error());
                    continue;
                }
                // SAFETY: mmap just created this mapping.
                let mapping = unsafe { Mapping::new(mapped as usize, range.len()) };
                let base = mapping.base();
                if base < TASK_ADDR_MIN
                    || base
                        .checked_add(range.len())
                        .is_none_or(|end| end > TASK_ADDR_MAX)
                {
                    continue;
                }
                std::mem::forget(mapping);
                self.owned.insert(base..base + range.len());
                return Ok(base);
            }
            return Err(error);
        }

        if behavior == FixedAddressBehavior::NoReplace && self.owned.overlaps(&range) {
            return Err(AllocationError::AddressInUse);
        }
        let mut reservations = Vec::new();
        for gap in self.owned.gaps(&range) {
            let mut address = gap.start as u64;
            // SAFETY: a FIXED reservation fails instead of overwriting existing (host) memory.
            let result = unsafe {
                mach_vm_allocate(
                    mach_task_self(),
                    &raw mut address,
                    gap.len() as u64,
                    MachVmFlags::FIXED,
                )
            };
            if result != KernReturn::SUCCESS {
                return Err(result.into());
            }
            // SAFETY: mach_vm_allocate just reserved this gap.
            reservations.push(unsafe { Mapping::new(gap.start, gap.len()) });
        }
        // SAFETY: owned pages and this call's reservations cover the range; the caller
        // excludes users of replaced pages.
        unsafe { map_fixed(&range, permissions) }.map_err(allocation_error)?;
        reservations.into_iter().for_each(std::mem::forget);
        self.owned.insert(range.clone());
        Ok(range.start)
    }

    pub(super) fn update_permissions(
        &mut self,
        range: Range<usize>,
        permissions: Perm,
    ) -> Result<(), PermissionUpdateError> {
        if permissions.contains(Perm::WRITE | Perm::EXEC) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        let prot = native_prot(permissions);
        if self.owned.gaps(&range).next().is_some() {
            return Err(PermissionUpdateError::Unallocated);
        }
        // XNU validates every page's maximum protection before changing any, so a failure
        // leaves the whole range unchanged.
        // SAFETY: the range is owned and the caller excludes conflicting accesses.
        if unsafe { libc::mprotect(range.start as *mut _, range.len(), prot) } != 0 {
            return Err(permission_error());
        }
        if permissions.contains(Perm::EXEC) {
            // SAFETY: the owned range was just made readable.
            unsafe { sys_icache_invalidate(range.start as *mut _, range.len()) };
        }
        Ok(())
    }

    pub(super) fn decommit(&mut self, range: Range<usize>) -> Result<(), DeallocationError> {
        if self.owned.gaps(&range).next().is_some() {
            return Err(DeallocationError::AlreadyUnallocated);
        }
        // SAFETY: the range is owned and the caller excludes all users.
        unsafe { map_fixed(&range, Perm::empty()) }
            .map_err(|_| DeallocationError::AlreadyUnallocated)
    }

    /// Unmap only owned pages; holes in `range` may hold host memory.
    pub(super) fn deallocate(&mut self, range: Range<usize>) {
        let runs: Vec<_> = self
            .owned
            .overlapping(&range)
            .map(|run| run.start.max(range.start)..run.end.min(range.end))
            .collect();
        for run in runs {
            // SAFETY: `owned` covers this run and removes it below.
            drop(unsafe { Mapping::new(run.start, run.len()) });
            self.owned.remove(run);
        }
    }
}
