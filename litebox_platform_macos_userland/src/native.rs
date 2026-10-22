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
#[cfg(feature = "shared_cache")]
use super::{MachBoolean, MachVmInheritance, MachVmProtection, mach_vm_remap};

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

    /// Replace the owned pages of `range` with a private view of `file` at `offset` (host-page
    /// aligned). `owned` is unchanged: the view takes over the pages' ownership. Written copies of
    /// signed file pages lose their code-signing validation (`vm_page_copy`), so making them
    /// executable requires a runner without code-signing enforcement (no hardened runtime).
    #[cfg(feature = "shared_cache")]
    pub(super) fn map_file(
        &mut self,
        range: &Range<usize>,
        file: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        permissions: Perm,
    ) -> Result<(), PermissionUpdateError> {
        // On arm64 XNU syncs the icache only on a page's first executable mapping
        // (`vm_fault_enter_set_mapped`, osfmk/vm/vm_fault.c), so only `update_permissions`, which
        // invalidates, may make the view executable.
        if permissions.contains(Perm::EXEC) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        if self.owned.gaps(range).next().is_some() {
            return Err(PermissionUpdateError::Unallocated);
        }
        let offset = libc::off_t::try_from(offset).map_err(|_| PermissionUpdateError::Unaligned)?;
        // Like `map_fixed`, a failed MAP_FIXED leaves the replaced pages in place: the file path
        // also ends in `vm_map_enter` (`vm_map_enter_mem_object_control`).
        // SAFETY: the caller owns the whole range and excludes its users, so MAP_FIXED replaces
        // only this instance's idle pages.
        let mapped = unsafe {
            libc::mmap(
                range.start as *mut _,
                range.len(),
                native_prot(permissions),
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                std::os::fd::AsRawFd::as_raw_fd(&file),
                offset,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(permission_error());
        }
        Ok(())
    }

    /// Replace the owned pages of `range` with private pages holding `bytes` (as long as `range`)
    /// and `permissions`. They are built in a staging mapping and moved in by one `mach_vm_remap`
    /// with `VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE`: XNU's `vm_map_remap` removes the old entries
    /// with `vm_map_delete_and_iunlock(VM_MAP_REMOVE_TO_OVERWRITE)`, which holds the range with a
    /// sentinel entry and then under the map interlock until the new entries are inserted, and
    /// fails having removed nothing (`vm_map_locate_space_fixed`, osfmk/vm/vm_map.c). An access
    /// therefore faults or sees all of `bytes`. `owned` is unchanged: the new pages take over the old pages' ownership.
    #[cfg(feature = "shared_cache")]
    pub(super) fn publish(
        &mut self,
        range: &Range<usize>,
        bytes: &[u8],
        permissions: Perm,
    ) -> Result<(), PermissionUpdateError> {
        // As in `map_file`, only `update_permissions`, which invalidates the icache, may make
        // the pages executable.
        if permissions.contains(Perm::EXEC) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        if self.owned.gaps(range).next().is_some() {
            return Err(PermissionUpdateError::Unallocated);
        }
        // SAFETY: without MAP_FIXED the kernel chooses unused pages.
        let staging = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                range.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if staging == libc::MAP_FAILED {
            return Err(permission_error());
        }
        // SAFETY: mmap just created this mapping, which this call exclusively owns.
        let staging = unsafe { Mapping::new(staging as usize, range.len()) };
        let pages = staging.base() as *mut libc::c_void;
        // SAFETY: the staging mapping is writable, private to this call, and as long as `bytes`.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pages.cast(), bytes.len()) };
        // SAFETY: the staging mapping is private to this call.
        if unsafe { libc::mprotect(pages, range.len(), native_prot(permissions)) } != 0 {
            return Err(permission_error());
        }
        let mut target = range.start as u64;
        let mut current = MachVmProtection::empty();
        let mut maximum = MachVmProtection::empty();
        // SAFETY: the caller owns the whole range and excludes its writers, so OVERWRITE replaces
        // only this instance's pages. copy=false shares the staging pages, with their protection,
        // instead of copying them; dropping `staging` leaves the target their only mapping.
        let result = unsafe {
            mach_vm_remap(
                mach_task_self(),
                &raw mut target,
                range.len() as u64,
                0,
                MachVmFlags::FIXED | MachVmFlags::OVERWRITE,
                mach_task_self(),
                staging.base() as u64,
                MachBoolean::FALSE,
                &raw mut current,
                &raw mut maximum,
                MachVmInheritance::Copy,
            )
        };
        if result != KernReturn::SUCCESS {
            return Err(PermissionUpdateError::PlatformFailure);
        }
        Ok(())
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
