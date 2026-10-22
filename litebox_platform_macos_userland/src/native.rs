// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native host-page management.
//!
//! Ranges reaching [`Pages`] must be nonempty and host-page aligned. Each operation issues a
//! constant number of syscalls, plus one per unowned gap or owned run where the semantics
//! require it.

use std::ops::Range;

use rangemap::RangeSet;

use litebox::utils::TruncateExt as _;
use litebox_common_macos::CopyOnWriteError;

use super::{
    AllocationError, DeallocationError, FixedAddressBehavior, HOST_PAGE_SIZE, KernReturn,
    MachBoolean, MachVmFlags, MachVmInheritance, MachVmProtection, MemoryRegionPermissions as Perm,
    PermissionUpdateError, TASK_ADDR_MAX, TASK_ADDR_MIN, mach_task_self, mach_vm_allocate,
    mach_vm_remap, prot_flags, sys_icache_invalidate,
};

/// Guest copy-on-write pages inherit like `mmap`'d guest pages (`VM_INHERIT_DEFAULT`).
const GUEST_INHERITANCE: MachVmInheritance = MachVmInheritance::Copy;

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

/// Map a private copy of `source` with `prot` wherever the kernel places it.
/// `copy=TRUE` gives the result its own copy-on-write object, so later writes on either side stay
/// private (`vm_map_remap`, osfmk/vm/vm_map.c). Legacy remap keeps each source entry's maximum
/// protection and reports their intersection (`vm_map_remap_extract`). Later `update_permissions`
/// calls may ask for any protection, so a maximum without read, write and execute is refused.
fn remap_copy(source: &[u8], prot: i32) -> Result<Mapping, CopyOnWriteError> {
    let len = source.len();
    let mut target = 0;
    let mut current = MachVmProtection::empty();
    let mut maximum = MachVmProtection::empty();
    // SAFETY: ANYWHERE never overwrites existing mappings; `source` stays mapped and all outputs
    // are valid.
    let result = unsafe {
        mach_vm_remap(
            mach_task_self(),
            &raw mut target,
            len as u64,
            0,
            MachVmFlags::ANYWHERE,
            mach_task_self(),
            source.as_ptr() as u64,
            MachBoolean::TRUE,
            &raw mut current,
            &raw mut maximum,
            GUEST_INHERITANCE,
        )
    };
    if result != KernReturn::SUCCESS {
        litebox_util_log::warn!(
            kr:? = result, len:% = format_args!("{len:#x}");
            "copy-on-write staging mach_vm_remap failed"
        );
        return Err(CopyOnWriteError::Host);
    }
    // SAFETY: mach_vm_remap just created this mapping.
    let mapping = unsafe { Mapping::new(target.trunc(), len) };
    if !maximum
        .contains(MachVmProtection::READ | MachVmProtection::WRITE | MachVmProtection::EXECUTE)
    {
        litebox_util_log::debug!(
            maximum:% = format_args!("{:#x}", maximum.bits());
            "copy-on-write source maximum protection lacks read, write or execute"
        );
        return Err(CopyOnWriteError::UnsupportedSource);
    }
    // SAFETY: the mapping was just created by this call and has no users.
    if unsafe { libc::mprotect(mapping.base() as *mut _, len, prot) } != 0 {
        let error = std::io::Error::last_os_error();
        litebox_util_log::warn!(error:% = error, prot; "copy-on-write staging mprotect failed");
        return Err(CopyOnWriteError::Host);
    }
    Ok(mapping)
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

    /// Replace the owned pages at `start` with a private copy-on-write copy of the host pages of
    /// `source`; see [`litebox_common_macos::CopyOnWritePages`]. `source`'s host mappings must
    /// allow read, write and execute, as anonymous and `MAP_PRIVATE` file memory do. Any failure
    /// leaves the target unchanged.
    pub(super) fn replace_with_copy_on_write(
        &mut self,
        start: usize,
        source: &[u8],
        permissions: Perm,
    ) -> Result<(), CopyOnWriteError> {
        let len = source.len();
        if len == 0
            || !len.is_multiple_of(HOST_PAGE_SIZE)
            || !start.is_multiple_of(HOST_PAGE_SIZE)
            || !(source.as_ptr() as usize).is_multiple_of(HOST_PAGE_SIZE)
        {
            return Err(CopyOnWriteError::Unaligned);
        }
        // On arm64 XNU syncs the icache only on a page's first executable mapping
        // (`vm_fault_enter_set_mapped`, osfmk/vm/vm_fault.c), so an executable copy of rewritten
        // source pages at an address that ran other code can run stale instructions. Only
        // `update_permissions` invalidates.
        if permissions.contains(Perm::EXEC) {
            return Err(CopyOnWriteError::Unsupported);
        }
        let range = start
            .checked_add(len)
            .map(|end| start..end)
            .ok_or(CopyOnWriteError::NotMapped)?;
        if self.owned.gaps(&range).next().is_some() {
            litebox_util_log::debug!(
                range:% = format_args!("{:#x}..{:#x}", range.start, range.end);
                "copy-on-write target is not owned"
            );
            return Err(CopyOnWriteError::NotMapped);
        }
        // Stage the copy with its final protections elsewhere first, so a failure leaves the
        // target untouched. `mach_vm_remap_new` could copy straight to the target with
        // FIXED|OVERWRITE, but it rejects a maximum protection holding both write and execute
        // (`mach_vm_remap_new_external`, osfmk/vm/vm_user.c), so its copy could never later
        // switch between RW and RX.
        let staged = remap_copy(source, native_prot(permissions))?;
        let mut target = range.start as u64;
        let mut current = MachVmProtection::empty();
        let mut maximum = MachVmProtection::empty();
        // XNU extracts the staged entries, with their protections, before the atomic
        // FIXED|OVERWRITE removal (`vm_map_remap`, `vm_map_locate_space_fixed`), so a failure
        // leaves the target as it was.
        // SAFETY: `owned` covers the range; the caller excludes users of the replaced pages.
        let result = unsafe {
            mach_vm_remap(
                mach_task_self(),
                &raw mut target,
                len as u64,
                0,
                MachVmFlags::FIXED | MachVmFlags::OVERWRITE,
                mach_task_self(),
                staged.base() as u64,
                MachBoolean::FALSE,
                &raw mut current,
                &raw mut maximum,
                GUEST_INHERITANCE,
            )
        };
        if result != KernReturn::SUCCESS {
            litebox_util_log::warn!(
                kr:? = result, range:% = format_args!("{:#x}..{:#x}", range.start, range.end);
                "copy-on-write mach_vm_remap onto the target failed"
            );
            return Err(CopyOnWriteError::Host);
        }
        // The target holds its own reference to the copy; `staged` unmaps on drop.
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn owns_any(&self, range: &Range<usize>) -> bool {
        self.owned.overlaps(range)
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
