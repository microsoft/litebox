// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel's record of a process's mappings and permissions.
//!
//! Contract (see `litebox_common_vm_abi`, Memory): this record is
//! authoritative for demand paging, call validation, and anything about
//! security or resources. The runner's shim chooses the layout of the
//! runner-managed area, but nothing here relies on its view; if the views
//! disagree, only that process's calls fail or no-op.

use alloc::boxed::Box;
use core::ops::Range;
use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions};
use litebox::platform::{PageManagementProvider, RawConstPointer as _, RawMutPointer as _};
use litebox_common_linux::vmem::{PAGE_SIZE, VmFlags, VmemPageFaultHandler};
use litebox_common_vm_abi::{Placement, Populate, Prot, Status};
use litebox_platform_vm_kernel::VmKernel;
use rangemap::RangeMap;

type UserConstPtr<T> = <VmKernel as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type UserMutPtr<T> = <VmKernel as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

fn permissions(prot: Prot) -> MemoryRegionPermissions {
    let mut permissions = MemoryRegionPermissions::empty();
    permissions.set(MemoryRegionPermissions::READ, prot.read());
    permissions.set(MemoryRegionPermissions::WRITE, prot.write());
    permissions.set(MemoryRegionPermissions::EXEC, prot.exec());
    permissions
}

fn vm_flags(prot: Prot) -> VmFlags {
    let mut flags = VmFlags::empty();
    flags.set(VmFlags::VM_READ, prot.read());
    flags.set(VmFlags::VM_WRITE, prot.write());
    flags.set(VmFlags::VM_EXEC, prot.exec());
    flags
}

/// # Errors
///
/// [`Status::InvalidArgument`] unless page-aligned and nonempty;
/// [`Status::Denied`] outside `bounds`.
pub(crate) fn checked_range(
    addr: u64,
    len: u64,
    bounds: Range<u64>,
) -> Result<Range<usize>, Status> {
    let end = addr.checked_add(len).ok_or(Status::InvalidArgument)?;
    if len == 0 || !addr.is_multiple_of(PAGE_SIZE as u64) || !len.is_multiple_of(PAGE_SIZE as u64) {
        return Err(Status::InvalidArgument);
    }
    if addr < bounds.start || end > bounds.end {
        return Err(Status::Denied);
    }
    let start = usize::try_from(addr).map_err(|_| Status::InvalidArgument)?;
    let end = usize::try_from(end).map_err(|_| Status::InvalidArgument)?;
    Ok(start..end)
}

/// x86 page-fault error code bit.
const PF_INSTRUCTION_FETCH: u64 = 1 << 4;

/// What [`Mappings`] needs of the platform; a seam for tests.
pub(crate) trait Frames {
    fn allocate(
        &self,
        range: Range<usize>,
        prot: Prot,
        placement: Placement,
        populate: Populate,
    ) -> Result<(), Status>;

    /// # Safety
    ///
    /// The kernel must hold no references into the range's user memory.
    unsafe fn release(&self, range: Range<usize>) -> Result<(), Status>;

    /// # Safety
    ///
    /// As for [`Self::release`].
    unsafe fn protect(&self, range: Range<usize>, prot: Prot) -> Result<(), Status>;

    /// Whether the page at `addr` was populated.
    ///
    /// # Safety
    ///
    /// For a page fault on a page mapped with `flags` that they allow.
    unsafe fn populate(&self, addr: usize, flags: VmFlags, error_code: u64) -> bool;
}

impl Frames for VmKernel {
    fn allocate(
        &self,
        range: Range<usize>,
        prot: Prot,
        placement: Placement,
        populate: Populate,
    ) -> Result<(), Status> {
        let behavior = match placement {
            Placement::NoReplace => FixedAddressBehavior::NoReplace,
            Placement::Replace => FixedAddressBehavior::Replace,
        };
        PageManagementProvider::<PAGE_SIZE>::allocate_pages(
            self,
            range,
            permissions(prot),
            false,
            populate == Populate::Now,
            behavior,
        )
        .map(|_| ())
        .map_err(|e| match e {
            litebox::platform::page_mgmt::AllocationError::OutOfMemory => Status::NoMemory,
            _ => Status::InvalidArgument,
        })
    }

    unsafe fn release(&self, range: Range<usize>) -> Result<(), Status> {
        // Safety: forwarded to the caller.
        unsafe { PageManagementProvider::<PAGE_SIZE>::release_pages(self, range) }
            .map_err(|_| Status::InvalidArgument)
    }

    unsafe fn protect(&self, range: Range<usize>, prot: Prot) -> Result<(), Status> {
        // Safety: forwarded to the caller.
        unsafe {
            PageManagementProvider::<PAGE_SIZE>::update_permissions(self, range, permissions(prot))
        }
        .map_err(|_| Status::InvalidArgument)
    }

    unsafe fn populate(&self, addr: usize, flags: VmFlags, error_code: u64) -> bool {
        // Safety: forwarded to the caller.
        unsafe { self.handle_page_fault(addr, flags, error_code) }.is_ok()
    }
}

/// Every method requires the owning process's address space to be current.
pub(crate) struct Mappings<F: Frames + 'static = VmKernel> {
    platform: &'static F,
    regions: core::cell::RefCell<RangeMap<usize, Prot>>,
}

impl<F: Frames + 'static> Mappings<F> {
    pub(crate) fn new(platform: &'static F) -> Self {
        Self {
            platform,
            regions: core::cell::RefCell::new(RangeMap::new()),
        }
    }

    /// A failed [`Placement::Replace`] leaves the range unmapped.
    pub(crate) fn map(
        &self,
        range: Range<usize>,
        prot: Prot,
        placement: Placement,
        populate: Populate,
    ) -> Result<(), Status> {
        if placement == Placement::NoReplace && self.regions.borrow().overlaps(&range) {
            return Err(Status::Exists);
        }
        self.platform
            .allocate(range.clone(), prot, placement, populate)
            .inspect_err(|_| {
                if placement == Placement::Replace {
                    // The old mapping may be partly gone.
                    let _ = self.unmap(range.clone());
                }
            })?;
        self.regions.borrow_mut().insert(range, prot);
        Ok(())
    }

    pub(crate) fn unmap(&self, range: Range<usize>) -> Result<(), Status> {
        // Safety: the process gives up the range; the kernel holds no
        // references into user memory.
        unsafe { self.platform.release(range.clone()) }?;
        self.regions.borrow_mut().remove(range);
        Ok(())
    }

    /// Unmapped parts of `range` stay unmapped.
    pub(crate) fn protect(&self, range: Range<usize>, prot: Prot) -> Result<(), Status> {
        // Safety: the kernel holds no references into user memory.
        unsafe { self.platform.protect(range.clone(), prot) }?;
        let mut regions = self.regions.borrow_mut();
        let mapped: alloc::vec::Vec<Range<usize>> = regions
            .overlapping(&range)
            .map(|(r, _)| r.start.max(range.start)..r.end.min(range.end))
            .collect();
        for r in mapped {
            regions.insert(r, prot);
        }
        Ok(())
    }

    /// Whether the fault at `addr` was resolved by populating the page.
    pub(crate) fn demand_page(&self, addr: usize, error_code: u64) -> bool {
        let Some(prot) = self
            .regions
            .try_borrow()
            .ok()
            .and_then(|r| r.get(&addr).copied())
        else {
            return false;
        };
        let flags = vm_flags(prot);
        // The platform's check lets a fetch from a not-present page through;
        // NX would refuse it only on the retry, after a frame was spent.
        let fetch = error_code & PF_INSTRUCTION_FETCH != 0;
        if (fetch && !prot.exec())
            || <VmKernel as VmemPageFaultHandler>::access_error(error_code, flags)
        {
            return false;
        }
        // Safety: called for a page fault on a page the process mapped with
        // `flags`, and the access is allowed.
        unsafe { self.platform.populate(addr, flags, error_code) }
    }
}

/// # Errors
///
/// [`Status::Fault`] if any byte is inaccessible.
pub(crate) fn copy_from_user(addr: u64, len: usize) -> Result<Box<[u8]>, Status> {
    if len == 0 {
        return Ok(Box::default());
    }
    let addr = usize::try_from(addr).map_err(|_| Status::Fault)?;
    UserConstPtr::<u8>::from_usize(addr)
        .to_owned_slice(len)
        .ok_or(Status::Fault)
}

/// # Errors
///
/// [`Status::Fault`] if any byte is inaccessible.
pub(crate) fn copy_to_user(addr: u64, bytes: &[u8]) -> Result<(), Status> {
    if bytes.is_empty() {
        return Ok(());
    }
    let addr = usize::try_from(addr).map_err(|_| Status::Fault)?;
    UserMutPtr::<u8>::from_usize(addr)
        .copy_from_slice(0, bytes)
        .ok_or(Status::Fault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Allocate(Range<usize>, Prot, Placement),
        Release(Range<usize>),
        Protect(Range<usize>, Prot),
        Populate(usize),
    }

    #[derive(Default)]
    struct Mock {
        calls: RefCell<Vec<Call>>,
        allocate_fails: Cell<Option<Status>>,
    }

    impl Frames for Mock {
        fn allocate(
            &self,
            range: Range<usize>,
            prot: Prot,
            placement: Placement,
            _: Populate,
        ) -> Result<(), Status> {
            self.calls
                .borrow_mut()
                .push(Call::Allocate(range, prot, placement));
            self.allocate_fails.get().map_or(Ok(()), Err)
        }

        unsafe fn release(&self, range: Range<usize>) -> Result<(), Status> {
            self.calls.borrow_mut().push(Call::Release(range));
            Ok(())
        }

        unsafe fn protect(&self, range: Range<usize>, prot: Prot) -> Result<(), Status> {
            self.calls.borrow_mut().push(Call::Protect(range, prot));
            Ok(())
        }

        unsafe fn populate(&self, addr: usize, _: VmFlags, _: u64) -> bool {
            self.calls.borrow_mut().push(Call::Populate(addr));
            true
        }
    }

    const P: usize = PAGE_SIZE;
    /// x86 page-fault error code bits.
    const WRITE: u64 = 1 << 1;
    const FETCH: u64 = 1 << 4;

    fn mappings() -> (Mappings<Mock>, &'static Mock) {
        let mock: &'static Mock = Box::leak(Box::default());
        (Mappings::new(mock), mock)
    }

    fn map(
        m: &Mappings<Mock>,
        range: Range<usize>,
        prot: Prot,
        placement: Placement,
    ) -> Result<(), Status> {
        m.map(range, prot, placement, Populate::Lazy)
    }

    #[test]
    fn no_replace_overlap_never_reaches_the_platform() {
        let (m, mock) = mappings();
        map(&m, P..3 * P, Prot::ReadWrite, Placement::NoReplace).unwrap();
        mock.calls.borrow_mut().clear();
        assert_eq!(
            map(&m, 2 * P..4 * P, Prot::Read, Placement::NoReplace),
            Err(Status::Exists)
        );
        assert!(mock.calls.borrow().is_empty());
        map(&m, 2 * P..4 * P, Prot::Read, Placement::Replace).unwrap();
        assert_eq!(m.regions.borrow().get(&(2 * P)), Some(&Prot::Read));
        assert_eq!(m.regions.borrow().get(&P), Some(&Prot::ReadWrite));
    }

    #[test]
    fn failed_replace_leaves_the_range_unmapped() {
        let (m, mock) = mappings();
        map(&m, P..3 * P, Prot::ReadWrite, Placement::NoReplace).unwrap();
        mock.allocate_fails.set(Some(Status::NoMemory));
        assert_eq!(
            map(&m, P..2 * P, Prot::Read, Placement::Replace),
            Err(Status::NoMemory)
        );
        assert!(mock.calls.borrow().contains(&Call::Release(P..2 * P)));
        assert_eq!(m.regions.borrow().get(&P), None);
        assert_eq!(m.regions.borrow().get(&(2 * P)), Some(&Prot::ReadWrite));
    }

    #[test]
    fn failed_no_replace_records_nothing() {
        let (m, mock) = mappings();
        mock.allocate_fails.set(Some(Status::NoMemory));
        assert_eq!(
            map(&m, P..2 * P, Prot::Read, Placement::NoReplace),
            Err(Status::NoMemory)
        );
        assert_eq!(m.regions.borrow().get(&P), None);
    }

    #[test]
    fn protect_and_unmap_keep_holes() {
        let (m, _) = mappings();
        map(&m, P..2 * P, Prot::Read, Placement::NoReplace).unwrap();
        map(&m, 3 * P..4 * P, Prot::Read, Placement::NoReplace).unwrap();
        m.protect(0..5 * P, Prot::ReadWrite).unwrap();
        let regions = m.regions.borrow();
        assert_eq!(regions.get(&P), Some(&Prot::ReadWrite));
        assert_eq!(regions.get(&(2 * P)), None, "the hole stays unmapped");
        assert_eq!(regions.get(&0), None);
        drop(regions);
        m.unmap(0..4 * P).unwrap();
        assert!(m.regions.borrow().is_empty());
    }

    #[test]
    fn demand_paging_follows_the_record() {
        let (m, mock) = mappings();
        map(&m, P..2 * P, Prot::Read, Placement::NoReplace).unwrap();
        map(&m, 2 * P..3 * P, Prot::None, Placement::NoReplace).unwrap();
        mock.calls.borrow_mut().clear();
        assert!(!m.demand_page(5 * P, 0), "not recorded");
        assert!(!m.demand_page(P, WRITE), "write to read-only");
        assert!(!m.demand_page(P, FETCH), "fetch from no-exec");
        assert!(!m.demand_page(2 * P, 0), "no access");
        assert!(mock.calls.borrow().is_empty());
        assert!(m.demand_page(P + 8, 0));
        assert_eq!(*mock.calls.borrow(), [Call::Populate(P + 8)]);
    }
}
