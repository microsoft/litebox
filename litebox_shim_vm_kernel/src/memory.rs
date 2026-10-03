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

/// Every method requires the owning process's address space to be current.
pub(crate) struct Mappings {
    platform: &'static VmKernel,
    regions: core::cell::RefCell<RangeMap<usize, Prot>>,
}

impl Mappings {
    pub(crate) fn new(platform: &'static VmKernel) -> Self {
        Self {
            platform,
            regions: core::cell::RefCell::new(RangeMap::new()),
        }
    }

    pub(crate) fn map(
        &self,
        range: Range<usize>,
        prot: Prot,
        placement: Placement,
        populate: Populate,
    ) -> Result<(), Status> {
        let behavior = match placement {
            Placement::NoReplace => {
                if self.regions.borrow().overlaps(&range) {
                    return Err(Status::Exists);
                }
                FixedAddressBehavior::NoReplace
            }
            Placement::Replace => FixedAddressBehavior::Replace,
        };
        PageManagementProvider::<PAGE_SIZE>::allocate_pages(
            self.platform,
            range.clone(),
            permissions(prot),
            false,
            populate == Populate::Now,
            behavior,
        )
        .map_err(|e| match e {
            litebox::platform::page_mgmt::AllocationError::OutOfMemory => Status::NoMemory,
            _ => Status::InvalidArgument,
        })?;
        self.regions.borrow_mut().insert(range, prot);
        Ok(())
    }

    pub(crate) fn unmap(&self, range: Range<usize>) -> Result<(), Status> {
        // Safety: the process gives up the range; the kernel holds no
        // references into user memory.
        unsafe { PageManagementProvider::<PAGE_SIZE>::release_pages(self.platform, range.clone()) }
            .map_err(|_| Status::InvalidArgument)?;
        self.regions.borrow_mut().remove(range);
        Ok(())
    }

    /// Unmapped parts of `range` stay unmapped.
    pub(crate) fn protect(&self, range: Range<usize>, prot: Prot) -> Result<(), Status> {
        // Safety: the kernel holds no references into user memory.
        unsafe {
            PageManagementProvider::<PAGE_SIZE>::update_permissions(
                self.platform,
                range.clone(),
                permissions(prot),
            )
        }
        .map_err(|_| Status::InvalidArgument)?;
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
        if <VmKernel as VmemPageFaultHandler>::access_error(error_code, flags) {
            return false;
        }
        // Safety: called for a page fault on a page the process mapped with
        // `flags`, and the access is allowed.
        unsafe { self.platform.handle_page_fault(addr, flags, error_code) }.is_ok()
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
