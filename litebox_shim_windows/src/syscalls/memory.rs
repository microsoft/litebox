// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT virtual memory syscall handlers.
//!
//! Implements NtAllocateVirtualMemory, NtFreeVirtualMemory,
//! NtProtectVirtualMemory, and NtQueryVirtualMemory on top of
//! the LiteBox PageManager.

use litebox::mm::PageManager;
use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawPointerProvider;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_common_windows::nt_types::{mem_alloc_type, mem_protect, mem_state};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

use super::NtSyscallArgs;

const PAGE_SIZE: usize = 4096;

/// Helper to create a platform raw mutable pointer from a usize address.
fn raw_mut_ptr(addr: usize) -> <Platform as RawPointerProvider>::RawMutPointer<u8> {
    <Platform as RawPointerProvider>::RawMutPointer::from_usize(addr)
}

/// NtAllocateVirtualMemory — allocate or commit pages in the guest address space.
///
/// NT signature:
/// ```text
/// NTSTATUS NtAllocateVirtualMemory(
///     HANDLE ProcessHandle,     // r10
///     PVOID *BaseAddress,       // rdx (in/out)
///     ULONG_PTR ZeroBits,       // r8
///     PSIZE_T RegionSize,       // r9 (in/out)
///     ULONG AllocationType,     // [rsp+0x28]
///     ULONG Protect             // [rsp+0x30]
/// );
/// ```
pub(crate) fn nt_allocate_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    // Read in/out pointers from registers.
    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg3; // PSIZE_T RegionSize

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read the requested base address and size from guest memory.
    // Safety: these are guest-accessible pointers (userland shares address space).
    let requested_base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let requested_size = unsafe { core::ptr::read(region_size_ptr as *const usize) };

    // Read stack args: AllocationType at [rsp+0x28], Protect at [rsp+0x30]
    let alloc_type = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
    let protect = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };

    if requested_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Round size up to page boundary.
    let aligned_size = (requested_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let nz_size = match NonZeroPageSize::new(aligned_size) {
        Some(s) => s,
        None => return NtStatus::STATUS_INVALID_PARAMETER,
    };

    let flags = if requested_base != 0 {
        CreatePagesFlags::FIXED_ADDR
    } else {
        CreatePagesFlags::empty()
    };

    let suggested = if requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        NonZeroAddress::new(aligned_base)
    } else {
        None
    };

    // Dispatch based on protection requested.
    // The OS zero-fills pages on allocation (VirtualAlloc2 guarantee), so
    // we just return Ok(0) from the closure.
    let result = match nt_protect_to_page_op(protect) {
        PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
            pm.create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::ReadOnly => unsafe {
            pm.create_readable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::Execute | PageOp::ExecuteRead => unsafe {
            pm.create_executable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::NoAccess => unsafe {
            pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0))
        },
    };

    match result {
        Ok(ptr) => {
            let allocated_addr = ptr.as_usize();
            // Track the allocation size so MEM_RELEASE with size==0 can
            // free the entire region.
            ps.track_alloc(allocated_addr, aligned_size);
            // Write back the actual base address and size.
            unsafe {
                core::ptr::write(base_addr_ptr as *mut usize, allocated_addr);
                core::ptr::write(region_size_ptr as *mut usize, aligned_size);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => NtStatus::STATUS_NO_MEMORY,
    }
}

/// NtFreeVirtualMemory — decommit or release pages.
///
/// NT signature:
/// ```text
/// NTSTATUS NtFreeVirtualMemory(
///     HANDLE ProcessHandle,   // r10
///     PVOID *BaseAddress,     // rdx (in/out)
///     PSIZE_T RegionSize,     // r8 (in/out)
///     ULONG FreeType          // r9
/// );
/// ```
pub(crate) fn nt_free_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg2; // PSIZE_T RegionSize
    let free_type = args.arg3 as u32;

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let size = unsafe { core::ptr::read(region_size_ptr as *const usize) };

    if base == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    if free_type & mem_alloc_type::MEM_RELEASE != 0 {
        // MEM_RELEASE: free the entire region. Per NT spec, RegionSize
        // must be 0 and the kernel releases the full original allocation.
        let release_size = if size == 0 {
            // Look up the original allocation size.
            match ps.untrack_alloc(base) {
                Some(tracked) => tracked,
                None => {
                    // Unknown allocation — best-effort single page.
                    PAGE_SIZE
                }
            }
        } else {
            (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        };

        let ptr = raw_mut_ptr(base);
        let result = unsafe { pm.remove_pages(ptr, release_size) };
        match result {
            Ok(()) => NtStatus::STATUS_SUCCESS,
            Err(_) => NtStatus::STATUS_MEMORY_NOT_ALLOCATED,
        }
    } else if free_type & mem_alloc_type::MEM_DECOMMIT != 0 {
        // MEM_DECOMMIT: decommit pages but keep the reservation.
        // For now, treat same as release.
        let decommit_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if decommit_size == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let ptr = raw_mut_ptr(base);
        let result = unsafe { pm.remove_pages(ptr, decommit_size) };
        match result {
            Ok(()) => NtStatus::STATUS_SUCCESS,
            Err(_) => NtStatus::STATUS_MEMORY_NOT_ALLOCATED,
        }
    } else {
        NtStatus::STATUS_INVALID_PARAMETER
    }
}

/// NtProtectVirtualMemory — change page protection.
///
/// NT signature:
/// ```text
/// NTSTATUS NtProtectVirtualMemory(
///     HANDLE ProcessHandle,      // r10
///     PVOID *BaseAddress,        // rdx (in/out)
///     PSIZE_T RegionSize,        // r8 (in/out)
///     ULONG NewProtect,          // r9
///     PULONG OldProtect          // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_protect_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);

    let base_addr_ptr = args.arg1;
    let region_size_ptr = args.arg2;
    let new_protect = args.arg3 as u32;

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let size = unsafe { core::ptr::read(region_size_ptr as *const usize) };

    // Read OldProtect pointer from stack.
    let old_protect_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };

    let aligned_base = base & !(PAGE_SIZE - 1);
    let aligned_size = ((base + size) - aligned_base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    if aligned_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Write back the old protection (approximate — we report PAGE_READWRITE).
    if old_protect_ptr != 0 {
        unsafe {
            core::ptr::write(old_protect_ptr as *mut u32, mem_protect::PAGE_READWRITE);
        }
    }

    let ptr = raw_mut_ptr(aligned_base);
    let result = match nt_protect_to_page_op(new_protect) {
        PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
            pm.make_pages_writable(ptr, aligned_size)
        },
        PageOp::ReadOnly => unsafe { pm.make_pages_readable(ptr, aligned_size) },
        PageOp::Execute | PageOp::ExecuteRead => unsafe {
            pm.make_pages_executable(ptr, aligned_size)
        },
        PageOp::NoAccess => unsafe { pm.make_pages_inaccessible(ptr, aligned_size) },
    };

    match result {
        Ok(()) => {
            // Write back aligned values.
            unsafe {
                core::ptr::write(base_addr_ptr as *mut usize, aligned_base);
                core::ptr::write(region_size_ptr as *mut usize, aligned_size);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => NtStatus::STATUS_INVALID_PAGE_PROTECTION,
    }
}

/// NtQueryVirtualMemory — query information about a memory region.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryVirtualMemory(
///     HANDLE ProcessHandle,              // r10
///     PVOID BaseAddress,                 // rdx
///     MEMORY_INFORMATION_CLASS MemClass,  // r8
///     PVOID MemoryInformation,           // r9
///     SIZE_T MemoryInformationLength,    // [rsp+0x28]
///     PSIZE_T ReturnLength               // [rsp+0x30]
/// );
/// ```
pub(crate) fn nt_query_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    use litebox_common_windows::nt_types::MemoryBasicInformation;

    let args = NtSyscallArgs::from_ctx(ctx);
    let query_addr = args.arg1;
    let info_class = args.arg2 as u32;
    let info_ptr = args.arg3;

    let info_length = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let return_length_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };

    // Only MemoryBasicInformation (class 0) is supported.
    if info_class != 0 {
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    let mbi_size = core::mem::size_of::<MemoryBasicInformation>();
    if info_length < mbi_size || info_ptr == 0 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    // Query the page manager for permissions at the requested address.
    let aligned_addr = query_addr & !(PAGE_SIZE - 1);

    let (state, protect) = if let (Some(addr), Some(size)) = (
        NonZeroAddress::<PAGE_SIZE>::new(aligned_addr),
        NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE),
    ) {
        match pm.get_memory_permissions(addr, size) {
            Some(perms) => {
                let prot = region_perms_to_nt_protect(perms);
                (mem_state::MEM_COMMIT, prot)
            }
            None => (mem_state::MEM_FREE, 0u32),
        }
    } else {
        (mem_state::MEM_FREE, 0u32)
    };

    let mbi = MemoryBasicInformation {
        base_address: aligned_addr as u64,
        allocation_base: aligned_addr as u64,
        allocation_protect: protect,
        _pad0: 0,
        region_size: PAGE_SIZE as u64,
        state,
        protect,
        type_: if state == mem_state::MEM_COMMIT {
            0x0002_0000 // MEM_PRIVATE
        } else {
            0
        },
        _pad1: 0,
    };

    unsafe {
        core::ptr::write(info_ptr as *mut MemoryBasicInformation, mbi);
    }

    if return_length_ptr != 0 {
        unsafe {
            core::ptr::write(return_length_ptr as *mut usize, mbi_size);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// Internal page operation categories.
pub(crate) enum PageOp {
    NoAccess,
    ReadOnly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
}

/// Map NT PAGE_* protection to our internal operation category.
fn nt_protect_to_page_op(protect: u32) -> PageOp {
    // Strip modifier flags (PAGE_GUARD, PAGE_NOCACHE, etc.)
    let base = protect & 0xFF;
    match base {
        mem_protect::PAGE_NOACCESS => PageOp::NoAccess,
        mem_protect::PAGE_READONLY => PageOp::ReadOnly,
        mem_protect::PAGE_READWRITE => PageOp::ReadWrite,
        mem_protect::PAGE_WRITECOPY => PageOp::WriteCopy,
        mem_protect::PAGE_EXECUTE => PageOp::Execute,
        mem_protect::PAGE_EXECUTE_READ => PageOp::ExecuteRead,
        mem_protect::PAGE_EXECUTE_READWRITE => PageOp::ExecuteReadWrite,
        // Default to RW for unknown protection values.
        _ => PageOp::ReadWrite,
    }
}

/// Map litebox `MemoryRegionPermissions` to NT PAGE_* protection constants.
fn region_perms_to_nt_protect(perms: MemoryRegionPermissions) -> u32 {
    region_perms_to_nt_protect_pub(perms)
}

/// Public version of `nt_protect_to_page_op` for use by k32_handlers.
pub(crate) fn nt_protect_to_page_op_pub(protect: u32) -> PageOp {
    nt_protect_to_page_op(protect)
}

/// Public version of `region_perms_to_nt_protect` for use by k32_handlers.
pub(crate) fn region_perms_to_nt_protect_pub(perms: MemoryRegionPermissions) -> u32 {
    let r = perms.contains(MemoryRegionPermissions::READ);
    let w = perms.contains(MemoryRegionPermissions::WRITE);
    let x = perms.contains(MemoryRegionPermissions::EXEC);
    match (r, w, x) {
        (false, false, false) => mem_protect::PAGE_NOACCESS,
        (true, false, false) => mem_protect::PAGE_READONLY,
        (true, true, false) => mem_protect::PAGE_READWRITE,
        (true, false, true) => mem_protect::PAGE_EXECUTE_READ,
        (true, true, true) => mem_protect::PAGE_EXECUTE_READWRITE,
        (false, false, true) => mem_protect::PAGE_EXECUTE,
        _ => mem_protect::PAGE_READWRITE,
    }
}
