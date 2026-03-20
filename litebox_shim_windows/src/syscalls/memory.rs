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

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;

    if requested_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Round size up to page boundary.
    let aligned_size = (requested_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let has_commit = (alloc_type & MEM_COMMIT) != 0;
    let has_reserve = (alloc_type & MEM_RESERVE) != 0;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtAllocateVirtualMemory request: base=0x{requested_base:X} size=0x{aligned_size:X} type=0x{alloc_type:X} prot=0x{protect:X}\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    // MEM_COMMIT without MEM_RESERVE: upgrade existing pages (previously
    // reserved as inaccessible) to the requested protection.
    if has_commit && !has_reserve && requested_base != 0 {
        // Reject extremely large commits (>= 100 GB). ntdll's loader
        // creates a ~200 GB "mapping info index" via MEM_RESERVE then
        // MEM_COMMIT. The kernel is expected to fill entries during
        // NtMapViewOfSection(SEC_IMAGE); we don't implement that. Failing
        // the commit causes ntdll to release the reservation and fall back
        // to the traditional loader path that doesn't use this index.
        const MAPPING_INFO_THRESHOLD: usize = 100 * 1024 * 1024 * 1024; // 100 GB
        if aligned_size >= MAPPING_INFO_THRESHOLD {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: NtAllocateVirtualMemory MEM_COMMIT rejected (size 0x{aligned_size:X} >= threshold) → STATUS_INSUFFICIENT_RESOURCES\n",
                ));
            }
            return NtStatus(0xC000009A_u32 as i32); // STATUS_INSUFFICIENT_RESOURCES
        }

        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        let ptr = raw_mut_ptr(aligned_base);
        let result = match nt_protect_to_page_op(protect) {
            PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
                pm.make_pages_writable(ptr, aligned_size)
            },
            PageOp::ReadOnly => unsafe { pm.make_pages_readable(ptr, aligned_size) },
            PageOp::Execute | PageOp::ExecuteRead => unsafe {
                pm.make_pages_executable(ptr, aligned_size)
            },
            PageOp::NoAccess => Ok(()), // already inaccessible from reserve
        };
        // Ignore errors — pages may already have the right permissions.
        #[cfg(debug_assertions)]
        if result.is_err() {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemory MEM_COMMIT make_pages FAILED base=0x{aligned_base:X} size=0x{aligned_size:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        let _ = result;
        unsafe {
            core::ptr::write(base_addr_ptr as *mut usize, aligned_base);
            core::ptr::write(region_size_ptr as *mut usize, aligned_size);
        }
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemory → OK (MEM_COMMIT) base=0x{aligned_base:X} size=0x{aligned_size:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(nz_size) = NonZeroPageSize::new(aligned_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    // Reject extremely large reservations (>= 100 GB). ntdll's MI_MAP_INFO
    // index is ~200 GB and requires kernel-side entry population during
    // NtMapViewOfSection; we don't support that. Failing the reserve makes
    // the caller fall back to the traditional loader path.
    const MAPPING_INFO_RESERVE_THRESHOLD: usize = 100 * 1024 * 1024 * 1024;
    if aligned_size >= MAPPING_INFO_RESERVE_THRESHOLD {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtAllocateVirtualMemory rejected (size 0x{aligned_size:X} >= 100GB threshold)\n",
            ));
        }
        return NtStatus(0xC000009A_u32 as i32); // STATUS_INSUFFICIENT_RESOURCES
    }

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

    // MEM_RESERVE only: create inaccessible pages as a placeholder.
    // MEM_RESERVE|MEM_COMMIT: create pages with the requested protection.
    let result = if has_reserve && !has_commit {
        // Reserve only — inaccessible placeholder pages.
        unsafe { pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0)) }
    } else {
        // Reserve+commit (or commit-only fallback): allocate with requested protection.
        match nt_protect_to_page_op(protect) {
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
        }
    };

    match result {
        Ok(ptr) => {
            let allocated_addr = ptr.as_usize();
            ps.track_alloc(allocated_addr, aligned_size);
            unsafe {
                core::ptr::write(base_addr_ptr as *mut usize, allocated_addr);
                core::ptr::write(region_size_ptr as *mut usize, aligned_size);
            }
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemory → OK base=0x{allocated_addr:X} size=0x{aligned_size:X}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemory → STATUS_NO_MEMORY (req_base=0x{requested_base:X}, size=0x{aligned_size:X})\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NO_MEMORY
        }
    }
}

/// NtAllocateVirtualMemoryEx — extended allocation (segment heap uses this).
///
/// ```text
/// NTSTATUS NtAllocateVirtualMemoryEx(
///     HANDLE ProcessHandle,           // r10
///     PVOID *BaseAddress,             // rdx (in/out)
///     PSIZE_T RegionSize,             // r8 (in/out)
///     ULONG AllocationType,           // r9
///     ULONG PageProtection,           // [rsp+0x28]
///     MEM_EXTENDED_PARAMETER *Params, // [rsp+0x30]
///     ULONG ParamCount                // [rsp+0x38]
/// );
/// ```
pub(crate) fn nt_allocate_virtual_memory_ex(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    // Note: parameter layout differs from NtAllocateVirtualMemory!
    // arg2 (r8) = RegionSize* (not ZeroBits)
    // arg3 (r9) = AllocationType (not RegionSize*)
    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg2; // PSIZE_T RegionSize (r8, not r9!)
    let alloc_type = args.arg3 as u32; // ULONG AllocationType (r9)
    let protect = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let requested_base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let requested_size = unsafe { core::ptr::read(region_size_ptr as *const usize) };

    // Read extended parameters from stack.
    let ext_params_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let ext_params_count = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtAllocateVirtualMemoryEx(base=0x{requested_base:X}, size=0x{requested_size:X}, type=0x{alloc_type:X}, prot=0x{protect:X}, ext=0x{ext_params_ptr:X}, count={ext_params_count})\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        // Dump extended parameters if present.
        if ext_params_ptr != 0 && ext_params_count > 0 {
            // MEM_EXTENDED_PARAMETER is 16 bytes: { Type: ULONG64, union { ULong64, Pointer, Size, Handle, ULong }: 8 bytes }
            for i in 0..ext_params_count.min(8) {
                let param_addr = ext_params_ptr + (i as usize) * 16;
                let param_type = unsafe { core::ptr::read(param_addr as *const u64) };
                let param_value = unsafe { core::ptr::read((param_addr + 8) as *const u64) };
                let msg =
                    alloc::format!("  ext[{i}]: type=0x{param_type:X} value=0x{param_value:X}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
        }
    }

    if requested_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let aligned_size = (requested_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;

    let has_commit = (alloc_type & MEM_COMMIT) != 0;
    let has_reserve = (alloc_type & MEM_RESERVE) != 0;

    // MEM_COMMIT without MEM_RESERVE: upgrade existing inaccessible pages.
    if has_commit && !has_reserve && requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        let ptr = raw_mut_ptr(aligned_base);
        let result = match nt_protect_to_page_op(protect) {
            PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
                pm.make_pages_writable(ptr, aligned_size)
            },
            PageOp::ReadOnly => unsafe { pm.make_pages_readable(ptr, aligned_size) },
            PageOp::Execute | PageOp::ExecuteRead => unsafe {
                pm.make_pages_executable(ptr, aligned_size)
            },
            PageOp::NoAccess => Ok(()),
        };
        let _ = result;
        unsafe {
            core::ptr::write(base_addr_ptr as *mut usize, aligned_base);
            core::ptr::write(region_size_ptr as *mut usize, aligned_size);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(nz_size) = NonZeroPageSize::new(aligned_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
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

    let result = if has_reserve && !has_commit {
        // Reserve only — inaccessible placeholder pages.
        unsafe { pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0)) }
    } else {
        match nt_protect_to_page_op(protect) {
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
        }
    };

    match result {
        Ok(ptr) => {
            let allocated_addr = ptr.as_usize();
            ps.track_alloc(allocated_addr, aligned_size);
            unsafe {
                core::ptr::write(base_addr_ptr as *mut usize, allocated_addr);
                core::ptr::write(region_size_ptr as *mut usize, aligned_size);
            }
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemoryEx → OK base=0x{allocated_addr:X} size=0x{aligned_size:X}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemoryEx → STATUS_NO_MEMORY (base=0x{requested_base:X}, size=0x{aligned_size:X})\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NO_MEMORY
        }
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

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtFreeVirtualMemory base=0x{base:X} size=0x{size:X} type=0x{free_type:X}\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if base == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    if free_type & mem_alloc_type::MEM_RELEASE != 0 {
        // MEM_RELEASE: free pages from the address space.
        // size == 0: release the entire original allocation.
        // size != 0: partial release (NT kernel allows this to shrink a VAD).
        let release_size = if size == 0 {
            match ps.untrack_alloc(base) {
                Some(tracked) => tracked,
                None => PAGE_SIZE,
            }
        } else {
            (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        };

        let ptr = raw_mut_ptr(base);
        let result = unsafe { pm.remove_pages(ptr, release_size) };
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtFreeVirtualMemory MEM_RELEASE base=0x{:X} size=0x{:X} result={}\n",
                base,
                release_size,
                if result.is_ok() { "OK" } else { "FAILED" }
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
            // Dump nearby PM mappings after release to verify VMA splitting.
            let mappings = pm.mappings();
            for (range, flags) in &mappings {
                if range.start >= base.saturating_sub(0x200000)
                    && range.start <= base + release_size + 0x200000
                {
                    let perms = MemoryRegionPermissions::from(*flags);
                    let msg = alloc::format!(
                        "  VMA: 0x{:X}-0x{:X} (0x{:X}) perms={:?}\n",
                        range.start,
                        range.end,
                        range.end - range.start,
                        perms
                    );
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                }
            }
        }
        match result {
            Ok(()) => NtStatus::STATUS_SUCCESS,
            Err(_) => NtStatus::STATUS_MEMORY_NOT_ALLOCATED,
        }
    } else if free_type & mem_alloc_type::MEM_DECOMMIT != 0 {
        // MEM_DECOMMIT: revert pages to inaccessible (reserved) state.
        // The address range stays in the VA map but becomes inaccessible.
        let decommit_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if decommit_size == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let ptr = raw_mut_ptr(base);
        let result = unsafe { pm.make_pages_inaccessible(ptr, decommit_size) };
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtFreeVirtualMemory MEM_DECOMMIT base=0x{:X} size=0x{:X} result={}\n",
                base,
                decommit_size,
                if result.is_ok() { "OK" } else { "FAILED" }
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
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

    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtProtectVirtualMemory: base=0x{base:X} size=0x{size:X} new_protect=0x{new_protect:X} aligned=0x{aligned_base:X}+0x{aligned_size:X}\n"
            ),
        );
    }

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
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "  NtProtectVirtualMemory: FAILED base=0x{aligned_base:X} size=0x{aligned_size:X} prot=0x{new_protect:X}\n"
                ));
            }
            NtStatus::STATUS_INVALID_PAGE_PROTECTION
        }
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
    ps: &super::super::NtProcessState,
    module_bases: &[super::super::ModuleBase],
) -> NtStatus {
    use litebox_common_windows::nt_types::MemoryBasicInformation;

    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);
    let query_addr = args.arg1;
    let info_class = args.arg2 as u32;
    let info_ptr = args.arg3;

    let info_length = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let return_length_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };

    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtQueryVirtualMemory: addr=0x{query_addr:X} class={info_class} buf=0x{info_ptr:X} len={info_length}\n",
            ),
        );
    }

    // Class 6: MemoryImageInformation — return PE image base/size for an address.
    if info_class == 6 {
        // MEMORY_IMAGE_INFORMATION: { ImageBase: PVOID, SizeOfImage: SIZE_T, ImageFlags: ULONG }
        if info_ptr == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        // Find the module containing this address — check both runner-loaded
        // modules and dynamically mapped images (via NtMapViewOfSection).
        let module = module_bases
            .iter()
            .find(|m| query_addr >= m.base_address && query_addr < m.base_address + m.image_size);
        if let Some(m) = module {
            unsafe {
                core::ptr::write(info_ptr as *mut u64, m.base_address as u64);
                core::ptr::write((info_ptr + 8) as *mut u64, m.image_size as u64);
                core::ptr::write((info_ptr + 16) as *mut u32, 0); // ImageFlags = 0
            }
            if return_length_ptr != 0 {
                unsafe { core::ptr::write(return_length_ptr as *mut usize, 24) };
            }
            return NtStatus::STATUS_SUCCESS;
        }
        // Check dynamically loaded images (SEC_IMAGE via NtMapViewOfSection).
        {
            let img_mappings = ps.image_mappings.lock().unwrap();
            if let Some((&base, &size)) = img_mappings
                .range(..=query_addr)
                .next_back()
                .filter(|&(&b, &s)| query_addr < b + s)
            {
                unsafe {
                    core::ptr::write(info_ptr as *mut u64, base as u64);
                    core::ptr::write((info_ptr + 8) as *mut u64, size as u64);
                    core::ptr::write((info_ptr + 16) as *mut u32, 0);
                }
                if return_length_ptr != 0 {
                    unsafe { core::ptr::write(return_length_ptr as *mut usize, 24) };
                }
                return NtStatus::STATUS_SUCCESS;
            }
        }
        return NtStatus::STATUS_INVALID_ADDRESS;
    }

    // Class 4: MemoryWorkingSetExInformation — return zeroed data (no working set info in sandbox).
    if info_class == 4 {
        if info_ptr != 0 && info_length > 0 {
            unsafe {
                core::ptr::write_bytes(
                    info_ptr as *mut u8,
                    0,
                    core::cmp::min(info_length, 0x10000),
                );
            }
        }
        if return_length_ptr != 0 {
            unsafe { core::ptr::write(return_length_ptr as *mut usize, info_length) };
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Only MemoryBasicInformation (class 0) is supported beyond this point.
    // Class 14 = MemoryImageExtensionInformation — used by the loader for
    // image integrity checks. Return success with zeroed data to indicate
    // no extension info is available.
    if info_class == 14 {
        if info_ptr != 0 {
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, info_length.min(64));
            }
        }
        if return_length_ptr != 0 {
            unsafe { core::ptr::write(return_length_ptr as *mut usize, info_length) };
        }
        return NtStatus::STATUS_SUCCESS;
    }
    if info_class != 0 {
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    let mbi_size = core::mem::size_of::<MemoryBasicInformation>();
    if info_length < mbi_size || info_ptr == 0 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    // Query PageManager for the memory region containing this address.
    let aligned_addr = query_addr & !(PAGE_SIZE - 1);

    // Walk the PM's VMA list to find the region and its permissions.
    let mappings = pm.mappings();
    let mut state = mem_state::MEM_FREE;
    let mut protect = 0u32;
    let mut alloc_base = aligned_addr;
    let mut region_size = PAGE_SIZE;

    // Find the VMA containing aligned_addr.
    let mut found = false;
    for (range, flags) in &mappings {
        if aligned_addr >= range.start && aligned_addr < range.end {
            state = mem_state::MEM_COMMIT;
            let perms = MemoryRegionPermissions::from(*flags);
            protect = region_perms_to_nt_protect(perms);
            alloc_base = range.start;
            region_size = range.end - aligned_addr;
            found = true;
            break;
        }
    }

    // If not found in PM, also check module_bases for raw-mapped DLLs.
    if !found {
        for m in module_bases {
            if aligned_addr >= m.base_address && aligned_addr < m.base_address + m.image_size {
                state = mem_state::MEM_COMMIT;
                protect = mem_protect::PAGE_READONLY;
                alloc_base = m.base_address;
                region_size = m.base_address + m.image_size - aligned_addr;
                found = true;
                break;
            }
        }
    }

    // If still not found, report as free memory.  Compute region_size as the
    // gap to the next mapped region (or a default 64 KiB).
    if !found {
        state = mem_state::MEM_FREE;
        protect = 0;
        alloc_base = aligned_addr;
        region_size = 0x10000; // default gap size
        for (range, _) in &mappings {
            if range.start > aligned_addr {
                region_size = range.start - aligned_addr;
                break;
            }
        }
    }

    // Determine the memory type. Image-mapped DLLs report MEM_IMAGE;
    // regular allocations report MEM_PRIVATE. For image regions, also
    // correct the allocation base to the image base.
    let mem_type = if state == mem_state::MEM_COMMIT {
        // Check SEC_IMAGE mappings (dynamically loaded via NtMapViewOfSection).
        let img_mappings = ps.image_mappings.lock().unwrap();
        let dyn_img = img_mappings
            .range(..=aligned_addr)
            .next_back()
            .filter(|&(&base, &size)| aligned_addr < base + size);

        // Check runner-loaded modules (ntdll, EXE).
        let runner_img = module_bases.iter().find(|m| {
            aligned_addr >= m.base_address && aligned_addr < m.base_address + m.image_size
        });

        if let Some((&base, _)) = dyn_img {
            alloc_base = base;
            0x0100_0000 // MEM_IMAGE
        } else if let Some(m) = runner_img {
            alloc_base = m.base_address;
            0x0100_0000 // MEM_IMAGE
        } else {
            0x0002_0000 // MEM_PRIVATE
        }
    } else {
        0
    };

    {
        use litebox::platform::DebugLogProvider as _;
        let type_str = match mem_type {
            0x0100_0000 => "MEM_IMAGE",
            0x0002_0000 => "MEM_PRIVATE",
            _ => "MEM_FREE",
        };
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtQueryVirtualMemory: addr=0x{aligned_addr:X} → state=0x{state:X} protect=0x{protect:X} alloc_base=0x{alloc_base:X} region_size=0x{region_size:X} type={type_str}\n",
            ),
        );
    }

    let mbi = MemoryBasicInformation {
        base_address: aligned_addr as u64,
        allocation_base: alloc_base as u64,
        allocation_protect: protect,
        _pad0: 0,
        region_size: region_size as u64,
        state,
        protect,
        type_: mem_type,
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
