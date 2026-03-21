// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel32 virtual memory, system info, TLS/FLS, and environment handlers.
//!
//! These are kernel32 pseudo-syscalls dispatched via the 0x1000+ syscall
//! number range. They forward to the appropriate NT handlers or provide
//! direct implementations.

use core::sync::atomic::Ordering::Relaxed;

use litebox::mm::PageManager;
use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawPointerProvider;
use litebox_common_windows::nt_types::{mem_alloc_type, mem_protect};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

use super::NtSyscallArgs;
use super::memory::{self};

const PAGE_SIZE: usize = 4096;

/// Write a Win32 error code into the guest TEB's LastErrorValue field.
///
/// `teb_va` is the guest virtual address of the TEB. The LastErrorValue is
/// at offset 0x68 in the 64-bit TEB.
pub(crate) fn set_guest_last_error(teb_va: usize, error_code: u32) {
    if teb_va != 0 {
        unsafe {
            core::ptr::write(
                (teb_va + crate::peb_teb::teb_offsets::LAST_ERROR) as *mut u32,
                error_code,
            );
        }
    }
}

/// Resolve a potentially relative path against the guest CWD.
///
/// If the path is already absolute (starts with a drive letter or UNC prefix),
/// returns it as-is. Otherwise, prepends the guest CWD.
/// Collapse `.` and `..` segments in a Windows path.
///
/// Preserves the drive prefix (e.g. `C:\`) and handles both `\` and `/`
/// as separators. Segments of `.` are removed; `..` pops the previous
/// component (but never past the root).
fn canonicalize_segments(path: &str) -> alloc::string::String {
    // Split off the drive/root prefix so we never pop past it.
    let (prefix, rest) = if let Some(inner) = path.strip_prefix("\\??\\") {
        // NT object-manager prefix — detect inner path form to protect
        // the real root (e.g. \??\C:\ or \??\UNC\server\share\).
        if inner.len() >= 3
            && inner.as_bytes()[1] == b':'
            && (inner.as_bytes()[2] == b'\\' || inner.as_bytes()[2] == b'/')
        {
            // \??\C:\... — root is \??\C:\.
            (&path[..7], &path[7..])
        } else if let Some(after_unc) = inner.strip_prefix("UNC\\") {
            // \??\UNC\server\share\... — keep through share component.
            // "server\share\..."
            if let Some(server_end) = after_unc.find('\\') {
                let share_start = 4 + 4 + server_end + 1; // offset in path
                if let Some(share_end) = path[share_start..].find('\\') {
                    let root_end = share_start + share_end + 1;
                    (&path[..root_end], &path[root_end..])
                } else {
                    return alloc::string::String::from(path);
                }
            } else {
                return alloc::string::String::from(path);
            }
        } else {
            // Unknown NT path form — treat \??\ as root.
            ("\\??\\", inner)
        }
    } else if path.len() >= 3
        && path.as_bytes()[1] == b':'
        && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/')
    {
        (&path[..3], &path[3..])
    } else if let Some(after_slashes) = path.strip_prefix("\\\\") {
        // UNC — keep "\\server\share\" as the fixed root (two components).
        if let Some(server_end) = after_slashes.find('\\') {
            let share_start = 2 + server_end + 1;
            if let Some(share_end) = path[share_start..].find('\\') {
                let root_end = share_start + share_end + 1;
                (&path[..root_end], &path[root_end..])
            } else {
                return alloc::string::String::from(path);
            }
        } else {
            return alloc::string::String::from(path);
        }
    } else {
        // No recognized root; just canonicalize segments.
        ("", path)
    };

    let mut components: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in rest.split(['\\', '/']) {
        match seg {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }

    let mut result = alloc::string::String::from(prefix);
    for (i, comp) in components.iter().enumerate() {
        if i > 0 {
            result.push('\\');
        }
        result.push_str(comp);
    }
    result
}

pub(crate) fn resolve_relative_path(path: &str, cwd: &str) -> alloc::string::String {
    let bytes = path.as_bytes();
    // Absolute: drive letter (C:\...) or UNC (\\...) or NT prefix (\??\...)
    if (bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || path.starts_with("\\\\")
        || path.starts_with("\\??\\")
    {
        return canonicalize_segments(path);
    }
    // Drive-relative (C:foo) — use CWD only if it's on the same drive,
    // otherwise treat as drive root + filename (Windows per-drive CWD
    // tracking is not implemented; fall back to drive root).
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let path_drive = bytes[0].to_ascii_uppercase();
        let cwd_bytes = cwd.as_bytes();
        if cwd_bytes.len() >= 2 && cwd_bytes[0].to_ascii_uppercase() == path_drive {
            // Same drive — resolve relative to CWD.
            return canonicalize_segments(&alloc::format!("{}{}", cwd, &path[2..]));
        }
        // Different drive — fall back to the drive root.
        return canonicalize_segments(&alloc::format!("{}:\\{}", path_drive as char, &path[2..]));
    }
    // Root-relative (\foo) — prepend the CWD's drive letter.
    if bytes.first() == Some(&b'\\') {
        let cwd_bytes = cwd.as_bytes();
        if cwd_bytes.len() >= 2 && cwd_bytes[1] == b':' {
            return canonicalize_segments(&alloc::format!("{}:{}", cwd_bytes[0] as char, path));
        }
    }
    // Relative — prepend CWD.
    canonicalize_segments(&alloc::format!("{cwd}{path}"))
}

// ========================================================================
// VirtualAlloc / VirtualFree / VirtualProtect / VirtualQuery
//
// These are kernel32 wrappers around the Nt* virtual memory syscalls.
// The argument layout differs slightly from the NT versions.
// ========================================================================

/// VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -> LPVOID
///
/// Args: rcx(→r10)=lpAddress, rdx=dwSize, r8=flAllocationType, r9=flProtect
pub(crate) fn k32_virtual_alloc(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_address = args.arg0;
    let dw_size = args.arg1;
    let _fl_alloc_type = args.arg2 as u32;
    let fl_protect = args.arg3 as u32;

    if dw_size == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let aligned_size = (dw_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let Some(nz_size) = NonZeroPageSize::new(aligned_size) else {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    let suggested = if lp_address != 0 {
        NonZeroAddress::new(lp_address & !(PAGE_SIZE - 1))
    } else {
        None
    };

    let flags = if lp_address != 0 {
        litebox::mm::linux::CreatePagesFlags::FIXED_ADDR
    } else {
        litebox::mm::linux::CreatePagesFlags::empty()
    };

    let result = match memory::nt_protect_to_page_op_pub(fl_protect) {
        memory::PageOp::ReadWrite
        | memory::PageOp::WriteCopy
        | memory::PageOp::ExecuteReadWrite => unsafe {
            pm.create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        memory::PageOp::ReadOnly => unsafe {
            pm.create_readable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        memory::PageOp::Execute | memory::PageOp::ExecuteRead => unsafe {
            pm.create_executable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        memory::PageOp::NoAccess => unsafe {
            pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0))
        },
    };

    match result {
        Ok(ptr) => {
            let addr = ptr.as_usize();
            ps.track_alloc(addr, aligned_size);
            ctx.regs.rax = addr;
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            ctx.regs.rax = 0;
            NtStatus::STATUS_NO_MEMORY
        }
    }
}

/// VirtualFree(lpAddress, dwSize, dwFreeType) -> BOOL
///
/// Args: rcx(→r10)=lpAddress, rdx=dwSize, r8=dwFreeType
pub(crate) fn k32_virtual_free(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_address = args.arg0;
    let dw_size = args.arg1;
    let dw_free_type = args.arg2 as u32;

    if lp_address == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let free_size = if dw_free_type & mem_alloc_type::MEM_RELEASE != 0 {
        if dw_size == 0 {
            // Look up the original allocation size.
            ps.untrack_alloc(lp_address).unwrap_or(PAGE_SIZE)
        } else {
            (dw_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        }
    } else {
        (dw_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    };

    if free_size == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(lp_address);
    match unsafe { pm.remove_pages(ptr, free_size) } {
        Ok(()) => {
            ctx.regs.rax = 1; // TRUE
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            ctx.regs.rax = 0; // FALSE
            NtStatus::STATUS_INVALID_PARAMETER
        }
    }
}

/// VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) -> BOOL
///
/// Args: rcx(→r10)=lpAddress, rdx=dwSize, r8=flNewProtect, r9=lpflOldProtect
pub(crate) fn k32_virtual_protect(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_address = args.arg0;
    let dw_size = args.arg1;
    let fl_new_protect = args.arg2 as u32;
    let lp_old_protect = args.arg3;

    let aligned_base = lp_address & !(PAGE_SIZE - 1);
    let aligned_size = ((lp_address + dw_size) - aligned_base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    if aligned_size == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Write old protection (approximate).
    if lp_old_protect != 0 {
        unsafe {
            core::ptr::write(lp_old_protect as *mut u32, mem_protect::PAGE_READWRITE);
        }
    }

    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(aligned_base);
    let result = match memory::nt_protect_to_page_op_pub(fl_new_protect) {
        memory::PageOp::ReadWrite
        | memory::PageOp::WriteCopy
        | memory::PageOp::ExecuteReadWrite => unsafe { pm.make_pages_writable(ptr, aligned_size) },
        memory::PageOp::ReadOnly => unsafe { pm.make_pages_readable(ptr, aligned_size) },
        memory::PageOp::Execute | memory::PageOp::ExecuteRead => unsafe {
            pm.make_pages_executable(ptr, aligned_size)
        },
        memory::PageOp::NoAccess => unsafe { pm.make_pages_inaccessible(ptr, aligned_size) },
    };

    match result {
        Ok(()) => {
            ctx.regs.rax = 1; // TRUE
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            ctx.regs.rax = 0; // FALSE
            NtStatus::STATUS_INVALID_PAGE_PROTECTION
        }
    }
}

/// VirtualQuery(lpAddress, lpBuffer, dwLength) -> SIZE_T
///
/// Args: rcx(→r10)=lpAddress, rdx=lpBuffer, r8=dwLength
pub(crate) fn k32_virtual_query(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    use litebox_common_windows::nt_types::{MemoryBasicInformation, mem_state};

    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_address = args.arg0;
    let lp_buffer = args.arg1;
    let dw_length = args.arg2;

    let mbi_size = core::mem::size_of::<MemoryBasicInformation>();
    if dw_length < mbi_size || lp_buffer == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    let aligned_addr = lp_address & !(PAGE_SIZE - 1);
    let (state, protect) = if let (Some(addr), Some(size)) = (
        NonZeroAddress::<PAGE_SIZE>::new(aligned_addr),
        NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE),
    ) {
        match pm.get_memory_permissions(addr, size) {
            Some(perms) => {
                let prot = memory::region_perms_to_nt_protect_pub(perms);
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
            0x0002_0000
        } else {
            0
        },
        _pad1: 0,
    };

    unsafe {
        core::ptr::write(lp_buffer as *mut MemoryBasicInformation, mbi);
    }

    ctx.regs.rax = mbi_size;
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// System info
// ========================================================================

/// GetSystemInfo(lpSystemInfo) -> void
///
/// SYSTEM_INFO is 48 bytes on x64.
/// Args: rcx(→r10)=lpSystemInfo
pub(crate) fn k32_get_system_info(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let info_ptr = args.arg0;

    if info_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    // Zero and fill SYSTEM_INFO.
    unsafe {
        core::ptr::write_bytes(info_ptr as *mut u8, 0, 48);
        let base = info_ptr as *mut u8;
        // wProcessorArchitecture at offset 0 (WORD) — AMD64 = 9
        core::ptr::write(base.cast::<u16>(), 9);
        // dwPageSize at offset 4 (DWORD)
        core::ptr::write(base.add(4).cast::<u32>(), 4096);
        // lpMinimumApplicationAddress at offset 8 (LPVOID)
        core::ptr::write(base.add(8).cast::<u64>(), 0x10000);
        // lpMaximumApplicationAddress at offset 16 (LPVOID)
        core::ptr::write(base.add(16).cast::<u64>(), 0x7FFFFFFEFFFF);
        // dwActiveProcessorMask at offset 24 (DWORD_PTR)
        core::ptr::write(base.add(24).cast::<u64>(), 1);
        // dwNumberOfProcessors at offset 32 (DWORD)
        core::ptr::write(base.add(32).cast::<u32>(), 1);
        // dwProcessorType at offset 36 (DWORD) — 8664 = AMD64
        core::ptr::write(base.add(36).cast::<u32>(), 8664);
        // dwAllocationGranularity at offset 40 (DWORD)
        core::ptr::write(base.add(40).cast::<u32>(), 65536);
        // wProcessorLevel at offset 44 (WORD)
        core::ptr::write(base.add(44).cast::<u16>(), 6);
        // wProcessorRevision at offset 46 (WORD)
        core::ptr::write(base.add(46).cast::<u16>(), 0x4E03);
    }

    NtStatus::STATUS_SUCCESS
}

/// IsProcessorFeaturePresent(ProcessorFeature) -> BOOL
///
/// Args: rcx(→r10)=ProcessorFeature
pub(crate) fn k32_is_processor_feature(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let feature = args.arg0 as u32;

    // PF_XMMI_INSTRUCTIONS_AVAILABLE (6) = SSE
    // PF_XMMI64_INSTRUCTIONS_AVAILABLE (10) = SSE2
    // PF_SSE3_INSTRUCTIONS_AVAILABLE (13) = SSE3
    // PF_COMPARE_EXCHANGE128 (14)
    // PF_FASTFAIL_AVAILABLE (23)
    let supported = matches!(feature, 6 | 10 | 13 | 14 | 23);
    ctx.regs.rax = supported as usize;
    NtStatus::STATUS_SUCCESS
}

/// GetSystemTimeAsFileTime(lpSystemTimeAsFileTime) -> void
///
/// Args: rcx(→r10)=lpSystemTimeAsFileTime
pub(crate) fn k32_get_system_time_as_ft(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let ft_ptr = args.arg0;

    if ft_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let now = super::sysinfo::windows_filetime_now_pub();
    unsafe {
        core::ptr::write(ft_ptr as *mut i64, now);
    }

    NtStatus::STATUS_SUCCESS
}

/// QueryPerformanceCounter(lpPerformanceCount) -> BOOL
///
/// Args: rcx(→r10)=lpPerformanceCount
pub(crate) fn k32_query_perf_counter(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let counter_ptr = args.arg0;

    if counter_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    let now = super::sysinfo::windows_filetime_now_pub();
    unsafe {
        core::ptr::write(counter_ptr as *mut i64, now);
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// QueryPerformanceFrequency(lpFrequency) -> BOOL
///
/// Args: rcx(→r10)=lpFrequency
pub(crate) fn k32_query_perf_frequency(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let freq_ptr = args.arg0;

    if freq_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    const QPC_FREQUENCY: i64 = 10_000_000; // 10 MHz
    unsafe {
        core::ptr::write(freq_ptr as *mut i64, QPC_FREQUENCY);
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// TLS (Thread Local Storage)
// ========================================================================

/// TlsAlloc() -> DWORD
///
/// Returns a free TLS slot index, either from the free list or by
/// incrementing the high-water mark. Indices 0-63 map to TEB.TlsSlots,
/// 64-1087 map to the TLS expansion array.
pub(crate) fn k32_tls_alloc(
    ctx: &mut super::super::ExecutionContext,
    tls_next: &mut u32,
    tls_free_list: &mut alloc::vec::Vec<u32>,
) -> NtStatus {
    // First check the free list.
    if let Some(slot) = tls_free_list.pop() {
        ctx.regs.rax = slot as usize;
        return NtStatus::STATUS_SUCCESS;
    }
    let slot = *tls_next;
    if slot >= 1088 {
        // TLS_OUT_OF_INDEXES
        ctx.regs.rax = 0xFFFFFFFF;
        return NtStatus::STATUS_SUCCESS;
    }
    *tls_next += 1;
    ctx.regs.rax = slot as usize;
    NtStatus::STATUS_SUCCESS
}

/// TlsFree(dwTlsIndex) -> BOOL
///
/// Returns the TLS slot to the free list for reuse and zeroes the stored value.
/// Rejects indices that were never allocated or are already freed.
pub(crate) fn k32_tls_free(
    ctx: &mut super::super::ExecutionContext,
    tls_next: u32,
    tls_free_list: &mut alloc::vec::Vec<u32>,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;
    // Reject out-of-range or never-allocated indices.
    if index >= 1088 || index >= tls_next {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }
    // Reject double-free.
    if tls_free_list.contains(&index) {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }
    // Zero the stored value so a future alloc of this slot starts clean.
    if teb_va != 0 {
        if index < 64 {
            let slot_addr = teb_va + 0x1480 + (index as usize) * 8;
            // SAFETY: teb_va points to the guest TEB which we allocated.
            unsafe { core::ptr::write(slot_addr as *mut usize, 0) };
        } else {
            let exp_ptr =
                // SAFETY: TEB+0x1780 is the expansion pointer we manage.
                unsafe { core::ptr::read((teb_va + 0x1780) as *const usize) };
            if exp_ptr != 0 {
                let slot_addr = exp_ptr + ((index - 64) as usize) * 8;
                // SAFETY: expansion array is allocated by us.
                unsafe { core::ptr::write(slot_addr as *mut usize, 0) };
            }
        }
    }
    tls_free_list.push(index);
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// TlsGetValue(dwTlsIndex) -> LPVOID
///
/// Reads from TEB.TlsSlots[index] (offset 0x1480 + index * 8 for indices 0..63).
/// For index >= 64, reads from the TLS expansion array via TEB+0x1780.
/// Per Win32 contract: on success sets last error to ERROR_SUCCESS (0),
/// on failure returns NULL and sets last error to ERROR_INVALID_PARAMETER.
/// Args: rcx(→r10)=dwTlsIndex
pub(crate) fn k32_tls_get_value(
    ctx: &mut super::super::ExecutionContext,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;

    if teb_va == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    if index < 64 {
        let slot_addr = teb_va + 0x1480 + (index as usize) * 8;
        // SAFETY: teb_va points to the guest TEB which we allocated.
        let value = unsafe { core::ptr::read(slot_addr as *const usize) };
        ctx.regs.rax = value;
        set_guest_last_error(teb_va, 0); // ERROR_SUCCESS
    } else if index < 1088 {
        let exp_ptr =
            // SAFETY: TEB+0x1780 is the expansion pointer we manage.
            unsafe { core::ptr::read((teb_va + 0x1780) as *const usize) };
        if exp_ptr == 0 {
            ctx.regs.rax = 0;
        } else {
            let slot_addr = exp_ptr + ((index - 64) as usize) * 8;
            // SAFETY: expansion array is allocated by us.
            let value = unsafe { core::ptr::read(slot_addr as *const usize) };
            ctx.regs.rax = value;
        }
        set_guest_last_error(teb_va, 0); // ERROR_SUCCESS
    } else {
        ctx.regs.rax = 0;
        set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
    }

    NtStatus::STATUS_SUCCESS
}

/// TlsSetValue(dwTlsIndex, lpTlsValue) -> BOOL
///
/// Writes to TEB.TlsSlots[index] for 0..63, or to the TLS expansion array
/// for 64..1087. Allocates the expansion array on first use.
/// Args: rcx(→r10)=dwTlsIndex, rdx=lpTlsValue
pub(crate) fn k32_tls_set_value(
    ctx: &mut super::super::ExecutionContext,
    teb_va: usize,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;
    let value = args.arg1;

    if teb_va == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    if index < 64 {
        let slot_addr = teb_va + 0x1480 + (index as usize) * 8;
        unsafe {
            core::ptr::write(slot_addr as *mut usize, value);
        }
        ctx.regs.rax = 1; // TRUE
    } else if index < 1088 {
        // Get or allocate expansion slots.
        let exp_ptr_addr = teb_va + 0x1780;
        let mut exp_ptr = unsafe { core::ptr::read(exp_ptr_addr as *const usize) };
        if exp_ptr == 0 {
            // Allocate 1024 * 8 = 8192 bytes for expansion slots.
            use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
            let size = 1024 * 8;
            let aligned = (size + 4095) & !4095;
            if let Some(nz_size) = NonZeroPageSize::new(aligned) {
                let result = unsafe {
                    ps.pm
                        .create_writable_pages(None, nz_size, CreatePagesFlags::empty(), |_| Ok(0))
                };
                match result {
                    Ok(ptr) => {
                        exp_ptr = ptr.as_usize();
                        unsafe {
                            core::ptr::write_bytes(exp_ptr as *mut u8, 0, size);
                            core::ptr::write(exp_ptr_addr as *mut usize, exp_ptr);
                        }
                    }
                    Err(_) => {
                        ctx.regs.rax = 0; // FALSE — allocation failed
                        set_guest_last_error(teb_va, 8); // ERROR_NOT_ENOUGH_MEMORY
                        return NtStatus::STATUS_SUCCESS;
                    }
                }
            } else {
                ctx.regs.rax = 0;
                set_guest_last_error(teb_va, 8); // ERROR_NOT_ENOUGH_MEMORY
                return NtStatus::STATUS_SUCCESS;
            }
        }
        let slot_addr = exp_ptr + ((index - 64) as usize) * 8;
        unsafe {
            core::ptr::write(slot_addr as *mut usize, value);
        }
        ctx.regs.rax = 1; // TRUE
    } else {
        ctx.regs.rax = 0; // FALSE — out of range
        set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
    }

    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// FLS (Fiber Local Storage) — aliased to TLS for Phase 2
// ========================================================================

/// FlsAlloc(lpCallback) -> DWORD
///
/// Same as TlsAlloc for our purposes. FLS callbacks are ignored.
pub(crate) fn k32_fls_alloc(
    ctx: &mut super::super::ExecutionContext,
    fls_next: &mut u32,
    fls_free_list: &mut alloc::vec::Vec<u32>,
) -> NtStatus {
    // First check the free list.
    if let Some(slot) = fls_free_list.pop() {
        ctx.regs.rax = slot as usize;
        return NtStatus::STATUS_SUCCESS;
    }
    let slot = *fls_next;
    if slot >= 128 {
        ctx.regs.rax = 0xFFFFFFFF;
        return NtStatus::STATUS_SUCCESS;
    }
    *fls_next += 1;
    ctx.regs.rax = slot as usize;
    NtStatus::STATUS_SUCCESS
}

/// FlsGetValue(dwFlsIndex) -> LPVOID
///
/// Per Win32 contract: on success sets last error to ERROR_SUCCESS,
/// on failure returns NULL and sets ERROR_INVALID_PARAMETER.
pub(crate) fn k32_fls_get_value(
    ctx: &mut super::super::ExecutionContext,
    fls_slots: &[usize; 128],
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;

    if (index as usize) < fls_slots.len() {
        ctx.regs.rax = fls_slots[index as usize];
        if teb_va != 0 {
            set_guest_last_error(teb_va, 0); // ERROR_SUCCESS
        }
    } else {
        ctx.regs.rax = 0;
        if teb_va != 0 {
            set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// FlsSetValue(dwFlsIndex, lpFlsData) -> BOOL
///
/// On failure sets ERROR_INVALID_PARAMETER.
pub(crate) fn k32_fls_set_value(
    ctx: &mut super::super::ExecutionContext,
    fls_slots: &mut [usize; 128],
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;
    let value = args.arg1;

    if (index as usize) < fls_slots.len() {
        fls_slots[index as usize] = value;
        ctx.regs.rax = 1; // TRUE
    } else {
        ctx.regs.rax = 0; // FALSE
        if teb_va != 0 {
            set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// FlsFree(dwFlsIndex) -> BOOL
///
/// Returns the FLS slot to the free list for reuse.
/// Rejects indices that were never allocated or are already freed.
pub(crate) fn k32_fls_free(
    ctx: &mut super::super::ExecutionContext,
    fls_next: u32,
    fls_free_list: &mut alloc::vec::Vec<u32>,
    fls_slots: &mut [usize; 128],
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let index = args.arg0 as u32;
    // Reject out-of-range or never-allocated indices.
    if (index as usize) >= fls_slots.len() || index >= fls_next {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }
    // Reject double-free.
    if fls_free_list.contains(&index) {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }
    fls_slots[index as usize] = 0;
    fls_free_list.push(index);
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Exception handling
// ========================================================================

/// SetUnhandledExceptionFilter(lpTopLevelExceptionFilter) -> previous filter
///
/// Args: rcx(→r10)=lpTopLevelExceptionFilter
pub(crate) fn k32_set_unhandled_exception_filter(
    ctx: &mut super::super::ExecutionContext,
    prev_filter: &mut usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let new_filter = args.arg0;
    let old = *prev_filter;
    *prev_filter = new_filter;
    ctx.regs.rax = old;
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Environment
// ========================================================================

/// GetEnvironmentStringsW() -> LPWCH
///
/// Builds the environment block (double-NUL terminated UTF-16 string) from
/// the current env_vars map. Maintains a pool of allocated guest buffers with
/// in-use tracking; only reuses blocks that have been freed.
pub(crate) fn k32_get_environment_strings_w(
    ctx: &mut super::super::ExecutionContext,
    env_vars: &alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
    ps: &super::super::NtProcessState,
    pool: &spin::Mutex<alloc::vec::Vec<(usize, usize, bool)>>,
) -> NtStatus {
    use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
    use litebox::platform::RawConstPointer as _;

    // Build the double-NUL terminated UTF-16 environment block.
    let mut block = alloc::vec::Vec::<u16>::new();
    for (key, value) in env_vars {
        block.extend(key.encode_utf16());
        block.push(b'=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0); // double-NUL terminator

    let byte_len = block.len() * 2;
    let aligned_size = (byte_len + 4095) & !4095;

    // Search the pool for a free block large enough to reuse.
    let mut pool_ref = pool.lock();
    if let Some(idx) = pool_ref
        .iter()
        .position(|(_, sz, in_use)| !in_use && byte_len <= *sz)
    {
        let (va, sz, _) = pool_ref[idx];
        pool_ref[idx].2 = true; // mark in-use
        unsafe {
            core::ptr::write_bytes(va as *mut u8, 0, sz);
            core::ptr::copy_nonoverlapping(block.as_ptr() as *const u8, va as *mut u8, byte_len);
        }
        ctx.regs.rax = va;
        return NtStatus::STATUS_SUCCESS;
    }
    drop(pool_ref);

    // No existing block fits — allocate a new one.
    if let Some(nz_size) = NonZeroPageSize::new(aligned_size) {
        let result = unsafe {
            ps.pm
                .create_writable_pages(None, nz_size, CreatePagesFlags::empty(), |_| Ok(0))
        };
        match result {
            Ok(ptr) => {
                let va = ptr.as_usize();
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        block.as_ptr() as *const u8,
                        va as *mut u8,
                        byte_len,
                    );
                }
                pool.lock().push((va, aligned_size, true)); // in-use
                ctx.regs.rax = va;
            }
            Err(_) => {
                ctx.regs.rax = 0;
            }
        }
    } else {
        ctx.regs.rax = 0;
    }
    NtStatus::STATUS_SUCCESS
}

/// FreeEnvironmentStringsW(lpszEnvironmentBlock) -> BOOL
///
/// Marks the block as available for reuse in the pool.
/// Args: rcx(→r10)=lpszEnvironmentBlock
pub(crate) fn k32_free_environment_strings_w(
    ctx: &mut super::super::ExecutionContext,
    _ps: &super::super::NtProcessState,
    pool: &spin::Mutex<alloc::vec::Vec<(usize, usize, bool)>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let block_va = args.arg0;

    if block_va != 0 {
        let mut pool_ref = pool.lock();
        if let Some(entry) = pool_ref.iter_mut().find(|(va, _, _)| *va == block_va) {
            entry.2 = false; // mark as free
        }
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// GetEnvironmentVariableW(lpName, lpBuffer, nSize) -> DWORD
///
/// Args: rcx(→r10)=lpName, rdx=lpBuffer, r8=nSize
/// Returns the number of characters stored (excluding NUL), or 0 with
/// ERROR_ENVVAR_NOT_FOUND (203) if not found.
pub(crate) fn k32_get_environment_variable_w(
    ctx: &mut super::super::ExecutionContext,
    env_vars: &alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_name = args.arg0;
    let lp_buffer = args.arg1;
    let n_size = args.arg2;

    if lp_name == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Read the variable name (UTF-16LE NUL-terminated).
    let mut name_chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    loop {
        let ch = unsafe { core::ptr::read((lp_name + off) as *const u16) };
        if ch == 0 {
            break;
        }
        name_chars.push(ch);
        off += 2;
        if name_chars.len() > 32768 {
            break;
        }
    }
    let name = alloc::string::String::from_utf16_lossy(&name_chars);

    // Case-insensitive lookup (Windows env vars are case-insensitive).
    let name_upper = name.to_uppercase();
    let found = env_vars
        .iter()
        .find(|(k, _)| k.to_uppercase() == name_upper)
        .map(|(_, v)| v.clone());

    match found {
        Some(value) => {
            let wide: alloc::vec::Vec<u16> = value.encode_utf16().collect();
            let needed = wide.len() + 1; // include NUL terminator
            if n_size < needed {
                // Buffer too small — return required size (including NUL).
                ctx.regs.rax = needed;
            } else if lp_buffer != 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        wide.as_ptr(),
                        lp_buffer as *mut u16,
                        wide.len(),
                    );
                    core::ptr::write((lp_buffer + wide.len() * 2) as *mut u16, 0);
                }
                ctx.regs.rax = wide.len(); // chars written, excluding NUL
            } else {
                ctx.regs.rax = needed;
            }
            NtStatus::STATUS_SUCCESS
        }
        None => {
            ctx.regs.rax = 0;
            set_guest_last_error(teb_va, 203); // ERROR_ENVVAR_NOT_FOUND
            NtStatus::STATUS_SUCCESS
        }
    }
}

/// GetModuleFileNameW(hModule, lpFilename, nSize) -> DWORD
///
/// Args: rcx(→r10)=hModule, rdx=lpFilename, r8=nSize
///
/// For hModule==NULL or hModule==image_base, returns the main exe path.
/// For known DLL base addresses, returns the DLL name. For unknown
/// handles, sets ERROR_INVALID_HANDLE and returns 0.
pub(crate) fn k32_get_module_file_name_w(
    ctx: &mut super::super::ExecutionContext,
    exe_path: &str,
    module_bases: &[crate::ModuleBase],
    image_base: usize,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let h_module = args.arg0;
    let lp_filename = args.arg1;
    let n_size = args.arg2;

    if lp_filename == 0 || n_size == 0 {
        set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Resolve the path for the requested module.
    let path_str = if h_module == 0 || h_module == image_base {
        alloc::string::String::from(exe_path)
    } else {
        // Look up in loaded module bases.
        match module_bases.iter().find(|m| m.base_address == h_module) {
            Some(m) => m.path.clone(),
            None => {
                set_guest_last_error(teb_va, 126); // ERROR_MOD_NOT_FOUND
                ctx.regs.rax = 0;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    };

    // Encode as UTF-16 with NUL terminator.
    let wide: alloc::vec::Vec<u16> = path_str.encode_utf16().chain(core::iter::once(0)).collect();
    let chars_needed = wide.len() - 1; // excluding NUL

    if n_size >= wide.len() {
        // Buffer large enough — copy full path + NUL.
        unsafe {
            core::ptr::copy_nonoverlapping(wide.as_ptr(), lp_filename as *mut u16, wide.len());
        }
        ctx.regs.rax = chars_needed;
    } else {
        // Buffer too small — copy what fits, NUL-terminate, set error.
        unsafe {
            core::ptr::copy_nonoverlapping(wide.as_ptr(), lp_filename as *mut u16, n_size);
            if n_size > 0 {
                core::ptr::write((lp_filename + (n_size - 1) * 2) as *mut u16, 0);
            }
        }
        set_guest_last_error(teb_va, 122); // ERROR_INSUFFICIENT_BUFFER
        ctx.regs.rax = n_size;
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// String conversion (MultiByteToWideChar / WideCharToMultiByte)
// ========================================================================

/// Check if a byte is a valid UTF-8 continuation byte (10xxxxxx).
#[inline]
fn is_cont(b: u8) -> bool {
    b & 0xC0 == 0x80
}

/// MultiByteToWideChar(CodePage, dwFlags, lpMBStr, cbMultiByte,
///                     lpWideCharStr, cchWideChar) -> int
///
/// Supports CP_UTF8 (65001) and CP_ACP (0). For UTF-8, performs real
/// multi-byte decoding. For other codepages, falls back to Latin-1.
pub(crate) fn k32_multi_byte_to_wide_char(
    ctx: &mut super::super::ExecutionContext,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let code_page = args.arg0 as u32;
    let _flags = args.arg1 as u32;
    let mb_str = args.arg2;
    let cb_multi_byte = args.arg3 as i32;

    let wide_str = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let cch_wide_char = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const i32) };

    if mb_str == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Determine source byte length.
    let src_len = if cb_multi_byte == -1 {
        let mut len = 0usize;
        unsafe {
            while *((mb_str + len) as *const u8) != 0 {
                len += 1;
            }
        }
        len + 1 // include NUL
    } else {
        cb_multi_byte as usize
    };

    let src = unsafe { core::slice::from_raw_parts(mb_str as *const u8, src_len) };

    // Convert source bytes to UTF-16 code units.
    let wide: alloc::vec::Vec<u16> = if code_page == 65001 || code_page == 0 {
        // UTF-8 decode. Use core::str for valid UTF-8, fall back byte-by-byte.
        match core::str::from_utf8(src) {
            Ok(s) => s.encode_utf16().collect(),
            Err(_) => {
                // Best-effort: decode valid UTF-8 sequences, replace bad bytes.
                let mut out = alloc::vec::Vec::with_capacity(src_len);
                let mut i = 0;
                while i < src.len() {
                    let b = src[i];
                    if b < 0x80 {
                        out.push(b as u16);
                        i += 1;
                    } else if b < 0xC0 {
                        out.push(0xFFFD); // stray continuation byte
                        i += 1;
                    } else if b < 0xC2 {
                        // C0-C1: overlong 2-byte form — always invalid.
                        out.push(0xFFFD);
                        i += 1;
                    } else if b < 0xE0 && i + 1 < src.len() && is_cont(src[i + 1]) {
                        let cp = ((b as u32 & 0x1F) << 6) | (src[i + 1] as u32 & 0x3F);
                        out.push(cp as u16);
                        i += 2;
                    } else if b < 0xF0
                        && i + 2 < src.len()
                        && is_cont(src[i + 1])
                        && is_cont(src[i + 2])
                    {
                        let cp = ((b as u32 & 0x0F) << 12)
                            | ((src[i + 1] as u32 & 0x3F) << 6)
                            | (src[i + 2] as u32 & 0x3F);
                        if (0xD800..=0xDFFF).contains(&cp) || cp < 0x0800 {
                            // Surrogate range or overlong 3-byte encoding.
                            out.push(0xFFFD);
                            i += 1;
                        } else {
                            out.push(cp as u16);
                            i += 3;
                        }
                    } else if b <= 0xF4
                        && i + 3 < src.len()
                        && is_cont(src[i + 1])
                        && is_cont(src[i + 2])
                        && is_cont(src[i + 3])
                    {
                        let cp = ((b as u32 & 0x07) << 18)
                            | ((src[i + 1] as u32 & 0x3F) << 12)
                            | ((src[i + 2] as u32 & 0x3F) << 6)
                            | (src[i + 3] as u32 & 0x3F);
                        if (0x10000..=0x10FFFF).contains(&cp) {
                            // Valid supplementary code point — encode as surrogate pair.
                            let cp = cp - 0x10000;
                            out.push((0xD800 + (cp >> 10)) as u16);
                            out.push((0xDC00 + (cp & 0x3FF)) as u16);
                            i += 4;
                        } else {
                            // Out of Unicode range or overlong 4-byte encoding.
                            out.push(0xFFFD);
                            i += 1;
                        }
                    } else {
                        out.push(0xFFFD);
                        i += 1;
                    }
                }
                out
            }
        }
    } else {
        // Latin-1 fallback: each byte maps to same-valued UTF-16 code unit.
        src.iter().map(|&b| b as u16).collect()
    };

    if wide_str == 0 || cch_wide_char == 0 {
        // Query mode: return required buffer size in wide chars.
        ctx.regs.rax = wide.len();
        return NtStatus::STATUS_SUCCESS;
    }

    if wide.len() > cch_wide_char as usize {
        // Buffer too small — fail with ERROR_INSUFFICIENT_BUFFER.
        set_guest_last_error(teb_va, 122); // ERROR_INSUFFICIENT_BUFFER
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), wide_str as *mut u16, wide.len());
    }
    ctx.regs.rax = wide.len();
    NtStatus::STATUS_SUCCESS
}

/// WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar,
///                     lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefault) -> int
///
/// Supports CP_UTF8 (65001) and CP_ACP (0). For UTF-8, performs real
/// multi-byte encoding via Rust's char::encode_utf8. Other codepages
/// fall back to Latin-1 (bytes > 0xFF become '?').
pub(crate) fn k32_wide_char_to_multi_byte(
    ctx: &mut super::super::ExecutionContext,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let code_page = args.arg0 as u32;
    let _flags = args.arg1 as u32;
    let wide_str = args.arg2;
    let cch_wide_char = args.arg3 as i32;

    let mb_str = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let cb_multi_byte = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const i32) };

    if wide_str == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    let src_len = if cch_wide_char == -1 {
        let mut len = 0usize;
        unsafe {
            while *((wide_str + len * 2) as *const u16) != 0 {
                len += 1;
            }
        }
        len + 1
    } else {
        cch_wide_char as usize
    };

    let src = unsafe { core::slice::from_raw_parts(wide_str as *const u16, src_len) };

    // Convert UTF-16 to target encoding.
    let bytes: alloc::vec::Vec<u8> = if code_page == 65001 || code_page == 0 {
        // UTF-8 encode: decode UTF-16 (with surrogate pairs) into UTF-8.
        let mut out = alloc::vec::Vec::with_capacity(src_len * 3);
        let mut buf = [0u8; 4];
        let mut i = 0;
        while i < src.len() {
            let w = src[i];
            let cp = if (0xD800..=0xDBFF).contains(&w) && i + 1 < src.len() {
                let next = src[i + 1];
                if (0xDC00..=0xDFFF).contains(&next) {
                    // Valid surrogate pair → supplementary codepoint.
                    let hi = (w as u32 - 0xD800) << 10;
                    let lo = next as u32 - 0xDC00;
                    i += 2;
                    0x10000 + hi + lo
                } else {
                    // Lone high surrogate — emit replacement.
                    i += 1;
                    0xFFFD
                }
            } else if (0xD800..=0xDBFF).contains(&w) {
                // High surrogate at end of input — replacement.
                i += 1;
                0xFFFD
            } else {
                i += 1;
                w as u32
            };
            if let Some(ch) = char::from_u32(cp) {
                let encoded = ch.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            } else {
                // Invalid codepoint → replacement character U+FFFD.
                let encoded = '\u{FFFD}'.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
        out
    } else {
        // Latin-1 fallback.
        src.iter()
            .map(|&w| if w <= 0xFF { w as u8 } else { b'?' })
            .collect()
    };

    if mb_str == 0 || cb_multi_byte == 0 {
        // Query mode: return required buffer size.
        ctx.regs.rax = bytes.len();
        return NtStatus::STATUS_SUCCESS;
    }

    if bytes.len() > cb_multi_byte as usize {
        // Buffer too small — fail with ERROR_INSUFFICIENT_BUFFER.
        set_guest_last_error(teb_va, 122); // ERROR_INSUFFICIENT_BUFFER
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), mb_str as *mut u8, bytes.len());
    }
    ctx.regs.rax = bytes.len();
    NtStatus::STATUS_SUCCESS
}

/// GetCPInfo(CodePage, lpCPInfo) -> BOOL
///
/// CPINFO is 20 bytes: MaxCharSize(4), DefaultChar[2](2), LeadByte[12](12)
pub(crate) fn k32_get_cp_info(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let code_page = args.arg0 as u32;
    let info_ptr = args.arg1;

    if info_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // MaxCharSize: 4 for UTF-8 (65001) / ACP (0), 1 for single-byte codepages.
    let max_char_size: u32 = if code_page == 65001 || code_page == 0 {
        4
    } else {
        1
    };

    unsafe {
        core::ptr::write_bytes(info_ptr as *mut u8, 0, 20);
        let base = info_ptr as *mut u8;
        core::ptr::write(base.cast::<u32>(), max_char_size);
        // DefaultChar = '?'
        core::ptr::write(base.add(4), b'?');
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// GetStringTypeW — classify each UTF-16 character.
///
/// CT_CTYPE1 (1) classification bits:
///   C1_UPPER=0x0001, C1_LOWER=0x0002, C1_DIGIT=0x0004, C1_SPACE=0x0008,
///   C1_PUNCT=0x0010, C1_CNTRL=0x0020, C1_BLANK=0x0040, C1_XDIGIT=0x0080,
///   C1_ALPHA=0x0100, C1_DEFINED=0x0200
pub(crate) fn k32_get_string_type_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let info_type = args.arg0 as u32;
    let src_str = args.arg1;
    let cch_src = args.arg2 as i32;
    let char_type_ptr = args.arg3;

    if char_type_ptr == 0 || cch_src <= 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Only CT_CTYPE1 (1) is supported. Return FALSE for CT_CTYPE2/CT_CTYPE3.
    if info_type != 1 {
        ctx.regs.rax = 0; // FALSE — unsupported classification type
        return NtStatus::STATUS_SUCCESS;
    }

    for i in 0..(cch_src as usize) {
        let ch = unsafe { core::ptr::read((src_str + i * 2) as *const u16) };
        let ct = classify_utf16(ch);
        unsafe {
            core::ptr::write((char_type_ptr + i * 2) as *mut u16, ct);
        }
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// Classify a UTF-16 code unit into CT_CTYPE1 bits.
fn classify_utf16(ch: u16) -> u16 {
    const C1_UPPER: u16 = 0x0001;
    const C1_LOWER: u16 = 0x0002;
    const C1_DIGIT: u16 = 0x0004;
    const C1_SPACE: u16 = 0x0008;
    const C1_PUNCT: u16 = 0x0010;
    const C1_CNTRL: u16 = 0x0020;
    const C1_BLANK: u16 = 0x0040;
    const C1_XDIGIT: u16 = 0x0080;
    const C1_ALPHA: u16 = 0x0100;
    const C1_DEFINED: u16 = 0x0200;

    match ch {
        0x0009 => C1_SPACE | C1_BLANK | C1_CNTRL | C1_DEFINED, // TAB
        0x0000..=0x001F | 0x007F => C1_CNTRL | C1_DEFINED,
        0x0020 => C1_SPACE | C1_BLANK | C1_DEFINED, // space
        0x0030..=0x0039 => C1_DIGIT | C1_XDIGIT | C1_DEFINED, // '0'-'9'
        0x0041..=0x0046 => C1_UPPER | C1_ALPHA | C1_XDIGIT | C1_DEFINED, // 'A'-'F'
        0x0047..=0x005A => C1_UPPER | C1_ALPHA | C1_DEFINED, // 'G'-'Z'
        0x0061..=0x0066 => C1_LOWER | C1_ALPHA | C1_XDIGIT | C1_DEFINED, // 'a'-'f'
        0x0067..=0x007A => C1_LOWER | C1_ALPHA | C1_DEFINED, // 'g'-'z'
        // ASCII punctuation ranges
        0x0021..=0x002F | 0x003A..=0x0040 | 0x005B..=0x0060 | 0x007B..=0x007E => {
            C1_PUNCT | C1_DEFINED
        }
        // Latin-1 supplement: letters
        0x00C0..=0x00D6 | 0x00D8..=0x00DE => C1_UPPER | C1_ALPHA | C1_DEFINED,
        0x00DF..=0x00F6 | 0x00F8..=0x00FF => C1_LOWER | C1_ALPHA | C1_DEFINED,
        // Common Unicode letter ranges (simplified)
        0x0100..=0x024F => {
            // Latin Extended: even code points tend to be upper, odd lower
            let base = C1_ALPHA | C1_DEFINED;
            if ch & 1 == 0 {
                base | C1_UPPER
            } else {
                base | C1_LOWER
            }
        }
        // CJK, Arabic, Cyrillic, etc. — mark as alpha+defined
        0x0370..=0x052F => C1_ALPHA | C1_DEFINED,
        0x0600..=0x06FF | 0x0900..=0x097F => C1_ALPHA | C1_DEFINED,
        0x3000..=0x303F => C1_PUNCT | C1_DEFINED, // CJK punctuation
        0x3040..=0x30FF => C1_ALPHA | C1_DEFINED, // Hiragana/Katakana
        0x4E00..=0x9FFF => C1_ALPHA | C1_DEFINED, // CJK Unified Ideographs
        // Non-breaking space
        0x00A0 => C1_SPACE | C1_BLANK | C1_DEFINED,
        // Everything else above 0x7F that's printable
        0x0080..=0x009F => C1_CNTRL | C1_DEFINED,
        _ => C1_DEFINED,
    }
}

/// LCMapStringW — basic case mapping and sorting support.
///
/// Supports LCMAP_UPPERCASE (0x200) and LCMAP_LOWERCASE (0x100) flags.
/// For sort key generation (LCMAP_SORTKEY = 0x400), produces a simple
/// ordinal sort key.
pub(crate) fn k32_lc_map_string_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _locale = args.arg0;
    let map_flags = args.arg1 as u32;
    let src_str = args.arg2;
    let cch_src = args.arg3 as i32;
    let dest_str = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let cch_dest = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const i32) };

    const LCMAP_UPPERCASE: u32 = 0x0000_0200;
    const LCMAP_LOWERCASE: u32 = 0x0000_0100;
    const LCMAP_SORTKEY: u32 = 0x0000_0400;

    // Determine actual source length.
    let src_len = if cch_src < 0 {
        // NUL-terminated: count chars.
        let mut len = 0usize;
        loop {
            let ch = unsafe { core::ptr::read((src_str + len * 2) as *const u16) };
            if ch == 0 {
                break;
            }
            len += 1;
            if len > 32768 {
                break;
            }
        }
        len + 1 // include NUL
    } else {
        cch_src as usize
    };

    if map_flags & LCMAP_SORTKEY != 0 {
        // Produce a byte-level sort key: 2 bytes per char + NUL terminator.
        let key_len = src_len * 2 + 1;
        if cch_dest == 0 {
            ctx.regs.rax = key_len;
            return NtStatus::STATUS_SUCCESS;
        }
        if (cch_dest as usize) < key_len || dest_str == 0 {
            ctx.regs.rax = 0;
            return NtStatus::STATUS_SUCCESS;
        }
        for i in 0..src_len {
            let ch = unsafe { core::ptr::read((src_str + i * 2) as *const u16) };
            // Simple ordinal sort key: upper byte first, then lower byte.
            let upper = simple_toupper(ch);
            unsafe {
                core::ptr::write((dest_str + i * 2) as *mut u8, (upper >> 8) as u8);
                core::ptr::write((dest_str + i * 2 + 1) as *mut u8, upper as u8);
            }
        }
        unsafe {
            core::ptr::write((dest_str + src_len * 2) as *mut u8, 0);
        }
        ctx.regs.rax = key_len;
        return NtStatus::STATUS_SUCCESS;
    }

    // Case mapping.
    if cch_dest == 0 {
        // Query required buffer size.
        ctx.regs.rax = src_len;
        return NtStatus::STATUS_SUCCESS;
    }

    if (cch_dest as usize) < src_len || dest_str == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    for i in 0..src_len {
        let ch = unsafe { core::ptr::read((src_str + i * 2) as *const u16) };
        let mapped = if map_flags & LCMAP_UPPERCASE != 0 {
            simple_toupper(ch)
        } else if map_flags & LCMAP_LOWERCASE != 0 {
            simple_tolower(ch)
        } else {
            ch
        };
        unsafe {
            core::ptr::write((dest_str + i * 2) as *mut u16, mapped);
        }
    }
    ctx.regs.rax = src_len;
    NtStatus::STATUS_SUCCESS
}

/// Simple uppercase mapping for BMP characters.
fn simple_toupper(ch: u16) -> u16 {
    match ch {
        0x0061..=0x007A => ch - 0x20,                   // a-z → A-Z
        0x00E0..=0x00F6 | 0x00F8..=0x00FE => ch - 0x20, // Latin-1 lower → upper
        0x0430..=0x044F => ch - 0x20,                   // Cyrillic lower → upper
        _ => ch,
    }
}

/// Simple lowercase mapping for BMP characters.
fn simple_tolower(ch: u16) -> u16 {
    match ch {
        0x0041..=0x005A => ch + 0x20,                   // A-Z → a-z
        0x00C0..=0x00D6 | 0x00D8..=0x00DE => ch + 0x20, // Latin-1 upper → lower
        0x0410..=0x042F => ch + 0x20,                   // Cyrillic upper → lower
        _ => ch,
    }
}

/// CompareStringW — ordinal or case-insensitive string comparison.
///
/// Args: r10=Locale, rdx=dwCmpFlags, r8=lpString1, r9=cchCount1,
///       [rsp+0x28]=lpString2, [rsp+0x30]=cchCount2
/// Returns: CSTR_LESS_THAN(1), CSTR_EQUAL(2), CSTR_GREATER_THAN(3), or 0 on error.
pub(crate) fn k32_compare_string_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _locale = args.arg0;
    let cmp_flags = args.arg1 as u32;
    let str1_ptr = args.arg2;
    let cch1 = args.arg3 as i32;
    let str2_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let cch2 = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const i32) };

    const NORM_IGNORECASE: u32 = 0x0000_0001;
    let ignore_case = cmp_flags & NORM_IGNORECASE != 0;

    // Determine lengths (negative = NUL-terminated).
    let len1 = str_len_utf16(str1_ptr, cch1);
    let len2 = str_len_utf16(str2_ptr, cch2);
    let min_len = core::cmp::min(len1, len2);

    for i in 0..min_len {
        let mut c1 = unsafe { core::ptr::read((str1_ptr + i * 2) as *const u16) };
        let mut c2 = unsafe { core::ptr::read((str2_ptr + i * 2) as *const u16) };
        if ignore_case {
            c1 = simple_toupper(c1);
            c2 = simple_toupper(c2);
        }
        if c1 < c2 {
            ctx.regs.rax = 1; // CSTR_LESS_THAN
            return NtStatus::STATUS_SUCCESS;
        }
        if c1 > c2 {
            ctx.regs.rax = 3; // CSTR_GREATER_THAN
            return NtStatus::STATUS_SUCCESS;
        }
    }

    // Prefixes match — shorter string is less.
    ctx.regs.rax = match len1.cmp(&len2) {
        core::cmp::Ordering::Less => 1,    // CSTR_LESS_THAN
        core::cmp::Ordering::Equal => 2,   // CSTR_EQUAL
        core::cmp::Ordering::Greater => 3, // CSTR_GREATER_THAN
    };
    NtStatus::STATUS_SUCCESS
}

/// Determine the length of a UTF-16 string (excluding NUL).
fn str_len_utf16(ptr: usize, cch: i32) -> usize {
    if cch >= 0 {
        return cch as usize;
    }
    // NUL-terminated.
    let mut len = 0usize;
    loop {
        let ch = unsafe { core::ptr::read((ptr + len * 2) as *const u16) };
        if ch == 0 {
            break;
        }
        len += 1;
        if len > 32768 {
            break;
        }
    }
    len
}

// ========================================================================
// Kernel32 file I/O wrappers
// ========================================================================

/// CreateFileW — wraps NtCreateFile through the handle table.
///
/// Win32 signature:
/// ```text
/// HANDLE CreateFileW(
///     LPCWSTR lpFileName,            // rcx(→r10)
///     DWORD dwDesiredAccess,         // rdx
///     DWORD dwShareMode,             // r8
///     LPSECURITY_ATTRIBUTES lpSA,    // r9
///     DWORD dwCreationDisposition,   // [rsp+0x28]
///     DWORD dwFlagsAndAttributes,    // [rsp+0x30]
///     HANDLE hTemplateFile           // [rsp+0x38]
/// );
/// ```
pub(crate) fn k32_create_file_w(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
    cwd: &str,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let filename_ptr = args.arg0;
    let desired_access = args.arg1 as u32;
    let share_mode = args.arg2 as u32;

    let creation_disposition = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
    let flags_and_attributes = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };

    if filename_ptr == 0 {
        set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
        ctx.regs.rax = usize::MAX; // INVALID_HANDLE_VALUE
        return NtStatus::STATUS_SUCCESS;
    }

    // Read UTF-16LE filename from guest memory (supports extended-length paths).
    let mut path_chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    loop {
        let ch = unsafe { core::ptr::read((filename_ptr + off) as *const u16) };
        if ch == 0 {
            break;
        }
        path_chars.push(ch);
        off += 2;
        if path_chars.len() > 32768 {
            break;
        }
    }
    let path = alloc::string::String::from_utf16_lossy(&path_chars);
    let resolved = resolve_relative_path(&path, cwd);

    let want_read = desired_access & 0x8000_0001 != 0; // GENERIC_READ | FILE_READ_DATA
    let want_write = desired_access & 0x4000_0006 != 0; // GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA

    // Try VFS first.
    if let Some(super::file::TranslatedPath::Vfs(vfs_path)) =
        super::file::drive_path_to_vfs(&resolved)
        && let Some(fs) = shared.fs.get()
    {
        // Map Win32 creation disposition to VFS OFlags.
        // Win32 dispositions: CREATE_NEW=1, CREATE_ALWAYS=2,
        // OPEN_EXISTING=3, OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
        let mut oflags = litebox::fs::OFlags::empty();
        match creation_disposition {
            3 => {} // OPEN_EXISTING — no CREAT
            1 => oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::EXCL,
            4 => oflags |= litebox::fs::OFlags::CREAT,
            5 => oflags |= litebox::fs::OFlags::TRUNC,
            2 => oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::TRUNC,
            _ => {}
        }
        if want_write {
            if want_read {
                oflags |= litebox::fs::OFlags::RDWR;
            } else {
                oflags |= litebox::fs::OFlags::WRONLY;
            }
        } else {
            oflags |= litebox::fs::OFlags::RDONLY;
        }

        use litebox::fs::FileSystem as _;
        match fs.open(
            &*vfs_path,
            oflags,
            litebox::fs::Mode::RUSR | litebox::fs::Mode::WUSR,
        ) {
            Ok(typed_fd) => {
                let raw_fd = {
                    let mut rds = shared.raw_fds.lock();
                    rds.fd_into_raw_integer(typed_fd)
                };
                let nt_handle = handles.insert(crate::handle_table::NtObject::File {
                    path: resolved,
                    position: alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
                    raw_fd,
                    vfs_refcount: alloc::sync::Arc::new(core::sync::atomic::AtomicUsize::new(1)),
                });
                ctx.regs.rax = nt_handle as usize;
                return NtStatus::STATUS_SUCCESS;
            }
            Err(e) => {
                set_guest_last_error(teb_va, map_open_error_to_win32(&e));
                ctx.regs.rax = usize::MAX; // INVALID_HANDLE_VALUE
                return NtStatus::STATUS_SUCCESS;
            }
        }
    }

    // Path not VFS-translatable — no host fallback.
    set_guest_last_error(teb_va, 2); // ERROR_FILE_NOT_FOUND
    ctx.regs.rax = usize::MAX; // INVALID_HANDLE_VALUE
    NtStatus::STATUS_SUCCESS
}

/// ReadFile for ConsoleInput handles. Holds the pending mutex for the entire
/// operation to serialize with ReadConsoleW. Called after handle-table lock is
/// dropped.
pub(crate) fn k32_read_file_console(
    ctx: &mut super::super::ExecutionContext,
    teb_va: usize,
    console_pending: &spin::Mutex<alloc::vec::Vec<u8>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buffer = args.arg1;
    let bytes_to_read = args.arg2 as u32;
    let bytes_read_ptr = args.arg3;

    // Hold pending mutex for the entire operation to serialize with
    // ReadConsoleW on the same stdin stream.
    let mut pending = console_pending.lock();
    let mut filled = 0u32;

    // Drain any bytes stashed by ReadConsoleW first.
    if !pending.is_empty() {
        let drain = pending.len().min(bytes_to_read as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(pending.as_ptr(), buffer as *mut u8, drain);
        }
        pending.drain(..drain);
        filled = drain as u32;
    }

    if filled < bytes_to_read {
        let remaining = (bytes_to_read - filled) as usize;
        let buf = unsafe {
            core::slice::from_raw_parts_mut((buffer + filled as usize) as *mut u8, remaining)
        };
        use litebox::platform::StdioProvider as _;
        match litebox_platform_multiplex::platform().read_from_stdin(buf) {
            Ok(n) => filled += n as u32,
            Err(_) if filled == 0 => {
                set_guest_last_error(teb_va, 109); // ERROR_BROKEN_PIPE
                if bytes_read_ptr != 0 {
                    unsafe { core::ptr::write(bytes_read_ptr as *mut u32, 0) }
                }
                ctx.regs.rax = 0;
                return NtStatus::STATUS_SUCCESS;
            }
            Err(_) => {} // partial data already in buffer — return what we have
        }
    }

    if bytes_read_ptr != 0 {
        unsafe { core::ptr::write(bytes_read_ptr as *mut u32, filled) }
    }
    ctx.regs.rax = 1;
    NtStatus::STATUS_SUCCESS
}

/// WriteFile for console output handles. Non-blocking — prints to debug log.
pub(crate) fn k32_write_file_console(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buffer = args.arg1;
    let bytes_to_write = args.arg2 as u32;
    let bytes_written_ptr = args.arg3;

    if buffer != 0 && bytes_to_write > 0 {
        unsafe {
            let buf = core::slice::from_raw_parts(buffer as *const u8, bytes_to_write as usize);
            use litebox::platform::DebugLogProvider as _;
            if let Ok(s) = core::str::from_utf8(buf) {
                litebox_platform_multiplex::platform().debug_log_print(s);
            }
        }
    }
    if bytes_written_ptr != 0 {
        unsafe { core::ptr::write(bytes_written_ptr as *mut u32, bytes_to_write) }
    }
    ctx.regs.rax = 1;
    NtStatus::STATUS_SUCCESS
}

/// ReadFile for VFS-backed file handles. Called after handle-table lock is
/// dropped. Uses the same Win32 argument convention as `k32_read_file_host`.
pub(crate) fn k32_read_file_vfs(
    ctx: &mut super::super::ExecutionContext,
    raw_fd: usize,
    position: &alloc::sync::Arc<core::sync::atomic::AtomicU64>,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buffer = args.arg1;
    let bytes_to_read = args.arg2 as u32;
    let bytes_read_ptr = args.arg3;

    if buffer == 0 || bytes_to_read == 0 {
        if bytes_read_ptr != 0 {
            unsafe { core::ptr::write(bytes_read_ptr as *mut u32, 0) }
        }
        ctx.regs.rax = 1;
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(fs) = shared.fs.get() else {
        set_guest_last_error(teb_va, 6); // ERROR_INVALID_HANDLE
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    };

    let typed_fd = {
        let rds = shared.raw_fds.lock();
        match rds.fd_from_raw_integer::<crate::NtFS>(raw_fd) {
            Ok(fd) => fd,
            Err(_) => {
                set_guest_last_error(teb_va, 6);
                ctx.regs.rax = 0;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    };

    let start = position.fetch_add(bytes_to_read as u64, Relaxed);
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, bytes_to_read as usize) };

    use litebox::fs::FileSystem as _;
    match fs.read(&typed_fd, buf, Some(start as usize)) {
        Ok(read) => {
            let over = bytes_to_read as u64 - read as u64;
            if over > 0 {
                position.fetch_sub(over, Relaxed);
            }
            if bytes_read_ptr != 0 {
                unsafe { core::ptr::write(bytes_read_ptr as *mut u32, read as u32) }
            }
            ctx.regs.rax = 1;
        }
        Err(_) => {
            position.fetch_sub(bytes_to_read as u64, Relaxed);
            set_guest_last_error(teb_va, 5); // ERROR_ACCESS_DENIED
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// WriteFile for VFS-backed file handles. Called after handle-table lock is
/// dropped. Uses the same Win32 argument convention as `k32_write_file_host`.
pub(crate) fn k32_write_file_vfs(
    ctx: &mut super::super::ExecutionContext,
    raw_fd: usize,
    position: &alloc::sync::Arc<core::sync::atomic::AtomicU64>,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buffer = args.arg1;
    let bytes_to_write = args.arg2 as u32;
    let bytes_written_ptr = args.arg3;

    if buffer == 0 || bytes_to_write == 0 {
        if bytes_written_ptr != 0 {
            unsafe { core::ptr::write(bytes_written_ptr as *mut u32, 0) }
        }
        ctx.regs.rax = 1;
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(fs) = shared.fs.get() else {
        set_guest_last_error(teb_va, 6);
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    };

    let typed_fd = {
        let rds = shared.raw_fds.lock();
        match rds.fd_from_raw_integer::<crate::NtFS>(raw_fd) {
            Ok(fd) => fd,
            Err(_) => {
                set_guest_last_error(teb_va, 6);
                ctx.regs.rax = 0;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    };

    let start = position.fetch_add(bytes_to_write as u64, Relaxed);
    let buf = unsafe { core::slice::from_raw_parts(buffer as *const u8, bytes_to_write as usize) };

    use litebox::fs::FileSystem as _;
    match fs.write(&typed_fd, buf, Some(start as usize)) {
        Ok(written) => {
            let over = bytes_to_write as u64 - written as u64;
            if over > 0 {
                position.fetch_sub(over, Relaxed);
            }
            if bytes_written_ptr != 0 {
                unsafe { core::ptr::write(bytes_written_ptr as *mut u32, written as u32) }
            }
            ctx.regs.rax = 1;
        }
        Err(_) => {
            position.fetch_sub(bytes_to_write as u64, Relaxed);
            set_guest_last_error(teb_va, 5);
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// CloseHandle(hObject) -> BOOL
pub(crate) fn k32_close_handle(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    if let Some(obj) = handles.close(handle) {
        super::close_vfs_fd(&obj, shared);
        ctx.regs.rax = 1;
    } else {
        set_guest_last_error(teb_va, 6); // ERROR_INVALID_HANDLE
        ctx.regs.rax = 0;
    }
    NtStatus::STATUS_SUCCESS
}

/// GetFileType(hFile) -> DWORD
///
/// FILE_TYPE_CHAR (2) for console, FILE_TYPE_DISK (1) for files.
pub(crate) fn k32_get_file_type(
    ctx: &mut super::super::ExecutionContext,
    handles: &crate::handle_table::HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;

    ctx.regs.rax = match handles.get(handle) {
        Some(
            crate::handle_table::NtObject::ConsoleInput
            | crate::handle_table::NtObject::ConsoleOutput { .. },
        ) => 2,
        Some(
            crate::handle_table::NtObject::File { .. }
            | crate::handle_table::NtObject::Directory { .. },
        ) => 1,
        _ => 0,
    };
    NtStatus::STATUS_SUCCESS
}

/// GetFileSizeEx(hFile, lpFileSize) -> BOOL
pub(crate) fn k32_get_file_size_ex(
    ctx: &mut super::super::ExecutionContext,
    handles: &crate::handle_table::HandleTable,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let size_ptr = args.arg1;

    match handles.get(handle) {
        Some(crate::handle_table::NtObject::File { raw_fd, .. }) => {
            // VFS file — get size from fd_file_status.
            if let Some(fs) = shared.fs.get() {
                let rds = shared.raw_fds.lock();
                if let Ok(typed_fd) = rds.fd_from_raw_integer::<crate::NtFS>(*raw_fd) {
                    use litebox::fs::FileSystem as _;
                    if let Ok(status) = fs.fd_file_status(&typed_fd) {
                        if size_ptr != 0 {
                            unsafe { core::ptr::write(size_ptr as *mut i64, status.size as i64) }
                        }
                        ctx.regs.rax = 1;
                        return NtStatus::STATUS_SUCCESS;
                    }
                }
            }
            set_guest_last_error(teb_va, 6);
            ctx.regs.rax = 0;
        }
        _ => {
            set_guest_last_error(teb_va, 6);
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod) -> BOOL
pub(crate) fn k32_set_file_pointer_ex(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let distance = args.arg1 as i64;
    let new_pos_ptr = args.arg2;
    let move_method = args.arg3 as u32;

    match handles.get(handle) {
        Some(crate::handle_table::NtObject::File {
            raw_fd, position, ..
        }) => {
            let new_pos: i64 = match move_method {
                0 => distance,                                 // FILE_BEGIN
                1 => position.load(Relaxed) as i64 + distance, // FILE_CURRENT
                2 => {
                    // FILE_END — get file size from VFS.
                    let size = (|| -> Option<i64> {
                        let fs = shared.fs.get()?;
                        let rds = shared.raw_fds.lock();
                        let typed_fd = rds.fd_from_raw_integer::<crate::NtFS>(*raw_fd).ok()?;
                        use litebox::fs::FileSystem as _;
                        let st = fs.fd_file_status(&typed_fd).ok()?;
                        Some(st.size as i64)
                    })();
                    match size {
                        Some(s) => s + distance,
                        None => {
                            set_guest_last_error(teb_va, 6);
                            ctx.regs.rax = 0;
                            return NtStatus::STATUS_SUCCESS;
                        }
                    }
                }
                _ => {
                    set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
                    ctx.regs.rax = 0;
                    return NtStatus::STATUS_SUCCESS;
                }
            };

            if new_pos < 0 {
                set_guest_last_error(teb_va, 131); // ERROR_NEGATIVE_SEEK
                ctx.regs.rax = 0;
            } else {
                position.store(new_pos as u64, Relaxed);
                if new_pos_ptr != 0 {
                    unsafe { core::ptr::write(new_pos_ptr as *mut i64, new_pos) }
                }
                ctx.regs.rax = 1;
            }
        }
        _ => {
            set_guest_last_error(teb_va, 6);
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// SetEndOfFile(hFile) -> BOOL
///
/// Sets the end of file to the current file pointer position.
pub(crate) fn k32_set_end_of_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;

    match handles.get(handle) {
        Some(crate::handle_table::NtObject::File {
            raw_fd, position, ..
        }) => {
            // VFS truncate.
            let current_pos = position.load(Relaxed) as usize;
            let ok = (|| -> Option<()> {
                let fs = shared.fs.get()?;
                let rds = shared.raw_fds.lock();
                let typed_fd = rds.fd_from_raw_integer::<crate::NtFS>(*raw_fd).ok()?;
                use litebox::fs::FileSystem as _;
                fs.truncate(&typed_fd, current_pos, false).ok()
            })();
            if ok.is_some() {
                ctx.regs.rax = 1;
            } else {
                set_guest_last_error(teb_va, 5); // ERROR_ACCESS_DENIED
                ctx.regs.rax = 0;
            }
        }
        _ => {
            set_guest_last_error(teb_va, 6); // ERROR_INVALID_HANDLE
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Console mode
// ========================================================================

/// GetConsoleMode(hConsoleHandle, lpMode) -> BOOL
pub(crate) fn k32_get_console_mode(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _handle = args.arg0;
    let mode_ptr = args.arg1;

    if mode_ptr != 0 {
        // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
        // ENABLE_VIRTUAL_TERMINAL_INPUT
        unsafe {
            core::ptr::write(mode_ptr as *mut u32, 0x0207);
        }
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// SetConsoleMode(hConsoleHandle, dwMode) -> BOOL
pub(crate) fn k32_set_console_mode(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    ctx.regs.rax = 1; // TRUE — accepted but ignored
    NtStatus::STATUS_SUCCESS
}

/// ReadConsoleW(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl)
///
/// Reads wide characters from the console input buffer.  On Windows host we
/// use ReadFile on the real stdin to get bytes and convert to UTF-16.
///
/// The caller must validate the handle *before* calling this function (to
/// avoid holding the handle-table mutex across a blocking stdin read).
///
/// A carry-over buffer (`pending`) preserves bytes read from host stdin that
/// could not yet be returned to the guest (excess beyond `chars_to_read`, or
/// incomplete trailing UTF-8 sequences).  The pending mutex is held for the
/// entire operation to serialize concurrent stdin readers — this matches real
/// Windows, where ReadConsoleW is internally serialized by the console
/// subsystem.
///
/// **TOCTOU note:** the handle is validated before this function is called,
/// but another thread could close it concurrently.  This mirrors real Windows
/// behavior where an in-flight ReadConsole can race with CloseHandle; the
/// read simply completes on the process-global stdin regardless.
pub(crate) fn k32_read_console_w(
    ctx: &mut super::super::ExecutionContext,
    is_console_input: bool,
    teb_va: usize,
    pending: &spin::Mutex<alloc::vec::Vec<u8>>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buffer_ptr = args.arg1;
    let chars_to_read = args.arg2 as u32;
    let chars_read_ptr = args.arg3;

    if !is_console_input {
        set_guest_last_error(teb_va, 6); // ERROR_INVALID_HANDLE
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    if buffer_ptr == 0 || chars_to_read == 0 {
        if chars_read_ptr != 0 {
            unsafe { core::ptr::write(chars_read_ptr as *mut u32, 0) }
        }
        ctx.regs.rax = 1;
        return NtStatus::STATUS_SUCCESS;
    }

    // Hold the pending mutex for the entire operation to prevent concurrent
    // readers from both seeing an empty buffer, both reading stdin, and then
    // one overwriting the other's leftover bytes.
    let mut pending_guard = pending.lock();
    let mut buf = core::mem::take(&mut *pending_guard);

    // If the carry-over buffer is empty, do an initial read from host stdin.
    if buf.is_empty() {
        let mut raw = alloc::vec![0u8; 4096];
        use litebox::platform::StdioProvider as _;
        match litebox_platform_multiplex::platform().read_from_stdin(&mut raw) {
            Ok(n) if n > 0 => {
                raw.truncate(n);
                buf = raw;
            }
            Ok(_) => {
                // EOF
                if chars_read_ptr != 0 {
                    unsafe { core::ptr::write(chars_read_ptr as *mut u32, 0) }
                }
                ctx.regs.rax = 1;
                return NtStatus::STATUS_SUCCESS;
            }
            Err(_) => {
                set_guest_last_error(teb_va, 109); // ERROR_BROKEN_PIPE
                if chars_read_ptr != 0 {
                    unsafe { core::ptr::write(chars_read_ptr as *mut u32, 0) }
                }
                ctx.regs.rax = 0;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    }

    // Try to decode complete characters from what we have.
    let (consumed_bytes, write_count, wide) = utf8_prefix_to_utf16(&buf, chars_to_read as usize);

    if write_count > 0 {
        // We got at least one character — return it. Any remaining bytes
        // (including a possible incomplete trailing sequence) go back into
        // the carry-over buffer for the next call.
        if consumed_bytes < buf.len() {
            *pending_guard = buf[consumed_bytes..].to_vec();
        }
    } else {
        // No complete characters could be decoded. The buffer must consist
        // entirely of an incomplete UTF-8 sequence. Try one more read from
        // stdin to complete it.
        let mut raw = alloc::vec![0u8; 4096];
        use litebox::platform::StdioProvider as _;
        if let Ok(n) = litebox_platform_multiplex::platform().read_from_stdin(&mut raw)
            && n > 0
        {
            buf.extend_from_slice(&raw[..n]);
        }

        // Retry decode after appending new bytes.
        let (consumed2, write_count2, wide2) = utf8_prefix_to_utf16(&buf, chars_to_read as usize);

        if write_count2 > 0 {
            if consumed2 < buf.len() {
                *pending_guard = buf[consumed2..].to_vec();
            }
            let dest = buffer_ptr as *mut u16;
            for (i, &ch) in wide2.iter().enumerate().take(write_count2) {
                unsafe { core::ptr::write(dest.add(i), ch) }
            }
            if chars_read_ptr != 0 {
                unsafe { core::ptr::write(chars_read_ptr as *mut u32, write_count2 as u32) }
            }
            ctx.regs.rax = 1;
            return NtStatus::STATUS_SUCCESS;
        }

        // Still no complete chars — emit U+FFFD for each remaining byte
        // so we make forward progress and never wedge.
        let emit = buf.len().min(chars_to_read as usize);
        let dest = buffer_ptr as *mut u16;
        for i in 0..emit {
            unsafe { core::ptr::write(dest.add(i), 0xFFFD) }
        }
        if emit < buf.len() {
            *pending_guard = buf[emit..].to_vec();
        }
        if chars_read_ptr != 0 {
            unsafe { core::ptr::write(chars_read_ptr as *mut u32, emit as u32) }
        }
        ctx.regs.rax = 1;
        return NtStatus::STATUS_SUCCESS;
    }

    // Write UTF-16 code units to guest buffer.
    let dest = buffer_ptr as *mut u16;
    for (i, item) in wide.iter().enumerate().take(write_count) {
        unsafe { core::ptr::write(dest.add(i), *item) }
    }

    if chars_read_ptr != 0 {
        unsafe { core::ptr::write(chars_read_ptr as *mut u32, write_count as u32) }
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// Decode the largest prefix of `bytes` that is valid UTF-8 and produces at
/// most `max_chars` UTF-16 code units.
///
/// Returns `(bytes_consumed, utf16_count, utf16_data)`.
fn utf8_prefix_to_utf16(bytes: &[u8], max_chars: usize) -> (usize, usize, alloc::vec::Vec<u16>) {
    let mut wide = alloc::vec::Vec::with_capacity(max_chars);
    let mut byte_pos = 0;

    while byte_pos < bytes.len() && wide.len() < max_chars {
        // Determine the length of the next UTF-8 codepoint.
        let b = bytes[byte_pos];
        let cp_len = if b < 0x80 {
            1
        } else if b < 0xE0 {
            2
        } else if b < 0xF0 {
            3
        } else {
            4
        };

        // Check if the full sequence is available.
        if byte_pos + cp_len > bytes.len() {
            break; // incomplete sequence — leave for next call
        }

        // Decode the codepoint.
        let slice = &bytes[byte_pos..byte_pos + cp_len];
        if let Ok(s) = core::str::from_utf8(slice) {
            // Check if encoding to UTF-16 would exceed the limit.
            let u16_count = s.encode_utf16().count();
            if wide.len() + u16_count > max_chars {
                break; // would exceed caller's buffer — stop here
            }
            wide.extend(s.encode_utf16());
            byte_pos += cp_len;
        } else {
            // Invalid UTF-8 byte — skip it as U+FFFD.
            if wide.len() + 1 > max_chars {
                break;
            }
            wide.push(0xFFFD);
            byte_pos += 1;
        }
    }

    (byte_pos, wide.len(), wide)
}

// ========================================================================
// Version info
// ========================================================================

/// GetVersionExW — reports Windows 10 21H2 (build 19044).
pub(crate) fn k32_get_version_ex_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let info_ptr = args.arg0;

    if info_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    unsafe {
        let base = info_ptr as *mut u8;
        core::ptr::write(base.add(4).cast::<u32>(), 10); // dwMajorVersion
        core::ptr::write(base.add(8).cast::<u32>(), 0); // dwMinorVersion
        core::ptr::write(base.add(12).cast::<u32>(), 19044); // dwBuildNumber
        core::ptr::write(base.add(16).cast::<u32>(), 2); // VER_PLATFORM_WIN32_NT
    }
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Module loading
// ========================================================================

/// GetProcAddress(hModule, lpProcName) -> FARPROC
///
/// Looks up exported functions in loaded stub modules. For our synthetic
/// ntdll/kernel32 stubs, exports resolve through the PE export table in
/// guest memory. For truly unknown symbols, returns NULL with
/// ERROR_PROC_NOT_FOUND. This correctly handles optional API probes
/// (e.g., CorExitProcess) that check the return value before calling.
pub(crate) fn k32_get_proc_address(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let h_module = args.arg0;
    let proc_name = args.arg1;

    // Read the procedure name for logging.
    let name_str = if proc_name > 0xFFFF {
        let mut name = alloc::vec::Vec::new();
        let mut off = 0usize;
        unsafe {
            loop {
                let ch = *((proc_name + off) as *const u8);
                if ch == 0 || name.len() >= 256 {
                    break;
                }
                name.push(ch);
                off += 1;
            }
        }
        core::str::from_utf8(&name)
            .ok()
            .map(alloc::string::String::from)
    } else {
        None // Ordinal import
    };

    // Try to resolve from the module's PE export table in guest memory.
    if let Some(module) = module_bases.iter().find(|m| m.base_address == h_module) {
        if let Some(ref name) = name_str {
            if let Some(rva) = resolve_pe_export_by_name(module.base_address, name) {
                ctx.regs.rax = module.base_address + rva as usize;
                return NtStatus::STATUS_SUCCESS;
            }
        } else {
            // Ordinal lookup: proc_name is the ordinal value.
            let ordinal = proc_name as u16;
            if let Some(rva) = resolve_pe_export_by_ordinal(module.base_address, ordinal) {
                ctx.regs.rax = module.base_address + rva as usize;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    }

    // Not found — log and return NULL.
    if let Some(ref name) = name_str {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform()
            .debug_log_print(&alloc::format!("[NT shim] GetProcAddress: {name}\n"));
    }

    set_guest_last_error(teb_va, 127); // ERROR_PROC_NOT_FOUND
    ctx.regs.rax = 0;
    NtStatus::STATUS_SUCCESS
}

/// Resolve an export by name from a PE image loaded in guest memory.
/// Returns the RVA of the export if found, or None.
fn resolve_pe_export_by_name(image_base: usize, name: &str) -> Option<u32> {
    unsafe {
        let pe_offset = core::ptr::read((image_base + 0x3C) as *const u32) as usize;
        let pe_sig = core::ptr::read((image_base + pe_offset) as *const u32);
        if pe_sig != 0x0000_4550 {
            return None;
        }

        let opt_hdr = image_base + pe_offset + 24;
        let export_dir_rva = core::ptr::read((opt_hdr + 112) as *const u32) as usize;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir = image_base + export_dir_rva;
        let num_names = core::ptr::read((export_dir + 24) as *const u32) as usize;
        let names_rva = core::ptr::read((export_dir + 32) as *const u32) as usize;
        let ordinals_rva = core::ptr::read((export_dir + 36) as *const u32) as usize;
        let functions_rva = core::ptr::read((export_dir + 28) as *const u32) as usize;

        let names_table = image_base + names_rva;
        let ordinals_table = image_base + ordinals_rva;
        let functions_table = image_base + functions_rva;

        for i in 0..num_names {
            let name_rva = core::ptr::read((names_table + i * 4) as *const u32) as usize;
            let export_name_ptr = (image_base + name_rva) as *const u8;

            let target = name.as_bytes();
            let mut matches = true;
            for (j, &tb) in target.iter().enumerate() {
                let eb = *export_name_ptr.add(j);
                if eb != tb {
                    matches = false;
                    break;
                }
            }
            if matches && *export_name_ptr.add(target.len()) == 0 {
                let ordinal = core::ptr::read((ordinals_table + i * 2) as *const u16) as usize;
                let func_rva = core::ptr::read((functions_table + ordinal * 4) as *const u32);
                return Some(func_rva);
            }
        }
    }

    None
}

/// Resolve an export by ordinal from a PE image loaded in guest memory.
/// Returns the RVA of the export if found, or None.
fn resolve_pe_export_by_ordinal(image_base: usize, ordinal: u16) -> Option<u32> {
    unsafe {
        let pe_offset = core::ptr::read((image_base + 0x3C) as *const u32) as usize;
        let pe_sig = core::ptr::read((image_base + pe_offset) as *const u32);
        if pe_sig != 0x0000_4550 {
            return None;
        }

        let opt_hdr = image_base + pe_offset + 24;
        let export_dir_rva = core::ptr::read((opt_hdr + 112) as *const u32) as usize;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir = image_base + export_dir_rva;
        let num_functions = core::ptr::read((export_dir + 20) as *const u32);
        let ordinal_base = core::ptr::read((export_dir + 16) as *const u32);
        let functions_rva = core::ptr::read((export_dir + 28) as *const u32) as usize;

        let functions_table = image_base + functions_rva;
        if (ordinal as u32) < ordinal_base {
            return None;
        }
        let index = ordinal as u32 - ordinal_base;
        if index < num_functions {
            let func_rva = core::ptr::read((functions_table + index as usize * 4) as *const u32);
            if func_rva != 0 {
                return Some(func_rva);
            }
        }
    }

    None
}

/// LoadLibraryExW(lpLibFileName, hFile, dwFlags) -> HMODULE
///
/// Returns the base address of already-loaded modules (name match),
/// or NULL with ERROR_MOD_NOT_FOUND for unknown DLLs.
pub(crate) fn k32_load_library_ex_w(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let filename_ptr = args.arg0;

    if filename_ptr == 0 {
        set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Read UTF-16LE library name.
    let mut chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    unsafe {
        loop {
            let ch = *((filename_ptr + off) as *const u16);
            if ch == 0 || chars.len() >= 32768 {
                break;
            }
            chars.push(ch);
            off += 2;
        }
    }
    let name = alloc::string::String::from_utf16_lossy(&chars);
    let name_lower = name.to_ascii_lowercase();
    let basename = name_lower
        .rsplit_once('\\')
        .map_or(name_lower.as_str(), |(_, b)| b);

    // Check if the library is already loaded.
    if let Some(m) = module_bases
        .iter()
        .find(|m| m.name.to_ascii_lowercase() == basename)
    {
        ctx.regs.rax = m.base_address;
        return NtStatus::STATUS_SUCCESS;
    }

    use litebox::platform::DebugLogProvider as _;
    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
        "[NT shim] LoadLibraryExW: {name:?} not found\n"
    ));

    set_guest_last_error(teb_va, 126); // ERROR_MOD_NOT_FOUND
    ctx.regs.rax = 0;
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Debug output
// ========================================================================

/// OutputDebugStringA(lpOutputString)
pub(crate) fn k32_output_debug_string_a(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let str_ptr = args.arg0;

    if str_ptr != 0 {
        let mut buf = alloc::vec::Vec::new();
        let mut off = 0usize;
        unsafe {
            loop {
                let ch = *((str_ptr + off) as *const u8);
                if ch == 0 || buf.len() >= 1024 {
                    break;
                }
                buf.push(ch);
                off += 1;
            }
        }
        if let Ok(s) = core::str::from_utf8(&buf) {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(s);
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// OutputDebugStringW(lpOutputString)
pub(crate) fn k32_output_debug_string_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let str_ptr = args.arg0;

    if str_ptr != 0 {
        let mut chars = alloc::vec::Vec::new();
        let mut off = 0usize;
        unsafe {
            loop {
                let ch = *((str_ptr + off) as *const u16);
                if ch == 0 || chars.len() >= 512 {
                    break;
                }
                chars.push(ch);
                off += 2;
            }
        }
        let s = alloc::string::String::from_utf16_lossy(&chars);
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&s);
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Heap (additional)
// ========================================================================

/// HeapCreate — returns a fake heap handle (all heaps share one allocator).
pub(crate) fn k32_heap_create(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    static NEXT_HEAP: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0xDEAD_BEEF_0002);
    let h = NEXT_HEAP.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    ctx.regs.rax = h;
    NtStatus::STATUS_SUCCESS
}

/// HeapDestroy — no-op, returns TRUE.
pub(crate) fn k32_heap_destroy(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    ctx.regs.rax = 1;
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Path / directory
// ========================================================================

/// GetFullPathNameW(lpFileName, nBufferLength, lpBuffer, lpFilePart) -> DWORD
///
/// Resolves relative paths against the guest CWD and returns the full path.
pub(crate) fn k32_get_full_path_name_w(
    ctx: &mut super::super::ExecutionContext,
    cwd: &str,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let filename_ptr = args.arg0;
    let buf_len = args.arg1 as u32;
    let buffer_ptr = args.arg2;
    let file_part_ptr = args.arg3;

    if filename_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    let mut chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    unsafe {
        loop {
            let ch = *((filename_ptr + off) as *const u16);
            if ch == 0 || chars.len() >= 32768 {
                break;
            }
            chars.push(ch);
            off += 2;
        }
    }

    // Resolve relative paths against guest CWD.
    let input_path = alloc::string::String::from_utf16_lossy(&chars);
    let full_path = resolve_relative_path(&input_path, cwd);
    let full_wide: alloc::vec::Vec<u16> = full_path.encode_utf16().collect();

    // Required buffer size including NUL terminator.
    let needed = full_wide.len() + 1;

    if buffer_ptr == 0 || (buf_len as usize) < needed {
        // Buffer too small — return required size (including NUL).
        ctx.regs.rax = needed;
        return NtStatus::STATUS_SUCCESS;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(full_wide.as_ptr(), buffer_ptr as *mut u16, full_wide.len());
        core::ptr::write((buffer_ptr + full_wide.len() * 2) as *mut u16, 0);
    }

    // Set lpFilePart to point to the filename component after the last backslash.
    if file_part_ptr != 0 {
        let last_sep = full_wide
            .iter()
            .rposition(|&c| c == b'\\' as u16 || c == b'/' as u16);
        let fp = match last_sep {
            Some(pos) => buffer_ptr + (pos + 1) * 2,
            None => buffer_ptr,
        };
        unsafe {
            core::ptr::write(file_part_ptr as *mut usize, fp);
        }
    }

    ctx.regs.rax = full_wide.len(); // Length excluding NUL
    NtStatus::STATUS_SUCCESS
}

/// GetTempPathW(nBufferLength, lpBuffer) -> DWORD
pub(crate) fn k32_get_temp_path_w(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buf_len = args.arg0 as u32;
    let buffer_ptr = args.arg1;

    let temp: &[u16] = &[
        b'C' as u16,
        b':' as u16,
        b'\\' as u16,
        b'T' as u16,
        b'e' as u16,
        b'm' as u16,
        b'p' as u16,
        b'\\' as u16,
        0,
    ];
    let path_len = temp.len() - 1;
    if buffer_ptr == 0 || buf_len == 0 {
        ctx.regs.rax = path_len + 1;
        return NtStatus::STATUS_SUCCESS;
    }

    let copy_len = core::cmp::min(temp.len(), buf_len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(temp.as_ptr(), buffer_ptr as *mut u16, copy_len);
    }
    ctx.regs.rax = path_len;
    NtStatus::STATUS_SUCCESS
}

/// GetCurrentDirectoryW(nBufferLength, lpBuffer) -> DWORD
pub(crate) fn k32_get_current_directory_w(
    ctx: &mut super::super::ExecutionContext,
    cwd: &str,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let buf_len = args.arg0 as u32;
    let buffer_ptr = args.arg1;

    // The internal CWD always has a trailing backslash for resolve_relative_path.
    // Win32 GetCurrentDirectoryW returns without trailing backslash for non-root
    // directories (e.g. "C:\foo" not "C:\foo\"), but keeps "C:\" as-is.
    let display_cwd = if cwd.len() > 3 && cwd.ends_with('\\') {
        &cwd[..cwd.len() - 1]
    } else {
        cwd
    };

    let wide: alloc::vec::Vec<u16> = display_cwd
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let path_len = wide.len() - 1; // excluding NUL

    if buffer_ptr == 0 || (buf_len as usize) < wide.len() {
        // Return required size including NUL.
        ctx.regs.rax = wide.len();
        return NtStatus::STATUS_SUCCESS;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buffer_ptr as *mut u16, wide.len());
    }
    ctx.regs.rax = path_len;
    NtStatus::STATUS_SUCCESS
}

/// SetCurrentDirectoryW(lpPathName) -> BOOL
pub(crate) fn k32_set_current_directory_w(
    ctx: &mut super::super::ExecutionContext,
    cwd: &mut alloc::string::String,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let path_ptr = args.arg0;

    if path_ptr == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    // Read the new directory path.
    let mut chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    unsafe {
        loop {
            let ch = *((path_ptr + off) as *const u16);
            if ch == 0 || chars.len() >= 32768 {
                break;
            }
            chars.push(ch);
            off += 2;
        }
    }
    let raw_path = alloc::string::String::from_utf16_lossy(&chars);

    // Resolve relative paths against the current CWD.
    let mut new_dir = resolve_relative_path(&raw_path, cwd);

    // Try VFS validation first.
    let valid = if let Some(super::file::TranslatedPath::Vfs(vfs_path)) =
        super::file::drive_path_to_vfs(&new_dir)
    {
        if let Some(fs) = shared.fs.get() {
            use litebox::fs::FileSystem as _;
            fs.file_status(&*vfs_path)
                .map(|s| s.file_type == litebox::fs::FileType::Directory)
                .unwrap_or(false)
        } else {
            false
        }
    } else {
        // No VFS path — not found.
        false
    };

    if !valid {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }

    // Ensure it ends with a backslash.
    if !new_dir.ends_with('\\') {
        new_dir.push('\\');
    }

    *cwd = new_dir;
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Handle duplication
// ========================================================================

/// DuplicateHandle — creates a new handle table entry for the same object.
pub(crate) fn k32_duplicate_handle(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _h_source_process = args.arg0;
    let h_source = args.arg1 as u32;
    let _h_target_process = args.arg2;
    let lp_target_handle = args.arg3;

    match handles.duplicate(h_source) {
        Some(new_handle) => {
            if lp_target_handle != 0 {
                unsafe {
                    core::ptr::write(lp_target_handle as *mut usize, new_handle as usize);
                }
            }
            ctx.regs.rax = 1; // TRUE
            NtStatus::STATUS_SUCCESS
        }
        None => {
            ctx.regs.rax = 0; // FALSE
            NtStatus::STATUS_INVALID_HANDLE
        }
    }
}

// ========================================================================
// Environment (additional)
// ========================================================================

/// SetEnvironmentVariableW(lpName, lpValue) -> BOOL
///
/// Args: rcx(→r10)=lpName, rdx=lpValue
/// If lpValue is NULL, the variable is deleted.
pub(crate) fn k32_set_environment_variable_w(
    ctx: &mut super::super::ExecutionContext,
    env_vars: &mut alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let lp_name = args.arg0;
    let lp_value = args.arg1;

    if lp_name == 0 {
        ctx.regs.rax = 0; // FALSE
        return NtStatus::STATUS_SUCCESS;
    }

    // Read the variable name (UTF-16LE NUL-terminated).
    let mut name_chars = alloc::vec::Vec::new();
    let mut off = 0usize;
    loop {
        let ch = unsafe { core::ptr::read((lp_name + off) as *const u16) };
        if ch == 0 {
            break;
        }
        name_chars.push(ch);
        off += 2;
        if name_chars.len() > 32768 {
            break;
        }
    }
    let name = alloc::string::String::from_utf16_lossy(&name_chars);

    if lp_value == 0 {
        // Delete the variable (case-insensitive).
        let name_upper = name.to_uppercase();
        let key_to_remove = env_vars
            .keys()
            .find(|k| k.to_uppercase() == name_upper)
            .cloned();
        if let Some(key) = key_to_remove {
            env_vars.remove(&key);
        }
    } else {
        // Read the value (UTF-16LE NUL-terminated).
        let mut val_chars = alloc::vec::Vec::new();
        let mut voff = 0usize;
        loop {
            let ch = unsafe { core::ptr::read((lp_value + voff) as *const u16) };
            if ch == 0 {
                break;
            }
            val_chars.push(ch);
            voff += 2;
            if val_chars.len() > 32768 {
                break;
            }
        }
        let value = alloc::string::String::from_utf16_lossy(&val_chars);

        // Remove any existing key with a different case to prevent duplicates.
        let name_upper = name.to_uppercase();
        let existing_key = env_vars
            .keys()
            .find(|k| k.to_uppercase() == name_upper)
            .cloned();
        if let Some(key) = existing_key {
            env_vars.remove(&key);
        }
        env_vars.insert(name, value);
    }

    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Console handle
// ========================================================================

/// SetStdHandle(nStdHandle, hHandle) -> BOOL — accept but ignore.
pub(crate) fn k32_set_std_handle(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// File search (FindFirstFileExW / FindNextFileW / FindClose)
// ========================================================================

/// Try to enumerate files via VFS for a Win32 search pattern.
///
/// Returns:
/// - `None` — path cannot be translated to VFS; fall back to host.
/// - `Some(Ok(entries))` — VFS served the directory (may be empty).
/// - `Some(Err(win32_err))` — VFS error; set as last error + return
///   INVALID_HANDLE_VALUE.
fn find_files_vfs(
    pattern: &str,
    shared: &crate::NtSharedState,
) -> Option<Result<alloc::vec::Vec<crate::handle_table::DirEnumEntry>, u32>> {
    use crate::handle_table::DirEnumEntry;

    let fs = shared.fs.get()?;
    use litebox::fs::FileSystem as _;

    // Strip NT prefix if present, then convert to VFS path.
    let clean = pattern
        .strip_prefix("\\??\\")
        .or_else(|| pattern.strip_prefix("\\DosDevices\\"))
        .unwrap_or(pattern);

    // Split into directory + filename pattern at the last backslash.
    let (dir_part, file_pattern) = match clean.rfind('\\') {
        Some(idx) => (&clean[..idx], &clean[idx + 1..]),
        None => return None, // No directory component — can't determine VFS path.
    };

    // Convert directory to VFS path (C:\foo → /c/foo).
    let vfs_dir = super::file::drive_path_to_vfs(dir_part)?;
    let vfs_dir_str = match &vfs_dir {
        super::file::TranslatedPath::Vfs(p) => p.as_str(),
        super::file::TranslatedPath::Device(p) => p.as_str(),
        super::file::TranslatedPath::Registry(_) => return None,
    };

    // Path is VFS-translatable — authoritative from here.
    let dir_fd = match fs.open(
        vfs_dir_str,
        litebox::fs::OFlags::DIRECTORY | litebox::fs::OFlags::RDONLY,
        litebox::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => return Some(Err(map_open_error_to_win32(&e))),
    };
    let raw_entries = match fs.read_dir(&dir_fd) {
        Ok(entries) => {
            let _ = fs.close(&dir_fd);
            entries
        }
        Err(e) => {
            let _ = fs.close(&dir_fd);
            return Some(Err(map_readdir_error_to_win32(&e)));
        }
    };

    // Apply the filename pattern filter.
    let pat_lower = file_pattern.to_ascii_lowercase();
    let entries: alloc::vec::Vec<DirEnumEntry> = raw_entries
        .into_iter()
        .filter(|e| super::file::nt_wildcard_match(&e.name.to_ascii_lowercase(), &pat_lower))
        .map(|e| {
            let is_dir = e.file_type == litebox::fs::FileType::Directory;
            let file_size = if is_dir {
                0
            } else {
                let full = alloc::format!("{}/{}", vfs_dir_str, e.name);
                fs.file_status(&*full).map(|s| s.size as i64).unwrap_or(0)
            };
            let attrs = if is_dir {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            };
            DirEnumEntry {
                name: e.name,
                attributes: attrs,
                file_size,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
            }
        })
        .collect();

    Some(Ok(entries))
}

/// Map a VFS `OpenError` to a Win32 error code.
fn map_open_error_to_win32(e: &litebox::fs::errors::OpenError) -> u32 {
    use litebox::fs::errors::OpenError;
    match e {
        OpenError::PathError(_) => 3,       // ERROR_PATH_NOT_FOUND
        OpenError::AccessNotAllowed => 5,   // ERROR_ACCESS_DENIED
        OpenError::NoWritePerms => 5,       // ERROR_ACCESS_DENIED
        OpenError::ReadOnlyFileSystem => 5, // ERROR_ACCESS_DENIED
        OpenError::AlreadyExists => 183,    // ERROR_ALREADY_EXISTS
        OpenError::NotADirectory => 267,    // ERROR_DIRECTORY
        OpenError::Io => 31,                // ERROR_GEN_FAILURE
        _ => 2,                             // ERROR_FILE_NOT_FOUND
    }
}

/// Map a VFS `ReadDirError` to a Win32 error code.
fn map_readdir_error_to_win32(e: &litebox::fs::errors::ReadDirError) -> u32 {
    use litebox::fs::errors::ReadDirError;
    match e {
        ReadDirError::ClosedFd => 6,        // ERROR_INVALID_HANDLE
        ReadDirError::NotADirectory => 267, // ERROR_DIRECTORY
        ReadDirError::Io => 31,             // ERROR_GEN_FAILURE
        _ => 31,                            // ERROR_GEN_FAILURE
    }
}

/// FindFirstFileExW — VFS-first with host fallback.
///
/// Args: r10=lpFileName, rdx=fInfoLevelId, r8=lpFindFileData, r9=fSearchOp
/// Returns: search handle in rax, or INVALID_HANDLE_VALUE on no match.
pub(crate) fn k32_find_first_file_ex_w(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
    cwd: &str,
    shared: &crate::NtSharedState,
) -> NtStatus {
    use crate::handle_table::NtObject;

    let args = NtSyscallArgs::from_ctx(ctx);
    let filename_ptr = args.arg0;
    let _info_level = args.arg1;
    let find_data_ptr = args.arg2;

    if filename_ptr == 0 || find_data_ptr == 0 {
        ctx.regs.rax = usize::MAX;
        return NtStatus::STATUS_SUCCESS;
    }

    // Read the search pattern from guest memory (page-checked UTF-16).
    let pattern = {
        let va_start = shared
            .guest_va_start
            .load(core::sync::atomic::Ordering::Acquire);
        let va_end = shared
            .guest_va_end
            .load(core::sync::atomic::Ordering::Acquire);
        match super::super::read_wide_string_checked(
            &shared.process_state.pm,
            filename_ptr,
            va_start,
            va_end,
            32768,
        ) {
            Some(s) => s,
            None => {
                set_guest_last_error(teb_va, 87); // ERROR_INVALID_PARAMETER
                ctx.regs.rax = usize::MAX;
                return NtStatus::STATUS_SUCCESS;
            }
        }
    };

    // Resolve relative patterns against the guest CWD.
    let pattern = resolve_relative_path(&pattern, cwd);

    // ── VFS-first path ──────────────────────────────────────────────
    // Split the pattern into directory + filename glob, try VFS first.
    match find_files_vfs(&pattern, shared) {
        Some(Ok(vfs_entries)) => {
            if vfs_entries.is_empty() {
                set_guest_last_error(teb_va, 2); // ERROR_FILE_NOT_FOUND
                ctx.regs.rax = usize::MAX;
                return NtStatus::STATUS_SUCCESS;
            }
            write_find_data(find_data_ptr, &vfs_entries[0]);
            let handle = handles.insert(NtObject::FindSearch {
                entries: vfs_entries,
                next_index: 1,
            });
            ctx.regs.rax = handle as usize;
            NtStatus::STATUS_SUCCESS
        }
        Some(Err(win32_err)) => {
            set_guest_last_error(teb_va, win32_err);
            ctx.regs.rax = usize::MAX;
            NtStatus::STATUS_SUCCESS
        }
        None => {
            // Not VFS-translatable — no file found.
            set_guest_last_error(teb_va, 2); // ERROR_FILE_NOT_FOUND
            ctx.regs.rax = usize::MAX;
            NtStatus::STATUS_SUCCESS
        }
    }
}

/// FindNextFileW(hFindFile, lpFindFileData) -> BOOL
pub(crate) fn k32_find_next_file_w(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    teb_va: usize,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let h_find = args.arg0 as u32;
    let find_data_ptr = args.arg1;

    match handles.get_mut(h_find) {
        Some(crate::handle_table::NtObject::FindSearch {
            entries,
            next_index,
        }) => {
            if *next_index < entries.len() {
                write_find_data(find_data_ptr, &entries[*next_index]);
                *next_index += 1;
                ctx.regs.rax = 1; // TRUE
            } else {
                set_guest_last_error(teb_va, 18); // ERROR_NO_MORE_FILES
                ctx.regs.rax = 0; // FALSE — no more files
            }
        }
        _ => {
            set_guest_last_error(teb_va, 6); // ERROR_INVALID_HANDLE
            ctx.regs.rax = 0;
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// FindClose(hFindFile) -> BOOL
pub(crate) fn k32_find_close(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let h_find = args.arg0 as u32;

    if let Some(obj) = handles.close(h_find) {
        super::close_vfs_fd(&obj, shared);
        ctx.regs.rax = 1; // TRUE
    } else {
        ctx.regs.rax = 0; // FALSE
    }
    NtStatus::STATUS_SUCCESS
}

/// Write a DirEnumEntry into a WIN32_FIND_DATAW
/// structure at the given guest pointer.
///
/// WIN32_FIND_DATAW layout (592 bytes total):
///   +0   DWORD dwFileAttributes
///   +4   FILETIME ftCreationTime (8 bytes)
///   +12  FILETIME ftLastAccessTime (8 bytes)
///   +20  FILETIME ftLastWriteTime (8 bytes)
///   +28  DWORD nFileSizeHigh
///   +32  DWORD nFileSizeLow
///   +36  DWORD dwReserved0
///   +40  DWORD dwReserved1
///   +44  WCHAR cFileName[260] (520 bytes)
///   +564 WCHAR cAlternateFileName[14] (28 bytes)
fn write_find_data<T: FindDataSource>(ptr: usize, entry: &T) {
    if ptr == 0 {
        return;
    }
    unsafe {
        // Zero the full 592-byte structure.
        core::ptr::write_bytes(ptr as *mut u8, 0, 592);

        core::ptr::write(ptr as *mut u32, entry.attributes());
        // CreationTime as FILETIME (low, high)
        let ct = entry.creation_time();
        core::ptr::write((ptr + 4) as *mut u32, ct as u32);
        core::ptr::write((ptr + 8) as *mut u32, (ct >> 32) as u32);
        // LastAccessTime
        let at = entry.last_access_time();
        core::ptr::write((ptr + 12) as *mut u32, at as u32);
        core::ptr::write((ptr + 16) as *mut u32, (at >> 32) as u32);
        // LastWriteTime
        let wt = entry.last_write_time();
        core::ptr::write((ptr + 20) as *mut u32, wt as u32);
        core::ptr::write((ptr + 24) as *mut u32, (wt >> 32) as u32);
        // File size
        let sz = entry.file_size();
        core::ptr::write((ptr + 28) as *mut u32, (sz >> 32) as u32); // high
        core::ptr::write((ptr + 32) as *mut u32, sz as u32); // low
        // cFileName — NUL-terminated UTF-16 at +44
        let name_u16: alloc::vec::Vec<u16> = entry.name().encode_utf16().collect();
        let copy_len = core::cmp::min(name_u16.len(), 259);
        core::ptr::copy_nonoverlapping(name_u16.as_ptr(), (ptr + 44) as *mut u16, copy_len);
    }
}

/// Trait to abstract over DirEnumEntry for find data output.
trait FindDataSource {
    fn name(&self) -> &str;
    fn attributes(&self) -> u32;
    fn file_size(&self) -> i64;
    fn creation_time(&self) -> i64;
    fn last_access_time(&self) -> i64;
    fn last_write_time(&self) -> i64;
}

impl FindDataSource for crate::handle_table::DirEnumEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn attributes(&self) -> u32 {
        self.attributes
    }
    fn file_size(&self) -> i64 {
        self.file_size
    }
    fn creation_time(&self) -> i64 {
        self.creation_time
    }
    fn last_access_time(&self) -> i64 {
        self.last_access_time
    }
    fn last_write_time(&self) -> i64 {
        self.last_write_time
    }
}

// ========================================================================
// SEH / unwinding stubs
// ========================================================================

/// RtlCaptureContext(ContextRecord) -> void
///
/// Fills a CONTEXT structure from our saved guest registers.
pub(crate) fn k32_rtl_capture_context(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let context_ptr = args.arg0;

    if context_ptr != 0 {
        unsafe {
            // Zero 1232-byte CONTEXT struct, then fill key fields.
            core::ptr::write_bytes(context_ptr as *mut u8, 0, 1232);
            let base = context_ptr as *mut u8;
            // ContextFlags = CONTEXT_FULL (0x10000B)
            core::ptr::write(base.add(0x30).cast::<u32>(), 0x10000B);
            core::ptr::write(base.add(0x78).cast::<u64>(), ctx.regs.rax as u64);
            core::ptr::write(base.add(0x80).cast::<u64>(), ctx.regs.rcx as u64);
            core::ptr::write(base.add(0x88).cast::<u64>(), ctx.regs.rdx as u64);
            core::ptr::write(base.add(0x90).cast::<u64>(), ctx.regs.rbx as u64);
            core::ptr::write(base.add(0x98).cast::<u64>(), ctx.regs.rsp as u64);
            core::ptr::write(base.add(0xA0).cast::<u64>(), ctx.regs.rbp as u64);
            core::ptr::write(base.add(0xA8).cast::<u64>(), ctx.regs.rsi as u64);
            core::ptr::write(base.add(0xB0).cast::<u64>(), ctx.regs.rdi as u64);
            core::ptr::write(base.add(0xB8).cast::<u64>(), ctx.regs.r8 as u64);
            core::ptr::write(base.add(0xC0).cast::<u64>(), ctx.regs.r9 as u64);
            core::ptr::write(base.add(0xC8).cast::<u64>(), ctx.regs.r10 as u64);
            core::ptr::write(base.add(0xD0).cast::<u64>(), ctx.regs.r11 as u64);
            core::ptr::write(base.add(0xD8).cast::<u64>(), ctx.regs.r12 as u64);
            core::ptr::write(base.add(0xE0).cast::<u64>(), ctx.regs.r13 as u64);
            core::ptr::write(base.add(0xE8).cast::<u64>(), ctx.regs.r14 as u64);
            core::ptr::write(base.add(0xF0).cast::<u64>(), ctx.regs.r15 as u64);
            // Rip = return address from stack
            let return_addr = core::ptr::read(ctx.regs.rsp as *const u64);
            core::ptr::write(base.add(0xF8).cast::<u64>(), return_addr);
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// Find which loaded module contains `pc` and return (image_base, image_size).
fn find_module_for_pc(pc: usize, module_bases: &[crate::ModuleBase]) -> Option<(usize, usize)> {
    module_bases
        .iter()
        .find(|m| pc >= m.base_address && pc < m.base_address + m.image_size)
        .map(|m| (m.base_address, m.image_size))
}

/// RUNTIME_FUNCTION entry from PE .pdata section (12 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_data: u32,
}

/// Look up the RUNTIME_FUNCTION for `control_pc` by binary-searching the PE
/// exception directory (.pdata) of the containing module.
fn lookup_runtime_function(
    control_pc: usize,
    image_base: usize,
) -> Option<(RuntimeFunction, usize)> {
    unsafe {
        // Read PE offset from DOS header.
        let pe_off = core::ptr::read((image_base + 0x3C) as *const u32) as usize;
        let pe_sig = core::ptr::read((image_base + pe_off) as *const u32);
        if pe_sig != 0x0000_4550 {
            return None;
        }

        let opt_hdr = image_base + pe_off + 24;
        // Exception directory is data directory entry 3 (offset 112 + 3*8 = 136).
        let except_rva = core::ptr::read((opt_hdr + 136) as *const u32) as usize;
        let except_size = core::ptr::read((opt_hdr + 140) as *const u32) as usize;
        if except_rva == 0 || except_size == 0 {
            return None;
        }

        let table_va = image_base + except_rva;
        let count = except_size / 12; // each RUNTIME_FUNCTION is 12 bytes
        let rva = (control_pc - image_base) as u32;

        // Binary search for the RUNTIME_FUNCTION containing rva.
        let entries = core::slice::from_raw_parts(table_va as *const RuntimeFunction, count);
        match entries.binary_search_by(|e| {
            if rva < e.begin_address {
                core::cmp::Ordering::Greater
            } else if rva >= e.end_address {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => Some((entries[idx], image_base)),
            Err(_) => None,
        }
    }
}

/// RtlLookupFunctionEntry(ControlPc, ImageBase, HistoryTable) -> PRUNTIME_FUNCTION
///
/// Searches the PE exception directory for a RUNTIME_FUNCTION that covers
/// ControlPc. Returns a pointer to the entry (in guest .pdata) or NULL.
pub(crate) fn k32_rtl_lookup_function_entry(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let control_pc = args.arg0;
    let image_base_ptr = args.arg1;
    // arg2 = HistoryTable (ignored)

    if let Some((img_base, _img_size)) = find_module_for_pc(control_pc, module_bases) {
        if image_base_ptr != 0 {
            unsafe {
                core::ptr::write(image_base_ptr as *mut u64, img_base as u64);
            }
        }
        if let Some((rf, _)) = lookup_runtime_function(control_pc, img_base) {
            // Return a pointer to the RUNTIME_FUNCTION in guest .pdata.
            // We locate it by computing the table VA + index.
            unsafe {
                let pe_off = core::ptr::read((img_base + 0x3C) as *const u32) as usize;
                let opt_hdr = img_base + pe_off + 24;
                let except_rva = core::ptr::read((opt_hdr + 136) as *const u32) as usize;
                let except_size = core::ptr::read((opt_hdr + 140) as *const u32) as usize;
                let table_va = img_base + except_rva;
                let count = except_size / 12;
                let entries =
                    core::slice::from_raw_parts(table_va as *const RuntimeFunction, count);
                // Find the index of rf by matching begin_address.
                if let Some(idx) = entries
                    .iter()
                    .position(|e| e.begin_address == rf.begin_address)
                {
                    ctx.regs.rax = table_va + idx * 12;
                    return NtStatus::STATUS_SUCCESS;
                }
            }
        }
    }

    // Not found — write zero to ImageBase and return NULL.
    if image_base_ptr != 0 {
        unsafe {
            core::ptr::write(image_base_ptr as *mut u64, 0);
        }
    }
    ctx.regs.rax = 0;
    NtStatus::STATUS_SUCCESS
}

/// RtlVirtualUnwind(HandlerType, ImageBase, ControlPc, FunctionEntry,
///                   ContextRecord, HandlerData, EstablisherFrame, ContextPointers)
///
/// Performs a virtual unwind of one frame using the UNWIND_INFO from the PE.
/// This implements the basic unwind operations (PUSH_NONVOL, ALLOC_SMALL/LARGE,
/// SET_FPREG) needed for x64 frame walking.
pub(crate) fn k32_rtl_virtual_unwind(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _handler_type = args.arg0;
    let image_base = args.arg1;
    let _control_pc = args.arg2;
    let func_entry_ptr = args.arg3;
    // Stack-passed args: [rsp+0x28]=ContextRecord, [rsp+0x30]=HandlerData,
    //                     [rsp+0x38]=EstablisherFrame, [rsp+0x40]=ContextPointers
    let context_record = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u64) } as usize;
    let handler_data_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u64) } as usize;
    let establisher_frame_ptr =
        unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u64) } as usize;

    if func_entry_ptr == 0 || context_record == 0 {
        ctx.regs.rax = 0; // no exception handler
        return NtStatus::STATUS_SUCCESS;
    }

    let _ = module_bases; // used indirectly via image_base

    unsafe {
        let rf = core::ptr::read(func_entry_ptr as *const RuntimeFunction);
        let unwind_info_va = image_base + rf.unwind_data as usize;
        let unwind_info = unwind_info_va as *const u8;

        let version_flags = core::ptr::read(unwind_info);
        let _version = version_flags & 0x7;
        let flags = (version_flags >> 3) & 0x1F;
        let _prolog_size = core::ptr::read(unwind_info.add(1));
        let code_count = core::ptr::read(unwind_info.add(2)) as usize;
        let frame_register = core::ptr::read(unwind_info.add(3));
        let frame_reg_idx = (frame_register & 0x0F) as usize;
        let frame_offset = ((frame_register >> 4) as usize) * 16;

        // CONTEXT offsets for registers: Rax=0x78, Rcx=0x80, ... R15=0xF0, Rip=0xF8, Rsp=0x98
        // Register index mapping: 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP,
        //   6=RSI, 7=RDI, 8=R8, 9=R9, 10=R10, 11=R11, 12=R12, 13=R13, 14=R14, 15=R15
        let reg_offset = |idx: usize| -> usize {
            match idx {
                0 => 0x78,  // Rax
                1 => 0x80,  // Rcx
                2 => 0x88,  // Rdx
                3 => 0x90,  // Rbx
                4 => 0x98,  // Rsp
                5 => 0xA0,  // Rbp
                6 => 0xA8,  // Rsi
                7 => 0xB0,  // Rdi
                8 => 0xB8,  // R8
                9 => 0xC0,  // R9
                10 => 0xC8, // R10
                11 => 0xD0, // R11
                12 => 0xD8, // R12
                13 => 0xE0, // R13
                14 => 0xE8, // R14
                15 => 0xF0, // R15
                _ => 0x78,  // fallback to Rax
            }
        };

        // Read current RSP from CONTEXT.
        let ctx_base = context_record as *mut u8;
        let mut rsp_val = core::ptr::read(ctx_base.add(0x98).cast::<u64>()) as usize;

        // Process unwind codes (each is 2 bytes, starting at offset 4).
        let codes_base = unwind_info.add(4);
        let mut ci = 0usize;
        while ci < code_count {
            let _code_offset = core::ptr::read(codes_base.add(ci * 2));
            let op_info = core::ptr::read(codes_base.add(ci * 2 + 1));
            let op = op_info & 0x0F;
            let info = (op_info >> 4) & 0x0F;

            match op {
                0 => {
                    // UWOP_PUSH_NONVOL: pop register from stack
                    let val = core::ptr::read(rsp_val as *const u64);
                    core::ptr::write(ctx_base.add(reg_offset(info as usize)).cast::<u64>(), val);
                    rsp_val += 8;
                    ci += 1;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if info == 0 {
                        let slots =
                            core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u16>()) as usize;
                        rsp_val += slots * 8;
                        ci += 2;
                    } else {
                        let size =
                            core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u32>()) as usize;
                        rsp_val += size;
                        ci += 3;
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    rsp_val += (info as usize) * 8 + 8;
                    ci += 1;
                }
                3 => {
                    // UWOP_SET_FPREG: RSP = FrameRegister - FrameOffset
                    let freg_val =
                        core::ptr::read(ctx_base.add(reg_offset(frame_reg_idx)).cast::<u64>())
                            as usize;
                    rsp_val = freg_val.wrapping_sub(frame_offset);
                    ci += 1;
                }
                4 => {
                    // UWOP_SAVE_NONVOL
                    let slot_offset =
                        core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u16>()) as usize;
                    let saved_val = core::ptr::read((rsp_val + slot_offset * 8) as *const u64);
                    core::ptr::write(
                        ctx_base.add(reg_offset(info as usize)).cast::<u64>(),
                        saved_val,
                    );
                    ci += 2;
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR
                    let byte_offset =
                        core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u32>()) as usize;
                    let saved_val = core::ptr::read((rsp_val + byte_offset) as *const u64);
                    core::ptr::write(
                        ctx_base.add(reg_offset(info as usize)).cast::<u64>(),
                        saved_val,
                    );
                    ci += 3;
                }
                8 => {
                    // UWOP_SAVE_XMM128 — skip (2 slots)
                    ci += 2;
                }
                9 => {
                    // UWOP_SAVE_XMM128_FAR — skip (3 slots)
                    ci += 3;
                }
                10 => {
                    // UWOP_PUSH_MACHFRAME
                    if info == 0 {
                        rsp_val += 0x28; // 5 * 8 (no error code)
                    } else {
                        rsp_val += 0x30; // 6 * 8 (with error code)
                    }
                    ci += 1;
                }
                _ => {
                    // Unknown unwind op — skip.
                    ci += 1;
                }
            }
        }

        // Pop return address from the (now-restored) stack.
        let return_addr = core::ptr::read(rsp_val as *const u64);
        rsp_val += 8;

        // Write updated RSP and RIP into CONTEXT.
        core::ptr::write(ctx_base.add(0x98).cast::<u64>(), rsp_val as u64);
        core::ptr::write(ctx_base.add(0xF8).cast::<u64>(), return_addr);

        // EstablisherFrame = RSP after unwind (before return-addr pop).
        if establisher_frame_ptr != 0 {
            core::ptr::write(establisher_frame_ptr as *mut u64, (rsp_val - 8) as u64);
        }

        // Check for an exception handler (UNW_FLAG_EHANDLER=1 or UNW_FLAG_UHANDLER=2).
        if (flags & 0x3) != 0 {
            // Handler RVA is right after the unwind codes (aligned to u32).
            let codes_end = 4 + ((code_count + 1) & !1) * 2; // aligned up
            let handler_rva = core::ptr::read(unwind_info.add(codes_end).cast::<u32>()) as usize;
            let handler_va = image_base + handler_rva;

            if handler_data_ptr != 0 {
                // HandlerData points to the data after the handler RVA.
                let data_va = unwind_info_va + codes_end + 4;
                core::ptr::write(handler_data_ptr as *mut u64, data_va as u64);
            }

            ctx.regs.rax = handler_va;
        } else {
            if handler_data_ptr != 0 {
                core::ptr::write(handler_data_ptr as *mut u64, 0);
            }
            ctx.regs.rax = 0; // no handler
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
///              ContextRecord, HistoryTable)
///
/// Performs a full exception unwind to a target frame. This implementation
/// walks frames using RtlVirtualUnwind until reaching TargetFrame, then
/// restores the context. For now we implement the basic frame-walking loop.
pub(crate) fn k32_rtl_unwind_ex(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let target_frame = args.arg0;
    let target_ip = args.arg1;
    let _exception_record = args.arg2;
    let return_value = args.arg3;
    // Stack args: [rsp+0x28]=ContextRecord, [rsp+0x30]=HistoryTable
    let context_record = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u64) } as usize;

    if context_record == 0 {
        return NtStatus::STATUS_SUCCESS;
    }

    // Walk frames until we reach the target or run out of unwind data.
    let max_iterations = 256;
    for _ in 0..max_iterations {
        let rip = unsafe {
            core::ptr::read((context_record as *const u8).add(0xF8).cast::<u64>()) as usize
        };
        let rsp = unsafe {
            core::ptr::read((context_record as *const u8).add(0x98).cast::<u64>()) as usize
        };

        // Check if we've reached the target frame.
        if target_frame != 0 && rsp >= target_frame {
            break;
        }

        // Find the module and function entry for current RIP.
        if let Some((img_base, _)) = find_module_for_pc(rip, module_bases) {
            if let Some((rf, _)) = lookup_runtime_function(rip, img_base) {
                // Simulate RtlVirtualUnwind inline — process the unwind codes.
                let unwind_info_va = img_base + rf.unwind_data as usize;
                let unwind_info = unwind_info_va as *const u8;

                unsafe {
                    let version_flags = core::ptr::read(unwind_info);
                    let _version = version_flags & 0x7;
                    let code_count = core::ptr::read(unwind_info.add(2)) as usize;
                    let frame_register = core::ptr::read(unwind_info.add(3));
                    let frame_reg_idx = (frame_register & 0x0F) as usize;
                    let frame_off = ((frame_register >> 4) as usize) * 16;

                    let reg_offset = |idx: usize| -> usize {
                        match idx {
                            0 => 0x78,
                            1 => 0x80,
                            2 => 0x88,
                            3 => 0x90,
                            4 => 0x98,
                            5 => 0xA0,
                            6 => 0xA8,
                            7 => 0xB0,
                            8 => 0xB8,
                            9 => 0xC0,
                            10 => 0xC8,
                            11 => 0xD0,
                            12 => 0xD8,
                            13 => 0xE0,
                            14 => 0xE8,
                            15 => 0xF0,
                            _ => 0x78,
                        }
                    };

                    let ctx_base = context_record as *mut u8;
                    let mut cur_rsp = core::ptr::read(ctx_base.add(0x98).cast::<u64>()) as usize;

                    let codes_base = unwind_info.add(4);
                    let mut ci = 0usize;
                    while ci < code_count {
                        let op_info = core::ptr::read(codes_base.add(ci * 2 + 1));
                        let op = op_info & 0x0F;
                        let info = (op_info >> 4) & 0x0F;
                        match op {
                            0 => {
                                let val = core::ptr::read(cur_rsp as *const u64);
                                core::ptr::write(
                                    ctx_base.add(reg_offset(info as usize)).cast::<u64>(),
                                    val,
                                );
                                cur_rsp += 8;
                                ci += 1;
                            }
                            1 => {
                                if info == 0 {
                                    let slots =
                                        core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u16>())
                                            as usize;
                                    cur_rsp += slots * 8;
                                    ci += 2;
                                } else {
                                    let size =
                                        core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u32>())
                                            as usize;
                                    cur_rsp += size;
                                    ci += 3;
                                }
                            }
                            2 => {
                                cur_rsp += (info as usize) * 8 + 8;
                                ci += 1;
                            }
                            3 => {
                                let freg = core::ptr::read(
                                    ctx_base.add(reg_offset(frame_reg_idx)).cast::<u64>(),
                                ) as usize;
                                cur_rsp = freg.wrapping_sub(frame_off);
                                ci += 1;
                            }
                            4 => {
                                // UWOP_SAVE_NONVOL
                                let slot_offset =
                                    core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u16>())
                                        as usize;
                                let saved_val =
                                    core::ptr::read((cur_rsp + slot_offset * 8) as *const u64);
                                core::ptr::write(
                                    ctx_base.add(reg_offset(info as usize)).cast::<u64>(),
                                    saved_val,
                                );
                                ci += 2;
                            }
                            5 => {
                                // UWOP_SAVE_NONVOL_FAR
                                let byte_offset =
                                    core::ptr::read(codes_base.add((ci + 1) * 2).cast::<u32>())
                                        as usize;
                                let saved_val =
                                    core::ptr::read((cur_rsp + byte_offset) as *const u64);
                                core::ptr::write(
                                    ctx_base.add(reg_offset(info as usize)).cast::<u64>(),
                                    saved_val,
                                );
                                ci += 3;
                            }
                            8 => {
                                ci += 2;
                            }
                            9 => {
                                ci += 3;
                            }
                            _ => {
                                ci += 1;
                            }
                        }
                    }

                    let ret_addr = core::ptr::read(cur_rsp as *const u64);
                    cur_rsp += 8;
                    core::ptr::write(ctx_base.add(0x98).cast::<u64>(), cur_rsp as u64);
                    core::ptr::write(ctx_base.add(0xF8).cast::<u64>(), ret_addr);
                }
            } else {
                // Leaf function — pop return address directly.
                unsafe {
                    let ctx_base = context_record as *mut u8;
                    let cur_rsp = core::ptr::read(ctx_base.add(0x98).cast::<u64>()) as usize;
                    let ret_addr = core::ptr::read(cur_rsp as *const u64);
                    core::ptr::write(ctx_base.add(0x98).cast::<u64>(), (cur_rsp + 8) as u64);
                    core::ptr::write(ctx_base.add(0xF8).cast::<u64>(), ret_addr);
                }
            }
        } else {
            break; // PC not in any known module
        }
    }

    // Set return value (RAX) in the unwound context.
    if context_record != 0 {
        unsafe {
            core::ptr::write(
                (context_record as *mut u8).add(0x78).cast::<u64>(),
                return_value as u64,
            );
            // Set target IP if provided.
            if target_ip != 0 {
                core::ptr::write(
                    (context_record as *mut u8).add(0xF8).cast::<u64>(),
                    target_ip as u64,
                );
            }
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// RtlPcToFileHeader — maps a PC to its module image base.
pub(crate) fn k32_rtl_pc_to_file_header(
    ctx: &mut super::super::ExecutionContext,
    module_bases: &[crate::ModuleBase],
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let pc = args.arg0;
    let base_ptr = args.arg1;

    let image_base = find_module_for_pc(pc, module_bases).map_or(0, |(base, _)| base as u64);

    if base_ptr != 0 {
        unsafe {
            core::ptr::write(base_ptr as *mut u64, image_base);
        }
    }
    ctx.regs.rax = image_base as usize;
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// Exception raising
// ========================================================================

/// EXCEPTION_NONCONTINUABLE flag.
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;

/// RaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments) -> void
///
/// Dispatches an exception. Since the shim cannot call guest code inline
/// (no re-entrant guest execution), this implements the common-case semantics:
/// - Non-continuable exceptions terminate the guest process.
/// - Continuable exceptions return to the caller (treated as handled).
///
/// Note: SetUnhandledExceptionFilter is tracked but the registered filter
/// is not invoked because the shim has no mechanism to call a guest function
/// and consume its return value within a single syscall dispatch. A full
/// implementation would require a guest re-entry trampoline.
pub(crate) fn k32_raise_exception(ctx: &mut super::super::ExecutionContext) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let exception_code = args.arg0 as u32;
    let exception_flags = args.arg1 as u32;
    let _n_args = args.arg2;
    let _lp_arguments = args.arg3;

    if (exception_flags & EXCEPTION_NONCONTINUABLE) != 0 {
        // Non-continuable → terminate the guest with the exception code.
        ctx.regs.rax = exception_code as usize;
        return (NtStatus::STATUS_SUCCESS, true);
    }

    // Continuable exception — return to caller as if the exception was handled.
    ctx.regs.rax = 0;
    (NtStatus::STATUS_SUCCESS, false)
}

/// UnhandledExceptionFilter(ExceptionInfo) -> LONG
///
/// Examines the EXCEPTION_RECORD inside ExceptionInfo. If the exception is
/// non-continuable, returns EXCEPTION_EXECUTE_HANDLER (1) to indicate the
/// process should terminate. Otherwise returns EXCEPTION_CONTINUE_SEARCH (0).
pub(crate) fn k32_unhandled_exception_filter(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let exception_info_ptr = args.arg0;

    if exception_info_ptr != 0 {
        unsafe {
            // EXCEPTION_POINTERS.ExceptionRecord is at offset 0.
            let record_ptr = core::ptr::read(exception_info_ptr as *const u64) as usize;
            if record_ptr != 0 {
                // ExceptionFlags at offset 0x04.
                let flags = core::ptr::read((record_ptr + 0x04) as *const u32);
                if (flags & EXCEPTION_NONCONTINUABLE) != 0 {
                    // EXCEPTION_EXECUTE_HANDLER = 1
                    ctx.regs.rax = 1;
                    return NtStatus::STATUS_SUCCESS;
                }
            }
        }
    }

    // EXCEPTION_CONTINUE_SEARCH = 0
    ctx.regs.rax = 0;
    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Phase 3B: Sleep / SleepEx
// ---------------------------------------------------------------------------

/// Sleep(DWORD dwMilliseconds)
///
/// Suspends the current thread for the specified number of milliseconds.
pub(crate) fn k32_sleep(
    ctx: &mut super::super::ExecutionContext,
    wait_cx: &litebox::event::wait::WaitContext<'_, litebox_platform_multiplex::Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let ms = args.arg0 as u32;

    // Sleep(0) yields the current timeslice. We use a minimal 1µs wait
    // so the platform can actually yield to other threads.
    let timeout = match ms {
        0 => Some(core::time::Duration::from_micros(1)),
        0xFFFF_FFFF => None, // INFINITE
        _ => Some(core::time::Duration::from_millis(u64::from(ms))),
    };
    let cx = wait_cx.with_timeout(timeout);
    let _ = cx.sleep();

    NtStatus::STATUS_SUCCESS
}

/// SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
///
/// Same as Sleep but with alertable wait. We ignore the alertable flag.
pub(crate) fn k32_sleep_ex(
    ctx: &mut super::super::ExecutionContext,
    wait_cx: &litebox::event::wait::WaitContext<'_, litebox_platform_multiplex::Platform>,
) -> NtStatus {
    // SleepEx returns 0 if the sleep completed, WAIT_IO_COMPLETION (0xC0) if
    // an APC was dispatched. We never dispatch APCs, so always return 0.
    k32_sleep(ctx, wait_cx);
    ctx.regs.rax = 0;
    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Phase 3B: Critical Sections
// ---------------------------------------------------------------------------
//
// Windows CRITICAL_SECTION layout (40 bytes on x64):
//   +0x00  PRTL_CRITICAL_SECTION_DEBUG DebugInfo
//   +0x08  LONG LockCount
//   +0x0C  LONG RecursionCount
//   +0x10  HANDLE OwningThread
//   +0x18  HANDLE LockSemaphore
//   +0x20  ULONG_PTR SpinCount
//
// We use OwningThread as a simple thread ID. In single-threaded mode this
// always matches. For multi-threaded, we use a shim-side thread ID.
// LockSemaphore is unused (we don't need a real event for contention yet).
//
// LockCount semantics:
//   -1 = unlocked (available)
//   0  = locked, no waiters
//   >0 = locked, LockCount waiters

const CS_DEBUG_INFO: usize = 0x00;
const CS_LOCK_COUNT: usize = 0x08;
const CS_RECURSION_COUNT: usize = 0x0C;
const CS_OWNING_THREAD: usize = 0x10;
const CS_LOCK_SEMAPHORE: usize = 0x18;
const CS_SPIN_COUNT: usize = 0x20;

/// InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
pub(crate) fn k32_init_critical_section(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    init_cs(cs, 0);
    NtStatus::STATUS_SUCCESS
}

/// InitializeCriticalSectionEx(LPCRITICAL_SECTION, DWORD SpinCount, DWORD Flags)
pub(crate) fn k32_init_critical_section_ex(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    let spin_count = args.arg1 as u32;
    // arg2 = flags (CRITICAL_SECTION_NO_DEBUG_INFO etc, ignored)
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    init_cs(cs, spin_count as usize);
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

/// InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION, DWORD SpinCount)
pub(crate) fn k32_init_critical_section_and_spin_count(
    ctx: &mut super::super::ExecutionContext,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    let spin_count = args.arg1 as u32;
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }
    init_cs(cs, spin_count as usize);
    ctx.regs.rax = 1; // TRUE
    NtStatus::STATUS_SUCCESS
}

fn init_cs(cs: usize, spin_count: usize) {
    unsafe {
        core::ptr::write((cs + CS_DEBUG_INFO) as *mut usize, 0);
        core::ptr::write((cs + CS_LOCK_COUNT) as *mut i32, -1); // unlocked
        core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, 0);
        core::ptr::write((cs + CS_OWNING_THREAD) as *mut usize, 0);
        core::ptr::write((cs + CS_LOCK_SEMAPHORE) as *mut usize, 0);
        core::ptr::write((cs + CS_SPIN_COUNT) as *mut usize, spin_count);
    }
}

/// EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
///
/// Acquires the critical section using atomic CAS on LockCount.
/// Supports recursion by the owning thread. Spins then yields on contention.
pub(crate) fn k32_enter_critical_section(
    ctx: &mut super::super::ExecutionContext,
    thread_id: u32,
) -> NtStatus {
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let tid = thread_id as usize;

    unsafe {
        // Safety: CS_LOCK_COUNT (offset 0x08) and CS_OWNING_THREAD (offset 0x10)
        // are 8-byte aligned within the CRITICAL_SECTION struct, satisfying
        // AtomicI32 (4-byte) and AtomicUsize (8-byte) alignment requirements.
        let lock_count = &*((cs + CS_LOCK_COUNT) as *const AtomicI32);
        let owner = &*((cs + CS_OWNING_THREAD) as *const AtomicUsize);

        if owner.load(Ordering::Acquire) == tid {
            // Recursive acquisition — bump the recursion count.
            let rec = core::ptr::read((cs + CS_RECURSION_COUNT) as *const i32);
            core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, rec + 1);
            lock_count.fetch_add(1, Ordering::Relaxed);
            return NtStatus::STATUS_SUCCESS;
        }

        let spin_count = core::ptr::read((cs + CS_SPIN_COUNT) as *const usize);

        // Spin phase — try CAS on each iteration.
        for _ in 0..spin_count {
            if lock_count
                .compare_exchange_weak(-1, 0, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, 1);
                owner.store(tid, Ordering::Release);
                return NtStatus::STATUS_SUCCESS;
            }
            core::hint::spin_loop();
        }

        // Block phase — CAS retry with yield.
        loop {
            match lock_count.compare_exchange_weak(-1, 0, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => {
                    core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, 1);
                    owner.store(tid, Ordering::Release);
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(_) => core::hint::spin_loop(),
            }
        }
    }
}

/// TryEnterCriticalSection(LPCRITICAL_SECTION) -> BOOL
///
/// Attempts to acquire without blocking using atomic CAS. Returns TRUE (1) if
/// acquired.
pub(crate) fn k32_try_enter_critical_section(
    ctx: &mut super::super::ExecutionContext,
    thread_id: u32,
) -> NtStatus {
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    if cs == 0 {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_SUCCESS;
    }

    let tid = thread_id as usize;

    unsafe {
        let lock_count = &*((cs + CS_LOCK_COUNT) as *const AtomicI32);
        let owner = &*((cs + CS_OWNING_THREAD) as *const AtomicUsize);

        if owner.load(Ordering::Acquire) == tid {
            // Recursive — always succeeds.
            let rec = core::ptr::read((cs + CS_RECURSION_COUNT) as *const i32);
            core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, rec + 1);
            lock_count.fetch_add(1, Ordering::Relaxed);
            ctx.regs.rax = 1; // TRUE
            return NtStatus::STATUS_SUCCESS;
        }

        if lock_count
            .compare_exchange(-1, 0, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, 1);
            owner.store(tid, Ordering::Release);
            ctx.regs.rax = 1; // TRUE
        } else {
            ctx.regs.rax = 0; // FALSE
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
///
/// Releases the critical section. Validates that the caller owns the lock
/// to prevent cross-thread corruption.
pub(crate) fn k32_leave_critical_section(
    ctx: &mut super::super::ExecutionContext,
    thread_id: u32,
) -> NtStatus {
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let tid = thread_id as usize;

    unsafe {
        let lock_count = &*((cs + CS_LOCK_COUNT) as *const AtomicI32);
        let owner = &*((cs + CS_OWNING_THREAD) as *const AtomicUsize);

        // Verify the caller owns this CS.
        if owner.load(Ordering::Acquire) != tid {
            return NtStatus::STATUS_SUCCESS;
        }

        let rec = core::ptr::read((cs + CS_RECURSION_COUNT) as *const i32);
        if rec > 1 {
            // Still recursively held — decrement.
            core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, rec - 1);
            lock_count.fetch_sub(1, Ordering::Relaxed);
        } else {
            // Final release — clear ownership then unlock with atomic store.
            core::ptr::write((cs + CS_RECURSION_COUNT) as *mut i32, 0);
            owner.store(0, Ordering::Release);
            lock_count.store(-1, Ordering::Release);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
pub(crate) fn k32_delete_critical_section(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    use core::sync::atomic::{AtomicI32, Ordering};

    let args = NtSyscallArgs::from_ctx(ctx);
    let cs = args.arg0;
    if cs == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    unsafe {
        core::ptr::write_bytes(cs as *mut u8, 0, 0x28);
        let lock_count = &*((cs + CS_LOCK_COUNT) as *const AtomicI32);
        lock_count.store(-1, Ordering::Release);
    }

    NtStatus::STATUS_SUCCESS
}
