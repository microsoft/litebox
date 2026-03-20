// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Simple heap allocator for the NT shim.
//!
//! Implements GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, and HeapSize
//! backed by the LiteBox PageManager. Each allocation is page-granular with
//! an inline 16-byte header storing the usable size. This wastes memory for
//! small allocations but is simple and correct for Phase 2 CRT init.
//!
//! Layout of each allocation:
//! ```text
//! [ header (16 bytes) | user data (size bytes) | padding to page ]
//! ```
//! The header stores the requested size as a u64, allowing HeapSize and
//! HeapReAlloc to work without external tracking.

use litebox::mm::PageManager;
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawPointerProvider;
use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

use super::NtSyscallArgs;

const PAGE_SIZE: usize = 4096;
const HEADER_SIZE: usize = 16;

/// Fake heap handle returned by GetProcessHeap.
const PROCESS_HEAP_HANDLE: usize = 0xDEAD_BEEF_0001;

/// Flags for HeapAlloc.
const HEAP_ZERO_MEMORY: u32 = 0x00000008;

/// GetProcessHeap — return the process default heap handle.
///
/// Signature: `HANDLE GetProcessHeap(void);`
/// rcx is arg0 in the stub trampoline but is unused.
pub(crate) fn k32_get_process_heap(ctx: &mut super::super::ExecutionContext) {
    ctx.regs.rax = PROCESS_HEAP_HANDLE;
}

/// HeapAlloc — allocate memory from the process heap.
///
/// Signature: `LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);`
/// Args via stub trampoline: rcx(→r10)=hHeap, rdx=dwFlags, r8=dwBytes
pub(crate) fn k32_heap_alloc(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _heap = args.arg0;
    let flags = args.arg1 as u32;
    let size = args.arg2;

    if size == 0 {
        // Windows HeapAlloc(0) returns a valid pointer to a zero-size block.
        // Allocate a minimum block.
        return do_heap_alloc(ctx, pm, HEADER_SIZE, flags);
    }

    do_heap_alloc(ctx, pm, size, flags)
}

/// HeapReAlloc — reallocate a heap block.
///
/// Signature: `LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);`
/// Args: rcx(→r10)=hHeap, rdx=dwFlags, r8=lpMem, r9=dwBytes
pub(crate) fn k32_heap_realloc(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _heap = args.arg0;
    let flags = args.arg1 as u32;
    let old_ptr = args.arg2;
    let new_size = args.arg3;

    if old_ptr == 0 {
        // Like realloc(NULL, size) — just allocate.
        return do_heap_alloc(ctx, pm, new_size, flags);
    }

    // Read old size from header.
    let old_header = old_ptr - HEADER_SIZE;
    let old_size = unsafe { core::ptr::read(old_header as *const u64) } as usize;

    // If the new size fits in the existing allocation (same page count), reuse.
    let old_pages = (old_size + HEADER_SIZE + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_pages = (new_size + HEADER_SIZE + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if new_pages <= old_pages {
        // Update header with new size.
        unsafe {
            core::ptr::write(old_header as *mut u64, new_size as u64);
        }
        ctx.regs.rax = old_ptr;
        return NtStatus::STATUS_SUCCESS;
    }

    // Allocate new block, copy, free old.
    let result = do_heap_alloc(ctx, pm, new_size, flags);
    if result != NtStatus::STATUS_SUCCESS {
        return result;
    }

    let new_ptr = ctx.regs.rax;
    if new_ptr != 0 {
        let copy_size = core::cmp::min(old_size, new_size);
        unsafe {
            core::ptr::copy_nonoverlapping(old_ptr as *const u8, new_ptr as *mut u8, copy_size);
        }
        // Free old block.
        do_heap_free(pm, old_ptr);
    }

    NtStatus::STATUS_SUCCESS
}

/// HeapFree — free a heap allocation.
///
/// Signature: `BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);`
/// Args: rcx(→r10)=hHeap, rdx=dwFlags, r8=lpMem
pub(crate) fn k32_heap_free(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let ptr = args.arg2;

    if ptr == 0 {
        ctx.regs.rax = 1; // TRUE — freeing NULL is valid
        return NtStatus::STATUS_SUCCESS;
    }

    if do_heap_free(pm, ptr) {
        ctx.regs.rax = 1; // TRUE
    } else {
        ctx.regs.rax = 0; // FALSE
    }
    NtStatus::STATUS_SUCCESS
}

/// HeapSize — return the size of a heap allocation.
///
/// Signature: `SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);`
/// Args: rcx(→r10)=hHeap, rdx=dwFlags, r8=lpMem
pub(crate) fn k32_heap_size(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let ptr = args.arg2;

    if ptr == 0 {
        ctx.regs.rax = usize::MAX; // -1 = error
        return NtStatus::STATUS_SUCCESS;
    }

    let header = ptr - HEADER_SIZE;
    let size = unsafe { core::ptr::read(header as *const u64) } as usize;
    ctx.regs.rax = size;
    NtStatus::STATUS_SUCCESS
}

/// Internal: perform a heap allocation backed by PageManager.
fn do_heap_alloc(
    ctx: &mut super::super::ExecutionContext,
    pm: &PageManager<Platform, PAGE_SIZE>,
    size: usize,
    flags: u32,
) -> NtStatus {
    let total = size + HEADER_SIZE;
    let aligned = (total + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let Some(nz_size) = NonZeroPageSize::new(aligned) else {
        ctx.regs.rax = 0;
        return NtStatus::STATUS_NO_MEMORY;
    };

    let zero_fill = flags & HEAP_ZERO_MEMORY != 0;

    let result = unsafe {
        pm.create_writable_pages(None, nz_size, CreatePagesFlags::empty(), |ptr| {
            if zero_fill {
                // Explicit zero-fill requested. OS pages are already zeroed
                // on Windows, but be safe.
                let raw = ptr.as_usize() as *mut u8;
                core::ptr::write_bytes(raw, 0, aligned);
            }
            Ok(0)
        })
    };

    match result {
        Ok(ptr) => {
            let base = ptr.as_usize();
            // Write size header.
            unsafe {
                core::ptr::write(base as *mut u64, size as u64);
            }
            ctx.regs.rax = base + HEADER_SIZE;
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            ctx.regs.rax = 0;
            NtStatus::STATUS_NO_MEMORY
        }
    }
}

/// Internal: free a heap allocation.
fn do_heap_free(pm: &PageManager<Platform, PAGE_SIZE>, user_ptr: usize) -> bool {
    let header = user_ptr - HEADER_SIZE;
    let size = unsafe { core::ptr::read(header as *const u64) } as usize;
    let total = size + HEADER_SIZE;
    let aligned = (total + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(header);
    unsafe { pm.remove_pages(ptr, aligned) }.is_ok()
}
