// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT section syscall handlers.
//!
//! Implements NtCreateSection, NtMapViewOfSection, and NtQuerySection.
//! These are used by ntdll's loader to map DLL images into the guest
//! address space during initialization.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer, RawPointerProvider};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_common_windows::pe::section_chars;
use litebox_common_windows::pe_loader::{PeLoadError, PeMemoryMapper, SectionPermissions};
use litebox_common_windows::pe_parser::PeParsedFile;

use crate::handle_table::{HandleTable, NtObject};
use crate::{NtInitState, NtProcessState, PAGE_SIZE, Platform};

use super::NtSyscallArgs;

/// SEC_IMAGE flag (0x01000000) ΓÇö indicates an image section.
const SEC_IMAGE: u32 = 0x0100_0000;
const MIN_TLS_VECTOR_SLOTS: usize = 64;

fn known_tls_vector_slots(shared: &crate::NtSharedState, teb_va: usize) -> usize {
    shared
        .tls_vector_slots
        .lock()
        .get(&teb_va)
        .copied()
        .unwrap_or(MIN_TLS_VECTOR_SLOTS)
}

fn page_aligned_alloc_len(len: usize) -> usize {
    len.max(1)
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
        .unwrap_or(len.max(1))
}

fn free_tls_allocation(shared: &crate::NtSharedState, allocation: crate::TrackedGuestAllocation) {
    if !allocation.owned_by_shim || allocation.base == 0 || allocation.len == 0 {
        return;
    }

    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(allocation.base);
    let _ = unsafe { shared.process_state.pm.remove_pages(ptr, allocation.len) };
}

fn replace_thread_tls_vector_allocation(
    shared: &crate::NtSharedState,
    teb_va: usize,
    vector_base: usize,
    slot_count: usize,
    owned_by_shim: bool,
) -> Option<crate::TrackedGuestAllocation> {
    let slot_count = slot_count.max(MIN_TLS_VECTOR_SLOTS);
    shared.tls_vector_slots.lock().insert(teb_va, slot_count);
    let mut tls_allocations = shared.tls_allocations.lock();
    let thread_allocations = tls_allocations.entry(teb_va).or_default();
    thread_allocations
        .vector
        .replace(crate::TrackedGuestAllocation {
            base: vector_base,
            len: page_aligned_alloc_len(slot_count * core::mem::size_of::<usize>()),
            owned_by_shim,
        })
}

pub(crate) fn set_thread_tls_vector_allocation(
    shared: &crate::NtSharedState,
    teb_va: usize,
    vector_base: usize,
    slot_count: usize,
) {
    let _ = replace_thread_tls_vector_allocation(shared, teb_va, vector_base, slot_count, false);
}

fn push_thread_tls_block_allocation(
    shared: &crate::NtSharedState,
    teb_va: usize,
    block_base: usize,
    block_len: usize,
) {
    shared
        .tls_allocations
        .lock()
        .entry(teb_va)
        .or_default()
        .blocks
        .push(crate::TrackedGuestAllocation {
            base: block_base,
            len: page_aligned_alloc_len(block_len),
            owned_by_shim: true,
        });
}

pub(crate) fn free_thread_tls_allocations(shared: &crate::NtSharedState, teb_va: usize) {
    shared.tls_vector_slots.lock().remove(&teb_va);
    let Some(thread_allocations) = shared.tls_allocations.lock().remove(&teb_va) else {
        return;
    };

    if let Some(vector) = thread_allocations.vector {
        free_tls_allocation(shared, vector);
    }
    for block in thread_allocations.blocks {
        free_tls_allocation(shared, block);
    }
}

fn image_contains_range(image_base: usize, image_size: usize, start: usize, len: usize) -> bool {
    let Some(image_end) = image_base.checked_add(image_size) else {
        return false;
    };
    let Some(range_end) = start.checked_add(len) else {
        return false;
    };
    start >= image_base && range_end <= image_end
}

fn read_image_u32(image_base: usize, image_size: usize, addr: usize) -> Option<u32> {
    if !image_contains_range(image_base, image_size, addr, core::mem::size_of::<u32>()) {
        return None;
    }
    Some(unsafe { core::ptr::read(addr as *const u32) })
}

fn mapped_tls_directory(
    image_base: usize,
    image_size: usize,
) -> Option<(litebox_common_windows::pe::ImageTlsDirectory64, usize)> {
    use litebox_common_windows::pe::{IMAGE_DIRECTORY_ENTRY_TLS, ImageTlsDirectory64};

    let pe_offset = read_image_u32(image_base, image_size, image_base.checked_add(0x3C)?)? as usize;
    let opt = image_base.checked_add(pe_offset)?.checked_add(24)?;
    let num_dd = read_image_u32(image_base, image_size, opt.checked_add(0x6C)?)? as usize;
    if num_dd <= IMAGE_DIRECTORY_ENTRY_TLS {
        return None;
    }

    let tls_dd = opt.checked_add(0x70 + IMAGE_DIRECTORY_ENTRY_TLS * 8)?;
    let tls_rva = read_image_u32(image_base, image_size, tls_dd)? as usize;
    let tls_size = read_image_u32(image_base, image_size, tls_dd.checked_add(4)?)? as usize;
    if tls_rva == 0 || tls_size < core::mem::size_of::<ImageTlsDirectory64>() {
        return None;
    }

    let tls_dir_va = image_base.checked_add(tls_rva)?;
    if !image_contains_range(
        image_base,
        image_size,
        tls_dir_va,
        core::mem::size_of::<ImageTlsDirectory64>(),
    ) {
        return None;
    }
    let tls_dir = unsafe { core::ptr::read(tls_dir_va as *const ImageTlsDirectory64) };

    let addr_of_index = tls_dir.address_of_index as usize;
    if !image_contains_range(
        image_base,
        image_size,
        addr_of_index,
        core::mem::size_of::<u32>(),
    ) {
        return None;
    }

    let raw_start = tls_dir.start_address_of_raw_data as usize;
    let raw_end = tls_dir.end_address_of_raw_data as usize;
    if raw_end < raw_start {
        return None;
    }
    let raw_len = raw_end - raw_start;
    if raw_len != 0 && !image_contains_range(image_base, image_size, raw_start, raw_len) {
        return None;
    }

    Some((tls_dir, addr_of_index))
}

// ========================================================================
// NtCreateSection
// ========================================================================

/// NtCreateSection ΓÇö create a section object from a file handle.
///
/// NT signature:
/// ```text
/// NTSTATUS NtCreateSection(
///     PHANDLE SectionHandle,               // r10 (out)
///     ACCESS_MASK DesiredAccess,            // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes,  // r8
///     PLARGE_INTEGER MaximumSize,           // r9
///     ULONG SectionPageProtection,         // [rsp+0x28]
///     ULONG AllocationAttributes,          // [rsp+0x30]
///     HANDLE FileHandle                    // [rsp+0x38]
/// );
/// ```
///
/// For SEC_IMAGE sections, we read the PE data from the file handle,
/// parse it, and store the parsed info in a Section handle.
pub(crate) fn nt_create_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
    shared: &crate::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle_ptr = args.arg0;
    let _desired_access = args.arg1 as u32;
    let _obj_attr_ptr = args.arg2;
    let _max_size_ptr = args.arg3;

    // Stack arguments.
    let _page_protection = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
    let alloc_attributes = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };
    let file_handle = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };

    if section_handle_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let is_image = alloc_attributes & SEC_IMAGE != 0;

    if !is_image {
        // Non-image (data) section ΓÇö anonymous shared memory.
        // Read MaximumSize from r9.
        let max_size = if _max_size_ptr != 0 {
            (unsafe { core::ptr::read(_max_size_ptr as *const i64) }) as u64
        } else {
            0x10000 // default 64KB
        };

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtCreateSection data (alloc_attrs=0x{alloc_attributes:X}, size=0x{max_size:X})\n",
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }

        let handle = handles.insert(NtObject::DataSection { max_size });
        unsafe {
            core::ptr::write(section_handle_ptr as *mut u32, handle);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // SEC_IMAGE: read PE data from the file handle.
    let Some(pe_data) = read_pe_from_handle(handles, file_handle, shared) else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtCreateSection SEC_IMAGE ΓÇö invalid file handle 0x{file_handle:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    // Parse the PE.
    let parsed = match PeParsedFile::parse(&pe_data) {
        Ok(p) => p,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtCreateSection SEC_IMAGE ΓÇö PE parse error: {e:?}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        }
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtCreateSection SEC_IMAGE ok ΓÇö size_of_image=0x{:X}, base=0x{:X}, is_dll={}\n",
            parsed.size_of_image,
            parsed.image_base,
            parsed.is_dll,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    let handle = handles.insert(NtObject::Section {
        pe_data: Arc::new(pe_data),
        image_size: parsed.size_of_image,
        image_base: parsed.image_base,
        entry_point: parsed.entry_point,
        section_alignment: parsed.section_alignment,
        is_dll: parsed.is_dll,
    });

    unsafe {
        core::ptr::write(section_handle_ptr as *mut u32, handle);
    }
    NtStatus::STATUS_SUCCESS
}

/// Read the full PE data from a file handle (VFS-backed).
fn read_pe_from_handle(
    handles: &HandleTable,
    file_handle: u32,
    shared: &crate::NtSharedState,
) -> Option<Vec<u8>> {
    match handles.get(file_handle)? {
        NtObject::File { raw_fd, .. } => {
            // Read from VFS.
            let fs = shared.fs.get()?;
            let typed_fd = {
                let rds = shared.raw_fds.lock();
                rds.fd_from_raw_integer::<crate::NtFS>(*raw_fd).ok()?
            };
            // Get file size via fd_file_status, then read the entire file.
            use litebox::fs::FileSystem as _;
            let status = fs.fd_file_status(&typed_fd).ok()?;
            let size = status.size;
            if size == 0 || size > 256 * 1024 * 1024 {
                return None;
            }
            let mut buf = alloc::vec![0u8; size];
            let mut offset = 0usize;
            while offset < size {
                let bytes_read = fs.read(&typed_fd, &mut buf[offset..], Some(offset)).ok()?;
                if bytes_read == 0 {
                    return None;
                }
                offset = offset.checked_add(bytes_read)?;
            }
            Some(buf)
        }
        _ => None,
    }
}

// ========================================================================
// NtMapViewOfSection
// ========================================================================

/// NtMapViewOfSection ΓÇö map a section into the guest address space.
///
/// NT signature:
/// ```text
/// NTSTATUS NtMapViewOfSection(
///     HANDLE SectionHandle,         // r10
///     HANDLE ProcessHandle,         // rdx
///     PVOID *BaseAddress,           // r8  (in/out)
///     ULONG_PTR ZeroBits,           // r9
///     SIZE_T CommitSize,            // [rsp+0x28]
///     PLARGE_INTEGER SectionOffset, // [rsp+0x30]
///     PSIZE_T ViewSize,             // [rsp+0x38]
///     ULONG InheritDisposition,     // [rsp+0x40]
///     ULONG AllocationType,         // [rsp+0x48]
///     ULONG Win32Protect            // [rsp+0x50]
/// );
/// ```
///
/// For SEC_IMAGE sections, we map the PE into guest memory using the
/// page manager, applying relocations as needed.
pub(crate) fn nt_map_view_of_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
    shim_shared: &crate::NtSharedState,
    init_state: Option<&NtInitState>,
) -> NtStatus {
    let process_state = &shim_shared.process_state;
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle = args.arg0 as u32;
    let _process_handle = args.arg1; // should be NtCurrentProcess (-1)
    let base_addr_ptr = args.arg2;
    let _zero_bits = args.arg3;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection args: section=0x{:X} process=0x{:X} base_ptr=0x{:X} zero_bits=0x{:X} rsp=0x{:X}\n",
            section_handle,
            _process_handle,
            base_addr_ptr,
            _zero_bits,
            ctx.regs.rsp,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    // Stack arguments.
    let _commit_size = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let _section_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let view_size_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const usize) };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection stack: commit=0x{_commit_size:X} offset_ptr=0x{_section_offset_ptr:X} view_size_ptr=0x{view_size_ptr:X}\n",
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if base_addr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Determine section type.
    enum SectionType {
        Image {
            pe_data: Arc<Vec<u8>>,
            image_size: u32,
            image_base: u64,
        },
        Data {
            max_size: u64,
        },
    }

    let section_type = match handles.get(section_handle) {
        Some(NtObject::Section {
            pe_data,
            image_size,
            image_base,
            ..
        }) => SectionType::Image {
            pe_data: pe_data.clone(),
            image_size: *image_size,
            image_base: *image_base,
        },
        Some(NtObject::DataSection { max_size }) => SectionType::Data {
            max_size: *max_size,
        },
        _ => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtMapViewOfSection ΓÇö invalid section handle 0x{section_handle:X}\n",
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            return NtStatus::STATUS_INVALID_HANDLE;
        }
    };

    match section_type {
        SectionType::Data { max_size } => {
            map_data_section(ctx, process_state, base_addr_ptr, view_size_ptr, max_size)
        }
        SectionType::Image {
            pe_data,
            image_size,
            image_base: preferred_base,
        } => map_image_section(
            ctx,
            shim_shared,
            process_state,
            init_state,
            base_addr_ptr,
            view_size_ptr,
            &pe_data,
            image_size,
            preferred_base,
        ),
    }
}

/// Map a data section (anonymous shared memory) into guest address space.
fn map_data_section(
    ctx: &mut super::super::ExecutionContext,
    process_state: &Arc<NtProcessState>,
    base_addr_ptr: usize,
    view_size_ptr: usize,
    max_size: u64,
) -> NtStatus {
    let suggested_base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let view_size = if view_size_ptr != 0 {
        let vs = unsafe { core::ptr::read(view_size_ptr as *const usize) };
        if vs != 0 { vs } else { max_size as usize }
    } else {
        max_size as usize
    };

    let aligned_size = (view_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if aligned_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(aligned_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    let suggested = if suggested_base != 0 {
        NonZeroAddress::<PAGE_SIZE>::new(suggested_base)
    } else {
        None
    };

    let flags = if suggested.is_some() {
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
    } else {
        CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
    };

    let result = unsafe {
        process_state
            .pm
            .create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
    };

    match result {
        Ok(ptr) => {
            use litebox::platform::RawConstPointer as _;
            let mapped_addr = ptr.as_usize();

            unsafe {
                core::ptr::write(base_addr_ptr as *mut usize, mapped_addr);
            }
            if view_size_ptr != 0 {
                unsafe {
                    core::ptr::write(view_size_ptr as *mut usize, aligned_size);
                }
            }

            process_state.track_section_view(mapped_addr, aligned_size);

            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtMapViewOfSection data at 0x{mapped_addr:X} (size=0x{aligned_size:X})\n",
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }

            NtStatus::STATUS_SUCCESS
        }
        Err(_) => NtStatus::STATUS_NO_MEMORY,
    }
}

/// Map an image section (SEC_IMAGE PE) into guest address space.
fn map_image_section(
    ctx: &mut super::super::ExecutionContext,
    shim_shared: &crate::NtSharedState,
    process_state: &Arc<NtProcessState>,
    init_state: Option<&NtInitState>,
    base_addr_ptr: usize,
    view_size_ptr: usize,
    pe_data: &[u8],
    image_size: u32,
    preferred_base: u64,
) -> NtStatus {
    // Re-parse the PE (lightweight ΓÇö just reads headers).
    let Ok(parsed) = PeParsedFile::parse(pe_data) else {
        return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
    };

    // Determine load address.
    let suggested_base = unsafe { core::ptr::read(base_addr_ptr as *const usize) };
    let preferred = if suggested_base != 0 {
        suggested_base
    } else {
        preferred_base as usize
    };

    let aligned_size = (image_size as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut mapper = PmMapper {
        pm: &process_state.pm,
    };

    // Windows requires PE images to be mapped at allocation-granularity-
    // aligned addresses (64 KB). Try the preferred address first, then
    // fall back to a 64 KB-aligned system-chosen address.
    const ALLOC_GRANULARITY: usize = 0x10000; // 64 KB

    let load_base = if mapper.pre_reserve(preferred, aligned_size).is_ok() {
        preferred
    } else {
        // Over-allocate to guarantee a 64 KB-aligned range within the
        // allocation, then trim the leading/trailing excess.
        //
        // We must NOT free-then-re-allocate: between the free and the
        // re-allocation, PM considers the VA range available and other
        // allocations (e.g. heap MEM_RESERVE) could claim overlapping
        // addresses.  Instead, we keep the over-allocation intact, find
        // the aligned base within it, and trim only the excess pages at
        // the edges.  This mirrors how the real Windows kernel uses
        // placeholders (MEM_RESERVE_PLACEHOLDER / MEM_REPLACE_PLACEHOLDER)
        // to hold VA during section mapping without ever releasing it.
        let over_size = aligned_size + ALLOC_GRANULARITY - PAGE_SIZE;
        let Some(over_nz) = NonZeroPageSize::<PAGE_SIZE>::new(over_size) else {
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        };
        let flags = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        let over_ptr = match unsafe {
            process_state
                .pm
                .create_writable_pages(None, over_nz, flags, |_| Ok(0))
        } {
            Ok(ptr) => ptr,
            Err(_) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtMapViewOfSection — \
                             pre_reserve(0x{preferred:X}, 0x{aligned_size:X}) and fallback alloc both failed\n",
                    ));
                }
                return NtStatus::STATUS_CONFLICTING_ADDRESSES;
            }
        };
        let over_base = {
            use litebox::platform::RawConstPointer as _;
            over_ptr.as_usize()
        };
        let aligned_base = (over_base + ALLOC_GRANULARITY - 1) & !(ALLOC_GRANULARITY - 1);

        // Trim leading excess (pages before the aligned base).
        let leading = aligned_base - over_base;
        if leading > 0 {
            unsafe {
                let _ = process_state.pm.remove_pages(over_ptr, leading);
            }
        }
        // Trim trailing excess (pages after the image end).
        let trailing = over_size - leading - aligned_size;
        if trailing > 0 {
            let trail_ptr = {
                use litebox::platform::RawConstPointer as _;
                <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                    aligned_base + aligned_size,
                )
            };
            unsafe {
                let _ = process_state.pm.remove_pages(trail_ptr, trailing);
            }
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtMapViewOfSection — fallback alloc: over=0x{over_base:X}+0x{over_size:X}, \
                 aligned=0x{aligned_base:X}+0x{aligned_size:X}, trimmed lead=0x{leading:X} trail=0x{trailing:X}\n",
            ));
        }

        aligned_base
    };

    // Apply base relocations ourselves. The real Windows kernel applies
    // relocations inside NtMapViewOfSection for SEC_IMAGE sections and
    // ntdll trusts that the image is already relocated. If we skip this,
    // all absolute pointers (including TLS directory entries) would still
    // reference the preferred base address, causing crashes.
    let load_info = match litebox_common_windows::pe_loader::load_pe(
        &parsed,
        pe_data,
        load_base,
        &mut mapper,
    ) {
        Ok(info) => info,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!("NT shim: NtMapViewOfSection ΓÇö load_pe failed: {e}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        }
    };

    // Patch the in-memory PE header's ImageBase to match the actual load
    // address.  We already applied relocations in load_pe, but ntdll will
    // ALSO apply relocations when it sees STATUS_IMAGE_NOT_AT_BASE.
    // By setting ImageBase = actual load address, ntdll computes delta = 0
    // and its relocation pass becomes a no-op, preventing double-relocation
    // corruption.
    if load_info.image_base != preferred_base as usize {
        unsafe {
            let pe_sig_off =
                core::ptr::read((load_info.image_base as *const u32).byte_add(0x3C)) as usize;
            let opt_hdr = load_info.image_base + pe_sig_off + 0x18;
            let image_base_ptr = (opt_hdr + 0x18) as *mut u64;
            core::ptr::write(image_base_ptr, load_info.image_base as u64);
        }
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtMapViewOfSection mapped at 0x{:X} (size=0x{:X}, entry=0x{:X})\n",
            load_info.image_base,
            load_info.image_size,
            load_info.entry_point,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        // Log TLS directory info for this PE if present
        use litebox_common_windows::pe::{IMAGE_DIRECTORY_ENTRY_TLS, ImageTlsDirectory64};
        if let Some(tls_dd) = parsed.data_directory(IMAGE_DIRECTORY_ENTRY_TLS) {
            let tls_rva = tls_dd.virtual_address as usize;
            let tls_va = load_info.image_base + tls_rva;
            let tls_dir = unsafe { core::ptr::read(tls_va as *const ImageTlsDirectory64) };
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "  TLS dir at 0x{:X} (rva=0x{:X}): start=0x{:X} end=0x{:X} \
                 addr_of_index=0x{:X} addr_of_callbacks=0x{:X} zero_fill=0x{:X}\n",
                tls_va,
                tls_rva,
                tls_dir.start_address_of_raw_data,
                tls_dir.end_address_of_raw_data,
                tls_dir.address_of_index,
                tls_dir.address_of_callbacks,
                tls_dir.size_of_zero_fill,
            ));
            // Check if address_of_index is within this image (pre-relocation check)
            let pref = preferred_base as usize;
            let in_preferred = (tls_dir.address_of_index as usize) >= pref
                && (tls_dir.address_of_index as usize) < pref + load_info.image_size;
            let in_actual = (tls_dir.address_of_index as usize) >= load_info.image_base
                && (tls_dir.address_of_index as usize)
                    < load_info.image_base + load_info.image_size;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "  TLS addr_of_index: in_preferred_range={} in_actual_range={} \
                 (preferred=0x{:X} actual=0x{:X})\n",
                in_preferred,
                in_actual,
                pref,
                load_info.image_base,
            ));
        }
    }

    unsafe {
        core::ptr::write(base_addr_ptr as *mut usize, load_info.image_base);
    }
    if view_size_ptr != 0 {
        unsafe {
            core::ptr::write(view_size_ptr as *mut usize, load_info.image_size);
        }
    }

    // Track this image mapping so NtQueryVirtualMemory returns MEM_IMAGE type.
    process_state.track_image_mapping(load_info.image_base, load_info.image_size);

    backfill_static_tls(shim_shared, init_state, &parsed, load_info.image_base);

    // ── Neutralise Win32k syscall stubs (win32u.dll / gdi32full.dll) ──
    //
    // Only ntdll.dll has its syscall stubs rewritten to go through the
    // sandbox trampoline.  Other DLLs such as win32u.dll contain stubs
    // for Win32k system calls (window manager, GDI) that would execute
    // real `syscall` instructions and reach the host kernel's win32k
    // driver.  This is both unnecessary (console programs don't use
    // Win32k) and actively harmful: the host kernel may convert the
    // thread to a "GUI thread", dispatch user-mode callbacks, or
    // corrupt sandbox-internal state.
    //
    // We detect these stubs by the standard Windows syscall stub
    // pattern (`mov r10,rcx; mov eax,<nr>; … syscall; ret`) with
    // syscall numbers ≥ 0x1000 (the Win32k range) and patch each
    // stub to immediately return STATUS_NOT_IMPLEMENTED (0xC0000002).
    // This tells the calling DLL (user32, gdi32full, etc.) that
    // Win32k services are unavailable, letting it fall back to its
    // "no Win32 subsystem" code path gracefully.
    patch_win32k_stubs(
        load_info.image_base,
        load_info.image_size,
        &process_state.pm,
        process_state.trampoline_code_va(),
    );

    // ── Neutralise __fastfail (int 0x29) in all loaded DLLs ──
    //
    // __fastfail (CD 29) is a software interrupt that bypasses ALL
    // user-mode exception handlers (VEH, SEH, UEF) and directly
    // terminates the process.  The ntdll rewriter already patches
    // ntdll's __fastfail sites.  We must also patch DLLs loaded by
    // ntdll (kernelbase, kernel32, ucrtbase, etc.) to prevent them
    // from killing the host process on stack cookie failures, range
    // check failures, or other __fastfail scenarios.
    //
    // Patch: CD 29 → EB 00 (jmp +0, two-byte NOP).  This makes
    // __fastfail a no-op; the code after it (typically a `ret`)
    // executes normally.
    patch_fastfail(&parsed, load_info.image_base, &process_state.pm);

    // ── Patch gdi32full.dll: set gbFirst = 0 ──
    //
    // gdi32full!GdiProcessSetup checks a global `gbFirst` variable.
    // When gbFirst == 1 (the initial file value), GdiProcessSetup takes
    // the full GDI kernel initialization path, which requires a real
    // Win32k kernel and always fails in our sandbox.  When gbFirst == 0,
    // it takes a fast shortcut that reads PEB+0xF8 (GdiSharedHandleTable),
    // stores pointers in globals, and returns STATUS_SUCCESS.
    //
    // We detect gdi32full by reading the DLL name from its PE export
    // directory, then patch gbFirst at the known RVA from 1 to 0.
    patch_gdi32full_gbfirst(&parsed, pe_data, load_info.image_base, &process_state.pm);

    // ── Patch USER32.dll: force _UserClientDllInitialize past GdiDllInitialize check ──
    //
    // USER32's DllMain (_UserClientDllInitialize) calls GdiDllInitialize and
    // checks the return value: `test eax,eax; jns continue`.  In a sandbox
    // without Win32k, various GDI init sub-steps may fail, causing a negative
    // NTSTATUS return.  We patch the `jns` (opcode 0x79 0x07) at RVA 0x6E2AF
    // to an unconditional `jmp short` (0xEB 0x07), forcing the init to
    // continue regardless of the GdiDllInitialize return value.  Console
    // programs don't use GDI rendering, so this is safe.
    patch_user32_gdi_check(&parsed, pe_data, load_info.image_base, &process_state.pm);

    // ── Register in the inverted function table for SEH unwinding ──
    //
    // ntdll's SEH unwinding (RtlpxLookupFunctionTable) searches the
    // inverted function table for the .pdata (RUNTIME_FUNCTION array)
    // of each image on the stack.  Without an entry, unwinding fails
    // with STATUS_BAD_STACK.
    //
    // DISABLED: We now make ntdll's .mrdata section writable in the runner,
    // which allows ntdll's own RtlInsertInvertedFunctionTable to work.
    // Letting ntdll manage its own IFT is more correct than our interleaved
    // insertion (which could conflict with ntdll's sorted insertion logic).
    //
    // register_inverted_function_table_entry(
    //     &parsed,
    //     pe_data,
    //     load_info.image_base,
    //     load_info.image_size,
    //     process_state,
    // );

    // Return STATUS_IMAGE_NOT_AT_BASE when the image was loaded at a
    // different address than its preferred base. The loader uses this to
    // decide whether to apply relocations.
    if load_base == preferred_base as usize {
        NtStatus::STATUS_SUCCESS
    } else {
        NtStatus::STATUS_IMAGE_NOT_AT_BASE
    }
}

fn tls_alignment(characteristics: u32) -> usize {
    let nibble = (characteristics >> 20) & 0xF;
    let shift = if nibble == 0 { 0 } else { nibble - 1 };
    core::cmp::max(1usize << shift, 16)
}

fn next_static_tls_index(process_state: &NtProcessState) -> u32 {
    let mut max_idx = 0u32;
    for (base, size) in process_state.image_mappings_snapshot() {
        let Some((_tls_dir, addr_of_index)) = mapped_tls_directory(base, size) else {
            continue;
        };
        let idx = unsafe { core::ptr::read(addr_of_index as *const u32) };
        max_idx = max_idx.max(idx);
    }
    core::cmp::max(max_idx.saturating_add(1), 1)
}

fn ensure_thread_tls_vector(
    shared: &crate::NtSharedState,
    teb_va: usize,
    required_slots: usize,
) -> usize {
    let process_state = &shared.process_state;
    let tls_vector_ptr = unsafe {
        core::ptr::read((teb_va + crate::peb_teb::teb_offsets::TLS_POINTER) as *const usize)
    };
    if tls_vector_ptr != 0 {
        let known_slots = known_tls_vector_slots(shared, teb_va);
        if required_slots <= known_slots {
            return tls_vector_ptr;
        }

        let new_slots = required_slots.max(known_slots);
        let new_vec_va = process_state.alloc_rw_bytes(new_slots * 8);
        if new_vec_va == 0 {
            return 0;
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                tls_vector_ptr as *const u8,
                new_vec_va as *mut u8,
                known_slots * 8,
            );
            core::ptr::write(
                (teb_va + crate::peb_teb::teb_offsets::TLS_POINTER) as *mut usize,
                new_vec_va,
            );
        }
        if let Some(old_vector) =
            replace_thread_tls_vector_allocation(shared, teb_va, new_vec_va, new_slots, true)
        {
            free_tls_allocation(shared, old_vector);
        }
        return new_vec_va;
    }

    let slot_count = core::cmp::max(required_slots, MIN_TLS_VECTOR_SLOTS);
    let vec_va = process_state.alloc_rw_bytes(slot_count * 8);
    if vec_va != 0 {
        unsafe {
            core::ptr::write(
                (teb_va + crate::peb_teb::teb_offsets::TLS_POINTER) as *mut usize,
                vec_va,
            );
        }
        let _ = replace_thread_tls_vector_allocation(shared, teb_va, vec_va, slot_count, true);
    }
    vec_va
}

fn backfill_static_tls_for_mapped_image(
    shared: &crate::NtSharedState,
    teb_va: usize,
    image_base: usize,
    image_size: usize,
) -> Option<u32> {
    if teb_va == 0 {
        return None;
    }
    let (tls_dir, addr_of_index) = mapped_tls_directory(image_base, image_size)?;

    let mut tls_index = unsafe { core::ptr::read(addr_of_index as *const u32) };
    if tls_index == 0 {
        tls_index = next_static_tls_index(&shared.process_state);
        unsafe {
            core::ptr::write(addr_of_index as *mut u32, tls_index);
        }
    }

    let tls_vector = ensure_thread_tls_vector(shared, teb_va, tls_index as usize + 1);
    if tls_vector == 0 {
        return None;
    }

    let slot_addr = tls_vector + tls_index as usize * 8;
    let existing = unsafe { core::ptr::read(slot_addr as *const usize) };
    if existing != 0 {
        return Some(tls_index);
    }

    let raw_size = (tls_dir.end_address_of_raw_data as usize)
        .saturating_sub(tls_dir.start_address_of_raw_data as usize);
    let zero_fill = tls_dir.size_of_zero_fill as usize;
    let align = tls_alignment(tls_dir.characteristics);
    let total = raw_size.saturating_add(zero_fill).saturating_add(align);
    let block_base = shared.process_state.alloc_rw_bytes(total.max(16));
    if block_base == 0 {
        return None;
    }

    let aligned = (block_base + align - 1) & !(align - 1);
    if raw_size != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(
                tls_dir.start_address_of_raw_data as *const u8,
                aligned as *mut u8,
                raw_size,
            );
        }
    }
    if zero_fill != 0 {
        unsafe {
            core::ptr::write_bytes((aligned + raw_size) as *mut u8, 0, zero_fill);
        }
    }
    unsafe {
        core::ptr::write(slot_addr as *mut usize, aligned);
    }
    push_thread_tls_block_allocation(shared, teb_va, block_base, total.max(16));

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "  [TLS-backfill] base=0x{image_base:X} idx={} vec=0x{tls_vector:X} slot=0x{:X} data=0x{aligned:X} raw=0x{:X} zero=0x{:X}\n",
            tls_index,
            slot_addr,
            raw_size,
            zero_fill,
        ));
    }

    Some(tls_index)
}

pub(crate) fn initialize_static_tls_for_teb(shared: &crate::NtSharedState, teb_va: usize) {
    for (base, size) in shared.process_state.image_mappings_snapshot() {
        let _ = backfill_static_tls_for_mapped_image(shared, teb_va, base, size);
    }
}

fn backfill_static_tls(
    shared: &crate::NtSharedState,
    init_state: Option<&NtInitState>,
    parsed: &PeParsedFile,
    image_base: usize,
) {
    let Some(init) = init_state else {
        return;
    };

    if parsed
        .data_directory(litebox_common_windows::pe::IMAGE_DIRECTORY_ENTRY_TLS)
        .is_none()
    {
        return;
    }

    let teb_va = init.teb_va;
    let Some(tls_index) = backfill_static_tls_for_mapped_image(
        shared,
        teb_va,
        image_base,
        parsed.size_of_image as usize,
    ) else {
        return;
    };

    if let Some(ntdll_base) = init
        .module_bases
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case("ntdll.dll"))
        .map(|m| m.base_address)
    {
        let tls_bitmap_size = ntdll_base + 0x1D2720;
        let current = unsafe { core::ptr::read(tls_bitmap_size as *const u32) };
        if current <= tls_index {
            unsafe {
                core::ptr::write(tls_bitmap_size as *mut u32, tls_index + 1);
            }
        }
    }
}

/// Unmap a previously mapped section view from the guest address space.
///
/// If the base address corresponds to a tracked SEC_IMAGE mapping, the
/// pages are removed from the page manager and the tracking entry is
/// deleted.  Otherwise we return STATUS_NOT_MAPPED_VIEW.
pub fn nt_unmap_view_of_section(process_state: &NtProcessState, base_address: usize) -> NtStatus {
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUnmapViewOfSection base=0x{base_address:X}\n",
        ));
    }

    // Look up the address in our tracked image mappings.
    if let Some((mapped_base, size)) = process_state.untrack_image_mapping(base_address) {
        // Remove the pages from the page manager.
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_base);
        unsafe {
            let _ = process_state.pm.remove_pages(ptr, size);
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — unmapped image at 0x{mapped_base:X}+0x{size:X}\n",
            ));
        }

        NtStatus::STATUS_SUCCESS
    } else if let Some((mapped_base, size)) = process_state.untrack_section_view(base_address) {
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(mapped_base);
        unsafe {
            let _ = process_state.pm.remove_pages(ptr, size);
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — unmapped section view at 0x{mapped_base:X}+0x{size:X}\n",
            ));
        }

        NtStatus::STATUS_SUCCESS
    } else {
        // Not a tracked image mapping — still return success since the
        // caller may be unmapping a data section or a mapping we didn't
        // track (e.g., NLS data from NtMapViewOfSection for non-SEC_IMAGE
        // sections).  Returning an error here could confuse ntdll's loader.
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtUnmapViewOfSection — base 0x{base_address:X} not tracked, returning SUCCESS\n",
            ));
        }
        NtStatus::STATUS_SUCCESS
    }
}

/// Scan a freshly-mapped PE image for Win32k syscall stubs and rewrite
/// each one to jump through the sandbox trampoline.
///
/// A Win32k stub has the same layout as an ntdll stub:
///
/// ```text
/// +00: 4C 8B D1              mov  r10, rcx
/// +03: B8 xx xx xx xx        mov  eax, <syscall_nr>     (nr ≥ 0x1000)
/// +08: F6 04 25 08 03 FE 7F  test byte [0x7FFE0308], 1
/// +0F: 01
/// +10: 75 03                 jne  +3
/// +12: 0F 05                 syscall
/// +14: C3                    ret
/// ```
///
/// We preserve the first 16 bytes (which set up r10 and eax) and overwrite
/// bytes +10..+1E with an indirect JMP to the trampoline:
///
/// ```text
/// +10: FF 25 00 00 00 00     jmp  [rip+0]     (6 bytes)
/// +16: <8-byte trampoline_code_va>             (absolute address)
/// ```
///
/// This routes win32k syscalls through the same trampoline as ntdll stubs,
/// allowing the shim to dispatch them (or return STATUS_NOT_IMPLEMENTED).
fn patch_win32k_stubs(
    image_base: usize,
    image_size: usize,
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    trampoline_code_va: usize,
) {
    // Walk the mapped image looking for the syscall stub prefix.
    // The prefix is: 4C 8B D1 B8 xx xx xx xx (8 bytes).
    // We require syscall_nr >= 0x1000 to only target Win32k stubs.
    const STUB_LEN: usize = 0x20; // 32-byte aligned stubs
    const PREFIX: [u8; 3] = [0x4C, 0x8B, 0xD1]; // mov r10, rcx
    const SYSCALL_BYTES: [u8; 2] = [0x0F, 0x05]; // syscall

    // Replacement at offset +0x10: JMP [rip+0] followed by 8-byte address.
    // FF 25 00 00 00 00 = jmp qword ptr [rip+0]
    const JMP_INDIRECT: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    let tramp_addr_bytes = (trampoline_code_va as u64).to_le_bytes();

    if trampoline_code_va == 0 {
        // Trampoline not set up yet — fall back to the old behavior of
        // returning STATUS_NOT_IMPLEMENTED so we don't crash.
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(
                "NT shim: WARNING: trampoline_code_va is 0, skipping win32k stub patching\n",
            );
        }
        return;
    }

    let end = image_base + image_size;
    let mut patched = 0u32;
    let mut pos = image_base;

    while pos + STUB_LEN <= end {
        // Safety: the image was just mapped, so these addresses are valid.
        let bytes = unsafe { core::slice::from_raw_parts(pos as *const u8, STUB_LEN) };

        // Check prefix: mov r10, rcx; mov eax, <nr>
        if bytes[0..3] == PREFIX && bytes[3] == 0xB8 {
            let nr = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

            // Only patch Win32k stubs (syscall numbers >= 0x1000).
            if nr >= 0x1000 {
                // Verify the stub contains `syscall` somewhere in the expected range.
                let has_syscall = (8..STUB_LEN - 1)
                    .any(|i| bytes[i] == SYSCALL_BYTES[0] && bytes[i + 1] == SYSCALL_BYTES[1]);

                if has_syscall {
                    // Make the page writable so we can patch.
                    let page_addr = pos & !(PAGE_SIZE - 1);
                    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
                    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                        page_addr,
                    );
                    let _ = unsafe { pm.make_pages_writable(ptr, PAGE_SIZE) };

                    // If the patch straddles a page boundary, make the next page
                    // writable too (patch spans offset +0x10 to +0x1D = 14 bytes).
                    let patch_end_page = (pos + 0x1D) & !(PAGE_SIZE - 1);
                    if patch_end_page != page_addr {
                        let next_ptr =
                            <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                                patch_end_page,
                            );
                        let _ = unsafe { pm.make_pages_writable(next_ptr, PAGE_SIZE) };
                    }

                    // Write JMP [rip+0] at offset +0x10.
                    let patch_base = pos + 0x10;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            JMP_INDIRECT.as_ptr(),
                            patch_base as *mut u8,
                            JMP_INDIRECT.len(),
                        );
                        // Write the 8-byte trampoline address at offset +0x16.
                        core::ptr::copy_nonoverlapping(
                            tramp_addr_bytes.as_ptr(),
                            (patch_base + 6) as *mut u8,
                            8,
                        );
                    }
                    patched += 1;
                    pos += 0x20; // stubs are typically 32-byte aligned
                    continue;
                }
            }
        }

        pos += 1;
    }

    if patched > 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: patched {patched} Win32k stubs at 0x{image_base:X} → trampoline JMP\n",
            ));
        }
        let _ = patched;
    }
}

/// Scan the executable sections of a freshly-mapped PE image for `int 0x29`
/// (__fastfail) instructions and replace each with `jmp +0` (EB 00), a
/// two-byte NOP.
///
/// __fastfail bypasses all user-mode exception handlers.  On a real
/// Windows system the kernel handles int 0x29 and terminates the process.
/// In the sandbox we don't intercept int 0x29, so it would reach the
/// host kernel and kill the host process.  Neutralising it lets the
/// code fall through to whatever comes after (usually a `ret`).
fn patch_fastfail(
    parsed: &PeParsedFile,
    image_base: usize,
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
) {
    let mut patched = 0u32;

    for section in &parsed.sections {
        if section.characteristics & section_chars::IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let exec_size = (section.virtual_size as usize).max(section.size_of_raw_data as usize);
        if exec_size < 2 {
            continue;
        }

        let mut pos = image_base + section.virtual_address as usize;
        let end = pos.saturating_add(exec_size);
        while pos + 2 <= end {
            // Safety: the image was just mapped into guest VA.
            let b0 = unsafe { core::ptr::read(pos as *const u8) };
            let b1 = unsafe { core::ptr::read((pos + 1) as *const u8) };

            if b0 == 0xCD && b1 == 0x29 {
                // Make the page writable so we can patch.
                let page_addr = pos & !(PAGE_SIZE - 1);
                use litebox::platform::{RawConstPointer as _, RawPointerProvider};
                let ptr =
                    <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(page_addr);
                let _ = unsafe { pm.make_pages_writable(ptr, PAGE_SIZE) };

                // Replace CD 29 (int 0x29) with EB 00 (jmp +0 = NOP).
                unsafe {
                    core::ptr::write(pos as *mut u8, 0xEB);
                    core::ptr::write((pos + 1) as *mut u8, 0x00);
                }
                patched += 1;
                pos += 2;
                continue;
            }

            pos += 1;
        }
    }

    if patched > 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: patched {patched} __fastfail sites at 0x{image_base:X}\n",
            ));
        }
        let _ = patched;
    }
}

/// Patch gdi32full.dll's `gbFirst` global from 1 to 0 after it is mapped.
///
/// `gbFirst` lives at a known RVA in gdi32full's `.data` section.  When it
/// is 1 (the on-disk default), `GdiProcessSetup` takes the full kernel GDI
/// init path that requires Win32k — which fails in a sandbox.  Setting it
/// to 0 makes `GdiProcessSetup` take the fast shortcut path that reads
/// `PEB+0xF8` (GdiSharedHandleTable) and returns `STATUS_SUCCESS`.
///
/// We identify gdi32full by reading the DLL name from the PE export
/// directory.  If the name doesn't match, or has no export directory, this
/// function is a no-op.
fn patch_gdi32full_gbfirst(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    image_base: usize,
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
) {
    const GDI32FULL_SUPPORTED_TIMESTAMP: u32 = 0x2106_886A;
    const GDI32FULL_SUPPORTED_SIZE: u32 = 0x0012_C000;
    // gbFirst RVA in gdi32full.dll (Windows 10 build 19041, x86_64).
    // Located in the .data section at RVA 0x10B474.
    const GBFIRST_RVA: usize = 0x10B474;

    // Read the DLL name from the PE export directory.
    let dll_name = match get_pe_export_dll_name(parsed, pe_data) {
        Some(name) => name,
        None => return,
    };

    if !dll_name.eq_ignore_ascii_case("gdi32full.dll") {
        return;
    }
    if parsed.file_header.time_date_stamp != GDI32FULL_SUPPORTED_TIMESTAMP
        || parsed.size_of_image != GDI32FULL_SUPPORTED_SIZE
    {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: skipping gdi32full patch for unsupported build ts=0x{:X} size=0x{:X}\n",
                parsed.file_header.time_date_stamp,
                parsed.size_of_image,
            ));
        }
        return;
    }

    // Verify that the RVA is within the image bounds.
    if GBFIRST_RVA >= parsed.size_of_image as usize {
        return;
    }

    let gbfirst_va = image_base + GBFIRST_RVA;

    // Read the current value.
    let current = unsafe { core::ptr::read(gbfirst_va as *const u8) };
    if current != 1 {
        // Already 0 or unexpected value — don't patch.
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: gdi32full gbFirst at 0x{gbfirst_va:X} already = {current} (not patching)\n",
            ));
        }
        return;
    }

    // Make the page writable and patch gbFirst from 1 to 0.
    let page_addr = gbfirst_va & !(PAGE_SIZE - 1);
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(page_addr);
    let _ = unsafe { pm.make_pages_writable(ptr, PAGE_SIZE) };

    unsafe {
        core::ptr::write(gbfirst_va as *mut u8, 0);
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: patched gdi32full gbFirst at 0x{gbfirst_va:X} (1 → 0)\n",
        ));
    }
}

/// Patch USER32.dll's `_UserClientDllInitialize` to always succeed, bypassing
/// the GdiDllInitialize return-value check.
///
/// `_UserClientDllInitialize` is USER32's DllMain.  Its return value is
/// computed from `ebx`:
///
///   ```asm
///   0x6E2A2:  mov  ebx, eax        ; save GdiDllInitialize return
///   0x6E2A4:  cmp  edi, 1
///   0x6E2A7:  jne  epilogue
///   0x6E2AD:  test eax, eax
///   0x6E2AF:  jns  +7              ; if non-negative → continue init
///   0x6E2B1:  xor  eax, eax        ; failure → eax = 0
///   0x6E2B3:  jmp  epilogue
///   0x6E2B8:  <continuation>       ; call InitProcessDpiAwareness etc.
///   ...
///   epilogue:
///   0x6E38C:  not  ebx             ; NTSTATUS→BOOL: negative→FALSE
///   0x6E38E:  shr  ebx, 0x1F
///   0x6E391:  mov  eax, ebx
///   ```
///
/// In the sandbox without Win32k, GdiDllInitialize may return a negative
/// NTSTATUS, which makes ebx negative → `not+shr` = 0 (FALSE).
///
/// We apply two patches:
///   1. `mov ebx, eax` (8B D8) → `xor ebx, ebx` (31 DB) at RVA 0x6E2A2
///      Forces ebx = 0 so the epilogue produces TRUE (1).
///   2. `jns +7` (79 07) → `jmp short +7` (EB 07) at RVA 0x6E2AF
///      Forces the full init path even if GdiDllInitialize failed.
///
/// Console programs don't use GDI rendering, so this is safe.
fn patch_user32_gdi_check(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    image_base: usize,
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
) {
    const USER32_SUPPORTED_TIMESTAMP: u32 = 0x881D_14CA;
    const USER32_SUPPORTED_SIZE: u32 = 0x001C_5000;
    const MOV_EBX_EAX_RVA: usize = 0x6E2A2;
    const JNS_RVA: usize = 0x6E2AF;

    let dll_name = match get_pe_export_dll_name(parsed, pe_data) {
        Some(name) => name,
        None => return,
    };

    if !dll_name.eq_ignore_ascii_case("user32.dll") {
        return;
    }
    if parsed.file_header.time_date_stamp != USER32_SUPPORTED_TIMESTAMP
        || parsed.size_of_image != USER32_SUPPORTED_SIZE
    {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: skipping USER32 patch for unsupported build ts=0x{:X} size=0x{:X}\n",
                parsed.file_header.time_date_stamp,
                parsed.size_of_image,
            ));
        }
        return;
    }

    if MOV_EBX_EAX_RVA + 2 > parsed.size_of_image as usize
        || JNS_RVA + 2 > parsed.size_of_image as usize
    {
        return;
    }

    let mov_va = image_base + MOV_EBX_EAX_RVA;
    let jns_va = image_base + JNS_RVA;

    // Verify expected instruction bytes before patching.
    let mov_b0 = unsafe { core::ptr::read(mov_va as *const u8) };
    let mov_b1 = unsafe { core::ptr::read((mov_va + 1) as *const u8) };
    let jns_b0 = unsafe { core::ptr::read(jns_va as *const u8) };
    let jns_b1 = unsafe { core::ptr::read((jns_va + 1) as *const u8) };

    if mov_b0 != 0x8B || mov_b1 != 0xD8 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: USER32 patch: unexpected bytes at 0x{mov_va:X}: {mov_b0:02X} {mov_b1:02X} (expected 8B D8)\n",
            ));
        }
        return;
    }
    if jns_b0 != 0x79 || jns_b1 != 0x07 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: USER32 patch: unexpected bytes at 0x{jns_va:X}: {jns_b0:02X} {jns_b1:02X} (expected 79 07)\n",
            ));
        }
        return;
    }

    // Make both pages writable (they're likely on the same page in .text).
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    let page_addr = mov_va & !(PAGE_SIZE - 1);
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(page_addr);
    let _ = unsafe { pm.make_pages_writable(ptr, PAGE_SIZE) };

    // If jns_va is on a different page, make that writable too.
    let jns_page = jns_va & !(PAGE_SIZE - 1);
    if jns_page != page_addr {
        let ptr2 = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(jns_page);
        let _ = unsafe { pm.make_pages_writable(ptr2, PAGE_SIZE) };
    }

    // Patch 1: mov ebx, eax (8B D8) → xor ebx, ebx (31 DB)
    unsafe {
        core::ptr::write(mov_va as *mut u8, 0x31);
        core::ptr::write((mov_va + 1) as *mut u8, 0xDB);
    }

    // Patch 2: jns +7 (79 07) → jmp short +7 (EB 07)
    unsafe {
        core::ptr::write(jns_va as *mut u8, 0xEB);
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: patched USER32 _UserClientDllInitialize: 0x{mov_va:X} (mov→xor ebx) + 0x{jns_va:X} (jns→jmp)\n",
        ));
    }
}

/// Register a loaded DLL in `KiUserInvertedFunctionTable` so that SEH
/// unwinding can find its `.pdata` (RUNTIME_FUNCTION array).
///
/// Table layout:
/// ```text
///   +0x00  u32  CurrentSize
///   +0x04  u32  MaximumSize  (512)
///   +0x08  u32  Epoch
///   +0x0C  u8   Overflow + 3 reserved
///   +0x10  Entry[0]:  { u64 ExcDir, u64 Base, u32 Size, u32 ExcSize }  (24 bytes)
///   +0x28  Entry[1]:
///   ...
/// ```
fn register_inverted_function_table_entry(
    parsed: &PeParsedFile,
    _pe_data: &[u8],
    image_base: usize,
    image_size: usize,
    process_state: &crate::NtProcessState,
) {
    let ift_va = process_state.inverted_function_table_va();
    if ift_va == 0 {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform()
                .debug_log_print("NT shim: IFT registration skipped (ift_va=0)\n");
        }
        return;
    }

    // IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
    let exc_dd = match parsed.data_directory(3) {
        Some(dd) if dd.virtual_address != 0 && dd.size != 0 => dd,
        _ => return, // No .pdata — nothing to register.
    };

    let exc_dir_va = image_base + exc_dd.virtual_address as usize;
    let exc_dir_size = exc_dd.size;

    // Read current entry count and max.
    // The IFT is in ntdll's .mrdata section which may be read-only.
    // Make the page writable before reading/writing.
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    let ift_page = ift_va & !(PAGE_SIZE - 1);
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(ift_page);
    // SAFETY: ift_page is within the mapped ntdll PE image in guest VA.
    let _ = unsafe { process_state.pm.make_pages_writable(ptr, PAGE_SIZE) };

    // SAFETY: ift_va points into committed guest memory (ntdll's .mrdata).
    let current_size = unsafe { core::ptr::read(ift_va as *const u32) };
    let max_size = unsafe { core::ptr::read((ift_va + 4) as *const u32) };

    if current_size >= max_size {
        return; // Table full.
    }

    // Each entry is 24 bytes, starting at offset 0x10.
    let entry_offset = 0x10 + (current_size as usize) * 24;
    let entry_va = ift_va + entry_offset;

    // Make sure the entry's page is writable too (may span pages).
    let entry_page = entry_va & !(PAGE_SIZE - 1);
    if entry_page != ift_page {
        let ptr2 = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(entry_page);
        let _ = unsafe { process_state.pm.make_pages_writable(ptr2, PAGE_SIZE) };
    }

    if current_size >= max_size {
        return; // Table full.
    }

    // Each entry is 24 bytes, starting at offset 0x10.
    let entry_offset = 0x10 + (current_size as usize) * 24;
    let entry_va = ift_va + entry_offset;

    // SAFETY: entry_va is within the table's allocated space.
    unsafe {
        // ExceptionDirectory (u64)
        (entry_va as *mut u64).write(exc_dir_va as u64);
        // ImageBase (u64)
        ((entry_va + 8) as *mut u64).write(image_base as u64);
        // ImageSize (u32)
        ((entry_va + 16) as *mut u32).write(image_size as u32);
        // ExceptionDirectorySize (u32)
        ((entry_va + 20) as *mut u32).write(exc_dir_size);
        // Increment CurrentSize.
        (ift_va as *mut u32).write(current_size + 1);
    }

    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: IFT entry {current_size}: ExcDir=0x{exc_dir_va:X} Base=0x{image_base:X} Size=0x{image_size:X} ExcSize=0x{exc_dir_size:X}\n"
        ));
    }
}

/// Extract the DLL name from a PE file's export directory.
///
/// Returns `None` if the PE has no export directory or the name RVA is
/// invalid.
fn get_pe_export_dll_name<'a>(parsed: &PeParsedFile, pe_data: &'a [u8]) -> Option<&'a str> {
    let dd = parsed.data_directory(0)?; // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    if dd.virtual_address == 0 || dd.size == 0 {
        return None;
    }

    let export_dir_offset = parsed.rva_to_file_offset(dd.virtual_address)?;

    // The DLL name RVA is at offset 12 in IMAGE_EXPORT_DIRECTORY
    // (characteristics:4 + time_date_stamp:4 + major:2 + minor:2 = 12).
    let name_rva_off = export_dir_offset + 12;
    let name_rva_bytes = pe_data.get(name_rva_off..name_rva_off + 4)?;
    let name_rva = u32::from_le_bytes(name_rva_bytes.try_into().ok()?);

    if name_rva == 0 {
        return None;
    }

    parsed.read_string_at_rva(pe_data, name_rva)
}
///
/// Pre-reserves the entire image range as writable pages, then copies
/// section data and adjusts per-section permissions ΓÇö same strategy
/// as the runner's `PmMapper`.
struct PmMapper<'a> {
    pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
}

impl PmMapper<'_> {
    fn pre_reserve(&self, va: usize, size: usize) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let addr = NonZeroAddress::<PAGE_SIZE>::new(va).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(aligned).ok_or(PeLoadError::MapFailed)?;
        // NOREPLACE: fail if any part of the range is already mapped, preventing
        // DLL loads from silently overwriting existing heap/loader allocations.
        let flags = CreatePagesFlags::FIXED_ADDR
            | CreatePagesFlags::NOREPLACE
            | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        unsafe {
            self.pm
                .create_writable_pages(Some(addr), page_size, flags, |_| Ok(0))
        }
        .map_err(|_| PeLoadError::MapFailed)?;
        Ok(())
    }
}

impl PeMemoryMapper for PmMapper<'_> {
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if aligned == 0 {
            return Ok(());
        }

        // Pages are already committed-writable from pre_reserve().
        // Copy section data.
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len());
            }
        }
        if data.len() < size {
            unsafe {
                core::ptr::write_bytes((va + data.len()) as *mut u8, 0, size - data.len());
            }
        }

        // Leave all pages WRITABLE — ntdll's loader will write relocation
        // fixups, then call NtProtectVirtualMemory to set final permissions.
        // This emulates the real Windows kernel's PAGE_WRITECOPY behavior
        // where all SEC_IMAGE pages start copy-on-write (effectively writable).
        let _ = perm; // permissions applied later by ntdll

        Ok(())
    }
}

// ========================================================================
// NtQuerySection
// ========================================================================

/// NtQuerySection ΓÇö query information about a section object.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQuerySection(
///     HANDLE SectionHandle,                  // r10
///     SECTION_INFORMATION_CLASS InfoClass,    // rdx
///     PVOID SectionInformation,              // r8 (out)
///     SIZE_T SectionInformationLength,        // r9
///     PSIZE_T ReturnLength                   // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_section(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let section_handle = args.arg0 as u32;
    let info_class = args.arg1 as u32;
    let buffer_ptr = args.arg2;
    let buffer_len = args.arg3;

    let return_length_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };

    let section = match handles.get(section_handle) {
        Some(NtObject::Section {
            image_size,
            image_base,
            entry_point,
            section_alignment,
            is_dll,
            pe_data,
        }) => (
            *image_size,
            *image_base,
            *entry_point,
            *section_alignment,
            *is_dll,
            pe_data.clone(),
        ),
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let (image_size, image_base, entry_point, section_alignment, is_dll, pe_data) = section;

    match info_class {
        // SectionBasicInformation (0)
        0 => {
            // SECTION_BASIC_INFORMATION { BaseAddress, Attributes, Size }
            #[repr(C)]
            struct SectionBasicInfo {
                base_address: usize,
                attributes: u32,
                _pad: u32,
                size: i64,
            }
            let size = core::mem::size_of::<SectionBasicInfo>();
            if buffer_len < size {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }
            let info = SectionBasicInfo {
                base_address: 0,
                attributes: SEC_IMAGE,
                _pad: 0,
                size: image_size as i64,
            };
            unsafe {
                core::ptr::write(buffer_ptr as *mut SectionBasicInfo, info);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut usize, size);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SectionImageInformation (1)
        1 => {
            // SECTION_IMAGE_INFORMATION ΓÇö ntdll needs this for DLL loading.
            #[repr(C)]
            struct SectionImageInfo {
                transfer_address: usize, // entry point VA
                zero_bits: u32,
                maximum_stack_size: usize,
                committed_stack_size: usize,
                sub_system: u32,
                minor_sub_system_version: u16,
                major_sub_system_version: u16,
                major_operating_system_version: u16,
                minor_operating_system_version: u16,
                image_characteristics: u16,
                dll_characteristics: u16,
                machine: u16,
                image_contains_code: u8,
                image_flags: u8,
                loader_flags: u32,
                image_file_size: u32,
                checksum: u32,
            }
            let size = core::mem::size_of::<SectionImageInfo>();
            if buffer_len < size {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }

            // Re-parse to get detailed info.
            let Ok(parsed) = PeParsedFile::parse(&pe_data) else {
                return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
            };

            let info = SectionImageInfo {
                transfer_address: image_base as usize + entry_point as usize,
                zero_bits: 0,
                maximum_stack_size: parsed.optional_header.size_of_stack_reserve as usize,
                committed_stack_size: parsed.optional_header.size_of_stack_commit as usize,
                sub_system: parsed.optional_header.subsystem as u32,
                minor_sub_system_version: parsed.optional_header.minor_subsystem_version,
                major_sub_system_version: parsed.optional_header.major_subsystem_version,
                major_operating_system_version: parsed.optional_header.major_os_version,
                minor_operating_system_version: parsed.optional_header.minor_os_version,
                image_characteristics: parsed.file_header.characteristics,
                dll_characteristics: parsed.optional_header.dll_characteristics,
                machine: parsed.file_header.machine,
                image_contains_code: 1,
                image_flags: if is_dll { 0x04 } else { 0x00 }, // IMAGE_FLAGS_IS_DLL
                loader_flags: 0,
                image_file_size: pe_data.len() as u32,
                checksum: parsed.optional_header.checksum,
            };
            unsafe {
                core::ptr::write(buffer_ptr as *mut SectionImageInfo, info);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut usize, size);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        other => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!("NT shim: NtQuerySection unhandled info class {other}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    }
}
