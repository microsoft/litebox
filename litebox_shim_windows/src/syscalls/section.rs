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
use litebox_common_windows::pe_loader::{PeLoadError, PeMemoryMapper, SectionPermissions};
use litebox_common_windows::pe_parser::PeParsedFile;

use crate::handle_table::{HandleTable, NtObject};
use crate::{NtProcessState, PAGE_SIZE, Platform};

use super::NtSyscallArgs;

/// SEC_IMAGE flag (0x01000000) ΓÇö indicates an image section.
const SEC_IMAGE: u32 = 0x0100_0000;

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
    let Some(pe_data) = read_pe_from_handle(handles, file_handle) else {
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

/// Read the full PE data from a file handle (MemoryFile or host File).
fn read_pe_from_handle(handles: &HandleTable, file_handle: u32) -> Option<Vec<u8>> {
    match handles.get(file_handle)? {
        NtObject::MemoryFile { data, .. } => Some((**data).clone()),
        NtObject::File { host_handle, .. } => {
            // Read the entire file from the host.
            read_entire_host_file(*host_handle)
        }
        _ => None,
    }
}

/// Read an entire file from a host Windows HANDLE.
#[cfg(target_os = "windows")]
fn read_entire_host_file(host_handle: usize) -> Option<Vec<u8>> {
    unsafe extern "system" {
        fn GetFileSizeEx(h: usize, size: *mut i64) -> i32;
        fn SetFilePointerEx(h: usize, pos: i64, new_pos: *mut i64, method: u32) -> i32;
        fn ReadFile(
            h: usize,
            buf: *mut u8,
            len: u32,
            bytes_read: *mut u32,
            overlapped: usize,
        ) -> i32;
    }

    let mut file_size: i64 = 0;
    if unsafe { GetFileSizeEx(host_handle, &mut file_size) } == 0 {
        return None;
    }
    if file_size <= 0 || file_size > 256 * 1024 * 1024 {
        // Sanity check: DLLs shouldn't be > 256MB.
        return None;
    }

    // Seek to beginning.
    unsafe {
        SetFilePointerEx(host_handle, 0, core::ptr::null_mut(), 0);
    }

    let mut buf = alloc::vec![0u8; file_size as usize];
    let mut total_read = 0usize;
    while total_read < buf.len() {
        let mut bytes_read: u32 = 0;
        let to_read = (buf.len() - total_read).min(u32::MAX as usize) as u32;
        let ok = unsafe {
            ReadFile(
                host_handle,
                buf[total_read..].as_mut_ptr(),
                to_read,
                &mut bytes_read,
                0,
            )
        };
        if ok == 0 || bytes_read == 0 {
            break;
        }
        total_read += bytes_read as usize;
    }

    if total_read == buf.len() {
        Some(buf)
    } else {
        // Partial read ΓÇö return what we got (PE parser will validate).
        buf.truncate(total_read);
        Some(buf)
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
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
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
            process_state,
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
    process_state: &Arc<NtProcessState>,
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

    // Try preferred address first, then fall back to system-chosen address.
    // DLLs typically have preferred bases outside our VA partition, so the
    // fallback is common. The PE relocation table handles rebasing.
    let load_base = if mapper.pre_reserve(preferred, aligned_size).is_ok() {
        preferred
    } else {
        // Let the page manager choose an available address.
        use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
        let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(aligned_size) else {
            return NtStatus::STATUS_INVALID_IMAGE_FORMAT;
        };
        let flags = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        match unsafe {
            process_state
                .pm
                .create_writable_pages(None, nz_size, flags, |_| Ok(0))
        } {
            Ok(ptr) => {
                use litebox::platform::RawConstPointer as _;
                ptr.as_usize()
            }
            Err(_) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtMapViewOfSection ΓÇö \
                             pre_reserve(0x{preferred:X}, 0x{aligned_size:X}) and fallback alloc both failed\n",
                    ));
                }
                return NtStatus::STATUS_CONFLICTING_ADDRESSES;
            }
        }
    };

    // Map without applying relocations ΓÇö the ntdll loader will handle
    // relocations itself when we return STATUS_IMAGE_NOT_AT_BASE.
    let load_info = match litebox_common_windows::pe_loader::load_pe_no_reloc(
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

    // Return STATUS_IMAGE_NOT_AT_BASE when the image was loaded at a
    // different address than its preferred base. The loader uses this to
    // decide whether to apply relocations.
    if load_base == preferred_base as usize {
        NtStatus::STATUS_SUCCESS
    } else {
        NtStatus::STATUS_IMAGE_NOT_AT_BASE
    }
}

/// Thin adapter implementing `PeMemoryMapper` using the page manager.
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
        let flags = CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
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

        // Adjust protection to match the section's intended permissions.
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(va);
        match perm {
            SectionPermissions::ReadExecute => unsafe {
                self.pm.make_pages_executable(ptr, aligned)
            },
            SectionPermissions::ReadOnly => unsafe { self.pm.make_pages_readable(ptr, aligned) },
            SectionPermissions::ReadWrite => {
                // Already writable from pre_reserve.
                Ok(())
            }
        }
        .map_err(|_| PeLoadError::MapFailed)?;

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
