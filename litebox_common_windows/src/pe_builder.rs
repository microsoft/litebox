// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Programmatic PE builder for generating stub DLLs.
//!
//! Produces minimal but valid PE/COFF DLLs as byte vectors. Each exported
//! syscall function is a trampoline stub that jumps to the platform's
//! `syscall_callback` via an indirect pointer at the start of `.text`:
//!
//! ```text
//! mov r10, rcx                   ; preserve first arg
//! mov eax, <NR>                  ; syscall number
//! lea rcx, [rip + <ret_point>]   ; return address → RCX
//! jmp qword [rip + <callback>]   ; → syscall_callback
//! ret                            ; reached after callback resumes
//! ```
//!
//! The first 8 bytes of `.text` hold the callback pointer, which the runner
//! pre-patches with the address of `syscall_callback` before loading the DLL.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_SIGNATURE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_SUBSYSTEM_WINDOWS_CUI, ImageBaseRelocation, ImageDataDirectory,
    ImageDosHeader, ImageExportDirectory, ImageFileHeader, ImageImportDescriptor,
    ImageOptionalHeader64, ImageSectionHeader, image_file_chars, section_chars,
};

/// Size of the data header reserved at the start of .text in stub DLLs.
///
/// Layout (16 bytes):
/// - `[0..8]`: callback pointer (address of `syscall_callback`)
/// - `[8..16]`: GS lookup table pointer (address of the host-owned table)
///
/// The GS lookup table maps guest GS base → host GS base. It is allocated
/// and owned by the platform (not in guest-writable memory). Each trampoline
/// reads the table pointer from here, then does a linear scan to find the
/// host GS base for the current thread's guest GS.
pub const TEXT_HEADER_SIZE: usize = 16;

/// RVA of the callback pointer within a stub DLL (offset 0 in .text).
pub const CALLBACK_PTR_RVA: u32 = 0x1000;

/// RVA of the GS lookup table pointer within a stub DLL (offset 8 in .text).
pub const GS_TABLE_PTR_RVA: u32 = 0x1008;

/// An export to include in the generated stub DLL.
#[derive(Clone, Debug)]
pub struct StubExport {
    /// Function name (e.g., "NtWriteFile").
    pub name: String,
    /// How this export's code should be generated.
    pub kind: StubExportKind,
}

/// The kind of code to generate for a stub export.
#[derive(Clone, Debug)]
pub enum StubExportKind {
    /// A syscall stub that jumps to the platform's `syscall_callback`.
    ///
    /// Generated code layout (60 bytes — see `emit_syscall_trampoline`):
    /// ```text
    /// mov r10, rcx                   ;  3 — save arg0
    /// mov eax, <NR>                  ;  5 — syscall number
    /// rdgsbase r11                   ;  5 — read guest GS
    /// mov rcx, [rip + gs_table_ptr]  ;  7 — load GS table pointer
    /// ; linear scan: find entry where guest_gs == r11
    /// cmp qword [rcx], 0            ;  4 — sentinel check
    /// je .miss                       ;  2 — empty slot → ud2
    /// cmp [rcx], r11                 ;  3 — match?
    /// je .found                      ;  2 — yes → load host_gs
    /// add rcx, 16                   ;  4 — next entry
    /// jmp .probe                    ;  2 — loop
    /// .found:
    /// mov rcx, [rcx + 8]            ;  4 — host_gs
    /// wrgsbase rcx                   ;  5 — restore host GS
    /// lea rcx, [rip + <ret>]        ;  7 — return address
    /// jmp qword [rip + callback]    ;  6 — jump to callback
    /// .miss:
    /// ud2                           ;  2 — hard fault
    /// ret                           ;  1 — (after callback resumes)
    /// ```
    SyscallTrampoline { syscall_nr: u32 },
    /// A stub that returns a fixed NTSTATUS immediately.
    ReturnStatus { status: i32 },
    /// Raw code bytes (pre-assembled).
    RawCode { code: Vec<u8> },
}

impl StubExport {
    /// Create a syscall trampoline stub.
    pub fn syscall_stub(name: &str, syscall_nr: u32) -> Self {
        Self {
            name: String::from(name),
            kind: StubExportKind::SyscallTrampoline { syscall_nr },
        }
    }

    /// Create a stub that just returns the given NTSTATUS.
    pub fn return_status(name: &str, status: i32) -> Self {
        Self {
            name: String::from(name),
            kind: StubExportKind::ReturnStatus { status },
        }
    }

    /// Create a stub with pre-assembled code.
    pub fn raw(name: &str, code: Vec<u8>) -> Self {
        Self {
            name: String::from(name),
            kind: StubExportKind::RawCode { code },
        }
    }

    /// GetLastError: `mov eax, dword gs:[0x68]; ret`
    ///
    /// Reads TEB.LastErrorValue directly via GS segment, matching real
    /// Windows. Works because GS points to the guest TEB during guest
    /// execution.
    pub fn get_last_error() -> Self {
        // 65 8B 04 25 68 00 00 00 = mov eax, dword ptr gs:[0x68]
        // C3                       = ret
        Self::raw(
            "GetLastError",
            vec![0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, 0xC3],
        )
    }

    /// SetLastError: `mov dword gs:[0x68], ecx; ret`
    ///
    /// Writes TEB.LastErrorValue. Arg is in rcx (Windows x64 calling
    /// convention: first integer arg in rcx).
    pub fn set_last_error() -> Self {
        // 65 89 0C 25 68 00 00 00 = mov dword ptr gs:[0x68], ecx
        // C3                       = ret
        Self::raw(
            "SetLastError",
            vec![0x65, 0x89, 0x0C, 0x25, 0x68, 0x00, 0x00, 0x00, 0xC3],
        )
    }

    /// Return a fixed value in EAX and set TEB.LastErrorValue to a specific
    /// error code. Useful for stubs that return FALSE and need a meaningful
    /// GetLastError() value for the caller's fallback logic.
    ///
    /// Generated code:
    /// ```text
    /// mov dword gs:[0x68], <error>   ; set LastError
    /// mov eax, <retval>              ; return value
    /// ret
    /// ```
    pub fn return_status_with_last_error(name: &str, retval: i32, last_error: u32) -> Self {
        let mut code = Vec::with_capacity(18);
        // mov dword ptr gs:[0x68], imm32
        code.extend_from_slice(&[0x65, 0xC7, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&last_error.to_le_bytes());
        // mov eax, imm32
        code.push(0xB8);
        code.extend_from_slice(&(retval as u32).to_le_bytes());
        // ret
        code.push(0xC3);
        Self::raw(name, code)
    }
}

/// Alignment helpers.
fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Build a minimal PE DLL with the given exports.
///
/// The produced DLL has:
/// - A DOS stub (minimal)
/// - PE headers
/// - `.text` section containing the export code
/// - `.edata` section containing the export directory
/// - `.reloc` section containing base relocation data
///
/// The DLL has no imports (it's self-contained).
///
/// `image_base` sets the preferred load address. Each stub DLL should use a
/// distinct base to avoid collisions (e.g., ntdll at 0x1800_0000_0000,
/// kernel32 at 0x1800_0001_0000, etc.). If the loader must rebase, the
/// `.reloc` section provides the necessary fixup metadata.
pub fn build_stub_dll(dll_name: &str, exports: &[StubExport], image_base: u64) -> Vec<u8> {
    let file_alignment: u32 = 0x200; // 512 bytes
    let section_alignment: u32 = 0x1000; // 4096 bytes

    // Sort exports by name (PE export table requires sorted names for binary search).
    let mut sorted_exports: Vec<(usize, &StubExport)> = exports.iter().enumerate().collect();
    sorted_exports.sort_by(|a, b| a.1.name.as_bytes().cmp(b.1.name.as_bytes()));

    // ---- Build .text section content (all function code) ----
    // Reserve the first 16 bytes for the data header:
    //   [0..8]  = callback pointer (patched before load)
    //   [8..16] = host GS base     (patched before load)
    let mut text_data = vec![0u8; TEXT_HEADER_SIZE];

    // Map from original export index → offset within .text
    let mut code_offsets: Vec<u32> = vec![0; exports.len()];
    for (i, export) in exports.iter().enumerate() {
        // Align each function to 16 bytes.
        while text_data.len() % 16 != 0 {
            text_data.push(0xCC); // INT3 padding
        }
        let stub_offset = text_data.len() as u32;
        code_offsets[i] = stub_offset;

        match &export.kind {
            StubExportKind::SyscallTrampoline { syscall_nr } => {
                // Offsets are relative to stub_offset.
                //
                //  0: mov r10, rcx                          — 3
                //  3: mov eax, <NR>                         — 5
                //  8: rdgsbase r11    (guest GS = TEB VA)   — 5
                // 13: mov rcx, [rip+disp] (GS table ptr)   — 7
                // 20: cmp [rcx], r11  (.probe)              — 3
                // 23: je .found (+12)                       — 2
                // 25: add rcx, 16                           — 4
                // 29: cmp qword [rcx], 0                    — 4
                // 33: jne .probe (-15)                      — 2
                // 35: ud2             (miss → crash)        — 2
                // 37: mov rcx, [rcx+8] (.found: host_gs)   — 4
                // 41: wrgsbase rcx                          — 5
                // 46: lea rcx, [rip+6] (return addr)        — 7
                // 53: jmp [rip+disp]   (callback)           — 6
                // 59: ret                                   — 1
                // Total: 60 bytes

                // Trampoline layout (60 bytes):
                //  0: mov r10, rcx                             — 3
                //  3: mov eax, imm32                           — 5
                //  8: rdgsbase r11                             — 5
                // 13: mov rcx, [rip+disp] (GS table ptr)      — 7
                // 20: cmp [rcx], r11  (.probe)                 — 3
                // 23: je .found (+12 → 37)                     — 2
                // 25: add rcx, 16                              — 4
                // 29: cmp qword [rcx], 0                       — 4
                // 33: jne .probe (-15 → 20)                    — 2
                // 35: int3; int3  (miss → crash)               — 2
                // 37: mov rcx, [rcx+8] (.found: host_gs)      — 4
                // 41: wrgsbase rcx                             — 5
                // 46: lea rcx, [rip+6] (return addr)           — 7
                // 53: jmp [rip+disp]   (callback)              — 6
                // 59: ret                                      — 1
                // Total: 60 bytes

                //  0: mov r10, rcx  (49 89 CA)
                text_data.extend_from_slice(&[0x49, 0x89, 0xCA]);
                //  3: mov eax, imm32  (B8 xx xx xx xx)
                text_data.push(0xB8);
                text_data.extend_from_slice(&syscall_nr.to_le_bytes());
                //  8: rdgsbase r11  (F3 49 0F AE CB)
                text_data.extend_from_slice(&[0xF3, 0x49, 0x0F, 0xAE, 0xCB]);
                // 13: mov rcx, [rip+disp32]  (48 8B 0D xx xx xx xx)
                // disp = gs_table_ptr_offset - (stub_offset + 20)
                //   where gs_table_ptr is at TEXT_HEADER_SIZE/2..TEXT_HEADER_SIZE = offset 8
                let rip_after_mov_rcx = stub_offset + 20; // RIP after this 7-byte insn
                let gs_ptr_file_offset = 8u32; // GS table ptr at byte 8 in .text
                let mov_rcx_disp =
                    (gs_ptr_file_offset as i32).wrapping_sub(rip_after_mov_rcx as i32);
                text_data.extend_from_slice(&[0x48, 0x8B, 0x0D]);
                text_data.extend_from_slice(&mov_rcx_disp.to_le_bytes());
                // 20: cmp [rcx], r11  (4C 39 19)
                text_data.extend_from_slice(&[0x4C, 0x39, 0x19]);
                // 23: je .found (+12) → target is offset 37  (74 0C)
                text_data.extend_from_slice(&[0x74, 0x0C]);
                // 25: add rcx, 16  (48 83 C1 10)
                text_data.extend_from_slice(&[0x48, 0x83, 0xC1, 0x10]);
                // 29: cmp qword [rcx], 0  (48 83 39 00)
                text_data.extend_from_slice(&[0x48, 0x83, 0x39, 0x00]);
                // 33: jne .probe (-15) → target is offset 20  (75 F1)
                // offset 35 + (-15) = 20. disp = 20 - 35 = -15 = 0xF1
                text_data.extend_from_slice(&[0x75, 0xF1]);
                // 35: ud2 (miss → crash)
                text_data.extend_from_slice(&[0x0F, 0x0B]);
                // 37: mov rcx, [rcx+8]  (48 8B 49 08)
                text_data.extend_from_slice(&[0x48, 0x8B, 0x49, 0x08]);
                // 41: wrgsbase rcx  (F3 48 0F AE D9)
                text_data.extend_from_slice(&[0xF3, 0x48, 0x0F, 0xAE, 0xD9]);
                // 46: lea rcx, [rip+6]  (48 8D 0D 06 00 00 00)
                text_data.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x06, 0x00, 0x00, 0x00]);
                // 53: jmp qword [rip+disp32] → callback ptr at offset 0
                let rip_after_jmp = stub_offset + 59;
                let jmp_disp = 0i32.wrapping_sub(rip_after_jmp as i32);
                text_data.extend_from_slice(&[0xFF, 0x25]);
                text_data.extend_from_slice(&jmp_disp.to_le_bytes());
                // 59: ret  (C3)
                text_data.push(0xC3);
            }
            StubExportKind::ReturnStatus { status } => {
                // mov eax, imm32
                text_data.push(0xB8);
                text_data.extend_from_slice(&(*status as u32).to_le_bytes());
                // ret
                text_data.push(0xC3);
            }
            StubExportKind::RawCode { code } => {
                text_data.extend_from_slice(code);
            }
        }
    }
    // Final padding
    while text_data.len() % 16 != 0 {
        text_data.push(0xCC);
    }

    // ---- Build .edata section content (export directory) ----
    let num_exports = exports.len() as u32;
    let text_section_rva: u32 = section_alignment;
    let text_pages = (text_data.len() as u32 + section_alignment - 1) / section_alignment;
    let edata_section_rva: u32 = text_section_rva + text_pages * section_alignment;

    // Layout of .edata:
    //   [ImageExportDirectory]     offset 0
    //   [function RVA array]       offset 40
    //   [name RVA array]           offset 40 + 4*N
    //   [ordinal array]            offset 40 + 8*N
    //   [DLL name string]          offset 40 + 10*N
    //   [function name strings]    after DLL name

    let export_dir_size = size_of::<ImageExportDirectory>() as u32; // 40
    let func_rva_array_offset = export_dir_size;
    let name_rva_array_offset = func_rva_array_offset + 4 * num_exports;
    let ordinal_array_offset = name_rva_array_offset + 4 * num_exports;
    let strings_offset = ordinal_array_offset + 2 * num_exports;

    // Build the strings area: DLL name, then each function name
    let mut strings = Vec::new();
    let dll_name_offset_in_strings = 0u32;
    strings.extend_from_slice(dll_name.as_bytes());
    strings.push(0); // null terminator

    let mut name_offsets_in_strings: Vec<u32> = Vec::with_capacity(exports.len());
    for (_, export) in &sorted_exports {
        name_offsets_in_strings.push(strings.len() as u32);
        strings.extend_from_slice(export.name.as_bytes());
        strings.push(0);
    }

    let edata_total_size = strings_offset + strings.len() as u32;

    // Now assemble the .edata bytes
    let mut edata_data = vec![0u8; edata_total_size as usize];

    // Export directory
    let export_dir = ImageExportDirectory {
        characteristics: 0,
        time_date_stamp: 0,
        major_version: 0,
        minor_version: 0,
        name: edata_section_rva + strings_offset + dll_name_offset_in_strings,
        base: 1, // ordinals start at 1
        number_of_functions: num_exports,
        number_of_names: num_exports,
        address_of_functions: edata_section_rva + func_rva_array_offset,
        address_of_names: edata_section_rva + name_rva_array_offset,
        address_of_name_ordinals: edata_section_rva + ordinal_array_offset,
    };
    edata_data[..size_of::<ImageExportDirectory>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&export_dir));

    // Function RVA array (indexed by ordinal - base)
    // We need to map sorted order back to ordinal order. For simplicity, use
    // the original order as ordinal order: ordinal i → function i.
    for i in 0..num_exports {
        let rva = text_section_rva + code_offsets[i as usize];
        let off = (func_rva_array_offset + i * 4) as usize;
        edata_data[off..off + 4].copy_from_slice(&rva.to_le_bytes());
    }

    // Name RVA array (sorted by name, points into strings area)
    for (sorted_idx, _) in sorted_exports.iter().enumerate() {
        let name_rva = edata_section_rva + strings_offset + name_offsets_in_strings[sorted_idx];
        let off = (name_rva_array_offset + (sorted_idx as u32) * 4) as usize;
        edata_data[off..off + 4].copy_from_slice(&name_rva.to_le_bytes());
    }

    // Ordinal array (parallel with name RVA array; maps sorted name index → ordinal index)
    for (sorted_idx, (orig_idx, _)) in sorted_exports.iter().enumerate() {
        let ordinal = *orig_idx as u16;
        let off = (ordinal_array_offset + (sorted_idx as u32) * 2) as usize;
        edata_data[off..off + 2].copy_from_slice(&ordinal.to_le_bytes());
    }

    // Copy strings
    edata_data[strings_offset as usize..].copy_from_slice(&strings);

    // ---- Build .reloc section ----
    // Our stub code uses only position-independent instructions (mov-imm,
    // syscall, ret) with no absolute address references, so no actual fixups
    // are needed. However, DYNAMIC_BASE requires a valid .reloc section.
    // Emit a single empty relocation block with two IMAGE_REL_BASED_ABSOLUTE
    // (no-op) entries. Two entries (4 bytes) keep the block naturally 4-byte
    // aligned and make `size_of_block` (12) match the actual emitted size,
    // so a loader that advances by SizeOfBlock will land correctly.
    let block_entry_bytes = 2 * size_of::<u16>() as u32; // two u16 entries
    let reloc_block = ImageBaseRelocation {
        virtual_address: text_section_rva,
        size_of_block: size_of::<ImageBaseRelocation>() as u32 + block_entry_bytes,
    };
    let mut reloc_data = Vec::with_capacity(16);
    reloc_data.extend_from_slice(zerocopy::IntoBytes::as_bytes(&reloc_block));
    reloc_data.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());
    reloc_data.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());

    // ---- Assemble the PE file ----
    let text_raw_size = align_up(text_data.len() as u32, file_alignment);
    let edata_raw_size = align_up(edata_data.len() as u32, file_alignment);
    let reloc_raw_size = align_up(reloc_data.len() as u32, file_alignment);

    let num_sections = 3u16; // .text, .edata, .reloc
    let headers_size = {
        let dos_size = size_of::<ImageDosHeader>() as u32;
        let pe_sig_size = 4u32;
        let fh_size = size_of::<ImageFileHeader>() as u32;
        let oh_size = size_of::<ImageOptionalHeader64>() as u32;
        let dd_size =
            (IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) * size_of::<ImageDataDirectory>() as u32;
        let sh_size = u32::from(num_sections) * size_of::<ImageSectionHeader>() as u32;
        align_up(
            dos_size + pe_sig_size + fh_size + oh_size + dd_size + sh_size,
            file_alignment,
        )
    };

    let text_file_offset = headers_size;
    let edata_file_offset = text_file_offset + text_raw_size;
    let reloc_file_offset = edata_file_offset + edata_raw_size;
    let total_file_size = reloc_file_offset + reloc_raw_size;

    let text_virtual_size = text_data.len() as u32;
    let edata_virtual_size = edata_data.len() as u32;
    let reloc_virtual_size = reloc_data.len() as u32;
    let reloc_section_rva = edata_section_rva + align_up(edata_virtual_size, section_alignment);

    let size_of_image = align_up(
        reloc_section_rva + align_up(reloc_virtual_size, section_alignment),
        section_alignment,
    );

    let mut pe = vec![0u8; total_file_size as usize];

    // DOS header
    let pe_new_offset = size_of::<ImageDosHeader>() as i32;
    let dos_header = ImageDosHeader {
        e_magic: IMAGE_DOS_SIGNATURE,
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: pe_new_offset,
    };
    pe[..size_of::<ImageDosHeader>()].copy_from_slice(zerocopy::IntoBytes::as_bytes(&dos_header));

    // PE signature
    let sig_off = pe_new_offset as usize;
    pe[sig_off..sig_off + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    // COFF file header
    let fh_off = sig_off + 4;
    let file_header = ImageFileHeader {
        machine: IMAGE_FILE_MACHINE_AMD64,
        number_of_sections: num_sections,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: (size_of::<ImageOptionalHeader64>()
            + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * size_of::<ImageDataDirectory>())
            as u16,
        characteristics: image_file_chars::IMAGE_FILE_EXECUTABLE_IMAGE
            | image_file_chars::IMAGE_FILE_LARGE_ADDRESS_AWARE
            | image_file_chars::IMAGE_FILE_DLL,
    };
    pe[fh_off..fh_off + size_of::<ImageFileHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&file_header));

    // Optional header
    let oh_off = fh_off + size_of::<ImageFileHeader>();
    let optional_header = ImageOptionalHeader64 {
        magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        major_linker_version: 1,
        minor_linker_version: 0,
        size_of_code: text_raw_size,
        size_of_initialized_data: edata_raw_size + reloc_raw_size,
        size_of_uninitialized_data: 0,
        address_of_entry_point: 0, // DLLs with no DllMain
        base_of_code: text_section_rva,
        image_base,
        section_alignment,
        file_alignment,
        major_os_version: 10,
        minor_os_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image,
        size_of_headers: headers_size,
        checksum: 0,
        subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
        dll_characteristics: 0x0160, // NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA
        size_of_stack_reserve: 0x10_0000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x10_0000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32,
    };
    pe[oh_off..oh_off + size_of::<ImageOptionalHeader64>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&optional_header));

    // Data directories
    let dd_off = oh_off + size_of::<ImageOptionalHeader64>();
    let mut data_dirs = [ImageDataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT] = ImageDataDirectory {
        virtual_address: edata_section_rva,
        size: edata_total_size,
    };
    data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = ImageDataDirectory {
        virtual_address: reloc_section_rva,
        size: reloc_data.len() as u32,
    };
    for (i, dd) in data_dirs.iter().enumerate() {
        let off = dd_off + i * size_of::<ImageDataDirectory>();
        pe[off..off + size_of::<ImageDataDirectory>()]
            .copy_from_slice(zerocopy::IntoBytes::as_bytes(dd));
    }

    // Section headers
    let sh_off = dd_off + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * size_of::<ImageDataDirectory>();

    // .text section
    let mut text_name = [0u8; 8];
    text_name[..5].copy_from_slice(b".text");
    let text_sh = ImageSectionHeader {
        name: text_name,
        virtual_size: text_virtual_size,
        virtual_address: text_section_rva,
        size_of_raw_data: text_raw_size,
        pointer_to_raw_data: text_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_CODE
            | section_chars::IMAGE_SCN_MEM_EXECUTE
            | section_chars::IMAGE_SCN_MEM_READ,
    };
    pe[sh_off..sh_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&text_sh));

    // .edata section
    let sh2_off = sh_off + size_of::<ImageSectionHeader>();
    let mut edata_name = [0u8; 8];
    edata_name[..6].copy_from_slice(b".edata");
    let edata_sh = ImageSectionHeader {
        name: edata_name,
        virtual_size: edata_virtual_size,
        virtual_address: edata_section_rva,
        size_of_raw_data: edata_raw_size,
        pointer_to_raw_data: edata_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_INITIALIZED_DATA
            | section_chars::IMAGE_SCN_MEM_READ,
    };
    pe[sh2_off..sh2_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&edata_sh));

    // .reloc section
    let sh3_off = sh2_off + size_of::<ImageSectionHeader>();
    let mut reloc_name = [0u8; 8];
    reloc_name[..6].copy_from_slice(b".reloc");
    let reloc_sh = ImageSectionHeader {
        name: reloc_name,
        virtual_size: reloc_virtual_size,
        virtual_address: reloc_section_rva,
        size_of_raw_data: reloc_raw_size,
        pointer_to_raw_data: reloc_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_INITIALIZED_DATA
            | section_chars::IMAGE_SCN_MEM_READ
            | section_chars::IMAGE_SCN_MEM_DISCARDABLE,
    };
    pe[sh3_off..sh3_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&reloc_sh));

    // Write section data
    pe[text_file_offset as usize..text_file_offset as usize + text_data.len()]
        .copy_from_slice(&text_data);
    pe[edata_file_offset as usize..edata_file_offset as usize + edata_data.len()]
        .copy_from_slice(&edata_data);
    pe[reloc_file_offset as usize..reloc_file_offset as usize + reloc_data.len()]
        .copy_from_slice(&reloc_data);

    pe
}

/// Description of a function to import from a DLL.
#[derive(Clone, Debug)]
pub struct ImportFunction {
    /// Function name (e.g., "NtWriteFile").
    pub name: String,
}

/// Description of a DLL import.
#[derive(Clone, Debug)]
pub struct ImportDescriptor {
    /// DLL name (e.g., "ntdll.dll").
    pub dll_name: String,
    /// Functions to import.
    pub functions: Vec<ImportFunction>,
}

/// Build a minimal PE EXE (not DLL) with inline code and an import table.
///
/// The produced EXE has:
/// - `.text` section containing caller-provided code bytes (entry point at RVA 0x1000)
/// - `.idata` section containing the import directory + IAT + name strings
/// - `.reloc` section (minimal, for DYNAMIC_BASE)
///
/// `code` is the raw machine code placed at the start of `.text`.
/// `imports` describes which DLLs and functions to import.
///
/// Returns `(exe_bytes, iat_rvas)` where `iat_rvas[dll_idx][func_idx]` is the
/// RVA of the IAT slot for that import. The code can load these addresses.
pub fn build_test_exe(
    code: &[u8],
    imports: &[ImportDescriptor],
    image_base: u64,
) -> (Vec<u8>, Vec<Vec<u32>>) {
    let file_alignment: u32 = 0x200;
    let section_alignment: u32 = 0x1000;

    let text_section_rva: u32 = section_alignment;

    // ---- Build .text section ----
    let mut text_data = Vec::from(code);
    // Pad to 16-byte alignment
    while text_data.len() % 16 != 0 {
        text_data.push(0xCC);
    }

    // ---- Build .idata section ----
    // Layout:
    //   [ImportDescriptor[0]] ... [ImportDescriptor[N-1]] [null terminator (20 bytes)]
    //   [ILT entries for each DLL (8 bytes each, null-terminated)]
    //   [IAT entries for each DLL (8 bytes each, null-terminated)]
    //   [Hint/Name entries]
    //   [DLL name strings]
    let idata_section_rva: u32 = section_alignment * 2;

    let num_dlls = imports.len();
    let desc_table_size = ((num_dlls + 1) * size_of::<ImageImportDescriptor>()) as u32;

    // Count total functions across all DLLs (used for layout validation)
    let _total_funcs: usize = imports.iter().map(|d| d.functions.len()).sum();

    // ILT: for each DLL, (N+1) qwords (N entries + null terminator)
    let ilt_size: u32 = imports
        .iter()
        .map(|d| ((d.functions.len() + 1) * 8) as u32)
        .sum();

    // IAT: same layout as ILT
    let iat_size: u32 = ilt_size;

    let ilt_offset = desc_table_size;
    let iat_offset = ilt_offset + ilt_size;
    let hint_name_offset = iat_offset + iat_size;

    // Build hint/name entries: [u16 hint][name bytes][null][padding to even]
    let mut hint_name_data = Vec::new();
    let mut hint_name_rvas: Vec<Vec<u32>> = Vec::new();
    for dll in imports {
        let mut dll_rvas = Vec::new();
        for func in &dll.functions {
            let entry_rva = idata_section_rva + hint_name_offset + hint_name_data.len() as u32;
            dll_rvas.push(entry_rva);
            // Hint (u16) = 0
            hint_name_data.extend_from_slice(&0u16.to_le_bytes());
            hint_name_data.extend_from_slice(func.name.as_bytes());
            hint_name_data.push(0); // null terminator
            // Pad to even
            if hint_name_data.len() % 2 != 0 {
                hint_name_data.push(0);
            }
        }
        hint_name_rvas.push(dll_rvas);
    }

    let dll_names_offset = hint_name_offset + hint_name_data.len() as u32;

    // Build DLL name strings
    let mut dll_name_data = Vec::new();
    let mut dll_name_rvas = Vec::new();
    for dll in imports {
        let name_rva = idata_section_rva + dll_names_offset + dll_name_data.len() as u32;
        dll_name_rvas.push(name_rva);
        dll_name_data.extend_from_slice(dll.dll_name.as_bytes());
        dll_name_data.push(0);
    }

    let idata_total_size = dll_names_offset + dll_name_data.len() as u32;

    // Assemble .idata bytes
    let mut idata_data = vec![0u8; idata_total_size as usize];

    // Fill import descriptors
    let mut ilt_cursor = ilt_offset;
    let mut iat_cursor = iat_offset;
    let mut iat_rvas: Vec<Vec<u32>> = Vec::new();

    for (dll_idx, dll) in imports.iter().enumerate() {
        let desc = ImageImportDescriptor {
            original_first_thunk: idata_section_rva + ilt_cursor,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name: dll_name_rvas[dll_idx],
            first_thunk: idata_section_rva + iat_cursor,
        };
        let desc_off = dll_idx * size_of::<ImageImportDescriptor>();
        idata_data[desc_off..desc_off + size_of::<ImageImportDescriptor>()]
            .copy_from_slice(zerocopy::IntoBytes::as_bytes(&desc));

        let mut dll_iat_rvas = Vec::new();
        for (func_idx, _func) in dll.functions.iter().enumerate() {
            // ILT entry: RVA to hint/name (bit 63 clear = by name)
            let hn_rva = hint_name_rvas[dll_idx][func_idx] as u64;
            let ilt_off = ilt_cursor as usize + func_idx * 8;
            idata_data[ilt_off..ilt_off + 8].copy_from_slice(&hn_rva.to_le_bytes());

            // IAT entry: same as ILT (loader overwrites at load time)
            let iat_off = iat_cursor as usize + func_idx * 8;
            idata_data[iat_off..iat_off + 8].copy_from_slice(&hn_rva.to_le_bytes());

            dll_iat_rvas.push(idata_section_rva + iat_cursor + (func_idx as u32) * 8);
        }
        iat_rvas.push(dll_iat_rvas);

        // Null terminator for ILT and IAT
        let ilt_term = ilt_cursor as usize + dll.functions.len() * 8;
        idata_data[ilt_term..ilt_term + 8].copy_from_slice(&0u64.to_le_bytes());
        let iat_term = iat_cursor as usize + dll.functions.len() * 8;
        idata_data[iat_term..iat_term + 8].copy_from_slice(&0u64.to_le_bytes());

        ilt_cursor += ((dll.functions.len() + 1) * 8) as u32;
        iat_cursor += ((dll.functions.len() + 1) * 8) as u32;
    }

    // Copy hint/name entries
    let hn_start = hint_name_offset as usize;
    idata_data[hn_start..hn_start + hint_name_data.len()].copy_from_slice(&hint_name_data);

    // Copy DLL name strings
    let dn_start = dll_names_offset as usize;
    idata_data[dn_start..dn_start + dll_name_data.len()].copy_from_slice(&dll_name_data);

    // ---- Build .reloc section (same as DLL — minimal ABSOLUTE entries) ----
    let reloc_section_rva = idata_section_rva + align_up(idata_total_size, section_alignment);
    let block_entry_bytes = 2 * size_of::<u16>() as u32;
    let reloc_block = ImageBaseRelocation {
        virtual_address: text_section_rva,
        size_of_block: size_of::<ImageBaseRelocation>() as u32 + block_entry_bytes,
    };
    let mut reloc_data = Vec::with_capacity(16);
    reloc_data.extend_from_slice(zerocopy::IntoBytes::as_bytes(&reloc_block));
    reloc_data.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());
    reloc_data.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());

    // ---- Assemble the PE file ----
    let text_raw_size = align_up(text_data.len() as u32, file_alignment);
    let idata_raw_size = align_up(idata_data.len() as u32, file_alignment);
    let reloc_raw_size = align_up(reloc_data.len() as u32, file_alignment);

    let num_sections = 3u16;
    let headers_size = {
        let dos_size = size_of::<ImageDosHeader>() as u32;
        let pe_sig_size = 4u32;
        let fh_size = size_of::<ImageFileHeader>() as u32;
        let oh_size = size_of::<ImageOptionalHeader64>() as u32;
        let dd_size =
            (IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) * size_of::<ImageDataDirectory>() as u32;
        let sh_size = u32::from(num_sections) * size_of::<ImageSectionHeader>() as u32;
        align_up(
            dos_size + pe_sig_size + fh_size + oh_size + dd_size + sh_size,
            file_alignment,
        )
    };

    let text_file_offset = headers_size;
    let idata_file_offset = text_file_offset + text_raw_size;
    let reloc_file_offset = idata_file_offset + idata_raw_size;
    let total_file_size = reloc_file_offset + reloc_raw_size;

    let text_virtual_size = text_data.len() as u32;
    let idata_virtual_size = idata_data.len() as u32;
    let reloc_virtual_size = reloc_data.len() as u32;

    let size_of_image = align_up(
        reloc_section_rva + align_up(reloc_virtual_size, section_alignment),
        section_alignment,
    );

    let mut pe = vec![0u8; total_file_size as usize];

    // DOS header
    let pe_new_offset = size_of::<ImageDosHeader>() as i32;
    let dos_header = ImageDosHeader {
        e_magic: IMAGE_DOS_SIGNATURE,
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: pe_new_offset,
    };
    pe[..size_of::<ImageDosHeader>()].copy_from_slice(zerocopy::IntoBytes::as_bytes(&dos_header));

    // PE signature
    let sig_off = pe_new_offset as usize;
    pe[sig_off..sig_off + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    // COFF file header (EXE, not DLL)
    let fh_off = sig_off + 4;
    let file_header = ImageFileHeader {
        machine: IMAGE_FILE_MACHINE_AMD64,
        number_of_sections: num_sections,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: (size_of::<ImageOptionalHeader64>()
            + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * size_of::<ImageDataDirectory>())
            as u16,
        characteristics: image_file_chars::IMAGE_FILE_EXECUTABLE_IMAGE
            | image_file_chars::IMAGE_FILE_LARGE_ADDRESS_AWARE,
        // Note: no IMAGE_FILE_DLL — this is an EXE
    };
    pe[fh_off..fh_off + size_of::<ImageFileHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&file_header));

    // Optional header
    let oh_off = fh_off + size_of::<ImageFileHeader>();
    let optional_header = ImageOptionalHeader64 {
        magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        major_linker_version: 1,
        minor_linker_version: 0,
        size_of_code: text_raw_size,
        size_of_initialized_data: idata_raw_size + reloc_raw_size,
        size_of_uninitialized_data: 0,
        address_of_entry_point: text_section_rva, // Entry at start of .text
        base_of_code: text_section_rva,
        image_base,
        section_alignment,
        file_alignment,
        major_os_version: 10,
        minor_os_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image,
        size_of_headers: headers_size,
        checksum: 0,
        subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
        dll_characteristics: 0x0160, // NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA
        size_of_stack_reserve: 0x10_0000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x10_0000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32,
    };
    pe[oh_off..oh_off + size_of::<ImageOptionalHeader64>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&optional_header));

    // Data directories
    let dd_off = oh_off + size_of::<ImageOptionalHeader64>();
    let mut data_dirs = [ImageDataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    if !imports.is_empty() {
        data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT] = ImageDataDirectory {
            virtual_address: idata_section_rva,
            size: desc_table_size,
        };
        data_dirs[IMAGE_DIRECTORY_ENTRY_IAT] = ImageDataDirectory {
            virtual_address: idata_section_rva + iat_offset,
            size: iat_size,
        };
    }
    data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = ImageDataDirectory {
        virtual_address: reloc_section_rva,
        size: reloc_data.len() as u32,
    };
    for (i, dd) in data_dirs.iter().enumerate() {
        let off = dd_off + i * size_of::<ImageDataDirectory>();
        pe[off..off + size_of::<ImageDataDirectory>()]
            .copy_from_slice(zerocopy::IntoBytes::as_bytes(dd));
    }

    // Section headers
    let sh_off = dd_off + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * size_of::<ImageDataDirectory>();

    // .text
    let mut text_name = [0u8; 8];
    text_name[..5].copy_from_slice(b".text");
    let text_sh = ImageSectionHeader {
        name: text_name,
        virtual_size: text_virtual_size,
        virtual_address: text_section_rva,
        size_of_raw_data: text_raw_size,
        pointer_to_raw_data: text_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_CODE
            | section_chars::IMAGE_SCN_MEM_EXECUTE
            | section_chars::IMAGE_SCN_MEM_READ,
    };
    pe[sh_off..sh_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&text_sh));

    // .idata
    let sh2_off = sh_off + size_of::<ImageSectionHeader>();
    let mut idata_name = [0u8; 8];
    idata_name[..6].copy_from_slice(b".idata");
    let idata_sh = ImageSectionHeader {
        name: idata_name,
        virtual_size: idata_virtual_size,
        virtual_address: idata_section_rva,
        size_of_raw_data: idata_raw_size,
        pointer_to_raw_data: idata_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_INITIALIZED_DATA
            | section_chars::IMAGE_SCN_MEM_READ
            | section_chars::IMAGE_SCN_MEM_WRITE, // IAT needs to be writable
    };
    pe[sh2_off..sh2_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&idata_sh));

    // .reloc
    let sh3_off = sh2_off + size_of::<ImageSectionHeader>();
    let mut reloc_name = [0u8; 8];
    reloc_name[..6].copy_from_slice(b".reloc");
    let reloc_sh = ImageSectionHeader {
        name: reloc_name,
        virtual_size: reloc_virtual_size,
        virtual_address: reloc_section_rva,
        size_of_raw_data: reloc_raw_size,
        pointer_to_raw_data: reloc_file_offset,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: section_chars::IMAGE_SCN_CNT_INITIALIZED_DATA
            | section_chars::IMAGE_SCN_MEM_READ
            | section_chars::IMAGE_SCN_MEM_DISCARDABLE,
    };
    pe[sh3_off..sh3_off + size_of::<ImageSectionHeader>()]
        .copy_from_slice(zerocopy::IntoBytes::as_bytes(&reloc_sh));

    // Write section data
    pe[text_file_offset as usize..text_file_offset as usize + text_data.len()]
        .copy_from_slice(&text_data);
    pe[idata_file_offset as usize..idata_file_offset as usize + idata_data.len()]
        .copy_from_slice(&idata_data);
    pe[reloc_file_offset as usize..reloc_file_offset as usize + reloc_data.len()]
        .copy_from_slice(&reloc_data);

    (pe, iat_rvas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_parser::PeParsedFile;

    #[test]
    fn build_and_parse_stub_dll() {
        let exports = vec![
            StubExport::syscall_stub("NtClose", 0x0006),
            StubExport::syscall_stub("NtWriteFile", 0x0001),
            StubExport::return_status("RtlNtStatusToDosError", 0),
        ];

        let dll_bytes = build_stub_dll("ntdll.dll", &exports, 0x1800_0000_0000);

        // Should be a valid PE
        let parsed = PeParsedFile::parse(&dll_bytes).expect("should parse");
        assert!(parsed.is_dll);
        assert_eq!(parsed.file_header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(parsed.sections.len(), 3); // .text, .edata, .reloc

        // Should have 3 exports
        let pe_exports = parsed.exports(&dll_bytes);
        assert_eq!(pe_exports.len(), 3);

        // Exports should be sorted by name (EAT order matches original insertion
        // order, but names are sorted in the name table for binary search).
        let names: Vec<Option<&str>> = pe_exports.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            vec![
                Some("NtClose"),
                Some("NtWriteFile"),
                Some("RtlNtStatusToDosError")
            ]
        );

        // Should have no imports
        let imports = parsed.imports(&dll_bytes);
        assert!(imports.is_empty());

        // Should have a .reloc section with a valid base relocation directory
        let reloc_dd = parsed
            .data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .expect("should have base reloc directory");
        assert!(reloc_dd.size > 0);

        // Verify size_of_block matches directory size (no internal inconsistency).
        let reloc_offset = parsed
            .rva_to_file_offset(reloc_dd.virtual_address)
            .expect("reloc RVA should resolve");
        let reloc_header =
            zerocopy::FromBytes::read_from_prefix(&dll_bytes[reloc_offset as usize..])
                .expect("should parse reloc header")
                .0;
        let block: ImageBaseRelocation = reloc_header;
        assert_eq!(
            block.size_of_block, reloc_dd.size,
            "size_of_block must match directory size"
        );

        // Preferred image base should match what we passed
        assert_eq!(parsed.image_base, 0x1800_0000_0000);
    }

    #[test]
    fn distinct_image_bases() {
        let exports = vec![StubExport::syscall_stub("Foo", 1)];

        let ntdll = build_stub_dll("ntdll.dll", &exports, 0x1800_0000_0000);
        let kernel32 = build_stub_dll("kernel32.dll", &exports, 0x1800_0001_0000);

        let p1 = PeParsedFile::parse(&ntdll).unwrap();
        let p2 = PeParsedFile::parse(&kernel32).unwrap();

        assert_ne!(p1.image_base, p2.image_base);
        assert_eq!(p1.image_base, 0x1800_0000_0000);
        assert_eq!(p2.image_base, 0x1800_0001_0000);
    }

    #[test]
    fn build_and_parse_test_exe() {
        // Minimal code: "mov eax, 0; ret" (just returns 0)
        let code = vec![0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let imports = vec![
            ImportDescriptor {
                dll_name: String::from("ntdll.dll"),
                functions: vec![
                    ImportFunction {
                        name: String::from("NtWriteFile"),
                    },
                    ImportFunction {
                        name: String::from("NtTerminateProcess"),
                    },
                ],
            },
            ImportDescriptor {
                dll_name: String::from("kernel32.dll"),
                functions: vec![ImportFunction {
                    name: String::from("ExitProcess"),
                }],
            },
        ];

        let (exe_bytes, iat_rvas) = build_test_exe(&code, &imports, 0x0040_0000);

        // Should parse as valid PE
        let parsed = PeParsedFile::parse(&exe_bytes).expect("should parse");
        assert!(!parsed.is_dll, "should not be a DLL");
        assert_eq!(parsed.entry_point, 0x1000); // .text at section_alignment

        // Should have imports
        let pe_imports = parsed.imports(&exe_bytes);
        assert_eq!(pe_imports.len(), 2);
        assert_eq!(pe_imports[0].dll_name, "ntdll.dll");
        assert_eq!(pe_imports[0].functions.len(), 2);
        assert_eq!(pe_imports[1].dll_name, "kernel32.dll");
        assert_eq!(pe_imports[1].functions.len(), 1);

        // IAT RVAs should be valid
        assert_eq!(iat_rvas.len(), 2);
        assert_eq!(iat_rvas[0].len(), 2); // ntdll: NtWriteFile, NtTerminateProcess
        assert_eq!(iat_rvas[1].len(), 1); // kernel32: ExitProcess
    }
}
