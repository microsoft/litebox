// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE (Portable Executable) format structures.
//!
//! These structures represent the on-disk format of PE/COFF files. They are
//! used by both the PE parser (for loading guest binaries) and the PE builder
//! (for generating stub DLLs).

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// MS-DOS stub header. Every PE file starts with this.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub struct ImageDosHeader {
    /// Magic number: `MZ` (0x5A4D).
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// File offset of the PE signature (`PE\0\0`).
    pub e_lfanew: i32,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"

/// COFF file header, immediately after the PE signature.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// Characteristics flags for `ImageFileHeader`.
pub mod image_file_chars {
    pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const IMAGE_FILE_DLL: u16 = 0x2000;
}

/// PE32+ optional header (64-bit).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;

/// Data directory entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Well-known data directory indices.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Section header.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// Section characteristics flags.
pub mod section_chars {
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
}

/// Import directory entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct ImageImportDescriptor {
    /// RVA to the Import Lookup Table (or Import Name Table).
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    /// RVA to the DLL name (null-terminated ASCII).
    pub name: u32,
    /// RVA to the Import Address Table (IAT).
    pub first_thunk: u32,
}

/// Export directory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    /// RVA to the DLL name.
    pub name: u32,
    /// Starting ordinal number.
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    /// RVA to array of function RVAs.
    pub address_of_functions: u32,
    /// RVA to array of name RVAs.
    pub address_of_names: u32,
    /// RVA to array of ordinal indices (u16).
    pub address_of_name_ordinals: u32,
}

/// Base relocation block header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct ImageBaseRelocation {
    /// Page RVA that the following entries apply to.
    pub virtual_address: u32,
    /// Total size of this block (header + entries) in bytes.
    pub size_of_block: u32,
}

/// Relocation types (upper 4 bits of each reloc entry).
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0; // Padding, skip
pub const IMAGE_REL_BASED_DIR64: u16 = 10; // 64-bit address fixup

/// TLS directory (64-bit).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    /// Pointer to the TLS index variable (guest VA).
    pub address_of_index: u64,
    /// Pointer to array of TLS callback function pointers (guest VA).
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}
