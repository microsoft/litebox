// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE binary parser and loader
//!
//! This implements a minimal PE (Portable Executable) loader that can:
//! - Parse PE headers (DOS header, NT headers, optional headers)
//! - Load sections into memory
//! - Handle basic relocations
//! - Set up the initial execution context

use crate::{Result, WindowsShimError};

/// DOS header magic number "MZ"
const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// IMAGE_FILE_MACHINE_AMD64
const MACHINE_AMD64: u16 = 0x8664;

/// Minimal PE DOS header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DosHeader {
    e_magic: u16, // Magic number "MZ"
    _reserved1: [u8; 58],
    e_lfanew: u32, // Offset to PE header
}

/// PE file header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// Optional header (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

/// Data directory entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

/// Data directory indices
#[allow(dead_code)]
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
#[allow(dead_code)]
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
#[allow(dead_code)]
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

/// Import descriptor entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImportDescriptor {
    original_first_thunk: u32, // RVA to Import Lookup Table
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,        // RVA to DLL name string
    first_thunk: u32, // RVA to Import Address Table
}

/// TLS directory (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct TlsDirectory64 {
    start_address_of_raw_data: u64, // VA
    end_address_of_raw_data: u64,   // VA
    address_of_index: u64,          // VA
    address_of_call_backs: u64,     // VA
    size_of_zero_fill: u32,
    characteristics: u32,
}

/// Base relocation block header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BaseRelocationBlock {
    virtual_address: u32,
    size_of_block: u32,
}

/// Relocation entry types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// PE section header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _reserved: [u32; 3],
    characteristics: u32,
}

/// Information about a PE section
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (null-terminated string)
    pub name: String,
    /// Virtual address in memory
    pub virtual_address: u32,
    /// Virtual size in memory
    pub virtual_size: u32,
    /// Raw data from the file
    pub data: Vec<u8>,
    /// Section characteristics (permissions, etc.)
    pub characteristics: u32,
}

/// Information about an imported DLL
#[derive(Debug, Clone)]
pub struct ImportedDll {
    /// DLL name (e.g., "KERNEL32.dll")
    pub name: String,
    /// RVA to Import Address Table (IAT)
    pub iat_rva: u32,
    /// List of imported function names or ordinals
    pub functions: Vec<String>,
}

/// Information about a relocation
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Type of relocation
    pub reloc_type: u16,
    /// RVA where the relocation should be applied
    pub rva: u32,
}

/// Information about TLS (Thread Local Storage)
#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// Start address of TLS data template (VA, will be relative to image base)
    pub start_address: u64,
    /// End address of TLS data template (VA, will be relative to image base)
    pub end_address: u64,
    /// Address of TLS index variable (VA, will be relative to image base)
    pub address_of_index: u64,
    /// Size of zero-filled data following the initialized data
    pub size_of_zero_fill: u32,
    /// Address of callbacks table (VA; 0 if none)
    pub address_of_callbacks: u64,
}

/// Exception directory information from the .pdata section
///
/// This contains the location of the exception table used for structured
/// exception handling (SEH) on x64 Windows.
#[derive(Debug, Clone, Copy)]
pub struct ExceptionDirectoryInfo {
    /// RVA of the exception directory (.pdata section)
    pub rva: u32,
    /// Size of the exception directory in bytes
    pub size: u32,
}

/// PE binary loader
pub struct PeLoader {
    /// Raw binary data
    data: Vec<u8>,
    /// Entry point offset
    entry_point: u64,
    /// Image base address
    image_base: u64,
    /// Number of sections
    section_count: u16,
    /// Offset to first section header
    section_headers_offset: usize,
    /// Offset to data directories
    data_directories_offset: usize,
    /// Number of data directories
    number_of_rva_and_sizes: u32,
}

impl PeLoader {
    /// Create a new PE loader from binary data
    ///
    /// This performs minimal validation and header parsing
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() < core::mem::size_of::<DosHeader>() {
            return Err(WindowsShimError::InvalidPeBinary(
                "File too small to contain DOS header".to_string(),
            ));
        }

        // SAFETY: We just checked the size is sufficient for DosHeader.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let dos_header = unsafe { data.as_ptr().cast::<DosHeader>().read_unaligned() };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(WindowsShimError::InvalidPeBinary(format!(
                "Invalid DOS signature: expected 0x{:04X}, found 0x{:04X}",
                DOS_SIGNATURE, dos_header.e_magic
            )));
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "PE offset out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let pe_signature = unsafe { data.as_ptr().add(pe_offset).cast::<u32>().read_unaligned() };

        if pe_signature != PE_SIGNATURE {
            return Err(WindowsShimError::InvalidPeBinary(format!(
                "Invalid PE signature: expected 0x{PE_SIGNATURE:08X}, found 0x{pe_signature:08X}"
            )));
        }

        let file_header_offset = pe_offset + 4;
        if file_header_offset + core::mem::size_of::<FileHeader>() > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "File header out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let file_header = unsafe {
            data.as_ptr()
                .add(file_header_offset)
                .cast::<FileHeader>()
                .read_unaligned()
        };

        if file_header.machine != MACHINE_AMD64 {
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "Unsupported machine type: 0x{:04X} (only x64 is supported)",
                file_header.machine
            )));
        }

        let optional_header_offset = file_header_offset + core::mem::size_of::<FileHeader>();
        if optional_header_offset + core::mem::size_of::<OptionalHeader64>() > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "Optional header out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let optional_header = unsafe {
            data.as_ptr()
                .add(optional_header_offset)
                .cast::<OptionalHeader64>()
                .read_unaligned()
        };

        // Section headers start after the optional header
        let section_headers_offset =
            optional_header_offset + file_header.size_of_optional_header as usize;

        // Data directories start right after the OptionalHeader64 structure
        let data_directories_offset =
            optional_header_offset + core::mem::size_of::<OptionalHeader64>();

        Ok(Self {
            data,
            entry_point: u64::from(optional_header.address_of_entry_point),
            image_base: optional_header.image_base,
            section_count: file_header.number_of_sections,
            section_headers_offset,
            data_directories_offset,
            number_of_rva_and_sizes: optional_header.number_of_rva_and_sizes,
        })
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Get the preferred image base
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the number of sections
    pub fn section_count(&self) -> u16 {
        self.section_count
    }

    /// Get the raw binary data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get information about all sections
    pub fn sections(&self) -> Result<Vec<Section>> {
        let mut sections = Vec::new();

        for i in 0..self.section_count {
            let section_offset =
                self.section_headers_offset + i as usize * core::mem::size_of::<SectionHeader>();

            if section_offset + core::mem::size_of::<SectionHeader>() > self.data.len() {
                return Err(WindowsShimError::InvalidPeBinary(
                    "Section header out of bounds".to_string(),
                ));
            }

            // SAFETY: We checked bounds above.
            // Using read_unaligned to avoid alignment issues.
            #[allow(clippy::cast_ptr_alignment)]
            let section_header = unsafe {
                self.data
                    .as_ptr()
                    .add(section_offset)
                    .cast::<SectionHeader>()
                    .read_unaligned()
            };

            // Extract section name (null-terminated)
            let name_len = section_header
                .name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(section_header.name.len());
            let name = String::from_utf8_lossy(&section_header.name[..name_len]).to_string();

            // Extract section data
            let data_start = section_header.pointer_to_raw_data as usize;
            let data_size = section_header.size_of_raw_data as usize;

            let data = if data_start > 0 && data_size > 0 {
                if data_start + data_size > self.data.len() {
                    return Err(WindowsShimError::InvalidPeBinary(format!(
                        "Section {name} data out of bounds"
                    )));
                }
                self.data[data_start..data_start + data_size].to_vec()
            } else {
                Vec::new()
            };

            sections.push(Section {
                name,
                virtual_address: section_header.virtual_address,
                virtual_size: section_header.virtual_size,
                data,
                characteristics: section_header.characteristics,
            });
        }

        Ok(sections)
    }

    /// Load sections into memory at the given base address
    ///
    /// This copies section data to the appropriate virtual addresses.
    /// Returns the total size of the loaded image.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `base_address` points to a valid, writable memory region
    /// - The memory region is large enough to hold all sections
    /// - The memory region remains valid for the lifetime of the loaded program
    pub unsafe fn load_sections(&self, base_address: u64) -> Result<usize> {
        let sections = self.sections()?;
        let mut max_address = 0usize;

        for section in sections {
            // Check for overflow when adding virtual_address to base_address
            let target_address = base_address
                .checked_add(u64::from(section.virtual_address))
                .ok_or_else(|| {
                    WindowsShimError::InvalidPeBinary(format!(
                        "Address overflow: base 0x{base_address:X} + VA 0x{:X}",
                        section.virtual_address
                    ))
                })?;

            let data_size = section.data.len();
            let virtual_size = section.virtual_size as usize;

            // Copy initialized data if present
            if data_size > 0 {
                // SAFETY: Caller guarantees base_address is valid and has enough space
                unsafe {
                    let dest = target_address as *mut u8;
                    core::ptr::copy_nonoverlapping(section.data.as_ptr(), dest, data_size);
                }
            }

            // Zero-initialize any remaining space in the section
            // This is crucial for BSS sections (uninitialized data) which have
            // virtual_size > 0 but data_size == 0
            if virtual_size > data_size {
                let zero_start = target_address
                    .checked_add(data_size as u64)
                    .ok_or_else(|| {
                        WindowsShimError::InvalidPeBinary(format!(
                            "Address overflow in BSS section {} at 0x{:X}",
                            section.name, target_address
                        ))
                    })?;
                let zero_size = virtual_size - data_size;

                // SAFETY: Caller guarantees base_address region is valid and writable
                unsafe {
                    let dest = zero_start as *mut u8;
                    core::ptr::write_bytes(dest, 0, zero_size);
                }
            }

            // Track the maximum address used (checked to prevent overflow)
            let section_end = (section.virtual_address as usize)
                .checked_add(virtual_size)
                .ok_or_else(|| {
                    WindowsShimError::InvalidPeBinary(format!(
                        "Section size overflow: VA 0x{:X} + size 0x{:X}",
                        section.virtual_address, section.virtual_size
                    ))
                })?;
            if section_end > max_address {
                max_address = section_end;
            }
        }

        Ok(max_address)
    }

    /// Patch __CTOR_LIST__ to fix sentinel values that cause crashes
    ///
    /// MinGW CRT uses __CTOR_LIST__ for C++ global constructors. The list format is:
    /// `[-1 sentinel] [func_ptr_1] [func_ptr_2] ... [0 terminator]`
    ///
    /// Background: Rustc uses LLVM's @llvm.global_ctors mechanism for global constructors.
    /// The MinGW CRT (crtbegin.o) implements __do_global_ctors_aux which processes
    /// __CTOR_LIST__ at startup. However, this implementation doesn't properly handle
    /// the -1 sentinel and may try to call it as a function pointer.
    ///
    /// This function scans for __CTOR_LIST__ patterns and replaces -1 sentinels with 0
    /// to prevent crashes when the MinGW CRT processes the constructor list.
    ///
    /// # Safety
    /// This must be called after sections are loaded and relocations are applied.
    pub unsafe fn patch_ctor_list(&self, base_address: u64) -> Result<()> {
        // Scan all sections for the __CTOR_LIST__ pattern
        // Pattern: 0xffffffffffffffff followed by valid VA or 0
        let sections = self.sections()?;

        for section in sections {
            let section_va = base_address
                .checked_add(u64::from(section.virtual_address))
                .ok_or_else(|| {
                    WindowsShimError::InvalidPeBinary(format!(
                        "Address overflow in section {}",
                        section.name
                    ))
                })?;

            // Scan for 0xffffffffffffffff pattern
            let section_size = section.virtual_size as usize;
            let mut offset = 0;

            while offset + 16 <= section_size {
                // SAFETY: Caller guarantees base_address points to loaded sections
                let ptr = (section_va + offset as u64) as *mut u64;
                let value = unsafe { ptr.read() };

                if value == 0xffffffffffffffff {
                    // Check if next value looks like a valid VA or is 0 (terminator)
                    let next_ptr = unsafe { ptr.add(1) };
                    let next_value = unsafe { next_ptr.read() };

                    // Valid __CTOR_LIST__ if next is 0 or a VA within the relocated image range
                    // After relocations, pointers will be base_address + RVA
                    // So check if it's within [base_address, base_address + 256MB)
                    let looks_like_ctor_list = next_value == 0
                        || (next_value >= base_address && next_value < base_address + 0x10000000);

                    if looks_like_ctor_list {
                        // Patch the -1 sentinel to 0 to prevent crashes
                        unsafe { ptr.write(0) };
                    }
                }

                offset += 8; // Move to next 64-bit value
            }
        }

        Ok(())
    }

    /// Get a data directory by index
    fn get_data_directory(&self, index: usize) -> Result<DataDirectory> {
        if index >= self.number_of_rva_and_sizes as usize {
            return Ok(DataDirectory {
                virtual_address: 0,
                size: 0,
            });
        }

        let dir_offset =
            self.data_directories_offset + index * core::mem::size_of::<DataDirectory>();

        if dir_offset + core::mem::size_of::<DataDirectory>() > self.data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "Data directory out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let data_dir = unsafe {
            self.data
                .as_ptr()
                .add(dir_offset)
                .cast::<DataDirectory>()
                .read_unaligned()
        };

        Ok(data_dir)
    }

    /// Convert RVA to file offset
    #[allow(dead_code)]
    fn rva_to_offset(&self, rva: u32) -> Result<usize> {
        let sections = self.sections()?;

        for section in sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                let offset_in_section = rva - section.virtual_address;
                // Find the corresponding location in the raw data
                return Ok(offset_in_section as usize);
            }
        }

        Err(WindowsShimError::InvalidPeBinary(format!(
            "RVA 0x{rva:X} not found in any section"
        )))
    }

    /// Read a null-terminated string at the given RVA
    fn read_string_at_rva(&self, rva: u32) -> Result<String> {
        let sections = self.sections()?;

        // Find which section contains this RVA
        for section in sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                let offset_in_section = (rva - section.virtual_address) as usize;
                if offset_in_section < section.data.len() {
                    // Read null-terminated string from section data
                    let string_data = &section.data[offset_in_section..];
                    let null_pos = string_data
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(string_data.len());
                    return Ok(String::from_utf8_lossy(&string_data[..null_pos]).to_string());
                }
            }
        }

        Err(WindowsShimError::InvalidPeBinary(format!(
            "String at RVA 0x{rva:X} not found"
        )))
    }

    /// Read a u64 value at the given RVA (for Import Lookup Table entries)
    fn read_u64_at_rva(&self, rva: u32) -> Result<u64> {
        let sections = self.sections()?;

        // Find which section contains this RVA
        for section in sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                let offset_in_section = (rva - section.virtual_address) as usize;
                if offset_in_section + 8 <= section.data.len() {
                    // SAFETY: We checked bounds above. Using read_unaligned to avoid alignment issues.
                    #[allow(clippy::cast_ptr_alignment)]
                    let value = unsafe {
                        section
                            .data
                            .as_ptr()
                            .add(offset_in_section)
                            .cast::<u64>()
                            .read_unaligned()
                    };
                    return Ok(value);
                }
            }
        }

        Err(WindowsShimError::InvalidPeBinary(format!(
            "u64 at RVA 0x{rva:X} not found or out of bounds"
        )))
    }

    /// Parse the Import Lookup Table to get function names for a DLL
    fn parse_import_lookup_table(&self, ilt_rva: u32) -> Result<Vec<String>> {
        let mut functions = Vec::new();
        let mut current_rva = ilt_rva;

        // For 64-bit PE, each entry is 8 bytes
        loop {
            let entry = self.read_u64_at_rva(current_rva)?;

            // Null entry marks end of list
            if entry == 0 {
                break;
            }

            // Check if import is by ordinal (bit 63 set)
            if (entry & 0x8000_0000_0000_0000) != 0 {
                // Import by ordinal - store as "Ordinal_N"
                let ordinal = entry & 0xFFFF;
                functions.push(format!("Ordinal_{ordinal}"));
            } else {
                // Import by name - RVA points to IMAGE_IMPORT_BY_NAME structure
                // Skip the hint (first 2 bytes) and read the function name
                let name_rva = (entry & 0x7FFF_FFFF) as u32;
                let function_name = self.read_string_at_rva(name_rva + 2)?;
                functions.push(function_name);
            }

            current_rva += 8; // Move to next entry (8 bytes for 64-bit)
        }

        Ok(functions)
    }

    /// Parse import directory and return list of imported DLLs
    pub fn imports(&self) -> Result<Vec<ImportedDll>> {
        let import_dir = self.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)?;

        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            // No imports
            return Ok(Vec::new());
        }

        let sections = self.sections()?;
        let mut imports = Vec::new();

        // Find the section containing the import directory
        let import_section = sections
            .iter()
            .find(|s| {
                import_dir.virtual_address >= s.virtual_address
                    && import_dir.virtual_address < s.virtual_address + s.virtual_size
            })
            .ok_or_else(|| {
                WindowsShimError::InvalidPeBinary(
                    "Import directory not found in any section".to_string(),
                )
            })?;

        let import_offset_in_section =
            (import_dir.virtual_address - import_section.virtual_address) as usize;

        // Read import descriptors
        let mut descriptor_offset = import_offset_in_section;
        loop {
            if descriptor_offset + core::mem::size_of::<ImportDescriptor>()
                > import_section.data.len()
            {
                break;
            }

            // SAFETY: We checked bounds above.
            // Using read_unaligned to avoid alignment issues.
            #[allow(clippy::cast_ptr_alignment)]
            let descriptor = unsafe {
                import_section
                    .data
                    .as_ptr()
                    .add(descriptor_offset)
                    .cast::<ImportDescriptor>()
                    .read_unaligned()
            };

            // Null descriptor marks end of list
            if descriptor.name == 0 {
                break;
            }

            // Read DLL name
            let dll_name = self.read_string_at_rva(descriptor.name)?;

            // Parse the Import Lookup Table to get function names
            // Use original_first_thunk if available, otherwise use first_thunk
            let ilt_rva = if descriptor.original_first_thunk != 0 {
                descriptor.original_first_thunk
            } else {
                descriptor.first_thunk
            };

            let functions = self.parse_import_lookup_table(ilt_rva)?;

            imports.push(ImportedDll {
                name: dll_name,
                iat_rva: descriptor.first_thunk,
                functions,
            });

            descriptor_offset += core::mem::size_of::<ImportDescriptor>();
        }

        Ok(imports)
    }

    /// Parse base relocation directory and return list of relocations
    pub fn relocations(&self) -> Result<Vec<Relocation>> {
        let reloc_dir = self.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)?;

        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            // No relocations
            return Ok(Vec::new());
        }

        let sections = self.sections()?;
        let mut relocations = Vec::new();

        // Find the section containing the relocation directory
        let reloc_section = sections
            .iter()
            .find(|s| {
                reloc_dir.virtual_address >= s.virtual_address
                    && reloc_dir.virtual_address < s.virtual_address + s.virtual_size
            })
            .ok_or_else(|| {
                WindowsShimError::InvalidPeBinary(
                    "Relocation directory not found in any section".to_string(),
                )
            })?;

        let reloc_offset_in_section =
            (reloc_dir.virtual_address - reloc_section.virtual_address) as usize;

        // Parse relocation blocks
        let mut block_offset = reloc_offset_in_section;
        let reloc_end = reloc_offset_in_section + reloc_dir.size as usize;

        while block_offset + core::mem::size_of::<BaseRelocationBlock>() <= reloc_section.data.len()
            && block_offset < reloc_end
        {
            // SAFETY: We checked bounds above.
            // Using read_unaligned to avoid alignment issues.
            #[allow(clippy::cast_ptr_alignment)]
            let block = unsafe {
                reloc_section
                    .data
                    .as_ptr()
                    .add(block_offset)
                    .cast::<BaseRelocationBlock>()
                    .read_unaligned()
            };

            if block.size_of_block == 0 {
                break;
            }

            // Number of relocation entries in this block
            let num_entries =
                (block.size_of_block as usize - core::mem::size_of::<BaseRelocationBlock>()) / 2;

            // Read relocation entries
            let entries_offset = block_offset + core::mem::size_of::<BaseRelocationBlock>();
            for i in 0..num_entries {
                let entry_offset = entries_offset + i * 2;
                if entry_offset + 2 > reloc_section.data.len() {
                    break;
                }

                // SAFETY: We checked bounds above.
                #[allow(clippy::cast_ptr_alignment)]
                let entry = unsafe {
                    reloc_section
                        .data
                        .as_ptr()
                        .add(entry_offset)
                        .cast::<u16>()
                        .read_unaligned()
                };

                let reloc_type = entry >> 12;
                let offset = entry & 0x0FFF;

                if reloc_type != IMAGE_REL_BASED_ABSOLUTE {
                    relocations.push(Relocation {
                        reloc_type,
                        rva: block.virtual_address + u32::from(offset),
                    });
                }
            }

            block_offset += block.size_of_block as usize;
        }

        Ok(relocations)
    }

    /// Parse TLS directory and return TLS information
    ///
    /// Returns None if there is no TLS directory, or Some(TlsInfo) if TLS is present.
    pub fn tls_info(&self) -> Result<Option<TlsInfo>> {
        let tls_dir = self.get_data_directory(IMAGE_DIRECTORY_ENTRY_TLS)?;

        if tls_dir.virtual_address == 0 || tls_dir.size == 0 {
            // No TLS
            return Ok(None);
        }

        let sections = self.sections()?;

        // Find the section containing the TLS directory
        let tls_section = sections
            .iter()
            .find(|s| {
                tls_dir.virtual_address >= s.virtual_address
                    && tls_dir.virtual_address < s.virtual_address + s.virtual_size
            })
            .ok_or_else(|| {
                WindowsShimError::InvalidPeBinary(
                    "TLS directory not found in any section".to_string(),
                )
            })?;

        let tls_offset_in_section =
            (tls_dir.virtual_address - tls_section.virtual_address) as usize;

        if tls_offset_in_section + core::mem::size_of::<TlsDirectory64>() > tls_section.data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "TLS directory out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above.
        // Using read_unaligned to avoid alignment issues.
        #[allow(clippy::cast_ptr_alignment)]
        let tls_directory = unsafe {
            tls_section
                .data
                .as_ptr()
                .add(tls_offset_in_section)
                .cast::<TlsDirectory64>()
                .read_unaligned()
        };

        Ok(Some(TlsInfo {
            start_address: tls_directory.start_address_of_raw_data,
            end_address: tls_directory.end_address_of_raw_data,
            address_of_index: tls_directory.address_of_index,
            size_of_zero_fill: tls_directory.size_of_zero_fill,
            address_of_callbacks: tls_directory.address_of_call_backs,
        }))
    }

    /// Get exception directory information for SEH support
    ///
    /// Returns the RVA and size of the exception table (.pdata section) if present.
    /// The exception table contains `IMAGE_RUNTIME_FUNCTION_ENTRY` records used by
    /// `RtlLookupFunctionEntry` to locate unwind information for a given program counter.
    ///
    /// Returns `None` if no exception directory exists in the PE binary.
    /// Returns an error if the exception directory range is outside the loaded sections.
    pub fn exception_directory(&self) -> Result<Option<ExceptionDirectoryInfo>> {
        let dir = self.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;

        if dir.virtual_address == 0 || dir.size == 0 {
            return Ok(None);
        }

        // Validate that [virtual_address, virtual_address + size) lies within
        // a known section, preventing malformed PEs from advertising an out-of-range
        // .pdata RVA that could cause RtlLookupFunctionEntry to read unmapped memory.
        let end_rva = dir.virtual_address.checked_add(dir.size).ok_or_else(|| {
            WindowsShimError::InvalidPeBinary(
                "Exception directory range overflows RVA space".to_string(),
            )
        })?;

        let sections = self.sections()?;
        let in_section = sections.iter().any(|s| {
            let sec_end = s.virtual_address.saturating_add(s.virtual_size);
            dir.virtual_address >= s.virtual_address && end_rva <= sec_end
        });
        if !in_section {
            return Err(WindowsShimError::InvalidPeBinary(
                "Exception directory not contained within any section".to_string(),
            ));
        }

        Ok(Some(ExceptionDirectoryInfo {
            rva: dir.virtual_address,
            size: dir.size,
        }))
    }

    /// Apply relocations when loading at a different base address
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `base_address` points to a valid, writable memory region
    /// - The memory region contains the loaded PE image
    /// - The memory region remains valid for the operation
    pub unsafe fn apply_relocations(&self, base_address: u64, actual_base: u64) -> Result<()> {
        if base_address == actual_base {
            // No relocation needed
            return Ok(());
        }

        let delta = actual_base.wrapping_sub(base_address).cast_signed();
        let relocations = self.relocations()?;

        let mut crt_relocs = 0;
        for reloc in &relocations {
            let target_address = actual_base + u64::from(reloc.rva);

            // Count .CRT section relocations (RVA 0xD2000-0xD2068)
            if reloc.rva >= 0xD2000 && reloc.rva < 0xD2100 {
                crt_relocs += 1;
            }

            match reloc.reloc_type {
                IMAGE_REL_BASED_DIR64 => {
                    // SAFETY: Caller guarantees base_address is valid
                    unsafe {
                        let ptr = target_address as *mut u64;
                        let old_value = ptr.read_unaligned();
                        let new_value = old_value.cast_signed().wrapping_add(delta).cast_unsigned();
                        ptr.write_unaligned(new_value);
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // SAFETY: Caller guarantees base_address is valid
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    unsafe {
                        let ptr = target_address as *mut u32;
                        let old_value = ptr.read_unaligned();
                        let new_value = (i64::from(old_value).wrapping_add(delta)) as u32;
                        ptr.write_unaligned(new_value);
                    }
                }
                _ => {
                    // Ignore unknown relocation types
                }
            }
        }

        // Debug: Report if .CRT section had relocations
        #[cfg(debug_assertions)]
        if crt_relocs > 0 {
            // CRT relocations found - this is good!
        }

        Ok(())
    }

    /// Write resolved function addresses to the Import Address Table
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `base_address` points to a valid, writable memory region
    /// - The memory region contains the loaded PE image
    /// - `resolved_functions` contains valid function addresses for all imports
    pub unsafe fn write_iat(
        &self,
        base_address: u64,
        _dll_name: &str,
        iat_rva: u32,
        resolved_functions: &[u64],
    ) -> Result<()> {
        // Calculate the actual IAT address
        let iat_address = base_address + u64::from(iat_rva);

        // Write each function address to the IAT
        for (i, &func_addr) in resolved_functions.iter().enumerate() {
            let entry_address = iat_address + (i as u64 * 8); // 8 bytes per entry for 64-bit

            // SAFETY: Caller guarantees base_address is valid
            unsafe {
                let ptr = entry_address as *mut u64;
                ptr.write_unaligned(func_addr);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_too_small() {
        let data = vec![0; 10];
        let result = PeLoader::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_dos_signature() {
        let mut data = vec![0; 64];
        data[0] = 0x00; // Wrong signature
        data[1] = 0x00;
        let result = PeLoader::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_imports_empty() {
        // Create a minimal PE with no imports
        // For now, just test that calling imports() doesn't crash
        // on a minimal valid PE structure
        // This is a placeholder - real test would use a proper PE binary
        let data = vec![0; 64];
        let result = PeLoader::new(data);
        assert!(result.is_err()); // Will fail because it's not a valid PE
    }

    #[test]
    fn test_relocations_empty() {
        // Similar placeholder test for relocations
        let data = vec![0; 64];
        let result = PeLoader::new(data);
        assert!(result.is_err()); // Will fail because it's not a valid PE
    }

    /// Helper to create a minimal valid PE binary for testing
    fn create_minimal_pe(section_data: &[u8], virtual_address: u32, virtual_size: u32) -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // DOS header
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'
        // e_lfanew at offset 60 (0x3C) - point to PE header at offset 128
        let pe_offset: u32 = 128;
        data[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature at offset 128
        let pe_sig: u32 = 0x00004550;
        data[128..132].copy_from_slice(&pe_sig.to_le_bytes());

        // COFF File Header (20 bytes) at offset 132
        let file_header_offset = 132;
        // Machine = AMD64 (0x8664)
        data[file_header_offset..file_header_offset + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections = 1
        data[file_header_offset + 2..file_header_offset + 4].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader
        let opt_header_size =
            core::mem::size_of::<OptionalHeader64>() + 16 * core::mem::size_of::<DataDirectory>();
        #[allow(clippy::cast_possible_truncation)]
        let opt_header_size_u16 = opt_header_size as u16;
        data[file_header_offset + 16..file_header_offset + 18]
            .copy_from_slice(&opt_header_size_u16.to_le_bytes());

        // Optional Header (PE32+) at offset 152
        let opt_offset = file_header_offset + 20;
        // Magic = PE32+ (0x20B)
        data[opt_offset..opt_offset + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        // ImageBase
        data[opt_offset + 24..opt_offset + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // SectionAlignment
        data[opt_offset + 32..opt_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment
        data[opt_offset + 36..opt_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
        // NumberOfRvaAndSizes = 16
        data[opt_offset + 108..opt_offset + 112].copy_from_slice(&16u32.to_le_bytes());

        // Section header follows after optional header + data directories
        let section_offset = opt_offset + opt_header_size;

        // Section name ".test\0\0\0"
        data[section_offset..section_offset + 5].copy_from_slice(b".test");
        // VirtualSize
        data[section_offset + 8..section_offset + 12].copy_from_slice(&virtual_size.to_le_bytes());
        // VirtualAddress
        data[section_offset + 12..section_offset + 16]
            .copy_from_slice(&virtual_address.to_le_bytes());
        // SizeOfRawData
        #[allow(clippy::cast_possible_truncation)]
        let raw_size = section_data.len() as u32;
        data[section_offset + 16..section_offset + 20].copy_from_slice(&raw_size.to_le_bytes());
        // PointerToRawData (put data at offset 512)
        let raw_data_offset = 512u32;
        data[section_offset + 20..section_offset + 24]
            .copy_from_slice(&raw_data_offset.to_le_bytes());
        // Characteristics (readable, writable)
        data[section_offset + 36..section_offset + 40]
            .copy_from_slice(&0xC0000040u32.to_le_bytes());

        // Copy section data
        let start = raw_data_offset as usize;
        let end = start + section_data.len();
        if end <= data.len() {
            data[start..end].copy_from_slice(section_data);
        }

        data
    }

    #[test]
    fn test_patch_ctor_list_basic() {
        // Create section data with a __CTOR_LIST__ pattern:
        // [-1] [0 terminator] — simplest valid __CTOR_LIST__
        let va = 0x1000u32;

        let mut section_data = vec![0u8; 256];
        // Write -1 sentinel at offset 0
        section_data[0..8].copy_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_le_bytes());
        // Write 0 terminator at offset 8 (makes it a valid __CTOR_LIST__)
        section_data[8..16].copy_from_slice(&0u64.to_le_bytes());

        let pe = PeLoader::new(create_minimal_pe(&section_data, va, 256)).unwrap();

        // Allocate memory and load sections
        let mem = vec![0u8; 0x2000];
        let mem_base = mem.as_ptr() as u64;

        unsafe {
            pe.load_sections(mem_base).unwrap();
            pe.patch_ctor_list(mem_base).unwrap();
        }

        // Verify the sentinel was patched to 0
        let patched_value = unsafe { ((mem_base + u64::from(va)) as *const u64).read_unaligned() };
        assert_eq!(patched_value, 0, "Sentinel should be patched to 0");
    }

    #[test]
    fn test_patch_ctor_list_no_sentinel() {
        // Create section data WITHOUT any __CTOR_LIST__ pattern
        let va = 0x1000u32;
        let mut section_data = vec![0u8; 256];
        // Write some regular data
        section_data[0..8].copy_from_slice(&0x12345678u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0xABCDu64.to_le_bytes());

        let pe = PeLoader::new(create_minimal_pe(&section_data, va, 256)).unwrap();

        let mem = vec![0u8; 0x2000];
        let mem_base = mem.as_ptr() as u64;

        unsafe {
            pe.load_sections(mem_base).unwrap();
            pe.patch_ctor_list(mem_base).unwrap();
        }

        // Verify data was not modified
        let value = unsafe { ((mem_base + u64::from(va)) as *const u64).read_unaligned() };
        assert_eq!(value, 0x12345678, "Non-sentinel data should be unchanged");

        // Verify adjacent data was also not modified
        let value2 = unsafe { ((mem_base + u64::from(va) + 8) as *const u64).read_unaligned() };
        assert_eq!(value2, 0xABCD, "Adjacent data should be unchanged");
    }
}
