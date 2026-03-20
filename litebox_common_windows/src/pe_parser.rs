// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE file parser.
//!
//! Parses a PE/COFF file from a byte slice, validating headers and extracting
//! section table, import directory, export directory, relocation table, and
//! TLS directory information.

use alloc::string::String;
use alloc::vec::Vec;
use zerocopy::FromBytes;

use crate::pe::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_SIGNATURE,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory, ImageDosHeader, ImageExportDirectory,
    ImageFileHeader, ImageImportDescriptor, ImageOptionalHeader64, ImageSectionHeader,
    image_file_chars,
};

/// Errors that can occur during PE parsing.
#[derive(Debug)]
pub enum PeParseError {
    /// File is too small to contain the expected header.
    TooSmall,
    /// Invalid DOS signature (expected "MZ").
    BadDosSignature,
    /// Invalid PE signature (expected "PE\0\0").
    BadPeSignature,
    /// Unsupported machine type.
    UnsupportedMachine(u16),
    /// Unsupported optional header magic (expected PE32+).
    UnsupportedMagic(u16),
    /// A section header references data outside the file.
    SectionOutOfBounds,
    /// The PE has more data directories than expected.
    TooManyDataDirectories,
}

impl core::fmt::Display for PeParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "file too small"),
            Self::BadDosSignature => write!(f, "invalid DOS signature"),
            Self::BadPeSignature => write!(f, "invalid PE signature"),
            Self::UnsupportedMachine(m) => write!(f, "unsupported machine type: 0x{m:04X}"),
            Self::UnsupportedMagic(m) => write!(f, "unsupported optional header magic: 0x{m:04X}"),
            Self::SectionOutOfBounds => write!(f, "section data out of bounds"),
            Self::TooManyDataDirectories => write!(f, "too many data directories"),
        }
    }
}

/// A parsed PE file. Holds references into the original byte slice.
#[derive(Debug)]
pub struct PeParsedFile {
    /// The COFF file header.
    pub file_header: ImageFileHeader,
    /// The PE32+ optional header.
    pub optional_header: ImageOptionalHeader64,
    /// Data directory entries.
    pub data_directories: Vec<ImageDataDirectory>,
    /// Section headers.
    pub sections: Vec<ImageSectionHeader>,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Preferred image base.
    pub image_base: u64,
    /// Required alignment of sections when mapped into memory.
    pub section_alignment: u32,
    /// Required alignment of sections in the file.
    pub file_alignment: u32,
    /// Total size of the image when mapped (from optional header).
    pub size_of_image: u32,
    /// Size of headers (DOS + PE + section headers, rounded to file_alignment).
    pub size_of_headers: u32,
    /// True if this is a DLL (IMAGE_FILE_DLL set in characteristics).
    pub is_dll: bool,
}

impl PeParsedFile {
    /// Parse a PE file from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, PeParseError> {
        // DOS header
        let dos = ImageDosHeader::read_from_prefix(data)
            .map_err(|_| PeParseError::TooSmall)?
            .0;
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeParseError::BadDosSignature);
        }

        let pe_offset = dos.e_lfanew as usize;

        // PE signature
        let pe_sig = u32::read_from_prefix(data.get(pe_offset..).ok_or(PeParseError::TooSmall)?)
            .map_err(|_| PeParseError::TooSmall)?
            .0;
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err(PeParseError::BadPeSignature);
        }

        // COFF file header
        let fh_offset = pe_offset + 4;
        let file_header =
            ImageFileHeader::read_from_prefix(data.get(fh_offset..).ok_or(PeParseError::TooSmall)?)
                .map_err(|_| PeParseError::TooSmall)?
                .0;

        if file_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeParseError::UnsupportedMachine(file_header.machine));
        }

        // Optional header
        let oh_offset = fh_offset + size_of::<ImageFileHeader>();
        let optional_header = ImageOptionalHeader64::read_from_prefix(
            data.get(oh_offset..).ok_or(PeParseError::TooSmall)?,
        )
        .map_err(|_| PeParseError::TooSmall)?
        .0;

        if optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeParseError::UnsupportedMagic(optional_header.magic));
        }

        // Data directories (follow immediately after the fixed optional header fields)
        let dd_offset = oh_offset + size_of::<ImageOptionalHeader64>();
        let num_dirs = optional_header.number_of_rva_and_sizes as usize;
        if num_dirs > IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
            return Err(PeParseError::TooManyDataDirectories);
        }
        let mut data_directories = Vec::with_capacity(num_dirs);
        for i in 0..num_dirs {
            let off = dd_offset + i * size_of::<ImageDataDirectory>();
            let dd = ImageDataDirectory::read_from_prefix(
                data.get(off..).ok_or(PeParseError::TooSmall)?,
            )
            .map_err(|_| PeParseError::TooSmall)?
            .0;
            data_directories.push(dd);
        }

        // Section headers
        let sh_offset = oh_offset + file_header.size_of_optional_header as usize;
        let num_sections = file_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let off = sh_offset + i * size_of::<ImageSectionHeader>();
            let sh = ImageSectionHeader::read_from_prefix(
                data.get(off..).ok_or(PeParseError::TooSmall)?,
            )
            .map_err(|_| PeParseError::TooSmall)?
            .0;

            // Validate that raw data is within bounds
            if sh.size_of_raw_data > 0 {
                let end = sh.pointer_to_raw_data as usize + sh.size_of_raw_data as usize;
                if end > data.len() {
                    return Err(PeParseError::SectionOutOfBounds);
                }
            }

            sections.push(sh);
        }

        let is_dll = file_header.characteristics & image_file_chars::IMAGE_FILE_DLL != 0;

        Ok(Self {
            file_header,
            optional_header,
            data_directories,
            sections,
            entry_point: optional_header.address_of_entry_point,
            image_base: optional_header.image_base,
            section_alignment: optional_header.section_alignment,
            file_alignment: optional_header.file_alignment,
            size_of_image: optional_header.size_of_image,
            size_of_headers: optional_header.size_of_headers,
            is_dll,
        })
    }

    /// Get a data directory entry by index, or `None` if the index is out of
    /// range or the directory has zero size.
    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        self.data_directories.get(index).filter(|dd| dd.size > 0)
    }

    /// Resolve an RVA to a file offset using the section table.
    ///
    /// Returns `None` if the RVA doesn't fall within any section's raw data.
    /// Uses `max(virtual_size, size_of_raw_data)` as the section span, since
    /// some toolchains emit `virtual_size == 0` or `virtual_size < size_of_raw_data`.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let sec_start = section.virtual_address;
            // The addressable span is the larger of virtual_size and raw_data size.
            // Some linkers leave virtual_size at 0 (meaning "same as raw data"),
            // and others set it shorter than size_of_raw_data.
            let span = section.virtual_size.max(section.size_of_raw_data);
            if span == 0 {
                continue;
            }
            let sec_end = sec_start + span;
            if rva >= sec_start && rva < sec_end {
                let offset_in_section = rva - sec_start;
                if offset_in_section < section.size_of_raw_data {
                    return Some(section.pointer_to_raw_data as usize + offset_in_section as usize);
                }
                // RVA is in the virtual (zero-filled) portion beyond raw data
                return None;
            }
        }
        None
    }

    /// Read a null-terminated ASCII string at the given RVA from the file data.
    pub fn read_string_at_rva<'a>(&self, data: &'a [u8], rva: u32) -> Option<&'a str> {
        let offset = self.rva_to_file_offset(rva)?;
        let remaining = data.get(offset..)?;
        let nul_pos = remaining.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&remaining[..nul_pos]).ok()
    }

    /// Iterator over import descriptors. Returns (DLL name, list of imported function names).
    pub fn imports<'a>(&self, data: &'a [u8]) -> Vec<PeImport<'a>> {
        let dd = match self.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(dd) => dd,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut offset = match self.rva_to_file_offset(dd.virtual_address) {
            Some(o) => o,
            None => return Vec::new(),
        };

        loop {
            let desc =
                match ImageImportDescriptor::read_from_prefix(data.get(offset..).unwrap_or(&[])) {
                    Ok((d, _)) => d,
                    Err(_) => break,
                };

            // A zeroed-out descriptor marks the end of the import table.
            if desc.name == 0 {
                break;
            }

            let dll_name = self
                .read_string_at_rva(data, desc.name)
                .unwrap_or("<invalid>");

            // Read import names from the Import Lookup Table (ILT)
            let ilt_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };

            let mut functions = Vec::new();
            if let Some(mut ilt_off) = self.rva_to_file_offset(ilt_rva) {
                loop {
                    let entry = match u64::read_from_prefix(data.get(ilt_off..).unwrap_or(&[])) {
                        Ok((v, _)) => v,
                        Err(_) => break,
                    };

                    if entry == 0 {
                        break;
                    }

                    // Bit 63 set means import by ordinal
                    if entry & (1u64 << 63) != 0 {
                        functions.push(ImportEntry::Ordinal((entry & 0xFFFF) as u16));
                    } else {
                        // Import by name: entry is an RVA to a hint/name table entry
                        // (2-byte hint + null-terminated name string)
                        let hint_rva = entry as u32;
                        if let Some(name_off) = self.rva_to_file_offset(hint_rva) {
                            // Skip 2-byte hint
                            let name_start = name_off + 2;
                            if let Some(remaining) = data.get(name_start..)
                                && let Some(nul_pos) = remaining.iter().position(|&b| b == 0)
                                && let Ok(name) = core::str::from_utf8(&remaining[..nul_pos])
                            {
                                functions.push(ImportEntry::Name(name));
                            }
                        }
                    }

                    ilt_off += 8; // sizeof(u64)
                }
            }

            result.push(PeImport {
                dll_name,
                iat_rva: desc.first_thunk,
                functions,
            });

            offset += size_of::<ImageImportDescriptor>();
        }

        result
    }

    /// Iterate over exported functions. Includes both named exports and
    /// ordinal-only exports (those present in the EAT but not in the name
    /// table).
    pub fn exports<'a>(&self, data: &'a [u8]) -> Vec<PeExport<'a>> {
        let dd = match self.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(dd) => dd,
            None => return Vec::new(),
        };

        let export_dir_offset = match self.rva_to_file_offset(dd.virtual_address) {
            Some(o) => o,
            None => return Vec::new(),
        };

        let export_dir = match ImageExportDirectory::read_from_prefix(
            data.get(export_dir_offset..).unwrap_or(&[]),
        ) {
            Ok((d, _)) => d,
            Err(_) => return Vec::new(),
        };

        let num_functions = export_dir.number_of_functions as usize;
        let num_names = export_dir.number_of_names as usize;

        // Build a map from EAT index → names by walking the name/ordinal
        // arrays. Multiple names can alias the same EAT slot (export aliases),
        // so we collect all names per slot.
        let mut names_for_index: Vec<Vec<&str>> = (0..num_functions).map(|_| Vec::new()).collect();
        for i in 0..num_names {
            let ord_off = match self
                .rva_to_file_offset(export_dir.address_of_name_ordinals + (i as u32) * 2)
            {
                Some(o) => o,
                None => continue,
            };
            let ordinal_index = match u16::read_from_prefix(data.get(ord_off..).unwrap_or(&[])) {
                Ok((v, _)) => v as usize,
                Err(_) => continue,
            };
            if ordinal_index >= num_functions {
                continue;
            }

            let name_rva_off =
                match self.rva_to_file_offset(export_dir.address_of_names + (i as u32) * 4) {
                    Some(o) => o,
                    None => continue,
                };
            let name_rva = match u32::read_from_prefix(data.get(name_rva_off..).unwrap_or(&[])) {
                Ok((v, _)) => v,
                Err(_) => continue,
            };
            if let Some(name) = self.read_string_at_rva(data, name_rva) {
                names_for_index[ordinal_index].push(name);
            }
        }

        // Walk the full Export Address Table. For EAT slots with multiple
        // names (aliases), emit one PeExport per name so that a name-based
        // resolver can find all of them.
        let mut result = Vec::with_capacity(num_functions);
        #[allow(clippy::needless_range_loop)] // eat_index is used for both arithmetic and indexing
        for eat_index in 0..num_functions {
            let func_off = match self
                .rva_to_file_offset(export_dir.address_of_functions + (eat_index as u32) * 4)
            {
                Some(o) => o,
                None => continue,
            };
            let func_rva = match u32::read_from_prefix(data.get(func_off..).unwrap_or(&[])) {
                Ok((v, _)) => v,
                Err(_) => continue,
            };

            // An EAT entry of 0 means the ordinal slot is unused.
            if func_rva == 0 {
                continue;
            }

            let ordinal = export_dir.base + eat_index as u32;

            // Check if this is a forwarder: the function RVA points inside the
            // export directory itself.
            let is_forwarder =
                func_rva >= dd.virtual_address && func_rva < dd.virtual_address + dd.size;

            let forwarder = if is_forwarder {
                self.read_string_at_rva(data, func_rva).map(|s| {
                    let mut parts = s.splitn(2, '.');
                    let dll = parts.next().unwrap_or("");
                    let func = parts.next().unwrap_or("");
                    Forwarder {
                        dll: String::from(dll),
                        function: String::from(func),
                    }
                })
            } else {
                None
            };

            let names = &names_for_index[eat_index];
            if names.is_empty() {
                // Ordinal-only export.
                result.push(PeExport {
                    name: None,
                    ordinal,
                    rva: func_rva,
                    forwarder,
                });
            } else {
                // Emit one entry per name alias.
                for &name in names {
                    result.push(PeExport {
                        name: Some(name),
                        ordinal,
                        rva: func_rva,
                        forwarder: forwarder.clone(),
                    });
                }
            }
        }

        result
    }

    /// Get the section name as a string (trimmed of trailing nulls).
    pub fn section_name(section: &ImageSectionHeader) -> &str {
        let end = section
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(section.name.len());
        core::str::from_utf8(&section.name[..end]).unwrap_or("<invalid>")
    }
}

/// An imported DLL and its functions.
#[derive(Debug)]
pub struct PeImport<'a> {
    /// DLL name (e.g., "ntdll.dll").
    pub dll_name: &'a str,
    /// RVA of the IAT for this import.
    pub iat_rva: u32,
    /// Imported functions.
    pub functions: Vec<ImportEntry<'a>>,
}

/// A single import entry: either by name or by ordinal.
#[derive(Debug)]
pub enum ImportEntry<'a> {
    Name(&'a str),
    Ordinal(u16),
}

/// An exported function.
#[derive(Debug)]
pub struct PeExport<'a> {
    /// Function name, or `None` for ordinal-only exports.
    pub name: Option<&'a str>,
    /// Export ordinal.
    pub ordinal: u32,
    /// Function RVA (if not a forwarder).
    pub rva: u32,
    /// If this export is a forwarder, the target DLL.function.
    pub forwarder: Option<Forwarder>,
}

/// A forwarded export target: `DLL.FunctionName`.
#[derive(Debug, Clone)]
pub struct Forwarder {
    pub dll: String,
    pub function: String,
}
