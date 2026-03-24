// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE image loader.
//!
//! Maps a parsed PE file into guest virtual memory using a caller-provided
//! [`PeMemoryMapper`] trait. The loader:
//!
//! 1. Maps PE headers at the image base
//! 2. Maps each section at `base + section.virtual_address`
//! 3. Applies base relocations if the image was rebased
//! 4. Returns [`PeLoadInfo`] with entry point, import directory, etc.
//!
//! The loader is platform-agnostic — the shim provides the concrete mapper
//! implementation backed by [`PageManager`].

use alloc::vec::Vec;

use crate::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_REL_BASED_DIR64, ImageBaseRelocation,
};
use crate::pe_parser::PeParsedFile;

/// Section permission flags matching PE section characteristics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SectionPermissions {
    ReadExecute,
    ReadWrite,
    ReadOnly,
}

/// Errors during PE loading.
#[derive(Debug)]
pub enum PeLoadError {
    /// The mapper failed to allocate or map memory.
    MapFailed,
    /// The PE image has no relocation data but needs to be rebased.
    CannotRebase,
    /// A relocation entry references an address outside the image.
    BadRelocation,
    /// The PE file is malformed (truncated section data, etc.).
    Malformed,
    /// An imported DLL was not found among the loaded modules.
    UnresolvedModule(alloc::string::String),
    /// An imported function was not found in the provider DLL.
    UnresolvedImport {
        dll: alloc::string::String,
        function: alloc::string::String,
    },
}

impl core::fmt::Display for PeLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MapFailed => write!(f, "memory mapping failed"),
            Self::CannotRebase => write!(f, "image requires rebase but has no .reloc"),
            Self::BadRelocation => write!(f, "relocation references address outside image"),
            Self::Malformed => write!(f, "PE file is malformed"),
            Self::UnresolvedModule(name) => write!(f, "imported module not found: {name}"),
            Self::UnresolvedImport { dll, function } => {
                write!(f, "unresolved import: {dll}!{function}")
            }
        }
    }
}

/// Trait for mapping PE sections into guest memory.
///
/// The PE loader calls these methods to allocate and populate guest VA pages.
/// The shim implements this using `PageManager`.
pub trait PeMemoryMapper {
    /// Map a region at the given guest virtual address.
    ///
    /// - `va`: page-aligned guest virtual address
    /// - `data`: file bytes to copy (may be shorter than `size`)
    /// - `size`: total allocation size (page-aligned, >= data.len())
    /// - `perm`: desired protection
    ///
    /// The region from `data.len()..size` must be zero-filled (BSS).
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), PeLoadError>;
}

/// Information about a loaded PE image.
#[derive(Debug)]
pub struct PeLoadInfo {
    /// The actual base address where the image was loaded.
    pub image_base: usize,
    /// The absolute virtual address of the entry point.
    pub entry_point: usize,
    /// Total size of the mapped image.
    pub image_size: usize,
    /// RVA and size of the import directory (for import resolution).
    pub import_dir_rva: Option<u32>,
    pub import_dir_size: Option<u32>,
    /// RVA of the TLS directory, if present.
    pub tls_dir_rva: Option<u32>,
    /// Whether the image was rebased from its preferred address.
    pub rebased: bool,
}

/// Page-align a value upward.
fn page_align_up(value: usize) -> usize {
    (value + 0xFFF) & !0xFFF
}

/// Determine the permissions for a PE section from its characteristics.
fn section_permissions(characteristics: u32) -> SectionPermissions {
    use crate::pe::section_chars::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    let exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    // Executable sections are RX, writable sections are RW, otherwise RO.
    if exec {
        SectionPermissions::ReadExecute
    } else if write {
        SectionPermissions::ReadWrite
    } else {
        SectionPermissions::ReadOnly
    }
}

/// Load a PE image into guest memory.
///
/// `parsed` and `pe_data` are the parsed PE and its raw bytes.
/// `base_address` is the guest VA where the image should be loaded.
/// If it differs from `parsed.image_base`, the loader applies base
/// relocations to a copy of the PE bytes before mapping, so that all
/// sections get their correct final permissions (no RW→RX fixup needed).
///
/// The `mapper` performs the actual page allocation.
pub fn load_pe(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    base_address: usize,
    mapper: &mut impl PeMemoryMapper,
) -> Result<PeLoadInfo, PeLoadError> {
    load_pe_inner(parsed, pe_data, base_address, mapper, true)
}

/// Load a PE into memory, optionally skipping relocation processing.
///
/// When `apply_relocations` is false, the image is mapped with raw data
/// (no fixups applied). The caller (e.g., ntdll's loader) is expected to
/// handle relocations itself; the mapper returns `STATUS_IMAGE_NOT_AT_BASE`.
pub fn load_pe_no_reloc(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    base_address: usize,
    mapper: &mut impl PeMemoryMapper,
) -> Result<PeLoadInfo, PeLoadError> {
    load_pe_inner(parsed, pe_data, base_address, mapper, false)
}

fn load_pe_inner(
    parsed: &PeParsedFile,
    pe_data: &[u8],
    base_address: usize,
    mapper: &mut impl PeMemoryMapper,
    apply_relocations: bool,
) -> Result<PeLoadInfo, PeLoadError> {
    let preferred_base = parsed.image_base as usize;
    let needs_rebase = base_address != preferred_base;
    let image_size = parsed.size_of_image as usize;

    // If rebase is needed and we're applying relocations, verify the image
    // has a relocation directory.
    if needs_rebase
        && apply_relocations
        && parsed
            .data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .is_none()
    {
        return Err(PeLoadError::CannotRebase);
    }

    // Pre-apply relocations to a mutable copy of the PE bytes so that
    // sections are mapped with their correct final permissions (RX stays RX).
    let relocated;
    let effective_data = if needs_rebase && apply_relocations {
        relocated = {
            let mut buf = alloc::vec::Vec::from(pe_data);
            apply_relocations_to_buffer(parsed, &mut buf, parsed.image_base, base_address as u64)?;
            buf
        };
        &relocated[..]
    } else {
        pe_data
    };

    // Step 1: Map PE headers (everything up to the first section).
    let headers_size = parsed.size_of_headers as usize;
    let headers_page_size = page_align_up(headers_size);
    mapper.map_section(
        base_address,
        &effective_data[..headers_size.min(effective_data.len())],
        headers_page_size,
        SectionPermissions::ReadOnly,
    )?;

    // Step 2: Map each section with its final permissions.
    for section in &parsed.sections {
        let section_va = base_address + section.virtual_address as usize;
        let virtual_size = section.virtual_size as usize;
        let raw_size = section.size_of_raw_data as usize;
        let section_size = virtual_size.max(raw_size);
        if section_size == 0 {
            continue;
        }
        let map_size = page_align_up(section_size);
        let perm = section_permissions(section.characteristics);

        // File data to copy. Some images legitimately have
        // SizeOfRawData > VirtualSize, and the loader must preserve the full
        // file-backed contents rather than truncating to VirtualSize.
        let raw_offset = section.pointer_to_raw_data as usize;
        let copy_len = raw_size.min(section_size);

        let file_data = if copy_len > 0 && raw_offset + copy_len <= effective_data.len() {
            &effective_data[raw_offset..raw_offset + copy_len]
        } else if copy_len > 0 && raw_offset < effective_data.len() {
            // Truncated — copy what we can.
            &effective_data[raw_offset..]
        } else {
            // Pure BSS section (no file data).
            &[]
        };

        mapper.map_section(section_va, file_data, map_size, perm)?;
    }

    // Collect import directory info.
    let (import_dir_rva, import_dir_size) = parsed
        .data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .map_or((None, None), |dd| (Some(dd.virtual_address), Some(dd.size)));

    let tls_dir_rva = parsed
        .data_directory(IMAGE_DIRECTORY_ENTRY_TLS)
        .map(|dd| dd.virtual_address);

    let entry_point = base_address + parsed.entry_point as usize;

    Ok(PeLoadInfo {
        image_base: base_address,
        entry_point,
        image_size,
        import_dir_rva,
        import_dir_size,
        rebased: needs_rebase,
        tls_dir_rva,
    })
}

/// Apply base relocations directly to an in-memory image buffer.
///
/// This is the simpler variant used when you have a mutable copy of the
/// entire image (e.g., for stub DLLs built in memory). Mutates `image`
/// in place.
///
/// # Panics
///
/// Panics if relocation entries reference offsets beyond the image buffer.
pub fn apply_relocations_to_buffer(
    parsed: &PeParsedFile,
    image: &mut [u8],
    old_base: u64,
    new_base: u64,
) -> Result<(), PeLoadError> {
    let dd = match parsed.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(dd) => dd,
        None => return Ok(()),
    };

    let delta = new_base as i64 - old_base as i64;
    if delta == 0 {
        return Ok(());
    }

    let mut offset = match parsed.rva_to_file_offset(dd.virtual_address) {
        Some(o) => o,
        None => return Err(PeLoadError::Malformed),
    };

    let reloc_end = offset + dd.size as usize;

    while offset + size_of::<ImageBaseRelocation>() <= reloc_end {
        let block: ImageBaseRelocation =
            match zerocopy::FromBytes::read_from_prefix(&image[offset..]) {
                Ok((b, _)) => b,
                Err(_) => break,
            };

        if block.size_of_block == 0 {
            break;
        }

        let entries_start = offset + size_of::<ImageBaseRelocation>();
        let entries_end = (offset + block.size_of_block as usize)
            .min(reloc_end)
            .min(image.len());

        let mut entry_offset = entries_start;
        while entry_offset + 2 <= entries_end {
            let entry = u16::from_le_bytes([image[entry_offset], image[entry_offset + 1]]);
            let reloc_type = entry >> 12;
            let reloc_offset = u32::from(entry & 0x0FFF);

            match reloc_type {
                0 => {} // IMAGE_REL_BASED_ABSOLUTE — skip.
                IMAGE_REL_BASED_DIR64 => {
                    let fixup_rva = block.virtual_address + reloc_offset;
                    let fixup_off = match parsed.rva_to_file_offset(fixup_rva) {
                        Some(o) => o,
                        None => return Err(PeLoadError::BadRelocation),
                    };
                    if fixup_off + 8 > image.len() {
                        return Err(PeLoadError::BadRelocation);
                    }
                    let old_val =
                        i64::from_le_bytes(image[fixup_off..fixup_off + 8].try_into().unwrap());
                    let new_val = old_val + delta;
                    image[fixup_off..fixup_off + 8].copy_from_slice(&new_val.to_le_bytes());
                }
                _ => {} // Unknown type — skip.
            }

            entry_offset += 2;
        }

        offset += block.size_of_block as usize;
        if block.size_of_block as usize <= size_of::<ImageBaseRelocation>() {
            break;
        }
    }

    Ok(())
}

/// Information about a loaded module (DLL or EXE) used for import resolution.
#[derive(Debug)]
pub struct LoadedModule<'a> {
    /// Module name (e.g., "ntdll.dll").
    pub name: &'a str,
    /// Base address where the module is loaded in guest VA.
    pub base_address: usize,
    /// The raw PE bytes (for export lookup).
    pub pe_data: &'a [u8],
    /// Parsed PE file.
    pub parsed: &'a PeParsedFile,
}

/// Resolve imports for a loaded PE against a set of loaded modules.
///
/// Walks the import directory of `target`, looks up each imported function
/// in the appropriate `module`, and returns a list of IAT patches to apply.
///
/// The caller is responsible for writing the patches to guest memory.
pub fn resolve_imports(
    target: &PeParsedFile,
    target_data: &[u8],
    target_base: usize,
    modules: &[LoadedModule<'_>],
) -> Result<Vec<IatPatch>, PeLoadError> {
    resolve_imports_inner(target, target_data, target_base, modules, None)
}

/// Like `resolve_imports`, but unresolved imports are patched with
/// `fallback_va` instead of returning an error.  The names of skipped
/// imports are collected in the returned `Vec<String>`.
pub fn resolve_imports_lenient(
    target: &PeParsedFile,
    target_data: &[u8],
    target_base: usize,
    modules: &[LoadedModule<'_>],
    fallback_va: u64,
) -> Result<(Vec<IatPatch>, Vec<alloc::string::String>), PeLoadError> {
    let mut skipped = Vec::new();
    let patches = resolve_imports_inner(
        target,
        target_data,
        target_base,
        modules,
        Some((fallback_va, &mut skipped)),
    )?;
    Ok((patches, skipped))
}

fn resolve_imports_inner(
    target: &PeParsedFile,
    target_data: &[u8],
    target_base: usize,
    modules: &[LoadedModule<'_>],
    mut fallback: Option<(u64, &mut Vec<alloc::string::String>)>,
) -> Result<Vec<IatPatch>, PeLoadError> {
    let imports = target.imports(target_data);
    let mut patches = Vec::new();

    for import in &imports {
        // Resolve API-set names to physical DLL names.
        let dll_name = crate::apiset::resolve_apiset(import.dll_name).unwrap_or(import.dll_name);

        // Find the module that provides this DLL, but never resolve
        // a module's imports against itself (self-imports create infinite
        // JMP-to-self loops when an export thunk forwards through the IAT).
        let module = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(dll_name) && m.base_address != target_base);

        let module = if let Some(m) = module {
            m
        } else {
            if let Some((fb_va, ref mut skipped)) = fallback {
                // Patch all imports from this unknown DLL with fallback.
                let mut iat_rva = import.iat_rva;
                for func in &import.functions {
                    let desc = match func {
                        crate::pe_parser::ImportEntry::Name(n) => {
                            alloc::format!("{dll_name}!{n}")
                        }
                        crate::pe_parser::ImportEntry::Ordinal(o) => {
                            alloc::format!("{dll_name}!ordinal#{o}")
                        }
                    };
                    skipped.push(desc);
                    let iat_va = target_base + iat_rva as usize;
                    patches.push(IatPatch {
                        iat_va,
                        resolved_va: fb_va,
                    });
                    iat_rva += 8;
                }
                continue;
            }
            return Err(PeLoadError::UnresolvedModule(alloc::string::String::from(
                dll_name,
            )));
        };

        let module_exports = module.parsed.exports(module.pe_data);

        // Patch each imported function.
        let mut iat_rva = import.iat_rva;
        for func in &import.functions {
            let found_export = match func {
                crate::pe_parser::ImportEntry::Name(name) => {
                    module_exports.iter().find(|e| e.name == Some(name))
                }
                crate::pe_parser::ImportEntry::Ordinal(ord) => {
                    module_exports.iter().find(|e| e.ordinal == u32::from(*ord))
                }
            };

            // Resolve the export, following forwarder chains.
            let resolved_va = if let Some(exp) = found_export {
                resolve_export(exp, module, modules, target_base, 8)
            } else {
                None
            };

            if let Some(va) = resolved_va {
                let iat_va = target_base + iat_rva as usize;
                patches.push(IatPatch {
                    iat_va,
                    resolved_va: va as u64,
                });
            } else {
                let func_desc = match func {
                    crate::pe_parser::ImportEntry::Name(n) => alloc::string::String::from(*n),
                    crate::pe_parser::ImportEntry::Ordinal(o) => {
                        alloc::format!("ordinal #{o}")
                    }
                };

                if let Some((fb_va, ref mut skipped)) = fallback {
                    skipped.push(alloc::format!("{dll_name}!{func_desc}"));
                    let iat_va = target_base + iat_rva as usize;
                    patches.push(IatPatch {
                        iat_va,
                        resolved_va: fb_va,
                    });
                } else {
                    return Err(PeLoadError::UnresolvedImport {
                        dll: alloc::string::String::from(dll_name),
                        function: func_desc,
                    });
                }
            }

            iat_rva += 8; // Each IAT entry is 8 bytes (64-bit pointer).
        }
    }

    Ok(patches)
}

/// A single IAT patch: write `resolved_va` to guest memory at `iat_va`.
#[derive(Debug, Clone)]
pub struct IatPatch {
    /// Guest virtual address of the IAT slot.
    pub iat_va: usize,
    /// Resolved absolute virtual address to write into the IAT slot.
    pub resolved_va: u64,
}

/// Resolve an export to a concrete virtual address, following forwarder chains.
///
/// If the export is a direct export, returns `module.base_address + rva`.
/// If the export is a forwarder (e.g., `"NTDLL.RtlFoo"`), looks up the target
/// in `modules` and recurses. `depth` limits recursion to prevent cycles.
/// Returns `None` if the forwarder target cannot be found.
fn resolve_export(
    exp: &crate::pe_parser::PeExport<'_>,
    module: &LoadedModule<'_>,
    modules: &[LoadedModule<'_>],
    target_base: usize,
    depth: usize,
) -> Option<usize> {
    if depth == 0 {
        return None;
    }

    match &exp.forwarder {
        None => {
            // Direct export — return the VA.
            Some(module.base_address + exp.rva as usize)
        }
        Some(fwd) => {
            // Forwarded export: resolve the target DLL + function.
            let fwd_dll_full = alloc::format!("{}.dll", fwd.dll);
            let fwd_dll_name =
                crate::apiset::resolve_apiset(&fwd_dll_full).unwrap_or(&fwd_dll_full);

            // Find the target module (excluding self to prevent cycles).
            let target_module = modules.iter().find(|m| {
                m.name.eq_ignore_ascii_case(fwd_dll_name) && m.base_address != target_base
            })?;

            let target_exports = target_module.parsed.exports(target_module.pe_data);
            let target_exp = target_exports.iter().find(|e| {
                if let Some(name) = e.name {
                    name == fwd.function
                } else {
                    false
                }
            })?;

            resolve_export(target_exp, target_module, modules, target_base, depth - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_builder::{StubExport, build_stub_dll};
    use crate::pe_parser::PeParsedFile;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A test mapper that records what was mapped.
    struct TestMapper {
        mappings: Vec<(usize, usize, SectionPermissions)>,
        // Simulated memory at base address (sparse).
        memory: alloc::collections::BTreeMap<usize, Vec<u8>>,
    }

    impl TestMapper {
        fn new() -> Self {
            Self {
                mappings: Vec::new(),
                memory: alloc::collections::BTreeMap::new(),
            }
        }
    }

    impl PeMemoryMapper for TestMapper {
        fn map_section(
            &mut self,
            va: usize,
            data: &[u8],
            size: usize,
            perm: SectionPermissions,
        ) -> Result<(), PeLoadError> {
            self.mappings.push((va, size, perm));
            let mut buf = alloc::vec![0u8; size];
            buf[..data.len()].copy_from_slice(data);
            self.memory.insert(va, buf);
            Ok(())
        }
    }

    #[test]
    fn load_stub_dll() {
        let exports = vec![
            StubExport::syscall_stub("NtClose", 0x0006),
            StubExport::syscall_stub("NtWriteFile", 0x0001),
        ];

        let base: u64 = 0x1800_0000_0000;
        let dll_bytes = build_stub_dll("ntdll.dll", &exports, base);
        let parsed = PeParsedFile::parse(&dll_bytes).unwrap();

        let mut mapper = TestMapper::new();
        let info = load_pe(&parsed, &dll_bytes, base as usize, &mut mapper).unwrap();

        assert_eq!(info.image_base, base as usize);
        assert!(!info.rebased);
        // Should have mapped headers + 3 sections (.text, .edata, .reloc)
        assert_eq!(mapper.mappings.len(), 4);

        // Headers should be RO
        assert_eq!(mapper.mappings[0].2, SectionPermissions::ReadOnly);
        // .text should be RX
        assert_eq!(mapper.mappings[1].2, SectionPermissions::ReadExecute);
    }

    #[test]
    fn load_pe_preserves_raw_bytes_beyond_virtual_size() {
        let exports = vec![
            StubExport::syscall_stub("NtClose", 0x0006),
            StubExport::syscall_stub("NtWriteFile", 0x0001),
        ];
        let base: u64 = 0x1800_0000_0000;
        let mut dll_bytes = build_stub_dll("ntdll.dll", &exports, base);

        let pe_offset = u32::from_le_bytes(dll_bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let num_sections =
            u16::from_le_bytes(dll_bytes[pe_offset + 6..pe_offset + 8].try_into().unwrap())
                as usize;
        let optional_header_size = u16::from_le_bytes(
            dll_bytes[pe_offset + 20..pe_offset + 22]
                .try_into()
                .unwrap(),
        ) as usize;
        let section_table_offset = pe_offset + 24 + optional_header_size;

        let mut expected_va = None;
        let mut expected_tail_offset = 0usize;
        let mut expected_tail_bytes = Vec::new();

        for index in 0..num_sections {
            let section_offset = section_table_offset + index * 40;
            let virtual_address = u32::from_le_bytes(
                dll_bytes[section_offset + 12..section_offset + 16]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let raw_size = u32::from_le_bytes(
                dll_bytes[section_offset + 16..section_offset + 20]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let raw_offset = u32::from_le_bytes(
                dll_bytes[section_offset + 20..section_offset + 24]
                    .try_into()
                    .unwrap(),
            ) as usize;
            if raw_size < 16 || raw_offset + raw_size > dll_bytes.len() {
                continue;
            }

            let new_virtual_size = raw_size - 16;
            for (i, byte) in dll_bytes[raw_offset + new_virtual_size..raw_offset + raw_size]
                .iter_mut()
                .enumerate()
            {
                *byte = 0xA0u8.wrapping_add(i as u8);
            }
            let tail = dll_bytes[raw_offset + new_virtual_size..raw_offset + raw_size].to_vec();

            dll_bytes[section_offset + 8..section_offset + 12]
                .copy_from_slice(&(new_virtual_size as u32).to_le_bytes());
            expected_va = Some(base as usize + virtual_address);
            expected_tail_offset = new_virtual_size;
            expected_tail_bytes = tail;
            break;
        }

        let expected_va = expected_va.expect("failed to find section with non-zero raw overhang");
        let parsed = PeParsedFile::parse(&dll_bytes).unwrap();
        let mut mapper = TestMapper::new();
        load_pe(&parsed, &dll_bytes, base as usize, &mut mapper).unwrap();

        let mapped = mapper.memory.get(&expected_va).unwrap();
        assert_eq!(
            &mapped[expected_tail_offset..expected_tail_offset + expected_tail_bytes.len()],
            expected_tail_bytes.as_slice()
        );
    }

    #[test]
    fn resolve_imports_between_modules() {
        // Build ntdll stub.
        let ntdll_exports = vec![
            StubExport::syscall_stub("NtWriteFile", 0x0001),
            StubExport::syscall_stub("NtClose", 0x0006),
        ];
        let ntdll_base: u64 = 0x1800_0000_0000;
        let ntdll_bytes = build_stub_dll("ntdll.dll", &ntdll_exports, ntdll_base);
        let ntdll_parsed = PeParsedFile::parse(&ntdll_bytes).unwrap();

        // Build a "client" DLL that imports from ntdll.
        // For this test, we just verify the resolve_imports function works
        // with the ntdll module. We use ntdll itself as both source and target
        // (it has no imports, so the result should be empty).
        let modules = [LoadedModule {
            name: "ntdll.dll",
            base_address: ntdll_base as usize,
            pe_data: &ntdll_bytes,
            parsed: &ntdll_parsed,
        }];

        let patches =
            resolve_imports(&ntdll_parsed, &ntdll_bytes, ntdll_base as usize, &modules).unwrap();

        // ntdll has no imports, so no patches.
        assert!(patches.is_empty());
    }
}
