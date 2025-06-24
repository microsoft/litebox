//! Functions for validating kernel module ELFs

#[cfg(debug_assertions)]
use alloc::vec::Vec;

use crate::{debug_serial_println, mshv::vsm::ModuleMemory, serial_println};
use alloc::vec;
use elf::{
    ElfBytes,
    abi::{
        R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32, SHF_ALLOC, SHT_RELA,
    },
    endian::AnyEndian,
    parse::ParsingTable,
    section::SectionHeader,
    string_table::StringTable,
    symbol::Symbol,
};
use rangemap::set::RangeSet;

/// This function validates certain code (`.text`, `.init.text`) and data (`.init.rodata`, `.data..ro_after_init`)
/// sections of a kernel module ELF. It checks the integrity of "non-relocatable/patchable bytes" in ELF. Since
/// we check the signature of the entire ELF (including relocation and patch information) before calling this function,
/// the number of relocatable/patchable bytes under the adversary's control is limited.
pub fn validate_kernel_module_elf(
    elf_buf: &[u8],
    module_memory: &ModuleMemory,
) -> Result<bool, KernelElfError> {
    let mut result = true;

    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_buf)
        .map_err(|_| KernelElfError::ElfParseFailed)?;
    let Ok((Some(shdrs), Some(shdr_strtab))) = elf.section_headers_with_strtab() else {
        return Err(KernelElfError::ElfParseFailed);
    };
    let Ok(Some((symtab, sym_strtab))) = elf.symbol_table() else {
        return Err(KernelElfError::ElfParseFailed);
    };

    for target_section in sections_to_validate() {
        // in-memory ELF section (with VTL0's relocations and patches applied)
        let section_memory = module_memory
            .find_section_by_name(target_section)
            .expect("Section not found in module memory");
        if section_memory.is_empty() {
            continue;
        }

        let Some(target_shdr) = shdrs.iter().find(|s| {
            s.sh_flags & u64::from(SHF_ALLOC) != 0
                && s.sh_size > 0
                && usize::try_from(s.sh_name).is_ok()
                && shdr_strtab
                    .get(usize::try_from(s.sh_name).unwrap())
                    .is_ok_and(|n| n == target_section)
        }) else {
            return Err(KernelElfError::SectionNotFound);
        };

        let elf_params = ElfParams {
            elf: &elf,
            shdrs: &shdrs,
            shdr_strtab: &shdr_strtab,
            symtab: &symtab,
            sym_strtab: &sym_strtab,
        };

        // load original ELF section (no relocation and patch applied)
        let start =
            usize::try_from(target_shdr.sh_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
        let end = start
            .checked_add(
                usize::try_from(target_shdr.sh_size).map_err(|_| KernelElfError::ElfParseFailed)?,
            )
            .ok_or(KernelElfError::ElfParseFailed)?;
        let mut section_buf = vec![0u8; end - start];
        section_buf.copy_from_slice(&elf_buf[start..end]);

        // figure out relocatable ranges
        let mut reloc_ranges = RangeSet::<usize>::new();
        get_symbol_relocations(elf_params, target_section, &section_buf, &mut reloc_ranges)?;
        get_binary_patches(elf_params, target_section, &section_buf, &mut reloc_ranges)?;

        let mut to_validate = vec![0u8; section_buf.len()];
        section_memory
            .read_bytes(
                section_memory
                    .start()
                    .ok_or(KernelElfError::SectionReadFailed)?,
                &mut to_validate,
            )
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        // check whether non-relocatable bytes are modified
        #[cfg(not(debug_assertions))]
        {
            for reloc in reloc_ranges {
                section_buf[reloc.clone()].copy_from_slice(&to_validate[reloc.clone()]);
            }
            if section_buf != to_validate {
                serial_println!("Found {} mismatches in {target_section}", target_section);
                result = false;
            }
        }
        #[cfg(debug_assertions)]
        {
            let mut diffs = Vec::new();
            for non_reloc in reloc_ranges.gaps(&(0..section_buf.len())) {
                for i in non_reloc {
                    if section_buf[i] != to_validate[i] {
                        diffs.push(i);
                    }
                }
            }
            if !diffs.is_empty() {
                serial_println!(
                    "Found {} mismatches in {target_section} at {:?}",
                    diffs.len(),
                    diffs
                );
                result = false;
            }
        }
    }
    Ok(result)
}

// a list of sections which we validate
fn sections_to_validate() -> [&'static str; 4] {
    [
        ".text",
        ".init.text",
        ".init.rodata",
        ".data..ro_after_init",
    ]
}

// for passing ELF-related parameters around local functions
#[derive(Copy, Clone)]
struct ElfParams<'a> {
    elf: &'a ElfBytes<'a, AnyEndian>,
    shdrs: &'a ParsingTable<'a, AnyEndian, SectionHeader>,
    shdr_strtab: &'a StringTable<'a>,
    symtab: &'a ParsingTable<'a, AnyEndian, Symbol>,
    sym_strtab: &'a StringTable<'a>,
}

// This function handles symbol-based relocations in `.rela.<target_section>` sections.
fn get_symbol_relocations(
    elf_params: ElfParams<'_>,
    target_section: &str,
    section_buf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    if !sections_to_validate().contains(&target_section) {
        return Err(KernelElfError::SectionNotFound);
    }
    if let Some(rela_shdr) = elf_params.shdrs.iter().find(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
            && usize::try_from(s.sh_name).is_ok()
            && elf_params
                .shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == [".rela", target_section].join(""))
    }) {
        let relas = elf_params
            .elf
            .section_data_as_relas(&rela_shdr)
            .map_err(|_| KernelElfError::ElfParseFailed)?;
        for rela in relas {
            let r_sym = usize::try_from(rela.r_sym).map_err(|_| KernelElfError::ElfParseFailed)?;
            let r_offset =
                usize::try_from(rela.r_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
            if elf_params.symtab.get(r_sym).is_ok() {
                let reloc_size: usize = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };
                let start = r_offset;
                if let Some(end) = start
                    .checked_add(reloc_size)
                    .filter(|&end| end <= section_buf.len())
                {
                    reloc_ranges.insert(start..end);
                }
            }
        }
    } else {
        return Err(KernelElfError::SectionNotFound);
    }
    Ok(())
}

// Allowed list of relocation sections. We do not consider other relocation sections like `.rela.debug_*`
#[inline]
fn is_allowed_rela_section(name: &str) -> bool {
    matches!(
        name,
        ".rela.altinstructions"
            | ".rela.call_sites"
            | ".rela.ibt_endbr_seal"
            | ".rela.parainstructions"
            | ".rela.retpoline_sites"
            | ".rela.return_sites"
            | ".rela__patchable_function_entries"
    )
}

// This function handles `.rela.*` sections which can patch our target sections. For example,
// a rela section can relocate `.text` if it has unnamed symbols which belong to `.text`.
fn get_binary_patches(
    elf_params: ElfParams<'_>,
    target_section: &str,
    section_buf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    for shdr in elf_params.shdrs.iter().filter(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
            && usize::try_from(s.sh_name).is_ok()
            && elf_params
                .shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(is_allowed_rela_section)
    }) {
        let relas = elf_params
            .elf
            .section_data_as_relas(&shdr)
            .map_err(|_| KernelElfError::ElfParseFailed)?;
        for rela in relas {
            let r_sym = usize::try_from(rela.r_sym).map_err(|_| KernelElfError::ElfParseFailed)?;
            let r_addend =
                usize::try_from(rela.r_addend).map_err(|_| KernelElfError::ElfParseFailed)?;
            let Ok(sym) = elf_params.symtab.get(r_sym) else {
                continue;
            };
            if let Ok(sym_name) = elf_params
                .sym_strtab
                .get(usize::try_from(sym.st_name).map_err(|_| KernelElfError::ElfParseFailed)?)
            {
                if !sym_name.is_empty() {
                    continue;
                }
            }

            // checks whether an unnamed symbol belongs to the target section
            if elf_params
                .shdrs
                .get(usize::from(sym.st_shndx))
                .and_then(|s| {
                    if let Ok(sh_name) = usize::try_from(s.sh_name) {
                        elf_params
                            .shdr_strtab
                            .get(sh_name)
                            .map(|n| n == target_section)
                    } else {
                        Err(elf::ParseError::IntegerOverflow)
                    }
                })
                .is_ok()
            {
                let reloc_size: usize = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };

                // section-based binary patching relies on `r_addend` to specify the offsets to patch
                let start = r_addend;
                if let Some(end) = start
                    .checked_add(reloc_size)
                    .filter(|&end| end <= section_buf.len())
                {
                    reloc_ranges.insert(start..end);

                    // handle some exceptions which depend on sections
                    let section_name = elf_params
                        .shdr_strtab
                        .get(
                            usize::try_from(shdr.sh_name)
                                .map_err(|_| KernelElfError::ElfParseFailed)?,
                        )
                        .map_err(|_| KernelElfError::ElfParseFailed)?;
                    // `.rela.altinstructions` could patch `nop` which is one byte prior to the specified relocation.
                    if section_name == ".rela.altinstructions"
                        && start > 0
                        && section_buf[start - 1] == 0x90
                    {
                        reloc_ranges.insert(start - 1..start);
                    }
                }
            }
        }
    }
    Ok(())
}

/// This function parses the `.modinfo` section of a kernel module ELF
#[cfg(debug_assertions)]
pub fn parse_modinfo(elf_buf: &[u8]) -> Result<(), KernelElfError> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_buf)
        .map_err(|_| KernelElfError::ElfParseFailed)?;

    let (shdrs_opt, shdr_strtab_opt) = elf
        .section_headers_with_strtab()
        .map_err(|_| KernelElfError::ElfParseFailed)?;
    let shdrs = shdrs_opt.ok_or(KernelElfError::ElfParseFailed)?;
    let shdr_strtab = shdr_strtab_opt.ok_or(KernelElfError::ElfParseFailed)?;

    if let Some(shdr) = shdrs.iter().find(|s| {
        s.sh_flags & u64::from(SHF_ALLOC) != 0
            && s.sh_size > 0
            && usize::try_from(s.sh_name).is_ok()
            && shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == ".modinfo")
    }) {
        let start = usize::try_from(shdr.sh_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
        let end = start
            .checked_add(usize::try_from(shdr.sh_size).map_err(|_| KernelElfError::ElfParseFailed)?)
            .ok_or(KernelElfError::ElfParseFailed)?;
        let modinfo_data = &elf_buf[start..end];

        for entry in modinfo_data.split(|&b| b == 0) {
            if let Ok(s) = str::from_utf8(entry) {
                if let Some((k, v)) = s.split_once('=') {
                    if k == "name" {
                        debug_serial_println!("Modinfo: {} = {}", k, v);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Error for Kernel ELF validation and relocation failures.
#[derive(Debug, PartialEq)]
pub enum KernelElfError {
    SectionReadFailed,
    ElfParseFailed,
    SectionNotFound,
}
