//! Functions for validating kernel module ELFs

use crate::{debug_serial_println, mshv::vsm::ModuleMemoryContent, serial_println};
use alloc::{vec, vec::Vec};
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

/// This function validates the code sections (`.text` and `.init.text`) of a kernel module ELF.
/// In particular, this function checks the integrity of "non-relocatable bytes" in ELF. We check the
/// signature of the entire ELF (including relocation information) before calling this function,
/// so what the adversary can do with relocatable bytes is limited.
pub fn validate_module_elf(
    elf_buf: &[u8],
    module_memory: &ModuleMemoryContent,
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

    for target_section in [".text", ".init.text"] {
        // in-memory ELF section (with VTL0's relocations applied)
        let section_memory = module_memory
            .find_section_by_name(target_section)
            .expect("Section not found in module memory");
        if section_memory.is_empty() {
            continue;
        }

        let Some(target_shdr) = shdrs.iter().find(|s| {
            s.sh_flags & u64::from(SHF_ALLOC) != 0
                && s.sh_size > 0
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

        // load original ELF section (no relocation applied)
        let mut section_buf = vec![0u8; usize::try_from(target_shdr.sh_size).unwrap()];
        section_buf.copy_from_slice(
            &elf_buf[usize::try_from(target_shdr.sh_offset).unwrap()
                ..usize::try_from(target_shdr.sh_offset + target_shdr.sh_size).unwrap()],
        );

        // figure out relocatable ranges
        let mut reloc_ranges = RangeSet::<usize>::new();
        get_symbol_relocations(elf_params, target_section, &section_buf, &mut reloc_ranges)?;
        get_section_relocations(elf_params, target_section, &section_buf, &mut reloc_ranges)?;

        let mut to_validate = vec![0u8; section_buf.len()];
        section_memory
            .read_bytes(section_memory.start().unwrap(), &mut to_validate)
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        // check whether non-relocatable bytes are modified
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
    Ok(result)
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

// This function handles symbol-based relocations in `.rela.text` or `.rela.init.text` sections.
fn get_symbol_relocations(
    elf_params: ElfParams<'_>,
    target_section: &str,
    section_buf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    assert!(matches!(target_section, ".text" | ".init.text"));
    if let Some(rela_shdr) = elf_params.shdrs.iter().find(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
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
            if let Ok(sym) = elf_params.symtab.get(usize::try_from(rela.r_sym).unwrap()) {
                if let Ok(sym_name) = elf_params
                    .sym_strtab
                    .get(usize::try_from(sym.st_name).unwrap())
                {
                    if sym_name.is_empty()
                        && elf_params
                            .shdr_strtab
                            .get(usize::from(sym.st_shndx))
                            .is_err()
                    {
                        // neither symbol nor section relocation
                        continue;
                    }
                }
            }

            let reloc_size: u64 = match rela.r_type {
                R_X86_64_64 => 8,
                R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                _ => {
                    todo!("Unsupported relocation type {:?}", rela.r_type);
                }
            };
            if usize::try_from(rela.r_offset + reloc_size).unwrap() <= section_buf.len() {
                reloc_ranges.insert(
                    usize::try_from(rela.r_offset).unwrap()
                        ..usize::try_from(rela.r_offset + reloc_size).unwrap(),
                );
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

// This function handles `.rela.*` sections which can relocate `.text` or `.init.text` (section-based relocations).
// A rela section can relocate `.text` or `init.text` sections if it has unnamed symbols which belong to these sections.
fn get_section_relocations(
    elf_params: ElfParams<'_>,
    target_section: &str,
    section_buf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    for shdr in elf_params.shdrs.iter().filter(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
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
            let Ok(sym) = elf_params.symtab.get(usize::try_from(rela.r_sym).unwrap()) else {
                continue;
            };
            if let Ok(sym_name) = elf_params
                .sym_strtab
                .get(usize::try_from(sym.st_name).unwrap())
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
                    elf_params
                        .shdr_strtab
                        .get(usize::try_from(s.sh_name).unwrap())
                        .map(|n| n == target_section)
                })
                .is_ok()
            {
                let reloc_size: u64 = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };

                // section-based relocation relies on `r_addend` to specify the relocation offset
                if rela.r_addend >= 0
                    && usize::try_from(u64::try_from(rela.r_addend).unwrap() + reloc_size).unwrap()
                        <= section_buf.len()
                {
                    reloc_ranges.insert(
                        usize::try_from(rela.r_addend).unwrap()
                            ..usize::try_from(u64::try_from(rela.r_addend).unwrap() + reloc_size)
                                .unwrap(),
                    );

                    // handle some exceptions which depend on sections
                    let section_name = elf_params
                        .shdr_strtab
                        .get(usize::try_from(shdr.sh_name).unwrap())
                        .map_err(|_| KernelElfError::ElfParseFailed)?;
                    // `.rela.altinstructions` could patch `nop` which is one byte prior to the specified relocation.
                    if section_name == ".rela.altinstructions"
                        && rela.r_addend > 0
                        && section_buf[usize::try_from(rela.r_addend - 1).unwrap()] == 0x90
                    {
                        reloc_ranges.insert(
                            usize::try_from(rela.r_addend - 1).unwrap()
                                ..usize::try_from(rela.r_addend).unwrap(),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// This function parses the `.modinfo` section of a kernel module ELF
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
            && shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == ".modinfo")
    }) {
        let start = usize::try_from(shdr.sh_offset).unwrap();
        let end = start + usize::try_from(shdr.sh_size).unwrap();
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
