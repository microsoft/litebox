use crate::{
    debug_serial_println,
    mshv::vsm::{MemoryContent, ModuleMemoryContent},
};
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

/// This function validates the code sections (`.text` and `.init.text`) of a kernel module ELF file.
/// Basically, this function checks the integrity of "non-relocatable bytes" in ELF. We checks the
/// signature of the ELF file before validating the relocations, so what the adversary can do is
/// still limited.
pub fn validate_module_elf(
    elf_buf: &[u8],
    mod_mem: &ModuleMemoryContent,
) -> Result<bool, KernelElfError> {
    let mut result = true;

    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_buf)
        .map_err(|_| KernelElfError::ElfParseFailed)?;

    let (shdrs_opt, shdr_strtab_opt) = elf
        .section_headers_with_strtab()
        .map_err(|_| KernelElfError::ElfParseFailed)?;
    let shdrs = shdrs_opt.ok_or(KernelElfError::ElfParseFailed)?;
    let shdr_strtab = shdr_strtab_opt.ok_or(KernelElfError::ElfParseFailed)?;

    let Some((symtab, sym_strtab)) = elf
        .symbol_table()
        .map_err(|_| KernelElfError::ElfParseFailed)?
    else {
        return Err(KernelElfError::ElfParseFailed);
    };

    for target_section in [".text", ".init.text"] {
        // in-memory ELF section (with VTL0's relocations applied)
        let sect_mem = mod_mem
            .find_section_by_name(target_section)
            .expect("Section not found in module memory");
        if sect_mem.is_empty() {
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

        // load original ELF section (no relocation applied)
        let mut reloc_buf = vec![0u8; usize::try_from(target_shdr.sh_size).unwrap()];
        reloc_buf.copy_from_slice(
            &elf_buf[usize::try_from(target_shdr.sh_offset).unwrap()
                ..usize::try_from(target_shdr.sh_offset + target_shdr.sh_size).unwrap()],
        );

        symbol_relocation(
            ElfParams {
                elf: &elf,
                shdrs: &shdrs,
                shdr_strtab: &shdr_strtab,
                symtab: &symtab,
                sym_strtab: &sym_strtab,
            },
            target_section,
            sect_mem,
            &mut reloc_buf,
        )?;

        section_relocation(
            ElfParams {
                elf: &elf,
                shdrs: &shdrs,
                shdr_strtab: &shdr_strtab,
                symtab: &symtab,
                sym_strtab: &sym_strtab,
            },
            target_section,
            sect_mem,
            &mut reloc_buf,
        )?;

        // compare the loaded section with the relocated section
        let mut loaded = vec![0u8; reloc_buf.iter().len()];
        sect_mem
            .read_bytes(sect_mem.start().unwrap(), &mut loaded)
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        for (i, (&r, &l)) in reloc_buf.iter().zip(loaded.iter()).enumerate() {
            if r != l {
                debug_serial_println!("Mismatch at {i:#x} reloc = {r:#x}, loaded = {l:#x}");
                result = false;
            }
        }
    }

    Ok(result)
}

// for passing ELF-related parameters around local functions
struct ElfParams<'a> {
    elf: &'a ElfBytes<'a, AnyEndian>,
    shdrs: &'a ParsingTable<'a, AnyEndian, SectionHeader>,
    shdr_strtab: &'a StringTable<'a>,
    symtab: &'a ParsingTable<'a, AnyEndian, Symbol>,
    sym_strtab: &'a StringTable<'a>,
}

// This function handles `.rela.text` or `.rela.init.text` section (symbol-based relocations)
fn symbol_relocation(
    elf_params: ElfParams<'_>,
    target_section: &str,
    sect_mem: &MemoryContent,
    reloc_buf: &mut [u8],
) -> Result<(), KernelElfError> {
    if let Some(rela_shdr) = elf_params.shdrs.iter().find(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
            && elf_params
                .shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == [".rela", target_section].join(""))
    }) {
        // accept known relocations. additional security checks could be applied.
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

            let patch_size: u64 = match rela.r_type {
                R_X86_64_64 => 8,
                R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                _ => {
                    todo!("Unsupported relocation type {:?}", rela.r_type);
                }
            };
            if usize::try_from(rela.r_offset + patch_size).unwrap() <= reloc_buf.iter().len() {
                sect_mem
                    .read_bytes(
                        sect_mem.start().unwrap() + rela.r_offset,
                        &mut reloc_buf[usize::try_from(rela.r_offset).unwrap()
                            ..usize::try_from(rela.r_offset + patch_size).unwrap()],
                    )
                    .map_err(|_| KernelElfError::SectionRelocationFailed)?;
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
// In particular, if some sections have symbols with empty names which belong to `.text` or `.init.text`,
// they can relocate these sections.
fn section_relocation(
    elf_params: ElfParams<'_>,
    target_section: &str,
    sect_mem: &MemoryContent,
    reloc_buf: &mut [u8],
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
                    // symbol name is not empty, so it isn't a section-based relocation
                    continue;
                }
            }

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
                let patch_size: u64 = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };

                // section-based relocation uses `r_addend` to specify the offset
                if rela.r_addend >= 0
                    && usize::try_from(u64::try_from(rela.r_addend).unwrap() + patch_size).unwrap()
                        <= reloc_buf.iter().len()
                {
                    sect_mem
                        .read_bytes(
                            sect_mem.start().unwrap() + u64::try_from(rela.r_addend).unwrap(),
                            &mut reloc_buf[usize::try_from(rela.r_addend).unwrap()
                                ..usize::try_from(
                                    u64::try_from(rela.r_addend).unwrap() + patch_size,
                                )
                                .unwrap()],
                        )
                        .map_err(|_| KernelElfError::SectionRelocationFailed)?;

                    // exceptions.
                    let section_name = elf_params
                        .shdr_strtab
                        .get(usize::try_from(shdr.sh_name).unwrap())
                        .map_err(|_| KernelElfError::ElfParseFailed)?;
                    // `.rela.altinstructions` could patch `nop` which is 1-byte prior to the specified relocation.
                    if section_name == ".rela.altinstructions"
                        && rela.r_addend > 0
                        && reloc_buf[usize::try_from(rela.r_addend - 1).unwrap()] == 0x90
                    {
                        reloc_buf[usize::try_from(rela.r_addend - 1).unwrap()] = sect_mem
                            .read_byte(
                                sect_mem.start().unwrap()
                                    + u64::try_from(rela.r_addend - 1).unwrap(),
                            )
                            .unwrap();
                    }
                }
            }
        }
    }
    Ok(())
}

/// This function parses the `.modinfo` section of the kernel module ELF file and prints its contents.
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
    SectionRelocationFailed,
    ElfParseFailed,
    SectionNotFound,
}
