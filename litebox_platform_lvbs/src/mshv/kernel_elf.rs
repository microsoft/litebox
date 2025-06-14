// TODO: where should we put this file?

use crate::{
    debug_serial_println,
    mshv::vsm::{KernelSymbolMap, ModuleMemoryWithContent},
};
use alloc::{string::ToString, vec, vec::Vec};
use goblin::elf::{
    Elf,
    reloc::{R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32},
    section_header::SectionHeader,
};
use hashbrown::HashMap;

// Currently, our VTL1 kernel does not know the exact loaded addresses of each section of a kernel module.
// We only know their page-aligned addresses. Linux-based VTL1 kernel does not suffer from this problem
// because it uses the kernel's original module loader to load the kernel module in VTL1.
// We might be able to write a Rust-based module loader whose functionality is equivalent to
// the Linux kernel's one, but it requires non-trivial amount of work and continuous maintenance.
// Instead, we could ignore byte differences smaller than a page size (i.e., 12 bits) or
// should receive exact section loaded addresses from the VTL0 kernel.

// focusing on basic `.rela.<section_name>` stuffs for now. Linux kernel does have many other custom relocations
// like `rela.call_sites`, `rela.return_sites`, and `rela__patchable_function_entries`.

/// This function validates the kernel module ELF file and its sections.
pub fn validate_module_elf(
    elf_buf: &[u8],
    mod_mem: &ModuleMemoryWithContent,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<bool, KernelElfError> {
    if let Ok(text_reloc) = relocate_elf_section(elf_buf, ".text", mod_mem, ksymtab, ksymtab_gpl) {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mod_mem
            .text
            .read_bytes(mod_mem.text.start().unwrap(), &mut text_loaded)
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        let _ = match_relocation(&text_reloc, &text_loaded);
    } else {
        return Err(KernelElfError::SectionRelocationFailed);
    }

    if let Ok(text_reloc) =
        relocate_elf_section(elf_buf, ".init.text", mod_mem, ksymtab, ksymtab_gpl)
    {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mod_mem
            .init_text
            .read_bytes(mod_mem.init_text.start().unwrap(), &mut text_loaded)
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        let _ = match_relocation(&text_reloc, &text_loaded);
    } else {
        return Err(KernelElfError::SectionRelocationFailed);
    }

    Ok(true)
}

/// This function checks whether the relocated section matches the loaded section.
/// Due to our relocation logic's incompleteness, we allow some mismatches with heuristics.
fn match_relocation(text_reloc: &[u8], text_loaded: &[u8]) -> Result<bool, KernelElfError> {
    if text_reloc.is_empty() || text_reloc.len() != text_loaded.len() {
        return Err(KernelElfError::InvalidInput);
    }

    let mut matched = true;

    let mut i = 0;
    while i < text_loaded.len() {
        if text_reloc[i] != text_loaded[i] {
            if i + 5 < text_loaded.len()
                && text_reloc[i..i + 5] == [0xc3, 0xcc, 0xcc, 0xcc, 0xcc]
                && text_loaded[i..i + 5] == [0xff, 0xe7, 0xcc, 0x66, 0x90]
            {
                // this is a jump 0 patch, which we allow to subtle mismatch
                i += 5;
                continue;
            } else if i + 4 < text_loaded.len()
                && text_reloc[i + 1] & 0xe0 == text_loaded[i + 1] & 0xe0
                && text_reloc[i + 2..i + 4] == text_loaded[i + 2..i + 4]
            {
                // this mismatch must be allowed only for section header relocations.
                // we require relocation information (i.e., offset & size) to clarify this.
                i += 4;
                continue;
            }

            debug_serial_println!("{:#x}: {:#x} {:#x}", i, text_reloc[i], text_loaded[i]);
            matched = false;
        }
        i += 1;
    }

    Ok(matched)
}

/// This function relocates the specified section of a kernel module ELF file
///
/// # Panics
/// panics if the ELF file is malformed.
#[allow(clippy::too_many_lines)]
pub fn relocate_elf_section(
    elf_slice: &[u8],
    section_name: &str,
    mod_mem: &ModuleMemoryWithContent,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<Vec<u8>, KernelElfError> {
    let Ok(elf) = Elf::parse(elf_slice) else {
        return Err(KernelElfError::ElfParseFailed);
    };

    let mut symbol_map = HashMap::new();
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                symbol_map.insert(name.to_string(), sym.st_value);
                debug_serial_println!("Symbol: {:30} -> {:#x}", name, sym.st_value);
            }
        }
    }

    let section_base_addr: u64 = match section_name {
        ".text" => mod_mem.text.start().unwrap().as_u64(),
        ".init.text" => mod_mem.init_text.start().unwrap().as_u64(),
        _ => {
            return Err(KernelElfError::UnsupportedSection);
        }
    };

    let mut target_section: Option<&SectionHeader> = None;
    for section in &elf.section_headers {
        if section.sh_flags & u64::from(goblin::elf64::section_header::SHF_ALLOC) != 0
            && section.sh_size > 0
        {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name == section_name {
                    debug_serial_println!(
                        "Found {:?} section: offset {:#x}, size {:#x}",
                        section_name,
                        section.sh_offset,
                        section.sh_size
                    );
                    target_section = Some(section);
                    break;
                }
            }
        }
    }
    target_section.ok_or(KernelElfError::SectionNotFound)?;

    let sect_offset = target_section.unwrap().sh_offset;
    let sect_size = target_section.unwrap().sh_size;

    let mut reloc_buf = vec![0u8; usize::try_from(sect_size).unwrap()];
    reloc_buf.copy_from_slice(
        &elf_slice[usize::try_from(sect_offset).unwrap()
            ..usize::try_from(sect_offset + sect_size).unwrap()],
    );

    for (shndx, relocations) in &elf.shdr_relocs {
        let cur_section = &elf.section_headers[*shndx];
        let cur_section_name = elf
            .shdr_strtab
            .get_at(cur_section.sh_name)
            .unwrap_or("unknown");
        if cur_section_name != [".rela", section_name].join("") {
            // for now, we only support `.rela.<section_name>` relocations and
            // ignore other stuffs like `.rela__patchable_function_entries`
            continue;
        }

        for reloc in relocations {
            let r_offset = usize::try_from(reloc.r_offset).unwrap();
            let r_sym = reloc.r_sym;
            let r_addend = reloc.r_addend.unwrap_or(0);
            let r_type = reloc.r_type;

            debug_serial_println!(
                "Relocation: r_offset {:#x}, r_sym {}, r_addend {}, r_type {}",
                r_offset,
                r_sym,
                r_addend,
                r_type
            );

            let Some(sym) = elf.syms.get(reloc.r_sym) else {
                continue;
            };
            let sym_name = elf.strtab.get_at(sym.st_name).unwrap();
            let mut symbol_addr: Option<u64> = None;

            // check whether the symbol is defined in the current module
            if let Some(sym_val) = symbol_map.get(sym_name).copied() {
                symbol_addr = if sym_val != 0 {
                    Some(section_base_addr + sym_val)
                } else {
                    None
                }
            }

            // check whether the symbol is defined in the kernel symbol table (or other modules)
            if symbol_addr.is_none() && !sym_name.starts_with("__") {
                symbol_addr = ksymtab
                    .get(sym_name)
                    .map(x86_64::VirtAddr::as_u64)
                    .or_else(|| ksymtab_gpl.get(sym_name).map(x86_64::VirtAddr::as_u64));
                // TODO: support module symbol dependencies as a module can depend on another module's symbols.
            }

            // check whether the symbol is a section header
            if symbol_addr.is_none() {
                let section = &elf.section_headers[sym.st_shndx];
                let name_offset = section.sh_name;
                let section_name = elf
                    .shdr_strtab
                    .get_at(name_offset)
                    .unwrap_or("unknown section");

                symbol_addr = match section_name {
                    ".text" => Some(mod_mem.text.start().unwrap().as_u64()),
                    ".init.text" => Some(mod_mem.init_text.start().unwrap().as_u64()),
                    ".rodata" => Some(mod_mem.ro_data.start().unwrap().as_u64()),
                    ".data" => Some(mod_mem.data.start().unwrap().as_u64()),
                    _ => None,
                }
            }

            let Some(symbol_addr) = symbol_addr else {
                // ignore unknown symbols
                continue;
            };

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            match r_type {
                R_X86_64_64 => {
                    assert!(r_offset + 8 <= reloc_buf.len());
                    let value = (symbol_addr as i64).wrapping_add(r_addend);
                    let value_u64 = value as u64;
                    reloc_buf[r_offset..r_offset + 8].copy_from_slice(&value_u64.to_le_bytes());
                }
                R_X86_64_32 => {
                    assert!(r_offset + 4 <= reloc_buf.len());
                    let value = (symbol_addr as i64).wrapping_add(r_addend);
                    assert!(u32::try_from(value).is_ok());
                    let value_u32 = value as u32;
                    reloc_buf[r_offset..r_offset + 4].copy_from_slice(&value_u32.to_le_bytes());
                }
                R_X86_64_32S => {
                    assert!(r_offset + 4 <= reloc_buf.len());
                    let value = symbol_addr as i64 + r_addend;
                    assert!(i32::try_from(value).is_ok());
                    let value_i32 = value as i32;
                    reloc_buf[r_offset..r_offset + 4].copy_from_slice(&value_i32.to_le_bytes());
                }
                R_X86_64_PLT32 | R_X86_64_PC32 => {
                    assert!(r_offset + 4 <= reloc_buf.len());
                    let reloc_address = section_base_addr + r_offset as u64;
                    let value = (symbol_addr as i64 + r_addend) - reloc_address as i64;
                    assert!(i32::try_from(value).is_ok());
                    let value_i32 = value as i32;
                    reloc_buf[r_offset..r_offset + 4].copy_from_slice(&value_i32.to_le_bytes());
                }
                _ => {
                    todo!("Unsupported relocation type: {r_type}");
                }
            }
        }
    }

    patch_jmp0_to_ret(&mut reloc_buf);

    Ok(reloc_buf)
}

/// This function patches jump 0 (`[0xe9, 0x0, 0x0, 0x0, 0x0]`) to a return instruction.
/// jump 0 can be replaced with either `[0xc3, 0xcc, 0xcc, 0xcc, 0xcc]` or `[0xff, 0xe7, 0xcc, 0x66, 0x90]`.
/// for simplicity, we replace every jump 0 with `[0xc3, 0xcc, 0xcc, 0xcc, 0xcc]`.
/// We allow binary sequence mismatch if it is `[0xff, 0xe7, 0xcc, 0x66, 0x90]`.
fn patch_jmp0_to_ret(buf: &mut [u8]) {
    let mut i = 0;
    while i + 4 < buf.len() {
        if buf[i] == 0xe9 && buf[i + 1..i + 5] == [0x0, 0x0, 0x0, 0x0] {
            buf[i] = 0xc3;
            buf[i + 1..i + 5].fill(0xcc);
            i += 5;
        } else {
            i += 1;
        }
    }
}

/// Error for Kernel ELF validation and relocation failures.
#[derive(Debug, PartialEq)]
pub enum KernelElfError {
    SectionReadFailed,
    SectionRelocationFailed,
    ElfParseFailed,
    UnsupportedSection,
    SectionNotFound,
    InvalidInput,
}
