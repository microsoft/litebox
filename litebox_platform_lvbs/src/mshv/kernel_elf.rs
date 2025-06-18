// TODO: where should we put this file?

use crate::{
    debug_serial_println,
    mshv::vsm::{KernelSymbolMaps, ModuleMemoryContent},
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use goblin::elf::{
    Elf,
    reloc::{R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32},
};
use hashbrown::HashMap;
use rangemap::set::RangeSet;
use x86_64::VirtAddr;

// Currently, our VTL1 kernel does not know the exact loaded addresses of each section of a kernel module.
// We only know their page-aligned addresses. Linux-based VTL1 kernel does not suffer from this problem
// because it uses the kernel's original module loader to load the kernel module in VTL1.
// We might be able to write a Rust-based module loader whose functionality is equivalent to
// the Linux kernel's one, but it requires non-trivial amount of work and continuous maintenance.
// Instead, we could ignore byte differences smaller than a page size (i.e., 12 bits) or
// should receive exact section loaded addresses from the VTL0 kernel.

// focusing on basic `.rela.<section_name>` stuffs for now. Linux kernel does have many other custom relocations
// like `rela.call_sites`, `rela.return_sites`, and `rela__patchable_function_entries`.

// TODO: our goal is not to make a kernel module loader which is 100% compatible with that of Linux kernel.
// Instead, we check individual symbol/section relocation and ensure their relocated addresses are
// within a valid range including 1) memory type and 2) minor offset differences.
// This is slightly less strict but we don't need to worry about implementation errors, corner cases, and
// never-ending maintenance.

// key: module name or ID, value: a list of exported symbols
// module symbol table: key - symbol name, value - symbol address

/// This function validates the kernel module ELF file and its sections.
pub fn validate_module_elf(
    elf_buf: &[u8],
    mod_mem: &ModuleMemoryContent,
    symbol_maps: KernelSymbolMaps,
) -> Result<bool, KernelElfError> {
    let mut result = true;

    for section in [".text", ".init.text"] {
        let sect_mem = mod_mem.find_section_by_name(section).unwrap();
        if sect_mem.is_empty() {
            return Ok(result);
        }

        if let Ok(text_reloc) = relocate_elf_section(elf_buf, section, mod_mem, symbol_maps) {
            let mut text_loaded = vec![0u8; text_reloc.iter().len()];
            sect_mem
                .read_bytes(sect_mem.start().unwrap(), &mut text_loaded)
                .map_err(|_| KernelElfError::SectionReadFailed)?;

            for (i, (&r, &l)) in text_reloc.iter().zip(text_loaded.iter()).enumerate() {
                if r != l {
                    debug_serial_println!(
                        "Mismatch: reloc[{i:#x}] = {r:#x}, loaded[{i:#x}] = {l:#x}"
                    );
                    result = false;
                }
            }
        } else {
            return Err(KernelElfError::SectionRelocationFailed);
        }
    }

    Ok(result)
}

/// This function relocates the specified section of a kernel module ELF file using both ELF itself and loaded data.
/// Currently, it relies on heuristics because making a kernel module loader which is 100% compatible with
/// that of Linux kernel requires non-trivial amount of work and continuous maintenance.
/// Our heuristics include:
/// - all relocations must be already specified in the ELF sections like `.rela.text` and `.rela.call_sites`
/// - symbol addresses must be within the kernel's or known kernel module's address ranges with matching memory types (i.e., `.text`, `.data`, `.rodata`, etc.)
/// - patched instructions must be expected, safe ones like NOPs.
/// - accept known, special relocations like `__x86_return_thunk` with minimal validation
pub fn relocate_elf_section(
    elf_buf: &[u8],
    section_name: &str,
    mod_mem: &ModuleMemoryContent,
    symbol_maps: KernelSymbolMaps,
) -> Result<Vec<u8>, KernelElfError> {
    match section_name {
        ".text" | ".init.text" => {}
        _ => {
            return Err(KernelElfError::UnsupportedSection);
        }
    }

    let Ok(elf) = Elf::parse(elf_buf) else {
        return Err(KernelElfError::ElfParseFailed);
    };

    let Some(section) = elf.section_headers.iter().find(|s| {
        s.sh_flags & u64::from(goblin::elf64::section_header::SHF_ALLOC) != 0
            && s.sh_size > 0
            && elf.shdr_strtab.get_at(s.sh_name) == Some(section_name)
    }) else {
        return Err(KernelElfError::SectionNotFound);
    };

    let mut reloc_buf = vec![0u8; usize::try_from(section.sh_size).unwrap()];
    reloc_buf.copy_from_slice(
        &elf_buf[usize::try_from(section.sh_offset).unwrap()
            ..usize::try_from(section.sh_offset + section.sh_size).unwrap()],
    );

    relocate_symbols(&elf, section_name, &mut reloc_buf, mod_mem, symbol_maps)
        .map_err(|_| KernelElfError::SectionRelocationFailed)?;

    accept_patchables(&elf, section_name, &mut reloc_buf, mod_mem)
        .map_err(|_| KernelElfError::SectionRelocationFailed)?;

    Ok(reloc_buf)
}

#[allow(clippy::too_many_lines)]
fn relocate_symbols(
    elf: &Elf,
    section_name: &str,
    reloc_buf: &mut [u8],
    mod_mem: &ModuleMemoryContent,
    symbol_maps: KernelSymbolMaps,
) -> Result<(), KernelElfError> {
    let Some(mem_to_validate) = mod_mem.find_section_by_name(section_name) else {
        return Err(KernelElfError::UnsupportedSection);
    };
    let section_base_addr = mem_to_validate.start().unwrap().as_u64();

    for (shndx, relocations) in &elf.shdr_relocs {
        let cur_section = &elf.section_headers[*shndx];
        let Some(cur_section_name) = elf.shdr_strtab.get_at(cur_section.sh_name) else {
            continue;
        };
        if cur_section_name != [".rela", section_name].join("") {
            continue;
        }

        for reloc in relocations {
            let r_offset = usize::try_from(reloc.r_offset).unwrap();
            let r_sym = reloc.r_sym;
            let r_addend = reloc.r_addend.unwrap_or(0);
            let r_type = reloc.r_type;

            let mut buffer = [0u8; 8];

            match r_type {
                R_X86_64_64 | R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => {}
                _ => {
                    todo!("Unsupported relocation type {r_type}");
                }
            }

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            let value_to_validate = if r_type == R_X86_64_64 {
                assert!(r_offset + 8 <= reloc_buf.len());
                mem_to_validate
                    .read_bytes(
                        mem_to_validate.start().unwrap() + u64::try_from(r_offset).unwrap(),
                        &mut buffer,
                    )
                    .map_err(|_| KernelElfError::SectionReadFailed)?;
                if reloc_buf[r_offset..r_offset + 8] == buffer {
                    None
                } else {
                    let value = u64::from_le_bytes(buffer);
                    let value_i64 = value as i64;
                    Some(value_i64.wrapping_sub(r_addend) as u64)
                }
            } else {
                assert!(r_offset + 4 <= reloc_buf.len());
                mem_to_validate
                    .read_bytes(
                        mem_to_validate.start().unwrap() + u64::try_from(r_offset).unwrap(),
                        &mut buffer[0..4],
                    )
                    .map_err(|_| KernelElfError::SectionReadFailed)?;
                if reloc_buf[r_offset..r_offset + 4] == buffer[0..4] {
                    None
                } else {
                    match r_type {
                        R_X86_64_32 => {
                            let value = i32::from_le_bytes(buffer[0..4].try_into().unwrap());
                            let value_i64 = i64::from(value);
                            Some(value_i64.wrapping_sub(r_addend) as u64)
                        }
                        R_X86_64_32S => {
                            let value = i32::from_le_bytes(buffer[0..4].try_into().unwrap());
                            let value_i64 = i64::from(value);
                            Some((value_i64 - r_addend) as u64)
                        }
                        R_X86_64_PLT32 | R_X86_64_PC32 => {
                            let value = i32::from_le_bytes(buffer[0..4].try_into().unwrap());
                            let value_i64 = i64::from(value);
                            let reloc_address = section_base_addr + r_offset as u64;
                            Some((value_i64 + reloc_address as i64 - r_addend) as u64)
                        }
                        _ => None,
                    }
                }
            };
            let Some(value_to_validate) = value_to_validate else {
                continue;
            };

            let Some(sym) = elf.syms.get(r_sym) else {
                continue;
            };
            let Some(sym_name) = elf.strtab.get_at(sym.st_name) else {
                continue;
            };

            // NOTE. These are special cases. We accept these relocations with minimal validation
            if is_special_control_relocation(sym_name) {
                match r_type {
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => {
                        reloc_buf[r_offset - 1] = mem_to_validate
                            .read_byte(
                                mem_to_validate.start().unwrap()
                                    + u64::try_from(r_offset - 1).unwrap(),
                            )
                            .unwrap();
                        reloc_buf[r_offset..r_offset + 4].copy_from_slice(&buffer[0..4]);
                        // TODO: check whether `reloc_buf[r_offset - 1..r_offset + 4]` contains an expected instruction.
                    }
                    _ => {}
                }
                continue;
            }

            let (sym_addr, sym_section_name) = if sym.is_import() {
                if is_ignored_global_symbol(sym_name) {
                    (Some(section_base_addr + sym.st_value), None)
                } else {
                    (
                        symbol_maps.get_address(sym_name).map(VirtAddr::as_u64),
                        None,
                    )
                }
            } else if sym.st_shndx
                != usize::try_from(goblin::elf64::section_header::SHN_UNDEF).unwrap()
            {
                let sym_section = &elf.section_headers[sym.st_shndx];
                let name_offset = sym_section.sh_name;
                let sym_section_name = elf.shdr_strtab.get_at(name_offset);
                if sym_section_name.is_some() {
                    let sym_addr = get_section_loaded_address(sym_section_name.unwrap(), mod_mem)
                        .map(|loaded_addr| loaded_addr.as_u64() + sym.st_value);
                    (sym_addr, sym_section_name)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Reject known bad symbol relocations
            if let Some(sym_addr) = sym_addr {
                if sym.is_import() && value_to_validate != sym_addr {
                    continue;
                }
                if !sym.is_import()
                    && !is_valid_section_address(
                        sym_section_name.unwrap(),
                        mod_mem,
                        VirtAddr::new(sym_addr),
                    )
                {
                    continue;
                }
            }

            // Accept all unhandled symbol relocations for now
            if r_type == R_X86_64_64 {
                reloc_buf[r_offset..r_offset + 8].copy_from_slice(&buffer[0..8]);
            } else {
                reloc_buf[r_offset..r_offset + 4].copy_from_slice(&buffer[0..4]);
            }
        }
    }

    Ok(())
}

/// This functions accept patchable relocations. Currently, it accepts most patchables already specifed in
/// an ELF file without validation, which might be insecure in some cases. Additional hardening is required.
fn accept_patchables(
    elf: &Elf,
    section_name: &str,
    reloc_buf: &mut [u8],
    mod_mem: &ModuleMemoryContent,
) -> Result<(), KernelElfError> {
    let mut patchable = RangeSet::<i64>::new();

    let rela_sect_names = [
        ".rela.altinstructions",
        ".rela.call_sites",
        ".rela.ibt_endbr_seal",
        ".rela.parainstructions",
        ".rela.retpoline_sites",
        ".rela.return_sites",
        ".rela__patchable_function_entries",
    ];

    let Some(mem_to_validate) = mod_mem.find_section_by_name(section_name) else {
        return Err(KernelElfError::UnsupportedSection);
    };

    // detect all patch candidates and copy them
    for (shndx, relocations) in &elf.shdr_relocs {
        let cur_section = &elf.section_headers[*shndx];
        let Some(cur_section_name) = elf.shdr_strtab.get_at(cur_section.sh_name) else {
            continue;
        };
        if !rela_sect_names.contains(&cur_section_name) {
            continue;
        }

        for reloc in relocations {
            let r_sym = reloc.r_sym;
            let r_addend = reloc.r_addend.unwrap_or(0);
            let r_type = reloc.r_type;

            let sym = elf.syms.get(r_sym).unwrap();
            let Some(sym_name) = elf.strtab.get_at(sym.st_name) else {
                continue;
            };
            if !sym_name.is_empty() {
                // this function is for section-based relocations (like `.text + 5a`) so symbol name must be empty.
                continue;
            }

            let sym_section = &elf.section_headers[sym.st_shndx];
            let name_offset = sym_section.sh_name;
            let Some(sym_section_name) = elf.shdr_strtab.get_at(name_offset) else {
                continue;
            };
            if sym_section_name == section_name {
                // TODO: validate instructions
                if r_type == R_X86_64_64 {
                    patchable.insert(r_addend..r_addend + 8);
                } else {
                    patchable.insert(r_addend..r_addend + 4);
                }
            }
        }
    }

    for range in patchable.iter() {
        mem_to_validate
            .read_bytes(
                mem_to_validate.start().unwrap() + u64::try_from(range.start).unwrap(),
                &mut reloc_buf
                    [usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
            )
            .map_err(|_| KernelElfError::SectionReadFailed)?;
    }

    Ok(())
}

/// This function returns the loaded address of the specified section in the module memory.
/// Note that it does not return the exact address of the section (especially for data sections)
//  because we only know the page-aligned addresses of representative sections.
#[inline]
fn get_section_loaded_address(
    section_name: &str,
    mod_mem: &ModuleMemoryContent,
) -> Option<VirtAddr> {
    mod_mem
        .find_section_by_name(section_name)
        .map(|s| s.start().unwrap())
}

#[inline]
fn is_valid_section_address(
    section_name: &str,
    mod_mem: &ModuleMemoryContent,
    address: VirtAddr,
) -> bool {
    mod_mem
        .find_section_by_name(section_name)
        .is_some_and(|s| s.contains(address))
}

#[inline]
fn is_ignored_global_symbol(sym_name: &str) -> bool {
    // We ignore some global symbols which are not referred in the kernel module including some architecture-specific symbols.
    let ignored_symbols = ["pv_ops"];
    ignored_symbols.contains(&sym_name)
}

#[inline]
fn is_special_control_relocation(sym_name: &str) -> bool {
    let special_relocs = [
        "__x86_return_thunk",
        "__x86_indirect_thunk_array",
        "__x86_indirect_thunk_rax",
        "__x86_indirect_thunk_rcx",
        "__x86_indirect_thunk_rdx",
        "__x86_indirect_thunk_rbx",
        "__x86_indirect_thunk_rsp",
        "__x86_indirect_thunk_rbp",
        "__x86_indirect_thunk_rsi",
        "__x86_indirect_thunk_rdi",
        "__x86_indirect_thunk_r8",
        "__x86_indirect_thunk_r9",
        "__x86_indirect_thunk_r10",
        "__x86_indirect_thunk_r11",
        "__x86_indirect_thunk_r12",
        "__x86_indirect_thunk_r13",
        "__x86_indirect_thunk_r14",
        "__x86_indirect_thunk_r15",
        "__x86_indirect_call_thunk_array",
        "__x86_indirect_call_thunk_rax",
        "__x86_indirect_call_thunk_rcx",
        "__x86_indirect_call_thunk_rdx",
        "__x86_indirect_call_thunk_rbx",
        "__x86_indirect_call_thunk_rsp",
        "__x86_indirect_call_thunk_rbp",
        "__x86_indirect_call_thunk_rsi",
        "__x86_indirect_call_thunk_rdi",
        "__x86_indirect_call_thunk_r8",
        "__x86_indirect_call_thunk_r9",
        "__x86_indirect_call_thunk_r10",
        "__x86_indirect_call_thunk_r11",
        "__x86_indirect_call_thunk_r12",
        "__x86_indirect_call_thunk_r13",
        "__x86_indirect_call_thunk_r14",
        "__x86_indirect_call_thunk_r15",
        "__x86_indirect_jump_thunk_array",
        "__x86_indirect_jump_thunk_rax",
        "__x86_indirect_jump_thunk_rcx",
        "__x86_indirect_jump_thunk_rdx",
        "__x86_indirect_jump_thunk_rbx",
        "__x86_indirect_jump_thunk_rsp",
        "__x86_indirect_jump_thunk_rbp",
        "__x86_indirect_jump_thunk_rsi",
        "__x86_indirect_jump_thunk_rdi",
        "__x86_indirect_jump_thunk_r8",
        "__x86_indirect_jump_thunk_r9",
        "__x86_indirect_jump_thunk_r10",
        "__x86_indirect_jump_thunk_r11",
        "__x86_indirect_jump_thunk_r12",
        "__x86_indirect_jump_thunk_r13",
        "__x86_indirect_jump_thunk_r14",
        "__x86_indirect_jump_thunk_r15",
    ];
    special_relocs.contains(&sym_name)
}

/// This function parses the `.modinfo` section of the kernel module ELF file and prints its contents.
pub fn parse_modinfo(elf_buf: &[u8]) {
    let Ok(elf) = Elf::parse(elf_buf) else {
        return;
    };

    if let Some(section) = elf
        .section_headers
        .iter()
        .find(|s| s.sh_size > 0 && elf.shdr_strtab.get_at(s.sh_name) == Some(".modinfo"))
    {
        let start = usize::try_from(section.sh_offset).unwrap();
        let end = start + usize::try_from(section.sh_size).unwrap();
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
}

pub fn get_symbol_exports(
    elf_buf: &[u8],
    load_base_addr: VirtAddr,
) -> Result<HashMap<String, VirtAddr>, KernelElfError> {
    let Ok(elf) = Elf::parse(elf_buf) else {
        return Err(KernelElfError::ElfParseFailed);
    };

    let mut symbol_map: HashMap<String, VirtAddr> = HashMap::new();
    for sym in &elf.syms {
        if sym.st_bind() == goblin::elf::sym::STB_GLOBAL && sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty()
                    && !name.starts_with("__")
                    && name != "cleanup_module"
                    && name != "init_module"
                {
                    symbol_map.insert(name.to_string(), load_base_addr + sym.st_value);
                }
            }
        }
    }

    Ok(symbol_map)
}

/// Error for Kernel ELF validation and relocation failures.
#[derive(Debug, PartialEq)]
pub enum KernelElfError {
    SectionReadFailed,
    SectionRelocationFailed,
    ElfParseFailed,
    UnsupportedSection,
    SectionNotFound,
}
