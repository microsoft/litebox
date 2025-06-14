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

// focusing on basic `.rela.<section_name>` stuffs for now. Linux kernel does have many other custom relocations
// like `rela.call_sites`, `rela.return_sites`, and `rela__patchable_function_entries`.

pub fn validate_module_elf(
    mod_mem: &ModuleMemoryWithContent,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<(), ()> {
    let elf_size =
        usize::try_from(mod_mem.elf.end().unwrap() - mod_mem.elf.start().unwrap()).unwrap();

    // TODO: There are many kernel modules whose size exceeds VTL1's memory limit. We should consider how to handle them.
    if elf_size > 256 * 1024 {
        debug_serial_println!("VSM: ignore large module ELF for now: {}", elf_size);
        return Err(());
    }

    let mut elf_buf = vec![0u8; elf_size];
    mod_mem
        .elf
        .read_bytes(mod_mem.elf.start().unwrap(), &mut elf_buf)
        .expect("Failed to read kernel module ELF buffer");

    if let Ok(text_reloc) = load_elf(&elf_buf, ".text", mod_mem, ksymtab, ksymtab_gpl) {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mod_mem
            .text
            .read_bytes(mod_mem.text.start().unwrap(), &mut text_loaded)
            .expect("Failed to read kernel module .text section");

        let mut i = 0;
        while i < text_loaded.len() {
            if text_reloc[i] != text_loaded[i] {
                if i + 5 < text_loaded.len()
                    && text_reloc[i..=i + 5] == [0xc3, 0xcc, 0xcc, 0xcc, 0xcc]
                {
                    // this is a patched jump 0, which we allow to mismatch for now
                    i += 5;
                    continue;
                }
                debug_serial_println!("{:#x}: {:#x} {:#x}", i, text_reloc[i], text_loaded[i]);
            }
            i += 1;
        }
    }

    if let Ok(text_reloc) = load_elf(&elf_buf, ".init.text", mod_mem, ksymtab, ksymtab_gpl) {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mod_mem
            .init_text
            .read_bytes(mod_mem.init_text.start().unwrap(), &mut text_loaded)
            .expect("Failed to read kernel module .init.text section");

        let mut i = 0;
        while i < text_loaded.len() {
            if text_reloc[i] != text_loaded[i] {
                if i + 5 < text_loaded.len()
                    && text_reloc[i..=i + 5] == [0xc3, 0xcc, 0xcc, 0xcc, 0xcc]
                {
                    i += 5;
                    continue;
                }
                debug_serial_println!("{:#x}: {:#x} {:#x}", i, text_reloc[i], text_loaded[i]);
            }
            i += 1;
        }
    }

    Ok(())
}

/// # Panics
/// panics if the ELF file is malformed.
#[allow(clippy::too_many_lines)]
pub fn load_elf(
    elf_slice: &[u8],
    section_name: &str,
    mod_mem: &ModuleMemoryWithContent,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<Vec<u8>, i64> {
    let Ok(elf) = Elf::parse(elf_slice) else {
        return Err(-1);
    };
    let mut symbol_map = HashMap::new();
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.is_empty() {
                continue;
            }
            let addr = sym.st_value;
            symbol_map.insert(name.to_string(), addr);
            debug_serial_println!("Symbol: {:30} -> {:#x}", name, addr,);
        }
    }

    let section_base_addr: u64 = match section_name {
        ".text" => mod_mem.text.start().unwrap().as_u64(),
        ".init.text" => mod_mem.init_text.start().unwrap().as_u64(),
        _ => {
            debug_serial_println!("Unsupported section name: {section_name}");
            return Err(-1);
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

    assert!(
        target_section.is_some(),
        "No {section_name:?} section found in the ELF file"
    );

    let text_offset = target_section.unwrap().sh_offset;
    let text_size = target_section.unwrap().sh_size;

    let mut text_vec = vec![0u8; usize::try_from(text_size).unwrap()];
    text_vec.copy_from_slice(
        &elf_slice[usize::try_from(text_offset).unwrap()
            ..usize::try_from(text_offset + text_size).unwrap()],
    );

    let rela_section_name = [".rela", section_name].join("");

    for (shndx, relocations) in &elf.shdr_relocs {
        let target_section = &elf.section_headers[*shndx];
        let cur_section_name = elf
            .shdr_strtab
            .get_at(target_section.sh_name)
            .unwrap_or("unknown");
        if cur_section_name != rela_section_name {
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

            // symbol relocation
            let sym = elf
                .syms
                .get(reloc.r_sym)
                .ok_or_else(|| alloc::format!("Invalid symbol index: {}", reloc.r_sym));

            let mut symbol_addr: Option<u64> = None;

            let section = &elf.section_headers[sym.as_ref().unwrap().st_shndx];
            let name_offset = section.sh_name;
            let section_name = elf
                .shdr_strtab
                .get_at(name_offset)
                .unwrap_or("unknown section");
            match section_name {
                ".text" => {
                    symbol_addr = Some(mod_mem.text.start().unwrap().as_u64());
                }
                ".data" => {
                    symbol_addr = Some(mod_mem.data.start().unwrap().as_u64());
                }
                ".rodata" => {
                    symbol_addr = Some(mod_mem.ro_data.start().unwrap().as_u64());
                }
                _ => {}
            }
            if symbol_addr.is_none() {
                let sym_name = elf.strtab.get_at(sym.unwrap().st_name).unwrap();

                if !sym_name.starts_with("__") {
                    if let Some(sym_val) = symbol_map.get(sym_name).copied() {
                        if sym_val != 0 {
                            symbol_addr = Some(section_base_addr + sym_val);
                        } else {
                            // if a symbol is undefined (`st_value == 0`), check whether it is a symbol defined in the kernel.
                            if let Some(external_addr) = ksymtab.get(sym_name) {
                                symbol_addr = Some(external_addr.as_u64());
                            } else if let Some(external_addr) = ksymtab_gpl.get(sym_name) {
                                symbol_addr = Some(external_addr.as_u64());
                            } else {
                                symbol_addr = Some(section_base_addr);
                            }
                        }
                    }
                }
            }
            if symbol_addr.is_none() {
                continue;
            }
            let symbol_addr = symbol_addr.unwrap();

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            match r_type {
                R_X86_64_64 => {
                    assert!(r_offset + 8 <= text_vec.len());
                    let value = (symbol_addr as i64).wrapping_add(r_addend);
                    let value_u64 = value as u64;
                    text_vec[r_offset..r_offset + 8].copy_from_slice(&value_u64.to_le_bytes());
                }
                R_X86_64_32 => {
                    assert!(r_offset + 4 <= text_vec.len());
                    let value = (symbol_addr as i64).wrapping_add(r_addend);
                    assert!(u32::try_from(value).is_ok());
                    let value_u32 = value as u32;
                    text_vec[r_offset..r_offset + 4].copy_from_slice(&value_u32.to_le_bytes());
                }
                R_X86_64_32S => {
                    assert!(r_offset + 4 <= text_vec.len());
                    let value = symbol_addr as i64 + r_addend;
                    assert!(i32::try_from(value).is_ok());
                    let value_i32 = value as i32;
                    text_vec[r_offset..r_offset + 4].copy_from_slice(&value_i32.to_le_bytes());
                }
                R_X86_64_PLT32 | R_X86_64_PC32 => {
                    // debug_serial_println!("r_offset: {r_offset}, sym_name: {sym_name}");
                    assert!(r_offset + 4 <= text_vec.len());
                    let reloc_address = section_base_addr + r_offset as u64;
                    let value = (symbol_addr as i64 + r_addend) - reloc_address as i64;
                    assert!(i32::try_from(value).is_ok());
                    let value_i32 = value as i32;
                    text_vec[r_offset..r_offset + 4].copy_from_slice(&value_i32.to_le_bytes());
                }
                _ => {
                    todo!("Unsupported relocation type: {r_type}");
                }
            }
        }
    }

    patch_jmp0_to_ret(&mut text_vec);

    Ok(text_vec)
}

// for simplicity, we replace every jump 0 (`[0xe9, 0x0, 0x0, 0x0, 0x0]`) with `[0xc3, 0xcc, 0xcc, 0xcc, 0xcc]` and
// allow binary sequence mismatch only if it is `[0xff, 0xe7, 0xcc, 0x66, 0x90]`
fn patch_jmp0_to_ret(buf: &mut [u8]) {
    let mut i = 0;
    while i + 4 < buf.len() {
        if buf[i] == 0xe9 && buf[i + 1..=i + 4] == [0x0, 0x0, 0x0, 0x0] {
            buf[i] = 0xc3;
            buf[i + 1..=i + 4].fill(0xcc);
            i += 1;
        } else {
            i += 1;
        }
    }
}
