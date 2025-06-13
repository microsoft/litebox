// TODO: where should we put this file?

use crate::{
    debug_serial_println,
    mshv::vsm::{KernelSymbolMap, MemoryMapWithContent},
};
use alloc::{string::ToString, vec, vec::Vec};
use goblin::elf::{
    Elf,
    reloc::{R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32},
    section_header::SectionHeader,
};
use hashbrown::HashMap;

// handle `.text` section first and consider other sections (`.init.text`, `.rodata`) later.
// apply `.rela.call_sites`, `.rela.return_sites`, and `.rela__patchable_function_entries` to update
// `.call_sites`, `.return_sites`, and `__patchable_function_entries` sections, and
// use them together with `.rela.text`, `ksymtabs`, and `ksymtabs_gpl` to patch the `.text` section.

pub fn validate_module_elf(
    mem_elf: &MemoryMapWithContent,
    mem_text: &MemoryMapWithContent,
    mem_init_text: &MemoryMapWithContent,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<(), ()> {
    let elf_size = usize::try_from(mem_elf.end().unwrap() - mem_elf.start().unwrap()).unwrap();

    // TODO: There are many kernel modules whose size exceeds VTL1's memory limit. We should consider how to handle them.
    if elf_size > 256 * 1024 {
        debug_serial_println!("VSM: ignore large module ELF for now: {}", elf_size);
        return Err(());
    }

    let mut elf_buf = vec![0u8; elf_size];
    mem_elf
        .read_bytes(mem_elf.start().unwrap(), &mut elf_buf)
        .expect("Failed to read kernel module ELF buffer");

    let text_section_base_addr = mem_text.start().unwrap();
    if let Ok(text_reloc) = load_elf(
        &elf_buf,
        ".text",
        text_section_base_addr.as_u64(),
        ksymtab,
        ksymtab_gpl,
    ) {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mem_text
            .read_bytes(text_section_base_addr, &mut text_loaded)
            .expect("Failed to read kernel module .text section");

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

    let init_text_section_base_addr = mem_init_text.start().unwrap();
    if let Ok(text_reloc) = load_elf(
        &elf_buf,
        ".init.text",
        init_text_section_base_addr.as_u64(),
        ksymtab,
        ksymtab_gpl,
    ) {
        let mut text_loaded = vec![0u8; text_reloc.iter().len()];
        mem_init_text
            .read_bytes(init_text_section_base_addr, &mut text_loaded)
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
    section_base_addr: u64,
    ksymtab: &KernelSymbolMap,
    ksymtab_gpl: &KernelSymbolMap,
) -> Result<Vec<u8>, i64> {
    let Ok(elf) = Elf::parse(elf_slice) else {
        return Err(-1);
    };
    let mut symbol_map = HashMap::new();
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            let addr = if sym.st_value != 0 {
                sym.st_value
            } else if let Some(global_addr) = ksymtab.get(name) {
                global_addr.as_u64()
            } else if let Some(global_addr) = ksymtab_gpl.get(name) {
                global_addr.as_u64()
            } else {
                0
            };
            symbol_map.insert(name.to_string(), addr);
            debug_serial_println!("Symbol: {:30} -> {:#x}", name, addr,);
        }
    }

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

    for (shndx, relocations) in &elf.shdr_relocs {
        let target_section = &elf.section_headers[*shndx];
        let section_name = elf
            .shdr_strtab
            .get_at(target_section.sh_name)
            .unwrap_or("unknown");
        let rela_section_name = [".rela", section_name].join("");
        if section_name != rela_section_name {
            continue;
        }

        for reloc in relocations {
            // symbol relocation
            let sym = elf
                .syms
                .get(reloc.r_sym)
                .ok_or_else(|| alloc::format!("Invalid symbol index: {}", reloc.r_sym));
            let sym_name = elf.strtab.get_at(sym.unwrap().st_name).unwrap();
            let Some(sym_val) = symbol_map.get(sym_name).copied() else {
                continue;
            };

            let r_offset = reloc.r_offset;
            let r_addend = reloc.r_addend.unwrap_or(0);
            let r_type = reloc.r_type;

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            let result = match r_type {
                R_X86_64_64 | R_X86_64_32S => (sym_val as isize + r_addend as isize) as u64,
                R_X86_64_PC32 => {
                    let pc = section_base_addr + reloc.r_offset;
                    (sym_val as isize + r_addend as isize).wrapping_sub(pc as isize) as u64
                }
                R_X86_64_PLT32 => {
                    let relocation_address = section_base_addr + r_offset;
                    let relocation_address_plus_4 = relocation_address + 4;
                    let symbol_address = if sym_val != 0 {
                        section_base_addr + sym_val
                    } else {
                        todo!(
                            "checks whether {:?} is in the ksymtabs of the kernel text and get the address from it (if exists)",
                            sym_name
                        );
                    };

                    let rel32 =
                        (symbol_address as i64 + r_addend) - relocation_address_plus_4 as i64;

                    rel32 as u64
                }
                R_X86_64_32 => (sym_val as isize).wrapping_add(r_addend as isize) as u64,
                _ => {
                    debug_serial_println!("Unsupported relocation type: {}", r_type);
                    continue;
                }
            };

            debug_serial_println!(
                "r_offset {:#x} r_type {:#x} r_addend {:#x} sym_name: {} sym_val {:#x} result {:#x}",
                r_offset,
                r_type,
                r_addend,
                sym_name,
                sym_val,
                result,
            );
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
