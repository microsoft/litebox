use anyhow::{anyhow, Result};
use capstone::prelude::*;
use object::{File, write::{Object, StandardSegment}, Object as _, Architecture, BinaryFormat, Endianness, ObjectSection, SectionKind};
use std::{fs, path::Path};

pub fn rewrite_syscalls(path: &Path, _obj_file: &object::File, file_data: Vec<u8>) -> Result<()> {
    let parsed_obj = File::parse(&*file_data)?;

    let mut obj = Object::new(
        BinaryFormat::Elf,
        Architecture::X86_64,
        Endianness::Little,
    );

    // Copy original .text section explicitly
    let parsed_text_section = parsed_obj.section_by_name(".text").ok_or(anyhow!(".text section not found"))?;
    let text_data = parsed_text_section.data()?;
    let text_addr = parsed_text_section.address();

    let section_id = obj.add_section(
        obj.segment_name(StandardSegment::Text).to_vec(),
        b".text".to_vec(),
        SectionKind::Text,
    );
    obj.section_mut(section_id).set_data(text_data.to_vec(), parsed_text_section.align());

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .build()?;

    let instructions = cs.disasm_all(text_data, text_addr)?;

    // Determine safe trampoline address
    let max_section_end = parsed_obj.sections()
        .map(|sec| sec.address() + sec.size())
        .max()
        .unwrap_or(0);
    let trampoline_addr = (max_section_end + 0xFFF) & !0xFFF;

    // Create trampoline section safely
    let trampoline_section_id = obj.add_section(
        obj.segment_name(StandardSegment::Text).to_vec(),
        b".trampoline".to_vec(),
        SectionKind::Text,
    );
    obj.section_mut(trampoline_section_id).set_data(vec![0; 8], 8);

    for (i, inst) in instructions.iter().enumerate() {
        if inst.mnemonic().unwrap_or_default() == "syscall" {
            let mut replace_len = inst.bytes().len();
            let mut replace_start = inst.address();
            let mut prev_idx = i as isize - 1;

            while replace_len < 5 && prev_idx >= 0 {
                let prev_inst = &instructions[prev_idx as usize];
                replace_start = prev_inst.address();
                replace_len += prev_inst.bytes().len();
                prev_idx -= 1;
            }

            if replace_len < 5 {
                return Err(anyhow!("Not enough bytes before syscall at 0x{:x}", inst.address()));
            }

            // Build trampoline
            let mut trampoline = vec![];
            trampoline.extend_from_slice(
                &text_data[(replace_start - text_addr) as usize..(inst.address() - text_addr) as usize],
            );

            // call [rip + offset_to_shared_target]
            trampoline.extend_from_slice(&[0xFF, 0x15]);
            let disp32 = -(trampoline.len() as i32 + 4);
            trampoline.extend_from_slice(&disp32.to_le_bytes());

            // jmp back to original after syscall
            let return_addr = inst.address() + inst.bytes().len() as u64;
            let jmp_back_offset = return_addr as i64 - (trampoline_addr + trampoline.len() as u64 + 5) as i64;
            trampoline.push(0xE9);
            trampoline.extend_from_slice(&(jmp_back_offset as i32).to_le_bytes());

            // Write trampoline
            obj.append_section_data(trampoline_section_id, &trampoline, 1);

            // Replace original instructions with jump to trampoline
            let section = obj.section_mut(section_id);
            let replace_offset = (replace_start - text_addr) as usize;

            let section_data = section.data_mut();
            section_data[replace_offset] = 0xE9; // JMP rel32
            let jump_offset = trampoline_addr as i64 - (replace_start + 5) as i64;
            section_data[replace_offset + 1..replace_offset + 5]
                .copy_from_slice(&(jump_offset as i32).to_le_bytes());

            // Fill remaining bytes with NOP
            for idx in 5..replace_len {
                section_data[replace_offset + idx] = 0x90;
            }
        }
    }

    // Write patched ELF file to a new file
    let new_path = path.with_extension("patched");
    fs::write(&new_path, obj.write()?)?;
    println!("Successfully rewrote ELF file to {:?}", new_path);

    Ok(())
}
