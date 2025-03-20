use anyhow::{Context, Result};
use capstone::prelude::*;
use object::build::elf;
use std::{env, fs, path::Path, vec::Vec};

mod rewriter;

fn hook_syscalls(
    text_data: &mut Vec<u8>,
    text_addr: u64,
    trampoline_data: &mut Vec<u8>,
    trampoline_addr: u64,
    arch_mode: capstone::arch::x86::ArchMode,
) -> Result<()> {
    // Disassemble the .text section
    let cs = capstone::Capstone::new()
        .x86()
        .mode(arch_mode)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()?;
    let instructions = cs.disasm_all(text_data.as_slice(), text_addr)?;

    for (i, inst) in instructions.iter().enumerate() {
        if inst.mnemonic().unwrap_or_default() == "syscall" {
            let mut replace_len = inst.bytes().len();
            let mut replace_start = inst.address();
            let prev_idx = i;

            while replace_len < 5 && prev_idx.checked_sub(1).is_some() {
                let prev_inst = &instructions[prev_idx];
                replace_start = prev_inst.address();
                replace_len += prev_inst.bytes().len();
            }

            if replace_len < 5 {
                return Err(anyhow::anyhow!(
                    "Not enough bytes before syscall at 0x{:x}",
                    inst.address()
                ));
            }

            let target_addr = trampoline_addr + trampoline_data.len() as u64;

            // Copy the original instructions to the trampoline
            trampoline_data.extend_from_slice(
                &text_data[usize::try_from(replace_start - text_addr).unwrap()
                    ..usize::try_from(inst.address() - text_addr).unwrap()],
            );

            // Add call [rip + offset_to_shared_target]
            trampoline_data.extend_from_slice(&[0xFF, 0x15]);
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() + 4);
            trampoline_data.extend_from_slice(&disp32.to_le_bytes());

            // Add jmp back to original after syscall
            let return_addr = inst.address() + inst.bytes().len() as u64;
            let jmp_back_offset = i64::try_from(return_addr).unwrap()
                - i64::try_from(trampoline_addr + trampoline_data.len() as u64 + 5).unwrap();
            trampoline_data.push(0xE9);
            trampoline_data
                .extend_from_slice(&(i32::try_from(jmp_back_offset).unwrap().to_le_bytes()));

            // Replace original instructions with jump to trampoline
            let replace_offset = usize::try_from(replace_start - text_addr).unwrap();
            text_data[replace_offset] = 0xE9; // JMP rel32
            let jump_offset =
                i64::try_from(target_addr).unwrap() - i64::try_from(replace_start + 5).unwrap();
            text_data[replace_offset + 1..replace_offset + 5]
                .copy_from_slice(&(i32::try_from(jump_offset).unwrap().to_le_bytes()));

            // Fill remaining bytes with NOP
            for idx in 5..replace_len {
                text_data[replace_offset + idx] = 0x90;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn rewrite_elf(in_path: &Path) -> Result<()> {
    let in_file = fs::File::open(in_path)
        .with_context(|| format!("Failed to open input file '{}'", in_path.display()))?;
    let in_data = unsafe { memmap2::Mmap::map(&in_file) }
        .with_context(|| format!("Failed to map input file '{}'", in_path.display()))?;
    let in_data = &*in_data;

    let file_kind =
        object::FileKind::parse(in_data).with_context(|| "Failed to parse file kind")?;
    let arch_mode = match file_kind {
        object::FileKind::Elf32 => capstone::arch::x86::ArchMode::Mode32,
        object::FileKind::Elf64 => capstone::arch::x86::ArchMode::Mode64,
        _ => {
            return Err(anyhow::anyhow!("Unsupported file format"));
        }
    };

    let mut builder = elf::Builder::read(in_data)?;

    // Locate the .text section and its segment
    let mut text_section_id: Option<elf::SectionId> = None;
    let mut text_segment_id: Option<elf::SegmentId> = None;
    for section in &builder.sections {
        if section.name.eq_ignore_ascii_case(".text".as_bytes()) {
            text_section_id = Some(section.id());
            for segment in &builder.segments {
                if segment.contains_address(section.sh_addr) {
                    text_segment_id = Some(segment.id());
                    break;
                }
            }
            break;
        }
    }
    let Some(text_section_id) = text_section_id else {
        return Err(anyhow::anyhow!("No .text section found"));
    };
    let Some(text_segment_id) = text_segment_id else {
        return Err(anyhow::anyhow!("No segment found for .text section"));
    };

    let (mut text_data, text_addr, sh_type, sh_flags, sh_addralign) = {
        let text_section = builder.sections.get(text_section_id);
        let elf::SectionData::Data(text_data) = &text_section.data else {
            return Err(anyhow::anyhow!("Failed to get .text section data"));
        };
        let text_data = text_data.as_slice().to_vec();
        let text_addr = text_section.sh_addr;
        (
            text_data,
            text_addr,
            text_section.sh_type,
            text_section.sh_flags,
            text_section.sh_addralign,
        )
    };

    // Create a new loadable segment and section for the trampoline
    let (trampoline_section_id, trampoline_addr) = {
        let trampoline_section = builder.sections.add();
        let trampoline_name = trampoline_section.name.to_mut();
        trampoline_name.clear();
        trampoline_name.extend_from_slice(".trampoline".as_bytes());
        trampoline_section.sh_type = sh_type;
        trampoline_section.sh_flags = sh_flags;
        trampoline_section.sh_addralign = sh_addralign;

        let text_segment = builder.segments.get_mut(text_segment_id);
        text_segment.append_section(trampoline_section);
        (trampoline_section.id(), trampoline_section.sh_addr)
    };
    let mut trampoline_data = vec![0x0; 0x8];

    // Hook syscalls
    hook_syscalls(
        &mut text_data,
        text_addr,
        &mut trampoline_data,
        trampoline_addr,
        arch_mode,
    )
    .with_context(|| format!("Failed to hook syscalls in file '{}'", in_path.display()))?;

    // Update the text section data
    let text_section = builder.sections.get_mut(text_section_id);
    let elf::SectionData::Data(text_data_mut) = &mut text_section.data else {
        return Err(anyhow::anyhow!("Failed to get .text section data"));
    };
    let text_data_mut = text_data_mut.to_mut();
    text_data_mut.copy_from_slice(&text_data);

    // Update the trampoline section
    let trampoline_section = builder.sections.get_mut(trampoline_section_id);
    let elf::SectionData::Data(trampoline_data_mut) = &mut trampoline_section.data else {
        return Err(anyhow::anyhow!("Failed to get .trampoline section data"));
    };
    let trampoline_data_mut = trampoline_data_mut.to_mut();
    trampoline_data_mut.extend_from_slice(&trampoline_data);
    trampoline_section.sh_size = trampoline_data.len() as u64;

    // Update the segment containing the trampoline section
    let text_segment = builder.segments.get_mut(text_segment_id);
    text_segment.recalculate_ranges(&builder.sections);

    // Move sections
    rewriter::move_sections(&mut builder)
        .with_context(|| format!("Failed to move sections in file '{}'", in_path.display()))?;

    // Write the modified ELF file
    let out_path = in_path.with_extension("hooked");
    let out_file = fs::File::create(&out_path)
        .with_context(|| format!("Failed to create output file '{}'", out_path.display()))?;
    let mut out_buffer = object::write::StreamingBuffer::new(out_file);
    builder
        .write(&mut out_buffer)
        .with_context(|| format!("Failed to write output file '{}'", out_path.display()))?;
    out_buffer
        .result()
        .with_context(|| format!("Failed to finalize output file '{}'", out_path.display()))?;

    println!(
        "Hooked syscalls in '{}', output written to '{}'",
        in_path.display(),
        out_path.display()
    );

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: syscall-rewriter <elf-file>");
        std::process::exit(1);
    }

    let in_path = Path::new(&args[1]);
    rewrite_elf(in_path)
        .with_context(|| format!("Failed to hook syscalls in file '{}'", in_path.display()))?;

    Ok(())
}
