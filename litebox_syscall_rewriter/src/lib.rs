//! Rewrite ELF files to hook syscalls
//!
//! This crate sets up a trampoline point for every `syscall` instruction in its input binary,
//! allowing for conveniently taking control of a binary without ptrace/systrap/seccomp/...
//!
//! This approach is not 100% foolproof, and should not be considered a security boundary. Instead,
//! it is a slowly-improving best-effort technique. As an explicit non-goal, this technique will
//! **NOT** support dynamically generated `syscall` instructions (for example, generated in a JIT).
//! However, as an explicit goal, it is intended to provide low-overhead hooking of syscalls,
//! without needing to undergo a user-kernel transition.
//!
//! This crate currently only supports x86-64 (i.e., amd64) ELFs.

use std::collections::HashSet;

use thiserror::Error;

/// Possible errors during hooking of `syscall` instructions
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to parse: {0}")]
    ParseError(String),
    #[error("failed to generate object file: {0}")]
    GenerateObjFileError(String),
    #[error("unsupported executable")]
    UnsupportedObjectFile,
    #[error("executable is already hooked with trampoline")]
    AlreadyHooked,
    #[error("no .text section found")]
    NoTextSectionFound,
    #[error("no syscall instructions found")]
    NoSyscallInstructionsFound,
    #[error("failed to disassemble: {0}")]
    DisassemblyFailure(String),
    #[error("insufficient bytes before or after syscall at {0:#x}")]
    InsufficientBytesBeforeOrAfter(u64),
    #[error("provided trampoline address is too large for 32-bit executable")]
    TrampolineAddressTooLarge,
}

type Result<T> = std::result::Result<T, Error>;

/// The prefix for any trampolines inserted by any version of this crate.
///
/// Downstream users might wish to check for (case-insensitive) comparison against this to see if
/// there might be a trampoline, if the exact [`TRAMPOLINE_SECTION_NAME`] does not match, in order
/// to provide more useful error messages.
///
/// ```rust
/// # use litebox_syscall_rewriter::TRAMPOLINE_SECTION_NAME;
/// # use litebox_syscall_rewriter::TRAMPOLINE_SECTION_NAME_PREFIX;
/// assert!(TRAMPOLINE_SECTION_NAME.starts_with(TRAMPOLINE_SECTION_NAME_PREFIX));
/// ```
pub const TRAMPOLINE_SECTION_NAME_PREFIX: &str = ".trampolineLB";

/// The name of the section for the trampoline.
///
/// This contains both [`TRAMPOLINE_SECTION_NAME_PREFIX`] as well as a version number, that might be
/// incremented if its design changes significantly enough that downstream users might need to care
/// about it.
///
/// Downstream users are exepcted to check for this exact section name (including case sensitivity)
/// to know that they have a trampoline that satisfies the expected version.
pub const TRAMPOLINE_SECTION_NAME: &str = ".trampolineLB0";

/// The size of the trampoline section, which includes the magic number, the trampoline address, and the size of the trampoline data.
const TRAMPOLINE_SECTION_SIZE: usize = 0x18;

/// Update the `input_binary` with a call to `trampoline` instead of any `syscall` instructions.
///
/// The `trampoline` must be an absolute address if specified; if unspecified, it will be set to
/// zeros, and it is the caller's decision to overwrite it at loading time.
///
/// If it succeeds, it produces an executable with a [`TRAMPOLINE_SECTION_NAME`] section whose first
/// 8 bytes point to the `trampoline` address.
#[expect(
    clippy::missing_panics_doc,
    reason = "any panics in here are not part of the public contract and should be fixed within this module"
)]
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    let mut input_workaround: Vec<u64>;
    let input_binary: &[u8] = if (&raw const input_binary[0] as usize).is_multiple_of(8) {
        input_binary
    } else {
        // JB: This is an ugly workaround to `object` requiring that its input binary being parsed
        // is always aligned to 8-bytes (otherwise it throws an error); this is very surprising and
        // probably should be corrected upstream in `object`, but for now, we just make a copy and
        // re-run. Essentially, we use u64 to force a 8-byte alignment, but then we look at it as
        // bytes instead.
        input_workaround = vec![0u64; input_binary.len() / 8 + 1];
        let input_workaround_bytes: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                input_workaround.as_mut_ptr().cast(),
                input_workaround.len() * 8,
            )
        };
        let input_workaround_bytes = &mut input_workaround_bytes[..input_binary.len()];
        input_workaround_bytes.copy_from_slice(input_binary);
        &*input_workaround_bytes
    };
    assert_eq!((&raw const input_binary[0] as usize) % 8, 0);
    let mut builder = match object::FileKind::parse(input_binary)
        .map_err(|e| Error::ParseError(e.to_string()))?
    {
        object::FileKind::Elf64 => object::build::elf::Builder::read64(input_binary),
        object::FileKind::Elf32 => object::build::elf::Builder::read32(input_binary),
        _ => return Err(Error::UnsupportedObjectFile),
    }
    .map_err(|e| Error::ParseError(e.to_string()))?;
    let arch = if builder.is_64 {
        Arch::X86_64
    } else {
        Arch::X86_32
    };

    // Get symbols
    let dl_sysinfo_int80 = if arch == Arch::X86_32 {
        get_symbols(&builder)
    } else {
        None
    };

    let text_sections = text_sections(&builder)?;
    let trampoline_section = setup_trampoline_section(&mut builder)?;

    // Get control transfer targets
    let control_transfer_targets = get_control_transfer_targets(arch, &builder, &text_sections);

    let last_segment_id = {
        let s: Vec<_> = builder
            .segments
            .iter()
            .collect::<Vec<_>>()
            .windows(2)
            .filter(|seg| {
                // ensure the segment is okay to insert the trampoline section
                if seg[0].p_type != object::elf::PT_LOAD
                    || seg[0].p_flags & object::elf::PF_R == 0
                    || seg[0].p_filesz != seg[0].p_memsz
                {
                    return false;
                }
                // ensure the segment has enough space for the trampoline section
                let end_offset = seg[0].p_offset + seg[0].p_filesz;
                if seg[1].p_type == object::elf::PT_LOAD
                    && seg[1].p_offset - end_offset < TRAMPOLINE_SECTION_SIZE as u64
                {
                    return false;
                }
                if end_offset.next_multiple_of(0x1000) - end_offset < TRAMPOLINE_SECTION_SIZE as u64
                {
                    return false;
                }
                true
            })
            .map(|seg| seg[0])
            .collect();
        if s.is_empty() {
            return Err(Error::NoTextSectionFound);
        }
        s[s.len() - 1].id()
    };
    builder
        .segments
        .get_mut(last_segment_id)
        .append_section(builder.sections.get_mut(trampoline_section));

    let trampoline_base_addr = find_addr_for_trampoline_code(&builder);

    let mut trampoline_data = vec![];
    // The magic prefix for the trampoline section
    // This constant should be consistent with the definitions in the shim
    // (litebox_shim_linux/src/loader/mod.rs)
    trampoline_data.extend_from_slice("LITEBOX0".as_bytes());
    // The placeholder for the address of the new syscall entry point
    let trampoline = trampoline.unwrap_or(0);
    if arch == Arch::X86_64 {
        trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
    } else {
        let trampoline = u32::try_from(trampoline).map_err(|_| Error::TrampolineAddressTooLarge)?;
        trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
    }

    let mut syscall_insns_found = false;
    for s in &text_sections {
        let s = builder.sections.get_mut(*s);
        let object::build::elf::SectionData::Data(data) = &mut s.data else {
            unimplemented!()
        };
        match hook_syscalls_in_section(
            arch,
            &control_transfer_targets,
            s.sh_addr,
            data.to_mut(),
            trampoline_base_addr,
            dl_sysinfo_int80,
            &mut trampoline_data,
        ) {
            Ok(()) => {
                syscall_insns_found = true;
            }
            Err(Error::NoSyscallInstructionsFound) => {}
            Err(e) => return Err(e),
        }
    }

    if !syscall_insns_found {
        return Err(Error::NoSyscallInstructionsFound);
    }

    let mut trampoline_vec = Vec::new();
    // This constant should be consistent with the definitions in the shim
    // (litebox_shim_linux/src/loader/mod.rs)
    trampoline_vec.extend_from_slice("LITE BOX".as_bytes());
    trampoline_vec.extend_from_slice(&trampoline_base_addr.to_le_bytes());
    trampoline_vec.extend_from_slice(&(trampoline_data.len() as u64).to_le_bytes());
    assert_eq!(trampoline_vec.len(), TRAMPOLINE_SECTION_SIZE);
    builder.sections.get_mut(trampoline_section).sh_size = trampoline_vec.len() as u64;
    builder.sections.get_mut(trampoline_section).data =
        object::build::elf::SectionData::Data(trampoline_vec.into());
    builder
        .segments
        .get_mut(last_segment_id)
        .recalculate_ranges(&builder.sections);

    let mut out = vec![];
    builder
        .write(&mut out)
        .map_err(|e| Error::GenerateObjFileError(e.to_string()))?;
    // ensure the start address of the trampoline code is page-aligned
    let remain = out.len() % 0x1000;
    out.extend_from_slice(&vec![0; if remain == 0 { 0 } else { 0x1000 - remain }]);
    out.extend_from_slice(&trampoline_data);
    Ok(out)
}

/// (private) Get the section IDs for the text sections
fn text_sections(
    builder: &object::build::elf::Builder<'_>,
) -> Result<Vec<object::build::elf::SectionId>> {
    let text_sections: Vec<_> = builder
        .sections
        .iter()
        .filter(|s| {
            s.sh_type == object::elf::SHT_PROGBITS
                && s.sh_flags & u64::from(object::elf::SHF_ALLOC) != 0
                && s.sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0
        })
        .map(object::build::elf::Section::id)
        .collect();
    if text_sections.is_empty() {
        return Err(Error::NoTextSectionFound);
    }
    Ok(text_sections)
}

// (private) Sets up the trampoline section
fn setup_trampoline_section(
    builder: &mut object::build::elf::Builder<'_>,
) -> Result<object::build::elf::SectionId> {
    if builder
        .sections
        .iter()
        .any(|s| s.name == TRAMPOLINE_SECTION_NAME.into())
    {
        return Err(Error::AlreadyHooked);
    }
    let s = builder.sections.add();
    *s.name.to_mut() = TRAMPOLINE_SECTION_NAME.into();
    s.sh_type = object::elf::SHT_PROGBITS;
    s.sh_flags = object::elf::SHF_ALLOC.into();
    s.sh_addralign = 8;
    Ok(s.id())
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
enum Arch {
    X86_32,
    X86_64,
}

/// (private) Hook all syscalls in `section`, possibly extending `trampoline_data` to do so.
#[allow(clippy::too_many_arguments)]
fn hook_syscalls_in_section(
    arch: Arch,
    control_transfer_targets: &HashSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    dl_sysinfo_int80: Option<u64>,
    trampoline_data: &mut Vec<u8>,
) -> Result<()> {
    // Disassemble the section
    let mut decoder = iced_x86::Decoder::new(
        match arch {
            Arch::X86_32 => 32,
            Arch::X86_64 => 64,
        },
        section_data,
        iced_x86::DecoderOptions::NONE,
    );
    decoder.set_ip(section_base_addr);
    let instructions = decoder.iter().collect::<Vec<_>>();
    for (i, inst) in instructions.iter().enumerate() {
        // Forward search for `syscall` / `int 0x80` / `call DWORD PTR gs:0x10`
        match arch {
            Arch::X86_32 => {
                if dl_sysinfo_int80.is_some_and(|x| x == inst.ip()) {
                    continue; // Skip the `dl_sysinfo_int80` instruction
                }
                // `call DWORD PTR gs:0x10` or `int 0x80`
                if !((inst.code() == iced_x86::Code::Call_rm32
                    && inst.segment_prefix() == iced_x86::Register::GS
                    && inst.memory_displacement32() == 0x10)
                    || (inst.code() == iced_x86::Code::Int_imm8 && inst.immediate8() == 0x80))
                {
                    continue;
                }
            }
            Arch::X86_64 => {
                if inst.code() != iced_x86::Code::Syscall {
                    continue;
                }
            }
        }

        let replace_end = inst.next_ip();

        let mut replace_start = None;
        for inst_id in (0..=i).rev() {
            let prev_inst = &instructions[inst_id];
            // Check if the instruction does control transfer
            // TODO: Check if the instruction is an instruction-relative control transfer
            let is_control_transfer =
                inst_id != i && prev_inst.flow_control() != iced_x86::FlowControl::Next;
            if is_control_transfer {
                // If it's a control transfer, we don't want to cross it
                break;
            }
            if replace_end - prev_inst.ip() >= 5 {
                replace_start = Some(prev_inst.ip());
                break;
            } else if control_transfer_targets.contains(&prev_inst.ip()) {
                // If the previous instruction is a control transfer target, we don't want to cross it
                break;
            }
        }

        if replace_start.is_none() {
            hook_syscall_and_after(
                arch,
                control_transfer_targets,
                section_base_addr,
                section_data,
                trampoline_base_addr,
                trampoline_data,
                &instructions,
                i,
            )?;
            continue;
        }

        let replace_start = replace_start.unwrap();
        let replace_len = usize::try_from(replace_end - replace_start).unwrap();

        let target_addr = trampoline_base_addr + trampoline_data.len() as u64;

        // Copy the original instructions to the trampoline
        if replace_start < inst.ip() {
            trampoline_data.extend_from_slice(
                &section_data[usize::try_from(replace_start - section_base_addr).unwrap()
                    ..usize::try_from(inst.ip() - section_base_addr).unwrap()],
            );
        }

        let return_addr = inst.next_ip();
        if arch == Arch::X86_64 {
            // Put jump back location into rcx.
            let jmp_back_offset = i64::try_from(return_addr).unwrap()
                - i64::try_from(trampoline_base_addr + trampoline_data.len() as u64 + 7).unwrap();
            trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D]); // LEA RCX, [RIP + disp32]
            trampoline_data
                .extend_from_slice(&(i32::try_from(jmp_back_offset).unwrap().to_le_bytes()));

            // Add jmp [rip + offset_to_shared_target]
            trampoline_data.extend_from_slice(&[0xFF, 0x25]);
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 4);
            trampoline_data.extend_from_slice(&disp32.to_le_bytes());
        } else {
            // Add call [rip + offset_to_shared_target]
            // For 32-bit, use a different approach to simulate `call [rip + disp32]`
            trampoline_data.push(0x50); // PUSH EAX
            trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
            trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
            trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 11);
            trampoline_data.extend_from_slice(&disp32.to_le_bytes());
            // Note we skip `POP EAX` here as it is done by the callback `syscall_callback`
            // from litebox_shim_linux/src/lib.rs, which helps reduce the size of the trampoline.

            // Add jmp back to original after syscall
            let jmp_back_offset = i64::try_from(return_addr).unwrap()
                - i64::try_from(trampoline_base_addr + trampoline_data.len() as u64 + 5).unwrap();
            trampoline_data.push(0xE9);
            trampoline_data
                .extend_from_slice(&(i32::try_from(jmp_back_offset).unwrap().to_le_bytes()));
        }

        // Replace original instructions with jump to trampoline
        let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
        section_data[replace_offset] = 0xE9; // JMP rel32
        let jump_offset =
            i64::try_from(target_addr).unwrap() - i64::try_from(replace_start + 5).unwrap();
        section_data[replace_offset + 1..replace_offset + 5]
            .copy_from_slice(&(i32::try_from(jump_offset).unwrap().to_le_bytes()));

        // Fill remaining bytes with NOP
        for idx in 5..replace_len {
            section_data[replace_offset + idx] = 0x90;
        }
    }

    Ok(())
}

fn find_addr_for_trampoline_code(builder: &object::build::elf::Builder<'_>) -> u64 {
    // Find the highest virtual address among all sections in executable segments
    let max_virtual_addr = builder
        .segments
        .iter()
        .filter(|seg| seg.p_type == object::elf::PT_LOAD)
        .map(|seg| seg.p_vaddr + seg.p_memsz)
        .max()
        .unwrap();

    // Round up to the nearest page (assume 0x1000 page size)
    max_virtual_addr.next_multiple_of(0x1000)
}

fn get_symbols(builder: &object::build::elf::Builder<'_>) -> Option<u64> {
    let mut dl_sysinfo_int80 = None;
    for sym in &builder.symbols {
        if sym.st_type() == object::elf::STT_FUNC {
            let name = sym.name.to_string();
            if name == "_dl_sysinfo_int80" {
                dl_sysinfo_int80 = Some(sym.st_value);
            }
        }
    }
    dl_sysinfo_int80
}

fn get_control_transfer_targets(
    arch: Arch,
    builder: &object::build::elf::Builder<'_>,
    text_sections: &[object::build::elf::SectionId],
) -> HashSet<u64> {
    let mut control_transfer_targets = HashSet::new();
    for s in text_sections {
        let s = builder.sections.get(*s);
        let object::build::elf::SectionData::Data(section_data) = &s.data else {
            unimplemented!()
        };
        // Disassemble the section
        let mut decoder = iced_x86::Decoder::new(
            match arch {
                Arch::X86_32 => 32,
                Arch::X86_64 => 64,
            },
            section_data,
            iced_x86::DecoderOptions::NONE,
        );
        decoder.set_ip(s.sh_addr);
        control_transfer_targets.extend(decoder.into_iter().filter_map(|inst| {
            let target = inst.near_branch_target();
            (target != 0).then_some(target)
        }));
    }

    control_transfer_targets
}

#[allow(clippy::too_many_arguments)]
fn hook_syscall_and_after(
    arch: Arch,
    control_transfer_targets: &HashSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    trampoline_data: &mut Vec<u8>,
    instructions: &[iced_x86::Instruction],
    inst_index: usize,
) -> Result<()> {
    let syscall_inst = &instructions[inst_index];

    let replace_start = syscall_inst.ip();
    let mut replace_end = None;

    for next_inst in instructions.iter().skip(inst_index) {
        if next_inst.code() != syscall_inst.code()
            && control_transfer_targets.contains(&next_inst.ip())
        {
            // If the next instruction is a control transfer target, we don't want to cross it
            println!("Skipping control transfer target at {:#x}", next_inst.ip());
            break;
        }
        // Check if the instruction does control transfer
        // TODO: Check if the instruction is an instruction-relative control transfer
        let is_control_transfer = next_inst.code() != syscall_inst.code()
            && next_inst.flow_control() != iced_x86::FlowControl::Next;
        if is_control_transfer {
            // If it's a control transfer, we don't want to cross it
            break;
        }
        let next_end = next_inst.next_ip();

        if next_end - syscall_inst.ip() >= 5 {
            replace_end = Some(next_end);
            break;
        }
    }

    if replace_end.is_none() {
        return hook_syscall_before_and_after(
            arch,
            control_transfer_targets,
            section_base_addr,
            section_data,
            trampoline_base_addr,
            trampoline_data,
            instructions,
            inst_index,
        );
    }

    let replace_end = replace_end.unwrap();

    let target_addr = trampoline_base_addr + trampoline_data.len() as u64;

    if arch == Arch::X86_64 {
        // Put jump back location into rcx, via lea rcx, [next instruction]
        trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D]); // LEA RCX, [RIP + disp32]
        trampoline_data.extend_from_slice(&6u32.to_le_bytes());
        // Add jmp [rip + offset_to_shared_target]
        trampoline_data.extend_from_slice(&[0xFF, 0x25]);
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 4);
        trampoline_data.extend_from_slice(&disp32.to_le_bytes());
    } else {
        // Add call [rip + offset_to_shared_target]
        // For 32-bit, use a different approach to simulate `call [rip + disp32]`
        trampoline_data.push(0x50); // PUSH EAX
        trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
        trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
        trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 11);
        trampoline_data.extend_from_slice(&disp32.to_le_bytes());
        // Note we skip `POP EAX` here as it is done by the callback `syscall_callback`
        // from litebox_shim_linux/src/lib.rs, which helps reduce the size of the trampoline.
    }

    // Copy the original instructions to the trampoline
    let syscall_inst_end = syscall_inst.next_ip();
    if syscall_inst_end < replace_end {
        trampoline_data.extend_from_slice(
            &section_data[usize::try_from(syscall_inst_end - section_base_addr).unwrap()
                ..usize::try_from(replace_end - section_base_addr).unwrap()],
        );
    }

    // Add jmp back to original after syscall
    let jmp_back_offset = i64::try_from(replace_end).unwrap()
        - i64::try_from(trampoline_base_addr + trampoline_data.len() as u64 + 5).unwrap();
    trampoline_data.push(0xE9);
    trampoline_data.extend_from_slice(&(i32::try_from(jmp_back_offset).unwrap().to_le_bytes()));

    // Replace original instructions with jump to trampoline
    let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
    section_data[replace_offset] = 0xE9; // JMP rel32
    let jump_offset =
        i64::try_from(target_addr).unwrap() - i64::try_from(replace_start + 5).unwrap();
    section_data[replace_offset + 1..replace_offset + 5]
        .copy_from_slice(&(i32::try_from(jump_offset).unwrap().to_le_bytes()));

    // Fill remaining bytes with NOP
    let replace_len = usize::try_from(replace_end - replace_start).unwrap();
    for idx in 5..replace_len {
        section_data[replace_offset + idx] = 0x90;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hook_syscall_before_and_after(
    arch: Arch,
    control_transfer_targets: &HashSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    trampoline_data: &mut Vec<u8>,
    instructions: &[iced_x86::Instruction],
    inst_index: usize,
) -> Result<()> {
    let syscall_inst = &instructions[inst_index];
    let syscall_inst_addr = syscall_inst.ip();
    // We only support this case for x86
    if arch != Arch::X86_32 {
        return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
    }

    // We expect at least one instruction before and one instruction
    // after the syscall instruction
    if inst_index == 0 || inst_index + 1 >= instructions.len() {
        return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
    }

    let prev_inst = &instructions[inst_index - 1];
    let next_inst = &instructions[inst_index + 1];

    // Make sure we have enough space
    if prev_inst.len() + syscall_inst.len() + next_inst.len() < 5 {
        return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
    }

    // Both the syscall and its following instructions cannot be a control transfer target
    if control_transfer_targets.contains(&syscall_inst_addr)
        || control_transfer_targets.contains(&next_inst.ip())
    {
        return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
    }

    // We don't support the case when the previous instruction is a control transfer instruction
    if prev_inst.flow_control() != iced_x86::FlowControl::Next {
        return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
    }

    // We currently only support relative jmp or ret instructions
    // if it's a control transfer instruction.
    let need_jump_back = match next_inst.flow_control() {
        iced_x86::FlowControl::Next => true,
        iced_x86::FlowControl::Return => false,
        iced_x86::FlowControl::UnconditionalBranch => {
            if next_inst.near_branch_target() != prev_inst.ip() {
                return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
            }
            false
        }
        iced_x86::FlowControl::IndirectBranch
        | iced_x86::FlowControl::ConditionalBranch
        | iced_x86::FlowControl::Call
        | iced_x86::FlowControl::IndirectCall
        | iced_x86::FlowControl::Interrupt
        | iced_x86::FlowControl::XbeginXabortXend
        | iced_x86::FlowControl::Exception => {
            return Err(Error::InsufficientBytesBeforeOrAfter(syscall_inst_addr));
        }
    };

    let target_addr = trampoline_base_addr + trampoline_data.len() as u64;
    let replace_start = prev_inst.ip();
    let replace_len = usize::try_from(next_inst.next_ip() - replace_start).unwrap();

    // Copy the prev instructions to the trampoline
    trampoline_data.extend_from_slice(
        &section_data[usize::try_from(prev_inst.ip() - section_base_addr).unwrap()..]
            [..prev_inst.len()],
    );

    // For 32-bit, use a different approach to simulate `call [rip + disp32]`
    trampoline_data.push(0x50); // PUSH EAX
    trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
    trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
    trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
    let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 11);
    trampoline_data.extend_from_slice(&disp32.to_le_bytes());
    // Note we skip `POP EAX` here as it is done by the callback `syscall_callback`
    // from litebox_shim_linux/src/lib.rs, which helps reduce the size of the trampoline.

    // Copy the next inst
    trampoline_data.extend_from_slice(
        &section_data[usize::try_from(next_inst.ip() - section_base_addr).unwrap()..]
            [..next_inst.len()],
    );

    // Add jmp back to original after syscall if needed
    if need_jump_back {
        let return_addr = next_inst.next_ip();
        let jmp_back_offset = i64::try_from(return_addr).unwrap()
            - i64::try_from(trampoline_base_addr + trampoline_data.len() as u64 + 5).unwrap();
        trampoline_data.push(0xE9);
        trampoline_data.extend_from_slice(&(i32::try_from(jmp_back_offset).unwrap().to_le_bytes()));
    }

    // Replace original instructions with jump to trampoline
    let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
    section_data[replace_offset] = 0xE9; // JMP rel32
    let jump_offset =
        i64::try_from(target_addr).unwrap() - i64::try_from(replace_start + 5).unwrap();
    section_data[replace_offset + 1..replace_offset + 5]
        .copy_from_slice(&(i32::try_from(jump_offset).unwrap().to_le_bytes()));

    // Fill remaining bytes with NOP
    for idx in 5..replace_len {
        section_data[replace_offset + idx] = 0x90;
    }

    Ok(())
}
