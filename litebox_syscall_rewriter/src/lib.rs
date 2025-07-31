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

use capstone::arch::x86::X86InsnGroup::{X86_GRP_CALL, X86_GRP_JUMP, X86_GRP_RET};
use capstone::prelude::*;

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
}

impl From<capstone::Error> for Error {
    fn from(error: capstone::Error) -> Self {
        Error::DisassemblyFailure(error.to_string())
    }
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
#[allow(clippy::too_many_lines)]
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<usize>) -> Result<Vec<u8>> {
    let mut input_workaround: Vec<u64>;
    let input_binary: &[u8] = if (&raw const input_binary[0] as usize) % 8 != 0 {
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
    } else {
        input_binary
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
    let (dl_sysinfo_int80, libc_start_call_main) = if arch == Arch::X86_32 {
        get_symbols(&builder)
    } else {
        (None, None)
    };

    let text_sections = text_sections(&builder)?;
    let trampoline_section = setup_trampoline_section(&mut builder)?;

    // Get control transfer targets
    let control_transfer_targets =
        get_control_transfer_targets(arch, &builder, &text_sections).unwrap();

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
                // ensure the segment has enough space for the trampoline section (0x18 bytes)
                let end_offset = seg[0].p_offset + seg[0].p_filesz;
                if seg[1].p_type == object::elf::PT_LOAD && seg[1].p_offset - end_offset < 0x18 {
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
    trampoline_data.extend_from_slice(&trampoline.unwrap_or(0).to_le_bytes());

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
            libc_start_call_main,
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
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn hook_syscalls_in_section(
    arch: Arch,
    control_transfer_targets: &HashSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    dl_sysinfo_int80: Option<u64>,
    libc_start_call_main: Option<(u64, u64)>,
    trampoline_data: &mut Vec<u8>,
) -> Result<()> {
    // Disassemble the section
    let cs = capstone::Capstone::new()
        .x86()
        .mode(match arch {
            Arch::X86_32 => capstone::arch::x86::ArchMode::Mode32,
            Arch::X86_64 => capstone::arch::x86::ArchMode::Mode64,
        })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;
    let instructions = cs.disasm_all(section_data, section_base_addr)?;

    for (i, inst) in instructions.iter().enumerate() {
        // Forward search for `syscall` / `int 0x80` / `call DWORD PTR gs:0x10`
        match arch {
            Arch::X86_32 => {
                if dl_sysinfo_int80.is_some_and(|x| x == inst.address()) {
                    continue; // Skip the `dl_sysinfo_int80` instruction
                }
                // `call DWORD PTR gs:0x10` or `int 0x80`
                if inst.bytes() != [0x65, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00]
                    && inst.bytes() != [0xcd, 0x80]
                {
                    continue;
                }
            }
            Arch::X86_64 => {
                if capstone::arch::x86::X86Insn::from(inst.id().0)
                    != capstone::arch::x86::X86Insn::X86_INS_SYSCALL
                {
                    continue;
                }
            }
        }

        let replace_end = inst
            .address()
            .checked_add(inst.bytes().len().try_into().unwrap())
            .unwrap();

        let mut replace_start = None;
        for inst_id in (0..=i).rev() {
            let prev_inst = &instructions[inst_id];
            let prev_inst_detail = cs.insn_detail(prev_inst).unwrap();
            // Check if the instruction does control transfer
            // TODO: Check if the instruction is an instruction-relative control transfer
            let is_control_transfer = inst_id != i
                && prev_inst_detail.groups().iter().any(|&grp| {
                    grp.0 == u8::try_from(X86_GRP_JUMP).unwrap()
                        || grp.0 == u8::try_from(X86_GRP_CALL).unwrap()
                        || grp.0 == u8::try_from(X86_GRP_RET).unwrap()
                });
            if is_control_transfer {
                // If it's a control transfer, we don't want to cross it
                break;
            }
            if replace_end - prev_inst.address() >= 5 {
                replace_start = Some(prev_inst.address());
                break;
            }
            // We ignore this check inside the __libc_start_call_main function
            // because it has a redundant backward jmp to repeat the exit syscall
            // which is not supposed to be returned from the kernel.
            // Our current patching approach cannot handle this case yet.
            // A potential solution is to patch both before and after the syscall instruction.
            else if libc_start_call_main.is_none_or(|(addr, size)| {
                prev_inst.address() < addr || prev_inst.address() >= addr + size
            }) && control_transfer_targets.contains(&prev_inst.address())
            {
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
                &cs,
                &instructions,
                i,
            )?;
            continue;
        }

        let replace_start = replace_start.unwrap();
        let replace_len = usize::try_from(replace_end - replace_start).unwrap();

        let target_addr = trampoline_base_addr + trampoline_data.len() as u64;

        // Copy the original instructions to the trampoline
        if replace_start < inst.address() {
            trampoline_data.extend_from_slice(
                &section_data[usize::try_from(replace_start - section_base_addr).unwrap()
                    ..usize::try_from(inst.address() - section_base_addr).unwrap()],
            );
        }

        // Add call [rip + offset_to_shared_target]
        if arch == Arch::X86_64 {
            trampoline_data.extend_from_slice(&[0xFF, 0x15]);
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 4);
            trampoline_data.extend_from_slice(&disp32.to_le_bytes());
        } else {
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

        // Add jmp back to original after syscall
        let return_addr = inst.address() + inst.bytes().len() as u64;
        let jmp_back_offset = i64::try_from(return_addr).unwrap()
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

fn get_symbols(builder: &object::build::elf::Builder<'_>) -> (Option<u64>, Option<(u64, u64)>) {
    let mut dl_sysinfo_int80 = None;
    let mut libc_start_call_main = None;
    for sym in &builder.symbols {
        if sym.st_type() == object::elf::STT_FUNC {
            let name = sym.name.to_string();
            if name == "_dl_sysinfo_int80" {
                dl_sysinfo_int80 = Some(sym.st_value);
            } else if name == "__libc_start_call_main" {
                libc_start_call_main = Some((sym.st_value, sym.st_size));
            }
        }
    }
    (dl_sysinfo_int80, libc_start_call_main)
}

fn get_control_transfer_targets(
    arch: Arch,
    builder: &object::build::elf::Builder<'_>,
    text_sections: &[object::build::elf::SectionId],
) -> Result<HashSet<u64>> {
    let mut control_transfer_targets = HashSet::new();
    for s in text_sections {
        let s = builder.sections.get(*s);
        let object::build::elf::SectionData::Data(section_data) = &s.data else {
            unimplemented!()
        };
        // Disassemble the section
        let cs = capstone::Capstone::new()
            .x86()
            .mode(match arch {
                Arch::X86_32 => capstone::arch::x86::ArchMode::Mode32,
                Arch::X86_64 => capstone::arch::x86::ArchMode::Mode64,
            })
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?;
        let instructions = cs.disasm_all(section_data, s.sh_addr)?;

        for inst in instructions.iter() {
            let inst_detail = cs.insn_detail(inst).unwrap();

            // Check if the instruction does control transfer
            let is_jmp_or_call = inst_detail.groups().iter().any(|&grp| {
                grp.0 == u8::try_from(X86_GRP_JUMP).unwrap()
                    || grp.0 == u8::try_from(X86_GRP_CALL).unwrap()
            });
            if !is_jmp_or_call {
                continue;
            }
            let arch_detail = inst_detail.arch_detail();
            let ops = arch_detail.operands();
            if ops.len() != 1 {
                continue; // We expect a single operand when it's a direct control transfer
            }
            if let capstone::arch::ArchOperand::X86Operand(op) = &ops[0] {
                if let capstone::arch::x86::X86OperandType::Imm(imm) = op.op_type {
                    control_transfer_targets.insert(u64::try_from(imm).unwrap());
                }
            }
        }
    }

    Ok(control_transfer_targets)
}

#[allow(clippy::too_many_arguments)]
fn hook_syscall_and_after(
    arch: Arch,
    control_transfer_targets: &HashSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    trampoline_data: &mut Vec<u8>,
    cs: &capstone::Capstone,
    instructions: &[capstone::Insn],
    inst_index: usize,
) -> Result<()> {
    let syscall_inst = &instructions[inst_index];

    let replace_start = syscall_inst.address();

    let mut replace_end = None;

    for next_inst in instructions.iter().skip(inst_index) {
        if next_inst.id() != syscall_inst.id()
            && control_transfer_targets.contains(&next_inst.address())
        {
            // If the next instruction is a control transfer target, we don't want to cross it
            println!(
                "Skipping control transfer target at {:#x}",
                next_inst.address()
            );
            break;
        }
        let next_inst_detail = cs.insn_detail(next_inst).unwrap();
        // Check if the instruction does control transfer
        // TODO: Check if the instruction is an instruction-relative control transfer
        let is_control_transfer = next_inst.id() != syscall_inst.id()
            && next_inst_detail.groups().iter().any(|&grp| {
                grp.0 == u8::try_from(X86_GRP_JUMP).unwrap()
                    || grp.0 == u8::try_from(X86_GRP_CALL).unwrap()
                    || grp.0 == u8::try_from(X86_GRP_RET).unwrap()
            });
        if is_control_transfer {
            // If it's a control transfer, we don't want to cross it
            break;
        }
        let next_end = next_inst
            .address()
            .checked_add(next_inst.bytes().len().try_into().unwrap())
            .unwrap();

        if next_end - syscall_inst.address() >= 5 {
            replace_end = Some(next_end);
            break;
        }
    }

    let replace_end =
        replace_end.ok_or_else(|| Error::InsufficientBytesBeforeOrAfter(syscall_inst.address()))?;

    let target_addr = trampoline_base_addr + trampoline_data.len() as u64;

    // Add call [rip + offset_to_shared_target]
    if arch == Arch::X86_64 {
        trampoline_data.extend_from_slice(&[0xFF, 0x15]);
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 4);
        trampoline_data.extend_from_slice(&disp32.to_le_bytes());
    } else {
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
    let syscall_inst_end = syscall_inst
        .address()
        .checked_add(syscall_inst.bytes().len().try_into().unwrap())
        .unwrap();
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
