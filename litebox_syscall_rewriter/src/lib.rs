// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

use object::read::{Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Possible errors during hooking of `syscall` instructions
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to parse: {0}")]
    ParseError(String),
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

/// The magic bytes used to identify the trampoline data.
/// This is checked by the loader to verify that the trampoline is valid.
pub const TRAMPOLINE_MAGIC: &[u8; 8] = b"LITEBOX0";

/// Trampoline header for 64-bit: 8 (magic) + 8 (file_offset) + 8 (vaddr) + 8 (size) = 32 bytes
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct TrampolineHeader64 {
    magic: [u8; 8],
    file_offset: u64,
    vaddr: u64,
    trampoline_size: u64,
}

/// Trampoline header for 32-bit: 8 (magic) + 4 (file_offset) + 4 (vaddr) + 4 (size) = 20 bytes
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct TrampolineHeader32 {
    magic: [u8; 8],
    file_offset: u32,
    vaddr: u32,
    trampoline_size: u32,
}

/// Metadata about an executable section, extracted from the read-only ELF parse.
struct TextSectionInfo {
    /// Virtual address of the section
    vaddr: u64,
    /// File offset where the section data starts
    file_offset: u64,
    /// Size of the section data in bytes
    size: u64,
}

/// Update the `input_binary` with a call to `trampoline` instead of any `syscall` instructions.
///
/// The `trampoline` must be an absolute address if specified; if unspecified, it will be set to
/// zeros, and it is the caller's decision to overwrite it at loading time.
///
/// If it succeeds, it produces an executable with trampoline code appended at a page-aligned
/// offset after the ELF file. The file layout is:
/// `[original ELF][padding to page boundary][trampoline code][header]`
///
/// The header at the end contains:
/// - [`TRAMPOLINE_MAGIC`] (8 bytes)
/// - trampoline file offset (8 bytes for 64-bit, 4 bytes for 32-bit)
/// - trampoline virtual address (8 bytes for 64-bit, 4 bytes for 32-bit)
/// - trampoline size (8 bytes for 64-bit, 4 bytes for 32-bit)
///
/// This layout allows loaders to read just the last 32/20 bytes to get the metadata.
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    // `object::File::parse` requires that its input is 8-byte aligned. If not, make an aligned
    // copy. We use a Vec<u64> to guarantee 8-byte alignment, then view it as bytes.
    let mut aligned_buf: Vec<u64>;
    let input_binary: &[u8] = if (input_binary.as_ptr() as usize).is_multiple_of(8) {
        input_binary
    } else {
        // JB: This is an ugly workaround to `object` requiring that its input binary being parsed
        // is always aligned to 8-bytes (otherwise it throws an error); this is very surprising and
        // probably should be corrected upstream in `object`, but for now, we just make a copy and
        // re-run. Essentially, we use u64 to force a 8-byte alignment, but then we look at it as
        // bytes instead.
        aligned_buf = vec![0u64; input_binary.len().div_ceil(8)];
        let bytes: &mut [u8] = zerocopy::IntoBytes::as_mut_bytes(aligned_buf.as_mut_slice());
        bytes[..input_binary.len()].copy_from_slice(input_binary);
        &bytes[..input_binary.len()]
    };

    let file = object::File::parse(input_binary).map_err(|e| Error::ParseError(e.to_string()))?;

    let arch = match file {
        object::File::Elf64(_) => Arch::X86_64,
        object::File::Elf32(_) => Arch::X86_32,
        _ => return Err(Error::UnsupportedObjectFile),
    };

    // Get symbols
    let dl_sysinfo_int80 = if arch == Arch::X86_32 {
        get_symbols(&file)
    } else {
        None
    };

    let text_sections = text_sections(&file)?;

    // Check if the binary is already hooked by looking for TRAMPOLINE_MAGIC at end of file
    if is_already_hooked(input_binary, arch) {
        return Err(Error::AlreadyHooked);
    }

    // Get control transfer targets
    let control_transfer_targets =
        get_control_transfer_targets(arch, input_binary, &text_sections)?;

    let trampoline_base_addr = find_addr_for_trampoline_code(&file);

    // Build the trampoline code (without header - header goes at the end)
    // The code starts with the syscall entry point placeholder
    let mut trampoline_data = vec![];
    let trampoline = trampoline.unwrap_or(0);
    if arch == Arch::X86_64 {
        trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
    } else {
        let trampoline = u32::try_from(trampoline).map_err(|_| Error::TrampolineAddressTooLarge)?;
        trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
    }

    // Make a mutable copy of the input binary for in-place patching
    let mut out = input_binary.to_vec();

    let mut syscall_insns_found = false;
    for s in &text_sections {
        let section_data = section_slice_mut(&mut out, s)?;
        match hook_syscalls_in_section(
            arch,
            &control_transfer_targets,
            s.vaddr,
            section_data,
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

    // Append: [padding to page boundary][trampoline code][header]
    let remain = out.len() % 0x1000;
    out.extend_from_slice(&vec![0; if remain == 0 { 0 } else { 0x1000 - remain }]);

    // Calculate file offset where trampoline code starts
    let trampoline_file_offset = out.len() as u64;
    let trampoline_size = trampoline_data.len();

    // Append trampoline code
    out.extend_from_slice(&trampoline_data);

    // Build the header (goes at the end of the file)
    // The entry point placeholder is at offset 0 of the trampoline code, not in the header.
    if arch == Arch::X86_64 {
        let header = TrampolineHeader64 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: trampoline_file_offset,
            vaddr: trampoline_base_addr,
            trampoline_size: trampoline_size as u64,
        };
        out.extend_from_slice(header.as_bytes());
    } else {
        let file_offset_32 =
            u32::try_from(trampoline_file_offset).map_err(|_| Error::TrampolineAddressTooLarge)?;
        let trampoline_base_addr_32 =
            u32::try_from(trampoline_base_addr).map_err(|_| Error::TrampolineAddressTooLarge)?;
        #[allow(clippy::cast_possible_truncation)]
        let header = TrampolineHeader32 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: file_offset_32,
            vaddr: trampoline_base_addr_32,
            trampoline_size: trampoline_size as u32,
        };
        out.extend_from_slice(header.as_bytes());
    }
    Ok(out)
}

/// (private) Get metadata for executable sections
fn text_sections(file: &object::File<'_>) -> Result<Vec<TextSectionInfo>> {
    let text_sections: Vec<_> = file
        .sections()
        .filter_map(|s| {
            let object::SectionFlags::Elf { sh_flags } = s.flags() else {
                return None;
            };
            if s.kind() != object::SectionKind::Text {
                return None;
            }
            if sh_flags & u64::from(object::elf::SHF_ALLOC) == 0 {
                return None;
            }
            if sh_flags & u64::from(object::elf::SHF_EXECINSTR) == 0 {
                return None;
            }
            let (file_offset, size) = s.file_range()?;
            Some(TextSectionInfo {
                vaddr: s.address(),
                file_offset,
                size,
            })
        })
        .collect();
    if text_sections.is_empty() {
        return Err(Error::NoTextSectionFound);
    }
    Ok(text_sections)
}

/// Check if the binary is already hooked by looking for TRAMPOLINE_MAGIC at the end of the file.
fn is_already_hooked(input_binary: &[u8], arch: Arch) -> bool {
    let header_size = match arch {
        Arch::X86_64 => size_of::<TrampolineHeader64>(),
        Arch::X86_32 => size_of::<TrampolineHeader32>(),
    };

    if input_binary.len() < header_size {
        return false;
    }

    let header_start = input_binary.len() - header_size;
    let header = &input_binary[header_start..];

    if &header[..TRAMPOLINE_MAGIC.len()] != TRAMPOLINE_MAGIC {
        return false;
    }

    let (file_offset, vaddr, trampoline_size) = match arch {
        Arch::X86_64 => {
            let header = TrampolineHeader64::read_from_bytes(header).unwrap();
            (header.file_offset, header.vaddr, header.trampoline_size)
        }
        Arch::X86_32 => {
            let header = TrampolineHeader32::read_from_bytes(header).unwrap();
            (
                u64::from(header.file_offset),
                u64::from(header.vaddr),
                u64::from(header.trampoline_size),
            )
        }
    };

    if trampoline_size == 0 {
        return false;
    }
    if file_offset % 0x1000 != 0 {
        return false;
    }
    if vaddr % 0x1000 != 0 {
        return false;
    }
    if file_offset + trampoline_size != header_start as u64 {
        return false;
    }

    true
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

            // Add jmp [rip + offset_to_entry_point]
            // Entry point is at offset 0 of trampoline_data
            trampoline_data.extend_from_slice(&[0xFF, 0x25]);
            // disp32 points to offset 0 (entry point) from current RIP
            // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
            // We want: RIP + disp32 = trampoline_base_addr + 0
            // So: disp32 = -(trampoline_data.len() + 4)
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() + 4);
            trampoline_data.extend_from_slice(&disp32.to_le_bytes());
        } else {
            // For 32-bit, use a different approach to simulate indirect call
            // Entry point is at offset 0 of trampoline_data
            trampoline_data.push(0x50); // PUSH EAX
            trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
            trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
            trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
            // The offset should point to the entry at offset 0
            // After PUSH(1) + CALL(5) + POP(1) + opcode(2) = 9 bytes
            // EAX = base + (len_before_PUSH + 6) = base + (current_len - 9 + 6) = base + (current_len - 3)
            // We want: EAX + offset = base + 0
            // So: offset = -(current_len - 3)
            let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 3);
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

fn find_addr_for_trampoline_code(file: &object::File<'_>) -> u64 {
    // Find the highest virtual address among all loadable segments
    let max_virtual_addr = file
        .segments()
        .map(|seg| seg.address() + seg.size())
        .max()
        .unwrap();

    // Round up to the nearest page (assume 0x1000 page size)
    max_virtual_addr.next_multiple_of(0x1000)
}

fn get_symbols(file: &object::File<'_>) -> Option<u64> {
    file.symbols()
        .filter(|sym| sym.kind() == object::SymbolKind::Text)
        .find_map(|sym| {
            sym.name()
                .ok()
                .filter(|name| *name == "_dl_sysinfo_int80")
                .map(|_| sym.address())
        })
}

fn get_control_transfer_targets(
    arch: Arch,
    input_binary: &[u8],
    text_sections: &[TextSectionInfo],
) -> Result<HashSet<u64>> {
    let mut control_transfer_targets = HashSet::new();
    for s in text_sections {
        let section_data = section_slice(input_binary, s)?;
        // Disassemble the section
        let mut decoder = iced_x86::Decoder::new(
            match arch {
                Arch::X86_32 => 32,
                Arch::X86_64 => 64,
            },
            section_data,
            iced_x86::DecoderOptions::NONE,
        );
        decoder.set_ip(s.vaddr);
        control_transfer_targets.extend(decoder.into_iter().filter_map(|inst| {
            let target = inst.near_branch_target();
            (target != 0).then_some(target)
        }));
    }

    Ok(control_transfer_targets)
}

/// Returns the section data slice from `buf` corresponding to `section`, or an error if out of bounds.
fn section_slice<'a>(buf: &'a [u8], section: &TextSectionInfo) -> Result<&'a [u8]> {
    let offset = usize::try_from(section.file_offset)
        .map_err(|_| Error::ParseError("section file offset too large".into()))?;
    let size = usize::try_from(section.size)
        .map_err(|_| Error::ParseError("section size too large".into()))?;
    let end = offset
        .checked_add(size)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| Error::ParseError("section extends beyond file".into()))?;
    Ok(&buf[offset..end])
}

/// Returns a mutable section data slice from `buf` corresponding to `section`, or an error if out of bounds.
fn section_slice_mut<'a>(buf: &'a mut [u8], section: &TextSectionInfo) -> Result<&'a mut [u8]> {
    let offset = usize::try_from(section.file_offset)
        .map_err(|_| Error::ParseError("section file offset too large".into()))?;
    let size = usize::try_from(section.size)
        .map_err(|_| Error::ParseError("section size too large".into()))?;
    let end = offset
        .checked_add(size)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| Error::ParseError("section extends beyond file".into()))?;
    Ok(&mut buf[offset..end])
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
        // Add jmp [rip + offset_to_entry_point]
        // Entry point is at offset 0 of trampoline_data
        trampoline_data.extend_from_slice(&[0xFF, 0x25]);
        // disp32 points to offset 0 (entry point) from current RIP
        // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
        // We want: RIP + disp32 = trampoline_base_addr + 0
        // So: disp32 = -(trampoline_data.len() + 4)
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() + 4);
        trampoline_data.extend_from_slice(&disp32.to_le_bytes());
    } else {
        // For 32-bit, use a different approach to simulate indirect call
        // Entry point is at offset 0 of trampoline_data
        trampoline_data.push(0x50); // PUSH EAX
        trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
        trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
        trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
        // The offset should point to the entry at offset 0
        // After PUSH(1) + CALL(5) + POP(1) + opcode(2) = 9 bytes
        // EAX = base + (len_before_PUSH + 6) = base + (current_len - 9 + 6) = base + (current_len - 3)
        // We want: EAX + offset = base + 0
        // So: offset = -(current_len - 3)
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 3);
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
    // The offset should point to the entry at offset 0
    // After PUSH(1) + CALL(5) + POP(1) + opcode(2) = 9 bytes
    // EAX = base + (len_before_PUSH + 6) = base + (current_len - 9 + 6) = base + (current_len - 3)
    // We want: EAX + offset = base + 0
    // So: offset = -(current_len - 3)
    let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() - 3);
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
