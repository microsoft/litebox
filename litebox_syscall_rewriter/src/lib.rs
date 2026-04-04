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

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use object::read::elf::{ElfFile, ProgramHeader as _};
use object::read::{Object as _, ObjectSection as _, ObjectSymbol as _};
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
    #[error("unsupported Bun-packaged executable")]
    UnsupportedBunExecutable,
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

type Result<T> = core::result::Result<T, Error>;

const BUN_FOOTER_MARKER: &[u8] = b"\n---- Bun! ----\n";

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
/// If rewriting emits trampoline stubs, the returned executable has trampoline code appended at a
/// page-aligned offset after the ELF file. The file layout is:
/// `[original ELF][padding to page boundary][trampoline code][header]`
///
/// The header at the end contains:
/// - [`TRAMPOLINE_MAGIC`] (8 bytes)
/// - trampoline file offset (8 bytes for 64-bit, 4 bytes for 32-bit)
/// - trampoline virtual address (8 bytes for 64-bit, 4 bytes for 32-bit)
/// - trampoline size (8 bytes for 64-bit, 4 bytes for 32-bit)
///
/// This layout allows loaders to read just the last 32/20 bytes to get the metadata. Even when
/// no syscall instructions are patched, the rewriter still appends the header and the initial
/// syscall-entry placeholder so the loader/audit path can tell the binary was processed.
///
/// `skipped_addrs` receives the virtual addresses of any `syscall`
/// instructions that could not be patched (replaced with `UD2` so they
/// trap instead of escaping to the host kernel).
pub fn hook_syscalls_in_elf(
    input_binary: &[u8],
    trampoline: Option<u64>,
    skipped_addrs: &mut Vec<u64>,
) -> Result<Vec<u8>> {
    if has_bun_footer_marker(input_binary) {
        return Err(Error::UnsupportedBunExecutable);
    }

    // Relocatable object files (.o) must not be patched: they are linker
    // input, not executable code. Rewriting instructions or appending
    // trampoline data would corrupt the object file for the linker.
    // Check the ELF e_type field (bytes 16..18) before doing any work.
    if input_binary.len() >= 18 {
        let e_type = u16::from_le_bytes([input_binary[16], input_binary[17]]);
        if e_type == 1 {
            // ET_REL — relocatable object file
            return Err(Error::UnsupportedObjectFile);
        }
    }

    // Make a single mutable, 8-byte-aligned copy of the input binary. This serves as both the
    // parse buffer (object::File::parse requires 8-byte alignment) and the output buffer for
    // in-place patching. We use a Vec<u64> to guarantee alignment, then view it as bytes.
    let mut backing = vec![0u64; input_binary.len().div_ceil(8)];
    let buf: &mut [u8] = zerocopy::IntoBytes::as_mut_bytes(backing.as_mut_slice());
    buf[..input_binary.len()].copy_from_slice(input_binary);
    let buf = &mut buf[..input_binary.len()];

    // Some ELF files (e.g. Node.js SEA binaries) have a program header table at an offset that
    // is not 8-byte aligned, which the `object` crate rejects. Fix this by relocating the phdr
    // table within our mutable copy so it sits at an 8-byte aligned offset.
    fixup_phdr_alignment(buf);

    // Parse the ELF and extract all metadata we need, then drop the borrow so we can mutate buf.
    let (
        arch,
        dl_sysinfo_int80,
        text_sections,
        control_transfer_targets,
        trampoline_base_addr,
        fork_to_vfork_patch,
    ) = {
        let file = object::File::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;

        let arch = match file {
            object::File::Elf64(_) => Arch::X86_64,
            object::File::Elf32(_) => Arch::X86_32,
            _ => return Err(Error::UnsupportedObjectFile),
        };

        let dl_sysinfo_int80 = if arch == Arch::X86_32 {
            get_symbols(&file)
        } else {
            None
        };

        let text_sections = text_sections(&file)?;

        if is_already_hooked(&*buf, arch) {
            return Err(Error::AlreadyHooked);
        }

        let control_transfer_targets = get_control_transfer_targets(arch, &*buf, &text_sections)?;

        let trampoline_base_addr = find_addr_for_trampoline_code(&file)?;

        let fork_to_vfork_patch = find_fork_vfork_patch(&file, &text_sections);

        (
            arch,
            dl_sysinfo_int80,
            text_sections,
            control_transfer_targets,
            trampoline_base_addr,
            fork_to_vfork_patch,
        )
    };

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
    // Patch syscalls in-place in buf
    for s in &text_sections {
        let section_data = section_slice_mut(buf, s)?;
        match hook_syscalls_in_section(
            arch,
            &control_transfer_targets,
            s.vaddr,
            section_data,
            trampoline_base_addr,
            trampoline_base_addr, // entry point is at offset 0 of trampoline
            dl_sysinfo_int80,
            &mut trampoline_data,
            skipped_addrs,
        ) {
            Ok(()) | Err(Error::NoSyscallInstructionsFound) => {}
            Err(e) => return Err(e),
        }
    }

    // Patch fork → vfork: overwrite the first bytes of __libc_fork with a
    // JMP to __libc_vfork. This prevents glibc's fork wrapper from running
    // post-fork handlers that corrupt shared state under vfork semantics.
    if let Some((fork_file_offset, fork_patch_end, rel32)) = fork_to_vfork_patch {
        #[allow(clippy::cast_possible_truncation)]
        let off = fork_file_offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let patch_end = fork_patch_end as usize;
        if off + 5 <= buf.len() && patch_end <= buf.len() && off + 5 <= patch_end {
            buf[off] = 0xE9; // JMP rel32
            buf[off + 1..off + 5].copy_from_slice(&rel32.to_le_bytes());
        } else {
            return Err(Error::ParseError(format!(
                "fork→vfork patch range {off:#x}..{patch_end:#x} is invalid for buffer length {}",
                buf.len(),
            )));
        }
    }

    // Build output: [patched ELF][padding to page boundary][trampoline code][header]
    let mut out = buf.to_vec();
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
///
/// `trampoline_base_addr` is the virtual address corresponding to `trampoline_data[0]`.
/// `syscall_entry_addr` is the address of the 8-byte entry-point value that each trampoline
/// stub jumps to (via `JMP [RIP+disp32]` on x86-64 or `CALL [EAX+disp32]` on x86-32).
#[allow(clippy::too_many_arguments)]
fn hook_syscalls_in_section(
    arch: Arch,
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    dl_sysinfo_int80: Option<u64>,
    trampoline_data: &mut Vec<u8>,
    skipped_addrs: &mut Vec<u64>,
) -> Result<()> {
    let instructions = decode_section_instructions(arch, section_data, section_base_addr)?;
    let mut found_any = false;
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

        found_any = true;
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
            match hook_syscall_and_after(
                arch,
                control_transfer_targets,
                section_base_addr,
                section_data,
                trampoline_base_addr,
                syscall_entry_addr,
                trampoline_data,
                &instructions,
                i,
            ) {
                Ok(()) => {}
                Err(Error::InsufficientBytesBeforeOrAfter(_)) => {
                    // Replace the unpatchable syscall with UD2 so it traps
                    // instead of escaping to the host kernel.
                    replace_with_ud2(section_data, section_base_addr, inst);
                    skipped_addrs.push(inst.ip());
                }
                Err(e) => return Err(e),
            }
            continue;
        }

        let replace_start = replace_start.unwrap();
        let replace_len = usize::try_from(replace_end - replace_start).unwrap();

        let target_addr = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64,
            "syscall trampoline target",
        )?;

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
            let jmp_back_base = checked_add_u64(
                trampoline_base_addr,
                trampoline_data.len() as u64,
                "x86_64 trampoline jump-back base",
            )?;
            let jmp_back_base =
                checked_add_u64(jmp_back_base, 7, "x86_64 trampoline jump-back base")?;
            trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D]); // LEA RCX, [RIP + disp32]
            trampoline_data.extend_from_slice(&rel32_bytes(
                return_addr,
                jmp_back_base,
                "x86_64 trampoline jump-back",
            )?);

            // Add jmp [rip + offset_to_entry_point]
            trampoline_data.extend_from_slice(&[0xFF, 0x25]);
            // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
            // We want: RIP + disp32 = syscall_entry_addr
            let entry_base = checked_add_u64(
                trampoline_base_addr,
                trampoline_data.len() as u64,
                "x86_64 trampoline entry base",
            )?;
            let entry_base = checked_add_u64(entry_base, 4, "x86_64 trampoline entry base")?;
            trampoline_data.extend_from_slice(&rel32_bytes(
                syscall_entry_addr,
                entry_base,
                "x86_64 trampoline entry",
            )?);
        } else {
            // For 32-bit, use a different approach to simulate indirect call
            trampoline_data.push(0x50); // PUSH EAX
            trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
            trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
            trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
            // EAX = trampoline_base_addr + (trampoline_data.len() - 3)
            // We want: EAX + offset = syscall_entry_addr
            let call_base = checked_add_u64(
                trampoline_base_addr,
                trampoline_data.len() as u64,
                "x86 trampoline entry base",
            )?;
            let call_base = checked_sub_u64(call_base, 3, "x86 trampoline entry base")?;
            trampoline_data.extend_from_slice(&rel32_bytes(
                syscall_entry_addr,
                call_base,
                "x86 trampoline entry",
            )?);
            // Note we skip `POP EAX` here as it is done by the callback `syscall_callback`
            // from litebox_shim_linux/src/lib.rs, which helps reduce the size of the trampoline.

            // Add jmp back to original after syscall
            let jmp_back_base = checked_add_u64(
                trampoline_base_addr,
                trampoline_data.len() as u64,
                "x86 trampoline jump-back base",
            )?;
            let jmp_back_base = checked_add_u64(jmp_back_base, 5, "x86 trampoline jump-back base")?;
            trampoline_data.push(0xE9);
            trampoline_data.extend_from_slice(&rel32_bytes(
                return_addr,
                jmp_back_base,
                "x86 trampoline jump-back",
            )?);
        }

        // Replace original instructions with jump to trampoline
        let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
        section_data[replace_offset] = 0xE9; // JMP rel32
        let patch_base = checked_add_u64(replace_start, 5, "syscall patch jump base")?;
        section_data[replace_offset + 1..replace_offset + 5].copy_from_slice(&rel32_bytes(
            target_addr,
            patch_base,
            "syscall patch jump",
        )?);

        // Fill remaining bytes with NOP
        for idx in 5..replace_len {
            section_data[replace_offset + idx] = 0x90;
        }
    }

    if found_any {
        Ok(())
    } else {
        Err(Error::NoSyscallInstructionsFound)
    }
}

/// If the ELF64 program header table offset (`e_phoff`) is not 8-byte aligned, shift the table
/// forward by the necessary padding so the `object` crate can parse it. This is needed for
/// binaries like Node.js SEA executables where post-link tools append data and relocate the
/// program headers to a non-aligned offset.
///
/// The function modifies the buffer in-place: it moves the phdr table contents and updates
/// `e_phoff` in the ELF header. Only ELF64 files are handled (ELF32 requires 4-byte alignment
/// which is always satisfied when `e_phoff` is within a valid file).
fn fixup_phdr_alignment(buf: &mut [u8]) {
    // Minimum ELF header size for ELF64
    if buf.len() < 64 {
        return;
    }

    // Check ELF magic and class (must be ELF64)
    if &buf[0..4] != b"\x7fELF" || buf[4] != 2 {
        return;
    }

    let e_phoff = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let e_phentsize = u64::from(u16::from_le_bytes(buf[54..56].try_into().unwrap()));
    let e_phnum = u64::from(u16::from_le_bytes(buf[56..58].try_into().unwrap()));

    if e_phoff == 0 || e_phnum == 0 || e_phentsize == 0 {
        return;
    }

    let misalignment = e_phoff % 8;
    if misalignment == 0 {
        return; // already aligned
    }

    let Some(phdr_size) = e_phentsize.checked_mul(e_phnum) else {
        return;
    };
    let Ok(old_start) = usize::try_from(e_phoff) else {
        return;
    };
    let Ok(phdr_size) = usize::try_from(phdr_size) else {
        return;
    };
    let Some(old_end) = old_start.checked_add(phdr_size) else {
        return;
    };

    // Shift forward to align: new offset is the next 8-byte boundary.
    let Ok(padding) = usize::try_from(8 - misalignment) else {
        return;
    };
    let Some(new_start) = old_start.checked_add(padding) else {
        return;
    };
    let Some(new_end) = new_start.checked_add(phdr_size) else {
        return;
    };

    if old_end > buf.len() || new_end > buf.len() {
        return; // corrupt phdr table or not enough room
    }

    // Only relocate when the overwritten bytes are padding. Otherwise this would corrupt the file
    // by destroying whatever payload follows the existing program header table.
    if !buf[old_end..new_end].iter().all(|&byte| byte == 0) {
        return;
    }

    // Move the phdr table forward (use copy_within since src and dst overlap).
    buf.copy_within(old_start..old_end, new_start);

    // Update e_phoff in the ELF header.
    let new_phoff = (e_phoff + padding as u64).to_le_bytes();
    buf[32..40].copy_from_slice(&new_phoff);

    // Also update the PHDR segment's p_offset if present, so it matches.
    // PT_PHDR = 6, each Elf64_Phdr is e_phentsize bytes, p_type at offset 0, p_offset at offset 8.
    let Ok(e_phentsize_usize) = usize::try_from(e_phentsize) else {
        return;
    };
    let Ok(e_phnum_usize) = usize::try_from(e_phnum) else {
        return;
    };
    for i in 0..e_phnum_usize {
        let Some(entry_off) = new_start.checked_add(i.saturating_mul(e_phentsize_usize)) else {
            break;
        };
        if entry_off + 16 > buf.len() {
            break;
        }
        let p_type = u32::from_le_bytes(buf[entry_off..entry_off + 4].try_into().unwrap());
        if p_type == 6 {
            // PT_PHDR — update p_offset to match new location
            let p_offset_off = entry_off + 8;
            let old_p_offset =
                u64::from_le_bytes(buf[p_offset_off..p_offset_off + 8].try_into().unwrap());
            if old_p_offset == e_phoff {
                let new_p_offset = (old_p_offset + padding as u64).to_le_bytes();
                buf[p_offset_off..p_offset_off + 8].copy_from_slice(&new_p_offset);
            }
            // The PHDR segment size should match the phdr table; no change needed.
        }
    }
}

/// Find fork and vfork symbols in the ELF and compute the patch needed to
/// redirect fork -> vfork. Returns `Some((fork_file_offset, jmp_rel32))` if
/// both symbols are found, or `None` if this binary doesn't export fork.
fn find_fork_vfork_patch(
    file: &object::File<'_>,
    text_sections: &[TextSectionInfo],
) -> Option<(u64, u64, i32)> {
    use object::ObjectSymbol as _;

    let mut fork_vaddr = None;
    let mut vfork_vaddr = None;

    // Restrict this rewrite to libc-specific symbols. Plain `fork`/`vfork` names may belong to
    // arbitrary DSOs or user code, and retargeting them would silently change unrelated behavior.
    for sym in file.dynamic_symbols() {
        if sym.kind() != object::SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        match name {
            "__libc_fork" if fork_vaddr.is_none() => {
                fork_vaddr = Some(sym.address());
            }
            "__libc_vfork" | "__vfork" if vfork_vaddr.is_none() => {
                vfork_vaddr = Some(sym.address());
            }
            _ => {}
        }
    }

    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        match name {
            "__libc_fork" if fork_vaddr.is_none() => {
                fork_vaddr = Some(sym.address());
            }
            "__libc_vfork" | "__vfork" if vfork_vaddr.is_none() => {
                vfork_vaddr = Some(sym.address());
            }
            _ => {}
        }
    }

    let fork_vaddr = fork_vaddr?;
    let vfork_vaddr = vfork_vaddr?;
    if fork_vaddr == 0 || vfork_vaddr == 0 {
        return None;
    }

    // Convert fork's vaddr to a file offset using the text sections.
    let (fork_file_offset, fork_patch_end) = text_sections.iter().find_map(|s| {
        let section_end = s.vaddr + s.size;
        if fork_vaddr >= s.vaddr
            && fork_vaddr < section_end
            && fork_vaddr
                .checked_add(5)
                .is_some_and(|end| end <= section_end)
        {
            let file_offset = s.file_offset + (fork_vaddr - s.vaddr);
            let file_end = s.file_offset + s.size;
            Some((file_offset, file_end))
        } else {
            None
        }
    })?;

    // Compute the relative offset for a JMP rel32 instruction.
    // JMP rel32 encodes: target = rip_after_jmp + rel32
    // rip_after_jmp = fork_vaddr + 5 (size of JMP rel32 instruction)
    let rel32 = i64::try_from(vfork_vaddr)
        .ok()?
        .checked_sub(i64::try_from(fork_vaddr).ok()? + 5)?;
    let rel32 = i32::try_from(rel32).ok()?;

    Some((fork_file_offset, fork_patch_end, rel32))
}

/// Check if the input binary has the Bun footer marker at the end.
fn has_bun_footer_marker(input_binary: &[u8]) -> bool {
    input_binary.len() >= BUN_FOOTER_MARKER.len()
        && input_binary[input_binary.len() - BUN_FOOTER_MARKER.len()..] == *BUN_FOOTER_MARKER
}

/// Replace an unpatchable syscall instruction with `UD2` (`0F 0B`) so that
/// reaching it triggers SIGILL instead of silently escaping to the host kernel.
///
/// `syscall` (0F 05) and `int 0x80` (CD 80) are both 2 bytes — same size as
/// `ud2`. For `call DWORD PTR gs:0x10` (7 bytes), the remaining 5 bytes are
/// filled with NOPs.
fn replace_with_ud2(section_data: &mut [u8], section_base_addr: u64, inst: &iced_x86::Instruction) {
    let offset = usize::try_from(inst.ip() - section_base_addr).unwrap();
    let len = inst.len();
    // UD2 = 0F 0B
    section_data[offset] = 0x0F;
    section_data[offset + 1] = 0x0B;
    // Fill any remaining bytes (e.g. 7-byte `call gs:0x10`) with NOPs.
    for b in &mut section_data[offset + 2..offset + len] {
        *b = 0x90;
    }
}

fn checked_add_u64(base: u64, addend: u64, context: &'static str) -> Result<u64> {
    base.checked_add(addend)
        .ok_or_else(|| Error::ParseError(format!("{context} address overflow")))
}

fn checked_sub_u64(base: u64, subtrahend: u64, context: &'static str) -> Result<u64> {
    base.checked_sub(subtrahend)
        .ok_or_else(|| Error::ParseError(format!("{context} address underflow")))
}

fn rel32_bytes(target: u64, base: u64, context: &'static str) -> Result<[u8; 4]> {
    let disp = i128::from(target) - i128::from(base);
    let disp = i32::try_from(disp).map_err(|_| {
        Error::ParseError(format!(
            "{context} displacement out of range: target {target:#x}, base {base:#x}"
        ))
    })?;
    Ok(disp.to_le_bytes())
}

/// Patch a single mapped code segment in-place, returning trampoline stubs.
///
/// This is the runtime counterpart to [`hook_syscalls_in_elf`]. Instead of
/// processing a whole ELF file, it operates on a single already-mapped code
/// region — the caller is responsible for making the region writable before
/// calling and restoring permissions afterwards.
///
/// # Arguments
///
/// * `code` — mutable slice of the mapped code segment.
/// * `code_vaddr` — virtual address of `code[0]` in guest memory.
/// * `trampoline_write_vaddr` — virtual address where the returned stub bytes
///   will be placed by the caller.
/// * `syscall_entry_addr` — address of the 8-byte entry-point value that
///   each stub's indirect jump targets.
///
/// # Returns
///
/// The trampoline stub bytes. The caller must copy them to
/// `trampoline_write_vaddr`. Returns an empty `Vec` if no syscall
/// instructions are found in `code`.
///
/// `skipped_addrs` receives the virtual addresses of any `syscall`
/// instructions that could not be patched (replaced with `UD2` so they
/// trap instead of escaping to the host kernel).
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
    skipped_addrs: &mut Vec<u64>,
) -> Result<Vec<u8>> {
    let arch = Arch::X86_64; // runtime patching is x86-64 only

    // Build control-transfer targets for this segment.
    let instructions = decode_section_instructions(arch, code, code_vaddr)?;
    let mut control_transfer_targets = BTreeSet::new();
    for inst in &instructions {
        let target = inst.near_branch_target();
        if target != 0 {
            control_transfer_targets.insert(target);
        }
    }

    let mut trampoline_data = Vec::new();
    match hook_syscalls_in_section(
        arch,
        &control_transfer_targets,
        code_vaddr,
        code,
        trampoline_write_vaddr,
        syscall_entry_addr,
        None, // dl_sysinfo_int80 — not applicable on x86-64
        &mut trampoline_data,
        skipped_addrs,
    ) {
        Ok(()) => Ok(trampoline_data),
        Err(Error::NoSyscallInstructionsFound) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn find_addr_for_trampoline_code(file: &object::File<'_>) -> Result<u64> {
    // Find the highest virtual address among all PT_LOAD segments
    let max_virtual_addr = match file {
        object::File::Elf64(elf) => max_load_segment_end(elf),
        object::File::Elf32(elf) => max_load_segment_end(elf),
        _ => unreachable!(),
    }
    .ok_or_else(|| Error::ParseError("no PT_LOAD segments found".into()))?;

    // Round up to the nearest page (assume 0x1000 page size)
    checked_add_u64(max_virtual_addr, 0xFFF, "trampoline base").map(|addr| addr & !0xFFF)
}

/// Returns the highest `p_vaddr + p_memsz` among all `PT_LOAD` segments.
fn max_load_segment_end<Elf: object::read::elf::FileHeader>(elf: &ElfFile<'_, Elf>) -> Option<u64>
where
    Elf::Word: Into<u64>,
{
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .filter(|ph| ph.p_type(endian) == object::elf::PT_LOAD)
        .filter_map(|ph| {
            ph.p_vaddr(endian)
                .into()
                .checked_add(ph.p_memsz(endian).into())
        })
        .max()
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
) -> Result<BTreeSet<u64>> {
    let mut control_transfer_targets = BTreeSet::new();
    for s in text_sections {
        let section_data = section_slice(input_binary, s)?;
        let instructions = decode_section_instructions(arch, section_data, s.vaddr)?;
        control_transfer_targets.extend(instructions.into_iter().filter_map(|inst| {
            let target = inst.near_branch_target();
            (target != 0).then_some(target)
        }));
    }

    Ok(control_transfer_targets)
}

const MAX_X86_INSTRUCTION_LEN: usize = 15;
const CHUNK_OVERLAP_LEN: usize = MAX_X86_INSTRUCTION_LEN - 1;
const TARGET_DECODE_CHUNK_LEN: usize = 8 * 1024 * 1024;

fn bytes_until_next_4g_boundary(ptr: *const u8) -> usize {
    let low = (ptr as u64) & 0xFFFF_FFFF;
    let dist = (1u64 << 32) - low;
    usize::try_from(dist).unwrap_or(usize::MAX)
}

// NOTE: We need to do this 4GiB boundary checking due to an iced-x86 bug which
// has been fixed (see https://github.com/icedland/iced/pull/697) but not
// released onto crates.io.  We handle it by making sure that we are only ever
// sending iced-x86 inputs that are fully within the 4GiB scope.
fn decode_section_instructions(
    arch: Arch,
    section_data: &[u8],
    section_base_addr: u64,
) -> Result<Vec<iced_x86::Instruction>> {
    let bitness = match arch {
        Arch::X86_32 => 32,
        Arch::X86_64 => 64,
    };

    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < section_data.len() {
        let remaining = &section_data[offset..];
        let boundary_cap = remaining
            .len()
            .min(bytes_until_next_4g_boundary(remaining.as_ptr()));
        assert!(boundary_cap > 0);

        let chunk_advance_len = boundary_cap.min(TARGET_DECODE_CHUNK_LEN);
        let decode_window_len = remaining.len().min(chunk_advance_len + CHUNK_OVERLAP_LEN);
        let chunk_start_ip = section_base_addr + offset as u64;
        let chunk_end_ip = chunk_start_ip + chunk_advance_len as u64;

        let mut decoder = iced_x86::Decoder::new(
            bitness,
            &remaining[..decode_window_len],
            iced_x86::DecoderOptions::NONE,
        );
        decoder.set_ip(chunk_start_ip);

        for inst in &mut decoder {
            if inst.len() == 0 {
                return Err(Error::DisassemblyFailure(format!(
                    "iced-x86 decoded zero-length instruction at {:#x}",
                    inst.ip()
                )));
            }

            if inst.ip() >= chunk_end_ip {
                break;
            }

            instructions.push(inst);
        }

        offset = offset.checked_add(chunk_advance_len).unwrap();
    }

    Ok(instructions)
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
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
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
            syscall_entry_addr,
            trampoline_data,
            instructions,
            inst_index,
        );
    }

    let replace_end = replace_end.unwrap();

    let target_addr = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "syscall trampoline target",
    )?;

    if arch == Arch::X86_64 {
        // Put jump back location into rcx, via lea rcx, [next instruction]
        trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D]); // LEA RCX, [RIP + disp32]
        trampoline_data.extend_from_slice(&6u32.to_le_bytes());
        // Add jmp [rip + offset_to_entry_point]
        trampoline_data.extend_from_slice(&[0xFF, 0x25]);
        // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
        // We want: RIP + disp32 = syscall_entry_addr
        let entry_base = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64,
            "x86_64 trampoline entry base",
        )?;
        let entry_base = checked_add_u64(entry_base, 4, "x86_64 trampoline entry base")?;
        trampoline_data.extend_from_slice(&rel32_bytes(
            syscall_entry_addr,
            entry_base,
            "x86_64 trampoline entry",
        )?);
    } else {
        // For 32-bit, use a different approach to simulate indirect call
        trampoline_data.push(0x50); // PUSH EAX
        trampoline_data.extend_from_slice(&[0xE8, 0x0, 0x0, 0x0, 0x0]); // CALL next instruction
        trampoline_data.push(0x58); // POP EAX (effectively store IP in EAX)
        trampoline_data.extend_from_slice(&[0xFF, 0x90]); // CALL [EAX + offset]
        // EAX = trampoline_base_addr + (trampoline_data.len() - 3)
        // We want: EAX + offset = syscall_entry_addr
        let call_base = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64,
            "x86 trampoline entry base",
        )?;
        let call_base = checked_sub_u64(call_base, 3, "x86 trampoline entry base")?;
        trampoline_data.extend_from_slice(&rel32_bytes(
            syscall_entry_addr,
            call_base,
            "x86 trampoline entry",
        )?);
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
    let jmp_back_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "trampoline jump-back base",
    )?;
    let jmp_back_base = checked_add_u64(jmp_back_base, 5, "trampoline jump-back base")?;
    trampoline_data.push(0xE9);
    trampoline_data.extend_from_slice(&rel32_bytes(
        replace_end,
        jmp_back_base,
        "trampoline jump-back",
    )?);

    // Replace original instructions with jump to trampoline
    let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
    section_data[replace_offset] = 0xE9; // JMP rel32
    let patch_base = checked_add_u64(replace_start, 5, "syscall patch jump base")?;
    section_data[replace_offset + 1..replace_offset + 5].copy_from_slice(&rel32_bytes(
        target_addr,
        patch_base,
        "syscall patch jump",
    )?);

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
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
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

    let target_addr = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "syscall trampoline target",
    )?;
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
    // EAX = trampoline_base_addr + (trampoline_data.len() - 3)
    // We want: EAX + offset = syscall_entry_addr
    let call_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "x86 trampoline entry base",
    )?;
    let call_base = checked_sub_u64(call_base, 3, "x86 trampoline entry base")?;
    trampoline_data.extend_from_slice(&rel32_bytes(
        syscall_entry_addr,
        call_base,
        "x86 trampoline entry",
    )?);
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
        let jmp_back_base = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64,
            "x86 trampoline jump-back base",
        )?;
        let jmp_back_base = checked_add_u64(jmp_back_base, 5, "x86 trampoline jump-back base")?;
        trampoline_data.push(0xE9);
        trampoline_data.extend_from_slice(&rel32_bytes(
            return_addr,
            jmp_back_base,
            "x86 trampoline jump-back",
        )?);
    }

    // Replace original instructions with jump to trampoline
    let replace_offset = usize::try_from(replace_start - section_base_addr).unwrap();
    section_data[replace_offset] = 0xE9; // JMP rel32
    let patch_base = checked_add_u64(replace_start, 5, "syscall patch jump base")?;
    section_data[replace_offset + 1..replace_offset + 5].copy_from_slice(&rel32_bytes(
        target_addr,
        patch_base,
        "syscall patch jump",
    )?);

    // Fill remaining bytes with NOP
    for idx in 5..replace_len {
        section_data[replace_offset + idx] = 0x90;
    }

    Ok(())
}
