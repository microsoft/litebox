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
use object::read::{Object as _, ObjectSection as _};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Possible errors during hooking of `syscall` instructions
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to parse: {0}")]
    ParseError(String),
    #[error("unsupported executable: {0}")]
    UnsupportedExecutable(String),
    #[error("failed to disassemble: {0}")]
    DisassemblyFailure(String),
    #[error("address overflow: {0}")]
    AddressOverflow(String),
    #[error("unpatchable syscall instruction(s): {0}")]
    UnpatchableSyscalls(String),
}

/// Internal-only error variants used for control flow within the crate.
/// These are never exposed to callers — they are caught and handled (or
/// converted to [`enum@Error`]) before reaching the public API boundary.
#[derive(Debug)]
enum InternalError {
    /// A public error that should be propagated as-is.
    Public(Error),
    /// No executable `.text` section was found.
    NoTextSectionFound,
    /// No `syscall` instructions were found.
    NoSyscallInstructionsFound,
    /// Insufficient space around a syscall instruction to patch it.
    InsufficientBytesBeforeOrAfter,
}

impl From<Error> for InternalError {
    fn from(e: Error) -> Self {
        InternalError::Public(e)
    }
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
/// - trampoline file offset (8 bytes)
/// - trampoline virtual address (8 bytes)
/// - trampoline size (8 bytes)
///
/// This layout allows loaders to read just the last 32 bytes to get the metadata. Even when
/// there is no syscall instruction in the binary, the rewriter still appends the header and the initial
/// syscall-entry placeholder so the loader/audit path can tell the binary was processed.
///
/// Returns the rewritten binary. Binaries that cannot or do not need to be
/// patched (relocatable objects, non-ELF files, already-hooked binaries,
/// binaries without executable sections or syscall instructions) are returned
/// unchanged — these are not errors.
///
/// Returns `Err` for genuinely broken inputs (corrupt ELF, unsupported
/// executables like Bun, arithmetic overflow) and for binaries that contain
/// syscall instructions that could not be patched (replaced with `icebp; hlt`
/// so they trap instead of escaping to the host kernel).
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    if input_binary.ends_with(BUN_FOOTER_MARKER) {
        return Err(Error::UnsupportedExecutable(
            "Bun-packaged executable".into(),
        ));
    }

    // Relocatable object files (.o) must not be patched: they are linker
    // input, not executable code. Rewriting instructions or appending
    // trampoline data would corrupt the object file for the linker.
    // Check the ELF e_type field (bytes 16..18) before doing any work.
    if input_binary.len() >= 18 {
        let e_type = u16::from_le_bytes([input_binary[16], input_binary[17]]);
        if e_type == object::elf::ET_REL {
            return Ok(input_binary.to_vec());
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
    let (arch, text_sections, control_transfer_targets, trampoline_base_addr) = {
        let file = object::File::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;

        let arch = match file {
            object::File::Elf64(_) => Arch::X86_64,
            _ => return Ok(input_binary.to_vec()),
        };

        let text_sections = match text_sections(&file) {
            Ok(sections) => sections,
            Err(InternalError::NoTextSectionFound) => return Ok(input_binary.to_vec()),
            Err(InternalError::Public(e)) => return Err(e),
            Err(e) => unreachable!("unexpected internal error: {e:?}"),
        };

        if is_already_hooked(&*buf, arch) {
            return Ok(input_binary.to_vec());
        }

        let control_transfer_targets = get_control_transfer_targets(arch, &*buf, &text_sections)?;

        let trampoline_base_addr = find_addr_for_trampoline_code(&file)?;

        (
            arch,
            text_sections,
            control_transfer_targets,
            trampoline_base_addr,
        )
    };

    // Build the trampoline code (without header - header goes at the end)
    // The code starts with the syscall entry point placeholder (8 bytes for x86-64)
    let mut trampoline_data = vec![];
    let trampoline = trampoline.unwrap_or(0);
    trampoline_data.extend_from_slice(&trampoline.to_le_bytes());
    // Patch syscalls in-place in buf
    let mut skipped_addrs = Vec::new();
    let mut syscall_insns_found = false;
    for s in &text_sections {
        let section_data = section_slice_mut(buf, s)?;
        match hook_syscalls_in_section(
            arch,
            &control_transfer_targets,
            s.vaddr,
            section_data,
            trampoline_base_addr,
            trampoline_base_addr, // entry point is at offset 0 of trampoline
            &mut trampoline_data,
        ) {
            Ok(addrs) => {
                skipped_addrs.extend(addrs);
                syscall_insns_found = true;
            }
            Err(InternalError::NoSyscallInstructionsFound) => {}
            Err(InternalError::Public(e)) => return Err(e),
            Err(e) => unreachable!("unexpected internal error: {e:?}"),
        }
    }

    if !syscall_insns_found {
        // No syscall instructions found. Append a header-only marker so the
        // loader can distinguish "checked by rewriter, nothing to patch" from
        // "never processed." The trampoline_size=0 sentinel tells the loader
        // to skip trampoline mapping entirely.
        // Use the original input (not `buf`) to avoid emitting the phdr
        // alignment fixup that is only needed for the `object` crate parser.
        let mut out = input_binary.to_vec();
        let header = TrampolineHeader64 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: 0,
            vaddr: 0,
            trampoline_size: 0,
        };
        out.extend_from_slice(header.as_bytes());
        return Ok(out);
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
    let header = TrampolineHeader64 {
        magic: *TRAMPOLINE_MAGIC,
        file_offset: trampoline_file_offset,
        vaddr: trampoline_base_addr,
        trampoline_size: trampoline_size as u64,
    };
    out.extend_from_slice(header.as_bytes());
    if !skipped_addrs.is_empty() {
        return Err(Error::UnpatchableSyscalls(format!(
            "{} unpatchable syscall instruction(s) at {skipped_addrs:?}",
            skipped_addrs.len(),
        )));
    }
    Ok(out)
}
/// (private) Get metadata for executable sections
fn text_sections(
    file: &object::File<'_>,
) -> core::result::Result<Vec<TextSectionInfo>, InternalError> {
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
        return Err(InternalError::NoTextSectionFound);
    }
    Ok(text_sections)
}

/// Check if the binary is already hooked by looking for TRAMPOLINE_MAGIC at the end of the file.
fn is_already_hooked(input_binary: &[u8], arch: Arch) -> bool {
    let header_size = match arch {
        Arch::X86_64 => size_of::<TrampolineHeader64>(),
    };

    if input_binary.len() < header_size {
        return false;
    }

    let header_start = input_binary.len() - header_size;
    let header = &input_binary[header_start..];

    if &header[..TRAMPOLINE_MAGIC.len()] != TRAMPOLINE_MAGIC {
        return false;
    }

    let header = TrampolineHeader64::read_from_bytes(header).unwrap();
    let (file_offset, vaddr, trampoline_size) =
        (header.file_offset, header.vaddr, header.trampoline_size);

    if trampoline_size == 0 {
        // Size=0 sentinel: the rewriter processed this binary but found no
        // syscall instructions. It is already hooked (nothing to do).
        return true;
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
    X86_64,
}

/// (private) Hook all syscalls in `section`, possibly extending `trampoline_data` to do so.
///
/// `trampoline_base_addr` is the virtual address corresponding to `trampoline_data[0]`.
/// `syscall_entry_addr` is the address of the 8-byte entry-point value that each trampoline
/// stub jumps to (via `JMP [RIP+disp32]` on x86-64).
fn hook_syscalls_in_section(
    arch: Arch,
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    trampoline_data: &mut Vec<u8>,
) -> core::result::Result<Vec<u64>, InternalError> {
    let instructions = decode_section_instructions(arch, section_data, section_base_addr)?;
    let mut found_any = false;
    let mut skipped_addrs = Vec::new();
    for (i, inst) in instructions.iter().enumerate() {
        // Forward search for `syscall`
        match arch {
            Arch::X86_64 => {
                if inst.code() != iced_x86::Code::Syscall {
                    continue;
                }
            }
        }

        found_any = true;
        let replace_end = inst.next_ip();

        let mut replace_start = None;
        let mut replace_start_idx = 0;
        // If the syscall itself is a control transfer target, we cannot extend
        // the replaced range backward (a jump landing on the syscall would hit
        // NOPs instead). Skip the backward scan and fall through to the
        // forward-only path (hook_syscall_and_after).
        if !control_transfer_targets.contains(&inst.ip()) {
            for inst_id in (0..i).rev() {
                let prev_inst = &instructions[inst_id];
                if prev_inst.flow_control() != iced_x86::FlowControl::Next {
                    break;
                }
                if replace_end - prev_inst.ip() >= 5 {
                    replace_start = Some(prev_inst.ip());
                    replace_start_idx = inst_id;
                    break;
                } else if control_transfer_targets.contains(&prev_inst.ip()) {
                    // If the previous instruction is a control transfer target, we don't want to cross it
                    break;
                }
            }
        }

        if replace_start.is_none() {
            match hook_syscall_and_after(
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
                Err(InternalError::InsufficientBytesBeforeOrAfter) => {
                    // Replace the unpatchable syscall with ICEBP;HLT so it
                    // traps instead of escaping to the host kernel.
                    replace_with_trap(section_data, section_base_addr, inst);
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

        // Encode the pre-syscall instructions for the trampoline, re-encoding
        // any RIP-relative memory operands for the new location.
        let presyscall_bytes = if replace_start < inst.ip() {
            if let Some(bytes) =
                reencode_instructions(&instructions[replace_start_idx..i], target_addr)
            {
                bytes
            } else {
                match hook_syscall_and_after(
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
                    Err(InternalError::InsufficientBytesBeforeOrAfter) => {
                        replace_with_trap(section_data, section_base_addr, inst);
                        skipped_addrs.push(inst.ip());
                    }
                    Err(e) => return Err(e),
                }
                continue;
            }
        } else {
            Vec::new()
        };
        trampoline_data.extend_from_slice(&presyscall_bytes);

        let return_addr = inst.next_ip();

        // LEA RCX, [RIP + 6] — load RCX with the address of the in-trampoline
        // `post_jmp` (the instruction immediately after the indirect JMP into
        // the callback). The SA_RESTART handler relies on the invariant that
        // pt_regs.rcx - 6 points at the indirect JMP itself, so it can rewind
        // ctx.rip and re-enter the callback.
        trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x06, 0x00, 0x00, 0x00]);

        // Add jmp [rip + offset_to_entry_point]
        trampoline_data.extend_from_slice(&[0xFF, 0x25]);
        // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
        // We want: RIP + disp32 = syscall_entry_addr
        let entry_base = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64 + 4,
            "x86_64 trampoline entry base",
        )?;
        trampoline_data.extend_from_slice(&rel32_bytes(
            syscall_entry_addr,
            entry_base,
            "x86_64 trampoline entry",
        )?);

        // post_jmp: JMP rel32 back to the guest instruction following the
        // original syscall. The callback returns via `jmp rcx` and lands here.
        let jmp_back_base = checked_add_u64(
            trampoline_base_addr,
            trampoline_data.len() as u64 + 5,
            "x86_64 trampoline jump-back base",
        )?;
        trampoline_data.push(0xE9);
        trampoline_data.extend_from_slice(&rel32_bytes(
            return_addr,
            jmp_back_base,
            "x86_64 trampoline jump-back",
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
        for idx in 5..replace_len {
            section_data[replace_offset + idx] = 0x90;
        }
    }

    if found_any {
        Ok(skipped_addrs)
    } else {
        Err(InternalError::NoSyscallInstructionsFound)
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

    // Check ELF magic, class (must be ELF64), and byte order (must be little-endian).
    if &buf[0..4] != b"\x7fELF" || buf[4] != 2 || buf[5] != 1 {
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

    if new_end > buf.len() {
        return; // not enough room
    }

    // Only relocate when the overwritten bytes are padding. Otherwise this would corrupt the file
    // by destroying whatever payload follows the existing program header table.
    if !buf[old_end..new_end].iter().all(|&byte| byte == 0) {
        return;
    }

    // Move the phdr table forward (use copy_within since src and dst overlap).
    buf.copy_within(old_start..old_end, new_start);

    // Zero the gap left behind so stale phdr bytes don't linger.
    for b in &mut buf[old_start..old_start + padding] {
        *b = 0;
    }

    // Update e_phoff in the ELF header.
    let new_phoff = (e_phoff + padding as u64).to_le_bytes();
    buf[32..40].copy_from_slice(&new_phoff);

    // Also update the PHDR segment's p_offset, p_vaddr, and p_paddr if present.
    // Shifting the phdr table forward in the file shifts it within the PT_LOAD
    // mapping by the same amount, so all three fields need the same adjustment.
    let Ok(e_phentsize_usize) = usize::try_from(e_phentsize) else {
        return;
    };
    let Ok(e_phnum_usize) = usize::try_from(e_phnum) else {
        return;
    };
    for i in 0..e_phnum_usize {
        let Some(i_times_size) = i.checked_mul(e_phentsize_usize) else {
            break;
        };
        let Some(entry_off) = new_start.checked_add(i_times_size) else {
            break;
        };
        if entry_off + 32 > buf.len() {
            break;
        }
        let p_type = u32::from_le_bytes(buf[entry_off..entry_off + 4].try_into().unwrap());
        if p_type == object::elf::PT_PHDR {
            use core::mem::offset_of;
            use object::elf::ProgramHeader64;
            use object::endian::LittleEndian;
            // PT_PHDR — shift p_offset, p_vaddr, and p_paddr by `padding`.
            for field_off in [
                offset_of!(ProgramHeader64<LittleEndian>, p_offset),
                offset_of!(ProgramHeader64<LittleEndian>, p_vaddr),
                offset_of!(ProgramHeader64<LittleEndian>, p_paddr),
            ] {
                let off = entry_off + field_off;
                let old_val = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
                let new_val = (old_val + padding as u64).to_le_bytes();
                buf[off..off + 8].copy_from_slice(&new_val);
            }
            // The PHDR segment size should match the phdr table; no change needed.
        }
    }
}

/// Replace an unpatchable syscall instruction with `ICEBP; HLT` (`F1 F4`) so
/// that reaching it traps instead of silently escaping to the host kernel.
///
/// `ICEBP` alone does not trap on Linux in userspace, but `HLT` does
/// (SIGSEGV in ring 3), and the `F1` prefix makes it easy for a signal
/// handler to identify an intentionally poisoned syscall.
///
/// `syscall` (0F 05) is 2 bytes — same size as
/// `ICEBP; HLT`.
fn replace_with_trap(
    section_data: &mut [u8],
    section_base_addr: u64,
    inst: &iced_x86::Instruction,
) {
    let offset = usize::try_from(inst.ip() - section_base_addr).unwrap();
    let len = inst.len();
    // ICEBP (F1) + HLT (F4): traps in userspace, easy to identify in a handler.
    section_data[offset] = 0xF1;
    section_data[offset + 1] = 0xF4;
    // Fill any remaining bytes (e.g. 7-byte `call gs:0x10`) with NOPs.
    for b in &mut section_data[offset + 2..offset + len] {
        *b = 0x90;
    }
}

fn checked_add_u64(base: u64, addend: u64, context: &'static str) -> Result<u64> {
    base.checked_add(addend)
        .ok_or_else(|| Error::AddressOverflow(format!("{context} address overflow")))
}

fn rel32_bytes(target: u64, base: u64, context: &'static str) -> Result<[u8; 4]> {
    let disp = i128::from(target) - i128::from(base);
    let disp = i32::try_from(disp).map_err(|_| {
        Error::AddressOverflow(format!(
            "{context} displacement out of range: target {target:#x}, base {base:#x}"
        ))
    })?;
    Ok(disp.to_le_bytes())
}

/// This is the runtime counterpart to [`hook_syscalls_in_elf`]. Instead of
/// processing a whole ELF file, it operates on a single already-mapped code
/// region — the caller is responsible for making the region writable before
/// calling and restoring permissions afterwards.
///
/// # Returns
///
/// `(trampoline_stubs, skipped_addrs)`. The caller must copy the stubs to
/// `trampoline_write_vaddr`. Returns empty vecs if no syscall instructions
/// are found in `code`.
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
) -> Result<(Vec<u8>, Vec<u64>)> {
    // Build control-transfer targets for this segment.
    let instructions = decode_section_instructions(Arch::X86_64, code, code_vaddr)?;
    let mut control_transfer_targets = BTreeSet::new();
    for inst in &instructions {
        let target = inst.near_branch_target();
        if target != 0 {
            control_transfer_targets.insert(target);
        }
    }

    let mut trampoline_data = Vec::new();
    match hook_syscalls_in_section(
        Arch::X86_64,
        &control_transfer_targets,
        code_vaddr,
        code,
        trampoline_write_vaddr,
        syscall_entry_addr,
        &mut trampoline_data,
    ) {
        Ok(skipped_addrs) => Ok((trampoline_data, skipped_addrs)),
        Err(InternalError::NoSyscallInstructionsFound) => Ok((Vec::new(), Vec::new())),
        Err(InternalError::Public(e)) => Err(e),
        Err(e) => unreachable!("unexpected internal error: {e:?}"),
    }
}

/// Replace all `syscall` instructions in `code` with trap sequences (`ICEBP; HLT`).
///
/// This is the fallback when trampoline-based patching cannot be performed
/// (e.g. trampoline allocation failed or is too far away).
///
/// Returns the number of syscall instructions that were patched.
pub fn trap_all_syscalls_in_code(code: &mut [u8], code_vaddr: u64) -> Result<usize> {
    let instructions = decode_section_instructions(Arch::X86_64, code, code_vaddr)?;
    let mut count = 0;
    for inst in &instructions {
        if inst.code() == iced_x86::Code::Syscall {
            replace_with_trap(code, code_vaddr, inst);
            count += 1;
        }
    }
    Ok(count)
}

fn find_addr_for_trampoline_code(file: &object::File<'_>) -> Result<u64> {
    // Find the highest virtual address among all PT_LOAD segments
    let max_virtual_addr = match file {
        object::File::Elf64(elf) => max_load_segment_end(elf),
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

        append_decoded_instructions(
            bitness,
            &remaining[..decode_window_len],
            chunk_start_ip,
            chunk_end_ip,
            &mut instructions,
        )?;

        offset = offset.checked_add(chunk_advance_len).unwrap();
    }

    Ok(instructions)
}

fn append_decoded_instructions(
    bitness: u32,
    window: &[u8],
    chunk_start_ip: u64,
    chunk_end_ip: u64,
    instructions: &mut Vec<iced_x86::Instruction>,
) -> Result<()> {
    if bytes_until_next_4g_boundary(window.as_ptr()) > window.len() {
        return append_decoded_non_crossing_window(
            bitness,
            window,
            chunk_start_ip,
            chunk_end_ip,
            instructions,
        );
    }

    // If the scratch allocation starts immediately before a 4GiB boundary, the
    // copied window can be shifted to start at that boundary. 2x window length
    // always leaves enough room for that worst-case shift.
    let scratch_len = window
        .len()
        .checked_mul(2)
        .ok_or_else(|| Error::DisassemblyFailure("decode window too large".into()))?;
    let mut scratch = vec![0; scratch_len];
    let scratch_boundary_dist = bytes_until_next_4g_boundary(scratch.as_ptr());
    let scratch_offset = if scratch_boundary_dist > window.len() {
        0
    } else {
        scratch_boundary_dist
    };
    let scratch_end = scratch_offset
        .checked_add(window.len())
        .filter(|&end| end <= scratch.len())
        .ok_or_else(|| Error::DisassemblyFailure("decode scratch window overflow".into()))?;
    scratch[scratch_offset..scratch_end].copy_from_slice(window);

    let scratch_window = &scratch[scratch_offset..scratch_end];
    assert!(bytes_until_next_4g_boundary(scratch_window.as_ptr()) > scratch_window.len());
    append_decoded_non_crossing_window(
        bitness,
        scratch_window,
        chunk_start_ip,
        chunk_end_ip,
        instructions,
    )
}

fn append_decoded_non_crossing_window(
    bitness: u32,
    window: &[u8],
    chunk_start_ip: u64,
    chunk_end_ip: u64,
    instructions: &mut Vec<iced_x86::Instruction>,
) -> Result<()> {
    let mut decoder = iced_x86::Decoder::new(bitness, window, iced_x86::DecoderOptions::NONE);
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

    Ok(())
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

/// Re-encode a sequence of instructions at a new base address, fixing up
/// RIP-relative memory operands and IP-relative branch targets so they still
/// reference the same absolute addresses.  Returns `Some(bytes)` on success,
/// or `None` if any instruction cannot be re-encoded at the same length (which
/// would shift subsequent offsets and break the 1:1 replacement).
fn reencode_instructions(
    instructions: &[iced_x86::Instruction],
    base_addr: u64,
) -> Option<Vec<u8>> {
    let mut reencoded = Vec::new();
    let mut encoder = iced_x86::Encoder::new(64);
    for inst in instructions {
        let tramp_ip = base_addr + reencoded.len() as u64;
        if encoder.encode(inst, tramp_ip).is_err() {
            return None;
        }
        let bytes = encoder.take_buffer();
        if bytes.len() != inst.len() {
            return None;
        }
        reencoded.extend_from_slice(&bytes);
    }
    Some(reencoded)
}

#[allow(clippy::too_many_arguments)]
fn hook_syscall_and_after(
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    trampoline_data: &mut Vec<u8>,
    instructions: &[iced_x86::Instruction],
    inst_index: usize,
) -> core::result::Result<(), InternalError> {
    let syscall_inst = &instructions[inst_index];

    let replace_start = syscall_inst.ip();
    let mut replace_end = None;
    let mut replace_end_idx = inst_index;

    for (idx, next_inst) in instructions.iter().enumerate().skip(inst_index + 1) {
        if control_transfer_targets.contains(&next_inst.ip()) {
            // If the next instruction is a control transfer target, we don't want to cross it
            break;
        }
        let next_end = next_inst.next_ip();

        if next_end - syscall_inst.ip() >= 5 {
            replace_end = Some(next_end);
            replace_end_idx = idx + 1;
            break;
        }

        if next_inst.flow_control() != iced_x86::FlowControl::Next {
            break;
        }
    }

    if replace_end.is_none() {
        return Err(InternalError::InsufficientBytesBeforeOrAfter);
    }

    let replace_end = replace_end.unwrap();

    let target_addr = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "syscall trampoline target",
    )?;

    // Compute preamble size so we can determine where post-syscall
    // instructions will land and encode them before committing anything.
    // x86_64: LEA RCX,[RIP+disp32] (7) + JMP [RIP+disp32] (6) = 13
    let preamble_len: u64 = 13;

    // Encode the post-syscall instructions for the trampoline, re-encoding
    // any RIP-relative memory operands for the new location.
    let syscall_inst_end = syscall_inst.next_ip();
    let postsyscall_bytes = if syscall_inst_end < replace_end {
        let postsyscall_target = target_addr + preamble_len;
        match reencode_instructions(
            &instructions[(inst_index + 1)..replace_end_idx],
            postsyscall_target,
        ) {
            Some(bytes) => bytes,
            None => return Err(InternalError::InsufficientBytesBeforeOrAfter),
        }
    } else {
        Vec::new()
    };

    // LEA RCX, [RIP + 6] — make RCX point at the instruction immediately
    // following the indirect JMP: the start of postsyscall_bytes (or, when
    // none, the unconditional JMP back to guest). The SA_RESTART handler
    // relies on pt_regs.rcx - 6 pointing at the indirect JMP itself.
    trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x06, 0x00, 0x00, 0x00]);
    // Add jmp [rip + offset_to_entry_point]
    trampoline_data.extend_from_slice(&[0xFF, 0x25]);
    // RIP after this instruction = trampoline_base_addr + trampoline_data.len() + 4
    // We want: RIP + disp32 = syscall_entry_addr
    let entry_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64 + 4,
        "x86_64 trampoline entry base",
    )?;
    trampoline_data.extend_from_slice(&rel32_bytes(
        syscall_entry_addr,
        entry_base,
        "x86_64 trampoline entry",
    )?);

    trampoline_data.extend_from_slice(&postsyscall_bytes);

    // Add jmp back to original after syscall
    let jmp_back_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64 + 5,
        "trampoline jump-back base",
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[ignore = "allocates over 4GiB to reproduce the iced-x86 host-pointer bug without mmap"]
    fn decodes_instruction_crossing_4g_host_boundary() {
        let mut code = vec![0u8; (1usize << 32) + CHUNK_OVERLAP_LEN + MAX_X86_INSTRUCTION_LEN];
        let base_addr = code.as_mut_ptr() as usize;
        let boundary_addr =
            (base_addr + CHUNK_OVERLAP_LEN + ((1usize << 32) - 1)) & !((1usize << 32) - 1);
        let section_offset = boundary_addr - CHUNK_OVERLAP_LEN - base_addr;
        let section_len = MAX_X86_INSTRUCTION_LEN + CHUNK_OVERLAP_LEN;
        let section = &mut code[section_offset..section_offset + section_len];
        section.fill(0x90);

        // 15-byte NOP. The final byte lands after the 4GiB boundary, reproducing
        // the iced-x86 pointer-wrap panic that the decoder workaround avoids.
        section[..MAX_X86_INSTRUCTION_LEN].copy_from_slice(&[
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ]);

        let instructions = decode_section_instructions(Arch::X86_64, section, 0x1000).unwrap();

        assert_eq!(instructions[0].len(), MAX_X86_INSTRUCTION_LEN);
    }
}
