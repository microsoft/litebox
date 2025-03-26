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
    #[error("insufficient bytes before syscall at {0:#x}")]
    InsufficientBytesBefore(u64),
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
    if object::FileKind::parse(input_binary).map_err(|e| Error::ParseError(e.to_string()))?
        != object::FileKind::Elf64
    {
        return Err(Error::UnsupportedObjectFile);
    }
    let mut builder = object::build::elf::Builder::read64(input_binary)
        .map_err(|e| Error::ParseError(e.to_string()))?;

    let text_sections = text_sections(&builder)?;
    let trampoline_section = setup_trampoline_section(&mut builder)?;

    let executable_segment = {
        let mut s: Vec<_> = builder
            .segments
            .iter()
            .filter(|seg| seg.p_flags & object::elf::PF_X != 0)
            .collect();
        if s.len() != 1 {
            unimplemented!()
        }
        s.pop().unwrap().id()
    };
    assert!(text_sections.iter().all(|s| {
        builder
            .segments
            .get(executable_segment)
            .sections
            .contains(s)
    }));
    builder
        .segments
        .get_mut(executable_segment)
        .append_section(builder.sections.get_mut(trampoline_section));
    let trampoline_base_addr = builder.sections.get(trampoline_section).sh_addr;

    let mut trampoline_data = vec![];
    trampoline_data.extend_from_slice(&trampoline.unwrap_or(0).to_le_bytes());

    let mut syscall_insns_found = false;
    for s in &text_sections {
        let s = builder.sections.get_mut(*s);
        let object::build::elf::SectionData::Data(data) = &mut s.data else {
            unimplemented!()
        };
        match hook_syscalls_in_section(
            s.sh_addr,
            data.to_mut(),
            trampoline_base_addr,
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

    builder.sections.get_mut(trampoline_section).sh_size =
        trampoline_data.len().try_into().unwrap();
    builder.sections.get_mut(trampoline_section).data =
        object::build::elf::SectionData::Data(trampoline_data.into());
    builder
        .segments
        .get_mut(executable_segment)
        .recalculate_ranges(&builder.sections);

    let mut out = vec![];
    builder
        .write(&mut out)
        .map_err(|e| Error::GenerateObjFileError(e.to_string()))?;
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
    s.sh_flags = (object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR).into();
    s.sh_addralign = 8;
    Ok(s.id())
}

/// (private) Hook all syscalls in `section`, possibly extending `trampoline_data` to do so.
fn hook_syscalls_in_section(
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    trampoline_data: &mut Vec<u8>,
) -> Result<()> {
    use capstone::prelude::*;

    // Disassemble the section
    let cs = capstone::Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()?;
    let instructions = cs.disasm_all(section_data, section_base_addr)?;

    for (i, inst) in instructions.iter().enumerate() {
        if capstone::arch::x86::X86Insn::from(inst.id().0)
            != capstone::arch::x86::X86Insn::X86_INS_SYSCALL
        {
            continue;
        }

        let replace_end = inst
            .address()
            .checked_add(inst.bytes().len().try_into().unwrap())
            .unwrap();
        let replace_start = (0..=i)
            .rev()
            .map(|idx| instructions[idx].address())
            .find(|addr| replace_end - addr >= 5)
            .ok_or_else(|| Error::InsufficientBytesBefore(inst.address()))?;
        let replace_len = usize::try_from(replace_end - replace_start).unwrap();

        let target_addr = trampoline_base_addr + trampoline_data.len() as u64;

        // Copy the original instructions to the trampoline
        trampoline_data.extend_from_slice(
            &section_data[usize::try_from(replace_start - section_base_addr).unwrap()
                ..usize::try_from(inst.address() - section_base_addr).unwrap()],
        );

        // Add call [rip + offset_to_shared_target]
        trampoline_data.extend_from_slice(&[0xFF, 0x15]);
        let disp32 = -(i32::try_from(trampoline_data.len()).unwrap() + 4);
        trampoline_data.extend_from_slice(&disp32.to_le_bytes());

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
