// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rewrite binaries for LiteBox execution.
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
//! This crate currently supports x86-64 ELFs for syscall hooking and x86-64 PEs for syscall
//! hooking plus rewriting Windows TEB accesses from GS segment overrides to FS segment overrides.
//!
//! It also supports AArch64 ELFs, for Linux guests on Linux or macOS hosts (see [`Host`]), and
//! rewrites `SVC #imm` syscalls plus both directions of guest thread-pointer access
//! (`MSR TPIDR_EL0` writes and `MRS TPIDR_EL0` reads): the host owns a per-thread anchor register
//! and the guest thread pointer is fully virtualized to a host-managed memory slot reached through
//! it. Which register anchors the host varies by host OS -- [`hook_syscalls_in_elf`] defaults to
//! [`Host::Linux`]; [`hook_syscalls_in_elf_for_host`] selects explicitly. See the `arm64` module
//! for details, including a caveat on `Host::MacOs` guests that use `x18`.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

mod arm64;

pub use arm64::Host;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use litebox_common_windows::NtSysno;
use object::pe::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use object::read::elf::{ElfFile, ProgramHeader as _};
use object::read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _, PeFile64};
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

/// The pthread thread-specific-data slot index at which the macOS runtime
/// keeps each thread's guest thread pointer, as addressed by every gate a
/// [`Host::MacOs`] rewrite emits (`[TPIDRRO_EL0 + slot * 8]`). The runtime
/// reserves exactly this slot with `pthread_key_create` at platform init; see
/// the `arm64` module's `GUEST_TPIDR_OFFSET_MACOS` docs for the verified
/// Darwin TSD layout this rests on.
pub const MACOS_GUEST_TPIDR_TSD_SLOT: u16 = arm64::MACOS_GUEST_TPIDR_TSD_SLOT;

/// Byte offset, within an emitted AArch64 trampoline, of the word holding the
/// guest thread-pointer byte offset.
///
/// A loader writes the offset its runtime actually reserved into this word
/// before making the trampoline executable; gates emitted for a host that reads
/// the offset at run time load it from here. Exported so a loader names the same
/// slot the emitter wrote rather than repeating the number.
pub const TRAMPOLINE_GUEST_TP_SLOT_OFFSET: usize = arm64::HEADER_GUEST_TP_OFFSET_MACOS;

/// Rewrite a supported binary for LiteBox.
///
/// ELF64 inputs are passed through [`hook_syscalls_in_elf`] (the
/// [`Host::Linux`] anchor). PE64 inputs have executable-section GS segment
/// overrides rewritten to FS and `syscall` instructions redirected through a
/// LiteBox trampoline footer.
///
/// Use [`rewrite_binary_for_host`] to target an AArch64 ELF input at a
/// non-Linux host.
pub fn rewrite_binary(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    rewrite_binary_for_host(input_binary, trampoline, Host::Linux)
}

/// As [`rewrite_binary`], but selects the AArch64 host anchor explicitly
/// instead of defaulting to [`Host::Linux`] -- see [`hook_syscalls_in_elf_for_host`].
/// Ignored for PE64 input, which has no per-host anchor concept.
pub fn rewrite_binary_for_host(
    input_binary: &[u8],
    trampoline: Option<u64>,
    host: Host,
) -> Result<Vec<u8>> {
    if is_pe_binary(input_binary) {
        rewrite_pe_for_litebox(input_binary, trampoline)
    } else {
        hook_syscalls_in_elf_for_host(input_binary, trampoline, host)
    }
}

/// Trampoline header for 64-bit: 8 (magic) + 8 (file_offset) + 8 (vaddr) + 8 (size) = 32 bytes
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct TrampolineHeader64 {
    magic: [u8; 8],
    file_offset: u64,
    vaddr: u64,
    trampoline_size: u64,
}

/// Metadata about an executable section, extracted from a read-only object parse.
struct TextSectionInfo {
    /// Virtual address of the section
    vaddr: u64,
    /// File offset where the section data starts
    file_offset: u64,
    /// Size of the section data in bytes
    size: u64,
}

struct SyscallPatchResult {
    found_syscall: bool,
    skipped_addrs: Vec<u64>,
}

/// Limit on how far backward from a `syscall` we look for the `mov eax, imm32`
/// that loads its sysno. A real NT stub always sets `eax` within a handful of
/// instructions of the `syscall`; the bound keeps us from rewriting some
/// unrelated `mov eax` that happens to share an immediate value with a sysno.
const NT_SYSNO_REWRITE_LOOKBACK: usize = 16;

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
/// This layout allows loaders to read just the last 32 bytes to get the metadata.
///
/// When there is nothing to patch, both architectures append only a 32-byte
/// header carrying a `trampoline_size = 0` *sentinel* (no trampoline body), so a
/// loader can distinguish "processed, nothing to patch" from "never processed";
/// no instructions are rewritten in that case.
///
/// AArch64 differs in one way: it also rewrites guest thread-pointer accesses
/// (`MSR TPIDR_EL0` writes and `MRS TPIDR_EL0` reads), so a binary containing one
/// is patched (and gets a non-empty trampoline) even when it has no syscall
/// (`SVC`) instructions at all. (See the `arm64` module docs.)
///
/// Returns the rewritten binary. Binaries that cannot or do not need to be
/// patched (relocatable objects, non-ELF files, already-hooked binaries,
/// binaries without executable sections) are returned unchanged — these are
/// not errors. See the per-architecture behavior above.
///
/// Returns `Err` for genuinely broken inputs (corrupt ELF, unsupported
/// executables like Bun, arithmetic overflow) and for binaries that contain
/// patch sites that could not be redirected. An unpatchable site is replaced
/// with a trapping instruction so it faults instead of escaping to the host
/// kernel: `icebp; hlt` on x86-64, and `BRK` on AArch64 (where a patch site is
/// an `SVC`, `MSR TPIDR_EL0`, or `MRS TPIDR_EL0` instruction).
///
/// AArch64 gates against [`Host::Linux`]'s anchor (`TPIDR_EL0`); use
/// [`hook_syscalls_in_elf_for_host`] to target a different host.
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    hook_syscalls_in_elf_for_host(input_binary, trampoline, Host::Linux)
}

/// As [`hook_syscalls_in_elf`], but selects the AArch64 host anchor explicitly
/// instead of defaulting to [`Host::Linux`]. A binary rewritten for one host
/// will not run correctly under another. Ignored for x86-64 input, which has
/// no per-host anchor concept (and no macOS host at all, by design).
pub fn hook_syscalls_in_elf_for_host(
    input_binary: &[u8],
    trampoline: Option<u64>,
    host: Host,
) -> Result<Vec<u8>> {
    if input_binary.ends_with(BUN_FOOTER_MARKER) {
        return Err(Error::UnsupportedExecutable(
            "Bun-packaged executable".into(),
        ));
    }

    // Relocatable object files (.o) must not be patched: they are linker
    // input, not executable code. Rewriting instructions or appending
    // trampoline data would corrupt the object file for the linker.
    // Check the ELF e_type field (bytes 16..18) before doing any work. The
    // encoding of multi-byte fields is selected by e_ident[EI_DATA] (byte 5),
    // so decode e_type in that endianness rather than assuming little-endian.
    if input_binary.len() >= 18 {
        let e_type_bytes = [input_binary[16], input_binary[17]];
        let e_type = if input_binary[5] == object::elf::ELFDATA2MSB {
            u16::from_be_bytes(e_type_bytes)
        } else {
            u16::from_le_bytes(e_type_bytes)
        };
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
    let (arch, text_sections, trampoline_base_addr) = {
        let file = object::File::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;

        let arch = match file {
            object::File::Elf64(_) => match file.architecture() {
                object::Architecture::X86_64 => Arch::X86_64,
                object::Architecture::Aarch64 => Arch::Aarch64,
                _ => return Ok(input_binary.to_vec()),
            },
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

        let trampoline_base_addr = find_addr_for_trampoline_code(&file, arch.trampoline_align())?;

        (arch, text_sections, trampoline_base_addr)
    };

    // AArch64 uses a fully separate rewriting strategy (single-instruction
    // branch replacement, no instruction borrowing). Dispatch to it before any
    // x86-only work (iced-x86 decoding would misinterpret AArch64 bytes).
    // See the `arm64` module docs.
    if arch == Arch::Aarch64 {
        return hook_aarch64_elf(
            input_binary,
            buf,
            &text_sections,
            trampoline_base_addr,
            trampoline.unwrap_or(0),
            host,
        );
    }

    if !matches!(host, Host::Linux) {
        return Err(Error::UnsupportedExecutable(
            "x86-64 guests only run under a Linux host".into(),
        ));
    }

    let control_transfer_targets = get_control_transfer_targets(arch, &*buf, &text_sections)?;
    let mut trampoline_data = Vec::from(trampoline.unwrap_or(0).to_le_bytes());
    let patch_result = patch_syscalls_in_sections(
        arch,
        buf,
        &text_sections,
        &control_transfer_targets,
        trampoline_base_addr,
        trampoline_base_addr,
        &mut trampoline_data,
    )?;

    if !patch_result.found_syscall {
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
    append_trampoline_footer(
        &mut out,
        &mut trampoline_data,
        trampoline_base_addr,
        false,
        Arch::X86_64.trampoline_align(),
    );

    if !patch_result.skipped_addrs.is_empty() {
        return Err(Error::UnpatchableSyscalls(format!(
            "{} unpatchable syscall instruction(s) at {skipped_addrs:?}",
            patch_result.skipped_addrs.len(),
            skipped_addrs = patch_result.skipped_addrs,
        )));
    }
    Ok(out)
}

/// Rewrite an x86-64 PE for LiteBox's current Windows shim.
///
/// The PE file layout is preserved, but executable-section GS segment overrides
/// are rewritten to FS and `syscall` instructions are redirected through a
/// LiteBox trampoline appended as a file overlay. The Windows shim loader maps
/// that overlay by reading the footer this function appends.
pub fn rewrite_pe_for_litebox(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    if is_already_hooked(input_binary, Arch::X86_64) {
        return Ok(input_binary.to_vec());
    }

    let mut backing = vec![0u64; input_binary.len().div_ceil(8)];
    let buf: &mut [u8] = zerocopy::IntoBytes::as_mut_bytes(backing.as_mut_slice());
    buf[..input_binary.len()].copy_from_slice(input_binary);
    let buf = &mut buf[..input_binary.len()];

    let (text_sections, sysno_map, trampoline_base_rva, trampoline_base_addr) = {
        let pe = PeFile64::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;
        let optional_header = pe.nt_headers().optional_header();
        let size_of_image = u64::from(optional_header.size_of_image());
        let trampoline_base_rva =
            checked_add_u64(size_of_image, 0xfff, "PE trampoline base")? & !0xfff;
        let trampoline_base_addr = checked_add_u64(
            optional_header.image_base(),
            trampoline_base_rva,
            "PE trampoline virtual address",
        )?;

        let file = object::File::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;
        match file {
            object::File::Pe64(_) if file.architecture() == object::Architecture::X86_64 => {}
            _ => return Ok(input_binary.to_vec()),
        }

        let text_sections = match pe_text_sections(&file) {
            Ok(sections) => sections,
            Err(InternalError::NoTextSectionFound) => return Ok(input_binary.to_vec()),
            Err(InternalError::Public(e)) => return Err(e),
            Err(e) => unreachable!("unexpected internal error: {e:?}"),
        };
        let sysno_map = pe_ntdll_sysno_map(&file, buf, &text_sections)?;
        (
            text_sections,
            sysno_map,
            trampoline_base_rva,
            trampoline_base_addr,
        )
    };

    for section in &text_sections {
        let section_data = section_slice_mut(buf, section)?;
        rewrite_gs_to_fs_in_section(Arch::X86_64, section.vaddr, section_data)?;
    }
    let control_transfer_targets = get_control_transfer_targets(Arch::X86_64, buf, &text_sections)?;
    rewrite_nt_sysnos_in_sections(
        Arch::X86_64,
        buf,
        &text_sections,
        &sysno_map,
        &control_transfer_targets,
    )?;

    let mut trampoline_data = Vec::from(trampoline.unwrap_or(0).to_le_bytes());
    // Windows ntdll packs some syscall stubs too tightly for the generic
    // five-byte jump patcher; keep that PE-specific shape out of the generic path.
    let patched_dense_windows_stubs = patch_dense_windows_syscall_stubs_in_sections(
        Arch::X86_64,
        buf,
        &text_sections,
        &control_transfer_targets,
        trampoline_base_addr,
        trampoline_base_addr,
        &mut trampoline_data,
    )?;
    let patch_result = patch_syscalls_in_sections(
        Arch::X86_64,
        buf,
        &text_sections,
        &control_transfer_targets,
        trampoline_base_addr,
        trampoline_base_addr,
        &mut trampoline_data,
    )?;

    if !patched_dense_windows_stubs && !patch_result.found_syscall {
        return Ok(buf.to_vec());
    }

    let mut out = buf.to_vec();
    append_trampoline_footer(
        &mut out,
        &mut trampoline_data,
        trampoline_base_rva,
        true,
        Arch::X86_64.trampoline_align(),
    );

    if !patch_result.skipped_addrs.is_empty() {
        return Err(Error::UnpatchableSyscalls(format!(
            "{} unpatchable syscall instruction(s) at {skipped_addrs:?}",
            patch_result.skipped_addrs.len(),
            skipped_addrs = patch_result.skipped_addrs,
        )));
    }

    Ok(out)
}

fn is_pe_binary(input_binary: &[u8]) -> bool {
    if input_binary.len() < 0x40 || &input_binary[..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes(input_binary[0x3c..0x40].try_into().unwrap()) as usize;
    input_binary
        .get(pe_offset..pe_offset.saturating_add(4))
        .is_some_and(|magic| magic == b"PE\0\0")
}

fn pe_text_sections(
    file: &object::File<'_>,
) -> core::result::Result<Vec<TextSectionInfo>, InternalError> {
    let text_sections: Vec<_> = file
        .sections()
        .filter_map(|section| {
            let object::SectionFlags::Coff { characteristics } = section.flags() else {
                return None;
            };
            if characteristics & IMAGE_SCN_CNT_CODE == 0 {
                return None;
            }
            if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return None;
            }
            let (file_offset, size) = section.file_range()?;
            Some(TextSectionInfo {
                vaddr: section.address(),
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

/// For ntdll-like PEs, walks `Nt*` exports of `file`, reads the build-specific
/// sysno each stub loads into `eax`, and maps it to the stable LiteBox
/// [`NtSysno`] for that name. `Nt*` and `Zw*` always share sysno numbering
/// inside ntdll, so a map keyed on the build-specific number lets a later pass
/// rewrite both flavors (and any internal ntdll helpers that issue the same
/// syscall inline) uniformly.
fn pe_ntdll_sysno_map(
    file: &object::File<'_>,
    buf: &[u8],
    text_sections: &[TextSectionInfo],
) -> Result<BTreeMap<u32, NtSysno>> {
    let mut map = BTreeMap::new();
    let mut exports_ntdll_loader_entrypoint = false;

    for export in file
        .exports()
        .map_err(|e| Error::ParseError(e.to_string()))?
    {
        let Ok(name) = core::str::from_utf8(export.name()) else {
            continue;
        };
        exports_ntdll_loader_entrypoint |= name == "LdrInitializeThunk";

        let Some(sysno) = NtSysno::from_export_name(name) else {
            continue;
        };

        let addr = export.address();
        let Some(section) = text_sections.iter().find(|s| {
            s.vaddr
                .checked_add(s.size)
                .is_some_and(|end| addr >= s.vaddr && addr < end)
        }) else {
            continue;
        };

        let section_data = section_slice(buf, section)?;
        let stub_offset = usize::try_from(addr - section.vaddr)
            .map_err(|_| Error::ParseError("export offset out of range".into()))?;
        if let Some(build_sysno) = read_nt_stub_sysno(section_data, stub_offset) {
            map.insert(build_sysno, sysno);
        }
    }

    if !exports_ntdll_loader_entrypoint {
        return Ok(BTreeMap::new());
    }

    Ok(map)
}

/// Reads the `mov eax, imm32` immediate that precedes a `syscall` instruction
/// within the first 32 bytes of an NT syscall stub starting at `stub_offset`.
/// Returns `None` if the bytes do not match the expected stub shape.
fn read_nt_stub_sysno(section_data: &[u8], stub_offset: usize) -> Option<u32> {
    let stub = section_data.get(stub_offset..)?;
    let stub_len = stub.len().min(32);
    let syscall_offset = stub[..stub_len]
        .windows(2)
        .position(|bytes| bytes == [0x0f, 0x05])?;
    let mov_eax_offset = stub[..syscall_offset]
        .windows(5)
        .position(|bytes| bytes[0] == 0xb8)?;
    let imm = u32::from_le_bytes(
        stub[mov_eax_offset + 1..mov_eax_offset + 5]
            .try_into()
            .ok()?,
    );
    Some(imm)
}

fn rewrite_nt_sysnos_in_sections(
    arch: Arch,
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    sysno_map: &BTreeMap<u32, NtSysno>,
    control_transfer_targets: &BTreeSet<u64>,
) -> Result<usize> {
    if sysno_map.is_empty() {
        return Ok(0);
    }
    let mut rewritten = 0;
    for section in text_sections {
        let section_data = section_slice_mut(buf, section)?;
        rewritten += rewrite_nt_sysnos_in_section(
            arch,
            section.vaddr,
            section_data,
            sysno_map,
            control_transfer_targets,
        )?;
    }
    Ok(rewritten)
}

/// For every `syscall` in `section_data`, looks backward up to
/// [`NT_SYSNO_REWRITE_LOOKBACK`] instructions for the closest `mov r32, imm32`
/// that targets `eax`. If the immediate is a known build-specific sysno from
/// `sysno_map`, rewrites it in place to the stable LiteBox sysno.
///
/// The backward walk stops at any unconditional control transfer (`jmp`,
/// `ret`, indirect branch, exception), at any instruction that is itself a
/// control-transfer target, and at any earlier write to `eax`. Conditional
/// branches are walked through, because the canonical NT stub has a `test
/// [...], 1; jne +3; syscall` sequence where execution reaches `syscall` by
/// falling through `jne`. Syscalls that are themselves jump targets are
/// skipped entirely — there's no way to know which `mov eax` the jumping code
/// arrived with.
fn rewrite_nt_sysnos_in_section(
    arch: Arch,
    section_base_addr: u64,
    section_data: &mut [u8],
    sysno_map: &BTreeMap<u32, NtSysno>,
    control_transfer_targets: &BTreeSet<u64>,
) -> Result<usize> {
    let instructions = decode_section_instructions(arch, section_data, section_base_addr)?;
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let mut rewritten = 0;

    for (i, inst) in instructions.iter().enumerate() {
        if inst.code() != iced_x86::Code::Syscall {
            continue;
        }
        if control_transfer_targets.contains(&inst.ip()) {
            continue;
        }
        let lookback_start = i.saturating_sub(NT_SYSNO_REWRITE_LOOKBACK);
        for j in (lookback_start..i).rev() {
            let prev = &instructions[j];
            // A `jne`/`je`/etc. between `mov eax, sysno` and `syscall` is normal
            // (the canonical NT stub has `test ...; jne +3; syscall`), so we
            // keep walking through conditional branches and calls — they fall
            // through to the next instruction in the common case. We only stop
            // at unconditional transfers that prove the linear chain from
            // `prev → next → ... → syscall` was never the execution path.
            if matches!(
                prev.flow_control(),
                iced_x86::FlowControl::UnconditionalBranch
                    | iced_x86::FlowControl::IndirectBranch
                    | iced_x86::FlowControl::Call
                    | iced_x86::FlowControl::IndirectCall
                    | iced_x86::FlowControl::Return
                    | iced_x86::FlowControl::Exception
            ) {
                break;
            }
            if prev.code() == iced_x86::Code::Mov_r32_imm32
                && prev.op0_register() == iced_x86::Register::EAX
            {
                if let Some(&sysno) = sysno_map.get(&prev.immediate32()) {
                    let inst_offset = usize::try_from(prev.ip() - section_base_addr)
                        .map_err(|_| Error::ParseError("instruction offset out of range".into()))?;
                    // `Mov_r32_imm32` always encodes the 32-bit immediate as the
                    // last four bytes of the instruction, regardless of any REX
                    // prefix in front of the opcode.
                    let imm_end = inst_offset
                        .checked_add(prev.len())
                        .ok_or_else(|| Error::AddressOverflow("mov eax end".into()))?;
                    let imm_start = imm_end
                        .checked_sub(4)
                        .ok_or_else(|| Error::ParseError("mov eax length < 4".into()))?;
                    section_data[imm_start..imm_end].copy_from_slice(&sysno.as_raw().to_le_bytes());
                    rewritten += 1;
                }
                break;
            }
            if instruction_writes_eax(&mut info_factory, prev) {
                break;
            }
            if control_transfer_targets.contains(&prev.ip()) {
                break;
            }
        }
    }

    Ok(rewritten)
}

/// Returns `true` if `inst` writes (or partially writes) the `eax` register
/// family — `eax`, `rax`, `ax`, `al`, `ah` (including implicit writes such as
/// `cpuid`/`mul`/`div`/`cdq`). Used by the sysno rewriter to detect an EAX
/// clobber between a stale `mov eax, K` and a downstream `syscall`, so a
/// sequence like `mov eax, K; xor eax, eax; syscall` does not mis-rewrite `K`
/// as a sysno load.
fn instruction_writes_eax(
    info_factory: &mut iced_x86::InstructionInfoFactory,
    inst: &iced_x86::Instruction,
) -> bool {
    use iced_x86::{OpAccess, Register};
    for used in info_factory.info(inst).used_registers() {
        if !matches!(
            used.access(),
            OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
        ) {
            continue;
        }
        if matches!(
            used.register(),
            Register::EAX | Register::RAX | Register::AX | Register::AL | Register::AH
        ) {
            return true;
        }
    }
    false
}

fn rewrite_gs_to_fs_in_section(
    arch: Arch,
    section_base_addr: u64,
    section_data: &mut [u8],
) -> Result<usize> {
    let instructions = decode_section_instructions(arch, section_data, section_base_addr)?;
    let mut rewritten = 0;

    for instruction in &instructions {
        if instruction.memory_segment() != iced_x86::Register::GS {
            continue;
        }

        let offset = usize::try_from(instruction.ip() - section_base_addr).unwrap();
        let instruction_bytes = &mut section_data[offset..offset + instruction.len()];
        let Some(segment_prefix) = instruction_bytes.iter_mut().find(|byte| **byte == 0x65) else {
            return Err(Error::DisassemblyFailure(format!(
                "GS memory operand at {:#x} has no GS segment prefix",
                instruction.ip()
            )));
        };
        *segment_prefix = 0x64;
        rewritten += 1;
    }

    Ok(rewritten)
}

fn patch_syscalls_in_sections(
    arch: Arch,
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    control_transfer_targets: &BTreeSet<u64>,
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    trampoline_data: &mut Vec<u8>,
) -> Result<SyscallPatchResult> {
    let mut found_syscall = false;
    let mut skipped_addrs = Vec::new();

    for section in text_sections {
        let section_data = section_slice_mut(buf, section)?;
        match hook_syscalls_in_section(
            arch,
            control_transfer_targets,
            section.vaddr,
            section_data,
            trampoline_base_addr,
            syscall_entry_addr,
            trampoline_data,
        ) {
            Ok(addrs) => {
                found_syscall = true;
                skipped_addrs.extend(addrs);
            }
            Err(InternalError::NoSyscallInstructionsFound) => {}
            Err(InternalError::Public(e)) => return Err(e),
            Err(e) => unreachable!("unexpected internal error: {e:?}"),
        }
    }

    Ok(SyscallPatchResult {
        found_syscall,
        skipped_addrs,
    })
}

fn patch_dense_windows_syscall_stubs_in_sections(
    arch: Arch,
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    control_transfer_targets: &BTreeSet<u64>,
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    trampoline_data: &mut Vec<u8>,
) -> Result<bool> {
    let mut patched_any = false;

    for section in text_sections {
        let section_data = section_slice_mut(buf, section)?;
        let instructions = decode_section_instructions(arch, section_data, section.vaddr)?;
        for (i, inst) in instructions.iter().enumerate() {
            if inst.code() != iced_x86::Code::Syscall {
                continue;
            }

            patched_any |= patch_dense_windows_syscall_stub(
                control_transfer_targets,
                section.vaddr,
                section_data,
                trampoline_base_addr,
                syscall_entry_addr,
                trampoline_data,
                &instructions,
                i,
            )?;
        }
    }

    Ok(patched_any)
}

fn append_trampoline_footer(
    out: &mut Vec<u8>,
    trampoline_data: &mut Vec<u8>,
    header_vaddr: u64,
    align_trampoline_size: bool,
    align: u64,
) {
    // The file offset has to carry the same alignment as the virtual address:
    // the loader maps the trampoline straight out of the file at that offset,
    // and a page-granular file mapping cannot start part-way into a page.
    let align = usize::try_from(align).expect("trampoline alignment fits a pointer");
    let remain = out.len() % align;
    out.extend_from_slice(&vec![0; if remain == 0 { 0 } else { align - remain }]);

    let trampoline_file_offset = out.len() as u64;
    if align_trampoline_size {
        let trampoline_size = trampoline_data.len().next_multiple_of(align);
        trampoline_data.extend_from_slice(&vec![0; trampoline_size - trampoline_data.len()]);
    }
    let trampoline_size = trampoline_data.len();
    out.extend_from_slice(trampoline_data);

    let header = TrampolineHeader64 {
        magic: *TRAMPOLINE_MAGIC,
        file_offset: trampoline_file_offset,
        vaddr: header_vaddr,
        trampoline_size: trampoline_size as u64,
    };
    out.extend_from_slice(header.as_bytes());
}

/// Rewrite an AArch64 ELF, appending the trampoline and trailing header.
///
/// `input_binary` is the original, unmodified ELF; `buf` is the mutable copy
/// (patched in place by the arm64 module). `callback` is the absolute address
/// stored in the trampoline's callback slot (0 when the loader fills it in
/// later).
///
/// Like the x86-64 path, a binary with no patch sites is emitted as the
/// original bytes followed by a size-0 trampoline sentinel header (the arm64
/// module signals this by returning `None`). Otherwise the output layout is
/// `[patched ELF][padding to page boundary][trampoline code][header]`.
fn hook_aarch64_elf(
    input_binary: &[u8],
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    host: Host,
) -> Result<Vec<u8>> {
    let Some(outcome) =
        arm64::hook_syscalls_aarch64(buf, text_sections, trampoline_base_addr, callback, host)?
    else {
        // No patch sites: emit the original binary with a size-0 sentinel
        // header so the loader knows there is no trampoline to map.
        let mut out = input_binary.to_vec();
        let header = TrampolineHeader64 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: 0,
            vaddr: 0,
            trampoline_size: 0,
        };
        out.extend_from_slice(header.as_bytes());
        return Ok(out);
    };

    // Build output: [patched ELF][padding to page boundary][trampoline][header].
    let mut trampoline_data = outcome.trampoline;
    let mut out = buf.to_vec();
    append_trampoline_footer(
        &mut out,
        &mut trampoline_data,
        trampoline_base_addr,
        false,
        Arch::Aarch64.trampoline_align(),
    );

    if !outcome.trapped_sites.is_empty() {
        return Err(Error::UnpatchableSyscalls(format!(
            "{} unpatchable instruction(s) (SVC / MSR / MRS TPIDR_EL0) at {trapped:?}",
            outcome.trapped_sites.len(),
            trapped = outcome.trapped_sites,
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
        Arch::X86_64 | Arch::Aarch64 => size_of::<TrampolineHeader64>(),
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
        // Size=0 sentinel: the rewriter processed this binary but found nothing
        // to patch — no syscall instructions, and on AArch64 no `MSR`/`MRS
        // TPIDR_EL0` accesses either. It is already hooked (nothing to do).
        return true;
    }
    if file_offset % 0x1000 != 0 {
        return false;
    }
    if vaddr % 0x1000 != 0 {
        return false;
    }
    if file_offset.checked_add(trampoline_size) != Some(header_start as u64) {
        return false;
    }

    true
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Alignment for the appended trampoline's virtual address, file offset and
    /// size.
    ///
    /// The loader maps the trampoline as its own page-granular mapping and
    /// rejects a header whose `vaddr` is not aligned to the *host's* page size,
    /// so this has to satisfy every host the image might be loaded on, not the
    /// one that rewrote it. x86-64 pages are always 4 KiB. AArch64's are not:
    /// Apple Silicon uses 16 KiB, and Linux can be built for 16 KiB or 64 KiB,
    /// so a 4 KiB-aligned trampoline is unloadable on most of them. 64 KiB
    /// covers all three, and is the maximum page size AArch64 ELF images are
    /// conventionally linked for anyway (see `docs/macos.md`), so it costs
    /// address space that the layout already assumed.
    const fn trampoline_align(self) -> u64 {
        match self {
            Arch::X86_64 => 0x1000,
            Arch::Aarch64 => 0x1_0000,
        }
    }
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
            Arch::Aarch64 => unreachable!("AArch64 uses the arm64 module, not iced-x86"),
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

#[allow(clippy::too_many_arguments)]
fn patch_dense_windows_syscall_stub(
    control_transfer_targets: &BTreeSet<u64>,
    section_base_addr: u64,
    section_data: &mut [u8],
    trampoline_base_addr: u64,
    syscall_entry_addr: u64,
    trampoline_data: &mut Vec<u8>,
    instructions: &[iced_x86::Instruction],
    inst_index: usize,
) -> Result<bool> {
    if inst_index < 2 {
        return Ok(false);
    }

    let test_inst = &instructions[inst_index - 2];
    let jne_inst = &instructions[inst_index - 1];
    let syscall_inst = &instructions[inst_index];

    if !is_dense_windows_syscall_stub_sequence(test_inst, jne_inst, section_base_addr, section_data)
    {
        return Ok(false);
    }

    let stub_addr = test_inst.ip();
    let fallback_addr = checked_add_u64(
        jne_inst.ip(),
        DENSE_WINDOWS_SYSCALL_STUB_TAIL_FALLBACK_OFFSET as u64,
        "dense Windows syscall fallback address",
    )?;
    let stub_end_addr = checked_add_u64(
        jne_inst.ip(),
        DENSE_WINDOWS_SYSCALL_STUB_TAIL.len() as u64,
        "dense Windows syscall stub end address",
    )?;
    if control_transfer_targets
        .iter()
        .any(|target| (stub_addr..stub_end_addr).contains(target) && *target != fallback_addr)
    {
        return Ok(false);
    }

    let target_addr = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64,
        "dense Windows syscall trampoline target",
    )?;

    let return_addr = syscall_inst.next_ip();
    let jmp_back_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64 + 7,
        "dense Windows syscall trampoline return base",
    )?;
    // lea rcx, [rip + disp32]
    trampoline_data.extend_from_slice(&[0x48, 0x8D, 0x0D]);
    trampoline_data.extend_from_slice(&rel32_bytes(
        return_addr,
        jmp_back_base,
        "dense Windows syscall trampoline return",
    )?);

    // jmp qword ptr [rip + disp32]
    trampoline_data.extend_from_slice(&[0xFF, 0x25]);
    let entry_base = checked_add_u64(
        trampoline_base_addr,
        trampoline_data.len() as u64 + 4,
        "dense Windows syscall trampoline entry base",
    )?;
    trampoline_data.extend_from_slice(&rel32_bytes(
        syscall_entry_addr,
        entry_base,
        "dense Windows syscall trampoline entry",
    )?);

    let stub_offset = usize::try_from(stub_addr - section_base_addr).unwrap();
    section_data[stub_offset] = 0xe9;
    let patch_base = checked_add_u64(stub_addr, 5, "dense Windows syscall patch jump base")?;
    section_data[stub_offset + 1..stub_offset + 5].copy_from_slice(&rel32_bytes(
        target_addr,
        patch_base,
        "dense Windows syscall patch jump",
    )?);

    let syscall_end_offset = usize::try_from(syscall_inst.next_ip() - section_base_addr).unwrap();
    for byte in &mut section_data[stub_offset + 5..syscall_end_offset] {
        *byte = 0x90;
    }

    let fallback_offset = usize::try_from(fallback_addr - section_base_addr).unwrap();
    section_data[fallback_offset] = 0xeb;
    section_data[fallback_offset + 1] =
        i8::try_from(i128::from(stub_addr) - i128::from(fallback_addr) - 2)
            .map_err(|_| {
                Error::AddressOverflow("dense Windows syscall fallback jump out of range".into())
            })?
            .to_ne_bytes()[0];

    Ok(true)
}

fn is_dense_windows_syscall_stub_sequence(
    test_inst: &iced_x86::Instruction,
    jne_inst: &iced_x86::Instruction,
    section_base_addr: u64,
    section_data: &[u8],
) -> bool {
    if !matches!(
        test_inst.code(),
        iced_x86::Code::Test_rm8_imm8 | iced_x86::Code::Test_rm8_imm8_F6r1
    ) || test_inst.immediate8() != 1
    {
        return false;
    }

    let Ok(tail_offset) = usize::try_from(jne_inst.ip() - section_base_addr) else {
        return false;
    };
    let Some(tail_end) = tail_offset.checked_add(DENSE_WINDOWS_SYSCALL_STUB_TAIL.len()) else {
        return false;
    };

    section_data.get(tail_offset..tail_end) == Some(DENSE_WINDOWS_SYSCALL_STUB_TAIL)
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

fn find_addr_for_trampoline_code(file: &object::File<'_>, align: u64) -> Result<u64> {
    // Find the highest virtual address among all PT_LOAD segments
    let max_virtual_addr = match file {
        object::File::Elf64(elf) => max_load_segment_end(elf),
        _ => unreachable!(),
    }
    .ok_or_else(|| Error::ParseError("no PT_LOAD segments found".into()))?;

    checked_add_u64(max_virtual_addr, align - 1, "trampoline base").map(|addr| addr & !(align - 1))
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
// jne +3; syscall; ret; int 0x2e; ret
const DENSE_WINDOWS_SYSCALL_STUB_TAIL: &[u8] = &[0x75, 0x03, 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3];
const DENSE_WINDOWS_SYSCALL_STUB_TAIL_FALLBACK_OFFSET: usize = 5;

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
        Arch::Aarch64 => unreachable!("AArch64 uses the arm64 module, not iced-x86"),
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
        let postsyscall_target =
            checked_add_u64(target_addr, preamble_len, "post-syscall trampoline target")?;
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

    #[test]
    fn aarch64_out_of_range_site_is_rejected_as_unpatchable() {
        // A trampoline mapped 256MB above the text is outside the site's ±128MB
        // branch reach, so the `SVC` is trapped and the rewrite is rejected,
        // mirroring the x86-64 unpatchable-syscall contract.
        let mut buf = 0xD400_0001u32.to_le_bytes().to_vec(); // SVC #0
        let input = buf.clone();
        let sections = vec![TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        let err =
            hook_aarch64_elf(&input, &mut buf, &sections, 0x1000_0000, 0, Host::Linux).unwrap_err();
        assert!(
            matches!(err, Error::UnpatchableSyscalls(_)),
            "expected UnpatchableSyscalls, got {err:?}"
        );
    }

    const NT_STUB_BUILD_SYSNO: u32 = 0x1234;

    fn nt_stub_bytes() -> [u8; 24] {
        [
            0x4c, 0x8b, 0xd1, // mov r10, rcx
            0xb8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234
            0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, // test byte ptr [...], 1
            0x75, 0x03, // jne +3
            0x0f, 0x05, // syscall
            0xc3, // ret
            0xcd, 0x2e, // int 2e
            0xc3, // ret
        ]
    }

    #[test]
    fn read_nt_stub_sysno_extracts_build_specific_imm32() {
        let stub = nt_stub_bytes();
        assert_eq!(read_nt_stub_sysno(&stub, 0), Some(NT_STUB_BUILD_SYSNO));
    }

    #[test]
    fn read_nt_stub_sysno_rejects_stub_without_syscall() {
        let stub = [0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3];
        assert_eq!(read_nt_stub_sysno(&stub, 0), None);
    }

    #[test]
    fn rewrite_replaces_mov_eax_before_syscall() {
        let mut stub = nt_stub_bytes();
        let mut map = BTreeMap::new();
        map.insert(NT_STUB_BUILD_SYSNO, NtSysno::NtTerminateProcess);
        let targets = BTreeSet::new();

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut stub, &map, &targets).unwrap();
        assert_eq!(rewritten, 1);
        assert_eq!(
            &stub[4..8],
            &NtSysno::NtTerminateProcess.as_raw().to_le_bytes(),
        );
    }

    #[test]
    fn rewrite_covers_zw_alias_with_same_build_sysno() {
        // Two stubs back-to-back sharing the same build-specific sysno, the way
        // ntdll's Nt* / Zw* pair often look when emitted as separate stubs.
        let mut section = Vec::new();
        section.extend_from_slice(&nt_stub_bytes());
        section.extend_from_slice(&nt_stub_bytes());

        let mut map = BTreeMap::new();
        map.insert(NT_STUB_BUILD_SYSNO, NtSysno::NtTerminateProcess);
        let targets = BTreeSet::new();

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut section, &map, &targets).unwrap();
        assert_eq!(rewritten, 2);
        let expected = NtSysno::NtTerminateProcess.as_raw().to_le_bytes();
        assert_eq!(&section[4..8], &expected);
        assert_eq!(
            &section[nt_stub_bytes().len() + 4..nt_stub_bytes().len() + 8],
            &expected
        );
    }

    #[test]
    fn rewrite_leaves_mov_eax_with_unknown_imm_alone() {
        let mut stub = nt_stub_bytes();
        let map: BTreeMap<u32, NtSysno> = BTreeMap::new();
        let targets = BTreeSet::new();

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut stub, &map, &targets).unwrap();
        assert_eq!(rewritten, 0);
        assert_eq!(&stub[4..8], &NT_STUB_BUILD_SYSNO.to_le_bytes());
    }

    #[test]
    fn rewrite_skips_when_eax_is_clobbered_before_syscall() {
        // `mov eax, K; xor eax, eax; syscall`. The mov's K matches a known
        // build sysno, but the xor zeroes eax before the syscall — so K is not
        // the sysno that feeds the syscall and must not be rewritten.
        let mut section: Vec<u8> = vec![
            0xb8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234
            0x31, 0xc0, // xor eax, eax
            0x0f, 0x05, // syscall
        ];

        let mut map = BTreeMap::new();
        map.insert(NT_STUB_BUILD_SYSNO, NtSysno::NtTerminateProcess);
        let targets = BTreeSet::new();

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut section, &map, &targets).unwrap();
        assert_eq!(rewritten, 0);
        assert_eq!(&section[1..5], &NT_STUB_BUILD_SYSNO.to_le_bytes());
    }

    #[test]
    fn rewrite_does_not_cross_basic_block_boundary() {
        // `mov eax, K; ret; <next function body> syscall`. The mov's K matches
        // a known sysno but lives in a previous function (separated by `ret`);
        // the syscall is reached by control flow that never touched that mov.
        let mut section: Vec<u8> = vec![
            0xb8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234   (in prior function)
            0xc3, // ret                                       (block boundary)
            0x0f, 0x05, // syscall                            (next function)
        ];

        let mut map = BTreeMap::new();
        map.insert(NT_STUB_BUILD_SYSNO, NtSysno::NtTerminateProcess);
        let targets = BTreeSet::new();

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut section, &map, &targets).unwrap();
        assert_eq!(rewritten, 0);
        assert_eq!(&section[1..5], &NT_STUB_BUILD_SYSNO.to_le_bytes());
    }

    #[test]
    fn rewrite_skips_syscall_that_is_jump_target() {
        // `mov eax, K; syscall` where the syscall is jumped to from elsewhere.
        // We can't trust that the preceding mov is what set eax for callers that
        // arrived via the jump.
        let syscall_offset: u64 = 5;
        let mut section: Vec<u8> = vec![
            0xb8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234   (offset 0..5)
            0x0f, 0x05, // syscall                            (offset 5..7)
        ];

        let mut map = BTreeMap::new();
        map.insert(NT_STUB_BUILD_SYSNO, NtSysno::NtTerminateProcess);
        let mut targets = BTreeSet::new();
        targets.insert(syscall_offset);

        let rewritten =
            rewrite_nt_sysnos_in_section(Arch::X86_64, 0, &mut section, &map, &targets).unwrap();
        assert_eq!(rewritten, 0);
        assert_eq!(&section[1..5], &NT_STUB_BUILD_SYSNO.to_le_bytes());
    }

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
