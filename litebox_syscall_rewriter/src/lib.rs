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
//! It also supports AArch64 ELFs. Linux has complete syscall, guest
//! thread-pointer, and optional x18 virtualization. macOS and Windows target
//! selection currently provides x18-only host-anchor emission scaffolding;
//! there is no in-tree loader/runtime for those artifacts.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

// Only the runtime entry points dispatch on `target_arch`; the ahead-of-time
// ones select the architecture from the input object and build anywhere.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "litebox_syscall_rewriter's runtime patching entry points support only x86-64 and AArch64 hosts"
);

pub mod aarch64;

/// Callback-slot bytes the caller must populate; zero when emitted inline.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = size_of::<u64>();
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = 0;

/// Furthest a trampoline may sit from any byte of the code segment reaching it.
///
/// A rewritten site branches to its stub with a single direct branch, so a
/// trampoline beyond this displacement cannot be reached and the site has to
/// fall back to a trap. Each architecture's value is its direct-branch range
/// less a margin for the last stub in the trampoline.
#[cfg(target_arch = "x86_64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x7FFF_0000;
#[cfg(target_arch = "aarch64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x07FF_0000;

/// Alignment every write cursor into a trampoline must satisfy.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = 1;
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = aarch64::GATE_ALIGNMENT;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use litebox_common_windows::NtSysno;
use object::pe::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use object::read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _, PeFile64};
use object::read::{Object as _, ObjectSection as _, ObjectSegment as _};
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
    #[error("failed to patch trampoline: {0}")]
    TrampolinePatchFailure(String),
    #[error("trampoline needs {needed:#x} bytes but only {available:#x} are available")]
    TrampolineTooLarge { needed: u64, available: u64 },
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

/// Offset of `e_ident[EI_DATA]`, the byte selecting the header's endianness.
///
/// `e_ident` and `e_type` are laid out identically in ELF32 and ELF64, so the
/// ELF64 header's offsets locate these fields in either.
const ELF_EI_DATA_OFFSET: usize = core::mem::offset_of!(object::elf::Ident, data);

/// Offset of `e_machine`.
const ELF_E_MACHINE_OFFSET: usize =
    core::mem::offset_of!(object::elf::FileHeader64<object::LittleEndian>, e_machine);

const BUN_FOOTER_MARKER: &[u8] = b"\n---- Bun! ----\n";

/// The magic bytes used to identify the trampoline data.
/// This is checked by the loader to verify that the trampoline is valid.
pub const TRAMPOLINE_MAGIC: &[u8; 8] = b"LITEBOX0";

/// Host operating system for AArch64 guest rewriting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TargetHost {
    /// Linux, using `TPIDR_EL0` as the host per-thread anchor.
    #[default]
    Linux,
    /// Experimental macOS emission using `TPIDRRO_EL0` as the host anchor.
    /// No in-tree macOS runtime consumes these artifacts.
    MacOs,
    /// Experimental Windows emission using physical `x18` as the host anchor.
    /// No in-tree AArch64 Windows runtime consumes these artifacts.
    Windows,
}

/// Options for architecture-specific rewriting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RewriteOptions {
    target_host: TargetHost,
    virtualize_x18: bool,
}

impl RewriteOptions {
    /// Selects the AArch64 host and whether Linux guest `x18` accesses are
    /// virtualized. Non-Linux targets always virtualize `x18`.
    pub const fn new(target_host: TargetHost, virtualize_x18: bool) -> Self {
        Self {
            target_host,
            virtualize_x18: virtualize_x18 || !matches!(target_host, TargetHost::Linux),
        }
    }

    /// Returns the selected AArch64 host ABI.
    const fn target_host(self) -> TargetHost {
        self.target_host
    }

    /// Returns whether AArch64 guest `x18` accesses must be virtualized.
    const fn effective_virtualize_x18(self) -> bool {
        self.virtualize_x18
    }
}

/// Rewrite a supported binary for LiteBox.
///
/// ELF64 inputs are passed through [`hook_syscalls_in_elf`]. PE64 inputs have
/// executable-section GS segment overrides rewritten to FS and `syscall`
/// instructions redirected through a LiteBox trampoline footer.
pub fn rewrite_binary(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    rewrite_binary_with_options(input_binary, trampoline, RewriteOptions::default())
}

/// Rewrite a supported binary with explicit architecture-specific options.
///
/// The options affect AArch64 ELF rewriting and are ignored for PE input.
pub fn rewrite_binary_with_options(
    input_binary: &[u8],
    trampoline: Option<u64>,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    if is_pe_binary(input_binary) {
        rewrite_pe_for_litebox(input_binary, trampoline)
    } else {
        hook_syscalls_in_elf_with_options(input_binary, trampoline, options)
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
#[derive(Clone, Copy)]
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
/// For patch-site discovery, AArch64 also rewrites guest thread-pointer accesses
/// (`MSR TPIDR_EL0` writes and `MRS TPIDR_EL0` reads) and, when requested,
/// supported x18 accesses. Such a binary is patched even when it has no syscall
/// (`SVC`) instructions. See the `aarch64` module docs.
///
/// Returns the rewritten binary. Binaries that cannot or do not need to be
/// patched (relocatable objects, non-ELF files, already-hooked binaries,
/// binaries without executable sections) are returned unchanged.
///
/// Returns `Err` for genuinely broken inputs (corrupt ELF, unsupported
/// executables like Bun, arithmetic overflow) and for binaries that contain
/// patch sites that could not be redirected. An unpatchable site is replaced
/// with a trapping instruction so it faults instead of escaping to the host
/// kernel: `icebp; hlt` on x86-64, and `BRK` on AArch64 (where a patch site is
/// an `SVC`, `MSR TPIDR_EL0`, `MRS TPIDR_EL0`, or enabled x18 instruction).
pub fn hook_syscalls_in_elf(input_binary: &[u8], trampoline: Option<u64>) -> Result<Vec<u8>> {
    hook_syscalls_in_elf_with_options(input_binary, trampoline, RewriteOptions::default())
}

/// Rewrite an ELF with explicit architecture-specific options.
pub fn hook_syscalls_in_elf_with_options(
    input_binary: &[u8],
    trampoline: Option<u64>,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    if input_binary.ends_with(BUN_FOOTER_MARKER) {
        return Err(Error::UnsupportedExecutable(
            "Bun-packaged executable".into(),
        ));
    }

    // The AArch64 emitter reads and writes instruction words in little-endian
    // order, so reject a big-endian AArch64 object before parsing or mutating it.
    let data = input_binary.get(ELF_EI_DATA_OFFSET);
    let machine = input_binary
        .get(ELF_E_MACHINE_OFFSET..ELF_E_MACHINE_OFFSET + size_of::<u16>())
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes);
    if data == Some(&object::elf::ELFDATA2MSB) && machine == Some(object::elf::EM_AARCH64) {
        return Err(Error::UnsupportedExecutable(
            "big-endian AArch64 ELF".into(),
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
    let (arch, text_sections, aarch64_code_sections, placement) = {
        let file = object::File::parse(&*buf).map_err(|e| Error::ParseError(e.to_string()))?;

        let arch = match file {
            object::File::Elf64(_) => match file.architecture() {
                object::Architecture::X86_64 => Arch::X86_64,
                object::Architecture::Aarch64 => Arch::Aarch64,
                _ => return Ok(input_binary.to_vec()),
            },
            _ => return Ok(input_binary.to_vec()),
        };

        let (text_sections, aarch64_code_sections) = if arch == Arch::Aarch64 {
            let metadata = match aarch64::elf_code_metadata(&file) {
                Ok(metadata) => metadata,
                Err(InternalError::NoTextSectionFound) => return Ok(input_binary.to_vec()),
                Err(InternalError::Public(error)) => return Err(error),
                Err(error) => unreachable!("unexpected metadata error: {error:?}"),
            };
            (metadata.executable, metadata.identified)
        } else {
            let sections = match text_sections(&file) {
                Ok(sections) => sections,
                Err(InternalError::NoTextSectionFound) => return Ok(input_binary.to_vec()),
                Err(InternalError::Public(error)) => return Err(error),
                Err(error) => unreachable!("unexpected internal error: {error:?}"),
            };
            (sections, Vec::new())
        };

        if is_already_hooked(&*buf, arch) {
            return Ok(input_binary.to_vec());
        }

        let placement = find_addr_for_trampoline_code(&file)?;

        (arch, text_sections, aarch64_code_sections, placement)
    };

    // AArch64 uses a fully separate rewriting strategy (single-instruction
    // branch replacement, no instruction borrowing). Dispatch to it before any
    // x86-only work (iced-x86 decoding would misinterpret AArch64 bytes).
    // See the `aarch64` module docs.
    if arch == Arch::Aarch64 {
        return hook_aarch64_elf(
            input_binary,
            buf,
            aarch64::ScanSections {
                executable: &text_sections,
                code: &aarch64_code_sections,
            },
            placement,
            trampoline.unwrap_or(0),
            options,
        );
    }

    let trampoline_base_addr = placement.addr();
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
    append_trampoline_footer(&mut out, &mut trampoline_data, trampoline_base_addr, false);

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
    append_trampoline_footer(&mut out, &mut trampoline_data, trampoline_base_rva, true);

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
) {
    let remain = out.len() % 0x1000;
    out.extend_from_slice(&vec![0; if remain == 0 { 0 } else { 0x1000 - remain }]);

    let trampoline_file_offset = out.len() as u64;
    if align_trampoline_size {
        let trampoline_size = trampoline_data.len().next_multiple_of(0x1000);
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

/// Rewrites an AArch64 ELF, honoring `placement`.
///
/// The address is baked into every rewritten site, so it has to be chosen
/// before the trampoline's size is known. The rewrite therefore runs at the
/// preferred address and, if the trampoline outgrew the object's inter-segment
/// hole, runs again at the unreserved fallback address.
fn hook_aarch64_elf(
    input_binary: &[u8],
    buf: &mut [u8],
    sections: aarch64::ScanSections<'_>,
    placement: TrampolinePlacement,
    callback: u64,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    if let TrampolinePlacement::InsideLoadSpan { addr, limit, .. } = placement {
        let mut attempt = buf.to_vec();
        let out = hook_aarch64_elf_at(
            input_binary,
            &mut attempt,
            sections,
            addr,
            Some(limit),
            callback,
            options,
        );
        // A gap that is too small, or too far from the text for a gate's
        // branch to reach back, is a property of this address rather than of
        // the binary, so both are worth retrying elsewhere.
        if !matches!(
            out,
            Err(Error::TrampolineTooLarge { .. } | Error::UnpatchableSyscalls(_))
        ) {
            buf.copy_from_slice(&attempt);
            return out;
        }
        // Fall through to retry at the fallback address. `buf` is still
        // pristine: only `attempt` was patched, and a rescan of already-patched
        // bytes would find no sites.
    }
    hook_aarch64_elf_at(
        input_binary,
        buf,
        sections,
        placement.fallback_addr(),
        None,
        callback,
        options,
    )
}

/// Rewrites an AArch64 ELF at a fixed trampoline address, appending the
/// trampoline and trailing header.
///
/// `input_binary` is the original, unmodified ELF; `buf` is the mutable copy
/// (patched in place by the arm64 module). `callback` is the absolute address
/// stored in the trampoline's callback slot (0 when the loader fills it in
/// later). `trampoline_limit` bounds how many bytes the trampoline may occupy,
/// or is `None` where nothing bounds it; overshooting a bound is reported as
/// [`Error::TrampolineTooLarge`].
///
/// Like the x86-64 path, a binary with no patch sites is emitted as the
/// original bytes followed by a size-0 trampoline sentinel header (the arm64
/// module signals this by returning `None`). Otherwise the output layout is
/// `[patched ELF][padding to page boundary][trampoline code][header]`.
fn hook_aarch64_elf_at(
    input_binary: &[u8],
    buf: &mut [u8],
    sections: aarch64::ScanSections<'_>,
    trampoline_base_addr: u64,
    trampoline_limit: Option<u64>,
    callback: u64,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    let Some(outcome) = aarch64::hook_syscalls_aarch64_with_code_ranges(
        buf,
        sections.executable,
        sections.code,
        trampoline_base_addr,
        callback,
        aarch64::RewriteConfig::new(options.target_host(), options.effective_virtualize_x18()),
    )?
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
    let needed = trampoline_data.len() as u64;
    if let Some(limit) = trampoline_limit
        && needed > limit
    {
        return Err(Error::TrampolineTooLarge {
            needed,
            available: limit,
        });
    }
    if !outcome.trapped_sites.is_empty() {
        return Err(Error::UnpatchableSyscalls(format!(
            "{} unpatchable AArch64 patch site(s) (SVC / TPIDR_EL0 / x18) at {:?}",
            outcome.trapped_sites.len(),
            outcome.trapped_sites,
        )));
    }
    let mut out = buf.to_vec();
    append_trampoline_footer(&mut out, &mut trampoline_data, trampoline_base_addr, false);

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

/// Runtime counterpart to [`hook_syscalls_in_elf`], operating on one
/// already-mapped code region. The caller makes the region writable before
/// calling and restores permissions afterwards.
///
/// The region is rewritten for the architecture this crate is running on.
/// `syscall_entry_addr` means:
/// * x86-64: the address of the shared [`TRAMPOLINE_ENTRY_POINT_BYTES`]-sized
///   slot the caller placed at the trampoline base, which holds the callback.
/// * AArch64: the callback address itself; the emitter writes its callback slot.
///
/// TODO: give both architectures the same meaning -- always the callback
/// address -- once the x86-64 stubs branch directly rather than through the
/// slot. Drop this list when `TRAMPOLINE_ENTRY_POINT_BYTES` is zero on every
/// supported architecture.
///
/// # Returns
///
/// `(trampoline_stubs, unredirected_addrs)`, both empty if `code` has no
/// patchable instructions. The caller must copy the stubs to
/// `trampoline_write_vaddr`. On x86-64 the addresses were left native; on
/// AArch64 they were overwritten with `BRK`.
///
/// # Caller obligations on AArch64
///
/// The I-cache is not coherent with the D-cache, so the caller **must**
/// synchronize the instruction stream over the patched `code` and the written
/// stubs before either is fetched, and must pass the emitted gates through
/// [`aarch64::finalize_trampoline_gates`]. Neither omission fails cleanly.
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
) -> Result<(Vec<u8>, Vec<u64>)> {
    patch_code_segment_with_options(
        code,
        code_vaddr,
        trampoline_write_vaddr,
        syscall_entry_addr,
        RewriteOptions::default(),
    )
}

/// Runtime code-segment rewriting with explicit architecture-specific options.
pub fn patch_code_segment_with_options(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
    options: RewriteOptions,
) -> Result<(Vec<u8>, Vec<u64>)> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = options;
        patch_x86_64_code_segment(code, code_vaddr, trampoline_write_vaddr, syscall_entry_addr)
    }
    #[cfg(target_arch = "aarch64")]
    {
        patch_aarch64_code_segment(
            code,
            code_vaddr,
            trampoline_write_vaddr,
            syscall_entry_addr,
            options,
        )
    }
}

/// [`patch_code_segment`] for an x86-64 host.
///
/// The emitted stubs jump *indirectly* through a shared 8-byte slot the caller
/// places once per trampoline allocation, so `syscall_entry_addr` is the
/// address of that slot.
#[cfg(target_arch = "x86_64")]
fn patch_x86_64_code_segment(
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

/// [`patch_code_segment`] for an AArch64 host, where `syscall_entry_addr` is
/// the callback address itself, not a slot holding it.
///
/// The caller must pass the returned gates through
/// [`aarch64::finalize_trampoline_gates`] before making them executable.
#[cfg(any(test, target_arch = "aarch64"))]
fn patch_aarch64_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
    options: RewriteOptions,
) -> Result<(Vec<u8>, Vec<u64>)> {
    let ranges = whole_code_scan_ranges(code.len());
    patch_aarch64_code_segment_with_options_and_ranges(
        code,
        code_vaddr,
        &ranges,
        trampoline_write_vaddr,
        syscall_entry_addr,
        options,
    )
}

#[cfg(any(test, target_arch = "aarch64"))]
fn whole_code_scan_ranges(code_len: usize) -> aarch64::CodeScanRanges {
    let executable: Vec<Range<usize>> = core::iter::once(0..code_len).collect();
    let identified = executable.clone();
    aarch64::CodeScanRanges {
        executable,
        identified,
    }
}

/// Runtime AArch64 rewriting constrained by mapping-relative ELF code ranges.
pub fn patch_aarch64_code_segment_with_options_and_ranges(
    code: &mut [u8],
    code_vaddr: u64,
    ranges: &aarch64::CodeScanRanges,
    trampoline_write_vaddr: u64,
    syscall_entry_addr: u64,
    options: RewriteOptions,
) -> Result<(Vec<u8>, Vec<u64>)> {
    let executable = scan_sections(code_vaddr, &ranges.executable, code.len())?;
    let identified = scan_sections(code_vaddr, &ranges.identified, code.len())?;
    let Some(outcome) = aarch64::hook_syscalls_aarch64_with_code_ranges(
        code,
        &executable,
        &identified,
        trampoline_write_vaddr,
        syscall_entry_addr,
        aarch64::RewriteConfig::new(options.target_host(), options.effective_virtualize_x18()),
    )?
    else {
        return Ok((Vec::new(), Vec::new()));
    };

    Ok((outcome.trampoline, outcome.trapped_sites))
}

fn scan_sections(
    code_vaddr: u64,
    ranges: &[Range<usize>],
    code_len: usize,
) -> Result<Vec<TextSectionInfo>> {
    ranges
        .iter()
        .map(|range| {
            if range.start > range.end || range.end > code_len {
                return Err(Error::ParseError(
                    "scan range extends beyond mapping".into(),
                ));
            }
            Ok(TextSectionInfo {
                vaddr: code_vaddr
                    .checked_add(range.start as u64)
                    .ok_or_else(|| Error::AddressOverflow("scan range address".into()))?,
                file_offset: range.start as u64,
                size: (range.end - range.start) as u64,
            })
        })
        .collect()
}

/// Replace every syscall patch site in `code` with a trap instruction, so that
/// reaching one faults instead of escaping to the host kernel. Returns how many
/// were trapped.
///
/// The fail-safe when trampoline-based patching cannot be performed (allocation
/// failed, or the trampoline is out of branch range). It has to cover exactly
/// the sites the architecture's rewriter would have redirected, or it silently
/// fails safe on nothing.
///
/// On AArch64 the caller must synchronize the instruction stream over `code`
/// before it is fetched again; see [`patch_code_segment`].
pub fn trap_all_syscalls_in_code(code: &mut [u8], code_vaddr: u64) -> Result<usize> {
    trap_all_syscalls_in_code_with_options(code, code_vaddr, RewriteOptions::default())
}

/// Trap every architecture-specific patch site selected by `options`.
pub fn trap_all_syscalls_in_code_with_options(
    code: &mut [u8],
    code_vaddr: u64,
    options: RewriteOptions,
) -> Result<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = options;
        trap_all_x86_64_syscalls(code, code_vaddr)
    }
    #[cfg(target_arch = "aarch64")]
    {
        trap_all_aarch64_patch_sites(code, code_vaddr, options)
    }
}

/// [`trap_all_syscalls_in_code`] for an x86-64 host, where `syscall`
/// instructions become `ICEBP; HLT`.
#[cfg(target_arch = "x86_64")]
fn trap_all_x86_64_syscalls(code: &mut [u8], code_vaddr: u64) -> Result<usize> {
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

/// [`trap_all_syscalls_in_code`] for AArch64, where every site selected by
/// `options` (`SVC`, Linux TPIDR accesses, and enabled x18 accesses) becomes
/// `BRK`.
#[cfg(any(test, target_arch = "aarch64"))]
fn trap_all_aarch64_patch_sites(
    code: &mut [u8],
    code_vaddr: u64,
    options: RewriteOptions,
) -> Result<usize> {
    let ranges = whole_code_scan_ranges(code.len());
    trap_all_aarch64_patch_sites_with_options_and_ranges(code, code_vaddr, &ranges, options)
}

/// Trap runtime AArch64 patch sites selected by mapping-relative ELF ranges.
pub fn trap_all_aarch64_patch_sites_with_options_and_ranges(
    code: &mut [u8],
    code_vaddr: u64,
    ranges: &aarch64::CodeScanRanges,
    options: RewriteOptions,
) -> Result<usize> {
    let executable = scan_sections(code_vaddr, &ranges.executable, code.len())?;
    let identified = scan_sections(code_vaddr, &ranges.identified, code.len())?;
    aarch64::trap_all_patch_sites_with_code_ranges(
        code,
        &executable,
        &identified,
        aarch64::RewriteConfig::new(options.target_host(), options.effective_virtualize_x18()),
    )
}

/// The guest page size assumed when laying out the appended trampoline.
pub(crate) const TRAMPOLINE_PAGE_SIZE: u64 = 0x1000;

/// The address past the object's last `PT_LOAD` where an appended trampoline
/// goes. `max_load_end` is the highest `p_vaddr + p_memsz`, `max_align` the
/// largest `p_align`.
///
/// For AArch64 objects, where large `p_align` is common, this implementation
/// skips one further alignment unit. Other architectures retain the existing
/// page-granular placement.
///
/// **Nothing reserves the returned address**, and glibc packs objects
/// adjacently, so with several shared objects there may be no free gap here at
/// all. `trampoline_placement_for` reaches this only after preferring a hole
/// in the object's own load span; mapping here requires validating the range
/// first (`litebox_shim_linux`'s `trampoline_range_is_safe_to_map`).
pub fn trampoline_addr_for(max_load_end: u64, max_align: u64, e_machine: u16) -> Result<u64> {
    // Guard against a bogus `p_align`: the masking below requires a power of two.
    let align = if e_machine == object::elf::EM_AARCH64 && max_align.is_power_of_two() {
        max_align.max(TRAMPOLINE_PAGE_SIZE)
    } else {
        TRAMPOLINE_PAGE_SIZE
    };
    let aligned_end = checked_add_u64(max_load_end, align - 1, "trampoline base")? & !(align - 1);
    if align <= TRAMPOLINE_PAGE_SIZE {
        Ok(aligned_end)
    } else {
        checked_add_u64(aligned_end, align, "trampoline base")
    }
}

/// A `PT_LOAD` segment, reduced to the fields trampoline placement needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoadSegment {
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_filesz`.
    pub filesz: u64,
    /// `p_memsz`.
    pub memsz: u64,
    /// `p_align`.
    pub align: u64,
}

/// Where an object's appended trampoline goes, and how large it may grow.
///
/// TODO: one trampoline per object bounds every gate twice over -- by the hole
/// it is placed in, and by the callback literal's +-1MiB reach from the single
/// header. Both hold for `SVC` and thread-pointer sites, which are sparse, and
/// both fail if a host ever needs a gate per guest `x18` access: those run to
/// ~2% of instructions, several times the current site count. Placing several
/// smaller trampolines, each with its own header, near the sites they serve
/// would lift both limits and fit the page-sized holes real objects leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrampolinePlacement {
    /// A hole between two `PT_LOAD` segments, inside the object's own load
    /// span. The safe case: the loader reserved the whole span for this object,
    /// so nothing else can be placed there.
    InsideLoadSpan {
        /// Page-aligned virtual address (object-relative for `ET_DYN`).
        addr: u64,
        /// Maximum number of bytes that may be written at `addr` before the
        /// trampoline would run into the next segment.
        limit: u64,
        /// [`trampoline_addr_for`]'s address past the last segment, used when
        /// the trampoline outgrows `limit`.
        fallback_addr: u64,
    },
    /// Past the object's last segment, because its segments leave no big enough
    /// hole. Nothing reserves the range, so the shim validates it before
    /// mapping.
    PastLastSegment {
        /// Page-aligned virtual address (object-relative for `ET_DYN`).
        addr: u64,
    },
}

impl TrampolinePlacement {
    /// The address the trampoline is placed at, preferring the reserved one.
    pub(crate) fn addr(self) -> u64 {
        match self {
            Self::InsideLoadSpan { addr, .. } | Self::PastLastSegment { addr } => addr,
        }
    }

    /// The unreserved address past the last segment, which is the address
    /// itself once placement has already fallen back to it.
    pub(crate) fn fallback_addr(self) -> u64 {
        match self {
            Self::InsideLoadSpan { fallback_addr, .. } => fallback_addr,
            Self::PastLastSegment { addr } => addr,
        }
    }
}

/// Chooses where to put the trampoline appended to `segments`' object.
///
/// Prefers an inter-segment gap, reported as
/// [`TrampolinePlacement::InsideLoadSpan`]. No program header covers the
/// trampoline, so it must land in space the dynamic loader already reserved for
/// *this* object: glibc reserves the whole first-`mapstart` to last-`allocend`
/// span, so the gaps AArch64 objects leave (linked for 64 KiB pages, run with a
/// 4 KiB `AT_PAGESZ`) belong to the object for its lifetime. Addresses past the
/// last segment are unreserved and routinely owned by a neighboring object. The
/// gap is exact because LiteBox pins the guest's `AT_PAGESZ` to
/// [`TRAMPOLINE_PAGE_SIZE`].
///
/// An object with no usable gap falls back to [`trampoline_addr_for`], reported
/// as [`TrampolinePlacement::PastLastSegment`] so the caller knows the address
/// is unreserved and must be validated before mapping.
pub(crate) fn trampoline_placement_for(
    segments: &[LoadSegment],
    e_machine: u16,
) -> Result<TrampolinePlacement> {
    let max_load_end = segments
        .iter()
        .filter_map(|s| s.vaddr.checked_add(s.memsz))
        .max()
        .ok_or_else(|| Error::ParseError("no PT_LOAD segments found".into()))?;
    let max_align = segments.iter().map(|s| s.align).max().unwrap_or(0);
    let fallback_addr = trampoline_addr_for(max_load_end, max_align, e_machine)?;
    let fallback = TrampolinePlacement::PastLastSegment {
        addr: fallback_addr,
    };

    // Compatibility gate: preserve past-last-segment placement off AArch64.
    if e_machine != object::elf::EM_AARCH64 {
        return Ok(fallback);
    }

    Ok(
        largest_inter_segment_hole(segments).map_or(fallback, |(start, end)| {
            TrampolinePlacement::InsideLoadSpan {
                addr: start,
                limit: end - start,
                fallback_addr,
            }
        }),
    )
}

/// Returns the largest page-granular gap between consecutive `PT_LOAD`
/// segments, as `(start, end)`, or `None` when the segments are contiguous.
///
/// The bounds mirror glibc's `mapend` / `mapstart`, except that a segment is
/// treated as occupying `max(p_filesz, p_memsz)` rather than `p_filesz`:
/// `_dl_map_segments` maps anonymous pages over the difference for any segment
/// whose `p_memsz` exceeds its `p_filesz`, not only the last one, so counting
/// only `p_filesz` would open a gap that is actually backed.
fn largest_inter_segment_hole(segments: &[LoadSegment]) -> Option<(u64, u64)> {
    let page = TRAMPOLINE_PAGE_SIZE;
    let mut sorted: Vec<&LoadSegment> = segments.iter().collect();
    sorted.sort_unstable_by_key(|s| s.vaddr);

    let mut best: Option<(u64, u64)> = None;
    // `mapend` must account for every earlier segment, not just the previous
    // one, so that overlapping or out-of-order segments cannot open a fake gap.
    let mut covered_to = 0u64;
    for s in sorted {
        let start = s.vaddr & !(page - 1);
        // A segment whose memsz exceeds its filesz has anonymous pages mapped
        // over the difference, so treat the whole memsz as occupied.
        let end = s
            .vaddr
            .checked_add(s.filesz.max(s.memsz))
            .and_then(|e| e.checked_next_multiple_of(page))?;
        if start > covered_to
            && covered_to != 0
            && best.is_none_or(|(b0, b1)| start - covered_to > b1 - b0)
        {
            best = Some((covered_to, start));
        }
        covered_to = covered_to.max(end);
    }
    best
}

fn find_addr_for_trampoline_code(file: &object::File<'_>) -> Result<TrampolinePlacement> {
    let object::File::Elf64(elf) = file else {
        unreachable!()
    };
    trampoline_placement_for(
        &elf_load_segments(file),
        elf.elf_header().e_machine.get(elf.endian()),
    )
}

/// Collects the `PT_LOAD` segments of `file` in program-header order.
fn elf_load_segments(file: &object::File<'_>) -> Vec<LoadSegment> {
    file.segments()
        .map(|seg| LoadSegment {
            vaddr: seg.address(),
            filesz: seg.file_range().1,
            memsz: seg.size(),
            align: seg.align(),
        })
        .collect()
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

    fn seg(vaddr: u64, filesz: u64, memsz: u64, align: u64) -> LoadSegment {
        LoadSegment {
            vaddr,
            filesz,
            memsz,
            align,
        }
    }

    /// One shared object as the guest's `ld.so` laid it out.
    struct Obj {
        name: &'static str,
        /// Address the object's first `PT_LOAD` was mapped at.
        base: u64,
        /// Size of the trampoline the rewriter appended to it.
        tramp_size: u64,
        segs: Vec<LoadSegment>,
    }

    impl Obj {
        /// The address ranges glibc actually populates for this object: each
        /// `PT_LOAD` from `align_down(p_vaddr)` to `align_up(p_vaddr + p_memsz)`.
        fn mapped_ranges(&self) -> Vec<(u64, u64)> {
            let page = TRAMPOLINE_PAGE_SIZE;
            self.segs
                .iter()
                .map(|s| {
                    (
                        self.base + (s.vaddr & !(page - 1)),
                        self.base + (s.vaddr + s.memsz).next_multiple_of(page),
                    )
                })
                .collect()
        }
    }

    /// The four objects `python3 --version` loads, with the load addresses and
    /// trampoline sizes captured from a live LiteBox run on aarch64.
    fn python_objects() -> Vec<Obj> {
        alloc::vec![
            Obj {
                name: "ld-linux-aarch64.so.1",
                base: 0xfffffff90000,
                tramp_size: 0x99c,
                segs: alloc::vec![
                    seg(0x0, 0x25b64, 0x25b64, 0x10000),
                    seg(0x3ec18, 0x2588, 0x2730, 0x10000),
                ],
            },
            Obj {
                name: "libpython3.12.so.1.0",
                base: 0xfffffef50000,
                tramp_size: 0x2200,
                segs: alloc::vec![
                    seg(0x0, 0x45ae40, 0x45ae40, 0x10000),
                    seg(0x466f10, 0x1d6170, 0x1d7520, 0x10000),
                ],
            },
            Obj {
                name: "libc.so.6",
                base: 0xfffffed40000,
                tramp_size: 0x9ddc,
                segs: alloc::vec![
                    seg(0x0, 0x18215c, 0x18215c, 0x10000),
                    seg(0x19d2b0, 0x64398, 0x70d20, 0x10000),
                ],
            },
            Obj {
                name: "libm.so.6",
                base: 0xfffffec90000,
                tramp_size: 0xb50,
                segs: alloc::vec![
                    seg(0x0, 0x8a136, 0x8a136, 0x10000),
                    seg(0x9fc80, 0x398, 0x4d0, 0x10000),
                ],
            },
        ]
    }

    /// No object's trampoline may land on a page another object has mapped.
    ///
    /// The shim maps the trampoline with `MAP_FIXED`, which over a fully
    /// covered range does not fail — it silently replaces the victim's pages,
    /// and the corruption surfaces much later somewhere unrelated.
    ///
    /// The layout is a recording of a real `python3 --version` run, in which
    /// `libc`'s trampoline overwrote 40 KiB of `libpython`'s text and `libm`'s
    /// overwrote 4 KiB of `libc`'s.
    #[test]
    fn no_trampoline_overlaps_another_objects_mapping() {
        let objects = python_objects();
        let mut collisions = Vec::new();
        for obj in &objects {
            let placement =
                trampoline_placement_for(&obj.segs, object::elf::EM_AARCH64).expect("placement");
            let tramp = (
                obj.base + placement.addr(),
                obj.base
                    + (placement.addr() + obj.tramp_size).next_multiple_of(TRAMPOLINE_PAGE_SIZE),
            );
            for victim in &objects {
                if core::ptr::eq(obj, victim) {
                    continue;
                }
                for (lo, hi) in victim.mapped_ranges() {
                    let start = tramp.0.max(lo);
                    let end = tramp.1.min(hi);
                    if start < end {
                        collisions.push(format!(
                            "{}'s trampoline [{:#x},{:#x}) overwrites {:#x} bytes of {} \
                             [{:#x},{:#x})",
                            obj.name,
                            tramp.0,
                            tramp.1,
                            end - start,
                            victim.name,
                            lo,
                            hi,
                        ));
                    }
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "trampolines silently overwrote other objects:\n  {}",
            collisions.join("\n  ")
        );
    }

    /// Placement must land inside the object's own load span — the only region
    /// the dynamic loader reserves on its behalf — with room for the trampoline.
    #[test]
    fn placement_is_inside_the_objects_own_reservation() {
        for obj in &python_objects() {
            let placement =
                trampoline_placement_for(&obj.segs, object::elf::EM_AARCH64).expect("placement");
            let span_end = obj
                .segs
                .iter()
                .map(|s| (s.vaddr + s.memsz).next_multiple_of(TRAMPOLINE_PAGE_SIZE))
                .max()
                .unwrap();
            let TrampolinePlacement::InsideLoadSpan { addr, limit, .. } = placement else {
                panic!(
                    "{}: placement {:#x} is not reserved by anything",
                    obj.name,
                    placement.addr()
                );
            };
            assert!(
                addr.saturating_add(limit) <= span_end,
                "{}: placement [{:#x},{:#x}) escapes the load span (ends {span_end:#x})",
                obj.name,
                addr,
                addr.saturating_add(limit),
            );
            assert!(
                limit >= obj.tramp_size,
                "{}: {:#x}-byte hole cannot hold a {:#x}-byte trampoline",
                obj.name,
                limit,
                obj.tramp_size,
            );
        }
    }

    /// The chosen gap must be one the guest's loader leaves alone: glibc
    /// `mprotect`s exactly `[first.mapend, last.mapstart)` to `PROT_NONE` and
    /// never maps over it. These are the ranges observed in the live trace.
    #[test]
    fn placement_matches_the_gap_glibc_protects() {
        let expected = [
            ("libpython3.12.so.1.0", 0x45b000u64, 0x466000u64),
            ("libc.so.6", 0x183000, 0x19d000),
            ("libm.so.6", 0x8b000, 0x9f000),
        ];
        for (name, lo, hi) in expected {
            let obj = python_objects()
                .into_iter()
                .find(|o| o.name == name)
                .unwrap();
            let placement =
                trampoline_placement_for(&obj.segs, object::elf::EM_AARCH64).expect("placement");
            let TrampolinePlacement::InsideLoadSpan { addr, limit, .. } = placement else {
                panic!("{name}: expected a hole inside the load span");
            };
            assert_eq!(
                (addr, addr.saturating_add(limit)),
                (lo, hi),
                "{name}: gap does not match the range glibc leaves PROT_NONE"
            );
        }
    }

    /// An object with no gap has nowhere reserved to go, so placement falls
    /// back to the address past the last segment and says so, which is what
    /// makes the shim validate it before mapping.
    #[test]
    fn contiguous_segments_fall_back_and_are_marked_unreserved() {
        let segs = [
            seg(0x0, 0x1000, 0x1000, 0x10000),
            seg(0x1000, 0x100, 0x100, 0x10000),
        ];
        let placement = trampoline_placement_for(&segs, object::elf::EM_AARCH64).unwrap();
        assert!(matches!(
            placement,
            TrampolinePlacement::PastLastSegment { .. }
        ));
    }

    #[test]
    fn aarch64_fallback_keeps_program_headers_unchanged() {
        const ELF_HEADER_BYTES: usize = 64;
        const PROGRAM_HEADER_BYTES: usize = 56;
        let mut elf = vec![0u8; ELF_HEADER_BYTES + 2 * PROGRAM_HEADER_BYTES];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = object::elf::ELFCLASS64;
        elf[5] = object::elf::ELFDATA2LSB;
        elf[18..20].copy_from_slice(&object::elf::EM_AARCH64.to_le_bytes());
        elf[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64).to_le_bytes());
        elf[54..56].copy_from_slice(&u16::try_from(PROGRAM_HEADER_BYTES).unwrap().to_le_bytes());
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());

        let text = ELF_HEADER_BYTES;
        elf[text..text + 4].copy_from_slice(&object::elf::PT_LOAD.to_le_bytes());
        elf[text + 4..text + 8]
            .copy_from_slice(&(object::elf::PF_R | object::elf::PF_X).to_le_bytes());
        elf[text + 32..text + 40].copy_from_slice(&0x180000u64.to_le_bytes());
        elf[text + 40..text + 48].copy_from_slice(&0x180000u64.to_le_bytes());
        elf[text + 48..text + 56].copy_from_slice(&0x10000u64.to_le_bytes());

        let data = text + PROGRAM_HEADER_BYTES;
        elf[data..data + 4].copy_from_slice(&object::elf::PT_LOAD.to_le_bytes());
        elf[data + 4..data + 8]
            .copy_from_slice(&(object::elf::PF_R | object::elf::PF_W).to_le_bytes());
        elf[data + 8..data + 16].copy_from_slice(&0x18d2b0u64.to_le_bytes());
        elf[data + 16..data + 24].copy_from_slice(&0x19d2b0u64.to_le_bytes());
        elf[data + 40..data + 48].copy_from_slice(&0x70d20u64.to_le_bytes());
        elf[data + 48..data + 56].copy_from_slice(&0x10000u64.to_le_bytes());
        let phdrs_before = elf[ELF_HEADER_BYTES..].to_vec();
        let code_offset = elf.len();
        elf.extend((0..1025).flat_map(|_| 0xD400_0001u32.to_le_bytes()));
        let input = elf.clone();
        let section = TextSectionInfo {
            vaddr: 0x1000,
            file_offset: code_offset as u64,
            size: (elf.len() - code_offset) as u64,
        };
        let out = hook_aarch64_elf_at(
            &input,
            &mut elf,
            aarch64::ScanSections {
                executable: &[section],
                code: &[section],
            },
            0x220000,
            None,
            0,
            RewriteOptions::default(),
        )
        .unwrap();

        assert_eq!(
            &out[ELF_HEADER_BYTES..ELF_HEADER_BYTES + phdrs_before.len()],
            phdrs_before,
            "fixed slots must not modify program headers"
        );
    }

    /// A minimal AArch64 object whose text is a single `SVC #0` at `0x1000`.
    fn aarch64_elf_with_one_svc() -> Vec<u8> {
        const ELF_HEADER_BYTES: usize = 64;
        const PROGRAM_HEADER_BYTES: usize = 56;
        let mut elf = vec![0u8; ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = object::elf::ELFCLASS64;
        elf[5] = object::elf::ELFDATA2LSB;
        elf[6] = object::elf::EV_CURRENT;
        elf[16..18].copy_from_slice(&object::elf::ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&object::elf::EM_AARCH64.to_le_bytes());
        elf[20..24].copy_from_slice(&u32::from(object::elf::EV_CURRENT).to_le_bytes());
        elf[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64).to_le_bytes());
        elf[52..54].copy_from_slice(&u16::try_from(ELF_HEADER_BYTES).unwrap().to_le_bytes());
        elf[54..56].copy_from_slice(&u16::try_from(PROGRAM_HEADER_BYTES).unwrap().to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());

        let text = ELF_HEADER_BYTES;
        elf[text..text + 4].copy_from_slice(&object::elf::PT_LOAD.to_le_bytes());
        elf[text + 4..text + 8]
            .copy_from_slice(&(object::elf::PF_R | object::elf::PF_X).to_le_bytes());
        elf[text + 8..text + 16]
            .copy_from_slice(&((ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES) as u64).to_le_bytes());
        elf[text + 16..text + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[text + 32..text + 40].copy_from_slice(&4u64.to_le_bytes());
        elf[text + 40..text + 48].copy_from_slice(&4u64.to_le_bytes());
        elf[text + 48..text + 56].copy_from_slice(&0x10000u64.to_le_bytes());

        elf.extend(0xD400_0001u32.to_le_bytes());
        elf
    }

    /// A gap the gates cannot branch back from is retried at the fallback
    /// address rather than failing the whole binary.
    #[test]
    fn an_out_of_branch_range_gap_falls_back_instead_of_rejecting() {
        /// Comfortably past a `B`'s +-128MiB reach from the text at 0x1000.
        const UNREACHABLE_GAP: u64 = 0x2000_0000;

        let mut elf = aarch64_elf_with_one_svc();
        let input = elf.clone();
        let text_file_offset = (elf.len() - 4) as u64;
        let section = || TextSectionInfo {
            vaddr: 0x1000,
            file_offset: text_file_offset,
            size: 4,
        };

        // The gap alone cannot work: every site is out of range and trapped.
        let mut direct = elf.clone();
        assert!(
            matches!(
                hook_aarch64_elf_at(
                    &input,
                    &mut direct,
                    aarch64::ScanSections {
                        executable: &[section()],
                        code: &[section()],
                    },
                    UNREACHABLE_GAP,
                    None,
                    0,
                    RewriteOptions::default(),
                ),
                Err(Error::UnpatchableSyscalls(_))
            ),
            "the gap has to be genuinely unreachable for this test to mean anything"
        );

        // Offered the same gap plus a reachable fallback, rewriting succeeds.
        let placement = TrampolinePlacement::InsideLoadSpan {
            addr: UNREACHABLE_GAP,
            limit: 0x10000,
            fallback_addr: 0x20000,
        };
        hook_aarch64_elf(
            &input,
            &mut elf,
            aarch64::ScanSections {
                executable: &[section()],
                code: &[section()],
            },
            placement,
            0,
            RewriteOptions::default(),
        )
        .expect("the reachable fallback address must be retried");
    }

    /// x86-64 placement is deliberately unchanged; see `trampoline_addr_for`.
    #[test]
    fn placement_leaves_x86_64_alone() {
        for obj in &python_objects() {
            let placement =
                trampoline_placement_for(&obj.segs, object::elf::EM_X86_64).expect("placement");
            assert!(matches!(
                placement,
                TrampolinePlacement::PastLastSegment { .. }
            ));
        }
    }

    /// With page-sized segment alignment (the x86-64 case) the trampoline goes
    /// in the first page past the last `PT_LOAD`, unchanged from before.
    #[test]
    fn trampoline_addr_page_aligned_segments_use_next_page() {
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x1000, object::elf::EM_AARCH64).unwrap(),
            0x20e_000
        );
        assert_eq!(
            trampoline_addr_for(0x20e_000, 0x1000, object::elf::EM_AARCH64).unwrap(),
            0x20e_000
        );
        // A `p_align` below the page size must not pull the address down.
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x1, object::elf::EM_AARCH64).unwrap(),
            0x20e_000
        );
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0, object::elf::EM_AARCH64).unwrap(),
            0x20e_000
        );
    }

    /// With 64 KiB segment alignment (the aarch64 case) the trampoline must
    /// clear the whole `maplength + p_align` region glibc's `_dl_map_segment`
    /// reserves while mapping the object, otherwise the shim's `MAP_FIXED`
    /// straddles the reservation boundary and the load fails.
    #[test]
    fn trampoline_addr_skips_loader_alignment_slack() {
        // Real values from aarch64 `libc.so.6`: last PT_LOAD ends at 0x20dfd0.
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x10000, object::elf::EM_AARCH64).unwrap(),
            0x220_000
        );
        // Exactly on an alignment boundary still skips a full unit, because the
        // loader's reservation runs to `end + p_align`.
        assert_eq!(
            trampoline_addr_for(0x210_000, 0x10000, object::elf::EM_AARCH64).unwrap(),
            0x220_000
        );
    }

    /// A non-power-of-two `p_align` is bogus; fall back to the page size rather
    /// than corrupting the mask arithmetic.
    #[test]
    fn trampoline_addr_rejects_non_power_of_two_align() {
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x3000, object::elf::EM_AARCH64).unwrap(),
            0x20e_000
        );
    }

    /// The slow-path rule is gated on `EM_AARCH64`, not on the host arch. GNU
    /// ld's default max-page-size on x86-64 is 0x200000, so x86-64 objects
    /// routinely have a `p_align` above the page size, but their placement must
    /// not move: any change to this address changes which programs collide.
    /// This also covers cross-rewriting an x86-64 binary from an aarch64 host,
    /// where `cfg(target_arch)` would be the wrong test.
    #[test]
    fn trampoline_addr_slow_path_rule_is_aarch64_only() {
        // 2 MiB alignment, the x86-64 default: keeps the old next-page rule.
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x200000, object::elf::EM_X86_64).unwrap(),
            0x20e_000
        );
        // The identical object as aarch64 does skip an alignment unit.
        assert_eq!(
            trampoline_addr_for(0x20d_fd0, 0x200000, object::elf::EM_AARCH64).unwrap(),
            0x600_000
        );
    }

    #[test]
    fn trampoline_addr_reports_overflow() {
        assert!(trampoline_addr_for(u64::MAX - 1, 0x10000, object::elf::EM_AARCH64).is_err());
    }

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
        let placement = TrampolinePlacement::PastLastSegment { addr: 0x1000_0000 };
        let err = hook_aarch64_elf(
            &input,
            &mut buf,
            aarch64::ScanSections {
                executable: &sections,
                code: &sections,
            },
            placement,
            0,
            RewriteOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::UnpatchableSyscalls(_)),
            "expected UnpatchableSyscalls, got {err:?}"
        );
    }

    /// The runtime (mmap-time) AArch64 entry point: a bare code region with no
    /// ELF around it still gets its `SVC` redirected into a gate, and the blob
    /// is self-describing — its own callback slot at offset 0.
    #[test]
    fn aarch64_runtime_patch_redirects_svc_into_an_emitted_gate() {
        let mut code = 0xD400_0001u32.to_le_bytes().to_vec(); // SVC #0
        let code_vaddr = 0x1000_0000;
        let trampoline_vaddr = 0x1000_1000;
        let syscall_entry_addr = 0x1000_0000_0000;

        let (trampoline, trapped) = patch_aarch64_code_segment(
            &mut code,
            code_vaddr,
            trampoline_vaddr,
            syscall_entry_addr,
            RewriteOptions::default(),
        )
        .unwrap();

        assert!(
            trapped.is_empty(),
            "a nearby trampoline should be reachable"
        );
        assert!(!trampoline.is_empty(), "runtime patching emits a blob");
        assert_eq!(
            u64::from_le_bytes(trampoline[..8].try_into().unwrap()),
            syscall_entry_addr,
            "the blob's callback slot holds the runtime's syscall entry directly"
        );

        let branch = u32::from_le_bytes(code[..4].try_into().unwrap());
        assert_eq!(branch & 0xFC00_0000, 0x1400_0000, "the SVC becomes a B");
        let imm26 = i64::from(branch & 0x03FF_FFFF);
        let disp = ((imm26 << 38) >> 38) << 2;
        assert_eq!(
            code_vaddr.wrapping_add(disp.cast_unsigned()),
            trampoline_vaddr + 16,
            "the B targets the first aligned gate slot"
        );
    }

    /// A region with no patch sites must not produce a trampoline: the caller
    /// would otherwise map and charge a page for nothing, and — on the shim's
    /// runtime path — advance its trampoline cursor past a blob no code
    /// branches to.
    #[test]
    fn aarch64_runtime_patch_of_syscall_free_code_emits_nothing() {
        let mut code = 0xD503_201Fu32.to_le_bytes().to_vec(); // NOP
        let before = code.clone();
        let (trampoline, trapped) = patch_aarch64_code_segment(
            &mut code,
            0x1000,
            0x2000,
            0x3000,
            RewriteOptions::default(),
        )
        .unwrap();
        assert!(trampoline.is_empty());
        assert!(trapped.is_empty());
        assert_eq!(code, before, "syscall-free code is left untouched");
    }

    /// The runtime path emits the same thread-pointer placeholder the
    /// ahead-of-time path does, so the shim's loader-side finalization applies
    /// unchanged. Asserted rather than assumed, because if it stopped holding
    /// the gates would redirect the guest's thread pointer into host memory
    /// *without faulting*.
    #[test]
    fn aarch64_runtime_gates_carry_the_thread_pointer_placeholder() {
        // MRS X0, TPIDR_EL0 — a thread-pointer read, which is gated.
        let mut code = 0xD53B_D040u32.to_le_bytes().to_vec();
        let (mut trampoline, trapped) = patch_aarch64_code_segment(
            &mut code,
            0x1000,
            0x2000,
            0x3000,
            RewriteOptions::default(),
        )
        .unwrap();
        assert!(trapped.is_empty());
        assert!(
            aarch64::find_guest_tpidr_placeholder(&trampoline).is_some(),
            "a runtime-emitted thread-pointer gate must arrive unpatched"
        );
        assert_eq!(
            aarch64::patch_guest_tpidr_offset(&mut trampoline, 96).unwrap(),
            1
        );
        assert!(aarch64::find_guest_tpidr_placeholder(&trampoline).is_none());
    }

    #[test]
    fn aarch64_runtime_and_aot_emit_identical_slots() {
        let words = [0xD400_0001, 0xD53B_D040 | 9, 0xD51B_D040 | 5];
        let mut runtime_code = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut aot_code = runtime_code.clone();
        let code_vaddr = 0x1000;
        let trampoline_vaddr = 0x400000;

        let (runtime, skipped) = patch_aarch64_code_segment(
            &mut runtime_code,
            code_vaddr,
            trampoline_vaddr,
            0x1234,
            RewriteOptions::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        let section = TextSectionInfo {
            vaddr: code_vaddr,
            file_offset: 0,
            size: aot_code.len() as u64,
        };
        let aot = aarch64::hook_syscalls_aarch64(
            &mut aot_code,
            &[section],
            trampoline_vaddr,
            0x1234,
            aarch64::RewriteConfig::new(TargetHost::Linux, false),
        )
        .unwrap()
        .unwrap();

        assert_eq!(runtime_code, aot_code);
        assert_eq!(runtime, aot.trampoline);

        // Exercise the compact classifier independently on both products, not
        // only equality of their bytes. The three sites emit SVC, MRS, then MSR
        // slots at fixed aligned starts after the 16-byte trampoline header.
        let boundaries = [
            (16usize, 12usize), // 9 inbound SVC + 3 outbound-stub instructions.
            (80, 3),
            (96, 9),
        ];
        let mut classified = 0;
        for product in [&runtime, &aot.trampoline] {
            for (slot_offset, count) in boundaries {
                for instruction in 0..count {
                    let pc = trampoline_vaddr + (slot_offset + instruction * 4) as u64;
                    let gate = aarch64::classify_gate_pc(product, trampoline_vaddr, pc)
                        .unwrap_or_else(|| panic!("slot {slot_offset} boundary {instruction}"));
                    assert_eq!(gate.slot_offset(), slot_offset);
                    classified += 1;
                }
            }
        }
        assert_eq!(classified, 48, "24 boundaries in each emission path");
    }

    /// The fail-safe: when no trampoline can be placed, every site the hooking
    /// pass would have redirected becomes a `BRK`. A site left native escapes
    /// directly to the host kernel, so "found nothing, trapped nothing" is not
    /// an acceptable outcome.
    #[test]
    fn aarch64_trap_fallback_traps_every_patch_site() {
        let mut code = Vec::new();
        code.extend_from_slice(&0xD400_0001u32.to_le_bytes()); // SVC #0
        code.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        code.extend_from_slice(&0xD51B_D040u32.to_le_bytes()); // MSR TPIDR_EL0, X0
        code.extend_from_slice(&0xD53B_D041u32.to_le_bytes()); // MRS X1, TPIDR_EL0

        let count =
            trap_all_aarch64_patch_sites(&mut code, 0x1000, RewriteOptions::default()).unwrap();

        assert_eq!(count, 3, "SVC and both thread-pointer accesses are sites");
        for (index, word) in code.as_chunks::<4>().0.iter().enumerate() {
            let insn = u32::from_le_bytes(*word);
            if index == 1 {
                assert_eq!(insn, 0xD503_201F, "the NOP is not a patch site");
            } else {
                assert_eq!(insn & 0xFFE0_001F, 0xD420_0000, "site {index} becomes BRK");
            }
        }
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
