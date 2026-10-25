// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 patch-site discovery and rewrite orchestration.
//!
//! Discovers sites, supplies parameters to the shared builder and installs
//! inbound branches. The gate ABI, validation and recovery are defined in
//! [`litebox_trampoline::aarch64`].
//!
//! # Patch-site selection
//!
//! Scans executable ranges at four-byte boundaries for SVC/TPIDR_EL0 encodings.
//! Linux accepts any SVC immediate; `MRS XZR, TPIDR_EL0` reads stay native.
//! Darwin rewriting handles `SVC #0x80` and TPIDRRO_EL0 reads.
//!
//! x18 rewriting uses identified code ranges from object metadata or the caller;
//! Linux enables it only on request. Unsupported forms reject AOT rewriting or
//! become runtime-rewriting traps.
//!
//! Executable inline data can still resemble mandatory SVC/TP instructions.
//! Lexical exclusive-load/store tracking rejects x18 gates inside recognized
//! reservation sequences; it does not analyze noncontiguous control flow.
//!
//! # Placement and publication
//!
//! `B imm26` reaches ±128 MiB. Unreachable inbound/return branches produce
//! breakpoints reported in `HookOutcome::trapped_sites`, rather than leaving
//! native syscalls or TLS accesses unpatched.
//!
//! ELF AOT output leaves callback/TLS fields for the loader to finalize before
//! execution; images without patch sites get a zero-size footer. Mach-O runtime
//! [`crate::macho::Rewriter::patch_code_segment`] returns finalized gates.

use crate::{
    Error, InternalError, Result, TextSectionInfo, checked_add_u64, fixup_phdr_alignment,
    text_sections,
};
use alloc::format;
use alloc::string::ToString as _;
use alloc::vec::Vec;
use core::ops::Range;
use litebox_trampoline::TargetHost;
use litebox_trampoline::aarch64::{
    DARWIN_SVC, ExclusiveBoundary, GATE_ALIGNMENT, GATES_START_OFFSET, GateLayout, GateMetadata,
    INSN_BYTES, INSN_BYTES_U64, Insn, MAX_GATE_SLOT_BYTES, MRS_TPIDR_EL0_BITS, MRS_TPIDR_EL0_MASK,
    MSR_TPIDR_EL0_BITS, MSR_TPIDR_EL0_MASK, Opcode, REG_MASK, SVC_OPCODE_BITS, SVC_OPCODE_MASK,
    TRAP_BRK_IMM, X18, X18Adr, X18Classification, X18CompareBranch, X18IndirectBranchKind,
    X18StackWriteback, X18TransformResult, X18Unsupported, XZR, classify_adr_x18,
    classify_pc_relative_x18, classify_x18, classify_x18_conditional_branch,
    classify_x18_stack_writeback, emit_shared_prologue, exclusive_boundary, gate, sve,
};
use object::read::{Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _};
use zerocopy::IntoBytes as _;

#[derive(Clone, Copy)]
pub(crate) struct ScanSections<'a> {
    pub(crate) executable: &'a [TextSectionInfo],
    pub(crate) code: &'a [TextSectionInfo],
}

/// Mapping-relative ranges used by AArch64 patch-site scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeScanRanges {
    pub(crate) executable: Vec<Range<usize>>,
    pub(crate) identified: Vec<Range<usize>>,
}

impl CodeScanRanges {
    /// Mapping-relative executable ranges.
    pub fn executable(&self) -> &[Range<usize>] {
        &self.executable
    }

    /// Mapping-relative ranges positively identified as code.
    pub fn identified(&self) -> &[Range<usize>] {
        &self.identified
    }
}

/// Owned AArch64 ELF code metadata, independent of the parsed ELF buffer.
pub struct ElfCodeMetadata {
    pub(crate) executable: Vec<TextSectionInfo>,
    pub(crate) identified: Vec<TextSectionInfo>,
}

impl ElfCodeMetadata {
    /// Parse an ELF image in aligned storage, relocating an unaligned program
    /// header table within that storage if required by the object parser.
    pub fn parse_aligned_in_place(aligned: &mut [u64], byte_len: usize) -> Result<Self> {
        let bytes = aligned.as_mut_bytes();
        if byte_len > bytes.len() {
            return Err(Error::ParseError(
                "aligned ELF byte length exceeds storage".into(),
            ));
        }
        fixup_phdr_alignment(&mut bytes[..byte_len])?;
        let file = object::File::parse(&bytes[..byte_len])
            .map_err(|error| Error::ParseError(error.to_string()))?;
        if file.architecture() != object::Architecture::Aarch64 {
            return Err(Error::UnsupportedExecutable(
                "code metadata requires an AArch64 ELF".into(),
            ));
        }
        match elf_code_metadata(&file) {
            Ok(metadata) => Ok(metadata),
            Err(InternalError::Public(error)) => Err(error),
            Err(InternalError::NoTextSectionFound) => Err(Error::UnsupportedExecutable(
                "AArch64 ELF has no executable code ranges".into(),
            )),
            Err(error) => unreachable!("unexpected metadata error: {error:?}"),
        }
    }

    /// Project ELF file ranges into one file-backed mapping.
    pub fn ranges_for_mapping(
        &self,
        file_offset: u64,
        mapping_len: usize,
    ) -> Result<CodeScanRanges> {
        Ok(CodeScanRanges {
            executable: project_file_ranges(&self.executable, file_offset, mapping_len)?,
            identified: project_file_ranges(&self.identified, file_offset, mapping_len)?,
        })
    }

    /// Bounds gates at this ELF's file addresses. Remapping, load bias, or
    /// runtime rescans may still require growth.
    pub fn trampoline_size_upper_bound(
        &self,
        elf: &[u8],
        options: crate::RewriteOptions,
    ) -> Result<usize> {
        let sites = find_patch_sites_with_code_ranges(
            &self.executable,
            &self.identified,
            elf,
            RewriteConfig::new(options.target_host(), options.virtualizes_x18()),
        )?;
        sites.into_iter().try_fold(0usize, |total, site| {
            let gate_bytes = site.kind.metadata().map_or(0, |metadata| {
                metadata.slot_size_for_host(options.target_host())
            });
            // One prologue per site covers separate mapping batches.
            total
                .checked_add(GATES_START_OFFSET)
                .and_then(|total| total.checked_add(gate_bytes))
                .ok_or_else(|| Error::AddressOverflow("AArch64 trampoline size".into()))
        })
    }

    /// Total executable and identified-code bytes represented by this metadata.
    pub fn coverage_bytes(&self) -> (u64, u64) {
        let total = |ranges: &[TextSectionInfo]| {
            ranges
                .iter()
                .fold(0u64, |total, range| total.saturating_add(range.size))
        };
        (total(&self.executable), total(&self.identified))
    }
}

pub(crate) fn elf_code_metadata(
    file: &object::File<'_>,
) -> core::result::Result<ElfCodeMetadata, InternalError> {
    // Stripped ELFs may expose code only through executable PT_LOAD segments.
    let executable = match text_sections(file) {
        Ok(sections) => sections,
        Err(InternalError::NoTextSectionFound) => executable_segments(file)?,
        Err(error) => return Err(error),
    };
    let identified = code_sections(file, &executable);
    Ok(ElfCodeMetadata {
        executable,
        identified,
    })
}

fn executable_segments(
    file: &object::File<'_>,
) -> core::result::Result<Vec<TextSectionInfo>, InternalError> {
    let executable = file
        .segments()
        .filter_map(|segment| {
            let object::SegmentFlags::Elf { p_flags } = segment.flags() else {
                return None;
            };
            if p_flags & object::elf::PF_X == 0 {
                return None;
            }
            let (file_offset, size) = segment.file_range();
            (size != 0).then_some(TextSectionInfo {
                vaddr: segment.address(),
                file_offset,
                size,
            })
        })
        .collect::<Vec<_>>();
    if executable.is_empty() {
        return Err(InternalError::NoTextSectionFound);
    }
    Ok(executable)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the crate requires 64-bit pointers"
)]
pub(crate) fn project_file_ranges(
    ranges: &[TextSectionInfo],
    mapping_file_offset: u64,
    mapping_len: usize,
) -> Result<Vec<Range<usize>>> {
    let mapping_end = mapping_file_offset
        .checked_add(mapping_len as u64)
        .ok_or_else(|| Error::AddressOverflow("mapping file range".into()))?;
    let mut projected = Vec::new();
    for range in ranges {
        let range_end = range
            .file_offset
            .checked_add(range.size)
            .ok_or_else(|| Error::AddressOverflow("ELF code file range".into()))?;
        let start = range.file_offset.max(mapping_file_offset);
        let end = range_end.min(mapping_end);
        if start < end {
            projected
                .push((start - mapping_file_offset) as usize..(end - mapping_file_offset) as usize);
        }
    }
    Ok(projected)
}

/// Builds ranges where metadata positively identifies AArch64 code. Executable
/// bytes outside these ranges remain eligible for exact mandatory-site scans,
/// but not heuristic x18 classification.
fn code_sections(file: &object::File<'_>, executable: &[TextSectionInfo]) -> Vec<TextSectionInfo> {
    let mut ranges = Vec::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.kind() == object::SymbolKind::Text
            && symbol.size() != 0
            && let Some(end) = symbol.address().checked_add(symbol.size())
        {
            ranges.push((symbol.address(), end));
        }
    }

    if let Some(section) = file.section_by_name(".eh_frame")
        && let Ok(data) = section.uncompressed_data()
    {
        ranges.extend(eh_frame_ranges(
            &data,
            section.address(),
            file.section_by_name(".text").map(|text| text.address()),
            file.section_by_name(".got").map(|got| got.address()),
        ));
    }

    let has_function_metadata = !ranges_to_sections(ranges.clone(), executable).is_empty();
    if !has_function_metadata {
        return executable.to_vec();
    }

    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if (matches!(name, ".init" | ".fini" | ".plt" | ".iplt") || name.starts_with(".plt."))
            && let Some(end) = section.address().checked_add(section.size())
        {
            ranges.push((section.address(), end));
        }
    }

    ranges_to_sections(ranges, executable)
}

fn eh_frame_ranges(
    data: &[u8],
    eh_frame_address: u64,
    text_address: Option<u64>,
    got_address: Option<u64>,
) -> Vec<(u64, u64)> {
    let mut section = gimli::EhFrame::new(data, gimli::LittleEndian);
    section.set_address_size(8);
    let mut bases = gimli::BaseAddresses::default().set_eh_frame(eh_frame_address);
    if let Some(text_address) = text_address {
        bases = bases.set_text(text_address);
    }
    if let Some(got_address) = got_address {
        bases = bases.set_got(got_address);
    }
    let mut entries = gimli::UnwindSection::entries(&section, &bases);
    let mut ranges = Vec::new();
    loop {
        let Ok(Some(entry)) = entries.next() else {
            return ranges;
        };
        if let gimli::CieOrFde::Fde(partial) = entry {
            let Ok(fde) = partial.parse(gimli::UnwindSection::cie_from_offset) else {
                continue;
            };
            if fde.len() != 0
                && let Some(end) = fde.initial_address().checked_add(fde.len())
            {
                ranges.push((fde.initial_address(), end));
            }
        }
    }
}

fn ranges_to_sections(
    ranges: Vec<(u64, u64)>,
    executable: &[TextSectionInfo],
) -> Vec<TextSectionInfo> {
    let mut clipped = Vec::new();
    for (start, end) in ranges {
        for section in executable {
            let section_end = section.vaddr.saturating_add(section.size);
            let start = start
                .max(section.vaddr)
                .checked_add(3)
                .map_or(u64::MAX, |start| start & !3);
            let end = end.min(section_end) & !3;
            if start < end {
                clipped.push((start, end, section));
            }
        }
    }
    clipped.sort_unstable_by_key(|(start, _, _)| *start);

    let mut code: Vec<TextSectionInfo> = Vec::new();
    for (start, end, section) in clipped {
        if let Some(previous) = code.last_mut()
            && start >= previous.vaddr
            && previous.vaddr.saturating_add(previous.size) >= start
            && previous.file_offset.saturating_add(start - previous.vaddr)
                == section.file_offset.saturating_add(start - section.vaddr)
        {
            previous.size = end
                .max(previous.vaddr.saturating_add(previous.size))
                .saturating_sub(previous.vaddr);
            continue;
        }
        code.push(TextSectionInfo {
            vaddr: start,
            file_offset: section
                .file_offset
                .saturating_add(start.saturating_sub(section.vaddr)),
            size: end - start,
        });
    }
    code
}

#[derive(Clone, Copy)]
pub(crate) struct RewriteConfig {
    host: TargetHost,
    virtualize_x18: bool,
    /// The vaddr of the word that a `MOVPRFX` right before the scanned code
    /// prefixes, if there is one.
    movprfx_prefixed_vaddr: Option<u64>,
}

impl RewriteConfig {
    pub(crate) fn new(target: litebox_trampoline::TargetHost, virtualize_x18: bool) -> Self {
        Self {
            host: target,
            virtualize_x18,
            movprfx_prefixed_vaddr: None,
        }
    }

    /// The configuration of a runtime scan of the code at `code_vaddr`.
    pub(crate) fn runtime(options: crate::RewriteOptions, code_vaddr: u64) -> Self {
        Self {
            movprfx_prefixed_vaddr: options
                .preceding_word
                .is_some_and(sve::is_movprfx)
                .then_some(code_vaddr),
            ..Self::new(options.target_host(), options.virtualizes_x18())
        }
    }
}

/// A located instruction to rewrite.
struct PatchSite {
    /// Byte offset of the instruction within the code buffer.
    file_offset: usize,
    /// Virtual address of the instruction.
    vaddr: u64,
    kind: PatchKind,
}

/// The kind of instruction at a [`PatchSite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchKind {
    /// `SVC #imm` for any immediate. Linux dispatches every `SVC64` to the
    /// syscall handler regardless of the immediate (the number comes from `x8`),
    /// so the immediate is not significant and is not recorded.
    Svc,
    /// `MSR TPIDR_EL0, Xt`; the `u8` is the source register (0-31).
    MsrTpidr(u8),
    /// Guest thread-pointer read; the `u8` is the destination register (0-30).
    MrsTpidr(u8),
    /// An x18 use detected under explicit virtualization.
    X18(X18TransformResult),
    /// Immediate SP-based pair operation whose native instruction writes SP.
    X18StackWriteback(X18StackWriteback),
    /// A compare/test branch (`CBZ`/`CBNZ`/`TBZ`/`TBNZ`) on logical x18.
    X18CompareBranch(X18CompareBranch),
    /// An `ADR X18` with its original absolute target.
    X18Adr(X18Adr),
    /// A terminal indirect branch through logical x18.
    X18Branch(X18IndirectBranchKind),
}

impl PatchKind {
    fn metadata(self) -> Option<GateMetadata> {
        Some(match self {
            Self::Svc => GateMetadata::Svc,
            Self::MsrTpidr(source) => GateMetadata::MsrTpidr { source },
            Self::MrsTpidr(destination) => GateMetadata::MrsTpidr { destination },
            Self::X18(X18TransformResult::Supported(transform)) => GateMetadata::X18 {
                scratch: transform.scratch,
            },
            Self::X18(X18TransformResult::Unsupported(_)) => return None,
            Self::X18StackWriteback(pair) => GateMetadata::X18StackWriteback {
                scratch: pair.scratch,
            },
            Self::X18CompareBranch(branch) => GateMetadata::X18CompareBranch {
                scratch: branch.scratch,
            },
            Self::X18Adr(adr) => GateMetadata::X18Adr {
                scratch: adr.scratch,
            },
            Self::X18Branch(kind) => GateMetadata::X18Branch { kind },
        })
    }
}

/// Scans executable sections for Linux syscall/thread-pointer gates and, when
/// configured, x18 gates. Linux-specific sites are still rejected for Windows;
/// x18 sites inside lexical exclusive sequences are rejected. Sections are
/// scanned in virtual-address order, so sites are returned in ascending vaddr
/// order.
///
/// `MRS XZR, TPIDR_EL0` is a discarded read (register 31 as an `LDR` base would
/// mean `SP`), so it is left native; every other `MRS Xd, TPIDR_EL0` is gated.
#[cfg(test)]
fn find_patch_sites(
    sections: &[TextSectionInfo],
    buf: &[u8],
    config: RewriteConfig,
) -> Result<Vec<PatchSite>> {
    find_patch_sites_with_code_ranges(sections, sections, buf, config)
}

fn find_patch_sites_with_code_ranges(
    executable_sections: &[TextSectionInfo],
    code_sections: &[TextSectionInfo],
    buf: &[u8],
    config: RewriteConfig,
) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();
    // Section headers need not be sorted; both lists are walked in vaddr order.
    let mut executable_sections = executable_sections.to_vec();
    executable_sections.sort_by_key(|section| section.vaddr);
    let mut code_sections = code_sections.to_vec();
    code_sections.sort_by_key(|section| section.vaddr);
    // MOVPRFX prefixes the next word in execution order, so it carries into a
    // section that starts at the previous section's end vaddr, and from the
    // word before a runtime scan's code into its start.
    let mut previous_end = config.movprfx_prefixed_vaddr;
    let mut was_movprfx = previous_end.is_some();

    for section in &executable_sections {
        if previous_end != Some(section.vaddr) {
            was_movprfx = false;
        }
        previous_end = Some(section.vaddr.saturating_add(section.size));
        let start = usize::try_from(section.file_offset)
            .map_err(|_| Error::ParseError("section file offset too large".into()))?;
        let size = usize::try_from(section.size)
            .map_err(|_| Error::ParseError("section size too large".into()))?;
        let end = start
            .checked_add(size)
            .filter(|&e| e <= buf.len())
            .ok_or_else(|| Error::ParseError("section extends beyond file".into()))?;
        // The scan decodes fixed-width words at 4-byte strides from both the
        // file offset and the vaddr, so a section misaligned in either would
        // make every decoded word straddle two instructions and be silently
        // misinterpreted. Refuse instead: no conforming AArch64 object has one.
        if !section.file_offset.is_multiple_of(INSN_BYTES_U64)
            || !section.vaddr.is_multiple_of(INSN_BYTES_U64)
        {
            return Err(Error::ParseError(
                "AArch64 executable section is not 4-byte aligned".into(),
            ));
        }
        let section_data = &buf[start..end];
        let mut inside_exclusive_sequence = false;
        let mut was_known_code = false;
        let mut code_index = 0;

        for i in (0..section_data.len()).step_by(INSN_BYTES) {
            if i + INSN_BYTES > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + INSN_BYTES].try_into().unwrap());
            let vaddr = checked_add_u64(section.vaddr, i as u64, "patch site")?;
            // Without x18 virtualization, only these encodings are patch sites.
            // Code-range and exclusive-sequence tracking only qualifies x18
            // sites, so skip other words before doing that bookkeeping.
            if !config.virtualize_x18
                && (insn & SVC_OPCODE_MASK) != SVC_OPCODE_BITS
                && (insn & MSR_TPIDR_EL0_MASK) != MSR_TPIDR_EL0_BITS
                && (insn & MRS_TPIDR_EL0_MASK) != MRS_TPIDR_EL0_BITS
            {
                continue;
            }
            while code_index < code_sections.len()
                && code_sections[code_index]
                    .vaddr
                    .saturating_add(code_sections[code_index].size)
                    <= vaddr
            {
                code_index += 1;
            }
            let known_code = code_sections.get(code_index).is_some_and(|code| {
                vaddr >= code.vaddr && vaddr < code.vaddr.saturating_add(code.size)
            });
            if !known_code || !was_known_code {
                inside_exclusive_sequence = false;
            }
            if known_code {
                let exclusive_boundary = exclusive_boundary(insn);
                if exclusive_boundary == Some(ExclusiveBoundary::Load) {
                    inside_exclusive_sequence = true;
                } else if exclusive_boundary == Some(ExclusiveBoundary::Store) {
                    inside_exclusive_sequence = false;
                }
            }
            was_known_code = known_code;
            let follows_movprfx = core::mem::replace(&mut was_movprfx, sve::is_movprfx(insn));
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                if config.host == TargetHost::Windows {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 SVC site is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "SVC site")?
                    )));
                }
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                if config.host == TargetHost::Windows {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 TPIDR_EL0 write is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "TPIDR site")?
                    )));
                }
                let source = (insn & REG_MASK) as u8;
                if config.virtualize_x18 && u16::from(source) == X18 {
                    PatchKind::X18(X18TransformResult::Unsupported(
                        X18Unsupported::EncodingLayout,
                    ))
                } else {
                    PatchKind::MsrTpidr(source)
                }
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                if config.host == TargetHost::Windows {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 TPIDR_EL0 read is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "TPIDR site")?
                    )));
                }
                let rd = (insn & REG_MASK) as u8;
                // `MRS XZR, TPIDR_EL0` discards its result (a no-op read); gating
                // it would mean using register 31 as an `LDR` base (= SP), so
                // leave it native.
                if rd == XZR {
                    continue;
                }
                if config.virtualize_x18 && u16::from(rd) == X18 {
                    PatchKind::X18(X18TransformResult::Unsupported(
                        X18Unsupported::EncodingLayout,
                    ))
                } else {
                    PatchKind::MrsTpidr(rd)
                }
            } else if config.virtualize_x18 && known_code {
                if let Some(pair) = classify_x18_stack_writeback(insn) {
                    PatchKind::X18StackWriteback(pair)
                } else if let Some(branch) = classify_x18_conditional_branch(insn, vaddr) {
                    PatchKind::X18CompareBranch(branch)
                } else if let Some(adr) = classify_adr_x18(insn, vaddr) {
                    PatchKind::X18Adr(adr)
                } else if let Some(transformation) = classify_pc_relative_x18(insn, vaddr) {
                    PatchKind::X18(X18TransformResult::Supported(transformation))
                } else {
                    match classify_x18(insn) {
                        X18Classification::None => continue,
                        X18Classification::Branch(branch) => PatchKind::X18Branch(branch),
                        X18Classification::X18(result) => PatchKind::X18(result),
                    }
                }
            } else {
                continue;
            };
            let x18_site = matches!(
                kind,
                PatchKind::X18(_)
                    | PatchKind::X18StackWriteback(_)
                    | PatchKind::X18CompareBranch(_)
                    | PatchKind::X18Adr(_)
                    | PatchKind::X18Branch(_)
            );
            if inside_exclusive_sequence && x18_site {
                return Err(Error::UnsupportedExecutable(format!(
                    "AArch64 gate inside exclusive sequence at {:#x}",
                    checked_add_u64(section.vaddr, i as u64, "exclusive sequence gate")?
                )));
            }
            let kind = if follows_movprfx && x18_site {
                PatchKind::X18(X18TransformResult::Unsupported(
                    X18Unsupported::MovprfxSuccessor,
                ))
            } else {
                kind
            };
            sites.push(PatchSite {
                file_offset: start + i,
                vaddr,
                kind,
            });
        }
    }

    Ok(sites)
}

/// Outcome of rewriting one AArch64 image's patch sites.
pub(crate) struct HookOutcome {
    /// Emitted gates, including the callback header.
    pub trampoline: Vec<u8>,
    /// Virtual addresses of patch sites replaced with a trap instead of a
    /// redirect, because the inbound `B` or one of the gate's own branches fell
    /// outside ±128MB. A non-empty list means the rewrite is incomplete: those
    /// sites fault at runtime rather than entering the trampoline.
    pub trapped_sites: Vec<u64>,
}

/// Hook all `SVC #imm`, `MSR TPIDR_EL0` writes, and `MRS TPIDR_EL0` reads in an
/// AArch64 ELF image. (`MRS XZR, TPIDR_EL0` is a discarded read and is left
/// native — see the module docs.)
///
/// `buf` is patched in place. `trampoline_base_addr` is the virtual address the
/// trampoline will be mapped at; `callback` is the absolute address stored in
/// the callback slot (0 if the loader fills it in later).
///
/// Returns `Ok(None)` when the image contains no patch sites, so the caller
/// emits a size-0 sentinel header instead (matching the x86-64 path). Signal
/// returns are handled by the runtime rather than a per-binary gate, so a
/// syscall-free binary needs no trampoline at all.
///
/// Otherwise returns `Ok(Some(outcome))`. A site that cannot reach its gate, or
/// whose gate cannot branch back, is replaced with a trap and listed in
/// [`HookOutcome::trapped_sites`] so the caller can reject the incomplete
/// rewrite, mirroring the x86-64 unpatchable-syscall path.
#[cfg(test)]
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    config: RewriteConfig,
) -> Result<Option<HookOutcome>> {
    hook_syscalls_aarch64_with_code_ranges(
        buf,
        text_sections,
        text_sections,
        trampoline_base_addr,
        callback,
        config,
    )
}

pub(crate) fn hook_syscalls_aarch64_with_code_ranges(
    buf: &mut [u8],
    executable_sections: &[TextSectionInfo],
    code_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    config: RewriteConfig,
) -> Result<Option<HookOutcome>> {
    if !trampoline_base_addr.is_multiple_of(GATE_ALIGNMENT as u64) {
        return Err(Error::AddressOverflow(format!(
            "AArch64 trampoline base {trampoline_base_addr:#x} is not {GATE_ALIGNMENT}-byte aligned"
        )));
    }
    let sites = find_patch_sites_with_code_ranges(executable_sections, code_sections, buf, config)?;

    hook_sites(
        buf,
        &sites,
        trampoline_base_addr,
        callback,
        config,
        GateLayout::linux(config.host),
    )
}

/// Rewrite Darwin SVC and TPIDRRO_EL0 accesses into trampoline gates.
pub(crate) fn hook_macho(
    buf: &mut [u8],
    sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    options: crate::RewriteOptions,
) -> Result<Option<HookOutcome>> {
    let config = RewriteConfig::new(options.target_host(), false);
    let sites = find_macho_patch_sites(sections, buf)?;
    hook_sites(
        buf,
        &sites,
        trampoline_base_addr,
        callback,
        config,
        GateLayout::darwin(config.host),
    )
}

fn find_macho_patch_sites(sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();
    for section in sections {
        let data = crate::section_slice(buf, section)?;
        let start = usize::try_from(section.file_offset)
            .map_err(|_| Error::ParseError("Mach-O section offset".into()))?;
        if !section.file_offset.is_multiple_of(INSN_BYTES_U64)
            || !section.vaddr.is_multiple_of(INSN_BYTES_U64)
            || !data.len().is_multiple_of(INSN_BYTES)
        {
            return Err(Error::ParseError(
                "unaligned Mach-O instruction range".into(),
            ));
        }
        for (index, bytes) in data.as_chunks::<INSN_BYTES>().0.iter().enumerate() {
            let word = u32::from_le_bytes(*bytes);
            let vaddr = checked_add_u64(section.vaddr, (index * INSN_BYTES) as u64, "Mach-O site")?;
            let opcode = word & !REG_MASK;
            let kind = if word & SVC_OPCODE_MASK == SVC_OPCODE_BITS {
                if word != DARWIN_SVC {
                    return Err(Error::UnsupportedExecutable(format!(
                        "unsupported Darwin SVC immediate (expected #0x80) at {vaddr:#x}"
                    )));
                }
                PatchKind::Svc
            } else if opcode == Opcode::MrsTpidrroEl0.bits() {
                let destination = (word & REG_MASK) as u8;
                if destination == XZR {
                    continue;
                }
                PatchKind::MrsTpidr(destination)
            } else if opcode == Opcode::MsrTpidrroEl0.bits() {
                return Err(Error::UnsupportedExecutable(format!(
                    "unsupported Darwin TPIDRRO_EL0 write at {vaddr:#x}"
                )));
            } else {
                continue;
            };
            sites.push(PatchSite {
                file_offset: start + index * INSN_BYTES,
                vaddr,
                kind,
            });
        }
    }
    sites.sort_unstable_by_key(|site| site.file_offset);
    Ok(sites)
}

pub(crate) fn trap_macho_patch_sites(
    buf: &mut [u8],
    sections: &[TextSectionInfo],
) -> Result<usize> {
    let sites = find_macho_patch_sites(sections, buf)?;
    for site in &sites {
        trap_site(buf, site.file_offset);
    }
    Ok(sites.len())
}

pub(crate) fn macho_trampoline_size_upper_bound(
    buf: &[u8],
    sections: &[TextSectionInfo],
    options: crate::RewriteOptions,
) -> Result<usize> {
    let sites = find_macho_patch_sites(sections, buf)?;
    sites.iter().try_fold(0usize, |total, site| {
        let gate_bytes = site.kind.metadata().map_or(0, |metadata| {
            metadata.slot_size_for_host(options.target_host())
        });
        // Allow a separate callback header for each mapping batch.
        total
            .checked_add(GATES_START_OFFSET)
            .and_then(|size| size.checked_add(gate_bytes))
            .ok_or_else(|| Error::AddressOverflow("Mach-O trampoline size".into()))
    })
}

fn hook_sites(
    buf: &mut [u8],
    sites: &[PatchSite],
    trampoline_base_addr: u64,
    callback: u64,
    config: RewriteConfig,
    layout: GateLayout,
) -> Result<Option<HookOutcome>> {
    if !trampoline_base_addr.is_multiple_of(GATE_ALIGNMENT as u64) {
        return Err(Error::AddressOverflow(
            "unaligned AArch64 trampoline address".into(),
        ));
    }
    if sites.is_empty() {
        return Ok(None);
    }

    let mut trampoline_data: Vec<u8> = Vec::new();
    emit_shared_prologue(&mut trampoline_data, callback);

    let mut trapped_sites: Vec<u64> = Vec::new();

    for site in sites {
        let gate_offset = trampoline_data.len();
        let gate_vaddr =
            checked_add_u64(trampoline_base_addr, gate_offset as u64, "trampoline gate")?;

        // The gate's return branch spans a wider displacement than the inbound
        // one, so an encodable inbound branch is necessary but not sufficient:
        // the gate is built only once the inbound branch fits, and a gate whose
        // own branches are out of range makes `emit_gate` return `false` and
        // append nothing. If either is unreachable the site is trapped and no
        // gate is emitted.
        let b_offset = gate_vaddr
            .cast_signed()
            .saturating_sub(site.vaddr.cast_signed());
        let inbound = Insn::B(b_offset).encode();

        let emitted = match inbound {
            Some(_) => emit_gate(
                &mut trampoline_data,
                trampoline_base_addr,
                gate_vaddr,
                site,
                config,
                layout,
            )?,
            None => false,
        };

        if let (Some(b_insn), true) = (inbound, emitted) {
            // Replace the original instruction with `B <gate>`.
            buf[site.file_offset..site.file_offset + INSN_BYTES]
                .copy_from_slice(&b_insn.to_le_bytes());
        } else {
            trap_site(buf, site.file_offset);
            trapped_sites.push(site.vaddr);
        }
    }

    Ok(Some(HookOutcome {
        trampoline: trampoline_data,
        trapped_sites,
    }))
}

/// Builds and appends the gate for `site` at `gate_vaddr`. Returns `false`,
/// appending nothing, when the gate cannot reach its targets and the site must
/// be trapped instead.
fn emit_gate(
    trampoline_data: &mut Vec<u8>,
    trampoline_base: u64,
    gate_vaddr: u64,
    site: &PatchSite,
    config: RewriteConfig,
    layout: GateLayout,
) -> Result<bool> {
    let next = |context| checked_add_u64(site.vaddr, INSN_BYTES_U64, context);
    let x18 = |metadata, anchor, context| -> Result<gate::GateInstance> {
        let mut instance = gate::GateInstance::new(metadata, next(context)?);
        instance.anchor = anchor;
        Ok(instance)
    };
    let (instance, layout) = match site.kind {
        PatchKind::Svc => (
            gate::GateInstance::new(GateMetadata::Svc, next("SVC return")?),
            layout,
        ),
        PatchKind::MsrTpidr(source) => (
            gate::GateInstance::new(GateMetadata::MsrTpidr { source }, next("MSR return")?),
            GateLayout::linux(config.host),
        ),
        PatchKind::MrsTpidr(destination) => (
            gate::GateInstance::new(GateMetadata::MrsTpidr { destination }, next("MRS return")?),
            GateLayout::linux(config.host),
        ),
        PatchKind::X18(X18TransformResult::Supported(transform)) => {
            let mut instance = x18(
                GateMetadata::X18 {
                    scratch: transform.scratch,
                },
                transform.anchor_scratch,
                "x18 return",
            )?;
            instance.guest = transform.word;
            instance.pc_relative = transform.pc_relative;
            (instance, GateLayout::linux(config.host))
        }
        PatchKind::X18(X18TransformResult::Unsupported(_)) => return Ok(false),
        PatchKind::X18StackWriteback(pair) => {
            let mut instance = x18(
                GateMetadata::X18StackWriteback {
                    scratch: pair.scratch,
                },
                pair.anchor_scratch,
                "x18 SP-writeback return",
            )?;
            instance.guest = pair.word;
            instance.stack = pair.layout;
            (instance, GateLayout::linux(config.host))
        }
        PatchKind::X18CompareBranch(branch) => {
            let mut instance = x18(
                GateMetadata::X18CompareBranch {
                    scratch: branch.scratch,
                },
                branch.anchor_scratch,
                "x18 branch fallthrough",
            )?;
            instance.test = branch.kind;
            instance.taken = branch.target;
            (instance, GateLayout::linux(config.host))
        }
        PatchKind::X18Adr(adr) => {
            let mut instance = x18(
                GateMetadata::X18Adr {
                    scratch: adr.scratch,
                },
                adr.anchor_scratch,
                "ADR X18 return",
            )?;
            instance.adr_target = adr.target;
            (instance, GateLayout::linux(config.host))
        }
        PatchKind::X18Branch(kind) => (
            gate::GateInstance::new(GateMetadata::X18Branch { kind }, next("BR X18 provenance")?),
            GateLayout::linux(config.host),
        ),
    };
    let slot = match gate::build(&instance, layout, gate_vaddr, trampoline_base) {
        Ok(slot) => slot,
        Err(gate::BuildError::Unreachable) => return Ok(false),
        Err(error) => return Err(litebox_trampoline::Error::from(error).into()),
    };
    // Every emitted gate must be recognizable by the validator that signal
    // recovery and finalization rely on.
    let mut bytes = [0u8; MAX_GATE_SLOT_BYTES];
    let len = slot.words().len() * INSN_BYTES;
    for (chunk, word) in bytes
        .as_chunks_mut::<INSN_BYTES>()
        .0
        .iter_mut()
        .zip(slot.words())
    {
        *chunk = word.to_le_bytes();
    }
    if gate::validate(
        &bytes[..len],
        gate::SlotAddressing::Placed {
            trampoline_base,
            slot_vaddr: gate_vaddr,
        },
        instance.metadata,
        layout,
        &mut gate::BuiltSlot::empty(),
    )
    .is_none()
    {
        return Err(Error::TrampolinePatchFailure(
            "emitter produced an invalid AArch64 gate".into(),
        ));
    }
    slot.append_to(trampoline_data);
    Ok(true)
}

/// Replace the instruction at `file_offset` with a breakpoint.
///
/// A patch site left native escapes the virtualization: an `SVC` reaches the
/// host kernel directly, and an `MSR TPIDR_EL0` writes the hardware register
/// instead of the guest's slot -- on a Linux host, over the host's own anchor.
/// Both are silent, which is worse than a fault.
fn trap_site(buf: &mut [u8], file_offset: usize) {
    let brk = Insn::Brk(TRAP_BRK_IMM)
        .encode()
        .expect("BRK always encodes");
    buf[file_offset..file_offset + INSN_BYTES].copy_from_slice(&brk.to_le_bytes());
}

/// Replace every patch site in `buf` with a breakpoint, returning how
/// many were trapped.
///
/// The fail-safe behind [`crate::trap_all_syscalls_in_code`], for a segment
/// that could not be patched at all. The main hooker traps its own unreachable
/// sites as it goes and does not come through here.
///
/// The `cfg` tracks reachability, not capability: the scan and the rewrite are
/// host-agnostic, but nothing calls this in an x86-64 build.
pub(crate) fn trap_all_patch_sites_with_code_ranges(
    buf: &mut [u8],
    executable_sections: &[TextSectionInfo],
    code_sections: &[TextSectionInfo],
    config: RewriteConfig,
) -> Result<usize> {
    let sites = find_patch_sites_with_code_ranges(executable_sections, code_sections, buf, config)?;
    for site in &sites {
        trap_site(buf, site.file_offset);
    }
    Ok(sites.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_trampoline::aarch64::{
        Boundary, ClassifiedGate, EncodedGateMetadata, FIRST_SCANNABLE_OFFSET, Frame, FrameBase,
        GATE_METADATA_BYTES, GATE_METADATA_REGISTER_SHIFT, GATE_SLOT_SIZES,
        GUEST_TPIDR_OFFSET_ALIGN, GUEST_TPIDR_OFFSET_PLACEHOLDER, GuestSp, IMM26_MASK,
        LDST_UIMM12_IMM_MASK, LDST_UIMM12_IMM_SHIFT, MAX_GUEST_TPIDR_OFFSET,
        MIN_GUEST_TPIDR_OFFSET, MRS_SLOT_BYTES, MSR_FRAME_OFF_VALUE, MSR_SLOT_BYTES, NOP,
        OPCODE_TOP6_MASK, Resume, SP, SVC_0, SVC_FRAME_BYTES, SVC_FRAME_OFF_RETADDR,
        SVC_FRAME_OFF_STUB, SVC_FRAME_OFF_X16, SVC_GATE_BYTES, SVC_OUTBOUND_STUB_BYTES,
        SVC_SLOT_BYTES, Stage, Value, X16, X17, X18_ADR_SLOT_BYTES, X18_BRANCH_SLOT_BYTES,
        X18_COMPARE_BRANCH_SLOT_BYTES, X18_SLOT_BYTES, X18_STACK_WRITEBACK_SLOT_BYTES, anchor_mask,
        classify_copied_gate_slot_for_host, classify_copied_gate_slot_with_layout,
        classify_gate_pc, classify_gate_pc_with_candidates, decode_adrp_add_target_for,
        decode_adrp_target, decode_branch_target, decode_gate_metadata_word,
        finalize_trampoline_gates, finalize_trampoline_gates_for_host,
        find_guest_tpidr_placeholder, find_guest_x18_placeholder,
    };
    #[test]
    fn macos_fallback_traps_use_shared_marker() {
        let original = 0xd51bd052u32; // MSR TPIDR_EL0, x18: unsupported overlap
        let config = RewriteConfig::new(litebox_trampoline::TargetHost::MacOs, true);
        let (patched, outcome) = hook_words_opt_with_config(&[original], 0x1000, 0x400000, config);
        assert_eq!(outcome.unwrap().trapped_sites, [0x1000]);
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );

        let mut code = original.to_le_bytes();
        let sections = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 4,
        }];
        assert_eq!(
            trap_all_patch_sites_with_code_ranges(&mut code, &sections, &sections, config).unwrap(),
            1
        );
        assert_eq!(
            u32::from_le_bytes(code),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
    }
    #[test]
    fn macos_emits_tpidrro_tls_gates_and_svc_gate() {
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
        ];
        let (_, outcome) = hook_words_opt_with_config(
            &words,
            0x1000,
            0x400000,
            RewriteConfig::new(litebox_trampoline::TargetHost::MacOs, true),
        );
        let trampoline = outcome.unwrap().trampoline;
        assert_eq!(
            word_at(&trampoline, 16),
            Insn::MrsTpidrroEl0(9).encode().unwrap()
        );
        assert_eq!(word_at(&trampoline, 20), anchor_mask(9).encode().unwrap());
        assert_eq!(
            word_at(&trampoline, 48 + 12),
            Insn::MrsTpidrroEl0(X16).encode().unwrap()
        );
        assert_eq!(
            word_at(&trampoline, 48 + 16),
            anchor_mask(X16).encode().unwrap()
        );
        assert_eq!(
            word_at(&trampoline, 24),
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }
            .encode()
            .unwrap()
        );
        assert!(matches!(
            decode_gate_metadata_word(word_at(&trampoline, 112 + SVC_SLOT_BYTES - 4)),
            Some(GateMetadata::Svc)
        ));
    }
    #[test]
    fn macos_masks_every_emitted_tpidrro_anchor() {
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            0xaa00_03f2, // mov x18, x0
            0xa9bf_4ff2, // stp x18, x19, [sp, #-16]!
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
        ];
        let (_, outcome) = hook_words_opt_with_config(
            &words,
            0x1000,
            0x400000,
            RewriteConfig::new(litebox_trampoline::TargetHost::MacOs, true),
        );
        let trampoline = outcome.unwrap().trampoline;
        let mut anchors = 0;
        for offset in (0..trampoline.len() - INSN_BYTES).step_by(INSN_BYTES) {
            let word = word_at(&trampoline, offset);
            if word & !REG_MASK == Opcode::MrsTpidrroEl0.bits() {
                let register = (word & REG_MASK) as u8;
                assert_eq!(
                    word_at(&trampoline, offset + INSN_BYTES),
                    anchor_mask(register).encode().unwrap()
                );
                anchors += 1;
            }
        }
        assert_eq!(anchors, 8);

        let (_, linux) = hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        assert_ne!(
            word_at(&linux, GATES_START_OFFSET + INSN_BYTES),
            anchor_mask(9).encode().unwrap()
        );
        assert_eq!(linux.len(), GATES_START_OFFSET + MRS_SLOT_BYTES);
    }
    #[test]
    fn windows_rejects_linux_specific_sites_but_accepts_x18_only_scan() {
        let config = RewriteConfig::new(litebox_trampoline::TargetHost::Windows, true);
        for word in [SVC_0, MSR_TPIDR_EL0_BITS, MRS_TPIDR_EL0_BITS] {
            let bytes = word.to_le_bytes();
            let error = find_patch_sites(
                &[TextSectionInfo {
                    vaddr: 0x1000,
                    file_offset: 0,
                    size: 4,
                }],
                &bytes,
                config,
            )
            .err()
            .expect("non-Linux Linux-specific site must fail");
            assert!(
                matches!(error, Error::UnsupportedExecutable(reason) if reason.contains("selected host"))
            );
        }

        let bytes = 0x0b12_0063u32.to_le_bytes();
        let sites = find_patch_sites(
            &[TextSectionInfo {
                vaddr: 0x1000,
                file_offset: 0,
                size: 4,
            }],
            &bytes,
            config,
        )
        .unwrap();
        assert!(matches!(sites[0].kind, PatchKind::X18(_)));

        for instruction in [Insn::Br(18), Insn::Blr(18), Insn::Ret(18)] {
            let bytes = instruction.encode().unwrap().to_le_bytes();
            let sites = find_patch_sites(
                &[TextSectionInfo {
                    vaddr: 0x1000,
                    file_offset: 0,
                    size: 4,
                }],
                &bytes,
                config,
            )
            .unwrap();
            assert!(matches!(sites[0].kind, PatchKind::X18Branch(_)));
        }
    }
    #[test]
    fn macos_finalization_accepts_current_gates_and_rejects_cross_host_state_atomically() {
        let words = [SVC_0, MSR_TPIDR_EL0_BITS, MRS_TPIDR_EL0_BITS, 0x0b12_0063];
        let config = RewriteConfig::new(litebox_trampoline::TargetHost::MacOs, true);
        let (_, outcome) = hook_words_opt_with_config(&words, 0x1000, 0x400000, config);
        let mut trampoline = outcome.unwrap().trampoline;
        let original = trampoline.clone();
        assert!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                104,
                litebox_trampoline::TargetHost::Linux
            )
            .is_err()
        );
        assert_eq!(trampoline, original);
        assert!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                112,
                litebox_trampoline::TargetHost::MacOs
            )
            .is_err()
        );
        assert_eq!(trampoline, original);
        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::MacOs,
        )
        .unwrap();
        // Re-finalization is idempotent; a different slot layout is rejected.
        let finalized = trampoline.clone();
        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::MacOs,
        )
        .unwrap();
        assert_eq!(trampoline, finalized);
        assert!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                112,
                120,
                litebox_trampoline::TargetHost::MacOs
            )
            .is_err()
        );
        assert_eq!(trampoline, finalized);
    }
    #[test]
    fn x18_gate_inside_exclusive_sequence_is_rejected() {
        let scan = |words: &[u32]| {
            let bytes = words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>();
            find_patch_sites(
                &[TextSectionInfo {
                    vaddr: 0x1000,
                    file_offset: 0,
                    size: bytes.len() as u64,
                }],
                &bytes,
                RewriteConfig::new(TargetHost::Linux, true),
            )
        };

        let error = scan(&[
            0x885f_fc20, // ldaxr w0, [x1]
            0x8b12_0063, // add x3, x3, x18
            0x8804_fc25, // stlxr w4, w5, [x1]
        ])
        .err()
        .expect("x18 gate inside exclusive sequence must fail");
        assert!(
            matches!(error, Error::UnsupportedExecutable(reason) if reason.contains("exclusive sequence"))
        );

        let sites = scan(&[
            0x885f_fc20, // ldaxr w0, [x1]
            0x8804_fc25, // stlxr w4, w5, [x1]
            0x8b12_0063, // add x3, x3, x18
        ])
        .unwrap();
        assert_eq!(sites[0].vaddr, 0x1008);
    }
    #[test]
    fn sve_x18_operands_use_the_ordinary_x18_gate() {
        for (word, transformed) in [
            (0x0420_e3f2, 0x0420_e3f1), // cntb x18
            (0xa5f2_4000, 0xa5f1_4000), // ld1d { z0.d }, p0/z, [x0, x18, lsl #3]
        ] {
            let (patched, outcome) = hook_words_opt_with_config(
                &[word],
                0x1000,
                0x400000,
                x18_config(TargetHost::Linux),
            );
            let outcome = outcome.unwrap();
            assert_eq!(outcome.trapped_sites, [], "word {word:#010x}");
            assert_eq!(
                word_at(&patched, 0) & OPCODE_TOP6_MASK,
                Opcode::B.bits(),
                "word {word:#010x}"
            );
            // The copied guest instruction.
            assert_eq!(
                word_at(&outcome.trampoline, GATES_START_OFFSET + 20),
                transformed,
                "word {word:#010x}"
            );

            let (native, outcome) = hook_words_opt(&[word], 0x1000, 0x400000);
            assert_eq!(word_at(&native, 0), word);
            assert!(outcome.is_none());
        }
    }
    #[test]
    fn x18_site_after_movprfx_is_unsupported() {
        const CPY_X18: u32 = 0x05e8_a240; // mov z0.d, p0/m, x18
        let scan_with_code_ranges =
            |executable: &[TextSectionInfo], code: &[TextSectionInfo], words: &[u32]| {
                let bytes = words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>();
                find_patch_sites_with_code_ranges(
                    executable,
                    code,
                    &bytes,
                    x18_config(TargetHost::Linux),
                )
                .unwrap()
                .into_iter()
                .map(|site| (site.vaddr, site.kind))
                .collect::<Vec<_>>()
            };
        let scan = |sections: &[TextSectionInfo], words: &[u32]| {
            scan_with_code_ranges(sections, sections, words)
        };
        let section = |vaddr: u64, file_offset: u64, words: u64| TextSectionInfo {
            vaddr,
            file_offset,
            size: words * INSN_BYTES_U64,
        };
        let unsupported = PatchKind::X18(X18TransformResult::Unsupported(
            X18Unsupported::MovprfxSuccessor,
        ));
        for movprfx in [
            0x0420_bc20, // movprfx z0, z1
            0x04d1_2020, // movprfx z0.d, p0/m, z1.d
            0x04d0_2020, // movprfx z0.d, p0/z, z1.d
        ] {
            for sites in [
                scan(&[section(0x1000, 0, 2)], &[movprfx, CPY_X18]),
                scan(
                    &[section(0x1000, 0, 1), section(0x1004, 4, 1)],
                    &[movprfx, CPY_X18],
                ),
                scan(
                    &[section(0x1004, 4, 1), section(0x1000, 0, 1)],
                    &[movprfx, CPY_X18],
                ),
                // Contiguous in memory but not in the file.
                scan(
                    &[section(0x1000, 0, 1), section(0x1004, 8, 1)],
                    &[movprfx, NOP, CPY_X18],
                ),
                // MOVPRFX outside the identified code ranges.
                scan_with_code_ranges(
                    &[section(0x1000, 0, 2)],
                    &[section(0x1004, 4, 1)],
                    &[movprfx, CPY_X18],
                ),
            ] {
                assert_eq!(sites, [(0x1004, unsupported)], "movprfx {movprfx:#010x}");
            }
            for sites in [
                scan(&[section(0x1000, 0, 3)], &[movprfx, NOP, CPY_X18]),
                // Contiguous in the file but not in memory.
                scan(
                    &[section(0x1000, 0, 1), section(0x1008, 4, 1)],
                    &[movprfx, CPY_X18],
                ),
            ] {
                assert!(
                    matches!(
                        sites[..],
                        [(_, PatchKind::X18(X18TransformResult::Supported(_)))]
                    ),
                    "movprfx {movprfx:#010x}: {sites:?}"
                );
            }
        }
    }
    use alloc::vec;
    /// Bytes emitted per SVC site: the gate proper plus its outbound stub.
    const SVC_GATE_SIZE: usize = SVC_SLOT_BYTES;
    /// MSR gate instructions up to and including the first return branch. The
    /// slot holds one more `B`, which never executes.
    const MSR_GATE_INSNS: usize = 9;
    const MSR_GATE_SIZE: usize = MSR_SLOT_BYTES;
    const MRS_GATE_SIZE: usize = MRS_SLOT_BYTES;
    fn x18_config(host: TargetHost) -> RewriteConfig {
        RewriteConfig::new(host, true)
    }
    fn word_at(data: &[u8], byte_off: usize) -> u32 {
        u32::from_le_bytes(data[byte_off..byte_off + 4].try_into().unwrap())
    }
    /// An expected recovery stage.
    fn recover(
        frame: Frame,
        sp: GuestSp,
        value: Value,
        resume: Resume,
        runtime_fault: bool,
    ) -> Stage {
        Stage::Recover(Boundary {
            frame,
            sp,
            value,
            resume,
            runtime_fault,
            check_capture: false,
        })
    }
    /// The recovery stage the copied-slot classifier reports for every word of
    /// an emitted slot (`None` where the word is not executable).
    fn slot_stages(slot: &[u8], slot_vaddr: u64, layout: GateLayout) -> Vec<Option<Stage>> {
        (0..slot.len())
            .step_by(INSN_BYTES)
            .map(|offset| {
                classify_copied_gate_slot_with_layout(
                    slot,
                    slot_vaddr,
                    slot_vaddr + offset as u64,
                    layout,
                )
                .map(ClassifiedGate::stage)
            })
            .collect()
    }
    /// `MSR TPIDR_EL0, Xrt` guest instruction word. The rewriter only scans for
    /// this form and never emits it, so the encoder lives here.
    fn msr_tpidr_el0(rt: u8) -> u32 {
        MSR_TPIDR_EL0_BITS | u32::from(rt)
    }
    /// Build a one-section image whose section data == the supplied words and
    /// run the hooker. Returns `(patched_section, trampoline)`. Panics if the
    /// input has no patch sites (use [`hook_words_opt`] for that case).
    fn hook_words(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Vec<u8>) {
        let (patched, outcome) = hook_words_opt(words, base, tramp_base);
        (
            patched,
            outcome
                .expect("expected a trampoline (input has patch sites)")
                .trampoline,
        )
    }
    /// Like [`hook_words`] but prefills the trampoline's callback slot, so a
    /// test can plant arbitrary data there.
    fn hook_words_with_callback(
        words: &[u32],
        base: u64,
        tramp_base: u64,
        callback: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let sections = vec![TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        hook_syscalls_aarch64(
            &mut buf,
            &sections,
            tramp_base,
            callback,
            RewriteConfig::new(TargetHost::Linux, false),
        )
        .unwrap()
        .expect("expected a trampoline (input has patch sites)")
        .trampoline
    }
    /// Like [`hook_words`] but returns the raw `Option` outcome so callers can
    /// assert the "no patch sites" (`None`) sentinel and trapped-site cases.
    fn hook_words_opt(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Option<HookOutcome>) {
        hook_words_opt_with_config(
            words,
            base,
            tramp_base,
            RewriteConfig::new(TargetHost::Linux, false),
        )
    }
    fn hook_words_opt_with_config(
        words: &[u32],
        base: u64,
        tramp_base: u64,
        config: RewriteConfig,
    ) -> (Vec<u8>, Option<HookOutcome>) {
        let mut buf = Vec::new();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let sections = vec![TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        let outcome = hook_syscalls_aarch64(&mut buf, &sections, tramp_base, 0, config).unwrap();
        (buf, outcome)
    }
    #[test]
    fn sp_writeback_pair_uses_displacement_aware_x18_gate() {
        // stp x18, x19, [sp, #-16]!
        let original = 0xa9bf_4ff2;
        let pair = classify_x18_stack_writeback(original).unwrap();
        assert_eq!(pair.layout.delta, -16);
        assert_eq!(pair.layout.frame_bytes, 32);
        let (patched, outcome) = hook_words_opt_with_config(
            &[original],
            0x1000,
            0x400000,
            RewriteConfig::new(TargetHost::Linux, true),
        );
        let mut outcome = outcome.unwrap();
        assert_eq!(outcome.trapped_sites, []);
        assert_ne!(u32::from_le_bytes(patched.try_into().unwrap()), original);
        let gate = &outcome.trampoline[GATES_START_OFFSET..];
        assert_eq!(gate.len(), X18_STACK_WRITEBACK_SLOT_BYTES);
        let metadata = EncodedGateMetadata(u32::from_le_bytes(
            gate[gate.len() - 4..].try_into().unwrap(),
        ))
        .decode()
        .unwrap();
        assert_eq!(
            metadata,
            GateMetadata::X18StackWriteback {
                scratch: pair.scratch
            }
        );
        assert!(
            gate::validate(
                gate,
                gate::SlotAddressing::Placed {
                    trampoline_base: 0x400000,
                    slot_vaddr: 0x400000 + GATES_START_OFFSET as u64,
                },
                metadata,
                GateLayout::linux(TargetHost::Linux),
                &mut gate::BuiltSlot::empty(),
            )
            .is_some()
        );
        assert_eq!(word_at(gate, 0), Insn::SubSp(32).encode().unwrap());
        assert_eq!(word_at(gate, 44), Insn::AddSp(16).encode().unwrap());
        finalize_trampoline_gates_for_host(
            &mut outcome.trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::Linux,
        )
        .unwrap();
    }
    #[test]
    fn sp_writeback_pair_variants_preserve_scaled_displacements() {
        // Cover pre/post indexing, positive/negative displacements, and both
        // integer element widths. The expected values come from the ISA, not
        // from the gate's frame-size calculation.
        for (word, expected_delta, expected_frame, expected_final_add) in [
            (0xa9bf_4ff2, -16, 32, 16), // stp x18, x19, [sp, #-16]!
            (0xa8c1_4ff2, 16, 16, 32),  // ldp x18, x19, [sp], #16
            (0x29bf_4ff2, -8, 32, 24),  // stp w18, w19, [sp, #-8]!
            (0x28c1_4ff2, 8, 16, 24),   // ldp w18, w19, [sp], #8
        ] {
            let pair = classify_x18_stack_writeback(word).unwrap();
            assert_eq!(pair.layout.delta, expected_delta);
            assert_eq!(pair.layout.frame_bytes, expected_frame);

            let (_patched, outcome) = hook_words_opt_with_config(
                &[word],
                0x1000,
                0x400000,
                x18_config(TargetHost::Linux),
            );
            let outcome = outcome.unwrap();
            let gate = &outcome.trampoline[GATES_START_OFFSET..];
            assert_eq!(
                word_at(gate, 44), // final SP adjustment
                Insn::AddSp(expected_final_add).encode().unwrap()
            );
        }
    }
    #[test]
    fn sp_writeback_stages_attribute_only_the_pair_to_guest() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0xa9bf_4ff2], // stp x18, x19, [sp, #-16]!
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let trampoline = outcome.unwrap().trampoline;
        let stages = slot_stages(
            &trampoline[GATES_START_OFFSET..],
            0x400000 + GATES_START_OFFSET as u64,
            GateLayout::linux(TargetHost::Linux),
        );
        let transform = 24 / INSN_BYTES;
        for (index, stage) in stages.iter().take(13).enumerate() {
            let Some(Stage::Recover(boundary)) = stage else {
                panic!("word {index} has no recovery boundary");
            };
            assert_eq!(boundary.runtime_fault, index != transform, "word {index}");
        }
        assert_eq!(
            stages[transform],
            Some(Stage::Recover(Boundary {
                frame: Frame::Restore(FrameBase::Anchor),
                sp: GuestSp::Signal,
                value: Value::Scratch,
                resume: Resume::Site,
                runtime_fault: false,
                check_capture: false,
            }))
        );
        assert_eq!(
            stages[44 / INSN_BYTES],
            Some(recover(
                Frame::Live(FrameBase::Sp),
                GuestSp::FrameEndPlusDelta,
                Value::Slot,
                Resume::Next,
                true,
            ))
        );
    }
    #[test]
    fn x18_gate_uses_each_hosts_exact_anchor_read() {
        for (host, anchor_word) in [
            (TargetHost::Linux, 0xd53b_d050),
            (TargetHost::MacOs, 0xd53b_d070),
            (TargetHost::Windows, 0xaa12_03f0),
        ] {
            let (_, outcome) =
                hook_words_opt_with_config(&[0x0b12_0063], 0x1000, 0x400000, x18_config(host));
            let trampoline = outcome.unwrap().trampoline;
            let gate = &trampoline[GATES_START_OFFSET..];
            assert_eq!(
                gate.len(),
                GateMetadata::X18 { scratch: X17 }.slot_size_for_host(host)
            );
            assert_eq!(
                word_at(gate, 4), // first anchor read
                anchor_word
            );
            if host == TargetHost::MacOs {
                assert_eq!(word_at(gate, 8), anchor_mask(X16).encode().unwrap());
            }
            assert_eq!(
                word_at(gate, gate.len() - GATE_METADATA_BYTES),
                EncodedGateMetadata::encode(GateMetadata::X18 { scratch: X17 })
                    .unwrap()
                    .0
            );
        }
    }
    #[test]
    fn indirect_x18_control_flow_emits_persisted_trap_gates() {
        for instruction in [Insn::Br(18), Insn::Blr(18), Insn::Ret(18)] {
            let word = instruction.encode().unwrap();
            let (patched, outcome) = hook_words_opt_with_config(
                &[word],
                0x1000,
                0x400000,
                x18_config(TargetHost::Linux),
            );
            let outcome = outcome.unwrap();

            assert!(outcome.trapped_sites.is_empty(), "word {word:#010x}");
            assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
            let gate = &outcome.trampoline[GATES_START_OFFSET..];
            assert_eq!(gate.len(), 16);
            assert_eq!(word_at(gate, 0), Insn::Brk(0xB18).encode().unwrap());
            assert_eq!(
                decode_branch_target(word_at(gate, 4), 0x400000 + GATES_START_OFFSET as u64 + 4),
                Some(0x1004)
            );
            assert_eq!(word_at(gate, 8), NOP);
        }
    }
    #[test]
    fn cbnz_w18_gate_preserves_both_original_destinations() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0x3500_0332], // cbnz w18, 0x1064
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();

        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        let gate = &outcome.trampoline[GATES_START_OFFSET..];
        assert_eq!(gate.len(), 48);
        assert_eq!(
            decode_branch_target(word_at(gate, 28), 0x400000 + GATES_START_OFFSET as u64 + 28),
            Some(0x1004)
        );
        assert_eq!(
            decode_branch_target(word_at(gate, 40), 0x400000 + GATES_START_OFFSET as u64 + 40),
            Some(0x1064)
        );
    }
    #[test]
    fn compare_branch_x18_gate_finalizes_without_size_ambiguity() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0x3500_0332],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;

        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::Linux,
        )
        .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }
    #[test]
    fn tbnz_x18_bit_63_gate_encodes_without_panicking() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xb7f8_00b2], // tbnz x18, #63, 0x1014
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();

        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        let gate = &outcome.trampoline[GATES_START_OFFSET..];
        assert_eq!(word_at(gate, 16), 0xb7f8_0091); // tbnz x17, #63, +16
    }
    #[test]
    fn ordinary_x18_gate_allows_x30_operands() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0x2a12_03fe], // mov w30, w18
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();

        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
    }
    #[test]
    fn adrp_x18_gate_preserves_original_page_target() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xf000_0012], // adrp x18, +0x3000 from page 0x1000
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();

        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        // The relocated guest instruction is the gate's sixth word.
        let transformed_pc = 0x400000 + GATES_START_OFFSET as u64 + 20;
        assert_eq!(
            decode_adrp_target(
                word_at(&outcome.trampoline, GATES_START_OFFSET + 20,),
                transformed_pc,
                17,
            ),
            Some(0x4000)
        );
    }
    #[test]
    fn adr_x18_gate_preserves_original_target() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0x1000_0072], // adr x18, 0x100c
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();

        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(
            decode_adrp_add_target_for(
                word_at(&outcome.trampoline, GATES_START_OFFSET + 8),
                word_at(&outcome.trampoline, GATES_START_OFFSET + 12),
                0x400000 + GATES_START_OFFSET as u64 + 8,
                17,
            ),
            Some(0x100c)
        );
    }
    #[test]
    fn adr_x18_gate_finalizes() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0x1000_0072],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;

        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::Linux,
        )
        .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }
    #[test]
    fn x18_offsets_finalize_transactionally() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0x0b12_0063],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();
        assert!(matches!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                12,
                litebox_trampoline::TargetHost::Linux
            ),
            Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        assert!(matches!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                96,
                litebox_trampoline::TargetHost::Linux
            ),
            Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::Linux,
        )
        .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }
    #[test]
    fn tpidr_only_patcher_rejects_x18_gates_transactionally() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        assert!(finalize_trampoline_gates(&mut trampoline, 96).is_err());
        assert_eq!(trampoline, before);
    }
    #[test]
    fn combined_finalizer_validates_x18_offset_without_x18_gates() {
        let (_, mut trampoline) = hook_words(&[SVC_0], 0x1000, 0x400000);
        let before = trampoline.clone();

        assert!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                12,
                litebox_trampoline::TargetHost::Linux
            )
            .is_err()
        );
        assert_eq!(trampoline, before);
    }
    #[test]
    fn combined_finalizer_requires_adjacent_guest_slots() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        assert!(
            finalize_trampoline_gates_for_host(
                &mut trampoline,
                96,
                112,
                litebox_trampoline::TargetHost::Linux
            )
            .is_err()
        );
        assert_eq!(trampoline, before);
    }
    #[test]
    fn transformed_instruction_may_resemble_x18_placeholder() {
        let guest_instruction = 0xf97f_fc12; // ldr x18, [x0, #32760]
        let (_, outcome) = hook_words_opt_with_config(
            &[guest_instruction],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let transformed = GATES_START_OFFSET + 20; // the copied guest instruction
        let before = word_at(&trampoline, transformed);

        finalize_trampoline_gates_for_host(
            &mut trampoline,
            96,
            104,
            litebox_trampoline::TargetHost::Linux,
        )
        .unwrap();

        assert_eq!(word_at(&trampoline, transformed), before);
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
        assert_eq!(find_guest_tpidr_placeholder(&trampoline), None);
    }
    #[test]
    fn legacy_finalizer_rejects_x18_trampoline_transactionally() {
        let (_, outcome) = hook_words_opt_with_config(
            &[Insn::MrsTpidrEl0(9).encode().unwrap(), 0x0b12_0063],
            0x1000,
            0x400000,
            x18_config(TargetHost::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        let error = finalize_trampoline_gates(&mut trampoline, 96).unwrap_err();

        assert!(
            matches!(error, litebox_trampoline::Error::TrampolinePatchFailure(reason) if reason.contains("finalize_trampoline_gates_for_host"))
        );
        assert_eq!(trampoline, before);
    }
    #[test]
    fn x18_gate_out_of_branch_range_traps_without_emitting_a_slot() {
        let base = 0x1004u64;
        let max_forward = (1u64 << 27) - 4;
        let trampoline_base = base + max_forward - GATES_START_OFFSET as u64;
        let (patched, outcome) = hook_words_opt_with_config(
            &[0x0b12_0063],
            base,
            trampoline_base,
            x18_config(TargetHost::Linux),
        );
        let outcome = outcome.unwrap();
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![base]);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }
    #[test]
    fn tpidr_x18_overlap_is_x18_when_enabled_and_tp_gate_by_default() {
        let words = [msr_tpidr_el0(18), Insn::MrsTpidrEl0(18).encode().unwrap()];
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let section = TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: bytes.len() as u64,
        };
        let enabled = RewriteConfig::new(TargetHost::Linux, true);
        let sites = find_patch_sites(&[section], &bytes, enabled).unwrap();
        assert!(sites.iter().all(|site| matches!(
            site.kind,
            PatchKind::X18(X18TransformResult::Unsupported(
                X18Unsupported::EncodingLayout
            ))
        )));

        let (patched, outcome) = hook_words_opt_with_config(&words, 0x1000, 0x2000, enabled);
        let trap = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();
        assert_eq!(word_at(&patched, 0), trap);
        assert_eq!(word_at(&patched, 4), trap);
        assert_eq!(outcome.unwrap().trapped_sites, vec![0x1000, 0x1004]);

        let (patched, outcome) = hook_words_opt(&words, 0x1000, 0x2000);
        assert_ne!(word_at(&patched, 0), trap);
        assert_ne!(word_at(&patched, 4), trap);
        let outcome = outcome.unwrap();
        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(
            outcome.trampoline.len(),
            GATES_START_OFFSET + MSR_GATE_SIZE + MRS_GATE_SIZE
        );
    }
    #[test]
    fn unknown_executable_bytes_scan_mandatory_sites_but_not_heuristic_x18() {
        let words: [u32; 2] = [0xd400_0001, 0x5d56_4f48];
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let executable = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: bytes.len() as u64,
        }];

        let sites = find_patch_sites_with_code_ranges(
            &executable,
            &[],
            &bytes,
            x18_config(TargetHost::Linux),
        )
        .unwrap();

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].vaddr, 0x1000);
        assert_eq!(sites[0].kind, PatchKind::Svc);
    }
    #[test]
    fn non_x18_scan_preserves_mandatory_sites_across_code_ranges() {
        let mut words = vec![NOP, 0xc85f_7c20]; // NOP; LDXR X0, [X1]
        let mut expected = Vec::new();
        for reg in 0..=31 {
            for (word, kind) in [
                (msr_tpidr_el0(reg), Some(PatchKind::MsrTpidr(reg))),
                (
                    Insn::MrsTpidrEl0(reg).encode().unwrap(),
                    (reg != XZR).then_some(PatchKind::MrsTpidr(reg)),
                ),
            ] {
                let offset = words.len() * INSN_BYTES;
                words.push(word);
                if let Some(kind) = kind {
                    expected.push((offset, 0x1000 + offset as u64, kind));
                }
                words.push(NOP);
            }
        }
        for imm in [0, 1, 0xffff] {
            let offset = words.len() * INSN_BYTES;
            words.push(SVC_0 | (imm << 5));
            expected.push((offset, 0x1000 + offset as u64, PatchKind::Svc));
            words.push(NOP);
        }
        words.push(0xc802_7c20); // STXR W2, X0, [X1]
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let executable = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: bytes.len() as u64,
        }];
        let fragmented = [
            TextSectionInfo {
                vaddr: 0x1000,
                file_offset: 0,
                size: 16,
            },
            TextSectionInfo {
                vaddr: 0x1040,
                file_offset: 64,
                size: 16,
            },
        ];
        for code in [&[][..], &executable[..], &fragmented[..]] {
            let sites = find_patch_sites_with_code_ranges(
                &executable,
                code,
                &bytes,
                RewriteConfig::new(litebox_trampoline::TargetHost::Linux, false),
            )
            .unwrap();
            let actual = sites
                .iter()
                .map(|site| (site.file_offset, site.vaddr, site.kind))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn non_x18_scan_still_rejects_address_overflow_on_non_candidate() {
        let bytes = [NOP.to_le_bytes(), NOP.to_le_bytes()].concat();
        let executable = [TextSectionInfo {
            vaddr: u64::MAX - 3,
            file_offset: 0,
            size: bytes.len() as u64,
        }];
        assert!(matches!(
            find_patch_sites_with_code_ranges(
                &executable,
                &[],
                &bytes,
                RewriteConfig::new(litebox_trampoline::TargetHost::Linux, false),
            ),
            Err(Error::AddressOverflow(_))
        ));
    }
    #[test]
    fn metadata_ranges_are_clipped_aligned_and_merged() {
        let executable = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0x200,
            size: 0x20,
        }];

        let ranges = ranges_to_sections(
            vec![(0x0fff, 0x1006), (0x1004, 0x100d), (0x101e, 0x1024)],
            &executable,
        );

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].vaddr, 0x1000);
        assert_eq!(ranges[0].file_offset, 0x200);
        assert_eq!(ranges[0].size, 0xc);
    }
    #[test]
    fn trampoline_size_upper_bound_accounts_for_per_mapping_prologues() {
        let words = [
            SVC_0,
            msr_tpidr_el0(5),
            Insn::MrsTpidrEl0(9).encode().unwrap(),
        ];
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let metadata = ElfCodeMetadata {
            executable: vec![TextSectionInfo {
                vaddr: 0x1000,
                file_offset: 0,
                size: bytes.len() as u64,
            }],
            identified: vec![TextSectionInfo {
                vaddr: 0x1000,
                file_offset: 0,
                size: bytes.len() as u64,
            }],
        };

        let bound = metadata
            .trampoline_size_upper_bound(&bytes, crate::RewriteOptions::default())
            .unwrap();
        let emitted = words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                hook_words(&[*word], 0x1000 + (index * INSN_BYTES) as u64, 0x400000)
                    .1
                    .len()
            })
            .sum::<usize>();

        assert_eq!(
            bound,
            3 * GATES_START_OFFSET + SVC_SLOT_BYTES + MSR_SLOT_BYTES + MRS_SLOT_BYTES
        );
        assert_eq!(emitted, bound);
    }
    #[test]
    fn no_patch_sites_emit_no_trampoline() {
        // No patch sites: a NOP-only section yields no trampoline at all, so the
        // caller emits a size-0 sentinel (matching the x86-64 path).
        let (_patched, tramp) = hook_words_opt(&[0xD503_201F], 0x1000, 0x100000);
        assert!(tramp.is_none());
    }
    #[test]
    fn svc_is_replaced_with_branch_into_gate() {
        let base = 0x1000;
        let tramp_base = 0x200000;
        let (patched, tramp) = hook_words(&[SVC_0], base, tramp_base);

        // The SVC word became a `B`.
        let patched_word = word_at(&patched, 0);
        assert_eq!(
            patched_word & OPCODE_TOP6_MASK,
            Opcode::B.bits(),
            "expected B opcode"
        );

        // It targets the first per-site gate at GATES_START_OFFSET.
        let imm26 = i64::from(patched_word & IMM26_MASK);
        let disp = imm26 << 2; // positive here
        let target = base + disp.cast_unsigned();
        assert_eq!(target, tramp_base + GATES_START_OFFSET as u64);

        // The gate's first instruction is SUB SP, SP, #SVC_FRAME_BYTES.
        assert_eq!(
            word_at(&tramp, GATES_START_OFFSET),
            Insn::SubSp(SVC_FRAME_BYTES).encode().unwrap()
        );
        // Total = prologue + one SVC gate.
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }
    #[test]
    fn svc_with_nonzero_immediate_is_also_rewritten() {
        // Linux ignores the immediate; #0x80 does not select the Darwin frame.
        for immediate in [1, 0x80] {
            let word = SVC_0 | (immediate << 5);
            let (patched, tramp) = hook_words(&[word], 0x1000, 0x200000);
            assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
            assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
            assert_eq!(
                word_at(&tramp, GATES_START_OFFSET),
                Insn::SubSp(SVC_FRAME_BYTES).encode().unwrap()
            );
            assert_eq!(
                decode_gate_metadata_word(word_at(&tramp, tramp.len() - 4)),
                Some(GateMetadata::Svc)
            );
        }
    }
    #[test]
    fn site_beyond_branch_range_is_trapped() {
        // The trampoline sits 256MB above the section, past `B`'s ±128MB reach.
        // The site becomes `BRK`, is surfaced as trapped, and gets no gate,
        // leaving the trampoline at its prologue-only size.
        let (patched, outcome) = hook_words_opt(&[SVC_0], 0x1000, 0x1000_0000);
        let outcome = outcome.expect("expected a trampoline (input has patch sites)");
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![0x1000]);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }
    #[test]
    fn msr_gate_return_branch_out_of_range_is_trapped() {
        // Boundary window where the site can reach its gate but the gate cannot
        // reach back. The MSR gate's return `B` sits at `gate + 32` and targets
        // `site + 4`, so its displacement magnitude is `b_offset + 28`. Placing
        // the gate at the maximum encodable forward offset (`2^27 - 4`) lets
        // the inbound branch encode while the return needs `-(2^27 + 24)`, just
        // past reach. The site must be trapped gracefully, not error out. The
        // site is at +4 so the trampoline base stays 16-byte aligned.
        let base = 0x1004u64;
        let max_fwd = (1u64 << 27) - 4; // largest 4-aligned forward `B` offset
        let tramp_base = base + max_fwd - GATES_START_OFFSET as u64;
        let (patched, outcome) = hook_words_opt(&[msr_tpidr_el0(5)], base, tramp_base);
        let outcome = outcome.expect("expected a trampoline (input has patch sites)");
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![base]);
        // No gate emitted for the trapped site: prologue-only trampoline.
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }
    #[test]
    fn hvc_and_smc_are_not_treated_as_svc() {
        // `HVC #0` (…02) and `SMC #0` (…03) share the SVC opcode base but differ
        // in bits [1:0]; they must not be rewritten as syscalls.
        let hvc_0 = 0xD400_0002u32;
        let smc_0 = 0xD400_0003u32;
        let (_p, tramp) = hook_words_opt(&[hvc_0, smc_0], 0x1000, 0x200000);
        assert!(tramp.is_none(), "HVC/SMC must not be matched as SVC");
    }
    #[test]
    fn msr_and_mrs_both_get_gates() {
        let base = 0x1000;
        let tramp_base = 0x300000;
        // MSR TPIDR_EL0, X5  then  MRS X9, TPIDR_EL0.
        let words = [msr_tpidr_el0(5), Insn::MrsTpidrEl0(9).encode().unwrap()];
        let (patched, tramp) = hook_words(&words, base, tramp_base);
        // Both the write and the read are rewritten to a branch into their gate.
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(word_at(&patched, 4) & OPCODE_TOP6_MASK, Opcode::B.bits());
        // Trampoline = prologue + one MSR gate + one MRS gate.
        assert_eq!(
            tramp.len(),
            GATES_START_OFFSET + MSR_GATE_SIZE + MRS_GATE_SIZE
        );
    }
    #[test]
    fn mrs_with_xzr_dest_is_left_native() {
        // `MRS XZR, TPIDR_EL0` reads-and-discards; it must not be rewritten.
        let mrs_xzr = Insn::MrsTpidrEl0(31).encode().unwrap();
        let (_p, tramp) = hook_words_opt(&[mrs_xzr], 0x1000, 0x200000);
        assert!(tramp.is_none(), "MRS XZR, TPIDR_EL0 must be left native");
    }
    #[test]
    fn msr_gate_stores_guest_value_to_slot_for_any_register() {
        const BL_TOP6: u32 = 0x9400_0000;
        for n in [5u8, 16, 17, 30, 31] {
            let (_p, tramp) = hook_words(&[msr_tpidr_el0(n)], 0x1000, 0x500000);
            let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + MSR_GATE_SIZE];
            // Self-contained: never BL out.
            assert!(
                (0..MSR_GATE_INSNS).all(|i| word_at(gate, i * 4) & OPCODE_TOP6_MASK != BL_TOP6)
            );
            // Capture the guest value while pristine: STR Xn, [SP, #16].
            let capture = Insn::StrUimm {
                rt: n,
                rn: SP,
                imm_bytes: MSR_FRAME_OFF_VALUE,
            }
            .encode()
            .unwrap();
            let cap_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == capture)
                .expect("MSR gate must capture the guest value (incl. XZR=0) while pristine");
            // Read the host anchor: MRS X16, TPIDR_EL0.
            let anchor = Insn::MrsTpidrEl0(X16).encode().unwrap();
            let anc_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == anchor)
                .expect("MSR gate must read the host anchor");
            // Store to the slot: STR X17, [X16, #<placeholder>].
            let store = Insn::StrUimm {
                rt: X17,
                rn: X16,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }
            .encode()
            .unwrap();
            let st_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == store)
                .expect("MSR gate must store the guest value into its slot");
            assert!(
                cap_i < anc_i && anc_i < st_i,
                "capture -> anchor -> store order"
            );
            // Ends in B back to the guest (not the last word being the store).
            assert_eq!(
                word_at(gate, (MSR_GATE_INSNS - 1) * 4) & OPCODE_TOP6_MASK,
                Opcode::B.bits()
            );
        }
    }
    #[test]
    fn mrs_gate_loads_guest_tp_from_slot() {
        for d in [5u8, 16, 17, 30] {
            let (_p, tramp) =
                hook_words(&[Insn::MrsTpidrEl0(d).encode().unwrap()], 0x1000, 0x400000);
            let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + MRS_GATE_SIZE];
            assert_eq!(word_at(gate, 0), Insn::MrsTpidrEl0(d).encode().unwrap());
            assert_eq!(
                word_at(gate, 4),
                Insn::LdrUimm {
                    rt: d,
                    rn: d,
                    imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
                }
                .encode()
                .unwrap()
            );
            assert_eq!(word_at(gate, 8) & OPCODE_TOP6_MASK, Opcode::B.bits());
        }
    }
    #[test]
    fn svc_gate_saves_only_x16_and_records_return() {
        let base = 0x1000;
        let tramp_base = 0x600000;
        let (_p, tramp) = hook_words(&[SVC_0], base, tramp_base);
        let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + SVC_GATE_SIZE];
        // SUB SP,#32 ; STR X16,[SP] ; ADRP X16,.. ; ADD X16,X16,#.. ;
        // STR X16,[SP,#8] ; ADR X16,stub ; STR X16,[SP,#16] ; LDR callback ; BR.
        assert_eq!(
            word_at(gate, 0),
            Insn::SubSp(SVC_FRAME_BYTES).encode().unwrap()
        );
        assert_eq!(
            word_at(gate, 4),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_X16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(gate, 16),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_RETADDR
            }
            .encode()
            .unwrap()
        );
        // ADR X16, <stub>. Inline callback dispatch puts the stub 16 bytes past
        // this instruction.
        assert_eq!(
            word_at(gate, 20),
            Insn::Adr {
                rd: X16,
                byte_off: 16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(gate, 24),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_STUB
            }
            .encode()
            .unwrap()
        );
        assert_eq!(word_at(gate, 32), Insn::Br(X16).encode().unwrap());
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }
    #[test]
    fn svc_outbound_stub_restores_x16_pops_the_frame_and_returns_to_the_site() {
        // The stub is what makes `X16` survive an `SVC`: it reloads the guest
        // value the runtime staged at `[SP, #0]`, pops the gate frame so `SP`
        // becomes the true guest `SP` again, and branches to `site + 4` with a
        // static direct branch that needs no scratch register.
        let base = 0x1000;
        let tramp_base = 0x600000;
        let (_p, tramp) = hook_words(&[SVC_0], base, tramp_base);
        let stub_off = GATES_START_OFFSET + SVC_GATE_BYTES;
        let stub = &tramp[stub_off..stub_off + SVC_OUTBOUND_STUB_BYTES];

        assert_eq!(
            word_at(stub, 0),
            Insn::LdrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_X16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(stub, 4),
            Insn::AddSp(SVC_FRAME_BYTES).encode().unwrap()
        );

        // The final `B` targets `site + 4`.
        let branch = word_at(stub, 8);
        assert_eq!(branch & OPCODE_TOP6_MASK, Opcode::B.bits());
        let imm26 = i64::from(branch & IMM26_MASK);
        // Sign-extend the 26-bit field, then scale by 4.
        let disp = ((imm26 << 38) >> 38) * 4;
        let branch_vaddr = tramp_base + (stub_off + 8) as u64;
        assert_eq!(
            branch_vaddr.cast_signed() + disp,
            (base + 4).cast_signed(),
            "outbound stub must return to site + 4"
        );
    }
    /// An offset a real host runtime might measure: not the placeholder.
    const MEASURED_OFFSET: u16 = 96;
    #[test]
    fn patch_rewrites_both_gate_shapes_and_leaves_everything_else_alone() {
        // One MSR site and one MRS site, so both patchable shapes are present.
        let (_p, mut tramp) = hook_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );
        let before = tramp.clone();

        let patched = finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap();
        assert_eq!(patched, 2, "one MSR store and one MRS load");

        // Exactly two words changed, and each became the same instruction with
        // the measured offset in place of the placeholder.
        let changed: alloc::vec::Vec<usize> = (0..tramp.len() / 4)
            .filter(|&i| word_at(&tramp, i * 4) != word_at(&before, i * 4))
            .collect();
        assert_eq!(changed.len(), 2);
        for i in changed {
            let old = word_at(&before, i * 4);
            let new = word_at(&tramp, i * 4);
            assert_eq!(
                old & !LDST_UIMM12_IMM_MASK,
                new & !LDST_UIMM12_IMM_MASK,
                "only the immediate field may change"
            );
            assert_eq!(
                (new & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT,
                u32::from(MEASURED_OFFSET / GUEST_TPIDR_OFFSET_ALIGN)
            );
        }

        // Spot-check the exact encodings the gates must now hold.
        let msr_store = Insn::StrUimm {
            rt: X17,
            rn: X16,
            imm_bytes: MEASURED_OFFSET,
        }
        .encode()
        .unwrap();
        let mrs_load = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: MEASURED_OFFSET,
        }
        .encode()
        .unwrap();
        let words: alloc::vec::Vec<u32> = (0..tramp.len() / 4)
            .map(|i| word_at(&tramp, i * 4))
            .collect();
        assert!(words.contains(&msr_store), "MSR gate store must be patched");
        assert!(words.contains(&mrs_load), "MRS gate load must be patched");

        // Patching is idempotent in the sense that a second pass finds nothing:
        // the placeholder is gone.
        assert_eq!(
            finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
    }
    #[test]
    fn patch_leaves_an_svc_only_trampoline_untouched() {
        // The SVC gate and its outbound stub are full of `LDR`/`STR` words with
        // an `SP` base. None of them may be mistaken for a thread-pointer
        // access, and the header's callback slot is data that must be skipped.
        let (_p, mut tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
        let before = tramp.clone();
        assert_eq!(
            finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
        assert_eq!(tramp, before);
    }
    #[test]
    fn patch_skips_a_callback_slot_that_looks_like_a_gate_instruction() {
        // The callback address is arbitrary data. Prefill it with two copies of
        // a word that *is* a placeholder-bearing gate load, and check the patch
        // pass does not touch the header.
        let decoy = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        let callback = (u64::from(decoy) << 32) | u64::from(decoy);
        let mut tramp = hook_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
        assert_eq!(
            finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
        assert_eq!(
            u64::from_le_bytes(tramp[..8].try_into().unwrap()),
            callback,
            "the callback slot is data and must survive verbatim"
        );
    }
    /// The check a loader needs: an unpatched gate does not fault when
    /// executed, so scanning is the only way to detect one. See
    /// `GUEST_TPIDR_OFFSET_PLACEHOLDER`.
    #[test]
    fn find_placeholder_reports_gates_before_patching_and_none_after() {
        let (_p, mut tramp) = hook_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );

        let at = find_guest_tpidr_placeholder(&tramp).expect("an unpatched gate must be found");
        assert!(at >= FIRST_SCANNABLE_OFFSET && at.is_multiple_of(4));

        assert_eq!(
            finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap(),
            2
        );
        assert_eq!(
            find_guest_tpidr_placeholder(&tramp),
            None,
            "patching must leave no gate on the placeholder"
        );
    }
    #[test]
    fn find_placeholder_ignores_svc_gates_and_the_callback_slot() {
        // An SVC-only trampoline has no thread-pointer gate at all, and its
        // `LDR`/`STR` words off `SP` must not be mistaken for one.
        let (_p, tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);

        // The callback slot is a 64-bit address, i.e. data. Even when it
        // happens to spell a placeholder-bearing gate load, it is not one.
        let decoy = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        let callback = (u64::from(decoy) << 32) | u64::from(decoy);
        let tramp = hook_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);
    }
    #[test]
    fn patch_rejects_an_offset_a_gate_cannot_address() {
        let (_p, mut tramp) =
            hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        for bad in [
            // Not a multiple of the LDR scale, so not encodable at all.
            4u16,
            12,
            // Past the top of the imm12 field.
            MAX_GUEST_TPIDR_OFFSET + 8,
            // Inside the host's own per-thread state: patching with one of
            // these would aim every rewritten thread-pointer write at it, and
            // would leave no placeholder behind for anything downstream to
            // object to.
            0,
            8,
            MIN_GUEST_TPIDR_OFFSET - GUEST_TPIDR_OFFSET_ALIGN,
            // The placeholder itself: patching with it is indistinguishable
            // from not having patched.
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
        ] {
            assert!(
                matches!(
                    finalize_trampoline_gates(&mut tramp, bad),
                    Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
                ),
                "offset {bad} must be rejected"
            );
        }
        // The legitimate bounds are accepted, each on its own trampoline:
        // patching is single-shot, since an already-patched gate is
        // indistinguishable from one the guest shipped that way.
        for good in [
            MIN_GUEST_TPIDR_OFFSET,
            GUEST_TPIDR_OFFSET_PLACEHOLDER - GUEST_TPIDR_OFFSET_ALIGN,
        ] {
            let (_p, mut fresh) =
                hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
            assert!(
                finalize_trampoline_gates(&mut fresh, good).is_ok(),
                "offset {good} must be accepted"
            );
        }
    }
    #[test]
    fn classifier_rejects_mrs_xzr_metadata() {
        let base = 0x400000;
        let (_patched, mut trampoline) =
            hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, base);
        let xzr = EncodedGateMetadata::encode(GateMetadata::MrsTpidr { destination: 30 })
            .unwrap()
            .0
            | (1 << GATE_METADATA_REGISTER_SHIFT);
        trampoline[28..32].copy_from_slice(&xzr.to_le_bytes());
        trampoline[16..20].copy_from_slice(&Insn::MrsTpidrEl0(31).encode().unwrap().to_le_bytes());
        trampoline[20..24].copy_from_slice(
            &Insn::LdrUimm {
                rt: 31,
                rn: 31,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }
            .encode()
            .unwrap()
            .to_le_bytes(),
        );

        assert_eq!(EncodedGateMetadata(xzr).decode(), None);
        assert_eq!(classify_gate_pc(&trampoline, base, base + 16), None);
        assert_eq!(
            classify_copied_gate_slot_for_host(
                &trampoline[16..32],
                base + 16,
                base + 16,
                litebox_trampoline::TargetHost::Linux
            ),
            None
        );
    }
    /// A trampoline arrives from the guest's own file, so a gate may hold an
    /// offset this rewriter never emitted. It carries no placeholder, so
    /// nothing downstream would object, and the runtime would execute a gate
    /// addressing a slot it did not choose. Not a containment boundary — the
    /// userland platform shares one address space with the guest — but the
    /// invariant has to hold for thread-pointer virtualization to mean
    /// anything.
    #[test]
    fn patch_rejects_a_gate_holding_a_guest_chosen_thread_pointer_offset() {
        const TAMPERED: u16 = 4096;
        const REQUESTED: u16 = 96;

        let (_p, mut tramp) =
            hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        let site = GATES_START_OFFSET + INSN_BYTES;
        let insn = u32::from_le_bytes(tramp[site..site + INSN_BYTES].try_into().unwrap());
        let tampered_imm = u32::from(TAMPERED / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
        tramp[site..site + INSN_BYTES]
            .copy_from_slice(&((insn & !LDST_UIMM12_IMM_MASK) | tampered_imm).to_le_bytes());

        // The tampered gate carries no placeholder, so the loader's proof
        // obligation is satisfied and only this check stands between it and
        // an executable mapping.
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);
        assert!(matches!(
            finalize_trampoline_gates(&mut tramp, REQUESTED),
            Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
        ));
    }
    #[test]
    fn unaligned_trampoline_base_is_rejected() {
        let mut code = SVC_0.to_le_bytes();
        let section = TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: 4,
        };
        assert!(matches!(
            hook_syscalls_aarch64(
                &mut code,
                &[section],
                0x400004,
                0,
                RewriteConfig::new(TargetHost::Linux, false),
            ),
            Err(Error::AddressOverflow(_))
        ));
    }
    #[test]
    fn slot_padding_and_metadata_do_not_false_match_placeholder_scan() {
        let (_patched, mut tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);
        let before = tramp.clone();
        assert_eq!(
            finalize_trampoline_gates(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
        assert_eq!(tramp, before);
    }
    #[test]
    fn libc_scale_compact_slots_fit_in_64k() {
        let mut words = vec![Insn::MrsTpidrEl0(9).encode().unwrap(); 1_522];
        words.extend(core::iter::repeat_n(SVC_0, 503));
        let (_patched, trampoline) = hook_words(&words, 0x1000, 0x400000);

        assert_eq!(trampoline.len(), 16 + 1_522 * 16 + 503 * 64);
        assert!(trampoline.len() <= 64 * 1024);
    }
    #[test]
    fn compact_mixed_slots_have_exact_strides_and_trailing_metadata() {
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
            Insn::MrsTpidrEl0(3).encode().unwrap(),
        ];
        let (_patched, trampoline) = hook_words(&words, 0x1000, 0x400000);
        let expected = [
            (16, 16, GateMetadata::MrsTpidr { destination: 9 }),
            (32, 48, GateMetadata::MsrTpidr { source: 5 }),
            (80, 64, GateMetadata::Svc),
            (144, 16, GateMetadata::MrsTpidr { destination: 3 }),
        ];

        assert_eq!(trampoline.len(), 160);
        for (start, size, metadata) in expected {
            assert_eq!((0x400000 + start as u64) % 16, 0);
            let encoded = EncodedGateMetadata::encode(metadata)
                .unwrap()
                .0
                .to_le_bytes();
            assert_eq!(&trampoline[start + size - 4..start + size], &encoded);
        }
    }
    #[test]
    fn gates_validate_and_classify_at_high_addresses() {
        // Every gate kind, emitted and then classified far above the 4 GiB reach
        // of an ADRP from address zero, in place and after relocation.
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
            0xaa00_03f2, // mov x18, x0
            0xa9bf_4ff2, // stp x18, x19, [sp, #-16]!
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
            0xf000_0012, // adrp x18, +0x3000
            0xd61f_0240, // br x18
        ];
        for host in [TargetHost::Linux, TargetHost::MacOs] {
            for tramp_base in [0x1_0000_4000u64, 0x7f00_0000_1000] {
                let code_base = tramp_base - 0x10_0000;
                let (_, outcome) =
                    hook_words_opt_with_config(&words, code_base, tramp_base, x18_config(host));
                let outcome = outcome.expect("high-address rewrite must succeed");
                assert_eq!(outcome.trapped_sites, [], "{host:?} at {tramp_base:#x}");
                let trampoline = outcome.trampoline;
                let mut start = GATES_START_OFFSET;
                let mut gates = 0;
                while start < trampoline.len() {
                    let metadata = GATE_SLOT_SIZES
                        .into_iter()
                        .find_map(|size| {
                            let end = start + size;
                            let word =
                                u32::from_le_bytes(trampoline.get(end - 4..end)?.try_into().ok()?);
                            EncodedGateMetadata(word)
                                .decode()
                                .filter(|metadata| metadata.slot_size_for_host(host) == size)
                        })
                        .expect("slot metadata");
                    let size = metadata.slot_size_for_host(host);
                    let slot = &trampoline[start..start + size];
                    // A copied slot keeps its page offset: the SVC gate's ADRP
                    // must keep agreeing with its return branch.
                    let placed = tramp_base + start as u64;
                    for slot_vaddr in [placed, placed + 0x7d00_0000_0000] {
                        for offset in
                            (0..metadata.executable_end_for_host(host)).step_by(INSN_BYTES)
                        {
                            let classified = classify_copied_gate_slot_for_host(
                                slot,
                                slot_vaddr,
                                slot_vaddr + offset as u64,
                                if host == TargetHost::MacOs {
                                    litebox_trampoline::TargetHost::MacOs
                                } else {
                                    litebox_trampoline::TargetHost::Linux
                                },
                            );
                            assert_eq!(
                                classified.map(ClassifiedGate::metadata),
                                Some(metadata),
                                "{host:?} {metadata:?} at {slot_vaddr:#x} + {offset}"
                            );
                        }
                    }
                    start += size;
                    gates += 1;
                }
                assert_eq!(gates, words.len());
            }
        }
    }
    #[test]
    fn classifier_finds_every_instruction_boundary_and_rejects_non_slots() {
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
        ];
        let base = 0x400000;
        let (_patched, trampoline) = hook_words(&words, 0x1000, base);
        for (start, size, executable_end, metadata, site) in [
            (
                16usize,
                16usize,
                12usize,
                GateMetadata::MrsTpidr { destination: 9 },
                0x1000,
            ),
            (32, 48, 36, GateMetadata::MsrTpidr { source: 5 }, 0x1004),
            (80, 64, 48, GateMetadata::Svc, 0x1008),
        ] {
            for offset in (0..executable_end).step_by(INSN_BYTES) {
                let classified =
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64).unwrap();
                assert_eq!(classified.slot_offset(), start);
                assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                assert_eq!(classified.original_site(), site);
                assert_eq!(classified.metadata(), metadata);
                assert_eq!(classified.anchor_scratch(), None);
                assert_eq!(classified.stack_writeback(), None);
                assert_eq!(classified.conditional_target(), None);
            }
        }
        for offset in (0..16).step_by(INSN_BYTES) {
            assert_eq!(classify_gate_pc(&trampoline, base, base + offset), None);
        }
        assert_eq!(classify_gate_pc(&trampoline, base, base + 144), None);
        assert_eq!(classify_gate_pc(&trampoline, base, base - 4), None);
    }
    #[test]
    fn classifier_finds_every_x18_gate_kind() {
        let words = [
            0xaa00_03f2, // mov x18, x0
            0xa9bf_4ff2, // stp x18, x19, [sp, #-16]!
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
            0xd61f_0240, // br x18
        ];
        let base = 0x400000;
        let (_patched, outcome) =
            hook_words_opt_with_config(&words, 0x1000, base, x18_config(TargetHost::Linux));
        let trampoline = outcome.unwrap().trampoline;

        for (index, (start, size)) in [
            (16usize, X18_SLOT_BYTES),
            (16 + X18_SLOT_BYTES, X18_STACK_WRITEBACK_SLOT_BYTES),
            (
                16 + X18_SLOT_BYTES + X18_STACK_WRITEBACK_SLOT_BYTES,
                X18_COMPARE_BRANCH_SLOT_BYTES,
            ),
            (
                16 + X18_SLOT_BYTES
                    + X18_STACK_WRITEBACK_SLOT_BYTES
                    + X18_COMPARE_BRANCH_SLOT_BYTES,
                X18_ADR_SLOT_BYTES,
            ),
            (
                16 + X18_SLOT_BYTES
                    + X18_STACK_WRITEBACK_SLOT_BYTES
                    + X18_COMPARE_BRANCH_SLOT_BYTES
                    + X18_ADR_SLOT_BYTES,
                X18_BRANCH_SLOT_BYTES,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let metadata = EncodedGateMetadata(u32::from_le_bytes(
                trampoline[start + size - 4..start + size]
                    .try_into()
                    .unwrap(),
            ))
            .decode()
            .unwrap();
            assert!(match index {
                0 => matches!(metadata, GateMetadata::X18 { .. }),
                1 => matches!(metadata, GateMetadata::X18StackWriteback { .. }),
                2 => matches!(metadata, GateMetadata::X18CompareBranch { .. }),
                3 => matches!(metadata, GateMetadata::X18Adr { .. }),
                4 => matches!(metadata, GateMetadata::X18Branch { .. }),
                _ => unreachable!(),
            });
            for offset in
                (0..metadata.executable_end_for_host(TargetHost::Linux)).step_by(INSN_BYTES)
            {
                let classified =
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64)
                        .expect("emitted x18 slot must classify");
                assert_eq!(classified.slot_offset(), start);
                assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                assert_eq!(classified.metadata(), metadata);
            }
        }
    }
    #[test]
    fn copied_slot_classifier_finds_every_instruction_boundary() {
        let words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
        ];
        let base = 0x400000;
        let (_patched, trampoline) = hook_words(&words, 0x1000, base);
        for (start, size, executable_end, metadata) in [
            (
                16usize,
                16usize,
                12usize,
                GateMetadata::MrsTpidr { destination: 9 },
            ),
            (32, 48, 36, GateMetadata::MsrTpidr { source: 5 }),
            (80, 64, 48, GateMetadata::Svc),
        ] {
            let slot = &trampoline[start..start + size];
            for offset in (0..executable_end).step_by(INSN_BYTES) {
                let classified = classify_copied_gate_slot_for_host(
                    slot,
                    base + start as u64,
                    base + (start + offset) as u64,
                    litebox_trampoline::TargetHost::Linux,
                )
                .expect("emitted slot must classify");
                assert_eq!(classified.slot_offset(), 0);
                assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                assert_eq!(classified.metadata(), metadata);
            }
        }

        let (_patched, outcome) = hook_words_opt_with_config(
            &[0xa9bf_4ff2], // stp x18, x19, [sp, #-16]!
            0x1000,
            base,
            x18_config(TargetHost::Linux),
        );
        let trampoline = outcome.unwrap().trampoline;
        let slot = &trampoline[GATES_START_OFFSET..];
        let executable_end = GateMetadata::X18StackWriteback { scratch: 17 }
            .executable_end_for_host(TargetHost::Linux);
        assert_eq!(executable_end, 52);
        for offset in (0..executable_end).step_by(INSN_BYTES) {
            let classified = classify_copied_gate_slot_for_host(
                slot,
                base + GATES_START_OFFSET as u64,
                base + (GATES_START_OFFSET + offset) as u64,
                litebox_trampoline::TargetHost::Linux,
            )
            .expect("emitted x18 stack-writeback slot must classify");
            assert_eq!(classified.slot_offset(), 0);
            assert_eq!(
                classified.slot_size(),
                u8::try_from(X18_STACK_WRITEBACK_SLOT_BYTES).unwrap()
            );
            assert!(matches!(
                classified.metadata(),
                GateMetadata::X18StackWriteback { .. }
            ));
        }
    }
    #[test]
    fn classifier_rejects_forged_metadata_mutations_and_ambiguity() {
        let base = 0x400000;
        let (_patched, trampoline) = hook_words(
            &[
                Insn::MrsTpidrEl0(9).encode().unwrap(),
                msr_tpidr_el0(5),
                SVC_0,
            ],
            0x1000,
            base,
        );
        for (start, size) in [(16usize, 16usize), (32, 48), (80, 64)] {
            for word_offset in (0..size - 4).step_by(INSN_BYTES) {
                let mut mutated = trampoline.clone();
                let replacement = if word_at(&mutated, start + word_offset) == NOP {
                    0
                } else {
                    NOP
                };
                mutated[start + word_offset..start + word_offset + 4]
                    .copy_from_slice(&replacement.to_le_bytes());
                assert_eq!(
                    classify_gate_pc(&mutated, base, base + start as u64),
                    None,
                    "accepted mutation at slot {start} + {word_offset}"
                );
            }
        }

        let mut forged = trampoline.clone();
        forged[12..16].copy_from_slice(
            &EncodedGateMetadata::encode(GateMetadata::MrsTpidr { destination: 9 })
                .unwrap()
                .0
                .to_le_bytes(),
        );
        assert_eq!(classify_gate_pc(&forged, base, base), None);

        assert_eq!(
            classify_gate_pc_with_candidates(&trampoline, base, base + 32, [32, 32, 16, 0]),
            None,
            "more than one validated candidate must be rejected"
        );
    }
    #[test]
    fn classifier_validates_tpidr_immediate_policy() {
        let base = 0x400000;
        let (_patched, trampoline) = hook_words(
            &[Insn::MrsTpidrEl0(9).encode().unwrap(), msr_tpidr_el0(5)],
            0x1000,
            base,
        );
        for (slot_start, insn_offset) in [(16usize, 4usize), (32, 20)] {
            for valid in [
                GUEST_TPIDR_OFFSET_PLACEHOLDER,
                MIN_GUEST_TPIDR_OFFSET,
                96,
                GUEST_TPIDR_OFFSET_PLACEHOLDER - GUEST_TPIDR_OFFSET_ALIGN,
            ] {
                let mut candidate = trampoline.clone();
                set_tpidr_immediate(&mut candidate, slot_start + insn_offset, valid);
                assert!(
                    classify_gate_pc(&candidate, base, base + slot_start as u64).is_some(),
                    "rejected valid offset {valid}"
                );
            }
            for invalid in [0, 8] {
                let mut candidate = trampoline.clone();
                set_tpidr_immediate(&mut candidate, slot_start + insn_offset, invalid);
                assert_eq!(
                    classify_gate_pc(&candidate, base, base + slot_start as u64),
                    None,
                    "accepted host-header offset {invalid}"
                );
            }

            // Raw imm12 encodings are scaled by eight. A byte offset that is
            // not 8-aligned cannot be represented; pin rejection by mutating
            // the instruction to an impossible policy value below the minimum.
            let mut non_aligned = trampoline.clone();
            set_tpidr_immediate(&mut non_aligned, slot_start + insn_offset, 8);
            assert_eq!(
                classify_gate_pc(&non_aligned, base, base + slot_start as u64),
                None
            );
        }
    }
    #[test]
    fn macos_copied_slot_classifier_covers_expanded_instructions_and_padding() {
        let base = 0x400000;
        let normal_words = [
            Insn::MrsTpidrEl0(9).encode().unwrap(),
            msr_tpidr_el0(5),
            SVC_0,
        ];
        let (_, normal) = hook_words_opt_with_config(
            &normal_words,
            0x1000,
            base,
            RewriteConfig::new(litebox_trampoline::TargetHost::MacOs, true),
        );
        let x18_words = [
            0xaa00_03f2, // mov x18, x0
            0xa9bf_4ff2, // stp x18, x19, [sp, #-16]!
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
            0xd61f_0240, // br x18
        ];
        let (_, x18) =
            hook_words_opt_with_config(&x18_words, 0x2000, base, x18_config(TargetHost::MacOs));

        for (trampoline, sizes) in [
            (normal.unwrap().trampoline, vec![32, 64, 64]),
            (x18.unwrap().trampoline, vec![64, 80, 64, 48, 16]),
        ] {
            let mut start = GATES_START_OFFSET;
            for size in sizes {
                let slot = &trampoline[start..start + size];
                let metadata = EncodedGateMetadata(u32::from_le_bytes(
                    slot[size - GATE_METADATA_BYTES..].try_into().unwrap(),
                ))
                .decode()
                .unwrap();
                let executable_end = metadata.executable_end_for_host(TargetHost::MacOs);
                for offset in (0..executable_end).step_by(INSN_BYTES) {
                    let classified = classify_copied_gate_slot_for_host(
                        slot,
                        base + start as u64,
                        base + (start + offset) as u64,
                        litebox_trampoline::TargetHost::MacOs,
                    )
                    .expect("emitted macOS slot must classify");
                    assert_eq!(classified.slot_offset(), 0);
                    assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                    assert_eq!(classified.metadata(), metadata);
                }

                // The MSR slot's second recovery branch lies beyond its
                // guest-attributable range and immediately precedes metadata.
                // All remaining pre-metadata words are validated padding.
                let padding_start = match metadata {
                    GateMetadata::MsrTpidr { .. } => size - GATE_METADATA_BYTES,
                    GateMetadata::X18Branch { .. } => 8,
                    _ => executable_end,
                };
                for padding in (padding_start..size - GATE_METADATA_BYTES).step_by(INSN_BYTES) {
                    assert_eq!(
                        u32::from_le_bytes(slot[padding..padding + 4].try_into().unwrap()),
                        NOP
                    );
                    let mut corrupted = slot.to_vec();
                    corrupted[padding..padding + 4]
                        .copy_from_slice(&Insn::Brk(0).encode().unwrap().to_le_bytes());
                    assert_eq!(
                        classify_copied_gate_slot_for_host(
                            &corrupted,
                            base + start as u64,
                            base + start as u64,
                            litebox_trampoline::TargetHost::MacOs,
                        ),
                        None
                    );
                }
                start += size;
            }
        }
    }
    #[test]
    fn classifier_accepts_only_aligned_executable_instruction_pcs() {
        let base = 0x400000;
        let (_patched, trampoline) = hook_words(
            &[
                Insn::MrsTpidrEl0(9).encode().unwrap(),
                msr_tpidr_el0(5),
                SVC_0,
            ],
            0x1000,
            base,
        );
        for (start, executable_end, slot_size) in
            [(16usize, 12usize, 16usize), (32, 36, 48), (80, 48, 64)]
        {
            for offset in (0..executable_end).step_by(INSN_BYTES) {
                assert!(
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64).is_some(),
                    "rejected executable PC at slot {start} + {offset}"
                );
                for byte in 1..4 {
                    assert_eq!(
                        classify_gate_pc(&trampoline, base, base + (start + offset + byte) as u64,),
                        None,
                        "accepted unaligned PC at slot {start} + {}",
                        offset + byte
                    );
                }
            }
            for offset in (executable_end..slot_size - 4).step_by(INSN_BYTES) {
                assert_eq!(
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64),
                    None,
                    "accepted padding PC at slot {start} + {offset}"
                );
            }
            for byte in 0..4 {
                assert_eq!(
                    classify_gate_pc(
                        &trampoline,
                        base,
                        base + (start + slot_size - 4 + byte) as u64,
                    ),
                    None,
                    "accepted metadata PC at slot {start} + {}",
                    slot_size - 4 + byte
                );
            }
        }
    }
    #[test]
    fn patch_is_transactional_when_a_later_slot_is_malformed() {
        let (_patched, mut trampoline) = hook_words(
            &[Insn::MrsTpidrEl0(9).encode().unwrap(), msr_tpidr_el0(5)],
            0x1000,
            0x400000,
        );
        trampoline[32] ^= 1; // Corrupt the later MSR template.
        let before = trampoline.clone();

        assert!(matches!(
            finalize_trampoline_gates(&mut trampoline, MEASURED_OFFSET),
            Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(
            trampoline, before,
            "failed patching must not mutate earlier slots"
        );
    }
    #[test]
    fn patch_rejects_trailing_unknown_and_placeholder_like_content() {
        let (_patched, trampoline) = hook_words(&[SVC_0], 0x1000, 0x400000);
        for suffix in [
            NOP.to_le_bytes().to_vec(),
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }
            .encode()
            .unwrap()
            .to_le_bytes()
            .to_vec(),
        ] {
            let mut malformed = trampoline.clone();
            malformed.extend_from_slice(&suffix);
            let before = malformed.clone();
            assert!(matches!(
                finalize_trampoline_gates(&mut malformed, MEASURED_OFFSET),
                Err(litebox_trampoline::Error::TrampolinePatchFailure(_))
            ));
            assert_eq!(malformed, before);
        }
    }
    fn set_tpidr_immediate(trampoline: &mut [u8], offset: usize, byte_offset: u16) {
        let word = word_at(trampoline, offset);
        let immediate = u32::from(byte_offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
        trampoline[offset..offset + 4]
            .copy_from_slice(&((word & !LDST_UIMM12_IMM_MASK) | immediate).to_le_bytes());
    }
}
