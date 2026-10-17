// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 syscall and thread-pointer gates.
//!
//! Instructions are a fixed 4 bytes and `B imm26` reaches ±128MB, so a site is
//! replaced in place by a branch into its trampoline gate. A site out of that
//! reach becomes a breakpoint and is reported as trapped, which makes
//! the ELF-level caller reject the binary with `Error::UnpatchableSyscalls`.
//! Executing the `BRK` faults the guest instead of letting an unpatched
//! instruction reach the host kernel.
//!
//! Gated forms:
//!
//! * `SVC #imm` — syscall. The gate records the return address and tail-jumps
//!   through the trampoline header's callback pointer.
//! * `MSR TPIDR_EL0, Xn` — an in-place private breakpoint; the runtime stores
//!   Xn to the guest slot and resumes at the next instruction. It needs no
//!   guest stack and handles XZR and virtualized x18 sources.
//! * `MRS Xd, TPIDR_EL0` — thread-pointer read, loaded from it. `MRS XZR,
//!   TPIDR_EL0` is a discarded read and is left native.
//! * Darwin `SVC #0x80` — syscall, preserving the 128-byte red zone.
//! * `MRS Xd, TPIDRRO_EL0` — Darwin thread-pointer read.
//!
//! ### Assumption: executable sections contain only instructions
//!
//! The scan walks each executable section word-by-word and cannot tell inline
//! data — literal pools, jump tables — from code, so a data word matching a
//! gated encoding inside `.text` is rewritten. Default AArch64 codegen puts
//! constants in `.rodata`. TODO: bound the scan to `STT_FUNC` extents.
//!
//! ## Thread-pointer virtualization
//!
//! TLS gates access runtime-owned guest state through the selected host anchor.
//! Direct-TLS gates access anchor-relative fields; indirect-TLS gates load a
//! block pointer from an anchor-relative runtime slot first.
//!
//! Guest thread-pointer reads use `TPIDR_EL0` for ELF or `TPIDRRO_EL0` for
//! Mach-O. `TPIDRRO_EL0` is read-only at EL0, so there is no userspace write
//! to virtualize.
//!
//! ELF callers must finalize placeholders with [`finalize_trampoline_gates`]
//! (Linux without x18) or [`finalize_trampoline_gates_for_host`] before execution.
//! [`crate::macho::Rewriter::patch_code_segment`] returns finalized gates.
//! Unpatched gates can corrupt host memory without faulting.
//!
//! ## Gate scratch storage
//!
//! `SVC` clobbers no registers, so its gate spills to a frame carved from
//! the guest stack with `SUB`/`ADD SP` and **requires `SP` to
//! address a valid, writable, 16-byte-aligned stack at the patched site** — the
//! same condition the kernel relies on to write a signal frame. A site reached
//! with `SP` unmapped faults where the native instruction would not. The MRS
//! gate uses its destination as scratch and needs no frame. Persisted old MSR
//! stack gates remain recognized. Writes in identified exclusive regions keep
//! that inline form so a breakpoint cannot force every STXR retry to fail.
//!
//! X18 gates add memory accesses that can clear the local exclusive monitor, so
//! the scanner rejects x18 sites lexically bracketed by an exclusive load and
//! store. TODO: use function metadata and control flow to cover noncontiguous
//! exclusive sequences.
//!
//! X18 gates require writable stack below SP. SP-writeback pairs may spill as
//! deep as `align_up(16 + max(0, -writeback), 16)`. This extra spill can fault
//! even when the native guest instruction would succeed; such a runtime spill
//! fault is not attributed to the guest instruction. Arbitrary-register
//! aliasing is unsupported; SP-pair accesses are checked not to overlap it.
//!
//! ## `X16` is preserved across an `SVC`
//!
//! Linux preserves every register but `x0` across an `SVC`, and `X16` is the
//! SVC gate's only scratch. The gate spills guest `X16` to `[SP, #0]`, records
//! the return address and this site's *outbound stub* in the frame, then enters
//! the callback. The runtime returns through the stub:
//!
//! ```text
//! outbound_N:
//!     mrs x16, tpidr_el0    // Linux host anchor (macOS uses TPIDRRO + key)
//!     ldr x16, [x16, #slot] // restore guest X16 from runtime TLS
//!     add sp, sp, #32        // pop the gate frame
//!     b   site+4             // static target; needs no scratch register
//! ```
//!
//! AArch64 has no memory-indirect branch, so a runtime-side branch back into
//! the guest would burn a register on its target; a static branch in
//! guest-adjacent code does not. Before returning, the runtime stages
//! `PtRegs::regs[16]` in its own TLS slot. It never restages the guest frame.
//! A signal in the stub canonicalizes to `site+4` before a guest handler runs,
//! freeing that slot for nested syscalls. Old stack-restoring stubs remain
//! recognized; the runtime uses full-context restore instead of entering them.
//!
//! The stub only resumes at the original site. A redirected `PC` (signals,
//! `execve`) or an asynchronous resume is instead handled by synthesizing an
//! `rt_sigreturn` frame, restoring all 31 GPRs, `PC` and `PSTATE` at once.
//!
//! ## Gate templates
//!
//! Each gate kind's code is defined once, in the `gate` submodule. Every
//! emitted instruction carries a validation role and a recovery
//! [`Stage`]; slot validation, TLS-offset finalization and signal recovery all
//! derive from that one definition rather than from per-kind offset tables.
//!
//! ## Trampoline layout
//!
//! A callback address slot, then gate-aligned per-site slots each ending in a
//! metadata word; `HEADER_CALLBACK_OFFSET`, `GATES_START_OFFSET` and the
//! `*_SLOT_BYTES` constants define the offsets and sizes.
//! [`crate::hook_syscalls_in_elf`] writes zero into the callback slot when its
//! caller supplies no address, leaving the loader to fill it in before the
//! trampoline is executable. A binary with no patch sites gets no trampoline,
//! only a size-0 sentinel header, matching the x86-64 path.
//!
//! `rt_sigreturn` needs no gate: the runtime installs its own trampoline
//! address into the signal frame, and an absolute address is reachable
//! regardless of branch range.
//!
//! ## Guest x18 limits
//!
//! X18 virtualization handles ordinary register substitutions, `CBZ`/`CBNZ`,
//! `TBZ`/`TBNZ`, `ADC`/`SBC`, `UDIV`/`SDIV`, `ADR`/`ADRP`, and unauthenticated
//! `BR`/`BLR`/`RET` through x18. Other unsupported decoder layouts, other
//! PC-relative forms, and authenticated control flow through x18 reject AOT
//! rewriting and become traps during runtime rewriting.

mod gate;

use alloc::format;
use alloc::string::ToString as _;
use alloc::vec::Vec;
use core::ops::Range;
use object::read::{Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction as DecodedInstruction, Opcode as DecodedOpcode, Operand,
};
use zerocopy::IntoBytes as _;

use crate::{
    Error, InternalError, Result, TextSectionInfo, checked_add_u64, fixup_phdr_alignment,
    text_sections,
};

// ============================================================
// Recovery semantics shared by gate templates and platform signal handlers
// ============================================================

/// Where gate-saved guest registers live at an instruction boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    /// No gate frame exists.
    None,
    /// A frame exists at the given base, but the registers it saves still
    /// hold their guest values.
    Live(FrameBase),
    /// A frame exists at the given base and the registers it saves must be
    /// restored from it.
    Restore(FrameBase),
}

/// Address of the gate frame, relative to the interrupted context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameBase {
    /// The interrupted SP.
    Sp,
    /// One frame below the interrupted SP (the frame was popped early).
    BelowSp,
    /// The value held in the gate's anchor scratch register.
    Anchor,
}

/// How recovery reconstructs the guest SP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestSp {
    /// The interrupted SP is the guest's.
    Signal,
    /// The guest SP is the end of the gate frame.
    FrameEnd,
    /// The guest SP is the end of the gate frame plus the guest instruction's
    /// own SP writeback.
    FrameEndPlusDelta,
}

/// Source of the logical value the gate virtualizes: guest x18 for x18 gates,
/// or the MRS destination for thread-pointer reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// The architectural register already holds the logical value, or the gate
    /// virtualizes none.
    None,
    /// Read it from the runtime's guest slot.
    Slot,
    /// Read it from the gate's value scratch register.
    Scratch,
}

/// Guest PC reported after recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// The original patch site: the guest instruction has not taken effect.
    Site,
    /// The instruction after the site: the guest instruction completed.
    Next,
    /// The original compare/test branch's taken target.
    Taken,
    /// The logical x18 value: an emulated indirect branch through x18.
    LogicalX18,
}

/// Recovery semantics for a context interrupted before one gate instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub frame: Frame,
    pub sp: GuestSp,
    pub value: Value,
    pub resume: Resume,
    /// A synchronous fault here belongs to the runtime, not the guest.
    pub runtime_fault: bool,
    /// The MSR gate's staged source copy must equal the architectural source.
    pub check_capture: bool,
}

/// Recovery classification of one executable gate instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Canonicalize with these semantics.
    Recover(Boundary),
    /// The SVC gate's outbound stub, the runtime-owned return path.
    SvcOutbound,
    /// A TLS-backed SVC outbound instruction. The runtime must first check
    /// this is its recorded outbound stub; then normal recovery applies.
    SvcTlsOutbound(Boundary),
    /// Reachable only if a runtime invariant was violated.
    Invalid,
}

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

// ============================================================
// Constants
// ============================================================

/// `SVC #0` (supervisor call) — the canonical syscall instruction.
const SVC_0: u32 = 0xD400_0001;

/// `SVC #0x80`, used by Darwin syscall stubs.
const DARWIN_SVC: u32 = 0xD400_1001;

/// Mask/match for *any* `SVC #imm16`. Linux dispatches every `SVC64` exception
/// to the syscall handler regardless of the immediate (the syscall number comes
/// from `x8`), so all immediates are rewritten, not just `svc #0`. The `imm16`
/// field occupies bits \[20:5]; masking it out leaves bits \[4:0] = `0b00001`,
/// which distinguishes `SVC` from `HVC` (`…0b10`) and `SMC` (`…0b11`).
const SVC_OPCODE_MASK: u32 = 0xFFE0_001F;
const SVC_OPCODE_BITS: u32 = SVC_0;

/// Mask/match for `MSR TPIDR_EL0, Xt` (`0xD51BD04t`, the low 5 bits select Xt).
const MSR_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MSR_TPIDR_EL0_BITS: u32 = 0xD51B_D040;

/// Mask/match for `MRS Xd, TPIDR_EL0` (`0xD53BD04d`, the low 5 bits select Xd).
const MRS_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MRS_TPIDR_EL0_BITS: u32 = 0xD53B_D040;

/// `BRK` immediate planted at a patch site whose gate is out of `B` reach.
/// Executing it raises a synchronous debug exception (`SIGTRAP`) carrying this
/// immediate instead of letting the unpatched instruction escape to the host
/// kernel.
///
/// TODO: recognize this immediate in the runtime, to tell a rewriter trap from
/// a guest breakpoint.
const TRAP_BRK_IMM: u16 = 0xB10B;
/// `BRK` immediate used by the transparent `BR X18` trap gate.
const X18_BRANCH_BRK_IMM: u16 = 0xB18;

/// Private breakpoint namespace for a guest `MSR TPIDR_EL0, Xn`. The low five
/// immediate bits encode Xn (31 means XZR); no stack or out-of-line gate is
/// needed. The runtime consumes only a synchronous breakpoint with this tag.
const MSR_TPIDR_BRK_BASE: u16 = 0xB200;

/// Distinguishes the new TLS-restoring SVC outbound stub from the persisted
/// stack-restoring one. Callers use this only for a recorded outbound address;
/// it is a format discriminator, not authentication of guest code.
pub fn svc_stub_uses_tls(first_word: u32, host: crate::TargetHost) -> bool {
    Host::from(host).anchor_read(X16).encode() == Some(first_word)
}

/// Decode an in-place guest thread-pointer-write breakpoint's source register.
pub fn decode_msr_tpidr_trap(word: u32) -> Option<u8> {
    let immediate = ((word >> 5) & 0xffff) as u16;
    (word & 0xffe0_001f == Opcode::Brk.bits() && immediate & !31 == MSR_TPIDR_BRK_BASE)
        .then_some((immediate & 31) as u8)
}

/// Alignment every emitted gate slot starts on.
pub const GATE_ALIGNMENT: usize = 16;
/// Byte size of a direct-TLS `MRS TPIDR_EL0` gate slot.
pub const MRS_SLOT_BYTES: usize = 16;
/// Byte size of a host-aware Darwin shared-cache TPIDRRO gate.
const HOST_AWARE_MRS_SLOT_BYTES: usize = 64;
/// Offset of the runtime's guest-mode word from its guest-TP field.
pub const IN_GUEST_OFFSET_FROM_GUEST_TP: u16 = 32;
/// Byte size of a direct-TLS `MSR TPIDR_EL0` gate slot.
pub const MSR_SLOT_BYTES: usize = 48;
/// Byte size of a Linux or legacy `SVC` gate slot. A macOS TLS-returning
/// slot adds one alignment unit for its TLS-independent native epilogue.
pub const SVC_SLOT_BYTES: usize = 64;
/// Byte size of a direct-TLS ordinary x18 gate slot.
const X18_SLOT_BYTES: usize = 48;
/// Byte size of a direct-TLS x18 compare/test-branch gate slot.
const X18_COMPARE_BRANCH_SLOT_BYTES: usize = 48;
/// Byte size of a direct-TLS `ADR X18` gate slot.
const X18_ADR_SLOT_BYTES: usize = 32;
/// Byte size of a direct-TLS immediate SP-writeback pair x18 gate slot.
const X18_STACK_WRITEBACK_SLOT_BYTES: usize = 64;
/// Byte size of a terminal `BR X18` trap gate slot.
const X18_BRANCH_SLOT_BYTES: usize = 16;
/// Distinct compact-slot sizes probed by classifiers and finalizers. Metadata
/// distinguishes gate kinds that share a slot size.
pub const GATE_SLOT_SIZES: [usize; 5] = [
    MRS_SLOT_BYTES,
    X18_ADR_SLOT_BYTES,
    MSR_SLOT_BYTES,
    SVC_SLOT_BYTES,
    X18_STACK_WRITEBACK_SLOT_BYTES + GATE_ALIGNMENT,
];
/// Largest compact gate slot on any supported host.
pub const MAX_GATE_SLOT_BYTES: usize = X18_STACK_WRITEBACK_SLOT_BYTES + GATE_ALIGNMENT;
/// Candidate starts required to cover the largest executable gate body.
pub const GATE_PC_CANDIDATE_COUNT: usize = MAX_GATE_SLOT_BYTES / GATE_ALIGNMENT;
const NOP: u32 = 0xD503_201F;

const GATE_METADATA_MAGIC: u32 = 0xB807;
const GATE_METADATA_VERSION: u32 = 1;
const GATE_METADATA_MAGIC_MASK: u32 = 0xffff;
const GATE_METADATA_VERSION_SHIFT: u32 = 16;
const GATE_METADATA_VERSION_MASK: u32 = 0xf << GATE_METADATA_VERSION_SHIFT;
const GATE_METADATA_KIND_SHIFT: u32 = 20;
const GATE_METADATA_KIND_MASK: u32 = 0xf << GATE_METADATA_KIND_SHIFT;
const GATE_METADATA_REGISTER_SHIFT: u32 = 24;
const GATE_METADATA_REGISTER_MASK: u32 = 0x3f << GATE_METADATA_REGISTER_SHIFT;

/// The metadata word's `kind` field.
///
/// A persisted format: these discriminants are baked into every rewritten
/// binary, so an existing one may never be renumbered.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum GateKind {
    Svc = 0,
    MrsTpidr = 1,
    MsrTpidr = 2,
    X18 = 3,
    X18CompareBranch = 4,
    X18Adr = 5,
    X18Branch = 6,
    X18StackWriteback = 7,
    HostAwareMrsTpidr = 8,
    SvcTls = 9,
}

impl GateKind {
    const fn bits(self) -> u32 {
        self as u32
    }

    fn from_bits(bits: u32) -> Option<Self> {
        [
            Self::Svc,
            Self::MrsTpidr,
            Self::MsrTpidr,
            Self::X18,
            Self::X18CompareBranch,
            Self::X18Adr,
            Self::X18Branch,
            Self::X18StackWriteback,
            Self::HostAwareMrsTpidr,
            Self::SvcTls,
        ]
        .into_iter()
        .find(|kind| kind.bits() == bits)
    }
}

/// Highest register number a 5-bit register field can name.
const MAX_REGISTER: u8 = 31;
const GATE_METADATA_USED_MASK: u32 = GATE_METADATA_MAGIC_MASK
    | GATE_METADATA_VERSION_MASK
    | GATE_METADATA_KIND_MASK
    | GATE_METADATA_REGISTER_MASK;

/// Which kind of gate a compact slot holds, and the register it acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateMetadata {
    /// A trapped `SVC`: the shim performs the syscall.
    Svc,
    /// SVC with an outbound stub restoring x16 from runtime TLS. The separate
    /// persisted kind keeps old stack-restoring SVC slots unambiguous.
    SvcTls,
    /// Read the logical guest thread pointer into the destination register.
    MrsTpidr {
        /// Register the guest thread pointer is read into.
        destination: u8,
    },
    /// Read TPIDRRO from the physical host or private guest state according to
    /// the current LiteBox execution mode.
    HostAwareMrsTpidr { destination: u8 },
    /// A legacy inline `MSR TPIDR_EL0, <Xs>` gate. Ordinary writes use an
    /// in-place breakpoint; old slots and writes in recognized exclusive
    /// regions retain this form.
    MsrTpidr {
        /// Register holding the value to write.
        source: u8,
    },
    /// An ordinary instruction with every integer x18 operand replaced by the
    /// selected value scratch register.
    X18 {
        /// Scratch register substituted for x18.
        scratch: u8,
    },
    /// A compare/test branch (`CBZ`/`CBNZ`/`TBZ`/`TBNZ`) on logical x18.
    X18CompareBranch {
        /// Scratch register substituted in the gate-local branch.
        scratch: u8,
    },
    /// An `ADR X18` materialized through `scratch`.
    X18Adr {
        /// Scratch register receiving the absolute address.
        scratch: u8,
    },
    /// An indirect branch through logical x18 emulated by the exception handler.
    X18Branch { kind: X18IndirectBranchKind },
    /// An immediate, SP-based `STP`/`LDP` with pre/post-index writeback.
    X18StackWriteback { scratch: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X18IndirectBranchKind {
    Br = 0,
    Blr = 1,
    Ret = 2,
}

impl X18IndirectBranchKind {
    pub const fn writes_link_register(self) -> bool {
        matches!(self, Self::Blr)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodedGateMetadata(u32);

impl EncodedGateMetadata {
    pub(crate) fn encode(metadata: GateMetadata) -> Option<Self> {
        if matches!(
            metadata,
            GateMetadata::MrsTpidr { destination: XZR }
                | GateMetadata::HostAwareMrsTpidr { destination: XZR }
        ) {
            return None;
        }
        let (kind, register) = match metadata {
            GateMetadata::Svc => (GateKind::Svc, 0),
            GateMetadata::SvcTls => (GateKind::SvcTls, 0),
            GateMetadata::MrsTpidr { destination } => (GateKind::MrsTpidr, destination),
            GateMetadata::HostAwareMrsTpidr { destination } => {
                (GateKind::HostAwareMrsTpidr, destination)
            }
            GateMetadata::MsrTpidr { source } => (GateKind::MsrTpidr, source),
            GateMetadata::X18 { scratch } => (GateKind::X18, scratch),
            GateMetadata::X18CompareBranch { scratch } => (GateKind::X18CompareBranch, scratch),
            GateMetadata::X18Adr { scratch } => (GateKind::X18Adr, scratch),
            GateMetadata::X18Branch { kind } => (GateKind::X18Branch, kind as u8),
            GateMetadata::X18StackWriteback { scratch } => (GateKind::X18StackWriteback, scratch),
        };
        if register > MAX_REGISTER {
            return None;
        }
        Some(Self(
            GATE_METADATA_MAGIC
                | (GATE_METADATA_VERSION << GATE_METADATA_VERSION_SHIFT)
                | (kind.bits() << GATE_METADATA_KIND_SHIFT)
                | (u32::from(register) << GATE_METADATA_REGISTER_SHIFT),
        ))
    }

    pub(crate) fn decode(self) -> Option<GateMetadata> {
        let word = self.0;
        if word & GATE_METADATA_MAGIC_MASK != GATE_METADATA_MAGIC
            || (word & GATE_METADATA_VERSION_MASK) >> GATE_METADATA_VERSION_SHIFT
                != GATE_METADATA_VERSION
            || word & !GATE_METADATA_USED_MASK != 0
        {
            return None;
        }
        let kind =
            GateKind::from_bits((word & GATE_METADATA_KIND_MASK) >> GATE_METADATA_KIND_SHIFT)?;
        let register = ((word & GATE_METADATA_REGISTER_MASK) >> GATE_METADATA_REGISTER_SHIFT) as u8;
        if register > MAX_REGISTER {
            return None;
        }
        match kind {
            GateKind::Svc if register == 0 => Some(GateMetadata::Svc),
            GateKind::SvcTls if register == 0 => Some(GateMetadata::SvcTls),
            GateKind::MrsTpidr if register != XZR => Some(GateMetadata::MrsTpidr {
                destination: register,
            }),
            GateKind::HostAwareMrsTpidr if register != XZR => {
                Some(GateMetadata::HostAwareMrsTpidr {
                    destination: register,
                })
            }
            GateKind::MsrTpidr => Some(GateMetadata::MsrTpidr { source: register }),
            GateKind::X18 if register != XZR => Some(GateMetadata::X18 { scratch: register }),
            GateKind::X18CompareBranch if register != XZR => {
                Some(GateMetadata::X18CompareBranch { scratch: register })
            }
            GateKind::X18Adr if register != XZR => Some(GateMetadata::X18Adr { scratch: register }),
            GateKind::X18Branch => Some(GateMetadata::X18Branch {
                kind: match register {
                    0 => X18IndirectBranchKind::Br,
                    1 => X18IndirectBranchKind::Blr,
                    2 => X18IndirectBranchKind::Ret,
                    _ => return None,
                },
            }),
            GateKind::X18StackWriteback if register != XZR => {
                Some(GateMetadata::X18StackWriteback { scratch: register })
            }
            _ => None,
        }
    }
}

// --- Register operands used by the emitted gates/handlers ---
//
// X16/X17 are the intra-procedure scratch registers (IP0/IP1), and register
// number 31 names the stack pointer in a base-register position.

/// First scratch register (IP0).
const X16: u8 = 16;
const X8: u8 = 8;
/// Second scratch register (IP1).
const X17: u8 = 17;
/// Stack pointer (encoded as register 31 in a base-register field).
const SP: u8 = 31;
/// Zero register (register 31 in a transfer-register field, where it reads as
/// zero / discards writes — distinct from `SP`'s base-register meaning).
const XZR: u8 = 31;

const X18: u16 = 18;
const X18_ENCODED: u8 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18Classification {
    None,
    Branch(X18IndirectBranchKind),
    X18(X18TransformResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodedX18Classification {
    None,
    Ordinary,
    Unsupported(X18Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18TransformResult {
    Supported(X18Substitution),
    Unsupported(X18Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18Substitution {
    word: u32,
    scratch: u8,
    anchor_scratch: u8,
    pc_relative: Option<X18PcRelative>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18StackWriteback {
    word: u32,
    scratch: u8,
    anchor_scratch: u8,
    layout: X18StackWritebackLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18StackWritebackLayout {
    rt: u8,
    rt2: u8,
    delta: i16,
    element_bytes: u16,
    frame_bytes: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18PcRelative {
    Adr(u64),
    Adrp(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18CompareBranch {
    target: u64,
    scratch: u8,
    anchor_scratch: u8,
    kind: X18BranchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18BranchKind {
    CbzW,
    CbzX,
    CbnzW,
    CbnzX,
    Tbz(u8),
    Tbnz(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18Adr {
    target: u64,
    scratch: u8,
    anchor_scratch: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18Unsupported {
    ControlFlow,
    PcRelative,
    ExclusiveAtomic,
    EncodingLayout,
    DecodeFailure,
}

/// Decodes the deliberately narrow pair family supported by the
/// displacement-aware x18 gate. This is also used to validate persisted gates.
fn decode_x18_stack_writeback(word: u32) -> Option<X18StackWritebackLayout> {
    // Integer STP/LDP (32- or 64-bit), immediate pre/post-index, SP base.
    if word & 0x7e00_0000 != 0x2800_0000 || (word >> RN_SHIFT) & REG_MASK != u32::from(SP) {
        return None;
    }
    let mode = (word >> 23) & 3;
    if !matches!(mode, 1 | 3) {
        return None;
    }
    let element_bytes = if word >> 31 == 0 { 4 } else { 8 };
    let encoded_imm7 = ((word >> IMM7_SHIFT) & u32::from(IMM7_MASK)).to_le_bytes()[0];
    let imm7 = i16::from(encoded_imm7) << 9 >> 9;
    let delta = imm7.checked_mul(element_bytes)?;
    let depth = X18_FRAME_BYTES.checked_add(if delta < 0 { delta.unsigned_abs() } else { 0 })?;
    Some(X18StackWritebackLayout {
        rt: (word & REG_MASK) as u8,
        rt2: ((word >> RT2_SHIFT) & REG_MASK) as u8,
        delta,
        element_bytes: element_bytes.cast_unsigned(),
        frame_bytes: depth.checked_add(15)? & !15,
    })
}

fn classify_x18_stack_writeback(word: u32) -> Option<X18StackWriteback> {
    let layout = decode_x18_stack_writeback(word)?;
    if layout.rt != X18_ENCODED && layout.rt2 != X18_ENCODED {
        return None;
    }
    let instruction = decode_instruction(word)?;
    let (scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
    Some(X18StackWriteback {
        word: substitute_x18(word, scratch)?,
        scratch,
        anchor_scratch,
        layout,
    })
}

fn decode_instruction(word: u32) -> Option<DecodedInstruction> {
    let bytes = word.to_le_bytes();
    InstDecoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .ok()
}

fn operand_uses_x18(operand: &Operand) -> bool {
    match operand {
        Operand::Register(_, register)
        | Operand::RegisterOrSP(_, register)
        | Operand::RegShift(_, _, _, register)
        | Operand::RegPreIndex(register, _, _)
        | Operand::RegPostIndex(register, _) => *register == X18,
        Operand::RegisterPair(_, first) => *first == X18 || first.checked_add(1) == Some(X18),
        Operand::RegRegOffset(base, index, _, _, _) | Operand::RegPostIndexReg(base, index) => {
            *base == X18 || *index == X18
        }
        _ => false,
    }
}

fn mark_operand_registers(operand: &Operand, used: &mut [bool; 32]) {
    let mut mark = |register: u16| {
        if let Ok(register) = u8::try_from(register)
            && register <= MAX_REGISTER
        {
            used[usize::from(register)] = true;
        }
    };
    match operand {
        Operand::Register(_, register)
        | Operand::RegisterOrSP(_, register)
        | Operand::RegShift(_, _, _, register)
        | Operand::RegPreIndex(register, _, _)
        | Operand::RegPostIndex(register, _) => mark(*register),
        Operand::RegisterPair(_, first) => {
            mark(*first);
            if let Some(second) = first.checked_add(1) {
                mark(second);
            }
        }
        Operand::RegRegOffset(base, index, _, _, _) | Operand::RegPostIndexReg(base, index) => {
            mark(*base);
            mark(*index);
        }
        _ => {}
    }
}

fn select_x18_scratches(instruction: &DecodedInstruction) -> Option<(u8, u8)> {
    let mut used = [false; 32];
    for operand in &instruction.operands {
        mark_operand_registers(operand, &mut used);
    }
    let mut available = (7u8..=17)
        .rev()
        .filter(|register| !used[usize::from(*register)]);
    Some((available.next()?, available.next()?))
}

fn x18_fixed_gate_can_execute(instruction: &DecodedInstruction) -> bool {
    // SP reads are safe because the gate restores original SP for the
    // instruction, but an SP write would move the frame and make exact register
    // restoration impossible.
    let writes_sp = matches!(instruction.operands[0], Operand::RegisterOrSP(_, 31))
        || instruction.operands.iter().any(|operand| {
            matches!(
                operand,
                Operand::RegPreIndex(31, _, true)
                    | Operand::RegPostIndex(31, _)
                    | Operand::RegPostIndexReg(31, _)
            )
        });
    let overlaps_frame = instruction
        .operands
        .iter()
        .any(|operand| matches!(operand, Operand::RegPreIndex(31, offset, _) if *offset < 0));
    !writes_sp && !overlaps_frame
}

fn has_possible_x18_field(word: u32) -> bool {
    // Exclude vector-only SVE ADD, but retain scalar SVE x18 detection.
    if word & 0xFF20_FC00 == 0x0420_0000 {
        return false;
    }
    [0, 5, 10, 16]
        .into_iter()
        .any(|shift| (word >> shift) & REG_MASK == u32::from(X18))
        || [0, 16]
            .into_iter()
            .any(|shift| (word >> shift) & REG_MASK == u32::from(X18 - 1))
}

fn is_control_flow(opcode: DecodedOpcode) -> bool {
    matches!(
        opcode,
        DecodedOpcode::TBZ
            | DecodedOpcode::TBNZ
            | DecodedOpcode::CBZ
            | DecodedOpcode::CBNZ
            | DecodedOpcode::B
            | DecodedOpcode::BR
            | DecodedOpcode::Bcc(_)
            | DecodedOpcode::BCcc(_)
            | DecodedOpcode::BL
            | DecodedOpcode::BLR
            | DecodedOpcode::RET
            | DecodedOpcode::ERET
            | DecodedOpcode::DRPS
            | DecodedOpcode::BLRAA
            | DecodedOpcode::BLRAAZ
            | DecodedOpcode::BLRAB
            | DecodedOpcode::BLRABZ
            | DecodedOpcode::BRAA
            | DecodedOpcode::BRAAZ
            | DecodedOpcode::BRAB
            | DecodedOpcode::BRABZ
            | DecodedOpcode::RETAA
            | DecodedOpcode::RETAB
            | DecodedOpcode::ERETAA
            | DecodedOpcode::ERETAB
            | DecodedOpcode::RETAASPPC
            | DecodedOpcode::RETABSPPC
            | DecodedOpcode::RETAASPPCR
            | DecodedOpcode::RETABSPPCR
    )
}

fn is_exclusive_or_atomic(opcode: DecodedOpcode) -> bool {
    matches!(
        opcode,
        DecodedOpcode::LDAXP
            | DecodedOpcode::LDAXR
            | DecodedOpcode::LDAXRB
            | DecodedOpcode::LDAXRH
            | DecodedOpcode::LDXP
            | DecodedOpcode::LDXR
            | DecodedOpcode::LDXRB
            | DecodedOpcode::LDXRH
            | DecodedOpcode::STLXP
            | DecodedOpcode::STLXR
            | DecodedOpcode::STLXRB
            | DecodedOpcode::STLXRH
            | DecodedOpcode::STXP
            | DecodedOpcode::STXR
            | DecodedOpcode::STXRB
            | DecodedOpcode::STXRH
            | DecodedOpcode::SWP(_)
            | DecodedOpcode::SWPB(_)
            | DecodedOpcode::SWPH(_)
            | DecodedOpcode::LDADD(_)
            | DecodedOpcode::LDADDB(_)
            | DecodedOpcode::LDADDH(_)
            | DecodedOpcode::LDCLR(_)
            | DecodedOpcode::LDCLRB(_)
            | DecodedOpcode::LDCLRH(_)
            | DecodedOpcode::LDEOR(_)
            | DecodedOpcode::LDEORB(_)
            | DecodedOpcode::LDEORH(_)
            | DecodedOpcode::LDSET(_)
            | DecodedOpcode::LDSETB(_)
            | DecodedOpcode::LDSETH(_)
            | DecodedOpcode::LDSMAX(_)
            | DecodedOpcode::LDSMAXB(_)
            | DecodedOpcode::LDSMAXH(_)
            | DecodedOpcode::LDSMIN(_)
            | DecodedOpcode::LDSMINB(_)
            | DecodedOpcode::LDSMINH(_)
            | DecodedOpcode::LDUMAX(_)
            | DecodedOpcode::LDUMAXB(_)
            | DecodedOpcode::LDUMAXH(_)
            | DecodedOpcode::LDUMIN(_)
            | DecodedOpcode::LDUMINB(_)
            | DecodedOpcode::LDUMINH(_)
            | DecodedOpcode::CAS(_)
            | DecodedOpcode::CASB(_)
            | DecodedOpcode::CASH(_)
            | DecodedOpcode::CASP(_)
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExclusiveBoundary {
    Load,
    Store,
}

fn exclusive_boundary(word: u32) -> Option<ExclusiveBoundary> {
    use DecodedOpcode::{LDAXP, LDAXR, LDAXRB, LDAXRH, LDXP, LDXR, LDXRB, LDXRH};
    use DecodedOpcode::{STLXP, STLXR, STLXRB, STLXRH, STXP, STXR, STXRB, STXRH};

    let opcode = decode_instruction(word)?.opcode;
    if matches!(
        opcode,
        LDAXP | LDAXR | LDAXRB | LDAXRH | LDXP | LDXR | LDXRB | LDXRH
    ) {
        Some(ExclusiveBoundary::Load)
    } else if matches!(
        opcode,
        STLXP | STLXR | STLXRB | STLXRH | STXP | STXR | STXRB | STXRH
    ) {
        Some(ExclusiveBoundary::Store)
    } else {
        None
    }
}

fn classify_decoded_x18(instruction: &DecodedInstruction) -> DecodedX18Classification {
    if !instruction.operands.iter().any(operand_uses_x18) {
        return DecodedX18Classification::None;
    }
    if is_control_flow(instruction.opcode) {
        return DecodedX18Classification::Unsupported(X18Unsupported::ControlFlow);
    }
    if instruction
        .operands
        .iter()
        .any(|operand| matches!(operand, Operand::PCOffset(_)))
    {
        return DecodedX18Classification::Unsupported(X18Unsupported::PcRelative);
    }
    if is_exclusive_or_atomic(instruction.opcode) {
        return DecodedX18Classification::Unsupported(X18Unsupported::ExclusiveAtomic);
    }
    DecodedX18Classification::Ordinary
}

fn classify_x18(word: u32) -> X18Classification {
    if let Some(kind) = [
        (Insn::Br(18), X18IndirectBranchKind::Br),
        (Insn::Blr(18), X18IndirectBranchKind::Blr),
        (Insn::Ret(18), X18IndirectBranchKind::Ret),
    ]
    .into_iter()
    .find_map(|(instruction, kind)| (instruction.encode() == Some(word)).then_some(kind))
    {
        return X18Classification::Branch(kind);
    }
    // yaxpeax-arm 0.4.0 truncates the five-bit Rt field of MSR (register).
    // Check the architectural encoding so an X18 source cannot fail open.
    if word & 0xFFF0_001F == 0xD510_0012 {
        return X18Classification::X18(X18TransformResult::Unsupported(
            X18Unsupported::EncodingLayout,
        ));
    }
    let Some(instruction) = decode_instruction(word) else {
        return if has_possible_x18_field(word) {
            X18Classification::X18(X18TransformResult::Unsupported(
                X18Unsupported::DecodeFailure,
            ))
        } else {
            X18Classification::None
        };
    };
    match classify_decoded_x18(&instruction) {
        DecodedX18Classification::None => X18Classification::None,
        DecodedX18Classification::Unsupported(reason) => {
            X18Classification::X18(X18TransformResult::Unsupported(reason))
        }
        DecodedX18Classification::Ordinary if x18_fixed_gate_can_execute(&instruction) => {
            select_x18_scratches(&instruction)
                .and_then(|(scratch, anchor_scratch)| {
                    substitute_x18(word, scratch).map(|word| (word, scratch, anchor_scratch))
                })
                .map_or(
                    X18Classification::X18(X18TransformResult::Unsupported(
                        X18Unsupported::EncodingLayout,
                    )),
                    |(word, scratch, anchor_scratch)| {
                        X18Classification::X18(X18TransformResult::Supported(X18Substitution {
                            word,
                            scratch,
                            anchor_scratch,
                            pc_relative: None,
                        }))
                    },
                )
        }
        DecodedX18Classification::Ordinary => X18Classification::X18(
            X18TransformResult::Unsupported(X18Unsupported::EncodingLayout),
        ),
    }
}

fn classify_x18_conditional_branch(word: u32, vaddr: u64) -> Option<X18CompareBranch> {
    let instruction = decode_instruction(word)?;
    let (width, offset, test_bit) = match instruction.operands {
        [
            Operand::Register(width, X18),
            Operand::PCOffset(offset),
            Operand::Nothing,
            Operand::Nothing,
        ] if matches!(instruction.opcode, DecodedOpcode::CBZ | DecodedOpcode::CBNZ) => {
            (width, offset, None)
        }
        [
            Operand::Register(width, X18),
            Operand::Imm16(bit),
            Operand::PCOffset(offset),
            Operand::Nothing,
        ] if matches!(instruction.opcode, DecodedOpcode::TBZ | DecodedOpcode::TBNZ) => {
            (width, offset, Some(u8::try_from(bit).ok()?))
        }
        _ => return None,
    };
    if !matches!(
        width,
        yaxpeax_arm::armv8::a64::SizeCode::W | yaxpeax_arm::armv8::a64::SizeCode::X
    ) {
        return None;
    }
    let kind = match (instruction.opcode, width, test_bit) {
        (DecodedOpcode::CBZ, yaxpeax_arm::armv8::a64::SizeCode::W, None) => X18BranchKind::CbzW,
        (DecodedOpcode::CBZ, yaxpeax_arm::armv8::a64::SizeCode::X, None) => X18BranchKind::CbzX,
        (DecodedOpcode::CBNZ, yaxpeax_arm::armv8::a64::SizeCode::W, None) => X18BranchKind::CbnzW,
        (DecodedOpcode::CBNZ, yaxpeax_arm::armv8::a64::SizeCode::X, None) => X18BranchKind::CbnzX,
        (DecodedOpcode::TBZ, _, Some(bit)) => X18BranchKind::Tbz(bit),
        (DecodedOpcode::TBNZ, _, Some(bit)) => X18BranchKind::Tbnz(bit),
        _ => return None,
    };
    let (scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
    Some(X18CompareBranch {
        target: vaddr.checked_add_signed(offset)?,
        scratch,
        anchor_scratch,
        kind,
    })
}

fn classify_pc_relative_x18(word: u32, vaddr: u64) -> Option<X18Substitution> {
    let instruction = decode_instruction(word)?;
    let [
        Operand::Register(_, X18),
        Operand::PCOffset(offset),
        Operand::Nothing,
        Operand::Nothing,
    ] = instruction.operands
    else {
        return None;
    };
    if !matches!(instruction.opcode, DecodedOpcode::ADR | DecodedOpcode::ADRP) {
        return None;
    }
    let (scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
    let target = if instruction.opcode == DecodedOpcode::ADR {
        vaddr.checked_add_signed(offset)?
    } else {
        (vaddr & !PAGE_OFFSET_MASK).checked_add_signed(offset)?
    };
    Some(X18Substitution {
        word: word & !REG_MASK | u32::from(scratch),
        scratch,
        anchor_scratch,
        pc_relative: Some(if instruction.opcode == DecodedOpcode::ADR {
            X18PcRelative::Adr(target)
        } else {
            X18PcRelative::Adrp(target)
        }),
    })
}

fn classify_adr_x18(word: u32, vaddr: u64) -> Option<X18Adr> {
    let instruction = decode_instruction(word)?;
    let [
        Operand::Register(yaxpeax_arm::armv8::a64::SizeCode::X, X18),
        Operand::PCOffset(offset),
        Operand::Nothing,
        Operand::Nothing,
    ] = instruction.operands
    else {
        return None;
    };
    if instruction.opcode != DecodedOpcode::ADR {
        return None;
    }
    let (scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
    Some(X18Adr {
        target: vaddr.checked_add_signed(offset)?,
        scratch,
        anchor_scratch,
    })
}

fn replace_register_field(word: &mut u32, shift: u32, replacement: u8) -> Option<()> {
    if (*word >> shift) & REG_MASK != u32::from(X18) {
        return None;
    }
    *word = (*word & !(REG_MASK << shift)) | (u32::from(replacement) << shift);
    Some(())
}

fn expected_operand(operand: Operand, replacement: u16) -> Option<Operand> {
    let replace = |register| {
        if register == X18 {
            replacement
        } else {
            register
        }
    };
    Some(match operand {
        Operand::Register(size, X18) => Operand::Register(size, replacement),
        Operand::RegisterOrSP(size, X18) => Operand::RegisterOrSP(size, replacement),
        Operand::RegShift(style, amount, size, X18) => {
            Operand::RegShift(style, amount, size, replacement)
        }
        Operand::RegRegOffset(base, index, size, style, amount) => {
            Operand::RegRegOffset(replace(base), replace(index), size, style, amount)
        }
        Operand::RegPreIndex(X18, offset, writeback) => {
            Operand::RegPreIndex(replacement, offset, writeback)
        }
        Operand::RegPostIndex(X18, offset) => Operand::RegPostIndex(replacement, offset),
        Operand::RegPostIndexReg(base, index) => {
            Operand::RegPostIndexReg(replace(base), replace(index))
        }
        Operand::RegisterPair(_, first) if first == X18 || first.checked_add(1) == Some(X18) => {
            return None;
        }
        other => other,
    })
}

fn substitute_x18(word: u32, replacement: u8) -> Option<u32> {
    let instruction = decode_instruction(word)?;
    if classify_decoded_x18(&instruction) != DecodedX18Classification::Ordinary {
        return None;
    }
    let mut transformed_word = word;
    let mut expected = instruction;
    for (index, operand) in instruction.operands.iter().enumerate() {
        match operand {
            Operand::Register(_, X18) | Operand::RegisterOrSP(_, X18) => {
                let shift = match (instruction.opcode, index) {
                    (
                        DecodedOpcode::MADD
                        | DecodedOpcode::MSUB
                        | DecodedOpcode::SMADDL
                        | DecodedOpcode::SMSUBL
                        | DecodedOpcode::UMADDL
                        | DecodedOpcode::UMSUBL
                        | DecodedOpcode::LSLV
                        | DecodedOpcode::LSRV
                        | DecodedOpcode::ASRV
                        | DecodedOpcode::RORV
                        | DecodedOpcode::ADC
                        | DecodedOpcode::ADCS
                        | DecodedOpcode::SBC
                        | DecodedOpcode::SBCS
                        | DecodedOpcode::UDIV
                        | DecodedOpcode::SDIV
                        | DecodedOpcode::CSEL
                        | DecodedOpcode::CSINC
                        | DecodedOpcode::CSINV
                        | DecodedOpcode::CSNEG
                        | DecodedOpcode::EXTR
                        | DecodedOpcode::UMULH
                        | DecodedOpcode::SMULH,
                        2,
                    )
                    | (DecodedOpcode::CCMP | DecodedOpcode::CCMN, 1) => 16,
                    (
                        DecodedOpcode::MADD
                        | DecodedOpcode::MSUB
                        | DecodedOpcode::SMADDL
                        | DecodedOpcode::SMSUBL
                        | DecodedOpcode::UMADDL
                        | DecodedOpcode::UMSUBL,
                        3,
                    ) => RT2_SHIFT,
                    (DecodedOpcode::CCMP | DecodedOpcode::CCMN, 0) | (DecodedOpcode::EXTR, 1) => {
                        RN_SHIFT
                    }
                    (_, 0) if instruction.operands[1] != Operand::Nothing => 0,
                    (_, 1)
                        if matches!(
                            instruction.opcode,
                            DecodedOpcode::STP
                                | DecodedOpcode::LDP
                                | DecodedOpcode::STNP
                                | DecodedOpcode::LDNP
                                | DecodedOpcode::LDPSW
                        ) =>
                    {
                        RT2_SHIFT
                    }
                    (_, 1) => RN_SHIFT,
                    _ => return None,
                };
                replace_register_field(&mut transformed_word, shift, replacement)?;
            }
            Operand::RegShift(_, _, _, X18) => {
                replace_register_field(&mut transformed_word, 16, replacement)?;
            }
            Operand::RegRegOffset(base, index, _, _, _) | Operand::RegPostIndexReg(base, index) => {
                if *base == X18 {
                    replace_register_field(&mut transformed_word, RN_SHIFT, replacement)?;
                }
                if *index == X18 {
                    replace_register_field(&mut transformed_word, 16, replacement)?;
                }
            }
            Operand::RegPreIndex(X18, _, _) | Operand::RegPostIndex(X18, _) => {
                replace_register_field(&mut transformed_word, RN_SHIFT, replacement)?;
            }
            Operand::RegisterPair(_, first)
                if *first == X18 || first.checked_add(1) == Some(X18) =>
            {
                return None;
            }
            _ => {}
        }
        expected.operands[index] = expected_operand(*operand, u16::from(replacement))?;
    }
    (decode_instruction(transformed_word)? == expected).then_some(transformed_word)
}

// --- Guest thread-pointer virtualization ---
//
// The runtime supplies an anchor-relative offset for its guest TLS root: the
// fields for direct TLS, or a block pointer for indirect TLS. The rewriter
// emits a placeholder for that offset and the loader overwrites it.

/// Largest value the `imm12` field of an unsigned-offset `LDR`/`STR` can hold.
/// The field is 12 bits and unsigned, counting `0..=0xFFF` *scaled units*.
const LDST_UIMM12_IMM_MAX: u16 = (1 << 12) - 1;

/// Scale the 64-bit form applies to that `imm12`, i.e. the operand width in
/// bytes. Any offset the gates address must therefore be 8-aligned.
const LDST_UIMM12_SCALE_64BIT: u16 = 8;

/// Largest byte offset a 64-bit unsigned-offset `LDR`/`STR` can encode
/// (`0xFFF * 8 = 32760`), derived from the encoding rather than written out.
const LDR_UIMM12_MAX_BYTE_OFFSET: u16 = LDST_UIMM12_IMM_MAX * LDST_UIMM12_SCALE_64BIT;

/// Alignment the runtime-supplied guest TLS offset must satisfy.
pub const GUEST_TPIDR_OFFSET_ALIGN: u16 = LDST_UIMM12_SCALE_64BIT;

/// Guest x18's ABI offset from the guest thread pointer field.
pub const GUEST_X18_OFFSET_FROM_GUEST_TP: usize = core::mem::size_of::<usize>();
/// ABI offset of the outbound SVC x16 save slot from the guest-TP field.
/// Both hosts keep their existing prefix (including `in_guest` at 32).
pub const SVC_X16_OFFSET_FROM_GUEST_TP: u16 = 64;
const _: () = assert!(GUEST_X18_OFFSET_FROM_GUEST_TP == GUEST_TPIDR_OFFSET_ALIGN as usize);

/// Largest anchor-relative guest TLS root offset encodable by the gates.
pub const MAX_GUEST_TPIDR_OFFSET: u16 = LDR_UIMM12_MAX_BYTE_OFFSET;

/// The smallest guest-TLS root offset a gate may be patched with.
///
/// Rejects zero and the first anchor-relative slot; the runtime separately
/// validates ownership of its selected slot.
pub(crate) const MIN_GUEST_TPIDR_OFFSET: u16 = 16;

/// Placeholder for the runtime-supplied guest TLS offset.
///
/// It is `MAX_GUEST_TPIDR_OFFSET`, the largest value the field can hold, so it
/// cannot collide with a real runtime offset. That makes scanning for it exact,
/// which is what lets [`patch_guest_tpidr_offset`] and
/// [`find_guest_tpidr_placeholder`] work off the emitted words alone with no
/// side table of patch sites.
///
/// It buys **no** run-time safety: an unpatched gate accesses arbitrary
/// anchor-relative memory. A loader must use [`finalize_trampoline_gates`]
/// (Linux without x18) or [`finalize_trampoline_gates_for_host`] before making
/// a trampoline executable.
pub(crate) const GUEST_TPIDR_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;
/// Distinct placeholder used by direct-TLS x18 gates.
const GUEST_X18_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET - 8;
const SVC_X16_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;

/// Stack frame used by x18 gates to preserve their two scratch registers.
pub const X18_FRAME_BYTES: u16 = 16;
// --- SVC gate stack frame ---
//
// The SVC gate touches only X16, so the frame holds three words: the saved
// guest X16, the post-SVC return address, and this site's outbound stub
// address. Rounded up to 16-byte stack alignment, that is 32 bytes.

/// SVC gate frame size (`SUB/ADD SP, SP, #SVC_FRAME_BYTES`). 16-byte aligned.
///
/// ABI: `switch_to_guest` sets `SP` to `PtRegs::sp - SVC_FRAME_BYTES` before
/// entering an outbound stub, because the stub pops this frame.
pub const SVC_FRAME_BYTES: u16 = 32;
/// Darwin SVC stack decrement, including the 128-byte red zone.
/// Frame fields use the `SVC_FRAME_OFF_*` offsets.
pub const DARWIN_SVC_FRAME_BYTES: u16 = SVC_FRAME_BYTES + 128;
/// Saved guest X16. ABI: the outbound stub reloads `X16` from here.
pub const SVC_FRAME_OFF_X16: u16 = 0;
/// Post-SVC return address. ABI: the runtime's syscall callback reads it and
/// publishes it as the guest resume PC.
pub const SVC_FRAME_OFF_RETADDR: u16 = 8;
/// Address of this site's outbound stub. ABI: the runtime's syscall callback
/// branches here to resume at the original syscall site.
pub const SVC_FRAME_OFF_STUB: u16 = 16;

pub const RT_SIGRETURN_TRAMPOLINE_BYTES: usize = 48;

/// Emits a synthetic AArch64 `rt_sigreturn` restorer that dispatches through
/// `callback` using the rewriter's SVC frame ABI.
pub fn emit_rt_sigreturn_trampoline(
    callback: usize,
) -> Result<[u8; RT_SIGRETURN_TRAMPOLINE_BYTES]> {
    const NR_RT_SIGRETURN: u16 = 139;
    const CALLBACK_OFFSET: usize = 40;
    const CONTINUATION_OFFSET: i64 = 32;
    const ADR_OFFSET: i64 = 12;
    const LDR_OFFSET: i64 = 24;
    let instructions = [
        Insn::Movz {
            rd: X8,
            imm16: NR_RT_SIGRETURN,
        },
        Insn::SubSp(SVC_FRAME_BYTES),
        Insn::StrUimm {
            rt: X16,
            rn: SP,
            imm_bytes: SVC_FRAME_OFF_X16,
        },
        Insn::Adr {
            rd: X16,
            byte_off: CONTINUATION_OFFSET - ADR_OFFSET,
        },
        Insn::StrUimm {
            rt: X16,
            rn: SP,
            imm_bytes: SVC_FRAME_OFF_RETADDR,
        },
        Insn::StrUimm {
            rt: XZR,
            rn: SP,
            imm_bytes: SVC_FRAME_OFF_STUB,
        },
        Insn::LdrLiteral {
            rt: X16,
            off: i64::try_from(CALLBACK_OFFSET).map_err(|_| {
                Error::AddressOverflow("callback offset does not fit in i64".into())
            })? - LDR_OFFSET,
        },
        Insn::Br(X16),
        Insn::Nop,
        Insn::Nop,
    ];

    let mut out = [0; RT_SIGRETURN_TRAMPOLINE_BYTES];
    for (index, instruction) in instructions.into_iter().enumerate() {
        let word = instruction.encode().ok_or_else(|| {
            Error::AddressOverflow("rt_sigreturn trampoline instruction is not encodable".into())
        })?;
        out[index * INSN_BYTES..][..INSN_BYTES].copy_from_slice(&word.to_le_bytes());
    }
    out[CALLBACK_OFFSET..].copy_from_slice(&callback.to_ne_bytes());
    Ok(out)
}

// The gate carves the frame out of the guest stack with `SUB SP`, so the frame
// must keep `SP` 16-byte aligned, and it must be large enough for the three
// words the gate writes into it.
const _: () = assert!(
    SVC_FRAME_BYTES.is_multiple_of(16),
    "the SVC gate frame must keep SP 16-byte aligned"
);
const _: () = assert!(
    SVC_FRAME_OFF_STUB + 8 <= SVC_FRAME_BYTES,
    "the SVC gate frame must hold the saved X16, the return address and the stub address"
);

/// Size of the SVC gate proper, i.e. the distance from the gate's first
/// instruction to its outbound stub. The gate is `SUB SP / STR X16 / ADRP /
/// ADD / STR / ADR / STR / LDR X16 / BR` = 9 instructions.
pub const SVC_GATE_BYTES: usize = 9 * 4;
/// The macOS TLS-restoring outbound stub is six instructions. A native-host
/// epilogue follows it and restores x16 from the stack, without using guest TLS.
pub const MACOS_SVC_NATIVE_EPILOGUE_OFFSET_FROM_STUB: usize = 6 * INSN_BYTES;
/// Size of that native epilogue (`LDR X16 / ADD SP / B`).
pub const MACOS_SVC_NATIVE_EPILOGUE_BYTES: usize = 3 * INSN_BYTES;
/// Size of the per-site outbound stub (`LDR X16 / ADD SP / B`).
#[cfg(test)]
const SVC_OUTBOUND_STUB_BYTES: usize = 3 * 4;

// --- MSR gate stack frame ---
//
// The MSR gate spills X16/X17 (one `STP`/`LDP` pair) and stages the captured
// guest value so the source register needs no special-casing.

/// MSR gate frame size (`SUB/ADD SP, SP, #MSR_FRAME_BYTES`). 16-byte aligned.
pub const MSR_FRAME_BYTES: u16 = 32;
/// Captured guest thread-pointer value, staged while all guest registers are
/// still pristine.
pub const MSR_FRAME_OFF_VALUE: u16 = 16;

// --- Trampoline layout offsets (all in bytes) ---

/// Callback address slot.
const HEADER_CALLBACK_OFFSET: usize = 0;

/// First byte past the 8-byte callback slot.
#[cfg(test)]
const FIRST_SCANNABLE_OFFSET: usize = HEADER_CALLBACK_OFFSET + 8;

/// First byte of the per-site gates; the callback header is padded with NOPs to
/// the 16-byte slot alignment.
const GATES_START_OFFSET: usize = GATE_ALIGNMENT;

// ============================================================
// Instruction encoders
//
// Each encoder returns the 32-bit little-endian instruction word. Encoders that
// can fail range checks return `Option`; callers convert `None` into an
// `Error::AddressOverflow` with context.
//
// Each encoder ORs an [`Opcode`] base with its shifted, masked operands. The
// `IMM*_MASK` values isolate the immediate fields shared by several encoders.
// ============================================================

/// 26-bit `imm26` branch-offset field (`B`/`BL`), bits \[25:0].
const IMM26_MASK: u32 = 0x03FF_FFFF;
const OPCODE_TOP6_MASK: u32 = 0xFC00_0000;
/// 19-bit `imm19` offset field (`B.cond`/`LDR`-literal/`ADRP` immhi), bits \[18:0].
const IMM19_MASK: u32 = 0x0007_FFFF;

/// A PC-relative immediate counts instructions, so it scales by this many bits
/// to reach a byte displacement.
const INSN_BYTES_LOG2: u32 = 2;

/// Bytes in one AArch64 instruction. Every patch site, gate slot and scan
/// stride is a whole number of these.
pub(crate) const INSN_BYTES: usize = 1 << INSN_BYTES_LOG2;

/// [`INSN_BYTES`] where a virtual address is being measured.
pub(crate) const INSN_BYTES_U64: u64 = 1 << INSN_BYTES_LOG2;

/// The metadata word closing every compact gate slot.
const GATE_METADATA_BYTES: usize = 4;

// Field positions within an instruction word.
/// `Rn`, and the low bit of a PC-relative `imm19`.
const RN_SHIFT: u32 = 5;
/// `Rt2` of `STP`/`LDP`, and `imm12` of the add/sub and load/store forms.
const RT2_SHIFT: u32 = 10;
/// Signed `imm7` of `STP`/`LDP`.
const IMM7_SHIFT: u32 = 15;
/// `immlo` of `ADR`/`ADRP`; `immhi` sits at [`RN_SHIFT`].
const ADR_IMMLO_SHIFT: u32 = 29;
/// Bits an `ADRP` immediate is scaled by: it addresses 4KiB pages.
#[cfg(test)]
const ADRP_PAGE_SHIFT: u32 = 12;

// Widths of the signed immediate fields, used to sign-extend them into an
// `i64` by shifting left and back.
const IMM26_BITS: u32 = 26;
#[cfg(test)]
const IMM21_BITS: u32 = 21;
const IMM19_BITS: u32 = 19;

/// Sign-extends the low `bits` of `value`.
const fn sign_extend(value: i64, bits: u32) -> i64 {
    (value << (i64::BITS - bits)) >> (i64::BITS - bits)
}

/// Sign-extends a PC-relative immediate and scales it to a byte displacement.
const fn pcrel_bytes(imm: i64, bits: u32) -> i64 {
    sign_extend(imm, bits) << INSN_BYTES_LOG2
}

/// Register field, bits \[4:0] — `Rd`, `Rt` or the `Rn`/`Rt2` fields once
/// shifted into place.
const REG_MASK: u32 = 0x1F;

/// `immlo` of an `ADR`/`ADRP` pair, bits \[1:0] of the 21-bit immediate.
const ADR_IMMLO_MASK: u32 = 0x3;

/// Signed 7-bit scaled immediate of `STP`/`LDP`.
const IMM7_MASK: u16 = 0x7F;

/// Byte offset within a 4KiB page, the part an `ADRP` does not carry.
const PAGE_OFFSET_MASK: u64 = 0xFFF;

/// `ADRP` opcode bits plus `Rd`, ignoring the immediate.
const ADRP_SHAPE_MASK: u32 = 0x9F00_001F;

/// `ADD (immediate)` opcode bits plus `Rn` and `Rd`, ignoring the immediate.
const ADD_IMM_SHAPE_MASK: u32 = 0xFFC0_03FF;

/// `LDR (literal)` opcode bits plus `Rt`, ignoring the immediate.
const LDR_LITERAL_SHAPE_MASK: u32 = 0xFF00_001F;

/// Fixed instruction bits with operand fields zeroed, for encoding and matching.
#[repr(u32)]
#[derive(Clone, Copy)]
enum Opcode {
    B = 0x1400_0000,
    LdrLiteral = 0x5800_0000,
    Adr = 0x1000_0000,
    Adrp = 0x9000_0000,
    Br = 0xD61F_0000,
    Blr = 0xD63F_0000,
    Ret = 0xD65F_0000,
    Movz = 0xD280_0000,
    SubImm = 0xD100_0000,
    AddImm = 0x9100_0000,
    AndImm = 0x9200_0000,
    StrUimm = 0xF900_0000,
    LdrUimm = 0xF940_0000,
    Stp = 0xA900_0000,
    Ldp = 0xA940_0000,
    StpPre = 0xA980_0000,
    LdpPost = 0xA8C0_0000,
    MrsTpidrEl0 = MRS_TPIDR_EL0_BITS,
    MrsTpidrroEl0 = 0xD53B_D060,
    MsrTpidrroEl0 = 0xD51B_D060,
    MovReg = 0xAA00_03E0,
    CbnzW = 0x3500_0000,
    CbzW = 0x3400_0000,
    CbzX = 0xB400_0000,
    CbnzX = 0xB500_0000,
    Tbz = 0x3600_0000,
    Tbnz = 0x3700_0000,
    Brk = 0xD420_0000,
}

impl Opcode {
    /// The base opcode word, for ORing in operand fields.
    const fn bits(self) -> u32 {
        self as u32
    }
}

// --- Shared instruction-format encoders ---
//
// Several instructions share one field layout and differ only by opcode, so
// each layout is encoded once here and selected by an `Opcode`. [`Insn::encode`]
// dispatches each variant to its format here; every range check lives in exactly
// one place per format.

/// `op | imm26` — PC-relative branch (`B`/`BL`), ±128MB, 4-byte aligned.
fn branch_imm26(op: Opcode, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm26 = i32::try_from(offset >> 2).ok()?;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    Some(op.bits() | (imm26.cast_unsigned() & IMM26_MASK))
}

/// `op | imm19<<5 | low` — PC-relative imm19 form (`B.cond`/`LDR`-literal), ±1MB,
/// 4-byte aligned. `low` is the instruction's 5-bit \[4:0] field: `Rt`, or the
/// condition code for `B.cond`.
fn pcrel_imm19(op: Opcode, offset: i64, low: u32) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = i32::try_from(offset >> 2).ok()?;
    if !(-(1 << 18)..(1 << 18)).contains(&imm19) {
        return None;
    }
    Some(op.bits() | ((imm19.cast_unsigned() & IMM19_MASK) << RN_SHIFT) | low)
}

/// `op | immlo<<29 | immhi<<5 | rd` — 21-bit-signed PC-relative address form
/// (`ADR`/`ADRP`). The units of `imm` are the instruction's own: bytes for
/// `ADR` (±1MB), 4KB pages for `ADRP` (±4GB).
fn pcrel_imm21(op: Opcode, rd: u8, imm: i64) -> Option<u32> {
    let imm = i32::try_from(imm).ok()?;
    if !(-(1 << 20)..(1 << 20)).contains(&imm) {
        return None;
    }
    let imm = imm.cast_unsigned();
    let immlo = (imm & ADR_IMMLO_MASK) << ADR_IMMLO_SHIFT;
    let immhi = ((imm >> 2) & IMM19_MASK) << RN_SHIFT;
    Some(op.bits() | immlo | immhi | u32::from(rd))
}

/// `op | imm12<<10 | rn<<5 | rd` — 12-bit-immediate add/sub form
/// (`ADD`/`SUB`/`ADDS`). The caller supplies an already-scaled `imm12`.
fn data_imm12(op: Opcode, rd: u8, rn: u8, imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    Some(op.bits() | (u32::from(imm12) << RT2_SHIFT) | (u32::from(rn) << RN_SHIFT) | u32::from(rd))
}

/// Encodes a complete 64-bit logical-immediate instruction, including its
/// `N:immr:imms` fields.
fn logical_imm64(op: Opcode, rd: u8, rn: u8, immediate: u64) -> Option<u32> {
    if immediate == 0 || immediate == u64::MAX {
        return None;
    }
    for element_bits in [2u32, 4, 8, 16, 32, 64] {
        let element_mask = u64::MAX >> (64 - element_bits);
        let element = immediate & element_mask;
        let mut replicated = 0;
        for shift in (0..64).step_by(element_bits as usize) {
            replicated |= element << shift;
        }
        if replicated != immediate {
            continue;
        }
        let ones = element.count_ones();
        let unrotated = (1u64 << ones) - 1;
        for immr in 0..element_bits {
            let rotated = if immr == 0 {
                unrotated
            } else {
                (unrotated >> immr) | (unrotated << (element_bits - immr))
            } & element_mask;
            if rotated == element {
                let n = u32::from(element_bits == 64);
                let imms = ((!(element_bits - 1) << 1) | (ones - 1)) & 0x3f;
                return Some(
                    op.bits()
                        | (n << 22)
                        | (immr << 16)
                        | (imms << 10)
                        | (u32::from(rn) << RN_SHIFT)
                        | u32::from(rd),
                );
            }
        }
    }
    None
}

/// `op | imm12<<10 | rn<<5 | rt` — unsigned scaled (×8) 64-bit load/store
/// (`STR`/`LDR [Xn, #imm]`). `imm_bytes` must be a multiple of
/// `LDST_UIMM12_SCALE_64BIT` and at most `LDR_UIMM12_MAX_BYTE_OFFSET`.
fn ldst_uimm12(op: Opcode, rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
    if !imm_bytes.is_multiple_of(LDST_UIMM12_SCALE_64BIT) || imm_bytes > LDR_UIMM12_MAX_BYTE_OFFSET
    {
        return None;
    }
    let imm12 = imm_bytes / LDST_UIMM12_SCALE_64BIT;
    Some(
        op.bits()
            | (u32::from(imm12) << LDST_UIMM12_IMM_SHIFT)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// `op | imm7<<15 | rt2<<10 | rn<<5 | rt` — signed scaled (×8) 64-bit load/store
/// pair (`STP`/`LDP`). `imm_bytes` must be a multiple of 8 within ±512 bytes.
fn ldst_pair(op: Opcode, rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    let imm7_u = u32::from(imm7.cast_unsigned() & IMM7_MASK);
    Some(
        op.bits()
            | (imm7_u << IMM7_SHIFT)
            | (u32::from(rt2) << RT2_SHIFT)
            | (u32::from(rn) << RN_SHIFT)
            | u32::from(rt),
    )
}

/// A single AArch64 instruction emitted into a trampoline, described by its
/// mnemonic and operands. [`Insn::encode`] produces the 32-bit little-endian
/// word; range-checked forms return `None` when an operand is out of range.
///
/// Register operands are register numbers (`X16`, `SP`, ...). This enum, with
/// the format helpers above, is the only place instruction bit layouts live;
/// the gate emitters build `Insn` values and never touch raw opcodes.
#[derive(Clone, Copy)]
enum Insn {
    /// `B` (unconditional branch), PC-relative, ±128MB, 4-byte aligned.
    B(i64),
    /// `ADR Xd, #byte_off` — PC-relative address, ±1MB (byte granularity).
    Adr {
        rd: u8,
        byte_off: i64,
    },
    /// `ADRP Xd, #page_off` — page-relative address, ±4GB (in 4KB pages).
    Adrp {
        rd: u8,
        page_off: i64,
    },
    /// `LDR Xt, <literal>` (PC-relative literal load), ±1MB, 4-byte aligned.
    LdrLiteral {
        rt: u8,
        off: i64,
    },
    /// `BR Xn` (branch to register).
    Br(u8),
    /// `BLR Xn` (branch with link to register).
    Blr(u8),
    /// `RET Xn` (return to register).
    Ret(u8),
    /// `MOVZ Xd, #imm16`.
    Movz {
        rd: u8,
        imm16: u16,
    },
    Nop,
    /// `SUB SP, SP, #imm12`.
    SubSp(u16),
    /// `ADD SP, SP, #imm12`.
    AddSp(u16),
    /// `ADD Xd, Xn, #imm12`.
    AddImm {
        rd: u8,
        rn: u8,
        imm12: u16,
    },
    /// `AND Xd, Xn, #imm`.
    AndImm {
        rd: u8,
        rn: u8,
        imm: u64,
    },
    /// `STR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    StrUimm {
        rt: u8,
        rn: u8,
        imm_bytes: u16,
    },
    /// `LDR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    LdrUimm {
        rt: u8,
        rn: u8,
        imm_bytes: u16,
    },
    /// `STP Xt, Xt2, [Xn, #imm_bytes]` (signed scaled; `imm_bytes` multiple of 8).
    Stp {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `LDP Xt, Xt2, [Xn, #imm_bytes]` (signed scaled; `imm_bytes` multiple of 8).
    Ldp {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `STP Xt, Xt2, [Xn, #imm_bytes]!`.
    StpPre {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `LDP Xt, Xt2, [Xn], #imm_bytes`.
    LdpPost {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `MRS Xt, TPIDR_EL0` (read thread pointer).
    MrsTpidrEl0(u8),
    /// `MRS Xt, TPIDRRO_EL0` (macOS read-only thread pointer).
    MrsTpidrroEl0(u8),
    /// `MOV Xd, Xs`, encoded as `ORR Xd, XZR, Xs`.
    MovReg {
        rd: u8,
        rs: u8,
    },
    /// `CBNZ Wt, #offset`.
    CbnzW {
        rt: u8,
        offset: i64,
    },
    /// `CBZ Wt, #offset`.
    CbzW {
        rt: u8,
        offset: i64,
    },
    /// `CBZ Xt, #offset`.
    CbzX {
        rt: u8,
        offset: i64,
    },
    /// `CBNZ Xt, #offset`.
    CbnzX {
        rt: u8,
        offset: i64,
    },
    /// `TBZ`/`TBNZ Wt, #bit, #offset`.
    TestBranch {
        rt: u8,
        bit: u8,
        offset: i64,
        nonzero: bool,
    },
    /// `BRK #imm16` — software breakpoint raising a synchronous debug exception.
    Brk(u16),
}

impl Insn {
    /// Encode to a 32-bit little-endian instruction word, or `None` if an
    /// operand is outside the instruction's encodable range.
    fn encode(self) -> Option<u32> {
        match self {
            Insn::B(off) => branch_imm26(Opcode::B, off),
            Insn::Adr { rd, byte_off } => pcrel_imm21(Opcode::Adr, rd, byte_off),
            Insn::Adrp { rd, page_off } => pcrel_imm21(Opcode::Adrp, rd, page_off),
            Insn::LdrLiteral { rt, off } => pcrel_imm19(Opcode::LdrLiteral, off, u32::from(rt)),
            Insn::Br(rn) => Some(Opcode::Br.bits() | (u32::from(rn) << RN_SHIFT)),
            Insn::Blr(rn) => Some(Opcode::Blr.bits() | (u32::from(rn) << RN_SHIFT)),
            Insn::Ret(rn) => Some(Opcode::Ret.bits() | (u32::from(rn) << RN_SHIFT)),
            Insn::Movz { rd, imm16 } => {
                Some(Opcode::Movz.bits() | (u32::from(imm16) << RN_SHIFT) | u32::from(rd))
            }
            Insn::Nop => Some(NOP),
            Insn::SubSp(imm12) => data_imm12(Opcode::SubImm, SP, SP, imm12),
            Insn::AddSp(imm12) => data_imm12(Opcode::AddImm, SP, SP, imm12),
            Insn::AddImm { rd, rn, imm12 } => data_imm12(Opcode::AddImm, rd, rn, imm12),
            Insn::AndImm { rd, rn, imm } => logical_imm64(Opcode::AndImm, rd, rn, imm),
            Insn::StrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::StrUimm, rt, rn, imm_bytes),
            Insn::LdrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::LdrUimm, rt, rn, imm_bytes),
            Insn::Stp {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::Stp, rt, rt2, rn, imm_bytes),
            Insn::Ldp {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::Ldp, rt, rt2, rn, imm_bytes),
            Insn::StpPre {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::StpPre, rt, rt2, rn, imm_bytes),
            Insn::LdpPost {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::LdpPost, rt, rt2, rn, imm_bytes),
            Insn::MrsTpidrEl0(rt) => Some(Opcode::MrsTpidrEl0.bits() | u32::from(rt)),
            Insn::MrsTpidrroEl0(rt) => Some(Opcode::MrsTpidrroEl0.bits() | u32::from(rt)),
            Insn::MovReg { rd, rs } => {
                Some(Opcode::MovReg.bits() | (u32::from(rs) << 16) | u32::from(rd))
            }
            Insn::CbnzW { rt, offset } => pcrel_imm19(Opcode::CbnzW, offset, u32::from(rt)),
            Insn::CbzW { rt, offset } => pcrel_imm19(Opcode::CbzW, offset, u32::from(rt)),
            Insn::CbzX { rt, offset } => pcrel_imm19(Opcode::CbzX, offset, u32::from(rt)),
            Insn::CbnzX { rt, offset } => pcrel_imm19(Opcode::CbnzX, offset, u32::from(rt)),
            Insn::TestBranch {
                rt,
                bit,
                offset,
                nonzero,
            } => {
                if bit >= 64 || offset % 4 != 0 {
                    return None;
                }
                let imm14 = i32::try_from(offset >> 2).ok()?;
                if !(-(1 << 13)..(1 << 13)).contains(&imm14) {
                    return None;
                }
                Some(
                    if nonzero {
                        Opcode::Tbnz.bits()
                    } else {
                        Opcode::Tbz.bits()
                    } | (u32::from(bit >> 5) << 31)
                        | (u32::from(bit & 31) << 19)
                        | ((imm14.cast_unsigned() & 0x3fff) << RN_SHIFT)
                        | u32::from(rt),
                )
            }
            Insn::Brk(imm) => Some(Opcode::Brk.bits() | (u32::from(imm) << RN_SHIFT)),
        }
    }
}

// ============================================================
// Host anchor register
// ============================================================

/// The host OS whose TLS and register conventions the gates use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    /// Linux host: the kernel preserves `TPIDR_EL0` across host execution, so
    /// the anchor lives there and the anchor read is `MRS Xd, TPIDR_EL0`.
    Linux,
    /// macOS host: `TPIDRRO_EL0` anchors pthread TSD slots.
    MacOs,
    /// Windows host: physical `x18` points at the thread environment block.
    Windows,
}

/// Runner-selected TLS and SVC stack-frame layout.
#[derive(Clone, Copy)]
pub(crate) struct GateLayout {
    host: Host,
    svc_frame_bytes: u16,
}

impl GateLayout {
    const fn linux(host: Host) -> Self {
        Self {
            host,
            svc_frame_bytes: SVC_FRAME_BYTES,
        }
    }

    pub(crate) const fn darwin(host: Host) -> Self {
        Self {
            host,
            svc_frame_bytes: DARWIN_SVC_FRAME_BYTES,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RewriteConfig {
    host: Host,
    virtualize_x18: bool,
    preserve_host_thread_state: bool,
}

impl From<crate::TargetHost> for Host {
    fn from(target: crate::TargetHost) -> Self {
        match target {
            crate::TargetHost::Linux => Self::Linux,
            crate::TargetHost::MacOs => Self::MacOs,
            crate::TargetHost::Windows => Self::Windows,
        }
    }
}

impl RewriteConfig {
    pub(crate) fn new(target: crate::TargetHost, virtualize_x18: bool) -> Self {
        Self {
            host: target.into(),
            virtualize_x18,
            preserve_host_thread_state: false,
        }
    }

    fn with_host_thread_state_preservation(mut self, preserve: bool) -> Self {
        self.preserve_host_thread_state = preserve;
        self
    }
}

/// Bits occupied by Darwin's CPU-number tag in `TPIDRRO_EL0`.
const DARWIN_TPIDRRO_CPU_TAG_MASK: u64 = 0b111;

fn anchor_mask(rd: u8) -> Insn {
    Insn::AndImm {
        rd,
        rn: rd,
        imm: !DARWIN_TPIDRRO_CPU_TAG_MASK,
    }
}

impl Host {
    /// The instruction a gate uses to read this host's per-thread anchor into
    /// `rd`.
    fn anchor_read(self, rd: u8) -> Insn {
        match self {
            Host::Linux => Insn::MrsTpidrEl0(rd),
            Host::MacOs => Insn::MrsTpidrroEl0(rd),
            Host::Windows => Insn::MovReg { rd, rs: 18 },
        }
    }
}

// ============================================================
// Patch-site scanning
// ============================================================

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
    /// Retain the old inline sequence inside a recognized exclusive region:
    /// a breakpoint unconditionally clears the host's exclusive reservation.
    MsrTpidrInline(u8),
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
            Self::Svc => GateMetadata::SvcTls,
            Self::MsrTpidr(source) | Self::MsrTpidrInline(source) => {
                GateMetadata::MsrTpidr { source }
            }
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
/// x18 sites inside lexical exclusive sequences are rejected. AArch64
/// instructions are fixed-width, so sites are returned in ascending file order.
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

    for section in executable_sections {
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
        // Most objects contain no MSR. Preserve the fast exact scan there,
        // but identify exclusive regions in objects whose writes may trap.
        let track_exclusives = config.virtualize_x18
            || section_data
                .as_chunks::<INSN_BYTES>()
                .0
                .iter()
                .any(|bytes| u32::from_le_bytes(*bytes) & MSR_TPIDR_EL0_MASK == MSR_TPIDR_EL0_BITS);
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
            if !track_exclusives
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
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                if config.host == Host::Windows {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 SVC site is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "SVC site")?
                    )));
                }
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                if config.host == Host::Windows {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 TPIDR_EL0 write is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "TPIDR site")?
                    )));
                }
                let source = (insn & REG_MASK) as u8;
                if inside_exclusive_sequence {
                    if source == X18_ENCODED && config.virtualize_x18 {
                        return Err(Error::UnsupportedExecutable(format!(
                            "AArch64 virtual x18 MSR inside exclusive sequence at {vaddr:#x}"
                        )));
                    }
                    PatchKind::MsrTpidrInline(source)
                } else {
                    PatchKind::MsrTpidr(source)
                }
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                if config.host == Host::Windows {
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
            if inside_exclusive_sequence
                && matches!(
                    kind,
                    PatchKind::X18(_)
                        | PatchKind::X18StackWriteback(_)
                        | PatchKind::X18CompareBranch(_)
                        | PatchKind::X18Adr(_)
                        | PatchKind::X18Branch(_)
                )
            {
                return Err(Error::UnsupportedExecutable(format!(
                    "AArch64 gate inside exclusive sequence at {:#x}",
                    checked_add_u64(section.vaddr, i as u64, "exclusive sequence gate")?
                )));
            }
            sites.push(PatchSite {
                file_offset: start + i,
                vaddr,
                kind,
            });
        }
    }

    Ok(sites)
}

// ============================================================
// Main hooking entry point
// ============================================================

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
    let config = RewriteConfig::new(options.target_host(), false)
        .with_host_thread_state_preservation(options.preserves_host_thread_state());
    let sites = find_macho_patch_sites(sections, buf, !options.uses_native_guest_thread_pointer())?;
    hook_sites(
        buf,
        &sites,
        trampoline_base_addr,
        callback,
        config,
        GateLayout::darwin(config.host),
    )
}

fn find_macho_patch_sites(
    sections: &[TextSectionInfo],
    buf: &[u8],
    rewrite_tpidrro: bool,
) -> Result<Vec<PatchSite>> {
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
                if !rewrite_tpidrro {
                    continue;
                }
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
    let sites = find_macho_patch_sites(sections, buf, true)?;
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
    let sites = find_macho_patch_sites(sections, buf, !options.uses_native_guest_thread_pointer())?;
    sites.iter().try_fold(0usize, |total, site| {
        let gate_bytes = site.kind.metadata().map_or(0, |metadata| {
            if options.preserves_host_thread_state()
                && matches!(metadata, GateMetadata::MrsTpidr { .. })
            {
                HOST_AWARE_MRS_SLOT_BYTES
            } else {
                metadata.slot_size_for_host(options.target_host())
            }
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
        if let PatchKind::MsrTpidr(source) = site.kind {
            let instruction = Insn::Brk(MSR_TPIDR_BRK_BASE | u16::from(source))
                .encode()
                .expect("MSR breakpoint immediate is valid");
            buf[site.file_offset..site.file_offset + INSN_BYTES]
                .copy_from_slice(&instruction.to_le_bytes());
            continue;
        }
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
            gate::GateInstance::new(GateMetadata::SvcTls, next("SVC return")?),
            layout,
        ),
        PatchKind::MsrTpidr(source) | PatchKind::MsrTpidrInline(source) => (
            gate::GateInstance::new(GateMetadata::MsrTpidr { source }, next("MSR return")?),
            GateLayout::linux(config.host),
        ),
        PatchKind::MrsTpidr(destination) => (
            gate::GateInstance::new(
                if config.preserve_host_thread_state {
                    GateMetadata::HostAwareMrsTpidr { destination }
                } else {
                    GateMetadata::MrsTpidr { destination }
                },
                next("MRS return")?,
            ),
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
        Err(error) => return Err(error.into()),
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

impl From<gate::BuildError> for Error {
    fn from(error: gate::BuildError) -> Self {
        match error {
            gate::BuildError::Unreachable => {
                Error::AddressOverflow("AArch64 gate target out of range".into())
            }
            gate::BuildError::Overflow(context) => {
                Error::AddressOverflow(format!("{context} address overflow"))
            }
            gate::BuildError::Literal(offset) => {
                Error::AddressOverflow(format!("LDR literal offset {offset:#x} out of ±1MB range"))
            }
            gate::BuildError::Unencodable(what) => Error::AddressOverflow(what.into()),
            gate::BuildError::Unsupported(what) => Error::UnsupportedExecutable(what.into()),
            gate::BuildError::TooLarge(bytes) => Error::AddressOverflow(format!(
                "AArch64 gate is {bytes} bytes and does not fit before slot metadata"
            )),
            gate::BuildError::Metadata => {
                Error::AddressOverflow("invalid AArch64 gate metadata".into())
            }
        }
    }
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

/// Emit the callback header and deterministic alignment padding.
fn emit_shared_prologue(trampoline_data: &mut Vec<u8>, callback: u64) {
    // Offset 0: callback address.
    trampoline_data.extend_from_slice(&callback.to_le_bytes());

    while trampoline_data.len() < GATES_START_OFFSET {
        trampoline_data.extend_from_slice(&NOP.to_le_bytes());
    }
}

impl GateMetadata {
    /// Byte size of this gate's direct-TLS layout.
    pub const fn slot_size(self) -> usize {
        match self {
            GateMetadata::Svc | GateMetadata::SvcTls => SVC_SLOT_BYTES,
            GateMetadata::MrsTpidr { .. } => MRS_SLOT_BYTES,
            GateMetadata::HostAwareMrsTpidr { .. } => HOST_AWARE_MRS_SLOT_BYTES,
            GateMetadata::MsrTpidr { .. } => MSR_SLOT_BYTES,
            GateMetadata::X18 { .. } => X18_SLOT_BYTES,
            GateMetadata::X18StackWriteback { .. } => X18_STACK_WRITEBACK_SLOT_BYTES,
            GateMetadata::X18CompareBranch { .. } => X18_COMPARE_BRANCH_SLOT_BYTES,
            GateMetadata::X18Adr { .. } => X18_ADR_SLOT_BYTES,
            GateMetadata::X18Branch { .. } => X18_BRANCH_SLOT_BYTES,
        }
    }

    /// Returns this gate's slot size for the selected host layout.
    pub const fn slot_size_for_host(self, host: crate::TargetHost) -> usize {
        self.slot_size_for(match host {
            crate::TargetHost::Linux => Host::Linux,
            crate::TargetHost::MacOs => Host::MacOs,
            crate::TargetHost::Windows => Host::Windows,
        })
    }

    const fn slot_size_for(self, host: Host) -> usize {
        if !matches!(host, Host::MacOs) {
            return self.slot_size();
        }
        match self {
            GateMetadata::SvcTls => SVC_SLOT_BYTES + GATE_ALIGNMENT,
            GateMetadata::MrsTpidr { .. } => MRS_SLOT_BYTES + GATE_ALIGNMENT,
            GateMetadata::MsrTpidr { .. } => MSR_SLOT_BYTES + GATE_ALIGNMENT,
            GateMetadata::X18 { .. } => X18_SLOT_BYTES + GATE_ALIGNMENT,
            GateMetadata::X18StackWriteback { .. } => {
                X18_STACK_WRITEBACK_SLOT_BYTES + GATE_ALIGNMENT
            }
            GateMetadata::X18CompareBranch { .. } => X18_COMPARE_BRANCH_SLOT_BYTES + GATE_ALIGNMENT,
            GateMetadata::X18Adr { .. } => X18_ADR_SLOT_BYTES + GATE_ALIGNMENT,
            _ => self.slot_size(),
        }
    }
}

/// Decode one little-endian metadata word copied from a candidate slot.
pub fn decode_gate_metadata_word(word: u32) -> Option<GateMetadata> {
    EncodedGateMetadata(word).decode()
}

/// A validated gate slot containing some PC, with what a signal handler needs
/// to canonicalize the interrupted context: where the slot starts, which guest
/// instruction it replaced, and the recovery stage of the interrupted
/// instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedGate {
    slot_offset: usize,
    slot_size: u8,
    anchor_scratch: u8,
    stack_delta: i16,
    stack_frame_bytes: u16,
    original_site: u64,
    conditional_target: u64,
    metadata: GateMetadata,
    stage: Stage,
}

impl ClassifiedGate {
    /// Builds the classification of `pc` within a validated slot, or `None`
    /// when `pc` is not on an executable gate instruction.
    fn new(
        slot_offset: usize,
        slot: &gate::BuiltSlot,
        instance: &gate::GateInstance,
        pc_offset: usize,
    ) -> Option<Self> {
        let metadata = instance.metadata;
        let is_x18 = is_x18_gate(metadata);
        let stack = matches!(metadata, GateMetadata::X18StackWriteback { .. });
        Some(Self {
            slot_offset,
            slot_size: u8::try_from(slot.words().len() * INSN_BYTES).ok()?,
            anchor_scratch: if is_x18 { instance.anchor } else { 0 },
            stack_delta: if stack { instance.stack.delta } else { 0 },
            stack_frame_bytes: if stack { instance.stack.frame_bytes } else { 0 },
            original_site: instance.return_addr.checked_sub(INSN_BYTES_U64)?,
            conditional_target: if matches!(metadata, GateMetadata::X18CompareBranch { .. }) {
                instance.taken
            } else {
                0
            },
            metadata,
            stage: slot.stage_at(pc_offset)?,
        })
    }

    /// Byte offset of the validated slot within the trampoline.
    pub fn slot_offset(self) -> usize {
        self.slot_offset
    }

    /// Kind-derived byte size of the validated slot.
    pub fn slot_size(self) -> u8 {
        self.slot_size
    }

    pub fn anchor_scratch(self) -> Option<u8> {
        (is_x18_gate(self.metadata) && !matches!(self.metadata, GateMetadata::X18Branch { .. }))
            .then_some(self.anchor_scratch)
    }

    /// `(writeback displacement, scratch-frame depth)` for an SP-writeback pair.
    pub fn stack_writeback(self) -> Option<(i16, u16)> {
        matches!(self.metadata, GateMetadata::X18StackWriteback { .. })
            .then_some((self.stack_delta, self.stack_frame_bytes))
    }

    /// Original guest instruction address recovered from the return branch.
    pub fn original_site(self) -> u64 {
        self.original_site
    }

    /// Original taken target of a conditional x18 gate.
    pub fn conditional_target(self) -> Option<u64> {
        matches!(self.metadata, GateMetadata::X18CompareBranch { .. })
            .then_some(self.conditional_target)
    }

    /// Decoded semantic gate metadata.
    pub fn metadata(self) -> GateMetadata {
        self.metadata
    }

    /// Recovery stage of the interrupted gate instruction.
    pub fn stage(self) -> Stage {
        self.stage
    }
}

/// Whether `metadata` names a gate that virtualizes guest x18.
pub fn is_x18_gate(metadata: GateMetadata) -> bool {
    matches!(
        metadata,
        GateMetadata::X18 { .. }
            | GateMetadata::X18StackWriteback { .. }
            | GateMetadata::X18CompareBranch { .. }
            | GateMetadata::X18Adr { .. }
            | GateMetadata::X18Branch { .. }
    )
}

/// Classifies a Linux-host AArch64 trampoline PC by testing aligned candidate
/// slot starts and requiring exactly one exact-template match.
pub fn classify_gate_pc(
    trampoline: &[u8],
    trampoline_base: u64,
    pc: u64,
) -> Option<ClassifiedGate> {
    if !pc.is_multiple_of(INSN_BYTES_U64) {
        return None;
    }
    let relative = usize::try_from(pc.checked_sub(trampoline_base)?).ok()?;
    let aligned = relative & !(GATE_ALIGNMENT - 1);
    let candidates: [usize; GATE_PC_CANDIDATE_COUNT] =
        core::array::from_fn(|index| aligned.saturating_sub(index * GATE_ALIGNMENT));
    classify_gate_pc_with_candidates(trampoline, trampoline_base, pc, candidates)
}

fn classify_gate_pc_with_candidates<const N: usize>(
    trampoline: &[u8],
    trampoline_base: u64,
    pc: u64,
    candidates: [usize; N],
) -> Option<ClassifiedGate> {
    let relative = usize::try_from(pc.checked_sub(trampoline_base)?).ok()?;
    let mut match_found = None;
    for start in candidates {
        if start < GATES_START_OFFSET || !start.is_multiple_of(GATE_ALIGNMENT) {
            continue;
        }
        for slot_size in GATE_SLOT_SIZES {
            let end = start.checked_add(slot_size)?;
            if relative < start || relative >= end || end > trampoline.len() {
                continue;
            }
            let metadata_word =
                u32::from_le_bytes(trampoline[end - GATE_METADATA_BYTES..end].try_into().ok()?);
            let Some(metadata) = EncodedGateMetadata(metadata_word).decode() else {
                continue;
            };
            let mut slot = gate::BuiltSlot::empty();
            let Some(instance) = gate::validate(
                &trampoline[start..end],
                gate::SlotAddressing::Placed {
                    trampoline_base,
                    slot_vaddr: trampoline_base + start as u64,
                },
                metadata,
                GateLayout::linux(Host::Linux),
                &mut slot,
            ) else {
                continue;
            };
            let Some(classified) = ClassifiedGate::new(start, &slot, &instance, relative - start)
            else {
                continue;
            };
            if match_found.is_some() {
                return None;
            }
            match_found = Some(classified);
        }
    }
    match_found
}

/// Classify an ELF guest's copied gate slot using the selected host's TLS layout.
/// The caller must require exactly one matching candidate.
pub fn classify_copied_gate_slot_for_host(
    slot: &[u8],
    slot_vaddr: u64,
    pc: u64,
    host: crate::TargetHost,
) -> Option<ClassifiedGate> {
    classify_copied_gate_slot_with_layout(slot, slot_vaddr, pc, GateLayout::linux(host.into()))
}

pub(crate) fn classify_copied_gate_slot_with_layout(
    slot: &[u8],
    slot_vaddr: u64,
    pc: u64,
    layout: GateLayout,
) -> Option<ClassifiedGate> {
    let offset = usize::try_from(pc.checked_sub(slot_vaddr)?).ok()?;
    if !pc.is_multiple_of(INSN_BYTES_U64) {
        return None;
    }
    let metadata_word =
        u32::from_le_bytes(slot.get(slot.len().checked_sub(4)?..)?.try_into().ok()?);
    let metadata = EncodedGateMetadata(metadata_word).decode()?;
    // The SVC gate's base comes from the slot's own literal load, so its
    // callback-target check is a tautology here. The other template checks
    // still do real work; this is structural recognition, not authentication.
    // One slot buffer serves the base lookup, the probe and the rebuild, which
    // keeps this signal-handler path's stack small.
    let mut built = gate::BuiltSlot::empty();
    let trampoline_base = if matches!(metadata, GateMetadata::Svc | GateMetadata::SvcTls) {
        gate::svc_trampoline_base(slot, slot_vaddr, layout.host, &mut built)?
    } else {
        0
    };
    let instance = gate::validate(
        slot,
        gate::SlotAddressing::Placed {
            trampoline_base,
            slot_vaddr,
        },
        metadata,
        layout,
        &mut built,
    )?;
    ClassifiedGate::new(0, &built, &instance, offset)
}

fn valid_emitted_tpidr_offset(offset: u32) -> bool {
    offset == u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER)
        || (offset.is_multiple_of(u32::from(GUEST_TPIDR_OFFSET_ALIGN))
            && (u32::from(MIN_GUEST_TPIDR_OFFSET)..u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER))
                .contains(&offset))
}

fn valid_emitted_x18_offset(offset: u32) -> bool {
    offset == u32::from(GUEST_X18_OFFSET_PLACEHOLDER)
        || (offset.is_multiple_of(u32::from(GUEST_TPIDR_OFFSET_ALIGN))
            && (u32::from(MIN_GUEST_TPIDR_OFFSET)..u32::from(GUEST_X18_OFFSET_PLACEHOLDER))
                .contains(&offset))
}

/// Decodes an AArch64 unconditional immediate branch at `pc`.
/// Returns `None` if `word` is not `B` or the target overflows `u64`.
pub fn decode_branch_target(word: u32, pc: u64) -> Option<u64> {
    if word & OPCODE_TOP6_MASK != Opcode::B.bits() {
        return None;
    }
    let imm26 = i64::from(word & IMM26_MASK);
    let displacement = pcrel_bytes(imm26, IMM26_BITS);
    pc.checked_add_signed(displacement)
}

fn decode_ldr_literal_target(word: u32, pc: u64) -> Option<u64> {
    if word & LDR_LITERAL_SHAPE_MASK != Opcode::LdrLiteral.bits() | u32::from(X16) {
        return None;
    }
    let imm19 = i64::from((word >> RN_SHIFT) & IMM19_MASK);
    let displacement = pcrel_bytes(imm19, IMM19_BITS);
    pc.checked_add_signed(displacement)
}

#[cfg(test)]
fn decode_adrp_add_target_for(adrp: u32, add: u32, pc: u64, register: u8) -> Option<u64> {
    let page = decode_adrp_target(adrp, pc, register)?;
    if add & ADD_IMM_SHAPE_MASK
        != Opcode::AddImm.bits() | (u32::from(register) << RN_SHIFT) | u32::from(register)
    {
        return None;
    }
    page.checked_add(u64::from(add >> RT2_SHIFT) & PAGE_OFFSET_MASK)
}

#[cfg(test)]
fn decode_adrp_target(adrp: u32, pc: u64, rd: u8) -> Option<u64> {
    if adrp & ADRP_SHAPE_MASK != Opcode::Adrp.bits() | u32::from(rd) {
        return None;
    }
    let immlo = i64::from((adrp >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
    let immhi = i64::from((adrp >> RN_SHIFT) & IMM19_MASK);
    let imm21 = (immhi << 2) | immlo;
    let page_delta = sign_extend(imm21, IMM21_BITS) << ADRP_PAGE_SHIFT;
    (pc & !PAGE_OFFSET_MASK).checked_add_signed(page_delta)
}

// ============================================================
// Load-time guest thread-pointer offset patching
// ============================================================

/// The scaled 12-bit immediate field of an unsigned-offset load/store, \[21:10].
const LDST_UIMM12_IMM_MASK: u32 = 0x003F_FC00;
/// Bit position of that immediate field.
const LDST_UIMM12_IMM_SHIFT: u32 = 10;

/// Validates and patches every thread-pointer gate in a Linux-host trampoline.
/// Trampolines containing x18 gates must use
/// [`finalize_trampoline_gates_for_host`].
///
/// # Errors
///
/// Rejects invalid offsets, malformed slots, unexpected field values, and x18
/// gates before mutating the trampoline.
pub fn finalize_trampoline_gates(trampoline: &mut [u8], offset: u16) -> Result<()> {
    validate_guest_offset(offset, false)?;
    let validation = validate_trampoline_offsets_for_host(trampoline, offset, false, Host::Linux)?;
    if validation.has_x18_gate {
        return Err(Error::TrampolinePatchFailure(
            "AArch64 trampoline contains x18 gates or placeholders; use \
             finalize_trampoline_gates_for_host"
                .into(),
        ));
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(())
}

/// Validate and finalize an ELF guest's TLS gates for `host`.
///
/// Direct-TLS gates patch the guest TP and x18 field offsets independently.
/// Indirect-TLS gates patch both accesses with the root offset and use fixed
/// in-block field offsets. Leaves bytes unchanged on error.
pub fn finalize_trampoline_gates_for_host(
    trampoline: &mut [u8],
    guest_tpidr_offset: u16,
    guest_x18_offset: u16,
    host: crate::TargetHost,
) -> Result<()> {
    let expected_x18_offset = usize::from(guest_tpidr_offset)
        .checked_add(GUEST_X18_OFFSET_FROM_GUEST_TP)
        .and_then(|offset| u16::try_from(offset).ok());
    if expected_x18_offset != Some(guest_x18_offset) {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest x18 offset {guest_x18_offset} does not immediately follow guest thread-pointer \
             offset {guest_tpidr_offset}"
        )));
    }
    validate_guest_offset(guest_tpidr_offset, false)?;
    let host = host.into();
    let tp = validate_trampoline_offsets_for_host(trampoline, guest_tpidr_offset, false, host)?;
    validate_guest_offset(guest_x18_offset, true)?;
    // Indirect-TLS gates patch the root pointer load; field offsets are fixed.
    let x18_patch_value = if host == Host::MacOs {
        guest_tpidr_offset
    } else {
        guest_x18_offset
    };
    let x18 = validate_trampoline_offsets_for_host(trampoline, x18_patch_value, true, host)?;
    // Both sets are validated before mutation, so an error cannot leave a partial patch.
    patch_offset_words(trampoline, &tp.patch_offsets, guest_tpidr_offset);
    patch_offset_words(trampoline, &x18.patch_offsets, x18_patch_value);
    Ok(())
}

pub(crate) fn finalize_macho_trampoline(
    trampoline: &mut [u8],
    offset: u16,
    host: crate::TargetHost,
) -> Result<()> {
    validate_guest_offset(offset, false)?;
    let validation = validate_trampoline_offsets_with_layout(
        trampoline,
        offset,
        false,
        GateLayout::darwin(host.into()),
    )?;
    if validation.has_x18_gate {
        return Err(Error::TrampolinePatchFailure(
            "unexpected x18 gate in Mach-O trampoline".into(),
        ));
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(())
}

/// Whether `offset` is aligned and within the range accepted by guest TLS gates.
pub fn is_patchable_guest_tpidr_offset(offset: u16) -> bool {
    offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
        && (MIN_GUEST_TPIDR_OFFSET..GUEST_TPIDR_OFFSET_PLACEHOLDER).contains(&offset)
}

/// Whether `offset` is valid for a direct-TLS x18 access.
pub fn is_patchable_guest_x18_offset(offset: u16) -> bool {
    offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
        && (MIN_GUEST_TPIDR_OFFSET..GUEST_X18_OFFSET_PLACEHOLDER).contains(&offset)
}

/// Rewrites the guest thread-pointer offset in every Linux gate of one emitted
/// trampoline. The loader must call this before making the trampoline executable.
///
/// Returns the number of instructions patched. Zero is normal: a binary whose
/// only patch sites are `SVC` has no thread-pointer gate.
///
/// # Errors
///
/// Fails if `offset` is not a legitimate gate target — a multiple of
/// [`GUEST_TPIDR_OFFSET_ALIGN`], at least `MIN_GUEST_TPIDR_OFFSET` so it clears
/// the host's own per-thread state, and strictly below
/// [`MAX_GUEST_TPIDR_OFFSET`], which is reserved as the placeholder. Also fails
/// if the blob is not a well-formed trampoline: too short for the shared
/// prologue, not a whole number of instruction words, or holding a placeholder
/// in a metadata-designated field with an unexpected value. Trampolines with
/// x18 gates must instead use [`finalize_trampoline_gates_for_host`].
///
/// # Panics
///
/// Panics if a validated slot is shorter than its own metadata word, which the
/// slot templates make impossible.
pub fn patch_guest_tpidr_offset(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    validate_guest_offset(offset, false)?;
    let validation = validate_trampoline_offsets_for_host(trampoline, offset, false, Host::Linux)?;
    if validation.has_x18_gate {
        return Err(Error::TrampolinePatchFailure(
            "AArch64 trampoline contains x18 gates; use finalize_trampoline_gates_for_host".into(),
        ));
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(validation.patch_offsets.len())
}

fn validate_guest_offset(offset: u16, x18: bool) -> Result<()> {
    let (valid, slot, upper_bound) = if x18 {
        (
            is_patchable_guest_x18_offset(offset),
            "x18",
            GUEST_X18_OFFSET_PLACEHOLDER,
        )
    } else {
        (
            is_patchable_guest_tpidr_offset(offset),
            "thread-pointer",
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
        )
    };
    if !valid {
        return Err(Error::TrampolinePatchFailure(format!(
            "invalid guest {slot} offset {offset}: must be a multiple of \
             {GUEST_TPIDR_OFFSET_ALIGN}, at least {MIN_GUEST_TPIDR_OFFSET}, and below {upper_bound}"
        )));
    }
    Ok(())
}

fn patch_offset_words(trampoline: &mut [u8], patch_offsets: &[(usize, u16)], root: u16) {
    for &(offset, bias) in patch_offsets {
        // Validation checked every derived offset before any mutation.
        let new_imm = u32::from((root + bias) / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
        let word = &mut trampoline[offset..offset + INSN_BYTES];
        let insn = u32::from_le_bytes(word.try_into().expect("four-byte patch offset"));
        word.copy_from_slice(&((insn & !LDST_UIMM12_IMM_MASK) | new_imm).to_le_bytes());
    }
}

struct TrampolineValidation {
    patch_offsets: Vec<(usize, u16)>,
    has_x18_gate: bool,
}

fn validate_trampoline_offsets_for_host(
    trampoline: &[u8],
    expected_offset: u16,
    x18: bool,
    host: Host,
) -> Result<TrampolineValidation> {
    validate_trampoline_offsets_with_layout(
        trampoline,
        expected_offset,
        x18,
        GateLayout::linux(host),
    )
}

fn validate_trampoline_offsets_with_layout(
    trampoline: &[u8],
    expected_offset: u16,
    x18: bool,
    layout: GateLayout,
) -> Result<TrampolineValidation> {
    if trampoline.len() < GATES_START_OFFSET || !trampoline.len().is_multiple_of(INSN_BYTES) {
        return Err(Error::TrampolinePatchFailure(
            "malformed AArch64 trampoline length".into(),
        ));
    }
    if trampoline[8..GATES_START_OFFSET]
        .as_chunks::<4>()
        .0
        .iter()
        .any(|word| u32::from_le_bytes(*word) != NOP)
    {
        return Err(Error::TrampolinePatchFailure(
            "malformed AArch64 trampoline header padding".into(),
        ));
    }

    let mut cursor = GATES_START_OFFSET;
    let mut patch_offsets = Vec::new();
    let mut has_x18_gate = false;
    while cursor < trampoline.len() {
        let mut matched = None;
        for slot_size in GATE_SLOT_SIZES {
            let Some(end) = cursor
                .checked_add(slot_size)
                .filter(|&end| end <= trampoline.len())
            else {
                continue;
            };
            let metadata_word = u32::from_le_bytes(
                trampoline[end - GATE_METADATA_BYTES..end]
                    .try_into()
                    .unwrap(),
            );
            let Some(metadata) = EncodedGateMetadata(metadata_word).decode() else {
                continue;
            };
            let mut slot = gate::BuiltSlot::empty();
            if gate::validate(
                &trampoline[cursor..end],
                gate::SlotAddressing::Unplaced {
                    slot_offset: cursor as u64,
                },
                metadata,
                layout,
                &mut slot,
            )
            .is_none()
            {
                continue;
            }
            if matched.is_some() {
                return Err(Error::TrampolinePatchFailure(
                    "ambiguous AArch64 compact slot".into(),
                ));
            }
            matched = Some((end, metadata, slot));
        }
        let Some((end, metadata, slot)) = matched else {
            return Err(Error::TrampolinePatchFailure(format!(
                "malformed AArch64 compact slot at byte {cursor}"
            )));
        };
        has_x18_gate |= is_x18_gate(metadata);
        // Each pass patches the TLS fields of its own gate family: guest-TP
        // gates, or x18 gates (whose indirect-TLS root loads take the TP root).
        if is_x18_gate(metadata) == x18 {
            for (offset, field) in slot.tls_words() {
                let offset = cursor + offset;
                let insn =
                    u32::from_le_bytes(trampoline[offset..offset + INSN_BYTES].try_into().unwrap());
                let encoded = (insn & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
                let gate_offset = encoded * u32::from(GUEST_TPIDR_OFFSET_ALIGN);
                let derived = expected_offset
                    .checked_add(field.bias())
                    .filter(|offset| *offset < MAX_GUEST_TPIDR_OFFSET)
                    .ok_or_else(|| {
                        Error::TrampolinePatchFailure(
                            "derived AArch64 TLS field offset is out of range".into(),
                        )
                    })?;
                if gate_offset == u32::from(field.placeholder()) {
                    patch_offsets.push((offset, field.bias()));
                } else if gate_offset != u32::from(derived) {
                    return Err(Error::TrampolinePatchFailure(format!(
                        "AArch64 gate at byte {offset} uses TLS offset {gate_offset}, which is \
                         neither the placeholder nor the offset being patched in \
                         ({expected_offset})"
                    )));
                }
            }
        }
        cursor = end;
    }
    Ok(TrampolineValidation {
        patch_offsets,
        has_x18_gate,
    })
}

/// Byte offset of the first Linux-host gate instruction that still carries the
/// emitted placeholder.
///
/// Only metadata-designated thread-pointer fields in validated gate templates
/// are considered; copied guest instructions cannot create false positives.
/// This inspection helper also returns `None` for malformed/non-Linux input;
/// loaders must use the `Result`-returning finalizers for acceptance.
pub fn find_guest_tpidr_placeholder(trampoline: &[u8]) -> Option<usize> {
    find_structured_placeholder(trampoline, false)
}

/// Returns the first unfinalized guest-x18 access in a valid Linux-host
/// trampoline. Returns `None` for malformed/non-Linux input as well as absence;
/// loaders must use [`finalize_trampoline_gates_for_host`] for acceptance.
#[cfg(test)]
fn find_guest_x18_placeholder(trampoline: &[u8]) -> Option<usize> {
    find_structured_placeholder(trampoline, true)
}

fn find_structured_placeholder(trampoline: &[u8], x18: bool) -> Option<usize> {
    let validation = validate_trampoline_offsets_for_host(
        trampoline,
        // A valid hypothetical root lets validation range-check derived TLS
        // fields too. Placeholder words are returned regardless of that root;
        // already-finalized words need not be accepted by this inspection API.
        MIN_GUEST_TPIDR_OFFSET,
        x18,
        Host::Linux,
    )
    .ok()?;
    validation
        .patch_offsets
        .into_iter()
        .next()
        .map(|(offset, _)| offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_fallback_traps_use_shared_marker() {
        let original = 0xd53bd052u32; // MRS x18, TPIDR_EL0: unsupported overlap
        let config = RewriteConfig::new(crate::TargetHost::MacOs, true);
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
        let (_, outcome) = hook_legacy_words_opt_with_config(
            &words,
            0x1000,
            0x400000,
            RewriteConfig::new(crate::TargetHost::MacOs, true),
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
    fn macos_host_cache_gate_selects_guest_state_without_changing_host_tpidrro() {
        let mut code = Insn::MrsTpidrroEl0(9).encode().unwrap().to_le_bytes();
        let sections = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: code.len() as u64,
        }];
        let outcome = hook_macho(
            &mut code,
            &sections,
            0x400000,
            0,
            crate::RewriteOptions::macos_host_shared_cache(),
        )
        .unwrap()
        .unwrap();
        let gate = &outcome.trampoline[GATES_START_OFFSET..];
        assert_eq!(gate.len(), HOST_AWARE_MRS_SLOT_BYTES);
        assert_eq!(
            decode_gate_metadata_word(word_at(gate, HOST_AWARE_MRS_SLOT_BYTES - 4)),
            Some(GateMetadata::HostAwareMrsTpidr { destination: 9 })
        );
        assert_eq!(word_at(gate, 0), Insn::MrsTpidrroEl0(9).encode().unwrap());
        assert_eq!(
            word_at(gate, 16),
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: IN_GUEST_OFFSET_FROM_GUEST_TP,
            }
            .encode()
            .unwrap()
        );
        assert_eq!(word_at(gate, 44), Insn::MrsTpidrroEl0(9).encode().unwrap());

        let mut finalized = outcome.trampoline;
        finalize_macho_trampoline(&mut finalized, 24, crate::TargetHost::MacOs).unwrap();
        for offset in [GATES_START_OFFSET + 8, GATES_START_OFFSET + 32] {
            assert_eq!(
                word_at(&finalized, offset),
                Insn::LdrUimm {
                    rt: 9,
                    rn: 9,
                    imm_bytes: 24,
                }
                .encode()
                .unwrap()
            );
        }
        let gate_vaddr = 0x400000 + GATES_START_OFFSET as u64;
        let executable_end =
            GateMetadata::HostAwareMrsTpidr { destination: 9 }.executable_end_for_host(Host::MacOs);
        assert_eq!(executable_end, 52);
        for offset in (0..executable_end).step_by(INSN_BYTES) {
            let classified = classify_copied_gate_slot_with_layout(
                &finalized[GATES_START_OFFSET..],
                gate_vaddr,
                gate_vaddr + offset as u64,
                GateLayout::darwin(Host::MacOs),
            )
            .unwrap();
            assert_eq!(classified.original_site(), 0x1000);
        }
        // The host-path MRS is reachable only from host mode.
        assert_eq!(
            classify_copied_gate_slot_with_layout(
                &finalized[GATES_START_OFFSET..],
                gate_vaddr,
                gate_vaddr + 44,
                GateLayout::darwin(Host::MacOs),
            )
            .map(ClassifiedGate::stage),
            Some(Stage::Invalid)
        );

        let mut malformed = finalized[GATES_START_OFFSET..].to_vec();
        malformed[16..20].copy_from_slice(
            &Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: IN_GUEST_OFFSET_FROM_GUEST_TP + 8,
            }
            .encode()
            .unwrap()
            .to_le_bytes(),
        );
        assert!(
            classify_copied_gate_slot_with_layout(
                &malformed,
                gate_vaddr,
                gate_vaddr,
                GateLayout::darwin(Host::MacOs),
            )
            .is_none()
        );
    }

    #[test]
    fn host_aware_mrs_stages_cover_every_executable_boundary() {
        let mut code = Insn::MrsTpidrroEl0(9).encode().unwrap().to_le_bytes();
        let sections = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: code.len() as u64,
        }];
        let outcome = hook_macho(
            &mut code,
            &sections,
            0x400000,
            0,
            crate::RewriteOptions::macos_host_shared_cache(),
        )
        .unwrap()
        .unwrap();
        let incomplete = recover(
            Frame::None,
            GuestSp::Signal,
            Value::None,
            Resume::Site,
            false,
        );
        let from_slot = recover(
            Frame::None,
            GuestSp::Signal,
            Value::Slot,
            Resume::Next,
            true,
        );
        let from_register = recover(
            Frame::None,
            GuestSp::Signal,
            Value::None,
            Resume::Next,
            false,
        );
        let mut expected = vec![Some(incomplete)];
        expected.extend([Some(from_slot); 9]);
        expected.extend([
            Some(from_register),
            Some(Stage::Invalid),
            Some(from_register),
            None,
        ]);
        assert_eq!(
            slot_stages(
                &outcome.trampoline[GATES_START_OFFSET..],
                0x400000 + GATES_START_OFFSET as u64,
                GateLayout::darwin(Host::MacOs),
            )[..expected.len()],
            expected
        );
    }

    #[test]
    fn macos_native_guest_tpidrro_leaves_reads_native() {
        let options = crate::RewriteOptions::macos_native_guest_tpidrro();
        assert!(!options.preserves_host_thread_state());
        let mrs = Insn::MrsTpidrroEl0(9).encode().unwrap();
        let mut code = [mrs.to_le_bytes(), DARWIN_SVC.to_le_bytes()].concat();
        let sections = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: code.len() as u64,
        }];
        let outcome = hook_macho(&mut code, &sections, 0x400000, 0, options)
            .unwrap()
            .unwrap();
        assert_eq!(word_at(&code, 0), mrs);
        assert_ne!(word_at(&code, 4), DARWIN_SVC);
        assert_eq!(
            decode_gate_metadata_word(word_at(
                &outcome.trampoline,
                GATES_START_OFFSET + GateMetadata::SvcTls.slot_size_for(Host::MacOs)
                    - GATE_METADATA_BYTES,
            )),
            Some(GateMetadata::SvcTls)
        );
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
        let (_, outcome) = hook_legacy_words_opt_with_config(
            &words,
            0x1000,
            0x400000,
            RewriteConfig::new(crate::TargetHost::MacOs, true),
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

        let (_, linux) =
            hook_legacy_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        assert_ne!(
            word_at(&linux, GATES_START_OFFSET + INSN_BYTES),
            anchor_mask(9).encode().unwrap()
        );
        assert_eq!(linux.len(), GATES_START_OFFSET + MRS_SLOT_BYTES);
    }

    #[test]
    fn windows_rejects_linux_specific_sites_but_accepts_x18_only_scan() {
        let config = RewriteConfig::new(crate::TargetHost::Windows, true);
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
        let config = RewriteConfig::new(crate::TargetHost::MacOs, true);
        let (_, outcome) = hook_words_opt_with_config(&words, 0x1000, 0x400000, config);
        let mut trampoline = outcome.unwrap().trampoline;
        let original = trampoline.clone();
        assert!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::Linux)
                .is_err()
        );
        assert_eq!(trampoline, original);
        assert!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 112, crate::TargetHost::MacOs)
                .is_err()
        );
        assert_eq!(trampoline, original);
        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::MacOs)
            .unwrap();
        // Re-finalization is idempotent; a different slot layout is rejected.
        let finalized = trampoline.clone();
        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::MacOs)
            .unwrap();
        assert_eq!(trampoline, finalized);
        assert!(
            finalize_trampoline_gates_for_host(&mut trampoline, 112, 120, crate::TargetHost::MacOs)
                .is_err()
        );
        assert_eq!(trampoline, finalized);
    }

    #[test]
    fn msr_register_x18_fails_closed_despite_decoder_truncation() {
        assert!(matches!(
            classify_x18(0xd51b_4412), // msr fpcr, x18
            X18Classification::X18(X18TransformResult::Unsupported(
                X18Unsupported::EncodingLayout
            ))
        ));
        assert_eq!(classify_x18(0xd51b_4402), X18Classification::None); // msr fpcr, x2
    }

    #[test]
    fn negative_sp_relative_x18_access_is_rejected() {
        assert!(matches!(
            classify_x18(0xf81f_83f2), // stur x18, [sp, #-8]
            X18Classification::X18(X18TransformResult::Unsupported(
                X18Unsupported::EncodingLayout
            ))
        ));
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
                RewriteConfig {
                    host: Host::Linux,
                    virtualize_x18: true,
                    preserve_host_thread_state: false,
                },
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
    fn x18_semantics_override_raw_vector_fields() {
        for word in [0xaa00_03f2, 0x0b12_0063] {
            assert!(
                matches!(
                    classify_x18(word),
                    X18Classification::X18(X18TransformResult::Supported(_))
                ),
                "word {word:#010x}"
            );
        }
        for word in [
            0x4eb2_1e50, // mov v16.16b, v18.16b
            0x1400_0012, // b .+72
        ] {
            assert_eq!(classify_x18(word), X18Classification::None);
        }
    }

    #[test]
    fn x18_required_register_field_table() {
        for (word, transformed) in [
            (0xaa00_03f2, 0xaa00_03f1), // Rd
            (0xaa12_03e0, 0xaa11_03e0), // Rm
            (0x0b12_0063, 0x0b11_0063), // ADD Rm
            (0xf940_0642, 0xf940_0622), // memory base
            (0xf832_7824, 0xf831_7824), // memory index
            (0xa906_4bee, 0xa906_47ee), // STP Rt2
            (0xa801_480e, 0xa801_440e), // STNP Rt2
            (0xa841_480e, 0xa841_440e), // LDNP Rt2
            (0x6942_480e, 0x6942_440e), // LDPSW Rt2
            (0x9b08_486b, 0x9b08_446b), // MADD Ra
            (0x9b12_8c41, 0x9b11_8c41), // MSUB Rm
            (0x9b25_48a4, 0x9b25_44a4), // SMADDL Ra
            (0x9b32_8c41, 0x9b31_8c41), // SMSUBL Rm
            (0x9ba3_4841, 0x9ba3_4441), // UMADDL Ra
            (0x9bb2_8c41, 0x9bb1_8c41), // UMSUBL Rm
            (0xfa5e_1244, 0xfa5e_1224), // CCMP Rn
            (0x7a52_1344, 0x7a51_1344), // CCMP Rm
            (0xba52_1244, 0xba51_1224), // CCMN Rn/Rm
            (0x9ad2_25d2, 0x9ad1_25d1), // shift Rd/Rm
            (0x1a92_1146, 0x1a91_1146), // CSEL Rm
            (0x93d2_4e41, 0x93d1_4e21), // EXTR Rn/Rm
            (0x9bd2_7ce4, 0x9bd1_7ce4), // UMULH Rm
            (0x9b52_7ce4, 0x9b51_7ce4), // SMULH Rm
        ] {
            assert_eq!(
                substitute_x18(word, 17),
                Some(transformed),
                "word {word:#010x}"
            );
        }
    }

    #[test]
    fn x18_decoder_failure_fallback_table() {
        for (word, expected) in [
            (
                0xffff_fff2,
                X18Classification::X18(X18TransformResult::Unsupported(
                    X18Unsupported::DecodeFailure,
                )),
            ),
            (0xffff_ffff, X18Classification::None),
            (0x0420_e3e7, X18Classification::None), // SVE cntb
            (0x2522_1ce1, X18Classification::None), // SVE whilelo
            (0x04e1_0012, X18Classification::None), // SVE add z18.d, z0.d, z1.d
            (0x0432_0252, X18Classification::None), // SVE add z18.b, z18.b, z18.b
            (0x0472_0252, X18Classification::None), // SVE add z18.h, z18.h, z18.h
            (0x04b2_0252, X18Classification::None), // SVE add z18.s, z18.s, z18.s
            (0x04f2_0252, X18Classification::None), // SVE add z18.d, z18.d, z18.d
            (0xa400_a020, X18Classification::None), // SVE ld1b
            (0xe400_e060, X18Classification::None), // SVE st1b
        ] {
            assert_eq!(classify_x18(word), expected, "word {word:#010x}");
        }
    }

    #[test]
    fn sve_scalar_x18_operands_are_trapped() {
        for word in [
            0x0420_e3f2, // cntb x18
            0x04f2_e3f2, // incd x18, all, mul #3
            0x25e1_1e40, // whilelo p0.d, x18, x1
            0x25f2_1c00, // whilelo p0.d, x0, x18
            0xa5e0_a240, // ld1d { z0.d }, p0/z, [x18]
            0xe5e0_e240, // st1d { z0.d }, p0, [x18]
            0xa5f2_4000, // ld1d { z0.d }, p0/z, [x0, x18, lsl #3]
        ] {
            assert_eq!(
                classify_x18(word),
                X18Classification::X18(X18TransformResult::Unsupported(
                    X18Unsupported::DecodeFailure,
                )),
                "word {word:#010x}"
            );
            let (patched, outcome) =
                hook_words_opt_with_config(&[word], 0x1000, 0x2000, x18_config(Host::Linux));
            assert_eq!(
                word_at(&patched, 0),
                Insn::Brk(TRAP_BRK_IMM).encode().unwrap(),
                "word {word:#010x}"
            );
            assert_eq!(outcome.unwrap().trapped_sites, vec![0x1000]);

            let (native, outcome) = hook_words_opt(&[word], 0x1000, 0x2000);
            assert_eq!(word_at(&native, 0), word);
            assert!(outcome.is_none());
        }
    }

    #[test]
    fn decoder_fallback_does_not_treat_mov_immediate_as_x18() {
        assert_eq!(classify_x18(0x5280_0028), X18Classification::None); // mov w8, #1
    }

    #[test]
    fn guest_x18_patchability_excludes_reserved_placeholders() {
        assert!(is_patchable_guest_x18_offset(32744));
        assert!(!is_patchable_guest_x18_offset(32752));
        assert!(!is_patchable_guest_x18_offset(32760));
    }

    #[test]
    fn x18_unsupported_class_table() {
        assert_eq!(
            classify_x18(Insn::Br(18).encode().unwrap()),
            X18Classification::Branch(X18IndirectBranchKind::Br)
        );
        for (word, expected) in [
            (
                0xf000_0012,
                X18Classification::X18(X18TransformResult::Unsupported(X18Unsupported::PcRelative)),
            ), // adrp x18
            (
                0x5800_0012,
                X18Classification::X18(X18TransformResult::Unsupported(X18Unsupported::PcRelative)),
            ), // ldr x18, literal
            (
                0x4832_7ed4,
                X18Classification::X18(X18TransformResult::Unsupported(
                    X18Unsupported::ExclusiveAtomic,
                )),
            ), // casp
        ] {
            assert_eq!(classify_x18(word), expected, "word {word:#010x}");
        }
    }

    #[test]
    fn x18_arithmetic_substitution_rewrites_exact_register_fields() {
        for (word, expected) in [
            (0x9a12_018c, 0x9a11_018c),
            (0x9a12_0042, 0x9a11_0042),
            (0x9a12_0020, 0x9a11_0020),
            (0xba12_0020, 0xba11_0020),
            (0xda12_0020, 0xda11_0020),
            (0xfa12_0020, 0xfa11_0020), // ADC/ADCS/SBC/SBCS
            (0x9a12_0252, 0x9a11_0231), // adc x18, x18, x18
            (0x9ad2_0820, 0x9ad1_0820), // udiv x0, x1, x18
            (0x9ad2_0c20, 0x9ad1_0c20), // sdiv x0, x1, x18
        ] {
            let X18Classification::X18(X18TransformResult::Supported(transformation)) =
                classify_x18(word)
            else {
                panic!("word {word:#010x} was not supported");
            };
            assert_eq!(transformation.word, expected, "word {word:#010x}");
        }
    }

    #[test]
    fn rt_sigreturn_trampoline_uses_the_svc_gate_frame_abi() {
        let callback = 0x1122_3344_5566_7788usize;
        let code = emit_rt_sigreturn_trampoline(callback).unwrap();

        assert_eq!(&code[code.len() - 8..], &callback.to_ne_bytes());
        assert_eq!(code.len(), 48);
    }
    use alloc::vec;

    // The emitters append each gate at `trampoline_data.len()`, so these sizes
    // drive no emission; the tests use them to slice individual gates out of
    // the blob and to assert its total length.
    /// Bytes emitted per SVC site: the gate proper plus its outbound stub.
    const SVC_GATE_SIZE: usize = SVC_SLOT_BYTES;
    /// MSR gate instructions up to and including the first return branch. The
    /// slot holds one more `B`, which never executes.
    const MSR_GATE_INSNS: usize = 9;
    const MSR_GATE_SIZE: usize = MSR_SLOT_BYTES;
    const MRS_GATE_SIZE: usize = MRS_SLOT_BYTES;

    fn x18_config(host: Host) -> RewriteConfig {
        RewriteConfig {
            host,
            virtualize_x18: true,
            preserve_host_thread_state: false,
        }
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

    #[test]
    fn encoders_match_known_words() {
        // `B #0`.
        assert_eq!(Insn::B(0).encode().unwrap(), 0x1400_0000);
        // `B #4` advances one instruction.
        assert_eq!(Insn::B(4).encode().unwrap(), 0x1400_0001);
        // `B #-4` is the all-ones imm26.
        assert_eq!(Insn::B(-4).encode().unwrap(), 0x17FF_FFFF);
        // `BR X16`.
        assert_eq!(Insn::Br(16).encode().unwrap(), 0xD61F_0200);
        assert_eq!(Insn::Blr(18).encode().unwrap(), 0xD63F_0240);
        assert_eq!(Insn::Ret(18).encode().unwrap(), 0xD65F_0240);
        // `ADR X16, .+12` — how an SVC gate names its outbound stub.
        assert_eq!(
            Insn::Adr {
                rd: 16,
                byte_off: 12
            }
            .encode()
            .unwrap(),
            0x1000_0070
        );
        // TPIDR_EL0 accessor and `AND X9, X9, #0xfffffffffffffff8`.
        assert_eq!(Insn::MrsTpidrEl0(9).encode().unwrap(), 0xD53B_D049);
        assert_eq!(anchor_mask(9).encode().unwrap(), 0x927D_F129);
        // `MSR TPIDR_EL0, X9` guest word (scanned, never emitted).
        assert_eq!(msr_tpidr_el0(9), 0xD51B_D049);
        // Scaled (×8) 64-bit load/store: `ldr x9,[x9,#16]` / `str x17,[x16,#16]`.
        assert_eq!(
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: 16
            }
            .encode()
            .unwrap(),
            0xF940_0929
        );
        assert_eq!(
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 16
            }
            .encode()
            .unwrap(),
            0xF900_0A11
        );
        // The guest thread-pointer slot is emitted with the placeholder offset
        // that `patch_guest_tpidr_offset` overwrites at load time; pin both the
        // value and the emitted words. The placeholder saturates the scaled
        // 12-bit immediate (`imm12 = 0xFFF`).
        assert_eq!(GUEST_TPIDR_OFFSET_PLACEHOLDER, 32760);
        // Slot access: `ldr x9,[x9,#32760]` / `str x17,[x16,#32760]`.
        assert_eq!(
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
            }
            .encode()
            .unwrap(),
            0xF97F_FD29
        );
        assert_eq!(
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
            }
            .encode()
            .unwrap(),
            0xF93F_FE11
        );
        // `BRK #0xB10B`, the trap that replaces an out-of-range patch site.
        assert_eq!(Insn::Brk(TRAP_BRK_IMM).encode().unwrap(), 0xD436_2160);
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

    /// Like [`hook_words`] but returns the raw `Option` outcome so callers can
    /// assert the "no patch sites" (`None`) sentinel and trapped-site cases.
    fn hook_words_opt(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Option<HookOutcome>) {
        hook_words_opt_with_config(
            words,
            base,
            tramp_base,
            RewriteConfig {
                host: Host::Linux,
                virtualize_x18: false,
                preserve_host_thread_state: false,
            },
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

    /// Build persisted version-1 gates for compatibility tests. New rewriting
    /// uses in-place MSR breakpoints, but these slots must remain recognizable.
    fn hook_legacy_words_opt_with_config(
        words: &[u32],
        base: u64,
        tramp_base: u64,
        config: RewriteConfig,
    ) -> (Vec<u8>, Option<HookOutcome>) {
        let mut code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let sections = [TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: code.len() as u64,
        }];
        let sites = find_patch_sites(&sections, &code, config).unwrap();
        if sites.is_empty() {
            return (code, None);
        }
        let mut trampoline = Vec::new();
        emit_shared_prologue(&mut trampoline, 0);
        let mut trapped_sites = Vec::new();
        for site in sites {
            let gate = tramp_base + trampoline.len() as u64;
            let inbound =
                Insn::B(gate.cast_signed().saturating_sub(site.vaddr.cast_signed())).encode();
            let emitted = if site.kind == PatchKind::Svc && inbound.is_some() {
                match gate::build(
                    &gate::GateInstance::new(GateMetadata::Svc, site.vaddr + 4),
                    GateLayout::linux(config.host),
                    gate,
                    tramp_base,
                ) {
                    Ok(slot) => {
                        slot.append_to(&mut trampoline);
                        true
                    }
                    Err(gate::BuildError::Unreachable) => false,
                    Err(error) => panic!("legacy SVC: {error:?}"),
                }
            } else {
                inbound.is_some()
                    && emit_gate(
                        &mut trampoline,
                        tramp_base,
                        gate,
                        &site,
                        config,
                        GateLayout::linux(config.host),
                    )
                    .unwrap()
            };
            if emitted {
                code[site.file_offset..site.file_offset + 4]
                    .copy_from_slice(&inbound.unwrap().to_le_bytes());
            } else {
                trap_site(&mut code, site.file_offset);
                trapped_sites.push(site.vaddr);
            }
        }
        (
            code,
            Some(HookOutcome {
                trampoline,
                trapped_sites,
            }),
        )
    }

    fn hook_legacy_words_with_callback(
        words: &[u32],
        base: u64,
        tramp: u64,
        callback: u64,
    ) -> Vec<u8> {
        let (_, mut bytes) = hook_legacy_words(words, base, tramp);
        bytes[..8].copy_from_slice(&callback.to_le_bytes());
        bytes
    }

    fn hook_legacy_words(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Vec<u8>) {
        let (code, outcome) = hook_legacy_words_opt_with_config(
            words,
            base,
            tramp_base,
            RewriteConfig::new(crate::TargetHost::Linux, false),
        );
        (code, outcome.unwrap().trampoline)
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
            RewriteConfig {
                host: Host::Linux,
                virtualize_x18: true,
                preserve_host_thread_state: false,
            },
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
                GateLayout::linux(Host::Linux),
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
            crate::TargetHost::Linux,
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

            let (_patched, outcome) =
                hook_words_opt_with_config(&[word], 0x1000, 0x400000, x18_config(Host::Linux));
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
            x18_config(Host::Linux),
        );
        let trampoline = outcome.unwrap().trampoline;
        let stages = slot_stages(
            &trampoline[GATES_START_OFFSET..],
            0x400000 + GATES_START_OFFSET as u64,
            GateLayout::linux(Host::Linux),
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
            (Host::Linux, 0xd53b_d050),
            (Host::MacOs, 0xd53b_d070),
            (Host::Windows, 0xaa12_03f0),
        ] {
            let (_, outcome) =
                hook_words_opt_with_config(&[0x0b12_0063], 0x1000, 0x400000, x18_config(host));
            let trampoline = outcome.unwrap().trampoline;
            let gate = &trampoline[GATES_START_OFFSET..];
            assert_eq!(
                gate.len(),
                GateMetadata::X18 { scratch: X17 }.slot_size_for(host)
            );
            assert_eq!(
                word_at(gate, 4), // first anchor read
                anchor_word
            );
            if host == Host::MacOs {
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
            let (patched, outcome) =
                hook_words_opt_with_config(&[word], 0x1000, 0x400000, x18_config(Host::Linux));
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
    fn every_gate_metadata_slot_size_is_probed() {
        for metadata in [
            GateMetadata::Svc,
            GateMetadata::MrsTpidr { destination: 9 },
            GateMetadata::MsrTpidr { source: 9 },
            GateMetadata::X18 { scratch: 17 },
            GateMetadata::X18StackWriteback { scratch: 17 },
            GateMetadata::X18CompareBranch { scratch: 17 },
            GateMetadata::X18Adr { scratch: 17 },
            GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Br,
            },
            GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Blr,
            },
            GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Ret,
            },
        ] {
            for host in [
                crate::TargetHost::Linux,
                crate::TargetHost::MacOs,
                crate::TargetHost::Windows,
            ] {
                assert!(
                    GATE_SLOT_SIZES.contains(&metadata.slot_size_for_host(host)),
                    "{metadata:?} on {host:?}"
                );
            }
        }
    }

    #[test]
    fn cbnz_w18_gate_preserves_both_original_destinations() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0x3500_0332], // cbnz w18, 0x1064
            0x1000,
            0x400000,
            x18_config(Host::Linux),
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
        let (_, outcome) =
            hook_words_opt_with_config(&[0x3500_0332], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;

        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::Linux)
            .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }

    #[test]
    fn tbnz_x18_bit_63_gate_encodes_without_panicking() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xb7f8_00b2], // tbnz x18, #63, 0x1014
            0x1000,
            0x400000,
            x18_config(Host::Linux),
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
            x18_config(Host::Linux),
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
            x18_config(Host::Linux),
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
            x18_config(Host::Linux),
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
        let (_, outcome) =
            hook_words_opt_with_config(&[0x1000_0072], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;

        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::Linux)
            .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }

    #[test]
    fn x18_offsets_finalize_transactionally() {
        let (_, outcome) =
            hook_words_opt_with_config(&[0x0b12_0063], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();
        assert!(matches!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 12, crate::TargetHost::Linux),
            Err(Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        assert!(matches!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 96, crate::TargetHost::Linux),
            Err(Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::Linux)
            .unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }

    #[test]
    fn tpidr_only_patcher_rejects_x18_gates_transactionally() {
        let (_, outcome) =
            hook_words_opt_with_config(&[0xaa00_03f2], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        assert!(patch_guest_tpidr_offset(&mut trampoline, 96).is_err());
        assert_eq!(trampoline, before);
    }

    #[test]
    fn combined_finalizer_validates_x18_offset_without_x18_gates() {
        let (_, mut trampoline) = hook_words(&[SVC_0], 0x1000, 0x400000);
        let before = trampoline.clone();

        assert!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 12, crate::TargetHost::Linux)
                .is_err()
        );
        assert_eq!(trampoline, before);
    }

    #[test]
    fn combined_finalizer_requires_adjacent_guest_slots() {
        let (_, outcome) =
            hook_words_opt_with_config(&[0xaa00_03f2], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        assert!(
            finalize_trampoline_gates_for_host(&mut trampoline, 96, 112, crate::TargetHost::Linux)
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
            x18_config(Host::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let transformed = GATES_START_OFFSET + 20; // the copied guest instruction
        let before = word_at(&trampoline, transformed);

        finalize_trampoline_gates_for_host(&mut trampoline, 96, 104, crate::TargetHost::Linux)
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
            x18_config(Host::Linux),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        let error = finalize_trampoline_gates(&mut trampoline, 96).unwrap_err();

        assert!(
            matches!(error, Error::TrampolinePatchFailure(reason) if reason.contains("finalize_trampoline_gates_for_host"))
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
            x18_config(Host::Linux),
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
        let enabled = RewriteConfig {
            host: Host::Linux,
            virtualize_x18: true,
            preserve_host_thread_state: false,
        };
        let sites = find_patch_sites(&[section], &bytes, enabled).unwrap();
        assert_eq!(sites[0].kind, PatchKind::MsrTpidr(18));
        assert!(matches!(
            sites[1].kind,
            PatchKind::X18(X18TransformResult::Unsupported(_))
        ));

        let (patched, outcome) = hook_words_opt_with_config(&words, 0x1000, 0x2000, enabled);
        let trap = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();
        assert_eq!(decode_msr_tpidr_trap(word_at(&patched, 0)), Some(18));
        assert_eq!(word_at(&patched, 4), trap);
        assert_eq!(outcome.unwrap().trapped_sites, vec![0x1004]);

        let (patched, outcome) = hook_words_opt(&words, 0x1000, 0x2000);
        assert_ne!(word_at(&patched, 0), trap);
        assert_ne!(word_at(&patched, 4), trap);
        let outcome = outcome.unwrap();
        assert_eq!(outcome.trapped_sites, []);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET + MRS_GATE_SIZE);
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

        let sites =
            find_patch_sites_with_code_ranges(&executable, &[], &bytes, x18_config(Host::Linux))
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
                RewriteConfig::new(crate::TargetHost::Linux, false),
            )
            .unwrap();
            let actual = sites
                .iter()
                .map(|site| {
                    // The mandatory site set is independent of code metadata;
                    // only the MSR execution strategy varies inside exclusives.
                    let kind = match site.kind {
                        PatchKind::MsrTpidrInline(source) => PatchKind::MsrTpidr(source),
                        other => other,
                    };
                    (site.file_offset, site.vaddr, kind)
                })
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
                RewriteConfig::new(crate::TargetHost::Linux, false),
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
    fn host_aware_mrs_trampoline_size_bound_covers_emitted_gate() {
        let mut bytes = Insn::MrsTpidrroEl0(9).encode().unwrap().to_le_bytes();
        let sections = [TextSectionInfo {
            vaddr: 0x1000,
            file_offset: 0,
            size: bytes.len() as u64,
        }];
        let options = crate::RewriteOptions::macos_host_shared_cache();

        let bound = macho_trampoline_size_upper_bound(&bytes, &sections, options).unwrap();
        let emitted = hook_macho(&mut bytes, &sections, 0x400000, 0x800000, options)
            .unwrap()
            .unwrap()
            .trampoline;

        assert_eq!(bound, GATES_START_OFFSET + HOST_AWARE_MRS_SLOT_BYTES);
        assert_eq!(emitted.len(), bound);
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
        assert!(emitted <= bound);
    }

    #[test]
    fn msr_in_exclusive_regions_retains_the_inline_gate() {
        let words = [0xc85f_7c20, msr_tpidr_el0(5), 0xc802_7c20];
        for host in [Host::Linux, Host::MacOs] {
            let (patched, outcome) = hook_words_opt_with_config(
                &words,
                0x1000,
                0x400000,
                RewriteConfig {
                    host,
                    virtualize_x18: false,
                    preserve_host_thread_state: false,
                },
            );
            let outcome = outcome.unwrap();
            assert_eq!(outcome.trapped_sites, []);
            assert_eq!(word_at(&patched, 4) & OPCODE_TOP6_MASK, Opcode::B.bits());
            let slot = &outcome.trampoline[GATES_START_OFFSET..];
            assert_eq!(
                decode_gate_metadata_word(word_at(slot, slot.len() - 4)),
                Some(GateMetadata::MsrTpidr { source: 5 })
            );
        }
    }

    #[test]
    fn macos_svc_native_epilogue_needs_no_tls_and_is_not_guest_recovery_code() {
        const SITE: u64 = 0x7f00_0000_1000;
        const TRAMP: u64 = SITE + 0x4000;
        for darwin in [false, true] {
            let (outcome, layout) = if darwin {
                let mut code = DARWIN_SVC.to_le_bytes();
                let sections = [TextSectionInfo {
                    vaddr: SITE,
                    file_offset: 0,
                    size: 4,
                }];
                (
                    hook_macho(
                        &mut code,
                        &sections,
                        TRAMP,
                        0,
                        crate::RewriteOptions::macos_host_shared_cache(),
                    )
                    .unwrap()
                    .unwrap(),
                    GateLayout::darwin(Host::MacOs),
                )
            } else {
                (
                    hook_words_opt_with_config(&[SVC_0], SITE, TRAMP, x18_config(Host::MacOs))
                        .1
                        .unwrap(),
                    GateLayout::linux(Host::MacOs),
                )
            };
            let slot = &outcome.trampoline[GATES_START_OFFSET..];
            assert_eq!(slot.len(), 80);
            // The callback's TBNZ distinguishes the two outbound formats without
            // modifying carry or using TLS on a native-host return.
            assert_eq!(word_at(slot, SVC_GATE_BYTES) & (1 << 29), 0);
            let native = SVC_GATE_BYTES + MACOS_SVC_NATIVE_EPILOGUE_OFFSET_FROM_STUB;
            assert_eq!(
                word_at(slot, native),
                Insn::LdrUimm {
                    rt: X16,
                    rn: SP,
                    imm_bytes: SVC_FRAME_OFF_X16,
                }
                .encode()
                .unwrap()
            );
            assert_ne!(word_at(slot, native) & (1 << 29), 0); // legacy first word
            assert_eq!(
                word_at(slot, native + 4),
                Insn::AddSp(layout.svc_frame_bytes).encode().unwrap()
            );
            assert_eq!(
                decode_branch_target(
                    word_at(slot, native + 8),
                    TRAMP + GATES_START_OFFSET as u64 + native as u64 + 8
                ),
                Some(SITE + 4)
            );
            for offset in (native..native + MACOS_SVC_NATIVE_EPILOGUE_BYTES).step_by(INSN_BYTES) {
                assert!(
                    classify_copied_gate_slot_with_layout(
                        slot,
                        TRAMP + 16,
                        TRAMP + 16 + offset as u64,
                        layout
                    )
                    .is_none()
                );
            }
            // The native epilogue is validated, not arbitrary padding.
            let mut corrupted = slot.to_vec();
            corrupted[native..native + 4].copy_from_slice(&NOP.to_le_bytes());
            assert!(
                classify_copied_gate_slot_with_layout(&corrupted, TRAMP + 16, TRAMP + 16, layout)
                    .is_none()
            );
        }
    }

    #[test]
    fn svc_tls_finalization_patches_the_derived_slot_transactionally() {
        let (_, outcome) = hook_words_opt_with_config(
            &[Insn::MrsTpidrEl0(9).encode().unwrap(), SVC_0],
            0x1000,
            0x400000,
            RewriteConfig::new(crate::TargetHost::Linux, false),
        );
        let original = outcome.unwrap().trampoline;
        // MRS is first, then the 64-byte TLS-backed SVC slot.
        assert_eq!(find_guest_tpidr_placeholder(&original), Some(20));
        let svc = 32;
        assert_eq!(
            decode_gate_metadata_word(word_at(&original, svc + 60)),
            Some(GateMetadata::SvcTls)
        );
        assert!(svc_stub_uses_tls(
            word_at(&original, svc + SVC_GATE_BYTES),
            crate::TargetHost::Linux
        ));
        let mut patched = original.clone();
        assert_eq!(patch_guest_tpidr_offset(&mut patched, 96).unwrap(), 2);
        assert_eq!(
            (word_at(&patched, svc + 40) & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT,
            u32::from((96 + SVC_X16_OFFSET_FROM_GUEST_TP) / GUEST_TPIDR_OFFSET_ALIGN)
        );
        assert_eq!(find_guest_tpidr_placeholder(&patched), None);
        // Finalizing twice at the same root is a no-op; changing it is rejected.
        let after = patched.clone();
        assert_eq!(patch_guest_tpidr_offset(&mut patched, 96).unwrap(), 0);
        assert!(patch_guest_tpidr_offset(&mut patched, 104).is_err());
        assert_eq!(patched, after);
        // Even though the earlier MRS root fits, the derived SVC field cannot
        // use the reserved maximum offset. Failure must not partially patch MRS.
        let mut invalid = original.clone();
        assert!(
            patch_guest_tpidr_offset(
                &mut invalid,
                MAX_GUEST_TPIDR_OFFSET - SVC_X16_OFFSET_FROM_GUEST_TP
            )
            .is_err()
        );
        assert_eq!(invalid, original);
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
                Some(GateMetadata::SvcTls)
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
    fn legacy_msr_gate_return_branch_out_of_range_is_trapped() {
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
        let (patched, outcome) = hook_legacy_words_opt_with_config(
            &[msr_tpidr_el0(5)],
            base,
            tramp_base,
            RewriteConfig::new(crate::TargetHost::Linux, false),
        );
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
    fn legacy_msr_and_mrs_both_get_gates() {
        let base = 0x1000;
        let tramp_base = 0x300000;
        // MSR TPIDR_EL0, X5  then  MRS X9, TPIDR_EL0.
        let words = [msr_tpidr_el0(5), Insn::MrsTpidrEl0(9).encode().unwrap()];
        let (patched, tramp) = hook_legacy_words(&words, base, tramp_base);
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
    fn legacy_msr_gate_stores_guest_value_to_slot_for_any_register() {
        const BL_TOP6: u32 = 0x9400_0000;
        for n in [5u8, 16, 17, 30, 31] {
            let (_p, tramp) = hook_legacy_words(&[msr_tpidr_el0(n)], 0x1000, 0x500000);
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
        let (_p, tramp) = hook_legacy_words(&[SVC_0], base, tramp_base);
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

    // --- Load-time guest thread-pointer offset patching ---

    /// An offset a real host runtime might measure: not the placeholder.
    const MEASURED_OFFSET: u16 = 96;

    #[test]
    fn patch_rewrites_both_gate_shapes_and_leaves_everything_else_alone() {
        // One MSR site and one MRS site, so both patchable shapes are present.
        let (_p, mut tramp) = hook_legacy_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );
        let before = tramp.clone();

        let patched = patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap();
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
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
    }

    #[test]
    fn patch_leaves_an_svc_only_trampoline_untouched() {
        // The SVC gate and its outbound stub are full of `LDR`/`STR` words with
        // an `SP` base. None of them may be mistaken for a thread-pointer
        // access, and the header's callback slot is data that must be skipped.
        let (_p, mut tramp) = hook_legacy_words(&[SVC_0], 0x1000, 0x400000);
        let before = tramp.clone();
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
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
        let mut tramp = hook_legacy_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
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
        let (_p, mut tramp) = hook_legacy_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );

        let at = find_guest_tpidr_placeholder(&tramp).expect("an unpatched gate must be found");
        assert!(at >= FIRST_SCANNABLE_OFFSET && at.is_multiple_of(4));

        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
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
        let (_p, tramp) = hook_legacy_words(&[SVC_0], 0x1000, 0x400000);
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
        let tramp = hook_legacy_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
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
                    patch_guest_tpidr_offset(&mut tramp, bad),
                    Err(Error::TrampolinePatchFailure(_))
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
                patch_guest_tpidr_offset(&mut fresh, good).is_ok(),
                "offset {good} must be accepted"
            );
        }
    }

    #[test]
    fn patch_rejects_a_blob_that_is_not_a_trampoline() {
        // Shorter than the shared prologue.
        let mut short = vec![0u8; GATES_START_OFFSET - 4];
        assert!(matches!(
            patch_guest_tpidr_offset(&mut short, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));

        // Not a whole number of instructions.
        let mut ragged = vec![0u8; GATES_START_OFFSET + 2];
        assert!(matches!(
            patch_guest_tpidr_offset(&mut ragged, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));

        // A placeholder-bearing instruction in a shape no gate emits.
        let mut foreign = vec![0u8; GATES_START_OFFSET + 4];
        let bogus = Insn::LdrUimm {
            rt: 1,
            rn: 2,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        foreign[GATES_START_OFFSET..].copy_from_slice(&bogus.to_le_bytes());
        assert!(matches!(
            patch_guest_tpidr_offset(&mut foreign, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));
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
                crate::TargetHost::Linux
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
            patch_guest_tpidr_offset(&mut tramp, REQUESTED),
            Err(Error::TrampolinePatchFailure(_))
        ));
    }

    /// The metadata word is a persisted format, baked into every rewritten
    /// binary. A round-trip test cannot catch a renumbering — encode and decode
    /// move together — so pin the words.
    #[test]
    fn gate_metadata_words_are_a_stable_persisted_format() {
        let word = |m| EncodedGateMetadata::encode(m).unwrap().0;
        assert_eq!(word(GateMetadata::Svc), 0x0001b807);
        assert_eq!(word(GateMetadata::MrsTpidr { destination: 9 }), 0x0911b807);
        assert_eq!(
            word(GateMetadata::HostAwareMrsTpidr { destination: 9 }),
            0x0981b807
        );
        assert_eq!(word(GateMetadata::MsrTpidr { source: 9 }), 0x0921b807);
        assert_eq!(
            word(GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Br,
            }),
            0x0061b807
        );
        assert_eq!(
            word(GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Blr,
            }),
            0x0161b807
        );
        assert_eq!(
            word(GateMetadata::X18Branch {
                kind: X18IndirectBranchKind::Ret,
            }),
            0x0261b807
        );
        assert_eq!(
            word(GateMetadata::X18StackWriteback { scratch: 17 }),
            0x1171b807
        );
    }

    #[test]
    fn gate_metadata_rejects_invalid_fields_and_reserved_bits() {
        let valid = EncodedGateMetadata::encode(GateMetadata::MrsTpidr { destination: 9 })
            .unwrap()
            .0;

        for magic in 0..=u16::MAX {
            if u32::from(magic) != GATE_METADATA_MAGIC {
                let invalid = (valid & !GATE_METADATA_MAGIC_MASK) | u32::from(magic);
                assert_eq!(
                    EncodedGateMetadata(invalid).decode(),
                    None,
                    "magic {magic:#x}"
                );
            }
        }
        for version in 0..16 {
            if version != GATE_METADATA_VERSION {
                let invalid = (valid & !GATE_METADATA_VERSION_MASK)
                    | (version << GATE_METADATA_VERSION_SHIFT);
                assert_eq!(
                    EncodedGateMetadata(invalid).decode(),
                    None,
                    "version {version}"
                );
            }
        }
        for kind in 10..16 {
            let invalid = (valid & !GATE_METADATA_KIND_MASK) | (kind << GATE_METADATA_KIND_SHIFT);
            assert_eq!(EncodedGateMetadata(invalid).decode(), None, "kind {kind}");
        }
        for register in 32..64 {
            let invalid =
                (valid & !GATE_METADATA_REGISTER_MASK) | (register << GATE_METADATA_REGISTER_SHIFT);
            assert_eq!(
                EncodedGateMetadata(invalid).decode(),
                None,
                "register {register}"
            );
        }
        for bit in 30..32 {
            let invalid = valid | (1 << bit);
            assert_eq!(
                EncodedGateMetadata(invalid).decode(),
                None,
                "reserved bit {bit}"
            );
        }
        for register in 1..64 {
            let invalid = EncodedGateMetadata::encode(GateMetadata::Svc).unwrap().0
                | (register << GATE_METADATA_REGISTER_SHIFT);
            assert_eq!(
                EncodedGateMetadata(invalid).decode(),
                None,
                "SVC register {register}"
            );
        }
        for register in 32..=u8::MAX {
            assert!(
                EncodedGateMetadata::encode(GateMetadata::MrsTpidr {
                    destination: register,
                })
                .is_none()
            );
        }
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
                RewriteConfig {
                    host: Host::Linux,
                    virtualize_x18: false,
                    preserve_host_thread_state: false,
                },
            ),
            Err(Error::AddressOverflow(_))
        ));
    }

    #[test]
    fn slot_padding_and_metadata_do_not_false_match_placeholder_scan() {
        let (_patched, mut tramp) = hook_legacy_words(&[SVC_0], 0x1000, 0x400000);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);
        let before = tramp.clone();
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
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
        let (_patched, trampoline) = hook_legacy_words(&words, 0x1000, 0x400000);
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
        for host in [Host::Linux, Host::MacOs] {
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
                                .filter(|metadata| metadata.slot_size_for(host) == size)
                        })
                        .expect("slot metadata");
                    let size = metadata.slot_size_for(host);
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
                                if host == Host::MacOs {
                                    crate::TargetHost::MacOs
                                } else {
                                    crate::TargetHost::Linux
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
                assert_eq!(gates, words.len() - 1); // MSR is an in-place trap.
            }
        }
    }

    #[test]
    fn macos_anchor_expansion_preserves_linux_stages() {
        // macOS replaces each one-word anchor read by a three-word indirect
        // lookup. The two extra words must carry the stage of the instruction
        // that follows the anchor, and every other word its Linux stage.
        for metadata in [
            GateMetadata::MrsTpidr { destination: 9 },
            GateMetadata::MsrTpidr { source: 9 },
            GateMetadata::X18 { scratch: 17 },
            GateMetadata::X18StackWriteback { scratch: 17 },
            GateMetadata::X18CompareBranch { scratch: 17 },
            GateMetadata::X18Adr { scratch: 17 },
        ] {
            let mut instance = gate::GateInstance::new(metadata, 0x40_0000);
            instance.anchor = 16;
            let stages = |host| {
                let slot =
                    gate::build(&instance, GateLayout::linux(host), 0x40_0000, 0x40_0000).unwrap();
                let words = slot.words().to_vec();
                let stages: Vec<_> = (0..words.len())
                    .map(|index| slot.stage_at(index * INSN_BYTES))
                    .collect();
                (words, stages)
            };
            let (linux_words, linux_stages) = stages(Host::Linux);
            let (_, macos_stages) = stages(Host::MacOs);
            let mut expected = Vec::new();
            for (index, stage) in linux_stages.iter().enumerate() {
                expected.push(*stage);
                if linux_words[index] & MRS_TPIDR_EL0_MASK == MRS_TPIDR_EL0_BITS {
                    expected.extend([linux_stages[index + 1]; 2]);
                }
            }
            let executable = expected.iter().take_while(|stage| stage.is_some()).count();
            assert_eq!(
                macos_stages[..executable],
                expected[..executable],
                "{metadata:?}"
            );
            assert_eq!(macos_stages[executable], None, "{metadata:?}");
        }
    }

    #[test]
    fn compact_metadata_exhaustively_rejects_invalid_encodings() {
        let valid = EncodedGateMetadata::encode(GateMetadata::MrsTpidr { destination: 9 })
            .unwrap()
            .0;
        for magic in 0..=u16::MAX {
            if u32::from(magic) != GATE_METADATA_MAGIC {
                let word = (valid & !GATE_METADATA_MAGIC_MASK) | u32::from(magic);
                assert_eq!(EncodedGateMetadata(word).decode(), None, "magic {magic:#x}");
            }
        }
        for version in 0..16 {
            if version != GATE_METADATA_VERSION {
                let word = (valid & !GATE_METADATA_VERSION_MASK)
                    | (version << GATE_METADATA_VERSION_SHIFT);
                assert_eq!(
                    EncodedGateMetadata(word).decode(),
                    None,
                    "version {version}"
                );
            }
        }
        for kind in 10..16 {
            let word = (valid & !GATE_METADATA_KIND_MASK) | (kind << GATE_METADATA_KIND_SHIFT);
            assert_eq!(EncodedGateMetadata(word).decode(), None, "kind {kind}");
        }
        for register in 32..64 {
            let word =
                (valid & !GATE_METADATA_REGISTER_MASK) | (register << GATE_METADATA_REGISTER_SHIFT);
            assert_eq!(
                EncodedGateMetadata(word).decode(),
                None,
                "register {register}"
            );
        }
        for bit in 30..32 {
            assert_eq!(
                EncodedGateMetadata(valid | (1 << bit)).decode(),
                None,
                "reserved bit {bit}"
            );
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
        let (_patched, trampoline) = hook_legacy_words(&words, 0x1000, base);
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
            for offset in (0..executable_end).step_by(INSN_BYTES) {
                let classified =
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64).unwrap();
                assert_eq!(
                    classified,
                    ClassifiedGate {
                        slot_offset: start,
                        slot_size: u8::try_from(size).unwrap(),
                        anchor_scratch: 0,
                        stack_delta: 0,
                        stack_frame_bytes: 0,
                        original_site: 0x1000
                            + match metadata {
                                GateMetadata::MrsTpidr { .. }
                                | GateMetadata::HostAwareMrsTpidr { .. } => 0,
                                GateMetadata::MsrTpidr { .. } => 4,
                                GateMetadata::Svc | GateMetadata::SvcTls => 8,
                                GateMetadata::X18 { .. }
                                | GateMetadata::X18StackWriteback { .. }
                                | GateMetadata::X18CompareBranch { .. }
                                | GateMetadata::X18Adr { .. }
                                | GateMetadata::X18Branch { .. } => unreachable!(),
                            },
                        conditional_target: 0,
                        metadata,
                        stage: classified.stage,
                    }
                );
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
            hook_words_opt_with_config(&words, 0x1000, base, x18_config(Host::Linux));
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
            for offset in (0..metadata.executable_end()).step_by(INSN_BYTES) {
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
        let (_patched, trampoline) = hook_legacy_words(&words, 0x1000, base);
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
                    crate::TargetHost::Linux,
                )
                .expect("emitted slot must classify");
                assert_eq!(classified.slot_offset(), 0);
                assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                assert_eq!(classified.metadata(), metadata);
            }
        }

        let (_patched, outcome) = hook_legacy_words_opt_with_config(
            &[0xa9bf_4ff2], // stp x18, x19, [sp, #-16]!
            0x1000,
            base,
            x18_config(Host::Linux),
        );
        let trampoline = outcome.unwrap().trampoline;
        let slot = &trampoline[GATES_START_OFFSET..];
        let executable_end = GateMetadata::X18StackWriteback { scratch: 17 }.executable_end();
        assert_eq!(executable_end, 52);
        for offset in (0..executable_end).step_by(INSN_BYTES) {
            let classified = classify_copied_gate_slot_for_host(
                slot,
                base + GATES_START_OFFSET as u64,
                base + (GATES_START_OFFSET + offset) as u64,
                crate::TargetHost::Linux,
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
        let (_patched, trampoline) = hook_legacy_words(
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
        let (_patched, trampoline) = hook_legacy_words(
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

        for invalid in [
            4,
            12,
            u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER) + 8,
            u32::MAX,
        ] {
            assert!(
                !valid_emitted_tpidr_offset(invalid),
                "accepted impossible byte offset {invalid}"
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
        let (_, normal) = hook_legacy_words_opt_with_config(
            &normal_words,
            0x1000,
            base,
            RewriteConfig::new(crate::TargetHost::MacOs, true),
        );
        let x18_words = [
            0xaa00_03f2, // mov x18, x0
            0xa9bf_4ff2, // stp x18, x19, [sp, #-16]!
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
            0xd61f_0240, // br x18
        ];
        let (_, x18) =
            hook_legacy_words_opt_with_config(&x18_words, 0x2000, base, x18_config(Host::MacOs));

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
                let executable_end = metadata.executable_end_for_host(Host::MacOs);
                for offset in (0..executable_end).step_by(INSN_BYTES) {
                    let classified = classify_copied_gate_slot_for_host(
                        slot,
                        base + start as u64,
                        base + (start + offset) as u64,
                        crate::TargetHost::MacOs,
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
                            crate::TargetHost::MacOs,
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
        let (_patched, trampoline) = hook_legacy_words(
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
        let (_patched, mut trampoline) = hook_legacy_words(
            &[Insn::MrsTpidrEl0(9).encode().unwrap(), msr_tpidr_el0(5)],
            0x1000,
            0x400000,
        );
        trampoline[32] ^= 1; // Corrupt the later MSR template.
        let before = trampoline.clone();

        assert!(matches!(
            patch_guest_tpidr_offset(&mut trampoline, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
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
                patch_guest_tpidr_offset(&mut malformed, MEASURED_OFFSET),
                Err(Error::TrampolinePatchFailure(_))
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
