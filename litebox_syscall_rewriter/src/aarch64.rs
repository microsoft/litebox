// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 (ARM64) syscall rewriting support for Linux ELF binaries.
//!
//! Instructions are a fixed 4 bytes and `B imm26` reaches ±128MB, so a site is
//! replaced in place by a branch into its trampoline gate. A site out of that
//! reach becomes `BRK #TRAP_BRK_IMM` and is reported as trapped, which makes
//! the ELF-level caller reject the binary with `Error::UnpatchableSyscalls`.
//! Executing the `BRK` faults the guest instead of letting an unpatched
//! instruction reach the host kernel.
//!
//! Gated forms:
//!
//! * `SVC #imm` — syscall. The gate records the return address and tail-jumps
//!   through the trampoline header's callback pointer.
//! * `MSR TPIDR_EL0, Xn` — thread-pointer write, stored to the guest slot.
//! * `MRS Xd, TPIDR_EL0` — thread-pointer read, loaded from it. `MRS XZR,
//!   TPIDR_EL0` is a discarded read and is left native.
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
//! The guest's thread pointer is a host-managed slot at
//! `[anchor + guest_tpidr_offset]` that the MSR and MRS gates store to and load
//! from. Two registers are involved:
//!
//! * The one the *guest* uses: `TPIDR_EL0`, per the Linux ABI. This is an ELF
//!   rewriter, so it is the only one gated; a PE guest's `x18` TEB pointer and
//!   a Mach-O guest's `TPIDRRO_EL0` would need different gates.
//! * The one anchoring the *host*'s per-thread block, selected by `Host` —
//!   also `TPIDR_EL0` on a Linux host.
//!
//! `guest_tpidr_offset` is fixed by the host binary's link and one rewritten
//! guest must run under any host build, so gates carry a placeholder offset.
//! **A loader must pass staged gates through [`finalize_trampoline_gates`], or
//! [`finalize_trampoline_gates_with_x18`] when x18 virtualization is enabled,
//! before mapping the trampoline executable.** The finalizer validates every
//! slot and patches each metadata-designated placeholder; an unpatched gate
//! does not fault. See `GUEST_TPIDR_OFFSET_PLACEHOLDER`.
//!
//! ## Gate scratch storage
//!
//! `SVC` and `MSR TPIDR_EL0` clobber no registers, so their gates spill to a
//! frame carved from the guest stack with `SUB`/`ADD SP` and **require `SP` to
//! address a valid, writable, 16-byte-aligned stack at the patched site** — the
//! same condition the kernel relies on to write a signal frame. A site reached
//! with `SP` unmapped faults where the native instruction would not. The MRS
//! gate uses its destination as scratch and needs no frame.
//!
//! X18 gates add memory accesses that can clear the local exclusive monitor, so
//! the scanner rejects x18 sites lexically bracketed by an exclusive load and
//! store. TODO: use function metadata and control flow to cover noncontiguous
//! exclusive sequences.
//!
//! The x18 gates spill below the guest SP. A guest memory operand that aliases
//! that live spill area through an arbitrary register cannot be detected
//! statically and is outside the supported gate semantics.
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
//!     ldr x16, [sp, #0]      // restore guest X16
//!     add sp, sp, #32        // pop the gate frame
//!     b   site+4             // static target; needs no scratch register
//! ```
//!
//! AArch64 has no memory-indirect branch, so a runtime-side branch back into
//! the guest would burn a register on its target; a static branch in
//! guest-adjacent code does not. The runtime rewrites `[SP, #0]` from
//! `PtRegs::regs[16]` before branching rather than relying on the frame
//! surviving the round trip.
//!
//! The stub only resumes at the original site. A redirected `PC` (signals,
//! `execve`) or an asynchronous resume is instead handled by synthesizing an
//! `rt_sigreturn` frame, restoring all 31 GPRs, `PC` and `PSTATE` at once.
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
//! `TBZ`/`TBNZ`, and `ADR`/`ADRP` forms required by the supported workloads.
//! Currently unsupported decoder layouts such as `ADC`/`SBC`, other PC-relative
//! forms, and indirect control flow through x18 reject AOT rewriting and become
//! traps during runtime rewriting.

use alloc::format;
use alloc::vec::Vec;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction as DecodedInstruction, Opcode as DecodedOpcode, Operand,
};

use crate::{Error, Result, TextSectionInfo, checked_add_u64};

// ============================================================
// Constants
// ============================================================

/// `SVC #0` (supervisor call) — the canonical syscall instruction.
const SVC_0: u32 = 0xD400_0001;

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

/// Alignment every emitted gate slot starts on.
pub const GATE_ALIGNMENT: usize = 16;
/// Byte size of an emitted `MRS TPIDR_EL0` gate slot.
pub const MRS_SLOT_BYTES: usize = 16;
/// Byte size of an emitted `MSR TPIDR_EL0` gate slot.
pub const MSR_SLOT_BYTES: usize = 48;
/// Byte size of an emitted `SVC` gate slot.
pub const SVC_SLOT_BYTES: usize = 64;
/// Byte size of an ordinary self-contained x18 gate slot.
const X18_SLOT_BYTES: usize = 48;
/// Byte size of a self-contained x18 compare/test-branch gate slot.
const X18_COMPARE_BRANCH_SLOT_BYTES: usize = 48;
/// Byte size of a self-contained `ADR X18` gate slot.
const X18_ADR_SLOT_BYTES: usize = 32;
/// Distinct compact-slot sizes probed by classifiers and finalizers. Metadata
/// distinguishes gate kinds that share the 48-byte size.
pub const GATE_SLOT_SIZES: [usize; 4] = [
    MRS_SLOT_BYTES,
    X18_ADR_SLOT_BYTES,
    MSR_SLOT_BYTES,
    SVC_SLOT_BYTES,
];
/// Candidate starts required to cover the largest executable gate body:
/// `max(ceil(executable_end / GATE_ALIGNMENT))`, currently `ceil(48 / 16)`.
pub const GATE_PC_CANDIDATE_COUNT: usize = 3;
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
    /// A trapped `MRS <Xd>, TPIDR_EL0`, reading the guest thread pointer.
    MrsTpidr {
        /// Register the guest thread pointer is read into.
        destination: u8,
    },
    /// A trapped `MSR TPIDR_EL0, <Xs>`, writing the guest thread pointer.
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
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodedGateMetadata(u32);

impl EncodedGateMetadata {
    pub(crate) fn encode(metadata: GateMetadata) -> Option<Self> {
        if matches!(metadata, GateMetadata::MrsTpidr { destination: XZR }) {
            return None;
        }
        let (kind, register) = match metadata {
            GateMetadata::Svc => (GateKind::Svc, 0),
            GateMetadata::MrsTpidr { destination } => (GateKind::MrsTpidr, destination),
            GateMetadata::MsrTpidr { source } => (GateKind::MsrTpidr, source),
            GateMetadata::X18 { scratch } => (GateKind::X18, scratch),
            GateMetadata::X18CompareBranch { scratch } => (GateKind::X18CompareBranch, scratch),
            GateMetadata::X18Adr { scratch } => (GateKind::X18Adr, scratch),
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
            GateKind::MrsTpidr if register != XZR => Some(GateMetadata::MrsTpidr {
                destination: register,
            }),
            GateKind::MsrTpidr => Some(GateMetadata::MsrTpidr { source: register }),
            GateKind::X18 if register != XZR => Some(GateMetadata::X18 { scratch: register }),
            GateKind::X18CompareBranch if register != XZR => {
                Some(GateMetadata::X18CompareBranch { scratch: register })
            }
            GateKind::X18Adr if register != XZR => Some(GateMetadata::X18Adr { scratch: register }),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18Classification {
    None,
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
    // SVE ADD (vectors, unpredicated) uses these fields for Z registers only.
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
                            DecodedOpcode::STP | DecodedOpcode::LDP
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
// The host reaches its per-thread block through an anchor register its OS
// fixes, which `Host` names; the guest's logical thread pointer is a memory
// slot the runtime reserves at some byte offset from that anchor. Every gated
// guest read/write addresses the slot with a scaled `LDR`/`STR` off the
// anchor. The rewriter does not know the offset -- it is a property of the
// *host* runtime's link, not of the guest binary -- so it emits a placeholder
// the loader overwrites.

/// Largest value the `imm12` field of an unsigned-offset `LDR`/`STR` can hold.
/// The field is 12 bits and unsigned, counting `0..=0xFFF` *scaled units*.
const LDST_UIMM12_IMM_MAX: u16 = (1 << 12) - 1;

/// Scale the 64-bit form applies to that `imm12`, i.e. the operand width in
/// bytes. Any offset the gates address must therefore be 8-aligned.
const LDST_UIMM12_SCALE_64BIT: u16 = 8;

/// Largest byte offset a 64-bit unsigned-offset `LDR`/`STR` can encode
/// (`0xFFF * 8 = 32760`), derived from the encoding rather than written out.
const LDR_UIMM12_MAX_BYTE_OFFSET: u16 = LDST_UIMM12_IMM_MAX * LDST_UIMM12_SCALE_64BIT;

/// Alignment a runtime's guest thread-pointer slot must satisfy: the scale of
/// the 64-bit unsigned-offset `LDR`/`STR` the gates address it with.
pub const GUEST_TPIDR_OFFSET_ALIGN: u16 = LDST_UIMM12_SCALE_64BIT;

/// Guest x18 immediately follows the generic guest thread-pointer slot.
pub const GUEST_X18_OFFSET_FROM_GUEST_TP: usize = core::mem::size_of::<usize>();

/// Largest byte offset from the host anchor at which a runtime may place the
/// guest thread-pointer slot.
///
/// Not an independent policy choice: the gates reach the slot with one 64-bit
/// unsigned-offset `LDR`/`STR`, so the bound *is* `LDR_UIMM12_MAX_BYTE_OFFSET`.
pub const MAX_GUEST_TPIDR_OFFSET: u16 = LDR_UIMM12_MAX_BYTE_OFFSET;

/// The smallest guest thread-pointer offset a gate may be patched with.
///
/// A host keeps its own per-thread bookkeeping at the base of the block its
/// anchor points at, so a runtime places the guest slot past that and no
/// legitimate offset is ever this low. The bound matters because the
/// placeholder only catches a loader that forgets to patch at all: one that
/// patches with a defaulted or zeroed offset leaves nothing behind to detect,
/// and every rewritten thread-pointer write would then land on host state.
pub(crate) const MIN_GUEST_TPIDR_OFFSET: u16 = 16;

/// Placeholder byte offset baked into every emitted gate's guest thread-pointer
/// access, replaced at load time by [`patch_guest_tpidr_offset`].
///
/// It is `MAX_GUEST_TPIDR_OFFSET`, the largest value the field can hold, so it
/// cannot collide with a real runtime offset. That makes scanning for it exact,
/// which is what lets [`patch_guest_tpidr_offset`] and
/// [`find_guest_tpidr_placeholder`] work off the emitted words alone with no
/// side table of patch sites.
///
/// It buys **no** run-time safety. An unpatched gate does not fault: it reads
/// and writes one self-consistent address 32KB past the host thread pointer,
/// quietly corrupting eight bytes of whatever is mapped there. A loader must
/// use [`finalize_trampoline_gates`] or [`finalize_trampoline_gates_with_x18`]
/// before making a trampoline executable.
pub(crate) const GUEST_TPIDR_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;
/// Distinct placeholder for the anchor-relative guest x18 slot.
const GUEST_X18_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET - 8;

/// Stack frame used by x18 gates to preserve their two scratch registers.
pub const X18_FRAME_BYTES: u16 = 16;
const X18_FRAME_OFF_SCRATCHES: u16 = 0;

/// Whether a synchronous fault at a boundary is attributable to runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAccess {
    NoAccess,
    Memory,
}

/// Location of guest scratch state at an emitted x18 instruction boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X18FrameState {
    Absent,
    AtSpRegistersLive,
    AtSpRestoreRegisters,
    BelowSpRestoreRegisters,
}

/// Source of the guest-visible x18 value during recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X18ValueSource {
    Slot,
    Scratch,
}

/// Guest PC selected after x18 gate recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X18Resume {
    Original,
    Next,
    TakenTarget,
}

/// Host-neutral recovery semantics derived from an emitted x18 gate boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X18RecoveryPlan {
    pub frame: X18FrameState,
    pub value: X18ValueSource,
    pub resume: X18Resume,
    pub runtime_access: RuntimeAccess,
}

impl X18RecoveryPlan {
    const fn new(
        frame: X18FrameState,
        value: X18ValueSource,
        resume: X18Resume,
        runtime_access: RuntimeAccess,
    ) -> Self {
        Self {
            frame,
            value,
            resume,
            runtime_access,
        }
    }
}

/// Instruction boundaries in the persisted ordinary-x18 gate layout.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X18GateOffset {
    /// Gate entry, before the scratch frame is pushed.
    Entry = 0,
    /// First host-anchor read.
    FirstAnchor = 4,
    /// Logical-x18 slot load.
    SlotLoad = 8,
    /// Preserve the frame address across the transformed instruction.
    FrameAddress = 12,
    /// First frame pop.
    FirstPop = 16,
    /// Transformed guest instruction.
    Transform = 20,
    /// Restore the frame stack pointer.
    RestoreSp = 24,
    /// Second host-anchor read.
    SecondAnchor = 28,
    /// Logical-x18 slot store.
    SlotStore = 32,
    /// Scratch-register restore.
    RestoreRegisters = 36,
    /// Branch back to guest code.
    Return = 40,
    /// First byte after the executable gate body.
    ExecutableEnd = 44,
}

impl X18GateOffset {
    /// Returns the offset for indexing a gate byte slice.
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    /// Decodes an executable instruction boundary in an ordinary x18 gate.
    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::FirstAnchor,
            8 => Self::SlotLoad,
            12 => Self::FrameAddress,
            16 => Self::FirstPop,
            20 => Self::Transform,
            24 => Self::RestoreSp,
            28 => Self::SecondAnchor,
            32 => Self::SlotStore,
            36 => Self::RestoreRegisters,
            40 => Self::Return,
            _ => return None,
        })
    }

    /// Returns the recovery semantics for this emitted instruction boundary.
    pub const fn recovery_plan(self) -> Option<X18RecoveryPlan> {
        use RuntimeAccess::{Memory, NoAccess};
        use X18FrameState::{
            Absent, AtSpRegistersLive, AtSpRestoreRegisters, BelowSpRestoreRegisters,
        };
        use X18Resume::{Next, Original};
        use X18ValueSource::{Scratch, Slot};

        Some(match self {
            Self::Entry => X18RecoveryPlan::new(Absent, Slot, Original, NoAccess),
            Self::FirstAnchor => X18RecoveryPlan::new(AtSpRegistersLive, Slot, Original, NoAccess),
            Self::SlotLoad => X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Original, Memory),
            Self::FrameAddress | Self::FirstPop => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Original, NoAccess)
            }
            Self::Transform => {
                X18RecoveryPlan::new(BelowSpRestoreRegisters, Slot, Original, NoAccess)
            }
            Self::RestoreSp => {
                X18RecoveryPlan::new(BelowSpRestoreRegisters, Scratch, Next, NoAccess)
            }
            Self::SecondAnchor => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Scratch, Next, NoAccess)
            }
            Self::SlotStore => X18RecoveryPlan::new(AtSpRestoreRegisters, Scratch, Next, Memory),
            Self::RestoreRegisters => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Next, NoAccess)
            }
            Self::Return => X18RecoveryPlan::new(Absent, Slot, Next, NoAccess),
            Self::ExecutableEnd => return None,
        })
    }
}

/// Instruction boundaries in the persisted x18 compare/test-branch gate layout.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum X18CompareBranchOffset {
    /// Gate entry, before the frame is allocated.
    Entry = 0,
    /// Scratch-register spill.
    Spill = 4,
    /// Host-anchor read.
    Anchor = 8,
    /// Logical-x18 slot load.
    SlotLoad = 12,
    /// Original compare/test branch.
    Test = 16,
    /// Fallthrough scratch restore.
    FallthroughRestore = 20,
    /// Fallthrough frame pop.
    FallthroughPop = 24,
    /// Branch to the original fallthrough PC.
    FallthroughBranch = 28,
    /// Taken-path scratch restore.
    TakenRestore = 32,
    /// Taken-path frame pop.
    TakenPop = 36,
    /// Branch to the original taken target.
    TakenBranch = 40,
    /// First byte after the executable gate body.
    ExecutableEnd = 44,
}

impl X18CompareBranchOffset {
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    /// Decodes an executable instruction boundary.
    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::Spill,
            8 => Self::Anchor,
            12 => Self::SlotLoad,
            16 => Self::Test,
            20 => Self::FallthroughRestore,
            24 => Self::FallthroughPop,
            28 => Self::FallthroughBranch,
            32 => Self::TakenRestore,
            36 => Self::TakenPop,
            40 => Self::TakenBranch,
            _ => return None,
        })
    }

    /// Returns the recovery semantics for this emitted instruction boundary.
    pub const fn recovery_plan(self) -> Option<X18RecoveryPlan> {
        use RuntimeAccess::{Memory, NoAccess};
        use X18FrameState::{Absent, AtSpRegistersLive, AtSpRestoreRegisters};
        use X18Resume::{Next, Original, TakenTarget};
        use X18ValueSource::Slot;

        Some(match self {
            Self::Entry => X18RecoveryPlan::new(Absent, Slot, Original, NoAccess),
            Self::Spill => X18RecoveryPlan::new(AtSpRegistersLive, Slot, Original, NoAccess),
            Self::Anchor | Self::Test => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Original, NoAccess)
            }
            Self::SlotLoad => X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Original, Memory),
            Self::FallthroughRestore => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Next, NoAccess)
            }
            Self::FallthroughPop => X18RecoveryPlan::new(AtSpRegistersLive, Slot, Next, NoAccess),
            Self::FallthroughBranch => X18RecoveryPlan::new(Absent, Slot, Next, NoAccess),
            Self::TakenRestore => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, TakenTarget, NoAccess)
            }
            Self::TakenPop => X18RecoveryPlan::new(AtSpRegistersLive, Slot, TakenTarget, NoAccess),
            Self::TakenBranch => X18RecoveryPlan::new(Absent, Slot, TakenTarget, NoAccess),
            Self::ExecutableEnd => return None,
        })
    }
}

/// Instruction boundaries in the persisted ADR-x18 gate layout.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum X18AdrOffset {
    /// Gate entry, before the frame is pushed.
    Entry = 0,
    /// Host-anchor read.
    Anchor = 4,
    /// Materialize the target page.
    Adrp = 8,
    /// Add the target's page offset.
    Add = 12,
    /// Commit the result to the logical-x18 slot.
    SlotStore = 16,
    /// Restore scratch registers and SP.
    Restore = 20,
    /// Branch back to guest code.
    Return = 24,
    /// First byte after the executable gate body.
    ExecutableEnd = 28,
}

impl X18AdrOffset {
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    /// Decodes an executable instruction boundary.
    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::Anchor,
            8 => Self::Adrp,
            12 => Self::Add,
            16 => Self::SlotStore,
            20 => Self::Restore,
            24 => Self::Return,
            _ => return None,
        })
    }

    /// Returns the recovery semantics for this emitted instruction boundary.
    pub const fn recovery_plan(self) -> Option<X18RecoveryPlan> {
        use RuntimeAccess::{Memory, NoAccess};
        use X18FrameState::{Absent, AtSpRegistersLive, AtSpRestoreRegisters};
        use X18Resume::{Next, Original};
        use X18ValueSource::{Scratch, Slot};

        Some(match self {
            Self::Entry => X18RecoveryPlan::new(Absent, Slot, Original, NoAccess),
            Self::Anchor => X18RecoveryPlan::new(AtSpRegistersLive, Slot, Original, NoAccess),
            Self::Adrp | Self::Add => {
                X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Original, NoAccess)
            }
            Self::SlotStore => X18RecoveryPlan::new(AtSpRestoreRegisters, Scratch, Next, Memory),
            Self::Restore => X18RecoveryPlan::new(AtSpRestoreRegisters, Slot, Next, NoAccess),
            Self::Return => X18RecoveryPlan::new(Absent, Slot, Next, NoAccess),
            Self::ExecutableEnd => return None,
        })
    }
}

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
/// Saved guest X16. ABI: the outbound stub reloads `X16` from here.
pub const SVC_FRAME_OFF_X16: u16 = 0;
/// Post-SVC return address. ABI: the runtime's syscall callback reads it and
/// publishes it as the guest resume PC.
pub const SVC_FRAME_OFF_RETADDR: u16 = 8;
/// Address of this site's outbound stub. ABI: the runtime's syscall callback
/// branches here to resume at the original syscall site.
pub const SVC_FRAME_OFF_STUB: u16 = 16;

/// Source of the guest-visible MRS destination value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MrsTpidrValueSource {
    Register,
    Slot,
}

/// Host-neutral recovery semantics for an interrupted MRS-TPIDR gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MrsTpidrRecoveryPlan {
    pub value: MrsTpidrValueSource,
    pub completed: bool,
    pub runtime_access: RuntimeAccess,
}

/// Instruction boundaries in the emitted MRS-TPIDR gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MrsTpidrGateOffset {
    Entry = 0,
    SlotLoad = 4,
    Return = 8,
    ExecutableEnd = 12,
}

impl MrsTpidrGateOffset {
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::SlotLoad,
            8 => Self::Return,
            _ => return None,
        })
    }

    pub const fn recovery_plan(self) -> Option<MrsTpidrRecoveryPlan> {
        Some(match self {
            Self::Entry => MrsTpidrRecoveryPlan {
                value: MrsTpidrValueSource::Register,
                completed: false,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::SlotLoad => MrsTpidrRecoveryPlan {
                value: MrsTpidrValueSource::Slot,
                completed: true,
                runtime_access: RuntimeAccess::Memory,
            },
            Self::Return => MrsTpidrRecoveryPlan {
                value: MrsTpidrValueSource::Register,
                completed: true,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::ExecutableEnd => return None,
        })
    }
}

/// Location of guest x16 and SP at an emitted SVC instruction boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvcFrameState {
    NoFrame,
    FrameAtSpX16Live,
    RestoreX16FromFrame,
}

/// Host-neutral recovery semantics for an interrupted SVC gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SvcRecoveryPlan {
    pub frame: SvcFrameState,
    pub runtime_access: RuntimeAccess,
}

/// Instruction boundaries in the emitted SVC gate and its outbound stub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SvcGateOffset {
    Entry = 0,
    SpillX16 = 4,
    MaterializeReturnPage = 8,
    MaterializeReturnAddress = 12,
    StoreReturnAddress = 16,
    MaterializeOutboundStub = 20,
    StoreOutboundStub = 24,
    LoadCallback = 28,
    BranchCallback = 32,
    OutboundRestoreX16 = 36,
    OutboundRestoreSp = 40,
    Return = 44,
    ExecutableEnd = 48,
}

impl SvcGateOffset {
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::SpillX16,
            8 => Self::MaterializeReturnPage,
            12 => Self::MaterializeReturnAddress,
            16 => Self::StoreReturnAddress,
            20 => Self::MaterializeOutboundStub,
            24 => Self::StoreOutboundStub,
            28 => Self::LoadCallback,
            32 => Self::BranchCallback,
            36 => Self::OutboundRestoreX16,
            40 => Self::OutboundRestoreSp,
            44 => Self::Return,
            _ => return None,
        })
    }

    pub const fn recovery_plan(self) -> Option<SvcRecoveryPlan> {
        use RuntimeAccess::{Memory, NoAccess};
        Some(match self {
            Self::Entry => SvcRecoveryPlan {
                frame: SvcFrameState::NoFrame,
                runtime_access: NoAccess,
            },
            Self::SpillX16 | Self::MaterializeReturnPage => SvcRecoveryPlan {
                frame: SvcFrameState::FrameAtSpX16Live,
                runtime_access: NoAccess,
            },
            Self::MaterializeReturnAddress
            | Self::StoreReturnAddress
            | Self::MaterializeOutboundStub
            | Self::StoreOutboundStub
            | Self::BranchCallback => SvcRecoveryPlan {
                frame: SvcFrameState::RestoreX16FromFrame,
                runtime_access: NoAccess,
            },
            Self::LoadCallback => SvcRecoveryPlan {
                frame: SvcFrameState::RestoreX16FromFrame,
                runtime_access: Memory,
            },
            Self::OutboundRestoreX16
            | Self::OutboundRestoreSp
            | Self::Return
            | Self::ExecutableEnd => return None,
        })
    }
}

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
/// Size of the per-site outbound stub (`LDR X16 / ADD SP / B`).
const SVC_OUTBOUND_STUB_BYTES: usize = 3 * 4;

// --- MSR gate stack frame ---
//
// The MSR gate spills X16/X17 (one `STP`/`LDP` pair) and stages the captured
// guest value so the source register needs no special-casing.

/// MSR gate frame size (`SUB/ADD SP, SP, #MSR_FRAME_BYTES`). 16-byte aligned.
pub const MSR_FRAME_BYTES: u16 = 32;
/// Saved X16 (and, +8, X17 via the `STP`/`LDP` pair).
const MSR_FRAME_OFF_X16: u16 = 0;
/// Captured guest thread-pointer value, staged while all guest registers are
/// still pristine.
pub const MSR_FRAME_OFF_VALUE: u16 = 16;

/// Location of guest scratch state at an emitted MSR-TPIDR instruction boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsrTpidrFrameState {
    Absent,
    RegistersLive,
    RestoreRegisters,
}

/// Host-neutral recovery semantics for an interrupted MSR-TPIDR gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsrTpidrRecoveryPlan {
    pub frame: MsrTpidrFrameState,
    /// Whether the staged source value must authenticate recovery.
    pub validate_capture: bool,
    pub completed: bool,
    pub runtime_access: RuntimeAccess,
}

/// Instruction boundaries in the emitted MSR-TPIDR gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsrTpidrGateOffset {
    Entry = 0,
    SpillRegisters = 4,
    CaptureSource = 8,
    ReadAnchor = 12,
    LoadCapturedSource = 16,
    SlotStore = 20,
    RestoreRegisters = 24,
    RestoreSp = 28,
    Return = 32,
    ExecutableEnd = 36,
}

impl MsrTpidrGateOffset {
    const fn as_usize(self) -> usize {
        self as u8 as usize
    }

    pub fn from_offset(offset: usize) -> Option<Self> {
        Some(match offset {
            0 => Self::Entry,
            4 => Self::SpillRegisters,
            8 => Self::CaptureSource,
            12 => Self::ReadAnchor,
            16 => Self::LoadCapturedSource,
            20 => Self::SlotStore,
            24 => Self::RestoreRegisters,
            28 => Self::RestoreSp,
            32 => Self::Return,
            _ => return None,
        })
    }

    pub const fn recovery_plan(self) -> Option<MsrTpidrRecoveryPlan> {
        use MsrTpidrFrameState::{Absent, RegistersLive, RestoreRegisters};
        Some(match self {
            Self::Entry => MsrTpidrRecoveryPlan {
                frame: Absent,
                validate_capture: false,
                completed: false,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::SpillRegisters | Self::CaptureSource => MsrTpidrRecoveryPlan {
                frame: RegistersLive,
                validate_capture: false,
                completed: false,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::ReadAnchor => MsrTpidrRecoveryPlan {
                frame: RegistersLive,
                validate_capture: true,
                completed: false,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::LoadCapturedSource | Self::SlotStore => MsrTpidrRecoveryPlan {
                frame: RestoreRegisters,
                validate_capture: true,
                completed: false,
                runtime_access: if matches!(self, Self::SlotStore) {
                    RuntimeAccess::Memory
                } else {
                    RuntimeAccess::NoAccess
                },
            },
            Self::RestoreRegisters => MsrTpidrRecoveryPlan {
                frame: RestoreRegisters,
                validate_capture: true,
                completed: true,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::RestoreSp => MsrTpidrRecoveryPlan {
                frame: RegistersLive,
                validate_capture: false,
                completed: true,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::Return => MsrTpidrRecoveryPlan {
                frame: Absent,
                validate_capture: false,
                completed: true,
                runtime_access: RuntimeAccess::NoAccess,
            },
            Self::ExecutableEnd => return None,
        })
    }
}

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
const INSN_BYTES: usize = 1 << INSN_BYTES_LOG2;

/// [`INSN_BYTES`] where a virtual address is being measured.
const INSN_BYTES_U64: u64 = 1 << INSN_BYTES_LOG2;

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
const ADRP_PAGE_SHIFT: u32 = 12;

// Widths of the signed immediate fields, used to sign-extend them into an
// `i64` by shifting left and back.
const IMM26_BITS: u32 = 26;
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

/// Base opcode of an emitted instruction: every fixed bit set with all operand
/// fields zeroed. An encoder selects a variant and ORs in its operands via
/// [`Opcode::bits`]. (`MRS TPIDR_EL0` is encoded from [`Opcode::MrsTpidrEl0`],
/// whose bits equal [`MRS_TPIDR_EL0_BITS`] — the scan-detection pattern in
/// [`find_patch_sites`].)
#[repr(u32)]
#[derive(Clone, Copy)]
enum Opcode {
    B = 0x1400_0000,
    LdrLiteral = 0x5800_0000,
    Adr = 0x1000_0000,
    Adrp = 0x9000_0000,
    Br = 0xD61F_0000,
    Movz = 0xD280_0000,
    SubImm = 0xD100_0000,
    AddImm = 0x9100_0000,
    StrUimm = 0xF900_0000,
    LdrUimm = 0xF940_0000,
    Stp = 0xA900_0000,
    Ldp = 0xA940_0000,
    StpPre = 0xA980_0000,
    LdpPost = 0xA8C0_0000,
    MrsTpidrEl0 = MRS_TPIDR_EL0_BITS,
    MrsTpidrroEl0 = 0xD53B_D060,
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
            Insn::Movz { rd, imm16 } => {
                Some(Opcode::Movz.bits() | (u32::from(imm16) << RN_SHIFT) | u32::from(rd))
            }
            Insn::Nop => Some(NOP),
            Insn::SubSp(imm12) => data_imm12(Opcode::SubImm, SP, SP, imm12),
            Insn::AddSp(imm12) => data_imm12(Opcode::AddImm, SP, SP, imm12),
            Insn::AddImm { rd, rn, imm12 } => data_imm12(Opcode::AddImm, rd, rn, imm12),
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

/// The host OS the rewritten guest runs under. Its ABI fixes the *anchor
/// register* a gate reads to reach the host's per-thread block, and this names
/// which one; gates read it through [`Host::anchor_read`], so adding a host is
/// a new variant plus its arm there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    /// Linux host: the kernel preserves `TPIDR_EL0` across host execution, so
    /// the anchor lives there and the anchor read is `MRS Xd, TPIDR_EL0`.
    Linux,
    /// macOS host: `TPIDRRO_EL0` points at the host per-thread block.
    MacOs,
    /// Windows host: physical `x18` points at the thread environment block.
    Windows,
}

#[derive(Clone, Copy)]
pub(crate) struct RewriteConfig {
    host: Host,
    virtualize_x18: bool,
}

impl RewriteConfig {
    pub(crate) const fn new(target: crate::TargetHost, virtualize_x18: bool) -> Self {
        let host = match target {
            crate::TargetHost::Linux => Host::Linux,
            crate::TargetHost::MacOs => Host::MacOs,
            crate::TargetHost::Windows => Host::Windows,
        };
        Self {
            host,
            virtualize_x18,
        }
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
    /// Byte offset of the instruction within the ELF file image.
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
    /// `MRS Xd, TPIDR_EL0`; the `u8` is the destination register (0-30).
    MrsTpidr(u8),
    /// An x18 use detected under explicit virtualization.
    X18(X18TransformResult),
    /// A compare/test branch (`CBZ`/`CBNZ`/`TBZ`/`TBNZ`) on logical x18.
    X18CompareBranch(X18CompareBranch),
    /// An `ADR X18` with its original absolute target.
    X18Adr(X18Adr),
}

/// Scans executable sections for Linux syscall/thread-pointer gates and, when
/// configured, x18 gates. Linux-specific sites are rejected for other hosts;
/// x18 sites inside lexical exclusive sequences are rejected. AArch64
/// instructions are fixed-width, so sites are returned in ascending file order.
///
/// `MRS XZR, TPIDR_EL0` is a discarded read (register 31 as an `LDR` base would
/// mean `SP`), so it is left native; every other `MRS Xd, TPIDR_EL0` is gated.
fn find_patch_sites(
    sections: &[TextSectionInfo],
    buf: &[u8],
    config: RewriteConfig,
) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();

    for section in sections {
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

        for i in (0..section_data.len()).step_by(INSN_BYTES) {
            if i + INSN_BYTES > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + INSN_BYTES].try_into().unwrap());
            let exclusive_boundary = exclusive_boundary(insn);
            if exclusive_boundary == Some(ExclusiveBoundary::Load) {
                inside_exclusive_sequence = true;
            } else if exclusive_boundary == Some(ExclusiveBoundary::Store) {
                inside_exclusive_sequence = false;
            }
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                if config.host != Host::Linux {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 SVC site is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "SVC site")?
                    )));
                }
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                if config.host != Host::Linux {
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
                if config.host != Host::Linux {
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
            } else if config.virtualize_x18 {
                let vaddr = checked_add_u64(section.vaddr, i as u64, "x18 site")?;
                if let Some(branch) = classify_x18_conditional_branch(insn, vaddr) {
                    PatchKind::X18CompareBranch(branch)
                } else if let Some(adr) = classify_adr_x18(insn, vaddr) {
                    PatchKind::X18Adr(adr)
                } else if let Some(transformation) = classify_pc_relative_x18(insn, vaddr) {
                    PatchKind::X18(X18TransformResult::Supported(transformation))
                } else {
                    match classify_x18(insn) {
                        X18Classification::None => continue,
                        X18Classification::X18(result) => PatchKind::X18(result),
                    }
                }
            } else {
                continue;
            };
            if inside_exclusive_sequence
                && matches!(
                    kind,
                    PatchKind::X18(_) | PatchKind::X18CompareBranch(_) | PatchKind::X18Adr(_)
                )
            {
                return Err(Error::UnsupportedExecutable(format!(
                    "AArch64 gate inside exclusive sequence at {:#x}",
                    checked_add_u64(section.vaddr, i as u64, "exclusive sequence gate")?
                )));
            }
            sites.push(PatchSite {
                file_offset: start + i,
                vaddr: checked_add_u64(section.vaddr, i as u64, "patch site")?,
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
    /// Trampoline blob the caller appends after the ELF (page-aligned).
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
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    config: RewriteConfig,
) -> Result<Option<HookOutcome>> {
    if !trampoline_base_addr.is_multiple_of(GATE_ALIGNMENT as u64) {
        return Err(Error::AddressOverflow(format!(
            "AArch64 trampoline base {trampoline_base_addr:#x} is not {GATE_ALIGNMENT}-byte aligned"
        )));
    }
    let sites = find_patch_sites(text_sections, buf, config)?;

    if sites.is_empty() {
        // No patch sites: nothing to redirect, so no trampoline is
        // emitted. The caller writes a size-0 sentinel header instead.
        return Ok(None);
    }

    let mut trampoline_data: Vec<u8> = Vec::new();
    emit_shared_prologue(&mut trampoline_data, callback);

    let mut trapped_sites: Vec<u64> = Vec::new();

    for site in &sites {
        let gate_offset = trampoline_data.len();
        let gate_vaddr =
            checked_add_u64(trampoline_base_addr, gate_offset as u64, "trampoline gate")?;

        // The gate's return branch spans a wider displacement than the inbound
        // one, so an encodable inbound branch is necessary but not sufficient:
        // the gate is built only once the inbound branch fits, and a gate whose
        // own branches are out of range reports `GateBuild::Unreachable` and
        // appends nothing. If either is unreachable the site is trapped and no
        // gate is emitted.
        let b_offset = gate_vaddr
            .cast_signed()
            .saturating_sub(site.vaddr.cast_signed());
        let inbound = Insn::B(b_offset).encode();

        let build = if inbound.is_some() {
            match site.kind {
                PatchKind::Svc => emit_svc_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                )?,
                PatchKind::MsrTpidr(rt) => emit_msr_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rt,
                    config.host,
                )?,
                PatchKind::MrsTpidr(rd) => emit_mrs_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rd,
                    config.host,
                )?,
                PatchKind::X18(X18TransformResult::Supported(transformation)) => emit_x18_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    transformation,
                    config.host,
                )?,
                PatchKind::X18(X18TransformResult::Unsupported(_)) => GateBuild::Unreachable,
                PatchKind::X18CompareBranch(branch) => emit_x18_compare_branch_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    branch,
                    config.host,
                )?,
                PatchKind::X18Adr(adr) => emit_x18_adr_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    adr,
                    config.host,
                )?,
            }
        } else {
            GateBuild::Unreachable
        };

        if let (Some(b_insn), GateBuild::Emitted) = (inbound, build) {
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

/// Replace the four bytes at `file_offset` with `BRK #TRAP_BRK_IMM`.
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

/// Replace every patch site in `buf` with `BRK #TRAP_BRK_IMM`, returning how
/// many were trapped.
///
/// The fail-safe behind [`crate::trap_all_syscalls_in_code`], for a segment
/// that could not be patched at all. The main hooker traps its own unreachable
/// sites as it goes and does not come through here.
///
/// The `cfg` tracks reachability, not capability: the scan and the rewrite are
/// host-agnostic, but nothing calls this in an x86-64 build.
#[cfg(any(test, target_arch = "aarch64"))]
pub(crate) fn trap_all_patch_sites(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    config: RewriteConfig,
) -> Result<usize> {
    let sites = find_patch_sites(text_sections, buf, config)?;
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

// ============================================================
// SVC gate
// ============================================================

/// Whether a gate was fully emitted or could not be placed within reach.
///
/// A gate branches back to the guest, and the SVC gate also names its own
/// outbound stub. When one of those PC-relative references is out of range the
/// gate emits nothing and reports [`GateBuild::Unreachable`], leaving the blob
/// untouched so the caller can trap the originating site.
///
/// The SVC gate's callback literal is not one of them: it addresses the
/// trampoline header, so exceeding `LDR`-literal range means the trampoline
/// itself has outgrown that reach, and `Asm::ldr_literal` fails the whole
/// rewrite rather than trapping one site.
enum GateBuild {
    Emitted,
    Unreachable,
}

/// Per-site 64-byte SVC slot including callback dispatch and outbound stub.
///
/// The gate saves only X16, computes the post-SVC return address into it and
/// records that on the frame, records this site's outbound stub address
/// alongside, then loads and branches through the callback pointer in the
/// trampoline header. Guest X17/X18/LR and NZCV are untouched.
///
/// Frame layout, relative to the decremented SP:
/// `[0]=X16 [8]=return_addr [16]=outbound_stub [24]=pad`. Requires `SP` to
/// address a valid writable stack at the site; see the module docs, "Gate
/// scratch storage".
///
/// The outbound stub is emitted immediately after the gate and is the runtime's
/// normal way back into the guest; see the module docs, "`X16` is preserved
/// across an `SVC`".
fn emit_svc_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "SVC gate")?;
    let mut asm = Asm::new(gate_vaddr);

    // SUB SP, SP, #32 ; STR X16, [SP] — save the guest X16.
    asm.emit(Insn::SubSp(SVC_FRAME_BYTES));
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_X16,
    });

    // ADRP X16, <return_page>; ADD X16, X16, #<page offset> — post-SVC return
    // address.
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "SVC return")?;
    if !asm.adrp(X16, return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    let page_lo = u16::try_from(return_addr & PAGE_OFFSET_MASK).expect("masked to 12 bits");
    asm.emit(Insn::AddImm {
        rd: X16,
        rn: X16,
        imm12: page_lo,
    });

    // STR X16, [SP, #8] — record the return address.
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_RETADDR,
    });

    // ADR X16, <outbound stub> ; STR X16, [SP, #16] — record the stub. The stub
    // starts right after this gate's last instruction, well within ADR's ±1MB
    // reach, so a single ADR suffices (no ADRP/ADD pair).
    let stub_vaddr = checked_add_u64(gate_vaddr, SVC_GATE_BYTES as u64, "SVC outbound stub")?;
    if !asm.adr(X16, stub_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_STUB,
    });

    // LDR X16, =callback ; BR X16. The literal reaches back to the header, so
    // the last SVC gate has to sit within LDR-literal's ±1MiB of offset 0.
    // That caps one object at about 16K SVC slots; beyond it `ldr_literal`
    // reports `AddressOverflow` rather than encoding a wrapped offset.
    let callback_vaddr = checked_add_u64(
        trampoline_base_addr,
        HEADER_CALLBACK_OFFSET as u64,
        "callback slot",
    )?;
    asm.ldr_literal(X16, callback_vaddr)?;
    asm.emit(Insn::Br(X16));

    debug_assert_eq!(
        asm.here()?,
        stub_vaddr,
        "the outbound stub must start immediately after the gate"
    );

    // The outbound stub: LDR X16, [SP] ; ADD SP, SP, #32 ; B <site+4>.
    asm.emit(Insn::LdrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_X16,
    });
    asm.emit(Insn::AddSp(SVC_FRAME_BYTES));
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }

    debug_assert_eq!(
        asm.here()?,
        checked_add_u64(stub_vaddr, SVC_OUTBOUND_STUB_BYTES as u64, "SVC stub end")?,
        "the outbound stub must be SVC_OUTBOUND_STUB_BYTES long"
    );

    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::Svc,
        SVC_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

// ============================================================
// MSR + MRS gates
// ============================================================

/// Per-site MSR gate with a 32-byte frame, padded into one 48-byte slot.
///
/// Virtualizes a guest `MSR TPIDR_EL0, Xn` write by storing the guest value
/// into the guest thread-pointer slot at `[anchor + guest_tpidr_offset]`:
///
/// 1. spill X16/X17 and capture `Xn` to the frame while all guest registers are
///    still pristine, so `Xn` needs no special-casing even when it is one of the
///    scratch registers just spilled or XZR;
/// 2. read the host anchor into X16;
/// 3. reload the captured value into X17 and store it to the slot;
/// 4. restore X16/X17 and branch back to the instruction after the original MSR.
///
/// The slot is always reachable, so a guest value of `0` (XZR) is an ordinary
/// store, never a fault. Requires `SP` to address a valid writable stack at the
/// site (see the module docs). NZCV and X30 reach the guest unchanged.
fn emit_msr_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "MSR gate")?;
    let mut asm = Asm::new(gate_vaddr);

    // SUB SP, SP, #32 ; STP X16, X17, [SP] — spill the gate's scratch registers.
    asm.emit(Insn::SubSp(MSR_FRAME_BYTES));
    asm.emit(Insn::Stp {
        rt: X16,
        rt2: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_X16.cast_signed(),
    });

    // STR Xn, [SP, #16] — capture the guest value while all guest registers are
    // still pristine, so Xn needs no special-casing even when it is one of the
    // scratch registers just spilled (X16/X17) or XZR.
    asm.emit(Insn::StrUimm {
        rt,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_VALUE,
    });

    // MRS X16, <host anchor> — read the host anchor.
    asm.emit(host.anchor_read(X16));

    // LDR X17, [SP, #16] ; STR X17, [X16, #<tpidr offset>] — store the guest
    // value into its slot off the host anchor.
    asm.emit(Insn::LdrUimm {
        rt: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_VALUE,
    });
    asm.emit(Insn::StrUimm {
        rt: X17,
        rn: X16,
        imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
    });

    // Restore: LDP X16, X17, [SP] ; ADD SP, SP, #32.
    asm.emit(Insn::Ldp {
        rt: X16,
        rt2: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_X16.cast_signed(),
    });
    asm.emit(Insn::AddSp(MSR_FRAME_BYTES));

    // Two branches to the same return address. Only the first executes; the
    // pair pins the slot's absolute position, so the original PC need not be
    // stored in metadata. `validate_gate_slot` requires both to decode to one
    // target, so a gate that can encode only the first is unclassifiable and
    // must not be emitted -- which costs the second branch's 4 bytes of reach.
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "MSR return")?;
    if !asm.branch_to(return_addr)? || !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }

    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::MsrTpidr { source: rt },
        MSR_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

/// Virtualizes a guest `MRS Xd, TPIDR_EL0` read. The compact gate uses `Xd`
/// itself as scratch, so once its first `MRS` executes the old destination is
/// gone; canonicalization completes the logical MRS and reports the
/// post-instruction state rather than rewinding.
fn emit_mrs_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "MRS gate")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(host.anchor_read(rd));
    asm.emit(Insn::LdrUimm {
        rt: rd,
        rn: rd,
        imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
    });
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "MRS return")?;
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::MrsTpidr { destination: rd },
        MRS_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn emit_x18_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    transformation: X18Substitution,
    host: Host,
) -> Result<GateBuild> {
    let X18Substitution {
        mut word,
        scratch,
        anchor_scratch,
        pc_relative,
    } = transformation;
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "x18 gate")?;
    let mut asm = Asm::new(gate_vaddr);

    asm.emit(Insn::StpPre {
        rt: scratch,
        rt2: anchor_scratch,
        rn: SP,
        imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
    });
    asm.emit(host.anchor_read(anchor_scratch));
    asm.emit(Insn::LdrUimm {
        rt: scratch,
        rn: anchor_scratch,
        imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
    });
    asm.emit(Insn::AddImm {
        rd: anchor_scratch,
        rn: SP,
        imm12: 0,
    });
    asm.emit(Insn::AddSp(X18_FRAME_BYTES));
    if let Some(pc_relative) = pc_relative {
        let transformed_pc = asm.here()?;
        let relocated = match pc_relative {
            X18PcRelative::Adr(target) => Insn::Adr {
                rd: scratch,
                byte_off: target
                    .cast_signed()
                    .saturating_sub(transformed_pc.cast_signed()),
            },
            X18PcRelative::Adrp(target) => Insn::Adrp {
                rd: scratch,
                page_off: (target & !PAGE_OFFSET_MASK)
                    .cast_signed()
                    .saturating_sub((transformed_pc & !PAGE_OFFSET_MASK).cast_signed())
                    >> 12,
            },
        }
        .encode();
        let Some(relocated) = relocated else {
            return Ok(GateBuild::Unreachable);
        };
        word = relocated;
    }
    asm.push_word(word);

    // The transformed instruction excludes both scratches. The anchor scratch
    // can therefore carry the frame address while original SP is live.
    asm.emit(Insn::AddImm {
        rd: SP,
        rn: anchor_scratch,
        imm12: 0,
    });
    asm.emit(host.anchor_read(anchor_scratch));
    asm.emit(Insn::StrUimm {
        rt: scratch,
        rn: anchor_scratch,
        imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
    });
    asm.emit(Insn::LdpPost {
        rt: scratch,
        rt2: anchor_scratch,
        rn: SP,
        imm_bytes: X18_FRAME_BYTES.cast_signed(),
    });
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 return")?;
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18 { scratch },
        X18_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn emit_x18_compare_branch_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    branch: X18CompareBranch,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(
        trampoline_base_addr,
        gate_offset as u64,
        "x18 compare-branch gate",
    )?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(Insn::SubSp(X18_FRAME_BYTES));
    asm.emit(Insn::Stp {
        rt: branch.scratch,
        rt2: branch.anchor_scratch,
        rn: SP,
        imm_bytes: X18_FRAME_OFF_SCRATCHES.cast_signed(),
    });
    asm.emit(host.anchor_read(branch.anchor_scratch));
    asm.emit(Insn::LdrUimm {
        rt: branch.scratch,
        rn: branch.anchor_scratch,
        imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
    });
    asm.emit(match branch.kind {
        X18BranchKind::CbzW => Insn::CbzW {
            rt: branch.scratch,
            offset: 16,
        },
        X18BranchKind::CbzX => Insn::CbzX {
            rt: branch.scratch,
            offset: 16,
        },
        X18BranchKind::CbnzW => Insn::CbnzW {
            rt: branch.scratch,
            offset: 16,
        },
        X18BranchKind::CbnzX => Insn::CbnzX {
            rt: branch.scratch,
            offset: 16,
        },
        X18BranchKind::Tbz(bit) => Insn::TestBranch {
            rt: branch.scratch,
            bit,
            offset: 16,
            nonzero: false,
        },
        X18BranchKind::Tbnz(bit) => Insn::TestBranch {
            rt: branch.scratch,
            bit,
            offset: 16,
            nonzero: true,
        },
    });
    for target in [
        checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 branch fallthrough")?,
        branch.target,
    ] {
        asm.emit(Insn::Ldp {
            rt: branch.scratch,
            rt2: branch.anchor_scratch,
            rn: SP,
            imm_bytes: X18_FRAME_OFF_SCRATCHES.cast_signed(),
        });
        asm.emit(Insn::AddSp(X18_FRAME_BYTES));
        if !asm.branch_to(target)? {
            return Ok(GateBuild::Unreachable);
        }
    }
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18CompareBranch {
            scratch: branch.scratch,
        },
        X18_COMPARE_BRANCH_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn emit_x18_adr_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    adr: X18Adr,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "ADR X18 gate")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(Insn::StpPre {
        rt: adr.scratch,
        rt2: adr.anchor_scratch,
        rn: SP,
        imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
    });
    asm.emit(host.anchor_read(adr.anchor_scratch));
    if !asm.adrp(adr.scratch, adr.target)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.emit(Insn::AddImm {
        rd: adr.scratch,
        rn: adr.scratch,
        imm12: (adr.target & PAGE_OFFSET_MASK) as u16,
    });
    asm.emit(Insn::StrUimm {
        rt: adr.scratch,
        rn: adr.anchor_scratch,
        imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
    });
    asm.emit(Insn::LdpPost {
        rt: adr.scratch,
        rt2: adr.anchor_scratch,
        rn: SP,
        imm_bytes: X18_FRAME_BYTES.cast_signed(),
    });
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "ADR X18 return")?;
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18Adr {
            scratch: adr.scratch,
        },
        X18_ADR_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn append_gate_slot(
    trampoline_data: &mut Vec<u8>,
    mut code: Vec<u8>,
    trampoline_base: u64,
    slot_vaddr: u64,
    metadata: GateMetadata,
    slot_size: usize,
) -> Result<()> {
    let metadata_offset = slot_size - GATE_METADATA_BYTES;
    if code.len() > metadata_offset {
        return Err(Error::AddressOverflow(format!(
            "AArch64 gate is {} bytes and does not fit before slot metadata",
            code.len()
        )));
    }
    while code.len() < metadata_offset {
        code.extend_from_slice(&NOP.to_le_bytes());
    }
    let encoded = EncodedGateMetadata::encode(metadata)
        .ok_or_else(|| Error::AddressOverflow("invalid AArch64 gate metadata".into()))?;
    code.extend_from_slice(&encoded.0.to_le_bytes());
    debug_assert_eq!(code.len(), slot_size);
    let metadata_bytes: [u8; 4] = code[metadata_offset..]
        .try_into()
        .map_err(|_| Error::AddressOverflow("AArch64 metadata word length".into()))?;
    let decoded = EncodedGateMetadata(u32::from_le_bytes(metadata_bytes))
        .decode()
        .ok_or_else(|| Error::AddressOverflow("emitter produced invalid metadata".into()))?;
    debug_assert!(validate_gate_slot(
        &code,
        trampoline_base,
        slot_vaddr,
        decoded
    ));
    trampoline_data.extend_from_slice(&code);
    Ok(())
}

/// Validate the complete instruction template and metadata word of one slot.
/// This is structural recognition, not authentication: the gate-signal
/// canonicalization path must additionally fault-safely validate that the
/// recovered original site branches into this slot before canonicalizing an
/// interrupted context.
pub(crate) fn validate_gate_slot(
    slot: &[u8],
    trampoline_base: u64,
    slot_vaddr: u64,
    metadata: GateMetadata,
) -> bool {
    validate_gate_slot_inner(
        slot,
        SlotAddressing::Placed {
            trampoline_base,
            slot_vaddr,
        },
        metadata,
    )
}

/// Where a slot being validated lives, which decides how exactly its branch and
/// literal targets can be checked.
#[derive(Clone, Copy, Debug)]
enum SlotAddressing {
    /// The trampoline has been placed at its final address, so every target
    /// resolves to an absolute address and can be compared exactly.
    Placed {
        /// Address the trampoline starts at.
        trampoline_base: u64,
        /// Address the slot itself starts at.
        slot_vaddr: u64,
    },
    /// The trampoline is still a position-independent blob, so targets can only
    /// be checked structurally: the right opcodes, self-consistent with each
    /// other.
    Unplaced {
        /// Byte offset of the slot within the blob.
        slot_offset: u64,
    },
}

fn validate_gate_slot_inner(
    slot: &[u8],
    addressing: SlotAddressing,
    metadata: GateMetadata,
) -> bool {
    validate_gate_slot_inner_for_host(slot, addressing, metadata, None)
}

fn validate_gate_slot_inner_for_host(
    slot: &[u8],
    addressing: SlotAddressing,
    metadata: GateMetadata,
    host: Option<Host>,
) -> bool {
    let slot_size = metadata.slot_size();
    // Both variants' positions are 16-byte aligned by construction, because the
    // blob is laid out and mapped at gate alignment.
    let anchor = match addressing {
        SlotAddressing::Placed { slot_vaddr, .. } => slot_vaddr,
        SlotAddressing::Unplaced { slot_offset } => slot_offset,
    };
    if slot.len() != slot_size || !anchor.is_multiple_of(GATE_ALIGNMENT as u64) {
        return false;
    }
    let Some(encoded) = EncodedGateMetadata::encode(metadata) else {
        return false;
    };
    let metadata_offset = slot_size - GATE_METADATA_BYTES;
    if slot[metadata_offset..] != encoded.0.to_le_bytes() {
        return false;
    }
    let word = |offset: usize| {
        u32::from_le_bytes(
            slot[offset..offset + INSN_BYTES]
                .try_into()
                .expect("word-sized slice"),
        )
    };
    let exact = |offset: usize, insn: Insn| word(offset) == insn.encode().unwrap();
    let padding_is_nops = |start: usize| {
        (start..metadata_offset)
            .step_by(INSN_BYTES)
            .all(|offset| word(offset) == NOP)
    };

    match metadata {
        GateMetadata::Svc => {
            let adrp = word(8);
            let add = word(12);
            exact(0, Insn::SubSp(SVC_FRAME_BYTES))
                && exact(
                    4,
                    Insn::StrUimm {
                        rt: X16,
                        rn: SP,
                        imm_bytes: SVC_FRAME_OFF_X16,
                    },
                )
                && exact(
                    16,
                    Insn::StrUimm {
                        rt: X16,
                        rn: SP,
                        imm_bytes: SVC_FRAME_OFF_RETADDR,
                    },
                )
                && exact(
                    20,
                    Insn::Adr {
                        rd: X16,
                        byte_off: 16,
                    },
                )
                && exact(
                    24,
                    Insn::StrUimm {
                        rt: X16,
                        rn: SP,
                        imm_bytes: SVC_FRAME_OFF_STUB,
                    },
                )
                && match addressing {
                    // Unplaced, the literal load is still relative to the blob,
                    // so it resolves to the header slot's own offset.
                    SlotAddressing::Unplaced { slot_offset } => {
                        decode_ldr_literal_target(word(28), slot_offset + 28)
                            == Some(HEADER_CALLBACK_OFFSET as u64)
                    }
                    SlotAddressing::Placed {
                        trampoline_base,
                        slot_vaddr,
                    } => {
                        decode_ldr_literal_target(word(28), slot_vaddr + 28)
                            == Some(trampoline_base + HEADER_CALLBACK_OFFSET as u64)
                    }
                }
                && exact(32, Insn::Br(X16))
                && exact(
                    36,
                    Insn::LdrUimm {
                        rt: X16,
                        rn: SP,
                        imm_bytes: SVC_FRAME_OFF_X16,
                    },
                )
                && exact(40, Insn::AddSp(SVC_FRAME_BYTES))
                && match addressing {
                    SlotAddressing::Unplaced { .. } => {
                        adrp & ADRP_SHAPE_MASK == Opcode::Adrp.bits() | u32::from(X16)
                            && add & ADD_IMM_SHAPE_MASK
                                == Opcode::AddImm.bits()
                                    | (u32::from(X16) << RN_SHIFT)
                                    | u32::from(X16)
                            && word(44) & OPCODE_TOP6_MASK == Opcode::B.bits()
                    }
                    SlotAddressing::Placed { slot_vaddr, .. } => {
                        let return_from_adrp = decode_adrp_add_target(adrp, add, slot_vaddr + 8);
                        let return_from_branch = decode_branch_target(word(44), slot_vaddr + 44);
                        return_from_adrp.is_some() && return_from_adrp == return_from_branch
                    }
                }
                && padding_is_nops(48)
        }
        GateMetadata::MrsTpidr { destination } => {
            exact(0, Insn::MrsTpidrEl0(destination))
                && is_tpidr_access(word(4), Opcode::LdrUimm, destination, destination)
                && match addressing {
                    SlotAddressing::Unplaced { .. } => {
                        word(8) & OPCODE_TOP6_MASK == Opcode::B.bits()
                    }
                    SlotAddressing::Placed { slot_vaddr, .. } => {
                        decode_branch_target(word(8), slot_vaddr + 8).is_some()
                    }
                }
        }
        GateMetadata::MsrTpidr { source } => {
            exact(0, Insn::SubSp(MSR_FRAME_BYTES))
                && exact(
                    4,
                    Insn::Stp {
                        rt: X16,
                        rt2: X17,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(
                    8,
                    Insn::StrUimm {
                        rt: source,
                        rn: SP,
                        imm_bytes: MSR_FRAME_OFF_VALUE,
                    },
                )
                && exact(12, Insn::MrsTpidrEl0(X16))
                && exact(
                    16,
                    Insn::LdrUimm {
                        rt: X17,
                        rn: SP,
                        imm_bytes: MSR_FRAME_OFF_VALUE,
                    },
                )
                && is_tpidr_access(word(20), Opcode::StrUimm, X17, X16)
                && exact(
                    24,
                    Insn::Ldp {
                        rt: X16,
                        rt2: X17,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(28, Insn::AddSp(MSR_FRAME_BYTES))
                && match addressing {
                    SlotAddressing::Unplaced { .. } => {
                        word(32) & OPCODE_TOP6_MASK == Opcode::B.bits()
                            && word(36) & OPCODE_TOP6_MASK == Opcode::B.bits()
                            && branch_local_target(word(32), 32)
                                == branch_local_target(word(36), 36)
                    }
                    SlotAddressing::Placed { slot_vaddr, .. } => {
                        decode_branch_target(word(32), slot_vaddr + 32)
                            == decode_branch_target(word(36), slot_vaddr + 36)
                            && decode_branch_target(word(32), slot_vaddr + 32).is_some()
                    }
                }
                && padding_is_nops(40)
        }
        GateMetadata::X18 { scratch } => {
            let anchor_scratch = ((word(0) >> RT2_SHIFT) & REG_MASK) as u8;
            if !(7..=17).contains(&anchor_scratch) || anchor_scratch == scratch {
                return false;
            }
            exact(
                0,
                Insn::StpPre {
                    rt: scratch,
                    rt2: anchor_scratch,
                    rn: SP,
                    imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
                },
            ) && is_host_anchor_read(
                word(X18GateOffset::FirstAnchor.as_usize()),
                anchor_scratch,
                host,
            ) && is_x18_access(
                word(X18GateOffset::SlotLoad.as_usize()),
                Opcode::LdrUimm,
                scratch,
                anchor_scratch,
            ) && exact(
                X18GateOffset::FrameAddress.as_usize(),
                Insn::AddImm {
                    rd: anchor_scratch,
                    rn: SP,
                    imm12: 0,
                },
            ) && exact(
                X18GateOffset::FirstPop.as_usize(),
                Insn::AddSp(X18_FRAME_BYTES),
            ) && exact(
                X18GateOffset::RestoreSp.as_usize(),
                Insn::AddImm {
                    rd: SP,
                    rn: anchor_scratch,
                    imm12: 0,
                },
            ) && is_host_anchor_read(
                word(X18GateOffset::SecondAnchor.as_usize()),
                anchor_scratch,
                host,
            ) && word(X18GateOffset::FirstAnchor.as_usize())
                == word(X18GateOffset::SecondAnchor.as_usize())
                && is_x18_access(
                    word(X18GateOffset::SlotStore.as_usize()),
                    Opcode::StrUimm,
                    scratch,
                    anchor_scratch,
                )
                && exact(
                    X18GateOffset::RestoreRegisters.as_usize(),
                    Insn::LdpPost {
                        rt: scratch,
                        rt2: anchor_scratch,
                        rn: SP,
                        imm_bytes: X18_FRAME_BYTES.cast_signed(),
                    },
                )
                && word(X18GateOffset::Return.as_usize()) & OPCODE_TOP6_MASK == Opcode::B.bits()
                && padding_is_nops(X18GateOffset::ExecutableEnd.as_usize())
        }
        GateMetadata::X18CompareBranch { scratch } => {
            let anchor_scratch = ((word(4) >> RT2_SHIFT) & REG_MASK) as u8;
            if !(7..=17).contains(&anchor_scratch) || anchor_scratch == scratch {
                return false;
            }
            exact(0, Insn::SubSp(X18_FRAME_BYTES))
                && exact(
                    4,
                    Insn::Stp {
                        rt: scratch,
                        rt2: anchor_scratch,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && is_host_anchor_read(word(8), anchor_scratch, host)
                && is_x18_access(word(12), Opcode::LdrUimm, scratch, anchor_scratch)
                && ([
                    Insn::CbnzW {
                        rt: scratch,
                        offset: 16,
                    },
                    Insn::CbzW {
                        rt: scratch,
                        offset: 16,
                    },
                    Insn::CbnzX {
                        rt: scratch,
                        offset: 16,
                    },
                    Insn::CbzX {
                        rt: scratch,
                        offset: 16,
                    },
                ]
                .into_iter()
                .any(|instruction| exact(16, instruction))
                    || (0..64).any(|bit| {
                        [false, true].into_iter().any(|nonzero| {
                            exact(
                                16,
                                Insn::TestBranch {
                                    rt: scratch,
                                    bit,
                                    offset: 16,
                                    nonzero,
                                },
                            )
                        })
                    }))
                && exact(
                    20,
                    Insn::Ldp {
                        rt: scratch,
                        rt2: anchor_scratch,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(24, Insn::AddSp(X18_FRAME_BYTES))
                && word(28) & OPCODE_TOP6_MASK == Opcode::B.bits()
                && exact(
                    32,
                    Insn::Ldp {
                        rt: scratch,
                        rt2: anchor_scratch,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(36, Insn::AddSp(X18_FRAME_BYTES))
                && word(40) & OPCODE_TOP6_MASK == Opcode::B.bits()
        }
        GateMetadata::X18Adr { scratch } => {
            let anchor_scratch = ((word(0) >> RT2_SHIFT) & REG_MASK) as u8;
            let adrp = word(8);
            let add = word(12);
            if !(7..=17).contains(&anchor_scratch) || anchor_scratch == scratch {
                return false;
            }
            exact(
                0,
                Insn::StpPre {
                    rt: scratch,
                    rt2: anchor_scratch,
                    rn: SP,
                    imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
                },
            ) && is_host_anchor_read(word(4), anchor_scratch, host)
                && adrp & ADRP_SHAPE_MASK == Opcode::Adrp.bits() | u32::from(scratch)
                && add & ADD_IMM_SHAPE_MASK
                    == Opcode::AddImm.bits() | (u32::from(scratch) << RN_SHIFT) | u32::from(scratch)
                && is_x18_access(word(16), Opcode::StrUimm, scratch, anchor_scratch)
                && exact(
                    20,
                    Insn::LdpPost {
                        rt: scratch,
                        rt2: anchor_scratch,
                        rn: SP,
                        imm_bytes: X18_FRAME_BYTES.cast_signed(),
                    },
                )
                && word(24) & OPCODE_TOP6_MASK == Opcode::B.bits()
        }
    }
}

impl GateMetadata {
    /// Fixed byte size of this metadata version's compact slot.
    pub const fn slot_size(self) -> usize {
        match self {
            GateMetadata::Svc => SVC_SLOT_BYTES,
            GateMetadata::MrsTpidr { .. } => MRS_SLOT_BYTES,
            GateMetadata::MsrTpidr { .. } => MSR_SLOT_BYTES,
            GateMetadata::X18 { .. } => X18_SLOT_BYTES,
            GateMetadata::X18CompareBranch { .. } => X18_COMPARE_BRANCH_SLOT_BYTES,
            GateMetadata::X18Adr { .. } => X18_ADR_SLOT_BYTES,
        }
    }

    /// First byte offset past the slot's executable body.
    ///
    /// Everything from here to the trailing metadata word is `NOP` padding, so
    /// a PC at or past it is not inside the gate proper and must not be
    /// classified as one.
    pub(crate) const fn executable_end(self) -> usize {
        match self {
            GateMetadata::Svc => SvcGateOffset::ExecutableEnd.as_usize(),
            GateMetadata::MrsTpidr { .. } => MrsTpidrGateOffset::ExecutableEnd.as_usize(),
            GateMetadata::MsrTpidr { .. } => MsrTpidrGateOffset::ExecutableEnd.as_usize(),
            GateMetadata::X18 { .. } => X18GateOffset::ExecutableEnd.as_usize(),
            GateMetadata::X18CompareBranch { .. } => {
                X18CompareBranchOffset::ExecutableEnd.as_usize()
            }
            GateMetadata::X18Adr { .. } => X18AdrOffset::ExecutableEnd.as_usize(),
        }
    }

    /// Byte offset of the branch that returns to the instruction after the
    /// original site.
    pub(crate) const fn return_offset(self) -> usize {
        match self {
            GateMetadata::Svc => SvcGateOffset::Return.as_usize(),
            GateMetadata::MrsTpidr { .. } => MrsTpidrGateOffset::Return.as_usize(),
            GateMetadata::MsrTpidr { .. } => MsrTpidrGateOffset::Return.as_usize(),
            GateMetadata::X18 { .. } => X18GateOffset::Return.as_usize(),
            GateMetadata::X18CompareBranch { .. } => {
                X18CompareBranchOffset::FallthroughBranch.as_usize()
            }
            GateMetadata::X18Adr { .. } => X18AdrOffset::Return.as_usize(),
        }
    }
}

/// Decode one little-endian metadata word copied from a candidate slot.
pub fn decode_gate_metadata_word(word: u32) -> Option<GateMetadata> {
    EncodedGateMetadata(word).decode()
}

/// A validated gate slot containing some PC, with what a signal handler needs
/// to canonicalize the interrupted context: where the slot starts and which
/// guest instruction it replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedGate {
    slot_offset: usize,
    slot_size: u8,
    anchor_scratch: u8,
    original_site: u64,
    conditional_target: u64,
    metadata: GateMetadata,
}

impl ClassifiedGate {
    /// Byte offset of the validated slot within the trampoline.
    pub fn slot_offset(self) -> usize {
        self.slot_offset
    }

    /// Kind-derived byte size of the validated slot.
    pub fn slot_size(self) -> u8 {
        self.slot_size
    }

    pub fn anchor_scratch(self) -> Option<u8> {
        matches!(
            self.metadata,
            GateMetadata::X18 { .. }
                | GateMetadata::X18CompareBranch { .. }
                | GateMetadata::X18Adr { .. }
        )
        .then_some(self.anchor_scratch)
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

/// Classifies one Linux-host, fault-safely copied compact slot containing `pc`.
///
/// The caller is responsible for selecting candidate slot starts and for
/// requiring exactly one match. Keeping that policy outside this pure helper
/// lets a signal handler copy each candidate before inspecting it.
pub fn classify_copied_gate_slot(slot: &[u8], slot_vaddr: u64, pc: u64) -> Option<ClassifiedGate> {
    let offset = usize::try_from(pc.checked_sub(slot_vaddr)?).ok()?;
    if !pc.is_multiple_of(INSN_BYTES_U64) || !slot_vaddr.is_multiple_of(GATE_ALIGNMENT as u64) {
        return None;
    }
    let metadata_word =
        u32::from_le_bytes(slot.get(slot.len().checked_sub(4)?..)?.try_into().ok()?);
    let metadata = EncodedGateMetadata(metadata_word).decode()?;
    if metadata.slot_size() != slot.len() || offset >= metadata.executable_end() {
        return None;
    }
    let trampoline_base = match metadata {
        GateMetadata::Svc => decode_ldr_literal_target(
            u32::from_le_bytes(
                slot.get(
                    SvcGateOffset::LoadCallback.as_usize()
                        ..SvcGateOffset::LoadCallback.as_usize() + INSN_BYTES,
                )?
                .try_into()
                .ok()?,
            ),
            slot_vaddr + SvcGateOffset::LoadCallback.as_usize() as u64,
        )?,
        GateMetadata::MrsTpidr { .. }
        | GateMetadata::MsrTpidr { .. }
        | GateMetadata::X18 { .. }
        | GateMetadata::X18CompareBranch { .. }
        | GateMetadata::X18Adr { .. } => 0,
    };
    // For `Svc` the base was just recovered from the slot's own literal load,
    // so `validate_gate_slot`'s callback check is a tautology here. The other
    // template checks still do real work; this is structural recognition, not
    // authentication.
    if !validate_gate_slot_inner_for_host(
        slot,
        SlotAddressing::Placed {
            trampoline_base,
            slot_vaddr,
        },
        metadata,
        Some(Host::Linux),
    ) {
        return None;
    }
    let return_offset = metadata.return_offset();
    let return_target = decode_branch_target(
        u32::from_le_bytes(
            slot.get(return_offset..return_offset + INSN_BYTES)?
                .try_into()
                .ok()?,
        ),
        slot_vaddr + return_offset as u64,
    )?;
    let conditional_target = if matches!(metadata, GateMetadata::X18CompareBranch { .. }) {
        decode_branch_target(
            u32::from_le_bytes(
                slot[X18CompareBranchOffset::TakenBranch.as_usize()
                    ..X18CompareBranchOffset::TakenBranch.as_usize() + INSN_BYTES]
                    .try_into()
                    .ok()?,
            ),
            slot_vaddr + X18CompareBranchOffset::TakenBranch.as_usize() as u64,
        )?
    } else {
        0
    };
    Some(ClassifiedGate {
        slot_offset: 0,
        slot_size: u8::try_from(slot.len()).ok()?,
        anchor_scratch: match metadata {
            GateMetadata::X18 { .. }
            | GateMetadata::X18CompareBranch { .. }
            | GateMetadata::X18Adr { .. } => x18_anchor_scratch(slot, metadata)?,
            _ => 0,
        },
        original_site: return_target.checked_sub(4)?,
        conditional_target,
        metadata,
    })
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
            let slot = &trampoline[start..end];
            let slot_vaddr = trampoline_base + start as u64;
            // The size agreement has to come first: it is what makes the
            // decoded metadata's layout accessors apply to these bytes.
            if metadata.slot_size() != slot_size
                || relative >= start + metadata.executable_end()
                || !validate_gate_slot_inner_for_host(
                    slot,
                    SlotAddressing::Placed {
                        trampoline_base,
                        slot_vaddr,
                    },
                    metadata,
                    Some(Host::Linux),
                )
            {
                continue;
            }
            if match_found.is_some() {
                return None;
            }
            let return_offset = metadata.return_offset();
            let return_target = decode_branch_target(
                u32::from_le_bytes(
                    slot[return_offset..return_offset + INSN_BYTES]
                        .try_into()
                        .ok()?,
                ),
                slot_vaddr + return_offset as u64,
            )?;
            let conditional_target = if matches!(metadata, GateMetadata::X18CompareBranch { .. }) {
                decode_branch_target(
                    u32::from_le_bytes(
                        slot[X18CompareBranchOffset::TakenBranch.as_usize()
                            ..X18CompareBranchOffset::TakenBranch.as_usize() + INSN_BYTES]
                            .try_into()
                            .ok()?,
                    ),
                    slot_vaddr + X18CompareBranchOffset::TakenBranch.as_usize() as u64,
                )?
            } else {
                0
            };
            match_found = Some(ClassifiedGate {
                slot_offset: start,
                slot_size: u8::try_from(slot_size).ok()?,
                anchor_scratch: match metadata {
                    GateMetadata::X18 { .. }
                    | GateMetadata::X18CompareBranch { .. }
                    | GateMetadata::X18Adr { .. } => x18_anchor_scratch(slot, metadata)?,
                    _ => 0,
                },
                original_site: return_target.checked_sub(4)?,
                conditional_target,
                metadata,
            });
        }
    }
    match_found
}

fn is_tpidr_access(word: u32, opcode: Opcode, rt: u8, rn: u8) -> bool {
    if word & !LDST_UIMM12_IMM_MASK != opcode.bits() | (u32::from(rn) << RN_SHIFT) | u32::from(rt) {
        return false;
    }
    let encoded = (word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
    valid_emitted_tpidr_offset(encoded * u32::from(GUEST_TPIDR_OFFSET_ALIGN))
}

fn is_x18_access(word: u32, opcode: Opcode, rt: u8, rn: u8) -> bool {
    word & !LDST_UIMM12_IMM_MASK == opcode.bits() | (u32::from(rn) << RN_SHIFT) | u32::from(rt)
        && valid_emitted_x18_offset(
            ((word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT)
                * u32::from(GUEST_TPIDR_OFFSET_ALIGN),
        )
}

fn is_host_anchor_read(word: u32, register: u8, host: Option<Host>) -> bool {
    host.map_or_else(
        || {
            [Host::Linux, Host::MacOs, Host::Windows]
                .into_iter()
                .any(|host| host.anchor_read(register).encode() == Some(word))
        },
        |host| host.anchor_read(register).encode() == Some(word),
    )
}

fn x18_anchor_scratch(slot: &[u8], metadata: GateMetadata) -> Option<u8> {
    let offset = match metadata {
        GateMetadata::X18 { .. } | GateMetadata::X18Adr { .. } => 0,
        GateMetadata::X18CompareBranch { .. } => 4,
        _ => return None,
    };
    Some(
        ((u32::from_le_bytes(slot[offset..offset + 4].try_into().ok()?) >> RT2_SHIFT) & REG_MASK)
            as u8,
    )
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

fn branch_local_target(word: u32, pc_offset: i64) -> Option<i64> {
    if word & OPCODE_TOP6_MASK != Opcode::B.bits() {
        return None;
    }
    let imm26 = i64::from(word & IMM26_MASK);
    Some(pc_offset + pcrel_bytes(imm26, IMM26_BITS))
}

fn decode_ldr_literal_target(word: u32, pc: u64) -> Option<u64> {
    if word & LDR_LITERAL_SHAPE_MASK != Opcode::LdrLiteral.bits() | u32::from(X16) {
        return None;
    }
    let imm19 = i64::from((word >> RN_SHIFT) & IMM19_MASK);
    let displacement = pcrel_bytes(imm19, IMM19_BITS);
    pc.checked_add_signed(displacement)
}

fn decode_adrp_add_target(adrp: u32, add: u32, pc: u64) -> Option<u64> {
    decode_adrp_add_target_for(adrp, add, pc, X16)
}

fn decode_adrp_add_target_for(adrp: u32, add: u32, pc: u64, register: u8) -> Option<u64> {
    let page = decode_adrp_target(adrp, pc, register)?;
    if add & ADD_IMM_SHAPE_MASK
        != Opcode::AddImm.bits() | (u32::from(register) << RN_SHIFT) | u32::from(register)
    {
        return None;
    }
    page.checked_add(u64::from(add >> RT2_SHIFT) & PAGE_OFFSET_MASK)
}

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
/// [`finalize_trampoline_gates_with_x18`].
///
/// # Errors
///
/// Rejects invalid offsets, malformed slots, unexpected field values, and x18
/// gates before mutating the trampoline.
pub fn finalize_trampoline_gates(trampoline: &mut [u8], offset: u16) -> Result<()> {
    if !is_patchable_guest_tpidr_offset(offset) {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest thread-pointer offset {offset} is not a legitimate gate target"
        )));
    }
    let validation = validate_trampoline_and_collect_offsets(trampoline, offset, false)?;
    if validation.has_x18_gate {
        return Err(Error::TrampolinePatchFailure(
            "AArch64 trampoline contains x18 gates or placeholders; use \
             finalize_trampoline_gates_with_x18"
                .into(),
        ));
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(())
}

/// Finalizes both anchor-relative guest slots in a Linux-host trampoline.
/// Validation happens against a copy so an invalid offset cannot partially
/// patch the caller's trampoline.
pub fn finalize_trampoline_gates_with_x18(
    trampoline: &mut [u8],
    guest_tpidr_offset: u16,
    guest_x18_offset: u16,
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
    let mut staged = trampoline.to_vec();
    patch_guest_tpidr_offset_inner(&mut staged, guest_tpidr_offset, true)?;
    patch_guest_x18_offset(&mut staged, guest_x18_offset)?;
    trampoline.copy_from_slice(&staged);
    Ok(())
}

/// Whether a gate can be patched to reach `offset`: a multiple of
/// [`GUEST_TPIDR_OFFSET_ALIGN`], far enough from the thread pointer that it
/// cannot land on the host's own per-thread state, and below the value reserved
/// for the unpatched placeholder.
pub fn is_patchable_guest_tpidr_offset(offset: u16) -> bool {
    offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
        && (MIN_GUEST_TPIDR_OFFSET..GUEST_TPIDR_OFFSET_PLACEHOLDER).contains(&offset)
}

/// Whether an x18 gate can be patched to reach `offset` without retaining a
/// value reserved for an unpatched placeholder.
pub fn is_patchable_guest_x18_offset(offset: u16) -> bool {
    offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
        && (MIN_GUEST_TPIDR_OFFSET..GUEST_X18_OFFSET_PLACEHOLDER).contains(&offset)
}

/// Rewrites the guest thread-pointer offset in every gate of one emitted
/// trampoline, replacing the emitted placeholder with `offset`. The loader must
/// call this before making the trampoline executable.
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
/// x18 gates must instead use [`finalize_trampoline_gates_with_x18`].
///
/// # Panics
///
/// Panics if a validated slot is shorter than its own metadata word, which the
/// slot templates make impossible.
pub fn patch_guest_tpidr_offset(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    patch_guest_tpidr_offset_inner(trampoline, offset, false)
}

fn patch_guest_tpidr_offset_inner(
    trampoline: &mut [u8],
    offset: u16,
    allow_x18: bool,
) -> Result<usize> {
    if !is_patchable_guest_tpidr_offset(offset) {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest thread-pointer offset {offset} is not a legitimate gate target: it must be a \
             multiple of {GUEST_TPIDR_OFFSET_ALIGN}, at least {MIN_GUEST_TPIDR_OFFSET} so it \
             cannot land on the host's own per-thread state, and below \
             {GUEST_TPIDR_OFFSET_PLACEHOLDER} so a patched gate is never mistaken for an \
             unpatched one"
        )));
    }

    let validation = validate_trampoline_and_collect_offsets(trampoline, offset, false)?;
    if validation.has_x18_gate && !allow_x18 {
        return Err(Error::TrampolinePatchFailure(
            "AArch64 trampoline contains x18 gates; use finalize_trampoline_gates_with_x18".into(),
        ));
    }
    let patch_offsets = validation.patch_offsets;
    let new_imm = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
    for offset in &patch_offsets {
        let word = &mut trampoline[*offset..*offset + INSN_BYTES];
        let insn = u32::from_le_bytes(word.try_into().expect("four-byte patch offset"));
        let patched_insn = (insn & !LDST_UIMM12_IMM_MASK) | new_imm;
        word.copy_from_slice(&patched_insn.to_le_bytes());
    }
    Ok(patch_offsets.len())
}

fn patch_guest_x18_offset(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    if !is_patchable_guest_x18_offset(offset) {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest x18 offset {offset} is not a legitimate gate target"
        )));
    }
    let validation = validate_trampoline_and_collect_offsets(trampoline, offset, true)?;
    if !validation.has_x18_gate {
        return Ok(0);
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(validation.patch_offsets.len())
}

fn patch_offset_words(trampoline: &mut [u8], patch_offsets: &[usize], offset: u16) {
    let new_imm = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
    for offset in patch_offsets {
        let word = &mut trampoline[*offset..*offset + INSN_BYTES];
        let insn = u32::from_le_bytes(word.try_into().expect("four-byte patch offset"));
        word.copy_from_slice(&((insn & !LDST_UIMM12_IMM_MASK) | new_imm).to_le_bytes());
    }
}

struct TrampolineValidation {
    patch_offsets: Vec<usize>,
    has_x18_gate: bool,
}

/// Validates every Linux-host slot, reports whether any x18 gate is present,
/// and returns metadata-designated fields that still hold the selected
/// placeholder. A field holding neither the placeholder nor `expected_offset`
/// is rejected rather than left alone.
fn validate_trampoline_and_collect_offsets(
    trampoline: &[u8],
    expected_offset: u16,
    x18: bool,
) -> Result<TrampolineValidation> {
    if trampoline.len() < GATES_START_OFFSET || !trampoline.len().is_multiple_of(INSN_BYTES) {
        return Err(Error::TrampolinePatchFailure(
            "malformed AArch64 trampoline length".into(),
        ));
    }
    if trampoline[8..GATES_START_OFFSET]
        .chunks_exact(4)
        .any(|word| u32::from_le_bytes(word.try_into().unwrap()) != NOP)
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
            if metadata.slot_size() != slot_size
                || !validate_gate_slot_inner_for_host(
                    &trampoline[cursor..end],
                    SlotAddressing::Unplaced {
                        slot_offset: cursor as u64,
                    },
                    metadata,
                    Some(Host::Linux),
                )
            {
                continue;
            }
            if matched.is_some() {
                return Err(Error::TrampolinePatchFailure(
                    "ambiguous AArch64 compact slot".into(),
                ));
            }
            matched = Some((end, metadata));
        }
        let Some((end, metadata)) = matched else {
            return Err(Error::TrampolinePatchFailure(format!(
                "malformed AArch64 compact slot at byte {cursor}"
            )));
        };
        has_x18_gate |= matches!(
            metadata,
            GateMetadata::X18 { .. }
                | GateMetadata::X18CompareBranch { .. }
                | GateMetadata::X18Adr { .. }
        );
        let instruction_offsets: &[usize] = match (metadata, x18) {
            (GateMetadata::MrsTpidr { .. }, false) => &[cursor + 4],
            (GateMetadata::MsrTpidr { .. }, false) => &[cursor + 20],
            (GateMetadata::X18 { .. }, true) => &[
                cursor + X18GateOffset::SlotLoad.as_usize(),
                cursor + X18GateOffset::SlotStore.as_usize(),
            ],
            (GateMetadata::X18CompareBranch { .. }, true) => &[cursor + 12],
            (GateMetadata::X18Adr { .. }, true) => &[cursor + 16],
            _ => &[],
        };
        for &offset in instruction_offsets {
            let insn =
                u32::from_le_bytes(trampoline[offset..offset + INSN_BYTES].try_into().unwrap());
            let encoded = (insn & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
            let gate_offset = encoded * u32::from(GUEST_TPIDR_OFFSET_ALIGN);
            let placeholder = if x18 {
                GUEST_X18_OFFSET_PLACEHOLDER
            } else {
                GUEST_TPIDR_OFFSET_PLACEHOLDER
            };
            if gate_offset == u32::from(placeholder) {
                patch_offsets.push(offset);
            } else if gate_offset != u32::from(expected_offset) {
                return Err(Error::TrampolinePatchFailure(format!(
                    "AArch64 gate at byte {offset} addresses the host thread pointer at \
                     {gate_offset}, which is neither the placeholder nor the offset being \
                     patched in ({expected_offset})"
                )));
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
/// loaders must use [`finalize_trampoline_gates_with_x18`] for acceptance.
#[cfg(test)]
fn find_guest_x18_placeholder(trampoline: &[u8]) -> Option<usize> {
    find_structured_placeholder(trampoline, true)
}

fn find_structured_placeholder(trampoline: &[u8], x18: bool) -> Option<usize> {
    let validation = validate_trampoline_and_collect_offsets(
        trampoline,
        if x18 {
            GUEST_X18_OFFSET_PLACEHOLDER
        } else {
            GUEST_TPIDR_OFFSET_PLACEHOLDER
        },
        x18,
    )
    .ok()?;
    validation.patch_offsets.into_iter().next()
}

// ============================================================
// Small helpers
// ============================================================

/// A position-tracking assembler for one gate. It owns the emitted words and
/// the base virtual address of the first, so [`Asm::here`] is always known
/// without manual instruction counting.
///
/// Absolute-target forms resolve immediately against [`Asm::here`].
/// [`Asm::branch_to`] and [`Asm::adrp`] report an out-of-range target by
/// emitting nothing and returning `false`, so the caller can trap the site;
/// [`Asm::ldr_literal`] instead errors, since a callback literal that cannot be
/// placed is fatal.
struct Asm {
    base_vaddr: u64,
    code: Vec<u8>,
}

impl Asm {
    fn new(base_vaddr: u64) -> Self {
        Asm {
            base_vaddr,
            code: Vec::new(),
        }
    }

    /// Virtual address of the next instruction to be emitted.
    fn here(&self) -> Result<u64> {
        checked_add_u64(
            self.base_vaddr,
            self.code.len() as u64,
            "trampoline gate next-instruction",
        )
    }

    /// Append a raw little-endian word.
    fn push_word(&mut self, word: u32) {
        self.code.extend_from_slice(&word.to_le_bytes());
    }

    /// Append a fixed-operand instruction. Every operand at the call sites is a
    /// compile-time-known register or frame offset, so encoding cannot fail; a
    /// `None` would be a rewriter bug rather than an unencodable program.
    fn emit(&mut self, insn: Insn) {
        let word = insn.encode().expect("statically valid instruction");
        self.push_word(word);
    }

    /// `B <target>` — unconditional branch to an absolute address. Returns
    /// whether the target was within the branch's ±128MB reach: an out-of-range
    /// target emits nothing and yields `false`, so the caller can trap the
    /// originating site instead of failing the whole rewrite.
    fn branch_to(&mut self, target_vaddr: u64) -> Result<bool> {
        let offset = self.delta_to(target_vaddr)?;
        let Some(word) = Insn::B(offset).encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// `LDR Xt, =target` — PC-relative literal load of an absolute address.
    fn ldr_literal(&mut self, rt: u8, target_vaddr: u64) -> Result<()> {
        let offset = self.delta_to(target_vaddr)?;
        let word = Insn::LdrLiteral { rt, off: offset }
            .encode()
            .ok_or_else(|| {
                Error::AddressOverflow(format!("LDR literal offset {offset:#x} out of ±1MB range"))
            })?;
        self.push_word(word);
        Ok(())
    }

    /// `ADR Xd, <target>` — byte-granular PC-relative address of an absolute
    /// target, ±1MB. Returns whether the target was in reach (see
    /// [`Asm::branch_to`] for the out-of-range contract).
    fn adr(&mut self, rd: u8, target_vaddr: u64) -> Result<bool> {
        let byte_off = self.delta_to(target_vaddr)?;
        let Some(word) = Insn::Adr { rd, byte_off }.encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// `ADRP Xd, <target>` — page-relative address of an absolute target.
    /// Returns whether the target's page was within ADRP's ±4GB reach (see
    /// [`Asm::branch_to`] for the out-of-range contract).
    fn adrp(&mut self, rd: u8, target_vaddr: u64) -> Result<bool> {
        let here = self.here()?;
        let page_off = (target_vaddr & !PAGE_OFFSET_MASK)
            .cast_signed()
            .saturating_sub((here & !PAGE_OFFSET_MASK).cast_signed())
            >> 12;
        let Some(word) = Insn::Adrp { rd, page_off }.encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// Signed byte distance from [`Asm::here`] to `target_vaddr`. The subtraction
    /// saturates so a pathological address can't overflow it; a distance the
    /// branch can't encode is rejected by the encoder's range check at the call
    /// site, with the saturated value reported for diagnostics.
    fn delta_to(&self, target_vaddr: u64) -> Result<i64> {
        Ok(target_vaddr
            .cast_signed()
            .saturating_sub(self.here()?.cast_signed()))
    }

    /// Return the emitted bytes.
    fn finish(self) -> Vec<u8> {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_linux_rejects_linux_specific_sites_but_accepts_x18_only_scan() {
        for target in [crate::TargetHost::MacOs, crate::TargetHost::Windows] {
            let config = RewriteConfig::new(target, true);
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
        }
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
            (0xa906_4bee, 0xa906_47ee), // Rt2
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
            (0xa400_a020, X18Classification::None), // SVE ld1b
            (0xe400_e060, X18Classification::None), // SVE st1b
            (
                0xa5e0_a240, // SVE ld1d { z0.d }, p0/z, [x18]
                X18Classification::X18(X18TransformResult::Unsupported(
                    X18Unsupported::DecodeFailure,
                )),
            ),
        ] {
            assert_eq!(classify_x18(word), expected, "word {word:#010x}");
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
        for (word, expected) in [
            (
                0xd61f_0240,
                X18Classification::X18(X18TransformResult::Unsupported(
                    X18Unsupported::ControlFlow,
                )),
            ), // br x18
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
        }
    }

    fn word_at(data: &[u8], byte_off: usize) -> u32 {
        u32::from_le_bytes(data[byte_off..byte_off + 4].try_into().unwrap())
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
        // TPIDR_EL0 accessor.
        assert_eq!(Insn::MrsTpidrEl0(9).encode().unwrap(), 0xD53B_D049);
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
            RewriteConfig {
                host: Host::Linux,
                virtualize_x18: false,
            },
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
            RewriteConfig {
                host: Host::Linux,
                virtualize_x18: false,
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
            assert_eq!(gate.len(), X18_SLOT_BYTES);
            assert_eq!(
                word_at(gate, X18GateOffset::FirstAnchor.as_usize()),
                anchor_word
            );
            assert_eq!(
                word_at(gate, X18_SLOT_BYTES - GATE_METADATA_BYTES),
                EncodedGateMetadata::encode(GateMetadata::X18 { scratch: X17 })
                    .unwrap()
                    .0
            );
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

        assert!(outcome.trapped_sites.is_empty());
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

        finalize_trampoline_gates_with_x18(&mut trampoline, 96, 104).unwrap();
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

        assert!(outcome.trapped_sites.is_empty());
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

        assert!(outcome.trapped_sites.is_empty());
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

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        let transformed_pc =
            0x400000 + GATES_START_OFFSET as u64 + X18GateOffset::Transform.as_usize() as u64;
        assert_eq!(
            decode_adrp_target(
                word_at(
                    &outcome.trampoline,
                    GATES_START_OFFSET + X18GateOffset::Transform.as_usize(),
                ),
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

        assert!(outcome.trapped_sites.is_empty());
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

        finalize_trampoline_gates_with_x18(&mut trampoline, 96, 104).unwrap();
        assert_eq!(find_guest_x18_placeholder(&trampoline), None);
    }

    #[test]
    fn x18_offsets_finalize_transactionally() {
        let (_, outcome) =
            hook_words_opt_with_config(&[0x0b12_0063], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();
        assert!(matches!(
            finalize_trampoline_gates_with_x18(&mut trampoline, 96, 12),
            Err(Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        assert!(matches!(
            finalize_trampoline_gates_with_x18(&mut trampoline, 96, 96),
            Err(Error::TrampolinePatchFailure(_))
        ));
        assert_eq!(trampoline, before);

        finalize_trampoline_gates_with_x18(&mut trampoline, 96, 104).unwrap();
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

        assert!(finalize_trampoline_gates_with_x18(&mut trampoline, 96, 12).is_err());
        assert_eq!(trampoline, before);
    }

    #[test]
    fn combined_finalizer_requires_adjacent_guest_slots() {
        let (_, outcome) =
            hook_words_opt_with_config(&[0xaa00_03f2], 0x1000, 0x400000, x18_config(Host::Linux));
        let mut trampoline = outcome.unwrap().trampoline;
        let before = trampoline.clone();

        assert!(finalize_trampoline_gates_with_x18(&mut trampoline, 96, 112).is_err());
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
        let transformed = GATES_START_OFFSET + X18GateOffset::Transform.as_usize();
        let before = word_at(&trampoline, transformed);

        finalize_trampoline_gates_with_x18(&mut trampoline, 96, 104).unwrap();

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
            matches!(error, Error::TrampolinePatchFailure(reason) if reason.contains("finalize_trampoline_gates_with_x18"))
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
        };
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
        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(
            outcome.trampoline.len(),
            GATES_START_OFFSET + MSR_GATE_SIZE + MRS_GATE_SIZE
        );
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
        // Linux dispatches every `SVC64` exception to the syscall handler
        // regardless of the immediate (the syscall number comes from x8), so
        // `svc #imm` with imm != 0 must be rewritten too. imm16 occupies bits
        // [20:5], so `svc #1` is `SVC_0 | (1 << 5)`.
        let svc_imm1 = SVC_0 | (1 << 5);
        let (patched, tramp) = hook_words(&[svc_imm1], 0x1000, 0x200000);
        // The SVC word became a `B` into the gate.
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
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

    // --- Load-time guest thread-pointer offset patching ---

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
        let (_p, mut tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
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
        let mut tramp = hook_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
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
        let (_p, mut tramp) = hook_words(
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
            classify_copied_gate_slot(&trampoline[16..32], base + 16, base + 16),
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
        assert_eq!(word(GateMetadata::MsrTpidr { source: 9 }), 0x0921b807);
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
        for kind in 6..16 {
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
                },
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
        for kind in 6..16 {
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
            for offset in (0..executable_end).step_by(INSN_BYTES) {
                assert_eq!(
                    classify_gate_pc(&trampoline, base, base + (start + offset) as u64),
                    Some(ClassifiedGate {
                        slot_offset: start,
                        slot_size: u8::try_from(size).unwrap(),
                        anchor_scratch: 0,
                        original_site: 0x1000
                            + match metadata {
                                GateMetadata::MrsTpidr { .. } => 0,
                                GateMetadata::MsrTpidr { .. } => 4,
                                GateMetadata::Svc => 8,
                                GateMetadata::X18 { .. }
                                | GateMetadata::X18CompareBranch { .. }
                                | GateMetadata::X18Adr { .. } => unreachable!(),
                            },
                        conditional_target: 0,
                        metadata,
                    })
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
            0x3500_0332, // cbnz w18, +0x64
            0x1000_0072, // adr x18, +0xc
        ];
        let base = 0x400000;
        let (_patched, outcome) =
            hook_words_opt_with_config(&words, 0x1000, base, x18_config(Host::Linux));
        let trampoline = outcome.unwrap().trampoline;

        for (index, (start, size)) in [
            (16usize, X18_SLOT_BYTES),
            (16 + X18_SLOT_BYTES, X18_COMPARE_BRANCH_SLOT_BYTES),
            (
                16 + X18_SLOT_BYTES + X18_COMPARE_BRANCH_SLOT_BYTES,
                X18_ADR_SLOT_BYTES,
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
                1 => matches!(metadata, GateMetadata::X18CompareBranch { .. }),
                2 => matches!(metadata, GateMetadata::X18Adr { .. }),
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
                let classified = classify_copied_gate_slot(
                    slot,
                    base + start as u64,
                    base + (start + offset) as u64,
                )
                .expect("emitted slot must classify");
                assert_eq!(classified.slot_offset(), 0);
                assert_eq!(classified.slot_size(), u8::try_from(size).unwrap());
                assert_eq!(classified.metadata(), metadata);
            }
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
