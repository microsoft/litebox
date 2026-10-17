// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 trampoline definitions shared by the rewriter and runtimes.
//!
//! Emission, byte validation, TLS finalization and recovery classification use
//! the same instruction templates. This module does not parse binary files or
//! discover patch sites in executable images.

pub mod gate;
pub mod recovery;
use crate::{Error, Result, TargetHost};
use alloc::format;
use alloc::vec::Vec;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction as DecodedInstruction, Opcode as DecodedOpcode, Operand,
};

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
    /// Reachable only if a runtime invariant was violated.
    Invalid,
}

/// `SVC #0` (supervisor call) — the canonical syscall instruction.
pub const SVC_0: u32 = 0xD400_0001;

/// `SVC #0x80`, used by Darwin syscall stubs.
pub const DARWIN_SVC: u32 = 0xD400_1001;

/// Mask/match for *any* `SVC #imm16`. Linux dispatches every `SVC64` exception
/// to the syscall handler regardless of the immediate (the syscall number comes
/// from `x8`), so all immediates are rewritten, not just `svc #0`. The `imm16`
/// field occupies bits \[20:5]; masking it out leaves bits \[4:0] = `0b00001`,
/// which distinguishes `SVC` from `HVC` (`…0b10`) and `SMC` (`…0b11`).
pub const SVC_OPCODE_MASK: u32 = 0xFFE0_001F;

pub const SVC_OPCODE_BITS: u32 = SVC_0;

/// Mask/match for `MSR TPIDR_EL0, Xt` (`0xD51BD04t`, the low 5 bits select Xt).
pub const MSR_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;

pub const MSR_TPIDR_EL0_BITS: u32 = 0xD51B_D040;

/// Mask/match for `MRS Xd, TPIDR_EL0` (`0xD53BD04d`, the low 5 bits select Xd).
pub const MRS_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;

pub const MRS_TPIDR_EL0_BITS: u32 = 0xD53B_D040;

/// `BRK` immediate planted at a patch site whose gate is out of `B` reach.
/// Executing it raises a synchronous debug exception (`SIGTRAP`) carrying this
/// immediate instead of letting the unpatched instruction escape to the host
/// kernel.
///
/// TODO: recognize this immediate in the runtime, to tell a rewriter trap from
/// a guest breakpoint.
pub const TRAP_BRK_IMM: u16 = 0xB10B;

/// `BRK` immediate used by the transparent `BR X18` trap gate.
const X18_BRANCH_BRK_IMM: u16 = 0xB18;

/// Alignment every emitted gate slot starts on.
pub const GATE_ALIGNMENT: usize = 16;

/// Byte size of a direct-TLS `MRS TPIDR_EL0` gate slot.
pub const MRS_SLOT_BYTES: usize = 16;

/// Byte size of a host-aware Darwin shared-cache TPIDRRO gate.
pub const HOST_AWARE_MRS_SLOT_BYTES: usize = 64;

/// Offset of the runtime's guest-mode word from its guest-TP field.
pub const IN_GUEST_OFFSET_FROM_GUEST_TP: u16 = 32;

/// Byte size of a direct-TLS `MSR TPIDR_EL0` gate slot.
pub const MSR_SLOT_BYTES: usize = 48;

/// Byte size of an emitted `SVC` gate slot.
pub const SVC_SLOT_BYTES: usize = 64;

/// Byte size of a direct-TLS ordinary x18 gate slot.
pub const X18_SLOT_BYTES: usize = 48;

/// Byte size of a direct-TLS x18 compare/test-branch gate slot.
pub const X18_COMPARE_BRANCH_SLOT_BYTES: usize = 48;

/// Byte size of a direct-TLS `ADR X18` gate slot.
pub const X18_ADR_SLOT_BYTES: usize = 32;

/// Byte size of a direct-TLS immediate SP-writeback pair x18 gate slot.
pub const X18_STACK_WRITEBACK_SLOT_BYTES: usize = 64;

/// Byte size of a terminal `BR X18` trap gate slot.
pub const X18_BRANCH_SLOT_BYTES: usize = 16;

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

pub const NOP: u32 = 0xD503_201F;

const GATE_METADATA_MAGIC: u32 = 0xB807;

const GATE_METADATA_VERSION: u32 = 1;

const GATE_METADATA_MAGIC_MASK: u32 = 0xffff;

const GATE_METADATA_VERSION_SHIFT: u32 = 16;

const GATE_METADATA_VERSION_MASK: u32 = 0xf << GATE_METADATA_VERSION_SHIFT;

const GATE_METADATA_KIND_SHIFT: u32 = 20;

const GATE_METADATA_KIND_MASK: u32 = 0xf << GATE_METADATA_KIND_SHIFT;

pub const GATE_METADATA_REGISTER_SHIFT: u32 = 24;

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
}

impl GateKind {
    pub const fn bits(self) -> u32 {
        self as u32
    }

    pub fn from_bits(bits: u32) -> Option<Self> {
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
    /// Read the logical guest thread pointer into the destination register.
    MrsTpidr {
        /// Register the guest thread pointer is read into.
        destination: u8,
    },
    /// Read TPIDRRO from the physical host or private guest state according to
    /// the current LiteBox execution mode.
    HostAwareMrsTpidr { destination: u8 },
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
pub struct EncodedGateMetadata(pub u32);

impl EncodedGateMetadata {
    pub fn encode(metadata: GateMetadata) -> Option<Self> {
        if matches!(
            metadata,
            GateMetadata::MrsTpidr { destination: XZR }
                | GateMetadata::HostAwareMrsTpidr { destination: XZR }
        ) {
            return None;
        }
        let (kind, register) = match metadata {
            GateMetadata::Svc => (GateKind::Svc, 0),
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

    pub fn decode(self) -> Option<GateMetadata> {
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

/// First scratch register (IP0).
pub const X16: u8 = 16;

const X8: u8 = 8;

/// Second scratch register (IP1).
pub const X17: u8 = 17;

/// Stack pointer (encoded as register 31 in a base-register field).
pub const SP: u8 = 31;

/// Zero register (register 31 in a transfer-register field, where it reads as
/// zero / discards writes — distinct from `SP`'s base-register meaning).
pub const XZR: u8 = 31;

pub const X18: u16 = 18;

const X18_ENCODED: u8 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X18Classification {
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
pub enum X18TransformResult {
    Supported(X18Substitution),
    Unsupported(X18Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X18Substitution {
    pub word: u32,
    pub scratch: u8,
    pub anchor_scratch: u8,
    pub pc_relative: Option<X18PcRelative>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X18StackWriteback {
    pub word: u32,
    pub scratch: u8,
    pub anchor_scratch: u8,
    pub layout: X18StackWritebackLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X18StackWritebackLayout {
    pub rt: u8,
    pub rt2: u8,
    pub delta: i16,
    pub element_bytes: u16,
    pub frame_bytes: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X18PcRelative {
    Adr(u64),
    Adrp(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X18CompareBranch {
    pub target: u64,
    pub scratch: u8,
    pub anchor_scratch: u8,
    pub kind: X18BranchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X18BranchKind {
    CbzW,
    CbzX,
    CbnzW,
    CbnzX,
    Tbz(u8),
    Tbnz(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X18Adr {
    pub target: u64,
    pub scratch: u8,
    pub anchor_scratch: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X18Unsupported {
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

pub fn classify_x18_stack_writeback(word: u32) -> Option<X18StackWriteback> {
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
pub enum ExclusiveBoundary {
    Load,
    Store,
}

pub fn exclusive_boundary(word: u32) -> Option<ExclusiveBoundary> {
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

pub fn classify_x18(word: u32) -> X18Classification {
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

pub fn classify_x18_conditional_branch(word: u32, vaddr: u64) -> Option<X18CompareBranch> {
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

pub fn classify_pc_relative_x18(word: u32, vaddr: u64) -> Option<X18Substitution> {
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

pub fn classify_adr_x18(word: u32, vaddr: u64) -> Option<X18Adr> {
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

const _: () = assert!(GUEST_X18_OFFSET_FROM_GUEST_TP == GUEST_TPIDR_OFFSET_ALIGN as usize);

/// Largest anchor-relative guest TLS root offset encodable by the gates.
pub const MAX_GUEST_TPIDR_OFFSET: u16 = LDR_UIMM12_MAX_BYTE_OFFSET;

/// The smallest guest-TLS root offset a gate may be patched with.
///
/// Rejects zero and the first anchor-relative slot; the runtime separately
/// validates ownership of its selected slot.
pub const MIN_GUEST_TPIDR_OFFSET: u16 = 16;

/// Placeholder for the runtime-supplied guest TLS offset.
///
/// It is `MAX_GUEST_TPIDR_OFFSET`, the largest value the field can hold, so it
/// cannot collide with a real runtime offset. That makes scanning for it exact,
/// which is what lets [`finalize_trampoline_gates`] and
/// [`find_guest_tpidr_placeholder`] work off the emitted words alone with no
/// side table of patch sites.
///
/// It buys **no** run-time safety: an unpatched gate accesses arbitrary
/// anchor-relative memory. A loader must use [`finalize_trampoline_gates`]
/// (Linux without x18) or [`finalize_trampoline_gates_for_host`] before making
/// a trampoline executable.
pub const GUEST_TPIDR_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;

/// Distinct placeholder used by direct-TLS x18 gates.
const GUEST_X18_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET - 8;

/// Stack frame used by x18 gates to preserve their two scratch registers.
pub const X18_FRAME_BYTES: u16 = 16;

/// SVC gate frame size (`SUB/ADD SP, SP, #SVC_FRAME_BYTES`). 16-byte aligned.
///
/// ABI: guest resume sets `SP` to `guest_sp - SVC_FRAME_BYTES` before
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
pub const SVC_OUTBOUND_STUB_BYTES: usize = 3 * 4;

/// MSR gate frame size (`SUB/ADD SP, SP, #MSR_FRAME_BYTES`). 16-byte aligned.
pub const MSR_FRAME_BYTES: u16 = 32;

/// Captured guest thread-pointer value, staged while all guest registers are
/// still pristine.
pub const MSR_FRAME_OFF_VALUE: u16 = 16;

/// Callback address slot.
const HEADER_CALLBACK_OFFSET: usize = 0;

/// First byte past the 8-byte callback slot.
pub const FIRST_SCANNABLE_OFFSET: usize = HEADER_CALLBACK_OFFSET + 8;

/// First byte of the per-site gates; the callback header is padded with NOPs to
/// the 16-byte slot alignment.
pub const GATES_START_OFFSET: usize = GATE_ALIGNMENT;

/// 26-bit `imm26` branch-offset field (`B`/`BL`), bits \[25:0].
pub const IMM26_MASK: u32 = 0x03FF_FFFF;

pub const OPCODE_TOP6_MASK: u32 = 0xFC00_0000;

/// 19-bit `imm19` offset field (`B.cond`/`LDR`-literal/`ADRP` immhi), bits \[18:0].
const IMM19_MASK: u32 = 0x0007_FFFF;

/// A PC-relative immediate counts instructions, so it scales by this many bits
/// to reach a byte displacement.
const INSN_BYTES_LOG2: u32 = 2;

/// Bytes in one AArch64 instruction. Every patch site, gate slot and scan
/// stride is a whole number of these.
pub const INSN_BYTES: usize = 1 << INSN_BYTES_LOG2;

/// [`INSN_BYTES`] where a virtual address is being measured.
pub const INSN_BYTES_U64: u64 = 1 << INSN_BYTES_LOG2;

/// The metadata word closing every compact gate slot.
pub const GATE_METADATA_BYTES: usize = 4;

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
pub const REG_MASK: u32 = 0x1F;

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
pub enum Opcode {
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
    pub const fn bits(self) -> u32 {
        self as u32
    }
}

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
pub enum Insn {
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
    pub fn encode(self) -> Option<u32> {
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

/// Runner-selected TLS and SVC stack-frame layout.
#[derive(Clone, Copy)]
pub struct GateLayout {
    host: TargetHost,
    svc_frame_bytes: u16,
}

impl GateLayout {
    pub const fn linux(host: TargetHost) -> Self {
        Self {
            host,
            svc_frame_bytes: SVC_FRAME_BYTES,
        }
    }

    pub const fn darwin(host: TargetHost) -> Self {
        Self {
            host,
            svc_frame_bytes: DARWIN_SVC_FRAME_BYTES,
        }
    }
}

/// Bits occupied by Darwin's CPU-number tag in `TPIDRRO_EL0`.
const DARWIN_TPIDRRO_CPU_TAG_MASK: u64 = 0b111;

pub fn anchor_mask(rd: u8) -> Insn {
    Insn::AndImm {
        rd,
        rn: rd,
        imm: !DARWIN_TPIDRRO_CPU_TAG_MASK,
    }
}

impl TargetHost {
    /// The instruction a gate uses to read this host's per-thread anchor into
    /// `rd`.
    pub fn anchor_read(self, rd: u8) -> Insn {
        match self {
            TargetHost::Linux => Insn::MrsTpidrEl0(rd),
            TargetHost::MacOs => Insn::MrsTpidrroEl0(rd),
            TargetHost::Windows => Insn::MovReg { rd, rs: 18 },
        }
    }
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

/// Emit the callback header and deterministic alignment padding.
pub fn emit_shared_prologue(trampoline_data: &mut Vec<u8>, callback: u64) {
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
            GateMetadata::Svc => SVC_SLOT_BYTES,
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
    pub const fn slot_size_for_host(self, host: TargetHost) -> usize {
        if !matches!(host, TargetHost::MacOs) {
            return self.slot_size();
        }
        match self {
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

    /// Byte offset in the buffer used for classification.
    ///
    /// [`classify_gate_pc`] returns a trampoline-relative offset. Copied-slot
    /// classification ([`classify_copied_gate_slot_for_host`] or the explicit-layout
    /// [`classify_copied_gate_slot_with_layout`]) returns zero, not the
    /// slot's actual trampoline offset. The caller must retain that slot's
    /// runtime address separately; this result does not store it.
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

pub fn classify_gate_pc_with_candidates<const N: usize>(
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
                GateLayout::linux(TargetHost::Linux),
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
///
/// The result's [`ClassifiedGate::slot_offset`] is zero, relative to the supplied
/// slot slice rather than its containing trampoline. The caller must retain
/// `slot_vaddr` separately.
pub fn classify_copied_gate_slot_for_host(
    slot: &[u8],
    slot_vaddr: u64,
    pc: u64,
    host: crate::TargetHost,
) -> Option<ClassifiedGate> {
    classify_copied_gate_slot_with_layout(slot, slot_vaddr, pc, GateLayout::linux(host))
}

pub fn classify_copied_gate_slot_with_layout(
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
    let trampoline_base = if metadata == GateMetadata::Svc {
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

pub fn valid_emitted_tpidr_offset(offset: u32) -> bool {
    u16::try_from(offset).is_ok_and(|offset| {
        offset == GUEST_TPIDR_OFFSET_PLACEHOLDER || is_patchable_guest_tpidr_offset(offset)
    })
}

fn valid_emitted_x18_offset(offset: u32) -> bool {
    u16::try_from(offset).is_ok_and(|offset| {
        offset == GUEST_X18_OFFSET_PLACEHOLDER || is_patchable_guest_x18_offset(offset)
    })
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

pub fn decode_adrp_add_target_for(adrp: u32, add: u32, pc: u64, register: u8) -> Option<u64> {
    let page = decode_adrp_target(adrp, pc, register)?;
    if add & ADD_IMM_SHAPE_MASK
        != Opcode::AddImm.bits() | (u32::from(register) << RN_SHIFT) | u32::from(register)
    {
        return None;
    }
    page.checked_add(u64::from(add >> RT2_SHIFT) & PAGE_OFFSET_MASK)
}

pub fn decode_adrp_target(adrp: u32, pc: u64, rd: u8) -> Option<u64> {
    if adrp & ADRP_SHAPE_MASK != Opcode::Adrp.bits() | u32::from(rd) {
        return None;
    }
    let immlo = i64::from((adrp >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
    let immhi = i64::from((adrp >> RN_SHIFT) & IMM19_MASK);
    let imm21 = (immhi << 2) | immlo;
    let page_delta = sign_extend(imm21, IMM21_BITS) << ADRP_PAGE_SHIFT;
    (pc & !PAGE_OFFSET_MASK).checked_add_signed(page_delta)
}

/// The scaled 12-bit immediate field of an unsigned-offset load/store, \[21:10].
pub const LDST_UIMM12_IMM_MASK: u32 = 0x003F_FC00;

/// Bit position of that immediate field.
pub const LDST_UIMM12_IMM_SHIFT: u32 = 10;

/// Validates and patches every thread-pointer gate in a Linux-host trampoline.
/// Trampolines containing x18 gates must use
/// [`finalize_trampoline_gates_for_host`].
///
/// Returns the number of instructions patched. Zero is normal for a trampoline
/// containing only SVC gates. Call this before making the trampoline executable.
///
/// # Errors
///
/// Rejects invalid offsets, malformed slots, unexpected field values, and x18
/// gates before mutating the trampoline.
pub fn finalize_trampoline_gates(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    validate_guest_offset(offset, false)?;
    let validation = validate_trampoline_offsets_with_layout(
        trampoline,
        offset,
        false,
        GateLayout::linux(TargetHost::Linux),
    )?;
    if validation.has_x18_gate {
        return Err(Error::TrampolinePatchFailure(
            "AArch64 trampoline contains x18 gates or placeholders; use \
             finalize_trampoline_gates_for_host"
                .into(),
        ));
    }
    patch_offset_words(trampoline, &validation.patch_offsets, offset);
    Ok(validation.patch_offsets.len())
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
    let tp = validate_trampoline_offsets_with_layout(
        trampoline,
        guest_tpidr_offset,
        false,
        GateLayout::linux(host),
    )?;
    validate_guest_offset(guest_x18_offset, true)?;
    // Indirect-TLS gates patch the root pointer load; field offsets are fixed.
    let x18_patch_value = if host == TargetHost::MacOs {
        guest_tpidr_offset
    } else {
        guest_x18_offset
    };
    let x18 = validate_trampoline_offsets_with_layout(
        trampoline,
        x18_patch_value,
        true,
        GateLayout::linux(host),
    )?;
    // Both sets are validated before mutation, so an error cannot leave a partial patch.
    patch_offset_words(trampoline, &tp.patch_offsets, guest_tpidr_offset);
    patch_offset_words(trampoline, &x18.patch_offsets, x18_patch_value);
    Ok(())
}

pub fn finalize_macho_trampoline(
    trampoline: &mut [u8],
    offset: u16,
    host: crate::TargetHost,
) -> Result<()> {
    validate_guest_offset(offset, false)?;
    let validation = validate_trampoline_offsets_with_layout(
        trampoline,
        offset,
        false,
        GateLayout::darwin(host),
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

fn patch_offset_words(trampoline: &mut [u8], patch_offsets: &[usize], offset: u16) {
    let new_imm = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
    for offset in patch_offsets {
        let word = &mut trampoline[*offset..*offset + INSN_BYTES];
        let insn = u32::from_le_bytes(word.try_into().expect("four-byte patch offset"));
        word.copy_from_slice(&((insn & !LDST_UIMM12_IMM_MASK) | new_imm).to_le_bytes());
    }
}

struct TrampolineValidation {
    pub patch_offsets: Vec<usize>,
    pub has_x18_gate: bool,
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
                if gate_offset == u32::from(field.placeholder()) {
                    patch_offsets.push(offset);
                } else if gate_offset != u32::from(expected_offset) {
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
pub fn find_guest_x18_placeholder(trampoline: &[u8]) -> Option<usize> {
    find_structured_placeholder(trampoline, true)
}

fn find_structured_placeholder(trampoline: &[u8], x18: bool) -> Option<usize> {
    let validation = validate_trampoline_offsets_with_layout(
        trampoline,
        if x18 {
            GUEST_X18_OFFSET_PLACEHOLDER
        } else {
            GUEST_TPIDR_OFFSET_PLACEHOLDER
        },
        x18,
        GateLayout::linux(TargetHost::Linux),
    )
    .ok()?;
    validation.patch_offsets.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn decoder_fallback_does_not_treat_mov_immediate_as_x18() {
        assert_eq!(classify_x18(0x5280_0028), X18Classification::None); // mov w8, #1
    }
    #[test]
    fn emitted_tls_offsets_accept_runtime_values_and_placeholders() {
        for offset in 0..=u16::MAX {
            let aligned = offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN);
            let tp = aligned
                && (MIN_GUEST_TPIDR_OFFSET..GUEST_TPIDR_OFFSET_PLACEHOLDER).contains(&offset);
            let x18 =
                aligned && (MIN_GUEST_TPIDR_OFFSET..GUEST_X18_OFFSET_PLACEHOLDER).contains(&offset);
            assert_eq!(is_patchable_guest_tpidr_offset(offset), tp);
            assert_eq!(is_patchable_guest_x18_offset(offset), x18);
            assert_eq!(
                valid_emitted_tpidr_offset(u32::from(offset)),
                tp || offset == GUEST_TPIDR_OFFSET_PLACEHOLDER
            );
            assert_eq!(
                valid_emitted_x18_offset(u32::from(offset)),
                x18 || offset == GUEST_X18_OFFSET_PLACEHOLDER
            );
        }
        // Values wider than u16 must not wrap into a valid offset.
        for offset in [0x1_0000, 0x1_0010, 0x1_7ff0, u32::MAX] {
            assert!(!valid_emitted_tpidr_offset(offset));
            assert!(!valid_emitted_x18_offset(offset));
        }
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
        // that `finalize_trampoline_gates` overwrites at load time; pin both the
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
    /// An offset a real host runtime might measure: not the placeholder.
    const MEASURED_OFFSET: u16 = 96;
    #[test]
    fn patch_rejects_a_blob_that_is_not_a_trampoline() {
        // Shorter than the shared prologue.
        let mut short = vec![0u8; GATES_START_OFFSET - 4];
        assert!(matches!(
            finalize_trampoline_gates(&mut short, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));

        // Not a whole number of instructions.
        let mut ragged = vec![0u8; GATES_START_OFFSET + 2];
        assert!(matches!(
            finalize_trampoline_gates(&mut ragged, MEASURED_OFFSET),
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
            finalize_trampoline_gates(&mut foreign, MEASURED_OFFSET),
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
        for kind in 9..16 {
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
            let (linux_words, linux_stages) = stages(TargetHost::Linux);
            let (_, macos_stages) = stages(TargetHost::MacOs);
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
        for kind in 9..16 {
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
}
