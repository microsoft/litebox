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
//! * Supported integer x18/w18 operands, when explicitly enabled. Their gates
//!   share setup records by ordered scratch pair; unsupported or unreachable
//!   forms are replaced with `BRK` and reported as trapped.
//!
//! ### Code ranges
//!
//! AOT rewriting scans normalized code ranges identified from executable ELF
//! sections and function symbols. AArch64 `$x`/`$d` mapping symbols split
//! executable sections so marked inline data is not decoded as instructions.
//! Runtime rewriting still scans the exact executable mapping supplied by its
//! caller, which can contain data and needs a separate code-boundary solution.
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
//! **A loader must pass staged gates through [`finalize_trampoline_gates`],
//! which patches the offset and proves no placeholder survives, before mapping
//! the trampoline executable** — an unpatched gate does not fault. See
//! `GUEST_TPIDR_OFFSET_PLACEHOLDER`.
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
//! The gates' extra memory accesses clear the local exclusive monitor, so a
//! gated instruction between `LDXR` and `STXR` would livelock. No real codegen
//! emits that.
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
//! A callback address slot, shared x18 setup records in surviving first-use pair
//! order, then gate-aligned per-site slots each ending in a metadata word;
//! `HEADER_CALLBACK_OFFSET`, `GATES_START_OFFSET` and the `*_SLOT_BYTES`
//! constants define the offsets and sizes.
//! [`crate::hook_syscalls_in_elf`] writes zero into the callback slot when its
//! caller supplies no address, leaving the loader to fill it in before the
//! trampoline is executable. A binary with no patch sites gets no trampoline,
//! only a size-0 sentinel header, matching the x86-64 path.
//!
//! `rt_sigreturn` needs no gate: the runtime installs its own trampoline
//! address into the signal frame, and an absolute address is reachable
//! regardless of branch range.

use alloc::format;
use alloc::vec::Vec;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    DecodeError, InstDecoder, Instruction as DecodedInstruction, Opcode as DecodedOpcode, Operand,
};

use crate::{Error, Result, TextSectionInfo, checked_add_u64};

/// Platform ABI state required to install and execute AArch64 x18 gates.
pub trait Aarch64GatePlatform {
    /// Whether this platform build virtualizes guest x18.
    const VIRTUALIZE_X18: bool;

    /// Returns the host-thread-pointer-relative guest x18 value-slot offset.
    fn guest_x18_offset(&self) -> Option<usize>;

    /// Returns the host-thread-pointer-relative anchor and value scratch offsets.
    fn x18_scratch_offsets(&self) -> Option<(usize, usize)>;
}

#[cfg(not(target_arch = "aarch64"))]
impl<T> Aarch64GatePlatform for T {
    const VIRTUALIZE_X18: bool = false;

    fn guest_x18_offset(&self) -> Option<usize> {
        None
    }

    fn x18_scratch_offsets(&self) -> Option<(usize, usize)> {
        None
    }
}

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
/// Byte size of one shared x18 setup record, including pair metadata.
pub const X18_SETUP_BYTES: usize = 32;
/// Byte size of one per-site x18 gate slot.
pub const X18_SLOT_BYTES: usize = 64;
/// Byte size of one per-site x18 CBZ/CBNZ gate slot.
pub const X18_CONDITIONAL_SLOT_BYTES: usize = 80;
/// Byte size of one terminal `BR X18` emulation slot.
pub const X18_BR_SLOT_BYTES: usize = 16;
/// First byte past the executable instructions in an x18 site slot.
pub const X18_GATE_BYTES: usize = 48;
const NOP: u32 = 0xD503_201F;
const X18_BR_BRK_IMM: u16 = 0xB18;

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
    X18Conditional = 4,
    X18Br = 5,
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
            Self::X18Conditional,
            Self::X18Br,
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
    /// A trapped integer x18/w18 use and the two registers its gate borrows.
    ///
    /// The persisted six-bit payload indexes one of 55 ordered pairs from
    /// `x17..=x7`: values descend first, then anchors descend below each value
    /// (`(x17,x16)` is index 0 and `(x8,x7)` is index 54). Restricting the
    /// scratches to this stable set keeps the existing one-word format and
    /// leaves indices 55..=63 reserved.
    X18 {
        /// Register used to hold the host per-thread anchor.
        anchor_scratch: u8,
        /// Register used to hold the virtualized x18 value.
        value_scratch: u8,
    },
    /// A typed CBZ/CBNZ x18/w18 gate using the same scratch-pair payload.
    X18Conditional {
        anchor_scratch: u8,
        value_scratch: u8,
    },
    /// A terminal indirect `BR X18`, emulated by the signal path.
    X18Br,
}

const X18_SCRATCH_PAIRS: [(u8, u8); 55] = {
    let mut pairs = [(0, 0); 55];
    let mut index = 0;
    let mut value = 17;
    while value >= 8 {
        let mut anchor = value - 1;
        while anchor >= 7 {
            pairs[index] = (anchor, value);
            index += 1;
            if anchor == 7 {
                break;
            }
            anchor -= 1;
        }
        value -= 1;
    }
    pairs
};

fn encode_x18_scratch_pair(anchor_scratch: u8, value_scratch: u8) -> Option<u8> {
    X18_SCRATCH_PAIRS
        .iter()
        .position(|pair| *pair == (anchor_scratch, value_scratch))
        .and_then(|index| u8::try_from(index).ok())
}

fn decode_x18_scratch_pair(index: u8) -> Option<(u8, u8)> {
    X18_SCRATCH_PAIRS.get(usize::from(index)).copied()
}

#[repr(transparent)]
#[derive(Clone, Copy)]
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
            GateMetadata::X18 {
                anchor_scratch,
                value_scratch,
            } => (
                GateKind::X18,
                encode_x18_scratch_pair(anchor_scratch, value_scratch)?,
            ),
            GateMetadata::X18Conditional {
                anchor_scratch,
                value_scratch,
            } => (
                GateKind::X18Conditional,
                encode_x18_scratch_pair(anchor_scratch, value_scratch)?,
            ),
            GateMetadata::X18Br => (GateKind::X18Br, 0),
        };
        if !matches!(kind, GateKind::X18 | GateKind::X18Conditional) && register > MAX_REGISTER {
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
        if !matches!(kind, GateKind::X18 | GateKind::X18Conditional) && register > MAX_REGISTER {
            return None;
        }
        match kind {
            GateKind::Svc if register == 0 => Some(GateMetadata::Svc),
            GateKind::MrsTpidr if register != XZR => Some(GateMetadata::MrsTpidr {
                destination: register,
            }),
            GateKind::MsrTpidr => Some(GateMetadata::MsrTpidr { source: register }),
            GateKind::X18 => {
                let (anchor_scratch, value_scratch) = decode_x18_scratch_pair(register)?;
                Some(GateMetadata::X18 {
                    anchor_scratch,
                    value_scratch,
                })
            }
            GateKind::X18Conditional => {
                let (anchor_scratch, value_scratch) = decode_x18_scratch_pair(register)?;
                Some(GateMetadata::X18Conditional {
                    anchor_scratch,
                    value_scratch,
                })
            }
            GateKind::X18Br if register == 0 => Some(GateMetadata::X18Br),
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
/// prove no placeholder survives — see [`find_guest_tpidr_placeholder`] —
/// before making a trampoline executable.
pub const GUEST_TPIDR_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;

/// Placeholder for the virtualized x18 value slot.
pub const GUEST_X18_OFFSET_PLACEHOLDER: u16 = GUEST_TPIDR_OFFSET_PLACEHOLDER - 8;
/// Placeholder for the slot preserving the x18 gate's anchor scratch register.
pub const SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER: u16 = GUEST_X18_OFFSET_PLACEHOLDER - 8;
/// Placeholder for the slot preserving the x18 gate's value scratch register.
pub const SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER: u16 = SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER - 8;
/// Largest legitimate finalized x18 or scratch-storage offset. The three
/// aligned values above it are reserved by those exact x18 gate fields.
/// Guest TPIDR gates retain their independent historical range through 32752.
pub const MAX_REAL_X18_GATE_OFFSET: u16 = SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER - 8;

/// Anchor-relative runtime storage offsets used by AArch64 gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aarch64GateOffsets {
    guest_tpidr: u16,
    guest_x18: u16,
    saved_anchor_scratch: u16,
    saved_value_scratch: u16,
}

impl Aarch64GateOffsets {
    /// Constructs a non-aliasing set of encodable, finalized offsets.
    pub fn new(
        guest_tpidr: u16,
        guest_x18: u16,
        saved_anchor_scratch: u16,
        saved_value_scratch: u16,
    ) -> Result<Self> {
        let values = [
            guest_tpidr,
            guest_x18,
            saved_anchor_scratch,
            saved_value_scratch,
        ];
        if !is_patchable_guest_tpidr_offset(guest_tpidr)
            || [guest_x18, saved_anchor_scratch, saved_value_scratch]
                .iter()
                .any(|offset| {
                    !offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
                        || !(MIN_GUEST_TPIDR_OFFSET..=MAX_REAL_X18_GATE_OFFSET).contains(offset)
                })
            || values
                .iter()
                .enumerate()
                .any(|(index, offset)| values[..index].contains(offset))
        {
            return Err(Error::TrampolinePatchFailure(format!(
                "AArch64 gate offsets must be distinct and {GUEST_TPIDR_OFFSET_ALIGN}-byte aligned; \
                 guest TPIDR must be between {MIN_GUEST_TPIDR_OFFSET} and {}, while x18 and \
                 scratch offsets must be at most {MAX_REAL_X18_GATE_OFFSET}: {values:?}",
                GUEST_TPIDR_OFFSET_PLACEHOLDER - GUEST_TPIDR_OFFSET_ALIGN,
            )));
        }
        Ok(Self {
            guest_tpidr,
            guest_x18,
            saved_anchor_scratch,
            saved_value_scratch,
        })
    }

    /// Returns the guest `TPIDR_EL0` value-slot offset.
    pub const fn guest_tpidr(self) -> u16 {
        self.guest_tpidr
    }

    /// Returns the guest x18 value-slot offset.
    pub const fn guest_x18(self) -> u16 {
        self.guest_x18
    }

    /// Returns the saved anchor-scratch slot offset.
    pub const fn saved_anchor_scratch(self) -> u16 {
        self.saved_anchor_scratch
    }

    /// Returns the saved value-scratch slot offset.
    pub const fn saved_value_scratch(self) -> u16 {
        self.saved_value_scratch
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
const MSR_FRAME_OFF_VALUE: u16 = 16;

// --- Trampoline layout offsets (all in bytes) ---

/// Callback address slot.
const HEADER_CALLBACK_OFFSET: usize = 0;

/// First byte past the 8-byte callback slot, and so the first that can be read
/// as an instruction word. Scans start here: the slot holds an address, which
/// could bit-for-bit resemble any instruction they look for.
const FIRST_SCANNABLE_OFFSET: usize = HEADER_CALLBACK_OFFSET + 8;

/// First byte of the per-site gates; the callback header is padded with NOPs to
/// the 16-byte slot alignment. Everything from [`FIRST_SCANNABLE_OFFSET`] on is
/// instructions this module emitted, which is what lets
/// [`patch_guest_tpidr_offset`] scan for its patch sites instead of carrying a
/// side table of them.
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

fn checked_pcrel_difference(target: u64, pc: u64) -> Option<i64> {
    i64::try_from(i128::from(target) - i128::from(pc)).ok()
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
    Bl = 0x9400_0000,
    LdrLiteral = 0x5800_0000,
    Adr = 0x1000_0000,
    Adrp = 0x9000_0000,
    Br = 0xD61F_0000,
    Ret = 0xD65F_0000,
    Movz = 0xD280_0000,
    SubImm = 0xD100_0000,
    AddImm = 0x9100_0000,
    StrUimm = 0xF900_0000,
    LdrUimm = 0xF940_0000,
    Stp = 0xA900_0000,
    Ldp = 0xA940_0000,
    MrsTpidrEl0 = MRS_TPIDR_EL0_BITS,
    Brk = 0xD420_0000,
    CbzW = 0x3400_0000,
    CbnzW = 0x3500_0000,
    CbzX = 0xB400_0000,
    CbnzX = 0xB500_0000,
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
    /// `BL` (branch with link), PC-relative, ±128MB, 4-byte aligned.
    Bl(i64),
    /// `CBZ/CBNZ Wt|Xt`, PC-relative, ±1MB, 4-byte aligned.
    CompareBranch {
        rt: u8,
        offset: i64,
        nonzero: bool,
        width: X18Width,
    },
    /// `TBZ/TBNZ Wt|Xt, #bit`, PC-relative, +/-32KB, 4-byte aligned.
    TestBranch {
        rt: u8,
        offset: i64,
        nonzero: bool,
        bit: u8,
    },
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
    /// `RET Xn` (normally `RET X30`).
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
    /// `MRS Xt, TPIDR_EL0` (read thread pointer).
    MrsTpidrEl0(u8),
    /// `MRS Xt, TPIDRRO_EL0` (read-only thread pointer used by macOS).
    MrsTpidrroEl0(u8),
    /// `MOV Xd, Xs`, encoded as `ORR Xd, XZR, Xs`.
    MovReg {
        rd: u8,
        rs: u8,
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
            Insn::Bl(off) => branch_imm26(Opcode::Bl, off),
            Insn::CompareBranch {
                rt,
                offset,
                nonzero,
                width,
            } => pcrel_imm19(
                match (width, nonzero) {
                    (X18Width::W, false) => Opcode::CbzW,
                    (X18Width::W, true) => Opcode::CbnzW,
                    (X18Width::X, false) => Opcode::CbzX,
                    (X18Width::X, true) => Opcode::CbnzX,
                },
                offset,
                u32::from(rt),
            ),
            Insn::TestBranch {
                rt,
                offset,
                nonzero,
                bit,
            } => {
                if offset % 4 != 0 || bit >= 64 {
                    return None;
                }
                let imm14 = i32::try_from(offset >> 2).ok()?;
                if !(-(1 << 13)..(1 << 13)).contains(&imm14) {
                    return None;
                }
                Some(
                    0x3600_0000
                        | (u32::from(nonzero) << 24)
                        | (u32::from(bit & 0x20) << 26)
                        | (u32::from(bit & 0x1f) << 19)
                        | ((imm14.cast_unsigned() & 0x3fff) << 5)
                        | u32::from(rt),
                )
            }
            Insn::Adr { rd, byte_off } => pcrel_imm21(Opcode::Adr, rd, byte_off),
            Insn::Adrp { rd, page_off } => pcrel_imm21(Opcode::Adrp, rd, page_off),
            Insn::LdrLiteral { rt, off } => pcrel_imm19(Opcode::LdrLiteral, off, u32::from(rt)),
            Insn::Br(rn) => Some(Opcode::Br.bits() | (u32::from(rn) << RN_SHIFT)),
            Insn::Ret(rn) => Some(Opcode::Ret.bits() | (u32::from(rn) << RN_SHIFT)),
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
            Insn::MrsTpidrEl0(rt) => Some(Opcode::MrsTpidrEl0.bits() | u32::from(rt)),
            Insn::MrsTpidrroEl0(rt) => Some(0xD53B_D060 | u32::from(rt)),
            Insn::MovReg { rd, rs } => Some(0xAA00_03E0 | (u32::from(rs) << 16) | u32::from(rd)),
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
///
/// macOS anchors on `TPIDRRO_EL0`, while Windows copies its physical x18 TEB
/// pointer. Non-Linux TPIDR and SVC gates remain unsupported.
#[derive(Clone, Copy)]
pub(crate) enum Host {
    /// Linux host: the kernel preserves `TPIDR_EL0` across host execution, so
    /// the anchor lives there and the anchor read is `MRS Xd, TPIDR_EL0`.
    Linux,
    MacOs,
    Windows,
}

#[derive(Clone, Copy)]
pub(crate) struct RewriteConfig {
    host: Host,
    virtualize_x18: bool,
}

impl RewriteConfig {
    pub(crate) const fn new(host: Host, virtualize_x18: bool) -> Self {
        Self {
            host,
            virtualize_x18,
        }
    }

    #[cfg(test)]
    pub(crate) const fn virtualize_x18(self) -> bool {
        self.virtualize_x18
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

const fn host_for_target(target: crate::TargetHost) -> Host {
    match target {
        crate::TargetHost::Linux => Host::Linux,
        crate::TargetHost::MacOs => Host::MacOs,
        crate::TargetHost::Windows => Host::Windows,
    }
}

// ============================================================
// Patch-site scanning
// ============================================================

const X18: u16 = 18;

/// Returns whether an undecodable word could name x18/w18 in one of the four
/// common A64 GPR fields. Register 17 is also conservative because pair forms
/// can encode only the first register and implicitly access its successor.
///
/// This is only an escape filter for decoder failures. A successfully decoded
/// instruction is classified exclusively from its typed operands, and these
/// raw fields are never rewritten.
fn has_possible_x18_field(word: u32) -> bool {
    [0, 5, 10, 16]
        .into_iter()
        .any(|shift| (word >> shift) & REG_MASK == u32::from(X18))
        // Encodings with an implicit adjacent pair use Rt/Rs fields, not Rn/Rt2.
        || [0, 16]
            .into_iter()
            .any(|shift| (word >> shift) & REG_MASK == u32::from(X18 - 1))
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
enum X18DiscoveryError {
    Decode(DecodeError),
}

#[cfg(test)]
impl From<DecodeError> for X18DiscoveryError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

#[cfg(test)]
fn instruction_uses_x18(word: u32) -> core::result::Result<bool, X18DiscoveryError> {
    let bytes = word.to_le_bytes();
    let mut reader = U8Reader::new(&bytes);
    let instruction = InstDecoder::default().decode(&mut reader)?;
    for operand in &instruction.operands {
        if operand_uses_x18(operand) {
            return Ok(true);
        }
    }
    Ok(false)
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
        Operand::Nothing
        | Operand::SIMDRegister(_, _)
        | Operand::SIMDRegisterElements(_, _, _)
        | Operand::SIMDRegisterElementsLane(_, _, _, _)
        | Operand::SIMDRegisterElementsMultipleLane(_, _, _, _, _)
        | Operand::SIMDRegisterGroup(_, _, _, _)
        | Operand::SIMDRegisterGroupLane(_, _, _, _)
        | Operand::ConditionCode(_)
        | Operand::PCOffset(_)
        | Operand::Immediate(_)
        | Operand::Imm64(_)
        | Operand::Imm16(_)
        | Operand::ImmediateDouble(_)
        | Operand::ImmShift(_, _)
        | Operand::ImmShiftMSL(_, _)
        | Operand::PrefetchOp(_)
        | Operand::SystemReg(_)
        | Operand::ControlReg(_)
        | Operand::PstateField(_) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18Transformation {
    original_word: u32,
    word: u32,
    pcrel: Option<X18Pcrel>,
    value_scratch: u8,
    anchor_scratch: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18Pcrel {
    Adr(i64),
    Adrp(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18Width {
    W,
    X,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18ConditionalKind {
    Compare,
    Test { bit: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X18ConditionalBranch {
    original_word: u32,
    target: u64,
    nonzero: bool,
    width: X18Width,
    kind: X18ConditionalKind,
    value_scratch: u8,
    anchor_scratch: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18TransformResult {
    Supported(X18Transformation),
    Unsupported(X18TransformFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X18TransformFailure {
    PcRelativeOrControlFlow,
    InvalidTargetOverflow,
    ExclusiveOrAtomic,
    UnsupportedEncodingLayout,
    DecodeFailure,
}

fn decode_instruction(word: u32) -> core::result::Result<DecodedInstruction, DecodeError> {
    let bytes = word.to_le_bytes();
    let mut reader = U8Reader::new(&bytes);
    InstDecoder::default().decode(&mut reader)
}

fn collect_operand_gprs(operand: &Operand, present: &mut [bool; 32]) {
    let mut mark = |register: u16| {
        if let Ok(register) = u8::try_from(register)
            && register <= MAX_REGISTER
        {
            present[usize::from(register)] = true;
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
    // This is the persisted metadata scratch set; changing its order changes
    // metadata indices in rewritten binaries.
    const CANDIDATES: [u8; 11] = [X17, X16, 15, 14, 13, 12, 11, 10, 9, 8, 7];
    let mut present = [false; 32];
    present[usize::from(X18)] = true;
    present[usize::from(SP)] = true;
    for operand in &instruction.operands {
        collect_operand_gprs(operand, &mut present);
    }
    let mut candidates = CANDIDATES
        .into_iter()
        .filter(|register| !present[usize::from(*register)]);
    Some((candidates.next()?, candidates.next()?))
}

fn replace_register_field(word: &mut u32, shift: u32, replacement: u8) -> Option<()> {
    if (*word >> shift) & REG_MASK != u32::from(X18) {
        return None;
    }
    *word = (*word & !(REG_MASK << shift)) | (u32::from(replacement) << shift);
    Some(())
}

fn expected_rewritten_operand(operand: Operand, replacement: u16) -> Option<Operand> {
    let replace_x18 = |register| {
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
            Operand::RegRegOffset(replace_x18(base), replace_x18(index), size, style, amount)
        }
        Operand::RegPreIndex(X18, offset, writeback) => {
            Operand::RegPreIndex(replacement, offset, writeback)
        }
        Operand::RegPostIndex(X18, offset) => Operand::RegPostIndex(replacement, offset),
        Operand::RegPostIndexReg(base, index) => {
            Operand::RegPostIndexReg(replace_x18(base), replace_x18(index))
        }
        Operand::RegisterPair(_, first) if first == X18 || first.checked_add(1) == Some(X18) => {
            return None;
        }
        other => other,
    })
}

fn map_x18_operand_field(
    word: &mut u32,
    instruction: &DecodedInstruction,
    operand_index: usize,
    operand: &Operand,
    replacement: u8,
) -> Option<()> {
    match operand {
        Operand::Register(_, X18) | Operand::RegisterOrSP(_, X18) => {
            let shift = match (instruction.opcode, operand_index) {
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
                ) => 10,
                (DecodedOpcode::CCMP | DecodedOpcode::CCMN, 0) | (DecodedOpcode::EXTR, 1) => {
                    RN_SHIFT
                }
                (_, 0) if instruction.operands[1] != Operand::Nothing => 0,
                (_, 1) if matches!(instruction.opcode, DecodedOpcode::STP | DecodedOpcode::LDP) => {
                    RT2_SHIFT
                }
                (_, 1) => RN_SHIFT,
                _ => return None,
            };
            replace_register_field(word, shift, replacement)
        }
        Operand::RegShift(_, _, _, X18) => replace_register_field(word, 16, replacement),
        Operand::RegRegOffset(base, index, _, _, _) | Operand::RegPostIndexReg(base, index) => {
            if *base == X18 {
                replace_register_field(word, RN_SHIFT, replacement)?;
            }
            if *index == X18 {
                replace_register_field(word, 16, replacement)?;
            }
            Some(())
        }
        Operand::RegPreIndex(X18, _, _) | Operand::RegPostIndex(X18, _) => {
            replace_register_field(word, RN_SHIFT, replacement)
        }
        Operand::RegisterPair(_, first) if *first == X18 || first.checked_add(1) == Some(X18) => {
            None
        }
        _ => Some(()),
    }
}

fn is_control_flow_opcode(opcode: DecodedOpcode) -> bool {
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

fn is_exclusive_or_atomic_opcode(opcode: DecodedOpcode) -> bool {
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

fn transform_x18_instruction(word: u32) -> X18TransformResult {
    let Ok(instruction) = decode_instruction(word) else {
        return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
    };
    transform_decoded_x18_instruction(word, instruction)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcrelTarget {
    NotInstruction,
    Target { displacement: i64, address: u64 },
    InvalidTargetOverflow,
}

fn decode_adrp_target(word: u32, pc: u64, rd: u8) -> PcrelTarget {
    if word & ADRP_SHAPE_MASK != Opcode::Adrp.bits() | u32::from(rd) {
        return PcrelTarget::NotInstruction;
    }
    let immlo = i64::from((word >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
    let immhi = i64::from((word >> RN_SHIFT) & IMM19_MASK);
    let page_delta = sign_extend((immhi << 2) | immlo, IMM21_BITS) << ADRP_PAGE_SHIFT;
    match (pc & !PAGE_OFFSET_MASK).checked_add_signed(page_delta) {
        Some(address) => PcrelTarget::Target {
            displacement: page_delta,
            address,
        },
        None => PcrelTarget::InvalidTargetOverflow,
    }
}

fn decode_adr_target(word: u32, pc: u64, rd: u8) -> PcrelTarget {
    if word & ADRP_SHAPE_MASK != Opcode::Adr.bits() | u32::from(rd) {
        return PcrelTarget::NotInstruction;
    }
    let immlo = i64::from((word >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
    let immhi = i64::from((word >> RN_SHIFT) & IMM19_MASK);
    let displacement = sign_extend((immhi << 2) | immlo, IMM21_BITS);
    match pc.checked_add_signed(displacement) {
        Some(address) => PcrelTarget::Target {
            displacement,
            address,
        },
        None => PcrelTarget::InvalidTargetOverflow,
    }
}

fn transform_decoded_x18_instruction(
    word: u32,
    instruction: DecodedInstruction,
) -> X18TransformResult {
    if !instruction.operands.iter().any(operand_uses_x18) {
        return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
    }
    if instruction
        .operands
        .iter()
        .any(|operand| matches!(operand, Operand::PCOffset(_)))
        || is_control_flow_opcode(instruction.opcode)
    {
        return X18TransformResult::Unsupported(X18TransformFailure::PcRelativeOrControlFlow);
    }
    if is_exclusive_or_atomic_opcode(instruction.opcode) {
        return X18TransformResult::Unsupported(X18TransformFailure::ExclusiveOrAtomic);
    }
    let Some((value_scratch, anchor_scratch)) = select_x18_scratches(&instruction) else {
        return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
    };

    let mut transformed_word = word;
    let mut expected = instruction;
    for (index, operand) in instruction.operands.iter().enumerate() {
        if map_x18_operand_field(
            &mut transformed_word,
            &instruction,
            index,
            operand,
            value_scratch,
        )
        .is_none()
        {
            return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
        }
        let Some(expected_operand) = expected_rewritten_operand(*operand, u16::from(value_scratch))
        else {
            return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
        };
        expected.operands[index] = expected_operand;
    }

    let Ok(transformed) = decode_instruction(transformed_word) else {
        return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
    };
    if transformed != expected {
        return X18TransformResult::Unsupported(X18TransformFailure::UnsupportedEncodingLayout);
    }
    X18TransformResult::Supported(X18Transformation {
        original_word: word,
        word: transformed_word,
        pcrel: None,
        value_scratch,
        anchor_scratch,
    })
}

fn classify_decoded_x18_at(
    word: u32,
    instruction: DecodedInstruction,
    vaddr: u64,
) -> Option<PatchKind> {
    if instruction.opcode == DecodedOpcode::BR
        && instruction.operands
            == [
                Operand::Register(yaxpeax_arm::armv8::a64::SizeCode::X, X18),
                Operand::Nothing,
                Operand::Nothing,
                Operand::Nothing,
            ]
        && word == Insn::Br(18).encode().unwrap()
    {
        return Some(PatchKind::X18Br);
    }
    if matches!(instruction.opcode, DecodedOpcode::ADR | DecodedOpcode::ADRP)
        && let [
            Operand::Register(yaxpeax_arm::armv8::a64::SizeCode::X, X18),
            Operand::PCOffset(_),
            Operand::Nothing,
            Operand::Nothing,
        ] = instruction.operands
    {
        let (value_scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
        let decoded = if instruction.opcode == DecodedOpcode::ADR {
            decode_adr_target(word, vaddr, 18)
        } else {
            decode_adrp_target(word, vaddr, 18)
        };
        let displacement = match decoded {
            PcrelTarget::Target { displacement, .. } => displacement,
            PcrelTarget::InvalidTargetOverflow => {
                return Some(PatchKind::X18(X18TransformResult::Unsupported(
                    X18TransformFailure::InvalidTargetOverflow,
                )));
            }
            PcrelTarget::NotInstruction => return None,
        };
        return Some(PatchKind::X18(X18TransformResult::Supported(
            X18Transformation {
                original_word: word,
                word: word & !REG_MASK | u32::from(value_scratch),
                pcrel: Some(if instruction.opcode == DecodedOpcode::ADR {
                    X18Pcrel::Adr(displacement)
                } else {
                    X18Pcrel::Adrp(displacement)
                }),
                value_scratch,
                anchor_scratch,
            },
        )));
    }
    let conditional = match (instruction.opcode, instruction.operands) {
        (
            DecodedOpcode::CBZ | DecodedOpcode::CBNZ,
            [
                Operand::Register(width, X18),
                Operand::PCOffset(offset),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) => Some((width, offset, X18ConditionalKind::Compare)),
        (
            DecodedOpcode::TBZ | DecodedOpcode::TBNZ,
            [
                Operand::Register(width, X18),
                Operand::Imm16(bit),
                Operand::PCOffset(offset),
                Operand::Nothing,
            ],
        ) => u8::try_from(bit)
            .ok()
            .map(|bit| (width, offset, X18ConditionalKind::Test { bit })),
        _ => None,
    };
    if let Some((width, offset, kind)) = conditional
        && matches!(
            width,
            yaxpeax_arm::armv8::a64::SizeCode::W | yaxpeax_arm::armv8::a64::SizeCode::X
        )
    {
        let target = vaddr.checked_add_signed(offset)?;
        let (value_scratch, anchor_scratch) = select_x18_scratches(&instruction)?;
        return Some(PatchKind::X18Conditional(X18ConditionalBranch {
            original_word: word,
            target,
            nonzero: matches!(
                instruction.opcode,
                DecodedOpcode::CBNZ | DecodedOpcode::TBNZ
            ),
            width: if width == yaxpeax_arm::armv8::a64::SizeCode::W {
                X18Width::W
            } else {
                X18Width::X
            },
            kind,
            value_scratch,
            anchor_scratch,
        }));
    }
    instruction
        .operands
        .iter()
        .any(operand_uses_x18)
        .then(|| PatchKind::X18(transform_decoded_x18_instruction(word, instruction)))
}

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
    /// An integer x18/w18 use. A transformation is retained when the current
    /// structural rewriter supports it; `None` records an unsupported form.
    /// Supported forms emit x18 gates; unsupported forms remain trapped.
    X18(X18TransformResult),
    /// A typed CBZ/CBNZ or TBZ/TBNZ whose tested integer register is x18/w18.
    X18Conditional(X18ConditionalBranch),
    /// The one supported terminal indirect transfer: exact `BR X18`.
    X18Br,
}

/// Scan all executable sections for the configured patch-site set. Existing
/// `SVC` and TPIDR recognition takes precedence over semantic x18 discovery,
/// except that TPIDR forms whose register is x18 are x18 sites when x18 is
/// virtualized: their existing gates would access an unavailable physical x18.
/// AArch64 instructions are always 4-byte aligned, so we step in 4-byte units.
/// Returns sites in ascending file order.
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

        for i in (0..section_data.len()).step_by(INSN_BYTES) {
            if i + INSN_BYTES > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + INSN_BYTES].try_into().unwrap());
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                if !matches!(config.host, Host::Linux) {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 SVC site is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "SVC site")?
                    )));
                }
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                if !matches!(config.host, Host::Linux) {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 TPIDR_EL0 write site is unsupported for the selected host at {:#x}",
                        checked_add_u64(section.vaddr, i as u64, "TPIDR site")?
                    )));
                }
                let source = (insn & REG_MASK) as u8;
                if config.virtualize_x18 && u16::from(source) == X18 {
                    PatchKind::X18(X18TransformResult::Unsupported(
                        X18TransformFailure::UnsupportedEncodingLayout,
                    ))
                } else {
                    PatchKind::MsrTpidr(source)
                }
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                if !matches!(config.host, Host::Linux) {
                    return Err(Error::UnsupportedExecutable(format!(
                        "AArch64 TPIDR_EL0 read site is unsupported for the selected host at {:#x}",
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
                        X18TransformFailure::UnsupportedEncodingLayout,
                    ))
                } else {
                    PatchKind::MrsTpidr(rd)
                }
            } else if config.virtualize_x18 {
                match decode_instruction(insn) {
                    Ok(instruction) => match classify_decoded_x18_at(
                        insn,
                        instruction,
                        checked_add_u64(section.vaddr, i as u64, "x18 site")?,
                    ) {
                        Some(kind) => kind,
                        None => continue,
                    },
                    Err(_) if has_possible_x18_field(insn) => PatchKind::X18(
                        X18TransformResult::Unsupported(X18TransformFailure::DecodeFailure),
                    ),
                    Err(_) => continue,
                }
            } else {
                continue;
            };
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
    pub trapped_site_classes: [usize; 5],
    pub trapped_site_examples: [Option<u64>; 5],
    pub supported_x18_sites: usize,
}

pub(crate) const TRAP_CLASS_NAMES: [&str; 5] = [
    "PC-relative/control-flow",
    "exclusive/atomic",
    "unsupported encoding/layout",
    "decode failure",
    "branch reach",
];

fn trap_class(site: &PatchSite) -> usize {
    match site.kind {
        PatchKind::X18(X18TransformResult::Unsupported(
            X18TransformFailure::PcRelativeOrControlFlow
            | X18TransformFailure::InvalidTargetOverflow,
        )) => 0,
        PatchKind::X18(X18TransformResult::Unsupported(X18TransformFailure::ExclusiveOrAtomic)) => {
            1
        }
        PatchKind::X18(X18TransformResult::Unsupported(
            X18TransformFailure::UnsupportedEncodingLayout,
        )) => 2,
        PatchKind::X18(X18TransformResult::Unsupported(X18TransformFailure::DecodeFailure)) => 3,
        _ => 4,
    }
}

/// Hook all configured patch sites in an AArch64 ELF image. (`MRS XZR,
/// TPIDR_EL0` is a discarded read and is left native.)
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
    let host = config.host;
    if !trampoline_base_addr.is_multiple_of(GATE_ALIGNMENT as u64) {
        return Err(Error::AddressOverflow(format!(
            "AArch64 trampoline base {trampoline_base_addr:#x} is not {GATE_ALIGNMENT}-byte aligned"
        )));
    }
    let sites = find_patch_sites(text_sections, buf, config)?;
    let supported_x18_sites = sites
        .iter()
        .filter(|site| {
            matches!(
                site.kind,
                PatchKind::X18(X18TransformResult::Supported(_))
                    | PatchKind::X18Conditional(_)
                    | PatchKind::X18Br
            )
        })
        .count();

    if sites.is_empty() {
        // No patch sites: nothing to redirect, so no trampoline is
        // emitted. The caller writes a size-0 sentinel header instead.
        return Ok(None);
    }

    let plan = plan_x18_sites(&sites, trampoline_base_addr)?;
    let planned_x18_sites = plan.sites;

    let mut trampoline_data: Vec<u8> = Vec::new();
    emit_shared_prologue(&mut trampoline_data, callback);

    let x18_setups = collect_x18_setups(&sites, &planned_x18_sites);
    for &(anchor_scratch, value_scratch) in &x18_setups {
        emit_x18_setup(&mut trampoline_data, anchor_scratch, value_scratch, host)?;
    }

    let mut trapped_sites: Vec<u64> = Vec::new();
    let mut trapped_site_classes = [0usize; 5];
    let mut trapped_site_examples = [None; 5];

    for (site_index, site) in sites.iter().enumerate() {
        let (inbound, build) = emit_site_gate(
            &mut trampoline_data,
            trampoline_base_addr,
            site,
            host,
            &x18_setups,
            planned_x18_sites[site_index],
        )?;

        if let (Some(b_insn), GateBuild::Emitted) = (inbound, build) {
            // Replace the original instruction with `B <gate>`.
            buf[site.file_offset..site.file_offset + INSN_BYTES]
                .copy_from_slice(&b_insn.to_le_bytes());
        } else {
            trap_site(buf, site.file_offset);
            trapped_sites.push(site.vaddr);
            let class = trap_class(site);
            trapped_site_classes[class] += 1;
            trapped_site_examples[class].get_or_insert(site.vaddr);
        }
    }

    Ok(Some(HookOutcome {
        trampoline: trampoline_data,
        trapped_sites,
        trapped_site_classes,
        trapped_site_examples,
        supported_x18_sites,
    }))
}

fn collect_x18_setups(sites: &[PatchSite], planned_x18_sites: &[bool]) -> Vec<(u8, u8)> {
    let mut setups = Vec::new();
    for (site, planned) in sites.iter().zip(planned_x18_sites) {
        if *planned {
            let pair = match site.kind {
                PatchKind::X18(X18TransformResult::Supported(transformation)) => {
                    Some((transformation.anchor_scratch, transformation.value_scratch))
                }
                PatchKind::X18Conditional(branch) => {
                    Some((branch.anchor_scratch, branch.value_scratch))
                }
                _ => None,
            };
            let Some(pair) = pair else { continue };
            if !setups.contains(&pair) {
                setups.push(pair);
            }
        }
    }
    setups
}

fn plan_x18_sites(sites: &[PatchSite], trampoline_base_addr: u64) -> Result<X18Plan> {
    let candidates = sites
        .iter()
        .map(|site| {
            matches!(
                site.kind,
                PatchKind::X18(X18TransformResult::Supported(_))
                    | PatchKind::X18Conditional(_)
                    | PatchKind::X18Br
            )
        })
        .collect::<Vec<_>>();
    let candidate_setups = collect_x18_setups(sites, &candidates);
    let setup_bytes = candidate_setups
        .len()
        .checked_mul(X18_SETUP_BYTES)
        .ok_or_else(|| Error::AddressOverflow("AArch64 x18 setup layout size".into()))?;
    let mut maximum_gate_offset = GATES_START_OFFSET
        .checked_add(setup_bytes)
        .ok_or_else(|| Error::AddressOverflow("AArch64 x18 gate layout size".into()))?;
    let minimum_gate_offset = GATES_START_OFFSET + X18_SETUP_BYTES;
    let mut selected = Vec::with_capacity(sites.len());
    let mut layout_checks = 0;

    for (site, candidate) in sites.iter().zip(candidates) {
        let reachable = if candidate {
            layout_checks += 1;
            x18_layout_envelope_reachable(
                site,
                trampoline_base_addr,
                minimum_gate_offset,
                maximum_gate_offset,
                &candidate_setups,
            )?
        } else {
            false
        };
        selected.push(reachable);
        maximum_gate_offset = maximum_gate_offset
            .checked_add(maximum_site_slot_size(site))
            .ok_or_else(|| Error::AddressOverflow("AArch64 gate layout size".into()))?;
    }

    Ok(X18Plan {
        sites: selected,
        layout_checks,
    })
}

struct X18Plan {
    sites: Vec<bool>,
    #[cfg_attr(not(test), allow(dead_code))]
    layout_checks: usize,
}

/// Conservatively proves one x18 gate reachable at every offset it can occupy.
///
/// Setup removal and unreachable earlier gates can only compact a gate between
/// `minimum_gate_offset` and its source-order `maximum_gate_offset`. AArch64
/// direct-branch displacement is affine in the gate address, so checking both
/// endpoints proves every intermediate aligned position. Candidate setup
/// records are similarly bounded by the full candidate setup list. This makes
/// planning O(n * p), where p is the fixed maximum of 55 scratch pairs, with no
/// gate-byte emission; the compact final trampoline is emitted exactly once.
fn x18_layout_envelope_reachable(
    site: &PatchSite,
    trampoline_base_addr: u64,
    minimum_gate_offset: usize,
    maximum_gate_offset: usize,
    candidate_setups: &[(u8, u8)],
) -> Result<bool> {
    let (pair, return_offsets, targets): ((u8, u8), &[usize], &[u64]) = match site.kind {
        PatchKind::X18(X18TransformResult::Supported(transformation)) => (
            (transformation.anchor_scratch, transformation.value_scratch),
            &[40],
            &[checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 return")?],
        ),
        PatchKind::X18Conditional(branch) => (
            (branch.anchor_scratch, branch.value_scratch),
            &[40, 56],
            &[
                checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 conditional fallthrough")?,
                branch.target,
            ],
        ),
        PatchKind::X18Br => {
            for gate_offset in [minimum_gate_offset, maximum_gate_offset] {
                let gate_vaddr = checked_add_u64(
                    trampoline_base_addr,
                    gate_offset as u64,
                    "planned x18 BR gate",
                )?;
                if !branch_encodes(gate_vaddr, site.vaddr, false)
                    || !branch_encodes(site.vaddr + 4, gate_vaddr + 4, false)
                {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        _ => return Ok(false),
    };
    let setup_index = candidate_setups
        .iter()
        .position(|candidate| *candidate == pair)
        .expect("candidate x18 pair was collected");
    let maximum_setup_offset = GATES_START_OFFSET + setup_index * X18_SETUP_BYTES;

    for gate_offset in [minimum_gate_offset, maximum_gate_offset] {
        let gate_vaddr =
            checked_add_u64(trampoline_base_addr, gate_offset as u64, "planned x18 gate")?;
        if !branch_encodes(gate_vaddr, site.vaddr, false) {
            return Ok(false);
        }
        for (&return_offset, &target) in return_offsets.iter().zip(targets) {
            let branch_pc = checked_add_u64(gate_vaddr, return_offset as u64, "x18 return branch")?;
            if !branch_encodes(target, branch_pc, false) {
                return Ok(false);
            }
        }
        if let PatchKind::X18(X18TransformResult::Supported(X18Transformation {
            pcrel: Some(pcrel),
            ..
        })) = site.kind
        {
            let target = match pcrel {
                X18Pcrel::Adr(displacement) => site.vaddr.checked_add_signed(displacement),
                X18Pcrel::Adrp(displacement) => {
                    (site.vaddr & !PAGE_OFFSET_MASK).checked_add_signed(displacement)
                }
            };
            let Some(target) = target else {
                return Ok(false);
            };
            let relocated_pc = checked_add_u64(gate_vaddr, 24, "planned x18 PC-relative")?;
            let encodes = adrp_encodes(target, relocated_pc);
            if !encodes {
                return Ok(false);
            }
        }
        for setup_offset in [GATES_START_OFFSET, maximum_setup_offset] {
            let setup_vaddr = checked_add_u64(
                trampoline_base_addr,
                setup_offset as u64,
                "planned x18 setup",
            )?;
            let call_pc = checked_add_u64(gate_vaddr, 12, "x18 setup call")?;
            if !branch_encodes(setup_vaddr, call_pc, true) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn branch_encodes(target: u64, pc: u64, link: bool) -> bool {
    checked_pcrel_difference(target, pc).is_some_and(|offset| {
        if link {
            Insn::Bl(offset).encode().is_some()
        } else {
            Insn::B(offset).encode().is_some()
        }
    })
}

fn adrp_encodes(target: u64, pc: u64) -> bool {
    checked_pcrel_difference(target & !PAGE_OFFSET_MASK, pc & !PAGE_OFFSET_MASK).is_some_and(
        |page_bytes| {
            Insn::Adrp {
                rd: 0,
                page_off: page_bytes >> ADRP_PAGE_SHIFT,
            }
            .encode()
            .is_some()
        },
    )
}

const fn maximum_site_slot_size(site: &PatchSite) -> usize {
    match site.kind {
        PatchKind::Svc => SVC_SLOT_BYTES,
        PatchKind::MsrTpidr(_) => MSR_SLOT_BYTES,
        PatchKind::MrsTpidr(_) => MRS_SLOT_BYTES,
        PatchKind::X18(X18TransformResult::Supported(_)) => X18_SLOT_BYTES,
        PatchKind::X18Conditional(_) => X18_CONDITIONAL_SLOT_BYTES,
        PatchKind::X18Br => X18_BR_SLOT_BYTES,
        PatchKind::X18(X18TransformResult::Unsupported(_)) => 0,
    }
}

fn emit_site_gate(
    trampoline_data: &mut Vec<u8>,
    trampoline_base_addr: u64,
    site: &PatchSite,
    host: Host,
    x18_setups: &[(u8, u8)],
    emit_x18: bool,
) -> Result<(Option<u32>, GateBuild)> {
    let gate_offset = trampoline_data.len();
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "trampoline gate")?;

    // The gate's return branch spans a wider displacement than the inbound
    // one, so an encodable inbound branch is necessary but not sufficient:
    // the gate is built only once the inbound branch fits, and a gate whose
    // own branches are out of range reports `GateBuild::Unreachable` and
    // appends nothing. If either is unreachable the site is trapped and no
    // gate is emitted.
    let inbound = checked_pcrel_difference(gate_vaddr, site.vaddr)
        .and_then(|offset| Insn::B(offset).encode());

    let build = if inbound.is_some() {
        match site.kind {
            PatchKind::Svc => {
                emit_svc_gate(trampoline_data, gate_offset, trampoline_base_addr, site)?
            }
            PatchKind::MsrTpidr(rt) => emit_msr_gate(
                trampoline_data,
                gate_offset,
                trampoline_base_addr,
                site,
                rt,
                host,
            )?,
            PatchKind::MrsTpidr(rd) => emit_mrs_gate(
                trampoline_data,
                gate_offset,
                trampoline_base_addr,
                site,
                rd,
                host,
            )?,
            PatchKind::X18(result) => {
                if emit_x18 && let X18TransformResult::Supported(transformation) = result {
                    let pair = (transformation.anchor_scratch, transformation.value_scratch);
                    let setup_index = x18_setups
                        .iter()
                        .position(|candidate| *candidate == pair)
                        .expect("supported x18 pair was collected");
                    let setup_offset = GATES_START_OFFSET + setup_index * X18_SETUP_BYTES;
                    emit_x18_gate(
                        trampoline_data,
                        gate_offset,
                        setup_offset,
                        trampoline_base_addr,
                        site,
                        transformation,
                    )?
                } else {
                    GateBuild::Unreachable
                }
            }
            PatchKind::X18Conditional(branch) => {
                if emit_x18 {
                    let pair = (branch.anchor_scratch, branch.value_scratch);
                    let setup_index = x18_setups
                        .iter()
                        .position(|candidate| *candidate == pair)
                        .expect("conditional x18 pair was collected");
                    let setup_offset = GATES_START_OFFSET + setup_index * X18_SETUP_BYTES;
                    emit_x18_conditional_gate(
                        trampoline_data,
                        gate_offset,
                        setup_offset,
                        trampoline_base_addr,
                        site,
                        branch,
                    )?
                } else {
                    GateBuild::Unreachable
                }
            }
            PatchKind::X18Br => {
                if emit_x18 {
                    emit_x18_br_gate(trampoline_data, gate_offset, trampoline_base_addr, site)?
                } else {
                    GateBuild::Unreachable
                }
            }
        }
    } else {
        GateBuild::Unreachable
    };
    Ok((inbound, build))
}

fn emit_x18_setup(
    trampoline_data: &mut Vec<u8>,
    anchor_scratch: u8,
    value_scratch: u8,
    host: Host,
) -> Result<()> {
    debug_assert!(trampoline_data.len().is_multiple_of(GATE_ALIGNMENT));
    let mut code = Vec::with_capacity(X18_SETUP_BYTES);
    for instruction in [
        host.anchor_read(anchor_scratch),
        Insn::LdrUimm {
            rt: value_scratch,
            rn: SP,
            imm_bytes: 0,
        },
        Insn::StrUimm {
            rt: value_scratch,
            rn: anchor_scratch,
            imm_bytes: SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
        },
        Insn::LdrUimm {
            rt: value_scratch,
            rn: SP,
            imm_bytes: 8,
        },
        Insn::StrUimm {
            rt: value_scratch,
            rn: anchor_scratch,
            imm_bytes: SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
        },
        Insn::LdrUimm {
            rt: value_scratch,
            rn: anchor_scratch,
            imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
        },
        Insn::Ret(30),
    ] {
        code.extend_from_slice(
            &instruction
                .encode()
                .expect("valid x18 setup instruction")
                .to_le_bytes(),
        );
    }
    code.extend_from_slice(
        &EncodedGateMetadata::encode(GateMetadata::X18 {
            anchor_scratch,
            value_scratch,
        })
        .ok_or_else(|| Error::AddressOverflow("invalid x18 setup metadata".into()))?
        .0
        .to_le_bytes(),
    );
    debug_assert_eq!(code.len(), X18_SETUP_BYTES);
    trampoline_data.extend_from_slice(&code);
    Ok(())
}

fn emit_x18_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    setup_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    transformation: X18Transformation,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "x18 gate")?;
    let setup_vaddr = checked_add_u64(trampoline_base_addr, setup_offset as u64, "x18 setup")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(Insn::SubSp(32));
    asm.emit(Insn::Stp {
        rt: transformation.anchor_scratch,
        rt2: transformation.value_scratch,
        rn: SP,
        imm_bytes: 0,
    });
    asm.emit(Insn::StrUimm {
        rt: 30,
        rn: SP,
        imm_bytes: 16,
    });
    if !asm.call_to(setup_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.emit(Insn::LdrUimm {
        rt: 30,
        rn: SP,
        imm_bytes: 16,
    });
    asm.emit(Insn::AddSp(32));
    if let Some(pcrel) = transformation.pcrel {
        let target = match pcrel {
            X18Pcrel::Adr(displacement) => site.vaddr.checked_add_signed(displacement),
            X18Pcrel::Adrp(displacement) => {
                (site.vaddr & !PAGE_OFFSET_MASK).checked_add_signed(displacement)
            }
        };
        let Some(target) = target else {
            return Ok(GateBuild::Unreachable);
        };
        let emitted = asm.adrp(transformation.value_scratch, target)?;
        if !emitted {
            return Ok(GateBuild::Unreachable);
        }
        asm.emit(match pcrel {
            X18Pcrel::Adr(_) => Insn::AddImm {
                rd: transformation.value_scratch,
                rn: transformation.value_scratch,
                imm12: u16::try_from(target & PAGE_OFFSET_MASK)
                    .expect("page offset fits ADD immediate"),
            },
            X18Pcrel::Adrp(_) => Insn::Nop,
        });
    } else {
        asm.push_word(transformation.word);
        asm.emit(Insn::Nop);
    }
    asm.emit(Insn::StrUimm {
        rt: transformation.value_scratch,
        rn: transformation.anchor_scratch,
        imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
    });
    asm.emit(Insn::LdrUimm {
        rt: transformation.value_scratch,
        rn: transformation.anchor_scratch,
        imm_bytes: SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
    });
    asm.emit(Insn::LdrUimm {
        rt: transformation.anchor_scratch,
        rn: transformation.anchor_scratch,
        imm_bytes: SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
    });
    let return_addr = checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 return")?;
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    // Non-executable provenance descriptor: bind the transformed instruction
    // to the exact original word selected by discovery.
    asm.push_word(transformation.original_word);
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18 {
            anchor_scratch: transformation.anchor_scratch,
            value_scratch: transformation.value_scratch,
        },
        X18_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn emit_x18_br_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "x18 BR gate")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(Insn::Brk(X18_BR_BRK_IMM));
    if !asm.branch_to(checked_add_u64(site.vaddr, 4, "x18 BR provenance")?)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.push_word(Insn::Br(18).encode().unwrap());
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18Br,
        X18_BR_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

fn emit_x18_conditional_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    setup_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    branch: X18ConditionalBranch,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(
        trampoline_base_addr,
        gate_offset as u64,
        "x18 conditional gate",
    )?;
    let setup_vaddr = checked_add_u64(trampoline_base_addr, setup_offset as u64, "x18 setup")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(Insn::SubSp(32));
    asm.emit(Insn::Stp {
        rt: branch.anchor_scratch,
        rt2: branch.value_scratch,
        rn: SP,
        imm_bytes: 0,
    });
    asm.emit(Insn::StrUimm {
        rt: 30,
        rn: SP,
        imm_bytes: 16,
    });
    if !asm.call_to(setup_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.emit(Insn::LdrUimm {
        rt: 30,
        rn: SP,
        imm_bytes: 16,
    });
    asm.emit(Insn::AddSp(32));
    asm.emit(match branch.kind {
        X18ConditionalKind::Compare => Insn::CompareBranch {
            rt: branch.value_scratch,
            offset: 20,
            nonzero: branch.nonzero,
            width: branch.width,
        },
        X18ConditionalKind::Test { bit } => Insn::TestBranch {
            rt: branch.value_scratch,
            offset: 20,
            nonzero: branch.nonzero,
            bit,
        },
    });
    for target in [
        checked_add_u64(site.vaddr, INSN_BYTES_U64, "x18 conditional fallthrough")?,
        branch.target,
    ] {
        asm.emit(Insn::StrUimm {
            rt: branch.value_scratch,
            rn: branch.anchor_scratch,
            imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
        });
        asm.emit(Insn::LdrUimm {
            rt: branch.value_scratch,
            rn: branch.anchor_scratch,
            imm_bytes: SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
        });
        asm.emit(Insn::LdrUimm {
            rt: branch.anchor_scratch,
            rn: branch.anchor_scratch,
            imm_bytes: SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
        });
        if !asm.branch_to(target)? {
            return Ok(GateBuild::Unreachable);
        }
    }
    asm.push_word(branch.original_word);
    append_gate_slot(
        trampoline_data,
        asm.finish(),
        trampoline_base_addr,
        gate_vaddr,
        GateMetadata::X18Conditional {
            anchor_scratch: branch.anchor_scratch,
            value_scratch: branch.value_scratch,
        },
        X18_CONDITIONAL_SLOT_BYTES,
    )?;
    Ok(GateBuild::Emitted)
}

/// Replace the four bytes at `file_offset` with `BRK #TRAP_BRK_IMM`.
///
/// A patch site left native escapes the configured virtualization, potentially
/// reaching the host kernel or modifying host-owned register state. That is a
/// silent failure, which is worse than a fault.
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
/// that could not be patched at all. [`hook_syscalls_aarch64`] traps its own
/// unreachable sites as it goes and does not come through here.
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
        GateMetadata::X18 {
            anchor_scratch,
            value_scratch,
        } => {
            let offsets = [
                x18_access_offset(word(32), Opcode::StrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(36), Opcode::LdrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(40), Opcode::LdrUimm, anchor_scratch, anchor_scratch),
            ];
            let setup_target = decode_branch_link_target(word(12), anchor + 12);
            let return_is_valid = match addressing {
                SlotAddressing::Unplaced { .. } => word(44) & OPCODE_TOP6_MASK == Opcode::B.bits(),
                SlotAddressing::Placed { .. } => decode_branch_target(word(44), anchor + 44)
                    .is_some_and(|target| {
                        target.is_multiple_of(INSN_BYTES_U64)
                            && !(anchor..anchor + X18_SLOT_BYTES as u64).contains(&target)
                    }),
            };
            exact(0, Insn::SubSp(32))
                && exact(
                    4,
                    Insn::Stp {
                        rt: anchor_scratch,
                        rt2: value_scratch,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(
                    8,
                    Insn::StrUimm {
                        rt: 30,
                        rn: SP,
                        imm_bytes: 16,
                    },
                )
                && setup_target.is_some_and(|target| {
                    target.is_multiple_of(GATE_ALIGNMENT as u64) && target < anchor
                })
                && exact(
                    16,
                    Insn::LdrUimm {
                        rt: 30,
                        rn: SP,
                        imm_bytes: 16,
                    },
                )
                && exact(20, Insn::AddSp(32))
                && match addressing {
                    SlotAddressing::Placed { .. } => exact_x18_transformation(
                        word(48),
                        word(24),
                        word(28),
                        anchor_scratch,
                        value_scratch,
                        decode_branch_target(word(44), anchor + 44)
                            .and_then(|return_target| return_target.checked_sub(INSN_BYTES_U64)),
                        anchor + 24,
                    ),
                    SlotAddressing::Unplaced { slot_offset } => exact_x18_unplaced_transformation(
                        word(48),
                        word(24),
                        word(28),
                        anchor_scratch,
                        value_scratch,
                        i64::try_from(slot_offset)
                            .ok()
                            .and_then(|offset| offset.checked_add(44))
                            .and_then(|pc| branch_local_target(word(44), pc))
                            .and_then(|return_target| {
                                return_target.checked_sub(INSN_BYTES_U64.cast_signed())
                            }),
                        i64::try_from(slot_offset)
                            .ok()
                            .and_then(|offset| offset.checked_add(24)),
                    ),
                }
                && exact_x18_site_offsets(offsets)
                && return_is_valid
                && padding_is_nops(52)
        }
        GateMetadata::X18Conditional {
            anchor_scratch,
            value_scratch,
        } => {
            let original = word(60);
            let condition = word(24);
            let offsets = [
                x18_access_offset(word(28), Opcode::StrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(32), Opcode::LdrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(36), Opcode::LdrUimm, anchor_scratch, anchor_scratch),
                x18_access_offset(word(44), Opcode::StrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(48), Opcode::LdrUimm, value_scratch, anchor_scratch),
                x18_access_offset(word(52), Opcode::LdrUimm, anchor_scratch, anchor_scratch),
            ];
            let setup_target = decode_branch_link_target(word(12), anchor + 12);
            let continuations_valid = match addressing {
                SlotAddressing::Unplaced { .. } => branch_local_target(word(40), 40)
                    .zip(branch_local_target(word(56), 56))
                    .zip(decoded_conditional_offset(original))
                    .is_some_and(|((fallthrough, taken), original_offset)| {
                        taken - fallthrough == original_offset - 4
                    }),
                SlotAddressing::Placed { .. } => decode_branch_target(word(40), anchor + 40)
                    .zip(decode_branch_target(word(56), anchor + 56))
                    .zip(decoded_conditional_offset(original))
                    .is_some_and(|((fallthrough, taken), original_offset)| {
                        fallthrough
                            .checked_sub(INSN_BYTES_U64)
                            .and_then(|site| site.checked_add_signed(original_offset))
                            == Some(taken)
                    }),
            };
            exact(0, Insn::SubSp(32))
                && exact(
                    4,
                    Insn::Stp {
                        rt: anchor_scratch,
                        rt2: value_scratch,
                        rn: SP,
                        imm_bytes: 0,
                    },
                )
                && exact(
                    8,
                    Insn::StrUimm {
                        rt: 30,
                        rn: SP,
                        imm_bytes: 16,
                    },
                )
                && setup_target.is_some_and(|target| {
                    target.is_multiple_of(GATE_ALIGNMENT as u64) && target < anchor
                })
                && exact(
                    16,
                    Insn::LdrUimm {
                        rt: 30,
                        rn: SP,
                        imm_bytes: 16,
                    },
                )
                && exact(20, Insn::AddSp(32))
                && exact_x18_conditional(original, condition, value_scratch)
                && offsets[..3] == offsets[3..]
                && exact_x18_site_offsets([offsets[0], offsets[1], offsets[2]])
                && continuations_valid
                && padding_is_nops(64)
        }
        GateMetadata::X18Br => {
            exact(0, Insn::Brk(X18_BR_BRK_IMM))
                && exact(8, Insn::Br(18))
                && match addressing {
                    SlotAddressing::Unplaced { .. } => {
                        word(4) & OPCODE_TOP6_MASK == Opcode::B.bits()
                    }
                    SlotAddressing::Placed { .. } => decode_branch_target(word(4), anchor + 4)
                        .is_some_and(|target| target.is_multiple_of(INSN_BYTES_U64)),
                }
        }
    }
}

impl GateMetadata {
    pub fn anchor_scratch(self) -> Option<u8> {
        match self {
            Self::X18 { anchor_scratch, .. } | Self::X18Conditional { anchor_scratch, .. } => {
                Some(anchor_scratch)
            }
            _ => None,
        }
    }

    pub fn value_scratch(self) -> Option<u8> {
        match self {
            Self::X18 { value_scratch, .. } | Self::X18Conditional { value_scratch, .. } => {
                Some(value_scratch)
            }
            _ => None,
        }
    }

    /// Fixed byte size of this metadata version's compact slot.
    pub const fn slot_size(self) -> usize {
        match self {
            GateMetadata::Svc => SVC_SLOT_BYTES,
            GateMetadata::MrsTpidr { .. } => MRS_SLOT_BYTES,
            GateMetadata::MsrTpidr { .. } => MSR_SLOT_BYTES,
            GateMetadata::X18 { .. } => X18_SLOT_BYTES,
            GateMetadata::X18Conditional { .. } => X18_CONDITIONAL_SLOT_BYTES,
            GateMetadata::X18Br => X18_BR_SLOT_BYTES,
        }
    }

    /// First byte offset past the slot's executable body.
    ///
    /// Everything from here to the trailing metadata word is `NOP` padding, so
    /// a PC at or past it is not inside the gate proper and must not be
    /// classified as one.
    pub(crate) const fn executable_end(self) -> usize {
        match self {
            // The `B` back to the original site at 44 is the last instruction.
            GateMetadata::Svc => 48,
            // `MRS`, the guest-TLS `LDR`, then the `B` back.
            GateMetadata::MrsTpidr { .. } => 12,
            // Frame teardown ends at 28, then the `B` back at 32. The second
            // `B` at 36 never executes, so a PC there is not a live gate PC.
            GateMetadata::MsrTpidr { .. } => 36,
            GateMetadata::X18 { .. } => X18_GATE_BYTES,
            GateMetadata::X18Conditional { .. } => 60,
            GateMetadata::X18Br => 4,
        }
    }

    /// Byte offset of the branch that returns to the instruction after the
    /// original site.
    pub(crate) const fn return_offset(self) -> usize {
        match self {
            GateMetadata::Svc | GateMetadata::X18 { .. } => 44,
            GateMetadata::MrsTpidr { .. } => 8,
            GateMetadata::MsrTpidr { .. } => 32,
            GateMetadata::X18Conditional { .. } => 40,
            GateMetadata::X18Br => 4,
        }
    }

    /// Byte offset of the instruction that commits the gate's architectural
    /// effect. A saved PC names the instruction about to execute, so past this
    /// offset the effect has happened.
    ///
    /// This says when the effect lands, not that the context is rewindable
    /// before it. Only [`GateMetadata::MsrTpidr`] is, from its spill frame.
    /// [`GateMetadata::MrsTpidr`] destroys the register a rewind would restore,
    /// so every PC inside it is carried forward instead.
    pub const fn commit_offset(self) -> usize {
        match self {
            // The shim performs the syscall, so any PC in an `SVC` slot is
            // still pre-commit — though at 4 or beyond `SP` and `X16` still
            // need undoing.
            GateMetadata::Svc
            | GateMetadata::X18 { .. }
            | GateMetadata::X18Conditional { .. }
            | GateMetadata::X18Br => 0,
            // The guest-TLS load.
            GateMetadata::MrsTpidr { .. } => 4,
            // The guest-TLS store.
            GateMetadata::MsrTpidr { .. } => 20,
        }
    }
}

/// Decode one little-endian metadata word copied from a candidate slot.
pub fn decode_gate_metadata_word(word: u32) -> Option<GateMetadata> {
    EncodedGateMetadata(word).decode()
}

/// A validated gate slot containing some PC, with what a signal handler needs
/// to canonicalize the interrupted context: where the slot starts, how far
/// into it the guest-visible effect commits, and which guest instruction it
/// replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedGate {
    slot_offset: usize,
    slot_size: u8,
    commit_offset: u8,
    original_site: u64,
    metadata: GateMetadata,
    x18: Option<ClassifiedX18Gate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedX18Gate {
    original_instruction: u32,
    transformed_instruction: u32,
    materialization_tail: u32,
    setup_handler: u64,
    guest_x18_offset: u16,
    saved_anchor_scratch_offset: u16,
    saved_value_scratch_offset: u16,
    fallthrough: u64,
    taken: Option<u64>,
}

impl ClassifiedX18Gate {
    pub fn original_instruction(self) -> u32 {
        self.original_instruction
    }
    pub fn transformed_instruction(self) -> u32 {
        self.transformed_instruction
    }
    pub fn original_is_adr(self) -> bool {
        self.original_instruction & ADRP_SHAPE_MASK == Opcode::Adr.bits() | u32::from(X18)
    }
    pub fn original_is_adrp(self) -> bool {
        self.original_instruction & ADRP_SHAPE_MASK == Opcode::Adrp.bits() | u32::from(X18)
    }
    pub fn setup_handler(self) -> u64 {
        self.setup_handler
    }
    pub fn guest_x18_offset(self) -> u16 {
        self.guest_x18_offset
    }
    pub fn saved_anchor_scratch_offset(self) -> u16 {
        self.saved_anchor_scratch_offset
    }
    pub fn saved_value_scratch_offset(self) -> u16 {
        self.saved_value_scratch_offset
    }
    pub const fn setup_call_offset(self) -> u8 {
        12
    }
    pub const fn post_setup_offset(self) -> u8 {
        16
    }
    pub const fn transformed_instruction_offset(self) -> u8 {
        24
    }
    pub const fn return_offset(self) -> u8 {
        40
    }
    pub fn fallthrough(self) -> u64 {
        self.fallthrough
    }
    pub fn taken(self) -> Option<u64> {
        self.taken
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedX18Setup {
    instruction_offset: u8,
    metadata: GateMetadata,
    guest_x18_offset: u16,
    saved_anchor_scratch_offset: u16,
    saved_value_scratch_offset: u16,
}

impl ClassifiedX18Setup {
    pub fn instruction_offset(self) -> u8 {
        self.instruction_offset
    }
    pub fn metadata(self) -> GateMetadata {
        self.metadata
    }
    pub fn guest_x18_offset(self) -> u16 {
        self.guest_x18_offset
    }
    pub fn saved_anchor_scratch_offset(self) -> u16 {
        self.saved_anchor_scratch_offset
    }
    pub fn saved_value_scratch_offset(self) -> u16 {
        self.saved_value_scratch_offset
    }
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

    /// Template-derived architectural commit offset.
    pub fn commit_offset(self) -> u8 {
        self.commit_offset
    }

    /// Original guest instruction address recovered from the return branch.
    pub fn original_site(self) -> u64 {
        self.original_site
    }

    /// Decoded semantic gate metadata.
    pub fn metadata(self) -> GateMetadata {
        self.metadata
    }

    pub fn x18(self) -> Option<ClassifiedX18Gate> {
        self.x18
    }
}

/// Classify an AArch64 trampoline PC by testing at most four aligned candidate
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
    let candidates = core::array::from_fn(|index| aligned.saturating_sub(index * GATE_ALIGNMENT));
    classify_gate_pc_with_candidates(trampoline, trampoline_base, pc, candidates)
}

/// Classifies one fault-safely copied compact slot containing `pc`.
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
            u32::from_le_bytes(slot.get(28..32)?.try_into().ok()?),
            slot_vaddr + 28,
        )?,
        GateMetadata::MrsTpidr { .. }
        | GateMetadata::MsrTpidr { .. }
        | GateMetadata::X18 { .. }
        | GateMetadata::X18Conditional { .. }
        | GateMetadata::X18Br => 0,
    };
    // For `Svc` the base was just recovered from the slot's own literal load,
    // so `validate_gate_slot`'s callback check is a tautology here. The other
    // template checks still do real work; this is structural recognition, not
    // authentication.
    if !validate_gate_slot(slot, trampoline_base, slot_vaddr, metadata) {
        return None;
    }
    classified_gate_from_validated_slot(slot, 0, slot_vaddr, metadata)
}

pub fn classify_copied_x18_setup_record(
    record: &[u8],
    record_vaddr: u64,
    pc: u64,
) -> Option<ClassifiedX18Setup> {
    classify_copied_x18_setup_record_for_host(record, record_vaddr, pc, crate::TargetHost::Linux)
}

/// Host-aware counterpart to [`classify_copied_x18_setup_record`].
pub fn classify_copied_x18_setup_record_for_host(
    record: &[u8],
    record_vaddr: u64,
    pc: u64,
    target_host: crate::TargetHost,
) -> Option<ClassifiedX18Setup> {
    let offset = usize::try_from(pc.checked_sub(record_vaddr)?).ok()?;
    if record.len() != X18_SETUP_BYTES
        || !record_vaddr.is_multiple_of(GATE_ALIGNMENT as u64)
        || !pc.is_multiple_of(INSN_BYTES_U64)
        || offset >= X18_SETUP_BYTES - GATE_METADATA_BYTES
    {
        return None;
    }
    let metadata = EncodedGateMetadata(copied_word(record, 28)?).decode()?;
    let GateMetadata::X18 {
        anchor_scratch,
        value_scratch,
    } = metadata
    else {
        return None;
    };
    validate_x18_setup(
        record,
        anchor_scratch,
        value_scratch,
        host_for_target(target_host),
    )
    .then_some(ClassifiedX18Setup {
        instruction_offset: u8::try_from(offset).ok()?,
        metadata,
        guest_x18_offset: x18_access_offset(
            copied_word(record, 20)?,
            Opcode::LdrUimm,
            value_scratch,
            anchor_scratch,
        )?,
        saved_anchor_scratch_offset: x18_access_offset(
            copied_word(record, 8)?,
            Opcode::StrUimm,
            value_scratch,
            anchor_scratch,
        )?,
        saved_value_scratch_offset: x18_access_offset(
            copied_word(record, 16)?,
            Opcode::StrUimm,
            value_scratch,
            anchor_scratch,
        )?,
    })
}

/// Classification of persisted x18 structures in a trampoline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X18Topology {
    /// No x18 metadata-shaped setup or site is present.
    Absent,
    /// At least one complete site/setup graph is present.
    Valid,
    /// X18-shaped metadata exists but its graph or exact template is invalid.
    Malformed,
}

#[derive(Clone, Copy)]
struct ValidatedSetup {
    offset: usize,
    metadata: GateMetadata,
    referenced: bool,
}

#[derive(Clone, Copy)]
struct ValidatedSlot {
    offset: usize,
    metadata: GateMetadata,
}

struct ValidatedTrampoline {
    setups: Vec<ValidatedSetup>,
    slots: Vec<ValidatedSlot>,
}

#[derive(Clone, Copy)]
struct TrampolineParseFailure {
    x18_shaped: bool,
}

/// Classifies complete x18 setup/site topology for the selected host.
pub fn classify_x18_topology_for_host(
    trampoline: &[u8],
    target_host: crate::TargetHost,
) -> X18Topology {
    match parse_validated_trampoline(trampoline, host_for_target(target_host)) {
        Ok(parsed)
            if parsed.setups.is_empty()
                && !parsed
                    .slots
                    .iter()
                    .any(|slot| matches!(slot.metadata, GateMetadata::X18Br)) =>
        {
            X18Topology::Absent
        }
        Ok(_) => X18Topology::Valid,
        Err(failure) if failure.x18_shaped => X18Topology::Malformed,
        Err(_) => X18Topology::Absent,
    }
}

fn parse_validated_trampoline(
    trampoline: &[u8],
    host: Host,
) -> core::result::Result<ValidatedTrampoline, TrampolineParseFailure> {
    let failure = |x18_shaped| TrampolineParseFailure { x18_shaped };
    if trampoline.len() < GATES_START_OFFSET
        || !trampoline.len().is_multiple_of(INSN_BYTES)
        || trampoline[8..GATES_START_OFFSET]
            .chunks_exact(INSN_BYTES)
            .any(|word| u32::from_le_bytes(word.try_into().unwrap()) != NOP)
    {
        let x18_shaped = trampoline.chunks_exact(INSN_BYTES).any(|word| {
            matches!(
                EncodedGateMetadata(u32::from_le_bytes(word.try_into().unwrap())).decode(),
                Some(
                    GateMetadata::X18 { .. }
                        | GateMetadata::X18Conditional { .. }
                        | GateMetadata::X18Br
                )
            )
        });
        return Err(failure(x18_shaped));
    }

    let mut parsed = ValidatedTrampoline {
        setups: Vec::new(),
        slots: Vec::new(),
    };
    let mut cursor = GATES_START_OFFSET;
    while let Some(end) = cursor
        .checked_add(X18_SETUP_BYTES)
        .filter(|end| *end <= trampoline.len())
    {
        let Some(
            metadata @ GateMetadata::X18 {
                anchor_scratch,
                value_scratch,
            },
        ) = copied_word(trampoline, end - GATE_METADATA_BYTES)
            .and_then(|word| EncodedGateMetadata(word).decode())
        else {
            break;
        };
        if !validate_x18_setup(
            &trampoline[cursor..end],
            anchor_scratch,
            value_scratch,
            host,
        ) {
            return Err(failure(true));
        }
        parsed.setups.push(ValidatedSetup {
            offset: cursor,
            metadata,
            referenced: false,
        });
        cursor = end;
    }

    while cursor < trampoline.len() {
        let mut matched = None;
        let mut x18_shaped = false;
        for slot_size in [
            MRS_SLOT_BYTES,
            MSR_SLOT_BYTES,
            SVC_SLOT_BYTES,
            X18_CONDITIONAL_SLOT_BYTES,
        ] {
            let Some(end) = cursor
                .checked_add(slot_size)
                .filter(|end| *end <= trampoline.len())
            else {
                continue;
            };
            let Some(metadata) = copied_word(trampoline, end - GATE_METADATA_BYTES)
                .and_then(|word| EncodedGateMetadata(word).decode())
            else {
                continue;
            };
            x18_shaped |= matches!(
                metadata,
                GateMetadata::X18 { .. }
                    | GateMetadata::X18Conditional { .. }
                    | GateMetadata::X18Br
            );
            if metadata.slot_size() == slot_size
                && validate_gate_slot_inner(
                    &trampoline[cursor..end],
                    SlotAddressing::Unplaced {
                        slot_offset: cursor as u64,
                    },
                    metadata,
                )
            {
                if matched.is_some() {
                    return Err(failure(x18_shaped || !parsed.setups.is_empty()));
                }
                matched = Some((end, metadata));
            }
        }
        let Some((end, metadata)) = matched else {
            return Err(failure(x18_shaped || !parsed.setups.is_empty()));
        };
        if matches!(
            metadata,
            GateMetadata::X18 { .. } | GateMetadata::X18Conditional { .. }
        ) {
            let target = copied_word(trampoline, cursor + 12)
                .zip(i64::try_from(cursor + 12).ok())
                .and_then(|(word, pc)| branch_link_local_target(word, pc))
                .and_then(|target| usize::try_from(target).ok());
            let Some(setup) = target.and_then(|target| {
                parsed.setups.iter_mut().find(|setup| {
                    setup.offset == target
                        && setup.metadata.anchor_scratch() == metadata.anchor_scratch()
                        && setup.metadata.value_scratch() == metadata.value_scratch()
                })
            }) else {
                return Err(failure(true));
            };
            setup.referenced = true;
        }
        parsed.slots.push(ValidatedSlot {
            offset: cursor,
            metadata,
        });
        cursor = end;
    }
    if parsed.setups.iter().any(|setup| !setup.referenced) {
        return Err(failure(true));
    }
    Ok(parsed)
}

fn classify_gate_pc_with_candidates(
    trampoline: &[u8],
    trampoline_base: u64,
    pc: u64,
    candidates: [usize; 4],
) -> Option<ClassifiedGate> {
    let relative = usize::try_from(pc.checked_sub(trampoline_base)?).ok()?;
    let mut match_found = None;
    for start in candidates {
        if start < GATES_START_OFFSET || !start.is_multiple_of(GATE_ALIGNMENT) {
            continue;
        }
        for slot_size in [
            MRS_SLOT_BYTES,
            MSR_SLOT_BYTES,
            SVC_SLOT_BYTES,
            X18_CONDITIONAL_SLOT_BYTES,
        ] {
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
                || !validate_gate_slot(slot, trampoline_base, slot_vaddr, metadata)
            {
                continue;
            }
            if match_found.is_some() {
                return None;
            }
            match_found = Some(classified_gate_from_validated_slot(
                slot, start, slot_vaddr, metadata,
            )?);
        }
    }
    match_found
}

fn classified_gate_from_validated_slot(
    slot: &[u8],
    slot_offset: usize,
    slot_vaddr: u64,
    metadata: GateMetadata,
) -> Option<ClassifiedGate> {
    let return_offset = metadata.return_offset();
    let return_target = decode_branch_target(
        copied_word(slot, return_offset)?,
        slot_vaddr + return_offset as u64,
    )?;
    let x18 = match metadata {
        GateMetadata::X18 { .. } | GateMetadata::X18Conditional { .. } => Some(ClassifiedX18Gate {
            original_instruction: copied_word(
                slot,
                if matches!(metadata, GateMetadata::X18Conditional { .. }) {
                    60
                } else {
                    48
                },
            )?,
            transformed_instruction: copied_word(slot, 24)?,
            materialization_tail: copied_word(slot, 28)?,
            setup_handler: decode_branch_link_target(copied_word(slot, 12)?, slot_vaddr + 12)?,
            guest_x18_offset: x18_access_offset(
                copied_word(
                    slot,
                    if matches!(metadata, GateMetadata::X18 { .. }) {
                        32
                    } else {
                        28
                    },
                )?,
                Opcode::StrUimm,
                metadata.value_scratch()?,
                metadata.anchor_scratch()?,
            )?,
            saved_anchor_scratch_offset: x18_access_offset(
                copied_word(
                    slot,
                    if matches!(metadata, GateMetadata::X18 { .. }) {
                        40
                    } else {
                        36
                    },
                )?,
                Opcode::LdrUimm,
                metadata.anchor_scratch()?,
                metadata.anchor_scratch()?,
            )?,
            saved_value_scratch_offset: x18_access_offset(
                copied_word(
                    slot,
                    if matches!(metadata, GateMetadata::X18 { .. }) {
                        36
                    } else {
                        32
                    },
                )?,
                Opcode::LdrUimm,
                metadata.value_scratch()?,
                metadata.anchor_scratch()?,
            )?,
            fallthrough: return_target,
            taken: matches!(metadata, GateMetadata::X18Conditional { .. })
                .then(|| decode_branch_target(copied_word(slot, 56)?, slot_vaddr + 56))
                .flatten(),
        }),
        _ => None,
    };
    Some(ClassifiedGate {
        slot_offset,
        slot_size: u8::try_from(slot.len()).ok()?,
        commit_offset: u8::try_from(metadata.commit_offset()).ok()?,
        original_site: return_target.checked_sub(4)?,
        metadata,
        x18,
    })
}

fn is_tpidr_access(word: u32, opcode: Opcode, rt: u8, rn: u8) -> bool {
    if word & !LDST_UIMM12_IMM_MASK != opcode.bits() | (u32::from(rn) << RN_SHIFT) | u32::from(rt) {
        return false;
    }
    let encoded = (word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
    valid_emitted_tpidr_offset(encoded * u32::from(GUEST_TPIDR_OFFSET_ALIGN))
}

fn copied_word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + INSN_BYTES)?.try_into().ok()?,
    ))
}

fn x18_access_offset(word: u32, opcode: Opcode, rt: u8, rn: u8) -> Option<u16> {
    (word & !LDST_UIMM12_IMM_MASK == opcode.bits() | (u32::from(rn) << RN_SHIFT) | u32::from(rt))
        .then(|| {
            u16::try_from(
                ((word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT)
                    * u32::from(GUEST_TPIDR_OFFSET_ALIGN),
            )
            .ok()
        })
        .flatten()
}

fn exact_x18_offset_role(offset: u16, placeholder: u16) -> bool {
    offset == placeholder
        || (offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN)
            && (MIN_GUEST_TPIDR_OFFSET..=MAX_REAL_X18_GATE_OFFSET).contains(&offset))
}

fn exact_x18_site_offsets(offsets: [Option<u16>; 3]) -> bool {
    if offsets
        == [
            Some(GUEST_X18_OFFSET_PLACEHOLDER),
            Some(SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER),
            Some(SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER),
        ]
    {
        return true;
    }
    offsets.into_iter().enumerate().all(|(index, offset)| {
        offset.is_some_and(|offset| {
            exact_x18_offset_role(offset, 0)
                && offset <= MAX_REAL_X18_GATE_OFFSET
                && !offsets[..index].contains(&Some(offset))
        })
    })
}

fn validate_x18_setup(record: &[u8], anchor_scratch: u8, value_scratch: u8, host: Host) -> bool {
    let [
        Some(word0),
        Some(word1),
        Some(word2),
        Some(word3),
        Some(word4),
        Some(word5),
        Some(word6),
        Some(word7),
    ] = [0, 4, 8, 12, 16, 20, 24, 28].map(|offset| copied_word(record, offset))
    else {
        return false;
    };
    let decoded = [word0, word1, word2, word3, word4, word5, word6, word7];
    let offsets = [
        x18_access_offset(decoded[2], Opcode::StrUimm, value_scratch, anchor_scratch),
        x18_access_offset(decoded[4], Opcode::StrUimm, value_scratch, anchor_scratch),
        x18_access_offset(decoded[5], Opcode::LdrUimm, value_scratch, anchor_scratch),
    ];
    decoded[0] == host.anchor_read(anchor_scratch).encode().unwrap()
        && decoded[1]
            == Insn::LdrUimm {
                rt: value_scratch,
                rn: SP,
                imm_bytes: 0,
            }
            .encode()
            .unwrap()
        && decoded[3]
            == Insn::LdrUimm {
                rt: value_scratch,
                rn: SP,
                imm_bytes: 8,
            }
            .encode()
            .unwrap()
        && (offsets
            == [
                Some(SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER),
                Some(SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER),
                Some(GUEST_X18_OFFSET_PLACEHOLDER),
            ]
            || offsets.into_iter().enumerate().all(|(index, offset)| {
                offset.is_some_and(|offset| {
                    offset <= MAX_REAL_X18_GATE_OFFSET
                        && exact_x18_offset_role(offset, 0)
                        && !offsets[..index].contains(&Some(offset))
                })
            }))
        && decoded[6] == Insn::Ret(30).encode().unwrap()
        && EncodedGateMetadata(decoded[7]).decode()
            == Some(GateMetadata::X18 {
                anchor_scratch,
                value_scratch,
            })
}

fn exact_x18_transformation(
    original_word: u32,
    transformed_word: u32,
    materialization_tail: u32,
    anchor_scratch: u8,
    value_scratch: u8,
    original_pc: Option<u64>,
    transformed_pc: u64,
) -> bool {
    if let Some(original_pc) = original_pc
        && let Ok(instruction) = decode_instruction(original_word)
        && let Some(PatchKind::X18(X18TransformResult::Supported(transformation))) =
            classify_decoded_x18_at(original_word, instruction, original_pc)
        && transformation.pcrel.is_some()
    {
        let same_target = match transformation.pcrel.unwrap() {
            X18Pcrel::Adr(_) => match decode_adr_target(original_word, original_pc, 18) {
                PcrelTarget::Target {
                    address: original, ..
                } => {
                    decode_adrp_add_target_for_rd(
                        transformed_word,
                        materialization_tail,
                        transformed_pc,
                        value_scratch,
                    ) == Some(original)
                }
                _ => false,
            },
            X18Pcrel::Adrp(_) => match (
                decode_adrp_target(transformed_word, transformed_pc, value_scratch),
                decode_adrp_target(original_word, original_pc, 18),
            ) {
                (
                    PcrelTarget::Target {
                        address: transformed,
                        ..
                    },
                    PcrelTarget::Target {
                        address: original, ..
                    },
                ) => transformed == original && materialization_tail == NOP,
                _ => false,
            },
        };
        return transformation.original_word == original_word
            && same_target
            && transformation.anchor_scratch == anchor_scratch
            && transformation.value_scratch == value_scratch;
    }
    matches!(
        transform_x18_instruction(original_word),
        X18TransformResult::Supported(transformation)
            if transformation.original_word == original_word
                && transformation.word == transformed_word
                && materialization_tail == NOP
                && transformation.anchor_scratch == anchor_scratch
                && transformation.value_scratch == value_scratch
    )
}

fn decode_adrp_add_target_for_rd(adrp: u32, add: u32, pc: u64, rd: u8) -> Option<u64> {
    if adrp & ADRP_SHAPE_MASK != Opcode::Adrp.bits() | u32::from(rd)
        || add & ADD_IMM_SHAPE_MASK
            != Opcode::AddImm.bits() | (u32::from(rd) << RN_SHIFT) | u32::from(rd)
    {
        return None;
    }
    let PcrelTarget::Target { address: page, .. } = decode_adrp_target(adrp, pc, rd) else {
        return None;
    };
    page.checked_add(u64::from((add >> 10) & 0xfff))
}

fn exact_x18_unplaced_transformation(
    original_word: u32,
    transformed_word: u32,
    materialization_tail: u32,
    anchor_scratch: u8,
    value_scratch: u8,
    original_pc: Option<i64>,
    transformed_pc: Option<i64>,
) -> bool {
    let byte_delta = |word: u32, rd: u8| {
        (word & ADRP_SHAPE_MASK == Opcode::Adr.bits() | u32::from(rd)).then(|| {
            let immlo = i64::from((word >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
            let immhi = i64::from((word >> RN_SHIFT) & IMM19_MASK);
            sign_extend((immhi << 2) | immlo, IMM21_BITS)
        })
    };
    let page_delta = |word: u32, rd: u8| {
        (word & ADRP_SHAPE_MASK == Opcode::Adrp.bits() | u32::from(rd)).then(|| {
            let immlo = i64::from((word >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
            let immhi = i64::from((word >> RN_SHIFT) & IMM19_MASK);
            sign_extend((immhi << 2) | immlo, IMM21_BITS) << ADRP_PAGE_SHIFT
        })
    };
    if let (
        Some(original_pc),
        Some(transformed_pc),
        Some(original_delta),
        Some(transformed_delta),
    ) = (
        original_pc,
        transformed_pc,
        page_delta(original_word, 18),
        page_delta(transformed_word, value_scratch),
    ) {
        return materialization_tail == NOP
            && (original_pc & !PAGE_OFFSET_MASK.cast_signed()).checked_add(original_delta)
                == (transformed_pc & !PAGE_OFFSET_MASK.cast_signed())
                    .checked_add(transformed_delta)
            && decode_instruction(original_word).is_ok_and(|instruction| {
                select_x18_scratches(&instruction) == Some((value_scratch, anchor_scratch))
            });
    }
    if let (
        Some(original_pc),
        Some(transformed_pc),
        Some(original_delta),
        Some(transformed_page_delta),
    ) = (
        original_pc,
        transformed_pc,
        byte_delta(original_word, 18),
        page_delta(transformed_word, value_scratch),
    ) {
        let add_imm = (materialization_tail & ADD_IMM_SHAPE_MASK
            == Opcode::AddImm.bits()
                | (u32::from(value_scratch) << RN_SHIFT)
                | u32::from(value_scratch))
        .then_some(i64::from((materialization_tail >> 10) & 0xfff));
        return add_imm.is_some_and(|add_imm| {
            original_pc.checked_add(original_delta)
                == (transformed_pc & !PAGE_OFFSET_MASK.cast_signed())
                    .checked_add(transformed_page_delta)
                    .and_then(|page| page.checked_add(add_imm))
        }) && decode_instruction(original_word).is_ok_and(|instruction| {
            select_x18_scratches(&instruction) == Some((value_scratch, anchor_scratch))
        });
    }
    exact_x18_transformation(
        original_word,
        transformed_word,
        materialization_tail,
        anchor_scratch,
        value_scratch,
        None,
        0,
    )
}

fn exact_x18_conditional(original_word: u32, condition_word: u32, value_scratch: u8) -> bool {
    let Ok(instruction) = decode_instruction(original_word) else {
        return false;
    };
    let Some(PatchKind::X18Conditional(branch)) =
        classify_decoded_x18_at(original_word, instruction, 1 << 32)
    else {
        return false;
    };
    match branch.kind {
        X18ConditionalKind::Compare => Insn::CompareBranch {
            rt: value_scratch,
            offset: 20,
            nonzero: branch.nonzero,
            width: branch.width,
        },
        X18ConditionalKind::Test { bit } => Insn::TestBranch {
            rt: value_scratch,
            offset: 20,
            nonzero: branch.nonzero,
            bit,
        },
    }
    .encode()
        == Some(condition_word)
        && branch.value_scratch == value_scratch
}

fn decoded_conditional_offset(original_word: u32) -> Option<i64> {
    let instruction = decode_instruction(original_word).ok()?;
    if !matches!(
        instruction.opcode,
        DecodedOpcode::CBZ | DecodedOpcode::CBNZ | DecodedOpcode::TBZ | DecodedOpcode::TBNZ
    ) {
        return None;
    }
    instruction
        .operands
        .iter()
        .find_map(|operand| match operand {
            Operand::PCOffset(offset) => Some(*offset),
            _ => None,
        })
}

fn valid_emitted_tpidr_offset(offset: u32) -> bool {
    offset == u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER)
        || (offset.is_multiple_of(u32::from(GUEST_TPIDR_OFFSET_ALIGN))
            && (u32::from(MIN_GUEST_TPIDR_OFFSET)..u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER))
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

fn decode_branch_link_target(word: u32, pc: u64) -> Option<u64> {
    if word & OPCODE_TOP6_MASK != Opcode::Bl.bits() {
        return None;
    }
    let imm26 = i64::from(word & IMM26_MASK);
    pc.checked_add_signed(pcrel_bytes(imm26, IMM26_BITS))
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
    if adrp & ADRP_SHAPE_MASK != Opcode::Adrp.bits() | u32::from(X16)
        || add & ADD_IMM_SHAPE_MASK
            != Opcode::AddImm.bits() | (u32::from(X16) << RN_SHIFT) | u32::from(X16)
    {
        return None;
    }
    let immlo = i64::from((adrp >> ADR_IMMLO_SHIFT) & ADR_IMMLO_MASK);
    let immhi = i64::from((adrp >> RN_SHIFT) & IMM19_MASK);
    let imm21 = (immhi << 2) | immlo;
    let page_delta = sign_extend(imm21, IMM21_BITS) << ADRP_PAGE_SHIFT;
    let page = (pc & !PAGE_OFFSET_MASK).checked_add_signed(page_delta)?;
    page.checked_add(u64::from(add >> RT2_SHIFT) & PAGE_OFFSET_MASK)
}

// ============================================================
// Load-time guest thread-pointer offset patching
// ============================================================

/// Bits \[31:10] of an unsigned-offset load/store: everything except `Rn`
/// (\[9:5]) and `Rt` (\[4:0]), i.e. the opcode *and* the scaled `imm12`.
const LDST_UIMM12_OPCODE_AND_IMM_MASK: u32 = 0xFFFF_FC00;
/// The scaled 12-bit immediate field of an unsigned-offset load/store, \[21:10].
const LDST_UIMM12_IMM_MASK: u32 = 0x003F_FC00;
/// Bit position of that immediate field.
const LDST_UIMM12_IMM_SHIFT: u32 = 10;

/// Patches every gate and fails if any executable placeholder remains.
///
/// # Errors
///
/// Propagates errors from [`patch_guest_tpidr_offset`] and fails if any
/// placeholder survives.
pub fn finalize_trampoline_gates(trampoline: &mut [u8], offset: u16) -> Result<()> {
    let mut staged = trampoline.to_vec();
    patch_guest_tpidr_offset(&mut staged, offset)?;
    if let Some(at) = find_guest_tpidr_placeholder(&staged) {
        return Err(Error::TrampolinePatchFailure(format!(
            "trampoline byte {at} still holds the guest thread-pointer placeholder after patching \
             with offset {offset}"
        )));
    }
    trampoline.copy_from_slice(&staged);
    Ok(())
}

/// Transactionally validates and finalizes all TPIDR and x18 gate offsets.
pub fn finalize_trampoline_gates_with_offsets(
    trampoline: &mut [u8],
    offsets: Aarch64GateOffsets,
) -> Result<()> {
    finalize_trampoline_gates_for_host(trampoline, offsets, crate::TargetHost::Linux)
}

/// Host-aware structured finalization of all TPIDR and x18 gate offsets.
pub fn finalize_trampoline_gates_for_host(
    trampoline: &mut [u8],
    offsets: Aarch64GateOffsets,
    target_host: crate::TargetHost,
) -> Result<()> {
    let mut staged = trampoline.to_vec();
    let patches = validate_trampoline_and_collect_patches(
        &staged,
        offsets.guest_tpidr(),
        Some(offsets),
        host_for_target(target_host),
    )?;
    for (at, replacement) in patches {
        patch_ldst_offset(&mut staged, at, replacement);
    }
    validate_trampoline_and_collect_patches(
        &staged,
        offsets.guest_tpidr(),
        Some(offsets),
        host_for_target(target_host),
    )?;
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
/// [`GUEST_TPIDR_OFFSET_PLACEHOLDER`], preserving the original TPIDR ABI. Also fails
/// if the blob is not a well-formed trampoline: too short for the shared
/// prologue, not a whole number of instruction words, or holding a placeholder
/// in a shape no gate emits.
///
/// # Panics
///
/// Panics if a validated slot is shorter than its own metadata word, which the
/// slot templates make impossible.
pub fn patch_guest_tpidr_offset(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    if !is_patchable_guest_tpidr_offset(offset) {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest thread-pointer offset {offset} is not a legitimate gate target: it must be a \
             multiple of {GUEST_TPIDR_OFFSET_ALIGN}, at least {MIN_GUEST_TPIDR_OFFSET} so it \
             cannot land on the host's own per-thread state, and below \
             {GUEST_TPIDR_OFFSET_PLACEHOLDER} so a patched gate is never mistaken for an \
             unpatched one"
        )));
    }

    let patches = validate_trampoline_and_collect_patches(trampoline, offset, None, Host::Linux)?;
    for &(at, replacement) in &patches {
        patch_ldst_offset(trampoline, at, replacement);
    }
    Ok(patches.len())
}

fn patch_ldst_offset(trampoline: &mut [u8], at: usize, offset: u16) {
    let word = &mut trampoline[at..at + INSN_BYTES];
    let insn = u32::from_le_bytes(word.try_into().expect("four-byte patch offset"));
    let immediate = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;
    word.copy_from_slice(&((insn & !LDST_UIMM12_IMM_MASK) | immediate).to_le_bytes());
}

/// Validates every slot and returns the offsets of the thread-pointer
/// instructions still holding the placeholder.
///
/// A trampoline arrives from the guest's own file and the slot templates accept
/// any encodable offset, so a thread-pointer access holding neither the
/// placeholder nor `expected_offset` is one this rewriter did not put there and
/// is rejected rather than left alone.
fn validate_trampoline_and_collect_patches(
    trampoline: &[u8],
    expected_offset: u16,
    x18_offsets: Option<Aarch64GateOffsets>,
    host: Host,
) -> Result<Vec<(usize, u16)>> {
    let parsed = parse_validated_trampoline(trampoline, host).map_err(|_| {
        Error::TrampolinePatchFailure("malformed AArch64 trampoline structure".into())
    })?;
    if !parsed.setups.is_empty() && x18_offsets.is_none() {
        return Err(Error::TrampolinePatchFailure(
            "legacy AArch64 finalizer cannot finalize x18 structures".into(),
        ));
    }
    let mut patch_offsets = Vec::new();
    for setup in &parsed.setups {
        let offsets = x18_offsets.expect("x18 offsets checked above");
        let GateMetadata::X18 {
            anchor_scratch,
            value_scratch,
        } = setup.metadata
        else {
            unreachable!()
        };
        for (relative, opcode, placeholder, replacement) in [
            (
                8,
                Opcode::StrUimm,
                SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
                offsets.saved_anchor_scratch(),
            ),
            (
                16,
                Opcode::StrUimm,
                SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
                offsets.saved_value_scratch(),
            ),
            (
                20,
                Opcode::LdrUimm,
                GUEST_X18_OFFSET_PLACEHOLDER,
                offsets.guest_x18(),
            ),
        ] {
            let at = setup.offset + relative;
            if !collect_exact_x18_access(
                &mut patch_offsets,
                copied_word(trampoline, at).unwrap(),
                at,
                opcode,
                value_scratch,
                anchor_scratch,
                (placeholder, replacement),
            ) {
                return Err(Error::TrampolinePatchFailure(format!(
                    "malformed AArch64 x18 setup access at byte {at}"
                )));
            }
        }
    }
    for slot in &parsed.slots {
        let instruction_offset = match slot.metadata {
            GateMetadata::MrsTpidr { .. } => Some(slot.offset + 4),
            GateMetadata::MsrTpidr { .. } => Some(slot.offset + 20),
            GateMetadata::Svc
            | GateMetadata::X18 { .. }
            | GateMetadata::X18Conditional { .. }
            | GateMetadata::X18Br => None,
        };
        if let Some(offset) = instruction_offset {
            let insn =
                u32::from_le_bytes(trampoline[offset..offset + INSN_BYTES].try_into().unwrap());
            let encoded = (insn & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
            let gate_offset = encoded * u32::from(GUEST_TPIDR_OFFSET_ALIGN);
            if gate_offset == u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER) {
                patch_offsets.push((offset, expected_offset));
            } else if gate_offset != u32::from(expected_offset) {
                return Err(Error::TrampolinePatchFailure(format!(
                    "AArch64 gate at byte {offset} addresses the host thread pointer at \
                     {gate_offset}, which is neither the placeholder nor the offset being \
                     patched in ({expected_offset})"
                )));
            }
        }
        if let GateMetadata::X18 {
            anchor_scratch,
            value_scratch,
        }
        | GateMetadata::X18Conditional {
            anchor_scratch,
            value_scratch,
        } = slot.metadata
        {
            let offsets = x18_offsets.expect("x18 offsets checked above");
            let teardown_starts: &[usize] =
                if matches!(slot.metadata, GateMetadata::X18Conditional { .. }) {
                    &[28, 44]
                } else {
                    &[32]
                };
            for path in teardown_starts {
                for (relative, opcode, rt, placeholder, replacement) in [
                    (
                        *path,
                        Opcode::StrUimm,
                        value_scratch,
                        GUEST_X18_OFFSET_PLACEHOLDER,
                        offsets.guest_x18(),
                    ),
                    (
                        *path + 4,
                        Opcode::LdrUimm,
                        value_scratch,
                        SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
                        offsets.saved_value_scratch(),
                    ),
                    (
                        *path + 8,
                        Opcode::LdrUimm,
                        anchor_scratch,
                        SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
                        offsets.saved_anchor_scratch(),
                    ),
                ] {
                    let at = slot.offset + relative;
                    let word = u32::from_le_bytes(trampoline[at..at + 4].try_into().unwrap());
                    if !collect_exact_x18_access(
                        &mut patch_offsets,
                        word,
                        at,
                        opcode,
                        rt,
                        anchor_scratch,
                        (placeholder, replacement),
                    ) {
                        return Err(Error::TrampolinePatchFailure(format!(
                            "malformed x18 access at byte {at}"
                        )));
                    }
                }
            }
        }
    }
    Ok(patch_offsets)
}

fn collect_exact_x18_access(
    patches: &mut Vec<(usize, u16)>,
    word: u32,
    at: usize,
    opcode: Opcode,
    rt: u8,
    rn: u8,
    offsets: (u16, u16),
) -> bool {
    if word & !LDST_UIMM12_IMM_MASK != opcode.bits() | (u32::from(rn) << RN_SHIFT) | u32::from(rt) {
        return false;
    }
    let offset =
        ((word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT) as u16 * GUEST_TPIDR_OFFSET_ALIGN;
    if offset == offsets.0 {
        patches.push((at, offsets.1));
        true
    } else {
        offset == offsets.1
    }
}

fn branch_link_local_target(word: u32, pc_offset: i64) -> Option<i64> {
    if word & OPCODE_TOP6_MASK != Opcode::Bl.bits() {
        return None;
    }
    Some(pc_offset + pcrel_bytes(i64::from(word & IMM26_MASK), IMM26_BITS))
}

/// The `imm12` field, already shifted into place, that an unpatched gate's
/// `LDR`/`STR` carries.
fn placeholder_imm_field() -> u32 {
    u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT
}

/// Byte offset of the first instruction in `trampoline` that still carries the
/// emitted placeholder, or `None` if no gate is left unpatched. This is the
/// loader's proof obligation: an unpatched gate does not fault, so its absence
/// has to be checked rather than assumed.
///
/// Skips the header's callback slot, which is a 64-bit address and could
/// bit-for-bit resemble a gate instruction. Matches the shape-independent
/// opcode-and-immediate pattern, so a placeholder-bearing word in a shape no
/// gate emits is still reported.
///
/// # Panics
///
/// Panics if a four-byte window fails to convert to an array, which the
/// chunked iteration makes impossible.
pub fn find_guest_tpidr_placeholder(trampoline: &[u8]) -> Option<usize> {
    let placeholder_imm = placeholder_imm_field();
    let ldr_pattern = Opcode::LdrUimm.bits() | placeholder_imm;
    let str_pattern = Opcode::StrUimm.bits() | placeholder_imm;

    trampoline
        .get(FIRST_SCANNABLE_OFFSET..)?
        .chunks_exact(4)
        .enumerate()
        .find_map(|(index, word)| {
            let offset = FIRST_SCANNABLE_OFFSET + index * 4;
            if is_valid_x18_guest_instruction_word(trampoline, offset) {
                return None;
            }
            let insn = u32::from_le_bytes(word.try_into().expect("chunks_exact(4) yields 4 bytes"));
            let opcode_and_imm = insn & LDST_UIMM12_OPCODE_AND_IMM_MASK;
            (opcode_and_imm == ldr_pattern || opcode_and_imm == str_pattern).then_some(offset)
        })
}

fn is_valid_x18_guest_instruction_word(trampoline: &[u8], offset: usize) -> bool {
    [24usize, 48].into_iter().any(|word_offset| {
        let Some(start) = offset.checked_sub(word_offset) else {
            return false;
        };
        if !start.is_multiple_of(GATE_ALIGNMENT) {
            return false;
        }
        let Some(slot) = trampoline.get(start..start + X18_SLOT_BYTES) else {
            return false;
        };
        let Some(metadata) = copied_word(slot, X18_SLOT_BYTES - GATE_METADATA_BYTES)
            .and_then(|word| EncodedGateMetadata(word).decode())
        else {
            return false;
        };
        matches!(metadata, GateMetadata::X18 { .. })
            && validate_gate_slot_inner(
                slot,
                SlotAddressing::Unplaced {
                    slot_offset: start as u64,
                },
                metadata,
            )
    })
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
        let Some(offset) = self.delta_to(target_vaddr)? else {
            return Ok(false);
        };
        let Some(word) = Insn::B(offset).encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    fn call_to(&mut self, target_vaddr: u64) -> Result<bool> {
        let Some(offset) = self.delta_to(target_vaddr)? else {
            return Ok(false);
        };
        let Some(word) = Insn::Bl(offset).encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// `LDR Xt, =target` — PC-relative literal load of an absolute address.
    fn ldr_literal(&mut self, rt: u8, target_vaddr: u64) -> Result<()> {
        let offset = self.delta_to(target_vaddr)?.ok_or_else(|| {
            Error::AddressOverflow("LDR literal displacement does not fit i64".into())
        })?;
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
        let Some(byte_off) = self.delta_to(target_vaddr)? else {
            return Ok(false);
        };
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
        let Some(page_bytes) =
            checked_pcrel_difference(target_vaddr & !PAGE_OFFSET_MASK, here & !PAGE_OFFSET_MASK)
        else {
            return Ok(false);
        };
        let page_off = page_bytes >> 12;
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
    fn delta_to(&self, target_vaddr: u64) -> Result<Option<i64>> {
        Ok(checked_pcrel_difference(target_vaddr, self.here()?))
    }

    /// Return the emitted bytes.
    fn finish(self) -> Vec<u8> {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaxpeax_arm::armv8::a64::{Operand, ShiftStyle, SizeCode};

    #[test]
    fn decoder_finds_integer_x18_in_real_instructions() {
        for word in [
            0xaa00_03f2, // mov x18, x0
            0x0b12_0063, // add w3, w3, w18
            0xf940_0642, // ldr x2, [x18, #8]
            0xf832_7824, // str x4, [x1, x18, lsl #3]
            0xa906_4bee, // stp x14, x18, [sp, #0x60]
            0x4832_7ed4, // casp x18, x19, x20, x21, [x22]
        ] {
            assert!(instruction_uses_x18(word).unwrap(), "word {word:#010x}");
        }
    }

    #[test]
    fn decoder_ignores_non_gpr_uses_of_the_number_18() {
        for word in [
            0x4eb2_1e50, // mov v16.16b, v18.16b
            0xd280_0240, // mov x0, #18
            0x1400_0012, // b .+72 (raw imm26 is 18)
            0xd503_201f, // nop
            0xaa00_03e1, // mov x1, x0
        ] {
            assert!(!instruction_uses_x18(word).unwrap(), "word {word:#010x}");
        }
    }

    #[test]
    fn decoder_errors_are_returned() {
        assert_eq!(
            instruction_uses_x18(0xffff_ffff),
            Err(X18DiscoveryError::Decode(DecodeError::InvalidOpcode))
        );
    }

    #[test]
    fn operand_walker_covers_every_gpr_bearing_variant() {
        let x = SizeCode::X;
        let lsl = ShiftStyle::LSL;
        for operand in [
            Operand::Register(x, 18),
            Operand::RegisterPair(x, 18),
            // CASP only permits even pair starts, but the walker must honor the
            // public Operand contract that a pair also names `first + 1`.
            Operand::RegisterPair(x, 17),
            Operand::RegisterOrSP(x, 18),
            Operand::RegShift(lsl, 3, x, 18),
            Operand::RegRegOffset(18, 0, x, lsl, 0),
            Operand::RegRegOffset(0, 18, x, lsl, 0),
            Operand::RegPreIndex(18, 8, false),
            Operand::RegPostIndex(18, 8),
            Operand::RegPostIndexReg(18, 0),
            Operand::RegPostIndexReg(0, 18),
        ] {
            assert!(operand_uses_x18(&operand), "operand {operand:?}");
        }

        assert!(!operand_uses_x18(&Operand::RegisterPair(x, u16::MAX)));
        assert!(!operand_uses_x18(&Operand::SIMDRegister(
            yaxpeax_arm::armv8::a64::SIMDSizeCode::Q,
            18,
        )));
    }

    fn supported_x18_rewrite(word: u32) -> X18Transformation {
        match transform_x18_instruction(word) {
            X18TransformResult::Supported(transformation) => transformation,
            X18TransformResult::Unsupported(_) => panic!("word {word:#010x} was unsupported"),
        }
    }

    #[test]
    fn transforms_required_x18_field_layouts() {
        for (word, transformed) in [
            (0xaa00_03f2, 0xaa00_03f1), // mov x18, x0: Rd
            (0xaa12_03e0, 0xaa11_03e0), // mov x0, x18: Rm
            (0x0b12_0063, 0x0b11_0063), // add w3, w3, w18: Rm
            (0xf940_0642, 0xf940_0622), // ldr x2, [x18, #8]: Rn
            (0xf832_7824, 0xf831_7824), // str x4, [x1, x18, lsl #3]: Rm index
            (0xa906_4bee, 0xa906_47ee), // stp x14, x18, [sp, #0x60]: Rt2
        ] {
            let rewrite = supported_x18_rewrite(word);
            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
            assert_eq!(rewrite.value_scratch, 17);
            assert_ne!(rewrite.anchor_scratch, rewrite.value_scratch);
        }
    }

    #[test]
    fn transforms_multiply_add_family_register_fields() {
        for (word, transformed) in [
            (0x1b12_7c63, 0x1b11_7c63), // mul w3, w3, w18: MADD Rm
            (0x9b08_486b, 0x9b08_446b), // madd x11, x3, x8, x18: Ra
            (0x9b12_8c41, 0x9b11_8c41), // msub x1, x2, x18, x3: Rm
            (0x9b25_48a4, 0x9b25_44a4), // smaddl x4, w5, w5, x18: Ra
            (0x9b32_8c41, 0x9b31_8c41), // smsubl x1, w2, w18, x3: Rm
            (0x9ba3_4841, 0x9ba3_4441), // umaddl x1, w2, w3, x18: Ra
            (0x9bb2_8c41, 0x9bb1_8c41), // umsubl x1, w2, w18, x3: Rm
        ] {
            let rewrite = supported_x18_rewrite(word);
            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
        }
    }

    #[test]
    fn transforms_multiply_high_rm_fields() {
        for (word, opcode, transformed) in [
            // Exact failures from Python 3.12's `_decimal` extension.
            (0x9bd2_7ce4, DecodedOpcode::UMULH, 0x9bd1_7ce4),
            (0x9bd2_7ce7, DecodedOpcode::UMULH, 0x9bd1_7ce7),
            (0x9b52_7ce4, DecodedOpcode::SMULH, 0x9b51_7ce4),
        ] {
            let original = decode_instruction(word).unwrap();
            assert_eq!(original.opcode, opcode, "word {word:#010x}");
            assert!(matches!(
                original.operands[2],
                Operand::Register(SizeCode::X, 18)
            ));

            let rewrite = supported_x18_rewrite(word);

            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
            let rewritten = decode_instruction(rewrite.word).unwrap();
            assert_eq!(rewritten.opcode, original.opcode);
            assert_eq!(
                rewritten.operands[2],
                Operand::Register(SizeCode::X, u16::from(rewrite.value_scratch))
            );
        }
    }

    #[test]
    fn transforms_conditional_compare_register_fields() {
        for (word, transformed) in [
            (0xfa5e_1244, 0xfa5e_1224), // ccmp x18, x30, #4, ne: Rn
            (0x7a52_1344, 0x7a51_1344), // ccmp w26, w18, #4, ne: Rm
            (0xba52_1244, 0xba51_1224), // ccmn x18, x18, #4, ne: Rn and Rm
            (0x3a52_1144, 0x3a51_1144), // ccmn w10, w18, #4, ne: Rm
        ] {
            let rewrite = supported_x18_rewrite(word);
            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
        }
    }

    #[test]
    fn transforms_variable_shift_and_conditional_select_rm_fields() {
        for (word, transformed) in [
            (0x9ad2_25d2, 0x9ad1_25d1), // lsr x18, x14, x18: Rd and Rm
            (0x1a92_1146, 0x1a91_1146), // csel w6, w10, w18, ne: Rm
        ] {
            let rewrite = supported_x18_rewrite(word);
            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
            assert_eq!(
                decode_instruction(rewrite.word).unwrap().opcode,
                decode_instruction(word).unwrap().opcode,
            );
        }
    }

    #[test]
    fn transforms_extr_sources_without_changing_immediates() {
        // Independently assembled with LLVM 18. ROR is the tied-source EXTR alias.
        for (word, transformed) in [
            (0x1392_1e40, 0x1391_1e20), // ror w0, w18, #7: Rn and Rm
            (0x93d2_4e41, 0x93d1_4e21), // ror x1, x18, #19: Rn and Rm
            (0x1383_1642, 0x1383_1622), // extr w2, w18, w3, #5: Rn only
            (0x93d2_5ca4, 0x93d1_5ca4), // extr x4, x5, x18, #23: Rm only
            (0x93d2_a646, 0x93d1_a626), // ror x6, x18, #41: Rn and Rm
            // Representative encodings from the local Python 3.12 `_sha2` module.
            (0x1392_2e4a, 0x1391_2e2a), // ror w10, w18, #11
            (0x1397_4af2, 0x1397_4af1), // ror w18, w23, #18
            (0x93d2_4a58, 0x93d1_4a38), // ror x24, x18, #18
            (0x93ce_21d2, 0x93ce_21d1), // ror x18, x14, #8
        ] {
            let original = decode_instruction(word).unwrap();
            assert_eq!(original.opcode, DecodedOpcode::EXTR);

            let rewrite = supported_x18_rewrite(word);

            assert_eq!(rewrite.word, transformed, "word {word:#010x}");
            let rewritten = decode_instruction(rewrite.word).unwrap();
            assert_eq!(rewritten.opcode, original.opcode);
            assert_eq!(rewritten.operands[3], original.operands[3]);
        }
    }

    #[test]
    fn scratch_selection_avoids_all_explicit_gprs() {
        // add x18, x17, x16: both preferred scratches occur explicitly.
        let rewrite = supported_x18_rewrite(0x8b10_0232);
        assert_eq!(rewrite.value_scratch, 15);
        assert_eq!(rewrite.anchor_scratch, 14);
        assert_eq!(rewrite.word, 0x8b10_022f);
    }

    #[test]
    fn decoder_recognized_unmapped_x18_layout_is_unsupported() {
        let word = 0xd61f_0240; // br x18: operand 0 is encoded in Rn, not Rd
        assert!(instruction_uses_x18(word).unwrap());
        assert_eq!(
            transform_x18_instruction(word),
            X18TransformResult::Unsupported(X18TransformFailure::PcRelativeOrControlFlow)
        );
    }

    #[test]
    fn br_x18_emits_exact_terminal_gate_without_setup_or_scratch() {
        const SITE: u64 = 0x1d0a9c;
        const TRAMPOLINE_BASE: u64 = 0x200000;
        const BR_X18: u32 = 0xd61f_0240;
        let (patched, outcome) = hook_words_opt_with_config(
            &[BR_X18],
            SITE,
            TRAMPOLINE_BASE,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        let slot = GATES_START_OFFSET;

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(outcome.trampoline.len(), slot + X18_BR_SLOT_BYTES);
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), SITE),
            Some(TRAMPOLINE_BASE + slot as u64)
        );
        assert_eq!(
            word_at(&outcome.trampoline, slot),
            Insn::Brk(X18_BR_BRK_IMM).encode().unwrap()
        );
        assert_eq!(
            decode_branch_target(
                word_at(&outcome.trampoline, slot + 4),
                TRAMPOLINE_BASE + (slot + 4) as u64,
            ),
            Some(SITE + 4)
        );
        assert_eq!(word_at(&outcome.trampoline, slot + 8), BR_X18);
        assert_eq!(
            decode_gate_metadata_word(word_at(&outcome.trampoline, slot + 12)),
            Some(GateMetadata::X18Br)
        );
    }

    #[test]
    fn only_exact_br_x18_gets_the_terminal_gate() {
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xd61f_0220],
            0x1000,
            0x400000,
            RewriteConfig::new(Host::Linux, true),
        );
        assert!(outcome.is_none());
        assert_eq!(word_at(&patched, 0), 0xd61f_0220);

        for word in [0xd63f_0240, 0xd65f_0240] {
            let (_, outcome) = hook_words_opt_with_config(
                &[word],
                0x1000,
                0x400000,
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();
            assert_eq!(outcome.trapped_sites, vec![0x1000], "word {word:#010x}");
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }
    }

    #[test]
    fn terminal_br_gate_classifies_only_brk_and_rejects_malformed_descriptor() {
        let (_, outcome) = hook_words_opt_with_config(
            &[0xd61f_0240],
            0x1000,
            0x400000,
            RewriteConfig::new(Host::Linux, true),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let slot = GATES_START_OFFSET;
        let classified = classify_gate_pc(&trampoline, 0x400000, 0x400000 + slot as u64).unwrap();
        assert_eq!(classified.metadata(), GateMetadata::X18Br);
        assert_eq!(classified.original_site(), 0x1000);
        assert!(classify_gate_pc(&trampoline, 0x400000, 0x400000 + slot as u64 + 4).is_none());
        assert_eq!(
            classify_x18_topology_for_host(&trampoline, crate::TargetHost::Linux),
            X18Topology::Valid
        );
        finalize_trampoline_gates_with_offsets(
            &mut trampoline,
            Aarch64GateOffsets::new(96, 104, 112, 120).unwrap(),
        )
        .unwrap();

        trampoline[slot + 8..slot + 12].copy_from_slice(&0xd63f_0240u32.to_le_bytes());
        assert!(classify_gate_pc(&trampoline, 0x400000, 0x400000 + slot as u64).is_none());
        assert_eq!(
            classify_x18_topology_for_host(&trampoline, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
        assert!(
            finalize_trampoline_gates_with_offsets(
                &mut trampoline,
                Aarch64GateOffsets::new(96, 104, 112, 120).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn relocation_unsafe_x18_instructions_are_unsupported() {
        for (word, opcode) in [
            (0xf000_0012, DecodedOpcode::ADRP), // adrp x18, ...
            (0xd63f_0240, DecodedOpcode::BLR),  // blr x18
            (0x5800_0012, DecodedOpcode::LDR),  // ldr x18, literal at PC
        ] {
            let instruction = decode_instruction(word).unwrap();
            assert_eq!(instruction.opcode, opcode, "word {word:#010x}");
            assert!(instruction_uses_x18(word).unwrap(), "word {word:#010x}");
            assert_eq!(
                transform_x18_instruction(word),
                X18TransformResult::Unsupported(X18TransformFailure::PcRelativeOrControlFlow),
                "word {word:#010x}"
            );
        }
    }

    #[test]
    fn x18_adrp_gate_relocates_the_original_absolute_page_target() {
        const SITE: u64 = 0x111e08;
        const TRAMPOLINE_BASE: u64 = 0x200000;
        let original = 0xf000_0012; // adrp x18, 0x114000 at SITE
        let (patched, outcome) = hook_words_opt_with_config(
            &[original],
            SITE,
            TRAMPOLINE_BASE,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        let slot = GATES_START_OFFSET + X18_SETUP_BYTES;
        let relocated = word_at(&outcome.trampoline, slot + 24);

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), SITE),
            Some(TRAMPOLINE_BASE + slot as u64)
        );
        assert_eq!(
            decode_adrp_target(relocated, TRAMPOLINE_BASE + (slot + 24) as u64, 17),
            PcrelTarget::Target {
                displacement: -0xec000,
                address: 0x114000,
            }
        );
    }

    #[test]
    fn x18_adr_gate_relocates_exact_cryptography_encoding() {
        const SITE: u64 = 0x1d0a90;
        const TRAMPOLINE_BASE: u64 = 0x200000;
        const ORIGINAL: u32 = 0x1000_0092; // adr x18, SITE + 0x10
        let (patched, outcome) = hook_words_opt_with_config(
            &[ORIGINAL],
            SITE,
            TRAMPOLINE_BASE,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        let slot = GATES_START_OFFSET + X18_SETUP_BYTES;
        let relocated_pc = TRAMPOLINE_BASE + (slot + 24) as u64;

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(outcome.trampoline.len(), slot + X18_SLOT_BYTES);
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), SITE),
            Some(TRAMPOLINE_BASE + slot as u64)
        );
        assert_eq!(
            decode_adrp_add_target_for_rd(
                word_at(&outcome.trampoline, slot + 24),
                word_at(&outcome.trampoline, slot + 28),
                relocated_pc,
                17,
            ),
            Some(SITE + 0x10)
        );
    }

    #[test]
    fn x18_adr_gate_beyond_adr_reach_materializes_exact_target() {
        const SITE: u64 = 0x20_00ff8;
        const TARGET: u64 = SITE + 0x20;
        const TRAMPOLINE_BASE: u64 = 0x240_0000;
        let original = Insn::Adr {
            rd: 18,
            byte_off: i64::try_from(TARGET - SITE).unwrap(),
        }
        .encode()
        .unwrap();
        let (patched, outcome) = hook_words_opt_with_config(
            &[original],
            SITE,
            TRAMPOLINE_BASE,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        let slot = GATES_START_OFFSET + X18_SETUP_BYTES;
        let materialization_pc = TRAMPOLINE_BASE + (slot + 24) as u64;

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), SITE),
            Some(TRAMPOLINE_BASE + slot as u64)
        );
        assert_eq!(
            decode_adrp_add_target_for_rd(
                word_at(&outcome.trampoline, slot + 24),
                word_at(&outcome.trampoline, slot + 28),
                materialization_pc,
                17,
            ),
            Some(TARGET)
        );
        assert_eq!(TARGET & PAGE_OFFSET_MASK, 0x18);
    }

    #[test]
    fn x18_adr_materialization_is_pie_invariant_across_page_boundary() {
        const SITE: u64 = 0x20_0ff8;
        const TRAMPOLINE_BASE: u64 = 0x240_0000;
        const BIAS: u64 = 0x7f00_0000_0000;
        let original = Insn::Adr {
            rd: 18,
            byte_off: 0x10,
        }
        .encode()
        .unwrap();
        let words = |site, trampoline_base| {
            let (_, outcome) = hook_words_opt_with_config(
                &[original],
                site,
                trampoline_base,
                RewriteConfig::new(Host::Linux, true),
            );
            let trampoline = outcome.unwrap().trampoline;
            let slot = GATES_START_OFFSET + X18_SETUP_BYTES;
            [
                word_at(&trampoline, slot + 24),
                word_at(&trampoline, slot + 28),
            ]
        };

        assert_eq!(
            words(SITE, TRAMPOLINE_BASE),
            words(SITE + BIAS, TRAMPOLINE_BASE + BIAS)
        );
        let pair = words(SITE, TRAMPOLINE_BASE);
        assert_eq!(
            decode_adrp_add_target_for_rd(
                pair[0],
                pair[1],
                TRAMPOLINE_BASE + (GATES_START_OFFSET + X18_SETUP_BYTES + 24) as u64,
                17,
            ),
            Some(SITE + 0x10)
        );
        assert_eq!((SITE + 0x10) & PAGE_OFFSET_MASK, 8);
    }

    #[test]
    fn x18_adr_relocation_is_invariant_under_pie_load_bias() {
        const SITE: u64 = 0x1d0a90;
        const TRAMPOLINE_BASE: u64 = 0x200000;
        const BIAS: u64 = 0x7f00_0000_0000;
        const ORIGINAL: u32 = 0x1000_0092;
        let relocated_word = |site, trampoline_base| {
            let (_, outcome) = hook_words_opt_with_config(
                &[ORIGINAL],
                site,
                trampoline_base,
                RewriteConfig::new(Host::Linux, true),
            );
            word_at(
                &outcome.unwrap().trampoline,
                GATES_START_OFFSET + X18_SETUP_BYTES + 24,
            )
        };

        assert_eq!(
            relocated_word(SITE, TRAMPOLINE_BASE),
            relocated_word(SITE + BIAS, TRAMPOLINE_BASE + BIAS)
        );
    }

    #[test]
    fn x18_adr_original_target_underflow_and_overflow_trap() {
        let minimum = Insn::Adr {
            rd: 18,
            byte_off: -(1 << 20),
        }
        .encode()
        .unwrap();
        let maximum = Insn::Adr {
            rd: 18,
            byte_off: (1 << 20) - 1,
        }
        .encode()
        .unwrap();
        let brk = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();

        for (word, site) in [(minimum, 0), (maximum, u64::MAX - 15)] {
            let (patched, outcome) = hook_words_opt_with_config(
                &[word],
                site,
                if site == 0 { 0x1000 } else { site - 0x1000 },
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();
            assert_eq!(word_at(&patched, 0), brk, "site {site:#x}");
            assert_eq!(outcome.trapped_sites, vec![site]);
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }
    }

    #[test]
    fn x18_adr_relocated_range_limits_are_exact() {
        let gate_pc = 0x10_0000_0000u64;
        for displacement in [-(1i64 << 20), (1i64 << 20) - 1] {
            let target = gate_pc.checked_add_signed(displacement).unwrap();
            let mut asm = Asm::new(gate_pc);
            assert!(asm.adr(17, target).unwrap(), "displacement {displacement}");
        }
        for target in [gate_pc - ((1u64 << 20) + 1), gate_pc + (1u64 << 20)] {
            let mut asm = Asm::new(gate_pc);
            assert!(!asm.adr(17, target).unwrap());
        }
    }

    #[test]
    fn x18_adrp_original_target_address_overflow_traps() {
        let min_delta = Insn::Adrp {
            rd: 18,
            page_off: -(1 << 20),
        }
        .encode()
        .unwrap();
        let max_delta = Insn::Adrp {
            rd: 18,
            page_off: (1 << 20) - 1,
        }
        .encode()
        .unwrap();
        let brk = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();

        for (word, site) in [(min_delta, 0), (max_delta, !PAGE_OFFSET_MASK)] {
            let instruction = decode_instruction(word).unwrap();
            assert!(matches!(
                classify_decoded_x18_at(word, instruction, site),
                Some(PatchKind::X18(X18TransformResult::Unsupported(_)))
            ));
            let (patched, outcome) = hook_words_opt_with_config(
                &[word],
                site,
                if site == 0 { 0x1000 } else { site - 0x1000 },
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();

            assert_eq!(word_at(&patched, 0), brk, "site {site:#x}");
            assert_eq!(outcome.trapped_sites, vec![site]);
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }
    }

    #[test]
    fn x18_adrp_relocated_page_range_limits_are_exact() {
        for (gate_pc, page_delta) in [
            (0x10_0000_0000u64, -(1i64 << 20)),
            (0x10_0000_0000u64, (1i64 << 20) - 1),
        ] {
            let target = gate_pc
                .checked_add_signed(page_delta << ADRP_PAGE_SHIFT)
                .unwrap();
            let mut asm = Asm::new(gate_pc);
            assert!(asm.adrp(17, target).unwrap(), "page delta {page_delta}");
        }

        for (gate_pc, target) in [
            (0x10_0000_0000, 0x10_0000_0000 - ((1u64 << 20) + 1) * 0x1000),
            (0x10_0000_0000, 0x10_0000_0000 + (1u64 << 20) * 0x1000),
        ] {
            let mut asm = Asm::new(gate_pc);
            assert!(!asm.adrp(17, target).unwrap());
        }
    }

    #[test]
    fn x18_adrp_relocated_page_out_of_range_traps_without_a_gate() {
        const SITE: u64 = 0x20_0000_0000;
        let gate_offset = (GATES_START_OFFSET + X18_SETUP_BYTES) as u64;
        let brk = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();
        for (page_delta, gate_distance) in [
            ((1i64 << 20) - 1, -((1i64 << 27) - 0x1000)),
            (-(1i64 << 20), (1i64 << 27) - 0x1000),
        ] {
            let original = Insn::Adrp {
                rd: 18,
                page_off: page_delta,
            }
            .encode()
            .unwrap();
            let gate = SITE.checked_add_signed(gate_distance).unwrap();
            let trampoline_base = gate - gate_offset;
            let (patched, outcome) = hook_words_opt_with_config(
                &[original],
                SITE,
                trampoline_base,
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();

            assert_eq!(word_at(&patched, 0), brk, "page delta {page_delta}");
            assert_eq!(outcome.trapped_sites, vec![SITE]);
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }
    }

    #[test]
    fn x18_adrp_relocation_is_invariant_under_pie_load_bias() {
        const SITE: u64 = 0x11_1e08;
        const TRAMPOLINE_BASE: u64 = 0x20_0000;
        const BIAS: u64 = 0x7f00_0000_0000;
        let original = 0xf000_0012;
        let relocated_word = |site, trampoline_base| {
            let (_, outcome) = hook_words_opt_with_config(
                &[original],
                site,
                trampoline_base,
                RewriteConfig::new(Host::Linux, true),
            );
            let trampoline = outcome.unwrap().trampoline;
            word_at(&trampoline, GATES_START_OFFSET + X18_SETUP_BYTES + 24)
        };

        assert_eq!(
            relocated_word(SITE, TRAMPOLINE_BASE),
            relocated_word(SITE + BIAS, TRAMPOLINE_BASE + BIAS)
        );
    }

    #[test]
    fn x18_adrp_exact_local_libc_forms_preserve_page_targets() {
        const SITE: u64 = 0x111e08;
        for (word, target) in [
            (0x9000_0012, 0x111000),
            (0xb000_0012, 0x112000),
            (0xd000_0012, 0x113000),
            (0xf000_0012, 0x114000),
        ] {
            let instruction = decode_instruction(word).unwrap();
            let Some(PatchKind::X18(X18TransformResult::Supported(transformation))) =
                classify_decoded_x18_at(word, instruction, SITE)
            else {
                panic!("libc word {word:#010x} was not a supported ADRP x18");
            };
            assert!(matches!(
                decode_adrp_target(word, SITE, 18),
                PcrelTarget::Target { address, .. } if address == target
            ));
            assert!(matches!(transformation.pcrel, Some(X18Pcrel::Adrp(_))));
        }
    }

    #[test]
    fn classifies_typed_x18_conditionals_with_target_condition_width_and_bit() {
        for (word, target, nonzero, width) in [
            (0x3400_0092, 0x1010, false, X18Width::W), // cbz w18
            (0xb500_00b2, 0x1014, true, X18Width::X),  // cbnz x18
            (0x3600_0092, 0x1010, false, X18Width::W), // tbz w18, #0
            (0xb7f8_00b2, 0x1014, true, X18Width::X),  // tbnz x18, #63
        ] {
            let instruction = decode_instruction(word).unwrap();
            let kind = classify_decoded_x18_at(word, instruction, 0x1000).unwrap();
            let PatchKind::X18Conditional(branch) = kind else {
                panic!("word {word:#010x} was not a specialized conditional site");
            };
            assert_eq!(branch.target, target);
            assert_eq!(branch.nonzero, nonzero);
            assert_eq!(branch.width, width);
            assert_eq!(branch.original_word, word);
        }
    }

    #[test]
    fn x18_test_branch_target_arithmetic_rejects_address_overflow() {
        for (word, address) in [
            (0x3604_0012, 0),            // tbz w18, #0, -32768
            (0x3603_fff2, u64::MAX - 3), // tbz w18, #0, +32764
        ] {
            let instruction = decode_instruction(word).unwrap();
            assert!(classify_decoded_x18_at(word, instruction, address).is_none());
        }
    }

    #[test]
    fn exclusive_x18_instructions_are_unsupported() {
        // Assembled by LLVM as `ldxr x18, [x0]`.
        let word = 0xc85f_7c12;
        let instruction = decode_instruction(word).unwrap();
        assert_eq!(instruction.opcode, DecodedOpcode::LDXR);
        assert!(instruction_uses_x18(word).unwrap());
        assert_eq!(
            transform_x18_instruction(word),
            X18TransformResult::Unsupported(X18TransformFailure::ExclusiveOrAtomic)
        );
    }

    #[test]
    fn lse_atomic_with_structurally_supported_x18_base_is_unsupported() {
        // Assembled by LLVM with `-mattr=+lse` as `swp x0, x1, [x18]`.
        let word = 0xf820_8241;
        let instruction = decode_instruction(word).unwrap();
        assert!(matches!(instruction.opcode, DecodedOpcode::SWP(_)));
        assert_eq!(
            instruction.operands,
            [
                Operand::Register(SizeCode::X, 0),
                Operand::Register(SizeCode::X, 1),
                Operand::RegPreIndex(18, 0, false),
                Operand::Nothing,
            ]
        );

        // Its x18 base has the ordinary Rn layout the structural mapper handles.
        let mut structurally_transformed = word;
        assert!(
            map_x18_operand_field(
                &mut structurally_transformed,
                &instruction,
                2,
                &instruction.operands[2],
                17,
            )
            .is_some()
        );
        assert_eq!(structurally_transformed, 0xf820_8221);
        assert_eq!(
            decode_instruction(structurally_transformed)
                .unwrap()
                .operands[2],
            Operand::RegPreIndex(17, 0, false)
        );

        assert!(is_exclusive_or_atomic_opcode(instruction.opcode));
        assert!(!is_control_flow_opcode(instruction.opcode));
        assert!(
            !instruction
                .operands
                .iter()
                .any(|operand| matches!(operand, Operand::PCOffset(_)))
        );
        assert_eq!(
            transform_x18_instruction(word),
            X18TransformResult::Unsupported(X18TransformFailure::ExclusiveOrAtomic)
        );
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
        assert_eq!(Insn::Bl(0).encode().unwrap(), 0x9400_0000);
        assert_eq!(Insn::Bl(4).encode().unwrap(), 0x9400_0001);
        assert_eq!(Insn::Bl(-4).encode().unwrap(), 0x97FF_FFFF);
        assert!(Insn::Bl(1 << 27).encode().is_none());
        assert!(Insn::Bl(-(1 << 27) - 4).encode().is_none());
        assert!(Insn::Bl(2).encode().is_none());
        // `BR X16`.
        assert_eq!(Insn::Br(16).encode().unwrap(), 0xD61F_0200);
        assert_eq!(Insn::Ret(30).encode().unwrap(), 0xD65F_03C0);
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

    #[test]
    fn checked_pcrel_difference_handles_unsigned_address_boundaries() {
        let below = i64::MAX as u64 - 3;
        let above = i64::MAX as u64 + 5;
        assert_eq!(checked_pcrel_difference(above, below), Some(8));
        assert_eq!(checked_pcrel_difference(below, above), Some(-8));
        assert_eq!(checked_pcrel_difference(u64::MAX, 0), None);
        assert_eq!(checked_pcrel_difference(0, u64::MAX), None);
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
            RewriteConfig::new(Host::Linux, false),
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
            RewriteConfig::new(Host::Linux, false),
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
    fn no_patch_sites_emit_no_trampoline() {
        // No patch sites: a NOP-only section yields no trampoline at all, so the
        // caller emits a size-0 sentinel (matching the x86-64 path).
        let (_patched, tramp) = hook_words_opt(&[0xD503_201F], 0x1000, 0x100000);
        assert!(tramp.is_none());
    }

    #[test]
    fn default_config_leaves_standalone_x18_native() {
        let word = 0xaa00_03f2; // mov x18, x0
        let (patched, outcome) = hook_words_opt(&[word], 0x1000, 0x200000);

        assert_eq!(word_at(&patched, 0), word);
        assert!(outcome.is_none());
    }

    #[test]
    fn enabled_x18_traps_supported_and_unsupported_forms_in_address_order() {
        let base = 0x1000;
        let words = [
            0xaa00_03f2, // mov x18, x0: structurally supported
            0x0b12_0063, // add w3, w3, w18: structurally supported
            0xf940_0642, // ldr x2, [x18, #8]: structurally supported
            0xf900_0642, // str x2, [x18, #8]: structurally supported
            0xa906_4bee, // stp x14, x18, [sp, #0x60]: structurally supported
            0xf000_0012, // adrp x18, ...: specialized PC-relative relocation
            0x3400_5812, // cbz w18, ...: specialized conditional
            0xd63f_0240, // blr x18: control flow
            0xc85f_7c12, // ldxr x18, [x0]: exclusive
        ];
        let (patched, outcome) = hook_words_opt_with_config(
            &words,
            base,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.expect("x18 uses are patch sites");
        let brk = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();

        assert!(
            (0..7).all(|index| word_at(&patched, index * 4) & OPCODE_TOP6_MASK == Opcode::B.bits())
        );
        assert!((7..words.len()).all(|index| word_at(&patched, index * 4) == brk));
        assert_eq!(
            outcome.trapped_sites,
            [7usize, 8]
                .into_iter()
                .map(|index| base + (index * INSN_BYTES) as u64)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            outcome.trampoline.len(),
            GATES_START_OFFSET + X18_SETUP_BYTES + 6 * X18_SLOT_BYTES + X18_CONDITIONAL_SLOT_BYTES
        );
    }

    #[test]
    fn x18_preferred_pair_has_exact_setup_and_site_templates() {
        let base = 0x1000;
        let trampoline_base = 0x200000;
        let original = 0xaa00_03f2; // mov x18, x0
        let (patched, outcome) = hook_words_opt_with_config(
            &[original],
            base,
            trampoline_base,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        let trampoline = outcome.trampoline;
        let setup = GATES_START_OFFSET;
        let slot = setup + X18_SETUP_BYTES;

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(
            trampoline.len(),
            GATES_START_OFFSET + X18_SETUP_BYTES + X18_SLOT_BYTES
        );
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), base),
            Some(trampoline_base + slot as u64)
        );
        // Independently checked with LLVM 18 `llvm-mc -triple=aarch64 -show-encoding`.
        let expected_setup = [
            0xd53b_d050, // mrs x16, TPIDR_EL0
            0xf940_03f1, // ldr x17, [sp]
            0xf93f_f611, // str x17, [x16, #32744]
            0xf940_07f1, // ldr x17, [sp, #8]
            0xf93f_f211, // str x17, [x16, #32736]
            0xf97f_fa11, // ldr x17, [x16, #32752]
            0xd65f_03c0, // ret x30
            0x0031_b807, // X18 metadata: anchor x16, value x17
        ];
        for (index, expected) in expected_setup.into_iter().enumerate() {
            assert_eq!(word_at(&trampoline, setup + index * 4), expected);
        }

        let expected_site = [
            0xd100_83ff, // sub sp, sp, #32
            0xa900_47f0, // stp x16, x17, [sp]
            0xf900_0bfe, // str x30, [sp, #16]
            0x97ff_fff5, // bl setup (-44 bytes)
            0xf940_0bfe, // ldr x30, [sp, #16]
            0x9100_83ff, // add sp, sp, #32
            0xaa00_03f1, // mov x17, x0
            0xd503_201f, // second materialization word
            0xf93f_fa11, // str x17, [x16, #32752]
            0xf97f_f211, // ldr x17, [x16, #32736]
            0xf97f_f610, // ldr x16, [x16, #32744]
            0x17f8_03ea, // b 0x1004 from 0x20005c
            0xaa00_03f2, // original instruction descriptor
            0xd503_201f, // nop padding
            0xd503_201f, // nop padding
            0x0031_b807, // X18 metadata: anchor x16, value x17
        ];
        for (index, expected) in expected_site.into_iter().enumerate() {
            assert_eq!(word_at(&trampoline, slot + index * 4), expected);
        }
        assert_eq!(
            decode_branch_target(
                word_at(&trampoline, slot + 44),
                trampoline_base + (slot + 44) as u64
            ),
            Some(base + 4)
        );
    }

    #[test]
    fn x18_ccmp_gate_preserves_instruction_nzcv_through_teardown() {
        let original = 0xfa5e_1244; // ccmp x18, x30, #4, ne
        let (_patched, outcome) = hook_words_opt_with_config(
            &[original],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let trampoline = outcome.unwrap().trampoline;
        let slot = GATES_START_OFFSET + X18_SETUP_BYTES;

        assert_eq!(
            (6..=11)
                .map(|index| word_at(&trampoline, slot + index * INSN_BYTES))
                .collect::<Vec<_>>(),
            [
                0xfa5e_1224, // ccmp x17, x30, #4, ne
                0xd503_201f, // second materialization word
                0xf93f_fa11, // str x17, [x16, #32752]
                0xf97f_f211, // ldr x17, [x16, #32736]
                0xf97f_f610, // ldr x16, [x16, #32744]
                0x17f8_03ea, // b 0x1004
            ]
        );
    }

    #[test]
    fn x18_conditional_gates_have_exact_templates_and_continuations() {
        const BASE: u64 = 0x1000;
        const TRAMPOLINE_BASE: u64 = 0x200000;
        for (original, expected_condition, taken_target, expected_taken_branch) in [
            (0x3400_0092, 0x3400_00b1, 0x1010, 0x17f8_03ea), // cbz w18
            (0xb500_00b2, 0xb500_00b1, 0x1014, 0x17f8_03eb), // cbnz x18
            (0x3600_0092, 0x3600_00b1, 0x1010, 0x17f8_03ea), // tbz w18, #0
            (0xb7f8_00b2, 0xb7f8_00b1, 0x1014, 0x17f8_03eb), // tbnz x18, #63
        ] {
            let (patched, outcome) = hook_words_opt_with_config(
                &[original],
                BASE,
                TRAMPOLINE_BASE,
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();
            let trampoline = outcome.trampoline;
            let slot = GATES_START_OFFSET + X18_SETUP_BYTES;
            assert!(outcome.trapped_sites.is_empty());
            assert_eq!(trampoline.len(), slot + X18_CONDITIONAL_SLOT_BYTES);
            assert_eq!(
                decode_branch_target(word_at(&patched, 0), BASE),
                Some(TRAMPOLINE_BASE + slot as u64)
            );

            let expected = [
                0xd100_83ff, // sub sp, sp, #32
                0xa900_47f0, // stp x16, x17, [sp]
                0xf900_0bfe, // str x30, [sp, #16]
                0x97ff_fff5, // bl setup
                0xf940_0bfe, // ldr x30, [sp, #16]
                0x9100_83ff, // add sp, sp, #32
                expected_condition,
                0xf93f_fa11, // fallthrough: commit x18
                0xf97f_f211, // restore x17
                0xf97f_f610, // restore x16
                0x17f8_03eb, // b site+4
                0xf93f_fa11, // taken: commit x18
                0xf97f_f211, // restore x17
                0xf97f_f610, // restore x16
                expected_taken_branch,
                original, // original descriptor
                0xd503_201f,
                0xd503_201f,
                0xd503_201f,
                0x0041_b807, // conditional X18 metadata: anchor x16, value x17
            ];
            for (index, expected) in expected.into_iter().enumerate() {
                assert_eq!(word_at(&trampoline, slot + index * 4), expected);
            }
            assert_eq!(
                decode_branch_target(
                    word_at(&trampoline, slot + 40),
                    TRAMPOLINE_BASE + (slot + 40) as u64
                ),
                Some(BASE + 4)
            );
            assert_eq!(
                decode_branch_target(
                    word_at(&trampoline, slot + 56),
                    TRAMPOLINE_BASE + (slot + 56) as u64
                ),
                Some(taken_target)
            );
            let classified = classify_copied_gate_slot(
                &trampoline[slot..slot + X18_CONDITIONAL_SLOT_BYTES],
                TRAMPOLINE_BASE + slot as u64,
                TRAMPOLINE_BASE + (slot + 24) as u64,
            )
            .unwrap();
            let details = classified.x18().unwrap();
            assert_eq!(details.fallthrough(), BASE + 4);
            assert_eq!(details.taken(), Some(taken_target));

            for mutation in [60usize, X18_CONDITIONAL_SLOT_BYTES - 4] {
                let mut changed = trampoline[slot..slot + X18_CONDITIONAL_SLOT_BYTES].to_vec();
                changed[mutation] ^= 1;
                assert!(
                    classify_copied_gate_slot(
                        &changed,
                        TRAMPOLINE_BASE + slot as u64,
                        TRAMPOLINE_BASE + (slot + 24) as u64,
                    )
                    .is_none()
                );
            }
        }
    }

    #[test]
    fn x18_gate_return_out_of_range_traps_site_without_orphan_setup() {
        let base = 0x1004u64;
        let max_forward_branch = (1u64 << 27) - 4;
        let final_gate_offset = GATES_START_OFFSET + X18_SETUP_BYTES;
        let trampoline_base = base + max_forward_branch - final_gate_offset as u64;
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2], // mov x18, x0: supported, unique preferred pair
            base,
            trampoline_base,
            RewriteConfig::new(Host::Linux, true),
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
    fn x18_gate_compaction_shift_is_safe_and_has_no_orphan_setup() {
        let trampoline_base = 0x2000_0000u64;
        let second_gate_with_both_setups = GATES_START_OFFSET + 2 * X18_SETUP_BYTES;
        let second_site = trampoline_base + second_gate_with_both_setups as u64 - ((1 << 27) - 20);
        let words = [
            0x8b10_0232u32, // alternate pair; deliberately unreachable
            0xaa00_03f2,    // preferred pair; reachable after alternate setup removal
        ];
        let mut code = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let sections = [
            TextSectionInfo {
                vaddr: trampoline_base + (1 << 28),
                file_offset: 0,
                size: 4,
            },
            TextSectionInfo {
                vaddr: second_site,
                file_offset: 4,
                size: 4,
            },
        ];

        let outcome = hook_syscalls_aarch64(
            &mut code,
            &sections,
            trampoline_base,
            0,
            RewriteConfig::new(Host::Linux, true),
        )
        .unwrap()
        .unwrap();

        assert_eq!(word_at(&code, 0), Insn::Brk(TRAP_BRK_IMM).encode().unwrap());
        if outcome.trapped_sites == vec![sections[0].vaddr] {
            assert_eq!(
                decode_branch_target(word_at(&code, 4), second_site),
                Some(trampoline_base + GATES_START_OFFSET as u64 + X18_SETUP_BYTES as u64)
            );
            assert_eq!(
                outcome.trampoline.len(),
                GATES_START_OFFSET + X18_SETUP_BYTES + X18_SLOT_BYTES
            );
        } else {
            assert_eq!(
                outcome.trapped_sites,
                vec![sections[0].vaddr, sections[1].vaddr]
            );
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }
    }

    #[test]
    fn x18_gate_cooperative_pairs_may_conservatively_trap_without_orphan_setups() {
        let trampoline_base = 0x2000_0000u64;
        let branch_reach = 1u64 << 27;
        let site_base =
            trampoline_base + (GATES_START_OFFSET + X18_SETUP_BYTES) as u64 + branch_reach + 16;
        let words = [
            0x8b10_0232u32, // alternate pair
            0xaa00_03f2,    // preferred pair
        ];

        for (word, site) in [(words[0], site_base), (words[1], site_base + 4)] {
            let (_patched, outcome) = hook_words_opt_with_config(
                &[word],
                site,
                trampoline_base,
                RewriteConfig::new(Host::Linux, true),
            );
            let outcome = outcome.unwrap();
            assert_eq!(outcome.trapped_sites, vec![site]);
            assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        }

        let mut code = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let sections = [
            TextSectionInfo {
                vaddr: site_base,
                file_offset: 0,
                size: 4,
            },
            TextSectionInfo {
                vaddr: site_base + 4,
                file_offset: 4,
                size: 4,
            },
        ];
        let outcome = hook_syscalls_aarch64(
            &mut code,
            &sections,
            trampoline_base,
            0,
            RewriteConfig::new(Host::Linux, true),
        )
        .unwrap()
        .unwrap();

        assert_eq!(outcome.trapped_sites, vec![site_base, site_base + 4]);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
        assert!((0..2).all(|index| {
            word_at(&code, index * INSN_BYTES) == Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        }));
    }

    #[test]
    fn x18_gate_small_branch_differences_crossing_i64_max_are_encodable() {
        let site = i64::MAX as u64 - 15;
        let trampoline_base = (i64::MAX as u64 + 1).next_multiple_of(GATE_ALIGNMENT as u64);
        let (patched, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            site,
            trampoline_base,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(
            decode_branch_target(word_at(&patched, 0), site),
            Some(trampoline_base + (GATES_START_OFFSET + X18_SETUP_BYTES) as u64)
        );
    }

    #[test]
    fn x18_gate_planner_does_bounded_analytical_work_at_scale() {
        const SITE_COUNT: usize = 18_000;
        let transformation = supported_x18_rewrite(0xaa00_03f2);
        let sites = (0..SITE_COUNT)
            .map(|index| PatchSite {
                file_offset: index * INSN_BYTES,
                vaddr: 0x1000 + (index * INSN_BYTES) as u64,
                kind: PatchKind::X18(X18TransformResult::Supported(transformation)),
            })
            .collect::<Vec<_>>();
        let plan = plan_x18_sites(&sites, 0x2000_0000).unwrap();

        assert!(plan.sites.iter().all(|selected| !selected));
        assert_eq!(plan.layout_checks, SITE_COUNT);
    }

    #[test]
    fn x18_gate_planner_bounds_adversarial_cascading_layout_work() {
        const SITE_COUNT: usize = 18_000;
        let transformation = supported_x18_rewrite(0xaa00_03f2);
        let sites = (0..SITE_COUNT)
            .map(|index| PatchSite {
                file_offset: index * INSN_BYTES,
                // Alternate around both branch-range boundaries. Under a
                // compacting fixed-point planner, eliminating one side shifts
                // every later gate and can trigger another removal wave.
                vaddr: if index.is_multiple_of(2) {
                    0x1800_0000 + (index * INSN_BYTES) as u64
                } else {
                    0x2800_0000 - (index * INSN_BYTES) as u64
                },
                kind: PatchKind::X18(X18TransformResult::Supported(transformation)),
            })
            .collect::<Vec<_>>();
        let plan = plan_x18_sites(&sites, 0x2000_0000).unwrap();

        assert_eq!(plan.layout_checks, SITE_COUNT);
    }

    #[test]
    fn x18_setups_are_deduplicated_in_first_pair_use_order_and_x30_is_available_to_guest() {
        let words = [
            0x8b10_0232, // add x18, x17, x16 => value x15, anchor x14
            0xaa1e_03f2, // mov x18, x30 => preferred pair, reads x30
            0xaa12_03fe, // mov x30, x18 => preferred pair, writes x30
            0xaa00_03f2, // preferred pair again
        ];
        let (_patched, outcome) = hook_words_opt_with_config(
            &words,
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let trampoline = outcome.unwrap().trampoline;
        assert_eq!(
            trampoline.len(),
            GATES_START_OFFSET + 2 * X18_SETUP_BYTES + 4 * X18_SLOT_BYTES
        );
        assert_eq!(
            word_at(&trampoline, GATES_START_OFFSET + 28),
            EncodedGateMetadata::encode(GateMetadata::X18 {
                anchor_scratch: 14,
                value_scratch: 15
            })
            .unwrap()
            .0
        );
        assert_eq!(
            word_at(&trampoline, GATES_START_OFFSET + X18_SETUP_BYTES + 28),
            EncodedGateMetadata::encode(GateMetadata::X18 {
                anchor_scratch: 16,
                value_scratch: 17
            })
            .unwrap()
            .0
        );
        let first_slot = GATES_START_OFFSET + 2 * X18_SETUP_BYTES;
        for index in 0..words.len() {
            let slot = first_slot + index * X18_SLOT_BYTES;
            assert_eq!(
                word_at(&trampoline, slot + 16),
                Insn::LdrUimm {
                    rt: 30,
                    rn: SP,
                    imm_bytes: 16
                }
                .encode()
                .unwrap()
            );
            assert_eq!(
                word_at(&trampoline, slot + 20),
                Insn::AddSp(32).encode().unwrap()
            );
        }
        assert_eq!(
            word_at(&trampoline, first_slot + X18_SLOT_BYTES + 24),
            0xaa1e_03f1
        );
        assert_eq!(
            word_at(&trampoline, first_slot + 2 * X18_SLOT_BYTES + 24),
            0xaa11_03fe
        );
    }

    #[test]
    fn x18_incremental_bytes_and_alternate_pair_templates_are_exact() {
        const PREFERRED: u32 = 0xaa00_03f2; // mov x18, x0: (anchor x16, value x17)
        const SAME_PAIR: u32 = 0xaa12_03e0; // mov x0, x18: same pair
        const ALTERNATE: u32 = 0x8b10_0232; // add x18, x17, x16: (anchor x14, value x15)
        const BASE: u64 = 0x1000;
        const TRAMPOLINE_BASE: u64 = 0x20_0000;
        let hook = |words: &[u32]| {
            hook_words_opt_with_config(
                words,
                BASE,
                TRAMPOLINE_BASE,
                RewriteConfig::new(Host::Linux, true),
            )
            .1
            .unwrap()
            .trampoline
        };

        assert_eq!(GATE_ALIGNMENT, 16);
        assert_eq!(X18_SETUP_BYTES, 32);
        assert_eq!(X18_SLOT_BYTES, 64);
        assert_eq!(X18_GATE_BYTES, 48);

        let preferred = hook(&[PREFERRED]);
        let same_pair = hook(&[PREFERRED, SAME_PAIR]);
        let alternate = hook(&[PREFERRED, SAME_PAIR, ALTERNATE]);
        assert_eq!(
            preferred.len(),
            GATES_START_OFFSET + X18_SETUP_BYTES + X18_SLOT_BYTES,
            "first x18 pair costs one setup plus one site slot"
        );
        assert_eq!(
            same_pair.len(),
            GATES_START_OFFSET + X18_SETUP_BYTES + 2 * X18_SLOT_BYTES
        );
        assert_eq!(
            same_pair.len() - preferred.len(),
            X18_SLOT_BYTES,
            "a same-pair site adds only its site slot"
        );
        assert_eq!(
            alternate.len(),
            GATES_START_OFFSET + 2 * X18_SETUP_BYTES + 3 * X18_SLOT_BYTES
        );
        assert_eq!(
            alternate.len() - same_pair.len(),
            X18_SETUP_BYTES + X18_SLOT_BYTES,
            "a new-pair site adds one setup and one site slot"
        );

        let setup = GATES_START_OFFSET + X18_SETUP_BYTES;
        // Independently checked with LLVM 18 `llvm-mc -triple=aarch64 -show-encoding`.
        let expected_setup = [
            0xd53b_d04e, // mrs x14, TPIDR_EL0
            0xf940_03ef, // ldr x15, [sp]
            0xf93f_f5cf, // str x15, [x14, #32744]
            0xf940_07ef, // ldr x15, [sp, #8]
            0xf93f_f1cf, // str x15, [x14, #32736]
            0xf97f_f9cf, // ldr x15, [x14, #32752]
            0xd65f_03c0, // ret x30
            0x1331_b807, // X18 metadata: anchor x14, value x15
        ];
        for (index, expected) in expected_setup.into_iter().enumerate() {
            assert_eq!(word_at(&alternate, setup + index * 4), expected);
        }

        let site = GATES_START_OFFSET + 2 * X18_SETUP_BYTES + 2 * X18_SLOT_BYTES;
        let expected_site = [
            0xd100_83ff, // sub sp, sp, #32
            0xa900_3fee, // stp x14, x15, [sp]
            0xf900_0bfe, // str x30, [sp, #16]
            0x97ff_ffd5, // bl alternate setup (-172 bytes)
            0xf940_0bfe, // ldr x30, [sp, #16]
            0x9100_83ff, // add sp, sp, #32
            0x8b10_022f, // add x15, x17, x16
            0xd503_201f, // second materialization word
            0xf93f_f9cf, // str x15, [x14, #32752]
            0xf97f_f1cf, // ldr x15, [x14, #32736]
            0xf97f_f5ce, // ldr x14, [x14, #32744]
            0x17f8_03c4, // b 0x100c from 0x2000fc
            0x8b10_0232, // original instruction descriptor
            0xd503_201f, // nop padding
            0xd503_201f, // nop padding
            0x1331_b807, // X18 metadata: anchor x14, value x15
        ];
        for (index, expected) in expected_site.into_iter().enumerate() {
            assert_eq!(word_at(&alternate, site + index * 4), expected);
        }
    }

    #[test]
    fn scanner_preserves_svc_tpidr_and_x18_order_and_precedence() {
        let base = 0x4000;
        let words = [
            SVC_0,
            msr_tpidr_el0(5),
            0xaa00_03f2, // mov x18, x0
            Insn::MrsTpidrEl0(9).encode().unwrap(),
        ];
        let mut bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let sections = [TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: bytes.len() as u64,
        }];
        let sites =
            find_patch_sites(&sections, &bytes, RewriteConfig::new(Host::Linux, true)).unwrap();

        assert_eq!(
            sites.iter().map(|site| site.vaddr).collect::<Vec<_>>(),
            vec![base, base + 4, base + 8, base + 12]
        );
        assert!(matches!(sites[0].kind, PatchKind::Svc));
        assert!(matches!(sites[1].kind, PatchKind::MsrTpidr(5)));
        assert!(matches!(sites[2].kind, PatchKind::X18(_)));
        assert!(matches!(sites[3].kind, PatchKind::MrsTpidr(9)));

        let normal = hook_syscalls_aarch64(
            &mut bytes,
            &sections,
            0x1000_0000,
            0,
            RewriteConfig::new(Host::Linux, true),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            normal.trapped_sites,
            vec![base, base + 4, base + 8, base + 12]
        );
    }

    #[test]
    fn enabled_x18_traps_tpidr_overlap_sites_even_when_gates_are_in_range() {
        let base = 0x4000;
        let tramp_base = 0x8000;
        let words = [msr_tpidr_el0(18), Insn::MrsTpidrEl0(18).encode().unwrap()];
        let mut bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let sections = [TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: bytes.len() as u64,
        }];
        let sites =
            find_patch_sites(&sections, &bytes, RewriteConfig::new(Host::Linux, true)).unwrap();

        assert!(matches!(
            sites[0].kind,
            PatchKind::X18(X18TransformResult::Unsupported(_))
        ));
        assert!(matches!(
            sites[1].kind,
            PatchKind::X18(X18TransformResult::Unsupported(_))
        ));

        let outcome = hook_syscalls_aarch64(
            &mut bytes,
            &sections,
            tramp_base,
            0,
            RewriteConfig::new(Host::Linux, true),
        )
        .unwrap()
        .unwrap();
        let brk = Insn::Brk(TRAP_BRK_IMM).encode().unwrap();
        assert_eq!(word_at(&bytes, 0), brk);
        assert_eq!(word_at(&bytes, 4), brk);
        assert_eq!(outcome.trapped_sites, vec![base, base + 4]);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }

    #[test]
    fn default_config_keeps_tpidr_x18_overlap_gate_behavior() {
        let words = [msr_tpidr_el0(18), Insn::MrsTpidrEl0(18).encode().unwrap()];
        let (patched, outcome) = hook_words_opt(&words, 0x4000, 0x8000);
        let outcome = outcome.unwrap();

        assert!(outcome.trapped_sites.is_empty());
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(word_at(&patched, 4) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(
            outcome.trampoline.len(),
            GATES_START_OFFSET + MSR_GATE_SIZE + MRS_GATE_SIZE
        );
    }

    #[test]
    fn only_candidate_decode_failures_trap_when_x18_virtualization_is_enabled() {
        let candidate = 0xffff_fff2;
        let non_candidate = 0xffff_ffff;
        assert!(decode_instruction(candidate).is_err());
        assert!(decode_instruction(non_candidate).is_err());

        let (patched, outcome) = hook_words_opt_with_config(
            &[candidate, non_candidate],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let outcome = outcome.unwrap();
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(word_at(&patched, 4), non_candidate);
        assert_eq!(outcome.trapped_sites, vec![0x1000]);
    }

    #[test]
    fn decoded_vector_instruction_uses_semantics_despite_raw_x18_candidate() {
        let word = 0x4eb2_1e50; // mov v16.16b, v18.16b
        assert!(has_possible_x18_field(word));
        assert!(!instruction_uses_x18(word).unwrap());

        let (patched, outcome) = hook_words_opt_with_config(
            &[word],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );

        assert_eq!(word_at(&patched, 0), word);
        assert!(outcome.is_none());
    }

    #[test]
    fn pair_adjacency_candidate_traps_only_after_decode_failure() {
        let decoded = 0xaa11_03e0; // mov x0, x17
        let failed = 0xffff_fff1;
        assert!(has_possible_x18_field(decoded));
        assert!(has_possible_x18_field(failed));
        assert!(!instruction_uses_x18(decoded).unwrap());
        assert!(decode_instruction(failed).is_err());

        let (patched, outcome) = hook_words_opt_with_config(
            &[decoded, failed],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        assert_eq!(word_at(&patched, 0), decoded);
        let outcome = outcome.unwrap();
        assert_eq!(
            word_at(&patched, 4),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![0x1004]);
    }

    #[test]
    fn decoder_failure_prefilter_checks_all_possible_gpr_fields_and_pair_adjacency() {
        for shift in [0, 5, 10, 16] {
            assert!(has_possible_x18_field(18 << shift), "shift {shift}");
        }
        assert!(has_possible_x18_field(17));
        assert!(has_possible_x18_field(17 << 16));
        assert!(!has_possible_x18_field(17 << 5));
        assert!(!has_possible_x18_field(17 << 10));
        assert!(!has_possible_x18_field(16));
        assert!(!has_possible_x18_field(19));
    }

    #[test]
    fn representative_sve_decode_failures_remain_native() {
        // yaxpeax-arm 0.4 does not decode SVE. Keep one example from each SVE
        // family seen in glibc rather than pinning a distro-specific libc dump.
        let words = [
            0x0420_e3e7, // cntb x7
            0x04e0_e3e0, // cntd x0
            0x2522_1ce1, // whilelo p1.b, x7, x2
            0xa400_a020, // ld1b {z0.b}, p0/z, [x1]
            0xe400_e060, // st1b {z0.b}, p0, [x3]
            0x0520_3820, // mov z0.b, w1
        ];
        assert!(words.iter().all(|word| decode_instruction(*word).is_err()));

        let (patched, outcome) = hook_words_opt_with_config(
            &words,
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );

        assert_eq!(
            patched,
            words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>()
        );
        assert!(outcome.is_none());
    }

    #[test]
    fn default_config_leaves_decode_failures_unchanged() {
        let undecodable = 0xffff_ffff;
        assert!(decode_instruction(undecodable).is_err());

        let (patched, outcome) = hook_words_opt_with_config(
            &[undecodable],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, false),
        );

        assert_eq!(word_at(&patched, 0), undecodable);
        assert!(outcome.is_none());
    }

    #[test]
    fn trap_all_enabled_matches_normal_rewrite_trapped_set() {
        let words = [SVC_0, 0xaa00_03f2, 0xf000_0012, 0xffff_fff2, NOP];
        let base = 0x1000;
        let config = RewriteConfig::new(Host::Linux, true);
        let (normal_code, normal) = hook_words_opt_with_config(&words, base, 0x1000_0000, config);
        let normal = normal.unwrap();
        let mut trap_code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let sections = [TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: trap_code.len() as u64,
        }];

        let count = trap_all_patch_sites(&mut trap_code, &sections, config).unwrap();

        assert_eq!(count, normal.trapped_sites.len());
        assert_eq!(trap_code, normal_code);
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
        assert_eq!(
            word(GateMetadata::X18 {
                anchor_scratch: 16,
                value_scratch: 17,
            }),
            0x0031b807
        );
    }

    #[test]
    fn x18_metadata_exhaustively_round_trips_persisted_scratch_pairs() {
        for (index, &(anchor_scratch, value_scratch)) in X18_SCRATCH_PAIRS.iter().enumerate() {
            let metadata = GateMetadata::X18 {
                anchor_scratch,
                value_scratch,
            };
            let encoded = EncodedGateMetadata::encode(metadata).unwrap();
            assert_eq!(
                (encoded.0 & GATE_METADATA_REGISTER_MASK) >> GATE_METADATA_REGISTER_SHIFT,
                u32::try_from(index).unwrap()
            );
            assert_eq!(encoded.decode(), Some(metadata));
        }
    }

    #[test]
    fn x18_metadata_rejects_unmapped_or_invalid_scratches() {
        for (anchor_scratch, value_scratch) in [
            (17, 17),
            (16, 16),
            (18, 17),
            (16, 18),
            (31, 17),
            (16, 31),
            (32, 17),
            (16, 32),
            (17, 16),
            (6, 17),
        ] {
            assert!(
                EncodedGateMetadata::encode(GateMetadata::X18 {
                    anchor_scratch,
                    value_scratch,
                })
                .is_none(),
                "pair ({anchor_scratch}, {value_scratch})"
            );
        }

        let base = EncodedGateMetadata::encode(GateMetadata::X18 {
            anchor_scratch: 16,
            value_scratch: 17,
        })
        .unwrap()
        .0;
        for index in 55..64 {
            let invalid =
                (base & !GATE_METADATA_REGISTER_MASK) | (index << GATE_METADATA_REGISTER_SHIFT);
            assert_eq!(EncodedGateMetadata(invalid).decode(), None, "index {index}");
        }
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
        for kind in 5..16 {
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
    fn structured_gate_offsets_reject_alignment_range_and_aliasing() {
        for values in [
            [17, 24, 32, 40],
            [16, 25, 32, 40],
            [16, 24, 33, 40],
            [16, 24, 32, 41],
            [8, 24, 32, 40],
            [16, 24, 32, GUEST_TPIDR_OFFSET_PLACEHOLDER],
            [16, 16, 32, 40],
            [16, 24, 24, 40],
            [16, 24, 32, 32],
        ] {
            assert!(Aarch64GateOffsets::new(values[0], values[1], values[2], values[3]).is_err());
        }
    }

    #[test]
    fn gate_offset_placeholders_are_distinct_and_above_real_offsets() {
        assert_eq!(GUEST_TPIDR_OFFSET_PLACEHOLDER, 32760);
        assert_eq!(GUEST_X18_OFFSET_PLACEHOLDER, 32752);
        assert_eq!(SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER, 32744);
        assert_eq!(SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER, 32736);
        assert_eq!(MAX_REAL_X18_GATE_OFFSET, 32728);

        let reserved = [
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
            GUEST_X18_OFFSET_PLACEHOLDER,
            SAVED_ANCHOR_SCRATCH_OFFSET_PLACEHOLDER,
            SAVED_VALUE_SCRATCH_OFFSET_PLACEHOLDER,
        ];
        for (index, value) in reserved.into_iter().enumerate() {
            assert!(value > MAX_REAL_X18_GATE_OFFSET);
            assert!(!reserved[..index].contains(&value));
        }
    }

    #[test]
    fn structured_finalization_preserves_tp_only_behavior() {
        let (_p, mut structured) =
            hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        let mut compatible = structured.clone();
        let offsets = Aarch64GateOffsets::new(MEASURED_OFFSET, 104, 112, 120).unwrap();

        finalize_trampoline_gates_with_offsets(&mut structured, offsets).unwrap();
        finalize_trampoline_gates(&mut compatible, MEASURED_OFFSET).unwrap();

        assert_eq!(structured, compatible);
    }

    #[test]
    fn historical_top_tpidr_offsets_remain_accepted_by_both_finalizers() {
        for guest_tpidr in [32736, 32744, 32752] {
            let (_p, trampoline) =
                hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
            let mut legacy = trampoline.clone();
            let mut structured = trampoline;
            let offsets = Aarch64GateOffsets::new(guest_tpidr, 104, 112, 120).unwrap();

            finalize_trampoline_gates(&mut legacy, guest_tpidr).unwrap();
            finalize_trampoline_gates_with_offsets(&mut structured, offsets).unwrap();

            assert_eq!(legacy, structured, "guest TP offset {guest_tpidr}");
        }
    }

    #[test]
    fn structured_finalization_is_transactional_on_malformed_input() {
        let (_p, mut trampoline) = hook_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );
        let last = trampoline.len() - 1;
        trampoline[last] ^= 1;
        let before = trampoline.clone();
        let offsets = Aarch64GateOffsets::new(MEASURED_OFFSET, 104, 112, 120).unwrap();

        assert!(finalize_trampoline_gates_with_offsets(&mut trampoline, offsets).is_err());
        assert_eq!(trampoline, before);
    }

    #[test]
    fn structured_finalization_exactly_patches_x18_setup_and_site_placeholders() {
        let (_patched, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let offsets = Aarch64GateOffsets::new(96, 104, 112, 120).unwrap();

        finalize_trampoline_gates_with_offsets(&mut trampoline, offsets).unwrap();

        let setup = GATES_START_OFFSET;
        let slot = setup + X18_SETUP_BYTES;
        assert_eq!(
            word_at(&trampoline, setup + 8),
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 112
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(&trampoline, setup + 16),
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 120
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(&trampoline, setup + 20),
            Insn::LdrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 104
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(&trampoline, slot + 32),
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 104
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(&trampoline, slot + 36),
            Insn::LdrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 120
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(&trampoline, slot + 40),
            Insn::LdrUimm {
                rt: 16,
                rn: 16,
                imm_bytes: 112
            }
            .encode()
            .unwrap()
        );
        assert!(
            validate_trampoline_and_collect_patches(&trampoline, 96, Some(offsets), Host::Linux)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn x18_finalizers_reject_malformed_or_legacy_inputs_transactionally() {
        let (_patched, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let trampoline = outcome.unwrap().trampoline;
        let offsets = Aarch64GateOffsets::new(96, 104, 112, 120).unwrap();

        let mut legacy = trampoline.clone();
        assert!(finalize_trampoline_gates(&mut legacy, 96).is_err());
        assert_eq!(legacy, trampoline);

        let mut malformed = trampoline.clone();
        malformed[GATES_START_OFFSET] ^= 1;
        let before = malformed.clone();
        assert!(finalize_trampoline_gates_with_offsets(&mut malformed, offsets).is_err());
        assert_eq!(malformed, before);
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
                RewriteConfig::new(Host::Linux, false),
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
        for kind in 5..16 {
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
                        commit_offset: match metadata {
                            GateMetadata::Svc => 0,
                            GateMetadata::MrsTpidr { .. } => 4,
                            GateMetadata::MsrTpidr { .. } => 20,
                            GateMetadata::X18 { .. }
                            | GateMetadata::X18Conditional { .. }
                            | GateMetadata::X18Br => unreachable!(),
                        },
                        original_site: 0x1000
                            + match metadata {
                                GateMetadata::MrsTpidr { .. } => 0,
                                GateMetadata::MsrTpidr { .. } => 4,
                                GateMetadata::Svc => 8,
                                GateMetadata::X18 { .. }
                                | GateMetadata::X18Conditional { .. }
                                | GateMetadata::X18Br => unreachable!(),
                            },
                        metadata,
                        x18: None,
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

    fn finalized_x18_fixture() -> (Vec<u8>, Vec<u8>, u64, usize, usize) {
        let site = 0x1000;
        let base = 0x200000;
        let (code, outcome) = hook_words_opt_with_config(
            &[0xaa00_03f2],
            site,
            base,
            RewriteConfig::new(Host::Linux, true),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        finalize_trampoline_gates_with_offsets(
            &mut trampoline,
            Aarch64GateOffsets::new(96, 104, 112, 120).unwrap(),
        )
        .unwrap();
        (
            code,
            trampoline,
            base,
            GATES_START_OFFSET,
            GATES_START_OFFSET + X18_SETUP_BYTES,
        )
    }

    fn finalized_x18_conditional_fixture() -> (Vec<u8>, usize) {
        let (_code, outcome) = hook_words_opt_with_config(
            &[0xb400_0032, NOP], // cbz x18, +4
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        finalize_trampoline_gates_with_offsets(
            &mut trampoline,
            Aarch64GateOffsets::new(96, 104, 112, 120).unwrap(),
        )
        .unwrap();
        (trampoline, GATES_START_OFFSET + X18_SETUP_BYTES)
    }

    #[test]
    fn x18_copied_site_classification_is_exact_and_exposes_provenance() {
        let (_code, trampoline, base, _setup, site_slot) = finalized_x18_fixture();
        let slot = &trampoline[site_slot..site_slot + X18_SLOT_BYTES];
        for offset in (0..X18_GATE_BYTES).step_by(INSN_BYTES) {
            let gate = classify_copied_gate_slot(
                slot,
                base + site_slot as u64,
                base + (site_slot + offset) as u64,
            )
            .unwrap_or_else(|| panic!("x18 site +{offset} did not classify"));
            assert_eq!(gate.original_site(), 0x1000);
            let details = gate.x18().expect("x18 details");
            assert_eq!(details.original_instruction(), 0xaa00_03f2);
            assert_eq!(details.transformed_instruction(), 0xaa00_03f1);
            assert_eq!(details.setup_handler(), base + GATES_START_OFFSET as u64);
            assert_eq!(details.setup_call_offset(), 12);
            assert_eq!(details.post_setup_offset(), 16);
            assert_eq!(details.transformed_instruction_offset(), 24);
            assert_eq!(details.return_offset(), 40);
        }
        for offset in (X18_GATE_BYTES..X18_SLOT_BYTES).step_by(INSN_BYTES) {
            assert_eq!(
                classify_copied_gate_slot(
                    slot,
                    base + site_slot as u64,
                    base + (site_slot + offset) as u64
                ),
                None,
                "accepted x18 padding/metadata +{offset}"
            );
        }
        assert_eq!(
            classify_copied_gate_slot(slot, base + site_slot as u64, base + site_slot as u64 + 1),
            None
        );
    }

    #[test]
    fn x18_copied_site_rejects_every_forged_relationship() {
        let (_code, trampoline, base, _setup, site_slot) = finalized_x18_fixture();
        let pristine = &trampoline[site_slot..site_slot + X18_SLOT_BYTES];
        for (offset, replacement, label) in [
            (4, NOP, "metadata scratches"),
            (12, Insn::Bl(0).encode().unwrap(), "setup BL target"),
            (24, NOP, "transformed instruction"),
            (
                28,
                Insn::StrUimm {
                    rt: 17,
                    rn: 16,
                    imm_bytes: GUEST_X18_OFFSET_PLACEHOLDER,
                }
                .encode()
                .unwrap(),
                "placeholder after finalization",
            ),
            (
                32,
                Insn::LdrUimm {
                    rt: 17,
                    rn: 16,
                    imm_bytes: 112,
                }
                .encode()
                .unwrap(),
                "wrong finalized access",
            ),
            (40, Insn::B(0).encode().unwrap(), "return branch"),
            (44, 0, "original instruction descriptor"),
        ] {
            let mut slot = pristine.to_vec();
            slot[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
            assert_eq!(
                classify_copied_gate_slot(&slot, base + site_slot as u64, base + site_slot as u64),
                None,
                "accepted forged {label}"
            );
        }

        let mut other_valid_transformation = pristine.to_vec();
        other_valid_transformation[24..28].copy_from_slice(&0xaa11_03e0u32.to_le_bytes());
        assert_eq!(
            classify_copied_gate_slot(
                &other_valid_transformation,
                base + site_slot as u64,
                base + site_slot as u64,
            ),
            None,
            "a different valid same-pair transformation must not match the stored original",
        );

        let mut other_valid_descriptor = pristine.to_vec();
        other_valid_descriptor[44..48].copy_from_slice(&0xaa12_03e0u32.to_le_bytes());
        assert_eq!(
            classify_copied_gate_slot(
                &other_valid_descriptor,
                base + site_slot as u64,
                base + site_slot as u64,
            ),
            None,
            "a different valid same-pair original must not match the transformed instruction",
        );
    }

    #[test]
    fn x18_original_descriptor_is_not_scanned_as_a_placeholder_access() {
        let original = Insn::LdrUimm {
            rt: 2,
            rn: 18,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        let (_code, outcome) = hook_words_opt_with_config(
            &[original],
            0x1000,
            0x200000,
            RewriteConfig::new(Host::Linux, true),
        );
        let mut trampoline = outcome.unwrap().trampoline;
        let offsets = Aarch64GateOffsets::new(96, 104, 112, 120).unwrap();

        finalize_trampoline_gates_with_offsets(&mut trampoline, offsets).unwrap();

        assert_eq!(find_guest_tpidr_placeholder(&trampoline), None);
    }

    #[test]
    fn x18_setup_record_has_separate_exact_classifier() {
        let (_code, trampoline, base, setup, site_slot) = finalized_x18_fixture();
        let record = &trampoline[setup..setup + X18_SETUP_BYTES];
        for offset in (0..28).step_by(INSN_BYTES) {
            let classified = classify_copied_x18_setup_record(
                record,
                base + setup as u64,
                base + (setup + offset) as u64,
            )
            .unwrap_or_else(|| panic!("setup +{offset} did not classify"));
            assert_eq!(
                classified.instruction_offset(),
                u8::try_from(offset).unwrap()
            );
            assert_eq!(
                classified.metadata(),
                GateMetadata::X18 {
                    anchor_scratch: 16,
                    value_scratch: 17
                }
            );
        }
        assert_eq!(
            classify_copied_x18_setup_record(record, base + setup as u64, base + setup as u64 + 28),
            None
        );
        assert_eq!(
            classify_copied_gate_slot(record, base + setup as u64, base + setup as u64),
            None
        );

        let mut forged = record.to_vec();
        forged[20..24].copy_from_slice(
            &Insn::LdrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 120,
            }
            .encode()
            .unwrap()
            .to_le_bytes(),
        );
        assert_eq!(
            classify_copied_x18_setup_record(&forged, base + setup as u64, base + setup as u64),
            None
        );

        let site = &trampoline[site_slot..site_slot + X18_SLOT_BYTES];
        assert_eq!(
            classify_copied_x18_setup_record(
                site,
                base + site_slot as u64,
                base + site_slot as u64
            ),
            None
        );
    }

    #[test]
    fn x18_topology_rejects_orphan_setup_and_orphan_site() {
        let (_code, trampoline, _base, setup, site) = finalized_x18_fixture();
        let setup_record = &trampoline[setup..setup + X18_SETUP_BYTES];
        let site_slot = &trampoline[site..site + X18_SLOT_BYTES];

        assert_eq!(
            classify_x18_topology_for_host(setup_record, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
        assert_eq!(
            classify_x18_topology_for_host(site_slot, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
        assert_eq!(
            classify_x18_topology_for_host(&trampoline, crate::TargetHost::Linux),
            X18Topology::Valid
        );
    }

    #[test]
    fn x18_topology_distinguishes_absent_and_malformed_metadata() {
        let absent = [0u8; GATES_START_OFFSET];
        assert_eq!(
            classify_x18_topology_for_host(&absent, crate::TargetHost::Linux),
            X18Topology::Absent
        );

        let (_code, mut trampoline, _base, _setup, site) = finalized_x18_fixture();
        let at = site + X18_SLOT_BYTES - 4;
        let metadata = u32::from_le_bytes(trampoline[at..at + 4].try_into().unwrap())
            ^ (1 << GATE_METADATA_REGISTER_SHIFT);
        trampoline[at..at + 4].copy_from_slice(&metadata.to_le_bytes());
        assert_eq!(
            classify_x18_topology_for_host(&trampoline, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
    }

    #[test]
    fn x18_topology_rejects_orphan_conditional_site() {
        let (trampoline, site) = finalized_x18_conditional_fixture();
        let conditional = &trampoline[site..site + X18_CONDITIONAL_SLOT_BYTES];

        assert_eq!(
            classify_x18_topology_for_host(conditional, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
    }

    #[test]
    fn x18_topology_rejects_malformed_standalone_conditional_records() {
        let (trampoline, site) = finalized_x18_conditional_fixture();
        let mut malformed_template = trampoline[site..site + X18_CONDITIONAL_SLOT_BYTES].to_vec();
        malformed_template[24..28].copy_from_slice(&NOP.to_le_bytes());

        assert_eq!(
            classify_x18_topology_for_host(&malformed_template, crate::TargetHost::Linux),
            X18Topology::Malformed
        );

        let metadata = &trampoline[site + X18_CONDITIONAL_SLOT_BYTES - GATE_METADATA_BYTES
            ..site + X18_CONDITIONAL_SLOT_BYTES];
        let mut malformed_prefix = vec![0; GATES_START_OFFSET - GATE_METADATA_BYTES];
        malformed_prefix.extend_from_slice(metadata);
        assert_eq!(
            classify_x18_topology_for_host(&malformed_prefix, crate::TargetHost::Linux),
            X18Topology::Malformed
        );
    }

    #[test]
    fn structured_finalizer_rejects_unused_x18_setup_transactionally() {
        let (_code, trampoline, _base, setup, _site) = finalized_x18_fixture();
        let mut orphan = [
            trampoline[..GATES_START_OFFSET].to_vec(),
            trampoline[setup..setup + X18_SETUP_BYTES].to_vec(),
        ]
        .concat();
        let before = orphan.clone();
        let offsets = Aarch64GateOffsets::new(96, 104, 112, 120).unwrap();

        assert!(
            finalize_trampoline_gates_for_host(&mut orphan, offsets, crate::TargetHost::Linux)
                .is_err()
        );
        assert_eq!(orphan, before);
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
