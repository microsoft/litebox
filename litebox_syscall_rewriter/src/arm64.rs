// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 (ARM64) syscall rewriting support for Linux ELF binaries.
//!
//! Every AArch64 instruction is 4 bytes including a direct branch (`B imm26`)
//! with a ±128MB range. This lets us replace a single instruction with
//! a branch into the trampoline without instruction borrowing.
//!
//! The trampoline is placed just past the highest mapped segment, so every
//! site-to-gate branch points forward. A site farther than the `B imm26`
//! ±128MB reach from its gate cannot redirect; it is replaced with a sentinel
//! `BRK #TRAP_BRK_IMM` and reported as a trapped site. Any trapped site makes
//! the rewrite incomplete, so the ELF-level caller rejects the binary with
//! `Error::UnpatchableSyscalls`, mirroring the x86-64 unpatchable-syscall path.
//! Executing the `BRK` raises a synchronous debug exception, so a trapped site
//! faults the guest rather than letting the unpatched instruction escape to the
//! host kernel. Recognizing the `TRAP_BRK_IMM` immediate in the runtime — to
//! attribute the trap to the rewriter rather than a guest breakpoint — is
//! planned but not yet implemented.
//!
//! ### Assumption: executable sections contain only instructions
//!
//! The patch scan walks each executable section word-by-word and treats every
//! 4-byte word that matches the `SVC`/`MSR TPIDR_EL0`/`MRS TPIDR_EL0` bit
//! patterns as that instruction. It does **not** distinguish inline data — literal
//! pools or jump tables embedded in `.text` — from code, because a fixed-width
//! decode cannot tell a data word from an instruction with the same bits. In
//! practice this is safe: default AArch64 codegen places constants in `.rodata`,
//! not `.text`, and the odds of an unrelated data word colliding with these
//! patterns are tiny. A binary that stores such a word inside an executable section
//! would have it rewritten; bounding the scan to symbol-defined function ranges
//! (via `STT_FUNC` extents) would remove the assumption (TODO).
//!
//! Two kinds of access are involved, three forms of instruction gated:
//!
//! * `SVC #imm` — the syscall instruction (any immediate; Linux ignores it).
//!   Replaced with a branch to a per-site *SVC gate* that records the return
//!   address and falls through to the shared SVC handler, a thin shim that
//!   tail-jumps to the syscall callback.
//! * `MSR TPIDR_EL0, Xn` — a write to the thread pointer. Replaced with a branch
//!   to a per-site *MSR gate* that stores the guest value into the guest
//!   thread-pointer slot at `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`.
//! * `MRS Xd, TPIDR_EL0` — a read of the thread pointer. Replaced with a branch
//!   to a per-site *MRS gate* that loads the guest value from the same slot.
//!   `MRS XZR, TPIDR_EL0` is a discarded read and is left native.
//!
//! ## Thread-pointer virtualization
//!
//! The host owns the hardware `TPIDR_EL0` as a per-thread anchor; the guest's
//! logical thread pointer is a host-managed memory slot at `[TPIDR_EL0 +
//! GUEST_TPIDR_OFFSET]`. Every gated guest read/write of the thread pointer
//! addresses that slot with a scaled `LDR`/`STR` off the anchor:
//!
//! * the MSR gate reads the anchor (`MRS X16, TPIDR_EL0`) and stores the guest
//!   value into the slot;
//! * the MRS gate reads the anchor and loads the guest value from the slot.
//!
//! This mirrors the x64 model: the host keeps the native thread-pointer anchor,
//! the guest is statically relegated off it, and the gates emit nothing
//! TLS-related to the callback.
//!
//! ## Gate scratch storage and the stack invariant
//!
//! `SVC` and `MSR TPIDR_EL0` clobber no general-purpose registers, so a gate has
//! no free scratch register on entry. The SVC and MSR gates therefore spill their
//! scratch registers (and, for SVC, the computed return address the callback
//! reads back) to a frame carved out of the guest stack with `SUB SP, SP, #frame`
//! / `ADD SP, SP, #frame`. The MRS gate normally needs no frame: it reuses its own
//! destination register as scratch and never touches the stack. It does take one
//! when the host reads its guest thread-pointer offset at run time
//! (`GuestTpAddressing::RuntimeSlot`), because holding that offset costs a second
//! register that the guest may still be using — X16/X17 are reserved for linker
//! veneers, not dead at an arbitrary instruction the way they are at an `SVC`.
//!
//! Consequently those gates **require `SP` to hold a valid, writable,
//! 16-byte-aligned stack at the patched site** — the same condition the kernel
//! relies on when it writes a signal frame below `SP`, and which every conforming
//! AArch64 caller already satisfies at a syscall boundary. The gate decrements
//! `SP` before storing, so nothing (signal delivery included) writes into the
//! frame while it is live; there is no red-zone hazard. A site reached with `SP`
//! pointing at unmapped or guard memory would fault where the native instruction
//! would not. AArch64 offers no cheaper alternative: with no segment-relative
//! store (unlike x86's `gs:`-relative spill) and no free register, reaching any
//! runtime-owned scratch area would itself require first clobbering an unsaved
//! guest register to materialize a base pointer.
//!
//! ## Trampoline layout (Linux)
//!
//! ```text
//! Offset 0:   [8 bytes]  syscall callback address (filled at load time)
//! Offset 8:   [8 bytes]  shared SVC handler (LDR X16,<callback>; BR X16)
//! Offset 16:  per-site gates (SVC: 24 bytes, MSR: 36 bytes, MRS: 12 bytes)
//! ```
//!
//! A binary with **no** patch sites gets no trampoline at all: the rewriter
//! appends only a size-0 sentinel header (matching the x86-64 path), recording
//! that the image was checked and needs no redirection. Signal returns are
//! handled by the runtime (see "Signal returns" below).
//!
//! The offset-0 callback address is **filled in by the loader/runtime, not by
//! this crate.** The emitted trampolines are therefore *not runnable as-is*: a
//! loader must write the syscall-callback address at offset 0 before any guest
//! `SVC` reaches a gate. (`callback` may be passed to [`hook_syscalls_aarch64`]
//! to prefill offset 0.) The callback reads host TLS from `TPIDR_EL0` and the
//! guest thread pointer from `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]` itself.
//!
//! ## Signal returns
//!
//! This crate emits no sigreturn gate; `rt_sigreturn` is handled by the runtime.
//! The runtime installs its own sigreturn trampoline address into the signal
//! frame's return slot; because that is an absolute address (not a `B`), a
//! single runtime-owned gate is reachable from any guest regardless of the
//! ±128MB branch range, so no per-binary gate is required.
//!
//! ## Runtime contract
//!
//! Per thread, the runtime sets the hardware `TPIDR_EL0` to the host anchor and
//! reserves the guest thread-pointer slot at `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`.
//! No new callback ABI is introduced: the callback reaches host TLS through
//! `TPIDR_EL0` directly. Multi-threaded correctness depends only on the runtime
//! keeping the anchor valid and the slot reachable for every thread it starts;
//! no process-global table is involved, so concurrent threads never contend.
//!
//! ## Host-OS scope
//!
//! This module fully virtualizes the guest thread pointer against a stable
//! per-thread host anchor register. The model is host-OS-agnostic; only the
//! choice of anchor register varies per host, selected by [`Host`] (a gate names
//! its anchor through [`Host::anchor_read`]). On a Linux host the anchor is
//! `TPIDR_EL0` itself: the kernel preserves it across host execution, so the host
//! can keep its own value there as the anchor while the guest thread pointer
//! lives in the slot beside it. The instruction encoders and gate framing here
//! are host-agnostic; see [`Host`] for the per-host anchor registers and what
//! each additional host requires.

use alloc::format;
use alloc::vec::Vec;

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

/// `MRS Xd, TPIDRRO_EL0` (`0xD53BD06d`) — [`Host::MacOs`]'s anchor read.
/// `TPIDRRO_EL0` differs from `TPIDR_EL0` only in the `op2` system-register
/// field (3 instead of 2), which is bit 5 of the instruction word, so this is
/// exactly [`MRS_TPIDR_EL0_BITS`] with that bit set. Confirmed against a real
/// toolchain (`cc`/`otool -tvV` on an Apple M3 Pro): `mrs x9, TPIDR_EL0` and
/// `mrs x9, TPIDRRO_EL0` assemble to `0xD53BD049` and `0xD53BD069`
/// respectively. This is the EL0-*read-only* companion register, which Darwin
/// keeps pointing at the current pthread's thread-specific-data base; it is an
/// emitted-gate anchor only, never a scanned patch pattern (a Linux guest
/// image has no reason to contain it, and rewriting one would be wrong
/// anyway).
const MRS_TPIDRRO_EL0_BITS: u32 = 0xD53B_D060;

/// `BRK` immediate planted at a patch site whose gate lies outside the `B`
/// instruction's ±128MB reach. Executing the site raises a synchronous debug
/// exception (`SIGTRAP`) carrying this immediate, faulting the guest rather than
/// letting the unpatched instruction escape to the host kernel; the site is also
/// reported as a trapped site so the ELF-level caller can reject the binary.
///
/// Recognizing this immediate in the runtime — to attribute the trap to the
/// rewriter rather than a guest breakpoint — is planned but not yet implemented.
const TRAP_BRK_IMM: u16 = 0xB10B;

// --- Register operands used by the emitted gates/handlers ---
//
// X16/X17 are the intra-procedure scratch registers (IP0/IP1), and register
// number 31 names the stack pointer in a base-register position.

/// First scratch register (IP0).
const X16: u8 = 16;
/// Second scratch register (IP1).
const X17: u8 = 17;
/// Stack pointer (encoded as register 31 in a base-register field).
const SP: u8 = 31;
/// Zero register (register 31 in a transfer-register field, where it reads as
/// zero / discards writes — distinct from `SP`'s base-register meaning).
const XZR: u8 = 31;

// --- Guest thread-pointer virtualization ---
//
// The host owns the hardware `TPIDR_EL0` as a per-thread anchor; the guest's
// logical thread pointer is a memory slot the runtime reserves at a fixed byte
// offset from that anchor. Every gated guest read/write of the thread pointer
// addresses the slot with a scaled `LDR`/`STR` off `TPIDR_EL0`.

/// Byte offset from the host anchor in `TPIDR_EL0` at which the runtime reserves
/// this thread's guest thread-pointer slot. Every guest read/write of the thread
/// pointer is virtualized to `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]` via a scaled
/// `LDR`/`STR`.
///
/// Fixed ABI offset: the runtime points `TPIDR_EL0` at a per-thread block whose
/// `guest_tp` field sits just past the AArch64 variant-1 16-byte TCB header, so a
/// stray "deref `TPIDR_EL0` as a TCB" cannot mistake the guest pointer for the
/// dtv slot. Because the scaled immediate is baked into statically rewritten
/// binaries, this value is part of the rewriter/runtime ABI and must match the
/// runtime's block layout.
const GUEST_TPIDR_OFFSET: u16 = 16;

/// [`Host::MacOs`]'s counterpart of [`GUEST_TPIDR_OFFSET`]: the byte offset
/// from the macOS anchor (`TPIDRRO_EL0`) of the guest thread-pointer slot.
///
/// On Darwin the anchor register is *kernel-owned*: `TPIDRRO_EL0` points at
/// the current pthread's thread-specific-data array (TSD slot `N` lives at
/// `[TPIDRRO_EL0 + N*8]`, with no low-bit masking on arm64 — verified against
/// xnu's `libsyscall/os/tsd.h` `_os_tsd_get_base`), so the runtime cannot
/// point it at a block of its own the way the Linux runtime does with
/// `TPIDR_EL0`. Instead the guest thread-pointer slot is a pthread TSD slot:
/// index [`MACOS_GUEST_TPIDR_TSD_SLOT`], i.e. byte offset `256 * 8`.
///
/// Slot 256 is the *first dynamic key* on macOS (`pthread_key_create` hands
/// out keys 256..768 there; 0..255 are reserved static keys — values verified
/// against apple-oss-distributions/libpthread `pthread_tsd.c` and
/// `types_internal.h`). The runtime owns it by calling `pthread_key_create`
/// during platform init, before anything else in the process creates a
/// dynamic key, and verifying it was handed exactly this slot; reading and
/// writing the slot directly off `TPIDRRO_EL0` is then the same "direct TSD"
/// fast path libSystem's own `errno` accessor and WebKit's `FastTLS`
/// (`_pthread_getspecific_direct`) use. Like [`GUEST_TPIDR_OFFSET`], this is
/// rewriter/runtime ABI: statically rewritten binaries bake the scaled
/// immediate in.
const GUEST_TPIDR_OFFSET_MACOS: u16 = MACOS_GUEST_TPIDR_TSD_SLOT * 8;

/// The pthread TSD slot index backing [`GUEST_TPIDR_OFFSET_MACOS`]. Exported
/// (via the crate root) so the macOS runtime reserves exactly the slot the
/// emitted gates address, rather than the two ever drifting apart.
pub(crate) const MACOS_GUEST_TPIDR_TSD_SLOT: u16 = 256;

// --- SVC gate stack frame ---
//
// The SVC gate touches only X16, so it needs a minimal 16-byte frame: one slot
// for the saved guest X16 and one for the computed post-SVC return address.

/// SVC gate frame size (`SUB/ADD SP, SP, #SVC_FRAME_BYTES`). 16-byte aligned.
const SVC_FRAME_BYTES: u16 = 16;
/// Saved guest X16.
const SVC_FRAME_OFF_X16: u16 = 0;
/// Computed post-SVC return address.
const SVC_FRAME_OFF_RETADDR: u16 = 8;

// --- MSR gate stack frame ---
//
// The MSR gate spills X16/X17 (one `STP`/`LDP` pair) and stages the captured
// guest value so the source register needs no special-casing.

/// MSR gate frame size (`SUB/ADD SP, SP, #MSR_FRAME_BYTES`). 16-byte aligned.
const MSR_FRAME_BYTES: u16 = 32;
/// Saved X16 (and, +8, X17 via the `STP`/`LDP` pair).
const MSR_FRAME_OFF_X16: u16 = 0;
/// Captured guest thread-pointer value, staged while all guest registers are
/// still pristine.
const MSR_FRAME_OFF_VALUE: u16 = 16;

// --- MRS gate stack frame ---
//
// Only the `GuestTpAddressing::RuntimeSlot` form needs a frame, to borrow one
// scratch register for the loaded offset. The baked form touches only `Rd` and
// emits no frame at all.

/// MRS gate frame size (`SUB/ADD SP, SP, #MRS_FRAME_BYTES`). 16-byte aligned:
/// AArch64 requires `SP` to stay 16-byte aligned on every access that uses it as
/// a base, so 16 is the smallest legal frame even though one register is spilled.
const MRS_FRAME_BYTES: u16 = 16;
/// Saved scratch register.
const MRS_FRAME_OFF_SCRATCH: u16 = 0;

// --- Trampoline layout offsets (all in bytes) ---

/// Callback address slot.
const HEADER_CALLBACK_OFFSET: usize = 0;

/// Guest thread-pointer *byte offset* slot, read by [`Host::MacOs`] gates.
///
/// Holds the byte offset from the host anchor at which the runtime keeps the
/// guest thread pointer — never the thread pointer itself. A `Host::MacOs` gate
/// loads this word and addresses `[TPIDRRO_EL0 + offset]`, so the number the
/// gates use is settled when the image is loaded rather than when it is
/// packaged. That is the whole point of the slot: the TSD key a macOS runtime
/// gets from `pthread_key_create` is a property of the runner binary's own
/// startup sequence, which the ahead-of-time rewriter cannot know.
///
/// A thread-pointer *value* could not live here. The loader maps the trampoline
/// writable, fills the header, then flips it to read+execute
/// (`litebox_common_linux`'s `load_trampoline`), so nothing may write this word
/// again once a guest runs — and one word cannot serve two threads anyway. An
/// offset is constant for the process; the per-thread part comes from
/// `TPIDRRO_EL0`, which is already per-thread.
///
/// The rewriter seeds it with [`GUEST_TPIDR_OFFSET_MACOS`], so an image whose
/// loader does not fill the slot keeps the exact behaviour of the earlier
/// baked-immediate gates instead of addressing offset zero — which would be
/// pthread TSD slot 0, live libpthread state.
pub(crate) const HEADER_GUEST_TP_OFFSET_MACOS: usize = HEADER_CALLBACK_OFFSET + 8;

/// Shared SVC handler, placed just past the trampoline header slots. Per-site gates
/// follow it and are each appended dynamically, so this shared prologue is the
/// only fixed-offset region the emitters reference.
const SHARED_SVC_HANDLER_OFFSET: usize = HEADER_GUEST_TP_OFFSET_MACOS + 8;

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
/// 19-bit `imm19` offset field (`B.cond`/`LDR`-literal/`ADRP` immhi), bits \[18:0].
const IMM19_MASK: u32 = 0x0007_FFFF;

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
    Adrp = 0x9000_0000,
    Br = 0xD61F_0000,
    SubImm = 0xD100_0000,
    AddImm = 0x9100_0000,
    StrUimm = 0xF900_0000,
    LdrUimm = 0xF940_0000,
    /// `LDR Xt, [Xn, Xm]` — register offset, `option=LSL`, `S=0`, so `Xm` is a
    /// byte offset rather than an element index. The base word already carries
    /// bit 21 and `bits[11:10]=0b10`; those two fields are what select the
    /// register-offset class at all, and clearing either one decodes as an
    /// `LDUR` with a garbage immediate rather than failing.
    LdrReg = 0xF860_6800,
    /// `ADD Xd, Xn, Xm` — shifted register, `LSL #0`.
    AddReg = 0x8B00_0000,
    Stp = 0xA900_0000,
    Ldp = 0xA940_0000,
    MrsTpidrEl0 = MRS_TPIDR_EL0_BITS,
    /// [`Host::MacOs`]'s anchor read.
    MrsTpidrroEl0 = MRS_TPIDRRO_EL0_BITS,
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
    Some(op.bits() | ((imm19.cast_unsigned() & IMM19_MASK) << 5) | low)
}

/// `op | rn<<5` — instruction whose only operand is a register in the `Rn` field
/// (`BR`/`RET`).
fn reg_in_rn(op: Opcode, rn: u8) -> u32 {
    op.bits() | (u32::from(rn) << 5)
}

/// `op | imm12<<10 | rn<<5 | rd` — 12-bit-immediate add/sub form
/// (`ADD`/`SUB`/`ADDS`). The caller supplies an already-scaled `imm12`.
fn data_imm12(op: Opcode, rd: u8, rn: u8, imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    Some(op.bits() | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rd))
}

/// `op | imm12<<10 | rn<<5 | rt` — unsigned scaled (×8) 64-bit load/store
/// (`STR`/`LDR [Xn, #imm]`). `imm_bytes` must be a multiple of 8.
fn ldst_uimm12(op: Opcode, rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
    if !imm_bytes.is_multiple_of(8) {
        return None;
    }
    let imm12 = imm_bytes / 8;
    if imm12 >= (1 << 12) {
        return None;
    }
    Some(op.bits() | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rt))
}

/// `op | rm<<16 | rn<<5 | rt` — register-offset 64-bit load
/// (`LDR Xt, [Xn, Xm]`). Every fixed field, including the `option`, `S` and
/// bit-21 bits that select the register-offset class, is already part of `op`.
fn ldst_reg_offset(op: Opcode, rt: u8, rn: u8, rm: u8) -> u32 {
    op.bits() | (u32::from(rm) << 16) | (u32::from(rn) << 5) | u32::from(rt)
}

/// `op | rm<<16 | rn<<5 | rd` — three-register data-processing form
/// (`ADD Xd, Xn, Xm`).
fn data_reg(op: Opcode, rd: u8, rn: u8, rm: u8) -> u32 {
    op.bits() | (u32::from(rm) << 16) | (u32::from(rn) << 5) | u32::from(rd)
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
    let imm7_u = u32::from(imm7.cast_unsigned() & 0x7F);
    Some(op.bits() | (imm7_u << 15) | (u32::from(rt2) << 10) | (u32::from(rn) << 5) | u32::from(rt))
}

/// `base | rt` — system-register move (`MRS`/`MSR`); `base` already encodes the
/// system register and transfer direction.
fn sysreg_move(base: u32, rt: u8) -> u32 {
    base | u32::from(rt)
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
    /// `ADRP Xd, #page_off` — page-relative address, ±4GB (in 4KB pages).
    Adrp { rd: u8, page_off: i64 },
    /// `LDR Xt, <literal>` (PC-relative literal load), ±1MB, 4-byte aligned.
    LdrLiteral { rt: u8, off: i64 },
    /// `BR Xn` (branch to register).
    Br(u8),
    /// `SUB SP, SP, #imm12`.
    SubSp(u16),
    /// `ADD SP, SP, #imm12`.
    AddSp(u16),
    /// `ADD Xd, Xn, #imm12`.
    AddImm { rd: u8, rn: u8, imm12: u16 },
    /// `STR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    StrUimm { rt: u8, rn: u8, imm_bytes: u16 },
    /// `LDR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    LdrUimm { rt: u8, rn: u8, imm_bytes: u16 },
    /// `LDR Xt, [Xn, Xm]` — register offset, unscaled, so `Xm` is a byte offset.
    LdrReg { rt: u8, rn: u8, rm: u8 },
    /// `ADD Xd, Xn, Xm`.
    AddReg { rd: u8, rn: u8, rm: u8 },
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
    /// `MRS Xt, TPIDRRO_EL0` (read the EL0-read-only thread register — the
    /// Darwin pthread TSD base; [`Host::MacOs`]'s anchor read).
    MrsTpidrroEl0(u8),
    /// `BRK #imm16` — software breakpoint raising a synchronous debug exception.
    Brk(u16),
}

impl Insn {
    /// Encode to a 32-bit little-endian instruction word, or `None` if an
    /// operand is outside the instruction's encodable range.
    fn encode(self) -> Option<u32> {
        match self {
            Insn::B(off) => branch_imm26(Opcode::B, off),
            Insn::Adrp { rd, page_off } => {
                let imm = i32::try_from(page_off).ok()?;
                if !(-(1 << 20)..(1 << 20)).contains(&imm) {
                    return None;
                }
                let imm = imm.cast_unsigned();
                let immlo = (imm & 0x3) << 29;
                let immhi = ((imm >> 2) & IMM19_MASK) << 5;
                Some(Opcode::Adrp.bits() | immlo | immhi | u32::from(rd))
            }
            Insn::LdrLiteral { rt, off } => pcrel_imm19(Opcode::LdrLiteral, off, u32::from(rt)),
            Insn::Br(rn) => Some(reg_in_rn(Opcode::Br, rn)),
            Insn::SubSp(imm12) => data_imm12(Opcode::SubImm, SP, SP, imm12),
            Insn::AddSp(imm12) => data_imm12(Opcode::AddImm, SP, SP, imm12),
            Insn::AddImm { rd, rn, imm12 } => data_imm12(Opcode::AddImm, rd, rn, imm12),
            Insn::StrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::StrUimm, rt, rn, imm_bytes),
            Insn::LdrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::LdrUimm, rt, rn, imm_bytes),
            Insn::LdrReg { rt, rn, rm } => Some(ldst_reg_offset(Opcode::LdrReg, rt, rn, rm)),
            Insn::AddReg { rd, rn, rm } => Some(data_reg(Opcode::AddReg, rd, rn, rm)),
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
            Insn::MrsTpidrEl0(rt) => Some(sysreg_move(Opcode::MrsTpidrEl0.bits(), rt)),
            Insn::MrsTpidrroEl0(rt) => Some(sysreg_move(Opcode::MrsTpidrroEl0.bits(), rt)),
            Insn::Brk(imm) => Some(Opcode::Brk.bits() | (u32::from(imm) << 5)),
        }
    }
}

// ============================================================
// Host anchor selection
// ============================================================

/// The host OS the rewritten guest runs under.
///
/// The guest thread pointer is virtualized the same way on every host; only the
/// *anchor register* a gate reads to reach the host's per-thread block varies.
/// [`Host`] selects that register, so a gate names the anchor through
/// `Host::anchor_read` rather than hardcoding a system register. Adding a host
/// is a new variant plus its anchor-read arm.
///
/// A host OS beyond these two needs a different stable anchor register (a
/// future variant supplying its own `anchor_read` and `guest_tp_offset`):
///
/// * **Linux-on-Windows** (Windows on ARM64): Windows does not preserve
///   `TPIDR_EL0` across context switches and reserves `x18` as the TEB pointer
///   (always valid). The TEB is the stable anchor: the per-thread TLS state is
///   reached through a TEB TLS slot, and `TPIDR_EL0` (plus guest `x18`, where the
///   guest uses it) is virtualized against that.
#[derive(Clone, Copy)]
pub enum Host {
    /// Linux host. The kernel preserves `TPIDR_EL0` across host execution, so the
    /// host keeps its anchor there and the guest thread-pointer slot lives beside
    /// it; the anchor read is `MRS Xd, TPIDR_EL0`.
    Linux,
    /// macOS host (Apple Silicon). Confirmed on real hardware (Apple M3 Pro,
    /// macOS 26.3.1): XNU clobbers `TPIDR_EL0` across both a voluntary
    /// context switch and a signal-handler invocation — not merely leaves it
    /// stale, but overwrites it with its own per-thread value — so it cannot
    /// anchor the guest thread pointer. The anchor is the EL0-read-only
    /// `TPIDRRO_EL0` (confirmed stable across a reschedule and distinct per
    /// thread on the same hardware), which Darwin keeps pointing at the
    /// current pthread's TSD base. The runtime cannot repoint a read-only,
    /// kernel-owned register at a block of its own the way the Linux runtime
    /// does with `TPIDR_EL0` — addressing a fixed raw offset into the pthread
    /// structure it points at would corrupt live libpthread state — so the
    /// guest thread-pointer slot is instead a *runtime-reserved pthread TSD
    /// slot*, addressed at `GUEST_TPIDR_OFFSET_MACOS`; see that constant
    /// for the verified TSD layout and how the runtime reserves the slot.
    ///
    /// Caveat, deliberate and documented rather than silently wrong: XNU also
    /// zeroes `x18` on every return to EL0 for ordinary (non-Rosetta,
    /// non-entitled) processes, so a guest binary that uses `x18` as a live
    /// general-purpose register cannot run correctly under this host. `x18`
    /// uses cannot be found reliably without full disassembly (any operand
    /// field of any instruction can name it), so they are not scanned or
    /// gated; guests should be built with `-ffixed-x18`. Linux AArch64
    /// distro binaries generally treat `x18` as allocatable, so this is a
    /// real restriction, not a formality.
    MacOs,
}

impl Host {
    /// The instruction a gate uses to read this host's per-thread anchor into
    /// `rd`.
    fn anchor_read(self, rd: u8) -> Insn {
        match self {
            Host::Linux => Insn::MrsTpidrEl0(rd),
            Host::MacOs => Insn::MrsTpidrroEl0(rd),
        }
    }

    /// How a gate on this host reaches the guest thread-pointer slot.
    fn guest_tp_addressing(self) -> GuestTpAddressing {
        match self {
            Host::Linux => GuestTpAddressing::Baked(GUEST_TPIDR_OFFSET),
            Host::MacOs => GuestTpAddressing::RuntimeSlot,
        }
    }
}

/// How a gate obtains the byte offset from the host anchor to the guest
/// thread-pointer slot.
///
/// The hosts differ in *when* that number is knowable, not in what it means, so
/// the choice is spelled out here rather than left implicit in each emitter.
#[derive(Clone, Copy)]
enum GuestTpAddressing {
    /// Rewriter/runtime ABI, fixed at packaging time and baked into each gate's
    /// scaled `LDR`/`STR` immediate. Linux qualifies: its runtime owns
    /// `TPIDR_EL0` outright and puts the slot at a compile-time offset beside its
    /// own block.
    Baked(u16),
    /// Read at run time from [`HEADER_GUEST_TP_OFFSET_MACOS`], because the
    /// packaging-time rewriter cannot know it. macOS qualifies: the anchor is
    /// kernel-owned and the slot is a pthread TSD key whose number depends on the
    /// runner binary's own startup sequence.
    RuntimeSlot,
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
}

/// Scan all executable sections for `SVC #imm`, `MSR TPIDR_EL0` (thread-pointer
/// writes), and `MRS TPIDR_EL0` (thread-pointer reads). AArch64 instructions are
/// always 4-byte aligned, so we step in 4-byte units. Returns sites in ascending
/// file order.
///
/// `MRS XZR, TPIDR_EL0` is a discarded read (register 31 as an `LDR` base would
/// mean `SP`), so it is left native; every other `MRS Xd, TPIDR_EL0` is gated.
fn find_patch_sites(sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
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
        let section_data = &buf[start..end];

        for i in (0..section_data.len()).step_by(4) {
            if i + 4 > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + 4].try_into().unwrap());
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                PatchKind::MsrTpidr((insn & 0x1F) as u8)
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                let rd = (insn & 0x1F) as u8;
                // `MRS XZR, TPIDR_EL0` discards its result (a no-op read); gating
                // it would mean using register 31 as an `LDR` base (= SP), so
                // leave it native.
                if rd == XZR {
                    continue;
                }
                PatchKind::MrsTpidr(rd)
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
    /// Virtual addresses of patch sites that could not be redirected to their
    /// gate — the inbound `B` or one of the gate's own branches fell outside the
    /// branch's ±128MB range — and were replaced with a trap instead of a
    /// redirect. A non-empty list means the rewrite is incomplete: those sites
    /// fault at runtime rather than entering the trampoline.
    pub trapped_sites: Vec<u64>,
}

/// Hook all `SVC #imm`, `MSR TPIDR_EL0` writes, and `MRS TPIDR_EL0` reads in an
/// AArch64 ELF image. (`MRS XZR, TPIDR_EL0` is a discarded read and is left
/// native — see the module docs.)
///
/// `buf` is patched in place; the returned [`HookOutcome::trampoline`] is the
/// blob that the caller appends after the ELF (page-aligned).
/// `trampoline_base_addr` is the virtual address the trampoline will be mapped
/// at; `callback` is the absolute address stored in the callback slot (0 if the
/// loader fills it in later).
///
/// Returns `Ok(None)` when the image contains no patch sites: no trampoline is
/// needed and the caller emits a size-0 sentinel header instead (matching the
/// x86-64 path). Signal returns are handled by the runtime — not a per-binary
/// gate — so a syscall-free binary needs no trampoline at all.
///
/// Otherwise returns `Ok(Some(outcome))`. A site whose inbound `B` cannot reach
/// its gate, or whose gate cannot branch back within the `B` instruction's
/// ±128MB reach, cannot be redirected; it is replaced with a trap and listed in
/// [`HookOutcome::trapped_sites`] so the caller can reject the incomplete
/// rewrite, mirroring the x86-64 unpatchable-syscall path.
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    host: Host,
) -> Result<Option<HookOutcome>> {
    let sites = find_patch_sites(text_sections, buf)?;

    if sites.is_empty() {
        // No patch sites: nothing to redirect, so no trampoline is
        // emitted. The caller writes a size-0 sentinel header instead.
        return Ok(None);
    }

    let mut trampoline_data: Vec<u8> = Vec::new();
    emit_shared_prologue(&mut trampoline_data, trampoline_base_addr, callback)?;

    let mut trapped_sites: Vec<u64> = Vec::new();

    for site in &sites {
        let gate_offset = trampoline_data.len();
        let gate_vaddr =
            checked_add_u64(trampoline_base_addr, gate_offset as u64, "trampoline gate")?;

        // A site is redirected to its gate with a single in-place `B` (±128MB
        // forward reach), and each gate branches back to `site + 4` (the SVC gate
        // also reaches its shared handler). The gate's return branch spans a wider
        // displacement than the inbound one, so the inbound branch encoding is
        // necessary but not sufficient: the gate is built only when the inbound
        // branch fits, and a gate whose own branches are out of range reports
        // `GateBuild::Unreachable` and appends nothing. If either the inbound
        // branch or the gate is unreachable, replace the site with the sentinel
        // trap, record it as unpatchable, and emit no gate.
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
                    host,
                )?,
                PatchKind::MrsTpidr(rd) => emit_mrs_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rd,
                    host,
                )?,
            }
        } else {
            GateBuild::Unreachable
        };

        if let (Some(b_insn), GateBuild::Emitted) = (inbound, build) {
            // Replace the original instruction with `B <gate>`.
            buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
        } else {
            let brk = Insn::Brk(TRAP_BRK_IMM)
                .encode()
                .expect("BRK always encodes");
            buf[site.file_offset..site.file_offset + 4].copy_from_slice(&brk.to_le_bytes());
            trapped_sites.push(site.vaddr);
        }
    }

    Ok(Some(HookOutcome {
        trampoline: trampoline_data,
        trapped_sites,
    }))
}

/// Emit the header slot and the shared SVC handler — the fixed-size shared
/// prologue that per-site gates follow.
fn emit_shared_prologue(
    trampoline_data: &mut Vec<u8>,
    trampoline_base_addr: u64,
    callback: u64,
) -> Result<()> {
    // Offset 0: callback address.
    trampoline_data.extend_from_slice(&callback.to_le_bytes());

    // Offset 8: guest thread-pointer byte offset, seeded with the packaging-time
    // default so a loader that does not fill it leaves the gates behaving exactly
    // as the earlier baked-immediate ones did. Zero would mean pthread TSD slot 0
    // on macOS, which is live libpthread state.
    trampoline_data.extend_from_slice(&u64::from(GUEST_TPIDR_OFFSET_MACOS).to_le_bytes());

    emit_shared_svc_handler(
        trampoline_data,
        SHARED_SVC_HANDLER_OFFSET,
        trampoline_base_addr,
    )?;

    Ok(())
}

// ============================================================
// SVC gate + shared SVC handler
// ============================================================

/// Whether a gate was fully emitted or could not be placed within reach.
///
/// A gate redirects back to the guest (and, for the SVC gate, out to the shared
/// handler) with PC-relative branches. When any of those branches is out of
/// range the gate emits nothing and reports [`GateBuild::Unreachable`], leaving
/// the trampoline blob untouched so the caller can trap the originating site.
enum GateBuild {
    Emitted,
    Unreachable,
}

/// Per-site SVC gate (6 instructions, 24 bytes, 16-byte frame).
///
/// Saves only X16 (already a scratch register), computes the post-SVC return
/// address into X16, records it on the frame, then branches to the shared SVC
/// handler. Guest X17/X18/LR and NZCV are untouched; the callback finds the
/// post-SVC return address at `[SP, #8]` and restores X16 from `[SP, #0]`.
///
/// Frame layout (relative to the decremented SP): `[0]=X16 [8]=return_addr`.
/// Requires `SP` to address a valid writable stack at the site (see the module
/// docs, "Gate scratch storage and the stack invariant").
fn emit_svc_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "SVC gate")?;
    let mut asm = Asm::new(gate_vaddr);

    // SUB SP, SP, #16 ; STR X16, [SP] — save the guest X16.
    asm.emit(Insn::SubSp(SVC_FRAME_BYTES));
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_X16,
    });

    // ADRP X16, <return_page>; ADD X16, X16, #<page offset> — post-SVC return
    // address.
    let return_addr = checked_add_u64(site.vaddr, 4, "SVC return")?;
    if !asm.adrp(X16, return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    let page_lo = u16::try_from(return_addr & 0xFFF).expect("masked to 12 bits");
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

    // B <shared SVC handler>.
    let handler_vaddr = checked_add_u64(
        trampoline_base_addr,
        SHARED_SVC_HANDLER_OFFSET as u64,
        "SVC handler",
    )?;
    if !asm.branch_to(handler_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

/// Shared SVC handler (2 instructions, 8 bytes).
///
/// A thin shim that conveys nothing TLS-related: it loads the syscall-callback
/// pointer from the trampoline header and tail-jumps to it. The callback reads
/// host TLS from `TPIDR_EL0` (the host anchor) and the guest thread pointer from
/// `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]` itself, so the handler carries no TLS state.
///
/// Nothing in the handler clobbers NZCV, so the guest's pre-svc flags reach the
/// callback unchanged with no save/restore.
fn emit_shared_svc_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
) -> Result<()> {
    let handler_vaddr =
        checked_add_u64(trampoline_base_addr, handler_offset as u64, "SVC handler")?;
    let callback_vaddr = checked_add_u64(
        trampoline_base_addr,
        HEADER_CALLBACK_OFFSET as u64,
        "callback slot",
    )?;
    let mut asm = Asm::new(handler_vaddr);

    // LDR X16, =callback ; BR X16. Nothing here clobbers NZCV, so the guest's
    // pre-svc flags reach the callback unchanged with no save/restore.
    asm.ldr_literal(X16, callback_vaddr)?;
    asm.emit(Insn::Br(X16));

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(())
}

// ============================================================
// MSR + MRS gates
// ============================================================

/// Per-site MSR gate (9 instructions, 36 bytes, 32-byte frame).
///
/// Virtualizes a guest `MSR TPIDR_EL0, Xn` write. The hardware register holds the
/// host anchor, so the gate stores the guest value into the guest thread-pointer
/// slot at `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`:
///
/// 1. spill X16/X17 and capture the guest value `Xn` to the frame while all guest
///    registers are still pristine (so `Xn` needs no special-casing, even when it
///    is one of the scratch registers just spilled (X16/X17) or XZR);
/// 2. `MRS X16, TPIDR_EL0` reads the host anchor;
/// 3. reload the captured value into X17 and `STR X17, [X16, #GUEST_TPIDR_OFFSET]`
///    stores it into the guest thread-pointer slot;
/// 4. restore X16/X17 and branch back to the instruction after the original MSR.
///
/// The slot is always reachable because `TPIDR_EL0` is the host anchor the
/// runtime keeps valid, so a guest value of `0` (XZR) is an ordinary store — never
/// a fault.
///
/// The X16/X17 spill and the captured value use a guest-stack frame, so this gate
/// requires `SP` to address a valid writable stack at the site (see the module
/// docs, "Gate scratch storage and the stack invariant").
///
/// `MSR TPIDR_EL0` does not touch the condition flags and the gate uses only
/// plain loads/stores and `B` (never `BL`), so NZCV and X30 reach the guest
/// unchanged with no save/restore.
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

    // Put the slot's address in X16, then store the captured guest value through
    // it. Under `Baked` the address is anchor + immediate, so the immediate rides
    // on the store itself; under `RuntimeSlot` the offset is a loaded value, so it
    // has to be folded into the base first — a register-offset store would need
    // three live registers (value, base, offset) and this gate has only X16/X17.
    match host.guest_tp_addressing() {
        GuestTpAddressing::Baked(offset) => {
            // MRS X16, <anchor> ; LDR X17, [SP, #16] ; STR X17, [X16, #offset].
            asm.emit(host.anchor_read(X16));
            asm.emit(Insn::LdrUimm {
                rt: X17,
                rn: SP,
                imm_bytes: MSR_FRAME_OFF_VALUE,
            });
            asm.emit(Insn::StrUimm {
                rt: X17,
                rn: X16,
                imm_bytes: offset,
            });
        }
        GuestTpAddressing::RuntimeSlot => {
            // LDR X16, <offset slot> ; MRS X17, <anchor> ; ADD X16, X17, X16
            // ; LDR X17, [SP, #16] ; STR X17, [X16].
            let slot_vaddr = checked_add_u64(
                trampoline_base_addr,
                HEADER_GUEST_TP_OFFSET_MACOS as u64,
                "MSR guest-TP offset slot",
            )?;
            if !asm.ldr_literal_reachable(X16, slot_vaddr)? {
                return Ok(GateBuild::Unreachable);
            }
            asm.emit(host.anchor_read(X17));
            asm.emit(Insn::AddReg {
                rd: X16,
                rn: X17,
                rm: X16,
            });
            asm.emit(Insn::LdrUimm {
                rt: X17,
                rn: SP,
                imm_bytes: MSR_FRAME_OFF_VALUE,
            });
            asm.emit(Insn::StrUimm {
                rt: X17,
                rn: X16,
                imm_bytes: 0,
            });
        }
    }

    // Restore: LDP X16, X17, [SP] ; ADD SP, SP, #32.
    asm.emit(Insn::Ldp {
        rt: X16,
        rt2: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_X16.cast_signed(),
    });
    asm.emit(Insn::AddSp(MSR_FRAME_BYTES));

    // B <return_addr>.
    if !asm.branch_to(checked_add_u64(site.vaddr, 4, "MSR return")?)? {
        return Ok(GateBuild::Unreachable);
    }

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

/// Per-site MRS gate (3 instructions baked, 8 with a runtime offset).
///
/// Virtualizes a guest `MRS Xd, TPIDR_EL0` read. The hardware register holds the
/// host anchor, so the gate reads the anchor and then loads the guest thread
/// pointer from its slot.
///
/// Under [`GuestTpAddressing::Baked`] the offset is an immediate, so `Xd` — which
/// the guest's own `MRS` was about to overwrite anyway — is the only register
/// touched and no frame is needed:
/// `MRS Xd, TPIDR_EL0 ; LDR Xd, [Xd, #GUEST_TPIDR_OFFSET] ; B <site+4>`.
///
/// Under [`GuestTpAddressing::RuntimeSlot`] the offset arrives in a register, so
/// the gate needs a second one and must give it back untouched: an `MRS` site is
/// an ordinary instruction in the middle of a function, not a call boundary, and
/// X16/X17 are only reserved for linker veneers — a compiler is free to keep a
/// live value in either across it. The gate therefore spills its scratch to a
/// 16-byte frame, which makes this variant share the SVC and MSR gates'
/// requirement that `SP` address a valid writable stack at the site (see the
/// module docs, "Gate scratch storage and the stack invariant").
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

    match host.guest_tp_addressing() {
        GuestTpAddressing::Baked(offset) => {
            asm.emit(host.anchor_read(rd));
            asm.emit(Insn::LdrUimm {
                rt: rd,
                rn: rd,
                imm_bytes: offset,
            });
        }
        GuestTpAddressing::RuntimeSlot => {
            // The scratch register must not be `rd`: the anchor read lands in `rd`
            // and would destroy a loaded offset held there.
            let scratch = if rd == X16 { X17 } else { X16 };

            let slot_vaddr = checked_add_u64(
                trampoline_base_addr,
                HEADER_GUEST_TP_OFFSET_MACOS as u64,
                "MRS guest-TP offset slot",
            )?;

            // SUB SP, SP, #16 ; STR Xs, [SP] — spill the borrowed scratch.
            asm.emit(Insn::SubSp(MRS_FRAME_BYTES));
            asm.emit(Insn::StrUimm {
                rt: scratch,
                rn: SP,
                imm_bytes: MRS_FRAME_OFF_SCRATCH,
            });

            // LDR Xs, <offset slot> ; MRS Xd, <anchor> ; LDR Xd, [Xd, Xs].
            if !asm.ldr_literal_reachable(scratch, slot_vaddr)? {
                return Ok(GateBuild::Unreachable);
            }
            asm.emit(host.anchor_read(rd));
            asm.emit(Insn::LdrReg {
                rt: rd,
                rn: rd,
                rm: scratch,
            });

            // LDR Xs, [SP] ; ADD SP, SP, #16 — hand the scratch back.
            asm.emit(Insn::LdrUimm {
                rt: scratch,
                rn: SP,
                imm_bytes: MRS_FRAME_OFF_SCRATCH,
            });
            asm.emit(Insn::AddSp(MRS_FRAME_BYTES));
        }
    }

    if !asm.branch_to(checked_add_u64(site.vaddr, 4, "MRS return")?)? {
        return Ok(GateBuild::Unreachable);
    }
    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

// ============================================================
// Small helpers
// ============================================================

/// A position-tracking assembler for one trampoline fragment (a gate or a shared
/// handler). It owns the emitted words and the base virtual address of the first
/// word, so the current vaddr — [`Asm::here`] — is always known without manual
/// instruction counting.
///
/// Branches and loads to an absolute target ([`Asm::branch_to`],
/// [`Asm::ldr_literal`], [`Asm::ldr_literal_reachable`], [`Asm::adrp`]) resolve
/// immediately against [`Asm::here`]. Everything a *per-site gate* emits
/// ([`Asm::branch_to`], [`Asm::ldr_literal_reachable`], [`Asm::adrp`]) reports an
/// out-of-range target by emitting nothing and returning `false`, so the caller
/// can trap that one site and keep rewriting; [`Asm::ldr_literal`], used by the
/// fixed prologue, instead errors, since a prologue that cannot be placed is
/// fatal. A gate reaching for the fatal variant would turn one unreachable site
/// into a failed rewrite of the whole image.
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

    /// `LDR Xt, <target>` — PC-relative literal load that reports reach instead
    /// of failing. An out-of-range target emits nothing and yields `false`, so a
    /// per-site gate can trap its own site and leave the rest of the rewrite
    /// intact. [`Asm::ldr_literal`] is the fatal variant, for the fixed prologue.
    fn ldr_literal_reachable(&mut self, rt: u8, target_vaddr: u64) -> Result<bool> {
        let offset = self.delta_to(target_vaddr)?;
        let Some(word) = (Insn::LdrLiteral { rt, off: offset }).encode() else {
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

    /// `ADRP Xd, <target>` — page-relative address of an absolute target.
    /// Returns whether the target's page was within ADRP's ±4GB reach (see
    /// [`Asm::branch_to`] for the out-of-range contract).
    fn adrp(&mut self, rd: u8, target_vaddr: u64) -> Result<bool> {
        let here = self.here()?;
        let page_off = (target_vaddr & !0xFFF)
            .cast_signed()
            .saturating_sub((here & !0xFFF).cast_signed())
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
    use alloc::vec;

    // Gate and shared-handler sizes. The emitters append each gate dynamically
    // (`gate_offset = trampoline_data.len()`), so these sizes drive no emission;
    // the tests use them to slice individual gates out of the trampoline blob and
    // to assert its total length. `GATES_START_OFFSET` is the fixed shared-prologue
    // size that the per-site gates follow.
    const SVC_GATE_INSNS: usize = 6;
    const SVC_GATE_SIZE: usize = SVC_GATE_INSNS * 4;
    const SHARED_SVC_HANDLER_INSNS: usize = 2;
    const SHARED_SVC_HANDLER_SIZE: usize = SHARED_SVC_HANDLER_INSNS * 4;
    const MSR_GATE_INSNS: usize = 9;
    const MSR_GATE_SIZE: usize = MSR_GATE_INSNS * 4;
    const MRS_GATE_INSNS: usize = 3;
    const MRS_GATE_SIZE: usize = MRS_GATE_INSNS * 4;
    // `GuestTpAddressing::RuntimeSlot` sizes: the MSR gate gains the offset load
    // and the fold into the base; the MRS gate gains those plus its spill pair.
    const MSR_GATE_INSNS_RUNTIME_SLOT: usize = MSR_GATE_INSNS + 2;
    const MSR_GATE_SIZE_RUNTIME_SLOT: usize = MSR_GATE_INSNS_RUNTIME_SLOT * 4;
    const MRS_GATE_INSNS_RUNTIME_SLOT: usize = MRS_GATE_INSNS + 5;
    const MRS_GATE_SIZE_RUNTIME_SLOT: usize = MRS_GATE_INSNS_RUNTIME_SLOT * 4;
    const GATES_START_OFFSET: usize = SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE;

    /// Top-6 opcode bits, isolating the `B`/`BL` major opcode for read-back checks.
    const OPCODE_TOP6_MASK: u32 = 0xFC00_0000;

    fn word_at(data: &[u8], byte_off: usize) -> u32 {
        u32::from_le_bytes(data[byte_off..byte_off + 4].try_into().unwrap())
    }

    /// `MSR TPIDR_EL0, Xrt` guest instruction word (the low 5 bits select Xrt).
    /// The rewriter only matches/scans this form; it never emits it, so the
    /// encoder lives only here for building test inputs.
    fn msr_tpidr_el0(rt: u8) -> u32 {
        MSR_TPIDR_EL0_BITS | u32::from(rt)
    }

    /// Helper: emit just the shared SVC handler and return its instruction words.
    fn shared_svc_handler_words() -> vec::Vec<u32> {
        let mut buf = vec::Vec::new();
        emit_shared_svc_handler(&mut buf, 0, 0x1000).unwrap();
        buf.as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_le_bytes(*w))
            .collect()
    }

    #[test]
    fn svc_handler_jumps_to_callback_without_tls() {
        let words = shared_svc_handler_words();
        assert_eq!(words.len(), SHARED_SVC_HANDLER_INSNS);
        // The handler conveys nothing TLS-related: it loads the callback pointer
        // and tail-jumps. The callback reads host TLS from TPIDR_EL0 itself.
        assert_eq!(
            words[1],
            Insn::Br(X16).encode().unwrap(),
            "handler ends in BR X16"
        );
        // No MRS TPIDR_EL0 anywhere in the handler.
        assert!(
            !words
                .iter()
                .any(|&w| w & MRS_TPIDR_EL0_MASK == MRS_TPIDR_EL0_BITS)
        );
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
        // TPIDR_EL0 accessor.
        assert_eq!(Insn::MrsTpidrEl0(9).encode().unwrap(), 0xD53B_D049);
        // TPIDRRO_EL0 accessor (`Host::MacOs`'s anchor read). Cross-checked
        // against a real toolchain: `cc -c` + `otool -tvV` on an Apple M3 Pro
        // assembles `mrs x9, tpidrro_el0` to this exact word.
        assert_eq!(Insn::MrsTpidrroEl0(9).encode().unwrap(), 0xD53B_D069);
        // `MSR TPIDR_EL0, X9` guest word (scanned, never emitted).
        assert_eq!(msr_tpidr_el0(9), 0xD51B_D049);
        // Register-offset load and three-register add, cross-checked against a
        // real toolchain (`clang -arch arm64` + `otool -t` on an Apple M3 Pro):
        // `ldr x0,[x1,x2]` and `add x0,x1,x2`.
        //
        // These two words are worth pinning exactly. The register-offset class is
        // selected by bit 21 together with `bits[11:10]=0b10`; drop either and the
        // word silently decodes as an `LDUR` with an unrelated immediate rather
        // than failing to encode, so a mask-based check can pass on an encoding
        // that addresses the wrong memory.
        assert_eq!(
            Insn::LdrReg {
                rt: 0,
                rn: 1,
                rm: 2
            }
            .encode()
            .unwrap(),
            0xF862_6820
        );
        assert_eq!(
            Insn::AddReg {
                rd: 0,
                rn: 1,
                rm: 2
            }
            .encode()
            .unwrap(),
            0x8B02_0020
        );
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
        // The guest thread-pointer slot lives at the fixed ABI offset
        // GuestThreadBlock::guest_tp; pin both the value and the emitted word.
        assert_eq!(GUEST_TPIDR_OFFSET, 16);
        // Slot access at GUEST_TPIDR_OFFSET: `ldr x9,[x9,#16]` / `str x17,[x16,#16]`.
        assert_eq!(
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: GUEST_TPIDR_OFFSET
            }
            .encode()
            .unwrap(),
            0xF940_0929
        );
        assert_eq!(
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: GUEST_TPIDR_OFFSET
            }
            .encode()
            .unwrap(),
            0xF900_0A11
        );
        // `BRK #0xB10B`, the trap that replaces an out-of-range patch site.
        assert_eq!(Insn::Brk(TRAP_BRK_IMM).encode().unwrap(), 0xD436_2160);
    }

    #[test]
    fn encoder_range_checks() {
        assert!(Insn::B(2).encode().is_none()); // not 4-aligned
        assert!(Insn::B(1 << 27).encode().is_none()); // out of ±128MB
        assert!(
            Insn::StrUimm {
                rt: 0,
                rn: 0,
                imm_bytes: 4
            }
            .encode()
            .is_none()
        ); // not 8-scaled
    }

    #[test]
    fn asm_ldr_literal_computes_pc_relative_offset() {
        let mut asm = Asm::new(0x1000);
        asm.emit(Insn::Br(30)); // [0] at 0x1000
        asm.ldr_literal(16, 0x1010).unwrap(); // [1] at 0x1004, target 0x1010 => +0xC
        let code = asm.finish();
        assert_eq!(
            word_at(&code, 4),
            Insn::LdrLiteral { rt: 16, off: 0xC }.encode().unwrap()
        );
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
        hook_words_host(words, base, tramp_base, Host::Linux)
    }

    /// Like [`hook_words_opt`] with an explicit [`Host`].
    fn hook_words_host(
        words: &[u32],
        base: u64,
        tramp_base: u64,
        host: Host,
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
        let outcome = hook_syscalls_aarch64(&mut buf, &sections, tramp_base, 0, host).unwrap();
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
        // The trampoline sits 256MB above the section, past the `B` instruction's
        // ±128MB reach, so the site cannot branch into its gate. It is replaced
        // with the sentinel `BRK`, surfaced as a trapped site, and no gate is
        // emitted for it, leaving the trampoline at the prologue-only size.
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
        // reach back. The MSR gate's return `B` is its last instruction, at
        // `gate + 32`, branching to `site + 4`; its displacement magnitude is
        // `b_offset + 28`, larger than the inbound `B`'s `b_offset`. Placing the
        // gate at the maximum encodable forward offset (`2^27 - 4`) makes the
        // inbound branch encode while the return needs `-(2^27 + 24)`, just past
        // the `-2^27` reach. The site must still be trapped gracefully — replaced
        // with `BRK` and surfaced through `trapped_sites` — not error out.
        let base = 0x1000u64;
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
    fn macos_host_anchors_gates_on_tpidrro_el0() {
        // Same input as `msr_and_mrs_both_get_gates`, but hooked for
        // `Host::MacOs`: both gates' anchor-read instruction must be
        // `MRS X16, TPIDRRO_EL0`, not `TPIDR_EL0` -- real hardware (see this
        // module's `Host` doc comment) confirmed `TPIDR_EL0` does not survive
        // a host context switch on macOS.
        let base = 0x1000;
        let tramp_base = 0x300000;
        let words = [msr_tpidr_el0(5), Insn::MrsTpidrEl0(9).encode().unwrap()];
        let mut buf = Vec::new();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let sections = vec![TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        let outcome = hook_syscalls_aarch64(&mut buf, &sections, tramp_base, 0, Host::MacOs)
            .unwrap()
            .expect("expected a trampoline (input has patch sites)");
        let tramp = outcome.trampoline;

        // MSR gate: SubSp, Stp, StrUimm, LdrLiteral, <anchor into X17>, ... --
        // anchor is the 5th instruction (index 4). It lands in X17 rather than
        // X16 because X16 already holds the offset loaded from the header slot.
        let msr_anchor_off = GATES_START_OFFSET + 4 * 4;
        assert_eq!(
            word_at(&tramp, msr_anchor_off),
            Insn::MrsTpidrroEl0(X17).encode().unwrap()
        );
        assert_ne!(
            word_at(&tramp, msr_anchor_off),
            Insn::MrsTpidrEl0(X17).encode().unwrap()
        );

        // MRS gate: SubSp, StrUimm, LdrLiteral, <anchor>, ... -- anchor is the
        // 4th instruction (index 3), read directly into the guest's own
        // destination register (X9 here, from `Insn::MrsTpidrEl0(9)` above).
        let mrs_anchor_off = GATES_START_OFFSET + MSR_GATE_SIZE_RUNTIME_SLOT + 3 * 4;
        assert_eq!(
            word_at(&tramp, mrs_anchor_off),
            Insn::MrsTpidrroEl0(9).encode().unwrap()
        );
        assert_ne!(
            word_at(&tramp, mrs_anchor_off),
            Insn::MrsTpidrEl0(9).encode().unwrap()
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
            // Store to the slot: STR X17, [X16, #GUEST_TPIDR_OFFSET].
            let store = Insn::StrUimm {
                rt: X17,
                rn: X16,
                imm_bytes: GUEST_TPIDR_OFFSET,
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
                    imm_bytes: GUEST_TPIDR_OFFSET
                }
                .encode()
                .unwrap()
            );
            assert_eq!(word_at(gate, 8) & OPCODE_TOP6_MASK, Opcode::B.bits());
        }
    }

    #[test]
    fn macos_host_gates_anchor_on_tpidrro_at_tsd_slot() {
        // Under `Host::MacOs` the same guest instructions produce gates that
        // anchor on `TPIDRRO_EL0` (Darwin's pthread TSD base) and address the
        // guest thread-pointer slot at the reserved TSD offset — never the
        // Linux anchor or block offset.
        let base = 0x1000;
        let tramp_base = 0x300000;
        let words = [msr_tpidr_el0(5), Insn::MrsTpidrEl0(9).encode().unwrap()];
        let (patched, outcome) = hook_words_host(&words, base, tramp_base, Host::MacOs);
        let tramp = outcome.expect("both sites must be gated").trampoline;
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(word_at(&patched, 4) & OPCODE_TOP6_MASK, Opcode::B.bits());

        // The offset the gates use is no longer an immediate: it is read from the
        // header slot, so neither gate may contain the baked macOS offset and the
        // slot itself must carry it as the packaging-time seed.
        let seeded = u64::from_le_bytes(
            tramp[HEADER_GUEST_TP_OFFSET_MACOS..HEADER_GUEST_TP_OFFSET_MACOS + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            seeded,
            u64::from(GUEST_TPIDR_OFFSET_MACOS),
            "the header slot must be seeded with the packaging-time default"
        );

        // MSR gate: LdrLiteral(X16), MRS X17 anchor, ADD X16, X17, X16,
        // LDR X17, [SP,#16], STR X17, [X16]. The Linux anchor never appears.
        let msr_gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + MSR_GATE_SIZE_RUNTIME_SLOT];
        let anchor = Insn::MrsTpidrroEl0(X17).encode().unwrap();
        assert!(
            (0..MSR_GATE_INSNS_RUNTIME_SLOT).any(|i| word_at(msr_gate, i * 4) == anchor),
            "MSR gate must read TPIDRRO_EL0 as the anchor"
        );
        let fold = Insn::AddReg {
            rd: X16,
            rn: X17,
            rm: X16,
        }
        .encode()
        .unwrap();
        assert!(
            (0..MSR_GATE_INSNS_RUNTIME_SLOT).any(|i| word_at(msr_gate, i * 4) == fold),
            "MSR gate must fold the loaded offset into the anchor"
        );
        let store = Insn::StrUimm {
            rt: X17,
            rn: X16,
            imm_bytes: 0,
        }
        .encode()
        .unwrap();
        assert!(
            (0..MSR_GATE_INSNS_RUNTIME_SLOT).any(|i| word_at(msr_gate, i * 4) == store),
            "MSR gate must store the guest value through the folded slot address"
        );
        let baked_store = Insn::StrUimm {
            rt: X17,
            rn: X16,
            imm_bytes: GUEST_TPIDR_OFFSET_MACOS,
        }
        .encode()
        .unwrap();
        assert!(
            (0..MSR_GATE_INSNS_RUNTIME_SLOT).all(|i| word_at(msr_gate, i * 4) != baked_store),
            "the baked offset must not survive in a runtime-slot gate"
        );
        for linux_anchor in [
            Insn::MrsTpidrEl0(X16).encode().unwrap(),
            Insn::MrsTpidrEl0(X17).encode().unwrap(),
        ] {
            assert!(
                (0..MSR_GATE_INSNS_RUNTIME_SLOT).all(|i| word_at(msr_gate, i * 4) != linux_anchor),
                "the Linux anchor read must not appear in a macOS gate"
            );
        }

        // MRS gate: SUB SP ; STR X16,[SP] ; LDR X16,<slot> ; MRS X9, TPIDRRO_EL0
        // ; LDR X9,[X9,X16] ; LDR X16,[SP] ; ADD SP ; B.
        let mrs_gate =
            &tramp[GATES_START_OFFSET + MSR_GATE_SIZE_RUNTIME_SLOT..][..MRS_GATE_SIZE_RUNTIME_SLOT];
        assert_eq!(
            word_at(mrs_gate, 0),
            Insn::SubSp(MRS_FRAME_BYTES).encode().unwrap()
        );
        assert_eq!(
            word_at(mrs_gate, 4),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: MRS_FRAME_OFF_SCRATCH
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(mrs_gate, 12),
            Insn::MrsTpidrroEl0(9).encode().unwrap()
        );
        assert_eq!(
            word_at(mrs_gate, 16),
            Insn::LdrReg {
                rt: 9,
                rn: 9,
                rm: X16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(mrs_gate, 20),
            Insn::LdrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: MRS_FRAME_OFF_SCRATCH
            }
            .encode()
            .unwrap(),
            "the borrowed scratch register must be handed back"
        );
        assert_eq!(
            word_at(mrs_gate, 24),
            Insn::AddSp(MRS_FRAME_BYTES).encode().unwrap()
        );
        assert_eq!(word_at(mrs_gate, 28) & OPCODE_TOP6_MASK, Opcode::B.bits());
    }

    #[test]
    fn macos_mrs_gate_scratch_never_collides_with_the_destination() {
        // The anchor read lands in the guest's own destination register, so the
        // borrowed scratch holding the loaded offset must never be that register
        // -- otherwise the anchor would overwrite the offset before it is used.
        for d in [5u8, 16, 17, 30] {
            let (_p, outcome) = hook_words_host(
                &[Insn::MrsTpidrEl0(d).encode().unwrap()],
                0x1000,
                0x300000,
                Host::MacOs,
            );
            let tramp = outcome.expect("site must be gated").trampoline;
            let gate = &tramp[GATES_START_OFFSET..][..MRS_GATE_SIZE_RUNTIME_SLOT];
            let scratch = if d == X16 { X17 } else { X16 };
            assert_ne!(scratch, d, "scratch must differ from the destination");
            assert_eq!(
                word_at(gate, 4),
                Insn::StrUimm {
                    rt: scratch,
                    rn: SP,
                    imm_bytes: MRS_FRAME_OFF_SCRATCH
                }
                .encode()
                .unwrap()
            );
            assert_eq!(
                word_at(gate, 16),
                Insn::LdrReg {
                    rt: d,
                    rn: d,
                    rm: scratch
                }
                .encode()
                .unwrap()
            );
        }
    }

    #[test]
    fn macos_tsd_slot_offset_is_stable_abi_and_encodable() {
        // Slot 256 is the first dynamic pthread key on macOS; the byte offset
        // is baked into statically rewritten binaries, so it must never move,
        // and it must stay encodable as a scaled LDR/STR immediate.
        assert_eq!(MACOS_GUEST_TPIDR_TSD_SLOT, 256);
        assert_eq!(GUEST_TPIDR_OFFSET_MACOS, 2048);
        assert!(
            Insn::LdrUimm {
                rt: 0,
                rn: 0,
                imm_bytes: GUEST_TPIDR_OFFSET_MACOS
            }
            .encode()
            .is_some()
        );
    }

    #[test]
    fn svc_gate_saves_only_x16_and_records_return() {
        let base = 0x1000;
        let tramp_base = 0x600000;
        let (_p, tramp) = hook_words(&[SVC_0], base, tramp_base);
        let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + SVC_GATE_SIZE];
        // SUB SP,#16 ; STR X16,[SP] ; ADRP X16,.. ; ADD X16,X16,#.. ; STR X16,[SP,#8] ; B
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
        // Self-contained tail branch to the shared handler (B, never BL).
        assert_eq!(word_at(gate, 20) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }
}
