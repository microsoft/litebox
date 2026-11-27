// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RV64 Linux gate ABI shared by the rewriter and platform runtimes.
//!
//! During guest execution physical `gp` points to a runtime-owned per-thread
//! block that starts with [`GateTls`]; physical `tp` belongs to the guest.
//! Every guest instruction that would observe or change `gp`, and every
//! `ecall`, is replaced by a `jal x0` (or `c.j`) to a gate that [`gate::emit`]
//! appends to the trampoline. A gate borrows one temporary register `r`, which
//! it saves in [`GateTls::spill`] first and reloads last. `r` is `t0` for
//! `ecall` and `auipc gp` gates; otherwise it is the first of `t0`–`t2` that is
//! not an operand of the instruction. `SPILL`, `ENTRY` and `GUEST_GP` are the
//! offsets of the [`GateTls`] fields.
//!
//! ```text
//! sd   r, SPILL(gp)
//! ...                  body: the form-specific instructions below
//! ld   r, SPILL(gp)
//! jal  x0, next        next = site + site length
//! ```
//!
//! The body depends on the replaced instruction:
//!
//! - `ecall`: `ld t0, ENTRY(gp)`; `jalr t0, 0(t0)`.
//! - `auipc gp, imm`: `auipc t0, hi`; `addi t0, t0, lo`; `sd t0, GUEST_GP(gp)`.
//! - Any other instruction with a gp operand: the instruction with `r` for gp,
//!   preceded by `ld r, GUEST_GP(gp)` if it reads gp and followed by
//!   `sd r, GUEST_GP(gp)` if it writes gp.
//!
//! `ecall` gates enter the runtime with `t0` holding the continuation, the
//! address of the reload. A runtime either returns there, with `t0` equal to
//! the continuation and the guest `t0` in [`GateTls::spill`], or resumes the
//! guest from a full register context.
//!
//! [`recovery`] maps a context interrupted inside a gate, or while an `ecall`
//! gate enters the runtime, back to an architectural guest context, without
//! allocating, using caller-supplied fallible reads.

pub mod gate;
pub mod recovery;

/// Shared layout for emitted code and the Linux userland entry assembly.
#[derive(Default)]
#[repr(C)]
pub struct GateTls {
    /// Architectural x3 presented to the guest, including in its signal context.
    pub guest_gp: u64,
    /// Original value of a temporary register while a gate is active.
    /// A runtime must finish or canonicalize a gate before reentering guest code.
    pub spill: u64,
    /// Assembly entry address, not a C function. On entry t0 is the return
    /// continuation and the guest t0 is in `spill`; all other registers,
    /// including ra, sp, tp, a0..a5 and a7, are unchanged.
    pub syscall_entry: u64,
}
