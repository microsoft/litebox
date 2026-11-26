// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RV64 Linux gate ABI shared by the rewriter and platform runtimes.
//!
//! During guest execution physical `gp` points to a runner-owned per-thread
//! block that starts with [`GateTls`]; physical `tp` belongs to the guest.
//! Every guest instruction that would observe or change `gp`, and every
//! `ecall`, is replaced by a `jal x0` (or `c.j`) to a gate that [`gate::emit`]
//! appends to the trampoline. A gate borrows one temporary register `r`, which
//! it saves in [`GateTls::spill`] first and reloads last:
//!
//! ```text
//! sd   r, SPILL(gp)
//! ...                  body: the form-specific instructions below
//! ld   r, SPILL(gp)
//! jal  x0, next        next = site + site length
//! ```
//!
//! | Form             | Body                                                     |
//! | ---------------- | -------------------------------------------------------- |
//! | `ecall`          | `ld t0, ENTRY(gp)`; `jalr t0, 0(t0)`                     |
//! | `auipc gp, imm`  | `auipc t0, hi`; `addi t0, t0, lo`; `sd t0, GUEST_GP(gp)` |
//! | other gp operand | [`ld r, GUEST_GP(gp)`]; the instruction with `r` for gp; [`sd r, GUEST_GP(gp)`] |
//!
//! The bracketed loads and stores are present iff the instruction reads or
//! writes gp, respectively. `ecall` gates enter the runtime with `t0` holding
//! the continuation, the address of the reload; the runtime returns there with
//! `t0` equal to the continuation and the guest `t0` in [`GateTls::spill`].
//!
//! [`recovery`] maps a context interrupted inside a gate back to an
//! architectural guest context, without allocating, using caller-supplied
//! fallible reads.

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
    /// continuation and its guest value is in `spill`; all other registers,
    /// including ra, sp, tp, a0..a5 and a7, are unchanged.
    pub syscall_entry: u64,
}
