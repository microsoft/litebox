// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RV64 Linux gate ABI. During guest execution physical `gp` points to this
//! prefix of a runner-owned TLS block; physical `tp` belongs to the guest.

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
