// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for x86_64 signal context structures.

use crate::signal::x86::FpxSwBytes;

#[repr(C)]
#[derive(Clone)]
pub struct Sigcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64, /* RFLAGS */
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub reserved1: [u64; 8],
}

#[repr(C)]
#[derive(Clone)]
pub struct FpState {
    pub cwd: u16,
    pub swd: u16,
    pub twd: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st_space: [u32; 32],
    pub xmm_space: [u32; 64],
    pub reserved2: [u32; 12],
    pub sw_reserved: FpxSwBytes,
}
