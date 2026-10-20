// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for x86_64 signal context structures.

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// `FpxSwBytes::magic1` value marking an XSAVE-format FP state.
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// Trailer stored immediately after the XSAVE area of a signal frame.
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Size of the `FP_XSTATE_MAGIC2` trailer.
pub const FP_XSTATE_MAGIC2_SIZE: usize = size_of::<u32>();

/// `Ucontext::flags` bit: the FP state is in XSAVE format.
pub const UC_FP_XSTATE: usize = 0x1;
/// `Ucontext::flags` bit: `Sigcontext::ss` holds the interrupted SS.
pub const UC_SIGCONTEXT_SS: usize = 0x2;
/// `Ucontext::flags` bit: `rt_sigreturn` restores SS as saved.
pub const UC_STRICT_RESTORE_SS: usize = 0x4;

/// Software-reserved bytes describing the XSAVE layout of a signal frame,
/// stored in the otherwise unused tail of the legacy FP area.
#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes)]
pub struct FpxSwBytes {
    pub magic1: u32,
    pub extended_size: u32,
    pub xfeatures: u64,
    pub xstate_size: u32,
    pub padding: [u32; 7],
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
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

const _: () = assert!(size_of::<FpState>() == 512);
const _: () = assert!(core::mem::offset_of!(FpState, sw_reserved) == 464);
