// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for x86 signal context structures.

#[repr(C)]
#[derive(Clone)]
pub struct Sigcontext {
    pub gs: u32,
    pub fs: u32,
    pub es: u32,
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub trapno: u32,
    pub err: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp_at_signal: u32,
    pub ss: u32,
    pub fpstate: u32,
    pub oldmask: u32,
    pub cr2: u32,
}

// TODO
#[derive(Clone)]
pub enum FpState {}

#[repr(C)]
#[derive(Clone)]
pub struct FpxSwBytes {
    pub magic1: u32,
    pub extended_size: u32,
    pub xfeatures: u64,
    pub xstate_size: u32,
    pub padding: [u32; 7],
}
