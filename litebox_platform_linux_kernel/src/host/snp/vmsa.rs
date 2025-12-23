// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[repr(C, packed)]
pub struct VmsaSegmentRegister {
    pub selector: u16,
    pub attr: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, packed)]
/// Virtual Machine Saving Area for world switches
pub struct Vmsa {
    pub es: VmsaSegmentRegister,
    pub cs: VmsaSegmentRegister,
    pub ss: VmsaSegmentRegister,
    pub ds: VmsaSegmentRegister,
    pub fs: VmsaSegmentRegister,
    pub gs: VmsaSegmentRegister,
    pub gdtr: VmsaSegmentRegister,
    pub ldtr: VmsaSegmentRegister,
    pub idtr: VmsaSegmentRegister,
    pub tr: VmsaSegmentRegister,

    pub reserved1: [u8; 42],

    pub vmpl: u8,
    pub cpl: u8,

    pub reserved2: [u8; 4],

    pub efer: u64,

    pub reserved3: [u8; 104],

    pub xss: u64,
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,

    pub reserved4: [u8; 88],

    pub rsp: u64,

    pub reserved5: [u8; 24],

    pub rax: u64,

    pub reserved6: [u8; 104],

    pub gpat: u64,

    pub reserved7: [u8; 152],

    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,

    pub reserved8: [u8; 8],

    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub reserved_9: [u8; 16],
    pub sw_exit_code: u64,
    pub sw_exit_info_1: u64,
    pub sw_exit_info_2: u64,
    pub sw_scratch: u64,

    pub sev_features: u64,
    pub vintr_ctrl: u64,

    pub guest_error_code: u64,

    pub virtual_tom: u64,

    pub reserved_12: [u8; 24],

    pub xcr0: u64,
}
