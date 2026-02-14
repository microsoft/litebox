// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V constants and data-only types shared between platform and runner.

use modular_bitfield::prelude::*;
use modular_bitfield::specifiers::B62;
use num_enum::TryFromPrimitive;

// --- HV_STATUS constants ---

pub const HV_STATUS_SUCCESS: u32 = 0;
pub const HV_STATUS_INVALID_HYPERCALL_CODE: u32 = 2;
pub const HV_STATUS_INVALID_HYPERCALL_INPUT: u32 = 3;
pub const HV_STATUS_INVALID_ALIGNMENT: u32 = 4;
pub const HV_STATUS_INVALID_PARAMETER: u32 = 5;
pub const HV_STATUS_ACCESS_DENIED: u32 = 6;
pub const HV_STATUS_OPERATION_DENIED: u32 = 8;
pub const HV_STATUS_INSUFFICIENT_MEMORY: u32 = 11;
pub const HV_STATUS_INVALID_PORT_ID: u32 = 17;
pub const HV_STATUS_INVALID_CONNECTION_ID: u32 = 18;
pub const HV_STATUS_INSUFFICIENT_BUFFERS: u32 = 19;
pub const HV_STATUS_TIME_OUT: u32 = 120;
pub const HV_STATUS_VTL_ALREADY_ENABLED: u32 = 134;

// --- VSM constants ---

pub const HV_REGISTER_VSM_PARTITION_CONFIG: u32 = 0x000d_0007;
pub const HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0: u32 = 0x000d_0010;
pub const HV_REGISTER_CR_INTERCEPT_CONTROL: u32 = 0x000e_0000;
pub const HV_REGISTER_CR_INTERCEPT_CR0_MASK: u32 = 0x000e_0001;
pub const HV_REGISTER_CR_INTERCEPT_CR4_MASK: u32 = 0x000e_0002;

pub const HV_SECURE_VTL_BOOT_TOKEN: u8 = 0xdc;

/// VTL call parameters (`param[0]`: function ID, `param[1..4]`: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

pub const VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL: u32 = 0x1_ffe0;
pub const VSM_VTL_CALL_FUNC_ID_BOOT_APS: u32 = 0x1_ffe1;
pub const VSM_VTL_CALL_FUNC_ID_LOCK_REGS: u32 = 0x1_ffe2;
pub const VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT: u32 = 0x1_ffe3;
pub const VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY: u32 = 0x1_ffe4;
pub const VSM_VTL_CALL_FUNC_ID_LOAD_KDATA: u32 = 0x1_ffe5;
pub const VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE: u32 = 0x1_ffe6;
pub const VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT: u32 = 0x1_ffe7;
pub const VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE: u32 = 0x1_ffe8;
pub const VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY: u32 = 0x1_ffe9;
pub const VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE: u32 = 0x1_ffea;
pub const VSM_VTL_CALL_FUNC_ID_PATCH_TEXT: u32 = 0x1_ffeb;
pub const VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY: u32 = 0x1_ffec;

// This VSM function ID for OP-TEE messages is subject to change
pub const VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE: u32 = 0x1_fff0;

/// VSM Functions
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum VsmFunction {
    // VSM/Heki functions
    EnableAPsVtl = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
    BootAPs = VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    LockRegs = VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
    SignalEndOfBoot = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    ProtectMemory = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
    LoadKData = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    ValidateModule = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE,
    FreeModuleInit = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    UnloadModule = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
    CopySecondaryKey = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    KexecValidate = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
    PatchText = VSM_VTL_CALL_FUNC_ID_PATCH_TEXT,
    OpteeMessage = VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE,
    AllocateRingbufferMemory = VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY,
}

// --- Bitflags ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvPageProtFlags: u8 {
        const HV_PAGE_ACCESS_NONE = 0x0;
        const HV_PAGE_READABLE = 0x1;
        const HV_PAGE_WRITABLE = 0x2;
        const HV_PAGE_KERNEL_EXECUTABLE = 0x4;
        const HV_PAGE_USER_EXECUTABLE = 0x8;

        const _ = !0;

        const HV_PAGE_EXECUTABLE = Self::HV_PAGE_KERNEL_EXECUTABLE.bits() | Self::HV_PAGE_USER_EXECUTABLE.bits();
        const HV_PAGE_FULL_ACCESS = Self::HV_PAGE_READABLE.bits()
            | Self::HV_PAGE_WRITABLE.bits()
            | Self::HV_PAGE_EXECUTABLE.bits();
    }
}

// --- Bitfield structs ---

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmVpSecureVtlConfig {
    pub mbec_enabled: bool,
    pub tlb_locked: bool,
    #[skip]
    __: B62,
}

impl HvRegisterVsmVpSecureVtlConfig {
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.into_bytes())
    }
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmPartitionConfig {
    pub enable_vtl_protection: bool,
    pub default_vtl_protection_mask: B4,
    pub zero_memory_on_reset: bool,
    pub deny_lower_vtl_startup: bool,
    pub intercept_acceptance: bool,
    pub intercept_enable_vtl_protection: bool,
    pub intercept_vp_startup: bool,
    pub intercept_cpuid_unimplemented: bool,
    pub intercept_unrecoverable_exception: bool,
    pub intercept_page: bool,
    #[skip]
    __: B51,
}

impl HvRegisterVsmPartitionConfig {
    /// Get the raw u64 value for compatibility with existing code
    pub fn as_u64(&self) -> u64 {
        // Convert the 8-byte array to u64
        u64::from_le_bytes(self.into_bytes())
    }

    /// Create from a u64 value for compatibility with existing code
    pub fn from_u64(value: u64) -> Self {
        Self::from_bytes(value.to_le_bytes())
    }
}

// --- CR bitflags ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr4Flags: u32 {
        const X86_CR4_VME = 1 << 0;
        const X86_CR4_PVI = 1 << 1;
        const X86_CR4_TSD = 1 << 2;
        const X86_CR4_DE = 1 << 3;
        const X86_CR4_PSE = 1 << 4;
        const X86_CR4_PAE = 1 << 5;
        const X86_CR4_MCE = 1 << 6;
        const X86_CR4_PGE = 1 << 7;
        const X86_CR4_PCE = 1 << 8;
        const X86_CR4_OSFXSR = 1 << 9;
        const X86_CR4_OSXMMEXCPT = 1 << 10;
        const X86_CR4_UMIP = 1 << 11;
        const X86_CR4_LA57 = 1 << 12;
        const X86_CR4_VMXE = 1 << 13;
        const X86_CR4_SMXE = 1 << 14;
        const X86_CR4_FSGBASE = 1 << 16;
        const X86_CR4_PCIDE = 1 << 17;
        const X86_CR4_OSXSAVE = 1 << 18;
        const X86_CR4_SMEP = 1 << 20;
        const X86_CR4_SMAP = 1 << 21;
        const X86_CR4_PKE = 1 << 22;

        const _ = !0;

        const CR4_PIN_MASK = !(Self::X86_CR4_MCE.bits()
            | Self::X86_CR4_PGE.bits()
            | Self::X86_CR4_PCE.bits()
            | Self::X86_CR4_VMXE.bits());
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr0Flags: u32 {
        const X86_CR0_PE = 1 << 0;
        const X86_CR0_MP = 1 << 1;
        const X86_CR0_EM = 1 << 2;
        const X86_CR0_TS = 1 << 3;
        const X86_CR0_ET = 1 << 4;
        const X86_CR0_NE = 1 << 5;
        const X86_CR0_WP = 1 << 16;
        const X86_CR0_AM = 1 << 18;
        const X86_CR0_NW = 1 << 29;
        const X86_CR0_CD = 1 << 30;
        const X86_CR0_PG = 1 << 31;

        const _ = !0;

        const CR0_PIN_MASK = Self::X86_CR0_PE.bits() | Self::X86_CR0_WP.bits() | Self::X86_CR0_PG.bits();
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvCrInterceptControlFlags: u64 {
        const CR0_WRITE = 1 << 0;
        const CR4_WRITE = 1 << 1;
        const XCR0_WRITE = 1 << 2;
        const IA32MISCENABLE_READ = 1 << 3;
        const IA32MISCENABLE_WRITE = 1 << 4;
        const MSR_LSTAR_READ = 1 << 5;
        const MSR_LSTAR_WRITE = 1 << 6;
        const MSR_STAR_READ = 1 << 7;
        const MSR_STAR_WRITE = 1 << 8;
        const MSR_CSTAR_READ = 1 << 9;
        const MSR_CSTAR_WRITE = 1 << 10;
        const MSR_APIC_BASE_READ = 1 << 11;
        const MSR_APIC_BASE_WRITE = 1 << 12;
        const MSR_EFER_READ = 1 << 13;
        const MSR_EFER_WRITE = 1 << 14;
        const GDTR_WRITE = 1 << 15;
        const IDTR_WRITE = 1 << 16;
        const LDTR_WRITE = 1 << 17;
        const TR_WRITE = 1 << 18;
        const MSR_SYSENTER_CS_WRITE = 1 << 19;
        const MSR_SYSENTER_EIP_WRITE = 1 << 20;
        const MSR_SYSENTER_ESP_WRITE = 1 << 21;
        const MSR_SFMASK_WRITE = 1 << 22;
        const MSR_TSC_AUX_WRITE = 1 << 23;
        const MSR_SGX_LAUNCH_CTRL_WRITE = 1 << 24;

        const _ = !0;
    }
}
