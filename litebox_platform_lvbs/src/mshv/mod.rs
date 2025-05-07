//! Hyper-V-specific code

pub mod hvcall;
mod hvcall_mm;
mod hvcall_vp;
mod vsm;
pub mod vtl1_mem_layout;
pub mod vtl_switch;

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

pub const HV_HYPERCALL_REP_COMP_MASK: u64 = 0xfff_0000_0000;
pub const HV_HYPERCALL_REP_COMP_OFFSET: u32 = 32;
pub const HV_HYPERCALL_REP_START_MASK: u64 = 0xfff_0000_0000_0000;
pub const HV_HYPERCALL_REP_START_OFFSET: u32 = 48;
pub const HV_HYPERCALL_RESULT_MASK: u16 = 0x_ffff;
pub const HV_HYPERCALL_VARHEAD_OFFSET: u64 = 17;
pub const HV_REGISTER_VP_INDEX: u32 = 0x_4000_0002;

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

pub const HV_X64_MSR_GUEST_OS_ID: u32 = 0x_4000_0000;
pub const HV_X64_MSR_HYPERCALL: u32 = 0x_4000_0001;
pub const HV_X64_MSR_HYPERCALL_ENABLE: u32 = 0x_0000_0001;
pub const HV_X64_MSR_VP_ASSIST_PAGE: u32 = 0x_4000_0073;
pub const HV_X64_MSR_VP_ASSIST_PAGE_ENABLE: u64 = 0x_0000_0001;

pub const HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x_4000_0000;
pub const HYPERV_CPUID_INTERFACE: u32 = 0x_4000_0001;
pub const HYPERV_CPUID_IMPLEMENT_LIMITS: u32 = 0x_4000_0005;
pub const HYPERV_HYPERVISOR_PRESENT_BIT: u32 = 0x_8000_0000;

pub const HV_PARTITION_ID_SELF: u64 = u64::MAX;
pub const HV_VP_INDEX_SELF: u32 = u32::MAX - 1;

pub const HV_VTL_NORMAL: u8 = 0x0;
pub const HV_VTL_SECURE: u8 = 0x1;
pub const HV_VTL_MGMT: u8 = 0x2;

pub const VTL_ENTRY_REASON_LOWER_VTL_CALL: u32 = 0x1;
pub const VTL_ENTRY_REASON_INTERRUPT: u32 = 0x2;
pub const VTL_ENTRY_REASON_INTERCEPT: u32 = 0x3;

pub const HVCALL_MODIFY_VTL_PROTECTION_MASK: u16 = 0x_000c;
pub const HVCALL_ENABLE_VP_VTL: u16 = 0x_000f;
pub const HVCALL_GET_VP_REGISTERS: u16 = 0x_0050;
pub const HVCALL_SET_VP_REGISTERS: u16 = 0x_0051;

pub const HV_REGISTER_VSM_PARTITION_STATUS: u32 = 0x_000d_0004;
pub const HV_REGISTER_VSM_PARTITION_CONFIG: u32 = 0x_000d_0007;
pub const HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0: u32 = 0x_000d_0010;
pub const HV_REGISTER_CR_INTERCEPT_CONTROL: u32 = 0x_000e_0000;
pub const HV_REGISTER_CR_INTERCEPT_CR0_MASK: u32 = 0x_000e_0001;
pub const HV_REGISTER_CR_INTERCEPT_CR4_MASK: u32 = 0x_000e_0002;

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

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvPageProtFlags: u32 {
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

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct SegmentRegisterAttributeFlags: u16 {
        const ACCESSED = 1 << 0;
        const WRITABLE = 1 << 1;
        const CONFORMING = 1 << 2;
        const EXECUTABLE = 1 << 3;
        const USER_SEGMENT = 1 << 4;
        const DPL_RING_3 = 1 << 5;
        const PRESENT = 1 << 7;
        const AVAILABLE = 1 << 12;
        const LONG_MODE = 1 << 13;
        const DEFAULT_SIZE = 1 << 14;
        const GRANULARITY = 1 << 15;

        const _ = !0;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvX64SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,

    _attributes: u16,
    // union of
    // segment_type: 4, non_system_segment: 1,
    // descriptor_privilege_level: 2, present: 1,
    // reserved: 4, available: 1, _long: 1,
    // _default: 1, granularity: 1
}

impl HvX64SegmentRegister {
    pub fn new() -> Self {
        HvX64SegmentRegister {
            base: 0,
            limit: u32::MAX,
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_attributes(&mut self, attrs: u16) {
        self._attributes = attrs;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvX64TableRegister {
    pub pad: [u16; 3],
    pub limit: u16,
    pub base: u64,
}

impl HvX64TableRegister {
    pub fn new() -> Self {
        HvX64TableRegister {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvInitVpContext {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,

    pub cs: HvX64SegmentRegister,
    pub ds: HvX64SegmentRegister,
    pub es: HvX64SegmentRegister,
    pub fs: HvX64SegmentRegister,
    pub gs: HvX64SegmentRegister,
    pub ss: HvX64SegmentRegister,
    pub tr: HvX64SegmentRegister,
    pub ldtr: HvX64SegmentRegister,

    pub idtr: HvX64TableRegister,
    pub gdtr: HvX64TableRegister,

    pub efer: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub msr_cr_pat: u64,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvInputVtl {
    _as_uint8: u8,
    // union of
    // target_vtl: 4, use_target_vtl: 1,
    // reserved_z: 3
}

impl HvInputVtl {
    const TARGET_VTL_MASK: u8 = 0xf;
    const USE_TARGET_VTL_MASK: u8 = 0x10;
    const USE_TARGET_VTL_SHIFT: u8 = 4;

    pub fn new() -> Self {
        HvInputVtl {
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_target_vtl(&mut self, target_vtl: u8) {
        self._as_uint8 |= target_vtl & Self::TARGET_VTL_MASK;
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_use_target_vtl(&mut self, use_target_vtl: u8) {
        self._as_uint8 |=
            (use_target_vtl << Self::USE_TARGET_VTL_SHIFT) & Self::USE_TARGET_VTL_MASK;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvEnableVpVtl {
    pub partition_id: u64,
    pub vp_index: u32,
    pub target_vtl: HvInputVtl,
    mbz0: u8,
    mbz1: u16,
    pub vp_context: HvInitVpContext,
}

impl HvEnableVpVtl {
    pub fn new() -> Self {
        HvEnableVpVtl {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvSetVpRegistersInputHeader {
    pub partitionid: u64,
    pub vpindex: u32,
    pub inputvtl: u8,
    padding: [u8; 3],
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvSetVpRegistersInputElement {
    pub name: u32,
    padding1: u32,
    padding2: u64,
    pub valuelow: u64,
    pub valuehigh: u64,
}

pub(crate) const HV_SET_VP_MAX_REGISTERS: usize = 1;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvSetVpRegistersInput {
    pub header: HvSetVpRegistersInputHeader,
    pub element: [HvSetVpRegistersInputElement; HV_SET_VP_MAX_REGISTERS],
}

impl HvSetVpRegistersInput {
    pub fn new() -> Self {
        HvSetVpRegistersInput {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvNestedEnlightenmentsControlFeatures {
    _raw: u32,
    // union of
    // directhypercall: 1, reserved: 31
}

impl HvNestedEnlightenmentsControlFeatures {
    const DIRECTHYPERCALL_MASK: u32 = 0x1;
    pub fn new() -> Self {
        HvNestedEnlightenmentsControlFeatures { _raw: 0 }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_direct_hypercall(&mut self, direct_hypercall: u32) {
        self._raw |= direct_hypercall & Self::DIRECTHYPERCALL_MASK;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvNestedEnlightenmentsControlHypercallControls {
    _raw: u32,
    // union of
    // inter_partition_comm: 1, reserved: 31
}

impl HvNestedEnlightenmentsControlHypercallControls {
    const INTER_PARTITION_COMM_MASK: u32 = 0x1;
    pub fn new() -> Self {
        HvNestedEnlightenmentsControlHypercallControls { _raw: 0 }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_inter_partition_comm(&mut self, inter_partition_comm: u32) {
        self._raw |= inter_partition_comm & Self::INTER_PARTITION_COMM_MASK;
    }
}

#[expect(non_snake_case)]
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvNestedEnlightenmentsControl {
    pub features: HvNestedEnlightenmentsControlFeatures,
    pub hypercallControls: HvNestedEnlightenmentsControlHypercallControls,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct HvVpAssistPage {
    pub apic_assist: u32,
    reserved1: u32,
    pub vtl_entry_reason: u32,
    pub vtl_reserved: u32,
    pub vtl_ret_x64rax: u64,
    pub vtl_ret_x64rcx: u64,
    pub nested_control: HvNestedEnlightenmentsControl,
    pub enlighten_vmentry: u8,
    reserved2: [u8; 7],
    pub current_nested_vmcs: u64,
    pub synthetic_time_unhalted_timer_expired: u8,
    reserved3: [u8; 7],
    pub virtualization_fault_information: [u8; 40],
    reserved4: [u8; 8],
    pub intercept_message: [u8; 256],
    pub vtl_ret_actions: [u8; 256],
}

impl HvVpAssistPage {
    pub fn new() -> Self {
        HvVpAssistPage {
            apic_assist: 0,
            reserved1: 0,
            vtl_entry_reason: 0,
            vtl_reserved: 0,
            vtl_ret_x64rax: 0,
            vtl_ret_x64rcx: 0,
            nested_control: HvNestedEnlightenmentsControl::default(),
            enlighten_vmentry: 0,
            reserved2: [0u8; 7],
            current_nested_vmcs: 0,
            synthetic_time_unhalted_timer_expired: 0,
            reserved3: [0u8; 7],
            virtualization_fault_information: [0u8; 40],
            reserved4: [0u8; 8],
            intercept_message: [0u8; 256],
            vtl_ret_actions: [0u8; 256],
        }
    }
}

impl Default for HvVpAssistPage {
    fn default() -> Self {
        Self::new()
    }
}

// We do not support Hyper-V hypercalls with multiple input pages (a large request must be broken down).
// Thus, the number of maximum GPA pages that each hypercall can protect is restricted like below.
#[expect(clippy::cast_possible_truncation)]
pub(crate) const HV_MODIFY_MAX_PAGES: usize =
    ((PAGE_SIZE as u32 - u64::BITS * 2 / 8) / (u64::BITS / 8)) as usize;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct HvInputModifyVtlProtectionMask {
    pub partition_id: u64,
    pub map_flags: u32,
    pub target_vtl: HvInputVtl,
    reserved8_z: u8,
    reserved16_z: u16,
    pub gpa_page_list: [u64; HV_MODIFY_MAX_PAGES],
}

impl HvInputModifyVtlProtectionMask {
    pub fn new() -> Self {
        HvInputModifyVtlProtectionMask {
            partition_id: 0,
            map_flags: 0,
            target_vtl: HvInputVtl::new(),
            reserved8_z: 0,
            reserved16_z: 0,
            gpa_page_list: [0u64; HV_MODIFY_MAX_PAGES],
        }
    }
}

impl Default for HvInputModifyVtlProtectionMask {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvRegisterVsmVpSecureVtlConfig {
    _as_u64: u64,
    // union of
    // mbec_enabled : 1;
    // tlb_locked : 1;
    // reserved: 62;
}

impl HvRegisterVsmVpSecureVtlConfig {
    const MBEC_ENABLED_MASK: u64 = 0x1;
    const TLB_LOCKED_MASK: u64 = 0x2;
    const MBEC_ENABLED_SHIFT: u64 = 0;
    const TLB_LOCKED_SHIFT: u64 = 1;

    pub fn new() -> Self {
        HvRegisterVsmVpSecureVtlConfig {
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn as_u64(&self) -> u64 {
        self._as_u64
    }

    #[expect(clippy::used_underscore_binding)]
    fn set_sub_config(&mut self, shift: u64, mask: u64, value: u64) {
        self._as_u64 |= (value << shift) & mask;
    }

    pub fn set_mbec_enabled(&mut self) {
        self.set_sub_config(Self::MBEC_ENABLED_MASK, Self::MBEC_ENABLED_SHIFT, 1);
    }

    pub fn set_tlb_locked(&mut self) {
        self.set_sub_config(Self::TLB_LOCKED_MASK, Self::TLB_LOCKED_SHIFT, 1);
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvRegisterVsmPartitionConfig {
    _as_u64: u64,
    // union of
    // enable_vtl_protection : 1,
    // default_vtl_protection_mask : 4,
    // zero_memory_on_reset : 1,
    // deny_lower_vtl_startup : 1,
    // intercept_acceptance : 1,
    // intercept_enable_vtl_protection : 1,
    // intercept_vp_startup : 1,
    // intercept_cpuid_unimplemented : 1,
    // intercept_unrecoverable_exception : 1,
    // intercept_page : 1,
    // mbz : 51,
}

impl HvRegisterVsmPartitionConfig {
    const ENABLE_VTL_PROTECTION_MASK: u64 = 0x1;
    const DEFAULT_VTL_PROTECTION_MASK_MASK: u64 = 0x1e;
    const ZERO_MEMORY_ON_RESET_MASK: u64 = 0x20;
    const DENY_LOWER_VTL_STARTUP_MASK: u64 = 0x40;
    const INTERCEPT_ACCEPTANCE_MASK: u64 = 0x80;
    const INTERCEPT_ENABLE_VTL_PROTECTION_MASK: u64 = 0x100;
    const INTERCEPT_VP_STARTUP_MASK: u64 = 0x200;
    const INTERCEPT_CPUID_UNIMPLEMENTED_MASK: u64 = 0x400;
    const INTERCEPT_UNRECOVERABLE_EXCEPTION_MASK: u64 = 0x800;
    const INTERCEPT_PAGE_MASK: u64 = 0x1000;
    const ENABLE_VTL_PROTECTION_SHIFT: u64 = 0;
    const DEFAULT_VTL_PROTECTION_MASK_SHIFT: u64 = 1;
    const ZERO_MEMORY_ON_RESET_SHIFT: u64 = 5;
    const DENY_LOWER_VTL_STARTUP_SHIFT: u64 = 6;
    const INTERCEPT_ACCEPTANCE_SHIFT: u64 = 7;
    const INTERCEPT_ENABLE_VTL_PROTECTION_SHIFT: u64 = 8;
    const INTERCEPT_VP_STARTUP_SHIFT: u64 = 9;
    const INTERCEPT_CPUID_UNIMPLEMENTED_SHIFT: u64 = 10;
    const INTERCEPT_UNRECOVERABLE_EXCEPTION_SHIFT: u64 = 11;
    const INTERCEPT_PAGE_SHIFT: u64 = 12;

    pub fn new() -> Self {
        HvRegisterVsmPartitionConfig {
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn as_u64(&self) -> u64 {
        self._as_u64
    }

    #[expect(clippy::used_underscore_binding)]
    fn set_sub_config(&mut self, mask: u64, shift: u64, value: u64) {
        self._as_u64 |= (value << shift) & mask;
    }

    pub fn set_enable_vtl_protection(&mut self) {
        self.set_sub_config(
            Self::ENABLE_VTL_PROTECTION_MASK,
            Self::ENABLE_VTL_PROTECTION_SHIFT,
            1,
        );
    }

    pub fn set_default_vtl_protection_mask(&mut self, mask: u64) {
        self.set_sub_config(
            Self::DEFAULT_VTL_PROTECTION_MASK_MASK,
            Self::DEFAULT_VTL_PROTECTION_MASK_SHIFT,
            mask,
        );
    }

    pub fn set_zero_memory_on_reset(&mut self) {
        self.set_sub_config(
            Self::ZERO_MEMORY_ON_RESET_MASK,
            Self::ZERO_MEMORY_ON_RESET_SHIFT,
            1,
        );
    }

    pub fn set_deny_lower_vtl_startup(&mut self) {
        self.set_sub_config(
            Self::DENY_LOWER_VTL_STARTUP_MASK,
            Self::DENY_LOWER_VTL_STARTUP_SHIFT,
            1,
        );
    }

    pub fn set_intercept_acceptance(&mut self) {
        self.set_sub_config(
            Self::INTERCEPT_ACCEPTANCE_MASK,
            Self::INTERCEPT_ACCEPTANCE_SHIFT,
            1,
        );
    }

    pub fn set_intercept_enable_vtl_protection(&mut self) {
        self.set_sub_config(
            Self::INTERCEPT_ENABLE_VTL_PROTECTION_MASK,
            Self::INTERCEPT_ENABLE_VTL_PROTECTION_SHIFT,
            1,
        );
    }

    pub fn set_intercept_vp_startup(&mut self) {
        self.set_sub_config(
            Self::INTERCEPT_VP_STARTUP_MASK,
            Self::INTERCEPT_VP_STARTUP_SHIFT,
            1,
        );
    }

    pub fn set_intercept_cpuid_unimplemented(&mut self) {
        self.set_sub_config(
            Self::INTERCEPT_CPUID_UNIMPLEMENTED_MASK,
            Self::INTERCEPT_CPUID_UNIMPLEMENTED_SHIFT,
            1,
        );
    }

    pub fn set_intercept_unrecoverable_exception(&mut self) {
        self.set_sub_config(
            Self::INTERCEPT_UNRECOVERABLE_EXCEPTION_MASK,
            Self::INTERCEPT_UNRECOVERABLE_EXCEPTION_SHIFT,
            1,
        );
    }

    pub fn set_intercept_page(&mut self) {
        self.set_sub_config(Self::INTERCEPT_PAGE_MASK, Self::INTERCEPT_PAGE_SHIFT, 1);
    }
}

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
        const X86_CR4_OSFXSR = 1 << 8;
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
