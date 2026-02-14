// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V-specific code

pub mod hvcall;
pub mod hvcall_mm;
pub mod hvcall_vp;
pub mod ringbuffer;
pub mod vsm_intercept;
pub mod vtl1_mem_layout;
pub mod vtl_switch;

use crate::host::linux::CpuMask;
use crate::mshv::vtl1_mem_layout::PAGE_SIZE;
use alloc::boxed::Box;
use modular_bitfield::prelude::*;
use modular_bitfield::specifiers::{B16, B3, B31, B32, B4, B45, B7, B8};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use spin::Once;

pub static CPU_ONLINE_MASK: Once<Box<CpuMask>> = Once::new();

pub const HV_HYPERCALL_REP_COMP_MASK: u64 = 0xfff_0000_0000;
pub const HV_HYPERCALL_REP_COMP_OFFSET: u32 = 32;
pub const HV_HYPERCALL_REP_START_MASK: u64 = 0xfff_0000_0000_0000;
pub const HV_HYPERCALL_REP_START_OFFSET: u32 = 48;
pub const HV_HYPERCALL_RESULT_MASK: u16 = 0x_ffff;
pub const HV_HYPERCALL_VARHEAD_OFFSET: u64 = 17;
pub const HV_REGISTER_VP_INDEX: u32 = 0x_4000_0002;

pub const HV_X64_MSR_GUEST_OS_ID: u32 = 0x_4000_0000;
pub const HV_X64_MSR_HYPERCALL: u32 = 0x_4000_0001;
pub const HV_X64_MSR_HYPERCALL_ENABLE: u32 = 0x_0000_0001;
pub const HV_X64_MSR_VP_ASSIST_PAGE: u32 = 0x_4000_0073;
pub const HV_X64_MSR_VP_ASSIST_PAGE_ENABLE: u64 = 0x_0000_0001;
pub const HV_X64_MSR_SCONTROL: u32 = 0x_4000_0080;
pub const HV_X64_MSR_SCONTROL_ENABLE: u32 = 0x_0000_0001;
pub const HV_X64_MSR_SIEFP: u32 = 0x_4000_0082;
pub const HV_X64_MSR_SIEFP_ENABLE: u32 = 0x_0000_0001;
pub const HV_X64_MSR_SIMP: u32 = 0x_4000_0083;
pub const HV_X64_MSR_SIMP_ENABLE: u32 = 0x_0000_0001;
pub const HV_X64_MSR_SINT0: u32 = 0x_4000_0090;

pub const HYPERVISOR_CALLBACK_VECTOR: u8 = 0xf3;

pub const HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x_4000_0000;
pub const HYPERV_CPUID_INTERFACE: u32 = 0x_4000_0001;
pub const HYPERV_CPUID_IMPLEMENT_LIMITS: u32 = 0x_4000_0005;
pub const HYPERV_HYPERVISOR_PRESENT_BIT: u32 = 0x_8000_0000;

pub const HV_PARTITION_ID_SELF: u64 = u64::MAX;
pub const HV_VP_INDEX_SELF: u32 = u32::MAX - 1;

pub const HV_VTL_NORMAL: u8 = 0x0;
pub const HV_VTL_SECURE: u8 = 0x1;
pub const HV_VTL_MGMT: u8 = 0x2;

pub const VTL_ENTRY_REASON_RESERVED: u32 = 0x0;
pub const VTL_ENTRY_REASON_LOWER_VTL_CALL: u32 = 0x1;
pub const VTL_ENTRY_REASON_INTERRUPT: u32 = 0x2;

pub const HVCALL_MODIFY_VTL_PROTECTION_MASK: u16 = 0x_000c;
pub const HVCALL_ENABLE_VP_VTL: u16 = 0x_000f;
pub const HVCALL_GET_VP_REGISTERS: u16 = 0x_0050;
pub const HVCALL_SET_VP_REGISTERS: u16 = 0x_0051;

pub const HV_X64_REGISTER_RIP: u32 = 0x0002_0010;
pub const HV_X64_REGISTER_LDTR: u32 = 0x0006_0006;
pub const HV_X64_REGISTER_TR: u32 = 0x0006_0007;
pub const HV_X64_REGISTER_IDTR: u32 = 0x0007_0000;
pub const HV_X64_REGISTER_GDTR: u32 = 0x0007_0001;
pub const HV_X64_REGISTER_VSM_VP_STATUS: u32 = 0x000d_0003;
pub const HV_REGISTER_VSM_CODEPAGE_OFFSETS: u32 = 0x000d_0002;
pub const HV_REGISTER_VSM_PARTITION_STATUS: u32 = 0x000d_0004;
pub const HV_REGISTER_PENDING_EVENT0: u32 = 0x0001_0004;

pub const MSR_EFER: u32 = 0xc000_0080;
pub const MSR_STAR: u32 = 0xc000_0081;
pub const MSR_LSTAR: u32 = 0xc000_0082;
pub const MSR_CSTAR: u32 = 0xc000_0083;
pub const MSR_SYSCALL_MASK: u32 = 0x0000_0084;
pub const MSR_IA32_APICBASE: u32 = 0x1b;
pub const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;

pub const DEFAULT_REG_PIN_MASK: u64 = u64::MAX;

bitflags::bitflags! {
    #[derive(Debug, PartialEq, Clone, Copy, Default)]
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
    pub attributes: SegmentRegisterAttributeFlags,
}

impl HvX64SegmentRegister {
    pub fn new() -> Self {
        HvX64SegmentRegister {
            limit: u32::MAX,
            ..Default::default()
        }
    }

    pub fn set_attributes(&mut self, attrs: SegmentRegisterAttributeFlags) {
        self.attributes = attrs;
    }

    pub fn get_attributes(&self) -> SegmentRegisterAttributeFlags {
        self.attributes
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

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvInputVtl {
    pub target_vtl: B4,
    pub use_target_vtl: bool,
    #[skip]
    __: B3,
}

impl HvInputVtl {
    /// `target_vtl` specifies the VTL (0-15) that a Hyper-V hypercall works at.
    pub fn new_for_vtl(target_vtl: u8) -> Self {
        Self::new()
            .with_target_vtl(target_vtl)
            .with_use_target_vtl(true)
    }

    /// use the current VTL
    pub fn current() -> Self {
        Self::new().with_use_target_vtl(false)
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
    pub target_vtl: HvInputVtl,
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
pub struct HvGetVpRegistersInputHeader {
    pub partitionid: u64,
    pub vpindex: u32,
    pub target_vtl: HvInputVtl,
    padding: [u8; 3],
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvGetVpRegistersInputElement {
    pub name0: u32,
    pub name1: u32,
}

pub(crate) const HV_GET_VP_MAX_REGISTERS: usize = 1;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvGetVpRegistersInput {
    pub header: HvGetVpRegistersInputHeader,
    pub element: [HvGetVpRegistersInputElement; HV_GET_VP_MAX_REGISTERS],
}

impl HvGetVpRegistersInput {
    pub fn new() -> Self {
        HvGetVpRegistersInput {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvGetVpRegistersOutput {
    value: [u64; 2],
}

impl HvGetVpRegistersOutput {
    pub fn new() -> Self {
        HvGetVpRegistersOutput {
            ..Default::default()
        }
    }

    pub fn as64(&self) -> (u64, u64) {
        (self.value[0], self.value[1])
    }

    pub fn as32(&self) -> (u32, u32, u32, u32) {
        (
            (self.value[0] & 0xffff_ffff) as u32,
            ((self.value[0] >> 32) & 0xffff_ffff) as u32,
            (self.value[1] & 0xffff_ffff) as u32,
            ((self.value[1] >> 32) & 0xffff_ffff) as u32,
        )
    }
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvNestedEnlightenmentsControlFeatures {
    pub direct_hypercall: bool,
    #[skip]
    __: B31,
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvNestedEnlightenmentsControlHypercallControls {
    pub inter_partition_comm: bool,
    #[skip]
    __: B31,
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
const HV_MODIFY_MAX_PAGES: usize =
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
    pub const MAX_PAGES_PER_REQUEST: usize = HV_MODIFY_MAX_PAGES;

    pub fn new() -> Self {
        HvInputModifyVtlProtectionMask {
            partition_id: 0,
            map_flags: 0,
            target_vtl: HvInputVtl::current(),
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

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmCodePageOffsets {
    pub vtl_call_offset: B12,
    pub vtl_return_offset: B12,
    #[skip]
    __: B40,
}

impl HvRegisterVsmCodePageOffsets {
    pub fn from_u64(value: u64) -> Self {
        Self::from_bytes(value.to_le_bytes())
    }
}

#[derive(Default, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum HvMessageType {
    #[default]
    None = 0x0,
    UnmappedGpa = 0x8000_0000,
    GpaIntercept = 0x8000_0001,
    TimerExpired = 0x8000_0010,
    InvalidVpRegisterValue = 0x8000_0020,
    UnrecoverableException = 0x8000_0021,
    UnsupportedFeature = 0x8000_0022,
    EventLogBufferComplete = 0x8000_0040,
    IoPortIntercept = 0x8001_0000,
    MsrIntercept = 0x8001_0001,
    CpuidIntercept = 0x8001_0002,
    ExceptionIntercept = 0x8001_0003,
    ApicEoi = 0x8001_0004,
    LegacyFpError = 0x8001_0005,
    RegisterIntercept = 0x8001_0006,
    Unknown = 0xffff_ffff,
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HvMessageHeader {
    pub message_type: u32,
    pub payload_size: u8,
    pub message_flags: u8,
    pub reserved: [u8; 2],
    pub sender: u64,
}

impl HvMessageHeader {
    pub fn new() -> Self {
        HvMessageHeader {
            ..Default::default()
        }
    }
}

const HV_MESSAGE_PAYLOAD_QWORD_COUNT: usize = 30;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvMessage {
    pub header: HvMessageHeader,
    pub payload: [u64; HV_MESSAGE_PAYLOAD_QWORD_COUNT],
}

impl HvMessage {
    pub fn new() -> Self {
        HvMessage {
            header: HvMessageHeader::new(),
            payload: [0u64; HV_MESSAGE_PAYLOAD_QWORD_COUNT],
        }
    }
}

const HV_SYNIC_SINT_COUNT: usize = 16;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvMessagePage {
    pub sint_message: [HvMessage; HV_SYNIC_SINT_COUNT],
}

impl HvMessagePage {
    pub fn new() -> Self {
        HvMessagePage {
            sint_message: [HvMessage::new(); HV_SYNIC_SINT_COUNT],
        }
    }
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvSynicSint {
    pub vector: B8,
    #[skip]
    __reserved1: B8,
    pub masked: bool,
    pub auto_eoi: bool,
    pub polling: bool,
    #[skip]
    __reserved2: B45,
}

impl HvSynicSint {
    pub fn as_uint64(&self) -> u64 {
        u64::from_le_bytes(self.into_bytes())
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvInterceptMessageHeader {
    pub vp_index: u32,
    pub instruction_length: u8,
    pub intercept_access_type: u8,
    pub execution_state: u16,
    pub cs_segment: HvX64SegmentRegister,
    pub rip: u64,
    pub rflags: u64,
}

bitflags::bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq)]
    pub struct HvMemoryAccessInfo: u8 {
        const GVA_VALID = 1 << 0;
        const GVA_GPA_VALID = 1 << 1;
        const HYPERCALL_OP_PENDING = 1 << 2;
        const TLB_BLOCKED = 1 << 3;
        const SUPERVISOR_SHADOW_STACK = 1 << 4;
        const VERIFY_PAGE_WR = 1 << 5;

        const _ = !0;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvMemInterceptMessage {
    pub hdr: HvInterceptMessageHeader,
    pub cache_type: u32,
    pub instruction_byte_count: u8,
    pub info: HvMemoryAccessInfo,
    pub tpr_priority: u8,
    reserved: u8,
    pub gva: u64,
    pub gpa: u64,
    pub instr_bytes: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub union HvRegisterAccessInfo {
    pub reg_value_low: u64,
    pub reg_value_high: u64,
    pub reg_name: u32,
    pub src_addr: u64,
    pub dest_addr: u64,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct HvInterceptMessage {
    pub hdr: HvInterceptMessageHeader,
    pub is_memory_op: u8,
    reserved_0: u8,
    reserved_1: u16,
    pub reg_name: u32,
    pub info: HvRegisterAccessInfo,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HvMsrInterceptMessage {
    pub hdr: HvInterceptMessageHeader,
    pub msr: u32,
    reserved_0: u32,
    pub rdx: u64,
    pub rax: u64,
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvPendingExceptionEvent {
    pub event_pending: bool,
    pub event_type: B3,
    #[skip]
    __reserved_0: B4,
    pub deliver_error_code: bool,
    #[skip]
    __reserved_1: B7,
    pub vector: B16,
    pub error_code: B32,
}

impl HvPendingExceptionEvent {
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_lvbs::mshv::{HvRegisterVsmPartitionConfig, HvRegisterVsmVpSecureVtlConfig};

    #[test]
    fn test_hv_input_vtl_bitfield() {
        // Test the new bitfield-based HvInputVtl implementation

        // Test new_for_vtl constructor
        let vtl = HvInputVtl::new_for_vtl(5);
        assert_eq!(vtl.target_vtl(), 5);
        assert!(vtl.use_target_vtl());

        // Test current constructor
        let current_vtl = HvInputVtl::current();
        assert!(!current_vtl.use_target_vtl());

        // Test individual field manipulation
        let mut vtl = HvInputVtl::new();
        vtl.set_target_vtl(10_u8);
        vtl.set_use_target_vtl(true);
        assert_eq!(vtl.target_vtl(), 10);
        assert!(vtl.use_target_vtl());

        // Test size - should be 1 byte
        assert_eq!(core::mem::size_of::<HvInputVtl>(), 1);

        // Test that VTL values are properly bounded to 4 bits (0-15)
        let vtl = HvInputVtl::new_for_vtl(15);
        assert_eq!(vtl.target_vtl(), 15);

        // Test that Default trait works
        let default_vtl = HvInputVtl::default();
        assert_eq!(default_vtl.target_vtl(), 0);
        assert!(!default_vtl.use_target_vtl());
    }

    #[test]
    fn test_hv_register_vsm_partition_config_bitfield() {
        // Test the new bitfield-based HvRegisterVsmPartitionConfig implementation

        let mut config = HvRegisterVsmPartitionConfig::new();

        // Test individual boolean flags
        config.set_enable_vtl_protection(true);
        assert!(config.enable_vtl_protection());

        config.set_zero_memory_on_reset(true);
        assert!(config.zero_memory_on_reset());

        config.set_intercept_page(true);
        assert!(config.intercept_page());

        // Test the 4-bit protection mask field
        config.set_default_vtl_protection_mask(0b1010_u8);
        assert_eq!(u64::from(config.default_vtl_protection_mask()), 0b1010);

        // Test size - should be 8 bytes (64 bits)
        assert_eq!(core::mem::size_of::<HvRegisterVsmPartitionConfig>(), 8);

        // Test as_u64 and from_u64 round-trip
        let original = config.as_u64();
        let restored = HvRegisterVsmPartitionConfig::from_u64(original);

        assert!(restored.enable_vtl_protection());
        assert!(restored.zero_memory_on_reset());
        assert!(restored.intercept_page());
        assert_eq!(u64::from(restored.default_vtl_protection_mask()), 0b1010);

        // Test that Default trait works
        let default_config = HvRegisterVsmPartitionConfig::default();
        assert!(!default_config.enable_vtl_protection());
        assert_eq!(default_config.as_u64(), 0);

        // Test chaining builder-style methods (generated by bitfield macro)
        let chained_config = HvRegisterVsmPartitionConfig::new()
            .with_enable_vtl_protection(true)
            .with_intercept_acceptance(true)
            .with_intercept_vp_startup(true);

        assert!(chained_config.enable_vtl_protection());
        assert!(chained_config.intercept_acceptance());
        assert!(chained_config.intercept_vp_startup());
        assert!(!chained_config.zero_memory_on_reset());
    }

    #[test]
    fn test_hv_nested_enlightenments_control_features_bitfield() {
        // Test the new bitfield-based HvNestedEnlightenmentsControlFeatures implementation

        let mut features = HvNestedEnlightenmentsControlFeatures::new();

        // Test setting direct hypercall flag
        features.set_direct_hypercall(true);
        assert!(features.direct_hypercall());

        // Test direct method
        let mut features2 = HvNestedEnlightenmentsControlFeatures::new();
        features2.set_direct_hypercall(true);
        assert!(features2.direct_hypercall());

        features2.set_direct_hypercall(false);
        assert!(!features2.direct_hypercall());

        // Test size - should be 4 bytes (32 bits)
        assert_eq!(
            core::mem::size_of::<HvNestedEnlightenmentsControlFeatures>(),
            4
        );

        // Test that Default trait works
        let default_features = HvNestedEnlightenmentsControlFeatures::default();
        assert!(!default_features.direct_hypercall());
    }

    #[test]
    fn test_hv_nested_enlightenments_control_hypercall_controls_bitfield() {
        // Test the new bitfield-based HvNestedEnlightenmentsControlHypercallControls implementation

        let mut controls = HvNestedEnlightenmentsControlHypercallControls::new();

        // Test setting inter partition comm flag
        controls.set_inter_partition_comm(true);
        assert!(controls.inter_partition_comm());

        // Test direct method
        let mut controls2 = HvNestedEnlightenmentsControlHypercallControls::new();
        controls2.set_inter_partition_comm(true);
        assert!(controls2.inter_partition_comm());

        controls2.set_inter_partition_comm(false);
        assert!(!controls2.inter_partition_comm());

        // Test size - should be 4 bytes (32 bits)
        assert_eq!(
            core::mem::size_of::<HvNestedEnlightenmentsControlHypercallControls>(),
            4
        );

        // Test that Default trait works
        let default_controls = HvNestedEnlightenmentsControlHypercallControls::default();
        assert!(!default_controls.inter_partition_comm());
    }

    #[test]
    fn test_hv_register_vsm_vp_secure_vtl_config_bitfield() {
        // Test the new bitfield-based HvRegisterVsmVpSecureVtlConfig implementation

        let mut config = HvRegisterVsmVpSecureVtlConfig::new();

        // Test individual boolean flags
        config.set_mbec_enabled(true);
        assert!(config.mbec_enabled());

        config.set_tlb_locked(true);
        assert!(config.tlb_locked());

        // Test direct methods
        let mut config2 = HvRegisterVsmVpSecureVtlConfig::new();
        config2.set_mbec_enabled(true);
        assert!(config2.mbec_enabled());

        config2.set_tlb_locked(true);
        assert!(config2.tlb_locked());

        // Test size - should be 8 bytes (64 bits)
        assert_eq!(core::mem::size_of::<HvRegisterVsmVpSecureVtlConfig>(), 8);

        // Test as_u64 method
        let config_u64 = config.as_u64();
        assert_ne!(config_u64, 0); // Should have some bits set

        // Test that Default trait works
        let default_config = HvRegisterVsmVpSecureVtlConfig::default();
        assert!(!default_config.mbec_enabled());
        assert!(!default_config.tlb_locked());
        assert_eq!(default_config.as_u64(), 0);
    }

    #[test]
    fn test_hv_synic_sint_bitfield() {
        // Test the new bitfield-based HvSynicSint implementation

        let mut sint = HvSynicSint::new();

        // Test vector field (8 bits)
        sint.set_vector(0xf3_u8);
        assert_eq!(sint.vector(), 0xf3);

        // Test boolean flags
        sint.set_masked(true);
        assert!(sint.masked());

        sint.set_auto_eoi(true);
        assert!(sint.auto_eoi());

        sint.set_polling(true);
        assert!(sint.polling());

        // Test direct methods
        let mut sint2 = HvSynicSint::new();
        sint2.set_vector(0xf3_u8);
        assert_eq!(sint2.vector(), 0xf3);

        sint2.set_masked(true);
        assert!(sint2.masked());

        sint2.set_auto_eoi(true);
        assert!(sint2.auto_eoi());

        sint2.set_polling(true);
        assert!(sint2.polling());

        // Test size - should be 8 bytes (64 bits)
        assert_eq!(core::mem::size_of::<HvSynicSint>(), 8);

        // Test as_uint64 method
        let sint_u64 = sint.as_uint64();
        assert_ne!(sint_u64, 0); // Should have some bits set

        // Test that Default trait works
        let default_sint = HvSynicSint::default();
        assert_eq!(default_sint.vector(), 0);
        assert!(!default_sint.masked());
        assert!(!default_sint.auto_eoi());
        assert!(!default_sint.polling());
    }

    #[test]
    fn test_hv_pending_exception_event_bitfield() {
        // Test the new bitfield-based HvPendingExceptionEvent implementation

        let mut exception = HvPendingExceptionEvent::new();

        // Test boolean flags
        exception.set_event_pending(true);
        assert!(exception.event_pending());

        exception.set_deliver_error_code(true);
        assert!(exception.deliver_error_code());

        // Test multi-bit fields
        exception.set_event_type(0b101_u8); // 3 bits
        assert_eq!(exception.event_type(), 0b101);

        exception.set_vector(0x1234_u16); // 16 bits
        assert_eq!(exception.vector(), 0x1234);

        exception.set_error_code(0x87654321_u32); // 32 bits
        assert_eq!(exception.error_code(), 0x87654321);

        // Test direct methods
        let mut exception2 = HvPendingExceptionEvent::new();
        exception2.set_event_pending(true);
        assert!(exception2.event_pending());

        exception2.set_deliver_error_code(true);
        assert!(exception2.deliver_error_code());

        exception2.set_event_type(7_u8);
        assert_eq!(exception2.event_type(), 7);

        exception2.set_vector(0xabcd_u16);
        assert_eq!(exception2.vector(), 0xabcd);

        exception2.set_error_code(0x12345678_u32);
        assert_eq!(exception2.error_code(), 0x12345678);

        // Test size - should be 8 bytes (64 bits)
        assert_eq!(core::mem::size_of::<HvPendingExceptionEvent>(), 8);

        // Test as_u64 method
        let exception_u64 = exception.as_u64();
        assert_ne!(exception_u64, 0); // Should have some bits set

        // Test that Default trait works
        let default_exception = HvPendingExceptionEvent::default();
        assert!(!default_exception.event_pending());
        assert!(!default_exception.deliver_error_code());
        assert_eq!(default_exception.event_type(), 0);
        assert_eq!(default_exception.vector(), 0);
        assert_eq!(default_exception.error_code(), 0);
        assert_eq!(default_exception.as_u64(), 0);
    }
}
