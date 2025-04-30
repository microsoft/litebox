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

pub const HV_PARTITION_ID_SELF: u64 = 0xffff_ffff_ffff_ffffu64;
pub const HV_VP_INDEX_SELF: u32 = 0xffff_fffeu32;

pub const VTL_ENTRY_REASON_LOWER_VTL_CALL: u32 = 0x1;
pub const VTL_ENTRY_REASON_INTERCEPT: u32 = 0x2;
pub const VTL_ENTRY_REASON_INTERRUPT: u32 = 0x3;

pub const HVCALL_MODIFY_VTL_PROTECTION_MASK: u16 = 0x_000c;
pub const HVCALL_ENABLE_VP_VTL: u16 = 0x_000f;
pub const HVCALL_GET_VP_REGISTERS: u16 = 0x_0050;
pub const HVCALL_SET_VP_REGISTERS: u16 = 0x_0051;

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

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_x64_segment_register {
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

impl hv_x64_segment_register {
    pub fn new() -> Self {
        hv_x64_segment_register {
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
pub struct hv_x64_table_register {
    pub pad: [u16; 3],
    pub limit: u16,
    pub base: u64,
}

impl hv_x64_table_register {
    pub fn new() -> Self {
        hv_x64_table_register {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_init_vp_context {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,

    pub cs: hv_x64_segment_register,
    pub ds: hv_x64_segment_register,
    pub es: hv_x64_segment_register,
    pub fs: hv_x64_segment_register,
    pub gs: hv_x64_segment_register,
    pub ss: hv_x64_segment_register,
    pub tr: hv_x64_segment_register,
    pub ldtr: hv_x64_segment_register,

    pub idtr: hv_x64_table_register,
    pub gdtr: hv_x64_table_register,

    pub efer: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub msr_cr_pat: u64,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_input_vtl {
    _u8: u8,
    // union of
    // target_vtl: 4, use_target_vtl: 1,
    // reserved_z: 3
}

impl hv_input_vtl {
    pub fn new() -> Self {
        hv_input_vtl {
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn set_target_vtl(&mut self, target_vtl: u8) {
        self._u8 |= target_vtl & 0xf;
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_enable_vp_vtl {
    pub partition_id: u64,
    pub vp_index: u32,
    pub target_vtl: hv_input_vtl,
    mbz0: u8,
    mbz1: u16,
    pub vp_context: hv_init_vp_context,
}

impl hv_enable_vp_vtl {
    pub fn new() -> Self {
        hv_enable_vp_vtl {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_vp_registers_input_header {
    pub partitionid: u64,
    pub vpindex: u32,
    pub inputvtl: u8,
    padding: [u8; 3],
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_get_vp_registers_input_element {
    pub name0: u32,
    pub name1: u32,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_get_vp_registers_input {
    pub header: hv_vp_registers_input_header,
    pub element: hv_get_vp_registers_input_element,
    // in fact, it is an array of undefined length, element[], but we only use one element
}

impl hv_get_vp_registers_input {
    pub fn new() -> Self {
        hv_get_vp_registers_input {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_get_vp_registers_output_as32 {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_get_vp_registers_output_as64 {
    pub low: u64,
    pub high: u64,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_get_vp_registers_output {
    _data: [u32; 4],
    // union of
    // hv_get_vp_registers_output_as32 and hv_get_vp_registers_output_as64,
}

impl hv_get_vp_registers_output {
    pub fn new() -> Self {
        hv_get_vp_registers_output {
            ..Default::default()
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn as_u32(&self) -> hv_get_vp_registers_output_as32 {
        hv_get_vp_registers_output_as32 {
            a: self._data[0],
            b: self._data[1],
            c: self._data[2],
            d: self._data[3],
        }
    }

    #[expect(clippy::used_underscore_binding)]
    pub fn as_u64(&self) -> hv_get_vp_registers_output_as64 {
        hv_get_vp_registers_output_as64 {
            low: u64::from(self._data[0]) | (u64::from(self._data[1]) << 32),
            high: u64::from(self._data[2]) | (u64::from(self._data[3]) << 32),
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_set_vp_registers_input_element {
    pub name: u32,
    padding1: u32,
    padding2: u64,
    pub valuelow: u64,
    pub valuehigh: u64,
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_set_vp_registers_input {
    pub header: hv_vp_registers_input_header,
    pub element: hv_set_vp_registers_input_element,
    // in fact, it is an array of undefined length, element[], but we only use one element
}

impl hv_set_vp_registers_input {
    pub fn new() -> Self {
        hv_set_vp_registers_input {
            ..Default::default()
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_nested_enlightenments_control_features {
    _data: u32,
    // union of
    // directhypercall: 1, reserved: 31
}

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_nested_enlightenments_control_hypercallControls {
    _data: u32,
    // union of
    // inter_partition_comm: 1, reserved: 31
}

#[expect(non_snake_case)]
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct hv_nested_enlightenments_control {
    pub features: hv_nested_enlightenments_control_features,
    pub hypercallControls: hv_nested_enlightenments_control_hypercallControls,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct hv_vp_assist_page {
    pub apic_assist: u32,
    reserved1: u32,
    pub vtl_entry_reason: u32,
    pub vtl_reserved: u32,
    pub vtl_ret_x64rax: u64,
    pub vtl_ret_x64rcx: u64,
    pub nested_control: hv_nested_enlightenments_control,
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

impl hv_vp_assist_page {
    pub fn new() -> Self {
        hv_vp_assist_page {
            apic_assist: 0,
            reserved1: 0,
            vtl_entry_reason: 0,
            vtl_reserved: 0,
            vtl_ret_x64rax: 0,
            vtl_ret_x64rcx: 0,
            nested_control: hv_nested_enlightenments_control::default(),
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

impl Default for hv_vp_assist_page {
    fn default() -> Self {
        Self::new()
    }
}
