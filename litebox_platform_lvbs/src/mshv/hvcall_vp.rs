//! Hyper-V Hypercall functions for virtual processor (VP)

use crate::{
    arch::{
        instrs::rdmsr,
        msr::{MSR_EFER, MSR_IA32_CR_PAT},
    },
    kernel_context::{MAX_CORES, get_per_core_kernel_context},
    mshv::{
        HV_PARTITION_ID_SELF, HV_VP_INDEX_SELF, HV_VTL_NORMAL, HV_VTL_SECURE, HVCALL_ENABLE_VP_VTL,
        HVCALL_GET_VP_REGISTERS, HVCALL_SET_VP_REGISTERS, HvEnableVpVtl, HvGetVpRegistersInput,
        HvGetVpRegistersOutput, HvInputVtl, HvSetVpRegistersInput, SegmentRegisterAttributeFlags,
        hvcall::{HypervCallError, hv_do_hypercall, hv_do_rep_hypercall},
        vtl1_mem_layout::{
            PAGE_SIZE, VTL1_KERNEL_STACK_PAGE, VTL1_TSS_PAGE, get_address_of_special_page,
        },
    },
    serial_println,
};
use x86_64::{
    PrivilegeLevel,
    structures::{gdt::SegmentSelector, tss::TaskStateSegment},
};

fn hvcall_set_vp_registers_internal(
    reg_name: u32,
    value: u64,
    target_vtl: HvInputVtl,
) -> Result<u64, HypervCallError> {
    let kernel_context = get_per_core_kernel_context();
    let hvin = unsafe {
        &mut *kernel_context
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvSetVpRegistersInput>()
    };
    *hvin = HvSetVpRegistersInput::new();

    hvin.header.partitionid = HV_PARTITION_ID_SELF;
    hvin.header.vpindex = HV_VP_INDEX_SELF;
    hvin.header.target_vtl = target_vtl;
    hvin.element[0].name = reg_name;
    hvin.element[0].valuelow = value;

    hv_do_rep_hypercall(
        HVCALL_SET_VP_REGISTERS,
        1,
        0,
        (&raw const *hvin).cast::<core::ffi::c_void>(),
        core::ptr::null_mut(),
    )
}

/// Hyper-V Hypercall to set current VTL (i.e., VTL1)'s registers. It can program Hyper-V registers
/// like `HV_REGISTER_VSM_PARTITION_CONFIG`.
#[inline]
pub fn hvcall_set_vp_registers(reg_name: u32, value: u64) -> Result<u64, HypervCallError> {
    hvcall_set_vp_registers_internal(reg_name, value, HvInputVtl::current())
}

/// Hyper-V Hypercall to set VTL0's registers like MSR and control registers.
#[inline]
pub fn hvcall_set_vp_vtl0_registers(reg_name: u32, value: u64) -> Result<u64, HypervCallError> {
    hvcall_set_vp_registers_internal(reg_name, value, HvInputVtl::new(HV_VTL_NORMAL))
}

fn hvcall_get_vp_registers_internal(
    reg_name: u32,
    target_vtl: HvInputVtl,
) -> Result<u64, HypervCallError> {
    let kernel_context = get_per_core_kernel_context();
    let hvin = unsafe {
        &mut *kernel_context
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvGetVpRegistersInput>()
    };
    *hvin = HvGetVpRegistersInput::new();
    let hvout = unsafe {
        &mut *kernel_context
            .hv_hypercall_output_page_as_mut_ptr()
            .cast::<HvGetVpRegistersOutput>()
    };
    *hvout = HvGetVpRegistersOutput::new();

    hvin.header.partitionid = HV_PARTITION_ID_SELF;
    hvin.header.vpindex = HV_VP_INDEX_SELF;
    hvin.header.target_vtl = target_vtl;
    hvin.element[0].name0 = reg_name;

    hv_do_rep_hypercall(
        HVCALL_GET_VP_REGISTERS,
        1,
        0,
        (&raw const *hvin).cast::<core::ffi::c_void>(),
        (&raw mut *hvout).cast::<core::ffi::c_void>(),
    )?;

    Ok(hvout.as64().0)
}

/// Hyper-V Hypercall to get current VTL (i.e., VTL1)'s registers. It can access Hyper-V registers
/// like `HV_REGISTER_VSM_PARTITION_CONFIG`.
#[expect(dead_code)]
#[inline]
pub fn hvcall_get_vp_registers(reg_name: u32) -> Result<u64, HypervCallError> {
    hvcall_get_vp_registers_internal(reg_name, HvInputVtl::current())
}

/// Hyper-V Hypercall to get VTL0's registers like MSR and control registers.
#[inline]
pub fn hvcall_get_vp_vtl0_registers(reg_name: u32) -> Result<u64, HypervCallError> {
    hvcall_get_vp_registers_internal(reg_name, HvInputVtl::new(HV_VTL_NORMAL))
}

/// Populate the VP context for VTL1
#[expect(clippy::similar_names)]
fn hv_vtl_populate_vp_context(input: &mut HvEnableVpVtl, tss: u64, rip: u64, rsp: u64) {
    use x86_64::instructions::tables::{sgdt, sidt};
    use x86_64::registers::{
        control::{Cr0, Cr3, Cr4},
        rflags,
    };

    input.vp_context.rip = rip;
    input.vp_context.rsp = rsp;
    input.vp_context.rflags = rflags::read_raw();
    input.vp_context.efer = rdmsr(MSR_EFER);
    input.vp_context.cr0 = Cr0::read_raw();
    let (frame, val) = Cr3::read_raw();
    input.vp_context.cr3 = frame.start_address().as_u64() | u64::from(val);
    input.vp_context.cr4 = Cr4::read_raw();
    input.vp_context.msr_cr_pat = rdmsr(MSR_IA32_CR_PAT);

    let gdt_ptr = sgdt();
    let idt_ptr = sidt();

    input.vp_context.gdtr.limit = gdt_ptr.limit;
    input.vp_context.gdtr.base = gdt_ptr.base.as_u64();

    input.vp_context.idtr.limit = idt_ptr.limit;
    input.vp_context.idtr.base = idt_ptr.base.as_u64();

    // We only support 64-bit long mode for now, so most of the segment register fields are ignored.
    input.vp_context.cs.selector = SegmentSelector::new(1, PrivilegeLevel::Ring0).0;
    input.vp_context.cs.set_attributes(
        SegmentRegisterAttributeFlags::ACCESSED.bits()
            | SegmentRegisterAttributeFlags::WRITABLE.bits()
            | SegmentRegisterAttributeFlags::EXECUTABLE.bits()
            | SegmentRegisterAttributeFlags::USER_SEGMENT.bits()
            | SegmentRegisterAttributeFlags::PRESENT.bits()
            | SegmentRegisterAttributeFlags::AVAILABLE.bits()
            | SegmentRegisterAttributeFlags::LONG_MODE.bits(),
    );

    input.vp_context.ss.selector = SegmentSelector::new(2, PrivilegeLevel::Ring0).0;
    input.vp_context.ss.set_attributes(
        SegmentRegisterAttributeFlags::ACCESSED.bits()
            | SegmentRegisterAttributeFlags::WRITABLE.bits()
            | SegmentRegisterAttributeFlags::USER_SEGMENT.bits()
            | SegmentRegisterAttributeFlags::PRESENT.bits()
            | SegmentRegisterAttributeFlags::AVAILABLE.bits(),
    );

    input.vp_context.tr.selector = SegmentSelector::new(3, PrivilegeLevel::Ring0).0;
    input.vp_context.tr.base = tss;
    input.vp_context.tr.limit =
        u32::try_from(core::mem::size_of::<TaskStateSegment>()).unwrap() - 1;
    input.vp_context.tr.set_attributes(
        SegmentRegisterAttributeFlags::ACCESSED.bits()
            | SegmentRegisterAttributeFlags::WRITABLE.bits()
            | SegmentRegisterAttributeFlags::EXECUTABLE.bits()
            | SegmentRegisterAttributeFlags::PRESENT.bits(),
    );
}

/// Hyper-V Hypercall to enable a certain VTL for a specific virtual processor (VP)
#[expect(clippy::similar_names)]
fn hvcall_enable_vp_vtl(
    core_id: u32,
    new_vtl: u8,
    tss: u64,
    rip: u64,
    rsp: u64,
) -> Result<u64, HypervCallError> {
    let mut hvin = HvEnableVpVtl::new();

    hvin.partition_id = HV_PARTITION_ID_SELF;
    hvin.vp_index = core_id;

    // `HVCALL_ENABLE_VP_VTL` uses `HvInputVtl` differently. It expects the `target_vtl` field specifies
    // a new VTL to enable and the `use_target_vtl` field is `false`.
    hvin.target_vtl.set_target_vtl(new_vtl);
    hvin.target_vtl.set_use_target_vtl(false);

    hv_vtl_populate_vp_context(&mut hvin, tss, rip, rsp);

    hv_do_hypercall(
        u64::from(HVCALL_ENABLE_VP_VTL),
        (&raw const hvin).cast::<core::ffi::c_void>(),
        core::ptr::null_mut(),
    )
}

unsafe extern "C" {
    static _start: u8;
}

#[inline]
fn get_entry() -> u64 {
    &raw const _start as u64
}

/// Hyper-V Hypercall to initialize VTL (VTL1 for now) for all online cores (except core 0)
///
/// # Panics
/// Panics if the number of online cores is greater than `MAX_CORES`.
#[expect(clippy::similar_names)]
pub fn init_vtl_aps(online_cores: u32) -> Result<u64, HypervCallError> {
    assert!(online_cores <= u32::try_from(MAX_CORES).expect("MAX_CORES"));

    let rip: u64 = get_entry() as *const () as u64;
    let rsp = get_address_of_special_page(VTL1_KERNEL_STACK_PAGE) + PAGE_SIZE as u64 - 1;
    let tss = get_address_of_special_page(VTL1_TSS_PAGE);

    for core in 1..online_cores {
        let result = hvcall_enable_vp_vtl(core, HV_VTL_SECURE, tss, rip, rsp);
        if result.is_err() {
            serial_println!("Failed to enable VTL for core {}: {:?}", core, result);
            return result;
        }
    }

    Ok(0)
}
