//! Hyper-V Hypercall functions for virtual processor (VP)

use crate::{
    arch::{
        instrs::rdmsr,
        msr::{MSR_EFER, MSR_IA32_CR_PAT},
    },
    kernel_context::MAX_CORES,
    mshv::{
        HV_PARTITION_ID_SELF, HV_VP_INDEX_SELF, HV_VTL_SECURE, HVCALL_ENABLE_VP_VTL,
        HVCALL_SET_VP_REGISTERS, HvEnableVpVtl, HvSetVpRegistersInput,
        hvcall::{HypervCallError, hv_do_hypercall, hv_do_rep_hypercall},
        vtl1_mem_layout::{
            PAGE_SIZE, VTL1_KERNEL_STACK_PAGE, VTL1_TSS_PAGE, get_address_of_special_page,
        },
    },
    serial_println,
};

/// Hyper-V Hypercall to set virtual processor (VP) registers
#[expect(dead_code)]
pub fn hvcall_set_vp_registers(
    reg_name: u32,
    value: u64,
    input_vtl: u8,
) -> Result<u64, HypervCallError> {
    let mut hvin = HvSetVpRegistersInput::new();

    hvin.header.partitionid = HV_PARTITION_ID_SELF;
    hvin.header.vpindex = HV_VP_INDEX_SELF;
    hvin.header.inputvtl = input_vtl;
    hvin.element.name = reg_name;
    hvin.element.valuelow = value;

    hv_do_rep_hypercall(
        HVCALL_SET_VP_REGISTERS,
        1,
        0,
        (&raw const hvin).cast::<core::ffi::c_void>(),
        core::ptr::null_mut(),
    )
}

/// Populate the VP context for VTL1
// TODO: avoid using magic numbers
#[expect(clippy::similar_names)]
fn hv_vtl_populate_vp_context(input: &mut HvEnableVpVtl, tss: u64, rip: u64, rsp: u64) {
    use x86_64::instructions::tables::{sgdt, sidt};
    use x86_64::registers::control::{Cr0, Cr3, Cr4};

    input.vp_context.rip = rip;
    input.vp_context.rsp = rsp;
    input.vp_context.rflags = 0x2;
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

    input.vp_context.cs.selector = 1 << 3;
    input.vp_context.cs.base = 0;
    input.vp_context.cs.limit = 0xffff_ffff;
    input.vp_context.cs.set_attributes(0xa09b);

    input.vp_context.ss.selector = 2 << 3;
    input.vp_context.ss.base = 0;
    input.vp_context.ss.limit = 0xffff_ffff;
    input.vp_context.ss.set_attributes(0xc093);

    input.vp_context.tr.selector = 3 << 3;
    input.vp_context.tr.base = tss;
    input.vp_context.tr.limit = 104 - 1;
    input.vp_context.tr.set_attributes(0x8b);
}

/// Hyper-V Hypercall to enable a certain VTL for a specific virtual processor (VP)
#[expect(clippy::similar_names)]
fn hvcall_enable_vp_vtl(
    core_id: u32,
    target_vtl: u8,
    tss: u64,
    rip: u64,
    rsp: u64,
) -> Result<u64, HypervCallError> {
    let mut hvin = HvEnableVpVtl::new();

    hvin.partition_id = HV_PARTITION_ID_SELF;
    hvin.vp_index = core_id;
    hvin.target_vtl.set_target_vtl(target_vtl);

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
