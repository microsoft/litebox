//! Hyper-V Hypercall functions

use crate::{
    arch::instrs::{rdmsr, wrmsr},
    debug_serial_println,
    kernel_context::{get_core_id, get_per_core_kernel_context},
    mshv::{
        HV_HYPERCALL_REP_COMP_MASK, HV_HYPERCALL_REP_COMP_OFFSET, HV_HYPERCALL_REP_START_MASK,
        HV_HYPERCALL_REP_START_OFFSET, HV_HYPERCALL_RESULT_MASK, HV_HYPERCALL_VARHEAD_OFFSET,
        HV_STATUS_ACCESS_DENIED, HV_STATUS_INSUFFICIENT_BUFFERS, HV_STATUS_INSUFFICIENT_MEMORY,
        HV_STATUS_INVALID_ALIGNMENT, HV_STATUS_INVALID_CONNECTION_ID,
        HV_STATUS_INVALID_HYPERCALL_CODE, HV_STATUS_INVALID_HYPERCALL_INPUT,
        HV_STATUS_INVALID_PARAMETER, HV_STATUS_INVALID_PORT_ID, HV_STATUS_OPERATION_DENIED,
        HV_STATUS_SUCCESS, HV_STATUS_TIME_OUT, HV_STATUS_VTL_ALREADY_ENABLED,
        HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL, HV_X64_MSR_HYPERCALL_ENABLE,
        HV_X64_MSR_SCONTROL, HV_X64_MSR_SCONTROL_ENABLE, HV_X64_MSR_SIMP, HV_X64_MSR_SIMP_ENABLE,
        HV_X64_MSR_SINT0, HV_X64_MSR_VP_ASSIST_PAGE, HV_X64_MSR_VP_ASSIST_PAGE_ENABLE,
        HYPERV_CPUID_IMPLEMENT_LIMITS, HYPERV_CPUID_INTERFACE,
        HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, HYPERV_HYPERVISOR_PRESENT_BIT,
        HYPERVISOR_CALLBACK_VECTOR, HvSynicSint, vsm,
    },
};
use core::arch::asm;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[cfg(debug_assertions)]
use crate::mshv::HV_REGISTER_VP_INDEX;

const CPU_VERSION_INFO: u32 = 1;
const HV_CPUID_SIGNATURE_EAX: u32 = 0x31237648;

// TODO: use real vendor IDs and version code
const LINUX_VERSION_CODE: u32 = 266002;
const PKG_ABI: u32 = 0;
const HV_CANONICAL_VENDOR_ID: u32 = 0x80;
const HV_LINUX_VENDOR_ID: u32 = 0x8100;

#[inline]
fn generate_guest_id(dinfo1: u64, kernver: u64, dinfo2: u64) -> u64 {
    let mut guest_id = u64::from(HV_LINUX_VENDOR_ID) << 48;
    guest_id |= dinfo1 << 48;
    guest_id |= kernver << 16;
    guest_id |= dinfo2;

    guest_id
}

fn check_hyperv() -> Result<(), HypervError> {
    use core::arch::x86_64::__cpuid_count as cpuid_count;

    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
    if result.ecx & HYPERV_HYPERVISOR_PRESENT_BIT == 0 {
        return Err(HypervError::NonVirtualized);
    }

    let result = unsafe { cpuid_count(HYPERV_CPUID_INTERFACE, 0x0) };
    if result.eax != HV_CPUID_SIGNATURE_EAX {
        return Err(HypervError::NonHyperv);
    }

    let result = unsafe { cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0) };
    if result.eax < HYPERV_CPUID_IMPLEMENT_LIMITS {
        return Err(HypervError::NoVTLSupport);
    }

    Ok(())
}

/// Enable Hyper-V Hypercalls by initializing MSR and VP registers (for a core)
/// # Panics
/// Panics if the underlying hardware/platform is not Hyper-V
/// Panics if the MSR/VP registers writes fail
pub fn init() -> Result<(), HypervError> {
    check_hyperv()?;

    debug_serial_println!("HV_REGISTER_VP_INDEX: {:#x}", rdmsr(HV_REGISTER_VP_INDEX));

    let kernel_context = get_per_core_kernel_context();

    wrmsr(
        HV_X64_MSR_VP_ASSIST_PAGE,
        kernel_context.hv_vp_assist_page_as_u64() | HV_X64_MSR_VP_ASSIST_PAGE_ENABLE,
    );
    if rdmsr(HV_X64_MSR_VP_ASSIST_PAGE)
        != kernel_context.hv_vp_assist_page_as_u64() | HV_X64_MSR_VP_ASSIST_PAGE_ENABLE
    {
        return Err(HypervError::InvalidAssistPage);
    }
    debug_serial_println!(
        "HV_X64_MSR_VP_ASSIST_PAGE: {:#x}",
        rdmsr(HV_X64_MSR_VP_ASSIST_PAGE)
    );

    let guest_id = generate_guest_id(
        HV_CANONICAL_VENDOR_ID.into(),
        LINUX_VERSION_CODE.into(),
        PKG_ABI.into(),
    );
    wrmsr(HV_X64_MSR_GUEST_OS_ID, guest_id);
    if guest_id != rdmsr(HV_X64_MSR_GUEST_OS_ID) {
        return Err(HypervError::InvalidGuestOSID);
    }
    if get_core_id() == 0 {
        debug_serial_println!(
            "HV_X64_MSR_GUEST_OS_ID: {:#x}",
            rdmsr(HV_X64_MSR_GUEST_OS_ID)
        );
    }

    wrmsr(
        HV_X64_MSR_HYPERCALL,
        kernel_context.hv_hypercall_page_as_u64() | u64::from(HV_X64_MSR_HYPERCALL_ENABLE),
    );
    if rdmsr(HV_X64_MSR_HYPERCALL)
        != kernel_context.hv_hypercall_page_as_u64() | u64::from(HV_X64_MSR_HYPERCALL_ENABLE)
    {
        return Err(HypervError::InvalidHypercallPage);
    }

    wrmsr(
        HV_X64_MSR_SIMP,
        kernel_context.hv_simp_page_as_u64() | u64::from(HV_X64_MSR_SIMP_ENABLE),
    );
    if rdmsr(HV_X64_MSR_SIMP)
        != kernel_context.hv_simp_page_as_u64() | u64::from(HV_X64_MSR_SIMP_ENABLE)
    {
        return Err(HypervError::InvalidSimpPage);
    }
    debug_serial_println!("HV_X64_MSR_SIMP: {:#x}", rdmsr(HV_X64_MSR_SIMP));

    let mut sint = HvSynicSint::new();
    sint.set_vector_u64(u64::from(HYPERVISOR_CALLBACK_VECTOR));
    sint.set_auto_eoi_flag();

    wrmsr(HV_X64_MSR_SINT0, sint.as_uint64());
    if get_core_id() == 0 {
        debug_serial_println!("HV_X64_MSR_SINT0: {:#x}", rdmsr(HV_X64_MSR_SINT0));
    }

    wrmsr(HV_X64_MSR_SCONTROL, u64::from(HV_X64_MSR_SCONTROL_ENABLE));

    vsm::init();

    Ok(())
}

#[inline]
fn hv_result(status: u64) -> u32 {
    u32::try_from(status & u64::from(HV_HYPERCALL_RESULT_MASK)).expect("mask error")
}

#[inline]
pub fn hv_result_success(status: u64) -> bool {
    hv_result(status) == HV_STATUS_SUCCESS
}

/// Hyper-V Hypercall using the hypercall page
pub fn hv_do_hypercall(
    control: u64,
    input: *const core::ffi::c_void,
    output: *mut core::ffi::c_void,
) -> Result<u64, HypervCallError> {
    let mut status: u64;
    let kernel_context = get_per_core_kernel_context();
    let hypercall_pg_addr: u64 = kernel_context.hv_hypercall_page_as_u64();

    unsafe {
        asm!(
            "call rax",
            in("rax") hypercall_pg_addr, in("rcx") control, in("rdx") input,
            in("r8") output, lateout("rax") status, options(nostack)
        );
    }

    if !hv_result_success(status) {
        let err = HypervCallError::try_from(hv_result(status)).unwrap_or(HypervCallError::Unknown);
        return Err(err);
    }

    Ok(status)
}

#[inline]
fn hv_repcomp(status: u64) -> u16 {
    ((status & HV_HYPERCALL_REP_COMP_MASK) >> HV_HYPERCALL_REP_COMP_OFFSET) as u16
}

/// Hyper-V Hypercall with repeat support
pub fn hv_do_rep_hypercall(
    code: u16,
    rep_count: u16,
    varhead_size: u16,
    input: *const core::ffi::c_void,
    output: *mut core::ffi::c_void,
) -> Result<u64, HypervCallError> {
    let mut control: u64 = u64::from(code);
    let mut rep_comp: u16;

    control |= u64::from(varhead_size) << HV_HYPERCALL_VARHEAD_OFFSET;
    control |= u64::from(rep_count) << HV_HYPERCALL_REP_COMP_OFFSET;

    loop {
        let status = hv_do_hypercall(control, input, output)?;

        rep_comp = hv_repcomp(status);
        control &= !HV_HYPERCALL_REP_START_MASK;
        control |= u64::from(rep_comp) << HV_HYPERCALL_REP_START_OFFSET;

        if rep_comp >= rep_count {
            break;
        }
    }

    Ok(rep_comp.into())
}

/// Error for Hyper-V initialization
#[derive(Debug, PartialEq)]
pub enum HypervError {
    NonVirtualized,
    NonHyperv,
    NoVTLSupport,
    InvalidAssistPage,
    InvalidGuestOSID,
    InvalidHypercallPage,
    InvalidSiefpPage,
    InvalidSimpPage,
    VPSetupFailed,
    Unknown,
}

/// Error for Hyper-V Hypercall
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum HypervCallError {
    InvalidCode = HV_STATUS_INVALID_HYPERCALL_CODE,
    InvalidInput = HV_STATUS_INVALID_HYPERCALL_INPUT,
    InvalidAlignment = HV_STATUS_INVALID_ALIGNMENT,
    InvalidParameter = HV_STATUS_INVALID_PARAMETER,
    AccessDenied = HV_STATUS_ACCESS_DENIED,
    OperationDenied = HV_STATUS_OPERATION_DENIED,
    InsufficientMemory = HV_STATUS_INSUFFICIENT_MEMORY,
    InvalidPortID = HV_STATUS_INVALID_PORT_ID,
    InvalidConnectionID = HV_STATUS_INVALID_CONNECTION_ID,
    InsufficientBuffers = HV_STATUS_INSUFFICIENT_BUFFERS,
    TimeOut = HV_STATUS_TIME_OUT,
    AlreadyEnabled = HV_STATUS_VTL_ALREADY_ENABLED,
    Unknown = 0xffff_ffff,
}
