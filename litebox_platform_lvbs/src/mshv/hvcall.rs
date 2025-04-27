use crate::{
    arch::instrs::{rdmsr, wrmsr},
    kernel_context::get_per_core_kernel_context,
    mshv::mshv_bindings::{
        HV_STATUS_ACCESS_DENIED, HV_STATUS_INSUFFICIENT_BUFFERS, HV_STATUS_INSUFFICIENT_MEMORY,
        HV_STATUS_INVALID_ALIGNMENT, HV_STATUS_INVALID_CONNECTION_ID,
        HV_STATUS_INVALID_HYPERCALL_CODE, HV_STATUS_INVALID_HYPERCALL_INPUT,
        HV_STATUS_INVALID_PARAMETER, HV_STATUS_INVALID_PORT_ID, HV_STATUS_OPERATION_DENIED,
        HV_STATUS_TIME_OUT, HV_STATUS_VTL_ALREADY_ENABLED, HV_X64_MSR_GUEST_OS_ID,
        HV_X64_MSR_HYPERCALL, HV_X64_MSR_HYPERCALL_ENABLE, HV_X64_MSR_VP_ASSIST_PAGE,
        HV_X64_MSR_VP_ASSIST_PAGE_ENABLE, HYPERV_CPUID_IMPLEMENT_LIMITS, HYPERV_CPUID_INTERFACE,
        HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, HYPERV_HYPERVISOR_PRESENT_BIT,
    },
};
use num_enum::TryFromPrimitive;

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

/// Enable Hyper-V hypercalls by initializing MSR and VP registers (per core)
/// # Panics
/// Panics if the underlying hardware/platform is not Hyper-V
pub fn init() -> Result<(), HypervError> {
    let result = check_hyperv();

    #[expect(clippy::question_mark)]
    if result.is_err() {
        return result;
    }

    let kernel_context = get_per_core_kernel_context();

    wrmsr(
        HV_X64_MSR_VP_ASSIST_PAGE,
        kernel_context.hv_vp_assist_page_as_u64() | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE),
    );
    if rdmsr(HV_X64_MSR_VP_ASSIST_PAGE)
        != kernel_context.hv_vp_assist_page_as_u64() | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE)
    {
        return Err(HypervError::InvalidAssistPage);
    }

    let guest_id = generate_guest_id(
        HV_CANONICAL_VENDOR_ID.into(),
        LINUX_VERSION_CODE.into(),
        PKG_ABI.into(),
    );
    wrmsr(HV_X64_MSR_GUEST_OS_ID, guest_id);
    if guest_id != rdmsr(HV_X64_MSR_GUEST_OS_ID) {
        return Err(HypervError::InvalidGuestOSID);
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

    // TODO: configure virtual partitions (if core # is 0)

    Ok(())
}

// TODO: add hv_do and hv_do_rep hypercalls

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

/// Error for Hyper-V initialization
#[derive(Debug, PartialEq)]
pub enum HypervError {
    NonVirtualized,
    NonHyperv,
    NoVTLSupport,
    InvalidAssistPage,
    InvalidGuestOSID,
    InvalidHypercallPage,
}

/// Error for Hyper-V hypercall
#[derive(Debug, TryFromPrimitive)]
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
}
