use crate::{
    arch::msr::msr_instr::{rdmsr, wrmsr},
    kernel_context::get_per_core_kernel_context,
    mshv::{
        mshv_bindings::{
            HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL, HV_X64_MSR_HYPERCALL_ENABLE,
            HV_X64_MSR_VP_ASSIST_PAGE, HV_X64_MSR_VP_ASSIST_PAGE_ENABLE,
            HYPERV_CPUID_IMPLEMENT_LIMITS, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS,
            HYPERV_HYPERVISOR_PRESENT_BIT, hv_vp_assist_page,
        },
        vtl1_mem_layout::get_hypercall_page_address,
    },
};

const CPU_VERSION_INFO: u32 = 1;
// const HV_CPUID_SIGNATURE_EAX: u32 = 0x31237648;
const LINUX_VERSION_CODE: u32 = 266002;
const PKG_ABI: u32 = 0;
const HV_CANONICAL_VENDOR_ID: u32 = 0x80;
const HV_LINUX_VENDOR_ID: u32 = 0x8100;

#[inline]
fn generate_guest_id(dinfo1: u64, kernver: u64, dinfo2: u64) -> u64 {
    let mut guest_id = (HV_LINUX_VENDOR_ID as u64) << 48;
    guest_id |= dinfo1 << 48;
    guest_id |= kernver << 16;
    guest_id |= dinfo2;

    guest_id
}

impl hv_vp_assist_page {
    #[expect(clippy::similar_names)]
    pub fn set_vtl_ret_regs(&mut self, rax: u64, rcx: u64) {
        self.vtl_ret_x64rax = rax;
        self.vtl_ret_x64rcx = rcx;
    }

    pub fn get_vtl_entry_reason(&self) -> u32 {
        self.vtl_entry_reason
    }
}

/// Initialize per-core MSR and virtual partition registers for Hyper-V Hypercalls
#[expect(clippy::missing_panics_doc)]
pub fn per_core_init() {
    #[cfg(not(test))]
    assert!(is_hyperv());

    let kernel_context = get_per_core_kernel_context();

    wrmsr(
        HV_X64_MSR_VP_ASSIST_PAGE,
        &raw const kernel_context.hv_vp_assist_page as u64
            | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE),
    );
    assert_eq!(
        rdmsr(HV_X64_MSR_VP_ASSIST_PAGE),
        &raw const kernel_context.hv_vp_assist_page as u64
            | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE)
    );

    let guest_id = generate_guest_id(
        HV_CANONICAL_VENDOR_ID as _,
        LINUX_VERSION_CODE as _,
        PKG_ABI as _,
    );
    wrmsr(HV_X64_MSR_GUEST_OS_ID, guest_id);

    wrmsr(
        HV_X64_MSR_HYPERCALL,
        get_hypercall_page_address() | u64::from(HV_X64_MSR_HYPERCALL_ENABLE),
    );
    assert_eq!(
        rdmsr(HV_X64_MSR_HYPERCALL),
        get_hypercall_page_address() | u64::from(HV_X64_MSR_HYPERCALL_ENABLE)
    );

    // TODO: configure VP partition (if the core is 0)
}

fn is_hyperv() -> bool {
    use core::arch::x86_64::__cpuid_count as cpuid_count;

    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
    if result.ecx & HYPERV_HYPERVISOR_PRESENT_BIT == 0 {
        return false;
    }

    // let result = unsafe { cpuid_count(HYPERV_CPUID_INTERFACE, 0x0) };
    // if result.eax != HV_CPUID_SIGNATURE_EAX {
    //     return false;
    // }

    let result = unsafe { cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0) };
    if result.eax < HYPERV_CPUID_IMPLEMENT_LIMITS {
        return false;
    }

    true
}
