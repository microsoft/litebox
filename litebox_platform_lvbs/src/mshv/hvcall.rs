use crate::arch::msr::msr_instr::{rdmsr, wrmsr};
use crate::kernel_context::get_per_core_kernel_context;
use crate::mshv::{
    mshv_bindings::{
        HV_X64_MSR_HYPERCALL, HV_X64_MSR_HYPERCALL_ENABLE, HV_X64_MSR_VP_ASSIST_PAGE,
        HV_X64_MSR_VP_ASSIST_PAGE_ENABLE, hv_vp_assist_page,
    },
    vtl1_mem_layout::get_hypercall_page_address,
};

const CPU_VERSION_INFO: u32 = 1;
const HYPERVISOR_PRESENT: u32 = 1 << 31;
const HV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
const HV_CPUID_INTERFACE: u32 = 0x40000001;
const HV_CPUID_IMPLEMENT_LIMITS: u32 = 0x40000005;
const HV_CPUID_SIGNATURE_EAX: u32 = 0x31237648;

impl hv_vp_assist_page {
    pub fn as_u64(&mut self) -> u64 {
        &raw const self as u64
    }

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
        kernel_context.hv_vp_assist_page.as_u64() | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE),
    );
    assert_eq!(
        rdmsr(HV_X64_MSR_VP_ASSIST_PAGE),
        kernel_context.hv_vp_assist_page.as_u64() | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE)
    );

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
    if result.ecx & HYPERVISOR_PRESENT == 0 {
        return false;
    }

    let result = unsafe { cpuid_count(HV_CPUID_INTERFACE, 0x0) };
    if result.eax != HV_CPUID_SIGNATURE_EAX {
        return false;
    }

    let result = unsafe { cpuid_count(HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0) };
    if result.eax < HV_CPUID_IMPLEMENT_LIMITS {
        return false;
    }

    true
}
