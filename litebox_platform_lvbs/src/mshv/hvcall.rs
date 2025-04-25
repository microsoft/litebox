use crate::arch::msr::msr_instr::wrmsr;
use crate::mshv::{
    mshv_bindings::{
        HV_X64_MSR_HYPERCALL, HV_X64_MSR_HYPERCALL_ENABLE, HV_X64_MSR_VP_ASSIST_PAGE,
        HV_X64_MSR_VP_ASSIST_PAGE_ENABLE, hv_vp_assist_page,
    },
    vtl1_mem_layout::{self, VTL1_HYPERCALL_PAGE, VTL1_VP_ASSIST_PAGE, get_address_from_page},
};
use lazy_static::lazy_static;
use spin::Mutex;

pub struct HvVpAssistPageWrapper {
    page: &'static mut hv_vp_assist_page,
}

impl HvVpAssistPageWrapper {
    pub fn as_u64(&mut self) -> u64 {
        &raw const self.page as u64
    }

    #[expect(clippy::similar_names)]
    pub fn set_vtl_ret_regs(&mut self, rax: u64, rcx: u64) {
        self.page.vtl_ret_x64rax = rax;
        self.page.vtl_ret_x64rcx = rcx;
    }

    pub fn get_vtl_entry_reason(&self) -> u32 {
        self.page.vtl_entry_reason
    }
}

// TODO: per-core, so let's use heap
lazy_static! {
    static ref HV_VP_ASSIST_PAGE: Mutex<HvVpAssistPageWrapper> =
        Mutex::new(HvVpAssistPageWrapper {
            page: unsafe {
                &mut *(get_address_from_page(VTL1_VP_ASSIST_PAGE) as *mut hv_vp_assist_page)
            }
        });
}

#[repr(C, packed)]
struct HvHypercallPage {
    pub buffer: [u8; vtl1_mem_layout::PAGE_SIZE],
}

pub struct HvHypercallPageWrapper {
    page: &'static mut HvHypercallPage,
}

impl HvHypercallPageWrapper {
    pub fn as_u64(&mut self) -> u64 {
        &raw const self.page as u64
    }
}

// shared, read-only. doesn't have to use heap
lazy_static! {
    static ref HV_HYPERCALL_PAGE: Mutex<HvHypercallPageWrapper> =
        Mutex::new(HvHypercallPageWrapper {
            page: unsafe {
                &mut *(get_address_from_page(VTL1_HYPERCALL_PAGE) as *mut HvHypercallPage)
            }
        });
}

/// Initialize per-core MSR and virtual partition registers for Hyper-V Hypercalls
pub fn per_core_init() {
    wrmsr(
        HV_X64_MSR_VP_ASSIST_PAGE,
        HV_VP_ASSIST_PAGE.lock().as_u64() | u64::from(HV_X64_MSR_VP_ASSIST_PAGE_ENABLE),
    );

    wrmsr(
        HV_X64_MSR_HYPERCALL,
        HV_HYPERCALL_PAGE.lock().as_u64() | u64::from(HV_X64_MSR_HYPERCALL_ENABLE),
    );
}
