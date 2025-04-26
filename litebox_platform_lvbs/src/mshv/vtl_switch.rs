use crate::mshv::mshv_bindings::hv_vp_assist_page;
use core::arch::asm;

// TODO: add VTL switch related stuffs

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

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn vtl_return(result: u64) {
    unsafe {
        asm!(
            "vmcall",
            in("rax") 0x0, in("rcx") 0x12, in("r8") result
        );
    }
}
