//! Hyper-V Hypercall functions for memory management

use crate::{
    kernel_context::get_per_core_kernel_context,
    mshv::{
        HV_MODIFY_MAX_PAGES, HV_PARTITION_ID_SELF, HV_STATUS_SUCCESS, HV_VTL_SECURE,
        HVCALL_MODIFY_VTL_PROTECTION_MASK, HvInputModifyVtlProtectionMask, HvPageProtFlags,
        hvcall::{HypervCallError, hv_do_rep_hypercall},
        vtl1_mem_layout::PAGE_SIZE,
    },
    serial_println,
};

pub fn hv_modify_vtl_protection_mask(
    start: u64,
    num_pages: u64,
    page_access: HvPageProtFlags,
) -> Result<u64, HypervCallError> {
    let kernel_context = get_per_core_kernel_context();
    let hvin = unsafe {
        &mut *kernel_context
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvInputModifyVtlProtectionMask>()
    };
    *hvin = HvInputModifyVtlProtectionMask::new();

    hvin.partition_id = HV_PARTITION_ID_SELF;
    hvin.target_vtl.set_target_vtl(HV_VTL_SECURE);
    hvin.map_flags = page_access.bits();

    let mut total_protected: u64 = 0;
    while total_protected < num_pages {
        let mut pages_to_protect: u16 = 0;
        for i in 0..HV_MODIFY_MAX_PAGES {
            if total_protected + i as u64 >= num_pages {
                break;
            } else {
                hvin.gpa_page_list[i] = start + (total_protected + i as u64) * PAGE_SIZE as u64;
                pages_to_protect += 1;
            }
        }
        for i in pages_to_protect as usize..HV_MODIFY_MAX_PAGES {
            hvin.gpa_page_list[i] = 0;
        }

        if let Err(status) = hv_do_rep_hypercall(
            HVCALL_MODIFY_VTL_PROTECTION_MASK,
            pages_to_protect,
            0,
            (&raw const hvin).cast::<core::ffi::c_void>(),
            core::ptr::null_mut(),
        ) {
            serial_println!("Err: {:?}", status);
            return Err(status);
        }

        total_protected += u64::from(pages_to_protect);
    }

    Ok(HV_STATUS_SUCCESS.into())
}
