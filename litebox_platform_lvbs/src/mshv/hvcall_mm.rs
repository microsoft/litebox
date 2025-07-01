//! Hyper-V Hypercall functions for memory management

use crate::{
    kernel_context::get_per_core_kernel_context,
    mshv::{
        HV_PARTITION_ID_SELF, HVCALL_MODIFY_VTL_PROTECTION_MASK, HvInputModifyVtlProtectionMask,
        HvInputVtl, HvPageProtFlags,
        hvcall::{HypervCallError, hv_do_rep_hypercall},
        vtl1_mem_layout::PAGE_SHIFT,
    },
    serial_println,
};

/// Hyper-V Hypercall to prevent lower VTLs (i.e., VTL0) from accessing a specified range of
/// guest physical memory pages with a given protection flag.
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
    hvin.target_vtl = HvInputVtl::current();
    hvin.map_flags = u32::from(page_access.bits());

    let mut total_protected: u64 = 0;
    while total_protected < num_pages {
        let mut pages_to_protect: u16 = 0;
        for i in 0..HvInputModifyVtlProtectionMask::MAX_PAGES_PER_REQUEST {
            if total_protected + i as u64 >= num_pages {
                break;
            } else {
                hvin.gpa_page_list[i] = (start >> PAGE_SHIFT) + (total_protected + i as u64);
                pages_to_protect += 1;
            }
        }

        let result = hv_do_rep_hypercall(
            HVCALL_MODIFY_VTL_PROTECTION_MASK,
            pages_to_protect,
            0,
            (&raw const *hvin).cast::<core::ffi::c_void>(),
            core::ptr::null_mut(),
        );

        if let Ok(protected) = result {
            total_protected += protected;
        } else {
            serial_println!("Err: {:?}", result);
            return result;
        }
    }

    Ok(total_protected)
}
