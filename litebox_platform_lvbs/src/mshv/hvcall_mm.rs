// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V Hypercall functions for memory management

use crate::{
    host::per_cpu_variables::with_per_cpu_variables_mut,
    mshv::{
        hvcall::{hv_do_rep_hypercall, HypervCallError},
        vtl1_mem_layout::PAGE_SHIFT,
        HvInputModifyVtlProtectionMask, HvInputVtl, HVCALL_MODIFY_VTL_PROTECTION_MASK,
        HV_PARTITION_ID_SELF,
    },
};
use litebox_common_lvbs::mshv::HvPageProtFlags;

/// Hyper-V Hypercall to prevent lower VTLs (i.e., VTL0) from accessing a specified range of
/// guest physical memory pages with a given protection flag.
pub fn hv_modify_vtl_protection_mask(
    start: u64,
    num_pages: u64,
    page_access: HvPageProtFlags,
) -> Result<u64, HypervCallError> {
    let hvin = with_per_cpu_variables_mut(|per_cpu_variables| unsafe {
        &mut *per_cpu_variables
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvInputModifyVtlProtectionMask>()
    });
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

        total_protected += result?;
    }

    Ok(total_protected)
}
