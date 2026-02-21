// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V Hypercall functions for memory management

#[cfg(not(test))]
use crate::mshv::{
    HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES, HV_FLUSH_EX_VP_SET_BANKS, HV_GENERIC_SET_SPARSE_4K,
    HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX, HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX,
    HvInputFlushVirtualAddressListEx, HvInputFlushVirtualAddressSpaceEx, hvcall::hv_do_hypercall,
    vtl_switch::vtl1_vp_mask,
};
use crate::{
    host::per_cpu_variables::with_per_cpu_variables_mut,
    mshv::{
        HV_PARTITION_ID_SELF, HVCALL_MODIFY_VTL_PROTECTION_MASK, HvInputModifyVtlProtectionMask,
        HvInputVtl, HvPageProtFlags,
        hvcall::{HypervCallError, hv_do_rep_hypercall},
        vtl1_mem_layout::PAGE_SHIFT,
    },
};

#[cfg(not(test))]
#[inline]
fn vp_set_valid_bank_mask(vp_set_bank_contents: [u64; HV_FLUSH_EX_VP_SET_BANKS]) -> u64 {
    vp_set_bank_contents
        .iter()
        .enumerate()
        .fold(0u64, |mask, (bank, contents)| {
            if *contents != 0 {
                mask | (1u64 << bank)
            } else {
                mask
            }
        })
}

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

/// Flush the entire virtual address space on VPs currently in VTL1.
///
/// Issues `HvCallFlushVirtualAddressSpace` with
/// `HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES` targeting only the VPs
/// whose bits are set in [`vtl1_vp_mask`].  VPs running in VTL0 use
/// a separate address space and don't need flushing — they will
/// get a full TLB flush on their next VTL1 entry.
///
/// This is the cross-core equivalent of a local CR3 reload.
#[cfg(not(test))]
pub(crate) fn hv_flush_virtual_address_space() -> Result<(), HypervCallError> {
    let vp_mask = vtl1_vp_mask();
    let valid_bank_mask = vp_set_valid_bank_mask(vp_mask);
    if valid_bank_mask == 0 {
        return Ok(());
    }
    let input = with_per_cpu_variables_mut(|pcv| unsafe {
        &mut *pcv
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvInputFlushVirtualAddressSpaceEx>()
    });

    *input = HvInputFlushVirtualAddressSpaceEx {
        address_space: 0,
        flags: HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES,
        vp_set_format: HV_GENERIC_SET_SPARSE_4K,
        vp_set_valid_bank_mask: valid_bank_mask,
        vp_set_bank_contents: vp_mask,
    };

    hv_do_hypercall(
        u64::from(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX),
        (&raw const *input).cast::<core::ffi::c_void>(),
        core::ptr::null_mut(),
    )?;

    Ok(())
}

/// Flush specific virtual addresses on VPs currently in VTL1.
///
/// Issues `HvCallFlushVirtualAddressList` with
/// `HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES` targeting only the VPs
/// whose bits are set in [`vtl1_vp_mask`].
///
/// # Arguments
/// - `start_va`: first virtual address to flush (must be page-aligned)
/// - `page_count`: number of pages to flush
#[cfg(not(test))]
pub(crate) fn hv_flush_virtual_address_list(
    start_va: u64,
    page_count: usize,
) -> Result<(), HypervCallError> {
    debug_assert!(
        start_va.is_multiple_of(4096),
        "start_va {start_va:#x} is not page-aligned"
    );
    debug_assert!(page_count > 0, "page_count must not be 0");

    let vp_mask = vtl1_vp_mask();
    let valid_bank_mask = vp_set_valid_bank_mask(vp_mask);
    if valid_bank_mask == 0 {
        return Ok(());
    }
    let input = with_per_cpu_variables_mut(|pcv| unsafe {
        &mut *pcv
            .hv_hypercall_input_page_as_mut_ptr()
            .cast::<HvInputFlushVirtualAddressListEx>()
    });

    input.address_space = 0;
    input.flags = HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;
    input.vp_set_format = HV_GENERIC_SET_SPARSE_4K;
    input.vp_set_valid_bank_mask = valid_bank_mask;
    input.vp_set_bank_contents = vp_mask;

    let mut remaining = page_count;
    let mut current_va = start_va;

    while remaining > 0 {
        let mut gva_count: u16 = 0;

        while remaining > 0
            && (gva_count as usize) < HvInputFlushVirtualAddressListEx::MAX_GVAS_PER_REQUEST
        {
            // Each entry can cover up to `MAX_ADDITIONAL_PAGES + 1` pages.
            let additional = remaining.saturating_sub(1).min(MAX_ADDITIONAL_PAGES);
            let pages_in_entry = additional + 1;

            // GVA range entry: bits 63:12 = page number, bits 11:0 = additional_pages
            let page_number = current_va >> 12;
            input.gva_range_list[gva_count as usize] = (page_number << 12) | additional as u64;

            current_va += (pages_in_entry as u64) << 12;
            remaining -= pages_in_entry;
            gva_count += 1;
        }

        hv_do_rep_hypercall(
            HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX,
            gva_count,
            HvInputFlushVirtualAddressListEx::VP_SET_QWORD_COUNT,
            (&raw const *input).cast::<core::ffi::c_void>(),
            core::ptr::null_mut(),
        )?;
    }

    Ok(())
}

/// Maximum number of additional pages encodable in bits 11:0 of a
/// GVA range entry (TLFS §3.5.3).
#[cfg(not(test))]
const MAX_ADDITIONAL_PAGES: usize = 0xFFF; // 4095
