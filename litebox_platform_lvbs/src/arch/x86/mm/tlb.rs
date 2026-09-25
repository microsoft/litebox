// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local x86 TLB mechanics. These functions do not perform remote shootdowns.

use x86_64::{
    VirtAddr,
    structures::paging::{Page, PageSize, Size4KiB},
};

/// Above this count a local CR3 reload is cheaper than individual INVLPGs.
/// Heuristic inherited from the existing LVBS implementation:
/// <https://elixir.bootlin.com/linux/v6.18.6/source/arch/x86/mm/tlb.c#L1394>
const SINGLE_PAGE_FLUSH_CEILING: usize = 33;

/// Invalidate non-global translations on the current CPU only.
///
/// # Safety
/// The caller must run at kernel privilege with PCID disabled. This does not
/// establish cross-CPU completion: the caller must exclude other users of the
/// changed mappings or separately arrange remote invalidation before reuse.
/// `start` and `page_count` must describe a non-wrapping canonical page range.
#[inline]
pub unsafe fn invalidate_local(start: Page<Size4KiB>, page_count: usize) {
    if page_count <= SINGLE_PAGE_FLUSH_CEILING {
        let base = start.start_address().as_u64();
        for i in 0..page_count {
            x86_64::instructions::tlb::flush(VirtAddr::new(base + i as u64 * Size4KiB::SIZE));
        }
    } else {
        x86_64::instructions::tlb::flush_all();
    }
}
