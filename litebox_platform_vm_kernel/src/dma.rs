// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`litebox_hal::dma::Hal`]: DMA from the page allocator (RAM is
//! direct-mapped, so contiguous), and device memory mapped uncacheable in
//! [`IOREMAP`], each mapping followed by an unmapped guard page, as Linux's
//! `ioremap` does.

use crate::mm::MemoryProvider;
use crate::{IOREMAP, VmKernel};
use core::ptr::NonNull;
use litebox_hal::dma::{Hal, Mmio};
use x86_64::structures::paging::{Page, PageSize, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

fn order(pages: usize) -> u32 {
    pages.next_power_of_two().trailing_zeros()
}

// Safety: page-allocator blocks are contiguous, exclusively owned until
// freed, and mapped writable at `PA + KERNEL_OFFSET`. Device memory is
// mapped uncacheable for the kernel's lifetime, and RAM is refused.
unsafe impl Hal for VmKernel {
    fn dma_alloc(&self, pages: usize) -> Option<(NonNull<u8>, u64)> {
        let va = NonNull::new(Self::mem_allocate_pages(order(pages))?)?;
        Some((va, Self::va_to_pa(VirtAddr::from_ptr(va.as_ptr())).as_u64()))
    }

    unsafe fn dma_dealloc(&self, va: NonNull<u8>, pages: usize) {
        // Safety: from `dma_alloc` with the same `pages`.
        unsafe { Self::mem_free_pages(va.as_ptr(), order(pages)) };
    }

    unsafe fn map_mmio(&self, pa: u64, len: usize) -> Option<Mmio> {
        let end = pa
            .checked_add(u64::try_from(len).ok()?)
            .filter(|_| len != 0)?;
        let first = PhysFrame::<Size4KiB>::containing_address(PhysAddr::try_new(pa).ok()?);
        let last =
            PhysFrame::containing_address(PhysAddr::try_new(end).ok()?.align_up(Size4KiB::SIZE));
        if self
            .ram_frame_ranges
            .iter()
            .any(|r| r.start < last && first < r.end)
        {
            return None;
        }
        let start = {
            let mut next = self.ioremap_next.lock();
            let start = *next;
            let after = start
                .checked_add(last.start_address() - first.start_address())?
                .checked_add(Size4KiB::SIZE)?;
            if after > IOREMAP.end {
                return None;
            }
            *next = after;
            start
        };
        let page = Page::from_start_address(VirtAddr::new(start)).ok()?;
        // Safety: device registers (the caller's contract), not RAM (checked),
        // in a part of `IOREMAP` only this mapping gets.
        unsafe {
            self.page_table_manager
                .base_page_table
                .map_kernel_mmio(page, PhysFrame::range(first, last))
        }
        .ok()?;
        let va = page.start_address() + (pa - first.start_address().as_u64());
        // Safety: mapped uncacheable above, for the kernel's lifetime.
        Some(unsafe { Mmio::new(NonNull::new(va.as_mut_ptr())?, len) })
    }
}
