// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use super::PrivilegedVtl0PhysMutPtr;
use core::fmt;
use litebox::mm::linux::PAGE_SIZE;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmap::PhysPageAddr;
use spin::{Mutex, Once};
use x86_64::PhysAddr;

pub struct RingBuffer {
    rb_pa: PhysAddr,
    write_offset: usize,
    size: usize,
    // True iff `rb_pa` is page-aligned and `size` is a non-zero page multiple,
    // i.e. wraparound can be collapsed into a single non-contiguous mapping.
    // Pages themselves are derived from `rb_pa + idx * PAGE_SIZE` since the ring
    // is physically contiguous.
    fast_path_eligible: bool,
}

impl RingBuffer {
    pub fn new(phys_addr: PhysAddr, requested_size: usize) -> Self {
        let pa: usize = phys_addr.as_u64().trunc();
        let fast_path_eligible = requested_size > 0
            && requested_size.is_multiple_of(PAGE_SIZE)
            && pa.is_multiple_of(PAGE_SIZE);
        RingBuffer {
            rb_pa: phys_addr,
            write_offset: 0,
            size: requested_size,
            fast_path_eligible,
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        if self.size == 0 || buf.is_empty() {
            return;
        }
        self.write_offset = if self.fast_path_eligible {
            write_fast(self.rb_pa, self.size, self.write_offset, buf)
        } else {
            write_slow(self.rb_pa, self.size, self.write_offset, buf)
        };
    }
}

#[inline]
fn advance_offset(size: usize, write_offset: usize, len: usize) -> usize {
    if len >= size {
        0
    } else {
        (write_offset + len) % size
    }
}

/// Fast path for a page-aligned, page-sized ring buffer. Wraparound becomes a
/// single virtually-contiguous, physically non-contiguous mapping by emitting
/// the wrap span as `[rb_pa + (start_page + i) % page_count * PAGE_SIZE]`.
/// Returns the new write offset after attempting the write.
fn write_fast(rb_pa: PhysAddr, size: usize, write_offset: usize, buf: &[u8]) -> usize {
    const MAX_SPAN_PAGES: usize = 16;

    // Inputs longer than the buffer overwrite the whole ring with the trailing bytes.
    let (buf, start) = if buf.len() >= size {
        (&buf[(buf.len() - size)..], 0)
    } else {
        (buf, write_offset)
    };

    let page_count = size / PAGE_SIZE;
    let start_page = start / PAGE_SIZE;
    let in_page_offset = start % PAGE_SIZE;
    let span_pages = (in_page_offset + buf.len()).div_ceil(PAGE_SIZE);
    // `span_pages > page_count`: the wrap *revisits* the start page, so the span
    //   would map the same physical page twice and vmap rejects the duplicate.
    // `span_pages > MAX_SPAN_PAGES`: the span is too long for `span` below.
    if span_pages > page_count || span_pages > MAX_SPAN_PAGES {
        return write_slow(rb_pa, size, write_offset, buf);
    }
    let rb_pa: usize = rb_pa.as_u64().trunc();
    let mut span: arrayvec::ArrayVec<PhysPageAddr<PAGE_SIZE>, MAX_SPAN_PAGES> =
        arrayvec::ArrayVec::new();
    for i in 0..span_pages {
        let page_idx = (start_page + i) % page_count;
        let Some(addr) = page_idx
            .checked_mul(PAGE_SIZE)
            .and_then(|off| rb_pa.checked_add(off))
            .and_then(PhysPageAddr::<PAGE_SIZE>::new)
        else {
            return write_offset;
        };
        span.push(addr);
    }

    let Ok(ptr) = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::new(&span, in_page_offset) else {
        return advance_offset(size, write_offset, buf.len());
    };
    let _ = ptr.write_slice_at_offset(0, buf);
    advance_offset(size, write_offset, buf.len())
}

/// Slow path used when `rb_pa` or `size` is not page-aligned/page-multiple.
/// Wraparound issues two map/unmap cycles. Returns the new write offset
/// after attempting the write.
fn write_slow(rb_pa: PhysAddr, size: usize, write_offset: usize, buf: &[u8]) -> usize {
    let write_slice = |pa: PhysAddr, slice: &[u8]| -> bool {
        PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
            pa.as_u64().trunc(),
            slice.len(),
        )
        .and_then(|ptr| ptr.write_slice_at_offset(0, slice))
        .is_ok()
    };

    if buf.len() >= size {
        let single_slice = &buf[(buf.len() - size)..];
        let _ = write_slice(rb_pa, single_slice);
        return advance_offset(size, write_offset, buf.len());
    }

    let space_remaining = size - write_offset;
    if buf.len() > space_remaining {
        let first_slice = &buf[..space_remaining];
        let wraparound_slice = &buf[space_remaining..];
        let _ = write_slice(rb_pa + write_offset as u64, first_slice);
        let _ = write_slice(rb_pa, wraparound_slice);
    } else {
        let _ = write_slice(rb_pa + write_offset as u64, buf);
    }
    advance_offset(size, write_offset, buf.len())
}

static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();
pub(crate) fn set_ringbuffer(pa: PhysAddr, size: usize) -> &'static Mutex<RingBuffer> {
    RINGBUFFER_ONCE.call_once(|| {
        let ring_buffer = RingBuffer::new(pa, size);
        Mutex::new(ring_buffer)
    })
}

pub(crate) fn ringbuffer() -> Option<&'static Mutex<RingBuffer>> {
    RINGBUFFER_ONCE.get()
}

impl fmt::Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}
