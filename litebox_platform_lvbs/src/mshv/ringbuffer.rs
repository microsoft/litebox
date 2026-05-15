// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use crate::Vtl0PhysMutPtr;
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
    // True iff `rb_pa` is page-aligned and `size` is a non-zero page multiple.
    // The fast path collapses wraparound into a single map/unmap by passing the
    // wrap span as a non-contiguous page list; pages themselves are derived from
    // `rb_pa + idx * PAGE_SIZE` since the ring is physically contiguous.
    page_aligned: bool,
}

impl RingBuffer {
    pub fn new(phys_addr: PhysAddr, requested_size: usize) -> Self {
        let pa: usize = phys_addr.as_u64().trunc();
        let page_aligned = requested_size > 0
            && requested_size.is_multiple_of(PAGE_SIZE)
            && pa.is_multiple_of(PAGE_SIZE);
        RingBuffer {
            rb_pa: phys_addr,
            write_offset: 0,
            size: requested_size,
            page_aligned,
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        if self.size == 0 || buf.is_empty() {
            return;
        }
        self.write_offset = if self.page_aligned {
            write_fast(self.rb_pa, self.size, self.write_offset, buf)
        } else {
            write_slow(self.rb_pa, self.size, self.write_offset, buf)
        };
    }
}

/// Fast path for a page-aligned, page-sized ring buffer. Wraparound becomes a
/// single virtually-contiguous, physically non-contiguous mapping by emitting
/// the wrap span as `[rb_pa + (start_page + i) % page_count * PAGE_SIZE]`.
/// Returns the new write offset (unchanged on failure).
fn write_fast(rb_pa: PhysAddr, size: usize, write_offset: usize, buf: &[u8]) -> usize {
    // If `buf` would force the start page into the span twice, vmap rejects the
    // duplicate. Hand off to the two-write slow path before truncating `buf`.
    if buf.len() < size && write_offset % PAGE_SIZE + buf.len() > size {
        return write_slow(rb_pa, size, write_offset, buf);
    }

    // Inputs longer than the buffer overwrite the whole ring with the trailing bytes.
    let (buf, start) = if buf.len() >= size {
        (&buf[(buf.len() - size)..], 0)
    } else {
        (buf, write_offset)
    };

    let rb_pa: usize = rb_pa.as_u64().trunc();
    let page_count = size / PAGE_SIZE;
    let start_page = start / PAGE_SIZE;
    let in_page_offset = start % PAGE_SIZE;
    let span_pages = (in_page_offset + buf.len()).div_ceil(PAGE_SIZE);
    let mut span = alloc::vec::Vec::with_capacity(span_pages);
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

    let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::new(&span, in_page_offset) else {
        return write_offset;
    };
    if unsafe { ptr.write_slice_at_offset(0, buf) }.is_ok() {
        (start + buf.len()) % size
    } else {
        write_offset
    }
}

/// Slow path used when `rb_pa` or `size` is not page-aligned/page-multiple.
/// Wraparound issues two map/unmap cycles; the returned offset advances by
/// bytes actually written so a mid-sequence failure does not strand stale data.
fn write_slow(rb_pa: PhysAddr, size: usize, write_offset: usize, buf: &[u8]) -> usize {
    let write_slice = |pa: PhysAddr, slice: &[u8]| -> bool {
        Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(pa.as_u64().trunc(), slice.len())
            .and_then(|mut ptr| unsafe { ptr.write_slice_at_offset(0, slice) })
            .is_ok()
    };

    if buf.len() >= size {
        let single_slice = &buf[(buf.len() - size)..];
        return if write_slice(rb_pa, single_slice) {
            0
        } else {
            write_offset
        };
    }

    let space_remaining = size - write_offset;
    if buf.len() > space_remaining {
        let first_slice = &buf[..space_remaining];
        let wraparound_slice = &buf[space_remaining..];
        if !write_slice(rb_pa + write_offset as u64, first_slice) {
            return write_offset;
        }
        if !write_slice(rb_pa, wraparound_slice) {
            return 0;
        }
        wraparound_slice.len()
    } else if write_slice(rb_pa + write_offset as u64, buf) {
        (write_offset + buf.len()) % size
    } else {
        write_offset
    }
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
