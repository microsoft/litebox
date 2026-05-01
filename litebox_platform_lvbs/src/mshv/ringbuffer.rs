// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use crate::Vtl0PhysMutPtr;
use core::fmt;
use litebox::mm::linux::PAGE_SIZE;
use litebox::utils::TruncateExt;
use spin::{Mutex, Once};
use x86_64::PhysAddr;

pub struct RingBuffer {
    rb_pa: PhysAddr,
    write_offset: usize,
    // TODO: If ring buffers are constrained to page-sized/page-aligned ranges,
    // wraparound writes can be optimized into a single non-contiguous mapping.
    size: usize,
}

impl RingBuffer {
    pub fn new(phys_addr: PhysAddr, requested_size: usize) -> Self {
        RingBuffer {
            rb_pa: phys_addr,
            write_offset: 0,
            size: requested_size,
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        if self.size == 0 || buf.is_empty() {
            return;
        }

        // If the input buffer is longer than the ring buffer, fill the whole ring buffer with
        // the final [ring buffer size] values from the input buffer
        if buf.len() >= self.size {
            let single_slice = &buf[(buf.len() - self.size)..];
            let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                self.rb_pa.as_u64().truncate(),
                single_slice.len(),
            ) else {
                return;
            };
            if unsafe { ptr.write_slice_at_offset(0, single_slice) }.is_err() {
                return;
            }
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let first_slice = &buf[..space_remaining];
            let wraparound_slice = &buf[space_remaining..];
            let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                (self.rb_pa + self.write_offset as u64).as_u64().truncate(),
                first_slice.len(),
            ) else {
                return;
            };
            if unsafe { ptr.write_slice_at_offset(0, first_slice) }.is_err() {
                return;
            }

            let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                self.rb_pa.as_u64().truncate(),
                wraparound_slice.len(),
            ) else {
                return;
            };
            if unsafe { ptr.write_slice_at_offset(0, wraparound_slice) }.is_err() {
                return;
            }
        } else {
            let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                (self.rb_pa + self.write_offset as u64).as_u64().truncate(),
                buf.len(),
            ) else {
                return;
            };
            if unsafe { ptr.write_slice_at_offset(0, buf) }.is_err() {
                return;
            }
        }
        self.write_offset = (self.write_offset + buf.len()) % self.size;
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
