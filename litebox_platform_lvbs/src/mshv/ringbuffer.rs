// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use crate::Vtl0PhysMutPtr;
use alloc::vec::Vec;
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
        // If the input buffer is longer than the ring buffer, fill the whole ring buffer with
        // the final [ring buffer size] values from the input buffer
        if buf.len() >= self.size {
            let single_slice = &buf[(buf.len() - self.size)..];
            if let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                self.rb_pa.as_u64().truncate(),
                single_slice.len(),
            ) {
                let _ = unsafe { ptr.write_slice_at_offset(0, single_slice) };
            }
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let write_pa = self.rb_pa + self.write_offset as u64;
            let write_start = write_pa.align_down(PAGE_SIZE as u64);
            let write_end = (write_pa + space_remaining as u64).align_up(PAGE_SIZE as u64);
            let wraparound_end =
                (self.rb_pa + (buf.len() - space_remaining) as u64).align_up(PAGE_SIZE as u64);
            let tail_page_count: usize = ((write_end - write_start) / PAGE_SIZE as u64).truncate();
            let wraparound_page_count: usize =
                ((wraparound_end - self.rb_pa.align_down(PAGE_SIZE as u64)) / PAGE_SIZE as u64)
                    .truncate();
            let mut pages = Vec::with_capacity(tail_page_count + wraparound_page_count);
            let mut cur_page = write_start;
            while cur_page < write_end {
                if let Some(page) = PhysPageAddr::<PAGE_SIZE>::new(cur_page.as_u64().truncate()) {
                    pages.push(page);
                }
                cur_page += PAGE_SIZE as u64;
            }
            cur_page = self.rb_pa.align_down(PAGE_SIZE as u64);
            while cur_page < wraparound_end {
                if let Some(page) = PhysPageAddr::<PAGE_SIZE>::new(cur_page.as_u64().truncate()) {
                    pages.push(page);
                }
                cur_page += PAGE_SIZE as u64;
            }
            if let Ok(mut ptr) =
                Vtl0PhysMutPtr::<u8, PAGE_SIZE>::new(&pages, (write_pa - write_start).truncate())
            {
                let _ = unsafe { ptr.write_slice_at_offset(0, buf) };
            }
        } else if let Ok(mut ptr) = Vtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
            (self.rb_pa + self.write_offset as u64).as_u64().truncate(),
            buf.len(),
        ) {
            let _ = unsafe { ptr.write_slice_at_offset(0, buf) };
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
