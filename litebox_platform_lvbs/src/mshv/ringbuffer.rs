// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use core::fmt;
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
            unsafe {
                crate::platform_low().copy_slice_to_vtl0_phys(self.rb_pa, single_slice);
            }
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let first_slice = &buf[..space_remaining];
            let wraparound_slice = &buf[space_remaining..];
            unsafe {
                crate::platform_low()
                    .copy_slice_to_vtl0_phys(self.rb_pa + self.write_offset as u64, first_slice);
                crate::platform_low().copy_slice_to_vtl0_phys(self.rb_pa, wraparound_slice);
            }
        } else {
            unsafe {
                crate::platform_low()
                    .copy_slice_to_vtl0_phys(self.rb_pa + self.write_offset as u64, buf);
            }
        }
        self.write_offset = (self.write_offset + buf.len()) % self.size;
    }
}

static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();
pub fn set_ringbuffer(pa: PhysAddr, size: usize) -> &'static Mutex<RingBuffer> {
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
