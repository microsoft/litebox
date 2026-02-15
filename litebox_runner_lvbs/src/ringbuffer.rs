// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation backed by VTL0 physical memory.
//!
//! Migrated from `litebox_platform_lvbs::mshv::ringbuffer`.
//! Uses `NormalWorldMutPtr` instead of `platform_low().copy_slice_to_vtl0_phys()`.

use core::fmt;
use litebox::utils::TruncateExt;
use litebox_common_lvbs::PAGE_SIZE;
use litebox_shim_optee::NormalWorldMutPtr;
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

    fn copy_slice_to_vtl0(pa: PhysAddr, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        // Best-effort write; ignore errors (matches original behavior).
        let _ = unsafe {
            NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                pa.as_u64().truncate(),
                buf.len(),
            )
            .and_then(|mut ptr| ptr.write_slice_at_offset(0, buf))
        };
    }

    pub fn write(&mut self, buf: &[u8]) {
        // If the input buffer is longer than the ring buffer, fill the whole ring buffer with
        // the final [ring buffer size] values from the input buffer
        if buf.len() >= self.size {
            let single_slice = &buf[(buf.len() - self.size)..];
            Self::copy_slice_to_vtl0(self.rb_pa, single_slice);
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let first_slice = &buf[..space_remaining];
            let wraparound_slice = &buf[space_remaining..];
            Self::copy_slice_to_vtl0(self.rb_pa + self.write_offset as u64, first_slice);
            Self::copy_slice_to_vtl0(self.rb_pa, wraparound_slice);
        } else {
            Self::copy_slice_to_vtl0(self.rb_pa + self.write_offset as u64, buf);
        }
        self.write_offset = (self.write_offset + buf.len()) % self.size;
    }
}

impl fmt::Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();

pub fn set_ringbuffer(pa: PhysAddr, size: usize) -> &'static Mutex<RingBuffer> {
    RINGBUFFER_ONCE.call_once(|| {
        let ring_buffer = RingBuffer::new(pa, size);
        Mutex::new(ring_buffer)
    })
}

fn ringbuffer() -> Option<&'static Mutex<RingBuffer>> {
    RINGBUFFER_ONCE.get()
}

/// Print hook function registered with `ioport::register_print_hook`.
/// Called by platform's `print()` to mirror output to the ring buffer.
pub fn print_to_ringbuffer(args: fmt::Arguments) {
    if let Some(rb) = ringbuffer() {
        use fmt::Write;
        let _ = rb.lock().write_fmt(args);
    }
}
