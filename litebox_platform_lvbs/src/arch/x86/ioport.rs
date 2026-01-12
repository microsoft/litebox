// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! I/O Port-based serial communication

use core::{arch::asm, fmt};
use spin::{Mutex, Once};

//ringbuffer imports
extern crate alloc;
use crate::mshv::vsm::{get_ringbuffer_phys_addr, get_ringbuffer_size, is_ringbuffer_allocated};
use alloc::{boxed::Box, slice};
use x86_64::structures::paging::PageTableFlags;

// LVBS uses COM PORT 2 for printing out debug messages
const COM_PORT_2: u16 = 0x2F8;

const INTERRUPT_ENABLE_OFFSET: u16 = 1;
const OUT_FIFO_CONTROL_OFFSET: u16 = 2;
const SCRATCH_REGISTER_OFFSET: u16 = 7;
const MODEM_CONTROL_OFFSET: u16 = 4;
const IN_LINE_STATUS_OFFSET: u16 = 5;

const MAX_WAIT_ITERATIONS: u32 = 1_000_000;

#[expect(clippy::inline_always)]
#[inline(always)]
fn inb(port: u16) -> u8 {
    let mut value: u8;

    unsafe {
        asm!(
            "in al, dx",
            in("dx") port, out("al") value
        );
    }

    value
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn outb(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port, in("al") value
        );
    }
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn interrupt_enable(port: u16, value: u8) {
    outb(port + INTERRUPT_ENABLE_OFFSET, value);
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn fifo_control(port: u16, value: u8) {
    outb(port + OUT_FIFO_CONTROL_OFFSET, value);
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn modem_control(port: u16, value: u8) {
    outb(port + MODEM_CONTROL_OFFSET, value);
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn line_status(port: u16) -> u8 {
    inb(port + IN_LINE_STATUS_OFFSET)
}

pub struct RingBuffer {
    data: Box<[u8]>,
    head_lpos: usize,
}

impl RingBuffer {
    /// Create a new RingBuffer mapped to the given physical address and size
    ///
    /// # Panics
    ///
    /// Panics if the mapped size is less than the requested size
    pub fn new(phys_addr: x86_64::PhysAddr, size: usize) -> Self {
        let platform = crate::platform_low();

        // Map the physical memory to virtual space
        let core::prelude::v1::Ok((virt_ptr, mapped_size)) = platform.map_vtl0_phys_range(
            phys_addr,
            phys_addr + size as u64,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        ) else {
            todo!()
        };

        // Ensure we have enough space
        assert!(mapped_size >= size);

        // Create slice from mapped memory
        let slice = unsafe { slice::from_raw_parts_mut(virt_ptr, size) };
        slice.fill(0);

        // Convert to boxed slice
        let data = unsafe { Box::from_raw(slice) };

        Self { data, head_lpos: 0 }
    }

    // #[inline]
    pub fn size(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn mask(&self) -> usize {
        self.size() - 1
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        let mut written = 0;
        while written < buf.len() {
            let index = self.head_lpos & self.mask();
            self.data[index] = buf[written];
            self.head_lpos += 1;
            written += 1;
        }

        written
    }
}

pub struct ComPort {
    port: u16,
    available: bool,
}

impl ComPort {
    pub const fn new(port: u16) -> Self {
        ComPort {
            port,
            available: false,
        }
    }

    pub fn init(&mut self) {
        outb(self.port + SCRATCH_REGISTER_OFFSET, 0x55);
        let scratch = inb(self.port + SCRATCH_REGISTER_OFFSET);
        if scratch != 0x55 {
            self.available = false;
            return;
        }
        self.available = true;
        interrupt_enable(self.port, 0x00); // Disable all interrupts
        fifo_control(self.port, 0xc7); // Enable FIFO, clear them, with 14-byte threshold
        modem_control(self.port, 0x0f); // Enable data terminal ready, request to send, and IRQ
    }

    pub fn write_byte(&mut self, byte: u8) {
        if !self.available {
            return;
        }

        /* Timeout to ensure that we do not loop indefinitely */
        let mut wait_iterations = 0;
        loop {
            if line_status(self.port) & 0x20 != 0 {
                // transmittable
                break;
            }
            wait_iterations += 1;
            if wait_iterations >= MAX_WAIT_ITERATIONS {
                return;
            }
        }

        match byte {
            0x20..=0x7e => outb(self.port, byte),
            b'\n' => {
                outb(self.port, b'\r');
                outb(self.port, b'\n');
            }
            _ => outb(self.port, 0xfe),
        }
    }

    pub fn write_string(&mut self, s: &str) {
        if !self.available {
            return;
        }

        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}

fn com() -> &'static Mutex<ComPort> {
    static COM_ONCE: Once<Mutex<ComPort>> = Once::new();
    COM_ONCE.call_once(|| {
        let mut com_port = ComPort::new(COM_PORT_2);
        com_port.init();
        Mutex::new(com_port)
    })
}

fn ringbuffer() -> &'static Mutex<RingBuffer> {
    static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();
    RINGBUFFER_ONCE.call_once(|| {
        let ring_buffer = RingBuffer::new(
            get_ringbuffer_phys_addr().unwrap(),
            get_ringbuffer_size().unwrap(),
        );
        Mutex::new(ring_buffer)
    })
}

impl fmt::Write for ComPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

impl fmt::Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

#[doc(hidden)]
pub fn print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = com().lock().write_fmt(args);
    if is_ringbuffer_allocated() {
        let _ring_buffer = ringbuffer().lock().write_fmt(args);
    }
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::arch::ioport::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! debug_serial_print {
    ($($arg:tt)*) => (#[cfg(debug_assertions)] $crate::arch::ioport::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! debug_serial_println {
    () => (#[cfg(debug_assertions)] $crate::serial_print!("\n"));
    ($($arg:tt)*) => (#[cfg(debug_assertions)] $crate::serial_print!("{}\n", format_args!($($arg)*)));
}

pub fn serial_print_string(s: &str) {
    com().lock().write_string(s);
}
