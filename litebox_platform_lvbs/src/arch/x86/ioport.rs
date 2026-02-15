// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! I/O Port-based serial communication

use core::{
    arch::asm,
    fmt,
    sync::atomic::{AtomicPtr, Ordering},
};
use spin::{Mutex, Once};

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

impl fmt::Write for ComPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

/// Function pointer hook for auxiliary print output (e.g., ring buffer).
/// Set by the runner after initializing the ring buffer.
static PRINT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register a print hook function that will be called with every `print()` invocation.
///
/// # Safety
///
/// `hook` must point to a function with signature `fn(fmt::Arguments)` that is safe to call
/// from any context where `print()` is called.
pub unsafe fn register_print_hook(hook: fn(fmt::Arguments)) {
    PRINT_HOOK.store(hook as *mut (), Ordering::Release);
}

#[doc(hidden)]
pub fn print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = com().lock().write_fmt(args);
    let hook = PRINT_HOOK.load(Ordering::Acquire);
    if !hook.is_null() {
        // SAFETY: The caller of `register_print_hook` guarantees the pointer is a valid
        // `fn(fmt::Arguments)`.
        let f: fn(fmt::Arguments) = unsafe { core::mem::transmute(hook) };
        f(args);
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
