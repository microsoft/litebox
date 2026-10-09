// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Console: a 16550 UART on COM1. Output is dropped if no UART answers.

use core::fmt;
use spin::{Mutex, Once};
use x86_64::instructions::port::{Port, PortReadOnly};

const COM1: u16 = 0x3F8;

const MAX_WAIT_ITERATIONS: u32 = 1_000_000;

struct ComPort {
    data: Port<u8>,
    interrupt_enable: Port<u8>,
    fifo_control: Port<u8>,
    modem_control: Port<u8>,
    line_status: PortReadOnly<u8>,
    scratch: Port<u8>,
    available: bool,
}

impl ComPort {
    const fn new(base: u16) -> Self {
        ComPort {
            data: Port::new(base),
            interrupt_enable: Port::new(base + 1),
            fifo_control: Port::new(base + 2),
            modem_control: Port::new(base + 4),
            line_status: PortReadOnly::new(base + 5),
            scratch: Port::new(base + 7),
            available: false,
        }
    }

    fn init(&mut self) {
        // Safety: the UART belongs to this console, and its registers have no
        // memory side effects. The same holds for every port access below.
        unsafe {
            self.scratch.write(0x55);
            if self.scratch.read() != 0x55 {
                return;
            }
            self.interrupt_enable.write(0x00); // polled, no interrupts
            self.fifo_control.write(0xc7); // enable and clear FIFOs
            self.modem_control.write(0x0f); // DTR, RTS, OUT1, OUT2
        }
        self.available = true;
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.available {
            return;
        }

        // A stuck UART must not block kernel progress.
        let mut wait_iterations = 0;
        // Safety: see `init`.
        while unsafe { self.line_status.read() } & 0x20 == 0 {
            wait_iterations += 1;
            if wait_iterations >= MAX_WAIT_ITERATIONS {
                return;
            }
        }

        // Safety: see `init`.
        unsafe {
            match byte {
                0x20..=0x7e => self.data.write(byte),
                b'\n' => {
                    self.data.write(b'\r');
                    self.data.write(b'\n');
                }
                _ => self.data.write(0xfe), // non-printable
            }
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        if !self.available {
            return;
        }

        for &byte in bytes {
            self.write_byte(byte);
        }
    }

    fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }
}

static COM_ONCE: Once<Mutex<ComPort>> = Once::new();

fn com() -> &'static Mutex<ComPort> {
    COM_ONCE.call_once(|| {
        let mut com_port = ComPort::new(COM1);
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

pub fn print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = com().lock().write_fmt(args);
}

pub fn print_str(s: &str) {
    com().lock().write_string(s);
}

/// Non-printable bytes show as `0xfe`.
pub fn print_bytes(bytes: &[u8]) {
    com().lock().write_bytes(bytes);
}

/// Panic may interrupt a locked or initializing console. Never wait for it
/// or alias its mutable handle; emergency output may interleave.
pub fn panic_print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    if let Some(mut com) = COM_ONCE.get().and_then(Mutex::try_lock) {
        let _ = com.write_fmt(args);
        return;
    }
    // Assume a UART is present: without one, writes go nowhere and the
    // transmit wait is bounded.
    let mut com = ComPort::new(COM1);
    com.available = true;
    let _ = com.write_fmt(args);
}

/// `println!` to the console.
#[macro_export]
macro_rules! console_println {
    () => ($crate::console::print(format_args!("\n")));
    ($($arg:tt)*) => ($crate::console::print(format_args!("{}\n", format_args!($($arg)*))));
}
