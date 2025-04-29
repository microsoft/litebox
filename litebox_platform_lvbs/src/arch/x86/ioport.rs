//! I/O Port-based serial communication

use core::{arch::asm, fmt};
use spin::{Mutex, Once};

// LVBS uses COM PORT 2 for printing out debug messages
const COM_PORT_2: u16 = 0x2F8;

// const DATA_OFFSET: u16 = 0;
const INTERRUPT_ENABLE_OFFSET: u16 = 1;
// const IN_INTERRUPT_IDENTIFICATION_OFFSET: u16 = 2;
const OUT_FIFO_CONTROL_OFFSET: u16 = 2;
// const LINE_CONTROL_OFFSET: u16 = 3;
const MODEM_CONTROL_OFFSET: u16 = 4;
const IN_LINE_STATUS_OFFSET: u16 = 5;
// const IN_MODEM_STATUS_OFFSET: u16 = 6;
// const SCRATCH_OFFSET: u16 = 7;

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
}

impl ComPort {
    pub const fn new(port: u16) -> Self {
        ComPort { port }
    }

    pub fn init(&mut self) {
        interrupt_enable(self.port, 0x00); // Disable all interrupts
        fifo_control(self.port, 0xc7); // Enable FIFO, clear them, with 14-byte threshold
        modem_control(self.port, 0x0f); // Enable data terminal ready, request to send, and IRQ
    }

    pub fn write_byte(&mut self, byte: u8) {
        loop {
            if (line_status(self.port) & 0x20) != 0 {
                // transmittable
                break;
            }
        }

        match byte {
            0x20..=0x7e => outb(self.port, byte),
            b'\n' => self.new_line(),
            _ => outb(self.port, 0xfe),
        }
    }

    fn new_line(&mut self) {
        loop {
            if (line_status(self.port) & 0x20) != 0 {
                // transmittable
                break;
            }
        }
        outb(self.port, b'\r');
        outb(self.port, b'\n');
    }

    pub fn write_string(&mut self, s: &str) {
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

#[doc(hidden)]
pub fn print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = com().lock().write_fmt(args);
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

pub fn serial_print_string(s: &str) {
    com().lock().write_string(s);
}
