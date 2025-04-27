use core::{arch::asm, fmt};
use spin::{Mutex, Once};
// use lazy_static::lazy_static;

// LVBS uses COM PORT 2 for printing out debug messages
const COM_PORT_2: u16 = 0x2F8;

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

pub struct ComPort {
    port: u16,
}

impl ComPort {
    pub const fn new(port: u16) -> Self {
        ComPort { port }
    }

    pub fn init(&mut self) {
        outb(self.port + 1, 0x00); // Disable all interrupts
        outb(self.port + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold
        outb(self.port + 4, 0x0F);
    }

    pub fn write_byte(&mut self, byte: u8) {
        loop {
            if (inb(self.port + 5) & 0x20) != 0 {
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
            if (inb(self.port + 5) & 0x20) != 0 {
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

// lazy_static! {
//     pub static ref COM: Mutex<ComPort> = {
//         let mut com_port = ComPort::new(COM_PORT_2);
//         com_port.init();

//         Mutex::new(com_port)
//     };
// }

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
    // let _ = COM.lock().write_fmt(args);
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
    // COM.lock().write_string(s);
}
