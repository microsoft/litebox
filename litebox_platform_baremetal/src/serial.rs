//! Serial port driver for COM1 (0x3F8)
//! Used for debug output and stdout/stderr

use spin::Once;
use uart_16550::SerialPort;

static SERIAL1: Once<spin::Mutex<SerialPort>> = Once::new();

/// Initialize the serial port
pub fn init() {
    SERIAL1.call_once(|| {
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };
        serial_port.init();
        spin::Mutex::new(serial_port)
    });
}

/// Write a string to the serial port
pub fn write_str(s: &str) {
    if let Some(serial) = SERIAL1.get() {
        let mut serial = serial.lock();
        for byte in s.bytes() {
            serial.send(byte);
        }
    }
}

/// Write bytes to the serial port
pub fn write_bytes(bytes: &[u8]) {
    if let Some(serial) = SERIAL1.get() {
        let mut serial = serial.lock();
        for &byte in bytes {
            serial.send(byte);
        }
    }
}

/// Macro for printing to serial port (like println!)
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Macro for printing to serial port with newline
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    if let Some(serial) = SERIAL1.get() {
        let mut serial = serial.lock();
        serial.write_fmt(args).ok();
    }
}
