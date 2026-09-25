// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS diagnostic policy: serial first, then the optional VTL0 ringbuffer.
//! Ordinary log records remain serial-only. No shared-console registration is
//! needed to use this module directly, including from the early panic handler.

use crate::{arch::ioport::ComPort, mshv::ringbuffer::ringbuffer};
use core::fmt::{self, Write};
use spin::{Mutex, Once};

#[cfg(feature = "devbox")]
const SERIAL_PORT: u16 = 0x2F8;
#[cfg(not(feature = "devbox"))]
const SERIAL_PORT: u16 = 0x3F8;

fn serial() -> &'static Mutex<ComPort> {
    static SERIAL: Once<Mutex<ComPort>> = Once::new();
    SERIAL.call_once(|| {
        let mut port = ComPort::new(SERIAL_PORT);
        port.init();
        Mutex::new(port)
    })
}

/// Write diagnostics to serial and, if installed, the VTL0 ringbuffer.
/// The serial lock is released before looking up or writing the ringbuffer.
/// Formatting errors in either sink remain best-effort, as before.
pub fn print(args: fmt::Arguments<'_>) {
    write_diagnostics(
        args,
        |args| serial().lock().write_fmt(args),
        |args| match ringbuffer() {
            Some(rb) => rb.lock().write_fmt(args),
            None => Ok(()),
        },
    );
}

/// Serial-only output for HostInterface::log and the runner's log backend.
/// Deliberately does not go through the shared diagnostic router or ringbuffer.
pub fn write_serial(message: &str) {
    serial().lock().write_string(message);
}

fn write_diagnostics(
    args: fmt::Arguments<'_>,
    serial: impl FnOnce(fmt::Arguments<'_>) -> fmt::Result,
    mirror: impl FnOnce(fmt::Arguments<'_>) -> fmt::Result,
) {
    let _ = serial(args);
    let _ = mirror(args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String, vec::Vec};
    use core::cell::{Cell, RefCell};

    #[test]
    fn diagnostics_preserve_sink_order_and_formatting() {
        let output = RefCell::new(Vec::new());
        write_diagnostics(
            format_args!("value={}\n", 42),
            |args| {
                output.borrow_mut().push(format!("serial:{args}"));
                Ok(())
            },
            |args| {
                output.borrow_mut().push(format!("ring:{args}"));
                Ok(())
            },
        );
        assert_eq!(*output.borrow(), ["serial:value=42\n", "ring:value=42\n"]);
    }

    #[test]
    fn serial_failure_does_not_suppress_the_mirror() {
        let mirrored = Cell::new(false);
        write_diagnostics(
            format_args!("best effort"),
            |_| Err(fmt::Error),
            |_| {
                mirrored.set(true);
                Ok(())
            },
        );
        assert!(mirrored.get());
    }

    #[test]
    fn serial_guard_is_released_before_mirror_lookup_and_write() {
        let serial = Mutex::new(String::new());
        let mirror = Mutex::new(String::new());
        write_diagnostics(
            format_args!("message"),
            |args| serial.lock().write_fmt(args),
            |args| {
                assert!(
                    serial.try_lock().is_some(),
                    "serial guard spans the mirror write"
                );
                mirror.lock().write_fmt(args)
            },
        );
        assert_eq!(*serial.lock(), "message");
        assert_eq!(*mirror.lock(), "message");
    }

    #[test]
    fn mirror_availability_is_checked_after_serial_on_each_message() {
        let ready = Cell::new(false);
        let output = RefCell::new(String::new());
        for message in ["early", "late"] {
            write_diagnostics(
                format_args!("{message}"),
                |_| {
                    ready.set(message == "late");
                    Ok(())
                },
                |args| {
                    if ready.get() {
                        output.borrow_mut().write_fmt(args)
                    } else {
                        Ok(())
                    }
                },
            );
        }
        assert_eq!(*output.borrow(), "late");
    }
}
