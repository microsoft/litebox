// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VM-wide diagnostic routing, available before per-CPU/kernel objects exist.
//!
//! The runner installs a writer after final relocation and before calling code
//! that emits shared diagnostics. Routing allocates nothing and holds no lock
//! while invoking the writer. UART selection and any additional sinks belong
//! to the platform/runner, not to this module. This is not guest stdio.

use core::fmt;
use spin::Once;

/// A diagnostic writer has already been installed; it cannot be replaced.
#[derive(Debug, PartialEq, Eq)]
pub struct AlreadyInstalled;

struct Console {
    writer: Once<fn(fmt::Arguments<'_>)>,
}

impl Console {
    const fn new() -> Self {
        Self {
            writer: Once::new(),
        }
    }

    fn install(&self, writer: fn(fmt::Arguments<'_>)) -> Result<(), AlreadyInstalled> {
        let mut installed_here = false;
        self.writer.call_once(|| {
            installed_here = true;
            writer
        });
        if installed_here {
            Ok(())
        } else {
            Err(AlreadyInstalled)
        }
    }

    fn print(&self, args: fmt::Arguments<'_>) {
        let writer = self
            .writer
            .get()
            .expect("console not installed by the runner");
        writer(args);
    }
}

static CONSOLE: Console = Console::new();

/// Install the VM's diagnostic writer once, before starting APs or shared
/// kernel initialization. The writer may subsequently be called concurrently.
/// It owns sink locking and must not recursively call the shared print path.
///
/// Call only after final relocation: this stores a runtime function pointer,
/// which later ELF relocation passes would not update. A runner's early panic
/// handler must use its platform's early-output path directly, not this router.
pub fn install(writer: fn(fmt::Arguments<'_>)) -> Result<(), AlreadyInstalled> {
    CONSOLE.install(writer)
}

/// Write shared diagnostics through the runner-selected writer.
///
/// # Panics
/// Panics if no writer has been installed. There is no implicit hardware probe
/// or silent default sink; the runner must make its diagnostic policy explicit.
#[doc(hidden)]
pub fn print(args: fmt::Arguments<'_>) {
    CONSOLE.print(args);
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::console::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! debug_serial_print {
    ($($arg:tt)*) => (#[cfg(debug_assertions)] $crate::console::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! debug_serial_println {
    () => (#[cfg(debug_assertions)] $crate::serial_print!("\n"));
    ($($arg:tt)*) => (#[cfg(debug_assertions)] $crate::serial_print!("{}\n", format_args!($($arg)*)));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{format, string::String, vec::Vec};
    use core::cell::RefCell;
    use std::sync::Barrier;

    std::thread_local! {
        static OUTPUT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn first(args: fmt::Arguments<'_>) {
        OUTPUT.with_borrow_mut(|output| output.push(format!("first:{args}")));
    }

    fn second(args: fmt::Arguments<'_>) {
        OUTPUT.with_borrow_mut(|output| output.push(format!("second:{args}")));
    }

    #[test]
    #[should_panic(expected = "console not installed by the runner")]
    fn missing_writer_is_an_explicit_setup_error() {
        Console::new().print(format_args!("no hardware should be probed"));
    }

    #[test]
    fn install_does_not_emit_and_print_preserves_borrowed_formatting() {
        OUTPUT.with_borrow_mut(Vec::clear);
        let console = Console::new();
        assert_eq!(console.install(first), Ok(()));
        OUTPUT.with_borrow(|output| assert!(output.is_empty()));
        let value = String::from("borrowed");
        console.print(format_args!("{value} {}\n", 7));
        OUTPUT.with_borrow(|output| assert_eq!(output.as_slice(), ["first:borrowed 7\n"]));
    }

    #[test]
    fn repeated_installation_cannot_replace_the_writer() {
        OUTPUT.with_borrow_mut(Vec::clear);
        let console = Console::new();
        assert_eq!(console.install(first), Ok(()));
        assert_eq!(console.install(second), Err(AlreadyInstalled));
        assert_eq!(console.install(first), Err(AlreadyInstalled));
        console.print(format_args!("still selected"));
        OUTPUT.with_borrow(|output| assert_eq!(output.as_slice(), ["first:still selected"]));
    }

    #[test]
    fn public_macros_use_the_installed_writer_and_preserve_debug_gating() {
        // This is the only test using the VM-wide slot; other routing tests use
        // independent Console values. Output is per-thread, so concurrent tests
        // cannot pollute this capture even if they emit diagnostics.
        OUTPUT.with_borrow_mut(Vec::clear);
        super::install(first).unwrap();
        crate::serial_print!("raw {}", 7);
        crate::serial_println!("line {}", "value");
        crate::serial_println!();
        let evaluations = core::cell::Cell::new(0);
        crate::debug_serial_print!("{}", {
            evaluations.set(evaluations.get() + 1);
            "debug"
        });
        crate::debug_serial_println!("line");
        crate::debug_serial_println!();
        #[cfg(debug_assertions)]
        {
            assert_eq!(evaluations.get(), 1);
            OUTPUT.with_borrow(|output| {
                assert_eq!(
                    output.as_slice(),
                    [
                        "first:raw 7",
                        "first:line value\n",
                        "first:\n",
                        "first:debug",
                        "first:line\n",
                        "first:\n",
                    ]
                );
            });
        }
        #[cfg(not(debug_assertions))]
        {
            assert_eq!(evaluations.get(), 0);
            OUTPUT.with_borrow(|output| {
                assert_eq!(
                    output.as_slice(),
                    ["first:raw 7", "first:line value\n", "first:\n",]
                );
            });
        }
    }

    #[test]
    fn concurrent_installation_has_exactly_one_winner() {
        OUTPUT.with_borrow_mut(Vec::clear);
        let console = Console::new();
        let barrier = Barrier::new(2);
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                console.install(first)
            });
            let b = scope.spawn(|| {
                barrier.wait();
                console.install(second)
            });
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_ne!(a.is_ok(), b.is_ok());
        console.print(format_args!("published"));
        let expected = if a.is_ok() {
            "first:published"
        } else {
            "second:published"
        };
        OUTPUT.with_borrow(|output| assert_eq!(output.as_slice(), [expected]));
    }
}
