// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Diagnostic formatting with an explicit writer, not a global registry.
//! Writers may be functions or closures borrowing caller-owned state. The
//! macros do not allocate or select hardware, and need no boot registration.

#[macro_export]
macro_rules! serial_print {
    ($writer:expr; $($arg:tt)*) => (($writer)(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    ($writer:expr;) => ($crate::serial_print!($writer; "\n"));
    ($writer:expr; $($arg:tt)*) => ($crate::serial_print!($writer; "{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! debug_serial_print {
    ($writer:expr; $($arg:tt)*) => (#[cfg(debug_assertions)] $crate::serial_print!($writer; $($arg)*));
}

#[macro_export]
macro_rules! debug_serial_println {
    ($writer:expr; $($arg:tt)*) => (#[cfg(debug_assertions)] $crate::serial_println!($writer; $($arg)*));
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use core::{cell::Cell, fmt::Write};

    #[test]
    fn caller_owned_writers_are_independent_and_preserve_formatting() {
        let mut first = String::new();
        let mut second = String::new();
        crate::serial_print!(|args| first.write_fmt(args).unwrap(); "raw {}", 7);
        crate::serial_println!(|args| second.write_fmt(args).unwrap(); "line {}", "value");
        crate::serial_println!(|args| first.write_fmt(args).unwrap(););
        assert_eq!(first, "raw 7\n");
        assert_eq!(second, "line value\n");
    }

    #[test]
    fn debug_gating_skips_both_writer_and_argument_evaluation() {
        let mut output = String::new();
        let writers = Cell::new(0);
        let arguments = Cell::new(0);
        crate::debug_serial_print!({
            writers.set(writers.get() + 1);
            |args| output.write_fmt(args).unwrap()
        }; "{}", { arguments.set(arguments.get() + 1); "debug" });
        crate::debug_serial_println!(|args| output.write_fmt(args).unwrap(); "line");
        crate::debug_serial_println!(|args| output.write_fmt(args).unwrap(););
        #[cfg(debug_assertions)]
        {
            assert_eq!(output, "debugline\n\n");
            assert_eq!(writers.get(), 1);
            assert_eq!(arguments.get(), 1);
        }
        #[cfg(not(debug_assertions))]
        {
            // Keep the mutable binding used even when debug macros disappear.
            output.clear();
            assert!(output.is_empty());
            assert_eq!(writers.get(), 0);
            assert_eq!(arguments.get(), 0);
        }
    }
}
