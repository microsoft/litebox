// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs OP-TEE TAs with LiteBox as the guest kernel of a QEMU VM. Exits QEMU
//! with status 33 if all tests pass and 65 otherwise (see
//! [`litebox_hal::power::exit`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod broker;
mod optee;
mod tests;

use core::panic::PanicInfo;
use litebox_bootloader::Kernel;
use litebox_hal::{console, console_println, power};
use litebox_platform_vm_kernel::providers::set_platform_root_key;

litebox_bootloader::entry!(kernel_main, &SERIAL_LOGGER);

fn kernel_main(kernel: Kernel) -> ! {
    set_platform_root_key(&litebox_hal::prk::development());
    tests::check_user_memory_protection(kernel.platform);

    optee::run(kernel.platform, kernel.boot_info);
    console_println!("[litebox] ALL TESTS PASSED");
    power::exit(true)
}

struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if is_spurious_tar_error(record) {
            return;
        }
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        console::print_str(&buf);
    }

    fn flush(&self) {}
}

/// `tar-no-std` logs this error for the end-of-archive block of every valid
/// archive.
fn is_spurious_tar_error(record: &log::Record) -> bool {
    use core::fmt::Write as _;
    const SPURIOUS: &str = "Unparsable size (ParseIntError { kind: Empty })";
    if record.level() != log::Level::Error || !record.target().starts_with("tar_no_std") {
        return false;
    }
    // Only the prefix is needed; truncation is expected.
    let mut msg = arrayvec::ArrayString::<64>::new();
    let _ = write!(msg, "{}", record.args());
    msg.starts_with(SPURIOUS)
}

static SERIAL_LOGGER: SerialLogger = SerialLogger;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    console::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    power::exit(false)
}
