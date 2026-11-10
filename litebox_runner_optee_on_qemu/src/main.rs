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
use litebox_hal::{power, serial, serial_println};
use litebox_platform_vm_kernel::providers::set_platform_root_key;

litebox_bootloader::entry!(kernel_main, &SERIAL_LOGGER);

fn kernel_main(kernel: Kernel) -> ! {
    set_platform_root_key(&litebox_hal::prk::development());
    tests::check_user_memory_protection(kernel.platform);

    optee::run(kernel.platform, kernel.boot_info);
    serial_println!("[litebox] ALL TESTS PASSED");
    power::exit(true)
}

struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        serial::print_str(&buf);
    }

    fn flush(&self) {}
}

static SERIAL_LOGGER: SerialLogger = SerialLogger;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    power::exit(false)
}
