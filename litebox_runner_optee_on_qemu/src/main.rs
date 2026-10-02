// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs OP-TEE TAs with LiteBox as the guest kernel of a QEMU VM. Exits QEMU
//! with status 33 if all tests pass and 65 otherwise (see
//! [`litebox_bootloader::machine::exit`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod broker;
mod optee;
mod tests;

use core::panic::PanicInfo;
use litebox_bootloader::{Kernel, machine, serial, serial_println};
use litebox_platform_vm_kernel::providers::{PRK_LEN, set_platform_root_key};

litebox_bootloader::entry!(kernel_main, &SERIAL_LOGGER);

fn kernel_main(kernel: Kernel) -> ! {
    install_development_platform_root_key();
    tests::check_user_memory_protection(kernel.platform);

    optee::run(kernel.platform, kernel.boot_info);
    serial_println!("[litebox] ALL TESTS PASSED");
    machine::exit(true)
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
        serial::print_str(&buf);
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
    serial::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    machine::exit(false)
}

/// SHA-256 of "litebox-vm development platform root key v1 -- NOT A SECRET".
const DEV_PRK: [u8; PRK_LEN] = [
    0xb3, 0x09, 0x9d, 0xf9, 0x38, 0x4f, 0xc7, 0x67, 0xb7, 0x38, 0x1c, 0x49, 0xc1, 0x67, 0x13, 0x82,
    0xeb, 0x25, 0x85, 0xaf, 0x85, 0xf0, 0x39, 0xc9, 0xe8, 0x30, 0x4e, 0x4e, 0x04, 0xe1, 0xc8, 0x11,
];

/// No confidentiality: this development PRK is public and identical on every boot.
/// TODO: provision a TPM-backed PRK.
fn install_development_platform_root_key() {
    litebox_util_log::warn!(
        "installing a DEVELOPMENT platform root key with NO SECURITY VALUE; \
         anything sealed with keys derived from it is sealed against nobody"
    );
    set_platform_root_key(&DEV_PRK);
}
