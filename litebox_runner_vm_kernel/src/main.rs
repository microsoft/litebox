// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU guest kernel: a [service](service::Service) in ring-3 runner
//! processes, and a [client](client) for it. Today: OP-TEE TAs in
//! `litebox_runner_optee_on_vm_userland` processes, one per TA instance
//! ([`service::optee`]),
//! driven by a test client ([`client::script`]). QEMU exits with 33 if all
//! tests pass, 65 otherwise. Runner processes' standard streams are a virtio
//! console, if there is one ([`devices`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod client;
mod devices;
mod payload;
mod service;

use core::panic::PanicInfo;
use litebox_bootloader::Kernel;
use litebox_hal::{console, console_println, power};
use litebox_platform_vm_kernel::providers::set_platform_root_key;

litebox_bootloader::entry!(kernel_main, &SerialLogger);

fn kernel_main(kernel: Kernel) -> ! {
    set_platform_root_key(&litebox_hal::prk::development());
    let payload =
        payload::Payload::read(kernel.boot_info).unwrap_or_else(|e| panic!("payload: {e}"));
    let devices = devices::Devices::init(kernel.platform, kernel.tsc_khz);
    let broker = litebox_broker_vm_kernel::Broker::new(litebox_broker_vm_kernel::Config {
        console: devices,
        events: devices,
    });
    let mut service = service::optee::Optee::new(kernel.platform, kernel.tsc_khz, &payload, broker);
    client::script::run(&payload, &mut service);
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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    console::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    power::exit(false)
}
