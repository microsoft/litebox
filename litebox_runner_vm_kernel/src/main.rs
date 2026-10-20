// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU guest kernel: a [service] in ring-3 runner processes, which the host
//! controls over the kernel's [control channel](control) on the VM's
//! virtio-vsock device; any host process that can connect to the VM's CID
//! may use it (see its
//! [trust model](litebox_common_vm_control#trust-model)). The payload
//! decides the service:
//! - With `ldelf.elf`: OP-TEE TAs in `litebox_runner_optee_on_vm_userland`
//!   processes, one per TA instance ([`service::optee`]).
//! - Otherwise: standalone programs in `runner.elf` processes
//!   ([`service::program`]), e.g., Linux programs in
//!   `litebox_runner_linux_on_vm_userland`.
//!
//! The host shuts the VM down, and says whether QEMU exits with 33 or 65. A
//! VM without a vsock device, or with one the kernel cannot drive, is a
//! panic, and a kernel panic exits with 65. Runner processes' standard
//! streams are the VM's console device, if there is one, and their sockets
//! reach the VM's network device, if there is one; programs also see the
//! host directories of virtio-9p devices, read-only, at their mount tags
//! ([`devices`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod control;
mod devices;
mod payload;
mod service;
mod stdio;

use alloc::boxed::Box;
use core::panic::PanicInfo;
use litebox_bootloader::Kernel;
use litebox_hal::{power, serial};
use litebox_platform_vm_kernel::providers::set_platform_root_key;

litebox_bootloader::entry!(kernel_main, &SerialLogger);

fn kernel_main(kernel: Kernel) -> ! {
    set_platform_root_key(&litebox_hal::prk::development());
    let payload =
        payload::Payload::read(kernel.boot_info).unwrap_or_else(|e| panic!("payload: {e}"));
    let devices = devices::Devices::init(kernel.platform, kernel.clock);
    let wall_clock = devices::wall_clock(kernel.platform, kernel.clock);
    let broker = |console, shares, allow_process_duplication| {
        litebox_broker_vm_kernel::Broker::new(litebox_broker_vm_kernel::Config {
            platform: kernel.platform,
            console,
            events: devices,
            root: payload.file("rootfs.tar"),
            shares,
            network: devices.network(),
            allow_process_duplication,
        })
    };
    // The kernel's one scheduler, which every runner process runs in.
    let scheduler = litebox_shim_vm_kernel::sched::Scheduler::default();
    let vsock = match devices.vsock(litebox_common_vm_control::PORT) {
        Ok(Some(vsock)) => vsock,
        Ok(None) => panic!(
            "no vsock device: the host controls the kernel over vsock \
             (attach -device vhost-vsock-pci,guest-cid=<CID>)"
        ),
        Err(error) => panic!("the VM's vsock device is unusable: {error}"),
    };
    let server = if payload.file("ldelf.elf").is_some() {
        control::Server::Optee(service::optee::Optee::new(
            scheduler,
            kernel.platform,
            kernel.clock,
            wall_clock,
            devices,
            &payload,
            // No shares: TA storage (OP-TEE secure storage) needs a file
            // system of its own, not provided yet.
            broker(devices, alloc::vec::Vec::new(), false),
        ))
    } else {
        let stdio: &'static stdio::Stdio = Box::leak(Box::new(stdio::Stdio::new(devices)));
        control::Server::Programs(
            Box::new(service::program::Programs::new(
                scheduler,
                kernel.platform,
                kernel.clock,
                wall_clock,
                devices,
                &payload,
                // Programs may start child processes.
                broker(stdio, devices.shares(), true),
            )),
            stdio,
        )
    };
    control::serve(vsock, server)
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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::panic_print(format_args!("[litebox] PANIC: {info}\n"));
    power::exit(false)
}
