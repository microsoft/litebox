// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU guest kernel: a [service](service::Service) in ring-3 runner
//! processes, and a [client](client) for it, chosen by the payload:
//! - With `programs.json`: standalone programs in `runner.elf` processes
//!   ([`service::program`]), e.g., Linux programs in
//!   `litebox_runner_linux_on_vm_userland`, driven by [`client::program`].
//! - Otherwise: OP-TEE TAs in `litebox_runner_optee_on_vm_userland`
//!   processes, one per TA instance ([`service::optee`]), driven by a test
//!   client ([`client::script`]).
//!
//! QEMU exits with 33 if all tests pass, 65 otherwise. Runner processes'
//! standard streams are the VM's console device, if there is one, and their
//! sockets reach the VM's network device, if there is one; programs also see
//! the host directories of virtio-9p devices, read-only, at their mount tags
//! ([`devices`]).
//!
//! Every CPU runs the processes ([`litebox_shim_vm_kernel::sched`]); the boot
//! CPU also runs the client and service, the others only the processes
//! ([`cpu_main`]).

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
use litebox_hal::{power, serial, serial_println};
use litebox_platform_vm_kernel::VmKernel;
use litebox_platform_vm_kernel::cpu::CpuId;
use litebox_platform_vm_kernel::providers::set_platform_root_key;
use litebox_shim_vm_kernel::sched::Scheduler;

litebox_bootloader::entry!(kernel_main, &SerialLogger);

/// The kernel's one scheduler, which every runner process runs in, on every
/// CPU; published before the other CPUs start.
static SCHEDULER: spin::Once<Scheduler> = spin::Once::new();

fn kernel_main(kernel: Kernel) -> ! {
    set_platform_root_key(&litebox_hal::prk::development());
    let payload =
        payload::Payload::read(kernel.boot_info).unwrap_or_else(|e| panic!("payload: {e}"));
    let devices = devices::Devices::init(kernel.platform, kernel.clock);
    let scheduler = SCHEDULER.call_once(|| Scheduler::new(devices));
    kernel.start_cpus(devices, cpu_main);
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
    if let Some(programs) = payload.file("programs.json") {
        let stdio: &'static client::program::Stdio =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(client::program::Stdio::new(devices)));
        let mut service = service::program::Programs::new(
            scheduler.clone(),
            kernel.platform,
            kernel.clock,
            wall_clock,
            devices,
            &payload,
            // Programs may start child processes.
            broker(stdio, devices.shares(), true),
        );
        client::program::run(programs, &mut service, stdio);
    } else {
        let mut service = service::optee::Optee::new(
            scheduler.clone(),
            kernel.platform,
            kernel.clock,
            wall_clock,
            devices,
            &payload,
            // No shares: TA storage (OP-TEE secure storage) needs a file
            // system of its own, not provided yet.
            broker(devices, alloc::vec::Vec::new(), false),
        );
        client::script::run(&payload, &mut service);
    }
    // Whatever the log level, for the test scripts.
    serial_println!("[litebox] slices run per CPU: {:?}", scheduler.slices());
    serial_println!("[litebox] threads parked per CPU: {:?}", scheduler.parks());
    serial_println!("[litebox] ALL TESTS PASSED");
    power::exit(true)
}

/// Each other CPU's kernel, once online: it runs the processes.
fn cpu_main(_platform: &'static VmKernel, _cpu: CpuId) -> ! {
    SCHEDULER
        .get()
        .expect("the scheduler is published before the CPUs start")
        .run()
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
    serial::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    power::exit(false)
}
