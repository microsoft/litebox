// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU guest kernel, hosting ring-3 runner processes, chosen by the payload:
//! - With [`init::RUNNER`]: [`init`], e.g., the guest service.
//! - Otherwise, with the `optee` feature: OP-TEE TAs, one per TA instance
//!   (`service::optee`), driven by a test client (`client::script`).
//!
//! QEMU exits with 33 if init exits with 0 or the OP-TEE tests pass, and 65
//! otherwise. Runner processes' standard streams are the VM's console
//! device, if there is one, their sockets reach the VM's network device, if
//! there is one, and their vsock sockets the host through the VM's socket
//! device, if there is one; programs also see the host directories of
//! virtio-9p devices, read-only, at their mount tags ([`devices`]).
//!
//! Every CPU runs the processes ([`litebox_shim_vm_kernel::sched`],
//! [`cpu_main`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

#[cfg(feature = "optee")]
mod client;
mod devices;
mod init;
mod payload;
#[cfg(debug_assertions)]
mod self_check;
#[cfg(feature = "optee")]
mod service;
mod test_hooks;

use core::panic::PanicInfo;
use litebox_bootloader::Kernel;
use litebox_common_vm_abi::program::ExitStatus;
use litebox_hal::{power, serial, serial_println};
use litebox_platform_vm_kernel::VmKernel;
use litebox_platform_vm_kernel::cpu::CpuId;
use litebox_platform_vm_kernel::providers::set_platform_root_key;
use litebox_shim_vm_kernel::ProcessConfig;
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
    let scheduler = SCHEDULER.call_once(|| Scheduler::new(devices, devices, kernel.platform));
    litebox_platform_vm_kernel::kthread::set_preemption(scheduler);
    // Once interrupts and the timer are set up: alone, then with the others.
    #[cfg(debug_assertions)]
    self_check::kthreads(kernel.platform, devices);
    kernel.start_cpus(devices, cpu_main);
    #[cfg(debug_assertions)]
    self_check::smp_kthreads(kernel.platform, devices);
    let wall_clock = devices::wall_clock(kernel.platform, kernel.clock);
    let Some(runner) = payload.file(init::RUNNER) else {
        #[cfg(feature = "optee")]
        run_optee(&kernel, &payload, devices, scheduler, wall_clock);
        #[cfg(not(feature = "optee"))]
        panic!(
            "payload has no {}, and the kernel has no OP-TEE support",
            init::RUNNER
        );
    };
    let path = kernel
        .boot_info
        .cmdline_value(init::PATH_KEY)
        .unwrap_or(init::DEFAULT_PATH);
    // Before any broker thread exists: e.g., a share's 9P connection halts.
    let broker = litebox_broker_vm_kernel::Broker::new(litebox_broker_vm_kernel::Config {
        platform: kernel.platform,
        console: devices,
        root: payload.file("rootfs.tar"),
        shares: devices.shares(),
        network: devices.network(),
        vsock: devices.vsock(),
        allow_process_duplication: true,
        events: devices,
        #[cfg(debug_assertions)]
        gate: devices.gate(),
    });
    scheduler.start_broker(&broker);
    #[cfg(debug_assertions)]
    let mut hooks = test_hooks::Boot::set(kernel.boot_info, scheduler, devices);
    #[cfg(not(debug_assertions))]
    test_hooks::warn_ignored(kernel.boot_info);
    let config = ProcessConfig {
        runner,
        images: &[],
        identity: [0; litebox_common_vm_abi::IDENTITY_LEN],
        clock_khz: kernel.clock.khz(),
        wall_clock,
        timer: devices,
        started_runner: Some(runner),
        #[cfg(debug_assertions)]
        give_up_once: kernel.boot_info.cmdline_value(init::REPLAY_KEY) == Some("1"),
        #[cfg(debug_assertions)]
        hooks: hooks.process,
    };
    let status = init::run(
        scheduler,
        kernel.platform,
        &broker.handle(),
        &config,
        path,
        #[cfg(debug_assertions)]
        &mut hooks,
    );
    // Init is gone; in debug builds, with every other process (see
    // `init::run`), so the broker shuts down. Release builds power off
    // without (as OP-TEE's, below, do not).
    if cfg!(debug_assertions) {
        scheduler.shut_down_broker(broker);
    }
    print_slices(scheduler);
    devices.drain_console();
    power::exit(status == Ok(ExitStatus::Exited { code: 0 }))
}

/// Runs the OP-TEE tests of `payload` (see the crate's docs), and powers off.
#[cfg(feature = "optee")]
fn run_optee(
    kernel: &Kernel,
    payload: &payload::Payload,
    devices: &'static devices::Devices,
    scheduler: &Scheduler,
    wall_clock: litebox_common_vm_abi::WallClock,
) -> ! {
    // Before any broker thread exists.
    let broker = litebox_broker_vm_kernel::Broker::new(litebox_broker_vm_kernel::Config {
        platform: kernel.platform,
        console: devices,
        root: None,
        // No shares: TA storage (OP-TEE secure storage) needs a file
        // system of its own, not provided yet.
        shares: alloc::vec::Vec::new(),
        network: devices.network(),
        vsock: devices.vsock(),
        allow_process_duplication: false,
        events: devices,
        #[cfg(debug_assertions)]
        gate: devices.gate(),
    });
    scheduler.start_broker(&broker);
    let mut service = service::optee::Optee::new(
        scheduler.clone(),
        kernel.platform,
        kernel.clock,
        wall_clock,
        devices,
        payload,
        broker.handle(),
    );
    client::script::run(payload, &mut service);
    // With its processes, the keep-alive instances' too.
    drop(service);
    scheduler.shut_down_broker(broker);
    print_slices(scheduler);
    // Whatever the log level, for the test scripts.
    serial_println!("[litebox] ALL TESTS PASSED");
    devices.drain_console();
    power::exit(true)
}

/// Prints what each CPU ran, for the test scripts.
fn print_slices(scheduler: &Scheduler) {
    serial_println!("[litebox] slices run per CPU: {:?}", scheduler.slices());
    serial_println!("[litebox] threads parked per CPU: {:?}", scheduler.parks());
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
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        serial::print_str(&buf);
    }

    fn flush(&self) {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::panic_print(format_args!("[litebox] PANIC: {info}\n"));
    power::exit(false)
}
