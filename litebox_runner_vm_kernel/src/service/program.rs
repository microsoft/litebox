// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standalone programs in runner processes, one per run. From the payload:
//! `runner.elf`, which decides the guest OS (e.g.,
//! `litebox_runner_linux_on_vm_userland`); the programs' files are the
//! broker's (see `rootfs.tar` in [`crate::payload`]).

use super::Service;
use crate::payload::Payload;
use litebox_common_vm_abi::WallClock;
use litebox_common_vm_abi::program::{ExitStatus, Program};
use litebox_hal::clock::Clock;
use litebox_platform_vm_kernel::VmKernel;
use litebox_shim_vm_kernel::program::RunError;
use litebox_shim_vm_kernel::{Process, ProcessConfig, ProcessTimer};

pub struct Programs {
    platform: &'static VmKernel,
    clock: Clock,
    wall_clock: WallClock,
    timer: &'static dyn ProcessTimer,
    broker: litebox_broker_vm_kernel::Broker,
    runner: &'static [u8],
}

pub struct Reply {
    pub status: Result<ExitStatus, RunError>,
    /// Guest syscalls the runner did not take directly, so the kernel
    /// reflected them.
    pub reflected_syscalls: u64,
}

impl Programs {
    /// # Panics
    ///
    /// Without `runner.elf` in the payload.
    pub fn new(
        platform: &'static VmKernel,
        clock: Clock,
        wall_clock: WallClock,
        timer: &'static dyn ProcessTimer,
        payload: &Payload,
        broker: litebox_broker_vm_kernel::Broker,
    ) -> Self {
        Self {
            platform,
            clock,
            wall_clock,
            timer,
            broker,
            runner: payload
                .file("runner.elf")
                .expect("payload has no runner.elf"),
        }
    }
}

impl Service for Programs {
    type Request = Program;
    type Reply = Reply;

    /// The process ends with the call.
    fn call(&mut self, program: Program) -> Reply {
        let mut process = Process::spawn(
            self.platform,
            &self.broker,
            &ProcessConfig {
                runner: self.runner,
                images: &[],
                identity: [0; litebox_common_vm_abi::IDENTITY_LEN],
                clock_khz: self.clock.khz(),
                wall_clock: self.wall_clock,
                timer: self.timer,
            },
        )
        .unwrap_or_else(|error| panic!("failed to spawn a program runner: {error}"));
        let status = process
            .start()
            .map_err(RunError::Dead)
            .and_then(|()| litebox_shim_vm_kernel::program::run(&mut process, &program));
        Reply {
            status,
            reflected_syscalls: process.reflected_syscalls(),
        }
    }
}
