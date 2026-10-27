// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standalone programs in runner processes, one per run, possibly several at
//! once. From the payload:
//! `runner.elf`, which decides the guest OS (e.g.,
//! `litebox_runner_linux_on_vm_userland`); the programs' files are the
//! broker's (see `rootfs.tar` in [`crate::payload`]).

use super::Service;
use crate::payload::Payload;
use alloc::vec::Vec;
use core::time::Duration;
use litebox_common_vm_abi::WallClock;
use litebox_common_vm_abi::program::{ExitStatus, Program};
use litebox_hal::clock::Clock;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::{VmKernel, cpu};
#[cfg(debug_assertions)]
use litebox_shim_vm_kernel::Hooks;
use litebox_shim_vm_kernel::program::RunError;
use litebox_shim_vm_kernel::sched::Scheduler;
use litebox_shim_vm_kernel::{Process, ProcessConfig, ProcessTimer};

pub struct Programs {
    scheduler: Scheduler,
    platform: &'static VmKernel,
    clock: Clock,
    wall_clock: WallClock,
    timer: &'static dyn ProcessTimer,
    broker: litebox_broker_vm_kernel::BrokerHandle,
    runner: &'static [u8],
    /// Debug builds: see [`Self::give_up_once`].
    #[cfg(debug_assertions)]
    give_up_once: bool,
    #[cfg(debug_assertions)]
    hooks: Vec<RunHooks>,
    #[cfg(debug_assertions)]
    hold_starts: bool,
}

/// Debug builds: a run's process's hooks (see [`Programs::set_hooks`]).
#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RunHooks {
    pub process: Hooks,
    /// Its spawn fails first, out of broker stacks; then it is spawned again.
    pub fail_spawn: bool,
}

pub struct Reply {
    pub status: Result<ExitStatus, RunError>,
    /// Guest syscalls the runner did not take directly, so the kernel
    /// reflected them.
    pub reflected_syscalls: u64,
    /// Debug builds: see [`Process::replay_counts`].
    #[cfg(debug_assertions)]
    pub replay_counts: [u32; 5],
}

impl Programs {
    /// # Panics
    ///
    /// Without `runner.elf` in the payload.
    pub fn new(
        scheduler: Scheduler,
        platform: &'static VmKernel,
        clock: Clock,
        wall_clock: WallClock,
        timer: &'static dyn ProcessTimer,
        payload: &Payload,
        broker: litebox_broker_vm_kernel::BrokerHandle,
    ) -> Self {
        Self {
            scheduler,
            platform,
            clock,
            wall_clock,
            timer,
            broker,
            runner: payload
                .file("runner.elf")
                .expect("payload has no runner.elf"),
            #[cfg(debug_assertions)]
            give_up_once: false,
            #[cfg(debug_assertions)]
            hooks: Vec::new(),
            #[cfg(debug_assertions)]
            hold_starts: false,
        }
    }
}

impl Programs {
    /// Debug builds, for tests of replays: the processes of the next
    /// [`Self::run_concurrently`] each give up on their claims at their first
    /// kernel entry of each kind, so that each is replayed (see
    /// [`ProcessConfig::give_up_once`]).
    #[cfg(debug_assertions)]
    pub fn give_up_once(&mut self) {
        self.give_up_once = true;
    }

    /// Debug builds: the processes of the next [`Self::run_concurrently`] have
    /// `hooks`, by index.
    #[cfg(debug_assertions)]
    pub fn set_hooks(&mut self, hooks: Vec<RunHooks>) {
        self.hooks = hooks;
    }

    /// Debug builds: once the processes of the next [`Self::run_concurrently`]
    /// started, the kernel starts no launched process until released.
    #[cfg(debug_assertions)]
    pub fn hold_starts(&mut self) {
        self.hold_starts = true;
    }

    /// Debug builds: the scheduler, for tests to set its hooks.
    #[cfg(debug_assertions)]
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Runs `programs` at once, a process each, which ends with the call;
    /// replies are in order. Debug builds call `between_steps` between the
    /// scheduler's steps, from each process's start on, until it returns true.
    pub fn run_concurrently(
        &mut self,
        programs: &[Program],
        #[cfg(debug_assertions)] mut between_steps: impl FnMut(usize, &mut Process) -> bool,
    ) -> Vec<Reply> {
        #[cfg(debug_assertions)]
        let mut processes: Vec<Process> = (0..programs.len())
            .map(|index| self.start(index, |process| between_steps(index, process)))
            .collect();
        #[cfg(not(debug_assertions))]
        let mut processes: Vec<Process> = programs.iter().map(|_| self.start()).collect();
        #[cfg(debug_assertions)]
        {
            self.give_up_once = false;
            self.hooks = Vec::new();
            if core::mem::take(&mut self.hold_starts) {
                self.scheduler
                    .hooks()
                    .hold_starts
                    .store(true, core::sync::atomic::Ordering::SeqCst);
            }
        }
        let statuses = {
            let mut runs: Vec<(&mut Process, &Program)> =
                processes.iter_mut().zip(programs).collect();
            litebox_shim_vm_kernel::program::run_all(
                &self.scheduler,
                &mut runs,
                #[cfg(debug_assertions)]
                |runs| {
                    let mut done = true;
                    for (index, (process, _)) in runs.iter_mut().enumerate() {
                        done &= between_steps(index, process);
                    }
                    done
                },
            )
        };
        processes
            .iter()
            .zip(statuses)
            .map(|(process, status)| Reply {
                status,
                reflected_syscalls: process.reflected_syscalls(),
                #[cfg(debug_assertions)]
                replay_counts: process.replay_counts(),
            })
            .collect()
    }

    /// Checks that the processes that ran, which all ended, left nothing
    /// behind in the kernel: no address space, no frame shared copy-on-write,
    /// and no broker stack but the source thread's, once their broker work ran
    /// and the other CPUs released what they still held.
    ///
    /// # Panics
    ///
    /// If they did.
    pub fn check_released(&self) {
        /// Ample for the other CPUs to release them, even under emulation.
        const TIMEOUT: Duration = Duration::from_secs(5);
        /// Between looks, which take locks that releasing them takes.
        const BACKOFF: Duration = Duration::from_micros(100);
        self.scheduler.run_until_idle();
        let released = || {
            self.scheduler.reap();
            self.platform.address_space_count() == 0 && self.platform.shared_frame_count() == 0
        };
        let after = |duration| {
            self.platform
                .now()
                .checked_add(duration)
                .expect("the clock is far from overflowing")
        };
        let deadline = after(TIMEOUT);
        while !released() && self.platform.now() < deadline {
            let next = after(BACKOFF);
            while self.platform.now() < next {
                cpu::relax();
            }
        }
        assert_eq!(
            self.platform.address_space_count(),
            0,
            "ended processes left address spaces, after waiting {TIMEOUT:?} for the other CPUs"
        );
        assert_eq!(
            self.platform.shared_frame_count(),
            0,
            "ended processes left shared frames, after waiting {TIMEOUT:?} for the other CPUs"
        );
        assert_eq!(
            litebox_platform_vm_kernel::kthread::stacks(),
            1,
            "ended processes left broker stacks"
        );
    }

    /// A runner process, started: dead if it did not get that far. Debug
    /// builds give it run `index`'s hooks.
    fn start(
        &self,
        #[cfg(debug_assertions)] index: usize,
        #[cfg(debug_assertions)] between_steps: impl FnMut(&mut Process) -> bool,
    ) -> Process {
        #[cfg(debug_assertions)]
        let hooks = self.hooks.get(index).copied().unwrap_or_default();
        let config = ProcessConfig {
            runner: self.runner,
            images: &[],
            identity: [0; litebox_common_vm_abi::IDENTITY_LEN],
            clock_khz: self.clock.khz(),
            wall_clock: self.wall_clock,
            timer: self.timer,
            // Programs may start child processes.
            started_runner: Some(self.runner),
            #[cfg(debug_assertions)]
            give_up_once: self.give_up_once,
            #[cfg(debug_assertions)]
            hooks: hooks.process,
        };
        let spawn = || Process::spawn(&self.scheduler, self.platform, &self.broker, &config);
        #[cfg(debug_assertions)]
        if hooks.fail_spawn {
            litebox_platform_vm_kernel::kthread::fail_next_stack();
            assert!(
                matches!(
                    spawn(),
                    Err(litebox_shim_vm_kernel::SpawnError::Map(
                        litebox_common_vm_abi::Status::NoMemory
                    ))
                ),
                "a spawn whose broker stack cannot be allocated fails"
            );
        }
        let mut process =
            spawn().unwrap_or_else(|error| panic!("failed to spawn a program runner: {error}"));
        // A dead process fails its run.
        #[cfg(debug_assertions)]
        let _ = process.start_with(between_steps);
        #[cfg(not(debug_assertions))]
        let _ = process.start();
        process
    }
}

impl Service for Programs {
    type Request = Program;
    type Reply = Reply;

    /// The process ends with the call.
    fn call(&mut self, program: Program) -> Reply {
        self.run_concurrently(
            core::slice::from_ref(&program),
            #[cfg(debug_assertions)]
            |_, _| true,
        )
        .pop()
        .expect("one reply per program")
    }
}
