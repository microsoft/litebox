// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: tests' hooks into a boot's broker work, from the kernel
//! command line, for tests that boot their program as init (see
//! `dev_tools/run_linux_on_vm_userland.sh`). Release builds ignore the keys,
//! with a warning.
//!
//! - [`ARGS_KEY`]: init's arguments after its path, comma-separated (so none
//!   holds a comma or whitespace).
//! - [`HOOKS_KEY`]: comma-separated hooks:
//!   - init's, which its descendants inherit (see
//!     `litebox_shim_vm_kernel::Hooks`): `fail_adoption`, `slow_serves`,
//!     `misbehave:bad_wake_slot` or `misbehave:bad_fs_base`, and
//!     `stack_failure:spawn`, `stack_failure:after_association` or
//!     `stack_failure:clone`;
//!   - `stack_failure:root`: init's first spawn fails, out of broker stacks,
//!     and init is spawned again;
//!   - the broker's gate (see `litebox_broker_vm_kernel::gate`): `gate:read`,
//!     `gate:handshake`, `gate:adopt` or `gate:transmitted`;
//!   - the scheduler's (see `litebox_shim_vm_kernel::sched::SchedulerHooks`):
//!     `hold_starts`, `broker_slice_us:N`, `hold_retake:handshake`,
//!     `hold_retake:futex`, `hold_retake:preempted_futex` or
//!     `hold_retake:preempted_futex_ran`, `post_as_finished`, and
//!     `keep_reaped`;
//!   - the devices': `lose_share_response`.
//! - [`SCRIPT_KEY`]: comma-separated steps, taken in turn from init's start,
//!   between the scheduler's steps:
//!   - `held`: the gate holds a broker thread, or a step held a launched
//!     process's start (`hold_starts`);
//!   - `lock_sleeper`: a broker thread sleeps for a lock;
//!   - `migrate`: the broker thread the gate releases next moves to another
//!     CPU;
//!   - `kill`: the kernel kills init;
//!   - `release`: the gate releases the thread it holds, and the starts go on.
//!
//! At init's end, once the processes ran until idle, the hooks must have
//! acted, and the script must be done (see [`Boot::check`]).

use litebox_bootloader::handoff::BootInfo;
#[cfg(debug_assertions)]
use {
    crate::devices::Devices,
    alloc::vec::Vec,
    core::sync::atomic::Ordering,
    litebox_broker_vm_kernel::gate::Point,
    litebox_shim_vm_kernel::sched::{RetakeHold, Scheduler},
    litebox_shim_vm_kernel::{Hooks, Misbehavior, Process, StackFailure},
};

/// The command line's key for init's arguments.
pub const ARGS_KEY: &str = "litebox.init.args";
/// The command line's key for the hooks.
pub const HOOKS_KEY: &str = "litebox.hooks";
/// The command line's key for the script.
pub const SCRIPT_KEY: &str = "litebox.script";

/// Release builds: warns of the debug builds' keys in `boot_info`'s command
/// line, which they ignore.
#[cfg(not(debug_assertions))]
pub fn warn_ignored(boot_info: &BootInfo) {
    for key in [ARGS_KEY, HOOKS_KEY, SCRIPT_KEY] {
        if boot_info.cmdline_value(key).is_some() {
            litebox_util_log::warn!(key:% = key; "ignored: a debug builds' key");
        }
    }
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Held,
    LockSleeper,
    Migrate,
    Kill,
    Release,
}

/// A boot's debug parameters, from its command line.
#[cfg(debug_assertions)]
#[expect(clippy::struct_excessive_bools, reason = "independent hooks")]
pub struct Boot {
    devices: &'static Devices,
    scheduler: Scheduler,
    /// Init's arguments after its path.
    pub args: Vec<&'static str>,
    /// Init's hooks.
    pub process: Hooks,
    /// Init's first spawn fails (`stack_failure:root`).
    pub fail_spawn: bool,
    /// The processes reaped are kept until the broker's shutdown.
    pub keep_reaped: bool,
    lose_share_response: bool,
    hold_retake: bool,
    broker_slice: bool,
    post_as_finished: bool,
    steps: Vec<Step>,
    /// The next step to take.
    next: usize,
    /// The share requests that timed out before init.
    share_timeouts: u64,
}

#[cfg(debug_assertions)]
impl Boot {
    /// Parses `boot_info`'s debug keys, and sets the hooks of the
    /// scheduler, the gate and the devices.
    ///
    /// # Panics
    ///
    /// On an unknown hook or step, or a `held` step with nothing to hold.
    pub fn set(
        boot_info: &'static BootInfo,
        scheduler: &Scheduler,
        devices: &'static Devices,
    ) -> Self {
        let items = |key| {
            boot_info
                .cmdline_value(key)
                .into_iter()
                .flat_map(|value| value.split(','))
                .filter(|item| !item.is_empty())
        };
        let mut boot = Self {
            devices,
            scheduler: scheduler.clone(),
            args: items(ARGS_KEY).collect(),
            process: Hooks::default(),
            fail_spawn: false,
            keep_reaped: false,
            lose_share_response: false,
            hold_retake: false,
            broker_slice: false,
            post_as_finished: false,
            steps: Vec::new(),
            next: 0,
            share_timeouts: devices.share_timeouts(),
        };
        let hooks = scheduler.hooks();
        let mut holds = false;
        for hook in items(HOOKS_KEY) {
            let (name, value) = hook.split_once(':').unwrap_or((hook, ""));
            match (name, value) {
                ("fail_adoption", "") => boot.process.fail_adoption = true,
                ("slow_serves", "") => boot.process.slow_serves = true,
                ("misbehave", "bad_wake_slot") => {
                    boot.process.misbehavior = Some(Misbehavior::BadWakeSlot);
                }
                ("misbehave", "bad_fs_base") => {
                    boot.process.misbehavior = Some(Misbehavior::BadFsBase);
                }
                ("stack_failure", "root") => boot.fail_spawn = true,
                ("stack_failure", "spawn") => {
                    boot.process.stack_failure = Some(StackFailure::Spawn);
                }
                ("stack_failure", "after_association") => {
                    boot.process.stack_failure = Some(StackFailure::AfterAssociation);
                }
                ("stack_failure", "clone") => {
                    boot.process.stack_failure = Some(StackFailure::Clone);
                }
                ("gate", point) => {
                    holds = true;
                    devices.gate().arm(match point {
                        "read" => Point::Read,
                        "handshake" => Point::Handshake,
                        "adopt" => Point::Adopt,
                        "transmitted" => Point::Transmitted,
                        _ => panic!("unknown gate point in {HOOKS_KEY}: {hook}"),
                    });
                }
                ("hold_starts", "") => {
                    holds = true;
                    hooks.hold_starts.store(true, Ordering::SeqCst);
                }
                ("broker_slice_us", us) => {
                    let us: u64 = us
                        .parse()
                        .unwrap_or_else(|_| panic!("not microseconds in {HOOKS_KEY}: {hook}"));
                    boot.broker_slice = true;
                    hooks
                        .broker_slice
                        .store(us.saturating_mul(1000).max(1), Ordering::SeqCst);
                }
                ("hold_retake", case) => {
                    boot.hold_retake = true;
                    hooks.hold_retake(Some(match case {
                        "handshake" => RetakeHold::Handshake,
                        "futex" => RetakeHold::Futex,
                        "preempted_futex" => RetakeHold::PreemptedFutex,
                        "preempted_futex_ran" => RetakeHold::PreemptedFutexRan,
                        _ => panic!("unknown retake case in {HOOKS_KEY}: {hook}"),
                    }));
                }
                ("post_as_finished", "") => {
                    boot.post_as_finished = true;
                    hooks.post_as_finished.store(true, Ordering::SeqCst);
                }
                ("lose_share_response", "") => {
                    boot.lose_share_response = true;
                    devices.lose_share_response();
                }
                ("keep_reaped", "") => {
                    boot.keep_reaped = true;
                    hooks.keep_reaped();
                }
                _ => panic!("unknown hook in {HOOKS_KEY}: {hook}"),
            }
        }
        boot.steps = items(SCRIPT_KEY)
            .map(|step| match step {
                "held" => Step::Held,
                "lock_sleeper" => Step::LockSleeper,
                "migrate" => Step::Migrate,
                "kill" => Step::Kill,
                "release" => Step::Release,
                _ => panic!("unknown step in {SCRIPT_KEY}: {step}"),
            })
            .collect();
        assert!(
            holds || !boot.steps.contains(&Step::Held),
            "{SCRIPT_KEY}'s `held` needs a gate or `hold_starts` in {HOOKS_KEY}"
        );
        // So that the boot CPU looks at the script often enough.
        hooks.poll.store(!boot.steps.is_empty(), Ordering::SeqCst);
        boot
    }

    /// Takes the steps it can, on init's `process`, until one waits:
    /// whether it took them all.
    pub fn advance(&mut self, process: &mut Process) -> bool {
        let gate = self.devices.gate();
        let hooks = self.scheduler.hooks();
        while let Some(&step) = self.steps.get(self.next) {
            let ready = match step {
                Step::Held => gate.holds() || hooks.held_start.load(Ordering::SeqCst),
                Step::LockSleeper => litebox_platform_vm_kernel::lock_sleepers() != 0,
                Step::Migrate => {
                    gate.migrate();
                    true
                }
                Step::Kill => {
                    process.kill("killed by its test script");
                    true
                }
                Step::Release => {
                    gate.release();
                    hooks.hold_starts.store(false, Ordering::SeqCst);
                    true
                }
            };
            if !ready {
                return false;
            }
            self.next += 1;
        }
        true
    }

    /// At init's end, once the processes ran until idle: checks that the
    /// script is done, that the hooks acted, and that the share requests
    /// that timed out were the lost one, if any.
    ///
    /// # Panics
    ///
    /// If not.
    pub fn check(&self) {
        let hooks = self.scheduler.hooks();
        assert!(
            self.next == self.steps.len(),
            "init ended before its script's step {:?}",
            self.steps[self.next]
        );
        assert!(
            !self.hold_retake || hooks.retaken.load(Ordering::SeqCst),
            "no handoff of the case was held"
        );
        assert!(
            !self.post_as_finished || !hooks.post_as_finished.load(Ordering::SeqCst),
            "no broker thread finished bound"
        );
        assert!(
            !self.broker_slice || hooks.broker_slice_preemptions.load(Ordering::SeqCst) != 0,
            "no capped broker run returned preempted with its deadline elapsed"
        );
        assert_eq!(
            self.devices.share_timeouts() - self.share_timeouts,
            u64::from(self.lose_share_response),
            "share requests that timed out"
        );
    }
}
