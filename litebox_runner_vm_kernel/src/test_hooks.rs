// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: tests' hooks into a boot's broker work, from the kernel
//! command line, for tests that boot their program as init (see
//! `dev_tools/run_linux_on_vm_userland.sh`): [`ARGS_KEY`] gives init's
//! arguments, and [`HOOKS_KEY`] the hooks ([`Boot::set`]), each
//! comma-separated.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use litebox_bootloader::handoff::BootInfo;
use litebox_shim_vm_kernel::sched::Scheduler;

/// Init's arguments after its path, comma-separated: so none holds a comma or
/// whitespace.
pub const ARGS_KEY: &str = "litebox.init.args";
pub const HOOKS_KEY: &str = "litebox.hooks";

/// A boot's hooks, from its command line.
pub struct Boot {
    scheduler: Scheduler,
    pub args: Vec<&'static str>,
}

impl Boot {
    /// Parses `boot_info`'s keys, and sets the scheduler's hooks they name
    /// (see `litebox_shim_vm_kernel::sched::SchedulerHooks`).
    ///
    /// # Panics
    ///
    /// On an unknown hook.
    pub fn set(boot_info: &'static BootInfo, scheduler: &Scheduler) -> Self {
        let items = |key| {
            boot_info
                .cmdline_value(key)
                .into_iter()
                .flat_map(|value| value.split(','))
                .filter(|item| !item.is_empty())
        };
        for hook in items(HOOKS_KEY) {
            let Some(us) = hook.strip_prefix("broker_slice_us:") else {
                panic!("unknown hook in {HOOKS_KEY}: {hook}");
            };
            let us: u64 = us
                .parse()
                .unwrap_or_else(|_| panic!("not microseconds in {HOOKS_KEY}: {hook}"));
            scheduler
                .hooks()
                .broker_slice
                .store(us.saturating_mul(1000).max(1), Ordering::SeqCst);
        }
        Self {
            scheduler: scheduler.clone(),
            args: items(ARGS_KEY).collect(),
        }
    }

    /// At init's end, once the processes ran until idle: checks that the
    /// hooks acted.
    ///
    /// # Panics
    ///
    /// If one did not.
    pub fn check(&self) {
        let hooks = self.scheduler.hooks();
        assert!(
            hooks.broker_slice.load(Ordering::SeqCst) == 0
                || hooks.broker_slice_preempted.load(Ordering::SeqCst),
            "no capped broker run returned preempted with its deadline elapsed"
        );
    }
}
