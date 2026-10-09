// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Round-robin time slicing of [`Process`]es on one CPU.
//!
//! The kernel is not preemptible: a process's thread runs until its slice
//! ends (the platform's deadline timer interrupts it), it blocks
//! ([`CallId::Wait`](litebox_common_vm_abi::CallId::Wait)), waits for a
//! request, or dies. With nothing to run, the CPU idles until the next wait
//! deadline or time limit. Without a timer, threads run until they stop by
//! themselves, and idling spins.

use crate::Process;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::{Instant, VmKernel};

/// The longest a thread runs while others are runnable.
pub const SLICE: core::time::Duration = core::time::Duration::from_millis(10);

/// Runs `processes` until none can run again: each is dead, or waits for a
/// request.
pub fn run(platform: &'static VmKernel, processes: &mut [&mut Process]) {
    // The next process to consider, so that each gets its turn.
    let mut next = 0;
    loop {
        let now = platform.now();
        for process in processes.iter_mut() {
            process.expire(now);
        }
        let count = processes.len();
        if let Some(index) = (0..count)
            .map(|offset| (next + offset) % count)
            .find(|&index| processes[index].runnable())
        {
            let deadline = processes
                .iter()
                .filter_map(|process| process.next_event())
                .chain(now.checked_add(SLICE))
                .min();
            platform.set_timer(deadline);
            processes[index].run_slice();
            platform.set_timer(None);
            next = index + 1;
            continue;
        }
        let Some(deadline) = processes
            .iter()
            .filter_map(|process| process.next_event())
            .min()
        else {
            break;
        };
        idle_until(platform, deadline);
    }
}

/// Returns at `deadline`, or earlier.
fn idle_until(platform: &VmKernel, deadline: Instant) {
    if platform.has_timer() {
        platform.set_timer(Some(deadline));
        platform.idle();
        platform.set_timer(None);
    } else {
        while platform.now() < deadline {
            core::hint::spin_loop();
        }
    }
}
