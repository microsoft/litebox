// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Round-robin scheduling of runner processes on the one CPU.
//!
//! A process runs until it stops (waits for a request, or dies) or its slice
//! of [`QUANTUM`] ends; preemption is transparent to it. A process alone has
//! no slice end. Only user mode is preempted; a broker wait holds the CPU
//! until it ends.

use crate::Process;
use core::time::Duration;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::Instant;

/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_millis(10);

/// Runs `processes` until each one waits for a request (see
/// [`Process::submit`]) or is dead.
pub fn run(processes: &mut [&mut Process]) {
    let count = processes.len();
    let mut next = 0;
    while let Some(index) = (0..count)
        .map(|offset| (next + offset) % count)
        .find(|&index| !processes[index].inner.is_stopped())
    {
        let others = (0..count).any(|other| other != index && !processes[other].inner.is_stopped());
        let slice_end = others.then(|| {
            processes[index]
                .inner
                .platform
                .now()
                .checked_add(QUANTUM)
                .unwrap_or(Instant::from_nanos(u64::MAX))
        });
        processes[index].run_slice(slice_end);
        next = index + 1;
    }
}

impl Process {
    /// Runs the process until it stops or `slice_end` passes (none: until it
    /// stops).
    fn run_slice(&mut self, slice_end: Option<Instant>) {
        self.inner.slice_end.set(slice_end);
        let new = self.inner.is_new();
        let resume = self.inner.preempted.get();
        self.activate();
        // Safety: single CPU, and no other thread runs; `ctx` is this
        // process's context.
        unsafe {
            let (inner, ctx, state) = (&self.inner, &mut self.ctx, &mut self.user_state);
            if new {
                litebox_platform_vm_kernel::run_thread_ref(inner, ctx, state);
            } else if resume {
                litebox_platform_vm_kernel::resume_thread_ref(inner, ctx, state);
            } else {
                litebox_platform_vm_kernel::reenter_thread_ref(inner, ctx, state);
            }
        }
        self.deactivate();
        if !self.inner.preempted.get() && !self.inner.is_stopped() {
            self.inner.kill("returned to the kernel without waiting");
        }
    }
}
