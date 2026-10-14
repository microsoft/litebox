// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scheduling of runner processes on the one CPU, with the broker's worker.
//!
//! The runnable process that used the least CPU (its runs, and the worker's
//! serving of its requests) runs next; one back from waiting is due at most a
//! slice more than the others. So processes that wait (e.g., for files) run
//! soon after, and the others share the CPU.
//!
//! A process runs until it stops (waits for a request, or dies), blocks in a
//! broker wait, or its slice of [`QUANTUM`] ends; preemption and blocking are
//! transparent to it. A slice ends early once another may run (a blocked
//! process's deadline or notification, or the worker's deadline or a device
//! interrupt), and a process alone has none. Only user mode is preempted.
//!
//! Between slices, the worker serves what processes submitted, one process's
//! requests at a time, on its own stack ([`litebox_platform_vm_kernel::worker`]):
//! a request that waits for a device suspends it, and processes run
//! meanwhile. A process that submits yields to it, and, if served at once,
//! keeps the rest of its slice. The CPU halts only when nothing can run.

use crate::{Inner, Process, Suspended};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::time::Duration;
use litebox_broker_vm_kernel::{EnterError, WaitState};
use litebox_common_vm_abi::Status;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::Instant;
use litebox_platform_vm_kernel::worker::{self, Ran};

const QUANTUM_NANOS: u64 = 10_000_000;
/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_nanos(QUANTUM_NANOS);

/// Runs `processes` until each one waits for a request (see
/// [`Process::submit`]) or is dead.
pub fn run(processes: &mut [&mut Process]) {
    let count = processes.len();
    let mut next = 0;
    // The least CPU time of the processes that could run, as of the last slice.
    let mut floor: u64 = 0;
    // The process whose request the worker is suspended in.
    let mut serving = None;
    loop {
        serve(processes, &mut serving);
        let turns: Vec<Turn> = (0..count)
            .map(|index| processes[index].turn(serving == Some(index)))
            .collect();
        // Polling published to a wait already polled.
        if processes
            .first()
            .is_some_and(|process| process.inner.broker.take_woken())
        {
            continue;
        }
        let worker_wake = match worker::state() {
            worker::State::Suspended { wake } => wake,
            _ => None,
        };
        let runnable = || (0..count).filter(|&index| turns[index] == Turn::Runnable);
        // A process back from waiting (e.g., for a device) is due at most a
        // slice more than the others.
        for index in runnable() {
            let cpu_time = &processes[index].inner.cpu_time;
            cpu_time.set(cpu_time.get().max(floor.saturating_sub(QUANTUM_NANOS)));
        }
        // The one that used the least CPU; round-robin from `next` for ties.
        let Some(index) = (0..count)
            .map(|offset| (next + offset) % count)
            .filter(|&index| turns[index] == Turn::Runnable)
            .min_by_key(|&index| processes[index].inner.cpu_time.get())
        else {
            let blocked = turns.iter().any(|turn| matches!(turn, Turn::Blocked(_)));
            if !blocked && serving.is_none() {
                return;
            }
            let wake = turns
                .iter()
                .filter_map(|turn| turn.wake())
                .chain(worker_wake)
                .min();
            if !processes[0].inner.broker.halt(wake) && serving.is_none() {
                // Nothing could end a wait without a deadline.
                for (process, turn) in processes.iter().zip(&turns) {
                    if *turn == Turn::Blocked(None) {
                        process.inner.broker.abandon_wait();
                        process
                            .inner
                            .suspended
                            .set(Suspended::Woken(Err(Status::Stalled)));
                    }
                }
            }
            continue;
        };
        let others = || (0..count).filter(move |&other| other != index);
        let slice = others()
            .any(|other| turns[other] == Turn::Runnable)
            .then(|| {
                let now = processes[index].inner.platform.now();
                now.checked_add(QUANTUM)
                    .unwrap_or(Instant::from_nanos(u64::MAX))
            });
        // Also until the earliest wake, for that process, or the worker, to
        // run then.
        let slice_end = others()
            .filter_map(|other| turns[other].wake())
            .chain(slice)
            .chain(worker_wake)
            .min();
        let process = &mut *processes[index];
        loop {
            process.run_slice(slice_end);
            if process.inner.suspended.get() != Suspended::Yielded || serving.is_some() {
                break;
            }
            // Served at once, it keeps the rest of its slice, unless the
            // request waits for a device, or another may run now.
            if process.work(false) == Ran::Suspended {
                serving = Some(index);
                break;
            }
            let now = process.inner.platform.now();
            if process.inner.is_stopped()
                || slice_end.is_some_and(|slice_end| now >= slice_end)
                || process.inner.others_due()
            {
                break;
            }
        }
        next = index + 1;
        // Including that slice, but not processes that were waiting.
        let least = runnable()
            .map(|index| processes[index].inner.cpu_time.get())
            .min();
        floor = floor.max(least.unwrap_or(0));
    }
}

/// The broker's worker: resumes the request it was suspended in, if any,
/// then serves what processes submitted, until a request suspends it.
fn serve(processes: &mut [&mut Process], serving: &mut Option<usize>) {
    if let Some(index) = *serving {
        if processes[index].work(true) == Ran::Suspended {
            return;
        }
        *serving = None;
    }
    for (index, process) in processes.iter_mut().enumerate() {
        if process.inner.broker.has_submitted()
            && !process.inner.is_dead()
            && process.work(false) == Ran::Suspended
        {
            *serving = Some(index);
            return;
        }
    }
}

/// A process's state for one scheduling round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Runnable,
    /// Waits for a request, or is dead.
    Stopped,
    /// In a broker wait, until an event or the wake, if any.
    Blocked(Option<Instant>),
    /// Its requests are for the worker, which is suspended in one.
    Busy,
}

impl Turn {
    /// When a blocked process may become runnable without an event (`None`:
    /// never, or not blocked).
    fn wake(self) -> Option<Instant> {
        match self {
            Turn::Blocked(wake) => wake,
            _ => None,
        }
    }
}

impl Inner {
    /// Adds the CPU time since `start` (its run, or the worker's for it).
    fn charge(&self, start: Instant) {
        let used = self
            .platform
            .now()
            .as_nanos()
            .saturating_sub(start.as_nanos());
        self.cpu_time.set(self.cpu_time.get().saturating_add(used));
    }

    /// Whether another may need to run before this process's slice ends: a
    /// blocked process whose wait may end, or the suspended worker after a
    /// device interrupted.
    pub(crate) fn others_due(&self) -> bool {
        self.broker.take_woken()
            || (matches!(worker::state(), worker::State::Suspended { .. })
                && self.broker.take_device_interrupt())
    }
}

impl Process {
    /// Runs the process until it stops, blocks, or `slice_end` passes (none:
    /// until it stops or blocks).
    fn run_slice(&mut self, slice_end: Option<Instant>) {
        let start = self.inner.platform.now();
        self.inner.slice_end.set(slice_end);
        let new = self.inner.is_new();
        let resume = self.inner.suspended.get() != Suspended::No;
        self.activate();
        // Safety: single CPU, and no other thread runs; `ctx` is this
        // process's context.
        unsafe {
            let (inner, ctx, state) = (&*self.inner, &mut self.ctx, &mut self.user_state);
            if new {
                litebox_platform_vm_kernel::run_thread_ref(inner, ctx, state);
            } else if resume {
                litebox_platform_vm_kernel::resume_thread_ref(inner, ctx, state);
            } else {
                litebox_platform_vm_kernel::reenter_thread_ref(inner, ctx, state);
            }
        }
        self.deactivate();
        self.inner.charge(start);
        if self.inner.suspended.get() == Suspended::No && !self.inner.is_stopped() {
            self.inner.kill("returned to the kernel without waiting");
        }
    }

    /// Has the worker serve what the process submitted, or `resume` serving
    /// it, in its address space, until done or suspended.
    fn work(&mut self, resume: bool) -> Ran {
        let start = self.inner.platform.now();
        self.activate();
        // The work looks at the devices itself.
        let _ = self.inner.broker.take_device_interrupt();
        let ran = if resume {
            worker::resume()
        } else {
            // Its own reference: the scheduler takes `&mut Process`es while
            // the work is suspended.
            let inner = self.inner.clone();
            worker::start(
                self.inner.platform,
                Box::new(move || {
                    // Demand-pages the shared buffers, as in its kernel calls.
                    let result = litebox_platform_vm_kernel::with_user_faults(&*inner, || {
                        inner.broker.serve()
                    });
                    if result.is_err() {
                        inner.kill("broker association failed");
                    }
                }),
            )
        };
        self.deactivate();
        self.inner.charge(start);
        ran
    }

    /// Its [`Turn`], given whether the worker is suspended serving it; ends
    /// its broker wait first, if it can.
    fn turn(&self, served: bool) -> Turn {
        if served {
            return Turn::Busy;
        }
        if let Suspended::Waiting(wait) = self.inner.suspended.get() {
            let woken = match self.inner.broker.poll_wait(&wait) {
                WaitState::Blocked { wake } => return Turn::Blocked(wake),
                WaitState::Ended(Ok(())) => Ok(()),
                WaitState::Ended(Err(EnterError::Status(status))) => Err(status),
                WaitState::Ended(Err(EnterError::Failed)) => {
                    self.inner.kill("broker association failed");
                    return Turn::Stopped;
                }
            };
            self.inner.suspended.set(Suspended::Woken(woken));
        }
        if self.inner.is_stopped() {
            Turn::Stopped
        } else if self.inner.suspended.get() == Suspended::Yielded
            && self.inner.broker.has_submitted()
        {
            // Queued for the worker.
            Turn::Busy
        } else {
            Turn::Runnable
        }
    }
}
