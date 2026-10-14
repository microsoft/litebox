// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Round-robin scheduling of runner processes on the one CPU, with the
//! broker's worker.
//!
//! A process runs until it stops (waits for a request, or dies), blocks in a
//! broker wait, or its slice of [`QUANTUM`] ends; preemption and blocking are
//! transparent to it. A slice ends early once a blocked process may run (its
//! deadline, or a notification), and a process alone has none. Only user mode
//! is preempted.
//!
//! Between slices, the worker serves what processes submitted; one that
//! submits yields to it, and keeps the rest of its slice. The CPU halts only
//! when no process can run.

use crate::{Process, Suspended};
use alloc::vec::Vec;
use core::time::Duration;
use litebox_broker_vm_kernel::{EnterError, WaitState};
use litebox_common_vm_abi::Status;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::Instant;

/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_millis(10);

/// Runs `processes` until each one waits for a request (see
/// [`Process::submit`]) or is dead.
pub fn run(processes: &mut [&mut Process]) {
    let count = processes.len();
    let mut next = 0;
    loop {
        for process in processes.iter_mut() {
            process.serve_broker();
        }
        let turns: Vec<Turn> = processes.iter().map(|process| process.turn()).collect();
        // Polling published to a wait already polled.
        if processes
            .first()
            .is_some_and(|process| process.inner.broker.take_woken())
        {
            continue;
        }
        let Some(index) = (0..count)
            .map(|offset| (next + offset) % count)
            .find(|&index| turns[index] == Turn::Runnable)
        else {
            if !turns.iter().any(|turn| matches!(turn, Turn::Blocked(_))) {
                return;
            }
            let wake = turns.iter().filter_map(|turn| turn.wake()).min();
            if !processes[0].inner.broker.halt(wake) {
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
        // Also until the earliest wake, for that process to run then.
        let slice_end = others()
            .filter_map(|other| turns[other].wake())
            .chain(slice)
            .min();
        let process = &mut *processes[index];
        loop {
            process.run_slice(slice_end);
            if process.inner.suspended.get() != Suspended::Yielded {
                break;
            }
            // Served at once, it keeps the rest of its slice, unless a
            // blocked process may run now.
            process.serve_broker();
            let now = process.inner.platform.now();
            if process.inner.is_stopped()
                || slice_end.is_some_and(|slice_end| now >= slice_end)
                || process.inner.broker.take_woken()
            {
                break;
            }
        }
        next = index + 1;
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

impl Process {
    /// Runs the process until it stops, blocks, or `slice_end` passes (none:
    /// until it stops or blocks).
    fn run_slice(&mut self, slice_end: Option<Instant>) {
        self.inner.slice_end.set(slice_end);
        let new = self.inner.is_new();
        let resume = self.inner.suspended.get() != Suspended::No;
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
        if self.inner.suspended.get() == Suspended::No && !self.inner.is_stopped() {
            self.inner.kill("returned to the kernel without waiting");
        }
    }

    /// The broker's worker, for this process: serves what it submitted.
    fn serve_broker(&mut self) {
        if !self.inner.broker.has_submitted() || self.inner.is_dead() {
            return;
        }
        self.activate();
        // Demand-pages the shared buffers, as in its kernel calls.
        let result =
            litebox_platform_vm_kernel::with_user_faults(&self.inner, || self.inner.broker.serve());
        self.deactivate();
        if result.is_err() {
            self.inner.kill("broker association failed");
        }
    }

    /// Its [`Turn`]; ends its broker wait first, if it can.
    fn turn(&self) -> Turn {
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
        } else {
            Turn::Runnable
        }
    }
}
