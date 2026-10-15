// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scheduling of runner processes' threads on the one CPU, with the broker's
//! worker.
//!
//! The runnable thread that used the least CPU runs next: its runs, and the
//! worker's serving of its process's requests, charged to the thread that
//! made the last broker call (the main thread, if that one exited or none
//! did; see `Inner::broker_requester`). One back from waiting is due at
//! most a slice more than the others. So threads that wait (e.g., for files)
//! run soon after, and the others share the CPU.
//!
//! A thread runs until it stops (exits, or, for the main thread, waits for a
//! request; or its process dies), blocks in a broker or futex wait, or its
//! slice of [`QUANTUM`] ends; preemption and blocking are transparent to it.
//! A slice ends early once another may run (a blocked thread's deadline or
//! notification, or the worker's deadline or a device interrupt), and a
//! thread alone has none. Only user mode is preempted.
//!
//! Between slices, the worker serves what processes submitted, one process's
//! requests at a time, on its own stack ([`litebox_platform_vm_kernel::worker`]):
//! a request that waits for a device suspends it, and threads run meanwhile,
//! but not with that process's broker association, which the worker is using:
//! a thread's broker call waits for the worker. A thread that submits yields
//! to it, and, if served at once, keeps the rest of its slice. The CPU halts
//! only when nothing can run.

use crate::thread::{FutexState, Thread};
use crate::{Inner, Process, Running, Suspended};
use alloc::boxed::Box;
use alloc::rc::Rc;
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
    let mut next = 0;
    // The least CPU time of the threads that could run, as of the last slice.
    let mut floor: u64 = 0;
    // The process whose request the worker is suspended in.
    let mut serving = None;
    loop {
        serve(processes, &mut serving);
        for (index, process) in processes.iter().enumerate() {
            process.inner.broker_busy.set(serving == Some(index));
        }
        let threads: Vec<(usize, Rc<Thread>)> = processes
            .iter()
            .enumerate()
            .flat_map(|(index, process)| {
                let threads = process.inner.threads.borrow().clone();
                threads.into_iter().map(move |thread| (index, thread))
            })
            .collect();
        // Before polling, which may publish (e.g., input) to a process
        // polled already; after, as polling ended waits.
        let mark_notification_waiters = || {
            for process in processes.iter() {
                process.inner.mark_notification_waiter();
            }
        };
        mark_notification_waiters();
        let turns: Vec<Turn> = threads
            .iter()
            .map(|(index, thread)| processes[*index].inner.turn(thread))
            .collect();
        mark_notification_waiters();
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
        let count = threads.len();
        let runnable = || (0..count).filter(|&index| turns[index] == Turn::Runnable);
        // A thread back from waiting (e.g., for a device) is due at most a
        // slice more than the others.
        for index in runnable() {
            let cpu_time = &threads[index].1.cpu_time;
            cpu_time.set(cpu_time.get().max(floor.saturating_sub(QUANTUM_NANOS)));
        }
        // The one that used the least CPU; round-robin from `next` for ties.
        let Some(index) = (0..count)
            .map(|offset| (next + offset) % count)
            .filter(|&index| turns[index] == Turn::Runnable)
            .min_by_key(|&index| threads[index].1.cpu_time.get())
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
                for ((owner, thread), turn) in threads.iter().zip(&turns) {
                    if *turn == Turn::Blocked(None) {
                        processes[*owner].inner.broker.abandon_wait();
                        thread.suspended.set(Suspended::Woken(Err(Status::Stalled)));
                    }
                }
            }
            continue;
        };
        let others = || (0..count).filter(move |&other| other != index);
        let (owner, thread) = &threads[index];
        let process = &mut *processes[*owner];
        let slice = others()
            .any(|other| turns[other] == Turn::Runnable)
            .then(|| {
                let now = process.inner.platform.now();
                now.checked_add(QUANTUM)
                    .unwrap_or(Instant::from_nanos(u64::MAX))
            });
        // Also until the earliest wake, for that thread, or the worker, to
        // run then.
        let mut slice_end = others()
            .filter_map(|other| turns[other].wake())
            .chain(slice)
            .chain(worker_wake)
            .min();
        loop {
            process.run_slice(thread, slice_end);
            // The slice may have been cut short (see `Inner::share_cpu`).
            slice_end = process.inner.slice_end.get();
            if thread.suspended.get() != Suspended::Yielded || serving.is_some() {
                break;
            }
            // Served at once, it keeps the rest of its slice, unless the
            // request waits for a device, or another may run now.
            if process.work(false) == Ran::Suspended {
                serving = Some(*owner);
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
        // Including that slice, but not threads that were waiting.
        let least = runnable()
            .map(|index| threads[index].1.cpu_time.get())
            .min();
        floor = floor.max(least.unwrap_or(0));
    }
}

/// Whether a notification may end `thread`'s wait: a futex wait (see
/// [`Inner::poll_futex`]), or a broker wait on the notification epoch. Its
/// process is then a notification waiter (see
/// [`Inner::mark_notification_waiter`]).
fn waits_for_notifications(thread: &Thread) -> bool {
    match thread.suspended.get() {
        Suspended::Futex(_) => true,
        Suspended::Waiting(wait) => wait.is_for_notifications(),
        _ => false,
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

/// A thread's state for one scheduling round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Runnable,
    /// Exited, waits for a request, or its process is dead.
    Stopped,
    /// In a broker or futex wait, until an event or the wake, if any.
    Blocked(Option<Instant>),
    /// Its broker call is for the worker, which is busy.
    Busy,
}

impl Turn {
    /// When a blocked thread may become runnable without an event (`None`:
    /// never, or not blocked).
    fn wake(self) -> Option<Instant> {
        match self {
            Turn::Blocked(wake) => wake,
            _ => None,
        }
    }
}

impl Inner {
    /// Whether another may need to run before the running thread's slice
    /// ends: a blocked thread whose wait may end, or the suspended worker
    /// after a device interrupted.
    pub(crate) fn others_due(&self) -> bool {
        self.broker.take_woken()
            || (matches!(worker::state(), worker::State::Suspended { .. })
                && self.broker.take_device_interrupt())
    }

    /// Tells the broker whether a thread of the process waits for
    /// notifications, so that one published to it sets `take_woken`: the
    /// scheduler polls the waits again.
    fn mark_notification_waiter(&self) {
        let waiting = self
            .threads
            .borrow()
            .iter()
            .any(|thread| !thread.exited.get() && waits_for_notifications(thread));
        self.broker.set_notification_waiter(waiting);
    }

    /// Another thread of the process became runnable as one runs (it created
    /// or woke it), which the slice end did not account for (e.g., none, as
    /// alone, or a blocked thread's distant wake): it ends a slice from now at
    /// the latest, so that the other runs then.
    pub(crate) fn share_cpu(&self) {
        let end = self
            .platform
            .now()
            .checked_add(QUANTUM)
            .unwrap_or(Instant::from_nanos(u64::MAX));
        let slice_end = self
            .slice_end
            .get()
            .map_or(end, |slice_end| slice_end.min(end));
        self.slice_end.set(Some(slice_end));
    }

    /// `thread`'s [`Turn`]; ends its wait first, if it can.
    fn turn(&self, thread: &Thread) -> Turn {
        // Before polling a wait, which a stopped process's threads have none
        // of to end.
        if thread.exited.get() || self.is_stopped() {
            return Turn::Stopped;
        }
        let suspended = thread.suspended.get();
        if self.broker_busy.get()
            && matches!(
                suspended,
                Suspended::Yielded | Suspended::Waiting(_) | Suspended::Retry
            )
        {
            return Turn::Busy;
        }
        let woken = match suspended {
            Suspended::Waiting(wait) => match self.broker.poll_wait(&wait) {
                WaitState::Blocked { wake } => return Turn::Blocked(wake),
                WaitState::Ended(Ok(())) => Some(Ok(())),
                WaitState::Ended(Err(EnterError::Status(status))) => Some(Err(status)),
                WaitState::Ended(Err(EnterError::Failed)) => {
                    self.kill("broker association failed");
                    return Turn::Stopped;
                }
            },
            Suspended::Futex(wait) => match self.poll_futex(thread, &wait) {
                FutexState::Blocked { wake } => return Turn::Blocked(wake),
                FutexState::Ended(result) => Some(result),
            },
            _ => None,
        };
        if let Some(woken) = woken {
            thread.suspended.set(Suspended::Woken(woken));
        }
        if self.is_stopped() {
            // Polling killed it.
            Turn::Stopped
        } else if thread.suspended.get() == Suspended::Yielded && self.broker.has_submitted() {
            // Queued for the worker.
            Turn::Busy
        } else {
            Turn::Runnable
        }
    }
}

impl Process {
    /// Runs `thread` until it stops, blocks, or `slice_end` passes (none:
    /// until it stops or blocks).
    fn run_slice(&mut self, thread: &Thread, slice_end: Option<Instant>) {
        let start = self.inner.platform.now();
        self.inner.slice_end.set(slice_end);
        let new = self.inner.is_new();
        let resume = thread.suspended.get() != Suspended::No;
        self.activate_thread(thread);
        {
            let running = Running {
                inner: &self.inner,
                thread,
            };
            let mut ctx = thread.ctx.borrow_mut();
            let mut state = thread.user_state.borrow_mut();
            let (ctx, state) = (&mut *ctx, &mut *state);
            // Safety: single CPU, and no other thread runs; `ctx` is this
            // thread's context.
            unsafe {
                if new {
                    litebox_platform_vm_kernel::run_thread_ref(&running, ctx, state);
                } else if resume {
                    litebox_platform_vm_kernel::resume_thread_ref(&running, ctx, state);
                } else {
                    litebox_platform_vm_kernel::reenter_thread_ref(&running, ctx, state);
                }
            }
        }
        self.deactivate_thread(thread);
        thread.charge(self.inner.platform, start);
        if thread.exited.get() {
            self.inner.reap(thread);
        } else if thread.suspended.get() == Suspended::No && !self.inner.is_stopped() {
            self.inner.kill("returned to the kernel without waiting");
        }
    }

    /// Has the worker serve what the process submitted, or `resume` serving
    /// it, in its address space, until done or suspended. Charged to the
    /// thread that made the last broker call (see
    /// [`Inner::broker_requester`]): the requests of several at once are
    /// charged to one.
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
                    let main = inner.main_thread();
                    let running = Running {
                        inner: &inner,
                        thread: &main,
                    };
                    // Demand-pages the shared buffers, as in its kernel calls.
                    let result = litebox_platform_vm_kernel::with_user_faults(&running, || {
                        inner.broker.serve()
                    });
                    if result.is_err() {
                        inner.kill("broker association failed");
                    }
                }),
            )
        };
        self.deactivate();
        self.inner
            .broker_requester()
            .charge(self.inner.platform, start);
        ran
    }
}
