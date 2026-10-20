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
//! A thread that clones its process stops in the call, for the clone to be
//! made once its run ended (see `crate::fork`); it keeps the rest of its
//! slice, to release what it held across the call.
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
use crate::{Inner, Running, State, Suspended};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::time::Duration;
use litebox_broker_vm_kernel::{EnterError, WaitState};
use litebox_common_vm_abi::Status;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::Instant;
use litebox_platform_vm_kernel::worker::{self, Ran};

const QUANTUM_NANOS: u64 = 10_000_000;
/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_nanos(QUANTUM_NANOS);

/// The kernel's scheduler, which every runner process runs in from its
/// creation until it dies, whether a service spawned it
/// ([`crate::Process::spawn`]) or it is a launched process (see
/// [`crate::ProcessConfig::started_runner`]). Like Linux's run queue, it
/// belongs to the kernel, not to a caller: a caller runs it until what it
/// waits for happens (e.g., a reply), and every process runs meanwhile. Clones
/// share it.
#[derive(Clone, Default)]
pub struct Scheduler(Rc<RefCell<RunQueue>>);

#[derive(Default)]
struct RunQueue {
    /// The live processes, and the dead one the worker is serving, if any.
    processes: Vec<Rc<Inner>>,
    /// Where the round-robin for ties starts.
    next: usize,
    /// The least CPU time of the threads that could run, as of the last
    /// slice.
    floor: u64,
    /// The process whose request the worker is suspended in.
    serving: Option<Rc<Inner>>,
}

impl Scheduler {
    /// Runs the processes until `done`, checked between steps, or until each
    /// waits for a request or is dead, without checking `done` after that
    /// last step.
    pub fn run_until(&self, mut done: impl FnMut() -> bool) {
        let mut queue = self.0.borrow_mut();
        while !done() && queue.step() {}
    }

    /// Runs the processes until each waits for a request or is dead, as the
    /// userland broker waits for its runners to drain.
    pub fn run_until_idle(&self) {
        self.run_until(|| false);
    }

    pub(crate) fn add(&self, process: Rc<Inner>) {
        self.0.borrow_mut().processes.push(process);
    }

    /// Drops the dead processes, but one the broker's worker serves, which
    /// releases their address spaces unless a [`crate::Process`] holds them.
    pub fn reap(&self) {
        self.0.borrow_mut().reap();
    }
}

impl RunQueue {
    /// [`Self::reap`], then [`Self::schedule`].
    fn step(&mut self) -> bool {
        self.reap();
        self.schedule()
    }

    /// Drops the dead processes, but the one the worker is serving, which
    /// releases their address spaces unless a [`crate::Process`] holds them.
    fn reap(&mut self) {
        let serving = self.serving.clone();
        self.processes.retain(|process| {
            !process.is_dead()
                || serving
                    .as_ref()
                    .is_some_and(|serving| Rc::ptr_eq(serving, process))
        });
    }

    /// Serves the broker, then runs one thread for a slice, or halts until
    /// one can run. False once each process waits for a request or is dead,
    /// and the worker is not suspended. Once children were started (even if
    /// their runner processes could not be created), runs no thread, so the
    /// next step resumes the worker, which waits for them.
    fn schedule(&mut self) -> bool {
        self.serve();
        let mut spawned = Vec::new();
        let mut started = false;
        for process in &self.processes {
            started |= process.spawn_launched(&mut spawned);
        }
        if started {
            self.processes.extend(spawned);
            return true;
        }
        let Self {
            processes,
            next,
            floor,
            serving,
        } = self;
        for process in processes.iter() {
            let busy = serving
                .as_ref()
                .is_some_and(|serving| Rc::ptr_eq(serving, process));
            process.broker_busy.set(busy);
        }
        let threads: Vec<(usize, Rc<Thread>)> = processes
            .iter()
            .enumerate()
            .flat_map(|(index, process)| {
                let threads = process.threads.borrow().clone();
                threads.into_iter().map(move |thread| (index, thread))
            })
            .collect();
        // Before polling, which may publish (e.g., input) to a process
        // polled already; after, as polling ended waits.
        let mark_notification_waiters = || {
            for process in processes.iter() {
                process.mark_notification_waiter();
            }
        };
        mark_notification_waiters();
        let turns: Vec<Turn> = threads
            .iter()
            .map(|(index, thread)| processes[*index].turn(thread))
            .collect();
        mark_notification_waiters();
        // Polling published to a wait already polled.
        if processes
            .first()
            .is_some_and(|process| process.broker.take_woken())
        {
            return true;
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
            .map(|offset| (*next + offset) % count)
            .filter(|&index| turns[index] == Turn::Runnable)
            .min_by_key(|&index| threads[index].1.cpu_time.get())
        else {
            let blocked = turns.iter().any(|turn| matches!(turn, Turn::Blocked(_)));
            if !blocked && serving.is_none() {
                return false;
            }
            let wake = turns
                .iter()
                .filter_map(|turn| turn.wake())
                .chain(worker_wake)
                .min();
            if !processes[0].broker.halt(wake) && serving.is_none() {
                // Nothing could end a wait without a deadline.
                for ((owner, thread), turn) in threads.iter().zip(&turns) {
                    if *turn == Turn::Blocked(None) {
                        processes[*owner].broker.abandon_wait();
                        thread.suspended.set(Suspended::Woken(Err(Status::Stalled)));
                    }
                }
            }
            return true;
        };
        let others = || (0..count).filter(move |&other| other != index);
        let (owner, thread) = &threads[index];
        let process = &processes[*owner];
        let slice = others()
            .any(|other| turns[other] == Turn::Runnable)
            .then(|| {
                let now = process.platform.now();
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
        // Run from the next step on.
        let mut clones = Vec::new();
        loop {
            clones.extend(process.run_slice(thread, slice_end));
            // Those that ended (e.g., replaced by a later one): freed here,
            // between runs, as freeing one switches address spaces.
            clones.retain(|clone| !clone.is_dead());
            debug_assert!(
                clones.len() <= 1,
                "a process has at most one clone to adopt"
            );
            // The slice may have been cut short (see `Inner::share_cpu`).
            slice_end = process.slice_end.get();
            match thread.suspended.get() {
                // Served at once, it keeps the rest of its slice, unless the
                // request waits for a device.
                Suspended::Yielded if serving.is_none() => {
                    if process.work(false) == Ran::Suspended {
                        *serving = Some(process.clone());
                        break;
                    }
                }
                // It keeps the rest of its slice too, for the runner to let go
                // of what it held across the call.
                Suspended::Cloned { .. } => {}
                _ => break,
            }
            // Unless another may run now.
            let now = process.platform.now();
            if process.is_stopped()
                || slice_end.is_some_and(|slice_end| now >= slice_end)
                || process.others_due()
            {
                break;
            }
        }
        processes.extend(clones);
        *next = index + 1;
        // Including that slice, but not threads that were waiting.
        let least = runnable()
            .map(|index| threads[index].1.cpu_time.get())
            .min();
        *floor = (*floor).max(least.unwrap_or(0));
        true
    }

    /// The broker's worker: resumes the request it was suspended in, if any,
    /// then serves what processes submitted, until a request suspends it.
    fn serve(&mut self) {
        if let Some(process) = &self.serving {
            if process.work(true) == Ran::Suspended {
                return;
            }
            self.serving = None;
        }
        for process in &self.processes {
            if process.broker.has_submitted()
                && !process.is_dead()
                && process.work(false) == Ran::Suspended
            {
                self.serving = Some(process.clone());
                return;
            }
        }
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
        // of to end. A clone that was not adopted runs nothing, and a thread
        // is made a process clone of once its run ends, never later.
        if thread.exited.get()
            || self.is_stopped()
            || matches!(*self.state.borrow(), State::Cloned { .. })
            || matches!(thread.suspended.get(), Suspended::Forking { .. })
        {
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

impl Inner {
    /// Runs `thread` until it stops, blocks, or `slice_end` passes (none:
    /// until it stops or blocks). Returns the process clone it made, if any
    /// (see `crate::fork`), for the scheduler to run.
    fn run_slice(&self, thread: &Thread, slice_end: Option<Instant>) -> Option<Rc<Self>> {
        let start = self.platform.now();
        self.slice_end.set(slice_end);
        let new = self.is_new();
        let resume = thread.suspended.get() != Suspended::No;
        self.activate_thread(thread);
        {
            let running = Running {
                inner: self,
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
        // Once the run saved the thread's state.
        let clone = match thread.suspended.get() {
            Suspended::Forking { slot } => self.fork(thread, slot),
            _ => None,
        };
        thread.charge(self.platform, start);
        if thread.exited.get() {
            self.reap(thread);
        } else if thread.suspended.get() == Suspended::No && !self.is_stopped() {
            self.kill("returned to the kernel without waiting");
        }
        clone
    }

    /// Has the worker serve what the process submitted, or `resume` serving
    /// it, in its address space, until done or suspended. Charged to the
    /// thread that made the last broker call (see
    /// [`Inner::broker_requester`]): the requests of several at once are
    /// charged to one.
    fn work(self: &Rc<Self>, resume: bool) -> Ran {
        let start = self.platform.now();
        self.activate();
        // The work looks at the devices itself.
        let _ = self.broker.take_device_interrupt();
        let ran = if resume {
            worker::resume()
        } else {
            // Its own reference: the work may outlast the step.
            let inner = self.clone();
            worker::start(
                self.platform,
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
        self.broker_requester().charge(self.platform, start);
        ran
    }
}
