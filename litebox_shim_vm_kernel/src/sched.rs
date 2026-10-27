// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scheduling of runner processes' threads and brokers on the CPUs.
//!
//! One run queue ([`Scheduler`]) holds every process. Each CPU takes steps
//! (the boot CPU in [`Scheduler::run_until`], between its services' calls;
//! the others in [`Scheduler::run`]): it polls the processes, then runs the
//! best runnable entity, a thread for a slice, or a process's broker for a
//! batch, or halts until the earliest wake it saw. It works on a process
//! under its claim (see `claim`), which it hands to the thread it runs, so
//! that other CPUs may run the process's other threads meanwhile (see
//! `Running`). Polls skip the threads that run, but first finish the runs of
//! those parked (see `finish_parked`).
//!
//! The runnable entity that used the least CPU runs next, ties going
//! round-robin in creation order; one back from waiting is due at most a slice
//! more than the others (see `key` and `counted`). A thread runs until it
//! stops, blocks in a broker or futex wait, or its slice of [`QUANTUM`] ends,
//! earlier if another may run then, but only once the thread ran a while (see
//! `Shared::run_best`). Only user mode is preempted, transparently.
//!
//! Each process's broker is an entity too: a cooperative task (see
//! `Inner::task`) that serves at most `BATCH` of the requests the process's
//! threads published, charged to the broker alone (see `Shared::run_broker`);
//! and, once the process is dead, ends its association, releasing what it
//! holds, before the process is forgotten (see `Shared::reap`). A request
//! that waits (e.g., for a device, a lock, or a child process's start)
//! suspends the task: threads run meanwhile, on any CPU, but their broker
//! calls wait for it, and only its CPU resumes it, once its wait may have
//! ended ([`worker::Task::is_due`]). A CPU may hold any number of suspended
//! brokers. A batch runs under its process's claim, and suspends holding no
//! other claim (see `batch`); one that finished frees its broker for any CPU.
//!
//! What may make work for another CPU wakes it (see `claim` and
//! [`litebox_platform_vm_kernel::cpu`]): adding a process, releasing one with
//! work left, or one it found claimed; a notification to a waiting process,
//! which has every CPU look again within `NOTIFIED`; and whatever may end a
//! suspended broker's wait (see [`worker::wake_blocked`]), which interrupts
//! the busy CPUs holding suspended brokers ([`worker::due`]), to look again
//! within `NOTIFIED` too.
//!
//! An entity's CPU time includes the step that chose it: each dispatch pays
//! for the scan of every process before it, however short the dispatch.
//!
//! Nothing runs once every process waits for a request, is dead (its
//! association ended), or is a process clone not adopted yet, none is claimed,
//! no thread runs, and no broker is suspended. Waits that nothing could end
//! ([`Status::Stalled`]) are abandoned by the boot CPU, once no other CPU runs
//! anything.
//!
//! Known limitations:
//! - A thread's run, the step that chose it, and a broker's dispatch (its step
//!   and batch) are each charged at most one slice of CPU time (see
//!   `charged`), because the clock cannot tell long kernel work from time the
//!   host did not run the vCPU. An entity whose dispatches regularly exceed a
//!   slice therefore gets more than its share of the CPU.
//! - A notification to any waiting process shortens every busy CPU's slice.
//! - A process running on another CPU, with no thread waiting for
//!   notifications, sees one only at its next kernel entry, at the latest as
//!   its slice ends.
//! - Waking suspended brokers is global: each [`worker::wake_blocked`] (on a
//!   contended platform lock's release, a process's lifecycle change, e.g.,
//!   its start or exit, a child's start handed off to its parent's task, or
//!   a device's interrupt) advances the one wake generation, which makes
//!   every suspended broker due, on every CPU, and interrupts every CPU
//!   holding one, busy or idle, but the waker's, which looks at its own (for
//!   a device's, the boot CPU's): a thread such a CPU runs makes way within
//!   `NOTIFIED`, once it ran a while (see `admitted`). That is correct, as no
//!   wake is lost, but each costs every CPU holding a suspended broker a
//!   look, and every suspended broker a resume, spurious unless its own wait
//!   ended: a global cost, growing with the CPUs and brokers suspended. Nor
//!   is `NOTIFIED` a latency bound: a CPU busy in the kernel (e.g., in a
//!   batch's request) looks only once done.
//! - While the boot CPU runs its services, the brokers suspended on it wait.
//! - A batch is bounded by requests, not time: a request runs until it
//!   finishes or suspends (e.g., in a 9P round trip), and a dead process's
//!   resources are released only as its broker's next batch ends its
//!   association.
//! - A thread whose kernel entry finds its process's claim held past a brief
//!   spin (e.g., by a broker's batch, or by its other threads' entries) is
//!   parked, as is ordinary under contention (see [`Scheduler::parks`]),
//!   until a step claims the process again. Its CPU steps again at once, and
//!   wakes the idle CPUs; but if the claim is still held, and no CPU is idle
//!   once it is released, the thread waits for a busy CPU's next step, up to
//!   a slice later.

use crate::claim::{Claim, Owned};
use crate::thread::{FutexState, Thread};
use crate::{Ended, Inner, Running, Suspended, Unclaimed};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_vm_kernel::{EnterError, Events, WaitState};
use litebox_common_vm_abi::Status;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::Instant;
use litebox_platform_vm_kernel::cpu::{self, CpuId, MAX_CPUS};
use litebox_platform_vm_kernel::worker::{self, Ran};
use spin::mutex::SpinMutex;

const QUANTUM_NANOS: u64 = 10_000_000;
/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_nanos(QUANTUM_NANOS);
/// With other CPUs online, at most how long a thread still runs once its CPU
/// is notified (see `Inner::take_notified`; alone, it stops at once): a
/// notification tells every CPU, and this is so that a stream of
/// notifications does not stop every CPU's thread at once. Also the least a
/// thread runs, once admitted, before its slice ends for others' sake (see
/// [`admitted`]).
const NOTIFIED: Duration = Duration::from_nanos(QUANTUM_NANOS / 10);
/// At most how many requests a broker serves per batch: a quarter of its
/// request ring, so that one whose process keeps making requests is compared
/// with the other entities again after each batch.
const BATCH: usize = 16;

/// The kernel's scheduler, which every runner process runs in from its
/// creation until it dies, whether a service spawned it
/// ([`crate::Process::spawn`]) or it is a launched process (see
/// [`crate::ProcessConfig::started_runner`]). Like Linux's run queue, it
/// belongs to the kernel, not to a caller: a caller runs it until what it
/// waits for happens (e.g., a reply), and every process runs meanwhile, on
/// every CPU. Its `Clone`s share it.
#[derive(Clone)]
pub struct Scheduler(Arc<Shared>);

struct Shared {
    /// Held only for short list operations: never while running, polling,
    /// serving, spawning, halting, or dropping a process.
    queue: SpinMutex<RunQueue>,
    /// Per CPU, by index; shared with the processes, which count the attempts
    /// to take their claims there (see `Owned`).
    counts: Arc<[CpuCounts; MAX_CPUS]>,
    /// To halt with.
    events: &'static dyn Events,
    /// The next [`Owned::seq`].
    next_seq: AtomicU64,
}

/// A CPU's counts, which only it changes: on a cache line of its own, so that
/// CPUs counting at once (e.g., on every kernel entry) do not contend.
#[derive(Default)]
#[repr(align(64))]
pub(crate) struct CpuCounts {
    /// Its attempts to take a claim of the scheduler's processes, each
    /// counted just before it is made, taken or not (see
    /// [`Shared::claim_attempts`]).
    pub(crate) claims: AtomicU64,
    /// The slices it ran.
    slices: AtomicU64,
    /// The threads it parked (see [`Scheduler::parks`]).
    parks: AtomicU64,
}

#[derive(Default)]
struct RunQueue {
    /// The live processes, and the dead ones whose brokers have yet to end
    /// their associations (see [`Owned::is_quiescent`]).
    processes: Vec<Arc<Owned>>,
    /// Where the round-robin for ties starts: after this entity.
    last: Id,
    /// The least CPU time of the entities that could run, as of the last
    /// dispatch (of any CPU).
    floor: u64,
}

impl Scheduler {
    /// One that halts with `events` (see [`Events::wait`]) when no process
    /// can run: the runner's.
    pub fn new(events: &'static dyn Events) -> Self {
        Self(Arc::new(Shared {
            queue: SpinMutex::new(RunQueue::default()),
            counts: Arc::new(core::array::from_fn(|_| CpuCounts::default())),
            events,
            next_seq: AtomicU64::new(1),
        }))
    }

    /// Runs the processes until `done`, checked between steps, or until
    /// nothing runs (see the [module](self) docs), without checking `done`
    /// after that last step. On the boot CPU, which a process that stops
    /// wakes: so `done` must change only as processes stop (e.g.,
    /// [`crate::Process::is_stopped`]). Between calls, the brokers suspended
    /// on this CPU wait (see the module docs).
    pub fn run_until(&self, mut done: impl FnMut() -> bool) {
        debug_assert_eq!(cpu::current(), CpuId::BOOT, "services run on the boot CPU");
        loop {
            // Before looking, at `done` too (see `cpu::acknowledge`).
            cpu::acknowledge();
            if done() || !self.0.step() {
                break;
            }
        }
    }

    /// Runs the processes until nothing runs, as the userland broker waits
    /// for its runners to drain.
    pub fn run_until_idle(&self) {
        self.run_until(|| false);
    }

    /// Runs the processes on a CPU other than the boot CPU, forever.
    pub fn run(&self) -> ! {
        debug_assert_ne!(cpu::current(), CpuId::BOOT, "the boot CPU runs services");
        loop {
            cpu::acknowledge();
            if !self.0.step() {
                cpu::halt();
            }
        }
    }

    /// How many slices each online CPU ran, in order, for diagnostics.
    pub fn slices(&self) -> Vec<u64> {
        cpu::online()
            .map(|cpu| self.0.counts[cpu.index()].slices.load(Ordering::Relaxed))
            .collect()
    }

    /// How many times each online CPU, in order, parked a thread whose entry
    /// found its process's claim held past a brief spin, for diagnostics: an
    /// ordinary outcome of contention for a process (e.g., its threads
    /// entering the kernel at once; see the [module](self) docs).
    pub fn parks(&self) -> Vec<u64> {
        cpu::online()
            .map(|cpu| self.0.counts[cpu.index()].parks.load(Ordering::Relaxed))
            .collect()
    }

    /// Publishes `inner` (see [`Shared::add`]).
    pub(crate) fn add(&self, inner: Inner) -> Arc<Owned> {
        let process = self.0.own(inner);
        self.0.add(process.clone());
        process
    }

    /// Forgets the dead processes whose brokers ended their associations,
    /// with no batch left suspended, which releases their address spaces
    /// unless a [`crate::Process`] holds them. Another CPU may release some a
    /// moment later (e.g., ones its step holds, or that it forgot first).
    pub fn reap(&self) {
        self.0.reap();
    }
}

/// A process's schedulable entity (see the [module](self) docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Entity {
    /// By ID.
    Thread(u64),
    #[default]
    Broker,
}

/// An entity, in the round-robin order: its process's [`Owned::seq`], then
/// its place in the process.
type Id = (u64, Entity);

/// Ordering of runnable entities, least first: by CPU time, then
/// round-robin, from after [`RunQueue::last`] (see [`key`]).
type Key = (u64, bool, u64, Entity);

/// The key of entity `id`, which used `time`, with `last` the last to run.
fn key(time: u64, id: Id, last: Id) -> Key {
    (time, id <= last, id.0, id.1)
}

/// [`RunQueue::floor`] once an entity ran, which then used `time` (that run
/// included), with the others that could run having used `others`.
fn floor_after(floor: u64, time: u64, others: impl IntoIterator<Item = u64>) -> u64 {
    floor.max(others.into_iter().fold(time, u64::min))
}

/// The end of a slice that ends at `slice_end` (none: no end) once it is to
/// end `duration` after `now` at the latest: never later.
fn ended_by(slice_end: Option<Instant>, now: Instant, duration: Duration) -> Instant {
    let end = now
        .checked_add(duration)
        .unwrap_or(Instant::from_nanos(u64::MAX));
    slice_end.map_or(end, |slice_end| slice_end.min(end))
}

/// The end of a slice that ends at `slice_end` (none: no end) as its thread
/// first returns to ring 3 in a run, at `now`: no sooner than [`NOTIFIED`]
/// from then, if it ends earlier for others' sake (e.g., at a blocked broker's
/// deadline the step saw, which may have passed since), so that the thread
/// runs before the scheduler looks again, but by the end of its `quantum`, if
/// any.
fn admitted(slice_end: Option<Instant>, quantum: Option<Instant>, now: Instant) -> Option<Instant> {
    let soon = now
        .checked_add(NOTIFIED)
        .unwrap_or(Instant::from_nanos(u64::MAX));
    let end = slice_end?.max(soon);
    Some(quantum.map_or(end, |quantum| end.min(quantum)))
}

/// Whether a run's thread is yet to return to ring 3 in it (see [`admitted`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// A fresh run's, whose thread's quantum ends at `quantum` (none: no end).
    Pending { quantum: Option<Instant> },
    /// It did, or the run continues one where it did (see `crate::fork`).
    Done,
}

/// What a step runs: a thread of the process, or its broker.
enum Chosen {
    Thread(Arc<Thread>),
    Broker,
}

/// The entity a step runs.
struct Best<'a> {
    claim: Claim<'a>,
    chosen: Chosen,
    key: Key,
    /// Its process has another runnable entity.
    siblings: bool,
}

/// What a step found, polling the processes it claimed.
#[derive(Default)]
struct Found<'a> {
    best: Option<Best<'a>>,
    /// The least CPU time of the other runnable entities.
    others: Option<u64>,
    /// That of the processes held by other CPUs, as last polled (see
    /// [`Owned::runnable`]).
    held: Option<u64>,
    /// The earliest of the blocked threads' and brokers' wakes; and if it
    /// could not claim the process of a broker suspended on this CPU,
    /// [`NOTIFIED`] from then.
    wake: Option<Instant>,
    blocked: bool,
    /// A thread's broker call waits for its broker.
    busy: bool,
    /// The threads blocked with no wake, as they were.
    forever: Vec<(Weak<Owned>, Arc<Thread>, Suspended)>,
    /// Another CPU held a process's claim.
    skipped: bool,
}

/// Bit `i`: CPU `i`.
pub(crate) fn bit(cpu: CpuId) -> u64 {
    1 << cpu.index()
}

/// The CPU time to count for a runnable entity that has used `cpu_time`, as
/// it is polled: at least one slice below `floor` (the [`RunQueue::floor`]).
/// An entity back from a long wait (e.g., a thread for a device, or a broker
/// for requests) thus gets at most one extra slice before the others get
/// their turns, instead of running until it has caught up with them.
///
/// It never lowers `cpu_time`. The floor can stop rising while entities run
/// (e.g., while a stalled CPU holds a process, see [`Found::held`]); pulling
/// their CPU time down toward it would erase their progress and leave them
/// tied, ordered only by the shared round-robin position, which other CPUs
/// keep moving, so an entity could starve.
fn counted(cpu_time: u64, floor: u64) -> u64 {
    cpu_time.max(floor.saturating_sub(QUANTUM_NANOS))
}

/// The CPU time to charge for a thread's run, the step that chose it, or a
/// broker's dispatch (its step and batch), that took `elapsed` nanoseconds:
/// at most one slice. The clock also counts time the host did not run the
/// vCPU, which looks the same as real work; without this cap, an entity
/// charged for such a stall would wait until every other entity caught up
/// with it.
pub(crate) fn charged(elapsed: u64) -> u64 {
    elapsed.min(QUANTUM_NANOS)
}

/// The rest of a run that ended without its process's claim, which only its
/// CPU had, for the claim's next holder to finish the run with
/// ([`finish_parked`]).
pub(crate) struct Parked {
    /// Why the run ended without the claim.
    unclaimed: Unclaimed,
    /// The FS base the thread left, unchecked.
    fs_base: usize,
    /// The CPU time to charge for the run, in nanoseconds (see [`charged`]).
    used: u64,
}

/// How a run of a thread ended (see [`Shared::run_slice`]).
enum Slice<'a> {
    /// Under its process's claim.
    Claimed(Claim<'a>),
    /// Without it: the thread is parked, and `cpu_time` is its CPU time once
    /// that run is charged.
    Parked { cpu_time: u64 },
}

impl Shared {
    /// Spawns launched processes and polls the processes, then runs the best
    /// runnable entity, a thread for a slice or a broker for a batch, or
    /// halts until one may run. False once nothing runs (see
    /// [`Self::is_idle`]). Once children were started (even if their runner
    /// processes could not be created), runs nothing, so that the next step
    /// sees them, and the brokers waiting for them. The caller acknowledged
    /// this CPU's wakeups first (see [`cpu::acknowledge`]): one after, even
    /// as a broker looks (e.g., for a launched process's start), has it step
    /// again.
    fn step(&self) -> bool {
        let cpu = cpu::current();
        let claims = self.claim_attempts();
        // Before the polls look at the brokers this CPU holds.
        let seen = worker::observe();
        let mut claimed = 0;
        self.reap();
        let (processes, last, floor) = {
            let queue = self.queue.lock();
            (queue.processes.clone(), queue.last, queue.floor)
        };
        // The step's polls are charged to what it runs, as its run is (see
        // `Self::run_best`): some entities' dispatches are far shorter, and
        // more frequent, than a scan of every process.
        let begun = processes.first().map(|process| process.platform().now());
        // Whether a claim taken before `claims` was read may still be held:
        // every other is counted, or was released before, its effects seen by
        // the polls (see `Self::quiet`).
        let held = processes.iter().any(|process| process.is_held());
        let mut found = Found::default();
        let mut spawned = Vec::new();
        let mut started = false;
        // From a different place on each CPU, so that CPUs polling at once
        // claim different processes (the order does not change the choice).
        let first = cpu.index() % processes.len().max(1);
        for process in processes[first..].iter().chain(&processes[..first]) {
            if process.is_quiescent() {
                continue;
            }
            // A broker suspended on this CPU, which only it resumes: if its
            // process is held (e.g., by an entry of one of its threads), this
            // spins briefly, unless it holds a candidate's claim (no CPU waits
            // for a claim holding another), but only once `try_claim` failed,
            // so that the release wakes this CPU (its failed attempts fail
            // this step's `Self::quiet`). Still held, it is tried again soon,
            // not a slice later, as others may wait for what the broker holds
            // (e.g., a lock).
            let mine = process.task_cpu() == Some(cpu);
            let brief = mine && found.best.is_none();
            let claim = process
                .try_claim()
                .or_else(|| brief.then(|| process.claim_briefly()).flatten());
            let Some(claim) = claim else {
                found.skip(process);
                if mine {
                    let soon = process.platform().now().checked_add(NOTIFIED);
                    found.wake = [found.wake, soon].into_iter().flatten().min();
                }
                continue;
            };
            claimed += 1;
            finish_parked(&claim);
            started |= claim.spawn_launched(&mut spawned);
            if !started {
                found.poll(claim, cpu, floor, last);
            }
        }
        if started {
            if let Some(best) = &found.best {
                best.claim.share();
            }
            drop(found);
            for process in spawned {
                self.add(self.own(process));
            }
            return true;
        }
        let Some(Best {
            claim,
            chosen,
            siblings,
            ..
        }) = found.best.take()
        else {
            // Not across the halt: a process that dies on another CPU
            // meanwhile is freed then, not once this CPU wakes.
            let found = found.detach();
            drop(processes);
            // None if a claim held as it began may have effects it missed.
            let claims = (!held).then_some(claims + claimed);
            return self.idle(cpu, found, seen, claims);
        };
        let begun = begun.expect("a step that found an entity found processes");
        match chosen {
            Chosen::Thread(thread) => {
                thread.charge(claim.platform, begun);
                self.run_best(cpu, claim, &thread, siblings, &found);
            }
            Chosen::Broker => self.run_broker(cpu, claim, begun, siblings, &found),
        }
        true
    }

    /// Runs the claimed process's broker on `cpu`, the calling one, until its
    /// batch finishes or suspends: the one this CPU holds, or a new one (see
    /// `batch`). Charged from `begun`, as its step began, to the broker
    /// alone, at most a slice (see [`charged`]). A batch that finished after
    /// it suspended frees the threads whose broker calls waited for it, for
    /// any CPU: the release publishes that, and wakes the other idle CPUs, as
    /// it does on the boot CPU, which may return to its services first. This
    /// CPU steps again at once, and polls them.
    fn run_broker(
        &self,
        cpu: CpuId,
        claim: Claim<'_>,
        begun: Instant,
        siblings: bool,
        found: &Found<'_>,
    ) {
        let platform = claim.platform;
        let resumed = claim.task.cpu() == Some(cpu);
        let ran = if resumed {
            claim.task.resume()
        } else {
            claim.task.start(batch(claim.process().clone()))
        };
        claim.deactivate();
        let used = platform.now().as_nanos().saturating_sub(begun.as_nanos());
        let used = charged(used);
        let time = claim.broker_time.get().saturating_add(used);
        claim.broker_time.set(time);
        if siblings || (ran == Ran::Finished && (resumed || cpu == CpuId::BOOT)) {
            claim.share();
        }
        let mut queue = self.queue.lock();
        queue.last = (claim.process().seq, Entity::Broker);
        let others = [found.others, found.held].into_iter().flatten();
        queue.floor = floor_after(queue.floor, time, others);
    }

    /// Runs the best thread a step found, of `claim`'s process, for a slice,
    /// and, if it cloned its process (see `crate::fork`), more of its slice,
    /// unless a run parks it. If the process has other runnable entities, the
    /// other idle CPUs are woken to run them meanwhile. The slice ends early
    /// once another may run: at a blocked thread's or broker's deadline, or
    /// soon after a notification, or after a broker this CPU holds may have
    /// become due (see `Inner::make_way_for_tasks`); but not before the thread
    /// ran a while, however late the step or the run's start (see
    /// [`admitted`]). With one CPU, a thread alone has no slice end but those;
    /// with more, every run has one, as other CPUs may make more runnable
    /// unseen (e.g., processes they held, start, or end the waits of), or need
    /// the boot CPU's services to look between slices at what they wait for.
    fn run_best(
        &self,
        cpu: CpuId,
        mut claim: Claim<'_>,
        thread: &Thread,
        siblings: bool,
        found: &Found<'_>,
    ) {
        let process = claim.process();
        // With other CPUs, more may become runnable, unseen (e.g., processes
        // they held, or start).
        let alone = found.others.is_none() && cpu::online_count() == 1;
        let slice = (!alone).then(|| {
            let now = claim.platform.now();
            now.checked_add(QUANTUM)
                .unwrap_or(Instant::from_nanos(u64::MAX))
        });
        // Also until the earliest wake, for that thread, or broker, to run
        // then.
        let mut slice_end = [found.wake, slice].into_iter().flatten().min();
        let mut admission = Admission::Pending { quantum: slice };
        // Polling published to a wait already polled, or another CPU did:
        // another may be due soon.
        thread.slice_end.set(slice_end);
        claim.take_notified(thread);
        slice_end = thread.slice_end.get();
        self.counts[cpu.index()]
            .slices
            .fetch_add(1, Ordering::Relaxed);
        if siblings {
            claim.share();
        }
        let end = loop {
            claim = match self.run_slice(cpu, claim, thread, slice_end, admission) {
                Slice::Claimed(claim) => claim,
                parked @ Slice::Parked { .. } => break parked,
            };
            admission = Admission::Done;
            // It keeps the rest of its slice, for the runner to let go of
            // what it held across the call.
            if !matches!(thread.suspended.get(), Suspended::Cloned { .. }) {
                break Slice::Claimed(claim);
            }
            // Unless another may run now. The slice may have been cut short
            // (see `Inner::share_cpu`, `Inner::take_notified` and
            // `Inner::make_way_for_tasks`).
            claim.take_notified(thread);
            claim.make_way_for_tasks(thread);
            slice_end = thread.slice_end.get();
            let now = claim.platform.now();
            if claim.is_stopped() || slice_end.is_some_and(|slice_end| now >= slice_end) {
                break Slice::Claimed(claim);
            }
        };
        // Including that slice, but not threads that were waiting.
        let cpu_time = match &end {
            Slice::Claimed(_) => thread.cpu_time.get(),
            Slice::Parked { cpu_time } => *cpu_time,
        };
        {
            let mut queue = self.queue.lock();
            queue.last = (process.seq, Entity::Thread(thread.id));
            let others = [found.others, found.held].into_iter().flatten();
            queue.floor = floor_after(queue.floor, cpu_time, others);
        }
        // Shared unless nothing of it may run (so that, for a thread that
        // blocked, another CPU sees its wake, and marks it a notification
        // waiter), as this CPU may not look at it again soon: the boot CPU
        // may return to its services first, and any CPU's next step may first
        // free the processes it reaps (see `Self::reap`), or this step the
        // last of its snapshot's as it returns, work not bounded in time. A
        // parked thread waits for a step that claims its process: the idle
        // CPUs look at once, as this one may run another thread first, or
        // return to its services.
        match end {
            Slice::Claimed(claim) => {
                if siblings || !(thread.exited.get() || claim.is_stopped()) {
                    claim.share();
                }
            }
            Slice::Parked { .. } => cpu::wake_idle(cpu),
        }
    }

    /// The end of a step that found nothing to run: false if nothing runs
    /// (see [`Self::is_idle`]); otherwise halts until the earliest wake,
    /// unless, on the boot CPU, it abandons the waits that nothing could end
    /// (see [`Self::abandon`]), which needs `claims` (the count as of the
    /// step's start, plus the claims it took): `None` if a claim was held as
    /// the step began (see [`Self::quiet`]). `seen` is the wake generation the
    /// step began with (see [`worker::observe`]).
    fn idle(&self, cpu: CpuId, found: Found<'_>, seen: u64, claims: Option<u64>) -> bool {
        if !(found.blocked || found.busy || found.skipped) && self.is_idle() {
            return false;
        }
        // A wake since the step began (e.g., a device's interrupt, which the
        // boot CPU takes unmarked, as the step waited for a lock): it may have
        // ended a wait the step saw blocked, so this steps again.
        if worker::wakes() != seen {
            return true;
        }
        if self.events.wait(found.wake) {
            return true;
        }
        // No deadline, and no device could end the halt: only another CPU
        // could end the waits. If none runs anything, nothing could.
        if !(found.forever.is_empty() || found.busy || found.skipped || worker::live_here() != 0) {
            if cpu != CpuId::BOOT {
                cpu::wake(CpuId::BOOT);
            } else if cpu::marked() {
                return true;
            } else if let Some(claims) = claims
                && self.quiet(claims)
                && self.abandon(&found.forever, claims)
            {
                return true;
            }
        }
        cpu::halt();
        true
    }

    /// Whether nothing runs, nor will until a service's call: every process
    /// waits for a request, is dead, or is a process clone not adopted yet,
    /// with nothing to do (see [`Owned::is_quiescent`]: so no broker is
    /// suspended), and none is claimed.
    fn is_idle(&self) -> bool {
        let claims = self.claim_attempts();
        self.queue
            .lock()
            .processes
            .iter()
            .all(|process| !process.is_held() && process.is_quiescent())
            && self.claim_attempts() == claims
    }

    /// Whether no other CPU ran anything since the count of claims was
    /// `claims` (with those the calling CPU's step took): none tried to take
    /// one since (but a CPU in the midst of taking one then, see
    /// [`Self::claim_attempts`]), none is held, no thread runs (in ring 3,
    /// without a claim, one may still end others' waits), and no broker is
    /// suspended. The step began with none held (see `Self::step`), so every
    /// claim since was counted, and the step's polls saw what those released
    /// before did; the step's own failed attempts (not in `claims`) make this
    /// fail. Teardown under no claim (e.g., a reap) publishes nothing: a dead
    /// process's broker releases its references under its claim.
    fn quiet(&self, claims: u64) -> bool {
        !self.queue.lock().processes.iter().any(|process| {
            process.is_held() || process.is_running() || process.task_cpu().is_some()
        }) && self.claim_attempts() == claims
    }

    /// Ends the waits, as they were, that nothing could end
    /// ([`Status::Stalled`]), if still nothing ran since the count of claims
    /// was `claims` (as far as [`Self::quiet`] tells): under all their
    /// processes' claims, taken first. So no thread runs between the checks
    /// (one could end another's wait, which would then be made again, the
    /// same, and ended here), but on a CPU in the midst of taking a claim at
    /// the first. False if something ran, or tried to: the caller then halts,
    /// as when `quiet` fails, rather than step again into other CPUs'
    /// attempts on these claims.
    fn abandon(&self, forever: &[(Weak<Owned>, Arc<Thread>, Suspended)], claims: u64) -> bool {
        debug_assert_eq!(
            cpu::current(),
            CpuId::BOOT,
            "only the boot CPU abandons waits"
        );
        // Not those freed meanwhile (so dead).
        let mut processes: Vec<Arc<Owned>> = Vec::new();
        for process in forever.iter().filter_map(|(process, ..)| process.upgrade()) {
            if !processes.iter().any(|other| Arc::ptr_eq(other, &process)) {
                processes.push(process);
            }
        }
        let held: Vec<Claim<'_>> = processes.iter().map_while(Owned::try_claim).collect();
        if held.len() < processes.len() || self.claim_attempts() != claims + held.len() as u64 {
            return false;
        }
        for (process, thread, suspended) in forever {
            let Some(claim) = processes
                .iter()
                .position(|other| core::ptr::eq(Arc::as_ptr(other), process.as_ptr()))
                .map(|index| &held[index])
            else {
                continue;
            };
            if thread.suspended.get() == *suspended {
                claim.broker.abandon_wait();
                thread.suspended.set(Suspended::Woken(Err(Status::Stalled)));
                claim.share();
            }
        }
        true
    }

    /// How many times the CPUs tried to take a claim of the processes so far,
    /// each counted just before, taken or not (see [`CpuCounts`]): unchanged
    /// between two reads, none was taken in between (e.g., nothing ran), but by
    /// a CPU in the midst of taking one at the first (e.g., paused there by its
    /// host). A read sums the CPUs' counts one by one, each only growing: "in
    /// between" is from the end of the first read to the start of the second.
    fn claim_attempts(&self) -> u64 {
        self.counts
            .iter()
            .map(|counts| counts.claims.load(Ordering::SeqCst))
            .fold(0, u64::wrapping_add)
    }

    /// `inner`, last in the round-robin order so far, for [`Self::add`].
    fn own(&self, inner: Inner) -> Arc<Owned> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        Arc::new(Owned::new(inner, seq, self.counts.clone()))
    }

    /// Publishes `process` to every CPU.
    fn add(&self, process: Arc<Owned>) {
        // Any CPU may start it, unless quiescent (e.g., a process clone not
        // adopted yet).
        let wake = !process.is_quiescent();
        self.queue.lock().processes.push(process);
        if wake {
            cpu::wake_idle(cpu::current());
        }
    }

    /// See [`Scheduler::reap`].
    fn reap(&self) {
        let mut reaped = Vec::new();
        self.queue.lock().processes.retain(|process| {
            // `dead` first (see `Claim`'s `Drop`).
            let dead = process.is_dead() && process.is_quiescent();
            if dead {
                reaped.push(process.clone());
            }
            !dead
        });
        // Outside the lock: a process's last reference releases its address
        // space (its broker ended its association, on its task).
        drop(reaped);
    }
}

impl Found<'_> {
    /// With nothing to run, so no claim: the rest, which does not borrow
    /// the step's snapshot of the processes.
    fn detach(self) -> Found<'static> {
        Found {
            best: None,
            others: self.others,
            held: self.held,
            wake: self.wake,
            blocked: self.blocked,
            busy: self.busy,
            forever: self.forever,
            skipped: self.skipped,
        }
    }
}

impl<'a> Found<'a> {
    /// `process` was held by another CPU.
    fn skip(&mut self, process: &Owned) {
        self.skipped = true;
        self.held = [self.held, process.runnable()].into_iter().flatten().min();
    }

    /// Another runnable entity used `cpu_time` (see [`Self::others`]).
    fn other(&mut self, cpu_time: u64) {
        self.others = Some(self.others.map_or(cpu_time, |others| others.min(cpu_time)));
    }

    /// Polls the claimed process's threads, ending the waits it can, and its
    /// broker, as `cpu` sees it, and keeps its claim if it has the best
    /// runnable entity so far; otherwise, releases it, for another CPU to take
    /// if it has work left.
    fn poll(&mut self, claim: Claim<'a>, cpu: CpuId, floor: u64, last: Id) {
        let process = claim.process();
        let threads = claim.threads.borrow().clone();
        // Before polling, which may publish (e.g., input) to a process
        // polled already; after, as polling ended waits.
        claim.mark_notification_waiter();
        let turns: Vec<Turn> = threads.iter().map(|thread| claim.turn(thread)).collect();
        claim.mark_notification_waiter();
        let entities = threads
            .iter()
            .map(Some)
            .zip(turns)
            .chain([(None, claim.broker_turn(cpu))]);
        // The best, as a thread, or `None` for the broker.
        let mut best: Option<(Key, Option<&Arc<Thread>>)> = None;
        let mut runnable = 0;
        for (thread, turn) in entities {
            match turn {
                Turn::Runnable => {
                    runnable += 1;
                    let (time, entity) = match thread {
                        Some(thread) => (&thread.cpu_time, Entity::Thread(thread.id)),
                        None => (&claim.broker_time, Entity::Broker),
                    };
                    time.set(counted(time.get(), floor));
                    let key = key(time.get(), (process.seq, entity), last);
                    let other = match best {
                        Some((best_key, _)) if best_key <= key => key.0,
                        _ => {
                            let other = best.map(|(best_key, _)| best_key.0);
                            best = Some((key, thread));
                            match other {
                                Some(other) => other,
                                None => continue,
                            }
                        }
                    };
                    self.other(other);
                }
                Turn::Blocked(wake) => {
                    self.blocked = true;
                    self.wake = [self.wake, wake].into_iter().flatten().min();
                    if let (None, Some(thread)) = (wake, thread) {
                        self.forever.push((
                            Arc::downgrade(process),
                            thread.clone(),
                            thread.suspended.get(),
                        ));
                    }
                }
                Turn::Busy => self.busy = true,
                Turn::Running | Turn::Stopped => {}
            }
        }
        claim.set_runnable(best.map(|(key, _)| key.0));
        let Some((key, thread)) = best else {
            return;
        };
        if self.best.as_ref().is_some_and(|best| best.key <= key) {
            self.other(key.0);
            claim.share();
            return;
        }
        let best = Best {
            chosen: thread.map_or(Chosen::Broker, |thread| Chosen::Thread(thread.clone())),
            claim,
            key,
            siblings: runnable > 1,
        };
        if let Some(previous) = self.best.replace(best) {
            self.other(previous.key.0);
            previous.claim.share();
        }
    }
}

/// A batch of `process`'s broker (see `Shared::run_broker`): it serves at
/// most [`BATCH`] requests, or, once the process is dead, ends its
/// association (see [`litebox_broker_vm_kernel::Association::run`]). Its own
/// reference to the process is never the last: the run queue keeps the
/// process until the batch finished (see [`Owned::is_quiescent`]).
fn batch(process: Arc<Owned>) -> Box<dyn FnOnce()> {
    Box::new(move || {
        // Safety: a batch runs, and resumes, only under the claim, on the CPU
        // that took it (see `Shared::run_broker`).
        let inner = unsafe { process.claimed() }.expect("a batch starts under the claim");
        if inner.broker.run(BATCH).is_err() {
            inner.kill("broker association failed");
        }
    })
}

/// Whether a notification may end `thread`'s wait: a futex wait (see
/// [`Inner::poll_futex`]), or a broker wait on the notification wake counter.
/// Its process is then a notification waiter (see
/// [`Inner::mark_notification_waiter`]).
fn waits_for_notifications(thread: &Thread) -> bool {
    match thread.suspended.get() {
        Suspended::Futex(_) => true,
        Suspended::Waiting(wait) => wait.is_for_notifications(),
        _ => false,
    }
}

/// An entity's state for one scheduling round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Runnable,
    /// On a CPU: neither runnable nor blocked (for a broker, suspended on
    /// another CPU).
    Running,
    /// Exited, waits for a request, or its process is dead; for a broker,
    /// nothing to do.
    Stopped,
    /// In a broker or futex wait, until an event or the wake, if any; for a
    /// broker, suspended on this CPU (see [`worker::Wait`]).
    Blocked(Option<Instant>),
    /// Its broker call waits for its broker (see `Inner::broker_busy`).
    Busy,
}

impl Inner {
    /// If this CPU was notified (a blocked thread's wait may have ended),
    /// ends the slice of `thread`, which runs on it: at once if it is the
    /// only CPU online, else within [`NOTIFIED`].
    pub(crate) fn take_notified(&self, thread: &Thread) {
        if cpu::take_notified() {
            self.end_slice_by(
                thread,
                if cpu::online_count() == 1 {
                    Duration::ZERO
                } else {
                    NOTIFIED
                },
            );
        }
    }

    /// The broker's [`Turn`], as `cpu` sees it: suspended, only on the CPU
    /// that holds it, and runnable once due; else, a new batch may run on any
    /// CPU, while the broker has work: requests the live process published,
    /// or, once it is dead, its association to end.
    fn broker_turn(&self, cpu: CpuId) -> Turn {
        match self.task.cpu() {
            Some(holder) if holder != cpu => Turn::Running,
            Some(_) if self.task.is_due(self.platform.now()) => Turn::Runnable,
            Some(_) => Turn::Blocked(self.task.deadline()),
            None if self.broker.has_work() => Turn::Runnable,
            None => Turn::Stopped,
        }
    }

    /// Tells the broker whether a thread of the process waits for
    /// notifications, so that one published to it notifies every CPU: they
    /// poll the waits again.
    fn mark_notification_waiter(&self) {
        let waiting = self
            .threads
            .borrow()
            .iter()
            .any(|thread| !thread.exited.get() && waits_for_notifications(thread));
        self.broker.set_notification_waiter(waiting);
    }

    /// Another thread of the process became runnable (it was created or
    /// woken): the claim's release wakes the other idle CPUs, to run it. If a
    /// thread runs on this CPU (its entry made the other runnable), and the
    /// slice end did not account for that (e.g., none, as alone, or a
    /// blocked thread's distant wake), its slice ends a slice from now at the
    /// latest, for the other to run then, if no other CPU took it.
    pub(crate) fn share_cpu(&self) {
        self.share();
        let cpu = cpu::current();
        if let Some(thread) = self
            .threads
            .borrow()
            .iter()
            .find(|thread| thread.running.get() == Some(cpu))
        {
            self.end_slice_by(thread, QUANTUM);
        }
    }

    /// If a broker task this CPU holds may be due ([`worker::due`]), ends the
    /// slice of `thread`, which runs on it, within [`NOTIFIED`]: the task, which
    /// only this CPU resumes, then competes for it as any other entity does,
    /// and the thread runs on meanwhile, however often the CPUs wake tasks
    /// (see `ended_by`). Whether that ended the slice earlier (so the caller
    /// may need to arm the timer again).
    pub(crate) fn make_way_for_tasks(&self, thread: &Thread) -> bool {
        let slice_end = thread.slice_end.get();
        if worker::due() {
            self.end_slice_by(thread, NOTIFIED);
        }
        thread.slice_end.get() != slice_end
    }

    /// `thread`, which a run admits, returns to ring 3 for the first time in
    /// it, its quantum ending at `quantum` (none: no end): see [`admitted`].
    /// Whether that moved its slice's end (so the caller may need to arm the
    /// timer again).
    pub(crate) fn admit(&self, thread: &Thread, quantum: Option<Instant>) -> bool {
        let slice_end = thread.slice_end.get();
        thread
            .slice_end
            .set(admitted(slice_end, quantum, self.platform.now()));
        thread.slice_end.get() != slice_end
    }

    /// Ends `thread`'s slice `duration` from now, at the latest.
    fn end_slice_by(&self, thread: &Thread, duration: Duration) {
        let now = self.platform.now();
        let slice_end = ended_by(thread.slice_end.get(), now, duration);
        thread.slice_end.set(Some(slice_end));
    }

    /// `thread`'s [`Turn`]; ends its wait first, if it can.
    fn turn(&self, thread: &Thread) -> Turn {
        if thread.running.get().is_some() {
            return Turn::Running;
        }
        // Before polling a wait, which a stopped process's threads have none
        // of to end. A clone that was not adopted runs nothing, and a thread
        // is made a process clone of once its run ends, never later.
        if thread.exited.get()
            || self.is_stopped()
            || self.is_cloned()
            || matches!(thread.suspended.get(), Suspended::Forking { .. })
        {
            return Turn::Stopped;
        }
        let suspended = thread.suspended.get();
        if self.broker_busy()
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
            // Until its broker served them.
            Turn::Busy
        } else {
            Turn::Runnable
        }
    }
}

impl Shared {
    /// Runs `thread` of `claim`'s process on `cpu`, the calling one, until it
    /// stops, blocks, or `slice_end` passes (none: until it stops or blocks;
    /// moved as the thread first resumes ring 3 if the run admits it, as
    /// `admission` says: see [`admitted`]), handing the claim to the run (see
    /// `Running`). Adds the process clone the thread made, if any (see
    /// `crate::fork`), at once: another CPU may adopt it as the thread runs on.
    /// If the run ended without the claim, the CPU parks the thread
    /// ([`Parked`]) rather than wait for the claim, which its holder may keep
    /// for long: the thread counts as running (so no other CPU runs or polls
    /// it) until a step that claims the process finishes the run
    /// ([`finish_parked`]).
    fn run_slice<'a>(
        &self,
        cpu: CpuId,
        claim: Claim<'a>,
        thread: &Thread,
        slice_end: Option<Instant>,
        admission: Admission,
    ) -> Slice<'a> {
        let platform = claim.platform;
        let start = platform.now();
        thread.slice_end.set(slice_end);
        let new = claim.is_new();
        let resume = thread.suspended.get() != Suspended::No;
        // Read under the claim, which a run that parks the thread ends
        // without.
        let cpu_time = thread.cpu_time.get();
        claim.set_running(thread, Some(cpu));
        let space = claim.activate_thread(thread);
        let running = Running::new(claim, thread, admission);
        {
            let mut ctx = thread.ctx.borrow_mut();
            let mut state = thread.user_state.borrow_mut();
            let (ctx, state) = (&mut *ctx, &mut *state);
            // Safety: the thread runs on this CPU alone (see
            // `Thread::running`), where no other thread runs; `ctx` is its
            // context.
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
        let fs_base = space.end();
        let claim = match running.end() {
            Ended::Claimed(claim) => claim,
            Ended::Unclaimed(unclaimed) => {
                if let Unclaimed::GaveUp(_) = unclaimed {
                    self.counts[cpu.index()]
                        .parks
                        .fetch_add(1, Ordering::Relaxed);
                }
                let used = platform.now().as_nanos().saturating_sub(start.as_nanos());
                let used = charged(used);
                *thread.parked.lock() = Some(Parked {
                    unclaimed,
                    fs_base,
                    used,
                });
                return Slice::Parked {
                    cpu_time: cpu_time.saturating_add(used),
                };
            }
        };
        claim.save_fs_base(thread, fs_base);
        // Once the run saved the thread's state.
        if let Suspended::Forking { slot } = thread.suspended.get()
            && let Some(clone) = claim.fork(thread, slot, |clone| self.own(clone))
        {
            self.add(clone);
        }
        thread.charge(platform, start);
        claim.set_running(thread, None);
        if thread.exited.get() {
            claim.reap(thread);
        } else if thread.suspended.get() == Suspended::No && !claim.is_stopped() {
            claim.kill("returned to the kernel without waiting");
        }
        Slice::Claimed(claim)
    }
}

/// Finishes the runs of the claimed process's parked threads, as
/// [`Shared::run_slice`] finishes the others: charges the CPU time, saves the
/// FS base, and has the thread replay the entry that gave up on the claim,
/// unless the process stopped; or, if the platform could not return to the
/// thread, kills the process. Only between runs: killing may free a process
/// clone, which leaves the kernel's address space current (see
/// `fork::end_pending`).
fn finish_parked(claim: &Claim<'_>) {
    for thread in claim.threads.borrow().iter() {
        if thread.running.get().is_none() {
            continue;
        }
        // Not parked yet: its CPU then wakes the idle CPUs, and steps itself
        // (see `Shared::run_best`).
        let Some(parked) = thread.parked.lock().take() else {
            continue;
        };
        claim.set_running(thread, None);
        thread
            .cpu_time
            .set(thread.cpu_time.get().saturating_add(parked.used));
        match parked.unclaimed {
            Unclaimed::GaveUp(entry) => {
                if !claim.is_stopped() {
                    thread.suspended.set(Suspended::Replay(entry));
                }
            }
            // Nothing to replay: the shim never saw the entry, or handled it.
            Unclaimed::InvalidContext => claim.kill("invalid user return context"),
        }
        claim.save_fs_base(thread, parked.fs_base);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Entity, Id, NOTIFIED, QUANTUM, QUANTUM_NANOS, RunQueue, admitted, charged, counted,
        ended_by, floor_after, key,
    };
    use crate::{InterruptAction, timer_deadline};
    use alloc::vec::Vec;
    use core::time::Duration;
    use litebox_platform::time::Instant as _;
    use litebox_platform_vm_kernel::Instant;

    /// An entity, as one CPU's steps see it.
    struct Model {
        id: Id,
        time: u64,
        /// What each of its dispatches uses.
        cost: u64,
        runnable: bool,
        runs: usize,
    }

    fn entity(id: Id, cost: u64) -> Model {
        Model {
            id,
            time: 0,
            cost,
            runnable: true,
            runs: 0,
        }
    }

    /// Models one scheduling step (`Shared::step`, then `Shared::run_best` or
    /// `Shared::run_broker`) on a CPU that claims only the processes of
    /// `entities`: the runnable ones, polled, count their `counted` time; the
    /// least key runs, and is charged its dispatch's `charged` cost; then the
    /// floor rises to the least time of those that could run and `held`, the
    /// least CPU time published by processes that other CPUs hold. Returns
    /// the entity run, by index.
    fn take_step(queue: &mut RunQueue, entities: &mut [Model], held: Option<u64>) -> usize {
        for entity in entities.iter_mut().filter(|entity| entity.runnable) {
            entity.time = counted(entity.time, queue.floor);
        }
        let best = (0..entities.len())
            .filter(|&index| entities[index].runnable)
            .min_by_key(|&index| key(entities[index].time, entities[index].id, queue.last))
            .expect("a runnable entity");
        let others: Vec<u64> = (0..entities.len())
            .filter(|&index| index != best && entities[index].runnable)
            .map(|index| entities[index].time)
            .chain(held)
            .collect();
        let ran = &mut entities[best];
        ran.time += charged(ran.cost);
        ran.runs += 1;
        queue.last = ran.id;
        queue.floor = floor_after(queue.floor, ran.time, others);
        best
    }

    /// One CPU's steps (see `take_step`), with no process held by another
    /// CPU: `between` changes what is runnable, or what a dispatch uses,
    /// before each step. Returns the entities run, by index.
    fn steps(
        entities: &mut [Model],
        count: usize,
        mut between: impl FnMut(usize, &mut [Model]),
    ) -> Vec<usize> {
        let mut queue = RunQueue::default();
        let mut order = Vec::new();
        for step in 0..count {
            between(step, entities);
            order.push(take_step(&mut queue, entities, None));
        }
        order
    }

    /// Asserts that, of `count` entities, none went more than two rounds
    /// (`2 * count` steps) without running; `order` lists the index of the
    /// entity that ran at each step. This checks for a reasonable share of
    /// the CPU (about half a fair share at least), not an exact one.
    fn assert_no_starvation(order: &[usize], count: usize) {
        for entity in 0..count {
            let wait = order
                .split(|&ran| ran == entity)
                .map(<[usize]>::len)
                .max()
                .unwrap_or_default();
            assert!(
                wait <= 2 * count,
                "entity {entity} waited {wait} steps: {order:?}"
            );
        }
    }

    #[test]
    fn brokers_and_threads_share_by_cpu_time() {
        // Two processes' threads, using whole slices, and four brokers with
        // batches of different lengths, all always runnable.
        let mut entities = Vec::new();
        for (seq, cost) in [(1, 50_000), (2, 300_000), (3, 1_000_000), (4, 20_000)] {
            entities.push(entity((seq, Entity::Broker), cost));
        }
        entities.push(entity((1, Entity::Thread(1)), QUANTUM_NANOS));
        entities.push(entity((4, Entity::Thread(1)), QUANTUM_NANOS));
        let most = QUANTUM_NANOS;
        let order = steps(&mut entities, 20_000, |_, _| {});
        // Each used about as much as the others: within a dispatch of each.
        let times: Vec<u64> = entities.iter().map(|entity| entity.time).collect();
        let (least, greatest) = (times.iter().min().unwrap(), times.iter().max().unwrap());
        assert!(greatest - least <= 2 * most, "{times:?}");
        // Between two dispatches of any one, the others use at most a
        // dispatch of its and one of their own each.
        for (index, entity) in entities.iter().enumerate() {
            let mut since = 0;
            for &ran in order.iter().skip_while(|&&ran| ran != index) {
                if ran == index {
                    since = 0;
                } else {
                    since += entities[ran].cost;
                    let bound = (entities.len() as u64 - 1) * (entity.cost + most);
                    assert!(since <= bound, "{:?} waited {since} ns", entity.id);
                }
            }
        }
    }

    #[test]
    fn ties_go_round_robin_whatever_the_creation_order() {
        // Brokers whose batches use no measurable time: their times stay
        // equal, so only the round-robin after the last one picks.
        let mut entities: Vec<Model> = (1..=8)
            .map(|seq| entity((seq, Entity::Broker), 0))
            .collect();
        entities.push(entity((3, Entity::Thread(7)), 0));
        let order = steps(&mut entities, 9 * 50, |_, _| {});
        for round in order.chunks(9) {
            let mut seen = round.to_vec();
            seen.sort_unstable();
            assert_eq!(seen, (0..9).collect::<Vec<_>>(), "each once a round");
        }
        // In the order of the IDs: process 3's thread before its broker.
        assert_eq!(&order[..9], [0, 1, 8, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn a_broker_back_from_idle_runs_at_most_a_slice_ahead() {
        // A thread always runnable; a broker with requests only from step
        // 1000 on, by then far behind it in CPU time.
        let cost = 100_000;
        let mut entities = alloc::vec![
            entity((1, Entity::Thread(1)), QUANTUM_NANOS),
            entity((2, Entity::Broker), cost),
        ];
        entities[1].runnable = false;
        let order = steps(&mut entities, 2_000, |step, entities| {
            entities[1].runnable = step >= 1_000;
        });
        let first = order.iter().position(|&ran| ran == 1).unwrap();
        assert_eq!(first, 1_000, "at once, once it has requests");
        // It runs ahead by the slice it was raised short of the floor, then
        // takes turns with the thread.
        let ahead = order[first..].iter().take_while(|&&ran| ran == 1).count();
        assert!(ahead as u64 <= QUANTUM_NANOS / cost + 1, "{ahead}");
        let after = &order[first + ahead..];
        assert!(after.contains(&0) && after.contains(&1));
        let (thread, broker) = (&entities[0], &entities[1]);
        assert!(thread.time.abs_diff(broker.time) <= 2 * QUANTUM_NANOS);
        assert!(thread.runs >= 1_000 && broker.runs > 0);
    }

    #[test]
    fn a_thread_whose_run_the_host_stalled_runs_again_soon() {
        let mut threads: Vec<Model> = (0..8)
            .map(|id| entity((1, Entity::Thread(id)), QUANTUM_NANOS))
            .collect();
        let order = steps(&mut threads, 200, |step, threads| {
            // The run at step 20 takes 70 ms longer, as if the host stopped the
            // vCPU during it.
            let stall = if step == 20 { 70_000_000 } else { 0 };
            for thread in threads {
                thread.cost = QUANTUM_NANOS + stall;
            }
        });
        // Without the cap, the stalled thread would wait about 7 rounds, until
        // every other thread had run 70 ms more.
        assert_no_starvation(&order, 8);
    }

    #[test]
    fn a_broker_whose_dispatch_the_host_stalled_runs_again_soon() {
        // Four processes' threads and brokers, whose dispatches each use a
        // slice (a broker's, e.g., in a long request), take turns in the order
        // of their IDs.
        let mut entities: Vec<Model> = (1..=4)
            .flat_map(|seq| [(seq, Entity::Thread(1)), (seq, Entity::Broker)])
            .map(|id| entity(id, QUANTUM_NANOS))
            .collect();
        let order = steps(&mut entities, 200, |step, entities| {
            // The dispatch at step 21, process 3's broker's, takes 70 ms
            // longer, as if the host stopped the vCPU during it.
            let stall = if step == 21 { 70_000_000 } else { 0 };
            for entity in entities {
                entity.cost = QUANTUM_NANOS + stall;
            }
        });
        assert_eq!(entities[order[21]].id, (3, Entity::Broker));
        // Without the cap, the broker would wait about 7 rounds, until every
        // other entity had run 70 ms more.
        assert_no_starvation(&order, 8);
    }

    #[test]
    fn neither_sibling_starves_while_a_stalled_cpu_holds_the_floor_down() {
        let mut queue = RunQueue::default();
        // A stalled CPU holds process 1, whose published least CPU time is 0,
        // so the floor stays at 0 (see `Found::held`).
        let held = Some(0);
        // Process 2's thread and broker run on one CPU and process 3's thread
        // on another, their steps interleaved: each run of process 3 moves the
        // shared round-robin position past process 2's entities.
        let mut siblings =
            [(2, Entity::Thread(1)), (2, Entity::Broker)].map(|id| entity(id, QUANTUM_NANOS));
        let mut other = [entity((3, Entity::Thread(1)), QUANTUM_NANOS)];
        let mut order = Vec::new();
        for _ in 0..100 {
            order.push(take_step(&mut queue, &mut siblings, held));
            take_step(&mut queue, &mut other, held);
        }
        // Each run adds to the siblings' CPU time, so they keep taking turns;
        // erasing it would leave them tied, and the moved round-robin would
        // always pick the first.
        assert_no_starvation(&order, 2);
    }

    #[test]
    fn a_thread_runs_on_for_a_while_however_often_brokers_are_woken() {
        // Alone on the only CPU, a thread's slice has no end; then a broker
        // its CPU holds may be due as each of its entries ends, every 100 µs
        // (see `Inner::make_way_for_tasks`, and `Inner::on_interrupt`, which
        // preempts it once its slice ended).
        let start = Instant::from_nanos(1_000_000_000);
        let after = |duration: Duration| start.checked_add(duration).unwrap();
        let (mut slice_end, mut resumed, mut armed) = (None, 0, 0);
        for entry in 0..100 {
            let now = after(Duration::from_micros(100) * entry);
            let ended = ended_by(slice_end, now, NOTIFIED);
            // The first wake sets the end, and the timer is armed for it (see
            // `Running::leave`); none puts it off.
            assert_eq!(ended, after(NOTIFIED));
            if Some(ended) != slice_end {
                armed += 1;
            }
            slice_end = Some(ended);
            if now >= ended {
                break;
            }
            resumed += 1;
        }
        // It ran on until then.
        assert_eq!((resumed, armed), (10, 1));
        // An earlier end stays (e.g., a blocked thread's wake); a later one
        // does not (e.g., a slice's).
        let earlier = after(Duration::from_micros(300));
        assert_eq!(ended_by(Some(earlier), start, NOTIFIED), earlier);
        assert_eq!(
            ended_by(Some(after(QUANTUM)), start, NOTIFIED),
            after(NOTIFIED)
        );
    }

    #[test]
    fn a_thread_admitted_past_others_deadlines_runs_a_while_first() {
        let start = Instant::from_nanos(1_000_000_000);
        let after = |micros| start.checked_add(Duration::from_micros(micros)).unwrap();
        let quantum = Some(after(10_000));
        // Until a broker's deadline a step saw (see `Found::wake`), 1 ms on.
        let slice_end = Some(after(1_000));
        // Past it as the thread first returns to ring 3 (the step, or the
        // run's start, took that long), or just before it: the thread runs
        // `NOTIFIED` from then, then the broker's turn comes.
        for entered in [after(1_100), after(2_500), after(999)] {
            assert_eq!(
                admitted(slice_end, quantum, entered),
                Some(ended_by(None, entered, NOTIFIED))
            );
        }
        // A later end stays, and so does no end; but its quantum ends it
        // first, however short (e.g., the run's start took most of it).
        assert_eq!(admitted(quantum, quantum, start), quantum);
        assert_eq!(admitted(None, None, start), None);
        let short = Some(after(1_500));
        assert_eq!(admitted(slice_end, short, after(1_100)), short);
        // Once admitted, later requests to look again soon put the end off no
        // further (see `ended_by`).
        let end = admitted(slice_end, quantum, after(1_100)).unwrap();
        for request in 0..30 {
            assert_eq!(
                ended_by(Some(end), after(1_100 + 100 * request), NOTIFIED),
                end
            );
        }
        // The process's own deadline, armed apart (see `Inner::arm_timer`),
        // still interrupts the thread first, to deliver it, within its slice.
        let deadline = after(1_300);
        assert!(deadline < end);
        assert_eq!(
            InterruptAction::decide(timer_deadline(false, Some(deadline), None), deadline, false),
            InterruptAction::Deliver
        );
    }

    #[test]
    fn a_blocked_brokers_deadline_passed_at_each_admission_starves_no_thread() {
        // One CPU, a thread always runnable, and a broker in a long 9P round
        // trip: each time it resumes, it polls its device, and suspends for
        // 1 ms more. Each step polls the broker first, while it is blocked; the
        // rest of the step, then the run's start, end past its deadline, as
        // `scan` and `entry` say. The thread's run up to its first return to
        // ring 3 and the broker's run are charged as `Shared::run_best` and
        // `Shared::run_broker` charge them.
        let poll = 1_000_000;
        let broker_run = 5_000;
        for (scan, entry) in [(1_100_000, 20_000), (100_000, 1_200_000)] {
            let (thread, broker) = ((2, Entity::Thread(1)), (1, Entity::Broker));
            let start = 1_000_000_000;
            let mut now = start;
            let (mut thread_time, mut broker_time) = (0, scan);
            let (mut last, mut floor) = (broker, 0);
            let mut deadline = now + poll;
            let (mut runs, mut resumes, mut ran) = (0, 0, 0);
            for _ in 0..10_000 {
                let due = now >= deadline;
                thread_time = counted(thread_time, floor);
                if due {
                    broker_time = counted(broker_time, floor);
                }
                let wake = (!due).then_some(deadline);
                now += scan;
                if due && key(broker_time, broker, last) < key(thread_time, thread, last) {
                    now += broker_run;
                    broker_time += scan + broker_run;
                    deadline = now + poll;
                    resumes += 1;
                    last = broker;
                    floor = floor_after(floor, broker_time, [thread_time]);
                    continue;
                }
                let quantum = now + QUANTUM_NANOS;
                let slice_end = wake.map_or(quantum, |wake| wake.min(quantum));
                now += entry;
                let end = admitted(
                    Some(Instant::from_nanos(slice_end)),
                    Some(Instant::from_nanos(quantum)),
                    Instant::from_nanos(now),
                )
                .unwrap()
                .as_nanos();
                // What the thread ran in ring 3 before its slice ended.
                let user = end.saturating_sub(now);
                assert!(
                    user >= poll,
                    "{user} ns after a {scan} ns step and {entry} ns start"
                );
                now += user;
                ran += user;
                runs += 1;
                thread_time += scan + entry + user;
                last = thread;
                floor = floor_after(floor, thread_time, due.then_some(broker_time));
            }
            // The broker polled its device all along, and the thread ran in
            // ring 3 for a fair share of the time.
            assert!(
                runs > 1_000 && resumes > 1_000,
                "{runs} runs, {resumes} resumes"
            );
            assert!(ran * 4 >= now - start, "{ran} of {} ns", now - start);
        }
    }
}
