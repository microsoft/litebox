// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scheduling of runner processes' threads on the CPUs, each with its broker
//! worker.
//!
//! One run queue ([`Scheduler`]) holds every process. Each CPU takes steps
//! (the boot CPU in [`Scheduler::run_until`], between its services' calls;
//! the others in [`Scheduler::run`]): it resumes its worker, serves what the
//! processes submitted, polls their threads, and runs the best runnable thread
//! for a slice, or halts until the earliest wake it saw. It works on a process
//! under its claim (see `claim`), which it hands to the thread it runs, so
//! that other CPUs may run the process's other threads meanwhile (see
//! `Running`). Polls skip the threads that run, but first finish the runs of
//! those parked (see `finish_parked`).
//!
//! The runnable thread that used the least CPU runs next, ties going
//! round-robin in creation order; one back from waiting is due at most a slice
//! more than the others. A thread runs until it stops, blocks in a broker or
//! futex wait, or its slice of [`QUANTUM`] ends (see `Shared::run_best`). Only
//! user mode is preempted, transparently.
//!
//! Each CPU's worker serves one process's requests at a time, on its own stack
//! ([`litebox_platform_vm_kernel::worker`]), charged to the thread that made
//! the last broker call (see `Inner::broker_requester`). A request that waits
//! (e.g., for a device) suspends it: threads run meanwhile, on any CPU, but
//! their broker calls wait for it, and only its CPU resumes it (see
//! `Inner::worker`). A CPU runs its worker holding no claim but that of the
//! process it serves (see `serve`), and outside the threads' runs.
//!
//! What may make work for another CPU wakes it (see `claim` and
//! [`litebox_platform_vm_kernel::cpu`]): adding a process, releasing one with
//! work left, or one it found claimed; a notification to a waiting process,
//! which has every CPU look again within `NOTIFIED`; and a device interrupt,
//! which also interrupts the busy CPUs whose workers are suspended (see
//! `Inner::worker_due`).
//!
//! Nothing runs once every process waits for a request, is dead, or is a
//! process clone not adopted yet, none is claimed, no thread runs, and no
//! worker is suspended. Waits that nothing could end ([`Status::Stalled`]) are
//! abandoned by the boot CPU, once no other CPU runs anything.
//!
//! Known limitations:
//! - A run, or a worker job for a thread, is charged at most one slice of CPU
//!   time (see `charged`), because the clock cannot tell long kernel work from
//!   time the host did not run the vCPU. A thread whose runs regularly exceed
//!   a slice therefore gets more than its share of the CPU.
//! - A notification to any waiting process shortens every busy CPU's slice.
//! - A process running on another CPU, with no thread waiting for
//!   notifications, sees one only at its next kernel entry, at the latest as
//!   its slice ends.
//! - While the boot CPU runs its services (but for their claim waits), a
//!   process whose request its worker is suspended in waits.
//! - A thread whose kernel entry finds its process's claim held past a brief
//!   spin (e.g., by a worker serving a request, across a 9P round trip, or by
//!   its other threads' entries) is parked, as is ordinary under contention
//!   (see [`Scheduler::parks`]), until a step claims the process again. Its
//!   CPU steps again at once, and wakes the idle CPUs; but if the claim is
//!   still held, and no CPU is idle once it is released, the thread waits for
//!   a busy CPU's next step, up to a slice later.

use crate::claim::{Claim, Owned};
use crate::thread::{FutexState, Thread};
use crate::{Ended, Inner, Running, Suspended, Unclaimed};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// notifications does not stop every CPU's thread at once.
const NOTIFIED: Duration = Duration::from_nanos(QUANTUM_NANOS / 10);

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
    /// Whether the boot CPU steps (in [`Scheduler::run_until`], not in its
    /// services, nor in `done`), so that its worker may serve what other CPUs
    /// share (see `serve`).
    boot_stepping: AtomicBool,
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
    /// The live processes, and the dead ones a worker is suspended in.
    processes: Vec<Arc<Owned>>,
    /// Where the round-robin for ties starts: after this thread, as its
    /// process's [`Owned::seq`] and its ID.
    last: (u64, u64),
    /// The least CPU time of the threads that could run, as of the last
    /// slice (of any CPU).
    floor: u64,
}

impl Scheduler {
    /// One that halts with `events` (see [`Events::wait`]) when no process
    /// can run: the brokers' (`litebox_broker_vm_kernel::Config::events`),
    /// whose device interrupts its workers take.
    pub fn new(events: &'static dyn Events) -> Self {
        Self(Arc::new(Shared {
            queue: SpinMutex::new(RunQueue::default()),
            counts: Arc::new(core::array::from_fn(|_| CpuCounts::default())),
            boot_stepping: AtomicBool::new(false),
            events,
            next_seq: AtomicU64::new(1),
        }))
    }

    /// Runs the processes until `done`, checked between steps, or until
    /// nothing runs (see the [module](self) docs), without checking `done`
    /// after that last step. On the boot CPU, which a process that stops
    /// wakes: so `done` must change only as processes stop (e.g.,
    /// [`crate::Process::is_stopped`]). Between calls (but in a service's
    /// claim waits), a process whose request this CPU's worker is suspended
    /// in waits (see the module docs).
    pub fn run_until(&self, mut done: impl FnMut() -> bool) {
        debug_assert_eq!(cpu::current(), CpuId::BOOT, "services run on the boot CPU");
        loop {
            // Before looking, at `done` too (see `cpu::acknowledge`).
            cpu::acknowledge();
            if done() {
                break;
            }
            self.0.boot_stepping.store(true, Ordering::Relaxed);
            let more = self.0.step();
            self.0.boot_stepping.store(false, Ordering::Relaxed);
            if !more {
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

    /// Forgets the dead processes that no worker is suspended in, which
    /// releases their address spaces unless a [`crate::Process`] holds them.
    /// Another CPU may release some a moment later (e.g., ones its step
    /// holds, or that it forgot first).
    pub fn reap(&self) {
        self.0.reap();
    }

    /// For a service, which must hold no claim: `process`'s claim, once no
    /// other CPU holds it. Meanwhile, now and then, resumes this CPU's
    /// suspended worker, if it can claim its process (only this CPU resumes
    /// it, see `Inner::worker`), as the holder may wait for what the worker
    /// holds (e.g., a lock, see `worker`). Nothing else: it runs no thread,
    /// serves no new request, and clears no wakeup (which the caller, e.g.,
    /// `run_until`'s `done`, may not have looked at yet).
    pub(crate) fn claim<'a>(&self, process: &'a Arc<Owned>) -> Claim<'a> {
        process.claim(|| self.0.resume_own_worker())
    }
}

/// Ordering of runnable threads, least first: by CPU time, then
/// round-robin, from after [`RunQueue::last`] (see [`Found::poll`]).
type Key = (u64, bool, u64, u64);

/// The thread a step runs.
struct Best<'a> {
    claim: Claim<'a>,
    thread: Arc<Thread>,
    key: Key,
    /// Its process has another runnable thread.
    siblings: bool,
}

/// What a step found, polling the processes it claimed.
#[derive(Default)]
struct Found<'a> {
    best: Option<Best<'a>>,
    /// The least CPU time of the other runnable threads.
    others: Option<u64>,
    /// That of the processes held by other CPUs, as last polled (see
    /// [`Owned::runnable`]).
    held: Option<u64>,
    /// The earliest of the blocked threads' wakes; if the step shared a
    /// process for another CPU's worker, a slice from then (see `serve`); and
    /// if it could not resume this CPU's worker, [`NOTIFIED`] from then.
    wake: Option<Instant>,
    blocked: bool,
    /// A thread's broker call waits for a worker.
    busy: bool,
    /// The threads blocked with no wake, as they were.
    forever: Vec<(Weak<Owned>, Arc<Thread>, Suspended)>,
    /// Another CPU held a process's claim, or it is queued for another CPU's
    /// worker.
    skipped: bool,
}

/// Bit `i`: CPU `i`.
pub(crate) fn bit(cpu: CpuId) -> u64 {
    1 << cpu.index()
}

/// The CPU time to count for a runnable thread that has used `cpu_time`, as
/// it is polled: at least one slice below `floor` (the [`RunQueue::floor`]).
/// A thread back from a long wait (e.g., for a device) thus gets at most one
/// extra slice before the others get their turns, instead of running until
/// it has caught up with them.
///
/// It never lowers `cpu_time`. The floor can stop rising while threads run
/// (e.g., while a stalled CPU holds a process, see [`Found::held`]); pulling
/// their CPU time down toward it would erase their progress and leave them
/// tied, ordered only by the shared round-robin position, which other CPUs
/// keep moving, so a thread could starve.
fn counted(cpu_time: u64, floor: u64) -> u64 {
    cpu_time.max(floor.saturating_sub(QUANTUM_NANOS))
}

/// The CPU time to charge for a thread's run, or a worker job for it, that
/// took `elapsed` nanoseconds: at most one slice. The clock also counts time
/// the host did not run the vCPU, which looks the same as real work; without
/// this cap, a thread charged for such a stall would wait until every other
/// thread caught up with it.
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
    /// that run is charged (other CPUs may charge it more, e.g., a worker's).
    Parked { cpu_time: u64 },
}

impl Shared {
    /// Serves the broker, then spawns launched processes and polls the
    /// threads, then runs one thread for a slice, or halts until one may run.
    /// False once nothing runs (see [`Self::is_idle`]). Once children were
    /// started (even if their runner processes could not be created), runs no
    /// thread, so the next step resumes the worker, which waits for them. The
    /// caller acknowledged this CPU's wakeups first (see [`cpu::acknowledge`]):
    /// one after, even as its worker looks (e.g., for a launched process's
    /// start), has it step again.
    fn step(&self) -> bool {
        let cpu = cpu::current();
        let claims = self.claim_attempts();
        let mut claimed = 0;
        self.reap();
        let (processes, last, floor) = {
            let queue = self.queue.lock();
            (queue.processes.clone(), queue.last, queue.floor)
        };
        // Whether a claim taken before `claims` was read may still be held:
        // every other is counted, or was released before, its effects seen by
        // the polls (see `Self::quiet`).
        let held = processes.iter().any(|process| process.is_held());
        // The CPUs whose workers are suspended, and whether this one's is.
        let workers = processes
            .iter()
            .filter_map(|process| process.worker())
            .fold(0, |workers, worker| workers | bit(worker));
        let mut serving = workers & bit(cpu) != 0;
        debug_assert_eq!(
            serving,
            matches!(worker::state(), worker::State::Suspended { .. })
        );
        // The other CPUs whose workers can serve what this one shares (see
        // `serve`): not suspended, nor the boot CPU's outside its steps.
        let mut free = cpu::online_mask() & !workers & !bit(cpu);
        if !self.boot_stepping.load(Ordering::Relaxed) {
            free &= !bit(CpuId::BOOT);
        }
        let mut found = Found::default();
        // This CPU's worker, which only it can resume. If its process is held
        // (e.g., by an entry of one of its threads), this spins briefly,
        // holding no claim, but only once `try_claim` failed, so that the
        // release wakes this CPU: its failed attempts fail this step's
        // `Self::quiet`, so it must step again. Still held, it is tried again
        // soon, not a slice later, as others may wait for what the worker
        // holds (e.g., a lock, see `worker`).
        if let Some(process) = processes.iter().find(|p| p.worker() == Some(cpu)) {
            if let Some(claim) = process.try_claim().or_else(|| process.claim_briefly()) {
                claimed += 1;
                serving &= !resume_worker(&claim);
            } else {
                found.skipped = true;
                found.wake = process.platform().now().checked_add(NOTIFIED);
            }
        }
        // From a different place on each CPU, so that CPUs polling at once
        // claim different processes (the order does not change the choice).
        let first = cpu.index() % processes.len().max(1);
        let order = || processes[first..].iter().chain(&processes[..first]);
        // First what they submitted, claiming each alone (see `serve`), and
        // only those that may need it (see `Owned::needs_serving`).
        let mut shared = Vec::new();
        for process in order().filter(|process| process.needs_serving()) {
            let Some(claim) = process.try_claim() else {
                found.skip(process);
                continue;
            };
            claimed += 1;
            if serve(cpu, &claim, &mut serving, free) {
                let again = claim.platform.now().checked_add(QUANTUM);
                found.wake = [found.wake, again].into_iter().flatten().min();
                shared.push(process);
            }
        }
        // Now released: only the free workers' CPUs can serve those.
        if !shared.is_empty() {
            cpu::online()
                .filter(|&other| free & bit(other) != 0)
                .for_each(cpu::wake);
        }
        // Then their threads.
        let mut spawned = Vec::new();
        let mut started = false;
        for process in order() {
            if process.is_quiescent() {
                continue;
            }
            // Queued for another CPU's worker: left to that one.
            if shared.iter().any(|other| Arc::ptr_eq(other, process)) {
                found.skip(process);
                continue;
            }
            let Some(claim) = process.try_claim() else {
                found.skip(process);
                continue;
            };
            claimed += 1;
            finish_parked(&claim);
            started |= claim.spawn_launched(&mut spawned);
            if !started {
                found.poll(claim, floor, last);
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
        let worker_wake = match worker::state() {
            worker::State::Suspended { wake } => wake,
            _ => None,
        };
        let Some(best) = found.best.take() else {
            // Not across the halt: a process that dies on another CPU
            // meanwhile is freed then, not once this CPU wakes.
            let found = found.detach();
            drop(processes);
            // None if a claim held as it began may have effects it missed.
            let claims = (!held).then_some(claims + claimed);
            return self.idle(cpu, found, serving, worker_wake, claims);
        };
        self.run_best(cpu, best, &found, serving, worker_wake);
        true
    }

    /// Runs the best thread a step found for a slice, and, if its broker
    /// calls are served at once, or it cloned its process (see
    /// `crate::fork`), more of its slice, unless a run parks it. If the
    /// process has other runnable threads, the other idle CPUs are woken to
    /// run them meanwhile. The slice ends early once another may run: a
    /// blocked thread's deadline, soon after a notification, or the worker's
    /// deadline or a device interrupt. With one CPU, a thread alone has no
    /// slice end; with more, every run has one, as other CPUs may make more
    /// runnable unseen (e.g., processes they held, start, or end the waits
    /// of), or need the boot CPU's services to look between slices at what
    /// they wait for.
    fn run_best(
        &self,
        cpu: CpuId,
        best: Best<'_>,
        found: &Found<'_>,
        serving: bool,
        worker_wake: Option<Instant>,
    ) {
        let Best {
            mut claim,
            thread,
            siblings,
            ..
        } = best;
        let process = claim.process();
        // With other CPUs, more may become runnable, unseen (e.g., processes
        // they held, or start).
        let alone = found.others.is_none() && cpu::online_count() == 1;
        let slice = (!alone).then(|| {
            let now = claim.platform.now();
            now.checked_add(QUANTUM)
                .unwrap_or(Instant::from_nanos(u64::MAX))
        });
        // Also until the earliest wake, for that thread, or the worker, to
        // run then.
        let mut slice_end = [found.wake, slice, worker_wake].into_iter().flatten().min();
        // Polling published to a wait already polled, or another CPU did, or
        // what the worker waits for happened: another may be due soon.
        thread.slice_end.set(slice_end);
        claim.take_notified(&thread);
        slice_end = thread.slice_end.get();
        self.counts[cpu.index()]
            .slices
            .fetch_add(1, Ordering::Relaxed);
        if siblings {
            claim.share();
        }
        let end = loop {
            claim = match self.run_slice(cpu, claim, &thread, slice_end) {
                Slice::Claimed(claim) => claim,
                parked @ Slice::Parked { .. } => break parked,
            };
            match thread.suspended.get() {
                // Served at once, it keeps the rest of its slice, unless the
                // request waits (e.g., for a device).
                Suspended::Yielded if !serving => {
                    if work(&claim, false) == Ran::Suspended {
                        claim.worker.set(Some(cpu));
                        break Slice::Claimed(claim);
                    }
                }
                // It keeps the rest of its slice too, for the runner to let go
                // of what it held across the call.
                Suspended::Cloned { .. } => {}
                _ => break Slice::Claimed(claim),
            }
            // Unless another may run now. The slice may have been cut short
            // (see `Inner::share_cpu` and `Inner::take_notified`).
            claim.take_notified(&thread);
            slice_end = thread.slice_end.get();
            let now = claim.platform.now();
            if claim.is_stopped()
                || slice_end.is_some_and(|slice_end| now >= slice_end)
                || claim.worker_due()
            {
                break Slice::Claimed(claim);
            }
        };
        // Including that slice, but not threads that were waiting.
        let cpu_time = match &end {
            Slice::Claimed(_) => thread.cpu_time.get(),
            Slice::Parked { cpu_time } => *cpu_time,
        };
        let runnable = [found.others, found.held]
            .into_iter()
            .flatten()
            .fold(cpu_time, u64::min);
        {
            let mut queue = self.queue.lock();
            queue.last = (process.seq, thread.id);
            queue.floor = queue.floor.max(runnable);
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

    /// The end of a step that found no thread to run: false if nothing runs
    /// (see [`Self::is_idle`]); otherwise halts until the earliest wake,
    /// unless, on the boot CPU, it abandons the waits that nothing could end
    /// (see [`Self::abandon`]), which needs `claims` (the count as of the
    /// step's start, plus the claims it took): `None` if a claim was held as
    /// the step began (see [`Self::quiet`]).
    fn idle(
        &self,
        cpu: CpuId,
        found: Found<'_>,
        serving: bool,
        worker_wake: Option<Instant>,
        claims: Option<u64>,
    ) -> bool {
        if !(found.blocked || found.busy || found.skipped || serving) && self.is_idle() {
            return false;
        }
        // The boot CPU takes devices' interrupts, unmarked: one that came as
        // the step ran, after its worker looked or its polls (e.g., as it
        // waited for a lock, or a 9P response), has it step again (see
        // `Inner::worker_due`).
        if cpu == CpuId::BOOT && self.events.take_device_interrupt() {
            return true;
        }
        let wake = [found.wake, worker_wake].into_iter().flatten().min();
        if self.events.wait(wake) {
            return true;
        }
        // No deadline, and no device could end the halt: only another CPU
        // could end the waits. If none runs anything, nothing could.
        if !(found.forever.is_empty() || found.busy || found.skipped || serving) {
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
    /// with nothing to do (see [`Owned::is_quiescent`]: so no worker is
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
    /// without a claim, one may still end others' waits), and no worker is
    /// suspended. The step began with none held (see `Self::step`), so every
    /// claim since was counted, and the step's polls saw what those released
    /// before did; the step's own failed attempts (not in `claims`) make this
    /// fail. Teardown under no claim (e.g., a reap) publishes nothing: a death
    /// releases its references under its claim.
    fn quiet(&self, claims: u64) -> bool {
        !self
            .queue
            .lock()
            .processes
            .iter()
            .any(|process| process.is_held() || process.is_running() || process.worker().is_some())
            && self.claim_attempts() == claims
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
            let dead = process.is_dead() && process.is_quiescent();
            if dead {
                reaped.push(process.clone());
            }
            !dead
        });
        // Outside the lock: a process's last reference releases its address
        // space, and its broker process exits.
        drop(reaped);
    }

    /// See [`Scheduler::claim`]. Not from the work itself (then running), so
    /// never nested.
    fn resume_own_worker(&self) {
        if !matches!(worker::state(), worker::State::Suspended { .. }) {
            return;
        }
        let cpu = cpu::current();
        // Held across the work, for the claim, so that the work's own
        // reference is never the last (the process stays queued until the
        // work finished). This one may be, as a reap's.
        let process = self
            .queue
            .lock()
            .processes
            .iter()
            .find(|process| process.worker() == Some(cpu))
            .cloned();
        if let Some(process) = process
            && let Some(claim) = process.try_claim()
        {
            resume_worker(&claim);
        }
    }
}

impl Found<'_> {
    /// With no thread to run, so no claim: the rest, which does not borrow
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
    /// `process` was held by another CPU, or is queued for its worker.
    fn skip(&mut self, process: &Owned) {
        self.skipped = true;
        self.held = [self.held, process.runnable()].into_iter().flatten().min();
    }

    /// Another runnable thread used `cpu_time` (see [`Self::others`]).
    fn other(&mut self, cpu_time: u64) {
        self.others = Some(self.others.map_or(cpu_time, |others| others.min(cpu_time)));
    }

    /// Polls the claimed process's threads, ending the waits it can, and
    /// keeps its claim if it has the best runnable thread so far; otherwise,
    /// releases it, for another CPU to take if it has work left.
    fn poll(&mut self, claim: Claim<'a>, floor: u64, last: (u64, u64)) {
        let process = claim.process();
        let threads = claim.threads.borrow().clone();
        // Before polling, which may publish (e.g., input) to a process
        // polled already; after, as polling ended waits.
        claim.mark_notification_waiter();
        let turns: Vec<Turn> = threads.iter().map(|thread| claim.turn(thread)).collect();
        claim.mark_notification_waiter();
        let mut best: Option<(Key, &Arc<Thread>)> = None;
        let mut runnable = 0;
        for (thread, turn) in threads.iter().zip(turns) {
            match turn {
                Turn::Runnable => {
                    runnable += 1;
                    let cpu_time = &thread.cpu_time;
                    cpu_time.set(counted(cpu_time.get(), floor));
                    let id = (process.seq, thread.id);
                    let key = (cpu_time.get(), id <= last, id.0, id.1);
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
                    if wake.is_none() {
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
            thread: thread.clone(),
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

/// Has this CPU's worker serve what the claimed process submitted, if it
/// is free. Called holding no other claim (by the step's first pass), as a
/// CPU runs its worker holding none but that of the process it serves: the
/// work may take long (e.g., a 9P round trip), and would keep other
/// processes from the other CPUs and the boot CPU's services. Else, if
/// another CPU's is free (in `free`: not suspended, nor the boot CPU's
/// outside its steps), returns true, sharing the process with it: the step
/// wakes those CPUs once it released the claim (not the others, which cannot
/// serve it), and does not poll it, running none of its threads, which would
/// keep it from that CPU meanwhile. That CPU may be busy in its step (e.g.,
/// running a thread, or reaping a process): it serves it once done, the boot
/// CPU maybe only after its services; this CPU looks again within a slice
/// (see `Found::wake`).
fn serve(cpu: CpuId, claim: &Claim<'_>, serving: &mut bool, free: u64) -> bool {
    if claim.broker_busy() || claim.is_dead() || !claim.broker.has_submitted() {
        return false;
    }
    if !*serving {
        if work(claim, false) == Ran::Suspended {
            claim.worker.set(Some(cpu));
            *serving = true;
        }
        false
    } else if free != 0 {
        // Queued for a worker: another CPU's is free. (Otherwise, the CPU
        // whose worker finishes next serves it then, or, if that is in a claim
        // wait, a later step does.)
        true
    } else {
        false
    }
}

/// Resumes this CPU's worker, suspended serving the claimed process: whether
/// its work finished. Then, the process no longer needs this CPU (see
/// `Inner::worker`), and its threads that waited for the worker may run on
/// any: the release publishes that, and wakes the other idle CPUs.
fn resume_worker(claim: &Claim<'_>) -> bool {
    let finished = work(claim, true) == Ran::Finished;
    if finished {
        claim.worker.set(None);
        claim.share();
    }
    finished
}

/// Has this CPU's worker serve what the claimed process submitted, or
/// `resume` serving it, until done or suspended. The work reaches the
/// process's memory only through pinned pages (see
/// `litebox_broker_vm_kernel`), so in no particular address space. Charged to
/// the thread that made the last broker call (see
/// [`Inner::broker_requester`]): the requests of several at once are charged
/// to one.
fn work(claim: &Claim<'_>, resume: bool) -> Ran {
    let start = claim.platform.now();
    // The work looks at the devices itself.
    let _ = claim.broker.take_device_interrupt();
    let ran = if resume {
        worker::resume()
    } else {
        // Its own reference: the work may outlast the step.
        let process = claim.process().clone();
        worker::start(
            claim.platform,
            Box::new(move || {
                // Safety: the work runs only in `work`, under the claim,
                // which this CPU takes again to resume it.
                let inner = unsafe { process.claimed() }.expect("the work starts under the claim");
                if inner.broker.serve().is_err() {
                    inner.kill("broker association failed");
                }
            }),
        )
    };
    claim.deactivate();
    claim.broker_requester().charge(claim.platform, start);
    ran
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

/// A thread's state for one scheduling round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Runnable,
    /// On a CPU: neither runnable nor blocked.
    Running,
    /// Exited, waits for a request, or its process is dead.
    Stopped,
    /// In a broker or futex wait, until an event or the wake, if any.
    Blocked(Option<Instant>),
    /// Its broker call is for the worker, which is busy.
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

    /// Whether this CPU's suspended worker may need to run now, before the
    /// running thread's slice ends: a device interrupted. The handler marks
    /// the other CPUs and interrupts those with suspended workers
    /// ([`worker::interrupt_suspended`]); the boot CPU takes the interrupt
    /// itself. Then an entry preempts its thread as it leaves (see
    /// `Running::leave`), a halt ends, and mid-step `Shared::idle` steps
    /// again. But not one that came as a new work ran, before it first
    /// suspended, seen at the latest as the slice ends.
    pub(crate) fn worker_due(&self) -> bool {
        matches!(worker::state(), worker::State::Suspended { .. })
            && self.broker.take_device_interrupt()
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

    /// Ends `thread`'s slice `duration` from now, at the latest.
    fn end_slice_by(&self, thread: &Thread, duration: Duration) {
        let end = self
            .platform
            .now()
            .checked_add(duration)
            .unwrap_or(Instant::from_nanos(u64::MAX));
        let slice_end = thread
            .slice_end
            .get()
            .map_or(end, |slice_end| slice_end.min(end));
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
            // Queued for the worker.
            Turn::Busy
        } else {
            Turn::Runnable
        }
    }
}

impl Shared {
    /// Runs `thread` of `claim`'s process on `cpu`, the calling one, until it
    /// stops, blocks, or `slice_end` passes (none: until it stops or blocks),
    /// handing the claim to the run (see `Running`). Adds the process clone
    /// the thread made, if any (see `crate::fork`), at once: another CPU may
    /// adopt it as the thread runs on. If the run ended without the claim, the
    /// CPU parks the thread ([`Parked`]) rather than wait for the claim, which
    /// its holder may keep for long: the thread counts as running (so no other
    /// CPU runs or polls it) until a step that claims the process finishes the
    /// run ([`finish_parked`]).
    fn run_slice<'a>(
        &self,
        cpu: CpuId,
        claim: Claim<'a>,
        thread: &Thread,
        slice_end: Option<Instant>,
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
        let running = Running::new(claim, thread);
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
    use super::*;

    /// Models one scheduling step (`Shared::step`, then `Shared::run_best`) on
    /// a CPU that claims only process `seq`, whose threads are all runnable,
    /// thread `id` having used `cpu_time[id]`. It picks the thread with the
    /// least counted CPU time (ties go round-robin), charges it for a run of
    /// `elapsed` nanoseconds, and raises the floor to the least CPU time among
    /// these threads and `held`, the least CPU time published by processes
    /// that other CPUs hold. Returns the ID of the thread that ran.
    fn take_step(
        queue: &mut RunQueue,
        seq: u64,
        cpu_time: &mut [u64],
        elapsed: u64,
        held: Option<u64>,
    ) -> u64 {
        for time in &mut *cpu_time {
            *time = counted(*time, queue.floor);
        }
        let (id, time) = (0..)
            .zip(&mut *cpu_time)
            .min_by_key(|(id, time)| -> Key { (**time, (seq, *id) <= queue.last, seq, *id) })
            .expect("a runnable thread");
        *time += charged(elapsed);
        let runnable = cpu_time.iter().copied().chain(held).min();
        queue.floor = queue.floor.max(runnable.expect("a thread"));
        queue.last = (seq, id);
        id
    }

    /// Asserts that, of `count` threads, none went more than two rounds
    /// (`2 * count` steps) without running; `order` lists the ID of the
    /// thread that ran at each step. This checks for a reasonable share of
    /// the CPU (about half a fair share at least), not an exact one.
    fn assert_no_starvation(order: &[u64], count: usize) {
        for thread in (0..).take(count) {
            let wait = order
                .split(|&ran| ran == thread)
                .map(<[u64]>::len)
                .max()
                .unwrap_or_default();
            assert!(
                wait <= 2 * count,
                "thread {thread} waited {wait} steps: {order:?}"
            );
        }
    }

    #[test]
    fn a_thread_whose_run_the_host_stalled_runs_again_soon() {
        let mut queue = RunQueue::default();
        let mut cpu_time = [0; 8];
        let mut order = Vec::new();
        for step in 0..200 {
            // The run at step 20 takes 70 ms longer, as if the host stopped the
            // vCPU during it.
            let stall = if step == 20 { 70_000_000 } else { 0 };
            let elapsed = QUANTUM_NANOS + stall;
            order.push(take_step(&mut queue, 1, &mut cpu_time, elapsed, None));
        }
        // Without the cap, the stalled thread would wait about 7 rounds, until
        // every other thread had run 70 ms more.
        assert_no_starvation(&order, 8);
    }

    #[test]
    fn neither_sibling_starves_while_a_stalled_cpu_holds_the_floor_down() {
        let mut queue = RunQueue::default();
        // A stalled CPU holds process 1, whose published least CPU time is 0,
        // so the floor stays at 0 (see `Found::held`).
        let held = Some(0);
        // Process 2's two threads run on one CPU and process 3's thread on
        // another, their steps interleaved: each run of process 3 moves the
        // shared round-robin position past process 2's threads.
        let (mut siblings, mut other) = ([0; 2], [0]);
        let mut order = Vec::new();
        for _ in 0..100 {
            order.push(take_step(&mut queue, 2, &mut siblings, QUANTUM_NANOS, held));
            take_step(&mut queue, 3, &mut other, QUANTUM_NANOS, held);
        }
        // Each run adds to the siblings' CPU time, so they keep taking turns;
        // erasing it would leave them tied, and the moved round-robin would
        // always pick the first.
        assert_no_starvation(&order, 2);
    }
}
